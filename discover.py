#!/usr/bin/env python3
"""
Target discovery v6 — fixes secondary rate limit escalation seen in v5 logs.

ROOT CAUSE (from the v5 log):
  Retry-After values escalated: 2s → 11s → 20s → 104s → 123s → 141s
  This is GitHub's abuse-detection progressively increasing the penalty
  each time we re-offend immediately after sleeping the exact Retry-After.

  The bisection tree fires peek() → returns → immediately fires the sibling
  peek() with zero gap between them. SEARCH_DELAY=7s only applied WITHIN
  paginate_all/peek calls, never BETWEEN recursive bisection calls. That
  burst pattern is what abuse detection targets, not total volume.

FIXES:
  1. GLOBAL ADAPTIVE THROTTLE: a single shared state tracks the last
     request time for each endpoint and enforces a minimum gap before
     every request, regardless of where in the call tree it originates.
     This replaces the per-call time.sleep() that only paced within
     individual functions.

  2. PENALTY ACCUMULATOR: each secondary rate limit hit adds to a
     running penalty (additive, up to a cap). The penalty decays slowly
     only when requests succeed cleanly. So a burst of hits causes the
     throttle to back off for a sustained window, not just one sleep.

  3. JITTER: ±20% randomness on every sleep to break synchronization
     patterns that look machine-generated to abuse detection.

  4. PROBE-THEN-SETTLE: after a secondary hit, we sleep Retry-After,
     then make exactly ONE probe request, then wait the full adaptive
     gap before the next one — instead of firing immediately after waking.

USAGE:
    export GITHUB_TOKEN="ghp_..."
    python discover_targets_v6.py
    python discover_targets_v6.py --resume
    python discover_targets_v6.py --skip-channel5
"""

import requests
import time
import os
import json
import random
import argparse
import logging
from datetime import datetime, timedelta, timezone

API_ROOT = "https://api.github.com"
GRAPHQL_URL = f"{API_ROOT}/graphql"
SEARCH_CODE_URL = f"{API_ROOT}/search/code"
SEARCH_COMMITS_URL = f"{API_ROOT}/search/commits"
SEARCH_REPOS_URL = f"{API_ROOT}/search/repositories"

# Base inter-request gap for each endpoint. Code search has a 10 req/min
# primary limit (one per 6s minimum), but secondary kicks in well before
# that on bursts. We start conservative; the throttle adapts upward.
BASE_CODE_SEARCH_GAP = 12.0    # seconds between any two code search requests
BASE_REPO_SEARCH_GAP = 5.0     # repo search has a 30 req/min primary limit
BASE_COMMIT_SEARCH_GAP = 12.0
BASE_GRAPHQL_GAP = 2.0

JITTER_FACTOR = 0.2            # ±20% randomness on every sleep

# Adaptive penalty: each secondary hit adds this many seconds to the gap,
# up to the cap. Penalty decays by PENALTY_DECAY_RATE per successful request.
PENALTY_PER_HIT = 8.0          # seconds added per secondary hit
PENALTY_MAX = 120.0            # ceiling on added penalty
PENALTY_DECAY_RATE = 0.5       # seconds removed per clean request

MAX_RETRIES = 5                # more retries now that we pace correctly

CODE_SEARCH_MAX_INDEXED_BYTES = 384_000
SIZE_MIN_LEAF_WIDTH = 1
SIZE_MAX_DEPTH = 20

DATE_MIN_LEAF_WIDTH_DAYS = 1
DATE_MAX_DEPTH = 15

STARS_MIN_LEAF_WIDTH = 1
STARS_MAX_DEPTH = 25

EARLIEST_GITHUB_DATE = datetime(2008, 1, 1, tzinfo=timezone.utc)

CODE_QUERIES = [
    'language:Go "import \\"C\\""',
    'language:Go "cgo.Handle"',
    'language:Go "//go:build cgo"',
]

COMMIT_PHRASES = [
    "rewrite in go", "rewritten in go", "port to go", "porting to go",
    "migrate to go", "migrating to go", "replace cgo", "remove cgo",
    "drop cgo", "pure go implementation", "pure-go implementation",
    "reimplement in go", "reimplemented in go",
]

TOPIC_QUERIES = ["cgo", "purego", "go-migration", "c-to-go", "golang-migration", "go-rewrite"]

DESCRIPTION_KEYWORDS = [
    "rewrite in go", "go rewrite of", "go port of", "go implementation of",
    "successor to", "pure go implementation", "reimplementation in go",
]

LARGE_C_LANGUAGES = ["C", "C++"]
LARGE_C_MIN_STARS = 1000
MIN_GO_BYTES_SIGNAL = 50_000

OUTPUT_JSON = "discovered_targets_v6.json"
OUTPUT_ORGS = "orgs.txt"
CHANNEL5_CHECKPOINT = "channel5_checkpoint.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                     datefmt="%H:%M:%S")
log = logging.getLogger("discover_v6")


# ============================================================
# Global adaptive throttle
# ============================================================

class AdaptiveThrottle:
    """
    Per-endpoint throttle with adaptive penalty for secondary rate limits.
    All requests to a given URL base go through this; it enforces the
    inter-request gap globally, not just within individual function calls.
    """
    def __init__(self, base_gap):
        self.base_gap = base_gap
        self.penalty = 0.0
        self.last_request_time = 0.0

    def _effective_gap(self):
        raw = self.base_gap + self.penalty
        jitter = raw * JITTER_FACTOR * (2 * random.random() - 1)
        return max(1.0, raw + jitter)

    def wait(self):
        gap = self._effective_gap()
        elapsed = time.time() - self.last_request_time
        remaining = gap - elapsed
        if remaining > 0:
            time.sleep(remaining)

    def record_success(self):
        self.last_request_time = time.time()
        self.penalty = max(0.0, self.penalty - PENALTY_DECAY_RATE)

    def record_secondary_hit(self, retry_after):
        self.last_request_time = time.time()
        self.penalty = min(PENALTY_MAX, self.penalty + PENALTY_PER_HIT)
        effective_gap = self._effective_gap()
        log.info(f"secondary rate limit — sleeping {retry_after}s (Retry-After), "
                 f"penalty now +{self.penalty:.0f}s, next gap ~{effective_gap:.0f}s")
        time.sleep(retry_after + 1)

    def record_primary_hit(self, reset_ts):
        self.last_request_time = time.time()
        wait = max(0, reset_ts - int(time.time())) + 1
        log.info(f"primary rate limit — sleeping {wait}s (X-RateLimit-Reset)")
        time.sleep(wait)


# One throttle instance per endpoint type, shared across all calls
throttles = {
    SEARCH_CODE_URL: AdaptiveThrottle(BASE_CODE_SEARCH_GAP),
    SEARCH_COMMITS_URL: AdaptiveThrottle(BASE_COMMIT_SEARCH_GAP),
    SEARCH_REPOS_URL: AdaptiveThrottle(BASE_REPO_SEARCH_GAP),
    GRAPHQL_URL: AdaptiveThrottle(BASE_GRAPHQL_GAP),
}


def get_throttle(url):
    for base_url, throttle in throttles.items():
        if url.startswith(base_url) or url == base_url:
            return throttle
    return AdaptiveThrottle(10.0)  # safe default for unexpected URLs


# ============================================================
# HTTP helpers
# ============================================================

def gh_headers(extra_accept=None):
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": extra_accept or "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def request_with_retry(method, url, **kwargs):
    throttle = get_throttle(url)
    last_resp = None

    for attempt in range(1, MAX_RETRIES + 1):
        throttle.wait()

        try:
            resp = requests.request(method, url, timeout=20, **kwargs)
        except requests.exceptions.RequestException as e:
            log.warning(f"connection error (attempt {attempt}/{MAX_RETRIES}): {e}")
            time.sleep(5 * attempt)
            continue

        last_resp = resp

        # Secondary rate limit (abuse detection) — Retry-After header
        if resp.status_code in (403, 429) and "Retry-After" in resp.headers:
            retry_after = int(resp.headers["Retry-After"])
            throttle.record_secondary_hit(retry_after)
            continue

        # Primary rate limit — X-RateLimit-Reset header
        if resp.status_code == 403 and "X-RateLimit-Reset" in resp.headers:
            reset_ts = int(resp.headers["X-RateLimit-Reset"])
            throttle.record_primary_hit(reset_ts)
            continue

        if resp.status_code >= 500:
            log.warning(f"HTTP {resp.status_code} from {url} (attempt {attempt})")
            time.sleep(5 * attempt)
            continue

        throttle.record_success()
        return resp

    body = f" | status={last_resp.status_code} body={last_resp.text[:300]!r}" if last_resp else ""
    log.error(f"GIVING UP after {MAX_RETRIES} attempts on {url}{body}")
    return None


# ============================================================
# Search helpers
# ============================================================

def peek_total_count(url, query, extra_accept=None):
    resp = request_with_retry("GET", url, params={"q": query, "per_page": 1},
                               headers=gh_headers(extra_accept))
    if resp is None:
        log.error(f"peek failed for {query!r} — treating as 0 (will undercount if transient)")
        return 0
    if resp.status_code != 200:
        return 0
    return resp.json().get("total_count", 0)


def paginate_all(url, query, extra_accept=None, sort=None):
    items = []
    for page in range(1, 11):
        params = {"q": query, "per_page": 100, "page": page}
        if sort:
            params["sort"] = sort
        resp = request_with_retry("GET", url, params=params, headers=gh_headers(extra_accept))
        if resp is None:
            log.error(f"paginate_all aborted at page {page} for {query!r} — results INCOMPLETE")
            break
        if resp.status_code != 200:
            break
        page_items = resp.json().get("items", [])
        items.extend(page_items)
        if len(page_items) < 100:
            break
    return items


# ============================================================
# Bisection (date / size / stars) — no per-call sleep; throttle handles it
# ============================================================

def bisect_by_date(url, base_query, date_field, start, end, extra_accept=None,
                    sort=None, depth=0):
    query = f"{base_query} {date_field}:{start.strftime('%Y-%m-%d')}..{end.strftime('%Y-%m-%d')}"
    total = peek_total_count(url, query, extra_accept)
    width_days = (end - start).days
    is_leaf = total <= 1000 or width_days < DATE_MIN_LEAF_WIDTH_DAYS or depth >= DATE_MAX_DEPTH
    if is_leaf:
        if total > 1000:
            log.warning(f"cannot narrow further: {query!r} (total={total})")
        items = paginate_all(url, query, extra_accept, sort) if total > 0 else []
        return items, total
    mid = start + timedelta(days=width_days // 2)
    log.info(f"  splitting {start.date()}..{end.date()} ({total}) at {mid.date()}")
    left, lt = bisect_by_date(url, base_query, date_field, start, mid, extra_accept, sort, depth + 1)
    right, rt = bisect_by_date(url, base_query, date_field, mid, end, extra_accept, sort, depth + 1)
    if abs((lt + rt) - total) > max(5, total * 0.05):
        log.warning(f"count mismatch {query!r}: parent={total}, children={lt+rt} "
                    f"(GitHub total_count is approximate on some endpoints)")
    return left + right, lt + rt


def bisect_by_size(query_base, low, high, depth=0):
    query = f"{query_base} size:{low}..{high}"
    total = peek_total_count(SEARCH_CODE_URL, query)
    width = high - low
    is_leaf = total <= 1000 or width < SIZE_MIN_LEAF_WIDTH or depth >= SIZE_MAX_DEPTH
    if is_leaf:
        if total > 1000:
            log.warning(f"cannot narrow further: {query!r} (total={total})")
        items = paginate_all(SEARCH_CODE_URL, query) if total > 0 else []
        return items, total
    mid = low + width // 2
    log.info(f"  splitting size {low}..{high} ({total}) at {mid}")
    left, lt = bisect_by_size(query_base, low, mid, depth + 1)
    right, rt = bisect_by_size(query_base, mid + 1, high, depth + 1)
    return left + right, lt + rt


def bisect_by_stars(base_query, low, high, depth=0):
    query = f"{base_query} stars:{low}..{high}"
    total = peek_total_count(SEARCH_REPOS_URL, query)
    width = high - low
    is_leaf = total <= 1000 or width < STARS_MIN_LEAF_WIDTH or depth >= STARS_MAX_DEPTH
    if is_leaf:
        if total > 1000:
            log.warning(f"cannot narrow further: {query!r} (total={total})")
        items = paginate_all(SEARCH_REPOS_URL, query, sort="stars") if total > 0 else []
        return items, total
    mid = low + width // 2
    log.info(f"  splitting stars {low}..{high} ({total}) at {mid}")
    left, lt = bisect_by_stars(base_query, low, mid, depth + 1)
    right, rt = bisect_by_stars(base_query, mid + 1, high, depth + 1)
    return left + right, lt + rt


# ============================================================
# Channels 1-4
# ============================================================

def channel_code_search(query):
    items, total = bisect_by_size(query, 0, CODE_SEARCH_MAX_INDEXED_BYTES)
    log.info(f"  collected: {len(items)} (reported ~{total})")
    return {item["repository"]["full_name"] for item in items}


def channel_commit_search(phrase):
    now = datetime.now(timezone.utc)
    items, total = bisect_by_date(
        SEARCH_COMMITS_URL, f'"{phrase}"', "committer-date",
        EARLIEST_GITHUB_DATE, now,
        extra_accept="application/vnd.github.cloak-preview+json",
    )
    log.info(f"  collected: {len(items)} (reported ~{total})")
    return {item["repository"]["full_name"] for item in items}


def channel_topic_search(topic):
    now = datetime.now(timezone.utc)
    items, total = bisect_by_date(
        SEARCH_REPOS_URL, f"topic:{topic}", "created",
        EARLIEST_GITHUB_DATE, now, sort="stars",
    )
    log.info(f"  collected: {len(items)} (reported ~{total})")
    return {item["full_name"] for item in items}


def channel_description_search(keyword):
    now = datetime.now(timezone.utc)
    items, total = bisect_by_date(
        SEARCH_REPOS_URL, f'"{keyword}" in:description', "created",
        EARLIEST_GITHUB_DATE, now, sort="stars",
    )
    log.info(f"  collected: {len(items)} (reported ~{total})")
    return {item["full_name"] for item in items}


# ============================================================
# Channel 5 (GraphQL, unchanged logic from v5)
# ============================================================

ORG_REPOS_LANGUAGES_QUERY = """
query($org: String!, $cursor: String) {
  organization(login: $org) {
    repositories(first: 100, after: $cursor, isFork: false,
                 privacy: PUBLIC, orderBy: {field: PUSHED_AT, direction: DESC}) {
      pageInfo { hasNextPage endCursor }
      nodes {
        nameWithOwner
        stargazerCount
        languages(first: 15, orderBy: {field: SIZE, direction: DESC}) {
          edges { size node { name } }
        }
      }
    }
  }
}
"""


def graphql_request(query, variables):
    throttle = get_throttle(GRAPHQL_URL)
    last_resp = None
    for attempt in range(1, MAX_RETRIES + 1):
        throttle.wait()
        try:
            resp = requests.post(GRAPHQL_URL, json={"query": query, "variables": variables},
                                  headers=gh_headers(), timeout=20)
        except requests.exceptions.RequestException as e:
            log.warning(f"GraphQL connection error (attempt {attempt}): {e}")
            time.sleep(5 * attempt)
            continue

        last_resp = resp

        if resp.status_code in (403, 429) and "Retry-After" in resp.headers:
            throttle.record_secondary_hit(int(resp.headers["Retry-After"]))
            continue

        if resp.status_code == 403 and "X-RateLimit-Reset" in resp.headers:
            throttle.record_primary_hit(int(resp.headers["X-RateLimit-Reset"]))
            continue

        if resp.status_code != 200:
            log.warning(f"GraphQL HTTP {resp.status_code}, retrying")
            time.sleep(5 * attempt)
            continue

        data = resp.json()
        if "errors" in data:
            err_types = {e.get("type") for e in data["errors"]}
            if "NOT_FOUND" in err_types:
                throttle.record_success()
                return None
            if "RATE_LIMITED" in err_types:
                throttle.record_secondary_hit(60)
                continue
            log.warning(f"GraphQL errors: {data['errors']}, retrying")
            time.sleep(5 * attempt)
            continue

        throttle.record_success()
        return data.get("data")

    body = f" | {last_resp.status_code} {last_resp.text[:200]!r}" if last_resp else ""
    log.error(f"GraphQL GIVING UP after {MAX_RETRIES} attempts{body}")
    return None


def get_org_go_repos_graphql(org_login, max_pages=5):
    go_repos = []
    cursor = None
    for _ in range(max_pages):
        data = graphql_request(ORG_REPOS_LANGUAGES_QUERY, {"org": org_login, "cursor": cursor})
        if data is None or data.get("organization") is None:
            break
        repo_conn = data["organization"]["repositories"]
        for node in repo_conn["nodes"]:
            go_size = next((e["size"] for e in node["languages"]["edges"]
                            if e["node"]["name"] == "Go"), 0)
            if go_size >= MIN_GO_BYTES_SIGNAL:
                go_repos.append({"repo": node["nameWithOwner"], "go_bytes": go_size,
                                  "stars": node["stargazerCount"]})
        if not repo_conn["pageInfo"]["hasNextPage"]:
            break
        cursor = repo_conn["pageInfo"]["endCursor"]
    return go_repos


def load_channel5_checkpoint():
    if os.path.exists(CHANNEL5_CHECKPOINT):
        with open(CHANNEL5_CHECKPOINT) as f:
            return json.load(f)
    return {"checked_orgs": [], "candidates": {}}


def save_channel5_checkpoint(state):
    with open(CHANNEL5_CHECKPOINT, "w") as f:
        json.dump(state, f, indent=2)


def channel_c_orgs_with_go_sibling(resume=False):
    seed_items = []
    for lang in LARGE_C_LANGUAGES:
        base_query = f"language:{lang}"
        log.info(f"  bisecting: {base_query} stars:>={LARGE_C_MIN_STARS}")
        items, total = bisect_by_stars(base_query, LARGE_C_MIN_STARS, 300_000)
        log.info(f"  {base_query}: {len(items)} repos (reported ~{total})")
        seed_items.extend(items)

    seed_by_repo = {}
    for item in seed_items:
        fn = item["full_name"]
        if fn not in seed_by_repo or item.get("stargazers_count", 0) > seed_by_repo[fn].get("stargazers_count", 0):
            seed_by_repo[fn] = item

    orgs_seen = set()
    seed_by_org = {}
    for item in seed_by_repo.values():
        if item["owner"]["type"] != "Organization":
            continue
        owner = item["owner"]["login"]
        if owner in orgs_seen:
            continue
        orgs_seen.add(owner)
        seed_by_org[owner] = item

    log.info(f"  {len(seed_by_org)} unique org owners among large C/C++ repos")

    state = load_channel5_checkpoint() if resume else {"checked_orgs": [], "candidates": {}}
    checked = set(state["checked_orgs"])
    candidates = state["candidates"]
    if resume:
        log.info(f"  resuming: {len(checked)} orgs already done")

    remaining = {o: item for o, item in seed_by_org.items() if o not in checked}
    total_orgs = len(seed_by_org)

    for i, (owner, seed_item) in enumerate(remaining.items(), 1):
        log.info(f"  channel5 [{len(checked) + i}/{total_orgs}] {owner} "
                 f"(seed {seed_item['full_name']}, {seed_item.get('stargazers_count', 0)} stars)")
        go_repos = get_org_go_repos_graphql(owner)
        if go_repos:
            candidates[owner] = {"seed_c_repo": seed_item["full_name"],
                                  "seed_c_stars": seed_item.get("stargazers_count", 0),
                                  "go_repos": go_repos}
            log.info(f"    -> HIT: {len(go_repos)} substantial Go repo(s)")
        checked.add(owner)
        state["checked_orgs"] = list(checked)
        state["candidates"] = candidates
        save_channel5_checkpoint(state)

    return candidates


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Discover CGo/Go-migration targets — v6")
    parser.add_argument("--skip-channel5", action="store_true")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--limit-queries", type=int, default=None)
    args = parser.parse_args()

    if not os.environ.get("GITHUB_TOKEN"):
        log.warning("GITHUB_TOKEN not set — search and GraphQL both require auth.")

    org_matches = {}
    channel5_data = {}

    def record(repos):
        for full_name in repos:
            if "/" not in full_name:
                continue
            owner = full_name.split("/")[0]
            org_matches.setdefault(owner, set()).add(full_name)

    log.info("=== Channel 1: code search ===")
    for q in CODE_QUERIES[: args.limit_queries]:
        log.info(f"query: {q!r}")
        record(channel_code_search(q))

    log.info("=== Channel 2: commit search ===")
    for p in COMMIT_PHRASES[: args.limit_queries]:
        log.info(f"phrase: {p!r}")
        record(channel_commit_search(p))

    log.info("=== Channel 3: topic search ===")
    for t in TOPIC_QUERIES[: args.limit_queries]:
        log.info(f"topic: {t!r}")
        record(channel_topic_search(t))

    log.info("=== Channel 4: description search ===")
    for kw in DESCRIPTION_KEYWORDS[: args.limit_queries]:
        log.info(f"keyword: {kw!r}")
        record(channel_description_search(kw))

    if not args.skip_channel5:
        log.info("=== Channel 5: large C/C++ orgs with a Go sibling repo ===")
        found = channel_c_orgs_with_go_sibling(resume=args.resume)
        channel5_data.update(found)
        for org, data in found.items():
            org_matches.setdefault(org, set()).update(r["repo"] for r in data["go_repos"])
            org_matches[org].add(data["seed_c_repo"])
        if os.path.exists(CHANNEL5_CHECKPOINT):
            os.remove(CHANNEL5_CHECKPOINT)
    else:
        log.info("=== Channel 5 skipped ===")

    log.info(f"{len(org_matches)} unique candidate orgs across all channels")

    output = {"orgs": {org: sorted(repos) for org, repos in org_matches.items()},
              "channel5_detail": channel5_data}
    with open(OUTPUT_JSON, "w") as f:
        json.dump(output, f, indent=2)
    with open(OUTPUT_ORGS, "w") as f:
        f.write("# Auto-discovered targets (v6, full-recall) — unfiltered.\n")
        f.write(f"# Generated {datetime.now(timezone.utc).isoformat()}\n")
        for org in sorted(org_matches):
            f.write(f"{org}\n")

    log.info(f"=== DISCOVERY COMPLETE: {len(org_matches)} candidate orgs ===")
    log.info(f"wrote {OUTPUT_JSON} and {OUTPUT_ORGS}")


if __name__ == "__main__":
    main()
