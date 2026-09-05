#!/usr/bin/env python3
"""
Target discovery v5 — fixes a silent-stall bug found in the v4 run:

BUG: request_with_retry / graphql_request gave up after MAX_RETRIES with
NO log message, so a failed request (in this case very likely GitHub's
SECONDARY rate limit — an abuse-detection 403 with a `Retry-After` header,
which v4 didn't check for at all, only the primary `X-RateLimit-Reset`)
silently produced an empty result. That empty result looked identical to
"nothing left to find", so the run appeared to finish cleanly at 435/1000
instead of visibly failing.

FIXES:
  1. Every give-up now logs an ERROR with status code + response body.
  2. Retry-After (secondary rate limit) is now checked and honored,
     same as X-RateLimit-Reset (primary limit) was already.
  3. Channel 5's seed search (language:C stars:>1000) is now star-bisected
     like size/date elsewhere, instead of a flat paginate_all capped at
     1000 raw results — your v3 log showed this query alone has 2472
     total matches, so a third of it was invisible before.
  4. Channel 5 checkpoints after every org, so a future stall costs
     minutes of re-work, not the whole run. --resume picks back up.

USAGE:
    export GITHUB_TOKEN="ghp_..."
    python discover_targets_v5.py
    python discover_targets_v5.py --resume
    python discover_targets_v5.py --skip-channel5
"""

import requests
import time
import os
import json
import argparse
import logging
from datetime import datetime, timedelta, timezone

API_ROOT = "https://api.github.com"
GRAPHQL_URL = f"{API_ROOT}/graphql"
SEARCH_CODE_URL = f"{API_ROOT}/search/code"
SEARCH_COMMITS_URL = f"{API_ROOT}/search/commits"
SEARCH_REPOS_URL = f"{API_ROOT}/search/repositories"

SEARCH_DELAY = 7
REPO_SEARCH_DELAY = 3
GRAPHQL_DELAY = 1.5
FETCH_DELAY = 0.4
MAX_RETRIES = 4
RETRY_BACKOFF_BASE = 5

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

TOPIC_QUERIES = ["cgo", "purego", "go-migration", "c-to-go", "golang-migration",
                  "go-rewrite"]

DESCRIPTION_KEYWORDS = [
    "rewrite in go", "go rewrite of", "go port of", "go implementation of",
    "successor to", "pure go implementation", "reimplementation in go",
]

LARGE_C_LANGUAGES = ["C", "C++"]
LARGE_C_MIN_STARS = 1000

MIN_GO_BYTES_SIGNAL = 50_000

OUTPUT_JSON = "discovered_targets_v5.json"
OUTPUT_ORGS = "orgs.txt"
CHANNEL5_CHECKPOINT = "channel5_checkpoint.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                     datefmt="%H:%M:%S")
log = logging.getLogger("discover_v5")


# ============================================================
# HTTP helpers — FIX 1 + FIX 2
# ============================================================

def gh_headers(extra_accept=None):
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": extra_accept or "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def request_with_retry(method, url, **kwargs):
    last_resp = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.request(method, url, timeout=15, **kwargs)
        except requests.exceptions.RequestException as e:
            log.warning(f"connection error (attempt {attempt}/{MAX_RETRIES}) on {url}: {e}")
            time.sleep(RETRY_BACKOFF_BASE * attempt)
            continue

        last_resp = resp

        if resp.status_code in (403, 429) and "Retry-After" in resp.headers:
            wait = int(resp.headers["Retry-After"]) + 1
            log.info(f"secondary rate limit hit on {url}, sleeping {wait}s (Retry-After)...")
            time.sleep(wait)
            continue

        if resp.status_code == 403 and "X-RateLimit-Reset" in resp.headers:
            reset = int(resp.headers["X-RateLimit-Reset"])
            wait = max(0, reset - int(time.time())) + 1
            log.info(f"primary rate limit hit on {url}, sleeping {wait}s...")
            time.sleep(wait)
            continue

        if resp.status_code >= 500:
            wait = RETRY_BACKOFF_BASE * attempt
            log.warning(f"HTTP {resp.status_code} from {url}, retrying in {wait}s")
            time.sleep(wait)
            continue

        return resp

    body_preview = ""
    if last_resp is not None:
        body_preview = f" | status={last_resp.status_code} body={last_resp.text[:300]!r}"
    log.error(f"GIVING UP after {MAX_RETRIES} attempts on {url}{body_preview}")
    return None


def peek_total_count(url, query, extra_accept=None, delay=SEARCH_DELAY):
    resp = request_with_retry("GET", url, params={"q": query, "per_page": 1},
                               headers=gh_headers(extra_accept))
    time.sleep(delay)
    if resp is None:
        log.error(f"peek_total_count failed for query {query!r} — treating as 0, "
                  f"THIS WILL UNDERCOUNT if the failure was transient. Check the "
                  f"GIVING UP log line above for the real cause.")
        return 0
    if resp.status_code != 200:
        return 0
    return resp.json().get("total_count", 0)


def paginate_all(url, query, extra_accept=None, sort=None, delay=SEARCH_DELAY):
    items = []
    for page in range(1, 11):
        params = {"q": query, "per_page": 100, "page": page}
        if sort:
            params["sort"] = sort
        resp = request_with_retry("GET", url, params=params, headers=gh_headers(extra_accept))
        if resp is None:
            log.error(f"paginate_all aborted early for {query!r} at page {page} — "
                      f"results below are INCOMPLETE for this query")
            break
        if resp.status_code != 200:
            break
        data = resp.json()
        page_items = data.get("items", [])
        items.extend(page_items)
        if len(page_items) < 100:
            break
        time.sleep(delay)
    return items


# ============================================================
# Bisection: date / size / stars
# ============================================================

def bisect_by_date(url, base_query, date_field, start, end, extra_accept=None,
                    sort=None, delay=SEARCH_DELAY, depth=0):
    query = f"{base_query} {date_field}:{start.strftime('%Y-%m-%d')}..{end.strftime('%Y-%m-%d')}"
    total = peek_total_count(url, query, extra_accept, delay)
    width_days = (end - start).days
    is_leaf = total <= 1000 or width_days < DATE_MIN_LEAF_WIDTH_DAYS or depth >= DATE_MAX_DEPTH
    if is_leaf:
        if total > 1000:
            log.warning(f"cannot narrow further: {query!r} (total={total}, depth={depth})")
        items = paginate_all(url, query, extra_accept, sort, delay) if total > 0 else []
        return items, total
    mid = start + timedelta(days=width_days // 2)
    log.info(f"  splitting {start.date()}..{end.date()} ({total} results) at {mid.date()}")
    left, lt = bisect_by_date(url, base_query, date_field, start, mid, extra_accept, sort, delay, depth + 1)
    right, rt = bisect_by_date(url, base_query, date_field, mid, end, extra_accept, sort, delay, depth + 1)
    if abs((lt + rt) - total) > max(5, total * 0.05):
        log.warning(f"count reconciliation mismatch for {query!r}: parent={total}, children={lt+rt} "
                    f"(GitHub search total_count is approximate on some endpoints)")
    return left + right, lt + rt


def bisect_by_size(query_base, low, high, depth=0):
    query = f"{query_base} size:{low}..{high}"
    total = peek_total_count(SEARCH_CODE_URL, query, delay=SEARCH_DELAY)
    width = high - low
    is_leaf = total <= 1000 or width < SIZE_MIN_LEAF_WIDTH or depth >= SIZE_MAX_DEPTH
    if is_leaf:
        if total > 1000:
            log.warning(f"cannot narrow further: {query!r} (total={total}, depth={depth})")
        items = paginate_all(SEARCH_CODE_URL, query, delay=SEARCH_DELAY) if total > 0 else []
        return items, total
    mid = low + width // 2
    log.info(f"  splitting size {low}..{high} ({total} results) at {mid}")
    left, lt = bisect_by_size(query_base, low, mid, depth + 1)
    right, rt = bisect_by_size(query_base, mid + 1, high, depth + 1)
    return left + right, lt + rt


def bisect_by_stars(base_query, low, high, depth=0):
    query = f"{base_query} stars:{low}..{high}"
    total = peek_total_count(SEARCH_REPOS_URL, query, delay=REPO_SEARCH_DELAY)
    width = high - low
    is_leaf = total <= 1000 or width < STARS_MIN_LEAF_WIDTH or depth >= STARS_MAX_DEPTH
    if is_leaf:
        if total > 1000:
            log.warning(f"cannot narrow further: {query!r} (total={total}, depth={depth})")
        items = paginate_all(SEARCH_REPOS_URL, query, sort="stars", delay=REPO_SEARCH_DELAY) \
            if total > 0 else []
        return items, total
    mid = low + width // 2
    log.info(f"  splitting stars {low}..{high} ({total} results) at {mid}")
    left, lt = bisect_by_stars(base_query, low, mid, depth + 1)
    right, rt = bisect_by_stars(base_query, mid + 1, high, depth + 1)
    return left + right, lt + rt


# ============================================================
# Channels 1-4
# ============================================================

def channel_code_search(query):
    items, total = bisect_by_size(query, 0, CODE_SEARCH_MAX_INDEXED_BYTES)
    log.info(f"  total collected: {len(items)} (search reported ~{total})")
    return {item["repository"]["full_name"] for item in items}


def channel_commit_search(phrase):
    now = datetime.now(timezone.utc)
    items, total = bisect_by_date(
        SEARCH_COMMITS_URL, f'"{phrase}"', "committer-date",
        EARLIEST_GITHUB_DATE, now,
        extra_accept="application/vnd.github.cloak-preview+json",
    )
    log.info(f"  total collected: {len(items)} (search reported ~{total})")
    return {item["repository"]["full_name"] for item in items}


def channel_topic_search(topic):
    now = datetime.now(timezone.utc)
    items, total = bisect_by_date(
        SEARCH_REPOS_URL, f"topic:{topic}", "created",
        EARLIEST_GITHUB_DATE, now, sort="stars", delay=REPO_SEARCH_DELAY,
    )
    log.info(f"  total collected: {len(items)} (search reported ~{total})")
    return {item["full_name"] for item in items}


def channel_description_search(keyword):
    now = datetime.now(timezone.utc)
    items, total = bisect_by_date(
        SEARCH_REPOS_URL, f'"{keyword}" in:description', "created",
        EARLIEST_GITHUB_DATE, now, sort="stars", delay=REPO_SEARCH_DELAY,
    )
    log.info(f"  total collected: {len(items)} (search reported ~{total})")
    return {item["full_name"] for item in items}


# ============================================================
# Channel 5
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
    last_resp = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(GRAPHQL_URL, json={"query": query, "variables": variables},
                                  headers=gh_headers(), timeout=20)
        except requests.exceptions.RequestException as e:
            log.warning(f"GraphQL connection error (attempt {attempt}/{MAX_RETRIES}): {e}")
            time.sleep(RETRY_BACKOFF_BASE * attempt)
            continue

        last_resp = resp

        if resp.status_code in (403, 429) and "Retry-After" in resp.headers:
            wait = int(resp.headers["Retry-After"]) + 1
            log.info(f"GraphQL secondary rate limit, sleeping {wait}s (Retry-After)...")
            time.sleep(wait)
            continue

        if resp.status_code == 403 and "X-RateLimit-Reset" in resp.headers:
            reset = int(resp.headers["X-RateLimit-Reset"])
            wait = max(0, reset - int(time.time())) + 1
            log.info(f"GraphQL primary rate limit, sleeping {wait}s...")
            time.sleep(wait)
            continue

        if resp.status_code != 200:
            log.warning(f"GraphQL HTTP {resp.status_code}, retrying: {resp.text[:200]!r}")
            time.sleep(RETRY_BACKOFF_BASE * attempt)
            continue

        data = resp.json()
        if "errors" in data:
            err_types = {e.get("type") for e in data["errors"]}
            if "NOT_FOUND" in err_types:
                return None
            if "RATE_LIMITED" in err_types:
                log.info("GraphQL point budget exhausted, sleeping 60s...")
                time.sleep(60)
                continue
            log.warning(f"GraphQL errors, retrying: {data['errors']}")
            time.sleep(RETRY_BACKOFF_BASE * attempt)
            continue

        return data.get("data")

    body_preview = f" | status={last_resp.status_code} body={last_resp.text[:300]!r}" if last_resp else ""
    log.error(f"GraphQL GIVING UP after {MAX_RETRIES} attempts (org query){body_preview}")
    return None


def get_org_go_repos_graphql(org_login, max_pages=5):
    go_repos = []
    cursor = None
    for _ in range(max_pages):
        data = graphql_request(ORG_REPOS_LANGUAGES_QUERY, {"org": org_login, "cursor": cursor})
        time.sleep(GRAPHQL_DELAY)
        if data is None or data.get("organization") is None:
            break
        repo_conn = data["organization"]["repositories"]
        for node in repo_conn["nodes"]:
            go_size = next((e["size"] for e in node["languages"]["edges"]
                            if e["node"]["name"] == "Go"), 0)
            if go_size >= MIN_GO_BYTES_SIGNAL:
                go_repos.append({"repo": node["nameWithOwner"], "go_bytes": go_size,
                                  "stars": node["stargazerCount"]})
        page_info = repo_conn["pageInfo"]
        if not page_info["hasNextPage"]:
            break
        cursor = page_info["endCursor"]
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
        log.info(f"  bisecting seed search: {base_query} stars:>={LARGE_C_MIN_STARS}")
        items, total = bisect_by_stars(base_query, LARGE_C_MIN_STARS, 300_000)
        log.info(f"  {base_query}: {len(items)} repos collected (search reported ~{total})")
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

    log.info(f"  {len(seed_by_org)} unique organization owners among large C/C++ repos")

    state = load_channel5_checkpoint() if resume else {"checked_orgs": [], "candidates": {}}
    checked = set(state["checked_orgs"])
    candidates = state["candidates"]
    if resume:
        log.info(f"  resuming channel 5: {len(checked)} orgs already checked")

    remaining = {o: item for o, item in seed_by_org.items() if o not in checked}
    total_orgs = len(seed_by_org)

    for i, (owner, seed_item) in enumerate(remaining.items(), 1):
        log.info(f"  channel5 [{len(checked) + i}/{total_orgs}] checking org {owner} "
                 f"(seed {seed_item['full_name']}, {seed_item.get('stargazers_count', 0)} stars)...")
        go_repos = get_org_go_repos_graphql(owner)
        if go_repos:
            candidates[owner] = {
                "seed_c_repo": seed_item["full_name"],
                "seed_c_stars": seed_item.get("stargazers_count", 0),
                "go_repos": go_repos,
            }
            log.info(f"    -> HIT: {owner} has {len(go_repos)} substantial Go repo(s)")
        checked.add(owner)
        state["checked_orgs"] = list(checked)
        state["candidates"] = candidates
        save_channel5_checkpoint(state)

    return candidates


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Discover CGo/Go-migration targets — full recall, v5")
    parser.add_argument("--skip-channel5", action="store_true")
    parser.add_argument("--resume", action="store_true", help="resume channel 5 from checkpoint")
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
        f.write("# Auto-discovered targets (v5, full-recall) — unfiltered.\n")
        f.write(f"# Generated {datetime.now(timezone.utc).isoformat()}\n")
        for org in sorted(org_matches):
            f.write(f"{org}\n")

    log.info(f"=== DISCOVERY COMPLETE: {len(org_matches)} candidate orgs (unfiltered) ===")
    log.info(f"wrote {OUTPUT_JSON} and {OUTPUT_ORGS}")


if __name__ == "__main__":
    main()
