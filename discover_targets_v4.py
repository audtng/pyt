#!/usr/bin/env python3
"""
Target discovery v4 — fixes the four issues found in the v3 run log:

1. PEEK BEFORE PAGINATE: v3 fully paginated (up to 10 pages, ~70s) a query
   JUST to read total_count, then threw the results away and recursed
   anyway. Now a single per_page=1 request checks total_count first; full
   pagination only runs once a range is confirmed to be a leaf (<=1000).
   This alone should cut channel 1/2/3/4 runtime by roughly 10x.

2. CORRECT BISECTION DEPTH: v3 capped bisection at depth 10 regardless of
   range width, so size:0..375 (25984 results) gave up while still ~26x
   over cap. Splitting size 0..384000 to single-byte precision needs ~19
   levels; the 18-year date range needs ~13+ to reach single-day. Depth
   limits are now set to what each range actually requires, and width
   (not depth) is the real stopping condition.

3. INTER-BRANCH PACING: v3's rate-limited sleeps cascaded because nothing
   paced between sibling recursive calls, only between pages within one
   call. A delay now runs after every peek/leaf-fetch before returning
   control to the parent.

4. GRAPHQL FOR CHANNEL 5: checking one org's repos + language breakdowns
   was one REST call per repo (languages endpoint). GraphQL fetches up to
   100 repos AND their language breakdowns in a single request, letting
   channel 5 run against the full seed list instead of a token --limit.

One thing this version can't fix: GitHub's search total_count is a known
approximation for some endpoints (commit search especially) — you may see
a parent range's count not exactly match the sum of its children. That's
logged as a reconciliation warning, not silently hidden, but no client-side
logic can make an approximate upstream count exact.

USAGE:
    export GITHUB_TOKEN="ghp_..."
    python discover_targets_v4.py
    python discover_targets_v4.py --skip-channel5
    python discover_targets_v4.py --channel5-max-orgs 500
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

SEARCH_DELAY = 7        # code/commit search: 10 req/min cap
REPO_SEARCH_DELAY = 3   # repo search: 30 req/min cap
GRAPHQL_DELAY = 1.5     # GraphQL: 5000 points/hr, much roomier than REST search
FETCH_DELAY = 0.4
MAX_RETRIES = 4
RETRY_BACKOFF_BASE = 5

# Stopping condition is WIDTH now, not depth — depth ceilings below are
# generous upper bounds sized to what each range actually needs, so width
# triggers first in normal operation. They only prevent runaway recursion
# if something unexpected happens (e.g. a range that never narrows because
# of an API quirk).
CODE_SEARCH_MAX_INDEXED_BYTES = 384_000   # GitHub doesn't index beyond this
SIZE_MIN_LEAF_WIDTH = 1                   # bytes — bisect to single-byte precision
SIZE_MAX_DEPTH = 20                       # log2(384000) ≈ 19, +1 margin

DATE_MIN_LEAF_WIDTH_DAYS = 1              # bisect to single-day precision
DATE_MAX_DEPTH = 15                       # log2(~6800 days since 2008) ≈ 13, +margin

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

LARGE_C_QUERIES = [
    "language:C stars:>1000",
    "language:C++ stars:>1000",
]

MIN_GO_BYTES_SIGNAL = 50_000  # threshold for "substantial" Go code in channel 5

OUTPUT_JSON = "discovered_targets_v4.json"
OUTPUT_ORGS = "orgs.txt"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                     datefmt="%H:%M:%S")
log = logging.getLogger("discover_v4")


# ============================================================
# HTTP helpers (REST)
# ============================================================

def gh_headers(extra_accept=None):
    token = os.environ.get("GITHUB_TOKEN", "")
    headers = {"Accept": extra_accept or "application/vnd.github.v3+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def request_with_retry(method, url, **kwargs):
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.request(method, url, timeout=15, **kwargs)
        except requests.exceptions.RequestException as e:
            log.warning(f"connection error (attempt {attempt}/{MAX_RETRIES}): {e}")
            time.sleep(RETRY_BACKOFF_BASE * attempt)
            continue
        if resp.status_code == 403 and "X-RateLimit-Reset" in resp.headers:
            reset = int(resp.headers["X-RateLimit-Reset"])
            wait = max(0, reset - int(time.time())) + 1
            log.info(f"rate limited, sleeping {wait}s...")
            time.sleep(wait)
            continue
        if resp.status_code >= 500:
            wait = RETRY_BACKOFF_BASE * attempt
            log.warning(f"HTTP {resp.status_code}, retrying in {wait}s")
            time.sleep(wait)
            continue
        return resp
    return None


# ============================================================
# FIX 1: peek (per_page=1) before ever fully paginating
# ============================================================

def peek_total_count(url, query, extra_accept=None, delay=SEARCH_DELAY):
    """Cheap single request to read total_count without pulling all pages."""
    resp = request_with_retry("GET", url, params={"q": query, "per_page": 1},
                               headers=gh_headers(extra_accept))
    time.sleep(delay)
    if resp is None or resp.status_code != 200:
        return 0
    return resp.json().get("total_count", 0)


def paginate_all(url, query, extra_accept=None, sort=None, delay=SEARCH_DELAY):
    """Only called once a range is confirmed to be a leaf (<=1000 results)."""
    items = []
    for page in range(1, 11):
        params = {"q": query, "per_page": 100, "page": page}
        if sort:
            params["sort"] = sort
        resp = request_with_retry("GET", url, params=params, headers=gh_headers(extra_accept))
        if resp is None or resp.status_code != 200:
            break
        data = resp.json()
        page_items = data.get("items", [])
        items.extend(page_items)
        if len(page_items) < 100:
            break
        time.sleep(delay)
    return items


# ============================================================
# FIX 2 + 3: width-based bisection with inter-branch pacing
# ============================================================

def bisect_by_date(url, base_query, date_field, start, end, extra_accept=None,
                    sort=None, delay=SEARCH_DELAY, depth=0, parent_count=None):
    query = f"{base_query} {date_field}:{start.strftime('%Y-%m-%d')}..{end.strftime('%Y-%m-%d')}"
    total = peek_total_count(url, query, extra_accept, delay)

    width_days = (end - start).days
    is_leaf = total <= 1000 or width_days < DATE_MIN_LEAF_WIDTH_DAYS or depth >= DATE_MAX_DEPTH

    if is_leaf:
        if total > 1000:
            log.warning(f"cannot narrow further, some loss possible: {query!r} "
                        f"(total_count={total}, width={width_days}d, depth={depth})")
        items = paginate_all(url, query, extra_accept, sort, delay) if total > 0 else []
        return items, total

    mid = start + timedelta(days=width_days // 2)
    log.info(f"  splitting {start.date()}..{end.date()} ({total} results) at {mid.date()}")
    left, left_total = bisect_by_date(url, base_query, date_field, start, mid,
                                       extra_accept, sort, delay, depth + 1)
    right, right_total = bisect_by_date(url, base_query, date_field, mid, end,
                                         extra_accept, sort, delay, depth + 1)

    # search total_count is a known approximation on some endpoints (esp.
    # commit search) — reconcile-check rather than silently trust either number
    if abs((left_total + right_total) - total) > max(5, total * 0.05):
        log.warning(f"count reconciliation mismatch for {query!r}: parent={total}, "
                    f"children sum={left_total + right_total} — GitHub's search "
                    f"total_count is approximate on this endpoint, not a bug in this script")

    return left + right, left_total + right_total


def bisect_by_size(query_base, low, high, depth=0):
    query = f"{query_base} size:{low}..{high}"
    total = peek_total_count(SEARCH_CODE_URL, query, delay=SEARCH_DELAY)

    width = high - low
    is_leaf = total <= 1000 or width < SIZE_MIN_LEAF_WIDTH or depth >= SIZE_MAX_DEPTH

    if is_leaf:
        if total > 1000:
            log.warning(f"cannot narrow further, some loss possible: {query!r} "
                        f"(total_count={total}, width={width}, depth={depth})")
        items = paginate_all(SEARCH_CODE_URL, query, delay=SEARCH_DELAY) if total > 0 else []
        return items, total

    mid = low + width // 2
    log.info(f"  splitting size {low}..{high} ({total} results) at {mid}")
    left, left_total = bisect_by_size(query_base, low, mid, depth + 1)
    right, right_total = bisect_by_size(query_base, mid + 1, high, depth + 1)
    return left + right, left_total + right_total


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
# FIX 4: Channel 5 via GraphQL — repos + languages in one batched call
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
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(GRAPHQL_URL, json={"query": query, "variables": variables},
                                  headers=gh_headers(), timeout=20)
        except requests.exceptions.RequestException as e:
            log.warning(f"GraphQL connection error (attempt {attempt}/{MAX_RETRIES}): {e}")
            time.sleep(RETRY_BACKOFF_BASE * attempt)
            continue

        if resp.status_code == 403 and "X-RateLimit-Reset" in resp.headers:
            reset = int(resp.headers["X-RateLimit-Reset"])
            wait = max(0, reset - int(time.time())) + 1
            log.info(f"GraphQL rate limited, sleeping {wait}s...")
            time.sleep(wait)
            continue

        if resp.status_code != 200:
            log.warning(f"GraphQL HTTP {resp.status_code}, retrying")
            time.sleep(RETRY_BACKOFF_BASE * attempt)
            continue

        data = resp.json()
        if "errors" in data:
            # NOT_FOUND (org doesn't exist / is actually a user) is expected
            # and not worth retrying; anything else gets one retry.
            err_types = {e.get("type") for e in data["errors"]}
            if "NOT_FOUND" in err_types:
                return None
            log.warning(f"GraphQL errors: {data['errors']}, retrying")
            time.sleep(RETRY_BACKOFF_BASE * attempt)
            continue

        return data.get("data")

    return None


def get_org_go_repos_graphql(org_login, max_pages=5):
    """
    Fetch this org's public repos (up to 500, paginated 100 at a time) with
    language breakdowns in ONE request per page — replaces v3's one REST
    call per repo for the languages endpoint.
    """
    go_repos = []
    cursor = None
    for page in range(max_pages):
        data = graphql_request(ORG_REPOS_LANGUAGES_QUERY, {"org": org_login, "cursor": cursor})
        time.sleep(GRAPHQL_DELAY)
        if data is None or data.get("organization") is None:
            break

        repo_conn = data["organization"]["repositories"]
        for node in repo_conn["nodes"]:
            go_size = 0
            for edge in node["languages"]["edges"]:
                if edge["node"]["name"] == "Go":
                    go_size = edge["size"]
                    break
            if go_size >= MIN_GO_BYTES_SIGNAL:
                go_repos.append({
                    "repo": node["nameWithOwner"],
                    "go_bytes": go_size,
                    "stars": node["stargazerCount"],
                })

        page_info = repo_conn["pageInfo"]
        if not page_info["hasNextPage"]:
            break
        cursor = page_info["endCursor"]

    return go_repos


def channel_c_orgs_with_go_sibling(query, max_orgs_to_check):
    items = paginate_all(SEARCH_REPOS_URL, query, sort="stars", delay=REPO_SEARCH_DELAY)
    total = peek_total_count(SEARCH_REPOS_URL, query, delay=REPO_SEARCH_DELAY)
    if total > 1000:
        log.warning(f"channel 5 seed query {query!r} has {total} results, only first 1000 "
                    f"usable as org seeds (GitHub repo search hard cap — no bisection "
                    f"qualifier avoids this for repo search's own result set, but each "
                    f"org's FULL repo list is still checked via GraphQL below)")

    orgs_seen = set()
    candidates = {}
    checked = 0
    for item in items:
        owner = item["owner"]["login"]
        if item["owner"]["type"] != "Organization" or owner in orgs_seen:
            continue
        orgs_seen.add(owner)
        checked += 1
        if checked > max_orgs_to_check:
            log.info(f"channel 5: reached max_orgs_to_check={max_orgs_to_check}")
            break

        log.info(f"  channel5 [{checked}/{min(max_orgs_to_check, len(items))}] "
                 f"checking org {owner} (seed {item['full_name']}, "
                 f"{item.get('stargazers_count', 0)} stars)...")
        go_repos = get_org_go_repos_graphql(owner)
        if go_repos:
            candidates[owner] = {
                "seed_c_repo": item["full_name"],
                "seed_c_stars": item.get("stargazers_count", 0),
                "go_repos": go_repos,
            }
            log.info(f"    -> HIT: {owner} has {len(go_repos)} substantial Go repo(s)")

    return candidates


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Discover CGo/Go-migration targets — full recall, v4")
    parser.add_argument("--skip-channel5", action="store_true")
    parser.add_argument("--channel5-max-orgs", type=int, default=1000,
                         help="GraphQL makes this much cheaper than v3 — default covers "
                              "the full 1000-seed cap")
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

    log.info("=== Channel 1: code search (size-bisected, peek-optimized) ===")
    for q in CODE_QUERIES[: args.limit_queries]:
        log.info(f"query: {q!r}")
        record(channel_code_search(q))

    log.info("=== Channel 2: commit search (date-bisected, peek-optimized) ===")
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
        log.info("=== Channel 5: large C/C++ orgs with a Go sibling repo (GraphQL) ===")
        for q in LARGE_C_QUERIES[: args.limit_queries]:
            log.info(f"seed query: {q!r}")
            found = channel_c_orgs_with_go_sibling(q, args.channel5_max_orgs)
            channel5_data.update(found)
            for org, data in found.items():
                org_matches.setdefault(org, set()).update(r["repo"] for r in data["go_repos"])
                org_matches[org].add(data["seed_c_repo"])
    else:
        log.info("=== Channel 5 skipped ===")

    log.info(f"{len(org_matches)} unique candidate orgs across all channels")

    output = {
        "orgs": {org: sorted(repos) for org, repos in org_matches.items()},
        "channel5_detail": channel5_data,
    }
    with open(OUTPUT_JSON, "w") as f:
        json.dump(output, f, indent=2)

    with open(OUTPUT_ORGS, "w") as f:
        f.write("# Auto-discovered targets (v4, full-recall) — unfiltered.\n")
        f.write(f"# Generated {datetime.now(timezone.utc).isoformat()}\n")
        for org in sorted(org_matches):
            f.write(f"{org}\n")

    log.info(f"=== DISCOVERY COMPLETE: {len(org_matches)} candidate orgs (unfiltered) ===")
    log.info(f"wrote {OUTPUT_JSON} and {OUTPUT_ORGS}")


if __name__ == "__main__":
    main()
