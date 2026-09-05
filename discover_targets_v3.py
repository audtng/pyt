#!/usr/bin/env python3
"""
Target discovery v3 — optimized for COMPLETE RECALL. No filtering happens
here; everything found gets kept. Run migration_activity_scanner.py
afterward to rank/filter by how ACTIVE each candidate is.

Two structural fixes over v2:

1. AUTOMATIC QUERY BISECTION. v2 detected when a query exceeded GitHub's
   1000-result cap but just logged a warning and silently dropped the rest.
   This version actually splits an over-cap query in two (by date range for
   commit/repo search, by file size for code search — code search has no
   date qualifier) and recurses until every sub-query fits under the cap.
   This is the only way to get ALL results for a popular query, not just
   the first 1000.

2. A KEYWORD-INDEPENDENT CHANNEL. Every other channel requires the org to
   have used specific words ("rewrite", "cgo") or tags. An org that migrated
   without ever saying so in a commit message or topic is invisible to all
   of them. Channel 5 instead finds large C/C++ repos, then checks each
   org's OTHER repos for a substantial Go codebase via the languages
   breakdown — a purely structural signal, no text matching at all.

USAGE:
    export GITHUB_TOKEN="ghp_..."
    python discover_targets_v3.py
    python discover_targets_v3.py --skip-channel5   # faster, skips the
                                                       # heaviest channel
"""

import requests
import time
import os
import json
import argparse
import logging
from datetime import datetime, timedelta, timezone

API_ROOT = "https://api.github.com"
SEARCH_CODE_URL = f"{API_ROOT}/search/code"
SEARCH_COMMITS_URL = f"{API_ROOT}/search/commits"
SEARCH_REPOS_URL = f"{API_ROOT}/search/repositories"

SEARCH_DELAY = 7        # code/commit search: 10 req/min cap
REPO_SEARCH_DELAY = 3   # repo search: 30 req/min cap
FETCH_DELAY = 0.4
MAX_RETRIES = 4
RETRY_BACKOFF_BASE = 5
MAX_BISECT_DEPTH = 10   # 2^10 = 1024 sub-ranges ceiling, plenty

# GitHub code search excludes files over ~384KB from its index entirely,
# so that's the real upper bound for size-based bisection — no point
# splitting further than the space that's actually indexed.
CODE_SEARCH_MAX_INDEXED_BYTES = 384_000

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

# Channel 5: seed queries for large C/C++ projects to check for sibling Go repos
LARGE_C_QUERIES = [
    "language:C stars:>1000",
    "language:C++ stars:>1000",
]

OUTPUT_JSON = "discovered_targets_v3.json"
OUTPUT_ORGS = "orgs.txt"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                     datefmt="%H:%M:%S")
log = logging.getLogger("discover_v3")


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


def paginate_all(url, query, extra_accept=None, sort=None, delay=SEARCH_DELAY):
    """Fetch every page up to GitHub's 1000-result cap. Returns (items, total_count)."""
    items = []
    total_count = None
    for page in range(1, 11):  # 10 pages * 100 = 1000, the hard cap
        params = {"q": query, "per_page": 100, "page": page}
        if sort:
            params["sort"] = sort
        resp = request_with_retry("GET", url, params=params, headers=gh_headers(extra_accept))
        if resp is None or resp.status_code != 200:
            break
        data = resp.json()
        total_count = data.get("total_count", 0)
        page_items = data.get("items", [])
        items.extend(page_items)
        if len(page_items) < 100:
            break
        time.sleep(delay)
    return items, (total_count if total_count is not None else len(items))


# ============================================================
# Bisection: date-based (commit search, repo search)
# ============================================================

def bisect_by_date(url, base_query, date_field, start, end, extra_accept=None,
                    sort=None, delay=SEARCH_DELAY, depth=0):
    """
    Recursively split [start, end) on `date_field` until every sub-query's
    total_count fits under 1000, guaranteeing full recall instead of a
    silently truncated first-1000.
    """
    query = f"{base_query} {date_field}:{start.strftime('%Y-%m-%d')}..{end.strftime('%Y-%m-%d')}"
    items, total = paginate_all(url, query, extra_accept, sort, delay)

    if total <= 1000 or depth >= MAX_BISECT_DEPTH or (end - start).days < 1:
        if total > 1000:
            log.warning(f"query still over cap at max bisect depth, some loss possible: {query!r} "
                        f"(total_count={total})")
        else:
            log.info(f"  [{query}] {total} results (complete)")
        return items

    mid = start + (end - start) / 2
    log.info(f"  splitting {start.date()}..{end.date()} ({total} results) at {mid.date()}")
    left = bisect_by_date(url, base_query, date_field, start, mid, extra_accept, sort, delay, depth + 1)
    right = bisect_by_date(url, base_query, date_field, mid, end, extra_accept, sort, delay, depth + 1)
    return left + right


# ============================================================
# Bisection: size-based (code search — no date qualifier available)
# ============================================================

def bisect_by_size(query_base, low, high, depth=0):
    query = f"{query_base} size:{low}..{high}"
    items, total = paginate_all(SEARCH_CODE_URL, query, delay=SEARCH_DELAY)

    if total <= 1000 or depth >= MAX_BISECT_DEPTH or high - low < 10:
        if total > 1000:
            log.warning(f"code query still over cap at max bisect depth: {query!r} "
                        f"(total_count={total})")
        else:
            log.info(f"  [{query}] {total} results (complete)")
        return items

    mid = (low + high) // 2
    log.info(f"  splitting size {low}..{high} ({total} results) at {mid}")
    left = bisect_by_size(query_base, low, mid, depth + 1)
    right = bisect_by_size(query_base, mid + 1, high, depth + 1)
    return left + right


# ============================================================
# Channels 1-4 (same querysets as v2, now with full-recall bisection)
# ============================================================

def channel_code_search(query):
    items = bisect_by_size(query, 0, CODE_SEARCH_MAX_INDEXED_BYTES)
    return {item["repository"]["full_name"] for item in items}


def channel_commit_search(phrase):
    now = datetime.now(timezone.utc)
    items = bisect_by_date(
        SEARCH_COMMITS_URL, f'"{phrase}"', "committer-date",
        EARLIEST_GITHUB_DATE, now,
        extra_accept="application/vnd.github.cloak-preview+json",
    )
    return {item["repository"]["full_name"] for item in items}


def channel_topic_search(topic):
    now = datetime.now(timezone.utc)
    items = bisect_by_date(
        SEARCH_REPOS_URL, f"topic:{topic}", "created",
        EARLIEST_GITHUB_DATE, now, sort="stars", delay=REPO_SEARCH_DELAY,
    )
    return {item["full_name"] for item in items}


def channel_description_search(keyword):
    now = datetime.now(timezone.utc)
    items = bisect_by_date(
        SEARCH_REPOS_URL, f'"{keyword}" in:description', "created",
        EARLIEST_GITHUB_DATE, now, sort="stars", delay=REPO_SEARCH_DELAY,
    )
    return {item["full_name"] for item in items}


# ============================================================
# Channel 5: keyword-independent — large C/C++ orgs with a sibling Go repo
# ============================================================

def get_org_languages_summary(org_login, max_repos=30):
    """Check whether this org has any repo with substantial Go code."""
    resp = request_with_retry(
        "GET", f"{API_ROOT}/orgs/{org_login}/repos",
        params={"per_page": max_repos, "sort": "pushed", "type": "public"},
        headers=gh_headers(),
    )
    time.sleep(FETCH_DELAY)
    if resp is None or resp.status_code != 200:
        return []
    repos = resp.json()

    go_repos = []
    for r in repos:
        lang_resp = request_with_retry(
            "GET", f"{API_ROOT}/repos/{r['full_name']}/languages", headers=gh_headers(),
        )
        time.sleep(FETCH_DELAY)
        if lang_resp is None or lang_resp.status_code != 200:
            continue
        langs = lang_resp.json()
        go_bytes = langs.get("Go", 0)
        if go_bytes > 50_000:  # meaningful amount of Go, not a stray script
            go_repos.append({"repo": r["full_name"], "go_bytes": go_bytes,
                              "stars": r.get("stargazers_count", 0)})
    return go_repos


def channel_c_orgs_with_go_sibling(query, max_orgs_to_check=100):
    """
    Find large C/C++ repos, then for each owning ORG (not user), check
    whether it also has a substantial Go repo elsewhere — independent of
    any migration keyword or topic tag.
    """
    items, total = paginate_all(SEARCH_REPOS_URL, query, sort="stars", delay=REPO_SEARCH_DELAY)
    if total > 1000:
        log.warning(f"channel 5 seed query {query!r} has {total} results, only first 1000 "
                    f"considered as org seeds (still checks each org's FULL repo list though)")

    orgs_seen = set()
    candidates = {}
    checked = 0
    for item in items:
        owner = item["owner"]["login"]
        if item["owner"]["type"] != "Organization":
            continue
        if owner in orgs_seen:
            continue
        orgs_seen.add(owner)
        checked += 1
        if checked > max_orgs_to_check:
            log.info(f"channel 5: reached max_orgs_to_check={max_orgs_to_check}, stopping "
                     f"(raise this limit for more coverage at higher API cost)")
            break

        log.info(f"  channel5 checking org {owner} (seed repo {item['full_name']}, "
                 f"{item.get('stargazers_count', 0)} stars)...")
        go_repos = get_org_languages_summary(owner)
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
    parser = argparse.ArgumentParser(description="Discover CGo/Go-migration targets — full recall")
    parser.add_argument("--skip-channel5", action="store_true",
                         help="skip the large-C-org/Go-sibling channel (much cheaper, less recall)")
    parser.add_argument("--channel5-max-orgs", type=int, default=100,
                         help="cap how many orgs channel 5 deep-checks (cost control)")
    parser.add_argument("--limit-queries", type=int, default=None,
                         help="cap queries per channel, for testing")
    args = parser.parse_args()

    if not os.environ.get("GITHUB_TOKEN"):
        log.warning("GITHUB_TOKEN not set — search endpoints require auth.")

    org_matches = {}  # org -> set of matched repo full_names
    channel5_data = {}

    def record(repos):
        for full_name in repos:
            if "/" not in full_name:
                continue
            owner = full_name.split("/")[0]
            org_matches.setdefault(owner, set()).add(full_name)

    log.info("=== Channel 1: code search (size-bisected for full recall) ===")
    for q in CODE_QUERIES[: args.limit_queries]:
        log.info(f"query: {q!r}")
        found = channel_code_search(q)
        log.info(f"  total: {len(found)} repos")
        record(found)

    log.info("=== Channel 2: commit search (date-bisected for full recall) ===")
    for p in COMMIT_PHRASES[: args.limit_queries]:
        log.info(f"phrase: {p!r}")
        found = channel_commit_search(p)
        log.info(f"  total: {len(found)} repos")
        record(found)

    log.info("=== Channel 3: topic search (date-bisected) ===")
    for t in TOPIC_QUERIES[: args.limit_queries]:
        log.info(f"topic: {t!r}")
        found = channel_topic_search(t)
        log.info(f"  total: {len(found)} repos")
        record(found)

    log.info("=== Channel 4: description search (date-bisected) ===")
    for kw in DESCRIPTION_KEYWORDS[: args.limit_queries]:
        log.info(f"keyword: {kw!r}")
        found = channel_description_search(kw)
        log.info(f"  total: {len(found)} repos")
        record(found)

    if not args.skip_channel5:
        log.info("=== Channel 5: large C/C++ orgs with a Go sibling repo (keyword-independent) ===")
        for q in LARGE_C_QUERIES[: args.limit_queries]:
            log.info(f"seed query: {q!r}")
            found = channel_c_orgs_with_go_sibling(q, args.channel5_max_orgs)
            channel5_data.update(found)
            for org, data in found.items():
                org_matches.setdefault(org, set()).update(
                    r["repo"] for r in data["go_repos"])
                org_matches[org].add(data["seed_c_repo"])
    else:
        log.info("=== Channel 5 skipped (--skip-channel5) ===")

    log.info(f"{len(org_matches)} unique candidate orgs across all channels")

    output = {
        "orgs": {org: sorted(repos) for org, repos in org_matches.items()},
        "channel5_detail": channel5_data,
    }
    with open(OUTPUT_JSON, "w") as f:
        json.dump(output, f, indent=2)

    with open(OUTPUT_ORGS, "w") as f:
        f.write("# Auto-discovered targets (v3, full-recall) — unfiltered.\n")
        f.write(f"# Generated {datetime.now(timezone.utc).isoformat()}\n")
        f.write("# Run migration_activity_scanner.py against this list to rank by activity.\n")
        for org in sorted(org_matches):
            f.write(f"{org}\n")

    log.info(f"=== DISCOVERY COMPLETE: {len(org_matches)} candidate orgs (unfiltered) ===")
    log.info(f"wrote {OUTPUT_JSON} and {OUTPUT_ORGS}")


if __name__ == "__main__":
    main()
