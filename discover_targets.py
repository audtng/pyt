#!/usr/bin/env python3
"""
Target discovery for the CGo migration scanner.

Instead of a hand-maintained org list, this searches GitHub GLOBALLY for
migration/cgo signal, then filters the resulting repo owners down to
plausible commercial targets:

  - owner is a GitHub Organization (not a personal account)
  - repo has enough stars to be a real, non-toy project
  - repo has a SECURITY.md (or similar) referencing a bounty platform
    (HackerOne / Bugcrowd / Intigriti) as a proxy for "runs a paid
    bounty program" — this is a heuristic, not a scope confirmation

Output: discovered_targets.json (full detail) + orgs.txt (one org per
line, ready for `cgo_scanner_v4.py --targets orgs.txt`).

USAGE:
    export GITHUB_TOKEN="ghp_..."
    python discover_targets.py
    python discover_targets.py --min-stars 500 --limit-queries 3
"""

import requests
import time
import os
import re
import json
import argparse
import logging
from datetime import datetime, timezone

API_ROOT = "https://api.github.com"
SEARCH_CODE_URL = f"{API_ROOT}/search/code"
SEARCH_COMMITS_URL = f"{API_ROOT}/search/commits"
SEARCH_REPOS_URL = f"{API_ROOT}/search/repositories"

SEARCH_DELAY = 7
FETCH_DELAY = 0.5
MAX_RETRIES = 4
RETRY_BACKOFF_BASE = 5

# Global (unscoped) queries used to discover candidate repos/owners.
# Kept short and high-signal — broad terms like bare "import \"C\"" would
# return too much noise (test fixtures, generated bindings, forks, etc.)
CODE_DISCOVERY_QUERIES = [
    'language:Go "import \\"C\\"" cgo migration',
    'language:Go "import \\"C\\"" "pure go" rewrite',
]

COMMIT_DISCOVERY_PHRASES = [
    "rewrite in go", "port to go", "replace cgo", "remove cgo",
    "pure go implementation",
]

BOUNTY_SIGNALS = ["hackerone.com", "bugcrowd.com", "intigriti.com"]
SECURITY_MD_PATHS = ["SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"]

OUTPUT_JSON = "discovered_targets.json"
OUTPUT_ORGS = "orgs.txt"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                     datefmt="%H:%M:%S")
log = logging.getLogger("discover_targets")


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
            log.warning(f"HTTP {resp.status_code} from {url}, retrying in {wait}s")
            time.sleep(wait)
            continue
        return resp
    log.error(f"giving up on {url}")
    return None


# ============================================================
# STEP 1: global discovery searches -> candidate repos
# ============================================================

def discover_via_code_search(query, max_pages=3):
    repos = set()
    for page in range(1, max_pages + 1):
        resp = request_with_retry(
            "GET", SEARCH_CODE_URL,
            params={"q": query, "per_page": 100, "page": page, "sort": "indexed"},
            headers=gh_headers(),
        )
        if resp is None or resp.status_code != 200:
            break
        items = resp.json().get("items", [])
        for item in items:
            repos.add(item["repository"]["full_name"])
        if len(items) < 100:
            break
        time.sleep(SEARCH_DELAY)
    return repos


def discover_via_commit_search(phrase, max_pages=2):
    repos = set()
    for page in range(1, max_pages + 1):
        resp = request_with_retry(
            "GET", SEARCH_COMMITS_URL,
            params={"q": f'"{phrase}"', "per_page": 100, "page": page},
            headers=gh_headers(extra_accept="application/vnd.github.cloak-preview+json"),
        )
        if resp is None or resp.status_code != 200:
            break
        items = resp.json().get("items", [])
        for item in items:
            repos.add(item["repository"]["full_name"])
        if len(items) < 100:
            break
        time.sleep(SEARCH_DELAY)
    return repos


# ============================================================
# STEP 2: filter candidates -> commercial-org targets
# ============================================================

def get_repo_info(repo_full_name):
    resp = request_with_retry("GET", f"{API_ROOT}/repos/{repo_full_name}", headers=gh_headers())
    if resp is None or resp.status_code != 200:
        return None
    return resp.json()


def get_owner_type(owner_login):
    resp = request_with_retry("GET", f"{API_ROOT}/users/{owner_login}", headers=gh_headers())
    if resp is None or resp.status_code != 200:
        return None
    return resp.json().get("type")  # "Organization" or "User"


def check_bounty_signal(repo_full_name):
    """Look for a SECURITY.md referencing a known bounty platform."""
    for path in SECURITY_MD_PATHS:
        resp = request_with_retry(
            "GET", f"{API_ROOT}/repos/{repo_full_name}/contents/{path}", headers=gh_headers(),
        )
        if resp is None or resp.status_code != 200:
            continue
        data = resp.json()
        if data.get("encoding") == "base64":
            import base64
            try:
                text = base64.b64decode(data["content"]).decode("utf-8", errors="ignore").lower()
            except Exception:
                continue
            for signal in BOUNTY_SIGNALS:
                if signal in text:
                    return signal
    return None


def evaluate_candidate(repo_full_name, min_stars):
    info = get_repo_info(repo_full_name)
    time.sleep(FETCH_DELAY)
    if info is None:
        return None

    stars = info.get("stargazers_count", 0)
    if stars < min_stars:
        return None

    owner_login = info["owner"]["login"]
    owner_type = get_owner_type(owner_login)
    time.sleep(FETCH_DELAY)
    if owner_type != "Organization":
        return None

    bounty_signal = check_bounty_signal(repo_full_name)
    time.sleep(FETCH_DELAY)

    return {
        "org": owner_login,
        "repo": repo_full_name,
        "stars": stars,
        "bounty_signal": bounty_signal,
        "description": info.get("description", ""),
    }


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Discover CGo-migration bug-bounty targets")
    parser.add_argument("--min-stars", type=int, default=300,
                         help="minimum repo stars to count as a real commercial project")
    parser.add_argument("--limit-queries", type=int, default=None,
                         help="only run the first N discovery queries (for testing)")
    parser.add_argument("--require-bounty-signal", action="store_true",
                         help="only keep orgs where a SECURITY.md references a bounty platform")
    args = parser.parse_args()

    if not os.environ.get("GITHUB_TOKEN"):
        log.warning("GITHUB_TOKEN not set — search endpoints require auth and will likely fail.")

    code_queries = CODE_DISCOVERY_QUERIES[: args.limit_queries]
    commit_phrases = COMMIT_DISCOVERY_PHRASES[: args.limit_queries]

    candidate_repos = set()

    log.info("=== running global code-search discovery ===")
    for q in code_queries:
        found = discover_via_code_search(q)
        log.info(f"  query {q!r}: {len(found)} repos")
        candidate_repos |= found
        time.sleep(SEARCH_DELAY)

    log.info("=== running global commit-search discovery ===")
    for phrase in commit_phrases:
        found = discover_via_commit_search(phrase)
        log.info(f"  phrase {phrase!r}: {len(found)} repos")
        candidate_repos |= found
        time.sleep(SEARCH_DELAY)

    log.info(f"{len(candidate_repos)} unique candidate repos before filtering")

    qualified = []
    for i, repo in enumerate(sorted(candidate_repos), 1):
        log.info(f"[{i}/{len(candidate_repos)}] evaluating {repo}")
        result = evaluate_candidate(repo, args.min_stars)
        if result is None:
            continue
        if args.require_bounty_signal and not result["bounty_signal"]:
            continue
        qualified.append(result)
        log.info(f"  -> QUALIFIED: org={result['org']} stars={result['stars']} "
                 f"bounty_signal={result['bounty_signal']}")

    # dedupe by org, keep the highest-star repo as representative, but track all hits
    orgs = {}
    for r in qualified:
        org = r["org"]
        if org not in orgs or r["stars"] > orgs[org]["stars"]:
            orgs[org] = r

    ranked = sorted(orgs.values(), key=lambda r: (bool(r["bounty_signal"]), r["stars"]),
                     reverse=True)

    with open(OUTPUT_JSON, "w") as f:
        json.dump(ranked, f, indent=2)

    with open(OUTPUT_ORGS, "w") as f:
        f.write("# Auto-discovered targets — review before use.\n")
        f.write(f"# Generated {datetime.now(timezone.utc).isoformat()}\n")
        f.write("# org_name  (stars, bounty_signal, representative repo)\n")
        for r in ranked:
            f.write(f"{r['org']}\n")

    log.info(f"=== DISCOVERY COMPLETE: {len(ranked)} candidate orgs ===")
    log.info(f"wrote {OUTPUT_JSON} and {OUTPUT_ORGS}")
    log.info("Review orgs.txt before feeding it to cgo_scanner_v4.py — "
             "confirm each org's actual bounty program scope manually.")


if __name__ == "__main__":
    main()
