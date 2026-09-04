#!/usr/bin/env python3
"""
CGo migration scanner — targets repos where C/C++ -> Go migration is
ACTIVELY HAPPENING (not just repos that happen to contain cgo), on the
thesis that fresh, time-pressured boundary code is a higher-yield audit
target than long-stable bindings.

Pipeline per org:
  1. code search:    find files with `import "C"` (candidate bridges)
  2. commit search:  find commits whose message signals a migration
                      ("rewrite in go", "port to go", "replace C with Go", ...)
  3. co-evolution:   for top candidate repos, check whether recent commits
                      touch BOTH .go and .c/.h files — the transitional zone
  4. risk-score      the matched bridge files' content
  5. output          per-org Markdown audit worksheet + JSON/CSV

USAGE:
    export GITHUB_TOKEN="ghp_..."
    python cgo_scanner_v4.py --targets orgs.txt
    python cgo_scanner_v4.py --targets orgs.txt --limit 5 --dry-run
    python cgo_scanner_v4.py --targets orgs.txt --resume
"""

import requests
import time
import os
import re
import json
import csv
import sys
import argparse
import logging
import base64
from datetime import datetime, timezone

# ============================================================
# CONFIG
# ============================================================

API_ROOT = "https://api.github.com"
SEARCH_CODE_URL = f"{API_ROOT}/search/code"
SEARCH_COMMITS_URL = f"{API_ROOT}/search/commits"

SEARCH_DELAY = 7
FETCH_DELAY = 0.5
MAX_RETRIES = 4
RETRY_BACKOFF_BASE = 5

MAX_REPOS_PER_ORG = 8
MAX_FILES_PER_REPO = 5
MAX_COMMITS_TO_INSPECT = 15   # for co-evolution check, per repo

SKIP_PATH_PATTERNS = [
    r"/vendor/", r"_test\.go$", r"\.pb\.go$", r"/testdata/",
    r"/third_party/", r"/examples?/",
]

RISK_PATTERNS = {
    "manual_malloc_free": r"C\.(malloc|free|realloc)\s*\(",
    "unsafe_pointer": r"unsafe\.Pointer",
    "cgo_handle": r"cgo\.(NewHandle|Handle)",
    "manual_memcpy": r"C\.memcpy|C\.memmove",
    "string_to_c": r"C\.CString|C\.GoString|C\.GoBytes",
    "slice_from_c_ptr": r"unsafe\.Slice\(",
    "pointer_arithmetic": r"uintptr\(unsafe\.Pointer",
}

# Commit-message phrases suggesting an active C/C++ -> Go migration
MIGRATION_KEYWORDS = [
    "rewrite in go", "rewritten in go", "port to go", "porting to go",
    "migrate to go", "migrating to go", "replace c with go",
    "replace cgo", "remove cgo", "drop cgo", "cgo removal",
    "pure go implementation", "convert to go",
]

C_SOURCE_EXT = (".c", ".h", ".cc", ".cpp", ".hpp", ".cxx")

CHECKPOINT_FILE = "cgo_migration_checkpoint.json"
OUTPUT_JSON = "cgo_migration_results.json"
OUTPUT_CSV = "cgo_migration_results.csv"
WORKSHEET_DIR = "audit_worksheets"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s",
                     datefmt="%H:%M:%S")
log = logging.getLogger("cgo_migration_scanner")


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
            log.warning(f"HTTP {resp.status_code} from {url}, retrying in {wait}s")
            time.sleep(wait)
            continue

        return resp

    log.error(f"giving up on {url} after {MAX_RETRIES} attempts")
    return None


def is_noise_path(path):
    return any(re.search(pat, path) for pat in SKIP_PATH_PATTERNS)


# ============================================================
# STEP 1: cgo bridge code search (paginated)
# ============================================================

def search_cgo_files(org_name):
    query = f'org:{org_name} language:Go "import \\"C\\""'
    all_items = []
    page = 1
    while True:
        params = {"q": query, "per_page": 100, "page": page}
        resp = request_with_retry("GET", SEARCH_CODE_URL, params=params, headers=gh_headers())
        if resp is None or resp.status_code != 200:
            break
        data = resp.json()
        items = data.get("items", [])
        for item in items:
            path = item.get("path", "")
            if is_noise_path(path):
                continue
            all_items.append({
                "repo": item["repository"]["full_name"],
                "path": path,
                "html_url": item.get("html_url", ""),
            })
        if len(items) < 100 or page >= 10:
            break
        page += 1
        time.sleep(SEARCH_DELAY)
    return all_items


# ============================================================
# STEP 2: migration-signal commit search
# ============================================================

def search_migration_commits(org_name):
    """Search commit messages for migration language, scoped to the org."""
    hits = []
    priority_phrases = ["rewrite in go", "port to go", "replace cgo", "remove cgo"]

    for phrase in priority_phrases:
        query = f'org:{org_name} "{phrase}"'
        resp = request_with_retry(
            "GET", SEARCH_COMMITS_URL, params={"q": query, "per_page": 20},
            headers=gh_headers(extra_accept="application/vnd.github.cloak-preview+json"),
        )
        time.sleep(SEARCH_DELAY)
        if resp is None or resp.status_code != 200:
            continue
        data = resp.json()
        for item in data.get("items", []):
            hits.append({
                "repo": item["repository"]["full_name"],
                "sha": item["sha"][:7],
                "message": item["commit"]["message"].splitlines()[0][:120],
                "date": item["commit"]["committer"]["date"],
                "url": item["html_url"],
                "matched_phrase": phrase,
            })
    return hits


# ============================================================
# STEP 3: C/Go co-evolution — recent commits touching both languages
# ============================================================

def check_coevolution(repo_full_name):
    """
    Look at the most recent commits on the repo's default branch and check
    whether both Go and C/C++ files are being actively touched — the
    transitional-migration signature.
    """
    resp = request_with_retry(
        "GET", f"{API_ROOT}/repos/{repo_full_name}/commits",
        params={"per_page": MAX_COMMITS_TO_INSPECT}, headers=gh_headers(),
    )
    if resp is None or resp.status_code != 200:
        return None

    commits = resp.json()
    touched_go = False
    touched_c = False
    newest_date = None
    oldest_date = None

    for c in commits:
        sha = c["sha"]
        detail = request_with_retry(
            "GET", f"{API_ROOT}/repos/{repo_full_name}/commits/{sha}", headers=gh_headers(),
        )
        time.sleep(FETCH_DELAY)
        if detail is None or detail.status_code != 200:
            continue
        files = detail.json().get("files", [])
        for f in files:
            fname = f.get("filename", "")
            if fname.endswith(".go"):
                touched_go = True
            elif fname.endswith(C_SOURCE_EXT):
                touched_c = True

        date_str = c["commit"]["committer"]["date"]
        if newest_date is None:
            newest_date = date_str
        oldest_date = date_str

    return {
        "coevolving": touched_go and touched_c,
        "touched_go": touched_go,
        "touched_c": touched_c,
        "window_newest": newest_date,
        "window_oldest": oldest_date,
        "commits_inspected": len(commits),
    }


# ============================================================
# STEP 4: fetch + risk-score bridge files
# ============================================================

def fetch_raw_file(repo_full_name, path):
    url = f"{API_ROOT}/repos/{repo_full_name}/contents/{path}"
    resp = request_with_retry("GET", url, headers=gh_headers(), params={"ref": "HEAD"})
    if resp is None or resp.status_code != 200:
        return None
    data = resp.json()
    if data.get("encoding") == "base64":
        try:
            return base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        except Exception:
            return None
    return None


def score_and_snippet(content):
    """Return {label: {count, snippet, line}} — risk hits with surrounding context."""
    lines = content.splitlines()
    hits = {}
    for label, pattern in RISK_PATTERNS.items():
        matches = list(re.finditer(pattern, content))
        if not matches:
            continue
        first_match_pos = matches[0].start()
        line_no = content.count("\n", 0, first_match_pos)
        start = max(0, line_no - 2)
        end = min(len(lines), line_no + 3)
        snippet = "\n".join(lines[start:end])
        hits[label] = {"count": len(matches), "snippet": snippet, "line": line_no + 1}
    return hits


def last_commit_info(repo_full_name, path):
    resp = request_with_retry(
        "GET", f"{API_ROOT}/repos/{repo_full_name}/commits",
        params={"path": path, "per_page": 1}, headers=gh_headers(),
    )
    if resp is None or resp.status_code != 200:
        return None
    commits = resp.json()
    if not commits:
        return None
    commit = commits[0]
    date_str = commit["commit"]["committer"]["date"]
    dt = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    days_ago = (datetime.now(timezone.utc) - dt).days
    return {"sha": commit["sha"][:7], "date": date_str, "days_ago": days_ago}


# ============================================================
# ORG-LEVEL ORCHESTRATION
# ============================================================

def scan_org(org_name, dry_run=False):
    log.info(f"scanning org: {org_name}")

    cgo_matches = search_cgo_files(org_name)
    migration_commits = search_migration_commits(org_name)

    if not cgo_matches and not migration_commits:
        log.info(f"  no cgo files or migration commits found for {org_name}")
        return {"org": org_name, "repos": {}, "migration_commits": []}

    repo_counts = {}
    for m in cgo_matches:
        repo_counts[m["repo"]] = repo_counts.get(m["repo"], 0) + 1
    migration_repos = {c["repo"] for c in migration_commits}
    for r in migration_repos:
        repo_counts[r] = repo_counts.get(r, 0) + 5  # weight migration signal heavily

    top_repos = sorted(repo_counts, key=repo_counts.get, reverse=True)[:MAX_REPOS_PER_ORG]
    log.info(f"  {len(cgo_matches)} cgo files, {len(migration_commits)} migration commits, "
             f"{len(top_repos)} priority repos")

    org_data = {"org": org_name, "repos": {}, "migration_commits": migration_commits}

    if dry_run:
        for r in top_repos:
            org_data["repos"][r] = {"dry_run": True}
        return org_data

    for repo in top_repos:
        log.info(f"  inspecting repo: {repo}")
        coevo = check_coevolution(repo)
        time.sleep(FETCH_DELAY)

        repo_files = [m for m in cgo_matches if m["repo"] == repo][:MAX_FILES_PER_REPO]
        files_out = []
        for item in repo_files:
            time.sleep(FETCH_DELAY)
            content = fetch_raw_file(repo, item["path"])
            if content is None:
                continue
            hits = score_and_snippet(content)
            time.sleep(FETCH_DELAY)
            commit_info = last_commit_info(repo, item["path"])
            files_out.append({
                "path": item["path"],
                "url": item["html_url"],
                "risk_score": sum(h["count"] for h in hits.values()),
                "risk_hits": hits,
                "last_commit": commit_info,
            })
            if hits:
                recency = f"{commit_info['days_ago']}d ago" if commit_info else "unknown"
                log.info(f"    [HIT] {item['path']} "
                         f"score={sum(h['count'] for h in hits.values())} last={recency}")

        org_data["repos"][repo] = {
            "coevolution": coevo,
            "migration_commit_count": sum(1 for c in migration_commits if c["repo"] == repo),
            "files": files_out,
        }

    return org_data


# ============================================================
# OUTPUT: JSON / CSV / Markdown worksheets
# ============================================================

def flatten_for_csv(all_org_data):
    rows = []
    for org_data in all_org_data:
        org = org_data["org"]
        for repo, rdata in org_data["repos"].items():
            if rdata.get("dry_run"):
                continue
            coevo = rdata.get("coevolution") or {}
            for f in rdata.get("files", []):
                days_ago = f["last_commit"]["days_ago"] if f.get("last_commit") else ""
                rows.append([
                    org, repo, f["path"], f["risk_score"],
                    ";".join(f"{k}={v['count']}" for k, v in f["risk_hits"].items()),
                    days_ago, coevo.get("coevolving", False),
                    rdata.get("migration_commit_count", 0), f["url"],
                ])
    rows.sort(key=lambda r: r[3], reverse=True)
    return rows


def write_json_csv(all_org_data):
    with open(OUTPUT_JSON, "w") as f:
        json.dump(all_org_data, f, indent=2)

    rows = flatten_for_csv(all_org_data)
    with open(OUTPUT_CSV, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["org", "repo", "path", "risk_score", "risk_hits",
                          "last_commit_days_ago", "coevolving_c_go",
                          "migration_commit_count", "url"])
        writer.writerows(rows)
    log.info(f"wrote {OUTPUT_JSON} and {OUTPUT_CSV} ({len(rows)} flagged files)")


def write_worksheets(all_org_data):
    os.makedirs(WORKSHEET_DIR, exist_ok=True)
    for org_data in all_org_data:
        org = org_data["org"]
        has_content = any(
            not r.get("dry_run") for r in org_data["repos"].values()
        ) or org_data["migration_commits"]
        if not has_content:
            continue

        path = os.path.join(WORKSHEET_DIR, f"{org}.md")
        with open(path, "w") as f:
            f.write(f"# Audit worksheet: {org}\n\n")
            f.write(f"_Generated {datetime.now(timezone.utc).isoformat()}_\n\n")

            if org_data["migration_commits"]:
                f.write("## Migration-signal commits\n\n")
                for c in org_data["migration_commits"]:
                    f.write(f"- `{c['sha']}` **{c['repo']}** — \"{c['message']}\" "
                            f"({c['date']}, matched: *{c['matched_phrase']}*)\n"
                            f"  {c['url']}\n")
                f.write("\n")

            for repo, rdata in org_data["repos"].items():
                if rdata.get("dry_run"):
                    continue
                f.write(f"## {repo}\n\n")
                coevo = rdata.get("coevolution")
                if coevo:
                    flag = "YES — active C/Go co-evolution" if coevo["coevolving"] else "no"
                    f.write(f"**Co-evolution signal:** {flag}  \n")
                    f.write(f"(inspected last {coevo['commits_inspected']} commits: "
                            f"touched .go={coevo['touched_go']}, "
                            f"touched .c/.h={coevo['touched_c']})\n\n")
                f.write(f"**Migration commits referencing this repo:** "
                        f"{rdata.get('migration_commit_count', 0)}\n\n")

                for file_entry in rdata.get("files", []):
                    f.write(f"### `{file_entry['path']}`\n\n")
                    f.write(f"- Score: {file_entry['risk_score']}\n")
                    lc = file_entry.get("last_commit")
                    f.write(f"- Last touched: {lc['days_ago']}d ago ({lc['sha']})\n" if lc
                            else "- Last touched: unknown\n")
                    f.write(f"- {file_entry['url']}\n\n")
                    for label, hit in file_entry["risk_hits"].items():
                        f.write(f"**{label}** (x{hit['count']}, around line {hit['line']}):\n")
                        f.write("```go\n" + hit["snippet"] + "\n```\n\n")
                    f.write("**Notes:** _(fill in during review)_\n\n---\n\n")

        log.info(f"wrote worksheet: {path}")


# ============================================================
# Targets / checkpoint
# ============================================================

def load_targets_from_file(path):
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def load_checkpoint():
    if os.path.exists(CHECKPOINT_FILE):
        with open(CHECKPOINT_FILE) as f:
            return json.load(f)
    return {"completed_orgs": [], "results": []}


def save_checkpoint(state):
    with open(CHECKPOINT_FILE, "w") as f:
        json.dump(state, f, indent=2)


# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="CGo migration-focused bug-bounty recon scanner")
    parser.add_argument("--targets", required=True,
                         help="path to a file of GitHub org names, one per line")
    parser.add_argument("--limit", type=int, help="only scan the first N targets")
    parser.add_argument("--dry-run", action="store_true", help="search only, no fetches")
    parser.add_argument("--resume", action="store_true", help="resume from checkpoint")
    args = parser.parse_args()

    if not os.environ.get("GITHUB_TOKEN"):
        log.warning("GITHUB_TOKEN not set. Search and commit-search both require auth.")

    targets = load_targets_from_file(args.targets)
    if args.limit:
        targets = targets[: args.limit]
    log.info(f"loaded {len(targets)} targets from {args.targets}")

    state = load_checkpoint() if args.resume else {"completed_orgs": [], "results": []}
    completed = set(state["completed_orgs"])
    all_org_data = state["results"]

    remaining = [o for o in targets if o not in completed]
    if args.resume:
        log.info(f"resuming: {len(completed)} done, {len(remaining)} remaining")

    log.info(f"=== STARTING MIGRATION SCAN: {len(remaining)} organizations ===")

    try:
        for org in remaining:
            org_data = scan_org(org, dry_run=args.dry_run)
            all_org_data.append(org_data)
            completed.add(org)
            state["completed_orgs"] = list(completed)
            state["results"] = all_org_data
            if not args.dry_run:
                save_checkpoint(state)
            time.sleep(SEARCH_DELAY)
    except KeyboardInterrupt:
        log.warning("interrupted — checkpoint saved, rerun with --resume")
        save_checkpoint(state)
        sys.exit(1)

    if not args.dry_run:
        write_json_csv(all_org_data)
        write_worksheets(all_org_data)
        if os.path.exists(CHECKPOINT_FILE):
            os.remove(CHECKPOINT_FILE)

    log.info("=== SCAN COMPLETE ===")


if __name__ == "__main__":
    main()
