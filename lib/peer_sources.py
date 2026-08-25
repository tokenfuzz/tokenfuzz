"""Peer-fix data sources for Strategy S6.

Each function returns a list of dicts shaped like:

    {
        "source": "osv" | "vcs" | "ossfuzz",
        "id":     "CVE-2025-12345" | "<short-hash>" | "issue-NNN",
        "fix_hash": "<full-git-sha>" | "",   # may be empty for non-VCS sources
        "repo_url": "<canonical VCS URL>" | "",
        "range_start_hash": "<last-affected-git-sha>" | "",
        "evidence_url": "<direct fixed-range diff or endpoint patch URL>" | "",
        "evidence_kind": "fixed-range" | "endpoint" | "",
        "summary": "<one-line summary>",
        "url":     "<canonical URL>",
        "modified": "<ISO timestamp>" | "",
    }

The orchestrator (bin/peer-fix-cards) calls these per peer, dedupes by
fix_hash where possible, and emits bounded evidence cards for the audit agent.

Robustness:
    - Every fetch has a hard timeout (default 15s).
    - Per-peer failures are non-fatal: return [] and let the orchestrator continue.
    - HTTP responses are cached on disk (caller passes cache_dir / TTL).
    - No source is mandatory; missing sources just yield fewer cards.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional


# ─── Caching ────────────────────────────────────────────────────────

def _cache_get(cache_dir: Optional[Path], key: str, ttl_seconds: int) -> Optional[dict]:
    """Read cached JSON for `key` if present and fresher than ttl_seconds."""
    if cache_dir is None:
        return None
    h = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
    p = cache_dir / f"{h}.json"
    if not p.is_file():
        return None
    try:
        age = time.time() - p.stat().st_mtime
        if age > ttl_seconds:
            return None
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def _cache_put(cache_dir: Optional[Path], key: str, value: dict) -> None:
    if cache_dir is None:
        return
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        h = hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]
        p = cache_dir / f"{h}.json"
        tmp = cache_dir / f".{h}.{os.getpid()}.tmp"
        tmp.write_text(json.dumps(value), encoding="utf-8")
        os.replace(tmp, p)
    except OSError:
        # Cache failures are non-fatal — just means next call re-fetches.
        return


_NON_PRODUCT_DIFF_ROOTS = {
    ".github", "doc", "docs", "example", "examples", "external", "test",
    "tests", "third_party", "vendor",
}
_SOURCE_DIFF_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cxx", ".go", ".h", ".hh", ".hpp", ".java",
    ".js", ".kt", ".py", ".rs", ".ts",
}


_DIFF_SUMMARY_NOISE = {
    "address", "after", "crash", "error", "heap", "read", "segv",
    "unknown", "write",
}


def _production_diff_excerpt(raw: str, max_bytes: int, summary: str = "") -> str:
    """Prefer top-level production hunks while retaining a test-only fallback."""
    blocks = re.split(r"(?=^diff --git )", raw, flags=re.MULTILINE)
    diff_blocks = [block for block in blocks if block.startswith("diff --git ")]
    if not diff_blocks:
        return raw[:max_bytes]
    words = re.findall(
        r"[a-z0-9]+",
        re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", summary).lower(),
    )
    summary_tokens = {
        word for word in words if len(word) >= 4 and word not in _DIFF_SUMMARY_NOISE
    }
    production_source = []
    for index, block in enumerate(diff_blocks):
        header = block.splitlines()[0]
        match = re.match(r"diff --git a/(.+?) b/", header)
        if not match:
            continue
        path = Path(match.group(1))
        if (
            path.parts
            and path.parts[0].lower() not in _NON_PRODUCT_DIFF_ROOTS
            and path.suffix.lower() in _SOURCE_DIFF_SUFFIXES
        ):
            normalized_path = re.sub(r"[^a-z0-9]", "", str(path).lower())
            relevance = sum(token in normalized_path for token in summary_tokens)
            production_source.append((relevance, index, block))
    if production_source:
        production_source.sort(key=lambda row: (-row[0], row[1]))
        return "".join(row[2] for row in production_source)[:max_bytes]
    return "".join(diff_blocks)[:max_bytes]


def fetch_patch_excerpt(
    url: str,
    *,
    cache_dir: Optional[Path] = None,
    cache_ttl_seconds: int = 7 * 24 * 3600,
    timeout: int = 15,
    max_bytes: int = 6000,
    summary: str = "",
) -> str:
    """Fetch, production-prioritize, and cache a bounded HTTPS patch excerpt."""
    try:
        parsed = urllib.parse.urlsplit(url)
    except ValueError:
        return ""
    if parsed.scheme != "https" or not parsed.hostname or max_bytes <= 0:
        return ""
    cache_key = f"patch-excerpt-v2:{max_bytes}:{summary}:{url}"
    cached = _cache_get(cache_dir, cache_key, cache_ttl_seconds)
    if cached is not None:
        return str(cached.get("excerpt", ""))
    req = urllib.request.Request(url, headers={"User-Agent": "TokenFuzz/peer-fix-cards"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(max_bytes * 40).decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError):
        return ""
    excerpt = _production_diff_excerpt(raw, max_bytes, summary)
    _cache_put(cache_dir, cache_key, {"excerpt": excerpt})
    return excerpt


# ─── OSV (osv.dev) — structured advisory aggregator ─────────────────

def osv_query(
    peer: str,
    ecosystem: str = "OSS-Fuzz",
    days: int = 3650,
    timeout: int = 15,
    cache_dir: Optional[Path] = None,
    cache_ttl_seconds: int = 7 * 24 * 3600,
    max_results: int = 30,
    source_errors: Optional[list[str]] = None,
) -> list[dict]:
    """Query OSV for recent fixes affecting `peer`.

    Returns at most `max_results` entries with fix_hash populated.

    OSS-Fuzz is the default because, for C/C++ library peers, it is the only
    ecosystem that publishes commit-level fixes. Distro trackers carry far
    more advisories but pin a *package version* rather than a revision, so a
    GIT range — the only thing `_osv_pick_git_fix` can use — is absent.
    Measured 2026-08-24, entries carrying a GIT `fixed` commit:

        peer      OSS-Fuzz   Debian   Ubuntu   Alpine
        wolfssl     24/27      0/139    0/134     0/0
        openssl     10/10      0/369    0/245    0/123
        gnutls      12/12        0/0      0/0    0/37
        libxml2     54/56      0/176    0/127    0/36

    So widening the ecosystem adds requests and no cards. ("GHSA" is not an
    ecosystem value at all — the API rejects it with HTTP 400.) The parameter
    stays because the judgement is per-language, not universal: a peer in a
    package-manager ecosystem (npm, PyPI, Go, crates.io) does get commit-level
    GHSA data there. Re-measure before changing it, and see the caller in
    `gather_peer_fixes` — the endpoint handling is tied to this choice.
    """
    cutoff_epoch = time.time() - days * 86400
    # v4 preserves the repository and the narrowest direct evidence URL:
    # preferably the last-affected..first-fixed diff, otherwise the endpoint
    # patch. Do not replay an older card that forces an offline agent to
    # rediscover either.
    cache_key = f"osv-v4:{ecosystem}:{peer}:{days}:{max_results}"
    cached = _cache_get(cache_dir, cache_key, cache_ttl_seconds)
    if cached is not None:
        return cached.get("entries", [])

    body = json.dumps({"package": {"name": peer, "ecosystem": ecosystem}}).encode("utf-8")
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        # Network failure — return [] but do NOT cache it. A negative
        # cache entry here is byte-identical to a legitimate empty OSV
        # result, so caching it would suppress S6 mining for the full
        # TTL (default 7 days) after a single transient failure — e.g.
        # one sandboxed run with no network poisons every later run.
        # Leaving it uncached means the next run simply retries.
        if source_errors is not None:
            source_errors.append(f"OSV unavailable: {type(error).__name__}")
        return []

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        # Malformed body — also a fetch failure, not a real empty result.
        # Same reasoning as above: return [] without caching.
        if source_errors is not None:
            source_errors.append("OSV unavailable: malformed response")
        return []

    vulns = payload.get("vulns") or []
    entries: list[dict] = []
    for vuln in vulns:
        modified_raw = vuln.get("modified") or vuln.get("published") or ""
        # OSV timestamps are ISO 8601 UTC, e.g. "2025-01-15T12:34:56Z".
        modified_epoch = _iso_to_epoch(modified_raw)
        if modified_epoch and modified_epoch < cutoff_epoch:
            continue
        fix_hash, repo_url, range_start_hash = _osv_pick_git_fix(vuln)
        if not fix_hash:
            continue
        evidence_url, evidence_kind = _github_fix_evidence(
            repo_url, fix_hash, range_start_hash,
        )
        vid = vuln.get("id") or ""
        entries.append({
            "source": "osv",
            "id": vid,
            "fix_hash": fix_hash,
            "repo_url": repo_url,
            "range_start_hash": range_start_hash,
            "evidence_url": evidence_url,
            "evidence_kind": evidence_kind,
            "summary": (vuln.get("summary") or "")[:200],
            "url": f"https://osv.dev/vulnerability/{vid}" if vid else "",
            "modified": modified_raw,
        })
        if len(entries) >= max_results:
            break

    _cache_put(cache_dir, cache_key, {"entries": entries})
    return entries


def _osv_pick_git_fix(vuln: dict) -> tuple[str, str, str]:
    """Pick one GIT endpoint, repository, and OSV last-affected boundary."""
    for aff in vuln.get("affected") or []:
        for r in aff.get("ranges") or []:
            if r.get("type") != "GIT":
                continue
            repo_url = r.get("repo") if isinstance(r.get("repo"), str) else ""
            for ev in r.get("events") or []:
                fixed = ev.get("fixed")
                if fixed and isinstance(fixed, str):
                    fixed_range = (aff.get("database_specific") or {}).get("fixed_range", "")
                    range_start = ""
                    if isinstance(fixed_range, str) and ":" in fixed_range:
                        candidate, range_end = fixed_range.rsplit(":", 1)
                        if range_end == fixed:
                            range_start = candidate
                    return fixed, repo_url, range_start
    return "", "", ""


def _github_fix_evidence(
    repo_url: str, fix_hash: str, range_start_hash: str = "",
) -> tuple[str, str]:
    """Return GitHub's narrowest deterministic evidence URL and its kind."""
    try:
        parsed = urllib.parse.urlsplit(repo_url)
    except ValueError:
        return "", ""
    path = parsed.path.rstrip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.strip("/").split("/")
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or len(parts) != 2
        or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", part) for part in parts)
        or not re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", fix_hash)
    ):
        return "", ""
    base = f"https://github.com/{parts[0]}/{parts[1]}"
    if re.fullmatch(r"(?:[0-9a-fA-F]{40}|[0-9a-fA-F]{64})", range_start_hash):
        return f"{base}/compare/{range_start_hash}...{fix_hash}.diff", "fixed-range"
    return f"{base}/commit/{fix_hash}.patch", "endpoint"


def _iso_to_epoch(s: str) -> Optional[float]:
    if not s:
        return None
    # Tolerant parse — strip trailing 'Z' and fractional seconds.
    s2 = s.rstrip("Z")
    s2 = re.sub(r"\.\d+$", "", s2)
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            import datetime
            return datetime.datetime.strptime(s2, fmt).replace(
                tzinfo=datetime.timezone.utc
            ).timestamp()
        except ValueError:
            continue
    return None


# ─── VCS log — works for any clone the operator has locally ─────────

# Conservative noise filter: commits that look like prior fixes tend to be
# small (≤3 files, ≤80 lines changed) and mention these tokens.
_VCS_FIX_KEYWORDS = re.compile(
    r"\b(CVE-\d+|fix.*(overflow|bound|uninit|underrun|underflow|use[- ]?after|free|leak|"
    r"buffer|integer|sanitize|crash|deref|nullptr|null pointer|race|toctou|toctou|"
    r"oob|out[- ]of[- ]bound))",
    re.IGNORECASE,
)

# Same filter, handed to git so it does not compute a shortstat for every
# commit in a large peer repository. Derived from the pattern above rather than
# restated, so the two dialects cannot drift: git's ERE has no `\d`, and `\b`
# is not portable across the regex libraries git links against. Dropping the
# anchor only widens the pre-filter, and the canonical Python filter above
# still decides — so this can cost an extra shortstat, never a candidate.
_VCS_FIX_GREP = _VCS_FIX_KEYWORDS.pattern.replace(r"\b", "").replace(r"\d", "[0-9]")

# Within the bounded card supply, prefer commits whose subject names a
# memory-safety mechanism. Stable source order breaks ties, so recent fixes
# still win among equally strong candidates.
_VCS_HIGH_SIGNAL = re.compile(
    r"\b(CVE-\d+|use[- ]?after[- ]?free|double[- ]?free|OOB|out[- ]of[- ]bound|"
    r"(?:heap|stack)[- ]?(?:buffer[- ]?)?(?:overflow|underflow)|"
    r"(?:buffer|length|integer) overflow|uninit)",
    re.IGNORECASE,
)
_VCS_MEDIUM_SIGNAL = re.compile(
    r"\b(overflow|underflow|bound|buffer|unsafe|untrusted|race|deref|nullptr)",
    re.IGNORECASE,
)


def _rank_vcs_entries(entries: list[dict], limit: int) -> list[dict]:
    """Order fix candidates by how strongly the subject names a memory-safety
    mechanism. Ranks only what the keyword filter already admitted, and the
    sort is stable, so recency still decides between equal candidates.

    Deliberately no test/example penalty: a subject mentioning a test does not
    make the commit a test change (a real fix routinely names the harness that
    caught it), the size bound and the diff pathspec already suppress test
    churn, and demoting on the mention alone sank real fixes below cleanups.
    """
    def priority(entry: dict) -> int:
        subject = str(entry.get("summary", ""))
        if _VCS_HIGH_SIGNAL.search(subject):
            return 2
        return 1 if _VCS_MEDIUM_SIGNAL.search(subject) else 0

    return sorted(entries, key=priority, reverse=True)[:limit]


def _env_int(name: str, default: int) -> int:
    """Read a positive-int tuning knob from the environment, else `default`.

    Non-numeric or non-positive values fall back to the default, so a typo
    can never silently disable a filter.
    """
    raw = os.environ.get(name, "").strip()
    if raw.isdigit():
        value = int(raw)
        if value > 0:
            return value
    return default


# VCS fix-candidate diff-size filter (S6 peer mining). Commits larger than
# these bounds are treated as refactors/features and skipped. The defaults
# are deliberately generous: a real security fix routinely also carries a
# regression test, a header change, a changelog entry, and call-site
# updates, and `git --shortstat` counts all of that churn — too tight a
# bound is a false negative (a whole bug class never mined), which is far
# worse than the extra tokens of a slightly-too-large diff. Candidate
# *volume* is bounded separately by max_per_source, so widening these does
# not multiply LLM-call count.
#
# Exploration knobs, not fixed policy: raise them when a target's real
# fixes land in larger commits (e.g. PEER_VCS_MAX_LINES=1000 for projects
# with bulky test-data files); set very high to disable the size filter.
_VCS_MAX_FILES_CHANGED = _env_int("PEER_VCS_MAX_FILES", 10)
_VCS_MAX_LINES_CHANGED = _env_int("PEER_VCS_MAX_LINES", 400)


def vcs_log_search(
    peer_clone: Path,
    days: int = 1095,
    timeout: int = 15,
    max_results: int = 30,
    source_errors: Optional[list[str]] = None,
) -> list[dict]:
    """Scan a local git/hg clone of a peer for security-shaped commits.

    Filters by message keywords AND shortstat (small diffs only), then ranks
    by memory-safety signal with recency as the tiebreak. Skips silently if
    peer_clone isn't a clone we can drive.
    """
    if not peer_clone.is_dir():
        return []
    if (peer_clone / ".git").exists() or (peer_clone / "HEAD").is_file():
        return _vcs_log_git(peer_clone, days, timeout, max_results, source_errors)
    if (peer_clone / ".hg").exists():
        return _vcs_log_hg(peer_clone, days, timeout, max_results, source_errors)
    return []


def _vcs_log_git(
    peer_clone: Path, days: int, timeout: int, max_results: int,
    source_errors: Optional[list[str]] = None,
) -> list[dict]:
    # Use --shortstat so we can filter small diffs in Python (cheaper than
    # parsing inside an awk one-liner that splits on changing column widths).
    cmd = [
        "git", "-C", str(peer_clone), "log",
        f"--since={days} days ago",
        "--pretty=format:%H%x09%s%x09%cI",
        "--shortstat",
        "--no-merges",
        "--regexp-ignore-case",
        "--extended-regexp",
        f"--grep={_VCS_FIX_GREP}",
    ]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        ).stdout
    except (subprocess.TimeoutExpired, OSError) as error:
        if source_errors is not None:
            source_errors.append(f"git log unavailable: {type(error).__name__}")
        return []

    return _parse_git_shortstat(out, max_results)


def _parse_git_shortstat(out: str, max_results: int) -> list[dict]:
    entries: list[dict] = []
    lines = out.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if "\t" in line:
            parts = line.split("\t", 2)
            if len(parts) >= 3:
                full_hash, subject, when = parts[0], parts[1], parts[2]
                # shortstat is next non-blank line
                files_changed = 0
                lines_changed = 0
                j = i + 1
                while j < len(lines) and not lines[j].strip():
                    j += 1
                if j < len(lines) and "changed" in lines[j]:
                    stat_line = lines[j]
                    m_files = re.search(r"(\d+)\s+files?\s+changed", stat_line)
                    m_ins = re.search(r"(\d+)\s+insertion", stat_line)
                    m_del = re.search(r"(\d+)\s+deletion", stat_line)
                    files_changed = int(m_files.group(1)) if m_files else 0
                    lines_changed = (int(m_ins.group(1)) if m_ins else 0) + (
                        int(m_del.group(1)) if m_del else 0
                    )
                    i = j
                # Apply filters (size bounds are env-tunable — see above)
                if (_VCS_FIX_KEYWORDS.search(subject)
                        and files_changed <= _VCS_MAX_FILES_CHANGED
                        and lines_changed <= _VCS_MAX_LINES_CHANGED):
                    entries.append({
                        "source": "vcs",
                        "id": full_hash[:12],
                        "fix_hash": full_hash,
                        "summary": subject[:200],
                        "url": "",
                        "modified": when,
                    })
        i += 1
    return _rank_vcs_entries(entries, max_results)


_HG_DIFFSTAT = re.compile(r"^(\d+): \+(\d+)/-(\d+)$")


def _vcs_log_hg(
    peer_clone: Path, days: int, timeout: int, max_results: int,
    source_errors: Optional[list[str]] = None,
) -> list[dict]:
    # {diffstat} is Mercurial's --shortstat, so the same size bounds apply to
    # both VCSes; sort(-rev) keeps newest-first, which the revset would
    # otherwise reorder to ascending.
    cmd = [
        "hg", "-R", str(peer_clone), "log",
        "-d", f"-{days}",
        "-r", "sort(not merge(), -rev)",
        "--template", "{node}\\t{desc|firstline}\\t{date|isodate}\\t{diffstat}\\n",
        "-l", str(max_results * 4),  # over-fetch; filter below
    ]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        ).stdout
    except (subprocess.TimeoutExpired, OSError) as error:
        if source_errors is not None:
            source_errors.append(f"hg log unavailable: {type(error).__name__}")
        return []
    entries: list[dict] = []
    for line in out.splitlines():
        parts = line.split("\t", 3)
        if len(parts) < 4:
            continue
        full_hash, subject, when, diffstat = parts
        if not _VCS_FIX_KEYWORDS.search(subject):
            continue
        sizes = _HG_DIFFSTAT.match(diffstat.strip())
        if sizes and (int(sizes.group(1)) > _VCS_MAX_FILES_CHANGED
                      or int(sizes.group(2)) + int(sizes.group(3)) > _VCS_MAX_LINES_CHANGED):
            continue
        entries.append({
            "source": "vcs",
            "id": full_hash[:12],
            "fix_hash": full_hash,
            "summary": subject[:200],
            "url": "",
            "modified": when,
        })
    return _rank_vcs_entries(entries, max_results)


# ─── OSS-Fuzz issue tracker (URL emission only) ─────────────────────

def ossfuzz_tracker_reference(peer: str) -> dict:
    """Reference card pointing the agent at OSS-Fuzz issues for `peer`.

    Returns a single entry that the orchestrator can include as a
    catch-all hint when other sources yielded nothing. Not a fix-commit
    source — the operator/agent has to click through.
    """
    return {
        "source": "ossfuzz",
        "id": f"ossfuzz:{peer}",
        "fix_hash": "",
        "summary": f"Browse OSS-Fuzz issues for {peer}",
        "url": f"https://issues.oss-fuzz.com/issues?q=projectId:{peer}",
        "modified": "",
    }


# ─── Diff fetching (per-fix, on demand) ─────────────────────────────

def fetch_fix_diff(
    peer_clone: Path,
    fix_hash: str,
    timeout: int = 10,
    max_bytes: int = 8000,
) -> str:
    """Resolve a fix hash to a diff via the local peer clone.

    Empty string if the clone isn't present or the hash isn't there.
    Bounded byte size — large diffs are truncated so LLM prompts don't
    blow up on refactor commits the keyword filter missed.
    """
    if not peer_clone.is_dir() or not fix_hash:
        return ""
    if (peer_clone / ".git").exists() or (peer_clone / "HEAD").is_file():
        # `--format=` drops the commit header and message. The subject is
        # already a card field, and a verbose message otherwise spends the
        # excerpt budget before the first hunk: measured 6529 characters of
        # prose ahead of `diff --git` on a 6000-character cap, i.e. a card
        # carrying no code at all. Empty output now means exactly "no hunks",
        # which is what selects the unfiltered fallback below.
        commands = [[
            "git", "-C", str(peer_clone), "show", "--format=", "--unified=4",
            fix_hash, "--", ".", ":(exclude)tests", ":(exclude)test",
            ":(exclude)examples", ":(exclude)example",
        ], ["git", "-C", str(peer_clone), "show", "--format=", "--unified=4",
            fix_hash]]
    elif (peer_clone / ".hg").exists():
        commands = [["hg", "-R", str(peer_clone), "log", "-pr", fix_hash]]
    else:
        return ""
    for cmd in commands:
        try:
            completed = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout,
            )
        except (subprocess.TimeoutExpired, OSError):
            return ""
        if completed.returncode:
            return ""
        if completed.stdout.strip():
            return completed.stdout[:max_bytes]
    return ""


# ─── Local clone discovery ──────────────────────────────────────────

def find_peer_clone(peer: str, search_roots: list[Path]) -> Optional[Path]:
    """Look for a clone of `peer` under any of `search_roots`.

    A clone is a directory whose name equals the peer slug AND contains
    a .git or .hg entry. Local history is the preferred exact-fix source;
    returns None when the operator has no peer repo checked out.
    """
    for root in search_roots:
        if not root.is_dir():
            continue
        for candidate in (root / peer, root / peer.replace("/", "_")):
            if not candidate.is_dir():
                continue
            if (candidate / ".git").exists() or (candidate / ".hg").exists():
                return candidate
    return None


# ─── Orchestrator helper ────────────────────────────────────────────

def gather_peer_fixes(
    peer: str,
    cache_dir: Optional[Path] = None,
    cache_ttl_seconds: int = 7 * 24 * 3600,
    days: int = 3650,
    peer_clone_search_roots: Optional[list[Path]] = None,
    max_per_source: int = 20,
    source_errors: Optional[list[str]] = None,
) -> list[dict]:
    """One-stop entrypoint: gather fixes for a peer from all available sources.

    Returns deduplicated by fix_hash where possible. Per-source failures
    are silent — the function returns whatever did succeed.
    """
    # Identity is per source. A VCS entry *is* its commit, so the hash
    # identifies it. An OSV entry is an advisory whose GIT `fixed` event only
    # ends its vulnerable range, and ClusterFuzz bisects many distinct bugs to
    # the same first-good commit — keying on that endpoint collapsed 15-58% of
    # a peer's advisories into one (gnutls: 7 of 12). Sources are also not
    # cross-deduplicated: an advisory and a commit that share a revision still
    # describe different things.
    seen: set[tuple[str, str]] = set()
    out: list[dict] = []

    # 1. Local VCS commits are exact fixes with their original commit message
    # and an immediately available diff. OSV's GIT `fixed` event is only a
    # vulnerable-range endpoint and is often an unrelated later commit, so it
    # must not consume the per-peer review cap before this stronger evidence.
    if peer_clone_search_roots:
        clone = find_peer_clone(peer, peer_clone_search_roots)
        if clone is not None:
            for entry in vcs_log_search(
                clone, days=days, max_results=max_per_source,
                source_errors=source_errors,
            ):
                key = ("vcs", entry.get("fix_hash", ""))
                if key[1] and key in seen:
                    continue
                if key[1]:
                    seen.add(key)
                out.append(entry)

    # 2. OSV supplies vulnerability-scoped leads when local history is absent
    # or sparse. OSS-Fuzz derives its `fixed` event from ClusterFuzz
    # bisection, so the revision ends the vulnerable range rather than being
    # the repair — sampled against a local peer clone it was an unrelated
    # merge or feature commit every time. Consumers therefore treat an `osv`
    # entry's revision as an anchor to resolve, not a patch, and ship no diff
    # for it. Adding an ecosystem whose `fixed` *is* the repair means revising
    # that handling too, not just this call.
    for entry in osv_query(
        peer, ecosystem="OSS-Fuzz", days=days,
        cache_dir=cache_dir, cache_ttl_seconds=cache_ttl_seconds,
        max_results=max_per_source,
        source_errors=source_errors,
    ):
        key = ("osv", entry.get("id", ""))
        if key[1] and key in seen:
            continue
        if key[1]:
            seen.add(key)
        out.append(entry)

    # 3. OSS-Fuzz tracker reference (always emitted as a hint if we got
    #    nothing else)
    if not out:
        out.append(ossfuzz_tracker_reference(peer))

    return out
