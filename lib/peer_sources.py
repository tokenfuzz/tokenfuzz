"""Peer-fix data sources for Strategy S6.

Each function returns a list of dicts shaped like:

    {
        "source": "osv" | "vcs" | "ossfuzz",
        "id":     "CVE-2025-12345" | "<short-hash>" | "issue-NNN",
        "fix_hash": "<full-git-sha>" | "",   # may be empty for non-VCS sources
        "summary": "<one-line summary>",
        "url":     "<canonical URL>",
        "modified": "<ISO timestamp>" | "",
    }

The orchestrator (bin/peer-fix-cards) calls these per peer, dedupes by
fix_hash where possible, and feeds each entry through LLM distillation.

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


# ─── OSV (osv.dev) — structured advisory aggregator ─────────────────

def osv_query(
    peer: str,
    ecosystem: str = "OSS-Fuzz",
    days: int = 3650,
    timeout: int = 15,
    cache_dir: Optional[Path] = None,
    cache_ttl_seconds: int = 7 * 24 * 3600,
    max_results: int = 30,
) -> list[dict]:
    """Query OSV for recent fixes affecting `peer`.

    Returns at most `max_results` entries with fix_hash populated. Tries
    OSS-Fuzz ecosystem first by default — many C/C++ libraries live there.
    Caller can re-call with ecosystem="Debian" or others for broader history.
    """
    cutoff_epoch = time.time() - days * 86400
    cache_key = f"osv:{ecosystem}:{peer}:{days}:{max_results}"
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
    except (urllib.error.URLError, TimeoutError, OSError):
        # Network failure — return [] but do NOT cache it. A negative
        # cache entry here is byte-identical to a legitimate empty OSV
        # result, so caching it would suppress S6 mining for the full
        # TTL (default 7 days) after a single transient failure — e.g.
        # one sandboxed run with no network poisons every later run.
        # Leaving it uncached means the next run simply retries.
        return []

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        # Malformed body — also a fetch failure, not a real empty result.
        # Same reasoning as above: return [] without caching.
        return []

    vulns = payload.get("vulns") or []
    entries: list[dict] = []
    for vuln in vulns:
        modified_raw = vuln.get("modified") or vuln.get("published") or ""
        # OSV timestamps are ISO 8601 UTC, e.g. "2025-01-15T12:34:56Z".
        modified_epoch = _iso_to_epoch(modified_raw)
        if modified_epoch and modified_epoch < cutoff_epoch:
            continue
        fix_hash = _osv_pick_fix_hash(vuln)
        if not fix_hash:
            continue
        vid = vuln.get("id") or ""
        entries.append({
            "source": "osv",
            "id": vid,
            "fix_hash": fix_hash,
            "summary": (vuln.get("summary") or "")[:200],
            "url": f"https://osv.dev/vulnerability/{vid}" if vid else "",
            "modified": modified_raw,
        })
        if len(entries) >= max_results:
            break

    _cache_put(cache_dir, cache_key, {"entries": entries})
    return entries


def _osv_pick_fix_hash(vuln: dict) -> str:
    """Pick the first GIT-typed fix commit hash from an OSV vuln entry."""
    for aff in vuln.get("affected") or []:
        for r in aff.get("ranges") or []:
            if r.get("type") != "GIT":
                continue
            for ev in r.get("events") or []:
                fixed = ev.get("fixed")
                if fixed and isinstance(fixed, str):
                    return fixed
    return ""


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
) -> list[dict]:
    """Scan a local git/hg clone of a peer for security-shaped commits.

    Returns most-recent first. Filters by message keywords AND shortstat
    (small diffs only). Skips silently if peer_clone isn't a clone we can
    drive.
    """
    if not peer_clone.is_dir():
        return []
    if (peer_clone / ".git").exists() or (peer_clone / "HEAD").is_file():
        return _vcs_log_git(peer_clone, days, timeout, max_results)
    if (peer_clone / ".hg").exists():
        return _vcs_log_hg(peer_clone, days, timeout, max_results)
    return []


def _vcs_log_git(peer_clone: Path, days: int, timeout: int, max_results: int) -> list[dict]:
    # Use --shortstat so we can filter small diffs in Python (cheaper than
    # parsing inside an awk one-liner that splits on changing column widths).
    cmd = [
        "git", "-C", str(peer_clone), "log",
        f"--since={days} days ago",
        "--pretty=format:%H%x09%s%x09%cI",
        "--shortstat",
        "--no-merges",
    ]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return []

    return _parse_git_shortstat(out, max_results)


def _parse_git_shortstat(out: str, max_results: int) -> list[dict]:
    entries: list[dict] = []
    lines = out.splitlines()
    i = 0
    while i < len(lines) and len(entries) < max_results:
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
    return entries


def _vcs_log_hg(peer_clone: Path, days: int, timeout: int, max_results: int) -> list[dict]:
    cmd = [
        "hg", "-R", str(peer_clone), "log",
        "-d", f"-{days}",
        "--template", "{node}\\t{desc|firstline}\\t{date|isodate}\\n",
        "-l", str(max_results * 4),  # over-fetch; filter below
    ]
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return []
    entries: list[dict] = []
    for line in out.splitlines():
        parts = line.split("\t", 2)
        if len(parts) < 3:
            continue
        full_hash, subject, when = parts
        if not _VCS_FIX_KEYWORDS.search(subject):
            continue
        entries.append({
            "source": "vcs",
            "id": full_hash[:12],
            "fix_hash": full_hash,
            "summary": subject[:200],
            "url": "",
            "modified": when,
        })
        if len(entries) >= max_results:
            break
    return entries


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
        cmd = ["git", "-C", str(peer_clone), "show", "--unified=4", fix_hash]
    elif (peer_clone / ".hg").exists():
        cmd = ["hg", "-R", str(peer_clone), "log", "-pr", fix_hash]
    else:
        return ""
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        ).stdout
    except (subprocess.TimeoutExpired, OSError):
        return ""
    return out[:max_bytes]


# ─── Local clone discovery ──────────────────────────────────────────

def find_peer_clone(peer: str, search_roots: list[Path]) -> Optional[Path]:
    """Look for a clone of `peer` under any of `search_roots`.

    A clone is a directory whose name equals the peer slug AND contains
    a .git or .hg entry. Used to enable VCS-log fallback when the operator
    has peer repos checked out locally; returns None otherwise.
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
) -> list[dict]:
    """One-stop entrypoint: gather fixes for a peer from all available sources.

    Returns deduplicated by fix_hash where possible. Per-source failures
    are silent — the function returns whatever did succeed.
    """
    seen_hashes: set[str] = set()
    out: list[dict] = []

    # 1. OSV (highest structured signal when available)
    for entry in osv_query(
        peer, ecosystem="OSS-Fuzz", days=days,
        cache_dir=cache_dir, cache_ttl_seconds=cache_ttl_seconds,
        max_results=max_per_source,
    ):
        h = entry.get("fix_hash", "")
        if h and h in seen_hashes:
            continue
        if h:
            seen_hashes.add(h)
        out.append(entry)

    # 2. VCS log (universal fallback; works whether or not OSV had data)
    if peer_clone_search_roots:
        clone = find_peer_clone(peer, peer_clone_search_roots)
        if clone is not None:
            for entry in vcs_log_search(clone, days=days, max_results=max_per_source):
                h = entry.get("fix_hash", "")
                if h and h in seen_hashes:
                    continue
                if h:
                    seen_hashes.add(h)
                out.append(entry)

    # 3. OSS-Fuzz tracker reference (always emitted as a hint if we got
    #    nothing else)
    if not out:
        out.append(ossfuzz_tracker_reference(peer))

    return out
