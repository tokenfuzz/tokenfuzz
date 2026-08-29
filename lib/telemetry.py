"""Passive run telemetry read from a results tree.

Everything here answers "where did the wall go" for a finished or running
audit: worker occupancy, blocked housekeeping, time to first artifact, lane
share, execution verdicts, duplicate roots, and card-to-cluster lineage. It
only ever reads state, and a missing or malformed source yields ``None`` or an
empty count — never a zero that reads as a measurement (docs/concepts/benchmark.md
"Efficiency").

Two sources are read with a fallback so cells recorded before the stamps
existed still measure:

- session spans come from ``started``/``ended`` on ``index.jsonl`` rows, or
  from the prompt render and raw transcript file clocks when a row predates
  them (``source`` names which);
- housekeeping phases come from ``housekeeping_phase`` rows in
  ``state/events.jsonl``, or from ``index.log`` ``Housekeeping phases:`` lines.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

import llm_usage
import workqueue

# Roles that are agent sessions rather than harness decisions. Decision rows
# are ``decision:<kind>``; the preflight is a one-turn tool check.
_NON_SESSION_ROLE_PREFIXES = ("decision:",)
_NON_SESSION_ROLES = frozenset({"model-preflight"})

_STRATEGY_RE = re.compile(r"^S[1-8]$")
_PHASE_LINE_RE = re.compile(r"Housekeeping phases: (.*)$")
# ``name=12.3s`` optionally followed by a parenthesised detail list; the
# detail belongs to the span and must not be summed again.
_PHASE_TOKEN_RE = re.compile(r"([a-z_]+)=([\d.]+)s(?:\(([^)]*)\))?")


def _parse_ts(value: object) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _iso(stamp: float | None) -> str | None:
    if stamp is None:
        return None
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


def _rows(path: Path) -> list[dict]:
    return [row for row in workqueue.read_jsonl(path) if isinstance(row, dict)]


def _latest_by_id(rows: list[dict]) -> dict[str, dict]:
    latest: dict[str, dict] = {}
    for row in rows:
        identity = row.get("id")
        if isinstance(identity, str) and identity:
            latest[identity] = row
    return latest


def is_session_role(role: object) -> bool:
    text = str(role or "")
    if not text or text in _NON_SESSION_ROLES:
        return False
    return not text.startswith(_NON_SESSION_ROLE_PREFIXES)


def index_rows(results_dir: Path) -> list[dict]:
    return _rows(llm_usage.find_usage_index(results_dir))


def session_spans(results_dir: Path) -> list[dict]:
    """One span per agent session: started, ended, seconds, source.

    ``started``/``ended`` on the index row are authoritative. Rows written
    before those fields existed fall back to the prompt file (rendered at
    launch) and raw transcript (last written at exit) clocks, which is how the
    same number was first measured by hand.
    """
    spans: list[dict] = []
    for row in index_rows(results_dir):
        if not is_session_role(row.get("role")):
            continue
        started = _parse_ts(row.get("started"))
        ended = _parse_ts(row.get("ended"))
        source = "recorded"
        if started is None or ended is None:
            raw = row.get("raw_log")
            if not isinstance(raw, str) or not raw.endswith(".log.raw"):
                continue
            raw_path = Path(raw)
            prompt_path = raw_path.with_name(raw_path.name[: -len(".log.raw")] + ".prompt.md")
            try:
                started = prompt_path.stat().st_mtime
                ended = raw_path.stat().st_mtime
            except OSError:
                continue
            source = "file_mtime"
        if ended < started:
            continue
        spans.append({
            "agent": row.get("agent"),
            "iteration": row.get("iteration"),
            "role": row.get("role"),
            "started": _iso(started),
            "ended": _iso(ended),
            "seconds": round(ended - started, 3),
            "source": source,
        })
    return spans


def occupancy(results_dir: Path) -> dict:
    """Occupied agent-seconds. The fraction needs seats × wall, which only the
    cell record knows, so it is computed by the benchmark aggregation."""
    spans = session_spans(results_dir)
    if not spans:
        return {"sessions": 0, "occupied_seconds": None, "source": None}
    sources = {span["source"] for span in spans}
    return {
        "sessions": len(spans),
        "occupied_seconds": round(sum(span["seconds"] for span in spans), 3),
        "source": "recorded" if sources == {"recorded"} else "file_mtime",
    }


def _phases_from_events(events: list[dict]) -> tuple[dict[str, float], float, int]:
    totals: dict[str, float] = {}
    blocked = 0.0
    iterations: set[object] = set()
    seen = False
    for row in events:
        if row.get("type") != "housekeeping_phase":
            continue
        seen = True
        name = str(row.get("phase") or "")
        try:
            seconds = float(row.get("seconds"))
        except (TypeError, ValueError):
            continue
        if not name or seconds < 0:
            continue
        totals[name] = totals.get(name, 0.0) + seconds
        if row.get("blocked", True):
            blocked += seconds
        iterations.add(row.get("iteration"))
    if not seen:
        return {}, 0.0, -1
    return totals, blocked, len(iterations)


def parse_phase_line(line: str) -> dict[str, float]:
    """Top-level spans of one ``Housekeeping phases:`` log line."""
    match = _PHASE_LINE_RE.search(line)
    if not match:
        return {}
    return {
        name: float(seconds)
        for name, seconds, _detail in _PHASE_TOKEN_RE.findall(match.group(1))
    }


def _phases_from_index_log(results_dir: Path) -> tuple[dict[str, float], float, int]:
    log = llm_usage.find_usage_index(results_dir).with_name("index.log")
    totals: dict[str, float] = {}
    lines = 0
    try:
        with log.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                spans = parse_phase_line(line)
                if not spans:
                    continue
                lines += 1
                for name, seconds in spans.items():
                    totals[name] = totals.get(name, 0.0) + seconds
    except OSError:
        return {}, 0.0, -1
    if not lines:
        return {}, 0.0, -1
    return totals, sum(totals.values()), lines


def housekeeping(results_dir: Path) -> dict:
    """Per-phase housekeeping seconds and how much of it blocked the pool."""
    events = _rows(Path(results_dir) / "state" / "events.jsonl")
    totals, blocked, iterations = _phases_from_events(events)
    source = "events"
    if iterations < 0:
        totals, blocked, iterations = _phases_from_index_log(results_dir)
        source = "index_log"
    if iterations < 0:
        return {"phases": {}, "blocked_seconds": None, "total_seconds": None,
                "iterations": 0, "source": None}
    return {
        "phases": {name: round(seconds, 3) for name, seconds in sorted(totals.items())},
        "blocked_seconds": round(blocked, 3),
        "total_seconds": round(sum(totals.values()), 3),
        "iterations": iterations,
        "source": source,
    }


def run_start(results_dir: Path) -> float | None:
    """The run's first clock: the earliest index row, else the earliest state row."""
    stamps = [_parse_ts(row.get("timestamp")) for row in index_rows(results_dir)]
    stamps = [stamp for stamp in stamps if stamp is not None]
    if stamps:
        return min(stamps)
    state = Path(results_dir) / "state"
    for name in ("claims.jsonl", "hypotheses.jsonl", "runs.jsonl"):
        for row in _rows(state / name):
            stamp = _parse_ts(row.get("claimed_at") or row.get("created_at"))
            if stamp is not None:
                stamps.append(stamp)
    return min(stamps) if stamps else None


def _min_stamp(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return min(present) if present else None


def time_to_first(results_dir: Path) -> dict:
    """Seconds from run start to the first filed, confirmed, and admitted artifact."""
    results = Path(results_dir)
    start = run_start(results)
    events = _rows(results / "state" / "events.jsonl")
    runs = _rows(results / "state" / "runs.jsonl")
    filed = _min_stamp([
        _parse_ts(row.get("mtime") or row.get("first_seen"))
        for row in events if row.get("type") in ("finding_created", "crash_created")
    ])
    confirmed = _min_stamp([
        _parse_ts(row.get("created_at"))
        for row in runs if str(row.get("verdict") or "").upper() == "CRASH"
    ])
    admitted = _min_stamp([
        _parse_ts(row.get("first_seen"))
        for row in events if row.get("type") == "artifact_admitted"
    ])

    def relative(stamp: float | None) -> float | None:
        if stamp is None or start is None:
            return None
        return round(max(0.0, stamp - start), 3)

    return {
        "run_start": _iso(start),
        "filed_seconds": relative(filed),
        "crash_confirmed_seconds": relative(confirmed),
        "admitted_seconds": relative(admitted),
    }


def _strategy_key(value: object) -> str:
    text = str(value or "").strip().upper()[:2]
    return text if _STRATEGY_RE.match(text) else "other"


def _productive(status: object) -> bool:
    return str(status or "").upper().startswith(("CRASH", "FIND"))


def lane_stats(results_dir: Path) -> dict[str, dict[str, int]]:
    """Hypotheses and productive hypotheses per strategy, latest row per id."""
    latest = _latest_by_id(_rows(Path(results_dir) / "state" / "hypotheses.jsonl"))
    stats: dict[str, dict[str, int]] = {}
    for row in latest.values():
        lane = stats.setdefault(_strategy_key(row.get("strategy")), {"hypotheses": 0, "productive": 0})
        lane["hypotheses"] += 1
        if _productive(row.get("status")):
            lane["productive"] += 1
    return dict(sorted(stats.items()))


def execution_verdicts(results_dir: Path) -> dict:
    """Probe verdict counts. EXEC_FAIL is the target rejecting the input — a
    launch that cost a sanitizer run and taught nothing."""
    counts: dict[str, int] = {}
    for row in _rows(Path(results_dir) / "state" / "runs.jsonl"):
        verdict = str(row.get("verdict") or "").upper() or "UNKNOWN"
        counts[verdict] = counts.get(verdict, 0) + 1
    total = sum(counts.values())
    return {
        "counts": dict(sorted(counts.items())),
        "total": total,
        "exec_fail_share": (round(counts.get("EXEC_FAIL", 0) / total, 4) if total else None),
    }


def _agent_by_artifact(results_dir: Path) -> dict[str, set[str]]:
    agents: dict[str, set[str]] = {}
    latest = _latest_by_id(_rows(Path(results_dir) / "state" / "hypotheses.jsonl"))
    for row in latest.values():
        status = str(row.get("status") or "")
        if _productive(status):
            agents.setdefault(status, set()).add(str(row.get("agent") or ""))
    return agents


def duplicate_roots(results_dir: Path) -> dict:
    """Artifact signatures filed by more than one agent: convergence, not yield."""
    events = _rows(Path(results_dir) / "state" / "events.jsonl")
    by_signature: dict[tuple, set[str]] = {}
    agents = _agent_by_artifact(results_dir)
    for row in events:
        if row.get("type") not in ("finding_created", "crash_created"):
            continue
        signature = row.get("signature")
        if not isinstance(signature, list) or not signature:
            continue
        artifact = str(row.get("id") or "")
        by_signature.setdefault(tuple(signature), set()).update(agents.get(artifact, set()))
    multi = sum(1 for members in by_signature.values() if len(members - {""}) > 1)
    total = len(by_signature)
    return {
        "signatures": total,
        "multi_agent": multi,
        "rate": (round(multi / total, 4) if total else None),
    }


def lineage(results_dir: Path) -> list[dict]:
    """card → hypothesis → testcases → artifact → signature, one row per hypothesis."""
    results = Path(results_dir)
    latest = _latest_by_id(_rows(results / "state" / "hypotheses.jsonl"))
    testcases: dict[str, list[str]] = {}
    for row in _rows(results / "state" / "runs.jsonl"):
        hypothesis = str(row.get("hypothesis_id") or "")
        sha = str(row.get("testcase_sha1") or "")
        if hypothesis and sha and sha not in testcases.setdefault(hypothesis, []):
            testcases[hypothesis].append(sha)
    signatures: dict[str, list] = {}
    for row in _rows(results / "state" / "events.jsonl"):
        if row.get("type") in ("finding_created", "crash_created"):
            signatures[str(row.get("id") or "")] = list(row.get("signature") or [])
    rows: list[dict] = []
    for identity, row in sorted(latest.items()):
        status = str(row.get("status") or "")
        artifact = status if _productive(status) else None
        rows.append({
            "card_id": row.get("card_id"),
            "hypothesis_id": identity,
            "agent": row.get("agent"),
            "strategy": _strategy_key(row.get("strategy")),
            "status": status,
            "testcases": testcases.get(identity, []),
            "artifact": artifact,
            "signature": signatures.get(artifact or "", []),
        })
    return rows


def write_lineage(results_dir: Path, path: Path) -> int:
    rows = lineage(results_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True) + "\n")
    os.replace(temporary, path)
    return len(rows)


def summary(results_dir: Path) -> dict:
    """The whole telemetry block for one results tree (see harvest)."""
    results = Path(results_dir)
    return {
        "occupancy": occupancy(results),
        "housekeeping": housekeeping(results),
        "time_to_first": time_to_first(results),
        "lanes": lane_stats(results),
        "execution": execution_verdicts(results),
        "duplicate_roots": duplicate_roots(results),
        "lineage_rows": len(lineage(results)),
    }
