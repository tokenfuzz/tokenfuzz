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
import coverage_ledger
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


def finalization(results_dir: Path) -> dict:
    """Off-audit-wall crash/find adjudication time recorded by the benchmark."""
    candidates = [
        row for row in _rows(Path(results_dir) / "state" / "events.jsonl")
        if row.get("type") == "finalization_phase"
    ]
    # Regeneration can adjudicate a cell again, and a missing replay build can
    # skip only crash triage. Keep the newest measurement of each phase rather
    # than accumulating operator maintenance or dropping an unrerun phase.
    latest: dict[str, dict] = {}
    for row in candidates:
        name = str(row.get("phase") or "")
        if name:
            latest[name] = row
    totals: dict[str, float] = {}
    rows = 0
    for name, row in latest.items():
        try:
            seconds = float(row.get("seconds"))
        except (TypeError, ValueError):
            continue
        if not name or seconds < 0:
            continue
        totals[name] = totals.get(name, 0.0) + seconds
        rows += 1
    return {
        "phases": {name: round(seconds, 3) for name, seconds in sorted(totals.items())},
        "total_seconds": round(sum(totals.values()), 3) if rows else None,
        "phase_count": rows,
        "source": "events" if rows else None,
    }


def run_start(results_dir: Path, origin: str = "") -> float | None:
    """The run's first clock: the cell's own start, or the earliest row found.

    ``origin`` is the cell's recorded ``started_at``, which is the only honest
    clock a model-direct cell has: it writes no agent index rows while it runs,
    so the rows discovered below are its *finalization*, minutes to hours after
    the fact, and every artifact then reads as filed at second zero. Harness
    cells have both, and the earliest of the two is the run's start either way,
    so a resumed cell whose stamp moved forward cannot push the origin past
    work already on disk.
    """
    # Agent index rows are appended when a session ends. Their ``timestamp``
    # therefore measures completion, while ``started`` is the run clock the
    # occupancy recorder already captured. Prefer it when present so an
    # artifact filed during the first session does not clamp to time zero.
    declared = _parse_ts(origin)
    stamps = [
        _parse_ts(row.get("started") or row.get("timestamp"))
        for row in index_rows(results_dir)
    ]
    stamps = [stamp for stamp in stamps if stamp is not None]
    if not stamps:
        state = Path(results_dir) / "state"
        for name in ("claims.jsonl", "hypotheses.jsonl", "runs.jsonl"):
            for row in _rows(state / name):
                stamp = _parse_ts(row.get("claimed_at") or row.get("created_at"))
                if stamp is not None:
                    stamps.append(stamp)
    if declared is not None:
        stamps.append(declared)
    return min(stamps) if stamps else None


def _min_stamp(values: list[float | None]) -> float | None:
    present = [value for value in values if value is not None]
    return min(present) if present else None


def time_to_first(results_dir: Path, origin: str = "") -> dict:
    """Seconds from run start to the first filed, confirmed, and admitted artifact.

    `crash_confirmed` is the filing time of the earliest crash that review
    admitted. Filing already requires the sanitizer to reproduce the crash,
    and reading confirmation from the run log instead credited the first
    reproduced crash even when triage later rejected it.
    """
    results = Path(results_dir)
    start = run_start(results, origin)
    events = _rows(results / "state" / "events.jsonl")
    filed = _min_stamp([
        _parse_ts(row.get("mtime") or row.get("first_seen"))
        for row in events if row.get("type") in ("finding_created", "crash_created")
    ])
    admitted_crashes = {
        row.get("id") for row in events
        if row.get("type") == "artifact_admitted" and row.get("kind") == "crash"
    }
    confirmed = _min_stamp([
        _parse_ts(row.get("mtime") or row.get("first_seen"))
        for row in events
        if row.get("type") == "crash_created" and row.get("id") in admitted_crashes
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


def _names_artifact(status: object) -> bool:
    return str(status or "").upper().startswith(("CRASH", "FIND"))


_ARTIFACT_LANES = ("crashes", "findings", "crashes-rejected", "findings-rejected")
_CARD_LINE_RE = re.compile(r"^CARD-ID:\s*(\S+)", re.MULTILINE)


def _artifact_directories(results: Path) -> dict[str, tuple[Path, bool]]:
    """Artifact name -> (directory, adjudicated on its own).

    Bundles folded as duplicates sit under ``crashes/.duplicates``; they
    resolve, so a hypothesis that closed on one is placed, but they were
    never a result of their own.
    """
    found: dict[str, tuple[Path, bool]] = {}
    for lane in _ARTIFACT_LANES:
        root = results / lane
        if root.is_dir():
            for path in root.iterdir():
                if path.is_dir() and _names_artifact(path.name):
                    found.setdefault(path.name, (path, True))
    duplicates = results / "crashes" / ".duplicates"
    if duplicates.is_dir():
        for path in duplicates.iterdir():
            if path.is_dir() and _names_artifact(path.name):
                found.setdefault(path.name, (path, False))
    return found


def _finding_card(directory: Path) -> str:
    """The `CARD-ID:` a finding report carries, or ""."""
    import report_identity  # lazy: it imports the triage helpers

    report = report_identity.find_report(directory)
    if report is None:
        return ""
    try:
        match = _CARD_LINE_RE.search(report.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return ""
    return match.group(1) if match else ""


def _resolve_artifact(
    status: str, agent: str, card_id: str, directories: dict[str, tuple[Path, bool]],
) -> str:
    """The directory a hypothesis status names, or the status itself.

    Agents close a hypothesis with the id `bin/probe` printed, which for a
    crash omits the slot suffix the bundle directory carries (`CRASH-002`
    from agent 2 is `crashes/CRASH-002-2`) and for a finding omits the slug
    (`FIND-001` is `findings/FIND-001-<slug>`, one per agent that filed a
    FIND-001). Joining on the bare id matched nothing, so every metric built
    on the join read zero.
    """
    if status in directories:
        return status
    suffixed = f"{status}-{agent}" if agent else ""
    if suffixed in directories:
        return suffixed
    matches = [name for name in directories if name.startswith(status + "-")]
    if len(matches) > 1 and card_id and status.startswith("FIND"):
        matches = [
            name for name in matches
            if _finding_card(directories[name][0]) == card_id
        ]
    return matches[0] if len(matches) == 1 else status


def hypothesis_artifacts(results_dir: Path) -> dict[str, dict]:
    """Per hypothesis id: the artifact it closed on and whether that was yield.

    A hypothesis is productive when it is the first to close on an artifact
    that was adjudicated on its own. A later hypothesis closing on the same
    bundle re-derived it, and one closing on a bundle folded as a duplicate
    filed a copy of a state already on disk: both are convergence, not
    yield, and counting them made a lane that re-probed filed reproducers
    read as productive. A status naming an artifact no directory resolves
    keeps the agent's claim, as before.
    """
    results = Path(results_dir)
    latest = _latest_by_id(_rows(results / "state" / "hypotheses.jsonl"))
    directories = _artifact_directories(results)
    resolved: dict[str, str | None] = {}
    for identity, row in latest.items():
        status = str(row.get("status") or "").strip()
        if not _names_artifact(status):
            resolved[identity] = None
            continue
        resolved[identity] = _resolve_artifact(
            status.upper(), str(row.get("agent") or ""), str(row.get("card_id") or ""),
            directories,
        )
    first_by_artifact: dict[str, str] = {}
    for identity in sorted(
        (i for i, name in resolved.items() if name),
        key=lambda i: (str(latest[i].get("created_at") or ""), i),
    ):
        first_by_artifact.setdefault(resolved[identity], identity)
    out: dict[str, dict] = {}
    for identity, name in resolved.items():
        if name is None:
            out[identity] = {"artifact": None, "productive": False}
            continue
        placed = directories.get(name)
        productive = (
            placed is None or (placed[1] and first_by_artifact[name] == identity)
        )
        out[identity] = {"artifact": name, "productive": productive}
    return out


def lane_stats(results_dir: Path) -> dict[str, dict[str, int]]:
    """Hypotheses and productive hypotheses per strategy, latest row per id."""
    latest = _latest_by_id(_rows(Path(results_dir) / "state" / "hypotheses.jsonl"))
    artifacts = hypothesis_artifacts(results_dir)
    stats: dict[str, dict[str, int]] = {}
    for identity, row in latest.items():
        lane = stats.setdefault(_strategy_key(row.get("strategy")), {"hypotheses": 0, "productive": 0})
        lane["hypotheses"] += 1
        if artifacts[identity]["productive"]:
            lane["productive"] += 1
    return dict(sorted(stats.items()))


#: Claim statuses that close a card for the run, from the queue's own
#: contract so a new terminal status cannot go uncounted here.
_CONCLUDED_CARD_STATUSES = frozenset(workqueue.TERMINAL_CARD_STATUSES)


def coverage(results_dir: Path) -> dict:
    """How much of the ranked attack surface each lane examined.

    Lanes and hypotheses say what a run produced; this says what it was
    handed, so a queue or rotation change that starves a lane shows up as an
    unexamined share rather than a quiet drop in yield. Cards come from the
    rank window (``work-cards.jsonl``); "examined" is a claim-based proxy — a
    session claimed the card — not proof it read the card's file, and
    "concluded" means its latest claim carries a terminal status.
    """
    results = Path(results_dir)
    cards = _rows(results / "work-cards.jsonl")
    latest_claim: dict[str, str] = {}
    for row in _rows(results / "state" / "claims.jsonl"):
        card_id = row.get("card_id")
        if isinstance(card_id, str) and card_id:
            latest_claim[card_id] = str(row.get("status") or "").lower()
    lanes: dict[str, dict] = {}
    for card in cards:
        lane = lanes.setdefault(_strategy_key(card.get("strategy")), {
            "cards": 0, "examined": 0, "concluded": 0,
            "_files": set(), "_files_examined": set(),
        })
        card_id = str(card.get("id") or "")
        file_name = str(card.get("file") or "")
        lane["cards"] += 1
        lane["_files"].add(file_name)
        status = latest_claim.get(card_id)
        if status is not None:
            lane["examined"] += 1
            lane["_files_examined"].add(file_name)
            if status in _CONCLUDED_CARD_STATUSES:
                lane["concluded"] += 1
    out: dict[str, dict] = {}
    for lane, stats in sorted(lanes.items()):
        out[lane] = {
            "cards": stats["cards"],
            "examined": stats["examined"],
            "concluded": stats["concluded"],
            "files": len(stats["_files"]),
            "files_examined": len(stats["_files_examined"]),
            "examined_share": round(stats["examined"] / stats["cards"], 4),
        }
    total = sum(v["cards"] for v in out.values())
    examined = sum(v["examined"] for v in out.values())
    return {
        "cards": total,
        "examined": examined,
        "examined_share": round(examined / total, 4) if total else None,
        "lanes": out,
        "tree": tree_coverage(results),
    }


def tree_coverage(results_dir: Path) -> dict:
    """The manifest side of coverage: how much of the tree the window reached.

    Lane shares are over cards, which only ever exist for files inside the
    ranked window; this block is over every auditable file the ranker
    enumerated, so a large tree with a small window reads as mostly unoffered
    rather than as fully examined.
    """
    manifest = coverage_ledger.read_manifest(Path(results_dir))
    receipted = coverage_ledger.examined_ranges_by_file(Path(results_dir))
    files = len(manifest)
    offered = sum(1 for row in manifest if row.get("offered"))
    lines = sum(int(row.get("lines") or 0) for row in manifest)
    examined = sum(
        min(int(row.get("lines") or 0),
            coverage_ledger.examined_lines(receipted.get(str(row.get("file") or ""), [])))
        for row in manifest
    )
    return {
        "files": files,
        "offered": offered,
        "offered_share": round(offered / files, 4) if files else None,
        "receipted": sum(1 for row in manifest if receipted.get(row.get("file"))),
        "lines_examined_share": round(examined / lines, 4) if lines else None,
    }


def execution_verdicts(results_dir: Path) -> dict:
    """Probe verdict counts. EXEC_FAIL is a command that returned without
    completing cleanly — rejected input, loader, usage, or runner failure — a
    launch that cost a sanitizer run and taught nothing."""
    counts: dict[str, int] = {}
    checked = repeats = 0
    for row in _rows(Path(results_dir) / "state" / "runs.jsonl"):
        verdict = str(row.get("verdict") or "").upper() or "UNKNOWN"
        counts[verdict] = counts.get(verdict, 0) + 1
        if "duplicate_of" in row:
            checked += 1
            repeats += bool(row["duplicate_of"])
    total = sum(counts.values())
    return {
        "counts": dict(sorted(counts.items())),
        "total": total,
        "exec_fail_share": (round(counts.get("EXEC_FAIL", 0) / total, 4) if total else None),
        # Sanitizer crashes that repeated a filed state through the same
        # route: re-derived work. None when no run recorded the check.
        "filed_state_repeats": repeats if checked else None,
        "filed_state_checked": checked,
    }


_CRASH_SLOT_RE = re.compile(r"^CRASH-\d+-(\d+)(?:\..*)?$")


def _agent_by_artifact(results_dir: Path) -> dict[str, set[str]]:
    """Artifact directory name -> agents whose hypotheses closed on it."""
    agents: dict[str, set[str]] = {}
    latest = _latest_by_id(_rows(Path(results_dir) / "state" / "hypotheses.jsonl"))
    for identity, placed in hypothesis_artifacts(results_dir).items():
        if placed["artifact"]:
            agents.setdefault(placed["artifact"], set()).add(
                str(latest[identity].get("agent") or ""),
            )
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
        filers = set(agents.get(artifact, set()))
        # A crash bundle names its slot, so it places itself even when no
        # hypothesis was closed on it.
        slot = _CRASH_SLOT_RE.match(artifact)
        if slot:
            filers.add(slot.group(1))
        by_signature.setdefault(tuple(signature), set()).update(filers)
    multi = sum(1 for members in by_signature.values() if len(members - {""}) > 1)
    total = len(by_signature)
    return {
        "signatures": total,
        "multi_agent": multi,
        "rate": (round(multi / total, 4) if total else None),
    }


# ``<stamp> <decision> [key=value ...] OK|FAIL|SKIP <rest>``; a batch decision
# puts its vote tally before the outcome.
_DECISION_LINE_RE = re.compile(
    r"^\S+ (?P<decision>\S+)(?: \S+=\S+)* (?P<outcome>OK|FAIL|SKIP)\b(?P<rest>.*)$"
)
_ELAPSED_RE = re.compile(r"elapsed=(\d+)s")


def decisions(results_dir: Path) -> dict:
    """Harness review calls: how many ran, failed, were skipped, and what they cost.

    A review decision that times out is fail-cached and logged only in
    ``llm-decisions.log``; one such call held the background gate for 330
    wall-seconds while the cell reported a clean run. ``failed_seconds`` is
    the wall those calls consumed. ``None`` when the log was never written.
    """
    log = llm_usage.find_usage_index(Path(results_dir)).with_name("llm-decisions.log")
    try:
        lines = log.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"calls": None, "failed": None, "skipped": None, "failed_seconds": None, "failures": []}
    calls = failed = skipped = 0
    failed_seconds = 0.0
    failures: list[str] = []
    for line in lines:
        match = _DECISION_LINE_RE.match(line.strip())
        if not match:
            continue
        outcome = match.group("outcome")
        if outcome == "SKIP":
            skipped += 1
            continue
        calls += 1
        if outcome == "FAIL":
            failed += 1
            elapsed = _ELAPSED_RE.search(match.group("rest"))
            failed_seconds += float(elapsed.group(1)) if elapsed else 0.0
            failures.append(f"{match.group('decision')}{match.group('rest').rstrip()}")
    return {
        "calls": calls, "failed": failed, "skipped": skipped,
        "failed_seconds": round(failed_seconds, 3), "failures": failures,
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
    artifacts = hypothesis_artifacts(results)
    rows: list[dict] = []
    for identity, row in sorted(latest.items()):
        status = str(row.get("status") or "")
        artifact = artifacts[identity]["artifact"]
        rows.append({
            "card_id": row.get("card_id"),
            "hypothesis_id": identity,
            "agent": row.get("agent"),
            "strategy": _strategy_key(row.get("strategy")),
            "status": status,
            "testcases": testcases.get(identity, []),
            "artifact": artifact,
            "productive": artifacts[identity]["productive"],
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


def summary(results_dir: Path, origin: str = "") -> dict:
    """The whole telemetry block for one results tree (see harvest).

    ``origin`` is the cell's recorded start; see run_start for why a
    model-direct cell cannot be clocked without it.
    """
    results = Path(results_dir)
    return {
        "occupancy": occupancy(results),
        "housekeeping": housekeeping(results),
        "finalization": finalization(results),
        "time_to_first": time_to_first(results, origin),
        "lanes": lane_stats(results),
        "coverage": coverage(results),
        "execution": execution_verdicts(results),
        "duplicate_roots": duplicate_roots(results),
        "decisions": decisions(results),
        "lineage_rows": len(lineage(results)),
    }
