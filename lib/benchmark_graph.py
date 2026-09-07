#!/usr/bin/env python3
"""Discovery timing for the benchmark result page (lib/benchmark_page.py).

Why this exists in its own module: the audit's in-run counter (`totals=N
findings` in audit.log) is an *inventory*, not a discovery log — it falls when a
finding is demoted and finalization re-adjudicates it in either direction, so it
cannot carry a curve. This builds the honest one instead:

  * the pooled per-condition directories are authoritative for *what* survived,
    so the curve ends exactly on the number the table reports;
  * each result is placed at *when* it was found, resolved from the cells;
  * results use the clusterers' own membership; rejected legacy rows without
    clustering evidence remain visible as an explicitly marked upper bound.

The curve is therefore monotonic by construction. Anything whose discovery time
cannot be resolved is placed at the end of the run rather than dropped, so the
endpoint always equals the table.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta
from pathlib import Path

import benchmark
import crash_artifacts
import finding_dedup
import finding_signature
import stack_frames

_TS = re.compile(r"^\[(\d\d):(\d\d):(\d\d)\]")


def _report_text(directory: Path) -> str:
    for name in ("report.md", "REPORT.md"):
        candidate = directory / name
        if candidate.is_file():
            return candidate.read_text(encoding="utf-8", errors="replace")
    return ""


def _signature(directory: Path, kind: str) -> tuple | None:
    """Join key for one artifact, or None when it cannot be identified.

    Must survive pooling: pooling renames FIND-002-foo to FIND-0001, so a
    name-based key can never join a pooled result back to the cell that found
    it. Crashes therefore fall back to sanitizer.txt — the evidence the real
    crash clusterer keys on — before giving up. Giving up returns None rather
    than a name, because an identity that cannot join is worse than an admitted
    unknown: it silently lands the result at the run's end.
    """
    text = _report_text(directory)
    if kind == "find":
        if not text:
            return None
        return tuple(str(p) for p in finding_signature.finding_signature(text)["key"])
    state = finding_dedup.crash_state(text, want=3) if text else ()
    if not state:
        sanitizer = directory / "sanitizer.txt"
        if sanitizer.is_file():
            state = finding_dedup.crash_state(
                sanitizer.read_text(encoding="utf-8", errors="replace"), want=3,
            )
    return state or None


def _cell_start(cell_dir: Path) -> float | None:
    """Epoch seconds when the cell started doing work.

    The audit log sits beside cell.json, not down in the nested results tree.
    Probing next to results/ silently found nothing, and a missing origin
    rebases every curve onto its own first artifact — planting "hour zero"
    wherever the first result happened to land instead of at the run's start.

    started_at is authoritative when the cell recorded it (it also covers
    model-direct, which keeps no audit log); the audit's first iteration stamp
    is the fallback that reads runs recorded before that field existed.
    """
    cell_dir = Path(cell_dir)
    try:
        meta = json.loads((cell_dir / "cell.json").read_text(encoding="utf-8"))
        started = meta.get("started_at")
        if started:
            return datetime.fromisoformat(started).timestamp()
    except (OSError, ValueError, TypeError):
        pass
    log = cell_dir / "audit.log"
    if not log.is_file():
        return None
    try:
        stamp = log.stat().st_mtime
    except OSError:
        return None
    first = None
    with log.open(errors="replace") as stream:
        for line in stream:
            match = _TS.match(line)
            if match and "Iteration 1 starting" in line:
                first = match.groups()
                break
    if not first:
        return None
    # audit.log stamps are local wall clock and carry no date, so anchor them
    # against the log's own mtime read in local time — reading that mtime as
    # UTC skews every hour by the zone offset.
    tail = datetime.fromtimestamp(stamp)
    anchor = tail.replace(hour=int(first[0]), minute=int(first[1]),
                          second=int(first[2]), microsecond=0)
    # the log's mtime is the run's tail, so a start reading later than the tail
    # means the run crossed midnight
    if anchor > tail:
        anchor -= timedelta(days=1)
    return anchor.timestamp()


def _artifact_time(directory: Path) -> float | None:
    """Compatibility name for the shared artifact filing clock."""
    return crash_artifacts.filing_time(directory)


def _discovery_index(cells: list[Path]) -> dict[tuple, dict[tuple, float]]:
    """{kind: {signature: earliest hours-into-run it was seen}}."""
    index: dict[str, dict[tuple, float]] = {"find": {}, "crash": {}}
    for cell in cells:
        try:
            meta = json.loads((cell / "cell.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        results = benchmark.cell_results_dir(meta)
        if results is None or not results.is_dir():
            continue
        stamps = _event_stamps(results)
        origin = _cell_start(cell)
        roots = {
            "find": ("findings", "findings-rejected"),
            "crash": ("crashes", "crashes-rejected"),
        }
        found: dict[str, list[tuple[Path, float]]] = {}
        for kind, subdirs in roots.items():
            for sub in subdirs:
                root = results / sub
                if not root.is_dir():
                    continue
                for directory in sorted(root.iterdir()):
                    if not directory.is_dir():
                        continue
                    when = stamps.get(directory.name)
                    if when is None:
                        when = _artifact_time(directory)
                    if when is None:
                        continue
                    # key it once: _signature re-reads the report off disk
                    key = _signature(directory, kind)
                    if key is None:
                        continue
                    found.setdefault(kind, []).append((key, when))
        if not found:
            continue
        # One origin for the whole cell. Falling back per artifact kind gave
        # findings and crashes different zeroes, so the two panels of a row no
        # longer shared a clock.
        base = origin if origin else min(
            when for entries in found.values() for _, when in entries
        )
        for kind, entries in found.items():
            for key, when in entries:
                hours = max(0.0, (when - base) / 3600.0)
                previous = index[kind].get(key)
                if previous is None or hours < previous:
                    index[kind][key] = hours
    return index


def _event_stamps(results: Path) -> dict[str, float]:
    """finding_created stamps, when the run recorded them (new runs only)."""
    events = results / "state" / "events.jsonl"
    if not events.is_file():
        return {}
    out: dict[str, float] = {}
    with events.open(errors="replace") as stream:
        for line in stream:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if row.get("type") != "finding_created":
                continue
            stamp = row.get("mtime") or row.get("first_seen")
            try:
                out[row["id"]] = datetime.fromisoformat(stamp).timestamp()
            except (TypeError, ValueError, KeyError):
                continue
    return out


def _load_clusters(path: Path) -> list[dict]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    return data.get("clusters", []) if isinstance(data, dict) else []


def _cluster_site(cluster: dict, kind: str) -> str:
    """Source location the cluster is pinned to, or "" when it has none.

    Both clusterers already carry it — findings key on (class, file, line), and
    crash dedup signatures preserve their parsed frame displays — so the graph
    names the same site as the cluster index it sits beside, with no second
    parse of the reports. A frame without a file (an entry thunk) falls through
    to the next one rather than reporting the symbol as a path.
    """
    if kind == "find":
        source = str(cluster.get("file") or "").strip()
        line = str(cluster.get("line") or "").strip()
        return f"{source}:{line}" if source and line else source
    for display in str(cluster.get("signature") or "").split(" -> "):
        fallback = display.startswith("fallback:")
        body = display.removeprefix("fallback:")
        while body:
            # Fallback states can append a stack/report object after their
            # source root. Trim only that controlled fallback suffix; real
            # frame displays are parsed whole so dotted function tokens cannot
            # be reconsidered as paths.
            _function, location = stack_frames.parse_frame_body(body)
            if location and not location.startswith(("(", "??:", "<unknown>:")):
                return location
            if not fallback or " " not in body:
                break
            body = body.rsplit(" ", 1)[0]
    return ""


def _cluster_times(
    run_dir: Path, cond: str, kind: str, rejected: bool,
    index: dict, members: dict, fallback: float,
) -> tuple[list[tuple[float, str, str]], bool]:
    """Earliest discovery time and source site per REAL cluster, from the
    clusterer's own JSON.

    The clusterers merge more than a raw signature key does, so a locally
    deduplicated list cannot be mapped onto their counts by truncation: given
    times 0.1 and 0.2 in one fuzzy cluster and 0.9 in another, dropping the tail
    yields [0.1, 0.2] when the honest answer is [0.1, 0.9]. Reading the real
    membership and taking each cluster's earliest member gives the right curve
    and the right length at once.

    Returns ([(time, site, cluster_id)], approximate) — approximate when any
    cluster had no member we could place on the timeline. The id lets the page
    replay a run: it joins each step back to the dot it becomes.
    """
    sub = ("crashes" if kind == "crash" else "findings") + ("-rejected" if rejected else "")
    owner = benchmark.credited_pool_members(members, sub)
    pool_dir = run_dir / "pool" / sub
    times: list[tuple[float, str, str]] = []
    approximate = False
    for cluster in _load_clusters(run_dir / f"clusters-{sub}.json"):
        mine = [m for m in (cluster.get("members") or []) if owner.get(m) == cond]
        if not mine:
            continue
        best = None
        for member in mine:
            directory = pool_dir / member
            if not directory.is_dir():
                continue
            key = _signature(directory, kind)
            when = index.get(kind, {}).get(key) if key else None
            if when is not None and (best is None or when < best):
                best = when
        if best is None:
            # counted by the table, but nothing we can honestly place in time
            best = fallback
            approximate = True
        when = min(max(0.0, best), fallback) if fallback else max(0.0, best)
        times.append((when, _cluster_site(cluster, kind), str(cluster.get("id") or "")))
    return sorted(times), approximate


def _is_batch_quantized(times: list[float]) -> bool:
    """True when the clock is the gate's batch write, not per-result discovery.

    Without the finding_created stream the only surviving clock on an old
    artifact is whatever the quality gate wrote, and the gate validates in
    batches — so many results collapse onto one instant and the curve grows a
    vertical cliff it has not earned. Detect that directly rather than trusting
    the stamps' presence: a re-run of the gate writes stamps too, and they are
    just as batched.
    """
    if len(times) < 3:
        return False
    # a batch write spans a second or two, so bucket to ~36s rather than test
    # exact equality — 2.519h and 2.520h are the same write
    buckets: dict[int, int] = {}
    for value in times:
        key = round(value / 0.01)
        buckets[key] = buckets.get(key, 0) + 1
    return max(buckets.values()) / len(times) > 0.3


def _reconcile(
    times: list[tuple[float, str, str]], count: int, wall: float,
) -> list[tuple[float, str, str]]:
    """Make the curve land exactly on the count the table reports.

    The clusterers merge a little more than the raw signature key does, so a
    local dedup can differ by one or two. The table is authoritative for *how
    many*; this list only carries *when* and *where*. Extra entries drop from
    the tail (a merged pair is discovered when its earlier half was); a
    shortfall lands at the end of the run, with no site, rather than inventing
    an early discovery or a location it was never given.
    """
    if count <= 0:
        return []
    if len(times) > count:
        return times[:count]
    return times + [(wall, "", "")] * (count - len(times))


def build(bench_root: Path) -> dict:
    """Collect one series per target/backend/condition/run."""
    bench_root = Path(bench_root)
    series: list[dict] = []
    target_groups: set[tuple[str, str]] = set()
    for run_dir in sorted(bench_root.glob("*/*")):
        run_json = run_dir / "run.json"
        if not run_json.is_file():
            continue
        try:
            run = json.loads(run_json.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        try:
            members = json.loads((run_dir / "pool-members.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            members = {}
        report_path = run_dir / "report.json"
        try:
            report = json.loads(report_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        target = str(run.get("target") or "?")
        target_sha = str(run.get("target_sha") or "")
        cells_by_cond: dict[str, list[Path]] = {}
        for cell in sorted((run_dir / "cells").glob("*")):
            if not (cell / "cell.json").is_file():
                continue
            name = cell.name
            cond = "harness" if name.startswith("harness") else "model-direct"
            cells_by_cond.setdefault(cond, []).append(cell)
        for condition in report.get("conditions", []):
            cond = condition.get("condition")
            cells = cells_by_cond.get(cond, [])
            if not cells:
                continue
            index = _discovery_index(cells)
            wall = (condition.get("wall_median") or 0) / 3600.0
            entry = {
                "target": target,
                "target_sha": target_sha,
                "backend": run.get("backend", "?"),
                "model": (run.get("model") or "").strip(),
                "condition": cond,
                "run_id": run_dir.name,
                "version": (run.get("tokenfuzz_sha") or "")[:7],
                "replicates": condition.get("replicates_done", 0),
                "wall_h": round(wall, 3),
            }
            for kind, uniq_key, rej_key, upper_key, mplus in (
                ("find", "unique_finding_clusters",
                 "unique_rejected_finding_clusters",
                 "rejected_finding_clusters_upper_bound", "medium_plus_findings"),
                ("crash", "unique_crash_clusters",
                 "unique_rejected_crash_clusters",
                 "rejected_crash_clusters_upper_bound", "medium_plus_bugs"),
            ):
                # the table's number is authoritative; these lists carry only the
                # timing of it, so the curve can never disagree with the table
                n_accepted = condition.get(uniq_key) or 0
                n_rejected = condition.get(rej_key) or 0
                declared_upper_bound = bool(condition.get(upper_key))
                acc_times, acc_approx = _cluster_times(
                    run_dir, cond, kind, False, index, members, wall)
                rej_times, rej_approx = _cluster_times(
                    run_dir, cond, kind, True, index, members, wall)
                # Reports written before the explicit bit can still reveal the
                # upper bound: more rejected results than clusters means some
                # rows had no clustering evidence or the cluster file failed.
                rejected_upper_bound = (
                    declared_upper_bound or len(rej_times) < n_rejected
                )
                accepted = _reconcile(acc_times, n_accepted, wall)
                rejected = _reconcile(rej_times, n_rejected, wall)
                entry[kind] = {
                    # approximate when a cluster could not be placed in time, when
                    # the table's count and the clusters we could read disagree, or
                    # when the only surviving clock is a batch write
                    "approx_timing": bool(
                        acc_approx or rej_approx
                        or rejected_upper_bound
                        or len(acc_times) != n_accepted
                        or len(rej_times) != n_rejected
                        or _is_batch_quantized([t for t, _, _ in accepted])
                    ),
                    "accepted": n_accepted,
                    "rejected": n_rejected,
                    "rejected_upper_bound": rejected_upper_bound,
                    "medium_plus": condition.get(mplus, 0),
                    "accepted_times": [round(t, 4) for t, _, _ in accepted],
                    # parallel to accepted_times: the source site behind each
                    # step and the cluster it is, "" where unknown
                    "accepted_sites": [site for _, site, _ in accepted],
                    "accepted_ids": [cid for _, _, cid in accepted],
                    "rejected_times": [round(t, 4) for t, _, _ in rejected],
                    "rejected_ids": [cid for _, _, cid in rejected],
                }
            series.append(entry)
            target_groups.add((target, target_sha))
    return {
        "series": series,
        "target_groups": [
            {"target": target, "target_sha": target_sha}
            for target, target_sha in sorted(target_groups)
        ],
    }
