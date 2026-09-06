#!/usr/bin/env python3
"""The cross-backend benchmark result page: `output/benchmark/benchmark-result.html`.

Why this is one module and not a Markdown table plus a graph bolted on: the
question the benchmark answers — does the harness find stronger real bugs than
the same model asked directly — has several axes that a flat crosstab cannot
show side by side. What each condition found that the other did not, at which
severity and in which bug class; when it found it; what the agents were doing
while they looked; how much of what they claimed survived review; and what
each of those cost. The page carries all of them from the same on-disk evidence
the Markdown ledger reads, so no number here can disagree with a number there.

Two rules keep the page honest:

  * Every count comes from the run's `report.json` (or, for a run still going,
    the same aggregate the ledger uses) — the page never re-counts artifacts.
    Timing and activity come from the cell state streams the audit wrote while
    it ran, and are placed on the run's own clock; where a result cannot be
    placed in time it is marked approximate rather than dropped.
  * A gap in the evidence is shown as a gap. Pending, unjudged, floor, retained,
    estimated, and upper-bound states all reach the page with their marks, and a
    run without a final report renders as provisional.

The page is self-contained (inline CSS and script, no network), so it opens
from `file://`, survives `bin/export-benchmark`, and renders without script as a
plain scoreboard and per-run tables.
"""

from __future__ import annotations

import html
import json
import math
import re
from datetime import datetime, timezone
from pathlib import Path

import benchmark
import benchmark_graph
import severity_receipt
import stack_frames
import strategies

BIN_HOURS = 0.25
MAX_BINS = 96

# What each strategy lane means, for the activity legend and the lane table.
# The registry owns the tokens; the words follow docs/concepts/strategy-model.md.
LANE_NAMES = {
    "S1": "Prior-fix variant",
    "S2": "Invariant negation",
    "S3": "Spec vs. implementation",
    "S4": "Boundary fuzzing",
    "S5": "Lifetime and state",
    "S6": "Cross-project variant",
    "S7": "Adversarial input",
    "S8": "Property oracles",
}
# Probe verdicts the timeline draws, in stack order. Anything else the runner
# records (PROPERTY, NO_EXEC) folds into "other" so the strip never hides work.
PROBE_VERDICTS = ("CRASH", "CLEAN", "TIMEOUT", "EXEC_FAIL", "other")

_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
_TITLE = re.compile(r"^#\s*(?:[A-Z]+-[\w.-]+\s*[:—–-]\s*)?(.+?)\s*$")
_BUG_LINE = re.compile(r"^-\s*\*\*Bug\*\*\s*[—–-]\s*(.+?)\s*$")


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _iter_jsonl(path: Path):
    if not path.is_file():
        return
    with path.open(errors="replace") as stream:
        for line in stream:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                yield row


def _epoch(stamp: object) -> float | None:
    if not isinstance(stamp, str) or not stamp:
        return None
    try:
        return datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _href(path: Path | None) -> str:
    """A clickable link for an artifact on disk, or "" when there is none.

    Links go through the ledger's own path helper so an exported bundle gets
    relative links and a local page gets `file://` ones — and a link is only
    emitted for something that exists, so a `0` never points at a sibling
    condition's evidence.
    """
    if path is None or not path.exists():
        return ""
    return benchmark._path_uri(path)


def _report_href(directory: Path, basename: str) -> str:
    for suffix in (".html", ".md"):
        candidate = directory / f"{basename}{suffix}"
        if candidate.is_file():
            return _href(candidate)
    return _href(directory) if directory.is_dir() else ""


def _artifact_href(directory: Path) -> str:
    for name in ("report.html", "REPORT.html", "report.md", "REPORT.md"):
        if (directory / name).is_file():
            return _href(directory / name)
    return ""


def _artifact_title(directory: Path) -> str:
    """The report's own heading, without its artifact id prefix.

    A direct-condition report often carries no H1 at all — the enrichment
    TL;DR is the first thing in the file — so the reviewer's one-line "Bug"
    summary stands in, trimmed to a title's length. Neither is invented: both
    are the report's own words.
    """
    for name in ("report.md", "REPORT.md"):
        candidate = directory / name
        if not candidate.is_file():
            continue
        fallback = ""
        try:
            with candidate.open(encoding="utf-8", errors="replace") as stream:
                for line in stream:
                    if line.startswith("# "):
                        match = _TITLE.match(line)
                        return match.group(1) if match else line[2:].strip()
                    if not fallback:
                        match = _BUG_LINE.match(line)
                        if match:
                            fallback = match.group(1).strip()
        except OSError:
            return ""
        if fallback:
            return fallback if len(fallback) <= 140 else fallback[:137].rstrip() + "…"
    return ""


def _severity_of(cluster: dict, members: set[str] | None = None) -> tuple[str, int]:
    """(level, rank) for a cluster, from its own field or its strongest member.

    Finding clusters in report.json carry a placeholder level with the member
    scores beside it; crash clusters carry the level directly. With *members*
    given, only those members are scored — the aggregate credits a condition
    for the severity of the reports *it* filed, so a shared cluster can be
    Medium for one side and Low for the other, and the M+ count in the table
    is the per-side figure. A side whose own report was never scored is
    unscored, not a borrower of the other side's score.
    """
    if members is None:
        level = str(cluster.get("severity_level") or "").strip()
        if level in _SEVERITY_RANK:
            return level, _SEVERITY_RANK[level]
    best = ("", 0)
    for name, member in (cluster.get("member_severity") or {}).items():
        if not isinstance(member, dict) or (members is not None and name not in members):
            continue
        label = str(member.get("level") or "")
        rank = _SEVERITY_RANK.get(label, 0)
        if rank > best[1]:
            best = (label, rank)
    return best


def _cluster_index(run_dir: Path, kind: str) -> dict[str, dict]:
    """Clusterer output keyed by cluster id: sites and signatures live there."""
    name = "findings" if kind == "find" else "crashes"
    out: dict[str, dict] = {}
    for entry in benchmark_graph._load_clusters(run_dir / f"clusters-{name}.json"):
        if isinstance(entry, dict) and entry.get("id"):
            out[str(entry["id"])] = entry
    return out


def _clusters(run_dir: Path, report: dict, bench_dir: Path | None) -> dict[str, list[dict]]:
    """Every reportable cluster of the run, with which conditions found it.

    `conditions` on a cluster is the overlap the whole page turns on: a problem
    found by one side only is that side's unique yield, and one found by both
    is shared. The site and title come from the cluster's canonical report so
    a reader can open exactly the evidence behind a dot.
    """
    members = _read_json(run_dir / "pool-members.json", {}) or {}
    out: dict[str, list[dict]] = {"find": [], "crash": []}
    for kind, key, sub in (
        ("find", "finding_clusters", "findings"),
        ("crash", "crash_clusters", "crashes"),
    ):
        index = _cluster_index(run_dir, kind)
        owner = members.get(sub, {}) or {}
        for cluster in report.get(key) or []:
            if not isinstance(cluster, dict):
                continue
            cid = str(cluster.get("id") or "")
            detail = index.get(cid, {})
            level, rank = _severity_of(cluster)
            conditions = [str(c) for c in (cluster.get("conditions") or [])]
            canonical = str(detail.get("canonical") or "")
            member_list = [str(m) for m in (cluster.get("members") or [])]
            severity_by = {
                cond: _severity_of(cluster, {m for m in member_list if owner.get(m) == cond})[0]
                for cond in conditions
            }
            if not canonical and member_list:
                canonical = member_list[0]
            href = ""
            if bench_dir is not None and canonical:
                # the per-condition pool copy carries the same canonical name
                for cond in conditions:
                    if cond == "model-direct" and owner.get(canonical) != cond:
                        # canonical may belong to the other side; find a member
                        # this condition filed
                        mine = [m for m in member_list if owner.get(m) == cond]
                        artifact = mine[0] if mine else canonical
                    else:
                        artifact = canonical
                    href = _artifact_href(
                        benchmark._condition_pool_dir(bench_dir, cond, sub) / artifact
                    )
                    if href:
                        break
            title = _artifact_title(run_dir / "pool" / sub / canonical) if canonical else ""
            out[kind].append({
                "id": cid,
                "kind": kind,
                # crash clusters carry no finding class; they are their own row
                "class": "sanitizer crash" if kind == "crash" else str(
                    cluster.get("class") or detail.get("class") or "other"),
                "conditions": sorted(set(conditions)),
                "severity": level,
                "rank": rank,
                "severity_by": severity_by,
                "score": cluster.get("severity_score"),
                "primitive": str(cluster.get("primitive") or ""),
                "site": benchmark_graph._cluster_site(detail, kind),
                "title": title,
                "href": href,
                "size": int(cluster.get("size") or len(member_list) or 1),
                "strategy": str(detail.get("strategy") or ""),
            })
    return out


def _rejected_clusters(run_dir: Path, bench_dir: Path | None) -> dict[str, list[dict]]:
    """Rejected clusters with the reviewer's reason: what did not hold up.

    Rejections are as much a description of a condition as its yield — the
    same over-claiming that a raw tally rewards shows up here as a reason. Only
    findings carry a per-artifact rationale on disk; rejected crashes carry
    their disposition in the index the count links to.
    """
    members = _read_json(run_dir / "pool-members.json", {}) or {}
    reasons: dict[str, str] = {}
    rejected_root = run_dir / "pool" / "findings-rejected"
    if rejected_root.is_dir():
        for row in benchmark._rejected_finding_rows(rejected_root):
            reasons[row["id"]] = re.sub(r"\s+", " ", row.get("reason") or "").strip()
    out: dict[str, list[dict]] = {"find": [], "crash": []}
    for kind, sub in (("find", "findings-rejected"), ("crash", "crashes-rejected")):
        owner = members.get(sub, {}) or {}
        for cluster in benchmark_graph._load_clusters(run_dir / f"clusters-{sub}.json"):
            member_list = [str(m) for m in (cluster.get("members") or [])]
            conditions = sorted({owner[m] for m in member_list if m in owner})
            if not conditions:
                continue
            canonical = str(cluster.get("canonical") or (member_list[0] if member_list else ""))
            level, rank = _severity_of({
                "severity_level": cluster.get("severity_label") or cluster.get("severity_level"),
                "member_severity": cluster.get("member_severity"),
            })
            href = ""
            if bench_dir is not None and canonical:
                for cond in conditions:
                    href = _artifact_href(
                        benchmark._condition_pool_dir(bench_dir, cond, sub) / canonical
                    )
                    if href:
                        break
            out[kind].append({
                "id": str(cluster.get("id") or canonical),
                "kind": kind,
                "class": "sanitizer crash" if kind == "crash" else str(cluster.get("class") or "other"),
                "conditions": conditions,
                "severity": level,
                "rank": rank,
                "site": benchmark_graph._cluster_site(cluster, kind),
                "title": _artifact_title(run_dir / "pool" / sub / canonical) if canonical else "",
                "reason": next((reasons[m] for m in member_list if reasons.get(m)), ""),
                "href": href,
                "size": len(member_list) or 1,
            })
    return out


# ── activity: what the agents were doing, on the run's clock ─────────────────

def _new_activity(bins: int) -> dict:
    return {
        "bin_h": BIN_HOURS,
        "bins": bins,
        "hyp": {},
        "probe": {verdict: [0] * bins for verdict in PROBE_VERDICTS},
        "filed_find": [0] * bins,
        "filed_crash": [0] * bins,
        "admitted": [0] * bins,
        "rejected": [0] * bins,
        "out_tokens": [0] * bins,
        "cells": 0,
        "agents": 0,
        "sources": [],
    }


def _bin_of(activity: dict, when: float | None, origin: float,
            limit: float | None = None) -> int | None:
    if when is None or (limit is not None and when > limit):
        return None
    index = int((when - origin) / 3600.0 / activity["bin_h"])
    if index < 0 or index >= activity["bins"]:
        return None
    return index


def _usage_index(results: Path) -> Path | None:
    """The cell's usage stream, wherever this backend's harvester put it."""
    for candidate in (results / "logs" / "index.jsonl",
                      results.parent / "logs" / "index.jsonl"):
        if candidate.is_file():
            return candidate
    return None


def _add_cell_activity(activity: dict, cell_dir: Path, meta: dict) -> None:
    """Fold one cell's state streams into the condition's activity.

    Everything is placed on the cell's own start clock, the same origin the
    discovery curve uses, so the two panels of a run share an x-axis. Events
    past the wall (finalization, post-cell review) fall outside the bins and
    are not activity — they are measurement.
    """
    results = benchmark.cell_results_dir(meta)
    if results is None or not results.is_dir():
        return
    origin = benchmark_graph._cell_start(cell_dir)
    if origin is None:
        return
    # the cell's own elapsed wall bounds its activity: what follows it is
    # post-cell review, which the page reports as measurement, not work
    elapsed = _float(meta.get("wall_seconds"))
    limit = origin + elapsed if elapsed and elapsed > 0 else None
    activity["cells"] += 1
    activity["agents"] += int(meta.get("actual_agents") or 0) or (
        0 if meta.get("condition") == "harness" else 1
    )
    state = results / "state"
    for row in _iter_jsonl(state / "hypotheses.jsonl"):
        index = _bin_of(activity, _epoch(row.get("created_at")), origin, limit)
        if index is None:
            continue
        lane = strategies.normalize(str(row.get("strategy") or "")) or "other"
        activity["hyp"].setdefault(lane, [0] * activity["bins"])[index] += 1
        _mark(activity, "hypotheses")
    for row in _iter_jsonl(state / "runs.jsonl"):
        index = _bin_of(activity, _epoch(row.get("created_at")), origin, limit)
        if index is None:
            continue
        verdict = str(row.get("verdict") or "")
        if verdict not in activity["probe"]:
            verdict = "other"
        activity["probe"][verdict][index] += 1
        _mark(activity, "probes")
    for row in _iter_jsonl(state / "events.jsonl"):
        kind = row.get("type")
        if kind == "finding_created":
            key = "filed_find"
        elif kind == "crash_created":
            key = "filed_crash"
        elif kind == "artifact_admitted":
            key = "admitted"
        elif kind == "artifact_rejected":
            key = "rejected"
        else:
            continue
        stamp = row.get("mtime") if kind.endswith("_created") else row.get("first_seen")
        index = _bin_of(activity, _epoch(stamp or row.get("first_seen")), origin, limit)
        if index is None:
            continue
        activity[key][index] += 1
        _mark(activity, "events")
    usage = _usage_index(results)
    if usage is not None:
        for row in _iter_jsonl(usage):
            index = _bin_of(activity, _epoch(row.get("timestamp")), origin, limit)
            if index is None:
                continue
            tokens = row.get("tokens") or {}
            try:
                activity["out_tokens"][index] += int(tokens.get("output") or 0)
            except (TypeError, ValueError):
                continue
            _mark(activity, "usage")


def _mark(activity: dict, source: str) -> None:
    if source not in activity["sources"]:
        activity["sources"].append(source)


def _condition_activity(bench_dir: Path | None, condition: str, wall_h: float) -> dict | None:
    if bench_dir is None:
        return None
    cells = []
    for cell_dir in sorted((bench_dir / "cells").glob("*")):
        meta = _read_json(cell_dir / "cell.json", None)
        if isinstance(meta, dict) and meta.get("condition") == condition:
            cells.append((cell_dir, meta))
    # the axis spans the longest repeat, not the median: a repeat that ran
    # past the median keeps its tail instead of losing it off the last bin
    span = max([wall_h] + [
        (_float(meta.get("wall_seconds")) or 0.0) / 3600.0 for _, meta in cells
    ])
    bins = max(1, min(MAX_BINS, math.ceil(max(span, BIN_HOURS) / BIN_HOURS)))
    activity = _new_activity(bins)
    for cell_dir, meta in cells:
        _add_cell_activity(activity, cell_dir, meta)
    if not activity["sources"]:
        return None
    # trailing bins with nothing in them are still audit time: keep them
    return activity


# ── the mind trace: every hypothesis an agent opened, and what became of it ──

# Terminal statuses the audit writes on a hypothesis, folded to what a reader
# needs to know: did the idea pay off, fail on evidence, get dropped untested,
# or stall on the environment. Anything else is still open.
_OUTCOME = {
    "CONFIRMED": "confirmed",
    "REFUTED": "refuted", "DISPROVED": "refuted", "CONFIRMED-NO-CRASH": "refuted",
    "DISCARDED": "dropped", "CLOSED": "dropped",
    "ENV-BLOCKED": "blocked", "BLOCKED": "blocked",
}
OUTCOMES = ("hit", "confirmed", "refuted", "dropped", "blocked", "open")
_TEXT_CAP = {"hypothesis": 480, "guard_gap": 280, "input_shape": 200, "note": 320}


def _outcome(status: str, artifact: str) -> str:
    if artifact or status.startswith(("FIND-", "CRASH-")):
        return "hit"
    return _OUTCOME.get(status, "open")


def _subsystem(path: str) -> str:
    """The top-level directory a hypothesis or cluster site names, or ""."""
    location = str(path or "").split(":", 1)[0].strip().lstrip("./")
    if "/" not in location:
        return ""
    return location.split("/", 1)[0]


def _clip(text: object, cap: int) -> str:
    """Agent free text, on one line, without the host's paths, cut to *cap*.

    Notes quote build lines and absolute checkout paths; the pooled reports
    already have those collapsed to repo-relative form, and the page must not
    put them back — it is what gets exported.
    """
    value = benchmark._scrub_local_paths(re.sub(r"\s+", " ", str(text or "")).strip())
    return value if len(value) <= cap else value[:cap - 1].rstrip() + "…"


def _trace(cell_dir: Path, meta: dict) -> dict | None:
    """One cell's hypotheses on its own clock, each with the probes it drove.

    This is the run's reasoning as the audit recorded it: what each agent
    thought was wrong, where, which strategy lane framed it, what it ran to
    check, and how it ended. The text is the agent's own, clipped for the page;
    nothing is summarised on its behalf.
    """
    results = benchmark.cell_results_dir(meta)
    if results is None or not results.is_dir():
        return None
    origin = benchmark_graph._cell_start(cell_dir)
    if origin is None:
        return None
    elapsed = _float(meta.get("wall_seconds")) or 0.0
    wall_h = elapsed / 3600.0 if elapsed > 0 else None
    state = results / "state"

    def hours(stamp: object, clamp: bool = False) -> float | None:
        """Hours into the cell, or None when the stamp falls outside its wall.

        With *clamp*, a stamp past the wall reads as the wall: a hypothesis
        resolved by teardown was still open when the wall ended, and a bar
        that collapses to its opening instant would say it was dropped at
        once.
        """
        when = _epoch(stamp)
        if when is None:
            return None
        value = (when - origin) / 3600.0
        if value < 0:
            return None
        if wall_h is not None and value > wall_h:
            return round(wall_h, 4) if clamp else None
        return round(value, 4)

    artifacts: dict[str, str] = {}
    for row in _iter_jsonl(cell_dir / "lineage.jsonl"):
        if row.get("artifact") and row.get("hypothesis_id"):
            artifacts[str(row["hypothesis_id"])] = str(row["artifact"])
    probes: dict[str, list] = {}
    for row in _iter_jsonl(state / "runs.jsonl"):
        when = hours(row.get("created_at"))
        hid = str(row.get("hypothesis_id") or "")
        if when is None or not hid:
            continue
        probes.setdefault(hid, []).append({
            "t": when,
            "verdict": str(row.get("verdict") or "other"),
            "s": round(_float(row.get("duration_seconds")) or 0.0, 1),
        })
    notes: dict[str, list] = {}
    for row in _iter_jsonl(state / "notes.jsonl"):
        hid = str(row.get("hypothesis_id") or "")
        text = _clip(row.get("text"), 240)
        if not hid or not text:
            continue
        notes.setdefault(hid, []).append({
            "t": hours(row.get("created_at")), "kind": str(row.get("kind") or ""), "text": text,
        })
    hyps: list[dict] = []
    for row in _iter_jsonl(state / "hypotheses.jsonl"):
        hid = str(row.get("id") or "")
        t0 = hours(row.get("created_at"))
        if not hid or t0 is None:
            continue
        mine = sorted(probes.get(hid, []), key=lambda p: p["t"])
        t1 = max([t0, hours(row.get("updated_at"), clamp=True) or t0] + [p["t"] for p in mine])
        status = str(row.get("status") or "").strip().upper()
        artifact = artifacts.get(hid, "")
        hyps.append({
            "id": hid,
            "agent": str(row.get("agent") or "?"),
            "lane": strategies.normalize(str(row.get("strategy") or "")) or "other",
            "file": str(row.get("file") or ""),
            "subsystem": _subsystem(row.get("file")),
            "diagnostic": str(row.get("diagnostic") or ""),
            "t0": t0,
            "t1": t1,
            "status": status,
            "outcome": _outcome(status, artifact),
            "artifact": artifact,
            "text": _clip(row.get("hypothesis"), _TEXT_CAP["hypothesis"]),
            "guard_gap": _clip(row.get("guard_gap"), _TEXT_CAP["guard_gap"]),
            "input_shape": _clip(row.get("input_shape"), _TEXT_CAP["input_shape"]),
            "note": _clip(row.get("note"), _TEXT_CAP["note"]),
            "probes": mine,
            "notes": notes.get(hid, []),
        })
    if not hyps:
        return None
    hyps.sort(key=lambda h: (h["t0"], h["agent"]))
    summary = {outcome: 0 for outcome in OUTCOMES}
    for hyp in hyps:
        summary[hyp["outcome"]] += 1
    resolved = sorted(
        (h["t1"] - h["t0"]) * 60 for h in hyps if h["outcome"] not in ("open",))
    middle = len(resolved) // 2
    median = None
    if resolved:
        median = resolved[middle] if len(resolved) % 2 else (
            resolved[middle - 1] + resolved[middle]) / 2
    return {
        "cell": cell_dir.name,
        "wall_h": round(wall_h, 3) if wall_h else None,
        "agents": sorted({h["agent"] for h in hyps}, key=lambda a: (len(a), a)),
        "hyps": hyps,
        "summary": summary,
        "median_minutes": round(median, 1) if median is not None else None,
    }


def _traces(bench_dir: Path | None, condition: str) -> list[dict]:
    if bench_dir is None:
        return []
    traces = []
    for cell_dir in sorted((bench_dir / "cells").glob("*")):
        meta = _read_json(cell_dir / "cell.json", None)
        if not isinstance(meta, dict) or meta.get("condition") != condition:
            continue
        trace = _trace(cell_dir, meta)
        if trace:
            traces.append(trace)
    return traces


def _stamp_clusters(run: dict, series: dict[str, dict]) -> None:
    """Give every cluster the hour it was first seen, for the replay.

    The timing builder already joins clusters to the event stream and parks
    the unplaceable ones at the wall; taking the earliest across conditions
    keeps a shared cluster at the moment either side reached it.
    """
    when: dict[str, float] = {}
    for entry in series.values():
        for kind in ("find", "crash"):
            block = entry.get(kind) or {}
            for key_ids, key_times in (("accepted_ids", "accepted_times"),
                                       ("rejected_ids", "rejected_times")):
                for cid, hours in zip(block.get(key_ids) or [], block.get(key_times) or []):
                    if cid and (cid not in when or hours < when[cid]):
                        when[cid] = hours
    walls = [c["wall_h"] or 0.0 for c in run["conditions"]]
    wall = max(walls) if walls else None
    for bucket in (run["clusters"], run["rejected"]):
        for kind in ("find", "crash"):
            for cluster in bucket[kind]:
                # a cluster the builder trimmed or could not join has no hour
                # of its own; it lands at the wall like the padding does, so
                # it never plays back as found before everything else
                cluster["t"] = when.get(cluster["id"], wall if series else None)


def _attention(run: dict) -> list[dict]:
    """Where each side looked, and where the merged results were.

    Looking is only observable for the harness — its hypotheses name a file —
    so the direct control has a "found" column and nothing else, which is
    itself the honest picture: its process left no trace to draw.
    """
    rows: dict[str, dict] = {}

    def slot(name: str) -> dict:
        return rows.setdefault(name or "(no path)", {
            "subsystem": name or "(no path)", "hypotheses": 0, "probes": 0,
            "hits": 0, "harness": 0, "direct": 0, "rejected": 0})

    harness = _harness_of(run)
    for trace in (harness or {}).get("traces") or []:
        for hyp in trace["hyps"]:
            row = slot(hyp["subsystem"])
            row["hypotheses"] += 1
            row["probes"] += len(hyp["probes"])
            row["hits"] += hyp["outcome"] == "hit"
    for kind in ("find", "crash"):
        for cluster in run["clusters"][kind]:
            row = slot(_subsystem(cluster["site"]))
            for cond in cluster["conditions"]:
                row["harness" if cond == "harness" else "direct"] += 1
        for cluster in run["rejected"][kind]:
            slot(_subsystem(cluster["site"]))["rejected"] += 1
    return sorted(rows.values(), key=lambda r: (
        -(r["hypotheses"] + r["harness"] + r["direct"]), r["subsystem"]))


# ── per-condition summary ────────────────────────────────────────────────────

def _int(value: object) -> int:
    return benchmark._as_int(value)


def _float(value: object) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    try:
        out = float(value)
    except (TypeError, ValueError):
        return None
    return out if math.isfinite(out) else None


def _hours(seconds: object) -> float | None:
    value = _float(seconds)
    return round(value / 3600.0, 3) if value is not None and value > 0 else None


def _minutes(seconds: object) -> float | None:
    value = _float(seconds)
    return round(value / 60.0, 1) if value is not None and value >= 0 else None


def _waterfall(condition: dict, kind: str) -> dict | None:
    waterfall = condition.get("validation_waterfall")
    if not isinstance(waterfall, dict):
        return None
    stage = waterfall.get("findings" if kind == "find" else "crashes")
    if not isinstance(stage, dict):
        return None
    lanes = stage.get("lanes") if isinstance(stage.get("lanes"), dict) else {}
    return {
        "candidates": _int(stage.get("candidates")),
        "evidence": _int(stage.get("evidence_complete")),
        "validated": _int(stage.get("validated")),
        "reportable": _int(stage.get("reportable")),
        "rejected": _int(lanes.get("rejected")),
        "not_reportable": _int(lanes.get("not-reportable")),
        "pending": _int(lanes.get("pending")),
    }


def _count_block(condition: dict, kind: str, bench_dir: Path | None,
                 cond: str, provisional: bool, series: dict | None) -> dict:
    """One kind's counts for one condition, labelled the way the ledger does.

    The label strings reuse the ledger's own formatter so `≥`, `M+`, `classes`,
    `unjudged`, and `retained` mean exactly what the Markdown table says.
    """
    if kind == "find":
        unique = _int(condition.get("unique_finding_clusters"))
        mplus = _int(condition.get("medium_plus_findings"))
        unjudged = _int(condition.get("unadjudicated_finding_total"))
        floor = bool(condition.get("finding_total_is_floor"))
        classes = benchmark._finding_class_count(condition)
        retained = 0
        rejected = condition.get("unique_rejected_finding_clusters")
        rejected_upper = bool(condition.get("rejected_finding_clusters_upper_bound"))
        pool_sub, rejected_sub = "findings", "findings-rejected"
        basename, rejected_basename = "FINDING-CLUSTERS", "REJECTED-FINDINGS"
    else:
        unique = _int(condition.get("unique_crash_clusters"))
        mplus = _int(condition.get("medium_plus_bugs"))
        unjudged = _int(condition.get("unadjudicated_crash_total"))
        floor = bool(condition.get("crash_total_is_floor"))
        classes = 0
        retained = _int(condition.get("retained_crash_total"))
        rejected = condition.get("unique_rejected_crash_clusters")
        rejected_upper = bool(condition.get("rejected_crash_clusters_upper_bound"))
        pool_sub, rejected_sub = "crashes", "crashes-rejected"
        basename, rejected_basename = "CRASH-CLUSTERS", "REJECTED-CRASHES"
    label = benchmark._unique_with_medium_plus(
        unique, mplus, unjudged, classes, floor=floor, retained=retained)
    href = rejected_href = ""
    if bench_dir is not None:
        href = _report_href(benchmark._condition_pool_dir(bench_dir, cond, pool_sub), basename)
        rejected_href = _report_href(
            benchmark._condition_pool_dir(bench_dir, cond, rejected_sub), rejected_basename)
    block = {
        "unique": unique,
        "mplus": mplus,
        "classes": classes,
        "histogram": (condition.get("finding_class_histogram") or {}) if kind == "find" else {},
        "unjudged": unjudged,
        "floor": floor,
        "retained": retained,
        "label": "Pending" if provisional else label,
        "href": "" if provisional else href,
        "rejected": None if rejected is None else _int(rejected),
        "rejected_upper": rejected_upper,
        "rejected_label": "Pending" if provisional else (
            "—" if rejected is None else str(benchmark._rejected_label(_int(rejected), rejected_upper))
        ),
        "rejected_href": "" if provisional else rejected_href,
        "waterfall": _waterfall(condition, kind),
        "times": [],
        "sites": [],
        "rejected_times": [],
        "approx": False,
    }
    if series is not None:
        block["times"] = list(series.get("accepted_times") or [])
        block["sites"] = list(series.get("accepted_sites") or [])
        block["rejected_times"] = list(series.get("rejected_times") or [])
        block["approx"] = bool(series.get("approx_timing"))
    elif unique and not provisional:
        # No cells to read a clock from (an exported bundle ships none): the
        # count is still the table's, so it lands at the end of the run and
        # says so, rather than drawing a curve that found nothing.
        wall_h = _hours(condition.get("wall_median")) or 0.0
        block["times"] = [wall_h] * unique
        block["sites"] = [""] * unique
        block["approx"] = True
    return block


def _efficiency(condition: dict) -> dict:
    """Where the wall went — medians the aggregate already computed."""
    seats = _float(condition.get("worker_wall_total"))
    wall = _float(condition.get("wall_median"))
    confirmed = _int(condition.get("unique_finding_clusters")) + _int(
        condition.get("unique_crash_clusters"))
    seat_hours = seats / 3600.0 if seats else None
    per_seat_hour = (
        round(confirmed / seat_hours, 2) if seat_hours and confirmed else None
    )
    cost = _float(condition.get("cost_usd_total"))
    estimated = bool(condition.get("cost_estimated")) or str(
        condition.get("token_source") or "") in ("estimated", "unknown")
    return {
        "occupancy": _float(condition.get("worker_occupancy_median")),
        "occupancy_source": condition.get("worker_occupancy_source"),
        "blocked": _float(condition.get("housekeeping_blocked_fraction_median")),
        "review_s": _float(condition.get("review_seconds_per_artifact_median")),
        "first_filed_min": _minutes(condition.get("time_to_first_filed_median")),
        "first_crash_min": _minutes(condition.get("time_to_first_crash_confirmed_median")),
        "first_admitted_min": _minutes(condition.get("time_to_first_admitted_median")),
        "exec_fail": _float(condition.get("exec_fail_share_median")),
        "duplicate_roots": _float(condition.get("duplicate_root_rate_median")),
        "seat_hours": round(seat_hours, 2) if seat_hours else None,
        "seat_floor": bool(condition.get("spend_lower_bound")) or not condition.get(
            "delegation_observable", True),
        "per_seat_hour": per_seat_hour,
        "cost_per_confirmed": (
            round(cost / confirmed, 2)
            if cost and confirmed and not estimated and wall else None
        ),
        "delegations": _int(condition.get("delegation_events_total")),
    }


def _tokens(condition: dict) -> dict:
    estimated = bool(condition.get("cost_estimated")) or str(
        condition.get("token_source") or "") in ("estimated", "unknown")
    return {
        "input": benchmark._fmt_input_cell(condition),
        "output": benchmark._fmt_output_cell(condition),
        "cost": benchmark._fmt_cost_compact_cell(condition),
        "input_raw": _int(condition.get("input_tokens_total")),
        "output_raw": _int(condition.get("output_tokens_total")),
        "cached_raw": _int(condition.get("cached_input_tokens_total")),
        "cost_raw": _float(condition.get("cost_usd_total")),
        "estimated": estimated,
        "source": str(condition.get("token_source") or ""),
    }


def _replicates(condition: dict) -> dict:
    return {
        "done": _int(condition.get("replicates_done")),
        "total": _int(condition.get("replicates_total")),
        "limited": _int(condition.get("replicates_provider_limited")),
        "terminated": _int(condition.get("replicates_backend_terminated")),
        "recovered": _int(condition.get("replicates_provider_recovered")),
    }


def _lanes(condition: dict) -> dict:
    """Per-lane hypothesis yield, summed over the condition's cells."""
    out: dict[str, dict[str, int]] = {}
    for cell in condition.get("cells") or []:
        telemetry = ((cell.get("metrics") or {}).get("telemetry") or {})
        for lane, counts in (telemetry.get("lanes") or {}).items():
            if not isinstance(counts, dict):
                continue
            slot = out.setdefault(str(lane), {"hypotheses": 0, "productive": 0})
            slot["hypotheses"] += _int(counts.get("hypotheses"))
            slot["productive"] += _int(counts.get("productive"))
    return out


def _cells(condition: dict, bench_dir: Path | None, provisional_reason: str) -> list[dict]:
    rows = []
    for cell in condition.get("cells") or []:
        metrics = cell.get("metrics") or {}
        has_metrics = bool(metrics) and metrics.get("exists") is not False
        name = str(cell.get("cell") or "?")
        rows.append({
            "name": name,
            "status": "regenerate" if provisional_reason == "pre-receipt" else str(
                cell.get("status") or "unknown"),
            "quality": str(cell.get("run_quality") or ""),
            "wall_h": _hours(cell.get("wall_effective_seconds")),
            "paused_h": _hours(cell.get("paused_seconds")),
            "agents": _int(cell.get("actual_agents")),
            "findings_raw": (
                _int(metrics.get("findings")) + _int(metrics.get("findings_rejected"))
                if has_metrics else None
            ),
            "crashes_raw": (
                _int(metrics.get("confirmed_crashes")) + _int(metrics.get("crashes_rejected"))
                if has_metrics else None
            ),
            "href": _href(bench_dir / "cells" / name) if bench_dir else "",
        })
    return rows


def _condition(condition: dict, run: dict, bench_dir: Path | None,
               provisional: bool, provisional_reason: str,
               series: dict[str, dict]) -> dict:
    cond = str(condition.get("condition") or "?")
    backend = str(run.get("backend") or "")
    model = str(run.get("model") or "")
    wall_h = _hours(condition.get("wall_median"))
    budget_h = _hours(condition.get("wall_budget_seconds"))
    timing = series.get(cond)
    return {
        "token": cond,
        "label": benchmark._condition_label(cond, backend, model),
        "provisional": provisional,
        "wall_h": wall_h,
        "budget_h": budget_h,
        "wall_label": benchmark._wall_cell(condition),
        "replicates": _replicates(condition),
        "find": _count_block(condition, "find", bench_dir, cond, provisional,
                             timing.get("find") if timing else None),
        "crash": _count_block(condition, "crash", bench_dir, cond, provisional,
                              timing.get("crash") if timing else None),
        "top_severity": "Pending" if provisional else str(
            condition.get("top_severity_level") or "—"),
        "tokens": _tokens(condition),
        "efficiency": _efficiency(condition),
        "lanes": _lanes(condition),
        "activity": _condition_activity(bench_dir, cond, wall_h or budget_h or 0.0),
        "traces": _traces(bench_dir, cond) if cond == "harness" else [],
        "cells": _cells(condition, bench_dir, provisional_reason),
        "unjudged_published": [
            {"name": str(a.get("name") or "?"), "why": str(a.get("why") or "?")}
            for a in (condition.get("pool_unjudged") or []) if isinstance(a, dict)
        ],
    }


def build(bench_root: Path) -> dict:
    """Collect every run under *bench_root* into the page's data model."""
    bench_root = Path(bench_root)
    timing: dict[tuple[str, str, str], dict] = {}
    for entry in benchmark_graph.build(bench_root).get("series", []):
        timing[(entry["backend"], entry["run_id"], entry["condition"])] = entry
    runs: list[dict] = []
    for root in benchmark._benchmark_roots(bench_root):
        ledger = root / "benchmark-results.html"
        if not ledger.exists():
            ledger = root / "benchmark-results.md"
        for report in benchmark._reports_by_run_target(root):
            run = report.get("run") or {}
            bench_dir_raw = report.get("bench_dir")
            bench_dir = Path(bench_dir_raw) if bench_dir_raw else None
            run_id = str(run.get("runid") or (bench_dir.name if bench_dir else "?"))
            backend = str(run.get("backend") or root.name)
            provisional = bool(report.get("provisional"))
            provisional_reason = str(report.get("provisional_reason") or "")
            series = {
                cond: timing[(backend, run_id, cond)]
                for cond in ("harness", "model-direct")
                if (backend, run_id, cond) in timing
            }
            conditions = [
                _condition(c, run, bench_dir, provisional, provisional_reason, series)
                for c in (report.get("conditions") or []) if isinstance(c, dict)
            ]
            run_dir = bench_dir if bench_dir and bench_dir.is_dir() else root / run_id
            clusters = {"find": [], "crash": []}
            rejected = {"find": [], "crash": []}
            if not provisional and run_dir.is_dir():
                clusters = _clusters(run_dir, report, bench_dir)
                rejected = _rejected_clusters(run_dir, bench_dir)
            runs.append({
                "key": f"{backend}/{run_id}",
                "target": str(run.get("target") or "?"),
                "target_sha": benchmark._hash_text(run.get("target_sha")),
                "backend": backend,
                "model": str(run.get("model") or "").strip(),
                "effort": str(run.get("resolved_effort") or ""),
                "security": str(run.get("agent_security") or ""),
                "tokenfuzz_sha": benchmark._tokenfuzz_sha(run),
                "run_id": run_id,
                "budget_h": _hours(run.get("budget_wall")),
                "replicates": _int(run.get("replicates")),
                "provisional": provisional,
                "provisional_reason": provisional_reason,
                "outdated_scorers": benchmark._outdated_scorers(report, bench_dir),
                "ledger_href": _href(ledger),
                "conditions": conditions,
                "clusters": clusters,
                "rejected": rejected,
            })
            _stamp_clusters(runs[-1], series)
            runs[-1]["attention"] = _attention(runs[-1])
    runs.sort(key=lambda r: (r["target"], r["backend"], r["run_id"]))
    return {
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "scorer": severity_receipt.SCORER_DECISION_VERSION,
        "lane_names": LANE_NAMES,
        "runs": runs,
    }


# ── rendering ────────────────────────────────────────────────────────────────

def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _link(label: str, href: str, cls: str = "") -> str:
    attrs = f' class="{cls}"' if cls else ""
    if not href:
        return f"<span{attrs}>{_e(label)}</span>"
    return f'<a{attrs} href="{_e(href)}">{_e(label)}</a>'


def _severity_pill(level: str) -> str:
    key = level.lower() if level in _SEVERITY_RANK else ("pending" if level == "Pending" else "none")
    return f'<span class="sev sev-{key}">{_e(level or "—")}</span>'


def _fmt_h(value: float | None) -> str:
    return "—" if value is None else f"{value:.2f}h"


def _fmt_min(value: float | None) -> str:
    if value is None:
        return "—"
    if value >= 120:
        return f"{value / 60:.1f}h"
    return f"{value:.0f}m"


def _fmt_pct(value: float | None) -> str:
    return "—" if value is None else f"{value * 100:.0f}%"


def _direct_of(run: dict) -> dict | None:
    return next((c for c in run["conditions"] if c["token"] == "model-direct"), None)


def _harness_of(run: dict) -> dict | None:
    return next((c for c in run["conditions"] if c["token"] == "harness"), None)


def _scoreboard(runs: list[dict]) -> str:
    head = (
        "<tr><th data-sort=\"text\">Target</th><th data-sort=\"text\">Backend</th>"
        "<th data-sort=\"text\">Condition</th><th data-sort=\"text\">Run</th>"
        "<th class=\"num\" data-sort=\"num\">Wall (h)</th>"
        "<th class=\"num\" data-sort=\"num\">Replicates</th>"
        "<th class=\"num\" data-sort=\"num\">Rejected findings</th>"
        "<th class=\"num\" data-sort=\"num\">Security findings</th>"
        "<th class=\"num\" data-sort=\"num\">Rejected crashes</th>"
        "<th class=\"num\" data-sort=\"num\">Security crashes</th>"
        "<th data-sort=\"num\">Top crash severity</th>"
        "<th class=\"num\" data-sort=\"num\">Input</th>"
        "<th class=\"num\" data-sort=\"num\">Output</th>"
        "<th class=\"num\" data-sort=\"num\">Cost</th></tr>"
    )
    rows = []
    for run in runs:
        target = _e(run["target"])
        sha = f'<span class="sha">{_e(run["target_sha"][:7])}</span>' if run["target_sha"] else ""
        backend = _link(run["backend"], run["ledger_href"], "mono")
        run_label = _e(run["run_id"]) + (
            ' <abbr class="mark" title="Severities came from a superseded scorer; '
            'M+ counts are not on the current scale. bin/benchmark --regenerate rescores.">‡</abbr>'
            if run["outdated_scorers"] else "")
        conditions = run["conditions"] or [None]
        for cond in conditions:
            if cond is None:
                rows.append(
                    f'<tr data-run="{_e(run["key"])}" data-backend="{_e(run["backend"])}">'
                    f'<td>{target} {sha}</td><td>{backend}</td><td>—</td><td class="mono">{run_label}</td>'
                    + "<td class=\"num\">—</td>" * 10 + "</tr>")
                continue
            reps = cond["replicates"]
            reps_label = f'{reps["done"]}/{reps["total"]}'
            marks = []
            if reps["limited"]:
                marks.append(f'<abbr class="mark" title="{reps["limited"]} replicate(s) hit a provider '
                             f'limit that never cleared and are excluded; re-running the same run id '
                             f'retries them.">({reps["limited"]}p)</abbr>')
            if reps["terminated"]:
                marks.append(f'<abbr class="mark" title="{reps["terminated"]} counted replicate(s) '
                             f'stopped early on a terminal backend exit, so their share came from a '
                             f'shorter wall than the grant.">({reps["terminated"]}t)</abbr>')
            find, crash = cond["find"], cond["crash"]
            sev = cond["top_severity"]
            tokens = cond["tokens"]
            cost_num = tokens["cost_raw"] if tokens["cost_raw"] is not None else -1
            rows.append(
                f'<tr data-run="{_e(run["key"])}" data-backend="{_e(run["backend"])}" '
                f'data-cond="{_e(cond["token"])}">'
                f'<td data-v="{target}">{target} {sha}</td>'
                f'<td data-v="{_e(run["backend"])}">{backend}</td>'
                f'<td data-v="{_e(cond["label"])}"><span class="cond cond-{_e(cond["token"])}">'
                f'{_e(cond["label"])}</span></td>'
                f'<td class="mono" data-v="{_e(run["run_id"])}">{run_label}</td>'
                f'<td class="num" data-v="{cond["wall_h"] or 0}">{_e(cond["wall_label"])}</td>'
                f'<td class="num" data-v="{reps["done"]}">{reps_label} {" ".join(marks)}</td>'
                f'<td class="num" data-v="{find["rejected"] if find["rejected"] is not None else -1}">'
                f'{_link(find["rejected_label"], find["rejected_href"])}</td>'
                f'<td class="num" data-v="{find["unique"]}">{_link(find["label"], find["href"], "count")}</td>'
                f'<td class="num" data-v="{crash["rejected"] if crash["rejected"] is not None else -1}">'
                f'{_link(crash["rejected_label"], crash["rejected_href"])}</td>'
                f'<td class="num" data-v="{crash["unique"]}">{_link(crash["label"], crash["href"], "count")}</td>'
                f'<td data-v="{_SEVERITY_RANK.get(sev, 0)}">{_severity_pill(sev)}</td>'
                f'<td class="num" data-v="{tokens["input_raw"]}">{_e(tokens["input"])}</td>'
                f'<td class="num" data-v="{tokens["output_raw"]}">{_e(tokens["output"])}</td>'
                f'<td class="num" data-v="{cost_num}">{_e(tokens["cost"])}</td></tr>')
    return (
        '<div class="tablewrap"><table class="score" id="scoreboard"><thead>'
        + head + "</thead><tbody>" + "".join(rows) + "</tbody></table></div>"
    )


def _verdict_cards(runs: list[dict]) -> str:
    cards = []
    for run in runs:
        harness, direct = _harness_of(run), _direct_of(run)
        title = f'{_e(run["target"])}'
        sub = f'{_e(run["model"] or run["backend"])} · {_e(run["backend"])} · {_e(run["run_id"])}'
        if run["provisional"]:
            body = ('<p class="pending">Still running or awaiting review — counts arrive when the '
                    'run\'s own review finishes.</p>')
        elif harness is None or direct is None:
            only = harness or direct
            body = (f'<p class="pending">One condition only ({_e(only["label"]) if only else "—"}); '
                    'no comparison to draw.</p>')
        else:
            def side(cond: dict) -> str:
                f, c = cond["find"], cond["crash"]
                return (
                    f'<div class="side side-{_e(cond["token"])}">'
                    f'<div class="who">{_e(cond["label"])}</div>'
                    f'<div class="big">{"≥" if f["floor"] and f["unique"] else ""}{f["unique"]}<small>findings</small></div>'
                    f'<div class="big">{"≥" if c["floor"] and c["unique"] else ""}{c["unique"]}<small>crashes</small></div>'
                    f'<div class="fine">{f["mplus"] + c["mplus"]} Medium+ · top crash '
                    f'{_severity_pill(cond["top_severity"])} · {_e(cond["wall_label"])}</div>'
                    + (f'<div class="fine warn">{f["unjudged"] + c["unjudged"]} unjudged — a floor, not a yield</div>'
                       if f["unjudged"] or c["unjudged"] else "")
                    + "</div>")
            uniq = _overlap_counts(run)
            body = (
                '<div class="sides">' + side(harness) + '<div class="vs">vs</div>' + side(direct) + "</div>"
                f'<div class="overlap"><span class="sw sw-harness"></span>{uniq["harness"]} only tokenfuzz'
                f' · <span class="sw sw-both"></span>{uniq["both"]} both'
                f' · <span class="sw sw-direct"></span>{uniq["direct"]} only direct'
                '</div>'
            )
        cards.append(
            f'<a class="card" href="#run-{_e(_slug(run["key"]))}" data-backend="{_e(run["backend"])}">'
            f'<div class="ct">{title} <span class="sha">{_e(run["target_sha"][:7])}</span></div>'
            f'<div class="cs">{sub}</div>{body}</a>')
    return '<div class="cards">' + "".join(cards) + "</div>"


def _overlap_counts(run: dict) -> dict:
    out = {"harness": 0, "both": 0, "direct": 0}
    for kind in ("find", "crash"):
        for cluster in run["clusters"][kind]:
            conds = set(cluster["conditions"])
            if "harness" in conds and "model-direct" in conds:
                out["both"] += 1
            elif "harness" in conds:
                out["harness"] += 1
            elif "model-direct" in conds:
                out["direct"] += 1
    return out


def _slug(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", value).strip("-")


def _cluster_map(run: dict) -> str:
    """Every distinct problem as one dot: row = bug class, column = who found it.

    A table of counts says "23 vs 12"; this says which twenty-three, in which
    classes, at what severity, and which of them the other side also reached.
    Reportable dots sit in the three yield columns; rejected clusters get their
    own column so over-claiming stays visible beside yield.
    """
    columns = [("harness", "Only tokenfuzz"), ("both", "Both"),
               ("direct", "Only direct"), ("rejected", "Rejected")]
    rows: dict[str, dict[str, list[dict]]] = {}

    def place(cluster: dict, column: str) -> None:
        rows.setdefault(cluster["class"], {c: [] for c, _ in columns})[column].append(cluster)

    for kind in ("find", "crash"):
        for cluster in run["clusters"][kind]:
            conds = set(cluster["conditions"])
            if {"harness", "model-direct"} <= conds:
                place(cluster, "both")
            elif "harness" in conds:
                place(cluster, "harness")
            elif "model-direct" in conds:
                place(cluster, "direct")
        for cluster in run["rejected"][kind]:
            place(cluster, "rejected")
    if not rows:
        return '<p class="empty">No reportable clusters on either side.</p>'
    order = sorted(rows, key=lambda name: (
        -sum(len(v) for c, v in rows[name].items() if c != "rejected"), name))
    out = ['<div class="cmap"><div class="cmap-head"><div></div>']
    for key, label in columns:
        out.append(f'<div class="cmap-col cmap-{key}">{label}</div>')
    out.append("</div>")
    for name in order:
        out.append(f'<div class="cmap-row"><div class="cmap-class">{_e(name)}</div>')
        for key, _label in columns:
            dots = sorted(rows[name][key], key=lambda c: (-c["rank"], c["kind"], c["site"]))
            out.append(f'<div class="cmap-cell cmap-{key}">')
            for cluster in dots:
                sev = cluster["severity"].lower() if cluster["severity"] in _SEVERITY_RANK else "none"
                tag = "a" if cluster["href"] else "span"
                href = f' href="{_e(cluster["href"])}"' if cluster["href"] else ""
                who = ", ".join(
                    "tokenfuzz" if c == "harness" else "direct" for c in cluster["conditions"])
                by_side = cluster.get("severity_by") or {}
                if len(set(by_side.values())) > 1:
                    sev_label = " / ".join(
                        f'{by_side[c] or "unscored"} as {"tokenfuzz" if c == "harness" else "direct"} filed it'
                        for c in cluster["conditions"])
                else:
                    sev_label = cluster["severity"] or "unscored"
                out.append(
                    f'<{tag} class="dot dot-{cluster["kind"]} sev-{sev}"{href} '
                    f'data-title="{_e(cluster["title"])}" data-site="{_e(cluster["site"])}" '
                    f'data-sev="{_e(sev_label)}" data-kind="{cluster["kind"]}" '
                    f'data-who="{_e(who)}" data-size="{cluster["size"]}" '
                    f'data-reason="{_e(cluster.get("reason") or "")}" '
                    f'data-strategy="{_e(cluster.get("strategy") or "")}" '
                    + (f'data-t="{cluster["t"]}" ' if cluster.get("t") is not None else "") +
                    f'title="{_e(cluster["title"] or cluster["site"] or cluster["id"])}"></{tag}>')
            out.append("</div>")
        out.append("</div>")
    out.append("</div>")
    return "".join(out)


def _funnel(run: dict) -> str:
    """Candidates → evidence complete → validated → reportable, per side."""
    parts = []
    for cond in run["conditions"]:
        for kind, noun in (("find", "findings"), ("crash", "crashes")):
            stage = cond[kind]["waterfall"]
            if not stage:
                continue
            top = max(stage["candidates"], 1)
            bars = []
            for key, label in (("candidates", "claimed"), ("evidence", "evidence complete"),
                               ("validated", "validated"), ("reportable", "reportable")):
                width = 100.0 * stage[key] / top
                bars.append(
                    f'<div class="fr"><span class="fl">{label}</span>'
                    f'<span class="fb"><span class="ff ff-{_e(cond["token"])}" style="width:{width:.1f}%"></span></span>'
                    f'<span class="fv">{stage[key]}</span></div>')
            tail = []
            if stage["rejected"]:
                tail.append(f'{stage["rejected"]} rejected')
            if stage["not_reportable"]:
                tail.append(f'{stage["not_reportable"]} not reportable')
            if stage["pending"]:
                tail.append(f'{stage["pending"]} pending')
            parts.append(
                f'<div class="funnel"><div class="ft"><span class="cond cond-{_e(cond["token"])}">'
                f'{_e(cond["label"])}</span> {noun}</div>' + "".join(bars)
                + (f'<div class="fn">{" · ".join(tail)}</div>' if tail else "") + "</div>")
    if not parts:
        return ""
    return '<div class="funnels">' + "".join(parts) + "</div>"


def _lane_table(run: dict) -> str:
    harness = _harness_of(run)
    if harness is None or not harness["lanes"]:
        return ""
    rows = []
    total_h = total_p = 0
    for lane in sorted(harness["lanes"], key=lambda k: (k not in LANE_NAMES, k)):
        counts = harness["lanes"][lane]
        h, p = counts["hypotheses"], counts["productive"]
        total_h += h
        total_p += p
        rate = f"{100 * p / h:.0f}%" if h else "—"
        width = 100.0 * p / h if h else 0
        rows.append(
            f'<tr><td><span class="lane lane-{_e(lane)}">{_e(lane)}</span> {_e(LANE_NAMES.get(lane, lane))}</td>'
            f'<td class="num">{h}</td><td class="num">{p}</td>'
            f'<td class="num"><span class="mini"><span style="width:{width:.0f}%"></span></span> {rate}</td></tr>')
    rows.append(
        f'<tr class="total"><td>All lanes</td><td class="num">{total_h}</td><td class="num">{total_p}</td>'
        f'<td class="num">{f"{100 * total_p / total_h:.0f}%" if total_h else "—"}</td></tr>')
    return (
        '<div class="tablewrap"><table class="lanes"><thead><tr><th>Strategy lane</th>'
        '<th class="num">Hypotheses</th><th class="num">Productive</th><th class="num">Rate</th>'
        '</tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>")


def _tile(label: str, value: str, note: str = "") -> str:
    return (f'<div class="tile"><div class="tl">{_e(label)}</div><div class="tv">{value}</div>'
            + (f'<div class="tn">{note}</div>' if note else "") + "</div>")


def _effort(run: dict) -> str:
    blocks = []
    for cond in run["conditions"]:
        eff, tok = cond["efficiency"], cond["tokens"]
        tiles = [
            _tile("Wall spent / granted", _e(cond["wall_label"])),
            _tile("Seat-hours", "—" if eff["seat_hours"] is None else
                  f'{"≤" if eff["seat_floor"] else ""}{eff["seat_hours"]:g}h',
                  "agent launches × wall"),
            _tile("Occupancy", _fmt_pct(eff["occupancy"]) + (
                '<abbr class="mark" title="From file clocks, not recorded session spans">†</abbr>'
                if eff["occupancy"] is not None and eff["occupancy_source"] != "recorded" else "")),
            _tile("First filed", _fmt_min(eff["first_filed_min"]), "from the first backend call"),
            _tile("First crash confirmed", _fmt_min(eff["first_crash_min"])),
            _tile("First admitted", _fmt_min(eff["first_admitted_min"]), "first reportable receipt"),
            _tile("Probe EXEC_FAIL share", _fmt_pct(eff["exec_fail"])),
            _tile("Input tokens", _e(tok["input"]), "fresh input + cache writes"),
            _tile("Output tokens", _e(tok["output"])),
            _tile("Cost", _e(tok["cost"]), "list price" + (", estimated" if tok["estimated"] else "")),
            _tile("Confirmed / seat-h", "—" if eff["per_seat_hour"] is None else
                  f'{"≤" if eff["seat_floor"] else ""}{eff["per_seat_hour"]:g}'),
            _tile("$ / confirmed", "—" if eff["cost_per_confirmed"] is None else
                  f'${eff["cost_per_confirmed"]:,.0f}'),
        ]
        blocks.append(
            f'<div class="effort"><div class="ft"><span class="cond cond-{_e(cond["token"])}">'
            f'{_e(cond["label"])}</span></div><div class="tiles">' + "".join(tiles) + "</div></div>")
    return "".join(blocks)


def _cells_table(run: dict) -> str:
    rows = []
    for cond in run["conditions"]:
        for cell in cond["cells"]:
            rows.append(
                f'<tr><td>{_link(cell["name"], cell["href"], "mono")}</td>'
                f'<td><span class="cond cond-{_e(cond["token"])}">{_e(cond["label"])}</span></td>'
                f'<td>{_e(cell["status"])}{(" · " + _e(cell["quality"])) if cell["quality"] and cell["quality"] != "clean" else ""}</td>'
                f'<td class="num">{cell["agents"] or "—"}</td>'
                f'<td class="num">{"—" if cell["findings_raw"] is None else cell["findings_raw"]}</td>'
                f'<td class="num">{"—" if cell["crashes_raw"] is None else cell["crashes_raw"]}</td>'
                f'<td class="num">{_fmt_h(cell["wall_h"])}</td></tr>')
    if not rows:
        return ""
    return (
        '<div class="tablewrap"><table class="cells"><thead><tr><th>Cell</th><th>Condition</th>'
        '<th>Status</th><th class="num">Agents</th><th class="num">Findings (raw)</th>'
        '<th class="num">Crashes (raw)</th><th class="num">Wall</th></tr></thead><tbody>'
        + "".join(rows) + "</tbody></table></div>")


def _leaderboard(runs: list[dict]) -> str:
    """Every condition of every finished run on one target, strongest first.

    Ranked by Medium-or-higher yield, then distinct problems: the two numbers
    the guide says to read first. Marks travel with the labels, so a floor or
    an unjudged remainder ranks with its mark, never as a clean count.
    """
    groups: dict[tuple[str, str], list[dict]] = {}
    for run in runs:
        groups.setdefault((run["target"], run["target_sha"]), []).append(run)
    out = []
    for (target, sha), members in sorted(groups.items()):
        rows = []
        for run in members:
            for cond in run["conditions"]:
                f, c = cond["find"], cond["crash"]
                eff, tok = cond["efficiency"], cond["tokens"]
                rows.append({
                    "run": run, "cond": cond,
                    "mplus": f["mplus"] + c["mplus"],
                    "unique": f["unique"] + c["unique"],
                    "cost_per": eff["cost_per_confirmed"], "cost": tok["cost"],
                })
        rows.sort(key=lambda r: (r["run"]["provisional"], -r["mplus"], -r["unique"],
                                 r["cond"]["label"]))
        top = max([r["mplus"] for r in rows] + [1])
        body = []
        for rank, row in enumerate(rows, 1):
            run, cond = row["run"], row["cond"]
            pending = run["provisional"]
            width = 100.0 * row["mplus"] / top
            mplus_cell = "Pending" if pending else (
                f'<span class="mini wide"><span style="width:{width:.0f}%"></span></span> '
                f'{row["mplus"]}')
            cost_per = "—" if row["cost_per"] is None else f'${row["cost_per"]:,.0f}'
            body.append(
                f'<tr data-run="{_e(run["key"])}" data-backend="{_e(run["backend"])}">'
                f'<td class="num">{"—" if pending else rank}</td>'
                f'<td><span class="cond cond-{_e(cond["token"])}">{_e(cond["label"])}</span>'
                f' <span class="be be-{_e(run["backend"])}">{_e(run["backend"])}</span></td>'
                f'<td class="mono dim">{_e(run["run_id"])}</td>'
                f'<td class="num">{mplus_cell}</td>'
                f'<td class="num">{_link(cond["find"]["label"], cond["find"]["href"], "count")}</td>'
                f'<td class="num">{_link(cond["crash"]["label"], cond["crash"]["href"], "count")}</td>'
                f'<td>{_severity_pill(cond["top_severity"])}</td>'
                f'<td class="num">{_e(cond["wall_label"])}</td>'
                f'<td class="num">{_e(row["cost"])}</td>'
                f'<td class="num">{cost_per}</td></tr>')
        out.append(
            f'<div class="lb"><div class="lbt">{_e(target)} <span class="sha">{_e(sha[:7])}</span></div>'
            '<div class="tablewrap"><table class="board"><thead><tr><th class="num">#</th>'
            '<th>Condition</th><th>Run</th><th class="num">Medium+ problems</th>'
            '<th class="num">Security findings</th><th class="num">Security crashes</th>'
            '<th>Top crash</th><th class="num">Wall</th><th class="num">Cost</th>'
            '<th class="num">$ / confirmed</th></tr></thead><tbody>' + "".join(body)
            + "</tbody></table></div></div>")
    return "".join(out)


def _replay_bar(run: dict) -> str:
    walls = [c["wall_h"] or 0 for c in run["conditions"]] + [
        t["wall_h"] or 0 for c in run["conditions"] for t in c["traces"]]
    wall = max(walls + [0])
    if wall <= 0:
        return ""
    ticks = int(round(wall * 100))
    return (
        f'<div class="replay" data-wall="{wall:.3f}">'
        '<button type="button" class="play">▶ Replay the run</button>'
        f'<input type="range" min="0" max="{ticks}" value="{ticks}" step="1" '
        'aria-label="hours into the run">'
        f'<span class="rt">{wall:.2f}h</span><span class="rn">whole run</span></div>')


def _trace_panel(run: dict) -> str:
    harness = _harness_of(run)
    if harness is None or not harness["traces"]:
        return ""
    parts = ['<div class="panel"><div class="pt">How the harness reasoned</div>'
             '<p class="pd">Every hypothesis an agent opened, as a bar from the moment it was '
             'written to the moment it was resolved, one row per agent. Colour is the outcome; '
             'the ticks above a bar are the sanitizer probes it drove, coloured by verdict; a '
             'dot at the end marks a hypothesis that became a filed artifact. Hover for the '
             'idea in the agent\'s own words; click to read its reasoning, guard gap, input '
             'shape, probes, and notes. The control leaves no such trace: it reports, and '
             'nothing records what it considered and discarded.</p>'
             '<div class="legend">'
             '<span class="k"><b class="o-hit"></b>became an artifact</span>'
             '<span class="k"><b class="o-confirmed"></b>confirmed, not filed</span>'
             '<span class="k"><b class="o-refuted"></b>refuted by evidence</span>'
             '<span class="k"><b class="o-dropped"></b>dropped untested</span>'
             '<span class="k"><b class="o-blocked"></b>blocked by the environment</span>'
             '<span class="k"><b class="o-open"></b>still open</span></div>']
    for trace in harness["traces"]:
        summary = trace["summary"]
        total = sum(summary.values())
        bits = [f'{total} hypotheses']
        for outcome in OUTCOMES:
            if summary[outcome]:
                bits.append(f'{summary[outcome]} {outcome}')
        if trace["median_minutes"] is not None:
            bits.append(f'median {trace["median_minutes"]:g} min from opened to resolved')
        parts.append(
            f'<div class="tsum"><span class="mono">{_e(trace["cell"])}</span> · '
            + _e(" · ".join(bits)) + "</div>"
            f'<div class="chart trace" data-run="{_e(run["key"])}" data-cell="{_e(trace["cell"])}"></div>')
    parts.append("</div>")
    return "".join(parts)


def _attention_panel(run: dict) -> str:
    rows = run.get("attention") or []
    if not rows:
        return ""
    direct = _direct_of(run) is not None
    top = max([r["hypotheses"] for r in rows] + [1])
    body = []
    for row in rows:
        width = 100.0 * row["hypotheses"] / top
        body.append(
            f'<tr><td class="mono">{_e(row["subsystem"])}</td>'
            f'<td class="num"><span class="mini wide"><span style="width:{width:.0f}%"></span></span> '
            f'{row["hypotheses"] or "—"}</td>'
            f'<td class="num">{row["probes"] or "—"}</td>'
            f'<td class="num">{row["hits"] or "—"}</td>'
            f'<td class="num">{row["harness"] or "—"}</td>'
            + (f'<td class="num">{row["direct"] or "—"}</td>' if direct else "")
            + f'<td class="num">{row["rejected"] or "—"}</td></tr>')
    return (
        '<div class="panel"><div class="pt">Where they looked, where they found</div>'
        '<p class="pd">The harness\'s hypotheses name a file, so its attention can be placed by '
        'top-level directory beside the merged results that landed there. The control\'s '
        'attention is not observable — only what it reported is — so it has a found column and '
        'nothing else.</p><div class="tablewrap"><table class="attn"><thead><tr>'
        '<th>Subsystem</th><th class="num">Hypotheses</th><th class="num">Probes</th>'
        '<th class="num">Became artifacts</th><th class="num">Kept · tokenfuzz</th>'
        + ('<th class="num">Kept · direct</th>' if direct else "")
        + '<th class="num">Rejected</th></tr></thead><tbody>' + "".join(body)
        + "</tbody></table></div></div>")


def _run_section(run: dict) -> str:
    anchor = _slug(run["key"])
    identity = " · ".join(filter(None, [
        f'model {_e(run["model"])}' if run["model"] else "",
        f'effort {_e(run["effort"])}' if run["effort"] else "",
        f'{_e(run["security"])}' if run["security"] else "",
        f'tokenfuzz {_e(run["tokenfuzz_sha"][:7])}' if run["tokenfuzz_sha"] else "",
        f'budget {run["budget_h"]:g}h' if run["budget_h"] else "",
    ]))
    parts = [
        f'<section class="run" id="run-{_e(anchor)}" data-run="{_e(run["key"])}" '
        f'data-backend="{_e(run["backend"])}">',
        f'<div class="rh"><h2>{_e(run["target"])} <span class="sha">{_e(run["target_sha"][:7])}</span>'
        f' <span class="be be-{_e(run["backend"])}">{_e(run["backend"])}</span>'
        f' <span class="mono dim">{_e(run["run_id"])}</span></h2><div class="ident">{identity}</div></div>',
    ]
    if run["provisional"]:
        why = ("finished before publication receipts existed; run bin/benchmark --regenerate "
               "to re-derive its counts" if run["provisional_reason"] == "pre-receipt"
               else "still running — the counts below are raw per-cell tallies, not the "
                    "reviewed, duplicate-merged result")
        parts.append(f'<p class="banner">Provisional: {why}.</p>')
    unjudged = [(cond, a) for cond in run["conditions"] for a in cond["unjudged_published"]]
    if unjudged:
        items = "".join(
            f'<li><span class="cond cond-{_e(c["token"])}">{_e(c["label"])}</span> '
            f'<code>{_e(a["name"])}</code> — {_e(a["why"])}</li>' for c, a in unjudged)
        parts.append(
            '<p class="banner">Published unjudged: the review receipt no longer matched the report, '
            'so each of these counts in its row\'s unjudged remainder and earns no credit.</p>'
            f'<ul class="unjudged">{items}</ul>')
    if not run["provisional"]:
        replay = _replay_bar(run)
        if replay:
            parts.append(
                '<div class="panel"><div class="pt">Replay</div>'
                '<p class="pd">Drag, or press play, to watch the run unfold: every panel below '
                'shows only what existed by that hour — the problems found so far, the curves, '
                'the activity, and the hypotheses the agents had opened.</p>' + replay + "</div>")
        parts.append(
            '<div class="panel"><div class="pt">What each side found</div>'
            '<p class="pd">One dot per distinct problem after duplicate merging. Row is the bug '
            'class, column is who reached it, colour is severity, shape is the evidence: '
            '<span class="dot dot-crash sev-high demo"></span> a sanitizer crash with a '
            'reproducer, <span class="dot dot-find sev-high demo"></span> a source-backed '
            'finding. Hover for the site; click to open the report.</p>'
            + _cluster_map(run) + "</div>")
    has_timing = any(
        cond[k]["times"] or cond[k]["unique"] for cond in run["conditions"] for k in ("find", "crash"))
    if has_timing and not run["provisional"]:
        parts.append(
            '<div class="panel"><div class="pt">When it was found</div>'
            '<p class="pd">Cumulative distinct results on the run\'s clock. Each step is one '
            'problem that held up, placed at the hour it was first seen; a flat tail is audit time '
            'that found nothing new. Solid is tokenfuzz, dashed is the model on its own. Ticks below '
            'the axis are rejected results, placed the same way.</p>'
            f'<div class="chart ttd" data-run="{_e(run["key"])}"></div></div>')
    parts.append(_trace_panel(run))
    if any(cond["activity"] for cond in run["conditions"]):
        parts.append(
            '<div class="panel"><div class="pt">How the run thought</div>'
            '<p class="pd">What the agents were doing, in quarter-hour bins on the same clock: '
            'hypotheses opened by strategy lane, sanitizer probes by verdict, artifacts filed, '
            'and model output tokens. The direct control writes no hypotheses or probe records, '
            'so its strip shows only what it filed and what it generated.</p>'
            f'<div class="chart act" data-run="{_e(run["key"])}"></div></div>')
    parts.append(_attention_panel(run))
    funnel = _funnel(run)
    if funnel:
        parts.append(
            '<div class="panel"><div class="pt">What survived review</div>'
            '<p class="pd">Every claim, then how far it got: evidence on disk, a validation '
            'verdict, and finally reportable under the declared attacker controls. The gap '
            'between the first bar and the last is what the raw count would have overstated.</p>'
            + funnel + "</div>")
    lanes = _lane_table(run)
    if lanes:
        parts.append(
            '<div class="panel"><div class="pt">Where the ideas came from</div>'
            '<p class="pd">Hypotheses the harness opened per strategy lane, and how many led to '
            'an admitted artifact. tokenfuzz only — the control has no lanes.</p>' + lanes + "</div>")
    parts.append(
        '<div class="panel"><div class="pt">What it took</div>'
        '<p class="pd">Medians over completed repeats. A dash is unrecorded, never zero; '
        '≤ marks a seat count that is a floor because the backend delegated or cannot show '
        'its fan-out.</p>' + _effort(run) + "</div>")
    cells = _cells_table(run)
    if cells:
        parts.append(
            '<div class="panel"><div class="pt">Cells</div>'
            '<p class="pd">One row per repeat. Raw counts include candidates later rejected '
            'and count each report once; the reviewed numbers are in the scoreboard.</p>'
            + cells + "</div>")
    parts.append("</section>")
    return "".join(parts)


_GUIDE = """
<details class="guide" id="guide"><summary>How to read this page</summary>
<div class="gbody">
<h3>The comparison</h3>
<p>Each run audits one target at one commit with one model and one wall-clock budget, twice: <b>tokenfuzz</b> is the full harness — a ranked work queue, several agents, sanitizer probes, review, duplicate merging, exported reproducers — and <b>&lt;model&gt;-direct</b> is the control: the same model and budget given one plain request to find vulnerabilities and none of that machinery. Both sides are then held to the same evidence bar, so the two counts mean the same thing. Every target is audited on live, unfixed code; there is no planted bug to re-find.</p>
<h3>Findings and crashes</h3>
<p>A <b>crash</b> counts only when sanitizer output and reproducer material are on disk; what an agent claimed is not evidence. A <b>finding</b> is a security issue reported without a crash behind it — real and possibly serious, but the evidence is an argument, so read one as a lead until its report names a concrete boundary and shows how a caller crosses it. Both are merged so one problem reported several times counts once. Labels read <code>N (M M+, C classes)</code>: N distinct problems, M scored Medium or higher, spread across C bug classes. One mechanism at thirty sites is thirty findings and one class; that is not the same result as thirty classes.</p>
<p>A <code>K unjudged</code> term means K reports never reached a verdict before the run was published; they earn no credit, so read the cell as a floor. A leading <code>≥</code> means the unjudged remainder outnumbers the verdicts and the count is a lower bound, not a result to compare. <code>K retained</code> counts reproduced crashes a reviewer placed outside the declared attacker controls: real defects, kept on disk, no security credit. <code>up to N</code> on a rejected count is an upper bound where duplicates could not be merged. <code>bin/benchmark --regenerate</code> finishes an unfinished gate.</p>
<p>The rejected and accepted columns are merged separately, so one problem can be reportable in one write-up and rejected in another. Do not divide them into a pass rate.</p>
<h3>Severity</h3>
<p>One scorer rates findings and crashes on the same scale, so impact can be compared rather than report count. <b>Top crash severity</b> is the strongest reportable crash in the row. A <code>‡</code> on a run means its severities came from a superseded scorer and its M+ counts are not on the current scale.</p>
<h3>Effort</h3>
<p><b>Wall</b> is <code>spent/granted</code> hours, the median across finished repeats; time parked on a provider reset counts as neither. The harness usually spends the whole grant; the control stops when the model decides it is done, so a short numerator beside a count means that count came from a shorter experiment. <b>Replicates</b> is <code>done/total</code>; <code>(Np)</code> repeats never came back and are excluded, <code>(Nt)</code> repeats stopped early on a terminal backend exit but are counted. The wall contains every second the harness spent deciding what to look at next — housekeeping between iterations is steering, not overhead — and only provider-withheld capacity is subtracted.</p>
<h3>Tokens and cost</h3>
<p>Token columns are normalised so backends can be compared: <b>Input</b> is tokens charged at the full input rate (Claude's fresh input plus cache writes; running totals from Codex and Gemini have cache reads subtracted back out). <b>Output</b> includes tool-call payloads where reported. <b>Cost</b> prices each backend's own billing buckets at its published list rates and rounds to whole dollars; a <code>~</code> prefix marks a figure estimated from character counts because the backend reported no usage. Each backend's own ledger keeps the cents.</p>
<h3>What makes this comparable</h3>
<p>There is no answer key. Planted-bug suites score a model on re-finding a known defect at a known site; every target here is live, unfixed code, so a result is a problem nobody had filed, held to the same evidence bar on both sides — a reproducing sanitizer crash, or a source-backed report that names a boundary and a caller that crosses it — and merged so the same problem counts once however many times it was written up. The control is the same model with the same budget and a plain prompt, so the difference between the two rows is the harness and nothing else. The trace panels show the process that produced the numbers, from the audit's own state streams, so a reader can see not only what was found but what was tried, refuted, and dropped along the way.</p>
<h3>Timing and activity</h3>
<p>Discovery times come from the audit's own event stream, joined to the merged clusters, and placed on the cell's start clock; a result that cannot be placed lands at the end of the run and the panel says <i>timing approximate</i>. The activity strip reads the hypothesis, probe, event, and usage streams each cell wrote while it ran; events after the wall are review, not activity, and are not drawn. Multiple repeats are summed.</p>
</div></details>
"""


def render(data: dict) -> str:
    runs = data.get("runs") or []
    provisional = [r for r in runs if r["provisional"]]
    backends = sorted({r["backend"] for r in runs})
    targets = sorted({(r["target"], r["target_sha"]) for r in runs})
    payload = json.dumps(_payload(data), separators=(",", ":")).replace("<", "\\u003c")
    chips = "".join(
        f'<button class="chip on" data-backend="{_e(b)}"><span class="sw be-{_e(b)}"></span>{_e(b)}</button>'
        for b in backends)
    head = (
        '<header class="hero"><p class="kick">TokenFuzz benchmark</p>'
        '<h1>Does the harness beat the same model asked directly?</h1>'
        '<p class="lede">Same target, same model, same time budget — one side with the audit '
        'harness around it, one side with a plain prompt. Every count below is a distinct security '
        'problem that survived review, merged across duplicate reports, and every number links to '
        'the evidence behind it.</p>'
        f'<p class="meta">Generated {_e(data["generated_at"])} · '
        f'{len(runs)} run{"s" if len(runs) != 1 else ""} · '
        f'{len(targets)} target revision{"s" if len(targets) != 1 else ""} · '
        f'{len(backends)} backend{"s" if len(backends) != 1 else ""} · '
        f'scorer <span class="mono">{_e(data["scorer"])}</span> · <a href="#guide">how to read this page</a></p>'
        + ('<p class="banner">Some runs are still going. Their rows show only what finished work '
           'has already written to disk; duplicate-merged totals, severity, and the comparison '
           'itself arrive when the run ends.</p>' if provisional else "")
        + "</header>"
    )
    if not runs:
        body = '<p class="empty">No benchmark runs found yet.</p>'
    else:
        body = (
            f'<div class="filters"><span class="fl">Backends</span>{chips}'
            '<span class="fsp"></span>'
            '<button class="chip toggle" id="show-rejected" aria-pressed="true">Show rejected</button>'
            '</div>'
            '<section class="sec"><h2>At a glance</h2>' + _verdict_cards(runs) + "</section>"
            '<section class="sec"><h2>Leaderboard</h2><p class="pd">Every condition of every '
            'run on the same target revision, ranked by Medium-or-higher problems and then by '
            'distinct problems. The harness and the plain model are ranked together on purpose: '
            'the question is what finds real bugs, not which product wins.</p>'
            + _leaderboard(runs) + "</section>"
            '<section class="sec"><h2>Scoreboard</h2><p class="pd">One row per target, backend, '
            'condition, and run; re-runs keep their own rows. Click a heading to sort; click a '
            'count to open its evidence.</p>' + _scoreboard(runs) + "</section>"
            '<section class="sec"><h2>Run by run</h2>' + "".join(_run_section(r) for r in runs)
            + "</section>"
        )
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<title>benchmark-result</title>\n<style>" + _CSS + "</style>\n</head>\n<body>\n"
        '<main class="page">' + head + body + _GUIDE + "</main>\n"
        '<div class="tip" id="tip" role="tooltip"></div>\n'
        '<aside class="drawer" id="drawer" hidden><div class="dh"><b id="dtitle"></b>'
        '<button type="button" class="dclose" aria-label="close">×</button></div>'
        '<div class="db" id="dbody"></div></aside>\n'
        f'<script type="application/json" id="bench-data">{payload}</script>\n'
        "<script>" + _JS + "</script>\n</body>\n</html>\n"
    )


def _payload(data: dict) -> dict:
    """The subset the script needs: timing curves and activity, per run."""
    runs = []
    for run in data.get("runs") or []:
        conditions = []
        for cond in run["conditions"]:
            conditions.append({
                "token": cond["token"],
                "label": cond["label"],
                "wall_h": cond["wall_h"],
                "budget_h": cond["budget_h"],
                "find": {k: cond["find"][k] for k in
                         ("unique", "times", "sites", "rejected_times", "approx", "rejected", "rejected_upper")},
                "crash": {k: cond["crash"][k] for k in
                          ("unique", "times", "sites", "rejected_times", "approx", "rejected", "rejected_upper")},
                "activity": cond["activity"],
                "traces": cond["traces"],
                "first_filed_min": cond["efficiency"]["first_filed_min"],
                "first_crash_min": cond["efficiency"]["first_crash_min"],
                "first_admitted_min": cond["efficiency"]["first_admitted_min"],
            })
        runs.append({
            "key": run["key"],
            "backend": run["backend"],
            "model": run["model"],
            "target": run["target"],
            "run_id": run["run_id"],
            "provisional": run["provisional"],
            "conditions": conditions,
        })
    return {"runs": runs, "lane_names": data.get("lane_names") or LANE_NAMES}


def write(bench_root: Path, path: Path) -> Path:
    """Render the page for *bench_root* into *path*."""
    path = Path(path)
    path.write_text(render(build(bench_root)), encoding="utf-8")
    return path


# Backend hues: the reference categorical order validated for both surfaces
# (adjacent-pair CVD ΔE ≥ 8, normal ΔE ≥ 15). Severity uses the reserved
# status steps and never doubles as a series colour.
_CSS = r"""
:root{color-scheme:light;
 --bg:#f9f9f7;--surf:#fcfcfb;--surf2:#f1f1ee;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;
 --grid:#e1e0d9;--axis:#c3c2b7;--ring:rgba(11,11,11,.10);--link:#1c5cab;
 --codex:#2a78d6;--claude:#eb6834;--gemini:#4a3aa7;--grok:#1baf7a;--oss:#eda100;--opencode:#e87ba4;
 --other:#898781;--harness:#0b0b0b;--direct:#898781;
 --crit:#d03b3b;--high:#ec835a;--med:#fab219;--low:#86b6ef;--none:#c3c2b7;--good:#0ca30c;
 --S1:#2a78d6;--S2:#eb6834;--S3:#1baf7a;--S4:#eda100;--S5:#e87ba4;--S6:#008300;--S7:#4a3aa7;--S8:#e34948;
 --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
 --sans:system-ui,-apple-system,"Segoe UI",sans-serif}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;
 --bg:#0d0d0d;--surf:#1a1a19;--surf2:#232321;--ink:#fff;--ink2:#c3c2b7;--muted:#898781;
 --grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);--link:#86b6ef;
 --codex:#3987e5;--claude:#d95926;--gemini:#9085e9;--grok:#199e70;--oss:#c98500;--opencode:#d55181;
 --harness:#fff;--direct:#898781;--low:#5598e7;--none:#383835;
 --S1:#3987e5;--S2:#d95926;--S3:#199e70;--S4:#c98500;--S5:#d55181;--S6:#008300;--S7:#9085e9;--S8:#e66767}}
:root[data-theme="dark"]{color-scheme:dark;
 --bg:#0d0d0d;--surf:#1a1a19;--surf2:#232321;--ink:#fff;--ink2:#c3c2b7;--muted:#898781;
 --grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);--link:#86b6ef;
 --codex:#3987e5;--claude:#d95926;--gemini:#9085e9;--grok:#199e70;--oss:#c98500;--opencode:#d55181;
 --harness:#fff;--direct:#898781;--low:#5598e7;--none:#383835;
 --S1:#3987e5;--S2:#d95926;--S3:#199e70;--S4:#c98500;--S5:#d55181;--S6:#008300;--S7:#9085e9;--S8:#e66767}
*{box-sizing:border-box}
html{background:var(--bg)}
body{margin:0;font:15px/1.55 var(--sans);color:var(--ink);background:var(--bg)}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
.page{max-width:1280px;margin:0 auto;padding:28px 22px 60px}
.mono{font-family:var(--mono);font-size:.9em}.dim{color:var(--muted)}
.hero{padding:6px 0 18px}
.kick{font-size:.72em;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--ink2);margin:0 0 8px}
h1{font-size:2.1em;line-height:1.15;margin:0 0 12px;letter-spacing:-.01em}
.lede{font-size:1.08em;color:var(--ink2);max-width:62em;margin:0 0 10px}
.meta{font-size:.86em;color:var(--muted);margin:0}
.banner{background:var(--surf2);border-left:3px solid var(--med);padding:10px 14px;border-radius:8px;margin:14px 0;color:var(--ink2)}
.sec{margin:26px 0 0}.sec>h2{font-size:1.25em;margin:0 0 8px;letter-spacing:-.005em}
.pd{color:var(--ink2);font-size:.92em;margin:0 0 12px;max-width:74em}
.empty{color:var(--muted);font-style:italic}
.filters{display:flex;align-items:center;gap:8px;flex-wrap:wrap;position:sticky;top:0;z-index:5;
 background:var(--bg);padding:10px 0;border-bottom:1px solid var(--grid);margin:8px 0 6px}
.filters .fl{font-size:.8em;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-right:4px}
.filters .fsp{flex:1}
.chip{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--grid);background:var(--surf);color:var(--ink);
 border-radius:999px;padding:4px 12px 4px 8px;font:inherit;font-size:.86em;cursor:pointer}
.chip:not(.on){opacity:.45}.chip.toggle[aria-pressed="false"]{opacity:.45}
.sw{display:inline-block;width:10px;height:10px;border-radius:50%;background:var(--other)}
.be-codex,.sw.be-codex{background:var(--codex)}.be-claude,.sw.be-claude{background:var(--claude)}
.be-gemini,.sw.be-gemini{background:var(--gemini)}.be-grok,.sw.be-grok{background:var(--grok)}
.be-oss,.sw.be-oss{background:var(--oss)}.be-opencode,.sw.be-opencode{background:var(--opencode)}
span.be{display:inline-block;color:#fff;font-size:.6em;font-weight:700;padding:2px 8px;border-radius:999px;vertical-align:middle;letter-spacing:.04em}
.sw-harness{background:var(--harness)}.sw-direct{background:var(--direct)}.sw-both{background:linear-gradient(90deg,var(--harness) 50%,var(--direct) 50%)}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(360px,1fr));gap:14px}
.card{display:block;background:var(--surf);border:1px solid var(--ring);border-radius:14px;padding:14px 16px;color:inherit;
 box-shadow:0 1px 2px rgba(0,0,0,.05)}
.card:hover{text-decoration:none;border-color:var(--axis)}.card[hidden]{display:none}
.ct{font-weight:700;font-size:1.05em}.cs{color:var(--muted);font-size:.82em;margin:2px 0 10px}
.sides{display:grid;grid-template-columns:1fr auto 1fr;gap:10px;align-items:start}
.side .who{font-size:.78em;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--ink2)}
.side-model-direct .who{color:var(--muted)}
.big{font-size:1.7em;font-weight:700;line-height:1.15;letter-spacing:-.01em}.big small{font-size:.5em;font-weight:500;color:var(--muted);margin-left:5px}
.side .fine{font-size:.8em;color:var(--ink2);margin-top:4px}.fine.warn{color:var(--high)}
.vs{align-self:center;color:var(--muted);font-size:.8em;font-weight:700}
.overlap{font-size:.82em;color:var(--ink2);margin-top:10px;padding-top:8px;border-top:1px solid var(--grid)}
.overlap .sw{width:9px;height:9px;margin-right:3px}
.pending{color:var(--muted);font-style:italic;margin:0}
.sha{font-family:var(--mono);font-size:.72em;color:var(--muted);font-weight:500}
.tablewrap{overflow-x:auto;background:var(--surf);border:1px solid var(--ring);border-radius:12px}
table{border-collapse:collapse;width:100%;font-size:.86em}
th,td{padding:7px 8px;text-align:left;vertical-align:top;border-bottom:1px solid var(--grid)}
th{font-size:.78em;text-transform:uppercase;letter-spacing:.05em;color:var(--ink2);background:var(--surf2);white-space:nowrap;position:sticky;top:0}
th[data-sort]{cursor:pointer;user-select:none}th[data-sort]:hover{color:var(--ink)}th.sorted::after{content:" ▾";color:var(--muted)}th.sorted.asc::after{content:" ▴"}
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
tbody tr:hover{background:var(--surf2)}tr.total td{font-weight:700;border-top:2px solid var(--axis)}
tr[hidden]{display:none}
.count{font-weight:700}
.cond{display:inline-block;white-space:nowrap;font-family:var(--mono);font-size:.86em;padding:1px 7px;border-radius:6px;background:var(--surf2);border:1px solid var(--grid)}
.cond-harness{border-color:var(--harness);color:var(--ink)}.cond-model-direct{color:var(--ink2)}
.sev{display:inline-block;font-size:.78em;font-weight:700;padding:1px 8px;border-radius:999px;color:#fff;white-space:nowrap}
.sev-critical{background:var(--crit)}.sev-high{background:var(--high)}.sev-medium{background:var(--med);color:#3a2a00}
.sev-low{background:var(--low);color:#0b0b0b}.sev-none,.sev-pending{background:var(--none);color:var(--ink2)}
abbr.mark{text-decoration:none;cursor:help;color:var(--muted);border-bottom:1px dotted var(--muted)}
.run{background:var(--surf);border:1px solid var(--ring);border-radius:16px;padding:18px 20px;margin:16px 0;scroll-margin-top:64px}
.run[hidden]{display:none}
.rh h2{margin:0;font-size:1.3em}.rh .ident{font-size:.82em;color:var(--muted);margin-top:2px;font-family:var(--mono)}
.panel{margin:18px 0 0;padding-top:14px;border-top:1px solid var(--grid)}
.pt{font-weight:700;font-size:1.02em;margin-bottom:4px}
.unjudged{font-size:.86em;color:var(--ink2)}
.cmap{display:grid;grid-template-columns:1fr;gap:0;font-size:.88em}
.cmap-head,.cmap-row{display:grid;grid-template-columns:160px 1fr 1fr 1fr 1fr;align-items:stretch}
.cmap-head>div{font-size:.78em;font-weight:700;text-transform:uppercase;letter-spacing:.05em;color:var(--ink2);padding:6px 8px;border-bottom:1px solid var(--axis)}
.cmap-row>div{padding:7px 8px;border-bottom:1px solid var(--grid);min-height:34px}
.cmap-class{font-family:var(--mono);font-size:.92em;color:var(--ink)}
.cmap-cell{display:flex;flex-wrap:wrap;gap:5px;align-content:flex-start}
.cmap-both{background:var(--surf2)}.cmap-rejected{opacity:.75}
.cmap.hide-rejected .cmap-rejected{display:none}
.cmap.hide-rejected .cmap-head,.cmap.hide-rejected .cmap-row{grid-template-columns:160px 1fr 1fr 1fr}
.dot{display:inline-block;width:14px;height:14px;border:2px solid var(--surf);box-shadow:0 0 0 1px var(--ring);cursor:pointer}
.dot-find{border-radius:50%}.dot-crash{border-radius:3px;transform:rotate(45deg) scale(.85)}
.dot.sev-critical{background:var(--crit)}.dot.sev-high{background:var(--high)}.dot.sev-medium{background:var(--med)}
.dot.sev-low{background:var(--low)}.dot.sev-none{background:var(--none)}
.dot:hover{box-shadow:0 0 0 2px var(--ink)}
.dot.demo{vertical-align:middle;cursor:default;width:12px;height:12px}
.chart{margin-top:6px}.chart svg{display:block;width:100%;height:auto;overflow:visible;font:inherit}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:.82em;color:var(--ink2);margin:6px 0 2px}
.legend .k{display:inline-flex;align-items:center;gap:6px}.legend .k i{display:inline-block;width:14px;height:0;border-top:2.5px solid var(--ink)}
.legend .k i.dash{border-top-style:dashed}.legend .k b{display:inline-block;width:10px;height:10px;border-radius:2px}
.seg{display:inline-flex;border:1px solid var(--grid);border-radius:8px;overflow:hidden;font-size:.82em;margin-bottom:6px}
.seg button{background:var(--surf);color:var(--ink2);border:0;padding:4px 12px;font:inherit;cursor:pointer}
.seg button[aria-pressed="true"]{background:var(--ink);color:var(--surf)}
.funnels{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px 22px}
.funnel .ft,.effort .ft{font-size:.88em;font-weight:700;margin-bottom:6px}
.fr{display:grid;grid-template-columns:120px 1fr 36px;align-items:center;gap:8px;font-size:.84em;margin:3px 0}
.fl{color:var(--ink2)}.fb{height:12px;background:var(--surf2);border-radius:4px;overflow:hidden}
.ff{display:block;height:100%;border-radius:4px;background:var(--harness)}.ff-model-direct{background:var(--direct)}
.fv{text-align:right;font-variant-numeric:tabular-nums}.fn{font-size:.8em;color:var(--muted);margin-top:4px}
.lane{display:inline-block;font-family:var(--mono);font-size:.82em;font-weight:700;padding:0 6px;border-radius:5px;color:#fff;background:var(--other)}
.lane-S1{background:var(--S1)}.lane-S2{background:var(--S2)}.lane-S3{background:var(--S3)}.lane-S4{background:var(--S4);color:#3a2a00}
.lane-S5{background:var(--S5)}.lane-S6{background:var(--S6)}.lane-S7{background:var(--S7)}.lane-S8{background:var(--S8)}
.mini{display:inline-block;width:70px;height:8px;background:var(--surf2);border-radius:4px;vertical-align:middle;overflow:hidden;margin-right:6px}
.mini span{display:block;height:100%;background:var(--harness);border-radius:4px}
.effort{margin:8px 0 14px}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px}
.tile{background:var(--surf2);border-radius:10px;padding:8px 10px}
.tl{font-size:.74em;color:var(--ink2);text-transform:uppercase;letter-spacing:.05em}
.tv{font-size:1.25em;font-weight:700;margin-top:2px;line-height:1.2}.tn{font-size:.74em;color:var(--muted);margin-top:2px}
.guide{margin:34px 0 0;scroll-margin-top:64px;background:var(--surf);border:1px solid var(--ring);border-radius:14px;padding:6px 18px}
.guide summary{cursor:pointer;font-weight:700;padding:8px 0}
.gbody{font-size:.93em;color:var(--ink2);max-width:76em}.gbody h3{font-size:.95em;color:var(--ink);margin:14px 0 4px}
.gbody code{font-family:var(--mono);font-size:.9em;background:var(--surf2);padding:0 4px;border-radius:4px}
.lb{margin:10px 0 16px}.lbt{font-weight:700;margin:0 0 6px}
.mini.wide{width:110px}
.replay{display:flex;align-items:center;gap:12px;flex-wrap:wrap;background:var(--surf2);border-radius:10px;padding:10px 12px}
.replay .play{font:inherit;font-size:.86em;font-weight:700;border:1px solid var(--axis);background:var(--surf);color:var(--ink);border-radius:8px;padding:5px 12px;cursor:pointer}
.replay input[type=range]{flex:1;min-width:200px;accent-color:var(--ink)}
.replay .rt{font-variant-numeric:tabular-nums;font-weight:700;min-width:4.5em}.replay .rn{font-size:.84em;color:var(--ink2)}
.dot.future{opacity:.12}
.tsum{font-size:.84em;color:var(--ink2);margin:10px 0 2px}
.legend .k b.o-hit{background:var(--codex)}.legend .k b.o-confirmed{background:var(--good)}.legend .k b.o-refuted{background:var(--muted)}
.legend .k b.o-dropped{background:var(--none)}.legend .k b.o-blocked{background:var(--med)}.legend .k b.o-open{background:var(--surf);border:1.5px solid var(--ink2)}
.run[data-backend=claude] .legend .k b.o-hit{background:var(--claude)}.run[data-backend=gemini] .legend .k b.o-hit{background:var(--gemini)}
.run[data-backend=grok] .legend .k b.o-hit{background:var(--grok)}.run[data-backend=oss] .legend .k b.o-hit{background:var(--oss)}
.run[data-backend=opencode] .legend .k b.o-hit{background:var(--opencode)}
.chart.trace svg .hyp{cursor:pointer}.chart.trace svg .hyp:hover{stroke:var(--ink);stroke-width:1.5}
.drawer{position:fixed;top:0;right:0;bottom:0;width:min(520px,100vw);z-index:70;background:var(--surf);border-left:1px solid var(--ring);
 box-shadow:-4px 0 24px rgba(0,0,0,.18);display:flex;flex-direction:column}
.drawer[hidden]{display:none}
.dh{display:flex;align-items:flex-start;gap:10px;padding:14px 16px;border-bottom:1px solid var(--grid)}
.dh b{flex:1;font-family:var(--mono);font-size:.9em;word-break:break-all}
.dclose{font:inherit;font-size:1.3em;line-height:1;border:0;background:none;color:var(--ink2);cursor:pointer}
.db{overflow:auto;padding:6px 16px 24px;font-size:.9em;line-height:1.55}
.db h4{font-size:.76em;text-transform:uppercase;letter-spacing:.06em;color:var(--ink2);margin:14px 0 3px}
.db p{margin:0;color:var(--ink)}.db ul{margin:2px 0 0;padding-left:18px;color:var(--ink2)}.db li{margin:2px 0}
.db .meta{font-size:.84em;color:var(--ink2)}
.tip{position:fixed;z-index:60;display:none;pointer-events:none;max-width:320px;background:var(--ink);color:var(--surf);
 font-size:.8em;line-height:1.5;padding:8px 10px;border-radius:9px;box-shadow:0 2px 10px rgba(0,0,0,.3)}
.tip b{display:block;font-weight:700}.tip .src{font-family:var(--mono);word-break:break-all;color:var(--low)}.tip .dim{opacity:.75}
@media(max-width:820px){.cmap-head,.cmap-row{grid-template-columns:110px 1fr 1fr 1fr 1fr}.cmap.hide-rejected .cmap-head,.cmap.hide-rejected .cmap-row{grid-template-columns:110px 1fr 1fr 1fr}
 h1{font-size:1.6em}.sides{grid-template-columns:1fr}.vs{display:none}}
@media print{.filters{display:none}.tip{display:none!important}}
"""

_JS = r"""
(function(){
"use strict";
var D=JSON.parse(document.getElementById("bench-data").textContent),NS="http://www.w3.org/2000/svg";
var css=getComputedStyle(document.documentElement);
function v(name){return css.getPropertyValue(name).trim()}
var HUE={codex:v("--codex"),claude:v("--claude"),gemini:v("--gemini"),grok:v("--grok"),oss:v("--oss"),opencode:v("--opencode")};
function hue(b){return HUE[b]||v("--other")}
var LANES=["S1","S2","S3","S4","S5","S6","S7","S8"];
var VERD={CRASH:v("--crit"),CLEAN:v("--good"),TIMEOUT:v("--med"),EXEC_FAIL:v("--muted"),other:v("--none")};
function el(t,a,k){var e=document.createElementNS(NS,t);for(var x in a)if(a[x]!=null)e.setAttribute(x,a[x]);(k||[]).forEach(function(c){e.appendChild(c)});return e}
function tx(s){return document.createTextNode(String(s))}
function h(t,cls,text){var e=document.createElement(t);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e}
// ── shared tooltip ─────────────────────────────────────────────────────────
var tip=document.getElementById("tip");
function place(e){var pad=14,w=tip.offsetWidth,ht=tip.offsetHeight,x=e.clientX+pad,y=e.clientY+pad;
 if(x+w>innerWidth-8)x=e.clientX-w-pad;if(y+ht>innerHeight-8)y=e.clientY-ht-pad;tip.style.left=Math.max(8,x)+"px";tip.style.top=Math.max(8,y)+"px"}
function show(e,lines){tip.replaceChildren();lines.forEach(function(l){if(!l||!l.text)return;var p=document.createElement(l.b?"b":"span");
 p.textContent=l.text;if(l.src)p.className="src";if(l.dim)p.className="dim";tip.appendChild(p);if(!l.b)tip.appendChild(document.createElement("br"))});
 tip.style.display="block";place(e)}
function hide(){tip.style.display="none"}
function hover(node,fn){node.addEventListener("mouseenter",function(e){show(e,fn())});node.addEventListener("mousemove",place);node.addEventListener("mouseleave",hide)}
// cluster dots: their facts ride on data attributes
document.querySelectorAll(".dot[data-kind]").forEach(function(d){hover(d,function(){var s=d.dataset;return[
 {text:s.title||s.site||"(untitled)",b:true},{text:s.site,src:true},
 {text:(s.kind==="crash"?"sanitizer crash":"finding")+" · "+s.sev+(s.size>1?" · "+s.size+" reports merged":"")},
 {text:"found by "+s.who+(s.strategy?" · lane "+s.strategy:"")},
 s.reason?{text:"rejected: "+s.reason,dim:true}:null,
 d.href?{text:"click to open the report",dim:true}:null]})});
// ── filters ────────────────────────────────────────────────────────────────
var chips=[].slice.call(document.querySelectorAll(".chip[data-backend]"));
function applyFilters(){var on={};chips.forEach(function(c){if(c.classList.contains("on"))on[c.dataset.backend]=1});
 document.querySelectorAll("[data-backend]:not(.chip)").forEach(function(n){n.hidden=!on[n.dataset.backend]})}
chips.forEach(function(c){c.addEventListener("click",function(){c.classList.toggle("on");applyFilters()})});
var rej=document.getElementById("show-rejected");
if(rej)rej.addEventListener("click",function(){var on=rej.getAttribute("aria-pressed")!=="true";rej.setAttribute("aria-pressed",on?"true":"false");
 document.querySelectorAll(".cmap").forEach(function(m){m.classList.toggle("hide-rejected",!on)});document.querySelectorAll(".ttd").forEach(function(c){c.dataset.rejected=on?"1":"0";drawTTD(c)})});
// ── scoreboard sort ────────────────────────────────────────────────────────
var table=document.getElementById("scoreboard");
if(table){var ths=[].slice.call(table.querySelectorAll("th[data-sort]"));ths.forEach(function(th,i){th.addEventListener("click",function(){
 var asc=th.classList.contains("sorted")&&!th.classList.contains("asc");ths.forEach(function(t){t.classList.remove("sorted","asc")});
 th.classList.add("sorted");if(asc)th.classList.add("asc");var body=table.tBodies[0],rows=[].slice.call(body.rows),num=th.dataset.sort==="num";
 rows.sort(function(a,b){var x=a.cells[i].dataset.v||a.cells[i].textContent,y=b.cells[i].dataset.v||b.cells[i].textContent;
  if(num){x=parseFloat(x)||0;y=parseFloat(y)||0;return asc?x-y:y-x}return asc?String(x).localeCompare(y):String(y).localeCompare(x)});
 rows.forEach(function(r){body.appendChild(r)})})})}
// ── helpers ────────────────────────────────────────────────────────────────
function nice(vmax,n,integer){if(!(vmax>0))vmax=1;var s=vmax/(n||4),p=Math.pow(10,Math.floor(Math.log10(s))),q=s/p;
 var st=(q<=1?1:q<=2?2:q<=2.5?2.5:q<=5?5:10)*p;if(integer)st=Math.max(1,Math.round(st));return{step:st,top:Math.ceil(vmax/st-1e-9)*st}}
function hrs(x){return (Math.round((+x||0)*100)/100)+"h"}
function fmtH(q){return (q%1?q.toFixed(1):q)+"h"}
function binH(i,bw){return (i*bw).toFixed(2)+"–"+((i+1)*bw).toFixed(2)+"h"}
function noun(kind,n){return kind==="crash"?(n===1?"crash":"crashes"):(n===1?"finding":"findings")}
function steps(times){var p=[[0,0]];times.forEach(function(t,i){p.push([t,i]);p.push([t,i+1])});return p}
function runOf(key){for(var i=0;i<D.runs.length;i++)if(D.runs[i].key===key)return D.runs[i];return null}
// the replay cut: hours into the run that the section is showing, Infinity for all of it
function cutOf(host){var r=host.closest(".run"),c=r?r.dataset.cut:"";return c==null||c===""?Infinity:+c}
function playhead(s,x,y1,y2){s.appendChild(el("line",{x1:x,x2:x,y1:y1,y2:y2,stroke:v("--ink"),"stroke-width":1.5,"stroke-dasharray":"4 3"}))}
function axes(s,X,Y,ys,xs,ml,mt,pw,ph,ylabel){
 for(var yv=0;yv<=ys.top+1e-9;yv+=ys.step){var q=Math.round(yv*1e6)/1e6;
  s.appendChild(el("line",{x1:ml,x2:ml+pw,y1:Y(q),y2:Y(q),stroke:q?v("--grid"):v("--axis"),"stroke-width":q?1:1.5}));
  s.appendChild(el("text",{x:ml-8,y:Y(q)+4,"text-anchor":"end","font-size":10.5,fill:v("--muted")},[tx(q)]))}
 s.appendChild(el("text",{x:4,y:mt-6,"font-size":10,"font-weight":700,fill:v("--muted")},[tx(ylabel)]));
 for(var xv=0;xv<=xs.top+1e-9;xv+=xs.step){var r=Math.round(xv*1e6)/1e6;
  s.appendChild(el("text",{x:X(r),y:mt+ph+16,"text-anchor":"middle","font-size":10.5,fill:v("--muted")},[tx(fmtH(r))]))}
 s.appendChild(el("text",{x:ml,y:mt+ph+30,"font-size":10,"font-weight":700,fill:v("--muted")},[tx("hours since the cell started →")]))}
// ── time to discovery ──────────────────────────────────────────────────────
function drawTTD(host){var run=runOf(host.dataset.run);if(!run)return;var kind=host.dataset.kind||"find",showRej=host.dataset.rejected!=="0",cut=cutOf(host);
 host.replaceChildren();
 var seg=h("div","seg");[["find","Findings"],["crash","Crashes"]].forEach(function(k){var b=h("button",null,k[1]);b.setAttribute("aria-pressed",k[0]===kind?"true":"false");
  b.addEventListener("click",function(){host.dataset.kind=k[0];drawTTD(host)});seg.appendChild(b)});host.appendChild(seg);
 var legend=h("div","legend");run.conditions.forEach(function(c){var k=h("span","k");var i=h("i");i.style.borderTopColor=hue(run.backend);if(c.token!=="harness")i.className="dash";
  k.appendChild(i);k.appendChild(tx(c.label+" — "+c[kind].unique+" "+noun(kind,c[kind].unique)+" kept"+(c[kind].rejected!=null?", "+(c[kind].rejected_upper?"up to ":"")+c[kind].rejected+" rejected":"")));legend.appendChild(k)});
 host.appendChild(legend);
 var W=900,ml=46,mr=70,pw=W-ml-mr,mt=16,ph=220,H=mt+ph+50,maxY=1,maxX=.5,approx=false;
 run.conditions.forEach(function(c){var m=c[kind];maxY=Math.max(maxY,m.unique);maxX=Math.max(maxX,c.wall_h||0,c.budget_h||0);
  m.times.forEach(function(t){maxX=Math.max(maxX,t)});if(m.approx)approx=true});
 var ys=nice(maxY*1.12,4,true),xs=nice(maxX*1.02,5),X=function(x){return ml+(x/xs.top)*pw},Y=function(y){return mt+ph-(y/ys.top)*ph};
 var s=el("svg",{viewBox:"0 0 "+W+" "+H,role:"img","aria-label":"cumulative "+noun(kind,2)+" over time"});
 axes(s,X,Y,ys,xs,ml,mt,pw,ph,"distinct "+noun(kind,2));
 run.conditions.forEach(function(c){var m=c[kind],col=hue(run.backend),direct=c.token!=="harness",name=c.label;
  if(c.budget_h){s.appendChild(el("line",{x1:X(c.budget_h),x2:X(c.budget_h),y1:mt,y2:mt+ph,stroke:v("--axis"),"stroke-width":1,"stroke-dasharray":"2 4"}))}
  if(showRej)m.rejected_times.forEach(function(t){s.appendChild(el("line",{x1:X(t),x2:X(t),y1:mt+ph+2,y2:mt+ph+8,stroke:direct?v("--direct"):col,"stroke-width":direct?1.5:2,opacity:.8}))});
  // a side that kept nothing still ran: its end mark sits on the axis at the hour it stopped
  var pts=steps(m.times),end=pts[pts.length-1];
  if((c.wall_h||0)>end[0]){pts=pts.concat([[c.wall_h,end[1]]]);end=pts[pts.length-1]}
  var d=pts.map(function(p,i){return (i?"L":"M")+X(p[0]).toFixed(2)+","+Y(p[1]).toFixed(2)}).join(" ");
  if(!direct&&m.unique)s.appendChild(el("polygon",{points:pts.map(function(p){return X(p[0]).toFixed(2)+","+Y(p[1]).toFixed(2)}).concat([X(end[0]).toFixed(2)+","+Y(0),X(0)+","+Y(0)]).join(" "),fill:col,"fill-opacity":.08}));
  s.appendChild(el("path",{d:d,fill:"none",stroke:col,"stroke-width":direct?2:2.5,"stroke-dasharray":direct?"6 5":null,"stroke-linejoin":"round","stroke-linecap":"round"}));
  m.times.forEach(function(t,i){var px=X(t),py=Y(i+1);
   var dot=el("circle",{cx:px,cy:py,r:direct?3.2:3.8,fill:direct?v("--surf"):col,stroke:direct?col:v("--surf"),"stroke-width":2,opacity:t>cut?.15:null});
   var hit=el("circle",{cx:px,cy:py,r:10,fill:"transparent",style:"cursor:pointer"});s.appendChild(dot);s.appendChild(hit);
   hover(hit,function(){return[{text:name+" · "+noun(kind,1)+" "+(i+1)+" of "+m.unique,b:true},{text:m.sites[i]||"",src:true},{text:"first seen "+hrs(t)+" into the run"},
    {text:"one distinct problem after duplicate merging; the same problem written up more than once counts once",dim:true}]})});
  var ex=X(end[0]),ey=Y(end[1]);
  var mark=direct?el("polygon",{points:[[ex-6,ey-6],[ex-6,ey+6],[ex+6,ey]].map(function(p){return p.join(",")}).join(" "),fill:v("--surf"),stroke:col,"stroke-width":2,"stroke-linejoin":"round"})
   :el("polygon",{points:[[ex,ey-5.5],[ex+5.5,ey],[ex,ey+5.5],[ex-5.5,ey]].map(function(p){return p.join(",")}).join(" "),fill:col,stroke:v("--surf"),"stroke-width":2});
  mark.style.cursor="pointer";s.appendChild(mark);
  hover(mark,function(){var l=[{text:name+" · final: "+m.unique+" "+noun(kind,m.unique)+" kept",b:true},{text:(direct?"stopped at ":"audited for ")+hrs(c.wall_h)},
   {text:direct?"the model alone, judged by the same rules as the harness row":"counted across this run's repeats with duplicates merged",dim:true}];
   if(m.approx)l.push({text:"discovery timing approximate",dim:true});return l});
  s.appendChild(el("text",{x:ex+10,y:ey+4,"font-size":11.5,"font-weight":700,fill:v("--ink")},[tx(m.unique)]))});
 if(approx)s.appendChild(el("text",{x:ml+pw,y:mt+12,"text-anchor":"end","font-size":9.5,"font-style":"italic",fill:v("--muted")},[tx("timing approximate — one or more discovery times unavailable")]));
 if(cut<Infinity){var cx=X(Math.min(cut,xs.top));s.appendChild(el("rect",{x:cx,y:mt,width:Math.max(0,ml+pw-cx),height:ph,fill:v("--bg"),opacity:.7}));playhead(s,cx,mt,mt+ph)}
 host.appendChild(s)}
// ── activity ───────────────────────────────────────────────────────────────
function drawActivity(host){var run=runOf(host.dataset.run);if(!run)return;host.replaceChildren();
 var conds=run.conditions.filter(function(c){return c.activity});if(!conds.length)return;
 var legend=h("div","legend");LANES.forEach(function(l){if(!conds.some(function(c){return c.activity.hyp[l]}))return;var k=h("span","k");var b=h("b");b.style.background=v("--"+l);k.appendChild(b);k.appendChild(tx(l+" "+(D.lane_names[l]||l)));legend.appendChild(k)});
 ["CRASH","CLEAN","TIMEOUT","EXEC_FAIL"].forEach(function(vd){var k=h("span","k");var b=h("b");b.style.background=VERD[vd];k.appendChild(b);k.appendChild(tx("probe "+vd));legend.appendChild(k)});
 host.appendChild(legend);
 var cut=cutOf(host);
 conds.forEach(function(c){var A=c.activity,n=A.bins,bw=A.bin_h,wall=n*bw;
  var W=900,ml=92,mr=24,pw=W-ml-mr,rows=[],hasHyp=Object.keys(A.hyp).length>0,hasProbe=PROBEsum(A)>0,hasTok=A.out_tokens.some(function(x){return x>0});
  if(hasHyp)rows.push("hyp");if(hasProbe)rows.push("probe");rows.push("filed");if(hasTok)rows.push("tokens");
  var RH={hyp:90,probe:70,filed:44,tokens:56},gap=22,mt=26,H=mt+rows.reduce(function(a,r){return a+RH[r]+gap},0)+30;
  var s=el("svg",{viewBox:"0 0 "+W+" "+H,role:"img","aria-label":c.label+" activity"});
  var X=function(x){return ml+(x/wall)*pw},bx=pw/n,y=mt;
  s.appendChild(el("text",{x:ml,y:14,"font-size":12,"font-weight":700,fill:v("--ink")},[tx(c.label+(A.cells>1?" · "+A.cells+" repeats summed":"")+(A.agents?" · "+A.agents+" agent"+(A.agents>1?"s":""):""))]));
  function label(t,y0){s.appendChild(el("text",{x:ml-8,y:y0+11,"text-anchor":"end","font-size":10,"font-weight":700,fill:v("--muted")},[tx(t)]))}
  function stack(y0,hgt,series,colors,title){var tops=[];for(var i=0;i<n;i++){var t=0;series.forEach(function(sr){t+=sr.data[i]});tops.push(t)}
   var top=Math.max.apply(null,tops.concat([1])),ys=nice(top,2,true);label(title,y0);
   s.appendChild(el("text",{x:ml-8,y:y0+hgt,"text-anchor":"end","font-size":9.5,fill:v("--muted")},[tx("0–"+ys.top)]));
   s.appendChild(el("line",{x1:ml,x2:ml+pw,y1:y0+hgt,y2:y0+hgt,stroke:v("--axis")}));
   for(var i=0;i<n;i++){var acc=0;series.forEach(function(sr){var val=sr.data[i];if(!val)return;var hh=(val/ys.top)*hgt;
    var r=el("rect",{x:(X(i*bw)+1).toFixed(1),y:(y0+hgt-acc-hh).toFixed(1),width:Math.max(1,bx-2).toFixed(1),height:hh.toFixed(1),fill:colors[sr.key],rx:1.5});
    (function(i,sr,val){hover(r,function(){var l=[{text:c.label+" · "+binH(i,bw),b:true}];
     series.forEach(function(s2){if(s2.data[i])l.push({text:s2.data[i]+" "+s2.name})});return l})})(i,sr,val);
    s.appendChild(r);acc+=hh})}}
  rows.forEach(function(r){if(r==="hyp"){var ser=[];LANES.concat(Object.keys(A.hyp).filter(function(k){return LANES.indexOf(k)<0})).forEach(function(l){if(A.hyp[l])ser.push({key:l,name:"hypotheses in "+l+" "+(D.lane_names[l]||""),data:A.hyp[l]})});
    var cols={};ser.forEach(function(sr){cols[sr.key]=LANES.indexOf(sr.key)>=0?v("--"+sr.key):v("--other")});stack(y,RH.hyp,ser,cols,"hypotheses")}
   else if(r==="probe"){var ser2=["CRASH","CLEAN","TIMEOUT","EXEC_FAIL","other"].map(function(k){return{key:k,name:"probes "+k,data:A.probe[k]}}).filter(function(sr){return sr.data.some(function(x){return x>0})});stack(y,RH.probe,ser2,VERD,"probes")}
   else if(r==="filed"){label("filed",y);var base=y+RH.filed;s.appendChild(el("line",{x1:ml,x2:ml+pw,y1:base,y2:base,stroke:v("--axis")}));
    for(var i=0;i<n;i++){var f=A.filed_find[i],cr=A.filed_crash[i],ad=A.admitted[i],rj=A.rejected[i];if(!(f||cr||ad||rj))continue;
     var cx=X((i+.5)*bw),items=[];if(cr)items.push(["crash",cr]);if(f)items.push(["find",f]);var yy=base-6;
     items.forEach(function(it){var sz=Math.min(12,6+it[1]*1.5);var g=it[0]==="crash"?el("rect",{x:cx-sz/2,y:yy-sz/2,width:sz,height:sz,fill:v("--crit"),transform:"rotate(45 "+cx+" "+yy+")",rx:1}):el("circle",{cx:cx,cy:yy,r:sz/2,fill:hue(run.backend)});
      (function(i){hover(g,function(){return[{text:c.label+" · "+binH(i,bw),b:true},{text:A.filed_crash[i]+" crash"+(A.filed_crash[i]===1?"":"es")+" filed"},{text:A.filed_find[i]+" finding"+(A.filed_find[i]===1?"":"s")+" filed"},
       {text:A.admitted[i]+" admitted · "+A.rejected[i]+" rejected by the in-run gate"}]})})(i);s.appendChild(g);yy-=sz+2});
     if(ad)s.appendChild(el("line",{x1:cx-3,x2:cx+3,y1:base+3,y2:base+3,stroke:v("--good"),"stroke-width":2}));if(rj)s.appendChild(el("line",{x1:cx-3,x2:cx+3,y1:base+7,y2:base+7,stroke:v("--crit"),"stroke-width":2}))}}
   else if(r==="tokens"){var top=Math.max.apply(null,A.out_tokens.concat([1])),ys=nice(top,2);label("output tokens",y);
    s.appendChild(el("text",{x:ml-8,y:y+RH.tokens,"text-anchor":"end","font-size":9.5,fill:v("--muted")},[tx("0–"+ktok(ys.top))]));
    s.appendChild(el("line",{x1:ml,x2:ml+pw,y1:y+RH.tokens,y2:y+RH.tokens,stroke:v("--axis")}));
    var pts=A.out_tokens.map(function(val,i){return X((i+.5)*bw).toFixed(1)+","+(y+RH.tokens-(val/ys.top)*RH.tokens).toFixed(1)});
    s.appendChild(el("polygon",{points:[X(.5*bw).toFixed(1)+","+(y+RH.tokens)].concat(pts).concat([X((n-.5)*bw).toFixed(1)+","+(y+RH.tokens)]).join(" "),fill:hue(run.backend),"fill-opacity":.12}));
    s.appendChild(el("polyline",{points:pts.join(" "),fill:"none",stroke:hue(run.backend),"stroke-width":2,"stroke-linejoin":"round"}));
    for(var i=0;i<n;i++){var hit=el("rect",{x:X(i*bw),y:y,width:bx,height:RH.tokens,fill:"transparent"});(function(i){hover(hit,function(){return[{text:c.label+" · "+binH(i,bw),b:true},{text:ktok(A.out_tokens[i])+" output tokens"}]})})(i);s.appendChild(hit)}}
   y+=RH[r]+gap});
  // clock marks: first filed / first crash / first admitted, from the aggregate
  [["first_filed_min","first filed"],["first_crash_min","first crash confirmed"],["first_admitted_min","first admitted"]].forEach(function(m,j){var mins=c[m[0]];if(mins==null)return;var x=X(mins/60);if(x>ml+pw)return;
   s.appendChild(el("line",{x1:x,x2:x,y1:mt,y2:y-gap+6,stroke:v("--ink2"),"stroke-width":1,"stroke-dasharray":"3 3",opacity:.6}));
   s.appendChild(el("text",{x:x+3,y:y-gap+16+(j%2)*10,"font-size":9,fill:v("--ink2")},[tx(m[1]+" "+fmtH(Math.round(mins/60*100)/100))]))});
  for(var xv=0,xs=nice(wall,6);xv<=wall+1e-9;xv+=xs.step){var q=Math.round(xv*1e6)/1e6;s.appendChild(el("text",{x:X(q),y:H-6,"text-anchor":"middle","font-size":10.5,fill:v("--muted")},[tx(fmtH(q))]))}
  if(cut<Infinity&&cut<wall){var cx=X(cut);s.appendChild(el("rect",{x:cx,y:mt,width:ml+pw-cx,height:y-gap-mt+6,fill:v("--bg"),opacity:.7}));playhead(s,cx,mt,y-gap+6)}
  host.appendChild(s)})}
function PROBEsum(A){var t=0;for(var k in A.probe)A.probe[k].forEach(function(x){t+=x});return t}
function ktok(n){return n>=1e6?(n/1e6).toFixed(1)+"M":n>=1e3?Math.round(n/1e3)+"k":String(n)}
// ── the mind trace: one row per agent, one bar per hypothesis ────────────────
function traceOf(run,cell){var h=run.conditions.filter(function(c){return c.token==="harness"})[0];
 return ((h&&h.traces)||[]).filter(function(t){return t.cell===cell})[0]||null}
function drawTrace(host){var run=runOf(host.dataset.run),T=run&&traceOf(run,host.dataset.cell);if(!T)return;host.replaceChildren();
 var cut=cutOf(host),wall=T.wall_h||Math.max.apply(null,T.hyps.map(function(x){return x.t1}).concat([1]));
 var col=hue(run.backend),OUT={hit:{fill:col},confirmed:{fill:v("--good")},refuted:{fill:v("--muted")},dropped:{fill:v("--none")},blocked:{fill:v("--med")},open:{fill:v("--surf"),stroke:v("--ink2")}};
 // pack each agent's hypotheses into sub-rows so overlapping ideas stay legible
 var subs={};T.agents.forEach(function(a){subs[a]=[]});
 T.hyps.forEach(function(hp){var rows=subs[hp.agent]||(subs[hp.agent]=[]),i=0;for(;i<rows.length;i++)if(rows[i]<=hp.t0)break;
  if(i>=rows.length){if(rows.length>=6)i=rows.length-1;else rows.push(0)}rows[i]=Math.max(rows[i]||0,hp.t1+wall*.004);hp._row=i});
 var W=900,ml=70,mr=16,pw=W-ml-mr,rowH=13,gap=3,agentGap=16,mt=10,y=mt,ys={};
 Object.keys(subs).forEach(function(a){ys[a]=y;y+=Math.max(1,subs[a].length)*(rowH+gap)+agentGap});
 var H=y+18,X=function(x){return ml+(x/wall)*pw};
 var s=el("svg",{viewBox:"0 0 "+W+" "+H,role:"img","aria-label":"hypotheses over time"});
 for(var xv=0,xs=nice(wall,6);xv<=wall+1e-9;xv+=xs.step){var q=Math.round(xv*1e6)/1e6;
  s.appendChild(el("line",{x1:X(q),x2:X(q),y1:mt-4,y2:y-agentGap+4,stroke:v("--grid")}));
  s.appendChild(el("text",{x:X(q),y:H-3,"text-anchor":"middle","font-size":10.5,fill:v("--muted")},[tx(fmtH(q))]))}
 Object.keys(subs).forEach(function(a){s.appendChild(el("text",{x:ml-8,y:ys[a]+10,"text-anchor":"end","font-size":10.5,"font-weight":700,fill:v("--ink2")},[tx("agent "+a)]))});
 T.hyps.forEach(function(hp){if(hp.t0>cut)return;var y0=ys[hp.agent]+hp._row*(rowH+gap),x0=X(hp.t0),x1=X(Math.min(hp.t1,cut)),w=Math.max(3,x1-x0),o=OUT[hp.outcome]||OUT.open;
  var r=el("rect",{x:x0.toFixed(1),y:y0+3,width:w.toFixed(1),height:rowH-4,rx:2,fill:o.fill,stroke:o.stroke||null,"stroke-width":o.stroke?1.2:null,"class":"hyp"});
  s.appendChild(r);
  hp.probes.forEach(function(p){if(p.t>cut)return;s.appendChild(el("rect",{x:(X(p.t)-1).toFixed(1),y:y0,width:2,height:3,fill:VERD[p.verdict]||VERD.other}))});
  if(hp.outcome==="hit"&&hp.t1<=cut)s.appendChild(el("circle",{cx:X(hp.t1),cy:y0+3+(rowH-4)/2,r:3.5,fill:col,stroke:v("--surf"),"stroke-width":1.5,"pointer-events":"none"}));
  hover(r,function(){var n=hp.probes.length;return[{text:hp.file||hp.id,b:true},
   {text:hp.lane+" "+(D.lane_names[hp.lane]||"")+" · "+hp.outcome+(hp.status?" ("+hp.status+")":"")+" · "+n+" probe"+(n===1?"":"s")},
   {text:hp.text.length>240?hp.text.slice(0,239)+"…":hp.text},
   {text:"opened "+hrs(hp.t0)+(hp.t1>hp.t0?" · resolved "+hrs(hp.t1):""),dim:true},{text:"click to read the reasoning",dim:true}]});
  r.addEventListener("click",function(){openDrawer(run,hp)})});
 if(cut<Infinity&&cut<wall)playhead(s,X(cut),mt-6,y-agentGap+6);
 host.appendChild(s)}
// ── the reasoning drawer ────────────────────────────────────────────────────
var drawer=document.getElementById("drawer"),dtitle=document.getElementById("dtitle"),dbody=document.getElementById("dbody");
function section(title,text){if(!text)return;dbody.appendChild(h("h4",null,title));dbody.appendChild(h("p",null,text))}
function openDrawer(run,hp){dtitle.textContent=hp.file||hp.id;dbody.replaceChildren();
 var meta=h("p","meta",hp.lane+" "+(D.lane_names[hp.lane]||"")+" · agent "+hp.agent+" · "+hp.outcome+(hp.status?" ("+hp.status+")":"")+(hp.artifact?" · filed as "+hp.artifact:"")+(hp.diagnostic?" · "+hp.diagnostic:"")+" · opened "+hrs(hp.t0)+(hp.t1>hp.t0?", resolved "+hrs(hp.t1):"")+" into the run");
 dbody.appendChild(meta);
 section("Hypothesis",hp.text);section("Guard gap",hp.guard_gap);section("Input shape",hp.input_shape);section("Agent's conclusion",hp.note);
 if(hp.probes.length){dbody.appendChild(h("h4",null,hp.probes.length+" sanitizer probe"+(hp.probes.length===1?"":"s")));var ul=h("ul");
  hp.probes.forEach(function(p){ul.appendChild(h("li",null,hrs(p.t)+" · "+p.verdict+(p.s?" · "+p.s+"s":"")))});dbody.appendChild(ul)}
 if(hp.notes.length){dbody.appendChild(h("h4",null,"Notes"));var nl=h("ul");hp.notes.forEach(function(n){nl.appendChild(h("li",null,(n.kind?n.kind+": ":"")+n.text))});dbody.appendChild(nl)}
 drawer.hidden=false}
drawer.querySelector(".dclose").addEventListener("click",function(){drawer.hidden=true});
document.addEventListener("keydown",function(e){if(e.key==="Escape")drawer.hidden=true});
// ── replay: one cut per run, every panel redrawn from it ────────────────────
function redraw(run){run.querySelectorAll(".ttd").forEach(drawTTD);run.querySelectorAll(".act").forEach(drawActivity);run.querySelectorAll(".trace").forEach(drawTrace);
 var cut=run.dataset.cut==null||run.dataset.cut===""?Infinity:+run.dataset.cut;
 run.querySelectorAll(".dot[data-t]").forEach(function(d){d.classList.toggle("future",+d.dataset.t>cut)})}
document.querySelectorAll(".replay").forEach(function(bar){var run=bar.closest(".run"),range=bar.querySelector("input"),play=bar.querySelector(".play"),out=bar.querySelector(".rt"),note=bar.querySelector(".rn"),max=+range.max,timer=null,pending=false;
 var R=runOf(run.dataset.run);
 function kept(cut){var parts=[];(R?R.conditions:[]).forEach(function(c){var f=c.find.times.filter(function(t){return t<=cut}).length,k=c.crash.times.filter(function(t){return t<=cut}).length;parts.push(c.label+" "+f+" / "+k)});return parts.join(" · ")}
 function apply(){pending=false;var val=+range.value;if(val>=max){run.dataset.cut="";out.textContent=(max/100).toFixed(2)+"h";note.textContent="whole run"}
  else{var cut=val/100;run.dataset.cut=String(cut);out.textContent=cut.toFixed(2)+"h";note.textContent="findings / crashes kept so far: "+kept(cut)}redraw(run)}
 range.addEventListener("input",function(){if(!pending){pending=true;requestAnimationFrame(apply)}});
 function stop(){if(timer)cancelAnimationFrame(timer);timer=null;play.textContent="▶ Replay the run"}
 play.addEventListener("click",function(){if(timer){stop();return}if(+range.value>=max)range.value=0;
  var from=+range.value,start=null,dur=Math.max(3000,(max-from)/max*18000);
  play.textContent="❚❚ Pause";
  var last=-1;
  (function step(ts){if(start==null)start=ts;var p=Math.min(1,(ts-start)/dur),val=Math.round(from+(max-from)*p);
   if(val!==last){last=val;range.value=val;apply()}if(p<1)timer=requestAnimationFrame(step);else stop()})(performance.now())})});
document.querySelectorAll(".ttd").forEach(drawTTD);
document.querySelectorAll(".act").forEach(drawActivity);
document.querySelectorAll(".trace").forEach(drawTrace);
})();
"""
