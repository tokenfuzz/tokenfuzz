#!/usr/bin/env python3
"""The cross-backend benchmark result page: data model and rendering."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import benchmark  # noqa: E402
import benchmark_page  # noqa: E402
import severity_receipt  # noqa: E402

START = "2026-01-01T00:00:00+00:00"


def _lanes(reportable: int, rejected: int = 0, pending: int = 0) -> dict:
    return {
        "candidates": reportable + rejected + pending,
        "evidence_complete": reportable + rejected,
        "validated": reportable + rejected,
        "routed": reportable + rejected + pending,
        "reportable": reportable,
        "lanes": {"reportable": reportable, "not-reportable": 0, "pending": pending,
                  "rejected": rejected, "legacy-provisional": 0},
    }


def _condition(name: str, **overrides) -> dict:
    base = {
        "condition": name, "replicates_total": 1, "replicates_done": 1,
        "replicates_provider_limited": 0, "replicates_backend_terminated": 0,
        "wall_median": 10800, "wall_budget_seconds": 10800,
        "unique_finding_clusters": 0, "medium_plus_findings": 0,
        "finding_class_histogram": {}, "unadjudicated_finding_total": 0,
        "finding_total_is_floor": False, "unique_rejected_finding_clusters": 0,
        "rejected_finding_clusters_upper_bound": False,
        "unique_crash_clusters": 0, "medium_plus_bugs": 0,
        "unadjudicated_crash_total": 0, "crash_total_is_floor": False,
        "retained_crash_total": 0, "unique_rejected_crash_clusters": 0,
        "rejected_crash_clusters_upper_bound": False,
        "top_severity_level": "—",
        "validation_waterfall": {"findings": _lanes(0), "crashes": _lanes(0)},
        "input_tokens_total": 1000, "output_tokens_total": 200,
        "cost_usd_total": "3.5", "token_source": "measured", "cost_estimated": False,
        "time_to_first_filed_median": 600, "cells": [],
    }
    base.update(overrides)
    return base


class Fixture:
    """One finished run with two conditions and one shared cluster."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.run = root / "codex" / "20260101-000000"
        cells = self.run / "cells"
        self.harness = cells / "harness-r1"
        self.direct = cells / "model-direct-r1"
        for cell in (self.harness, self.direct):
            (cell / "state").mkdir(parents=True)
            (cell / "logs").mkdir()
        (self.run / "run.json").write_text(json.dumps({
            "runid": "20260101-000000", "target": "sampleproj", "backend": "codex",
            "model": "gpt-5.6-sol", "resolved_effort": "high",
            "agent_security": "sandboxed", "budget_wall": 10800, "replicates": 1,
            "target_sha": "abcdef0123456789", "tokenfuzz_sha": "deadbeefcafe",
        }), encoding="utf-8")
        for cell, cond in ((self.harness, "harness"), (self.direct, "model-direct")):
            (cell / "cell.json").write_text(json.dumps({
                "condition": cond, "replicate": 1, "status": "done",
                "started_at": START, "wall_seconds": 10800,
                "wall_effective_seconds": 10800, "results_dir": str(cell),
                "actual_agents": 3 if cond == "harness" else None,
            }), encoding="utf-8")
        # harness: three findings, one crash; direct: two findings, one shared
        harness = _condition(
            "harness", unique_finding_clusters=3, medium_plus_findings=2,
            finding_class_histogram={"memory-safety": 2, "dos": 1},
            unique_rejected_finding_clusters=1, unique_crash_clusters=1,
            medium_plus_bugs=1, top_severity_level="High",
            validation_waterfall={"findings": _lanes(3, rejected=1), "crashes": _lanes(1)},
            worker_wall_total=32400.0, worker_occupancy_median=0.9,
            worker_occupancy_source="recorded",
            cells=[{"cell": "harness-r1", "condition": "harness", "status": "done",
                    "run_quality": "clean", "wall_effective_seconds": 10800,
                    "actual_agents": 3,
                    "metrics": {"exists": True, "findings": 4, "findings_rejected": 1,
                                "confirmed_crashes": 1, "crashes_rejected": 0,
                                "telemetry": {"lanes": {"S3": {"hypotheses": 4, "productive": 2},
                                                        "S7": {"hypotheses": 2, "productive": 0}}}}}],
        )
        direct = _condition(
            "model-direct", unique_finding_clusters=2, medium_plus_findings=1,
            finding_class_histogram={"memory-safety": 1, "auth": 1},
            wall_median=5400, unadjudicated_finding_total=1,
            validation_waterfall={"findings": _lanes(2, pending=1), "crashes": _lanes(0)},
            cells=[{"cell": "model-direct-r1", "condition": "model-direct",
                    "status": "done", "run_quality": "clean",
                    "wall_effective_seconds": 5400,
                    "metrics": {"exists": True, "findings": 3, "findings_rejected": 0,
                                "confirmed_crashes": 0, "crashes_rejected": 0}}],
        )
        self.report = {
            "bench_dir": str(self.run),
            "run": json.loads((self.run / "run.json").read_text(encoding="utf-8")),
            "severity_scorers": [severity_receipt.SCORER_DECISION_VERSION],
            "conditions": [harness, direct],
            "finding_clusters": [
                {"id": "FCL-1", "class": "memory-safety", "conditions": ["harness"],
                 "members": ["FIND-0001"], "size": 1, "severity_level": "—",
                 "member_severity": {"FIND-0001": {"level": "High", "rank": 3}}},
                {"id": "FCL-2", "class": "memory-safety",
                 "conditions": ["harness", "model-direct"],
                 "members": ["FIND-0002", "FIND-0004"], "size": 2, "severity_level": "—",
                 "member_severity": {"FIND-0002": {"level": "Low", "rank": 1},
                                     "FIND-0004": {"level": "Medium", "rank": 2}}},
                {"id": "FCL-3", "class": "dos", "conditions": ["harness"],
                 "members": ["FIND-0003"], "size": 1, "severity_level": "—",
                 "member_severity": {"FIND-0003": {"level": "Medium", "rank": 2}}},
                {"id": "FCL-4", "class": "auth", "conditions": ["model-direct"],
                 "members": ["FIND-0005"], "size": 1, "severity_level": "—",
                 "member_severity": {"FIND-0005": {"level": "Low", "rank": 1}}},
            ],
            "crash_clusters": [
                {"id": "CL-1", "class": "other", "conditions": ["harness"],
                 "members": ["CRASH-0001"], "size": 1, "primitive": "SEGV",
                 "severity_level": "High", "severity_rank": 3, "severity_score": 7.5,
                 "member_severity": {"CRASH-0001": {"level": "High", "rank": 3}}},
            ],
        }
        (self.run / "report.json").write_text(json.dumps(self.report), encoding="utf-8")
        (self.run / "pool-members.json").write_text(json.dumps({
            "findings": {"FIND-0001": "harness", "FIND-0002": "harness",
                         "FIND-0003": "harness", "FIND-0004": "model-direct",
                         "FIND-0005": "model-direct"},
            "crashes": {"CRASH-0001": "harness"},
            "findings-rejected": {"FIND-REJECTED-0001": "harness"},
        }), encoding="utf-8")
        (self.run / "clusters-findings.json").write_text(json.dumps({"clusters": [
            {"id": "FCL-1", "canonical": "FIND-0001", "members": ["FIND-0001"],
             "class": "memory-safety", "file": "src/app_parse.c", "line": "91",
             "strategy": "S3"},
            {"id": "FCL-2", "canonical": "FIND-0002", "members": ["FIND-0002", "FIND-0004"],
             "class": "memory-safety", "file": "src/app_io.c", "line": "12"},
            {"id": "FCL-3", "canonical": "FIND-0003", "members": ["FIND-0003"],
             "class": "dos", "file": "src/app_alloc.c", "line": "40"},
            {"id": "FCL-4", "canonical": "FIND-0005", "members": ["FIND-0005"],
             "class": "auth", "file": "src/app_auth.c", "line": "7"},
        ]}), encoding="utf-8")
        (self.run / "clusters-crashes.json").write_text(json.dumps({"clusters": [
            {"id": "CL-1", "canonical": "CRASH-0001", "members": ["CRASH-0001"],
             "signature": "child_free child.c:91 -> app_parse parse.c:12"},
        ]}), encoding="utf-8")
        (self.run / "clusters-findings-rejected.json").write_text(json.dumps({"clusters": [
            {"id": "FCL-r1", "canonical": "FIND-REJECTED-0001",
             "members": ["FIND-REJECTED-0001"], "class": "dos",
             "file": "src/app_loop.c", "line": "3", "severity_label": "Low"},
        ]}), encoding="utf-8")
        self._report("pool/findings/FIND-0001", "# FIND-001 — Parser trusts a length field\n")
        self._report("pool/findings/FIND-0002",
                     "<!-- enrich:tldr -->\n- **Bug** — I/O path frees a buffer twice\n")
        self._report("pool/findings/FIND-0003", "# FIND-003: Allocation grows without bound\n")
        self._report("pool/findings/FIND-0005", "## Fields\n")
        self._report("pool/crashes/CRASH-0001", "# CRASH-001-1: SEGV in child_free\n", "REPORT.md")
        self._report("pool/findings-rejected/FIND-REJECTED-0001", "# FIND-009 — Loop\n")
        (self.run / "pool/findings-rejected/FIND-REJECTED-0001/REJECTION.md").write_text(
            "# Rejected\n\nReason: no attacker-controlled path reaches the loop\n",
            encoding="utf-8")
        for cond in ("harness", "model-direct"):
            for kind, basename in (("findings", "FINDING-CLUSTERS"), ("crashes", "CRASH-CLUSTERS"),
                                   ("findings-rejected", "REJECTED-FINDINGS")):
                directory = self.run / "pool" / cond / kind
                directory.mkdir(parents=True)
                (directory / f"{basename}.html").write_text("<p>index</p>", encoding="utf-8")
        for name in ("FIND-0001", "FIND-0002", "FIND-0003"):
            self._report(f"pool/harness/findings/{name}", "# x\n", "report.html")
        self._report("pool/harness/crashes/CRASH-0001", "<p>x</p>", "REPORT.html")
        self._report("pool/model-direct/findings/FIND-0004", "# x\n", "report.html")
        self._report("pool/model-direct/findings/FIND-0005", "# x\n", "report.html")
        # harness state streams: two hypotheses in the wall, one after it
        self._jsonl(self.harness / "state" / "hypotheses.jsonl", [
            {"id": "H-1", "agent": "1", "strategy": "S3-spec", "file": "src/app_parse.c:app_parse:91",
             "hypothesis": "the length field is trusted before the bounds check",
             "guard_gap": "no check between read and use", "input_shape": "a short header",
             "note": "confirmed with a two-byte header", "status": "FIND-001",
             "created_at": "2026-01-01T00:20:00Z", "updated_at": "2026-01-01T00:40:00Z"},
            {"id": "H-2", "agent": "2", "strategy": "s7", "file": "src/app_io.c:app_read:12",
             "hypothesis": "a second read reuses the freed buffer", "status": "REFUTED",
             "created_at": "2026-01-01T01:50:00Z", "updated_at": "2026-01-01T02:10:00Z"},
            {"id": "H-3", "agent": "1", "strategy": "S3", "file": "src/app_alloc.c:app_grow:40",
             "hypothesis": "growth is unbounded", "status": "PENDING",
             "created_at": "2026-01-01T04:00:00Z"},
            {"id": "H-4", "agent": "2", "strategy": "S5", "file": "src/app_io.c:app_close:80",
             "hypothesis": "close runs twice on the error path", "status": "DISCARDED",
             "note": f"build tree at {ROOT}/targets/sampleproj/build-asan is pinned",
             "created_at": "2026-01-01T02:30:00Z", "updated_at": "2026-01-01T03:20:00Z"},
        ])
        self._jsonl(self.harness / "state" / "runs.jsonl", [
            {"id": "RUN-1", "hypothesis_id": "H-1", "verdict": "CLEAN",
             "duration_seconds": 2.5, "created_at": "2026-01-01T00:25:00Z"},
            {"id": "RUN-2", "hypothesis_id": "H-1", "verdict": "CRASH",
             "duration_seconds": 1.0, "created_at": "2026-01-01T00:26:00Z"},
            {"id": "RUN-3", "hypothesis_id": "H-2", "verdict": "PROPERTY",
             "created_at": "2026-01-01T00:27:00Z"},
        ])
        self._jsonl(self.harness / "lineage.jsonl", [
            {"hypothesis_id": "H-1", "artifact": "FIND-001", "status": "FIND-001", "agent": "1"},
            {"hypothesis_id": "H-2", "artifact": None, "status": "REFUTED", "agent": "2"},
        ])
        self._jsonl(self.harness / "state" / "notes.jsonl", [
            {"hypothesis_id": "H-1", "kind": "decision", "text": "drive the parser directly",
             "created_at": "2026-01-01T00:30:00Z"},
        ])
        self._jsonl(self.harness / "state" / "events.jsonl", [
            {"type": "finding_created", "id": "FIND-001", "mtime": "2026-01-01T00:30:00+00:00",
             "first_seen": "2026-01-01T00:45:00+00:00"},
            {"type": "crash_created", "id": "CRASH-001", "mtime": "2026-01-01T00:40:00+00:00",
             "first_seen": "2026-01-01T00:45:00+00:00"},
            {"type": "artifact_admitted", "id": "FIND-001", "kind": "finding",
             "first_seen": "2026-01-01T00:45:00+00:00"},
            {"type": "housekeeping_phase", "phase": "indexes",
             "recorded": "2026-01-01T00:45:00+00:00"},
        ])
        self._jsonl(self.harness / "logs" / "index.jsonl", [
            {"tokens": {"output": 500}},  # session total: no clock, not placed
            {"timestamp": "2026-01-01T00:10:00+00:00", "tokens": {"output": 120}},
            {"timestamp": "2026-01-01T00:20:00+00:00", "tokens": {"output": 80}},
            {"timestamp": "2026-01-01T03:30:00+00:00", "tokens": {"output": 999}},
        ])
        self._jsonl(self.direct / "state" / "events.jsonl", [
            {"type": "finding_created", "id": "FIND-1", "mtime": "2026-01-01T01:00:00+00:00"},
        ])

    def _report(self, relative: str, text: str, name: str = "report.md") -> None:
        directory = self.run / relative
        directory.mkdir(parents=True, exist_ok=True)
        (directory / name).write_text(text, encoding="utf-8")

    @staticmethod
    def _jsonl(path: Path, rows: list[dict]) -> None:
        path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")


class BuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="bench-page-")
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Fixture(Path(self.temporary.name))
        self.data = benchmark_page.build(self.fixture.root)
        self.run = self.data["runs"][0]

    def _cond(self, token: str) -> dict:
        return next(c for c in self.run["conditions"] if c["token"] == token)

    def test_counts_are_labelled_exactly_as_the_ledger_labels_them(self) -> None:
        self.assertEqual(len(self.data["runs"]), 1)
        self.assertFalse(self.run["provisional"])
        harness, direct = self._cond("harness"), self._cond("model-direct")
        self.assertEqual(harness["label"], "tokenfuzz")
        self.assertEqual(direct["label"], "gpt-5.6-sol-direct")
        self.assertEqual(harness["find"]["label"], "3 (2 M+, 2 classes)")
        self.assertEqual(harness["crash"]["label"], "1 (1 M+)")
        self.assertEqual(direct["find"]["label"], "2 (1 M+, 2 classes, 1 unjudged)")
        self.assertEqual(harness["wall_label"], "3.00/3.00h")
        self.assertEqual(direct["wall_label"], "1.50/3.00h")
        self.assertTrue(harness["find"]["href"].endswith("FINDING-CLUSTERS.html"))
        self.assertIn("/pool/harness/", harness["find"]["href"])
        self.assertIn("/pool/model-direct/", direct["find"]["href"])

    def test_clusters_carry_overlap_site_title_and_per_side_severity(self) -> None:
        finds = {c["id"]: c for c in self.run["clusters"]["find"]}
        shared = finds["FCL-2"]
        self.assertEqual(shared["conditions"], ["harness", "model-direct"])
        # the aggregate credits each side for the severity of its own report
        self.assertEqual(shared["severity_by"], {"harness": "Low", "model-direct": "Medium"})
        self.assertEqual(shared["severity"], "Medium")
        self.assertEqual(shared["site"], "src/app_io.c:12")
        # no H1: the reviewer's Bug line stands in as the title
        self.assertEqual(shared["title"], "I/O path frees a buffer twice")
        self.assertEqual(finds["FCL-1"]["title"], "Parser trusts a length field")
        self.assertEqual(finds["FCL-3"]["title"], "Allocation grows without bound")
        self.assertEqual(finds["FCL-4"]["title"], "")
        self.assertTrue(finds["FCL-1"]["href"].endswith("pool/harness/findings/FIND-0001/report.html"))
        # a direct-only cluster links into the direct pool copy
        self.assertTrue(finds["FCL-4"]["href"].endswith("pool/model-direct/findings/FIND-0005/report.html"))
        crash = self.run["clusters"]["crash"][0]
        self.assertEqual(crash["class"], "sanitizer crash")
        self.assertEqual(crash["site"], "child.c:91")
        self.assertEqual(crash["title"], "SEGV in child_free")
        rejected = self.run["rejected"]["find"][0]
        self.assertEqual(rejected["conditions"], ["harness"])
        self.assertIn("no attacker-controlled path", rejected["reason"])

    def test_activity_is_binned_on_the_cell_clock_and_stops_at_its_wall(self) -> None:
        activity = self._cond("harness")["activity"]
        self.assertEqual(activity["bins"], 12)
        # lane tokens are normalised, and the hypothesis after the wall is not activity
        self.assertEqual(sum(activity["hyp"]["S3"]), 1)
        self.assertEqual(sum(activity["hyp"]["S7"]), 1)
        self.assertEqual(activity["hyp"]["S3"][1], 1)
        self.assertEqual(activity["hyp"]["S7"][7], 1)
        self.assertEqual(sum(activity["probe"]["CLEAN"]), 1)
        self.assertEqual(sum(activity["probe"]["CRASH"]), 1)
        self.assertEqual(sum(activity["probe"]["other"]), 1)
        # a filed artifact is placed at its write time, not at the gate's later stamp
        self.assertEqual(activity["filed_find"][2], 1)
        self.assertEqual(activity["filed_crash"][2], 1)
        self.assertEqual(activity["admitted"][3], 1)
        # the session total without a clock is not placed; in-wall records are
        self.assertEqual(sum(activity["out_tokens"]), 200)
        self.assertEqual(activity["agents"], 3)
        direct = self._cond("model-direct")["activity"]
        self.assertEqual(direct["hyp"], {})
        self.assertEqual(sum(direct["filed_find"]), 1)

    def test_trace_carries_each_hypothesis_with_its_probes_and_outcome(self) -> None:
        harness = self._cond("harness")
        self.assertEqual(len(harness["traces"]), 1)
        trace = harness["traces"][0]
        self.assertEqual(trace["cell"], "harness-r1")
        self.assertEqual(trace["agents"], ["1", "2"])
        # the hypothesis after the wall is not part of the run's reasoning
        self.assertEqual([h["id"] for h in trace["hyps"]], ["H-1", "H-2", "H-4"])
        hit, refuted, dropped = trace["hyps"]
        # resolved by teardown after the wall: still open at the wall, so the
        # bar runs to the wall rather than collapsing to its opening instant
        self.assertEqual((dropped["t0"], dropped["t1"]), (2.5, 3.0))
        self.assertEqual(dropped["outcome"], "dropped")
        # the agent's note names the checkout; the page must not
        self.assertNotIn(str(ROOT), dropped["note"])
        self.assertIn("build-asan is pinned", dropped["note"])
        self.assertEqual(hit["outcome"], "hit")
        self.assertEqual(hit["artifact"], "FIND-001")
        self.assertEqual(hit["lane"], "S3")
        self.assertEqual(hit["subsystem"], "src")
        self.assertEqual((hit["t0"], hit["t1"]), (0.3333, 0.6667))
        self.assertEqual([p["verdict"] for p in hit["probes"]], ["CLEAN", "CRASH"])
        self.assertEqual(hit["probes"][0]["s"], 2.5)
        self.assertEqual(hit["notes"][0]["text"], "drive the parser directly")
        self.assertEqual(hit["text"], "the length field is trusted before the bounds check")
        self.assertEqual(refuted["outcome"], "refuted")
        self.assertEqual(refuted["lane"], "S7")
        # a probe filed before the hypothesis still belongs to it, and the bar
        # runs to the later of its last update and its last probe
        self.assertEqual(refuted["probes"][0]["verdict"], "PROPERTY")
        self.assertEqual(trace["summary"]["hit"], 1)
        self.assertEqual(trace["summary"]["refuted"], 1)
        self.assertEqual(trace["summary"]["dropped"], 1)
        self.assertEqual(trace["summary"]["open"], 0)
        # 20, 20, 30 minutes resolved: the middle value
        self.assertEqual(trace["median_minutes"], 20.0)
        self.assertEqual(self._cond("model-direct")["traces"], [])

    def test_clusters_are_stamped_with_their_discovery_hour(self) -> None:
        stamped = {c["id"]: c["t"] for c in self.run["clusters"]["find"]}
        # every cluster the table counts has an hour; the timing builder parks
        # the ones it cannot place at the wall
        self.assertEqual(set(stamped), {"FCL-1", "FCL-2", "FCL-3", "FCL-4"})
        self.assertTrue(all(t is not None for t in stamped.values()))
        self.assertTrue(all(0 <= t <= 3.0 for t in stamped.values()))

    def test_attention_places_hypotheses_and_results_by_subsystem(self) -> None:
        rows = {r["subsystem"]: r for r in self.run["attention"]}
        src = rows["src"]
        self.assertEqual(src["hypotheses"], 3)
        self.assertEqual(src["probes"], 3)
        self.assertEqual(src["hits"], 1)
        self.assertEqual(src["harness"], 3)
        self.assertEqual(src["direct"], 2)
        self.assertEqual(src["rejected"], 1)
        # a crash site with no directory lands in its own row, never in a fake one
        self.assertEqual(rows["(no path)"]["harness"], 1)
        self.assertEqual(benchmark_page._subsystem("libx/y.c:fn:3"), "libx")
        self.assertEqual(benchmark_page._subsystem("y.c:3"), "")
        self.assertEqual(benchmark_page._outcome("CONFIRMED-NO-CRASH", ""), "refuted")
        self.assertEqual(benchmark_page._outcome("PROBED", ""), "open")
        self.assertEqual(benchmark_page._outcome("DISCARDED", "CRASH-001"), "hit")

    def test_lane_yield_and_waterfall_reach_the_condition(self) -> None:
        harness = self._cond("harness")
        self.assertEqual(harness["lanes"]["S3"], {"hypotheses": 4, "productive": 2})
        self.assertEqual(harness["find"]["waterfall"]["candidates"], 4)
        self.assertEqual(harness["find"]["waterfall"]["reportable"], 3)
        self.assertEqual(harness["find"]["waterfall"]["rejected"], 1)
        self.assertEqual(harness["efficiency"]["seat_hours"], 9.0)
        self.assertEqual(harness["efficiency"]["per_seat_hour"], 0.44)
        self.assertEqual(harness["efficiency"]["first_filed_min"], 10.0)

    def test_a_run_without_a_final_report_is_provisional(self) -> None:
        (self.fixture.run / "report.json").unlink()
        data = benchmark_page.build(self.fixture.root)
        run = data["runs"][0]
        self.assertTrue(run["provisional"])
        for cond in run["conditions"]:
            self.assertEqual(cond["find"]["label"], "Pending")
            self.assertEqual(cond["top_severity"], "Pending")
        self.assertEqual(run["clusters"], {"find": [], "crash": []})
        # activity still reads the cells, so a live run shows what it is doing
        harness = next(c for c in run["conditions"] if c["token"] == "harness")
        self.assertIsNotNone(harness["activity"])

    def test_a_run_without_cells_parks_its_counts_at_the_wall(self) -> None:
        # an exported bundle ships no cells/, so nothing can be placed in time;
        # the count is still the table's and must not read as a flat zero curve
        shutil.rmtree(self.fixture.run / "cells")
        run = benchmark_page.build(self.fixture.root)["runs"][0]
        harness = next(c for c in run["conditions"] if c["token"] == "harness")
        self.assertEqual(harness["find"]["times"], [3.0, 3.0, 3.0])
        self.assertTrue(harness["find"]["approx"])
        self.assertIsNone(harness["activity"])

    def test_bins_span_the_longest_repeat(self) -> None:
        meta = json.loads((self.fixture.harness / "cell.json").read_text(encoding="utf-8"))
        meta["wall_seconds"] = 18000
        (self.fixture.harness / "cell.json").write_text(json.dumps(meta), encoding="utf-8")
        run = benchmark_page.build(self.fixture.root)["runs"][0]
        harness = next(c for c in run["conditions"] if c["token"] == "harness")
        self.assertEqual(harness["activity"]["bins"], 20)
        # the hypothesis at 4h is inside this cell's wall now, so it counts
        self.assertEqual(sum(harness["activity"]["hyp"]["S3"]), 2)

    def test_empty_root_builds_no_runs(self) -> None:
        with tempfile.TemporaryDirectory() as empty:
            self.assertEqual(benchmark_page.build(Path(empty))["runs"], [])


class SeverityTests(unittest.TestCase):
    def test_cluster_severity_from_its_field_or_its_members(self) -> None:
        self.assertEqual(benchmark_page._severity_of({"severity_level": "High"}), ("High", 3))
        cluster = {"severity_level": "—", "member_severity": {
            "A": {"level": "Low"}, "B": {"level": "Critical"}}}
        self.assertEqual(benchmark_page._severity_of(cluster), ("Critical", 4))
        self.assertEqual(benchmark_page._severity_of(cluster, {"A"}), ("Low", 1))
        # a side with no scored report of its own is unscored, as the aggregate counts it
        self.assertEqual(benchmark_page._severity_of(cluster, {"Z"}), ("", 0))
        self.assertEqual(benchmark_page._severity_of({}), ("", 0))


class RenderTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="bench-page-render-")
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Fixture(Path(self.temporary.name))

    def test_page_is_self_contained_and_links_into_the_evidence(self) -> None:
        html = benchmark_page.render(benchmark_page.build(self.fixture.root))
        self.assertIn("<title>benchmark-result</title>", html)
        self.assertNotIn("<link ", html)
        self.assertNotIn('<script src=', html)
        self.assertIn("3 (2 M+, 2 classes)", html)
        self.assertIn("gpt-5.6-sol-direct", html)
        self.assertIn("FINDING-CLUSTERS.html", html)
        self.assertIn('data-site="src/app_io.c:12"', html)
        self.assertIn("sanitizer crash", html)
        self.assertIn("Spec vs. implementation", html)
        self.assertIn('id="run-codex-20260101-000000"', html)
        self.assertIn("1 only direct", html)
        self.assertIn("1 both", html)
        self.assertIn("How to read this page", html)
        self.assertIn(".card[hidden]{display:none}", html)
        # leaderboard ranks the harness first here (2 M+ findings + 1 crash vs 1)
        board = html[html.index('<table class="board">'):html.index("</table>", html.index('<table class="board">'))]
        self.assertLess(board.index("tokenfuzz"), board.index("gpt-5.6-sol-direct"))
        # replay, trace, attention, and the drawer are all on the page
        self.assertIn('class="replay" data-wall="3.000"', html)
        self.assertIn('data-cell="harness-r1"', html)
        self.assertIn("1 hit · 1 refuted", html)
        self.assertIn('<table class="attn">', html)
        self.assertIn('id="drawer"', html)
        self.assertIn('data-t="', html)

    def test_relative_rendering_emits_no_absolute_paths(self) -> None:
        with benchmark._render_relative_to(self.fixture.root):
            html = benchmark_page.render(benchmark_page.build(self.fixture.root))
        self.assertNotIn(str(self.fixture.root), html)
        self.assertNotIn(str(ROOT), html)
        self.assertNotIn("file://", html)
        hrefs = re.findall(r'href="([^"]+)"', html)
        self.assertIn("codex/20260101-000000/pool/harness/findings/FINDING-CLUSTERS.html", hrefs)
        for href in hrefs:
            if href.startswith("#"):
                continue
            self.assertTrue((self.fixture.root / href).exists(), href)

    def test_run_metadata_is_escaped(self) -> None:
        metadata = json.loads((self.fixture.run / "run.json").read_text(encoding="utf-8"))
        metadata["model"] = '<img src=x onerror="alert(1)">'
        (self.fixture.run / "run.json").write_text(json.dumps(metadata), encoding="utf-8")
        report = json.loads((self.fixture.run / "report.json").read_text(encoding="utf-8"))
        report["run"]["model"] = metadata["model"]
        (self.fixture.run / "report.json").write_text(json.dumps(report), encoding="utf-8")
        html = benchmark_page.render(benchmark_page.build(self.fixture.root))
        self.assertNotIn('<img src=x', html)
        self.assertIn("&lt;img src=x", html)
        self.assertNotIn("innerHTML", html)

    def test_no_runs_renders_an_empty_notice(self) -> None:
        html = benchmark_page.render({"generated_at": "now", "scorer": "s", "runs": []})
        self.assertIn("No benchmark runs found yet", html)

    @unittest.skipUnless(shutil.which("node"), "node not installed")
    def test_the_page_script_parses(self) -> None:
        # one inline script draws every chart; a syntax slip costs all of them
        # while the static tables still render, so the slip has to be caught here
        html = benchmark_page.render(benchmark_page.build(self.fixture.root))
        script = re.search(r"<script>(.*)</script>", html, re.S).group(1)
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as handle:
            handle.write(script)
            path = handle.name
        self.addCleanup(Path(path).unlink)
        checked = subprocess.run(
            ["node", "--check", path], capture_output=True, text=True, check=False)
        self.assertEqual(checked.returncode, 0, checked.stderr)

    def test_write_places_the_page_beside_the_ledger(self) -> None:
        out = self.fixture.root / "benchmark-result.html"
        benchmark_page.write(self.fixture.root, out)
        self.assertIn("Scoreboard", out.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
