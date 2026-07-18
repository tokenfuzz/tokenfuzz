#!/usr/bin/env python3
"""Time-to-discovery graph.

The invariant under test: the curve is a cumulative discovery line that only
ever climbs, and it lands exactly on the deduplicated count the table reports.
A graph that disagrees with the table beside it is worse than no graph.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import benchmark_graph  # noqa: E402


class ReconcileTests(unittest.TestCase):
    def test_extra_local_dedup_entries_drop_from_the_tail(self) -> None:
        # the clusterers merge a little more than the raw key: table wins
        self.assertEqual(
            benchmark_graph._reconcile([0.1, 0.2, 0.9], 2, 3.0), [0.1, 0.2],
        )

    def test_unresolved_results_land_at_the_end_not_dropped(self) -> None:
        # endpoint must still equal the table's count
        self.assertEqual(
            benchmark_graph._reconcile([0.5], 3, 3.0), [0.5, 3.0, 3.0],
        )

    def test_zero_count_is_empty(self) -> None:
        self.assertEqual(benchmark_graph._reconcile([0.4], 0, 3.0), [])

    def test_curve_length_always_equals_the_table_count(self) -> None:
        for times, count in (([], 4), ([0.2] * 9, 3), ([0.1, 0.2], 2), ([], 0)):
            with self.subTest(times=len(times), count=count):
                out = benchmark_graph._reconcile(list(times), count, 3.0)
                self.assertEqual(len(out), count)
                self.assertEqual(out, sorted(out), "a discovery curve never falls")


class BatchQuantizedTests(unittest.TestCase):
    """A curve must not imply timing it does not have."""

    def test_batch_write_is_detected(self) -> None:
        # the gate validates in batches: many results land on one instant and
        # the curve grows a vertical cliff it has not earned
        times = [1.43, 1.6, 1.78, 1.88] + [2.52] * 9
        self.assertTrue(benchmark_graph._is_batch_quantized(times))

    def test_a_batch_spanning_a_second_still_counts_as_one(self) -> None:
        # 2.519h and 2.520h are the same write, not two discoveries
        self.assertTrue(benchmark_graph._is_batch_quantized(
            [0.1, 0.4] + [2.519, 2.520, 2.521] * 2))

    def test_genuinely_spread_timing_is_not_flagged(self) -> None:
        self.assertFalse(benchmark_graph._is_batch_quantized([0.0, 0.43, 0.47, 0.88]))

    def test_too_few_points_to_judge(self) -> None:
        self.assertFalse(benchmark_graph._is_batch_quantized([1.0, 1.0]))


class CellOriginTests(unittest.TestCase):
    """The curve's zero must be the run's start, not its first artifact."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="origin-")
        self.cell = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_reads_the_audit_log_beside_cell_json(self) -> None:
        # the real layout: audit.log sits next to cell.json, NOT down in the
        # nested results tree — probing beside results/ found nothing and
        # silently rebased every curve onto its own first artifact
        (self.cell / "audit.log").write_text(
            "[01:00:00] Iteration 1 starting: agents=3\n"
            "[04:00:00] Reached productive wall budget: 10800s productive\n",
            encoding="utf-8",
        )
        self.assertIsNotNone(benchmark_graph._cell_start(self.cell))

    def test_started_at_is_authoritative_and_covers_model_direct(self) -> None:
        # model-direct keeps no audit log, so started_at is its only origin
        (self.cell / "cell.json").write_text(
            '{"condition": "model-direct", "started_at": "2026-07-16T04:00:00+00:00"}',
            encoding="utf-8",
        )
        self.assertEqual(
            benchmark_graph._cell_start(self.cell),
            datetime(2026, 7, 16, 4, 0, tzinfo=timezone.utc).timestamp(),
        )

    def test_no_origin_is_admitted_not_invented(self) -> None:
        self.assertIsNone(benchmark_graph._cell_start(self.cell))

    def test_crash_filing_clock_overrides_copied_evidence_mtimes(self) -> None:
        crash = self.cell / "CRASH-001"
        crash.mkdir()
        (crash / "testcase.bin").write_bytes(b"old source bytes")
        filed = "2026-07-18T12:34:56+00:00"
        (crash / ".crash-created-at").write_text(filed + "\n", encoding="utf-8")
        self.assertEqual(
            benchmark_graph._artifact_time(crash),
            datetime.fromisoformat(filed).timestamp(),
        )

    def test_exported_crash_filing_clock_is_read_from_audit_provenance(self) -> None:
        crash = self.cell / "CRASH-EXPORTED" / ".audit"
        crash.mkdir(parents=True)
        filed = "2026-07-18T12:34:56+00:00"
        (crash / ".crash-created-at").write_text(filed + "\n", encoding="utf-8")
        self.assertEqual(
            benchmark_graph._artifact_time(crash.parent),
            datetime.fromisoformat(filed).timestamp(),
        )


class CrashIdentityTests(unittest.TestCase):
    """Identity must survive pooling, which renames every directory."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sig-")
        self.dir = Path(self.temporary.name) / "CRASH-001-agent-name"
        self.dir.mkdir(parents=True)
        self.addCleanup(self.temporary.cleanup)

    def test_falls_back_to_sanitizer_evidence(self) -> None:
        # a valid bundle whose stack lives only in sanitizer.txt — the evidence
        # the real crash clusterer keys on
        (self.dir / "REPORT.md").write_text("# Crash\n\nNo stack here.\n")
        (self.dir / "sanitizer.txt").write_text(
            "ERROR: AddressSanitizer: heap-use-after-free\n"
            "    #0 0x1 in xmlFree parser.c:120\n"
            "    #1 0x2 in xmlParseDoc parser.c:200\n",
        )
        sig = benchmark_graph._signature(self.dir, "crash")
        self.assertIsNotNone(sig)
        self.assertNotIn("CRASH-001-agent-name", str(sig),
                         "a name-based key cannot join across pooling")

    def test_unidentifiable_crash_is_none_not_a_directory_name(self) -> None:
        # pooling renames CRASH-001-agent-name to CRASH-0001, so a name key
        # never joins; admit the unknown instead of faking a join
        (self.dir / "REPORT.md").write_text("# Crash\n\nNo stack anywhere.\n")
        self.assertIsNone(benchmark_graph._signature(self.dir, "crash"))


class ClusterMembershipTimingTests(unittest.TestCase):
    """Timestamps follow the clusterer's real membership, not a sorted tail."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cluster-time-")
        self.run = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def _crash(self, name: str, frame: str) -> None:
        d = self.run / "pool" / "crashes" / name
        d.mkdir(parents=True)
        (d / "REPORT.md").write_text(
            f"ERROR: AddressSanitizer: heap-use-after-free\n"
            f"    #0 0x1 in {frame}\n", encoding="utf-8")

    def test_each_cluster_takes_its_earliest_member(self) -> None:
        # two members of ONE fuzzy cluster at 0.1/0.2 and another at 0.9: the
        # honest curve is [0.1, 0.9]. Truncating the sorted list to the cluster
        # count would answer [0.1, 0.2] and silently misplace the second step.
        self._crash("CRASH-0001", "a_fn a.c:1")
        self._crash("CRASH-0002", "b_fn b.c:2")
        self._crash("CRASH-0003", "c_fn c.c:3")
        (self.run / "clusters-crashes.json").write_text(json.dumps({"clusters": [
            {"id": "CL-a", "members": ["CRASH-0001", "CRASH-0002"]},
            {"id": "CL-b", "members": ["CRASH-0003"]},
        ]}), encoding="utf-8")
        members = {"crashes": {"CRASH-0001": "harness", "CRASH-0002": "harness",
                               "CRASH-0003": "harness"}}
        index = {"crash": {
            benchmark_graph._signature(self.run / "pool" / "crashes" / "CRASH-0001", "crash"): 0.1,
            benchmark_graph._signature(self.run / "pool" / "crashes" / "CRASH-0002", "crash"): 0.2,
            benchmark_graph._signature(self.run / "pool" / "crashes" / "CRASH-0003", "crash"): 0.9,
        }}
        times, approx = benchmark_graph._cluster_times(
            self.run, "harness", "crash", False, index, members, 3.0)
        self.assertEqual(times, [0.1, 0.9])
        self.assertFalse(approx)

    def test_unplaceable_cluster_is_marked_approximate(self) -> None:
        self._crash("CRASH-0001", "a_fn a.c:1")
        (self.run / "clusters-crashes.json").write_text(json.dumps({"clusters": [
            {"id": "CL-a", "members": ["CRASH-0001"]}]}), encoding="utf-8")
        times, approx = benchmark_graph._cluster_times(
            self.run, "harness", "crash", False, {"crash": {}},
            {"crashes": {"CRASH-0001": "harness"}}, 3.0)
        self.assertEqual(times, [3.0])   # parked at the end, never dropped
        self.assertTrue(approx)

    def test_other_conditions_do_not_leak_into_a_curve(self) -> None:
        self._crash("CRASH-0001", "a_fn a.c:1")
        (self.run / "clusters-crashes.json").write_text(json.dumps({"clusters": [
            {"id": "CL-a", "members": ["CRASH-0001"]}]}), encoding="utf-8")
        times, _ = benchmark_graph._cluster_times(
            self.run, "harness", "crash", False, {"crash": {}},
            {"crashes": {"CRASH-0001": "model-direct"}}, 3.0)
        self.assertEqual(times, [])


class RejectedApproximationTests(unittest.TestCase):
    """Missing rejected cluster times must never be presented as exact."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="rejected-time-")
        self.root = Path(self.temporary.name)
        self.run = self.root / "codex" / "run"
        cell = self.run / "cells" / "harness-r1"
        cell.mkdir(parents=True)
        self.addCleanup(self.temporary.cleanup)
        (self.run / "run.json").write_text(json.dumps({
            "target": "sample", "target_sha": "abc1234", "backend": "codex",
            "model": "gpt-5.6-sol", "tokenfuzz_sha": "deadbeef",
        }), encoding="utf-8")
        (self.run / "pool-members.json").write_text("{}", encoding="utf-8")
        (cell / "cell.json").write_text(json.dumps({
            "condition": "harness", "started_at": "2026-01-01T00:00:00+00:00",
        }), encoding="utf-8")

    def _series(self, upper_bound: bool = False) -> dict:
        (self.run / "report.json").write_text(json.dumps({"conditions": [{
            "condition": "harness", "replicates_done": 1, "wall_median": 10800,
            "unique_finding_clusters": 0,
            "unique_rejected_finding_clusters": 2,
            "rejected_finding_clusters_upper_bound": upper_bound,
        }]}), encoding="utf-8")
        return benchmark_graph.build(self.root)["series"][0]["find"]

    def test_model_name_flows_into_the_series(self) -> None:
        # the graph labels each row by the model that ran it, not the backend,
        # so the recorded model must reach the series the renderer reads
        self._series()
        self.assertEqual(
            benchmark_graph.build(self.root)["series"][0]["model"], "gpt-5.6-sol")

    def test_same_target_at_different_revisions_gets_separate_rows(self) -> None:
        self._series()
        metadata = json.loads((self.run / "run.json").read_text(encoding="utf-8"))
        metadata["target_sha"] = "abcdef0111111111"
        (self.run / "run.json").write_text(json.dumps(metadata), encoding="utf-8")
        other = self.root / "claude" / "other-run"
        shutil.copytree(self.run, other)
        metadata = json.loads((other / "run.json").read_text(encoding="utf-8"))
        metadata["target_sha"] = "abcdef0222222222"
        (other / "run.json").write_text(json.dumps(metadata), encoding="utf-8")
        data = benchmark_graph.build(self.root)
        self.assertEqual(data["target_groups"], [
            {"target": "sample", "target_sha": "abcdef0111111111"},
            {"target": "sample", "target_sha": "abcdef0222222222"},
        ])
        self.assertEqual(
            {row["target_sha"] for row in data["series"]},
            {"abcdef0111111111", "abcdef0222222222"},
        )

    def test_rejected_count_mismatch_marks_timing_approximate(self) -> None:
        # Historical reports have no upper-bound bit. The count/cluster mismatch
        # alone still proves the padded wall timestamps are approximate.
        series = self._series()
        self.assertEqual(series["rejected_times"], [3.0, 3.0])
        self.assertTrue(series["rejected_upper_bound"])
        self.assertTrue(series["approx_timing"])

    def test_upper_bound_state_reaches_the_graph(self) -> None:
        series = self._series(upper_bound=True)
        self.assertTrue(series["rejected_upper_bound"])
        self.assertTrue(series["approx_timing"])


class RenderTests(unittest.TestCase):
    def _data(self) -> dict:
        return {
            "target_groups": [{"target": "sample", "target_sha": "abc1234"}],
            "series": [{
                "target": "sample", "target_sha": "abc1234", "backend": "codex",
                "model": "gpt-5.6-sol",
                "condition": "harness", "run_id": "20260101-000000",
                "version": "deadbee", "replicates": 2, "wall_h": 3.0,
                "find": {"accepted": 2, "rejected": 5, "medium_plus": 1,
                         "accepted_times": [0.5, 1.5], "rejected_times": [0.2, 0.3],
                         "rejected_upper_bound": True},
                "crash": {"accepted": 0, "rejected": 0, "medium_plus": 0,
                          "accepted_times": [], "rejected_times": []},
            }],
        }

    def test_empty_data_renders_nothing(self) -> None:
        self.assertEqual(benchmark_graph.render({"series": []}), "")

    def test_row_label_uses_the_model_name(self) -> None:
        # the row is named by the model that ran it; the backend is only the
        # fallback for runs recorded before the model was captured
        html = benchmark_graph.render(self._data())
        self.assertIn('"model":"gpt-5.6-sol"', html)
        self.assertIn("r.model||r.backend", html)

    def test_curve_runs_flat_to_the_cell_wall(self) -> None:
        # a cell that stops finding early kept auditing to its wall; the curve
        # must carry the count flat to wall_h, not stop at the last discovery
        html = benchmark_graph.render(self._data())
        self.assertIn("[[r.wall_h,end[1]]]", html)

    def test_points_are_interactive(self) -> None:
        # every point carries a hover tooltip; the fragment ships the tooltip
        # container, the hover wiring, and the reader-facing hint
        html = benchmark_graph.render(self._data())
        self.assertIn("ttd-tip", html)
        self.assertIn("mouseenter", html)
        self.assertIn("Hover any point", html)

    def test_metadata_is_inserted_with_text_content_only(self) -> None:
        data = self._data()
        data["series"][0]["model"] = '<img src=x onerror="alert(1)">'
        data["target_groups"][0]["target"] = "<script>alert(2)</script>"
        data["series"][0]["target"] = "<script>alert(2)</script>"
        html = benchmark_graph.render(data)
        self.assertNotIn("innerHTML", html)
        self.assertIn("tip.replaceChildren", html)
        self.assertIn("heading.textContent=title", html)
        self.assertNotIn("<script>alert(2)</script>", html)

    def test_all_supported_backends_have_distinct_colours(self) -> None:
        html = benchmark_graph.render(self._data())
        backends = ("codex", "claude", "gemini", "grok", "oss")
        colours = dict(re.findall(
            rf'({"|".join(backends)}):"(#[0-9a-fA-F]{{6}})"', html
        ))
        self.assertEqual(set(colours), set(backends))
        self.assertEqual(len(set(colours.values())), len(backends))

    def test_fragment_is_self_contained(self) -> None:
        html = benchmark_graph.render(self._data())
        self.assertIn('id="ttd-data"', html)
        self.assertIn('id="ttd-rows"', html)
        # No external assets — the report is opened straight off disk, often
        # offline. (The SVG namespace URI is not a fetch, so match asset loads.)
        for fetch in ('src="http', "src='http", 'href="http', "href='http",
                      "@import", "fetch("):
            with self.subTest(fetch=fetch):
                self.assertNotIn(fetch, html)
        self.assertIn('"rejected_upper_bound":true', html)
        self.assertNotIn("% kept", html)
        # the rejected magnitude lives in the chip and the crosstab; the old
        # per-row rejected mini-strip was redundant and is gone
        self.assertNotIn("REJECTED BY THE GATE", html)

    def test_inject_places_the_graph_after_the_table(self) -> None:
        page = (
            "<body>\n<h1>x</h1>\n<div class=\"table-wrap\">\n<table>\n"
            "<tr><td>1</td></tr>\n</table>\n</div>\n<p>after</p>\n</body>"
        )
        out = benchmark_graph.inject(page, ROOT / "does-not-exist")
        # no runs -> unchanged, never a broken page
        self.assertEqual(out, page)

    def test_inject_is_a_noop_without_the_table_marker(self) -> None:
        self.assertEqual(benchmark_graph.inject("<body>x</body>", ROOT), "<body>x</body>")


if __name__ == "__main__":
    unittest.main()
