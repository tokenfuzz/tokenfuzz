"""lib/telemetry.py: where the wall went, read passively from a results tree.

Every number here is asserted against a fixture built line by line, so a
change in what a row means fails the test rather than moving a median.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import benchmark  # noqa: E402
import telemetry  # noqa: E402


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")


class TelemetryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="telemetry-")
        self.root = Path(self.temporary.name)
        self.results = self.root / "results"
        self.logs = self.root / "logs"
        (self.results / "state").mkdir(parents=True)
        self.logs.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _index(self, rows: list[dict]) -> None:
        _write_jsonl(self.logs / "index.jsonl", rows)

    def test_session_spans_come_from_recorded_stamps(self) -> None:
        self._index([
            {"role": "model-preflight", "timestamp": "2026-08-28T10:00:00+00:00"},
            {"role": "decision:work_rerank", "timestamp": "2026-08-28T10:00:30+00:00"},
            {"role": "analysis", "agent": 1, "iteration": 1,
             "timestamp": "2026-08-28T10:20:00+00:00",
             "started": "2026-08-28T10:01:00+00:00", "ended": "2026-08-28T10:20:00+00:00"},
            {"role": "reproduce", "agent": 2, "iteration": 1,
             "timestamp": "2026-08-28T10:11:00+00:00",
             "started": "2026-08-28T10:01:00Z", "ended": "2026-08-28T10:11:00Z"},
        ])
        spans = telemetry.session_spans(self.results)
        self.assertEqual([s["seconds"] for s in spans], [1140.0, 600.0])
        self.assertEqual({s["source"] for s in spans}, {"recorded"})
        occupancy = telemetry.occupancy(self.results)
        self.assertEqual(occupancy, {
            "sessions": 2, "occupied_seconds": 1740.0, "source": "recorded",
        })

    def test_session_spans_fall_back_to_file_clocks_for_old_rows(self) -> None:
        raw = self.logs / ".raw"
        raw.mkdir()
        prompt = raw / "session_20260828_100100_1_deep_investigation-1.prompt.md"
        log = raw / "session_20260828_100100_1_deep_investigation-1.log.raw"
        prompt.write_text("prompt", encoding="utf-8")
        log.write_text("transcript", encoding="utf-8")
        os.utime(prompt, (1_000_000, 1_000_000))
        os.utime(log, (1_000_000 + 900, 1_000_000 + 900))
        self._index([
            {"role": "analysis", "agent": 1, "raw_log": str(log),
             "timestamp": "2026-08-28T10:16:00+00:00"},
            # A row with no clock at all is skipped, not counted as zero.
            {"role": "analysis", "agent": 2, "timestamp": "2026-08-28T10:16:00+00:00"},
        ])
        occupancy = telemetry.occupancy(self.results)
        self.assertEqual(occupancy["sessions"], 1)
        self.assertEqual(occupancy["occupied_seconds"], 900.0)
        self.assertEqual(occupancy["source"], "file_mtime")

    def test_occupancy_is_none_not_zero_without_sessions(self) -> None:
        self._index([{"role": "model-preflight", "timestamp": "2026-08-28T10:00:00+00:00"}])
        self.assertEqual(
            telemetry.occupancy(self.results),
            {"sessions": 0, "occupied_seconds": None, "source": None},
        )

    def test_housekeeping_prefers_structured_rows_and_sums_blocked_time(self) -> None:
        _write_jsonl(self.results / "state" / "events.jsonl", [
            {"type": "housekeeping_phase", "iteration": 1, "phase": "crash_triage",
             "seconds": 10.0, "blocked": True},
            {"type": "housekeeping_phase", "iteration": 1, "phase": "result_gates",
             "seconds": 100.0, "blocked": True},
            {"type": "housekeeping_phase", "iteration": 2, "phase": "result_gates",
             "seconds": 50.0, "blocked": False},
            {"type": "finding_created", "id": "FIND-001", "signature": ["a"]},
        ])
        (self.logs / "index.log").write_text(
            "[00:00:01] Housekeeping phases: crash_triage=999.0s\n", encoding="utf-8",
        )
        house = telemetry.housekeeping(self.results)
        self.assertEqual(house["source"], "events")
        self.assertEqual(house["phases"], {"crash_triage": 10.0, "result_gates": 150.0})
        self.assertEqual(house["blocked_seconds"], 110.0)
        self.assertEqual(house["total_seconds"], 160.0)
        self.assertEqual(house["iterations"], 2)

    def test_housekeeping_falls_back_to_index_log_lines(self) -> None:
        (self.logs / "index.log").write_text(
            "[19:53:13] Housekeeping: crashes promoted=0\n"
            "[19:53:13] Housekeeping phases: crash_triage=0.0s "
            "result_gates=765.0s(finding_gate=765.0s cluster_expand=0.0s) "
            "indexes=4.3s orphan_enforce=0.9s corpus_promote=0.0s\n"
            "[20:42:27] Housekeeping phases: crash_triage=1.0s result_gates=624.9s\n",
            encoding="utf-8",
        )
        house = telemetry.housekeeping(self.results)
        self.assertEqual(house["source"], "index_log")
        # Sub-phases inside the parentheses belong to result_gates and are not
        # summed again.
        self.assertEqual(house["phases"]["result_gates"], 1389.9)
        self.assertEqual(house["phases"]["crash_triage"], 1.0)
        self.assertAlmostEqual(house["total_seconds"], 1396.1, places=3)
        self.assertEqual(house["blocked_seconds"], house["total_seconds"])
        self.assertEqual(house["iterations"], 2)

    def test_housekeeping_without_any_source_is_none(self) -> None:
        house = telemetry.housekeeping(self.results)
        self.assertIsNone(house["blocked_seconds"])
        self.assertIsNone(house["source"])
        self.assertEqual(house["phases"], {})

    def test_time_to_first_is_relative_to_the_runs_first_clock(self) -> None:
        self._index([
            {"role": "model-preflight", "timestamp": "2026-08-28T10:00:00+00:00"},
        ])
        _write_jsonl(self.results / "state" / "runs.jsonl", [
            {"id": "RUN-1", "verdict": "CLEAN", "created_at": "2026-08-28T10:05:00Z"},
            {"id": "RUN-2", "verdict": "CRASH", "created_at": "2026-08-28T10:30:00Z"},
            {"id": "RUN-3", "verdict": "crash", "created_at": "2026-08-28T10:20:00Z"},
        ])
        _write_jsonl(self.results / "state" / "events.jsonl", [
            {"type": "finding_created", "id": "FIND-001", "signature": ["x"],
             "first_seen": "2026-08-28T11:00:00+00:00",
             "mtime": "2026-08-28T10:04:00+00:00"},
            {"type": "crash_created", "id": "CRASH-001-1", "signature": [],
             "first_seen": "2026-08-28T11:00:00+00:00",
             "mtime": "2026-08-28T10:03:00+00:00"},
            {"type": "artifact_admitted", "id": "FIND-001", "kind": "finding",
             "first_seen": "2026-08-28T12:00:00+00:00"},
        ])
        ttf = telemetry.time_to_first(self.results)
        self.assertEqual(ttf["run_start"], "2026-08-28T10:00:00+00:00")
        self.assertEqual(ttf["filed_seconds"], 180.0)
        self.assertEqual(ttf["crash_confirmed_seconds"], 1200.0)
        self.assertEqual(ttf["admitted_seconds"], 7200.0)

    def test_time_to_first_is_none_without_a_start_or_an_event(self) -> None:
        ttf = telemetry.time_to_first(self.results)
        self.assertEqual(ttf, {
            "run_start": None, "filed_seconds": None,
            "crash_confirmed_seconds": None, "admitted_seconds": None,
        })

    def test_lane_stats_use_the_latest_row_per_hypothesis(self) -> None:
        _write_jsonl(self.results / "state" / "hypotheses.jsonl", [
            {"id": "H-1", "strategy": "S3", "status": "PENDING", "agent": "1"},
            {"id": "H-1", "strategy": "S3", "status": "FIND-001", "agent": "1"},
            {"id": "H-2", "strategy": "s7-fuzz", "status": "DISCARDED", "agent": "2"},
            {"id": "H-3", "strategy": "", "status": "CRASH-001-1", "agent": "2"},
        ])
        self.assertEqual(telemetry.lane_stats(self.results), {
            "S3": {"hypotheses": 1, "productive": 1},
            "S7": {"hypotheses": 1, "productive": 0},
            "other": {"hypotheses": 1, "productive": 1},
        })

    def test_execution_verdicts_and_exec_fail_share(self) -> None:
        _write_jsonl(self.results / "state" / "runs.jsonl", [
            {"verdict": "CLEAN"}, {"verdict": "EXEC_FAIL"}, {"verdict": "EXEC_FAIL"},
            {"verdict": "CRASH"}, {},
        ])
        execution = telemetry.execution_verdicts(self.results)
        self.assertEqual(execution["counts"], {
            "CLEAN": 1, "CRASH": 1, "EXEC_FAIL": 2, "UNKNOWN": 1,
        })
        self.assertEqual(execution["total"], 5)
        self.assertEqual(execution["exec_fail_share"], 0.4)
        self.assertIsNone(telemetry.execution_verdicts(self.root)["exec_fail_share"])

    def test_duplicate_roots_count_signatures_filed_by_two_agents(self) -> None:
        _write_jsonl(self.results / "state" / "hypotheses.jsonl", [
            {"id": "H-1", "strategy": "S3", "status": "FIND-001", "agent": "1"},
            {"id": "H-2", "strategy": "S3", "status": "FIND-002", "agent": "2"},
            {"id": "H-3", "strategy": "S5", "status": "FIND-003", "agent": "2"},
        ])
        _write_jsonl(self.results / "state" / "events.jsonl", [
            {"type": "finding_created", "id": "FIND-001", "signature": ["k", "a.c", "1"]},
            {"type": "finding_created", "id": "FIND-002", "signature": ["k", "a.c", "1"]},
            {"type": "finding_created", "id": "FIND-003", "signature": ["k", "b.c", "9"]},
            {"type": "finding_created", "id": "FIND-004", "signature": []},
        ])
        self.assertEqual(telemetry.duplicate_roots(self.results), {
            "signatures": 2, "multi_agent": 1, "rate": 0.5,
        })

    def test_lineage_joins_card_hypothesis_testcase_and_artifact(self) -> None:
        _write_jsonl(self.results / "state" / "hypotheses.jsonl", [
            {"id": "H-1", "card_id": "WORK-a", "strategy": "S3", "status": "PENDING",
             "agent": "1"},
            {"id": "H-1", "card_id": "WORK-a", "strategy": "S3", "status": "FIND-001",
             "agent": "1"},
            {"id": "H-2", "card_id": "WORK-b", "strategy": "S7", "status": "DISCARDED",
             "agent": "2"},
        ])
        _write_jsonl(self.results / "state" / "runs.jsonl", [
            {"hypothesis_id": "H-1", "testcase_sha1": "aaa"},
            {"hypothesis_id": "H-1", "testcase_sha1": "aaa"},
            {"hypothesis_id": "H-1", "testcase_sha1": "bbb"},
        ])
        _write_jsonl(self.results / "state" / "events.jsonl", [
            {"type": "finding_created", "id": "FIND-001", "signature": ["k", "a.c", "1"]},
        ])
        rows = telemetry.lineage(self.results)
        self.assertEqual(rows, [
            {"card_id": "WORK-a", "hypothesis_id": "H-1", "agent": "1", "strategy": "S3",
             "status": "FIND-001", "testcases": ["aaa", "bbb"], "artifact": "FIND-001",
             "signature": ["k", "a.c", "1"]},
            {"card_id": "WORK-b", "hypothesis_id": "H-2", "agent": "2", "strategy": "S7",
             "status": "DISCARDED", "testcases": [], "artifact": None, "signature": []},
        ])
        target = self.root / "cell" / "lineage.jsonl"
        self.assertEqual(telemetry.write_lineage(self.results, target), 2)
        self.assertEqual(len(target.read_text(encoding="utf-8").splitlines()), 2)

    def test_summary_has_every_block_even_on_an_empty_tree(self) -> None:
        summary = telemetry.summary(self.results)
        self.assertEqual(
            set(summary),
            {"occupancy", "housekeeping", "time_to_first", "lanes", "execution",
             "duplicate_roots", "lineage_rows"},
        )
        self.assertEqual(summary["lineage_rows"], 0)


class StampTests(unittest.TestCase):
    """The writers telemetry reads: phase rows and artifact disposition stamps."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="telemetry-stamps-")
        self.root = Path(self.temporary.name)
        self.results = self.root / "results"
        (self.results / "state").mkdir(parents=True)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_phase_spans_write_structured_rows_beside_the_log_line(self) -> None:
        import audit_runner
        from types import SimpleNamespace
        from unittest import mock

        runtime = SimpleNamespace(results=self.results, logs=self.root / "logs")
        spans: list[str] = []
        records: list[dict] = []
        with mock.patch.object(audit_runner.time, "monotonic", side_effect=[10.0, 12.5]):
            with audit_runner._phase_span(spans, "crash_triage", records=records):
                pass
        self.assertEqual(spans, ["crash_triage=2.5s"])
        self.assertEqual(records, [{"phase": "crash_triage", "seconds": 2.5}])
        with mock.patch.object(audit_runner, "index_log") as index_log:
            audit_runner._log_phase_spans(runtime, spans, records=records, iteration=3)
        index_log.assert_called_once_with(runtime, "Housekeeping phases: crash_triage=2.5s")
        rows = [
            json.loads(line) for line in
            (self.results / "state" / "events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(
            {k: rows[0][k] for k in ("type", "iteration", "phase", "seconds", "blocked")},
            {"type": "housekeeping_phase", "iteration": 3, "phase": "crash_triage",
             "seconds": 2.5, "blocked": True},
        )
        self.assertEqual(telemetry.housekeeping(self.results)["blocked_seconds"], 2.5)

    def test_artifact_events_stamp_crashes_and_terminal_receipts_once(self) -> None:
        import triage

        def artifact(lane: str, name: str, state: str | None) -> None:
            directory = self.results / lane / name
            directory.mkdir(parents=True)
            if state is not None:
                (directory / "validation.json").write_text(
                    json.dumps({"state": state}), encoding="utf-8",
                )

        artifact("crashes", "CRASH-001-1", "reportable")
        artifact("crashes", "CRASH-002-1", "pending")
        artifact("findings", "FIND-001", "reportable")
        artifact("findings", "FIND-002", None)
        artifact("findings-rejected", "FIND-003", "rejected")
        artifact("crashes-rejected", "CRASH-003-1", "rejected")
        self.assertEqual(triage.record_artifact_events(self.results), 7)
        rows = [
            json.loads(line) for line in
            (self.results / "state" / "events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        by_kind = {}
        for row in rows:
            by_kind.setdefault(row["type"], []).append(row["id"])
        self.assertEqual(sorted(by_kind["crash_created"]),
                         ["CRASH-001-1", "CRASH-002-1", "CRASH-003-1"])
        self.assertEqual(sorted(by_kind["artifact_admitted"]), ["CRASH-001-1", "FIND-001"])
        self.assertEqual(sorted(by_kind["artifact_rejected"]), ["CRASH-003-1", "FIND-003"])
        # A second pass is idempotent; a later state change gets its own row
        # while the first stamp stays where it was.
        self.assertEqual(triage.record_artifact_events(self.results), 0)
        (self.results / "findings" / "FIND-002" / "validation.json").write_text(
            json.dumps({"state": "reportable"}), encoding="utf-8",
        )
        self.assertEqual(triage.record_artifact_events(self.results), 1)
        # Without a run clock the offsets are None, never zero.
        self.assertIsNone(telemetry.time_to_first(self.results)["filed_seconds"])
        _write_jsonl(self.root / "logs" / "index.jsonl", [
            {"role": "model-preflight", "timestamp": "2020-01-01T00:00:00+00:00"},
        ])
        ttf = telemetry.time_to_first(self.results)
        self.assertIsNotNone(ttf["filed_seconds"])
        self.assertIsNotNone(ttf["admitted_seconds"])


class EfficiencyAggregationTests(unittest.TestCase):
    """benchmark._efficiency_summary and the rendered table."""

    @staticmethod
    def _cell(**telemetry_block: object) -> dict:
        return {
            "condition": "harness", "wall_effective_seconds": 1000, "actual_agents": 2,
            "metrics": {
                "telemetry": telemetry_block,
                "validation_waterfall": {
                    "crashes": {"candidates": 2}, "findings": {"candidates": 3},
                },
            },
        }

    def test_medians_over_recorded_cells_and_none_otherwise(self) -> None:
        cells = [
            self._cell(
                occupancy={"occupied_seconds": 1500.0, "source": "recorded"},
                housekeeping={"blocked_seconds": 100.0, "source": "events",
                              "phases": {"crash_triage": 10.0, "result_gates": 40.0}},
                time_to_first={"filed_seconds": 60.0, "crash_confirmed_seconds": None,
                               "admitted_seconds": 600.0},
                execution={"exec_fail_share": 0.25},
                duplicate_roots={"rate": 0.0},
            ),
            self._cell(),  # an old cell: contributes nothing, not zeros
        ]
        summary = benchmark._efficiency_summary(cells)
        self.assertEqual(summary["worker_occupancy_median"], 0.75)
        self.assertEqual(summary["worker_occupancy_source"], "recorded")
        self.assertEqual(summary["housekeeping_blocked_fraction_median"], 0.1)
        self.assertEqual(summary["review_seconds_per_artifact_median"], 10.0)
        self.assertEqual(summary["time_to_first_filed_median"], 60.0)
        self.assertIsNone(summary["time_to_first_crash_confirmed_median"])
        self.assertEqual(summary["time_to_first_admitted_median"], 600.0)
        self.assertEqual(summary["exec_fail_share_median"], 0.25)
        self.assertEqual(summary["duplicate_root_rate_median"], 0.0)
        self.assertTrue(all(value is None for key, value in
                            benchmark._efficiency_summary([self._cell()]).items()
                            if key != "worker_occupancy_source"))

    def test_occupancy_needs_seats_and_is_capped_at_one(self) -> None:
        cell = self._cell(occupancy={"occupied_seconds": 5000.0, "source": "file_mtime"})
        self.assertEqual(benchmark._efficiency_summary([cell])["worker_occupancy_median"], 1.0)
        self.assertEqual(
            benchmark._efficiency_summary([cell])["worker_occupancy_source"], "file_mtime",
        )
        cell.pop("actual_agents")
        self.assertIsNone(benchmark._efficiency_summary([cell])["worker_occupancy_median"])

    def test_table_renders_only_when_something_was_recorded(self) -> None:
        empty = [{"condition": "harness"}, {"condition": "model-direct"}]
        self.assertEqual(benchmark._render_efficiency(empty, "codex"), [])
        recorded = [{
            "condition": "harness", "worker_occupancy_median": 0.702,
            "worker_occupancy_source": "file_mtime",
            "housekeeping_blocked_fraction_median": 0.143,
            "review_seconds_per_artifact_median": 51.7,
            "time_to_first_filed_median": 303.0,
            "time_to_first_crash_confirmed_median": None,
            "time_to_first_admitted_median": None,
            "exec_fail_share_median": 0.4321, "duplicate_root_rate_median": 0.0,
            "unique_finding_clusters": 3, "unique_crash_clusters": 1,
            "worker_wall_median": 36000.0, "cost_usd_total": 136.8,
        }, {"condition": "model-direct"}]
        lines = benchmark._render_efficiency(recorded, "codex")
        row = next(line for line in lines if "70%†" in line)
        self.assertIn("| 14% | 52s | 5m | — | — | 43% | 0% | 0.40 | $34 |", row)
        direct = next(
            line for line in lines if "| — | — | — | — | — | — | — | — | — | — |" in line
        )
        self.assertIn("direct", direct.lower())


if __name__ == "__main__":
    unittest.main()
