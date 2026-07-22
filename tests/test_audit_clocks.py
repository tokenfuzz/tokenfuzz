#!/usr/bin/env python3
"""Audit wall-clock and housekeeping telemetry regressions."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner
import benchmark
import benchmark_runner


class AuditClockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="audit-clocks-")
        self.root = Path(self.temporary.name)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.runtime = SimpleNamespace(
            logs=self.logs,
            index=self.logs / "index.log",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_productive_budget_includes_housekeeping(self) -> None:
        state = audit_runner.BackendState(
            self.runtime, mock.Mock(), started_at=100.0,
            paused_seconds=10, housekeeping_seconds=20,
        )
        with mock.patch.dict(
            os.environ, {"AUDIT_WALL_BUDGET_SECS": "50"}, clear=False,
        ), mock.patch.object(audit_runner.time, "monotonic", return_value=159.0):
            self.assertFalse(audit_runner._productive_wall_exhausted(state))
            self.assertEqual(audit_runner._productive_wall_remaining(state), 1)

        with mock.patch.dict(
            os.environ, {"AUDIT_WALL_BUDGET_SECS": "50"}, clear=False,
        ), mock.patch.object(audit_runner.time, "monotonic", return_value=161.0):
            self.assertTrue(audit_runner._productive_wall_exhausted(state))

    def test_housekeeping_wrapper_records_time_without_changing_work(self) -> None:
        state = audit_runner.BackendState(
            self.runtime, mock.Mock(), started_at=100.0,
        )
        with mock.patch.dict(
            os.environ, {"AUDIT_WALL_BUDGET_SECS": "50"}, clear=False,
        ), mock.patch.object(audit_runner, "post_iteration") as post, \
                mock.patch.object(
                    audit_runner.time, "monotonic", side_effect=[120.0, 132.5],
                ):
            audit_runner._run_post_iteration(state)

        post.assert_called_once_with(self.runtime, deadline=150.0)
        self.assertEqual(state.housekeeping_seconds, 12.5)
        self.assertEqual(float((self.logs / ".housekeeping_secs").read_text()), 12.5)

    def test_cell_effective_wall_keeps_measured_housekeeping(self) -> None:
        path = self.root / "cell" / "cell.json"
        benchmark_runner.write_cell(
            path, "harness", 1, "fixture", self.root / "results",
            100, "done", 2, paused=10, housekeeping=25,
        )
        cell = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(cell["housekeeping_seconds"], 25)
        self.assertEqual(cell["wall_effective_seconds"], 90)
        self.assertEqual(
            benchmark._effective_wall({
                "wall_seconds": 100,
                "paused_seconds": 10,
                "housekeeping_seconds": 25,
            }),
            90,
        )


if __name__ == "__main__":
    unittest.main()
