#!/usr/bin/env python3
"""Probe execution-count CLI behavior."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
LOADER = importlib.machinery.SourceFileLoader("probe_command", str(ROOT / "bin/probe"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
probe = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(probe)


class ProbeArgumentTests(unittest.TestCase):
    def test_explicit_sanitizer_runs_are_recorded_as_executed(self) -> None:
        args = probe.parse_args(["--sanitizer-runs", "17", "testcase.bin"])
        self.assertEqual(probe.sanitizer_run_count(args, {}), 17)

    def test_confirm_preserves_the_five_run_contract(self) -> None:
        args = probe.parse_args(["--confirm", "testcase.bin"])
        self.assertEqual(probe.sanitizer_run_count(args, {"SANITIZER_RUNS": "99"}), 5)

    def test_explicit_sanitizer_runs_must_be_positive(self) -> None:
        with self.assertRaisesRegex(ValueError, "positive integer"):
            probe.parse_args(["--sanitizer-runs", "0", "testcase.bin"])

    def test_probe_records_the_counts_completed_by_every_routed_runner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            instance = object.__new__(probe.Probe)
            instance.actual_runs_path = Path(directory) / "actual-runs"
            instance.environment = {"SANITIZER_RUNS": "9"}
            instance.actual_runs_path.write_text(
                "0\n2\n3\npartial\n", encoding="utf-8"
            )

            self.assertEqual(instance._actual_sanitizer_runs(), 5)
            self.assertFalse(instance.actual_runs_path.exists())

    def test_malformed_run_records_do_not_inflate_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            instance = object.__new__(probe.Probe)
            instance.actual_runs_path = Path(directory) / "actual-runs"
            instance.environment = {"SANITIZER_RUNS": "9"}
            instance.actual_runs_path.write_text("partial\n", encoding="utf-8")

            self.assertEqual(instance._actual_sanitizer_runs(), 0)
            self.assertFalse(instance.actual_runs_path.exists())

    def test_uninstrumented_modes_keep_the_requested_run_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            instance = object.__new__(probe.Probe)
            instance.actual_runs_path = Path(directory) / "missing-actual-runs"
            instance.environment = {"SANITIZER_RUNS": "4"}

            self.assertEqual(instance._actual_sanitizer_runs(), 4)


if __name__ == "__main__":
    unittest.main()
