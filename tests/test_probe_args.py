#!/usr/bin/env python3
"""Probe execution-count CLI behavior."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent.parent
LOADER = importlib.machinery.SourceFileLoader("probe_command", str(ROOT / "bin/probe"))
SPEC = importlib.util.spec_from_loader(LOADER.name, LOADER)
probe = importlib.util.module_from_spec(SPEC)
LOADER.exec_module(probe)


class ProbeArgumentTests(unittest.TestCase):
    def test_s8_requires_a_named_property_kind(self) -> None:
        probe.validate_s8_property("S8", "equivalence")
        probe.validate_s8_property("S8-property", "inverse")
        with self.assertRaisesRegex(ValueError, "S8 testcase requires PROPERTY"):
            probe.validate_s8_property("S8", "")
        with self.assertRaisesRegex(ValueError, "S8 testcase requires PROPERTY"):
            probe.validate_s8_property("S8", "collision")
        probe.validate_s8_property("S7", "")

    def test_s8_property_violation_is_executed_evidence_not_no_exec(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            instance = object.__new__(probe.Probe)
            instance.output = Path(directory) / "property.asan.txt"
            instance.output.write_text(
                "ASAN_RUN_HEADER: sanitizer=asan runs=1\n"
                "PROPERTY VIOLATION: equivalent forms differ\n",
                encoding="utf-8",
            )
            instance.config = SimpleNamespace(runner_crash_patterns=[])
            instance.sanitizer = "asan"
            instance.hypothesis_strategy = "S8"
            instance.header = {"property": "equivalence"}

            self.assertEqual(instance._classify(2), "PROPERTY")
            self.assertNotEqual(instance._classify(0), "PROPERTY")

            instance.output.write_text(
                "ASAN_RUN_HEADER: sanitizer=asan runs=1\n"
                "PROPERTY VIOLATION: equivalent forms differ\n"
                "[run-asan] generic EXECUTION VERIFIED (post-run, rc=1)\n",
                encoding="utf-8",
            )
            self.assertEqual(instance._classify(0), "PROPERTY")

    def test_runner_unavailable_exception_requires_testcase_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            testcase = root / "testcase.py"
            target = root / "target.py"
            output = root / "runner.txt"
            instance = object.__new__(probe.Probe)
            instance.output = output
            instance.exec_testcase = testcase
            instance.sanitizer = "runner"
            instance.config = SimpleNamespace(runner_crash_patterns=["Traceback"])
            instance.hypothesis_strategy = "S8"
            instance.header = {"property": "equivalence"}

            for message in (
                "feature is unavailable in this build",
                "feature is not available in this build",
            ):
                output.write_text(
                    "Traceback (most recent call last):\n"
                    f'  File "{testcase}", line 1, in <module>\n'
                    f"RuntimeError: {message}\n",
                    encoding="utf-8",
                )
                self.assertEqual(instance._classify(1), "NO_EXEC", message)

            output.write_text(
                "Traceback (most recent call last):\n"
                f'  File "{testcase}", line 1, in <module>\n'
                f'  File "{target}", line 2, in parse\n'
                "RuntimeError: feature is unavailable in this build\n",
                encoding="utf-8",
            )
            self.assertEqual(instance._classify(1), "CRASH")

    def test_missing_module_attribute_requires_testcase_provenance(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            testcase = root / "testcase.py"
            target = root / "target.py"
            output = root / "runner.txt"
            instance = object.__new__(probe.Probe)
            instance.output = output
            instance.exec_testcase = testcase
            instance.sanitizer = "runner"
            instance.config = SimpleNamespace(runner_crash_patterns=["Traceback"])
            instance.hypothesis_strategy = "S8"
            instance.header = {"property": "equivalence"}

            output.write_text(
                "Traceback (most recent call last):\n"
                f'  File "{testcase}", line 1, in <module>\n'
                "AttributeError: module 'sample' has no attribute 'FastLoader'\n",
                encoding="utf-8",
            )
            self.assertEqual(instance._classify(1), "NO_EXEC")

            output.write_text(
                "Traceback (most recent call last):\n"
                f'  File "{testcase}", line 1, in <module>\n'
                f'  File "{target}", line 2, in parse\n'
                "AttributeError: module 'sample' has no attribute 'FastLoader'\n",
                encoding="utf-8",
            )
            self.assertEqual(instance._classify(1), "CRASH")

    def test_opaque_browser_input_uses_browser_runner(self) -> None:
        instance = object.__new__(probe.Probe)
        instance.args = SimpleNamespace(mode="auto")
        instance.header = {"mode": ""}
        instance.testcase = Path("testcase.bin")
        instance.config = SimpleNamespace(
            is_browser="1", build_system="mach", runner_args=[],
        )

        self.assertEqual(instance._mode(), "browser")

    def test_script_engine_js_uses_generic_runner_contract(self) -> None:
        instance = object.__new__(probe.Probe)
        instance.args = SimpleNamespace(mode="auto")
        instance.header = {"mode": ""}
        instance.testcase = Path("testcase.js")
        instance.config = SimpleNamespace(
            is_browser="1", build_system="", runner_args=[
                "--input", "{TESTCASE}",
            ],
        )

        self.assertEqual(instance._mode(), "generic")

    def test_opaque_non_browser_input_remains_generic(self) -> None:
        instance = object.__new__(probe.Probe)
        instance.args = SimpleNamespace(mode="auto")
        instance.header = {"mode": ""}
        instance.testcase = Path("testcase.bin")
        instance.config = SimpleNamespace(is_browser="0")

        self.assertEqual(instance._mode(), "generic")

    def test_a_tampered_session_pin_never_falls_back_to_shared_config(self) -> None:
        # probe's no-session fallback reads the shared output/<slug>/target.toml
        # directly. Reaching it on a broken pin would swap the runner and the
        # threat-model gate under a live session without saying so.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / "output" / "sampleproj" / "codex" / "results"
            (results / "scratch-1").mkdir(parents=True)
            shared = results.parents[1] / "target.toml"
            shared.write_text(
                'target = "sampleproj"\n[threat_model]\n'
                'attacker_controls = ["timing"]\n', encoding="utf-8",
            )
            probe.target_config.write_session_env(
                results, str(results), str(root / "target"), "sampleproj",
                "abcd1234", str(results.parent / "logs"),
            )
            probe.target_config.pin_session_config(results, shared)
            testcase = results / "scratch-1" / "testcase.js"
            testcase.write_text("// TARGET: sampleproj\n", encoding="utf-8")
            self.assertEqual(
                ["timing"], probe.load_config(testcase).attacker_controls
            )

            shared.write_text(
                'target = "sampleproj"\n[threat_model]\n'
                'attacker_controls = ["bytes"]\n', encoding="utf-8",
            )
            (results / ".target.toml").write_text(
                'target = "sampleproj"\n[threat_model]\n'
                'attacker_controls = ["race"]\n', encoding="utf-8",
            )
            with self.assertRaisesRegex(
                probe.target_config.PinnedConfigError, "after audit preflight"
            ):
                probe.load_config(testcase)

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


class OpaqueInputHeaderTests(unittest.TestCase):
    """An opaque byte input cannot carry a header, so the fields a
    testcase would declare in one arrive as flags instead."""

    def test_opaque_input_flags_are_accepted(self) -> None:
        args = probe.parse_args(
            ["--hypothesis-id", "H-7", "--harness", "fuzz_api.c",
             "--property", "inverse", "input.bin"])
        self.assertEqual(args.hypothesis_id, "H-7")
        self.assertEqual(args.harness, "fuzz_api.c")
        self.assertEqual(args.property, "inverse")

    def test_they_default_empty_so_a_headered_testcase_is_unaffected(self) -> None:
        args = probe.parse_args(["testcase.html"])
        self.assertEqual(args.hypothesis_id, "")
        self.assertEqual(args.harness, "")
        self.assertEqual(args.property, "")

    def test_the_flag_supplies_the_harness_a_binary_input_cannot_declare(self) -> None:
        # A fuzz artifact is exact bytes: prepending a `HARNESS:` comment would
        # change the input that reproduces the crash.
        self.assertIn("HARNESS", probe.HEADER_RE["harness"].pattern)
        self.assertIn("--harness", probe.HELP)
        self.assertIn("--property", probe.HELP)

    def test_opaque_s8_violation_survives_a_configured_nonzero_success_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            results = root / "output" / "sampleproj" / "codex" / "results"
            logs = results.parent / "logs"
            scratch = results / "scratch-1"
            target.mkdir()
            logs.mkdir(parents=True)
            scratch.mkdir(parents=True)
            driver = target / "driver.py"
            driver.write_text(
                "import pathlib, sys\n"
                "assert pathlib.Path(sys.argv[1]).read_bytes() == b'\\x00oracle\\xff'\n"
                "print('PROPERTY VIOLATION: inverse forms differ')\n"
                "raise SystemExit(1)\n",
                encoding="utf-8",
            )
            shared = results.parents[1] / "target.toml"
            shared.write_text(
                'target = "sampleproj"\nis_browser = "0"\n'
                '[sanitizer]\nenabled = []\n'
                '[runner]\n'
                f'bin = {json.dumps(sys.executable)}\n'
                f'args = [{json.dumps(str(driver))}, "{{TESTCASE}}"]\n'
                'success_codes = [0, 1]\n',
                encoding="utf-8",
            )
            probe.target_config.write_session_env(
                results, str(results), str(target), "sampleproj", "plain",
                str(logs),
            )
            probe.target_config.pin_session_config(results, shared)
            state = results / "state"
            state.mkdir()
            (state / "fixed-strategy").write_text("S8\n", encoding="utf-8")
            (state / "hypotheses.jsonl").write_text(json.dumps({
                "id": "H-7", "agent": "1", "strategy": "S8",
                "status": "INVESTIGATING", "file": "driver.py:main:1",
                "card_id": "WORK-S8",
            }) + "\n", encoding="utf-8")
            testcase = scratch / "input.bin"
            original = b"\x00oracle\xff"
            testcase.write_bytes(original)
            environment = os.environ.copy()
            environment["PROBE_AUTO_ROUTE"] = "0"

            completed = subprocess.run(
                [str(ROOT / "bin/probe"), "--hypothesis-id", "H-7",
                 "--property", "inverse", str(testcase)],
                env=environment, capture_output=True, text=True, check=False,
                timeout=30,
            )

            self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
            self.assertIn("[probe] verdict=PROPERTY", completed.stdout)
            self.assertEqual(testcase.read_bytes(), original)
            run = json.loads((state / "runs.jsonl").read_text().splitlines()[-1])
            self.assertEqual(run["verdict"], "PROPERTY")


if __name__ == "__main__":
    unittest.main()
