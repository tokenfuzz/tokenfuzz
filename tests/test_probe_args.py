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
from unittest import mock


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
            self.assertEqual(instance._classify(124), "TIMEOUT")

            instance.output.write_text(
                "ASAN_RUN_HEADER: sanitizer=asan runs=1\n"
                "PROPERTY VIOLATION: equivalent forms differ\n"
                "[run-asan] generic EXECUTION VERIFIED (post-run, rc=1)\n",
                encoding="utf-8",
            )
            self.assertEqual(instance._classify(0), "PROPERTY")

    def test_a_run_that_returned_is_exec_fail_not_a_dead_harness(self) -> None:
        """A command that ran and returned uncleanly is EXEC_FAIL, not NO_EXEC.

        NO_EXEC sends the agent to repair the harness or testcase header, so
        collapsing the two spends sessions on a harness that works: on measured
        5h cells 133 of 150 NO_EXEC rows had in fact got this far. The marker
        proves only that the command returned, so a loader failure lands here
        too and the verdict alone never names the repair.
        """
        with tempfile.TemporaryDirectory() as directory:
            instance = object.__new__(probe.Probe)
            instance.output = Path(directory) / "run.txt"
            instance.exec_testcase = Path(directory) / "testcase.mp4"
            instance.config = SimpleNamespace(runner_crash_patterns=[])
            instance.sanitizer = "asan"
            instance.hypothesis_strategy = "S7"
            instance.header = {"property": ""}

            reached = (
                "ASAN_RUN_HEADER: sanitizer=asan runs=1 mode=generic\n"
                "[run-asan] generic EXECUTION INCONCLUSIVE (post-run, rc=69)\n"
                "[run-sanitizer-multi] EXECUTION_RATE: 1/1\n"
                "[run-sanitizer-multi] SUCCESS_RATE: 0/1\n"
            )
            instance.output.write_text(reached, encoding="utf-8")
            self.assertEqual(instance._classify(69), "EXEC_FAIL")

            # The testcase itself declared a missing prerequisite (the S7/S8
            # contract): nothing ran, whatever the runner's marker says.
            instance.output.write_text(
                "ASAN_RUN_HEADER: sanitizer=asan runs=1 mode=generic\n"
                "NO_EXEC: optional decoder module is not built\n"
                "[run-asan] generic EXECUTION INCONCLUSIVE (post-run, rc=2)\n"
                "[run-sanitizer-multi] EXECUTION_RATE: 1/1\n"
                "[run-sanitizer-multi] SUCCESS_RATE: 0/1\n",
                encoding="utf-8",
            )
            self.assertEqual(instance._classify(2), "NO_EXEC")

            # No repetition reached the target: still a harness problem.
            instance.output.write_text(
                "ASAN_RUN_HEADER: sanitizer=asan runs=1 mode=generic\n"
                "[run-sanitizer-multi] EXECUTION_RATE: 0/1\n"
                "[run-sanitizer-multi] SUCCESS_RATE: 0/1\n",
                encoding="utf-8",
            )
            self.assertEqual(instance._classify(2), "NO_EXEC")

            # A loader failure reaches the same verdict: the marker records an
            # execution attempt, not that the target's entry point ran, so
            # EXEC_FAIL must not be read as "the input was rejected".
            instance.output.write_text(
                "ASAN_RUN_HEADER: sanitizer=asan runs=1 mode=generic\n"
                "Permission denied\n"
                "[run-asan] generic EXECUTION INCONCLUSIVE (post-run, rc=126)\n"
                "[run-sanitizer-multi] EXECUTION_RATE: 1/1\n",
                encoding="utf-8",
            )
            self.assertEqual(instance._classify(126), "EXEC_FAIL")

            # A crash still outranks both.
            instance.output.write_text(
                reached + "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
                encoding="utf-8",
            )
            self.assertEqual(instance._classify(1), "CRASH")

    def test_timeout_uses_reserved_returncode_not_testcase_output(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            instance = object.__new__(probe.Probe)
            instance.output = Path(directory) / "runner.txt"
            instance.output.write_text(
                "ASAN_RUN_HEADER: sanitizer=runner runs=1\n"
                "[run-asan] generic runner timed out after 15s\n",
                encoding="utf-8",
            )
            instance.exec_testcase = Path(directory) / "testcase.kts"
            instance.config = SimpleNamespace(runner_crash_patterns=[])
            instance.sanitizer = "runner"
            instance.hypothesis_strategy = "S5"
            instance.header = {"property": ""}

            self.assertEqual(instance._classify(124), "TIMEOUT")
            self.assertEqual(instance._classify(2), "NO_EXEC")

            instance.output.write_text(
                "[run-sanitizer-multi] SUCCESS_RATE: 1/2\n",
                encoding="utf-8",
            )
            self.assertEqual(instance._classify(124), "TIMEOUT")

            instance.output.write_text(
                "java.lang.OutOfMemoryError: requested array size exceeds VM limit\n",
                encoding="utf-8",
            )
            self.assertEqual(instance._classify(124), "CRASH")

            # Repetition reports the deadline it reached alongside the runs that
            # crashed. The diagnostic is what a later probe can reproduce, so it
            # still decides the verdict; the rate stays on the artifact.
            instance.output.write_text(
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
                "CRASH_RATE: 1/2\n"
                "[run-sanitizer-multi] TIMEOUTS: 1/2 runs reached the deadline\n",
                encoding="utf-8",
            )
            self.assertEqual(instance._classify(124), "CRASH")

            instance.output.unlink()
            self.assertEqual(instance._classify(124), "TIMEOUT")

    def test_runner_diagnostic_note_preserves_compact_amplification(self) -> None:
        instance = object.__new__(probe.Probe)
        instance.header = {"hypothesis": "H-RESOURCE"}
        instance.agent = "2"
        instance.card = "WORK-PARSER"
        instance.mode = "generic"
        instance.testcase = Path("testcase.job")
        instance.output = Path("runner.txt")
        instance.sanitizer = "runner"
        instance.environment = {"SANITIZER_RUNS": "1"}
        instance.elapsed_seconds = 1.0
        commands = []
        instance._state_command = lambda *args: commands.append(args)

        with mock.patch.object(Path, "read_bytes", return_value=b"input"):
            instance._record_state("CRASH")

        note = next(args for args in commands if args[0] == "add-note")
        text = note[note.index("--text") + 1]
        self.assertIn("distinct resource-effect hypothesis", text)
        self.assertIn("target's size ceiling", text)
        self.assertIn("ordinary OOM remains noise", text)

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
