#!/usr/bin/env python3
"""End-to-end coverage for feature-sentinel routing to sibling builds."""

from __future__ import annotations

import os
import json
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "bin" / "probe"
ROUTES = ROOT / "lib" / "build_routes.py"


class ProbeAutoRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="probe-route-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.results = self.root / "results"
        self.logs = self.root / "logs"
        for path in (
            self.target / "build-asan" / "bin",
            self.target / "build-asan-jit" / "bin",
            self.target / "build-asan-empty" / "bin",
            self.results / "scratch-1", self.results / "crashes",
            self.results / "crashes-rejected", self.results / "findings", self.logs,
        ):
            path.mkdir(parents=True)
        self.canonical = self.target / "build-asan" / "bin" / "myrunner"
        self.sibling = self.target / "build-asan-jit" / "bin" / "myrunner"
        self.write_runner(self.canonical, False)
        self.write_runner(self.sibling, True)
        (self.target / "target.toml").write_text(
            'target = "testproject"\n'
            'upstream_url = "https://example.invalid/testproject"\n'
            'build_system = "make"\n'
            'asan_bin = "build-asan/bin/myrunner"\n'
            'is_browser = "0"\n'
            '[threat_model]\nattacker_controls = ["bytes"]\n'
            '[sanitizer]\nenabled = ["asan"]\n',
            encoding="utf-8",
        )
        (self.results / ".session-env").write_text(
            f'export RESULTS_DIR="{self.results}"\n'
            f'export TARGET_ROOT="{self.target}"\n'
            'export TARGET_SLUG="testproject"\n',
            encoding="utf-8",
        )
        self.testcase = self.results / "scratch-1" / "tc.txt"
        self.testcase.write_text(
            "// TARGET: src/pcre2_jit_compile.c:compile:42\n"
            "// HYPOTHESIS-ID: H-route\n// CATEGORY: state\n// MODE: generic\n",
            encoding="utf-8",
        )
        self.env = os.environ.copy()
        self.env.update(
            RESULTS_DIR=str(self.results), TARGET_ROOT=str(self.target),
            TARGET_SLUG="testproject", LOGDIR=str(self.logs),
            ASAN_GENERIC_BIN=str(self.canonical), PROBE_SANITIZER="asan",
            LLM_DECIDE_DISABLE="1",
        )
        self.env.pop("AUDIT_BUILD_SUFFIX", None)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_runner(self, path: Path, succeeds: bool) -> None:
        if succeeds:
            lines = "print('myrunner v1.0 (JIT enabled)')\nprint('OK: pattern executed')\n"
        else:
            lines = (
                "print('myrunner v1.0')\n"
                "print('FAIL: No just-in-time compiler support')\nraise SystemExit(1)\n"
            )
        path.write_text(f"#!{sys.executable}\n{lines}", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def route_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(ROUTES), *args], capture_output=True, text=True
        )

    def run_probe(self, *args: str, **env) -> subprocess.CompletedProcess:
        command_env = self.env.copy()
        command_env.update(env)
        return subprocess.run(
            [str(PROBE), *args, str(self.testcase)], capture_output=True, text=True, env=command_env
        )

    def test_an_exec_fail_names_its_class_and_repair(self) -> None:
        # A program that rejects its command line is a route problem, not an
        # input problem; probe says which, and the run row keeps it.
        self.canonical.write_text(
            f"#!{sys.executable}\nimport sys\n"
            "print('usage: myrunner [--jit] <file>', file=sys.stderr)\nraise SystemExit(2)\n",
            encoding="utf-8",
        )
        for sibling in (self.target / "build-asan-jit", self.target / "build-asan-empty"):
            shutil.rmtree(sibling)
        proc = self.run_probe()
        output = proc.stdout + proc.stderr
        self.assertIn("[probe] verdict=EXEC_FAIL", output)
        self.assertIn("[probe] EXEC_FAIL class=usage:", output)
        self.assertIn("[runner].args", output)
        runs = (self.results / "state" / "runs.jsonl").read_text(encoding="utf-8")
        self.assertIn('"reason": "child-rc=2 class=usage"', runs)

    def test_sentinel_and_enumeration(self) -> None:
        output = self.root / "canonical.out"
        proc = subprocess.run([str(self.canonical)], capture_output=True, text=True)
        output.write_text(proc.stdout + proc.stderr, encoding="utf-8")
        self.assertEqual(self.route_cli("sentinel", str(output)).returncode, 0)
        proc = self.route_cli("enumerate", str(self.target), str(self.canonical))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("build-asan-jit/bin/myrunner", proc.stdout)
        self.assertNotIn("build-asan-empty", proc.stdout)
        self.assertNotIn("build-asan/bin/myrunner", proc.stdout)

    def test_enumeration_skips_unready_managed_configuration(self) -> None:
        unready = self.target / "build-asan+cfg-wide-deadbeef00" / "bin" / "myrunner"
        unready.parent.mkdir(parents=True)
        self.write_runner(unready, True)
        proc = self.route_cli("enumerate", str(self.target), str(self.canonical))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn(str(unready), proc.stdout)

    def test_probe_routes_and_caches_the_working_sibling(self) -> None:
        proc = self.run_probe()
        output = proc.stdout + proc.stderr
        self.assertRegex(output, r"(?m)^\[probe\] ROUTED: ")
        self.assertIn("build-asan-jit/bin/myrunner", output)
        cache = self.results / "build-routes.jsonl"
        self.assertGreater(cache.stat().st_size, 0)
        proc = self.route_cli(
            "lookup", str(self.results), "file:src/pcre2_jit_compile.c"
        )
        self.assertIn("build-asan-jit/bin/myrunner", proc.stdout)

    def test_disable_switch_and_route_miss(self) -> None:
        proc = self.run_probe(PROBE_AUTO_ROUTE="0")
        self.assertNotIn("ROUTED", proc.stdout + proc.stderr)
        cache = self.results / "build-routes.jsonl"
        if cache.exists():
            cache.unlink()
        self.write_runner(self.sibling, False)
        proc = self.run_probe(PROBE_AUTO_ROUTE="1")
        output = proc.stdout + proc.stderr
        self.assertIn("ROUTE_MISS", output)
        self.assertIsNone(__import__("re").search(r"(?m)^\[probe\] ROUTED:", output))

    def test_raw_input_uses_structured_hypothesis_without_changing_bytes(self) -> None:
        original = b"\x00raw\xffinput\n"
        self.testcase.write_bytes(original)
        state = self.results / "state"
        state.mkdir()
        (state / "hypotheses.jsonl").write_text(json.dumps({
            "id": "H-raw",
            "agent": "2",
            "card_id": "WORK-raw",
            "file": "src/decoder.c:decode:42",
            "status": "INVESTIGATING",
        }) + "\n", encoding="utf-8")
        self.write_runner(self.canonical, True)

        proc = self.run_probe("--hypothesis-id", "H-raw", PROBE_AUTO_ROUTE="0")

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(self.testcase.read_bytes(), original)
        runs = [json.loads(line) for line in (state / "runs.jsonl").read_text().splitlines()]
        self.assertEqual(len(runs), 1)
        self.assertEqual(runs[0]["hypothesis_id"], "H-raw")
        self.assertEqual(runs[0]["card_id"], "WORK-raw")
        self.assertEqual(runs[0]["verdict"], "CLEAN")

    def recorded_run(self) -> dict:
        state = self.results / "state"
        runs = [
            json.loads(line)
            for line in (state / "runs.jsonl").read_text().splitlines()
        ]
        self.assertEqual(len(runs), 1)
        return runs[0]

    def prepare_hypothesis(self) -> None:
        state = self.results / "state"
        state.mkdir(parents=True, exist_ok=True)
        (state / "hypotheses.jsonl").write_text(json.dumps({
            "id": "H-route", "agent": "1", "card_id": "WORK-route",
            "file": "src/pcre2_jit_compile.c:compile:42",
            "status": "INVESTIGATING",
        }) + "\n", encoding="utf-8")

    def test_recorded_duration_covers_the_execution_that_produced_the_verdict(self) -> None:
        """A run count cannot see inside a harness; the wall it took can.

        `_auto_route` re-runs the whole command once per candidate build and
        the recorded verdict comes from that later run, so timing only the
        canonical attempt would undercount exactly the multi-build probes the
        measurement exists to reveal.
        """
        self.prepare_hypothesis()
        # Only the routed leg is slow, so its cost cannot be confused with
        # interpreter start-up on the canonical attempt.
        self.write_runner(self.canonical, False)
        self.write_runner(self.sibling, True)
        text = self.sibling.read_text(encoding="utf-8")
        self.sibling.write_text(
            text.replace("print(", "import time; time.sleep(1.5); print(", 1),
            encoding="utf-8",
        )

        proc = self.run_probe()
        self.assertRegex(proc.stdout + proc.stderr, r"(?m)^\[probe\] ROUTED: ")
        duration = self.recorded_run()["duration_seconds"]
        self.assertGreaterEqual(
            duration, 1.4,
            "duration must span the routed execution the verdict came from",
        )

    def test_an_unrouted_probe_still_records_its_duration(self) -> None:
        self.prepare_hypothesis()
        self.write_runner(self.canonical, True)
        text = self.canonical.read_text(encoding="utf-8")
        self.canonical.write_text(
            text.replace("print(", "import time; time.sleep(0.3); print(", 1),
            encoding="utf-8",
        )

        proc = self.run_probe(PROBE_AUTO_ROUTE="0")

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertGreaterEqual(self.recorded_run()["duration_seconds"], 0.3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
