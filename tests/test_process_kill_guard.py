#!/usr/bin/env python3
"""Regression tests for audit-agent process-name kill guards."""

from __future__ import annotations

import os
import subprocess
import sys
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
GUARDS = ROOT / "lib" / "agent_shell_guards"


class ProcessKillGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        # Unique per run: should the guard ever regress into exec'ing the real
        # tool, the pattern this suite hands it must not match anything but
        # these two processes.
        self.token = f"sampleproj-{os.getpid()}"
        # Both commands carry that name, reproducing the shape in which
        # `pkill -f <target>` from one audit killed a sibling benchmark.
        self.processes = [
            subprocess.Popen([
                sys.executable, "-c", "import time; time.sleep(60)",
                "bin/benchmark", "--target", self.token,
            ]),
            subprocess.Popen([
                sys.executable, "-c", "import time; time.sleep(60)",
                f"build-asan/{self.token}",
            ]),
        ]
        time.sleep(0.1)

    def tearDown(self) -> None:
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
        for process in self.processes:
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    @staticmethod
    def alive(process: subprocess.Popen) -> bool:
        # poll() reaps an exited child. A kill(0) probe would report a killed
        # but unreaped zombie as alive and let the regression pass falsely.
        return process.poll() is None

    def run_guard(self, tool: str, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(GUARDS / tool), *args],
            capture_output=True, text=True, check=False,
        )

    def test_name_based_killers_cannot_touch_matching_sibling_processes(self) -> None:
        cases = (
            ("pkill", "-9", "-f", self.token),
            ("killall", "-9", self.token),
        )
        for tool, *args in cases:
            with self.subTest(tool=tool):
                completed = self.run_guard(tool, *args)
                self.assertEqual(completed.returncode, 2)
                self.assertIn("name-based process killing", completed.stderr)
                self.assertIn("exact PID", completed.stderr)
                self.assertTrue(all(self.alive(process) for process in self.processes))

    def test_guard_does_not_offer_an_environment_bypass(self) -> None:
        environment = os.environ.copy()
        environment["AGENT_WRAPPERS_BYPASS"] = "all pkill killall"
        for tool in ("pkill", "killall"):
            with self.subTest(tool=tool):
                completed = subprocess.run(
                    [str(GUARDS / tool), self.token],
                    env=environment, capture_output=True, text=True, check=False,
                )
                self.assertEqual(completed.returncode, 2)
                self.assertTrue(all(self.alive(process) for process in self.processes))

    def test_guard_never_persists_command_arguments(self) -> None:
        sensitive = "SENSITIVE_EXPANDED_VALUE"
        completed = self.run_guard("pkill", "-9", "-f", sensitive)
        self.assertEqual(completed.returncode, 2)
        self.assertIn("refusing pkill", completed.stderr)
        self.assertNotIn(sensitive, completed.stderr)
        self.assertNotIn("-9", completed.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
