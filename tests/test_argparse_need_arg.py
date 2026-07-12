#!/usr/bin/env python3
"""Regression coverage for missing values on Python CLI options."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class MissingArgumentTests(unittest.TestCase):
    CASES = {
        "coverage-summary": (
            "--slug", "--depth", "--min-edges", "--format", "--out",
            "--results-dir",
        ),
        "hits": (
            "--testcase", "--want", "--mode", "--timeout", "--save",
            "--log", "--slug", "--agent",
        ),
        "audit-recon": (
            "--target", "--target-path", "--backend", "--concurrency",
            "--out", "--report", "--timeout", "--validate", "--scope",
            "--path", "--recon-lookback",
        ),
        "validate-finding": (
            "--finding", "--target-path", "--backend", "--model", "--gate",
            "--output", "--timeout",
        ),
    }

    def run_tool(self, tool: str, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(ROOT / "bin" / tool), *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

    def test_value_bearing_options_fail_with_a_usage_error(self) -> None:
        for tool, flags in self.CASES.items():
            for flag in flags:
                with self.subTest(tool=tool, flag=flag):
                    proc = self.run_tool(tool, flag)
                    self.assertEqual(proc.returncode, 2, proc.stdout)
                    normalized = proc.stdout.replace("-", "_")
                    self.assertTrue(
                        f"{flag} requires a value" in proc.stdout
                        or (
                            "expected one argument" in proc.stdout
                            and flag[2:].replace("-", "_") in normalized
                        ),
                        proc.stdout,
                    )

    def test_coverage_depth_must_be_positive(self) -> None:
        proc = self.run_tool("coverage-summary", "--depth", "0")
        self.assertEqual(proc.returncode, 2, proc.stdout)
        self.assertIn("--depth must be a positive integer", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
