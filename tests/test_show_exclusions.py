#!/usr/bin/env python3
"""Behavior tests for current result-layout exclusion reporting."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "show-exclusions"


class ShowExclusionsTests(unittest.TestCase):
    def test_current_layout_and_counts_are_reported(self) -> None:
        with tempfile.TemporaryDirectory(prefix="show-exclusions-") as temporary:
            results = Path(temporary) / "results"
            for relative in (
                "crashes/CRASH-001-alpha", "findings/FIND-010-state",
                "crashes-rejected/CRASH-002-null",
                "crashes-rejected/CRASH-003-timeout",
                "fuzz-crashes/FuzzerA/shutdown-noise",
            ):
                (results / relative).mkdir(parents=True)
            (results / "crashes-rejected/CRASH-002-null/.autodiscard").write_text(
                "# Auto-rejected by triage\n# Reason: null-deref\n", encoding="utf-8"
            )
            (results / "crashes-rejected/CRASH-003-timeout/.autodiscard").write_text(
                "  # Auto-rejected by triage\n  # Reason: timeout-only\n", encoding="utf-8"
            )
            (results / "fuzz-crashes/FuzzerA/shutdown-noise/crash-da39").write_text(
                "shutdown noise\n", encoding="utf-8"
            )
            proc = subprocess.run(
                [str(COMMAND), str(results)], capture_output=True, text=True
            )
            output = proc.stdout + proc.stderr
            self.assertEqual(proc.returncode, 0, output)
            for expected in (
                "Active crash candidates", "CRASH-001-alpha", "FIND-010-state",
                "fuzz-crashes/FuzzerA/shutdown-noise/crash-da39",
            ):
                with self.subTest(expected=expected):
                    self.assertIn(expected, output)
            for pattern in (
                r"CRASH-002-null\s+null-deref",
                r"CRASH-003-timeout\s+timeout-only",
                r"active crashes:\s+1", r"confirmed findings:\s+1",
                r"rejected crashes:\s+2", r"fuzz noise moved:\s+1",
            ):
                with self.subTest(pattern=pattern):
                    self.assertRegex(output, pattern)
            self.assertNotIn("VULN-", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
