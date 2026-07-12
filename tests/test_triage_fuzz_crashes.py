#!/usr/bin/env python3
"""Behavior tests for fuzz-crash lead filtering and bounds."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from typing import Optional


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "triage-fuzz-crashes"


class TriageFuzzCrashTests(unittest.TestCase):
    def run_triage(self, results: Path, limit: Optional[str] = None) -> subprocess.CompletedProcess:
        args = [str(COMMAND), str(results)]
        if limit is not None:
            args.append(limit)
        return subprocess.run(args, capture_output=True, text=True)

    def test_no_run_marker_and_filtered_bounded_leads(self) -> None:
        with tempfile.TemporaryDirectory(prefix="triage-fuzz-") as temporary:
            results = Path(temporary) / "results"
            results.mkdir()
            leads = results / "fuzz-leads.md"

            proc = self.run_triage(results)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(leads.is_file())
            self.assertIn("# Fuzz Crash Leads", leads.read_text(encoding="utf-8"))
            self.assertIn("run a fuzz target first", leads.read_text(encoding="utf-8"))

            parser_a = results / "fuzz-crashes" / "ParserA"
            noise = results / "fuzz-crashes" / "ParserB" / "shutdown-noise"
            parser_a.mkdir(parents=True)
            noise.mkdir(parents=True)
            older = parser_a / "timeout-old"
            newer = parser_a / "crash-new"
            older.write_text("older input\n", encoding="utf-8")
            newer.write_text("newer input\n", encoding="utf-8")
            (parser_a / "oom-empty").touch()
            (noise / "crash-noise").write_text("noise\n", encoding="utf-8")
            old_time = datetime(2026, 1, 1, 1, 1).timestamp()
            new_time = datetime(2026, 2, 2, 2, 2).timestamp()
            os.utime(str(older), (old_time, old_time))
            os.utime(str(newer), (new_time, new_time))

            proc = self.run_triage(results, "1")
            output = proc.stdout + proc.stderr
            self.assertEqual(proc.returncode, 0, output)
            self.assertIn("1 leads", output)
            text = leads.read_text(encoding="utf-8")
            self.assertIn("## ParserA / crash-new", text)
            self.assertNotIn("timeout-old", text)
            self.assertNotIn("oom-empty", text)
            self.assertNotIn("crash-noise", text)
            self.assertIn("FUZZER=ParserA bin/run-asan fuzz-repro", text)

            proc = self.run_triage(results, "0")
            self.assertIn("0 leads", proc.stdout + proc.stderr)
            text = leads.read_text(encoding="utf-8")
            self.assertNotRegex(text, r"(?m)^## ")
            self.assertIn("No non-noise fuzz crashes found", text)

            proc = self.run_triage(results, "invalid")
            self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
            self.assertIn("max_leads must be a non-negative integer", proc.stdout + proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
