#!/usr/bin/env python3
"""Behavior tests for fuzz-crash lead filtering and bounds."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "triage-fuzz-crashes"
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner  # noqa: E402
import fuzz_campaign  # noqa: E402
import fuzz_triage  # noqa: E402
import prompt  # noqa: E402


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

    def test_audit_refresh_is_in_process_current_and_fail_open(self) -> None:
        with tempfile.TemporaryDirectory(prefix="triage-fuzz-direct-") as temporary:
            results = Path(temporary) / "results"
            results.mkdir()
            runtime = SimpleNamespace(
                results=results,
                index=Path(temporary) / "index.log",
            )

            with mock.patch.object(
                audit_runner.subprocess, "run",
                side_effect=AssertionError("fuzz triage spawned a process"),
            ):
                self.assertTrue(audit_runner.refresh_fuzz_leads(runtime))
            leads = results / "fuzz-leads.md"
            self.assertIn("run a fuzz target first", leads.read_text(encoding="utf-8"))
            self.assertEqual(runtime.index.read_text(encoding="utf-8"), "")

            artifact = results / "fuzz-crashes" / "Parser" / "crash-new"
            artifact.parent.mkdir(parents=True)
            artifact.write_text("input\n", encoding="utf-8")
            self.assertTrue(audit_runner.refresh_fuzz_leads(runtime))
            self.assertIn("## Parser / crash-new", leads.read_text(encoding="utf-8"))
            self.assertIn("[triage] wrote ", runtime.index.read_text(encoding="utf-8"))

            artifact.unlink()
            self.assertTrue(audit_runner.refresh_fuzz_leads(runtime))
            self.assertNotIn("## Parser / crash-new", leads.read_text(encoding="utf-8"))

            with mock.patch.object(
                fuzz_triage, "update_fuzz_leads",
                side_effect=RuntimeError("synthetic failure"),
            ):
                self.assertFalse(audit_runner.refresh_fuzz_leads(runtime))
            log = runtime.index.read_text(encoding="utf-8")
            self.assertIn("RuntimeError: synthetic failure", log)
            self.assertIn("WARN: triage-fuzz-crashes failed rc=1", log)

    def test_unreplayed_campaign_artifacts_are_leads_and_replayed_ones_are_not(self) -> None:
        # `bin/fuzz run` writes under fuzz/artifacts/<harness>/, not the
        # legacy fuzz-crashes/ root, so its artifacts never became leads. One
        # the campaign already replayed through probe must not become one.
        with tempfile.TemporaryDirectory(prefix="triage-fuzz-campaign-") as temporary:
            results = Path(temporary) / "results"
            artifacts = results / "fuzz" / "artifacts" / "fuzz_sample"
            artifacts.mkdir(parents=True)
            (artifacts / "crash-replayed").write_bytes(b"a")
            (artifacts / "crash-pending").write_bytes(b"b")
            fuzz_campaign.save_states(results, {
                "fuzz_sample": fuzz_campaign.HarnessState(
                    name="fuzz_sample", binary="/bin/fuzz_sample",
                    seen_artifacts=["crash-replayed"]),
            })

            returncode, message = fuzz_triage.update_fuzz_leads(results, 20)
            self.assertEqual(returncode, 0, message)
            self.assertIn("1 leads", message)
            text = (results / "fuzz-leads.md").read_text(encoding="utf-8")
            self.assertIn("## fuzz_sample / crash-pending", text)
            self.assertIn("fuzz/artifacts/fuzz_sample/crash-pending", text)
            self.assertIn("bin/fuzz run", text)
            self.assertNotIn("crash-replayed", text)
            self.assertFalse(prompt.fuzz_leads_empty(results))

            fuzz_campaign.save_states(results, {
                "fuzz_sample": fuzz_campaign.HarnessState(
                    name="fuzz_sample", binary="/bin/fuzz_sample",
                    seen_artifacts=["crash-pending", "crash-replayed"]),
            })
            fuzz_triage.update_fuzz_leads(results, 20)
            # An index with nothing left to replay reads as no lead, so an
            # idle slot is not launched on it.
            self.assertTrue(prompt.fuzz_leads_empty(results))

    def test_write_failure_preserves_the_previous_index(self) -> None:
        with tempfile.TemporaryDirectory(prefix="triage-fuzz-write-") as temporary:
            results = Path(temporary) / "results"
            (results / "fuzz-crashes").mkdir(parents=True)
            leads = results / "fuzz-leads.md"
            leads.write_text("previous index\n", encoding="utf-8")

            with mock.patch.object(
                fuzz_triage, "atomic_write", side_effect=OSError("disk full"),
            ):
                returncode, message = fuzz_triage.update_fuzz_leads(results, 20)

            self.assertEqual(returncode, 1)
            self.assertIn("failed to write", message)
            self.assertIn("disk full", message)
            self.assertEqual(leads.read_text(encoding="utf-8"), "previous index\n")


if __name__ == "__main__":
    unittest.main(verbosity=2)
