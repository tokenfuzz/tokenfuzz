#!/usr/bin/env python3
"""Read-only digest coverage for structured probe run history."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "probe-history"


class ProbeHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="probe-history-")
        self.results = Path(self.temporary.name) / "results"
        (self.results / "state").mkdir(parents=True)
        (self.results / "scratch-1").mkdir()
        (self.results / "scratch-2").mkdir()
        self.first = self.results / "scratch-1" / "altsvc-expire-size-3.bin"
        self.renamed = self.results / "scratch-1" / "altsvc-expire-size-3-renamed.bin"
        self.other = self.results / "scratch-2" / "version_string_1.bin"
        self.first.write_bytes(b"GET / HTTP/1.1\r\n")
        self.renamed.write_bytes(self.first.read_bytes())
        self.other.write_text("different testcase\n")
        self.first_sha1 = hashlib.sha1(self.first.read_bytes()).hexdigest()
        self.other_sha1 = hashlib.sha1(self.other.read_bytes()).hexdigest()
        rows = [
            self.row("RUN-aaaa000001", "1", "H-altsvc", "PATCH-001", self.first,
                     self.first_sha1, "NO_EXEC", 1, "2026-05-11T14:13:00Z"),
            self.row("RUN-aaaa000002", "1", "H-altsvc", "PATCH-001", self.first,
                     self.first_sha1, "CRASH", 1, "2026-05-11T14:18:00Z"),
            self.row("RUN-aaaa000003", "1", "H-altsvc", "PATCH-001", self.first,
                     self.first_sha1, "CRASH", 5, "2026-05-11T14:21:00Z"),
            self.row("RUN-aaaa000004", "3", "H-altsvc", "PATCH-001", self.renamed,
                     self.first_sha1, "CRASH", 5, "2026-05-11T15:04:00Z"),
            self.row("RUN-bbbb000005", "2", "H-version", "PATCH-002", self.other,
                     self.other_sha1, "CLEAN", 1, "2026-05-11T15:10:00Z"),
        ]
        self.write_rows(self.results, rows)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def row(self, identifier, agent, hypothesis, card, testcase, sha1, verdict, runs, created):
        return {
            "id": identifier, "agent": agent, "hypothesis_id": hypothesis,
            "card_id": card, "mode": "generic", "testcase": str(testcase),
            "testcase_sha1": sha1, "asan_output": str(testcase) + ".asan.txt",
            "verdict": verdict, "sanitizer_runs": runs, "created_at": created,
        }

    def write_rows(self, results, rows):
        state = results / "state"
        state.mkdir(parents=True, exist_ok=True)
        (state / "runs.jsonl").write_text(
            "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
        )

    def run_history(self, *args, results=None, unset_results=False):
        env = os.environ.copy()
        if unset_results:
            env.pop("RESULTS_DIR", None)
        else:
            env["RESULTS_DIR"] = str(results or self.results)
        return subprocess.run(
            [sys.executable, str(COMMAND), *map(str, args)],
            capture_output=True, text=True, env=env,
        )

    def test_help_and_usage_errors(self) -> None:
        help_text = self.run_history("--help").stdout
        self.assertIn("probe-history", help_text)
        self.assertIn("Read-only digest", help_text)
        cases = (
            ((), {}, "supply TESTCASE"),
            (("--all",), {"unset_results": True}, "RESULTS_DIR not set"),
            (("--sha1", "not-hex!!!"), {}, "must be a hex string"),
            (("--all", "--verdict", "[(unclosed"), {}, "invalid --verdict regex"),
        )
        for args, kwargs, message in cases:
            with self.subTest(args=args):
                proc = self.run_history(*args, **kwargs)
                self.assertEqual(proc.returncode, 2)
                self.assertIn(message, proc.stdout + proc.stderr)

    def test_path_and_sha1_lookup_include_renames_and_confirmation(self) -> None:
        proc = self.run_history(self.first)
        output = proc.stdout
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn(self.first.name, output)
        self.assertIn("sha1=" + self.first_sha1[:12], output)
        self.assertIn("4 runs across 2 agents", output)
        self.assertIn("← confirmed", output)
        self.assertIn("confirmed verdict", output)
        all_rows = self.run_history(self.first, "--limit", "0").stdout
        self.assertEqual(len(re.findall(r"(?m)^  202", all_rows)), 4)
        self.assertNotIn("more)", all_rows)
        by_hash = self.run_history("--sha1", self.first_sha1).stdout
        self.assertIn(self.first_sha1[:12], by_hash)
        self.assertIn("4 runs across 2 agents", by_hash)

    def test_hypothesis_card_agent_verdict_and_all_filters(self) -> None:
        output = self.run_history("--hypothesis-id", "H-version").stdout
        self.assertIn(self.other.name, output)
        self.assertIn("1 runs", output)
        proc = self.run_history("--hypothesis-id", "H-nope")
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no matching runs", proc.stdout + proc.stderr)
        output = self.run_history("--card-id", "PATCH-001").stdout
        self.assertIn("PATCH-001", output)
        self.assertIn("4 runs", output)
        self.assertIn("1 runs", self.run_history(self.first, "--agent", "3").stdout)
        self.assertIn("3 runs", self.run_history(self.first, "--agent", "1").stdout)
        crashes = self.run_history("--all", "--verdict", "CRASH").stdout
        self.assertIn("3 runs", crashes)
        self.assertNotRegex(crashes, r"CLEAN|NO_EXEC")
        all_rows = self.run_history("--all", "--limit", "0").stdout
        self.assertIn("5 runs", all_rows)
        self.assertIn("all runs", all_rows)

    def test_tsv_json_and_pretty_limits(self) -> None:
        tsv = self.run_history("--all", "--format", "tsv").stdout.splitlines()
        self.assertIn("created_at", tsv[0])
        self.assertIn("sanitizer_runs", tsv[0])
        self.assertEqual(len(tsv[1:]), 5)
        json_lines = self.run_history("--all", "--format", "json").stdout.splitlines()
        self.assertEqual(len(json_lines), 5)
        self.assertIn("verdict", json.loads(json_lines[0]))
        limited = self.run_history("--all", "--limit", "2").stdout
        self.assertIn("more)", limited)
        self.assertIn("5 runs across 3 agents", limited)
        self.assertIn("[summary] 3 CRASH · 1 CLEAN · 1 NO_EXEC", limited)
        self.assertEqual(len(re.findall(r"(?m)^  202", limited)), 2)
        source = COMMAND.read_text(encoding="utf-8")
        self.assertRegex(source, r"(?m)^def read_jsonl\(")
        self.assertNotIn("from workqueue import", source)

    def test_empty_missing_and_no_confirmation_states(self) -> None:
        empty = Path(self.temporary.name) / "empty"
        self.write_rows(empty, [])
        proc = self.run_history("--all", results=empty)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("no matching runs", proc.stdout + proc.stderr)
        missing = Path(self.temporary.name) / "missing"
        missing.mkdir()
        self.assertEqual(self.run_history("--all", results=missing).returncode, 1)
        no_confirm = Path(self.temporary.name) / "no-confirm"
        self.write_rows(no_confirm, [self.row(
            "RUN-dddd000001", "1", "H-x", "", Path("/tmp/x.bin"), "abc",
            "CLEAN", 1, "2026-05-11T16:00:00Z",
        )])
        output = self.run_history("--all", results=no_confirm).stdout
        self.assertIn("no --confirm run recorded yet", output)
        self.assertNotIn("← confirmed", output)

    def test_missing_testcase_falls_back_to_recorded_path(self) -> None:
        self.first.unlink()
        proc = self.run_history(self.first)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("sha1=?", proc.stdout)

    def test_pretty_output_is_bounded_and_newline_aligned(self) -> None:
        results = Path(self.temporary.name) / "big"
        rows = [self.row(
            f"RUN-eeee{number:06d}", "1", "H-bulk", "PATCH-bulk", self.first,
            self.first_sha1, "CLEAN", 1, f"2026-05-11T17:00:{number % 60:02d}Z",
        ) for number in range(1, 201)]
        self.write_rows(results, rows)
        proc = self.run_history(self.first, "--limit", "0", results=results)
        output = (proc.stdout + proc.stderr).encode()
        self.assertLessEqual(len(output), 8500)
        self.assertIn(b"output clipped", output)
        self.assertTrue(output.endswith(b"\n"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
