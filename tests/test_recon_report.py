#!/usr/bin/env python3
"""Behavior tests for recon report rendering and relocation."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "lib" / "recon_report.py"


class ReconReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="recon-report-")
        self.root = Path(self.temporary.name)
        self.results = self.root / "results"
        self.recon = self.results / "recon" / "RECON-deadbeefcafe0001"
        self.recon.mkdir(parents=True)
        (self.recon / "finding.json").write_text(json.dumps({
            "id": "RECON-deadbeefcafe0001", "slice": "slice-1-parsers",
            "title": "URL decoder allocates length+1 without guarding SIZE_MAX",
            "file": "/home/x/work/targets/curl/lib/decode.c", "line": 116,
            "function": "decode_input", "class": "integer-overflow",
            "notes": "alloc is used as malloc(alloc + 1) without a wrap check.",
            "confidence": "NEEDS-VERIFICATION", "validator_verdict": "Reject",
            "validator_details": "verdict=Reject",
        }) + "\n", encoding="utf-8")
        votes = (
            {
                "vote": "Reject",
                "rationale": "No attacker-reachable path supplies SIZE_MAX; the exported API caps length at INT_MAX.",
                "verified": {"reachability": False, "guards": None, "primitive": False},
                "caveats": "Source tracing only; no dynamic reproducer.",
            },
            {
                "vote": "Reject", "rationale": "decode_input is internal; confirmed not exported.",
                "verified": {"reachability": False},
            },
        )
        for number, vote in enumerate(votes, 1):
            (self.recon / f"validator-vote-{number}.json").write_text(
                json.dumps(vote) + "\n", encoding="utf-8"
            )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_report(self, path: Path, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(COMMAND), str(path), *args],
            capture_output=True,
            text=True,
        )

    def test_single_directory_render_is_complete_and_idempotent(self) -> None:
        proc = self.run_report(self.recon)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        report = self.recon / "REPORT.md"
        self.assertTrue(report.is_file())
        text = report.read_text(encoding="utf-8")
        for expected in (
            "RECON-deadbeefcafe0001 — URL decoder allocates", "UNVERIFIED",
            "lib/decode.c:116", "Vote 1 — Reject", "Vote 2 — Reject",
            "No attacker-reachable path", "reachability=no", "guards=unknown",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)
        self.assertNotIn("/home/x/work/targets", text)
        digest = hashlib.sha256(report.read_bytes()).digest()
        proc = self.run_report(self.recon)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(hashlib.sha256(report.read_bytes()).digest(), digest)

    def test_discovery_modes_and_no_html(self) -> None:
        report = self.recon / "REPORT.md"
        proc = self.run_report(self.results)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(report.is_file())
        self.assertIn("wrote 1 REPORT", proc.stdout)
        report.unlink()
        proc = self.run_report(self.results / "recon")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(report.is_file())
        report.unlink()
        html = self.recon / "REPORT.html"
        if html.exists():
            html.unlink()
        proc = self.run_report(self.recon, "--no-html")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertTrue(report.is_file())
        self.assertFalse(html.exists())

    def test_missing_and_empty_paths_have_stable_statuses(self) -> None:
        self.assertEqual(self.run_report(self.root / "missing").returncode, 1)
        empty = self.root / "empty"
        empty.mkdir()
        self.assertEqual(self.run_report(empty).returncode, 0)

    def test_audit_recon_uses_recon_tree(self) -> None:
        source = (ROOT / "bin" / "audit-recon").read_text(encoding="utf-8")
        self.assertIn('results_dir / "recon" / fid', source)
        self.assertNotIn('finding_dir="$RESULTS_DIR/findings/$fid"', source)

    def test_optional_schema_fields_render(self) -> None:
        rich = self.results / "recon" / "RECON-deadbeefcafe0002"
        rich.mkdir()
        (rich / "finding.json").write_text(json.dumps({
            "id": "RECON-deadbeefcafe0002", "title": "rich row",
            "file": "targets/x/a.c", "line": 5, "function": "f",
            "class": "bounds", "notes": "n", "confidence": "NEEDS-VERIFICATION",
            "reach_path": ["entry", "mid", "sink"],
            "input_shape": "oversized header", "guards_passed": ["len>0", "not-null"],
            "primitive": "oob-write", "falsification": "tried small input, clean",
        }) + "\n", encoding="utf-8")
        proc = self.run_report(rich, "--no-html")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        text = (rich / "REPORT.md").read_text(encoding="utf-8")
        for expected in (
            "entry → mid → sink", "oversized header", "oob-write",
            "not run through the validation gate",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
