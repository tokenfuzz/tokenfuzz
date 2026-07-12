#!/usr/bin/env python3
"""FIND materialization, routing, fan-out, idempotence, and wiring coverage."""

from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "lib" / "recon_to_cards.py"
sys.path.insert(0, str(ROOT / "lib"))

import finding_signature
import recon_to_cards


class ReconFindMaterializationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="recon-find-")
        self.root = Path(self.temporary.name)
        self.recon = self.root / "recon.jsonl"
        self.cards = self.root / "work-cards.jsonl"
        self.results = self.root / "results"
        self.results.mkdir()
        self.target = "/synthetic/target"
        rows = (
            self.row("REC-promote", "callback invalidates query", "src/lib/proc.c", 1477,
                     "end_query", "lifetime", "callback clears state before next loop", "CONFIRMED-HIGH",
                     validator_verdict="Promote", validator_details="verdict=Promote votes=2/2"),
            self.row("REC-needs", "multiplication wraps", "src/lib/record/rec.c", 1249,
                     "set_bin", "size", "count multiplication wraps", "NEEDS-VERIFICATION"),
            self.row("REC-reject", "document size not validated", "src/lib/json.c", 127,
                     "parse_doc", "state", "declared size is discarded", "NEEDS-VERIFICATION",
                     validator_verdict="Reject", validator_details="verdict=Reject votes=0/2"),
            self.row("REC-uncertain", "key collision", "src/lib/cache.c", 125,
                     "key", "state", "delimiter concatenation collides", "CONFIRMED-MEDIUM",
                     validator_verdict="Uncertain"),
            {"id": "REC-sparse-noline", "title": "missing line", "file": self.target + "/src/sparse.c",
             "function": "f", "class": "lifetime", "notes": "present", "confidence": "NEEDS-VERIFICATION"},
            {"id": "REC-sparse-nofn", "title": "missing function", "file": self.target + "/src/sparse.c",
             "line": 10, "class": "lifetime", "notes": "present", "confidence": "NEEDS-VERIFICATION"},
            {"id": "REC-sparse-nonotes", "title": "missing notes", "file": self.target + "/src/sparse.c",
             "line": 10, "function": "f", "class": "lifetime", "confidence": "NEEDS-VERIFICATION"},
            {"id": "REC-audit-clean", "confidence": "AUDIT-CLEAN", "notes": "nothing here"},
        )
        self.recon.write_text("".join(json.dumps(row) + "\n" for row in rows))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def row(self, identifier, title, file, line, function, issue_class, notes, confidence, **extra):
        row = {
            "id": identifier, "slice": "slice", "title": title,
            "file": self.target + "/" + file, "line": line, "function": function,
            "class": issue_class, "notes": notes, "confidence": confidence,
        }
        row.update(extra)
        return row

    def run_cards(self, recon=None, cards=None, results=None, sanitizers=None, omit_results=False):
        args = [
            sys.executable, str(COMMAND), "--target-slug", "testproject",
            "--target-path", self.target, "--recon-jsonl", str(recon or self.recon),
            "--work-cards", str(cards or self.cards),
        ]
        if not omit_results:
            args.extend(("--results-dir", str(results or self.results)))
        if sanitizers is not None:
            args.extend(("--sanitizers", sanitizers))
        args.append("--quiet")
        return subprocess.run(args, capture_output=True, text=True)

    def read_cards(self, path=None):
        return [json.loads(line) for line in (path or self.cards).read_text().splitlines() if line]

    def cards_for(self, identifier, path=None):
        return [card for card in self.read_cards(path) if card.get("recon", {}).get("id") == identifier]

    def test_complete_non_rejected_rows_materialize_findings_and_generic_cards(self) -> None:
        proc = self.run_cards()
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual({card["mode"] for card in self.read_cards()}, {"generic"})
        for identifier in ("REC-promote", "REC-needs", "REC-uncertain"):
            with self.subTest(identifier=identifier):
                cards = self.cards_for(identifier)
                self.assertTrue(cards)
                find_id = cards[0].get("find_id")
                self.assertTrue(find_id)
                report = self.results / "findings" / find_id / "report.md"
                self.assertGreater(report.stat().st_size, 0)
        promote = self.cards_for("REC-promote")[0]
        report = (self.results / "findings" / promote["find_id"] / "report.md").read_text()
        for expected in (
            "callback invalidates query", "end_query", "1477", "REC-promote",
            "validator verdict: Promote",
        ):
            self.assertIn(expected, report)

    def test_rejected_sparse_and_clean_rows_follow_distinct_policies(self) -> None:
        self.assertEqual(self.run_cards().returncode, 0)
        rejected = self.cards_for("REC-reject")
        self.assertTrue(rejected)
        self.assertTrue(all(not card.get("find_id") for card in rejected))
        for identifier in ("REC-sparse-noline", "REC-sparse-nofn", "REC-sparse-nonotes"):
            cards = self.cards_for(identifier)
            self.assertTrue(cards)
            self.assertTrue(all(not card.get("find_id") for card in cards))
        self.assertEqual(self.cards_for("REC-audit-clean"), [])
        finding_names = [path.name for path in (self.results / "findings").glob("FIND-RECON-*")]
        self.assertTrue(all("reject" not in name and "audit-clean" not in name for name in finding_names))

    def test_multi_sanitizer_fanout_shares_one_find_id_and_directory(self) -> None:
        recon = self.root / "multi.jsonl"
        cards = self.root / "multi-cards.jsonl"
        results = self.root / "multi-results"
        results.mkdir()
        recon.write_text(json.dumps(self.row(
            "REC-multi", "size wrap", "src/x.c", 42, "alloc", "size",
            "count wraps", "NEEDS-VERIFICATION",
        )) + "\n")
        proc = self.run_cards(recon, cards, results, "asan,ubsan")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        emitted = self.cards_for("REC-multi", cards)
        self.assertGreater(len(emitted), 1)
        self.assertEqual(len({card["find_id"] for card in emitted}), 1)
        self.assertEqual(len(list((results / "findings").glob("FIND-RECON-*"))), 1)

    def test_rerun_keeps_stable_id_and_preserves_agent_augmentation(self) -> None:
        self.assertEqual(self.run_cards().returncode, 0)
        first = self.cards_for("REC-promote")[0]["find_id"]
        report = self.results / "findings" / first / "report.md"
        with report.open("a") as stream:
            stream.write("\n## Dynamic evidence\nFixture evidence.\n")
        digest = hashlib.sha256(report.read_bytes()).digest()
        self.assertEqual(self.run_cards().returncode, 0)
        self.assertEqual(self.cards_for("REC-promote")[0]["find_id"], first)
        self.assertEqual(hashlib.sha256(report.read_bytes()).digest(), digest)

    def test_results_dir_is_mandatory_and_runtime_wiring_passes_it(self) -> None:
        proc = self.run_cards(omit_results=True)
        self.assertNotEqual(proc.returncode, 0)
        self.assertRegex(proc.stdout + proc.stderr, r"missing required arg.*--results-dir")
        source = (ROOT / "lib" / "audit_runner.py").read_text()
        self.assertIn('"--results-dir", str(runtime.results)', source)

    def test_prefiled_prompt_and_materialized_signature_fields_are_parseable(self) -> None:
        self.assertIn("PRE-FILED FIND", (ROOT / "lib" / "prompt.py").read_text())
        self.assertIn("find_id", (ROOT / "lib" / "prompt.py").read_text())
        self.assertIn(
            "PRE-FILED FIND",
            (ROOT / "lib" / "prompts" / "find_first_directive.md.j2").read_text(),
        )
        self.assertEqual(self.run_cards().returncode, 0)
        find_id = self.cards_for("REC-promote")[0]["find_id"]
        text = (self.results / "findings" / find_id / "report.md").read_text()
        file, function = finding_signature.extract_location(text, "")
        self.assertTrue(file)
        self.assertTrue(function)
        rendered = recon_to_cards._render_find_report({
            "id": "REC-x", "title": "Sample", "file": "src/x.c", "line": 1,
            "function": "f", "class": "lifetime", "notes": "demo",
            "confidence": "NEEDS-VERIFICATION",
        }, "src/x.c", 1, "tp")
        raw_class = finding_signature.extract_class(rendered)
        self.assertTrue(raw_class)
        self.assertTrue(finding_signature.normalize_class(raw_class))


if __name__ == "__main__":
    unittest.main(verbosity=2)
