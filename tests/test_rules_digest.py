#!/usr/bin/env python3
"""Coverage and prompt-integration checks for the compact session digest."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
REFERENCES = ROOT / ".agents" / "references"
FULL = REFERENCES / "session-rules.md"
DIGEST = REFERENCES / "session-rules.digest.md"
sys.path.insert(0, str(ROOT / "lib"))

import prompt


class RulesDigestTests(unittest.TestCase):
    def test_digest_is_compact_but_substantive(self) -> None:
        self.assertTrue(FULL.is_file())
        self.assertTrue(DIGEST.is_file())
        full_size = FULL.stat().st_size
        digest_size = DIGEST.stat().st_size
        self.assertLess(digest_size, full_size // 2)
        self.assertGreater(digest_size, 2000)

    def test_digest_covers_load_bearing_topics(self) -> None:
        text = DIGEST.read_text(encoding="utf-8").casefold()
        topics = (
            "bin/probe", "TARGET:", "find-seed", "guards-db", "tried-inputs",
            "rg-safe", "bin/peek", "show-patch", "NEUTRAL",
            "bin/state resume --agent", "crashes-rejected", "FINDING-CLUSTERS",
            "Caller contract", "Trigger source", "Parameter control", "FIND",
            "patch.diff", "write that section", "differential",
        )
        for topic in topics:
            with self.subTest(topic=topic):
                self.assertIn(topic.casefold(), text)

    def test_digest_drilldown_and_cheat_sheet_are_complete(self) -> None:
        digest = DIGEST.read_text(encoding="utf-8")
        full = FULL.read_text(encoding="utf-8")
        for expected in (
            "session-rules.md", "Drill-down", "Fix Direction", "best-effort",
            "bin/state cheat sheet", "add-hyp", "update-hyp", "add-note",
            "update-card", "show-recent", "list-cards", "recent-notes",
            "recent-claims", "recent-tried", "explain-queue", "strategy S",
            "bin/state recent-tried --agent N --limit 40",
            "Do not run `bin/rank-work` just to browse cards",
            "bin/scratch-status --agent N", "reverse-engineer the harness",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, digest)
        self.assertNotIn("tail -40 <RESULTS_DIR>/tried-inputs-N.log", digest)
        for expected in ("apply --check", "non-mutating", "not a dry run", "single writer", "Fix Direction"):
            with self.subTest(full_rule=expected):
                self.assertIn(expected, full)

    def test_prompt_integration_and_missing_file_fallback(self) -> None:
        rendered = prompt.session_rules_digest(REFERENCES)
        self.assertRegex(rendered, r"Session Rules.*Digest")
        self.assertIn("bin/probe", rendered)
        with tempfile.TemporaryDirectory(prefix="missing-rules-") as temporary:
            missing = prompt.session_rules_digest(Path(temporary))
        self.assertIn("digest missing", missing)

    def test_resume_rule_preserves_forward_progress(self) -> None:
        digest = DIGEST.read_text(encoding="utf-8")
        full = FULL.read_text(encoding="utf-8")
        for text in (digest, full):
            with self.subTest(source="digest" if text is digest else "full"):
                self.assertIn("before claiming new work", text)
                self.assertNotIn("No new exploration", text)
                self.assertNotIn("No new recon", text)
                self.assertNotIn("`recon/`", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
