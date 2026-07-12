#!/usr/bin/env python3
"""Keep auto-loaded runtime instructions separate from development guidance."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class InstructionFileTests(unittest.TestCase):
    def test_development_guide_is_not_root_autoloaded(self) -> None:
        self.assertTrue((ROOT / "docs" / "development.md").is_file())
        self.assertFalse((ROOT / "CLAUDE.md").exists())
        self.assertFalse((ROOT / "GEMINI.md").exists())

    def test_agents_contains_runtime_guidance_only(self) -> None:
        text = (ROOT / "AGENTS.md").read_text(encoding="utf-8")
        for forbidden in (
            "harness-dev-only", "Coding Discipline", "Testing Discipline",
            "Logging Discipline",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_audit_injects_agents_without_dev_block_stripping(self) -> None:
        self.assertNotIn(
            "harness-dev-only", (ROOT / "bin" / "audit").read_text(encoding="utf-8")
        )
        self.assertIn(
            'root / "AGENTS.md"',
            (ROOT / "lib" / "audit_runner.py").read_text(encoding="utf-8"),
        )

    def test_development_page_has_the_canonical_startup_prompt(self) -> None:
        self.assertFalse((ROOT / "docs" / "contributing.md").exists())
        text = (ROOT / "docs" / "development.md").read_text(encoding="utf-8")
        for required in (
            "Read docs/development.md first",
            "Start your coding agent",
            "`claude`, `codex`, `gemini`, `grok`",
            "Read docs/development.md first, then help me with: <task>",
            "Use broad, stable rules",
        ):
            with self.subTest(required=required):
                self.assertIn(required, text)
        self.assertNotIn("One-shot sessions", text)
        self.assertIsNone(re.search(r"^## Context$", text, re.MULTILINE))


if __name__ == "__main__":
    unittest.main(verbosity=2)
