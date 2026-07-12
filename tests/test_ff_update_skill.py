#!/usr/bin/env python3
"""Regression checks for the Firefox update skill conflict scan."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class FirefoxUpdateSkillTests(unittest.TestCase):
    def test_conflict_check_ignores_untracked_build_outputs(self) -> None:
        skill = ROOT / ".agents" / "skills" / "ff-update" / "SKILL.md"
        self.assertTrue(skill.is_file())
        text = skill.read_text(encoding="utf-8")
        self.assertIn("hg -R targets/firefox status -mard", text)
        self.assertIn("hg status -mard", text)
        self.assertIsNone(re.search(r"^hg -R targets/firefox status$", text, re.MULTILINE))


if __name__ == "__main__":
    unittest.main(verbosity=2)
