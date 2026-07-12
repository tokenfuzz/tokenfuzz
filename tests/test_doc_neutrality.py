#!/usr/bin/env python3
"""Require agent-read documentation to be a fixed point of neutralize_line."""

from __future__ import annotations

import difflib
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
VOCAB = ROOT / "lib" / "vocab_rules.py"


class DocumentationNeutralityTests(unittest.TestCase):
    def test_agent_documentation_is_canonical(self) -> None:
        documents = [ROOT / "AGENTS.md"]
        documents.extend(sorted((ROOT / ".agents" / "references").rglob("*.md")))
        self.assertTrue(documents)
        for document in documents:
            with self.subTest(document=document.relative_to(ROOT)):
                before = document.read_text(encoding="utf-8")
                proc = subprocess.run(
                    [sys.executable, str(VOCAB), "line-core"],
                    input=before,
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(proc.returncode, 0, proc.stderr)
                if before != proc.stdout:
                    diff = "".join(difflib.unified_diff(
                        before.splitlines(True), proc.stdout.splitlines(True),
                        fromfile=str(document), tofile="neutralized", n=3,
                    ))
                    self.fail(diff[:4000])


if __name__ == "__main__":
    unittest.main(verbosity=2)
