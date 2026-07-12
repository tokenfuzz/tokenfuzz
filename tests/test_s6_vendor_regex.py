#!/usr/bin/env python3
"""Keep the S6 strategy matcher generic and target-agnostic."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import workqueue


class S6VendorRegexTests(unittest.TestCase):
    def test_retired_vendor_alternation_stays_retired(self) -> None:
        self.assertFalse(hasattr(workqueue, "_S6_VENDOR_ALT"))

    def test_generic_vocabulary_matches(self) -> None:
        matcher = workqueue.STRATEGY_KEYWORDS["S6"][0]
        for text in (
            "look at the upstream fix", "CVE-2024-12345 affects us too",
            "analogous to another impl", "cross-engine variant",
            "same bug in the other library", "oss-fuzz reported",
        ):
            with self.subTest(text=text):
                self.assertIsNotNone(matcher.search(text))

    def test_unrelated_text_does_not_match(self) -> None:
        matcher = workqueue.STRATEGY_KEYWORDS["S6"][0]
        for text in (
            "fix the typo", "rename the variable", "update the docs",
            "refactor the parser", "the zlib-ng patch", "firefox bug here",
        ):
            with self.subTest(text=text):
                self.assertIsNone(matcher.search(text))


if __name__ == "__main__":
    unittest.main(verbosity=2)
