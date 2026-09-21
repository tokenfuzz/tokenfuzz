#!/usr/bin/env python3
"""The one reading of a report's title that every index and page shares."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import report_identity  # noqa: E402


class ReportTitleTest(unittest.TestCase):
    def test_h1_without_its_artifact_id_prefix(self) -> None:
        for heading in ("# FIND-006: Parser trusts a length field",
                        "# CRASH-001-1 — Parser trusts a length field",
                        "#  Parser trusts a length field  "):
            self.assertEqual(report_identity.report_title(heading + "\n\n## Summary\n\nOther.\n"),
                             "Parser trusts a length field", heading)

    def test_untitled_report_is_named_by_its_summary_sentence(self) -> None:
        # Harness and direct reports share one fallback: the Summary's first
        # sentence, which the contract defines as the defect in plain words.
        # The enrichment TL;DR is derived text and is skipped, so a stale
        # copy never outranks the prose it came from.
        text = (
            "<!-- enrich:tldr -->\n- **Bug** — stale derived line.\n<!-- /enrich:tldr -->\n\n"
            "Location: src/app_parse.c:app_parse:91\n\n"
            "## Fields\n\n| Field | Value |\n| :-- | :-- |\n| Class | dos |\n\n"
            "## Summary\n\nThe parser trusts a length field before\n"
            "checking it. Two bytes reach it.\n"
        )
        self.assertEqual(report_identity.report_title(text),
                         "The parser trusts a length field before checking it")

    def test_an_id_only_heading_names_nothing(self) -> None:
        text = "# FIND-006\n\n## Summary\n\nA loop grows without bound.\n"
        self.assertEqual(report_identity.report_title(text), "A loop grows without bound")

    def test_headings_inside_fences_and_empty_sections_are_not_titles(self) -> None:
        text = "```sh\n# build first\n```\n\n## Summary\n\n## Root Cause\n\nNo bound.\n"
        self.assertEqual(report_identity.report_title(text), "")

    def test_indented_code_and_bare_summary_label(self) -> None:
        # Four spaces make an indented code block, not a heading; up to three
        # are still a heading. The bare `Summary:` label is a section too.
        text = "    # build first\n\nSummary:\nThe loop grows without bound. Then more.\n"
        self.assertEqual(report_identity.report_title(text), "The loop grows without bound")
        self.assertEqual(report_identity.report_title("   # Three spaces\n"), "Three spaces")

    def test_long_titles_are_clipped_once(self) -> None:
        text = "## Summary\n\n" + "word " * 60 + "end.\n"
        title = report_identity.report_title(text, limit=40)
        self.assertLessEqual(len(title), 40)
        self.assertTrue(title.endswith("…"))


if __name__ == "__main__":
    unittest.main()
