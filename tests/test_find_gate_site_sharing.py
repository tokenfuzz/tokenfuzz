#!/usr/bin/env python3
"""Findings at one source site retain independent review evidence."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import triage  # noqa: E402
import validation_receipt  # noqa: E402


class SiteReviewTests(unittest.TestCase):
    def test_legacy_same_site_verdicts_return_to_independent_review(self) -> None:
        with tempfile.TemporaryDirectory(prefix="legacy-site-review-") as temporary:
            results = Path(temporary)
            findings = results / "findings"
            rejected = results / "findings-rejected"
            findings.mkdir()
            rejected.mkdir()

            accepted = findings / "FIND-0001"
            accepted.mkdir()
            (accepted / "report.md").write_text("# First claim\n", encoding="utf-8")
            validation_receipt.write(
                accepted, kind="finding", state="reportable",
                detail="same-site: FIND-0000: inherited accept",
            )

            denied = rejected / "FIND-0002"
            denied.mkdir()
            (denied / "report.md").write_text("# Second claim\n", encoding="utf-8")
            (denied / "rejection.md").write_text(
                "# Rejected artifact\n\n"
                "Reason: same-site: FIND-0000: inherited reject\n",
                encoding="utf-8",
            )

            with mock.patch.dict(os.environ, {"LLM_DECIDE_DISABLE": "1"}):
                counts = triage.validate_find_gate(results, workers=1)

            restored = findings / "FIND-0002"
            self.assertTrue(restored.is_dir())
            self.assertFalse((restored / "rejection.md").exists())
            self.assertNotEqual(
                "reportable",
                (validation_receipt.read_current(accepted) or {}).get("state"),
            )
            self.assertEqual(counts["pending"], 2)

    def test_same_site_claims_are_reviewed_independently(self) -> None:
        with tempfile.TemporaryDirectory(prefix="site-review-") as temporary:
            results = Path(temporary)
            findings = results / "findings"
            findings.mkdir()
            directories = []
            for number in (1, 2):
                directory = findings / f"FIND-000{number}"
                directory.mkdir()
                (directory / "report.md").write_text(
                    "# Claim\n\n"
                    "## Fields\n\n"
                    "| Field | Value |\n|:--|:--|\n"
                    "| Class | stack-buffer-overflow |\n"
                    "| File | `src/app.c` |\n"
                    "| Function | `app_check` |\n"
                    "| Line | 196 |\n\n"
                    f"## Summary\n\nDistinct trigger {number} reaches this operation.\n",
                    encoding="utf-8",
                )
                directories.append(directory)

            reviewed: list[Path] = []

            def settle(directory, _results, **_kwargs):
                reviewed.append(directory)
                validation_receipt.write(
                    directory, kind="finding", state="not-reportable",
                    detail=f"independent review of {directory.name}",
                    review_facts={"trigger_controls_fit": "outside"},
                )
                return "accepted"

            with mock.patch.object(
                triage, "validate_one_finding", side_effect=settle,
            ):
                counts = triage.validate_find_gate(results, workers=1)

            self.assertEqual(reviewed, directories)
            self.assertEqual(counts["accepted"], 2)
            for directory in directories:
                receipt = validation_receipt.read_current(directory)
                self.assertIn(directory.name, receipt["detail"])


if __name__ == "__main__":
    unittest.main()
