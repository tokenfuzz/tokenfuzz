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


class AvailabilityOnlyTests(unittest.TestCase):
    """Denial of service is not scored: a dos-family FIND is rejected unvoted."""

    def test_dos_family_finding_is_rejected_without_a_vote_and_stays_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dos-scope-") as temporary:
            results = Path(temporary)
            findings = results / "findings"
            findings.mkdir()
            slow = findings / "FIND-0002-quadratic"
            slow.mkdir()
            (slow / "report.md").write_text(
                "# Translation permits quadratic CPU exhaustion\n\n"
                "Location: xpath.c:app_translate:7809\n\n"
                "## Fields\n\n| Field | Value |\n|:--|:--|\n"
                "| Class | denial-of-service |\n| File | `xpath.c` |\n"
                "| Function | `app_translate` |\n| Line | 7809 |\n\n"
                "## Summary\n\nEvery input character rescans the mapping string.\n",
                encoding="utf-8",
            )
            with mock.patch.dict(os.environ, {"LLM_DECIDE_DISABLE": "1"}):
                counts = triage.validate_find_gate(results, workers=1)
            self.assertEqual(counts, {"accepted": 0, "rejected": 1, "pending": 0})
            rejected = results / "findings-rejected" / "FIND-0002-quadratic"
            self.assertTrue(rejected.is_dir())
            self.assertIn(
                triage.AVAILABILITY_ONLY_REJECTION_REASON,
                (rejected / "rejection.md").read_text(encoding="utf-8"),
            )
            self.assertFalse((rejected / ".llm-find-quality.json").exists(), "no vote spent")
            # A later pass must not requeue a policy rejection as a stale verdict.
            with mock.patch.dict(os.environ, {"LLM_DECIDE_DISABLE": "1"}):
                triage.validate_find_gate(results, workers=1)
            self.assertTrue(rejected.is_dir())
            self.assertEqual(list(findings.glob("FIND-*")), [])

    def test_a_contradictory_primitive_fails_open_to_quality_review(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dos-primitive-") as temporary:
            results = Path(temporary)
            finding = results / "findings" / "FIND-0001"
            finding.mkdir(parents=True)
            (finding / "report.md").write_text(
                "# Conflicting authored fields\n\n"
                "Class: denial-of-service\nPrimitive: heap_write\n",
                encoding="utf-8",
            )
            counts = {"accepted": 0, "rejected": 0, "pending": 0}
            kept = triage.reject_availability_only(results, [finding], counts)
            self.assertEqual(kept, [finding])
            self.assertEqual(counts, {"accepted": 0, "rejected": 0, "pending": 0})

    def test_dos_primitives_do_not_bypass_policy_rejection(self) -> None:
        for primitive in sorted(triage.AVAILABILITY_ONLY_PRIMITIVES):
            with self.subTest(primitive=primitive), tempfile.TemporaryDirectory(
                prefix="dos-primitive-",
            ) as temporary:
                results = Path(temporary)
                finding = results / "findings" / "FIND-0001"
                finding.mkdir(parents=True)
                (finding / "report.md").write_text(
                    "# Availability-only finding\n\n"
                    f"Class: denial-of-service\nPrimitive: {primitive}\n",
                    encoding="utf-8",
                )
                counts = {"accepted": 0, "rejected": 0, "pending": 0}
                kept = triage.reject_availability_only(results, [finding], counts)
                self.assertEqual(kept, [])
                self.assertEqual(
                    counts, {"accepted": 0, "rejected": 1, "pending": 0},
                )


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
