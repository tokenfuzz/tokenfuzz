#!/usr/bin/env python3
"""tests/test_find_gate_site_sharing.py — one review per site.

Every review is a fresh draw from a model. Reviewing N copies of one claim
gave it N chances to be accepted, so the number of copies a condition filed
decided what it was credited with. Findings at a concluded site inherit that
verdict; unreviewed copies within one drain wait for their representative.
"""

from __future__ import annotations

import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import triage  # noqa: E402
import validation_receipt  # noqa: E402


def _report(function: str, line: int, title: str) -> str:
    return (
        f"# {title}\n\n"
        "## Fields\n\n"
        "| Field    | Value |\n|:---------|:------|\n"
        "| Class    | stack-buffer-overflow |\n"
        "| Severity | High |\n"
        "| File     | `src/app.c` |\n"
        f"| Function | `{function}` |\n"
        f"| Line     | {line} |\n\n"
        f"Location: src/app.c:{function}:{line}\n\n"
        "## Summary\n\nThe copy is bounded by the wrong limit.\n"
    )


class SiteSharingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="site-share-")
        self.results = Path(self.temp.name)
        (self.results / "findings").mkdir()
        (self.results / "findings-rejected").mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def finding(self, name: str, function: str, line: int, *, rejected: str = "") -> Path:
        parent = self.results / ("findings-rejected" if rejected else "findings")
        directory = parent / name
        directory.mkdir()
        (directory / "report.md").write_text(
            _report(function, line, f"{name} at {function}"), encoding="utf-8",
        )
        if rejected:
            (directory / "REJECTION.md").write_text(
                f"# Rejected artifact\n\nReason: {rejected}\n", encoding="utf-8",
            )
        return directory

    def gate(self) -> dict[str, int]:
        # An expired deadline asks no model anything: what the gate settles
        # here, it settles by sharing.
        return triage.validate_find_gate(
            self.results, workers=1, deadline=time.time() - 1,
        )

    def test_an_unreviewed_copy_inherits_the_sites_kept_verdict(self) -> None:
        source = self.finding("FIND-0001", "app_check", 196)
        validation_receipt.write(
            source, kind="finding", state="reportable",
            detail="source review placed the trigger within attacker_controls=bytes",
            review_facts={"trigger_controls_fit": "within"},
            attacker_controls=["bytes"],
        )
        copy = self.finding("FIND-0002", "app_check", 196)
        other = self.finding("FIND-0003", "app_other", 40)
        counts = self.gate()
        receipt = validation_receipt.read_current(copy)
        self.assertEqual(receipt["state"], "reportable")
        self.assertTrue(receipt["detail"].startswith("same-site: FIND-0001:"))
        self.assertEqual(receipt["evidence"]["review_facts"], {"trigger_controls_fit": "within"})
        self.assertEqual(validation_receipt.read_current(other)["state"], "pending")
        self.assertEqual(counts["accepted"], 2)
        self.assertEqual(counts["pending"], 1)
        # A second drain does not ask again.
        self.assertEqual(self.gate()["accepted"], 2)

    def test_an_unreviewed_copy_follows_a_site_level_rejection(self) -> None:
        self.finding(
            "FIND-0001", "app_check", 196,
            rejected="threat-model: source review placed the trigger outside attacker_controls=bytes",
        )
        copy = self.finding("FIND-0002", "app_check", 196)
        counts = self.gate()
        self.assertFalse(copy.is_dir())
        moved = self.results / "findings-rejected" / "FIND-0002"
        self.assertTrue(moved.is_dir())
        self.assertTrue(triage._rejection_reason(moved).startswith("same-site: FIND-0001:"))
        self.assertEqual(counts["rejected"], 1)
        # The copy is requeued when its source is: a shared verdict never
        # outlives the review it came from.
        (self.results / "findings-rejected" / "FIND-0001" / "REJECTION.md").unlink()
        (self.results / "findings-rejected" / "FIND-0001").rename(self.results / "findings" / "FIND-0001")
        self.gate()
        self.assertTrue((self.results / "findings" / "FIND-0002").is_dir())

    def test_a_write_up_rejection_is_not_shared(self) -> None:
        self.finding(
            "FIND-0001", "app_check", 196,
            rejected="incomplete missing: missing Data Flow section",
        )
        copy = self.finding("FIND-0002", "app_check", 196)
        self.gate()
        self.assertTrue(copy.is_dir())

    def test_copies_in_one_drain_wait_for_their_representative(self) -> None:
        first = self.finding("FIND-0001", "app_check", 196)
        second = self.finding("FIND-0002", "app_check", 196)
        reviewed: list[Path] = []

        def settle(directory, results, **_kwargs):
            reviewed.append(directory)
            validation_receipt.write(
                directory, kind="finding", state="not-reportable",
                detail="reviewed once", review_facts={"trigger_controls_fit": "outside"},
            )
            return "accepted"

        with mock.patch.object(triage, "validate_one_finding", side_effect=settle):
            counts = triage.validate_find_gate(self.results, workers=1)
        self.assertEqual(reviewed, [first])
        self.assertEqual(validation_receipt.read_current(second)["state"], "not-reportable")
        self.assertEqual(counts["accepted"], 2)


if __name__ == "__main__":
    unittest.main()
