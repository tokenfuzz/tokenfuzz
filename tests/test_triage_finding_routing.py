#!/usr/bin/env python3
"""Deterministic routing for sanitizer-backed finding artifacts."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import triage  # noqa: E402
import validation_receipt  # noqa: E402


DIAGNOSTIC = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1
READ of size 1 at 0x1 thread T0
SUMMARY: AddressSanitizer: heap-buffer-overflow app_parse sample.c:12
"""


class FindingCrashRoutingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="finding-routing-")
        self.results = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def finding(self, name: str, *, diagnostic: str = DIAGNOSTIC) -> Path:
        directory = self.results / "findings" / name
        directory.mkdir(parents=True)
        (directory / "report.md").write_text(
            "# Bounds issue\n\nBoundary: public input\n", encoding="utf-8",
        )
        (directory / "sanitizer.txt").write_text(diagnostic, encoding="utf-8")
        return directory

    def test_complete_memory_diagnostic_routes_to_crash_triage(self) -> None:
        directory = self.finding("FIND-001")
        (directory / "input.bin").write_bytes(b"input")
        self.assertEqual(triage.route_finding_diagnostics(self.results), 1)
        routed = self.results / "crashes" / "CRASH-001"
        self.assertTrue(routed.is_dir())
        self.assertIn("Routed from `findings/`", (routed / "report.md").read_text())

    def test_unreproduced_memory_diagnostic_stays_as_visible_crash_lead(self) -> None:
        directory = self.finding("FIND-002")
        self.assertEqual(triage.route_finding_diagnostics(self.results), 0)
        self.assertTrue(directory.is_dir())
        self.assertTrue((directory / ".crash-lead.json").is_file())

    def test_harness_source_without_input_is_not_a_runnable_reproducer(self) -> None:
        directory = self.finding("FIND-006")
        (directory / "harness.c").write_text(
            "int main(void) { return 0; }\n", encoding="utf-8",
        )
        self.assertEqual(triage.route_finding_diagnostics(self.results), 0)
        self.assertTrue(directory.is_dir())
        self.assertTrue((directory / ".crash-lead.json").is_file())

    def test_exported_audit_sidecar_routes_the_whole_finding(self) -> None:
        directory = self.finding("FIND-005")
        audit = directory / ".audit"
        audit.mkdir()
        (directory / "sanitizer.txt").replace(audit / "sanitizer.txt")
        (directory / "input.bin").write_bytes(b"input")

        self.assertEqual(triage.route_finding_diagnostics(self.results), 1)
        routed = self.results / "crashes" / "CRASH-005"
        self.assertTrue(routed.is_dir())
        self.assertTrue((routed / ".audit" / "sanitizer.txt").is_file())
        self.assertFalse((self.results / "findings" / "FIND-005").exists())

    def test_deliberate_crash_demotion_never_loops_back(self) -> None:
        directory = self.finding("FIND-003")
        (directory / "input.bin").write_bytes(b"input")
        with (directory / "report.md").open("a", encoding="utf-8") as stream:
            stream.write(
                "\n## Triage disposition\n\n"
                "Demoted from `crashes/`: replay did not reproduce.\n"
            )
        self.assertEqual(triage.route_finding_diagnostics(self.results), 0)
        self.assertTrue(directory.is_dir())

    def test_quarantine_class_is_not_misrouted_as_corruption(self) -> None:
        directory = self.finding(
            "FIND-004",
            diagnostic=(
                "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
                "SUMMARY: AddressSanitizer: SEGV app_parse sample.c:12\n"
            ),
        )
        (directory / "input.bin").write_bytes(b"input")
        self.assertEqual(triage.route_finding_diagnostics(self.results), 0)
        self.assertTrue(directory.is_dir())


if __name__ == "__main__":
    unittest.main()


class HeldBundleReceiptTests(unittest.TestCase):
    """A crash waiting on evidence must report as pending, not as legacy data."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="held-bundle-")
        self.results = Path(self.temporary.name) / "results"
        self.crashes = self.results / "crashes"
        self.crashes.mkdir(parents=True)
        self.crash = self.crashes / "CRASH-0001"
        self.crash.mkdir()
        (self.crash / "report.md").write_text(
            "# incomplete bundle\n", encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_held_then_aged_out_bundle_carries_the_matching_receipt(self) -> None:
        rejected = self.results / "crashes-rejected"
        missing = ["testcase or harness"]
        with mock.patch.dict(
            os.environ, {"CRASH_PROMOTION_PENDING_MAX": "2"}, clear=False,
        ):
            first = triage._hold_incomplete(
                self.crash, rejected, self.crash / "report.md",
                "bundle", missing,
            )
            self.assertEqual(first, "pending")
            # Without a receipt this is indistinguishable from an artifact
            # written before receipts existed, i.e. it would read as
            # un-migrated data rather than a crash still gathering evidence.
            receipt = validation_receipt.read_current(self.crash)
            self.assertIsNotNone(receipt)
            self.assertEqual(receipt["state"], "pending")

            second = triage._hold_incomplete(
                self.crash, rejected, self.crash / "report.md",
                "bundle", missing,
            )
        self.assertEqual(second, "rejected")
        moved = next(rejected.iterdir())
        # Rejection supersedes the pending receipt, so the artifact cannot be
        # double-counted in the pending lane after it leaves crashes/.
        aged = validation_receipt.read_current(moved)
        self.assertIsNotNone(aged)
        self.assertEqual(aged["state"], "rejected")
