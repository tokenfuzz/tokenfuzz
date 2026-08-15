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

    def test_historical_unmeasured_replay_demotion_can_be_reconsidered(self) -> None:
        directory = self.finding("FIND-007")
        (directory / "input.bin").write_bytes(b"input")
        with (directory / "report.md").open("a", encoding="utf-8") as stream:
            stream.write(
                "\n## Triage disposition\n\n"
                "Demoted from `crashes/`: configured-target replay produced no "
                "measurement of the original fault (see .audit/reverify.log).\n"
            )
        self.assertEqual(
            triage.route_finding_diagnostics(
                self.results, reconsider_unverifiable_replay=True,
            ),
            1,
        )
        self.assertTrue((self.results / "crashes" / "CRASH-007").is_dir())

    def test_historical_no_contract_demotion_can_be_reconsidered(self) -> None:
        # The resolver answered "no contract" for every bundle whose harness
        # export-repro had migrated into .audit/, and that demotion was
        # permanent — the crash never came back on a later pass.
        directory = self.finding("FIND-010")
        (directory / ".audit").mkdir()
        (directory / ".audit" / "input").write_bytes(b"input")
        with (directory / "report.md").open("a", encoding="utf-8") as stream:
            stream.write(
                "\n## Triage disposition\n\n"
                "Demoted from `crashes/`: sanitizer evidence has no executable "
                "configured-target replay contract.\n"
            )
        self.assertEqual(triage.route_finding_diagnostics(self.results), 0)
        self.assertEqual(
            triage.route_finding_diagnostics(
                self.results, reconsider_unverifiable_replay=True,
            ),
            1,
        )
        self.assertTrue((self.results / "crashes" / "CRASH-010").is_dir())

    def test_historical_harness_only_demotion_can_be_reconsidered(self) -> None:
        # Ordinary source-only findings stay findings, but this artifact was a
        # crash before the withdrawn replay demotion. A harness that embeds its
        # input must not be stranded merely because it has no separate testcase.
        directory = self.finding("FIND-011")
        (directory / "harness.c").write_text(
            "int main(void) { return 0; }\n", encoding="utf-8",
        )
        with (directory / "report.md").open("a", encoding="utf-8") as stream:
            stream.write(
                "\n## Triage disposition\n\n"
                "Demoted from `crashes/`: sanitizer evidence has no executable "
                "configured-target replay contract.\n"
            )

        self.assertEqual(
            triage.route_finding_diagnostics(
                self.results, reconsider_unverifiable_replay=True,
            ),
            1,
        )
        routed = self.results / "crashes" / "CRASH-011"
        self.assertTrue(routed.is_dir())
        disposition = (routed / "report.md").read_text(encoding="utf-8")
        self.assertIn("saved reproducer", disposition)
        self.assertNotIn("runnable reproducer", disposition)

    def test_rejected_historical_replay_demotion_is_reconsidered_too(self) -> None:
        directory = self.results / "findings-rejected" / "FIND-008"
        directory.mkdir(parents=True)
        (directory / "report.md").write_text(
            "# Bounds issue\n\n"
            "Demoted from `crashes/`: configured-target replay produced no "
            "measurement of the original fault (see .audit/reverify.log).\n",
            encoding="utf-8",
        )
        (directory / "sanitizer.txt").write_text(DIAGNOSTIC, encoding="utf-8")
        (directory / "input.bin").write_bytes(b"input")
        (directory / "REJECTION.md").write_text(
            "Reason: finding quality reject\n", encoding="utf-8",
        )
        validation_receipt.write(
            directory, kind="finding", state="rejected",
        )
        self.assertEqual(
            triage.route_finding_diagnostics(
                self.results, reconsider_unverifiable_replay=True,
            ),
            1,
        )
        routed = self.results / "crashes" / "CRASH-008"
        self.assertTrue(routed.is_dir())
        self.assertFalse((routed / "REJECTION.md").exists())

    def test_a_newer_replay_verdict_is_not_reopened_by_the_old_marker(self) -> None:
        directory = self.finding("FIND-009")
        (directory / "input.bin").write_bytes(b"input")
        with (directory / "report.md").open("a", encoding="utf-8") as stream:
            stream.write(
                "\nDemoted from `crashes/`: configured-target replay produced "
                "no measurement of the original fault (see .audit/reverify.log).\n"
                "\nDemoted from `crashes/`: sanitizer evidence did not reproduce "
                "through the configured target invocation.\n"
            )
        self.assertEqual(
            triage.route_finding_diagnostics(
                self.results, reconsider_unverifiable_replay=True,
            ),
            0,
        )
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

    def test_reportless_crash_is_pending_after_regeneration_deadline(self) -> None:
        (self.crash / "report.md").unlink()
        status = triage.triage_one_crash(
            self.crash, self.results, self.results / "target",
            "sampleproj", ["bytes"], deadline=0, age_pending=False,
        )
        self.assertEqual(status, "pending")
        receipt = validation_receipt.read_current(self.crash)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "pending")


class PublicationDetailTests(unittest.TestCase):
    """A receipt's recorded reason must be the reason it was decided for."""

    def test_a_scope_review_decision_is_not_reported_as_the_reach_verdict(self) -> None:
        # The reach verdict reads the report's self-declared trigger; the
        # source review outranks it. Recording the reach reason under the
        # review's decision published receipts contradicting themselves —
        # "trigger within attacker_controls=bytes" stamped on not-reportable —
        # which reads as a broken gate rather than a reviewer's call.
        self.assertEqual(
            "source review placed the trigger outside attacker_controls=bytes",
            triage._publication_detail(
                "not-reportable", "promote",
                "trigger within attacker_controls=bytes",
                {"trigger_controls_fit": "outside"}, ["bytes"],
            ),
        )
        self.assertEqual(
            "real defect that crosses no security boundary",
            triage._publication_detail(
                "not-reportable", "promote",
                "trigger within attacker_controls=bytes",
                {"rejection_kind": "no-added-boundary"}, ["bytes"],
            ),
        )

    def test_every_override_explains_the_branch_that_decided(self) -> None:
        detail = "trigger requires call-sequence outside attacker_controls=bytes"
        self.assertEqual(
            detail,
            triage._publication_detail(
                "not-reportable", "out-of-model", detail, {}, ["bytes"],
            ),
        )
        self.assertEqual(
            "source review placed the trigger within attacker_controls=bytes",
            triage._publication_detail(
                "reportable", "out-of-model", detail,
                {"trigger_controls_fit": "within"}, ["bytes"],
            ),
        )
        self.assertEqual(
            "confirmed probe placed the trigger within attacker_controls=bytes",
            triage._publication_detail(
                "reportable", "out-of-model", detail,
                {"trigger_controls_fit": "outside"}, ["bytes"],
                direct_trigger_proof=True,
            ),
        )
        contract_detail = "caller contract is missing"
        self.assertEqual(
            contract_detail,
            triage._publication_detail(
                "not-reportable", "contract-flag", contract_detail,
                {"trigger_controls_fit": "outside"}, ["bytes"],
            ),
        )
        self.assertEqual(
            triage._UNSETTLED_REVIEW_DETAIL,
            triage._publication_detail(
                "pending", "promote", "trigger within attacker_controls=bytes",
                {"trigger_controls_fit": "outside"}, ["bytes"],
            ),
        )


if __name__ == "__main__":
    unittest.main()
