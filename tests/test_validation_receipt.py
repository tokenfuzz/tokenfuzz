#!/usr/bin/env python3
"""Content-addressed publication receipt behavior."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import validation_receipt  # noqa: E402


class ValidationReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="validation-receipt-")
        self.directory = Path(self.temporary.name) / "findings" / "FIND-001"
        self.directory.mkdir(parents=True)
        self.report = self.directory / "report.md"
        self.report.write_text("# Boundary issue\n\nSource-backed consequence.\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_receipt_is_current_only_for_the_evidence_it_validated(self) -> None:
        payload = validation_receipt.write(
            self.directory,
            kind="finding",
            state="reportable",
            target_revision="revision-a",
            target_config_sha256="config-a",
            attacker_controls=["bytes"],
        )
        self.assertIsNotNone(payload)
        self.assertEqual(
            validation_receipt.read_current(self.directory)["state"],
            "reportable",
        )
        self.report.write_text(
            "# Boundary issue\n\nA materially different consequence.\n",
            encoding="utf-8",
        )
        self.assertIsNone(validation_receipt.read_current(self.directory))

    def test_small_mutable_evidence_is_never_served_from_the_memo(self) -> None:
        # Gate caches are small and rewritten in place. A same-size rewrite can
        # land inside the filesystem's mtime granularity, so these must be
        # re-digested every time rather than memoized on stat data.
        gate = self.directory / ".trigger-gate.json"
        gate.write_text('{"vote": "Promote"}', encoding="utf-8")
        first = validation_receipt.evidence_record(self.directory)
        stat = gate.stat()
        gate.write_text('{"vote": "Rejects"}', encoding="utf-8")
        os.utime(gate, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        self.assertEqual(gate.stat().st_size, stat.st_size)
        self.assertNotEqual(
            first["evidence_id"],
            validation_receipt.evidence_record(self.directory)["evidence_id"],
        )

    def test_trigger_resolution_is_bound_as_publication_evidence(self) -> None:
        resolution = self.directory / ".trigger-gate-resolution.json"
        resolution.write_text('{"vote": "Promote"}', encoding="utf-8")
        validation_receipt.write(
            self.directory, kind="finding", state="reportable",
        )
        self.assertIsNotNone(validation_receipt.read_current(self.directory))
        resolution.write_text('{"vote": "Rejects"}', encoding="utf-8")
        self.assertIsNone(validation_receipt.read_current(self.directory))

    def test_large_evidence_memo_still_notices_a_rewrite(self) -> None:
        # Large reproducers are memoized so one pass digests them once across
        # the several consumers that rebuild the record. Restoring mtime after
        # a same-size rewrite must not resurrect the cached digest.
        testcase = self.directory / "input.bin"
        with mock.patch.object(
            validation_receipt, "_DIGEST_MEMO_MIN_BYTES", 1,
        ):
            testcase.write_bytes(b"original")
            first = validation_receipt.evidence_record(self.directory)
            self.assertEqual(
                first, validation_receipt.evidence_record(self.directory),
            )
            stat = testcase.stat()
            testcase.write_bytes(b"changed!")
            os.utime(
                testcase, ns=(stat.st_atime_ns, stat.st_mtime_ns),
            )
            self.assertEqual(testcase.stat().st_size, stat.st_size)
            self.assertNotEqual(
                first["evidence_id"],
                validation_receipt.evidence_record(self.directory)["evidence_id"],
            )

    def test_primary_build_differential_is_receipt_evidence(self) -> None:
        result = self.directory / ".primary-build-differential.json"
        sanitizer = self.directory / ".primary-build-sanitizer.txt"
        result.write_text(
            '{"version":1,"status":"not-reproduced"}\n', encoding="utf-8",
        )
        sanitizer.write_text("CRASH_RATE: 0/5\n", encoding="utf-8")
        validation_receipt.write(
            self.directory, kind="finding", state="not-reportable",
        )
        self.assertIsNotNone(validation_receipt.read_current(self.directory))
        result.write_text(
            '{"version":1,"status":"reproduced"}\n', encoding="utf-8",
        )
        self.assertIsNone(validation_receipt.read_current(self.directory))
        validation_receipt.write(
            self.directory, kind="finding", state="not-reportable",
        )
        self.assertIsNotNone(validation_receipt.read_current(self.directory))
        sanitizer.write_text("CRASH_RATE: 5/5\n", encoding="utf-8")
        self.assertIsNone(validation_receipt.read_current(self.directory))

    def test_testcase_or_diagnostic_change_invalidates_the_receipt(self) -> None:
        (self.directory / "input.bin").write_bytes(b"original")
        (self.directory / "sanitizer.txt").write_text(
            "ERROR: AddressSanitizer: heap-buffer-overflow\n",
            encoding="utf-8",
        )
        validation_receipt.write(
            self.directory, kind="finding", state="not-reportable",
            attacker_controls=["bytes"],
        )
        self.assertIsNotNone(validation_receipt.read_current(self.directory))
        (self.directory / "input.bin").write_bytes(b"changed")
        self.assertIsNone(validation_receipt.read_current(self.directory))

    def test_receipt_binds_bundled_testcase_not_external_header_path(self) -> None:
        scratch = Path(self.temporary.name) / "scratch" / "input.bin"
        scratch.parent.mkdir()
        scratch.write_bytes(b"mutable scratch")
        bundled = self.directory / "input.bin"
        bundled.write_bytes(b"immutable bundle")
        (self.directory / "sanitizer.txt").write_text(
            "ASAN_RUN_HEADER: "
            f"testcase={scratch}\n"
            "ERROR: AddressSanitizer: heap-buffer-overflow\n",
            encoding="utf-8",
        )
        payload = validation_receipt.write(
            self.directory, kind="finding", state="not-reportable",
            attacker_controls=["bytes"],
        )
        self.assertIsNotNone(payload)
        self.assertIn("input.bin", payload["evidence"]["artifacts"])
        self.assertIsNotNone(validation_receipt.read_current(self.directory))
        scratch.write_bytes(b"changed scratch")
        self.assertIsNotNone(validation_receipt.read_current(self.directory))
        bundled.write_bytes(b"changed bundle")
        self.assertIsNone(validation_receipt.read_current(self.directory))

    def test_receipt_file_is_never_mistaken_for_a_testcase(self) -> None:
        validation_receipt.write(
            self.directory, kind="finding", state="pending",
            attacker_controls=["bytes"],
        )
        payload = json.loads((self.directory / "validation.json").read_text())
        self.assertEqual(payload["evidence"]["artifacts"], {})
        self.assertIsNotNone(validation_receipt.read_current(self.directory))

    def test_pending_receipt_binds_an_absent_report_until_content_arrives(self) -> None:
        self.report.unlink()
        self.assertIsNone(validation_receipt.write(
            self.directory, kind="finding", state="reportable",
        ))
        pending = validation_receipt.write(
            self.directory, kind="finding", state="pending",
            detail="missing report",
        )
        self.assertIsNotNone(pending)
        self.assertEqual(pending["evidence"]["report_sha1"], "")
        self.assertIsNotNone(validation_receipt.read_current(self.directory))
        self.report.write_text(
            "# Boundary issue\n\nContent arrived.\n", encoding="utf-8",
        )
        self.assertIsNone(validation_receipt.read_current(self.directory))

    def test_generated_enrichment_code_fence_does_not_stale_receipt(self) -> None:
        validation_receipt.write(
            self.directory, kind="finding", state="reportable",
            attacker_controls=["bytes"],
        )
        self.report.write_text(
            self.report.read_text(encoding="utf-8")
            + "\n<!-- enrich:data-flow-snippets -->\n"
            + "```text\n"
            + "generated source excerpt\n"
            + "```\n"
            + "<!-- /enrich:data-flow-snippets -->\n",
            encoding="utf-8",
        )
        self.assertIsNotNone(validation_receipt.read_current(self.directory))

    def test_explicit_scope_change_invalidates_the_receipt(self) -> None:
        validation_receipt.write(
            self.directory,
            kind="finding",
            state="reportable",
            target_revision="revision-a",
            target_config_sha256="config-a",
            attacker_controls=["bytes"],
        )
        with mock.patch.dict(os.environ, {"TARGET_REV": "revision-b"}):
            self.assertIsNone(validation_receipt.read_current(self.directory))
        with mock.patch.dict(
            os.environ,
            {"TARGET_ATTACKER_CONTROLS_CSV": "bytes,call-sequence"},
        ):
            self.assertIsNone(validation_receipt.read_current(self.directory))


if __name__ == "__main__":
    unittest.main()
