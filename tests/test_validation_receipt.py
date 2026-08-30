#!/usr/bin/env python3
"""Content-addressed publication receipt behavior."""

from __future__ import annotations

import hashlib
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

    def test_source_attestation_invalidates_a_same_revision_source_edit(self) -> None:
        target = Path(self.temporary.name) / "targets" / "sampleproj"
        source = target / "src" / "sample.c"
        source.parent.mkdir(parents=True)
        excerpt = "if (length > capacity) return ERROR;"
        source.write_text(
            "int app_parse(void) {\n"
            f"  {excerpt}\n"
            "}\n",
            encoding="utf-8",
        )
        gate = self.directory / ".trigger-gate.json"
        gate.write_text(json.dumps({
            "vote": "Promote",
            "anchors_verified": True,
            "anchors": [{
                "path": "src/sample.c",
                "line": 2,
                "symbol": "app_parse",
                "kind": "source",
                "excerpt": excerpt,
                # The host must replace a reviewer-supplied digest.
                "excerpt_sha256": "not-authoritative",
            }],
        }), encoding="utf-8")

        with mock.patch.dict(os.environ, {
            "TARGET_ROOT": str(target),
            "TARGET_REV": "revision-a",
        }):
            payload = validation_receipt.write(
                self.directory,
                kind="finding",
                state="reportable",
                target_revision="revision-a",
                target_config_sha256="config-a",
            )
            self.assertEqual(
                payload["evidence"]["source_attestations"],
                [{
                    "review_artifact": ".trigger-gate.json",
                    "review_sha256": hashlib.sha256(
                        gate.read_bytes(),
                    ).hexdigest(),
                    "verifier": "source-anchor-v1",
                    "anchors": [{
                        "path": "src/sample.c",
                        "line": 2,
                        "symbol": "app_parse",
                        "kind": "source",
                        "excerpt": excerpt,
                        "excerpt_sha256": hashlib.sha256(
                            excerpt.encode(),
                        ).hexdigest(),
                    }],
                }],
            )
            self.assertIsNotNone(validation_receipt.read_current(self.directory))
            with mock.patch.dict(os.environ, {"TARGET_ROOT": ""}):
                self.assertIsNotNone(
                    validation_receipt.read_current(self.directory),
                )
            source.write_text(
                "int app_parse(void) {\n"
                "  if (length >= capacity) return ERROR;\n"
                "}\n",
                encoding="utf-8",
            )
            self.assertIsNone(validation_receipt.read_current(self.directory))

    def _source_attested_receipt(self) -> tuple[Path, Path, dict]:
        target = Path(self.temporary.name) / "targets" / "sampleproj"
        source = target / "src" / "sample.c"
        source.parent.mkdir(parents=True, exist_ok=True)
        excerpt = "if (length > capacity) return ERROR;"
        source.write_text(
            "int app_parse(void) {\n"
            f"  {excerpt}\n"
            "}\n",
            encoding="utf-8",
        )
        gate = self.directory / ".trigger-gate.json"
        gate.write_text(json.dumps({
            "vote": "Promote",
            "anchors": [{
                "path": "src/sample.c",
                "line": 2,
                "symbol": "app_parse",
                "kind": "source",
                "excerpt": excerpt,
            }],
        }), encoding="utf-8")
        with mock.patch.dict(os.environ, {"TARGET_ROOT": str(target)}):
            payload = validation_receipt.write(
                self.directory, kind="finding", state="reportable",
            )
        self.assertIsNotNone(payload)
        self.assertEqual(len(payload["evidence"]["source_attestations"]), 1)
        return target, gate, payload

    def test_equivalent_transform_preserves_attestation_without_checkout(
        self,
    ) -> None:
        _target, _gate, original = self._source_attested_receipt()
        with mock.patch.dict(os.environ, {"TARGET_ROOT": ""}):
            prior = validation_receipt.read_current(self.directory)
            rebound = validation_receipt.rewrite_after_equivalent_transform(
                self.directory, prior,
            )
            current = validation_receipt.read_current(self.directory)

        self.assertEqual(
            rebound["evidence"]["source_attestations"],
            original["evidence"]["source_attestations"],
        )
        self.assertIsNotNone(current)

    def test_equivalent_transform_rebinds_moved_review_by_digest(self) -> None:
        _target, gate, original = self._source_attested_receipt()
        with mock.patch.dict(os.environ, {"TARGET_ROOT": ""}):
            prior = validation_receipt.read_current(self.directory)
            audit = self.directory / ".audit"
            audit.mkdir()
            gate.replace(audit / gate.name)
            rebound = validation_receipt.rewrite_after_equivalent_transform(
                self.directory, prior,
            )
            current = validation_receipt.read_current(self.directory)

        self.assertEqual(
            rebound["evidence"]["source_attestations"][0]["review_artifact"],
            ".audit/.trigger-gate.json",
        )
        self.assertEqual(
            rebound["evidence"]["source_attestations"][0]["review_sha256"],
            original["evidence"]["source_attestations"][0]["review_sha256"],
        )
        self.assertIsNotNone(current)

    def test_equivalent_transform_reverifies_review_metadata_rewrite(self) -> None:
        target, gate, prior = self._source_attested_receipt()
        old_digest = prior["evidence"]["source_attestations"][0][
            "review_sha256"
        ]
        review = json.loads(gate.read_text(encoding="utf-8"))
        review["content_sha1"] = "updated-by-trusted-scoring-pass"
        gate.write_text(json.dumps(review), encoding="utf-8")

        with mock.patch.dict(os.environ, {"TARGET_ROOT": str(target)}):
            rebound = validation_receipt.rewrite_after_equivalent_transform(
                self.directory, prior,
            )
            current = validation_receipt.read_current(self.directory)

        self.assertIsNotNone(rebound)
        self.assertNotEqual(
            rebound["evidence"]["source_attestations"][0]["review_sha256"],
            old_digest,
        )
        self.assertEqual(
            rebound["evidence"]["source_attestations"][0]["anchors"],
            prior["evidence"]["source_attestations"][0]["anchors"],
        )
        self.assertIsNotNone(current)

    def test_equivalent_transform_preserves_scrubbed_review_without_checkout(
        self,
    ) -> None:
        _target, gate, prior = self._source_attested_receipt()
        old_digest = prior["evidence"]["source_attestations"][0][
            "review_sha256"
        ]
        review = json.loads(gate.read_text(encoding="utf-8"))
        review["rationale"] = "scrubbed representation no longer names /local"
        gate.write_text(json.dumps(review), encoding="utf-8")

        with mock.patch.dict(os.environ, {
            "TARGET_ROOT": "", "TARGET_REV": "",
        }):
            rebound = validation_receipt.rewrite_after_equivalent_transform(
                self.directory, prior,
            )
            current = validation_receipt.read_current(self.directory)

        self.assertIsNotNone(rebound)
        self.assertNotEqual(
            rebound["evidence"]["source_attestations"][0]["review_sha256"],
            old_digest,
        )
        self.assertIsNotNone(current)

    def test_unrelated_checkout_does_not_reverify_historical_attestation(
        self,
    ) -> None:
        target, gate, _original = self._source_attested_receipt()
        with mock.patch.dict(os.environ, {
            "TARGET_ROOT": str(target), "TARGET_REV": "revision-a",
        }), mock.patch.object(
            validation_receipt.target_config,
            "detect_rev",
            return_value="revision-a",
        ):
            prior = validation_receipt.write(
                self.directory,
                kind="finding",
                state="reportable",
                target_revision="revision-a",
            )
        audit = self.directory / ".audit"
        audit.mkdir()
        gate.replace(audit / gate.name)
        source = target / "src" / "sample.c"
        source.write_text(
            "int app_parse(void) {\n"
            "  if (length >= capacity) return ERROR;\n"
            "}\n",
            encoding="utf-8",
        )
        unrelated = Path(self.temporary.name) / "targets" / "otherproj"
        unrelated.mkdir()

        unrelated_environment = {"TARGET_ROOT": str(unrelated)}
        with mock.patch.dict(os.environ, unrelated_environment, clear=True), \
                mock.patch.object(
                    validation_receipt.target_config,
                    "detect_rev",
                    return_value="revision-b",
                ):
            rebound = validation_receipt.rewrite_after_equivalent_transform(
                self.directory, prior,
            )
            historical = validation_receipt.read_current(self.directory)

        self.assertIsNotNone(rebound)
        self.assertIsNotNone(historical)
        with mock.patch.dict(
            os.environ, {"TARGET_ROOT": str(target)}, clear=True,
        ), \
                mock.patch.object(
                    validation_receipt.target_config,
                    "detect_rev",
                    return_value="revision-a",
        ):
            self.assertIsNone(validation_receipt.read_current(self.directory))

    def test_plain_source_context_distinguishes_unrelated_roots(self) -> None:
        target, _gate, prior = self._source_attested_receipt()
        self.assertTrue(
            prior["evidence"]["source_context"].startswith(
                "root-path-sha256:",
            ),
        )
        unrelated = Path(self.temporary.name) / "targets" / "otherproj"
        unrelated.mkdir()

        with mock.patch.dict(
            os.environ, {"TARGET_ROOT": str(unrelated)}, clear=True,
        ):
            self.assertIsNotNone(
                validation_receipt.read_current(self.directory),
            )

        source = target / "src" / "sample.c"
        source.write_text(
            "int app_parse(void) { return ERROR; }\n",
            encoding="utf-8",
        )
        with mock.patch.dict(
            os.environ, {"TARGET_ROOT": str(target)}, clear=True,
        ):
            self.assertIsNone(validation_receipt.read_current(self.directory))

    def test_unrelated_checkout_cannot_mint_a_source_attestation(self) -> None:
        target, _gate, _original = self._source_attested_receipt()
        with mock.patch.dict(
            os.environ, {"TARGET_ROOT": str(target)}, clear=True,
        ), mock.patch.object(
            validation_receipt.target_config,
            "detect_rev",
            return_value="revision-b",
        ):
            payload = validation_receipt.write(
                self.directory,
                kind="finding",
                state="reportable",
                target_revision="revision-a",
            )

        self.assertEqual(payload["evidence"]["source_attestations"], [])

    def test_identical_reviews_keep_distinct_paths_across_export_move(self) -> None:
        target, first_gate, _original = self._source_attested_receipt()
        second_gate = self.directory / ".trigger-gate-2.json"
        second_gate.write_bytes(first_gate.read_bytes())
        with mock.patch.dict(os.environ, {"TARGET_ROOT": str(target)}):
            prior = validation_receipt.write(
                self.directory, kind="finding", state="reportable",
            )
        self.assertEqual(len(prior["evidence"]["source_attestations"]), 2)

        audit = self.directory / ".audit"
        audit.mkdir()
        first_gate.replace(audit / first_gate.name)
        second_gate.replace(audit / second_gate.name)
        with mock.patch.dict(os.environ, {"TARGET_ROOT": ""}):
            rebound = validation_receipt.rewrite_after_equivalent_transform(
                self.directory, prior,
            )
            without_checkout = validation_receipt.read_current(self.directory)

        self.assertEqual(
            [
                item["review_artifact"]
                for item in rebound["evidence"]["source_attestations"]
            ],
            [
                ".audit/.trigger-gate.json",
                ".audit/.trigger-gate-2.json",
            ],
        )
        self.assertIsNotNone(without_checkout)
        with mock.patch.dict(os.environ, {"TARGET_ROOT": str(target)}):
            self.assertIsNotNone(
                validation_receipt.read_current(self.directory),
            )

    def test_equivalent_transform_does_not_mint_an_unbound_attestation(self) -> None:
        _target, gate, _original = self._source_attested_receipt()
        with mock.patch.dict(os.environ, {"TARGET_ROOT": ""}):
            prior = validation_receipt.read_current(self.directory)
            gate.unlink()
            self.assertIsNone(
                validation_receipt.rewrite_after_equivalent_transform(
                    self.directory, prior,
                ),
            )
            self.assertIsNone(validation_receipt.read_current(self.directory))

    def test_equivalent_transform_cannot_drop_one_live_source_claim(self) -> None:
        target = Path(self.temporary.name) / "targets" / "sampleproj"
        source = target / "src" / "sample.c"
        source.parent.mkdir(parents=True)
        first = "if (length > capacity) return ERROR;"
        second = "if (offset > length) return ERROR;"
        source.write_text(
            "int app_parse(void) {\n"
            f"  {first}\n"
            f"  {second}\n"
            "}\n",
            encoding="utf-8",
        )
        gate = self.directory / ".trigger-gate.json"
        gate.write_text(json.dumps({
            "vote": "Promote",
            "anchors": [
                {
                    "path": "src/sample.c", "line": 2,
                    "symbol": "app_parse", "kind": "source",
                    "excerpt": first,
                },
                {
                    "path": "src/sample.c", "line": 3,
                    "symbol": "app_parse", "kind": "source",
                    "excerpt": second,
                },
            ],
        }), encoding="utf-8")
        with mock.patch.dict(os.environ, {"TARGET_ROOT": str(target)}):
            prior = validation_receipt.write(
                self.directory, kind="finding", state="reportable",
            )
            self.assertEqual(
                len(prior["evidence"]["source_attestations"][0]["anchors"]),
                2,
            )
            source.write_text(
                "int app_parse(void) {\n"
                f"  {first}\n"
                "  if (offset >= length) return ERROR;\n"
                "}\n",
                encoding="utf-8",
            )
            self.assertIsNone(
                validation_receipt.rewrite_after_equivalent_transform(
                    self.directory, prior,
                ),
            )

    def test_unverifiable_review_anchors_are_not_attested(self) -> None:
        target = Path(self.temporary.name) / "targets" / "sampleproj"
        source = target / "src" / "sample.c"
        source.parent.mkdir(parents=True)
        source.write_text(
            "int app_parse(void) { return 0; }\n", encoding="utf-8",
        )
        (self.directory / ".trigger-gate.json").write_text(json.dumps({
            "vote": "Promote",
            "anchors_verified": True,
            "anchors": [
                {
                    "path": "../outside.c", "line": 1,
                    "symbol": "app_parse", "kind": "source",
                    "excerpt": "int app_parse(void) { return 0; }",
                },
                {
                    "path": "src/sample.c", "line": 1,
                    "symbol": "app_parse", "kind": "source",
                    "excerpt": "different source line",
                },
            ],
        }), encoding="utf-8")

        with mock.patch.dict(os.environ, {"TARGET_ROOT": str(target)}):
            payload = validation_receipt.write(
                self.directory, kind="finding", state="pending",
            )
        self.assertEqual(payload["evidence"]["source_attestations"], [])

    def test_legacy_receipt_without_source_attestations_remains_current(self) -> None:
        payload = validation_receipt.write(
            self.directory, kind="finding", state="reportable",
        )
        evidence = payload["evidence"]
        evidence.pop("source_attestations")
        identity = {
            key: value for key, value in evidence.items()
            if key != "evidence_id"
        }
        evidence["evidence_id"] = hashlib.sha256(json.dumps(
            identity, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        (self.directory / "validation.json").write_text(
            json.dumps(payload), encoding="utf-8",
        )

        self.assertIsNotNone(validation_receipt.read_current(self.directory))

    def test_reading_a_legacy_receipt_asks_the_vcs_nothing(self) -> None:
        """A read discards a fresh source claim, so it must not derive one.

        Deriving one runs `detect_rev`, and each call is two subprocesses on a
        git checkout. `read_current` runs once per artifact across whole pool
        trees, so a derivation whose result is thrown away is paid for on
        every one of them.
        """
        # A pinned revision is what reaches `detect_rev`; an unpinned one
        # short-circuits to the checkout-path identity before asking.
        payload = validation_receipt.write(
            self.directory, kind="finding", state="reportable",
            target_revision="a" * 40,
        )
        evidence = payload["evidence"]
        evidence.pop("source_attestations")
        identity = {
            key: value for key, value in evidence.items()
            if key != "evidence_id"
        }
        evidence["evidence_id"] = hashlib.sha256(json.dumps(
            identity, sort_keys=True, separators=(",", ":"),
        ).encode()).hexdigest()
        (self.directory / "validation.json").write_text(
            json.dumps(payload), encoding="utf-8",
        )
        target = Path(self.temporary.name) / "src"
        target.mkdir(parents=True, exist_ok=True)

        with mock.patch.dict(os.environ, {"TARGET_ROOT": str(target)}):
            with mock.patch.object(
                validation_receipt.target_config, "detect_rev",
                side_effect=AssertionError("read_current derived a revision"),
            ):
                self.assertIsNotNone(
                    validation_receipt.read_current(self.directory),
                )

    def test_writing_a_receipt_derives_the_revision_once(self) -> None:
        """The mint already proves which checkout it described.

        `_new_source_context` returns a revision context only when the live
        checkout is already at that revision, so asking again to confirm the
        match repeats two subprocesses for an answer just computed.
        """
        target = Path(self.temporary.name) / "src"
        target.mkdir(parents=True, exist_ok=True)
        calls: list[str] = []

        def counted(root: object) -> str:
            calls.append(str(root))
            return "a" * 40

        with mock.patch.dict(os.environ, {"TARGET_ROOT": str(target)}):
            with mock.patch.object(
                validation_receipt.target_config, "detect_rev", counted,
            ):
                payload = validation_receipt.write(
                    self.directory, kind="finding", state="reportable",
                    target_revision="a" * 40,
                )

        self.assertIsNotNone(payload)
        self.assertEqual(len(calls), 1, calls)


if __name__ == "__main__":
    unittest.main()
