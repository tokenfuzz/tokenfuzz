#!/usr/bin/env python3
"""Regression coverage for incremental, recall-safe finding validation."""

from __future__ import annotations

import contextlib
import io
import json
import hashlib
import os
import runpy
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner  # noqa: E402
import benchmark  # noqa: E402
import crash_bundle  # noqa: E402
import finding_signature  # noqa: E402
import llm_decide  # noqa: E402
import report_identity  # noqa: E402
import target_config  # noqa: E402
import triage  # noqa: E402
import triage_validate  # noqa: E402
import validation_receipt  # noqa: E402


def quality_vote(item_id: str, accept: bool = True) -> dict:
    return {
        "items": [{
            "id": item_id,
            "accept": accept,
            "reason": "concrete boundary issue" if accept else "not security relevant",
            "class": "auth:bypass" if accept else "",
            "severity": "high" if accept else "",
        }]
    }


def source_anchor(target_root: Path) -> dict:
    source = target_root / "sample.c"
    excerpt = "int app_parse(void) { return 0; }"
    source.write_text(excerpt + "\n", encoding="utf-8")
    return {
        "path": "sample.c",
        "line": 1,
        "symbol": "app_parse",
        "kind": "source",
        "excerpt": excerpt,
        "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
    }


def trigger_vote(
    report: Path, target_root: Path, vote: str = "Promote",
    *, controls: list[str] | None = None,
) -> dict:
    evidence = crash_bundle.recorded_evidence_context(report.parent)
    payload = {
        "vote": vote,
        "content_sha1": report_identity.content_sha1(report),
        "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
        "attacker_controls": (
            controls
            if controls is not None
            else triage_validate.trigger_attacker_controls()
        ),
        "anchors": [source_anchor(target_root)],
        "anchors_verified": True,
        "target_revision": str(
            (evidence or {}).get("target_revision")
            or os.environ.get("TARGET_REV", ""),
        ),
        "target_config_sha256": str(
            (evidence or {}).get("target_config_sha256")
            or os.environ.get("TARGET_CONFIG_SHA256", ""),
        ),
    }
    if evidence is not None:
        payload["evidence_id"] = evidence["evidence_id"]
    if vote == "Reject":
        payload["review_facts"] = {"rejection_kind": "contract-invalid"}
    elif vote == "Promote":
        # A compliant reviewer answers the scope question on every Promote;
        # tests for a review that did not set `review_facts` themselves.
        payload["review_facts"] = {"trigger_controls_fit": "within"}
    return payload


def trigger_resolution_vote(
    report: Path, target_root: Path, prior_reviews: list[Path],
    vote: str = "Promote",
) -> dict:
    payload = trigger_vote(report, target_root, vote)
    payload["decision_version"] = (
        triage_validate.TRIGGER_RESOLUTION_DECISION_VERSION
    )
    payload["prior_review_sha256s"] = triage_validate.prior_review_sha256s(
        prior_reviews,
    )
    return payload


def _write_batch_votes(command: list[str], only: set[str] | None = None) -> None:
    """Simulate the batched trigger validator: write a valid cached vote for each
    manifest item (optionally only a subset), so the caller sees those ids as
    voted and the rest as still-missing."""
    manifest = Path(command[command.index("--batch-manifest") + 1])
    target_root = Path(command[command.index("--target-path") + 1])
    for item in json.loads(manifest.read_text(encoding="utf-8"))["items"]:
        if only is not None and item["id"] not in only:
            continue
        finding = Path(item["finding"])
        Path(item["output"]).write_text(
            json.dumps(trigger_vote(finding, target_root)),
            encoding="utf-8",
        )


class IncrementalFindingValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="triage-incremental-")
        self.root = Path(self.temp.name)
        self.finding = self.root / "findings" / "FIND-001"
        self.finding.mkdir(parents=True)
        self.report = self.finding / "report.md"
        self.report.write_text(
            "# State issue\n\nA caller-controlled request crosses an authorization boundary.\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _gate(self) -> dict[str, int]:
        with mock.patch.object(
            triage, "_finalize_accepted_finding", return_value="accepted",
        ), mock.patch.object(
            triage, "_prepare_accepted_finding", return_value=self.report,
        ), mock.patch.object(
            triage, "_batch_reach_field_decisions", return_value=(set(), {}, set()),
        ):
            return triage.validate_find_gate(self.root, workers=2)

    def test_human_override_is_materialized_as_a_validation_receipt(self) -> None:
        with self.report.open("a", encoding="utf-8") as stream:
            stream.write(
                "\nSurface: network\n"
                "Primitive: authz_bypass\n"
                "Class: authorization\n"
                "Caller contract: obeyed\n"
                "Caller controls: bytes\n"
                "Trigger source: bytes\n"
                "Parameter control: direct\n"
                "Trusted caller actions: normal public call\n"
                "Boundary: public request handler\n"
                "Advisory: no\n"
            )
        (self.finding / ".keep").touch()
        with mock.patch.object(triage, "_run_tool") as scorer:
            self.assertEqual(
                triage.validate_one_finding(self.finding, self.root),
                "accepted",
            )
        receipt = validation_receipt.read_current(self.finding)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "reportable")
        scorer.assert_called_once_with(
            "severity", "--report", str(self.finding),
        )

    def test_human_override_with_missing_facts_remains_pending(self) -> None:
        (self.finding / ".reviewed").touch()
        self.assertEqual(
            triage.validate_one_finding(self.finding, self.root),
            "pending",
        )
        receipt = validation_receipt.read_current(self.finding)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "pending")

    def test_reportless_finding_is_explicitly_pending_not_legacy(self) -> None:
        self.report.unlink()
        self.assertEqual(
            triage.validate_one_finding(
                self.finding, self.root, deadline=0,
            ),
            "pending",
        )
        receipt = validation_receipt.read_current(self.finding)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "pending")
        metrics = benchmark.harvest(self.root)
        lanes = metrics["validation_waterfall"]["findings"]["lanes"]
        self.assertEqual(lanes["pending"], 1)
        self.assertEqual(lanes["legacy-provisional"], 0)

    def test_finished_drain_rejects_a_reportless_finding(self) -> None:
        self.report.unlink()
        with mock.patch.dict(os.environ, {"LLM_DECIDE_DISABLE": "1"}):
            self.assertEqual(
                triage.validate_find_gate(
                    self.root, reject_missing_reports=True,
                ),
                {"accepted": 0, "rejected": 1, "pending": 0},
            )
        self.assertFalse(self.finding.exists())
        rejected = self.root / "findings-rejected" / self.finding.name
        self.assertTrue(rejected.is_dir())
        receipt = validation_receipt.read_current(rejected)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "rejected")
        self.assertEqual(
            receipt["detail"],
            "incomplete missing: missing report.md",
        )

    def test_partial_vote_survives_pass_and_completes_quorum_once(self) -> None:
        with mock.patch.object(
            triage.llm_decide, "llm_decide",
            side_effect=[quality_vote(self.finding.name), None, None],
        ) as first_calls:
            self.assertEqual(self._gate(), {"accepted": 0, "rejected": 0, "pending": 1})
        progress = json.loads((self.finding / ".llm-find-quality.json").read_text())
        self.assertNotIn("accept", progress)
        self.assertEqual((progress["accept_count"], len(progress["votes"])), (1, 1))
        self.assertEqual(first_calls.call_count, 3)

        with mock.patch.object(
            triage.llm_decide, "llm_decide",
            return_value=quality_vote(self.finding.name),
        ) as second_calls:
            self.assertEqual(self._gate(), {"accepted": 1, "rejected": 0, "pending": 0})
        terminal = json.loads((self.finding / ".llm-find-quality.json").read_text())
        self.assertIs(terminal["accept"], True)
        self.assertEqual((terminal["accept_count"], len(terminal["votes"])), (2, 2))
        self.assertEqual(terminal["report_sha1"], report_identity.content_sha1(self.report))
        self.assertEqual(second_calls.call_count, 1)

    def test_report_edit_invalidates_terminal_acceptance_before_retry(self) -> None:
        cache = self.finding / ".llm-find-quality.json"
        cache.write_text(json.dumps({
            "decision_version": report_identity.FIND_QUALITY_DECISION_VERSION,
            "content_sha1": "stale",
            "accept": True,
            "accept_count": 2,
            "reason": "old report",
            "class": "auth:bypass",
            "severity": "high",
        }))
        with mock.patch.object(triage.llm_decide, "llm_decide", return_value=None):
            self.assertEqual(self._gate(), {"accepted": 0, "rejected": 0, "pending": 1})
        invalidated = json.loads(cache.read_text())
        self.assertNotIn("accept", invalidated)
        self.assertEqual(invalidated["content_sha1"], triage._quality_content_sha1(
            triage.read_report_bounded(self.report)
        ))

    def test_report_edit_cannot_replay_a_stale_rejection(self) -> None:
        cache = self.finding / ".llm-find-quality.json"
        cache.write_text(json.dumps({
            "decision_version": report_identity.FIND_QUALITY_DECISION_VERSION,
            "content_sha1": "stale",
            "accept": False,
            "reject_count": 2,
            "reason": "old report",
        }))
        with mock.patch.object(triage.llm_decide, "llm_decide", return_value=None):
            self.assertEqual(self._gate(), {"accepted": 0, "rejected": 0, "pending": 1})
        self.assertTrue(self.finding.is_dir())
        self.assertNotIn("accept", json.loads(cache.read_text()))

    def test_rejection_replaces_the_originating_hypothesis_artifact_status(self) -> None:
        state = self.root / "state"
        state.mkdir()
        (state / "hypotheses.jsonl").write_text(json.dumps({
            "id": "H-1",
            "agent": "1",
            "card_id": "WORK-A",
            "status": "FIND-001",
            "file": "src/sample.c:app_parse:91",
            "subsystem": "src",
        }) + "\n", encoding="utf-8")
        report_text = triage.read_report_bounded(self.report)
        reject = quality_vote(self.finding.name, accept=False)["items"][0]
        (self.finding / ".llm-find-quality.json").write_text(json.dumps(
            triage._quality_payload(
                report_text, [reject, reject], 2, 2,
                report_identity.content_sha1(self.report),
            )
        ))

        self.assertEqual(
            triage.validate_one_finding(self.finding, self.root), "rejected",
        )

        latest = json.loads((state / "hypotheses.jsonl").read_text().splitlines()[-1])
        self.assertEqual(latest["status"], "DISCARDED")
        self.assertIn("Triage rejected FIND-001", latest["note"])
        self.assertTrue((self.root / "findings-rejected/FIND-001/REJECTION.md").is_file())

    def test_full_semantic_identity_is_authoritative_for_new_cache(self) -> None:
        report_text = triage.read_report_bounded(self.report)
        payload = triage._quality_payload(
            report_text,
            [
                quality_vote(self.finding.name)["items"][0],
                quality_vote(self.finding.name)["items"][0],
            ],
            2,
            2,
            report_identity.content_sha1(self.report),
        )
        # A generated annotation can move the bounded head/tail cut points in
        # a large report without changing its full semantic identity.
        payload["content_sha1"] = "different-bounded-view"
        (self.finding / ".llm-find-quality.json").write_text(json.dumps(payload))

        with mock.patch.object(triage.llm_decide, "llm_decide") as decide:
            self.assertEqual(self._gate(), {"accepted": 1, "rejected": 0, "pending": 0})
        decide.assert_not_called()

    def test_pre_canonicalization_verdicts_survive_the_table_hash_transition(self) -> None:
        controls = ["bytes"]
        self.report.write_text(
            "# State issue\n\n"
            "| Field | Value |\n"
            "| --- | --- |\n"
            "| Boundary | caller-controlled |\n",
            encoding="utf-8",
        )
        report_text = self.report.read_text(encoding="utf-8")
        legacy_sha1 = report_identity.legacy_semantic_text_sha1(report_text)
        self.assertNotEqual(legacy_sha1, report_identity.content_sha1(self.report))

        quality = {
            "decision_version": report_identity.FIND_QUALITY_DECISION_VERSION,
            "report_sha1": legacy_sha1,
            "accept": True,
        }
        quality_path = self.finding / ".llm-find-quality.json"
        quality_path.write_text(json.dumps(quality), encoding="utf-8")
        self.assertTrue(report_identity.quality_cache_matches_report(self.finding, quality))
        self.assertTrue(triage._quality_cache_matches(
            quality_path, quality, self.report, report_text,
        ))

        trigger = trigger_vote(
            self.report, self.root, controls=controls,
        )
        trigger["content_sha1"] = legacy_sha1
        trigger_path = self.finding / ".trigger-gate.json"
        trigger_path.write_text(json.dumps(trigger), encoding="utf-8")
        with mock.patch.object(
            triage_validate, "trigger_attacker_controls", return_value=controls,
        ):
            self.assertEqual(
                triage._cached_trigger_vote(self.report, trigger_path), "Promote",
            )
        self.assertTrue(benchmark._finding_trigger_kept(self.finding))

        self.report.write_text(
            report_text.replace("caller-controlled", "trusted-only"),
            encoding="utf-8",
        )
        self.assertFalse(report_identity.quality_cache_matches_report(self.finding, quality))
        self.assertIsNone(triage._cached_trigger_vote(self.report, trigger_path))
        self.assertFalse(benchmark._finding_trigger_kept(self.finding))

    def test_finalizer_advances_content_key_after_harness_enrichment(self) -> None:
        original = triage.read_report_bounded(self.report)
        cache = self.finding / ".llm-find-quality.json"
        cache.write_text(json.dumps(triage._quality_payload(
            original,
            [
                quality_vote(self.finding.name)["items"][0],
                quality_vote(self.finding.name)["items"][0],
            ],
            2,
            2,
        )))

        def enrich(*_args, **_kwargs):
            self.report.write_text(
                self.report.read_text() + "\nSurface: library-api\n",
                encoding="utf-8",
            )
            return False

        def score(*_args, **_kwargs):
            self.report.write_text(
                self.report.read_text() + "\n## Severity rationale\n\nGenerated.\n",
                encoding="utf-8",
            )
            return 0

        with mock.patch.object(triage, "fill_reach_fields", side_effect=enrich), mock.patch.object(
            triage, "_finding_trigger_disposition", return_value="accepted",
        ), mock.patch.object(
            triage, "evaluate_crash_verdict", return_value=("promote", ""),
        ), mock.patch.object(
            triage, "_run_tool", side_effect=score,
        ), mock.patch.object(
            triage, "_record_accepted_finding_card",
        ) as record_productive:
            self.assertEqual(
                triage._finalize_accepted_finding(
                    self.finding, self.root, self.report, None,
                ),
                "accepted",
            )
        record_productive.assert_called_once_with(self.finding, self.root)
        finalized = json.loads(cache.read_text())
        self.assertEqual(
            finalized["content_sha1"],
            triage._quality_content_sha1(triage.read_report_bounded(self.report)),
        )
        self.assertEqual(finalized["report_sha1"], report_identity.content_sha1(self.report))

    def test_harness_annotations_do_not_invalidate_semantic_content_key(self) -> None:
        base = "# State issue\n\nCaller-controlled data crosses a boundary.\n"
        generated = base + """
Cluster: CL-state-1
Dedup key: [loc] sample.c:10
| Severity | High (CVSS-BTE 4.0: 8.1) |

<!-- enrich:tldr -->
> Generated summary.
<!-- /enrich:tldr -->

## Patch

Generated patch text.

## Severity rationale

Generated score text.
"""
        self.assertEqual(
            triage._quality_content_sha1(base),
            triage._quality_content_sha1(generated),
        )
        self.assertNotEqual(
            triage._quality_content_sha1(base),
            triage._quality_content_sha1(base.replace("crosses", "does not cross")),
        )
        self.assertNotEqual(
            triage._quality_content_sha1(base),
            triage._quality_content_sha1(
                base + "\n## Reachability — external callers\n\nSubstantive path.\n"
            ),
        )
        fenced = base + "\n```text\n## Patch\nsubstantive example\n```\n"
        self.assertNotEqual(
            triage._quality_content_sha1(fenced),
            triage._quality_content_sha1(fenced.replace("substantive", "changed")),
        )
        generated_code = (
            base
            + "\n<!-- enrich:data-flow-snippets -->\n"
            + "```text\n"
            + "generated source excerpt\n"
            + "```\n"
            + "<!-- /enrich:data-flow-snippets -->\n"
        )
        self.assertEqual(
            triage._quality_content_sha1(base),
            triage._quality_content_sha1(generated_code),
        )
        contract_before_bare_summary = (
            "## Contract concern\n\nGenerated concern.\n\n"
            "Summary: substantive agent analysis\n"
        )
        self.assertNotEqual(
            triage._quality_content_sha1(contract_before_bare_summary),
            triage._quality_content_sha1(
                contract_before_bare_summary.replace("agent analysis", "revised analysis")
            ),
        )

    def test_contract_concern_writer_and_stripper_share_one_vocabulary(self) -> None:
        # The triage writer and report_identity stripper must not desync: a
        # harness-inserted contract concern stays cache-neutral, while real
        # prose beneath it still changes identity.
        before = report_identity.content_sha1(self.report)
        triage._set_contract_concern(self.report, "caller supplies the length")
        self.assertIn(
            report_identity.CONTRACT_CONCERN_HEADING,
            self.report.read_text(encoding="utf-8"),
        )
        self.assertEqual(before, report_identity.content_sha1(self.report))
        self.report.write_text(
            self.report.read_text(encoding="utf-8").replace("crosses", "does not cross"),
            encoding="utf-8",
        )
        self.assertNotEqual(before, report_identity.content_sha1(self.report))

    def test_table_padding_does_not_invalidate_report_identity(self) -> None:
        self.report.write_text(
            "# State issue\n\n| Field | Value |\n| --- | --- |\n"
            "| Boundary | caller-controlled request |\n",
            encoding="utf-8",
        )
        before = report_identity.content_sha1(self.report)
        subprocess.run(
            [sys.executable, str(ROOT / "bin" / "render-md"), str(self.report)],
            check=True,
        )
        self.assertEqual(before, report_identity.content_sha1(self.report))
        self.report.write_text(
            self.report.read_text().replace("caller-controlled", "trusted"),
            encoding="utf-8",
        )
        self.assertNotEqual(before, report_identity.content_sha1(self.report))

    def test_a_raw_pipe_in_one_cell_does_not_repad_every_row_s_identity(self) -> None:
        # A value holding a raw `|` reads as a cell break, so padding widens the
        # whole table. That is still padding: it must not restate the identity a
        # severity or validation receipt already bound, or the pool audit fails
        # a finished run over its own cosmetic rewrite.
        for stray in ("parse with FLAG_LOAD | FLAG_VALID", "parse with FLAG_LOAD |"):
            with self.subTest(stray=stray):
                self.report.write_text(
                    "# State issue\n\n| Field | Value |\n| --- | --- |\n"
                    "| Boundary | caller-controlled request |\n"
                    f"| Trusted caller actions | {stray} |\n",
                    encoding="utf-8",
                )
                before = report_identity.content_sha1(self.report)
                subprocess.run(
                    [sys.executable, str(ROOT / "bin" / "render-md"), str(self.report)],
                    check=True,
                )
                header = self.report.read_text(encoding="utf-8").splitlines()[2]
                self.assertEqual(len(header.strip().strip("|").split("|")), 3)
                self.assertEqual(before, report_identity.content_sha1(self.report))
                self.report.write_text(
                    self.report.read_text().replace("caller-controlled", "trusted"),
                    encoding="utf-8",
                )
                self.assertNotEqual(before, report_identity.content_sha1(self.report))

    def _receipt_bound_to(self, sha1: str) -> None:
        """Stand in for a receipt a prior version of this module wrote."""
        validation_receipt.write(
            self.finding, kind="finding", state="reportable",
            attacker_controls=triage_validate.trigger_attacker_controls(),
        )
        path = self.finding / "validation.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["report_sha1"] = sha1
        path.write_text(json.dumps(payload), encoding="utf-8")

    def test_a_receipt_bound_before_padding_trimming_stays_current(self) -> None:
        # Trimming padded columns moved the identity of every already-widened
        # report. Carrying the prior identity keeps their concluded reviews —
        # the alternative is the pool audit refusing a finished run over a
        # harness-side identity change no reviewer caused.
        self.report.write_text(
            "# State issue\n\n| Field | Value | |\n| --- | --- | --- |\n"
            "| Boundary | caller-controlled | |\n",
            encoding="utf-8",
        )
        report_text = self.report.read_text(encoding="utf-8")
        legacy_sha1 = report_identity.legacy_padded_table_semantic_text_sha1(report_text)
        self.assertNotEqual(legacy_sha1, report_identity.content_sha1(self.report))
        self._receipt_bound_to(legacy_sha1)
        self.assertIsNotNone(validation_receipt.read_current(self.finding))

    def test_a_receipt_bound_before_enrich_stripping_stays_current(self) -> None:
        # Enrich stripping predates padding trimming, so the identities that
        # helper reproduces were written at the padded width. Trimming them too
        # computes a combination no version ever wrote and strands the receipts
        # the helper exists to keep — and reads identical to the correct value
        # unless a padded report is compared against its unpadded twin.
        body = (
            "# State issue\n\n{table}\n"
            "<!-- enrich:callers -->\n```\napp_parse\n```\n<!-- /enrich:callers -->\n"
        )
        narrow = body.format(table=(
            "| Field | Value |\n| --- | --- |\n| Boundary | caller-controlled |\n"
        ))
        padded = body.format(table=(
            "| Field | Value | |\n| --- | --- | --- |\n| Boundary | caller-controlled | |\n"
        ))
        self.assertEqual(
            report_identity.semantic_text_sha1(narrow),
            report_identity.semantic_text_sha1(padded),
        )
        self.assertNotEqual(
            report_identity.legacy_enrich_semantic_text_sha1(narrow),
            report_identity.legacy_enrich_semantic_text_sha1(padded),
        )
        self.report.write_text(padded, encoding="utf-8")
        self._receipt_bound_to(
            report_identity.legacy_enrich_semantic_text_sha1(padded),
        )
        self.assertIsNotNone(validation_receipt.read_current(self.finding))

    def test_a_short_separator_table_survives_rendering(self) -> None:
        # `| - | - |` is a valid GFM separator that render-md pads. Identity has
        # to recognize the same tables the padder does, or the padding it calls
        # cosmetic invalidates a concluded review.
        self.report.write_text(
            "# State issue\n\n| Field | Value |\n| - | - |\n"
            "| Boundary | caller-controlled |\n",
            encoding="utf-8",
        )
        self._receipt_bound_to(report_identity.content_sha1(self.report))
        subprocess.run(
            [sys.executable, str(ROOT / "bin" / "render-md"), str(self.report)],
            check=True,
        )
        self.assertIsNotNone(validation_receipt.read_current(self.finding))

    def test_an_emptied_third_column_still_changes_report_identity(self) -> None:
        # Ignoring padding cells must not blind identity to a real column: a
        # table whose third column carries content keeps all three.
        self.report.write_text(
            "# State issue\n\n| Metric | Value | Derived from |\n| --- | --- | --- |\n"
            "| Attack Vector | N | surface tier |\n",
            encoding="utf-8",
        )
        before = report_identity.content_sha1(self.report)
        self.report.write_text(
            self.report.read_text().replace("surface tier", ""),
            encoding="utf-8",
        )
        self.assertNotEqual(before, report_identity.content_sha1(self.report))

    def test_read_only_consumers_reject_a_stale_new_quality_cache(self) -> None:
        report_text = triage.read_report_bounded(self.report)
        cache = self.finding / ".llm-find-quality.json"
        cache.write_text(json.dumps(triage._quality_payload(
            report_text,
            [
                quality_vote(self.finding.name)["items"][0],
                quality_vote(self.finding.name)["items"][0],
            ],
            2,
            2,
            report_identity.content_sha1(self.report),
        )))
        (self.finding / ".trigger-gate.json").write_text(json.dumps(
            trigger_vote(self.report, self.root),
        ))
        validation_receipt.write(
            self.finding, kind="finding", state="reportable",
            attacker_controls=triage_validate.trigger_attacker_controls(),
        )
        self.assertEqual(benchmark.count_confirmed_findings(self.finding.parent)[0], 1)
        self.assertEqual(finding_signature.read_llm_cache(self.finding)["class"], "auth:bypass")
        self.report.write_text(
            self.report.read_text() + "\n## Reachability — external callers\n\nRevised.\n",
            encoding="utf-8",
        )
        self.assertEqual(benchmark.count_confirmed_findings(self.finding.parent)[0], 0)
        self.assertEqual(benchmark.harvest(self.root)["gate_states"][0]["trigger"], "stale")
        self.assertEqual(finding_signature.read_llm_cache(self.finding), {})

    def test_independent_batch_chunks_run_in_bounded_parallel(self) -> None:
        items = [{"id": f"FIND-{index:03d}", "report": "report"} for index in range(17)]
        lock = threading.Lock()
        active = maximum = 0

        def decide(*_args, **_kwargs):
            nonlocal active, maximum
            with lock:
                active += 1
                maximum = max(maximum, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return {"items": []}

        with mock.patch.object(triage.llm_decide, "llm_decide", side_effect=decide):
            self.assertEqual(
                triage._batch_decisions(
                    "find_quality_batch", "triage_find_quality_batch.md.j2",
                    "instructions", items, 5, None, workers=2,
                ),
                {},
            )
        self.assertEqual(maximum, 2)

    def test_reach_and_trigger_batches_use_bounded_parallelism(self) -> None:
        directories = []
        for index in range(9):
            directory = self.root / "findings" / f"FIND-{index + 10:03d}"
            directory.mkdir()
            (directory / "report.md").write_text(
                "# State issue\n\nA public request crosses a boundary.\n",
                encoding="utf-8",
            )
            directories.append(directory)

        lock = threading.Lock()
        active = maximum = calls = 0
        reach_timeouts: list[int] = []

        def decide(_decision, _required, _prompt, timeout, **_kwargs):
            nonlocal active, maximum, calls
            with lock:
                reach_timeouts.append(timeout)
                active += 1
                calls += 1
                maximum = max(maximum, active)
            time.sleep(0.05)
            with lock:
                active -= 1
            return {"items": []}

        with mock.patch.object(triage.llm_decide, "llm_decide", side_effect=decide):
            triage._batch_reach_field_decisions(
                directories, None, workers=2,
            )
        self.assertEqual((calls, maximum), (3, 2))
        self.assertEqual(reach_timeouts, [120, 120, 120])

        active = maximum = calls = 0

        def run(command, *_args, **_kwargs):
            nonlocal active, maximum, calls
            with lock:
                active += 1
                calls += 1
                maximum = max(maximum, active)
            time.sleep(0.05)
            _write_batch_votes(command)  # complete response: no ids left to retry
            with lock:
                active -= 1
            return mock.Mock(returncode=0)

        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
        }, clear=False), mock.patch.object(
            triage.llm_decide, "provider_limit_open", return_value=False,
        ), mock.patch.object(triage.subprocess, "run", side_effect=run):
            attempted = triage._batch_finding_trigger_votes(
                directories, self.root, None, None, False, workers=2,
            )
        self.assertEqual(attempted, set(directories))
        self.assertEqual((calls, maximum), (3, 2))

    def test_repeat_finalization_of_unchanged_findings_spends_no_provider_call(self) -> None:
        """Finalize twice; the second pass must reach no provider at all.

        Every claim about what adjudication costs depends on whether a second
        pass over unchanged artifacts re-pays for verdicts already on disk.
        Asserting it directly is what keeps that question answered: the caches
        bind on report identity, so any transform that rewrites a report
        between passes silently reintroduces the entire bill.
        """
        self.report.write_text(
            "# State issue\n\n"
            "A caller-controlled request crosses an authorization boundary.\n\n"
            "Boundary: network\n"
            "Caller controls: bytes\n"
            "Trusted caller actions: none\n"
            "Caller contract: obeyed\n"
            "Trigger source: bytes\n"
            "Surface: network\n"
            "Primitive: authz_bypass\n"
            "Class: authorization\n"
            "Parameter control: direct\n"
            "Advisory: no\n"
            "Strategy: S3\n",
            encoding="utf-8",
        )
        quality_calls: list[str] = []
        provider_calls: list[list[str]] = []
        subprocess_run = subprocess.run

        def run(command, *_args, **_kwargs):
            if "--batch-manifest" in command:
                provider_calls.append(list(command))
                _write_batch_votes(command)
                return mock.Mock(returncode=0)
            return subprocess_run(command, *_args, **_kwargs)

        def quality_batch(directories, *_args, **_kwargs):
            quality_calls.append("batch")
            return {
                directory: [
                    {"accept": True, "reason": "concrete boundary issue",
                     "class": "auth:bypass", "severity": "high"},
                ] * 2
                for directory in directories
            }

        def gate() -> dict[str, int]:
            with mock.patch.dict(os.environ, {
                "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
            }, clear=False), mock.patch.object(
                triage.llm_decide, "provider_limit_open", return_value=False,
            ), mock.patch.object(
                triage.subprocess, "run", side_effect=run,
            ), mock.patch.object(
                triage, "_batch_quality_votes", side_effect=quality_batch,
            ):
                return triage.validate_find_gate(self.root, workers=1)

        first = gate()
        self.assertEqual(first["accepted"], 1)
        self.assertTrue(quality_calls, "the first pass must review the finding")
        self.assertTrue(provider_calls, "the first pass must reach the validator")
        self.assertIsNotNone(
            validation_receipt.read_current(self.finding),
            "severity formatting must not make the accepted finding uncountable",
        )

        before = self.report.read_text(encoding="utf-8")
        quality_calls.clear()
        provider_calls.clear()
        second = gate()

        self.assertEqual(second["accepted"], 1)
        self.assertIsNotNone(validation_receipt.read_current(self.finding))
        self.assertEqual(
            self.report.read_text(encoding="utf-8"), before,
            "an unchanged finding must not be rewritten by finalization",
        )
        self.assertEqual(
            (quality_calls, provider_calls), ([], []),
            "a second finalization of unchanged findings must be free",
        )

    def test_incomplete_trigger_batch_retries_only_missing_ids_once(self) -> None:
        directories = []
        for index in range(2):
            directory = self.root / "findings" / f"FIND-{index + 10:03d}"
            directory.mkdir()
            (directory / "report.md").write_text(
                "# State issue\n\nA public request crosses a boundary.\n",
                encoding="utf-8",
            )
            directories.append(directory)

        runs = []

        def run(command, *_args, **_kwargs):
            manifest = Path(command[command.index("--batch-manifest") + 1])
            ids = [item["id"] for item in json.loads(manifest.read_text())["items"]]
            runs.append(ids)
            # First pass votes only the first id; the retry must carry only the
            # still-missing second id, then complete it.
            _write_batch_votes(command, only={directories[0].name} if len(runs) == 1 else None)
            return mock.Mock(returncode=0)

        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
        }, clear=False), mock.patch.object(
            triage.llm_decide, "provider_limit_open", return_value=False,
        ), mock.patch.object(triage.subprocess, "run", side_effect=run):
            triage._batch_finding_trigger_votes(
                directories, self.root, None, None, False, workers=1,
            )
        self.assertEqual(len(runs), 2)
        self.assertEqual(runs[1], [directories[1].name])
        for directory in directories:
            self.assertIsNotNone(triage._cached_trigger_vote(
                directory / "report.md", directory / ".trigger-gate.json",
            ))

    def test_trigger_retries_follow_every_initial_batch(self) -> None:
        directories = []
        for index in range(9):
            directory = self.root / "findings" / f"FIND-{index + 10:03d}"
            directory.mkdir()
            (directory / "report.md").write_text(
                "# State issue\n\nA public request crosses a boundary.\n",
                encoding="utf-8",
            )
            directories.append(directory)

        runs = []

        def run(command, *_args, **_kwargs):
            manifest = Path(command[command.index("--batch-manifest") + 1])
            runs.append([
                item["id"] for item in json.loads(manifest.read_text())["items"]
            ])
            return mock.Mock(returncode=0)

        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
        }, clear=False), mock.patch.object(
            triage.llm_decide, "provider_limit_open", return_value=False,
        ), mock.patch.object(triage.subprocess, "run", side_effect=run):
            triage._batch_finding_trigger_votes(
                directories, self.root, None, None, False, workers=1,
            )
        expected = [
            [directory.name for directory in directories[start:start + 4]]
            for start in range(0, len(directories), 4)
        ]
        self.assertEqual(runs[:3], expected)
        self.assertEqual(runs[3:], expected)

    def test_timed_out_trigger_batch_retries_missing_ids_individually(self) -> None:
        directories = []
        for index in range(2):
            directory = self.root / "findings" / f"FIND-{index + 10:03d}"
            directory.mkdir()
            (directory / "report.md").write_text(
                "# State issue\n\nA public request crosses a boundary.\n",
                encoding="utf-8",
            )
            directories.append(directory)
        runs = []

        def run(command, *_args, **_kwargs):
            manifest = Path(command[command.index("--batch-manifest") + 1])
            ids = [item["id"] for item in json.loads(manifest.read_text())["items"]]
            runs.append(ids)
            if len(runs) == 1:
                return mock.Mock(returncode=124)
            _write_batch_votes(command)
            return mock.Mock(returncode=0)

        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
        }, clear=False), mock.patch.object(
            triage.llm_decide, "provider_limit_open", return_value=False,
        ), mock.patch.object(triage.subprocess, "run", side_effect=run):
            triage._batch_finding_trigger_votes(
                directories, self.root, None, None, False, workers=1,
            )

        self.assertEqual(
            runs,
            [
                [directory.name for directory in directories],
                [directories[0].name],
                [directories[1].name],
            ],
        )
        for directory in directories:
            self.assertIsNotNone(triage._cached_trigger_vote(
                directory / "report.md", directory / ".trigger-gate.json",
            ))

    def _pending_findings(self, count: int, first: int) -> list[Path]:
        directories = []
        for index in range(count):
            directory = self.root / "findings" / f"FIND-{index + first:03d}"
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "report.md").write_text(
                "# State issue\n\nA public request crosses a boundary.\n",
                encoding="utf-8",
            )
            directories.append(directory)
        return directories

    def test_a_group_reaches_dispositions_before_the_next_one_opens(self) -> None:
        # Every stage needs two votes to conclude, so running any of them
        # across the whole corpus first means a wall that runs out leaves the
        # field one vote short of everything.
        self._pending_findings(40, 400)
        calls: list[str] = []

        def quality(dirs, *_a, **_k):
            calls.append("quality")
            return {}

        def trigger(dirs, *_a, **kwargs):
            calls.append(kwargs.get("vote_name", ".trigger-gate.json"))
            return set(dirs)

        def finalize(directory, *_a, **_k):
            calls.append("finalize")
            return "rejected"

        with mock.patch.object(
            triage, "_batch_quality_votes", side_effect=quality,
        ), mock.patch.object(
            triage, "validate_one_finding", return_value="quality-accepted",
        ), mock.patch.object(
            triage, "_batch_reach_field_decisions", return_value=(set(), {}, None),
        ), mock.patch.object(
            triage, "_prepare_accepted_finding", return_value=None,
        ), mock.patch.object(
            triage, "_cached_trigger_vote", return_value="Reject",
        ), mock.patch.object(
            triage, "_batch_finding_trigger_votes", side_effect=trigger,
        ), mock.patch.object(
            triage, "_finalize_accepted_finding", side_effect=finalize,
        ):
            triage.validate_find_gate(self.root, workers=1, deadline=None)

        self.assertGreater(calls.count("quality"), 1, calls)
        # Nothing from a later group may start before the first group has
        # recorded a disposition.
        before_first_disposition = calls[:calls.index("finalize")]
        self.assertEqual(before_first_disposition.count("quality"), 1, calls)
        self.assertEqual(
            before_first_disposition.count(".trigger-gate-2.json"), 1, calls,
        )

    def test_a_group_that_consumes_the_wall_still_finishes(self) -> None:
        # The boundary the grouping exists for: the work is paid for, then the
        # wall expires. Finalizing only after every group would discard it and
        # publish the same zero-completion outcome the ordering fixes.
        directories = self._pending_findings(40, 600)
        expired = {"yes": False}
        finalized: list[Path] = []

        def trigger(dirs, *_a, **_k):
            expired["yes"] = True   # the first group's votes spend the wall
            return set(dirs)

        def finalize(directory, *_a, **_k):
            finalized.append(directory)
            return "rejected"

        with mock.patch.object(
            triage, "_batch_quality_votes", return_value={},
        ), mock.patch.object(
            triage, "validate_one_finding", return_value="quality-accepted",
        ), mock.patch.object(
            triage, "_batch_reach_field_decisions", return_value=(set(), {}, None),
        ), mock.patch.object(
            triage, "_prepare_accepted_finding", return_value=None,
        ), mock.patch.object(
            triage, "_cached_trigger_vote", return_value="Reject",
        ), mock.patch.object(
            triage, "_batch_finding_trigger_votes", side_effect=trigger,
        ), mock.patch.object(
            triage, "_finalize_accepted_finding", side_effect=finalize,
        ), mock.patch.object(
            triage, "_deadline_expired", side_effect=lambda _d: expired["yes"],
        ):
            counts = triage.validate_find_gate(
                self.root, workers=1, deadline=1.0,
                finish_started_group=True,
            )

        self.assertTrue(finalized, "the group's work was paid for and discarded")
        self.assertGreater(counts["rejected"], 0, counts)
        # The wall still stops the run: later groups are never opened.
        self.assertLess(len(finalized), len(directories), len(finalized))
        self.assertGreater(counts["pending"], 0, counts)
        # Every finding the gate saw is accounted for exactly once, whichever
        # group it landed in.
        self.assertEqual(
            sum(counts.values()),
            len([p for p in (self.root / "findings").iterdir() if p.is_dir()]),
            counts,
        )

    def test_post_cell_group_finishes_quality_quorum_after_wall(self) -> None:
        # Exercise the real quality cache loop. The earlier regression test
        # mocked validate_one_finding as accepted and the cache reader as a
        # Reject even when only one provider round had actually written a
        # vote, so it could not catch paid-for one-vote starvation.
        self._pending_findings(8, 700)
        expired = {"yes": False}
        rounds = {"count": 0}

        def decisions(_decision, _template, _instructions, items, *_a, **_k):
            rounds["count"] += 1
            result = {
                item["id"]: {
                    "id": item["id"], "accept": True, "reason": "complete",
                }
                for item in items
            }
            if rounds["count"] == 1:
                expired["yes"] = True
            return result

        with mock.patch.object(
            triage, "_batch_decisions", side_effect=decisions,
        ), mock.patch.object(
            triage, "_batch_reach_field_decisions", return_value=(set(), {}, None),
        ), mock.patch.object(
            triage, "_prepare_accepted_finding", return_value=None,
        ), mock.patch.object(
            triage, "_cached_trigger_vote", return_value="Promote",
        ), mock.patch.object(
            triage, "_batch_finding_trigger_votes", return_value=set(),
        ), mock.patch.object(
            triage, "_finalize_accepted_finding", return_value="accepted",
        ), mock.patch.object(
            triage, "_deadline_expired",
            side_effect=lambda deadline: deadline is not None and expired["yes"],
        ):
            counts = triage.validate_find_gate(
                self.root, workers=1, deadline=1.0,
                finish_started_group=True,
            )

        # The admitted quality batch reaches real two-vote quorum without
        # sacrificing its 16-item batching. One trigger-sized disposition
        # group (4 findings for one worker) finishes; the next never starts.
        self.assertEqual(2, rounds["count"], rounds)
        self.assertEqual(4, counts["accepted"], counts)
        self.assertEqual(
            sum(counts.values()),
            len([p for p in (self.root / "findings").iterdir() if p.is_dir()]),
            counts,
        )
        completed_quality = []
        for directory in (self.root / "findings").glob("FIND-*"):
            cache = directory / ".llm-find-quality.json"
            if not cache.is_file():
                continue
            payload = json.loads(
                cache.read_text(encoding="utf-8")
            )
            if len(payload.get("votes", [])) == 2:
                completed_quality.append(directory)
        self.assertEqual(
            len([p for p in (self.root / "findings").glob("FIND-*") if p.is_dir()]),
            len(completed_quality),
            completed_quality,
        )

    def test_trigger_review_wall_covers_the_observed_review(self) -> None:
        """Every review session gets the full wall, batched or single.

        A review that runs out of wall emits no vote at all, so its ids cost a
        retry wall on top. Measured cost sits in per-session setup rather than
        per-item work, so the wall does not shrink for a batch or grow with it.
        """
        directories = []
        for index in range(5):
            directory = self.root / "findings" / f"FIND-{index + 10:03d}"
            directory.mkdir()
            (directory / "report.md").write_text(
                "# State issue\n\nA public request crosses a boundary.\n",
                encoding="utf-8",
            )
            directories.append(directory)

        seen = []

        def run(command, *_args, **_kwargs):
            manifest = Path(command[command.index("--batch-manifest") + 1])
            items = json.loads(manifest.read_text(encoding="utf-8"))["items"]
            seen.append((
                len(items), int(command[command.index("--timeout") + 1]),
            ))
            _write_batch_votes(command)
            return mock.Mock(returncode=0)

        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
        }, clear=False), mock.patch.object(
            triage.llm_decide, "provider_limit_open", return_value=False,
        ), mock.patch.object(triage.subprocess, "run", side_effect=run):
            triage._batch_finding_trigger_votes(
                directories, self.root, None, None, False, workers=1,
            )

        # Five findings split 4 + 1; both reviews get the same full wall.
        self.assertEqual(seen, [(4, 700), (1, 700)])

        # The wall is the decision's measured default, not a fixed ceiling: an
        # explicit operator timeout still overrides it, per its documented
        # contract, and a slow `oss` host still earns the tier's extra room.
        seen.clear()
        for directory in directories:
            (directory / ".trigger-gate.json").unlink(missing_ok=True)
        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
            "LLM_DECISION_TIMEOUT": "30",
        }, clear=False), mock.patch.object(
            triage.llm_decide, "provider_limit_open", return_value=False,
        ), mock.patch.object(triage.subprocess, "run", side_effect=run):
            triage._batch_finding_trigger_votes(
                directories, self.root, None, None, False, workers=1,
            )
        self.assertEqual(seen, [(4, 30), (1, 30)])

    def test_timed_out_trigger_batch_retry_keeps_the_singleton_wall(self) -> None:
        directories = []
        for index in range(2):
            directory = self.root / "findings" / f"FIND-{index + 10:03d}"
            directory.mkdir()
            (directory / "report.md").write_text(
                "# State issue\n\nA public request crosses a boundary.\n",
                encoding="utf-8",
            )
            directories.append(directory)

        seen = []

        def run(command, *_args, **_kwargs):
            manifest = Path(command[command.index("--batch-manifest") + 1])
            items = json.loads(manifest.read_text(encoding="utf-8"))["items"]
            seen.append((
                len(items), int(command[command.index("--timeout") + 1]),
            ))
            if len(seen) == 1:
                return mock.Mock(returncode=124)
            _write_batch_votes(command)
            return mock.Mock(returncode=0)

        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
        }, clear=False), mock.patch.object(
            triage.llm_decide, "provider_limit_open", return_value=False,
        ), mock.patch.object(triage.subprocess, "run", side_effect=run):
            triage._batch_finding_trigger_votes(
                directories, self.root, None, None, False, workers=1,
            )

        # The singleton retries a timeout fans out to get the same full wall as
        # the batch that starved: at 300s those retries were starving too.
        self.assertEqual(seen, [(2, 700), (1, 700), (1, 700)])

    def test_provider_limited_trigger_batch_is_not_retried(self) -> None:
        directory = self.root / "findings" / "FIND-010"
        directory.mkdir()
        (directory / "report.md").write_text(
            "# State issue\n\nA public request crosses a boundary.\n",
            encoding="utf-8",
        )
        calls = 0

        def run(command, *_args, **_kwargs):
            nonlocal calls
            calls += 1
            return mock.Mock(returncode=2)  # transient backend failure: no votes

        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
        }, clear=False), mock.patch.object(
            triage.llm_decide, "provider_limit_open", return_value=False,
        ), mock.patch.object(triage.subprocess, "run", side_effect=run):
            triage._batch_finding_trigger_votes(
                [directory], self.root, None, None, False, workers=1,
            )
        self.assertEqual(calls, 1)  # provider/backend failures are not hot-retried

    def test_trigger_batch_validator_distinguishes_wall_exhaustion(self) -> None:
        validator = runpy.run_path(str(ROOT / "bin" / "validate-finding"))
        manifest = self.root / "trigger-batch.json"
        manifest.write_text(json.dumps({
            "items": [{
                "id": self.finding.name,
                "finding": str(self.report),
                "output": str(self.finding / ".trigger-gate.json"),
            }],
        }), encoding="utf-8")
        arguments = [
            "--batch-manifest", str(manifest),
            "--target-path", str(self.root),
            "--backend", "codex",
            "--gate", "trigger",
        ]

        def invoke_status(status: int):
            def invoke(_backend, _prompt, _timeout, raw, **_kwargs):
                Path(raw).write_text("backend did not return a vote\n", encoding="utf-8")
                return status
            return invoke

        with mock.patch.object(
            validator["llm_invoke"], "run_agent_prompt",
            side_effect=invoke_status(124),
        ), mock.patch.object(
            validator["llm_usage"], "append_usage_event",
        ):
            self.assertEqual(validator["main"](arguments), 124)

        with mock.patch.object(
            validator["llm_invoke"], "run_agent_prompt",
            side_effect=invoke_status(127),
        ), mock.patch.object(
            validator["llm_usage"], "append_usage_event",
        ):
            self.assertEqual(validator["main"](arguments), 2)

    def test_trigger_resolution_prompt_carries_the_prior_open_question(self) -> None:
        validator = runpy.run_path(str(ROOT / "bin" / "validate-finding"))
        first = self.finding / ".trigger-gate.json"
        prior = trigger_vote(self.report, self.root, "Uncertain")
        prior["rationale"] = "The object replacement path was not settled."
        first.write_text(json.dumps(prior), encoding="utf-8")
        output = self.finding / ".trigger-gate-resolution.json"
        manifest = self.root / "trigger-resolution.json"
        manifest.write_text(json.dumps({
            "items": [{
                "id": self.finding.name,
                "finding": str(self.report),
                "output": str(output),
                "prior_reviews": [str(first)],
            }],
        }), encoding="utf-8")
        arguments = [
            "--batch-manifest", str(manifest),
            "--target-path", str(self.root),
            "--backend", "codex", "--gate", "trigger",
            "--resolve-trigger",
        ]
        prompts: list[str] = []

        def invoke(_backend, prompt, _timeout, raw, **_kwargs):
            prompts.append(prompt)
            vote = trigger_vote(self.report, self.root, "Promote")
            vote["id"] = self.finding.name
            Path(raw).write_text(
                json.dumps({
                    "type": "item.completed",
                    "item": {
                        "type": "agent_message",
                        "text": json.dumps({"items": [vote]}),
                    },
                }) + "\n",
                encoding="utf-8",
            )
            return 0

        with mock.patch.object(
            validator["llm_invoke"], "run_agent_prompt", side_effect=invoke,
        ), mock.patch.object(
            validator["llm_usage"], "append_usage_event",
        ):
            self.assertEqual(validator["main"](arguments), 0)

        self.assertIn("Resolve their exact disagreement", prompts[0])
        self.assertIn("object replacement path was not settled", prompts[0])
        self.assertNotIn("You have NOT seen this finding before", prompts[0])
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(
            payload["decision_version"],
            triage_validate.TRIGGER_RESOLUTION_DECISION_VERSION,
        )
        self.assertEqual(
            payload["prior_review_sha256s"],
            [hashlib.sha256(first.read_bytes()).hexdigest()],
        )

    def test_trigger_cache_requires_current_prompt_and_report(self) -> None:
        cache = self.finding / ".trigger-gate.json"
        cache.write_text(json.dumps(trigger_vote(self.report, self.root)))
        with mock.patch.dict(os.environ, {"LLM_DECIDE_DISABLE": "1"}, clear=False):
            self.assertEqual(
                triage._trigger_vote(
                    self.report, cache, "codex", "fixture", self.root,
                ),
                0,
            )
            self.report.write_text(
                self.report.read_text()
                + "\nCluster: FCL-generated\n\n## Severity rationale\n\nGenerated.\n",
                encoding="utf-8",
            )
            self.assertEqual(
                triage._trigger_vote(
                    self.report, cache, "codex", "fixture", self.root,
                ),
                0,
            )
            self.report.write_text(
                self.report.read_text()
                + "\n## Reachability — external callers\n\nRevised caller contract.\n",
                encoding="utf-8",
            )
            self.assertEqual(
                triage._trigger_vote(
                    self.report, cache, "codex", "fixture", self.root,
                ),
                2,
            )

    def test_trigger_cache_binds_to_threat_model(self) -> None:
        # A current-version verdict is reusable only under the threat model it was
        # produced for; a controls change forces a fresh review (recall-safe).
        cache = self.finding / ".trigger-gate.json"
        sha = report_identity.content_sha1(self.report)
        with mock.patch.dict(
            os.environ,
            {"LLM_DECIDE_DISABLE": "1", "TARGET_ATTACKER_CONTROLS_CSV": "bytes"},
            clear=False,
        ):
            cache.write_text(json.dumps(trigger_vote(
                self.report, self.root, "Reject", controls=["bytes"],
            )))
            self.assertEqual(  # matching controls -> cached Reject reused
                triage._trigger_vote(self.report, cache, "codex", "x", self.root), 1)
            cache.write_text(json.dumps(trigger_vote(
                self.report, self.root, "Reject",
                controls=["bytes", "call-sequence"],
            )))
            self.assertEqual(  # controls changed -> not reused (LLM disabled -> 2)
                triage._trigger_vote(self.report, cache, "codex", "x", self.root), 2)
            legacy = {"decision_version": "trigger-v2-caller-buffer", "content_sha1": sha}
            cache.write_text(json.dumps({**legacy, "vote": "Promote"}))
            self.assertEqual(  # legacy keep reused (fail-open)
                triage._trigger_vote(self.report, cache, "codex", "x", self.root), 0)
            cache.write_text(json.dumps({**legacy, "vote": "Reject"}))
            self.assertEqual(  # legacy Reject never reused -> fresh review
                triage._trigger_vote(self.report, cache, "codex", "x", self.root), 2)
            superseded = {
                "decision_version": "trigger-v5-public-boundary",
                "content_sha1": sha,
                "vote": "Promote",
            }
            cache.write_text(json.dumps(superseded))
            self.assertEqual(  # v5 never considered the claimed consequence
                triage._trigger_vote(self.report, cache, "codex", "x", self.root), 2)

    def test_trigger_cache_binds_to_revision_and_live_source_anchor(self) -> None:
        cache = self.finding / ".trigger-gate.json"
        with mock.patch.dict(
            os.environ,
            {
                "LLM_DECIDE_DISABLE": "1",
                "TARGET_ROOT": str(self.root),
                "TARGET_REV": "revision-a",
            },
            clear=False,
        ):
            cache.write_text(json.dumps(trigger_vote(
                self.report, self.root,
            )))
            self.assertEqual(
                triage._trigger_vote(
                    self.report, cache, "codex", "x", self.root,
                ),
                0,
            )
            with mock.patch.dict(
                os.environ, {"TARGET_REV": "revision-b"}, clear=False,
            ):
                self.assertEqual(
                    triage._trigger_vote(
                        self.report, cache, "codex", "x", self.root,
                    ),
                    2,
                )
            (self.root / "sample.c").write_text(
                "int app_parse(void) { return 1; }\n", encoding="utf-8",
            )
            self.assertEqual(
                triage._trigger_vote(
                    self.report, cache, "codex", "x", self.root,
                ),
                2,
            )

    def test_unsettled_trigger_reviews_remain_retryable_for_resolution(self) -> None:
        first = self.finding / ".trigger-gate.json"
        second = self.finding / ".trigger-gate-2.json"

        first.write_text(json.dumps(trigger_vote(
            self.report, self.root, "Uncertain",
        )), encoding="utf-8")
        self.assertFalse(triage._cached_trigger_resolution(
            self.finding, self.report,
        ))

        first.write_text(json.dumps(trigger_vote(
            self.report, self.root, "Reject",
        )), encoding="utf-8")
        second.write_text(json.dumps(trigger_vote(
            self.report, self.root, "Promote",
        )), encoding="utf-8")
        self.assertFalse(triage._cached_trigger_resolution(
            self.finding, self.report,
        ))

    def test_focused_resolution_can_settle_a_review_conflict(self) -> None:
        first = self.finding / ".trigger-gate.json"
        second = self.finding / ".trigger-gate-2.json"
        resolution = self.finding / ".trigger-gate-resolution.json"
        first.write_text(json.dumps(trigger_vote(
            self.report, self.root, "Reject",
        )), encoding="utf-8")
        second.write_text(json.dumps(trigger_vote(
            self.report, self.root, "Promote",
        )), encoding="utf-8")
        resolution.write_text(json.dumps(trigger_resolution_vote(
            self.report, self.root, [first, second], "Promote",
        )), encoding="utf-8")

        with mock.patch.object(
            triage, "evaluate_crash_verdict", return_value=("promote", "within"),
        ), mock.patch.object(triage, "_run_tool", return_value=0):
            self.assertEqual(
                triage._finalize_accepted_finding(
                    self.finding, self.root, self.report, None, prepared=True,
                ),
                "accepted",
            )
        receipt = validation_receipt.read_current(self.finding)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "reportable")

    def test_a_resolver_does_not_overturn_an_agreed_boundary_surface(self) -> None:
        # The reviewers split on scope but agreed the surface is file-format.
        # A resolver is aimed at the disputed question and fills the rest of the
        # schema in passing, yet vulnerable_boundary_surface overrides the
        # Surface severity scores -- so consensus must survive it.
        first = self.finding / ".trigger-gate.json"
        second = self.finding / ".trigger-gate-2.json"
        resolution = self.finding / ".trigger-gate-resolution.json"
        for path, vote, fit in (
            (first, "Reject", "within"), (second, "Promote", "outside"),
        ):
            payload = trigger_vote(self.report, self.root, vote)
            payload["review_facts"] = {
                "vulnerable_boundary_surface": "file-format",
                "trigger_controls_fit": fit,
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
        resolved = trigger_resolution_vote(
            self.report, self.root, [first, second], "Promote",
        )
        resolved["review_facts"] = {
            "vulnerable_boundary_surface": "network",
            "trigger_controls_fit": "within",
        }
        resolution.write_text(json.dumps(resolved), encoding="utf-8")

        votes, facts = triage._trigger_publication_evidence(
            self.report, self.finding,
        )
        self.assertEqual(votes, {"Promote"})
        # The resolver settles the question it was asked...
        self.assertEqual(facts.get("trigger_controls_fit"), "within")
        # ...and the reviewers keep the one they agreed on.
        self.assertEqual(facts.get("vulnerable_boundary_surface"), "file-format")

    def test_a_resolution_survives_a_harness_reach_field_annotation(self) -> None:
        # The harness annotates reach fields onto the report, which changes its
        # identity and rewrites the reviews the resolution is bound to. Carrying
        # the reviews but not the resolution would drop a settled answer and buy
        # a second resolver call for a question already resolved.
        first = self.finding / ".trigger-gate.json"
        resolution = self.finding / ".trigger-gate-resolution.json"
        first.write_text(json.dumps(trigger_vote(
            self.report, self.root, "Uncertain",
        )), encoding="utf-8")
        resolution.write_text(json.dumps(trigger_resolution_vote(
            self.report, self.root, [first], "Promote",
        )), encoding="utf-8")
        self.assertEqual(
            triage._cached_trigger_vote(self.report, resolution), "Promote",
        )

        self.assertTrue(
            triage._materialize_reach_fields_preserving_positive_votes(
                self.report, {"boundary": "network"},
            )
        )
        self.assertEqual(
            triage._cached_trigger_vote(self.report, first), "Uncertain",
        )
        self.assertEqual(
            triage._cached_trigger_vote(self.report, resolution), "Promote",
        )
        self.assertTrue(triage._cached_trigger_resolution(
            self.finding, self.report,
        ))

    def test_focused_resolution_is_stale_when_a_prior_review_changes(self) -> None:
        first = self.finding / ".trigger-gate.json"
        resolution = self.finding / ".trigger-gate-resolution.json"
        first.write_text(json.dumps(trigger_vote(
            self.report, self.root, "Uncertain",
        )), encoding="utf-8")
        resolution.write_text(json.dumps(trigger_resolution_vote(
            self.report, self.root, [first], "Promote",
        )), encoding="utf-8")
        self.assertEqual(
            triage._cached_trigger_vote(self.report, resolution), "Promote",
        )

        changed = json.loads(first.read_text(encoding="utf-8"))
        changed["rationale"] = "A later review identified a different open fact."
        first.write_text(json.dumps(changed), encoding="utf-8")
        self.assertIsNone(
            triage._cached_trigger_vote(self.report, resolution),
        )

    def test_resolution_reject_needs_and_can_join_a_prior_reject(self) -> None:
        first = self.finding / ".trigger-gate.json"
        second = self.finding / ".trigger-gate-2.json"
        resolution = self.finding / ".trigger-gate-resolution.json"
        reject = trigger_vote(self.report, self.root, "Reject")
        reject["review_facts"] = {"rejection_kind": "contract-invalid"}
        first.write_text(json.dumps(reject), encoding="utf-8")
        second.write_text(json.dumps(trigger_vote(
            self.report, self.root, "Promote",
        )), encoding="utf-8")
        resolved = trigger_resolution_vote(
            self.report, self.root, [first, second], "Reject",
        )
        resolved["review_facts"] = {"rejection_kind": "contract-invalid"}
        resolution.write_text(json.dumps(resolved), encoding="utf-8")

        with mock.patch.dict(
            os.environ,
            {"ACTIVE_BACKEND": "", "BACKEND": "", "TARGET_ROOT": str(self.root)},
            clear=False,
        ):
            self.assertEqual(
                triage._finding_trigger_disposition(
                    self.finding, self.report, None,
                ),
                "rejected",
            )

    def test_one_resolution_reject_cannot_quarantine_after_uncertainty(self) -> None:
        first = self.finding / ".trigger-gate.json"
        resolution = self.finding / ".trigger-gate-resolution.json"
        first.write_text(json.dumps(trigger_vote(
            self.report, self.root, "Uncertain",
        )), encoding="utf-8")
        resolution.write_text(json.dumps(trigger_resolution_vote(
            self.report, self.root, [first], "Reject",
        )), encoding="utf-8")

        with mock.patch.object(
            triage, "evaluate_crash_verdict", return_value=("promote", "within"),
        ):
            self.assertEqual(
                triage._finalize_accepted_finding(
                    self.finding, self.root, self.report, None, prepared=True,
                ),
                "pending",
            )
        self.assertTrue(self.finding.is_dir())
        self.assertEqual(
            validation_receipt.read_current(self.finding)["state"], "pending",
        )

    def test_find_gate_stabilizes_report_before_batched_trigger_vote(self) -> None:
        report_text = triage.read_report_bounded(self.report)
        (self.finding / ".llm-find-quality.json").write_text(json.dumps(
            triage._quality_payload(
                report_text,
                [
                    quality_vote(self.finding.name)["items"][0],
                    quality_vote(self.finding.name)["items"][0],
                ],
                2,
                2,
                report_identity.content_sha1(self.report),
            )
        ))

        def fill(*_args, **_kwargs):
            self.report.write_text(
                self.report.read_text()
                + "\nSurface: library-api\n"
                + "Boundary: public API\n"
                + "Caller contract: obeyed\n"
                + "Trigger source: bytes\n",
                encoding="utf-8",
            )
            return True

        def batch(directories, *_args, **_kwargs):
            self.assertEqual(directories, [self.finding])
            self.assertIn("Boundary: public API", self.report.read_text())
            (self.finding / ".trigger-gate.json").write_text(json.dumps(
                trigger_vote(self.report, self.root),
            ))
            return {self.finding}

        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
        }, clear=False), mock.patch.object(
            triage, "_batch_reach_field_decisions",
            return_value=({self.finding}, {self.finding: {}}, set()),
        ), mock.patch.object(
            triage, "fill_reach_fields", side_effect=fill,
        ), mock.patch.object(
            triage, "_run_tool", return_value=0,
        ), mock.patch.object(
            triage, "_batch_finding_trigger_votes", side_effect=batch,
        ), mock.patch.object(
            triage.subprocess, "run",
            side_effect=AssertionError("individual trigger fallback"),
        ):
            self.assertEqual(
                triage.validate_find_gate(self.root, workers=1),
                {"accepted": 1, "rejected": 0, "pending": 0},
            )

    def test_find_gate_batches_required_second_reject_votes(self) -> None:
        self.report.write_text(
            self.report.read_text(encoding="utf-8")
            + "\nSurface: library-api\n"
            + "Boundary: public API\n"
            + "Caller contract: violated\n"
            + "Trigger source: call-sequence\n",
            encoding="utf-8",
        )
        report_text = triage.read_report_bounded(self.report)
        (self.finding / ".llm-find-quality.json").write_text(json.dumps(
            triage._quality_payload(
                report_text,
                [
                    quality_vote(self.finding.name)["items"][0],
                    quality_vote(self.finding.name)["items"][0],
                ],
                2,
                2,
                report_identity.content_sha1(self.report),
            )
        ))
        rounds = []

        def batch(
            directories, *_args, vote_name=".trigger-gate.json", **_kwargs,
        ):
            rounds.append(vote_name)
            for directory in directories:
                report = directory / "report.md"
                (directory / vote_name).write_text(json.dumps(
                    trigger_vote(report, self.root, vote="Reject"),
                ))
            return set(directories)

        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
        }, clear=False), mock.patch.object(
            triage, "_batch_reach_field_decisions",
            return_value=(set(), {}, set()),
        ), mock.patch.object(
            triage, "fill_reach_fields", return_value=False,
        ), mock.patch.object(
            triage, "_batch_finding_trigger_votes", side_effect=batch,
        ), mock.patch.object(
            triage.subprocess, "run",
            side_effect=AssertionError("individual trigger fallback"),
        ):
            self.assertEqual(
                triage.validate_find_gate(self.root, workers=1),
                {"accepted": 0, "rejected": 1, "pending": 0},
            )
        self.assertEqual(
            rounds, [".trigger-gate.json", ".trigger-gate-2.json"],
        )

    def test_find_gate_batches_a_focused_resolution_after_uncertainty(self) -> None:
        self.report.write_text(
            self.report.read_text(encoding="utf-8")
            + "\nSurface: library-api\n"
            + "Boundary: public API\n"
            + "Caller contract: obeyed\n"
            + "Trigger source: bytes\n",
            encoding="utf-8",
        )
        report_text = triage.read_report_bounded(self.report)
        (self.finding / ".llm-find-quality.json").write_text(json.dumps(
            triage._quality_payload(
                report_text,
                [
                    quality_vote(self.finding.name)["items"][0],
                    quality_vote(self.finding.name)["items"][0],
                ],
                2,
                2,
                report_identity.content_sha1(self.report),
            )
        ))
        rounds: list[str] = []

        def batch(
            directories, *_args, vote_name=".trigger-gate.json", **_kwargs,
        ):
            rounds.append(vote_name)
            for directory in directories:
                report = directory / "report.md"
                output = directory / vote_name
                if vote_name == ".trigger-gate-resolution.json":
                    first = directory / ".trigger-gate.json"
                    payload = trigger_resolution_vote(
                        report, self.root, [first], "Promote",
                    )
                else:
                    payload = trigger_vote(report, self.root, "Uncertain")
                output.write_text(json.dumps(payload), encoding="utf-8")
            return set(directories)

        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
        }, clear=False), mock.patch.object(
            triage, "_batch_reach_field_decisions",
            return_value=(set(), {}, set()),
        ), mock.patch.object(
            triage, "fill_reach_fields", return_value=False,
        ), mock.patch.object(
            triage, "_batch_finding_trigger_votes", side_effect=batch,
        ), mock.patch.object(
            triage, "_run_tool", return_value=0,
        ), mock.patch.object(
            triage.subprocess, "run",
            side_effect=AssertionError("individual trigger fallback"),
        ):
            self.assertEqual(
                triage.validate_find_gate(self.root, workers=1),
                {"accepted": 1, "rejected": 0, "pending": 0},
            )
        self.assertEqual(
            rounds, [".trigger-gate.json", ".trigger-gate-resolution.json"],
        )

    def test_find_gate_finalizes_cached_work_before_unresolved_quality_batch(self) -> None:
        self.report.write_text(
            "# State issue\n\nA public request crosses an authorization boundary.\n\n"
            "Surface: library-api\n"
            "Primitive: authz_bypass\n"
            "Class: authorization\n"
            "Caller contract: obeyed\n"
            "Caller controls: bytes\n"
            "Trigger source: bytes\n"
            "Parameter control: direct\n"
            "Trusted caller actions: normal public call\n"
            "Boundary: public request handler\n"
            "Advisory: no\n",
            encoding="utf-8",
        )
        report_text = triage.read_report_bounded(self.report)
        (self.finding / ".llm-find-quality.json").write_text(json.dumps(
            triage._quality_payload(
                report_text,
                [
                    quality_vote(self.finding.name)["items"][0],
                    quality_vote(self.finding.name)["items"][0],
                ],
                2,
                2,
                report_identity.content_sha1(self.report),
            )
        ))
        (self.finding / ".trigger-gate.json").write_text(json.dumps(
            trigger_vote(self.report, self.root),
        ))
        unresolved = self.root / "findings" / "FIND-002"
        unresolved.mkdir()
        (unresolved / "report.md").write_text(
            "# Unresolved state issue\n", encoding="utf-8",
        )

        def quality_batch(*_args, **_kwargs):
            self.assertIsNotNone(validation_receipt.read_current(self.finding))
            return {unresolved: []}

        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
        }, clear=False), mock.patch.object(
            triage, "_batch_quality_votes", side_effect=quality_batch,
        ), mock.patch.object(
            triage, "_batch_reach_field_decisions",
            return_value=(set(), {}, set()),
        ), mock.patch.object(
            triage, "_batch_finding_trigger_votes", return_value=set(),
        ), mock.patch.object(
            triage, "_run_tool", return_value=0,
        ):
            self.assertEqual(
                triage.validate_find_gate(self.root, workers=1),
                {"accepted": 1, "rejected": 0, "pending": 1},
            )

    def test_crash_gate_processes_cached_work_before_reachability_batch(self) -> None:
        crashes = self.root / "crashes"
        ready = crashes / "CRASH-001"
        unresolved = crashes / "CRASH-002"
        for directory in (ready, unresolved):
            directory.mkdir(parents=True)
            (directory / "sanitizer.txt").write_text(
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n",
                encoding="utf-8",
            )
        ready_report = ready / "report.md"
        ready_report.write_text(
            "# Bounds issue\n\n"
            "Surface: library-api\n"
            "Primitive: out_of_bounds_read\n"
            "Class: memory-safety\n"
            "Caller contract: obeyed\n"
            "Trigger source: bytes\n"
            "Parameter control: direct\n"
            "Boundary: public parser\n"
            "Caller controls: bytes\n"
            "Trusted caller actions: normal public call\n"
            "Advisory: no\n",
            encoding="utf-8",
        )
        (ready / ".trigger-gate.json").write_text(json.dumps(
            trigger_vote(ready_report, self.root),
        ))
        (unresolved / "report.md").write_text(
            "# Unresolved bounds issue\n", encoding="utf-8",
        )
        processed: list[Path] = []

        def triage_one(directory, *_args, **_kwargs):
            processed.append(directory)
            return "promoted" if directory == ready else "pending"

        def reach_batch(directories, *_args, **_kwargs):
            self.assertEqual(processed, [ready])
            self.assertEqual(directories, [unresolved])
            return set(), {}, set()

        with mock.patch.object(
            triage, "triage_one_crash", side_effect=triage_one,
        ), mock.patch.object(
            triage, "_batch_reach_field_decisions", side_effect=reach_batch,
        ):
            self.assertEqual(
                triage.triage_crash_dirs(
                    self.root, self.root, "sampleproj", workers=1,
                ),
                {"promoted": 1, "rejected": 0, "pending": 1, "demoted": 0},
            )

    def test_crash_gate_batches_two_trigger_rounds_before_per_crash_triage(self) -> None:
        crashes = self.root / "crashes"
        directories = [crashes / "CRASH-001", crashes / "CRASH-002"]
        report_text = (
            "# Bounds issue\n\nSurface: library-api\n"
            "Caller contract: obeyed\nTrigger source: call-sequence\n"
            "Boundary: public API\nCaller controls: call order\n"
            "Trusted caller actions: callback\n"
        )
        for directory in directories:
            directory.mkdir(parents=True)
            (directory / "report.md").write_text(report_text, encoding="utf-8")
            (directory / "sanitizer.txt").write_text(
                "==1==ERROR: AddressSanitizer: heap-use-after-free\n",
                encoding="utf-8",
            )

        rounds: list[tuple[str, list[Path]]] = []

        def batch(items, _results, _deadline, _usage, _product, _workers, vote_name=".trigger-gate.json"):
            rounds.append((vote_name, list(items)))
            for directory in items:
                report = directory / "report.md"
                (directory / vote_name).write_text(
                    json.dumps(trigger_vote(report, self.root, "Reject")),
                    encoding="utf-8",
                )
            return set(items)

        attempted: list[bool] = []

        def triage_one(_directory, *_args, **kwargs):
            attempted.append(bool(kwargs.get("trigger_batch_attempted")))
            return "rejected"

        with mock.patch.object(
            triage, "converge_reach_fields",
        ), mock.patch.object(
            triage, "_direct_probe_trigger_bypass", return_value=False,
        ), mock.patch.object(
            triage, "_bundle_needs_refresh", return_value=False,
        ), mock.patch.object(
            triage, "_bundle_missing_artifacts", return_value=[],
        ), mock.patch.object(
            triage, "_batch_finding_trigger_votes", side_effect=batch,
        ), mock.patch.object(
            triage, "triage_one_crash", side_effect=triage_one,
        ):
            counts = triage.triage_crash_dirs(
                self.root, self.root, "sampleproj", workers=1,
            )

        self.assertEqual(
            rounds,
            [
                (".trigger-gate.json", directories),
                (".trigger-gate-2.json", directories),
            ],
        )
        self.assertEqual(attempted, [True, True])
        self.assertEqual(
            counts,
            {"promoted": 0, "rejected": 2, "pending": 0, "demoted": 0},
        )

    def test_crash_gate_converges_fields_on_canonical_report_after_export(self) -> None:
        crash = self.root / "crashes" / "CRASH-001"
        crash.mkdir(parents=True)
        report = crash / "report.md"
        report.write_text(
            "# Lifetime issue\n\n"
            "Surface: library-api\n"
            "Caller contract: obeyed\n"
            "Trigger source: call-sequence\n"
            "Boundary: public API\n"
            "Caller controls: call order\n"
            "Trusted caller actions: callback\n",
            encoding="utf-8",
        )
        (crash / "sanitizer.txt").write_text(
            "==1==ERROR: AddressSanitizer: heap-use-after-free\n",
            encoding="utf-8",
        )
        testcase = crash / "input.txt"
        testcase.write_text("sample\n", encoding="utf-8")
        events: list[str] = []

        def run(tool, *_args, **_kwargs):
            self.assertEqual(tool, "export-repro")
            events.append("export")
            report.rename(crash / "REPORT.md")
            return 0

        def converge(directories, *_args, **_kwargs):
            self.assertEqual(directories, [crash])
            self.assertTrue((crash / "REPORT.md").is_file())
            self.assertEqual(triage._report(crash).name, "REPORT.md")
            events.append("converge")

        with mock.patch.object(
            triage.crash_artifacts, "find_testcase", return_value=testcase,
        ), mock.patch.object(
            triage.crash_artifacts, "find_harness_source", return_value=None,
        ), mock.patch.object(
            triage, "_bundle_needs_refresh", return_value=True,
        ), mock.patch.object(
            triage, "_bundle_missing_artifacts", return_value=[],
        ), mock.patch.object(
            triage, "has_valid_diagnostic", return_value=True,
        ), mock.patch.object(
            triage, "_run_tool", side_effect=run,
        ), mock.patch.object(
            triage, "converge_reach_fields", side_effect=converge,
        ), mock.patch.object(
            triage, "_direct_probe_trigger_bypass", return_value=False,
        ), mock.patch.object(
            triage, "_batch_finding_trigger_votes", return_value=set(),
        ), mock.patch.object(
            triage, "triage_one_crash", return_value="promoted",
        ):
            counts = triage.triage_crash_dirs(
                self.root, self.root, "sampleproj", workers=1,
            )

        self.assertEqual(events, ["export", "converge"])
        self.assertEqual(
            counts,
            {"promoted": 1, "rejected": 0, "pending": 0, "demoted": 0},
        )

    def test_index_maintenance_rebinds_receipts_after_generated_report_edits(self) -> None:
        validation_receipt.write(
            self.finding, kind="finding", state="reportable",
            attacker_controls=["bytes"],
        )
        self.assertIsNotNone(validation_receipt.read_current(self.finding))
        edited = False

        def run(tool, *_args, **_kwargs):
            nonlocal edited
            if tool == "cluster-findings" and not edited:
                self.report.write_text(
                    self.report.read_text(encoding="utf-8")
                    + "\n## Fields\n\n"
                    + "| Field | Value |\n"
                    + "| --- | --- |\n"
                    + "| Cluster | FCL-generated |\n",
                    encoding="utf-8",
                )
                edited = True
            return 0

        with mock.patch.object(triage, "_run_tool", side_effect=run):
            self.assertTrue(
                triage.maintain_indexes(self.root, self.root, workers=1),
            )
        self.assertTrue(edited)
        self.assertIsNotNone(validation_receipt.read_current(self.finding))

    def test_malformed_batched_trigger_vote_stays_pending(self) -> None:
        report_text = triage.read_report_bounded(self.report)
        (self.finding / ".llm-find-quality.json").write_text(json.dumps(
            triage._quality_payload(
                report_text,
                [
                    quality_vote(self.finding.name)["items"][0],
                    quality_vote(self.finding.name)["items"][0],
                ],
                2,
                2,
                report_identity.content_sha1(self.report),
            )
        ))

        def batch(directories, *_args, **_kwargs):
            (self.finding / ".trigger-gate.json").write_text(
                json.dumps({"vote": "ParseFailure"})
            )
            return set(directories)

        def fill(*_args, **_kwargs):
            if "Boundary: public API" not in self.report.read_text():
                self.report.write_text(
                    self.report.read_text() + "\nBoundary: public API\n",
                    encoding="utf-8",
                )
            return True

        with mock.patch.object(
            triage, "_batch_reach_field_decisions",
            return_value=({self.finding}, {self.finding: {}}, set()),
        ), mock.patch.object(
            triage, "fill_reach_fields", side_effect=fill,
        ), mock.patch.object(
            triage, "_run_tool", return_value=0,
        ), mock.patch.object(
            triage, "_batch_finding_trigger_votes", side_effect=batch,
        ), mock.patch.object(
            triage, "_batch_decisions",
            side_effect=AssertionError("quality review repeated after stabilization"),
        ), mock.patch.object(
            triage.subprocess, "run",
            side_effect=AssertionError("individual trigger fallback"),
        ):
            self.assertEqual(
                triage.validate_find_gate(self.root, workers=1),
                {"accepted": 0, "rejected": 0, "pending": 1},
            )
            self.assertEqual(
                triage.validate_find_gate(self.root, workers=1),
                {"accepted": 0, "rejected": 0, "pending": 1},
            )
        cache = triage._finding_cache(self.finding / ".llm-find-quality.json")
        self.assertTrue(triage._quality_cache_matches(
            self.finding / ".llm-find-quality.json",
            cache,
            self.report,
            triage.read_report_bounded(self.report),
        ))

    def test_trigger_reject_requires_a_valid_vote_artifact(self) -> None:
        cache = self.finding / ".trigger-gate.json"
        with mock.patch.dict(
            os.environ, {"LLM_DECIDE_DISABLE": "0"}, clear=False,
        ), mock.patch.object(
            triage.llm_decide, "provider_limit_open", return_value=False,
        ), mock.patch.object(
            triage.subprocess, "run", return_value=mock.Mock(returncode=1),
        ):
            self.assertEqual(
                triage._trigger_vote(
                    self.report, cache, "codex", "fixture", self.root,
                ),
                2,
            )

        def write_reject(*_args, **_kwargs):
            cache.write_text(json.dumps(trigger_vote(
                self.report, self.root, "Reject",
            )))
            return mock.Mock(returncode=1)

        with mock.patch.dict(
            os.environ, {"LLM_DECIDE_DISABLE": "0"}, clear=False,
        ), mock.patch.object(
            triage.llm_decide, "provider_limit_open", return_value=False,
        ), mock.patch.object(triage.subprocess, "run", side_effect=write_reject):
            self.assertEqual(
                triage._trigger_vote(
                    self.report, cache, "codex", "fixture", self.root,
                ),
                1,
            )

    def test_trigger_validator_stamps_cache_identity(self) -> None:
        validator = runpy.run_path(str(ROOT / "bin" / "validate-finding"))
        args = validator["parse_args"]([
            "--finding", str(self.report),
            "--target-path", str(self.root),
            "--backend", "codex",
            "--gate", "trigger",
        ])
        source = self.root / "sample.c"
        excerpt = "int app_parse(void) { return 0; }"
        source.write_text(excerpt + "\n", encoding="utf-8")
        anchor = {
            "path": "sample.c",
            "line": 1,
            "symbol": "app_parse",
            "kind": "source",
            "excerpt": excerpt,
            "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
        }
        stamped = validator["stamp_trigger_vote"](
            args, {"vote": "Promote", "anchors": [anchor]}, "report-sha1",
            self.root,
        )
        self.assertEqual(
            stamped,
            {
                "vote": "Promote",
                "anchors": [anchor],
                "anchors_verified": True,
                "review_facts": {},
                "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
                "content_sha1": "report-sha1",
                "attacker_controls": triage_validate.trigger_attacker_controls(),
                "target_revision": "",
                "target_config_sha256": "",
            },
        )
        self.report.write_text(
            self.report.read_text()
            + "\n## Severity rationale\n\nGenerated score prose.\n",
            encoding="utf-8",
        )
        facts, content_sha1 = validator["candidate_snapshot"](
            self.report, semantic=True,
        )
        self.assertNotIn("Generated score prose", facts["report"])
        self.assertEqual(content_sha1, report_identity.content_sha1(self.report))
        batch_prompt = validator["render_trigger_batch_prompt"](
            args, [{"id": "FIND-001", "facts": facts}],
        )
        self.assertIn('"anchors":[', batch_prompt)
        self.assertIn('"rejection_kind":', batch_prompt)

    def test_trigger_validator_stamps_only_verified_boundary_facts(self) -> None:
        validator = runpy.run_path(str(ROOT / "bin" / "validate-finding"))
        args = validator["parse_args"]([
            "--finding", str(self.report),
            "--target-path", str(self.root),
            "--backend", "codex",
            "--gate", "trigger",
        ])
        source = self.root / "sample.c"
        excerpt = "int app_parse(void) { return 0; }"
        source.write_text(excerpt + "\n", encoding="utf-8")
        anchor = {
            "path": "sample.c", "line": 1, "symbol": "app_parse",
            "kind": "source", "excerpt": excerpt,
        }
        stamped = validator["stamp_trigger_vote"](
            args, {
                "vote": "Promote",
                "anchors": [anchor],
                "vulnerable_boundary_surface": "file-format",
                "reproducer_carrier": "cli",
                "trigger_controls_fit": "within",
            },
            "report-sha1", self.root,
        )
        self.assertEqual(
            stamped["review_facts"],
            {
                "vulnerable_boundary_surface": "file-format",
                "reproducer_carrier": "cli",
                "trigger_controls_fit": "within",
            },
        )

        # A scope answer decides publication, so an off-schema value is
        # dropped rather than guessed at.
        off_schema = validator["stamp_trigger_vote"](
            args, {
                "vote": "Promote",
                "anchors": [anchor],
                "trigger_controls_fit": "probably in scope",
            },
            "report-sha1", self.root,
        )
        self.assertEqual(off_schema["review_facts"], {})

        unanchored = validator["stamp_trigger_vote"](
            args, {
                "vote": "Promote",
                "anchors": [],
                "vulnerable_boundary_surface": "network",
            },
            "report-sha1", self.root,
        )
        self.assertEqual(unanchored["vote"], "Uncertain")
        self.assertEqual(unanchored["review_facts"], {})

    def test_reviewed_boundary_facts_fail_open_on_disagreement(self) -> None:
        common = trigger_vote(self.report, self.root)
        first = self.finding / ".trigger-gate.json"
        second = self.finding / ".trigger-gate-2.json"
        first.write_text(json.dumps({
            **common,
            "review_facts": {
                "vulnerable_boundary_surface": "file-format",
                "reproducer_carrier": "cli",
            },
        }))
        second.write_text(json.dumps({
            **common,
            "review_facts": {
                "vulnerable_boundary_surface": "library-api",
                "reproducer_carrier": "cli",
            },
        }))
        self.assertEqual(
            triage._source_review_facts(self.report, (first, second)),
            {"reproducer_carrier": "cli"},
        )

    def test_negative_classification_requires_two_reviewers(self) -> None:
        common = trigger_vote(self.report, self.root, "Reject")
        first = self.finding / ".trigger-gate.json"
        second = self.finding / ".trigger-gate-2.json"
        first.write_text(json.dumps({
            **common,
            "review_facts": {"rejection_kind": "no-added-boundary"},
        }))
        self.assertEqual(
            triage._source_review_facts(
                self.report, (first, second), rejection_quorum=2,
            ),
            {},
        )
        second.write_text(json.dumps({
            **common,
            "review_facts": {"rejection_kind": "no-added-boundary"},
        }))
        self.assertEqual(
            triage._source_review_facts(
                self.report, (first, second), rejection_quorum=2,
            ),
            {"rejection_kind": "no-added-boundary"},
        )

    def test_review_order_rotates_classes_before_it_exhausts_one(self) -> None:
        """A drain cut short must leave a sample, not one whole class unread.

        Name order made the prefix a single class: one cell adjudicated 80 of
        274 reports and every one shared a class, while every other class it
        filed went unread. That prefix is not a floor of the same corpus.
        """
        findings = self.root / "findings"
        for index, klass in enumerate(
            ["uninit"] * 6 + ["overflow"] * 2 + ["credential"],
        ):
            directory = findings / f"FIND-{index:03d}"
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "report.md").write_text(
                f"| Class | {klass} |\n", encoding="utf-8",
            )
        directories = sorted(findings.glob("FIND-*"))
        ordered = triage._finding_review_order(directories)
        self.assertCountEqual(ordered, directories)

        def klass_of(directory: Path) -> str:
            return triage._finding_review_rank(directory)[0]

        # Every class the cell filed appears in the first three reviewed.
        self.assertEqual(
            {klass_of(directory) for directory in ordered[:3]},
            {"uninit", "overflow", "credential"},
        )

    def test_review_order_puts_the_settleable_report_first(self) -> None:
        """Evidence completeness ranks the queue; it never drops a report."""
        findings = self.root / "findings"
        complete = findings / "FIND-100"
        thin = findings / "FIND-010"
        for directory in (complete, thin):
            directory.mkdir(parents=True, exist_ok=True)
        (thin / "report.md").write_text("| Class | uninit |\n", encoding="utf-8")
        (complete / "report.md").write_text(
            "| Class | uninit |\n"
            + "".join(
                f"| {label} | stated |\n"
                for key, label in triage._REACH_FIELD_LABELS.items()
                if key != "class"
            ),
            encoding="utf-8",
        )
        ordered = triage._finding_review_order([thin, complete])
        self.assertEqual(ordered, [complete, thin])

    def test_pending_sidecars_clear_where_the_reader_looks(self) -> None:
        """A verified crash cannot stay PENDING off a marker no pass reaches.

        cluster_common.promotion_pending_reasons searches the bundle and its
        `.audit/`, where export and pooling move sidecars, but clearing covered
        only the top level. One crash reproduced 5/5 with sanitizer output and
        still published as PENDING.
        """
        import cluster_common
        bundle = self.root / "CRASH-900"
        (bundle / ".audit").mkdir(parents=True)
        for base in (bundle, bundle / ".audit"):
            (base / ".promotion_pending").write_text(
                "sanitizer.txt(valid)\n", encoding="utf-8",
            )
        self.assertTrue(cluster_common.promotion_pending_reasons(bundle))
        triage._clear_promotion_sidecars(bundle)
        self.assertEqual(cluster_common.promotion_pending_reasons(bundle), [])

    def test_disclosed_content_is_optional_and_enum_bound(self) -> None:
        """Silence keeps today's severity; only a reviewed value may move it."""
        self.assertIn("disclosed_content", triage._OPTIONAL_REACH_FIELD_LABELS)
        self.assertNotIn("disclosed_content", triage._REACH_FIELD_LABELS)
        # An unclassified report is complete: absence never blocks publication.
        self.assertNotIn(
            "disclosed_content", triage._missing_reach_fields("| Class | x |"),
        )
        self.assertEqual(
            triage._valid_reach_field("disclosed_content", "cross-principal"),
            "cross-principal",
        )
        self.assertEqual(
            triage._valid_reach_field("disclosed_content", "invented"), "",
        )

    def test_complete_disclosure_report_is_still_asked_once(self) -> None:
        """A complete report short-circuits the fill; the ask must survive it.

        `_missing_reach_fields` lists only publication-required fields, so an
        otherwise complete disclosure report returned early and the optional
        classification could never be populated on the reports it exists for.
        """
        required = "".join(
            f"| {label} | stated |\n"
            for label in triage._REACH_FIELD_LABELS.values()
        )
        disclosure = "| Class | info-disclosure:uninitialized-memory |\n" + required
        self.assertEqual(triage._missing_reach_fields(disclosure), {})
        self.assertIn(
            "disclosed_content", triage._pending_optional_reach_fields(disclosure),
        )
        # A non-disclosure report must not buy an extra provider call...
        self.assertEqual(
            triage._pending_optional_reach_fields(
                "| Class | memory-safety:bounds |\n" + required,
            ),
            {},
        )
        # ...and one already classified is never asked twice.
        self.assertEqual(
            triage._pending_optional_reach_fields(
                disclosure + "| Disclosed content | same-context |\n",
            ),
            {},
        )

        # Exercise the actual report -> decision -> materialization path. A
        # helper-only test would miss another early return in fill_reach_fields.
        self.report.write_text(disclosure, encoding="utf-8")
        self.assertTrue(triage.fill_reach_fields(
            self.finding,
            decision_override={"disclosed_content": "same-context"},
        ))
        self.assertEqual(
            triage._field(self.report.read_text(), "Disclosed content"),
            "same-context",
        )
        attempts = json.loads(
            (self.finding / ".llm_fields.json").read_text(encoding="utf-8"),
        )["_fill_attempts"]
        self.assertFalse(triage.fill_reach_fields(
            self.finding,
            decision_override={"disclosed_content": "cross-principal"},
        ))
        self.assertEqual(
            json.loads(
                (self.finding / ".llm_fields.json").read_text(encoding="utf-8"),
            )["_fill_attempts"],
            attempts,
        )

    def test_split_disproof_names_still_remove_the_finding(self) -> None:
        """Quorum is on the disproof, not on the name given to it.

        Two anchored reviewers refuted one report with the same cited source
        and filed it under different dispositive kinds. Requiring an identical
        label voided the quorum and republished the finding as reportable,
        where it counted toward the security total and its Medium+ subset.
        """
        common = trigger_vote(self.report, self.root, "Reject")
        votes = (
            self.finding / ".trigger-gate.json",
            self.finding / ".trigger-gate-2.json",
        )
        for vote, kind in zip(votes, ("unreachable", "contract-invalid")):
            vote.write_text(json.dumps({
                **common, "review_facts": {"rejection_kind": kind},
            }))
        # The label disagreement still means no agreed fact to publish.
        self.assertEqual(
            triage._source_review_facts(
                self.report, votes, rejection_quorum=2,
            ),
            {},
        )
        self.assertTrue(
            triage._trigger_rejection_is_dispositive(self.report, votes),
        )
        with mock.patch.dict(
            os.environ,
            {"ACTIVE_BACKEND": "", "BACKEND": "", "TARGET_ROOT": str(self.root)},
            clear=False,
        ):
            self.assertEqual(
                triage._finding_trigger_disposition(
                    self.finding, self.report, None,
                ),
                "rejected",
            )
        # A split over whether any boundary was added is a real disagreement
        # about the claim, so it keeps the softer outcome.
        votes[1].write_text(json.dumps({
            **common, "review_facts": {"rejection_kind": "no-added-boundary"},
        }))
        self.assertFalse(
            triage._trigger_rejection_is_dispositive(self.report, votes),
        )

    def test_unreachable_disproof_is_dispositive_at_a_public_surface(self) -> None:
        """Two anchored `unreachable` Rejects remove the finding anywhere.

        The reviewer, not the surface, preserves a scope mismatch: the prompt
        routes a contract-obeying public call outside configured controls to
        Promote. Re-reading an `unreachable` disproof as a scope mismatch
        because the surface is public republished refuted reports.
        """
        payload = trigger_vote(self.report, self.root, "Reject")
        payload["review_facts"] = {
            "rejection_kind": "unreachable",
            "vulnerable_boundary_surface": "library-api",
            "reproducer_carrier": "harness",
        }
        for name in (".trigger-gate.json", ".trigger-gate-2.json"):
            (self.finding / name).write_text(
                json.dumps(payload), encoding="utf-8",
            )
        with mock.patch.dict(
            os.environ,
            {
                "ACTIVE_BACKEND": "",
                "BACKEND": "",
                "TARGET_ROOT": str(self.root),
            },
            clear=False,
        ):
            self.assertEqual(
                triage._finding_trigger_disposition(
                    self.finding, self.report, None,
                ),
                "rejected",
            )
        votes = (
            self.finding / ".trigger-gate.json",
            self.finding / ".trigger-gate-2.json",
        )
        for surface in ("library-api", "network", "file-format", "cli",
                        "internal", "unknown"):
            payload["review_facts"]["vulnerable_boundary_surface"] = surface
            for vote in votes:
                vote.write_text(json.dumps(payload), encoding="utf-8")
            self.assertTrue(
                triage._trigger_rejection_is_dispositive(self.report, votes),
                surface,
            )
        # A public surface still cannot turn a non-dispositive kind into one.
        payload["review_facts"]["rejection_kind"] = "no-added-boundary"
        for vote in votes:
            vote.write_text(json.dumps(payload), encoding="utf-8")
        self.assertFalse(
            triage._trigger_rejection_is_dispositive(self.report, votes),
        )

    def test_consequence_disproof_requires_two_anchored_reviewers(self) -> None:
        """A reachable trigger cannot preserve a source-refuted impact claim."""
        payload = trigger_vote(self.report, self.root, "Reject")
        payload["review_facts"] = {
            "rejection_kind": "consequence-disproved",
            "vulnerable_boundary_surface": "file-format",
            "reproducer_carrier": "file-format",
        }
        first = self.finding / ".trigger-gate.json"
        second = self.finding / ".trigger-gate-2.json"
        first.write_text(json.dumps(payload), encoding="utf-8")

        self.assertEqual(
            triage._source_review_facts(
                self.report, (first, second), rejection_quorum=2,
            ),
            {
                "vulnerable_boundary_surface": "file-format",
                "reproducer_carrier": "file-format",
            },
        )

        second.write_text(json.dumps(payload), encoding="utf-8")
        facts = triage._source_review_facts(
            self.report, (first, second), rejection_quorum=2,
        )
        self.assertEqual(facts["rejection_kind"], "consequence-disproved")
        votes = (first, second)
        self.assertTrue(triage._trigger_rejection_is_dispositive(
            self.report, votes, allow_consequence=True,
        ))
        # A sanitizer-backed crash keeps its diagnostic: consequence disproof
        # is only dispositive for a source-only finding.
        self.assertFalse(
            triage._trigger_rejection_is_dispositive(self.report, votes),
        )
        # One reviewer naming the refuted consequence and the other an
        # unreachable trigger are still two anchored disproofs.
        mixed = dict(payload)
        mixed["review_facts"] = {**payload["review_facts"],
                                 "rejection_kind": "unreachable"}
        second.write_text(json.dumps(mixed), encoding="utf-8")
        self.assertTrue(triage._trigger_rejection_is_dispositive(
            self.report, votes, allow_consequence=True,
        ))
        second.write_text(json.dumps(payload), encoding="utf-8")
        with mock.patch.dict(
            os.environ,
            {"ACTIVE_BACKEND": "", "BACKEND": "", "TARGET_ROOT": str(self.root)},
            clear=False,
        ):
            self.assertEqual(
                triage._finding_trigger_disposition(
                    self.finding, self.report, None,
                ),
                "rejected-consequence",
            )
            self.assertEqual(
                triage._finalize_accepted_finding(
                    self.finding, self.root, self.report, None,
                    prepared=True,
                ),
                "rejected",
            )

        rejected = self.root / "findings-rejected" / self.finding.name
        self.assertTrue(rejected.is_dir())
        self.assertIn(
            "exact claimed security consequence is source-disproved",
            (rejected / "REJECTION.md").read_text(encoding="utf-8"),
        )
        self.assertFalse(
            (self.root / "state" / "unreachable-routes.jsonl").exists(),
        )

    def test_lone_unreachable_reject_keeps_the_finding(self) -> None:
        """One Reject is not the quorum: recall comes from agreement, not surface."""
        payload = trigger_vote(self.report, self.root, "Reject")
        payload["review_facts"] = {
            "rejection_kind": "unreachable",
            "vulnerable_boundary_surface": "library-api",
            "reproducer_carrier": "harness",
        }
        (self.finding / ".trigger-gate.json").write_text(
            json.dumps(payload), encoding="utf-8",
        )
        second = trigger_vote(self.report, self.root, "Promote")
        second["review_facts"] = {
            "vulnerable_boundary_surface": "library-api",
            "reproducer_carrier": "harness",
        }
        (self.finding / ".trigger-gate-2.json").write_text(
            json.dumps(second), encoding="utf-8",
        )
        self.assertEqual(
            triage._source_review_facts(
                self.report,
                (self.finding / ".trigger-gate.json",
                 self.finding / ".trigger-gate-2.json"),
                rejection_quorum=2,
            ).get("rejection_kind"),
            None,
        )

    def test_disagreeing_trigger_review_leaves_the_finding_unsettled(self) -> None:
        """A split stays pending while its focused resolver has no answer.

        The finding earns no security credit, but the cached split is no longer
        considered complete provider work: a later bounded pass can resolve it.
        """
        first = trigger_vote(self.report, self.root, "Reject")
        first["review_facts"] = {
            "rejection_kind": "contract-invalid",
            "vulnerable_boundary_surface": "internal",
            "reproducer_carrier": "harness",
        }
        second = trigger_vote(self.report, self.root, "Promote")
        second["review_facts"] = {
            "vulnerable_boundary_surface": "library-api",
            "reproducer_carrier": "harness",
        }
        (self.finding / ".trigger-gate.json").write_text(
            json.dumps(first), encoding="utf-8",
        )
        (self.finding / ".trigger-gate-2.json").write_text(
            json.dumps(second), encoding="utf-8",
        )

        with mock.patch.dict(
            os.environ,
            {
                "ACTIVE_BACKEND": "",
                "BACKEND": "",
                "TARGET_ROOT": str(self.root),
            },
            clear=False,
        ), mock.patch.object(
            triage, "evaluate_crash_verdict", return_value=("promote", ""),
        ), mock.patch.object(triage, "_run_tool", return_value=0):
            self.assertEqual(
                triage._finalize_accepted_finding(
                    self.finding, self.root, self.report, None,
                    prepared=True,
                ),
                "pending",
            )

        receipt = validation_receipt.read_current(self.finding)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "pending")
        self.assertFalse(
            triage._cached_trigger_resolution(self.finding, self.report),
        )

    def test_legacy_trigger_rejection_is_requeued_for_current_review(self) -> None:
        rejected = self.root / "findings-rejected"
        rejected.mkdir()
        moved = rejected / self.finding.name
        self.finding.rename(moved)
        report = moved / "report.md"
        payload = trigger_vote(report, self.root, "Reject")
        payload["decision_version"] = "trigger-v4-source-anchors"
        for name in (".trigger-gate.json", ".trigger-gate-2.json"):
            (moved / name).write_text(json.dumps(payload), encoding="utf-8")
        (moved / "REJECTION.md").write_text(
            "# Rejected artifact\n\n"
            "Reason: trigger-provenance: state not attacker-reachable\n",
            encoding="utf-8",
        )

        self.assertEqual(
            triage._restore_stale_trigger_rejections(
                self.root, kind="finding",
            ),
            1,
        )
        restored = self.root / "findings" / self.finding.name
        self.assertTrue(restored.is_dir())
        self.assertFalse((restored / "REJECTION.md").exists())
        receipt = validation_receipt.read_current(restored)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "pending")

    def test_current_trigger_rejection_receipt_is_refreshed(self) -> None:
        rejected = self.root / "findings-rejected"
        rejected.mkdir()
        rejected_dir = rejected / self.finding.name
        self.finding.rename(rejected_dir)
        report = rejected_dir / "report.md"
        payload = trigger_vote(report, self.root, "Reject")
        for name in (".trigger-gate.json", ".trigger-gate-2.json"):
            (rejected_dir / name).write_text(
                json.dumps(payload), encoding="utf-8",
            )
        (rejected_dir / "REJECTION.md").write_text(
            "# Rejected artifact\n\n"
            "Reason: trigger-provenance: documented caller contract violated\n",
            encoding="utf-8",
        )
        self.assertEqual(
            triage._restore_stale_trigger_rejections(
                self.root, kind="finding",
            ),
            0,
        )
        receipt = validation_receipt.read_current(rejected_dir)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "rejected")

    def test_quality_rejection_receipt_refresh_and_stale_requeue(self) -> None:
        rejected = self.root / "findings-rejected"
        rejected.mkdir()
        current_dir = rejected / self.finding.name
        self.finding.rename(current_dir)
        report = current_dir / "report.md"
        report_text = triage.read_report_bounded(report)
        votes = [
            {
                "accept": False, "reason": "not security relevant",
                "class": "", "severity": "",
            },
            {
                "accept": False, "reason": "not security relevant",
                "class": "", "severity": "",
            },
        ]
        payload = triage._quality_payload(
            report_text, votes, 2, 2, report_identity.content_sha1(report),
        )
        (current_dir / ".llm-find-quality.json").write_text(
            json.dumps(payload), encoding="utf-8",
        )
        (current_dir / "REJECTION.md").write_text(
            "# Rejected artifact\n\nReason: not security relevant\n",
            encoding="utf-8",
        )
        self.assertEqual(
            triage._refresh_or_restore_quality_rejections(
                self.root, quorum=2, accept_quorum=2,
            ),
            0,
        )
        receipt = validation_receipt.read_current(current_dir)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "rejected")

        (current_dir / ".llm-find-quality.json").write_text(
            json.dumps({**payload, "report_sha1": "stale"}),
            encoding="utf-8",
        )
        self.assertEqual(
            triage._refresh_or_restore_quality_rejections(
                self.root, quorum=2, accept_quorum=2,
            ),
            1,
        )
        self.assertTrue((self.root / "findings" / self.finding.name).is_dir())

    def test_deterministic_crash_class_preserves_positive_legacy_vote(self) -> None:
        crash = self.root / "crashes" / "CRASH-001"
        crash.mkdir(parents=True)
        report = crash / "report.md"
        report.write_text(
            "# Bounds issue\n\n"
            "Surface: library-api\n"
            "Primitive: out_of_bounds_read\n",
            encoding="utf-8",
        )
        payload = trigger_vote(report, self.root)
        payload["decision_version"] = "trigger-v4-source-anchors"
        vote = crash / ".trigger-gate.json"
        vote.write_text(json.dumps(payload), encoding="utf-8")
        self.assertTrue(triage._materialize_crash_class(crash))
        self.assertEqual(triage._field(report.read_text(), "Class"), "memory-safety")
        self.assertEqual(triage._cached_trigger_vote(report, vote), "Uncertain")

    def test_legacy_positive_finding_vote_is_not_security_yield(self) -> None:
        """A legacy vote is not a current review, so it evidences nothing.

        It cannot publish the finding, and it is equally no evidence that the
        trigger is out of scope, so the finding stays unadjudicated.
        """
        payload = trigger_vote(self.report, self.root)
        payload["decision_version"] = "trigger-v4-source-anchors"
        (self.finding / ".trigger-gate.json").write_text(
            json.dumps(payload), encoding="utf-8",
        )
        self.assertTrue(triage.fill_reach_fields(
            self.finding,
            decision_override={
                "surface": "library-api",
                "primitive": "authorization-bypass",
                "class": "authorization",
                "caller_contract": "obeyed",
                "caller_controls": "bytes",
                "trigger_source": "request",
            },
        ))
        self.assertEqual(
            triage._cached_trigger_vote(
                self.report, self.finding / ".trigger-gate.json",
            ),
            "Uncertain",
        )
        with mock.patch.object(
            triage, "evaluate_crash_verdict", return_value=("promote", ""),
        ), mock.patch.object(triage, "_run_tool", return_value=0):
            self.assertEqual(
                triage._finalize_accepted_finding(
                    self.finding, self.root, self.report, None,
                ),
                "pending",
            )
        receipt = validation_receipt.read_current(self.finding)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "pending")

    def test_optional_severity_fields_do_not_block_cached_finalization(self) -> None:
        self.report.write_text(
            "# State issue\n\n"
            "Surface: network\n"
            "Primitive: authorization_bypass\n"
            "Caller contract: obeyed\n"
            "Caller controls: bytes\n"
            "Trigger source: bytes\n"
            "Trusted caller actions: normal public call\n"
            "Boundary: request authorization boundary\n",
            encoding="utf-8",
        )
        report_text = triage.read_report_bounded(self.report)
        quality = triage._quality_payload(
            report_text,
            [
                quality_vote(self.finding.name)["items"][0],
                quality_vote(self.finding.name)["items"][0],
            ],
            2,
            2,
            report_identity.content_sha1(self.report),
        )
        (self.finding / ".llm-find-quality.json").write_text(
            json.dumps(quality), encoding="utf-8",
        )
        payload = trigger_vote(self.report, self.root)
        (self.finding / ".trigger-gate.json").write_text(
            json.dumps(payload), encoding="utf-8",
        )
        self.assertEqual(
            triage._missing_reach_fields(self.report.read_text()),
            {
                "class": "Class",
                "parameter_control": "Parameter control",
                "advisory": "Advisory",
            },
        )
        self.assertTrue(
            triage._finding_ready_for_cached_finalization(
                self.finding, 2, 2,
            ),
        )

    def test_obsolete_reach_retry_exhaustion_is_reopened(self) -> None:
        sidecar = self.finding / ".llm_fields.json"
        sidecar.write_text(
            json.dumps({"_fill_attempts": 2}), encoding="utf-8",
        )
        self.assertTrue(triage.fill_reach_fields(
            self.finding,
            decision_override={
                "surface": "network",
                "primitive": "authorization_bypass",
                "class": "authorization",
            },
        ))
        cache = json.loads(sidecar.read_text(encoding="utf-8"))
        self.assertEqual(
            cache["_decision_version"],
            triage._REACH_FIELD_DECISION_VERSION,
        )
        self.assertEqual(cache["_fill_attempts"], 1)

    def test_pre_batch_schema_retry_exhaustion_is_reopened(self) -> None:
        """A fixed prompt must not inherit the broken prompt's retry ceiling."""
        required = "".join(
            f"{label}: stated\n"
            for key, label in triage._REACH_FIELD_LABELS.items()
            if key != "class"
        )
        self.report.write_text(
            "Class: info-disclosure\n" + required,
            encoding="utf-8",
        )
        sidecar = self.finding / ".llm_fields.json"
        sidecar.write_text(json.dumps({
            "_decision_version": "reach-fields-v4-fixed-setup",
            "_fill_attempts": 2,
        }), encoding="utf-8")
        self.assertTrue(triage.fill_reach_fields(
            self.finding,
            decision_override={"disclosed_content": "cross-principal"},
        ))
        cache = json.loads(sidecar.read_text(encoding="utf-8"))
        self.assertEqual(
            cache["_decision_version"],
            triage._REACH_FIELD_DECISION_VERSION,
        )
        self.assertEqual(cache["_fill_attempts"], 1)

    def test_legacy_positive_crash_vote_is_not_security_yield(self) -> None:
        """A legacy vote is not a current review, so it evidences nothing.

        It cannot publish the crash, and it is equally no evidence that the
        trigger is out of scope, so the crash stays unadjudicated.
        """
        crash = self.root / "crashes" / "CRASH-001"
        crash.mkdir(parents=True)
        report = crash / "report.md"
        report.write_text(
            "# Bounds issue\n\n"
            "Surface: library-api\n"
            "Primitive: out_of_bounds_read\n"
            "Caller contract: obeyed\n"
            "Trigger source: call-sequence\n",
            encoding="utf-8",
        )
        (crash / "sanitizer.txt").write_text(
            "ERROR: AddressSanitizer: heap-buffer-overflow\n",
            encoding="utf-8",
        )
        (crash / "input.bin").write_bytes(b"x")
        payload = trigger_vote(report, self.root)
        payload["decision_version"] = "trigger-v4-source-anchors"
        (crash / ".trigger-gate.json").write_text(
            json.dumps(payload), encoding="utf-8",
        )
        with mock.patch.object(
            triage, "_harness_rooted", return_value=False,
        ), mock.patch.object(
            triage, "has_valid_diagnostic", return_value=True,
        ), mock.patch.object(
            triage, "_has_memory_safety_signal", return_value=True,
        ), mock.patch.object(
            triage, "_bundle_needs_refresh", return_value=False,
        ), mock.patch.object(
            triage, "_bundle_missing_artifacts", return_value=[],
        ), mock.patch.object(
            triage, "fill_reach_fields", return_value=False,
        ), mock.patch.object(
            triage, "evaluate_crash_verdict", return_value=("promote", ""),
        ), mock.patch.object(
            triage, "_direct_probe_trigger_bypass", return_value=False,
        ), mock.patch.object(triage, "_run_tool", return_value=0):
            self.assertEqual(
                triage.triage_one_crash(
                    crash, self.root, self.root, "sampleproj", ["bytes"],
                ),
                "pending",
            )
        receipt = validation_receipt.read_current(crash)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "pending")

    def test_ambiguous_surface_review_honors_operator_opt_out(self) -> None:
        with mock.patch.dict(
            os.environ, {"CRASH_TRIGGER_GATE": "0"}, clear=False,
        ), mock.patch.object(triage, "_trigger_vote") as vote:
            triage._review_ambiguous_crash_surface(
                self.finding, self.report, self.root, None, None, False,
            )
        vote.assert_not_called()

    def test_source_review_corrects_the_finder_scope_label_both_ways(self) -> None:
        """`Trigger source` is a self-report and is wrong in both directions.

        A driver that exercises documented entry points reads as caller-driven
        even when attacker bytes decide the fault; an unreproduced claim reads
        as byte-driven even when only a caller can reach it. Only the
        anchor-verified source reviewer read the code, so its
        `trigger_controls_fit` decides scope when the two disagree.
        """
        resolve = triage._final_publication_state
        promote = frozenset({"Promote"})
        # Finder says out of model; the reviewer read the code and disagrees.
        self.assertEqual(
            resolve("out-of-model", promote, {"trigger_controls_fit": "within"}),
            "reportable",
        )
        # Finder says in model; the reviewer disagrees.
        self.assertEqual(
            resolve("promote", promote, {"trigger_controls_fit": "outside"}),
            "not-reportable",
        )
        # A review that ran and did not answer cannot carry an artifact to
        # security yield on the finder's word alone — in either direction. Nor
        # is its silence evidence against the claim, so it settles nothing.
        for verdict in ("out-of-model", "promote"):
            for facts in ({}, {"trigger_controls_fit": "unclear"}):
                with self.subTest(verdict=verdict, facts=facts):
                    self.assertEqual(
                        resolve(verdict, promote, facts), "pending",
                    )
        # With no review at all — a machine trigger proof, an operator opt-out,
        # or a human pin — there is no reviewer to have answered, so the
        # report's own comparison is all there is.
        self.assertEqual(resolve("promote"), "reportable")
        self.assertEqual(resolve("out-of-model"), "not-reportable")
        # Admitted caller misuse is the report's own words, not a scope guess,
        # so no reviewer opinion promotes it.
        self.assertEqual(
            resolve("contract-flag", promote, {"trigger_controls_fit": "within"}),
            "not-reportable",
        )

    def test_unsettled_review_is_unadjudicated_not_a_negative(self) -> None:
        """Doubt is not a finding that the trigger is out of scope.

        `not-reportable` asserts something about the artifact that neither an
        Uncertain vote nor two disagreeing reviewers established, and it is
        final — recording it would drop the artifact out of the unjudged
        remainder that marks the benchmark counts a floor.
        """
        resolve = triage._final_publication_state
        for votes in (frozenset({"Uncertain"}), frozenset({"Promote", "Reject"})):
            with self.subTest(votes=sorted(votes)):
                self.assertEqual(
                    resolve("promote", votes, {"trigger_controls_fit": "within"}),
                    "pending",
                )
        # An affirmative out-of-scope fact still settles it against the claim.
        self.assertEqual(
            resolve(
                "promote", frozenset({"Uncertain"}),
                {"trigger_controls_fit": "outside"},
            ),
            "not-reportable",
        )

    def test_an_unsettled_review_still_delivers_the_scope_it_did_settle(self) -> None:
        """A reviewer can settle scope without settling the defect.

        The prompt asks for `trigger_controls_fit` on an Uncertain vote, and
        `_final_publication_state` already turns an `outside` answer into
        `not-reportable`. What never happened was delivery: facts were collected
        from settled votes only, so a decided out-of-model call was dropped and
        the artifact published as an unjudged remainder instead.
        """
        vote_file = self.finding / ".trigger-gate.json"
        vote = trigger_vote(self.report, self.root, "Uncertain")
        vote["trigger_controls_fit"] = "outside"
        vote_file.write_text(json.dumps(vote), encoding="utf-8")
        with mock.patch.dict(os.environ, {"TARGET_ROOT": str(self.root)}):
            facts = triage._source_review_facts(self.report, (vote_file,))
        self.assertEqual(facts, {"trigger_controls_fit": "outside"})
        self.assertEqual(
            triage._final_publication_state("promote", {"Uncertain"}, facts),
            "not-reportable",
        )

    def test_a_stale_anchor_cannot_terminally_suppress_a_finding(self) -> None:
        """`not-reportable` is terminal, so the citations are re-read.

        A settled vote re-verifies its anchors against the live source before it
        counts. Trusting the recorded `anchors_verified` bit alone let a review
        of source that has since changed keep demoting the artifact out of the
        unjudged floor — the other dangerous direction from publishing.
        """
        vote_file = self.finding / ".trigger-gate.json"
        vote = trigger_vote(self.report, self.root, "Uncertain")
        vote["trigger_controls_fit"] = "outside"
        vote_file.write_text(json.dumps(vote), encoding="utf-8")
        # The cited line changes; the recorded revision does not.
        (self.root / "sample.c").write_text(
            "int app_parse(void) { return 1; }\n", encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {"TARGET_ROOT": str(self.root)}):
            facts = triage._source_review_facts(self.report, (vote_file,))
        self.assertEqual(facts, {})
        self.assertEqual(
            triage._final_publication_state("promote", {"Uncertain"}, facts),
            "pending",
        )

    def test_an_unsettled_review_cannot_publish_or_outvote_a_settled_one(self) -> None:
        """The scope fallback may withhold credit; it may never grant it.

        `within` from a reviewer that did not settle must not become security
        yield, an unverifiable reading must not count at all, and a reviewer that
        did settle must not be outranked by one that did not.
        """
        vote_file = self.finding / ".trigger-gate.json"

        def write(**overrides) -> None:
            vote = trigger_vote(self.report, self.root, "Uncertain")
            vote.update(overrides)
            vote_file.write_text(json.dumps(vote), encoding="utf-8")

        def facts(*votes: Path) -> dict:
            with mock.patch.dict(os.environ, {"TARGET_ROOT": str(self.root)}):
                return triage._source_review_facts(self.report, votes)

        write(trigger_controls_fit="within")
        self.assertEqual(
            triage._final_publication_state(
                "promote", {"Uncertain"}, facts(vote_file),
            ),
            "pending",
        )

        # A vote downgraded to Uncertain for citing nothing read nothing.
        write(trigger_controls_fit="outside", anchors_verified=False)
        self.assertEqual(facts(vote_file), {})

        # A settled reviewer answered, so the fallback is never consulted.
        write(trigger_controls_fit="outside")
        settled = self.finding / ".trigger-gate-2.json"
        settled_vote = trigger_vote(self.report, self.root, "Promote")
        settled_vote["review_facts"] = {"trigger_controls_fit": "within"}
        settled.write_text(json.dumps(settled_vote), encoding="utf-8")
        self.assertEqual(
            facts(vote_file, settled), {"trigger_controls_fit": "within"},
        )

    def test_machine_trigger_proof_survives_an_unsettled_surface_review(self) -> None:
        """A 5/5 direct byte-path proof is not negated by a boundary review.

        The ambiguous-surface reviewer runs only to settle boundary and
        carrier, but writes to the same vote file the trigger gate reads, so
        its doubt about an already-proved byte path would otherwise decide
        scope.
        """
        resolve = triage._final_publication_state
        for votes in (
            frozenset({"Uncertain"}), frozenset({"Promote"}), frozenset({None}),
        ):
            with self.subTest(votes=sorted(votes, key=str)):
                self.assertEqual(
                    resolve(
                        "out-of-model", votes, {}, direct_trigger_proof=True,
                    ),
                    "reportable",
                )
        # The report's own admission of caller misuse still decides.
        self.assertEqual(
            resolve("contract-flag", frozenset(), {}, direct_trigger_proof=True),
            "not-reportable",
        )

    def test_reviewed_in_model_trigger_publishes_despite_finder_label(self) -> None:
        """The correction reaches a finding through a real vote file."""
        payload = trigger_vote(self.report, self.root)
        payload["review_facts"] = {"trigger_controls_fit": "within"}
        (self.finding / ".trigger-gate.json").write_text(
            json.dumps(payload), encoding="utf-8",
        )
        with mock.patch.object(
            triage, "evaluate_crash_verdict",
            return_value=("out-of-model", "trigger requires call-sequence"),
        ), mock.patch.object(triage, "_run_tool", return_value=0):
            self.assertEqual(
                triage._finalize_accepted_finding(
                    self.finding, self.root, self.report, None, prepared=True,
                ),
                "accepted",
            )
        receipt = validation_receipt.read_current(self.finding)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "reportable")
        self.assertEqual(
            receipt["evidence"]["review_facts"]["trigger_controls_fit"],
            "within",
        )

    def test_no_added_boundary_is_preserved_as_not_reportable(self) -> None:
        vote_path = self.finding / ".trigger-gate.json"
        payload = trigger_vote(self.report, self.root, "Reject")
        payload["review_facts"] = {
            "rejection_kind": "no-added-boundary",
            "vulnerable_boundary_surface": "dev-tool",
        }
        vote_path.write_text(json.dumps(payload), encoding="utf-8")
        (self.finding / ".trigger-gate-2.json").write_text(
            json.dumps(payload), encoding="utf-8",
        )
        with mock.patch.object(
            triage, "_run_tool", return_value=0,
        ) as scorer, mock.patch.object(
            triage, "_record_accepted_finding_card",
        ) as record_productive:
            self.assertEqual(
                triage._finalize_accepted_finding(
                    self.finding, self.root, self.report, None, None,
                    prepared=True,
                ),
                "accepted",
            )
        receipt = validation_receipt.read_current(self.finding)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "not-reportable")
        scorer.assert_called_once_with(
            "severity", "--report", str(self.finding),
        )
        record_productive.assert_not_called()

    def test_failed_severity_clear_holds_the_artifact_retryable(self) -> None:
        """A final receipt must not freeze a voided score onto the report.

        The scorer is what removes it, and the next pass skips current final
        receipts, so a swallowed failure would leave a numeric CVSS line beside
        the decision that voided it for good.
        """
        vote_path = self.finding / ".trigger-gate.json"
        payload = trigger_vote(self.report, self.root, "Reject")
        payload["review_facts"] = {
            "rejection_kind": "no-added-boundary",
            "vulnerable_boundary_surface": "dev-tool",
        }
        vote_path.write_text(json.dumps(payload), encoding="utf-8")
        (self.finding / ".trigger-gate-2.json").write_text(
            json.dumps(payload), encoding="utf-8",
        )
        with mock.patch.object(
            triage, "_run_tool", return_value=1,
        ), contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(
                triage._finalize_accepted_finding(
                    self.finding, self.root, self.report, None, None,
                    prepared=True,
                ),
                "pending",
            )
        receipt = validation_receipt.read_current(self.finding)
        self.assertIsNotNone(receipt)
        self.assertEqual(receipt["state"], "pending")
        self.assertIn("obsolete numeric severity", stderr.getvalue())


class DecisionTimeoutBackoffTests(unittest.TestCase):
    def test_decision_timeout_honors_the_session_setting_and_backend_tier(self) -> None:
        for backend, expected in (
            ("codex", 45), ("claude", 45), ("oss", 180), ("", 45),
        ):
            with mock.patch.dict(
                os.environ, {"ACTIVE_BACKEND": backend}, clear=True,
            ):
                self.assertEqual(llm_decide.decision_timeout("unmeasured"), expected)
        for value, expected in (
            ("17", 17), ("45", 45), ("180", 180), ("0", 45),
            ("junk", 45), ("", 45),
        ):
            with mock.patch.dict(
                os.environ,
                {"LLM_DECISION_TIMEOUT": value, "ACTIVE_BACKEND": "codex"},
                clear=True,
            ):
                self.assertEqual(llm_decide.decision_timeout("unmeasured"), expected)

    def test_agent_reading_decisions_get_their_measured_default(self) -> None:
        # Hosted, then the same values scaled by the oss tier ratio.
        for backend, expand, rerank, other in (
            ("claude", 800, 150, 45), ("oss", 3200, 600, 180),
        ):
            with mock.patch.dict(
                os.environ, {"ACTIVE_BACKEND": backend}, clear=True,
            ):
                self.assertEqual(llm_decide.decision_timeout("cluster_expand"), expand)
                self.assertEqual(llm_decide.decision_timeout("work_rerank"), rerank)
                self.assertEqual(llm_decide.decision_timeout("find_quality_batch"), other)

    def test_decision_timeout_requires_a_decision_name(self) -> None:
        with self.assertRaises(TypeError):
            llm_decide.decision_timeout()  # type: ignore[call-arg]

    def test_explicit_setting_overrides_the_measured_default_downward(self) -> None:
        # A per-decision default is a default, never a floor over the operator.
        with mock.patch.dict(
            os.environ,
            {"LLM_DECISION_TIMEOUT": "30", "ACTIVE_BACKEND": "claude"},
            clear=True,
        ):
            self.assertEqual(llm_decide.decision_timeout("cluster_expand"), 30)
            self.assertEqual(llm_decide.decision_timeout("work_rerank"), 30)

    def _runtime(self, base: Path, decision_timeout: int) -> "audit_runner.Runtime":
        return audit_runner.Runtime(
            root=base, target_root=base, target_slug="sampleproj",
            output_slug="sampleproj", backend="claude", model="",
            config=target_config.Config(
                target_root=str(base), is_browser="0",
                sanitizers_explicitly_disabled=False,
                sanitizers_enabled=["asan"],
            ),
            target_rev="HEAD", repo_type="none",
            results=base, logs=base, raw=base,
            index=base / "index.log", index_jsonl=base / "index.jsonl",
            num_agents=1, browser_agents=0, shell_agents=1,
            agent_roles=(), fixed_strategy="", decision_timeout=decision_timeout,
        )

    def test_operator_decision_timeout_records_only_an_explicit_choice(self) -> None:
        for override in (None, ""):
            self.assertEqual(audit_runner._operator_decision_timeout(override), 0)
        self.assertEqual(audit_runner._operator_decision_timeout("240"), 240)
        for bad in ("0", "-5", "junk"):
            with self.assertRaises(ValueError):
                audit_runner._operator_decision_timeout(bad)

    def test_activate_runtime_exports_only_a_real_operator_choice(self) -> None:
        with tempfile.TemporaryDirectory(prefix="activate-runtime-") as tmp:
            base = Path(tmp)
            # No operator choice: nothing exported, so the per-decision default
            # applies. Exporting a resolved tier default would suppress it.
            with mock.patch.dict(os.environ, {}, clear=True):
                audit_runner._activate_runtime(self._runtime(base, 0))
                self.assertNotIn("LLM_DECISION_TIMEOUT", os.environ)
                self.assertEqual(llm_decide.decision_timeout("cluster_expand"), 800)
            # A choice the runtime carries reaches the decision, whether or not
            # it was already in this environment.
            with mock.patch.dict(os.environ, {}, clear=True):
                audit_runner._activate_runtime(self._runtime(base, 30))
                self.assertEqual(os.environ["LLM_DECISION_TIMEOUT"], "30")
                self.assertEqual(llm_decide.decision_timeout("cluster_expand"), 30)
            # A stale value from an earlier runtime does not leak into one that
            # carries no choice.
            with mock.patch.dict(
                os.environ, {"LLM_DECISION_TIMEOUT": "30"}, clear=True,
            ):
                audit_runner._activate_runtime(self._runtime(base, 0))
                self.assertNotIn("LLM_DECISION_TIMEOUT", os.environ)

    def test_activate_runtime_exports_only_its_pinned_config_digest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="activate-config-") as tmp:
            base = Path(tmp)
            runtime = self._runtime(base, 0)
            target_config.write_session_env(
                base, str(base), str(base), "sampleproj", "HEAD", str(base),
            )
            config = base / "target.toml"
            config.write_text(
                'target = "sampleproj"\n'
                '[threat_model]\nattacker_controls = ["bytes"]\n',
                encoding="utf-8",
            )
            digest = target_config.pin_session_config(base, config)
            with mock.patch.dict(os.environ, {}, clear=True):
                audit_runner._activate_runtime(runtime)
                self.assertEqual(
                    os.environ.get("TARGET_CONFIG_SHA256"), digest,
                )
                finding = base / "findings" / "FIND-001"
                finding.mkdir(parents=True)
                (finding / "report.md").write_text(
                    "# source-backed finding\n", encoding="utf-8",
                )
                receipt = validation_receipt.write(
                    finding, kind="finding", state="reportable",
                )
                self.assertEqual(
                    receipt["evidence"]["target_config_sha256"], digest,
                )
            (base / ".session-env").write_text(
                "RESULTS_DIR=" + str(base) + "\n",
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ, {"TARGET_CONFIG_SHA256": "stale"}, clear=True,
            ):
                audit_runner._activate_runtime(runtime)
                self.assertNotIn("TARGET_CONFIG_SHA256", os.environ)

    def test_standalone_find_gate_keeps_its_batched_fallback(self) -> None:
        with tempfile.TemporaryDirectory(prefix="find-gate-timeout-") as tmp:
            results = Path(tmp)
            finding = results / "findings" / "FIND-001"
            finding.mkdir(parents=True)
            (finding / "report.md").write_text("# concrete finding\n")
            captured: list[int] = []

            def batch(_directories, _results, _q, _aq, timeout, *_args):
                captured.append(timeout)
                return {}

            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(
                triage, "_batch_quality_votes", side_effect=batch,
            ), mock.patch.object(
                triage, "validate_one_finding", return_value="pending",
            ):
                self.assertEqual(
                    triage.validate_find_gate(results, workers=1),
                    {"accepted": 0, "rejected": 0, "pending": 1},
                )
            self.assertEqual(captured, [300])

    def test_exact_timed_out_prompt_is_deferred_after_one_full_timeout(self) -> None:
        with tempfile.TemporaryDirectory(prefix="decision-timeout-") as tmp:
            environment = {
                "ACTIVE_BACKEND": "codex",
                "LLM_DECIDE_FAILCACHE_FILE": str(Path(tmp) / "failcache.json"),
                "LLM_DECIDE_LOG": str(Path(tmp) / "decisions.log"),
                "LLM_DECIDE_MAX_CALLS": "0",
                "LLM_DECIDE_FAIL_THRESHOLD": "2",
                "LLM_DECIDE_FAIL_COOLDOWN": "300",
            }
            timeout = subprocess.TimeoutExpired(["codex"], 1)
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
                llm_decide, "_invoke_backend", side_effect=timeout,
            ) as invoke:
                self.assertIsNone(llm_decide.llm_decide("cluster_expand", "rows", "same prompt", 1))
                self.assertIsNone(llm_decide.llm_decide("cluster_expand", "rows", "same prompt", 1))
            self.assertEqual(invoke.call_count, 1)

    def test_timeout_backoff_is_exact_keyed_and_half_opens(self) -> None:
        with tempfile.TemporaryDirectory(prefix="decision-timeout-scope-") as tmp:
            environment = {
                "ACTIVE_BACKEND": "codex",
                "LLM_DECIDE_FAILCACHE_FILE": str(Path(tmp) / "failcache.json"),
                "LLM_DECIDE_LOG": str(Path(tmp) / "decisions.log"),
                "LLM_DECIDE_MAX_CALLS": "0",
                "LLM_DECIDE_FAIL_THRESHOLD": "2",
                "LLM_DECIDE_FAIL_COOLDOWN": "300",
            }
            now = [100.0]
            timeout = subprocess.TimeoutExpired(["codex"], 1)
            with mock.patch.dict(os.environ, environment, clear=True), mock.patch.object(
                llm_decide.time, "time", side_effect=lambda: now[0],
            ), mock.patch.object(
                llm_decide, "_invoke_backend",
                side_effect=[timeout, '{"rows":[]}', '{"rows":[]}'],
            ) as invoke:
                self.assertIsNone(llm_decide.llm_decide(
                    "cluster_expand", "rows", "slow prompt", 1,
                ))
                self.assertEqual(llm_decide.llm_decide(
                    "cluster_expand", "rows", "unrelated prompt", 1,
                ), {"rows": []})
                self.assertIsNone(llm_decide.llm_decide(
                    "cluster_expand", "rows", "slow prompt", 1,
                ))
                now[0] = 401.0
                self.assertEqual(llm_decide.llm_decide(
                    "cluster_expand", "rows", "slow prompt", 1,
                ), {"rows": []})
            self.assertEqual(invoke.call_count, 3)


class ValidatorScratchPlacementTests(unittest.TestCase):
    """The validator's .validator-cwd must never land inside a pooled artifact.

    f51b3a6 made the scratch view persistent in the results tree, anchored on a
    `results`-named ancestor. Model-direct benchmark cells have no such ancestor
    (the cell dir is the results dir), so the scratch was landing inside each
    findings/FIND-N/ dir and breaking pool copy/remove.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="validator-cwd-place-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.target.mkdir()
        (self.target / "src.c").write_text("int main(void){return 0;}\n")
        self.validator_cwd = runpy.run_path(
            str(ROOT / "bin" / "validate-finding")
        )["validator_cwd"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _report(self, results: Path) -> Path:
        report = results / "findings" / "FIND-1" / "report.md"
        report.parent.mkdir(parents=True)
        report.write_text("# finding\n")
        return report

    def test_model_direct_scratch_anchors_outside_finding_dir(self) -> None:
        # Cell dir is the results dir; no `results`-named ancestor.
        results = self.root / "cells" / "model-direct-r1"
        report = self._report(results)
        cwd = self.validator_cwd(report, self.target)
        self.assertEqual(cwd, results / ".validator-cwd")
        self.assertNotIn("FIND-1", cwd.parts)
        self.assertTrue((cwd / "src.c").is_symlink())

    def test_harness_scratch_still_anchors_at_results_root(self) -> None:
        results = self.root / "output" / "x" / "codex" / "results"
        report = self._report(results)
        cwd = self.validator_cwd(report, self.target)
        self.assertEqual(cwd, results / ".validator-cwd")


if __name__ == "__main__":
    unittest.main(verbosity=2)
