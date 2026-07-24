#!/usr/bin/env python3
"""Regression coverage for incremental, recall-safe finding validation."""

from __future__ import annotations

import json
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

import benchmark  # noqa: E402
import finding_signature  # noqa: E402
import llm_decide  # noqa: E402
import report_identity  # noqa: E402
import triage  # noqa: E402
import triage_validate  # noqa: E402


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


def _write_batch_votes(command: list[str], only: set[str] | None = None) -> None:
    """Simulate the batched trigger validator: write a valid cached vote for each
    manifest item (optionally only a subset), so the caller sees those ids as
    voted and the rest as still-missing."""
    manifest = Path(command[command.index("--batch-manifest") + 1])
    for item in json.loads(manifest.read_text(encoding="utf-8"))["items"]:
        if only is not None and item["id"] not in only:
            continue
        finding = Path(item["finding"])
        Path(item["output"]).write_text(json.dumps({
            "vote": "Promote",
            "content_sha1": sorted(report_identity.content_sha1_candidates(finding))[0],
            "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
            "attacker_controls": triage_validate.trigger_attacker_controls(),
        }), encoding="utf-8")


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
            triage, "_batch_reach_field_decisions", return_value=(set(), {}),
        ):
            return triage.validate_find_gate(self.root, workers=2)

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
            "decision_version": "v13-python",
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
            "decision_version": "v13-python",
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

        trigger = {
            "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
            "content_sha1": legacy_sha1,
            "attacker_controls": controls,
            "vote": "Promote",
        }
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

        def trigger(_directory, report, *_args, **_kwargs):
            self.assertIn("## Severity rationale", report.read_text())
            return False

        with mock.patch.object(triage, "fill_reach_fields", side_effect=enrich), mock.patch.object(
            triage, "_finding_trigger_rejected", side_effect=trigger,
        ), mock.patch.object(triage, "_run_tool", side_effect=score):
            self.assertEqual(
                triage._finalize_accepted_finding(
                    self.finding, self.root, self.report, None,
                ),
                "accepted",
            )
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
        (self.finding / ".trigger-gate.json").write_text(json.dumps({
            "content_sha1": report_identity.content_sha1(self.report),
            "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
            "attacker_controls": triage_validate.trigger_attacker_controls(),
            "vote": "Promote",
        }))
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

        def decide(*_args, **_kwargs):
            nonlocal active, maximum, calls
            with lock:
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

    def test_transient_trigger_batch_is_not_retried(self) -> None:
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
        self.assertEqual(calls, 1)  # a timeout is never hot-retried

    def test_trigger_cache_requires_current_prompt_and_report(self) -> None:
        cache = self.finding / ".trigger-gate.json"
        cache.write_text(json.dumps({
            "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
            "content_sha1": report_identity.content_sha1(self.report),
            "attacker_controls": triage_validate.trigger_attacker_controls(),
            "vote": "Promote",
        }))
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
            cache.write_text(json.dumps({
                "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
                "content_sha1": sha, "attacker_controls": ["bytes"], "vote": "Reject",
            }))
            self.assertEqual(  # matching controls -> cached Reject reused
                triage._trigger_vote(self.report, cache, "codex", "x", self.root), 1)
            cache.write_text(json.dumps({
                "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
                "content_sha1": sha,
                "attacker_controls": ["bytes", "call-sequence"], "vote": "Reject",
            }))
            self.assertEqual(  # controls changed -> not reused (LLM disabled -> 2)
                triage._trigger_vote(self.report, cache, "codex", "x", self.root), 2)
            legacy = {"decision_version": "trigger-v2-caller-buffer", "content_sha1": sha}
            cache.write_text(json.dumps({**legacy, "vote": "Promote"}))
            self.assertEqual(  # legacy keep reused (fail-open)
                triage._trigger_vote(self.report, cache, "codex", "x", self.root), 0)
            cache.write_text(json.dumps({**legacy, "vote": "Reject"}))
            self.assertEqual(  # legacy Reject never reused -> fresh review
                triage._trigger_vote(self.report, cache, "codex", "x", self.root), 2)

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
                self.report.read_text() + "\nBoundary: public API\n",
                encoding="utf-8",
            )
            return True

        def batch(directories, *_args, **_kwargs):
            self.assertEqual(directories, [self.finding])
            self.assertIn("Boundary: public API", self.report.read_text())
            (self.finding / ".trigger-gate.json").write_text(json.dumps({
                "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
                "content_sha1": report_identity.content_sha1(self.report),
                "attacker_controls": triage_validate.trigger_attacker_controls(),
                "vote": "Promote",
            }))
            return {self.finding}

        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(self.root),
        }, clear=False), mock.patch.object(
            triage, "_batch_reach_field_decisions",
            return_value=({self.finding}, {self.finding: {}}),
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
            return_value=({self.finding}, {self.finding: {}}),
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
            cache.write_text(json.dumps({
                "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
                "content_sha1": report_identity.content_sha1(self.report),
                "attacker_controls": triage_validate.trigger_attacker_controls(),
                "vote": "Reject",
            }))
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
        stamped = validator["stamp_trigger_vote"](
            args, {"vote": "Promote"}, "report-sha1",
        )
        self.assertEqual(
            stamped,
            {
                "vote": "Promote",
                "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
                "content_sha1": "report-sha1",
                "attacker_controls": triage_validate.trigger_attacker_controls(),
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


class DecisionTimeoutBackoffTests(unittest.TestCase):
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
