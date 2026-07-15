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
        self.assertEqual(benchmark.count_confirmed_findings(self.finding.parent)[0], 1)
        self.assertEqual(finding_signature.read_llm_cache(self.finding)["class"], "auth:bypass")
        self.report.write_text(
            self.report.read_text() + "\n## Reachability — external callers\n\nRevised.\n",
            encoding="utf-8",
        )
        self.assertEqual(benchmark.count_confirmed_findings(self.finding.parent)[0], 0)
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

    def test_trigger_cache_requires_current_prompt_and_report(self) -> None:
        cache = self.finding / ".trigger-gate.json"
        cache.write_text(json.dumps({
            "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
            "content_sha1": report_identity.content_sha1(self.report),
            "attacker_controls": ["bytes"],
            "vote": "Promote",
        }))
        with mock.patch.dict(os.environ, {
            "LLM_DECIDE_DISABLE": "1",
            "TARGET_ATTACKER_CONTROLS_CSV": "bytes",
        }, clear=False):
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

    def test_trigger_cache_is_bound_to_attacker_controls(self) -> None:
        cache = self.finding / ".trigger-gate.json"
        cache.write_text(json.dumps({
            "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
            "content_sha1": report_identity.content_sha1(self.report),
            "attacker_controls": ["bytes"],
            "vote": "Promote",
        }))
        with mock.patch.dict(os.environ, {
            "LLM_DECIDE_DISABLE": "1",
            "TARGET_ATTACKER_CONTROLS_CSV": "bytes,call-sequence",
        }, clear=False):
            self.assertEqual(
                triage._trigger_vote(
                    self.report, cache, "codex", "fixture", self.root,
                ),
                2,
            )

    def test_legacy_trigger_cache_reuses_only_fail_open_votes(self) -> None:
        cache = self.finding / ".trigger-gate.json"
        base = {
            "decision_version": "trigger-v2-caller-buffer",
            "content_sha1": report_identity.content_sha1(self.report),
        }
        with mock.patch.dict(os.environ, {"LLM_DECIDE_DISABLE": "1"}, clear=False):
            cache.write_text(json.dumps({**base, "vote": "Promote"}))
            self.assertEqual(
                triage._trigger_vote(
                    self.report, cache, "codex", "fixture", self.root,
                ),
                0,
            )
            cache.write_text(json.dumps({**base, "vote": "Reject"}))
            self.assertEqual(
                triage._trigger_vote(
                    self.report, cache, "codex", "fixture", self.root,
                ),
                2,
            )

    def test_finding_trigger_rejection_requires_two_negative_votes(self) -> None:
        environment = {"BACKEND": "codex", "TARGET_ROOT": str(self.root)}
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
            triage, "_trigger_vote", side_effect=[1, 0],
        ) as votes:
            self.assertFalse(triage._finding_trigger_rejected(
                self.finding, self.report,
            ))
            self.assertEqual(votes.call_count, 2)
        with mock.patch.dict(os.environ, environment, clear=False), mock.patch.object(
            triage, "_trigger_vote", side_effect=[1, 1],
        ) as votes:
            self.assertTrue(triage._finding_trigger_rejected(
                self.finding, self.report,
            ))
            self.assertEqual(votes.call_count, 2)

    def test_trigger_validator_stamps_cache_identity(self) -> None:
        validator = runpy.run_path(str(ROOT / "bin" / "validate-finding"))
        args = validator["parse_args"]([
            "--finding", str(self.report),
            "--target-path", str(self.root),
            "--backend", "codex",
            "--gate", "trigger",
        ])
        with mock.patch.dict(
            os.environ, {"TARGET_ATTACKER_CONTROLS_CSV": "bytes"}, clear=False,
        ):
            stamped = validator["stamp_trigger_vote"](
                args, {"vote": "Promote"}, "report-sha1",
            )
        self.assertEqual(
            stamped,
            {
                "vote": "Promote",
                "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
                "content_sha1": "report-sha1",
                "attacker_controls": ["bytes"],
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
