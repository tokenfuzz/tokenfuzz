"""A promoted finding without machine proof gets a second reader through the
reachability lens before it publishes; rejection still needs two disproofs."""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
sys.path.insert(0, str(ROOT / "tests"))

import triage  # noqa: E402
import triage_validate  # noqa: E402
from test_triage_incremental_validation import trigger_vote  # noqa: E402


class SecondLensTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="second-lens-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "target"
        self.target.mkdir()
        self.finding = self.root / "findings" / "FIND-001"
        self.finding.mkdir(parents=True)
        self.report = self.finding / "report.md"
        self.report.write_text(
            "# State issue\n\nA caller-controlled request crosses an authorization boundary.\n",
            encoding="utf-8",
        )
        self.env = mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": "claude", "TARGET_ROOT": str(self.target),
        })
        self.env.start()
        self.addCleanup(self.env.stop)

    def _reviewer(self, answers: dict[str, str]):
        """A fake reviewer that writes the vote its file name is scripted for."""
        calls: list[tuple[str, str, bool]] = []

        def vote(report, vote_file, *_args, resolve=False, lens="", **_kwargs):
            calls.append((vote_file.name, lens, resolve))
            answer = answers.get(vote_file.name)
            if answer is None:
                return 2
            vote_file.write_text(
                json.dumps(trigger_vote(report, self.target, answer)), encoding="utf-8",
            )
            return 1 if answer == "Reject" else 0
        return calls, vote

    def _dispose(self, answers: dict[str, str]) -> tuple[str, list]:
        calls, vote = self._reviewer(answers)
        with mock.patch.object(triage, "_trigger_vote", side_effect=vote), \
             mock.patch.object(triage, "_promote_left_scope_open", return_value=False), \
             mock.patch.object(triage, "_trigger_rejection_is_dispositive", return_value=True):
            state = triage._finding_trigger_disposition(self.finding, self.report)
        return state, calls

    def test_a_second_reader_agreeing_publishes(self) -> None:
        state, calls = self._dispose({
            ".trigger-gate.json": "Promote", ".trigger-gate-2.json": "Promote",
        })
        self.assertEqual(state, "accepted")
        self.assertEqual(
            calls, [(".trigger-gate.json", "", False),
                    (".trigger-gate-2.json", triage.TRIGGER_SECOND_LENS, False)],
        )

    def test_a_split_goes_to_the_resolver_and_one_disproof_cannot_reject(self) -> None:
        state, calls = self._dispose({
            ".trigger-gate.json": "Promote", ".trigger-gate-2.json": "Uncertain",
            ".trigger-gate-resolution.json": "Reject",
        })
        self.assertEqual(state, "accepted")
        self.assertEqual(calls[-1], (".trigger-gate-resolution.json", "", True))

    def test_two_disproofs_after_a_promote_reject(self) -> None:
        state, _calls = self._dispose({
            ".trigger-gate.json": "Promote", ".trigger-gate-2.json": "Reject",
            ".trigger-gate-resolution.json": "Reject",
        })
        self.assertEqual(state, "rejected")

    def test_no_second_reviewer_leaves_the_first_verdict_standing(self) -> None:
        state, calls = self._dispose({".trigger-gate.json": "Promote"})
        self.assertEqual(state, "accepted")
        self.assertEqual(len(calls), 2)

    def test_a_machine_proved_finding_needs_no_second_reader(self) -> None:
        (self.finding / ".trigger-gate.json").write_text(
            json.dumps(trigger_vote(self.report, self.target, "Promote")), encoding="utf-8",
        )
        with mock.patch.object(triage, "_promote_left_scope_open", return_value=False):
            self.assertTrue(triage._second_review_due(self.finding, self.report))
            with mock.patch.object(triage, "_trigger_bypass_confirmed", return_value=True):
                self.assertFalse(triage._second_review_due(self.finding, self.report))

    def test_resolution_reads_both_reviews_after_a_promote_split(self) -> None:
        def names(first, second, first_fit="within", second_fit="within"):
            return triage_validate.trigger_resolution_review_names(
                first, second, first_fit=first_fit, second_fit=second_fit,
            )
        both = (".trigger-gate.json", ".trigger-gate-2.json")
        self.assertEqual(names("Promote", "Reject"), both)
        self.assertEqual(names("Promote", "Uncertain"), both)
        self.assertEqual(names("Promote", "Promote"), ())
        self.assertEqual(names("Promote", None, second_fit=None), ())
        # Agreeing on reachability is not agreeing on the scope that publishes.
        self.assertEqual(names("Promote", "Promote", second_fit="outside"), both)
        self.assertEqual(
            names("Promote", "Promote", first_fit="unclear"),
            (".trigger-gate.json",),
        )

    def test_the_validator_renders_the_lens_only_for_a_second_review(self) -> None:
        loader = __import__("importlib.machinery", fromlist=["SourceFileLoader"])
        module = loader.SourceFileLoader("validate_finding_cli", str(ROOT / "bin" / "validate-finding")).load_module()
        base = dict(target_path=str(self.target), tiebreak=False, resolve_trigger=False,
                    gate="trigger", target_root_is_product=False, timeout=30)
        from types import SimpleNamespace
        with_lens = module.render_validator_prompt(SimpleNamespace(lens="reachability", **base), {})
        without = module.render_validator_prompt(SimpleNamespace(lens="", **base), {})
        self.assertIn("Your lens: REACHABILITY", with_lens)
        self.assertNotIn("Your lens", without)
        self.assertIn(
            "Knowledge or guessing of a useful mapped address", without,
        )
        resolving = module.render_validator_prompt(
            SimpleNamespace(lens="reachability", **{**base, "resolve_trigger": True}), {})
        self.assertNotIn("Your lens", resolving)

    def test_a_review_stopped_at_the_tool_cap_is_not_logged_as_unparsable(self) -> None:
        loader = __import__("importlib.machinery", fromlist=["SourceFileLoader"])
        module = loader.SourceFileLoader("validate_finding_cli", str(ROOT / "bin" / "validate-finding")).load_module()
        outcomes = []
        with mock.patch.object(
            module.llm_decide, "log_decision",
            side_effect=lambda _decision, outcome, **_kwargs: outcomes.append(outcome),
        ):
            module.log_validator_decision("trigger-validator", 0, "p", 0.0, 30, 0, 1, True)
            module.log_validator_decision("trigger-validator", 0, "p", 0.0, 30, 0, 1)
        self.assertEqual(outcomes, ["FAIL turn-cap", "FAIL parse"])


    def test_a_hand_run_review_judges_under_the_pinned_threat_model(self) -> None:
        import hashlib
        loader = __import__("importlib.machinery", fromlist=["SourceFileLoader"])
        module = loader.SourceFileLoader("validate_finding_cli", str(ROOT / "bin" / "validate-finding")).load_module()
        config = self.root / ".target.toml"
        config.write_text(
            'target = "sampleproj"\n[threat_model]\nattacker_controls = ["bytes", "race"]\n',
            encoding="utf-8",
        )
        (self.root / ".session-env").write_text(
            f"RESULTS_DIR={self.root}\nTARGET_ROOT={self.target}\n"
            f"TARGET_CONFIG_SHA256={hashlib.sha256(config.read_bytes()).hexdigest()}\n",
            encoding="utf-8",
        )
        report = self.finding / "report.md"
        self.assertEqual(module.results_tree(report), self.root.resolve())
        with mock.patch.dict(os.environ, {
            "TARGET_ATTACKER_CONTROLS_CSV": "bytes", "TARGET_ROOT": "/elsewhere",
        }):
            module.adopt_pinned_session(module.results_tree(report))
            self.assertEqual(os.environ["TARGET_ATTACKER_CONTROLS_CSV"], "bytes,race")
            self.assertEqual(os.environ["TARGET_ROOT"], "/elsewhere",
                             "the caller's checkout still wins")

    def test_a_batch_spanning_results_trees_is_refused(self) -> None:
        # One process carries one tree's threat model and source root, so a
        # mixed batch would judge its later items under the first item's.
        other = self.root / "other"
        (other / "findings" / "FIND-9").mkdir(parents=True)
        (other / "findings" / "FIND-9" / "report.md").write_text("# other\n", encoding="utf-8")
        for tree in (self.root, other):
            (tree / ".session-env").write_text(f"RESULTS_DIR={tree}\n", encoding="utf-8")
        manifest = self.root / "batch.json"
        manifest.write_text(json.dumps({"items": [
            {"id": "a", "finding": str(self.finding / "report.md"), "output": str(self.root / "a.json")},
            {"id": "b", "finding": str(other / "findings" / "FIND-9" / "report.md"),
             "output": str(self.root / "b.json")},
        ]}), encoding="utf-8")
        result = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "validate-finding"), "--gate", "trigger",
             "--batch-manifest", str(manifest), "--target-path", str(self.target),
             "--backend", "codex"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn("spans results trees", result.stderr)

if __name__ == "__main__":
    unittest.main()
