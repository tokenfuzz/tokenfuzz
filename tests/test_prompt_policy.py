#!/usr/bin/env python3
"""Behavior tests for the assembled deep-investigation policy."""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import prompt  # noqa: E402
import target_config  # noqa: E402
import workqueue  # noqa: E402


class DeepInvestigationPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.results = self.root / "results"
        state = self.results / "state"
        state.mkdir(parents=True)
        (state / "hypotheses.jsonl").write_text(
            json.dumps({
                "id": "H-1",
                "agent": "1",
                "status": "INVESTIGATING",
                "file": "src/sample.c:app_parse:91",
                "hypothesis": "boundary length reaches bounds",
                "input_shape": "document with boundary length",
                "guard_gap": "length accepted before copy",
                "diagnostic": "bounds",
                "strategy": "S2",
            }) + "\n",
            encoding="utf-8",
        )
        self.references = self.root / "references"
        self.references.mkdir()
        (self.references / "session-rules.digest.md").write_text(
            "SESSION DIGEST\n", encoding="utf-8"
        )
        self.target = self.root / "target"
        self.target.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def context(
        self, config: target_config.Config | None = None, role: str = "reproduce",
    ) -> prompt.PromptContext:
        return prompt.PromptContext(
            results_dir=self.results,
            target_root=self.target,
            target_slug="sampleproj",
            reference_dir=self.references,
            num_agents=1,
            agent_roles=(role,),
            config=config,
        )

    def render(self, config: target_config.Config | None = None) -> str:
        return prompt.deep_investigation_prompt(self.context(config), 1)

    def test_assembled_prompt_has_one_adaptive_policy_and_real_card_floor(self) -> None:
        rendered = self.render()
        compact = re.sub(r"\s+", " ", rendered)

        self.assertIn(
            "requires at least 3 card-linked CLEAN `bin/probe` runs across at least 2 distinct hypothesis shapes that were actually probed",
            compact,
        )
        self.assertIn("One run is enough only for a deterministic trigger", compact)
        self.assertIn("A HIT proves the location executed, not that its runtime predicate held", compact)
        self.assertIn("mark the hypothesis `ENV-BLOCKED`; that soft-blocks its owning card", compact)
        self.assertIn("A MISSED verdict alone is not proof of unreachability", compact)
        self.assertIn("session target configuration is pinned", compact)
        self.assertIn("never edit `target.toml`", compact)
        self.assertIn("Never put symlinks in FIND/CRASH bundles", compact)
        self.assertIn("Keep compiled harnesses on the public boundary", compact)
        self.assertIn("Fixture setup is testcase execution", compact)
        self.assertIn("do not invoke the target binary or library ad hoc", compact)
        self.assertIn("never overwrite a shared harness", compact)
        self.assertIn("refuses process wrappers that set loader interposition", compact)
        self.assertIn("inject a constructor that fabricates target-owned typed state", compact)
        self.assertIn("Wrapper testcases must fail closed", rendered)
        self.assertIn("A trailing `printf`", rendered)
        self.assertIn("direct `.sh` testcase is target input", rendered)
        self.assertIn("Source-only defects have no crash evidence to preserve", rendered)
        self.assertIn("record it with `bin/state add-note`", rendered)
        self.assertNotIn("Try at least three variants before discarding", rendered)
        self.assertNotIn("If CLEAN: write a variant", rendered)
        self.assertNotIn("running ASan on the first", rendered)
        self.assertNotIn("{{ card_discard_min_", rendered)

    def test_prompt_uses_the_same_configured_floor_as_enforcement(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "WORK_CARD_MIN_RUNS_BEFORE_DISCARD": "5",
                "WORK_CARD_MIN_HYPS_BEFORE_DISCARD": "4",
            },
            clear=False,
        ):
            self.assertEqual(workqueue.card_discard_requirements(), (5, 4))
            compact = re.sub(r"\s+", " ", self.render())

        self.assertIn(
            "requires at least 5 card-linked CLEAN `bin/probe` runs across at least 4 distinct hypothesis shapes that were actually probed",
            compact,
        )

    def test_findings_only_generic_prompt_is_runner_neutral(self) -> None:
        config = target_config.Config(
            slug="sampleproj",
            target_root=str(self.target),
            results_dir=str(self.results),
            sanitizers_explicitly_disabled=True,
            runner_bin="python3",
            runner_args=["{TESTCASE}"],
        )
        rendered = self.render(config)

        self.assertIn("SANITIZER BUILDS - DISABLED", rendered)
        self.assertIn("running `bin/probe` on the first", rendered)
        self.assertIn("`bin/probe` verdict", rendered)
        self.assertNotIn("running ASan on the first", rendered)
        self.assertNotIn("ASan verdict", rendered)

    def test_runtime_guide_matches_the_adaptive_policy(self) -> None:
        guide = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

        self.assertIn("DEPTH FOLLOWS EVIDENCE", guide)
        self.assertIn("at least 3 card-linked CLEAN `bin/probe` runs", guide)
        self.assertNotIn("2-3 DEEP investigations", guide)
        self.assertNotIn("Clean? → 2+ variants", guide)

    def test_resume_policy_continues_without_repeating_work(self) -> None:
        (self.results / ".session_seed_1.md").write_text(
            "src/sample.c:80-120 already reviewed\n", encoding="utf-8",
        )
        rendered = self.render()
        guide = (ROOT / "AGENTS.md").read_text(encoding="utf-8")

        for text in (rendered, guide):
            with self.subTest(source="prompt" if text is rendered else "guide"):
                self.assertIn("before claiming new work", text)
                self.assertIn("PRIOR SESSION SEED", text)
                self.assertNotIn("No new exploration", text)

        self.assertEqual(rendered.count("## PRIOR SESSION SEED"), 1)
        # The compact variant starts from structured state only: no seed
        # section and no seed body.
        compact = prompt.compact_fresh_prompt(self.context(), 1)
        self.assertNotIn("## PRIOR SESSION SEED", compact)
        self.assertNotIn("already reviewed", compact)

    def test_every_launch_variant_carries_the_runtime_contract(self) -> None:
        # A compact continuation is a NEW conversation with no memory of the
        # workflow, and it is the most common variant. It needs exact CLI
        # syntax and rollover guidance, but replaying the full 22 KB suffix
        # would erase much of the reason this variant is compact.
        context = self.context()
        for name, rendered in (
            ("cold", prompt.cold_start_prompt(context, 1)),
            ("compact", prompt.compact_fresh_prompt(context, 1)),
            ("deep", prompt.deep_investigation_prompt(context, 1)),
        ):
            with self.subTest(variant=name):
                self.assertIn("bin/state resume --agent", rendered)
                self.assertIn("TURN BUDGET", rendered)
                self.assertIn("Batch independent tool calls", rendered)
                self.assertIn("bin/probe", rendered)
                self.assertIn("target code must generate, transform, or inspect a seed", rendered)
                self.assertIn("kill by process name/argv", rendered)
                self.assertIn("`pkill`", rendered)
                self.assertIn("`killall`", rendered)
                self.assertRegex(rendered, r"including absolute\s+paths")
                self.assertIn("matched PIDs", rendered)
                # Report narrative contract — every variant that can file a
                # report must carry it, including the compact one, which has
                # no session-rules digest to fall back on.
                self.assertIn("## Report narrative", rendered)
                self.assertIn("**Impact**", rendered)
                self.assertEqual(rendered.count("## Report narrative"), 1)
        compact = prompt.compact_fresh_prompt(context, 1)
        self.assertIn("## COMPACT RUNTIME CONTRACT", compact)
        self.assertIn("bin/state update-hyp --id", compact)
        self.assertNotIn("## SESSION RULES DIGEST", compact)
        self.assertLess(len(compact), len(prompt.cold_start_prompt(context, 1)))
        compact_contract = prompt.compact_suffix(context, 1)
        self.assertIn("--strategy STRATEGY", compact_contract)
        self.assertNotIn("--strategy S1", compact_contract)

    def test_compact_prompt_defers_to_the_resumed_cards_strategy_gate(self) -> None:
        compact = prompt.compact_fresh_prompt(self.context(), 1)

        self.assertIn("follow its `Next action` from the structured resume", compact)
        self.assertIn("strategy-specific source, consumer, or input-route gate", compact)
        self.assertNotIn("If a card is assigned, create one hypothesis", compact)

    def test_turn_budget_is_backend_neutral_and_bounds_the_soft_target(self) -> None:
        self.assertEqual(prompt.DEFAULT_TURN_SOFT_CAP, 128)
        context = self.context()
        context.turn_soft_cap = 40
        suffix = prompt.common_suffix(context)

        self.assertIn("TURN BUDGET (all backends)", suffix)
        self.assertNotIn("codex sessions only", suffix)
        self.assertIn("~40 agent/tool turns", suffix)
        self.assertIn("Antigravity (`agy`)", suffix)
        # A self-pacing hint above the cap that actually ends the session is a
        # contradiction the agent reads as permission to run past it.
        self.assertEqual(context.soft_target(deep=True), 40)
        self.assertEqual(context.soft_target(deep=False), 40)
        context.turn_soft_cap = 0
        self.assertEqual(context.soft_target(deep=True), 150)
        uncapped = prompt.turn_budget_section(context)
        self.assertIn("rollover is disabled", uncapped)
        self.assertNotIn("~0", uncapped)

    def test_reproduce_prompts_put_execution_before_turn_twenty(self) -> None:
        context = self.context()
        for rendered in (
            prompt.cold_start_prompt(context, 1),
            prompt.deep_investigation_prompt(context, 1),
            prompt.compact_fresh_prompt(context, 1),
        ):
            with self.subTest(prompt=rendered.splitlines()[3:5]):
                self.assertIn("FIRST-PROBE CHECKPOINT", rendered)
                self.assertIn("before turn 20", rendered)
                self.assertIn("NO_EXEC does not satisfy", rendered)
                self.assertIn("--hypothesis-id H-...", rendered)

        cold = prompt.cold_start_prompt(context, 1)
        self.assertLess(cold.index("Record one concrete hypothesis"), cold.index("fill the same-subsystem queue"))
        self.assertLess(cold.index("bin/find-seed"), cold.index("fill the same-subsystem queue"))

        analysis = self.context(role="analysis")
        self.assertNotIn(
            "FIRST-PROBE CHECKPOINT", prompt.deep_investigation_prompt(analysis, 1),
        )

    def test_pinned_s6_verifies_the_peer_fix_before_creating_a_hypothesis(self) -> None:
        context = self.context()
        context.fixed_strategy = "S6"

        rendered = prompt.cold_start_prompt(context, 1)

        self.assertIn("S6 SOURCE GATE", rendered)
        self.assertIn("do not manufacture a testcase", rendered)
        self.assertIn("verify a target analogue", rendered)
        self.assertIn("Every hypothesis on this run must be Strategy S6.", rendered)
        # The default step 4 would have it file a hypothesis before the gate.
        self.assertNotIn(
            "Record one concrete hypothesis with `bin/state add-hyp`, take the best",
            rendered,
        )

    def test_a_pin_states_the_strategy_without_restating_the_workflow(self) -> None:
        context = self.context()
        context.fixed_strategy = "S3"

        rendered = prompt.cold_start_prompt(context, 1)

        self.assertIn("Every hypothesis on this run must be Strategy S3.", rendered)
        self.assertIn("Record one concrete hypothesis with `bin/state add-hyp`", rendered)

    def test_s1_cold_prompt_names_its_playbook(self) -> None:
        context = self.context()
        context.fixed_strategy = "S1"

        rendered = prompt.cold_start_prompt(context, 1)

        self.assertIn("Strategy brief (S1)", rendered)
        self.assertIn("S1-prior-fix-review.md", rendered)

    def test_prompt_allows_targeted_revisits_without_an_absolute_ban(self) -> None:
        rendered = self.render()

        # The absolute path-level ban caused false negatives on large sources.
        self.assertNotIn("Never read the same file path twice", rendered)
        self.assertIn("Revisiting a file for a different, targeted range is valid", rendered)
        self.assertIn("Prefer one useful range over many narrow overlapping reads", rendered)


class SharedPolicyAgreementTests(unittest.TestCase):
    """Rules restated across prompts, asserted as agreeing rather than present.

    The renderer has no include, so the emit contract, the harness FIND
    directive and the find-quality gate each carry the resource-exhaustion bar
    in their own voice. When one said "skip only when NEITHER fact holds"
    while another said "in scope only when BOTH hold", a report quantifying an
    amplification the project's own cap already neutralized passed emit and
    gate while the contract excluded it.
    """

    def read(self, *parts: str) -> str:
        return " ".join((ROOT.joinpath(*parts)).read_text(encoding="utf-8").split())

    def test_every_statement_of_the_rule_requires_both_facts(self) -> None:
        for name in ("audit_bug_contract.md.j2", "find_first_directive.md.j2",
                     "triage_find_quality.md.j2"):
            with self.subTest(prompt=name):
                body = self.read("lib", "prompts", name)
                self.assertIn("BOTH quantif", body)
                self.assertIn("AND show", body)
                # The De Morgan inversion that split them the first time.
                self.assertNotIn("neither the amplification", body)

    def test_application_supplied_reaches_the_scorer_from_author_docs(self) -> None:
        # Scoring must not depend on the bounded triage fill-in pass: the
        # agent needs the value in its own vocabulary and bin/severity has to
        # recognize it. Either end missing loses the precondition silently.
        for parts in ((".agents", "references", "session-rules.md"),
                      (".agents", "references", "session-rules.digest.md"),
                      ("bin", "severity")):
            with self.subTest(source=parts[-1]):
                self.assertIn("application-supplied", self.read(*parts))


    def test_unassigned_cold_worker_does_not_duplicate_a_leased_card(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = root / "results"
            target = root / "target"
            references = root / "references"
            target.mkdir()
            references.mkdir()
            queue_context = workqueue.Context(
                ROOT, target, "sampleproj", results, "none",
            )
            workqueue.init_state(queue_context)
            card = {
                "id": "WORK-ONLY", "kind": "ranked-source",
                "file": "src/parser.c", "subsystem": "src",
                "strategy": "S7", "mode": "generic", "score": 10,
                "reason": "parser boundary", "auditable": True,
            }
            workqueue.write_cards(results / "work-cards.jsonl", [card])
            claimed = workqueue.claim_next_card(
                queue_context, "3", "generic", "analysis", strategy="S7",
            )
            self.assertEqual(claimed["id"], "WORK-ONLY")
            context = prompt.PromptContext(
                results_dir=results, target_root=target,
                target_slug="sampleproj", reference_dir=references,
                num_agents=3, fixed_strategy="S7",
            )

            rendered = prompt.cold_start_prompt(context, 1)

            # audit_runner.should_skip_launch launches a cardless worker when a
            # fuzz lead is waiting, and launches agent 1 on nothing at all.
            # Exiting without reading those sources would drop the very work
            # those launches exist for.
            (results / "fuzz-leads.md").write_text(
                "# Fuzz leads\n\n- crash-000 reached app_parse\n", encoding="utf-8",
            )
            with_lead = prompt.cold_start_prompt(context, 1)

        self.assertIn("No work card is assigned", rendered)
        self.assertIn("Do not inspect the target", rendered)
        self.assertNotIn("fill the same-subsystem queue to 3-5 hypotheses", rendered)
        self.assertNotIn("No work card is assigned", with_lead)


if __name__ == "__main__":
    unittest.main(verbosity=2)
