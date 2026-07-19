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

    def render(self, config: target_config.Config | None = None) -> str:
        context = prompt.PromptContext(
            results_dir=self.results,
            target_root=self.target,
            target_slug="sampleproj",
            reference_dir=self.references,
            num_agents=1,
            agent_roles=("reproduce",),
            config=config,
        )
        return prompt.deep_investigation_prompt(context, 1)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
