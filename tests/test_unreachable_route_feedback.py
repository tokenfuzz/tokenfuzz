#!/usr/bin/env python3
"""A disproved trigger route must reach the next session that would repeat it.

The trigger gate writes a precise, anchored reason for every rejection, then
moves the artifact and drops the reason. Measured across four targets, 55% of
trigger rejections landed on a file that had already produced one in the same
run, each paying a full harness / confirm / bundle / enrich cycle to re-derive
the same answer.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import prompt  # noqa: E402
import triage  # noqa: E402
import workqueue  # noqa: E402


DISPROOF = (
    "Clause (c). Blocking invariant: sampleproj/app.c:app_open:41 clears the "
    "borrowed pointer on every path that set it, so only the caller freeing "
    "its own buffer mid-call reaches the reported state."
)


class UnreachableRouteFeedbackTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="unreachable-routes-")
        self.root = Path(self.temporary.name)
        self.results = self.root / "results"
        (self.results / "state").mkdir(parents=True)
        self.target = self.root / "target"
        self.target.mkdir()
        self.references = self.root / "references"
        self.references.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def artifact(self, name: str, *, disproof: str = DISPROOF, path: str = "src/app.c") -> Path:
        directory = self.results / "findings" / name
        directory.mkdir(parents=True)
        (directory / "report.md").write_text("# report\n", encoding="utf-8")
        (directory / ".trigger-gate.json").write_text(json.dumps({
            "anchors": [{"path": path, "symbol": "app_parse", "line": 91}],
            "disproof": disproof,
        }), encoding="utf-8")
        return directory

    def routes(self) -> list[dict]:
        return workqueue.read_jsonl(
            self.results / "state" / "unreachable-routes.jsonl"
        )

    def test_only_a_trigger_rejection_records_a_route(self) -> None:
        triage._reject(
            self.artifact("FIND-001"), self.results / "findings-rejected",
            "trigger-provenance: triggering state not attacker-reachable",
            category=workqueue.UNREACHABLE_REJECTION_CATEGORY,
        )
        recorded = self.routes()
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0]["file"], "src/app.c")
        self.assertEqual(recorded[0]["symbol"], "app_parse")
        self.assertIn("Blocking invariant", recorded[0]["summary"])
        self.assertIn(
            "Clause (c)", recorded[0]["summary"],
            "the clause label alone is useless, but it must survive with the reason",
        )

        # A rejection for any other reason leaves no route behind.
        triage._reject(
            self.artifact("FIND-002"), self.results / "findings-rejected",
            "find-quality: no security impact",
        )
        self.assertEqual(len(self.routes()), 1)

    def test_a_gate_without_usable_anchors_records_nothing(self) -> None:
        directory = self.results / "findings" / "FIND-003"
        directory.mkdir(parents=True)
        (directory / ".trigger-gate.json").write_text(
            json.dumps({"anchors": [], "disproof": DISPROOF}), encoding="utf-8",
        )
        triage._reject(
            directory, self.results / "findings-rejected",
            "trigger-provenance: triggering state not attacker-reachable",
            category=workqueue.UNREACHABLE_REJECTION_CATEGORY,
        )
        self.assertEqual(self.routes(), [])

    def test_the_next_card_on_that_file_carries_the_disproof(self) -> None:
        triage._reject(
            self.artifact("FIND-004"), self.results / "findings-rejected",
            "trigger-provenance: triggering state not attacker-reachable",
            category=workqueue.UNREACHABLE_REJECTION_CATEGORY,
        )
        workqueue.write_cards(self.results / "work-cards.jsonl", [{
            "id": "WORK-A", "kind": "ranked-source", "file": "src/app.c",
            "subsystem": "src", "strategy": "S5", "mode": "generic",
            "score": 40, "reason": "lifetime/ownership operation",
            "status": "unclaimed",
        }])
        (self.results / "state" / "strategy-1").write_text("S5\n", encoding="utf-8")
        context = prompt.PromptContext(
            results_dir=self.results, target_root=self.target,
            target_slug="sampleproj", reference_dir=self.references,
            num_agents=1, repo_type="none",
        )
        rendered = prompt.work_card_directive(context, 1, force=True)

        self.assertIn("Trigger routes already disproved on this file", rendered)
        self.assertIn("app_parse", rendered)
        self.assertIn("Blocking invariant", rendered)
        # Advisory, not a filter: the card is still assigned and another route
        # is explicitly still worth taking, or a real defect reachable a second
        # way would be lost.
        self.assertIn("WORK-A", rendered)
        self.assertIn("rule out a *route*, not the file", rendered)

    def test_an_unrelated_file_gets_no_note_and_repeats_collapse(self) -> None:
        for index, path in enumerate(("src/app.c", "src/app.c", "src/other.c")):
            triage._reject(
                self.artifact(f"FIND-1{index}", path=path),
                self.results / "findings-rejected",
                "trigger-provenance: triggering state not attacker-reachable",
                category=workqueue.UNREACHABLE_REJECTION_CATEGORY,
            )
        context = prompt.PromptContext(
            results_dir=self.results, target_root=self.target,
            target_slug="sampleproj", reference_dir=self.references,
            num_agents=1, repo_type="none",
        )
        self.assertEqual(len(self.routes()), 3)
        # Identical disproofs collapse, so a file rejected repeatedly does not
        # crowd the card with the same line.
        lines = prompt._ruled_out_routes(context, "src/app.c")
        self.assertEqual(
            sum(1 for line in lines if "Blocking invariant" in line), 1,
        )
        self.assertEqual(prompt._ruled_out_routes(context, "src/unseen.c"), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
