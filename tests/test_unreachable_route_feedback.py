#!/usr/bin/env python3
"""A disproved trigger route must reach the next session — and only while it holds.

The trigger gate writes a precise, anchored reason for every rejection, then
moves the artifact and drops the reason. Measured across four targets, 55% of
trigger rejections landed on a file that had already produced one in the same
run, each paying a full harness / confirm / bundle / enrich cycle to re-derive
the same answer.

The note tells a session not to rebuild a reproducer, so it must never outlive
the rejection it describes: the rejected artifact is the record of its own
rejection, and the gate requeues one whose verdict goes stale.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
TRIGGER_REASON = "trigger-provenance: triggering state not attacker-reachable"


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

    def artifact(
        self, name: str, *, disproof: str = DISPROOF,
        anchors: list[dict] | None = None, verified: bool = True,
    ) -> Path:
        directory = self.results / "findings" / name
        directory.mkdir(parents=True)
        (directory / "report.md").write_text("# report\n", encoding="utf-8")
        (directory / ".trigger-gate.json").write_text(json.dumps({
            "anchors": anchors if anchors is not None else [
                {"path": "src/app.c", "symbol": "app_parse", "line": 91},
            ],
            "anchors_verified": verified,
            "disproof": disproof,
        }), encoding="utf-8")
        return directory

    def reject(self, directory: Path, reason: str = TRIGGER_REASON) -> Path:
        return triage._reject(
            directory, self.results / "findings-rejected", reason,
            category=(
                workqueue.UNREACHABLE_REJECTION_CATEGORY
                if reason == TRIGGER_REASON else ""
            ),
        )

    def routes(self) -> list[dict]:
        return workqueue.read_jsonl(
            self.results / "state" / "unreachable-routes.jsonl"
        )

    def context(self) -> prompt.PromptContext:
        return prompt.PromptContext(
            results_dir=self.results, target_root=self.target,
            target_slug="sampleproj", reference_dir=self.references,
            num_agents=1, repo_type="none",
        )

    def test_only_a_trigger_rejection_records_a_route(self) -> None:
        self.reject(self.artifact("FIND-001"))
        recorded = self.routes()
        self.assertEqual(len(recorded), 1)
        self.assertEqual(recorded[0]["sites"][0]["file"], "src/app.c")
        self.assertEqual(recorded[0]["lane"], "findings-rejected")
        self.assertIn("Clause (c)", recorded[0]["summary"])
        self.assertIn("Blocking invariant", recorded[0]["summary"])

        self.reject(self.artifact("FIND-002"), "find-quality: no security impact")
        self.assertEqual(len(self.routes()), 1)

    def test_nothing_is_recorded_without_verified_anchors(self) -> None:
        self.reject(self.artifact("FIND-003", anchors=[]))
        self.assertEqual(self.routes(), [])
        # An unverified anchor set is the reviewer's unchecked claim about
        # where the code is, so it cannot key advice onto a file.
        self.reject(self.artifact("FIND-004", verified=False))
        self.assertEqual(self.routes(), [])

    def test_a_failed_move_records_nothing(self) -> None:
        """The artifact stays active, so no session may be told it was ruled out."""
        directory = self.artifact("FIND-005")
        with mock.patch.object(
            triage.shutil, "move", side_effect=OSError("device busy"),
        ):
            with self.assertRaises(OSError):
                self.reject(directory)
        self.assertEqual(self.routes(), [])
        self.assertTrue(directory.is_dir(), "the artifact is still active")

    def test_the_next_card_on_that_file_carries_the_disproof(self) -> None:
        self.reject(self.artifact("FIND-006"))
        workqueue.write_cards(self.results / "work-cards.jsonl", [{
            "id": "WORK-A", "kind": "ranked-source", "file": "src/app.c",
            "subsystem": "src", "strategy": "S5", "mode": "generic",
            "score": 40, "reason": "lifetime/ownership operation",
            "status": "unclaimed",
        }])
        (self.results / "state" / "strategy-1").write_text("S5\n", encoding="utf-8")
        rendered = prompt.work_card_directive(self.context(), 1, force=True)

        self.assertIn("Trigger routes already disproved on this file", rendered)
        self.assertIn("app_parse", rendered)
        self.assertIn("Blocking invariant", rendered)
        # Advisory, not a filter: the card is still assigned and another route
        # is explicitly still worth taking.
        self.assertIn("WORK-A", rendered)
        self.assertIn("rule out a *route*, not the file", rendered)

    def test_a_requeued_rejection_stops_being_advertised(self) -> None:
        """A stale verdict goes back for review; its note must go with it.

        The gate requeues a rejection whose report, revision, threat model, or
        decision version moved on. Leaving the note behind would keep telling
        sessions not to rebuild a reproducer the harness had itself reopened.
        """
        destination = self.reject(self.artifact("FIND-007"))
        context = self.context()
        self.assertTrue(prompt._ruled_out_routes(context, "src/app.c"))

        triage._restore_rejected_artifact(
            destination, self.results / "findings", kind="finding",
            detail="requeued because the trigger verdict is stale",
        )
        self.assertEqual(
            prompt._ruled_out_routes(context, "src/app.c"), [],
            "a reopened rejection advertises nothing",
        )
        self.assertEqual(self.routes(), [])

    def test_rejecting_a_reopened_artifact_cannot_revive_its_old_route(self) -> None:
        """Rejected paths are reusable, so path existence is not an identity."""
        destination = self.reject(self.artifact(
            "FIND-REUSE", disproof="Clause (c). The old route is impossible.",
        ))
        reopened = triage._restore_rejected_artifact(
            destination, self.results / "findings", kind="finding",
            detail="requeued because the trigger verdict is stale",
        )
        gate = reopened / ".trigger-gate.json"
        vote = json.loads(gate.read_text(encoding="utf-8"))
        vote["disproof"] = "Clause (c). The new review found another invariant."
        gate.write_text(json.dumps(vote), encoding="utf-8")

        self.reject(reopened)

        lines = "\n".join(prompt._ruled_out_routes(
            self.context(), "src/app.c",
        ))
        self.assertIn("new review", lines)
        self.assertNotIn("old route", lines)
        self.assertEqual(len(self.routes()), 1)

    def test_startup_reconciliation_retracts_stale_route_advice(self) -> None:
        """A resumed agent must not spend one cohort under an obsolete vote."""
        self.reject(self.artifact("FIND-STALE"))
        self.assertTrue(prompt._ruled_out_routes(self.context(), "src/app.c"))

        # The fixture vote deliberately lacks the current gate identity, just
        # like a rejection persisted by an older decision schema.
        self.assertEqual(
            triage.restore_stale_trigger_rejections(self.results), 1,
        )
        self.assertEqual(
            prompt._ruled_out_routes(self.context(), "src/app.c"), [],
        )
        self.assertEqual(self.routes(), [])

    def test_every_verified_anchor_carries_the_note(self) -> None:
        """The schema fixes no primary anchor.

        On the measured runs the leading anchor named a different file from the
        reported one 17 times in 61, so keying only on the first would land the
        note on a file whose agents never ran that route.
        """
        self.reject(self.artifact("FIND-008", anchors=[
            {"path": "src/caller.c", "symbol": "app_open", "line": 41},
            {"path": "src/app.c", "symbol": "app_parse", "line": 91},
        ]))
        context = self.context()
        for path, symbol in (("src/caller.c", "app_open"), ("src/app.c", "app_parse")):
            with self.subTest(path=path):
                lines = prompt._ruled_out_routes(context, path)
                self.assertTrue(lines)
                self.assertIn(symbol, "\n".join(lines))
        self.assertEqual(prompt._ruled_out_routes(context, "src/other.c"), [])

    def test_the_newest_routes_are_shown_and_repeats_collapse(self) -> None:
        """A session repeats the route it just watched fail."""
        for index in range(4):
            self.reject(self.artifact(
                f"FIND-01{index}", disproof=f"Clause (c). Route number {index}.",
            ))
        lines = "\n".join(prompt._ruled_out_routes(self.context(), "src/app.c"))

        self.assertIn("Route number 3", lines)
        self.assertNotIn("Route number 0", lines)

        # Identical disproofs collapse, so one repeatedly rejected route does
        # not crowd out the others.
        for index in range(3):
            self.reject(self.artifact(f"FIND-02{index}", disproof="Clause (c). Same route."))
        lines = prompt._ruled_out_routes(self.context(), "src/app.c")
        self.assertEqual(sum(1 for line in lines if "Same route" in line), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
