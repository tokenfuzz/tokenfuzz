#!/usr/bin/env python3
"""The sealed background result gate that runs while agent slots are busy.

A result gate may only touch an artifact no live session can still write.
These cover the seal itself, what a sweep hands each gate, that a failing
sweep is loud and survivable, and that the pool gates a clean session's
findings while its peers keep running -- but never a turn-capped session's.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner  # noqa: E402
import triage  # noqa: E402


def _runtime(root: Path, num_agents: int = 2) -> SimpleNamespace:
    results = root / "results"
    (results / "findings").mkdir(parents=True)
    (results / "crashes").mkdir(parents=True)
    raw = root / "raw"
    raw.mkdir()
    return SimpleNamespace(
        num_agents=num_agents, index=root / "index.log", raw=raw,
        results=results, target_root=root / "target", target_slug="sampleproj",
        config=SimpleNamespace(
            attacker_controls=["bytes"], sanitizers_explicitly_disabled=False,
        ),
    )


def _artifact(results: Path, kind: str, name: str, *, skeleton: bool = False) -> Path:
    directory = results / kind / name
    directory.mkdir()
    body = "# Issue\n\nsampleproj\n"
    if skeleton:
        # What bin/probe files: fields the owning agent is told to replace.
        body += "Root cause: _TODO (agent): explain\n"
    (directory / "report.md").write_text(body, encoding="utf-8")
    return directory


class SealTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sealed-gate-")
        self.root = Path(self.temp.name)
        self.runtime = _runtime(self.root)
        self.results = self.runtime.results
        self.state = audit_runner.BackendState(self.runtime, mock.Mock(), iteration=1)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _worker(self) -> audit_runner.SealedGateWorker:
        with mock.patch.object(threading.Thread, "start"):
            return audit_runner.SealedGateWorker(self.state)

    def _sealed(self, worker) -> tuple[set[str], set[str]]:
        findings, crashes, _total_f, _total_c = worker.sealed()
        return {d.name for d in findings}, {d.name for d in crashes}

    def test_a_finding_is_sealed_once_every_live_chain_started_after_it(self) -> None:
        pre = _artifact(self.results, "findings", "FIND-001-pre")
        worker = self._worker()
        self.assertEqual(self._sealed(worker), ({pre.name}, set()))
        worker.launch(1, continuation=False)
        worker.launch(2, continuation=False)
        # Something filed while both chains run is unsealed until both end.
        filed = _artifact(self.results, "findings", "FIND-002-live")
        worker.observe()
        self.assertEqual(self._sealed(worker), ({pre.name}, set()))
        worker.retire(1)
        self.assertEqual(self._sealed(worker), ({pre.name}, set()))
        # Slot 1 relaunching a fresh chain does not unseal what it may have
        # filed earlier; slot 2's chain, older than the filing, still does.
        worker.launch(1, continuation=False)
        self.assertEqual(self._sealed(worker), ({pre.name}, set()))
        worker.retire(2)
        worker.launch(2, continuation=False)
        self.assertEqual(self._sealed(worker), ({pre.name, filed.name}, set()))

    def test_a_continuation_inherits_its_predecessors_chain(self) -> None:
        worker = self._worker()
        worker.launch(1, continuation=False)
        cut = _artifact(self.results, "findings", "FIND-003-cut")
        worker.observe()
        # Turn-capped: the successor resumes the cut session's in-flight work.
        worker.launch(1, continuation=True)
        self.assertEqual(self._sealed(worker), (set(), set()))
        worker.retire(1)
        worker.launch(1, continuation=True)
        # No chain to continue: a "continuation" with nothing in flight is a
        # fresh chain, and the earlier filing is behind it.
        self.assertEqual(self._sealed(worker), ({cut.name}, set()))

    def test_a_crash_is_sealed_by_its_owning_slot(self) -> None:
        worker = self._worker()
        worker.launch(1, continuation=False)
        mine = _artifact(self.results, "crashes", "CRASH-001-1")
        peer = _artifact(self.results, "crashes", "CRASH-002-2")
        unnamed = _artifact(self.results, "crashes", "CRASH-003")
        worker.observe()
        # Slot 2 is idle, so its crash is sealed even though slot 1 still
        # runs; slot 1's own crash is not; a name with no owner falls back to
        # the every-chain rule a finding uses.
        self.assertEqual(self._sealed(worker), (set(), {peer.name}))
        worker.retire(1)
        worker.launch(1, continuation=False)
        self.assertEqual(
            self._sealed(worker), (set(), {mine.name, peer.name, unnamed.name}),
        )

    def test_an_unfinished_crash_bundle_is_never_sealed(self) -> None:
        # bin/probe files a skeleton; the owner's next resume sends it back to
        # finish the bundle, so "owner's session ended" is no seal until the
        # bundle is complete -- and the chain that completes it is the one
        # the seal must then outwait. A triage hold does the same.
        worker = self._worker()
        worker.launch(1, continuation=False)
        skeleton = _artifact(self.results, "crashes", "CRASH-001-1", skeleton=True)
        held = _artifact(self.results, "crashes", "CRASH-002-1")
        (held / ".promotion_pending").write_text("missing: testcase\n", encoding="utf-8")
        worker.observe()
        worker.retire(1)
        self.assertEqual(self._sealed(worker), (set(), set()))
        # Slot 1's next session completes the skeleton and clears the hold.
        worker.launch(1, continuation=False)
        (skeleton / "report.md").write_text("# Issue\n\nRoot cause: known\n", encoding="utf-8")
        (held / ".promotion_pending").unlink()
        worker.observe()
        self.assertEqual(self._sealed(worker), (set(), set()))
        worker.retire(1)
        self.assertEqual(self._sealed(worker), (set(), {skeleton.name, held.name}))
        # Held again after a stamp: first-seen restarts from the completion
        # that follows, not the stamp that preceded the hold.
        (held / ".promotion_pending").write_text("missing: REPORT.md\n", encoding="utf-8")
        worker.observe()
        self.assertEqual(self._sealed(worker), (set(), {skeleton.name}))
        worker.launch(1, continuation=False)
        (held / ".promotion_pending").unlink()
        worker.observe()
        self.assertEqual(self._sealed(worker), (set(), {skeleton.name}))
        worker.retire(1)
        self.assertEqual(self._sealed(worker), (set(), {skeleton.name, held.name}))

    def test_a_sweep_hands_each_gate_only_the_sealed_set_and_never_ages(self) -> None:
        sealed_finding = _artifact(self.results, "findings", "FIND-001-old")
        sealed_crash = _artifact(self.results, "crashes", "CRASH-001-2")
        worker = self._worker()
        worker.launch(1, continuation=False)
        live_finding = _artifact(self.results, "findings", "FIND-002-live")
        live_crash = _artifact(self.results, "crashes", "CRASH-002-1")
        worker.observe()
        calls: dict[str, dict] = {}

        def crash_gate(*_args, **kwargs):
            calls["crash"] = kwargs
            return {"promoted": 1, "rejected": 0, "pending": 0, "demoted": 0}

        def find_gate(*_args, **kwargs):
            calls["find"] = kwargs
            return {"accepted": 1, "rejected": 0, "pending": 0}

        def expand(_runtime, **kwargs):
            calls["expand"] = kwargs
            return {"expanded": 0, "added": 0, "skipped": 0, "pending": 0}

        with mock.patch.object(triage, "triage_crash_dirs", side_effect=crash_gate), \
             mock.patch.object(triage, "validate_find_gate", side_effect=find_gate), \
             mock.patch.object(audit_runner, "expand_new_crash_clusters", side_effect=expand):
            worker._sweep()
        self.assertEqual(calls["crash"]["only"], [sealed_crash])
        self.assertFalse(calls["crash"]["age_pending"])
        self.assertEqual(calls["find"]["only"], [sealed_finding])
        self.assertEqual(calls["expand"]["only"], [sealed_crash])
        self.assertEqual(worker.sweeps, 1)
        self.assertTrue(live_finding.is_dir() and live_crash.is_dir())
        # Review cost stays on the timeline, marked as not blocking the pool.
        rows = [
            json.loads(line)
            for line in (self.results / "state" / "events.jsonl").read_text().splitlines()
        ]
        self.assertEqual(
            sorted((row["phase"], row["blocked"], row["iteration"]) for row in rows),
            [("crash_triage", False, 1), ("result_gates", False, 1)],
        )

    def test_a_failed_sweep_is_logged_and_the_worker_keeps_serving(self) -> None:
        _artifact(self.results, "findings", "FIND-001-old")
        worker = audit_runner.SealedGateWorker(self.state)
        try:
            served = threading.Event()

            def find_gate(*_args, **_kwargs):
                if not served.is_set():
                    served.set()
                    raise RuntimeError("provider exploded")
                return {"accepted": 1, "rejected": 0, "pending": 0}

            with mock.patch.object(triage, "validate_find_gate", side_effect=find_gate), \
                 mock.patch.object(
                     audit_runner, "expand_new_crash_clusters",
                     return_value={"expanded": 0, "added": 0, "skipped": 0, "pending": 0},
                 ):
                worker.request_sweep()
                self.assertTrue(served.wait(5))
                worker.request_sweep()
                deadline = time.monotonic() + 5
                while worker.sweeps < 1 and time.monotonic() < deadline:
                    time.sleep(0.01)
        finally:
            worker.close()
        self.assertEqual(worker.sweeps, 1)
        log = self.runtime.index.read_text(encoding="utf-8")
        self.assertIn("ERROR: background result gate failed: RuntimeError: provider exploded", log)

    def test_a_runtime_without_results_gates_nothing(self) -> None:
        state = audit_runner.BackendState(
            SimpleNamespace(num_agents=1, index=self.root / "i.log", raw=self.root),
            mock.Mock(), iteration=1,
        )
        worker = audit_runner.SealedGateWorker(state)
        worker.launch(1, continuation=False)
        worker.request_sweep()
        worker.close()
        self.assertEqual(worker.sweeps, 0)


    def _transcript(self, name: str, lines: list[dict]) -> Path:
        path = self.root / f"{name}.log.raw"
        path.write_text("\n".join(json.dumps(row) for row in lines) + "\n", encoding="utf-8")
        return path

    def test_attribution_reads_commands_and_file_writes_but_never_outputs(self) -> None:
        codex = self._transcript("codex", [
            {"type": "item.completed", "item": {"type": "command_execution",
             "command": "mkdir -p $R/findings/FIND-004-mine && cat > $R/findings/FIND-004-mine/report.md",
             "aggregated_output": "FIND-009-not-mine listed here\n"}},
            {"type": "item.completed", "item": {"type": "file_change",
             "changes": [{"path": "/r/crashes/CRASH-003-1/REPORT.md", "kind": "update"}]}},
            {"type": "item.completed", "item": {"type": "agent_message", "text": "see FIND-010-prose"}},
        ])
        claude = self._transcript("claude", [
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "name": "Write", "input": {"file_path": "/r/findings/FIND-005-theirs/report.md"}},
                {"type": "tool_use", "name": "Bash", "input": {"command": "bin/peek FIND-006-read/report.md"}},
            ]}},
            {"type": "user", "message": {"content": [
                {"type": "tool_result", "content": "FIND-007-output FIND-008-output"},
            ]}},
        ])
        self.assertEqual(
            audit_runner.audit_helpers.transcript_artifacts_touched(codex),
            {"FIND-004-mine", "CRASH-003-1"},
        )
        self.assertEqual(
            audit_runner.audit_helpers.transcript_artifacts_touched(claude),
            {"FIND-005-theirs", "FIND-006-read"},
        )
        self.assertEqual(
            audit_runner.audit_helpers.transcript_artifacts_touched(self.root / "missing.raw"), set(),
        )

    def test_a_touched_finding_seals_when_its_touchers_end_not_the_oldest_chain(self) -> None:
        worker = self._worker()
        worker.launch(2, continuation=False)   # the long-running peer, older than everything
        worker.launch(1, continuation=False)
        mine = _artifact(self.results, "findings", "FIND-001-mine")
        untouched = _artifact(self.results, "findings", "FIND-002-nobody")
        raw = self._transcript("s1", [{"type": "command_execution",
                                        "command": "cat > $R/findings/FIND-001-mine/report.md"}])
        worker.attribute(1, raw)
        worker.observe()
        # Slot 1 still running: nothing sealed.
        self.assertEqual(self._sealed(worker), (set(), set()))
        worker.retire(1)
        # Slot 1 ended: its finding seals although slot 2's older chain runs;
        # the untouched finding still waits for that chain.
        self.assertEqual(self._sealed(worker), ({mine.name}, set()))
        # A fresh chain of slot 1 does not unseal it; a continuation would.
        worker.launch(1, continuation=False)
        self.assertEqual(self._sealed(worker), ({mine.name}, set()))
        worker.retire(1)
        worker.launch(2, continuation=False)
        worker.retire(2)
        self.assertEqual(self._sealed(worker), ({mine.name, untouched.name}, set()))

    def test_a_continuation_of_a_toucher_keeps_its_finding_unsealed(self) -> None:
        worker = self._worker()
        worker.launch(1, continuation=False)
        mine = _artifact(self.results, "findings", "FIND-003-cut")
        raw = self._transcript("cut", [{"type": "command_execution",
                                         "command": "mkdir $R/findings/FIND-003-cut"}])
        worker.attribute(1, raw)
        worker.observe()
        worker.launch(1, continuation=True)    # turn-capped: same chain tick
        self.assertEqual(self._sealed(worker), (set(), set()))
        worker.retire(1)
        self.assertEqual(self._sealed(worker), ({mine.name}, set()))

    def test_a_finding_without_a_report_is_never_sealed(self) -> None:
        worker = self._worker()
        bare = self.results / "findings" / "FIND-004-bare"
        bare.mkdir()
        worker.observe()
        self.assertEqual(self._sealed(worker), (set(), set()))
        (bare / "report.md").write_text("# Issue\n", encoding="utf-8")
        worker.observe()
        self.assertEqual(self._sealed(worker), ({bare.name}, set()))

    def test_a_peer_that_touched_a_crash_bundle_delays_its_seal(self) -> None:
        worker = self._worker()
        worker.launch(2, continuation=False)
        bundle = _artifact(self.results, "crashes", "CRASH-001-1")
        raw = self._transcript("peer", [{"type": "command_execution",
                                          "command": "cp seed.bin $R/crashes/CRASH-001-1/testcase.bin"}])
        worker.observe()
        self.assertEqual(self._sealed(worker), (set(), {bundle.name}), "owner idle: sealed")
        worker.attribute(2, raw)
        worker.launch(2, continuation=True)
        self.assertEqual(self._sealed(worker), (set(), set()), "the peer's chain still touches it")
        worker.retire(2)
        self.assertEqual(self._sealed(worker), (set(), {bundle.name}))


class PoolIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="sealed-pool-")
        self.root = Path(self.temp.name)
        self.runtime = _runtime(self.root)
        self.results = self.runtime.results
        context = mock.Mock()
        context.role.return_value = "reproduce"
        self.state = audit_runner.BackendState(
            self.runtime, context, iteration=1, started_at=time.monotonic(),
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _result(self, agent: int, *, turn_capped: bool = False) -> audit_runner.AgentResult:
        return audit_runner.AgentResult(
            agent, "reproduce", 0, Path(), Path(), {}, "none", None, turn_capped,
            tool_calls=1, transcript_events=1,
        )

    def _run(self, turn_capped: bool) -> tuple[list[tuple[list[str], bool]], bool]:
        """Slot 1 files a finding and ends; both slots then run younger chains.

        A finding is sealed once every chain in flight started after it was
        filed. Slot 2's first session is older than the filing, so it must
        end first; its refill is younger, and while that refill runs the
        finding is sealed -- unless slot 1's refill is a continuation of the
        cut session that filed it.

        Returns every sweep's gated names with whether slot 1's refill had
        already ended, plus whether slot 2's refill saw the finding gated
        while it was itself still running.
        """
        gated: list[tuple[list[str], bool]] = []
        finding_gated = threading.Event()
        slot1_refill_started = threading.Event()
        refill_done = threading.Event()
        peer_done = threading.Event()
        slot1_sessions = 0
        peer_saw_gate: list[bool] = []
        lock = threading.Lock()

        def find_gate(_results, **kwargs):
            names = sorted(path.name for path in kwargs["only"])
            gated.append((names, refill_done.is_set()))
            if "FIND-001-slot1" in names:
                finding_gated.set()
            return {"accepted": len(names), "rejected": 0, "pending": 0}

        def agent(_runtime, _context, number, _iteration, cold, _limit):
            nonlocal slot1_sessions
            if number == 1:
                with lock:
                    slot1_sessions += 1
                    session = slot1_sessions
                if session == 1:
                    _artifact(self.results, "findings", "FIND-001-slot1")
                    return self._result(1, turn_capped=turn_capped)
                if session == 2:
                    # The refill: a continuation when the cold session was
                    # cut. It outlives slot 2's refill.
                    slot1_refill_started.set()
                    peer_done.wait(2)
                    refill_done.set()
                return self._result(1)
            if cold:
                # Older than the filing: must end before the seal can hold.
                slot1_refill_started.wait(2)
                return self._result(2)
            if not peer_saw_gate:
                peer_saw_gate.append(finding_gated.wait(0.6))
                peer_done.set()
            return self._result(2)

        no_expand = {"expanded": 0, "added": 0, "skipped": 0, "pending": 0}
        with mock.patch.object(audit_runner, "run_agent_guarded", side_effect=agent), \
             mock.patch.object(audit_runner, "should_skip_launch", return_value=False), \
             mock.patch.object(triage, "validate_find_gate", side_effect=find_gate), \
             mock.patch.object(
                 triage, "triage_crash_dirs",
                 return_value={"promoted": 0, "rejected": 0, "pending": 0, "demoted": 0},
             ), \
             mock.patch.object(audit_runner, "expand_new_crash_clusters", return_value=no_expand), \
             mock.patch.dict(os.environ, {"AUDIT_WALL_BUDGET_SECS": ""}, clear=False):
            audit_runner.run_agent_pool(self.state, [1, 2], True)
        return gated, bool(peer_saw_gate and peer_saw_gate[0])

    def test_a_clean_sessions_finding_is_gated_while_its_peers_run(self) -> None:
        gated, peer_saw_gate = self._run(turn_capped=False)
        self.assertTrue(peer_saw_gate, repr(gated))
        # The pool joined its worker before returning: every sweep it started
        # is on record, so post-iteration triage never overlaps one.
        self.assertIn((["FIND-001-slot1"], False), gated)

    def test_a_turn_capped_sessions_finding_waits_for_its_continuation(self) -> None:
        gated, peer_saw_gate = self._run(turn_capped=True)
        self.assertFalse(peer_saw_gate, repr(gated))
        # The continuation inherits the chain that filed the finding, so no
        # sweep gated it before that chain ended. Whether one gates it after
        # depends on a peer still running; with none left the barrier does.
        early = [names for names, refill_ended in gated if not refill_ended]
        self.assertNotIn(["FIND-001-slot1"], early, repr(gated))


if __name__ == "__main__":
    unittest.main()
