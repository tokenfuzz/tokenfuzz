"""RESULT_GATES_BACKGROUND: the find gate deferred to the next cohort.

Crash triage stays serial in front; the find gate and cluster expansion run
beside the next cohort and are joined before the next iteration's crash triage.
These assert the ordering and the one-iteration lag, not the gate internals.
"""
from __future__ import annotations

import os
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "lib"))

import audit_runner  # noqa: E402


class BackgroundGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="bg-gate-")
        self.root = Path(self.temporary.name)
        self.results = self.root / "results"
        (self.results / "state").mkdir(parents=True)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.runtime = SimpleNamespace(
            results=self.results, logs=self.logs, num_agents=2,
            index=self.logs / "index.log",
            target_root=self.root / "target", target_slug="sampleproj",
            config=SimpleNamespace(attacker_controls=["bytes"],
                                   sanitizers_explicitly_disabled=False),
        )
        self.state = audit_runner.BackendState(self.runtime, mock.Mock(), started_at=0.0)
        self.events: list[str] = []
        self.lock = threading.Lock()
        self.gate_hold = 0.0
        self._install_base_patches()

    def tearDown(self) -> None:
        audit_runner.drain_pending_gate(self.state)
        self.temporary.cleanup()

    def _note(self, name: str) -> None:
        with self.lock:
            self.events.append(name)

    def _install_base_patches(self) -> None:
        # Alive for the whole test (addCleanup), so a gate future that runs on
        # the executor thread after the barrier returns still sees the fakes.
        def crash(*_a, **_k):
            self._note("crash_triage")
            return {"promoted": 0, "rejected": 0, "pending": 0, "demoted": 0}

        def find_gate(*_a, **_k):
            self._note("find_gate:start")
            if self.gate_hold:
                time.sleep(self.gate_hold)
            self._note("find_gate:end")
            return {"accepted": 1, "rejected": 0, "pending": 0}

        patches = (
            mock.patch.object(audit_runner.triage, "triage_crash_dirs", side_effect=crash),
            mock.patch.object(audit_runner.triage, "validate_find_gate", side_effect=find_gate),
            mock.patch.object(audit_runner, "expand_new_crash_clusters",
                              side_effect=lambda *_a, **_k: self._note("cluster_expand") or {"added": 0}),
            mock.patch.object(audit_runner, "maintain_local_indexes", lambda *_a, **_k: self._note("indexes")),
            mock.patch.object(audit_runner, "maintain_aggregate_indexes", lambda *_a, **_k: None),
            mock.patch.object(audit_runner.triage, "record_artifact_events", lambda *_a, **_k: 0),
            mock.patch.object(audit_runner, "enforce_orphan_testcases", lambda *_a, **_k: 0),
            mock.patch.object(audit_runner, "promote_corpus", lambda *_a, **_k: 0),
        )
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)

    def _run_background_iteration(self, gate_hold: float = 0.0) -> None:
        self.gate_hold = gate_hold
        with mock.patch.dict(os.environ, {"RESULT_GATES_BACKGROUND": "1"}, clear=False):
            audit_runner._post_iteration_background(self.state)

    def test_gate_is_deferred_not_run_at_the_barrier(self) -> None:
        self.state.iteration = 1
        self._run_background_iteration(gate_hold=0.2)
        # The barrier finished before the gate did: crash triage and the index
        # render happened while the gate had not yet started or was still going.
        self.assertIn("crash_triage", self.events)
        self.assertIn("indexes", self.events)
        self.assertLess(self.events.index("crash_triage"), self.events.index("indexes"))
        self.assertIsNotNone(self.state.pending_gate)
        audit_runner.drain_pending_gate(self.state)
        self.assertIn("find_gate:end", self.events)
        self.assertIsNone(self.state.pending_gate)

    def test_next_barrier_joins_the_previous_gate_before_its_crash_triage(self) -> None:
        self.state.iteration = 1
        self._run_background_iteration(gate_hold=0.3)
        # Iteration 2's barrier must join iteration 1's gate before it runs its
        # own crash triage, so a gate never overlaps another gate or a demotion.
        self.state.iteration = 2
        self.events.clear()
        self._run_background_iteration(gate_hold=0.0)
        self.assertIn("find_gate:end", self.events)
        self.assertIn("crash_triage", self.events)
        self.assertLess(
            self.events.index("find_gate:end"), self.events.index("crash_triage"),
            "the previous gate must be joined before this iteration's crash triage",
        )
        audit_runner.drain_pending_gate(self.state)

    def test_two_gate_passes_never_run_at_once(self) -> None:
        # A gate still running when the next iteration starts must be joined,
        # never joined by a second concurrently launched pass. Track the live
        # count of gate passes and assert it never exceeds one.
        self.state.iteration = 1
        active = {"now": 0, "max": 0}
        active_lock = threading.Lock()
        original = audit_runner._result_gate_pass

        def guarded(*args, **kwargs):
            with active_lock:
                active["now"] += 1
                active["max"] = max(active["max"], active["now"])
            try:
                time.sleep(0.15)
                return original(*args, **kwargs)
            finally:
                with active_lock:
                    active["now"] -= 1

        with mock.patch.object(audit_runner, "_result_gate_pass", side_effect=guarded):
            self._run_background_iteration(gate_hold=0.0)
            self.state.iteration = 2
            self._run_background_iteration(gate_hold=0.0)
            audit_runner.drain_pending_gate(self.state)
        self.assertEqual(active["max"], 1, "a second gate pass ran while one was live")


    def test_admit_lags_one_iteration_but_is_never_lost(self) -> None:
        # A finding admitted by iteration 1's deferred gate is not run when
        # iteration 1's barrier renders its indexes, but is settled by the time
        # iteration 2's barrier joins it — the accepted one-iteration lag.
        self.state.iteration = 1
        self._run_background_iteration(gate_hold=0.3)
        # Iteration 1's index render ran without the gate having ended: the
        # finding it will admit is not yet visible to this iteration's barrier.
        self.assertIn("indexes", self.events)
        self.assertNotIn("find_gate:end", self.events[: self.events.index("indexes") + 1])
        self.state.iteration = 2
        self._run_background_iteration(gate_hold=0.0)
        # Iteration 1's gate has completed by iteration 2's barrier (joined),
        # so its admit lands one iteration late — never lost.
        self.assertGreaterEqual(self.events.count("find_gate:end"), 1)
        # The final drain settles iteration 2's gate too; each gate runs once.
        audit_runner.drain_pending_gate(self.state)
        self.assertEqual(self.events.count("find_gate:end"), 2)
        self.assertIsNone(self.state.pending_gate)

    def test_deadline_reached_runs_the_gate_inline(self) -> None:
        # With no budget to launch a gate that could not finish, it runs inline
        # so the wall that pays for it is this iteration's, and nothing defers.
        self.state.iteration = 1
        with mock.patch.dict(os.environ, {"RESULT_GATES_BACKGROUND": "1"}, clear=False), \
                mock.patch.object(audit_runner, "_productive_wall_deadline", return_value=0.0), \
                mock.patch.object(audit_runner.time, "monotonic", return_value=100.0):
            audit_runner._post_iteration_background(self.state)
        self.assertIn("find_gate:end", self.events)
        self.assertIsNone(self.state.pending_gate)

    def test_deferred_gate_compute_counts_as_total_not_blocked(self) -> None:
        # The gate that overlapped the cohort must show up in housekeeping
        # total (so Review s/artifact is comparable across the flag) while only
        # the barrier wait counts as blocked.
        import telemetry
        self.state.iteration = 1
        self._run_background_iteration(gate_hold=0.25)  # gate still running at return
        self.state.iteration = 2
        self._run_background_iteration(gate_hold=0.0)   # joins iter 1's gate
        audit_runner.drain_pending_gate(self.state)
        house = telemetry.housekeeping(self.results)
        gate_total = house["phases"].get("result_gates", 0.0)
        self.assertGreater(gate_total, 0.2, "the deferred gate's compute is in total")
        self.assertLess(
            house["blocked_seconds"], gate_total + 0.2,
            "blocked time must not include the whole overlapped gate compute",
        )

    def test_default_mode_leaves_post_iteration_serial(self) -> None:
        # Flag off: _run_post_iteration calls the serial post_iteration, and no
        # gate is ever deferred.
        self.state.iteration = 1
        with mock.patch.object(audit_runner, "post_iteration") as post, \
                mock.patch.object(audit_runner, "_post_iteration_background") as background:
            with mock.patch.dict(os.environ, {"RESULT_GATES_BACKGROUND": "0"}, clear=False):
                audit_runner._run_post_iteration(self.state)
        post.assert_called_once()
        background.assert_not_called()
        self.assertIsNone(self.state.pending_gate)


if __name__ == "__main__":
    unittest.main()
