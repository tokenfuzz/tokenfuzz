#!/usr/bin/env python3
"""The continuous scheduler: slots refill to the wall, steering on a timer.

The cohort model held fast slots at a barrier for the slowest peer. These
cover what replaces it: a finished slot relaunches at once, a provider halt
stops launches and drains, the generation ceiling and the wall stop refills,
the steward tick fires without stopping anyone, and the only full barrier is
the final pass after the last slot drains. Sizing tests cover the
machine-aware default and its container limits.
"""

from __future__ import annotations

import contextlib
import io
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


def _snapshot() -> audit_runner.ProgressSnapshot:
    return audit_runner.ProgressSnapshot(0, 0, 0, 0, 0, 0, {})


class _Harness:
    """A fake runtime and the patch set that isolates the scheduler loop."""

    def __init__(self, root: Path, num_agents: int = 2) -> None:
        raw = root / "raw"
        raw.mkdir()
        self.runtime = SimpleNamespace(
            num_agents=num_agents, index=root / "index.log", raw=raw,
        )
        context = mock.Mock()
        context.role.return_value = "reproduce"
        self.state = audit_runner.BackendState(
            self.runtime, context, iteration=0, started_at=time.monotonic(),
        )
        self.calls: list[tuple[int, bool, int]] = []
        self.lock = threading.Lock()
        self.steers = 0
        self.barriers = 0

    def result(self, agent: int, *, rc: int = 0, issue: str = "none", turn_capped: bool = False):
        return audit_runner.AgentResult(
            agent, "reproduce", rc, Path(), Path(), {}, issue, None, turn_capped,
            tool_calls=1, transcript_events=1,
        )

    @contextlib.contextmanager
    def patched(self, agent, *, skip_launch=False, steer_status="continue"):
        def _steer(state, before, filed, **_kwargs):
            self.steers += 1
            return steer_status, before, filed

        def _barrier(_state):
            self.barriers += 1

        def _agent(_runtime, _context, number, _iteration, cold, limit):
            with self.lock:
                self.calls.append((number, cold, limit))
            return agent(number, cold)

        inert = {name: mock.DEFAULT for name in (
            "_activate_runtime", "refresh_fuzz_leads", "reset_sanitizer_run_counters",
            "reset_llm_decision_counters", "refresh_work_cards",
            "expand_work_cards_if_exhausted", "initialize_agent_strategies",
            "_log_foreign_active_work", "assign_build_configs",
        )}
        with mock.patch.multiple(audit_runner, **inert), \
             mock.patch.object(audit_runner, "release_stale_card_claims", return_value=0), \
             mock.patch.object(audit_runner, "_cold", return_value=True), \
             mock.patch.object(audit_runner, "progress", return_value=_snapshot()), \
             mock.patch.object(audit_runner, "filed_artifact_count", return_value=0), \
             mock.patch.object(audit_runner, "_steward_steer", side_effect=_steer), \
             mock.patch.object(audit_runner, "_run_post_iteration", side_effect=_barrier), \
             mock.patch.object(
                 audit_runner, "_assess_generation",
                 side_effect=lambda state, before, filed, results: (
                     next((
                         {"backend_rejected": "rejected", "capacity_limited": "capacity",
                          "transient": "transient"}[r.provider_issue]
                         for r in results if r.provider_issue in audit_runner._PROVIDER_HALT_ISSUES
                     ), "dry"), results,
                 ),
             ), \
             mock.patch.object(audit_runner, "run_agent_guarded", side_effect=_agent), \
             mock.patch.object(
                 audit_runner, "should_skip_launch",
                 side_effect=(
                     skip_launch if callable(skip_launch)
                     else lambda *_a, **_k: skip_launch
                 ),
             ), \
             mock.patch.dict(os.environ, {"AUDIT_WALL_BUDGET_SECS": "", "STEWARD_INTERVAL_SECS": "300"}, clear=False):
            yield


class ContinuousSchedulerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="continuous-")
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_a_fast_slot_never_waits_for_its_slow_peer(self) -> None:
        h = _Harness(self.root)
        slow_done = threading.Event()

        def agent(number, cold):
            if number == 2:
                # The slow peer: holds until slot 1 has run several sessions.
                deadline = time.monotonic() + 2
                while time.monotonic() < deadline:
                    with h.lock:
                        if sum(1 for n, _c, _l in h.calls if n == 1) >= 3:
                            break
                    time.sleep(0.005)
                slow_done.set()
                return h.result(2)
            if slow_done.is_set():
                # Once the peer is gone the queue is dry for this test.
                with mock.patch.object(audit_runner, "should_skip_launch", return_value=True):
                    return h.result(1)
            return h.result(1)

        # After the peer ends, slot 1 must stop: emulate a dry queue by
        # making the skip check true once the slow peer has finished.
        def skip(_runtime, _context, agent_number, **_k):
            return slow_done.is_set()

        with h.patched(agent), mock.patch.object(audit_runner, "should_skip_launch", side_effect=skip):
            status, results = audit_runner.run_continuous(h.state)
        slot1 = [c for c in h.calls if c[0] == 1]
        # One launch plus the two clean relaunches the between-tick cap
        # allows, all while the peer was still running.
        self.assertGreaterEqual(len(slot1), 3, repr(h.calls))
        self.assertTrue(slot1[0][1] and not any(c[1] for c in slot1[1:]), "only the first launch is cold")
        self.assertEqual(h.barriers, 1, "exactly one full barrier, after the drain")
        self.assertIn(status, ("dry", "stalled", "budget"))

    def test_a_provider_halt_stops_launches_drains_and_reports(self) -> None:
        h = _Harness(self.root)
        peer_running = threading.Event()

        def agent(number, cold):
            if number == 2:
                peer_running.set()
                time.sleep(0.2)
                return h.result(2)
            peer_running.wait(1)
            return h.result(1, rc=1, issue="capacity_limited")

        with h.patched(agent):
            status, _results = audit_runner.run_continuous(h.state)
        self.assertEqual(status, "capacity")
        self.assertEqual(sorted(c[0] for c in h.calls), [1, 2], "no relaunch after the halt")
        self.assertEqual(h.barriers, 1)
        self.assertIn("reported capacity_limited", h.runtime.index.read_text())

    def test_the_generation_ceiling_stops_refills_but_not_the_first_launch(self) -> None:
        h = _Harness(self.root)
        h.state.max_generations = 1
        with h.patched(lambda number, cold: h.result(number)):
            status, _ = audit_runner.run_continuous(h.state)
        self.assertEqual(sorted(c[0] for c in h.calls), [1, 2])
        self.assertEqual(h.barriers, 1)

    def test_the_steward_ticks_while_slots_run_and_can_stall_the_run(self) -> None:
        h = _Harness(self.root)
        ticks = 0

        def agent(number, cold):
            time.sleep(0.15)
            return h.result(number, turn_capped=True)

        with h.patched(agent, steer_status="stalled"), \
             mock.patch.dict(os.environ, {"STEWARD_INTERVAL_SECS": "1"}, clear=False):
            status, _ = audit_runner.run_continuous(h.state)
        self.assertEqual(status, "stalled")
        self.assertGreaterEqual(h.steers, 1)
        self.assertEqual(h.barriers, 1)

    def test_a_deadline_outcome_idles_the_slot(self) -> None:
        h = _Harness(self.root, num_agents=1)
        with h.patched(lambda number, cold: h.result(number, rc=124)):
            audit_runner.run_continuous(h.state)
        self.assertEqual(len(h.calls), 1)
        self.assertIn("idle after deadline outcome", h.runtime.index.read_text())


    def test_the_ceiling_also_stops_tick_relaunches(self) -> None:
        h = _Harness(self.root)
        h.state.max_generations = 1

        def agent(number, cold):
            if number == 2:
                time.sleep(1.4)   # outlives one steward interval
            return h.result(number)

        with h.patched(agent), \
             mock.patch.dict(os.environ, {"STEWARD_INTERVAL_SECS": "1"}, clear=False):
            audit_runner.run_continuous(h.state)
        self.assertEqual(sorted(c[0] for c in h.calls), [1, 2], repr(h.calls))
        self.assertEqual(h.steers, 0, "no generation opens past the ceiling")


    def test_clean_relaunches_are_bounded_between_ticks(self) -> None:
        # A sticky work source answers "yes" to every relaunch; the cap
        # parks the slot until the steward has re-ranked.
        h = _Harness(self.root, num_agents=1)
        with h.patched(lambda number, cold: h.result(number)):
            audit_runner.run_continuous(h.state)
        self.assertEqual(len(h.calls), 3, repr(h.calls))
        self.assertIn("idle until the next steward tick", h.runtime.index.read_text())

    def test_a_sweep_outliving_the_last_session_is_charged_as_housekeeping(self) -> None:
        h = _Harness(self.root)
        results = self.root / "results"
        (results / "findings" / "FIND-001-old").mkdir(parents=True)
        (results / "findings" / "FIND-001-old" / "report.md").write_text("# Issue\n", encoding="utf-8")
        (results / "crashes").mkdir()
        (self.root / "logs").mkdir()
        h.runtime.results = results
        h.runtime.logs = self.root / "logs"
        h.runtime.target_root = self.root
        h.runtime.target_slug = "sampleproj"
        h.runtime.config = SimpleNamespace(attacker_controls=["bytes"], sanitizers_explicitly_disabled=False)
        peer_started = threading.Event()

        def agent(number, cold):
            if number == 2:
                peer_started.set()
                time.sleep(0.1)
                return h.result(2)
            peer_started.wait(1)
            return h.result(1)

        def slow_gate(*_a, **_k):
            time.sleep(0.4)
            return {"accepted": 1, "rejected": 0, "pending": 0}

        no_expand = {"expanded": 0, "added": 0, "skipped": 0, "pending": 0}
        def only_initial(*_a, **kwargs):
            return not kwargs.get("primary_always_launches", True)

        with h.patched(agent, skip_launch=only_initial), \
             mock.patch.object(audit_runner.triage, "validate_find_gate", side_effect=slow_gate), \
             mock.patch.object(audit_runner.triage, "triage_crash_dirs", return_value={"promoted": 0, "rejected": 0, "pending": 0, "demoted": 0}), \
             mock.patch.object(audit_runner, "expand_new_crash_clusters", return_value=no_expand):
            audit_runner.run_continuous(h.state)
        self.assertGreater(h.state.housekeeping_seconds, 0.0)
        rows = [json.loads(l) for l in (results / "state" / "events.jsonl").read_text().splitlines()]
        tail = [r for r in rows if r.get("phase") == "gate_drain"]
        self.assertEqual(len(tail), 1, repr(rows))
        self.assertTrue(tail[0]["blocked"])
        self.assertAlmostEqual(tail[0]["seconds"], h.state.housekeeping_seconds, places=2)

    def test_no_refill_workers_keeps_the_cohort_driver(self) -> None:
        runtime = SimpleNamespace(refill_workers=False, config=SimpleNamespace(attacker_controls=[]))
        state = audit_runner.BackendState(runtime, mock.Mock(), iteration=0)
        args = SimpleNamespace(allow_concurrent=False, max_iterations=1)
        with mock.patch.object(audit_runner, "instance_lock", return_value=contextlib.nullcontext()), \
             mock.patch.object(audit_runner, "_fixed_lane_unavailable", return_value=""), \
             mock.patch.object(audit_runner.runner_preflight, "validate"), \
             mock.patch.object(audit_runner, "validate_model"), \
             mock.patch.object(audit_runner, "preflight_build"), \
             mock.patch.object(audit_runner, "initialize_backend", return_value=state), \
             mock.patch.object(audit_runner, "run_iteration", return_value=("stalled", [])) as cohort, \
             mock.patch.object(audit_runner, "run_continuous", return_value=("stalled", [])) as continuous:
            audit_runner.run_backend(runtime, args, "")
        cohort.assert_called_once()
        continuous.assert_not_called()


class StewardTickTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="steward-")
        root = Path(self.temp.name)
        self.runtime = SimpleNamespace(num_agents=3, index=root / "index.log", raw=root)
        self.state = audit_runner.BackendState(self.runtime, mock.Mock(), iteration=4)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _tick(self, *, ended: set[int], live: set[int], status: str = "dry"):
        before = _snapshot()
        self.mocks = {}
        with mock.patch.object(audit_runner, "_assess_generation", return_value=(status, [])) as assess, \
             mock.patch.object(audit_runner, "refresh_work_cards") as refresh, \
             mock.patch.object(audit_runner, "release_stale_card_claims", return_value=0) as release, \
             mock.patch.object(audit_runner, "expand_work_cards_if_exhausted"), \
             mock.patch.object(audit_runner, "initialize_agent_strategies"), \
             mock.patch.object(audit_runner, "maintain_local_indexes") as indexes, \
             mock.patch.object(audit_runner, "refresh_fuzz_leads") as leads, \
             mock.patch.object(audit_runner, "reset_sanitizer_run_counters") as sanitizer, \
             mock.patch.object(audit_runner, "reset_llm_decision_counters") as decisions, \
             mock.patch.object(audit_runner, "assign_build_configs") as assign, \
             mock.patch.object(audit_runner, "progress", return_value=before), \
             mock.patch.object(audit_runner, "filed_artifact_count", return_value=7):
            result = audit_runner._steward_steer(
                self.state, before, 3, live_agents=live, ended_agents=ended,
            )
        self.mocks = {"indexes": indexes, "leads": leads, "sanitizer": sanitizer, "decisions": decisions}
        return result, assess, refresh, release, assign

    def test_a_tick_without_an_ended_session_only_refreshes_the_queue(self) -> None:
        (status, _before, filed), assess, refresh, release, assign = self._tick(ended=set(), live={1, 2})
        self.assertEqual((status, filed), ("continue", 3))
        self.assertEqual(self.state.iteration, 4, "no generation is scored or opened")
        assess.assert_not_called()
        refresh.assert_called_once()
        assign.assert_not_called()
        self.mocks["sanitizer"].assert_not_called()
        self.assertEqual(release.call_args.kwargs["keep_agents"], {1, 2})

    def test_a_scored_tick_scores_only_ended_slots_and_renews_the_budgets(self) -> None:
        (status, _before, filed), assess, _refresh, release, assign = self._tick(ended={1, 2}, live={3})
        self.assertEqual((status, filed, self.state.iteration), ("continue", 7, 5))
        assess.assert_called_once()
        self.assertEqual(assess.call_args.kwargs["scored_agents"], {1, 2})
        self.assertEqual(release.call_args.kwargs["keep_agents"], {3})
        self.assertEqual(assign.call_args.kwargs["skip_agents"], {3})
        for name in ("leads", "sanitizer", "decisions"):
            self.mocks[name].assert_called_once()
        self.assertIn("Iteration 5 starting", self.runtime.index.read_text())

    def test_the_live_steward_never_rewrites_reports(self) -> None:
        # cluster-findings, enrichment and rendering rewrite report.md; beside
        # a session still writing one that loses its narrative. Indexes are
        # the final barrier's job.
        for ended in (set(), {1}):
            self._tick(ended=ended, live={2})
            self.mocks["indexes"].assert_not_called()

    def test_a_stalled_tick_stops_before_touching_the_queue(self) -> None:
        (status, _b, _f), _assess, refresh, _release, _assign = self._tick(ended={1}, live=set(), status="stalled")
        self.assertEqual(status, "stalled")
        refresh.assert_not_called()

    def test_scoring_passes_the_ended_slots_to_rotation(self) -> None:
        before = _snapshot()
        with mock.patch.object(audit_runner, "progress", return_value=before), \
             mock.patch.object(audit_runner, "agent_progress", return_value=audit_runner.AgentProgress(0, 0, frozenset())), \
             mock.patch.object(audit_runner, "newly_introduced_roots", return_value=set()), \
             mock.patch.object(audit_runner, "filed_artifact_count", return_value=0), \
             mock.patch.object(audit_runner, "update_subsystem_dry_streaks") as subsystems, \
             mock.patch.object(audit_runner, "update_strategy_rotation") as rotation:
            audit_runner._assess_generation(self.state, before, 0, [], scored_agents={2})
        self.assertEqual(rotation.call_args.kwargs["agents"], {2})
        self.assertEqual(subsystems.call_args.kwargs["agents"], {2})


class PoolSizingTests(unittest.TestCase):
    def test_default_pool_is_sized_by_cpu_memory_and_ceiling(self) -> None:
        with mock.patch.object(audit_runner, "_machine_cpus", return_value=16), \
             mock.patch.object(audit_runner, "_machine_memory_gb", return_value=64.0), \
             mock.patch.dict(os.environ, {"AGENT_POOL_MAX": "", "AGENT_MEMORY_GB": ""}, clear=False):
            os.environ.pop("AGENT_POOL_MAX"); os.environ.pop("AGENT_MEMORY_GB")
            self.assertEqual(audit_runner._auto_shell_agents(), 8)
        with mock.patch.object(audit_runner, "_machine_cpus", return_value=4), \
             mock.patch.object(audit_runner, "_machine_memory_gb", return_value=8.0):
            self.assertEqual(audit_runner._auto_shell_agents(), 2, "8 GB at 4 GB per agent")
        with mock.patch.object(audit_runner, "_machine_cpus", return_value=2), \
             mock.patch.object(audit_runner, "_machine_memory_gb", return_value=0.0):
            self.assertEqual(audit_runner._auto_shell_agents(), 2, "unknown RAM defers to CPU")
        with mock.patch.object(audit_runner, "_machine_cpus", return_value=32), \
             mock.patch.object(audit_runner, "_machine_memory_gb", return_value=256.0), \
             mock.patch.dict(os.environ, {"AGENT_POOL_MAX": "12"}, clear=False):
            self.assertEqual(audit_runner._auto_shell_agents(), 12)

    def test_explicit_counts_still_win(self) -> None:
        config = SimpleNamespace(is_browser="0")
        with mock.patch.dict(os.environ, {"NUM_AGENTS": "5"}, clear=False):
            self.assertEqual(audit_runner._agent_counts(config, 0), (5, 0, 5))
        with mock.patch.dict(os.environ, {"SHELL_AGENTS": "3"}, clear=False):
            os.environ.pop("NUM_AGENTS", None)
            self.assertEqual(audit_runner._agent_counts(config, 0), (3, 0, 3))
        self.assertEqual(audit_runner._agent_counts(config, 1), (1, 0, 1), "a one-iteration smoke stays single")

    def test_cgroup_limits_bound_the_host_figures(self) -> None:
        def fake_open(path, *args, **kwargs):
            data = {
                "/sys/fs/cgroup/cpu.max": "200000 100000\n",
                "/sys/fs/cgroup/memory.max": str(6 * 1024 ** 3) + "\n",
            }
            if path in data:
                return io.StringIO(data[path])
            raise OSError(path)

        with mock.patch("builtins.open", side_effect=fake_open), \
             mock.patch.object(os, "cpu_count", return_value=16):
            self.assertEqual(audit_runner._cgroup_cpu_limit(), 2.0)
            self.assertEqual(audit_runner._machine_cpus(), 2)
            self.assertEqual(audit_runner._cgroup_memory_limit_bytes(), 6 * 1024 ** 3)
            self.assertLessEqual(audit_runner._machine_memory_gb(), 6.0)

        def unlimited(path, *args, **kwargs):
            if path == "/sys/fs/cgroup/cpu.max":
                return io.StringIO("max 100000\n")
            if path == "/sys/fs/cgroup/memory.max":
                return io.StringIO("max\n")
            raise OSError(path)

        with mock.patch("builtins.open", side_effect=unlimited):
            self.assertEqual(audit_runner._cgroup_cpu_limit(), 0.0)
            self.assertEqual(audit_runner._cgroup_memory_limit_bytes(), 0)


if __name__ == "__main__":
    unittest.main()
