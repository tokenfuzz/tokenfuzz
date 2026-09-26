#!/usr/bin/env python3
"""Audit wall-clock and housekeeping telemetry regressions."""

from __future__ import annotations

import contextlib
import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner
import benchmark
import benchmark_runner


class AuditClockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="audit-clocks-")
        self.root = Path(self.temporary.name)
        self.logs = self.root / "logs"
        self.logs.mkdir()
        self.runtime = SimpleNamespace(
            logs=self.logs,
            index=self.logs / "index.log",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_unavailable_fixed_lane_records_a_structured_outcome(self) -> None:
        results = self.root / "results"
        runtime = SimpleNamespace(
            results=results, index=self.runtime.index, fixed_strategy="S4",
        )
        args = SimpleNamespace(allow_concurrent=False)
        with (mock.patch.object(audit_runner, "instance_lock",
                                return_value=contextlib.nullcontext()),
              mock.patch.object(audit_runner, "_fixed_lane_unavailable",
                                return_value="native sanitizer library unavailable"),
              mock.patch.object(audit_runner, "refresh_work_cards")):
            self.assertEqual(audit_runner.run_backend(runtime, args, ""), 0)
        events = audit_runner.workqueue.read_jsonl(
            results / "state" / "events.jsonl")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "lane_stop")
        self.assertEqual(events[0]["outcome"], "unavailable")
        self.assertEqual(events[0]["strategy"], "S4")
        self.assertIn("native sanitizer library", events[0]["reason"])

    def test_productive_budget_includes_housekeeping(self) -> None:
        state = audit_runner.BackendState(
            self.runtime, mock.Mock(), started_at=100.0,
            paused_seconds=10, housekeeping_seconds=20,
        )
        with mock.patch.dict(
            os.environ, {"AUDIT_WALL_BUDGET_SECS": "50"}, clear=False,
        ), mock.patch.object(audit_runner.time, "monotonic", return_value=159.0):
            self.assertFalse(audit_runner._productive_wall_exhausted(state))
            self.assertEqual(audit_runner._productive_wall_remaining(state), 1)

        with mock.patch.dict(
            os.environ, {"AUDIT_WALL_BUDGET_SECS": "50"}, clear=False,
        ), mock.patch.object(audit_runner.time, "monotonic", return_value=161.0):
            self.assertTrue(audit_runner._productive_wall_exhausted(state))

    def test_housekeeping_wrapper_records_time_without_changing_work(self) -> None:
        state = audit_runner.BackendState(
            self.runtime, mock.Mock(), started_at=100.0,
        )
        with mock.patch.dict(
            os.environ, {"AUDIT_WALL_BUDGET_SECS": "50"}, clear=False,
        ), mock.patch.object(audit_runner, "post_iteration") as post, \
                mock.patch.object(
                    audit_runner.time, "monotonic", side_effect=[120.0, 132.5],
                ):
            audit_runner._run_post_iteration(state)

        # The iteration rides along so housekeeping_phase rows can say which
        # barrier they cost; state.iteration starts at 0 before the first cohort.
        post.assert_called_once_with(self.runtime, deadline=150.0, iteration=0)
        self.assertEqual(state.housekeeping_seconds, 12.5)
        self.assertEqual(float((self.logs / ".housekeeping_secs").read_text()), 12.5)

    def test_post_iteration_records_every_completed_phase(self) -> None:
        runtime = SimpleNamespace(
            results=self.root / "results", target_root=self.root / "target",
            target_slug="sampleproj", num_agents=2, index=self.runtime.index,
            config=SimpleNamespace(
                attacker_controls=["bytes"],
                sanitizers_explicitly_disabled=False,
            ),
        )
        crash_counts = {"promoted": 0, "rejected": 0, "pending": 0, "demoted": 0}
        finding_counts = {"accepted": 0, "rejected": 0, "pending": 0}
        with mock.patch.object(
            audit_runner.triage, "triage_crash_dirs", return_value=crash_counts,
        ) as crash_gate, mock.patch.object(
            audit_runner.triage, "validate_find_gate", return_value=finding_counts,
        ) as finding_gate, mock.patch.object(
            audit_runner, "expand_new_crash_clusters", return_value={"added": 0},
        ), mock.patch.object(audit_runner, "maintain_local_indexes"), \
                mock.patch.object(audit_runner, "maintain_aggregate_indexes"), \
                mock.patch.object(audit_runner, "enforce_orphan_testcases", return_value=0), \
                mock.patch.object(audit_runner, "promote_corpus", return_value=0), \
                mock.patch.object(audit_runner, "index_log") as index_log:
            audit_runner.post_iteration(runtime)

        self.assertIs(crash_gate.call_args.kwargs["target_root_is_product"], True)
        self.assertIs(finding_gate.call_args.kwargs["target_root_is_product"], True)

        # The barrier only hands crashes to the expansion lane, so the span
        # names what that handover did rather than timing a wait it never pays.
        phase_line = index_log.call_args_list[-1].args[1]
        self.assertRegex(
            phase_line,
            r"^Housekeeping phases: crash_triage=[\d.]+s "
            r"result_gates=[\d.]+s\(finding_gate=[\d.]+s cluster_expand=(idle|started|in-flight)\) "
            r"artifact_events=[\d.]+s indexes=[\d.]+s "
            r"orphan_enforce=[\d.]+s corpus_promote=[\d.]+s$",
        )

    def test_crash_discovery_is_stamped_when_the_wall_is_already_spent(self) -> None:
        # A wall-cut iteration defers the index phase, but crash discovery must
        # still land on the timeline the way finding discovery does — otherwise
        # a crash filed on the last iteration has no first-seen stamp.
        results = self.root / "wallcut"
        (results / "state").mkdir(parents=True)
        crash = results / "crashes" / "CRASH-9f9f9f-1"
        crash.mkdir(parents=True)
        (crash / "sanitizer.txt").write_text(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "    #0 0x1 in app_parse sample.c:91\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow sample.c:91 in app_parse\n",
            encoding="utf-8",
        )
        runtime = SimpleNamespace(
            results=results, target_root=self.root / "target",
            target_slug="sampleproj", num_agents=1, index=self.runtime.index,
            config=SimpleNamespace(
                attacker_controls=["bytes"],
                sanitizers_explicitly_disabled=False,
            ),
        )
        with mock.patch.object(
            audit_runner.triage, "triage_crash_dirs",
            return_value={"promoted": 0, "rejected": 0, "pending": 0, "demoted": 0},
        ), mock.patch.object(
            audit_runner.triage, "validate_find_gate",
            return_value={"accepted": 0, "rejected": 0, "pending": 0},
        ), mock.patch.object(
            audit_runner, "expand_new_crash_clusters", return_value={"added": 0},
        ), mock.patch.object(
            audit_runner, "maintain_local_indexes",
        ) as indexes, mock.patch.object(
            audit_runner, "maintain_aggregate_indexes",
        ), mock.patch.object(audit_runner, "index_log"):
            audit_runner.post_iteration(
                runtime, deadline=audit_runner.time.monotonic() - 1,
            )

        indexes.assert_not_called()
        rows = [
            json.loads(line) for line in
            (results / "state" / "events.jsonl").read_text(encoding="utf-8").splitlines()
        ]
        self.assertTrue(
            any(r["type"] == "crash_created" and r["id"] == "CRASH-9f9f9f-1" for r in rows),
            "a deferred index phase must not drop the crash's first-seen stamp",
        )

    def test_the_barrier_never_waits_for_an_expansion_in_flight(self) -> None:
        """A 604s expansion decision held every slot of a cohort run idle at
        the barrier. The barrier hands crashes to the lane, overlaps the find
        gate with it, and returns; only a drain waits, billed as blocked."""
        results = self.root / "results"
        crash = results / "crashes" / "CRASH-001-1"
        crash.mkdir(parents=True)
        (results / "state").mkdir()
        runtime = SimpleNamespace(
            results=results, target_root=self.root / "target",
            target_slug="sampleproj", num_agents=2, index=self.runtime.index,
            logs=self.logs,
            config=SimpleNamespace(
                attacker_controls=["bytes"],
                sanitizers_explicitly_disabled=False,
            ),
        )
        expand_running = threading.Event()
        release = threading.Event()
        batches: list[list[Path]] = []

        def _gate(*_args, **_kwargs):
            # The gate still overlaps the expansion it handed over.
            self.assertTrue(expand_running.wait(5))
            return {"accepted": 0, "rejected": 0, "pending": 0}

        def _expand(_runtime, **kwargs):
            batches.append(list(kwargs["only"]))
            expand_running.set()
            release.wait(5)
            return {"expanded": 1, "added": 2, "skipped": 0, "pending": 0}

        state = audit_runner.BackendState(runtime, mock.Mock(), iteration=3)
        with mock.patch.object(
            audit_runner.triage, "triage_crash_dirs",
            return_value={"promoted": 0, "rejected": 0, "pending": 0, "demoted": 0},
        ), mock.patch.object(
            audit_runner.triage, "validate_find_gate", side_effect=_gate,
        ), mock.patch.object(
            audit_runner, "expand_new_crash_clusters", side_effect=_expand,
        ), mock.patch.object(audit_runner, "maintain_local_indexes"), \
                mock.patch.object(audit_runner, "maintain_aggregate_indexes"), \
                mock.patch.object(audit_runner, "enforce_orphan_testcases", return_value=0), \
                mock.patch.object(audit_runner, "promote_corpus", return_value=0):
            try:
                audit_runner.post_iteration(runtime, iteration=3)
                lane = runtime.cluster_lane
                self.assertTrue(lane.busy(), "the barrier returned mid-expansion")
                # The next barrier neither waits nor starts a second decision
                # over the same seed.
                audit_runner.post_iteration(runtime, iteration=4)
                self.assertEqual(batches, [[crash]])
                self.assertIn("cluster_expand=in-flight", self.runtime.index.read_text())
                threading.Timer(0.2, release.set).start()
                self.assertTrue(audit_runner._drain_cluster_lane(state))
            finally:
                release.set()
        self.assertFalse(lane.busy())
        self.assertFalse(audit_runner._drain_cluster_lane(state), "an idle lane is not waited on")
        self.assertIn("Background cluster expansion: expanded=1 added=2", self.runtime.index.read_text())
        rows = [
            json.loads(line)
            for line in (results / "state" / "events.jsonl").read_text().splitlines()
        ]
        drained = [row for row in rows if row.get("phase") == "expansion_drain"]
        self.assertEqual(len(drained), 1, rows)
        self.assertTrue(drained[0]["blocked"])
        self.assertAlmostEqual(drained[0]["seconds"], state.housekeeping_seconds, places=2)
        self.assertGreater(state.housekeeping_seconds, 0.1)
        background = [row for row in rows if row.get("phase") == "cluster_expand"]
        self.assertEqual([row["blocked"] for row in background], [False])

    def test_a_pinned_lane_is_not_exhausted_while_expansion_mints_its_leads(self) -> None:
        """With the barrier no longer waiting, the next cohort can start before
        expansion lands; an empty lane then waits for it instead of stopping."""
        results = self.root / "results"
        (results / "state").mkdir(parents=True)
        runtime = SimpleNamespace(
            results=results, index=self.runtime.index, logs=self.logs,
            fixed_strategy="s4",
        )
        state = audit_runner.BackendState(runtime, mock.Mock(), iteration=2)
        release = threading.Event()
        crash = results / "crashes" / "CRASH-001-1"
        crash.mkdir(parents=True)

        def _expand(_runtime, **_kwargs):
            release.wait(5)
            return {"expanded": 1, "added": 1, "skipped": 0, "pending": 0}

        busy_when_asked: list[bool] = []

        def _exhausted(_runtime, _iteration=0):
            busy_when_asked.append(runtime.cluster_lane.busy())
            return True

        noop = mock.Mock(return_value=0)
        with mock.patch.object(audit_runner, "expand_new_crash_clusters", side_effect=_expand), \
                mock.patch.multiple(
                    audit_runner, _activate_runtime=noop, refresh_fuzz_leads=noop,
                    reset_sanitizer_run_counters=noop, reset_llm_decision_counters=noop,
                    progress=noop, filed_artifact_count=noop, _cold=noop,
                    refresh_work_cards=noop, release_stale_card_claims=noop,
                    expand_work_cards_if_exhausted=noop,
                    initialize_agent_strategies=noop,
                    _productive_wall_exhausted=mock.Mock(return_value=False),
                    _fixed_lane_unavailable=mock.Mock(return_value=""),
                    fixed_lane_exhausted=mock.Mock(side_effect=_exhausted),
                ):
            try:
                audit_runner._cluster_lane(runtime).schedule([crash], None, 2)
                threading.Timer(0.2, release.set).start()
                status, _results = audit_runner.run_iteration(state)
            finally:
                release.set()
        self.assertEqual(status, "stalled")
        self.assertEqual(busy_when_asked, [True, False])

    def test_agent_progress_matches_bare_status_to_suffixed_artifact(self) -> None:
        runtime = SimpleNamespace(results=self.root / "results")
        snapshot = audit_runner.ProgressSnapshot(
            findings=1, crashes=0, finding_roots=1, crash_roots=0,
            active=0, env_blocked=0,
            artifact_roots={
                "FIND-005-plugin-timer": "finding:FCL-TIMER",
            },
        )
        with mock.patch.object(
            audit_runner.structured_state, "agent_counts",
            return_value={"active": 0, "env_blocked": 0},
        ), mock.patch.object(
            audit_runner.structured_state, "agent_rows",
            return_value=[{"status": "FIND-005"}],
        ):
            progress = audit_runner.agent_progress(runtime, 2, snapshot)

        self.assertEqual(progress.roots, frozenset({"finding:FCL-TIMER"}))

    def test_agent_progress_uses_the_artifact_matcher_triage_uses(self) -> None:
        # A full name claims its collision-renamed copy, never a same-numbered
        # finding another agent filed.
        runtime = SimpleNamespace(results=self.root / "results")
        snapshot = audit_runner.ProgressSnapshot(
            findings=2, crashes=0, finding_roots=2, crash_roots=0,
            active=0, env_blocked=0,
            artifact_roots={
                "FIND-003-alpha.20260924T120000Z.1": "finding:FCL-ALPHA",
                "FIND-003-beta": "finding:FCL-BETA",
            },
        )
        with mock.patch.object(
            audit_runner.structured_state, "agent_counts",
            return_value={"active": 0, "env_blocked": 0},
        ), mock.patch.object(
            audit_runner.structured_state, "agent_rows",
            return_value=[{"status": "FIND-003-alpha"}],
        ):
            progress = audit_runner.agent_progress(runtime, 2, snapshot)

        self.assertEqual(progress.roots, frozenset({"finding:FCL-ALPHA"}))

    def test_phase_failure_is_recorded_without_masking_the_failure(self) -> None:
        runtime = SimpleNamespace(
            results=self.root / "results", target_root=self.root / "target",
            target_slug="sampleproj", num_agents=1, index=self.runtime.index,
            config=SimpleNamespace(
                attacker_controls=["bytes"],
                sanitizers_explicitly_disabled=False,
            ),
        )
        with mock.patch.object(
            audit_runner.triage, "triage_crash_dirs",
            side_effect=RuntimeError("triage failed"),
        ), mock.patch.object(
            audit_runner.time, "monotonic", side_effect=[10.0, 12.5],
        ), mock.patch.object(
            audit_runner, "index_log", side_effect=OSError("log unavailable"),
        ) as index_log:
            with self.assertRaisesRegex(RuntimeError, "triage failed"):
                audit_runner.post_iteration(runtime)
        index_log.assert_called_once_with(
            runtime, "Housekeeping phases: crash_triage=2.5s",
        )

    def test_initial_queue_refresh_is_recorded_as_housekeeping(self) -> None:
        results = self.root / "results"
        results.mkdir()
        runtime = SimpleNamespace(
            backend="codex", model="fixture", target_slug="sampleproj",
            target_root=self.root / "target", results=results, logs=self.logs,
            prompt_context=lambda _guide: mock.Mock(),
        )
        with mock.patch.object(audit_runner, "_activate_runtime"), \
                mock.patch.object(audit_runner, "index_log"), \
                mock.patch.object(audit_runner.prompt, "write_static_prompt_file"), \
                mock.patch.object(
                    audit_runner.triage, "restore_stale_trigger_rejections",
                ) as restore_rejections, \
                mock.patch.object(audit_runner, "refresh_work_cards"), \
                mock.patch.object(audit_runner, "initialize_agent_strategies"), \
                mock.patch.object(
                    audit_runner.time, "monotonic", side_effect=[120.0, 132.5],
                ):
            state = audit_runner.initialize_backend(
                runtime, SimpleNamespace(), "guide", started_at=100.0,
            )

        self.assertEqual(state.housekeeping_seconds, 12.5)
        self.assertEqual(float((self.logs / ".housekeeping_secs").read_text()), 12.5)
        restore_rejections.assert_called_once_with(results)

    def test_target_config_repair_does_not_dirty_source_work_cards(self) -> None:
        results = self.root / "output" / "sampleproj" / "codex" / "results"
        coverage = results / "coverage"
        coverage.mkdir(parents=True)
        config = results.parents[1] / "target.toml"
        config.write_text('target = "sampleproj"\n', encoding="utf-8")
        runtime = SimpleNamespace(
            results=results, target_root=self.root / "target",
            target_rev="rev-1",
            config=SimpleNamespace(s6_domain="", s6_peers=[]),
        )

        with mock.patch.object(
            audit_runner.target_config, "vcs_source_signature",
            return_value="source-1",
        ):
            first = audit_runner._work_card_signature(runtime)
        config.write_text(
            'target = "sampleproj"\nis_browser = true\n', encoding="utf-8",
        )
        with mock.patch.object(
            audit_runner.target_config, "vcs_source_signature",
            return_value="source-1",
        ):
            second = audit_runner._work_card_signature(runtime)
        self.assertEqual(first, second)

        runtime.config.s6_peers = ["peer-project"]
        with mock.patch.object(
            audit_runner.target_config, "vcs_source_signature",
            return_value="source-1",
        ):
            peer_changed = audit_runner._work_card_signature(runtime)
        self.assertNotEqual(second, peer_changed)

        (coverage / "edges-agent-1.journal").write_text(
            "edge|source.c:1\n", encoding="utf-8",
        )
        with mock.patch.object(
            audit_runner.target_config, "vcs_source_signature",
            return_value="source-1",
        ):
            self.assertNotEqual(
                peer_changed, audit_runner._work_card_signature(runtime)
            )
        with mock.patch.object(
            audit_runner.target_config, "vcs_source_signature",
            return_value="source-2",
        ):
            self.assertNotEqual(
                audit_runner._work_card_signature(runtime),
                audit_runner._work_card_signature(
                    runtime, source_signature="source-1",
                ),
            )

    def test_ranking_policy_is_part_of_the_work_card_signature(self) -> None:
        results = self.root / "output" / "sampleproj" / "codex" / "results"
        results.mkdir(parents=True)
        runtime = SimpleNamespace(
            results=results, target_root=self.root / "target",
            target_rev="rev-1",
            config=SimpleNamespace(s6_domain="", s6_peers=[]),
        )
        with mock.patch.object(
            audit_runner.target_config, "vcs_source_signature",
            return_value="source-1",
        ), mock.patch.object(
            audit_runner.callgraph, "cache_signature", return_value="graph-1",
        ), mock.patch.object(
            audit_runner.housekeeping, "signature", return_value="signature",
        ) as signature:
            self.assertEqual(audit_runner._work_card_signature(runtime), "signature")

        paths = signature.call_args.args[1]
        self.assertIn(str(ROOT / "bin" / "rank-work"), paths)
        self.assertIn(str(ROOT / "lib" / "workqueue.py"), paths)
        self.assertIn(str(ROOT / "lib" / "audit_scope.py"), paths)

    def test_cell_effective_wall_keeps_measured_housekeeping(self) -> None:
        path = self.root / "cell" / "cell.json"
        benchmark_runner.write_cell(
            path, "harness", 1, "fixture", self.root / "results",
            100, "done", 2, paused=10, housekeeping=25,
        )
        cell = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(cell["housekeeping_seconds"], 25)
        self.assertEqual(cell["wall_effective_seconds"], 90)
        self.assertEqual(
            benchmark._effective_wall({
                "wall_seconds": 100,
                "paused_seconds": 10,
                "housekeeping_seconds": 25,
            }),
            90,
        )

    def test_session_tokens_are_reported_as_separate_buckets(self) -> None:
        # Summing them reads as generated content when the figure is almost
        # entirely replayed context, which is how a cache-replay cost gets
        # diagnosed as a prompt-size problem.
        measured = audit_runner._token_display(
            {"tokens": {
                "input": 1_200, "cached_input": 81_500_000,
                "cache_creation": 505_000, "output": 264_000,
            }},
            True,
        )
        self.assertEqual(
            measured, "in:1200 cache:81500000 create:505000 out:264000",
        )
        self.assertNotIn(str(1_200 + 81_500_000 + 505_000 + 264_000), measured)
        # A session that ended without terminal telemetry still has real cache
        # numbers; hiding them loses the buckets that dominate the bill.
        self.assertTrue(
            audit_runner._token_display(
                {"tokens": {"cached_input": 5}}, False,
            ).endswith(
                "(estimated)",
            )
        )
        # Recovered Claude and character-count-only generic-backend rows are
        # usable enough to keep the audit moving, so usage_complete can be true
        # even though the numbers remain estimates.
        self.assertTrue(
            audit_runner._token_display(
                {"tokens": {"cached_input": 5}, "estimated": True}, True,
            ).endswith("(estimated)")
        )
        self.assertEqual(audit_runner._token_display({}, False), "unknown")

    def test_codex_session_log_shows_uncached_input(self) -> None:
        self.assertEqual(
            audit_runner._token_display(
                {"tokens": {
                    "input": 4_049_112,
                    "cached_input": 3_960_960,
                    "cache_creation": 0,
                    "output": 19_379,
                }},
                True,
                backend="codex",
            ),
            "in:4049112 cache:3960960 uncached:88152 create:0 out:19379",
        )


if __name__ == "__main__":
    unittest.main()
