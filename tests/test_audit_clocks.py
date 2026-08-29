#!/usr/bin/env python3
"""Audit wall-clock and housekeeping telemetry regressions."""

from __future__ import annotations

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

        # The finding gate and cluster expansion share one wall, so they report
        # as the single span they cost, keeping each component's own duration so
        # a regression in either is still attributable.
        phase_line = index_log.call_args_list[-1].args[1]
        self.assertRegex(
            phase_line,
            r"^Housekeeping phases: crash_triage=[\d.]+s "
            r"result_gates=[\d.]+s\(finding_gate=[\d.]+s cluster_expand=[\d.]+s\) "
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

    def test_the_two_result_gates_actually_run_at_the_same_time(self) -> None:
        """The span name is not the claim; overlap is. Each gate blocks until it
        sees the other running, so a sequential implementation deadlocks out."""
        runtime = SimpleNamespace(
            results=self.root / "results", target_root=self.root / "target",
            target_slug="sampleproj", num_agents=2, index=self.runtime.index,
            config=SimpleNamespace(
                attacker_controls=["bytes"],
                sanitizers_explicitly_disabled=False,
            ),
        )
        gate_running = threading.Event()
        expand_running = threading.Event()
        saw = {}

        def _gate(*_args, **_kwargs):
            gate_running.set()
            saw["gate_saw_expand"] = expand_running.wait(5)
            return {"accepted": 0, "rejected": 0, "pending": 0}

        def _expand(*_args, **_kwargs):
            expand_running.set()
            saw["expand_saw_gate"] = gate_running.wait(5)
            return {"added": 0}

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
                mock.patch.object(audit_runner, "promote_corpus", return_value=0), \
                mock.patch.object(audit_runner, "index_log"):
            audit_runner.post_iteration(runtime)

        self.assertEqual(
            saw, {"gate_saw_expand": True, "expand_saw_gate": True},
        )

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


if __name__ == "__main__":
    unittest.main()
