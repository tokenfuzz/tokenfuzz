#!/usr/bin/env python3
"""Harvest, aggregate, pooling, ledger, and cost-accounting regressions."""

from __future__ import annotations

import errno
import io
import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import benchmark
import llm_invoke
import llm_usage
import report_identity
import severity_receipt
import triage_validate
import validation_receipt


ASAN = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602\n"


class BenchmarkMetricsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="benchmark-metrics-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")

    def make_cell(
        self,
        bench: Path,
        name: str,
        condition: str,
        replicate: int,
        crashes: int,
        *,
        status: str = "done",
        findings: int = 0,
        rejected_findings: int = 0,
        refusals: int = 0,
        actual_agents: int | None = None,
        unadjudicated_crashes: int = 0,
        retained_crashes: int = 0,
    ) -> Path:
        cell = bench / "cells" / name
        payload = {
            "condition": condition,
            "replicate": replicate,
            "status": status,
            "wall_seconds": 42,
        }
        if actual_agents is not None:
            payload["actual_agents"] = actual_agents
        self.write_json(cell / "cell.json", payload)
        self.write_json(cell / "metrics.json", {
            "confirmed_crashes": crashes,
            "crash_candidates": crashes + retained_crashes + unadjudicated_crashes,
            "finalized_crashes": crashes + retained_crashes,
            "crashes_unadjudicated": unadjudicated_crashes,
            "crash_clusters": crashes,
            "crash_dirs": [f"CRASH-{i}" for i in range(crashes)],
            "findings": findings,
            "confirmed_findings": findings,
            "findings_rejected": rejected_findings,
            "model_refusals": refusals,
            "validation_waterfall": {
                "crashes": {
                    "candidates": crashes,
                    "evidence_complete": crashes,
                    "validated": crashes,
                    "routed": crashes,
                    "reportable": crashes,
                    "lanes": {"reportable": crashes},
                },
                "findings": {
                    "candidates": findings + rejected_findings,
                    "evidence_complete": findings,
                    "validated": findings + rejected_findings,
                    "routed": findings + rejected_findings,
                    "reportable": findings,
                    "lanes": {
                        "reportable": findings,
                        "rejected": rejected_findings,
                    },
                },
            },
            "tokens": {"output_tokens": 111, "token_source": "measured"},
        })
        return cell

    @staticmethod
    def finalize_fixture_finding(directory: Path) -> None:
        validation_receipt.write(
            directory,
            kind="finding",
            state="reportable",
            attacker_controls=["bytes"],
        )

    @staticmethod
    def finalize_fixture_crash(directory: Path) -> None:
        validation_receipt.write(
            directory,
            kind="crash",
            state="reportable",
            attacker_controls=["bytes"],
        )

    def test_harvest_counts_only_proved_and_adjudicated_artifacts(self) -> None:
        results = self.root / "results"
        proved = results / "crashes" / "CRASH-001"
        claimed = results / "crashes" / "CRASH-002"
        provisional = results / "crashes" / "CRASH-003"
        proved.mkdir(parents=True)
        claimed.mkdir()
        provisional.mkdir()
        (proved / "sanitizer.txt").write_text(ASAN)
        (proved / "input.bin").write_bytes(b"fixture")
        (proved / "report.md").write_text("# Proved bounds issue\n")
        self.finalize_fixture_crash(proved)
        (claimed / "report.md").write_text("claim only\n")
        (provisional / "report.md").write_text("# Provisional bounds issue\n")
        (provisional / "sanitizer.txt").write_text(ASAN)
        (provisional / "input.bin").write_bytes(b"fixture")
        rejected = results / "crashes-rejected"
        (rejected / "CRASH-009").mkdir(parents=True)
        (rejected / "REJECTED-CRASHES.md").write_text(
            "# Rejected crashes\n\n## Rejected crash directories\n\n"
            "| ID | Site | Reason | Report |\n|:--|:--|:--|:--|\n"
            "| `CRASH-009` | app_parse app.c:91 | rejected | "
            "[Link](CRASH-009/REPORT.md) |\n"
        )

        findings = results / "findings"
        for name in ("FIND-ACCEPTED", "FIND-PENDING", "FIND-KEEP", "FIND-REVIEWED"):
            (findings / name).mkdir(parents=True)
        accepted_report = findings / "FIND-ACCEPTED" / "report.md"
        accepted_report.write_text("# Accepted state issue\n")
        self.write_json(findings / "FIND-ACCEPTED" / ".llm-find-quality.json", {"accept": True})
        self.write_json(findings / "FIND-ACCEPTED" / ".trigger-gate.json", {
            "vote": "Promote",
            "content_sha1": report_identity.content_sha1(accepted_report),
            "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
            "attacker_controls": ["bytes"],
            "anchors_verified": True,
        })
        validation_receipt.write(
            findings / "FIND-ACCEPTED",
            kind="finding",
            state="reportable",
            attacker_controls=["bytes"],
        )
        (findings / "FIND-KEEP" / ".keep").touch()
        (findings / "FIND-REVIEWED" / ".reviewed").touch()
        for name in ("FIND-KEEP", "FIND-REVIEWED"):
            (findings / name / "report.md").write_text(
                f"# {name} state issue\n", encoding="utf-8",
            )
            self.finalize_fixture_finding(findings / name)
        (results / "findings-rejected" / "FIND-REJECTED").mkdir(parents=True)
        (results / "findings-rejected" / "FIND-REJECTED" / "report.md").write_text(
            "# rejected report\n", encoding="utf-8",
        )
        # A directory an agent created and never wrote into, closed by the
        # gate as `incomplete missing: missing report.md`: not a report review
        # turned down, so it is not a rejected finding.
        (results / "findings-rejected" / "FIND-EMPTY").mkdir(parents=True)
        (results / "findings-rejected" / "FIND-EMPTY" / "REJECTION.md").write_text(
            "# Rejected artifact\n\nReason: incomplete missing: missing report.md\n",
            encoding="utf-8",
        )
        (results / "state").mkdir()
        (results / "state" / "hypotheses.jsonl").write_text(
            '{"id":"H1","status":"DISCARDED"}\n{"id":"H2","status":"PENDING"}\n'
        )
        logs = results / "logs"
        logs.mkdir()
        (logs / "index.jsonl").write_text(
            '{"backend":"codex","tokens":{"input":1000,"cached_input":800,"output":50}}\n'
            '{"backend":"codex","tokens":{"input":500,"cached_input":400,"output":30}}\n'
        )
        (logs / "provider.refusals.log").write_text("WARN MODEL_REFUSAL one\nnoise\n")

        metrics = benchmark.harvest(results)
        self.assertEqual(metrics["confirmed_crashes"], 1)
        self.assertEqual(metrics["crash_dirs"], ["CRASH-001"])
        self.assertEqual(metrics["crash_candidates"], 2)
        self.assertEqual(metrics["crashes_unadjudicated"], 1)
        self.assertEqual(metrics["crashes_rejected"], 1)
        self.assertEqual(metrics["findings"], 4)
        self.assertEqual(metrics["confirmed_findings"], 3)
        self.assertEqual(metrics["confirmed_finding_dirs"], ["FIND-ACCEPTED", "FIND-KEEP", "FIND-REVIEWED"])
        self.assertEqual(metrics["findings_unadjudicated"], 1)
        self.assertEqual(metrics["findings_rejected"], 1)
        self.assertEqual(metrics["discarded_hypotheses"], 1)
        self.assertEqual(metrics["model_refusals"], 1)
        self.assertEqual(metrics["tokens"]["input_tokens"], 300)
        self.assertEqual(metrics["tokens"]["cached_input_tokens"], 1200)
        self.assertEqual(metrics["tokens"]["output_tokens"], 80)
        # No probe state and no transcript: the one confirmed crash is the floor.
        self.assertEqual(metrics["tokens"]["asan_invocations"], 1)
        self.assertEqual(
            metrics["validation_waterfall"]["crashes"]["candidates"], 4,
        )
        self.assertEqual(
            metrics["validation_waterfall"]["crashes"]["evidence_complete"], 2,
        )
        self.assertEqual(
            metrics["validation_waterfall"]["findings"]["lanes"]["reportable"],
            3,
        )
        self.assertEqual(
            metrics["validation_waterfall"]["findings"]["lanes"][
                "legacy-provisional"
            ],
            1,
        )
        # The waterfall is the full gate ledger, so the report-less directory
        # is a candidate that fell at evidence and was routed to the rejected
        # lane; the headline `findings_rejected` counts reports turned down.
        self.assertEqual(
            metrics["validation_waterfall"]["findings"]["lanes"]["rejected"],
            2,
        )
        self.assertEqual(
            metrics["validation_waterfall"]["findings"]["candidates"], 6,
        )
        self.assertEqual(
            metrics["validation_waterfall"]["findings"]["evidence_complete"], 3,
        )

        legacy = self.root / "legacy-row-rejected"
        (legacy / "crashes-rejected").mkdir(parents=True)
        (legacy / "crashes-rejected" / "REJECTED-CRASHES.md").write_text(
            "| ID | Crash site | Rejected at |\n|:--|:--|:--|\n"
            "| CR-a | app_parse.c:10 | t1 |\n"
            "| CR-b | app_parse.c:20 | t2 |\n"
        )
        self.assertEqual(benchmark.harvest(legacy)["crashes_rejected"], 2)

    def test_not_reportable_is_excluded_but_a_reportable_low_counts(self) -> None:
        """The two meanings of "low" must not merge into one column."""
        results = self.root / "not-reportable"
        crash = results / "crashes" / "CRASH-001"
        finding = results / "findings" / "FIND-001"
        for directory, kind in ((crash, "crash"), (finding, "finding")):
            directory.mkdir(parents=True)
            (directory / "report.md").write_text(
                "# Retained engineering defect\n", encoding="utf-8",
            )
            validation_receipt.write(
                directory,
                kind=kind,
                state="not-reportable",
                attacker_controls=["bytes"],
            )
        (crash / "sanitizer.txt").write_text(ASAN, encoding="utf-8")
        (crash / "input.bin").write_bytes(b"fixture")
        validation_receipt.write(
            crash,
            kind="crash",
            state="not-reportable",
            attacker_controls=["bytes"],
        )
        # A security report whose CVSS band happens to be Low still counts.
        reportable_low = results / "crashes" / "CRASH-002"
        reportable_low.mkdir(parents=True)
        (reportable_low / "report.md").write_text(
            "# Reportable low-severity issue\n\n"
            "- **Severity**: Low (CVSS-BT 4.0: 3.3 Low; primitive=sample)\n",
            encoding="utf-8",
        )
        (reportable_low / "sanitizer.txt").write_text(ASAN, encoding="utf-8")
        (reportable_low / "input.bin").write_bytes(b"fixture")
        validation_receipt.write(
            reportable_low,
            kind="crash",
            state="reportable",
            attacker_controls=["bytes"],
        )

        metrics = benchmark.harvest(results)
        self.assertEqual(metrics["confirmed_crashes"], 1)
        self.assertEqual(metrics["crash_dirs"], ["CRASH-002"])
        self.assertEqual(metrics["confirmed_findings"], 0)
        self.assertEqual(metrics["finalized_crashes"], 2)
        self.assertEqual(metrics["finalized_findings"], 1)
        self.assertEqual(metrics["crashes_unadjudicated"], 0)
        self.assertEqual(metrics["findings_unadjudicated"], 0)
        self.assertEqual(
            metrics["validation_waterfall"]["crashes"]["lanes"][
                "reportable"
            ],
            1,
        )
        self.assertEqual(
            metrics["validation_waterfall"]["crashes"]["lanes"][
                "not-reportable"
            ],
            1,
        )
        self.assertEqual(
            metrics["validation_waterfall"]["findings"]["lanes"][
                "not-reportable"
            ],
            1,
        )

    def test_legacy_finding_metrics_preserve_quality_only_run_semantics(self) -> None:
        results = self.root / "legacy-findings"
        finding = results / "findings" / "FIND-001"
        finding.mkdir(parents=True)
        report = finding / "report.md"
        report.write_text("# State issue\n", encoding="utf-8")
        self.write_json(finding / ".llm-find-quality.json", {
            "accept": True,
            "report_sha1": report_identity.content_sha1(report),
        })

        current = benchmark.harvest(results)
        legacy = benchmark.harvest(
            results, require_trigger_confirmation=False,
        )

        self.assertEqual(current["confirmed_findings"], 0)
        self.assertEqual(current["findings_unadjudicated"], 1)
        self.assertEqual(current["finding_confirmation"], "quality-trigger-v1")
        self.assertEqual(legacy["confirmed_findings"], 1)
        self.assertEqual(legacy["findings_unadjudicated"], 0)
        self.assertEqual(legacy["finding_confirmation"], "legacy-quality")

    def test_sibling_logs_and_sanitizer_effort_floor(self) -> None:
        backend = self.root / "experiment" / "codex"
        results = backend / "results"
        logs = backend / "logs"
        results.mkdir(parents=True)
        logs.mkdir()
        (logs / "index.jsonl").write_text(
            '{"backend":"codex","tokens":{"input":4000,"cached_input":3800,"output":120}}\n'
        )
        metrics = benchmark.harvest(results)
        self.assertEqual(metrics["tokens"]["input_tokens"], 200)
        # Nothing executed and nothing crashed: the honest answer is zero, and
        # the source says which signal that came from.
        self.assertEqual(metrics["tokens"]["asan_invocations"], 0)
        self.assertEqual(metrics["execution"]["source"], "none")

        state = results / "state"
        state.mkdir()
        (state / "runs.jsonl").write_text(
            json.dumps({
                "id": "RUN-1", "verdict": "CLEAN", "sanitizer": "asan",
                "sanitizer_runs": 1,
            }) + "\n" + json.dumps({
                "id": "RUN-2", "verdict": "CRASH", "sanitizer": "asan",
                "sanitizer_runs": 5,
            }) + "\n" + json.dumps({
                "id": "RUN-3", "verdict": "NO_EXEC", "sanitizer": "ubsan",
                "sanitizer_runs": 2,
            }) + "\n" + json.dumps({
                "id": "RUN-4", "verdict": "MISSED", "sanitizer": "asan",
                "sanitizer_runs": 0,
            }) + "\nnot-json\n",
            encoding="utf-8",
        )
        metrics = benchmark.harvest(results)
        self.assertEqual(metrics["execution"]["probe_records"], 4)
        self.assertEqual(metrics["execution"]["sanitizer_invocations"], 8)
        self.assertEqual(metrics["execution"]["by_sanitizer"], {"asan": 6, "ubsan": 2})
        self.assertEqual(metrics["execution"]["by_verdict"], {
            "CLEAN": 1, "CRASH": 5, "NO_EXEC": 2, "MISSED": 0,
        })
        self.assertEqual(metrics["execution"]["source"], "state/runs.jsonl")
        self.assertEqual(metrics["tokens"]["asan_invocations"], 8)

        direct = self.root / "direct"
        crash = direct / "crashes" / "CRASH-1"
        crash.mkdir(parents=True)
        (crash / "sanitizer.txt").write_text(ASAN)
        (crash / "report.md").write_text("# Proved bounds issue\n")
        self.finalize_fixture_crash(crash)
        direct_metrics = benchmark.harvest(direct)
        self.assertEqual(direct_metrics["tokens"]["asan_invocations"], 1)
        self.assertEqual(direct_metrics["execution"]["source"], "crash-floor")

    def test_model_direct_execution_is_read_from_its_own_transcript(self) -> None:
        """A hand-driven cell must not score as zero execution.

        A model-direct cell runs the sanitizer build itself instead of through
        bin/probe, so it writes no state/runs.jsonl. Every such row reported
        zero sanitizer work, which read the same whether the cell never touched
        the binary or fuzzed it for four hours.
        """
        direct = self.root / "direct-cell"
        (direct / "crashes").mkdir(parents=True)
        (direct / "findings").mkdir(parents=True)
        (direct / "backend.raw.log").write_text(
            # Claude assistant-message shape.
            json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [
                {"type": "tool_use", "name": "Bash", "input": {
                    "command": "ASAN_OPTIONS=detect_leaks=0 ./build-asan/app poc"}},
            ]}}) + "\n"
            # The result echoing that command back must not count twice.
            + json.dumps({"type": "user", "message": {"role": "user", "content": [
                {"type": "tool_result", "content":
                 "ASAN_OPTIONS=detect_leaks=0 ./build-asan/app poc\nclean"},
            ]}}) + "\n"
            # Codex shape, a different sanitizer runtime.
            + json.dumps({"type": "command_execution",
                          "command": "UBSAN_OPTIONS=halt_on_error=1 ./build-ubsan/app poc"}) + "\n"
            # Reading source is not executing it.
            + json.dumps({"type": "assistant", "message": {"role": "assistant", "content": [
                {"type": "tool_use", "name": "Bash",
                 "input": {"command": "rg ASAN_OPTIONS docs/"}},
            ]}}) + "\n",
            encoding="utf-8",
        )
        metrics = benchmark.harvest(direct)
        self.assertEqual(metrics["execution"]["sanitizer_command_requests"], 2)
        self.assertEqual(metrics["execution"]["probe_records"], 0)
        # The request count is evidence the crash lane was worked. It is not
        # an execution count in either direction — one matched loop can run
        # the target thousands of times, and a command that only writes a
        # script naming the option matches too — so it must never reach the
        # exact counters or be rendered as probes.
        self.assertEqual(metrics["execution"]["sanitizer_invocations"], 0)
        self.assertEqual(metrics["tokens"]["asan_invocations"], 0)
        self.assertEqual(metrics["execution"]["source"], "none")

    def test_a_request_count_is_neither_a_floor_nor_a_ceiling(self) -> None:
        """Pin both directions so nobody later reads it as an execution total."""
        direct = self.root / "inexact"
        direct.mkdir(parents=True)
        (direct / "backend.raw.log").write_text(
            # Over-counts: this writes a script, it does not run one.
            json.dumps({"type": "command_execution", "command":
                        "cat > run.sh <<'EOF'\nASAN_OPTIONS=detect_leaks=0 ./app\nEOF"}) + "\n"
            # Under-counts: one request, thousands of executions, no option named.
            + json.dumps({"type": "command_execution", "command": "./run.sh 6000"}) + "\n"
            # A race runtime names its own option variable, not *SAN_OPTIONS.
            + json.dumps({"type": "command_execution",
                          "command": "GORACE=halt_on_error=1 ./racer poc"}) + "\n",
            encoding="utf-8",
        )
        execution = benchmark.harvest(direct)["execution"]
        self.assertEqual(execution["sanitizer_command_requests"], 2)
        self.assertEqual(execution["sanitizer_invocations"], 0)

    def test_structured_probe_state_outranks_the_transcript(self) -> None:
        """A harness cell exports the same options through bin/probe.

        Both signals describe the same runs, so adding them would bill the work
        twice; structured state is the precise one and wins outright.
        """
        results = self.root / "harness-cell"
        (results / "state").mkdir(parents=True)
        (results / "state" / "runs.jsonl").write_text(
            json.dumps({"id": "RUN-1", "verdict": "CRASH",
                        "sanitizer": "asan", "sanitizer_runs": 3}) + "\n",
            encoding="utf-8",
        )
        (results / "backend.raw.log").write_text(
            "\n".join(
                json.dumps({"type": "command_execution",
                            "command": f"ASAN_OPTIONS=halt_on_error=1 ./app {n}"})
                for n in range(9)
            ) + "\n",
            encoding="utf-8",
        )
        metrics = benchmark.harvest(results)
        self.assertEqual(metrics["execution"]["probe_records"], 1)
        self.assertEqual(metrics["execution"]["sanitizer_invocations"], 3)
        self.assertEqual(metrics["execution"]["sanitizer_command_requests"], 0)
        self.assertEqual(metrics["execution"]["source"], "state/runs.jsonl")

    def test_focused_trigger_resolution_replaces_the_raw_vote_conflict(self) -> None:
        finding = self.root / "findings" / "FIND-001"
        finding.mkdir(parents=True)
        report = finding / "report.md"
        report.write_text("# Boundary issue\n", encoding="utf-8")
        common = {
            "content_sha1": report_identity.content_sha1(report),
            "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
            "attacker_controls": ["bytes"],
            "anchors": [{"path": "sample.c"}],
            "anchors_verified": True,
        }
        first = finding / ".trigger-gate.json"
        second = finding / ".trigger-gate-2.json"
        first.write_text(json.dumps({**common, "vote": "Reject"}))
        second.write_text(json.dumps({**common, "vote": "Promote"}))
        self.assertEqual(benchmark._trigger_snapshot(finding)[0], "conflict")

        (finding / ".trigger-gate-resolution.json").write_text(json.dumps({
            **common,
            "vote": "Promote",
            "decision_version": (
                triage_validate.TRIGGER_RESOLUTION_DECISION_VERSION
            ),
            "prior_review_sha256s": triage_validate.prior_review_sha256s(
                (first, second),
            ),
        }))
        self.assertEqual(
            benchmark._trigger_snapshot(finding), ("promote", {"Promote"}),
        )

    def test_oss_input_is_disjoint_from_cache_reads(self) -> None:
        # OpenCode reports fresh input separately from cache reads, so a long
        # session's summed cache reads dwarf its summed input. Normalizing oss
        # as cumulative subtracted the one from the other and floored the whole
        # session at zero, which published a measured cell as near-free.
        index = self.root / "index.jsonl"
        index.write_text(json.dumps({
            "backend": "oss",
            "tokens": {
                "input": 2657971, "cached_input": 65454784, "output": 127967,
            },
        }) + "\n")
        totals = benchmark.harvest_tokens(index)
        self.assertEqual(totals["input_tokens"], 2657971)
        self.assertEqual(totals["cached_input_tokens"], 65454784)
        self.assertEqual(totals["output_tokens"], 127967)
        self.assertEqual(totals["token_source"], "measured")

    def test_token_normalization_sources_and_pricing(self) -> None:
        index = self.root / "index.jsonl"
        rows = [
            {"backend": "codex", "tokens": {"input": 1000, "cached_input": 800, "output": 50}},
            {"backend": "claude", "tokens": {"input": 30, "cached_input": 4000, "cache_creation": 120, "output": 700}},
            {"backend": "gemini", "tokens": {"input": 58000, "cached_input": 55000, "output": 80}},
        ]
        index.write_text("".join(json.dumps(row) + "\n" for row in rows))
        totals = benchmark.harvest_tokens(index)
        self.assertEqual(totals["input_tokens"], 3350)
        self.assertEqual(totals["cached_input_tokens"], 59800)
        self.assertEqual(totals["cache_creation_tokens"], 120)
        self.assertEqual(totals["output_tokens"], 830)
        self.assertEqual(totals["token_source"], "measured")

        cases = (
            ("claude", "claude-opus-4-8", {"input": 1000, "cached_input": 2000, "cache_creation": 400, "output": 3000}, "0.083500"),
            ("grok", "grok-build-0.1", {"input": 3000, "cached_input": 2000, "output": 3000}, "0.007400"),
            ("codex", "gpt-5.5", {"input": 5000000, "cached_input": 4800000, "output": 1000, "prompt_estimate_build": 16000}, "3.430000"),
            ("codex", "gpt-5.6-sol", {"input": 5000000, "cached_input": 4800000, "output": 1000, "prompt_estimate_build": 16000}, "2.740000"),
        )
        for backend, model, tokens, expected in cases:
            with self.subTest(backend=backend, model=model):
                index.write_text(json.dumps({
                    "backend": backend, "model": model,
                    "timestamp": "2026-08-22T00:00:00+00:00",
                    "tokens": tokens,
                }) + "\n")
                self.assertEqual(benchmark.harvest_tokens(index)["cost_usd"], expected)

        index.write_text(json.dumps({
            "backend": "claude", "model": "claude-opus-4-8",
            "cost_usd": 0.123456, "cost_source": "backend-reported",
            "tokens": {"input": 1, "output": 1},
        }) + "\n")
        native = benchmark.harvest_tokens(index)
        self.assertEqual(native["cost_usd"], "0.123456")
        self.assertEqual(native["cost_source"], "backend-reported")

    def test_artifact_links_are_advisory_and_preserve_raw_counts(self) -> None:
        results = self.root / "linked-results"
        findings = results / "findings"
        crashes = results / "crashes"
        for name in ("FIND-001", "FIND-002"):
            directory = findings / name
            directory.mkdir(parents=True)
            (directory / ".keep").touch()
            suffix = "\nRelated evidence: CRASH-001\n" if name == "FIND-001" else "\n"
            (directory / "report.md").write_text(
                f"# State issue\n\nCluster: FCL-same{suffix}", encoding="utf-8"
            )
            self.finalize_fixture_finding(directory)
        for name in ("CRASH-001", "CRASH-002"):
            directory = crashes / name
            directory.mkdir(parents=True)
            (directory / "sanitizer.txt").write_text(ASAN, encoding="utf-8")
            (directory / "REPORT.md").write_text(
                "# Bounds issue\n\nCluster: CL-same\n", encoding="utf-8"
            )
            self.finalize_fixture_crash(directory)

        metrics = benchmark.harvest(results)

        self.assertEqual(metrics["confirmed_findings"], 2)
        self.assertEqual(metrics["confirmed_crashes"], 2)
        self.assertEqual(metrics["artifact_links"]["duplicate_groups"], [
            {
                "kind": "crash", "cluster": "CL-same",
                "members": ["CRASH-001", "CRASH-002"],
            },
            {
                "kind": "finding", "cluster": "FCL-same",
                "members": ["FIND-001", "FIND-002"],
            },
        ])
        self.assertEqual(metrics["artifact_links"]["cross_kind"], [
            {
                "finding": "FIND-001", "crash": "CRASH-001",
                "evidence": "explicit-reference",
            },
        ])

    def test_an_unstamped_cluster_row_does_not_group_unrelated_crashes(self) -> None:
        # export-repro stamps every bundle's Cluster row with a placeholder
        # until bin/cluster-crashes computes a real id. Read as a value, that
        # placeholder is one cluster key every exported bundle shares.
        rows = {
            "table": (
                "| Field | Value |\n| --- | --- |\n"
                "| Cluster | (set by bin/cluster-crashes) |\n"
            ),
            "bare": "Cluster: (set by bin/cluster-crashes)\n",
        }
        for form, row in rows.items():
            with self.subTest(form=form):
                results = self.root / f"unstamped-{form}-results"
                crashes = results / "crashes"
                for name in ("CRASH-001", "CRASH-002"):
                    directory = crashes / name
                    directory.mkdir(parents=True)
                    (directory / "sanitizer.txt").write_text(
                        ASAN, encoding="utf-8",
                    )
                    (directory / "REPORT.md").write_text(
                        f"# {name}\n\n{row}", encoding="utf-8",
                    )
                    self.finalize_fixture_crash(directory)

                metrics = benchmark.harvest(results)

                self.assertEqual(metrics["confirmed_crashes"], 2)
                self.assertEqual(metrics["crash_clusters"], 2)
                self.assertEqual(
                    metrics["artifact_links"]["duplicate_groups"], [],
                )

    def test_a_blank_canonical_cluster_does_not_resurrect_a_stale_secondary_stamp(self) -> None:
        # REPORT.md/report.md is the artifact's current report. If more than
        # one recognized report form exists, a stale secondary stamp must not
        # override the canonical report and merge unrelated artifacts.
        results = self.root / "canonical-cluster-results"
        findings = results / "findings"
        for name in ("FIND-001", "FIND-002"):
            directory = findings / name
            directory.mkdir(parents=True)
            (directory / "report.md").write_text(
                f"# {name}\n\nCluster: (set by bin/cluster-crashes)\n",
                encoding="utf-8",
            )
            (directory / "README.md").write_text(
                "# Old report\n\nCluster: FCL-stale\n", encoding="utf-8",
            )
            self.finalize_fixture_finding(directory)

        metrics = benchmark.harvest(results)

        self.assertEqual(metrics["confirmed_findings"], 2)
        self.assertEqual(metrics["finding_clusters"], 2)
        self.assertEqual(metrics["artifact_links"]["duplicate_groups"], [])

    def test_metric_report_reads_are_bounded(self) -> None:
        report = self.root / "oversized-report.md"
        report.write_bytes(b"a" * (benchmark._MAX_SCAN_BYTES + 4096))

        text = benchmark._read_metric_report(report)

        self.assertEqual(len(text.encode()), benchmark._MAX_SCAN_BYTES)

    def test_gate_states_expose_observed_conflicts_without_redisposition(self) -> None:
        results = self.root / "gate-results"
        finding = results / "findings" / "FIND-001"
        pending = results / "findings" / "FIND-002"
        rejected = results / "findings-rejected" / "FIND-003"
        crash = results / "crashes" / "CRASH-001"
        for directory in (finding, pending, rejected, crash):
            directory.mkdir(parents=True)

        finding_report = finding / "report.md"
        finding_report.write_text(
            "# State issue\n\nRelated evidence: CRASH-001\n", encoding="utf-8"
        )
        self.write_json(finding / ".llm-find-quality.json", {"accept": True})
        self.write_json(finding / ".trigger-gate.json", {
            "vote": "Reject",
            "content_sha1": report_identity.content_sha1(finding_report),
            "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
            "attacker_controls": ["bytes"],
            "anchors": [{"path": "sample.c"}],
            "anchors_verified": True,
            "review_facts": {"rejection_kind": "contract-invalid"},
        })
        (pending / "report.md").write_text("# Pending state issue\n", encoding="utf-8")
        self.write_json(pending / ".llm-find-quality.json", {
            "accept": True, "report_sha1": "stale-report",
        })

        rejected_report = rejected / "report.md"
        rejected_report.write_text("# Rejected state issue\n", encoding="utf-8")
        self.write_json(rejected / ".llm-find-quality.json", {
            "accept": False, "accept_count": 1, "reject_count": 1,
        })

        crash_report = crash / "REPORT.md"
        crash_report.write_text("# Bounds issue\n", encoding="utf-8")
        (crash / "sanitizer.txt").write_text(ASAN, encoding="utf-8")
        self.write_json(crash / ".trigger-gate.json", {
            "vote": "Promote",
            "content_sha1": report_identity.content_sha1(crash_report),
            "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
            "attacker_controls": ["bytes"],
            "anchors": [{"path": "sample.c"}],
            "anchors_verified": True,
        })
        self.finalize_fixture_crash(crash)

        metrics = benchmark.harvest(results)
        states = {row["id"]: row for row in metrics["gate_states"]}

        self.assertEqual(metrics["confirmed_findings"], 0)
        self.assertEqual(metrics["findings_rejected_pending"], 0)
        self.assertEqual(metrics["findings_unadjudicated"], 2)
        self.assertEqual(metrics["findings_rejected"], 1)
        self.assertEqual(metrics["confirmed_crashes"], 1)
        self.assertEqual(states["FIND-001"]["disposition"], "pending")
        self.assertEqual(states["FIND-001"]["quality"], "accept")
        self.assertEqual(states["FIND-001"]["trigger"], "reject")
        self.assertTrue(states["FIND-001"]["reproduced"])
        self.assertEqual(states["FIND-001"]["conflicts"], ["linked-trigger"])
        self.assertEqual(states["CRASH-001"]["conflicts"], ["linked-trigger"])
        self.assertEqual(states["FIND-002"]["disposition"], "pending")
        self.assertEqual(states["FIND-002"]["quality"], "stale")
        self.assertTrue(states["FIND-002"]["pending"])
        self.assertEqual(states["FIND-003"]["disposition"], "rejected")
        self.assertEqual(states["FIND-003"]["conflicts"], ["quality-votes"])

    def test_rejected_receipt_left_in_active_lane_is_not_unadjudicated(self) -> None:
        results = self.root / "results"
        finding = results / "findings" / "FIND-001"
        finding.mkdir(parents=True)
        (finding / "report.md").write_text(
            "# Rejected state issue\n", encoding="utf-8",
        )
        validation_receipt.write(
            finding, kind="finding", state="rejected",
            detail="directory move pending",
        )

        metrics = benchmark.harvest(results)

        self.assertEqual(metrics["confirmed_findings"], 0)
        self.assertEqual(metrics["findings_rejected_pending"], 1)
        self.assertEqual(metrics["findings_unadjudicated"], 0)

    def test_current_model_families_use_their_exact_price_tiers(self) -> None:
        cases = (
            ("codex", "gpt-5.6", "4", "0.40", "20"),
            ("codex", "gpt-5.6-sol", "4", "0.40", "20"),
            ("codex", "gpt-5.6-terra", "2", "0.20", "12"),
            ("codex", "gpt-5.6-luna", "0.20", "0.02", "1.20"),
            ("codex", "gpt-5.5-2026-04-23", "5", "0.50", "30"),
            ("codex", "gpt-5.5-pro", "30", "0", "180"),
            ("codex", "gpt-5.4", "2.50", "0.25", "15"),
            ("codex", "gpt-5.4-mini", "0.75", "0.075", "4.50"),
            ("codex", "gpt-5.4-nano", "0.20", "0.02", "1.25"),
            ("codex", "gpt-5.4-pro", "30", "0", "180"),
            ("codex", "gpt-5.3-codex", "1.75", "0.175", "14"),
            ("codex", "gpt-5.2", "1.75", "0.175", "14"),
            ("codex", "gpt-5.2-pro", "21", "0", "168"),
            ("codex", "gpt-5.1", "1.25", "0.125", "10"),
            ("codex", "gpt-5", "1.25", "0.125", "10"),
            ("codex", "gpt-5-mini", "0.25", "0.025", "2"),
            ("codex", "gpt-5-nano", "0.05", "0.005", "0.40"),
            ("codex", "gpt-4.1", "2", "0.50", "8"),
            ("codex", "gpt-4.1-mini", "0.40", "0.10", "1.60"),
            ("codex", "gpt-4o", "2.50", "1.25", "10"),
            ("codex", "gpt-4o-2024-05-13", "5", "0", "15"),
            ("codex", "gpt-4o-mini", "0.15", "0.075", "0.60"),
            ("codex", "o1", "15", "7.50", "60"),
            ("codex", "o1-pro", "150", "0", "600"),
            ("codex", "o3", "2", "0.50", "8"),
            ("codex", "o3-pro", "20", "0", "80"),
            ("codex", "o4-mini", "1.10", "0.275", "4.40"),
            ("codex", "gpt-4-turbo-2024-04-09", "10", "0", "30"),
            ("codex", "gpt-3.5-turbo", "0.50", "0", "1.50"),
            ("claude", "claude-fable-5", "10", "1", "50"),
            ("claude", "claude-mythos-5", "10", "1", "50"),
            ("claude", "claude-opus-5", "5", "0.50", "25"),
            ("claude", "claude-opus-4-8", "5", "0.50", "25"),
            ("claude", "claude-opus-4-5", "5", "0.50", "25"),
            ("claude", "claude-opus-4-1", "15", "1.50", "75"),
            ("claude", "claude-3-opus-20240229", "15", "1.50", "75"),
            ("claude", "claude-sonnet-5", "2", "0.20", "10"),
            ("claude", "claude-sonnet-4-6", "3", "0.30", "15"),
            ("claude", "claude-sonnet-4-5", "3", "0.30", "15"),
            ("claude", "claude-3-7-sonnet-20250219", "3", "0.30", "15"),
            ("claude", "claude-3-5-sonnet-20241022", "3", "0.30", "15"),
            ("claude", "claude-haiku-4-5-20251001", "1", "0.10", "5"),
            ("claude", "claude-3-5-haiku-20241022", "0.80", "0.08", "4"),
            ("claude", "claude-3-haiku-20240307", "0.25", "0.03", "1.25"),
            ("gemini", "gemini-3.7-flash", "0.75", "0.075", "3.75"),
            ("gemini", "gemini-3.6-flash", "0.75", "0.075", "3.75"),
            ("gemini", "gemini-3.5-flash", "1.50", "0.15", "9"),
            ("gemini", "gemini-3.5-flash-lite", "0.30", "0.03", "2.50"),
            ("gemini", "gemini-3.1-pro-preview", "2", "0.20", "12"),
            ("gemini", "gemini-3.1-flash-lite", "0.25", "0.025", "1.50"),
            ("gemini", "gemini-3-flash-preview", "0.50", "0.05", "3"),
            ("gemini", "gemini-2.5-pro", "1.25", "0.125", "10"),
            ("gemini", "gemini-2.5-flash", "0.30", "0.03", "2.50"),
            ("gemini", "gemini-2.5-flash-lite", "0.10", "0.01", "0.40"),
            ("gemini", "gemini-2.0-flash", "0.10", "0.025", "0.40"),
            ("gemini", "gemini-2.0-flash-lite", "0.075", "0", "0.30"),
            ("grok", "grok-build-0.1", "1", "0.20", "2"),
            ("grok", "grok-4.6", "2", "0.50", "6"),
            ("grok", "grok-4.5", "2", "0.30", "6"),
            ("grok", "grok-4.3", "1.25", "0.20", "2.50"),
            ("grok", "grok-4.20-0309-reasoning", "1.25", "0.20", "2.50"),
        )
        for backend, model, input_rate, cache_rate, output_rate in cases:
            with self.subTest(backend=backend, model=model):
                rates = benchmark._pricing_rates(backend, model)
                self.assertIsNotNone(rates)
                if rates.get("tiered"):
                    self.assertEqual(str(rates["input_low"]), input_rate)
                    self.assertEqual(str(rates["cache_read_low"]), cache_rate)
                    self.assertEqual(str(rates["output_low"]), output_rate)
                else:
                    self.assertEqual(str(rates["input"]), input_rate)
                    self.assertEqual(str(rates.get("cache_read", 0)), cache_rate)
                    self.assertEqual(str(rates["output"]), output_rate)

        # The old "mini" suffix is not a GPT-5.6 model tier, and arbitrary
        # future-looking names must not inherit Sol pricing by substring.
        self.assertIsNone(benchmark._pricing_rates("codex", "gpt-5.6-mini"))
        self.assertIsNone(benchmark._pricing_rates("codex", "gpt-5.60"))
        self.assertIsNone(benchmark._pricing_rates("codex", "gpt-5-6"))
        self.assertIsNone(benchmark._pricing_rates("claude", "claude-haiku-5"))
        self.assertIsNone(benchmark._pricing_rates("claude", "claude-opus-6"))
        # Sonnet 5 is the standing argument against pricing an announcement:
        # its 2026-09-01 increase to $3/$15 was cancelled and the launch price
        # became standard. No row keys on a date, so nothing in the table can
        # restate a finished run's spend on a day a change was merely
        # scheduled for.
        self.assertNotIn(
            "priced_at",
            inspect.signature(benchmark._pricing_rates).parameters,
        )
        self.assertNotIn(
            "priced_at",
            inspect.signature(benchmark._cost_decimal).parameters,
        )
        sonnet = benchmark._pricing_rates("claude", "claude-sonnet-5")
        self.assertEqual(str(sonnet["input"]), "2")
        self.assertEqual(str(sonnet["cache_write"]), "2.50")
        self.assertEqual(str(sonnet["cache_write_1h"]), "4")
        self.assertEqual(str(sonnet["cache_read"]), "0.20")
        self.assertEqual(str(sonnet["output"]), "10")
        # Both Flash generations sit on the same promotion at the same rate,
        # and each still names its own generation in the cost source.
        for model in ("gemini-3.7-flash", "gemini-3.6-flash"):
            flash = benchmark._pricing_rates("gemini", model)
            self.assertEqual(str(flash["input"]), "0.75")
            self.assertEqual(str(flash["cache_read"]), "0.075")
            self.assertEqual(str(flash["output"]), "3.75")
            self.assertEqual(
                flash["source"],
                f"gemini-api-{model.removeprefix('gemini-').removesuffix('-flash')}"
                "-flash-standard",
            )

        long_context = (
            ("gpt-5.6-sol", "8", "0.80", "10", "30"),
            ("gpt-5.6-terra", "4", "0.40", "5", "18"),
            ("gpt-5.6-luna", "0.40", "0.04", "0.50", "1.80"),
            ("gpt-5.5", "10", "1", None, "45"),
            ("gpt-5.5-pro", "60", "0", None, "270"),
        )
        for model, input_high, cache_high, write_high, output_high in long_context:
            with self.subTest(model=model, tier="long-context"):
                rates = benchmark._pricing_rates("codex", model)
                self.assertEqual(str(rates["input_high"]), input_high)
                self.assertEqual(str(rates["cache_read_high"]), cache_high)
                self.assertEqual(str(rates["output_high"]), output_high)
                if write_high is None:
                    self.assertNotIn("cache_write_high", rates)
                else:
                    self.assertEqual(str(rates["cache_write_high"]), write_high)

        claude_cache = (
            ("claude-fable-5", "12.50", "20"),
            ("claude-opus-5", "6.25", "10"),
            ("claude-opus-4-8", "6.25", "10"),
            ("claude-sonnet-5", "2.50", "4"),
            ("claude-sonnet-4-6", "3.75", "6"),
            ("claude-haiku-4-5", "1.25", "2"),
            ("claude-3-5-haiku", "1", "1.60"),
            ("claude-3-haiku", "0.30", "0.50"),
        )
        for model, write_5m, write_1h in claude_cache:
            with self.subTest(model=model, tier="cache-write"):
                rates = benchmark._pricing_rates("claude", model)
                self.assertEqual(str(rates["cache_write"]), write_5m)
                self.assertEqual(str(rates["cache_write_1h"]), write_1h)

    def test_tiered_cache_writes_estimates_and_corrupt_rows_price_safely(self) -> None:
        # GPT-5.6 cache writes cost 1.25x uncached input. The normalized input
        # bucket contains writes, so pricing must split them back out.
        cost, source = benchmark._cost_decimal(
            "codex", "gpt-5.6-terra",
            input_tokens=1_000_000,
            cached_input_tokens=1_000_000,
            cache_creation_tokens=400_000,
            output_tokens=1_000_000,
            prompt_tokens_for_tier=200_000,
        )
        self.assertEqual(benchmark._decimal_text(cost), "14.400000")
        self.assertEqual(source, "openai-api-gpt-5.6-terra-standard")

        # Claude splits cache writes by TTL: 1.25x base for 5m, 2x for 1h.
        # A prompt far past 200k does not change the rate — no Sonnet carries a
        # long-context premium any more.
        claude_cache_ttl, _ = benchmark._cost_decimal(
            "claude", "claude-sonnet-4-5",
            input_tokens=1_000_000,
            cached_input_tokens=1_000_000,
            cache_creation_tokens=400_000,
            cache_creation_1h_tokens=200_000,
            output_tokens=1_000_000,
            prompt_tokens_for_tier=1_400_000,
        )
        self.assertEqual(benchmark._decimal_text(claude_cache_ttl), "19.050000")

        gemini_long, _ = benchmark._cost_decimal(
            "gemini", "gemini-2.5-pro",
            input_tokens=1_000_000, cached_input_tokens=1_000_000,
            output_tokens=1_000_000, prompt_tokens_for_tier=200_001,
        )
        self.assertEqual(benchmark._decimal_text(gemini_long), "17.750000")

        # Google's low tier is "<= 200k" and xAI's is "< 200k", so the same
        # 200k threshold bills low here and high for grok just below.
        gemini_at_boundary, _ = benchmark._cost_decimal(
            "gemini", "gemini-2.5-pro",
            input_tokens=1_000_000, cached_input_tokens=1_000_000,
            output_tokens=1_000_000, prompt_tokens_for_tier=200_000,
        )
        self.assertEqual(benchmark._decimal_text(gemini_at_boundary), "11.375000")

        grok_standard, _ = benchmark._cost_decimal(
            "grok", "grok-4.5",
            input_tokens=1_000_000, cached_input_tokens=1_000_000,
            output_tokens=1_000_000, prompt_tokens_for_tier=199_999,
        )
        self.assertEqual(benchmark._decimal_text(grok_standard), "8.300000")

        grok_long, _ = benchmark._cost_decimal(
            "grok", "grok-4.5",
            input_tokens=1_000_000, cached_input_tokens=1_000_000,
            output_tokens=1_000_000, prompt_tokens_for_tier=200_000,
        )
        self.assertEqual(benchmark._decimal_text(grok_long), "16.600000")

        # Vendor thresholds are per request. Harness rows retain the rendered
        # prompt size, so cumulative session input must not force the high tier.
        index = self.root / "tier-boundary.jsonl"
        index.write_text(json.dumps({
            "backend": "gemini", "model": "gemini-2.5-pro",
            "prompt_chars": 800_000,
            "tokens": {"input": 1_000_000, "output": 1_000_000},
        }) + "\n")
        at_boundary = benchmark.harvest_tokens(index)
        self.assertEqual(at_boundary["cost_usd"], "11.250000")
        self.assertTrue(at_boundary["cost_estimated"])
        index.write_text(json.dumps({
            "backend": "gemini", "model": "gemini-2.5-pro",
            "prompt_chars": 800_001,
            "tokens": {"input": 1_000_000, "output": 1_000_000},
        }) + "\n")
        over_boundary = benchmark.harvest_tokens(index)
        self.assertEqual(over_boundary["cost_usd"], "17.500000")
        self.assertTrue(over_boundary["cost_estimated"])

        index.write_text(json.dumps({
            "backend": "gemini", "model": "gemini-2.5-pro",
            "prompt_chars": 800_001, "cost_usd": 9.25,
            "cost_source": "backend-reported",
            "tokens": {"input": 1_000_000, "output": 1_000_000},
        }) + "\n")
        reported = benchmark.harvest_tokens(index)
        self.assertEqual(reported["cost_usd"], "9.250000")
        self.assertFalse(reported["cost_estimated"])

        index = self.root / "estimated.jsonl"
        index.write_text(json.dumps({
            "backend": "grok", "model": "grok-build-0.1", "estimated": True,
            "tokens": {"input": 0, "prompt_estimate": 1000, "output": 1000},
        }) + "\n")
        estimated = benchmark.harvest_tokens(index)
        self.assertEqual(estimated["cost_usd"], "0.003000")
        self.assertTrue(estimated["estimated"])

        # JSONL is durable shared state: syntactically valid but malformed
        # values must not crash a live report or create negative/NaN totals.
        index.write_text(
            "[]\n"
            + json.dumps({"backend": "grok", "model": "grok-build-0.1", "tokens": []}) + "\n"
            + json.dumps({
                "backend": "grok", "model": "grok-build-0.1",
                "cost_usd": "NaN", "tokens": {"input": -3, "output": 1e999},
            }) + "\n"
        )
        corrupt = benchmark.harvest_tokens(index)
        self.assertEqual(corrupt["input_tokens"], 0)
        self.assertEqual(corrupt["output_tokens"], 0)
        self.assertEqual(corrupt["cost_usd"], "0.000000")
        self.assertEqual(benchmark._fmt_usd("NaN"), "—")
        self.assertEqual(benchmark._fmt_usd("Infinity"), "—")
        self.assertEqual(
            benchmark._sum_cost_usd([
                {"cost_usd": "NaN"}, {"cost_usd": "Infinity"},
                {"cost_usd": "1.25"},
            ]),
            "1.250000",
        )

        cell = {
            "condition": "harness", "status": "done",
            "wall_seconds": "not-a-number",
            "metrics": {"tokens": {
                "input_tokens": -1, "output_tokens": float("inf"),
                "usage_records": "broken",
            }},
        }
        token_row = benchmark._tokens_for_cell(cell)
        self.assertEqual(token_row["input_tokens"], 0)
        self.assertEqual(token_row["output_tokens"], 0)
        self.assertEqual(token_row["wall_seconds"], 0)
        self.assertEqual(token_row["usage_records"], 0)

    def test_configured_default_models_have_pricing(self) -> None:
        # Every backend default in config/models.toml must key a pricing row.
        # Backends without a backend-reported cost (codex/gemini/grok) render a
        # blank dollar column when the table lacks their model, so a model bump
        # that skips the table degrades silently — this pins the two together.
        for backend in ("claude", "codex", "gemini", "grok"):
            model = llm_invoke.default_model(backend)
            self.assertTrue(model, f"{backend} has no configured default model")
            self.assertIsNotNone(
                benchmark._pricing_rates(backend, model),
                f"no pricing row for {backend} default model {model!r}",
            )

    def test_usage_extraction_for_supported_backend_shapes(self) -> None:
        cases = (
            ("codex", [
                {"type": "item.completed", "usage": {"input_tokens": 2000, "cached_input_tokens": 1800, "cache_write_tokens": 100, "output_tokens": 90}},
            ], (2000, 1800, 100, 90)),
            ("oss", [
                {"type": "step_finish", "part": {"type": "step-finish", "tokens": {"input": 1200, "output": 34, "cache": {"read": 900, "write": 25}}}},
            ], (1200, 900, 25, 34)),
            ("claude", [
                {"type": "assistant", "message": {"usage": {"input_tokens": 5, "output_tokens": 7}}},
                {"type": "result", "usage": {"input_tokens": 50, "cache_read_input_tokens": 40, "cache_creation_input_tokens": 15, "output_tokens": 12}},
            ], (50, 40, 15, 12)),
            ("gemini", [
                {"type": "result", "stats": {"input_tokens": 58000000, "output_tokens": 80, "cached": 55000000}},
            ], (58000000, 55000000, 0, 80)),
            ("grok", [
                {"type": "response.completed", "usage": {
                    "input_tokens": 5000, "output_tokens": 60,
                    "input_tokens_details": {
                        "cached_tokens": 4000, "cache_write_tokens": 250,
                    },
                }},
            ], (5000, 4000, 250, 60)),
        )
        for backend, rows, expected in cases:
            with self.subTest(backend=backend):
                path = self.root / f"{backend}.log"
                path.write_text("".join(json.dumps(row) + "\n" for row in rows))
                usage = llm_usage.extract_usage(str(path), backend=backend)
                tokens = usage["tokens"]
                self.assertEqual(
                    (tokens["input"], tokens["cached_input"], tokens["cache_creation"], tokens["output"]),
                    expected,
                )
        self.assertEqual(
            llm_usage.extract_usage(str(self.root / "missing.log"), backend="codex")["tokens"]["input"],
            0,
        )

    def test_aggregate_excludes_incomplete_cells_and_keeps_observed_counts(self) -> None:
        bench = self.root / "bench"
        self.write_json(bench / "run.json", {
            "runid": "run1", "target": "sample", "backend": "codex",
            "replicates": 2, "budget_wall": 60,
            "conditions": ["model-direct", "harness"],
            "target_sha": "abc", "harness_sha": "def",
        })
        self.make_cell(bench, "model-direct-r1", "model-direct", 1, 0, rejected_findings=2, refusals=1)
        self.make_cell(bench, "model-direct-r2", "model-direct", 2, 0)
        self.make_cell(bench, "harness-r1", "harness", 1, 3, findings=2, refusals=2)
        self.make_cell(bench, "harness-r2", "harness", 2, 1, findings=1)
        aggregate = benchmark.aggregate(bench)
        by_condition = {row["condition"]: row for row in aggregate["conditions"]}
        harness = by_condition["harness"]
        self.assertEqual(harness["crashes"], [3, 1])
        self.assertEqual(harness["crash_total"], 4)
        self.assertEqual(harness["crash_median"], 2)
        self.assertEqual(harness["confirmed_finding_total"], 3)
        self.assertEqual(harness["model_refusal_total"], 2)
        self.assertEqual(
            harness["validation_waterfall"]["crashes"]["candidates"], 4,
        )
        self.assertEqual(
            harness["validation_waterfall"]["findings"]["lanes"]["reportable"],
            3,
        )
        self.assertEqual(by_condition["model-direct"]["rejected_finding_total"], 2)

        failed = self.make_cell(bench, "harness-r3", "harness", 3, 0, status="failed")
        (failed / "metrics.json").unlink()
        self.make_cell(bench, "harness-r4", "harness", 4, 6, status="incomplete", findings=5)
        updated = {row["condition"]: row for row in benchmark.aggregate(bench)["conditions"]}["harness"]
        self.assertEqual(updated["replicates_total"], 4)
        self.assertEqual(updated["replicates_done"], 2)
        self.assertEqual(updated["crash_total"], 4)
        self.assertEqual(updated["incomplete_observed"][0]["crashes"], 6)
        self.assertEqual(updated["incomplete_observed"][0]["findings"], 5)

    def test_finding_class_concentration_counts_unique_clusters(self) -> None:
        """Duplicate reports cannot inflate the class count beside a unique count."""
        bench = self.root / "finding-class-clusters"
        self.write_json(bench / "run.json", {
            "runid": "run1", "target": "sample", "backend": "codex",
            "replicates": 1, "budget_wall": 60,
            "conditions": ["harness"],
            "target_sha": "abc", "harness_sha": "def",
        })
        self.make_cell(
            bench, "harness-r1", "harness", 1, 0, findings=4,
        )
        finding_members = {
            "FIND-dos-a": "harness",
            "FIND-dos-b": "harness",
            "FIND-dos-c": "harness",
            "FIND-auth": "harness",
        }
        self.write_json(bench / "pool-members.json", {
            "crashes": {}, "crash_cells": {},
            "crashes-rejected": {}, "findings-rejected": {},
            "findings": finding_members,
        })
        self.write_json(bench / "clusters-findings.json", {
            "clusters": [
                {
                    "id": "FINDING-dos", "class": "dos",
                    "members": ["FIND-dos-a", "FIND-dos-b", "FIND-dos-c"],
                },
                {
                    "id": "FINDING-auth", "class": "auth",
                    "members": ["FIND-auth"],
                },
            ],
        })
        for name in finding_members:
            finding = bench / "pool" / "findings" / name
            finding.mkdir(parents=True)
            klass = "auth" if name == "FIND-auth" else "dos"
            self.write_json(finding / ".llm-find-quality.json", {
                "accept": True, "class": klass,
            })

        condition = benchmark.aggregate(bench)["conditions"][0]

        self.assertEqual(condition["unique_finding_clusters"], 2)
        self.assertEqual(
            condition["finding_class_histogram"], {"auth": 1, "dos": 1},
        )
        self.assertEqual(condition["unique_finding_classes"], 2)
        self.assertNotIn("top_finding_class", condition)
        self.assertEqual(
            sum(condition["finding_class_histogram"].values()),
            condition["unique_finding_clusters"],
        )

        (bench / "clusters-findings.json").unlink()
        unclustered = benchmark.aggregate(bench)["conditions"][0]
        self.assertEqual(unclustered["finding_class_histogram"], {})
        self.assertEqual(unclustered["unique_finding_classes"], 0)

    def test_renderers_require_a_complete_cluster_class_histogram(self) -> None:
        """Legacy occurrence shares must not label a unique-cluster count."""
        run = self.root / "class-render" / "codex" / "run1"
        condition = {
            "condition": "harness",
            "replicates_done": 1,
            "replicates_total": 1,
            "wall_median": 60,
            "unique_finding_clusters": 2,
            "medium_plus_findings": 0,
            # These legacy scalars came from four report directories: three
            # duplicate dos reports and one auth report.
            "unique_finding_classes": 2,
            "top_finding_class": "dos",
            "top_finding_class_pct": 75,
            "unique_crash_clusters": 0,
            "medium_plus_bugs": 0,
            "top_severity_level": "—",
            "tokens": {},
            "validation_waterfall": {
                "crashes": {"candidates": 0, "lanes": {}},
                "findings": {"candidates": 2, "lanes": {"reportable": 2}},
            },
        }
        report = {
            "run": {
                "runid": "run1", "target": "sample", "backend": "codex",
                "model": "gpt-test", "replicates": 1, "budget_wall": 60,
            },
            "bench_dir": str(run),
            "conditions": [condition],
            "crash_clusters": [],
        }
        self.write_json(run / "report.json", report)

        legacy_section = benchmark.render_section(report)
        legacy_crosstab = benchmark.crosstab(self.root / "class-render")
        self.assertIn("2 (0 M+)", legacy_section)
        self.assertIn("2 (0 M+)", legacy_crosstab)
        self.assertNotIn("75% dos", legacy_section)
        self.assertNotIn("75% dos", legacy_crosstab)

        condition["finding_class_histogram"] = {"auth": 1, "dos": 1}
        self.write_json(run / "report.json", report)
        current_section = benchmark.render_section(report)
        current_crosstab = benchmark.crosstab(self.root / "class-render")
        self.assertIn("2 (0 M+, 2 classes)", current_section)
        self.assertIn("2 (0 M+, 2 classes)", current_crosstab)
        self.assertNotIn("% dos", current_section)
        self.assertNotIn("% dos", current_crosstab)

        condition["finding_class_histogram"] = {"dos": 3}
        self.assertNotIn("class", benchmark.render_section(report))

    def _finding(self, findings: Path, name: str, file: str, func: str) -> None:
        directory = findings / name
        directory.mkdir(parents=True)
        (directory / "report.md").write_text(
            "## Fields\n\n"
            f"| File | `{file}` |\n"
            f"| Function | `{func}` |\n",
            encoding="utf-8",
        )
        validation_receipt.write(
            directory, kind="finding", state="reportable",
            attacker_controls=["bytes"],
        )

    def test_a_finding_does_not_credit_a_bug_planted_in_another_file(self) -> None:
        """Same function name, different file, is not the same bug.

        The oracle matched on the fault function alone, so a finding at
        a.c:parse credited a planted bug at b.c:parse. An entry that pins its
        file is now held to it.
        """
        findings = self.root / "oracle" / "findings"
        self._finding(findings, "FIND-0001", "src/b.c", "parse")
        manifest = {"planted_bugs": [{
            "id": "planted-in-a", "kind": "real", "primitive": "dos",
            "signature_symbol": "parse", "file": "src/a.c",
            "findings_only": True,
        }]}
        scored = benchmark.score_findings_ground_truth(findings, manifest)
        self.assertEqual(scored["overall"]["detected"], [])
        self.assertEqual(scored["overall"]["missed"], ["planted-in-a"])
        # Not a precision failure either — it is simply someone else's bug.
        self.assertEqual(scored["overall"]["open_world_findings"], ["FIND-0001"])

        # The same finding against the file it really is in still counts.
        manifest["planted_bugs"][0]["file"] = "src/b.c"
        scored = benchmark.score_findings_ground_truth(findings, manifest)
        self.assertEqual(scored["overall"]["detected"], ["planted-in-a"])

    def test_a_basename_only_report_still_matches_a_pinned_path(self) -> None:
        """The extractor yields a bare basename when nothing richer is there.

        Comparing basenames is the best either side can support then, so it
        must not cost a real detection. A report that names no file at all is
        a different case: with no identity evidence it is unattributed.
        """
        findings = self.root / "oracle-shapes" / "findings"
        self._finding(findings, "FIND-0001", "chtio.c", "cht_read")
        manifest = {"planted_bugs": [{
            "id": "pinned", "kind": "real", "primitive": "double-free",
            "signature_symbol": "cht_read", "file": "src/chtio.c",
            "findings_only": True,
        }]}
        scored = benchmark.score_findings_ground_truth(findings, manifest)
        self.assertEqual(scored["overall"]["detected"], ["pinned"], "basename must match a path")

        fileless = self.root / "oracle-fileless" / "findings"
        directory = fileless / "FIND-0001"
        directory.mkdir(parents=True)
        (directory / "report.md").write_text(
            "## Fields\n\n| Function | `cht_read` |\n", encoding="utf-8")
        validation_receipt.write(
            directory, kind="finding", state="reportable",
            attacker_controls=["bytes"],
        )
        scored = benchmark.score_findings_ground_truth(fileless, manifest)
        self.assertEqual(scored["overall"]["detected"], [])
        self.assertEqual(
            scored["overall"]["open_world_findings"], ["FIND-0001"],
            "a report that locates nothing is unattributed, not credited",
        )
        # Unattributed is not a precision failure either.
        self.assertEqual(scored["overall"]["false_positive_findings"], 0)

    def test_same_basename_in_another_directory_is_a_different_file(self) -> None:
        """Two qualified paths are compared whole: that is the point."""
        findings = self.root / "oracle-dirs" / "findings"
        self._finding(findings, "FIND-0001", "src/b/parse.c", "parse")
        manifest = {"planted_bugs": [{
            "id": "in-a", "kind": "real", "primitive": "dos",
            "signature_symbol": "parse", "file": "src/a/parse.c",
            "findings_only": True,
        }]}
        scored = benchmark.score_findings_ground_truth(findings, manifest)
        self.assertEqual(scored["overall"]["detected"], [])

    def test_two_bugs_sharing_a_symbol_in_different_files_are_distinct(self) -> None:
        """Pinning a file makes them separate entries, not a collision."""
        distinct = {"planted_bugs": [
            {"id": "a", "kind": "real", "primitive": "dos",
             "signature_symbol": "parse", "file": "src/a.c"},
            {"id": "b", "kind": "real", "primitive": "dos",
             "signature_symbol": "parse", "file": "src/b.c"},
        ]}
        self.assertEqual(benchmark.manifest_errors(distinct), [])
        # Without files they could be the same site, so they still collide.
        for bug in distinct["planted_bugs"]:
            bug.pop("file")
        self.assertTrue(benchmark.manifest_errors(distinct))









    def _scored_run(self, name: str, versions: dict[str, str]) -> tuple[Path, dict]:
        """A run whose pooled findings carry the given scorer versions."""
        run = self.root / name / "codex" / "run1"
        for artifact, version in versions.items():
            self.write_json(
                run / "pool" / "findings" / artifact / "severity.json",
                {"level": "Medium", "score": 4.6, "scorer_version": version},
            )
        condition = {
            "condition": "harness",
            "replicates_done": 1, "replicates_total": 1, "wall_median": 60,
            "unique_finding_clusters": 1, "medium_plus_findings": 1,
            "unique_crash_clusters": 0, "medium_plus_bugs": 0,
            "top_severity_level": "—", "tokens": {},
            "validation_waterfall": {
                "crashes": {"candidates": 0, "lanes": {}},
                "findings": {"candidates": 1, "lanes": {"reportable": 1}},
            },
        }
        report = {
            "run": {
                "runid": "run1", "target": "sample", "backend": "codex",
                "model": "gpt-test", "replicates": 1, "budget_wall": 60,
            },
            "bench_dir": str(run),
            "conditions": [condition],
            "crash_clusters": [],
        }
        self.write_json(run / "report.json", report)
        return run, report

    def test_a_row_scored_by_a_superseded_scorer_says_so(self) -> None:
        """M+ from another scorer is a different scale, and must not read as one.

        The page accumulates rows for months. When the scoring rules change,
        the same artifacts yield a different M+, so an unlabelled old row
        invites a comparison that is not valid.
        """
        run, report = self._scored_run("stale-scorer", {"FIND-0001": "severity-v0-ancient"})
        rendered = benchmark.crosstab(self.root / "stale-scorer")
        self.assertIn("‡", rendered)
        self.assertIn("severity-v0-ancient", rendered)
        self.assertIn(severity_receipt.SCORER_DECISION_VERSION, rendered)
        self.assertIn("not on the same scale", rendered)
        # The per-run page carries the same warning in its own words.
        self.assertIn("severity-v0-ancient", benchmark.render_section(report))

    def test_a_row_scored_by_the_current_scorer_carries_no_mark(self) -> None:
        """Silence is the common case; a mark on every row would say nothing."""
        run, report = self._scored_run(
            "current-scorer",
            {"FIND-0001": severity_receipt.SCORER_DECISION_VERSION},
        )
        rendered = benchmark.crosstab(self.root / "current-scorer")
        self.assertNotIn("‡", rendered)
        self.assertNotIn("not on the same scale", rendered)
        self.assertNotIn("not on the same scale", benchmark.render_section(report))

    def test_scorer_versions_come_from_the_receipts_not_the_report(self) -> None:
        """A report written before the field existed still has its receipts.

        Reading the pool is what makes the mark appear on runs that predate
        the record; a run with no pool at all stays silent rather than
        guessing a scale it cannot know.
        """
        run, report = self._scored_run(
            "receipt-scan",
            {"FIND-0001": "severity-v0-ancient", "FIND-0002": "severity-v0-ancient"},
        )
        self.assertEqual(
            benchmark.severity_scorer_versions(run), ["severity-v0-ancient"],
        )
        # A receipt that cannot name its scorer reads as unknown, never as
        # the current one: silence there would let the row pass as current.
        (run / "pool" / "findings" / "FIND-0003").mkdir(parents=True)
        (run / "pool" / "findings" / "FIND-0003" / "severity.json").write_text("{not json")
        self.write_json(run / "pool" / "findings" / "FIND-0004" / "severity.json", {"level": "Low"})
        self.assertEqual(
            benchmark.severity_scorer_versions(run),
            ["severity-v0-ancient", benchmark.UNKNOWN_SCORER],
        )
        self.assertIn(
            benchmark.UNKNOWN_SCORER,
            benchmark._outdated_scorers({}, run),
            "an unnameable scorer must not read as the current one",
        )
        self.assertEqual(benchmark.severity_scorer_versions(self.root / "nope"), [])
        # No report field and no pool: nothing is claimed either way.
        self.assertEqual(benchmark._outdated_scorers({}, None), [])

    def test_finding_cluster_class_is_condition_local_and_missing_is_other(self) -> None:
        attributed = benchmark.attribute_clusters(
            {
                "clusters": [
                    {
                        "id": "FINDING-shared", "class": "auth",
                        "members": ["FIND-harness", "FIND-direct"],
                    },
                    {
                        "id": "FINDING-unlabelled",
                        "members": ["FIND-harness-other"],
                    },
                ],
            },
            {
                "FIND-harness": "harness",
                "FIND-direct": "model-direct",
                "FIND-harness-other": "harness",
            },
        )["by_condition"]

        self.assertEqual(
            attributed["harness"]["class_histogram"],
            {"auth": 1, "other": 1},
        )
        self.assertEqual(
            attributed["model-direct"]["class_histogram"], {"auth": 1},
        )

    def test_aggregate_and_report_surface_unadjudicated_crashes(self) -> None:
        bench = self.root / "unjudged-crashes"
        self.write_json(bench / "run.json", {
            "runid": "run1", "target": "sample", "backend": "codex",
            "replicates": 1, "budget_wall": 60,
            "conditions": ["model-direct"],
            "target_sha": "abc", "harness_sha": "def",
        })
        self.make_cell(
            bench, "model-direct-r1", "model-direct", 1, 0,
            unadjudicated_crashes=2,
        )
        report = benchmark.aggregate(bench)
        condition = report["conditions"][0]
        self.assertEqual(condition["unadjudicated_crash_total"], 2)
        self.assertTrue(condition["crash_total_is_floor"])
        self.assertIn("2 unjudged", benchmark.render_section(report))

    def test_aggregate_and_report_surface_retained_crashes(self) -> None:
        """Out-of-scope reproduced crashes are counted beside the credit.

        On a bytes-only target a condition that reproduced eight real defects
        through caller call sequences read exactly like one that reproduced
        none: they are finalized `not-reportable`, never pooled, and the cell
        showed a bare `0`.
        """
        bench = self.root / "retained-crashes"
        self.write_json(bench / "run.json", {
            "runid": "run1", "target": "sample", "backend": "codex",
            "replicates": 1, "budget_wall": 60,
            "conditions": ["model-direct"],
            "target_sha": "abc", "harness_sha": "def",
        })
        self.make_cell(
            bench, "model-direct-r1", "model-direct", 1, 0, retained_crashes=8,
        )
        report = benchmark.aggregate(bench)
        condition = report["conditions"][0]
        self.assertEqual(condition["retained_crash_total"], 8)
        self.assertEqual(condition["crash_total"], 0)
        self.assertFalse(condition["crash_total_is_floor"])
        self.assertIn("0 (8 retained)", benchmark.render_section(report))
        self.assertEqual("0", benchmark._unique_with_medium_plus(0, 0))
        self.assertEqual(
            "2 (1 M+, 6 retained)",
            benchmark._unique_with_medium_plus(2, 1, retained=6),
        )
        self.assertEqual(
            "≥2 (1 M+, 3 unjudged, 6 retained)",
            benchmark._unique_with_medium_plus(2, 1, 3, floor=True, retained=6),
        )

    def test_wall_is_also_reported_as_worker_capacity(self) -> None:
        """Equal wall is not equal effort across conditions.

        The harness works several agents concurrently inside one cell while
        model-direct is a single session by contract, so wall alone credits
        the harness with work it bought by adding seats. This is capacity —
        seats times time — and an upper bound on effort. A harness cell that
        recorded no seat count is a gap, not a single agent, and reporting a
        median over just the cells that did record one would describe fewer
        repeats than the row claims, so the whole column goes blank instead.
        Only model-direct's absent count is knowledge: it is one by contract.
        """
        bench = self.root / "bench-worker-hours"
        self.write_json(bench / "run.json", {
            "runid": "run1", "target": "sample", "backend": "codex",
            "replicates": 1, "budget_wall": 60,
            "conditions": ["model-direct", "harness"],
            "target_sha": "abc", "harness_sha": "def",
        })
        self.make_cell(bench, "model-direct-r1", "model-direct", 1, 0)
        self.make_cell(bench, "harness-r1", "harness", 1, 1, actual_agents=3)
        by_condition = {
            row["condition"]: row
            for row in benchmark.aggregate(bench)["conditions"]
        }

        self.assertEqual(by_condition["harness"]["wall_median"], 42)
        self.assertEqual(by_condition["harness"]["worker_wall_median"], 126)
        self.assertEqual(by_condition["model-direct"]["wall_median"], 42)
        self.assertEqual(by_condition["model-direct"]["worker_wall_median"], 42)

        # One unrecorded harness seat count blanks the column rather than
        # publishing a median that silently covers one of two repeats.
        self.make_cell(bench, "harness-r2", "harness", 2, 1)
        unrecorded = {
            row["condition"]: row
            for row in benchmark.aggregate(bench)["conditions"]
        }["harness"]
        self.assertEqual(unrecorded["replicates_done"], 2)
        self.assertEqual(unrecorded["wall_median"], 42)
        self.assertIsNone(
            unrecorded["worker_wall_median"],
            "a partial sample must not be shown as the condition's capacity",
        )

    def test_ledger_replaces_same_run_and_reset_archives(self) -> None:
        bench = self.root / "bench-ledger"
        self.write_json(bench / "run.json", {
            "runid": "run1", "target": "sample", "backend": "codex",
            "conditions": ["harness"], "replicates": 1,
        })
        self.make_cell(bench, "harness-r1", "harness", 1, 1)
        ledger = self.root / "ledger.md"
        section = benchmark.render_section(benchmark.aggregate(bench))
        self.assertIn("### Security decisions", section)
        self.assertNotIn("Legacy provisional", section)
        self.assertNotIn("Reviewed root families", section)
        self.assertIn("| all conditions | crashes |", section)
        benchmark.append_to_ledger(ledger, section)
        benchmark.append_to_ledger(ledger, section)
        text = ledger.read_text()
        self.assertEqual(text.count("# Benchmark results"), 1)
        self.assertEqual(text.count("Benchmark run `run1`"), 1)

        archived = benchmark.reset_ledger(ledger)
        self.assertFalse(ledger.exists())
        self.assertIsNotNone(archived)
        self.assertTrue(Path(archived).is_file())
        ledger.write_text("temporary\n")
        self.assertIsNone(benchmark.reset_ledger(ledger, hard=True))
        self.assertFalse(ledger.exists())

    def test_unknown_token_source_marks_totals_with_one_marker(self) -> None:
        bench = self.root / "bench-unknown-tokens"
        self.write_json(bench / "run.json", {
            "runid": "run1", "target": "sample", "backend": "codex",
            "conditions": ["harness"], "replicates": 1,
        })
        cell = self.make_cell(bench, "harness-r1", "harness", 1, 1)
        metrics = json.loads((cell / "metrics.json").read_text())
        metrics["tokens"]["token_source"] = "unknown"
        self.write_json(cell / "metrics.json", metrics)

        section = benchmark.render_section(benchmark.aggregate(bench))
        self.assertIn("| unknown |", section)
        self.assertGreaterEqual(section.count("~111"), 2)
        # Token and cost figures carry at most one marker. `≥` keeps its one
        # meaning in this report — the unjudged artifact remainder — and must
        # never reach a token or cost number.
        self.assertNotIn("≥111", section)
        self.assertNotIn("≥~", section)
        self.assertNotIn("~~", section)
        self.assertIn("reads low", section)

    def test_estimated_cost_keeps_one_marker_when_a_session_is_also_missing(self) -> None:
        bench = self.root / "bench-estimated-and-unknown"
        self.write_json(bench / "run.json", {
            "runid": "run1", "target": "sample", "backend": "codex",
            "conditions": ["harness"], "replicates": 1,
        })
        cell = self.make_cell(bench, "harness-r1", "harness", 1, 1)
        metrics = json.loads((cell / "metrics.json").read_text())
        metrics["tokens"]["token_source"] = "unknown"
        metrics["tokens"]["cost_estimated"] = True
        metrics["tokens"]["cost_usd"] = "12.5"
        self.write_json(cell / "metrics.json", metrics)

        section = benchmark.render_section(benchmark.aggregate(bench))
        rows = [ln for ln in section.splitlines() if ln.startswith("|")]
        self.assertTrue(any("$12.5" in ln for ln in rows), rows)
        for row in rows:
            self.assertNotIn("~~", row)
            self.assertNotIn("≥", row, "no floor mark on a token or cost figure")

    def test_pool_and_split_preserve_condition_membership_and_rejections(self) -> None:
        bench = self.root / "pool-bench"
        self.write_json(bench / "run.json", {
            "runid": "pool", "target": "sample", "backend": "codex",
            "conditions": ["model-direct", "harness"], "replicates": 1,
        })
        for condition in ("model-direct", "harness"):
            results = self.root / f"results-{condition}"
            crash = results / "crashes" / "CRASH-001"
            finding = results / "findings" / "FIND-001"
            rejected = results / "findings-rejected" / "FIND-REJECTED"
            rejected_crash = results / "crashes-rejected" / "CRASH-OLD"
            crash.mkdir(parents=True)
            finding.mkdir(parents=True)
            rejected.mkdir(parents=True)
            rejected_crash.mkdir(parents=True)
            (crash / "sanitizer.txt").write_text(
                ASAN + f"workspace: {Path.home() / 'work' / 'sample.c'}\n"
            )
            (crash / "report.md").write_text(
                f"# {condition} crash\n\n"
                "Surface: file-format\n"
                "Primitive: out_of_bounds_read\n"
                "Class: memory-safety\n"
                "Caller contract: obeyed\n"
                "Caller controls: bytes\n"
                "Trigger source: bytes\n"
                "Parameter control: direct\n"
                "Trusted caller actions: normal public call\n"
                "Boundary: public parser\n"
                "Advisory: no\n"
            )
            self.finalize_fixture_crash(crash)
            (finding / "report.md").write_text(
                f"# {condition} finding\n\n"
                f"workspace: {Path.home() / 'work' / 'sample.c'}\n"
            )
            (finding / ".keep").touch()
            self.finalize_fixture_finding(finding)
            self.assertIsNotNone(validation_receipt.read_current(crash))
            self.assertIsNotNone(validation_receipt.read_current(finding))
            (rejected / "report.md").write_text("# rejected\n")
            (rejected_crash / "REPORT.md").write_text("# Rejected crash\n")
            (results / "crashes-rejected" / "REJECTED-CRASHES.md").write_text(
                "# Rejected crashes\n\n## Rejected crash directories\n\n"
                "| ID | Site | Reason | Report |\n|:--|:--|:--|:--|\n"
                "| `CRASH-OLD` | app_parse app.c:91 | rejected | "
                "[Link](CRASH-OLD/REPORT.md) |\n"
            )
            cell = self.make_cell(bench, f"{condition}-r1", condition, 1, 1, findings=1, rejected_findings=1)
            data = json.loads((cell / "cell.json").read_text())
            data["results_dir"] = str(results)
            self.write_json(cell / "cell.json", data)
            metrics = benchmark.harvest(results)
            self.write_json(cell / "metrics.json", metrics)

        pooled = benchmark.build_pool(bench)
        self.assertEqual(len(pooled["crashes"]), 2)
        self.assertEqual(len(pooled["findings"]), 2)
        for directory in (
            *sorted((bench / "pool" / "crashes").glob("CRASH-*")),
            *sorted((bench / "pool" / "findings").glob("FIND-*")),
        ):
            self.assertIsNotNone(validation_receipt.read_current(directory))
            self.assertNotIn(
                str(Path.home() / "work"),
                "\n".join(
                    path.read_text(encoding="utf-8", errors="replace")
                    for path in directory.iterdir()
                    if path.is_file()
                ),
            )
        for directory in sorted((bench / "pool" / "crashes").glob("CRASH-*")):
            completed = subprocess.run(
                [
                    sys.executable, str(ROOT / "bin" / "severity"),
                    "--report", str(directory),
                ],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertTrue((directory / "severity.json").is_file())
            self.assertIsNotNone(validation_receipt.read_current(directory))
        self.assertFalse(any(
            (bench / "pool" / "crashes-rejected").glob("CELL-REJECTIONS-*.md")
        ))
        members = json.loads((bench / "pool-members.json").read_text())
        self.assertEqual(set(members["crashes"].values()), {"model-direct", "harness"})
        split = benchmark.split_pool(bench)
        self.assertEqual(split["model-direct"], 4)
        self.assertEqual(split["harness"], 4)
        for condition in ("model-direct", "harness"):
            condition_pool = bench / "pool" / condition
            self.assertEqual(len(list((condition_pool / "crashes").glob("CRASH-*"))), 1)
            self.assertEqual(len(list((condition_pool / "findings").glob("FIND-*"))), 1)
            self.assertTrue((condition_pool / "findings-rejected" / "REJECTED-FINDINGS.md").is_file())
            for directory in (
                *condition_pool.joinpath("crashes").glob("CRASH-*"),
                *condition_pool.joinpath("findings").glob("FIND-*"),
            ):
                self.assertIsNotNone(validation_receipt.read_current(directory))

    def test_pool_scrub_rebinds_source_attestation_without_checkout(self) -> None:
        bench = self.root / "attested-pool"
        self.write_json(bench / "run.json", {
            "runid": "attested", "target": "sample", "backend": "codex",
            "conditions": ["harness"], "replicates": 1,
        })
        target = self.root / "target"
        source = target / "src" / "sample.c"
        source.parent.mkdir(parents=True)
        local_build_root = str(Path.home() / "work" / "private" / "build")
        excerpt = f'const char *build_root = "{local_build_root}";'
        source.write_text(
            "int app_parse(void) {\n"
            f"  {excerpt}\n"
            "}\n",
            encoding="utf-8",
        )
        unrelated = self.root / "unrelated-target"
        unrelated_source = unrelated / "src" / "sample.c"
        unrelated_source.parent.mkdir(parents=True)
        unrelated_source.write_text(
            "int other_parse(void) { return 0; }\n",
            encoding="utf-8",
        )
        results = self.root / "attested-results"
        finding = results / "findings" / "FIND-001"
        finding.mkdir(parents=True)
        (finding / "report.md").write_text("# Bounds finding\n")
        review = finding / ".trigger-gate.json"
        local_metadata_key = str(
            Path.home() / "work" / "private" / "unverified-key.txt"
        )
        colliding_metadata_key = str(Path.home() / "work" / "path")
        self.write_json(review, {
            "vote": "Promote",
            "rationale": {
                "trace": str(
                    Path.home() / "work" / "private" / "trace.txt"
                ),
                "exact_home": str(Path.home()),
                "sentence_home": f"checkout was {Path.home()}.",
                "sibling": f"{Path.home()}-backup/source",
                "dot_sibling": f"{Path.home()}.backup/source",
                "comma_sibling": f"{Path.home()},backup/source",
                "colon_sibling": f"{Path.home()}:backup/source",
                "uri_fragment": f"{Path.home().as_uri()}#fragment",
                "uri_query": f"{Path.home().as_uri()}?view=1",
            },
            "anchors": [{
                "path": "src/sample.c", "line": 2,
                "symbol": "app_parse", "kind": "build",
                "excerpt": excerpt,
                local_metadata_key: "unverified metadata",
                colliding_metadata_key: "must not replace the source path",
            }],
        })
        shadow_path = str(
            Path.home() / "work" / "private" / "unverified.c"
        )
        review.write_text(
            review.read_text(encoding="utf-8").replace(
                '"path": "src/sample.c"',
                f'"path": {json.dumps(shadow_path)}, '
                '"path": "src/sample.c"',
                1,
            ),
            encoding="utf-8",
        )
        with mock.patch.dict(os.environ, {
            "TARGET_ROOT": str(target), "TARGET_REV": "",
        }):
            prior = validation_receipt.write(
                finding, kind="finding", state="reportable",
            )
        old_review_sha = prior["evidence"]["source_attestations"][0][
            "review_sha256"
        ]
        cell = self.make_cell(
            bench, "harness-r1", "harness", 1, 0, findings=1,
        )
        cell_data = json.loads((cell / "cell.json").read_text())
        cell_data["results_dir"] = str(results)
        self.write_json(cell / "cell.json", cell_data)
        self.write_json(cell / "metrics.json", benchmark.harvest(results))

        with mock.patch.dict(os.environ, {
            "TARGET_ROOT": str(unrelated), "TARGET_REV": "",
        }, clear=True):
            self.assertIsNotNone(validation_receipt.read_current(finding))
            benchmark.build_pool(bench)
            pooled = bench / "pool" / "findings" / "FIND-0001"
            unrelated_current = validation_receipt.read_current(pooled)

        with mock.patch.dict(os.environ, {
            "TARGET_ROOT": str(target), "TARGET_REV": "",
        }, clear=True):
            original_current = validation_receipt.read_current(pooled)

        self.assertIsNotNone(unrelated_current)
        self.assertIsNotNone(original_current)
        self.assertNotEqual(
            original_current["evidence"]["source_attestations"][0][
                "review_sha256"
            ],
            old_review_sha,
        )
        pooled_review = json.loads(
            (pooled / ".trigger-gate.json").read_text(encoding="utf-8"),
        )
        self.assertEqual(pooled_review["anchors"][0]["excerpt"], excerpt)
        self.assertEqual(
            pooled_review["anchors"][0]["path"], "src/sample.c",
        )
        self.assertNotIn(
            shadow_path,
            (pooled / ".trigger-gate.json").read_text(encoding="utf-8"),
        )
        self.assertNotIn(local_metadata_key, pooled_review["anchors"][0])
        self.assertNotIn(colliding_metadata_key, pooled_review["anchors"][0])
        self.assertEqual(pooled_review["rationale"]["exact_home"], "~")
        self.assertEqual(
            pooled_review["rationale"]["sentence_home"], "checkout was ~.",
        )
        self.assertEqual(
            pooled_review["rationale"]["sibling"],
            f"{Path.home()}-backup/source",
        )
        self.assertEqual(
            pooled_review["rationale"]["dot_sibling"],
            f"{Path.home()}.backup/source",
        )
        self.assertEqual(
            pooled_review["rationale"]["comma_sibling"],
            f"{Path.home()},backup/source",
        )
        self.assertEqual(
            pooled_review["rationale"]["colon_sibling"],
            f"{Path.home()}:backup/source",
        )
        self.assertEqual(
            pooled_review["rationale"]["uri_fragment"], "~#fragment",
        )
        self.assertEqual(
            pooled_review["rationale"]["uri_query"], "~?view=1",
        )
        self.assertNotIn(
            str(Path.home() / "work"),
            json.dumps(pooled_review["rationale"]),
        )

    def test_pool_rebuild_survives_concurrent_writer_during_stale_cleanup(self) -> None:
        # A leftover staging tree from an interrupted run must be cleared even
        # when a concurrent writer (Spotlight/Finder/an indexer) drops a file
        # into a directory the removal just emptied — the race that makes a
        # direct rmtree fail with ENOTEMPTY mid-walk.
        bench = self.root / "race-bench"
        self.write_json(bench / "run.json", {
            "runid": "race", "target": "sample", "backend": "codex",
            "conditions": ["harness"], "replicates": 1,
        })
        results = self.root / "race-results"
        finding = results / "findings" / "FIND-001"
        finding.mkdir(parents=True)
        (finding / "report.md").write_text("# finding\n")
        cell = self.make_cell(bench, "harness-r1", "harness", 1, 0, findings=1)
        data = json.loads((cell / "cell.json").read_text())
        data["results_dir"] = str(results)
        self.write_json(cell / "cell.json", data)
        self.write_json(cell / "metrics.json", benchmark.harvest(results))

        benchmark.build_pool(bench)
        self.assertTrue((bench / "pool").is_dir())

        # A skeleton a prior best-effort removal could not finish must be swept,
        # not accumulate across rebuilds.
        skeleton = bench / ".discard-pool-999999"
        (skeleton / "leftover").mkdir(parents=True)

        real_rmtree = shutil.rmtree

        def racing_rmtree(path, *rest, **kwargs):
            # Reproduce the traceback: a raw removal of the stale pool raises
            # ENOTEMPTY. Best-effort removals (ignore_errors) pass through.
            if Path(path) == bench / "pool" and not kwargs.get("ignore_errors"):
                raise OSError(errno.ENOTEMPTY, "Directory not empty", str(path))
            return real_rmtree(path, *rest, **kwargs)

        with mock.patch.object(shutil, "rmtree", racing_rmtree):
            benchmark.build_pool(bench)
        self.assertTrue((bench / "pool").is_dir())
        self.assertFalse(any(bench.glob(".discard-*")))

    def test_pool_excludes_validator_scratch_with_dangling_symlinks(self) -> None:
        # Older model-direct cells embedded the validator's .validator-cwd (a
        # symlink farm into the target tree) inside each finding dir. copytree
        # follows those symlinks and raises shutil.Error on a dangling one, so
        # pooling must skip the scratch entirely.
        bench = self.root / "scratch-bench"
        self.write_json(bench / "run.json", {
            "runid": "scratch", "target": "sample", "backend": "codex",
            "conditions": ["model-direct"], "replicates": 1,
        })
        results = self.root / "scratch-results"
        finding = results / "findings" / "FIND-1"
        finding.mkdir(parents=True)
        (finding / "report.md").write_text("# finding\n")
        (finding / ".keep").touch()
        self.finalize_fixture_finding(finding)
        scratch = finding / ".validator-cwd"
        scratch.mkdir()
        (scratch / "src").symlink_to(self.root / "does-not-exist")
        cell = self.make_cell(bench, "model-direct-r1", "model-direct", 1, 0, findings=1)
        data = json.loads((cell / "cell.json").read_text())
        data["results_dir"] = str(results)
        self.write_json(cell / "cell.json", data)
        self.write_json(cell / "metrics.json", benchmark.harvest(results))

        benchmark.build_pool(bench)

        pooled = bench / "pool" / "findings" / "FIND-0001"
        self.assertTrue((pooled / "report.md").is_file())
        self.assertFalse((pooled / ".validator-cwd").exists())

    def test_pool_survives_a_dangling_reproducer_symlink(self) -> None:
        # A finding can outlive a scratch file that an agent linked as its
        # reproducer. copytree resolves the dangling link, gets ENOENT and
        # raises shutil.Error — aborting the pool build after every cell has
        # already completed. Keep the finding, but do not treat the missing
        # scratch file as durable evidence.
        bench = self.root / "dangling-repro-bench"
        self.write_json(bench / "run.json", {
            "runid": "dangling", "target": "sample", "backend": "codex",
            "conditions": ["harness"], "replicates": 1,
        })
        results = self.root / "dangling-results"
        finding = results / "findings" / "FIND-1"
        finding.mkdir(parents=True)
        (finding / "report.md").write_text("# finding\n")
        (finding / ".keep").touch()
        (finding / "reproducer.xml").symlink_to("../../scratch-3/pruned.xml")
        self.finalize_fixture_finding(finding)
        cell = self.make_cell(bench, "harness-r1", "harness", 1, 0, findings=1)
        data = json.loads((cell / "cell.json").read_text())
        data["results_dir"] = str(results)
        self.write_json(cell / "cell.json", data)
        self.write_json(cell / "metrics.json", benchmark.harvest(results))

        warnings = io.StringIO()
        with redirect_stderr(warnings):
            benchmark.build_pool(bench)

        pooled = bench / "pool" / "findings" / "FIND-0001"
        self.assertTrue((pooled / "report.md").is_file())
        self.assertFalse((pooled / "reproducer.xml").exists())
        self.assertIn("symlink", warnings.getvalue())

    def test_pool_materialises_a_live_evidence_symlink(self) -> None:
        # copytree dereferences a live link, so the agent's link into scratch
        # lands in the pool as a regular file holding the real bytes — the
        # self-contained bundle every reproducer path (export-repro,
        # find-crash-testcase, the E:P evidence grade) depends on. Dropping it
        # would pool a finding stripped of its testcase, which is worse than
        # the dangling case this rule exists to survive.
        bench = self.root / "linked-repro-bench"
        self.write_json(bench / "run.json", {
            "runid": "linked", "target": "sample", "backend": "codex",
            "conditions": ["harness"], "replicates": 1,
        })
        results = self.root / "linked-results"
        finding = results / "findings" / "FIND-1"
        scratch = results / "scratch-1"
        finding.mkdir(parents=True)
        scratch.mkdir()
        (finding / "report.md").write_text("# finding\n")
        (finding / ".keep").touch()
        target = scratch / "testcase.xml"
        target.write_text("<r/>", encoding="utf-8")
        (finding / "reproducer.xml").symlink_to(target)
        self.finalize_fixture_finding(finding)
        cell = self.make_cell(bench, "harness-r1", "harness", 1, 0, findings=1)
        data = json.loads((cell / "cell.json").read_text())
        data["results_dir"] = str(results)
        self.write_json(cell / "cell.json", data)
        self.write_json(cell / "metrics.json", benchmark.harvest(results))

        warnings = io.StringIO()
        with redirect_stderr(warnings):
            benchmark.build_pool(bench)

        pooled = bench / "pool" / "findings" / "FIND-0001"
        self.assertTrue((pooled / "report.md").is_file())
        # Pooled as a REGULAR file carrying the bytes — not a link, so the
        # bundle no longer depends on scratch surviving.
        repro = pooled / "reproducer.xml"
        self.assertTrue(repro.is_file())
        self.assertFalse(repro.is_symlink())
        self.assertEqual(repro.read_text(encoding="utf-8"), "<r/>")
        self.assertNotIn("reproducer.xml", warnings.getvalue())

    def test_pool_does_not_follow_a_symlinked_artifact_directory(self) -> None:
        bench = self.root / "linked-finding-bench"
        self.write_json(bench / "run.json", {
            "runid": "linked-dir", "target": "sample", "backend": "codex",
            "conditions": ["harness"], "replicates": 1,
        })
        results = self.root / "linked-dir-results"
        outside = self.root / "outside-finding"
        outside.mkdir()
        (outside / "report.md").write_text("# outside\n")
        findings = results / "findings"
        findings.mkdir(parents=True)
        (findings / "FIND-1").symlink_to(outside, target_is_directory=True)
        cell = self.make_cell(bench, "harness-r1", "harness", 1, 0, findings=1)
        data = json.loads((cell / "cell.json").read_text())
        data["results_dir"] = str(results)
        self.write_json(cell / "cell.json", data)
        self.write_json(cell / "metrics.json", {
            "confirmed_finding_dirs": ["FIND-1"],
        })

        warnings = io.StringIO()
        with redirect_stderr(warnings):
            benchmark.build_pool(bench)

        self.assertEqual(list((bench / "pool" / "findings").iterdir()), [])
        self.assertEqual((outside / "report.md").read_text(encoding="utf-8"), "# outside\n")
        self.assertIn("artifact directory is a symlink", warnings.getvalue())

    def test_pool_rejected_finding_keeps_reason_in_index(self) -> None:
        bench = self.root / "rejection-reason-bench"
        self.write_json(bench / "run.json", {
            "runid": "rejection-reason", "target": "sample",
            "backend": "codex", "conditions": ["harness"], "replicates": 1,
        })
        results = self.root / "rejection-reason-results"
        rejected = results / "findings-rejected" / "FIND-REJECTED"
        rejected.mkdir(parents=True)
        report = rejected / "report.md"
        report.write_text("# Rejected finding\n", encoding="utf-8")
        reason = "caller control does not reach the reported operation"
        self.write_json(rejected / ".llm-find-quality.json", {
            "accept": False,
            "reason": reason,
            "report_sha1": report_identity.content_sha1(report),
        })
        (rejected / "REJECTION.md").write_text(
            f"# Rejected artifact\n\nReason: {reason}\n\n"
            "The original evidence is retained for audit.\n",
            encoding="utf-8",
        )
        cell = self.make_cell(
            bench, "harness-r1", "harness", 1, 0, rejected_findings=1,
        )
        data = json.loads((cell / "cell.json").read_text(encoding="utf-8"))
        data["results_dir"] = str(results)
        self.write_json(cell / "cell.json", data)
        self.write_json(cell / "metrics.json", benchmark.harvest(results))

        benchmark.build_pool(bench)

        pooled = bench / "pool" / "findings-rejected" / "FIND-REJECTED-0001"
        index = (pooled.parent / "REJECTED-FINDINGS.md").read_text()
        self.assertIn(reason, index)

    def test_rejection_artifact_is_the_final_disposition(self) -> None:
        rejected_root = self.root / "final-disposition"
        finding = rejected_root / "FIND-TRIGGER-REJECTED"
        finding.mkdir(parents=True)
        report = finding / "report.md"
        report.write_text("# Finding\n", encoding="utf-8")
        self.write_json(finding / ".llm-find-quality.json", {
            "accept": True,
            "reason": "quality gate accepted the report",
            "report_sha1": report_identity.content_sha1(report),
        })
        final_reason = "triggering state is not attacker-reachable"
        (finding / "REJECTION.md").write_text(
            f"# Rejected artifact\n\nReason: {final_reason}\n",
            encoding="utf-8",
        )

        rows = benchmark._rejected_finding_rows(rejected_root)

        self.assertEqual(rows[0]["reason"], final_reason)

    def test_rejected_crash_index_renders_the_rejection_reason(self) -> None:
        # Triage writes REJECTION.md on the reject path before moving the
        # directory, so it is the one reason a pooled rejected crash carries.
        rejected = self.root / "crash-reason"
        with_reason = rejected / "CRASH-REJECTED-0001"
        with_reason.mkdir(parents=True)
        reason = "trigger-provenance: state not attacker-reachable"
        (with_reason / "REJECTION.md").write_text(
            f"# Rejected artifact\n\nReason: {reason}\n", encoding="utf-8",
        )
        # No artifact: the row still renders, with an em-dash reason.
        (rejected / "CRASH-REJECTED-0002").mkdir()

        benchmark.write_rejected_crashes_index(rejected)

        index = (rejected / "REJECTED-CRASHES.md").read_text(encoding="utf-8")
        self.assertIn(f"| `CRASH-REJECTED-0001` | — | {reason} |", index)
        self.assertIn("| `CRASH-REJECTED-0002` | — | — |", index)

    def test_crosstab_explains_finalized_populations_without_pending_columns(self) -> None:
        run = self.root / "crosstab" / "codex" / "20260101-000000"
        report = {
            "run": {
                "runid": "20260101-000000", "target": "sample",
                "backend": "codex", "model": "gpt-test",
            },
            "bench_dir": str(run),
            "conditions": [{
                "condition": "harness", "replicates_done": 1,
                "replicates_total": 1, "wall_median": 60,
                "rejected_finding_total": 2, "confirmed_finding_total": 3,
                "unique_finding_clusters": 2, "medium_plus_findings": 1,
                "unique_rejected_finding_clusters": 2,
                "rejected_finding_clusters_upper_bound": True,
                "rejected_crash_total": 4, "crash_total": 5,
                "unique_crash_clusters": 3, "medium_plus_bugs": 2,
                "unique_rejected_crash_clusters": 3,
                "top_severity_level": "High", "tokens": {},
                # A finalized report carries validation lanes; without them the
                # crosstab treats the counts as predating publication receipts
                # and shows them as pending instead.
                "validation_waterfall": {
                    "crashes": {"candidates": 5, "lanes": {"reportable": 3}},
                    "findings": {"candidates": 3, "lanes": {"reportable": 2}},
                },
            }],
        }
        self.write_json(run / "report.json", report)
        text = benchmark.crosstab(self.root / "crosstab")
        # Rejected columns precede reportable ones; upper bounds are explicit.
        for expected in (
            "can appear on both sides if it was reportable in one write-up",
            "Unique rejected findings | Security findings to report",
            "Unique rejected crashes | Unique security crashes to report",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)
        for gone in (
            "| Confirmed findings |", "| Confirmed crashes |",
            "| Rejected findings |", "| Rejected crashes |",
        ):
            with self.subTest(gone=gone):
                self.assertNotIn(gone, text)
        self.assertNotIn("Pending findings", text)
        self.assertNotIn("Pending crashes", text)
        self.assertNotIn("leads", text)
        ledger = benchmark.render_section(report)
        self.assertNotIn("Pending findings", ledger)
        self.assertNotIn("Pending crashes", ledger)
        self.assertIn("up to 2", text)
        self.assertIn("up to 2", ledger)

    def test_crosstab_shows_pre_receipt_counts_as_pending(self) -> None:
        # Counts written before publication receipts existed no longer follow
        # from the artifacts, and recounting without receipts reads zero. Show
        # neither number: the stale count reads as measured, and the zero reads
        # as "found nothing".
        run = self.root / "stale" / "codex" / "20260301-000000"
        report = {
            "run": {
                "runid": "20260301-000000", "target": "sample",
                "backend": "codex", "model": "gpt-test",
            },
            "bench_dir": str(run),
            "conditions": [{
                "condition": "harness", "replicates_done": 1,
                "replicates_total": 1, "wall_median": 60,
                "unique_crash_clusters": 7, "medium_plus_bugs": 4,
                "unique_finding_clusters": 5, "medium_plus_findings": 2,
                "top_severity_level": "High", "tokens": {},
                "cells": [{
                    "cell": "harness-r1", "condition": "harness",
                    "status": "done", "wall_effective_seconds": 3600,
                    "metrics": {"exists": True},
                }],
            }],
        }
        self.write_json(run / "report.json", report)
        text = benchmark.crosstab(self.root / "stale")
        self.assertIn("Pending", text)
        self.assertNotIn("7 (4 M+)", text)
        self.assertNotIn("5 (2 M+)", text)
        # The reader is told which runs need regenerating, and why.
        self.assertIn("bin/benchmark --regenerate", text)
        self.assertIn("regenerate", text)

        # A schema-v1 report does have lanes, but its conditional lane was
        # counted as security yield. It is equally superseded and must not
        # preserve those old headline numbers.
        report["conditions"][0]["validation_waterfall"] = {
            "crashes": {"lanes": {
                "reportable": 1, "conditional": 6,
                "native-hardening": 0,
            }},
            "findings": {"lanes": {
                "reportable": 2, "conditional": 3,
                "native-hardening": 0,
            }},
        }
        self.write_json(run / "report.json", report)
        superseded = benchmark.crosstab(self.root / "stale")
        self.assertIn("Pending", superseded)
        self.assertNotIn("7 (4 M+)", superseded)
        self.assertNotIn("5 (2 M+)", superseded)

    def test_crosstab_shows_receipt_backed_subset_without_migration_noise(self) -> None:
        run = self.root / "partial" / "codex" / "20260302-000000"
        report = {
            "run": {
                "runid": "20260302-000000", "target": "sample",
                "backend": "codex", "model": "gpt-test",
            },
            "bench_dir": str(run),
            "conditions": [{
                "condition": "harness", "replicates_done": 1,
                "replicates_total": 1, "wall_median": 60,
                "unique_crash_clusters": 7, "medium_plus_bugs": 4,
                "unique_finding_clusters": 5, "medium_plus_findings": 2,
                "top_severity_level": "High", "tokens": {},
                "validation_waterfall": {
                    "crashes": {
                        "candidates": 7,
                        "lanes": {
                            "reportable": 3, "legacy-provisional": 4,
                        },
                    },
                    "findings": {
                        "candidates": 5,
                        "lanes": {
                            "reportable": 5, "legacy-provisional": 0,
                        },
                    },
                },
                "cells": [{
                    "cell": "harness-r1", "condition": "harness",
                    "status": "done", "wall_effective_seconds": 3600,
                    "metrics": {"exists": True},
                }],
            }, {
                "condition": "model-direct", "replicates_done": 1,
                "replicates_total": 1, "wall_median": 60,
                "unique_crash_clusters": 9, "medium_plus_bugs": 4,
                "unique_finding_clusters": 8, "medium_plus_findings": 2,
                "top_severity_level": "High", "tokens": {},
                "validation_waterfall": {
                    "crashes": {
                        "candidates": 9,
                        "lanes": {
                            "reportable": 9, "legacy-provisional": 0,
                        },
                    },
                    "findings": {
                        "candidates": 8,
                        "lanes": {
                            "reportable": 8, "legacy-provisional": 0,
                        },
                    },
                },
                "cells": [{
                    "cell": "model-direct-r1", "condition": "model-direct",
                    "status": "done", "wall_effective_seconds": 3600,
                    "metrics": {"exists": True},
                }],
            }],
        }
        self.write_json(run / "report.json", report)
        text = benchmark.crosstab(self.root / "partial")
        self.assertNotIn("publication receipts for only part", text)
        self.assertNotIn("| regenerate |", text)
        self.assertIn("7 (4 M+)", text)
        self.assertIn("5 (2 M+)", text)
        self.assertIn("9 (4 M+)", text)
        self.assertIn("8 (2 M+)", text)
        self.assertNotIn("unmigrated", text)
        self.assertNotIn("## Runs awaiting review", text)

    def test_crosstab_live_progress_totals_include_rejected(self) -> None:
        run = self.root / "live" / "claude" / "20260201-000000"
        report = {
            "run": {
                "runid": "20260201-000000", "target": "sample",
                "backend": "claude", "model": "claude-test",
            },
            "bench_dir": str(run),
            "provisional": True,
            "conditions": [{
                "condition": "model-direct", "replicates_done": 1,
                "replicates_total": 2, "wall_median": 60,
                "cells": [{
                    "cell": "model-direct-r1", "condition": "model-direct",
                    "status": "done", "wall_effective_seconds": 3162,
                    "metrics": {
                        "exists": True,
                        # 0 confirmed but 3 filed-and-rejected findings: the raw
                        # total must surface them, not read as "found nothing".
                        "confirmed_findings": 0, "findings": 0,
                        "findings_rejected": 3,
                        "confirmed_crashes": 0, "crashes_rejected": 0,
                    },
                }],
            }],
        }
        self.write_json(run / "report.json", report)
        text = benchmark.crosstab(self.root / "live")
        self.assertIn("## Runs awaiting review", text)
        self.assertIn("Findings (raw) | Crashes (raw)", text)
        # the reader has to be told these two columns are not the settled ones
        self.assertIn("count one problem once per report", text)
        self.assertIn("include candidates later rejected", text)
        # 3 rejected findings surface as the raw total despite 0 confirmed.
        self.assertIn("| 3 | 0 |", text)


    def test_accepted_findings_cell_separates_none_survived_from_none_judged(
        self,
    ) -> None:
        # A drain cut short by finalize_wall leaves findings unjudged, and they
        # count as unconfirmed. Without the remainder the cell reads "this
        # condition found nothing", which is the opposite conclusion.
        self.assertEqual("0", benchmark._unique_with_medium_plus(0, 0))
        self.assertEqual(
            "0 (172 unjudged)", benchmark._unique_with_medium_plus(0, 0, 172),
        )
        self.assertEqual("6 (3 M+)", benchmark._unique_with_medium_plus(6, 3))
        self.assertEqual(
            "6 (3 M+, 4 unjudged)", benchmark._unique_with_medium_plus(6, 3, 4),
        )

    def test_accepted_findings_cell_carries_class_spread_and_floor_mark(
        self,
    ) -> None:
        # Same count, different results: one mechanism at 57 sites is not the
        # same coverage as 30 findings over 21 classes, and the count alone
        # cannot say which. A remainder that outnumbers the verdicts marks the
        # count as a lower bound rather than a yield to compare.
        self.assertEqual(
            "30 (23 M+, 21 classes)",
            benchmark._unique_with_medium_plus(30, 23, 0, 21),
        )
        self.assertEqual(
            "≥57 (41 M+, 3 classes, 194 unjudged)",
            benchmark._unique_with_medium_plus(57, 41, 194, 3, True),
        )
        # A residue beside an adjudicated majority still reads as measured.
        self.assertEqual(
            "57 (41 M+, 3 classes, 2 unjudged)",
            benchmark._unique_with_medium_plus(57, 41, 2, 3, False),
        )

    def test_finalization_tokens_split_by_stamp_not_by_role(self) -> None:
        """Adjudication tokens are recorded apart from discovery, not displayed.

        Post-cell review writes to the same index the audit does, so one
        re-review moved a direct cell from 13.9M to 24.9M input. In-run
        housekeeping decisions steer the audit and stay with it, so the split
        is by the finalization stamp, never by decision role.
        """
        logs = self.root / "tokensplit" / "logs"
        logs.mkdir(parents=True)
        index = logs / "index.jsonl"
        index.write_text("".join(json.dumps(row) + "\n" for row in (
            {"timestamp": "2026-08-03T01:00:00+00:00", "role": "decision:x",
             "tokens": {"input": 100, "output": 10}},
            {"timestamp": "2026-08-03T09:00:00+00:00", "role": "decision:x",
             "tokens": {"input": 700, "output": 70}},
        )), encoding="utf-8")
        # No stamp: a run predating it reports nothing rather than a guess.
        self.assertEqual(benchmark.harvest_finalization_tokens(index), {})
        (logs / ".finalization_started").write_text("2026-08-03T08:00:00+00:00")
        split = benchmark.harvest_finalization_tokens(index)
        self.assertEqual(split["started_at"], "2026-08-03T08:00:00+00:00")
        # Only the post-stamp row counts; the in-run decision stays with audit.
        self.assertEqual(split["input_tokens"], 700)
        # No scratch file: logs/ is shared across parallel agents and the
        # orchestrator, so a fixed-name temp there is a concurrent-write hazard.
        self.assertEqual(sorted(p.name for p in logs.iterdir()),
                         [".finalization_started", "index.jsonl"])

    def test_finding_classes_count_distinct_reviewed_bug_classes(self) -> None:
        findings = self.root / "class-spread"
        names = []
        for index, klass in enumerate(
            ["info-disclosure:uninit"] * 3 + ["memory-safety:bounds"],
        ):
            name = f"FIND-{index:04d}"
            names.append(name)
            directory = findings / name
            directory.mkdir(parents=True)
            (directory / ".llm-find-quality.json").write_text(
                json.dumps({"accept": True, "class": klass}), encoding="utf-8",
            )
        # No reviewed class: the report's own field carries it instead.
        names.append("FIND-0004")
        fallback = findings / "FIND-0004"
        fallback.mkdir()
        (fallback / "report.md").write_text(
            "| Class | dos:resource-exhaustion |\n", encoding="utf-8",
        )
        self.assertEqual(
            3, benchmark.confirmed_finding_class_count(findings, names),
        )

    def test_crosstab_tells_the_reader_what_an_unjudged_remainder_means(self) -> None:
        run = self.root / "unjudged" / "codex" / "20260202-000000"
        report = {
            "run": {
                "runid": "20260202-000000", "target": "sample",
                "backend": "codex", "model": "codex-test",
            },
            "bench_dir": str(run),
            "conditions": [{
                "condition": "model-direct", "replicates_done": 1,
                "replicates_total": 1, "wall_median": 3600,
                "unique_finding_clusters": 0, "medium_plus_findings": 0,
                "unadjudicated_finding_total": 172, "tokens": {},
                "validation_waterfall": {
                    "crashes": {"candidates": 0, "lanes": {}},
                    "findings": {"candidates": 19, "lanes": {"reportable": 0}},
                },
            }],
        }
        self.write_json(run / "report.json", report)
        text = benchmark.crosstab(self.root / "unjudged")
        self.assertIn("172 unjudged", text)
        self.assertIn("read the cell as a floor, not as a measured yield", text)
        self.assertIn("172 unjudged", benchmark.render_section(report))


class BenchmarkWallBudgetTests(unittest.TestCase):
    """Wall must be read against the budget the cell was granted.

    A cell that stops far under budget aggregates as a clean replicate, and a
    spent-only Wall column reads exactly like one that ran to the deadline —
    so the counts beside it look like the yield of an equal experiment.
    """

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="benchmark-wall-")
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    @staticmethod
    def write_json(path: Path, value: object) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(value) + "\n", encoding="utf-8")

    def make_run(self, bench: Path, budget_wall: int) -> None:
        self.write_json(bench / "run.json", {
            "runid": "run1", "target": "sample", "backend": "claude",
            "replicates": 1, "budget_wall": budget_wall,
            "conditions": ["model-direct", "harness"],
            "target_sha": "abc", "harness_sha": "def",
        })

    def make_cell(self, bench: Path, name: str, condition: str,
                  wall_seconds: int, *, status: str = "done",
                  run_quality: str = "clean") -> None:
        cell = bench / "cells" / name
        self.write_json(cell / "cell.json", {
            "condition": condition, "replicate": 1, "status": status,
            "run_quality": run_quality, "wall_seconds": wall_seconds,
            "paused_seconds": 0, "wall_effective_seconds": wall_seconds,
        })
        self.write_json(cell / "metrics.json", {
            "confirmed_crashes": 0, "findings": 1, "confirmed_findings": 1,
        })

    def test_aggregate_carries_the_granted_budget(self) -> None:
        bench = self.root / "bench-agg"
        self.make_run(bench, 18000)
        self.make_cell(bench, "model-direct-r1", "model-direct", 1875)
        self.make_cell(bench, "harness-r1", "harness", 17940)
        by_condition = {
            row["condition"]: row
            for row in benchmark.aggregate(bench)["conditions"]
        }
        self.assertEqual(by_condition["model-direct"]["wall_budget_seconds"], 18000)
        self.assertEqual(by_condition["harness"]["wall_budget_seconds"], 18000)

    def test_unlimited_budget_reports_no_share(self) -> None:
        bench = self.root / "bench-unlimited"
        self.make_run(bench, 0)
        self.make_cell(bench, "harness-r1", "harness", 900)
        row = benchmark.aggregate(bench)["conditions"][0]
        self.assertIsNone(row["wall_budget_seconds"])
        self.assertEqual(benchmark._wall_cell(row), "0.25h")

    def test_wall_column_carries_the_denominator(self) -> None:
        self.assertEqual(
            benchmark._wall_cell(
                {"wall_median": 17940.0, "wall_budget_seconds": 18000}
            ),
            "4.98/5.00h",
        )
        self.assertEqual(
            benchmark._wall_cell(
                {"wall_median": 1875.0, "wall_budget_seconds": 18000}
            ),
            "0.52/5.00h",
        )
        # Runs predating the field keep the bare spent-hours form.
        self.assertEqual(benchmark._wall_cell({"wall_median": 1875.0}), "0.52h")
        self.assertEqual(
            benchmark._wall_cell({"wall_median": 0, "wall_budget_seconds": 18000}),
            "\u2014",
        )

    def test_a_counted_terminated_replicate_cannot_hide_in_the_median(self) -> None:
        """A terminated cell counts, so the reader has to see that it did.

        With one repeat the short **Wall (h)** numerator says it. With several,
        the median comes back to the full-budget repeats and the truncated one
        becomes invisible - which is the shape that would silently understate
        the direct control against a full-budget harness cell.
        """
        bench = self.root / "bench-terminated"
        self.make_run(bench, 18000)
        self.make_cell(bench, "model-direct-r1", "model-direct", 17940)
        self.make_cell(bench, "model-direct-r2", "model-direct", 17940)
        self.make_cell(
            bench, "model-direct-r3", "model-direct", 1875,
            run_quality="backend_terminated",
        )
        self.make_cell(bench, "harness-r1", "harness", 17940)
        by_condition = {
            row["condition"]: row
            for row in benchmark.aggregate(bench)["conditions"]
        }
        direct = by_condition["model-direct"]
        self.assertEqual(direct["replicates_done"], 3)
        self.assertEqual(direct["replicates_backend_terminated"], 1)
        # The median wall is a full-budget repeat: the marker is the only signal.
        self.assertEqual(benchmark._wall_cell(direct), "4.98/5.00h")
        self.assertIn("(1t)", benchmark._replicates_cell(direct))
        self.assertEqual(by_condition["harness"]["replicates_backend_terminated"], 0)
        self.assertNotIn("t)", benchmark._replicates_cell(by_condition["harness"]))

    def test_short_cell_shows_its_share_and_keeps_the_verdict(self) -> None:
        """A condition that stops early is a result, not a broken measurement.

        The direct control decides for itself when it is done, so the report
        states what it spent of what it was granted and still names the
        strongest bug \u2014 a run-wide refusal to conclude would fire on the
        control's normal behaviour and on a harness cell that legitimately
        exhausts its hypotheses early.
        """
        report = {
            "run": {"runid": "run1", "target": "sample", "backend": "claude",
                    "replicates": 1, "budget_wall": 18000},
            "conditions": [{
                "condition": "model-direct", "replicates_done": 1,
                "replicates_total": 1, "wall_median": 1875,
                "wall_budget_seconds": 18000,
            }],
            "crash_clusters": [{
                "id": "CRCL-1", "severity_level": "High", "severity_score": 8.0,
                "severity_rank": 3, "conditions": ["harness"], "members": [],
            }],
        }
        rendered = benchmark.render_section(report)
        self.assertIn("0.52/5.00h", rendered)
        self.assertIn("The strongest bug this run", rendered)


if __name__ == "__main__":
    unittest.main()
