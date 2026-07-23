#!/usr/bin/env python3
"""Regression tests for high-risk orchestration and triage behavior."""

from __future__ import annotations

import json
import os
import runpy
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_helpers
import audit_runner
import benchmark
import benchmark_runner
import gemini_watchdog
import llm_invoke
import process_tree
import report_identity
import target_config
import triage
import triage_validate
import verdict
import vocab_rules
import workqueue

passed = failed = 0


def check(condition: bool, name: str, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        failed += 1
        print(f"  \033[0;31m✗\033[0m {name}")
        if detail:
            print(f"    {detail}")


def _crash_dir(root: Path, name: str, *, report: str | None, sanitizer: str | None,
               testcase: bool) -> Path:
    directory = root / "crashes" / name
    directory.mkdir(parents=True)
    if report is not None:
        (directory / "REPORT.md").write_text(report, encoding="utf-8")
    if sanitizer is not None:
        (directory / "sanitizer.txt").write_text(sanitizer, encoding="utf-8")
    if testcase:
        (directory / "testcase.bin").write_bytes(b"\x01\x02\x03\x04crashinput")
    return directory


_ASAN = (
    "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000\n"
    "    #0 0x1 in app_parse app.c:91\n"
    "SUMMARY: AddressSanitizer: heap-buffer-overflow app.c:91 in app_parse\n"
)
_GOOD_REPORT = (
    "| Field | Value |\n| Caller contract | respected |\n| Caller controls | bytes |\n"
    "| Trigger source | bytes |\n\n## Summary\nOut-of-bounds read.\n"
)


with tempfile.TemporaryDirectory(prefix="py-migration-regressions-") as temporary:
    root = Path(temporary)
    # Keep the LLM-driven gates out of these unit checks; each capability is
    # exercised through its structural path (env opt-out, byte accounting, etc.).
    os.environ["CRASH_TRIGGER_GATE"] = "0"

    # The productive wall and final measurement have independent budgets. A
    # harness that consumes its investigation budget still receives a bounded
    # finalization window and finishes as a countable benchmark cell.
    bench_root = root / "benchmark"
    backend_root = bench_root / "codex"
    bench_dir = backend_root / "wall-budget"
    cells_dir = bench_dir / "cells"
    cells_dir.mkdir(parents=True)
    fake_script_root = root / "benchmark-script-root"
    (fake_script_root / "targets" / "sampleproj").mkdir(parents=True)
    drained_deadlines: list[object] = []

    def _budget_harness(cell_dir, *_args):
        results = cell_dir / "results"
        finding = results / "findings" / "FIND-001"
        finding.mkdir(parents=True)
        (finding / "report.md").write_text("# Finding\n", encoding="utf-8")
        for index in range(1, 4):
            crash = results / "crashes" / f"CRASH-00{index}-1"
            crash.mkdir(parents=True)
            (crash / "sanitizer.txt").write_text(_ASAN, encoding="utf-8")
            (crash / "REPORT.md").write_text(
                _GOOD_REPORT if index < 3 else "## Root Cause\n_TODO (agent): fill in\n",
                encoding="utf-8",
            )
        return 0, results

    def _budget_crash_triage(*_args, **_kwargs):
        return {"promoted": 2, "rejected": 0, "demoted": 0, "pending": 1}

    def _budget_drain(results, *_args, **kwargs):
        drained_deadlines.append(kwargs.get("deadline"))
        finding = results / "findings" / "FIND-001"
        report = finding / "report.md"
        (finding / ".llm-find-quality.json").write_text(
            json.dumps({"accept": True}), encoding="utf-8"
        )
        if "harness-r2" in results.parts:
            return {"accepted": 0, "rejected": 0, "pending": 1}
        (finding / ".trigger-gate.json").write_text(json.dumps({
            "vote": "Promote",
            "content_sha1": report_identity.content_sha1(report),
            "decision_version": triage_validate.TRIGGER_GATE_DECISION_VERSION,
            "attacker_controls": ["bytes"],
        }), encoding="utf-8")
        return {"accepted": 1, "rejected": 0, "pending": 0}

    budget_args = SimpleNamespace(
        model="test-model", backend="codex", target="sampleproj", replicates=2,
        budget_wall=1, finalize_wall=7, agents=1, dry_run=False,
        regenerate=False, validate_findings=True,
    )
    empty_report = {"conditions": []}
    budget_clock = iter([0])
    def _budget_time():
        return next(budget_clock, 5)
    with mock.patch.object(benchmark_runner, "SCRIPT_ROOT", fake_script_root), \
         mock.patch.object(benchmark_runner.llm_invoke, "apply_memory_policy"), \
         mock.patch.object(benchmark_runner.target_config, "detect_rev", return_value="rev"), \
         mock.patch.object(benchmark_runner, "_git_rev", return_value="rev"), \
         mock.patch.object(benchmark_runner, "preflight_build"), \
         mock.patch.object(benchmark_runner, "run_harness", side_effect=_budget_harness), \
         mock.patch.object(benchmark_runner, "triage_cell_crashes", side_effect=_budget_crash_triage), \
         mock.patch.object(benchmark_runner, "drain_find_gate", side_effect=_budget_drain), \
         mock.patch.object(benchmark_runner, "update_result", return_value=empty_report), \
         mock.patch.object(benchmark_runner.metrics, "render_section", return_value=""), \
         mock.patch.object(benchmark_runner.metrics, "append_to_ledger"), \
         mock.patch.object(benchmark_runner.time, "monotonic", side_effect=_budget_time):
        budget_rc = benchmark_runner._run_locked(
            budget_args, bench_root, backend_root, bench_dir, cells_dir,
            backend_root / "benchmark-results.md", "wall-budget", ["harness"],
        )
    budget_cell = json.loads(
        (cells_dir / "harness-r1" / "cell.json").read_text(encoding="utf-8")
    )
    budget_metrics = json.loads(
        (cells_dir / "harness-r1" / "metrics.json").read_text(encoding="utf-8")
    )
    pending_cell = json.loads(
        (cells_dir / "harness-r2" / "cell.json").read_text(encoding="utf-8")
    )
    pending_metrics = json.loads(
        (cells_dir / "harness-r2" / "metrics.json").read_text(encoding="utf-8")
    )
    check(budget_rc == 0, "trigger residue does not discard an otherwise completed benchmark cell")
    check(
        drained_deadlines == [12, 12],
        "final benchmark triage receives its independent deadline",
        repr(drained_deadlines),
    )
    finalize_clock = iter([100.0, 250.0])
    with mock.patch.object(
        benchmark_runner.time, "monotonic", side_effect=lambda: next(finalize_clock)
    ):
        crash_phase = benchmark_runner._finalize_deadline(7)
        find_phase = benchmark_runner._finalize_deadline(7)
    check(
        crash_phase == 107.0 and find_phase == 257.0 and find_phase > crash_phase,
        "each finalization phase computes a fresh, independent deadline",
        (crash_phase, find_phase),
    )
    check(
        benchmark_runner._finalize_deadline(0) is None,
        "an unbounded finalize budget yields no deadline",
    )
    check(
        budget_cell["status"] == "done" and budget_cell["run_quality"] == "clean",
        "budget-complete harness cell remains done and clean",
        repr(budget_cell),
    )
    check(
        budget_metrics["confirmed_findings"] == 1,
        "metrics are harvested after final finding adjudication",
        repr(budget_metrics),
    )
    check(
        pending_cell["status"] == "done"
        and pending_cell["run_quality"] == "clean"
        and pending_metrics["confirmed_findings"] == 0
        and pending_metrics["findings_unadjudicated"] == 1,
        "quality-only findings remain visible without excluding the completed cell",
        repr((pending_cell, pending_metrics)),
    )
    check(
        budget_metrics["confirmed_crashes"] == 3
        and budget_metrics["crashes_pending"] == 1
        and budget_metrics["crashes_rejected"] == 0,
        "two promoted crashes and one report skeleton all retain sanitizer credit",
        repr(budget_metrics),
    )
    budget_report = benchmark.aggregate(bench_dir, include_pool=False)
    budget_condition = budget_report["conditions"][0]
    check(
        budget_condition["crash_total"] == 6
        and budget_condition["pending_crash_total"] == 2
        and budget_condition["confirmed_finding_total"] == 1,
        "pending findings and reports are qualified individually without erasing cell evidence",
        repr(budget_condition),
    )

    # Regeneration re-derives stale accounting status only after both
    # finalizers return normally. Provider-limited cells remain excluded.
    budget_cell["status"] = "incomplete"
    budget_cell["run_quality"] = "incomplete"
    (cells_dir / "harness-r1" / "cell.json").write_text(
        json.dumps(budget_cell), encoding="utf-8"
    )
    pending_cell["status"] = "incomplete"
    pending_cell["run_quality"] = "incomplete"
    (cells_dir / "harness-r2" / "cell.json").write_text(
        json.dumps(pending_cell), encoding="utf-8"
    )
    provider_dir = cells_dir / "harness-r3"
    provider_dir.mkdir()
    provider_results = provider_dir / "results"
    provider_results.mkdir()
    (provider_dir / ".backend-unavailable").touch()
    (provider_dir / "cell.json").write_text(json.dumps({
        "condition": "harness", "replicate": 3, "experiment": "provider",
        "results_dir": str(provider_results), "wall_seconds": 1,
        "status": "incomplete", "run_quality": "provider_limited",
    }), encoding="utf-8")
    regenerate_args = SimpleNamespace(**{**vars(budget_args), "regenerate": True})
    regenerate_age_pending = []
    def _regenerate_crash_triage(*args, **kwargs):
        regenerate_age_pending.append(kwargs.get("age_pending"))
        return _budget_crash_triage(*args, **kwargs)
    with mock.patch.object(benchmark_runner, "SCRIPT_ROOT", fake_script_root), \
         mock.patch.object(benchmark_runner, "triage_cell_crashes", side_effect=_regenerate_crash_triage), \
         mock.patch.object(benchmark_runner, "drain_find_gate", side_effect=_budget_drain), \
         mock.patch.object(benchmark_runner, "update_result", return_value=empty_report), \
         mock.patch.object(benchmark_runner.metrics, "render_section", return_value=""), \
         mock.patch.object(benchmark_runner.metrics, "append_to_ledger"):
        benchmark_runner._run_locked(
            regenerate_args, bench_root, backend_root, bench_dir, cells_dir,
            backend_root / "benchmark-results.md", "wall-budget", ["harness"],
        )
    recovered = json.loads((cells_dir / "harness-r1" / "cell.json").read_text())
    provider = json.loads((provider_dir / "cell.json").read_text())
    still_pending = json.loads((cells_dir / "harness-r2" / "cell.json").read_text())
    check(
        recovered["status"] == "done" and recovered["run_quality"] == "clean",
        "regenerate recomputes stale artifact-pending incomplete status",
        repr(recovered),
    )
    check(
        provider["status"] == "incomplete" and provider["run_quality"] == "provider_limited",
        "regenerate preserves genuine provider-limited status",
        repr(provider),
    )
    check(
        still_pending["status"] == "done"
        and still_pending["run_quality"] == "clean",
        "regenerate recovers an artifact-pending cell after finalizers return normally",
        repr(still_pending),
    )
    check(
        regenerate_age_pending and all(value is False for value in regenerate_age_pending),
        "regenerate triages without consuming pending-artifact lifetime",
        repr(regenerate_age_pending),
    )
    recovered["status"] = "incomplete"
    recovered["run_quality"] = "incomplete"
    (cells_dir / "harness-r1" / "cell.json").write_text(
        json.dumps(recovered), encoding="utf-8"
    )
    with mock.patch.object(benchmark_runner, "SCRIPT_ROOT", fake_script_root), \
         mock.patch.object(benchmark_runner, "triage_cell_crashes", side_effect=RuntimeError("triage failed")), \
         mock.patch.object(benchmark_runner, "drain_find_gate", side_effect=_budget_drain), \
         mock.patch.object(benchmark_runner, "update_result", return_value=empty_report), \
         mock.patch.object(benchmark_runner.metrics, "render_section", return_value=""), \
         mock.patch.object(benchmark_runner.metrics, "append_to_ledger"):
        benchmark_runner._run_locked(
            regenerate_args, bench_root, backend_root, bench_dir, cells_dir,
            backend_root / "benchmark-results.md", "wall-budget", ["harness"],
        )
    finalizer_failed = json.loads(
        (cells_dir / "harness-r1" / "cell.json").read_text()
    )
    check(
        finalizer_failed["status"] == "incomplete",
        "regenerate does not recover a cell when a finalizer actually fails",
        repr(finalizer_failed),
    )

    # A pending crash is explicit resumable work and preempts card claiming.
    resume_results = root / "resume-pending"
    resume_crash = resume_results / "crashes" / "CRASH-003-1"
    resume_crash.mkdir(parents=True)
    (resume_crash / "report.md").write_text(
        "## Root Cause\n_TODO (agent): complete\n", encoding="utf-8"
    )
    resume_ctx = workqueue.Context(ROOT, root, "sampleproj", resume_results, "none")
    workqueue.init_state(resume_ctx)
    (resume_results / "work-cards.jsonl").write_text(json.dumps({
        "id": "WORK-next", "kind": "ranked-source", "status": "unclaimed",
        "file": "src/next.c", "subsystem": "next", "strategy": "S2",
    }) + "\n", encoding="utf-8")
    resume_text = workqueue.state_resume(resume_ctx, "1", claim=True)
    check(
        "## Pending Crash Completion" in resume_text
        and "CRASH-003-1" in resume_text
        and "work-card assignment is deferred" in resume_text,
        "unfinished crash report is the highest-priority resumable work",
        resume_text,
    )
    claims = workqueue.read_jsonl(resume_results / "state" / "claims.jsonl")
    check(not claims, "pending crash completion does not claim a new work card", repr(claims))

    # ── #1 promotion-pending TTL: an incomplete crash is held, not rejected ──
    incomplete_root = root / "ttl"
    (incomplete_root / "crashes-rejected").mkdir(parents=True)
    os.environ["CRASH_PROMOTION_PENDING_MAX"] = "3"
    crash = _crash_dir(incomplete_root, "CRASH-001", report=None, sanitizer=_ASAN, testcase=True)
    status = triage.triage_one_crash(crash, incomplete_root, root, "sampleproj", ["bytes"])
    check(status == "pending", "incomplete crash (missing report) is held promotion-pending", status)
    check(crash.is_dir(), "held crash stays in crashes/ (not moved to rejected)")
    check((crash / ".promotion_pending.count").read_text().strip() == "1", "first pending pass counts 1")
    triage.triage_one_crash(crash, incomplete_root, root, "sampleproj", ["bytes"])
    check((crash / ".promotion_pending.count").read_text().strip() == "2", "same missing signature bumps the counter")
    final = triage.triage_one_crash(crash, incomplete_root, root, "sampleproj", ["bytes"])
    check(final == "rejected", "crash ages out to rejected after CRASH_PROMOTION_PENDING_MAX passes")
    check(not crash.is_dir(), "aged-out crash is moved out of crashes/")
    rejected = list((incomplete_root / "crashes-rejected").glob("CRASH-001*"))
    check(bool(rejected), "aged-out crash is preserved under crashes-rejected/")

    # An unenriched bin/probe skeleton report is held pending, not promoted.
    skeleton_root = root / "skeleton"
    (skeleton_root / "crashes-rejected").mkdir(parents=True)
    skeleton = _crash_dir(
        skeleton_root, "CRASH-010",
        report="## Root Cause\n_TODO (agent): fill in\n", sanitizer=_ASAN, testcase=True,
    )
    check(
        triage.triage_one_crash(skeleton, skeleton_root, root, "sampleproj", ["bytes"]) == "pending",
        "unenriched _TODO skeleton is held pending, not promoted",
    )

    # Read-only regeneration may revisit a pending artifact many times. It
    # refreshes the marker but must not consume live triage attempts or age
    # sanitizer evidence into crashes-rejected.
    replay_root = root / "replay-safe-pending"
    (replay_root / "crashes-rejected").mkdir(parents=True)
    replay_crash = _crash_dir(
        replay_root, "CRASH-011",
        report="## Root Cause\n_TODO (agent): fill in\n",
        sanitizer=_ASAN, testcase=True,
    )
    for _ in range(12):
        replay = triage.triage_crash_dirs(
            replay_root, root, "sampleproj", ["bytes"], workers=1,
            age_pending=False,
        )
        check(replay["pending"] == 1, "regeneration keeps incomplete crash pending")
    check(replay_crash.is_dir(), "regeneration never ages pending crash into rejected")
    check(
        not (replay_crash / ".promotion_pending.count").exists(),
        "regeneration does not consume a promotion-pending attempt",
    )

    # A complete crash clears the pending sidecars and is promotable.
    complete_root = root / "complete"
    (complete_root / "crashes-rejected").mkdir(parents=True)
    complete = _crash_dir(complete_root, "CRASH-020", report=_GOOD_REPORT, sanitizer=_ASAN, testcase=True)
    (complete / ".promotion_pending.count").write_text("2\n", encoding="utf-8")
    result = triage.triage_one_crash(complete, complete_root, root, "sampleproj", ["bytes"])
    check(result == "promoted", "complete crash promotes", result)
    check(not (complete / ".promotion_pending.count").exists(), "promotion clears the pending sidecars")

    # Export failure is a separate pending scope. It must not be reported as a
    # promoted maintainer bundle merely because the audit-side files exist.
    bundle_root = root / "bundle-failure"
    (bundle_root / "crashes-rejected").mkdir(parents=True)
    bundle = _crash_dir(
        bundle_root, "CRASH-025", report=_GOOD_REPORT,
        sanitizer=_ASAN, testcase=True,
    )
    with mock.patch.object(triage, "_run_tool", return_value=1):
        bundle_status = triage.triage_one_crash(
            bundle, bundle_root, root, "sampleproj", ["bytes"]
        )
    check(bundle_status == "pending", "failed export leaves the crash bundle pending", bundle_status)
    check(
        (bundle / ".promotion_pending.sig").read_text().startswith("bundle:"),
        "bundle failure uses an independent TTL signature",
    )

    # export-repro moves report.md under .audit and creates REPORT.md. The
    # trigger gate must review the new canonical path, not the stale source.
    gate_root = root / "post-export-gate"
    (gate_root / "crashes-rejected").mkdir(parents=True)
    gate_crash = _crash_dir(
        gate_root, "CRASH-026", report=_GOOD_REPORT,
        sanitizer=_ASAN, testcase=True,
    )
    (gate_crash / "REPORT.md").rename(gate_crash / "report.md")
    reviewed_paths: list[Path] = []

    def _fake_export(tool_name, *_args, **_kwargs):
        if tool_name != "export-repro":
            return 0
        audit_dir = gate_crash / ".audit"
        audit_dir.mkdir(exist_ok=True)
        shutil.move(gate_crash / "report.md", audit_dir / "report.md")
        (gate_crash / "REPORT.md").write_text(_GOOD_REPORT, encoding="utf-8")
        (gate_crash / "reproduce.sh").write_text("#!/bin/sh\n", encoding="utf-8")
        (gate_crash / "input.bin").write_bytes(b"input")
        return 0

    def _record_gate(
        _directory, report_path, _target_root, _deadline=None, _usage_index=None,
        _target_root_is_product=False,
        _attacker_controls=None,
    ):
        reviewed_paths.append(report_path)
        return False

    with mock.patch.object(triage, "_run_tool", side_effect=_fake_export), \
         mock.patch.object(triage, "_crash_trigger_gate", side_effect=_record_gate):
        gate_status = triage.triage_one_crash(
            gate_crash, gate_root, root, "sampleproj", ["bytes"]
        )
    check(gate_status == "promoted", "post-export crash reaches the trigger gate", gate_status)
    check(
        reviewed_paths == [gate_crash / "REPORT.md"],
        "trigger gate receives the canonical post-export REPORT.md",
        repr(reviewed_paths),
    )

    expired_finding_root = root / "expired-finding"
    expired_finding = expired_finding_root / "findings" / "FIND-001"
    expired_finding.mkdir(parents=True)
    (expired_finding / "report.md").write_text(_GOOD_REPORT, encoding="utf-8")
    with mock.patch.object(triage.time, "monotonic", return_value=10.0), \
         mock.patch.object(triage, "_quality_vote") as expired_vote:
        expired_status = triage.validate_one_finding(
            expired_finding, expired_finding_root, deadline=10.0,
        )
    check(
        expired_status == "pending" and not expired_vote.called,
        "expired result triage stays pending without launching another LLM decision",
    )

    # Non-security autodiscard classes still reject immediately (no TTL grace).
    oom_root = root / "oom"
    (oom_root / "crashes-rejected").mkdir(parents=True)
    oom = _crash_dir(
        oom_root, "CRASH-030", report=_GOOD_REPORT,
        sanitizer="==1==ERROR: AddressSanitizer: out-of-memory\n", testcase=True,
    )
    check(
        triage.triage_one_crash(oom, oom_root, root, "sampleproj", ["bytes"]) == "rejected",
        "non-security autodiscard (OOM) rejects immediately without TTL grace",
    )
    check(
        triage.autodiscard_reason(
            "==1==ERROR: AddressSanitizer: ABRT\n"
            "    #0 0x1 in __assert_fail\nSIGABRT\n"
        ) == "debug assertion abort",
        "ASan ABRT through libc assert is auto-quarantined",
    )

    # Non-security UBSan is actionable undefined behavior, but not a
    # sanitizer-class crash. Route it through findings after completeness.
    ubsan_root = root / "ubsan-nonsecurity"
    (ubsan_root / "crashes-rejected").mkdir(parents=True)
    ubsan = _crash_dir(
        ubsan_root, "CRASH-035", report=_GOOD_REPORT,
        sanitizer="sample.c:12:7: runtime error: signed integer overflow: 1 + 2\n",
        testcase=True,
    )
    check(
        triage.triage_one_crash(ubsan, ubsan_root, root, "sampleproj", ["bytes"]) == "demoted",
        "non-security UBSan is demoted to findings instead of counted as a crash",
    )
    check((ubsan_root / "findings" / "FIND-035").is_dir(), "UBSan demotion preserves the artifact as a finding")

    nonmemory_root = root / "asan-nonmemory"
    (nonmemory_root / "crashes-rejected").mkdir(parents=True)
    nonmemory = _crash_dir(
        nonmemory_root, "CRASH-035A", report=_GOOD_REPORT,
        sanitizer="==1==ERROR: AddressSanitizer: FPE on unknown address 0x1234\n",
        testcase=True,
    )
    check(
        triage.triage_one_crash(
            nonmemory, nonmemory_root, root, "sampleproj", ["bytes"]
        ) == "demoted",
        "a sanitizer diagnostic without a memory-safety class cannot inflate crash metrics",
    )
    check(
        (nonmemory_root / "findings" / "FIND-035A").is_dir(),
        "a non-memory sanitizer report remains available to the finding-quality gate",
    )
    check(
        triage._has_memory_safety_signal(
            "==1==ERROR: HWAddressSanitizer: tag-mismatch on address 0x1234\n"
        ),
        "HWASan tag-mismatch remains a memory-safety crash class",
    )
    check(
        triage._has_memory_safety_signal(
            "==1==ERROR: AddressSanitizer: use-after-poison on address 0x1234\n"
        ),
        "ASan use-after-poison reaches the crash path that already scores it as UAF",
    )
    for diagnostic in (
        "free-size-mismatch", "reallocarray-overflow", "pvalloc-overflow",
    ):
        check(
            triage._has_memory_safety_signal(
                f"==1==ERROR: AddressSanitizer: {diagnostic} on address 0x1234\n"
            ),
            f"ASan {diagnostic} has admission/scoring parity",
        )
    for non_security_diagnostic in (
        "invalid-allocation-alignment", "odr-violation",
        "bad-__sanitizer_annotate_contiguous_container",
    ):
        check(
            not triage._has_memory_safety_signal(
                "==1==ERROR: AddressSanitizer: "
                f"{non_security_diagnostic}\n"
            ),
            f"ASan {non_security_diagnostic} is not promoted without consequence evidence",
        )
    check(
        not triage._has_memory_safety_signal(
            "WARNING: ThreadSanitizer: thread leak (pid=1)\n"
        ),
        "TSan thread leaks do not masquerade as memory-safety crashes",
    )

    mixed_root = root / "ubsan-mixed"
    (mixed_root / "crashes-rejected").mkdir(parents=True)
    mixed = _crash_dir(
        mixed_root, "CRASH-036", report=_GOOD_REPORT,
        sanitizer=_ASAN + "sample.c:12:7: runtime error: signed integer overflow\n",
        testcase=True,
    )
    check(
        triage.triage_one_crash(mixed, mixed_root, root, "sampleproj", ["bytes"]) == "promoted",
        "ASan memory-safety evidence outranks a secondary non-security UBSan line",
    )

    rooted_root = root / "harness-rooted"
    (rooted_root / "crashes-rejected").mkdir(parents=True)
    rooted = _crash_dir(
        rooted_root, "CRASH-037", report=_GOOD_REPORT,
        sanitizer=(
            "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x60200000\n"
            "    #0 0x100 in main sample_harness.c:84\n"
            "    #1 0x188 in start+0x1b4c\n"
            "SUMMARY: AddressSanitizer: heap-use-after-free sample_harness.c:84 in main\n"
        ),
        testcase=True,
    )
    check(
        triage.triage_one_crash(rooted, rooted_root, root, "sampleproj", ["bytes"]) == "rejected",
        "a crash rooted entirely in the audit harness is removed from crash metrics",
    )

    # A harness-only ASan crash (no testcase; export-repro stages harness.c and a
    # runnable reproduce.sh) is complete and must promote, not age out on a
    # spurious missing-input.* signature.
    harness_root = root / "harness-only"
    (harness_root / "crashes-rejected").mkdir(parents=True)
    harness_crash = _crash_dir(
        harness_root, "CRASH-040", report=_GOOD_REPORT, sanitizer=_ASAN, testcase=False,
    )
    (harness_crash / "reproduce.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (harness_crash / "harness.c").write_text("int main(){return 0;}\n", encoding="utf-8")
    with mock.patch.object(triage, "_run_tool", return_value=0):
        harness_status = triage.triage_one_crash(
            harness_root / "crashes" / "CRASH-040", harness_root, root, "sampleproj", ["bytes"],
        )
    check(harness_status == "promoted", "harness-only crash (staged harness, no testcase) promotes", harness_status)

    # A findings-only target ([sanitizer] enabled = []) has no instrumented
    # build; a language-runtime diagnostic stands in for a sanitizer trace so a
    # real crash is not aged out as "never-reproduced-under-sanitizer".
    runtime_root = root / "findings-only"
    (runtime_root / "crashes-rejected").mkdir(parents=True)
    runtime_crash = _crash_dir(
        runtime_root, "CRASH-050", report=_GOOD_REPORT,
        sanitizer="panic: runtime error: index out of range [5] with length 3\n"
                  "\ngoroutine 1 [running]:\nmain.parse()\n",
        testcase=True,
    )
    (runtime_crash / "reproduce.sh").write_text("#!/bin/sh\n", encoding="utf-8")
    (runtime_crash / "input.bin").write_bytes(b"crashinput")  # post-export bundle shape
    with mock.patch.object(triage, "_run_tool", return_value=0):
        held = triage.triage_one_crash(
            runtime_root / "crashes" / "CRASH-050", runtime_root, root, "sampleproj",
            ["bytes"], findings_only=False,
        )
    check(held == "pending", "runtime-only crash on a SANITIZER target is held (no valid diagnostic)", held)
    check(
        benchmark.count_confirmed_crashes(runtime_root / "crashes")[0] == 0,
        "Go runtime panic is not miscounted as a sanitizer-confirmed crash",
    )
    with mock.patch.object(triage, "_run_tool", return_value=0):
        runtime_counts = triage.triage_crash_dirs(
            runtime_root, root, "sampleproj", ["bytes"],
            findings_only=True, workers=1,
        )
    runtime_finding = runtime_root / "findings" / "FIND-050"
    check(runtime_counts["demoted"] == 1, "runtime demotion is reported separately from rejection")
    check(runtime_counts["rejected"] == 0, "runtime demotion does not inflate rejected-crash accounting")
    check(runtime_finding.is_dir(), "runtime-only crash is demoted to findings/FIND-*", str(runtime_finding))
    check(not runtime_crash.exists(), "demoted runtime artifact no longer remains in crashes/")
    check(
        "runtime diagnostic without a sanitizer-class" in (runtime_finding / "REPORT.md").read_text(),
        "demoted finding records its triage disposition",
    )

    # Rust panic text is normally an immediate crash autodiscard. In findings-only
    # mode it must reach the same demotion path instead of being lost before the
    # runtime-diagnostic exception is considered.
    rust_root = root / "findings-only-rust"
    (rust_root / "crashes-rejected").mkdir(parents=True)
    rust_crash = _crash_dir(
        rust_root, "CRASH-051", report=_GOOD_REPORT,
        sanitizer="thread 'main' panicked at index out of bounds\n",
        testcase=True,
    )
    rust_status = triage.triage_one_crash(
        rust_crash, rust_root, root, "sampleproj", ["bytes"], findings_only=True,
    )
    check(rust_status == "demoted", "findings-only Rust panic leaves crashes/", rust_status)
    check((rust_root / "findings" / "FIND-051").is_dir(), "findings-only Rust panic is demoted, not discarded")

    # A real sanitizer diagnostic still wins on a findings-only target (for
    # example a managed runtime with an instrumented native extension).
    native_root = root / "findings-only-native-signal"
    (native_root / "crashes-rejected").mkdir(parents=True)
    native_crash = _crash_dir(
        native_root, "CRASH-052", report=_GOOD_REPORT, sanitizer=_ASAN, testcase=True,
    )
    check(
        triage.triage_one_crash(
            native_crash, native_root, root, "sampleproj", ["bytes"], findings_only=True,
        ) == "promoted",
        "sanitizer-class signal remains a crash even when the target is findings-only",
    )

    del os.environ["CRASH_PROMOTION_PENDING_MAX"]

    # ── #2 trigger-provenance crash gate wiring ──
    check(
        triage._crash_trigger_gate(root, root / "missing.md", root) is False,
        "trigger gate opt-out (CRASH_TRIGGER_GATE=0) keeps the crash",
    )
    del os.environ["CRASH_TRIGGER_GATE"]
    # With no backend resolvable the vote is a non-verdict (retryable), so the
    # gate keeps the crash — recall-safe, never a spurious reject.
    for key in ("ACTIVE_BACKEND", "BACKEND"):
        os.environ.pop(key, None)
    report_path = root / "trig.md"
    report_path.write_text(_GOOD_REPORT, encoding="utf-8")
    check(
        triage._trigger_vote(report_path, root / "vote.json", "", "", root) == 2,
        "trigger vote with no backend is a non-verdict (retryable, recall-safe)",
    )
    check(
        triage._crash_trigger_gate(root, report_path, root) is False,
        "default-on trigger gate keeps the crash when no vote is conclusive",
    )
    with mock.patch.object(triage, "_trigger_vote", side_effect=[1, 0]) as votes:
        check(
            triage._crash_trigger_gate(root, report_path, root) is False and votes.call_count == 2,
            "one trigger reject cannot remove a sanitizer-confirmed crash",
        )
    with mock.patch.object(triage, "_trigger_vote", side_effect=[1, 1]) as votes:
        check(
            triage._crash_trigger_gate(root, report_path, root) is True and votes.call_count == 2,
            "two trigger rejects satisfy the crash gate quorum",
        )
    with mock.patch.dict(os.environ, {"LLM_DECIDE_DISABLE": "0"}, clear=False), \
         mock.patch.object(subprocess, "run", return_value=SimpleNamespace(returncode=0)) as run:
        triage._trigger_vote(
            report_path, root / "product-vote.json", "codex", "fixture", root,
            target_root_is_product=True,
        )
        check(
            "--target-root-is-product" in run.call_args.args[0],
            "benchmark product boundary is passed explicitly to trigger validation",
        )
    validator = runpy.run_path(str(ROOT / "bin" / "validate-finding"))
    validator_args = validator["parse_args"]([
        "--finding", str(report_path), "--target-path", str(root),
        "--backend", "codex", "--gate", "trigger",
        "--target-root-is-product",
    ])
    product_prompt = validator["render_validator_prompt"](
        validator_args, {"report": _GOOD_REPORT}
    )
    check(
        "configured benchmark target root is the product boundary" in product_prompt
        and "Clause\n(d) still applies" in product_prompt,
        "product-root scope preserves non-shipping review below the root",
    )
    second_product_prompt = validator["render_validator_prompt"](
        validator_args, {"report": "different candidate"}
    )
    product_prefix = product_prompt.split("# Finding under review", 1)[0]
    second_prefix = second_product_prompt.split("# Finding under review", 1)[0]
    check(
        product_prefix == second_prefix and len(product_prefix) > 4000,
        "trigger validators share a long invariant prefix before candidate-specific facts",
    )
    batch_prompt = validator["render_trigger_batch_prompt"](
        validator_args,
        [{"id": "FIND-1", "facts": {"report": "A"}},
         {"id": "FIND-2", "facts": {"report": "B"}}],
    )
    check(
        batch_prompt.startswith(product_prefix)
        and '"id": "FIND-1"' in batch_prompt
        and "Review every item independently" in batch_prompt,
        "trigger batching shares startup context while retaining keyed independent reviews",
    )
    parsed_batch = validator["extract_vote_batch"](
        '{"items":[{"id":"FIND-1","vote":"Promote"},'
        '{"id":"FIND-2","vote":"Reject","disproof":"src/a.c:guard"}]}'
    )
    check(
        set(parsed_batch) == {"FIND-1", "FIND-2"},
        "trigger batch parser preserves exact keyed verdicts",
    )
    finding_args = validator["parse_args"]([
        "--finding", str(report_path), "--target-path", str(root),
        "--backend", "codex", "--gate", "finding",
    ])
    finding_prompt_a = validator["render_validator_prompt"](finding_args, {"report": "A"})
    finding_prompt_b = validator["render_validator_prompt"](finding_args, {"report": "B"})
    check(
        finding_prompt_a.split("# Finding under review", 1)[0]
        == finding_prompt_b.split("# Finding under review", 1)[0],
        "source validators place changing facts after their cacheable preamble",
    )
    validator_output = root / "validator-output.json"
    with mock.patch.object(
        validator["llm_invoke"], "run_agent_prompt", return_value=0,
    ) as validator_launch, mock.patch.object(
        validator["llm_invoke"], "extract_text",
        return_value='{"vote":"Uncertain","rationale":"open","trigger_path":"","disproof":"","surface_applies":"yes"}',
    ):
        validator_rc = validator["main"]([
            "--finding", str(report_path), "--target-path", str(root),
            "--backend", "codex", "--gate", "trigger",
            "--output", str(validator_output),
        ])
    check(
        validator_rc == 2
        and validator_launch.call_args.kwargs.get("cwd") == root / ".validator-cwd",
        "validator launches reuse a stable isolated cwd",
    )
    finding_root = root / "finding-trigger"
    finding = finding_root / "findings" / "FIND-001"
    finding.mkdir(parents=True)
    finding_report = finding / "report.md"
    finding_report.write_text(_GOOD_REPORT, encoding="utf-8")
    (finding / ".llm-find-quality.json").write_text(
        '{"decision_version":"v13-python","accept":true,"accept_count":2}\n',
        encoding="utf-8",
    )
    with mock.patch.dict(os.environ, {
        "ACTIVE_BACKEND": "codex", "TARGET_ROOT": str(root), "MODEL": "fixture",
    }, clear=False), mock.patch.object(triage, "_trigger_vote", return_value=1):
        finding_status = triage.validate_one_finding(finding, finding_root)
    check(finding_status == "rejected", "accepted finding still receives source-reading trigger validation")
    check((finding_root / "findings-rejected" / "FIND-001").is_dir(), "trigger-disproved finding is quarantined, not deleted")

    # ── #6 report-gate head+tail bound ──
    os.environ.pop("REPORT_GATE_MAX_BYTES", None)
    check(
        triage._report_gate_cap() == 96 * 1024,
        "default report gate cap stays below Linux's per-argument ceiling",
    )
    os.environ["REPORT_GATE_MAX_BYTES"] = "1000"
    small = root / "small.md"
    small.write_bytes(b"S" * 400)
    check(triage.read_report_bounded(small) == "S" * 400, "small report returned whole")
    big = root / "big.md"
    big.write_bytes(b"H" * 900 + b"M" * 600 + b"T" * 900)
    bounded = triage.read_report_bounded(big)
    check("elided by REPORT_GATE_MAX_BYTES" in bounded, "oversize report gets an elision marker (no silent drop)")
    check(bounded.startswith("H"), "oversize report keeps the head")
    check(bounded.rstrip().endswith("T"), "oversize report keeps the tail (closing sections survive)")
    check(len("".join(c for c in bounded if c in "HMT")) < 2400, "oversize report is actually bounded")
    os.environ["REPORT_GATE_MAX_BYTES"] = "1"
    one_byte = triage.read_report_bounded(big)
    check(
        one_byte.startswith("H") and not one_byte.endswith("T") and len(one_byte) < 500,
        "sub-four-byte report caps do not accidentally include the whole tail",
    )
    del os.environ["REPORT_GATE_MAX_BYTES"]

    # ── #3 prompt vocabulary neutralizer ──
    text = "This is exploitable; an attacker could exploit it.\n"
    neutral = vocab_rules.neutralize_string(text)
    check("exploitable" not in neutral, "neutralizer rewrites classifier-hot vocabulary")
    protected = "<!-- NOVOCAB -->\nkeep exploit verbatim\n<!-- /NOVOCAB -->\n"
    kept = vocab_rules.neutralize_string(protected)
    check("keep exploit verbatim" in kept, "NOVOCAB block is left verbatim")
    check("NOVOCAB" not in vocab_rules.strip_markers(kept), "strip_markers removes the sentinels")
    check(hasattr(audit_runner, "vocab_rules"), "audit runner imports the neutralizer for the prompt path")

    # ── #4 orchestrator signal handler kills the agent tree + frees the lock ──
    lock_dir = root / "sig-lock.d"
    lock_dir.mkdir()
    second_lock_dir = root / "sig-lock-2.d"
    second_lock_dir.mkdir()
    child_pid_file = root / "grandchild.pid"
    probe = (
        "import os,sys,signal,time,subprocess;"
        "sys.path.insert(0,%r);import audit_runner;"
        "from pathlib import Path;"
        "lock=Path(sys.argv[1]);"
        "lock2=Path(sys.argv[3]);"
        "(lock/'pid').write_text(str(os.getpid()));"
        "(lock2/'pid').write_text(str(os.getpid()));"
        "audit_runner._OWNED_INSTANCE_LOCKS.add(lock2);"
        "c=subprocess.Popen([sys.executable,'-c',"
        "\"import os,time;open(%%r,'w').write(str(os.getpid()));time.sleep(120)\"%%sys.argv[2]],"
        "preexec_fn=os.setsid);"
        "\nwith audit_runner._terminate_on_signal(lock):\n"
        " [time.sleep(0.05) for _ in range(200) if not os.path.exists(sys.argv[2])];"
        "print('READY',flush=True);time.sleep(120)"
    ) % str(ROOT / "lib")
    orchestrator = subprocess.Popen(
        [sys.executable, "-c", probe, str(lock_dir), str(child_pid_file), str(second_lock_dir)],
        stdout=subprocess.PIPE, text=True,
    )
    ready = orchestrator.stdout.readline().strip() if orchestrator.stdout else ""
    grandchild = 0
    for _ in range(100):
        if child_pid_file.exists():
            grandchild = int(child_pid_file.read_text().strip())
            break
        time.sleep(0.05)
    orchestrator.terminate()  # SIGTERM to the orchestrator
    rc = orchestrator.wait(timeout=10)
    time.sleep(0.3)
    grandchild_alive = False
    if grandchild:
        try:
            os.kill(grandchild, 0)
            grandchild_alive = True
        except ProcessLookupError:
            grandchild_alive = False
    if grandchild_alive:
        os.kill(grandchild, 9)
    check(ready == "READY", "signal-handler probe started")
    check(rc == -int(signal.SIGTERM) or rc == 128 + int(signal.SIGTERM),
          "orchestrator exits with SIGTERM status after cleanup", str(rc))
    check(not grandchild_alive, "SIGTERM kills the setsid'd agent tree (no orphan)")
    check(
        not lock_dir.exists() and not second_lock_dir.exists(),
        "SIGTERM releases every instance lock owned by an ensemble run",
    )

    # ── #5 gemini watchdog terminates a quota-stalled agent ──
    os.environ["GEMINI_WATCHDOG_POLL_SECS"] = "1"
    os.environ["GEMINI_QUOTA_MIN_429"] = "10"
    os.environ["USE_GEMINI_CLI"] = "1"
    raw_dir = root / "raw"
    raw_dir.mkdir()
    raw = raw_dir / "gemini-raw.log"
    marker_dir = root / "agent-scratch"
    marker_dir.mkdir()
    command = [
        sys.executable, "-c",
        "import time;[print('Attempt %d failed with status 429'%i,flush=True) "
        "for i in range(1,13)];time.sleep(120)",
    ]
    start = time.time()
    watchdog_rc = llm_invoke._run_gemini_with_watchdog(
        command, None, raw, root, os.environ.copy(), marker_dir
    )
    elapsed = time.time() - start
    check(watchdog_rc != 0, "watchdog terminates the quota-stalled backend")
    check(elapsed < 15, "quota-stalled agent dies well before the wall clock", f"{elapsed:.1f}s")
    check((marker_dir / ".quota-exhausted").is_file(), "quota marker is written to the caller's scratch directory")
    check(not (raw_dir / ".quota-exhausted").exists(), "quota marker is not misplaced beside the raw log")

    # A live-watchdog quota marker is conclusive even when the transcript also
    # contains a transient provider failure, and benchmark classification sees
    # the marker even if no readable transcript was produced.
    classifier_marker = root / "quota-classifier" / ".quota-exhausted"
    classifier_marker.parent.mkdir()
    classifier_marker.touch()
    check(
        audit_helpers._provider_issue_from_lines(
            ['{"type":"error","message":"status 503"}'], classifier_marker,
        ) == "capacity_limited",
        "watchdog quota marker outranks a transient transcript classification",
    )
    check(
        benchmark_runner._provider_issue(classifier_marker.parent) == "capacity_limited",
        "benchmark honors a quota marker even when the raw transcript is absent",
    )

    # quota_dominates reads only a bounded tail: a huge transcript whose 429
    # burst sits in the last lines is still detected, and a progress line in the
    # tail vetoes it — without re-reading the whole file each poll.
    big = root / "big-transcript.log"
    with big.open("w", encoding="utf-8") as stream:
        for _ in range(50_000):
            stream.write('{"type":"tool_result","content":"' + "y" * 300 + '"}\n')
        for i in range(1, 13):
            stream.write(f"Attempt {i} failed with status 429\n")
    check(gemini_watchdog.quota_dominates(big), "quota_dominates detects a 429 burst in a large transcript tail")
    with big.open("a", encoding="utf-8") as stream:
        stream.write('{"role":"assistant"}\n')
    check(
        not gemini_watchdog.quota_dominates(big),
        "a progress line in the tail vetoes the quota trigger",
    )
    long_line = root / "long-transcript-line.log"
    long_line.write_text(
        '{"role":"assistant","padding":"' + "z" * (2 << 20) + '"}\n'
        + "".join(f"Attempt {i} failed with status 429\n" for i in range(1, 13)),
        encoding="utf-8",
    )
    check(
        not gemini_watchdog.quota_dominates(long_line),
        "quota tail keeps exact line semantics when one recent event exceeds a fixed byte window",
    )

    klog_predicates = root / "predicate-cli.log"
    now_stamp = time.strftime("I%m%d %H:%M:%S.000")
    klog_predicates.write_text(
        f"{now_stamp} text_drip.go:123] Drip stopped\n"
        f"{now_stamp} fetchAvailableModels\n",
        encoding="utf-8",
    )
    check(gemini_watchdog.drip_stopped(str(klog_predicates)), "watchdog recognizes the Antigravity Drip-stopped marker")
    check(
        gemini_watchdog.in_idle_heartbeat_loop(str(klog_predicates), 60),
        "heartbeat without a recent stream call is classified as idle",
    )
    with klog_predicates.open("a", encoding="utf-8") as stream:
        stream.write(f"{now_stamp} streamGenerateContent\n")
    check(
        not gemini_watchdog.in_idle_heartbeat_loop(str(klog_predicates), 60),
        "a recent stream call prevents an idle-heartbeat classification",
    )
    with klog_predicates.open("a", encoding="utf-8") as stream:
        for _ in range(5_000):
            stream.write(f"{now_stamp} unrelated klog detail\n")
        stream.write(f"{now_stamp} fetchAvailableModels\n")
    check(
        not gemini_watchdog.in_idle_heartbeat_loop(str(klog_predicates), 60),
        "idle detection scans the complete time window rather than a fixed line tail",
    )

    large_sanitizer = root / "large-sanitizer.txt"
    large_sanitizer.write_text(
        "target output\n" * 100_000
        + "ERROR: AddressSanitizer: heap-buffer-overflow\n",
        encoding="utf-8",
    )
    check(
        triage.has_valid_diagnostic(triage._read(large_sanitizer)),
        "triage sees a sanitizer diagnostic beyond the bounded-read prefix",
    )
    check(
        verdict.file_has_crash(large_sanitizer),
        "streaming crash classification sees a diagnostic in a large log tail",
    )

    # Probe budgets remain mode-aware and counters reset at each iteration.
    budget_context = audit_runner.prompt.PromptContext(
        results_dir=root / "budget-results",
        target_root=root,
        target_slug="sample",
        reference_dir=root,
        num_agents=2,
        is_browser=True,
        browser_agents=1,
    )
    check(
        audit_runner.sanitizer_run_budget(budget_context, 1, {}) == 25,
        "browser agents receive the browser sanitizer budget",
    )
    check(
        audit_runner.sanitizer_run_budget(budget_context, 2, {}) == 60,
        "shell agents receive the shell sanitizer budget",
    )
    check(
        audit_runner.sanitizer_run_budget(
            budget_context, 1, {"SANITIZER_RUN_BUDGET_PER_ITERATION": "7"}) == 7,
        "global sanitizer budget override applies to every mode",
    )

    # A waiter must not return merely because the builder's output became
    # executable while the build lock is still owned. Returning there lets the
    # waiter delete another process's lock in HarnessBuilder.build().
    probe_module = runpy.run_path(str(ROOT / "bin" / "probe"))
    builder = object.__new__(probe_module["HarnessBuilder"])
    build_lock = root / "harness.lock"
    build_lock.mkdir()
    (build_lock / "owner").write_text(f"pid={os.getpid()}\n", encoding="utf-8")
    built_binary = root / "harness.bin"
    built_binary.write_text("complete", encoding="utf-8")
    built_binary.chmod(0o755)
    build_failure = root / "harness.build.log"
    acquired = []
    with mock.patch.dict(os.environ, {"PROBE_HARNESS_BUILD_LOCK_TIMEOUT": "2"}, clear=False):
        waiter = threading.Thread(
            target=lambda: (builder._acquire(build_lock, built_binary, build_failure), acquired.append(True))
        )
        waiter.start()
        time.sleep(0.1)
        still_waiting = waiter.is_alive()
        (build_lock / "owner").unlink()
        build_lock.rmdir()
        waiter.join(timeout=2)
    check(
        still_waiting and acquired == [True] and (build_lock / "owner").is_file(),
        "harness build waiter acquires lock ownership before returning",
    )
    shutil.rmtree(build_lock, ignore_errors=True)
    # A holder releasing the lock mid-check must not crash the waiter's
    # staleness probe; a vanished lock is "not stale" so the next mkdir wins.
    check(
        builder._stale(root / "harness.lock.released") is False,
        "stale check tolerates a lock released during the check",
    )
    budget_logs = root / "budget-logs"
    budget_logs.mkdir()
    runtime_stub = mock.Mock(logs=budget_logs, num_agents=2)
    (budget_logs / ".sanitizer_runs_1").write_text("9", encoding="utf-8")
    audit_runner.reset_sanitizer_run_counters(runtime_stub)
    check(
        all((budget_logs / f".sanitizer_runs_{agent}").read_text() == "0" for agent in (1, 2)),
        "sanitizer counters reset for every agent before an iteration",
    )
    for path in (
        budget_logs / ".llm_decisions_harness",
        budget_logs / ".llm_decisions_1",
        budget_logs / ".llm_decisions_2",
    ):
        path.write_text("1000", encoding="utf-8")
    audit_runner.reset_llm_decision_counters(runtime_stub)
    check(
        all(
            path.read_text(encoding="utf-8") == "0"
            for path in (
                budget_logs / ".llm_decisions_harness",
                budget_logs / ".llm_decisions_1",
                budget_logs / ".llm_decisions_2",
            )
        ),
        "LLM decision counters reset for the harness and every agent before an iteration",
    )

    # Idle secondary agents are skipped only when no active hypothesis, work
    # card, or fuzz lead remains. Agent 1 always launches to make progress.
    skip_results = root / "skip-results"
    skip_results.mkdir()
    skip_runtime = mock.Mock(
        root=ROOT, results=skip_results, target_root=root,
        target_slug="sampleproj", repo_type="none",
    )
    skip_context = mock.Mock()
    skip_context.num_agents = 2
    skip_context.mode.return_value = "generic"
    skip_context.role.return_value = "reproduce"
    skip_context.strategy.return_value = "S1"
    with mock.patch.object(audit_runner.structured_state, "agent_counts", return_value={"active": 0}):
        check(
            not audit_runner.should_skip_launch(skip_runtime, skip_context, 1),
            "primary agent always launches even when the queue is empty",
        )
        check(
            audit_runner.should_skip_launch(skip_runtime, skip_context, 2),
            "idle secondary agent skips an empty iteration",
        )
        (skip_results / "fuzz-leads.md").write_text("candidate input\n", encoding="utf-8")
        check(
            not audit_runner.should_skip_launch(skip_runtime, skip_context, 2),
            "a fuzz lead keeps an idle secondary agent active",
        )
        (skip_results / "fuzz-leads.md").unlink()
        (skip_results / "work-cards.jsonl").write_text('{"id":"WORK-1"}\n', encoding="utf-8")
        with mock.patch.object(
            audit_runner.workqueue, "claim_next_card", return_value={"id": "WORK"},
        ):
            check(
                not audit_runner.should_skip_launch(skip_runtime, skip_context, 2),
                "an eligible work card keeps an idle secondary agent active",
            )
    with mock.patch.object(audit_runner.structured_state, "agent_counts", return_value={"active": 1}):
        check(
            not audit_runner.should_skip_launch(skip_runtime, skip_context, 2),
            "an active hypothesis keeps a secondary agent active",
        )

    # bin/audit owns the native build lazily: before agents spawn it rebuilds a
    # stale/missing sanitizer tree via setup-target --build so nobody audits a binary
    # the source moved past. (The old shell audit had this preflight; the Python
    # port must keep it.)
    pf_harness = root / "preflight-harness"
    pf_target = pf_harness / "targets" / "sampleproj"
    pf_target.mkdir(parents=True)
    pf_logs = root / "preflight-logs"
    pf_logs.mkdir()
    pf_results = root / "preflight-results"
    pf_raw = pf_logs / ".raw"
    pf_results.mkdir()
    pf_raw.mkdir()
    pf_runtime = audit_runner.Runtime(
        root=pf_harness,
        target_root=pf_target,
        target_slug="sampleproj",
        output_slug="sampleproj",
        backend="claude",
        model="",
        config=target_config.Config(
            target_root=str(pf_target),
            is_browser="0",
            sanitizers_explicitly_disabled=False,
            sanitizers_enabled=["asan"],
        ),
        target_rev="HEAD",
        repo_type="none",
        results=pf_results,
        logs=pf_logs,
        raw=pf_raw,
        index=pf_logs / "index.log",
        index_jsonl=pf_logs / "index.jsonl",
        num_agents=1,
        browser_agents=0,
        shell_agents=1,
        agent_roles=(),
        fixed_strategy="",
        decision_timeout=45,
    )
    with mock.patch.object(audit_runner.target_config, "build_freshness", return_value="fresh"), \
         mock.patch.object(audit_runner.build_preflight.subprocess, "run") as pf_run_fresh:
        audit_runner.preflight_build(pf_runtime)
    check(
        pf_run_fresh.call_count == 0,
        "preflight does not invoke setup-target when the build is fresh",
    )
    # missing before the (mocked) build, fresh after — verifies the re-probe.
    pf_states = iter(["missing", "fresh"])
    with mock.patch.object(audit_runner.target_config, "build_freshness",
                           side_effect=lambda troot, san="asan": next(pf_states)), \
         mock.patch.object(audit_runner.build_preflight.subprocess, "run",
                           return_value=mock.Mock(returncode=0)) as pf_run_missing:
        audit_runner.preflight_build(pf_runtime)
    pf_argv = pf_run_missing.call_args[0][0]
    check(
        pf_run_missing.call_count == 1
        and pf_argv[0].endswith("bin/setup-target")
        and pf_argv[1] == "sampleproj" and "--build" in pf_argv,
        "preflight rebuilds a missing ASan tree via setup-target --build",
    )
    # A build that stays stale must WARN, not silently proceed as if fresh.
    with mock.patch.object(audit_runner.target_config, "build_freshness", return_value="stale"), \
         mock.patch.object(audit_runner.build_preflight.subprocess, "run", return_value=mock.Mock(returncode=0)):
        audit_runner.preflight_build(pf_runtime)
    check(
        "WARN: sanitizer builds still stale/missing" in (pf_logs / "index.log").read_text(encoding="utf-8"),
        "preflight WARNs when the build is still stale after a rebuild attempt",
    )
    # Every enabled native sanitizer matters. A fresh ASan tree must not hide a
    # missing UBSan tree that agents are explicitly allowed to probe.
    pf_runtime.config.sanitizers_enabled = ["asan", "ubsan"]
    pf_states = iter(["fresh", "missing", "fresh", "fresh"])
    with mock.patch.object(
        audit_runner.target_config, "build_freshness",
        side_effect=lambda troot, san="asan": next(pf_states),
    ), mock.patch.object(
        audit_runner.build_preflight.subprocess, "run", return_value=mock.Mock(returncode=0)
    ) as pf_run_multisan:
        audit_runner.preflight_build(pf_runtime)
    check(
        pf_run_multisan.call_count == 1,
        "preflight rebuilds when any enabled native sanitizer tree is missing",
    )
    pf_runtime.config.sanitizers_enabled = ["asan"]
    # Failure to launch setup-target is visible but cannot abort the audit.
    with mock.patch.object(
        audit_runner.target_config, "build_freshness", return_value="missing"
    ), mock.patch.object(
        audit_runner.build_preflight.subprocess, "run", side_effect=OSError("synthetic launch failure")
    ):
        audit_runner.preflight_build(pf_runtime)
    check(
        "build preflight could not run; continuing" in
        (pf_logs / "index.log").read_text(encoding="utf-8"),
        "preflight launch failure warns and falls open",
    )
    # setup-target resolves targets beneath the harness root. An external
    # --target-path must never accidentally build a same-named in-tree target.
    pf_runtime.target_root = root / "external-target"
    pf_runtime.target_root.mkdir()
    with mock.patch.object(
        audit_runner.target_config, "build_freshness", return_value="missing"
    ), mock.patch.object(audit_runner.build_preflight.subprocess, "run") as pf_run_external:
        audit_runner.preflight_build(pf_runtime)
    check(
        pf_run_external.call_count == 0
        and "external --target-path" in (pf_logs / "index.log").read_text(encoding="utf-8"),
        "preflight never redirects an external target build to the in-tree slug",
    )
    pf_runtime.target_root = pf_target
    # Browser targets skip native build probing, then exercise the sanitizer
    # wrapper canary before agents launch.
    pf_runtime.config.is_browser = "1"
    def write_canary(*_args, **_kwargs):
        (pf_results / ".preflight" / "canary-asan.txt").write_text(
            "TESTCASE_EXECUTED\n", encoding="utf-8",
        )
        return mock.Mock(returncode=0)
    with mock.patch.object(audit_runner.target_config, "build_freshness") as pf_browser_probe, \
         mock.patch.object(audit_runner.subprocess, "run", side_effect=write_canary) as pf_canary:
        audit_runner.preflight_build(pf_runtime)
    check(
        pf_browser_probe.call_count == 0 and pf_canary.call_count == 1,
        "browser preflight skips native freshness and runs the sanitizer canary",
    )

    # Sanitizer-disabled generic targets have no native build recipe or canary.
    pf_runtime.config.is_browser = "0"
    pf_runtime.config.sanitizers_explicitly_disabled = True
    with mock.patch.object(audit_runner.target_config, "build_freshness") as pf_disabled_probe, \
         mock.patch.object(audit_runner.subprocess, "run") as pf_disabled_run:
        audit_runner.preflight_build(pf_runtime)
    check(
        pf_disabled_probe.call_count == 0 and pf_disabled_run.call_count == 0,
        "preflight skips sanitizer-disabled targets without probing or running a canary",
    )

    # Pool finalization must persist LLM-derived reach facts into the report:
    # bin/severity intentionally ignores auxiliary sidecars after the Python
    # migration, so a sidecar-only port would silently leave scoring unchanged.
    reach_dir = root / "reach-fields" / "crashes" / "CRASH-001"
    reach_dir.mkdir(parents=True)
    reach_report = reach_dir / "report.md"
    reach_report.write_text(
        "# Sequence-shaped lifetime issue\n\n"
        "| Field | Value |\n| :---- | :---- |\n"
        "| Caller controls | — |\n| Boundary | — |\n\n"
        "Trigger source: bytes\n\n"
        "A parsed object is removed by one public call and consumed by a later public call.\n",
        encoding="utf-8",
    )
    reach_decision = {
        "surface": "library-api — public object API",
        "primitive": "uaf_read",
        "class": "memory-safety",
        "caller_contract": "obeyed",
        "caller_controls": "call-sequence",
        "trigger_source": "both",
        "parameter_control": "application-supplied",
        "trusted_caller_actions": "normal public call",
        "boundary": "caller-created object graph",
        "advisory": "no",
    }
    with mock.patch.object(triage.llm_decide, "llm_decide", return_value=reach_decision):
        reach_changed = triage.fill_reach_fields(reach_dir)
    reach_text = reach_report.read_text(encoding="utf-8")
    check(reach_changed, "reach-field convergence updates an incomplete report")
    check(
        "Caller controls: call-sequence" in reach_text
        and "Boundary: caller-created object graph" in reach_text,
        "reach-field convergence materializes validated fallback fields in the report",
    )
    check(
        reach_text.count("Trigger source:") == 1 and "Trigger source: bytes" in reach_text,
        "reach-field convergence never overwrites an authored field",
    )
    with mock.patch.object(triage.llm_decide, "llm_decide") as no_refill:
        check(not triage.fill_reach_fields(reach_dir), "complete reach fields are idempotent")
    check(no_refill.call_count == 0, "complete reach fields spend no additional LLM decision")
    severity_run = subprocess.run(
        [str(ROOT / "bin" / "severity"), "--report", str(reach_dir), "--json"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
    )
    severity_payload = json.loads(severity_run.stdout)["severity"]
    check(severity_run.returncode == 0, "severity scores the converged report", severity_run.stderr)
    check(
        severity_payload["fields_used"]["caller_controls"] == "call-sequence",
        "severity consumes persisted reach fields without a sidecar fallback",
    )
    batch_reach_root = root / "batch-reach"
    for name in ("FIND-001", "FIND-002"):
        directory = batch_reach_root / "findings" / name
        directory.mkdir(parents=True)
        (directory / "report.md").write_text(
            f"# {name}\n\nA public input reaches a stale object.\n", encoding="utf-8",
        )
    batch_reach_result = {"items": [
        {"id": "FIND-001", **reach_decision},
        {"id": "FIND-002", **reach_decision},
    ]}
    with mock.patch.object(
        triage.llm_decide, "llm_decide", return_value=batch_reach_result,
    ) as batch_reach_call:
        batch_reach_count = triage.fill_reach_fields_tree(batch_reach_root)
    check(
        batch_reach_count == 2 and batch_reach_call.call_count == 1,
        "reach-field convergence batches independent reports in one provider call",
    )
    check(
        all(
            "Caller controls: call-sequence" in
            (batch_reach_root / "findings" / name / "report.md").read_text(encoding="utf-8")
            for name in ("FIND-001", "FIND-002")
        ),
        "batched reach fields are applied only to their keyed reports",
    )
    missing_batch_root = root / "missing-batch-reach"
    missing_batch_dir = missing_batch_root / "findings" / "FIND-003"
    missing_batch_dir.mkdir(parents=True)
    (missing_batch_dir / "report.md").write_text(
        "# FIND-003\n\nA public input reaches stale state.\n", encoding="utf-8",
    )
    with mock.patch.object(
        triage.llm_decide, "llm_decide", return_value={"items": []},
    ) as missing_batch_call:
        check(
            triage.fill_reach_fields_tree(missing_batch_root) == 0
            and missing_batch_call.call_count == 1,
            "a missing keyed reachability result stays pending without individual fan-out",
        )

    batch_quality_root = root / "batch-quality"
    batch_quality_dirs = []
    for name in ("FIND-011", "FIND-012"):
        directory = batch_quality_root / "findings" / name
        directory.mkdir(parents=True)
        (directory / "report.md").write_text(
            f"# {name}\n\nA caller-controlled request bypasses authorization.\n",
            encoding="utf-8",
        )
        batch_quality_dirs.append(directory)
    quality_result = {"items": [
        {"id": directory.name, "accept": True, "reason": "security boundary bypass",
         "class": "auth:bypass", "severity": "high"}
        for directory in batch_quality_dirs
    ]}
    with mock.patch.object(
        triage.llm_decide, "llm_decide", return_value=quality_result,
    ) as batch_quality_calls, mock.patch.object(
        triage, "_finalize_accepted_finding", return_value="accepted",
    ), mock.patch.object(
        triage, "_prepare_accepted_finding",
        side_effect=lambda _directory, report, *_args: report,
    ), mock.patch.object(
        triage, "_batch_reach_field_decisions", return_value=(set(), {}),
    ):
        batch_quality_counts = triage.validate_find_gate(batch_quality_root)
    check(
        batch_quality_counts == {"accepted": 2, "rejected": 0, "pending": 0}
        and batch_quality_calls.call_count == 2,
        "finding quality preserves two independent vote rounds while batching startup",
    )
    check(
        all((directory / ".llm-find-quality.json").is_file() for directory in batch_quality_dirs),
        "batched finding votes persist the same terminal quorum state",
    )
    live_root = root / "live-reach"
    (live_root / "crashes-rejected").mkdir(parents=True)
    live_crash = _crash_dir(
        live_root, "CRASH-090", report="# Lifetime issue\n\nPublic calls leave a stale object.\n",
        sanitizer=_ASAN, testcase=True,
    )
    with mock.patch.object(triage, "_bundle_needs_refresh", return_value=False), \
         mock.patch.object(triage, "_bundle_missing_artifacts", return_value=[]), \
         mock.patch.object(triage.llm_decide, "llm_decide", return_value=reach_decision), \
         mock.patch.object(triage, "_run_tool") as live_tools:
        live_status = triage.triage_one_crash(
            live_crash, live_root, root, "sampleproj", ["bytes", "call-sequence"]
        )
    check(live_status == "promoted", "live crash triage fills reach fields before its verdict")
    check(
        "Caller contract: obeyed" in (live_crash / "REPORT.md").read_text(encoding="utf-8")
        and any(call.args[:2] == ("severity", "--report") for call in live_tools.call_args_list),
        "live crash finalization persists fields before severity scoring",
    )

    live_finding_root = root / "live-finding"
    live_finding = live_finding_root / "findings/FIND-090"
    live_finding.mkdir(parents=True)
    (live_finding / "report.md").write_text(
        "# State issue\n\nA public input reaches inconsistent authorization state.\n",
        encoding="utf-8",
    )
    (live_finding / ".llm-find-quality.json").write_text(json.dumps({
        "decision_version": "v13-python", "accept": True, "accept_count": 2,
    }), encoding="utf-8")
    with mock.patch.object(triage.llm_decide, "llm_decide", return_value=reach_decision), \
         mock.patch.object(triage, "_finding_trigger_rejected", return_value=False), \
         mock.patch.object(triage, "_run_tool") as finding_tools:
        finding_status = triage.validate_one_finding(live_finding, live_finding_root)
    check(finding_status == "accepted", "live finding finalization fills reach fields")
    check(
        "Caller controls: call-sequence" in (live_finding / "report.md").read_text(encoding="utf-8")
        and finding_tools.call_args.args[:2] == ("severity", "--report"),
        "live finding severity consumes the converged report",
    )

    # split_pool creates condition directories after combined clustering. Every
    # condition must pass through the shared index maintainer so its cluster
    # reports, member Cluster lines, enrichment, and HTML all agree locally.
    condition_pool = root / "condition-pool"
    for name in ("crashes", "findings", "model-direct", "harness"):
        (condition_pool / name).mkdir(parents=True)
    finalized: list[tuple[str, str, str]] = []

    def _record_condition(path, _target, **_kwargs):
        finalized.append((Path(path).name, os.environ.get("BACKEND", ""), os.environ.get("MODEL", "")))
        return True

    with mock.patch.object(triage, "maintain_indexes", side_effect=_record_condition):
        benchmark_runner._finalize_condition_pools(
            condition_pool, root / "target", "codex", "test-model", "sampleproj",
            root / "decisions.log",
        )
    check(
        finalized == [("harness", "codex", "test-model"), ("model-direct", "codex", "test-model")],
        "condition finalization indexes every split condition and skips combined artifact roots",
        repr(finalized),
    )

    render_root = root / "batched-report-render"
    render_reports = []
    for parent, name in (("crashes", "CRASH-001"), ("findings", "FIND-001")):
        directory = render_root / parent / name
        directory.mkdir(parents=True)
        report = directory / "report.md"
        report.write_text(f"# {name}\n", encoding="utf-8")
        render_reports.append(triage._report(directory))
    render_calls: list[tuple[str, ...]] = []
    enrich_inputs: list[bytes | None] = []

    def _record_render_tool(*args, **_kwargs):
        render_calls.append(tuple(args))
        if args[0] == "enrich-report":
            enrich_inputs.append(_kwargs.get("stdin_data"))
        return 0

    with mock.patch.object(triage, "_run_tool", side_effect=_record_render_tool):
        render_ok = triage._render_reports(render_root, workers=2)
    enrich_calls = [call for call in render_calls if call[0] == "enrich-report"]
    html_calls = [call for call in render_calls if call[0] == "render-md"]
    check(
        render_ok
        and len(enrich_calls) == 1
        and enrich_calls[0] == ("enrich-report", "--quiet", "--paths-from-stdin")
        and len(enrich_inputs) == 1
        and enrich_inputs[0] is not None
        and set(enrich_inputs[0].rstrip(b"\0").split(b"\0"))
            == {os.fsencode(report) for report in render_reports},
        "housekeeping enriches every report in one shared process",
        repr(render_calls),
    )
    check(
        len(html_calls) == 2,
        "housekeeping still renders report HTML in parallel",
        repr(render_calls),
    )

    # The wall-clock timeout wrapper is the watched root process. The agy klog
    # is opened by its CLI descendant, so discovery must walk descendants.
    klog_dir = root / "antigravity-cli" / "log"
    klog_dir.mkdir(parents=True)
    klog = klog_dir / "cli-test.log"
    wrapper = subprocess.Popen([
        sys.executable, "-c",
        "import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',"
        "%r]);time.sleep(120)" % (
            "import time;f=open(%r,'a');f.flush();time.sleep(120)" % str(klog),
        ),
    ])
    for _ in range(50):
        if klog.exists():
            break
        time.sleep(0.1)
    located = gemini_watchdog.cli_log_for_pid(wrapper.pid)
    process_tree.kill_descendants(wrapper.pid, signal.SIGTERM, 0.1)
    wrapper.terminate()
    wrapper.wait(timeout=5)
    check(
        bool(located) and Path(located).resolve() == klog.resolve(),
        "watchdog discovers an agy klog opened by a timeout-wrapper descendant",
        located,
    )
    for key in ("GEMINI_WATCHDOG_POLL_SECS", "GEMINI_QUOTA_MIN_429", "USE_GEMINI_CLI"):
        os.environ.pop(key, None)

print(f"\n{passed}/{passed + failed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
