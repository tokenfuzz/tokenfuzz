#!/usr/bin/env python3
"""Behavior tests for the Python modules that replaced sourced shell libraries."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner
import benchmark_runner
import crash_bundle
import edges
import llm_decide
import llm_invoke
import llm_usage
import prompt
import sanitizer
import sanitizer_run
import structured_state
import target_config
import triage
import verdict
import vocab_rules
from timeout import run_timeout

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


def equal(expected, actual, name: str) -> None:
    check(expected == actual, name, f"expected={expected!r} actual={actual!r}")


with tempfile.TemporaryDirectory(prefix="migration-modules-") as temporary:
    root = Path(temporary)

    harness_results = root / "harness-layout" / "grok" / "results"
    sibling_index = harness_results.parent / "logs" / "index.jsonl"
    sibling_index.parent.mkdir(parents=True)
    sibling_index.write_text("{}\n", encoding="utf-8")
    # An ancillary in-results log directory must not split final decisions
    # away from the already-populated harness ledger.
    (harness_results / "logs").mkdir(parents=True)
    equal(
        sibling_index, llm_usage.find_usage_index(harness_results),
        "harness usage keeps the sibling ledger when results/logs also exists",
    )
    standalone_results = root / "standalone" / "results"
    standalone_index = standalone_results / "logs" / "index.jsonl"
    standalone_index.parent.mkdir(parents=True)
    standalone_index.write_text("{}\n", encoding="utf-8")
    equal(
        standalone_index, llm_usage.find_usage_index(standalone_results),
        "an existing standalone in-tree ledger remains readable",
    )
    (standalone_results.parent / "logs").mkdir()
    equal(
        standalone_index, llm_usage.find_usage_index(standalone_results),
        "an empty sibling log directory cannot displace an existing in-tree ledger",
    )
    direct_results = root / "model-direct-r1"
    equal(
        direct_results / "logs" / "index.jsonl",
        llm_usage.find_usage_index(direct_results),
        "model-direct usage keeps its in-tree ledger",
    )

    incomplete_cell_dir = root / "incomplete-cell"
    incomplete_cell_dir.mkdir()
    benchmark_runner.write_cell(
        incomplete_cell_dir / "cell.json", "harness", 1, "fixture",
        incomplete_cell_dir / "results", 10, "incomplete", None,
    )
    incomplete_cell = json.loads(
        (incomplete_cell_dir / "cell.json").read_text(encoding="utf-8")
    )
    equal(
        "incomplete", incomplete_cell["run_quality"],
        "artifact-incomplete cell is not mislabeled as provider-limited",
    )
    (incomplete_cell_dir / ".run-quality").write_text(
        "provider_limited\n", encoding="utf-8"
    )
    benchmark_runner.write_cell(
        incomplete_cell_dir / "cell.json", "harness", 1, "fixture",
        incomplete_cell_dir / "results", 10, "incomplete", None,
    )
    limited_cell = json.loads(
        (incomplete_cell_dir / "cell.json").read_text(encoding="utf-8")
    )
    equal(
        "provider_limited", limited_cell["run_quality"],
        "explicit provider-limit evidence retains its specific label",
    )
    cli_cell_dir = root / "cli-incomplete-cell"
    cli_cell_dir.mkdir()
    benchmark_module = __import__("benchmark")
    benchmark_module._cmd_write_cell(SimpleNamespace(
        path=str(cli_cell_dir / "cell.json"), condition="harness",
        replicate="1", experiment="fixture", results_dir=str(cli_cell_dir / "results"),
        wall_seconds="10", status="incomplete", requested_agents="",
        paused_seconds="0",
    ))
    cli_cell = json.loads(
        (cli_cell_dir / "cell.json").read_text(encoding="utf-8")
    )
    equal(
        "incomplete", cli_cell["run_quality"],
        "benchmark metadata CLI uses the same factual incomplete label",
    )

    # A productive session whose usage was never recorded (the zero-token
    # `primary` row) understates the cell total, so the cell must read
    # `unknown` — not hide behind the `mixed` that measured+estimated
    # decisions produce on every normal cell.
    missing_primary = root / "missing-primary-usage.jsonl"
    missing_primary.write_text(
        '{"backend":"codex","role":"primary","tokens":{"input":0,"output":0}}\n'
        '{"backend":"codex","role":"decision","tokens":{"input":10,"output":2}}\n',
        encoding="utf-8",
    )
    usage = __import__("benchmark").harvest_tokens(missing_primary)
    equal(
        "unknown", usage["token_source"],
        "a missing productive session makes the cell token source unknown",
    )
    # A fully-recorded cell that merely mixes measured + estimated decisions
    # must stay distinguishable from the missing-session case above, or the
    # `unknown` flag is useless.
    measured_estimated = root / "measured-estimated-usage.jsonl"
    measured_estimated.write_text(
        '{"backend":"codex","role":"decision","tokens":{"input":10,"output":2}}\n'
        '{"backend":"codex","role":"decision","estimated":true,'
        '"tokens":{"input":8,"output":1}}\n',
        encoding="utf-8",
    )
    usage_me = __import__("benchmark").harvest_tokens(measured_estimated)
    equal(
        "mixed", usage_me["token_source"],
        "measured+estimated stays 'mixed', distinct from a missing session",
    )
    incomplete_decision = root / "incomplete-decision-usage.jsonl"
    incomplete_decision.write_text(
        '{"backend":"claude","usage_complete":false,'
        '"tokens":{"input":10,"output":2}}\n', encoding="utf-8",
    )
    equal(
        "unknown", __import__("benchmark").harvest_tokens(incomplete_decision)["token_source"],
        "partial decision telemetry keeps the cell total explicitly unknown",
    )
    check(
        not llm_usage.usage_is_complete(
            {"estimated": False, "tokens": {"input": 0, "output": 0}}, 0,
        ),
        "a successful native session without terminal telemetry is incomplete",
    )

    state = root / "results" / "state"
    state.mkdir(parents=True)
    hypotheses = state / "hypotheses.jsonl"
    hypotheses.write_text(
        '{"agent":"1","status":"PENDING","file":"src/a.c","strategy":"S5"}\n'
        'not-json\n'
        '{"agent":"1","status":"DISCARDED","file":"src/b.c"}\n'
        '{"agent":"2","status":"NEEDS_TESTCASE","file":"lib/x.c"}\n',
        encoding="utf-8",
    )
    counts = structured_state.agent_counts("1", root / "results")
    equal(2, counts["total"], "structured state ignores corrupt JSONL rows")
    equal(1, counts["active"], "structured state counts active statuses")
    with mock.patch.dict(os.environ, {"RESULTS_DIR": str(root / "results")}, clear=False):
        equal("src/a.c", structured_state.agent_subsystem("1"), "structured state preserves generic subsystem paths")
        equal("S5", structured_state.latest_strategy("1"), "structured state reads latest strategy")

    edge_log = root / "edges.log"
    edge_log.write_text("parse_a\nsrc/a.c:10:4\nparse_b\nlib/b.c:2:1\nparse_a\nsrc/a.c:10:9\n", encoding="utf-8")
    extracted = edges.extract(edge_log)
    equal(["parse_a|src/a.c:10", "parse_b|lib/b.c:2"], extracted, "edge extraction de-duplicates and sorts")
    edge_journal = root / "edge-journal"
    edge_journal.write_text("\n".join(extracted) + "\n", encoding="utf-8")
    equal(set(extracted), edges.file_edges(edge_journal), "edge journals load as sets")

    env = {"TARGET_ROOT": str(root / "target"), "AUDIT_BUILD_SUFFIX": "-img42"}
    equal(root / "target" / "build-asan-img42", sanitizer.build_dir("asan", env=env), "sanitizer build suffix is centralized")
    runtime = sanitizer.prepare_runtime_env("asan", {"PATH": "/bin", "ASAN_OPTIONS": "stale"})
    check("ASAN_OPTIONS" in runtime and "MSAN_OPTIONS" not in runtime, "sanitizer runtime keeps only the selected sanitizer options")
    check(sanitizer.validate_fuzzer_name("Parse_target_2"), "sanitizer accepts safe fuzzer names")
    check(not sanitizer.validate_fuzzer_name("../target"), "sanitizer rejects unsafe fuzzer names")
    equal("detect_leaks=0", sanitizer.runtime_options("asan", "detect_leaks=0", {}), "sanitizer options preserve explicit base")
    equal(
        "base:symbolize=1:symbolize=0",
        sanitizer.runtime_options(
            "asan", "base", {"ASAN_OPTIONS": "symbolize=1"}, "symbolize=0"
        ),
        "forced sanitizer options follow and override the ambient environment",
    )
    option_rows = []
    for line in sanitizer.OPTIONS_FILE.read_text(encoding="utf-8").splitlines():
        fields = line.split(None, 2)
        if len(fields) == 3 and not fields[0].startswith("#"):
            option_rows.append(tuple(fields))
    expected_modes = {
        *(('asan', mode) for mode in ('full', 'minimal', 'js', 'xpcshell', 'fuzz', 'fuzz-repro')),
        *(('ubsan', mode) for mode in ('full', 'minimal', 'js', 'fuzz', 'fuzz-repro')),
        *(('msan', mode) for mode in ('full', 'js', 'fuzz', 'fuzz-repro')),
        *(('tsan', mode) for mode in ('full', 'js', 'fuzz', 'fuzz-repro')),
    }
    check(
        expected_modes <= {(name, mode) for name, mode, _ in option_rows},
        "sanitizer option table covers every supported runtime mode",
    )
    for sanitizer_name, mode, expected in option_rows:
        equal(
            expected,
            sanitizer.options_for(sanitizer_name, mode),
            f"sanitizer option table round-trips {sanitizer_name}/{mode}",
        )

    executable = root / "runner.py"
    executable.write_text("#!/usr/bin/env python3\nimport sys\nprint(open(sys.argv[1]).read().strip())\n", encoding="utf-8")
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    testcase = root / "input.txt"
    testcase.write_text("EXECUTED\n", encoding="utf-8")
    runner = sanitizer_run.SanitizerRunner("ubsan", env={"UBSAN_GENERIC_BIN": str(executable), "PATH": os.environ["PATH"]})
    with mock.patch.object(sanitizer, "symbolize_available", return_value=False):
        equal(0, runner.generic("", 5, [str(testcase)]), "sanitizer generic runner executes configured command")
    equal(1, sanitizer_run.run_standard("ubsan", []), "sanitizer runner rejects a missing mode")

    crash_log = root / "verdict-crash.log"
    crash_log.write_text("==7==ERROR: AddressSanitizer: heap-buffer-overflow\n", encoding="utf-8")
    check(verdict.file_has_crash(crash_log), "verdict recognizes an ASan crash")
    crash_log.write_text("WARNING: DATA RACE\n", encoding="utf-8")
    check(verdict.file_has_crash(crash_log), "verdict recognizes a Go race diagnostic")
    crash_log.write_text("panic: runtime error: index out of range\n", encoding="utf-8")
    check(verdict.file_has_crash(crash_log), "verdict recognizes a managed-runtime crash")
    clean_log = root / "verdict-clean.log"
    clean_log.write_text("[probe] asan EXECUTION VERIFIED (post-run, rc=0)\n", encoding="utf-8")
    check(verdict.file_is_clean(clean_log), "verdict recognizes verified clean probe output")
    check(not verdict.file_has_crash(clean_log), "clean execution is not classified as a crash")

    raw_report = root / "raw-symbols.txt"
    raw_report.write_text("    #0 0x123  (/tmp/apptool+0x123)\n", encoding="utf-8")
    symbolizer_command = []
    def _fake_symbolizer(command, **kwargs):
        symbolizer_command.extend(command)
        kwargs["stdout"].write(b"    #0 0x123 in app_parse sample.c:42\n")
        return SimpleNamespace(returncode=0)
    with mock.patch.object(sanitizer.sys, "platform", "darwin"), \
         mock.patch.object(sanitizer.shutil, "which", side_effect=lambda name: "/usr/bin/atos" if name == "atos" else None), \
         mock.patch.object(sanitizer.subprocess, "run", side_effect=_fake_symbolizer):
        sanitizer.symbolize_file(raw_report)
    check(
        "--no-llvm-symbolizer" in symbolizer_command,
        "macOS offline symbolization explicitly prefers debug-map-aware atos",
        repr(symbolizer_command),
    )
    check("sample.c:42" in raw_report.read_text(), "offline symbolization replaces raw frames in place")

    completed = run_timeout([sys.executable, "-c", "print('timeout-ok')"], 2, capture_output=True)
    check(completed.returncode == 0 and completed.stdout.strip() == b"timeout-ok", "timeout runner captures successful commands")
    completed = run_timeout([sys.executable, "-c", "import time; time.sleep(2)"], 1, capture_output=True)
    equal(124, completed.returncode, "timeout runner terminates expired commands")

    with mock.patch.dict(os.environ, {"LLM_DECIDE_MOCK_THREAT_MODEL_SUGGEST": '{"attacker_controls":["bytes"],"reasoning":"fixture"}'}, clear=False):
        equal(
            {"attacker_controls": ["bytes"], "reasoning": "fixture"},
            llm_decide.llm_decide("threat-model-suggest", "attacker_controls,reasoning", "suggest", 2),
            "LLM decision mocks use the Python engine",
        )
    equal("reproducer and external party", vocab_rules.neutralize_line("exploit and attacker"), "vocabulary normalization remains available in Python")

    references = root / "references"
    (references / "strategies").mkdir(parents=True)
    (references / "session-rules.digest.md").write_text("DIGEST\n", encoding="utf-8")
    (root / "target").mkdir()
    results = root / "prompt-results"
    (results / "state").mkdir(parents=True)
    context = prompt.PromptContext(
        results, root / "target", "demo", references, 3,
        is_browser=True, browser_agents=1,
    )
    equal("browser", context.mode(1), "prompt assigns the configured browser worker")
    equal("shell", context.mode(2), "prompt assigns remaining browser-target workers shell mode")
    equal("analysis", context.role(3), "prompt assigns final parallel agent analysis role")
    (results / "state" / "strategy-1").write_text("S7\n", encoding="utf-8")
    equal("S7", context.strategy(1), "prompt reads persisted strategy")
    (results / "work-cards.jsonl").write_text(
        json.dumps({
            "id": "WORK-prompt-card", "kind": "ranked-source", "target_slug": "demo",
            "subsystem": "src/parser", "file": "src/parser/input.c", "mode": "browser",
            "strategy": "S7", "score": 80, "reason": "input parser",
            "status": "unclaimed",
        }) + "\n",
        encoding="utf-8",
    )
    assigned = prompt.work_card_directive(context, 1, force=True)
    check(
        "WORK-prompt-card" in assigned and "ASSIGNED WORK CARD" in assigned,
        "prompt claims and renders a real work card through the queue API",
        assigned,
    )
    static = prompt.write_static_prompt_file(context)
    check(static.is_file() and "DIGEST" in static.read_text(encoding="utf-8"), "prompt writes cached static rules atomically")
    cold = prompt.cold_start_prompt(context, 1)
    check("Agent 1" in cold and "ROLE: REPRODUCE" in cold, "cold prompt renders role and agent identity")
    check(
        "BUILD CONFIGURATION" not in cold,
        "browser prompts do not advertise native alternate-build controls",
        cold,
    )
    check(
        "--role reproduce --strategy S7" in cold
        and "reproduce--strategy" not in cold,
        "cold prompt renders a parseable strategy-bearing state resume command",
    )
    static_text = static.read_text(encoding="utf-8")
    check(
        "bin/state resume --agent N" in static_text
        and "bin/state resume --agent `" not in static_text,
        "static prompt suffix keeps its compression resume command agent-neutral",
    )

    generic_target = root / "generic-target"
    (generic_target / "build-asan").mkdir(parents=True)
    generic_config = target_config.Config(
        target_root=str(generic_target), sanitizers_enabled=["ubsan"],
        attacker_controls=["bytes", "call-sequence"], includes=["include"],
        link_libs=["-lsample"], runner_bin="python3",
    )
    generic_context = prompt.PromptContext(
        results, generic_target, "demo", references, 2, config=generic_config,
    )
    directive = prompt.sanitizer_build_directive(generic_context)
    check(
        "build-asan" in directive and "ubsan" in directive,
        "generic prompt reports the mandatory ASan build and selected sanitizer",
        directive,
    )
    check(
        "attacker_controls`: `bytes,call-sequence`" in directive
        and "`link_libs`: `-lsample`" in directive,
        "generic prompt injects parsed threat-model and harness config",
        directive,
    )
    cache = results / "scratch-1" / ".harness-cache"
    cache.mkdir(parents=True)
    for index in range(3):
        (cache / f"fixture-{index}.build.log").write_text("missing header\n", encoding="utf-8")
    failure_directive = prompt.harness_build_failures_directive(generic_context)
    check(
        "PERSISTENT HARNESS BUILD FAILURES" in failure_directive
        and "target.toml" in failure_directive,
        "generic prompt surfaces persistent harness build failures",
        failure_directive,
    )
    (results / "work-cards.jsonl").write_text('{"id":"WORK-1"}\n', encoding="utf-8")
    card_payload = {
        "id": "WORK-1", "kind": "ranked-source", "subsystem": "parser",
        "file": "src/parser.c", "strategy": "S7", "score": 90,
        "reason": "structural rank", "fix_hashes": ["abc123"],
    }
    with mock.patch.object(prompt.workqueue, "claim_next_card", return_value=card_payload), \
         mock.patch.object(structured_state, "agent_counts", return_value=None):
        directive = prompt.work_card_directive(context, 1)
    check("src/parser.c" in directive and "abc123" in directive, "prompt renders work-card detail")

    equal("null-deref", triage.autodiscard_reason("Hint: address points to the zero page"), "triage rejects null dereferences")
    equal("", triage.autodiscard_reason("ERROR: AddressSanitizer: heap-buffer-overflow"), "triage retains memory-safety diagnostics")
    equal(("promote", "trigger within attacker_controls=bytes"), triage.evaluate_crash_verdict("Trigger source: bytes\n", ["bytes"]), "triage promotes in-contract triggers")
    equal(
        ("incomplete", "report has no Caller contract or Trigger source field"),
        triage.evaluate_crash_verdict("## Summary\nCrash details only.\n", ["bytes"]),
        "triage does not promote reports missing contract and trigger fields",
    )
    verdict, reason = triage.evaluate_crash_verdict("Trigger source: env\n", ["bytes"])
    check(verdict == "contract-flag" and "env" in reason, "triage flags out-of-contract triggers without discarding")
    verdict, _ = triage.evaluate_crash_verdict(
        "Caller controls: bytes\nParameter control: harness-only\nTrigger source: input\n",
        ["bytes"],
    )
    equal("contract-flag", verdict, "triage reads Parameter control independently from Caller controls")
    verdict, _ = triage.evaluate_crash_verdict("Trigger source: both\n", ["bytes"])
    equal("contract-flag", verdict, "triage expands both into bytes plus call-sequence")

    rejected_results = root / "triage-results"
    crash = rejected_results / "crashes" / "CRASH-001"
    crash.mkdir(parents=True)
    # A crash with no sanitizer evidence is held promotion-pending, not rejected
    # on the first pass — a real crash still being bundled must not be lost. It
    # ages out to crashes-rejected/ only after CRASH_PROMOTION_PENDING_MAX passes.
    equal(
        "pending",
        triage.triage_one_crash(crash, rejected_results, root / "target", "demo", ["bytes"]),
        "triage holds a crash without sanitizer evidence promotion-pending",
    )
    with mock.patch.dict(os.environ, {"CRASH_PROMOTION_PENDING_MAX": "1"}, clear=False):
        equal(
            "rejected",
            triage.triage_one_crash(crash, rejected_results, root / "target", "demo", ["bytes"]),
            "triage quarantines a crash that never produces sanitizer evidence",
        )
    check((rejected_results / "crashes-rejected" / "CRASH-001" / "REJECTION.md").is_file(), "triage preserves a rejection rationale")

    findings = rejected_results / "findings"
    accepted = findings / "FIND-ACCEPTED"
    accepted.mkdir(parents=True)
    (accepted / "report.md").write_text("# Concrete issue\n\nsrc/a.c:10 bounds issue\n", encoding="utf-8")
    (accepted / ".llm-find-quality.json").write_text(json.dumps({"decision_version": "v13-python", "accept": True, "accept_count": 2}), encoding="utf-8")
    equal("accepted", triage.validate_one_finding(accepted, rejected_results), "finding gate honors accepted cached quorum")
    batched_pending = findings / "FIND-BATCH-PENDING"
    batched_pending.mkdir()
    (batched_pending / "report.md").write_text("# Concrete issue\n\nsrc/c.c:30 state issue\n", encoding="utf-8")
    with mock.patch.object(triage, "_quality_vote", side_effect=AssertionError("individual fan-out")):
        equal(
            "pending",
            triage.validate_one_finding(
                batched_pending, rejected_results, initial_votes=[],
            ),
            "missing batch votes stay pending without individual quality fan-out",
        )
    with mock.patch.dict(
        os.environ,
        {"ACTIVE_BACKEND": "claude", "TARGET_ROOT": str(root)},
        clear=False,
    ), mock.patch.object(triage.llm_decide, "provider_limit_open", return_value=True):
        equal(
            {accepted},
            triage._batch_finding_trigger_votes(
                [accepted], rejected_results, None, None, False,
            ),
            "provider-limited trigger batches leave quality-accepted findings pending",
        )
    pending = findings / "FIND-PENDING"
    pending.mkdir()
    equal("pending", triage.validate_one_finding(pending, rejected_results), "finding gate leaves missing reports pending")
    check((pending / ".needs-content").is_file(), "finding gate marks reports needing content")
    rejected = findings / "FIND-REJECTED"
    rejected.mkdir()
    (rejected / "report.md").write_text("# Concrete issue\n\nsrc/b.c:20 state issue\n", encoding="utf-8")
    (rejected / ".llm-find-quality.json").write_text(json.dumps({"decision_version": "v13-python", "accept": False, "reject_count": 2, "reason": "not security relevant"}), encoding="utf-8")
    equal("rejected", triage.validate_one_finding(rejected, rejected_results), "finding gate quarantines cached reject quorums")
    check((rejected_results / "findings-rejected" / "FIND-REJECTED" / "REJECTION.md").is_file(), "finding rejection keeps the validator rationale")

    check(crash_bundle.should_file("CRASH", "asan", 5), "crash bundle files confirmed sanitizer crashes")
    check(not crash_bundle.should_file("CLEAN", "asan", 5), "crash bundle rejects clean probes")
    check(not crash_bundle.should_file("CRASH", "asan", 1), "crash bundle requires confirmation runs")
    bundle_results = root / "bundle-results"
    bundle_case = root / "bundle.dat"
    bundle_case.write_text("input\n", encoding="utf-8")
    bundle_san = root / "bundle.asan.txt"
    bundle_san.write_text("ERROR: AddressSanitizer: heap-buffer-overflow\n", encoding="utf-8")
    outcome, crash_id = crash_bundle.materialize(
        bundle_results, "2", bundle_case, bundle_san, "asan", "generic",
        args=("--decode",), target="src/decode.c:parse:10", hypothesis="H-1", strategy="S7",
    )
    equal("FILED", outcome, "crash bundle materializes a first confirmed diagnostic")
    bundle_dir = bundle_results / "crashes" / crash_id
    check((bundle_dir / "report.md").is_file() and (bundle_dir / "repro.cmd").is_file(), "crash bundle includes report and replay arguments")
    equal(
        ["{TESTCASE}", "--decode"],
        shlex.split((bundle_dir / "repro.cmd").read_text().splitlines()[-1]),
        "crash bundle keeps trailing probe arguments after the testcase",
    )
    template_case = root / "template-bundle.dat"
    template_case.write_text("input\n", encoding="utf-8")
    _, template_id = crash_bundle.materialize(
        bundle_results, "2", template_case, bundle_san, "asan", "generic",
        args=("--input", "{TESTCASE}", "--sink", "/dev/null"),
    )
    equal(
        ["--input", "{TESTCASE}", "--sink", "/dev/null"],
        shlex.split(
            (bundle_results / "crashes" / template_id / "repro.cmd")
            .read_text().splitlines()[-1]
        ),
        "crash bundle preserves a learned runner template's testcase position",
    )
    created_at = (bundle_dir / ".crash-created-at").read_text(encoding="utf-8")
    check(bool(created_at.strip()), "crash bundle records its immutable filing clock")
    duplicate, duplicate_id = crash_bundle.materialize(
        bundle_results, "2", bundle_case, bundle_san, "asan", "generic", args=("--decode",)
    )
    equal(("DUP", crash_id), (duplicate, duplicate_id), "crash bundle identity prevents duplicate filing")
    equal(
        created_at,
        (bundle_dir / ".crash-created-at").read_text(encoding="utf-8"),
        "duplicate confirmation does not rewrite the filing clock",
    )

    original_path_open = Path.open

    def fail_bundle_index(path, *args, **kwargs):
        if path.name == ".probe-filed-3.tsv" and args and "a" in args[0]:
            raise PermissionError("synthetic index failure")
        return original_path_open(path, *args, **kwargs)

    warnings = io.StringIO()
    with mock.patch.object(Path, "open", fail_bundle_index), contextlib.redirect_stderr(warnings):
        filed, unindexed_id = crash_bundle.materialize(
            bundle_results, "3", bundle_case, bundle_san, "asan", "generic"
        )
    equal("FILED", filed, "crash bundle remains filed when only its dedup index is unwritable")
    check(
        (bundle_results / "crashes" / unindexed_id / "report.md").is_file()
        and "dedup index update failed" in warnings.getvalue(),
        "crash bundle preserves evidence and reports the failed index update",
    )
    duplicate, duplicate_id = crash_bundle.materialize(
        bundle_results, "3", bundle_case, bundle_san, "asan", "generic"
    )
    equal(
        ("DUP", unindexed_id), (duplicate, duplicate_id),
        "bundle-local identity preserves dedup when the optional index was not written",
    )

    direct_target = root / "direct-target"
    (direct_target / "src").mkdir(parents=True)
    (direct_target / "src" / "app.c").write_text("int app_parse(void) { return 0; }\n")
    direct_binary = direct_target / "build-asan" / "app"
    direct_binary.parent.mkdir()
    direct_binary.write_bytes(b"sanitizer build\n")
    direct_binary.chmod(0o755)
    direct_case = root / "direct-input.bin"
    direct_case.write_bytes(b"input")
    direct_san = root / "direct.asan.txt"
    direct_san.write_text(
        "ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "    #0 0x1 in app_parse src/app.c:1\n"
        "CRASH_RATE: 5/5\n",
        encoding="utf-8",
    )
    direct_results = root / "direct-results"
    _, direct_id = crash_bundle.materialize(
        direct_results, "1", direct_case, direct_san, "asan", "generic",
        binary=direct_binary,
    )
    direct_crash = direct_results / "crashes" / direct_id
    direct_context = crash_bundle.verified_probe_context(direct_crash)
    check(direct_context is not None, "probe context verifies testcase and sanitizer build identity")
    _ctx_path = direct_crash / ".probe-context.json"
    _ctx_v1 = _ctx_path.read_text()
    _ctx_v2 = json.loads(_ctx_v1); _ctx_v2["version"] = 2
    _ctx_path.write_text(json.dumps(_ctx_v2), encoding="utf-8")
    check(
        crash_bundle.verified_probe_context(direct_crash) is not None,
        "probe context version 2 is accepted (resume compatibility)",
    )
    _ctx_path.write_text(_ctx_v1, encoding="utf-8")  # restore v1 for the flow below
    check(
        triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
        "5/5 standard target byte-input crash bypasses only trigger review",
    )
    check(
        (direct_crash / ".trigger-gate-bypass.json").is_file(),
        "trigger bypass leaves machine-readable provenance",
    )
    published_results = root / "published-results"
    nested_crash = published_results / "session" / "results" / "crashes" / direct_id
    nested_crash.parent.mkdir(parents=True)
    shutil.copytree(direct_crash, nested_crash)
    published_crash = published_results / "crashes" / "CRASH-1"
    published_crash.mkdir(parents=True)
    shutil.copy2(direct_crash / direct_case.name, published_crash / "input.bin")
    shutil.copy2(direct_crash / "sanitizer.txt", published_crash / "sanitizer.txt")
    (published_crash / "report.md").write_text("Trigger source: bytes\n", encoding="utf-8")
    with mock.patch.object(benchmark_runner.triage, "triage_crash_dirs", return_value={"promoted": 1}):
        benchmark_runner.triage_cell_crashes(
            published_results, direct_target, "direct-target", workers=1,
        )
    check(
        crash_bundle.verified_probe_context(published_crash) is not None
        and triage._direct_probe_trigger_bypass(published_crash, direct_target, ["bytes"]),
        "model-direct triage restores exact nested probe provenance after testcase rename",
    )
    unreplayable_results = root / "unreplayable-results"
    unreplayable = unreplayable_results / "crashes" / "CRASH-1"
    unreplayable.mkdir(parents=True)
    (unreplayable / "sanitizer.txt").write_text(
        "ERROR: AddressSanitizer: heap-buffer-overflow\n", encoding="utf-8",
    )
    (unreplayable / "report.md").write_text("# Concrete crash\n", encoding="utf-8")
    (unreplayable / "input.bin").write_bytes(b"input")
    with mock.patch.object(
        benchmark_runner.triage, "triage_crash_dirs",
        return_value={"promoted": 0, "rejected": 0, "demoted": 0, "pending": 0},
    ), mock.patch.object(benchmark_runner, "_resolve_reverify_fields", return_value=None):
        replay_counts = benchmark_runner.triage_cell_crashes(
            unreplayable_results, direct_target, "direct-target", workers=1,
            require_replay=True,
        )
    check(
        replay_counts["promoted"] == 0
        and replay_counts["demoted"] == 1
        and (unreplayable_results / "findings" / "FIND-1" / "sanitizer.txt").is_file(),
        "unreplayable model-direct sanitizer evidence is preserved as a finding",
    )
    failed_replay_results = root / "failed-replay-results"
    failed_replay = failed_replay_results / "crashes" / "CRASH-1"
    shutil.copytree(unreplayable_results / "findings" / "FIND-1", failed_replay)
    with mock.patch.object(
        benchmark_runner.triage, "triage_crash_dirs",
        return_value={"promoted": 0, "rejected": 0, "demoted": 0, "pending": 0},
    ), mock.patch.object(
        benchmark_runner, "_resolve_reverify_fields", return_value=({"MODE": "generic", "BIN": "fixture"}, []),
    ), mock.patch.object(benchmark_runner, "reverify_one_crash", return_value=False):
        failed_replay_counts = benchmark_runner.triage_cell_crashes(
            failed_replay_results, direct_target, "direct-target", workers=1,
            require_replay=True,
        )
    check(
        failed_replay_counts["promoted"] == 0
        and failed_replay_counts["demoted"] == 1
        and (failed_replay_results / "findings" / "FIND-1").is_dir(),
        "an executable model-direct crash that cannot be measured remains a finding",
    )
    standard_replay = root / "standard-replay" / "CRASH-1"
    shutil.copytree(failed_replay_results / "findings" / "FIND-1", standard_replay)

    def _record_standard_replay(crash_dir, _target, _slug):
        with (crash_dir / "sanitizer.txt").open("a", encoding="utf-8") as stream:
            stream.write("CRASH_RATE: 5/5\n")
        return True

    with mock.patch.object(
        benchmark_runner.triage, "_direct_probe_trigger_bypass", return_value=False,
    ), mock.patch.object(
        benchmark_runner, "_resolve_reverify_fields",
        return_value=({"MODE": "cli", "BIN": str(direct_binary)}, []),
    ), mock.patch.object(
        benchmark_runner, "reverify_one_crash", side_effect=_record_standard_replay,
    ), mock.patch.object(
        benchmark_runner.triage, "_fault_frame_is_in_target", return_value=True,
    ):
        equal(
            "bypass",
            benchmark_runner._verify_model_direct_crash(
                standard_replay, direct_target, "direct-target", ["bytes"],
            ),
            "a configured-target 5/5 replay bypasses redundant trigger review",
        )
    zero_rate = root / "zero-rate-crashes" / "CRASH-1"
    zero_rate.mkdir(parents=True)
    (zero_rate / "sanitizer.txt").write_text(
        "ERROR: AddressSanitizer: heap-buffer-overflow\nCRASH_RATE: 0/5\n",
        encoding="utf-8",
    )
    equal(
        (0, []), __import__("benchmark").count_confirmed_crashes(zero_rate.parent),
        "a measured zero-rate diagnostic cannot inflate benchmark crash counts",
    )
    check(
        not benchmark_runner._same_sanitizer_fault(
            "SUMMARY: AddressSanitizer: heap-buffer-overflow child.c:9",
            "SUMMARY: AddressSanitizer: ABRT child.c:8",
        ),
        "reverify cannot substitute an assertion abort for the reported memory fault",
    )
    mismatched = published_results / "crashes" / "CRASH-2"
    shutil.copytree(published_crash, mismatched)
    (mismatched / ".probe-context.json").unlink()
    (mismatched / ".probe-identity").unlink()
    (mismatched / "sanitizer.txt").write_text("different evidence\n", encoding="utf-8")
    check(
        not crash_bundle.restore_probe_context([nested_crash], mismatched),
        "model-direct provenance recovery fails closed on changed sanitizer evidence",
    )
    with mock.patch.object(crash_bundle, "verified_probe_context", return_value={
        **direct_context, "harness": True,
    }):
        check(
            not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
            "custom harness evidence cannot bypass trigger review",
        )
    with mock.patch.object(crash_bundle, "verified_probe_context", return_value={
        **direct_context, "args": ["--nonstandard"],
    }):
        check(
            not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
            "non-standard argv cannot bypass trigger review",
        )
    with mock.patch.object(crash_bundle, "verified_probe_context", return_value={
        **direct_context, "build_config_id": "wide-id",
    }), mock.patch.object(crash_bundle, "verified_primary_differential", return_value=None):
        check(
            not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
            "alternate-config crash cannot bypass trigger review without a primary differential",
        )
    with mock.patch.object(crash_bundle, "verified_probe_context", return_value={
        **direct_context, "build_config_id": "wide-id",
    }), mock.patch.object(crash_bundle, "verified_primary_differential", return_value={
        "status": "reproduced",
    }):
        check(
            triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
            "same-fault primary reproduction restores the direct byte-path bypass",
        )
    check(
        not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["call-sequence"]),
        "out-of-model input cannot bypass trigger review",
    )
    filed_sanitizer = direct_crash / "sanitizer.txt"
    filed_sanitizer.write_text(
        "ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "    #0 0x1 in app_parse src/app.c:1\n"
        "CRASH_RATE: 4/5\n",
        encoding="utf-8",
    )
    check(
        not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
        "non-deterministic crash cannot bypass trigger review",
    )
    filed_sanitizer.write_text(
        "ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "    #0 0x1 in wrapper /outside/wrapper.c:1\n"
        "CRASH_RATE: 5/5\n",
        encoding="utf-8",
    )
    check(
        not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
        "fault frame outside the target cannot bypass trigger review",
    )
    filed_sanitizer.write_text(direct_san.read_text(encoding="utf-8"), encoding="utf-8")
    with mock.patch.object(triage, "_direct_probe_trigger_bypass", return_value=True), \
         mock.patch.object(triage, "_trigger_vote") as trigger_vote:
        check(
            triage._crash_trigger_gate(
                direct_crash, direct_crash / "report.md", direct_target,
                attacker_controls=["bytes"],
            ) is False and trigger_vote.call_count == 0,
            "direct proof bypasses only the LLM trigger votes",
        )
    filed_testcase = direct_crash / direct_case.name
    filed_testcase.write_bytes(b"changed input")
    check(
        crash_bundle.verified_probe_context(direct_crash) is None,
        "changed testcase invalidates direct-probe evidence",
    )
    filed_testcase.write_bytes(direct_case.read_bytes())
    direct_binary.write_bytes(b"changed sanitizer build\n")
    check(
        crash_bundle.verified_probe_context(direct_crash) is None
        and not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
        "changed sanitizer build invalidates direct-probe bypass",
    )

    artifact_target = root / "artifact-target"
    old = artifact_target / "findings" / "FIND-OLD"
    old.mkdir(parents=True)
    marked = benchmark_runner.mark_target_artifacts(artifact_target)
    new = artifact_target / "findings" / "FIND-NEW"
    new.mkdir()
    destination = root / "cell"
    destination.mkdir()
    equal(1, benchmark_runner.sweep_target_artifacts(artifact_target, destination, marked), "benchmark sweeps only newly leaked artifacts")
    check(old.is_dir() and (destination / "findings" / "FIND-NEW").is_dir(), "benchmark preserves pre-existing target artifacts")

    scratch_cell = root / "scratch-cell"
    (scratch_cell / "scratch" / "nested").mkdir(parents=True)
    (scratch_cell / "scratch-1").mkdir()
    benchmark_runner.cleanup_model_direct_scratch(scratch_cell)
    check(not (scratch_cell / "scratch").exists() and (scratch_cell / "scratch-1").is_dir(), "benchmark cleanup is scoped to model-direct scratch")

    lock = root / "locks" / ".run-demo.lock"
    with benchmark_runner.BenchmarkLock(lock):
        check(lock.is_file(), "benchmark lock is materialized while owned")
        try:
            with benchmark_runner.BenchmarkLock(lock):
                pass
            duplicate_refused = False
        except RuntimeError:
            duplicate_refused = True
        check(duplicate_refused, "benchmark refuses a live duplicate target run")
    check(not lock.exists(), "benchmark releases its lock")

    parser = audit_runner.build_parser()
    args = parser.parse_args(["--target", "demo", "--backend", "codex", "--experiment", "Exp A"])
    equal("exp-a", audit_runner._sanitize_experiment(args.experiment), "audit experiment names become safe path components")
    equal("demo-exp-a", audit_runner._output_slug("demo", "exp-a"), "audit experiment output slug is deterministic")
    with mock.patch.object(audit_runner.llm_invoke, "backend_bin", return_value=sys.executable), \
         mock.patch.object(
             audit_runner.subprocess, "run",
             side_effect=audit_runner.subprocess.TimeoutExpired([sys.executable], 30),
         ), contextlib.redirect_stderr(io.StringIO()):
        check(
            not audit_runner.backend_configured("codex"),
            "a hung backend preflight is unavailable instead of aborting audit startup",
        )
    model_runtime = SimpleNamespace(
        root=ROOT, logs=root / "model-preflight-logs",
        raw=root / "model-preflight-logs" / ".raw",
        index=root / "model-preflight-logs" / "index.log",
        backend="gemini", model="fixture-model",
    )
    model_runtime.raw.mkdir(parents=True)
    with mock.patch.dict(
        os.environ,
        {"AUDIT_MODEL_PREFLIGHT_ATTEMPTS": "1"},
        clear=False,
    ), mock.patch.object(audit_runner.llm_invoke, "run_agent_prompt", return_value=0), \
         mock.patch.object(audit_runner.llm_invoke, "extract_text", return_value="MODEL_PREFLIGHT_OK"):
        audit_runner.validate_model(model_runtime)
    check(
        "Model preflight passed" in model_runtime.index.read_text(encoding="utf-8"),
        "model preflight exercises the requested model through the agent launch path",
    )
    preflight_usage = json.loads(
        (model_runtime.logs / "index.jsonl").read_text(encoding="utf-8")
    )
    check(
        preflight_usage["role"] == "model-preflight"
        and preflight_usage["backend"] == "gemini",
        "model preflight usage is charged to the session ledger",
    )
    model_runtime.backend = "oss"
    with mock.patch.dict(
        os.environ,
        {"AUDIT_MODEL_PREFLIGHT_ATTEMPTS": "1"},
        clear=False,
    ), mock.patch.object(audit_runner.llm_invoke, "run_agent_prompt", return_value=0), \
         mock.patch.object(
             audit_runner.llm_invoke, "extract_text",
             side_effect=lambda _backend, _raw: (model_runtime.logs / ".preflight/oss-tool-sentinel.txt").read_text().strip(),
         ), mock.patch.object(audit_runner.llm_invoke, "raw_has_tool", return_value=True):
        audit_runner.validate_model(model_runtime)
    check(
        not (model_runtime.logs / ".preflight/oss-tool-sentinel.txt").exists(),
        "OSS preflight requires a real read-tool result and removes its sentinel",
    )
    model_runtime.backend = "gemini"
    with mock.patch.dict(
        os.environ,
        {"AUDIT_MODEL_PREFLIGHT_ATTEMPTS": "1"},
        clear=False,
    ), mock.patch.object(audit_runner.llm_invoke, "run_agent_prompt", return_value=0), \
         mock.patch.object(audit_runner.llm_invoke, "extract_text", return_value="wrong model response"):
        try:
            audit_runner.validate_model(model_runtime)
            rejected_bad_model = False
        except RuntimeError:
            rejected_bad_model = True
    check(rejected_bad_model, "model preflight rejects a nominal exit with the wrong response")
    config = target_config.Config(is_browser="1")
    with mock.patch.dict(os.environ, {"BROWSER_AGENTS": "2", "SHELL_AGENTS": "2"}, clear=False):
        equal((4, 2, 2), audit_runner._agent_counts(config, 10), "audit honors configured browser and shell role counts")
    equal((1, 1, 0), audit_runner._agent_counts(config, 1), "browser smoke mode keeps one browser worker")
    with mock.patch.dict(os.environ, {"AGENT_ROLES": "analysis,reproduce,reproduce"}, clear=False):
        equal(
            ("analysis", "reproduce", "reproduce"),
            audit_runner._agent_roles(3),
            "audit honors explicit per-agent roles",
        )
    explicit_context = prompt.PromptContext(
        results, generic_target, "demo", references, 3,
        agent_roles=("analysis", "reproduce", "reproduce"),
    )
    equal("analysis", explicit_context.role(1), "prompt applies explicit role ordering")
    handoff_results = root / "handoff-results"
    (handoff_results / "state").mkdir(parents=True)
    (handoff_results / "state/hypotheses.jsonl").write_text(json.dumps({
        "id": "H-HANDOFF", "agent": "1", "status": "NEEDS_TESTCASE",
        "file": "src/parser.c:app_parse:91", "hypothesis": "nested state reaches stale entry",
        "input_shape": "nested document", "guard_gap": "cleanup ordering",
        "diagnostic": "lifetime", "strategy": "S5", "updated_at": "2026-07-10T00:00:00Z",
    }) + "\n", encoding="utf-8")
    handoff_context = prompt.PromptContext(
        handoff_results, generic_target, "demo", references, 3,
        agent_roles=("analysis", "reproduce", "reproduce"),
    )
    assigned_handoffs = {
        agent: prompt.handoff_rows(handoff_context, agent) for agent in (2, 3)
    }
    assigned_agent = next(agent for agent, rows in assigned_handoffs.items() if rows)
    check(
        sum(bool(rows) for rows in assigned_handoffs.values()) == 1
        and "H-HANDOFF" in prompt.handoff_directive(handoff_context, assigned_agent),
        "analysis NEEDS_TESTCASE is routed to exactly one reproduce worker",
    )
    handoff_runtime = SimpleNamespace(
        root=ROOT, results=handoff_results, target_root=generic_target,
        target_slug="demo", repo_type="none",
    )
    check(
        not audit_runner.should_skip_launch(handoff_runtime, handoff_context, assigned_agent),
        "a pending analysis handoff keeps its reproduce worker launchable",
    )

    strategy_results = root / "strategy-results"
    (strategy_results / "state").mkdir(parents=True)
    strategy_cards = [
        {"id": "WORK-S7-a", "strategy": "S7", "status": "unclaimed"},
        {"id": "WORK-S7-b", "strategy": "S7", "status": "unclaimed"},
        {"id": "WORK-S2", "strategy": "S2", "status": "unclaimed"},
    ]
    (strategy_results / "work-cards.jsonl").write_text(
        "".join(json.dumps(card) + "\n" for card in strategy_cards), encoding="utf-8"
    )
    strategy_runtime = SimpleNamespace(
        root=ROOT, target_root=generic_target, target_slug="demo",
        results=strategy_results, repo_type="none", num_agents=3, fixed_strategy="",
    )
    audit_runner.initialize_agent_strategies(strategy_runtime)
    equal(
        ["S7", "S2", "S7"],
        [
            (strategy_results / "state" / f"strategy-{agent}").read_text().strip()
            for agent in range(1, 4)
        ],
        "cold-start strategies fan out by available queue load",
    )

    rotation_runtime = SimpleNamespace(
        root=ROOT, target_root=generic_target, target_slug="demo",
        results=strategy_results, repo_type="none", num_agents=1, fixed_strategy="",
        index=root / "strategy-index.log",
    )
    (strategy_results / "state" / "strategy-1").write_text("S2\n", encoding="utf-8")
    (strategy_results / ".agent_strategy_streak_1").write_text("2\n", encoding="utf-8")
    rotation_context = prompt.PromptContext(
        strategy_results, generic_target, "demo", references, 1,
    )
    idle_progress = audit_runner.AgentProgress(0, 0, frozenset())
    with mock.patch.object(
        audit_runner.workqueue, "strategy_completion_status",
        return_value={"complete": True, "evidence": 2, "threshold": 2},
    ):
        audit_runner.update_strategy_rotation(
            rotation_runtime, rotation_context,
            {1: idle_progress}, set(),
        )
    equal(
        "S7", (strategy_results / "state" / "strategy-1").read_text().strip(),
        "dry strategy rotation selects the largest available queue",
    )
    (strategy_results / "state" / "strategy-1").write_text("S2\n", encoding="utf-8")
    (strategy_results / ".agent_strategy_streak_1").write_text("2\n", encoding="utf-8")
    with mock.patch.object(
        audit_runner.workqueue, "strategy_completion_status",
        return_value={"complete": True, "evidence": 2, "threshold": 2},
    ):
        audit_runner.update_strategy_rotation(
            rotation_runtime, rotation_context,
            {1: audit_runner.AgentProgress(0, 1, frozenset())},
            set(),
        )
    equal(
        "S7", (strategy_results / "state" / "strategy-1").read_text().strip(),
        "environment-blocked work advances strategy rotation",
    )

    subsystem_runtime = SimpleNamespace(
        root=ROOT, target_root=generic_target, target_slug="demo",
        results=strategy_results, repo_type="none", num_agents=2,
    )
    (strategy_results / "state" / "hypotheses.jsonl").write_text(
        json.dumps({"agent": "1", "status": "FIND-001", "file": "src/parser/a.c", "subsystem": "src/parser"}) + "\n"
        + json.dumps({"agent": "2", "status": "DISCARDED", "file": "src/parser/b.c", "subsystem": "src/parser"}) + "\n",
        encoding="utf-8",
    )
    audit_runner.update_subsystem_dry_streaks(
        subsystem_runtime, {1},
    )
    equal(
        0,
        audit_runner.workqueue.subsystem_dry_streak(
            audit_runner._queue_context(subsystem_runtime), "src/parser"
        ),
        "any productive agent resets a shared subsystem dry streak",
    )
    audit_runner.update_subsystem_dry_streaks(
        subsystem_runtime, set(),
    )
    equal(
        1,
        audit_runner.workqueue.subsystem_dry_streak(
            audit_runner._queue_context(subsystem_runtime), "src/parser"
        ),
        "multiple dry agents advance a shared subsystem only once per iteration",
    )
    audit_runner.update_subsystem_dry_streaks(
        subsystem_runtime, set(),
    )
    equal(
        2,
        audit_runner.workqueue.subsystem_dry_streak(
            audit_runner._queue_context(subsystem_runtime), "src/parser"
        ),
        "environment-blocked work advances subsystem dry streak",
    )

    refresh_results = root / "refresh-results"
    refresh_logs = root / "refresh-logs"
    refresh_results.mkdir()
    refresh_logs.mkdir()
    refresh_runtime = SimpleNamespace(
        root=ROOT, target_root=generic_target, target_slug="demo",
        target_rev="rev1", repo_type="none", results=refresh_results,
        logs=refresh_logs, backend="codex", model="fixture-model",
        config=generic_config, index=refresh_logs / "index.log",
    )
    with mock.patch.object(audit_runner.housekeeping, "should_run", return_value=True), \
         mock.patch.object(audit_runner.housekeeping, "mark_clean"), \
         mock.patch.object(audit_runner.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as launched:
        refreshed = audit_runner.refresh_work_cards(refresh_runtime)
    launched_tools = [Path(call.args[0][0]).name for call in launched.call_args_list]
    check(
        refreshed and launched_tools == ["patch-cards", "peer-fix-cards", "rank-work"],
        "work-card refresh includes patch, peer-fix, and rank passes",
        repr(launched_tools),
    )
    with mock.patch.object(audit_runner.housekeeping, "should_run", return_value=False), \
         mock.patch.object(audit_runner.subprocess, "run") as skipped_refresh:
        unchanged = audit_runner.refresh_work_cards(refresh_runtime)
    check(
        not unchanged and not skipped_refresh.called,
        "unchanged work-card inputs skip the expensive ranking pipeline",
    )
    (refresh_results / "patch-cards.jsonl").write_text("{}\n", encoding="utf-8")
    (refresh_results / "s6-peer-cards.jsonl").write_text("{}\n", encoding="utf-8")
    (refresh_results / "work-cards.jsonl").write_text(
        json.dumps({"id": "OLD", "kind": "ranked-source"}) + "\n",
        encoding="utf-8",
    )
    with mock.patch.object(audit_runner.housekeeping, "should_run", return_value=True), \
         mock.patch.object(audit_runner.housekeeping, "mark_clean") as failed_clean, \
         mock.patch.object(
             audit_runner.subprocess, "run",
             side_effect=[SimpleNamespace(returncode=1)] * 3,
         ):
        audit_runner.refresh_work_cards(refresh_runtime)
    remaining_cards = audit_runner.workqueue.read_jsonl(
        refresh_results / "work-cards.jsonl"
    )
    check(
        not failed_clean.called
        and not (refresh_results / "patch-cards.jsonl").exists()
        and not (refresh_results / "s6-peer-cards.jsonl").exists()
        and remaining_cards == [],
        "failed card generators cannot leave stale cards or mark the refresh clean",
    )
    cycle_order = []
    ensemble_runtimes = [
        SimpleNamespace(backend="claude", config=mock.Mock()),
        SimpleNamespace(backend="codex", config=mock.Mock()),
    ]
    def _initialize_cycle(runtime, _args, _guide, **_kwargs):
        return audit_runner.BackendState(runtime, mock.Mock(), started_at=1.0)
    def _cycle_once(state):
        cycle_order.append(state.runtime.backend)
        state.iteration += 1
        return "dry", []
    with mock.patch.object(audit_runner, "instance_lock", return_value=contextlib.nullcontext()), \
         mock.patch.object(audit_runner, "_activate_runtime"), \
         mock.patch.object(audit_runner.runner_preflight, "validate") as ensemble_runner_preflight, \
         mock.patch.object(audit_runner, "validate_model") as ensemble_model_preflight, \
         mock.patch.object(audit_runner, "preflight_build") as ensemble_preflight, \
         mock.patch.object(audit_runner, "initialize_backend", side_effect=_initialize_cycle), \
         mock.patch.object(audit_runner, "run_iteration", side_effect=_cycle_once), \
         mock.patch.dict(os.environ, {"COOLDOWN": "0"}, clear=False):
        ensemble_rc = audit_runner.run_ensemble(
            ensemble_runtimes, SimpleNamespace(max_iterations=3, allow_concurrent=False), "guide"
        )
    check(
        ensemble_rc == 0 and cycle_order == ["claude", "codex", "claude"]
        and ensemble_runner_preflight.call_count == 1
        and ensemble_model_preflight.call_count == 2
        and ensemble_preflight.call_count == 1,
        "ensemble mode preflights the runner/build once, each model, and cycles backends",
        repr(cycle_order),
    )

    budget_runtime = SimpleNamespace(
        index=root / "budget-index.log", logs=root / "budget-runtime-logs",
    )
    budget_runtime.logs.mkdir()
    budget_state = audit_runner.BackendState(
        budget_runtime, mock.Mock(), started_at=100.0, paused_seconds=20,
    )
    with mock.patch.dict(os.environ, {"AUDIT_WALL_BUDGET_SECS": "50"}, clear=False), \
         mock.patch.object(audit_runner.time, "monotonic", return_value=171.0):
        wall_done = audit_runner._productive_wall_exhausted(budget_state)
    check(
        wall_done and budget_state.stopped,
        "audit wall budget excludes provider-recovery pause and stops cleanly",
    )
    with mock.patch.dict(os.environ, {"AUDIT_WALL_BUDGET_SECS": "50"}, clear=False), \
         mock.patch.object(audit_runner.time, "monotonic", return_value=171.0):
        equal(
            0, audit_runner._productive_wall_remaining(budget_state),
            "expired audit budget exposes zero remaining time instead of a synthetic extra second",
        )
    init_runtime = SimpleNamespace(
        backend="codex", model="fixture-model", target_slug="demo",
        target_root=generic_target, results=root / "init-results",
        logs=root / "init-logs", prompt_context=lambda _guide: mock.Mock(),
    )
    with mock.patch.dict(os.environ, {"AUDIT_WALL_BUDGET_SECS": "50"}, clear=False), \
         mock.patch.object(audit_runner, "_activate_runtime"), \
         mock.patch.object(audit_runner, "index_log"), \
         mock.patch.object(audit_runner.prompt, "write_static_prompt_file"), \
         mock.patch.object(audit_runner, "refresh_work_cards", return_value=False), \
         mock.patch.object(audit_runner, "initialize_agent_strategies"), \
         mock.patch.object(audit_runner.time, "monotonic", return_value=120.0):
        initialized = audit_runner.initialize_backend(
            init_runtime, SimpleNamespace(), "guide", started_at=100.0,
        )
    check(
        initialized.started_at == 100.0,
        "audit productive clock carries the caller's start time",
    )
    recovery_state = audit_runner.BackendState(
        budget_runtime, mock.Mock(), started_at=100.0,
    )
    with mock.patch.object(audit_runner.time, "time", return_value=1000), \
         mock.patch.object(audit_runner.time, "sleep") as paused:
        recovered = audit_runner._recover_capacity(
            recovery_state, [SimpleNamespace(reset_at=1020)]
        )
    check(
        recovered and recovery_state.paused_seconds == 50
        and paused.call_args == mock.call(50)
        and (budget_runtime.logs / ".run-quality").read_text().strip() == "provider_recovered",
        "provider capacity pause uses the reported reset and records excluded wall time",
    )
    budget_prompt = audit_runner._session_budget('A "quoted" prompt', 20, root / "scratch-1")
    check('A "quoted" prompt' in budget_prompt and "roughly 20 turns" in budget_prompt, "audit session budget preserves quoted prompt text")

    launch_results = root / "launch-results"
    launch_logs = root / "launch-logs"
    launch_raw = launch_logs / ".raw"
    launch_scratch = launch_results / "scratch-1"
    for directory in (launch_results, launch_logs, launch_raw, launch_scratch):
        directory.mkdir(parents=True, exist_ok=True)
    launch_runtime = SimpleNamespace(
        root=ROOT, target_root=generic_target, target_slug="demo",
        results=launch_results, logs=launch_logs, raw=launch_raw,
        index=launch_logs / "index.log", index_jsonl=launch_logs / "index.jsonl",
        backend="codex", model="fixture-model",
    )
    launch_context = mock.Mock()
    launch_context.role.return_value = "reproduce"
    launch_context.scratch_dir.return_value = launch_scratch
    with mock.patch.object(audit_runner.prompt, "cold_start_prompt", return_value="prompt"), \
         mock.patch.object(audit_runner.llm_invoke, "run_agent_prompt", return_value=0) as launch_invoke, \
         mock.patch.object(audit_runner.llm_invoke, "extract_text", return_value="done"), \
         mock.patch.object(audit_runner.llm_usage, "extract_usage", return_value={}), \
         mock.patch.object(audit_runner.build_session_seed, "write_session_seed", return_value=True) as seed_refresh:
        audit_runner.run_agent(launch_runtime, launch_context, 1, 1, True)
    seed_args = seed_refresh.call_args.args
    check(
        len(seed_args) == 2
        and Path(seed_args[0]).parent == launch_raw
        and seed_args[1] == str(launch_results / ".session_seed_1.md"),
        "each completed agent launch refreshes the next prompt's session seed",
        repr(seed_refresh.call_args),
    )
    launch_env = launch_invoke.call_args.kwargs["extra_env"]
    check(
        launch_env["HITS_LOG_PATH"] == str(launch_results / "hits-1.log")
        and launch_env["TRIED_INPUTS_LOG"] == str(launch_results / "tried-inputs-1.log"),
        "agent and probe share the canonical per-agent evidence journals",
        repr(launch_env),
    )
    launch_usage_row = json.loads((launch_logs / "index.jsonl").read_text())
    check(
        (launch_logs / ".index.jsonl.lock").is_file()
        and launch_usage_row["agent"] == 1
        and launch_usage_row["resolved_effort"] == "high",
        "agent usage writes share the JSONL lock used by concurrent harness writers",
    )
    corpus_testcase = launch_scratch / "coverage.html"
    corpus_testcase.write_text(
        "<!-- HYPOTHESIS-ID: H77 -->\n<!-- TARGET: src/parser.c -->\n"
        "<!-- CATEGORY: bounds -->\n<html></html>\n",
        encoding="utf-8",
    )
    (launch_scratch / "coverage.asan.txt").write_text(
        "[run-sanitizer-multi] SUCCESS_RATE: 1/1\n",
        encoding="utf-8",
    )
    (launch_results / "hits-1.log").write_text(
        f"HIT: 2026-07-10T00:00:00Z testcase={corpus_testcase} "
        "want=app_parse edges=2 new=1 frame=app_parse\n",
        encoding="utf-8",
    )
    launch_runtime.num_agents = 1
    with mock.patch.dict(os.environ, {"RESULTS_DIR": str(launch_results)}, clear=False):
        promoted = audit_runner.promote_corpus(launch_runtime)
    check(
        promoted == 1 and any((launch_results / "corpus").glob("COVER-*/coverage.html")),
        "post-iteration corpus promotion consumes probe's canonical HIT journal",
    )
    orphan = launch_scratch / "orphan.html"
    orphan.write_text("<!-- TARGET: src/parser.c -->\n<!-- HYPOTHESIS-ID: H78 -->\n<html/>\n")
    def _enforce_probe(command, _seconds, **_kwargs):
        Path(command[-1]).with_suffix(".asan.txt").write_text(
            "[run-sanitizer-multi] SUCCESS_RATE: 1/1\n", encoding="utf-8"
        )
        return SimpleNamespace(returncode=0)
    with mock.patch.object(audit_runner, "run_timeout", side_effect=_enforce_probe):
        enforced = audit_runner.enforce_orphan_testcases(launch_runtime)
    check(
        enforced == 1 and "CLEAN `orphan.html`" in
        (launch_results / ".enforcement_results_1").read_text(encoding="utf-8"),
        "post-iteration housekeeping probes runnable orphan testcases once",
    )
    enforcement_context = prompt.PromptContext(
        launch_results, generic_target, "demo", references, 1,
    )
    check(
        "ORPHAN TESTCASE RESULTS" in prompt.enforcement_results_directive(enforcement_context, 1),
        "the next agent prompt receives orphan enforcement results",
    )

    audit_logs = root / "audit-logs"
    audit_logs.mkdir()
    audit_runtime = SimpleNamespace(logs=audit_logs)
    with audit_runner.instance_lock(audit_runtime, False):
        check((audit_logs / ".instance.lock.d" / "pid").is_file(), "audit instance lock records its owner")
        try:
            with audit_runner.instance_lock(audit_runtime, False):
                pass
            refused = False
        except RuntimeError:
            refused = True
        check(refused, "audit instance lock refuses a live duplicate")
    check(not (audit_logs / ".instance.lock.d").exists(), "audit instance lock releases cleanly")
    fresh_lock = audit_logs / ".instance.lock.d"
    fresh_lock.mkdir()
    try:
        with audit_runner.instance_lock(audit_runtime, False):
            pass
        initializing_refused = False
    except RuntimeError:
        initializing_refused = True
    check(
        initializing_refused and fresh_lock.is_dir(),
        "audit lock fails closed while another process is initializing its owner file",
    )
    fresh_lock.rmdir()

    queue_runtime = SimpleNamespace(
        root=ROOT, results=results, target_root=generic_target,
        target_slug="demo", repo_type="none", num_agents=2,
    )
    with mock.patch.object(structured_state, "agent_counts", return_value=None):
        check(
            audit_runner.should_skip_launch(queue_runtime, generic_context, 2),
            "audit skips an idle secondary agent when every work source is dry",
        )
        check(
            not audit_runner.should_skip_launch(queue_runtime, generic_context, 1),
            "audit always preserves one discovery agent",
        )
        (results / "fuzz-leads.md").write_text("# Leads\nparser.c:91\n", encoding="utf-8")
        check(
            not audit_runner.should_skip_launch(queue_runtime, generic_context, 2),
            "a fuzz lead keeps an otherwise idle secondary agent launchable",
        )
        (results / "fuzz-leads.md").unlink()
        with mock.patch.object(
            audit_runner.workqueue, "claim_next_card", return_value={"id": "WORK"},
        ):
            check(
                not audit_runner.should_skip_launch(queue_runtime, generic_context, 2),
                "an eligible peekable work card keeps the secondary agent launchable",
            )

    with mock.patch.object(
        audit_runner.workqueue, "release_stale_claims", return_value=[{}, {}],
    ):
        equal(2, audit_runner.release_stale_card_claims(queue_runtime), "audit loop wires stale-claim release through structured state")

    pool_runtime = SimpleNamespace(
        num_agents=2, index=root / "pool-index.log", raw=root / "pool-raw",
    )
    pool_runtime.raw.mkdir()
    pool_context = mock.Mock()
    pool_context.role.return_value = "reproduce"
    pool_state = audit_runner.BackendState(
        pool_runtime, pool_context, iteration=1, started_at=1.0,
    )
    refill_started = threading.Event()
    pool_calls = []
    def _pool_agent(_runtime, _context, agent, _iteration, cold, _limit):
        pool_calls.append((agent, cold))
        if agent == 2:
            refill_started.wait(10)
        elif pool_calls.count((1, False)):
            refill_started.set()
        return audit_runner.AgentResult(
            agent, "reproduce", 0, Path(), Path(), {}, "none", None
        )
    with mock.patch.object(audit_runner, "run_agent_guarded", side_effect=_pool_agent), \
         mock.patch.object(audit_runner, "should_skip_launch", return_value=False):
        pool_results = audit_runner.run_agent_pool(pool_state, [1, 2], True)
    check(
        len(pool_results) == 3 and pool_calls.count((1, False)) == 1,
        "an early worker receives one refill while another initial slot is active",
        repr(pool_calls),
    )
    pool_runtime.refill_workers = False
    no_refill_calls = []
    def _no_refill_agent(_runtime, _context, agent, _iteration, cold, _limit):
        no_refill_calls.append((agent, cold))
        return audit_runner.AgentResult(
            agent, "reproduce", 0, Path(), Path(), {}, "none", None
        )
    with mock.patch.object(audit_runner, "run_agent_guarded", side_effect=_no_refill_agent), \
         mock.patch.object(audit_runner, "should_skip_launch", return_value=False):
        audit_runner.run_agent_pool(pool_state, [1, 2], True)
    check(
        sorted(no_refill_calls) == [(1, True), (2, True)],
        "disabled worker refills never expand the configured pool",
        repr(no_refill_calls),
    )
    pool_runtime.refill_workers = True
    refill_block = threading.Event()
    expired_calls = []
    def _expired_pool_agent(_runtime, _context, agent, _iteration, cold, _limit):
        expired_calls.append((agent, cold))
        if agent == 2:
            refill_block.wait(0.2)
        else:
            refill_block.set()
        return audit_runner.AgentResult(
            agent, "reproduce", 0, Path(), Path(), {}, "none", None
        )
    with mock.patch.object(
        audit_runner, "run_agent_guarded", side_effect=_expired_pool_agent,
    ), mock.patch.object(
        audit_runner, "should_skip_launch", return_value=False,
    ), mock.patch.object(
        audit_runner, "_productive_wall_remaining", return_value=0,
    ):
        audit_runner.run_agent_pool(pool_state, [1, 2], True)
    check(
        sorted(expired_calls) == [(1, True), (2, True)],
        "worker-pool refill is suppressed once the productive deadline expires",
        repr(expired_calls),
    )
    with mock.patch.object(audit_runner, "run_agent", side_effect=RuntimeError("fixture failure")):
        guarded = audit_runner.run_agent_guarded(
            pool_runtime, pool_context, 1, 1, False
        )
    check(
        guarded.provider_issue == "internal" and guarded.raw.is_file(),
        "one internal agent failure is logged and isolated from the worker pool",
    )

    benchmark_preflight_args = SimpleNamespace(
        dry_run=False, regenerate=False, target="sample-c",
        backend="codex",
    )
    with mock.patch.object(
        benchmark_runner.target_config, "load_toml_into"
    ), mock.patch.object(
        benchmark_runner.build_preflight, "refresh"
    ) as benchmark_preflight:
        benchmark_runner.preflight_build(
            benchmark_preflight_args, root / "benchmark-preflight", "fixture-model"
        )
    check(
        benchmark_preflight.call_count == 1
        and benchmark_preflight.call_args[0][2] == "sample-c"
        and benchmark_preflight.call_args[0][5:7] == ("codex", "fixture-model")
        and benchmark_preflight.call_args.kwargs.get("include_alternates") is False,
        "benchmark preflights the shared primary sanitizer build without alternate synthesis",
    )
    benchmark_preflight_args.dry_run = True
    with mock.patch.object(
        benchmark_runner.build_preflight, "refresh"
    ) as dry_preflight:
        benchmark_runner.preflight_build(
            benchmark_preflight_args, root / "benchmark-preflight", "fixture-model"
        )
    check(
        dry_preflight.call_count == 0,
        "benchmark dry runs do not materialize sanitizer builds",
    )

    limited_cell = root / "limited-cell"
    limited_cell.mkdir()
    with mock.patch.object(
        benchmark_runner, "_provider_issue", return_value="capacity_limited"
    ):
        benchmark_runner._record_provider_quality(limited_cell, limited_cell)
    check(
        (limited_cell / ".backend-unavailable").is_file()
        and (limited_cell / ".run-quality").read_text().strip() == "provider_limited",
        "quota evidence with no artifacts overrides a nominally successful cell",
    )
    productive_cell = root / "productive-limited-cell"
    (productive_cell / "findings" / "FIND-001").mkdir(parents=True)
    with mock.patch.object(
        benchmark_runner, "_provider_issue", return_value="capacity_limited"
    ):
        benchmark_runner._record_provider_quality(productive_cell, productive_cell)
    check(
        not (productive_cell / ".backend-unavailable").exists()
        and (productive_cell / ".run-quality").read_text().strip() == "provider_recovered",
        "quota evidence preserves a productive partial cell as recovered",
    )

    gate_results = root / "benchmark-gate"
    gate_results.mkdir()
    decision_seen = {}
    def _gate_probe(_results, **_kwargs):
        decision_seen.update(
            backend=os.environ.get("ACTIVE_BACKEND"),
            model=os.environ.get("MODEL"), target=os.environ.get("TARGET_ROOT"),
            controls=os.environ.get("TARGET_ATTACKER_CONTROLS_CSV"),
            product=_kwargs.get("target_root_is_product"),
        )
        return {"accepted": 1, "rejected": 0, "pending": 0}
    with mock.patch.object(
        benchmark_runner, "benchmark_target_config", return_value=generic_config,
    ), mock.patch.object(triage, "validate_find_gate", side_effect=_gate_probe):
        counts = benchmark_runner.drain_find_gate(
            gate_results, "codex", "fixture-model", generic_target, "demo",
        )
    check(
        counts["accepted"] == 1 and decision_seen == {
            "backend": "codex", "model": "fixture-model", "target": str(generic_target),
            "controls": "bytes,call-sequence", "product": True,
        },
        "benchmark finding drain receives target scope and threat-model controls",
        repr(decision_seen),
    )
    gate_passes = [0]
    def _limited_gate(_results, **_kwargs):
        # First pass records an unknown provider reset; the second recovers.
        marker = Path(os.environ["LLM_DECIDE_LIMIT_FILE"])
        gate_passes[0] += 1
        if gate_passes[0] == 1:
            marker.write_text("unknown\n", encoding="utf-8")
        return {"accepted": gate_passes[0], "rejected": 0, "pending": 0}
    with mock.patch.dict(os.environ, {
        "FIND_GATE_MAX_PAUSES": "1", "FIND_GATE_PAUSE_MAX_TOTAL": "1",
        "FIND_GATE_PAUSE_CHUNK": "1",
    }, clear=False), mock.patch.object(triage, "validate_find_gate", side_effect=_limited_gate), \
         mock.patch.object(benchmark_runner.time, "sleep") as sleep_mock:
        resumed = benchmark_runner.drain_find_gate(
            gate_results, "codex", "fixture-model", generic_target, "demo",
        )
    check(
        gate_passes[0] == 2 and resumed["accepted"] == 2 and sleep_mock.call_count == 1,
        "benchmark finding drain resumes after a provider-limit marker",
    )
    with mock.patch.object(
        triage, "validate_find_gate",
        return_value={"accepted": 0, "rejected": 0, "pending": 1},
    ) as expired_gate, \
         mock.patch.object(benchmark_runner.time, "monotonic", return_value=100.0):
        expired_counts = benchmark_runner.drain_find_gate(
            gate_results, "codex", "fixture-model", generic_target, "demo",
            deadline=100.0,
        )
    check(
        expired_counts == {"accepted": 0, "rejected": 0, "pending": 1}
        and expired_gate.call_args.kwargs["deadline"] == 100.0,
        "expired benchmark validation reports pending findings without extending the deadline",
    )

    limit_marker = root / "decision-provider-limit"
    limit_marker.write_text("unknown\n", encoding="utf-8")
    with mock.patch.dict(os.environ, {"LLM_DECIDE_LIMIT_FILE": str(limit_marker)}, clear=False), \
         mock.patch.object(llm_decide, "_resolve_mock_value", return_value=""), \
         mock.patch.object(llm_decide, "_run_decision") as limited_decision:
        limited_result = llm_decide.llm_decide(
            "find_quality", "accept,reason,class,severity", "review this", 1,
        )
    check(
        limited_result is None and not limited_decision.called,
        "a confirmed provider limit stops queued validation decisions",
    )

    decision_payload = '{"accept":true,"reason":"ok","class":"state","severity":"low"}'
    for usage_backend in ("claude", "codex", "gemini", "grok"):
        usage_index = root / f"usage-index-{usage_backend}.jsonl"
        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": usage_backend, "MODEL": "fixture-model",
        }, clear=False), mock.patch.object(
            llm_decide, "_invoke_backend", return_value=decision_payload,
        ):
            usage_result, usage_error = llm_decide._run_decision(
                "find_quality", "accept,reason,class,severity", "p" * 400, 1, "",
                usage_index,
            )
        usage_row = json.loads(usage_index.read_text(encoding="utf-8"))
        check(
            usage_result == {"accept": True, "reason": "ok", "class": "state", "severity": "low"}
            and usage_error is False
            and usage_row["estimated"] is True
            and usage_row["tokens"]["input"] == 100
            and usage_row["tokens"]["output"] > 0
            and usage_row["role"] == "decision:find_quality"
            and usage_row["backend"] == usage_backend
            and usage_row["resolved_effort"] == llm_invoke.default_effort(usage_backend),
            f"{usage_backend} one-shot decisions append labeled estimated usage",
            repr(usage_row),
        )
    timeout_index = root / "usage-index-timeout.jsonl"
    timeout_error = subprocess.TimeoutExpired(
        ["claude"], 45, output=b'{"type":"assistant"}', stderr=b"partial",
    )
    with mock.patch.dict(os.environ, {
        "ACTIVE_BACKEND": "claude", "MODEL": "fixture-model",
    }, clear=False), mock.patch.object(
        llm_decide, "_invoke_backend", side_effect=timeout_error,
    ):
        timeout_result, timeout_backend_error = llm_decide._run_decision(
            "find_quality", "accept,reason,class,severity", "review", 45, "",
            timeout_index,
        )
    timeout_row = json.loads(timeout_index.read_text(encoding="utf-8"))
    check(
        timeout_result is None and timeout_backend_error is False
        and timeout_row["usage_complete"] is False,
        "timed-out decisions retain partial usage without crashing finalization",
    )

    check(
        benchmark_runner.parser().parse_args([]).finalize_wall == 3600,
        "benchmark final validation defaults to a one-hour safety window",
    )
    layout_root = root / "usage-layouts"
    harness_results = layout_root / "harness" / "results"
    harness_results.mkdir(parents=True)
    (harness_results.parent / "logs").mkdir()
    direct_results = layout_root / "direct"
    (direct_results / "logs").mkdir(parents=True)
    check(
        benchmark_runner.metrics._find_index_jsonl(harness_results)
        == harness_results.parent / "logs" / "index.jsonl"
        and benchmark_runner.metrics._find_index_jsonl(direct_results)
        == direct_results / "logs" / "index.jsonl",
        "usage ledger routing is stable before either layout creates index.jsonl",
    )

    config_root = root / "config-root"
    target_tree = config_root / "targets" / "nested" / "demo"
    target_tree.mkdir(parents=True)
    base_config = config_root / "output" / "nested" / "demo" / "target.toml"
    base_config.parent.mkdir(parents=True)
    base_config.write_text('target = "nested/demo"\n[threat_model]\nattacker_controls = ["timing"]\n', encoding="utf-8")
    experiment_root = config_root / "output" / "nested" / "demo-exp"
    loaded_config = audit_runner._load_config(config_root, target_tree, experiment_root, "nested/demo")
    equal(["timing"], loaded_config.attacker_controls, "audit experiments preserve the curated base target config")
    check((experiment_root / "target.toml").is_file(), "audit experiment config is materialized for reproducibility")

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        equal(1, benchmark_runner.main(["--target", ", ,", "--dry-run"]), "benchmark rejects an empty target list")
    check("non-empty slug" in stderr.getvalue(), "benchmark empty-target error is actionable")

print(f"\n{passed}/{passed + failed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
