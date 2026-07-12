#!/usr/bin/env python3
"""Regression coverage for orchestration parity restored after 9356915."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner
import file_tools
import llm_invoke
import prompt
import target_config
import triage
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


with tempfile.TemporaryDirectory(prefix="audit-migration-parity-") as temporary:
    root = Path(temporary)
    target = root / "target"
    target.mkdir()
    references = root / "references"
    references.mkdir()
    (references / "session-rules.digest.md").write_text("digest\n", encoding="utf-8")

    prompt_results = root / "prompt-results"
    (prompt_results / "state").mkdir(parents=True)
    (prompt_results / "state" / "strategy-1").write_text("S5\n", encoding="utf-8")
    context = prompt.PromptContext(prompt_results, target, "sample", references, 1)
    rendered = prompt.cold_start_prompt(context, 1)
    check(
        "--role reproduce --strategy S5" in rendered
        and "reproduce--strategy" not in rendered,
        "state resume command keeps role and strategy as separate arguments",
    )
    check(
        "bin/state resume --agent N" in prompt.common_suffix(context),
        "static suffix uses an agent-neutral resume placeholder",
    )

    counter_logs = root / "counter-logs"
    counter_logs.mkdir()
    counter_runtime = SimpleNamespace(logs=counter_logs, num_agents=2)
    for name in (".llm_decisions_harness", ".llm_decisions_1", ".llm_decisions_2"):
        (counter_logs / name).write_text("1000", encoding="utf-8")
    audit_runner.reset_llm_decision_counters(counter_runtime)
    check(
        all((counter_logs / name).read_text() == "0" for name in (
            ".llm_decisions_harness", ".llm_decisions_1", ".llm_decisions_2"
        )),
        "iteration reset covers harness and per-agent LLM decision budgets",
    )

    progress_results = root / "progress-results"
    findings = progress_results / "findings"
    state = progress_results / "state"
    findings.mkdir(parents=True)
    state.mkdir()

    def finding(name: str, cluster: str) -> None:
        directory = findings / name
        directory.mkdir()
        (directory / ".keep").touch()
        (directory / "report.md").write_text(f"Cluster: {cluster}\n", encoding="utf-8")

    finding("FIND-001", "FCL-A")
    runtime = SimpleNamespace(results=progress_results, num_agents=1)
    before = audit_runner.progress(runtime)
    finding("FIND-002", "FCL-A")
    duplicate = audit_runner.progress(runtime)
    check(
        not audit_runner.newly_introduced_roots(before, duplicate),
        "duplicate artifact directories do not count as productive root causes",
    )
    finding("FIND-003", "FCL-B")
    novel = audit_runner.progress(runtime)
    check(
        audit_runner.newly_introduced_roots(duplicate, novel) == {"finding:FCL-B"},
        "a newly accepted root cause counts as productivity",
    )
    (state / "hypotheses.jsonl").write_text(
        json.dumps({"agent": "1", "status": "ENV-BLOCKED"}) + "\n",
        encoding="utf-8",
    )
    check(
        audit_runner.progress(runtime).env_blocked == 1,
        "progress snapshot carries diagnostic ENV-BLOCKED closures",
    )

    queue_results = root / "queue-results"
    (queue_results / "state").mkdir(parents=True)
    queue_runtime = SimpleNamespace(
        root=ROOT, target_root=target, target_slug="sample", results=queue_results,
        repo_type="none", index=root / "queue-index.log",
    )
    (queue_results / "work-cards.jsonl").write_text(
        json.dumps({"id": "WORK-1", "kind": "ranked-source", "status": "unclaimed"}) + "\n",
        encoding="utf-8",
    )
    (queue_results / "state" / "claims.jsonl").write_text(
        json.dumps({"card_id": "WORK-1", "status": "discarded"}) + "\n",
        encoding="utf-8",
    )
    (queue_results / "state" / "rank-work-window.json").write_text(
        json.dumps({"limit": 120, "core_count": 120}) + "\n",
        encoding="utf-8",
    )
    with mock.patch.object(audit_runner, "refresh_work_cards", return_value=True) as refresh:
        expanded = audit_runner.expand_work_cards_if_exhausted(queue_runtime)
    check(
        expanded and refresh.call_args.kwargs == {"force": True, "limit": 240},
        "an exhausted full rank window expands before audit shutdown",
    )

    strategy_results = root / "strategy-results"
    (strategy_results / "state").mkdir(parents=True)
    (strategy_results / "work-cards.jsonl").write_text(
        json.dumps({
            "id": "PROMOTE", "status": "unclaimed", "strategy": "S7",
            "allowed_strategies": ["S5", "S7"],
        }) + "\n",
        encoding="utf-8",
    )
    strategy_runtime = SimpleNamespace(
        root=ROOT, target_root=target, target_slug="sample",
        results=strategy_results, repo_type="none",
    )
    workqueue.init_state(audit_runner._queue_context(strategy_runtime))
    counts = audit_runner._eligible_strategy_counts(strategy_runtime)
    check(
        counts["S5"] == counts["S7"] == 1,
        "scheduler availability matches allowed-strategy claim semantics",
    )

    stream_results = root / "stream-results"
    stream_logs = root / "stream-logs"
    stream_raw = stream_logs / ".raw"
    (stream_results / "scratch-1").mkdir(parents=True)
    stream_raw.mkdir(parents=True)
    stream_runtime = audit_runner.Runtime(
        ROOT, target, "sample", "sample", "claude", "fixture-model",
        target_config.Config(target_root=str(target)), "HEAD", "none",
        stream_results, stream_logs, stream_raw,
        stream_logs / "index.log", stream_logs / "index.jsonl",
        1, 0, 1, (), "", 45,
    )
    stream_context = mock.Mock()
    stream_context.role.return_value = "reproduce"
    stream_context.scratch_dir.return_value = stream_results / "scratch-1"
    def launch(_backend, _prompt, _timeout, raw_log, **_kwargs):
        launch_count[0] += 1
        if launch_count[0] == 1:
            Path(raw_log).write_text("Stream idle timeout - partial response received\n", encoding="utf-8")
            return 1
        Path(raw_log).write_text('{"type":"result","result":"done"}\n', encoding="utf-8")
        return 0

    launch_count = [0]
    with mock.patch.object(prompt, "cold_start_prompt", return_value="prompt"), \
         mock.patch.object(llm_invoke, "run_agent_prompt", side_effect=launch), \
         mock.patch.object(llm_invoke, "extract_text", return_value="done"), \
         mock.patch.object(audit_runner.llm_usage, "extract_usage", return_value={"tokens": {}}), \
         mock.patch.object(audit_runner.build_session_seed, "write_session_seed"):
        result = audit_runner.run_agent(stream_runtime, stream_context, 1, 1, True)
    check(
        launch_count[0] == 2 and result.returncode == 0,
        "Claude stream-idle failure retries once through the real launch path",
    )

    check(
        audit_runner._decision_timeout_for_backend("oss", None) == 180
        and audit_runner._decision_timeout_for_backend("codex", None) == 45
        and audit_runner._decision_timeout_for_backend("oss", "240") == 240,
        "decision timeout keeps hosted/OSS defaults and explicit override precedence",
    )
    check(
        triage._valid_reach_field("caller_controls", "bytes") == "bytes"
        and triage._valid_reach_field("caller_controls", "bytes, length") == "",
        "caller-controls validation keeps the prompt's single-enum scorer contract",
    )

    fake_codex = root / "fake_codex.py"
    fake_codex.write_text(
        "import json,time\n"
        "for i in range(4):\n"
        " print(json.dumps({'type':'item.completed','item':{'type':'command_execution','id':i}}), flush=True)\n"
        " time.sleep(0.2)\n"
        "time.sleep(10)\n",
        encoding="utf-8",
    )
    watchdog_raw = root / "watchdog.raw"
    started = time.monotonic()
    watchdog_rc = llm_invoke._run_codex_with_turn_watchdog(
        [sys.executable, str(fake_codex)], None, watchdog_raw, root,
        os.environ.copy(), 2,
    )
    check(
        watchdog_rc == 0
        and time.monotonic() - started < 5
        and "TURN_SOFT_CAP reached" in watchdog_raw.read_text(encoding="utf-8"),
        "Codex turn watchdog checkpoints and terminates a session at the soft cap",
    )

    # A crash confirmed at the nominal cap gets a bounded enrichment tail.
    grace_results = root / "grace-results"
    grace_report = grace_results / "crashes" / "CRASH-001-1" / "report.md"
    grace_report.parent.mkdir(parents=True)
    grace_report.write_text("_TODO (agent): enrich\n", encoding="utf-8")
    grace_tried = grace_results / "tried-inputs-1.log"
    grace_codex = root / "grace_codex.py"
    grace_codex.write_text(
        "import json,sys,time\n"
        "from pathlib import Path\n"
        "report=Path(sys.argv[1])\n"
        "for i in range(6):\n"
        " print(json.dumps({'type':'item.completed','item':{'type':'command_execution','id':i}}), flush=True)\n"
        " time.sleep(0.6)\n"
        " if i == 3: report.write_text('## Root Cause\\ncomplete\\n')\n"
        "time.sleep(10)\n",
        encoding="utf-8",
    )
    grace_env = {**os.environ, "TRIED_INPUTS_LOG": str(grace_tried), "AGENT_NUM": "1"}
    grace_raw = root / "grace-watchdog.raw"
    grace_started = time.monotonic()
    grace_rc = llm_invoke._run_codex_with_turn_watchdog(
        [sys.executable, str(grace_codex), str(grace_report)], None,
        grace_raw, root, grace_env, 2,
    )
    grace_text = grace_raw.read_text(encoding="utf-8")
    check(
        grace_rc == 0
        and grace_text.count('"type": "item.completed"') >= 4
        and time.monotonic() - grace_started < 7,
        "Codex watchdog permits mandatory crash enrichment past the nominal cap",
        grace_text,
    )

    # The enrichment exception remains bounded when the report never finishes.
    grace_report.write_text("_TODO (agent): still pending\n", encoding="utf-8")
    bounded_raw = root / "bounded-watchdog.raw"
    with mock.patch.object(llm_invoke, "_CRASH_ENRICHMENT_GRACE_COMMANDS", 2), \
         mock.patch.object(llm_invoke, "_CRASH_ENRICHMENT_GRACE_SECONDS", 2):
        bounded_rc = llm_invoke._run_codex_with_turn_watchdog(
            [sys.executable, str(fake_codex)], None, bounded_raw, root,
            grace_env, 2,
        )
    check(
        bounded_rc == 0
        and "TURN_SOFT_CAP reached" in bounded_raw.read_text(encoding="utf-8"),
        "Codex crash-enrichment tail remains bounded",
    )

    singleton_runtime = object()
    singleton_target = root / "singleton-target"
    singleton_target.mkdir()
    with mock.patch.dict(os.environ, {"SCRIPT_ROOT": str(ROOT)}, clear=False), \
         mock.patch.object(audit_runner, "discover_backends", return_value=["codex"]), \
         mock.patch.object(audit_runner, "prepare_runtime", return_value=singleton_runtime), \
         mock.patch.object(audit_runner, "run_backend", return_value=0) as single_run, \
         mock.patch.object(audit_runner, "run_ensemble", return_value=0) as ensemble_run:
        main_rc = audit_runner.main([
            "--target-path", str(singleton_target), "--backend", "all", "1",
        ])
    check(
        main_rc == 0 and single_run.call_count == 1 and ensemble_run.call_count == 0,
        "default all-backend mode uses recoverable single-backend orchestration when only one exists",
    )

    with file_tools.capture_command([
        sys.executable, "-c", "import sys; sys.stdout.write('x' * (5 * 1024 * 1024))",
    ]) as captured:
        capped = file_tools.cap_output_file(
            captured.stdout, "large-fixture",
            {"OUTCAP_MAX_BYTES": "1024", "OUTCAP_HEAD_BYTES": "600", "OUTCAP_TAIL_BYTES": "400"},
        )
        capture_size = captured.stdout.stat().st_size
    check(
        capture_size == 5 * 1024 * 1024
        and len(capped) < 4096
        and b"5,242,880 total bytes" in capped,
        "file-backed command capture caps multi-megabyte output after disk capture",
    )


print(f"\n{passed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
