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

import audit_helpers
import audit_runner
import benchmark
import cluster_common
import file_tools
import llm_invoke
import process_tree
import prompt
import report_identity
import target_config
import triage
import validation_receipt
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

    run_config = root / "run-config.json"
    audit_runner._write_run_config(
        run_config, 1, 0, 1, "codex", "fixture-model", "sample",
        "sandboxed",
    )
    check(
        json.loads(run_config.read_text(encoding="utf-8"))["agent_security"]
        == "sandboxed",
        "audit run metadata records the selected agent security profile",
    )

    # On a case-insensitive filesystem a `directory / "REPORT.md"` probe
    # answers for an on-disk `report.md` and hands back the case it was asked
    # for. Every consumer must agree on the one spelling the directory has:
    # triage feeds it to `render-md --html-sibling`, which names the sibling
    # after it, and the cluster tools then link that pair by exact name.
    report_dir = root / "exact-report-case"
    report_dir.mkdir()
    (report_dir / "report.md").write_text("finding\n", encoding="utf-8")
    check(
        {
            report_identity.find_report(report_dir),
            triage._report(report_dir),
            cluster_common.artifact_report_paths(report_dir)[0],
        } == {report_dir / "report.md"},
        "report consumers agree on the report's exact on-disk case",
    )

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
        validation_receipt.write(
            directory,
            kind="finding",
            state="reportable",
            detail="neutral migration fixture",
        )

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
    secondary_report = findings / "FIND-004"
    secondary_report.mkdir()
    (secondary_report / ".keep").touch()
    (secondary_report / "report.md").write_text(
        "# Primary report without a cluster stamp\n", encoding="utf-8"
    )
    (secondary_report / "description.md").write_text(
        "Cluster: FCL-B\n", encoding="utf-8"
    )
    validation_receipt.write(
        secondary_report,
        kind="finding",
        state="reportable",
        detail="neutral migration fixture",
    )
    secondary_duplicate = audit_runner.progress(runtime)
    check(
        audit_runner.newly_introduced_roots(novel, secondary_duplicate)
        == {"finding:FIND-004"},
        "progress does not resurrect a stale cluster stamp from a secondary report file",
    )
    trigger_pending = findings / "FIND-005"
    trigger_pending.mkdir()
    trigger_report = trigger_pending / "report.md"
    trigger_report.write_text("# State issue\n\nCluster: FCL-C\n", encoding="utf-8")
    (trigger_pending / ".llm-find-quality.json").write_text(json.dumps({
        "accept": True,
        "report_sha1": report_identity.content_sha1(trigger_report),
    }), encoding="utf-8")
    pending_progress = audit_runner.progress(runtime)
    check(
        audit_runner.newly_introduced_roots(secondary_duplicate, pending_progress)
        == {"finding:FCL-C"},
        "a quality-accepted finding counts as audit progress while trigger review is pending",
    )
    check(
        benchmark.count_confirmed_findings(findings)[0] == 4,
        "strict benchmark credit still excludes the trigger-pending finding",
    )
    validation_receipt.write(
        trigger_pending,
        kind="finding",
        state="not-reportable",
        detail="real defect outside the configured security boundary",
    )
    uncredited_progress = audit_runner.progress(runtime)
    check(
        uncredited_progress.findings == pending_progress.findings - 1
        and "FIND-005" not in uncredited_progress.artifact_roots,
        "a final not-reportable receipt removes live security progress",
    )
    (state / "hypotheses.jsonl").write_text(
        json.dumps({"agent": "1", "status": "ENV-BLOCKED"}) + "\n",
        encoding="utf-8",
    )
    check(
        audit_runner.progress(runtime).env_blocked == 1,
        "progress snapshot carries diagnostic ENV-BLOCKED closures",
    )

    # A candidate filed but not yet adjudicated is invisible to progress()
    # (admitted-only) yet must show up in filed_artifact_count so the iteration
    # label can say "filed-unadjudicated" instead of "env-blocked".
    filed_before = audit_runner.filed_artifact_count(runtime)
    bare = findings / "FIND-006"
    bare.mkdir()
    (bare / "report.md").write_text("# Ungated candidate\n", encoding="utf-8")
    check(
        audit_runner.filed_artifact_count(runtime) == filed_before + 1
        and audit_runner.progress(runtime).findings == uncredited_progress.findings,
        "filed_artifact_count sees an ungated candidate that admitted-only progress does not",
    )

    label = audit_runner.iteration_outcome_label
    check(
        label(productive=True, filed=True, diagnostic=True) == "productive"
        and label(productive=False, filed=True, diagnostic=False) == "filed-unadjudicated"
        and label(productive=False, filed=False, diagnostic=True) == "env-blocked"
        and label(productive=False, filed=False, diagnostic=False) == "dry",
        "iteration labels name what actually happened",
    )
    check(
        label(productive=False, filed=True, diagnostic=True)
        == "filed-unadjudicated+env-blocked",
        "filing does not hide an env-blocked closure the operator is looking for",
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

    window_results = root / "window-results"
    (window_results / "state").mkdir(parents=True)
    (window_results / "work-cards.jsonl").write_text(
        "\n".join([
            json.dumps({"id": "A-S5", "kind": "ranked-source", "file": "src/a.c"}),
            json.dumps({"id": "A-S7", "kind": "ranked-source", "file": "src/a.c"}),
            json.dumps({"id": "PATCH-1", "kind": "s1-patch", "file": "src/b.c"}),
            json.dumps({"id": "PEER-1", "kind": "s6-peer-fix", "file": ""}),
        ]) + "\n",
        encoding="utf-8",
    )
    window_runtime = SimpleNamespace(results=window_results)
    audit_runner._write_rank_window(window_runtime, 120)
    window_row = json.loads(
        (window_results / "state" / "rank-work-window.json").read_text()
    )
    check(
        window_row == {"limit": 120, "core_count": 2},
        "rank-window exhaustion counts one slot per source file, not per strategy angle",
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

    # A lane whose cards are gone must not keep its agent: nothing else moves
    # it, and post-iteration rotation never runs on an interrupted iteration.
    starved_results = root / "starved-results"
    (starved_results / "state").mkdir(parents=True)
    (starved_results / "work-cards.jsonl").write_text(
        "".join(
            json.dumps({"id": f"C{index}", "status": "unclaimed", "strategy": "S3"}) + "\n"
            for index in range(3)
        ),
        encoding="utf-8",
    )
    starved_runtime = SimpleNamespace(
        root=ROOT, target_root=target, target_slug="sample",
        results=starved_results, repo_type="none",
        num_agents=2, fixed_strategy="", agent_roles="",
    )
    workqueue.init_state(audit_runner._queue_context(starved_runtime))
    lane_one = starved_results / "state" / "strategy-1"
    lane_one.write_text("S8\n", encoding="utf-8")
    (starved_results / "state" / "strategy-2").write_text("S3\n", encoding="utf-8")
    audit_runner.initialize_agent_strategies(starved_runtime)
    check(
        lane_one.read_text().strip() == "S3",
        "an agent on a lane with no claimable cards is reassigned to one with cards",
    )
    check(
        (starved_results / "state" / "strategy-2").read_text().strip() == "S3",
        "an agent whose lane still has cards keeps it",
    )

    # A claimed card leaves the unclaimed count, so an agent that just took the
    # last card in its lane must not be rotated off the work it is doing.
    claimed_results = root / "claimed-results"
    (claimed_results / "state").mkdir(parents=True)
    (claimed_results / "work-cards.jsonl").write_text(
        json.dumps({"id": "HELD", "status": "unclaimed", "strategy": "S8",
                    "file": "src/a.c"}) + "\n"
        + json.dumps({"id": "FREE", "status": "unclaimed", "strategy": "S1",
                      "file": "src/b.c"}) + "\n",
        encoding="utf-8",
    )
    claimed_runtime = SimpleNamespace(
        root=ROOT, target_root=target, target_slug="sample",
        results=claimed_results, repo_type="none",
        num_agents=1, fixed_strategy="", agent_roles="",
    )
    claimed_ctx = audit_runner._queue_context(claimed_runtime)
    workqueue.init_state(claimed_ctx)
    workqueue.claim_next_card(claimed_ctx, agent="1", strategy="S8")
    lane = claimed_results / "state" / "strategy-1"
    lane.write_text("S8\n", encoding="utf-8")
    audit_runner.initialize_agent_strategies(claimed_runtime)
    check(
        lane.read_text().strip() == "S8",
        "an agent holding a live claim keeps its lane when the queue reads empty",
    )

    # A card is claimable under its primary strategy and under every angle in
    # allowed_strategies, which is how select_strategy_window carries dropped
    # companions. A claim taken through one of those is still this agent's work.
    allowed_results = root / "allowed-results"
    (allowed_results / "state").mkdir(parents=True)
    (allowed_results / "work-cards.jsonl").write_text(
        json.dumps({"id": "VIA", "status": "unclaimed", "strategy": "S7",
                    "allowed_strategies": ["S8"], "file": "src/a.c"}) + "\n"
        + json.dumps({"id": "OTHER", "status": "unclaimed", "strategy": "S1",
                      "file": "src/b.c"}) + "\n",
        encoding="utf-8",
    )
    allowed_runtime = SimpleNamespace(
        root=ROOT, target_root=target, target_slug="sample",
        results=allowed_results, repo_type="none",
        num_agents=1, fixed_strategy="", agent_roles="",
    )
    allowed_ctx = audit_runner._queue_context(allowed_runtime)
    workqueue.init_state(allowed_ctx)
    workqueue.claim_next_card(allowed_ctx, agent="1", strategy="S8")
    allowed_lane = allowed_results / "state" / "strategy-1"
    allowed_lane.write_text("S8\n", encoding="utf-8")
    audit_runner.initialize_agent_strategies(allowed_runtime)
    check(
        allowed_lane.read_text().strip() == "S8",
        "a claim taken through allowed_strategies keeps that lane",
    )
    # And from an open hypothesis when the claim is not this agent's: the card
    # was released and taken by a peer while this agent is still investigating
    # it, so neither the unclaimed count nor its own claims mention the lane.
    workqueue.claim_next_card(claimed_ctx, agent="2", strategy="S8")
    (claimed_results / "state" / "hypotheses.jsonl").write_text(
        json.dumps({"agent": "1", "card_id": "HELD", "status": "INVESTIGATING"}) + "\n",
        encoding="utf-8",
    )
    check(
        not audit_runner._eligible_strategy_counts(claimed_runtime).get("S8")
        and "S8" in audit_runner._agent_live_strategies(claimed_runtime).get("1", set()),
        "the lane reads empty in the queue and live only through the hypothesis",
    )
    lane.write_text("S8\n", encoding="utf-8")
    audit_runner.initialize_agent_strategies(claimed_runtime)
    check(
        lane.read_text().strip() == "S8",
        "an agent with an open hypothesis keeps its lane",
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
    stream_runtime.agent_security = "external-bypass"
    with mock.patch.dict(os.environ, {}, clear=True):
        audit_runner._activate_runtime(stream_runtime)
        inherited_security = os.environ.get(llm_invoke.AGENT_SECURITY_ENV)
    check(
        inherited_security == "external-bypass",
        "audit propagates its security profile to validator subprocesses",
    )
    stream_context = mock.Mock()
    stream_context.role.return_value = "reproduce"
    stream_context.scratch_dir.return_value = stream_results / "scratch-1"
    stream_context.turn_soft_cap = 128
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


    with mock.patch.dict(os.environ, {"ACTIVE_BACKEND": "oss"}, clear=True):
        oss_tier = triage.llm_decide.decision_timeout("unmeasured")
    with mock.patch.dict(os.environ, {"ACTIVE_BACKEND": "codex"}, clear=True):
        hosted_tier = triage.llm_decide.decision_timeout("unmeasured")
    check(
        oss_tier == 180 and hosted_tier == 45
        and audit_runner._operator_decision_timeout(None) == 0
        and audit_runner._operator_decision_timeout("240") == 240,
        "tier defaults hold and the runtime records only an explicit ceiling",
    )
    check(
        triage._valid_reach_field("caller_controls", "bytes") == "bytes"
        and triage._valid_reach_field("caller_controls", "bytes, length") == ""
        and triage._valid_reach_field("caller_contract", "unspecified") == "unspecified"
        and triage._reach_field_present(
            "Caller contract: unspecified", "Caller contract"
        )
        and not triage._reach_field_present("Surface: unspecified", "Surface")
        and not triage._reach_field_present("| Surface | ? |", "Surface"),
        "reach validation keeps enums aligned and all placeholders missing",
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
    watchdog_rc = llm_invoke._run_agent_process(
        [sys.executable, str(fake_codex)], None, watchdog_raw, root,
        os.environ.copy(), turn_cap=2,
    )
    check(
        watchdog_rc == 0
        and time.monotonic() - started < 5
        and "TURN_SOFT_CAP reached" in watchdog_raw.read_text(encoding="utf-8"),
        "the turn watchdog checkpoints and terminates a session at the soft cap",
    )

    # A completed-result watchdog must not terminate the tool at dispatch.
    # Before the backend-neutral cap, Claude had only a 1000-turn native
    # ceiling, so observed sessions still ran to hundreds of requests.
    fake_claude = root / "fake_claude.py"
    fake_claude.write_text(
        "import json,time\n"
        "for i in range(4):\n"
        " print(json.dumps({'type':'assistant','message':{'id':'m%d'%i,'content':["
        "{'type':'text','text':'step'},{'type':'tool_use','name':'Bash'}]}}), flush=True)\n"
        " time.sleep(0.4)\n"
        " print(json.dumps({'type':'user','message':{'content':["
        "{'type':'tool_result','tool_use_id':'u%d'%i,'content':'done'}]}}), flush=True)\n"
        " time.sleep(0.1)\n"
        "time.sleep(10)\n",
        encoding="utf-8",
    )
    claude_raw = root / "claude-watchdog.raw"
    claude_started = time.monotonic()
    claude_rc = llm_invoke._run_agent_process(
        [sys.executable, str(fake_claude)], None, claude_raw, root,
        os.environ.copy(), turn_cap=2,
    )
    claude_text = claude_raw.read_text(encoding="utf-8")
    check(
        claude_rc == 0
        and time.monotonic() - claude_started < 5
        and "TURN_SOFT_CAP reached" in claude_text
        and claude_text.count('"type": "user"') >= 2
        and llm_invoke.session_turn_capped(claude_raw),
        "the transcript cap waits for Claude tool results before checkpointing",
        claude_text,
    )
    check(
        not llm_invoke.session_turn_capped(root / "does-not-exist.raw"),
        "a session that was never capped is not reported as checkpointed",
    )
    spoofed_cap = root / "spoofed-cap.raw"
    spoofed_cap.write_text(
        f"tool output: [audit] {llm_invoke.TURN_CAP_MARKER} after 2 calls\n"
        '{"type":"turn.completed"}\n',
        encoding="utf-8",
    )
    check(
        not llm_invoke.session_turn_capped(spoofed_cap),
        "tool output cannot spoof a cap marker before a natural terminal event",
    )

    class ExitedAtCap:
        pid = 123
        returncode = None

        def poll(self):
            return self.returncode

        def terminate(self):
            # The child already exited on its own; terminate() races with that.
            self.returncode = 0
            raise ProcessLookupError

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

        def kill(self):
            self.returncode = -9

    natural_raw = root / "natural-at-cap.raw"
    with mock.patch.object(llm_invoke.subprocess, "Popen", return_value=ExitedAtCap()), \
         mock.patch.object(audit_helpers, "tool_call_delta", return_value=(2, 0)), \
         mock.patch.object(process_tree, "kill_descendants"):
        natural_rc = llm_invoke._run_agent_process(
            ["unused"], None, natural_raw, root, os.environ.copy(), turn_cap=2,
        )
    check(
        natural_rc == 0
        and "TURN_SOFT_CAP reached" not in natural_raw.read_text(encoding="utf-8"),
        "a process that exits at the cap is not mislabeled as checkpointed",
    )

    native_cap = root / "native-cap.py"
    native_cap.write_text(
        "import json,sys\n"
        "print(json.dumps({'type':'result','subtype':'error_max_turns',"
        "'is_error':True,'modelUsage':{'claude':{'inputTokens':2}}}))\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    native_raw = root / "native-cap.raw"
    native_rc = llm_invoke._run_agent_process(
        [sys.executable, str(native_cap)], None, native_raw, root,
        os.environ.copy(), checkpoint_on_native_limit=True,
    )
    check(
        native_rc == 0 and llm_invoke.session_turn_capped(native_raw),
        "an explicitly armed Claude native ceiling is a checkpoint with usage, not a failure",
    )

    grok_cap = root / "grok-native-cap.py"
    grok_cap.write_text(
        "import json\n"
        "print(json.dumps({'type':'max_turns_reached','turns':100}))\n",
        encoding="utf-8",
    )
    grok_raw = root / "grok-native-cap.raw"
    grok_rc = llm_invoke._run_agent_process(
        [sys.executable, str(grok_cap)], None, grok_raw, root,
        os.environ.copy(), checkpoint_on_native_limit=True,
    )
    check(
        grok_rc == 0 and llm_invoke.session_turn_capped(grok_raw),
        "an explicitly armed Grok native ceiling is normalized from its structured event",
    )

    gemini_cap = root / "gemini-native-cap.py"
    gemini_cap.write_text(
        "import json,sys\n"
        "print(json.dumps({'type':'result','status':'error','error':{"
        "'type':'FatalTurnLimitedError','message':'turn limit'},"
        "'stats':{'input_tokens':2}}))\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    gemini_raw = root / "gemini-native-cap.raw"
    gemini_rc = llm_invoke._run_agent_process(
        [sys.executable, str(gemini_cap)], None, gemini_raw, root,
        os.environ.copy(), checkpoint_on_native_limit=True,
    )
    check(
        gemini_rc == 0 and llm_invoke.session_turn_capped(gemini_raw),
        "an explicitly armed Gemini native ceiling retains terminal stats",
    )

    prose_limit = root / "native-cap-prose.py"
    prose_limit.write_text(
        "import json,sys\n"
        "print(json.dumps({'type':'assistant','message':{'content':["
        "{'type':'text','text':'error_max_turns'}]}}))\n"
        "sys.exit(1)\n",
        encoding="utf-8",
    )
    prose_raw = root / "native-cap-prose.raw"
    prose_rc = llm_invoke._run_agent_process(
        [sys.executable, str(prose_limit)], None, prose_raw, root,
        os.environ.copy(), checkpoint_on_native_limit=True,
    )
    check(
        prose_rc == 1 and not llm_invoke.session_turn_capped(prose_raw),
        "model prose cannot spoof the structured native-cap checkpoint signal",
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
    grace_rc = llm_invoke._run_agent_process(
        [sys.executable, str(grace_codex), str(grace_report)], None,
        grace_raw, root, grace_env, turn_cap=2,
    )
    grace_text = grace_raw.read_text(encoding="utf-8")
    check(
        grace_rc == 0
        and grace_text.count('"type": "item.completed"') >= 4
        and time.monotonic() - grace_started < 7,
        "the turn watchdog permits mandatory crash enrichment past the nominal cap",
        grace_text,
    )

    # The enrichment exception remains bounded when the report never finishes.
    grace_report.write_text("_TODO (agent): still pending\n", encoding="utf-8")
    bounded_raw = root / "bounded-watchdog.raw"
    with mock.patch.object(llm_invoke, "_CRASH_ENRICHMENT_GRACE_COMMANDS", 2), \
         mock.patch.object(llm_invoke, "_CRASH_ENRICHMENT_GRACE_SECONDS", 2):
        bounded_rc = llm_invoke._run_agent_process(
            [sys.executable, str(fake_codex)], None, bounded_raw, root,
            grace_env, turn_cap=2,
        )
    check(
        bounded_rc == 0
        and "TURN_SOFT_CAP reached" in bounded_raw.read_text(encoding="utf-8"),
        "the crash-enrichment tail remains bounded",
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

    filtered_runtime = object()
    filtered_target = root / "filtered-target"
    filtered_target.mkdir()
    with mock.patch.dict(os.environ, {"SCRIPT_ROOT": str(ROOT)}, clear=False), \
         mock.patch.object(
             audit_runner, "discover_backends", return_value=["grok", "codex"],
         ), \
         mock.patch.object(
             audit_runner, "prepare_runtime", return_value=filtered_runtime,
         ) as filtered_prepare, \
         mock.patch.object(audit_runner, "run_backend", return_value=0), \
         mock.patch.object(audit_runner, "run_ensemble", return_value=0):
        filtered_rc = audit_runner.main([
            "--target-path", str(filtered_target), "--backend", "all", "1",
        ])
    filtered_backends = [
        call.args[4] for call in filtered_prepare.call_args_list
    ]
    check(
        filtered_rc == 0 and filtered_backends == ["codex"],
        "an ensemble spends its iteration limit on backends the profile can launch",
    )

    overlay_root = root / "overlay-harness"
    overlay = overlay_root / "lib" / "target-overlays"
    chromium_source = overlay_root / "targets" / "chromium" / "src"
    overlay.mkdir(parents=True)
    chromium_source.mkdir(parents=True)
    (overlay / "chromium.toml").write_text(
        'source_subdir = "src"\n', encoding="utf-8"
    )
    overlay_runtime = object()
    with mock.patch.dict(
        os.environ, {"SCRIPT_ROOT": str(overlay_root)}, clear=False
    ), mock.patch.object(
        audit_runner, "backend_configured", return_value=True
    ), mock.patch.object(
        audit_runner, "prepare_runtime", return_value=overlay_runtime
    ) as overlay_prepare, mock.patch.object(
        audit_runner, "run_backend", return_value=0
    ):
        overlay_rc = audit_runner.main([
            "--target", "chromium", "--backend", "codex", "1",
        ])
    overlay_args = (
        overlay_prepare.call_args.args
        if overlay_prepare.call_args is not None else ()
    )
    check(
        overlay_rc == 0
        and len(overlay_args) >= 4
        and overlay_args[1] == chromium_source
        and overlay_args[2:4] == ("chromium/src", "chromium/src")
        # agent security then the delta base: no --since means "".
        and overlay_args[-2:] == ("sandboxed", ""),
        "audit target overlay resolves source and output identity before runtime setup",
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
