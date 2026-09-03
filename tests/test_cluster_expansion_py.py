#!/usr/bin/env python3
"""Behavior coverage for post-crash sibling expansion."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner
import triage
import workqueue


def check(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)
    print(f"  \033[0;32m✓\033[0m {message}")


def crash_with_frame(results: Path, target: Path, crash_id: str) -> Path:
    crash = results / "crashes" / crash_id
    crash.mkdir(parents=True)
    source = target / "src" / "parser.c"
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text("\n".join(f"int line_{line};" for line in range(1, 40)) + "\n")
    (crash / "sanitizer.txt").write_text(
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
        f"    #0 0x1 in app_parse {source}:20\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow\n",
        encoding="utf-8",
    )
    return crash


with tempfile.TemporaryDirectory(prefix="cluster-expansion-") as temporary:
    root = Path(temporary)
    target = root / "target"
    results = root / "results"
    (results / "crashes").mkdir(parents=True)
    (results / "state").mkdir()
    context = workqueue.Context(ROOT, target, "sampleproj", results, "git")

    crash = crash_with_frame(results, target, "CRASH-010-2")
    captured: dict[str, object] = {}

    def decide(_name, _keys, prompt, timeout, **kwargs):
        captured.update(prompt=prompt, timeout=timeout, **kwargs)
        return {
            "items": [{
                "id": crash.name,
                "rows": [{
                    "file": "src/parser.c", "function": "parse_next", "line": 24,
                    "hypothesis": "neighbor parser shares the unchecked length", "category": "bounds",
                }],
            }]
        }

    with mock.patch.dict(os.environ, {"LLM_DECISION_TIMEOUT": "17"}, clear=False), \
         mock.patch.object(triage.llm_decide, "llm_decide", side_effect=decide):
        rows = triage.cluster_expansion_decisions([crash], target).get(crash)
    check(len(rows or []) == 1, "decision returns a concrete sibling row")
    check("int line_20" in str(captured.get("prompt")), "decision prompt includes bounded nearby source")
    check(captured.get("timeout") == 17, "an explicit session setting overrides the per-decision default")
    check(
        captured.get("usage_index") == results / "logs" / "index.jsonl",
        "cluster decisions charge the results-tree usage ledger",
    )

    partial = crash_with_frame(results, target, "CRASH-011-2")
    with mock.patch.object(
        triage.llm_decide, "llm_decide", side_effect=decide,
    ) as one_batch:
        keyed = triage.cluster_expansion_decisions([crash, partial], target)
    check(one_batch.call_count == 1, "a crash group uses one keyed expansion decision")
    check(keyed[crash] == rows, "a returned crash id keeps its sibling rows")
    check(keyed[partial] is None, "a missing crash id remains retryable")
    (partial / ".cluster_expanded").write_text("covered by batch parsing test\n")

    # Unset, this decision gets its own measured default -- the tier ceiling is
    # shorter than a single observed call, so every call would time out.
    for backend, expected in (("claude", 800), ("oss", 3200)):
        captured.clear()
        with mock.patch.dict(os.environ, {"ACTIVE_BACKEND": backend}, clear=True), \
             mock.patch.object(triage.llm_decide, "llm_decide", side_effect=decide):
            triage.cluster_expansion_decisions([crash], target)
        check(
            captured.get("timeout") == expected,
            f"standalone cluster decisions get the measured {backend} default",
        )

    origin = {
        "id": "H-origin", "agent": "2", "card_id": "WORK-origin",
        "hypothesis": "origin", "file": "src/parser.c:app_parse:20",
        "input_shape": "bytes", "guard_gap": "missing check", "diagnostic": "bounds",
        "strategy": "S2", "status": "CRASH-010-2",
    }
    (results / "state" / "hypotheses.jsonl").write_text(json.dumps(origin) + "\n", encoding="utf-8")
    added = workqueue.add_cluster_hypotheses(context, crash.name, rows or [], num_agents=2)
    hypotheses = workqueue.read_jsonl(results / "state" / "hypotheses.jsonl")
    sibling = hypotheses[-1]
    check(added["added"] == 1 and sibling["agent"] == "2", "sibling is owned by the filing agent")
    check(sibling["strategy"] == "S2", "sibling inherits the originating strategy")
    check(sibling["diagnostic"] == "bounds", "canonical category is preserved")
    duplicate = workqueue.add_cluster_hypotheses(context, crash.name, rows or [], num_agents=2)
    check(duplicate["added"] == 0, "active sibling hypotheses deduplicate across repeated crashes")

    off_taxonomy = [{
        "file": "src/parser.c", "function": "parse_alt", "line": 30,
        "hypothesis": "alternate parser shares the state gap", "category": "heap-overflow",
    }]
    clamped = workqueue.add_cluster_hypotheses(
        context, "CRASH-020-5", off_taxonomy, num_agents=2,
    )
    hypotheses = workqueue.read_jsonl(results / "state" / "hypotheses.jsonl")
    check(clamped["agent"] == "1", "persisted crash agent is clamped to the live worker set")
    check(hypotheses[-1]["diagnostic"] == "state", "off-taxonomy labels retain the lead in a neutral category")

    runtime = SimpleNamespace(
        results=results, target_root=target, num_agents=2, root=ROOT,
        target_slug="sampleproj", repo_type="git", index=root / "index.log",
        config=SimpleNamespace(attacker_controls=["bytes"]),
    )
    (results / "crashes" / "CRASH-CLUSTERS.md").write_text(
        "[CRASH-010-2](CRASH-010-2/REPORT.md)\n", encoding="utf-8"
    )
    audit_runner._migrate_cluster_backlog(runtime)
    check((crash / ".cluster_expanded").is_file(), "one-time migration skips already-indexed backlog crashes")

    fresh = crash_with_frame(results, target, "CRASH-030-1")
    empty = crash_with_frame(results, target, "CRASH-031-1")
    retry = crash_with_frame(results, target, "CRASH-032-1")

    def expansion(directories, _target, **_kwargs):
        return {
            directory: (
                None if directory == retry else [] if directory == empty else [{
                    "file": "src/parser.c", "function": "parse_fresh", "line": 35,
                    "hypothesis": "fresh crash exposes another neighbor", "category": "size",
                }]
            )
            for directory in directories
        }

    with mock.patch.object(triage, "cluster_expansion_decisions", side_effect=expansion) as decision:
        counts = audit_runner.expand_new_crash_clusters(runtime)
        retried = audit_runner.expand_new_crash_clusters(runtime)
    check(counts == {"expanded": 2, "added": 1, "skipped": 0, "pending": 1},
          "driver distinguishes completed, empty, and retryable decisions")
    check(retried == {"expanded": 0, "added": 0, "skipped": 0, "pending": 1},
          "unavailable expansion remains pending without retrying in the same audit")
    check(decision.call_count == 1, "new crashes share one expansion attempt per audit")
    check((fresh / ".cluster_expanded").is_file(), "successful expansion is marked exactly once")
    check((empty / ".cluster_expanded").is_file(), "empty rows are a completed expansion")
    check(not (retry / ".cluster_expanded").exists(), "unavailable decisions remain retryable")

    # An out-of-model seed still expands: expansion proposes source
    # neighbours, and a neighbour reachable from bytes can sit beside a crash
    # that is not. Skipping the seed would lose that lead for good. The seed's
    # scope constrains the leads instead, through attacker_controls.
    uncredited = crash_with_frame(results, target, "CRASH-040-1")
    (uncredited / "validation.json").write_text(
        json.dumps({"kind": "crash", "state": "not-reportable"}), encoding="utf-8",
    )
    runtime.config = SimpleNamespace(attacker_controls=["bytes"])
    runtime.cluster_expansion_attempted = set()
    with mock.patch.object(triage, "cluster_expansion_decisions", side_effect=expansion) as scoped:
        audit_runner.expand_new_crash_clusters(runtime)
    considered = [directory for call in scoped.call_args_list for directory in call.args[0]]
    check(uncredited in considered, "an out-of-model crash is still expanded")
    check(
        all(call.kwargs.get("attacker_controls") == ["bytes"]
            for call in scoped.call_args_list),
        "every expansion is scoped by the declared attacker_controls",
    )

    captured: dict[str, object] = {}

    def scoped_decide(_name, _keys, prompt, timeout, **kwargs):
        captured["prompt"] = prompt
        return {"items": [{"id": crash.name, "rows": []}]}

    with mock.patch.object(triage.llm_decide, "llm_decide", side_effect=scoped_decide):
        triage.cluster_expansion_decisions(
            [crash], target, attacker_controls=["bytes", "call-sequence"],
        )
    check(
        "bytes,call-sequence" in str(captured.get("prompt")),
        "the expansion prompt carries the declared controls",
    )

print("\ncluster expansion tests passed")
