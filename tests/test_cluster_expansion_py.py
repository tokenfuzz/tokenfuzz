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
            "rows": [{
                "file": "src/parser.c", "function": "parse_next", "line": 24,
                "hypothesis": "neighbor parser shares the unchecked length", "category": "bounds",
            }]
        }

    with mock.patch.dict(os.environ, {"LLM_DECISION_TIMEOUT": "17"}, clear=False), \
         mock.patch.object(triage.llm_decide, "llm_decide", side_effect=decide):
        rows = triage.cluster_expansion_decision(crash, target)
    check(len(rows or []) == 1, "decision returns a concrete sibling row")
    check("int line_20" in str(captured.get("prompt")), "decision prompt includes bounded nearby source")
    check(captured.get("timeout") == 17, "cluster decision uses the configured bounded timeout without a ten-minute floor")
    check(
        captured.get("usage_index") == results / "logs" / "index.jsonl",
        "cluster decisions charge the results-tree usage ledger",
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
    )
    (results / "crashes" / "CRASH-CLUSTERS.md").write_text(
        "[CRASH-010-2](CRASH-010-2/REPORT.md)\n", encoding="utf-8"
    )
    audit_runner._migrate_cluster_backlog(runtime)
    check((crash / ".cluster_expanded").is_file(), "one-time migration skips already-indexed backlog crashes")

    fresh = crash_with_frame(results, target, "CRASH-030-1")
    empty = crash_with_frame(results, target, "CRASH-031-1")
    retry = crash_with_frame(results, target, "CRASH-032-1")

    def expansion(directory, _target, **_kwargs):
        if directory == retry:
            return None
        if directory == empty:
            return []
        return [{
            "file": "src/parser.c", "function": "parse_fresh", "line": 35,
            "hypothesis": "fresh crash exposes another neighbor", "category": "size",
        }]

    with mock.patch.object(triage, "cluster_expansion_decision", side_effect=expansion) as decision:
        counts = audit_runner.expand_new_crash_clusters(runtime)
        retried = audit_runner.expand_new_crash_clusters(runtime)
    check(counts == {"expanded": 2, "added": 1, "skipped": 0, "pending": 1},
          "driver distinguishes completed, empty, and retryable decisions")
    check(retried == {"expanded": 0, "added": 0, "skipped": 0, "pending": 1},
          "unavailable expansion remains pending without retrying in the same audit")
    check(decision.call_count == 3, "each new crash gets at most one expansion attempt per audit")
    check((fresh / ".cluster_expanded").is_file(), "successful expansion is marked exactly once")
    check((empty / ".cluster_expanded").is_file(), "empty rows are a completed expansion")
    check(not (retry / ".cluster_expanded").exists(), "unavailable decisions remain retryable")

print("\ncluster expansion tests passed")
