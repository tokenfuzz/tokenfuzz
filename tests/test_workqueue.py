#!/usr/bin/env python3
"""Production-grade behavioral coverage for structured audit work queues."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import report_identity
import workqueue


class WorkQueueTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="workqueue-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.results = self.root / "results"
        self.target.mkdir()
        (self.target / ".git").mkdir()
        self.ctx = workqueue.Context(ROOT, self.target, "sample", self.results, "git")
        workqueue.init_state(self.ctx)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_cards(self, cards: list[dict]) -> None:
        workqueue.write_cards(self.results / "work-cards.jsonl", cards)

    def test_compact_finding_ignores_stale_content_addressed_gate_fields(self) -> None:
        finding = self.results / "findings" / "FIND-001"
        finding.mkdir(parents=True)
        report = finding / "report.md"
        report.write_text("# State issue\n\nConcrete boundary rationale.\n")
        (finding / ".llm-find-quality.json").write_text(json.dumps({
            "accept": True,
            "class": "auth:bypass",
            "severity": "high",
            "report_sha1": report_identity.content_sha1(report),
        }))
        current = workqueue._compact_finding(self.ctx, {"id": finding.name})
        self.assertEqual((current["class"], current["severity"]), ("auth:bypass", "high"))
        report.write_text(report.read_text() + "\nRevised substantive analysis.\n")
        stale = workqueue._compact_finding(self.ctx, {"id": finding.name})
        self.assertEqual((stale["class"], stale["severity"]), ("", ""))

    def run_command(
        self, command: list[str], *, env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            env=env,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

    def test_read_sample_uses_256kb_boundary(self) -> None:
        source = self.target / "large.c"
        source.write_bytes(b"A" * 255_999 + b"B" + b"C")

        sample = workqueue.read_sample(source)

        self.assertEqual(len(sample), 256_000)
        self.assertTrue(sample.endswith("B"))
        self.assertNotIn("C", sample)

    @staticmethod
    def card(
        card_id: str,
        file: str,
        *,
        strategy: str = "S1",
        mode: str = "generic",
        score: int = 10,
        kind: str = "ranked-source",
        **extra,
    ) -> dict:
        return {
            "id": card_id,
            "kind": kind,
            "file": file,
            "subsystem": str(Path(file).parent),
            "strategy": strategy,
            "mode": mode,
            "score": score,
            "reason": "ranked regression fixture",
            "auditable": True,
            **extra,
        }

    def add_hypothesis(self, *, hyp_id: str = "H-1", card_id: str = "WORK-A", agent: str = "1", **overrides) -> dict:
        values = {
            "id": hyp_id,
            "agent": agent,
            "card_id": card_id,
            "hypothesis": "issue in app_parse",
            "file": "src/app.c:app_parse:10",
            "input_shape": "crafted byte input",
            "guard_gap": "length check after read",
            "diagnostic": "bounds",
            "strategy": "S7",
            "status": "PENDING",
        }
        values.update(overrides)
        return workqueue.add_hypothesis(self.ctx, argparse.Namespace(**values))

    def add_run(self, *, card_id: str = "WORK-A", verdict: str = "CLEAN", index: int = 1, **overrides) -> dict:
        values = {
            "agent": "1",
            "hypothesis_id": "H-1",
            "card_id": card_id,
            "mode": "generic",
            "testcase": str(self.results / f"scratch-1/testcase-{index}.bin"),
            "testcase_sha1": "",
            "asan_output": str(self.results / f"scratch-1/testcase-{index}.asan.txt"),
            "verdict": verdict,
            "sanitizer": "asan",
            "sanitizer_runs": 1,
        }
        values.update(overrides)
        return workqueue.add_run(self.ctx, argparse.Namespace(**values))

    def test_path_classification_slug_and_subsystem_are_portable(self) -> None:
        self.assertEqual(workqueue.sanitize_slug("My Target++"), "my-target")
        self.assertEqual(workqueue.normalized_relpath("./src\\parser.c:func:9"), "src/parser.c:func:9")
        self.assertEqual(workqueue.subsystem_for("src/parser/token.c"), "src/parser")
        for path in ("src/parser.c", "lib/module.py", "Sources/App.swift", "crate/src/lib.rs"):
            with self.subTest(path=path):
                self.assertTrue(workqueue.is_auditable_source_path(path))
        for path in ("tests/parser.c", "examples/demo.cc", "build-asan/generated.c", ".git/config", "docs/readme.md"):
            with self.subTest(path=path):
                self.assertFalse(workqueue.is_auditable_source_path(path))
        self.assertEqual(workqueue.mode_for_file("page.html"), "auto")
        self.assertEqual(workqueue.mode_for_file("script.js"), "js")
        self.assertEqual(workqueue.mode_for_file("parser.c"), "auto")

    def test_patch_descriptions_and_deduplication_reject_noise(self) -> None:
        self.assertTrue(workqueue.is_version_only_file_set(["VERSION", "CHANGELOG.md"]))
        self.assertFalse(workqueue.is_version_only_file_set(["VERSION", "src/app.c"]))
        self.assertTrue(workqueue.is_non_audit_patch_description("Update documentation", ["docs/guide.md"]))
        self.assertFalse(workqueue.is_non_audit_patch_description("Fix out-of-bounds read", ["src/app.c"]))
        self.assertGreater(workqueue.matches_audit_boost("fix heap use after free and bounds check"), 0)

        first = self.card("WORK-A", "src/app.c", score=20)
        duplicate = self.card("WORK-B", "src/app.c", strategy="S1", score=10)
        distinct = self.card("WORK-C", "src/other.c", score=5)
        deduped = workqueue.dedupe_work_cards([duplicate, distinct, first])
        self.assertEqual([row["id"] for row in deduped], ["WORK-B", "WORK-C"])

    def test_code_feature_signals_cover_languages_and_strategy_mapping(self) -> None:
        cases = (
            ("int parse_packet(const char *p) { memcpy(dst, p, n); }", "S7", "input-consumption entrypoint"),
            ("MOZ_ASSERT(index < length);", "S2", "asserted invariant"),
            ("extern \"C\" int public_api();", "S3", "exported API surface"),
            ("free(node); callback(owner);", "S5", "lifetime/ownership operation"),
            ("return normalize(normalize(value));", "S8", "round-trip property surface"),
            ("pickle.loads(data)", "S7", "deserialization sink"),
            ("exec.CommandContext(ctx, userValue)", "S7", "command/injection surface"),
        )
        for source, strategy, reason in cases:
            with self.subTest(source=source):
                score, reasons = workqueue.code_feature_reasons(source)
                self.assertGreater(score, 0)
                self.assertIn(reason, reasons)
                self.assertEqual(workqueue.strategy_for(reasons), strategy)
        score, reasons = workqueue.code_feature_reasons("int checksum = 0; int thread_count = 1;")
        self.assertEqual((score, reasons), (0, []))

    def test_source_iteration_has_no_hidden_cap_and_skips_excluded_trees(self) -> None:
        for index in range(140):
            path = self.target / "src" / f"file_{index:03}.c"
            path.parent.mkdir(exist_ok=True)
            path.write_text("int value;\n")
        excluded = self.target / "tests" / "hidden.c"
        excluded.parent.mkdir()
        excluded.write_text("int hidden;\n")
        files = [path.relative_to(self.target).as_posix() for path in workqueue.iter_source_files(self.target)]
        self.assertEqual(len(files), 140)
        self.assertNotIn("tests/hidden.c", files)
        self.assertEqual(len(list(workqueue.iter_source_files(self.target, max_files=7))), 7)

    def test_git_patch_scan_ranks_old_security_fixes_above_recent_churn(self) -> None:
        subprocess.run(
            ["git", "-C", str(self.target), "init", "-q"],
            check=True, timeout=10,
        )
        for key, value in (("user.email", "test@example.invalid"), ("user.name", "Test User")):
            subprocess.run(
                ["git", "-C", str(self.target), "config", key, value],
                check=True, timeout=10,
            )
        commits = (
            ("Fix out-of-bounds write in parser", "src/parser.c"),
            ("Update generated defaults", "src/defaults.c"),
            ("Refresh comments", "src/comments.c"),
            ("Adjust formatting", "src/format.c"),
        )
        for message, relative in commits:
            path = self.target / relative
            path.parent.mkdir(exist_ok=True)
            path.write_text(f"int {path.stem};\n", encoding="utf-8")
            subprocess.run(
                ["git", "-C", str(self.target), "add", relative],
                check=True, timeout=10,
            )
            subprocess.run(
                ["git", "-C", str(self.target), "commit", "-q", "-m", message],
                check=True, timeout=10,
            )
        (self.target / "src/untracked.c").write_text("int untracked;\n", encoding="utf-8")

        cards = workqueue.build_patch_cards(
            self.ctx, limit=1, inspect_commits=4, scan_window=4,
        )
        self.assertEqual(len(cards), 1)
        self.assertIn("out-of-bounds", cards[0]["description"])
        self.assertEqual(cards[0]["touched_files"], ["src/parser.c"])
        self.assertNotIn("src/untracked.c", cards[0]["touched_files"])

    @unittest.skipUnless(shutil.which("hg"), "Mercurial is not installed")
    def test_mercurial_patch_scan_honors_the_explicit_window(self) -> None:
        shutil.rmtree(self.target / ".git")
        subprocess.run(["hg", "init", str(self.target)], check=True, timeout=10)
        env = os.environ | {"HGUSER": "Test User <test@example.invalid>"}
        for message, relative in (
            ("Fix use-after-free in decoder", "src/decoder.c"),
            ("Update comments", "src/comments.c"),
        ):
            path = self.target / relative
            path.parent.mkdir(exist_ok=True)
            path.write_text(f"int {path.stem};\n", encoding="utf-8")
            subprocess.run(
                ["hg", "-R", str(self.target), "add", str(path)],
                check=True, timeout=10, env=env,
            )
            subprocess.run(
                ["hg", "-R", str(self.target), "commit", "-m", message],
                check=True, timeout=10, env=env,
            )
        context = workqueue.Context(ROOT, self.target, "sample", self.results, "hg")
        rows = workqueue.vcs_log_rows(context, 1)
        self.assertEqual(len(rows), 1)
        self.assertIn("Update comments", rows[0]["Description"])
        cards = workqueue.build_patch_cards(context, limit=1, inspect_commits=2, scan_window=2)
        self.assertIn("use-after-free", cards[0]["description"])

    def test_jsonl_updates_are_atomic_and_concurrent_appends_do_not_lose_rows(self) -> None:
        path = self.results / "state" / "concurrent.jsonl"

        def append(index: int) -> None:
            workqueue.append_jsonl(path, {"id": index, "payload": f"row-{index}"})

        with ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(append, range(100)))
        rows = workqueue.read_jsonl(path)
        self.assertEqual(len(rows), 100)
        self.assertEqual({row["id"] for row in rows}, set(range(100)))

        rewritten, result = workqueue.update_jsonl(
            path, lambda items: (items.append({"id": 100, "payload": "final"}) or "updated")
        )
        self.assertEqual(result, "updated")
        self.assertEqual(len(rewritten), 101)
        self.assertEqual(len(workqueue.read_jsonl(path)), 101)

    def test_hypothesis_ids_claims_and_ambiguous_updates_are_safe(self) -> None:
        self.write_cards([self.card("WORK-A", "src/app.c")])
        row = self.add_hypothesis()
        self.assertEqual(row["status"], "PENDING")
        claims = workqueue.read_jsonl(self.results / "state" / "claims.jsonl")
        self.assertEqual(claims[-1]["card_id"], "WORK-A")
        self.assertIn("expires_at", claims[-1])

        with self.assertRaises(workqueue.DuplicateHypothesisIdError):
            self.add_hypothesis()
        duplicate = dict(row)
        duplicate["agent"] = "2"
        workqueue.append_jsonl(self.results / "state" / "hypotheses.jsonl", duplicate)
        with self.assertRaises(workqueue.AmbiguousHypothesisUpdateError):
            workqueue.update_hypothesis(self.ctx, "H-1", "DISCARDED")
        updated = workqueue.update_hypothesis(self.ctx, "H-1", "DISCARDED", agent="2")
        self.assertEqual(updated["agent"], "2")
        self.assertEqual(updated["status"], "DISCARDED")

    def test_environment_block_closes_own_card_and_matching_siblings_only(self) -> None:
        cards = [
            self.card("WORK-C", "yaml/_yaml.c"),
            self.card("WORK-H", "yaml/_yaml.h"),
            self.card("WORK-OTHER", "yaml/parser.c"),
        ]
        self.write_cards(cards)
        self.add_hypothesis(card_id="WORK-C", file="yaml/_yaml.pyx:parse:1")
        updated = workqueue.update_hypothesis(
            self.ctx, "H-1", "ENV-BLOCKED", "ModuleNotFoundError: yaml._yaml", agent="1"
        )
        self.assertEqual(updated["status"], "ENV-BLOCKED")
        latest = workqueue.latest_claims_by_card(self.ctx)
        self.assertEqual(latest["WORK-C"]["status"], "blocked")
        self.assertEqual(latest["WORK-H"]["status"], "blocked")
        self.assertNotIn("WORK-OTHER", latest)

    def test_claiming_honors_mode_strategy_surface_and_fresh_leases(self) -> None:
        cards = [
            self.card("WORK-A", "src/a.js", strategy="S1", mode="js", score=50),
            self.card("WORK-B", "src/b.js", strategy="S7", mode="js", score=49),
            self.card("WORK-C", "src/c.c", strategy="S7", mode="generic", score=48),
        ]
        self.write_cards(cards)
        chosen = workqueue.claim_next_card(self.ctx, "1", mode="generic", strategy="S7", claim=False)
        self.assertEqual(chosen["id"], "WORK-B")
        self.assertIsNone(workqueue.claim_next_card(self.ctx, "1", mode="generic", strategy="S2", claim=False))

        claimed = workqueue.claim_next_card(self.ctx, "1", mode="generic", strategy="S7", claim=True)
        self.assertEqual(claimed["id"], "WORK-B")
        next_card = workqueue.claim_next_card(self.ctx, "2", mode="generic", strategy="S7", claim=False)
        self.assertEqual(next_card["id"], "WORK-C")

        stale = workqueue.read_jsonl(self.results / "state" / "claims.jsonl")[-1]
        stale.update({"claimed_at": "2000-01-01T00:00:00Z", "expires_at": "2000-01-01T00:01:00Z"})
        workqueue.append_jsonl(self.results / "state" / "claims.jsonl", stale)
        reclaimed = workqueue.claim_next_card(self.ctx, "2", mode="generic", strategy="S7", claim=False)
        self.assertEqual(reclaimed["id"], "WORK-B")

    def test_active_hypothesis_reserves_duplicate_surface(self) -> None:
        cards = [
            self.card("WORK-A", "src/app.c", score=20),
            self.card("WORK-DUP", "src/app.c", score=100),
            self.card("WORK-B", "src/other.c", score=10),
        ]
        self.write_cards(cards)
        self.add_hypothesis(card_id="WORK-A")
        next_card = workqueue.claim_next_card(self.ctx, "2", mode="generic", claim=False)
        self.assertEqual(next_card["id"], "WORK-B")
        reasons = {row["id"]: row["reason"] for row in workqueue.explain_queue(self.ctx, ["generic"])}
        self.assertEqual(reasons["WORK-A"], "active-hypothesis")
        self.assertEqual(reasons["WORK-DUP"], "active-surface")

    def test_card_status_gates_require_real_run_and_hypothesis_evidence(self) -> None:
        self.write_cards([self.card("WORK-A", "src/app.c")])
        with self.assertRaisesRegex(workqueue.CardStatusUpdateError, "refuses crash"):
            workqueue.update_card_status(self.ctx, "WORK-A", "crash", agent="1")
        self.add_run(verdict="CRASH")
        self.assertEqual(workqueue.update_card_status(self.ctx, "WORK-A", "crash", agent="1")["status"], "crash")

        with self.assertRaisesRegex(workqueue.CardStatusUpdateError, "refuses discard"):
            workqueue.update_card_status(self.ctx, "WORK-A", "discarded", agent="1")
        self.add_hypothesis()
        self.add_hypothesis(
            hyp_id="H-2", hypothesis="issue in app_close", input_shape="callback sequence",
            guard_gap="state checked after callback", diagnostic="lifetime", strategy="S5",
        )
        self.add_run(index=2)
        self.add_run(index=3, hypothesis_id="H-2")
        self.add_run(index=4, hypothesis_id="H-2")
        self.assertEqual(workqueue.update_card_status(self.ctx, "WORK-A", "discarded")["status"], "discarded")

    def test_card_discard_ignores_nonclean_runs_and_unprobed_hypotheses(self) -> None:
        self.write_cards([self.card("WORK-A", "src/app.c")])
        self.add_hypothesis()
        self.add_hypothesis(
            hyp_id="H-2", hypothesis="issue in app_close", input_shape="callback sequence",
            guard_gap="state checked after callback", diagnostic="lifetime", strategy="S5",
        )
        self.add_run(verdict="NO_EXEC")
        self.add_run(index=2)
        self.add_run(index=3)

        with self.assertRaisesRegex(workqueue.CardStatusUpdateError, "clean_runs=2.*probed_distinct_hypotheses=1"):
            workqueue.update_card_status(self.ctx, "WORK-A", "discarded", agent="1")

        self.add_run(index=4, hypothesis_id="H-2")
        self.assertEqual(workqueue.card_discard_evidence(self.ctx, "WORK-A"), (3, 2))
        self.assertEqual(
            workqueue.update_card_status(self.ctx, "WORK-A", "discarded", agent="1")["status"],
            "discarded",
        )

    def test_env_blocked_is_the_non_discard_exit_for_unreachable_card(self) -> None:
        self.write_cards([self.card("WORK-A", "src/app.c")])
        self.add_hypothesis()
        self.add_run(verdict="MISSED")

        with self.assertRaisesRegex(workqueue.CardStatusUpdateError, "clean_runs=0"):
            workqueue.update_card_status(self.ctx, "WORK-A", "discarded", agent="1")

        workqueue.update_hypothesis(
            self.ctx, "H-1", "ENV-BLOCKED",
            "feature is unavailable in every configured sibling build", agent="1",
        )
        blocked = workqueue.latest_claims_by_card(self.ctx)["WORK-A"]
        self.assertEqual(blocked["status"], "blocked")
        self.assertEqual(blocked["source"], "env-block-own-card")

    def test_per_agent_reject_skips_are_recorded(self) -> None:
        cards = [self.card("WORK-OTHER", "src/c.c")]
        self.write_cards(cards)
        workqueue.record_card_reject_skip(self.ctx, "WORK-OTHER", "1", "CRASH-REJECTED", "caller misuse")
        self.assertEqual(workqueue.card_reject_skips_for_agent(self.ctx, "1"), {"WORK-OTHER"})
        self.assertEqual(workqueue.card_reject_skips_for_agent(self.ctx, "2"), set())

    def test_compact_card_and_artifact_apis_are_bounded_and_filterable(self) -> None:
        self.write_cards([
            self.card("WORK-A", "src/a.c", strategy="S1", reason="raw memory operation " + "x" * 400),
            self.card("WORK-B", "lib/b.c", strategy="S7"),
        ])
        shown = workqueue.show_work_card(self.ctx, "WORK-A")
        self.assertEqual(shown["id"], "WORK-A")
        self.assertLessEqual(len(shown["why_ranked"]), 220)
        listed = workqueue.list_work_cards(self.ctx, strategy_filter="S7", limit=1)
        self.assertEqual([row["id"] for row in listed], ["WORK-B"])
        self.assertNotIn("why_ranked", listed[0])
        verbose = workqueue.list_work_cards(self.ctx, contains_filters=["raw memory"], verbose=True)
        self.assertEqual(verbose[0]["id"], "WORK-A")

        crash = self.results / "crashes" / "CRASH-1"
        crash.mkdir(parents=True)
        (crash / "REPORT.md").write_text(
            "# Crash\n\n| Field | Value |\n|:--|:--|\n"
            "| Primitive | heap-use-after-free |\n| Surface | library-api — public |\n"
            "| Severity | Medium (5.5) |\n| Crash site | app_free child.c:91 |\n| Cluster | CL-one |\n"
            "\nLarge report body that must not be returned.\n"
        )
        (crash / "reproduce.sh").write_text("#!/bin/sh\n")
        finding = self.results / "findings" / "FIND-1"
        finding.mkdir(parents=True)
        (finding / "report.md").write_text(
            "Cluster: FCL-one\nDedup key: demo\n# Finding\n"
            "Surface: Public API\nClass: state\nSeverity: Low\n"
            "- **Location**: app.c:app_parse:10\n"
        )
        (finding / "repro.py").write_text("pass\n")
        crash_row = workqueue.show_crash(self.ctx, "CRASH-1")
        self.assertEqual(crash_row["cluster"], "CL-one")
        self.assertIn("reproduce.sh", crash_row["repro"])
        finding_row = workqueue.show_finding(self.ctx, "FIND-1")
        self.assertEqual(finding_row["cluster"], "FCL-one")
        self.assertIn("repro.py", finding_row["repro"])

    def test_recent_digests_strategy_yield_and_runtime_feedback(self) -> None:
        self.write_cards([
            self.card("WORK-A2", "src/a.c", strategy="S8"),
            self.card("WORK-B", "src/b.c", strategy="S5"),
        ])
        self.add_hypothesis(card_id="WORK-A2", strategy="S8")
        output = self.results / "scratch-1" / "run.txt"
        output.parent.mkdir()
        output.write_text("coverage gate missed; closest reached frame: app_parse\n")
        self.add_run(card_id="WORK-A2", verdict="MISSED", asan_output=str(output))
        self.add_run(card_id="WORK-A2", verdict="CRASH", index=2)
        self.add_run(card_id="WORK-B", verdict="EXEC_FAIL", index=3, hypothesis_id="")
        workqueue.add_note(self.ctx, argparse.Namespace(
            agent="1", hypothesis_id="H-1", card_id="WORK-A2",
            kind="guard", text="round-trip and idempotence property checked",
        ))
        workqueue.add_note(self.ctx, argparse.Namespace(
            agent="1", hypothesis_id="H-1", card_id="WORK-A2",
            kind="variants", text="inverse operation and fixed-point property checked",
        ))

        recent_hyps = workqueue.recent_hypotheses(self.ctx, limit=1, agent="1")
        self.assertEqual(len(recent_hyps.strip().splitlines()), 2)
        recent_runs = workqueue.recent_runs(self.ctx, limit=2, agent="1")
        self.assertEqual(len(recent_runs.strip().splitlines()), 3)
        feedback = workqueue.runtime_feedback(self.ctx, agent="1", card_id="WORK-A2")
        self.assertIn("productive-artifact", feedback)
        yields = {row["strategy"]: row for row in workqueue.strategy_yield(self.ctx)["strategies"]}
        self.assertEqual(yields["S8"]["runs"], 2)
        self.assertEqual(yields["S8"]["crash"], 1)
        self.assertEqual(yields["S5"]["other"], 1)
        completion = workqueue.strategy_completion_status(self.ctx, "1", "S8")
        self.assertTrue(completion["complete"])

    def test_rank_work_cli_preserves_and_merges_external_card_sources(self) -> None:
        source = self.target / "src/parser.py"
        source.parent.mkdir()
        source.write_text(
            "def parse_bytes(data):\n    assert data is not None\n    return bytes(data)\n",
            encoding="utf-8",
        )
        workqueue.write_jsonl(self.results / "s6-peer-cards.jsonl", [
            self.card("S6-valid", "src/parser.py", kind="s6-peer-fix", strategy="S6"),
            self.card("S6-ignore", "src/parser.py", kind="not-s6", strategy="S6"),
        ])
        command = [
            sys.executable, str(ROOT / "bin" / "rank-work"),
            "--results-dir", str(self.results),
            "--target-path", str(self.target),
            "--target-slug", "sample",
            "--limit", "20", "--llm-top-n", "0", "--summary-limit", "1",
        ]
        first = self.run_command(command)
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        self.assertLessEqual(len(first.stdout.splitlines()), 5)
        self.assertIn("inspect with bin/state list-cards", first.stdout)
        cards = workqueue.read_jsonl(self.results / "work-cards.jsonl")
        by_id = {row["id"]: row for row in cards}
        self.assertIn("src/parser.py", {row.get("file") for row in cards})
        self.assertEqual(by_id["S6-valid"]["kind"], "s6-peer-fix")
        self.assertNotIn("S6-ignore", by_id)

        second = self.run_command(command + ["--quiet"])
        self.assertEqual(second.returncode, 0, second.stdout + second.stderr)
        ids = [row["id"] for row in workqueue.read_jsonl(self.results / "work-cards.jsonl")]
        self.assertEqual(ids.count("S6-valid"), 1)

    def test_llm_rerank_is_cached_and_fails_open_on_invalid_output(self) -> None:
        cards = [self.card("WORK-A", "src/a.c"), self.card("WORK-B", "src/b.c")]
        decision_log = self.root / "decisions.log"
        environment = {
            "LLM_DECIDE_MOCK_WORK_RERANK": json.dumps({
                "cards": [{"id": "WORK-B", "boost": 20, "reason": "parser boundary"}],
            }),
            "LLM_DECIDE_LOG": str(decision_log),
            "ACTIVE_BACKEND": "",
        }
        with mock.patch.dict(os.environ, environment, clear=False):
            first = workqueue.llm_rerank_cards(self.ctx, cards, top_n=2, timeout=5)
            second = workqueue.llm_rerank_cards(self.ctx, cards, top_n=2, timeout=5)
        self.assertEqual(first[0]["id"], "WORK-B")
        self.assertIn("llm-rerank: parser boundary", first[0]["reason"])
        self.assertEqual(second, first)
        self.assertEqual(decision_log.read_text(encoding="utf-8").count("work_rerank MOCK"), 1)

        with mock.patch.dict(os.environ, {
            "LLM_DECIDE_MOCK_WORK_RERANK": "not json",
            "ACTIVE_BACKEND": "",
        }, clear=False):
            self.assertEqual(
                workqueue.llm_rerank_cards(self.ctx, cards, top_n=2, timeout=5), cards,
            )

    def test_state_cli_recent_filters_explanations_and_bad_regexes(self) -> None:
        self.write_cards([self.card("WORK-A", "src/app.c")])
        self.add_hypothesis(hyp_id="H-PENDING", status="PENDING")
        self.add_hypothesis(hyp_id="H-DONE", agent="2", status="DISCARDED")
        self.add_run(hypothesis_id="H-PENDING", verdict="CRASH")
        self.add_run(hypothesis_id="H-DONE", agent="2", verdict="CLEAN", index=2)
        workqueue.add_note(self.ctx, argparse.Namespace(
            agent="1", hypothesis_id="H-PENDING", card_id="WORK-A",
            kind="guard", text="length|guard checked after the read",
        ))
        (self.results / "tried-inputs-1.log").write_text(
            "2026-07-12T01:00:00Z verdict=CLEAN mode=generic testcase=one.bin "
            "hash=aaa111 hypothesis=H-PENDING target=src/app.c:app_parse:10 closest=<none>\n"
            "2026-07-12T02:00:00Z verdict=CRASH mode=generic testcase=two.bin "
            "hash=bbb222 hypothesis=H-PENDING target=src/app.c:app_parse:10 closest=app_parse\n",
            encoding="utf-8",
        )
        base = [
            sys.executable, str(ROOT / "bin" / "state"),
            "--results-dir", str(self.results),
            "--target-path", str(self.target),
            "--target-slug", "sample",
        ]
        pending = self.run_command(base + ["recent-hyps", "--status", "^PENDING$"])
        self.assertEqual(pending.returncode, 0, pending.stderr)
        self.assertIn("H-PENDING", pending.stdout)
        self.assertNotIn("H-DONE", pending.stdout)
        crashes = self.run_command(base + ["recent-runs", "--verdict", "^CRASH$"])
        self.assertIn("|CRASH|", crashes.stdout)
        self.assertNotIn("|CLEAN|", crashes.stdout)
        bad = self.run_command(base + ["recent-runs", "--verdict", "[bad"])
        bad_output = bad.stdout + bad.stderr
        self.assertIn("invalid --verdict regex", bad_output)
        self.assertNotIn("Traceback", bad_output)
        notes = self.run_command(base + ["recent-notes", "--kind", "guard"])
        self.assertIn("length/guard checked after the read", notes.stdout)
        tried = self.run_command(base + [
            "recent-tried", "--agent", "1", "--verdict", "^CRASH$",
        ])
        self.assertIn("bbb222", tried.stdout)
        self.assertNotIn("aaa111", tried.stdout)
        snapshot = self.run_command(base + [
            "show-recent", "--hyps", "1", "--runs", "1", "--claims", "1", "--notes", "1",
        ])
        for heading in ("# recent-hyps", "# recent-runs", "# recent-claims", "# recent-notes"):
            self.assertIn(heading, snapshot.stdout)
        explained = self.run_command(base + ["explain-queue", "--all"])
        self.assertEqual(explained.returncode, 0, explained.stderr)
        self.assertIn("WORK-A", explained.stdout)

    def test_resume_prioritizes_pending_crash_then_active_hypothesis(self) -> None:
        self.write_cards([self.card("WORK-A", "src/app.c")])
        self.add_hypothesis()
        crash = self.results / "crashes" / "CRASH-1-1"
        crash.mkdir(parents=True)
        (crash / ".promotion_pending").write_text("pending\n")
        (crash / "report.md").write_text("_TODO (agent): finish report\n")
        resume = workqueue.state_resume(self.ctx, "1", "generic")
        self.assertIn("CRASH-1-1", resume)
        self.assertIn("finish the oldest pending crash bundle", resume)
        self.assertIn("H-1", resume)
        self.assertIn("## Queue Health", resume)

    def test_context_requires_explicit_identity_without_session_metadata(self) -> None:
        args = argparse.Namespace(
            script_root=str(ROOT), target_path="", target_slug="", results_dir="",
        )
        with mock.patch.dict(os.environ, {
            "TARGET_ROOT": "", "TARGET_NAME": "", "TARGET_SLUG": "", "RESULTS_DIR": "",
        }, clear=False):
            with self.assertRaisesRegex(SystemExit, "no results directory"):
                workqueue.context_from_args(args)

    def test_state_cli_smoke_is_json_and_does_not_fall_through_to_help(self) -> None:
        self.write_cards([self.card("WORK-A", "src/app.c")])
        base = [
            sys.executable, str(ROOT / "bin" / "state"),
            "--results-dir", str(self.results),
            "--target-path", str(self.target),
            "--target-slug", "sample",
        ]
        init = self.run_command(base + ["init"])
        self.assertEqual(init.returncode, 0, init.stdout + init.stderr)
        self.assertTrue((self.results / "state" / "claims.jsonl").is_file())
        shown = self.run_command(base + ["show-card", "WORK-A"])
        self.assertEqual(shown.returncode, 0, shown.stdout + shown.stderr)
        self.assertEqual(json.loads(shown.stdout)["id"], "WORK-A")
        self.assertNotIn("usage: state", shown.stdout)
        listed = self.run_command(base + ["list-cards", "--limit", "1"])
        self.assertEqual(listed.returncode, 0, listed.stdout + listed.stderr)
        self.assertEqual(json.loads(listed.stdout)["id"], "WORK-A")


if __name__ == "__main__":
    unittest.main()
