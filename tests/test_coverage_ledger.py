#!/usr/bin/env python3
"""Review coverage: the manifest the ranker writes and the report over it."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import callgraph
import coverage_ledger
import read_ledger
import telemetry
import workqueue


PARSER = (
    "int parse_input(char *dst, const char *src, size_t length) {\n"
    "  memcpy(dst, src, length);\n"
    "  return length > 8 ? 8 : (int)length;\n"
    "}\n"
)


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="coverage-ledger-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.results = self.root / "results"
        (self.target / "src").mkdir(parents=True)
        self.ctx = workqueue.Context(ROOT, self.target, "sampleproj", self.results, "")
        workqueue.init_state(self.ctx)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_source(self, rel: str, body: str) -> Path:
        path = self.target / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(body, encoding="utf-8")
        return path

    def test_rank_target_writes_every_auditable_file_and_marks_the_window(self) -> None:
        # Three scored files and one quiet file; a window of one distinct file
        # must still list all four so the untouched share is visible.
        for index in range(3):
            self.write_source(f"src/unit{index}.c", PARSER * (3 - index))
        self.write_source("src/quiet.c", "int quiet(void) { return 0; }\n")
        cards = workqueue.rank_target(self.ctx, 1)
        offered = {card["file"] for card in cards}
        manifest = coverage_ledger.read_manifest(self.results)

        self.assertEqual(
            [row["file"] for row in manifest],
            ["src/quiet.c", "src/unit0.c", "src/unit1.c", "src/unit2.c"],
        )
        self.assertEqual(
            {row["file"] for row in manifest if row["offered"]}, offered,
        )
        quiet = next(row for row in manifest if row["file"] == "src/quiet.c")
        self.assertEqual(quiet["lines"], 1)
        self.assertEqual(quiet["card_id"], workqueue.ranked_card_id("sampleproj", "src/quiet.c"))
        self.assertEqual(quiet["scope"], "tree")
        self.assertEqual(len(quiet["sha1"]), 40)

    def test_offered_is_sticky_across_reranks_and_hashes_are_reused(self) -> None:
        # The window moves between reranks; a file that left it was still
        # handed to the run, so its offered mark must survive the rewrite.
        hot = self.write_source("src/hot.c", PARSER * 4)
        cold = self.write_source("src/cold.c", "int cold(void) { return 0; }\n")
        workqueue.rank_target(self.ctx, 1)
        first = {row["file"]: row for row in coverage_ledger.read_manifest(self.results)}
        self.assertTrue(first["src/hot.c"]["offered"])
        self.assertFalse(first["src/cold.c"]["offered"])

        coverage_ledger.write_manifest(
            self.ctx, [(hot, "src/hot.c"), (cold, "src/cold.c")], {"src/cold.c"},
        )
        second = {row["file"]: row for row in coverage_ledger.read_manifest(self.results)}
        self.assertTrue(second["src/hot.c"]["offered"], "leaving the window keeps the mark")
        self.assertTrue(second["src/cold.c"]["offered"])
        self.assertEqual(second["src/hot.c"]["sha1"], first["src/hot.c"]["sha1"])

        hot.write_text(PARSER, encoding="utf-8")
        os.utime(hot, ns=(first["src/hot.c"]["mtime_ns"] + 10**9,) * 2)
        coverage_ledger.write_manifest(
            self.ctx, [(hot, "src/hot.c"), (cold, "src/cold.c")], set(),
        )
        third = {row["file"]: row for row in coverage_ledger.read_manifest(self.results)}
        self.assertNotEqual(third["src/hot.c"]["sha1"], first["src/hot.c"]["sha1"])
        self.assertEqual(third["src/hot.c"]["lines"], 4)

    def test_same_size_edit_with_restored_mtime_invalidates_the_hash(self) -> None:
        source = self.write_source("src/same.c", "int same(void) { return 1; }\n")
        workqueue.rank_target(self.ctx, 5)
        first = coverage_ledger.manifest_row(self.results, "src/same.c")
        stat = source.stat()
        source.write_text("int same(void) { return 2; }\n", encoding="utf-8")
        os.utime(source, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        workqueue.rank_target(self.ctx, 5)
        second = coverage_ledger.manifest_row(self.results, "src/same.c")
        self.assertNotEqual(second["sha1"], first["sha1"])

    def test_file_identity_counts_a_trailing_partial_line(self) -> None:
        path = self.write_source("src/tail.c", "a\nb")
        self.assertEqual(coverage_ledger.file_identity(path)[0], 2)
        empty = self.write_source("src/empty.c", "")
        self.assertEqual(coverage_ledger.file_identity(empty)[0], 0)

    def test_delta_manifest_contains_exactly_its_recorded_scope(self) -> None:
        self.write_source("src/changed.c", PARSER)
        self.write_source("src/other.c", PARSER)
        workqueue.rank_target(
            self.ctx, 10, delta_files={"src/changed.c": "changed since base"},
        )
        manifest = coverage_ledger.read_manifest(self.results)
        self.assertEqual([row["file"] for row in manifest], ["src/changed.c"])
        self.assertEqual(manifest[0]["scope"], "delta")
        self.assertEqual(coverage_ledger.coverage_report(self.ctx)["scope"], "delta")
        # Even a direct rank invocation that switches scope materializes the
        # requested scope. The audit runner itself refuses this switch.
        workqueue.rank_target(self.ctx, 10)
        workqueue.rank_target(self.ctx, 10, delta_files={"src/changed.c": "changed again"})
        rows = {row["file"]: row for row in coverage_ledger.read_manifest(self.results)}
        self.assertEqual(set(rows), {"src/changed.c"})
        self.assertEqual(coverage_ledger.coverage_report(self.ctx)["scope"], "delta")

    def test_a_preview_rank_does_not_mark_files_offered(self) -> None:
        self.write_source("src/hot.c", PARSER * 4)
        workqueue.rank_target(self.ctx, 5, record_manifest=False)
        self.assertEqual(coverage_ledger.read_manifest(self.results), [])
        proc = subprocess.run(
            [str(ROOT / "bin" / "rank-work"), "--target-path", str(self.target),
             "--target-slug", "sampleproj", "--results-dir", str(self.results),
             "--limit", "5", "--quiet", "--output", str(self.root / "preview.jsonl")],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(coverage_ledger.read_manifest(self.results), [])


class ReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="coverage-receipts-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.results = self.root / "results"
        (self.target / "src").mkdir(parents=True)
        self.ctx = workqueue.Context(ROOT, self.target, "sampleproj", self.results, "")
        workqueue.init_state(self.ctx)
        self.source = self.target / "src" / "app_parse.c"
        self.source.write_text("\n".join(f"line {n}" for n in range(1, 101)) + "\n", encoding="utf-8")
        workqueue.write_cards(workqueue.work_cards_path(self.ctx), workqueue.rank_target(self.ctx, 5))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_callgraph(self, definitions: list[list]) -> None:
        (self.results / "state" / callgraph.ARTIFACT_NAME).write_text(json.dumps({
            "version": callgraph.SCHEMA_VERSION, "signature": "s", "root": str(self.target),
            "languages": ["c"], "entry": {}, "coverage": {},
            "files": {"src/app_parse.c": {
                "functions": len(definitions), "reachable": 0, "callers": [], "callees": [],
                "paths": [], "definitions": definitions,
            }},
        }), encoding="utf-8")

    def test_a_line_receipt_is_recorded_against_the_manifest_hash(self) -> None:
        row = coverage_ledger.record_receipt(
            self.ctx, "1", "./src/app_parse.c", lines="10-20,15-30,50", card_id="WORK-x",
        )
        self.assertEqual(row["ranges"], [[10, 30], [50, 50]])
        self.assertEqual(row["sha1"], coverage_ledger.manifest_row(self.results, "src/app_parse.c")["sha1"])
        info = coverage_ledger.file_examined(self.results, "src/app_parse.c")
        self.assertEqual((info["examined_lines"], info["fraction"]), (22, 0.22))
        self.assertEqual(coverage_ledger.examined_fraction_by_file(self.results), {"src/app_parse.c": 0.22})

    def test_receipts_outside_the_file_or_manifest_are_refused(self) -> None:
        with self.assertRaisesRegex(coverage_ledger.ReceiptError, "has 100 lines"):
            coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="90-140")
        with self.assertRaisesRegex(coverage_ledger.ReceiptError, "not in the manifest"):
            coverage_ledger.record_receipt(self.ctx, "1", "src/missing.c", lines="1-2")
        with self.assertRaisesRegex(coverage_ledger.ReceiptError, "needs --lines or --functions"):
            coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c")
        with self.assertRaisesRegex(coverage_ledger.ReceiptError, "empty or starts before"):
            coverage_ledger.parse_ranges("30-10")
        with self.assertRaisesRegex(coverage_ledger.ReceiptError, "not N or N-M"):
            coverage_ledger.parse_ranges("ten")
        self.assertEqual(workqueue.read_jsonl(coverage_ledger.receipts_path(self.results)), [])

    def test_a_touched_file_with_the_same_content_still_takes_receipts(self) -> None:
        # A checkout or build step changes times without changing content, and
        # a rerank happens only when tracked content changes; refusing here
        # would refuse every receipt on the file until the next revision.
        stat = self.source.stat()
        os.utime(self.source, ns=(stat.st_atime_ns + 10**9, stat.st_mtime_ns + 10**9))
        row = coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-10")
        self.assertEqual(row["ranges"], [[1, 10]])

    def test_a_receipt_is_refused_when_the_source_changed_after_the_manifest(self) -> None:
        expected = coverage_ledger.manifest_row(self.results, "src/app_parse.c")["sha1"]
        self.source.write_text("changed\n" * 100, encoding="utf-8")
        with self.assertRaisesRegex(coverage_ledger.ReceiptError, "changed since the coverage manifest"):
            coverage_ledger.record_receipt(
                self.ctx, "sweep", "src/app_parse.c", lines="1-100",
                expected_sha1=expected,
            )
        self.assertEqual(workqueue.read_jsonl(coverage_ledger.receipts_path(self.results)), [])

    def test_incomplete_stat_identity_cannot_bypass_the_content_hash(self) -> None:
        entry = dict(coverage_ledger.manifest_row(self.results, "src/app_parse.c"))
        incomplete = {"file": entry["file"], "bytes": entry["bytes"], "sha1": entry["sha1"]}
        original = self.source.read_text(encoding="utf-8")
        self.source.write_text(original.replace("line 1\n", "xxxx 1\n", 1), encoding="utf-8")
        self.assertEqual(self.source.stat().st_size, entry["bytes"])
        self.assertFalse(
            coverage_ledger.content_matches_manifest(self.target, "src/app_parse.c", incomplete)
        )

    def test_function_receipts_resolve_through_the_call_graph(self) -> None:
        self.write_callgraph([["app_open", 10, 39], ["app_parse", 40, 79], ["app_reset", 80, 100]])
        self.assertEqual(
            coverage_ledger.function_ranges(self.results, "src/app_parse.c", 100),
            [("app_open", 10, 39), ("app_parse", 40, 79), ("app_reset", 80, 100)],
        )
        row = coverage_ledger.record_receipt(
            self.ctx, "2", "src/app_parse.c", functions="app_parse, app_reset",
        )
        self.assertEqual(row["ranges"], [[40, 100]])
        self.assertEqual(row["functions"], ["app_parse", "app_reset"])
        info = coverage_ledger.file_examined(self.results, "src/app_parse.c")
        self.assertEqual(info["unexamined_functions"], [("app_open", 10, 39)])
        with self.assertRaisesRegex(coverage_ledger.ReceiptError, "unknown function.*app_close.*parsed functions are"):
            coverage_ledger.record_receipt(self.ctx, "2", "src/app_parse.c", functions="app_close")

    def test_function_receipts_need_a_parsed_file(self) -> None:
        with self.assertRaisesRegex(coverage_ledger.ReceiptError, "parsed no definitions.*use --lines"):
            coverage_ledger.record_receipt(self.ctx, "2", "src/app_parse.c", functions="app_parse")

    def test_function_ranges_are_the_parsers_not_run_to_the_next_definition(self) -> None:
        self.write_callgraph([["outer", 10, 40], ["inner", 20, 25], ["late", 90, 300]])
        self.assertEqual(
            coverage_ledger.function_ranges(self.results, "src/app_parse.c", 100),
            [("outer", 10, 40), ("inner", 20, 25), ("late", 90, 100)],
        )
        row = coverage_ledger.record_receipt(self.ctx, "2", "src/app_parse.c", functions="outer")
        self.assertEqual(row["ranges"], [[10, 40]])
        info = coverage_ledger.file_examined(self.results, "src/app_parse.c")
        self.assertEqual(info["unexamined_functions"], [("late", 90, 100)],
                         "a nested function inside a receipted parent is examined")

    def test_duplicate_function_names_require_explicit_lines(self) -> None:
        self.write_callgraph([["parse", 10, 39], ["parse", 40, 79], ["reset", 80, 100]])
        with self.assertRaisesRegex(coverage_ledger.ReceiptError, "ambiguous function.*parse.*use --lines"):
            coverage_ledger.record_receipt(self.ctx, "2", "src/app_parse.c", functions="parse")
        self.assertEqual(workqueue.read_jsonl(coverage_ledger.receipts_path(self.results)), [])

    def test_a_receipt_on_changed_content_stops_counting(self) -> None:
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-100")
        self.assertEqual(coverage_ledger.file_examined(self.results, "src/app_parse.c")["fraction"], 1.0)
        self.source.write_text("changed\n" * 100, encoding="utf-8")
        os.utime(self.source, ns=(self.source.stat().st_mtime_ns + 10**9,) * 2)
        workqueue.rank_target(self.ctx, 5)
        self.assertEqual(coverage_ledger.file_examined(self.results, "src/app_parse.c")["fraction"], 0.0)
        self.assertEqual(coverage_ledger.examined_fraction_by_file(self.results), {})

    def test_examined_markdown_names_ranges_and_what_is_left(self) -> None:
        self.assertEqual(coverage_ledger.examined_markdown(self.results, "src/none.c"), [])
        fresh = coverage_ledger.examined_markdown(self.results, "src/app_parse.c")
        self.assertIn("0% of 100 lines (no receipt yet)", fresh[0])
        self.assertIn("mark-examined --agent N --file src/app_parse.c", fresh[-1])
        self.write_callgraph([[f"fn{n:02d}", n * 5 + 1, n * 5 + 5] for n in range(12)])
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-10")
        lines = coverage_ledger.examined_markdown(self.results, "src/app_parse.c")
        self.assertIn("10% of 100 lines (lines 1-10)", lines[0])
        self.assertIn("`fn02` (l.11)", lines[1])
        self.assertIn("+2 more", lines[1], "the list is bounded, not a file listing")
        self.assertNotIn("fn00", lines[1], "a receipted function is not listed as unexamined")

    def test_resume_and_card_directive_carry_the_examined_block(self) -> None:
        import prompt
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-25")
        brief = workqueue.state_resume(self.ctx, "3", claim=False)
        self.assertIn("src/app_parse.c", brief)
        self.assertIn("**Examined so far:** 25% of 100 lines (lines 1-25)", brief)
        references = self.root / "references"
        (references / "strategies").mkdir(parents=True)
        (references / "session-rules.digest.md").write_text("digest\n", encoding="utf-8")
        context = prompt.PromptContext(self.results, self.target, "sampleproj", references, 1)
        directive = prompt.work_card_directive(context, 1, force=True)
        self.assertIn("ASSIGNED WORK CARD", directive)
        self.assertIn("**Examined so far:** 25% of 100 lines", directive)

    def test_state_mark_examined_command_records_and_refuses(self) -> None:
        base = [str(ROOT / "bin" / "state"), "--target-path", str(self.target),
                "--target-slug", "sampleproj", "--results-dir", str(self.results)]
        proc = subprocess.run(
            [*base, "mark-examined", "--agent", "1", "--file", "src/app_parse.c",
             "--lines", "1-40", "--card-id", "WORK-x"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "OK: mark-examined\n")
        refused = subprocess.run(
            [*base, "mark-examined", "--agent", "1", "--file", "src/app_parse.c", "--lines", "1-400"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(refused.returncode, 2)
        self.assertIn("has 100 lines", refused.stderr)
        report = subprocess.run(
            [*base, "coverage", "--format", "json"], capture_output=True, text=True, check=False,
        )
        totals = json.loads(report.stdout)["totals"]
        self.assertEqual((totals["receipted"], totals["lines_examined"]), (1, 40))


class CallEdgeCardTests(unittest.TestCase):
    """The second pass: edge cards appear only once a file is fully receipted."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="coverage-edges-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.results = self.root / "results"
        (self.target / "src").mkdir(parents=True)
        self.ctx = workqueue.Context(ROOT, self.target, "sampleproj", self.results, "")
        workqueue.init_state(self.ctx)
        (self.target / "src" / "app_parse.c").write_text(PARSER * 5, encoding="utf-8")
        (self.target / "src" / "main.c").write_text(PARSER, encoding="utf-8")
        (self.target / "src" / "io.c").write_text(PARSER, encoding="utf-8")
        (self.results / "state" / callgraph.ARTIFACT_NAME).write_text(json.dumps({
            "version": callgraph.SCHEMA_VERSION, "signature": "s", "root": str(self.target),
            "languages": ["c"], "entry": {}, "coverage": {},
            "files": {"src/app_parse.c": {
                "functions": 2, "reachable": 0, "paths": [],
                "callers": [["src/main.c", 3]], "caller_overflow": [["src/io.c", 1]],
                "callees": [], "definitions": [["parse_input", 1, 8], ["parse_tail", 9, 20]],
            }},
        }), encoding="utf-8")
        workqueue.rank_target(self.ctx, 10)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def edges(self, cards: list[dict]) -> list[dict]:
        return [card for card in cards if card["kind"] == "call-edge"]

    def test_no_edge_cards_until_every_function_is_receipted(self) -> None:
        self.assertEqual(self.edges(workqueue.rank_target(self.ctx, 10)), [])
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", functions="parse_input")
        self.assertEqual(self.edges(workqueue.rank_target(self.ctx, 10)), [])
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", functions="parse_tail")
        cards = workqueue.rank_target(self.ctx, 10)
        edges = self.edges(cards)
        self.assertEqual(
            [(card["file"], card["edge_from"], card["edge_count"], card["strategy"]) for card in edges],
            [("src/app_parse.c", "src/main.c", 2, "S3")],
        )
        primary = next(c for c in cards if c["file"] == "src/app_parse.c" and c["kind"] == "ranked-source" and not c["reason"].startswith("companion"))
        self.assertEqual(edges[0]["score"], primary["score"] - 1)
        # Distinct surfaces from the file's own S3 companion, so dedupe keeps both.
        surfaces = {workqueue.work_surface(card) for card in cards}
        self.assertEqual(len(surfaces), len(cards))
        self.assertIn("samples a set of 2 resolved caller file(s)", workqueue.card_next_action(edges[0]))
        self.assertTrue(workqueue.card_closed_for_run(self.ctx, edges[0], "discarded"),
                        "an edge card is concrete and closes like a patch card")

    def test_edge_gate_uses_parsed_functions_instead_of_line_share(self) -> None:
        source = self.target / "src" / "app_parse.c"
        source.write_text("/* preamble */\n" * 20 + PARSER * 2, encoding="utf-8")
        graph_path = self.results / "state" / callgraph.ARTIFACT_NAME
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
        graph["files"]["src/app_parse.c"]["definitions"] = [["parse_input", 21, 24], ["parse_tail", 25, 28]]
        graph_path.write_text(json.dumps(graph), encoding="utf-8")
        workqueue.rank_target(self.ctx, 10)
        coverage_ledger.record_receipt(
            self.ctx, "1", "src/app_parse.c", functions="parse_input,parse_tail",
        )
        self.assertEqual(len(self.edges(workqueue.rank_target(self.ctx, 10))), 1,
                         "a preamble is not an unexamined function")

        source.write_text("\n".join(["line"] * 1999 + ["short function"]) + "\n", encoding="utf-8")
        graph["files"]["src/app_parse.c"]["definitions"] = [["large", 1, 1999], ["short", 2000, 2000]]
        graph_path.write_text(json.dumps(graph), encoding="utf-8")
        workqueue.rank_target(self.ctx, 10)
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-1998")
        self.assertEqual(self.edges(workqueue.rank_target(self.ctx, 10)), [],
                         "99.9% of lines must not hide one unexamined function")

    def test_source_change_invalidates_edges_before_the_manifest_rewrite(self) -> None:
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-20")
        source = self.target / "src" / "app_parse.c"
        source.write_text("changed\n" * 20, encoding="utf-8")
        self.assertEqual(
            self.edges(workqueue.rank_target(self.ctx, 10)), [],
            "a receipt on the previous content cannot mint an edge during rerank",
        )

    def test_edge_cards_ride_the_window_with_their_file(self) -> None:
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-20")
        for index in range(6):
            (self.target / "src" / f"unit{index}.c").write_text(PARSER * (6 - index), encoding="utf-8")
        cards = workqueue.rank_target(self.ctx, 2)
        files = {c["file"] for c in cards if c["kind"] == "ranked-source"}
        self.assertEqual(len(files), 2)
        for edge in self.edges(cards):
            self.assertIn(edge["file"], files, "an edge never buys a slot its file did not")
        self.assertIn("src/app_parse.c", files)
        self.assertEqual(len(self.edges(cards)), 1)

    def test_high_fan_in_is_one_bounded_caller_set(self) -> None:
        graph_path = self.results / "state" / callgraph.ARTIFACT_NAME
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
        graph["files"]["src/app_parse.c"]["caller_overflow"] = [
            [f"src/caller-{index}.c", 1000 - index] for index in range(1000)
        ]
        graph_path.write_text(json.dumps(graph), encoding="utf-8")
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-20")
        first = self.edges(workqueue.rank_target(self.ctx, 1))
        self.assertEqual(len(first), 1)
        self.assertEqual(first[0]["edge_count"], 1001)
        workqueue.write_cards(workqueue.work_cards_path(self.ctx), first)
        report = coverage_ledger.coverage_report(self.ctx)
        self.assertEqual(
            report["call_edges"],
            {"available": True, "eligible_caller_sets": 1, "resolved_callers": 1001,
             "sampled_sets": 0, "concluded_sets": 0, "current_sample_cards": 1,
             "callers_without_individual_card": 1000},
        )
        self.assertIn("1000 caller(s) beyond the seeds have no individual card", coverage_ledger.render_coverage(report))
        workqueue.append_jsonl(workqueue.state_dir(self.results) / "claims.jsonl", {
            "card_id": first[0]["id"], "agent": "1", "status": "discarded",
            "updated_at": workqueue.now_iso(),
        })
        cards = workqueue.rank_target(self.ctx, 1)
        self.assertEqual(
            self.edges(cards), [],
            "closing the aggregate does not page 1,000 more agent sessions",
        )
        # The concluded sample leaves no card in the queue, and the report
        # must still say the set was sampled rather than never carded.
        workqueue.write_cards(workqueue.work_cards_path(self.ctx), cards)
        after = coverage_ledger.coverage_report(self.ctx)["call_edges"]
        self.assertEqual(
            (after["sampled_sets"], after["concluded_sets"], after["current_sample_cards"]),
            (1, 1, 0),
        )

    def test_caller_or_callee_content_change_reopens_the_sample(self) -> None:
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-20")
        first = self.edges(workqueue.rank_target(self.ctx, 10))
        self.assertEqual(len(first), 1)
        workqueue.append_jsonl(workqueue.state_dir(self.results) / "claims.jsonl", {
            "card_id": first[0]["id"], "agent": "1", "status": "discarded",
            "updated_at": workqueue.now_iso(),
        })
        (self.target / "src" / "main.c").write_text(PARSER + "/* changed caller contract */\n", encoding="utf-8")
        reopened = self.edges(workqueue.rank_target(self.ctx, 10))
        self.assertEqual(len(reopened), 1)
        self.assertNotEqual(reopened[0]["id"], first[0]["id"])

    def test_fully_receipted_diversity_floor_file_gets_an_edge_card(self) -> None:
        rel = "a/b/c/d/e/f/plain.c"
        source = self.target / rel
        source.parent.mkdir(parents=True)
        source.write_text("int plain(void) { return 0; }\n", encoding="utf-8")
        graph_path = self.results / "state" / callgraph.ARTIFACT_NAME
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
        graph["files"][rel] = {
            "functions": 1, "reachable": 0, "paths": [],
            "callers": [["src/main.c", 1]], "caller_overflow": [],
            "callees": [], "definitions": [["plain", 1, 1]],
        }
        graph_path.write_text(json.dumps(graph), encoding="utf-8")
        first = workqueue.rank_target(self.ctx, 10)
        floor = next(card for card in first if card["file"] == rel)
        self.assertTrue(floor["reason"].startswith("diversity floor:"))
        coverage_ledger.record_receipt(self.ctx, "1", rel, functions="plain")
        self.assertIn(rel, coverage_ledger.caller_sets(self.results, self.target))
        reranked = workqueue.rank_target(self.ctx, 3)
        edges = [card for card in self.edges(reranked) if card["file"] == rel]
        self.assertEqual(len(edges), 1)
        self.assertEqual(
            {card["kind"] for card in reranked if card["file"] == rel},
            {"ranked-source", "call-edge"},
            "the edge rides with its floor file without consuming another file slot",
        )
        self.assertEqual(
            len({card["file"] for card in reranked if card["kind"] == "ranked-source"}),
            3,
            "the floor edge must not displace a distinct main-window file",
        )

    def test_coverage_distinguishes_eligible_sets_from_current_cards(self) -> None:
        graph_path = self.results / "state" / callgraph.ARTIFACT_NAME
        graph = json.loads(graph_path.read_text(encoding="utf-8"))
        graph["files"]["src/io.c"] = {
            "functions": 2, "reachable": 0, "paths": [],
            "callers": [["src/main.c", 1]], "caller_overflow": [], "callees": [],
            "definitions": [["parse_input", 1, 2], ["parse_tail", 3, 4]],
        }
        graph_path.write_text(json.dumps(graph), encoding="utf-8")
        workqueue.rank_target(self.ctx, 10)
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-20")
        coverage_ledger.record_receipt(self.ctx, "1", "src/io.c", lines="1-4")
        cards = workqueue.rank_target(self.ctx, 1)
        workqueue.write_cards(workqueue.work_cards_path(self.ctx), cards)
        report = coverage_ledger.coverage_report(self.ctx)["call_edges"]
        self.assertEqual((report["eligible_caller_sets"], report["current_sample_cards"]), (2, 1))
        self.assertEqual(report["callers_without_individual_card"], 1)

    def test_a_file_completing_its_receipts_reranks_the_queue(self) -> None:
        # Reranks follow source and probe-coverage changes; the second pass
        # needs one when a file becomes fully receipted on a static tree.
        import audit_runner
        runtime = SimpleNamespace(
            results=self.results, target_root=self.target, target_rev="rev-1",
            config=SimpleNamespace(s6_domain="", s6_peers=[]),
        )
        with mock.patch.object(audit_runner.target_config, "vcs_source_signature", return_value="src"):
            before = audit_runner._work_card_signature(runtime)
            coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", functions="parse_input")
            partial = audit_runner._work_card_signature(runtime)
            coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", functions="parse_tail")
            complete = audit_runner._work_card_signature(runtime)
        self.assertEqual(before, partial, "a partial receipt does not force a source rescan")
        self.assertNotEqual(partial, complete)

    def test_delta_runs_mint_no_edge_cards(self) -> None:
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-20")
        cards = workqueue.rank_target(self.ctx, 10, delta_files={"src/app_parse.c": "changed"})
        self.assertEqual(self.edges(cards), [])

    def test_edge_cards_respect_a_fixed_strategy(self) -> None:
        (self.target / "src" / "z_s3.c").write_text("int query(void) { return 0; }\n", encoding="utf-8")

        def scores(paths):
            return iter(
                (100, ["query/template construction"], frozenset())
                if rel == "src/z_s3.c"
                else (1, ["input-consumption entrypoint"], frozenset())
                for _path, rel in paths
            )

        with mock.patch.object(workqueue, "source_feature_scores", side_effect=scores):
            workqueue.rank_target(self.ctx, 10)
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-20")
        with mock.patch.object(workqueue, "source_feature_scores", side_effect=scores):
            self.assertEqual(self.edges(workqueue.rank_target(self.ctx, 10, strategy="S7")), [])
            cards = workqueue.rank_target(self.ctx, 10, strategy="S3")
        edges = self.edges(cards)
        self.assertEqual([(card["file"], card["strategy"]) for card in edges], [("src/app_parse.c", "S3")])
        # The edge competes on score like any S3 card; it takes no priority
        # over first-pass work in the lane.
        self.assertEqual(cards[0]["file"], "src/z_s3.c")

    def test_resume_and_directive_name_the_caller(self) -> None:
        import prompt
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-20")
        cards = workqueue.rank_target(self.ctx, 10)
        workqueue.write_cards(workqueue.work_cards_path(self.ctx), self.edges(cards))
        brief = workqueue.state_resume(self.ctx, "3", claim=False)
        self.assertIn("- Caller set: 2 resolved file(s), starting with `src/main.c`", brief)
        references = self.root / "references"
        (references / "strategies").mkdir(parents=True)
        (references / "session-rules.digest.md").write_text("digest\n", encoding="utf-8")
        context = prompt.PromptContext(self.results, self.target, "sampleproj", references, 1)
        # Edge cards are S3 work; a lane pinned elsewhere is rightly not offered one.
        (self.results / "state" / "strategy-1").write_text("S3\n", encoding="utf-8")
        self.assertIn(
            "**Caller-set sample:** 2 resolved file(s), starting with `src/main.c`",
            prompt.work_card_directive(context, 1, force=True),
        )


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="coverage-report-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.results = self.root / "results"
        self.target.mkdir()
        self.ctx = workqueue.Context(ROOT, self.target, "sampleproj", self.results, "")
        workqueue.init_state(self.ctx)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def manifest(self, rows: list[tuple[str, int, bool]]) -> None:
        workqueue.write_jsonl(coverage_ledger.manifest_path(self.results), [
            {
                "file": rel, "lines": lines, "offered": offered, "scope": "tree",
                "sha1": "h-" + Path(rel).stem,
                "card_id": workqueue.ranked_card_id("sampleproj", rel),
                "subsystem": workqueue.subsystem_for(rel),
            }
            for rel, lines, offered in rows
        ])

    def claim(self, card_id: str, status: str = "claimed") -> None:
        workqueue.append_jsonl(
            workqueue.state_dir(self.results) / "claims.jsonl",
            {"card_id": card_id, "agent": "1", "status": status},
        )

    def test_report_buckets_offered_and_claimed_per_directory(self) -> None:
        self.manifest([
            ("src/parse/app_parse.c", 300, True),
            ("src/parse/child.c", 120, True),
            ("src/io/reader.c", 80, False),
            ("src/io/writer.c", 900, False),
            ("tools/gen.c", 40, False),
        ])
        # A companion card's id differs from the primary's; the claim must
        # still resolve to its file once the queue has been rewritten.
        self.claim(workqueue.ranked_card_id("sampleproj", "src/parse/child.c", "S5"))
        # A patch card on a file outside the manifest resolves via the queue.
        workqueue.write_jsonl(workqueue.work_cards_path(self.ctx), [
            {"id": "PATCH-1", "kind": "s1-patch", "file": "tools/gen.c"},
        ])
        self.claim("PATCH-1")

        # A receipt on the current hash counts; one on stale content does not.
        workqueue.append_jsonl(coverage_ledger.receipts_path(self.results), {
            "file": "src/parse/app_parse.c", "ranges": [[1, 30]], "sha1": "h-app_parse",
        })
        # Sweep source is placed directly in a tool-less decision prompt. It
        # remains examined coverage, but there can be no transcript read to
        # corroborate it, so it must not inflate the agent-receipt cross-check.
        workqueue.append_jsonl(coverage_ledger.receipts_path(self.results), {
            "file": "tools/gen.c", "ranges": [[1, 10]], "sha1": "h-gen",
            "source": "sweep",
        })
        workqueue.append_jsonl(coverage_ledger.receipts_path(self.results), {
            "file": "src/io/reader.c", "ranges": [[1, 80]], "sha1": "stale",
        })

        # A transcript read is evidence beside the receipt, not a receipt.
        workqueue.append_jsonl(read_ledger.reads_path(self.results), {
            "file": "src/io/writer.c", "ranges": [[1, None]], "sha1": "h-writer",
        })

        report = coverage_ledger.coverage_report(self.ctx, depth=2, untouched=1)
        self.assertEqual(
            report["totals"],
            {"files": 5, "offered": 2, "claimed": 2, "read_requested": 1, "receipted": 2,
             "lines": 1440, "lines_requested": 900, "lines_examined": 40,
             "lines_agent_attested": 30,
             "lines_attested_unrequested": 30},
        )
        by_dir = {row["directory"]: row for row in report["directories"]}
        self.assertEqual(
            by_dir["src/parse"],
            {"directory": "src/parse", "files": 2, "offered": 2, "claimed": 1,
             "read_requested": 0, "receipted": 1, "lines": 420, "lines_requested": 0,
             "lines_examined": 30, "lines_agent_attested": 30,
             "lines_attested_unrequested": 30},
        )
        self.assertEqual(by_dir["src/io"]["offered"], 0)
        self.assertEqual(by_dir["tools"]["claimed"], 1)
        self.assertEqual(report["never_offered"], 2)
        self.assertEqual(report["untouched"], [{"file": "src/io/writer.c", "lines": 900}])
        # Least-covered directories first: that is what an operator acts on.
        self.assertEqual(report["directories"][0]["directory"], "src/io")

        text = coverage_ledger.render_coverage(report)
        self.assertIn("Never offered, claimed, nor receipted: 2", text)
        self.assertIn(
            "Agent-attested lines no transcript read requested: 30 (100% of agent-attested)",
            text,
        )
        self.assertIn("| Requested % | Examined % |", text)
        self.assertNotIn("| Requested % | Attested % |", text)
        self.assertIn("| `src/io` | 2 | 0 | 0 | 1 | 0 | 980 | 92% | 0% |", text)
        self.assertIn("`src/io/writer.c` (900 lines)", text)
        self.assertEqual(
            json.loads(coverage_ledger.render_coverage(report, "json"))["totals"],
            report["totals"],
        )

    def test_historic_dynamic_claim_keeps_its_file_after_queue_rewrite(self) -> None:
        self.manifest([("src/io/reader.c", 80, True)])
        workqueue.append_jsonl(
            workqueue.state_dir(self.results) / "claims.jsonl",
            {"card_id": "WORK-edge", "file": "src/io/reader.c", "agent": "1", "status": "claimed"},
        )
        workqueue.write_jsonl(workqueue.work_cards_path(self.ctx), [])
        self.assertEqual(coverage_ledger.claimed_files(
            self.ctx, coverage_ledger.read_manifest(self.results),
        ), {"src/io/reader.c"})

    def test_empty_tree_reports_nothing_rather_than_a_share(self) -> None:
        report = coverage_ledger.coverage_report(self.ctx)
        self.assertEqual(report["totals"]["files"], 0)
        self.assertIn("No manifest yet", coverage_ledger.render_coverage(report))
        self.assertEqual(
            telemetry.tree_coverage(self.results),
            {"files": 0, "offered": 0, "offered_share": None,
             "receipted": 0, "lines_examined_share": None},
        )

    def test_state_coverage_command_renders_the_report(self) -> None:
        self.manifest([("src/a.c", 10, True), ("src/b.c", 20, False)])
        proc = subprocess.run(
            [str(ROOT / "bin" / "state"), "--target-path", str(self.target),
             "--target-slug", "sampleproj", "--results-dir", str(self.results),
             "coverage", "--format", "json"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["totals"]["offered"], 1)
        self.assertEqual(payload["untouched"], [{"file": "src/b.c", "lines": 20}])


if __name__ == "__main__":
    unittest.main()
