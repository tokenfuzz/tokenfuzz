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

    def test_file_identity_counts_a_trailing_partial_line(self) -> None:
        path = self.write_source("src/tail.c", "a\nb")
        self.assertEqual(coverage_ledger.file_identity(path)[0], 2)
        empty = self.write_source("src/empty.c", "")
        self.assertEqual(coverage_ledger.file_identity(empty)[0], 0)

    def test_delta_scope_is_recorded_on_the_manifest(self) -> None:
        self.write_source("src/changed.c", PARSER)
        self.write_source("src/other.c", PARSER)
        workqueue.rank_target(
            self.ctx, 10, delta_files={"src/changed.c": "changed since base"},
        )
        manifest = coverage_ledger.read_manifest(self.results)
        self.assertEqual([row["file"] for row in manifest], ["src/changed.c"])
        self.assertEqual(manifest[0]["scope"], "delta")


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

    def test_function_receipts_resolve_through_the_call_graph(self) -> None:
        self.write_callgraph([["app_open", 10], ["app_parse", 40], ["app_reset", 80]])
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
        self.write_callgraph([[f"fn{n:02d}", n * 5 + 1] for n in range(12)])
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
        self.assertTrue(proc.stdout.startswith("OK: mark-examined"), proc.stdout)
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
                "callees": [], "definitions": [["parse_input", 1], ["parse_tail", 9]],
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
            [(card["file"], card["edge_from"], card["strategy"]) for card in edges],
            [("src/app_parse.c", "src/main.c", "S3"), ("src/app_parse.c", "src/io.c", "S3")],
        )
        primary = next(c for c in cards if c["file"] == "src/app_parse.c" and c["kind"] == "ranked-source" and not c["reason"].startswith("companion"))
        self.assertEqual(edges[0]["score"], primary["score"] - 1)
        # Distinct surfaces from the file's own S3 companion, so dedupe keeps both.
        surfaces = {workqueue.work_surface(card) for card in cards}
        self.assertEqual(len(surfaces), len(cards))
        self.assertIn("contract with its caller `src/main.c`", workqueue.card_next_action(edges[0]))
        self.assertTrue(workqueue.card_closed_for_run(self.ctx, edges[0], "discarded"),
                        "an edge card is concrete and closes like a patch card")

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
        self.assertEqual(len(self.edges(cards)), 2)

    def test_delta_runs_mint_no_edge_cards(self) -> None:
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-20")
        cards = workqueue.rank_target(self.ctx, 10, delta_files={"src/app_parse.c": "changed"})
        self.assertEqual(self.edges(cards), [])

    def test_resume_and_directive_name_the_caller(self) -> None:
        import prompt
        coverage_ledger.record_receipt(self.ctx, "1", "src/app_parse.c", lines="1-20")
        cards = workqueue.rank_target(self.ctx, 10)
        workqueue.write_cards(workqueue.work_cards_path(self.ctx), self.edges(cards))
        brief = workqueue.state_resume(self.ctx, "3", claim=False)
        self.assertIn("- Edge from: `src/main.c`", brief)
        references = self.root / "references"
        (references / "strategies").mkdir(parents=True)
        (references / "session-rules.digest.md").write_text("digest\n", encoding="utf-8")
        context = prompt.PromptContext(self.results, self.target, "sampleproj", references, 1)
        # Edge cards are S3 work; a lane pinned elsewhere is rightly not offered one.
        (self.results / "state" / "strategy-1").write_text("S3\n", encoding="utf-8")
        self.assertIn("**Edge from:** `src/main.c`", prompt.work_card_directive(context, 1, force=True))


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
        workqueue.append_jsonl(coverage_ledger.receipts_path(self.results), {
            "file": "src/io/reader.c", "ranges": [[1, 80]], "sha1": "stale",
        })

        # A transcript read is evidence beside the receipt, not a receipt.
        workqueue.append_jsonl(read_ledger.reads_path(self.results), {
            "file": "src/io/writer.c", "ranges": [[1, None]],
        })

        report = coverage_ledger.coverage_report(self.ctx, depth=2, untouched=1)
        self.assertEqual(
            report["totals"],
            {"files": 5, "offered": 2, "claimed": 2, "loaded": 1, "receipted": 1,
             "lines": 1440, "lines_loaded": 900, "lines_examined": 30},
        )
        by_dir = {row["directory"]: row for row in report["directories"]}
        self.assertEqual(
            by_dir["src/parse"],
            {"directory": "src/parse", "files": 2, "offered": 2, "claimed": 1,
             "loaded": 0, "receipted": 1, "lines": 420, "lines_loaded": 0,
             "lines_examined": 30},
        )
        self.assertEqual(by_dir["src/io"]["offered"], 0)
        self.assertEqual(by_dir["tools"]["claimed"], 1)
        self.assertEqual(report["never_offered"], 2)
        self.assertEqual(report["untouched"], [{"file": "src/io/writer.c", "lines": 900}])
        # Least-covered directories first: that is what an operator acts on.
        self.assertEqual(report["directories"][0]["directory"], "src/io")

        text = coverage_ledger.render_coverage(report)
        self.assertIn("Never offered, claimed, nor receipted: 2", text)
        self.assertIn("| `src/io` | 2 | 0 | 0 | 1 | 0 | 980 | 92% | 0% |", text)
        self.assertIn("`src/io/writer.c` (900 lines)", text)
        self.assertEqual(
            json.loads(coverage_ledger.render_coverage(report, "json"))["totals"],
            report["totals"],
        )

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
