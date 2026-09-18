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

import coverage_ledger
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

        report = coverage_ledger.coverage_report(self.ctx, depth=2, untouched=1)
        self.assertEqual(
            report["totals"], {"files": 5, "offered": 2, "claimed": 2, "lines": 1440},
        )
        by_dir = {row["directory"]: row for row in report["directories"]}
        self.assertEqual(
            by_dir["src/parse"],
            {"directory": "src/parse", "files": 2, "offered": 2, "claimed": 1, "lines": 420},
        )
        self.assertEqual(by_dir["src/io"]["offered"], 0)
        self.assertEqual(by_dir["tools"]["claimed"], 1)
        self.assertEqual(report["never_offered"], 2)
        self.assertEqual(report["untouched"], [{"file": "src/io/writer.c", "lines": 900}])
        # Least-covered directories first: that is what an operator acts on.
        self.assertEqual(report["directories"][0]["directory"], "src/io")

        text = coverage_ledger.render_coverage(report)
        self.assertIn("Never offered nor claimed: 2", text)
        self.assertIn("| `src/io` | 2 | 0 | 0 | 980 |", text)
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
            {"files": 0, "offered": 0, "offered_share": None},
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
