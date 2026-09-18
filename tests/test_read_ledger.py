#!/usr/bin/env python3
"""Transcript-derived read requests, per backend."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import coverage_ledger
import read_ledger
import workqueue


class CommandParsingTests(unittest.TestCase):
    def test_shell_read_idioms_yield_file_and_range(self) -> None:
        cases = {
            "sed -n '10,40p' src/a.c": [("src/a.c", 10, 40)],
            "sed -n 10,40p src/a.c src/b.c": [("src/a.c", 10, 40), ("src/b.c", 10, 40)],
            "sed -n -e '5,$p' src/a.c": [("src/a.c", 5, None)],
            "sed -n '7p' src/a.c": [("src/a.c", 7, 7)],
            "cat src/a.c": [("src/a.c", 1, None)],
            "nl -ba src/a.c": [("src/a.c", 1, None)],
            "head -n 30 src/a.c": [("src/a.c", 1, 30)],
            "head --lines=30 src/a.c": [("src/a.c", 1, 30)],
            "head -30 src/a.c": [("src/a.c", 1, 30)],
            "tail -n 20 src/a.c": [("src/a.c", -20, None)],
            "tail src/a.c": [("src/a.c", -10, None)],
            "tail -n +20 src/a.c": [("src/a.c", 20, None)],
            "head src/a.c": [("src/a.c", 1, 10)],
            "bin/peek src/a.c:100-140": [("src/a.c", 100, 140)],
            "bin/peek src/a.c:100": [("src/a.c", 100, None)],
            "bin/peek src/a.c": [("src/a.c", 1, None)],
            "/bin/zsh -lc \"sed -n '1,20p' src/a.c && cat src/b.c\"": [
                ("src/a.c", 1, 20), ("src/b.c", 1, None),
            ],
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertEqual(read_ledger.reads_from_command(command), expected)

    def test_searches_pipelines_and_malformed_commands_record_nothing(self) -> None:
        for command in (
            "rg -n parse src/a.c",
            "bin/rg-safe -n parse src/a.c",
            "rg --files src | head -40",
            "sed -n '40,10p' src/a.c",
            "sed -i 's/a/b/' src/a.c",
            "sed -n -e '1,5p' -e '9,12p' src/a.c",
            "head -c 200 src/a.c",
            "tail -c 200 src/a.c",
            "sed -n 'unterminated",
            "head -n 30",
            "head -n 0 src/a.c",
            "tail -n 0 src/a.c",
            "sed '10,40p' src/a.c",
        ):
            with self.subTest(command=command):
                self.assertEqual(read_ledger.reads_from_command(command), [])


class EventShapeTests(unittest.TestCase):
    def test_native_read_tools_per_backend(self) -> None:
        claude = {"type": "assistant", "message": {"content": [
            {"type": "tool_use", "name": "Read",
             "input": {"file_path": "/t/src/a.c", "offset": 40, "limit": 60}},
            {"type": "tool_use", "name": "Bash", "input": {"command": "cat /t/src/b.c"}},
            {"type": "tool_use", "name": "Grep", "input": {"pattern": "x", "path": "/t/src"}},
        ]}}
        self.assertEqual(
            read_ledger.reads_from_event("claude", claude),
            [("/t/src/a.c", 40, 99), ("/t/src/b.c", 1, None)],
        )
        gemini = {"type": "tool_use", "tool_name": "read_file",
                  "parameters": {"absolute_path": "/t/src/a.c"}}
        self.assertEqual(read_ledger.reads_from_event("gemini", gemini), [("/t/src/a.c", 1, None)])
        gemini_shell = {"type": "tool_use", "tool_name": "run_shell_command",
                        "parameters": {"command": "sed -n '1,5p' /t/src/a.c"}}
        self.assertEqual(read_ledger.reads_from_event("gemini", gemini_shell), [("/t/src/a.c", 1, 5)])
        opencode = {"type": "tool_use", "part": {"type": "tool", "tool": "read",
                    "state": {"input": {"filePath": "/t/src/a.c", "offset": 0, "limit": 10}}}}
        self.assertEqual(read_ledger.reads_from_event("oss", opencode), [("/t/src/a.c", 1, 10)])
        codex = {"type": "item.completed", "item": {
            "type": "command_execution", "command": "/bin/zsh -lc 'head -n 12 /t/src/a.c'"}}
        self.assertEqual(read_ledger.reads_from_event("codex", codex), [("/t/src/a.c", 1, 12)])
        self.assertEqual(read_ledger.reads_from_event("codex", {"type": "turn.completed"}), [])

    def test_malformed_native_ranges_do_not_become_whole_file_requests(self) -> None:
        for params in (
            {"file_path": "/t/src/a.c", "offset": "bad", "limit": 10},
            {"file_path": "/t/src/a.c", "offset": 1, "limit": "bad"},
            {"file_path": "/t/src/a.c", "offset": 1, "limit": 0},
        ):
            event = {"type": "tool_use", "tool_name": "read_file", "parameters": params}
            self.assertEqual(read_ledger.reads_from_event("gemini", event), [])


class RecordingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="read-ledger-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "targets" / "sampleproj"
        self.results = self.root / "results"
        (self.target / "src").mkdir(parents=True)
        (self.target / "src" / "a.c").write_text("x\n" * 100, encoding="utf-8")
        (self.target / "src" / "b.c").write_text("y\n" * 50, encoding="utf-8")
        self.ctx = workqueue.Context(self.root, self.target, "sampleproj", self.results, "")
        workqueue.init_state(self.ctx)
        workqueue.rank_target(self.ctx, 5)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_transcript(self, events: list[dict]) -> Path:
        path = self.root / "session_1.log.raw"
        path.write_text(
            "prose line the parser must skip\n"
            + "".join(json.dumps(event) + "\n" for event in events),
            encoding="utf-8",
        )
        return path

    def test_session_reads_resolve_into_the_target_and_merge_per_file(self) -> None:
        raw = self.write_transcript([
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "name": "Read",
                 "input": {"file_path": str(self.target / "src" / "a.c"), "offset": 1, "limit": 20}},
                {"type": "tool_use", "name": "Bash",
                 "input": {"command": "sed -n '15,30p' targets/sampleproj/src/a.c"}},
                {"type": "tool_use", "name": "Bash",
                 "input": {"command": f"tail -n 10 {self.target}/src/b.c"}},
                {"type": "tool_use", "name": "Read",
                 "input": {"file_path": str(self.results / "scratch-1" / "poc.bin")}},
            ]}},
        ])
        self.assertEqual(
            read_ledger.record_session_reads(self.results, self.target, self.root, "1", "claude", raw, session="s1"), 2,
        )
        rows = workqueue.read_jsonl(read_ledger.reads_path(self.results))
        self.assertEqual([row["file"] for row in rows], ["src/a.c", "src/b.c"])
        self.assertEqual(rows[0]["ranges"], [[1, 20], [15, 30]])
        self.assertEqual((rows[0]["agent"], rows[0]["session"], rows[0]["source"]),
                         ("1", "s1", "transcript"))
        self.assertEqual(
            read_ledger.requested_ranges_by_file(self.results),
            {"src/a.c": [(1, 30)], "src/b.c": [(41, 50)]},
        )

    def test_open_ends_are_clipped_to_the_manifest(self) -> None:
        raw = self.write_transcript([
            {"type": "item.completed", "item": {"type": "command_execution",
             "command": f"cat {self.target}/src/b.c && head -n 900 {self.target}/src/a.c"}},
        ])
        read_ledger.record_session_reads(self.results, self.target, self.root, "2", "codex", raw)
        self.assertEqual(
            read_ledger.requested_ranges_by_file(self.results),
            {"src/a.c": [(1, 100)], "src/b.c": [(1, 50)]},
        )

    def test_reads_on_changed_content_stop_counting(self) -> None:
        raw = self.write_transcript([
            {"type": "item.completed", "item": {"type": "command_execution",
             "command": f"cat {self.target}/src/a.c"}},
        ])
        read_ledger.record_session_reads(self.results, self.target, self.root, "2", "codex", raw)
        self.assertEqual(read_ledger.requested_ranges_by_file(self.results), {"src/a.c": [(1, 100)]})
        source = self.target / "src" / "a.c"
        stat = source.stat()
        source.write_text("z\n" * 100, encoding="utf-8")
        os.utime(source, ns=(stat.st_atime_ns, stat.st_mtime_ns))
        workqueue.rank_target(self.ctx, 5)
        self.assertEqual(read_ledger.requested_ranges_by_file(self.results), {})

    def test_malformed_manifest_identity_does_not_break_session_shutdown(self) -> None:
        manifest = coverage_ledger.read_manifest(self.results)
        manifest[0]["ctime_ns"] = "not-a-number"
        workqueue._write_jsonl_unlocked(coverage_ledger.manifest_path(self.results), manifest)
        recorded = read_ledger.record_observed_reads(
            self.results, self.target, self.root, "2", "codex",
            [(str(self.target / manifest[0]["file"]), 1, 10)], "s1",
        )
        self.assertEqual(recorded, 0)
        self.assertFalse(read_ledger.reads_path(self.results).exists())

    def test_a_missing_transcript_or_no_reads_records_nothing(self) -> None:
        self.assertEqual(read_ledger.record_session_reads(self.results, self.target, self.root, "1", "claude", self.root / "none.raw"), 0)
        raw = self.write_transcript([{"type": "result", "result": "done"}])
        self.assertEqual(read_ledger.record_session_reads(self.results, self.target, self.root, "1", "claude", raw), 0)
        self.assertFalse(read_ledger.reads_path(self.results).exists())
        self.assertEqual(coverage_ledger.coverage_report(self.ctx)["totals"]["read_requested"], 0)


if __name__ == "__main__":
    unittest.main()
