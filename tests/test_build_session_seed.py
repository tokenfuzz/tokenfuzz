#!/usr/bin/env python3
"""Session-seed extraction across Claude, Codex, and Gemini logs."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import build_session_seed


class BuildSessionSeedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="session-seed-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_log(self, name: str, events: list[object]) -> Path:
        path = self.root / f"{name}.raw"
        lines = [event if isinstance(event, str) else json.dumps(event) for event in events]
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return path

    def seed(self, name: str, events: list[object], target_root: str = "") -> tuple[Path, str]:
        raw = self.write_log(name, events)
        output = self.root / f"{name}.seed"
        environment = {"TARGET_ROOT": target_root} if target_root else {"TARGET_ROOT": ""}
        with mock.patch.dict(os.environ, environment):
            build_session_seed.write_session_seed(str(raw), str(output))
        return output, output.read_text(encoding="utf-8") if output.exists() else ""

    @staticmethod
    def claude_read(
        tool_id: str, path: str, offset: object = 0, limit: object = 0,
        error: bool = False,
    ) -> list[dict]:
        return [
            {"type": "assistant", "message": {"content": [{
                "type": "tool_use", "id": tool_id, "name": "Read",
                "input": {"file_path": path, "offset": offset, "limit": limit},
            }]}},
            {"type": "user", "message": {"content": [{
                "type": "tool_result", "tool_use_id": tool_id, "is_error": error,
            }]}},
        ]

    @staticmethod
    def claude_write(tool_id: str, path: str) -> dict:
        return {"type": "assistant", "message": {"content": [{
            "type": "tool_use", "id": tool_id, "name": "Write",
            "input": {"file_path": path, "content": "sample"},
        }]}}

    @staticmethod
    def claude_shell(tool_id: str, command: str, error: bool = False) -> list[dict]:
        return [
            {"type": "assistant", "message": {"content": [{
                "type": "tool_use", "id": tool_id, "name": "Bash",
                "input": {"command": command},
            }]}},
            {"type": "user", "message": {"content": [{
                "type": "tool_result", "tool_use_id": tool_id,
                "is_error": error, "content": "ok",
            }]}},
        ]

    @staticmethod
    def codex_command(command: str, exit_code: int = 0) -> dict:
        return {"type": "item.completed", "item": {
            "id": "item", "type": "command_execution", "command": command,
            "aggregated_output": "", "status": "completed" if not exit_code else "failed",
            "exit_code": exit_code,
        }}

    @staticmethod
    def codex_header() -> list[dict]:
        return [{"type": "thread.started", "thread_id": "thread"}, {"type": "turn.started"}]

    @staticmethod
    def gemini_shell(tool_id: str, command: str, status: str = "success") -> list[dict]:
        return [
            {"type": "tool_use", "tool_name": "run_shell_command", "tool_id": tool_id,
             "parameters": {"command": command}},
            {"type": "tool_result", "tool_id": tool_id, "status": status, "output": "ok"},
        ]

    @staticmethod
    def gemini_header() -> list[object]:
        return [
            "YOLO mode is enabled.",
            {"type": "init", "timestamp": "2026-06-13T00:00:00Z",
             "session_id": "session", "model": "gemini"},
        ]

    def test_empty_missing_arguments_and_output_creation(self) -> None:
        empty = self.root / "empty.raw"
        empty.touch()
        output = self.root / "empty.seed"
        self.assertFalse(build_session_seed.write_session_seed(str(empty), str(output)))
        self.assertFalse(output.exists())
        self.assertFalse(
            build_session_seed.write_session_seed(str(self.root / "missing.raw"), str(output))
        )
        self.assertEqual(build_session_seed.main(["build_session_seed.py"]), 2)

        raw = self.write_log("auto", self.claude_read("r1", "/Users/dev/work/lib/foo.py", 1, 10))
        nested = self.root / "new" / "directory" / "seed.md"
        self.assertTrue(build_session_seed.write_session_seed(str(raw), str(nested)))
        self.assertTrue(nested.is_file())

    def test_claude_reads_ranges_exclusions_errors_writes_and_malformed_lines(self) -> None:
        events: list[object] = []
        events += self.claude_read("r1", "/Users/dev/work/lib/foo.py", 1, 100)
        events += self.claude_read("r2", "/Users/dev/work/lib/foo.py", 50, 100)
        events += self.claude_read("r3", "/Users/dev/work/lib/foo.py", 200, 50)
        events += self.claude_read("default", "/Users/dev/work/lib/default.py")
        events += self.claude_read("failed", "/Users/dev/work/lib/missing.py", 1, 100, True)
        for index, excluded in enumerate(
            ("/tmp/.session_seed_1.md", "/tmp/.read_log_1", "/tmp/.static-prompt-rules.md")
        ):
            events += self.claude_read(f"excluded-{index}", excluded, 1, 100)
        testcase = "/Users/dev/work/output/firefox/claude/results/scratch-1/testcase.html"
        events += [self.claude_write("w1", testcase), self.claude_write("w2", testcase)]
        events.insert(0, "not valid json {{{")
        events.append('{"truncated"')
        output, text = self.seed("claude", events)
        self.assertTrue(output.is_file())
        self.assertIn("Already Read", text)
        self.assertIn("lib/foo.py: 1-149, 200-249", text)
        self.assertIn("lib/default.py: 1-2000", text)
        self.assertNotIn("missing.py", text)
        for excluded in ("session_seed", "read_log", "static-prompt-rules"):
            self.assertNotIn(excluded, text)
        self.assertIn("Testcases written", text)
        self.assertEqual(text.count("testcase.html"), 1)

        _, shortened = self.seed(
            "shortened",
            self.claude_read("r", "/Users/dev/work/targets/firefox/dom/canvas/sample.cpp", 1, 100),
        )
        self.assertIn("dom/canvas/sample.cpp: 1-100", shortened)
        self.assertNotIn("/targets/firefox/", shortened)

    def test_seed_size_cap_preserves_header(self) -> None:
        events: list[object] = []
        for index in range(200):
            events += self.claude_read(
                f"r{index}", f"/Users/dev/work/lib/file_{index}_with_a_long_padding_name.py", 1, 100
            )
        output, text = self.seed("large", events)
        self.assertLessEqual(len(output.read_bytes()), 2200)
        self.assertIn("Already Read", text)

    def test_codex_read_commands_writes_detection_and_failures(self) -> None:
        cases = (
            ("sed", "sed -n '100,200p' /tmp/work/firefox/dom/foo.cpp", "dom/foo.cpp: 100-200"),
            ("head", "head -n 50 /tmp/work/firefox/dom/head.cpp", "dom/head.cpp: 1-50"),
            ("cat", "cat /tmp/work/firefox/dom/cat.cpp", "dom/cat.cpp: 1-2000"),
            ("peek", "bin/peek /tmp/work/firefox/dom/peek.cpp:75-125", "dom/peek.cpp: 75-125"),
            ("peek-start", "bin/peek --no-cap /tmp/work/firefox/dom/start.cpp:42", "dom/start.cpp: 42-241"),
        )
        for name, command, expected in cases:
            with self.subTest(name=name):
                events = self.codex_header() + [
                    self.codex_command(f'/bin/zsh -lc "{command}"')
                ]
                _, text = self.seed(name, events, "/tmp/work/firefox")
                self.assertIn(expected, text)
                self.assertEqual(build_session_seed.detect_format(self.root / f"{name}.raw"), "codex")

        quoted = '/bin/zsh -lc "sed -n \'1,50p\' "/tmp/work/firefox/quoted.cpp""'
        _, text = self.seed(
            "quoted", self.codex_header() + [self.codex_command(quoted)], "/tmp/work/firefox"
        )
        self.assertIn("quoted.cpp: 1-50", text)
        self.assertNotIn('quoted.cpp"', text)

        events = self.codex_header() + [
            self.codex_command('/bin/zsh -lc "cat <<EOF\nhello\nEOF"'),
            self.codex_command('/bin/zsh -lc "sed -n \'500,100p\' /tmp/work/firefox/inverted.cpp"'),
            self.codex_command('/bin/zsh -lc "bin/peek -A 30 -B 8 symbol /tmp/work/firefox/grep.cpp"'),
            self.codex_command('/bin/zsh -lc "sed -n \'1,10p\' /tmp/work/firefox/good.cpp"'),
            {"type": "item.completed", "item": {"id": "message", "type": "agent_message", "text": "hello"}},
            {"type": "item.completed", "item": {"id": "change", "type": "file_change",
                "changes": [
                    {"path": "/tmp/results/scratch-1/H1-test.html", "kind": "add"},
                    {"path": "/tmp/results/scratch-1/H2-test.html", "kind": "add"},
                ]}},
            self.codex_command('/bin/zsh -lc "sed -n \'1,20p\' targets/sample/missing.c"', 1),
            self.codex_command('/bin/zsh -lc "bin/rg-safe missing targets/sample/missing.c"', 1),
        ]
        _, text = self.seed("codex-mixed", events, "/tmp/work/firefox")
        self.assertIn("good.cpp: 1-10", text)
        for forbidden in ("<<EOF", "hello", "inverted.cpp", "grep.cpp", "missing.c"):
            self.assertNotIn(forbidden, text)
        self.assertIn("H1-test.html", text)
        self.assertIn("H2-test.html", text)

        auto_events = self.codex_header() + [
            self.codex_command('/bin/zsh -lc "sed -n \'1,10p\' /Users/x/proj/foo.c"')
        ]
        _, text = self.seed("codex-auto", auto_events)
        self.assertIn("foo.c", text)

    def test_gemini_shell_reads_writes_searches_and_command_boundaries(self) -> None:
        events = self.gemini_header()
        events += self.gemini_shell("peek", "bin/peek targets/libxml2/uri.c:1456-1554")
        events += self.gemini_shell("failed", "bin/peek targets/libxml2/missing.c:1-40", "error")
        events += self.gemini_shell("sed", "sed -n '10,20p' targets/libxml2/good.c")
        events += self.gemini_shell("cat", "cat targets/libxml2/parser.c")
        events += self.gemini_shell("heredoc-read", "cat <<EOF\nnot a path\nEOF")
        events += self.gemini_shell(
            "write", "cat << 'EOF' > /tmp/results/scratch-3/testcase.c\nint main(void){return 0;}\nEOF"
        )
        events += self.gemini_shell(
            "failed-write", "cat > /tmp/results/scratch-3/failed.c <<EOF\nbad\nEOF", "error"
        )
        events += self.gemini_shell("write-alt", "cat > /tmp/results/scratch-3/ok.c <<EOF\nok\nEOF")
        events += self.gemini_shell(
            "semicolon",
            "sed -n '900,910p' targets/brotli/c/tools/brotli.c; "
            "sed -n '170,230p' targets/brotli/c/enc/compound_dictionary.c;",
        )
        events += self.gemini_shell("search", "bin/rg-safe -n 'xmlParse' targets/libxml2/parser.c")
        events += self.gemini_shell("output-search", "grep -n 'includes' output/libxml2/target.toml")
        events += self.gemini_shell("peek-search", "bin/peek -A 50 -B 20 'xmlFree' targets/libxml2/tree.c")
        events += self.gemini_shell(
            "compound", "cd /tmp/work/targets/brotli && nm build-asan/libx.a | grep asan | head"
        )
        _, text = self.seed("gemini", events)
        self.assertEqual(build_session_seed.detect_format(self.root / "gemini.raw"), "gemini")
        for expected in (
            "targets/libxml2/uri.c: 1456-1554", "targets/libxml2/good.c: 10-20",
            "targets/libxml2/parser.c: 1-2000", "scratch-3/testcase.c", "scratch-3/ok.c",
            "targets/brotli/c/tools/brotli.c: 900-910",
            "targets/brotli/c/enc/compound_dictionary.c: 170-230",
            "Source searches already run", "bin/rg-safe -n 'xmlParse' targets/libxml2/parser.c",
            "bin/peek -A 50 -B 20 'xmlFree' targets/libxml2/tree.c",
        ):
            self.assertIn(expected, text)
        for forbidden in (
            "missing.c", "not a path", "failed.c", "brotli.c;",
            "compound_dictionary.c;", "output/libxml2/target.toml", "nm build-asan",
        ):
            self.assertNotIn(forbidden, text)

    def test_claude_shell_reads_writes_searches_and_failures(self) -> None:
        events: list[object] = []
        events += self.claude_shell("peek", "bin/peek targets/brotli/c/enc/encode.c:10-90")
        events += self.claude_shell("sed", "sed -n '100,130p' targets/brotli/c/dec/decode.c")
        events += self.claude_shell("failed-read", "bin/peek targets/brotli/missing.c:1-40", True)
        events += self.claude_shell(
            "failed-write", "cat <<EOF > /tmp/results/scratch-2/failed.c\nbad\nEOF", True
        )
        events += self.claude_shell(
            "write", "cat <<'EOF' > /tmp/results/scratch-2/harness.c\nint main(void){return 0;}\nEOF"
        )
        events += self.claude_shell(
            "search", "rg -n 'Decoder' targets/brotli/c/include/brotli/decode.h"
        )
        _, text = self.seed("claude-shell", events)
        for expected in (
            "targets/brotli/c/enc/encode.c: 10-90",
            "targets/brotli/c/dec/decode.c: 100-130",
            "scratch-2/harness.c", "rg -n 'Decoder' targets/brotli/c/include/brotli/decode.h",
        ):
            self.assertIn(expected, text)
        self.assertNotIn("missing.c", text)
        self.assertNotIn("failed.c", text)
        self.assertEqual(build_session_seed.detect_format(self.root / "claude-shell.raw"), "claude")


if __name__ == "__main__":
    unittest.main(verbosity=2)
