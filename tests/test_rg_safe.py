#!/usr/bin/env python3
"""Behavior tests for bounded ripgrep with explicit escape hatches."""

from __future__ import annotations

import json
import os
import py_compile
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "rg-safe"
WRAPPERS = ROOT / "lib" / "wrappers"


@unittest.skipIf(shutil.which("rg") is None, "ripgrep is unavailable")
class RipgrepSafeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="rg-safe-")
        self.root = Path(self.temporary.name)
        self.big = self.write(
            "big.txt", "".join(f"line {number} match\n" for number in range(1, 501))
        )
        self.small = self.write("small.txt", "foo\nbar\nbaz\n")
        self.huge = self.write("huge.txt", "X" * 150000 + " match\n")
        self.combo = self.write(
            "combo.txt", "".join("Y" * 200 + f" match {number}\n" for number in range(500))
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def run_rg(self, *args, **env):
        command_env = os.environ.copy()
        command_env.update({key: str(value) for key, value in env.items()})
        return subprocess.run(
            [str(COMMAND), *map(str, args)], capture_output=True, text=True, env=command_env
        )

    def test_syntax_full_small_output_and_exit_codes(self) -> None:
        py_compile.compile(str(COMMAND), doraise=True)
        proc = self.run_rg("match", self.big)
        self.assertEqual(len([line for line in proc.stdout.splitlines() if line.startswith("line")]), 500)
        self.assertNotIn("capped at", proc.stdout)
        uncapped = self.run_rg("--no-cap", "match", self.big)
        self.assertEqual(len([line for line in uncapped.stdout.splitlines() if line.startswith("line")]), 500)
        expected = subprocess.run(
            [shutil.which("rg"), "a", str(self.small)], capture_output=True, text=True
        )
        actual = self.run_rg("a", self.small)
        self.assertEqual(actual.stdout, expected.stdout)
        self.assertEqual(self.run_rg("unobtainium-zzzzz", self.small).returncode, 1)
        self.assertEqual(self.run_rg("foo", self.small).returncode, 0)
        self.assertEqual(len(self.run_rg("--", "match", self.big).stdout.splitlines()), 500)

    def test_missing_ripgrep_has_a_helpful_error(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(COMMAND), "foo", str(self.small)],
            capture_output=True, text=True, env={"PATH": str(self.root / "no-rg")},
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertRegex(proc.stdout + proc.stderr, r"rg .*ripgrep.* not found")

    def test_byte_cap_options_and_alignment(self) -> None:
        proc = self.run_rg("match", self.huge)
        self.assertLessEqual(len(proc.stdout.encode()), 56000)
        self.assertIn("output_cap: rg-safe truncated", proc.stdout)
        self.assertIn("OUTCAP_MAX_BYTES=0 to disable", proc.stdout)
        self.assertIn("output_cap: rg-safe truncated", self.run_rg(
            "match", self.huge, RG_BYTES=65536
        ).stdout)
        capped = self.run_rg("match", self.huge, RG_BYTES=8192).stdout
        self.assertLessEqual(len(capped.encode()), 9000)
        self.assertIn("output_cap: rg-safe truncated", capped)
        self.assertLessEqual(len(self.run_rg(
            "--cap-bytes", "4096", "match", self.huge, RG_BYTES=8192
        ).stdout.encode()), 5000)
        self.assertLessEqual(len(self.run_rg(
            "--cap-bytes=2048", "match", self.huge
        ).stdout.encode()), 3000)
        for args, env in (
            (("match", self.huge), {"RG_BYTES": 0}),
            (("--no-cap-bytes", "match", self.huge), {}),
            (("--no-cap", "match", self.huge), {}),
        ):
            with self.subTest(args=args, env=env):
                output = self.run_rg(*args, **env).stdout
                self.assertGreaterEqual(len(output), 150000)
                self.assertNotIn("output_cap", output)
        self.assertIn("output_cap: rg-safe truncated", self.run_rg(
            "--cap-bytes", "4096", "match", self.combo
        ).stdout)
        aligned = self.run_rg("--cap-bytes", "500", "match", self.combo).stdout
        data = [line for line in aligned.splitlines() if line.startswith("Y")]
        self.assertTrue(data)
        self.assertIn(" match ", data[-1])
        proc = self.run_rg("--cap-bytes", "notanumber", "match", self.big)
        self.assertIn("non-numeric --cap-bytes", proc.stdout + proc.stderr)
        self.assertNotEqual(self.run_rg("--cap-bytes").returncode, 0)

    def make_log_tree(self):
        tree = self.root / "logtree"
        relatives = (
            "targets/foo/src/code.c", "targets/foo/src/logs/parser.c",
            "targets/foo/src/.raw/corpus.txt", "targets/foo/output/pkg/logs/source.c",
            "output/foo/codex/logs/.raw/session_x.prompt.md",
            "output/foo/codex/logs/sess.log.raw",
            "output/foo/codex/logs/.raw/session.raw", "output/foo/codex/logs/index.log",
            "output/foo/codex/logs/session_x.log",
            "output/foo/codex/logs/.gemini-home/chats/s.jsonl",
            "output/foo/codex/.git/HEAD", "output/foo/codex/.hg/store",
        )
        for relative in relatives:
            path = tree / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("PATCH-deadbeef found here\n", encoding="utf-8")
        return tree

    def test_default_include_logs_hidden_and_caller_globs(self) -> None:
        tree = self.make_log_tree()
        output = self.run_rg("PATCH-deadbeef", tree).stdout
        self.assertIn("src/code.c", output)
        self.assertIn("src/logs/parser.c", output)
        for forbidden in (
            "output/pkg/logs/source.c", "session_x.prompt.md",
            "sess.log.raw", "codex/logs/.raw/session.raw", "codex/logs/index.log",
            "session_x.log:", ".git/HEAD", ".hg/store",
        ):
            self.assertNotIn(forbidden, output)
        hidden = self.run_rg("--hidden", "PATCH-deadbeef", tree).stdout
        self.assertIn("src/.raw/corpus.txt", hidden)
        for forbidden in ("gemini-home", "codex/logs/.raw/session.raw", ".git/HEAD", ".hg/store"):
            self.assertNotIn(forbidden, hidden)
        included = self.run_rg("--include-logs", "PATCH-deadbeef", tree).stdout
        self.assertIn("src/code.c", included)
        self.assertIn("session_x.log", included)
        self.assertIn("codex/logs/index.log", included)
        self.assertNotIn(".git/HEAD", included)
        self.assertNotIn(".hg/store", included)
        env_included = self.run_rg("PATCH-deadbeef", tree, RG_INCLUDE_LOGS=1).stdout
        self.assertIn("session_x.log", env_included)
        proc = subprocess.run(
            [str(COMMAND), "--glob", "!**/src/**", "PATCH-deadbeef", "."],
            cwd=str(tree), capture_output=True, text=True,
        )
        self.assertNotIn("src/code.c", proc.stdout)
        self.assertNotIn("sess.log.raw", proc.stdout)

    def test_real_raw_log_shape_is_capped(self) -> None:
        tree = self.make_log_tree()
        raw = tree / "output/foo/codex/logs/huge.log.raw"
        raw.write_text(json.dumps({
            "type": "item.completed",
            "item": {"command": "/bin/zsh -lc rg-safe match", "aggregated_output": "X" * 200000},
        }) + "\n", encoding="utf-8")
        output = self.run_rg("--include-logs", "aggregated_output", raw).stdout
        self.assertLessEqual(len(output.encode()), 56000)

    def test_wrapped_path_does_not_double_cap_or_hide_escape_hatches(self) -> None:
        tree = self.make_log_tree()
        wrapped_path = str(WRAPPERS) + os.pathsep + os.environ.get("PATH", "")
        output = self.run_rg("--no-cap", "match", self.big, PATH=wrapped_path).stdout
        self.assertEqual(len([line for line in output.splitlines() if line.startswith("line")]), 500)
        output = self.run_rg("match", self.big, PATH=wrapped_path).stdout
        self.assertEqual(len([line for line in output.splitlines() if line.startswith("line")]), 500)
        included = self.run_rg(
            "--include-logs", "-l", "PATCH-deadbeef", tree,
            PATH=wrapped_path, AGENT_WRAPPERS_PATH=WRAPPERS,
        ).stdout
        self.assertIn("session_x.log", included)
        default = self.run_rg(
            "-l", "PATCH-deadbeef", tree,
            PATH=wrapped_path, AGENT_WRAPPERS_PATH=WRAPPERS,
        ).stdout
        self.assertNotIn("session_x.log", default)
        output = self.run_rg("match", self.huge, PATH=wrapped_path, RG_BYTES=0).stdout
        self.assertGreaterEqual(len(output), 150000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
