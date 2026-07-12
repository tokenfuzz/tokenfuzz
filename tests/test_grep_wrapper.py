#!/usr/bin/env python3
"""Behavior tests for the Python grep output wrapper."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "lib" / "wrappers" / "grep"


class GrepWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="grep-wrapper-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def run_grep(self, *args, input_text=None, **env):
        command_env = os.environ.copy()
        command_env.update({key: str(value) for key, value in env.items()})
        return subprocess.run(
            [str(COMMAND), *map(str, args)], input=input_text,
            capture_output=True, text=True, env=command_env,
        )

    def test_normal_count_list_and_quiet_modes(self) -> None:
        small = self.write("small.txt", "foo\nbar\nbaz\n")
        proc = self.run_grep(".", small)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("foo", proc.stdout)
        self.assertIn("baz", proc.stdout)
        large = self.write("large.txt", "".join(f"{number}\n" for number in range(1, 501)))
        proc = self.run_grep(".", large)
        self.assertEqual(len(proc.stdout.splitlines()), 500)
        self.assertNotIn("truncated", proc.stdout)
        self.assertEqual(self.run_grep("-c", ".", large).stdout.strip(), "500")
        match = self.write("match.txt", "match\n")
        self.assertIn("match.txt", self.run_grep("-l", "match", match).stdout)
        self.assertEqual(self.run_grep("-q", "match", match).returncode, 0)
        self.assertEqual(self.run_grep("-q", "nomatch", match).returncode, 1)

    def test_recursive_mode_excludes_logs_and_vcs_but_not_other_dotdirs(self) -> None:
        tree = self.root / "logtree"
        files = {
            "src/logs/logger.c": "PATCH-grep-wrapper\n",
            "src/.raw/corpus.txt": "PATCH-grep-wrapper\n",
            "output/sample/codex/logs/.raw/session_1.prompt.md": "PATCH-grep-wrapper\n",
            "output/sample/codex/logs/.raw/session_1.log.raw": "PATCH-grep-wrapper\n",
            "output/sample/codex/logs/.gemini-home/chats/s.jsonl": "PATCH-grep-wrapper\n",
            "output/sample/codex/.hg/store": "PATCH-grep-wrapper\n",
        }
        for relative, text in files.items():
            path = tree / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        output = self.run_grep("-R", "PATCH-grep-wrapper", tree).stdout
        self.assertIn("src/.raw/corpus.txt", output)
        for forbidden in (
            "src/logs/logger.c", "session_1.prompt.md", "session_1.log.raw",
            "gemini-home", ".hg/store",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, output)

    def test_exit_codes_and_stderr_are_preserved(self) -> None:
        existing = self.write("exit.txt", "hello\n")
        self.assertEqual(self.run_grep("hello", existing).returncode, 0)
        self.assertEqual(self.run_grep("zzzznothere", existing).returncode, 1)
        proc = self.run_grep("needle", self.root / "missing.txt")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, "")
        self.assertIn("missing.txt", proc.stderr)
        missing = [self.root / f"missing-{number}.txt" for number in range(250)]
        proc = self.run_grep("needle", *missing)
        self.assertEqual(proc.stdout, "")
        self.assertEqual(len(proc.stderr.splitlines()), 250)

    def test_byte_cap_and_overrides(self) -> None:
        huge = self.write("huge.txt", "Z" * 150000 + " match\n")
        proc = self.run_grep("match", huge)
        self.assertLessEqual(len(proc.stdout.encode()), 56000)
        self.assertIn("output_cap: grep-stdout truncated", proc.stdout)
        self.assertIn("output_cap: grep-stdout truncated", self.run_grep(
            "match", huge, CAP_BYTES=65536
        ).stdout)
        capped = self.run_grep("match", huge, CAP_BYTES=4096).stdout
        self.assertIn("output_cap: grep-stdout truncated", capped)
        uncapped = self.run_grep("match", huge, CAP_BYTES=0).stdout
        self.assertGreaterEqual(len(uncapped), 150000)
        self.assertNotIn("output_cap", uncapped)

    def test_stdin_and_passthrough_boundary(self) -> None:
        stream = "".join(f"{number}\n" for number in range(1, 501))
        proc = self.run_grep(".", input_text=stream)
        self.assertEqual(proc.stdout.splitlines(), stream.splitlines())
        haystack = self.write(
            "passthru.txt", "".join("-c " + "Z" * 400 + "\n" for _ in range(500))
        )
        literal = self.run_grep("--", "-c", haystack).stdout
        self.assertLessEqual(len(literal.encode()), 56000)
        self.assertEqual(self.run_grep("-c", ".", haystack).stdout.strip(), "500")

    def test_empty_streams_emit_nothing(self) -> None:
        path = self.write("nomatch.txt", "needle\n")
        proc = self.run_grep("ABSENT_PATTERN_XYZ", path)
        self.assertEqual(proc.returncode, 1)
        self.assertEqual(proc.stdout, "")
        proc = self.run_grep("needle", path)
        self.assertEqual(proc.stderr, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
