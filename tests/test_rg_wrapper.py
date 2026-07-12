#!/usr/bin/env python3
"""Behavior tests for the Python ripgrep output wrapper."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "lib" / "wrappers" / "rg"
GREP = ROOT / "lib" / "wrappers" / "grep"


@unittest.skipIf(shutil.which("rg") is None, "ripgrep is unavailable")
class RipgrepWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="rg-wrapper-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def run_tool(self, command, *args, input_text=None, **env):
        command_env = os.environ.copy()
        command_env.update({key: str(value) for key, value in env.items()})
        return subprocess.run(
            [str(command), *map(str, args)], input=input_text,
            capture_output=True, text=True, env=command_env,
        )

    def run_rg(self, *args, input_text=None, **env):
        return self.run_tool(COMMAND, *args, input_text=input_text, **env)

    def test_small_large_and_count_output(self) -> None:
        small = self.write("small.txt", "alpha\nbeta\ngamma\n")
        proc = self.run_rg("a", small)
        self.assertIn("alpha", proc.stdout)
        self.assertIn("gamma", proc.stdout)
        large = self.write(
            "large.txt", "".join(f"{number} match\n" for number in range(1, 501))
        )
        proc = self.run_rg("match", large)
        self.assertEqual(sum("match" in line for line in proc.stdout.splitlines()), 500)
        self.assertNotIn("clipped", proc.stdout)
        self.assertIn("500", self.run_rg("--count", "match", large).stdout)

    def test_log_and_vcs_exclusions(self) -> None:
        tree = self.root / "logtree"
        files = {
            "src/logs/logger.c", "src/.raw/corpus.txt",
            "output/sample/codex/logs/.raw/session_1.prompt.md",
            "output/sample/codex/logs/session_1.log",
            "output/sample/codex/logs/.raw/session_1.log.raw",
            "output/sample/codex/logs/.gemini-home/chats/s.jsonl",
            "output/sample/codex/.hg/store",
        }
        for relative in files:
            path = tree / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("PATCH-rg-wrapper\n")
        output = self.run_rg("PATCH-rg-wrapper", tree).stdout
        self.assertIn("src/logs/logger.c", output)
        for forbidden in ("session_1.prompt.md", "session_1.log", ".hg/store"):
            self.assertNotIn(forbidden, output)
        hidden = self.run_rg("--hidden", "PATCH-rg-wrapper", tree).stdout
        self.assertIn("src/.raw/corpus.txt", hidden)
        for forbidden in ("logs/.raw/session_1.log.raw", "gemini-home", ".hg/store"):
            self.assertNotIn(forbidden, hidden)

    def test_diagnostics_stay_on_stderr(self) -> None:
        proc = self.run_rg("needle", self.root / "missing.txt")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertIn("missing.txt", proc.stderr)

    def test_byte_caps_alignment_and_escape(self) -> None:
        huge = self.write("huge.txt", "Z" * 150000 + " match\n")
        proc = self.run_rg("match", huge)
        self.assertLessEqual(len(proc.stdout.encode()), 56000)
        self.assertIn("output_cap: rg-stdout truncated", proc.stdout)
        self.assertIn("output_cap: rg-stdout truncated", self.run_rg(
            "match", huge, CAP_BYTES=65536
        ).stdout)
        capped = self.run_rg("match", huge, CAP_BYTES=4096).stdout
        self.assertLessEqual(len(capped.encode()), 5000)
        self.assertIn("output_cap: rg-stdout truncated", capped)
        uncapped = self.run_rg("match", huge, CAP_BYTES=0).stdout
        self.assertGreaterEqual(len(uncapped), 150000)
        combo = self.write(
            "combo.txt", "".join("W" * 800 + f" match {number}\n" for number in range(500))
        )
        proc = self.run_rg("match", combo)
        self.assertLessEqual(len(proc.stdout.encode()), 56000)
        self.assertIn("output_cap: rg-stdout truncated", proc.stdout)
        aligned = self.write(
            "align.txt", "".join("V" * 40 + f" match {number:03d}\n" for number in range(200))
        )
        output = self.run_rg("match", aligned, CAP_BYTES=600).stdout
        data_lines = [line for line in output.splitlines() if line.startswith("V")]
        self.assertTrue(data_lines)
        self.assertIn(" match ", data_lines[-1])

    def test_stdin_and_passthrough_boundary(self) -> None:
        stream = "".join(f"{number}\n" for number in range(1, 501))
        proc = self.run_rg("[0-9]+", input_text=stream)
        self.assertEqual(proc.stdout.splitlines(), stream.splitlines())
        haystack = self.write(
            "passthru.txt", "".join("--count " + "Z" * 400 + "\n" for _ in range(400))
        )
        output = self.run_rg("--", r"\-\-count", haystack).stdout
        self.assertLessEqual(len(output.encode()), 56000)

    def test_per_tool_bypass(self) -> None:
        huge = self.write("huge.txt", "Z" * 150000 + " match\n")
        cases = (
            ("rg", COMMAND, 150000, None),
            ("rg", GREP, None, 56000),
            ("all", COMMAND, 150000, None),
            ("", COMMAND, None, 56000),
        )
        for bypass, command, minimum, maximum in cases:
            with self.subTest(bypass=bypass, command=command.name):
                size = len(self.run_tool(
                    command, "match", huge, AGENT_WRAPPERS_BYPASS=bypass
                ).stdout.encode())
                if minimum is not None:
                    self.assertGreaterEqual(size, minimum)
                if maximum is not None:
                    self.assertLessEqual(size, maximum)


if __name__ == "__main__":
    unittest.main(verbosity=2)
