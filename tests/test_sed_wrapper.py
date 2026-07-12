#!/usr/bin/env python3
"""Behavior tests for the Python sed output wrapper."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "lib" / "wrappers" / "sed"


class SedWrapperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sed-wrapper-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write(self, name, text):
        path = self.root / name
        path.write_text(text, encoding="utf-8")
        return path

    def run_sed(self, *args, input_text=None, **env):
        command_env = os.environ.copy()
        command_env.update({key: str(value) for key, value in env.items()})
        return subprocess.run(
            [str(COMMAND), *map(str, args)], input=input_text,
            capture_output=True, text=True, env=command_env,
        )

    def test_small_and_large_line_ranges_pass_through(self) -> None:
        small = self.write("small.txt", "foo\nbar\nbaz\n")
        proc = self.run_sed("-n", "1,3p", small)
        self.assertEqual(proc.stdout, "foo\nbar\nbaz\n")
        self.assertNotIn("truncated", proc.stdout)
        large = self.write("large.txt", "".join(f"{number}\n" for number in range(1, 501)))
        proc = self.run_sed("-n", "1,500p", large)
        self.assertEqual(len(proc.stdout.splitlines()), 500)
        self.assertNotIn("truncated", proc.stdout)

    def test_byte_cap_and_escape_hatch(self) -> None:
        huge = self.write("huge.txt", "Z" * 150000 + "\n")
        proc = self.run_sed("-n", "1p", huge)
        self.assertLessEqual(len(proc.stdout.encode()), 56000)
        self.assertIn("output_cap: sed-stdout truncated", proc.stdout)
        self.assertIn("output_cap: sed-stdout truncated", self.run_sed(
            "-n", "1p", huge, CAP_BYTES=65536
        ).stdout)
        self.assertIn("output_cap: sed-stdout truncated", self.run_sed(
            "-n", "1p", huge, CAP_BYTES=4096
        ).stdout)
        large = self.write("large.txt", "".join(f"{number}\n" for number in range(1, 501)))
        proc = self.run_sed("-n", "1,500p", large, CAP_LINES=0, CAP_BYTES=0)
        self.assertEqual(len(proc.stdout.splitlines()), 500)
        self.assertNotIn("truncated", proc.stdout)

    def test_stdin_stream_passes_through(self) -> None:
        stream = "".join(f"{number}\n" for number in range(1, 501))
        proc = self.run_sed("-n", "p", input_text=stream)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, stream)

    def test_in_place_edit_is_portable_and_quiet(self) -> None:
        path = self.write("inplace.txt", "foo\nbar\n")
        proc = self.run_sed("-i", "", "s/foo/FOO/", path)
        if proc.returncode != 0:
            path.write_text("foo\nbar\n", encoding="utf-8")
            proc = self.run_sed("-i", "s/foo/FOO/", path)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("FOO", path.read_text(encoding="utf-8"))
        self.assertEqual(proc.stdout, "")

    def test_exit_status_and_stderr_are_preserved(self) -> None:
        small = self.write("small.txt", "foo\n")
        self.assertEqual(self.run_sed("-n", "1p", small).returncode, 0)
        proc = self.run_sed("-n", "1p", self.root / "missing.txt")
        self.assertNotEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout, "")
        self.assertIn("missing.txt", proc.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
