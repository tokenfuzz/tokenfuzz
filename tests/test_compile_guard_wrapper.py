#!/usr/bin/env python3
"""Behavior tests for Python compiler-output guards."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
WRAPPER = ROOT / "lib" / "wrappers" / "clang"


class CompileGuardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="compile-guard-")
        self.root = Path(self.temporary.name)
        self.results = self.root / "results"
        (self.results / "scratch-1").mkdir(parents=True)
        self.source = self.root / "input.c"
        self.source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        compiler = fake_bin / "clang"
        compiler.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "for index, arg in enumerate(args):\n"
            "    output = args[index + 1] if arg == '-o' and index + 1 < len(args) else arg[2:] if arg.startswith('-o') and len(arg) > 2 else ''\n"
            "    if output:\n        pathlib.Path(output).touch()\n",
            encoding="utf-8",
        )
        compiler.chmod(compiler.stat().st_mode | stat.S_IXUSR)
        self.env = os.environ.copy()
        self.env.update(
            PATH=str(fake_bin) + os.pathsep + self.env.get("PATH", ""),
            RESULTS_DIR=str(self.results), FAKE_COMPILER_LOG=str(self.root / "fake.log"),
        )
        self.root_output = ROOT / ("compile-guard-root-" + uuid.uuid4().hex)

    def tearDown(self) -> None:
        if self.root_output.exists():
            self.root_output.unlink()
        self.temporary.cleanup()

    def run_wrapper(self, *args, **env):
        command_env = self.env.copy()
        command_env.update(env)
        return subprocess.run(
            [str(WRAPPER), *map(str, args)], cwd=str(ROOT), env=command_env,
            capture_output=True, text=True,
        )

    def test_unsafe_root_top_level_scratch_and_implicit_outputs_are_rejected(self) -> None:
        cases = (
            (("-o", self.root_output.name, self.source), "refusing compiler output in audit repo root"),
            (("-o", "scratch-1/bad-bin", self.source), "top-level scratch-N"),
            ((self.source,), "no explicit safe -o path"),
        )
        for args, message in cases:
            with self.subTest(args=args):
                proc = self.run_wrapper(*args)
                self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
                self.assertIn(message, proc.stdout + proc.stderr)
        self.assertFalse(self.root_output.exists())

    def test_results_scratch_output_is_allowed_quietly(self) -> None:
        output = self.results / "scratch-1" / "good-bin"
        proc = self.run_wrapper("-o", output, self.source)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout + proc.stderr, "")
        self.assertTrue(output.is_file())

    def test_explicit_override_allows_root_output(self) -> None:
        proc = self.run_wrapper(
            "-o", self.root_output, self.source, AUDIT_ALLOW_ROOT_COMPILER_OUTPUT="1"
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(proc.stdout + proc.stderr, "")
        self.assertTrue(self.root_output.is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
