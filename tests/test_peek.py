#!/usr/bin/env python3
"""bin/peek range mode: which file a relative path names."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "peek"


class PeekPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="peek-")
        base = Path(self.temporary.name)
        self.cwd = base / "harness"
        self.target = base / "target"
        self.results = base / "results"
        for directory in (self.cwd, self.target / "src", self.results / "scratch-1"):
            directory.mkdir(parents=True)
        (self.target / "src" / "app_parse.c").write_text("one\ntwo\nthree\n")
        (self.results / "scratch-1" / "tc.txt").write_text("result bytes\n")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def peek(self, *args: str) -> subprocess.CompletedProcess:
        env = os.environ | {"TARGET_ROOT": str(self.target), "RESULTS_DIR": str(self.results)}
        return subprocess.run(
            [sys.executable, str(COMMAND), *args],
            capture_output=True, text=True, cwd=self.cwd, env=env, check=False,
        )

    def test_target_relative_source_resolves_under_the_target(self) -> None:
        proc = self.peek("src/app_parse.c:2-3")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "two\nthree\n")

    def test_results_relative_artifact_resolves_under_results(self) -> None:
        proc = self.peek("scratch-1/tc.txt")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout, "result bytes\n")

    def test_the_cwd_wins_and_a_missing_file_still_fails(self) -> None:
        (self.cwd / "src").mkdir()
        (self.cwd / "src" / "app_parse.c").write_text("local\n")
        self.assertEqual(self.peek("src/app_parse.c").stdout, "local\n")
        missing = self.peek("src/absent.c:1-2")
        self.assertEqual(missing.returncode, 2)
        self.assertIn("file not found: src/absent.c", missing.stderr)


if __name__ == "__main__":
    unittest.main()
