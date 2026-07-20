#!/usr/bin/env python3
"""Portable-language and syntax checks for production entry points."""

from __future__ import annotations

import compileall
import os
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class PortabilityLintTests(unittest.TestCase):
    def test_only_real_shell_behavior_remains_in_shell_suites(self) -> None:
        shell_tests = {path.name for path in (ROOT / "tests").glob("test_*.sh")}
        self.assertEqual(shell_tests, {"test_runner.sh", "test_zdotdir_shim.sh"})

    def production_files(self):
        for directory in (ROOT / "bin", ROOT / "lib"):
            yield from (path for path in directory.rglob("*") if path.is_file())

    def test_no_gnu_only_path_or_find_forms(self) -> None:
        patterns = {
            "GNU realpath/readlink": re.compile(r"realpath\s+--relative-to|readlink\s+-f"),
            "find -printf": re.compile(r"find[^\n]*\s-printf\s"),
        }
        for label, pattern in patterns.items():
            hits = []
            for path in self.production_files():
                try:
                    text = path.read_text(encoding="utf-8")
                except (OSError, UnicodeDecodeError):
                    continue
                if pattern.search(text):
                    hits.append(str(path.relative_to(ROOT)))
            with self.subTest(label=label):
                self.assertEqual(hits, [])

    def test_executable_production_entrypoints_are_not_bash(self) -> None:
        hits = []
        for base in (ROOT / "bin", ROOT / "lib", ROOT / ".agents"):
            for path in base.rglob("*"):
                if not path.is_file() or not os.access(str(path), os.X_OK):
                    continue
                try:
                    lines = path.read_text(encoding="utf-8").splitlines()
                except (OSError, UnicodeDecodeError):
                    continue
                if not lines:
                    continue
                first = lines[0]
                if "bash" in first:
                    hits.append(str(path.relative_to(ROOT)))
        self.assertEqual(hits, [])

    def test_all_production_python_compiles(self) -> None:
        for directory in (
            ROOT / "bin", ROOT / "lib",
            ROOT / ".agents" / "skills" / "ff-bsan" / "scripts",
        ):
            with self.subTest(directory=directory.relative_to(ROOT)):
                self.assertTrue(compileall.compile_dir(str(directory), quiet=1))

    def test_operator_commands_use_python(self) -> None:
        for name in (
            "audit", "benchmark", "hits", "probe", "run-asan",
            "run-msan", "run-tsan", "run-ubsan", "setup-target", "validate-finding",
        ):
            with self.subTest(name=name):
                first = (ROOT / "bin" / name).read_text(encoding="utf-8").splitlines()[0]
                self.assertIn("python3", first)


if __name__ == "__main__":
    unittest.main(verbosity=2)
