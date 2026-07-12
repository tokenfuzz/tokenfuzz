#!/usr/bin/env python3
"""Regression tests for the Python Firefox sanitizer build helper."""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
BUILD = ROOT / ".agents" / "skills" / "ff-bsan" / "scripts" / "build.py"


class FirefoxBuildHelperTests(unittest.TestCase):
    def test_build_helper_retains_portable_preflights(self) -> None:
        self.assertTrue(BUILD.is_file())
        source = BUILD.read_text(encoding="utf-8")
        for required in (
            "def llvm_prefix", "clobber required for", "def msan_supported",
            "skipping msan requested through all",
        ):
            with self.subTest(required=required):
                self.assertIn(required, source)
        self.assertNotIn('LLVM_PREFIX="/opt/homebrew/opt/llvm"', source)

    def test_has_symbol_handles_present_and_absent_symbols(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("cc is unavailable")
        with tempfile.TemporaryDirectory(prefix="ff-bsan-") as temporary:
            root = Path(temporary)
            source = root / "many_syms.c"
            binary = root / "many_syms"
            functions = "\n".join(
                f"int __probe_marker_{number}(void){{return {number};}}"
                for number in range(1, 101)
            )
            source.write_text(
                "#include <stdio.h>\n" + functions + "\nint main(void){return 0;}\n",
                encoding="utf-8",
            )
            proc = subprocess.run(
                [compiler, "-O0", "-o", str(binary), str(source)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

            spec = importlib.util.spec_from_file_location("ff_bsan_build", str(BUILD))
            self.assertIsNotNone(spec)
            self.assertIsNotNone(spec.loader if spec else None)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.assertTrue(module.has_symbol(binary, b"__probe_marker_1"))
            self.assertFalse(module.has_symbol(binary, b"__definitely_absent"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
