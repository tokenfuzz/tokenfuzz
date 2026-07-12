#!/usr/bin/env python3
"""Static regression checks for the sancov validation cache."""

from __future__ import annotations

import ast
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
HITS = ROOT / "bin" / "hits"


class HitsCacheTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tree = ast.parse(HITS.read_text(encoding="utf-8"), filename=str(HITS))
        cls.functions = {
            node.name: node for node in cls.tree.body if isinstance(node, ast.FunctionDef)
        }

    def test_cache_helpers_exist(self) -> None:
        self.assertIn("stat_key", self.functions)
        self.assertIn("cache_dir", self.functions)

    def test_probe_checks_cache_before_inspecting_sections(self) -> None:
        probe = self.functions["probe_sancov"]
        cache_line = None
        section_probe_line = None
        for node in ast.walk(probe):
            if isinstance(node, ast.Call):
                name = ast.unparse(node.func)
                if name == "cache.is_file":
                    cache_line = node.lineno
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if node.value in {"otool", "readelf", "llvm-readelf", "objdump"}:
                    if section_probe_line is None or node.lineno < section_probe_line:
                        section_probe_line = node.lineno
        self.assertIsNotNone(cache_line)
        self.assertIsNotNone(section_probe_line)
        self.assertLess(cache_line, section_probe_line)

    def test_sancov_cache_key_uses_the_binary_digest(self) -> None:
        source = ast.get_source_segment(HITS.read_text(encoding="utf-8"), self.functions["probe_sancov"])
        self.assertIsNotNone(source)
        self.assertRegex(source or "", r"sancov-.*hexdigest")


if __name__ == "__main__":
    unittest.main(verbosity=2)
