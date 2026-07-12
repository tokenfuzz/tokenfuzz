#!/usr/bin/env python3
"""Regression coverage for the deliberately narrow work-path exclusions."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

from workqueue import is_excluded_path_part, is_excluded_work_path


class ExcludedPathTests(unittest.TestCase):
    EXCLUDED = (
        "tests/foo.c", "docs/api.md", "fuzz/harness.c", "examples/demo.c",
        "src/tests/foo.c", "src/doc/foo.c", "subsys/docs/api.md",
        "third_party/lib/examples/x.c", "build-asan/foo.c",
        "build-asan-debug/x.c", "src/build-asan/y.c", "foo-install/x.c",
        "src/cmake-install/y.c", "src/parser_test.cpp", "src/test_parser.cpp",
        "build/CMakeFiles/proj.dir/compiler_depend.ts",
        "build/cmakefiles/proj.dir/x.cpp",
    )
    ALLOWED = (
        "src/parser.c", "xpath/internals.c", "foo/bar.c", "include/api.h",
        "net/quic/stream.cc", "third_party/zlib/inflate.c", "build/foo.c",
        "tools/munge.c", "scripts/helper.c", "external/foo/bar.c",
        "lib/CodeGen/SelectionDAG.cpp", "src/gen_table.c",
        "src/stub_resolver.c", "src/mock_backend.c", "src/perf_counter.c",
        "src/performance.c", "src/debugXML.c", "src/debug.c",
    )

    def test_excluded_paths(self) -> None:
        for path in self.EXCLUDED:
            with self.subTest(path=path):
                self.assertTrue(is_excluded_work_path(path))

    def test_allowed_paths(self) -> None:
        for path in self.ALLOWED:
            with self.subTest(path=path):
                self.assertFalse(is_excluded_work_path(path))

    def test_segment_patterns(self) -> None:
        for part in ("build-asan", "build-asan-debug", "foo-install", "tests", "CMakeFiles", "cmakefiles"):
            with self.subTest(part=part):
                self.assertTrue(is_excluded_path_part(part))
        for part in ("parser", "src"):
            with self.subTest(part=part):
                self.assertFalse(is_excluded_path_part(part))


if __name__ == "__main__":
    unittest.main(verbosity=2)
