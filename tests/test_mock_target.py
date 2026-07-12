#!/usr/bin/env python3
"""Verify the neutral mock target layout and analysis markers."""

from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MOCK = ROOT / "tests" / "fixtures" / "mock-target"


class MockTargetTests(unittest.TestCase):
    def assert_file_contains(self, relative: str, text: str) -> None:
        path = MOCK / relative
        self.assertTrue(path.is_file(), str(path))
        self.assertIn(text, path.read_text(encoding="utf-8"))

    def assert_file_not_contains(self, relative: str, text: str) -> None:
        path = MOCK / relative
        self.assertTrue(path.is_file(), str(path))
        self.assertNotIn(text, path.read_text(encoding="utf-8"))

    def test_firefox_shaped_directories_exist(self) -> None:
        for relative in (
            "dom/canvas", "dom/html/parser", "js/src/jit", "js/src/wasm",
            "js/src/gc", "image/decoders/png", "gfx/layers",
            "netwerk/protocol/http", "dom/svg", "mfbt", "dom/encoding",
            "third_party/rust/encoding_rs",
        ):
            with self.subTest(relative=relative):
                self.assertTrue((MOCK / relative).is_dir())

    def test_analysis_patterns_are_discoverable(self) -> None:
        patterns = (
            r"overflow|unchecked|truncat",
            r"freed|UAF|use-after-free|stale",
            r"OOB|out-of-bounds|overflow|past.*allocation",
        )
        cpp_text = [path.read_text(encoding="utf-8") for path in MOCK.rglob("*.cpp")]
        for pattern in patterns:
            with self.subTest(pattern=pattern):
                self.assertTrue(any(re.search(pattern, text) for text in cpp_text))

    def test_subsystem_markers_and_guards(self) -> None:
        expected = {
            "dom/canvas/CanvasRenderingContext2D.cpp": ("overflow", "UAF", "ValidateRect"),
            "js/src/jit/WarpBuilder.cpp": ("type", "truncat"),
            "image/decoders/png/nsPNGDecoder.cpp": ("OOB", "ValidateIDATChecksum"),
            "js/src/gc/Nursery.cpp": ("stale",),
            "dom/html/parser/nsHtml5TreeBuilder.cpp": ("double-free", "re-enter"),
            "js/src/wasm/WasmValidate.cpp": ("stack", "ValidateBlockType"),
            "netwerk/protocol/http/nsHttpChannel.cpp": ("truncat",),
            "dom/svg/SVGPathElement.cpp": ("UAF",),
        }
        for relative, markers in expected.items():
            for marker in markers:
                with self.subTest(relative=relative, marker=marker):
                    self.assert_file_contains(relative, marker)

    def test_clean_sources_retain_guards_without_markers(self) -> None:
        self.assert_file_not_contains("gfx/layers/Compositor.cpp", "BUG")
        self.assert_file_contains("media/libvpx/vp9_decoder.cpp", "return false")
        self.assert_file_not_contains("media/libvpx/vp9_decoder.cpp", "BUG")

    def test_headers_exist(self) -> None:
        self.assertTrue((MOCK / "dom/canvas/CanvasRenderingContext2D.h").is_file())
        self.assertTrue((MOCK / "mfbt/Assertions.h").is_file())


if __name__ == "__main__":
    unittest.main(verbosity=2)
