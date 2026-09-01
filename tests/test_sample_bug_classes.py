#!/usr/bin/env python3
"""The two single-class sample targets actually produce the bug they claim.

A fixture that no longer reproduces is worse than no fixture: recall for its
bug class silently reads zero and the answer key still says the bug is there.
Checking that a configured path exists proves nothing about that, so this
builds each target with its own recipe and runs it.

MemorySanitizer has no Darwin runtime. That is not a reason to skip: on a host
without one the recipe must *refuse*, because a silently uninstrumented binary
would read as a clean run of the very bug the target plants. So both hosts
assert something real — the refusal here, the diagnostic where MSan exists.
"""

from __future__ import annotations

import json
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import sanitizer  # noqa: E402


def _field(tag: int, value: bytes) -> bytes:
    """One type-length-value field, as both sample formats frame them."""
    return bytes([tag]) + struct.pack(">H", len(value)) + value


def _clang() -> str:
    found = sanitizer.llvm_tool("clang")
    return found if (shutil.which(found) or Path(found).is_file()) else ""


class SampleBugClassTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clang = _clang()
        if not self.clang:
            self.skipTest("no clang to build the sample fixtures")
        self._tmp = tempfile.TemporaryDirectory(prefix="sample-bug-class-")
        self.build = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _recipe(self, slug: str, name: str) -> Path:
        recipe = ROOT / "targets" / "samples" / slug / ".audit" / name
        self.assertTrue(recipe.is_file(), f"{slug} has no {name}")
        return recipe

    def _manifest(self, slug: str) -> dict:
        return json.loads(
            (ROOT / "output" / "samples" / slug / ".ground-truth.json").read_text()
        )

    def test_the_double_free_target_reproduces_its_planted_bug(self) -> None:
        slug = "sample-c-doublefree"
        source = ROOT / "targets" / "samples" / slug
        built = subprocess.run(
            ["bash", str(self._recipe(slug, "build.sh")), str(source), str(self.build)],
            capture_output=True, text=True, check=False, timeout=300)
        if built.returncode:
            self.skipTest(f"cannot build {slug}: {built.stderr[-300:]}")
        binary = self.build / "chtio"
        self.assertTrue(binary.is_file())

        # OPEN a one-byte transfer, then PUSH more than fits: the failure path
        # frees the buffer without clearing the owner, and the exit cleanup
        # frees it again.
        testcase = self.build / "case-doublefree"
        testcase.write_bytes(
            b"CHT1" + _field(0x01, struct.pack(">H", 1)) + _field(0x02, b"AAAA")
        )
        run = subprocess.run(
            [str(binary), str(testcase)],
            capture_output=True, text=True, check=False, timeout=120)
        report = run.stdout + run.stderr
        self.assertIn("AddressSanitizer", report)
        self.assertIn("double-free", report)
        # The frame the answer key pins is the one the sanitizer names.
        planted = self._manifest(slug)["planted_bugs"][0]
        self.assertEqual(planted["primitive"], "double-free")
        self.assertIn(planted["signature_symbol"], report)

    def test_a_clean_input_is_clean(self) -> None:
        """The trap the answer key says is safe must not fire."""
        slug = "sample-c-doublefree"
        source = ROOT / "targets" / "samples" / slug
        built = subprocess.run(
            ["bash", str(self._recipe(slug, "build.sh")), str(source), str(self.build)],
            capture_output=True, text=True, check=False, timeout=300)
        if built.returncode:
            self.skipTest(f"cannot build {slug}: {built.stderr[-300:]}")
        testcase = self.build / "case-note"
        testcase.write_bytes(b"CHT1" + _field(0x05, b"xy"))
        run = subprocess.run(
            [str(self.build / "chtio"), str(testcase)],
            capture_output=True, text=True, check=False, timeout=120)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertNotIn("AddressSanitizer", run.stdout + run.stderr)

    def test_the_uninit_target_reproduces_or_refuses_to_build(self) -> None:
        slug = "sample-c-uninit"
        source = ROOT / "targets" / "samples" / slug
        built = subprocess.run(
            ["bash", str(self._recipe(slug, "build-msan.sh")),
             str(source), str(self.build)],
            capture_output=True, text=True, check=False, timeout=300)
        binary = self.build / "gauge"

        if built.returncode:
            # No MSan runtime for this host. The contract is that the recipe
            # says so and produces nothing — never an uninstrumented binary
            # that would read as a clean run of the planted bug.
            self.assertFalse(binary.exists(), "a refused build left a binary behind")
            self.assertIn("MemorySanitizer", built.stderr)
            return

        self.assertTrue(binary.is_file())
        # A SAMPLE body of 2..4 bytes leaves the scale field unwritten, and
        # the handler branches on it.
        testcase = self.build / "case-uninit"
        testcase.write_bytes(b"GAU1" + _field(0x01, b"\x00\x05"))
        run = subprocess.run(
            [str(binary), str(testcase)],
            capture_output=True, text=True, check=False, timeout=120)
        report = run.stdout + run.stderr
        self.assertIn("MemorySanitizer", report)
        self.assertIn("use-of-uninitialized-value", report)
        planted = self._manifest(slug)["planted_bugs"][0]
        self.assertIn(planted["signature_symbol"], report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
