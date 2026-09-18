#!/usr/bin/env python3
"""The canary answer key, proven against the sanitizer's own report.

Builds a copy of targets/canary with its committed recipe and runs every
planted input and trap, then attributes each report the way the benchmark
scorer does. A manifest entry that the binary does not reproduce, or that
matches at the wrong symbol, is a broken yardstick, so this fails before a
benchmark run could mis-score.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import benchmark

CC = shutil.which(os.environ.get("CC", "clang"))
CANARY = ROOT / "targets" / "canary"
MANIFEST = ROOT / "output" / "canary" / ".ground-truth.json"


@unittest.skipUnless(CC, "a C compiler is required")
class CanaryPlantedBugTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="canary-planted-")
        root = Path(cls.temporary.name)
        cls.source = root / "canary"
        # Never build inside the checkout: the suite's checkout guard fails a
        # run that writes tracked trees, and parallel tests share the tree.
        shutil.copytree(
            CANARY, cls.source,
            ignore=shutil.ignore_patterns("build-*", "*-install"),
        )
        cls.build = root / "build-asan"
        subprocess.run(
            ["bash", str(cls.source / ".audit" / "build.sh"), str(cls.source), str(cls.build)],
            check=True, capture_output=True, text=True, env={**os.environ, "CC": CC},
        )
        cls.manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def run_input(self, relative: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [str(self.build / "canary"), str(self.source / relative)],
            capture_output=True, text=True, check=False,
            env={**os.environ, "ASAN_OPTIONS": "handle_abort=1:detect_leaks=0:symbolize=1"},
        )

    def attribution(self, report: str):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "sanitizer.txt").write_text(report, encoding="utf-8")
            return benchmark._attribution_evidence(Path(tmp))

    def test_manifest_is_valid(self) -> None:
        self.assertEqual(benchmark.manifest_errors(self.manifest), [])
        strategies = {b["id"]: b.get("strategy") for b in self.manifest["planted_bugs"]}
        self.assertTrue(all(strategies.values()), f"every bug names its strategy: {strategies}")
        self.assertGreaterEqual(len(set(strategies.values())), 4, "the key spans several strategy families")

    def test_every_planted_bug_crashes_at_its_signature(self) -> None:
        real = [b for b in self.manifest["planted_bugs"] if b.get("kind", "real") == "real"]
        for bug in real:
            with self.subTest(bug=bug["id"]):
                proc = self.run_input(bug["input"])
                self.assertIn("AddressSanitizer", proc.stderr, f"{bug['id']} produced no report")
                evidence = self.attribution(proc.stderr)
                self.assertIsNotNone(evidence, proc.stderr[-800:])
                primitive, site, access = evidence
                self.assertEqual(primitive, bug["primitive"], proc.stderr[-800:])
                self.assertIn(bug["signature_symbol"], site, proc.stderr[-800:])
                if bug.get("access"):
                    self.assertEqual(access, bug["access"])
                hit = benchmark._match_real(primitive, site, access, real)
                self.assertEqual(hit["id"], bug["id"], "the scorer credits this exact entry")

    def test_traps_do_not_present_as_memory_safety_faults(self) -> None:
        for trap in self.manifest["false_positive_traps"]:
            with self.subTest(trap=trap["id"]):
                proc = self.run_input(trap["input"])
                if trap["expected_outcome"] == "clean":
                    self.assertNotIn("AddressSanitizer", proc.stderr)
                    self.assertEqual(proc.returncode, 1, "a miss returns 1 without a report")
                else:
                    evidence = self.attribution(proc.stderr)
                    self.assertIsNotNone(evidence)
                    self.assertEqual(evidence[0], "ABRT", proc.stderr[-600:])


if __name__ == "__main__":
    unittest.main()
