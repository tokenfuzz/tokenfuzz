#!/usr/bin/env python3
"""Behavior tests for path-first scratch search output and exclusions."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "scratch-search"


@unittest.skipIf(shutil.which("rg") is None, "rg is unavailable")
class ScratchSearchTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="scratch-search-")
        self.results = Path(self.temporary.name) / "results"
        self.env = os.environ.copy()
        self.env["RESULTS_DIR"] = str(self.results)
        paths = {
            "scratch-1": self.results / "scratch-1",
            "scratch-2": self.results / "scratch-2",
            "corpus": self.results / "corpus",
            "crash": self.results / "crashes" / "CRASH-001-1",
            "finding": self.results / "findings" / "FIND-002-1",
        }
        for path in paths.values():
            path.mkdir(parents=True)
        (paths["scratch-1"] / "altsvc_harness.c").write_text(
            "// Two references to ALTSVC_NEEDLE inside the same file.\n"
            "int main(void) {\n  /* ALTSVC_NEEDLE entry point */\n"
            "  if (0) { /* second ALTSVC_NEEDLE for the search */ }\n  return 0;\n}\n",
            encoding="utf-8",
        )
        (paths["scratch-1"] / "altsvc_notes.md").write_text("ALTSVC_NEEDLE seen here too\n")
        (paths["scratch-2"] / "aws_sigv4_harness.c").write_text("no match here\n")
        (paths["corpus"] / "altsvc-input-1.txt").write_text("ALTSVC_NEEDLE in promoted corpus\n")
        (paths["crash"] / "report.md").write_text("## Summary  ALTSVC_NEEDLE in this crash report\n")
        (paths["scratch-1"] / "altsvc_harness.asan.txt").write_text("ALTSVC_NEEDLE in asan sidecar\n")
        (paths["scratch-1"] / "build.log").write_text("ALTSVC_NEEDLE in build log\n")
        cache = paths["scratch-1"] / ".harness-cache"
        cache.mkdir()
        (cache / "cache_marker").write_text("ALTSVC_NEEDLE in harness cache compile binary\n")
        (cache / "foo.c").write_text("ALTSVC_NEEDLE inside cache dir\n")
        self.scratch_one = paths["scratch-1"]

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_search(self, *args: str, results: bool = True) -> subprocess.CompletedProcess:
        env = self.env.copy()
        if not results:
            env["RESULTS_DIR"] = ""
        return subprocess.run(
            [str(COMMAND), *args], capture_output=True, text=True, env=env
        )

    def test_help_and_usage_errors(self) -> None:
        proc = self.run_search("--help")
        self.assertEqual(proc.returncode, 0)
        self.assertIn("scratch-search", proc.stdout + proc.stderr)
        proc = self.run_search()
        self.assertEqual(proc.returncode, 2)
        self.assertIn("PATTERN is required", proc.stdout + proc.stderr)
        self.assertEqual(self.run_search("foo", results=False).returncode, 2)

    def test_default_output_is_path_first_compact_and_excludes_sidecars(self) -> None:
        proc = self.run_search("ALTSVC_NEEDLE")
        output = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, 0, output)
        for pattern in (
            r"\[scratch-1\] 2 files", r"\[scratch-2\] no matches",
            r"\[corpus\] 1 file", r"\[crashes\] 1 file",
            r"\[findings\] no matches",
            r"paths only\. Re-run with --lines --section scratch-1 for match bodies",
        ):
            with self.subTest(pattern=pattern):
                self.assertRegex(output, pattern)
        for forbidden in ("/* ALTSVC_NEEDLE", "asan.txt", "build.log", "harness-cache", str(self.results)):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, output)
        self.assertIn("scratch-1/altsvc_harness.c", output)
        self.assertLess(len(output.encode()), 3072)

    def test_filters_sidecar_opt_in_and_line_mode(self) -> None:
        filtered = self.run_search("--section", "scratch-1", "ALTSVC_NEEDLE").stdout
        self.assertIn("[scratch-1]", filtered)
        self.assertNotIn("corpus", filtered)
        self.assertIn("asan.txt", self.run_search("--include-asan", "ALTSVC_NEEDLE").stdout)
        files_only = self.run_search("--files-only", "ALTSVC_NEEDLE").stdout
        self.assertRegex(files_only, r"\[scratch-1\] 2 files")
        self.assertNotIn("/*", files_only)
        lines = self.run_search("--lines", "ALTSVC_NEEDLE").stdout
        self.assertRegex(lines, r"\[scratch-1\] 4 matches in 2 files")
        self.assertRegex(lines, r"scratch-1/altsvc_harness.c:[0-9]+:  /\* ALTSVC_NEEDLE entry point \*/")
        self.assertRegex(lines, r"\[corpus\] 1 match in 1 file")

    def test_no_matches_and_cap(self) -> None:
        proc = self.run_search("ZZZ_NEVER_THERE_ZZZ")
        self.assertEqual(proc.returncode, 1)
        self.assertRegex(proc.stdout, r"\[scratch-1\] no matches")
        (self.scratch_one / "big_match.c").write_text(
            "".join(f"line {number} ALTSVC_NEEDLE\n" for number in range(1, 51)),
            encoding="utf-8",
        )
        proc = self.run_search("--lines", "--cap", "5", "ALTSVC_NEEDLE")
        self.assertRegex(proc.stdout, r"\[scratch-1\] 54 matches")
        self.assertIn("more matches in this section", proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
