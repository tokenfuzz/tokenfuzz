#!/usr/bin/env python3
"""tests/test_hits_generic.py — native execution coverage via `bin/hits --mode generic`.

The property, constructed rather than sampled: a target's configured binary,
rebuilt with SanitizerCoverage in a sibling tree, replays a testcase and reports
which source files it reached — as HIT rows and an edge journal — without
touching the shared `build-<san>` tree or the source signature it is measured
against. When no instrumented sibling exists, coverage is reported unavailable
(never a miss).

Builds its own trace-pc-guard binary with the harness's own clang discovery and
skips loudly when no capable toolchain is present.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import sanitizer  # noqa: E402
import target_config  # noqa: E402

HITS = ROOT / "bin" / "hits"

# One neutral translation unit carrying the reached function and a CLI main.
APP_C = """\
#include <stdio.h>
#include <stdlib.h>
int app_parse(const char *s, int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) { if (s[i] == 'x') acc++; else acc--; }
    return acc;
}
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 3;
    char buf[256];
    int n = (int)fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n == 0) return 0;
    return app_parse(buf, n) > 0 ? 0 : 1;
}
"""

TARGET_TOML = """\
target = "sampleproj"
upstream_url = "https://example.invalid/sampleproj"
build_system = "cmake"
asan_bin = "build-asan/app"
is_browser = "0"
[threat_model]
attacker_controls = ["bytes"]
[sanitizer]
enabled = ["asan"]
"""


def _tool(name: str) -> str:
    found = sanitizer.llvm_tool(name)
    return found if (os.access(found, os.X_OK) or shutil.which(found)) else ""


def _has_guards(binary: Path) -> bool:
    """Whether the compiler actually emitted trace-pc-guard instrumentation."""
    if sys.platform == "darwin":
        completed = subprocess.run(
            ["otool", "-l", str(binary)], capture_output=True, text=True, check=False)
    else:
        tool = shutil.which("readelf") or shutil.which("llvm-readelf") or shutil.which("objdump")
        if not tool:
            return False
        completed = subprocess.run(
            [tool, "-S" if "readelf" not in Path(tool).name else "-WS", str(binary)],
            capture_output=True, text=True, check=False)
    return "__sancov_guards" in (completed.stdout + completed.stderr)


class GenericCoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clang = _tool("clang")
        if not self.clang:
            self.skipTest("no clang for trace-pc-guard instrumentation")
        if not _tool("sancov"):
            self.skipTest("no sancov tool (install LLVM, or set LLVM_PREFIX)")
        if not sanitizer.symbolize_available():
            self.skipTest("no offline symbolizer (atos/llvm-symbolizer/addr2line)")
        import tempfile
        self._tmp = tempfile.TemporaryDirectory(prefix="hits-generic-")
        root = Path(self._tmp.name)
        self.target = root / "target"
        self.results = root / "output" / "sampleproj" / "codex" / "results"
        (self.results / "scratch-1").mkdir(parents=True)
        (self.results / "state").mkdir(parents=True)
        src = self.target / "src.c"
        self.target.mkdir(parents=True, exist_ok=True)
        # Native-build scaffolding so build_freshness has a real tree + recipe.
        (self.target / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.16)\n")
        (self.target / "main.c").write_text("int main(void){return 0;}\n")
        (self.target / ".audit").mkdir()
        (self.target / ".audit" / "build.sh").write_text("#!/bin/sh\n")
        src.write_text(APP_C)

        self.plain = self.target / "build-asan"
        self.sibling = self.target / "build-asan+cov"
        self.plain.mkdir()
        self.sibling.mkdir()
        # Plain build: exists so the config resolves and the tree is stampable.
        self._compile(src, self.plain / "app", instrumented=False)
        # Instrumented sibling: what generic coverage actually reads.
        self._compile(src, self.sibling / "app", instrumented=True)
        if not _has_guards(self.sibling / "app"):
            self.skipTest("this clang did not emit trace-pc-guard (__sancov_guards)")

        (root / "output" / "sampleproj" / "target.toml").write_text(TARGET_TOML)
        (self.results / ".session-env").write_text(
            f"RESULTS_DIR={self.results}\n"
            f"TARGET_ROOT={self.target}\n"
            "TARGET_SLUG=sampleproj\n"
            f"LOGDIR={self.results.parent / 'logs'}\n"
        )
        self.testcase = self.results / "scratch-1" / "tc.txt"
        self.testcase.write_bytes(b"xxxxxxxx")
        target_config.build_write_stamp(self.target, "asan")

    def tearDown(self) -> None:
        if hasattr(self, "_tmp"):
            self._tmp.cleanup()

    def _compile(self, src: Path, out: Path, *, instrumented: bool) -> None:
        flags = ["-g", "-O0"]
        if instrumented:
            flags += ["-fsanitize=address", "-fsanitize-coverage=trace-pc-guard"]
        else:
            flags += ["-fsanitize=address"]
        built = subprocess.run(
            [self.clang, *flags, "-o", str(out), str(src)],
            capture_output=True, text=True, check=False)
        if built.returncode:
            self.skipTest(f"cannot build instrumented fixture: {built.stderr[-200:]}")

    def _run_hits(self, want: str) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.update(
            SCRIPT_ROOT=str(ROOT), TARGET_SLUG="sampleproj",
            RESULTS_DIR=str(self.results),
        )
        return subprocess.run(
            [sys.executable, str(HITS), "--testcase", str(self.testcase),
             "--want", want, "--mode", "generic", "--agent", "1",
             "--slug", "sampleproj",
             "--log", str(self.results / "hits-1.log")],
            env=env, capture_output=True, text=True, timeout=120, check=False)

    def test_generic_coverage_writes_hit_rows_and_edges(self) -> None:
        before_sig = target_config.source_signature(self.target)
        before_fresh = target_config.build_freshness(self.target, "asan")

        result = self._run_hits("app_parse")
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("HIT: app_parse", output)

        # A HIT row landed in the per-agent journal promote_corpus reads.
        hits_log = (self.results / "hits-1.log").read_text()
        self.assertRegex(hits_log, r"^HIT: .* frame=app_parse", )
        self.assertRegex(hits_log, r"edges=[1-9]")

        # The edge journal coverage_gap_score/coverage-summary consume exists
        # and names the reached source file.
        journal = self.results / "coverage" / "edges-agent-1.journal"
        self.assertTrue(journal.is_file(), output)
        edges = journal.read_text()
        self.assertIn("app_parse|", edges)

        # The shared build was neither touched nor made to look stale.
        self.assertEqual(target_config.source_signature(self.target), before_sig)
        self.assertEqual(target_config.build_freshness(self.target, "asan"), before_fresh)
        self.assertEqual(before_fresh, "fresh")

    def test_missing_symbol_is_a_miss_not_an_error(self) -> None:
        result = self._run_hits("symbol_never_defined_anywhere")
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 1, output)
        self.assertIn("MISSED", output)

    def test_absent_sibling_reports_unavailable_never_a_miss(self) -> None:
        shutil.rmtree(self.sibling)
        result = self._run_hits("app_parse")
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 4, output)
        self.assertIn("COVERAGE_UNAVAILABLE", output)
        self.assertNotIn("MISSED", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
