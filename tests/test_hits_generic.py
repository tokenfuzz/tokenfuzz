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

import importlib.machinery
import os
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import build_config  # noqa: E402
import sanitizer  # noqa: E402
import target_config  # noqa: E402

HITS = ROOT / "bin" / "hits"

# One neutral translation unit carrying the reached function and a CLI main.
# The library half is also built alone (`libapp`) so a harness twin has the
# same library to link that bin/probe's harness would.
LIB_C = """\
int app_parse(const char *s, int n) {
    int acc = 0;
    for (int i = 0; i < n; i++) { if (s[i] == 'x') acc++; else acc--; }
    return acc;
}
"""
HARNESS_C = """\
#include <stdio.h>
int app_parse(const char *s, int n);
int main(int argc, char **argv) {
    if (argc < 2) return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 3;
    char buf[256];
    int n = (int)fread(buf, 1, sizeof buf, f);
    fclose(f);
    return app_parse(buf, n) > 0 ? 0 : 1;
}
"""
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
asan_lib = "build-asan/libapp.a"
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
        # The library both trees carry, for harness routes.
        lib_src = self.target / "lib.c"
        lib_src.write_text(LIB_C)
        self._archive(lib_src, self.plain / "libapp.a", instrumented=False)
        self._archive(lib_src, self.sibling / "libapp.a", instrumented=True)
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

    def _archive(self, src: Path, out: Path, *, instrumented: bool) -> None:
        flags = ["-g", "-O0", "-fsanitize=address", "-c"]
        if instrumented:
            flags.append("-fsanitize-coverage=trace-pc-guard")
        obj = out.with_suffix(".o")
        built = subprocess.run(
            [self.clang, *flags, "-o", str(obj), str(src)],
            capture_output=True, text=True, check=False)
        if built.returncode:
            self.skipTest(f"cannot build library fixture: {built.stderr[-200:]}")
        ar = shutil.which("ar") or shutil.which("llvm-ar")
        if not ar:
            self.skipTest("no ar to build the library fixture")
        packed = subprocess.run(
            [ar, "rcs", str(out), str(obj)], capture_output=True, text=True, check=False)
        if packed.returncode:
            self.skipTest(f"cannot archive library fixture: {packed.stderr[-200:]}")

    def _harness_route(self) -> tuple[Path, Path]:
        """bin/probe's harness route: the source and the plain-linked binary."""
        source = self.results / "scratch-1" / "harness.c"
        source.write_text(HARNESS_C)
        binary = self.results / "scratch-1" / ".harness-cache" / "harness.c.deadbeef.bin"
        binary.parent.mkdir(parents=True, exist_ok=True)
        built = subprocess.run(
            [self.clang, "-g", "-O0", "-fsanitize=address", "-o", str(binary),
             str(source), str(self.plain / "libapp.a")],
            capture_output=True, text=True, check=False)
        if built.returncode:
            self.skipTest(f"cannot build harness fixture: {built.stderr[-200:]}")
        return source, binary

    def _run_hits(
        self, want: str, *, environment: dict[str, str] | None = None,
        extra: list[str] | None = None,
    ) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.update(
            SCRIPT_ROOT=str(ROOT), TARGET_SLUG="sampleproj",
            RESULTS_DIR=str(self.results),
        )
        if environment:
            env.update(environment)
        return subprocess.run(
            [sys.executable, str(HITS), "--testcase", str(self.testcase),
             "--want", want, "--mode", "generic", "--agent", "1",
             "--slug", "sampleproj",
             "--log", str(self.results / "hits-1.log"), *(extra or [])],
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
        # and names the reached source file by the target-relative path a work
        # card carries — never a bare basename, never an absolute host path.
        journal = self.results / "coverage" / "edges-agent-1.journal"
        self.assertTrue(journal.is_file(), output)
        edges = journal.read_text()
        self.assertIn("app_parse|src.c\n", edges)
        self.assertNotIn("|/", edges)

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

    def test_sibling_without_guards_is_unavailable_not_an_env_error(self) -> None:
        # A sibling that exists but carries no __sancov_guards (e.g. a plain
        # +fuzz build predating the recipe fix) must be skipped at selection so
        # coverage reports UNAVAILABLE (rc 4, gate falls open cleanly) rather
        # than being chosen and raising in validate() (rc 2, read as env-fail).
        self._compile(self.target / "src.c", self.sibling / "app", instrumented=False)
        result = self._run_hits("app_parse")
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 4, output)
        self.assertIn("COVERAGE_UNAVAILABLE", output)
        self.assertIn("__sancov_guards", output)
        self.assertNotIn("MISSED", output)

    def test_route_override_is_unavailable_instead_of_gating_the_wrong_binary(self) -> None:
        harness = self.results / "scratch-1" / "harness"
        harness.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        harness.chmod(0o755)
        result = self._run_hits(
            "app_parse", environment={"ASAN_GENERIC_BIN": str(harness)},
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 4, output)
        self.assertIn("COVERAGE_UNAVAILABLE", output)
        self.assertIn("active sanitizer route", output)
        self.assertNotIn("HIT:", output)

    def test_a_harness_route_is_measured_through_a_coverage_twin(self) -> None:
        # bin/probe compiled the harness against the plain library; coverage
        # rebuilds that exact source against the sibling's instrumented
        # library, so the route that ran the sanitizer is the route measured.
        source, binary = self._harness_route()
        result = self._run_hits(
            "app_parse",
            environment={"ASAN_GENERIC_BIN": str(binary)},
            extra=["--harness-source", str(source)],
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("HIT: app_parse", output)
        twins = list((self.results / ".hits-cache").glob("harness.c.*.cov"))
        self.assertEqual(len(twins), 1, output)
        # Target coverage only: the harness's own frames never reach the
        # journal, so a harness file cannot rank as a subsystem.
        journal = (self.results / "coverage" / "edges-agent-1.journal").read_text()
        self.assertIn("app_parse|", journal)
        self.assertNotIn(str(self.results), journal)
        self.assertNotIn("harness.c", journal)

        # The twin is cached: a second run compiles nothing new.
        again = self._run_hits(
            "app_parse",
            environment={"ASAN_GENERIC_BIN": str(binary)},
            extra=["--harness-source", str(source)],
        )
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertEqual(
            list((self.results / ".hits-cache").glob("harness.c.*.cov")), twins)

    def test_a_harness_named_like_a_target_file_keeps_target_frames(self) -> None:
        # The fixture library is lib.c; a harness also called lib.c must not
        # cost the target's frames, only its own.
        source, binary = self._harness_route()
        collided = source.with_name("lib.c")
        source.rename(collided)
        result = self._run_hits(
            "app_parse",
            environment={"ASAN_GENERIC_BIN": str(binary)},
            extra=["--harness-source", str(collided)],
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("HIT: app_parse", output)
        journal = (self.results / "coverage" / "edges-agent-1.journal").read_text()
        self.assertIn("app_parse|lib.c", journal)
        self.assertNotIn("main|", journal)

    def test_a_harness_route_without_a_sibling_library_is_unavailable(self) -> None:
        source, binary = self._harness_route()
        (self.sibling / "libapp.a").unlink()
        result = self._run_hits(
            "app_parse",
            environment={"ASAN_GENERIC_BIN": str(binary)},
            extra=["--harness-source", str(source)],
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 4, output)
        self.assertIn("COVERAGE_UNAVAILABLE", output)
        self.assertIn("harness route harness.c", output)
        self.assertIn("bin/setup-target", output)
        self.assertNotIn("MISSED", output)

    def test_a_sibling_built_from_other_source_is_unavailable_not_a_miss(self) -> None:
        # A sibling left behind by a failed rebuild carries guards for old
        # code; replaying today's testcase against it would answer MISSED.
        with build_config.selected_suffix("+cov"):
            target_config.build_write_stamp(self.target, "asan")
        stamp = self.sibling / ".audit-build-stamp"
        lines = stamp.read_text().splitlines()
        lines[1] = "walk:0000000000000000000000000000000000000000"
        stamp.write_text("\n".join(lines) + "\n")
        result = self._run_hits("app_parse")
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 4, output)
        self.assertIn("COVERAGE_UNAVAILABLE", output)
        self.assertIn("different source", output)
        self.assertNotIn("MISSED", output)
        # The same stamp, matching the primary's, is accepted.
        target_config.build_write_stamp(self.target, "asan")
        with build_config.selected_suffix("+cov"):
            target_config.build_write_stamp(self.target, "asan")
        self.assertEqual(self._run_hits("app_parse").returncode, 0)

    def test_versioned_shared_objects_are_symbolized_against_themselves(self) -> None:
        # sancov names its dump after the module's real file, which on Linux
        # is the versioned name behind the `libx.so` symlink.
        loader = importlib.machinery.SourceFileLoader("hits_module_map", str(HITS))
        module = loader.load_module()
        tree = self.sibling / "lib"
        tree.mkdir()
        for name in ("libapp.so.1.7.18", "libapp.dylib", "libother.so", "notes.so.txt"):
            (tree / name).write_bytes(b"")
        (tree / "libapp.so").symlink_to(tree / "libapp.so.1.7.18")
        stub = SimpleNamespace(
            build=self.sibling, generic_tree=self.sibling,
            generic_binary=self.sibling / "app", args=SimpleNamespace(mode="generic"),
        )
        binaries, _ = module.Hits.binary_map(stub)
        names = sorted(path.name for path in binaries)
        self.assertEqual(
            names, ["app", "libapp.dylib", "libapp.so", "libapp.so.1.7.18", "libother.so"],
        )

    def test_an_internal_defect_is_an_environment_failure_not_a_miss(self) -> None:
        # Exit 1 means MISSED to the gate; a defect must not borrow it.
        result = subprocess.run(
            [sys.executable, "-c", (
                "import runpy, sys, unittest.mock as m\n"
                "sys.argv = ['hits', '--testcase', %r, '--want', 'app_parse',"
                " '--mode', 'generic']\n"
                "import importlib.machinery as im\n"
                "loader = im.SourceFileLoader('hits_module', %r)\n"
                "module = loader.load_module()\n"
                "with m.patch.object(module.Hits, '_resolve_generic',"
                " side_effect=KeyError('boom')):\n"
                "    raise SystemExit(module.main())\n"
            ) % (str(self.testcase), str(HITS))],
            env={**os.environ, "SCRIPT_ROOT": str(ROOT), "TARGET_SLUG": "sampleproj",
                 "RESULTS_DIR": str(self.results)},
            capture_output=True, text=True, timeout=120, check=False)
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 2, output)
        self.assertIn("KeyError", output)
        self.assertIn("internal error", output)

    def test_exact_preexpanded_arguments_do_not_pass_the_option_separator(self) -> None:
        result = self._run_hits(
            "app_parse",
            extra=["--generic-skip-testcase", "--", str(self.testcase)],
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("HIT: app_parse", output)

    def _deny_pty(self) -> Path:
        """A PYTHONPATH entry that takes the pty away from every child."""
        denied = Path(self._tmp.name) / "no-pty"
        denied.mkdir(exist_ok=True)
        (denied / "sitecustomize.py").write_text(
            "import pty\n"
            "def _denied(*args, **kwargs):\n"
            "    raise OSError(23, 'out of pty devices')\n"
            "pty.fork = _denied\n"
        )
        return denied

    def _counting_atos(self) -> tuple[Path, Path]:
        """An `atos` earlier on PATH that records how often it is executed."""
        shim = Path(self._tmp.name) / "atos-shim"
        shim.mkdir(exist_ok=True)
        calls = shim / "calls"
        real = shutil.which("atos")
        if not real:
            self.skipTest("no atos on this host")
        (shim / "atos").write_text(
            f'#!/bin/sh\necho call >> "{calls}"\nexec "{real}" "$@"\n')
        (shim / "atos").chmod(0o755)
        return shim, calls

    def test_a_shell_without_a_pty_symbolizes_coverage_in_one_atos_call(self) -> None:
        """Coverage asks atos once per module, never once per address.

        The shared symbolizer drives atos one address at a time through a pty.
        A sandboxed agent shell can be denied one, and the per-address fallback
        then spends a process per PC; a coverage run has hundreds, which
        overran the symbolizer's 60s budget and left every probe reporting no
        coverage at all. Both host properties are constructed rather than
        sampled: a host that grants a pty would never reach the fallback, and
        counting real processes is what separates one batched call from one
        call per address.
        """
        if sys.platform != "darwin":
            self.skipTest("atos, and this fallback, are macOS-only")
        shim, calls = self._counting_atos()
        result = self._run_hits("app_parse", environment={
            "PYTHONPATH": str(self._deny_pty()),
            "PATH": f"{shim}:{os.environ['PATH']}",
        })
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        self.assertIn("HIT: app_parse", output)
        # The reached edge still lands in the journal ranking consumes.
        journal = self.results / "coverage" / "edges-agent-1.journal"
        self.assertIn("app_parse|src.c\n", journal.read_text())
        # One module in this fixture, so exactly one atos execution. The
        # per-address fallback runs as many as the binary has guards.
        self.assertEqual(calls.read_text().count("call"), 1, output)

    def test_a_wedged_symbolizer_cannot_hang_the_run(self) -> None:
        """The batched call must not outlive the deadline the old path had.

        The coverage gate has no outer deadline of its own, so an unbounded
        symbolizer call hangs the whole audit rather than one probe. Falling
        back to the shared path on a deadline would wedge on the same tool for
        a second budget, so a deadline ends symbolization instead.
        """
        if sys.platform != "darwin":
            self.skipTest("the batched call is the macOS atos path")
        shim = Path(self._tmp.name) / "wedged-atos"
        shim.mkdir(exist_ok=True)
        (shim / "atos").write_text("#!/bin/sh\nsleep 600\n")
        (shim / "atos").chmod(0o755)
        loader = importlib.machinery.SourceFileLoader("hits_module_wedge", str(HITS))
        module = loader.load_module()
        with mock.patch.dict(os.environ, {"PATH": f"{shim}:{os.environ['PATH']}"}), \
                mock.patch.object(sys, "platform", "darwin"), \
                mock.patch.object(module.sanitizer, "SYMBOLIZE_TIMEOUT_SECONDS", 2):
            started = time.monotonic()
            lines, timed_out = module.Hits._batch_atos({"/bin/app": ["0x1"]}, "arm64")
            elapsed = time.monotonic() - started
        self.assertTrue(timed_out)
        self.assertIsNone(lines)
        self.assertLess(elapsed, 60, "the call ran past its own deadline")

    def test_an_atos_answer_that_does_not_line_up_is_declined_not_mispaired(self) -> None:
        """A short answer list must not shift every address onto a later name.

        Positional mapping is the whole economy of the batched call, so the
        one thing it may never do is pair an address with another address's
        answer. Declining returns None and the caller keeps the shared path.
        """
        loader = importlib.machinery.SourceFileLoader("hits_module_atos", str(HITS))
        module = loader.load_module()
        shim = Path(self._tmp.name) / "short-atos"
        shim.mkdir(exist_ok=True)
        (shim / "atos").write_text(
            '#!/bin/sh\necho "only_one (in mod) (/src/a.c:1)"\n')
        (shim / "atos").chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": f"{shim}:{os.environ['PATH']}"}), \
                mock.patch.object(sys, "platform", "darwin"):
            declined, declined_timeout = module.Hits._batch_atos(
                {"/bin/app": ["0x1", "0x2"]}, "arm64")
            paired, paired_timeout = module.Hits._batch_atos(
                {"/bin/app": ["0x1"]}, "arm64")
        # Declining is not a deadline: the caller still tries the shared path.
        self.assertIsNone(declined)
        self.assertFalse(declined_timeout)
        self.assertEqual(paired, ["only_one", "/src/a.c:1"])
        self.assertFalse(paired_timeout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
