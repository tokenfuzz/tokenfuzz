#!/usr/bin/env python3
"""C++ harness cache, locking, sanitizer, config, and failure coverage."""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "bin" / "probe"
CXX = shutil.which(os.environ.get("CXX", "clang++"))
CC = shutil.which(os.environ.get("CC", "clang"))
AR = shutil.which("ar")


@unittest.skipUnless(CXX and CC and AR, "C/C++ compiler and ar are required")
class ProbeCppHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="probe-cpp-")
        self.root = Path(self.temporary.name)
        self.slug_dir = self.root / "output" / "testproject"
        self.results = self.slug_dir / "codex" / "results"
        self.scratch = self.results / "scratch-1"
        self.target = self.root / "target"
        self.logs = self.root / "logs"
        self.scratch.mkdir(parents=True)
        (self.target / "build").mkdir(parents=True)
        self.logs.mkdir()
        source = self.target / "build" / "dummy.c"
        obj = self.target / "build" / "dummy.o"
        self.library = self.target / "build" / "libtarget.a"
        source.write_text("void audit_dummy_symbol(void) {}\n")
        subprocess.run([CC, "-c", str(source), "-o", str(obj)], check=True)
        subprocess.run([AR, "rcs", str(self.library), str(obj)], check=True)
        (self.results / ".session-env").write_text(
            f"RESULTS_DIR={self.results}\nTARGET_ROOT={self.target}\nTARGET_SLUG=testproject\n"
            f"TARGET_REV=test\nLOGDIR={self.logs}\n"
        )
        (self.slug_dir / "target.toml").write_text(
            'target = "testproject"\nasan_lib = "build/libtarget.a"\n'
            'includes = []\ndefines = []\nlink_libs = []\n'
            '[sanitizer]\nenabled = ["asan"]\n'
        )
        self.harness = self.scratch / "harness.cpp"
        self.harness.write_text(
            "#include <fstream>\n#include <iostream>\n#include <string>\n"
            "int main(int argc, char **argv) { if (argc < 2) return 2;"
            " std::ifstream in(argv[1]); std::string s((std::istreambuf_iterator<char>(in)), {});"
            " std::cout << s.size() << \"\\n\"; return 0; }\n"
        )
        self.testcase = self.write_testcase("testcase.txt", "harness.cpp", "H-cpp")
        self.env = os.environ.copy()
        self.env.update(
            RESULTS_DIR=str(self.results), TARGET_ROOT=str(self.target),
            TARGET_SLUG="testproject", LOGDIR=str(self.logs), TARGET_ASAN_LIB=str(self.library),
        )
        self.env.pop("AUDIT_BUILD_SUFFIX", None)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_testcase(self, name, harness, hypothesis):
        path = self.scratch / name
        path.write_text(
            "// TARGET: native/api.cpp:Parse:1\n"
            f"// HYPOTHESIS-ID: {hypothesis}\n// CATEGORY: bounds\n"
            f"// MODE: generic\n// HARNESS: {harness}\nabc\n"
        )
        return path

    def executable(self, name, body):
        path = self.root / name
        path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def fake_compiler(self, name="fake-cxx", sleep=0, fail=False):
        return self.executable(name,
            "import os, pathlib, stat, sys, time\nargs = sys.argv[1:]\n"
            "log = os.environ.get('FAKE_CXX_ARGS')\n"
            "pathlib.Path(log).write_text('\\n'.join(args) + '\\n') if log else None\n"
            "count = os.environ.get('FAKE_CXX_COUNT')\n"
            "open(count, 'a').write('1\\n') if count else None\n"
            + ("\n".join(
                [f"print('FAKE-COMPILER-LINE-{i:03d} {i:080d}', file=sys.stderr)"
                 for i in range(1, 221)]) + "\nraise SystemExit(1)\n" if fail else
               f"time.sleep({sleep})\nout = args[args.index('-o') + 1]\n"
               f"pathlib.Path(out).write_text('#!{sys.executable}\\nprint(\"TESTCASE_EXECUTED\")\\n')\n"
               "pathlib.Path(out).chmod(pathlib.Path(out).stat().st_mode | stat.S_IXUSR)\n")
        )

    def run_probe(self, testcase=None, **env):
        command_env = self.env.copy()
        command_env.update({key: str(value) for key, value in env.items()})
        return subprocess.run(
            [str(PROBE), "--dry-run", str(testcase or self.testcase)],
            capture_output=True, text=True, env=command_env,
        )

    def test_cache_build_and_reuse(self) -> None:
        first = self.run_probe()
        self.assertEqual(first.returncode, 0, first.stdout + first.stderr)
        output = first.stdout + first.stderr
        self.assertRegex(output, r"built harness: .*harness\.cpp\..*\.bin")
        self.assertIn("mode=generic", output)
        second = self.run_probe()
        self.assertNotIn("built harness:", second.stdout + second.stderr)
        binaries = list((self.scratch / ".harness-cache").glob("harness.cpp.*.bin"))
        self.assertEqual(len([path for path in binaries if os.access(str(path), os.X_OK)]), 1)

    def test_concurrent_builds_share_lock_and_stale_locks_are_reaped(self) -> None:
        race_harness = self.scratch / "race-harness.cpp"
        race_harness.write_text("int main(int, char **) { return 0; }\n")
        testcase = self.write_testcase("race-testcase.txt", race_harness.name, "H-race")
        compiler = self.fake_compiler("slow-cxx", sleep=0.2)
        count = self.root / "count"
        env = self.env.copy()
        env.update(CXX=str(compiler), FAKE_CXX_COUNT=str(count))
        processes = [subprocess.Popen(
            [str(PROBE), "--dry-run", str(testcase)], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        ) for _ in range(2)]
        outputs = [process.communicate(timeout=15) for process in processes]
        self.assertEqual([process.returncode for process in processes], [0, 0], outputs)
        self.assertEqual(len(count.read_text().splitlines()), 1)
        binary = next((self.scratch / ".harness-cache").glob("race-harness.cpp.*.bin"))
        self.assertTrue(os.access(str(binary), os.X_OK))
        lock = Path(str(binary)[:-4] + ".lock")
        binary.unlink()
        lock.mkdir()
        (lock / "owner").write_text("pid=99999999\nstarted=2020-01-01T00:00:00+0000\n")
        proc = self.run_probe(testcase, CXX=compiler, FAKE_CXX_COUNT=count)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("reaped stale harness build lock", proc.stdout + proc.stderr)
        self.assertTrue(os.access(str(binary), os.X_OK))
        self.assertFalse(lock.exists())
        binary.unlink()
        lock.mkdir()
        proc = self.run_probe(
            testcase, CXX=compiler, FAKE_CXX_COUNT=count, PROBE_HARNESS_LOCK_STALE_MIN=0
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("reaped stale harness build lock", proc.stdout + proc.stderr)

    def test_target_defines_and_selected_sanitizer_flags_and_libraries(self) -> None:
        (self.slug_dir / "target.toml").write_text(
            'target = "testproject"\nasan_lib = "build/libtarget.a"\nincludes = ["include"]\n'
            'defines = ["-DPROBE_TARGET_DEFINE=1", "-DSECOND_DEFINE=2"]\nlink_libs = ["-lm"]\n'
            '[sanitizer]\nenabled = ["asan"]\n'
        )
        compiler = self.fake_compiler()
        args_file = self.root / "defined-args"
        proc = self.run_probe(CXX=compiler, FAKE_CXX_ARGS=args_file)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        args = args_file.read_text()
        self.assertRegex(args, r"(?m)^-DPROBE_TARGET_DEFINE=1$")
        self.assertRegex(args, r"(?m)^-DSECOND_DEFINE=2$")
        for sanitizer, upper, flag in (
            ("ubsan", "UBSAN", "undefined"), ("msan", "MSAN", "memory"),
            ("tsan", "TSAN", "thread"),
        ):
            with self.subTest(sanitizer=sanitizer):
                library = self.target / f"build-{sanitizer}" / f"libtarget-{sanitizer}.a"
                library.parent.mkdir()
                library.write_text("fake archive\n")
                args_file = self.root / f"{sanitizer}-args"
                proc = self.run_probe(
                    CXX=compiler, FAKE_CXX_ARGS=args_file, PROBE_SANITIZER=sanitizer,
                    PROBE_ALLOW_DISABLED_SANITIZER=1, **{f"TARGET_{upper}_LIB": library},
                )
                output = proc.stdout + proc.stderr
                args = args_file.read_text()
                self.assertIn(f"fsanitize={flag}", args)
                self.assertIn(library.name, args)
                self.assertIn(f"sanitizer={sanitizer}", output)
                self.assertIn(f"run-sanitizer-multi {sanitizer} generic", output)

    def test_missing_non_asan_libraries_fall_back_unless_strict(self) -> None:
        compiler = self.fake_compiler()
        for sanitizer, upper, flag in (
            ("ubsan", "UBSAN", "undefined"), ("msan", "MSAN", "memory"),
            ("tsan", "TSAN", "thread"),
        ):
            missing = self.target / f"build-{sanitizer}" / f"libtarget-{sanitizer}-MISSING.a"
            missing.parent.mkdir(exist_ok=True)
            args_file = self.root / f"missing-{sanitizer}-args"
            proc = self.run_probe(
                CXX=compiler, FAKE_CXX_ARGS=args_file, PROBE_SANITIZER=sanitizer,
                PROBE_ALLOW_DISABLED_SANITIZER=1, **{f"TARGET_{upper}_LIB": missing},
            )
            output = proc.stdout + proc.stderr
            self.assertEqual(proc.returncode, 0, output)
            self.assertIn(f"{sanitizer}_lib missing", output)
            self.assertIn(f"building with -fsanitize={flag} only", output)
            args = args_file.read_text()
            self.assertIn(f"fsanitize={flag}", args)
            self.assertNotIn(missing.name, args)
        missing = self.target / "build-ubsan" / "strict.a"
        proc = self.run_probe(
            CXX=compiler, FAKE_CXX_ARGS=self.root / "strict-args", PROBE_SANITIZER="ubsan",
            PROBE_ALLOW_DISABLED_SANITIZER=1, PROBE_REQUIRE_SANITIZER_LIB=1,
            TARGET_UBSAN_LIB=missing,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("ubsan_lib missing", proc.stdout + proc.stderr)
        proc = self.run_probe(
            CXX=compiler, FAKE_CXX_ARGS=self.root / "asan-args", PROBE_SANITIZER="asan",
            PROBE_ALLOW_DISABLED_SANITIZER=1, TARGET_ASAN_LIB=self.target / "missing-asan.a",
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("asan_lib missing", proc.stdout + proc.stderr)

    def test_traversal_and_compiler_failure_digest_and_cache(self) -> None:
        bad = self.write_testcase("bad.txt", "../harness.cpp", "H-bad")
        proc = self.run_probe(bad)
        self.assertEqual(proc.returncode, 2)
        self.assertIn("HARNESS must stay under the testcase directory", proc.stdout + proc.stderr)
        failing_harness = self.scratch / "fail-harness.cpp"
        failing_harness.write_text("int main(void) { return 0; }\n")
        testcase = self.write_testcase("fail.txt", failing_harness.name, "H-fail")
        compiler = self.fake_compiler("failing-cxx", fail=True)
        count = self.root / "failure-count"
        proc = self.run_probe(
            testcase, CXX=compiler, FAKE_CXX_COUNT=count,
            PROBE_BUILD_LOG_HEAD_BYTES=700, PROBE_BUILD_LOG_TAIL_BYTES=700,
        )
        output = proc.stdout + proc.stderr
        self.assertEqual(proc.returncode, 2)
        self.assertIn("full compiler log:", output)
        self.assertIn("compiler log elided", output)
        self.assertIn("FAKE-COMPILER-LINE-001", output)
        self.assertIn("FAKE-COMPILER-LINE-220", output)
        self.assertNotIn("FAKE-COMPILER-LINE-120", output)
        log_match = re.findall(r"full compiler log: (.+)", output)
        self.assertTrue(log_match)
        self.assertIn("FAKE-COMPILER-LINE-120", Path(log_match[-1]).read_text())
        second = self.run_probe(
            testcase, CXX=compiler, FAKE_CXX_COUNT=count,
            PROBE_BUILD_LOG_HEAD_BYTES=700, PROBE_BUILD_LOG_TAIL_BYTES=700,
        )
        self.assertEqual(second.returncode, 2)
        self.assertIn("cached harness build failure", second.stdout + second.stderr)
        self.assertEqual(len(count.read_text().splitlines()), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
