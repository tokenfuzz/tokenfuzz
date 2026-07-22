#!/usr/bin/env python3
"""Multi-run sanitizer normalization, digest, and accounting regressions."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent


class SanitizerMultiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="sanitizer-multi-")
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        shutil.copy2(ROOT / "bin" / "run-sanitizer-multi", self.bin / "run-sanitizer-multi")
        (self.root / "lib").mkdir()
        (self.root / "lib" / "stack_frames.py").symlink_to(ROOT / "lib" / "stack_frames.py")
        self.testcase = self.root / "testcase.html"
        self.testcase.write_text("<html>sample</html>\n")
        self.write_hits()
        self.write_behavior_runner()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def executable(self, name: str, body: str) -> Path:
        path = self.bin / name
        path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
        path.chmod(0o755)
        return path

    def write_hits(self, body: str = "print('HIT: sample_function')\n") -> None:
        self.executable("hits", "import sys\n" + body)

    def write_runner(self, body: str) -> None:
        self.executable("run-asan", "import os, pathlib, sys\n" + body)

    def write_behavior_runner(self) -> None:
        self.write_runner(
            """behavior = os.environ.get("MOCK_ASAN_BEHAVIOR", "clean")
if behavior == "crash":
    print("==12345==ERROR: AddressSanitizer: heap-buffer-overflow")
    print("[run-asan] CRASH DETECTED: ASan error found")
elif behavior == "noexec":
    print("[run-asan] WARNING: no crash and no execution evidence")
else:
    print("TESTCASE_EXECUTED")
    print("[run-asan] browser EXECUTION VERIFIED (post-run, marker=TESTCASE_EXECUTED)")
"""
        )

    def run_multi(
        self, mode: str | None = "browser", testcase: Path | None = None,
        *, runs: int = 1, environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        for key in (
            "WANT", "SKIP_COVERAGE_GATE", "SANITIZER_RUN_COUNTER_FILE",
            "SANITIZER_RUN_BUDGET", "TRIED_INPUTS_LOG", "SANITIZER_NO_DIGEST",
            "SANITIZER_DIGEST_HEAD", "SANITIZER_DIGEST_TAIL", "ASAN_OUTPUT_FILE",
            "SAN_OUTPUT_FILE", "ASAN_OUTPUT_FILE_OPTIONAL", "SAN_OUTPUT_FILE_OPTIONAL",
        ):
            env.pop(key, None)
        env.update({
            "SCRIPT_ROOT": str(ROOT), "SANITIZER_RUNS": str(runs),
            "ASAN_OUTPUT_FILE_OPTIONAL": "1",
        })
        if environment:
            env.update({key: str(value) for key, value in environment.items()})
        command = [sys.executable, str(self.bin / "run-sanitizer-multi"), "asan"]
        if mode is not None:
            command.append(mode)
        if testcase is not None or mode is not None:
            command.append(str(testcase or self.testcase))
        return subprocess.run(
            command, env=env, capture_output=True, text=True, timeout=60, check=False,
        )

    @staticmethod
    def output(process: subprocess.CompletedProcess) -> str:
        return process.stdout + process.stderr

    def test_clean_crash_noexec_and_inconclusive_rates(self) -> None:
        clean = self.run_multi(runs=3)
        output = self.output(clean)
        for expected in (
            "CRASH_RATE: 0/3", "EXECUTION_RATE: 3/3", "SUCCESS_RATE: 3/3", "NO CRASHES",
        ):
            self.assertIn(expected, output)
        crash = self.run_multi(runs=2, environment={"MOCK_ASAN_BEHAVIOR": "crash"})
        self.assertIn("CRASH_RATE: 2/2", self.output(crash))
        self.assertIn("CRASHES FOUND", self.output(crash))
        noexec = self.run_multi(runs=2, environment={"MOCK_ASAN_BEHAVIOR": "noexec"})
        self.assertIn("EXECUTION_RATE: 0/2", self.output(noexec))
        self.assertIn("may not have executed", self.output(noexec))

        self.write_runner(
            "print('TESTCASE_EXECUTED')\nprint('target failed', file=sys.stderr)\nraise SystemExit(7)\n"
        )
        raw = self.run_multi("generic")
        self.assertIn("EXECUTION_RATE: 0/1", self.output(raw))
        self.write_runner(
            "print('TESTCASE_EXECUTED')\n"
            "print('[run-asan] generic EXECUTION INCONCLUSIVE (post-run, rc=7)')\n"
            "raise SystemExit(7)\n"
        )
        inconclusive = self.run_multi("generic", runs=2)
        output = self.output(inconclusive)
        self.assertEqual(inconclusive.returncode, 1)
        self.assertIn("EXECUTION_RATE: 2/2", output)
        self.assertIn("SUCCESS_RATE: 0/2", output)
        self.assertIn("EXECUTION FAILED", output)

    def test_coverage_gate_miss_environment_failure_and_execution_failure(self) -> None:
        self.write_runner(
            "print('TESTCASE_EXECUTED')\n"
            "print('[run-asan] browser EXECUTION VERIFIED (post-run, marker=TESTCASE_EXECUTED)')\n"
        )
        cases = (
            (1, "MISSED — closest reached: sample_near", "MISSED", 1, False),
            (2, "NO_COVERAGE: data missing", "COVERAGE_ENV_FAIL", 0, True),
            (3, "EXEC_FAIL: coverage browser failed", "COVERAGE_EXEC_FAIL", 0, True),
        )
        for code, message, marker, expected_rc, executed in cases:
            with self.subTest(code=code):
                self.write_hits(f"print({message!r})\nraise SystemExit({code})\n")
                output_file = self.root / f"coverage-{code}.txt"
                process = self.run_multi(environment={
                    "WANT": "sample_target", "ASAN_OUTPUT_FILE": str(output_file),
                })
                output = self.output(process)
                self.assertEqual(process.returncode, expected_rc)
                self.assertIn(f"COVERAGE GATE: {marker}", output)
                self.assertEqual("TESTCASE_EXECUTED" in output, executed)
                self.assertIn(f"COVERAGE_GATE: {marker}", output_file.read_text())

    def test_output_headers_derivation_budget_validation_and_tried_log(self) -> None:
        output_file = self.root / "recorded.txt"
        process = self.run_multi(environment={"ASAN_OUTPUT_FILE": str(output_file)})
        self.assertEqual(process.returncode, 0, self.output(process))
        recorded = output_file.read_text()
        for marker in ("ASAN_RUN_HEADER", "CRASH_RATE", "EXECUTION_RATE", "SUCCESS_RATE"):
            self.assertIn(marker, recorded)

        derived_case = self.root / "derived.html"
        derived_case.write_text("sample\n")
        process = self.run_multi(
            testcase=derived_case,
            environment={"ASAN_OUTPUT_FILE_OPTIONAL": "", "SAN_OUTPUT_FILE_OPTIONAL": ""},
        )
        self.assertEqual(process.returncode, 0, self.output(process))
        self.assertTrue(derived_case.with_suffix(".asan.txt").is_file())

        counter = self.root / "counter"
        actual = self.root / "actual-runs"
        env = {
            "SANITIZER_RUN_COUNTER_FILE": str(counter),
            "SANITIZER_RUN_BUDGET": "5",
            "SANITIZER_RUNS_ACTUAL_FILE": str(actual),
        }
        process = self.run_multi(runs=2, environment=env)
        self.assertEqual(counter.read_text(), "2")
        self.assertIn("CRASH_RATE: 0/2", self.output(process))
        process = self.run_multi(runs=4, environment=env)
        self.assertEqual(counter.read_text(), "5")
        self.assertIn("CLAMPED requested=4 actual=3", self.output(process))
        self.assertIn("CRASH_RATE: 0/3", self.output(process))
        process = self.run_multi(runs=2, environment=env)
        self.assertEqual(process.returncode, 2)
        self.assertEqual(counter.read_text(), "5")
        self.assertIn("EXHAUSTED", self.output(process))
        self.assertEqual(
            sum(int(line) for line in actual.read_text().splitlines()), 5
        )

        self.assertIn("mode argument required", self.output(self.run_multi(mode=None)))
        missing = self.root / "missing.html"
        self.assertIn("testcase not found", self.output(self.run_multi(testcase=missing)))

        tried = self.root / "tried.log"
        clean = self.run_multi(environment={"TRIED_INPUTS_LOG": str(tried)})
        self.assertEqual(clean.returncode, 0)
        crash = self.run_multi(environment={
            "TRIED_INPUTS_LOG": str(tried), "MOCK_ASAN_BEHAVIOR": "crash",
        })
        self.assertIn("verdict=CLEAN", tried.read_text())
        self.assertIn("verdict=CRASH", tried.read_text())
        self.assertNotEqual(crash.returncode, 0)

    def test_digest_filters_noise_shadow_blocks_and_can_be_disabled(self) -> None:
        self.write_runner(
            """print("*** You are running in headless mode.")
print("Crash Annotation GraphicsCriticalError: RenderCompositorSWGL failed mapping default framebuffer")
print("TESTCASE_EXECUTED")
print("[run-asan] browser EXECUTION VERIFIED (post-run, marker=TESTCASE_EXECUTED)")
"""
        )
        output_file = self.root / "noise.txt"
        process = self.run_multi(environment={"ASAN_OUTPUT_FILE": str(output_file)})
        output = self.output(process)
        self.assertNotIn("headless mode", output)
        self.assertNotIn("RenderCompositorSWGL", output)
        self.assertIn("TESTCASE_EXECUTED", output)
        self.assertIn("EXECUTION VERIFIED", output)
        self.assertIn("headless mode", output_file.read_text())
        self.assertIn("RenderCompositorSWGL", output_file.read_text())
        invalid = self.run_multi(environment={
            "ASAN_OUTPUT_FILE": str(output_file), "SANITIZER_DIGEST_HEAD": "invalid",
            "SANITIZER_DIGEST_TAIL": "invalid",
        })
        invalid_output = self.output(invalid)
        self.assertIn("SANITIZER_DIGEST_HEAD must be an integer; using 80", invalid_output)
        self.assertIn("SANITIZER_DIGEST_TAIL must be an integer; using 120", invalid_output)

        self.write_runner(
            """print("==99==ERROR: AddressSanitizer: heap-buffer-overflow")
print("    #0 0x123 in sample file.cpp:42")
print("SUMMARY: AddressSanitizer: heap-buffer-overflow file.cpp:42 in sample")
print("Shadow bytes around the buggy address:")
print("  0x123: 00 00 fa fa")
print("Shadow byte legend (one shadow byte represents 8 application bytes):")
print("  Addressable: 00")
print("=" * 65)
print("==99==ERROR: AddressSanitizer: heap-use-after-free")
print("    #0 0x456 in other other.cpp:88")
print("SUMMARY: AddressSanitizer: heap-use-after-free other.cpp:88 in other")
print("Shadow bytes around the buggy address:")
print("  0x456: fd fd fd fd")
print("==99==ABORTING")
print("[run-asan] CRASH DETECTED: ASan error found")
"""
        )
        output_file = self.root / "shadow.txt"
        process = self.run_multi(environment={"ASAN_OUTPUT_FILE": str(output_file)})
        output = self.output(process)
        for expected in (
            "heap-buffer-overflow", "heap-use-after-free", "in sample file.cpp:42",
            "in other other.cpp:88", "Shadow bytes block elided", "ABORTING", "CRASH DETECTED",
        ):
            self.assertIn(expected, output)
        self.assertNotIn("00 00 fa fa", output)
        self.assertNotIn("fd fd fd fd", output)
        self.assertIn("Shadow byte legend", output_file.read_text())
        unfiltered = self.run_multi(environment={
            "ASAN_OUTPUT_FILE": str(self.root / "unfiltered.txt"), "SANITIZER_NO_DIGEST": "1",
        })
        self.assertIn("Shadow byte legend", self.output(unfiltered))

    def flood_runner(self, diagnostic: str = "", count: int = 600) -> None:
        self.write_runner(
            "print('[run-asan] generic EXECUTION VERIFIED (pre-run)')\n"
            f"for index in range(1, {count + 1}): print(f'MIDDLE_LINE_{{index}} parseJob')\n"
            + (f"print({diagnostic!r})\n" if diagnostic else "")
            + "print('TESTCASE_EXECUTED')\n"
            + ("print('[run-asan] CRASH DETECTED: sanitizer error found')\n" if diagnostic else
               "print('[run-asan] generic EXECUTION VERIFIED (post-run, rc=0)')\n")
        )

    def test_clean_digest_truncation_preserves_full_file_but_never_clips_diagnostics(self) -> None:
        self.flood_runner()
        output_file = self.root / "flood.txt"
        env = {
            "ASAN_OUTPUT_FILE": str(output_file), "SANITIZER_DIGEST_HEAD": "10",
            "SANITIZER_DIGEST_TAIL": "15",
        }
        process = self.run_multi("generic", environment=env)
        output = self.output(process)
        self.assertIn("DIGEST: clean run", output)
        self.assertIn("middle line(s) elided", output)
        self.assertIn(str(output_file), output)
        self.assertIn("MIDDLE_LINE_1 parseJob", output)
        self.assertIn("MIDDLE_LINE_600 parseJob", output)
        self.assertNotIn("MIDDLE_LINE_300 parseJob", output)
        self.assertIn("MIDDLE_LINE_300 parseJob", output_file.read_text())

        for diagnostic in (
            "==99==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            "#0 in sample file.cpp:42\nSUMMARY: AddressSanitizer: heap-buffer-overflow file.cpp:42",
            "file.cpp:42:7: runtime error: load of misaligned address 0x7f",
        ):
            with self.subTest(diagnostic=diagnostic.splitlines()[0]):
                self.flood_runner(diagnostic)
                process = self.run_multi("generic", environment=env | {
                    "ASAN_OUTPUT_FILE": str(self.root / "diagnostic.txt")
                })
                output = self.output(process)
                self.assertNotIn("DIGEST: clean run", output)
                self.assertIn("MIDDLE_LINE_300 parseJob", output)
                self.assertIn(diagnostic.splitlines()[0], output)

        self.flood_runner(count=200)
        disabled = self.run_multi("generic", environment=env | {
            "ASAN_OUTPUT_FILE": str(self.root / "disabled.txt"), "SANITIZER_DIGEST_HEAD": "0",
        })
        self.assertNotIn("DIGEST: clean run", self.output(disabled))
        self.assertIn("MIDDLE_LINE_100 parseJob", self.output(disabled))
        self.write_runner(
            "print('[run-asan] generic EXECUTION VERIFIED (pre-run)')\n"
            "print('small body line 1')\nprint('small body line 2')\nprint('TESTCASE_EXECUTED')\n"
        )
        short = self.run_multi("generic", environment=env | {
            "ASAN_OUTPUT_FILE": str(self.root / "short.txt")
        })
        self.assertNotIn("DIGEST: clean run", self.output(short))
        self.assertIn("small body line 1", self.output(short))
        self.assertIn("small body line 2", self.output(short))

    def test_differential_generic_coverage_skip_and_crash_signature_dedup(self) -> None:
        self.write_runner(
            """if len(sys.argv) > 1 and sys.argv[1] == "js-diff":
    print("[run-asan] DIFFERENTIAL: outputs DIFFER — potential JIT issue")
    raise SystemExit(1)
print("TESTCASE_EXECUTED")
print("[run-asan] browser EXECUTION VERIFIED (post-run, marker=TESTCASE_EXECUTED)")
"""
        )
        javascript = self.root / "testcase.js"
        javascript.write_text("print('TESTCASE_EXECUTED');\n")
        tried = self.root / "diff.log"
        diff = self.run_multi("js", javascript, environment={"TRIED_INPUTS_LOG": str(tried)})
        self.assertEqual(diff.returncode, 1)
        self.assertIn("DIFFERENTIAL FINDING", self.output(diff))
        self.assertIn("verdict=DIFF", tried.read_text())

        self.write_hits(
            "if 'generic' in sys.argv: print('hits should not be called', file=sys.stderr); raise SystemExit(99)\n"
            "print('HIT: sample_function')\n"
        )
        generic_case = self.root / "input.dat"
        generic_case.write_text("sample\n")
        generic = self.run_multi("generic", generic_case, environment={"WANT": "some_symbol"})
        self.assertIn("CRASH_RATE: 0/1", self.output(generic))
        self.assertNotIn("hits should not be called", self.output(generic))

        counter = self.root / "dedup-counter"
        counter.write_text("0")
        self.write_runner(
            """counter = pathlib.Path(os.environ["MOCK_RUN_COUNTER"])
run = int(counter.read_text() or "0") + 1
counter.write_text(str(run))
top = "different_top_frame" if run == int(os.environ.get("MOCK_DIVERGE_AT", "0")) else "sample::lexer::scan"
print(f"==99999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60d000{run}")
print("READ of size 1")
print(f"    #0 0x1 in {top} /tmp/sample/lexer.h:152")
print("    #1 0x2 in sample::parser::parse /tmp/sample/parser.h:284")
print("    #2 0x3 in sample::value::read /tmp/sample/value.h:6234")
print(f"SUMMARY: AddressSanitizer: heap-buffer-overflow /tmp/sample/lexer.h:152 in {top}")
print("[run-asan] CRASH DETECTED: ASan error found")
"""
        )
        env = {"MOCK_RUN_COUNTER": str(counter), "ASAN_OUTPUT_FILE": str(self.root / "dedup.txt")}
        matching = self.run_multi(runs=5, environment=env)
        output = self.output(matching)
        self.assertEqual(output.count("VERIFIED — same crash signature"), 4)
        self.assertEqual(output.count("READ of size 1"), 1)
        self.assertEqual((self.root / "dedup.txt").read_text().count("READ of size 1"), 5)
        self.assertIn("CRASH_RATE: 5/5", output)

        counter.write_text("0")
        divergent = self.run_multi(runs=5, environment=env | {"MOCK_DIVERGE_AT": "3"})
        output = self.output(divergent)
        self.assertIn("Run 3/5: DIVERGED", output)
        self.assertIn("different_top_frame", output)
        self.assertEqual(output.count("VERIFIED — same crash signature"), 3)

        counter.write_text("0")
        full = self.run_multi(runs=3, environment=env | {"SANITIZER_NO_DIGEST": "1"})
        self.assertNotIn("VERIFIED — same crash", self.output(full))
        self.assertEqual(self.output(full).count("READ of size 1"), 3)

        broken = self.root / "broken-stack-frames.py"
        broken.write_text('raise SystemExit("simulated failure")\n')
        (self.root / "lib" / "stack_frames.py").unlink()
        (self.root / "lib" / "stack_frames.py").symlink_to(broken)
        counter.write_text("0")
        fallback = self.run_multi(runs=3, environment=env)
        self.assertNotIn("VERIFIED — same crash", self.output(fallback))
        self.assertEqual(self.output(fallback).count("READ of size 1"), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
