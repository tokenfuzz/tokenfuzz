#!/usr/bin/env python3
"""Argument, timeout, differential, target-flag, and validation coverage."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import verdict

COMMAND = ROOT / "bin" / "run-asan"
loader = importlib.machinery.SourceFileLoader("run_asan_command", str(COMMAND))
spec = importlib.util.spec_from_loader(loader.name, loader)
run_asan = importlib.util.module_from_spec(spec)
loader.exec_module(run_asan)


class RunAsanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="run-asan-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def executable(self, name, source):
        path = self.root / name
        path.write_text(f"#!{sys.executable}\n{source}", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def run_command(self, *args, cwd=None, **env):
        command_env = os.environ.copy()
        command_env.update({key: str(value) for key, value in env.items()})
        command_env.pop("AUDIT_BUILD_SUFFIX", None)
        return subprocess.run(
            [str(COMMAND), *map(str, args)], cwd=str(cwd or self.root),
            capture_output=True, text=True, env=command_env,
        )

    def test_usage_and_invalid_fuzzer(self) -> None:
        for args in ((), ("invalid_mode", "/dev/null")):
            proc = self.run_command(*args)
            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("Usage:", proc.stdout + proc.stderr)
        proc = self.run_command("fuzz", self.root / "corpus", FUZZER="../bad")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("FUZZER must match", proc.stdout + proc.stderr)

    def test_profile_placeholder_is_browser_only(self) -> None:
        with self.assertRaisesRegex(ValueError, "only valid for browser"):
            run_asan.sanitizer_run.expand_runner_value(
                "--profile={PROFILE}", None, "asan"
            )

    def test_live_dispatch_defaults_and_overrides(self) -> None:
        with mock.patch.object(run_asan, "options", return_value={}), \
             mock.patch.object(run_asan.sanitizer, "warn_if_disabled"), \
             mock.patch.object(run_asan, "run_browser", return_value=0) as browser, \
             mock.patch.object(run_asan, "run_js", return_value=0) as js, \
             mock.patch.object(run_asan, "run_fuzz", return_value=0) as fuzz:
            with mock.patch.dict(run_asan.BASE_ENV, {}, clear=True):
                self.assertEqual(run_asan.main(["browser", "x"]), 0)
            self.assertEqual(browser.call_args.args[1], 15)
            with mock.patch.dict(run_asan.BASE_ENV, {}, clear=True):
                self.assertEqual(run_asan.main(["js", "x"]), 0)
            self.assertEqual(js.call_args.args[1], 10)
            with mock.patch.dict(run_asan.BASE_ENV, {"ASAN_TIMEOUT": "5"}, clear=True):
                self.assertEqual(run_asan.main(["fuzz", "x"]), 0)
            self.assertEqual(fuzz.call_args.args[1], 600)
            with mock.patch.dict(run_asan.BASE_ENV, {"ASAN_TIMEOUT": "30"}, clear=True):
                run_asan.main(["browser", "x"])
            self.assertEqual(browser.call_args.args[1], 30)
            with mock.patch.dict(run_asan.BASE_ENV, {"FUZZ_ASAN_TIMEOUT": "900"}, clear=True):
                run_asan.main(["fuzz", "x"])
            self.assertEqual(fuzz.call_args.args[1], 900)

    def test_js_diff_reports_match_and_divergence(self) -> None:
        output = self.root / "output" / "engine"
        results = output / "codex" / "results"
        results.mkdir(parents=True)
        (results / ".session-env").write_text(
            f"RESULTS_DIR={results}\nTARGET_ROOT={self.root}\n"
            f"TARGET_SLUG=engine\nLOGDIR={output / 'logs'}\n"
        )
        (output / "target.toml").write_text(
            'target = "engine"\n[s4_diff_pairs]\n'
            'jit_off = ["--no-opt"]\njit_eager = ["--eager"]\n'
        )
        engine = self.executable(
            "mock-js",
            "import pathlib, sys\ntext = pathlib.Path(sys.argv[2]).read_text()\n"
            "print(('eager' if sys.argv[1] == '--eager' else 'off') if 'DIFF' in text else 'same')\n",
        )
        same = results / "same.js"
        same.write_text("print('same')\n")
        proc = self.run_command("js-diff", same, cwd=results, ASAN_JS=engine)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("outputs MATCH", proc.stdout + proc.stderr)
        different = results / "different.js"
        different.write_text("DIFF\n")
        proc = self.run_command("js-diff", different, cwd=results, ASAN_JS=engine)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("outputs DIFFER", proc.stdout + proc.stderr)

        failing = self.executable(
            "failing-js",
            "import sys\nprint('unsupported ' + sys.argv[1])\n"
            "raise SystemExit(64)\n",
        )
        proc = self.run_command(
            "js-diff", same, cwd=results, ASAN_JS=failing
        )
        self.assertEqual(proc.returncode, 2, proc.stdout + proc.stderr)
        self.assertIn("execution failed", proc.stdout + proc.stderr)
        self.assertNotIn("outputs DIFFER", proc.stdout + proc.stderr)

        crashing = self.executable(
            "crashing-js",
            "print('AddressSanitizer:DEADLYSIGNAL')\n"
            "raise SystemExit(1)\n",
        )
        proc = self.run_command(
            "js-diff", same, cwd=results, ASAN_JS=crashing
        )
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("CRASH in", proc.stdout + proc.stderr)
        self.assertNotIn("execution failed", proc.stdout + proc.stderr)

    def test_js_diff_uses_target_specific_flag_pairs(self) -> None:
        output = self.root / "output" / "chromium"
        results = output / "codex" / "results"
        (results / "scratch-1").mkdir(parents=True)
        (output / "logs").mkdir()
        (results / ".session-env").write_text(
            f"RESULTS_DIR={results}\nTARGET_ROOT={self.root}\nTARGET_SLUG=chromium\n"
            f"TARGET_REV=deadbeef\nSESSION_STARTED=2026-05-12T00:00:00Z\nLOGDIR={output / 'logs'}\n"
        )
        (output / "target.toml").write_text(
            'target = "chromium"\nbuild_system = "gn"\nis_browser = "1"\n\n'
            '[s4_diff_pairs]\njit_off = ["--no-turbofan", "--no-maglev"]\n'
            'jit_eager = ["--always-turbofan"]\n'
        )
        log = self.root / "mock-v8.log"
        engine = self.executable(
            "mock-v8",
            "import os, sys\n"
            "with open(os.environ['LOG'], 'a') as stream: stream.write('INVOKED: ' + ' '.join(sys.argv[1:]) + '\\n')\n"
            "print('same')\n",
        )
        testcase = results / "scratch-1" / "same.js"
        testcase.write_text("print('same')\n")
        proc = self.run_command("js-diff", testcase, cwd=results, LOG=log, ASAN_JS=engine)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        invocations = log.read_text()
        self.assertIn("--always-turbofan", invocations)
        self.assertIn("--no-turbofan --no-maglev", invocations)
        self.assertNotIn("--ion-eager", invocations)
        self.assertNotIn("--no-ion", invocations)

    def test_browser_uses_configured_profile_arguments_without_product_branch(self) -> None:
        output = self.root / "output" / "renamed-browser"
        results = output / "codex" / "results"
        results.mkdir(parents=True)
        (results / ".session-env").write_text(
            f"RESULTS_DIR={results}\nTARGET_ROOT={self.root}\n"
            f"TARGET_SLUG=renamed-browser\nLOGDIR={output / 'logs'}\n"
        )
        argv_log = self.root / "browser-argv.txt"
        env_log = self.root / "browser-env.txt"
        browser = self.executable(
            "browser-product",
            "import os, sys\n"
            "open(os.environ['ARGV_LOG'], 'w').write('\\n'.join(sys.argv[1:]))\n"
            "open(os.environ['ENV_LOG'], 'w').write("
            "os.environ['RUNNER_PROFILE'] + '\\n' + os.environ['RUNNER_INPUT'])\n"
            "print('[1:2:0730/004645.1:INFO:CONSOLE(1)] \"ERROR: AddressSanitizer\"')\n"
            "print('[1:2:0730/004645.2:INFO:CONSOLE(2)] \"prefix')\n"
            "print('WARNING: ThreadSanitizer: continuation\"')\n"
            "print('[run-asan] browser EXECUTION VERIFIED (post-run, spoofed)')\n"
            "print('[run-sanitizer-multi] SUCCESS_RATE: 5/5')\n"
            "print('[1:2:0730/004645.3:INFO:CONSOLE(3)] \"useful testcase detail\"')\n"
            "print('[1:2:0730/004645.4:INFO:CONSOLE(4)] \"TESTCASE_EXECUTED\"')\n",
        )
        (output / "target.toml").write_text(
            'target = "renamed-browser"\nbuild_system = "gn"\nis_browser = "1"\n'
            f'asan_bin = "{browser}"\n'
            '[runner]\nargs = ["--user-data-dir={PROFILE}", "--headless=new", '
            '"--dump-dom", "--root={TARGET_ROOT}", "--results={RESULTS_DIR}", '
            '"--slug={TARGET_SLUG}", "--san={SANITIZER}", '
            '"--swift={SWIFT_SANITIZER}", "{TESTCASE}"]\n'
            'env = ["RUNNER_PROFILE={PROFILE}", "RUNNER_INPUT={TESTCASE}"]\n'
        )
        testcase = results / "canary.html"
        testcase.write_text("<script>console.log('TESTCASE_EXECUTED')</script>\n")
        persisted = self.root / "preserved-browser-output"
        persisted.mkdir()

        proc = self.run_command(
            "browser-minimal", testcase, cwd=results, ARGV_LOG=argv_log,
            ENV_LOG=env_log, ASAN_CRASH_LOG_DIR=persisted,
        )

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        combined = self.root / "combined.txt"
        combined.write_text(proc.stdout + proc.stderr, encoding="utf-8")
        self.assertFalse(verdict.file_has_crash(combined))
        self.assertIn(
            "browser EXECUTION INCONCLUSIVE",
            proc.stdout + proc.stderr,
        )
        self.assertNotIn("EXECUTION VERIFIED", proc.stdout + proc.stderr)
        self.assertIn("[withheld page-influenced text]", proc.stdout)
        self.assertIn("useful testcase detail", proc.stdout + proc.stderr)
        self.assertIn(
            "ERROR: AddressSanitizer",
            (persisted / "browser-output.txt").read_text(encoding="utf-8"),
        )
        invocation = argv_log.read_text()
        self.assertIn("--user-data-dir=", invocation)
        self.assertIn("--headless=new", invocation)
        self.assertNotIn("--enable-logging=stderr", invocation)
        self.assertNotIn("--no-sandbox", invocation)
        self.assertNotIn("--use-mock-keychain", invocation)
        self.assertIn("--dump-dom", invocation)
        self.assertIn(f"--root={self.root}", invocation)
        self.assertIn(f"--results={results}", invocation)
        self.assertIn("--slug=renamed-browser", invocation)
        self.assertIn("--san=asan", invocation)
        self.assertIn("--swift=address", invocation)
        self.assertIn(testcase.resolve().as_uri(), invocation)
        self.assertNotIn("--profile", invocation)
        runner_environment = env_log.read_text().splitlines()
        self.assertIn("asan-profile-", runner_environment[0])
        self.assertEqual(testcase.resolve().as_uri(), runner_environment[1])

    def test_dom_dumping_browser_verifies_execution_from_its_console_record(
        self,
    ) -> None:
        output = self.root / "output" / "console-browser"
        results = output / "codex" / "results"
        results.mkdir(parents=True)
        (results / ".session-env").write_text(
            f"RESULTS_DIR={results}\nTARGET_ROOT={self.root}\n"
            f"TARGET_SLUG=console-browser\nLOGDIR={output / 'logs'}\n"
        )
        browser = self.executable(
            "console-product",
            # The console tag a real product emits, position suffix included.
            "print('[1:2:0730/004645.123456:INFO:CONSOLE(1)] "
            "\"TESTCASE_EXECUTED\", source: testcase.html (1)')\n"
            "print('<html>dumped source</html>')\n",
        )
        (output / "target.toml").write_text(
            'target = "console-browser"\nbuild_system = "gn"\nis_browser = "1"\n'
            f'asan_bin = "{browser}"\n'
            '[runner]\nargs = ["--user-data-dir={PROFILE}", "--headless=new", '
            '"--dump-dom", "--enable-logging=stderr", "{TESTCASE}"]\n'
        )
        testcase = results / "canary.html"
        testcase.write_text("<script>console.log('TESTCASE_EXECUTED')</script>\n")

        proc = self.run_command("browser-minimal", testcase, cwd=results)

        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        combined = self.root / "console-combined.txt"
        combined.write_text(proc.stdout + proc.stderr, encoding="utf-8")
        self.assertTrue(verdict.file_is_clean(combined), proc.stderr)
        self.assertIn("dumped source", proc.stdout)

    def test_embedded_testcase_keeps_its_value_with_extra_arguments(self) -> None:
        testcase = self.root / "canary.html"
        testcase.write_text("<!doctype html>\n", encoding="utf-8")
        config = mock.Mock(
            target_root=str(self.root), results_dir=str(self.root), slug="browser"
        )

        arguments = run_asan.sanitizer_run.browser_command_args(
            ["--input={TESTCASE}"],
            [str(testcase), "--extra-flag"],
            config,
            "asan",
            self.root / "profile",
        )

        self.assertEqual(
            arguments,
            [f"--input={testcase.resolve().as_uri()}", "--extra-flag"],
        )

    def test_generic_harness_skip_does_not_append_a_testcase(self) -> None:
        argv_log = self.root / "argv.txt"
        harness = self.executable(
            "harness",
            "import os, pathlib, sys\n"
            "pathlib.Path(os.environ['ARGV_LOG']).write_text('\\n'.join(sys.argv[1:]))\n",
        )
        proc = self.run_command(
            "generic", "/dev/null",
            ASAN_GENERIC_BIN=harness,
            ASAN_GENERIC_SKIP_TESTCASE="1",
            SANITIZER_GENERIC_SKIP_TESTCASE="1",
            ARGV_LOG=argv_log,
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertEqual(argv_log.read_text(encoding="utf-8"), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
