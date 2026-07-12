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
        engine = self.executable(
            "mock-js",
            "import pathlib, sys\ntext = pathlib.Path(sys.argv[2]).read_text()\n"
            "print(('ion' if sys.argv[1] == '--ion-eager' else 'noion') if 'DIFF' in text else 'same')\n",
        )
        same = self.root / "same.js"
        same.write_text("print('same')\n")
        proc = self.run_command("js-diff", same, ASAN_JS=engine)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("outputs MATCH", proc.stdout + proc.stderr)
        different = self.root / "different.js"
        different.write_text("DIFF\n")
        proc = self.run_command("js-diff", different, ASAN_JS=engine)
        self.assertEqual(proc.returncode, 1)
        self.assertIn("outputs DIFFER", proc.stdout + proc.stderr)

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
