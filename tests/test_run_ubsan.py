#!/usr/bin/env python3
"""Generic browser configuration coverage for the UBSan runner."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "run-ubsan"


class RunUbsanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="run-ubsan-")
        self.root = Path(self.temporary.name)
        self.output = self.root / "output" / "browser-product"
        self.results = self.output / "codex" / "results"
        self.results.mkdir(parents=True)
        (self.results / ".session-env").write_text(
            f"RESULTS_DIR={self.results}\nTARGET_ROOT={self.root}\n"
            f"TARGET_SLUG=browser-product\nLOGDIR={self.output / 'logs'}\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def executable(self, name: str, source: str) -> Path:
        path = self.root / name
        path.write_text(f"#!{sys.executable}\n{source}", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def run_command(self, *args: object, **environment: object) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.update({key: str(value) for key, value in environment.items()})
        env.pop("AUDIT_BUILD_SUFFIX", None)
        return subprocess.run(
            [str(COMMAND), *map(str, args)],
            cwd=self.results,
            capture_output=True,
            text=True,
            env=env,
        )

    def test_browser_uses_shared_configured_arguments_and_environment(self) -> None:
        argv_log = self.root / "browser-argv.txt"
        env_log = self.root / "browser-env.txt"
        browser = self.executable(
            "browser",
            "import os, pathlib, sys\n"
            "pathlib.Path(os.environ['ARGV_LOG']).write_text('\\n'.join(sys.argv[1:]))\n"
            "pathlib.Path(os.environ['ENV_LOG']).write_text("
            "os.environ['RUNNER_SAN'] + '\\n' + os.environ['RUNNER_PROFILE']"
            " + '\\n' + os.environ['RUNNER_INPUT'])\n"
            "print('[1:2:0730/004645.1:INFO:CONSOLE(1)] \"TESTCASE_EXECUTED\"')\n",
        )
        (self.output / "target.toml").write_text(
            'target = "browser-product"\nbuild_system = "gn"\nis_browser = "1"\n'
            '[sanitizer]\nenabled = ["ubsan"]\n'
            f'ubsan_bin = "{browser}"\n'
            '[runner]\nargs = ["--user-data-dir={PROFILE}", "--headless=new", '
            '"--root={TARGET_ROOT}", "--san={SANITIZER}", "{TESTCASE}"]\n'
            'env = ["RUNNER_SAN={SANITIZER}", "RUNNER_PROFILE={PROFILE}", '
            '"RUNNER_INPUT={TESTCASE}"]\n',
            encoding="utf-8",
        )
        testcase = self.results / "canary.html"
        testcase.write_text("<script>console.log('TESTCASE_EXECUTED')</script>\n")

        process = self.run_command(
            "browser-minimal", testcase, ARGV_LOG=argv_log, ENV_LOG=env_log
        )

        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        invocation = argv_log.read_text(encoding="utf-8")
        self.assertIn("--user-data-dir=", invocation)
        self.assertIn("--headless=new", invocation)
        self.assertNotIn("--enable-logging=stderr", invocation)
        self.assertNotIn("--no-sandbox", invocation)
        self.assertNotIn("--use-mock-keychain", invocation)
        self.assertIn(f"--root={self.root}", invocation)
        self.assertIn("--san=ubsan", invocation)
        self.assertIn(testcase.resolve().as_uri(), invocation)
        self.assertNotIn("--profile", invocation)
        runner_environment = env_log.read_text(encoding="utf-8").splitlines()
        self.assertEqual(runner_environment[0], "ubsan")
        self.assertIn("ubsan-profile-", runner_environment[1])
        self.assertEqual(testcase.resolve().as_uri(), runner_environment[2])

    def test_js_diff_requires_target_specific_pairs(self) -> None:
        engine = self.executable("js", "raise SystemExit(99)\n")
        (self.output / "target.toml").write_text(
            'target = "browser-product"\n[sanitizer]\nenabled = ["ubsan"]\n',
            encoding="utf-8",
        )
        testcase = self.results / "canary.js"
        testcase.write_text("print('same')\n", encoding="utf-8")

        process = self.run_command("js-diff", testcase, UBSAN_JS=engine)

        self.assertEqual(process.returncode, 2, process.stdout + process.stderr)
        self.assertIn("requires target.toml [s4_diff_pairs]", process.stderr)

    def test_js_diff_distinguishes_divergence_from_failed_modes(self) -> None:
        testcase = self.results / "canary.js"
        testcase.write_text("print('same')\n", encoding="utf-8")
        (self.output / "target.toml").write_text(
            'target = "browser-product"\n'
            '[sanitizer]\nenabled = ["ubsan"]\n'
            '[s4_diff_pairs]\njit_eager = ["--eager"]\n'
            'jit_off = ["--off"]\n',
            encoding="utf-8",
        )
        divergent = self.executable(
            "divergent-js",
            "import sys\n"
            "print('eager' if sys.argv[1] == '--eager' else 'off')\n",
        )

        process = self.run_command(
            "js-diff", testcase, UBSAN_JS=divergent
        )

        self.assertEqual(process.returncode, 1, process.stdout + process.stderr)
        self.assertIn("outputs DIFFER", process.stdout + process.stderr)

        failing = self.executable(
            "failing-js",
            "import sys\nprint('unsupported ' + sys.argv[1])\n"
            "raise SystemExit(64)\n",
        )
        process = self.run_command("js-diff", testcase, UBSAN_JS=failing)
        self.assertEqual(process.returncode, 2, process.stdout + process.stderr)
        self.assertIn("execution failed", process.stdout + process.stderr)
        self.assertNotIn("outputs DIFFER", process.stdout + process.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
