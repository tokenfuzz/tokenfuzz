#!/usr/bin/env python3
"""End-to-end coverage for feature-sentinel routing to sibling builds."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "bin" / "probe"
ROUTES = ROOT / "lib" / "build_routes.py"


class ProbeAutoRouteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="probe-route-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.results = self.root / "results"
        self.logs = self.root / "logs"
        for path in (
            self.target / "build-asan" / "bin",
            self.target / "build-asan-jit" / "bin",
            self.target / "build-asan-empty" / "bin",
            self.results / "scratch-1", self.results / "crashes",
            self.results / "crashes-rejected", self.results / "findings", self.logs,
        ):
            path.mkdir(parents=True)
        self.canonical = self.target / "build-asan" / "bin" / "myrunner"
        self.sibling = self.target / "build-asan-jit" / "bin" / "myrunner"
        self.write_runner(self.canonical, False)
        self.write_runner(self.sibling, True)
        (self.target / "target.toml").write_text(
            'target = "testproject"\n'
            'upstream_url = "https://example.invalid/testproject"\n'
            'build_system = "make"\n'
            'asan_bin = "build-asan/bin/myrunner"\n'
            'is_browser = "0"\n'
            '[threat_model]\nattacker_controls = ["bytes"]\n'
            '[sanitizer]\nenabled = ["asan"]\n',
            encoding="utf-8",
        )
        (self.results / ".session-env").write_text(
            f'export RESULTS_DIR="{self.results}"\n'
            f'export TARGET_ROOT="{self.target}"\n'
            'export TARGET_SLUG="testproject"\n',
            encoding="utf-8",
        )
        self.testcase = self.results / "scratch-1" / "tc.txt"
        self.testcase.write_text(
            "// TARGET: src/pcre2_jit_compile.c:compile:42\n"
            "// HYPOTHESIS-ID: H-route\n// CATEGORY: state\n// MODE: generic\n",
            encoding="utf-8",
        )
        self.env = os.environ.copy()
        self.env.update(
            RESULTS_DIR=str(self.results), TARGET_ROOT=str(self.target),
            TARGET_SLUG="testproject", LOGDIR=str(self.logs),
            ASAN_GENERIC_BIN=str(self.canonical), PROBE_SANITIZER="asan",
            LLM_DECIDE_DISABLE="1",
        )
        self.env.pop("AUDIT_BUILD_SUFFIX", None)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_runner(self, path: Path, succeeds: bool) -> None:
        if succeeds:
            lines = "print('myrunner v1.0 (JIT enabled)')\nprint('OK: pattern executed')\n"
        else:
            lines = (
                "print('myrunner v1.0')\n"
                "print('FAIL: No just-in-time compiler support')\nraise SystemExit(1)\n"
            )
        path.write_text(f"#!{sys.executable}\n{lines}", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)

    def route_cli(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(ROUTES), *args], capture_output=True, text=True
        )

    def run_probe(self, **env) -> subprocess.CompletedProcess:
        command_env = self.env.copy()
        command_env.update(env)
        return subprocess.run(
            [str(PROBE), str(self.testcase)], capture_output=True, text=True, env=command_env
        )

    def test_sentinel_and_enumeration(self) -> None:
        output = self.root / "canonical.out"
        proc = subprocess.run([str(self.canonical)], capture_output=True, text=True)
        output.write_text(proc.stdout + proc.stderr, encoding="utf-8")
        self.assertEqual(self.route_cli("sentinel", str(output)).returncode, 0)
        proc = self.route_cli("enumerate", str(self.target), str(self.canonical))
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("build-asan-jit/bin/myrunner", proc.stdout)
        self.assertNotIn("build-asan-empty", proc.stdout)
        self.assertNotIn("build-asan/bin/myrunner", proc.stdout)

    def test_probe_routes_and_caches_the_working_sibling(self) -> None:
        proc = self.run_probe()
        output = proc.stdout + proc.stderr
        self.assertRegex(output, r"(?m)^\[probe\] ROUTED: ")
        self.assertIn("build-asan-jit/bin/myrunner", output)
        cache = self.results / "build-routes.jsonl"
        self.assertGreater(cache.stat().st_size, 0)
        proc = self.route_cli(
            "lookup", str(self.results), "file:src/pcre2_jit_compile.c"
        )
        self.assertIn("build-asan-jit/bin/myrunner", proc.stdout)

    def test_disable_switch_and_route_miss(self) -> None:
        proc = self.run_probe(PROBE_AUTO_ROUTE="0")
        self.assertNotIn("ROUTED", proc.stdout + proc.stderr)
        cache = self.results / "build-routes.jsonl"
        if cache.exists():
            cache.unlink()
        self.write_runner(self.sibling, False)
        proc = self.run_probe(PROBE_AUTO_ROUTE="1")
        output = proc.stdout + proc.stderr
        self.assertIn("ROUTE_MISS", output)
        self.assertIsNone(__import__("re").search(r"(?m)^\[probe\] ROUTED:", output))


if __name__ == "__main__":
    unittest.main(verbosity=2)
