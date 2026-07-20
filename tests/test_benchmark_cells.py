#!/usr/bin/env python3
"""Benchmark cell launch, isolation, and lifecycle regression tests."""

from __future__ import annotations

import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import benchmark_runner
import llm_invoke


class BenchmarkCellTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="benchmark-cells-")
        self.work = Path(self.temporary.name)
        nonce = uuid.uuid4().hex
        self.slug = f"benchmark-test-target-{nonce}"
        self.target = ROOT / "targets" / self.slug
        (self.target / "build-asan").mkdir(parents=True)
        (self.target / "lib").mkdir()
        stale = self.target / "findings" / "FIND-stale"
        stale.mkdir(parents=True)
        (self.target / "target.toml").write_text(
            'target = "benchmark-test-target"\n\n'
            "[sanitizer]\n"
            "enabled = []\n\n"
            "[runner]\n"
            'bin = "/bin/true"\n'
            "args = []\n",
            encoding="utf-8",
        )
        self.helper = self.target / "build-asan" / "generated-helper"
        self.helper.write_text("#!/bin/sh\nprintf helper\n", encoding="utf-8")
        self.helper.chmod(0o644)
        (self.target / "lib" / "benchmark-visible.c").write_text(
            "int benchmark_visible;\n", encoding="utf-8"
        )
        (stale / "report.md").write_text("stale target finding\n", encoding="utf-8")
        self.created_roots: list[Path] = []

    def tearDown(self) -> None:
        shutil.rmtree(self.target, ignore_errors=True)
        for path in self.created_roots:
            shutil.rmtree(path, ignore_errors=True)
        self.temporary.cleanup()

    def executable(self, name: str, body: str) -> Path:
        path = self.work / name
        path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
        path.chmod(0o755)
        return path

    def benchmark_command(self, backend: str, bench_root: Path | str, wall: int = 5) -> list[str]:
        return [
            sys.executable,
            str(ROOT / "bin" / "benchmark"),
            "--target", self.slug,
            "--backend", backend,
            "--replicates", "1",
            "--conditions", "model-direct",
            "--budget-wall", str(wall),
            "--bench-root", str(bench_root),
        ]

    @staticmethod
    def run_command(command: list[str], environment: dict[str, str], cwd: Path | None = None):
        return subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=90,
            check=False,
        )

    def test_model_direct_backends_and_cell_isolation(self) -> None:
        fake_codex = self.executable(
            "fake-codex",
            """import json
import os
import sys
count = sys.argv[1:].count("--cd")
if count != 1:
    raise SystemExit(64)
index = sys.argv.index("--cd")
cwd = sys.argv[index + 1]
if not os.path.isabs(cwd) or not os.path.isdir(cwd):
    raise SystemExit(65)
print(json.dumps({"type": "item.completed", "usage": {
    "input_tokens": 1, "cached_input_tokens": 0, "output_tokens": 1}}))
""",
        )
        fake_claude = self.executable(
            "fake-claude-fail",
            "import json\nprint(json.dumps({'type': 'result', 'subtype': 'error_during_execution', 'is_error': True}))\nraise SystemExit(1)\n",
        )
        fake_gemini = self.executable(
            "fake-gemini",
            """import json
import os
import sys
sys.stdin.read()
name = os.environ.get("FAKE_BACKEND_RELATIVE_WRITE")
if name:
    open(name, "w", encoding="utf-8").write("contained\\n")
print(json.dumps({"id": "REC-empty", "slice": "sample", "confidence": "AUDIT-CLEAN", "notes": "clean"}))
""",
        )

        absolute_root = self.work / "codex-bench"
        relative_root = Path("output") / f"benchmark-relative-{uuid.uuid4().hex}"
        self.created_roots.append(ROOT / relative_root)
        claude_root = self.work / "claude-bench"
        gemini_root = self.work / "gemini-bench"
        unlimited_root = self.work / "gemini-unlimited"
        cli_root = self.work / "gemini-cli-unlimited"
        junk = f"benchmark-model-direct-junk-{uuid.uuid4().hex}.txt"
        self.assertFalse((ROOT / junk).exists())

        base = os.environ.copy()
        base["GEMINI_WATCHDOG_POLL_SECS"] = "1"
        cases = {
            "codex": (
                self.benchmark_command("codex", absolute_root),
                base | {"CODEX_BIN": str(fake_codex)},
                None,
            ),
            "relative": (
                self.benchmark_command("codex", relative_root),
                base | {"CODEX_BIN": str(fake_codex)},
                ROOT,
            ),
            "claude": (
                self.benchmark_command("claude", claude_root),
                base | {"CLAUDE_BIN": str(fake_claude)},
                ROOT,
            ),
            "gemini": (
                self.benchmark_command("gemini", gemini_root),
                base | {
                    "GEMINI_BIN": str(fake_gemini),
                    "FAKE_BACKEND_RELATIVE_WRITE": junk,
                },
                None,
            ),
            "unlimited": (
                self.benchmark_command("gemini", unlimited_root, wall=0),
                base | {"GEMINI_BIN": str(fake_gemini)},
                None,
            ),
            "cli": (
                self.benchmark_command("gemini", cli_root, wall=0),
                base | {
                    "GEMINI_BIN": str(fake_gemini),
                    "GEMINI_API_KEY": "fake-benchmark-key",
                    "USE_GEMINI_CLI": "1",
                },
                None,
            ),
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(cases)) as executor:
            futures = {
                name: executor.submit(self.run_command, command, environment, cwd)
                for name, (command, environment, cwd) in cases.items()
            }
            results = {name: future.result() for name, future in futures.items()}

        for name in ("codex", "relative", "gemini", "unlimited", "cli"):
            with self.subTest(name=name):
                self.assertEqual(results[name].returncode, 0, results[name].stdout)
                self.assertIn("Cells complete: 1 done, 0 failed", results[name].stdout)
        self.assertIn("refusals=0", results["codex"].stdout)
        start_marker = "benchmark-result live update (start model-direct-r1)"
        done_marker = "Cell model-direct-r1 done"
        self.assertIn(start_marker, results["codex"].stdout)
        self.assertLess(
            results["codex"].stdout.index(start_marker),
            results["codex"].stdout.index(done_marker),
        )
        self.assertEqual(self.helper.stat().st_mode & 0o777, 0o644)
        self.assertTrue((self.target / "findings" / "FIND-stale" / "report.md").is_file())
        relative_output = results["relative"].stdout
        self.assertRegex(
            relative_output,
            re.escape(f"Cell model-direct-r1 live log: {(ROOT / relative_root).resolve()}/codex/")
            + r".*/cells/model-direct-r1/backend\.raw\.log",
        )
        self.assertNotIn("live log: file://", relative_output)
        self.assertNotEqual(results["claude"].returncode, 0)
        self.assertIn("Cells complete: 0 done, 1 failed", results["claude"].stdout)
        self.assertFalse((ROOT / junk).exists())
        contained = list(gemini_root.glob(f"gemini/**/cells/model-direct-r1/{junk}"))
        self.assertEqual(len(contained), 1)
        self.assertIn("budget=unlimited", results["unlimited"].stdout)

    def test_agent_flags_harness_facade_and_cleanup(self) -> None:
        unlimited = llm_invoke.agent_flags("claude", max_turns=0, add_dirs="/tmp")
        capped = llm_invoke.agent_flags("claude", max_turns=80, add_dirs="/tmp")
        self.assertNotIn("--max-turns", unlimited)
        self.assertEqual(capped[capped.index("--max-turns") + 1], "80")

        cell = self.work / "harness-cell"
        facade = benchmark_runner.prepare_facade(cell, self.slug)
        junk = "relative-junk.txt"
        old_cwd = Path.cwd()
        try:
            os.chdir(facade)
            Path(junk).write_text("contained\n", encoding="utf-8")
        finally:
            os.chdir(old_cwd)
        self.assertFalse((ROOT / junk).exists())
        self.assertTrue((facade / junk).is_file())

        result = SimpleNamespace(returncode=0)
        with mock.patch.object(benchmark_runner, "run_timeout", return_value=result) as run_timeout, \
                mock.patch.object(benchmark_runner, "mark_target_artifacts", return_value=set()), \
                mock.patch.object(benchmark_runner, "sweep_target_artifacts"), \
                mock.patch.object(benchmark_runner, "_record_provider_quality"):
            rc, _ = benchmark_runner.run_harness(
                self.work / "launch-cell", self.slug, "codex", "",
                "sample-experiment", 1, 2,
            )
        self.assertEqual(rc, 0)
        command = run_timeout.call_args.args[0]
        kwargs = run_timeout.call_args.kwargs
        launch_facade = self.work / "launch-cell" / "repo-root"
        self.assertEqual(Path(command[0]), launch_facade / "bin" / "audit")
        self.assertEqual(kwargs["cwd"], launch_facade)
        self.assertIn("--no-refill-workers", command)

        scratch_cell = self.work / "scratch-cell"
        for relative in (
            "scratch/sub/junk.bin", "scratch-1/testcase.txt",
            "crashes/CRASH-1/report.md", "findings/FIND-1/report.md",
        ):
            path = scratch_cell / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        benchmark_runner.cleanup_model_direct_scratch(scratch_cell)
        self.assertFalse((scratch_cell / "scratch").exists())
        for relative in ("scratch-1", "crashes/CRASH-1", "findings/FIND-1"):
            self.assertTrue((scratch_cell / relative).is_dir())


if __name__ == "__main__":
    unittest.main(verbosity=2)
