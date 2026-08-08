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
import build_preflight
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
            f'bin = "{sys.executable}"\n'
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

    def benchmark_command(
        self, backend: str, bench_root: Path | str, wall: int = 5,
        agent_security: str = "",
    ) -> list[str]:
        command = [
            sys.executable,
            str(ROOT / "bin" / "benchmark"),
            "--target", self.slug,
            "--backend", backend,
            "--replicates", "1",
            "--conditions", "model-direct",
            "--budget-wall", str(wall),
            "--bench-root", str(bench_root),
        ]
        if agent_security:
            command += ["--agent-security", agent_security]
        return command

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
stdin_prompt = sys.stdin.read()
prompt_index = sys.argv.index("-p")
prompt_arg = sys.argv[prompt_index + 1]
if "--approval-mode=yolo" in sys.argv:
    if prompt_arg or not stdin_prompt:
        raise SystemExit(64)
elif not prompt_arg or stdin_prompt:
    raise SystemExit(65)
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
                self.benchmark_command(
                    "gemini", gemini_root, agent_security="external-bypass",
                ),
                base | {
                    "GEMINI_BIN": str(fake_gemini),
                    "FAKE_BACKEND_RELATIVE_WRITE": junk,
                    "IS_SANDBOX": "1",
                },
                None,
            ),
            "unlimited": (
                self.benchmark_command(
                    "gemini", unlimited_root, wall=0,
                    agent_security="external-bypass",
                ),
                base | {"GEMINI_BIN": str(fake_gemini), "IS_SANDBOX": "1"},
                None,
            ),
            "cli": (
                self.benchmark_command(
                    "gemini", cli_root, wall=0, agent_security="external-bypass",
                ),
                base | {
                    "GEMINI_BIN": str(fake_gemini),
                    "GEMINI_API_KEY": "fake-benchmark-key",
                    "USE_GEMINI_CLI": "1",
                    "IS_SANDBOX": "1",
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
        direct_cells = list(absolute_root.glob("codex/**/cells/model-direct-r1"))
        self.assertEqual(len(direct_cells), 1)
        self.assertFalse((direct_cells[0] / ".git").exists())
        self.assertIn("budget=unlimited", results["unlimited"].stdout)

    def test_a_crash_free_cell_is_excluded_when_its_runner_changes(self) -> None:
        runner = self.target / "target-runner"
        runner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        runner.chmod(0o755)
        (self.target / "target.toml").write_text(
            'target = "benchmark-test-target"\n'
            "[sanitizer]\nenabled = []\n"
            '[runner]\nbin = "target-runner"\nargs = []\n',
            encoding="utf-8",
        )
        fake_codex = self.executable(
            "fake-codex-build-drift",
            """import json
import os
from pathlib import Path
Path(os.environ["MUTATE_RUNNER"]).write_text("#!/bin/sh\\nexit 1\\n", encoding="utf-8")
print(json.dumps({"type": "item.completed", "usage": {
    "input_tokens": 1, "cached_input_tokens": 0, "output_tokens": 1}}))
""",
        )
        bench_root = self.work / "build-drift-bench"
        process = self.run_command(
            self.benchmark_command("codex", bench_root),
            os.environ | {
                "CODEX_BIN": str(fake_codex),
                "MUTATE_RUNNER": str(runner),
            },
        )
        self.assertNotEqual(process.returncode, 0, process.stdout)
        cells = list(bench_root.glob("codex/*/cells/model-direct-r1/cell.json"))
        self.assertEqual(len(cells), 1)
        cell = json.loads(cells[0].read_text(encoding="utf-8"))
        self.assertEqual(cell["status"], "incomplete")
        self.assertEqual(cell["run_quality"], "build_drift")
        self.assertIn("runner_bin changed", process.stdout)

    def test_same_backend_runs_share_one_root_concurrently(self) -> None:
        runner = self.target / "target-runner"
        runner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        runner.chmod(0o755)
        (self.target / "target.toml").write_text(
            'target = "benchmark-test-target"\n'
            "[sanitizer]\nenabled = []\n"
            '[runner]\nbin = "target-runner"\nargs = []\n',
            encoding="utf-8",
        )
        fake_codex = self.executable(
            "fake-codex-parallel",
            """import json
print(json.dumps({"type": "item.completed", "usage": {
    "input_tokens": 1, "cached_input_tokens": 0, "output_tokens": 1}}))
""",
        )
        bench_root = self.work / "same-backend"
        commands = []
        for run_id in ("parallel-a", "parallel-b", "parallel-c"):
            commands.append(
                self.benchmark_command("codex", bench_root)
                + ["--run-id", run_id, "--no-validate-findings"]
            )
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [
                executor.submit(
                    self.run_command, command,
                    os.environ | {"CODEX_BIN": str(fake_codex)},
                )
                for command in commands
            ]
            completed = [future.result() for future in futures]
        for process in completed:
            self.assertEqual(process.returncode, 0, process.stdout)
        ledger = (
            bench_root / "codex" / "benchmark-results.md"
        ).read_text(encoding="utf-8")
        for run_id in ("parallel-a", "parallel-b", "parallel-c"):
            self.assertIn(run_id, ledger)

    def test_parallel_runs_never_claim_another_cells_target_artifact(self) -> None:
        fake_codex = self.executable(
            "fake-codex-ambiguous-artifact",
            """import json
import os
import time
from pathlib import Path
finding = Path(os.environ["MISPLACED_TARGET"]) / "findings" / f"FIND-{os.getpid()}"
finding.mkdir(parents=True)
(finding / "report.md").write_text("misplaced\\n", encoding="utf-8")
time.sleep(0.5)
print(json.dumps({"type": "item.completed", "usage": {
    "input_tokens": 1, "cached_input_tokens": 0, "output_tokens": 1}}))
""",
        )
        bench_root = self.work / "ambiguous-target-artifacts"
        commands = [
            self.benchmark_command("codex", bench_root)
            + ["--run-id", run_id, "--no-validate-findings"]
            for run_id in ("parallel-a", "parallel-b")
        ]
        environment = os.environ | {
            "CODEX_BIN": str(fake_codex),
            "MISPLACED_TARGET": str(self.target),
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            completed = [
                future.result()
                for future in (
                    executor.submit(self.run_command, command, environment)
                    for command in commands
                )
            ]
        for process in completed:
            self.assertNotEqual(process.returncode, 0, process.stdout)
        cells = list(bench_root.glob(
            "codex/parallel-*/cells/model-direct-r1/cell.json"
        ))
        self.assertEqual(len(cells), 2)
        for cell_json in cells:
            cell = json.loads(cell_json.read_text(encoding="utf-8"))
            self.assertEqual(cell["status"], "incomplete")
            self.assertFalse(
                any(
                    path.name.startswith("FIND-")
                    for path in cell_json.parent.glob("findings/FIND-*")
                )
            )
        self.assertEqual(
            len(list((self.target / "findings").glob("FIND-*"))),
            3,
            "the stale artifact and both ambiguous artifacts stay unassigned",
        )

    def test_a_failed_cell_stays_failed_when_it_leaks_an_artifact(self) -> None:
        fake_codex = self.executable(
            "fake-codex-failed-artifact",
            """import json
import os
from pathlib import Path
finding = Path(os.environ["MISPLACED_TARGET"]) / "findings" / "FIND-failed"
finding.mkdir(parents=True)
print(json.dumps({"type": "item.completed", "usage": {
    "input_tokens": 1, "cached_input_tokens": 0, "output_tokens": 1}}))
raise SystemExit(23)
""",
        )
        bench_root = self.work / "failed-target-artifact"
        process = self.run_command(
            self.benchmark_command("codex", bench_root)
            + ["--run-id", "failed-artifact", "--no-validate-findings"],
            os.environ | {
                "CODEX_BIN": str(fake_codex),
                "MISPLACED_TARGET": str(self.target),
            },
        )
        self.assertNotEqual(process.returncode, 0, process.stdout)
        cell_path = (
            bench_root / "codex" / "failed-artifact" / "cells"
            / "model-direct-r1" / "cell.json"
        )
        cell = json.loads(cell_path.read_text(encoding="utf-8"))
        self.assertEqual(cell["status"], "failed")
        self.assertEqual(cell["run_quality"], "unowned_artifacts")

    def test_facades_use_the_run_config_snapshot(self) -> None:
        run = self.work / "snapshot-run"
        snapshot = benchmark_runner._snapshot_benchmark_config(
            run, self.target, self.slug, replace=True,
        )
        original = snapshot.read_bytes()
        (self.target / "target.toml").write_text(
            'target = "changed-live-config"\n', encoding="utf-8",
        )
        first = benchmark_runner.prepare_facade(
            self.work / "snapshot-cell-1", self.slug, snapshot,
        )
        second = benchmark_runner.prepare_facade(
            self.work / "snapshot-cell-2", self.slug, snapshot,
        )
        for facade in (first, second):
            self.assertEqual(
                (facade / "output" / self.slug / "target.toml").read_bytes(),
                original,
            )

    def test_agent_flags_harness_facade_and_cleanup(self) -> None:
        unlimited = llm_invoke.agent_flags("claude", max_turns=0, add_dirs="/tmp")
        capped = llm_invoke.agent_flags("claude", max_turns=80, add_dirs="/tmp")
        self.assertNotIn("--max-turns", unlimited)
        self.assertEqual(capped[capped.index("--max-turns") + 1], "80")

        cell = self.work / "harness-cell"
        # Facade preparation is backend-neutral. Backends needing an on-disk
        # boundary stage it immediately before their process launch.
        with mock.patch.dict(os.environ, {"PATH": "/tokenfuzz/no-git-here"}):
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
        self.assertFalse((facade / ".git").exists())

        result = SimpleNamespace(returncode=0)
        with mock.patch.object(benchmark_runner, "run_timeout", return_value=result) as run_timeout, \
                mock.patch.object(benchmark_runner, "mark_target_artifacts", return_value=set()), \
                mock.patch.object(benchmark_runner, "_record_provider_quality"):
            rc, _ = benchmark_runner.run_harness(
                self.work / "launch-cell", self.slug, "codex", "",
                "sample-experiment", 1, 2, {"version": 1},
            )
        self.assertEqual(rc, 0)
        command = run_timeout.call_args.args[0]
        kwargs = run_timeout.call_args.kwargs
        launch_facade = self.work / "launch-cell" / "repo-root"
        self.assertEqual(Path(command[0]), launch_facade / "bin" / "audit")
        self.assertEqual(kwargs["cwd"], launch_facade)
        self.assertNotIn("--no-refill-workers", command)
        self.assertEqual(
            command[command.index("--agent-security") + 1], "sandboxed",
        )
        self.assertEqual(
            json.loads(
                kwargs["env"][build_preflight.BENCHMARK_BUILD_PIN_ENV]
            ),
            {"version": 1},
        )

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
