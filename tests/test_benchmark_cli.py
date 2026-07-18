#!/usr/bin/env python3
"""Public benchmark CLI and orchestration lifecycle regressions."""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import benchmark
import benchmark_runner


class BenchmarkCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="benchmark-cli-")
        self.root = Path(self.temporary.name)
        self.bench_root = self.root / "benchmark"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cli(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["LLM_DECIDE_DISABLE"] = "1"
        return subprocess.run(
            [sys.executable, str(ROOT / "bin" / "benchmark"), *arguments],
            cwd=ROOT,
            env=environment,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=120,
            check=False,
        )

    def test_public_cli_rejects_invalid_arguments(self) -> None:
        cases = (
            (("--dry-run",), "--target is required"),
            (("--target", "sample", "--replicates", "0"), "must be >= 1"),
            (("--target", "sample", "--replicates", "many"), "positive integer"),
            (("--target", "sample", "--budget-wall", "-1"), "must be >= 0"),
            (("--target", "sample", "--agents", "0"), "must be >= 1"),
            (("--target", "sample", "--conditions", "unknown", "--dry-run"), "unknown condition"),
            (("--target", "sample", "--unknown-option"), "unrecognized arguments"),
            (("--target", " , ", "--dry-run"), "must contain at least one non-empty slug"),
        )
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                result = self.run_cli(*arguments, "--bench-root", str(self.bench_root))
                self.assertNotEqual(result.returncode, 0, result.stdout)
                self.assertIn(expected, result.stdout)

    def test_dry_run_resume_regenerate_and_atomic_pool_lifecycle(self) -> None:
        targets = ("samples/sample-python", "samples/sample-rust")
        base = (
            "--target", ", ".join(targets),
            "--backend", "codex",
            "--replicates", "1",
            "--conditions", "model-direct,harness",
            "--agents", "2",
            "--skip-recon",
            "--dry-run",
            "--run-id", "lifecycle",
            "--bench-root", str(self.bench_root),
        )
        first = self.run_cli(*base)
        self.assertEqual(first.returncode, 0, first.stdout)
        self.assertIn("Multi-target complete: 2/2 target(s) succeeded", first.stdout)

        run_dirs = []
        for target in targets:
            run = (
                self.bench_root
                / "codex"
                / f"lifecycle-{benchmark_runner.target_key(target)}"
            )
            run_dirs.append(run)
            metadata = json.loads((run / "run.json").read_text(encoding="utf-8"))
            self.assertEqual(metadata["target"], target)
            self.assertEqual(metadata["harness_agents"], 2)
            self.assertTrue(metadata["skip_recon"])
            self.assertTrue((run / "cells/model-direct-r1/cell.json").is_file())
            self.assertTrue((run / "cells/harness-r1/cell.json").is_file())
            self.assertTrue((run / "pool").is_dir())
            self.assertFalse((run / ".pool.staging").exists())
            self.assertFalse((run / ".pool.old").exists())

        resumed = self.run_cli(*base)
        self.assertEqual(resumed.returncode, 0, resumed.stdout)
        self.assertEqual(resumed.stdout.count("already done, skipping"), 4)

        regenerated = self.run_cli(
            "--regenerate", "--dry-run", "--bench-root", str(self.bench_root)
        )
        self.assertEqual(regenerated.returncode, 0, regenerated.stdout)
        self.assertIn("Regenerate-all: rebuilt", regenerated.stdout)
        self.assertNotIn("Cell model-direct-r1 starting", regenerated.stdout)
        for run in run_dirs:
            self.assertTrue((run / "pool").is_dir())
            self.assertFalse((run / ".pool.staging").exists())
            self.assertFalse((run / ".pool.old").exists())

    def test_resume_retries_provider_limited_but_keeps_recovered(self) -> None:
        target = "samples/sample-python"
        base = (
            "--target", target,
            "--backend", "codex",
            "--replicates", "2",
            "--conditions", "harness",
            "--agents", "2",
            "--skip-recon",
            "--dry-run",
            "--run-id", "retry",
            "--bench-root", str(self.bench_root),
        )
        first = self.run_cli(*base)
        self.assertEqual(first.returncode, 0, first.stdout)

        run = self.bench_root / "codex" / "retry"
        recovered = run / "cells/harness-r1/cell.json"
        limited = run / "cells/harness-r2/cell.json"

        # r1: a done replicate that recovered from a mid-run pause — kept as-is.
        data = json.loads(recovered.read_text(encoding="utf-8"))
        self.assertEqual(data["status"], "done")
        data["run_quality"] = "provider_recovered"
        recovered.write_text(json.dumps(data), encoding="utf-8")
        # r2: a provider-limited replicate excluded from the totals — retried.
        data = json.loads(limited.read_text(encoding="utf-8"))
        data["status"] = "incomplete"
        data["run_quality"] = "provider_limited"
        limited.write_text(json.dumps(data), encoding="utf-8")

        resumed = self.run_cli(*base)
        self.assertEqual(resumed.returncode, 0, resumed.stdout)
        self.assertIn("Cell harness-r1: already done, skipping", resumed.stdout)
        self.assertIn("Cell harness-r2: prior run provider_limited; retrying", resumed.stdout)
        self.assertIn("Cell harness-r2 starting", resumed.stdout)
        self.assertNotIn("Cell harness-r2: already done, skipping", resumed.stdout)
        # The retry produced a fresh, clean measurement for the excluded cell.
        self.assertEqual(
            json.loads(limited.read_text(encoding="utf-8"))["run_quality"], "clean"
        )

    def test_multi_target_isolates_a_fatal_target_from_the_grid(self) -> None:
        # A per-target startup fatal (e.g. an unusable [runner].bin caught at
        # preflight) must fail only its own target, leaving later targets in
        # the grid to run — not abort the whole run with an uncaught traceback.
        attempted = []

        def fake_run_single(args, _bench_root):
            attempted.append(args.target)
            if args.target == "samples/sample-rust":
                raise RuntimeError("configured [runner].bin failed startup check")
            return 0

        argv = [
            "--target", "samples/sample-rust,samples/sample-python",
            "--backend", "codex", "--bench-root", str(self.bench_root),
        ]
        output = io.StringIO()
        with mock.patch.object(benchmark_runner, "run_single", side_effect=fake_run_single), \
                redirect_stdout(output), redirect_stderr(output):
            rc = benchmark_runner.main(argv)
        self.assertEqual(attempted, ["samples/sample-rust", "samples/sample-python"])
        self.assertEqual(rc, 1)
        self.assertIn("FATAL: samples/sample-rust:", output.getvalue())
        self.assertIn("Multi-target complete: 1/2 target(s) succeeded", output.getvalue())

    def test_reset_and_live_lock_contracts(self) -> None:
        ledger = self.root / "benchmark-results.md"
        ledger.write_text("# existing results\n", encoding="utf-8")
        reset = self.run_cli("--reset", "--ledger", str(ledger))
        self.assertEqual(reset.returncode, 0, reset.stdout)
        self.assertFalse(ledger.exists())
        self.assertEqual(len(list(self.root.glob("benchmark-results.*.md"))), 1)

        target = "samples/sample-python"
        backend_root = self.bench_root / "codex"
        lock = backend_root / f".run-{benchmark_runner.target_key(target)}.lock"
        with benchmark_runner.BenchmarkLock(lock):
            blocked = self.run_cli(
                "--target", target, "--dry-run", "--run-id", "locked",
                "--bench-root", str(self.bench_root),
            )
        self.assertNotEqual(blocked.returncode, 0, blocked.stdout)
        self.assertIn("is already running", blocked.stdout)
        self.assertFalse((backend_root / "locked").exists())
        self.assertFalse(lock.exists())

    def test_relocate_experiments_rewrites_metadata_idempotently(self) -> None:
        run = self.root / "run"
        cell = run / "cells/harness-r1"
        results = self.root / "external-experiment/codex/results"
        results.mkdir(parents=True)
        cell.mkdir(parents=True)
        (results / "artifact.txt").write_text("evidence\n", encoding="utf-8")
        metadata = {
            "condition": "harness", "status": "done",
            "results_dir": str(results),
        }
        (cell / "cell.json").write_text(json.dumps(metadata) + "\n", encoding="utf-8")
        (cell / "metrics.json").write_text(json.dumps(metadata) + "\n", encoding="utf-8")

        moved = benchmark.relocate_experiments(run)
        self.assertEqual(len(moved), 1)
        relocated = run / "experiments/harness-r1/codex/results"
        self.assertTrue((relocated / "artifact.txt").is_file())
        stored = json.loads(
            (cell / "cell.json").read_text(encoding="utf-8")
        )["results_dir"]
        self.assertEqual(Path(stored).resolve(), relocated.resolve())
        self.assertEqual(benchmark.relocate_experiments(run), [])

    def test_shallow_warning_and_live_dashboard_failure_are_visible_and_safe(self) -> None:
        args = benchmark_runner.parser().parse_args([
            "--target", "samples/sample-python", "--backend", "codex"
        ])
        output = io.StringIO()
        with mock.patch.object(benchmark_runner, "_is_shallow_checkout", return_value=True), \
                mock.patch.object(benchmark_runner, "_run_locked", return_value=0), \
                redirect_stdout(output), redirect_stderr(output):
            self.assertEqual(benchmark_runner.run_single(args, self.bench_root), 0)
        self.assertIn("target checkout is shallow", output.getvalue())

        output = io.StringIO()
        with mock.patch.object(
            benchmark_runner, "_render_root_result", side_effect=RuntimeError("render failed")
        ), redirect_stdout(output), redirect_stderr(output):
            self.assertIsNone(benchmark_runner.update_live_result(self.bench_root, "test"))
        self.assertIn("live update failed (test): render failed", output.getvalue())


if __name__ == "__main__":
    unittest.main(verbosity=2)
