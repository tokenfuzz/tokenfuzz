#!/usr/bin/env python3
"""Behavior tests for audit and benchmark configured-runner preflight."""

from __future__ import annotations

import contextlib
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner
import benchmark_runner
import runner_preflight
import target_config


def executable(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


class RunnerPreflightTests(unittest.TestCase):
    def config(self, root: Path, runner: str, *, findings_only: bool = True):
        return target_config.Config(
            target_root=str(root), runner_bin=runner,
            sanitizers_explicitly_disabled=findings_only,
        )

    def test_missing_failed_and_target_relative_runners(self):
        with tempfile.TemporaryDirectory(prefix="runner-preflight-") as temporary:
            root = Path(temporary)
            # A runner is optional: a findings-only target with no [runner].bin
            # audits in code-review mode rather than failing at startup.
            messages = []
            self.assertIsNone(
                runner_preflight.validate(self.config(root, ""), messages.append)
            )
            self.assertTrue(any("code-review findings only" in m for m in messages))
            with mock.patch.object(runner_preflight.shutil, "which", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "was not found"):
                    runner_preflight.validate(self.config(root, "missing-runner"))

            custom = root / "tools" / "sample-driver"
            executable(custom)
            with mock.patch.object(runner_preflight.shutil, "which", return_value=None), \
                 mock.patch.object(runner_preflight, "run_timeout") as launched:
                resolved = runner_preflight.validate(
                    self.config(root, "tools/sample-driver")
                )
            self.assertEqual(custom, resolved)
            launched.assert_not_called()

            java = root / "java"
            executable(java)
            failed = SimpleNamespace(returncode=1, stdout=b"runtime unavailable\n")
            with mock.patch.object(runner_preflight.shutil, "which", return_value=str(java)), \
                 mock.patch.object(runner_preflight, "run_timeout", return_value=failed):
                with self.assertRaisesRegex(RuntimeError, "runtime unavailable"):
                    runner_preflight.validate(self.config(root, "java"))

    def test_every_sample_target_runner_contract(self):
        configs = sorted((ROOT / "output" / "samples").glob("*/target.toml"))
        self.assertGreaterEqual(len(configs), 14)
        with tempfile.TemporaryDirectory(prefix="sample-runner-matrix-") as temporary:
            temp = Path(temporary)
            path_dir = temp / "bin"
            loaded = []
            for config_path in configs:
                target = temp / "targets" / config_path.parent.name
                target.mkdir(parents=True)
                config = target_config.Config(target_root=str(target))
                target_config.load_toml_into(config, config_path)
                loaded.append(config)
                raw = config.runner_bin
                if not raw:
                    continue
                destination = target / raw if "/" in raw else path_dir / raw
                executable(destination)

            completed = SimpleNamespace(returncode=0, stdout=b"fixture version\n")
            with mock.patch.dict(os.environ, {"PATH": str(path_dir)}), \
                 mock.patch.object(runner_preflight, "run_timeout", return_value=completed) as launched:
                for config in loaded:
                    runner_preflight.validate(config)

            checked = {Path(call.args[0][0]).name for call in launched.call_args_list}
            self.assertEqual(
                {"Rscript", "java", "kotlinc", "node", "perl", "php",
                 "python3", "ruby", "swift", "ts-node"},
                checked,
            )

    def test_audit_and_benchmark_call_shared_preflight_before_work(self):
        events = []
        runtime = SimpleNamespace(config=self.config(Path("/target"), "python3"))
        args = SimpleNamespace(allow_concurrent=False, max_iterations=1)
        state = SimpleNamespace(iteration=0)
        with mock.patch.object(
            audit_runner, "instance_lock", return_value=contextlib.nullcontext()
        ), mock.patch.object(
            audit_runner.runner_preflight, "validate",
            side_effect=lambda *_a, **_k: events.append("runner"),
        ), mock.patch.object(
            audit_runner, "validate_model", side_effect=lambda *_a: events.append("model")
        ), mock.patch.object(
            audit_runner, "preflight_build", side_effect=lambda *_a: events.append("build")
        ), mock.patch.object(
            audit_runner, "initialize_backend", return_value=state
        ), mock.patch.object(
            audit_runner, "run_iteration", return_value=("stalled", [])
        ):
            audit_runner.run_backend(runtime, args, "")
        self.assertEqual(["runner", "model", "build"], events)

        bench_args = SimpleNamespace(
            dry_run=False, regenerate=False, target="sample-python", backend="codex",
        )
        with mock.patch.object(benchmark_runner.target_config, "load_toml_into"), \
             mock.patch.object(benchmark_runner.runner_preflight, "validate") as checked, \
             mock.patch.object(benchmark_runner.build_preflight, "refresh"):
            benchmark_runner.preflight_build(bench_args, Path("/bench"), "fixture-model")
        checked.assert_called_once()


if __name__ == "__main__":
    unittest.main(verbosity=2)
