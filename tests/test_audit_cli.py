#!/usr/bin/env python3
"""Public audit CLI contract: help, required target, rejected arguments."""

from __future__ import annotations

import io
import os
import shlex
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner
from python_test_helpers import invoke_main


def run_main(*arguments: str) -> tuple[int, str]:
    output = io.StringIO()
    with redirect_stdout(output), redirect_stderr(output):
        code = invoke_main(audit_runner.main, arguments, argv0=str(ROOT / "bin" / "audit"))
    return code, output.getvalue()


class AuditCliTests(unittest.TestCase):
    def test_model_preflight_retries_with_newer_codex_already_on_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / "old"
            new = root / "new"
            for path, version in ((old, "0.10.0"), (new, "0.20.0")):
                path.mkdir()
                binary = path / "codex"
                binary.write_text(
                    f"#!{sys.executable}\nprint('codex-cli {version}')\n",
                    encoding="utf-8",
                )
                binary.chmod(0o755)
            runtime = SimpleNamespace(
                root=root, target_root=root / "target", results=root / "results",
                logs=root / "logs", raw=root / "logs/.raw",
                index=root / "logs/index.log", backend="codex",
                model="fixture-model", agent_security="sandboxed",
            )
            runtime.target_root.mkdir()
            runtime.results.mkdir()
            runtime.raw.mkdir(parents=True)
            attempts = 0

            def run_agent(_backend, prompt_text, _timeout, raw, **_kwargs):
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    Path(raw).write_text(
                        "The model requires a newer version of Codex.\n",
                        encoding="utf-8",
                    )
                    return 1
                command = next(
                    line for line in prompt_text.splitlines()
                    if line.startswith("printf ")
                )
                parts = shlex.split(command)
                Path(parts[4]).write_text(parts[2], encoding="utf-8")
                return 0

            with mock.patch.dict(
                os.environ,
                {"PATH": f"{old}{os.pathsep}{new}",
                 "AUDIT_MODEL_PREFLIGHT_ATTEMPTS": "2"},
                clear=False,
            ), mock.patch.object(
                audit_runner.llm_invoke, "run_agent_prompt", side_effect=run_agent,
            ), mock.patch.object(
                audit_runner.llm_usage, "append_usage_event",
            ):
                os.environ.pop("CODEX_BIN", None)
                audit_runner.validate_model(runtime)
                self.assertEqual(os.environ["CODEX_BIN"], str((new / "codex").resolve()))
            self.assertEqual(attempts, 2)

    def test_runtime_config_reload_uses_the_checkout_root_once(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            checkout = root / "targets" / "sample"
            project = checkout / "nested"
            project.mkdir(parents=True)
            config_path = root / "output" / "sample" / "target.toml"
            config_path.parent.mkdir(parents=True)
            config_path.write_text(
                'target = "sample"\nsource_subdir = "nested"\n',
                encoding="utf-8",
            )
            config = audit_runner.target_config.Config(target_root=str(checkout))
            audit_runner.target_config.load_toml_into(config, config_path)
            runtime = SimpleNamespace(
                root=root, output_slug="sample", target_root=project,
                config=config, results=root / "results",
            )
            with mock.patch.object(
                audit_runner.target_config, "pin_session_config"
            ), mock.patch.object(audit_runner, "_activate_runtime"):
                audit_runner.pin_runtime_config(runtime)
            self.assertEqual(Path(runtime.config.target_root), project.resolve())
            self.assertEqual(
                Path(runtime.config.checkout_root).resolve(), checkout.resolve()
            )

    def test_bare_launch_prints_help_instead_of_auditing_a_default_target(self) -> None:
        code, output = run_main()
        self.assertEqual(code, 2, output)
        self.assertIn("usage: audit", output)
        self.assertIn("--target-path", output)
        self.assertNotIn("FATAL", output)

    def test_every_option_documents_itself(self) -> None:
        for action in audit_runner.build_parser()._actions:
            with self.subTest(option=action.dest):
                self.assertTrue(action.help, f"{action.dest} has no help text")

    def test_rejected_arguments_name_the_problem(self) -> None:
        cases = (
            (("--backend", "codex"), "one of --target or --target-path is required"),
            (("--target", "sample", "-1"), "must be >= 0"),
            (("--target", "sample", "--strategy", "S9"), "invalid choice"),
            (("--target", "sample", "--new-target"), "unrecognized arguments"),
        )
        for arguments, expected in cases:
            with self.subTest(arguments=arguments):
                code, output = run_main(*arguments)
                self.assertEqual(code, 2, output)
                self.assertIn(expected, output)


if __name__ == "__main__":
    unittest.main()
