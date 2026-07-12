#!/usr/bin/env python3
"""CLI, credentials, runtime, daemon, and image lifecycle coverage."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "audit-container-shell"


class AuditContainerShellTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="container-shell-")
        self.root = Path(self.temporary.name) / "root"
        self.home = Path(self.temporary.name) / "home"
        (self.root / ".codex").mkdir(parents=True)
        (self.root / ".gemini").mkdir()
        (self.home / ".claude").mkdir(parents=True)
        (self.home / ".claude.json").touch()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_command(self, *args, home=None, path=None, clear_credentials=False, **env):
        command_env = os.environ.copy()
        command_env.update(AUDIT_ROOT=str(self.root), HOME=str(home or self.home))
        if path is not None:
            command_env["PATH"] = str(path)
        if clear_credentials:
            for key in (
                "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN", "OPENAI_API_KEY",
                "GEMINI_API_KEY", "USE_GEMINI_CLI", "GOOGLE_API_KEY", "XAI_API_KEY",
                "GOOGLE_CLOUD_PROJECT", "GOOGLE_CLOUD_QUOTA_PROJECT",
                "GOOGLE_APPLICATION_CREDENTIALS",
            ):
                command_env.pop(key, None)
        command_env.update({key: str(value) for key, value in env.items()})
        return subprocess.run(
            [sys.executable, str(COMMAND), *map(str, args)],
            capture_output=True, text=True, env=command_env,
        )

    @staticmethod
    def output(proc):
        return proc.stdout + proc.stderr

    def executable(self, directory, name, source):
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        path.write_text(f"#!{sys.executable}\n{source}", encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def test_help_documents_shell_contract_without_hidden_or_removed_options(self) -> None:
        proc = self.run_command("--help")
        output = self.output(proc)
        self.assertEqual(proc.returncode, 0, output)
        for expected in (
            "mounts this", "repository at /root/work", "opens an interactive shell",
            "It does not run", "bin/audit", "node:lts-bookworm", "--image <image>",
            "--tag <name>", "--gvisor", "--docker-runtime <name>",
            "--forward-credentials", "starts logged out", "# codex login",
            "# codex login status", '# claude -p "Reply exactly: tokenfuzz-claude-auth-ok"',
            '# agy -p "Reply exactly: tokenfuzz-gemini-auth-ok"',
            '# grok -p "Reply exactly: tokenfuzz-grok-auth-ok"', "press Ctrl+C",
            "IS_SANDBOX=1", "dangerously-skip-permissions",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, output)
        for forbidden in ("AUDIT_CONTAINER_CLAUDE_JSON", "--skip-git-repo-check", "--version"):
            self.assertNotIn(forbidden, output)

    def test_rebuild_dry_run_contains_portable_build_and_hardened_run_arguments(self) -> None:
        proc = self.run_command("--dry-run", "--rebuild", "--tag", "test/audit-shell:latest")
        output = self.output(proc)
        self.assertEqual(proc.returncode, 0, output)
        for expected in (
            "BASE_IMAGE=node:lts-bookworm", "@anthropic-ai/claude-code@latest",
            "@openai/codex@latest", "@google/gemini-cli@latest",
            "AGY_INSTALL_URL=https://antigravity.google/cli/install.sh",
            "GROK_INSTALL_URL=https://x.ai/cli/install.sh", f"-v {self.root}:/root/work",
            "-e GEMINI_CLI_TRUST_WORKSPACE=true", "-e IS_SANDBOX=1",
            "--security-opt no-new-privileges",
        ):
            self.assertIn(expected, output)
        for forbidden in (
            ":/root/.claude:ro", ":/root/.claude.json:ro", ":/root/.codex:ro",
            ":/root/.gemini:ro", ":/root/.grok:ro",
        ):
            self.assertNotIn(forbidden, output)
        source = COMMAND.read_text(encoding="utf-8")
        runner = (ROOT / "tests" / "run-tests.sh").read_text(encoding="utf-8")
        self.assertNotIn("COPY tests/run-tests.sh", source)
        self.assertIn('tests/run-tests.sh" --install-container-deps', source)
        self.assertNotIn('packages="bash', source)
        self.assertIn("command -v yum", source)
        self.assertIn("command -v yum", runner)

    def test_image_runtime_package_and_alias_overrides(self) -> None:
        proc = self.run_command(
            "--dry-run", "--rebuild", "--docker-runtime", "runsc",
            "--image", "node:22-bookworm",
            CLAUDE_NPM_SPEC="claude-test@latest", CODEX_NPM_SPEC="codex-test@latest",
            GEMINI_CLI_NPM_SPEC="gemini-cli-test@latest",
            AGY_INSTALL_URL="https://example.test/agy-install.sh",
            GROK_INSTALL_URL="https://example.test/grok-install.sh",
        )
        output = self.output(proc)
        for expected in (
            "docker build", "--runtime runsc", "BASE_IMAGE=node:22-bookworm",
            "claude-test@latest", "codex-test@latest", "gemini-cli-test@latest",
            "AGY_INSTALL_URL=https://example.test/agy-install.sh",
            "GROK_INSTALL_URL=https://example.test/grok-install.sh",
        ):
            self.assertIn(expected, output)
        for alias in ("ubuntu", "fedora"):
            proc = self.run_command("--dry-run", "--rebuild", "--image", alias)
            self.assertEqual(proc.returncode, 0)
            self.assertIn(f"BASE_IMAGE={alias}:latest", self.output(proc))

    def test_credentials_are_opt_in_and_selectively_forwarded(self) -> None:
        adc = Path(self.temporary.name) / "google-adc.json"
        adc.write_text("{}\n")
        (self.home / ".config" / "gcloud").mkdir(parents=True)
        credentials = dict(
            GEMINI_API_KEY="test-key", USE_GEMINI_CLI=1, XAI_API_KEY="xai-test",
            GOOGLE_APPLICATION_CREDENTIALS=adc,
        )
        default = self.output(self.run_command("--dry-run", **credentials))
        for forbidden in (
            "-e GEMINI_API_KEY", "-e USE_GEMINI_CLI", "-e XAI_API_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS=/root/.config/audit-google-application-credentials.json",
            ":/root/.config/gcloud:ro",
        ):
            self.assertNotIn(forbidden, default)
        self.assertIn("--forward-credentials", default)
        forwarded = self.output(self.run_command("--dry-run", "--forward-credentials", **credentials))
        for expected in (
            "-e GEMINI_API_KEY", "-e USE_GEMINI_CLI", "-e XAI_API_KEY",
            "-e GOOGLE_APPLICATION_CREDENTIALS=/root/.config/audit-google-application-credentials.json",
            f"{adc}:/root/.config/audit-google-application-credentials.json:ro",
            f"{self.home}/.config/gcloud:/root/.config/gcloud:ro",
            "Forwarding host env vars:", "GEMINI_API_KEY",
            "Mounting GOOGLE_APPLICATION_CREDENTIALS read-only",
        ):
            self.assertIn(expected, forwarded)
        self.assertNotIn("log in inside the container or use --forward-credentials", forwarded)

    def test_empty_forwarding_default_hint_and_env_knob(self) -> None:
        empty_home = Path(self.temporary.name) / "empty-home"
        empty_home.mkdir()
        output = self.output(self.run_command(
            "--dry-run", "--forward-credentials", home=empty_home, clear_credentials=True
        ))
        self.assertIn("--forward-credentials set but no host credential", output)
        self.assertNotIn("log in inside the container or use --forward-credentials", output)
        self.assertIn(
            "log in inside the container or use --forward-credentials",
            self.output(self.run_command("--dry-run", clear_credentials=True)),
        )
        output = self.output(self.run_command(
            "--dry-run", OPENAI_API_KEY="test-key", AUDIT_FORWARD_CREDENTIALS=1
        ))
        self.assertIn("-e OPENAI_API_KEY", output)

    def test_default_dry_run_removed_options_and_runtime_selection(self) -> None:
        output = self.output(self.run_command("--dry-run"))
        self.assertNotIn("build command", output)
        self.assertNotIn("BASE_IMAGE=", output)
        self.assertIn("run command", output)
        for option in ("--no-cache", "--reuse-image", "--no-reuse-image", "--no-build"):
            with self.subTest(option=option):
                proc = self.run_command("--dry-run", option)
                self.assertNotEqual(proc.returncode, 0)
                self.assertIn(f"unknown option: {option}", self.output(proc))
        output = self.output(self.run_command("--dry-run", "--gvisor"))
        self.assertIn("Using Docker OCI runtime: runsc", output)
        self.assertIn("--runtime runsc", output)
        self.assertIn("--runtime runsc", self.output(self.run_command(
            "--dry-run", AUDIT_DOCKER_RUNTIME="runsc"
        )))

    def test_missing_unreachable_and_unsupported_runtime_errors(self) -> None:
        empty = Path(self.temporary.name) / "empty-path"
        empty.mkdir()
        proc = self.run_command("--runtime", "docker", path=empty)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("docker not installed", self.output(proc))
        dead = Path(self.temporary.name) / "dead-docker"
        self.executable(dead, "docker", "import sys\nraise SystemExit(1 if sys.argv[1:2] == ['info'] else 0)\n")
        proc = self.run_command(
            "--runtime", "docker", path=str(dead) + os.pathsep + "/usr/bin:/bin",
            AUDIT_CONTAINER_AUTO_START=0,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("docker installed but daemon not reachable", self.output(proc))
        proc = self.run_command(
            "--runtime", "nerdctl", path=str(dead) + os.pathsep + "/usr/bin:/bin"
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--runtime must be docker", self.output(proc))

    def test_daemon_auto_start_attempt_and_recovery(self) -> None:
        stubs = Path(self.temporary.name) / "autostart-bin"
        state = Path(self.temporary.name) / "autostart-state"
        state.mkdir()
        self.executable(stubs, "docker",
            "import pathlib, sys\nstate = pathlib.Path(" + repr(str(state / "up")) + ")\n"
            "raise SystemExit(0 if sys.argv[1:2] != ['info'] or state.exists() else 1)\n")
        self.executable(stubs, "systemctl",
            "import pathlib\npathlib.Path(" + repr(str(state / "up")) + ").touch()\n")
        self.executable(stubs, "uname", "print('Linux')\n")
        proc = self.run_command(
            "--runtime", "docker", path=str(stubs) + os.pathsep + "/usr/bin:/bin",
            AUDIT_CONTAINER_START_TIMEOUT=10,
        )
        output = self.output(proc)
        self.assertEqual(proc.returncode, 0, output)
        self.assertIn("daemon not reachable; attempting auto-start", output)
        self.assertIn("Attempting to start docker: systemctl", output)
        self.assertIn("docker daemon is now reachable", output)

    def docker_image_stub(self, name, image_exists, build_marker=None):
        directory = Path(self.temporary.name) / name
        source = (
            "import pathlib, sys\nargs = sys.argv[1:]\n"
            + (f"pathlib.Path({str(build_marker)!r}).touch() if args[:1] == ['build'] else None\n" if build_marker else "")
            + f"raise SystemExit({0 if image_exists else 1} if args[:2] == ['image', 'inspect'] else 0)\n"
        )
        self.executable(directory, "docker", source)
        return str(directory) + os.pathsep + "/usr/bin:/bin"

    def test_existing_missing_and_rebuilt_image_lifecycle(self) -> None:
        built = Path(self.temporary.name) / "built"
        path = self.docker_image_stub("image-exists", True, built)
        proc = self.run_command("--runtime", "docker", path=path)
        self.assertEqual(proc.returncode, 0, self.output(proc))
        self.assertFalse(built.exists())
        path = self.docker_image_stub("rebuild", True, built)
        proc = self.run_command("--runtime", "docker", "--rebuild", path=path)
        self.assertEqual(proc.returncode, 0, self.output(proc))
        self.assertTrue(built.is_file())
        path = self.docker_image_stub("image-missing", False)
        proc = self.run_command("--runtime", "docker", path=path)
        output = self.output(proc)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("image audit-cli-shell:latest does not exist locally", output)
        self.assertIn("run with --rebuild", output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
