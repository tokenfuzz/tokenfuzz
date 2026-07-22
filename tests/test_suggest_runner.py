#!/usr/bin/env python3
"""Native sanitizer CLI invocation bootstrap regressions."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "suggest-runner"
sys.path.insert(0, str(ROOT / "lib"))
import target_config

PROBE_LOADER = importlib.machinery.SourceFileLoader(
    "probe_runner_replay", str(ROOT / "bin/probe")
)
PROBE_SPEC = importlib.util.spec_from_loader(PROBE_LOADER.name, PROBE_LOADER)
probe = importlib.util.module_from_spec(PROBE_SPEC)
PROBE_LOADER.exec_module(probe)


class SuggestRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="suggest-runner-")
        self.root = Path(self.temporary.name)
        (self.root / "lib").symlink_to(ROOT / "lib", target_is_directory=True)
        self.target = self.root / "targets" / "sampleproj"
        self.output = self.root / "output" / "sampleproj"
        (self.target / "build-asan").mkdir(parents=True)
        self.output.mkdir(parents=True)
        self.binary = self.target / "build-asan" / "sampleproj"
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "if '-h' in sys.argv or '--help' in sys.argv:\n"
            " print('usage: sampleproj --input FILE --sink FILE' * 4)\n"
            " raise SystemExit(0)\n"
            "pathlib.Path(sys.argv[sys.argv.index('--input') + 1]).read_bytes()\n"
            "print('TESTCASE_EXECUTED')\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)
        self.toml = self.output / "target.toml"
        self.toml.write_text(
            'target = "sampleproj"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/sampleproj"\n'
            '[sanitizer]\nenabled = ["asan"]\n',
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_command(
        self, response: dict, *arguments: str, validation: dict | None = None,
    ) -> subprocess.CompletedProcess:
        env = os.environ | {
            "SCRIPT_ROOT": str(self.root),
            "ACTIVE_BACKEND": "codex",
            "LLM_DECIDE_DISABLE": "1",
            "LLM_DECIDE_MOCK_RUNNER_SUGGEST": json.dumps(response),
        }
        if validation is not None:
            env["LLM_DECIDE_MOCK_RUNNER_VALIDATE"] = json.dumps(validation)
        return subprocess.run(
            [sys.executable, str(COMMAND), "sampleproj", *arguments],
            env=env, capture_output=True, text=True, check=False,
        )

    def test_applies_bounded_args_without_replacing_sanitizer_binary(self) -> None:
        result = self.run_command({
            "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
            "reasoning": "help names an input and sink",
        }, "--apply")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = target_config.Config(target_root=str(self.target))
        target_config.load_toml_into(config, self.toml)
        self.assertEqual(config.asan_bin, "build-asan/sampleproj")
        self.assertEqual(
            config.runner_args,
            ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
        )
        self.assertEqual(self.run_command({}, "--apply").returncode, 4)

    def test_uses_the_first_enabled_executable_sanitizer(self) -> None:
        ubsan_binary = self.target / "build-ubsan" / "sampleproj"
        ubsan_binary.parent.mkdir()
        ubsan_binary.write_bytes(self.binary.read_bytes())
        ubsan_binary.chmod(0o755)
        self.binary.unlink()
        self.toml.write_text(
            'target = "sampleproj"\nbuild_system = "cmake"\n'
            '[sanitizer]\nenabled = ["ubsan"]\n'
            'ubsan_bin = "build-ubsan/sampleproj"\n',
            encoding="utf-8",
        )

        result = self.run_command({
            "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
            "reasoning": "help names an input and sink",
        }, "--apply")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = target_config.Config(target_root=str(self.target))
        target_config.load_toml_into(config, self.toml)
        self.assertEqual(config.runner_args[1], "{TESTCASE}")

    def test_rejects_missing_testcase_and_testcase_mutation(self) -> None:
        result = self.run_command(
            {"args": ["--version"], "reasoning": "bad"}, "--apply"
        )
        self.assertEqual(result.returncode, 3)
        embedded = self.run_command(
            {"args": ["--input={TESTCASE}"], "reasoning": "bad token shape"},
            "--apply",
        )
        self.assertEqual(embedded.returncode, 3)
        original = self.toml.read_text()
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "if '-h' in sys.argv or '--help' in sys.argv:\n"
            " print('usage: sampleproj --input FILE' * 6)\n"
            "else:\n"
            " pathlib.Path(sys.argv[-1]).write_text('changed')\n",
            encoding="utf-8",
        )
        result = self.run_command({
            "args": ["--input", "{TESTCASE}"], "reasoning": "mutates"
        }, "--apply")
        self.assertEqual(result.returncode, 3)
        self.assertEqual(self.toml.read_text(), original)

    def test_nonzero_launch_requires_evidence_that_input_parsing_started(self) -> None:
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "if '-h' in sys.argv or '--help' in sys.argv:\n"
            " print('usage: sampleproj --input FILE --sink FILE' * 4)\n"
            " raise SystemExit(0)\n"
            "path = pathlib.Path(sys.argv[sys.argv.index('--input') + 1])\n"
            "if not path.is_file():\n"
            " print('input does not exist')\n"
            " raise SystemExit(3)\n"
            "print('input has invalid data')\n"
            "raise SystemExit(2)\n",
            encoding="utf-8",
        )
        rejected = self.run_command(
            {
                "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
                "reasoning": "help names an input and sink",
            },
            "--apply",
            validation={"valid": False, "reasoning": "diagnostic is not parser evidence"},
        )
        self.assertEqual(rejected.returncode, 3)
        self.assertNotIn("[runner]", self.toml.read_text())

        accepted = self.run_command(
            {
                "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
                "reasoning": "help names an input and sink",
            },
            "--apply",
            validation={"valid": True, "reasoning": "diagnostic came from input parsing"},
        )
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)

    def test_zero_exit_launch_must_depend_on_the_testcase(self) -> None:
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import sys\n"
            "if '-h' in sys.argv or '--help' in sys.argv:\n"
            " print('usage: sampleproj --input FILE --sink FILE' * 4)\n"
            " raise SystemExit(0)\n"
            "print('completed without opening input')\n",
            encoding="utf-8",
        )
        result = self.run_command({
            "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
            "reasoning": "appears to name an input",
        }, "--apply")
        self.assertEqual(result.returncode, 3)
        self.assertIn("did not depend on testcase", result.stderr)
        self.assertNotIn("[runner]", self.toml.read_text())

    def test_probe_preserves_the_native_template_for_crash_replay(self) -> None:
        instance = object.__new__(probe.Probe)
        instance.args = SimpleNamespace(args=["--extra"])
        instance.repro_args = list(instance.args.args)
        instance.header = {"harness": ""}
        instance.mode = "generic"
        instance.sanitizer = "asan"
        instance.exec_testcase = Path("/tmp/crafted.bin")
        instance.testcase = instance.exec_testcase
        instance.environment = {}
        instance.config = SimpleNamespace(
            runner_args=[
                "--quiet", "--input", "{TESTCASE}", "--output", "{NULL_DEVICE}",
            ],
            runner_bin="",
            target_root="/tmp/target",
            results_dir="/tmp/results",
            slug="sampleproj",
            sanitizer_bin=lambda _name: "build-asan/sampleproj",
            resolve_path=lambda value: f"/tmp/target/{value}",
        )

        command = instance._command()

        self.assertIn("/tmp/crafted.bin", command)
        self.assertEqual(
            instance.repro_args,
            ["--quiet", "--input", "{TESTCASE}", "--output", "/dev/null", "--extra"],
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
