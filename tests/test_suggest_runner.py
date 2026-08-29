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
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "suggest-runner"
sys.path.insert(0, str(ROOT / "lib"))
import llm_decide
import target_config

PROBE_LOADER = importlib.machinery.SourceFileLoader(
    "probe_runner_replay", str(ROOT / "bin/probe")
)
PROBE_SPEC = importlib.util.spec_from_loader(PROBE_LOADER.name, PROBE_LOADER)
probe = importlib.util.module_from_spec(PROBE_SPEC)
PROBE_LOADER.exec_module(probe)

RUNNER_LOADER = importlib.machinery.SourceFileLoader(
    "suggest_runner", str(ROOT / "bin/suggest-runner")
)
RUNNER_SPEC = importlib.util.spec_from_loader(RUNNER_LOADER.name, RUNNER_LOADER)
suggest_runner = importlib.util.module_from_spec(RUNNER_SPEC)
RUNNER_LOADER.exec_module(suggest_runner)


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

    def instrumented_nm(self) -> str:
        """A PATH shim reporting every binary as sanitizer-instrumented.

        Candidate enumeration confirms instrumentation with nm, which cannot
        read the script stand-ins these tests use as build artifacts."""
        directory = self.root / "toolchain"
        directory.mkdir(exist_ok=True)
        shim = directory / "nm"
        shim.write_text(
            "#!/bin/sh\n"
            "echo '0000 T __asan_init'\n"
            "echo '0000 T __ubsan_handle_type_mismatch'\n"
            "echo '0000 T __msan_init'\n"
            "echo '0000 T __tsan_init'\n",
            encoding="utf-8",
        )
        shim.chmod(0o755)
        return str(directory)

    def selective_nm(self, instrumented_name: str) -> str:
        """A PATH shim that instruments only one named test executable."""
        directory = self.root / "selective-toolchain"
        directory.mkdir(exist_ok=True)
        shim = directory / "nm"
        shim.write_text(
            "#!/bin/sh\n"
            f'case "$1" in *"/{instrumented_name}") '
            "echo '0000 T __asan_init'; exit 0;; esac\n"
            "exit 1\n",
            encoding="utf-8",
        )
        shim.chmod(0o755)
        return str(directory)

    def run_command(
        self, response: dict, *arguments: str, validation: dict | None = None,
        path_prefix: str = "",
    ) -> subprocess.CompletedProcess:
        env = os.environ | {
            "SCRIPT_ROOT": str(self.root),
            "ACTIVE_BACKEND": "codex",
            "LLM_DECIDE_DISABLE": "1",
            "LLM_DECIDE_MOCK_RUNNER_SUGGEST": json.dumps(response),
        }
        env["PATH"] = (
            (path_prefix or self.instrumented_nm()) + os.pathsep + env["PATH"]
        )
        if validation is not None:
            env["LLM_DECIDE_MOCK_RUNNER_VALIDATE"] = json.dumps(validation)
        return subprocess.run(
            [sys.executable, str(COMMAND), "sampleproj", *arguments],
            env=env, capture_output=True, text=True, check=False,
        )

    def test_applies_bounded_args_without_replacing_sanitizer_binary(self) -> None:
        self.toml.chmod(0o640)
        result = self.run_command({
            "binary": "c1",
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
        self.assertEqual(config.runner_success_codes, [0])
        self.assertEqual(self.toml.stat().st_mode & 0o777, 0o640)
        self.assertEqual(self.run_command({}, "--apply").returncode, 4)

    def test_calibrates_existing_args_without_reasking_for_an_argv(self) -> None:
        self.toml.write_text(
            self.toml.read_text(encoding="utf-8")
            + '[runner]\nargs = ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"]\n',
            encoding="utf-8",
        )

        result = self.run_command({}, "--apply")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = target_config.Config(target_root=str(self.target))
        target_config.load_toml_into(config, self.toml)
        self.assertEqual(
            config.runner_args,
            ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
        )
        self.assertEqual(config.runner_success_codes, [0])

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
            "binary": "c1",
            "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
            "reasoning": "help names an input and sink",
        }, "--apply")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = target_config.Config(target_root=str(self.target))
        target_config.load_toml_into(config, self.toml)
        self.assertEqual(config.runner_args[1], "{TESTCASE}")

    def test_rejects_missing_testcase_and_testcase_mutation(self) -> None:
        result = self.run_command(
            {"binary": "c1", "args": ["--version"], "reasoning": "bad"}, "--apply"
        )
        self.assertEqual(result.returncode, 3)
        embedded = self.run_command(
            {
                "binary": "c1",
                "args": ["--input={TESTCASE}"],
                "reasoning": "bad token shape",
            },
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
            "binary": "c1",
            "args": ["--input", "{TESTCASE}"],
            "reasoning": "mutates",
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
            "raise SystemExit(42)\n",
            encoding="utf-8",
        )
        rejected = self.run_command(
            {
                "binary": "c1",
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
                "binary": "c1",
                "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
                "reasoning": "help names an input and sink",
            },
            "--apply",
            validation={"valid": True, "reasoning": "diagnostic came from input parsing"},
        )
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        config = target_config.Config(target_root=str(self.target))
        target_config.load_toml_into(config, self.toml)
        self.assertEqual(config.runner_success_codes, [0, 42])

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
            "binary": "c1",
            "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
            "reasoning": "appears to name an input",
        }, "--apply")
        self.assertEqual(result.returncode, 3)
        self.assertIn("did not depend on testcase", result.stderr)
        self.assertNotIn("[runner]", self.toml.read_text())

    def test_a_runner_must_answer_the_same_way_twice(self) -> None:
        """The precondition for reading anything into present-vs-missing.

        Concluding "it read the testcase" from a program behaving differently
        with and without one assumes it behaves the same way when nothing
        changed. A throughput benchmark does not, so it passed as a reader on
        noise alone — and it was selected for real, because it was the one
        candidate in a project of network examples whose help documented a
        file option. Disqualified by measurement, not by its name.
        """
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import sys, time\n"
            "if '-h' in sys.argv or '--help' in sys.argv:\n"
            " print('usage: sampleproj -hash_input FILE   data to hash' * 4)\n"
            " raise SystemExit(0)\n"
            "open(sys.argv[-1], 'rb').read()\n"
            "print('throughput %.6f MiB/s' % time.time())\n",
            encoding="utf-8",
        )
        result = self.run_command({
            "binary": "c1",
            "args": ["-hash_input", "{TESTCASE}"],
            "reasoning": "its help documents reading a file",
        }, "--apply")
        self.assertEqual(result.returncode, 3)
        self.assertIn("same way twice", result.stderr)
        self.assertIn("nothing can be concluded", result.stderr)
        self.assertNotIn("[runner]", self.toml.read_text())

    def test_help_probe_cannot_write_into_the_callers_tree(self) -> None:
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import pathlib\n"
            "pathlib.Path('driver.log').write_text('ran')\n"
            "print('usage: sampleproj --input FILE --sink FILE' * 4)\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)
        scratch = self.root / "caller-cwd"
        scratch.mkdir()
        previous = os.getcwd()
        os.chdir(scratch)
        try:
            help_text = suggest_runner.read_help(self.binary)
        finally:
            os.chdir(previous)

        self.assertIn("usage: sampleproj", help_text)
        self.assertEqual([], list(scratch.iterdir()))

    def test_loader_diagnostic_is_not_offered_as_cli_help(self) -> None:
        self.binary.write_text(
            "#!/bin/sh\n"
            "echo 'dyld[123]: Library not loaded: /opt/lib/libsample.1.dylib' >&2\n"
            "echo '  Referenced from: /tmp/build/sampleproj' >&2\n"
            "echo '  Reason: tried: /opt/lib/libsample.1.dylib (no such file)' >&2\n"
            "exit 134\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)

        result = self.run_command(
            {
                "binary": "c1", "args": ["{TESTCASE}"],
                "reasoning": "the diagnostic looked long enough to be help",
            },
            "--apply",
        )

        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("could not read help", result.stderr)
        self.assertNotIn("[runner]", self.toml.read_text(encoding="utf-8"))

    def test_selects_a_declared_cli_over_the_detected_test_driver(self) -> None:
        (self.target / "CMakeLists.txt").write_text(
            "add_executable(sampleproj driver.c)\n"
            "add_executable(cleantool tool.c)\n"
            "install(TARGETS sampleproj cleantool RUNTIME DESTINATION bin)\n",
            encoding="utf-8",
        )
        clean = self.target / "build-asan" / "cleantool"
        clean.write_bytes(self.binary.read_bytes())
        clean.chmod(0o755)
        # The configured binary is a suite driver: it writes a report next to
        # itself and never reads the testcase named on the command line.
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "if '-h' in sys.argv or '--help' in sys.argv:\n"
            " print('usage: sampleproj [--input FILE] runs the bundled suite' * 3)\n"
            " raise SystemExit(0)\n"
            "pathlib.Path('sampleproj.log').write_text('suite ran')\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)

        result = self.run_command(
            {
                "binary": "c2",
                "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
                "reasoning": "c1 runs a bundled suite; c2 reads --input",
            },
            "--apply",
            path_prefix=self.instrumented_nm(),
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = target_config.Config(target_root=str(self.target))
        target_config.load_toml_into(config, self.toml)
        self.assertEqual(config.asan_bin, "build-asan/cleantool")
        self.assertEqual(
            config.runner_args,
            ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
        )
        # Enumerating candidates must not leave the driver's output behind.
        self.assertEqual(
            [], sorted(p.name for p in self.target.glob("**/*.log"))
        )

    def test_replaces_an_uninstrumented_configured_binary(self) -> None:
        (self.target / "CMakeLists.txt").write_text(
            "add_executable(cleantool tool.c)\n"
            "install(TARGETS cleantool RUNTIME DESTINATION bin)\n",
            encoding="utf-8",
        )
        clean = self.target / "build-asan" / "cleantool"
        clean.write_bytes(self.binary.read_bytes())
        clean.chmod(0o755)

        result = self.run_command(
            {
                "binary": "c1",
                "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
                "reasoning": "the offered ASan program reads --input",
            },
            "--apply",
            path_prefix=self.selective_nm("cleantool"),
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("not an instrumented asan executable", result.stderr)
        config = target_config.Config(target_root=str(self.target))
        target_config.load_toml_into(config, self.toml)
        self.assertEqual(config.asan_bin, "build-asan/cleantool")

    def test_revises_a_candidate_after_launch_validation_rejects_it(self) -> None:
        (self.target / "CMakeLists.txt").write_text(
            "add_executable(sampleproj driver.c)\n"
            "add_executable(cleantool tool.c)\n"
            "install(TARGETS sampleproj cleantool RUNTIME DESTINATION bin)\n",
            encoding="utf-8",
        )
        clean = self.target / "build-asan" / "cleantool"
        clean.write_bytes(self.binary.read_bytes())
        clean.chmod(0o755)
        self.binary.write_text(
            f"#!{sys.executable}\n"
            "import pathlib, sys\n"
            "if '-h' in sys.argv or '--help' in sys.argv:\n"
            " print('usage: sampleproj FILE runs the bundled suite' * 4)\n"
            " raise SystemExit(0)\n"
            "pathlib.Path('suite.log').write_text('ran')\n",
            encoding="utf-8",
        )
        self.binary.chmod(0o755)
        responses = iter([
            {
                "binary": "c1", "args": ["{TESTCASE}"],
                "reasoning": "first attempt",
            },
            {
                "binary": "c2",
                "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
                "reasoning": "revision selects the input reader",
            },
        ])
        prompts: list[str] = []

        def decide(_decision, _keys, prompt, _timeout):
            prompts.append(prompt)
            return next(responses)

        environment = {
            "PATH": self.instrumented_nm() + os.pathsep + os.environ["PATH"],
        }
        with (
            mock.patch.object(suggest_runner, "ROOT", self.root),
            mock.patch.object(suggest_runner, "llm_decide", side_effect=decide),
            mock.patch.dict(os.environ, environment),
        ):
            result = suggest_runner.main(["sampleproj", "--apply"])

        self.assertEqual(result, 0)
        self.assertEqual(len(prompts), 2)
        self.assertIn("created output: suite.log", prompts[1])
        config = target_config.Config(target_root=str(self.target))
        target_config.load_toml_into(config, self.toml)
        self.assertEqual(config.asan_bin, "build-asan/cleantool")

    def test_retargets_the_same_program_in_enabled_sanitizer_builds(self) -> None:
        (self.target / "CMakeLists.txt").write_text(
            "add_executable(sampleproj driver.c)\n"
            "add_executable(cleantool tool.c)\n"
            "install(TARGETS sampleproj cleantool RUNTIME DESTINATION bin)\n",
            encoding="utf-8",
        )
        clean = self.target / "build-asan" / "cleantool"
        clean.write_bytes(self.binary.read_bytes())
        clean.chmod(0o755)
        ubsan_dir = self.target / "build-ubsan"
        ubsan_dir.mkdir()
        for name, source in (
            ("sampleproj", self.binary), ("cleantool", clean)
        ):
            destination = ubsan_dir / name
            destination.write_bytes(source.read_bytes())
            destination.chmod(0o755)
        self.toml.write_text(
            'target = "sampleproj"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/sampleproj"\n'
            '[sanitizer]\nenabled = ["asan", "ubsan"]\n'
            'ubsan_bin = "build-ubsan/sampleproj"\n',
            encoding="utf-8",
        )

        result = self.run_command(
            {
                "binary": "c2",
                "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
                "reasoning": "cleantool reads the supplied input",
            },
            "--apply",
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        config = target_config.Config(target_root=str(self.target))
        target_config.load_toml_into(config, self.toml)
        self.assertEqual(config.asan_bin, "build-asan/cleantool")
        self.assertEqual(config.ubsan_bin, "build-ubsan/cleantool")

    def test_refuses_shared_args_without_the_same_sibling_program(self) -> None:
        (self.target / "CMakeLists.txt").write_text(
            "add_executable(sampleproj driver.c)\n"
            "add_executable(cleantool tool.c)\n"
            "install(TARGETS sampleproj cleantool RUNTIME DESTINATION bin)\n",
            encoding="utf-8",
        )
        clean = self.target / "build-asan" / "cleantool"
        clean.write_bytes(self.binary.read_bytes())
        clean.chmod(0o755)
        ubsan = self.target / "build-ubsan" / "sampleproj"
        ubsan.parent.mkdir()
        ubsan.write_bytes(self.binary.read_bytes())
        ubsan.chmod(0o755)
        self.toml.write_text(
            'target = "sampleproj"\nbuild_system = "cmake"\n'
            'asan_bin = "build-asan/sampleproj"\n'
            '[sanitizer]\nenabled = ["asan", "ubsan"]\n'
            'ubsan_bin = "build-ubsan/sampleproj"\n',
            encoding="utf-8",
        )
        original = self.toml.read_text(encoding="utf-8")

        result = self.run_command(
            {
                "binary": "c2",
                "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
                "reasoning": "cleantool reads the supplied input",
            },
            "--apply",
        )

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("matching instrumented ubsan program", result.stderr)
        self.assertEqual(self.toml.read_text(encoding="utf-8"), original)

    def test_an_unknown_candidate_id_is_rejected(self) -> None:
        original = self.toml.read_text(encoding="utf-8")
        result = self.run_command({
            "binary": "c9",
            "args": ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"],
            "reasoning": "id the harness never offered",
        }, "--apply", path_prefix=self.instrumented_nm())

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("candidate id 'c9' was not offered", result.stderr)
        self.assertEqual(self.toml.read_text(encoding="utf-8"), original)

    def test_decision_shape_guard_covers_the_candidate_field(self) -> None:
        shape = llm_decide._validate_decision_shape
        self.assertTrue(shape("runner-suggest", {
            "args": ["{TESTCASE}"], "binary": "c2", "reasoning": "ok",
        }))
        self.assertFalse(shape("runner-suggest", {
            "args": ["{TESTCASE}"], "reasoning": "ok",
        }))
        self.assertFalse(shape("runner-suggest", {
            "args": ["{TESTCASE}"], "binary": 2, "reasoning": "ok",
        }))

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
