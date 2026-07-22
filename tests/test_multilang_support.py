#!/usr/bin/env python3
"""Multi-language probe routing and target configuration regressions."""

from __future__ import annotations

import concurrent.futures
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
PROBE = ROOT / "bin" / "probe"
sys.path.insert(0, str(ROOT / "lib"))

import languages
import target_config


class MultiLanguageSupportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="multilang-")
        self.root = Path(self.temporary.name)
        self.target = self.root / "target"
        self.target.mkdir()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def executable(self, path: Path, body: str) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
        path.chmod(0o755)
        return path

    def tree(self, name: str, config: str) -> Path:
        root = self.root / name
        results = root / "output" / "multilang" / "codex" / "results"
        scratch = results / "scratch-1"
        scratch.mkdir(parents=True)
        logs = root / "logs"
        logs.mkdir()
        (root / "output" / "multilang" / "target.toml").write_text(config, encoding="utf-8")
        (results / ".session-env").write_text(
            f"RESULTS_DIR={results}\nTARGET_ROOT={self.target}\nTARGET_SLUG=multilang\n"
            f"TARGET_REV=HEAD\nLOGDIR={logs}\n",
            encoding="utf-8",
        )
        return scratch

    @staticmethod
    def make_testcase(path: Path, body: str = "payload\n", harness: str = "") -> Path:
        comment = "#" if path.suffix == ".py" else "//"
        header = (
            f"{comment} TARGET: sample:main:1\n"
            f"{comment} HYPOTHESIS-ID: H_sample\n"
            f"{comment} CATEGORY: state\n"
        )
        if harness:
            header += f"{comment} HARNESS: {harness}\n"
        path.write_text(header + body, encoding="utf-8")
        return path

    @staticmethod
    def run_probe(testcase: Path, *arguments: str, environment: dict[str, str] | None = None):
        env = os.environ.copy()
        if environment:
            env.update(environment)
        return subprocess.run(
            [sys.executable, str(PROBE), *arguments, str(testcase)],
            env=env, capture_output=True, text=True, timeout=60, check=False,
        )

    def test_language_registry_runner_defaults_detection_and_seed_modes(self) -> None:
        expected_languages = {
            "cargo", "go", "swift", "maven", "gradle", "kotlin", "python",
            "npm", "bundler", "composer", "rlang", "perl",
        }
        for build_system in expected_languages:
            with self.subTest(build_system=build_system):
                defaults = target_config.language_runner_defaults(build_system)
                self.assertTrue(defaults.get("bin"), defaults)
                self.assertTrue(defaults.get("args"), defaults)
        self.assertEqual(target_config.language_runner_defaults("unknown"), {})
        python_env = target_config.language_runner_defaults("python")["env"]
        self.assertIn("PYTHONPATH={TARGET_ROOT}:{TARGET_ROOT}/src:{TARGET_ROOT}/lib", python_env)
        go_env = target_config.language_runner_defaults("go")["env"]
        self.assertIn("GOFLAGS=-mod=mod", go_env)
        self.assertIn("GORACE=halt_on_error=1", go_env)
        cargo_args = target_config.language_runner_defaults("cargo")["args"]
        self.assertIn("--manifest-path", cargo_args)
        self.assertIn("{TARGET_ROOT}/Cargo.toml", cargo_args)
        swift_args = target_config.language_runner_defaults("swift")["args"]
        for token in ("--package-path", "{TARGET_ROOT}", "{TARGET_SLUG}", "-sanitize={SWIFT_SANITIZER}"):
            self.assertIn(token, swift_args)

        fake_home = self.root / "jdk"
        java = self.executable(
            fake_home / "bin" / "java",
            "import sys\nprint('openjdk version 17', file=sys.stderr)\n",
        )
        with mock.patch.dict(os.environ, {"AUDIT_JAVA_HOME": str(fake_home), "JAVA_HOME": ""}):
            defaults = target_config.language_runner_defaults("maven")
        self.assertEqual(defaults["bin"], str(java))
        self.assertEqual(defaults["env"], [f"JAVA_HOME={fake_home}"])

        manifests = {
            "Cargo.toml": "cargo", "go.mod": "go", "Package.swift": "swift",
            "pom.xml": "maven", "build.gradle": "gradle", "build.gradle.kts": "gradle",
            "settings.gradle": "gradle", "Main.kts": "kotlin", "pyproject.toml": "python",
            "setup.py": "python", "package.json": "npm", "Gemfile": "bundler",
            "composer.json": "composer", "DESCRIPTION": "rlang", "Makefile.PL": "perl",
        }
        for index, (manifest, expected) in enumerate(manifests.items()):
            with self.subTest(manifest=manifest):
                directory = self.root / f"manifest-{index}"
                directory.mkdir()
                (directory / manifest).touch()
                self.assertEqual(target_config._detect_build_system(directory), expected)
        polyglot = self.root / "polyglot"
        polyglot.mkdir()
        (polyglot / "CMakeLists.txt").touch()
        (polyglot / "Cargo.toml").touch()
        self.assertEqual(target_config._detect_build_system(polyglot), "cmake")

        managed = (
            ("python", "pyproject.toml"), ("cargo", "Cargo.toml"),
            ("go", "go.mod"), ("npm", "package.json"), ("bundler", "Gemfile"),
            ("composer", "composer.json"), ("maven", "pom.xml"), ("kotlin", "Main.kts"),
        )
        for slug, manifest in managed:
            with self.subTest(seed=slug):
                directory = self.root / f"seed-{slug}"
                directory.mkdir()
                (directory / manifest).touch()
                output = directory / "target.toml"
                target_config.seed_toml(directory, output, "")
                text = output.read_text()
                self.assertIn("enabled = []", text)
                self.assertIn("[runner]", text)
                config = target_config.Config()
                target_config.load_toml_into(config, output)
                self.assertTrue(config.sanitizers_explicitly_disabled)
                self.assertTrue(config.runner_bin)
        for slug, manifest in (("cmake", "CMakeLists.txt"), ("meson", "meson.build"), ("swift", "Package.swift")):
            directory = self.root / f"native-{slug}"
            directory.mkdir()
            (directory / manifest).touch()
            output = directory / "target.toml"
            target_config.seed_toml(directory, output, "")
            text = output.read_text()
            self.assertIn('enabled = ["asan"]', text)
            if slug == "swift":
                self.assertIn("[runner]", text)

        required_harnesses = {".py", ".rb", ".pl", ".php", ".js", ".mjs", ".ts", ".java", ".kt", ".kts", ".sh"}
        self.assertTrue(required_harnesses <= languages.all_harness_exts())
        for extension in required_harnesses:
            self.assertIsNotNone(languages.probe_dispatch(extension))
        self.assertIsNone(languages.probe_dispatch(".bogus"))

    def test_findings_only_runner_headers_output_caps_and_argument_tokens(self) -> None:
        scratch = self.tree(
            "python",
            f'target = "multilang"\nbuild_system = "python"\n[sanitizer]\nenabled = []\n'
            f'[runner]\nbin = "{sys.executable}"\nargs = ["{{TESTCASE}}"]\n',
        )
        clean = self.make_testcase(scratch / "clean.py", 'print("TESTCASE_EXECUTED")\n')
        bare = scratch / "bare.py"
        bare.write_text(
            'TARGET: sample:main:1\nHYPOTHESIS-ID: H_bare\nCATEGORY: state\nprint("TESTCASE_EXECUTED")\n'
        )
        huge = self.make_testcase(
            scratch / "huge.py", 'print("A" * 4096)\nprint("TESTCASE_EXECUTED")\n'
        )
        huge_crash = self.make_testcase(
            scratch / "huge-crash.py",
            'print("A" * 2048)\nprint("ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef")\n'
            'print("B" * 2048)\nprint("TESTCASE_EXECUTED")\n',
        )
        traceback = self.make_testcase(scratch / "traceback.py", 'raise RecursionError("forced")\n')
        dry = self.run_probe(clean, "--dry-run")
        self.assertEqual(dry.returncode, 0, dry.stdout + dry.stderr)
        self.assertIn("mode=generic", dry.stdout + dry.stderr)
        real = self.run_probe(clean)
        self.assertIn("TESTCASE_EXECUTED", real.stdout + real.stderr)
        self.assertIn("EXECUTION VERIFIED", real.stdout + real.stderr)
        bare_result = self.run_probe(bare)
        self.assertIn("TESTCASE_EXECUTED", bare_result.stdout + bare_result.stderr)
        self.assertIn(f"testcase={bare.resolve()}", bare.with_suffix(".asan.txt").read_text())

        cap_env = {
            "PROBE_ASAN_OUTPUT_MAX_BYTES": "1024", "PROBE_ASAN_OUTPUT_HEAD_BYTES": "256",
            "PROBE_ASAN_OUTPUT_TAIL_BYTES": "256",
        }
        clean_result = self.run_probe(huge, environment=cap_env)
        clean_output = huge.with_suffix(".asan.txt")
        self.assertLess(clean_output.stat().st_size, 1200)
        self.assertIn("truncated for storage after verdict classification", clean_output.read_text())
        self.assertIn("NO CRASHES", clean_result.stdout + clean_result.stderr)
        crash_result = self.run_probe(huge_crash, environment=cap_env)
        self.assertLess(huge_crash.with_suffix(".asan.txt").stat().st_size, 1200)
        self.assertIn("verdict=CRASH", crash_result.stdout + crash_result.stderr)
        self.assertIn("Traceback", (self.run_probe(traceback).stdout + self.run_probe(traceback).stderr))

        printer = self.executable(
            self.root / "argv-printer",
            "import sys\nprint('ARGV=' + ' '.join(sys.argv[1:]))\nprint('TESTCASE_EXECUTED')\n",
        )
        cases = (
            ("no-token", '["--flag"]', lambda path: f"ARGV=--flag {path}"),
            ("embedded", '["--input={TESTCASE}", "--flag"]', lambda path: f"ARGV=--input={path} --flag"),
        )
        for name, arguments, expected in cases:
            scratch = self.tree(
                name,
                f'target = "multilang"\nbuild_system = "custom"\n[sanitizer]\nenabled = []\n'
                f'[runner]\nbin = "{printer}"\nargs = {arguments}\n',
            )
            testcase = self.make_testcase(scratch / "input.txt")
            result = self.run_probe(testcase)
            self.assertIn(expected(testcase.resolve()), result.stdout + result.stderr)

        scratch = self.tree(
            "native-cli-args",
            f'target = "multilang"\nbuild_system = "cmake"\n'
            f'asan_bin = "{printer}"\n[sanitizer]\nenabled = ["asan"]\n'
            '[runner]\nargs = ["--input", "{TESTCASE}", "--sink", "{NULL_DEVICE}"]\n',
        )
        testcase = self.make_testcase(scratch / "native-input.bin")
        result = self.run_probe(testcase)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(
            f"ARGV=--input {testcase.resolve()} --sink {os.devnull}",
            result.stdout + result.stderr,
        )

    def test_typescript_relative_runner_and_interpreted_harness(self) -> None:
        ts_node = self.executable(
            self.target / "node_modules" / ".bin" / "ts-node",
            "import sys\nprint('TS_NODE_ARGV=' + ' '.join(sys.argv[1:]))\n",
        )
        scratch = self.tree(
            "typescript",
            'target = "multilang"\nbuild_system = "npm"\n[sanitizer]\nenabled = []\n'
            '[runner]\nbin = "node"\nargs = ["{TESTCASE}"]\n',
        )
        testcase = scratch / "testcase.ts"
        testcase.write_text(
            'TARGET: sample:main:1\nHYPOTHESIS-ID: H_ts\nCATEGORY: state\n'
            'console.log("TESTCASE_EXECUTED");\n',
            encoding="utf-8",
        )
        result = self.run_probe(testcase)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertRegex(result.stdout + result.stderr, r"TS_NODE_ARGV=--transpile-only --skip-project --compiler-options .*\.exec\.ts")
        self.assertTrue(ts_node.is_file())

        # sample-rust is an ASan target: probe resolves the relative asan_bin
        # against target_root and drives it under the sanitizer runner.
        rust_asan_bin = self.executable(
            self.target / "build-asan" / "sample-rust",
            "import sys\nprint('RUST_RUNNER_ARG=' + sys.argv[1])\nprint('TESTCASE_EXECUTED')\n",
        )
        sample_config = (ROOT / "output" / "samples" / "sample-rust" / "target.toml").read_text()
        scratch = self.tree("rust", sample_config)
        rust_case = self.make_testcase(scratch / "input.txt")
        result = self.run_probe(rust_case)
        self.assertIn("TESTCASE_EXECUTED", result.stdout + result.stderr)
        self.assertIn(f"RUST_RUNNER_ARG={rust_case.resolve()}", result.stdout + result.stderr)
        self.assertTrue(rust_asan_bin.is_file())

        harness = self.executable(
            scratch / "sidecar.py",
            "import sys\nprint('HARNESS_ARG=' + sys.argv[1])\nprint('TESTCASE_EXECUTED')\n",
        )
        sidecar_case = self.make_testcase(scratch / "sidecar-input.txt", harness=harness.name)
        result = self.run_probe(sidecar_case, environment={"PROBE_SANITIZER": "runner"})
        self.assertIn(f"HARNESS_ARG={sidecar_case.resolve()}", result.stdout + result.stderr)
        self.assertIn("TESTCASE_EXECUTED", result.stdout + result.stderr)

        bogus = scratch / "harness.bogus"
        bogus.touch()
        bogus_case = self.make_testcase(scratch / "bogus.txt", harness=bogus.name)
        result = self.run_probe(bogus_case, "--dry-run", environment={"PROBE_SANITIZER": "runner"})
        self.assertIn("unsupported extension", result.stdout + result.stderr)

    def test_sanitizer_selection_environment_race_and_swift_tokens(self) -> None:
        runner_body = """import os, sys
for name in ("ASAN_OPTIONS", "UBSAN_OPTIONS", "MSAN_OPTIONS", "TSAN_OPTIONS"):
    value = os.environ.get(name)
    print(name + ("_UNSET" if value is None else "_VALUE=" + value))
print("ARGV=" + " ".join(sys.argv[1:]))
print("TESTCASE_EXECUTED")
"""
        jobs: list[tuple[str, Path, tuple[str, ...], dict[str, str]]] = []
        for sanitizer in ("ubsan", "msan", "tsan"):
            runner = self.executable(self.target / f"{sanitizer}-runner", runner_body)
            scratch = self.tree(
                f"san-{sanitizer}",
                f'target = "multilang"\n[sanitizer]\nenabled = ["{sanitizer}"]\n'
                f'{sanitizer}_bin = "{runner}"\n'
                f'{sanitizer}_options = "{sanitizer}_extra=1"\n',
            )
            testcase = self.make_testcase(scratch / "input.dat")
            jobs.append((sanitizer, testcase, (), {
                "ASAN_OPTIONS": "leak", "UBSAN_OPTIONS": "ubsan_env=1",
                "MSAN_OPTIONS": "msan_env=1", "TSAN_OPTIONS": "tsan_env=1",
            }))
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                sanitizer: executor.submit(self.run_probe, testcase, *arguments, environment=env)
                for sanitizer, testcase, arguments, env in jobs
            }
            results = {name: future.result() for name, future in futures.items()}
        for sanitizer, testcase, _, _ in jobs:
            output = results[sanitizer].stdout + results[sanitizer].stderr
            upper = sanitizer.upper()
            self.assertIn(f"{upper}_OPTIONS_VALUE=", output)
            self.assertIn("halt_on_error=1", output)
            self.assertIn(f"{sanitizer}_extra=1", output)
            self.assertIn(f"{sanitizer}_env=1", output)
            for other in ("ASAN", "UBSAN", "MSAN", "TSAN"):
                if other != upper:
                    self.assertIn(f"{other}_OPTIONS_UNSET", output)
            self.assertIn(f"ARGV={testcase.resolve()}", output)
            self.assertIn(f"SANITIZER_RUN_HEADER: sanitizer={sanitizer}", testcase.with_suffix(".asan.txt").read_text())

        asan = self.executable(self.target / "asan-runner", runner_body)
        scratch = self.tree(
            "multi-san",
            f'target = "multilang"\nasan_bin = "{asan}"\ntsan_bin = "{self.target / "tsan-runner"}"\n'
            '[sanitizer]\nenabled = ["tsan", "asan"]\n',
        )
        testcase = self.make_testcase(scratch / "input.dat")
        default = self.run_probe(testcase, "--dry-run")
        self.assertIn("sanitizer=tsan", default.stdout + default.stderr)
        override = self.run_probe(testcase, "--dry-run", environment={"PROBE_SANITIZER": "asan"})
        self.assertIn("sanitizer=asan", override.stdout + override.stderr)
        disabled = self.run_probe(testcase, "--dry-run", environment={"PROBE_SANITIZER": "msan"})
        self.assertEqual(disabled.returncode, 2)
        self.assertIn("not enabled", disabled.stdout + disabled.stderr)

        race_runner = self.executable(self.target / "race-runner", runner_body)
        scratch = self.tree(
            "race",
            f'target = "multilang"\n[sanitizer]\nenabled = ["race"]\n'
            f'[runner]\nbin = "{race_runner}"\nargs = ["-race", "{{TESTCASE}}"]\n',
        )
        race_case = self.make_testcase(scratch / "input.dat")
        race = self.run_probe(race_case, environment={
            "ASAN_OPTIONS": "leak", "UBSAN_OPTIONS": "leak",
            "MSAN_OPTIONS": "leak", "TSAN_OPTIONS": "leak",
        })
        race_output = race.stdout + race.stderr
        for name in ("ASAN", "UBSAN", "MSAN", "TSAN"):
            self.assertIn(f"{name}_OPTIONS_UNSET", race_output)
        self.assertIn(f"ARGV=-race {race_case.resolve()}", race_output)

        swift_runner = self.executable(self.target / "swift-runner", runner_body)
        mapping = {"asan": "address", "ubsan": "undefined", "tsan": "thread"}
        for sanitizer, swift_name in mapping.items():
            scratch = self.tree(
                f"swift-{sanitizer}",
                f'target = "multilang"\nbuild_system = "swift"\n[sanitizer]\nenabled = ["{sanitizer}"]\n'
                f'[runner]\nbin = "{swift_runner}"\n'
                'args = ["-sanitize={SWIFT_SANITIZER}", "{SANITIZER}", "{TESTCASE}"]\n'
                'env = ["SWIFT_SAN={SWIFT_SANITIZER}", "ACTIVE_SAN={SANITIZER}"]\n',
            )
            case = self.make_testcase(scratch / "input.dat")
            result = self.run_probe(case, environment={"SANITIZER_RUNS": "1"})
            output = result.stdout + result.stderr
            self.assertIn(f"ARGV=-sanitize={swift_name} {sanitizer} {case.resolve()}", output)
        scratch = self.tree(
            "swift-msan",
            f'target = "multilang"\nbuild_system = "swift"\n[sanitizer]\nenabled = ["msan"]\n'
            f'[runner]\nbin = "{swift_runner}"\nargs = ["-sanitize={{SWIFT_SANITIZER}}", "{{TESTCASE}}"]\n',
        )
        result = self.run_probe(self.make_testcase(scratch / "input.dat"))
        self.assertEqual(result.returncode, 2)
        self.assertIn("Swift runner does not support sanitizer 'msan'", result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
