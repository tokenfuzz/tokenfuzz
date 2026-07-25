#!/usr/bin/env python3
"""Crash-rate reverification regression tests."""

from __future__ import annotations

import concurrent.futures
import inspect
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import benchmark_runner
import crash_bundle


DIAGNOSTIC = (
    "==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010\n"
    "READ of size 8 at 0x602000000010 thread T0\n"
    "SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free\n"
)


class BenchmarkReverifyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="benchmark-reverify-")
        self.root = Path(self.temporary.name)
        self.config_dirs: list[Path] = []

    def tearDown(self) -> None:
        for path in self.config_dirs:
            shutil.rmtree(path, ignore_errors=True)
        self.temporary.cleanup()

    def make_target(
        self,
        name: str,
        behavior: str = "crash",
        *,
        binary: str = "build-asan/src/stub",
        library: str = "",
        config_in_output: bool = False,
        slug: str | None = None,
    ) -> tuple[Path, str]:
        target = self.root / name
        target.mkdir()
        slug = slug or name
        if library:
            instrumented = target / library
            instrumented.parent.mkdir(parents=True, exist_ok=True)
            instrumented.write_bytes(b"!<arch>\n")
        config = (
            f'target = "{slug}"\n'
            f'asan_bin = "{binary}"\n'
            + (f'asan_lib = "{library}"\n' if library else "")
            + "[sanitizer]\n"
            'enabled = ["asan"]\n'
        )
        if config_in_output:
            config_dir = ROOT / "output" / slug
            config_dir.mkdir(parents=True)
            (config_dir / "target.toml").write_text(config, encoding="utf-8")
            self.config_dirs.append(config_dir)
        else:
            (target / "target.toml").write_text(config, encoding="utf-8")

        executable = target / binary.replace("build-asan/", "build-asan/")
        executable.parent.mkdir(parents=True, exist_ok=True)
        if behavior == "missing":
            return target, slug
        bodies = {
            "crash": (
                "print('==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010')\n"
                "print('SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free')\n"
                "raise SystemExit(1)\n"
            ),
            "clean": "print('ran clean')\n",
            "invalid": "print('usage: missing required option', file=sys.stderr)\nraise SystemExit(2)\n",
            "flag-crash": (
                "if '--boom' in sys.argv[1:]:\n"
                "    print('==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010')\n"
                "    print('SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free')\n"
                "    raise SystemExit(1)\n"
                "print('ran clean')\n"
            ),
            "reject-leading-bin": (
                "if len(sys.argv) > 1 and sys.argv[1] == 'stub':\n"
                "    print('unexpected duplicated executable argument', file=sys.stderr)\n"
                "    raise SystemExit(2)\n"
                "print('==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010')\n"
                "print('SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free')\n"
                "raise SystemExit(1)\n"
            ),
            "ordered-crash": (
                "if len(sys.argv) == 5 and sys.argv[1] == '--input' "
                "and sys.argv[3:] == ['--sink', '/dev/null']:\n"
                "    print('==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010')\n"
                "    print('SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free')\n"
                "    raise SystemExit(1)\n"
                "print('ran clean')\n"
            ),
        }
        executable.write_text(
            f"#!{sys.executable}\nimport sys\n{bodies[behavior]}", encoding="utf-8"
        )
        executable.chmod(0o755)
        return target, slug

    def make_crash(self, name: str, *, footer: str = "") -> Path:
        crash = self.root / name / "crashes" / "CRASH-0001"
        crash.mkdir(parents=True)
        (crash / "sanitizer.txt").write_text(DIAGNOSTIC + footer, encoding="utf-8")
        (crash / "poc.bin").write_bytes(b"sample-bytes\n")
        return crash

    def make_harness_crash(self, name: str) -> Path:
        """A crash whose evidence is a harness binary the agent compiled.

        Copied from a real executable because the replay contract identifies a
        harness by asking `file` what it is, not by name.
        """
        crash = self.make_crash(name)
        (crash / "poc.bin").unlink()
        shutil.copy2(sys.executable, crash / "harness")
        return crash

    def replay_environment(self, crash: Path, target: Path, slug: str) -> dict[str, str]:
        """Env handed to the replay, with run-sanitizer-multi stubbed out.

        Only the sanitizer runner is stubbed: resolving the replay contract
        stays real, so this measures what the contract actually produced.
        """
        captured: dict[str, str] = {}
        real_run = benchmark_runner.subprocess.run

        def fake_run(command, **kwargs):
            if "run-sanitizer-multi" not in str(command[0]):
                return real_run(command, **kwargs)
            environment = kwargs.get("env") or {}
            captured.update(environment)
            Path(environment["SAN_OUTPUT_FILE"]).write_text(
                f"CRASH_RATE: 5/5\n[run-sanitizer-multi] SUCCESS_RATE: 0/5\n{DIAGNOSTIC}",
                encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0)

        with mock.patch.dict(os.environ, {"AUDIT_BUILD_SUFFIX": ""}), \
                mock.patch.object(benchmark_runner.subprocess, "run", fake_run):
            self.assertTrue(benchmark_runner.reverify_one_crash(crash, target, slug))
        return captured

    @staticmethod
    def reverify(pool: Path, target: Path, slug: str) -> int:
        return benchmark_runner.reverify_pool_crash_rates(pool, target, slug, "test")

    def test_reverification_outcomes_and_replay_contracts(self) -> None:
        crash_target, crash_slug = self.make_target("crash-target")
        clean_target, clean_slug = self.make_target("clean-target", "clean")
        invalid_target, invalid_slug = self.make_target("invalid-target", "invalid")
        missing_target, missing_slug = self.make_target("missing-target", "missing")
        flag_target, flag_slug = self.make_target("flag-target", "flag-crash")
        leading_target, leading_slug = self.make_target(
            "leading-target", "reject-leading-bin"
        )
        ordered_target, ordered_slug = self.make_target(
            "ordered-target", "ordered-crash"
        )

        reproducing = self.make_crash("reproducing")
        clean = self.make_crash("clean")
        invalid = self.make_crash("invalid")
        source_harness = self.make_crash("source-harness")
        (source_harness / "harness.c").write_text(
            "int main(void) { return 0; }\n", encoding="utf-8"
        )
        measured = self.make_crash("measured", footer="CRASH_RATE: 3/5\n")
        missing = self.make_crash("missing")
        with_args = self.make_crash("with-args")
        (with_args / "repro.cmd").write_text("--boom {TESTCASE}\n", encoding="utf-8")
        without_args = self.make_crash("without-args")
        normalized = self.make_crash("normalized")
        (normalized / "repro.cmd").write_text("stub {TESTCASE}\n", encoding="utf-8")
        ordered_pool = self.root / "ordered"
        ordered_case = self.root / "ordered-input.bin"
        ordered_case.write_bytes(b"sample-bytes\n")
        ordered_sanitizer = self.root / "ordered-sanitizer.txt"
        ordered_sanitizer.write_text(DIAGNOSTIC, encoding="utf-8")
        _, ordered_id = crash_bundle.materialize(
            ordered_pool, "1", ordered_case, ordered_sanitizer, "asan", "generic",
            args=("--input", "{TESTCASE}", "--sink", "/dev/null"),
        )
        ordered = ordered_pool / "crashes" / ordered_id

        unchanged = {
            path: (path / "sanitizer.txt").read_bytes()
            for path in (invalid, source_harness, measured, missing)
        }
        jobs = {
            "reproducing": (reproducing.parent.parent, crash_target, crash_slug),
            "clean": (clean.parent.parent, clean_target, clean_slug),
            "invalid": (invalid.parent.parent, invalid_target, invalid_slug),
            "source": (source_harness.parent.parent, clean_target, clean_slug),
            "measured": (measured.parent.parent, crash_target, crash_slug),
            "missing": (missing.parent.parent, missing_target, missing_slug),
            "with_args": (with_args.parent.parent, flag_target, flag_slug),
            "without_args": (without_args.parent.parent, flag_target, flag_slug),
            "normalized": (normalized.parent.parent, leading_target, leading_slug),
            "ordered": (ordered_pool, ordered_target, ordered_slug),
        }
        with mock.patch.dict(os.environ, {"AUDIT_BUILD_SUFFIX": ""}), \
                concurrent.futures.ThreadPoolExecutor(max_workers=len(jobs)) as executor:
            futures = {
                name: executor.submit(self.reverify, *arguments)
                for name, arguments in jobs.items()
            }
            results = {name: future.result() for name, future in futures.items()}

        self.assertEqual(results["reproducing"], 1)
        self.assertIn("CRASH_RATE: 5/5", (reproducing / "sanitizer.txt").read_text())
        self.assertEqual(results["clean"], 1)
        clean_text = (clean / "sanitizer.txt").read_text()
        self.assertIn("CRASH_RATE: 0/5", clean_text)
        self.assertIn("heap-use-after-free child.c:91", clean_text)
        for name, path in (
            ("invalid", invalid), ("source", source_harness),
            ("measured", measured), ("missing", missing),
        ):
            self.assertEqual(results[name], 0)
            self.assertEqual((path / "sanitizer.txt").read_bytes(), unchanged[path])
        self.assertIn("CRASH_RATE: 5/5", (with_args / "sanitizer.txt").read_text())
        self.assertIn("CRASH_RATE: 0/5", (without_args / "sanitizer.txt").read_text())
        self.assertIn("CRASH_RATE: 5/5", (normalized / "sanitizer.txt").read_text())
        self.assertIn("CRASH_RATE: 5/5", (ordered / "sanitizer.txt").read_text())

    def test_split_config_suffix_and_unsafe_path_resolution(self) -> None:
        nonce = uuid.uuid4().hex
        split_slug = f"reverify-split-{nonce}"
        split_target, _ = self.make_target(
            "split-target", slug=split_slug, config_in_output=True
        )
        split_crash = self.make_crash("split-crash")
        with mock.patch.dict(os.environ, {"AUDIT_BUILD_SUFFIX": ""}):
            self.assertEqual(self.reverify(split_crash.parent.parent, split_target, split_slug), 1)
        self.assertIn("CRASH_RATE: 5/5", (split_crash / "sanitizer.txt").read_text())

        suffix_slug = f"reverify-suffix-{nonce}"
        suffix_target, _ = self.make_target(
            "suffix-target", "missing", slug=suffix_slug, config_in_output=True
        )
        suffix_binary = suffix_target / "build-asan-img42" / "src" / "stub"
        suffix_binary.parent.mkdir(parents=True)
        suffix_binary.write_text(
            f"#!{sys.executable}\nprint('==4242==ERROR: AddressSanitizer: heap-use-after-free')\n"
            "print('SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free')\n"
            "raise SystemExit(1)\n",
            encoding="utf-8",
        )
        suffix_binary.chmod(0o755)
        suffix_crash = self.make_crash("suffix-crash")
        with mock.patch.dict(os.environ, {"AUDIT_BUILD_SUFFIX": "-img42"}):
            self.assertEqual(self.reverify(suffix_crash.parent.parent, suffix_target, suffix_slug), 1)
        self.assertIn("CRASH_RATE: 5/5", (suffix_crash / "sanitizer.txt").read_text())

        unsafe_slug = f"reverify-unsafe-{nonce}"
        unsafe_target, _ = self.make_target(
            "unsafe-target",
            binary="subdir/../build-asan/src/stub",
            slug=unsafe_slug,
            config_in_output=True,
        )
        unsafe_crash = self.make_crash("unsafe-crash")
        before = (unsafe_crash / "sanitizer.txt").read_bytes()
        with mock.patch.dict(os.environ, {"AUDIT_BUILD_SUFFIX": ""}):
            self.assertEqual(self.reverify(unsafe_crash.parent.parent, unsafe_target, unsafe_slug), 0)
        self.assertEqual((unsafe_crash / "sanitizer.txt").read_bytes(), before)

    def test_a_hand_compiled_harness_replay_gets_the_library_directory(self) -> None:
        # bin/probe bakes this directory in as an rpath; a harness the agent
        # compiled by hand has none, so without it the replay dies in the
        # loader and a reproducing crash is demoted.
        target, slug = self.make_target(
            "harness-target", "missing", library="build-asan/lib/libthing.a",
        )
        captured = self.replay_environment(
            self.make_harness_crash("harness-pool"), target, slug,
        )
        expected = str(target / "build-asan" / "lib")
        for variable in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
            self.assertIn(expected, captured.get(variable, "").split(os.pathsep))

    def test_a_configured_target_replay_keeps_its_own_loader_path(self) -> None:
        # The configured binary is launched the way the target itself is.
        # Overriding its loader path could resolve a different library than a
        # normal run would and turn a clean replay into a counted crash.
        target, slug = self.make_target(
            "cli-target", library="build-asan/lib/libthing.a",
        )
        captured = self.replay_environment(
            self.make_crash("cli-pool"), target, slug,
        )
        for variable in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
            self.assertEqual(
                captured.get(variable, ""), os.environ.get(variable, ""),
            )

    def test_an_unmeasurable_replay_keeps_its_output_for_diagnosis(self) -> None:
        target, slug = self.make_target("silent-target", "missing")
        crash = self.make_harness_crash("silent-pool")
        real_run = benchmark_runner.subprocess.run

        def fake_run(command, **kwargs):
            if "run-sanitizer-multi" not in str(command[0]):
                return real_run(command, **kwargs)
            Path((kwargs.get("env") or {})["SAN_OUTPUT_FILE"]).write_text(
                "dyld: Library not loaded: @rpath/libthing.dylib\n", encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0)

        with mock.patch.dict(os.environ, {"AUDIT_BUILD_SUFFIX": ""}), \
                mock.patch.object(benchmark_runner.subprocess, "run", fake_run):
            self.assertFalse(benchmark_runner.reverify_one_crash(crash, target, slug))
        self.assertIn(
            "Library not loaded",
            (crash / ".audit" / "reverify.log").read_text(encoding="utf-8"),
        )

    def test_pool_rebuild_requires_a_measured_canonical_report(self) -> None:
        source = inspect.getsource(benchmark_runner.rebuild_pool)
        self.assertIn('"## Expected sanitizer output"', source)
        self.assertIn(r'r"^CRASH_RATE:\s*[0-9]+/[0-9]+"', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
