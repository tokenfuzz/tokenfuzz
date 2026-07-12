#!/usr/bin/env python3
"""Crash-rate reverification regression tests."""

from __future__ import annotations

import concurrent.futures
import inspect
import os
import shutil
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import benchmark_runner


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
        config_in_output: bool = False,
        slug: str | None = None,
    ) -> tuple[Path, str]:
        target = self.root / name
        target.mkdir()
        slug = slug or name
        config = (
            f'target = "{slug}"\n'
            f'asan_bin = "{binary}"\n'
            "[sanitizer]\n"
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

    def test_pool_rebuild_requires_a_measured_canonical_report(self) -> None:
        source = inspect.getsource(benchmark_runner.rebuild_pool)
        self.assertIn('"## Expected sanitizer output"', source)
        self.assertIn(r'r"^CRASH_RATE:\s*[0-9]+/[0-9]+"', source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
