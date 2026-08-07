#!/usr/bin/env python3
"""Crash-rate reverification regression tests."""

from __future__ import annotations

import base64
import concurrent.futures
import inspect
import json
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
import validation_receipt


DIAGNOSTIC = (
    "==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010\n"
    "READ of size 8 at 0x602000000010 thread T0\n"
    "SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free\n"
)


SANITIZER_DIAGNOSTICS = {
    "ubsan": (
        "src/parse.c:91:17: runtime error: index 12 out of bounds "
        "for type 'char [8]'\n"
        "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/parse.c:91\n"
    ),
    "msan": (
        "==4242==WARNING: MemorySanitizer: use-of-uninitialized-value\n"
        "SUMMARY: MemorySanitizer: use-of-uninitialized-value src/parse.c:91\n"
    ),
    "tsan": (
        "==4242==WARNING: ThreadSanitizer: data race (pid=4242)\n"
        "SUMMARY: ThreadSanitizer: data race src/parse.c:91 in app_parse\n"
    ),
}


def multi_run_transcript(runs: list[str]) -> str:
    """One run-sanitizer-multi output file, in its real per-repetition shape."""
    patterns = ("ERROR:", "runtime error:", "MOZ_CRASH", "DATA RACE")
    crashed = sum(1 for run in runs if any(p in run for p in patterns))
    body = "".join(
        f"=== Run {index}/{len(runs)} ===\n{run}\n"
        for index, run in enumerate(runs, start=1)
    )
    return (
        f"{body}\n=== SUMMARY ===\nCRASH_RATE: {crashed}/{len(runs)}\n"
        f"[run-sanitizer-multi] SUCCESS_RATE: {len(runs) - crashed}/{len(runs)}\n"
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
        ubsan_library: str = "",
        sanitizer_binaries: tuple[str, ...] = (),
        config_in_output: bool = False,
        slug: str | None = None,
    ) -> tuple[Path, str]:
        target = self.root / name
        target.mkdir()
        slug = slug or name
        for relative in (library, ubsan_library):
            if not relative:
                continue
            instrumented = target / relative
            instrumented.parent.mkdir(parents=True, exist_ok=True)
            instrumented.write_bytes(b"!<arch>\n")
        for sanitizer in sanitizer_binaries:
            override = target / f"build-{sanitizer}" / "stub"
            override.parent.mkdir(parents=True, exist_ok=True)
            override.write_text(f"#!/bin/sh\necho {sanitizer}\n", encoding="utf-8")
            override.chmod(0o755)
        enabled = ", ".join(f'"{name}"' for name in ("asan", *sanitizer_binaries))
        config = (
            f'target = "{slug}"\n'
            f'asan_bin = "{binary}"\n'
            + (f'asan_lib = "{library}"\n' if library else "")
            + "[sanitizer]\n"
            f"enabled = [{enabled}]\n"
            + "".join(
                f'{sanitizer}_bin = "build-{sanitizer}/stub"\n'
                for sanitizer in sanitizer_binaries
            )
            + (f'ubsan_lib = "{ubsan_library}"\n' if ubsan_library else "")
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

    def replay_environment(
        self, crash: Path, target: Path, slug: str,
    ) -> tuple[list[str], dict[str, str]]:
        """Command and env handed to the replay, with the runner stubbed out.

        Only the sanitizer runner is stubbed: resolving the replay contract
        stays real, so this measures what the contract actually produced.
        """
        captured: dict[str, str] = {}
        command_used: list[str] = []
        real_run = benchmark_runner.subprocess.run
        transcript = multi_run_transcript(
            [(crash / "sanitizer.txt").read_text(encoding="utf-8")] * 5
        )

        def fake_run(command, **kwargs):
            if "run-sanitizer-multi" not in str(command[0]):
                return real_run(command, **kwargs)
            environment = kwargs.get("env") or {}
            captured.update(environment)
            command_used.extend(str(part) for part in command)
            Path(environment["SAN_OUTPUT_FILE"]).write_text(
                transcript, encoding="utf-8",
            )
            return subprocess.CompletedProcess(command, 0)

        with mock.patch.dict(os.environ, {"AUDIT_BUILD_SUFFIX": ""}), \
                mock.patch.object(benchmark_runner.subprocess, "run", fake_run):
            self.assertTrue(benchmark_runner.reverify_one_crash(crash, target, slug))
        return command_used, captured

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
            "harness-target", "missing", library="build-asan/lib/libthing.dylib",
        )
        _, captured = self.replay_environment(
            self.make_harness_crash("harness-pool"), target, slug,
        )
        expected = str(target / "build-asan" / "lib")
        for variable in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
            self.assertIn(expected, captured.get(variable, "").split(os.pathsep))

    def test_replay_restores_the_options_the_crash_was_found_under(self) -> None:
        # AGENTS.md tells agents to shape the allocator to surface a fault
        # (`ASAN_OPTIONS=quarantine_size_mb=1`). The runner header records what
        # was in effect; a replay that drops it is not a replay of that crash,
        # and the crash reads as clean.
        target, slug = self.make_target("options-target", "missing")
        crash = self.make_harness_crash("options-pool")
        options = "quarantine_size_mb=1:detect_stack_use_after_return=1"
        (crash / "sanitizer.txt").write_text(
            "ASAN_RUN_HEADER: sanitizer=asan runs=1 mode=generic testcase=x "
            f"env_options_b64={base64.b64encode(options.encode()).decode()} "
            "started=2026-07-25T00:00:00Z\n" + DIAGNOSTIC,
            encoding="utf-8",
        )
        _, captured = self.replay_environment(crash, target, slug)
        self.assertEqual(captured.get("ASAN_OPTIONS"), options)

    def test_replay_does_not_inherit_unrecorded_runtime_options(self) -> None:
        target, slug = self.make_target("empty-options-target", "missing")
        cases = {
            "explicitly empty": (
                "ASAN_RUN_HEADER: sanitizer=asan env_options_b64= started=x\n",
                "",
            ),
            "legacy header": (
                "ASAN_RUN_HEADER: sanitizer=asan started=x\n",
                None,
            ),
        }
        for name, (header, expected) in cases.items():
            with self.subTest(name):
                crash = self.make_harness_crash(f"empty-options-{name.replace(' ', '-')}")
                (crash / "sanitizer.txt").write_text(
                    header + DIAGNOSTIC, encoding="utf-8",
                )
                with mock.patch.dict(os.environ, {"ASAN_OPTIONS": "current_only=1"}):
                    _, captured = self.replay_environment(crash, target, slug)
                if expected is None:
                    self.assertNotIn("ASAN_OPTIONS", captured)
                else:
                    self.assertEqual(captured.get("ASAN_OPTIONS"), expected)

    def test_invalid_recorded_options_leave_replay_unmeasured(self) -> None:
        target, slug = self.make_target("invalid-options-target", "missing")
        invalid = {
            "invalid base64": "%",
            "embedded NUL": "AA==",
            "oversized": base64.b64encode(b"x" * (64 * 1024 + 1)).decode(),
        }
        for name, encoded in invalid.items():
            with self.subTest(name):
                crash = self.make_harness_crash(f"invalid-options-{name.replace(' ', '-')}")
                original = (
                    f"ASAN_RUN_HEADER: sanitizer=asan env_options_b64={encoded} started=x\n"
                    + DIAGNOSTIC
                )
                (crash / "sanitizer.txt").write_text(original, encoding="utf-8")
                self.assertEqual(
                    benchmark_runner.reverify_pool_crash_rates(
                        crash.parent.parent, target, slug, "test",
                    ),
                    0,
                )
                self.assertEqual(
                    (crash / "sanitizer.txt").read_text(encoding="utf-8"),
                    original,
                )
                self.assertIn(
                    "recorded sanitizer options are unusable",
                    (crash / ".audit" / "reverify.log").read_text(encoding="utf-8"),
                )

    def test_successful_reverification_rebinds_current_receipt(self) -> None:
        target, slug = self.make_target("receipt-target")
        crash = self.make_crash("receipt-pool")
        (crash / "report.md").write_text(
            "# Lifetime issue\n", encoding="utf-8",
        )
        validation_receipt.write(
            crash, kind="crash", state="reportable",
            attacker_controls=["bytes"],
        )
        self.assertIsNotNone(validation_receipt.read_current(crash))

        def reverify(directory, *_args, **_kwargs):
            with (directory / "sanitizer.txt").open("a", encoding="utf-8") as stream:
                stream.write("\nCRASH_RATE: 5/5\n")
            return True

        with mock.patch.object(
            benchmark_runner, "reverify_one_crash", side_effect=reverify,
        ):
            self.assertEqual(
                benchmark_runner.reverify_pool_crash_rates(
                    crash.parent.parent, target, slug, "test",
                ),
                1,
            )
        self.assertIsNotNone(validation_receipt.read_current(crash))

    def test_a_harness_replays_under_its_own_sanitizer(self) -> None:
        # Through the ASan wrapper a UBSan harness gets ASAN_OPTIONS and never
        # UBSAN_OPTIONS, so halt_on_error is unset, it exits 0, and a real
        # crash reads as clean. Its library follows the same sanitizer: the
        # ASan build directory holds the wrong instrumented library.
        target, slug = self.make_target(
            "ubsan-target", "missing",
            library="build-asan/lib/libthing.dylib",
            ubsan_library="build-ubsan/lib/libthing.dylib",
        )
        crash = self.make_harness_crash("ubsan-pool")
        (crash / "sanitizer.txt").write_text(
            "src/parse.c:91:17: runtime error: index 12 out of bounds for type 'char [8]'\n"
            "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/parse.c:91:17\n",
            encoding="utf-8",
        )
        command, captured = self.replay_environment(crash, target, slug)
        self.assertEqual(command[1], "ubsan")
        self.assertEqual(captured.get("UBSAN_GENERIC_BIN"), str(crash / "harness"))
        # A harness takes no testcase. bin/run-asan reads only its own flag;
        # the others fall back to it through lib/sanitizer_run.py.
        for flag in ("ASAN_GENERIC_SKIP_TESTCASE", "SANITIZER_GENERIC_SKIP_TESTCASE"):
            self.assertEqual(captured.get(flag), "1")
        for variable in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
            entries = captured.get(variable, "").split(os.pathsep)
            self.assertIn(str(target / "build-ubsan" / "lib"), entries)
            self.assertNotIn(str(target / "build-asan" / "lib"), entries)

    def test_raw_diagnostics_select_their_own_sanitizer(self) -> None:
        target, slug = self.make_target("raw-sanitizers", "missing")
        fixtures = {
            "asan": DIAGNOSTIC,
            "ubsan": (
                "src/parse.c:91:17: runtime error: index 12 out of bounds "
                "for type 'char [8]'\n"
                "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior "
                "src/parse.c:91:17\n"
            ),
            "msan": "WARNING: MemorySanitizer: use-of-uninitialized-value\n",
            "tsan": "WARNING: ThreadSanitizer: data race\n",
            "race": "WARNING: DATA RACE\nRead at 0x00 by goroutine 1\n",
        }
        for sanitizer, diagnostic in fixtures.items():
            with self.subTest(sanitizer=sanitizer):
                crash = self.make_harness_crash(f"raw-{sanitizer}")
                (crash / "sanitizer.txt").write_text(
                    diagnostic, encoding="utf-8",
                )
                resolved = benchmark_runner._resolve_reverify_fields(
                    crash, target, slug,
                )
                self.assertIsNotNone(resolved)
                self.assertEqual(resolved[0]["SAN"], sanitizer)

    def reproducing(self, original: str, runs: list[str]) -> int:
        return benchmark_runner._runs_reproducing(
            original, multi_run_transcript(runs),
        )

    def test_the_measured_rate_counts_only_the_original_fault(self) -> None:
        ubsan_bounds = (
            "src/parse.c:91:17: runtime error: index 12 out of bounds "
            "for type 'char [8]'\n"
        )
        ubsan_space = (
            "src/parse.c:91:17: runtime error: load of address 0x1 "
            "with insufficient space for an object of type 'char'\n"
        )
        stack_overflow = (
            "==4242==ERROR: AddressSanitizer: stack-overflow on address 0x1\n"
        )
        # Without a parseable frame the primitive is all the evidence
        # available; another sanitizer's and another primitive are not equal.
        cases = {
            "summary-only diagnostic": (
                DIAGNOSTIC, [DIAGNOSTIC.replace(":91", ":117")], 1,
            ),
            "same UBSan class": (ubsan_bounds, [ubsan_bounds], 1),
            "other UBSan class": (ubsan_bounds, [ubsan_space], 0),
            "other sanitizer": (ubsan_bounds, [DIAGNOSTIC], 0),
            "other TSan primitive": (
                "WARNING: ThreadSanitizer: data race\n",
                ["WARNING: ThreadSanitizer: heap-use-after-free\n"],
                0,
            ),
            "double-free reported twice over": (
                "ERROR: AddressSanitizer: attempting double-free on 0x1\n",
                ["SUMMARY: AddressSanitizer: double-free child.c:91\n"],
                1,
            ),
            # The transcript holds every repetition. A rate read off the whole
            # of it counts an unrelated fault as a reproduction, and rejects a
            # replay outright when only its last run diverged.
            "one run of five diverged": (
                DIAGNOSTIC, [stack_overflow] + [DIAGNOSTIC] * 4, 4,
            ),
            "only the last run matched": (
                DIAGNOSTIC, [stack_overflow] * 4 + [DIAGNOSTIC], 1,
            ),
            "no run matched": (DIAGNOSTIC, [stack_overflow] * 5, 0),
        }
        for name, (original, runs, expected) in cases.items():
            with self.subTest(name):
                self.assertEqual(self.reproducing(original, runs), expected)

    def test_a_reproduction_matches_the_exact_reported_fault_site(self) -> None:
        # Two unrelated overflows in one binary share a primitive. Counting one
        # as the other's reproduction confirms the wrong bug at the wrong rate.
        def report(function: str, location: str) -> str:
            return (
                "==4242==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
                f"    #0 0x10a in {function} {location}\n"
                f"SUMMARY: AddressSanitizer: heap-buffer-overflow {location} in {function}\n"
            )

        original = report(
            "app_parse", "targets/sample/src/front/parser.c:91",
        )
        self.assertEqual(
            self.reproducing(
                original,
                [report(
                    "app_parse",
                    "/workspace/targets/sample/src/front/parser.c:91",
                )] * 3,
            ),
            3,
            "a scrubbed workspace prefix does not change the source location",
        )
        self.assertEqual(
            self.reproducing(
                original,
                [report("app_parse", "targets/sample/vendor/back/parser.c:91")] * 3,
            ),
            0,
            "a duplicate basename in another directory is another fault",
        )
        self.assertEqual(
            self.reproducing(
                original,
                [report("app_parse", "targets/sample/src/front/parser.c:117")] * 3,
            ),
            0,
            "another line in the same function and file is another fault",
        )
        self.assertEqual(
            self.reproducing(original, [report("app_render", "src/render.c:12")] * 3),
            0,
            "another function is another fault",
        )
        # No parseable frame on either side leaves the primitive to stand alone
        # rather than reject a real reproduction.
        self.assertEqual(self.reproducing(DIAGNOSTIC, [DIAGNOSTIC] * 2), 2)
        # Whether a symbolizer is on PATH belongs to the host at replay time,
        # not to the fault. bin/run-asan symbolizes only when one is available,
        # so a regeneration on a host without it produces module offsets for
        # the very same crash — which must not read as a different one.
        unsymbolized = report("app_parse", "(targets/sample/build-asan/app+0x11cc1d)")
        self.assertEqual(self.reproducing(original, [unsymbolized] * 3), 3)
        self.assertEqual(self.reproducing(unsymbolized, [original] * 3), 3)

    def test_an_uncharacterised_fault_measures_nothing(self) -> None:
        # A fragment whose report headline never reached disk cannot be reduced
        # to a fault to compare. Counting whatever the replay crashed with as
        # its reproduction asserts a rate for a crash nothing confirmed; the
        # caller's unmeasured path keeps the evidence and leaves the rate unset.
        fragment = "SCARINESS: 41 (wild-addr-read)\n"
        self.assertIsNone(benchmark_runner.crash_artifacts.sanitizer_fault_key(fragment))
        self.assertEqual(self.reproducing(fragment, [DIAGNOSTIC] * 3), 0)

    def test_an_unconfigured_library_leaves_the_loader_path_alone(self) -> None:
        # Path("") is the working directory, so an unset library must not reach
        # the loader path as an empty entry.
        target, slug = self.make_target("nolib-target", "missing")
        crash = self.make_harness_crash("nolib-pool")
        with mock.patch.dict(os.environ, {"LD_LIBRARY_PATH": "/sentinel/ld"}):
            _, captured = self.replay_environment(crash, target, slug)
        self.assertEqual(captured.get("LD_LIBRARY_PATH"), "/sentinel/ld")
        self.assertNotIn("DYLD_LIBRARY_PATH", captured)

    def test_a_configured_target_replay_keeps_its_own_loader_path(self) -> None:
        # The configured binary is launched the way the target itself is.
        # Overriding its loader path could resolve a different library than a
        # normal run would and turn a clean replay into a counted crash.
        target, slug = self.make_target(
            "cli-target", library="build-asan/lib/libthing.a",
        )
        _, captured = self.replay_environment(
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

    def rebuild_tool_calls(
        self, bench: Path, *, dry_run: bool = False,
    ) -> list[tuple[str, tuple]]:
        """Tools rebuild_pool invokes, with everything but the tools stubbed."""
        calls: list[tuple[str, tuple]] = []

        def fake_run_tool(name, *args, **kwargs):
            calls.append((name, args))
            return 0

        with mock.patch.object(benchmark_runner.metrics, "build_pool"), \
                mock.patch.object(benchmark_runner.metrics, "relocate_experiments"), \
                mock.patch.object(benchmark_runner, "benchmark_target_config"), \
                mock.patch.object(benchmark_runner, "_decision_environment"), \
                mock.patch.object(benchmark_runner.triage, "fill_reach_fields_tree"), \
                mock.patch.object(benchmark_runner, "reverify_pool_crash_rates"), \
                mock.patch.object(benchmark_runner, "_run_tool", fake_run_tool):
            benchmark_runner.rebuild_pool(
                bench, "slug", "codex", "model", dry_run, "test",
            )
        return calls

    def rebuild_export_argv(self, bench: Path) -> list[tuple]:
        return [
            args for name, args in self.rebuild_tool_calls(bench)
            if name == "export-repro"
        ]

    def test_a_dry_run_pool_is_scored_before_it_is_clustered(self) -> None:
        # A dry run still recopies the pool from the cells and publishes it,
        # and clustering reads the Severity row out of each report. Skipping
        # the offline scorer there publishes whichever severity the cells
        # happened to carry, from whichever scorer last ran over them.
        for dry_run in (True, False):
            bench = self.root / f"pool-scoring-bench-{dry_run}"
            staging = bench / ".pool.staging"
            (staging / "crashes" / "CRASH-0001").mkdir(parents=True)
            (staging / "findings" / "FIND-0001").mkdir(parents=True)
            names = [
                name for name, _ in
                self.rebuild_tool_calls(bench, dry_run=dry_run)
            ]
            self.assertIn("severity", names, f"dry_run={dry_run}")
            self.assertLess(
                names.index("severity"), names.index("cluster-crashes"),
                f"dry_run={dry_run}",
            )

    def test_a_stale_score_aborts_before_clustering_or_pool_swap(self) -> None:
        bench = self.root / "stale-severity"
        staging = bench / ".pool.staging"
        staging.mkdir(parents=True)
        live = bench / "pool"
        live.mkdir()
        (live / "sentinel").write_text("previous result", encoding="utf-8")
        calls: list[str] = []

        def fake_run_tool(name, *args, **kwargs):
            calls.append(name)
            return 0

        with mock.patch.object(benchmark_runner.metrics, "build_pool"), \
                mock.patch.object(benchmark_runner.metrics, "relocate_experiments"), \
                mock.patch.object(benchmark_runner, "benchmark_target_config"), \
                mock.patch.object(
                    benchmark_runner, "_pool_receipt_problems",
                    return_value=([], ["findings/FIND-0001"]),
                ), \
                mock.patch.object(benchmark_runner, "_run_tool", fake_run_tool):
            with self.assertRaisesRegex(
                RuntimeError, "current scorer did not produce",
            ):
                benchmark_runner.rebuild_pool(
                    bench, "slug", "codex", "model", True, "test",
                )

        self.assertEqual(calls, ["severity"])
        self.assertTrue(staging.is_dir())
        self.assertEqual(
            (live / "sentinel").read_text(encoding="utf-8"),
            "previous result",
        )

    def test_a_rebuilt_pool_exports_the_revision_its_run_recorded(self) -> None:
        # A pool is rebuilt long after its run, against a slug whose live
        # session may belong to another run, so the export must carry the
        # revision this run recorded rather than rediscover one.
        bench = self.root / "bench"
        (bench / ".pool.staging" / "crashes" / "CRASH-0001").mkdir(parents=True)
        (bench / "run.json").write_text(
            '{"runid": "r1", "target_sha": "0badc0de"}', encoding="utf-8",
        )
        exported = self.rebuild_export_argv(bench)
        self.assertEqual(len(exported), 1)
        self.assertIn("--target-rev", exported[0])
        self.assertEqual(
            exported[0][exported[0].index("--target-rev") + 1], "0badc0de",
        )
        self.assertIn("--target-root", exported[0])
        self.assertEqual(
            exported[0][exported[0].index("--target-root") + 1],
            str(ROOT / "targets" / "slug"),
        )

    def test_a_run_that_recorded_no_revision_says_so(self) -> None:
        # Left to discover one, export reads the checkout's current commit —
        # which an old pool was never audited at, and which reads like an
        # answer. "norev" is the true one.
        bench = self.root / "no-rev-bench"
        (bench / ".pool.staging" / "crashes" / "CRASH-0001").mkdir(parents=True)
        exported = self.rebuild_export_argv(bench)[0]
        self.assertEqual(exported[exported.index("--target-rev") + 1], "norev")

    def test_replay_never_substitutes_a_different_live_build(self) -> None:
        target, slug = self.make_target("identity-target")
        results = self.make_crash("identity-cell").parent.parent
        unrelated_stamp = target / "build-ubsan" / ".audit-build-stamp"
        unrelated_stamp.parent.mkdir()
        unrelated_stamp.write_text("old\nsource\nrecipe\n", encoding="utf-8")
        recorded = benchmark_runner._target_build_identity(target, slug)
        self.assertTrue(recorded)
        self.assertEqual(
            benchmark_runner._replay_build_status(
                {"build_identity": recorded}, results, target, slug,
            ),
            (True, ""),
        )
        # A pooled crash is checked against the cell it came from, not against
        # every cell of the run: another cell's older build is not this crash's.
        bench = self.root / "identity-bench"
        cells = bench / "cells"
        (cells / "model-direct-r1").mkdir(parents=True)
        (cells / "model-direct-r1" / "cell.json").write_text(
            json.dumps({
                "condition": "model-direct",
                "results_dir": str(results),
                "build_identity": recorded,
            }),
            encoding="utf-8",
        )
        stale = json.loads(json.dumps(recorded))
        stale["artifacts"]["asan-bin"]["sha256"] = "0" * 64
        (cells / "harness-r2").mkdir()
        (cells / "harness-r2" / "cell.json").write_text(
            json.dumps({"condition": "harness", "build_identity": stale}),
            encoding="utf-8",
        )
        (bench / "pool-members.json").write_text(
            json.dumps({"crash_cells": {"CRASH-0001": "model-direct-r1"}}),
            encoding="utf-8",
        )
        self.assertEqual(
            benchmark_runner._pool_replay_blocked(bench, results, target, slug), {},
        )
        ok, reason = benchmark_runner._replay_build_status(
            {}, results, target, slug,
        )
        self.assertFalse(ok)
        self.assertIn("not part of this run's build pin", reason)

        unrelated_stamp.write_text("new\nsource\nrecipe\n", encoding="utf-8")
        self.assertEqual(
            benchmark_runner._replay_build_status(
                {"build_identity": recorded}, results, target, slug,
            ),
            (True, ""),
        )

        # Same size, restored timestamp, different bytes: the binary that runs
        # is a different binary, and only its content says so.
        binary = target / "build-asan" / "src" / "stub"
        before = binary.stat()
        body = binary.read_text(encoding="utf-8")
        binary.write_text(body[:-2] + "0\n", encoding="utf-8")
        os.utime(binary, ns=(before.st_atime_ns, before.st_mtime_ns))
        self.assertEqual(binary.stat().st_size, before.st_size)
        ok, reason = benchmark_runner._replay_build_status(
            {"build_identity": recorded}, results, target, slug,
        )
        self.assertFalse(ok)
        self.assertIn("asan_bin changed", reason)
        blocked = benchmark_runner._pool_replay_blocked(bench, results, target, slug)
        self.assertIn(
            "asan_bin changed", blocked.get("CRASH-0001", ""),
        )

        # Restoring the content restores the identity: an unchanged binary
        # someone merely touched is not a different build.
        binary.write_text(body, encoding="utf-8")
        binary.touch()
        self.assertEqual(
            benchmark_runner._replay_build_status(
                {"build_identity": recorded}, results, target, slug,
            ),
            (True, ""),
        )

        # A saved, statically linked harness does not consult a target build,
        # so historical replay remains available without inventing identity.
        static_results = self.make_harness_crash("static-cell").parent.parent
        self.assertEqual(
            benchmark_runner._replay_build_status(
                {}, static_results, target, slug,
            ),
            (True, ""),
        )

        cell_path = self.root / "recorded-cell" / "cell.json"
        benchmark_runner.write_cell(
            cell_path, "model-direct", 1, "experiment", results, 0,
            "running", 1, build_identity=recorded,
        )
        benchmark_runner.write_cell(
            cell_path, "model-direct", 1, "experiment", results, 1,
            "done", 1,
        )
        stored = json.loads(cell_path.read_text(encoding="utf-8"))
        self.assertEqual(stored["build_identity"], recorded)

    def test_replay_uses_the_run_config_snapshot(self) -> None:
        target, slug = self.make_target("snapshot-target")
        crash = self.make_crash(
            "snapshot-run/cells/model-direct-r1/results",
        )
        snapshot_binary = target / "build-asan" / "src" / "snapshot-stub"
        snapshot_binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        snapshot_binary.chmod(0o755)
        snapshot = self.root / "snapshot-run" / "target.toml"
        snapshot.write_text(
            (target / "target.toml").read_text(encoding="utf-8").replace(
                "build-asan/src/stub", "build-asan/src/snapshot-stub",
            ),
            encoding="utf-8",
        )
        (snapshot.parent / "run.json").write_text("{}\n", encoding="utf-8")
        (crash.parent.parent.parent / "target.toml").write_text(
            (target / "target.toml").read_text(encoding="utf-8"),
            encoding="utf-8",
        )

        fields, _ = benchmark_runner._resolve_reverify_fields(
            crash, target, slug,
        )
        self.assertEqual(fields["BIN"], str(snapshot_binary))

    def test_config_discovery_stops_at_the_benchmark_contract(self) -> None:
        target, slug = self.make_target("bounded-config")
        results = self.root / "loose" / "results"
        results.mkdir(parents=True)
        (self.root / "target.toml").write_text(
            'target = "unrelated"\n', encoding="utf-8",
        )
        discovered = benchmark_runner._benchmark_target_config_path(
            results, target, slug,
        )
        self.assertIsNotNone(discovered)
        self.assertEqual(discovered.resolve(), (target / "target.toml").resolve())

    def test_a_broken_runner_does_not_fall_back_to_asan(self) -> None:
        target, slug = self.make_target("broken-runner")
        with (target / "target.toml").open("a", encoding="utf-8") as output:
            output.write('[runner]\nbin = "../missing-runner"\n')
        crash = self.make_crash("broken-runner-cell")
        (crash / "sanitizer.txt").write_text(
            SANITIZER_DIAGNOSTICS["ubsan"], encoding="utf-8",
        )
        self.assertIsNone(
            benchmark_runner._resolve_reverify_fields(crash, target, slug),
        )

    def test_build_drift_fails_the_check_instead_of_dissolving_it(self) -> None:
        # The gate must not read its requirements off the live configuration:
        # a removed binary or a removed config key leaves no replay contract,
        # and skipping the check there demotes real evidence for the very
        # reason the check exists.
        for drift in ("build removed", "config key removed"):
            with self.subTest(drift):
                name = drift.replace(" ", "-")
                target, slug = self.make_target(name)
                results = self.make_crash(f"{name}-cell").parent.parent
                recorded = benchmark_runner._target_build_identity(target, slug)
                self.assertIn("asan-bin", recorded["artifacts"])
                if drift == "build removed":
                    shutil.rmtree(target / "build-asan")
                else:
                    config = target / "target.toml"
                    config.write_text(
                        config.read_text(encoding="utf-8").replace(
                            'asan_bin = "build-asan/src/stub"\n', "",
                        ),
                        encoding="utf-8",
                    )
                ok, reason = benchmark_runner._replay_build_status(
                    {"build_identity": recorded}, results, target, slug,
                )
                self.assertFalse(ok)
                self.assertTrue(reason)

    def test_a_target_owned_runner_is_verified(self) -> None:
        target = self.root / "runner-target"
        target.mkdir()
        (target / "target.toml").write_text(
            'target = "runner-target"\nbuild_system = "go"\n'
            '[sanitizer]\nenabled = ["race"]\n'
            '[runner]\nbin = "sample-go"\nargs = ["{TESTCASE}"]\n'
            'env = ["RUN_ROOT={TARGET_ROOT}", "RUN_RESULTS={RESULTS_DIR}", '
            '"RUN_SLUG={TARGET_SLUG}"]\n',
            encoding="utf-8",
        )
        runner = target / "sample-go"
        runner.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        runner.chmod(0o755)
        crash = self.make_crash("runner-cell")
        (crash / "sanitizer.txt").write_text(
            "WARNING: DATA RACE\nRead at 0x00 by goroutine 1:\n", encoding="utf-8",
        )
        results = crash.parent.parent
        identity = benchmark_runner._target_build_identity(target, "runner-target")
        self.assertIn("runner-bin", identity["artifacts"])
        fields, replay_args = benchmark_runner._resolve_reverify_fields(
            crash, target, "runner-target",
        )
        self.assertEqual(fields["BIN"], str(runner))
        self.assertEqual(replay_args, [str(crash / "poc.bin")])
        self.assertEqual(fields["ENV_0"], f"RUN_ROOT={target}")
        self.assertEqual(fields["ENV_1"], f"RUN_RESULTS={results}")
        self.assertEqual(fields["ENV_2"], "RUN_SLUG=runner-target")
        command, environment = self.replay_environment(
            crash, target, "runner-target",
        )
        self.assertEqual(environment["ASAN_GENERIC_BIN"], str(runner))
        self.assertEqual(environment["RUN_RESULTS"], str(results))
        self.assertEqual(command[-1], str(crash / "poc.bin"))
        self.assertEqual(
            benchmark_runner._replay_build_status(
                {"build_identity": identity}, results, target, "runner-target",
            ),
            (True, ""),
        )
        runner.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        ok, reason = benchmark_runner._replay_build_status(
            {"build_identity": identity}, results, target, "runner-target",
        )
        self.assertFalse(ok)
        self.assertIn("runner_bin changed", reason)

    def test_a_dropped_override_cannot_reroute_replay_to_another_build(self) -> None:
        # With ubsan_bin gone the resolver falls back to the ASan binary. If the
        # gate follows the live config it asks about asan-bin, matches, and the
        # UBSan crash is replayed under a binary it never ran on.
        for dropped in ("ubsan", "msan", "tsan"):
            with self.subTest(dropped):
                target, slug = self.make_target(
                    f"{dropped}-drop", sanitizer_binaries=(dropped,),
                )
                crash = self.make_crash(f"{dropped}-drop-cell")
                (crash / "sanitizer.txt").write_text(
                    SANITIZER_DIAGNOSTICS[dropped], encoding="utf-8",
                )
                results = crash.parent.parent
                recorded = benchmark_runner._target_build_identity(target, slug)
                self.assertIn(f"{dropped}-bin", recorded["artifacts"])
                config = target / "target.toml"
                config.write_text(
                    config.read_text(encoding="utf-8").replace(
                        f'{dropped}_bin = "build-{dropped}/stub"\n', "",
                    ),
                    encoding="utf-8",
                )
                ok, reason = benchmark_runner._replay_build_status(
                    {"build_identity": recorded}, results, target, slug,
                )
                self.assertFalse(ok, reason)

    def test_the_configured_library_belongs_only_to_a_harness_replay(self) -> None:
        # A static archive was consumed when the saved harness was linked; it
        # is no longer executed. A shared library remains a runtime dependency.
        target, slug = self.make_target(
            "lib-scope-target", library="build-asan/lib/libthing.a",
        )
        cli = self.make_crash("lib-scope-cli").parent.parent
        harness = self.make_harness_crash("lib-scope-harness").parent.parent
        recorded = benchmark_runner._target_build_identity(target, slug)
        (target / "build-asan" / "lib" / "libthing.a").write_bytes(b"!<arch>\nrebuilt\n")
        self.assertEqual(
            benchmark_runner._replay_build_status(
                {"build_identity": recorded}, cli, target, slug,
            ),
            (True, ""),
        )
        self.assertEqual(
            benchmark_runner._replay_build_status(
                {"build_identity": recorded}, harness, target, slug,
            ),
            (True, ""),
        )
        config = target / "target.toml"
        config.write_text(
            config.read_text(encoding="utf-8").replace(
                "build-asan/lib/libthing.a", "build-asan/lib/libthing.dylib",
            ),
            encoding="utf-8",
        )
        (target / "build-asan" / "lib" / "libthing.dylib").write_bytes(
            b"new shared library\n",
        )
        ok, reason = benchmark_runner._replay_build_status(
            {"build_identity": recorded}, harness, target, slug,
        )
        self.assertFalse(ok, reason)

        shared_target, shared_slug = self.make_target(
            "shared-lib-scope-target",
            library="build-asan/lib/libthing.dylib",
        )
        shared_harness = self.make_harness_crash(
            "shared-lib-scope-harness",
        ).parent.parent
        shared_recorded = benchmark_runner._target_build_identity(
            shared_target, shared_slug,
        )
        (shared_target / "build-asan" / "lib" / "libthing.dylib").write_bytes(
            b"rebuilt shared library\n",
        )
        ok, reason = benchmark_runner._replay_build_status(
            {"build_identity": shared_recorded},
            shared_harness,
            shared_target,
            shared_slug,
        )
        self.assertFalse(ok, reason)

    def test_an_unverifiable_build_does_not_relabel_a_failed_cell(self) -> None:
        # Regeneration promotes `incomplete` back to `done` once finalizers
        # succeed. A failed or provider-limited cell relabelled `incomplete`
        # would take that route into the aggregate it is excluded from.
        cases = {
            # Only `status` gates that promotion, so a failed cell keeps it;
            # its quality may still record that finalization did not finish.
            "failed": ({"status": "failed", "run_quality": "clean"}, "failed", "incomplete"),
            "provider-limited": (
                {"status": "done", "run_quality": "provider_limited"},
                "incomplete", "provider_limited",
            ),
            "clean": ({"status": "done", "run_quality": "clean"}, "incomplete", "incomplete"),
        }
        for name, (cell, status, quality) in cases.items():
            with self.subTest(name):
                benchmark_runner._mark_build_finalization_incomplete(cell, "why")
                self.assertEqual(cell["status"], status)
                self.assertEqual(cell["run_quality"], quality)
                self.assertEqual(cell["build_finalization_error"], "why")

    def test_pooled_bundles_survive_a_replay_the_build_cannot_verify(self) -> None:
        # Every accepted crash owes a maintainer a bundle. A bundle reproduces
        # from source at the recorded revision, so an unverifiable live build
        # stops the replay, not the export.
        bench = self.root / "unverified-bench"
        (bench / ".pool.staging" / "crashes" / "CRASH-0001").mkdir(parents=True)
        with mock.patch.object(
            benchmark_runner, "_pool_replay_blocked",
            return_value={"CRASH-0001": "the recorded target build is unavailable"},
        ):
            exported = self.rebuild_export_argv(bench)
        self.assertEqual(len(exported), 1)

    def test_one_stale_cell_does_not_block_the_whole_pool(self) -> None:
        # Pooled crashes come from different cells. One cell whose build has
        # moved on says nothing about a crash another cell found under the
        # build still on disk, and must not cost that crash its rate.
        target, slug = self.make_target("shared-build")
        pool = self.make_crash("pooled").parent.parent
        shutil.copytree(pool / "crashes" / "CRASH-0001", pool / "crashes" / "CRASH-0002")
        recorded = benchmark_runner._target_build_identity(target, slug)
        stale = json.loads(json.dumps(recorded))
        stale["artifacts"]["asan-bin"]["sha256"] = "0" * 64
        bench = self.root / "shared-bench"
        for name, identity in (("cell-a", recorded), ("cell-b", stale)):
            (bench / "cells" / name).mkdir(parents=True)
            (bench / "cells" / name / "cell.json").write_text(
                json.dumps({"condition": "model-direct", "build_identity": identity}),
                encoding="utf-8",
            )
        (bench / "pool-members.json").write_text(
            json.dumps({"crash_cells": {"CRASH-0001": "cell-a", "CRASH-0002": "cell-b"}}),
            encoding="utf-8",
        )
        blocked = benchmark_runner._pool_replay_blocked(bench, pool, target, slug)
        self.assertEqual(list(blocked), ["CRASH-0002"])

    def test_one_changed_artifact_does_not_block_other_crashes_in_its_cell(self) -> None:
        target, slug = self.make_target(
            "mixed-cell-build", sanitizer_binaries=("ubsan",),
        )
        pool = self.make_crash("mixed-cell-pool").parent.parent
        ubsan_crash = pool / "crashes" / "CRASH-0002"
        shutil.copytree(pool / "crashes" / "CRASH-0001", ubsan_crash)
        (ubsan_crash / "sanitizer.txt").write_text(
            SANITIZER_DIAGNOSTICS["ubsan"], encoding="utf-8",
        )
        recorded = benchmark_runner._target_build_identity(target, slug)
        bench = self.root / "mixed-cell-bench"
        cell_name = "model-direct-r1"
        (bench / "cells" / cell_name).mkdir(parents=True)
        (bench / "cells" / cell_name / "cell.json").write_text(
            json.dumps({"condition": "model-direct", "build_identity": recorded}),
            encoding="utf-8",
        )
        (bench / "pool-members.json").write_text(
            json.dumps({
                "crash_cells": {
                    "CRASH-0001": cell_name,
                    "CRASH-0002": cell_name,
                },
            }),
            encoding="utf-8",
        )
        (target / "build-ubsan" / "stub").write_text(
            "#!/bin/sh\necho rebuilt\n", encoding="utf-8",
        )
        blocked = benchmark_runner._pool_replay_blocked(
            bench, pool, target, slug,
        )
        self.assertEqual(list(blocked), ["CRASH-0002"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
