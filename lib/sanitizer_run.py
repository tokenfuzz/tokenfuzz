#!/usr/bin/env python3
"""Standalone sanitizer runner modes shared by MSan, TSan, and UBSan."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Sequence

import sanitizer
import sanitizer_helpers
from sanitizer_helpers import copy_file
from timeout import capture_timeout, run_timeout


def runner_exit_succeeded(config, returncode: int) -> bool:
    return returncode in (config.runner_success_codes if config else [0])


def expand_runner_value(
    value: str,
    config,
    sanitizer_name: str,
    testcase: str = "",
    profile: str | Path = "",
) -> str:
    swift = {"asan": "address", "ubsan": "undefined", "tsan": "thread"}.get(sanitizer_name)
    if "{SWIFT_SANITIZER}" in value and swift is None:
        raise ValueError(
            f"Swift runner does not support sanitizer '{sanitizer_name}' "
            "(supported: asan, ubsan, tsan)"
        )
    replacements = {
        "{TESTCASE}": testcase,
        "{SANITIZER}": sanitizer_name,
        "{SWIFT_SANITIZER}": swift or "",
        "{TARGET_ROOT}": config.target_root if config else os.environ.get("TARGET_ROOT", ""),
        "{RESULTS_DIR}": config.results_dir if config else os.environ.get("RESULTS_DIR", ""),
        "{TARGET_SLUG}": config.slug if config else os.environ.get("TARGET_SLUG", ""),
        "{NULL_DEVICE}": os.devnull,
    }
    if "{PROFILE}" in value:
        if not profile:
            raise ValueError("{PROFILE} is only valid for browser execution")
        replacements["{PROFILE}"] = str(profile)
    for token, replacement in replacements.items():
        value = value.replace(token, replacement)
    return value


def browser_command_args(
    configured_args: Sequence[str],
    testcase_args: Sequence[str],
    config,
    sanitizer_name: str,
    profile: Path,
) -> list[str]:
    """Expand one target-configured browser command line."""
    testcase = browser_testcase_value(testcase_args)
    resolved = list(testcase_args)
    if resolved:
        resolved[0] = testcase
    extra_args = resolved[1:]
    result: list[str] = []
    inserted_testcase = False
    for value in configured_args:
        if value == "{TESTCASE}":
            if testcase:
                result.append(testcase)
            inserted_testcase = True
            continue
        if "{TESTCASE}" in value:
            value = value.replace("{TESTCASE}", testcase)
            inserted_testcase = True
        result.append(
            expand_runner_value(
                value, config, sanitizer_name, profile=profile
            )
        )
    if not inserted_testcase and testcase:
        result.append(testcase)
    result.extend(extra_args)
    return result


def browser_testcase_value(testcase_args: Sequence[str]) -> str:
    """Return the browser-visible value of the primary testcase argument."""
    if not testcase_args:
        return ""
    value = testcase_args[0]
    return (
        Path(value).resolve().as_uri()
        if not value.startswith("-") and Path(value).is_file()
        else value
    )


class SanitizerRunner:
    def __init__(self, name: str, config=None, env=None):
        self.name = name
        self.upper = name.upper()
        self.config = config
        self.env = sanitizer.prepare_runtime_env(name, env)

    def _bin(self) -> str:
        configured = self.env.get(f"{self.upper}_GENERIC_BIN", "")
        if not configured and self.config:
            configured = self.config.sanitizer_bin(self.name)
            if configured:
                configured = self.config.resolve_path(configured)
        return configured

    def runtime_env(
        self,
        options: str,
        final_options: str = "",
        *,
        profile: str | Path = "",
        testcase: str = "",
    ) -> dict[str, str]:
        result = dict(self.env)
        result[f"{self.upper}_OPTIONS"] = sanitizer.runtime_options(
            self.name, options, self.env, final_options
        )
        if self.config:
            for entry in self.config.runner_env:
                expanded = expand_runner_value(
                    entry, self.config, self.name,
                    profile=profile, testcase=testcase,
                )
                key, value = expanded.split("=", 1)
                result[key] = value
        return result

    def generic(self, options: str, timeout: int, args: Sequence[str]) -> int:
        if not args:
            print(f"Usage: run-{self.name} generic <testcase> [target args...]", file=sys.stderr)
            return 1
        binary = self._bin()
        if not binary or not os.access(binary, os.X_OK):
            print(f"[run-{self.name}] generic runner missing or unset: {binary or '<unset>'}", file=sys.stderr)
            print(
                f"[run-{self.name}] set [sanitizer].{self.name}_bin in "
                f"output/<slug>/target.toml, or pass {self.upper}_GENERIC_BIN=",
                file=sys.stderr,
            )
            return 2
        command = [binary]
        if not sanitizer.generic_skips_testcase(self.name, self.env):
            command.append(args[0])
        command.extend(args[1:])
        completed = self._run_symbolized(
            command, options, timeout,
            rss_mb=sanitizer.generic_rss_limit_mb(self.env),
        )
        succeeded = runner_exit_succeeded(self.config, completed.returncode)
        if completed.returncode == 124:
            print(f"[run-{self.name}] generic runner timed out after {timeout}s", file=sys.stderr)
        elif succeeded:
            print(
                f"[run-{self.name}] generic EXECUTION VERIFIED "
                f"(post-run, rc={completed.returncode})",
                file=sys.stderr,
            )
        else:
            print(f"[run-{self.name}] generic EXECUTION INCONCLUSIVE (post-run, rc={completed.returncode})", file=sys.stderr)
        return 0 if succeeded else completed.returncode

    def _run_symbolized(
        self, command: list[str], options: str, timeout: int,
        *, extra_env: dict[str, str] | None = None, **kwargs,
    ):
        """This runner family's binding of the shared symbolizing helper."""
        return sanitizer_helpers.run_symbolized(
            command, timeout,
            {**self.runtime_env(options), **(extra_env or {})},
            f"{self.upper}_OPTIONS", **kwargs,
        )

    def js(self, options: str, timeout: int, args: Sequence[str]) -> int:
        binary = self.env.get(f"{self.upper}_JS") or str(
            sanitizer.build_dir(self.name, self.config.target_root if self.config else "", self.env) / "dist/bin/js"
        )
        completed = self._run_symbolized([binary, *args], options, timeout)
        if completed.returncode == 124:
            print(f"[run-{self.name}] JS shell timed out after {timeout}s", file=sys.stderr)
        elif completed.returncode == 0:
            print(f"[run-{self.name}] js EXECUTION VERIFIED (post-run, rc=0)", file=sys.stderr)
        return completed.returncode

    def _require_fuzzer(self) -> str | None:
        value = self.env.get("FUZZER", "")
        if not value:
            print("Error: FUZZER env var must be set.", file=sys.stderr)
            return None
        if not sanitizer.validate_fuzzer_name(value):
            print(f"Error: FUZZER must match ^[A-Za-z_][A-Za-z0-9_]*$ (got '{value}')", file=sys.stderr)
            return None
        return value

    def fuzz(self, options: str, timeout: int, args: Sequence[str]) -> int:
        fuzzer = self._require_fuzzer()
        if fuzzer is None:
            return 1 if not self.env.get("FUZZER") else 2
        binary = self._bin()
        if not binary or not os.access(binary, os.X_OK):
            print(f"[run-{self.name}] fuzz target missing: {binary or '<unset>'}", file=sys.stderr)
            return 2
        crash_dir = Path(self.env.get("FUZZ_CRASH_DIR", str(sanitizer.default_fuzz_crash_dir(self.env))))
        crash_dir.mkdir(parents=True, exist_ok=True)
        clean_args = [arg for arg in args if not arg.startswith("-fork=")]
        self._run_symbolized(
            [binary, *clean_args], options, timeout, kill=True, cwd=crash_dir,
            extra_env={"FUZZER": fuzzer},
        )
        print(f"[run-{self.name}] Fuzz artifacts (if any): {crash_dir}", file=sys.stderr)
        return 0

    def fuzz_repro(self, options: str, timeout: int, args: Sequence[str]) -> int:
        if not args:
            print("Error: provide a crash file to reproduce.", file=sys.stderr)
            return 1
        binary = self._bin()
        if not binary or not os.access(binary, os.X_OK):
            print(f"[run-{self.name}] fuzz-repro target missing: {binary or '<unset>'}", file=sys.stderr)
            return 2
        resolved = [str(Path(arg).resolve()) if not arg.startswith("-") and Path(arg).is_file() else arg for arg in args]
        return self._run_symbolized(
            [binary, *resolved], options, timeout, kill=True,
        ).returncode

    def fuzz_js(self, options: str, timeout: int, args: Sequence[str]) -> int:
        fuzzer = self._require_fuzzer()
        if fuzzer is None:
            return 1 if not self.env.get("FUZZER") else 2
        binary = sanitizer.build_dir(self.name, self.config.target_root if self.config else "", self.env) / "dist/bin/fuzz-tests"
        if not os.access(binary, os.X_OK):
            print(
                f"Error: fuzz-tests binary not found at {binary}. "
                "Run bin/setup-target <target> --build first.",
                file=sys.stderr,
            )
            return 1
        crash_dir = Path(self.env.get("FUZZ_CRASH_DIR", str(sanitizer.default_fuzz_crash_dir(self.env))))
        crash_dir.mkdir(parents=True, exist_ok=True)
        clean_args = [arg for arg in args if not arg.startswith("-fork=")]
        self._run_symbolized(
            [str(binary), *clean_args], options, timeout, cwd=crash_dir,
            extra_env={"FUZZER": fuzzer},
        )
        print(f"[run-{self.name}] Fuzz artifacts (if any): {crash_dir}", file=sys.stderr)
        return 0


def run_standard(name: str, argv: Sequence[str], config=None) -> int:
    modes = {"generic", "js", "fuzz", "fuzz-repro", "fuzz-js"}
    if not argv or argv[0] not in modes:
        print(f"Usage: run-{name} {{generic|js|fuzz|fuzz-repro|fuzz-js}} [args...]")
        return 1
    runner = SanitizerRunner(name, config)
    sanitizer.warn_if_disabled(name, config)
    sanitizer.hold_build(name, config.target_root if config else "")
    mode = argv[0]
    timeouts = {
        "generic": int(os.environ.get(f"{name.upper()}_TIMEOUT", "15")),
        "js": int(os.environ.get(f"{name.upper()}_TIMEOUT", "10")),
        "fuzz": int(os.environ.get(f"FUZZ_{name.upper()}_TIMEOUT", "600")),
        "fuzz-repro": int(os.environ.get(f"{name.upper()}_FUZZ_REPRO_TIMEOUT", "20")),
        "fuzz-js": int(os.environ.get(f"FUZZ_{name.upper()}_TIMEOUT", "600")),
    }
    option_mode = "fuzz" if mode == "fuzz-js" else mode
    options = sanitizer.compose_options(name, sanitizer.options_for(name, option_mode), config)
    method = getattr(runner, mode.replace("-", "_"))
    return method(options, timeouts[mode], argv[1:])
