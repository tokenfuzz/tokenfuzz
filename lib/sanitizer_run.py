#!/usr/bin/env python3
"""Standalone sanitizer runner modes shared by MSan, TSan, and UBSan."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Sequence

import sanitizer
from timeout import run_timeout


def _expand(value: str, config, sanitizer_name: str) -> str:
    swift = {"asan": "address", "ubsan": "undefined", "tsan": "thread"}.get(sanitizer_name)
    if "{SWIFT_SANITIZER}" in value and swift is None:
        raise ValueError(
            f"Swift runner does not support sanitizer '{sanitizer_name}' "
            "(supported: asan, ubsan, tsan)"
        )
    replacements = {
        "{TESTCASE}": "",
        "{SANITIZER}": sanitizer_name,
        "{SWIFT_SANITIZER}": swift or "",
        "{TARGET_ROOT}": config.target_root if config else os.environ.get("TARGET_ROOT", ""),
        "{RESULTS_DIR}": config.results_dir if config else os.environ.get("RESULTS_DIR", ""),
        "{TARGET_SLUG}": config.slug if config else os.environ.get("TARGET_SLUG", ""),
    }
    for token, replacement in replacements.items():
        value = value.replace(token, replacement)
    return value


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

    def _runtime_env(self, options: str, final_options: str = "") -> dict[str, str]:
        result = dict(self.env)
        result[f"{self.upper}_OPTIONS"] = sanitizer.runtime_options(
            self.name, options, self.env, final_options
        )
        if self.config:
            for entry in self.config.runner_env:
                expanded = _expand(entry, self.config, self.name)
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
        if self.env.get("SANITIZER_GENERIC_SKIP_TESTCASE", self.env.get("ASAN_GENERIC_SKIP_TESTCASE", "0")) != "1":
            command.append(args[0])
        command.extend(args[1:])
        offline = sanitizer.symbolize_available()
        completed = run_timeout(
            command,
            timeout,
            rss_mb=sanitizer.generic_rss_limit_mb(self.env),
            env=self._runtime_env(options, "symbolize=0" if offline else ""),
            capture_output=offline,
        )
        if offline:
            import tempfile
            with tempfile.NamedTemporaryFile() as report:
                report.write(completed.stdout + completed.stderr)
                report.flush()
                sanitizer.symbolize_file(report.name)
                sys.stdout.buffer.write(Path(report.name).read_bytes())
        if completed.returncode == 124:
            print(f"[run-{self.name}] generic runner timed out after {timeout}s", file=sys.stderr)
        elif completed.returncode == 0:
            print(f"[run-{self.name}] generic EXECUTION VERIFIED (post-run, rc=0)", file=sys.stderr)
        else:
            print(f"[run-{self.name}] generic EXECUTION INCONCLUSIVE (post-run, rc={completed.returncode})", file=sys.stderr)
        return completed.returncode

    def js(self, options: str, timeout: int, args: Sequence[str]) -> int:
        binary = self.env.get(f"{self.upper}_JS") or str(
            sanitizer.build_dir(self.name, self.config.target_root if self.config else "", self.env) / "dist/bin/js"
        )
        completed = run_timeout([binary, *args], timeout, env=self._runtime_env(options))
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
        run_timeout(
            [binary, *clean_args], timeout, kill=True, cwd=crash_dir,
            env={**self._runtime_env(options), "FUZZER": fuzzer},
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
        return run_timeout([binary, *resolved], timeout, kill=True, env=self._runtime_env(options)).returncode

    def fuzz_js(self, options: str, timeout: int, args: Sequence[str]) -> int:
        fuzzer = self._require_fuzzer()
        if fuzzer is None:
            return 1 if not self.env.get("FUZZER") else 2
        binary = sanitizer.build_dir(self.name, self.config.target_root if self.config else "", self.env) / "dist/bin/fuzz-tests"
        if not os.access(binary, os.X_OK):
            print(f"Error: fuzz-tests binary not found at {binary}. Run ff-bsan {self.name} first.", file=sys.stderr)
            return 1
        crash_dir = Path(self.env.get("FUZZ_CRASH_DIR", str(sanitizer.default_fuzz_crash_dir(self.env))))
        crash_dir.mkdir(parents=True, exist_ok=True)
        clean_args = [arg for arg in args if not arg.startswith("-fork=")]
        run_timeout(
            [str(binary), *clean_args], timeout, cwd=crash_dir,
            env={**self._runtime_env(options), "FUZZER": fuzzer},
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
