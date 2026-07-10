#!/usr/bin/env python3
"""Sanitizer policy, runtime options, and symbolization helpers."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Mapping

LIB_DIR = Path(__file__).resolve().parent
OPTIONS_FILE = LIB_DIR / "sanitizer_options.conf"
SYMBOLIZER = LIB_DIR / "clusterfuzz_symbolizer.py"
SANITIZER_ENV = {
    "asan": "ASAN_OPTIONS",
    "ubsan": "UBSAN_OPTIONS",
    "msan": "MSAN_OPTIONS",
    "tsan": "TSAN_OPTIONS",
}
FUZZER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
RAW_FRAME = re.compile(r"^ *#[0-9]+ +0x[0-9a-f]+ +\([^)]*\+0x[0-9a-f]+\)", re.M)


def build_dir(name: str, target_root: str = "", env: Mapping[str, str] | None = None) -> Path:
    environment = os.environ if env is None else env
    root = target_root or environment.get("TARGET_ROOT", "")
    return Path(root) / f"build-{name}{environment.get('AUDIT_BUILD_SUFFIX', '')}"


def prepare_runtime_env(selected: str, env: Mapping[str, str] | None = None) -> dict[str, str]:
    result = dict(os.environ if env is None else env)
    selected_name = SANITIZER_ENV.get(selected)
    if selected not in {*SANITIZER_ENV, "none", "runner", "race", ""}:
        raise ValueError(f"unknown sanitizer: {selected}")
    for name in SANITIZER_ENV.values():
        if name != selected_name:
            result.pop(name, None)
    return result


def options_for(name: str, mode: str) -> str:
    if not OPTIONS_FILE.is_file():
        raise FileNotFoundError(f"option table missing: {OPTIONS_FILE}")
    full = ""
    for line in OPTIONS_FILE.read_text().splitlines():
        fields = line.split(None, 2)
        if not fields or fields[0].startswith("#") or len(fields) < 3:
            continue
        sanitizer, configured_mode, options = fields
        if sanitizer != name:
            continue
        if configured_mode == mode:
            return options
        if configured_mode == "full":
            full = options
    return full


def runtime_options(
    name: str, base: str, env: Mapping[str, str] | None = None, final: str = ""
) -> str:
    environment = os.environ if env is None else env
    try:
        existing = environment.get(SANITIZER_ENV[name], "")
    except KeyError as exc:
        raise ValueError(f"unknown sanitizer: {name}") from exc
    # ``final`` is for harness invariants that ambient options must not undo.
    # Sanitizer runtimes use the last duplicate key, so it belongs after the
    # operator-provided environment rather than in ``base``.
    return ":".join(part for part in (base, existing, final) if part)


def compose_options(name: str, base: str, config=None) -> str:
    if config is None:
        return base
    parts = [base] if base else []
    suppression = config.sanitizer_suppressions_path(name)
    if suppression:
        if Path(suppression).is_file():
            parts.append(f"suppressions={suppression}")
        else:
            print(f"[sanitizer] WARNING: {name} suppressions file not found: {suppression}", file=sys.stderr)
    extra = config.sanitizer_options.get(name, "")
    if extra:
        parts.append(extra)
    return ":".join(parts)


def generic_rss_limit_mb(env: Mapping[str, str] | None = None) -> int:
    value = (os.environ if env is None else env).get("PROBE_RSS_LIMIT_MB", "5120")
    return int(value) if value.isdigit() and int(value) > 0 else 0


def validate_fuzzer_name(value: str) -> bool:
    return bool(FUZZER_NAME.fullmatch(value))


def default_fuzz_crash_dir(env: Mapping[str, str] | None = None) -> Path:
    environment = os.environ if env is None else env
    return Path(environment.get("RESULTS_DIR", "results")) / "fuzz-crashes" / environment.get("FUZZER", "")


def llvm_tool(name: str) -> str:
    prefix = os.environ.get("LLVM_PREFIX")
    if prefix and os.access(Path(prefix) / "bin" / name, os.X_OK):
        return str(Path(prefix) / "bin" / name)
    candidates = [Path("/opt/homebrew/opt/llvm"), Path("/usr/local/opt/llvm")]
    candidates.extend(sorted(Path("/usr/lib").glob("llvm-*")))
    candidates.append(Path("/usr/local"))
    for candidate in candidates:
        tool = candidate / "bin" / name
        if os.access(tool, os.X_OK):
            return str(tool)
    return shutil.which(name) or name


def symbolize_available() -> bool:
    if not SYMBOLIZER.is_file():
        return False
    tool = llvm_tool("llvm-symbolizer")
    return (Path(tool).is_file() and os.access(tool, os.X_OK)) or bool(shutil.which("atos") or shutil.which("addr2line"))


def symbolize_file(path: str | os.PathLike[str]) -> None:
    report = Path(path)
    if not report.is_file() or not report.stat().st_size or not SYMBOLIZER.is_file():
        return
    raw = report.read_text(errors="replace")
    if not RAW_FRAME.search(raw):
        return
    args = [sys.executable, str(SYMBOLIZER)]
    if sys.platform == "darwin" and shutil.which("atos"):
        args.append("--no-llvm-symbolizer")
    else:
        args.extend(("--llvm-symbolizer", llvm_tool("llvm-symbolizer")))
    with tempfile.NamedTemporaryFile() as rendered, report.open("rb") as source:
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("timeout.py")), "60", "TERM", "0", *args],
            stdin=source,
            stdout=rendered,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        rendered.flush()
        if completed.returncode == 0 and Path(rendered.name).stat().st_size:
            report.write_bytes(Path(rendered.name).read_bytes())


def warn_if_disabled(name: str, config=None) -> None:
    if config is None or not config.sanitizers_enabled:
        return
    if not config.sanitizer_is_enabled(name):
        print(
            f"[sanitizer] NOTE: '{name}' is not in [sanitizer].enabled in target.toml "
            f"- running anyway. Add '{name}' to enable it for the audit harness.",
            file=sys.stderr,
        )
