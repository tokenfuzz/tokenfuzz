#!/usr/bin/env python3
"""Shared implementations for audit-shell command wrappers."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import NoReturn, Sequence

LIB_DIR = Path(__file__).resolve().parent.parent
if str(LIB_DIR) not in sys.path:
    sys.path.insert(0, str(LIB_DIR))

from command_tools import find_executable
from file_tools import cap_output_file, capture_command


def _real_tool(name: str, wrapper_dir: Path) -> str:
    real = find_executable(name, skip=(wrapper_dir,))
    if real is None:
        raise FileNotFoundError(name)
    return real


def _exec(real: str, args: Sequence[str]) -> NoReturn:
    os.execv(real, [real, *args])


def _bypassed(tool: str) -> bool:
    configured = os.environ.get("AGENT_WRAPPERS_BYPASS", "").replace(",", " ")
    return "all" in configured.split() or tool in configured.split()


def _has_passthrough(args: Sequence[str], flags: set[str]) -> bool:
    if not flags:
        return False
    for arg in args:
        if arg == "--":
            break
        if arg in flags:
            return True
    return False


def capped_command(
    tool: str,
    args: Sequence[str],
    *,
    prefix: Sequence[str] = (),
    passthrough: Sequence[str] = (),
    wrapper_dir: Path | None = None,
) -> int:
    """Run a search tool with bounded stdout and stderr."""
    directory = (wrapper_dir or Path(__file__).resolve().parent).resolve()
    try:
        real = _real_tool(tool, directory)
    except FileNotFoundError:
        print(f"{tool}: real binary not found", file=sys.stderr)
        return 127

    cap_text = os.environ.get("CAP_BYTES")
    if cap_text is None:
        cap_text = os.environ.get("OUTCAP_MAX_BYTES", "51200")
    if not cap_text.isdigit():
        print(f"{tool}: CAP_BYTES must be a non-negative integer", file=sys.stderr)
        return 2
    cap = int(cap_text)
    command_args = [*prefix, *args]

    if _bypassed(tool) or _has_passthrough(args, set(passthrough)):
        _exec(real, command_args)

    cap_env = dict(os.environ)
    if "CAP_BYTES" in os.environ:
        cap_env["OUTCAP_MAX_BYTES"] = str(cap)
        cap_env["OUTCAP_HEAD_BYTES"] = str(cap * 3 // 5)
        cap_env["OUTCAP_TAIL_BYTES"] = str(cap * 2 // 5)
    with capture_command([real, *command_args]) as completed:
        try:
            stdout = cap_output_file(completed.stdout, f"{tool}-stdout", cap_env)
            stderr = cap_output_file(completed.stderr, f"{tool}-stderr", cap_env)
        except ValueError as exc:
            print(exc, file=sys.stderr)
            return 2

        sys.stdout.buffer.write(stdout)
        sys.stdout.buffer.flush()
        sys.stderr.buffer.write(stderr)
        sys.stderr.buffer.flush()
        return completed.returncode


SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".C",
    ".m",
    ".mm",
    ".S",
    ".s",
    ".i",
    ".ii",
    ".o",
    ".a",
}
SUPPRESS_OUTPUT = {"-E", "-M", "-MM", "-###", "--version", "-dumpversion", "-dumpmachine"}


def _reject_output(output: str, reason: str) -> int:
    print(f"[compile-guard] refusing compiler output in audit repo root: {output}", file=sys.stderr)
    print(f"[compile-guard] reason: {reason}", file=sys.stderr)
    print(
        "[compile-guard] write harnesses under $RESULTS_DIR/scratch-N and run them with bin/probe.",
        file=sys.stderr,
    )
    print(
        "[compile-guard] set AUDIT_ALLOW_ROOT_COMPILER_OUTPUT=1 to override for a trusted local experiment.",
        file=sys.stderr,
    )
    return 2


def _compiler_arguments(args: Sequence[str]) -> tuple[list[str], bool, bool, bool]:
    outputs: list[str] = []
    has_source = False
    suppress_output = False
    waiting_for_output = False
    for arg in args:
        if waiting_for_output:
            outputs.append(arg)
            waiting_for_output = False
            continue
        if arg == "-o":
            waiting_for_output = True
        elif arg.startswith("-o") and len(arg) > 2:
            outputs.append(arg[2:])
        elif arg in SUPPRESS_OUTPUT or arg.startswith("-print-") or arg.startswith("--print-"):
            suppress_output = True
        elif Path(arg).suffix in SOURCE_SUFFIXES:
            has_source = True
    return outputs, has_source, suppress_output, waiting_for_output


def compiler_guard(
    tool: str,
    args: Sequence[str],
    *,
    wrapper_dir: Path | None = None,
) -> int:
    """Reject compiler artifacts outside output/ and targets/ at repo root."""
    directory = (wrapper_dir or Path(__file__).resolve().parent).resolve()
    try:
        real = _real_tool(tool, directory)
    except FileNotFoundError:
        print(f"[compile-guard] real compiler not found after wrapper: {tool}", file=sys.stderr)
        return 127

    outputs, has_source, suppress_output, dangling_output = _compiler_arguments(args)
    repo_root = directory.parent.parent.resolve()
    guarded = (
        os.environ.get("AUDIT_ALLOW_ROOT_COMPILER_OUTPUT", "0") != "1"
        and Path.cwd().resolve() == repo_root
    )
    if dangling_output or not guarded:
        _exec(real, args)

    if not outputs and has_source and not suppress_output:
        return _reject_output(
            "a.out/object-in-cwd",
            "compiler command has source inputs but no explicit safe -o path",
        )

    for output in outputs:
        path = Path(output)
        if path.is_absolute():
            try:
                relative = path.relative_to(repo_root)
            except ValueError:
                continue
            parts = relative.parts
            if parts and parts[0] in {"output", "targets"}:
                continue
            if len(parts) > 1:
                return _reject_output(
                    output,
                    "absolute output resolves under the audit repo instead of output/ or targets/",
                )
            return _reject_output(
                output,
                "absolute output resolves to a top-level audit repo artifact",
            )

        normalized = output[2:] if output.startswith("./") else output
        parts = Path(normalized).parts
        if parts and parts[0] in {"output", "targets"} and len(parts) > 1:
            continue
        if parts and parts[0].startswith("scratch-") and parts[0][8:].isdigit():
            return _reject_output(
                output,
                "top-level scratch-N is not the active RESULTS_DIR scratch directory",
            )
        if len(parts) > 1:
            return _reject_output(
                output,
                "relative output would create an artifact under the audit repo outside output/ or targets/",
            )
        return _reject_output(
            output,
            "relative basename output would create a root-level artifact",
        )

    _exec(real, args)
