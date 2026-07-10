#!/usr/bin/env python3
"""Structured helpers for bin/probe.

The probe entrypoint owns target configuration and process dispatch. This
module owns path containment, command-word parsing, and bounded log rendering.
"""

from __future__ import annotations

import argparse
import os
import shlex
import sys
from pathlib import Path


def _nonnegative_int(value: str, default: int) -> int:
    try:
        return max(0, int(value))
    except ValueError:
        return default


def _cmd_path_under(args: argparse.Namespace) -> int:
    root = os.path.realpath(args.root)
    path = os.path.realpath(args.path)
    try:
        under = os.path.commonpath([root, path]) == root
    except ValueError:
        under = False
    return 0 if under else 1


def _cmd_split_shell_words(args: argparse.Namespace) -> int:
    try:
        parts = shlex.split(args.words)
    except ValueError as error:
        print(f"[probe] cannot parse shell words: {error}", file=sys.stderr)
        return 2
    for part in parts:
        sys.stdout.buffer.write(part.encode("utf-8", errors="surrogateescape") + b"\0")
    return 0


def _cmd_build_log_digest(args: argparse.Namespace) -> int:
    head = _nonnegative_int(args.head_bytes, 8192)
    tail = _nonnegative_int(args.tail_bytes, 8192)
    path = Path(args.log_file)
    data = path.read_bytes()

    size = len(data)
    if head == 0 and tail == 0:
        output = b""
    elif size <= head + tail + 256:
        output = data
    else:
        omitted = size - head - tail
        marker = (
            f"\n[probe] compiler log elided {omitted} bytes; full log: {path}\n"
        ).encode()
        output = data[:head] + marker + data[-tail:]

    sys.stderr.write(output.decode("utf-8", errors="replace"))
    if output and not output.endswith(b"\n"):
        sys.stderr.write("\n")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="probe_helpers")
    sub = parser.add_subparsers(dest="command", required=True)

    command = sub.add_parser("path-under")
    command.add_argument("root")
    command.add_argument("path")
    command.set_defaults(func=_cmd_path_under)

    command = sub.add_parser("split-shell-words")
    command.add_argument("words")
    command.set_defaults(func=_cmd_split_shell_words)

    command = sub.add_parser("build-log-digest")
    command.add_argument("log_file")
    command.add_argument("head_bytes")
    command.add_argument("tail_bytes")
    command.set_defaults(func=_cmd_build_log_digest)

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
