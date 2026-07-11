#!/usr/bin/env python3
"""Structured text operations shared by sanitizer runners."""

from __future__ import annotations

import argparse
import base64
import os
import re
import shutil
import sys
from pathlib import Path


def file_contains(path: Path, needle: bytes) -> bool:
    """Search a potentially large diagnostic without loading it into memory."""
    overlap = b""
    with path.open("rb") as stream:
        while chunk := stream.read(64 * 1024):
            data = overlap + chunk
            if needle in data:
                return True
            overlap = data[-max(0, len(needle) - 1):]
    return False


def copy_file(path: Path, destination) -> None:
    with path.open("rb") as source:
        shutil.copyfileobj(source, destination, 1024 * 1024)


def copy_filtered(path: Path, destination, patterns) -> None:
    with path.open("rb") as source:
        for raw in source:
            line = raw.decode(errors="replace")
            if not any(pattern.search(line) for pattern in patterns):
                destination.write(line.encode())


_BROWSER_NOISE = tuple(re.compile(pattern) for pattern in (
    r"^Nightly GPU Helper\[",
    r"^UNSUPPORTED \(log once\): POSSIBLE ISSUE: unit 1 GLD_TEXTURE_INDEX_2D",
    r'^console\.debug: "Registering new SmartBlock shim content scripts"',
    r'^console\.debug: "Registering new webcompat intervention content scripts"',
    r'^console\.debug: "Registering redirect listener for requestStorageAccess helper"',
    r'^console\.debug: "Allowing access to these logos:"',
    r'^console\.debug: "Shimming these"',
    r'^console\.debug: "Enabled" [0-9]+ "webcompat',
    r'^console\.debug: "Skipped" [0-9]+ "un-needed webcompat interventions"',
    r"^Exiting due to channel error\.$",
))

_FUZZ_TARGET = re.compile(
    r"MOZ_FUZZING_INTERFACE_(?:RAW|STREAM)\s*\("
    r"\s*[^,]+,\s*[^,]+,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)",
    re.MULTILINE | re.DOTALL,
)
_FUZZ_SOURCE_SUFFIXES = (".cpp", ".cc", ".h", ".c")
_FUZZ_SKIP_EXACT = {".git", ".hg", "obj-opt"}
_FUZZ_SKIP_PREFIXES = ("build-asan", "build-ubsan", "build-msan", "build-tsan")


def firefox_fuzz_targets(target_root: str | os.PathLike[str]) -> list[str]:
    """Return registered Firefox fuzz target identifiers from source."""
    targets = set()
    for directory, dirnames, filenames in os.walk(target_root):
        dirnames[:] = [
            name for name in dirnames
            if name not in _FUZZ_SKIP_EXACT
            and not name.startswith(_FUZZ_SKIP_PREFIXES)
        ]
        for filename in filenames:
            if not filename.endswith(_FUZZ_SOURCE_SUFFIXES):
                continue
            path = Path(directory) / filename
            try:
                data = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "MOZ_FUZZING_INTERFACE_" in data:
                targets.update(match.group(1) for match in _FUZZ_TARGET.finditer(data))
    return sorted(targets)


def _cmd_filter_browser(args: argparse.Namespace) -> int:
    with open(args.path, "r", encoding="utf-8", errors="replace") as source:
        for line in source:
            if not any(pattern.search(line) for pattern in _BROWSER_NOISE):
                sys.stdout.write(line)
    return 0


def _cmd_list_firefox_fuzz_targets(args: argparse.Namespace) -> int:
    for target in firefox_fuzz_targets(args.target_root):
        print(target)
    return 0


def _cmd_encode_options(args: argparse.Namespace) -> int:
    print(base64.b64encode(args.value.encode()).decode())
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="sanitizer_helpers")
    sub = parser.add_subparsers(dest="command", required=True)

    command = sub.add_parser("filter-browser")
    command.add_argument("path")
    command.set_defaults(func=_cmd_filter_browser)

    command = sub.add_parser("list-firefox-fuzz-targets")
    command.add_argument("target_root")
    command.set_defaults(func=_cmd_list_firefox_fuzz_targets)

    command = sub.add_parser("encode-options")
    command.add_argument("value")
    command.set_defaults(func=_cmd_encode_options)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
