#!/usr/bin/env python3
"""Canonical sanitizer-output crash and clean verdict classification."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


CRASH_PATTERNS = (
    r"ERROR: AddressSanitizer",
    r"ERROR: HWAddressSanitizer",
    r"AddressSanitizer:DEADLYSIGNAL",
    r"WARNING: ThreadSanitizer:",
    r"WARNING: MemorySanitizer:",
    r"WARNING: DataflowSanitizer:",
    r"runtime error:.*UndefinedBehaviorSanitizer",
    r"UndefinedBehaviorSanitizer:",
    r"\[run-asan\] CRASH DETECTED",
    r"\[run-ubsan\] UBSan issue detected",
    r"WARNING: DATA RACE",
    r"panic: runtime error:",
    r"fatal error: stack overflow",
    r"fatal error: out of memory",
    r"fatal error: concurrent map",
    r"thread '.*'( \([^)]*\))? panicked at",
    r"fatal runtime error:",
    r"^Exception in thread",
    r"java\.lang\.OutOfMemoryError",
    r"java\.lang\.StackOverflowError",
    r"Fatal Python error:",
    r"^FATAL ERROR:.*JavaScript heap out of memory",
    r"^FATAL ERROR:.*Allocation failed",
    r"\(NoMemoryError\)",
    r"SystemStackError",
    r"PHP Fatal error:",
    r"==[0-9]+==SEGV on",
    r"==[0-9]+==ERROR:",
)

CLEAN_PATTERN = (
    r"^\[run-sanitizer-multi\] SUCCESS_RATE: [1-9][0-9]*/[0-9]+$|"
    r"^\[run-(asan|ubsan|msan|tsan)\] (browser|js|xpcshell|generic) "
    r"EXECUTION VERIFIED \(post-run|"
    r"^\[run-ubsan\] EXECUTION VERIFIED:|"
    r"^\[probe\] (asan|ubsan|msan|tsan|race|runner) EXECUTION VERIFIED \(post-run"
)
_CRASH_RE = re.compile("|".join(CRASH_PATTERNS))
_CLEAN_RE = re.compile(CLEAN_PATTERN)


def _file_matches(path: str | Path, pattern: re.Pattern) -> bool:
    try:
        with Path(path).open(encoding="utf-8", errors="replace") as stream:
            return any(pattern.search(line) for line in stream)
    except OSError:
        return False


def file_has_crash(path: str | Path, extra_patterns: tuple[str, ...] = ()) -> bool:
    pattern = re.compile("|".join((*CRASH_PATTERNS, *extra_patterns))) if extra_patterns else _CRASH_RE
    return _file_matches(path, pattern)


def file_is_clean(path: str | Path) -> bool:
    return _file_matches(path, _CLEAN_RE)


def main() -> int:
    parser = argparse.ArgumentParser(prog="verdict")
    parser.add_argument("command", choices=("crash-patterns", "clean-pattern"))
    args = parser.parse_args()
    if args.command == "crash-patterns":
        print("\n".join(CRASH_PATTERNS))
    else:
        print(CLEAN_PATTERN)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
