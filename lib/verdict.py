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
_RUNNER_IMPORT_FAILURE_RE = re.compile(
    r"^(?:ModuleNotFoundError: No module named|ImportError: cannot import name)\b"
)
_RUNNER_ATTRIBUTE_FAILURE_RE = re.compile(
    r"^AttributeError: module '[^']+' has no attribute '[^']+'$"
)
_RUNNER_UNAVAILABLE_RE = re.compile(
    r"^(?:RuntimeError|OSError): .*\b(?:unavailable|not available)\b", re.IGNORECASE,
)
_RUNNER_ASSERTION_RE = re.compile(r"^AssertionError(?::|$)")
_PYTHON_FRAME_RE = re.compile(r'^\s*File "([^"]+)"')
#: The runner started the configured command and it returned, in at least one
#: repetition. This is an execution *attempt*, not proof the target's entry
#: point ran: the rate counts an "EXECUTION INCONCLUSIVE" repetition, which
#: run-<san> prints for any non-success status — a rejected input (rc=69) and a
#: non-executable binary (rc=126) alike.
_EXECUTION_ATTEMPTED_RE = re.compile(
    r"^\[run-sanitizer-multi\] EXECUTION_RATE: [1-9][0-9]*/[0-9]+$"
)


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


def file_execution_attempted(path: str | Path) -> bool:
    """Did the runner start the configured command and get a status back?

    Separates ``EXEC_FAIL`` (the command ran and returned without completing
    cleanly) from ``NO_EXEC`` (no execution evidence at all). It deliberately
    claims no more than that: the marker cannot tell an input the target
    rejected from an argv, loader, dependency, or runner failure, so a caller
    must read the output before naming the repair. Both are non-evidence
    verdicts, so neither can accept or discard anything; the split only
    narrows where the agent looks. Shared with bin/probe, bin/scratch-status
    and orphan enforcement so one rule answers for all three.
    """
    return _file_matches(path, _EXECUTION_ATTEMPTED_RE)


def runner_testcase_failure(path: str | Path, testcase: str | Path) -> str:
    """Classify a Python exception whose deepest frame is the testcase.

    A bare exception name is insufficient: target code can legitimately raise
    the same exception.  Traceback provenance keeps target-origin diagnostics
    visible while separating an unavailable prerequisite — a missing module,
    a missing attribute, a runtime that reports itself unavailable — from a
    testcase assertion.
    """
    try:
        expected = Path(testcase).resolve()
        last_frame: Path | None = None
        with Path(path).open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if line.startswith("Traceback (most recent call last):"):
                    last_frame = None
                    continue
                frame = _PYTHON_FRAME_RE.match(line)
                if frame:
                    last_frame = Path(frame.group(1)).resolve()
                    continue
                if last_frame != expected:
                    continue
                if (
                    _RUNNER_IMPORT_FAILURE_RE.match(line)
                    or _RUNNER_ATTRIBUTE_FAILURE_RE.match(line)
                    or _RUNNER_UNAVAILABLE_RE.match(line)
                ):
                    return "unavailable"
                if _RUNNER_ASSERTION_RE.match(line):
                    return "assertion"
    except OSError:
        pass
    return ""


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
