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
# Every static crash alternative contains at least one of these exact tokens.
# Check whole chunks first so ordinary target output does not pay for the much
# more expensive combined regex on every line. Configured extra patterns bypass
# this gate because their vocabulary is intentionally unconstrained.
_CRASH_HINTS = (
    "AddressSanitizer",
    "ThreadSanitizer",
    "MemorySanitizer",
    "DataflowSanitizer",
    "UndefinedBehaviorSanitizer",
    "CRASH DETECTED",
    "UBSan issue detected",
    "WARNING: DATA RACE",
    "panic: runtime error:",
    "fatal error:",
    "panicked at",
    "fatal runtime error:",
    "Exception in thread",
    "OutOfMemoryError",
    "StackOverflowError",
    "Fatal Python error:",
    "FATAL ERROR:",
    "NoMemoryError",
    "SystemStackError",
    "PHP Fatal error:",
    "SEGV on",
    "==",
)
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
#: The child's exit code, carried by every post-run marker run-<san> prints.
_POSTRUN_RC_RE = re.compile(
    r"EXECUTION (?:INCONCLUSIVE|VERIFIED) \(post-run, rc=(-?[0-9]+)\)"
)


def _file_matches(path: str | Path, pattern: re.Pattern) -> bool:
    try:
        with Path(path).open(encoding="utf-8", errors="replace") as stream:
            return any(pattern.search(line) for line in stream)
    except OSError:
        return False


def file_has_crash(path: str | Path, extra_patterns: tuple[str, ...] = ()) -> bool:
    if extra_patterns:
        pattern = re.compile("|".join((*CRASH_PATTERNS, *extra_patterns)))
        return _file_matches(path, pattern)
    try:
        pending = ""
        with Path(path).open(encoding="utf-8", errors="replace") as stream:
            while chunk := stream.read(64 * 1024):
                text = pending + chunk
                newline = text.rfind("\n")
                if newline < 0:
                    pending = text
                    continue
                complete = text[:newline + 1]
                pending = text[newline + 1:]
                if not any(hint in complete for hint in _CRASH_HINTS):
                    continue
                for line in complete.split("\n")[:-1]:
                    if _CRASH_RE.search(line + "\n"):
                        return True
            return bool(
                pending
                and any(hint in pending for hint in _CRASH_HINTS)
                and _CRASH_RE.search(pending)
            )
    except OSError:
        return False


def text_has_crash(text: str) -> bool:
    """Whether captured output carries a sanitizer or runtime diagnostic."""
    return any(_CRASH_RE.search(line) for line in text.splitlines())


#: A testcase or harness declaring that nothing executed: a managed
#: prerequisite it checked for was absent. Agent-authored, so it can only
#: withhold a verdict, never earn one.
_NO_EXEC_DECLARED_RE = re.compile(r"^NO_EXEC: \S")


def file_declares_no_exec(path: str | Path) -> bool:
    return _file_matches(path, _NO_EXEC_DECLARED_RE)


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


def execution_exit_reason(path: str | Path) -> str:
    """The child's exit code from the last post-run marker, as a compact reason.

    ``EXEC_FAIL``/``NO_EXEC`` are otherwise opaque in runs.jsonl: a target that
    cleanly rejected a malformed input (rc=69) and a loader that could not start
    the binary (rc=126) both record only the bare verdict. The marker already
    carries the child's exit code, so surfacing it lets a reader split
    input-quality failures from environment failures without opening the output
    file. Empty when no post-run marker was written (no execution evidence, or a
    runner that does not emit one). The last marker wins so a multi-run
    confirmation reports the outcome it settled on.
    """
    last = ""
    try:
        with Path(path).open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                match = _POSTRUN_RC_RE.search(line)
                if match:
                    last = f"child-rc={match.group(1)}"
    except OSError:
        return ""
    return last


_COVERAGE_GATE_RE = re.compile(
    r"^COVERAGE_GATE: (HIT|MISSED|COVERAGE_UNAVAILABLE|COVERAGE_ENV_FAIL|"
    r"COVERAGE_EXEC_FAIL)\b(?: - reached (?P<hit>.*))?"
    r"(?:.*\(closest: (?P<closest>.*)\))?.*$"
)

#: Industry-wide vocabulary a program uses to refuse an input before doing
#: anything with it. Inclusion criterion: the phrase names the *input* as the
#: problem (its syntax, format, framing, or integrity), not the environment.
FORMAT_REJECT_RE = re.compile(
    r"\b(?:parse|parsing|syntax|decod(?:e|ing)|format|magic|checksum|length|header)\s+"
    r"(?:error|fail(?:ed|ure)?|invalid|mismatch|rejected?)\b"
    r"|\b(?:invalid|malformed|corrupt(?:ed)?|unsupported|unrecognized|not a valid)\b"
    r"|\bnot an? [A-Za-z0-9_ -]{1,30} (?:file|stream|format|image|archive|document)\b"
    r"|\bcannot (?:parse|decode|read)\b",
    re.IGNORECASE,
)

#: The runner refused to start because this iteration's sanitizer budget is
#: spent. Nothing about the testcase was ever read, so the run records NO_EXEC
#: exactly like a broken harness does — and the repair is the opposite one:
#: wait for the next iteration rather than change the input.
BUDGET_EXHAUSTED_RE = re.compile(
    r"^\[run-sanitizer-multi\] BUDGET: EXHAUSTED", re.MULTILINE,
)


def file_budget_exhausted(path: str | Path) -> bool:
    """Whether a spent per-iteration sanitizer budget refused this run."""
    return _file_matches(path, BUDGET_EXHAUSTED_RE)


def strip_run_header(text: str) -> str:
    """Drop the sanitizer runner's header lines from saved output.

    The header names the testcase path; a file called `invalid-*.xml` must
    not read as the target rejecting its input, in any consumer of the text.
    """
    return "\n".join(
        line for line in text.splitlines()
        if not line.startswith(("ASAN_RUN_HEADER:", "SANITIZER_RUN_HEADER:"))
    )


#: The dynamic loader or exec layer refused the program: nothing about the
#: input was ever read.
_LOADER_RE = re.compile(
    r"dyld(?:\[\d+\])?: |Library not loaded|error while loading shared libraries"
    r"|cannot execute binary|[Ee]xec format error|symbol lookup error|Symbol not found"
    r"|cannot open shared object|image not found",
)
#: The program rejected its own command line.
_USAGE_RE = re.compile(
    r"\busage:|unrecognized option|invalid option|unknown option|illegal option"
    r"|missing (?:argument|operand)|too (?:few|many) arguments|requires an argument",
    re.IGNORECASE,
)
#: The process died on a signal or an assertion, with no sanitizer report.
_ABORT_RE = re.compile(
    r"killed by SIG[A-Z]+|Abort trap|Segmentation fault|Bus error|Illegal instruction"
    r"|Trace/BPT trap|[Aa]ssertion .* failed|Assertion failed|panicked at|fatal error:",
)

# Necessary supersets for the expensive execution-failure expressions. The
# full regex remains the authority; a false-positive hint only costs a scan.
_LOADER_HINTS = (
    "dyld",
    "Library not loaded",
    "error while loading shared libraries",
    "cannot execute binary",
    "Exec format error",
    "exec format error",
    "symbol lookup error",
    "Symbol not found",
    "cannot open shared object",
    "image not found",
)
_USAGE_HINTS = ("usage:", "option", "argument", "operand")
_ABORT_HINTS = (
    "killed by SIG",
    "Abort trap",
    "Segmentation fault",
    "Bus error",
    "Illegal instruction",
    "Trace/BPT trap",
    "assertion ",
    "Assertion ",
    "panicked at",
    "fatal error:",
)
_FORMAT_HINTS = (
    "parse",
    "parsing",
    "syntax",
    "decode",
    "decoding",
    "format",
    "magic",
    "checksum",
    "length",
    "header",
    "invalid",
    "malformed",
    "corrupt",
    "corrupted",
    "unsupported",
    "unrecognized",
    "not",
    "cannot",
)
_IGNORECASE_EXTRA_CHARS = "İıſK"

# (class, hint) pairs, most specific first. The hint names the repair the
# class implies; the class token is what telemetry counts.
_EXEC_FAIL_CLASSES = {
    "loader": "the program could not be loaded, so no input was read; fix the "
              "sanitizer binary/library route or [runner] env, not the testcase",
    "usage": "the program rejected its command line, not the input; fix argv, "
             "[runner].args, or the HARNESS invocation",
    "input-rejected": "the target refused the input before the suspicious code; "
                      "shape it past the parser (bin/find-seed; keep magic, "
                      "length, checksum, nesting) — the coverage closest frame "
                      "says where it stopped",
    "aborted": "the target died on a signal or assertion without a sanitizer "
               "report; an assertion is not a memory-safety bug by itself — "
               "confirm only if the guard protects memory",
    "unverified-exit": "exited 0 without the runner's success marker; check "
                       "[runner].success_codes and the post-run marker",
    "exit": "exited non-zero with no recognized diagnostic; read the output tail",
}


def execution_failure_class(
    path: str | Path, *, exit_reason: str | None = None,
) -> tuple[str, str]:
    """(class, hint) for an EXEC_FAIL, from the saved output and exit code.

    Deterministic and text-only: nothing here is a verdict or a model
    judgement, and no class accepts or discards anything. It only narrows
    where the agent looks, which is what 133 of 150 measured NO_EXEC rows —
    really EXEC_FAILs — never told them.
    """
    try:
        text = strip_run_header(Path(path).read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return "", ""
    reason = execution_exit_reason(path) if exit_reason is None else exit_reason
    try:
        rc = int(reason.rpartition("=")[2]) if reason else None
    except ValueError:
        rc = None
    folded: str | None = None

    def has_case_insensitive_hint(hints: tuple[str, ...]) -> bool:
        nonlocal folded
        if folded is None:
            folded = text.casefold()
        # Python's IGNORECASE gives ASCII ranges four extra Unicode matches.
        # Some casefold to an ASCII hint; checking all four explicitly covers
        # the remaining spellings without weakening the full-regex decision.
        return any(hint in folded for hint in hints) or any(
            character in text for character in _IGNORECASE_EXTRA_CHARS
        )

    if rc in (126, 127) or (
        any(hint in text for hint in _LOADER_HINTS) and _LOADER_RE.search(text)
    ):
        kind = "loader"
    elif (
        (rc in (2, 64) or rc is None)
        and has_case_insensitive_hint(_USAGE_HINTS)
        and _USAGE_RE.search(text)
    ):
        kind = "usage"
    elif (
        rc is not None and (-32 < rc < 0 or 128 < rc < 160)
    ) or (
        any(hint in text for hint in _ABORT_HINTS) and _ABORT_RE.search(text)
    ):
        # A signal death is a negative code from the runner's own wait, or
        # 129..159 through a shell; larger positive codes are a program's own
        # and say nothing about how it died. Decided before the input class:
        # a parser that warns "unsupported chunk" and then faults died on the
        # fault, and the hint must not send the agent back to the seed.
        kind = "aborted"
    elif rc in (65, 66) or (
        has_case_insensitive_hint(_FORMAT_HINTS)
        and FORMAT_REJECT_RE.search(text)
    ):
        kind = "input-rejected"
    elif rc == 0:
        kind = "unverified-exit"
    else:
        kind = "exit"
    return kind, _EXEC_FAIL_CLASSES[kind]


def coverage_outcome(path: str | Path) -> tuple[str, str]:
    """(coverage verdict, frame) recorded by the coverage gate, or ("", "").

    The frame is the reached symbol for a HIT and the closest reached frame
    for a MISSED; run-sanitizer-multi writes exactly one gate line per run,
    ahead of the sanitizer's own output.
    """
    try:
        with Path(path).open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                match = _COVERAGE_GATE_RE.match(line.rstrip("\n"))
                if match:
                    verdict = match.group(1)
                    if verdict.startswith("COVERAGE_"):
                        verdict = verdict[len("COVERAGE_"):]
                    frame = (match.group("hit") or match.group("closest") or "").strip()
                    # hits annotates a closest frame with the pool it came
                    # from; state keeps the frame, the output keeps the note.
                    frame = re.sub(r"\s*\[pool=[^\]]*\]\s*$", "", frame)
                    if frame in ("<none>", "<unnamed>") or frame.startswith("hits exited "):
                        frame = ""
                    return verdict, frame
    except OSError:
        return "", ""
    return "", ""


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
