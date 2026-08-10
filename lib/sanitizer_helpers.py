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

from verdict import CLEAN_PATTERN, CRASH_PATTERNS


def run_symbolized(
    command, timeout: int, environment: dict, options_var: str, **kwargs,
):
    """Run a sanitizer target and emit its report with source locations.

    In-process symbolization has to spawn a child, which a sandboxed agent shell
    can refuse; the report then names functions but carries no source line. So
    the run captures with symbolization off and the report is symbolized offline
    against the same build. One helper for every mode of every runner — the modes
    that grew their own execution path are exactly the ones that kept shipping
    addresses. Without an offline symbolizer to fall back on, the command streams
    as it did before.

    ``options_var`` is the sanitizer's options variable within ``environment``
    (``ASAN_OPTIONS``, ``UBSAN_OPTIONS``, …); later values win, so appending is
    enough to turn symbolization off.
    """
    import sanitizer  # deferred: sanitizer imports this module
    from timeout import capture_timeout, run_timeout

    if not sanitizer.symbolize_available():
        return run_timeout(command, timeout, env=environment, **kwargs)
    environment = dict(environment)
    environment[options_var] = (
        f"{environment.get(options_var, '')}:symbolize=0".lstrip(":")
    )
    with capture_timeout(
        command, timeout, env=environment, **kwargs
    ) as (completed, report):
        sanitizer.symbolize_file(report)
        copy_file(report, sys.stdout.buffer)
    return completed


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


def browser_dumps_dom(launch_args) -> bool:
    """Whether the runner echoes page source into its own output stream."""
    return any(
        value == "--dump-dom" or value.startswith("--dump-dom=")
        for value in launch_args
    )


def untrusted_browser_filters(launch_args) -> tuple:
    """Filters for a stream carrying page source, else nothing to neutralise.

    Only a DOM-dumping runner puts attacker-chosen bytes where a verdict is
    read from. Every other browser keeps its pre-existing raw output, so a
    sanitizer report that reached stderr instead of its log file still reads
    as the crash it is.
    """
    return _BROWSER_UNTRUSTED if browser_dumps_dom(launch_args) else ()


def browser_execution_marker_seen(path: Path, launch_args) -> bool:
    """Do not trust a marker that a DOM-dumping runner can echo from source."""
    if not browser_dumps_dom(launch_args):
        return file_contains(path, b"TESTCASE_EXECUTED")
    with path.open("rb") as stream:
        return any(
            _CHROMIUM_CONSOLE_RECORD.match(line)
            and b"TESTCASE_EXECUTED" in line
            for line in stream
        )


def report_browser_execution(
    path: Path,
    launch_args,
    withheld: set[re.Pattern],
    *,
    tool: str,
    sanitizer: str,
    persist: str = "",
) -> None:
    """Emit a metric-safe browser execution verdict when no report exists."""
    prefix = f"[run-{tool}]"
    marker_seen = browser_execution_marker_seen(path, launch_args)
    if _BROWSER_RAW_CRASH_TEXT in withheld:
        # A neutralised stream cannot be re-read for what it neutralised, so
        # keep the raw bytes wherever the crash path would have kept them.
        if persist and Path(persist).is_dir():
            shutil.copy2(path, Path(persist) / "browser-output.txt")
            print(
                f"{prefix} Raw browser output preserved in {persist}",
                file=sys.stderr,
            )
        if marker_seen:
            print(
                f"{prefix} browser EXECUTION INCONCLUSIVE "
                f"(post-run, sanitizer-like browser output had no dedicated "
                f"{sanitizer} report)",
                file=sys.stderr,
            )
        else:
            print(
                f"{prefix} WARNING: page-influenced browser output matched a "
                f"sanitizer signature but no dedicated {sanitizer} report "
                "was created; crash status and execution are inconclusive",
                file=sys.stderr,
            )
    elif marker_seen:
        print(
            f"{prefix} browser EXECUTION VERIFIED "
            "(post-run, marker=TESTCASE_EXECUTED)",
            file=sys.stderr,
        )
    else:
        print(
            f"{prefix} WARNING: no {sanitizer} issue and no execution "
            "evidence - testcase may not have run",
            file=sys.stderr,
        )


def copy_file(path: Path, destination) -> None:
    with path.open("rb") as source:
        shutil.copyfileobj(source, destination, 1024 * 1024)


def copy_filtered(
    path: Path, destination, patterns, *, mask=()
) -> set[re.Pattern]:
    """Copy the stream, dropping `patterns` and neutralising `mask` matches.

    Dropping is for known noise, which carries nothing. A `mask` match is
    page-influenced text that must not read as a verdict but is still evidence,
    so its matching spans are replaced in place and the rest of the line is
    kept. Returns every filter that matched.
    """
    withheld: set[re.Pattern] = set()
    with path.open("rb") as source:
        for raw in source:
            line = raw.decode(errors="replace")
            matched = next(
                (pattern for pattern in patterns if pattern.search(line)),
                None,
            )
            if matched is not None:
                withheld.add(matched)
                continue
            for pattern in mask:
                if not pattern.search(line):
                    continue
                withheld.add(pattern)
                line = pattern.sub(_MASKED, line)
                if pattern.search(line):
                    line = ""     # cannot be neutralised: drop it entirely
                    break
            destination.write(line.encode())
    return withheld


# Browser stdout/stderr can carry page-controlled console records, including
# unescaped newlines. Crash evidence comes from the sanitizer's separate
# log_path files, which the runners copy without this filter. The replacement
# deliberately shares no text with the patterns, so a masked line cannot match
# them again.
_MASKED = "[withheld page-influenced text]"
_CHROMIUM_CONSOLE_RECORD = re.compile(
    rb"^\[(?:[0-9]+:[0-9]+:)?[0-9]{4}/[0-9]{6}(?:\.[0-9]+)?"
    rb":INFO:CONSOLE\([0-9]+\)\]"
)
_BROWSER_RAW_CRASH_TEXT = re.compile("|".join(CRASH_PATTERNS))
_BROWSER_RAW_HARNESS_TEXT = re.compile(
    CLEAN_PATTERN
    + r"|^\[run-(?:asan|ubsan|msan|tsan)\] "
      r"(?:browser|js|xpcshell|generic) EXECUTION INCONCLUSIVE \(post-run"
)
_BROWSER_UNTRUSTED = (_BROWSER_RAW_CRASH_TEXT, _BROWSER_RAW_HARNESS_TEXT)

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
    copy_filtered(
        Path(args.path), sys.stdout.buffer, _BROWSER_NOISE,
        mask=untrusted_browser_filters(
            ["--dump-dom"] if args.dump_dom else []
        ),
    )
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
    command.add_argument("--dump-dom", action="store_true")
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
