"""Sanitizer stack-frame parsing and interesting-frame selection.

This module owns the harness-specific work: parsing sanitizer frame formats
(ASan ``#N 0x.. in func loc`` lines and Go race-detector ``func()`` / ``loc``
pairs) into frames, walking the crash stack, and selecting the top interesting
frames for the crash signature.

The ClusterFuzz-derived pieces — the ignore-regex list, the
``filter_function_name`` normalizer, ``MAX_CRASH_STATE_FRAMES``, and the
address/number scrubber — live in ``lib/clusterfuzz_stacktrace.py`` with
their upstream attribution and license. We follow ClusterFuzz's ordering:
the ignore check runs against the *raw* captured function name, and only a
surviving frame's name is normalized via ``filter_function_name`` before it
becomes part of the crash state (see ``StackFrame.state_function``).
"""

from __future__ import annotations

import argparse
import dataclasses
import re
import sys
from pathlib import Path

import clusterfuzz_stacktrace as _cf
from clusterfuzz_stacktrace import (
    MAX_CRASH_STATE_FRAMES,
    filter_addresses_and_numbers,
    filter_function_name,
)


_ASAN_FRAME_RE = re.compile(r"^\s*#(?P<index>\d+):?\s+(?P<addr>0x[0-9a-fA-F]+|[xX][0-9a-fA-F]+|<addr>)\s+(?:in\s+)?(?P<body>.+?)\s*$")
_LOC_RE = re.compile(r"(?P<loc>\S+:\d+(?::\d+)?)$")
_PATH_RE = re.compile(r"(?P<loc>\S+\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx|m|mm|rs|go|java|js|ts))$")
_MODULE_RE = re.compile(r"(?P<func>.*?)\s+(?P<loc>\([^)]*(?:\+0x[0-9a-fA-F]+)?\))$")
# A conflicting-access header opens each of the race's two accesses, e.g.
# "Write at 0x.. by goroutine 7:" / "Previous read at 0x.. by main goroutine:".
# We anchor at column 0 (headers are unindented; frames are indented) and stop
# at "by " so the goroutine/thread label can vary. The goroutine-*creation*
# stacks ("Goroutine 7 (running) created at:") are deliberately NOT matched —
# their ordering follows the scheduler and would destabilize the signature.
_GO_RACE_ACCESS_RE = re.compile(
    r"^(?:Atomic\s+)?(?:Previous\s+)?(?:Write|Read)\s+at\s+0x[0-9a-fA-F]+\s+by\s", re.IGNORECASE
)
_GO_RACE_FUNC_RE = re.compile(r"^\s+(?P<func>\S.*?)\(\)\s*$")
_GO_RACE_LOC_RE = re.compile(r"^\s+(?P<loc>\S+\.go:\d+)(?:\s+\+0x[0-9a-fA-F]+)?\s*$")
STATE_STOP_MARKERS = (
    "Direct leak of",
    "Uninitialized value was stored to memory at",
    "allocated by thread",
    "created by main thread at",
    "located in stack of thread",
    "previously allocated by",
)

# Canonical sanitizer-diagnostic signature: a line a sanitizer RUNTIME prints
# on a real memory-safety / UB / race fault — never something an agent can
# fabricate in prose. This is the single source of truth for "this text is a
# confirmed sanitizer crash"; it is shared by the benchmark's confirmed-crash
# count (lib/benchmark.py) and the severity scorer (bin/severity), and the
# The diagnostic gate in lib/triage.py mirrors it
# cross-language. Matches EVERY sanitizer the harness builds — ASan, HWASan,
# UBSan, TSan, MSan — so a crash from any of them is recognised identically.
SANITIZER_SIGNATURE_RE = re.compile(
    r"ERROR: (?:AddressSanitizer|HWAddressSanitizer|UndefinedBehaviorSanitizer)"
    r"|SUMMARY: (?:AddressSanitizer|HWAddressSanitizer|UndefinedBehaviorSanitizer)"
    r"|WARNING: (?:ThreadSanitizer|MemorySanitizer):"
    r"|SUMMARY: (?:ThreadSanitizer|MemorySanitizer):"
    r"|^WARNING: DATA RACE$"
    r"|UndefinedBehaviorSanitizer:"
    r"|^[^\s].*:\d+:\d+: runtime error:",
    re.MULTILINE,
)


def has_sanitizer_diagnostic(text: str) -> bool:
    """True when *text* carries a sanitizer runtime diagnostic for a real fault
    (any sanitizer the harness builds). The Python twin of lib/triage.py's
    ``_triage_has_sanitizer_diagnostic`` and the single gate behind the
    benchmark's confirmed-crash count — use it instead of hand-rolling an
    ASan-only ``ERROR: AddressSanitizer`` check, which silently misses
    HWASan/UBSan/TSan/MSan faults."""
    return bool(SANITIZER_SIGNATURE_RE.search(text or ""))


_DIAGNOSTIC_CLOSE_RE = re.compile(
    r"^\s*(?:==\d+==)?SUMMARY:\s", re.IGNORECASE,
)
_DIAGNOSTIC_OPEN_RE = re.compile(
    r"^\s*(?:==\d+==)?(?:ERROR|WARNING):\s"
    r"|^\s*UndefinedBehaviorSanitizer:"
    r"|^[^\s].*:\d+:\d+:\s*runtime error:",
    re.IGNORECASE,
)


def first_sanitizer_diagnostic(text: str) -> str | None:
    """Return the first complete runtime diagnostic in *text*.

    Reports may contain prose plus several confirmation runs.  Primitive
    classification must not splice a class from one run together with an
    access size or direction from another, and report prose must not outrank
    the runtime.  This bounded slice keeps the first diagnostic's headline,
    access line, SCARINESS metadata, and closing summary together.
    """
    if not text:
        return None
    match = SANITIZER_SIGNATURE_RE.search(text)
    if match is None:
        return None
    lines = text.splitlines(keepends=True)
    offset = 0
    start = 0
    for index, line in enumerate(lines):
        if offset + len(line) > match.start():
            start = index
            break
        offset += len(line)
    block = [lines[start]]
    for line in lines[start + 1:]:
        if _DIAGNOSTIC_CLOSE_RE.match(line):
            block.append(line)
            break
        if _DIAGNOSTIC_OPEN_RE.match(line):
            break
        block.append(line)
    return "".join(block)


@dataclasses.dataclass(frozen=True)
class StackFrame:
    index: int
    function: str
    location: str
    raw: str
    #: Instruction address as printed, or "" when the report carries none (a
    #: scrubbed `<addr>` placeholder, or a format with no address at all).
    #: Comparable only within one report — it moves with ASLR between runs.
    address: str = ""

    @property
    def state_function(self) -> str:
        """Function name normalized for the crash state — parameter list,
        ``[abi:...]`` suffixes, and anonymous namespaces stripped. See
        `filter_function_name`. Use this (not `function`) anywhere the name
        is shown to a human or used as a dedup key; `function` stays raw for
        the ignore step."""
        return filter_function_name(self.function)

    @property
    def display(self) -> str:
        """Crash-state line for this frame: normalized function name + location,
        then ASLR addresses and line numbers scrubbed via ClusterFuzz's
        `filter_addresses_and_numbers`. This is what flows into dedup keys
        (`crash_signature`, `extract_dedup_frames`); the raw `function` and
        `location` fields stay untouched for forensic display (render-md uses
        them directly for the triage card)."""
        func = self.state_function
        line = f"{func} {self.location}" if self.location else func
        return filter_addresses_and_numbers(line)


def parse_frame_body(body: str) -> tuple[str, str]:
    """Split a sanitizer frame display into its function and location."""
    body = body.strip()
    loc_match = _LOC_RE.search(body)
    if loc_match:
        loc = loc_match.group("loc")
        return body[:loc_match.start()].strip(), loc

    path_match = _PATH_RE.search(body)
    if path_match:
        loc = path_match.group("loc")
        return body[:path_match.start()].strip(), loc

    module_match = _MODULE_RE.match(body)
    if module_match:
        return module_match.group("func").strip(), module_match.group("loc").strip()

    return body, ""


def parse_asan_frame(line: str) -> StackFrame | None:
    match = _ASAN_FRAME_RE.match(line)
    if not match:
        return None
    function, location = parse_frame_body(match.group("body"))
    if not function:
        return None
    address = match.group("addr")
    return StackFrame(
        index=int(match.group("index")),
        function=function,
        location=location,
        raw=line.strip(),
        # A scrubbed placeholder is not an address: every frame carries the
        # same one, so grouping on it would fuse unrelated frames.
        address="" if address == "<addr>" else address,
    )


def is_ignored_frame(frame: StackFrame) -> bool:
    # Match against the function name (with params) and the full raw line —
    # ClusterFuzz runs the ignore check before name normalization.
    #
    # We deliberately do NOT pass `frame.location` as a separate haystack. The
    # location is a bare file path (e.g. `maint/utf8.c:361`), and several
    # ignore rules are `^`-anchored bare-identifier *function* rules (`^main`,
    # `^new`, `^free`, …). Matching those against a path produces false
    # positives — `^main` matches the path `maint/...`, silently dropping a
    # legitimate frame whose source happens to live under `maint/` (pcre2 and
    # friends have a top-level `maint/`). The raw line already contains the
    # location substring, so the genuine path-based rules (`.*/libc\+\+/`,
    # `.*/googletest/`, …) still fire through `raw`; and `raw` always starts
    # with `#<n> 0x…`, so the function-name `^` rules can never false-match it.
    function = frame.function
    if frame.raw.startswith("go-race ") and function.startswith("main."):
        # In Go, `main.` is the application package prefix, not the C/C++
        # process entrypoint that ClusterFuzz's `^main` rule targets. Strip it
        # so a genuine `main.<func>` race frame is not dropped as boilerplate.
        function = function.removeprefix("main.")
    return _cf.matches_ignore_regexes(function, frame.raw)


def iter_go_race_frames(text: str) -> list[StackFrame]:
    """Parse Go race-detector ``WARNING: DATA RACE`` reports into frames.

    Go prints each access as an indented ``pkg.func()`` line followed by an
    indented ``file.go:line +0x..`` line, with no ``#N 0x..`` prefix, so the
    ASan parser does not see them. We pair the two lines into a StackFrame
    keyed the same way as sanitizer frames.
    """
    if "WARNING: DATA RACE" not in text:
        return []

    frames: list[StackFrame] = []
    lines = text.splitlines()
    want_site = False
    for pos, line in enumerate(lines):
        if _GO_RACE_ACCESS_RE.match(line):
            # The first func()/loc pair after a header is the racing site; the
            # deeper call-chain frames below it are skipped until the next
            # access header so only the two racing sites form the signature.
            want_site = True
            continue
        if not want_site or pos + 1 >= len(lines):
            continue
        func_match = _GO_RACE_FUNC_RE.match(line)
        loc_match = _GO_RACE_LOC_RE.match(lines[pos + 1])
        if not func_match or not loc_match:
            continue
        loc = loc_match.group("loc")
        frames.append(
            StackFrame(
                index=len(frames),
                function=func_match.group("func") + "()",
                location=loc,
                raw=f"go-race {line.strip()} {loc}",
            )
        )
        want_site = False
    if len(frames) >= 2:
        # The race detector reports the conflicting access pair as read/write
        # or write/read depending on scheduler timing. Canonicalize the top
        # pair so confirm reruns don't look like different crashes.
        head = sorted(frames[:2], key=lambda frame: frame.display)
        frames = [dataclasses.replace(f, index=i) for i, f in enumerate(head + frames[2:])]
    return frames


def iter_asan_frames(text: str) -> list[StackFrame]:
    frames: list[StackFrame] = []
    fallback_frames: list[StackFrame] = []
    in_report = False
    for line in text.splitlines():
        if "ERROR: AddressSanitizer" in line or "ERROR: HWAddressSanitizer" in line:
            in_report = True
            frames = []
            continue
        frame = parse_asan_frame(line)
        if not in_report:
            if frame is not None:
                fallback_frames.append(frame)
            continue
        if frames and any(marker in line for marker in STATE_STOP_MARKERS):
            break
        if line.startswith("SUMMARY: "):
            break
        if frame is not None:
            frames.append(frame)
    return frames or fallback_frames or iter_go_race_frames(text)


def interesting_frames(text: str, want: int = 5) -> list[StackFrame]:
    out: list[StackFrame] = []
    for frame in iter_asan_frames(text):
        if is_ignored_frame(frame):
            continue
        out.append(frame)
        if len(out) >= min(want, MAX_CRASH_STATE_FRAMES):
            break
    return out


def first_interesting_frame(text: str) -> StackFrame | None:
    frames = interesting_frames(text, want=1)
    return frames[0] if frames else None


def leading_inline_group(text: str) -> list[StackFrame]:
    """The top interesting frame plus the inline expansion sharing its address.

    One instruction has as many names as the compiler inlined into it, and
    which of them a report shows is a property of the symbolizer, not of the
    fault: ASan's in-process symbolizer expands the chain into a frame per
    name, while an offline `atos` pass over a `-g1` binary prints only the
    outermost. So the same crash reads as `xmlVUpdateError` under one and
    `xmlVRaiseError` under the other. Comparing frame `#0` across two reports
    therefore calls one crash two bugs; compare the groups instead, which
    intersect exactly when both name the same instruction.
    """
    group: list[StackFrame] = []
    address = ""
    for frame in iter_asan_frames(text):
        if is_ignored_frame(frame):
            continue
        if not group:
            group.append(frame)
            address = frame.address
            if not address:
                break
            continue
        # Inline expansion is contiguous. Stopping at the first different
        # address keeps a recursive function's later frames, which repeat the
        # address further down the stack, out of the group. Do not reuse
        # interesting_frames() here: its crash-signature cap is deliberately
        # small, while an inline chain has no such three-name guarantee.
        if frame.address != address:
            break
        group.append(frame)
    return group


def crash_signature(text: str, want: int = MAX_CRASH_STATE_FRAMES) -> list[str]:
    """Address-stable fingerprint for a crash.

    Returns up to `want` (function, location) lines from the top of the
    interesting-frame stream. Used by run-sanitizer-multi to detect when reruns
    reproduce the same crash even though addresses, allocation tags, and
    thread ids differ between runs.

    Empty list = no parseable crash frames (clean run, or a non-ASan
    failure mode).
    """
    return [frame.display for frame in interesting_frames(text, want=want)]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("asan_file", type=Path)
    parser.add_argument("--first-display", action="store_true")
    parser.add_argument(
        "--signature",
        action="store_true",
        help="emit up to 3 top interesting frames (one per line) for crash matching",
    )
    args = parser.parse_args(argv)
    try:
        text = args.asan_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 1
    if args.signature:
        sig = crash_signature(text)
        # Empty output is a meaningful answer ("no crash signature"); the
        # caller distinguishes it from a missing file via exit code 0 vs 1.
        for line in sig:
            print(line)
        return 0
    frame = first_interesting_frame(text)
    if frame is None:
        return 1
    if args.first_display:
        print(frame.display)
    else:
        print(frame.raw)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
