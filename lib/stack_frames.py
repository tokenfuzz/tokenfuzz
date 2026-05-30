"""ASan stack-frame parsing and interesting-frame selection.

This module owns the harness-specific work: parsing ASan ``#N 0x.. in func
loc`` lines into frames, walking the crash stack, and selecting the top
interesting frames for the crash signature.

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


_ASAN_FRAME_RE = re.compile(r"^\s*#(?P<index>\d+):?\s+(?:0x[0-9a-fA-F]+|[xX][0-9a-fA-F]+|<addr>)\s+(?:in\s+)?(?P<body>.+?)\s*$")
_LOC_RE = re.compile(r"(?P<loc>\S+:\d+(?::\d+)?)$")
_PATH_RE = re.compile(r"(?P<loc>\S+\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx|m|mm|rs|go|java|js|ts))$")
_MODULE_RE = re.compile(r"(?P<func>.*?)\s+(?P<loc>\([^)]*(?:\+0x[0-9a-fA-F]+)?\))$")
STATE_STOP_MARKERS = (
    "Direct leak of",
    "Uninitialized value was stored to memory at",
    "allocated by thread",
    "created by main thread at",
    "located in stack of thread",
    "previously allocated by",
)


@dataclasses.dataclass(frozen=True)
class StackFrame:
    index: int
    function: str
    location: str
    raw: str

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


def _parse_frame_body(body: str) -> tuple[str, str]:
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
    function, location = _parse_frame_body(match.group("body"))
    if not function:
        return None
    return StackFrame(
        index=int(match.group("index")),
        function=function,
        location=location,
        raw=line.strip(),
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
    return _cf.matches_ignore_regexes(frame.function, frame.raw)


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
    return frames if frames else fallback_frames


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


def crash_signature(text: str, want: int = MAX_CRASH_STATE_FRAMES) -> list[str]:
    """Address-stable fingerprint for a crash.

    Returns up to `want` (function, location) lines from the top of the
    interesting-frame stream. Used by run-asan-multi to detect when reruns
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
