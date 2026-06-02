#!/usr/bin/env python3
"""Crash artifact discovery shared by triage and export tooling."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import Iterable, Optional


ARTIFACT_EXACT = {
    "REPORT.md",
    "REPORT.html",
    "report.md",
    "description.md",
    "README.md",
    "reproduce.sh",
    "testcase.sh",
    "reproducer.sh",
    "sanitizer.txt",
    "asan.txt",
    "asan-output.txt",
    "asan_output.txt",
    "msan.txt",
    "tsan.txt",
    "ubsan.txt",
    "harness.c",
    "reachability.json",
    "promotion.log",
}

ARTIFACT_SUFFIXES = (
    ".asan.txt",
    ".sanitizer.txt",
    ".msan.txt",
    ".tsan.txt",
    ".ubsan.txt",
    ".log",
    ".md",
    ".html.tmp",
    # `.out` / `.err` are reserved for audit-internal logs (e.g.
    # .audit/reachability.out is the human-readable summary written by
    # lib/triage.sh:966). Without this exclusion, find_testcase happily
    # selects reachability.out as the testcase, export-repro stages it
    # as input.out, and the generated reproduce.sh feeds prose into the
    # harness — the harness silently catches its parse failure and the
    # reproducer "succeeds" with no output. Testcases never use these
    # suffixes; if a target ever needs to, add it explicitly via the
    # ASAN_RUN_HEADER testcase= field (which bypasses this filter).
    ".out",
    ".err",
)

TESTCASE_PREFIXES = (
    "input.",
    "input_",
    "input-",
    "testcase",
    "test-case",
    "tc.",
    "tc_",
    "tc-",
    "repro.",
    "repro_",
    "repro-",
    "reproducer",
)

TEXT_EXTS_REQUIRING_PREFIX = {".txt"}
_BIN_FILE_RE = re.compile(r"executable|Mach-O|ELF|shared object|dSYM", re.IGNORECASE)
_ASAN_TESTCASE_RE = re.compile(r"\btestcase=([^ \t\r\n]+)")


def _sort_key(path: Path) -> tuple[int, str]:
    name = path.name
    priority = 1
    if name.startswith("input."):
        priority = 0
    elif any(name.startswith(p) for p in TESTCASE_PREFIXES):
        priority = 0
    return priority, name.casefold()


def _visible_files(directory: Path) -> list[Path]:
    try:
        entries = directory.iterdir()
    except OSError:
        return []
    return sorted(
        (p for p in entries if p.is_file() and not p.name.startswith(".")),
        key=_sort_key,
    )


def is_executable_binary(path: Path) -> bool:
    if not os.access(path, os.X_OK):
        return False
    try:
        out = subprocess.run(
            ["file", str(path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return bool(_BIN_FILE_RE.search(out.stdout))


def _looks_like_asan_artifact(name: str) -> bool:
    lower = name.lower()
    return (
        lower.startswith(("asan", "msan", "tsan", "ubsan"))
        or any(f".{kind}." in lower for kind in ("asan", "msan", "tsan", "ubsan"))
        or any(
            lower.endswith(suffix)
            for suffix in (
                ".asan.txt",
                ".msan.txt",
                ".tsan.txt",
                ".ubsan.txt",
                ".asan-output.txt",
                ".asan_output.txt",
            )
        )
    )


# Source extensions that probe builds with a C-family compiler. A file
# with one of these suffixes whose body defines main() is treated as
# the audit harness, never the testcase. We derive the tuple from the
# language registry so adding a new compiled C-family extension flows
# through automatically. Non-C compiled harness extensions (.rs/.go/
# .swift/.kt) are NOT included: they don't reach a free-standing main()
# the way C/C++ ones do, and the historical heuristic only fired on
# the C-family set.
def _harness_source_suffixes() -> tuple[str, ...]:
    # Lazy import to avoid a circular dep if crash_artifacts is loaded
    # before lib/ is on sys.path (e.g. when run as a script).
    import sys as _sys
    from pathlib import Path as _Path
    _lib_dir = str(_Path(__file__).resolve().parent)
    if _lib_dir not in _sys.path:
        _sys.path.insert(0, _lib_dir)
    import languages as _languages
    c_lang = _languages.for_name("c")
    cpp_lang = _languages.for_name("cpp")
    exts: list[str] = []
    for lang in (c_lang, cpp_lang):
        if lang:
            exts.extend(e.lower() for e in lang.harness_exts)
    # Dedupe while preserving order.
    seen: set[str] = set()
    unique: list[str] = []
    for e in exts:
        if e not in seen:
            seen.add(e)
            unique.append(e)
    return tuple(unique)


_HARNESS_SOURCE_SUFFIXES = _harness_source_suffixes()
_HARNESS_MAIN_RE = re.compile(r"^(?:int\s+)?main\s*\(", re.MULTILINE)


def _looks_like_harness_source(path: Path) -> bool:
    """A C/C++ source file whose body defines main() is the audit harness,
    never the testcase. Agent-named harnesses (e.g.
    `to_json_throwing_string_harness.cpp`) bypass the ARTIFACT_EXACT list,
    so we sniff for main() the same way find_harness() does."""
    suffix = path.suffix.lower()
    if suffix not in _HARNESS_SOURCE_SUFFIXES:
        return False
    try:
        # Cap the read — main() should be in the first few KB; very large
        # generated sources still scan in negligible time.
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(_HARNESS_MAIN_RE.search(text))


def is_testcase_candidate(path: Path, *, from_asan_header: bool = False,
                          min_bytes: int = 1) -> bool:
    """Return true when `path` is likely the reproducing testcase.

    The rule is deliberately exclusion-based for binary/parser inputs, but
    `.txt` is only accepted for canonical testcase names (`input.txt`,
    `testcase*.txt`, `reproducer*.txt`) or when ASan recorded the path in its
    `ASAN_RUN_HEADER`. This preserves pcre2-style text inputs without letting
    `notes.txt` satisfy promotion.
    """
    if not path.is_file():
        return False
    name = path.name
    if name.startswith("."):
        return False
    if name in ARTIFACT_EXACT:
        return False
    if any(name.endswith(suf) for suf in ARTIFACT_SUFFIXES):
        return False
    if _looks_like_asan_artifact(name):
        return False
    if is_executable_binary(path):
        return False
    try:
        if path.stat().st_size < min_bytes:
            return False
    except OSError:
        return False

    lower = name.lower()
    prefixed = any(lower.startswith(p) for p in TESTCASE_PREFIXES)
    # A C/C++ source file that defines main() is almost certainly the
    # audit harness (e.g. `to_json_throwing_string_harness.cpp`), not the
    # testcase. The exception is self-contained reproducer scripts whose
    # name advertises their role (`reproducer.c`, `tc-foo.cpp`); those
    # match TESTCASE_PREFIXES and bypass the heuristic. Without this
    # gate, find_testcase falls through past the rejected real testcase
    # and picks the harness — which export-repro then stages as
    # `input.cpp`, producing a reproduce.sh that compiles the harness as
    # its own input. See CRASH-002-1.20260509 incident.
    if not (prefixed or from_asan_header) and _looks_like_harness_source(path):
        return False
    if path.suffix.lower() in TEXT_EXTS_REQUIRING_PREFIX:
        return from_asan_header or prefixed
    return True


def _resolve_header_path(token: str, bases: Iterable[Path]) -> Optional[Path]:
    raw = token.strip().strip("\"'")
    if not raw:
        return None
    p = Path(raw)
    candidates = [p] if p.is_absolute() else [*(base / p for base in bases), p]
    for cand in candidates:
        if cand.is_file():
            return cand.resolve()
    return None


def testcase_from_asan_header(asan_files: Iterable[Path], bases: Iterable[Path],
                              min_bytes: int = 1) -> Optional[Path]:
    base_list = [Path.cwd(), *(Path(b) for b in bases)]
    for asan in asan_files:
        if not asan.is_file():
            continue
        try:
            text = asan.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = _ASAN_TESTCASE_RE.search(text)
        if not m:
            continue
        p = _resolve_header_path(m.group(1), base_list)
        if p is not None and is_testcase_candidate(p, from_asan_header=True, min_bytes=min_bytes):
            return p
    return None


def find_primary_asan(scan_dirs: Iterable[Path]) -> Optional[Path]:
    # Historical API name: callers still ask for "asan", but probe/export use
    # this for every sanitizer family and normalize the bundle to asan.txt.
    preferred = (
        "sanitizer.txt",
        "asan.txt",
        "asan-output.txt",
        "asan_output.txt",
        "msan.txt",
        "tsan.txt",
        "ubsan.txt",
    )
    dirs = [Path(d) for d in scan_dirs]
    for d in dirs:
        for name in preferred:
            p = d / name
            if p.is_file() and p.stat().st_size > 0:
                return p
    matches: list[Path] = []
    for d in dirs:
        for p in _visible_files(d):
            name = p.name
            if (
                name.startswith("asan-output")
                or name.startswith("asan_output")
                or name.startswith("asan-raw")
                or name.endswith(".asan.txt")
                or name.endswith(".msan.txt")
                or name.endswith(".tsan.txt")
                or name.endswith(".ubsan.txt")
            ):
                matches.append(p)
    return sorted(matches, key=lambda p: p.name.casefold())[0] if matches else None


def find_testcase(scan_dirs: Iterable[Path], *, asan_files: Iterable[Path] = (),
                  min_bytes: int = 1) -> Optional[Path]:
    dirs = [Path(d) for d in scan_dirs if Path(d).is_dir()]

    # Prefer audit-preserved originals before following ASAN_RUN_HEADER.
    # The header records the scratch path that crashed, but scratch dirs are
    # reused across investigations. A later testcase at the same path can
    # make export-repro stage the wrong input even though .audit/testcase.*
    # still holds the immutable reproducer captured with the crash.
    audit_dirs = [d for d in dirs if d.name == ".audit"]
    for d in audit_dirs:
        for p in _visible_files(d):
            if is_testcase_candidate(p, min_bytes=min_bytes):
                return p

    header_hit = testcase_from_asan_header(
        asan_files,
        [*dirs, *(d.parent for d in dirs)],
        min_bytes=min_bytes,
    )
    if header_hit is not None:
        return header_hit

    for d in dirs:
        for p in _visible_files(d):
            if is_testcase_candidate(p, min_bytes=min_bytes):
                return p
    return None
