#!/usr/bin/env python3
"""Crash artifact discovery shared by triage and export tooling."""

from __future__ import annotations

import base64
import binascii
import os
import re
import shlex
import subprocess
from pathlib import Path
from typing import Iterable, Optional

import stack_frames


ARTIFACT_EXACT = {
    "REPORT.md",
    "REPORT.html",
    "report.md",
    "report.html",
    "description.md",
    "README.md",
    "reproduce.sh",
    "sanitizer.txt",
    "harness.c",
    "severity.json",
    "validation.json",
    "promotion.log",
    # Recorded CLI argv (find_repro_args), not a testcase — excluded here
    # because it would otherwise match the "repro." TESTCASE_PREFIXES.
    "repro.cmd",
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
    # .audit/severity.out is the human-readable summary written by
    # lib/triage.py:966). Without this exclusion, find_testcase happily
    # selects severity.out as the testcase, export-repro stages it
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
# The model-direct crash contract names its testcase exactly `input`; it must
# rank ahead of a derived rendering such as `input.hex`.
TESTCASE_EXACT_NAMES = frozenset({"input"})

# Explicit self-contained reproducer roles. These are accepted alongside normal
# testcase discovery, but only for non-metadata files. In particular,
# ``repro.cmd`` is replay argv rather than a reproducer, and words such as
# ``reproduction-notes`` deliberately do not match these anchored prefixes.
REPRODUCER_ROLE_PREFIXES = (
    "poc.",
    "poc_",
    "poc-",
    "repro.",
    "repro_",
    "repro-",
    "reproducer",
    "testcase",
)

TEXT_EXTS_REQUIRING_PREFIX = {".txt"}

# Relaxed-mode exclusions: `.txt` stems that denote human-readable prose or
# metadata about a crash rather than a reproducing input. The relaxed
# last-resort pass in find_testcase accepts any other non-canonical `.txt`
# (e.g. `payload.txt`) so a real text reproducer is not lost, but a dir whose
# only `.txt` is one of these must still read as "no testcase". Inclusion
# criterion: a word naming notes/output/documentation, never a program input.
NONINPUT_TEXT_STEMS = {
    "notes", "note", "readme", "description", "desc", "summary",
    "comment", "comments", "changelog", "todo", "output", "out",
    "log", "logs", "analysis", "writeup", "write-up", "explanation",
}
_BIN_FILE_RE = re.compile(r"executable|Mach-O|ELF|shared object", re.IGNORECASE)
_ASAN_TESTCASE_RE = re.compile(r"\btestcase=([^ \t\r\n]+)")
_SHELL_SHEBANG_RE = re.compile(r"^\s*#!.*\b(?:sh|bash|zsh|ksh)\b")
_SHELL_WRAPPER_HINT_RE = re.compile(
    r'(?m)(?:^\s*set\s+-|^\s*(?:ROOT|SRC|BUILD|SCRATCH|HARNESS_C|HARNESS_BIN|BIN)='
    r'|^\s*(?:if|for|while)\s+|^\s*exec\s+|"\$(?:BIN|HARNESS_BIN|san_bin)"'
    r'|\$(?:BIN|HARNESS_BIN|san_bin|repro_src)\b|/build-(?:a|ub|m|t)san/)'
)

SANITIZER_NAMES = frozenset({"asan", "ubsan", "msan", "tsan", "race"})
MAX_RECORDED_SANITIZER_OPTIONS_BYTES = 64 * 1024
# A sanitizer report's own opening line, optionally carrying the runtime's
# process-id prefix.
_HEADLINE = r"^(?:==\d+==)?\s*(?:ERROR|WARNING|SUMMARY): "
# UBSan prefixes every check it reports with the source location it fired at.
# A bare "runtime error:" is also how Go opens a panic and how a target can
# label its own output, so the location is what separates the sanitizer's
# report from the program's. Inference and the fault key share this one form:
# reading an unanchored "runtime error:" let a line of target output stand in
# as the fault, and two unrelated crashes then keyed alike and counted as each
# other's reproduction.
_UBSAN_RUNTIME_ERROR = r"^[^\s].*?:\d+:\d+:\s*runtime error:"
# Raw-diagnostic fallback for output with no runner header. Each pattern is a
# sanitizer's own report line, not a mention of its name: a target that prints
# "runtime error:" or names MemorySanitizer in its own output must not reclassify
# an ASan report. First match wins, so a diagnostic carrying two reports is
# attributed to the more specific one — a Go race log that also panics with
# "runtime error:" is a race, not UBSan.
_RAW_DIAGNOSTIC_PATTERNS = (
    ("msan", re.compile(_HEADLINE + r"MemorySanitizer:", re.MULTILINE)),
    ("tsan", re.compile(_HEADLINE + r"ThreadSanitizer:", re.MULTILINE)),
    ("asan", re.compile(
        _HEADLINE + r"(?:HW)?AddressSanitizer:|AddressSanitizer:DEADLYSIGNAL"
        r"|^ASAN_RUN_HEADER:", re.MULTILINE,
    )),
    ("race", re.compile(r"^WARNING: DATA RACE$", re.MULTILINE)),
    ("ubsan", re.compile(
        _HEADLINE + r"UndefinedBehaviorSanitizer:|UndefinedBehaviorSanitizer:DEADLYSIGNAL"
        r"|" + _UBSAN_RUNTIME_ERROR, re.MULTILINE,
    )),
)
_ASAN_FAULT_RE = re.compile(
    r"(?:ERROR|SUMMARY):\s+(?:AddressSanitizer|HWAddressSanitizer):\s+"
    r"([A-Za-z0-9_-]+)"
)
_MSAN_FAULT_RE = re.compile(
    r"(?:ERROR|SUMMARY|WARNING):\s+MemorySanitizer:\s+([A-Za-z0-9_-]+)"
)
# UBSan names its check in the fixed prose of the `runtime error:` line; the
# rest of that line is run-specific (indices, addresses, type names), so the
# prose with those removed is a stable identity. This replaced a list of five
# message shapes that had rotted: division by zero, signed integer overflow,
# null dereference, misaligned access and every other check absent from it
# reduced to no fault at all, and a replay that reproduced 5/5 could not be
# told from one that never ran.
_UBSAN_RUNTIME_ERROR_RE = re.compile(
    _UBSAN_RUNTIME_ERROR + r"\s*(.+)$", re.MULTILINE
)
_UBSAN_RUN_SPECIFIC_RE = re.compile(
    r"'[^']*'"                              # quoted type names
    r"|0x[0-9a-fA-F]+"                      # addresses
    r"|\b\d+(?:\.\d+)?(?:[eE][-+]?\d+)?\b"  # numeric literals
)


# TSan states its kind as the leading prose of the report line; a parenthetical
# aside, the location and the thread ids follow it. Reading that prose covers
# every check the tool has, where naming two of them left lock-order-inversion,
# thread leak and mutex misuse with no fault to compare.
_TSAN_REPORT_RE = re.compile(r"(?:WARNING|SUMMARY):\s+ThreadSanitizer:\s*(.+)")
_TSAN_PARENTHETICAL_RE = re.compile(r"\([^)]*\)")
_TSAN_KIND_WORD_RE = re.compile(r"[A-Za-z][A-Za-z-]*")


# A fatal signal is not a check, so it carries no `runtime error:` line and
# neither sanitizer's normal parser sees it. It is stated on the runtime's own
# ERROR line; SUMMARY is left out because UBSan writes the same generic
# `undefined-behavior` there for every check, which would key two unrelated
# faults alike.
_FATAL_ERROR_LINE = r"^(?:==\d+==)?\s*ERROR:\s+%s:\s+([A-Za-z0-9_-]+)"
_UBSAN_FATAL_RE = re.compile(
    _FATAL_ERROR_LINE % "UndefinedBehaviorSanitizer", re.MULTILINE
)
_TSAN_FATAL_RE = re.compile(_FATAL_ERROR_LINE % "ThreadSanitizer", re.MULTILINE)


def _fatal_signal_kind(pattern: "re.Pattern[str]", text: str) -> Optional[str]:
    """The signal a sanitizer died on, when no check of its own reported it."""
    match = pattern.search(text)
    return match.group(1).lower() if match else None


def _tsan_fault_kind(text: str) -> Optional[str]:
    """The race or misuse TSan reported, without its location or operands."""
    match = _TSAN_REPORT_RE.search(text)
    if match is None:
        return None
    words: list[str] = []
    for token in _TSAN_PARENTHETICAL_RE.sub(" ", match.group(1)).split():
        # Prose only: the location and ids that follow carry a separator or a
        # digit, and the first such token ends the kind.
        if not _TSAN_KIND_WORD_RE.fullmatch(token):
            break
        words.append(token.lower())
    return "-".join(words) or None


def _ubsan_fault_kind(text: str) -> Optional[str]:
    """The check UBSan reported, stripped of the values that vary per run."""
    match = _UBSAN_RUNTIME_ERROR_RE.search(text)
    if match is None:
        return None
    # The clause before the first `:` or `,` is the check; what follows is the
    # operands it failed on ("... overflow: 2147483647 + 1 cannot be ...").
    description = re.split(r"[:,]", match.group(1), maxsplit=1)[0]
    prose = _UBSAN_RUN_SPECIFIC_RE.sub(" ", description)
    return " ".join(prose.split()).lower() or None


def sanitizer_run_header_fields(text: str) -> dict[str, str]:
    """Parse the normalized runner header, including the legacy ASan form."""
    for line in text.splitlines():
        prefix = ""
        sanitizer = ""
        if line.startswith("SANITIZER_RUN_HEADER:"):
            prefix = "SANITIZER_RUN_HEADER:"
        elif line.startswith("ASAN_RUN_HEADER:"):
            prefix = "ASAN_RUN_HEADER:"
            sanitizer = "asan"
        if not prefix:
            continue
        fields: dict[str, str] = {}
        for token in line[len(prefix):].strip().split():
            if "=" in token:
                key, value = token.split("=", 1)
                fields[key] = value
        if sanitizer:
            fields.setdefault("sanitizer", sanitizer)
        if fields.get("sanitizer"):
            return fields
    return {}


def infer_sanitizer_from_text(text: str, default: str = "asan") -> str:
    """Return the sanitizer family from a runner header or raw diagnostic."""
    fields = sanitizer_run_header_fields(text)
    sanitizer = fields.get("sanitizer", "").lower()
    if sanitizer in SANITIZER_NAMES:
        return sanitizer
    header = re.search(
        r"\bSANITIZER_RUN_HEADER:\s+[^\n]*\bsanitizer=([A-Za-z0-9_-]+)",
        text,
    )
    if header and header.group(1).lower() in SANITIZER_NAMES:
        return header.group(1).lower()
    for name, pattern in _RAW_DIAGNOSTIC_PATTERNS:
        if pattern.search(text):
            return name
    return default


def recorded_sanitizer_options(text: str) -> str | None:
    """The runtime options the recorded diagnostic was produced under.

    The runner header carries them because they are part of how a crash was
    found: allocator shaping such as `quarantine_size_mb=1` decides whether
    some faults are detectable at all. ``None`` means an older diagnostic did
    not record the field; ``""`` is an explicitly recorded empty option set.
    Malformed, oversized, or environment-invalid values raise ``ValueError``.
    """
    fields = sanitizer_run_header_fields(text)
    if "env_options_b64" not in fields:
        return None
    encoded = fields["env_options_b64"]
    if len(encoded) > MAX_RECORDED_SANITIZER_OPTIONS_BYTES * 2:
        raise ValueError("recorded sanitizer options are oversized")
    try:
        raw = base64.b64decode(encoded, validate=True)
        decoded = raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise ValueError("recorded sanitizer options are malformed") from exc
    if len(raw) > MAX_RECORDED_SANITIZER_OPTIONS_BYTES:
        raise ValueError("recorded sanitizer options are oversized")
    if "\0" in decoded:
        raise ValueError("recorded sanitizer options contain NUL")
    return decoded


def sanitizer_fault_key(text: str) -> tuple[str, str] | None:
    """Identify the first sanitizer fault without unstable stack frames.

    A confirmation transcript can concatenate several runtime reports. The
    crash site and access direction are read from the first complete report,
    so taking a later report's primitive would create a fault pair that never
    occurred. Within one report the closing SUMMARY still wins over its
    headline, which is required for ASan's ``attempting double-free`` prose.
    """
    diagnostic = stack_frames.first_sanitizer_diagnostic(text) or text
    configured = sanitizer_run_header_fields(text).get("sanitizer", "").lower()
    sanitizer = (
        configured if configured in SANITIZER_NAMES
        else infer_sanitizer_from_text(diagnostic, default="")
    )
    if sanitizer == "asan":
        kinds = _ASAN_FAULT_RE.findall(diagnostic)
        if not kinds:
            return None
        kind = kinds[-1].lower()
        if kind == "attempting":
            if re.search(r"AddressSanitizer:\s+attempting double-free", diagnostic):
                kind = "double-free"
            elif re.search(
                r"AddressSanitizer:\s+attempting free on address", diagnostic
            ):
                kind = "bad-free"
        return sanitizer, kind
    if sanitizer == "ubsan":
        kind = _ubsan_fault_kind(diagnostic) or _fatal_signal_kind(
            _UBSAN_FATAL_RE, diagnostic
        )
        return (sanitizer, kind) if kind else None
    if sanitizer == "msan":
        # Read the reported kind rather than naming one: MSan's own SEGV had
        # no fault key, so a crash under it could never be measured.
        kinds = _MSAN_FAULT_RE.findall(diagnostic)
        return (sanitizer, kinds[-1].lower()) if kinds else None
    if sanitizer == "tsan":
        kind = _tsan_fault_kind(diagnostic) or _fatal_signal_kind(
            _TSAN_FATAL_RE, diagnostic
        )
        return (sanitizer, kind) if kind else None
    if sanitizer == "race" and re.search(
        r"^WARNING: DATA RACE$", diagnostic, re.MULTILINE
    ):
        return sanitizer, "data-race"
    return None


def looks_like_shell_wrapper(path: Path) -> bool:
    try:
        with path.open(encoding="utf-8", errors="replace") as stream:
            text = stream.read(256 * 1024)
    except OSError:
        return False
    first = text.splitlines()[0] if text.splitlines() else ""
    return bool(_SHELL_SHEBANG_RE.search(first) or _SHELL_WRAPPER_HINT_RE.search(text))


def _sort_key(path: Path) -> tuple[int, str]:
    name = path.name
    priority = 1
    if name.casefold() in TESTCASE_EXACT_NAMES:
        priority = 0
    elif name.startswith("input."):
        priority = 0
    elif any(name.startswith(p) for p in TESTCASE_PREFIXES):
        priority = 0
    return priority, name.casefold()


def _visible_files(directory: Path) -> list[Path]:
    try:
        # list() inside the try: on Python <= 3.12 iterdir() is lazy, so a
        # missing directory only raises once the iterator is consumed.
        entries = list(directory.iterdir())
    except OSError:
        return []
    return sorted(
        # is_file() already follows the link: a dangling one is False, a live
        # one is real readable evidence. Excluding symlinks outright would hide
        # a testcase whose bytes are right there from every reproducer path.
        (p for p in entries if p.is_file() and not p.name.startswith(".")),
        key=_sort_key,
    )


def _nonempty_file(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def is_executable_binary(path: Path) -> bool:
    # X_OK on a directory means "searchable", not "runnable", so the regular-file
    # test has to come first: a build leaves `harness.dSYM/` beside `harness`.
    if not path.is_file() or not os.access(path, os.X_OK):
        return False
    try:
        out = subprocess.run(
            # -b describes the file without echoing its path, so a directory
            # component can never supply the match instead of the content.
            ["file", "-b", str(path)],
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
# .swift/.kt) are NOT included: their entrypoint syntax is different, so
# this C-family main() test cannot classify them reliably.
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
        with path.open(encoding="utf-8", errors="replace") as stream:
            return any(_HARNESS_MAIN_RE.search(line) for line in stream)
    except OSError:
        return False


def _is_testcase_named(path: Path) -> bool:
    """A canonical testcase name advertises an input, not a harness."""
    lower = path.name.lower()
    return (
        lower in TESTCASE_EXACT_NAMES
        or any(lower.startswith(p) for p in TESTCASE_PREFIXES)
    )


def _is_harness_named(path: Path) -> bool:
    """The documented harness convention is `harness.*` / `*-harness.*` /
    `*_harness.*` (lib/languages.py), so an explicit `harness` in the stem
    marks the audit harness even when a descriptive prefix like `repro-`
    would otherwise read as a testcase name."""
    return "harness" in path.name.lower()


def _is_harness_source(path: Path) -> bool:
    """The single harness/testcase rule shared by find_harness_source and
    is_testcase_candidate, so the two never disagree about one file. A
    main()-bearing C/C++ source is the audit harness unless its name marks it
    as an input — but an explicit harness name overrides a testcase prefix
    (`repro-harness.c` is a harness, `input.c` / `reproducer.c` are inputs)."""
    if not _looks_like_harness_source(path):
        return False
    return _is_harness_named(path) or not _is_testcase_named(path)


def find_harness_source(dirs: Iterable[Path], *,
                        exclude: Optional[Path] = None) -> Optional[Path]:
    """Return a C/C++ source harness (a file defining main()) in scan order.

    Source harnesses are API-level reproducers: a caller that cannot compile
    one must not fall back to a target CLI invocation and treat that result as
    a reproduction measurement. Discovery is harness-oriented, NOT
    testcase-oriented: a testcase-named source (input.c, reproducer.c,
    tc-*.cpp) is an input the CLI consumes, so it is excluded here exactly as
    is_testcase_candidate accepts it — a given source is classified the same
    way by both, and a compiler/parser target whose reproducer is `input.c`
    still reverifies through the CLI rather than being skipped. A name that
    advertises the harness role wins over an incidental main()-bearing source.

    `exclude` is the already-resolved testcase. The ASAN_RUN_HEADER can name a
    main()-bearing, harness-named source (e.g. `input_harness.c`) as the actual
    input; that recorded path is ground truth and must never also be claimed as
    the harness, so the caller passes it here to keep one file from being both.
    """
    excluded = exclude.resolve() if exclude is not None else None
    fallback: Optional[Path] = None
    for d in (Path(x) for x in dirs):
        for p in _visible_files(d):
            if excluded is not None and p.resolve() == excluded:
                continue
            if not _is_harness_source(p):
                continue
            if _is_harness_named(p):
                return p
            if fallback is None:
                fallback = p
    return fallback


def is_testcase_candidate(path: Path, *, from_asan_header: bool = False,
                          min_bytes: int = 1, relaxed: bool = False) -> bool:
    """Return true when `path` is likely the reproducing testcase.

    The rule is deliberately exclusion-based for binary/parser inputs, but
    `.txt` is only accepted for canonical testcase names (`input.txt`,
    `testcase*.txt`, `reproducer*.txt`) or when ASan recorded the path in its
    `ASAN_RUN_HEADER`. This preserves pcre2-style text inputs without letting
    `notes.txt` satisfy promotion.

    `relaxed=True` drops only the `.txt`-needs-a-canonical-name gate (every
    artifact/binary/harness exclusion still applies). find_testcase uses it for
    a last-resort pass so a genuine text reproducer under a non-canonical name
    (e.g. `payload.txt`) is found rather than failing promotion entirely.
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
    if lower in {"testcase.sh", "reproducer.sh"} and looks_like_shell_wrapper(path):
        return False
    prefixed = any(lower.startswith(p) for p in TESTCASE_PREFIXES)
    # A C/C++ source file that defines main() is almost certainly the
    # audit harness (e.g. `to_json_throwing_string_harness.cpp`), not the
    # testcase. The exception is self-contained reproducer scripts whose
    # name advertises their role (`reproducer.c`, `tc-foo.cpp`); those
    # match TESTCASE_PREFIXES and are inputs — but an explicit `harness`
    # name overrides that prefix (`_is_harness_source`), so the two
    # classifiers stay in lock-step. ASan-recorded testcases always win.
    # Without this gate, find_testcase falls through past the rejected
    # real testcase and picks the harness — which export-repro then stages
    # as `input.cpp`, producing a reproduce.sh that compiles the harness as
    # its own input. See CRASH-002-1.20260509 incident.
    if not from_asan_header and _is_harness_source(path):
        return False
    if path.suffix.lower() in TEXT_EXTS_REQUIRING_PREFIX:
        if relaxed and path.stem.lower() not in NONINPUT_TEXT_STEMS:
            return True
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


def testcase_from_sanitizer_header(sanitizer_files: Iterable[Path], bases: Iterable[Path],
                                   min_bytes: int = 1) -> Optional[Path]:
    base_list = [Path.cwd(), *(Path(b) for b in bases)]
    for sanitizer in sanitizer_files:
        if not sanitizer.is_file():
            continue
        try:
            with sanitizer.open(encoding="utf-8", errors="replace") as stream:
                text = stream.read(256 * 1024)
        except OSError:
            continue
        m = _ASAN_TESTCASE_RE.search(text)
        if not m:
            continue
        p = _resolve_header_path(m.group(1), base_list)
        if p is not None and is_testcase_candidate(p, from_asan_header=True, min_bytes=min_bytes):
            return p
    return None


SANITIZER_NAME = "sanitizer.txt"
# The names a saved diagnostic may have. Kept as one list so a consumer that has
# to visit every diagnostic cannot fall behind the one that picks a primary.
SANITIZER_ALIASES = frozenset({
    "asan.txt", "asan-output.txt", "asan_output.txt",
    "msan.txt", "msan-output.txt", "msan_output.txt",
    "tsan.txt", "tsan-output.txt", "tsan_output.txt",
    "ubsan.txt", "ubsan-output.txt", "ubsan_output.txt",
})
SANITIZER_SUFFIXES = (".asan.txt", ".msan.txt", ".tsan.txt", ".ubsan.txt")


def is_sanitizer_name(name: str) -> bool:
    return (
        name == SANITIZER_NAME
        or name.lower() in SANITIZER_ALIASES
        or name.endswith(SANITIZER_SUFFIXES)
    )


def find_primary_sanitizer(scan_dirs: Iterable[Path]) -> Optional[Path]:
    dirs = [Path(d) for d in scan_dirs]
    for d in dirs:
        p = d / SANITIZER_NAME
        if _nonempty_file(p):
            return p
    matches: list[Path] = []
    for d in dirs:
        for p in _visible_files(d):
            if p.name != SANITIZER_NAME and is_sanitizer_name(p.name):
                matches.append(p)
    return sorted(matches, key=lambda p: p.name.casefold())[0] if matches else None


def sanitizer_diagnostics(artifact_dir: Path) -> list[Path]:
    """Every saved diagnostic for one artifact, not just the primary.

    A consumer that rewrites diagnostics has to reach all of them; repairing the
    primary alone would leave a second copy disagreeing with it.
    """
    found: list[Path] = []
    for directory in crash_evidence_dirs(artifact_dir):
        for path in sorted(_visible_files(directory)):
            if is_sanitizer_name(path.name) and _nonempty_file(path):
                found.append(path)
    return found


def crash_evidence_dirs(crash_dir: Path) -> list[Path]:
    """Where one crash keeps its own artifacts, most specific first."""
    audit = Path(crash_dir) / ".audit"
    return ([audit] if audit.is_dir() else []) + [Path(crash_dir)]


def crash_sanitizer(crash_dir: Path) -> str:
    """The sanitizer family a crash's recorded diagnostic came from."""
    diagnostic = find_primary_sanitizer(crash_evidence_dirs(crash_dir))
    if diagnostic is None:
        return "asan"
    try:
        return infer_sanitizer_from_text(
            diagnostic.read_text(encoding="utf-8", errors="replace")
        )
    except OSError:
        return "asan"


def crash_harness_binary(crash_dir: Path) -> Optional[Path]:
    """The self-contained harness a crash carries, if it carries one.

    Scans the evidence dirs every sibling resolver scans. export-repro migrates
    the compiled harness into `.audit/` and leaves only source and the debug
    bundle at the root, so a root-only scan stops finding the binary as soon as
    a bundle is exported — and a later replay would then read a crash that
    still reproduces as having no replay contract at all.
    """
    for directory in crash_evidence_dirs(crash_dir):
        for candidate in sorted(directory.glob("harness*")):
            if is_executable_binary(candidate):
                return candidate
    return None


def find_testcase(scan_dirs: Iterable[Path], *, sanitizer_files: Iterable[Path] = (),
                  min_bytes: int = 1) -> Optional[Path]:
    return find_testcase_with_provenance(
        scan_dirs, sanitizer_files=sanitizer_files, min_bytes=min_bytes,
    )[0]


def find_testcase_with_provenance(
    scan_dirs: Iterable[Path], *, sanitizer_files: Iterable[Path] = (),
    min_bytes: int = 1,
) -> tuple[Optional[Path], bool]:
    """`find_testcase`, plus whether a sanitizer header named that exact file.

    Every other pass here picks by name, and a name is a guess: a caller that
    has to know whether the input was *recorded* — rather than inferred from a
    `repro.`/`input.` prefix — cannot recover that from the path alone.
    """
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
                return p, False

    header_hit = testcase_from_sanitizer_header(
        sanitizer_files,
        [*dirs, *(d.parent for d in dirs)],
        min_bytes=min_bytes,
    )
    if header_hit is not None:
        return header_hit, True

    for d in dirs:
        for p in _visible_files(d):
            if is_testcase_candidate(p, min_bytes=min_bytes):
                return p, False

    # Last resort before the caller reports "no testcase" (which TTL-rejects an
    # otherwise-complete crash): accept any non-artifact, non-binary,
    # non-harness file even under a non-canonical `.txt` name. A real reproducer
    # named `payload.txt` is better than losing the crash.
    for d in (*audit_dirs, *dirs):
        for p in _visible_files(d):
            if is_testcase_candidate(p, min_bytes=min_bytes, relaxed=True):
                return p, False
    return None, False


def source_defines_main(path: Path) -> bool:
    """Whether `path` is a C/C++ source that defines main().

    Public form of the harness-body test. `is_testcase_candidate` lets a
    testcase-*named* source (`repro.c`, `input.c`) stay an input, which is right
    for a target that parses source — and wrong for a library target, where the
    same file is an API driver that has to be compiled, not fed to a CLI.
    Callers that can tell those two targets apart need the body test on its own.
    """
    return _looks_like_harness_source(Path(path))


def carries_replay_evidence(artifact_dir: Path) -> bool:
    """Whether a saved artifact carries anything a replay could run.

    Testcase discovery includes every recorded sanitizer header: an input may
    still exist at the exact path captured by the crashing run even when it
    has not yet been copied into the bundle. Partial export can leave both an
    audit-preserved diagnostic and a root copy, while consumers legitimately
    prefer either one; checking only one header can therefore disagree with
    crash completeness and adjudicate a replay that never ran.
    """
    directory = Path(artifact_dir)
    scan_dirs = crash_evidence_dirs(directory)
    return (
        find_testcase(
            scan_dirs, sanitizer_files=sanitizer_diagnostics(directory),
        ) is not None
        or find_harness_source(scan_dirs) is not None
        or crash_harness_binary(directory) is not None
    )


def find_reproducer_artifact(scan_dirs: Iterable[Path]) -> Optional[Path]:
    """Return a saved input or explicitly named self-contained reproducer.

    ``find_testcase`` owns normal input discovery. This adds the narrower shape
    needed by evidence consumers: a source/script named for its PoC role can be
    the entire reproducer and therefore legitimately contain ``main`` instead
    of being an input consumed by a separate harness. Metadata suffixes and
    replay-only ``repro.cmd`` remain excluded.
    """
    dirs = [Path(d) for d in scan_dirs if Path(d).is_dir()]
    for directory in dirs:
        for path in _visible_files(directory):
            name = path.name
            lower = name.lower()
            # reproduce.sh is the one exact artifact whose contract is itself
            # runnable; repro.cmd and generated reports are not.
            if lower == "reproduce.sh":
                if _nonempty_file(path):
                    return path
                continue
            if (not any(lower.startswith(prefix)
                        for prefix in REPRODUCER_ROLE_PREFIXES)
                    or name in ARTIFACT_EXACT
                    or any(lower.endswith(suffix)
                           for suffix in ARTIFACT_SUFFIXES)):
                continue
            if _nonempty_file(path):
                return path

    testcase = find_testcase(dirs)
    if testcase is None:
        return None
    lower = testcase.name.lower()
    if _is_testcase_named(testcase):
        return testcase

    # Non-canonical input names (min.xml, payload.bin) need a second artifact
    # tying them to reproduction. This keeps an arbitrary source attachment in
    # a finding directory from becoming exploit-maturity evidence merely
    # because crash testcase discovery is intentionally relaxed.
    if find_harness_source(dirs, exclude=testcase) is not None:
        return testcase
    if find_primary_sanitizer(dirs) is not None:
        return testcase
    for directory in dirs:
        for name in ("repro.cmd", "reproduce.sh"):
            path = directory / name
            if _nonempty_file(path):
                return testcase
    return None


# ── CLI argv recovery ───────────────────────────────────────────────
# A crash that only fires under non-default arguments (extra flags, a
# subcommand, a pattern) can't reproduce under the bare `BIN <testcase>` that
# reverify and export-repro default to. The argv comes from one of two sources,
# each parsed by its own shape:
#   - repro.cmd: the args-only list after the binary (the prompt contract).
#     Used verbatim — never stripped, so a positional like `MODE=parse` or
#     `PATTERN=a=b` survives.
#   - report.md fallback: a full pasted command. Here the env prefix, the
#     binary, and redirections precede the argv and are stripped off.
REPRO_CMD_FILE = "repro.cmd"
TESTCASE_TOKEN = "{TESTCASE}"

# A shell env assignment (NAME=VALUE) — only meaningful as a prefix on a full
# command line, so it is stripped only on the report.md fallback path.
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Spaced shell redirection operators a pasted command may carry. Glued forms
# (`2>file`) are left as-is — rare in the model's spaced blocks, and a stray
# arg fails loudly rather than mis-reproducing silently.
_REDIRECT_OPS = {">", ">>", "<", "2>", "1>", "&>", ">&"}


def _split(line: str) -> list[str]:
    try:
        return shlex.split(line)
    except ValueError:
        return []


def _read_repro_cmd_line(scan_dirs: Iterable[Path]) -> str:
    """First non-comment line of repro.cmd — the args-only argv."""
    for d in (Path(x) for x in scan_dirs):
        p = d / REPRO_CMD_FILE
        if not p.is_file():
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for raw in text.splitlines():
            s = raw.strip()
            if s and not s.startswith("#"):
                return s
    return ""


def _report_command_args(scan_dirs: Iterable[Path],
                         bin_names: set[str]) -> list[str]:
    """Args of the fenced report.md command whose tokens name the binary, with
    the env prefix, the binary, and redirections stripped. [] when absent.

    Fallback for crashes written before repro.cmd existed (and for a model that
    documented the command only in prose). Anchored on a binary *token* (not a
    substring), so report prose is never mistaken for a command.
    """
    if not bin_names:
        return []
    for d in (Path(x) for x in scan_dirs):
        for name in ("report.md", "REPORT.md"):
            p = d / name
            if not p.is_file():
                continue
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # Join shell line-continuations so a multi-line command reads as one
            # logical line before we scan the fenced block.
            text = text.replace("\\\n", " ")
            in_fence = False
            for line in text.splitlines():
                if line.lstrip().startswith("```"):
                    in_fence = not in_fence
                    continue
                if not in_fence:
                    continue
                toks = _split(line)
                if any(os.path.basename(t) in bin_names for t in toks):
                    return _strip_command_prefix(toks, bin_names)
    return []


def _strip_command_prefix(toks: list[str], bin_names: set[str]) -> list[str]:
    """Drop a leading `env`, KEY=VAL env assignments, the binary token, and any
    spaced redirection + its target, leaving the argv after the binary."""
    i = 0
    if i < len(toks) and toks[i] == "env":
        i += 1
    while i < len(toks) and _ENV_ASSIGN_RE.match(toks[i]):
        i += 1
    if i < len(toks) and os.path.basename(toks[i]) in bin_names:
        i += 1
    out: list[str] = []
    skip_next = False
    for tok in toks[i:]:
        if skip_next:
            skip_next = False
            continue
        if tok in _REDIRECT_OPS:
            skip_next = True
            continue
        out.append(tok)
    return out


def _with_testcase_token(args: list[str], testcase_name: str) -> list[str]:
    """Rewrite a literal testcase filename to {TESTCASE} and ensure the token is
    present, so callers can place the staged input at the right position."""
    out = [TESTCASE_TOKEN
           if (testcase_name and os.path.basename(a) == testcase_name)
           else a for a in args]
    if not any(TESTCASE_TOKEN in arg for arg in out):
        out.append(TESTCASE_TOKEN)
    return out


def find_repro_args(scan_dirs: Iterable[Path], *,
                    bin_names: Iterable[str] = (),
                    testcase_name: str = "") -> list[str]:
    """Return the CLI argv a crash needs, with {TESTCASE} marking the input.

    Prefers the args-only `repro.cmd` (used verbatim), else recovers the args
    from report.md's fenced command block. Returns [] when only the testcase
    remains (a bare `BIN <input>`), so callers keep their default invocation
    unchanged for the common flag-less crash. Never raises.
    """
    names = {os.path.basename(b) for b in bin_names if b}
    line = _read_repro_cmd_line(scan_dirs)
    if line:
        args = _split(line)
        # repro.cmd is args-only, but some agents write the common bare
        # invocation as `BIN {TESTCASE}`.  Normalize only that exact,
        # unambiguous two-token shape: flags, literal testcase paths, and
        # arbitrary positional arguments remain verbatim.
        if (
            len(args) == 2
            and args[1] == TESTCASE_TOKEN
            and os.path.basename(args[0]) in names
        ):
            args = args[1:]
    else:
        args = _report_command_args(scan_dirs, names)
    if not args:
        return []
    args = _with_testcase_token(args, testcase_name)
    if args == [TESTCASE_TOKEN]:
        return []
    return args
