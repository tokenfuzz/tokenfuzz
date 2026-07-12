#!/usr/bin/env python3
"""Crash artifact discovery shared by triage and export tooling."""

from __future__ import annotations

import os
import re
import shlex
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
    "sanitizer.txt",
    "harness.c",
    "severity.json",
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
_BIN_FILE_RE = re.compile(r"executable|Mach-O|ELF|shared object|dSYM", re.IGNORECASE)
_ASAN_TESTCASE_RE = re.compile(r"\btestcase=([^ \t\r\n]+)")
_SHELL_SHEBANG_RE = re.compile(r"^\s*#!.*\b(?:sh|bash|zsh|ksh)\b")
_SHELL_WRAPPER_HINT_RE = re.compile(
    r'(?m)(?:^\s*set\s+-|^\s*(?:ROOT|SRC|BUILD|SCRATCH|HARNESS_C|HARNESS_BIN|BIN)='
    r'|^\s*(?:if|for|while)\s+|^\s*exec\s+|"\$(?:BIN|HARNESS_BIN|san_bin)"'
    r'|\$(?:BIN|HARNESS_BIN|san_bin|repro_src)\b|/build-(?:a|ub|m|t)san/)'
)


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
    if name.startswith("input."):
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
    """A name matching TESTCASE_PREFIXES advertises an input, not a harness."""
    lower = path.name.lower()
    return any(lower.startswith(p) for p in TESTCASE_PREFIXES)


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


def find_primary_sanitizer(scan_dirs: Iterable[Path]) -> Optional[Path]:
    dirs = [Path(d) for d in scan_dirs]
    for d in dirs:
        p = d / "sanitizer.txt"
        if p.is_file() and p.stat().st_size > 0:
            return p
    matches: list[Path] = []
    aliases = {
        "asan.txt", "asan-output.txt", "asan_output.txt",
        "msan.txt", "msan-output.txt", "msan_output.txt",
        "tsan.txt", "tsan-output.txt", "tsan_output.txt",
        "ubsan.txt", "ubsan-output.txt", "ubsan_output.txt",
    }
    for d in dirs:
        for p in _visible_files(d):
            name = p.name
            if (
                name.lower() in aliases
                or name.endswith(".asan.txt")
                or name.endswith(".msan.txt")
                or name.endswith(".tsan.txt")
                or name.endswith(".ubsan.txt")
            ):
                matches.append(p)
    return sorted(matches, key=lambda p: p.name.casefold())[0] if matches else None


def find_testcase(scan_dirs: Iterable[Path], *, sanitizer_files: Iterable[Path] = (),
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

    header_hit = testcase_from_sanitizer_header(
        sanitizer_files,
        [*dirs, *(d.parent for d in dirs)],
        min_bytes=min_bytes,
    )
    if header_hit is not None:
        return header_hit

    for d in dirs:
        for p in _visible_files(d):
            if is_testcase_candidate(p, min_bytes=min_bytes):
                return p

    # Last resort before the caller reports "no testcase" (which TTL-rejects an
    # otherwise-complete crash): accept any non-artifact, non-binary,
    # non-harness file even under a non-canonical `.txt` name. A real reproducer
    # named `payload.txt` is better than losing the crash.
    for d in (*audit_dirs, *dirs):
        for p in _visible_files(d):
            if is_testcase_candidate(p, min_bytes=min_bytes, relaxed=True):
                return p
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
    if TESTCASE_TOKEN not in out:
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
