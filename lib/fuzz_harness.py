#!/usr/bin/env python3
"""Which APIs deserve a fuzz target, and how one gets built without
disturbing the shared build.

Two halves, both target-agnostic:

*Admission.* A fuzz target is expensive — it has to be written, built, given
a corpus, and then run for hours before it says anything. Most exported
functions never repay that. This module admits a candidate only when three
structural facts hold at once: the build actually *publishes* the symbol, its
declaration takes a parameter shape the target's own declared
``attacker_controls`` can supply, and no harness in the tree already drives
it. Each is read from a structured source — the artifact's symbol table, the
public header's declaration, the harness sources on disk — not guessed from a
name. A candidate failing any one is reported with the reason it failed, so
"no candidates" is an answer rather than a silence.

The call graph deliberately does *not* gate. ``lib/callgraph`` states the rule
this module obeys: a syntactic graph is blind to indirect dispatch, so a
missing path is not evidence of unreachability. It ranks admitted candidates
and nothing more.

*Isolation.* A harness must never become part of the target's source or of
its shared sanitizer build. ``lib/target_config`` derives build freshness from
the checkout's VCS state including untracked paths, and ``build_lease``
pins one source signature per checkout — so a harness written into the tree
restales the build for every other backend reading it and makes their pins
disagree. Harness sources and binaries therefore live under ``RESULTS_DIR``,
which is per-backend, and link against the shared build read-only. The build
tree is never written; ``reject_in_tree_source`` is the enforcement point.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

import audit_scope
import native_symbols
import sanitizer
import symbol_names
import workqueue
from timeout import run_timeout

# ── Layout under RESULTS_DIR ────────────────────────────────────────
#
# Everything a campaign reads or writes sits under one directory, because the
# whole isolation argument rests on nothing landing anywhere else.

FUZZ_DIRNAME = "fuzz"


def fuzz_root(results_dir: "str | os.PathLike") -> Path:
    return Path(results_dir) / FUZZ_DIRNAME


def source_dir(results_dir: "str | os.PathLike") -> Path:
    return fuzz_root(results_dir) / "src"


def binary_dir(results_dir: "str | os.PathLike") -> Path:
    return fuzz_root(results_dir) / "bin"


def corpus_dir(results_dir: "str | os.PathLike", name: str) -> Path:
    return fuzz_root(results_dir) / "corpus" / name


def artifact_dir(results_dir: "str | os.PathLike", name: str) -> Path:
    return fuzz_root(results_dir) / "artifacts" / name


def log_dir(results_dir: "str | os.PathLike", name: str) -> Path:
    return fuzz_root(results_dir) / "logs" / name


# ── Existing harnesses ──────────────────────────────────────────────
#
# Entry-point spellings, not project names: every row is the signature its
# ecosystem's fuzzing driver requires, so it matches any project using that
# ecosystem and no project that does not. These are the same entry points
# OSS-Fuzz builds against.

_HARNESS_ENTRIES: "tuple[tuple[str, str, re.Pattern[str]], ...]" = (
    ("libfuzzer", ".c.cc.cpp.cxx.c++.m.mm",
     re.compile(r"\bLLVMFuzzerTestOneInput\s*\(")),
    ("cargo-fuzz", ".rs", re.compile(r"\bfuzz_target!\s*[\(|]")),
    # Go's native fuzzing takes a testing.F; the older go-fuzz convention is a
    # bare []byte entry returning int. Both are still in the wild.
    ("go-native", ".go", re.compile(r"\bfunc\s+Fuzz\w*\s*\(\s*\w+\s+\*testing\.F\s*\)")),
    ("go-fuzz", ".go", re.compile(r"\bfunc\s+Fuzz\w*\s*\(\s*\w+\s+\[\]byte\s*\)\s*int\b")),
    ("atheris", ".py", re.compile(r"\batheris\.(?:Setup|instrument_)")),
    ("jazzer", ".java.kt", re.compile(r"\bfuzzerTestOneInput\s*\(")),
)

# Structural weaknesses in an existing harness, in fuzz-introspector's sense of
# a "fuzz blocker": code between the mutator and the API that costs coverage no
# amount of fuzzing buys back. Each row is (id, pattern, what it costs).
_HARNESS_GAPS: "tuple[tuple[str, re.Pattern[str], str], ...]" = (
    ("magic-gate", re.compile(
        r"\b(?:memcmp|strncmp|strcmp)\s*\([^;]{0,120}\)\s*(?:!=|==)\s*0\s*\)\s*"
        r"(?:\{[^}]{0,40})?\breturn\b"),
     "rejects input on an exact-match check the mutator cannot guess; "
     "seed the corpus with a conforming prefix or drop the check"),
    ("size-floor", re.compile(r"\b(?:size|len|Size|Len)\s*<\s*(\d+)\s*\)\s*"
                              r"(?:\{[^}]{0,40})?\breturn\b"),
     "discards every input below a floor; a small floor is fine, a large one "
     "spends the whole early corpus on rejections"),
    ("single-call", re.compile(r"\A(?!.*(?:FuzzedDataProvider|ConsumeIntegral|"
                               r"Consume\w*\(|\bswitch\s*\(|%\s*\d+\s*\)))",
                               re.S),
     "drives one call shape only; lifetime and state defects need a "
     "data-driven call sequence"),
    ("no-teardown", re.compile(r"\A(?!.*(?:free|Free|destroy|Destroy|close|"
                               r"Close|release|Release|delete|drop)\s*\()", re.S),
     "never releases what it allocates, so leak reports describe the harness "
     "rather than the target"),
)


# A fuzz directory is excluded from the *audit* scope on purpose — a bug in a
# harness is not a bug in the product — but it is exactly where harnesses live,
# so the inventory looks inside it.
_FUZZ_DIR_NAMES = {"fuzz", "fuzzer", "fuzzers", "fuzzing", "oss-fuzz", "test"}


@dataclass
class ExistingHarness:
    path: str
    kind: str
    drives: "list[str]" = field(default_factory=list)
    gaps: "list[tuple[str, str]]" = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "path": self.path, "kind": self.kind, "drives": sorted(self.drives),
            "gaps": [{"id": gap, "cost": cost} for gap, cost in self.gaps],
        }


_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")


def _driven(calls: "set[str]", exported: "set[str]") -> "set[str]":
    """Exported symbols a harness's call sites actually reach.

    Resolves the width-suffix spelling both ways, so a harness calling
    `pcre2_compile` is credited with driving the exported `pcre2_compile_8`.
    Without it a target that mangles its whole API reads as having no
    coverage at all, and every already-fuzzed entry point is re-offered as a
    candidate.
    """
    aliases = suffix_aliases(exported)
    return (calls & exported) | {
        aliases[name] for name in calls if name in aliases
    }
# A harness large enough to be a whole framework is not a harness; reading it
# costs more than it tells us. libFuzzer entry files are tens of lines.
_MAX_HARNESS_BYTES = 256 * 1024


def _walk(root: Path, keep: "set[str] | None" = None) -> "list[Path]":
    """Files under `root`, pruning directories rather than filtering paths.

    `rglob` descends into `.git`, every `build-<san>/`, and node_modules before
    anything gets a chance to reject them — on a large target that is nearly
    the whole walk. Pruning at the directory level is the same answer for a
    fraction of the syscalls. `keep` names directories that are outside the
    *audit* scope but are exactly where this module needs to look.
    """
    keep = keep or set()
    found: "list[Path]" = []
    for current, directories, names in os.walk(root, topdown=True):
        directories[:] = sorted(
            name for name in directories
            if name in keep or (
                not audit_scope.is_excluded_path_part(name)
                and name not in {".git", ".hg", ".audit", "__pycache__"}
                and not name.startswith("build-")
            )
        )
        found.extend(Path(current) / name for name in sorted(names))
    return found


def discover(target_root: "str | os.PathLike",
             exported: "set[str] | None" = None) -> "list[ExistingHarness]":
    """Fuzz harnesses already in the target tree, and what each one drives.

    ``drives`` is intersected with the build's exported symbols, so an
    identifier that merely looks like a call — a macro, a local helper — does
    not count as API coverage and cannot suppress a real candidate.
    """
    root = Path(target_root)
    found: "list[ExistingHarness]" = []
    for path in _walk(root, keep=_FUZZ_DIR_NAMES):
        suffix = path.suffix.lower()
        if not suffix:
            continue
        kind = ""
        text = ""
        for name, suffixes, pattern in _HARNESS_ENTRIES:
            if suffix not in suffixes:
                continue
            try:
                if path.stat().st_size > _MAX_HARNESS_BYTES:
                    continue
                text = path.read_text(errors="replace")
            except OSError:
                continue
            if pattern.search(text):
                kind = name
                break
        if not kind:
            continue
        # Comments first: a `/* TODO api_parse(d, n); */` note would otherwise
        # count as driving api_parse and suppress a real candidate.
        calls = {match.group(1)
                 for match in _CALL_RE.finditer(_COMMENT_RE.sub(" ", text))}
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            relative = path.name
        found.append(ExistingHarness(
            path=relative, kind=kind,
            drives=sorted(_driven(calls, exported)) if exported else [],
            gaps=[(gap, cost) for gap, pattern, cost in _HARNESS_GAPS
                  if pattern.search(text)],
        ))
    return found


# ── Declarations from public headers ────────────────────────────────

# A candidate declaration site: an identifier followed by `(`. Which of these
# is really a declaration is decided by `_declarations_in`, which matches the
# parentheses and requires a `;` after them — a regex cannot, because a
# library's public declarations routinely wrap the return type in a macro that
# has parentheses of its own (`CJSON_PUBLIC(cJSON *) cJSON_Parse(...)`), and
# any single pattern either mis-anchors on the macro or drags the preceding
# text in with it. That shape is not an edge case: it is disproportionately how
# C libraries spell their *public entry points*, which is exactly the surface
# this module exists to find.
_CALL_SITE_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(")
_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.S)
_PREPROCESSOR_RE = re.compile(r"(?m)^[ \t]*#(?:.*\\\n)*.*$")
# Where a declaration starts: the end of the previous statement or block. A
# capture that ignores this drags whatever prose preceded it into the
# "declaration", and the shape classifier then reads a doc comment.
_STATEMENT_BREAK = ";{}"
_HEADER_SUFFIXES = {".h", ".hh", ".hpp", ".hxx", ".h++"}
# A header this large is a generated amalgamation, not an API surface.
_MAX_HEADER_BYTES = 2 * 1024 * 1024

# Local examples are construction evidence, not audit scope. Restricting the
# lookup to the conventional directories projects use for runnable examples
# keeps one template command from becoming another whole-tree source review.
# Every name here must survive `_tree`'s prune, or the entry is dead: the walk
# keeps `_FUZZ_DIR_NAMES | _SEED_DIR_NAMES` explicitly and drops everything
# else `audit_scope` excludes — singular `example/` among them.
_LOCAL_CALLER_DIR_NAMES = frozenset({
    "examples", "sample", "samples", "test", "tests",
    "fuzz", "fuzzer", "fuzzers", "fuzzing", "oss-fuzz",
})
_LOCAL_CALLER_SUFFIXES = frozenset({
    ".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm",
})
_MAX_LOCAL_CALLER_BYTES = 512 * 1024
# Which of those directories teaches the most, best first. An existing fuzz
# harness already solves this exact problem for a neighbouring API; a runnable
# example is the project's own demonstration; a test may be a data fixture that
# happens to end in `.c`. Without this, walk order decides, and on a large tree
# walk order is alphabetical noise. Ranking costs one pass over the pruned file
# list instead of stopping at the first two matches — 3s on a million-file tree
# whose walk already costs 8s, and milliseconds on every ordinary target.
_LOCAL_CALLER_RANKS = (
    frozenset({"fuzz", "fuzzer", "fuzzers", "fuzzing", "oss-fuzz"}),
    frozenset({"examples", "sample", "samples"}),
)


@dataclass(frozen=True)
class CallerExample:
    path: str
    line: int


def _blank_comment(match: "re.Match[str]") -> str:
    """Remove comment text without moving the source lines it occupied."""
    return "".join("\n" if character == "\n" else " "
                   for character in match.group(0))


def local_caller_examples(target_root: "str | os.PathLike", symbol: str,
                          limit: int = 2) -> "list[CallerExample]":
    """At most ``limit`` exact-symbol calls in local tests/examples.

    These locations teach a harness how ordinary callers construct arguments
    and release state. They deliberately do not feed admission or ranking: a
    test can use privileged setup, and no example is proof that an attacker
    reaches the same route. Missing, unreadable, or unparsable source simply
    yields no examples and leaves the existing declaration-first workflow.
    """
    if limit <= 0 or not re.fullmatch(r"[A-Za-z_]\w*", symbol):
        return []
    root = Path(target_root)
    call = re.compile(rf"\b{re.escape(symbol)}\s*\(")
    candidates: "list[tuple[int, str, Path]]" = []
    for path in _tree(root):
        if path.suffix.lower() not in _LOCAL_CALLER_SUFFIXES:
            continue
        try:
            relative = path.relative_to(root)
        except ValueError:
            continue
        directories = {part.lower() for part in relative.parts[:-1]}
        if not _LOCAL_CALLER_DIR_NAMES & directories:
            continue
        rank = next((index for index, names in enumerate(_LOCAL_CALLER_RANKS)
                     if names & directories), len(_LOCAL_CALLER_RANKS))
        candidates.append((rank, relative.as_posix(), path))
    found: "list[CallerExample]" = []
    for rank, relative_path, path in sorted(candidates):
        try:
            if path.stat().st_size > _MAX_LOCAL_CALLER_BYTES:
                continue
            text = path.read_text(errors="replace")
        except OSError:
            continue
        # Blanking comments is the expensive step and only ever removes
        # matches, so a file the symbol does not appear in at all is skipped
        # before paying for it.
        if call.search(text) is None:
            continue
        code = _COMMENT_RE.sub(_blank_comment, text)
        match = call.search(code)
        if match is None:
            continue
        found.append(CallerExample(
            path=relative_path, line=code.count("\n", 0, match.start()) + 1,
        ))
        if len(found) >= limit:
            break
    return found


def declaration_index(target_root: "str | os.PathLike",
                      include_dirs: "list[str] | None" = None) -> "dict[str, str]":
    """symbol -> its declaration text, read from the target's headers.

    Prefers the configured include directories, because those are the paths
    the target itself says are its public surface. Falls back to every header
    in the auditable tree when none are configured, which is the common case
    for a project whose target.toml points straight at a build tree.
    """
    root = Path(target_root)
    configured = [Path(d) for d in (include_dirs or []) if str(d)]
    roots = [path for path in configured if path.is_dir()]
    # No configured include contract means the source tree is the best
    # available discovery surface. An explicit but missing contract is
    # different: falling back there makes an unusable -I list look healthy and
    # prevents setup-target from repairing it.
    if not configured:
        roots = [root]
    index: "dict[str, str]" = {}
    for base in roots:
        for path in _walk(base):
            # `.h.in` is a public header a project generates at configure
            # time; the sorted walk keeps a real `.h` ahead of its template.
            filename = path.name.lower()
            if not any(
                filename.endswith(suffix) or filename.endswith(f"{suffix}.in")
                for suffix in _HEADER_SUFFIXES
            ):
                continue
            try:
                if path.stat().st_size > _MAX_HEADER_BYTES:
                    continue
                text = path.read_text(errors="replace")
            except OSError:
                continue
            for name, declaration in _declarations_in(text):
                index.setdefault(name, declaration)
    return index


def _matching_paren(text: str, open_at: int) -> int:
    """Index of the `)` closing the `(` at `open_at`, or -1."""
    depth = 0
    for index in range(open_at, len(text)):
        if text[index] == "(":
            depth += 1
        elif text[index] == ")":
            depth -= 1
            if depth == 0:
                return index
    return -1


def _declarations_in(text: str) -> "list[tuple[str, str]]":
    """(symbol, declaration) for every function prototype in a header.

    Comments and preprocessor lines go first: a macro's parameter list parses
    as a prototype, and a doc comment above a declaration is prose that ends
    up describing an "input shape" nobody wrote.
    """
    text = _PREPROCESSOR_RE.sub("", _COMMENT_RE.sub(" ", text))
    found: "list[tuple[str, str]]" = []
    for match in _CALL_SITE_RE.finditer(text):
        name = match.group(1)
        if name in _NON_API_NAMES:
            continue
        close = _matching_paren(text, match.end() - 1)
        if close < 0:
            continue
        # A prototype ends at `;`. A definition continues into `{`, and a
        # macro-wrapped return type is followed by the real name — both are
        # skipped here, and the real name is reached by a later match.
        tail = text[close + 1:]
        stripped = tail.lstrip()
        # Trailing attributes sit between the parameters and the semicolon.
        while stripped.startswith("__"):
            attribute = re.match(r"__\w+\s*(?:\([^)]*\))?\s*", stripped)
            if attribute is None:
                break
            stripped = stripped[attribute.end():]
        if not stripped.startswith(";"):
            continue
        start = max(text.rfind(character, 0, match.start())
                    for character in _STATEMENT_BREAK) + 1
        declaration = " ".join(text[start:close + 1].split()) + ";"
        found.append((name, declaration))
    return found


# C keywords that parse as a call site in a declaration position.
_NON_API_NAMES = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "defined",
    "typedef", "struct", "union", "enum", "operator", "catch",
})


# ── Input shapes an attacker control can supply ─────────────────────
#
# Inclusion criterion for a row: the shape must be decidable from a C
# declaration alone, and must correspond to data the named control genuinely
# puts under caller control. `timing`, `race`, and `env` get no shape — none
# of them is a parameter, so a function admitted on one of them would be
# admitted on its signature saying nothing at all, which is the failure mode
# this gate exists to prevent.

# Built-in byte types plus the established public-API aliases. Substring
# matching is unsafe here: `wchar_t`, `charset_context`, and `api_byte_context`
# all contain a byte-type spelling and are wide or opaque, not input bytes. A
# custom alias outside this list remains admissible when the pointer parameter
# itself carries a payload name.
_BYTE_ELEMENT_NAMES = frozenset({
    "byte", "bytef", "char", "gchar", "guchar", "int8_t", "octet",
    "schar", "u_char", "uchar", "uint8_t", "void", "xmlchar",
})
_BYTE_ALIAS_NAME = re.compile(
    r"(?:^|_)(?:byte|octet)s?(?:_t)?$|(?:Byte|Octet)s?(?:T)?$",
    re.IGNORECASE,
)


def _has_byte_element_type(pointer: str) -> bool:
    """Whether the pointer's element type is a byte the mutator can supply.

    The element type is what precedes the star, read from the last open paren
    because a macro-wrapped declaration puts its own return type in front of
    the first parameter.
    """
    element = pointer.rsplit("(", 1)[-1].split("*", 1)[0]
    return any(
        name.lower() in _BYTE_ELEMENT_NAMES or _BYTE_ALIAS_NAME.search(name)
        for name in re.findall(r"[A-Za-z_]\w*", element)
    )
_INT_TYPE = (
    r"(?:size_t|ssize_t|int|unsigned(?:\s+\w+)?|long(?:\s+long)?|short|"
    r"u?int(?:8|16|32|64)_t|off_t|ptrdiff_t)"
)
_STREAM_TYPE = re.compile(
    r"\b(?:FILE|std::istream|std::streambuf)\s*[\*&]"
    r"|\b\w*(?:stream|Stream|reader|Reader|channel|Channel|socket|Socket|"
    r"iobuf|IOBuf)\w*\s*\*")
_PATH_NAME = re.compile(
    r"(?:path|file|filename|url|uri|dir|dirname)\w*\s*$", re.I)
# The name a length parameter carries, and the name the buffer it measures
# carries. Either one confirms an adjacent pointer+integer pair really is a
# buffer and its length rather than two unrelated arguments — which is the
# difference between `xmlReadMemory(const char *buf, int size, ...)` and
# `htmlSaveFile(const char *filename, xmlDoc *cur, ...)`.
# A length parameter's last word says so — `size`, `len`, `count`, `bytes` —
# after a word start, an underscore, or a camelCase hump, plus the bare
# Hungarian forms (`n`, `nbytes`, `cbSize`, `destLen`). The looser `n\w*` that
# used to stand here read every `nPage`-style handle parameter as a byte
# length, which admitted an opaque handle as a fuzzable buffer.
_LENGTH_NAME = re.compile(
    r"(?:\b[nNcC]?_?|\w_|[A-Za-z0-9](?=[A-Z]))"
    r"(?i:size|sz|len|length|count|cnt|num|bytes?|cb)\w*\s*$"
    r"|\b[nN]\s*$"
)
# A pointer to something wider than a byte, measured by an adjacent integer,
# carries an *element count* rather than a byte length: the mutator's bytes
# cannot supply it, so a harness admitted here reaches the target only by
# claiming its array holds more elements than it allocated, and every crash
# that follows is the harness miscounting. Known byte typedefs and custom
# aliases whose whole type name ends in byte/octet remain eligible; an opaque
# context that merely contains that word does not. Any spelling of `char` is
# the byte buffer this must not touch.
_BYTE_ELEMENT = re.compile(r"\bchar\b")
_WIDE_ELEMENT = re.compile(
    r"\b(?:short|int|long|float|double|unsigned|"
    r"u?int(?:16|32|64|128)_t|size_t|ssize_t|ptrdiff_t)\b")
_PAYLOAD_NAME = re.compile(
    r"\b(?:data|buf|buffer|bytes|input|in|content|payload|chunk|blob|msg|"
    r"message|str|mem|memory|\w*_(?:data|buf|buffer|bytes))\s*$", re.I)

SHAPE_BUFFER = "buffer+length"
SHAPE_STRING = "nul-terminated string"
SHAPE_STREAM = "stream handle"
SHAPE_PATH = "filesystem path"
SHAPE_HANDLE = "opaque state handle"

# How much of a fuzzing surface each shape is, for ranking only. A caller-sized
# buffer is what a parser takes and what a mutator drives best; a bare string
# is the weakest signal, because in C every function that takes a name takes
# one. Never a gate: the threat model decides admission.
SHAPE_RANK = {
    SHAPE_BUFFER: 8, SHAPE_STREAM: 6, SHAPE_PATH: 4,
    SHAPE_STRING: 2, SHAPE_HANDLE: 1,
}

# attacker_controls token -> shapes it can drive. Tokens absent from this map
# supply no parameter and therefore admit nothing on their own.
CONTROL_SHAPES: "dict[str, tuple[str, ...]]" = {
    "bytes": (SHAPE_BUFFER, SHAPE_STRING, SHAPE_STREAM),
    "protocol-state": (SHAPE_BUFFER, SHAPE_STREAM),
    "fs-state": (SHAPE_PATH, SHAPE_STREAM),
    "call-sequence": (SHAPE_HANDLE,),
    "call-order": (SHAPE_HANDLE,),
    # `race` deliberately has no row. It is not a parameter, and the harness
    # this module generates is single-threaded — admitting every
    # handle-taking function under it would claim a concurrency surface
    # nothing here can drive.
}


def split_parameters(params: str) -> "list[str]":
    """Top-level comma split, so a function-pointer parameter stays whole."""
    out: "list[str]" = []
    depth = 0
    current: "list[str]" = []
    for character in params:
        if character in "([{<":
            depth += 1
        elif character in ")]}>":
            depth -= 1
        if character == "," and depth == 0:
            out.append("".join(current).strip())
            current = []
            continue
        current.append(character)
    tail = "".join(current).strip()
    if tail:
        out.append(tail)
    return [p for p in out if p and p not in {"void", "..."}]


# Qualifiers sit *between* the stars of an array of pointers
# (`const char *const *strings`), so counting stars without stripping them
# first reads that shape as a single pointer — and a harness admitted on it
# could only fabricate an array of pointers out of mutator bytes, which is the
# forged-state shape this gate exists to refuse.
_QUALIFIER = re.compile(r"\b(?:const|volatile|restrict|__restrict\w*)\b")


def _is_single_pointer(param: str) -> bool:
    """A pointer to one thing: not a double pointer, not a function pointer."""
    bare = _QUALIFIER.sub(" ", param)
    return ("*" in bare and "**" not in bare.replace(" ", "")
            and not re.search(r"\*\s*\)\s*\(", bare))


def _is_integer(param: str) -> bool:
    stripped = param.strip()
    if re.fullmatch(rf"(?:const\s+)?{_INT_TYPE}\s*\w*", stripped):
        return True
    # Public APIs frequently typedef their sizes. A scalar whose parameter
    # name explicitly says length is the same structural evidence without a
    # project-specific typedef list.
    return bool(
        _LENGTH_NAME.search(stripped)
        and re.fullmatch(r"(?:const\s+)?[A-Za-z_]\w*\s+[A-Za-z_]\w*", stripped)
    )


def counted_array(pointer: str, length: str) -> bool:
    """Whether two adjacent parameters are an array and its element count.

    The element type is what precedes the star, read from the last open paren
    because a macro-wrapped declaration puts its own return type in front of
    the first parameter (`PUBLIC(obj *) f(const double *v`).
    """
    if not _is_single_pointer(pointer) or not _is_integer(length):
        return False
    element = pointer.rsplit("(", 1)[-1].split("*", 1)[0]
    return bool(not _BYTE_ELEMENT.search(element)
                and _WIDE_ELEMENT.search(element))


def _buffer_pair(pointer: str, length: str) -> bool:
    """Whether two adjacent parameters are a payload and its length.

    Adjacency alone is not enough — ``const char *encoding, int options`` is
    adjacent and is not a buffer. A name on either side settles it, and when
    the declaration names neither parameter an adjacent pointer/integer pair
    is the convention with nothing else it could be.

    A length name alone is not enough either: `api_stmt *stmt, int N` is an
    opaque handle beside an unrelated integer, and a harness admitted on it
    hands mutator bytes to a pointer the API never parses. The pointer must
    also read as bytes — by element type or by payload name — which is why the
    element test names the byte types and their established aliases
    (``xmlChar``, ``guchar``, ``Bytef``) rather than matching a substring,
    which would read ``wchar_t`` and ``charset_context`` as byte buffers.
    """
    if not _is_single_pointer(pointer) or not _is_integer(length):
        return False
    if _PATH_NAME.search(pointer):
        return False
    if counted_array(pointer, length):
        return False
    byte_pointer = _has_byte_element_type(pointer)
    payload_named = bool(_PAYLOAD_NAME.search(pointer))
    if _LENGTH_NAME.search(length) or payload_named:
        return byte_pointer or payload_named
    # Unnamed on both sides: `int f(const void *, size_t)`.
    return byte_pointer and not re.search(r"\w\s*$", length.replace("*", " "))


def input_shapes(declaration: str) -> "set[str]":
    """Caller-supplied input shapes a declaration's parameters can carry."""
    match = re.search(r"\((?P<params>.*)\)\s*[^()]*$", declaration, re.S)
    if not match:
        return set()
    params = split_parameters(match.group("params"))
    shapes: "set[str]" = set()
    # Parameters a pair has already accounted for. A counted array joins them
    # without adding a shape: it is not a buffer the mutator can fill, and it
    # is not the opaque handle the fallback below would otherwise call it.
    spoken_for: "set[int]" = set()
    for index, param in enumerate(params[:-1]):
        if _buffer_pair(param, params[index + 1]):
            shapes.add(SHAPE_BUFFER)
            spoken_for.add(index)
        elif counted_array(param, params[index + 1]):
            spoken_for.add(index)
    for index, param in enumerate(params):
        # `char *` only. A `void *` or `uint8_t *` is a byte buffer, and
        # calling it a string would admit every raw-memory API on a target
        # whose threat model is text.
        text_pointer = bool(
            re.search(r"\bchar\s*(?:const\s*)?\*", param)
            and not re.search(r"\b(?:unsigned|signed|u_)\s*char", param)
            and _is_single_pointer(param))
        if text_pointer and index not in spoken_for:
            shapes.add(SHAPE_PATH if _PATH_NAME.search(param) else SHAPE_STRING)
        if _STREAM_TYPE.search(param) or re.fullmatch(
                r"(?:const\s+)?int\s+fd\w*", param.strip()):
            shapes.add(SHAPE_STREAM)
        # A pointer to something that is neither text nor a payload nor a
        # stream is the state object a call sequence mutates.
        if (_is_single_pointer(param) and not text_pointer
                and index not in spoken_for and not _STREAM_TYPE.search(param)):
            shapes.add(SHAPE_HANDLE)
    return shapes


# A symbol family built by appending a code-unit width or an ABI version to
# every public name, so the source says `pcre2_compile` and the build exports
# `pcre2_compile_8`. The mangling is a macro, so nothing short of a
# preprocessor sees both spellings — and without the link, a target's entire
# public surface reads as undeclared and its own harnesses as driving nothing.
# Broad and stable rather than a project list: a trailing `_<digits>` is the
# industry spelling of this (pcre2's 8/16/32, ICU's version suffix).
_WIDTH_SUFFIX_RE = re.compile(r"^(?P<base>\w+?)_(?P<width>\d{1,3})$")


def suffix_aliases(exported: "set[str]") -> "dict[str, str]":
    """Unsuffixed spelling -> the exported symbol it actually names.

    Only when the bare name is *not* itself exported: a library that publishes
    both `foo` and `foo_8` means two different functions, and aliasing them
    would hide one behind the other.
    """
    aliases: "dict[str, str]" = {}
    ambiguous: "set[str]" = set()
    for symbol in exported:
        match = _WIDTH_SUFFIX_RE.match(symbol)
        if match is None:
            continue
        base = match.group("base")
        if base in exported:
            continue
        if base in aliases:
            # Several widths of one family (8/16/32). Any of them answers
            # "is this covered", so keep the first by sort for determinism.
            ambiguous.add(base)
            aliases[base] = min(aliases[base], symbol)
            continue
        aliases[base] = symbol
    return aliases


# Word split for an identifier: `_` separators and camelCase humps alike, so
# `xmlReadMemory`, `xml_read_memory`, and `cJSON_ParseWithLength` all yield the
# verb. The vocabulary is workqueue's — one list of consume verbs for the whole
# harness — but its *pattern* cannot be reused here: it anchors on `\b`, and an
# underscore is a word character, so no boundary exists between `cJSON_` and
# `Parse` and the verb inside a mixed-convention symbol is never seen.
_WORD_SPLIT_RE = re.compile(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def consumes_input(symbol: str) -> bool:
    """Whether a symbol's own name says it consumes caller-supplied input."""
    return any(
        word.lower().startswith(verb)
        for word in _WORD_SPLIT_RE.split(symbol) if word
        for verb in workqueue._CONSUME_VERBS
    )


@dataclass
class Candidate:
    symbol: str
    declaration: str
    shapes: "list[str]"
    controls: "list[str]"
    admitted: bool
    blockers: "list[str]"
    covered_by: str = ""
    rank: int = 0
    route: str = ""

    def as_dict(self) -> dict:
        return {
            "symbol": self.symbol, "declaration": self.declaration,
            "shapes": self.shapes, "controls": self.controls,
            "admitted": self.admitted, "blockers": self.blockers,
            "covered_by": self.covered_by, "rank": self.rank,
            "route": self.route,
        }


def gate(symbol: str, declaration: str, exported: "set[str]",
         attacker_controls: "list[str]", covered_by: str = "") -> Candidate:
    """Decide whether one API earns a fuzz target, and say why not.

    Three independent facts, each from a structured source. Every one that
    fails is reported, rather than short-circuiting on the first: an agent
    told only "not exported" would go and fix that and then discover the
    signature takes nothing an attacker supplies.
    """
    blockers: "list[str]" = []
    if symbol not in exported:
        blockers.append(
            "not exported: the sanitizer build does not publish this symbol, "
            "so a harness could only reach it by compiling target internals"
        )
    elif symbol.startswith("_"):
        # C reserves file-scope identifiers beginning with an underscore for
        # the implementation, so a library naming a symbol this way has said
        # it is not public. The distinction matters most where it is otherwise
        # invisible: a *static archive* has no dynamic export list, so `nm`
        # reports every cross-translation-unit helper as global and the whole
        # internal surface would be offered as fuzz candidates.
        blockers.append(
            "reserved identifier: a leading underscore marks an internal, not "
            "a published API. Fuzzing it tests a contract no caller has"
        )
    shapes = input_shapes(declaration)
    reachable = sorted({
        control for control in attacker_controls
        if shapes & set(CONTROL_SHAPES.get(control, ()))
    })
    if not reachable:
        declared = ", ".join(attacker_controls) or "(none)"
        blockers.append(
            f"no untrusted parameter: the declaration carries "
            f"{', '.join(sorted(shapes)) or 'no caller-supplied input shape'}, "
            f"which [threat_model].attacker_controls ({declared}) cannot supply"
        )
    if covered_by:
        blockers.append(
            f"already driven by {covered_by}: improve that harness instead of "
            f"adding a second entry point onto the same API"
        )
    return Candidate(
        symbol=symbol, declaration=declaration, shapes=sorted(shapes),
        controls=reachable, admitted=not blockers, blockers=blockers,
        covered_by=covered_by,
    )


def candidates(config, exported: "set[str]",
               existing: "list[ExistingHarness]",
               declarations: "dict[str, str]",
               routes: "dict[str, str] | None" = None) -> "list[Candidate]":
    """Every exported symbol run through the gate, admitted ones ranked first.

    Rank is advisory throughout — the gate decides admission, this decides
    reading order, and on a large library that order is what an agent
    actually acts on. Every C function taking a `const char *` is admissible
    under a `bytes` threat model, so counting shapes would put a hundred
    object-builders ahead of the one parser. Three signals separate them:

    * how many distinct controls reach it (bytes *and* a call sequence is a
      richer surface than either alone);
    * the *strongest* shape rather than the number of them — a
      length-delimited buffer is a parser's signature, a bare string is not;
    * whether the name carries a consume verb, reusing the same
      target-agnostic verb family the work-card scorer ranks files by.
    """
    covered = {
        symbol: harness.path
        for harness in existing for symbol in harness.drives
    }
    aliases = suffix_aliases(exported)
    out: "list[Candidate]" = []
    for symbol in sorted(exported):
        declaration = declarations.get(symbol, "")
        if not declaration:
            # A width-suffixed export is declared under its bare name, because
            # the suffix is applied by a macro the header never spells out.
            match = _WIDTH_SUFFIX_RE.match(symbol)
            base = match.group("base") if match else ""
            if base and aliases.get(base) and base in declarations:
                declaration = declarations[base]
        if not declaration:
            # No public declaration is itself the answer to "is this a key
            # API": an exported symbol no header names is an internal the
            # linker happened to publish.
            continue
        candidate = gate(
            symbol, declaration, exported, config.attacker_controls,
            covered.get(symbol, ""),
        )
        candidate.route = (routes or {}).get(symbol, "")
        candidate.rank = (
            len(candidate.controls) * 10
            + max((SHAPE_RANK.get(shape, 0) for shape in candidate.shapes),
                  default=0)
            # Outweighs the whole shape scale on purpose. `(const double *,
            # int)` is a buffer by shape and an array builder in fact, while
            # `cJSON_Parse(const char *)` is the weakest shape and the actual
            # parser. When the two disagree, the verb is the better guess at
            # which one consumes untrusted input.
            + (10 if consumes_input(symbol) else 0)
            + (5 if candidate.route else 0)
        )
        out.append(candidate)
    out.sort(key=lambda c: (not c.admitted, -c.rank, c.symbol))
    return out


# ── Seeding an empty corpus ─────────────────────────────────────────
#
# Measured on libxml2: the same harness reached 1934 edges in its first slice
# from the target's own test files and 318 from nothing. A fuzzer starting
# empty spends its first slices rediscovering the file format, and on a short
# budget that is most of the budget. Every target that is worth fuzzing ships
# inputs somewhere; these are the conventional places, including OSS-Fuzz's
# `<fuzzer>_seed_corpus` layout.

_SEED_DIR_NAMES = (
    "seed_corpus", "seeds", "corpus", "testdata", "test-data",
    "fuzz", "fuzzing", "test", "tests", "testsuite", "examples",
)
# libFuzzer mutates small inputs far faster, and a corpus of huge files makes
# every later slice pay to reload them. These bounds are what keeps automatic
# seeding a speed-up rather than a new cost.
MAX_SEED_BYTES = 64 * 1024
MAX_SEED_FILES = 256


_TREE_CACHE: "dict[str, list[Path]]" = {}


def _tree(target_root: "str | os.PathLike") -> "list[Path]":
    """The pruned file list for a target, walked once per process.

    Seed discovery wanted eleven recursive globs and dictionary discovery one
    more per harness. On a large tree that is minutes of setup inside a
    five-minute campaign.
    """
    key = str(Path(target_root).resolve())
    if key not in _TREE_CACHE:
        # Seed and dictionary directories are outside the *audit* scope —
        # a bug in a test fixture is not a product bug — but they are exactly
        # what this walk is looking for, so they are kept explicitly.
        _TREE_CACHE[key] = _walk(
            Path(target_root),
            keep=_FUZZ_DIR_NAMES | {name.lower() for name in _SEED_DIR_NAMES})
    return _TREE_CACHE[key]


def seed_candidates(target_root: "str | os.PathLike") -> "list[Path]":
    """Small input-shaped files from the target's own test data.

    Deliberately not filtered by extension: a target's corpus is whatever
    format it parses, and guessing which suffixes count is how a seeding pass
    ends up copying nothing for the one target that needed it most. Source and
    build files are excluded instead, because those are the things that are
    definitely not inputs.
    """
    wanted = {name.lower() for name in _SEED_DIR_NAMES}
    found: "list[Path]" = []
    for path in _tree(target_root):
        if len(found) >= MAX_SEED_FILES:
            break
        if not wanted & {part.lower() for part in path.parts[:-1]}:
            continue
        if path.suffix.lower() in _NON_INPUT_SUFFIXES:
            continue
        try:
            if not 0 < path.stat().st_size <= MAX_SEED_BYTES:
                continue
        except OSError:
            continue
        found.append(path)
    return found


#: Env var naming a local directory of extra corpus inputs (an OSS-Fuzz or
#: ClusterFuzz corpus the operator staged). Operator-provided and local only —
#: the harness never fetches a corpus over the network.
SEED_CORPUS_DIR_ENV = "FUZZ_SEED_CORPUS_DIR"


def operator_seed_candidates(directory: "str | os.PathLike") -> "list[Path]":
    """Input files from an operator-provided local corpus directory.

    Unlike ``seed_candidates`` this is not filtered by the ``_SEED_DIR_NAMES``
    layout: the operator named the directory explicitly, so every file under it
    is a candidate, bounded by the same size and count limits that keep seeding
    a speed-up rather than a new cost. Source and build files are still skipped.
    """
    base = Path(directory)
    if not base.is_dir():
        return []
    found: "list[Path]" = []
    for path in sorted(base.rglob("*")):
        if len(found) >= MAX_SEED_FILES:
            break
        if not path.is_file() or path.suffix.lower() in _NON_INPUT_SUFFIXES:
            continue
        try:
            if not 0 < path.stat().st_size <= MAX_SEED_BYTES:
                continue
        except OSError:
            continue
        found.append(path)
    return found


# Code and build scaffolding: present in every test directory, and never the
# input a harness parses.
_NON_INPUT_SUFFIXES = frozenset({
    ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".py", ".rs", ".go", ".java",
    ".sh", ".bat", ".cmake", ".am", ".ac", ".m4", ".mk", ".o", ".a", ".so",
    ".dylib", ".dll", ".exe", ".md", ".txt.in", ".in", ".cmakein",
})
_SANITIZER_BUILD_RE = re.compile(r"/build-(?:asan|ubsan|msan|tsan)")


# ── Dictionaries ────────────────────────────────────────────────────
#
# A libFuzzer dictionary is a list of the tokens a format is built from, and
# it is the cheapest coverage a mutator can buy: without one it has to
# rediscover `<!DOCTYPE`, `<?xml`, and every keyword a byte at a time. OSS-Fuzz
# ships one next to the harness as `<fuzzer>.dict`, and projects that fuzz
# themselves keep them in the same place — every target in this tree already
# has one, and a campaign that ignores them starts from nothing on purpose.

_DICT_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def _name_tokens(text: str) -> "set[str]":
    return {token for token in _DICT_SPLIT_RE.split(text.lower())
            if len(token) > 2 and token not in {"fuzz", "fuzzer", "dict"}}


def dictionary_for(target_root: "str | os.PathLike", harness: str) -> str:
    """The dictionary that best matches a harness name, or "".

    Matched on shared name tokens — `fuzz_htmlReadMemory` against `html.dict`
    — because that is the association projects already encode in the filename.
    A target shipping exactly one dictionary uses it regardless: one format is
    the common case, and the alternative is leaving it on the floor.
    """
    found = [path for path in _tree(target_root)
             if path.suffix.lower() == ".dict"]
    if not found:
        return ""
    wanted = _name_tokens(harness)

    def affinity(stem: str) -> int:
        # Substring, not equality: a harness is named for the API it drives
        # (`fuzz_htmlReadMemory`), and the dictionary for the format
        # (`html.dict`), so the format name is buried inside the API name. The
        # longest matching token wins, which is what keeps `xml.dict` from
        # outbidding `html.dict` on an HTML harness.
        return max(
            (len(token) for token in _name_tokens(stem)
             if any(token in candidate for candidate in wanted)),
            default=0)

    scored = sorted(
        ((affinity(path.stem), -len(path.stem), str(path)) for path in found),
        reverse=True)
    best_score, _, best = scored[0]
    if best_score:
        return best
    return str(found[0]) if len(found) == 1 else ""


# ── Coverage instrumentation and the sibling build ──────────────────
#
# libFuzzer guides itself by SanitizerCoverage counters *inside the code under
# test*. An ordinary `build-<san>/` is sanitizer-instrumented but usually not
# coverage-instrumented, and a fuzzer linked against one runs blind: it still
# finds shallow faults, but it cannot tell that an input reached new code, so
# every campaign metric this module records would read zero forever.
#
# The fix must not be "rebuild the shared tree with coverage". That tree is
# what every other backend's recorded evidence was measured against, and
# replacing it needs the exclusive lease no live peer will yield. A *sibling*
# tree is free of both problems: `build-<san>+fuzz` is already matched by
# target_config's sanitizer-build pattern, so it is pruned from the source
# walk and cannot stale anything, and build_lease keys on the directory name,
# so building it never contends with `build-<san>`.

COVERAGE_TREE_SUFFIX = "+fuzz"
# The runtime hooks SanitizerCoverage emits calls to. Any one of them present
# as an undefined symbol means the object was compiled with coverage.
_COVERAGE_HOOKS = (
    "sanitizer_cov_trace_pc_guard", "sanitizer_cov_8bit_counters_init",
    "sanitizer_cov_pcs_init", "sanitizer_cov_trace_const_cmp",
    "sanitizer_cov_trace_cmp",
)


def is_coverage_instrumented(artifact: "str | os.PathLike") -> bool:
    """Whether a built artifact will drive libFuzzer's coverage feedback."""
    undefined = native_symbols.undefined_symbols(Path(artifact))
    return any(
        hook in name for name in undefined for hook in _COVERAGE_HOOKS
    )


@dataclass
class LibraryChoice:
    path: str
    tree: str
    instrumented: bool
    remedy: str = ""


def declared_exports(config, sanitizer: str) -> "tuple[int, int]":
    """(symbols the library exports, how many the configured includes declare).

    The pair the admission gate starts from, and a diagnostic for a harness
    route that exposes no callable API. Zero declared against a non-empty export
    list can mean `<san>_lib` and `includes` point at different things, but it can
    also describe a real internal/helper library with no public C API. Callers
    may report or rank this signal; it is not proof that a different artifact is
    the product.
    """
    library = coverage_library(config, sanitizer).path
    if not library or not Path(library).is_file():
        return 0, 0
    exported = native_symbols.defined_symbols(Path(library), exported_only=True)
    if not exported:
        return 0, 0
    index = declaration_index(
        config.target_root,
        [config.resolve_path(path) for path in config.includes],
    )
    declared = {symbol for symbol in exported if symbol in index}

    # Public names are not always spelled literally in the symbol table. The
    # candidate gate already resolves width/version suffixes such as PCRE2's
    # `pcre2_compile_8`; agreement must use the same rule or a working target
    # is reported as misconfigured. ELF symbol versions are another binary-only
    # suffix and are safe to remove after `@`.
    aliases = suffix_aliases(exported)
    declared.update(
        exported_symbol for source_name, exported_symbol in aliases.items()
        if source_name in index
    )
    declared.update(
        symbol for symbol in exported
        if symbol.split("@", 1)[0] in index
    )

    mangled = sorted(
        symbol for symbol in exported - declared
        if symbol.startswith(("_Z", "?"))
    )
    if mangled:
        # C++ headers carry source identifiers while nm carries ABI-mangled
        # names. Demangle in one bounded subprocess, then compare only the
        # final identifier before the parameter list (`ns::Type::parse` ->
        # `parse`). If no demangler is installed, the names remain unchanged;
        # setup merely reports the inconclusive mismatch and never rewrites the
        # operator's configuration from it.
        rendered = symbol_names.demangle_text("\n".join(mangled) + "\n")
        demangled = rendered.splitlines()
        if len(demangled) == len(mangled):
            for symbol, display in zip(mangled, demangled):
                prefix = display.split("(", 1)[0]
                match = re.search(r"([A-Za-z_]\w*)\s*$", prefix)
                if match and match.group(1) in index:
                    declared.add(symbol)
    return len(exported), len(declared)


def coverage_library(config, sanitizer: str) -> LibraryChoice:
    """The library a campaign should link, preferring a coverage build.

    Looks for the same library inside the sibling coverage tree first. Falling
    back to the plain build is not an error — a blind campaign is a real
    campaign — but it is reported, because a blind fuzzer that finds nothing
    looks identical to a guided one that found nothing.
    """
    raw = config.sanitizer_lib(sanitizer)
    plain = config.resolve_path(raw) if raw else ""
    if not plain:
        return LibraryChoice("", "", False, remedy=(
            f"target.toml has no {sanitizer}_lib, so there is no library to "
            f"link a harness against"
        ))
    tree = f"build-{sanitizer}{os.environ.get('AUDIT_BUILD_SUFFIX', '')}"
    sibling_tree = tree + COVERAGE_TREE_SUFFIX
    sibling = Path(str(plain).replace(f"/{tree}/", f"/{sibling_tree}/", 1))
    if str(sibling) != str(plain) and sibling.is_file():
        return LibraryChoice(
            str(sibling), sibling_tree, is_coverage_instrumented(sibling))
    instrumented = is_coverage_instrumented(plain)
    return LibraryChoice(plain, tree, instrumented, remedy="" if instrumented else (
        f"{Path(plain).name} carries no SanitizerCoverage, so libFuzzer will "
        f"run blind — it cannot tell that an input reached new code. "
        f"`bin/setup-target --build` builds a sibling tree with coverage on "
        f"(see .audit/build-materialize-{sanitizer}{COVERAGE_TREE_SUFFIX}.log "
        f"when it could not); by hand, the same thing is:\n"
        + rebuild_recipe(Path(config.target_root) / sibling_tree)
        + f"That toolchain and not the target's usual one: a sanitizer "
        f"runtime is version-locked to the code it instrumented, and only it "
        f"can share a process with the harness's.\n"
        f"The sibling never replaces {tree}/: it is pruned from the source "
        f"walk that decides build freshness and it takes its own build lease, "
        f"so no other backend's run is disturbed by building or using it."
    ))


# ── Out-of-tree build ───────────────────────────────────────────────

# libFuzzer is clang's; a target built by any compiler can still be fuzzed
# through it because the harness is a separate translation unit linked against
# the target's already-instrumented library.
COMPILE_SANITIZERS = {
    "asan": "address", "ubsan": "undefined", "msan": "memory", "tsan": "thread",
}


_CXX_SUFFIXES = {".cc", ".cpp", ".cxx", ".c++", ".mm"}


def rebuild_recipe(destination: "str | os.PathLike" = "") -> str:
    """The one way to rebuild a target's library for fuzzing.

    Both compilers and both flag variables, because a C++ target ignores CC
    and CFLAGS entirely and would come back with the same mismatch.
    """
    # -fsanitize-coverage=trace-pc-guard rides alongside fuzzer-no-link so the
    # one sibling serves both consumers: libFuzzer guides on the 8-bit counters
    # fuzzer-no-link emits, and the __sancov_guards section trace-pc-guard adds
    # is what ASan's `coverage=1` dump needs for bin/hits' native .sancov probe.
    # Redundant coverage kinds are legal to combine and only cost a little size.
    return (
        f"    CC={fuzzing_compiler()} CXX={fuzzing_compiler(cxx=True)}\n"
        f"    CFLAGS/CXXFLAGS += -fsanitize=fuzzer-no-link -fsanitize-coverage=trace-pc-guard\n"
        + (f"    build into {destination}/\n" if destination else "")
    )


def fuzzing_compiler(cxx: bool = False) -> str:
    """A clang that ships libFuzzer, not merely the first clang on PATH.

    On macOS the Command Line Tools clang has no ``libclang_rt.fuzzer``, so
    the default compiler links every fuzz harness with an error about a
    missing archive. ``sanitizer.llvm_tool`` already knows where a full LLVM
    lives on each platform; asking it here turns that failure into a working
    build wherever one is installed.
    """
    return sanitizer.llvm_tool("clang++" if cxx else "clang")


def compiler_for(source: Path) -> str:
    """The fuzzing compiler for one harness source, C or C++."""
    return fuzzing_compiler(source.suffix.lower() in _CXX_SUFFIXES)


# ── Source-grounded harness receipt ─────────────────────────────────
#
# A declaration proves the boundary shape, but not how a real caller creates
# state, relates arguments, or tears resources down. The generated harness
# carries one small comment receipt so those facts survive compilation and
# resume. It is context only: none of these fields participate in admission,
# contract linting, scheduling, crash classification, or publication.

_RECEIPT_FIELDS = {
    "BOUNDARY": "boundary",
    "CONTROLS": "controls",
    "DECLARATION": "declaration",
    "SOURCE-USAGE": "source_usage",
    "CONSTRUCTOR": "constructor",
    "ARG-RELATIONS": "argument_relations",
    "RESOURCE-FLOW": "resource_flow",
    "TEARDOWN": "teardown",
}
_RECEIPT_LINE = re.compile(
    r"^\s*//\s*S4-RECEIPT\s+([A-Z][A-Z-]*):\s*(.*?)\s*$", re.M)
# The fields an agent is expected to answer from source, and the token each
# contributes to `unresolved` while it has not been. Derived rather than
# trusted from the UNRESOLVED line, which otherwise goes stale the moment a
# field is filled in and its name is not struck from the list.
_RECEIPT_ANSWERABLE = (
    ("source-usage", "source_usage"),
    ("constructor", "constructor"),
    ("argument-relations", "argument_relations"),
    ("resource-flow", "resource_flow"),
    ("teardown", "teardown"),
)


@dataclass
class HarnessReceipt:
    # Whether the source carried a receipt at all. A hand-written harness has
    # none, and an all-blank receipt must not read as a grounded one.
    recorded: bool = False
    boundary: str = ""
    controls: str = ""
    declaration: str = ""
    source_usage: str = ""
    constructor: str = ""
    argument_relations: str = ""
    resource_flow: str = ""
    teardown: str = ""
    unresolved: "list[str]" = field(default_factory=list)
    warnings: "list[str]" = field(default_factory=list)

    def as_dict(self) -> dict:
        """The receipt as the manifest stores it, or nothing if there is none.

        The manifest's own ``schema`` versions this; an empty mapping is how a
        harness with no receipt is recorded, so every consumer can read
        "grounded" straight off the presence of the field.
        """
        if not self.recorded:
            return {}
        return {
            "boundary": self.boundary,
            "controls": self.controls,
            "declaration": self.declaration,
            "source_usage": self.source_usage,
            "constructor": self.constructor,
            "argument_relations": self.argument_relations,
            "resource_flow": self.resource_flow,
            "teardown": self.teardown,
            "unresolved": list(self.unresolved),
        }


def harness_receipt(source: "str | os.PathLike") -> HarnessReceipt:
    """Parse the neutral ``S4-RECEIPT`` comments at a harness's head.

    Legacy and hand-written harnesses carry no receipt and remain valid. A
    malformed or duplicate receipt stays visible as a warning but cannot turn
    into a build failure: these fields help the agent reason about a driver;
    the existing contract lints and probe path decide whether evidence counts.
    """
    try:
        text = Path(source).read_text(errors="replace")[:64 * 1024]
    except OSError:
        return HarnessReceipt()
    matches = list(_RECEIPT_LINE.finditer(text))
    if not matches:
        return HarnessReceipt()
    receipt = HarnessReceipt(recorded=True)
    seen: "set[str]" = set()
    for match in matches:
        label, value = match.group(1), match.group(2).strip()
        if label == "UNRESOLVED":
            if label in seen:
                receipt.warnings.append("duplicate UNRESOLVED field; kept the first")
                continue
            seen.add(label)
            receipt.unresolved = [
                item.strip() for item in value.split(",")
                if item.strip() and item.strip().lower() != "none"
            ]
            continue
        attribute = _RECEIPT_FIELDS.get(label)
        if attribute is None:
            receipt.warnings.append(f"unknown receipt field {label}")
            continue
        if label in seen:
            receipt.warnings.append(f"duplicate {label} field; kept the first")
            continue
        seen.add(label)
        setattr(receipt, attribute, value)
    for line in text.splitlines():
        if "S4-RECEIPT" in line and _RECEIPT_LINE.fullmatch(line) is None:
            receipt.warnings.append("malformed S4-RECEIPT line")
    for token, attribute in _RECEIPT_ANSWERABLE:
        value = getattr(receipt, attribute)
        if (not value or value.upper() == "UNRESOLVED") \
                and token not in receipt.unresolved:
            receipt.unresolved.append(token)
    return receipt


# ── Contract faithfulness ───────────────────────────────────────────
#
# The failure mode that makes fuzzing worthless is not a harness that finds
# nothing — it is a harness that finds a crash no caller could ever cause.
# Three shapes produce those, and all three are visible in the harness source:
# fabricating a state object out of fuzzer bytes, reaching past the public
# headers, and hand-declaring a symbol so an internal can be called directly.
# A crash from any of them is a crash in the harness's fiction, and triaging
# it costs a reviewer a session.
#
# Every row names the shape and the faithful alternative, because "rejected"
# without a repair is just an obstacle.

_CONTRACT_RULES: "tuple[tuple[str, re.Pattern[str], str], ...]" = (
    ("forged-state", re.compile(
        # A cast of the mutator's own buffer to something that is not bytes.
        r"\(\s*(?:const\s+)?(?:struct\s+|union\s+|class\s+)?"
        r"(?!void|char|unsigned|signed|uint8_t|int8_t|u_char|byte)"
        r"\w+\s*\*+\s*\)\s*(?:data|buf|buffer|bytes|input|payload)\b"),
     "casts the fuzzer's bytes straight into a typed object. No caller can "
     "hand the target a struct it did not build, so every crash reached this "
     "way is fiction. Build the object with the API's own constructor and "
     "feed the bytes to the function that parses them."),
    ("private-header", re.compile(
        r'#\s*include\s+"[^"]*(?:\.\./|/(?:internal|private|impl)/|'
        r'_(?:internal|private|impl)\.h)[^"]*"'),
     "includes a header from outside the target's public include path. An "
     "internal header exposes layouts and helpers no caller has, so what it "
     "lets you reach is not the attack surface. Include only what the "
     "installed headers declare."),
    ("hand-declared-symbol", re.compile(
        # An `extern` prototype, with or without a C++ linkage spec. The
        # fuzzing entry points are the exception and must be named: a C++
        # harness declares `extern "C" int LLVMFuzzerTestOneInput(...)`
        # exactly as OSS-Fuzz does, and flagging that would reject every
        # correct C++ harness.
        r"^\s*extern\s+(?:\"C(?:\+\+)?\"\s+)?"
        r"(?!.*\bLLVMFuzzer\w*\s*\()"
        r"[\w\s\*&:<>,]+?\w\s*\([^;{]*\)\s*;", re.M),
     "declares a target function by hand instead of including its header. "
     "That is how an unexported internal gets called, and an internal has no "
     "caller contract to violate. Include the public header; if the symbol "
     "is not in one, it is not the boundary."),
)


def contract_violations(source: "str | os.PathLike") -> "list[tuple[str, str]]":
    """Ways a harness reaches the target that a real caller could not."""
    try:
        text = Path(source).read_text(errors="replace")
    except OSError:
        return []
    # Comments carry example code and prose that trips every pattern; the
    # generated template's own guidance is the first thing that would.
    text = re.sub(r"/\*.*?\*/|//[^\n]*", "", text, flags=re.S)
    return [(name, repair) for name, pattern, repair in _CONTRACT_RULES
            if pattern.search(text)]


class UnfaithfulHarness(ValueError):
    """A harness reaches the target in a way no caller could."""


class InTreeSource(ValueError):
    """A harness source was found inside the target checkout."""


def reject_in_tree_source(source: Path, target_root: "str | os.PathLike") -> None:
    """Refuse to build a harness that lives in the target's checkout.

    This is the enforcement point for the isolation contract, and it is a hard
    error rather than a warning because the damage is not local. Build
    freshness is derived from the checkout's VCS state *including untracked
    paths*, so a harness file sitting in the tree restales the shared
    sanitizer build; every other backend auditing the same checkout then wants
    a rebuild it cannot take while a live peer holds the lease, and
    ``build_lease.claim_source_pin`` refuses the divergent run outright. One
    stray file stalls a whole concurrent benchmark cell.
    """
    try:
        resolved = source.resolve()
        root = Path(target_root).resolve()
    except (OSError, RuntimeError):
        return
    if resolved == root or root in resolved.parents:
        raise InTreeSource(
            f"harness source is inside the target checkout: {resolved}\n"
            f"Write it under RESULTS_DIR/{FUZZ_DIRNAME}/src/ instead. A file in "
            f"the checkout changes the source signature the shared build is "
            f"measured against, which stales that build for every other "
            f"backend reading it and makes their source pins disagree."
        )


def build_command(source: Path, binary: Path, san: str, config,
                  library: str, flags: "list[str]",
                  sanitize: bool = True) -> "list[str]":
    """The one compile invocation, so tests can read it without running it.

    ``-fsanitize=fuzzer`` supplies libFuzzer's ``main``; the target's own
    instrumentation comes from the library built earlier, which is linked, not
    rebuilt. ``-O1`` rather than probe's ``-O0``: a fuzzer's throughput is the
    product, and the harness is the only unit compiled here.

    The sanitizer is on by default and belongs there: it is what puts redzones
    around the *harness's* own stack and global objects, so a target that
    overruns a buffer its caller owns is reported rather than missed. ``build``
    drops it only after proving the link cannot start.
    """
    sanitizer_flag = COMPILE_SANITIZERS.get(san)
    if not sanitizer_flag:
        raise ValueError(f"fuzz harness does not support sanitizer: {san}")
    compiler = os.environ.get("FUZZ_CC", "") or compiler_for(source)
    includes = [
        value for path in config.includes
        for value in ("-I", config.resolve_path(path))
    ]
    library_args = [library] if library else []
    if library and Path(library).parent != Path("."):
        library_args.append(f"-Wl,-rpath,{Path(library).parent}")
    return [
        compiler, f"-fsanitize=fuzzer,{sanitizer_flag}" if sanitize else
        "-fsanitize=fuzzer",
        # The harness carries a standalone `main` for bin/probe to replay one
        # artifact against. libFuzzer supplies its own, so this define is what
        # compiles ours out of the campaign build — and its absence is what
        # compiles it back in when probe rebuilds the same source.
        "-DFUZZ_CAMPAIGN_BUILD=1",
        "-fno-omit-frame-pointer", "-g", "-O1", *flags,
        *config.defines, *includes, str(source), *library_args,
        *config.resolved_link_libs(),
        *shlex.split(os.environ.get("LDFLAGS", "")),
        "-o", str(binary),
    ]


def probe_compile_command(compiler: str, sanitizer_flag: str, source: Path,
                          binary: Path, config, library: str,
                          flags: "list[str]",
                          coverage: bool = False) -> "list[str]":
    """bin/probe's compile of one C/C++ harness, shared with its coverage twin.

    ``-O0`` and ``-g1`` because a probe binary exists to reproduce and name a
    frame, not to run fast. ``coverage`` adds trace-pc-guard so the same
    source, linked against the coverage sibling's library, dumps the
    ``.sancov`` `bin/hits` reads; everything else is identical on purpose,
    so the twin executes the route the sanitizer run executed.
    """
    includes = [
        value for path in config.includes
        for value in ("-I", config.resolve_path(path))
    ]
    library_args = [library] if library else []
    if library and Path(library).parent != Path("."):
        library_args.append(f"-Wl,-rpath,{Path(library).parent}")
    return [
        compiler, f"-fsanitize={sanitizer_flag}",
        *(("-fsanitize-coverage=trace-pc-guard",) if coverage else ()),
        "-g1", "-O0", *flags,
        *config.defines, *includes, str(source), *library_args,
        *config.resolved_link_libs(),
        *shlex.split(os.environ.get("LDFLAGS", "")), "-o", str(binary),
    ]


def build_identity(source: Path, san: str, config, library: str,
                   flags: "list[str]") -> str:
    """Content identity of everything the built fuzzer depends on.

    Same discipline as bin/probe's harness cache: a rebuild is skipped only
    when the source, the compiler, the sanitizer, the linked library's stat,
    and every configured flag are unchanged. A stale binary silently fuzzing
    an older library is the one cache failure that would corrupt results
    rather than merely waste time.
    """
    compiler = os.environ.get("FUZZ_CC", "") or compiler_for(source)
    try:
        stat = Path(library).stat() if library else None
    except OSError:
        stat = None
    parts = (
        "schema=2",
        f"source={hashlib.sha1(source.read_bytes()).hexdigest()}",
        f"compiler={shutil.which(compiler) or compiler}",
        f"sanitizer={san}",
        f"library={library}:{stat.st_size if stat else '-'}:"
        f"{stat.st_mtime_ns if stat else '-'}",
        f"includes={config.includes}", f"defines={config.defines}",
        f"links={config.resolved_link_libs()}", f"flags={flags}",
        f"ldflags={os.environ.get('LDFLAGS', '')}",
    )
    return hashlib.sha1("\n".join(parts).encode()).hexdigest()[:12]


STARTUP_PROBE_SECONDS = 30

# Two sanitizer runtimes in one process: whichever loses the race says so and
# aborts. Both spellings mean the same thing — the runtime linked here cannot
# own the process, because the library already brought its own.
_DUPLICATE_RUNTIME = re.compile(
    r"Interceptors are not working|runtime does not come first")


def duplicate_runtime(output: str) -> bool:
    """Whether a startup failure is two sanitizer runtimes in one process."""
    return bool(_DUPLICATE_RUNTIME.search(output))


def startup_failure(binary: Path, library: str, san: str) -> str:
    """What a harness printed when it cannot start, or "" when it can.

    ``-help=1`` makes libFuzzer print its flags and exit 0. The process still
    loads every library and initialises the sanitizer runtime — which is where
    a link that cannot run fails — but executes no input, so a non-zero status
    here is never a crash the campaign should have filed instead. A binary
    that dies this way would otherwise cost a slice and report as `dead`, a
    verdict naming the symptom while the cause sits in a log nobody reads.
    """
    environment = dict(os.environ)
    if library:
        environment[sanitizer.LIBRARY_PATH_ENV] = str(Path(library).parent)
    try:
        completed = run_timeout(
            [str(binary), "-help=1"], STARTUP_PROBE_SECONDS,
            kill=True, rss_mb=0, cwd=str(binary.parent),
            capture_output=True, text=True,
            env=sanitizer.prepare_runtime_env(san, environment),
        )
    except OSError as error:
        return str(error)
    if completed.returncode == 0:
        return ""
    output = ((completed.stdout or "") + (completed.stderr or "")).strip()
    return output or f"exited {completed.returncode} with no output"


@dataclass
class BuildResult:
    binary: str
    rebuilt: bool
    log: str = ""
    error: str = ""
    library: str = ""
    tree: str = ""
    guided: bool = False
    remedy: str = ""


# The sanitizer runtime is version-locked to the toolchain that instrumented
# the code, and the lock is a symbol: `__asan_version_mismatch_check_<tag>`,
# undefined at link when a library instrumented by one clang is linked by
# another. Broad and stable — every LLVM-derived toolchain spells the check
# this way — and it is the whole diagnosis, so the repair can be named instead
# of leaving an undefined symbol nobody reads.
_VERSION_LOCK = re.compile(r"__asan_version_mismatch_check\w*")


def toolchain_mismatch(output: str) -> str:
    """The repair for a link that failed on a version-locked runtime, or ""."""
    if not _VERSION_LOCK.search(output):
        return ""
    return (
        f"\nThe library was instrumented by a different toolchain than the one "
        f"linking this harness, and a sanitizer runtime is version-locked to "
        f"its own. Rebuild the library into the `build-<san>"
        f"{COVERAGE_TREE_SUFFIX}` sibling, which never replaces the shared "
        f"build, with that toolchain:\n" + rebuild_recipe()
    )


def build(source: Path, config, san: str = "asan",
          flags: "list[str] | None" = None) -> BuildResult:
    """Compile one harness out of tree, against the shared build read-only.

    Nothing here writes to the target checkout or to any ``build-<san>/``: the
    library is an input, the binary lands under RESULTS_DIR, and the caller
    holds only a *shared* build lease for the duration. That is what lets a
    claude campaign and a codex campaign fuzz the same pinned build at the
    same time without either invalidating the other.
    """
    reject_in_tree_source(source, config.target_root)
    violations = contract_violations(source)
    if violations:
        raise UnfaithfulHarness(
            f"{Path(source).name} would fuzz a target no caller can reach:\n"
            + "\n".join(f"  - {name}: {repair}" for name, repair in violations)
        )
    flags = list(flags or [])
    choice = coverage_library(config, san)
    library = choice.path
    if library and not Path(library).is_file():
        return BuildResult("", False, error=(
            f"target.toml {san}_lib is configured but missing: {library}. "
            f"Build the target first (bin/setup-target <slug> --build)."
        ))
    destination = binary_dir(config.results_dir)
    destination.mkdir(parents=True, exist_ok=True)
    digest = build_identity(source, san, config, library, flags)
    binary = destination / f"{source.stem}.{san}.{digest}"
    log = destination / f"{binary.name}.build.log"
    context = {
        "library": library, "tree": choice.tree,
        "guided": choice.instrumented, "remedy": choice.remedy,
    }
    if os.access(binary, os.X_OK):
        return BuildResult(str(binary), False, **context)
    def compile_once(sanitize: bool) -> "tuple[list[str], int, str]":
        command = build_command(
            source, binary, san, config, library, flags, sanitize)
        done = subprocess.run(command, capture_output=True, check=False)
        text = (done.stdout + done.stderr).decode(errors="replace")
        log.write_text(
            " ".join(shlex.quote(part) for part in command) + "\n\n" + text,
            encoding="utf-8",
        )
        return command, done.returncode, text

    def refuse(reason: str) -> BuildResult:
        binary.unlink(missing_ok=True)
        manifest_path(binary).unlink(missing_ok=True)
        return BuildResult("", False, log=str(log), error=reason, **context)

    command, returncode, output = compile_once(sanitize=True)
    if returncode or not os.access(binary, os.X_OK):
        return refuse(
            f"harness build failed (rc={returncode}); full log: {log}\n"
            + output[-4000:] + toolchain_mismatch(output))
    failure = startup_failure(binary, library, san)
    sanitized = True
    if failure and duplicate_runtime(failure):
        # The library brought its own runtime and will not share the process
        # with a second one. Linking the harness without the sanitizer leaves
        # one runtime, and the target — the code under audit — stays fully
        # instrumented. What is lost is the harness's own redzones, so a
        # target that overruns a buffer *its caller* owns goes unreported;
        # that is a real loss, and `context["remedy"]` says so rather than
        # letting a quieter campaign pass for an equal one.
        command, returncode, output = compile_once(sanitize=False)
        if returncode or not os.access(binary, os.X_OK):
            return refuse(
                f"harness build failed (rc={returncode}); full log: {log}\n"
                + output[-4000:] + toolchain_mismatch(output))
        sanitized = False
        failure = startup_failure(binary, library, san)
        if not failure:
            context["remedy"] = "\n".join(filter(None, (
                context["remedy"],
                f"{Path(library).name} loads its own {san} runtime, so the "
                f"harness had to be linked without one: the target stays "
                f"instrumented, but nothing guards the harness's own stack "
                f"and global objects, and a target that overruns a buffer its "
                f"caller owns will not be reported. Build the library with "
                f"the compiler that links the harnesses to get both:\n"
                + rebuild_recipe(
                    Path(config.target_root) / (
                        f"build-{san}{COVERAGE_TREE_SUFFIX}")))))
    if failure:
        return refuse(
            f"harness compiled but cannot start, so a campaign would spend a "
            f"slice on it and report `dead`; full log: {log}\n"
            + failure[-4000:])
    write_manifest(binary, source, san, choice, digest, sanitized)
    return BuildResult(str(binary), True, log=str(log), **context)


# ── Build manifest ──────────────────────────────────────────────────
#
# What a binary is cannot be recovered from its filename. Splitting on the
# first dot loses any harness whose source name contains one, and it cannot
# express which sanitizer the binary was built for — so a campaign asked for
# ASan would happily execute the UBSan build of the same harness because it
# sorted later. One small sidecar per binary answers all of it exactly.

MANIFEST_SUFFIX = ".manifest.json"


def manifest_path(binary: "str | os.PathLike") -> Path:
    return Path(str(binary) + MANIFEST_SUFFIX)


def write_manifest(binary: Path, source: Path, san: str,
                   choice: "LibraryChoice", digest: str,
                   sanitized: bool = True) -> None:
    hypothesis = ""
    try:
        head = source.read_text(errors="replace")[:4096]
        match = re.search(r"HYPOTHESIS-ID:\s*([^\s*/>]+)", head)
        hypothesis = match.group(1) if match else ""
    except OSError:
        pass
    try:
        source_sha1 = hashlib.sha1(source.read_bytes()).hexdigest()
    except OSError:
        source_sha1 = ""
    receipt = harness_receipt(source)
    manifest_path(binary).write_text(json.dumps({
        "schema": 2,
        "harness": source.stem,
        "source_sha1": source_sha1,
        "compiler": compiler_for(source),
        "source": str(source),
        "sanitizer": san,
        "digest": digest,
        "library": choice.path,
        "tree": choice.tree,
        "guided": choice.instrumented,
        "sanitized": sanitized,
        "hypothesis_id": hypothesis,
        "binary": str(binary),
        "receipt": receipt.as_dict(),
        "receipt_warnings": receipt.warnings,
    }, indent=2, sort_keys=True), encoding="utf-8")


def built_harnesses(results_dir: "str | os.PathLike",
                    san: str) -> "dict[str, dict]":
    """harness name -> manifest of its newest binary for this sanitizer.

    Reads manifests rather than parsing filenames, and filters on the exact
    sanitizer, so a campaign can never run a binary built for another one.
    """
    directory = binary_dir(results_dir)
    newest: "dict[str, dict]" = {}
    for path in sorted(directory.glob(f"*{MANIFEST_SUFFIX}") if directory.is_dir() else []):
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if record.get("schema") not in (1, 2) or record.get("sanitizer") != san:
            continue
        # Schema 1 predates source-grounding receipts. Keep it runnable and
        # fail open to empty context rather than making a cached binary rebuild
        # merely because status learned to explain it better.
        record.setdefault("receipt", {})
        record.setdefault("receipt_warnings", [])
        binary = Path(str(record.get("binary", "")))
        if not binary.is_file() or not os.access(binary, os.X_OK):
            continue
        name = str(record.get("harness", ""))
        record["current"] = _matches_source(record, san)
        current = newest.get(name)
        if current is None or _prefer(record, current):
            newest[name] = record
    return newest


def _matches_source(record: dict, san: str) -> bool:
    """Whether this binary was built from the source as it stands now.

    Identity, not recency. Build A, edit to B, revert to A: A's cached binary
    is never retouched, so B stays newest and the campaign fuzzes a source
    that no longer exists while replay copies A into scratch — every artifact
    then fails to reproduce.
    """
    source = Path(str(record.get("source", "")))
    if not source.is_file():
        return False
    return str(record.get("digest", "")) == record.get("source_digest", "") or \
        hashlib.sha1(source.read_bytes()).hexdigest() == str(record.get("source_sha1", ""))


def _prefer(candidate: dict, incumbent: dict) -> bool:
    """Current build wins; among equals, the newer binary."""
    if candidate.get("current") != incumbent.get("current"):
        return bool(candidate.get("current"))
    try:
        return (Path(candidate["binary"]).stat().st_mtime
                > Path(incumbent["binary"]).stat().st_mtime)
    except OSError:
        return False
