#!/usr/bin/env python3
"""Names a built native artifact defines, as ``nm`` reports them.

Two callers need the same answer to different questions. ``bin/callgraph``
bounds the audited code by the sanitizer artifact's symbol table, so an
example tree that happens to parse cannot contribute entry roots.
``lib/fuzz_harness`` asks whether a candidate API is actually published by
the build before admitting it as a fuzz entry point. Both are "what did this
build export", so both read it from here rather than each running its own
``nm``.

Stdlib only, by contract: ``bin/callgraph`` runs under a separate interpreter
that is guaranteed to have trailmark and nothing else, and reaches this module
by appending the harness ``lib/`` to ``sys.path``. A test enforces the
restriction, because a third-party import here would break that sidecar on an
interpreter the harness never chose.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

# One `nm` per artifact per process. A single `bin/fuzz` invocation asks the
# same question from the coverage probe, the export listing, each build, and
# the campaign's startup — five subprocesses over the same megabytes. Keyed on
# identity, not just path, so a rebuilt artifact is re-read.
_CACHE: "dict[tuple, set[str]]" = {}


def _identity(artifact: Path, kind: str) -> "tuple | None":
    try:
        stat = artifact.stat()
    except OSError:
        return None
    return (str(artifact), kind, stat.st_size, stat.st_mtime_ns)

# Toolchain-generated names that are never audited code. `__` covers the
# reserved C identifier space (compiler builtins, libc internals) that no
# target's own public API may use; the rest are emitted by the sanitizer
# runtime, the assembler, and the linker's outliner.
_GENERATED_PREFIXES = ("__", "asan.", "ltmp", "GCC_except", "OUTLINED")
_GENERATED_NAMES = {"_mh_execute_header", "rust_eh_personality"}

# Symbol types `nm` reports for code: text, and weak text. Everything these
# sets are compared against is a function, so admitting data and bss entries
# would pad the answer with names no caller could ever call.
_TEXT_KINDS = "TtWw"


def normalise(names: "set[str]") -> "set[str]":
    """Strip the Mach-O underscore, then drop toolchain-generated names.

    The prefix is removed only when the artifact as a whole carries it.
    Stripping per-name instead would corrupt the names that genuinely start
    with one (``_pcre2_...``) and — because both spellings would then be kept
    — would double the size of the set. Filtering runs after normalising: on
    Mach-O the toolchain's own symbols arrive as ``_asan.module_ctor``, and a
    prefix test against the raw spelling lets every one of them through.
    """
    prefixed = sum(1 for name in names if name.startswith("_"))
    if prefixed * 2 > len(names):
        names = {name[1:] if name.startswith("_") else name for name in names}
    return {
        name for name in names
        if name and name not in _GENERATED_NAMES
        and not name.startswith(_GENERATED_PREFIXES)
    }


def defined_symbols(artifact: Path, *, exported_only: bool = False) -> "set[str]":
    """Function names ``nm`` reports as defined in a built artifact.

    ``--defined-only`` is GNU binutils and LLVM; ``-U`` is the BSD/Mach-O
    spelling of the same filter. Trying both in order is what makes this work
    on a Linux CI image and a macOS developer machine without asking which
    one it is.
    """
    artifact = Path(artifact)
    if not artifact.is_file():
        return set()
    key = _identity(artifact, f"defined:{exported_only}")
    if key is not None and key in _CACHE:
        return _CACHE[key]
    base = ["nm"] + (["-g"] if exported_only else [])
    output = ""
    for selector in ("--defined-only", "-U"):
        proc = subprocess.run(
            [*base, selector, str(artifact)],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode == 0:
            output = proc.stdout
            break
    names: "set[str]" = set()
    for line in output.splitlines():
        fields = line.split()
        # "<addr> <type> <name>", or "<type> <name>" for an archive member's
        # address-less entry.
        if len(fields) < 2:
            continue
        kind, name = fields[-2], fields[-1]
        if len(kind) != 1 or kind not in _TEXT_KINDS:
            continue
        names.add(name)
    result = normalise(names)
    if key is not None:
        _CACHE[key] = result
    return result


def undefined_symbols(artifact: Path) -> "set[str]":
    """Names an artifact expects a runtime to supply, verbatim.

    Deliberately *not* normalised: the interesting entries here are the
    compiler runtime's own hooks — ``__sanitizer_cov_*`` and friends — and
    ``normalise`` exists to throw exactly those away. Asking "what runtime
    does this build require" is the only way to tell an instrumented library
    from a plain one without rebuilding it.
    """
    artifact = Path(artifact)
    if not artifact.is_file():
        return set()
    key = _identity(artifact, "undefined")
    if key is not None and key in _CACHE:
        return _CACHE[key]
    for selector in ("--undefined-only", "-u"):
        proc = subprocess.run(
            ["nm", selector, str(artifact)],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode == 0:
            result = {
                fields[-1] for fields in
                (line.split() for line in proc.stdout.splitlines()) if fields
            }
            if key is not None:
                _CACHE[key] = result
            return result
    return set()


# Itanium (`_Z`) and Rust (legacy `_ZN…E`, v0 `_R`) mangling. Everything else
# `nm` prints is already the identifier the source spelled.
_MANGLED_PREFIXES = ("_Z", "_R")
_RUST_LEGACY_HASH = re.compile(r"^h[0-9a-f]{16}$")
_IDENTIFIER = re.compile(r"^[A-Za-z_]\w*$")


def demangle_text(text: str, tool: "str | None" = None) -> str:
    """Demangle one symbol per line; unchanged when no demangler is present.

    `llvm-cxxfilt` handles Rust v0 as well as Itanium; GNU `c++filt` handles
    v0 only from binutils 2.36. A caller that knows a pinned LLVM passes its
    tool; otherwise PATH decides.
    """
    tool = tool or shutil.which("llvm-cxxfilt") or shutil.which("c++filt")
    if not text or tool is None:
        return text
    try:
        result = subprocess.run(
            [tool], input=text, capture_output=True, text=True, timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return text
    return result.stdout if result.returncode == 0 else text


def _split_scoped(text: str) -> "list[str]":
    """Split on `::` outside brackets, so a template argument's own `::`
    never becomes a scope of the symbol."""
    out, depth, start = [], 0, 0
    index = 0
    while index < len(text):
        char = text[index]
        if char in "<({[":
            depth += 1
        elif char in ">)}]":
            depth = max(0, depth - 1)
        elif depth == 0 and text.startswith("::", index):
            out.append(text[start:index])
            index += 2
            start = index
            continue
        index += 1
    out.append(text[start:])
    return out


def source_identifier(demangled: str) -> "tuple[str, str]":
    """(identifier, enclosing scope) a demangled symbol names, or ("", "").

    The identifier is what a source parser records as the function name; the
    scope is the namespace, module, class, or crate module directly around
    it, so a caller can ask whether that scope is one it parsed. Empty for
    what no parser could define from this tree's source: a template or
    generic instantiation or closure (many symbols to one definition,
    `vector<int>::push_back`, `Option<&str>::map::<…>`, `{closure#0}`), and
    names in the toolchain-reserved `__` space.
    """
    text = demangled.strip()
    if not text:
        return "", ""
    # The parameter list, and any cv/ref qualifiers after it, say nothing
    # about the name. Match the last `)` back to its `(` so a type inside
    # the list cannot cut the path short.
    close = text.rfind(")")
    if close != -1:
        depth = 0
        for index in range(close, -1, -1):
            if text[index] == ")":
                depth += 1
            elif text[index] == "(":
                depth -= 1
                if depth == 0:
                    text = text[:index]
                    break
    text = text.replace("(anonymous namespace)", "")
    if "<" in text or "{" in text or "(" in text:
        return "", ""
    segments = [part.strip() for part in _split_scoped(text) if part.strip()]
    if segments and _RUST_LEGACY_HASH.match(segments[-1]):
        segments.pop()
    if not segments:
        return "", ""
    identifier = segments[-1].split()[-1]
    if not _IDENTIFIER.match(identifier):
        return "", ""
    scope = segments[-2].split()[-1] if len(segments) > 1 else ""
    if identifier.startswith("__") or (segments[0].split()[-1]).startswith("__"):
        return "", ""
    return identifier, scope


def source_identifiers(names: "set[str]", tool: "str | None" = None) -> "set[tuple[str, str]]":
    """(identifier, scope) for every name, demangling the mangled ones.

    Plain C names have no scope, but still have to be source identifiers:
    compiler clones such as `parse.cold.1` are not definitions a parser can
    record. A mangled name the demangler leaves alone (no demangler installed,
    or an unknown scheme) is dropped rather than compared as its mangled
    spelling, which no source parser produces.
    """
    mangled = sorted(name for name in names if name.startswith(_MANGLED_PREFIXES))
    out = {
        parsed for name in names if not name.startswith(_MANGLED_PREFIXES)
        for parsed in (source_identifier(name),) if parsed[0]
    }
    if not mangled:
        return out
    rendered = demangle_text("\n".join(mangled) + "\n", tool).splitlines()
    if len(rendered) != len(mangled):
        return out
    for raw, display in zip(mangled, rendered):
        if display == raw:
            continue
        identifier, scope = source_identifier(display)
        if identifier:
            out.add((identifier, scope))
    return out
