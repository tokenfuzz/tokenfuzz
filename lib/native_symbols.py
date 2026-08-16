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

import subprocess
from pathlib import Path

# Toolchain-generated names that are never audited code. `__` covers the
# reserved C identifier space (compiler builtins, libc internals) that no
# target's own public API may use; the rest are emitted by the sanitizer
# runtime, the assembler, and the linker's outliner.
_GENERATED_PREFIXES = ("__", "asan.", "ltmp", "GCC_except", "OUTLINED")

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
        if name and not name.startswith(_GENERATED_PREFIXES)
    }


def defined_symbols(artifact: Path, *, exported_only: bool = False) -> "set[str]":
    """Function names ``nm`` reports as defined in a built artifact.

    ``--defined-only`` is GNU binutils and LLVM; ``-U`` is the BSD/Mach-O
    spelling of the same filter. Trying both in order is what makes this work
    on a Linux CI image and a macOS developer machine without asking which
    one it is.
    """
    if not Path(artifact).is_file():
        return set()
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
    return normalise(names)


def undefined_symbols(artifact: Path) -> "set[str]":
    """Names an artifact expects a runtime to supply, verbatim.

    Deliberately *not* normalised: the interesting entries here are the
    compiler runtime's own hooks — ``__sanitizer_cov_*`` and friends — and
    ``normalise`` exists to throw exactly those away. Asking "what runtime
    does this build require" is the only way to tell an instrumented library
    from a plain one without rebuilding it.
    """
    if not Path(artifact).is_file():
        return set()
    for selector in ("--undefined-only", "-u"):
        proc = subprocess.run(
            ["nm", selector, str(artifact)],
            capture_output=True, text=True, check=False,
        )
        if proc.returncode == 0:
            return {
                fields[-1] for fields in
                (line.split() for line in proc.stdout.splitlines()) if fields
            }
    return set()
