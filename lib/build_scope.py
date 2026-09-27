"""Does a reproducer driver test the pinned build, or a build of its own?

A driver that ``#include``s a target source file compiles that unit into
itself under its own flags. The sanitizer report is real, but it is not a
report about the pinned build: the unit may be one the pinned configuration
never compiled (an optional module the upstream default switches off), or
compiled under different options. ``bin/probe`` never offers that route, so a
crash reached through it in one benchmark condition has no counterpart in the
other, and a maintainer replaying against the pinned artifacts cannot see it.
The crash lane keeps such reports as findings, where source review adjudicates
them, and never as crashes.

The compiler answers the question, not a regex over include lines: ``-MM``
lists every user file the preprocessor actually opened, following the include
directories and conditional includes the driver really uses, and ``-MG`` keeps
the listing going past a header the scan cannot find (a generated one, or one
behind an include directory only the discovery build knew).

The suffix chooses the language except when a ``.c`` driver only parses as
C++; see ``driver_language``.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Sequence

import sanitizer
import timeout

# Suffixes of a file the compiler turns into object code: including one of
# these compiles a translation unit. Headers, however large, are the
# interface the pinned build also exposes.
TARGET_UNIT_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm"})
# Suffixes clang compiles as C++ (`.C` is case-sensitive, so it is checked
# apart from these lowercase ones).
CXX_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".c++", ".mm"})
SCAN_SECONDS = 60
# The scan's answer for one driver, beside it. Triage revisits a pending
# crash every pass; the answer changes when its bytes or compile context do.
CACHE_NAME = ".build-scope.json"
# One dependency token: runs of non-space characters, with `\ ` escaping a
# space inside a path, as make-style dependency output writes it.
_TOKEN_RE = re.compile(r"(?:\\ |\S)+")


def compiled_target_units(
    driver: Path, target_root: Path, *, include_dirs: tuple[Path, ...] = (),
    defines: tuple[str, ...] = (),
) -> list[Path] | None:
    """Target-tree source units the driver compiles into itself.

    Returns paths relative to ``target_root``, or ``None`` when the scan could
    not run at all (no compiler, a timeout, a preprocessor failure). A
    demotion is permanent, so it never rests on a scan's own failure: the
    caller keeps the crash and the warning names why.
    ``include_dirs`` are the directories the discovery build compiled with
    (the target configuration's ``includes``); a source unit the driver names
    through one of them is otherwise a bare token the scan cannot place.
    """
    try:
        driver = Path(driver).resolve(strict=True)
        root = Path(target_root).resolve(strict=True)
    except OSError:
        return None
    try:
        digest = hashlib.sha256(driver.read_bytes()).hexdigest()
    except OSError:
        return None
    cache = driver.parent / CACHE_NAME
    include_flags = [f"-I{directory}" for directory in (root, *include_dirs)]
    compile_flags = [*defines, *include_flags]
    try:
        cached = json.loads(cache.read_text(encoding="utf-8"))
        # The flags carry the target root as the first include directory.
        if cached.get("sha256") == digest and cached.get("flags") == compile_flags:
            return [Path(unit) for unit in cached["units"]]
    except (OSError, ValueError, KeyError, TypeError):
        pass
    language = driver_language(driver, compile_flags)
    cxx = language == "c++"
    command = [
        sanitizer.llvm_tool("clang++" if cxx else "clang"),
        # clang reads the language off every other suffix itself.
        *(("-x", "c++") if cxx and driver.suffix == ".c" else ()),
        "-MM", "-MG", *flags_for_language(compile_flags, language), str(driver),
    ]
    try:
        completed = timeout.run_timeout(
            command, SCAN_SECONDS, cwd=str(driver.parent),
            capture_output=True, text=True,
        )
    except OSError as exc:
        print(
            f"WARN: build-scope scan of {driver} could not start: {exc}",
            file=sys.stderr,
        )
        return None
    if completed.returncode != 0:
        print(
            f"WARN: build-scope scan of {driver} failed (rc={completed.returncode}): "
            f"{first_error(completed.stderr or completed.stdout)}",
            file=sys.stderr,
        )
        return None
    units: list[Path] = []
    tokens = _TOKEN_RE.findall(completed.stdout.replace("\\\n", " "))
    for token in tokens[1:]:  # tokens[0] is the `driver.o:` rule target
        resolved = _place(
            Path(token.replace("\\ ", " ")), (driver.parent, root, *include_dirs),
        )
        if resolved is None:
            continue  # `-MG` lists a header it could not find by name only
        if resolved == driver:
            continue
        if resolved.suffix.lower() not in TARGET_UNIT_SUFFIXES:
            continue
        if not resolved.is_relative_to(root):
            continue
        relative = resolved.relative_to(root)
        if relative not in units:
            units.append(relative)
    try:
        cache.write_text(
            json.dumps({"sha256": digest, "flags": compile_flags,
                        "units": [str(u) for u in units]}),
            encoding="utf-8",
        )
    except OSError as exc:
        print(f"WARN: build-scope scan result not cached beside {driver}: {exc}", file=sys.stderr)
    return units


def _place(token: Path, bases: tuple[Path, ...]) -> Path | None:
    """The file a dependency token names, or None when it names none.

    The preprocessor prints a found file with the path it opened it by, and a
    missing one (under ``-MG``) exactly as the ``#include`` wrote it, so a
    relative token is tried against every directory the compile could have
    searched.
    """
    candidates = [token] if token.is_absolute() else [base / token for base in bases]
    for candidate in candidates:
        try:
            return candidate.resolve(strict=True)
        except OSError:
            continue
    return None


def flags_for_language(flags: Sequence[str], language: str) -> list[str]:
    # A configured C++ standard can accompany a plain C driver (and vice
    # versa); passing it to the other compiler makes the scan fail before it
    # can answer whether target source was compiled into the driver.
    return [
        flag for flag in flags
        if not flag.startswith("-std=") or ("++" in flag) == (language == "c++")
    ]


def driver_language(driver: Path, flags: Sequence[str] = ()) -> str:
    """The language a C-family driver compiles as: ``"c"`` or ``"c++"``.

    The suffix decides, as it does for bin/probe, except for a ``.c`` file
    whose body is C++: model-direct drivers are built by the model's own
    command line, so nothing enforced the suffix, and a C++ API driver saved
    as ``harness.c`` built with ``clang++``. Such a file is C++ only when the
    compiler rejects it as C and accepts it as C++ under the same flags; a
    driver neither accepts (a header only the discovery build could find)
    keeps its suffix rather than guessing. A source that compiles in both
    languages keeps its suffix too; the original model-direct compiler was
    not recorded, so a dual-language legacy driver may need manual repair.
    Each parse drops the other language's ``-std=``: a C++ target's configured
    ``-std=c++17`` would fail every C parse, while a C++ parse keeps it.
    """
    driver = Path(driver)
    if driver.suffix == ".C" or driver.suffix.lower() in CXX_SUFFIXES:
        return "c++"
    if driver.suffix.lower() != ".c":
        return "c"

    def parses(language: str) -> bool:
        command = [
            sanitizer.llvm_tool("clang++" if language == "c++" else "clang"),
            "-x", language, "-fsyntax-only",
            *flags_for_language(flags, language),
            str(driver),
        ]
        try:
            completed = timeout.run_timeout(
                command, SCAN_SECONDS, cwd=str(driver.parent),
                capture_output=True, text=True,
            )
        except OSError:
            return False
        return completed.returncode == 0

    return "c++" if not parses("c") and parses("c++") else "c"


def first_error(output: str | None) -> str:
    """The compiler's first ``error:`` line, not its include-chain preamble."""
    lines = (output or "").strip().splitlines()
    return next(
        (line.strip() for line in lines if "error:" in line),
        lines[0].strip() if lines else "no diagnostic",
    )
