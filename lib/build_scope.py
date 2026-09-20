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
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import sanitizer
import timeout

# Suffixes of a file the compiler turns into object code: including one of
# these compiles a translation unit. Headers, however large, are the
# interface the pinned build also exposes.
TARGET_UNIT_SUFFIXES = frozenset({".c", ".cc", ".cpp", ".cxx", ".m", ".mm"})
_CXX_SUFFIXES = frozenset({".cc", ".cpp", ".cxx", ".mm"})
SCAN_SECONDS = 60
# The scan's answer for one driver, beside it. Triage revisits a pending
# crash every pass; the answer changes only when the driver's bytes do.
CACHE_NAME = ".build-scope.json"
# One dependency token: runs of non-space characters, with `\ ` escaping a
# space inside a path, as make-style dependency output writes it.
_TOKEN_RE = re.compile(r"(?:\\ |\S)+")


def compiled_target_units(
    driver: Path, target_root: Path, *, include_dirs: tuple[Path, ...] = (),
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
    try:
        cached = json.loads(cache.read_text(encoding="utf-8"))
        if cached.get("sha256") == digest and cached.get("root") == str(root):
            return [Path(unit) for unit in cached["units"]]
    except (OSError, ValueError, KeyError, TypeError):
        pass
    compiler = sanitizer.llvm_tool(
        "clang++" if driver.suffix.lower() in _CXX_SUFFIXES else "clang",
    )
    command = [
        compiler, "-MM", "-MG",
        *(f"-I{directory}" for directory in (root, *include_dirs)),
        str(driver),
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
        detail = (completed.stderr or completed.stdout or "").strip().splitlines()
        print(
            f"WARN: build-scope scan of {driver} failed (rc={completed.returncode}): "
            f"{detail[0] if detail else 'no diagnostic'}",
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
            json.dumps({"sha256": digest, "root": str(root), "units": [str(u) for u in units]}),
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

