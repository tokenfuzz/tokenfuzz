#!/usr/bin/env python3
"""Parse audit state files (markdown) for subsystem attribution.

The audit harness (bin/audit) and lib/structured_state.sh need to know
which subsystem an agent is currently focused on. This module replaces
the prior shell+awk multi-stage extraction with a single typed entry
point so both call sites share one definition.

The state file is a markdown document with three sections that all
carry signal, in priority order:

  1. ``## Primary Subsystem: <path>`` — authoritative current claim.
  2. ``## Current Hypothesis Queue`` table — File:Function:Line column
     of non-DISCARDED rows.
  3. ``## Entry Point Coverage`` table — Subsystem column of rows
     whose Notes don't mark them as archived/rotated out.

For browser targets, candidates must match a known prefix loaded from
a subsystems.txt file (see ``targets/firefox/subsystems.txt``). For
generic targets, the literal Primary Subsystem value is accepted; if
no Primary Subsystem header exists, callers can fall back to
:func:`subsystem_from_path` to derive one from a file path.

Two CLI subcommands:

  parse_state.py subsystem <state_file> [--subsystems FILE]
      Run the four-stage extraction; print the subsystem or
      "unknown".

  parse_state.py subsystem-from-path <path> [--subsystems FILE]
      Map a single file path to its subsystem; used to compute the
      subsystem for hypothesis-queue JSONL rows.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Strip [tag] and (note) decorations from Primary Subsystem header values.
_BRACKET_RE = re.compile(r"\[[^\]]*\]")
_PAREN_RE = re.compile(r"\([^)]*\)")
_PRIMARY_RE = re.compile(r"^(?:##\s+)?Primary Subsystem:\s*(.*?)\s*$")

# Notes that mark an Entry Point Coverage row as no-longer-active.
_ARCHIVED_NOTES_RE = re.compile(
    r"rotated out|archived|no active|do not resume|reverse-turn budget exhausted",
    re.IGNORECASE,
)


# Mode tokens an overlay line may carry as an optional first column
# ("browser dom/canvas"). Attribution ignores the mode — it is only a
# cold-start-pick gate (see bin/audit) — so load_subsystems strips it.
_SUBSYSTEM_MODE_TOKENS = {"browser", "shell", "both"}


def load_subsystems(path: Path | None) -> list[str]:
    """Load subsystem prefixes from a subsystems overlay file.

    Each line is a path prefix, optionally preceded by a mode column
    (`browser`/`shell`/`both`) which is stripped here — attribution uses
    every path regardless of mode. A bare prefix (no mode column) is also
    accepted, so older flat overlays keep working. Comments (`#`) and
    blank lines are ignored.
    """
    if path is None or not path.is_file():
        return []
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] in _SUBSYSTEM_MODE_TOKENS:
            line = parts[1].strip()
        if line:
            out.append(line)
    return out


def build_subsystem_pattern(subsystems: list[str]) -> re.Pattern[str] | None:
    """Compile a longest-first alternation over `subsystems`.

    Sorting longest-first ensures ``dom/media/webcodecs`` matches before
    ``dom/media`` when both are valid prefixes of an input path.
    """
    if not subsystems:
        return None
    parts = sorted({s for s in subsystems if s}, key=len, reverse=True)
    return re.compile("|".join(re.escape(p) for p in parts))


def _clean_primary_value(value: str) -> str:
    value = _BRACKET_RE.sub("", value)
    value = _PAREN_RE.sub("", value)
    return value.strip()


def _looks_like_subsystem(value: str) -> bool:
    """Heuristic: accept path-like strings, reject build-system references.

    Two structural rules — both project-agnostic:

    * No ``:`` anywhere in the value. POSIX paths don't use ``:`` as a
      separator, so a colon almost always indicates either a build-
      manifest reference (``Package.swift:target:15``,
      ``Cargo.toml:bin:foo``, ``CMakeLists.txt:lib:42``) or a
      ``file:line`` marker (``foo.cpp:42``) — neither of which is a
      subsystem.
    * No internal whitespace. Paths don't have spaces; prose does
      (``investigating multiple files``).

    Single-token dirs (``src``, ``rust``) and arbitrary path-like
    strings (``weird/path/no-match``) still pass — the goal is to keep
    flat-layout repos and unfamiliar trees working without an allowlist.
    Debugging tip: if a subsystem disappears unexpectedly, dump the
    rejected literal and check it against the two rules above.
    """
    if not value:
        return False
    if ":" in value:
        return False
    if any(ch.isspace() for ch in value):
        return False
    return True


def _read_primary_subsystem(lines: list[str]) -> str:
    for line in lines:
        m = _PRIMARY_RE.match(line)
        if m:
            value = _clean_primary_value(m.group(1))
            if _looks_like_subsystem(value):
                return value
            return ""
    return ""


def _iter_table_rows(lines: list[str], heading_prefix: str):
    """Yield stripped cells of each markdown-table row under `heading_prefix`.

    Stops at the next ``## `` heading. Header and separator rows are
    yielded too — callers filter them out by content.
    """
    in_section = False
    for line in lines:
        if not in_section:
            if line.startswith(heading_prefix):
                in_section = True
            continue
        if line.startswith("## "):
            return
        stripped = line.lstrip()
        if not stripped.startswith("|"):
            continue
        # Strip leading/trailing pipes then split. `| a | b |` -> ['a', 'b'].
        cells = [c.strip() for c in stripped.strip().strip("|").split("|")]
        yield cells


def _hypothesis_files(lines: list[str]) -> list[str]:
    """Files claimed by non-DISCARDED hypothesis-queue rows, in order."""
    out: list[str] = []
    for cells in _iter_table_rows(lines, "## Current Hypothesis Queue"):
        # Hypothesis Queue: | # | Hypothesis | File:F:L | Input | Guard |
        #                   Diagnostic | Strategy | Status |
        if len(cells) < 8:
            continue
        file_col = cells[2]
        status = cells[7]
        if file_col in ("", "File:Function:Line"):
            continue
        # Skip the markdown separator row, which becomes all dashes after split.
        if set(file_col) <= {"-"}:
            continue
        if status in ("", "Status") or status == "DISCARDED":
            continue
        out.append(file_col)
    return out


def _coverage_subsystems(lines: list[str]) -> list[str]:
    """Subsystem cells from Entry Point Coverage rows that aren't archived."""
    out: list[str] = []
    for cells in _iter_table_rows(lines, "## Entry Point Coverage"):
        # Entry Point Coverage: | Subsystem | Found | Examined | Remaining | Notes |
        if len(cells) < 5:
            continue
        subsystem = cells[0]
        notes = cells[4]
        if subsystem in ("", "Subsystem"):
            continue
        if set(subsystem) <= {"-"}:
            continue
        if _ARCHIVED_NOTES_RE.search(notes):
            continue
        out.append(subsystem)
    return out


def _first_pattern_match(text: str, pattern: re.Pattern[str] | None) -> str:
    if pattern is None:
        return ""
    m = pattern.search(text)
    return m.group(0) if m else ""


def extract_subsystem(
    state_file: Path,
    *,
    subsystems: list[str] | None = None,
) -> str:
    """Return the best subsystem candidate for a state file, or "unknown".

    `subsystems` is the known-prefix list (browser targets). When empty
    or None, generic-target semantics apply: the literal Primary
    Subsystem value is returned if present, else "unknown".
    """
    if not state_file.is_file():
        return "unknown"

    text = state_file.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    pattern = build_subsystem_pattern(subsystems or [])

    primary = _read_primary_subsystem(lines)

    # Generic target: accept the literal Primary Subsystem value as-is.
    if pattern is None:
        return primary or "unknown"

    # Browser target: every candidate must match the known-prefix regex.
    if primary:
        match = _first_pattern_match(primary, pattern)
        if match:
            return match

    for f in _hypothesis_files(lines):
        match = _first_pattern_match(f, pattern)
        if match:
            return match

    for s in _coverage_subsystems(lines):
        match = _first_pattern_match(s, pattern)
        if match:
            return match

    # Last resort: any known subsystem mention anywhere in the file.
    match = _first_pattern_match(text, pattern)
    return match or "unknown"


def subsystem_from_path(path: str, *, subsystems: list[str] | None = None) -> str:
    """Map a single file path to its subsystem.

    Browser semantics (subsystems list non-empty): regex-match the path
    against known prefixes, longest-first.

    Generic semantics (no list): use the first one or two path
    components. ``a/b/c.cpp`` -> ``a/b``; ``foo`` -> ``foo``.

    Absolute paths leak host-local prefixes into the subsystem ID.
    Callers should always pass a path relative to the target root; if
    we get an absolute path, we return "" so the caller falls back to
    "unknown" instead of bucketing agents under machine-specific paths.
    """
    if not path:
        return ""
    # Reject absolute paths; the leading "/" makes ``split("/")`` emit
    # an empty first segment. Anything that starts with "/" is unfit
    # for subsystem attribution.
    if path.startswith("/"):
        return ""

    pattern = build_subsystem_pattern(subsystems or [])
    if pattern is not None:
        return _first_pattern_match(path, pattern)

    parts = [p for p in path.split("/") if p]
    if not parts:
        return ""
    if len(parts) >= 2:
        return f"{parts[0]}/{parts[1]}"
    return parts[0]


def _add_subsystems_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--subsystems",
        type=Path,
        default=None,
        help="Path to a subsystems.txt file (one prefix per line). "
        "When omitted, generic-target semantics apply.",
    )


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_state = sub.add_parser(
        "subsystem",
        help="Extract the focus subsystem from a markdown state file.",
    )
    p_state.add_argument("state_file", type=Path)
    _add_subsystems_arg(p_state)

    p_path = sub.add_parser(
        "subsystem-from-path",
        help="Map a single file path to its subsystem.",
    )
    p_path.add_argument("path")
    _add_subsystems_arg(p_path)

    args = parser.parse_args(argv)

    subsystems = load_subsystems(args.subsystems) if args.subsystems else []

    if args.cmd == "subsystem":
        print(extract_subsystem(args.state_file, subsystems=subsystems))
        return 0

    if args.cmd == "subsystem-from-path":
        result = subsystem_from_path(args.path, subsystems=subsystems)
        if result:
            print(result)
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
