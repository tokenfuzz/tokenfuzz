#!/usr/bin/env python3
"""recon_slicer.py — Partition a target's source files into N non-overlapping
slices for breadth-first audit recon.

Partitioning is **structural**, not lexical. The previous version of this
file grouped root-level source files by a hand-maintained filename-prefix
regex table (NAME_PREFIX_GROUPS) plus a per-project prefix sniffer. That
approach was deleted: filename is a poor proxy for "what calls what", the
regex table rotted as an enumeration, and unmatched files collapsed into a
single `misc` bucket that `rebalance` then split on alphabetical halves.
What survived for the agent was only a cosmetic slice label — the agent
prompt receives a file list, never the label — so the regex bought a
rot-prone enumeration for prettier log lines.

The current algorithm:
  1. Build *dependency-coherent units*: connect files that directly depend
     on each other via target-local quoted includes/imports and uniquely
     resolved function calls, then take connected components. This recovers
     coherence on flat trees where directories cannot help (every file in
     one directory, yet heavily cross-including, e.g. libxml2). Edges are
     deliberately conservative — only unambiguous, in-scope references — so
     a noisy guess is never treated as anything but a context-packing hint.
  2. Build *directory-coherent units* for the files left unconnected:
     descend the directory tree, emitting a subtree as one unit once its
     total LOC drops below the per-slice target. Directories are the project
     author's own functional decomposition — a far stronger signal than
     filenames.
  3. Pack/split units into exactly N slices, balanced by **lines of code**,
     not file count. LOC balancing is what keeps one agent from drawing
     every 10k-line monster file (the libxml2 failure mode) while a peer
     draws forty stubs.
  4. Whatever still has no structure to exploit falls back to an
     explicitly-arbitrary LOC-balanced contiguous chunking. It is balanced
     and deterministic; it does not pretend to be semantic.

Scope selection:
  - default: every source file under the detected source root.
  - --path SUBDIR: restrict to one subtree (recursively partitioned the
    same way) — for auditing a specific subsystem on a large tree.
  - --changed-since REF: only files changed in REF..HEAD (git) — the
    bounded change-driven scope that keeps recon cost proportional to
    churn rather than codebase size.

Output: one file per slice in --out-dir, named slice-N-<short-label>.txt,
with one absolute path per line.

Guarantees audit relies on:
  - Every in-scope source file appears in exactly one slice.
  - The slice count is the requested N, or fewer when there is not enough
    material to split further (better to under-shard than spread thin).
  - Exit code 7 (not an error) means --changed-since matched no source
    files; callers treat this as "nothing to recon", not a failure.

Dependency units are best-effort context packing only. They do not change
what counts as a vulnerability and they are always subordinate to the
non-overlap and LOC-balance guarantees.
"""

from __future__ import annotations

import argparse
import functools
import random
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import languages  # noqa: E402
import target_config  # noqa: E402

# Single source of truth: the language registry. Covers C/C++/Rust/Go/
# Python/Java plus TS/JS/Kotlin/Swift/PHP/Ruby/Perl so recon for non-C
# targets is not silently zero-counted.
SOURCE_EXTS = languages.all_source_exts()

# Top-level dirs we always skip — generated code, vendored, build, tests.
SKIP_DIR_NAMES = {
    "build", "build-coverage",
    "tests", "test", "testing", "doc", "docs",
    "examples", "example", "fuzz", "fuzzing", "third_party", "thirdparty",
    "vendor", "vendored", "deps", "node_modules", ".git", ".hg",
    "__pycache__", "target", "dist", ".github",
}

# Sanitizer build trees are skipped by prefix so AUDIT_BUILD_SUFFIX
# variants (build-asan-<image-id>, etc. produced inside a container)
# are also excluded.
SKIP_DIR_PREFIXES = ("build-asan", "build-ubsan", "build-msan", "build-tsan")

# Exit code for "--changed-since matched no source files". Distinct from
# the hard-error codes so callers can treat a quiet change window as a
# clean no-op rather than a failure.
EXIT_EMPTY_CHANGED_SET = 7

# Dependency-edge signals. Per-language function-definition and local-include
# detectors live in the language registry (languages.Language.def_patterns /
# include_patterns), so coverage is a property of the supported-language set,
# not of this file — adding a language widens recon slicing automatically.
# Edges are conservative: an include only connects when it resolves to an
# in-scope file, and a call only connects when its name is defined in exactly
# one in-scope file. A wrong match merely co-locates two files in one slice;
# it never affects what counts as a finding.
#
# Call sites are language-agnostic (a bare `name(`), so one universal token
# matcher feeds every language's definitions.
CALL_TOKEN_RE = re.compile(r"\b(?P<name>[A-Za-z_]\w*)\s*\(")
# Keywords that look like calls/definitions but are control flow.
NON_CALL_NAMES = {
    "if", "for", "while", "switch", "return", "sizeof", "catch",
    "assert", "static_assert", "new", "delete",
}

# The one deliberate cross-language edge that does not fit the per-file
# def/include model: a Python `import <mod>` that resolves to the C/C++ file
# defining that CPython extension module's initializer (PyInit_<mod>). Kept
# here, isolated and documented, rather than forced into the registry.
PY_IMPORT_RE = re.compile(
    r"""
    ^\s*
    (?:
      import\s+(?P<imports>[A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)
      |
      from\s+(?P<from>[A-Za-z_]\w*)\s+import\s+
    )
    """,
    re.M | re.VERBOSE,
)
PY_CAPI_INIT_RE = re.compile(r"\bPyMODINIT_FUNC\s+PyInit_(?P<name>[A-Za-z_]\w*)\s*\(")


@functools.lru_cache(maxsize=None)
def _dependency_patterns(ext: str) -> tuple[tuple[re.Pattern[str], ...],
                                            tuple[re.Pattern[str], ...]]:
    """Compiled (def_patterns, include_patterns) for a source extension.

    Sourced from the language registry and cached per extension. Returns
    empty tuples for extensions with no language or no declared patterns."""
    lang = languages.for_source_ext(ext)
    if lang is None:
        return ((), ())
    defs = tuple(re.compile(p) for p in lang.def_patterns)
    incs = tuple(re.compile(p) for p in lang.include_patterns)
    return (defs, incs)


def _is_skipped_dir(name: str) -> bool:
    return name in SKIP_DIR_NAMES or name.startswith(SKIP_DIR_PREFIXES)


def find_source_root(target_path: Path) -> Path:
    """Best-effort detection of the primary source root for a target."""
    candidates = [
        target_path / "src" / "lib",
        target_path / "src",
        target_path / "lib",
        target_path,
    ]
    for c in candidates:
        if c.is_dir():
            # Has at least one .c/.cc/.cpp file directly?
            for entry in c.iterdir():
                if entry.is_file() and entry.suffix in {".c", ".cc", ".cpp"}:
                    return c
            # Look one level deeper for source files
            for entry in c.iterdir():
                if entry.is_dir() and not _is_skipped_dir(entry.name):
                    for inner in entry.iterdir():
                        if inner.is_file() and inner.suffix in {".c", ".cc", ".cpp"}:
                            return c
    return target_path


def collect_source_files(root: Path, checkout_root: Path | None = None) -> list[Path]:
    """All auditable source files under root, modulo SKIP_DIR_NAMES and — when
    the target is a git/hg checkout — untracked scratch files (agent PoCs,
    prior-run leftovers).

    root is the subtree being sliced; find_source_root often descends into
    src/, which has no .git of its own. checkout_root is the target directory
    that owns the VCS metadata — the tracked set and membership test are keyed
    to it, since asking vcs_tracked_files about a bare src/ would return None
    and silently disable the filter. It defaults to root for a whole-tree
    slice. None from vcs_tracked_files (non-VCS tree / probe failure) means no
    filter, so a plain-tarball target still slices its whole source."""
    base = checkout_root or root
    tracked = target_config.vcs_tracked_files(base)
    out: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in SOURCE_EXTS:
            continue
        if any(_is_skipped_dir(part) for part in path.relative_to(root).parts[:-1]):
            continue
        if tracked is not None and path.relative_to(base).as_posix() not in tracked:
            continue
        out.append(path)
    out.sort()
    return out


def changed_source_files(target_path: Path, root: Path, ref: str) -> list[Path]:
    """Source files changed in ref..HEAD, intersected with the in-scope
    source tree under root. Deleted files are dropped (they no longer
    exist to audit). Returns [] if git is unavailable or ref is unknown."""
    if target_config.detect_repo_type(target_path) != "git":
        return []
    try:
        repo_root = subprocess.run(
            ["git", "-C", str(target_path), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return []
    if not repo_root:
        return []
    try:
        diff = subprocess.run(
            ["git", "-C", repo_root, "diff", "--name-only", f"{ref}..HEAD"],
            capture_output=True, text=True, check=True,
        ).stdout
    except subprocess.CalledProcessError:
        return []
    repo = Path(repo_root)
    in_scope = set(collect_source_files(root, target_path))
    out: list[Path] = []
    seen: set[Path] = set()
    for rel in diff.splitlines():
        rel = rel.strip()
        if not rel:
            continue
        abspath = (repo / rel).resolve()
        if abspath in in_scope and abspath not in seen:
            seen.add(abspath)
            out.append(abspath)
    out.sort()
    return out


def file_loc(path: Path) -> int:
    """Line count of a file. Unreadable or empty files weigh 1 so they are
    still distributed across slices rather than piling up in one."""
    try:
        with path.open("rb") as fh:
            data = fh.read()
    except OSError:
        return 1
    if not data:
        return 1
    n = data.count(b"\n")
    if not data.endswith(b"\n"):
        n += 1
    return max(1, n)


def _read_text(path: Path, limit: int = 1_000_000) -> str:
    """Bounded source read for dependency hints."""
    try:
        data = path.read_bytes()[:limit]
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


def _local_include_target(src_root: Path, source: Path, include: str,
                          by_rel: dict[str, Path]) -> Path | None:
    """Resolve a quoted include/require to an in-scope file, or None.

    Tries the including file's directory first, then the source root.
    Absolute and out-of-tree paths are ignored."""
    if not include or include.startswith("/"):
        return None
    resolved_root = src_root.resolve()
    for candidate in ((source.parent / include).resolve(),
                      (resolved_root / include).resolve()):
        try:
            rel = candidate.relative_to(resolved_root).as_posix()
        except ValueError:
            continue
        if rel in by_rel:
            return by_rel[rel]
    return None


def _defined_names(text: str,
                   def_patterns: tuple[re.Pattern[str], ...]) -> set[str]:
    """Function/method names defined in this file, per its language's
    registry def_patterns."""
    names: set[str] = set()
    for rx in def_patterns:
        for match in rx.finditer(text):
            name = match.group("name")
            if name and name not in NON_CALL_NAMES:
                names.add(name)
    return names


def _included_paths(text: str,
                    include_patterns: tuple[re.Pattern[str], ...]) -> list[str]:
    """Local include/require targets named in this file, per its language's
    registry include_patterns. An optional `dir` group (e.g. PHP `__DIR__`)
    that prefixes an otherwise-absolute-looking path marks it relative."""
    out: list[str] = []
    for rx in include_patterns:
        for match in rx.finditer(text):
            path = match.group("path")
            if not path:
                continue
            if match.groupdict().get("dir") and path.startswith(("/", "\\")):
                path = path[1:]
            out.append(path)
    return out


def _called_names(text: str) -> set[str]:
    """Names invoked like a call in this file."""
    return {
        match.group("name")
        for match in CALL_TOKEN_RE.finditer(text)
        if match.group("name") not in NON_CALL_NAMES
    }


def _python_imported_modules(text: str) -> set[str]:
    """Top-level module names this Python file imports."""
    modules: set[str] = set()
    for match in PY_IMPORT_RE.finditer(text):
        if match.group("from"):
            modules.add(match.group("from"))
        for raw in (match.group("imports") or "").split(","):
            name = raw.strip()
            if name:
                modules.add(name)
    return modules


def _python_capi_modules(text: str) -> set[str]:
    """CPython extension module names this file defines (PyInit_<name>)."""
    return {match.group("name") for match in PY_CAPI_INIT_RE.finditer(text)}


def build_dependency_units(src_root: Path,
                           files: list[Path]) -> list[tuple[str, list[Path]]]:
    """Return conservative include/call-connected file units.

    Edges (each only created when it resolves unambiguously and in-scope):
      * local includes/requires that resolve to another in-scope file
        (per each language's registry include_patterns: C/C++ quoted
        `#include`, PHP require/include of target-local string paths);
      * calls to a function/method name defined in exactly one in-scope
        file of the same call-family (definitions come from each language's
        registry def_patterns, so every supported language contributes call
        edges; C/C++, JS/TS and Java/Kotlin are each one family, every other
        language its own, so a coincidental cross-runtime name match does
        not merge unrelated files);
      * Python imports that resolve to exactly one in-scope CPython
        extension module initializer (PyInit_<module>) — the one
        cross-language edge handled outside the registry.

    Angle-bracket/system includes and ambiguous (multiply-defined) names are
    ignored on purpose. The result is only a recon context-packing hint:
    files in the same connected component (size >= 2) become one unit.
    """
    if len(files) < 2:
        return []
    resolved_root = src_root.resolve()
    file_set = set(files)
    by_rel: dict[str, Path] = {}
    for f in files:
        try:
            by_rel[f.resolve().relative_to(resolved_root).as_posix()] = f
        except ValueError:
            # A symlink (or junction) that resolves outside the tree is not
            # an include-resolvable target. Skip it as a target here — it
            # still participates via call edges and the final partition —
            # rather than letting relative_to() abort the whole slicer.
            continue
    texts = {f: _read_text(f) for f in files}
    # Call-edge family per file. A bare-name call only unions to a unique
    # definition when both files share a family (C/C++, JS/TS, Java/Kotlin,
    # or the same single language). This is the mixed-language guard:
    # cross-runtime name collisions (a Python `decode(` vs a C `decode`)
    # never merge, while genuine intra-family cross-language calls still do.
    # Cross-family bindings are modeled explicitly (Python import -> PyInit).
    file_family = {f: languages.call_family_for_ext(f.suffix.lower()) for f in files}

    # A function name is an edge source only when it is defined in exactly
    # one in-scope file *of its call-family*. Keying uniqueness by
    # (family, name) does two things at once: it scopes uniqueness so an
    # unrelated cross-runtime duplicate (a Python `decode` vs a C `decode`)
    # cannot erase a valid same-family edge, and it makes the call lookup
    # below inherently same-family (a caller only finds a definition under
    # its own family key).
    defs: dict[tuple[str, str], set[Path]] = defaultdict(set)
    for f, text in texts.items():
        family = file_family.get(f)
        if family is None:
            continue
        def_patterns, _ = _dependency_patterns(f.suffix.lower())
        for name in _defined_names(text, def_patterns):
            defs[(family, name)].add(f)
    unique_defs = {key: next(iter(paths))
                   for key, paths in defs.items() if len(paths) == 1}

    capi_defs: dict[str, set[Path]] = defaultdict(set)
    for f, text in texts.items():
        for module in _python_capi_modules(text):
            capi_defs[module].add(f)
    unique_capi_defs = {module: next(iter(paths))
                        for module, paths in capi_defs.items()
                        if len(paths) == 1}

    parent: dict[Path, Path] = {f: f for f in files}

    def find(x: Path) -> Path:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: Path, b: Path) -> None:
        if a not in file_set or b not in file_set or a == b:
            return
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for f, text in texts.items():
        _, include_patterns = _dependency_patterns(f.suffix.lower())
        for include_path in _included_paths(text, include_patterns):
            target = _local_include_target(src_root, f, include_path, by_rel)
            if target:
                union(f, target)
        if f.suffix == ".py":
            for module in _python_imported_modules(text):
                target = unique_capi_defs.get(module)
                if target:
                    union(f, target)
        caller_family = file_family.get(f)
        if caller_family is not None:
            for name in _called_names(text):
                target = unique_defs.get((caller_family, name))
                if target is not None:
                    union(f, target)

    components: dict[Path, list[Path]] = defaultdict(list)
    for f in files:
        components[find(f)].append(f)
    units: list[tuple[str, list[Path]]] = []
    for fs in components.values():
        if len(fs) < 2:
            continue
        fs = sorted(fs, key=str)
        stems = sorted({f.stem for f in fs})
        label = "dep:" + "+".join(stems[:3])
        if len(stems) > 3:
            label += f"+{len(stems) - 3}more"
        units.append((label, fs))
    units.sort(key=lambda u: (u[0], [str(f) for f in u[1]]))
    return units


def _label(parts: tuple[str, ...]) -> str:
    return "/".join(parts) if parts else "root"


def build_directory_units(src_root: Path, files: list[Path], locs: dict[Path, int],
                          target_loc: int) -> list[tuple[str, list[Path]]]:
    """Descend the directory tree, emitting each subtree as one unit once
    its total LOC drops to target_loc or below (or it has no subdirectories
    left to descend into). Files lying directly in an over-target directory
    form their own `:files` unit so they are never merged with a child
    subtree's contents."""

    def rec(prefix: tuple[str, ...], flist: list[Path]) -> list[tuple[str, list[Path]]]:
        loc = sum(locs[f] for f in flist)
        depth = len(prefix)
        direct: list[Path] = []
        by_child: dict[str, list[Path]] = defaultdict(list)
        for f in flist:
            rel = f.relative_to(src_root).parts
            if len(rel) == depth + 1:
                direct.append(f)
            else:
                by_child[rel[depth]].append(f)
        if loc <= target_loc or not by_child:
            return [(_label(prefix), flist)]
        units: list[tuple[str, list[Path]]] = []
        for child in sorted(by_child):
            units += rec(prefix + (child,), by_child[child])
        if direct:
            units.append((_label(prefix) + ":files", direct))
        return units

    return rec((), files)


def build_units(src_root: Path, files: list[Path], locs: dict[Path, int],
                target_loc: int) -> list[tuple[str, list[Path]]]:
    """Dependency-coherent units first, then directory units for the files
    left unconnected. Every in-scope file lands in exactly one unit."""
    dep_units = build_dependency_units(src_root, files)
    dep_files = {f for _, fs in dep_units for f in fs}
    remaining = [f for f in files if f not in dep_files]
    units = list(dep_units)
    if remaining:
        units.extend(build_directory_units(src_root, remaining, locs, target_loc))
    return units


def _loc_split(files: list[Path], locs: dict[Path, int]) -> tuple[list[Path], list[Path]]:
    """Split a file list into two contiguous (path-sorted) halves of roughly
    equal LOC. Path-sorted so name-adjacent files stay together."""
    fs = sorted(files, key=str)
    if len(fs) < 2:
        return fs, []
    half = sum(locs[f] for f in fs) / 2.0
    cum = 0
    for i, f in enumerate(fs[:-1]):
        cum += locs[f]
        if cum >= half:
            return fs[: i + 1], fs[i + 1:]
    return fs[:-1], fs[-1:]


def _loc_chunks(files: list[Path], locs: dict[Path, int], n: int) -> list[list[Path]]:
    """Cut a file list into <=n contiguous chunks of roughly equal LOC."""
    if n <= 1 or len(files) <= 1:
        return [files] if files else []
    total = sum(locs[f] for f in files)
    chunks: list[list[Path]] = []
    cur: list[Path] = []
    cum = 0
    emitted = 0
    for idx, f in enumerate(files):
        cur.append(f)
        cum += locs[f]
        remaining_files = len(files) - idx - 1
        remaining_slots = n - emitted - 1
        # Cut when this chunk has reached its proportional LOC share, but
        # always leave at least one file per remaining slot.
        target = total * (emitted + 1) / n
        if remaining_slots > 0 and cum >= target and remaining_files >= remaining_slots:
            chunks.append(cur)
            cur = []
            emitted += 1
    if cur:
        chunks.append(cur)
    return chunks


def _pack(units: list[tuple[str, list[Path]]], locs: dict[Path, int],
          n: int) -> list[tuple[str, list[Path]]]:
    """Longest-processing-time bin-packing: assign each unit (largest LOC
    first) to the currently-lightest slice. Keeps each directory unit whole
    so slice coherence is preserved."""
    ordered = sorted(units, key=lambda u: (-sum(locs[f] for f in u[1]), u[0]))
    bins: list[dict] = [{"loc": 0, "labels": [], "files": []} for _ in range(n)]
    for lbl, fs in ordered:
        b = min(bins, key=lambda x: (x["loc"], len(x["files"])))
        b["loc"] += sum(locs[f] for f in fs)
        b["labels"].append(lbl)
        b["files"].extend(fs)
    out: list[tuple[str, list[Path]]] = []
    for b in bins:
        if not b["files"]:
            continue
        label = "+".join(b["labels"][:3])
        if len(b["labels"]) > 3:
            label += f"+{len(b['labels']) - 3}more"
        out.append((label, sorted(b["files"], key=str)))
    return out


def _split_to_n(units: list[tuple[str, list[Path]]], locs: dict[Path, int],
                n: int) -> list[tuple[str, list[Path]]]:
    """Split the largest unit (by LOC) repeatedly until we reach n units or
    no unit can be split further."""
    units = list(units)
    while len(units) < n:
        units.sort(key=lambda u: -sum(locs[f] for f in u[1]))
        lbl, fs = units[0]
        if len(fs) < 2:
            break
        a, b = _loc_split(fs, locs)
        if not a or not b:
            break
        units = units[1:] + [(f"{lbl}-a", a), (f"{lbl}-b", b)]
    return units


def partition(src_root: Path, files: list[Path], n: int,
              seed: int) -> list[tuple[str, list[Path]]]:
    """Partition `files` into <=n LOC-balanced, non-overlapping slices."""
    if not files:
        return []
    locs = {f: file_loc(f) for f in files}
    n = max(1, n)

    if seed > 0:
        # Re-roll partition: shuffle, then LOC-balanced contiguous chunks.
        # Ignores directory structure on purpose so a re-roll produces a
        # structurally different (but still non-overlapping) partition.
        shuffled = list(files)
        random.Random(seed).shuffle(shuffled)
        chunks = _loc_chunks(shuffled, locs, n)
        return [(f"reroll{seed}-slot{i + 1}", c) for i, c in enumerate(chunks)]

    total = sum(locs.values()) or 1
    # Descend until a subtree is at or below the per-slice LOC target. Units
    # somewhat smaller than total/n give the packer room to balance.
    target_loc = max(1, total // n)
    units = [(lbl, fs) for lbl, fs in build_units(src_root, files, locs, target_loc) if fs]
    if not units:
        return []

    # LOC rebalancing: break up any unit far larger than a fair slice share
    # so the packer can distribute its weight. Without this, a single big
    # directory (or a flat tree's lone unit) would hand one agent a wildly
    # heavier slice than its peers. A unit stops splitting once it holds a
    # single file — one oversized file is genuinely indivisible.
    ceiling = max(1, int(total * 1.5 // n))
    guard = 0
    while guard < 10000:
        guard += 1
        units.sort(key=lambda u: -sum(locs[f] for f in u[1]))
        lbl, fs = units[0]
        if sum(locs[f] for f in fs) <= ceiling or len(fs) < 2:
            break
        a, b = _loc_split(fs, locs)
        if not a or not b:
            break
        units = units[1:] + [(f"{lbl}-a", a), (f"{lbl}-b", b)]

    if len(units) > n:
        return _pack(units, locs, n)
    if len(units) < n:
        units = _split_to_n(units, locs, n)
    return [(lbl, sorted(fs, key=str)) for lbl, fs in units if fs]


def write_slices(slices: list[tuple[str, list[Path]]], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for idx, (label, files) in enumerate(slices, start=1):
        safe_label = re.sub(r"[^A-Za-z0-9_+.-]", "_", label) or f"group-{idx}"
        # Keep slice filenames bounded — a deeply-merged label can get long.
        safe_label = safe_label[:60].strip("_-+.") or f"group-{idx}"
        out_file = out_dir / f"slice-{idx}-{safe_label}.txt"
        with out_file.open("w", encoding="utf-8") as f:
            for p in files:
                f.write(str(p) + "\n")
        print(f"slice-{idx} ({safe_label}): {len(files)} file(s) → {out_file}",
              file=sys.stderr)


def count_source_files(root: Path) -> int:
    count = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix.lower() not in SOURCE_EXTS:
            continue
        relative = path.relative_to(root).parts
        if any(part in SKIP_DIR_NAMES for part in relative[:-1]):
            continue
        count += 1
    return count


def main(argv: list[str]) -> int:
    if argv and argv[0] == "count-source-files":
        if len(argv) != 2:
            print("usage: recon_slicer.py count-source-files <dir>", file=sys.stderr)
            return 2
        root = Path(argv[1]).expanduser().resolve()
        if not root.is_dir():
            return 1
        print(count_source_files(root))
        return 0
    ap = argparse.ArgumentParser(
        description="Slice a target's source tree into N non-overlapping audit groups.")
    ap.add_argument("--target-path", required=True,
                    help="Target root (the directory under targets/)")
    ap.add_argument("--slices", type=int, default=4,
                    help="Maximum number of slices to produce")
    ap.add_argument("--out-dir", required=True,
                    help="Output directory for slice-N-*.txt files")
    ap.add_argument("--seed", type=int, default=0,
                    help="Re-roll seed. 0 = deterministic directory-coherent "
                         "partition. Values >= 1 shuffle the file list and "
                         "LOC-chunk it, producing a different but still "
                         "non-overlapping partition.")
    ap.add_argument("--path", default="",
                    help="Restrict scope to this subtree (relative to the "
                         "target root). The subtree is partitioned the same "
                         "way as a whole tree.")
    ap.add_argument("--changed-since", default="",
                    help="Restrict scope to source files changed in "
                         "<REF>..HEAD (git revision). Exit 7 if the change "
                         "set contains no in-scope source files.")
    args = ap.parse_args(argv)

    target_path = Path(args.target_path).expanduser().resolve()
    if not target_path.is_dir():
        print(f"FATAL: target path does not exist: {target_path}", file=sys.stderr)
        return 2

    src_root = find_source_root(target_path)

    if args.path:
        scoped = (src_root / args.path).resolve()
        try:
            scoped.relative_to(src_root)
        except ValueError:
            # --path may be given relative to the target root rather than
            # the detected source root; accept that too.
            scoped = (target_path / args.path).resolve()
        if not scoped.is_dir():
            print(f"FATAL: --path subtree does not exist: {scoped}", file=sys.stderr)
            return 2
        src_root = scoped
    print(f"Source root: {src_root}", file=sys.stderr)

    if args.changed_since:
        files = changed_source_files(target_path, src_root, args.changed_since)
        print(f"Changed-since {args.changed_since}: {len(files)} in-scope "
              f"source file(s)", file=sys.stderr)
        if not files:
            print("No in-scope source files changed; nothing to slice.",
                  file=sys.stderr)
            Path(args.out_dir).expanduser().resolve().mkdir(parents=True, exist_ok=True)
            return EXIT_EMPTY_CHANGED_SET
    else:
        files = collect_source_files(src_root, target_path)
        print(f"Found {len(files)} source file(s)", file=sys.stderr)
        if not files:
            print("FATAL: no source files found", file=sys.stderr)
            return 3

    slices = partition(src_root, files, max(1, args.slices), args.seed)
    if not slices:
        print("FATAL: partition produced no slices", file=sys.stderr)
        return 3
    write_slices(slices, Path(args.out_dir).expanduser().resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
