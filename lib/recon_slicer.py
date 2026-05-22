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
  1. Build *directory-coherent units*: descend the directory tree, emitting
     a subtree as one unit once its total LOC drops below the per-slice
     target. Directories are the project author's own functional
     decomposition — a far stronger signal than filenames.
  2. Pack/split units into exactly N slices, balanced by **lines of code**,
     not file count. LOC balancing is what keeps one agent from drawing
     every 10k-line monster file (the libxml2 failure mode) while a peer
     draws forty stubs.
  3. Flat trees (every file in one directory, e.g. libxml2) have no
     directory structure to exploit. There is no cheap static signal that
     recovers semantic boundaries from filenames, so the fallback is an
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

FUTURE OPTION (documented, not built): true call-graph coherence would come
from clustering files by their #include / call edges rather than directory
layout — connected components over the include graph. That is the only
method that delivers coherent slices on a flat tree. It is deliberately not
implemented: for small targets the partition axis is yield-noise (the whole
tree is covered in one wave regardless), so it should be built only if
recon instrumentation shows coherence-related misses justify the cost.
"""

from __future__ import annotations

import argparse
import random
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import languages  # noqa: E402

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


def collect_source_files(root: Path) -> list[Path]:
    """All auditable source files under root, modulo SKIP_DIR_NAMES."""
    out: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix not in SOURCE_EXTS:
            continue
        rel_parts = path.relative_to(root).parts
        if any(_is_skipped_dir(part) for part in rel_parts[:-1]):
            continue
        out.append(path)
    out.sort()
    return out


def changed_source_files(target_path: Path, root: Path, ref: str) -> list[Path]:
    """Source files changed in ref..HEAD, intersected with the in-scope
    source tree under root. Deleted files are dropped (they no longer
    exist to audit). Returns [] if git is unavailable or ref is unknown."""
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
    in_scope = set(collect_source_files(root))
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


def _label(parts: tuple[str, ...]) -> str:
    return "/".join(parts) if parts else "root"


def build_units(src_root: Path, files: list[Path], locs: dict[Path, int],
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


def main(argv: list[str]) -> int:
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
        files = collect_source_files(src_root)
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
