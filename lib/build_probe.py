#!/usr/bin/env python3
"""Build feature probe — target-agnostic detection of compiled-in TUs and
features for a sanitizer build.

Purpose: when an optional-feature build (e.g. `./configure` without
`--with-openssl`) leaves whole subsystems as empty stubs, the harness
must know so recon does not propose dead work cards and the work queue
gates them out. We probe the *existing* build artifacts — no second
build, no LLM call. Three signal sources, target-agnostic:

  1. Binary feature report — `<bin> --version`, `<bin> --help`. Most
     CLIs print enabled features; we capture verbatim text.
  2. Object-file symbol coverage — `nm --defined-only` on each `.o`
     under the build tree and on shipped static/shared libraries. A
     compilation unit whose only defined symbols are sanitizer runtime
     hooks (e.g. `asan.module_ctor`, `__asan_*`) is a stub: the source
     was `#if`-guarded out under the current configure flags.
  3. Configure summary — `Configuration summary:` / `-- Configuring
     done` blocks already emitted to the build log; if a build log is
     supplied we capture the trailing summary verbatim.

Output: structured JSON at the path supplied by `--output`. Schema
defined by `FEATURES_SCHEMA_VERSION`. Consumers (workqueue, prompt
templates) call `load_features()` and `is_tu_stub()`; both fail open —
a missing or malformed manifest never blocks bug-finding work.

Industry-wide vocabulary only (per docs/development.md): no curl/ffmpeg/openssl
identifiers appear in this file. The probe reads what the build
produced and reports it; classification logic is purely structural
(zero non-runtime symbols → stub).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

FEATURES_SCHEMA_VERSION = 1

# Sanitizer-runtime symbol prefixes. A TU whose nm --defined-only output
# contains ONLY these is the sanitizer's auto-inserted ctor/dtor stub
# (e.g. asan_globals registration) — the source TU contributed no real
# symbol because every translation-unit member was inside an `#if 0`
# block under the current configure flags. Industry-wide vocabulary,
# stable across LLVM/GCC sanitizer versions.
_SANITIZER_RUNTIME_PREFIXES: tuple[str, ...] = (
    "__asan_",
    "__ubsan_",
    "__msan_",
    "__tsan_",
    "__hwasan_",
    "__sanitizer_",
    "asan.module_",
    "ubsan.module_",
    "msan.module_",
    "tsan.module_",
    "__profc_",
    "__profd_",
    "__profvp_",
    "__llvm_",
    "_GLOBAL__sub_",
    "_GLOBAL__I_",
    "_GLOBAL__D_",
    ".str",
    ".L",
)

# nm output line shape: "<addr> <type> <symbol>" where type letters
# T/W/D/B/R/S (and lowercase variants) indicate defined symbols. We use
# nm --defined-only so the type-letter filter is a sanity check, not a
# load-bearing constraint.
_NM_LINE_RE = re.compile(r"^[0-9a-fA-F]*\s+([A-Za-z])\s+(.+)$")

# Configure-summary heading markers — recognised industry-wide (autoconf,
# cmake, meson all emit one of these). Prefix matches keep the list
# robust as new build systems appear.
_CONFIGURE_SUMMARY_MARKERS: tuple[str, ...] = (
    "Configuration summary",
    "Configure summary",
    "Configuration Options",
    "-- Configuring done",
    "Build configuration",
    "Build options",
    "Build Configuration",
    "The following features will be compiled",
    "Features:",
    "Protocols:",
    "Enabled:",
    "Disabled:",
)

# Cap the configure-summary excerpt so it does not bloat features.json
# or the recon prompt. 200 lines is generous — autotools summaries
# rarely exceed 80, cmake "Configuring done" exceeds 200 only on
# Frankenbuilds (project + 30 deps).
_CONFIGURE_SUMMARY_MAX_LINES = 200


@dataclass
class BinaryProbe:
    path: str = ""
    version_output: str = ""
    help_output: str = ""
    features: list[str] = field(default_factory=list)
    protocols: list[str] = field(default_factory=list)


@dataclass
class FeaturesManifest:
    schema_version: int = FEATURES_SCHEMA_VERSION
    probed_at: str = ""
    target_root: str = ""
    build_dir: str = ""
    sanitizer: str = ""
    binary: BinaryProbe = field(default_factory=BinaryProbe)
    configure_summary: str = ""
    stub_tus: list[str] = field(default_factory=list)
    compiled_tus: list[str] = field(default_factory=list)
    probed_object_count: int = 0
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "probed_at": self.probed_at,
            "target_root": self.target_root,
            "build_dir": self.build_dir,
            "sanitizer": self.sanitizer,
            "binary": {
                "path": self.binary.path,
                "version_output": self.binary.version_output,
                "help_output": self.binary.help_output,
                "features": list(self.binary.features),
                "protocols": list(self.binary.protocols),
            },
            "configure_summary": self.configure_summary,
            "stub_tus": list(self.stub_tus),
            "compiled_tus": list(self.compiled_tus),
            "probed_object_count": self.probed_object_count,
            "notes": list(self.notes),
        }


# ─── Binary probe ──────────────────────────────────────────────────


def _run_capture(cmd: list[str], timeout: float = 8.0) -> str:
    """Run a binary with a short timeout, return combined stdout/stderr.

    Fail-open: any error returns ''. The probe is best-effort; failures
    here never block the rest of the run.
    """
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        # Trim absurd outputs so a misbehaving --help (e.g. a paginated
        # man-page dump) cannot bloat features.json.
        text = result.stdout.decode("utf-8", errors="replace")
        return text[:64 * 1024]
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired, OSError):
        return ""


def _parse_features_line(text: str, label: str) -> list[str]:
    """Extract whitespace-separated tokens following a `<label>:` line.

    Many CLIs (curl, ffmpeg, openssl, sqlite, libxml2) print one or more
    summary lines of the form `Features: a b c` or `Protocols: x y z`.
    We grep for the label case-insensitively at line start; tokens on
    the rest of the line become the list.
    """
    out: list[str] = []
    pattern = re.compile(rf"^\s*{re.escape(label)}\s*:\s*(.+)$", re.IGNORECASE | re.MULTILINE)
    for m in pattern.finditer(text):
        for tok in m.group(1).split():
            tok = tok.strip(",;|")
            if tok:
                out.append(tok)
    # Dedup while preserving order.
    seen: set[str] = set()
    deduped: list[str] = []
    for t in out:
        key = t.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(t)
    return deduped


def probe_binary(binary_path: Path) -> BinaryProbe:
    bp = BinaryProbe(path=str(binary_path))
    if not binary_path or not binary_path.exists():
        return bp
    if not os.access(binary_path, os.X_OK):
        return bp
    bp.version_output = _run_capture([str(binary_path), "--version"])
    # --help is captured only when --version did not already cover it.
    # Keep total captured text bounded.
    if len(bp.version_output) < 4096:
        bp.help_output = _run_capture([str(binary_path), "--help"])
    combined = f"{bp.version_output}\n{bp.help_output}"
    bp.features = _parse_features_line(combined, "Features")
    bp.protocols = _parse_features_line(combined, "Protocols")
    return bp


# ─── Symbol probe ──────────────────────────────────────────────────


def _is_sanitizer_runtime_symbol(name: str) -> bool:
    if not name:
        return True
    for prefix in _SANITIZER_RUNTIME_PREFIXES:
        if name.startswith(prefix):
            return True
    return False


def _nm_defined_symbols(path: Path) -> tuple[list[str], bool]:
    """Run `nm --defined-only` on a file; return (global_symbols, ran_ok).

    Returns only EXTERNAL (uppercase-type-letter) defined symbols.
    Local symbols (lowercase t/d/b/r/s/n) are assembler/DWARF
    scaffolding — `ltmp0`, `Lfunc_begin0`, `_.str.1`, etc. — and do not
    represent code or data the TU exports. Filtering them out is what
    makes stub detection reliable across macOS/Linux/BSD nm variants.

    ran_ok=False means nm was unavailable or errored. Callers must treat
    that as "no signal" and not classify the TU as stub.
    """
    nm = shutil.which("nm")
    if not nm:
        return ([], False)
    # `--defined-only` exists on GNU nm and llvm-nm (the macOS default
    # since recent Xcode); BSD nm uses the same flag spelling. If a
    # very old BSD nm doesn't recognise it, the run errors and we fail
    # open via the returncode check below.
    try:
        result = subprocess.run(
            [nm, "--defined-only", str(path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10.0,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return ([], False)
    if result.returncode != 0:
        # nm errors on non-object files (scripts, archives with no
        # members, etc.). Treat as "no signal".
        return ([], False)
    syms: list[str] = []
    for line in result.stdout.decode("utf-8", errors="replace").splitlines():
        m = _NM_LINE_RE.match(line)
        if not m:
            continue
        type_letter = m.group(1)
        # Uppercase = global/external. Stub detection cares only about
        # what the TU exposes to other TUs at link time.
        if not type_letter.isupper():
            continue
        syms.append(m.group(2).strip())
    return (syms, True)


def _classify_object(path: Path) -> str:
    """Return 'stub', 'real', or 'unknown' for a single .o.

    Stub: every defined symbol matches a sanitizer-runtime prefix.
    Real: at least one defined symbol is a non-runtime symbol.
    Unknown: nm failed or returned no signal — DO NOT classify as stub
             (fail-open keeps real TUs in the queue).
    """
    syms, ran_ok = _nm_defined_symbols(path)
    if not ran_ok:
        return "unknown"
    if not syms:
        # Empty defined-symbol set is ambiguous: could be a header-only
        # TU compiled for its side effects, or a TU whose contents were
        # all inlined. Treat as unknown rather than stub.
        return "unknown"
    if all(_is_sanitizer_runtime_symbol(s) for s in syms):
        return "stub"
    return "real"


def _disambiguate_by_location(
    obj_path: Path, candidates: list[Path], target_root: Path
) -> Path | None:
    """Choose the candidate source whose directory chain best matches the
    object's own location.

    Build systems (CMake, autotools VPATH, plain recursive Make) place an
    object at a path that mirrors its source's directory, so the candidate
    sharing the longest run of *trailing* directory components with the
    object is the correct source. Returns the unique best match, or None
    when two candidates tie (or none overlap) — the caller treats that as
    ambiguous and refuses to guess.
    """
    obj_dirs = obj_path.parent.parts
    scored: list[tuple[int, Path]] = []
    for cand in candidates:
        cand_dirs = cand.relative_to(target_root).parent.parts
        overlap = 0
        for a, b in zip(reversed(obj_dirs), reversed(cand_dirs)):
            if a != b:
                break
            overlap += 1
        scored.append((overlap, cand))
    top = max(s for s, _ in scored)
    winners = [c for s, c in scored if s == top]
    if top > 0 and len(winners) == 1:
        return winners[0]
    return None


def _source_for_object(obj_path: Path, target_root: Path) -> tuple[str | None, bool]:
    """Best-effort mapping from a build-tree .o back to a source path.

    Strategy: take the basename minus extension and search target_root for
    a matching `.c`/`.cc`/`.cpp`/`.cxx`/`.m`/`.mm`. With a single match,
    use it. With several (duplicate filenames in different directories),
    disambiguate by the object's own location via
    `_disambiguate_by_location`. If that stays ambiguous we refuse to
    guess: a wrong mapping would let one same-named TU's stub verdict block
    a *different*, real TU from audit (a silent false negative). Failing
    open here only risks leaving a genuine stub ungated (wasted effort),
    which is the safe direction.

    Returns `(target-root-relative path | None, ambiguous?)`. The flag is
    True only when matches existed but could not be resolved, so callers
    can surface how many surfaces were left ungated.

    Target-agnostic: structural path matching only, no project heuristics.
    """
    stem = obj_path.stem
    if not stem:
        return (None, False)
    # Many build systems suffix .o files (CMake: `<tu>.c.o`). Strip the
    # inner extension if present.
    inner = Path(stem).stem
    candidates = [stem, inner] if inner != stem else [stem]
    exts = (".c", ".cc", ".cpp", ".cxx", ".c++", ".m", ".mm")
    matches: list[Path] = []
    for cand in candidates:
        if not cand:
            continue
        for ext in exts:
            for p in target_root.rglob(f"{cand}{ext}"):
                # Skip files under build trees (build*, out, dist,
                # node_modules, .git). Industry-wide skip list.
                rel = p.relative_to(target_root)
                parts = set(rel.parts)
                if any(
                    seg.startswith("build") or seg in {"out", "dist", "node_modules", ".git", "CMakeFiles"}
                    for seg in parts
                ):
                    continue
                matches.append(p)
        if matches:
            break
    if not matches:
        return (None, False)
    matches = sorted(set(matches))
    if len(matches) == 1:
        chosen: Path | None = matches[0]
    else:
        chosen = _disambiguate_by_location(obj_path, matches, target_root)
        if chosen is None:
            return (None, True)
    try:
        return (str(chosen.relative_to(target_root)), False)
    except ValueError:
        return (None, False)


def probe_objects(
    build_dir: Path,
    target_root: Path,
    max_objects: int = 5000,
) -> tuple[list[str], list[str], int, int]:
    """Walk build_dir, classify each `.o`, return
    (stub_tus, compiled_tus, n, ambiguous).

    Both lists are deduplicated source-relative paths. `ambiguous` counts
    objects whose basename matched several sources that could not be
    resolved to one — they are left ungated (fail-open). The cap is a
    sanity bound — projects with >5000 TUs are rare and the cap can be
    raised via the CLI.
    """
    if not build_dir.is_dir():
        return ([], [], 0)
    stub_set: set[str] = set()
    real_set: set[str] = set()
    ambiguous = 0
    count = 0
    for obj in sorted(build_dir.rglob("*.o")):
        if count >= max_objects:
            break
        count += 1
        # libtool intermediate .lo wraps a .o; same nm result either way.
        verdict = _classify_object(obj)
        if verdict == "unknown":
            continue
        src, was_ambiguous = _source_for_object(obj, target_root)
        if src is None:
            # Ambiguous basename → left ungated on purpose (fail-open).
            ambiguous += was_ambiguous
            continue
        if verdict == "stub":
            stub_set.add(src)
        else:
            real_set.add(src)
    # If a TU has both a stub and a real .o (e.g. duplicate builds for
    # different configs), trust the "real" classification.
    stub_set -= real_set
    return (sorted(stub_set), sorted(real_set), count, ambiguous)


# ─── Configure summary probe ───────────────────────────────────────


def probe_configure_summary(build_log: Path | None) -> str:
    if not build_log or not build_log.is_file():
        return ""
    try:
        text = build_log.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    # Find the last occurrence of any summary marker — build logs often
    # contain prior partial runs; the last summary reflects the current
    # configuration.
    last_idx = -1
    for i, line in enumerate(lines):
        if any(marker in line for marker in _CONFIGURE_SUMMARY_MARKERS):
            last_idx = i
    if last_idx < 0:
        return ""
    excerpt = lines[last_idx : last_idx + _CONFIGURE_SUMMARY_MAX_LINES]
    return "\n".join(excerpt).strip()


# ─── Orchestration ─────────────────────────────────────────────────


def _iso_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def build_manifest(
    target_root: Path,
    build_dir: Path,
    sanitizer: str,
    binary_path: Path | None = None,
    build_log: Path | None = None,
    max_objects: int = 5000,
) -> FeaturesManifest:
    manifest = FeaturesManifest(
        probed_at=_iso_now(),
        target_root=str(target_root),
        build_dir=str(build_dir),
        sanitizer=sanitizer,
    )
    if binary_path is not None and Path(binary_path).exists():
        manifest.binary = probe_binary(Path(binary_path))
    stubs, reals, n, ambiguous = probe_objects(build_dir, target_root, max_objects=max_objects)
    manifest.stub_tus = stubs
    manifest.compiled_tus = reals
    manifest.probed_object_count = n
    manifest.configure_summary = probe_configure_summary(build_log)
    if n == 0:
        manifest.notes.append("no-objects-probed: build_dir contained no .o files; queue gate will fail-open")
    if ambiguous:
        manifest.notes.append(
            f"ambiguous-basename: {ambiguous} object(s) matched several same-named "
            f"sources and were left ungated (fail-open) rather than risk blocking a "
            f"real TU"
        )
    return manifest


def write_manifest(manifest: FeaturesManifest, output_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = output_path.with_suffix(output_path.suffix + ".tmp")
    tmp.write_text(json.dumps(manifest.to_dict(), indent=2, sort_keys=False) + "\n", encoding="utf-8")
    os.replace(tmp, output_path)


# ─── Consumer API ──────────────────────────────────────────────────


def load_features(path: Path | str) -> dict | None:
    """Load features.json. Returns None on any error (fail-open)."""
    if not path:
        return None
    p = Path(path)
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("schema_version") != FEATURES_SCHEMA_VERSION:
        # Future-proofing: a schema-version mismatch makes the manifest
        # unreadable to this version. Fail-open — old binary, new file.
        return None
    return data


def _norm_tu(path: str) -> str:
    """Normalise a TU path for comparison: forward slashes, no leading ./."""
    if not path:
        return ""
    p = path.replace("\\", "/").lstrip("./")
    # Strip a leading target-root-style prefix if present so callers
    # passing either repo-relative or absolute paths still match.
    return p.lower()


def is_tu_stub(features: dict | None, tu_path: str) -> bool:
    """True iff features.json explicitly lists tu_path as a stub.

    Fail-open: unknown manifest, unknown TU, or empty path returns False
    (do not block). The caller is responsible for handling the
    fail-open case (work proceeds as normal).
    """
    if not features or not tu_path:
        return False
    stubs = features.get("stub_tus") or []
    if not isinstance(stubs, list):
        return False
    needle = _norm_tu(tu_path)
    if not needle:
        return False
    # Match by exact path or by suffix (handles target-root-absolute
    # callers passing /abs/path while manifest stores repo-relative).
    for s in stubs:
        if not isinstance(s, str):
            continue
        cand = _norm_tu(s)
        if cand == needle or needle.endswith("/" + cand) or cand.endswith("/" + needle):
            return True
    return False


def summarise_for_prompt(features: dict | None, *, max_items: int = 40) -> str:
    """Render a compact prompt-ready block of the manifest.

    Designed for inclusion in recon and agent prompts. Returns '' when
    there is no signal to share (no probed objects, no missing features).
    """
    if not features:
        return ""
    stubs = list(features.get("stub_tus") or [])
    probed_n = int(features.get("probed_object_count") or 0)
    binary = features.get("binary") or {}
    feats = list(binary.get("features") or [])
    protos = list(binary.get("protocols") or [])
    if not stubs and probed_n == 0 and not feats and not protos:
        return ""
    lines: list[str] = []
    lines.append("## Build feature manifest")
    lines.append("")
    lines.append("These TUs are present in the source tree but produced "
                 "empty/sanitizer-runtime-only object files in the current "
                 "sanitizer build — they are NOT compiled in. Do not propose "
                 "or pivot to work cards against them; the queue gate will "
                 "block such cards as `tu-not-compiled`. Fix the build "
                 "(target.toml configure flags) if coverage of these TUs "
                 "is required.")
    lines.append("")
    if feats:
        lines.append(f"- Binary features: `{' '.join(feats)}`")
    if protos:
        lines.append(f"- Binary protocols: `{' '.join(protos)}`")
    if probed_n:
        lines.append(f"- Probed object files: {probed_n}; stub TUs: {len(stubs)}")
    if stubs:
        # Group by directory for readability — 47 lib/vtls/* stubs as
        # one entry, not 47.
        from collections import defaultdict
        by_dir: dict[str, list[str]] = defaultdict(list)
        for s in stubs:
            d = str(Path(s).parent) or "."
            by_dir[d].append(Path(s).name)
        lines.append("")
        lines.append("Stub TUs (grouped by directory):")
        shown = 0
        for d in sorted(by_dir):
            if shown >= max_items:
                lines.append(f"- … and more (truncated at {max_items} entries; "
                             f"see features.json for the full list)")
                break
            names = sorted(by_dir[d])
            lines.append(f"- `{d}/`: " + ", ".join(f"`{n}`" for n in names))
            shown += 1
    return "\n".join(lines).rstrip() + "\n"


# ─── CLI ───────────────────────────────────────────────────────────


def _cmd_probe(args: argparse.Namespace) -> int:
    target_root = Path(args.target_root).resolve()
    build_dir = Path(args.build_dir).resolve()
    binary_path = Path(args.binary).resolve() if args.binary else None
    build_log = Path(args.build_log).resolve() if args.build_log else None
    manifest = build_manifest(
        target_root=target_root,
        build_dir=build_dir,
        sanitizer=args.sanitizer or "asan",
        binary_path=binary_path,
        build_log=build_log,
        max_objects=args.max_objects,
    )
    if args.output:
        write_manifest(manifest, Path(args.output))
    if args.print_summary:
        sys.stdout.write(summarise_for_prompt(manifest.to_dict()))
    if args.print_json:
        json.dump(manifest.to_dict(), sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


def _cmd_check(args: argparse.Namespace) -> int:
    features = load_features(Path(args.features))
    stub = is_tu_stub(features, args.tu)
    sys.stdout.write("stub\n" if stub else "real\n")
    return 0 if stub else 1


def _cmd_summary(args: argparse.Namespace) -> int:
    features = load_features(Path(args.features))
    sys.stdout.write(summarise_for_prompt(features))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lib/build_probe.py",
        description="Probe an existing sanitizer build for compiled-in TUs/features.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("probe", help="Probe a build tree and write features.json.")
    p.add_argument("--target-root", required=True)
    p.add_argument("--build-dir", required=True)
    p.add_argument("--sanitizer", default="asan")
    p.add_argument("--binary", default="")
    p.add_argument("--build-log", default="")
    p.add_argument("--output", default="")
    p.add_argument("--max-objects", type=int, default=5000)
    p.add_argument("--print-summary", action="store_true")
    p.add_argument("--print-json", action="store_true")
    p.set_defaults(func=_cmd_probe)

    c = sub.add_parser("check", help="Check if a TU is a stub per features.json.")
    c.add_argument("--features", required=True)
    c.add_argument("--tu", required=True)
    c.set_defaults(func=_cmd_check)

    s = sub.add_parser("summary", help="Render the prompt-ready manifest summary.")
    s.add_argument("--features", required=True)
    s.set_defaults(func=_cmd_summary)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
