#!/usr/bin/env python3
"""Render lib/prompts/benchmark_model_direct.md.j2 with target.toml hints.

bin/benchmark's model_direct_prompt() shells out to this helper. Doing the
render in Python (rather than stitching multi-line blocks through bash
$(...) captures) keeps the pipeline NUL-safe and lets us reuse
lib/target_config.parse_toml + lib/prompt_render.render_template
directly.

CLI:
    python3 lib/benchmark_model_direct_render.py \\
        <target_path> <output_dir> [script_root]

Prints the fully-rendered prompt to stdout. Empty output_dir / target_path
fall through to render_template (the .md.j2 substitutes them in plain).

The sanitizer hints are NOT asan-only: the primary native sanitizer is chosen
from target.toml [sanitizer].enabled (asan/ubsan/msan/tsan), so a
ubsan/msan/tsan-only target advertises its own build, flag, and *_OPTIONS
(read from lib/sanitizer_options.conf). Go's `race` sanitizer is runner-based
and gets a runner hint when [runner] is configured. On managed/interpreted
targets with no usable sanitizer build or race runner the crash_objective
block degrades to the find-only framing and the two recipe blocks render
empty — matching the prior template's intent without the asymmetric "skip
CRASHes" off-ramp that suppressed crash production when a sanitizer build did
exist.
"""

from __future__ import annotations

import os
import shlex
import stat
import sys
from pathlib import Path


# Per-sanitizer prompt metadata for the C/C++ clang sanitizers. The runtime
# *_OPTIONS strings are NOT duplicated here — they are read from
# lib/sanitizer_options.conf (the single source of truth shared with
# lib/sanitizer.sh and bin/export-repro) by _san_options(). Only the stable
# name → (clang -fsanitize flag, *_OPTIONS env var, short/long label) mapping
# lives here.
#
# These are the four of target_config.SANITIZERS_VALID that build a
# `build-<san>/` tree with a <san>_bin / <san>_lib and a clang harness path.
# The fifth sanitizer slug, `race`, is Go's runtime race detector. Config
# intentionally has no race bin/lib fields; it is driven through [runner] and
# handled separately below.
_SAN_PROFILE = {
    "asan":  {"flag": "address",   "env": "ASAN_OPTIONS",
              "label": "asan",  "long": "AddressSanitizer"},
    "ubsan": {"flag": "undefined", "env": "UBSAN_OPTIONS",
              "label": "ubsan", "long": "UndefinedBehaviorSanitizer"},
    "msan":  {"flag": "memory",    "env": "MSAN_OPTIONS",
              "label": "msan",  "long": "MemorySanitizer"},
    "tsan":  {"flag": "thread",    "env": "TSAN_OPTIONS",
              "label": "tsan",  "long": "ThreadSanitizer"},
}


def _is_executable(p: Path) -> bool:
    try:
        mode = p.stat().st_mode
    except OSError:
        return False
    return bool(mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH))


def _san_options(script_root: str, san: str, mode: str = "full") -> str:
    """Canonical *_OPTIONS string for `san`, read from the shared conf.

    lib/sanitizer_options.conf is the single source of truth (also consumed by
    the bin/run-* shell runners and bin/export-repro). We never re-hardcode an
    option string here. Falls back to the sanitizer's `full` row, then "".
    """
    conf = Path(script_root) / "lib" / "sanitizer_options.conf"
    try:
        text = conf.read_text(encoding="utf-8")
    except OSError:
        return ""
    rows: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0] == san:
            rows[parts[1]] = parts[2]
    return rows.get(mode) or rows.get("full") or ""


def _env_assignment(name: str, options: str) -> str:
    # Keep rendered snippets shell-valid even when a fixture script_root lacks
    # lib/sanitizer_options.conf. `ASAN_OPTIONS=` is a valid empty assignment;
    # bare `ASAN_OPTIONS` would be parsed as a command.
    return f"{name}={options}" if options else f"{name}="


def _select_sanitizer(cfg) -> tuple:
    """Pick the primary sanitizer to advertise in the prompt.

    Honors target.toml [sanitizer].enabled order so a ubsan/msan/tsan-only
    target renders its own build instead of silently falling through to the
    find-only framing (the prior helper only ever looked at asan). Returns
    (san, bin_path, lib_path) for the first enabled sanitizer with a usable
    binary or static library on disk, else (None, None, None). bin_path is set
    only when executable, lib_path only when it is a file.
    """
    for raw in cfg.sanitizers_enabled:
        san = raw.lower()
        if san not in _SAN_PROFILE:
            continue
        bin_rel = cfg.sanitizer_bin(san)
        lib_rel = cfg.sanitizer_lib(san)
        bin_path = Path(cfg.resolve_path(bin_rel)) if bin_rel else None
        lib_path = Path(cfg.resolve_path(lib_rel)) if lib_rel else None
        bin_ok = bin_path is not None and _is_executable(bin_path)
        lib_ok = lib_path is not None and lib_path.is_file()
        if bin_ok or lib_ok:
            return san, (bin_path if bin_ok else None), \
                (lib_path if lib_ok else None)
    return None, None, None


def _build_crash_objective(present: bool, build_dir: Path,
                           output_dir: str, label: str,
                           race_runner_present: bool = False) -> str:
    if race_runner_present:
        return (
            "A race-detector runner is configured through `[runner]` (race). "
            "Your **primary**\n"
            "deliverable is at least one CRASH on disk — a real\n"
            "`WARNING: DATA RACE` trace from a real input or driver.\n"
            "File every source-proven FINDING as you go — findings stay\n"
            "first-class. But do not finish the session\n"
            f"with an empty `{output_dir}/crashes/` if a candidate looks\n"
            "reachable through the configured runner.\n"
        )
    if present:
        return (
            f"A sanitizer build exists at `{build_dir}/` ({label}). Your "
            "**primary**\n"
            "deliverable is at least one CRASH on disk — a real sanitizer\n"
            "trace from a real input or driver. File every source-proven\n"
            "FINDING as you go — findings stay first-class. But do not\n"
            "finish the session with an empty\n"
            f"`{output_dir}/crashes/` if a candidate looks reachable from a\n"
            "sanitizer-instrumented binary.\n"
        )
    # Managed / interpreted targets and any project without a usable
    # sanitizer build. Keep the word "sanitizer-instrumented" so callers
    # and tests can rely on its presence to detect the no-build framing.
    return (
        "No native sanitizer-instrumented build is present for this\n"
        "target. File FINDINGs as your primary deliverable; CRASHes are\n"
        "only expected when a sanitizer-instrumented binary or library\n"
        "exists.\n"
    )


def _build_invocation(san, bin_path: Path | None, output_dir: str,
                      options: str, profile: dict) -> str:
    # output_dir is the cell's results dir; rendered absolute so a model
    # that has `cd`'d into the source tree still writes back to the
    # right place. Relative `./crashes/...` in this hint silently
    # mis-routed a real CRASH into the target tree on gemini r1
    # (2026-05-24). Keep absolute.
    if san is None or bin_path is None:
        return ""
    label = profile["label"]
    longn = profile["long"]
    env = profile["env"]
    crash_dir = f"{output_dir}/crashes/CRASH-N"
    opt_line = _env_assignment(env, options)
    return (
        f"### Driving the {label} binary directly\n"
        f"\nA sanitizer-instrumented CLI is at:\n\n    {bin_path}\n\n"
        "Invoke it with crafted inputs and capture stderr to catch\n"
        f"{longn} output. Suggested wrapper:\n\n"
        f"    {opt_line} \\\n"
        f"      {bin_path} <args>  2> {crash_dir}/sanitizer.txt\n\n"
        "Try malformed inputs (URL escapes, oversized fields, protocol\n"
        "edge cases, integer extremes, embedded NULs) and inputs that\n"
        "exercise the surface area the source review flagged.\n\n"
        "If you rebuild the sanitizer tree yourself: optimized release\n"
        "config with symbols only (cmake `-DCMAKE_BUILD_TYPE=Release`,\n"
        "meson `--buildtype=release -Db_ndebug=true`, autotools without\n"
        "`--enable-debug`, and compile flags including\n"
        "`-O2 -g1 -DNDEBUG`).\n"
        "Do not use `RelWithDebInfo` or `debugoptimized`. Debug-profile\n"
        "builds compile in `assert(...)` and `[A-Z_]*(?:ASSERT|CHECK)`\n"
        "macros that don't ship — aborts on those are not security bugs\n"
        "by themselves.\n"
    )


def _build_recipe(san, lib_path: Path | None, include_dirs: list[str],
                  link_libs: list[str], output_dir: str,
                  options: str, profile: dict) -> str:
    # See _build_invocation for why output_dir is required. The driver
    # paths below must be absolute under {{ output_dir }} for the same
    # reason. include_dirs are already resolved to absolute paths via
    # Config.resolve_path (which applies AUDIT_BUILD_SUFFIX), so the
    # rendered -I flags point at the same headers the build used.
    if san is None or lib_path is None:
        # No static-lib harness path (managed targets have no library).
        return ""
    flag = profile["flag"]
    inc_flags = " ".join(f"-I{shlex.quote(i)}" for i in include_dirs)
    libs_str = " ".join(shlex.quote(l) for l in link_libs)
    crash_dir = f"{output_dir}/crashes/CRASH-N"
    env = profile["env"]
    opt_line = _env_assignment(env, options)
    return (
        "### Building a one-off harness driver\n"
        "\nThe sanitizer-built static library is at:\n\n"
        f"    {lib_path}\n\n"
        f"Write a small C driver under `{crash_dir}/harness.c` that\n"
        "calls into the API path you want to exercise, then build and\n"
        "run it:\n\n"
        f"    clang -fsanitize={flag} -fno-omit-frame-pointer -g1 -O1 \\\n"
        f"      {inc_flags} \\\n"
        f"      {crash_dir}/harness.c {lib_path} {libs_str} \\\n"
        f"      -o {crash_dir}/harness\n"
        f"    {opt_line} \\\n"
        f"      {crash_dir}/harness 2> {crash_dir}/sanitizer.txt\n\n"
        "Keep one driver per CRASH directory so each is reproducible on\n"
        "its own. Don't add `-DDEBUG`, `-DDEBUGBUILD`, `-UNDEBUG`, or\n"
        "any project-specific debug toggle — debug-only `assert(...)`\n"
        "and `[A-Z_]*(?:ASSERT|CHECK)` aborts don't ship and aren't\n"
        "security bugs by themselves.\n"
    )


def _swift_sanitizer_flag(san: str) -> str:
    return {
        "asan": "address",
        "ubsan": "undefined",
        "tsan": "thread",
    }.get(san, san)


def _expand_runner_token(value: str, cfg, san: str, testcase: str,
                         output_dir: str) -> str:
    out = value
    replacements = {
        "{TESTCASE}": testcase,
        "{TARGET_ROOT}": cfg.target_root,
        "{RESULTS_DIR}": output_dir,
        "{TARGET_SLUG}": cfg.slug,
        "{SANITIZER}": san,
        "{SWIFT_SANITIZER}": _swift_sanitizer_flag(san),
    }
    for key, repl in replacements.items():
        out = out.replace(key, repl or "")
    return out


def _runner_bin_for_prompt(cfg) -> str:
    raw = cfg.runner_bin
    if not raw:
        return ""
    if os.path.isabs(raw):
        return raw
    # Bare command names (go, python3, node, ...) are PATH-resolved by
    # bin/probe/bin/run-asan. Keep them as command names in the prompt rather
    # than inventing TARGET_ROOT/go.
    if "/" not in raw:
        return raw
    return cfg.resolve_path(raw)


def _build_race_runner_invocation(cfg, output_dir: str) -> str:
    if not cfg.runner_bin:
        return ""
    crash_dir = f"{output_dir}/crashes/CRASH-N"
    testcase = f"{crash_dir}/testcase.go"
    runner = _runner_bin_for_prompt(cfg)
    args = [
        _expand_runner_token(a, cfg, "race", testcase, output_dir)
        for a in cfg.runner_args
        if a
    ]
    if not any("{TESTCASE}" in a for a in cfg.runner_args):
        args.append(testcase)
    env = [
        _expand_runner_token(e, cfg, "race", "", output_dir)
        for e in cfg.runner_env
        if e
    ]
    env_prefix = ""
    if env:
        env_prefix = "env " + " ".join(shlex.quote(e) for e in env) + " "
    cmd = " ".join(
        [env_prefix + shlex.quote(runner)] +
        [shlex.quote(a) for a in args]
    )
    return (
        "### Driving the race runner directly\n"
        "\nThe target is configured for the Go race detector through "
        "`[runner]`. Write a small testcase, run it through the configured "
        "runner, and save a `WARNING: DATA RACE` diagnostic as sanitizer "
        "output:\n\n"
        f"    {cmd} > {crash_dir}/stdout.txt 2> {crash_dir}/sanitizer.txt\n\n"
        "A reproducing Go race detector report belongs under "
        f"`{output_dir}/crashes/`, not findings/.\n"
    )


def _resolve_toml_path(target: Path, script_root: str) -> Path | None:
    """Locate the canonical target.toml for this target tree.

    target.toml lives at output/<slug>/target.toml (generated by
    bin/setup-target / bin/audit, gitignored), NOT inside the target
    source tree — the same place target_output_root() /
    target_toml_from_results() resolve it for every other consumer. The
    in-tree path is kept only as a fallback for fixtures that ship a
    committed target.toml (e.g. tests/ early-cellbench targets).
    """
    # Derive the slug as the target's path relative to <repo>/targets so a
    # nested target (targets/samples/sample-python) resolves its config at
    # output/samples/sample-python/target.toml instead of collapsing to the
    # basename. A target provisioned outside that tree (--target-path) has no
    # such relation, so fall back to its basename — matching bin/audit's
    # sanitize_target_slug.
    targets_root = Path(script_root) / "targets"
    try:
        slug: Path = target.resolve().relative_to(targets_root.resolve())
    except ValueError:
        slug = Path(target.name)
    canonical = Path(script_root) / "output" / slug / "target.toml"
    if canonical.is_file():
        return canonical
    in_tree = target / "target.toml"
    if in_tree.is_file():
        return in_tree
    return None


def render(target_path: str, output_dir: str, script_root: str) -> str:
    sys.path.insert(0, os.path.join(script_root, "lib"))
    try:
        from target_config import Config, load_toml_into  # type: ignore
    except Exception:
        Config = None  # type: ignore
        load_toml_into = None  # type: ignore
    from audit_scope import non_audit_dirs_for_prompt  # type: ignore
    from prompt_render import render_template  # type: ignore

    target = Path(target_path)
    toml_path = _resolve_toml_path(target, script_root)

    san = None
    bin_path: Path | None = None
    lib_path: Path | None = None
    include_dirs: list[str] = []
    link_libs: list[str] = []
    race_runner_hint = ""
    # build_dir is for display only; resolve_path applies AUDIT_BUILD_SUFFIX
    # so the message names the build tree that actually exists in-container.
    build_dir = target / "build-asan"

    if Config is not None and toml_path is not None:
        try:
            cfg = Config()
            # resolve_path() joins target-relative values onto target_root
            # and rewrites build-<san>/ → build-<san><AUDIT_BUILD_SUFFIX>/,
            # exactly like the shell target_resolve_path; set it before use.
            cfg.target_root = str(target)
            load_toml_into(cfg, toml_path)
            # Drive off [sanitizer].enabled, not a hardcoded "asan" — a
            # ubsan/msan/tsan-only target gets its own build advertised.
            san, bin_path, lib_path = _select_sanitizer(cfg)
            include_dirs = [cfg.resolve_path(i) for i in cfg.includes if i]
            link_libs = list(cfg.link_libs)
            if san is not None:
                build_dir = Path(cfg.resolve_path(f"build-{san}"))
            elif "race" in cfg.sanitizers_enabled:
                race_runner_hint = _build_race_runner_invocation(
                    cfg, output_dir)
        except Exception:
            san = None
            bin_path = lib_path = None
            include_dirs = []
            link_libs = []
            race_runner_hint = ""

    profile = _SAN_PROFILE.get(san or "", _SAN_PROFILE["asan"])
    options = _san_options(script_root, san) if san else ""
    present = bin_path is not None or lib_path is not None

    ctx = {
        # Shared purpose/authorization opener — single source of truth in
        # lib/prompts/audit_goal_framing.md.j2, also rendered by
        # bin/audit-recon. Keeps the model-direct baseline and the recon
        # prompt framed identically so the benchmark measures harness
        # machinery, not a framing difference.
        "goal_framing": render_template("audit_goal_framing.md.j2", {}),
        # Shared definitional floor (what is NOT a security issue), the same
        # partial bin/audit-recon renders. Keeps the recon seed and this
        # baseline on one quality bar so neither drifts into filing (or
        # emitting) caller-misuse NULL-derefs the find-quality gate rejects.
        "bug_contract": render_template("audit_bug_contract.md.j2", {}),
        "target_path": target_path,
        "output_dir": output_dir,
        "crash_objective": _build_crash_objective(
            present, build_dir, output_dir, profile["label"],
            bool(race_runner_hint)),
        "asan_invocation_hint": race_runner_hint or _build_invocation(
            san, bin_path, output_dir, options, profile),
        "harness_build_recipe": _build_recipe(
            san, lib_path, include_dirs, link_libs, output_dir,
            options, profile),
        # Single source of truth (lib/audit_scope.py) — the harness
        # work-card pool uses the same set, so both audit modes scope
        # findings the same way. See the .j2 "Audit scope" section.
        "non_audit_dirs": non_audit_dirs_for_prompt(),
    }
    return render_template("benchmark_model_direct.md.j2", ctx)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: benchmark_model_direct_render.py "
              "<target_path> <output_dir> [script_root]", file=sys.stderr)
        return 2
    target_path = argv[1]
    output_dir = argv[2]
    script_root = argv[3] if len(argv) > 3 else os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    sys.stdout.write(render(target_path, output_dir, script_root))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
