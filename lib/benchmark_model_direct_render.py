#!/usr/bin/env python3
"""Render lib/prompts/benchmark_model_direct.md.j2 with target.toml hints.

bin/benchmark's model_direct_prompt() shells out to this helper. Doing the
render in Python (rather than stitching multi-line blocks through bash
$(...) captures) keeps the pipeline NUL-safe and lets us reuse
lib/target_config.parse_toml + lib/prompt_render.render_template
directly.

CLI:
    python3 lib/benchmark_model_direct_render.py \\
        <target_path> <output_dir> [script_root] [wall_seconds] [target_toml]

Every argument render() takes is forwarded, so a CLI render matches what
bin/benchmark produces; omitting wall_seconds renders a prompt with no
deadline, which is not the prompt a cell runs.

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
from datetime import datetime, timedelta, timezone
from pathlib import Path


# Per-sanitizer prompt metadata for the C/C++ clang sanitizers. The runtime
# *_OPTIONS strings are NOT duplicated here — they are read from
# lib/sanitizer_options.conf (the single source of truth shared with
# lib/sanitizer.py and bin/export-repro) by _san_options(). Only the stable
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
    the live runners and bin/export-repro). We never re-hardcode an
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


def _usable_cpus() -> int:
    """CPUs this process may actually run on, honouring a container quota.

    `os.cpu_count()` reports the machine, not the allocation: inside a
    container with a fractional CPU quota it can overstate by an order of
    magnitude, and a ceiling derived from it would license the overload it
    exists to prevent.
    """
    count = 0
    getter = getattr(os, "process_cpu_count", None)  # 3.13+
    if getter is not None:
        count = getter() or 0
    if not count and hasattr(os, "sched_getaffinity"):
        try:
            count = len(os.sched_getaffinity(0))
        except OSError:
            count = 0
    count = count or os.cpu_count() or 1
    for quota_path, period_path in (
        ("/sys/fs/cgroup/cpu.max", None),  # cgroup v2: "<quota|max> <period>"
        ("/sys/fs/cgroup/cpu/cpu.cfs_quota_us",
         "/sys/fs/cgroup/cpu/cpu.cfs_period_us"),
    ):
        try:
            raw = Path(quota_path).read_text().split()
            quota = raw[0]
            period = raw[1] if period_path is None else Path(period_path).read_text().strip()
            if quota in ("max", "-1"):
                continue
            allowed = int(quota) // int(period)
            if allowed >= 1:
                count = min(count, allowed)
        except (OSError, ValueError, IndexError, ZeroDivisionError):
            continue
    return max(1, count)


def _symbolize_available(script_root: str) -> bool:
    sys.path.insert(0, str(Path(script_root) / "lib"))
    import sanitizer  # noqa: PLC0415 - script_root is only known at call time

    return bool(sanitizer.symbolize_available())


def _symbolize_hint(script_root: str, present: bool) -> str:
    """One instruction for every way this prompt can reach a sanitizer.

    A sandboxed backend is denied the process spawn a sanitizer runtime needs
    to symbolize its own report, so the direct condition read address-only
    stacks while the harness — routing every run through bin/run-asan — read
    source lines. That is a difference in how evidence renders, not in what
    either condition can find, and it taxes only the crash lane: an
    unsymbolized trace cannot be told apart from one raised inside the agent's
    own driver.

    It belongs here rather than inside a single invocation block. The three
    ways a target advertises a sanitizer — a native binary, a one-off harness
    driver, and a `[runner]` command — are rendered by different builders and
    only one of them is chosen, so an instruction threaded through one builder
    reaches only the targets that happen to take that branch. The advice holds
    for all of them, because it keys on the symptom.
    """
    if not present or not _symbolize_available(script_root):
        return ""
    return (
        "## Sanitizer frames arrive without source lines\n"
        "\nThis sandbox denies a sanitizer runtime the process spawn its own\n"
        "symbolizer needs. Where the options above say `symbolize=0` that is\n"
        "already accounted for; where they do not, a runtime that cannot\n"
        "symbolize itself falls back to `module+offset` anyway. Either way,\n"
        "resolve any report whose frames carry no `file:line` before you read\n"
        "or file it:\n\n"
        f"    {Path(script_root) / 'bin' / 'symbolize'} <path-to-sanitizer.txt>\n\n"
        "It rewrites the report in place and exits non-zero if a frame stays\n"
        "raw. An address-only trace cannot be told apart from one raised\n"
        "inside your own driver, so do not judge a candidate on one.\n"
    )


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


# Shared body for every crash-capable framing. The prior text made execution a
# verification step downstream of source review ("when source review identifies
# a plausible candidate, prioritize driving it") and then discouraged the lane
# outright. A backend that followed it literally produced zero crashes in a full
# pass while one that ignored it produced eleven (2026-08-02) — so the crash
# column measured deviation from the prompt, not capability. Execution is now
# stated as a way to FIND bugs, not only to confirm them. The evidence bar (a
# real trace) is unchanged; only the discovery framing moved.
_CRASH_LANE = (
    "File every source-proven FINDING as you go. Source review and execution\n"
    "are both first-class ways to find bugs here — {vehicle} is\n"
    "not only for confirming what review already suspects, so budget real\n"
    "time for driving it. After filing a source-backed memory-safety FIND,\n"
    "do not start another broad source scan until you either run its smallest\n"
    "faithful sanitizer probe or record why no public execution route can test\n"
    "it. Repeat allocator-, state-, race-, and timing-dependent probes with a\n"
    "distinct shape; one clean run settles only a fully instantiated\n"
    "deterministic trigger. File a CRASH only when a real {trace} reproduces.\n"
)


def _build_crash_objective(present: bool, build_dir: Path, label: str,
                           race_runner_present: bool = False,
                           sanitizer_runner_present: bool = False) -> str:
    if race_runner_present:
        return (
            "A race-detector runner is configured through `[runner]` (race).\n"
            + _CRASH_LANE.format(vehicle="the configured runner",
                                 trace="`WARNING: DATA RACE` trace")
        )
    if sanitizer_runner_present:
        return (
            f"A {label} sanitizer runner is configured through `[runner]`.\n"
            + _CRASH_LANE.format(vehicle="the configured runner",
                                 trace="sanitizer trace")
        )
    if present:
        return (
            f"A sanitizer build exists at `{build_dir}/` ({label}).\n"
            + _CRASH_LANE.format(vehicle="the instrumented binary",
                                 trace="sanitizer trace")
        )
    # Managed / interpreted targets and any project without a usable
    # sanitizer build. Keep the word "sanitizer-instrumented" so callers
    # and tests can rely on its presence to detect the no-build framing.
    return (
        "No native sanitizer-instrumented build is present for this\n"
        "target. File FINDINGs as your primary deliverable. Use the configured\n"
        "runner, when available, to reproduce and deepen the strongest\n"
        "candidates, and save that evidence with the FINDING. Do not create a\n"
        "CRASH unless execution produces a real sanitizer-class diagnostic.\n"
    )


def _build_invocation(san, bin_path: Path | None, output_dir: str,
                      options: str, profile: dict, cfg=None) -> str:
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
    testcase = f"{crash_dir}/input"
    command = f"{bin_path} <args>"
    if cfg is not None and cfg.runner_args and not cfg.runner_bin:
        args = [
            _expand_runner_token(value, cfg, san, testcase, output_dir)
            for value in cfg.runner_args
        ]
        if not any("{TESTCASE}" in value for value in cfg.runner_args):
            args.append(testcase)
        command = " ".join(
            shlex.quote(str(value)) for value in (bin_path, *args)
        )
    return (
        f"### Driving the {label} binary directly\n"
        f"\nA sanitizer-instrumented CLI is at:\n\n    {bin_path}\n\n"
        "Invoke it with crafted inputs and capture stderr to catch\n"
        f"{longn} output. Suggested wrapper:\n\n"
        f"    {opt_line} \\\n"
        f"      {command}  2> {crash_dir}/sanitizer.txt\n\n"
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
        f"      {crash_dir}/harness.c {lib_path} -Wl,-rpath,{lib_path.parent} {libs_str} \\\n"
        f"      -o {crash_dir}/harness\n"
        f"    {opt_line} \\\n"
        f"      {crash_dir}/harness {crash_dir}/input 2> {crash_dir}/sanitizer.txt\n\n"
        "Keep `-Wl,-rpath` (without it the driver finds no instrumented\n"
        "library and dies in the loader before `main`), and read the input\n"
        "path from `argv[1]` rather than baking one into the source — the\n"
        "directory is renamed when the crash is filed, and the gate that\n"
        "reruns your driver passes the input as an argument.\n\n"
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
        "{NULL_DEVICE}": os.devnull,
        "{TARGET_ROOT}": cfg.target_root,
        "{RESULTS_DIR}": output_dir,
        "{TARGET_SLUG}": cfg.slug,
        "{SANITIZER}": san,
        "{SWIFT_SANITIZER}": _swift_sanitizer_flag(san),
    }
    for key, repl in replacements.items():
        out = out.replace(key, repl or "")
    return out


def _threat_model_block(cfg) -> str:
    """The effective threat-model section, or "" when no config loaded."""
    from prompt_render import render_template  # type: ignore

    controls = ", ".join(getattr(cfg, "attacker_controls", None) or [])
    if not controls:
        return ""
    # Carry its own surrounding blank lines so the template reads correctly
    # either way: the section spacing goes with the section, not the seam.
    block = render_template(
        "audit_threat_model.md.j2", {"attacker_controls": controls},
    ).strip()
    return f"\n{block}\n"


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


def _runner_command_for_prompt(cfg, san: str, testcase: str,
                               output_dir: str) -> str:
    runner = _runner_bin_for_prompt(cfg)
    args = [
        _expand_runner_token(a, cfg, san, testcase, output_dir)
        for a in cfg.runner_args
        if a
    ]
    if not any("{TESTCASE}" in a for a in cfg.runner_args):
        args.append(testcase)
    env = [
        _expand_runner_token(e, cfg, san, "", output_dir)
        for e in cfg.runner_env
        if e
    ]
    env_prefix = ""
    if env:
        env_prefix = "env " + " ".join(shlex.quote(e) for e in env) + " "
    return " ".join(
        [env_prefix + shlex.quote(runner)] +
        [shlex.quote(a) for a in args]
    )


def _build_race_runner_invocation(cfg, output_dir: str) -> str:
    if not cfg.runner_bin:
        return ""
    crash_dir = f"{output_dir}/crashes/CRASH-N"
    testcase = f"{crash_dir}/testcase.go"
    cmd = _runner_command_for_prompt(cfg, "race", testcase, output_dir)
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


def _build_sanitizer_runner_invocation(cfg, san: str, output_dir: str,
                                       profile: dict) -> str:
    """Render a runner command whose explicit tokens select a sanitizer."""
    if not cfg.runner_bin:
        return ""
    crash_dir = f"{output_dir}/crashes/CRASH-N"
    testcase = f"{crash_dir}/testcase"
    cmd = _runner_command_for_prompt(cfg, san, testcase, output_dir)
    return (
        f"### Driving the {profile['label']} runner directly\n"
        f"\nThe target selects {profile['long']} explicitly through "
        "`[runner]`. Run a crafted testcase through that command and save a "
        "real sanitizer diagnostic:\n\n"
        f"    {cmd} > {crash_dir}/stdout.txt 2> {crash_dir}/sanitizer.txt\n\n"
        "A reproducing sanitizer-class memory-safety diagnostic belongs under "
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


def _budget_line(wall_seconds: int, *, now: datetime | None = None) -> str:
    """State the budget as an observable deadline, not an effort estimate.

    Sizing the pass in tool calls ("many dozens") gave the model the only
    target it could check — it has no clock — and sessions ended on reaching
    that count, far under a multi-hour budget. Name an instant instead, and
    say that neither coverage nor a finished-feeling pass is a stopping
    condition. The stated command prints the deadline's own format so the
    check is a comparison, not a conversion the model has to do at the moment
    it is looking for a reason to stop. Minutes are the resolution that
    matters for a multi-hour budget; the deadline rounds up to the next whole
    minute so it is always in the future, however short the budget.

    Framing only: the control is meant to spend the budget on its own
    judgement, so nothing enforces it. The prose lives in lib/prompts with the
    rest of the audit contract; this helper computes only its timestamp and
    human-readable duration.
    """
    from prompt_render import render_template  # type: ignore

    clock = "date -u +'%Y-%m-%d %H:%M UTC'"
    amount = deadline = ""
    if wall_seconds and wall_seconds > 0:
        hours = wall_seconds / 3600.0
        if hours >= 1:
            n = round(hours)
            amount = f"about {n} hour{'s' if n != 1 else ''}"
        else:
            m = max(1, round(wall_seconds / 60.0))
            amount = f"about {m} minute{'s' if m != 1 else ''}"
        deadline = (
            (now or datetime.now(timezone.utc))
            + timedelta(seconds=int(wall_seconds) + 59)
        ).strftime("%Y-%m-%d %H:%M UTC")
    template = (
        "benchmark_model_direct_budget.md.j2"
        if deadline else "benchmark_model_direct_unbounded.md.j2"
    )
    return render_template(
        template,
        {"amount": amount, "clock": clock, "deadline": deadline},
    )


def render(
    target_path: str,
    output_dir: str,
    script_root: str,
    wall_seconds: int = 0,
    target_toml: str = "",
) -> str:
    sys.path.insert(0, os.path.join(script_root, "lib"))
    try:
        from target_config import (  # type: ignore
            Config, load_toml_into, SANITIZER_RUNNER_BUILD_SYSTEMS,
        )
    except Exception:
        Config = None  # type: ignore
        load_toml_into = None  # type: ignore
        SANITIZER_RUNNER_BUILD_SYSTEMS = frozenset()  # type: ignore
    from audit_scope import non_audit_dirs_for_prompt  # type: ignore
    from prompt_render import render_template  # type: ignore

    target = Path(target_path)
    toml_path = Path(target_toml) if target_toml else \
        _resolve_toml_path(target, script_root)

    san = None
    bin_path: Path | None = None
    lib_path: Path | None = None
    include_dirs: list[str] = []
    link_libs: list[str] = []
    race_runner_hint = ""
    sanitizer_runner_hint = ""
    cfg = None
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
            link_libs = cfg.resolved_link_libs()
            if san is not None:
                build_dir = Path(cfg.resolve_path(f"build-{san}"))
            elif "race" in cfg.sanitizers_enabled:
                race_runner_hint = _build_race_runner_invocation(
                    cfg, output_dir)
            elif cfg.runner_bin and \
                    cfg.build_system in SANITIZER_RUNNER_BUILD_SYSTEMS:
                san = next(
                    (name for name in cfg.sanitizers_enabled
                     if name in _SAN_PROFILE),
                    None,
                )
                if san is not None:
                    sanitizer_runner_hint = _build_sanitizer_runner_invocation(
                        cfg, san, output_dir, _SAN_PROFILE[san])
        except Exception:
            san = None
            bin_path = lib_path = None
            include_dirs = []
            link_libs = []
            race_runner_hint = ""
            sanitizer_runner_hint = ""

    profile = _SAN_PROFILE.get(san or "", _SAN_PROFILE["asan"])
    options = _san_options(script_root, san) if san else ""
    # Only the invocations this prompt writes the env line for can be told to
    # skip in-process symbolization; a [runner] command owns its own
    # environment. The hint below covers every path either way.
    if options and _symbolize_available(script_root):
        options = f"{options}:symbolize=0"
    present = bin_path is not None or lib_path is not None

    ctx = {
        # Shared purpose/authorization opener — single source of truth in
        # lib/prompts/audit_goal_framing.md.j2. Keeps the model-direct
        # baseline and the harness framed identically so the benchmark
        # measures harness machinery, not a framing difference.
        "goal_framing": render_template("audit_goal_framing.md.j2", {}),
        # Shared definitional floor (what is NOT a security issue). Keeps
        # this baseline on the same quality bar the find-quality gate
        # enforces, so it does not drift into filing caller-misuse
        # NULL-derefs the gate rejects.
        "bug_contract": render_template("audit_bug_contract.md.j2", {}),
        # The effective threat model, which decides whether triage scores an
        # artifact as security or keeps it as a defect. The harness session
        # prompt carries this contract already; without it here the baseline
        # searches against a rule it cannot see. Config loading supplies the
        # same bytes default triage uses; empty only when target.toml did not
        # load, because inventing a model then would be worse than none.
        "threat_model": _threat_model_block(cfg),
        # Shared report-narrative contract, the same partial the harness
        # session prompt renders. Report readability must not be a
        # condition difference either.
        "report_prose": render_template("report_prose.md.j2", {}),
        "target_path": target_path,
        "output_dir": output_dir,
        "crash_objective": _build_crash_objective(
            present, build_dir, profile["label"],
            bool(race_runner_hint), bool(sanitizer_runner_hint)),
        "asan_invocation_hint": (
            race_runner_hint or sanitizer_runner_hint or _build_invocation(
                san, bin_path, output_dir, options, profile, cfg)
        ),
        "harness_build_recipe": _build_recipe(
            san, lib_path, include_dirs, link_libs, output_dir,
            options, profile),
        "symbolize_hint": _symbolize_hint(
            script_root,
            present or bool(race_runner_hint) or bool(sanitizer_runner_hint),
        ),
        # Single source of truth (lib/audit_scope.py) — the harness
        # work-card pool uses the same set, so both audit modes scope
        # findings the same way. See the .j2 "Audit scope" section.
        "non_audit_dirs": non_audit_dirs_for_prompt(),
        # Sized from the CPUs this process may use, not from the machine:
        # the harness bounds its own concurrency by worker count, and a
        # baseline with no ceiling drove a benchmark host to a load average
        # of 108, at which point its own timeout-based oracles reported load
        # as findings. Never below 1, and never above half of what is there.
        "parallel_ceiling": max(1, _usable_cpus() // 2),
        "budget_line": _budget_line(wall_seconds),
    }
    return render_template("benchmark_model_direct.md.j2", ctx)


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print("usage: benchmark_model_direct_render.py "
              "<target_path> <output_dir> [script_root] [wall_seconds] "
              "[target_toml]", file=sys.stderr)
        return 2
    target_path = argv[1]
    output_dir = argv[2]
    script_root = argv[3] if len(argv) > 3 else os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))
    # Forwarded, not defaulted away: without the wall the rendered prompt
    # states no deadline, and the deadline is the pass's only stopping
    # condition. bin/benchmark calls render() directly, so this is what a
    # CLI render has to match to be the same prompt.
    try:
        wall_seconds = int(argv[4]) if len(argv) > 4 and argv[4] else 0
    except ValueError:
        print("wall_seconds must be an integer", file=sys.stderr)
        return 2
    target_toml = argv[5] if len(argv) > 5 else ""
    sys.stdout.write(
        render(target_path, output_dir, script_root, wall_seconds, target_toml)
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
