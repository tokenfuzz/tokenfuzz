#!/usr/bin/env python3
"""lib/languages.py — single source of truth for language support.

Audit-harness consumers (workqueue, target_config, crash_artifacts, probe,
setup-target, find-seed, scratch-status) each need a slice of "which
languages does this harness understand": which extensions are
audit-rankable source, which extensions are valid HARNESS files, how do
we dispatch a harness extension to a compiler or interpreter, what
runner defaults belong in target.toml for a given build_system, and
what bootstrap commands turn a fresh source checkout into something the
runner can actually execute.

Historically each consumer kept its own hardcoded list. That made
"add a new language" a five-file diff and let the lists drift — the
case that motivated this module was rank-work missing ``.py`` while
target_config.LANGUAGE_RUNNERS already supported Python.

The registry is intentionally a flat tuple of frozen dataclasses. All
consumers derive their needed slice via helper functions; nothing else
in the harness should special-case a language.

Two interfaces:

1. Python API (preferred — pure stdlib, no external deps):

       import languages
       languages.all_source_exts()        # {'.c', '.cc', ..., '.py', '.ts', ...}
       languages.for_build_system("python")
       languages.for_harness_ext(".rs")
       languages.runner_table()           # {'cargo': {...}, 'python': {...}, ...}

2. Subcommand CLI (for bash callers like bin/probe, bin/setup-target):

       python3 lib/languages.py exts --kind source        # newline-separated
       python3 lib/languages.py exts --kind harness
       python3 lib/languages.py probe-dispatch <harness_ext>
       python3 lib/languages.py bootstrap-cmds <build_system>
       python3 lib/languages.py list                       # human-readable table
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ─── Language entry ─────────────────────────────────────────────────
#
# Conventions:
#   - source_exts / harness_exts are lower-case and include the leading
#     dot. Workqueue and crash_artifacts compare via Path.suffix.lower()
#     so the leading-dot form is the natural shape.
#   - build_systems list every target.toml `build_system` slug that
#     selects this language. Multiple slugs are normal (java has
#     maven+gradle, c/c++ has cmake+meson+autotools+make+mach).
#   - interpreted=True means probe runs the harness directly through an
#     interpreter (no build cache). interpreted=False means probe shells
#     out to the language's compiler/build tool and caches the result.
#   - runner_* fields seed target.toml's [runner] block. They only apply
#     to build_systems whose targets typically lack an ASan build
#     (interpreted languages, plus cargo/go where the language runtime
#     IS the test driver). C/C++ build_systems (cmake/meson/...) leave
#     these empty so seed_toml does not emit a [runner] block.
#   - bootstrap_cmds runs inside the target checkout to make the source
#     tree importable/runnable. None means "no automatic build needed".
#     Each command is a tuple; arguments are NOT shell-expanded — the
#     caller execs them via subprocess.run([...]).
#
# Adding a language: append one entry to LANGUAGES and add coverage to
# tests/test_languages_py.py. No other file should need to change.


@dataclass(frozen=True)
class Language:
    name: str
    source_exts: tuple[str, ...] = ()
    harness_exts: tuple[str, ...] = ()
    build_systems: tuple[str, ...] = ()
    interpreted: bool = False

    # Compiled-harness build dispatch (probe build_kind). Only set when
    # the language has compiled harnesses; "" means no compiled path.
    build_kind: str = ""
    compiler_env: str = ""
    compiler_default: str = ""
    compiler_flags_env: str = ""

    # Interpreted-harness run dispatch. interpreter_default is the
    # binary probe invokes; interpreter_env is the override variable
    # (e.g. PYTHON3). interpreter_preargs are inserted before the
    # harness source path (e.g. ("-script",) for .kts).
    interpreter_env: str = ""
    interpreter_default: str = ""
    interpreter_preargs: tuple[str, ...] = ()

    # Script-only harness extensions for an otherwise-compiled
    # language. Kotlin is the motivating case: `.kt` is compiled via
    # `kotlinc` and run as a jar wrapper, but `.kts` is a script that
    # `kotlinc -script` interprets directly. Listing `.kts` here makes
    # probe_dispatch return the interpreted branch for that extension
    # while keeping `.kt` on the compiled path.
    script_exts: tuple[str, ...] = ()

    # target.toml [runner] block defaults. Only present for languages
    # whose typical target ships as source-only (interpreted) or whose
    # build tool doubles as a test driver. The dict shape matches
    # target_config.language_runner_defaults().
    runner_bin: str = ""
    runner_args: tuple[str, ...] = ("{TESTCASE}",)
    runner_env: tuple[str, ...] = ()
    crash_patterns: tuple[str, ...] = ()

    # Workqueue mode hint. workqueue.mode_for_file returns this string
    # when the file matches this language; the audit loop treats "js"
    # specially (browser-style probes). Empty defaults to "auto".
    work_mode: str = ""

    # Source-tree bootstrap. Tuple-of-tuples; each inner tuple is
    # argv-style (no shell expansion). When provided, bin/setup-target
    # --bootstrap runs them sequentially inside TARGET_ROOT. Use this
    # to compile C extensions, run cargo build, etc. before the audit
    # loop starts. Recipes are RELEASE mode (NDEBUG, -O2-class) so the
    # build does not pull in debug-only asserts that fire as noise
    # rather than security signal — see sanitizer_env below.
    bootstrap_cmds: tuple[tuple[str, ...], ...] = ()

    # When True, bootstrap is gated on the presence of a manifest file
    # in TARGET_ROOT (setup.py, pyproject.toml, Cargo.toml, ...).
    # Empty means "always run when --bootstrap is requested".
    bootstrap_manifests: tuple[str, ...] = ()

    # Fallback alternatives tried when the LAST bootstrap_cmd fails.
    # Used by `bin/setup-target` to express the npm "ci → install →
    # install --legacy-peer-deps" chain without target-specific
    # branching. Each entry is a full argv that replaces the failing
    # last command; the first one to exit zero wins. Empty (default)
    # means "the primary command must succeed or bootstrap aborts".
    bootstrap_alternatives: tuple[tuple[str, ...], ...] = ()

    # Environment variables to export before running bootstrap_cmds
    # AND captured into .audit/bootstrap.sh so reruns are
    # bit-identical. Use this to inject release-mode sanitizer flags
    # (CFLAGS, LDFLAGS, RUSTFLAGS, ...) that the language's build
    # tool consumes. KEY/value pairs; never expanded by a shell.
    sanitizer_env: tuple[tuple[str, str], ...] = ()

    # Maintained sanitizer / coverage-guided fuzzer toolchains that
    # exist for this language as of 2025. Informational; setup-target
    # prints it as one line so the operator sees what's auditable for
    # the target. Empty tuple = "no first-class toolchain in tree;
    # don't pretend otherwise." Drives nothing else — keep the field
    # honest rather than aspirational.
    fuzz_backends: tuple[str, ...] = ()


# ─── The registry ──────────────────────────────────────────────────
#
# Crash-pattern guidance: list runtime diagnostics that lib/triage.sh
# should flag as crash signal. Always include the LLVM sanitizer
# banners — even interpreted runtimes can be invoked under a
# sanitizer wrapper and emit one. Keep patterns anchored where
# possible (^FATAL beats FATAL) so we don't false-positive on
# narrative testcase output.


_ASAN_BANNER = r"==\d+==ERROR: AddressSanitizer"
_UBSAN_BANNER = r"==\d+==.*runtime error:"
_TSAN_BANNER = r"WARNING: ThreadSanitizer:"
_MSAN_BANNER = r"WARNING: MemorySanitizer:"


LANGUAGES: tuple[Language, ...] = (
    # ── C ──────────────────────────────────────────────────────────
    # Headers (.h) are auditable under C: many C public APIs live in
    # headers and prior-fix cards routinely touch them. C++ headers
    # (.hh/.hpp/.hxx) are under cpp below; .h is C by tradition though
    # C++ uses it too — workqueue.iter_source_files unions both so the
    # split doesn't matter for ranking.
    Language(
        name="c",
        source_exts=(".c", ".h"),
        harness_exts=(".c",),
        build_systems=("cmake", "meson", "autotools", "make", "mach"),
        interpreted=False,
        build_kind="cc",
        compiler_env="CC",
        compiler_default="clang",
        compiler_flags_env="CFLAGS",
        # No `bootstrap_cmds` here — C/C++ targets converge their
        # sanitizer build recipe through `bin/auto-build-script`,
        # which writes targets/<slug>/.audit/build.sh. Release-mode
        # ASan/UBSAN/MSAN/TSAN flags are produced there; this field
        # advertises which backends apply to a C target.
        fuzz_backends=("asan", "ubsan", "msan", "tsan", "libfuzzer"),
    ),

    # ── C++ ────────────────────────────────────────────────────────
    # C++ shares the C build_systems list — it's the same native tree.
    # We list build_systems empty here to avoid double-mapping a slug
    # to two languages in for_build_system(); C wins the lookup. The
    # source_exts and harness_exts still flow into the global unions.
    Language(
        name="cpp",
        source_exts=(".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx"),
        harness_exts=(".cc", ".cpp", ".cxx", ".C"),
        build_systems=(),
        interpreted=False,
        build_kind="cc",
        compiler_env="CXX",
        compiler_default="clang++",
        compiler_flags_env="CXXFLAGS",
        fuzz_backends=("asan", "ubsan", "msan", "tsan", "libfuzzer"),
    ),

    # ── Rust ───────────────────────────────────────────────────────
    Language(
        name="rust",
        source_exts=(".rs",),
        harness_exts=(".rs",),
        build_systems=("cargo",),
        interpreted=False,
        build_kind="rust",
        compiler_env="RUSTC",
        compiler_default="rustc",
        compiler_flags_env="RUSTFLAGS",
        runner_bin="cargo",
        runner_args=("run", "--quiet", "--", "{TESTCASE}"),
        crash_patterns=(
            r"thread '.*' panicked at",
            r"fatal runtime error:",
            _ASAN_BANNER,
            _TSAN_BANNER,
            _MSAN_BANNER,
        ),
        # Release build so `debug-assertions` (Rust's panic-on-invariant
        # equivalent of C `assert()`) and `overflow-checks` are off —
        # they produce panics on conditions that are not security
        # findings. `--locked` makes the bootstrap reproducible.
        bootstrap_cmds=(("cargo", "build", "--release", "--locked"),),
        # Fallback drops --locked: handles lockfile drift (older
        # Cargo.lock schema vs. current cargo, transitive yanks,
        # minimum-rust-version bumps). Cargo may regenerate the lock,
        # which is fine for an audit — the recipe persisted to
        # .audit/bootstrap.sh still names the exact command that ran.
        bootstrap_alternatives=(
            ("cargo", "build", "--release"),
        ),
        bootstrap_manifests=("Cargo.toml",),
        # ASan via `-Zsanitizer=address` requires the nightly toolchain
        # plus `rust-src` to rebuild std. That's a real setup step the
        # operator must take separately; we don't try to inject it here
        # because a wrong RUSTFLAGS hides the failure from cargo. The
        # release build alone is still useful — runs under the project's
        # own test suite with overflow/debug-asserts off.
        fuzz_backends=("cargo-fuzz", "afl.rs", "asan-nightly"),
    ),

    # ── Go ─────────────────────────────────────────────────────────
    Language(
        name="go",
        source_exts=(".go",),
        harness_exts=(".go",),
        build_systems=("go",),
        interpreted=False,
        build_kind="go",
        compiler_env="GO",
        compiler_default="go",
        compiler_flags_env="GOFLAGS",
        runner_bin="go",
        runner_args=("run", "{TESTCASE}"),
        runner_env=("GOFLAGS=-mod=mod", "GORACE=halt_on_error=1"),
        crash_patterns=(
            r"WARNING: DATA RACE",
            r"panic: runtime error:",
            r"fatal error: stack overflow",
            r"fatal error: out of memory",
            r"runtime: out of memory",
            r"^goroutine \d+ \[",
        ),
        # `-race` is Go's maintained sanitizer (TSan-class data-race
        # detection) and works on stock toolchains. `-trimpath` keeps
        # paths reproducible across hosts. `-asan`/`-msan` apply only
        # to cgo and degrade silently on pure-Go trees, so we leave
        # them out of the default and rely on -race + the release
        # build (assertions are not a Go concept).
        bootstrap_cmds=(("go", "build", "-race", "-trimpath", "./..."),),
        bootstrap_manifests=("go.mod",),
        fuzz_backends=("native-fuzz", "race"),
    ),

    # ── Swift ──────────────────────────────────────────────────────
    Language(
        name="swift",
        source_exts=(".swift",),
        harness_exts=(".swift",),
        build_systems=("swift",),
        interpreted=False,
        build_kind="swift",
        compiler_env="SWIFTC",
        compiler_default="swiftc",
        compiler_flags_env="SWIFTFLAGS",
        runner_bin="swift",
        runner_args=("{TESTCASE}",),
        crash_patterns=(
            r"Fatal error:",
            _ASAN_BANNER,
            _TSAN_BANNER,
        ),
        # Release config (`-c release` strips Swift debug asserts and
        # turns on optimizer) plus ASan via -Xswiftc. Works on stock
        # Apple and Swift.org Linux toolchains.
        bootstrap_cmds=(
            ("swift", "build", "-c", "release",
             "-Xswiftc", "-sanitize=address",
             "-Xswiftc", "-O"),
        ),
        bootstrap_manifests=("Package.swift",),
        fuzz_backends=("asan", "tsan", "ubsan", "libfuzzer"),
    ),

    # ── Java ───────────────────────────────────────────────────────
    # Both .java source compilation and single-file script execution
    # (JEP 330) are valid. We classify .java as interpreted in the
    # harness-dispatch table because `java <file>` runs without an
    # explicit compile step — but build_kind="java" is set so callers
    # that care can distinguish from a pure script language.
    Language(
        name="java",
        source_exts=(".java",),
        harness_exts=(".java",),
        build_systems=("maven", "gradle"),
        interpreted=True,
        build_kind="java",
        interpreter_env="JAVA",
        interpreter_default="java",
        runner_bin="java",
        runner_args=("{TESTCASE}",),
        crash_patterns=(
            r"Exception in thread",
            r"java\.lang\.OutOfMemoryError",
            r"java\.lang\.StackOverflowError",
            r"^\s+at \S+\(\S+:\d+\)",
        ),
        # The JVM is the memory-safety boundary; there is no
        # `-fsanitize=address`-style instrumentation for `javac`
        # output. The only first-class coverage-guided tool is
        # Code Intelligence's jazzer, which needs a written
        # FuzzXxx.java harness (a separate generator step).
        fuzz_backends=("jazzer",),
    ),

    # ── Kotlin ─────────────────────────────────────────────────────
    # Two harness extensions: .kt is compiled (kotlinc + jar wrapper),
    # .kts is script-interpreted (kotlinc -script). Both flow through
    # the same toolchain binary. .kt is treated as compiled by probe
    # while .kts is interpreted; interpreter_preargs encodes the
    # -script switch the kts path needs.
    Language(
        name="kotlin",
        source_exts=(".kt", ".kts"),
        harness_exts=(".kt", ".kts"),
        build_systems=("kotlin",),
        interpreted=False,
        build_kind="kotlin",
        compiler_env="KOTLINC",
        compiler_default="kotlinc",
        compiler_flags_env="KOTLINCFLAGS",
        # .kts is the script variant — same toolchain binary,
        # invoked with -script and run without an intermediate jar.
        # See script_exts docstring for the dispatch impact.
        script_exts=(".kts",),
        interpreter_env="KOTLINC",
        interpreter_default="kotlinc",
        interpreter_preargs=("-script",),
        runner_bin="kotlinc",
        runner_args=("-script", "{TESTCASE}"),
        crash_patterns=(
            r"Exception in thread",
            r"kotlin\.\w+(Exception|Error):",
            r"java\.lang\.\w+(Exception|Error):",
        ),
        fuzz_backends=("jazzer",),
    ),

    # ── Python ─────────────────────────────────────────────────────
    # Cython (.pyx/.pxd) is included as source so pyyaml-style trees
    # that ship a .pyx alongside a generated .c are ranked under
    # both. The .pyx is the audit-relevant source; the generated .c
    # is also picked up via the C entry.
    Language(
        name="python",
        source_exts=(".py", ".pyx", ".pxd"),
        harness_exts=(".py",),
        build_systems=("python",),
        interpreted=True,
        interpreter_env="PYTHON3",
        interpreter_default="python3",
        runner_bin="python3",
        runner_args=("{TESTCASE}",),
        runner_env=(
            "PYTHONDEVMODE=1",
            "PYTHONPATH={TARGET_ROOT}:{TARGET_ROOT}/src:{TARGET_ROOT}/lib",
        ),
        crash_patterns=(
            r"Traceback \(most recent call last\):",
            r"MemoryError",
            r"RecursionError",
            r"SystemError",
            r"Fatal Python error:",
            _ASAN_BANNER,
        ),
        # Build C extensions in-place so cp-tagged .so files match the
        # currently-running interpreter. Without this, prebuilt sdist
        # extensions (e.g. pyyaml shipping cp39 .so under a cp314
        # interpreter) ENV-BLOCK every C-side work card. The manifest
        # gate is `setup.py`: pure-Python or pyproject-only projects
        # without a shim do not need this step at all.
        #
        # Three-step recipe hardened against PEP 668 (Homebrew /
        # Debian externally-managed pythons), missing setuptools,
        # and projects that need Cython/numpy provisioned per
        # `[build-system].requires`:
        #   1. Create a venv at .audit/venv. The venv's interpreter
        #      is a thin wrapper around system python3, so .so files
        #      built under it carry the same cpython-XYZ ABI tag as
        #      the runner's python3 — the runner can still use
        #      system python3 to import them.
        #   2. Upgrade pip inside the venv (older pip lacks PEP 660
        #      editable-install hooks for C-extension projects).
        #   3. `pip install -e .` — editable install with build
        #      isolation. pip auto-provisions setuptools/Cython/numpy
        #      from pyproject.toml `[build-system].requires` into an
        #      ephemeral build env, so this works on guest accounts
        #      without setuptools and on projects that need Cython
        #      to regenerate .c sources. setuptools' editable_mode
        #      defaults to "compat" for C-ext projects, which writes
        #      the .so files in-place next to the source — exactly
        #      what the runner's PYTHONPATH expects. CFLAGS/LDFLAGS
        #      from sanitizer_env propagate through build isolation.
        bootstrap_cmds=(
            ("python3", "-m", "venv", ".audit/venv"),
            (".audit/venv/bin/python", "-m", "pip", "install",
             "--upgrade", "pip"),
            (".audit/venv/bin/python", "-m", "pip", "install", "-e", "."),
        ),
        bootstrap_manifests=("setup.py",),
        # Release-mode build flags. NDEBUG strips C-level asserts that
        # produce noise (defensive checks, internal invariants) and
        # are not security findings. -O2 matches what distros ship.
        # No `-fsanitize=address` here: importing an ASan-instrumented
        # .so under a non-ASan Python aborts with link-order errors;
        # the runner does not LD_PRELOAD libasan. Use the atheris
        # backend (see fuzz_backends) when ASan instrumentation is
        # actually needed.
        sanitizer_env=(
            ("CFLAGS", "-O2 -g -DNDEBUG -fno-omit-frame-pointer"),
            ("CXXFLAGS", "-O2 -g -DNDEBUG -fno-omit-frame-pointer"),
        ),
        fuzz_backends=("atheris",),
    ),

    # ── JavaScript (Node) ──────────────────────────────────────────
    Language(
        name="javascript",
        source_exts=(".js", ".mjs", ".cjs"),
        harness_exts=(".js", ".mjs"),
        build_systems=("npm",),
        interpreted=True,
        interpreter_env="NODE",
        interpreter_default="node",
        runner_bin="node",
        runner_args=("{TESTCASE}",),
        crash_patterns=(
            r"^FATAL ERROR:",
            r"RangeError: Maximum call stack",
            r"Allocation failed",
            r"^Error:",
            r"node:internal/.*",
        ),
        work_mode="js",
        # `npm install` is gated on package.json so monorepos without
        # one (e.g. plain script bundles) skip the step. We removed
        # `--silent` so failures are diagnosable in .audit/bootstrap.log
        # — the old quiet form ate ERESOLVE messages and made
        # bootstrap "fail without explanation."
        #
        # Primary attempt is `npm ci` (deterministic from lockfile);
        # fallbacks handle the common drift cases:
        #   * `npm install` when lockfile is absent or stale.
        #   * `npm install --legacy-peer-deps` when npm-7+ strict
        #     peer-dep resolution fails on monorepo-style trees.
        #   * `npx --yes pnpm install` when the project uses the
        #     `workspace:` dependency protocol (npm has no support;
        #     Angular and most modern monorepos hit this). npx
        #     fetches pnpm on demand so no global install is needed.
        bootstrap_cmds=(("npm", "ci", "--no-audit", "--no-fund"),),
        bootstrap_alternatives=(
            ("npm", "install", "--no-audit", "--no-fund"),
            ("npm", "install", "--no-audit", "--no-fund", "--legacy-peer-deps"),
            ("npx", "--yes", "pnpm", "install"),
        ),
        bootstrap_manifests=("package.json",),
        # JS itself has no memory unsafety to instrument; native
        # addons (N-API) could be ASan-instrumented but require
        # rebuilding Node under ASan, out of scope here. jsfuzz is
        # the maintained coverage-guided option; mark and move on.
        fuzz_backends=("jsfuzz",),
    ),

    # ── TypeScript ─────────────────────────────────────────────────
    # TS shares npm with JavaScript but has its own extension set and
    # ts-node interpreter. We list it as build_systems=() to avoid
    # double-mapping the "npm" slug; for_build_system("npm") will
    # return javascript, and for_harness_ext(".ts") will return
    # typescript — the right answer in both lookups.
    Language(
        name="typescript",
        source_exts=(".ts", ".tsx"),
        harness_exts=(".ts", ".tsx"),
        build_systems=(),
        interpreted=True,
        interpreter_env="TSNODE",
        interpreter_default="ts-node",
        # No runner_bin: a TS-only target is rare; npm is the build_system
        # and javascript supplies the runner block.
        fuzz_backends=("jsfuzz",),
    ),

    # ── PHP ────────────────────────────────────────────────────────
    Language(
        name="php",
        source_exts=(".php",),
        harness_exts=(".php",),
        build_systems=("composer",),
        interpreted=True,
        interpreter_env="PHP",
        interpreter_default="php",
        runner_bin="php",
        runner_args=("{TESTCASE}",),
        crash_patterns=(
            r"Fatal error:",
            r"PHP Fatal error:",
            r"Stack trace:",
            r"Uncaught \w+Error:",
        ),
        # Dropped --quiet so install failures (network, plugin
        # signatures, php-extension version pins) surface in
        # .audit/bootstrap.log instead of vanishing into a silent rc=1.
        bootstrap_cmds=(("composer", "install", "--no-interaction"),),
        bootstrap_manifests=("composer.json",),
        # No maintained sanitizer/coverage-guided fuzzer for PHP as
        # of 2025. Keep the field empty rather than name something
        # that is not actively maintained.
        fuzz_backends=(),
    ),

    # ── Ruby ───────────────────────────────────────────────────────
    Language(
        name="ruby",
        source_exts=(".rb",),
        harness_exts=(".rb",),
        build_systems=("bundler",),
        interpreted=True,
        interpreter_env="RUBY",
        interpreter_default="ruby",
        runner_bin="ruby",
        runner_args=("{TESTCASE}",),
        crash_patterns=(
            r"^[A-Z]\w*Error",
            r"SystemStackError",
            r"\(NoMemoryError\)",
            r"\(fatal\)",
        ),
        # Dropped --quiet for the same reason as composer/npm above.
        bootstrap_cmds=(("bundle", "install"),),
        bootstrap_manifests=("Gemfile",),
        # Install gems into the project (`vendor/bundle/`) instead of
        # the system Ruby gem dir. The default path on Homebrew /
        # rbenv-managed Rubies is not writable without sudo, and even
        # when it is, polluting the system gemset across targets is
        # the wrong default for an audit harness. BUNDLE_PATH is the
        # canonical bundler env var for this; honoured since bundler
        # 1.x. Operators must `bundle exec` to pick up the vendored
        # gems at run time (separate runner change).
        sanitizer_env=(("BUNDLE_PATH", "vendor/bundle"),),
        fuzz_backends=(),
    ),

    # ── Perl ───────────────────────────────────────────────────────
    Language(
        name="perl",
        source_exts=(".pl", ".pm"),
        harness_exts=(".pl",),
        build_systems=("perl",),
        interpreted=True,
        interpreter_env="PERL",
        interpreter_default="perl",
        runner_bin="perl",
        runner_args=("{TESTCASE}",),
        crash_patterns=(
            r"^Out of memory!",
            r"^Segmentation fault",
            r"died at .* line",
        ),
    ),

    # ── R ──────────────────────────────────────────────────────────
    Language(
        name="r",
        source_exts=(".r", ".R"),
        harness_exts=(".r", ".R"),
        build_systems=("rlang",),
        interpreted=True,
        interpreter_env="RSCRIPT",
        interpreter_default="Rscript",
        runner_bin="Rscript",
        runner_args=("{TESTCASE}",),
        crash_patterns=(r"^Error in", r"^Error:"),
    ),

    # ── Shell ──────────────────────────────────────────────────────
    # Shell scripts are not audit-rankable as source (no shell target in
    # the ranker's wheelhouse) but they ARE valid harness drivers — a
    # // HARNESS: harness.sh wrapping a CLI is the simplest possible
    # repro. We keep source_exts empty so workqueue doesn't pick up
    # build/*.sh by accident.
    Language(
        name="shell",
        source_exts=(),
        harness_exts=(".sh", ".bash"),
        build_systems=(),
        interpreted=True,
        interpreter_env="BASH",
        interpreter_default="bash",
    ),
)


# ─── Internal lookup tables ────────────────────────────────────────


def _by_name() -> dict[str, Language]:
    return {lang.name: lang for lang in LANGUAGES}


def _by_build_system() -> dict[str, Language]:
    table: dict[str, Language] = {}
    for lang in LANGUAGES:
        for slug in lang.build_systems:
            # First entry wins — order in LANGUAGES is the tie-break.
            # This is why C lists the native build systems and C++
            # lists none: a "cmake" target is C (its source_exts union
            # picks up C++ too).
            table.setdefault(slug, lang)
    return table


def _by_harness_ext() -> dict[str, Language]:
    table: dict[str, Language] = {}
    for lang in LANGUAGES:
        for ext in lang.harness_exts:
            # Case folding: store both lower and upper if both are
            # registered (e.g. ".C" vs ".c"). Probe passes the raw
            # extension; we look up lower-cased.
            table.setdefault(ext.lower(), lang)
    return table


def _by_source_ext() -> dict[str, Language]:
    table: dict[str, Language] = {}
    for lang in LANGUAGES:
        for ext in lang.source_exts:
            table.setdefault(ext.lower(), lang)
    return table


# ─── Public API ────────────────────────────────────────────────────


def all_source_exts() -> frozenset[str]:
    """All extensions workqueue should consider audit-rankable source.

    Returned as a frozenset of lower-cased ext strings with leading
    dots (".c", ".py", ".ts", ...). This is the union across every
    Language entry — adding a new language to LANGUAGES automatically
    widens the set everywhere workqueue uses it.
    """
    out: set[str] = set()
    for lang in LANGUAGES:
        for ext in lang.source_exts:
            out.add(ext.lower())
    return frozenset(out)


def all_harness_exts(*, compiled: Optional[bool] = None) -> frozenset[str]:
    """All extensions probe accepts as a // HARNESS: source.

    `compiled=True`  -> only extensions probe routes to a compiler
    `compiled=False` -> only extensions probe routes to an interpreter
    `compiled=None`  -> both

    Script extensions on a compiled language (e.g. `.kts` on Kotlin)
    are correctly bucketed as interpreted — probe runs them directly
    via `kotlinc -script` rather than going through the build cache.
    """
    out: set[str] = set()
    for lang in LANGUAGES:
        scripts = {e.lower() for e in lang.script_exts}
        for ext in lang.harness_exts:
            is_script = ext.lower() in scripts
            ext_compiled = (not lang.interpreted) and (not is_script)
            if compiled is True and not ext_compiled:
                continue
            if compiled is False and ext_compiled:
                continue
            out.add(ext.lower())
    return frozenset(out)


def for_name(name: str) -> Optional[Language]:
    return _by_name().get(name.lower())


def for_build_system(slug: str) -> Optional[Language]:
    """Return the language that owns `slug` as one of its build_systems."""
    return _by_build_system().get(slug)


def for_harness_ext(ext: str) -> Optional[Language]:
    """Return the language whose harness dispatch claims `ext`.

    `ext` may be passed with or without the leading dot; case is
    folded. Returns None when no language claims it — probe will
    surface this as an unsupported-extension error.
    """
    if not ext:
        return None
    if not ext.startswith("."):
        ext = "." + ext
    return _by_harness_ext().get(ext.lower())


def for_source_ext(ext: str) -> Optional[Language]:
    """Return the language whose source_exts claims `ext`, or None."""
    if not ext:
        return None
    if not ext.startswith("."):
        ext = "." + ext
    return _by_source_ext().get(ext.lower())


def mode_for_ext(ext: str) -> str:
    """Return the workqueue work_mode for a source extension.

    Defaults to "auto" when no language claims the extension or the
    language has no explicit mode. This replaces the hardcoded
    ".js/.mjs -> js" check in workqueue.mode_for_file.
    """
    lang = for_source_ext(ext)
    if lang and lang.work_mode:
        return lang.work_mode
    return "auto"


def runner_table() -> dict[str, dict]:
    """Build the LANGUAGE_RUNNERS dict consumed by target_config.

    The returned dict's keys are target.toml `build_system` slugs and
    the values are the [runner] block defaults (bin/args/env/crash_patterns).
    Languages whose runner_bin is empty (e.g. pure native C/C++) are
    omitted — seed_toml won't emit a [runner] block for them.
    """
    table: dict[str, dict] = {}
    for lang in LANGUAGES:
        if not lang.runner_bin:
            continue
        block = {
            "bin": lang.runner_bin,
            "args": list(lang.runner_args),
            "env": list(lang.runner_env),
            "crash_patterns": list(lang.crash_patterns),
        }
        for slug in lang.build_systems:
            table.setdefault(slug, block)
    return table


def probe_dispatch(ext: str) -> Optional[dict]:
    """Return a dict describing how bin/probe should run a harness ext.

    Shape:
        {
          "build_kind": "cc" | "rust" | ... | "interpret",
          "compiler_env":     str (compiled only),
          "compiler_default": str (compiled only),
          "flags_env":        str (compiled only),
          "interpreter_env":     str (interpreted only),
          "interpreter_default": str (interpreted only),
          "interpreter_preargs": list[str] (interpreted only),
        }

    Scripts on otherwise-compiled languages (`.kts` on Kotlin) return
    the interpreted branch so probe can run them directly without a
    compile cache.
    """
    lang = for_harness_ext(ext)
    if not lang:
        return None
    norm_ext = ("." + ext.lstrip(".")).lower()
    is_script = norm_ext in {e.lower() for e in lang.script_exts}
    if lang.interpreted or is_script:
        return {
            "build_kind": "interpret",
            "interpreter_env": lang.interpreter_env,
            "interpreter_default": lang.interpreter_default,
            "interpreter_preargs": list(lang.interpreter_preargs),
        }
    return {
        "build_kind": lang.build_kind,
        "compiler_env": lang.compiler_env,
        "compiler_default": lang.compiler_default,
        "flags_env": lang.compiler_flags_env,
    }


def bootstrap_for_target(target_root: Path, build_system: str) -> list[list[str]]:
    """Return the bootstrap commands setup-target should run.

    Each command is an argv list (no shell expansion). The build_system
    selects the language; bootstrap_manifests gates per-command on the
    presence of the matching file in `target_root` so we don't try to
    `npm install` a tree that has no package.json.
    """
    lang = for_build_system(build_system)
    if not lang or not lang.bootstrap_cmds:
        return []
    if lang.bootstrap_manifests:
        if not any((target_root / m).exists() for m in lang.bootstrap_manifests):
            return []
    return [list(cmd) for cmd in lang.bootstrap_cmds]


def bootstrap_plan_for_target(target_root: Path, build_system: str) -> dict:
    """Return the full bootstrap plan: cmds, alternatives, env, backends.

    Shape (always all keys present, possibly empty):
        {
          "language": <name>,
          "cmds": [["python3", "-m", "pip", ...], ...],
          "alternatives": [["npm", "install", ...], ...],
          "env": [["CFLAGS", "-O2 ..."], ...],
          "fuzz_backends": ["atheris", ...],
        }

    `alternatives` apply to the LAST command in `cmds`: setup-target
    tries the primary, then each alternative in order. Empty list = no
    fallback. `env` is a list of [key, value] pairs to export before
    running cmds (also persisted into .audit/bootstrap.sh).
    """
    lang = for_build_system(build_system)
    out = {
        "language": lang.name if lang else "",
        "cmds": [],
        "alternatives": [],
        "env": [],
        "fuzz_backends": [],
    }
    if not lang:
        return out
    out["fuzz_backends"] = list(lang.fuzz_backends)
    out["env"] = [list(p) for p in lang.sanitizer_env]
    if not lang.bootstrap_cmds:
        return out
    if lang.bootstrap_manifests:
        if not any((target_root / m).exists() for m in lang.bootstrap_manifests):
            return out
    out["cmds"] = [list(c) for c in lang.bootstrap_cmds]
    out["alternatives"] = [list(c) for c in lang.bootstrap_alternatives]
    return out


def fuzz_backends_for_build_system(build_system: str) -> list[str]:
    """Return the maintained fuzz/sanitizer backends for `build_system`."""
    lang = for_build_system(build_system)
    return list(lang.fuzz_backends) if lang else []


# `<modname>.cpython-NN[-platform...]` or `<modname>.pypyNN-NN[-platform...]`.
# We match the cpython/pypy + version prefix and stop — anything after
# (e.g. `-darwin`, `-x86_64-linux-gnu`) is the platform tag and varies.
_PY_EXT_ABI_RE = re.compile(r"^(cpython-\d+|pypy\d*-\d+)")


def stale_python_extensions(target_root: Path) -> list[Path]:
    """Return Python C-extension .so files in ``target_root`` that the
    current interpreter cannot load.

    A file is "stale" when its ABI tag does not match
    ``sys.implementation.cache_tag`` AND no sibling .so for the active
    tag exists alongside it. The sibling check prevents false positives
    on targets that ship a matrix of prebuilt extensions (e.g. pillow
    keeps `cp39` and `cp314` .so files side-by-side — the cp314 file
    loads under Python 3.14, so the cp39 file is not blocking import).

    Detection is purely structural: filename → embedded ABI tag → set
    comparison. No knowledge of which modules a given target ships, no
    target-specific paths. Plain `libfoo.so` wrappers and abi3 .so files
    are ignored because they have no version-specific cache tag.

    Drives ``bin/setup-target``'s auto-bootstrap path: when this returns
    non-empty for a Python target, the runner cannot import any of the
    listed extensions and ``setup.py build_ext --inplace`` must rebuild
    against the current interpreter.
    """
    expected = sys.implementation.cache_tag  # e.g. "cpython-314"
    if not expected or not target_root.is_dir():
        return []

    # Group extension files by (parent_dir, module_name) so we can ask
    # "is at least one .so under this base loadable by the current
    # interpreter?" If yes, the base is satisfied; if no, every .so
    # under it is stale.
    #
    # Skip transient build-tool output trees (``build/``, ``dist/``,
    # ``.tox/``, ``.eggs/``, ``*.egg-info/``). Stale artifacts there are
    # not what the runner imports — they're intermediate copies left by
    # ``setup.py build_ext``. Without this, a target that has ever been
    # built for any interpreter would flag forever even after a correct
    # in-place build lands the right .so under the package dir.
    skip_segments = {"build", "dist", ".tox", ".eggs", "__pycache__"}
    bases: dict[tuple[Path, str], list[Path]] = {}
    for so in target_root.rglob("*.so"):
        rel_parts = so.relative_to(target_root).parts[:-1]
        if any(seg in skip_segments or seg.endswith(".egg-info") for seg in rel_parts):
            continue
        parts = so.name.split(".")
        if len(parts) < 3:
            continue  # libfoo.so — not an ABI-tagged extension
        suffix = parts[-2]
        if not _PY_EXT_ABI_RE.match(suffix):
            continue  # abi3, unrelated .so, etc.
        module_name = parts[0]
        bases.setdefault((so.parent, module_name), []).append(so)

    stale: list[Path] = []
    for files in bases.values():
        if any(_PY_EXT_ABI_RE.match(f.name.split(".")[-2]).group(1) == expected
               for f in files):
            continue
        stale.extend(files)
    return sorted(stale)


def supported_extension_help() -> str:
    """Human-readable summary used by probe's unsupported-extension error."""
    compiled = sorted(all_harness_exts(compiled=True))
    interpreted = sorted(all_harness_exts(compiled=False))
    return (
        f"compiled:   {' '.join(compiled)}\n"
        f"interpreted: {' '.join(interpreted)}"
    )


# ─── CLI ───────────────────────────────────────────────────────────


def _emit_shell_assignments(d: dict) -> str:
    """Format a dict as `KEY=VALUE` lines for bash `eval`.

    Lists are emitted as a bash array literal (quoted, space-separated).
    Empty values still emit so the caller can rely on the key being
    set after `eval`.
    """
    lines: list[str] = []
    for key, val in d.items():
        shell_key = key.upper()
        if isinstance(val, list):
            quoted = " ".join(_shell_quote(v) for v in val)
            lines.append(f"{shell_key}=({quoted})")
        else:
            lines.append(f"{shell_key}={_shell_quote(str(val))}")
    return "\n".join(lines)


def _shell_quote(s: str) -> str:
    """Minimal POSIX shell single-quote escape."""
    if s == "":
        return "''"
    if all(c.isalnum() or c in "@%+=:,./-_" for c in s):
        return s
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _cmd_exts(args: argparse.Namespace) -> int:
    kind = args.kind
    if kind == "source":
        exts = sorted(all_source_exts())
    elif kind == "harness":
        exts = sorted(all_harness_exts())
    elif kind == "harness-compiled":
        exts = sorted(all_harness_exts(compiled=True))
    elif kind == "harness-interpreted":
        exts = sorted(all_harness_exts(compiled=False))
    else:
        print(f"unknown --kind: {kind}", file=sys.stderr)
        return 2
    for e in exts:
        # Drop the leading dot so callers can splice into
        # `find -iname '*.{e}'` style commands cleanly.
        print(e.lstrip("."))
    return 0


def _cmd_probe_dispatch(args: argparse.Namespace) -> int:
    info = probe_dispatch(args.ext)
    if not info:
        print(f"unsupported harness extension: {args.ext}", file=sys.stderr)
        print(supported_extension_help(), file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(info))
    else:
        print(_emit_shell_assignments(info))
    return 0


def _cmd_runner_block(args: argparse.Namespace) -> int:
    table = runner_table()
    block = table.get(args.build_system)
    if not block:
        return 1
    print(json.dumps(block, indent=2 if args.pretty else None))
    return 0


def _cmd_bootstrap_cmds(args: argparse.Namespace) -> int:
    target_root = Path(args.target_root).expanduser().resolve()
    cmds = bootstrap_for_target(target_root, args.build_system)
    if args.format == "json":
        print(json.dumps(cmds))
    else:
        for cmd in cmds:
            print(" ".join(_shell_quote(p) for p in cmd))
    return 0


def _cmd_bootstrap_plan(args: argparse.Namespace) -> int:
    target_root = Path(args.target_root).expanduser().resolve()
    plan = bootstrap_plan_for_target(target_root, args.build_system)
    print(json.dumps(plan))
    return 0


def _cmd_fuzz_backends(args: argparse.Namespace) -> int:
    backends = fuzz_backends_for_build_system(args.build_system)
    print(" ".join(backends))
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    rows: list[tuple[str, str, str, str]] = []
    for lang in LANGUAGES:
        rows.append((
            lang.name,
            " ".join(lang.source_exts) or "-",
            " ".join(lang.harness_exts) or "-",
            " ".join(lang.build_systems) or "-",
        ))
    widths = [max(len(r[i]) for r in rows + [("LANGUAGE", "SOURCE", "HARNESS", "BUILD_SYSTEMS")]) for i in range(4)]
    header = ("LANGUAGE", "SOURCE", "HARNESS", "BUILD_SYSTEMS")
    print("  ".join(h.ljust(widths[i]) for i, h in enumerate(header)))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(c.ljust(widths[i]) for i, c in enumerate(r)))
    return 0


def _cmd_stale_python_extensions(args: argparse.Namespace) -> int:
    target_root = Path(args.target_root).expanduser().resolve()
    stale = stale_python_extensions(target_root)
    for path in stale:
        print(path)
    return 0


def _cmd_supports_build_system(args: argparse.Namespace) -> int:
    lang = for_build_system(args.build_system)
    print(lang.name if lang else "")
    return 0 if lang else 1


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="lib/languages.py", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("exts", help="emit source or harness extensions, one per line")
    p.add_argument("--kind", choices=("source", "harness", "harness-compiled", "harness-interpreted"),
                   required=True)
    p.set_defaults(func=_cmd_exts)

    p = sub.add_parser("probe-dispatch", help="describe how probe should handle a harness extension")
    p.add_argument("ext", help="harness extension, with or without leading dot (e.g. py, .rs)")
    p.add_argument("--format", choices=("shell", "json"), default="shell")
    p.set_defaults(func=_cmd_probe_dispatch)

    p = sub.add_parser("runner-block", help="emit the target.toml [runner] block for a build_system")
    p.add_argument("build_system")
    p.add_argument("--pretty", action="store_true")
    p.set_defaults(func=_cmd_runner_block)

    p = sub.add_parser("bootstrap-cmds", help="emit bootstrap commands for a build_system + target_root")
    p.add_argument("build_system")
    p.add_argument("target_root")
    p.add_argument("--format", choices=("shell", "json"), default="shell")
    p.set_defaults(func=_cmd_bootstrap_cmds)

    p = sub.add_parser("bootstrap-plan",
                       help="emit full bootstrap plan (cmds + alternatives + env + fuzz_backends) as JSON")
    p.add_argument("build_system")
    p.add_argument("target_root")
    p.set_defaults(func=_cmd_bootstrap_plan)

    p = sub.add_parser("fuzz-backends",
                       help="emit maintained fuzz/sanitizer backends for a build_system, space-separated")
    p.add_argument("build_system")
    p.set_defaults(func=_cmd_fuzz_backends)

    p = sub.add_parser("supports-build-system",
                       help="exit 0 and print language name if build_system is known, else exit 1")
    p.add_argument("build_system")
    p.set_defaults(func=_cmd_supports_build_system)

    p = sub.add_parser("stale-python-extensions",
                       help="list Python C-extension .so files in target_root whose ABI tag mismatches the active interpreter")
    p.add_argument("target_root")
    p.set_defaults(func=_cmd_stale_python_extensions)

    p = sub.add_parser("list", help="print the registry as a table")
    p.set_defaults(func=_cmd_list)

    ns = parser.parse_args(argv)
    return int(ns.func(ns) or 0)


if __name__ == "__main__":
    sys.exit(main())
