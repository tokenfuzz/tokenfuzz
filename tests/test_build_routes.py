#!/usr/bin/env python3
"""tests/test_build_routes.py — sanitizer build-route discovery.

Covers the helper that powers bin/probe's auto-fallback to alternate
sanitizer builds:

  * FEATURE_DISABLED_RE matches the industry-wide phrases (no target
    slugs / no file paths in the regex).
  * enumerate_sibling_builds returns mtime-desc candidates, excludes
    the canonical build, only emits ones whose bin/<name> exists.
  * load_routes / record_route / lookup_route round-trip through the
    JSONL cache and last-write-wins on duplicate keys.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import build_routes  # noqa: E402
import build_config  # noqa: E402

_PASSED = 0
_FAILED = 0
_GREEN = "\033[0;32m"
_RED = "\033[0;31m"
_NC = "\033[0m"


def passed(name: str) -> None:
    global _PASSED
    _PASSED += 1
    print(f"  {_GREEN}✓{_NC} {name}")


def failed(name: str, detail: str = "") -> None:
    global _FAILED
    _FAILED += 1
    print(f"  {_RED}✗{_NC} {name}")
    if detail:
        print(f"    {detail}")


def assert_eq(expected, actual, name: str) -> None:
    if expected == actual:
        passed(name)
    else:
        failed(name, f"expected={expected!r} actual={actual!r}")


def assert_true(cond, name: str, detail: str = "") -> None:
    if cond:
        passed(name)
    else:
        failed(name, detail)


# ── FEATURE_DISABLED_RE coverage ────────────────────────────────────────
# Each phrase below is one a real target produces (pcre2, openssl,
# zlib, libxml2, expat, etc.) when a configure-time feature was off.
# False positives at this layer just cost an extra build sweep; false
# negatives leave the user stranded on ENV-BLOCKED, so the regex is
# permissive on purpose.
feature_disabled_phrases = [
    "No just-in-time compiler support",
    "JIT not available",
    "JIT not supported",
    "JIT disabled",
    "just-in-time compiler not available",
    "feature not compiled in",
    "this build was compiled without ICU support",
    "compiled without zlib support",
    "built without lzma support",
    "feature is disabled at runtime",
    "TLS not enabled at configure time",
    "Operation not supported in this build",
    "regex not supported by this binary",
]
for phrase in feature_disabled_phrases:
    assert_true(
        build_routes.output_is_feature_disabled(phrase),
        f"sentinel matches: {phrase[:48]!r}",
    )

# Phrases that look superficially similar but are NOT feature-disabled
# (missing library / missing header / actual crash / unrelated text)
# must NOT match — otherwise the auto-router would burn cycles on
# every true ENV-BLOCKED.
non_feature_disabled = [
    "ModuleNotFoundError: No module named 'xyz'",
    "ImportError: dynamic module not initialised",
    "fatal error: cannot find foo.h",
    "library not loaded: @rpath/libfoo.dylib",
    "unable to load shared library",
    "==1==ERROR: AddressSanitizer: heap-buffer-overflow",
    "compilation terminated.",
    "permission denied",
    "",
]
for phrase in non_feature_disabled:
    assert_true(
        not build_routes.output_is_feature_disabled(phrase),
        f"sentinel rejects non-feature-disabled: {phrase[:48]!r}",
    )

# Multi-line output: a feature-disabled sentinel anywhere in the buffer
# should still match (real probe outputs intersperse progress lines
# before the failure).
multiline = (
    "[run-asan] preparing /tmp/scratch-1/tc.txt\n"
    "[run-asan] running build-asan/bin/pcre2test\n"
    "pcre2_jit_compile returned -45 (No just-in-time compiler support)\n"
    "PCRE2 version 10.45\n"
)
assert_true(
    build_routes.output_is_feature_disabled(multiline),
    "sentinel matches in a multi-line buffer",
)


# ── enumerate_sibling_builds ────────────────────────────────────────────
# A fake target root with one canonical build (build-asan/) and three
# siblings (build-asan-jit/, build-asan-wide/, build-asan-other-tool/).
# build-asan-jit/bin/pcre2test exists; build-asan-wide/bin/pcre2test
# does NOT (different binary set); build-asan-other-tool/ has the
# binary but with a different name.
def make_tree() -> tempfile.TemporaryDirectory:
    td = tempfile.TemporaryDirectory()
    root = Path(td.name)  # only used while constructing the fixture
    for sub in ("build-asan", "build-asan-jit", "build-asan-wide",
                "build-asan-cmake"):
        (root / sub / "bin").mkdir(parents=True)
    # Canonical binary.
    canonical = root / "build-asan" / "bin" / "pcre2test"
    canonical.write_text("#!/bin/sh\necho canonical\n")
    canonical.chmod(0o755)
    # Sibling with matching binary (the routing target).
    jit_bin = root / "build-asan-jit" / "bin" / "pcre2test"
    jit_bin.write_text("#!/bin/sh\necho jit\n")
    jit_bin.chmod(0o755)
    # Sibling with the binary present.
    cmake_bin = root / "build-asan-cmake" / "bin" / "pcre2test"
    cmake_bin.write_text("#!/bin/sh\necho cmake\n")
    cmake_bin.chmod(0o755)
    # Sibling with NO matching binary — must be filtered out.
    # build-asan-wide/bin/ exists but lacks pcre2test.
    # Also create a non-build-* sibling to verify the prefix filter.
    (root / "src").mkdir()
    # enumerate_sibling_builds sorts on the build-* directory mtime. Pin
    # those mtimes explicitly so ordering is deterministic regardless of
    # filesystem timestamp granularity: the tight mkdir loop above can
    # tie on a coarse-resolution filesystem or a fast CI runner, and a
    # stable sort then falls back to arbitrary iterdir() order. cmake is
    # newest, so it must sort first.
    for offset, sub in enumerate(("build-asan", "build-asan-jit",
                                  "build-asan-wide", "build-asan-cmake")):
        stamp = 1_000_000_000 + offset
        os.utime(root / sub, (stamp, stamp))
    return td


with make_tree() as td:
    root = Path(td)
    canonical = root / "build-asan" / "bin" / "pcre2test"
    cands = build_routes.enumerate_sibling_builds(root, canonical)
    names = [c.build_dir.name for c in cands]
    assert_true(
        "build-asan-jit" in names,
        "enumerate: matching sibling build-asan-jit is listed",
        f"got={names}",
    )
    assert_true(
        "build-asan-cmake" in names,
        "enumerate: matching sibling build-asan-cmake is listed",
        f"got={names}",
    )
    assert_true(
        "build-asan-wide" not in names,
        "enumerate: build-asan-wide skipped (no matching binary)",
        f"got={names}",
    )
    assert_true(
        "build-asan" not in names,
        "enumerate: canonical build-asan excluded from candidates",
        f"got={names}",
    )
    assert_true(
        "src" not in names,
        "enumerate: non-build-* sibling skipped",
        f"got={names}",
    )
    # Order is mtime-desc; cmake was created last, so it should be first.
    assert_eq(
        "build-asan-cmake", names[0],
        "enumerate: mtime-desc order — newest sibling first",
    )

# Managed configuration siblings require readiness bound to the exact recipe,
# not merely a leftover marker from an older or interrupted build.
with make_tree() as td:
    root = Path(td)
    canonical = root / "build-asan" / "bin" / "pcre2test"
    managed = root / "build-asan+cfg-wide-abc" / "bin"
    managed.mkdir(parents=True)
    binary = managed / "pcre2test"
    binary.write_text("#!/bin/sh\n")
    binary.chmod(0o755)
    recipe = root / ".audit" / "configs" / "wide-abc.asan.sh"
    recipe.parent.mkdir(parents=True)
    recipe.write_text("#!/bin/sh\n")
    (managed.parent / ".audit-config-ready").write_text("stale\n")
    assert_true(
        all(c.build_dir != managed.parent for c in build_routes.enumerate_sibling_builds(root, canonical)),
        "enumerate: stale managed readiness proof is rejected",
    )
    build_config.write_recipe_stamp(managed.parent, recipe)
    build_config.mark_ready(managed.parent, recipe)
    assert_true(
        any(c.build_dir == managed.parent for c in build_routes.enumerate_sibling_builds(root, canonical)),
        "enumerate: exact managed readiness proof is accepted",
    )

# Absolute-path target_root must work, AND a non-existent target_root
# returns empty without crashing.
empty = build_routes.enumerate_sibling_builds(
    Path("/does/not/exist"), Path("/does/not/exist/build-asan/bin/x"),
)
assert_eq([], empty, "enumerate: missing target_root returns []")

# asan_bin not under a build-* dir → can't extrapolate → skip silently.
with make_tree() as td:
    root = Path(td)
    weird = root / "src" / "x"
    weird.parent.mkdir(exist_ok=True)
    weird.write_text("x")
    weird.chmod(0o755)
    cands = build_routes.enumerate_sibling_builds(root, weird)
    assert_eq([], cands,
              "enumerate: canonical binary not under build-* returns []")


# ── route cache ─────────────────────────────────────────────────────────
with tempfile.TemporaryDirectory() as td:
    rd = Path(td)
    # Empty cache.
    assert_eq({}, build_routes.load_routes(rd),
              "cache: empty results dir → no routes")
    assert_eq("", build_routes.lookup_route(rd, "file:foo.c"),
              "cache: lookup on empty cache returns ''")

    # Record one route; lookup hits.
    build_routes.record_route(
        rd, key="file:src/pcre2_jit_compile.c",
        binary="/abs/build-asan-jit/bin/pcre2test",
        feature="JIT not available",
        canonical_binary="/abs/build-asan/bin/pcre2test",
    )
    assert_eq(
        "/abs/build-asan-jit/bin/pcre2test",
        build_routes.lookup_route(rd, "file:src/pcre2_jit_compile.c"),
        "cache: lookup returns the recorded binary",
    )

    # Multiple keys — first match wins.
    assert_eq(
        "/abs/build-asan-jit/bin/pcre2test",
        build_routes.lookup_route(rd, "card:WORK-0001",
                                  "file:src/pcre2_jit_compile.c"),
        "cache: lookup tries keys in order, first hit wins",
    )

    # Last-write-wins on duplicate keys.
    build_routes.record_route(
        rd, key="file:src/pcre2_jit_compile.c",
        binary="/abs/build-asan-other/bin/pcre2test",
        feature="updated",
    )
    assert_eq(
        "/abs/build-asan-other/bin/pcre2test",
        build_routes.lookup_route(rd, "file:src/pcre2_jit_compile.c"),
        "cache: duplicate key → last write wins",
    )

    # Empty key / empty binary → no-op (cache file stays single-line per
    # earlier records; we don't write a row for a malformed input).
    rows_before = build_routes.routes_path(rd).read_text().count("\n")
    build_routes.record_route(rd, key="", binary="/some/path")
    build_routes.record_route(rd, key="file:foo.c", binary="")
    rows_after = build_routes.routes_path(rd).read_text().count("\n")
    assert_eq(rows_before, rows_after,
              "cache: empty key or empty binary writes no row")


print()
print(f"  {_PASSED} passed, {_FAILED} failed")
sys.exit(0 if _FAILED == 0 else 1)
