#!/usr/bin/env python3
"""Tests for lib/audit_scope.is_excluded_path_part — specifically the
CMakeFiles / cmake-build* additions that prevent CMake-generated bookkeeping
files from minting work-cards. The rule is exercised at scanner-walk time
by lib/workqueue.iter_source_files.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_scope  # noqa: E402

PASSED = 0
FAILED = 0


def ok(cond: bool, name: str, detail: str = "") -> None:
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        FAILED += 1
        suffix = f"\n    {detail}" if detail else ""
        print(f"  \033[0;31m✗\033[0m {name}{suffix}")


# ── EXCLUDED_PATH_SEGMENTS literal hits ────────────────────────────
for seg in ("doc", "docs", "test", "tests", "fuzz", "fuzzer", "example", "examples"):
    ok(
        audit_scope.is_excluded_path_part(seg),
        f"literal segment '{seg}' is excluded",
    )

# ── Sanitizer build trees ──────────────────────────────────────────
for d in ("build-asan", "build-ubsan", "build-msan", "build-tsan",
          "build-asan-cov", "build-asan-debug"):
    ok(
        audit_scope.is_excluded_path_part(d),
        f"sanitizer build dir '{d}' is excluded",
    )

# ── *-install (CMake staging) ──────────────────────────────────────
for d in ("foo-install", "out-install"):
    ok(
        audit_scope.is_excluded_path_part(d),
        f"install staging dir '{d}' is excluded",
    )

# ── NEW: CMakeFiles is excluded (universal CMake cache dir name) ───
ok(
    audit_scope.is_excluded_path_part("CMakeFiles"),
    "CMakeFiles (CMake's internal cache dir) is excluded",
)

# ── NEW: cmake-build* (JetBrains CLion build dirs) are excluded ────
for d in ("cmake-build-debug", "cmake-build-release", "cmake-build", "cmake-build-foo"):
    ok(
        audit_scope.is_excluded_path_part(d),
        f"CLion build dir '{d}' is excluded",
    )

# ── User source directory names are NOT excluded ───────────────────
for d in ("src", "include", "lib", "core", "sampledb", "sampledb.dir"):
    ok(
        not audit_scope.is_excluded_path_part(d),
        f"user source dir '{d}' is NOT excluded",
    )

# ── 'build' alone is NOT excluded — some projects use it as source ─
# (We do not blanket-block generic 'build'; only known-cruft names.)
ok(
    not audit_scope.is_excluded_path_part("build"),
    "plain 'build' is NOT excluded (some projects use it as source root)",
)

# ── Matching is case-insensitive — both production callers in
# lib/workqueue.py lowercase the path component before calling, so the
# rule MUST fire on the lowercased form. A case-sensitive 'CMakeFiles'
# literal never matched a real path and let CMakeFiles/compiler_depend.ts
# mint ranked-source work cards (the cmakefiles livelock).
ok(
    audit_scope.is_excluded_path_part("cmakefiles"),
    "lowercase 'cmakefiles' IS excluded (callers pass lowercased path parts)",
)

# ── Hidden dirs are not handled by audit_scope; the walker prunes them ─
# audit_scope shouldn't claim it excludes them.
ok(
    not audit_scope.is_excluded_path_part(".git"),
    "audit_scope leaves VCS metadata to the walker (.git not in its rules)",
)

# ── non_audit_dirs_for_prompt() must NOT mention the harness-internal
# CMakeFiles / cmake-build* rules — those stay scanner-internal. ────
prompt_dirs = audit_scope.non_audit_dirs_for_prompt()
ok(
    "CMakeFiles" not in prompt_dirs,
    "non_audit_dirs_for_prompt() does not surface CMakeFiles to model-direct",
)
ok(
    "cmake-build" not in prompt_dirs,
    "non_audit_dirs_for_prompt() does not surface cmake-build to model-direct",
)

print()
print(f"  {PASSED}/{PASSED + FAILED} passed", end="")
if FAILED:
    print(f", {FAILED} failed")
    sys.exit(1)
print()
sys.exit(0)
