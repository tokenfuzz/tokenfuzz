#!/usr/bin/env bash
# Regression test for lib/audit_scope.EXCLUDED_PATH_SEGMENTS. The set
# is intentionally narrow — only doc/example/test/fuzz families — so
# vendored deps, build outputs, tools, and scripts stay IN scope for
# both the harness work-card pool and the model-direct prompt. The
# prefix helpers (build-asan*, *-install) cover harness-derived dirs
# the agent should not audit; those stay scanner-only and do not
# appear in the model-direct prompt list.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

python3 - <<'PY'
import sys
sys.path.insert(0, "lib")
from workqueue import is_excluded_work_path, is_excluded_path_part

CASES_EXCLUDED = [
    # Literal segments at the root.
    ("tests/foo.c",            "tests/ at root"),
    ("docs/api.md",            "docs/ at root"),
    ("fuzz/harness.c",         "fuzz/ at root"),
    ("examples/demo.c",        "examples/ at root"),
    # Same literal segments anywhere — set matches at every path
    # component, not just the root.
    ("src/tests/foo.c",        "tests/ anywhere"),
    ("src/doc/foo.c",          "doc/ anywhere"),
    ("subsys/docs/api.md",     "docs/ anywhere"),
    ("third_party/lib/examples/x.c", "examples/ inside vendored dep"),
    # Pattern-based exclusions (build-asan*, *-install) — harness-only,
    # not surfaced into the model-direct prompt list.
    ("build-asan/foo.c",       "build-asan/ at root"),
    ("build-asan-debug/x.c",   "build-asan-* prefix"),
    ("src/build-asan/y.c",     "build-asan/ anywhere"),
    ("foo-install/x.c",        "*-install suffix at root"),
    ("src/cmake-install/y.c",  "*-install suffix anywhere"),
    # Test-shaped file names (separate is_excluded_work_path stem rule).
    ("src/parser_test.cpp",    "_test suffix"),
    ("src/test_parser.cpp",    "test_ prefix"),
]

CASES_ALLOWED = [
    ("src/parser.c",           "ordinary source"),
    ("xpath/internals.c",      "subsystem source"),
    ("foo/bar.c",              "two-level source"),
    ("include/api.h",          "headers"),
    ("net/quic/stream.cc",     "deep source"),
    # Deliberately back in scope after the audit_scope simplification —
    # vendored deps, plain build/, tools, scripts, external are
    # auditable now. Keeping these in the suite as live assertions so
    # a future re-expansion of the set fails the test instead of
    # silently shrinking scope.
    ("third_party/zlib/inflate.c", "vendored dep is auditable"),
    ("build/foo.c",                "plain build/ no longer auto-excluded"),
    ("tools/munge.c",              "tools/ is in scope"),
    ("scripts/helper.c",           "scripts/ is in scope"),
    ("external/foo/bar.c",         "external/ is in scope"),
]

failures = []
for path, reason in CASES_EXCLUDED:
    if not is_excluded_work_path(path):
        failures.append(f"  EXPECTED EXCLUDED: {path!r:40s}  ({reason})")
for path, reason in CASES_ALLOWED:
    if is_excluded_work_path(path):
        failures.append(f"  EXPECTED ALLOWED:  {path!r:40s}  ({reason})")

if failures:
    print("FAIL: is_excluded_work_path drift")
    for f in failures:
        print(f)
    sys.exit(1)

# Pattern helper exposed for direct testing.
assert is_excluded_path_part("build-asan")
assert is_excluded_path_part("build-asan-debug")
assert is_excluded_path_part("foo-install")
assert is_excluded_path_part("tests")
assert not is_excluded_path_part("parser")
assert not is_excluded_path_part("src")

print("OK")
PY
rc=$?
[ "$rc" -eq 0 ] || { echo "FAIL: test_excluded_path"; exit 1; }
echo "PASS: test_excluded_path"
