#!/usr/bin/env bash
# tests/test_export_repro_run.sh — end-to-end: actually build + run the
# reproduce.sh that bin/export-repro generates, and verify the ASan
# diagnostic surfaces.
#
# Why this test exists (the "super bad miss" guard):
#   Until 2026-05, every export-repro test asserted only the *shape* of
#   reproduce.sh (does it contain `cmake -S`? does it `exec "$asan_bin"`?).
#   Nothing built the harness, ran it, and verified that an ASan stack
#   trace + nonzero exit actually came out the other end. As a result, a
#   testcase-selection bug in lib/crash_artifacts.py shipped silently:
#   .audit/reachability.out was being chosen over the real testcase,
#   harness.cpp swallowed the parse error in a catch, and `./reproduce.sh`
#   produced ZERO output while reporting exit=0. The user thought the bug
#   had vanished.
#
#   This file is the floor: when reproduce.sh is generated from a known-
#   buggy harness, running it must actually crash. Skips cleanly if the
#   host has no clang/cmake/git.

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

trap 'teardown_test_env' EXIT

if ! command -v clang >/dev/null 2>&1; then
  pass "skipped: clang not available"
  summary
  exit 0
fi
if ! command -v cmake >/dev/null 2>&1; then
  pass "skipped: cmake not available"
  summary
  exit 0
fi
if ! command -v git >/dev/null 2>&1; then
  pass "skipped: git not available"
  summary
  exit 0
fi

# ─── Build a fake upstream-src tree ──────────────────────────────────
# The generated reproduce.sh expects to clone $URL@$REV, or use an
# existing checkout passed as argv[1]. We pre-stage a tiny tree with
# .git/ so the clone is skipped, and a minimal CMakeLists.txt so the
# `cmake -S "$src" -B "$build"` step succeeds (no targets — fast).
SRC="$TEST_TMPDIR/fake-src"
mkdir -p "$SRC/.git"
cat > "$SRC/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.10)
project(fake_target C)
EOF

# ─── Build a fake output/<slug>/ + crash dir ────────────────────────
OUTPUT_ROOT="$TEST_TMPDIR/output/exr-run-test"
RESULTS="$TEST_TMPDIR/results"
CRASH_DIR="$RESULTS/crashes/CRASH-RUN-1"
mkdir -p "$OUTPUT_ROOT" "$CRASH_DIR"

cat > "$OUTPUT_ROOT/target.toml" <<EOF
slug = "exr-run-test"
upstream_url = "https://example.com/fake"
build_system = "cmake"
pinned_rev = "deadbeef"
asan_bin = "build-asan/unused"
asan_lib = ""
includes = []
link_libs = []
is_browser = "0"

[threat_model]
attacker_controls = ["bytes"]
EOF

cat > "$OUTPUT_ROOT/.session-env" <<EOF
RESULTS_DIR=$RESULTS
TARGET_ROOT=$SRC
TARGET_SLUG=exr-run-test
TARGET_REV=deadbeef
LOGDIR=$TEST_TMPDIR/logs
EOF

# A harness with a deliberate ASan heap-buffer-overflow that triggers
# only when the recorded trailing argv is replayed. This mirrors the production
# pattern where harness.cpp reads a file, parses it, and exercises the
# library — only here the bug is direct so the test doesn't
# depend on testcase content. The catch-all guard is there on purpose:
# the production CRASH-002-1 harness silently caught parse failures and
# returned 0, which is exactly the path we want to outlaw. If the wrong
# input or argv ever gets selected here, the test fails loudly.
cat > "$CRASH_DIR/harness.c" <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <input>\n", argv[0]);
        return 2;
    }
    if (argc < 3 || strcmp(argv[2], "--needed") != 0) {
        fprintf(stderr, "missing recorded flag\n");
        return 0;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "open failed: %s\n", argv[1]);
        return 3;
    }
    char buf[16];
    size_t n = fread(buf, 1, sizeof(buf), f);
    fclose(f);

    char *small = (char *)malloc(4);
    memcpy(small, buf, 4);
    /* Deliberate one-byte read past end of 4-byte allocation. */
    char c = small[4 + (n & 3)];
    free(small);
    return c == 0 ? 0 : 1;
}
EOF

cat > "$CRASH_DIR/asan.txt" <<'EOF'
ASAN_RUN_HEADER: runs=5 mode=generic testcase=output/exr-run-test/scratch/missing.bin started=x
=== Run 1/5 ===
==99999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead at pc 0xface
READ of size 1 at 0xdead thread T0
    #0 0xdead in main /src/harness.c:18
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/harness.c:18 in main
CRASH_RATE: 5/5
EOF

cat > "$CRASH_DIR/report.md" <<'EOF'
# CRASH-RUN-1

## Summary

End-to-end fixture for tests/test_export_repro_run.sh.

Trigger source: bytes
Caller contract: obeyed
Boundary: input file
Caller controls: bytes
EOF

# The real testcase the harness will read from. Content is irrelevant once
# the recorded flag is replayed. Eight bytes so fread() returns >= 4.
printf 'AAAAAAAA' > "$CRASH_DIR/input.bin"
cat > "$CRASH_DIR/repro.cmd" <<'EOF'
{TESTCASE} --needed
EOF

# The regression bait: drop a `.audit/reachability.out` prose file in
# the dir. Before the lib/crash_artifacts.py fix, find_testcase would
# happily select it (alphabetic) and export-repro would stage it as
# `input.out`, producing a reproduce.sh that fed prose to the harness
# and silently exited 0. The test below pins that this never recurs.
mkdir -p "$CRASH_DIR/.audit"
cat > "$CRASH_DIR/.audit/reachability.out" <<'EOF'
Reachability for: main
  External callers (genuine):  0
  sourcegraph status=ok          hits=0
  gh        status=ok          hits=0

Severity: Low (score=10/100)
EOF

# ─── Run export-repro ────────────────────────────────────────────────
# bin/export-repro discovers output/<slug>/ by walking up from cwd, so
# we invoke it from inside OUTPUT_ROOT.
( cd "$OUTPUT_ROOT" && "$SCRIPT_ROOT/bin/export-repro" CRASH-RUN-1 ) > "$TEST_TMPDIR/exr.out" 2>&1
exr_rc=$?
if [ "$exr_rc" -eq 0 ]; then
  pass "export-repro exits 0"
else
  fail "export-repro exits 0" "rc=$exr_rc out=$(tail -c 600 "$TEST_TMPDIR/exr.out")"
  summary
  exit 1
fi

# ─── Inspect the staged bundle ───────────────────────────────────────
assert_file_exists "$CRASH_DIR/reproduce.sh" "bundle: reproduce.sh emitted"
assert_file_exists "$CRASH_DIR/sanitizer.txt" "bundle: neutral sanitizer output emitted"
assert_file_not_exists "$CRASH_DIR/asan.txt" \
  "bundle: legacy asan.txt alias NOT emitted (readers still accept it as a fallback)"
assert_file_exists "$CRASH_DIR/input.bin"    "bundle: input.bin preserved"
assert_file_not_exists "$CRASH_DIR/input.out" \
  "bundle: stale-or-fake input.out NOT staged as testcase"

# The reachability.out bait must NOT have leaked out of .audit/.
if [ -f "$CRASH_DIR/reachability.out" ]; then
  fail "bundle: reachability.out kept inside .audit/" \
       "reachability.out leaked into bundle root"
else
  pass "bundle: reachability.out kept inside .audit/"
fi
assert_file_exists "$CRASH_DIR/.audit/reachability.out" \
  "bundle: reachability.out preserved under .audit/"

# Stream-visibility guards — banner + exit code surface to the user.
assert_file_contains "$CRASH_DIR/reproduce.sh" 'echo "=== running ASan repro:' \
  "reproduce.sh: prints running-testcase banner"
assert_file_contains "$CRASH_DIR/reproduce.sh" 'quarantine_size_mb=256:redzone=64' \
  "reproduce.sh: keeps full run-asan ASan options"
assert_file_contains "$CRASH_DIR/reproduce.sh" 'echo "\[repro\] exit=' \
  "reproduce.sh: prints exit code after run"
assert_file_not_contains "$CRASH_DIR/reproduce.sh" '^exec "\$build/repro"' \
  "reproduce.sh: no bare exec that hides exit status"
assert_file_contains "$CRASH_DIR/reproduce.sh" '"\$build/repro" "\$here/input\.bin" --needed' \
  "reproduce.sh: replays recorded harness argv"
# Submodule-dependent builds (e.g. a JIT engine vendored under deps/) need the
# clone to pull submodules and the pinned-rev checkout to re-sync them.
assert_file_contains "$CRASH_DIR/reproduce.sh" 'git clone --recurse-submodules' \
  "reproduce.sh: clones with submodules"
assert_file_contains "$CRASH_DIR/reproduce.sh" 'submodule update --init --recursive' \
  "reproduce.sh: re-syncs submodules after pinning REV"

# ─── Actually build + run reproduce.sh ───────────────────────────────
# Pass the fake-src checkout explicitly so the embedded `git clone` is
# skipped. Capture stderr+stdout together — ASan writes to stderr.
run_out=$(bash "$CRASH_DIR/reproduce.sh" "$SRC" 2>&1)
run_rc=$?

# The harness has a deliberate ASan bug. A nonzero exit is mandatory.
if [ "$run_rc" -ne 0 ]; then
  pass "reproduce.sh exits nonzero (ASan crashed as expected)"
else
  fail "reproduce.sh exits nonzero (ASan crashed as expected)" \
       "rc=$run_rc tail=$(printf '%s' "$run_out" | tail -c 600)"
fi

assert_match 'AddressSanitizer: heap-buffer-overflow' "$run_out" \
  "reproduce.sh: ASan diagnostic surfaces in output"
assert_match '=== running ASan repro:' "$run_out" \
  "reproduce.sh: running-testcase banner printed at runtime"
assert_match '\[repro\] exit=' "$run_out" \
  "reproduce.sh: exit-code line printed at runtime"

# Confirm reproduce.sh fed input.bin (not the reachability prose).
# Without the crash_artifacts fix, find_testcase picked reachability.out
# and the produced script would reference input.out — assert it doesn't.
assert_file_not_contains "$CRASH_DIR/reproduce.sh" 'input\.out\b' \
  "reproduce.sh: references input.bin, not input.out"
assert_file_contains "$CRASH_DIR/reproduce.sh" 'input\.bin\b' \
  "reproduce.sh: references input.bin testcase"

summary
