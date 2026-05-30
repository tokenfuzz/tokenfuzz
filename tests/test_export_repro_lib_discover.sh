#!/usr/bin/env bash
# tests/test_export_repro_lib_discover.sh — end-to-end guard for the
# reproduce-time library discovery path.
#
# Why this test exists:
#   cmake/meson library targets (c-ares, pcre2, …) build an instrumented
#   library the C harness must link, but target.toml often carries no
#   <san>_lib (the seed only detected static archives, and shared-only
#   builds left it empty). export-repro then emitted a reproduce.sh whose
#   clang line linked nothing target-specific, so the harness died at link
#   with "undefined symbols" and the crash never reproduced.
#
#   The fix: when target.toml names no <san>_lib, the generated reproduce.sh
#   discovers the library the build just produced under $build and links it.
#   This test builds a real static library with an ASan bug, a harness that
#   calls into it, leaves asan_lib unset, and asserts the regenerated
#   reproduce.sh discovers + links the library and surfaces the crash.

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

trap 'teardown_test_env' EXIT

for tool in clang cmake git; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    pass "skipped: $tool not available"
    summary
    exit 0
  fi
done

# ─── Fake upstream tree: a static library + public header ────────────
SRC="$TEST_TMPDIR/fake-src"
mkdir -p "$SRC/.git"
cat > "$SRC/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.10)
project(tgt C)
add_library(tgt tgt.c)
# Generate the public header into a NON-standard build subdir (mirrors
# pcre2 emitting pcre2.h under build/interface/) and a config header into a
# second subdir (mirrors config.h). target.toml's includes name neither, so
# the harness can only find them via reproduce-time generated-header include
# discovery, and the API header is gated on -DHAVE_CONFIG_H — so the bundle
# only compiles if the reproducer also defines it (the private-header path).
configure_file(${CMAKE_SOURCE_DIR}/api.h.in ${CMAKE_BINARY_DIR}/interface/api.h)
configure_file(${CMAKE_SOURCE_DIR}/config.h.in ${CMAKE_BINARY_DIR}/conf/config.h)
EOF
cat > "$SRC/config.h.in" <<'EOF'
#define WIDGET_OK 1
EOF
cat > "$SRC/api.h.in" <<'EOF'
#if defined HAVE_CONFIG_H
#include "config.h"
#endif
#ifndef WIDGET_OK
#error "build config not applied: needs -DHAVE_CONFIG_H + config.h on path"
#endif
int boom(void);
EOF
cat > "$SRC/tgt.h" <<'EOF'
int boom(void);
EOF
# boom() writes past a 4-byte allocation — an unconditional ASan
# heap-buffer-overflow that only links if the harness finds libtgt. The
# `volatile` count is opaque to the optimizer, so the OOB write survives
# the reproducer's Release -O3 -DNDEBUG build (a plain p[4] read gets
# elided and would make this test silently pass without exercising ASan).
cat > "$SRC/tgt.c" <<'EOF'
#include "tgt.h"
#include <stdlib.h>
#include <string.h>
int boom(void) {
    volatile int n = 8;
    char *p = (char *)malloc(4);
    memset(p, 'A', n);
    int r = p[0];
    free(p);
    return r;
}
EOF

# ─── Fake output/<slug>/ + crash dir ────────────────────────────────
OUTPUT_ROOT="$TEST_TMPDIR/output/exr-libdisc"
RESULTS="$TEST_TMPDIR/results"
CRASH_DIR="$RESULTS/crashes/CRASH-LIB-1"
mkdir -p "$OUTPUT_ROOT" "$CRASH_DIR"

# asan_lib deliberately unset — this is the case the discovery path covers.
cat > "$OUTPUT_ROOT/target.toml" <<EOF
slug = "exr-libdisc"
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
TARGET_SLUG=exr-libdisc
TARGET_REV=deadbeef
LOGDIR=$TEST_TMPDIR/logs
EOF

# Self-contained harness (no input file). It includes the GENERATED header
# (built into build/interface/, not on target.toml's include path) and
# links against the discovered library — so the bundle only compiles if
# both reproduce-time discoveries fire.
cat > "$CRASH_DIR/harness.c" <<'EOF'
#include "api.h"
int main(void) {
    return boom();
}
EOF

cat > "$CRASH_DIR/asan.txt" <<'EOF'
ASAN_RUN_HEADER: runs=1 mode=generic testcase= started=x
==99999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead at pc 0xface
READ of size 1 at 0xdead thread T0
    #0 0xdead in boom tgt.c:7
SUMMARY: AddressSanitizer: heap-buffer-overflow tgt.c:7 in boom
EOF

cat > "$CRASH_DIR/report.md" <<'EOF'
# CRASH-LIB-1

## Summary

End-to-end fixture for tests/test_export_repro_lib_discover.sh.

Trigger source: bytes
Caller contract: obeyed
Boundary: library API
Caller controls: bytes
EOF

# ─── Run export-repro ────────────────────────────────────────────────
( cd "$OUTPUT_ROOT" && "$SCRIPT_ROOT/bin/export-repro" CRASH-LIB-1 ) > "$TEST_TMPDIR/exr.out" 2>&1
exr_rc=$?
if [ "$exr_rc" -eq 0 ]; then
  pass "export-repro exits 0"
else
  fail "export-repro exits 0" "rc=$exr_rc out=$(tail -c 600 "$TEST_TMPDIR/exr.out")"
  summary
  exit 1
fi

assert_file_exists "$CRASH_DIR/reproduce.sh" "bundle: reproduce.sh emitted"

# ─── Shape: the discovery block + guarded link are present ───────────
assert_file_contains "$CRASH_DIR/reproduce.sh" 'linking auto-discovered library' \
  "reproduce.sh: emits the library-discovery banner when asan_lib is unset"
assert_file_contains "$CRASH_DIR/reproduce.sh" 'find "\$build" -type f -name .\*\.a' \
  "reproduce.sh: discovery scans \$build for a static archive"
assert_file_contains "$CRASH_DIR/reproduce.sh" 'san_lib:\+"\$san_lib"' \
  "reproduce.sh: harness link line is guarded by the discovered san_lib"
assert_file_contains "$CRASH_DIR/reproduce.sh" 'gen_inc="\$gen_inc -I\$d"' \
  "reproduce.sh: emits generated-header include discovery"
assert_file_contains "$CRASH_DIR/reproduce.sh" '\-O1.*\$gen_inc' \
  "reproduce.sh: harness compile line consumes discovered include dirs"
assert_file_contains "$CRASH_DIR/reproduce.sh" 'have_config=" -DHAVE_CONFIG_H"' \
  "reproduce.sh: defines HAVE_CONFIG_H when the build emits a config header"
assert_file_contains "$CRASH_DIR/reproduce.sh" '\$gen_inc\$have_config' \
  "reproduce.sh: harness compile line consumes the HAVE_CONFIG_H define"

# ─── Actually build + run: must link the library and crash ───────────
run_out=$(bash "$CRASH_DIR/reproduce.sh" "$SRC" 2>&1)
run_rc=$?

if [ "$run_rc" -ne 0 ]; then
  pass "reproduce.sh exits nonzero (linked the library and ASan crashed)"
else
  fail "reproduce.sh exits nonzero (linked the library and ASan crashed)" \
       "rc=$run_rc tail=$(printf '%s' "$run_out" | tail -c 800)"
fi

assert_match 'linking auto-discovered library' "$run_out" \
  "reproduce.sh: discovery banner printed at runtime"
assert_match 'AddressSanitizer: heap-buffer-overflow' "$run_out" \
  "reproduce.sh: ASan diagnostic surfaces (library symbol resolved)"
# The failure mode this test guards against — a harness that never linked
# the library — shows up as an undefined-symbol link error, not a crash.
if printf '%s' "$run_out" | grep -qiE 'undefined symbol|symbol.* not found'; then
  fail "reproduce.sh: no undefined-symbol link failure" \
       "harness did not link the discovered library"
else
  pass "reproduce.sh: no undefined-symbol link failure"
fi

summary
