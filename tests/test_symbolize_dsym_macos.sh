#!/usr/bin/env bash
# tests/test_symbolize_dsym_macos.sh — macOS regression guard for offline
# symbolization of separately-linked target libraries.
#
# Why this exists (a real benchmark regression the mocked tests could not catch):
#   The audit's offline symbolizer (lib/clusterfuzz_symbolizer.py) prefers
#   llvm-symbolizer and treats a function-only result as final. On macOS a
#   CMake/-g1 target build links a dylib whose DWARF lives only in .o object
#   files, reachable through a Mach-O *debug map*; the dylib itself carries no
#   embedded DWARF and no .dSYM. atos follows that debug map — but
#   llvm-symbolizer does NOT (it reads DWARF only from the binary or a .dSYM).
#   So library crash frames symbolized through the offline chain degraded to
#   `func (module)` with no file:line.
#
#   lib/platform.sh:audit_make_dsyms bakes the debug map into a self-contained
#   .dSYM (bin/setup-target runs it after a build materializes), which both
#   llvm-symbolizer and atos can read.
#
#   tests/test_offline_symbolize.sh fully MOCKS the symbolizer with canned
#   source, so it cannot exercise this. This test compiles a REAL
#   separately-linked dylib, crashes into it, and symbolizes through the REAL
#   offline chain: the library frame must have NO source line before
#   audit_make_dsyms and a real file:line after.
#
#   macOS-only: the bug is the Mach-O debug map. Linux embeds -g1 DWARF directly
#   in the ELF .so, so the offline chain resolves there regardless.
#
#   Fixtures use neutral placeholder symbols (sample_overflow / apptool), never
#   a real target's symbols.

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
trap 'teardown_test_env' EXIT

if ! audit_is_darwin; then
  pass "skipped: not Darwin (the debug-map/.dSYM gap is macOS-only)"
  summary; exit 0
fi
if ! command -v clang >/dev/null 2>&1; then
  pass "skipped: clang not available"
  summary; exit 0
fi

SYM_PY="$SCRIPT_ROOT/lib/clusterfuzz_symbolizer.py"
assert_file_exists "$SYM_PY" "fixture: offline symbolizer module present"

# ── Build a separately-linked, -g1, NO-dSYM dylib (the CMake target shape) ──
src="$TEST_TMPDIR/src"; build="$TEST_TMPDIR/build"
mkdir -p "$src" "$build"
cat > "$src/sample.h" <<'EOF'
int sample_overflow(const char *s);
EOF
cat > "$src/sample.c" <<'EOF'
#include "sample.h"
#include <stdlib.h>
#include <string.h>
int sample_overflow(const char *s) {
    char *p = (char *)malloc(8);
    strcpy(p, s);            /* heap-buffer-overflow when s longer than 8 */
    int r = p[0];
    free(p);
    return r;
}
EOF
cat > "$src/apptool.c" <<'EOF'
#include "sample.h"
#include <stdio.h>
int main(void) { printf("%d\n", sample_overflow("AAAAAAAAAAAAAAAAAAAAAAAA")); return 0; }
EOF

# Separate compile + link is what puts the DWARF in the .o behind a debug map
# (no embedded DWARF, no auto-.dSYM) — exactly CMAKE_SHARED_LINKER output.
clang -fsanitize=address -O1 -g1 -fno-omit-frame-pointer -c "$src/sample.c" \
  -o "$build/sample.o" 2>/dev/null
clang -fsanitize=address -dynamiclib "$build/sample.o" \
  -o "$build/libsample.dylib" -install_name @rpath/libsample.dylib 2>/dev/null
clang -fsanitize=address -O1 -g1 -fno-omit-frame-pointer -I "$src" "$src/apptool.c" \
  -o "$build/apptool" -L"$build" -lsample -Wl,-rpath,"$build" 2>/dev/null

if [ ! -x "$build/apptool" ] || [ ! -e "$build/libsample.dylib" ]; then
  pass "skipped: toolchain could not build the asan fixture"
  summary; exit 0
fi

# Precondition: the freshly-linked dylib has NO .dSYM (the broken state).
if [ -e "$build/libsample.dylib.dSYM" ]; then
  fail "fixture precondition" "dylib unexpectedly already has a .dSYM"
else
  pass "fixture: separately-linked dylib starts without a .dSYM"
fi

# ── Capture a genuine symbolize=0 crash report ──
raw="$TEST_TMPDIR/raw.txt"
( cd "$build" && ASAN_OPTIONS="symbolize=0:detect_leaks=0:abort_on_error=0:exitcode=0" \
    ./apptool >/dev/null 2>"$raw" || true )
assert_file_contains "$raw" 'libsample\.dylib.*\+0x' \
  "raw symbolize=0 report references the dylib by module+offset"

# Force the offline LLVM path — the backend the audit chain prefers, and the one
# that is blind to the Mach-O debug map. If this host has no llvm-symbolizer the
# .dSYM-creation assertions below still run; only the before/after symbolize
# asserts (which need llvm-symbolizer to exhibit the blindness) are skipped.
ls_tool="$(audit_llvm_tool llvm-symbolizer)"
have_ls=0
case "$ls_tool" in
  */*) [ -x "$ls_tool" ] && have_ls=1 ;;
  *)   command -v "$ls_tool" >/dev/null 2>&1 && have_ls=1 ;;
esac

if [ "$have_ls" -eq 1 ]; then
  before="$TEST_TMPDIR/before.txt"
  python3 "$SYM_PY" --llvm-symbolizer "$ls_tool" <"$raw" >"$before" 2>/dev/null
  before_frame="$(grep -E 'sample_overflow' "$before" | head -1)"
  if printf '%s' "$before_frame" | grep -qE 'sample\.c:[0-9]'; then
    # A future llvm-symbolizer that follows the Mach-O debug map would resolve
    # the dylib even without a .dSYM. The fix is still valuable (it makes
    # symbolization backend-independent and survives build-tree teardown), so
    # treat this as a moot precondition, not a failure, and still validate the
    # .dSYM creation + after path below.
    pass "note: llvm-symbolizer already resolves the debug-map dylib; negative precondition moot, fix still validated below"
  else
    pass "BEFORE fix: llvm-symbolizer cannot resolve the debug-map dylib to file:line (regression repro)"
  fi
else
  pass "skipped before/after symbolize asserts: no llvm-symbolizer on host"
fi

# ── Apply the fix exactly as bin/setup-target's materialization path does ──
audit_make_dsyms "$build"
assert_file_exists "$build/libsample.dylib.dSYM/Contents/Resources/DWARF/libsample.dylib" \
  "audit_make_dsyms: produced a self-contained .dSYM for the dylib"

if [ "$have_ls" -eq 1 ]; then
  after="$TEST_TMPDIR/after.txt"
  python3 "$SYM_PY" --llvm-symbolizer "$ls_tool" <"$raw" >"$after" 2>/dev/null
  after_frame="$(grep -E 'sample_overflow' "$after" | head -1)"
  assert_match 'sample\.c:[0-9]' "$after_frame" \
    "AFTER fix: llvm-symbolizer resolves the dylib frame to file:line via the .dSYM"
fi

# ── Idempotence: a second pass over an up-to-date tree is a harmless no-op ──
audit_make_dsyms "$build"
assert_file_exists "$build/libsample.dylib.dSYM/Contents/Resources/DWARF/libsample.dylib" \
  "audit_make_dsyms: idempotent re-run keeps the .dSYM"

# ── Missing-tool / bad-input contract: never errors, returns 0 ──
rc=0; audit_make_dsyms "$TEST_TMPDIR/does-not-exist" || rc=$?
assert_eq 0 "$rc" "audit_make_dsyms: no-op (rc 0) on a missing build dir"

# ── audit_make_dsyms_for_target: every sanitizer build, not just asan ──
# The audit/benchmark fresh-build paths repair via the target-level wrapper,
# which must cover build-ubsan/msan/tsan too — not hardcode build-asan. The
# copied dylibs keep their debug map pointing at the still-present sample.o.
troot="$TEST_TMPDIR/troot"
mkdir -p "$troot/build-asan" "$troot/build-ubsan"
cp "$build/libsample.dylib" "$troot/build-asan/"
cp "$build/libsample.dylib" "$troot/build-ubsan/"
audit_make_dsyms_for_target "$troot"
assert_file_exists "$troot/build-asan/libsample.dylib.dSYM/Contents/Resources/DWARF/libsample.dylib" \
  "audit_make_dsyms_for_target: produced a .dSYM for build-asan"
assert_file_exists "$troot/build-ubsan/libsample.dylib.dSYM/Contents/Resources/DWARF/libsample.dylib" \
  "audit_make_dsyms_for_target: produced a .dSYM for build-ubsan (all sanitizers, not just asan)"

rc=0; audit_make_dsyms_for_target "$TEST_TMPDIR/no-such-target" || rc=$?
assert_eq 0 "$rc" "audit_make_dsyms_for_target: no-op (rc 0) on a missing target root"

summary
