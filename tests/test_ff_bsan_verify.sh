#!/usr/bin/env bash
# Regression test for the verify_build helper in .agents/skills/ff-bsan/scripts/build.sh.
# The previous `nm "$bin" | grep -q "PATTERN"` form was flaky under `set -euo pipefail`:
# grep -q exits on first match, sending SIGPIPE to nm, which under pipefail surfaced
# as a non-zero pipeline status even when the symbol was present. has_symbol uses
# `grep -c` so the full stream is read and there's no SIGPIPE race.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

BUILD_SH="$SCRIPT_ROOT/.agents/skills/ff-bsan/scripts/build.sh"
assert_file_exists "$BUILD_SH" "build.sh present"
assert_file_contains "$BUILD_SH" "resolve_llvm_prefix" \
  "ff-bsan: MSan config resolves LLVM prefix dynamically"
assert_file_contains "$BUILD_SH" "if ! run_mach" \
  "ff-bsan: mach build failures are inspected before exiting"
assert_file_contains "$BUILD_SH" "clobber required for" \
  "ff-bsan: clobber-required builds retry after mach failure"
assert_file_contains "$BUILD_SH" "msan_supported" \
  "ff-bsan: MSan support is preflighted before build"
assert_file_contains "$BUILD_SH" "skipping msan requested through all" \
  "ff-bsan: all can continue when host toolchain lacks MSan"

msan_template=$(sed -n '/cat > "$mozconfig" <<EOF/,/^EOF$/p' "$BUILD_SH")
if grep -q 'LLVM_PREFIX="/opt/homebrew/opt/llvm"' <<<"$msan_template"; then
  fail "ff-bsan: generated MSan mozconfig must not hardcode Homebrew LLVM"
else
  pass "ff-bsan: generated MSan mozconfig does not hardcode Homebrew LLVM"
fi

# Extract just the has_symbol function so we can source it without executing the
# top-level argument-parsing logic in build.sh.
sed -n '/^has_symbol() {/,/^}/p' "$BUILD_SH" > "$TEST_TMPDIR/has_symbol.sh"
assert_file_contains "$TEST_TMPDIR/has_symbol.sh" "grep -c" "has_symbol uses grep -c (not -q)"

# Build a binary with many symbols, one of which matches the search pattern.
# 'nm' output for any non-trivial binary easily exceeds the pipe buffer, which
# is what triggers the SIGPIPE race when consumed by grep -q.
CBIN="$TEST_TMPDIR/many_syms"
SRC="$TEST_TMPDIR/many_syms.c"
{
  echo '#include <stdio.h>'
  for i in $(seq 1 4000); do
    echo "int __probe_marker_${i}(void){return ${i};}"
  done
  echo 'int main(void){return 0;}'
} > "$SRC"
if ! cc -O0 -o "$CBIN" "$SRC" 2>"$TEST_TMPDIR/cc.err"; then
  cat "$TEST_TMPDIR/cc.err" >&2
  fail "could not compile fixture binary"
  teardown_test_env
  summary
fi

# Sanity: nm output must be large enough to actually exercise pipe buffering.
nm_lines=$(nm "$CBIN" 2>/dev/null | wc -l | tr -d ' ')
[ "$nm_lines" -gt 1000 ] && pass "fixture nm produces $nm_lines lines (enough to fill pipe buffer)" \
  || fail "fixture nm only produced $nm_lines lines; will not exercise SIGPIPE race"

# The old `nm | grep -q PATTERN` form can fail under pipefail when grep closes
# the pipe early. Whether the producer observes SIGPIPE is scheduler/toolchain
# dependent, so do not require the historical form to fail on every host.
old_form_rc=0
bash -c 'set -euo pipefail; nm "'"$CBIN"'" 2>/dev/null | grep -q "__probe_marker_1"' || old_form_rc=$?
pass "old grep -q form is host-dependent under pipefail (exit $old_form_rc here)"

# The fixed has_symbol must succeed for a present pattern and fail for an
# absent one — both under set -euo pipefail.
bash -c "set -euo pipefail; source '$TEST_TMPDIR/has_symbol.sh'; has_symbol '$CBIN' '__probe_marker_1'"
assert_eq 0 $? "has_symbol: present symbol returns 0 under pipefail"

bash -c "set -euo pipefail; source '$TEST_TMPDIR/has_symbol.sh'; has_symbol '$CBIN' '__definitely_not_present_zzz'"
assert_eq 1 $? "has_symbol: absent symbol returns 1 under pipefail"

# Missing/unreadable binary path must not blow up the pipefail script either.
bash -c "set -euo pipefail; source '$TEST_TMPDIR/has_symbol.sh'; has_symbol '$TEST_TMPDIR/does_not_exist' '__probe_marker_1'"
assert_eq 1 $? "has_symbol: missing file returns 1 (no pipefail crash)"

teardown_test_env
summary
