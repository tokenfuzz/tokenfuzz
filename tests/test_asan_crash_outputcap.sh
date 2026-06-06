#!/usr/bin/env bash
# Tests for bin/run-asan-multi crash-output truncation via lib/output_cap.sh.
#
# The historical _digest_asan only truncated CLEAN runs. Crash runs went
# through verbatim, which meant a stack-overflow with thousands of repeated
# frames could emit 200+ KB straight into the agent transcript. The new
# behavior routes crash output past OUTCAP_MAX_BYTES through the head+tail+
# spill helper, preserving the ASan ERROR header / first ~150 frames /
# SUMMARY / ABORTING lines while elider the repeating middle.
#
# Coverage:
#   - Small crash output (≤ OUTCAP_MAX_BYTES): unchanged passthrough.
#   - Large crash output: head+tail with explicit marker, ERROR header in
#     head, SUMMARY+ABORTING in tail, mid frames elided.
#   - OUTCAP_MAX_BYTES=0 disables the new cap (legacy "never truncate on
#     crash" behavior).
#   - ASAN_NO_DIGEST=1 still bypasses everything (existing contract).

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# _digest_asan now lives in the generic normalizer; run-asan-multi is a shim.
ASAN5X="$SCRIPT_ROOT/bin/run-sanitizer-multi"

bash -n "$ASAN5X" 2>/dev/null
assert_eq 0 $? "run-sanitizer-multi: syntax check passes"
bash -n "$SCRIPT_ROOT/bin/run-asan-multi" 2>/dev/null
assert_eq 0 $? "run-asan-multi shim: syntax check passes"

# _digest_asan is an internal function — to test it directly we source the
# script with a guard that skips main-body execution. The script has no
# explicit `return` guard; instead, we extract _digest_asan via awk and
# eval it into the test shell. This avoids triggering the side effects of
# sourcing (header writes, budget accounting, etc).
DIGEST_FN_SRC="$TEST_TMPDIR/_digest_asan.sh"
awk '
  /^_digest_asan\(\) \{/ { capture=1 }
  capture { print }
  capture && /^\}$/ { capture=0 }
' "$ASAN5X" > "$DIGEST_FN_SRC"

# Sanity: we successfully captured the function.
fn_lines=$(wc -l < "$DIGEST_FN_SRC" | tr -d ' ')
[ "$fn_lines" -gt 30 ]
assert_eq 0 $? "fixture: _digest_asan extracted (${fn_lines} lines)"

# Wrapper that loads output_cap + the extracted function and runs it.
_run_digest() {
  local input="$1"
  bash -c "
    set -uo pipefail
    source '$SCRIPT_ROOT/lib/output_cap.sh'
    $(cat "$DIGEST_FN_SRC")
    OUTPUT_FILE='$2' _digest_asan '$input'
  "
}

# ── Fixture: small crash output (under cap) — should pass through ──
SMALL_CRASH="$TEST_TMPDIR/small-crash.txt"
{
  echo "==99999==ERROR: AddressSanitizer: heap-use-after-free"
  echo "READ of size 8 at 0x603000000010 thread T0"
  for i in 0 1 2 3 4 5; do
    printf '    #%d 0x401000 in some_fn /target/foo.cc:%d\n' "$i" "$((100 + i))"
  done
  echo "SUMMARY: AddressSanitizer: heap-use-after-free"
  echo "==99999==ABORTING"
} > "$SMALL_CRASH"

output=$(OUTCAP_SPILL_DIR="$TEST_TMPDIR/spill" _run_digest "$SMALL_CRASH" "/tmp/dummy.asan.txt")
assert_not_match 'output_cap: asan-crash truncated' "$output" \
  "small crash: passthrough (no cap marker)"
assert_match 'heap-use-after-free' "$output" "small crash: ERROR preserved"
assert_match '==99999==ABORTING' "$output" "small crash: ABORTING preserved"

# ── Fixture: stack-overflow with 10K frames — should truncate ──
BIG_CRASH="$TEST_TMPDIR/big-crash.txt"
{
  echo "==12345==ERROR: AddressSanitizer: stack-overflow on address 0x7ffeefbff000"
  for i in $(seq 0 10000); do
    printf '    #%d 0x100%06x in recursive_fn(int) /target/recur.cc:%d\n' "$i" "$i" "$((42 + i % 5))"
  done
  echo "SUMMARY: AddressSanitizer: stack-overflow (libxml2+0xdeadbeef)"
  echo "==12345==ABORTING"
} > "$BIG_CRASH"

big_bytes=$(wc -c < "$BIG_CRASH" | tr -d ' ')
[ "$big_bytes" -gt 100000 ]
assert_eq 0 $? "big-crash fixture: over 100 KB (got $big_bytes)"

output=$(OUTCAP_SPILL_DIR="$TEST_TMPDIR/spill" _run_digest "$BIG_CRASH" "/tmp/dummy.asan.txt")
assert_match 'output_cap: asan-crash truncated' "$output" \
  "big crash: cap marker emitted"
assert_match 'AddressSanitizer: stack-overflow' "$output" \
  "big crash: ERROR header preserved in head"
assert_match '#0 0x100000000 in recursive_fn' "$output" \
  "big crash: first stack frame preserved in head"
assert_match 'SUMMARY: AddressSanitizer: stack-overflow' "$output" \
  "big crash: SUMMARY preserved in tail"
assert_match '==12345==ABORTING' "$output" \
  "big crash: ABORTING preserved in tail"
# A mid-range frame should be elided.
assert_not_match '#5000 0x100001388 in recursive_fn' "$output" \
  "big crash: mid-range frames elided"

# Total output well under the original 100 KB+ size.
out_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$out_bytes" -lt 56000 ]
assert_eq 0 $? "big crash: capped output stays under ~55 KB (got $out_bytes)"

# ── OUTCAP_MAX_BYTES=0 restores legacy "never truncate on crash" ──
output=$(OUTCAP_MAX_BYTES=0 OUTCAP_SPILL_DIR="$TEST_TMPDIR/spill" \
  _run_digest "$BIG_CRASH" "/tmp/dummy.asan.txt")
assert_not_match 'output_cap: asan-crash truncated' "$output" \
  "OUTCAP_MAX_BYTES=0: crash passthrough (no cap marker)"
out_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$out_bytes" -gt 100000 ]
assert_eq 0 $? "OUTCAP_MAX_BYTES=0: full crash trace emitted (got $out_bytes bytes)"

# ── ASAN_NO_DIGEST=1 also bypasses (existing contract preserved) ──
output=$(ASAN_NO_DIGEST=1 OUTCAP_SPILL_DIR="$TEST_TMPDIR/spill" \
  _run_digest "$BIG_CRASH" "/tmp/dummy.asan.txt")
assert_not_match 'output_cap: asan-crash truncated' "$output" \
  "ASAN_NO_DIGEST=1: cap suppressed"
out_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
[ "$out_bytes" -gt 100000 ]
assert_eq 0 $? "ASAN_NO_DIGEST=1: full crash trace emitted (got $out_bytes bytes)"

# ── Clean run truncation (existing behavior) still works ──
# A clean run with many lines should hit the line-based digest, not the
# new byte cap, and emit the "[run-asan-multi] DIGEST: clean run" marker.
CLEAN_RUN="$TEST_TMPDIR/clean-run.txt"
{
  for i in $(seq 1 500); do
    printf 'clean line %d — diagnostic output\n' "$i"
  done
  echo "[run-asan-multi] EXECUTION_RATE: 5/5"
} > "$CLEAN_RUN"

output=$(OUTCAP_SPILL_DIR="$TEST_TMPDIR/spill" _run_digest "$CLEAN_RUN" "/tmp/dummy.asan.txt")
assert_match 'DIGEST: clean run' "$output" "clean run: line-based digest still fires"
assert_not_match 'output_cap: asan-crash truncated' "$output" \
  "clean run: no asan-crash marker (it's the clean path)"
assert_match 'EXECUTION_RATE: 5/5' "$output" "clean run: verdict line preserved in tail"

teardown_test_env
summary
