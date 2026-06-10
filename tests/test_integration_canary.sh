#!/usr/bin/env bash
# Integration test for the canary ground-truth target.
#
# Builds targets/canary with AddressSanitizer and drives every planted bug
# and false-positive trap straight from targets/canary/ground-truth.json,
# so the manifest is self-checking: if canary.c drifts from its answer key
# (a bug stops firing, changes primitive, or loses its frame), this fails.
# It also confirms the two FP traps are correctly *not* counted as security
# crashes by the real lib/triage.sh autodiscard gate.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/triage.sh"

# The canary is a committed target (targets/ is gitignored except this one;
# see .gitignore). Build into TEST_TMPDIR; never touch its build-asan dir.
# The answer key lives OUTSIDE the target tree (output/canary/, not handed to
# audited agents) so the benchmark score stays blind; the test reads it here.
CANARY="$SCRIPT_ROOT/targets/canary"
MANIFEST="$SCRIPT_ROOT/output/canary/ground-truth.json"

assert_file_exists "$MANIFEST" "ground-truth manifest present"

CC="${CC:-clang}"
command -v "$CC" >/dev/null 2>&1 || CC=cc
if ! command -v "$CC" >/dev/null 2>&1; then
  echo "  (no C compiler — skipping canary build assertions)"
  summary
  exit 0
fi

# ── Build ────────────────────────────────────────────────────────────
BUILD="$TEST_TMPDIR/build-asan"
build_log="$TEST_TMPDIR/build.log"
if CC="$CC" bash "$CANARY/.audit/build.sh" "$CANARY" "$BUILD" > "$build_log" 2>&1; then
  pass "canary builds with AddressSanitizer"
else
  fail "canary builds with AddressSanitizer" "$(tail -5 "$build_log")"
  summary
  exit 1
fi
BIN="$BUILD/canary"
assert_file_exists "$BIN" "canary ASan binary produced"

# handle_abort=1 mirrors lib/sanitizer_options.conf so the assert trap is
# reported as an ASan ABRT (with the __assert frame the gate keys on).
# abort_on_error=0 makes ASan _exit(1) instead of raising SIGABRT, which
# keeps the report content identical but avoids job-control noise on the
# test's stderr from signal-killed children.
export ASAN_OPTIONS="handle_abort=1:detect_leaks=0:abort_on_error=0"

run_input() { "$BIN" "$CANARY/inputs/$1" > "$TEST_TMPDIR/out.txt" 2>&1; }

# ── Real planted bugs: each must fire its manifest primitive + symbol ──
while IFS='|' read -r id primitive symbol input; do
  [ -n "$id" ] || continue
  assert_file_exists "$CANARY/$input" "[$id] input committed"
  run_input "${input#inputs/}" >/dev/null
  out=$(cat "$TEST_TMPDIR/out.txt")
  assert_match "AddressSanitizer: $primitive" "$out" "[$id] fires $primitive"
  assert_match "$symbol" "$out" "[$id] stack carries planted frame $symbol"
  # The real triage gate must KEEP a clean memory-safety crash (exit 1).
  is_autodiscard_crash_output "$TEST_TMPDIR/out.txt"
  assert_eq 1 $? "[$id] triage keeps the crash (not autodiscarded)"
done < <(python3 - "$MANIFEST" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
for b in m.get("planted_bugs", []):
    if b.get("kind", "real") == "real":
        print("|".join([b["id"], b["primitive"], b["signature_symbol"], b["input"]]))
PY
)

# ── FP trap 1: guarded null-deref — no sanitizer diagnostic at all ────
run_input case-lookup >/dev/null
out=$(cat "$TEST_TMPDIR/out.txt")
assert_not_match "AddressSanitizer:" "$out" "guarded null-deref produces no sanitizer error"

# ── FP trap 2: debug-only assert — aborts, autodiscarded, not a mem bug ─
run_input case-pack >/dev/null
out=$(cat "$TEST_TMPDIR/out.txt")
assert_not_match "heap-buffer-overflow|stack-buffer-overflow|use-after-free" \
  "$out" "assert trap is not a memory-safety crash"
is_autodiscard_crash_output "$TEST_TMPDIR/out.txt"
assert_eq 0 $? "assert trap is autodiscarded by triage (debug ABRT, not security)"

summary
