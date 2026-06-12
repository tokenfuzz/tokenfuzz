#!/usr/bin/env bash
# tests/test_triage_parallel.sh — the bounded worker pool that runs
# independent CRASH-*/FIND-* triage pipelines concurrently
# (lib/triage.sh: _triage_dir_pool_size, triage_crash_dirs,
# validate_find_gate).
#
# Coverage:
#   1. TRIAGE_DIR_PARALLEL resolves: default 4, floor 1, garbage → 4.
#   2. Parallel sweep (pool=4) produces the same dispositions as the
#      serial sweep (pool=1): keepers stay, auto-discards move to
#      crashes-rejected/, and the aggregated REJECT count in the index
#      log is exact (outcome files survive the subshell boundary).
#   3. validate_find_gate touches every FIND dir under the pool
#      (markers written per dir) and respects .keep pins.

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/llm_decide.sh"
source "$SCRIPT_ROOT/lib/triage.sh"

setup_test_env

# Deterministic gates only: no LLM, no reachability, no confirm agent.
export LLM_DECIDE_DISABLE=1
export REACHABILITY_AUTO=0
export CRASH_CONFIRM_AUTO=0
export LLM_FIELD_FILL_DISABLE=1
export FIND_CLUSTER_DISABLE=1

# ── 1. pool-size resolution ─────────────────────────────────────────
assert_eq 4 "$(_triage_dir_pool_size)" "pool size defaults to 4"
assert_eq 2 "$(TRIAGE_DIR_PARALLEL=2 _triage_dir_pool_size)" "pool size honors TRIAGE_DIR_PARALLEL"
assert_eq 1 "$(TRIAGE_DIR_PARALLEL=0 _triage_dir_pool_size)" "pool size floors at 1"
assert_eq 4 "$(TRIAGE_DIR_PARALLEL=banana _triage_dir_pool_size)" "garbage pool size falls back to 4"

# ── fixtures ────────────────────────────────────────────────────────
mk_keeper_crash() {
  # Complete artifact set + memory-safety class: survives every
  # deterministic gate with the LLM disabled.
  local d="$RESULTS_DIR/crashes/$1"
  mkdir -p "$d"
  cat > "$d/asan.txt" <<'EOF'
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000001
WRITE of size 4 at 0x602000000001 thread T0
    #0 0x100 in app_parse src/app.c:42
SUMMARY: AddressSanitizer: heap-buffer-overflow src/app.c:42 in app_parse
EOF
  cat > "$d/report.md" <<'EOF'
# CRASH: heap-buffer-overflow in app_parse
Caller contract: obeyed
Trigger source: bytes
A length prefix is used without a bounds check.
EOF
  printf '0123456789abcdef0123456789abcdef\n' > "$d/testcase.bin"
}

mk_discard_crash() {
  # Null-deref trace: the regex auto-discard fires with the LLM
  # undecided, so the dir must move to crashes-rejected/.
  local d="$RESULTS_DIR/crashes/$1"
  mkdir -p "$d"
  cat > "$d/asan.txt" <<'EOF'
==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
Hint: address points to the zero page.
    #0 0x100 in app_parse src/app.c:42
SUMMARY: AddressSanitizer: SEGV src/app.c:42 in app_parse
EOF
  cat > "$d/report.md" <<'EOF'
# CRASH: null deref in app_parse
EOF
  printf '0123456789abcdef0123456789abcdef\n' > "$d/testcase.bin"
}

run_sweep() {
  local pool="$1"
  rm -rf "$RESULTS_DIR/crashes" "$RESULTS_DIR/crashes-rejected"
  mkdir -p "$RESULTS_DIR/crashes" "$RESULTS_DIR/crashes-rejected"
  : > "$INDEX"
  local i
  for i in 1 2 3 4 5; do mk_keeper_crash "CRASH-KEEP-$i"; done
  for i in 1 2 3; do mk_discard_crash "CRASH-DROP-$i"; done
  TRIAGE_DIR_PARALLEL="$pool" triage_crash_dirs >/dev/null 2>&1 || true
}

check_sweep() {
  local label="$1"
  local kept dropped
  kept=$(find "$RESULTS_DIR/crashes" -maxdepth 1 -type d -name 'CRASH-KEEP-*' 2>/dev/null | wc -l | tr -d ' ')
  dropped=$(find "$RESULTS_DIR/crashes-rejected" -maxdepth 1 -type d -name 'CRASH-DROP-*' 2>/dev/null | wc -l | tr -d ' ')
  assert_eq 5 "$kept" "$label: all 5 keepers stay in crashes/"
  assert_eq 3 "$dropped" "$label: all 3 null-derefs moved to crashes-rejected/"
  assert_file_contains "$INDEX" "REJECT: 3 crash dir" \
    "$label: aggregated reject count is exact across workers"
}

# ── 2. parallel and serial sweeps agree ─────────────────────────────
run_sweep 4
check_sweep "pool=4"
run_sweep 1
check_sweep "pool=1"

# ── 3. find gate pool touches every dir, honors .keep ───────────────
rm -rf "$RESULTS_DIR/findings"
mkdir -p "$RESULTS_DIR/findings"
for i in 1 2 3 4; do
  mkdir -p "$RESULTS_DIR/findings/FIND-EMPTY-$i"   # no report → .needs-content
done
mkdir -p "$RESULTS_DIR/findings/FIND-PINNED-1"
touch "$RESULTS_DIR/findings/FIND-PINNED-1/.keep"
TRIAGE_DIR_PARALLEL=4 validate_find_gate >/dev/null 2>&1 || true
for i in 1 2 3 4; do
  assert_file_exists "$RESULTS_DIR/findings/FIND-EMPTY-$i/.needs-content" \
    "find pool processed FIND-EMPTY-$i"
done
if [ -f "$RESULTS_DIR/findings/FIND-PINNED-1/.needs-content" ]; then
  fail "pinned FIND skipped by the gate" ".needs-content written despite .keep"
else
  pass "pinned FIND skipped by the gate"
fi

teardown_test_env
summary
