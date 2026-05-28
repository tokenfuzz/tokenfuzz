#!/usr/bin/env bash
# tests/test_housekeeping_background.sh — background housekeeping sweeper.
#
# run_post_iteration_housekeeping is split into a fast critical phase
# (strategy ROI, handoff, merged state — read by the next iter's prompt
# build) and a background phase (LLM-heavy gates and clustering passes).
# Spawning the background phase as a child process means iter N+1 can
# start without waiting for it. This file pins:
#
#   1. The critical phase runs synchronously and finishes before the
#      orchestrator returns.
#   2. The background phase runs without blocking the orchestrator.
#   3. wait_for_background_housekeeping joins an in-flight sweeper.
#   4. A second iteration waits for the prior sweeper before spawning a
#      new one — preserves the gate ordering inside the background phase.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# Pull the orchestration helpers out of bin/audit. We don't want to
# source the whole script (it eats stdin and starts agents) — extract
# just the four functions we exercise, plus a stub `log` since the
# extracted functions write to $INDEX via log.
audit_extract_function() {
  local name="$1"
  awk -v name="$name" '
    $0 ~ "^" name "\\(\\) \\{" { in_func=1 }
    in_func { print }
    in_func && $0 == "}" { exit }
  ' "$SCRIPT_ROOT/bin/audit"
}

log() { printf '%s\n' "$*"; }
INDEX="$TEST_TMPDIR/index.log"
touch "$INDEX"

# Stub the four downstream-call helpers the orchestration functions
# delegate to. Each appends to a per-stage marker so we can assert
# which phase ran. The background phase touches files with non-trivial
# delays so we can observe pre-join vs post-join state.
CRITICAL_LOG="$TEST_TMPDIR/critical.log"
BACKGROUND_LOG="$TEST_TMPDIR/background.log"
BACKGROUND_SENTINEL="$TEST_TMPDIR/background.sentinel"

record_iteration_guard_chain() { echo guard >> "$CRITICAL_LOG"; }
snapshot_quality_feedback() { echo snapshot >> "$CRITICAL_LOG"; }
warn_orphan_testcases() { echo warn_orphan >> "$CRITICAL_LOG"; }
enforce_asan_for_orphans() { echo enforce_asan >> "$CRITICAL_LOG"; }
promote_corpus_testcases() { echo promote_corpus >> "$CRITICAL_LOG"; }
refresh_handoff_file() { echo handoff >> "$CRITICAL_LOG"; }
merge_audit_state() { echo merge >> "$CRITICAL_LOG"; }

triage_crash_dirs() {
  echo triage_start >> "$BACKGROUND_LOG"
  # Simulate slow LLM work — the test asserts the critical phase
  # returns immediately while this sleep is still running.
  sleep 0.6
  echo triage_done >> "$BACKGROUND_LOG"
  touch "$BACKGROUND_SENTINEL"
}
warn_persistent_harness_build_failures() { echo persistent >> "$BACKGROUND_LOG"; }
validate_find_gate() { echo find_gate >> "$BACKGROUND_LOG"; }
patch_aware_rerun_review() { echo patch_review >> "$BACKGROUND_LOG"; }
expand_clusters_for_new_crashes() { echo expand >> "$BACKGROUND_LOG"; }
maintain_indexes() { echo indexes >> "$BACKGROUND_LOG"; }

# update_strategy_roi is "critical" in the new split (the next iter's
# prompt reads strategy-roi.md), so it goes under critical.
update_strategy_roi() { echo roi >> "$CRITICAL_LOG"; }

# Bypass the housekeeping_run_if_dirty dirty-bit cache: just call the
# delegate directly. The dirty-bit logic is tested separately in
# test_housekeeping_dirty.sh.
housekeeping_run_if_dirty() {
  # arg 1 = task name (unused); arg 2 = function; rest = inputs (unused)
  local _name="$1"; shift
  local fn="$1"; shift
  "$fn" "$@"
}

# Minimal stubs needed by the extracted critical phase. It calls
# state_file_path inside a for-loop, so just echo a known path.
state_file_path() { printf '%s\n' "$TEST_TMPDIR/state-$1"; }
RESULTS_DIR="$TEST_TMPDIR/results"
NUM_AGENTS=1
mkdir -p "$RESULTS_DIR/state"
: > "$RESULTS_DIR/state/hypotheses.jsonl"
TARGET_TOML="$TEST_TMPDIR/target.toml"
touch "$TARGET_TOML"
target_output_root() { echo "$TEST_TMPDIR"; }
SCRIPT_ROOT="$SCRIPT_ROOT"

eval "$(audit_extract_function wait_for_background_housekeeping)"
eval "$(audit_extract_function run_post_iteration_housekeeping_critical)"
eval "$(audit_extract_function run_post_iteration_housekeeping_background)"
eval "$(audit_extract_function run_post_iteration_housekeeping)"

# ─────────────────────────────────────────────────────────────────────
# 1. Critical phase runs all critical stages exactly once.
# ─────────────────────────────────────────────────────────────────────
: > "$CRITICAL_LOG"
run_post_iteration_housekeeping_critical >/dev/null
assert_file_contains "$CRITICAL_LOG" "guard"   "critical: guard chain ran"
assert_file_contains "$CRITICAL_LOG" "snapshot" "critical: quality snapshot ran"
assert_file_contains "$CRITICAL_LOG" "roi"      "critical: strategy ROI ran (next iter's prompt reads it)"
assert_file_contains "$CRITICAL_LOG" "handoff"  "critical: handoff file refresh ran"
assert_file_contains "$CRITICAL_LOG" "merge"    "critical: state merge ran"
assert_file_not_contains "$CRITICAL_LOG" "triage_start" \
  "critical: triage_crash_dirs is NOT in the critical phase"
assert_file_not_contains "$CRITICAL_LOG" "find_gate" \
  "critical: validate_find_gate is NOT in the critical phase"

# ─────────────────────────────────────────────────────────────────────
# 2. The orchestrator returns before the slow background gate finishes.
# ─────────────────────────────────────────────────────────────────────
: > "$CRITICAL_LOG"
: > "$BACKGROUND_LOG"
rm -f "$BACKGROUND_SENTINEL"
AUDIT_HOUSEKEEPING_BG_PID=""
start=$(date +%s)
run_post_iteration_housekeeping >/dev/null
elapsed=$(( $(date +%s) - start ))
# The critical phase + a fork is well under a second; the background
# triage takes 0.6s but we should NOT have waited for it.
[ $elapsed -lt 1 ] && pass "background default: critical+fork returns in <1s (got ${elapsed}s)" || fail "background default: critical+fork returns in <1s (got ${elapsed}s)"
[ -n "$AUDIT_HOUSEKEEPING_BG_PID" ] \
  && pass "background default: pid recorded after spawn" \
  || fail "background default: pid recorded after spawn"
# At this point the sentinel file from the slow triage MUST NOT exist —
# the background process is still mid-sleep.
[ ! -f "$BACKGROUND_SENTINEL" ] \
  && pass "background default: triage sentinel absent immediately after return" \
  || fail "background default: triage sentinel absent immediately after return"

# After joining, the background phase has produced all its markers.
wait_for_background_housekeeping
assert_file_contains "$BACKGROUND_LOG" "triage_done"  "background: triage finished after join"
assert_file_contains "$BACKGROUND_LOG" "find_gate"    "background: find_gate ran"
assert_file_contains "$BACKGROUND_LOG" "patch_review" "background: patch_review ran"
assert_file_contains "$BACKGROUND_LOG" "expand"       "background: cluster expand ran"
assert_file_contains "$BACKGROUND_LOG" "indexes"      "background: maintain_indexes ran"
assert_file_exists "$BACKGROUND_SENTINEL" \
  "background: sentinel exists after wait"
# wait_for_background_housekeeping must clear the pid so a second call
# is a free no-op.
assert_eq "" "$AUDIT_HOUSEKEEPING_BG_PID" \
  "background default: pid cleared after wait"

# ─────────────────────────────────────────────────────────────────────
# 3. Calling the orchestrator twice (two iterations) waits for the
#    prior sweeper before spawning the next — preserves background-
#    phase stage ordering across iters.
# ─────────────────────────────────────────────────────────────────────
: > "$CRITICAL_LOG"
: > "$BACKGROUND_LOG"
rm -f "$BACKGROUND_SENTINEL"
AUDIT_HOUSEKEEPING_BG_PID=""

run_post_iteration_housekeeping >/dev/null
first_pid="$AUDIT_HOUSEKEEPING_BG_PID"
[ -n "$first_pid" ] \
  && pass "iter1: first sweeper pid recorded" \
  || fail "iter1: first sweeper pid recorded"

# Second iteration's call must barrier-wait the first sweeper, then
# spawn a new one with a different pid.
run_post_iteration_housekeeping >/dev/null
second_pid="$AUDIT_HOUSEKEEPING_BG_PID"
[ -n "$second_pid" ] \
  && pass "iter2: second sweeper pid recorded" \
  || fail "iter2: second sweeper pid recorded"
[ "$first_pid" != "$second_pid" ] \
  && pass "iter2: second sweeper has a distinct pid" \
  || fail "iter2: second sweeper has a distinct pid"
# By the time the second sweeper was spawned, the first MUST have run
# to completion — the sentinel file from triage_done is present.
[ -f "$BACKGROUND_SENTINEL" ] \
  && pass "iter2: first sweeper's sentinel exists before second spawn (barrier worked)" \
  || fail "iter2: first sweeper's sentinel exists before second spawn (barrier worked)"

wait_for_background_housekeeping
teardown_test_env
summary
