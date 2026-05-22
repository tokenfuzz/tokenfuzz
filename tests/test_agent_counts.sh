#!/usr/bin/env bash
# Parity tests for `bin/state agent-counts` and structured_state_agent_counts_load.
#
# These tests are the safety net for the bash-jq → python migration. They
# guarantee that the new one-shot Python helper returns IDENTICAL counts to
# the legacy `structured_state_agent_*_count` jq counters across every
# status the audit harness emits, including the tricky regex-suffix cases
# (CRASH-DEDUPED, FIND-LOWPRIO).
#
# A drift here would silently corrupt strategy-rotation gates and quality
# feedback — both of which steer bug-finding — so failures must block the
# migration, not be papered over.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

source "$SCRIPT_ROOT/lib/structured_state.sh"

mkdir -p "$RESULTS_DIR/state"
HYP="$RESULTS_DIR/state/hypotheses.jsonl"

# ── Helper: emit one hypothesis row with the given agent/status ────
write_row() {
  local agent="$1" status="$2" id="${3:-H-$RANDOM}"
  printf '{"id":"%s","agent":"%s","status":"%s","file":"src/lib/x.cpp"}\n' \
    "$id" "$agent" "$status" >> "$HYP"
}

# Compare the new one-shot loader's output against the legacy jq counters
# for `agent_num`. Every key must match exactly.
assert_parity_for_agent() {
  local agent_num="$1" label="$2"

  local exp_pending exp_active exp_discards exp_env exp_needs exp_result exp_invest
  exp_pending=$(structured_state_agent_pending_count "$agent_num" 2>/dev/null || echo 0)
  exp_active=$(structured_state_agent_active_count "$agent_num" 2>/dev/null || echo 0)
  exp_discards=$(structured_state_agent_discard_count "$agent_num" 2>/dev/null || echo 0)
  exp_env=$(structured_state_agent_env_blocked_count "$agent_num" 2>/dev/null || echo 0)
  exp_needs=$(structured_state_agent_needs_testcase_count "$agent_num" 2>/dev/null || echo 0)
  exp_result=$(structured_state_agent_result_count "$agent_num" 2>/dev/null || echo 0)
  exp_invest=$(structured_state_count_agent_status_regex "$agent_num" '^INVESTIGATING$' 2>/dev/null || echo 0)
  exp_pending=${exp_pending:-0}; exp_active=${exp_active:-0}; exp_discards=${exp_discards:-0}
  exp_env=${exp_env:-0}; exp_needs=${exp_needs:-0}; exp_result=${exp_result:-0}; exp_invest=${exp_invest:-0}

  local p=0 a=0 d=0 e=0 n=0 r=0 i=0
  if structured_state_agent_counts_load "$agent_num" p a d e n r i; then
    assert_eq "$exp_pending"  "$p" "$label: pending parity"
    assert_eq "$exp_active"   "$a" "$label: active parity"
    assert_eq "$exp_discards" "$d" "$label: discards parity"
    assert_eq "$exp_env"      "$e" "$label: env_blocked parity"
    assert_eq "$exp_needs"    "$n" "$label: needs_testcase parity"
    assert_eq "$exp_result"   "$r" "$label: result parity"
    assert_eq "$exp_invest"   "$i" "$label: investigating parity"
  else
    # Loader fell through (no rows for this agent). Legacy counters must
    # also report all zeros — otherwise we have a real divergence.
    assert_eq "0" "$exp_pending"  "$label: loader fall-through implies pending=0"
    assert_eq "0" "$exp_active"   "$label: loader fall-through implies active=0"
    assert_eq "0" "$exp_discards" "$label: loader fall-through implies discards=0"
    assert_eq "0" "$exp_env"      "$label: loader fall-through implies env_blocked=0"
    assert_eq "0" "$exp_needs"    "$label: loader fall-through implies needs_testcase=0"
    assert_eq "0" "$exp_result"   "$label: loader fall-through implies result=0"
    assert_eq "0" "$exp_invest"   "$label: loader fall-through implies investigating=0"
  fi
}

# Same parity check, but against the canonical JSON form of the subcommand.
assert_json_parity_for_agent() {
  local agent_num="$1" label="$2"

  local out
  out=$("$SCRIPT_ROOT/bin/state" --results-dir "$RESULTS_DIR" \
        --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
        agent-counts --agent "$agent_num" 2>/dev/null) || {
    fail "$label: bin/state agent-counts exited non-zero"
    return
  }

  local exp_pending exp_active exp_discards exp_env exp_needs exp_result exp_invest
  exp_pending=$(structured_state_agent_pending_count "$agent_num" 2>/dev/null || echo 0)
  exp_active=$(structured_state_agent_active_count "$agent_num" 2>/dev/null || echo 0)
  exp_discards=$(structured_state_agent_discard_count "$agent_num" 2>/dev/null || echo 0)
  exp_env=$(structured_state_agent_env_blocked_count "$agent_num" 2>/dev/null || echo 0)
  exp_needs=$(structured_state_agent_needs_testcase_count "$agent_num" 2>/dev/null || echo 0)
  exp_result=$(structured_state_agent_result_count "$agent_num" 2>/dev/null || echo 0)
  exp_invest=$(structured_state_count_agent_status_regex "$agent_num" '^INVESTIGATING$' 2>/dev/null || echo 0)
  exp_pending=${exp_pending:-0}; exp_active=${exp_active:-0}; exp_discards=${exp_discards:-0}
  exp_env=${exp_env:-0}; exp_needs=${exp_needs:-0}; exp_result=${exp_result:-0}; exp_invest=${exp_invest:-0}

  assert_eq "$exp_pending"  "$(printf '%s' "$out" | jq -r '.pending')"        "$label: JSON pending parity"
  assert_eq "$exp_active"   "$(printf '%s' "$out" | jq -r '.active')"         "$label: JSON active parity"
  assert_eq "$exp_discards" "$(printf '%s' "$out" | jq -r '.discards')"       "$label: JSON discards parity"
  assert_eq "$exp_env"      "$(printf '%s' "$out" | jq -r '.env_blocked')"    "$label: JSON env_blocked parity"
  assert_eq "$exp_needs"    "$(printf '%s' "$out" | jq -r '.needs_testcase')" "$label: JSON needs_testcase parity"
  assert_eq "$exp_result"   "$(printf '%s' "$out" | jq -r '.result')"         "$label: JSON result parity"
  assert_eq "$exp_invest"   "$(printf '%s' "$out" | jq -r '.investigating')"  "$label: JSON investigating parity"
}

# ═══════════════════════════════════════════════════════════════
# 1. Missing state file → all zeros, exit 0
# ═══════════════════════════════════════════════════════════════
rm -f "$HYP"
out=$("$SCRIPT_ROOT/bin/state" --results-dir "$RESULTS_DIR" \
      --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
      agent-counts --agent 1 2>/dev/null)
assert_exit_code 0 "missing state: bin/state still exits 0"
assert_eq "0" "$(printf '%s' "$out" | jq -r '.pending')" "missing state: pending=0"
assert_eq "0" "$(printf '%s' "$out" | jq -r '.active')"  "missing state: active=0"
assert_eq "0" "$(printf '%s' "$out" | jq -r '.result')"  "missing state: result=0"

# ═══════════════════════════════════════════════════════════════
# 2. Empty state file → all zeros (parity with structured_state.sh)
# ═══════════════════════════════════════════════════════════════
: > "$HYP"
assert_parity_for_agent 1 "empty state"
assert_json_parity_for_agent 1 "empty state"

# ═══════════════════════════════════════════════════════════════
# 3. All status types covered, single agent
# ═══════════════════════════════════════════════════════════════
: > "$HYP"
write_row 1 PENDING        H-A1-1
write_row 1 INVESTIGATING  H-A1-2
write_row 1 NEEDS_TESTCASE H-A1-3
write_row 1 DISCARDED      H-A1-4
write_row 1 ENV-BLOCKED    H-A1-5
write_row 1 CRASH          H-A1-6
write_row 1 CRASH-DEDUPED  H-A1-7
write_row 1 FIND           H-A1-8
write_row 1 FIND-LOWPRIO   H-A1-9
assert_parity_for_agent 1 "full coverage agent 1"
assert_json_parity_for_agent 1 "full coverage agent 1"

# Counts we deliberately spell out — guards against accidental regex drift
# in either implementation.
p=0 a=0 d=0 e=0 n=0 r=0 i=0
structured_state_agent_counts_load 1 p a d e n r i
assert_eq "1" "$p" "agent 1 explicit: pending=1"
assert_eq "3" "$a" "agent 1 explicit: active=3 (PENDING+INVESTIGATING+NEEDS_TESTCASE)"
assert_eq "1" "$d" "agent 1 explicit: discards=1"
assert_eq "1" "$e" "agent 1 explicit: env_blocked=1"
assert_eq "1" "$n" "agent 1 explicit: needs_testcase=1"
assert_eq "4" "$r" "agent 1 explicit: result=4 (CRASH+CRASH-DEDUPED+FIND+FIND-LOWPRIO)"
assert_eq "1" "$i" "agent 1 explicit: investigating=1"

# ═══════════════════════════════════════════════════════════════
# 4. Multi-agent rows — one agent's counts must not bleed into another's
# ═══════════════════════════════════════════════════════════════
: > "$HYP"
# Agent 1: 2 pending, 1 discard
write_row 1 PENDING   H-A1-x1
write_row 1 PENDING   H-A1-x2
write_row 1 DISCARDED H-A1-x3
# Agent 2: 1 needs_testcase, 1 crash-deduped, 1 env-blocked
write_row 2 NEEDS_TESTCASE H-A2-y1
write_row 2 CRASH-DEDUPED  H-A2-y2
write_row 2 ENV-BLOCKED    H-A2-y3
# Agent 3: 1 investigating, 1 find
write_row 3 INVESTIGATING H-A3-z1
write_row 3 FIND          H-A3-z2

assert_parity_for_agent 1 "multi-agent agent 1"
assert_parity_for_agent 2 "multi-agent agent 2"
assert_parity_for_agent 3 "multi-agent agent 3"
assert_parity_for_agent 99 "multi-agent unknown agent (fall-through)"
assert_json_parity_for_agent 1 "multi-agent agent 1 JSON"
assert_json_parity_for_agent 2 "multi-agent agent 2 JSON"
assert_json_parity_for_agent 3 "multi-agent agent 3 JSON"

# Spot-check the cross-agent isolation explicitly.
p1=0 a1=0 d1=0 e1=0 n1=0 r1=0 i1=0
p2=0 a2=0 d2=0 e2=0 n2=0 r2=0 i2=0
structured_state_agent_counts_load 1 p1 a1 d1 e1 n1 r1 i1
structured_state_agent_counts_load 2 p2 a2 d2 e2 n2 r2 i2
assert_eq "2" "$p1" "isolation: agent 1 sees only its own pending"
assert_eq "0" "$p2" "isolation: agent 2 has no pending"
assert_eq "0" "$n1" "isolation: agent 1 has no needs_testcase"
assert_eq "1" "$n2" "isolation: agent 2 sees its own needs_testcase"
assert_eq "0" "$r1" "isolation: agent 1 has no result"
assert_eq "1" "$r2" "isolation: agent 2 sees its CRASH-DEDUPED as result"

# ═══════════════════════════════════════════════════════════════
# 5. Robustness: malformed JSONL line is skipped, not fatal
# ═══════════════════════════════════════════════════════════════
: > "$HYP"
write_row 1 PENDING H-A1-good
printf '{not really json\n' >> "$HYP"
write_row 1 DISCARDED H-A1-good2
out=$("$SCRIPT_ROOT/bin/state" --results-dir "$RESULTS_DIR" \
      --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
      agent-counts --agent 1 2>/dev/null)
assert_exit_code 0 "malformed line: bin/state still exits 0"
assert_eq "1" "$(printf '%s' "$out" | jq -r '.pending')"  "malformed line: pending counted"
assert_eq "1" "$(printf '%s' "$out" | jq -r '.discards')" "malformed line: discards counted"

# ═══════════════════════════════════════════════════════════════
# 6. Empty agent param defaults to all zeros (defensive)
# ═══════════════════════════════════════════════════════════════
: > "$HYP"
write_row 1 PENDING H-leak
out=$("$SCRIPT_ROOT/bin/state" --results-dir "$RESULTS_DIR" \
      --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
      agent-counts --agent "" 2>/dev/null)
assert_exit_code 0 "empty agent: bin/state still exits 0"
assert_eq "0" "$(printf '%s' "$out" | jq -r '.pending')" "empty agent: returns zero (does not match agent='')"

teardown_test_env
summary
