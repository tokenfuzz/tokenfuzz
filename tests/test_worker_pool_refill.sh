#!/usr/bin/env bash
# tests/test_worker_pool_refill.sh — continuous worker pool.
#
# A slot whose agent exits early while at least one other slot is
# still running gets a single replacement launch in that slot. The
# replacement uses the same role_prefix and prompt builder.
#
# Pins:
#   1. Slots that finish early during another slot's run get one refill,
#      observed via per-agent role names with the `-r1` suffix.
#   2. The last slot to finish never refills (any_active=0 guard) —
#      iter wall-time stays bounded by the slowest initial agent.
#   3. Per-slot refills are capped at 1: a slot that already used its
#      refill does not refill again even if other slots are still
#      running.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

audit_extract_function() {
  local name="$1"
  awk -v name="$name" '
    $0 ~ "^" name "\\(\\) \\{" { in_func=1 }
    in_func { print }
    in_func && $0 == "}" { exit }
  ' "$SCRIPT_ROOT/bin/audit"
}

log() { printf '%s\n' "$*" >> "$INDEX"; }
INDEX="$TEST_TMPDIR/index.log"
touch "$INDEX"

# Stubs for the launch-side helpers _launch_agent_into_slot calls.
LAUNCHES_LOG="$TEST_TMPDIR/launches.log"
: > "$LAUNCHES_LOG"

# Agent durations per slot (in seconds). Used by the fake prompt
# builder to encode "this agent finishes in N seconds" into the prompt,
# which the fake run_agent reads back. Slot 1 is slow (2s), slot 2 is
# fast (0s), slot 3 is fast (0s) — so slots 2 and 3 should refill while
# slot 1 is still running.
AGENT_DUR=()
AGENT_DUR[1]=2
AGENT_DUR[2]=0
AGENT_DUR[3]=0

# Fake the per-agent helpers _launch_agent_into_slot delegates to.
get_agent_subsystem() { echo "src/parser.c"; }
agent_mode() { echo "generic"; }
neutralize_qa_vocab_string() { cat; }
strip_novocab_markers() { cat; }
estimate_tokens() { printf '%d\n' "$(($(wc -c <<<"$1") / 4))"; }
fmt_count() { printf '%s\n' "$1"; }
write_prompt_artifacts() {
  # arg 1=ts, 2=role_name; just return a stable path
  printf '%s\n' "$TEST_TMPDIR/prompt-${2}.md"
}
log_agent_plan() {
  # arg 1=slot, 2=role_prefix, 3=role_name
  printf 'PLAN slot=%s role=%s\n' "$1" "$3" >> "$LAUNCHES_LOG"
}
# Fake run_agent: sleep the requested duration, then exit 0. Duration
# pulled from AGENT_DUR. Refills (second+ launch) sleep 0 — they finish
# fast so the loop can terminate quickly. Records itself in the
# launches log keyed by role name so the test can grep for refills.
run_agent() {
  local role_name="$1" slot="$2" model="$3" turns="$4" prompt="$5" ts="$6"
  printf 'LAUNCH slot=%s role=%s\n' "$slot" "$role_name" >> "$LAUNCHES_LOG"
  # Sleep duration: from prompt string (initial) or 0 (refill).
  local dur
  if [[ "$role_name" == *"-r"* ]]; then
    dur=0
  else
    dur="${AGENT_DUR[$slot]:-0}"
  fi
  sleep "$dur"
}
record_subsystem_claim() { :; }
normalize_agent_exit_code() { echo "0"; }

# A trivial prompt builder: echo a recognizable string so the launch
# log includes the slot number.
fake_prompt_builder() { printf 'prompt-for-slot-%s\n' "$1"; }

MAX_TURNS_ANALYSIS=10
MODEL="stub"
ACTIVE_BACKEND="codex"
RAW_DIR="$TEST_TMPDIR/raw"
mkdir -p "$RAW_DIR"
NUM_AGENTS=3

eval "$(audit_extract_function _launch_agent_into_slot)"
eval "$(audit_extract_function signal_name_for_exit_status)"
eval "$(audit_extract_function _finalize_agent_slot)"
eval "$(audit_extract_function _should_refill_slot)"
eval "$(audit_extract_function launch_agents_and_wait)"

# ─────────────────────────────────────────────────────────────────────
# 1. Slots 2 & 3 finish in 0s while slot 1 is still running, so both
#    refill once. Slot 1 never refills — it's the last to finish,
#    so any_active=0 when it exits.
# ─────────────────────────────────────────────────────────────────────
: > "$LAUNCHES_LOG"
: > "$INDEX"
launch_agents_and_wait "cold-start" fake_prompt_builder "20260528_000001" >/dev/null

launches_total=$(grep -c "^LAUNCH" "$LAUNCHES_LOG")
# Initial 3 + 2 refills (slots 2 and 3) = 5.
assert_eq 5 "$launches_total" "default: 3 initial + 2 refill = 5 launches total"
refill_count=$(awk '/^LAUNCH / && $3 ~ /-r1$/ {n++} END {print n+0}' "$LAUNCHES_LOG")
assert_eq 2 "$refill_count" "default: 2 slots refilled exactly once each"

# Slot 1 (the slow one) must NEVER refill — it's the last alive when
# it exits, so any_active=0 blocks the refill predicate.
slot1_refills=$(awk '/^LAUNCH / && $2 == "slot=1" && $3 ~ /-r/ {n++} END {print n+0}' "$LAUNCHES_LOG")
assert_eq 0 "$slot1_refills" "default: slot 1 (last to finish) never refills"

# Slot 2 and slot 3 each get exactly one refill.
slot2_refills=$(awk '/^LAUNCH / && $2 == "slot=2" && $3 ~ /-r/ {n++} END {print n+0}' "$LAUNCHES_LOG")
slot3_refills=$(awk '/^LAUNCH / && $2 == "slot=3" && $3 ~ /-r/ {n++} END {print n+0}' "$LAUNCHES_LOG")
assert_eq 1 "$slot2_refills" "default: slot 2 refilled once"
assert_eq 1 "$slot3_refills" "default: slot 3 refilled once"

assert_file_contains "$INDEX" "Worker-pool refill: slot 2" \
  "default: refill of slot 2 announced in index.log"
assert_file_contains "$INDEX" "Worker-pool refill: slot 3" \
  "default: refill of slot 3 announced in index.log"

# ─────────────────────────────────────────────────────────────────────
# 2. _should_refill_slot unit truth table (independent of orchestrator).
# ─────────────────────────────────────────────────────────────────────
_should_refill_slot 1 0 0; rc=$?
assert_eq 1 "$rc" "_should_refill_slot: no other agents running → false"

# A slot that already used its single refill cannot refill again, even
# if other agents are still running.
_should_refill_slot 1 1 1; rc=$?
assert_eq 1 "$rc" "_should_refill_slot: per-slot cap (1) already reached → false"

_should_refill_slot 1 0 1; rc=$?
assert_eq 0 "$rc" "_should_refill_slot: under-cap + other running → true"

# ─────────────────────────────────────────────────────────────────────
# 4. A signal-killed agent (wait status 128+N) is flagged distinctly from a
#    plain non-zero exit, so an external kill is diagnosable at reap time.
# ─────────────────────────────────────────────────────────────────────
: > "$INDEX"
# Identity normalize so the signal status is not masked to 0 for this case.
normalize_agent_exit_code() { echo "${2:-0}"; }
bash -c 'kill -TERM $$' & sig_pid=$!
_finalize_agent_slot 2 "deep_investigation" "deep_investigation-2-generic-r1" \
  "$sig_pid" "unknown" "20260528_000003"
assert_eq 143 "$_slot_rc" "_finalize_agent_slot: reap status is 128+SIGTERM (143)"
assert_file_contains "$INDEX" "signal-range status 143" \
  "_finalize_agent_slot: signal-killed agent flagged distinctly from a plain exit"
# Agents do not run under timeout.py, so the message must not send the reader to
# a per-agent wrapper log; it points at the agent's own raw session log instead.
assert_file_not_contains "$INDEX" "timeout.py" \
  "_finalize_agent_slot: does not cite a non-existent per-agent timeout wrapper"
assert_file_contains "$INDEX" "session_20260528_000003_deep_investigation-2-generic-r1.log.raw" \
  "_finalize_agent_slot: points at the agent's own raw session log"

: > "$INDEX"
normalize_agent_exit_code() { echo "255"; }
bash -c 'exit 255' & high_pid=$!
_finalize_agent_slot 2 "deep_investigation" "deep_investigation-2-generic-r1" \
  "$high_pid" "unknown" "20260528_000004"
assert_eq 255 "$_slot_rc" "_finalize_agent_slot: preserves high non-signal exit status"
assert_file_not_contains "$INDEX" "signal-range status 255" \
  "_finalize_agent_slot: does not mislabel high non-signal exits as signals"
assert_file_contains "$INDEX" "exited with non-zero code 255" \
  "_finalize_agent_slot: logs high non-signal exits as ordinary non-zero exits"
normalize_agent_exit_code() { echo "0"; }

teardown_test_env
summary
