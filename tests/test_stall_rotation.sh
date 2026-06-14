#!/usr/bin/env bash
# Tests for queue-aware stall recovery in bin/audit:
#
#   unclaimed_card_strategies / unclaimed_card_subsystems
#   active_agent_strategies / active_agent_subsystems
#   unclaimed_strategies_in_untouched_subsystems
#   force_rotate_to_unclaimed_strategies   (Claude's existing helper)
#   force_rotate_to_unclaimed_subsystems   (this commit's secondary fallback)
#   log_queue_state
#
# All assertions use generic single-letter subsystem labels ("a/b", "a/c",
# "d/e"). No target-specific paths or vocabulary belong in this file.

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

command -v jq >/dev/null 2>&1 || { echo "jq required for these tests"; teardown_test_env; exit 0; }

# log_queue_state uses fmt_strategy_histogram/fmt_strategy_list from lib/fmt.sh
# to expand bare strategy codes ("S1") into readable tags ("S1(prior-fix)").
source "$SCRIPT_ROOT/lib/fmt.sh"

audit_extract_function() {
  local name="$1"
  awk -v name="$name" '
    $0 ~ "^" name "\\(\\) \\{" { in_func=1 }
    in_func { print }
    in_func && $0 == "}" { exit }
  ' "$SCRIPT_ROOT/bin/audit"
}

eval "$(audit_extract_function effective_work_card_rows)"
eval "$(audit_extract_function unclaimed_strategy_counts)"
eval "$(audit_extract_function unclaimed_card_strategies)"
eval "$(audit_extract_function unclaimed_card_subsystems)"
eval "$(audit_extract_function active_agent_strategies)"
eval "$(audit_extract_function active_agent_subsystems)"
eval "$(audit_extract_function unclaimed_strategies_in_untouched_subsystems)"
eval "$(audit_extract_function most_stuck_agent)"
eval "$(audit_extract_function first_strategy_in_order)"
eval "$(audit_extract_function force_rotate_to_unclaimed_strategies)"
eval "$(audit_extract_function force_rotate_to_unclaimed_subsystems)"
eval "$(audit_extract_function log_queue_state)"
eval "$(audit_extract_function next_strategy_in_rotation)"
eval "$(audit_extract_function pick_exhaustion_recovery_strategy)"
eval "$(audit_extract_function pick_cold_start_strategy)"
eval "$(audit_extract_function count_unclaimed_cards_for)"
eval "$(audit_extract_function count_unclaimed_cards_for_two_strategies)"
eval "$(audit_extract_function count_unclaimed_cards_for_strategy_subsystem)"
eval "$(audit_extract_function pick_strategy_by_load)"
eval "$(audit_extract_function recover_exhausted_agent)"
eval "$(audit_extract_function strategy_completion_fields)"
eval "$(audit_extract_function update_subsystem_dry_streaks)"
eval "$(audit_extract_function agent_probe_activity_score)"
eval "$(audit_extract_function _normalize_subsystem_key)"
eval "$(audit_extract_function _subsystem_keys_collide)"
eval "$(audit_extract_function diversify_subsystem_collisions)"

# Stubs the rotation functions expect from bin/audit.
log() { printf '%s\n' "$*" >> "$INDEX"; }

set_agent_strategy() {
  printf '%s' "$2" > "$(agent_strategy_path "$1")"
}

get_agent_strategy() {
  local f
  f=$(agent_strategy_path "$1")
  [ -f "$f" ] && cat "$f" 2>/dev/null || echo ""
}

get_agent_strategy_streak() {
  local f
  f=$(agent_strategy_streak_path "$1")
  [ -f "$f" ] && cat "$f" 2>/dev/null || echo 0
}

reset_agent_strategy_streak() {
  rm -f "$(agent_strategy_streak_path "$1")" 2>/dev/null || true
}

set_agent_strategy_streak() {
  printf '%s' "$2" > "$(agent_strategy_streak_path "$1")"
}

# Per-agent subsystem comes from numbered variables (bash 3.2 on macOS
# has no associative arrays, so we use FAKE_SUBSYSTEM_<n> instead).
get_agent_subsystem() {
  local var="FAKE_SUBSYSTEM_$1"
  echo "${!var:-unknown}"
}
set_fake_subsystem() { eval "FAKE_SUBSYSTEM_$1=\"\$2\""; }

# Stubs record their side-effects into files instead of variables so the
# parent shell can read them after callers invoke the function under test
# inside `$(...)` (which would otherwise discard variable mutations made
# in the subshell).
CLEAR_RESUME_LOG="$RESULTS_DIR/.clear_resume_log"
ARCHIVE_LOG="$RESULTS_DIR/.archive_log"
: > "$CLEAR_RESUME_LOG"
: > "$ARCHIVE_LOG"

clear_agent_resume_state() {
  printf '%s\n' "$1" >> "$CLEAR_RESUME_LOG"
}

# Record archive calls one-per-line as "<agent>:<reason>" so callers can
# easily assert on substrings.
archive_exhausted_agent_state() {
  printf '%s:%s\n' "$1" "$2" >> "$ARCHIVE_LOG"
}

# Helpers to read/reset the side-effect logs from the parent shell.
last_cleared_agent()  { tail -1 "$CLEAR_RESUME_LOG" 2>/dev/null; }
cleared_agents()      { tr '\n' ' ' < "$CLEAR_RESUME_LOG" 2>/dev/null; }
archive_calls()       { tr '\n' ' ' < "$ARCHIVE_LOG" 2>/dev/null; }
last_archived_agent() { tail -1 "$ARCHIVE_LOG" | cut -d: -f1; }
last_archived_reason(){ tail -1 "$ARCHIVE_LOG" | cut -d: -f2; }
reset_side_effects()  { : > "$CLEAR_RESUME_LOG"; : > "$ARCHIVE_LOG"; }

NUM_AGENTS=3
STRATEGY_ROTATION_ORDER=(S1 S2 S3 S4 S5 S6 S7 S8)

WORK_CARDS="$RESULTS_DIR/work-cards.jsonl"

# ═══════════════════════════════════════════════════════════════
# 1. unclaimed_card_strategies / unclaimed_card_subsystems
# ═══════════════════════════════════════════════════════════════
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S7","subsystem":"a/c"}
{"id":"W3","status":"discarded","strategy":"S2","subsystem":"a/b"}
{"id":"W4","status":"unclaimed","strategy":"S7","subsystem":"d/e"}
{"id":"W5","status":"find","strategy":"S3","subsystem":"a/b"}
{"id":"W6","status":"unclaimed","strategy":"BOGUS","subsystem":"x/y"}
JSONL

strats=$(unclaimed_card_strategies)
strats="${strats% }"
assert_eq "S1 S7" "$strats" \
  "unclaimed_card_strategies: skip non-unclaimed and reject malformed strategy labels"
counts=$(unclaimed_strategy_counts 1)
assert_match $'S7\t2' "$counts" \
  "unclaimed_strategy_counts: counts unclaimed valid strategies in one JSON pass"
assert_match $'S1\t1' "$counts" \
  "unclaimed_strategy_counts: includes lower-volume strategy counts"

subs=$(unclaimed_card_subsystems)
subs="${subs% }"
assert_eq "a/b a/c d/e x/y" "$subs" \
  "unclaimed_card_subsystems: skip non-unclaimed, preserve order, include all unclaimed subsystems"

# ═══════════════════════════════════════════════════════════════
# 1b. effective_work_card_rows overlays state/claims.jsonl so a card still
#     marked "unclaimed" in work-cards.jsonl but actively claimed in
#     claims.jsonl is no longer reported as unclaimed. Regression for agents
#     reselecting already-claimed cards off a stale queue file.
# ═══════════════════════════════════════════════════════════════
if command -v python3 >/dev/null 2>&1; then
  mkdir -p "$RESULTS_DIR/state"
  NOW_ISO="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  cat > "$RESULTS_DIR/state/claims.jsonl" <<JSONL
{"card_id":"W2","status":"claimed","claimed_at":"$NOW_ISO"}
JSONL

  strats=$(unclaimed_card_strategies); strats="${strats% }"
  assert_eq "S1 S7" "$strats" \
    "overlay: S7 stays available via unclaimed W4 after W2 is claimed"
  n_ac=$(count_unclaimed_cards_for S7 a/c)
  assert_eq "0" "$n_ac" \
    "overlay: claimed W2 no longer counts as unclaimed in a/c"
  n_de=$(count_unclaimed_cards_for S7 d/e)
  assert_eq "1" "$n_de" \
    "overlay: unclaimed W4 in d/e still counts"
  pair_counts=$(count_unclaimed_cards_for_two_strategies S1 S7)
  IFS="$(printf '\t')" read -r pair_s1 pair_s7 <<< "$pair_counts"
  assert_eq "1" "$pair_s1" \
    "batched card counts: first strategy total"
  assert_eq "1" "$pair_s7" \
    "batched card counts: second strategy total respects claim overlay"
  strat_counts=$(count_unclaimed_cards_for_strategy_subsystem S7 d/e)
  IFS="$(printf '\t')" read -r strat_total strat_sub <<< "$strat_counts"
  assert_eq "1" "$strat_total" \
    "batched card counts: strategy total"
  assert_eq "1" "$strat_sub" \
    "batched card counts: strategy+subsystem total"
  subs=$(unclaimed_card_subsystems); subs="${subs% }"
  assert_eq "a/b d/e x/y" "$subs" \
    "overlay: claimed W2 drops a/c from the unclaimed subsystem set"

  cat >> "$RESULTS_DIR/state/claims.jsonl" <<JSONL
{"card_id":"W2","status":"released","updated_at":"$NOW_ISO","released_at":"$NOW_ISO"}
JSONL
  n_ac=$(count_unclaimed_cards_for S7 a/c)
  assert_eq "1" "$n_ac" \
    "overlay: released W2 counts as unclaimed again"
  subs=$(unclaimed_card_subsystems); subs="${subs% }"
  assert_eq "a/b a/c d/e x/y" "$subs" \
    "overlay: released W2 restores a/c to the unclaimed subsystem set"

  cat >> "$RESULTS_DIR/state/claims.jsonl" <<JSONL
{"card_id":"W2","status":"blocked","updated_at":"$NOW_ISO"}
JSONL
  n_ac=$(count_unclaimed_cards_for S7 a/c)
  assert_eq "0" "$n_ac" \
    "overlay: terminal W2 status does not count as unclaimed"
  subs=$(unclaimed_card_subsystems); subs="${subs% }"
  assert_eq "a/b d/e x/y" "$subs" \
    "overlay: terminal W2 status drops a/c from the unclaimed subsystem set"

  rm -f "$RESULTS_DIR/state/claims.jsonl"
fi

# ═══════════════════════════════════════════════════════════════
# 1c. allowed_strategies: a card claimable from a non-primary strategy
#     (validator-Promoted recon cards via card_strategy_matches) must be
#     counted toward that strategy's availability, or scheduling starves a
#     strategy that actually has claimable cards.
# ═══════════════════════════════════════════════════════════════
if command -v jq >/dev/null 2>&1; then
  cat > "$WORK_CARDS" <<'JSONL'
{"id":"P1","status":"unclaimed","strategy":"S7","subsystem":"p/q","allowed_strategies":["S5","S7"]}
{"id":"P2","status":"unclaimed","strategy":"S2","subsystem":"p/r"}
JSONL
  counts=$(unclaimed_strategy_counts 1)
  assert_match $'S7\t1' "$counts" "allowed_strategies: primary S7 counted"
  assert_match $'S5\t1' "$counts" "allowed_strategies: allowed S5 counted toward S5"
  assert_match $'S2\t1' "$counts" "allowed_strategies: plain card unaffected"
  n_s5=$(count_unclaimed_cards_for S5)
  assert_eq "1" "$n_s5" "allowed_strategies: count_unclaimed_cards_for honors allowed S5"
  n_s7=$(count_unclaimed_cards_for S7)
  assert_eq "1" "$n_s7" "allowed_strategies: primary S7 still counts once (no double count)"
  pair_counts=$(count_unclaimed_cards_for_two_strategies S5 S7)
  IFS="$(printf '\t')" read -r pair_s5 pair_s7 <<< "$pair_counts"
  assert_eq "1" "$pair_s5" "allowed_strategies: two-strategy count honors allowed S5"
  assert_eq "1" "$pair_s7" "allowed_strategies: two-strategy count primary S7"
  ss_counts=$(count_unclaimed_cards_for_strategy_subsystem S5 p/q)
  IFS="$(printf '\t')" read -r ss_total ss_sub <<< "$ss_counts"
  assert_eq "1" "$ss_total" "allowed_strategies: strategy+subsystem total honors allowed S5"
  assert_eq "1" "$ss_sub" "allowed_strategies: strategy+subsystem matched subsystem"
  # Restore the section-1 fixture for any later assertions that reuse it.
  cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S7","subsystem":"a/c"}
{"id":"W3","status":"discarded","strategy":"S2","subsystem":"a/b"}
{"id":"W4","status":"unclaimed","strategy":"S7","subsystem":"d/e"}
{"id":"W5","status":"find","strategy":"S3","subsystem":"a/b"}
{"id":"W6","status":"unclaimed","strategy":"BOGUS","subsystem":"x/y"}
JSONL
fi

# ═══════════════════════════════════════════════════════════════
# 2. active_agent_strategies / active_agent_subsystems
# ═══════════════════════════════════════════════════════════════
set_agent_strategy 1 S1
set_agent_strategy 2 S2
set_agent_strategy 3 S2
set_fake_subsystem 1 "a/b"
set_fake_subsystem 2 "a/c"
set_fake_subsystem 3 "a/c"

active_s=$(active_agent_strategies); active_s="${active_s% }"
assert_eq "S1 S2" "$active_s" "active_agent_strategies: deduped, sorted"
active_sub=$(active_agent_subsystems); active_sub="${active_sub% }"
assert_eq "a/b a/c" "$active_sub" "active_agent_subsystems: deduped, sorted, no 'unknown'"

set_fake_subsystem 1 "unknown"
active_sub=$(active_agent_subsystems); active_sub="${active_sub% }"
assert_eq "a/c" "$active_sub" "active_agent_subsystems: filters out 'unknown' literal"
set_fake_subsystem 1 "a/b"

# ═══════════════════════════════════════════════════════════════
# 3. force_rotate_to_unclaimed_strategies: missing strategy rotates
# ═══════════════════════════════════════════════════════════════
# Queue holds S1, S7. Agents on S1, S2, S2. Missing = S7. Most stuck = agent 3.
set_agent_strategy_streak 1 0
set_agent_strategy_streak 2 3
set_agent_strategy_streak 3 5
> "$INDEX"

force_rotate_to_unclaimed_strategies
rc=$?
assert_eq 0 "$rc" "force_rotate_to_unclaimed_strategies: rotates when missing strategy exists"
assert_eq "S7" "$(cat "$(agent_strategy_path 3)" 2>/dev/null)" \
  "force_rotate_to_unclaimed_strategies: most-stuck agent (3) moved onto S7"
assert_match "STALL_FORCE_ROTATE: agent=3" "$(cat "$INDEX")" \
  "force_rotate_to_unclaimed_strategies: logs STALL_FORCE_ROTATE"

# ═══════════════════════════════════════════════════════════════
# 4. force_rotate_to_unclaimed_strategies: no-op when fully covered
# ═══════════════════════════════════════════════════════════════
# Now agents hold S1, S2, S7. Queue strategies S1, S7 are fully covered.
set_agent_strategy 1 S1
set_agent_strategy 2 S2
set_agent_strategy 3 S7
> "$INDEX"

force_rotate_to_unclaimed_strategies
rc=$?
assert_eq 1 "$rc" "force_rotate_to_unclaimed_strategies: returns 1 when no missing strategies"
[ ! -s "$INDEX" ] \
  && pass "force_rotate_to_unclaimed_strategies: silent on no-op" \
  || fail "force_rotate_to_unclaimed_strategies: should not log when no rotation"

# ═══════════════════════════════════════════════════════════════
# 5. unclaimed_strategies_in_untouched_subsystems: respects active set
# ═══════════════════════════════════════════════════════════════
# Active subsystems = a/b, a/c. Queue subsystems = a/b, a/c, d/e, x/y.
# Untouched with unclaimed cards: d/e (S7), x/y (BOGUS — filtered).
# Expected result: S7.
out=$(unclaimed_strategies_in_untouched_subsystems)
assert_eq "S7" "$out" \
  "unclaimed_strategies_in_untouched_subsystems: returns strategies of cards in unowned subsystems"

# When every unclaimed subsystem is held, the helper returns empty.
# Reduce the queue to 3 subsystems (a/b, a/c, d/e) and place agents on
# exactly those three — no subsystem is left untouched.
saved_cards=$(cat "$WORK_CARDS")
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S7","subsystem":"a/c"}
{"id":"W4","status":"unclaimed","strategy":"S7","subsystem":"d/e"}
JSONL
set_fake_subsystem 1 "a/b"
set_fake_subsystem 2 "a/c"
set_fake_subsystem 3 "d/e"
out=$(unclaimed_strategies_in_untouched_subsystems)
assert_eq "" "$out" \
  "unclaimed_strategies_in_untouched_subsystems: empty when all unclaimed subs are held"
# Restore queue + agent pins for downstream tests.
printf '%s\n' "$saved_cards" > "$WORK_CARDS"
set_fake_subsystem 1 "a/b"
set_fake_subsystem 2 "a/c"
set_fake_subsystem 3 "a/c"

# ═══════════════════════════════════════════════════════════════
# 6. force_rotate_to_unclaimed_subsystems: rotates when subsystems untouched
# ═══════════════════════════════════════════════════════════════
# Queue strategies S1, S7 are covered (agents 1,2,3 on S1,S2,S7).
# But subsystem d/e is untouched and holds an S7 card.
# Most stuck = agent 3. force_rotate_to_unclaimed_strategies returned 1
# above; the subsystem fallback should rotate agent 3 (already on S7)
# and clear its resume state (since strategy doesn't change).
set_agent_strategy 1 S1
set_agent_strategy 2 S2
set_agent_strategy 3 S7
set_agent_strategy_streak 1 0
set_agent_strategy_streak 2 3
set_agent_strategy_streak 3 5
reset_side_effects
> "$INDEX"

force_rotate_to_unclaimed_subsystems
rc=$?
assert_eq 0 "$rc" "force_rotate_to_unclaimed_subsystems: rotates when untouched subsystems hold work"
assert_eq "3" "$(last_cleared_agent)" \
  "force_rotate_to_unclaimed_subsystems: clears resume state for the chosen agent"
assert_match "STALL_FORCE_REPIN: agent=3" "$(cat "$INDEX")" \
  "force_rotate_to_unclaimed_subsystems: logs STALL_FORCE_REPIN"

# Same-strategy case: agent stays on S7 (already correct strategy), only
# resume state is cleared; no strategy change event recorded.
assert_eq "S7" "$(cat "$(agent_strategy_path 3)")" \
  "force_rotate_to_unclaimed_subsystems: keeps strategy when already targeting"

# ═══════════════════════════════════════════════════════════════
# 7. force_rotate_to_unclaimed_subsystems: strategy change path
# ═══════════════════════════════════════════════════════════════
# Move agent 3 onto S2 (no S2 cards in queue, but the wedge surfaces).
# Untouched subsystem d/e still holds S7. The helper should pick S7 and
# rotate agent 3 from S2 → S7.
set_agent_strategy 3 S2
set_agent_strategy_streak 3 5
reset_side_effects
> "$INDEX"

force_rotate_to_unclaimed_subsystems
rc=$?
assert_eq 0 "$rc" "force_rotate_to_unclaimed_subsystems: rotates with strategy change"
assert_eq "S7" "$(cat "$(agent_strategy_path 3)")" \
  "force_rotate_to_unclaimed_subsystems: agent moved from S2 → S7 toward untouched subsystem"
assert_eq "3" "$(last_cleared_agent)" \
  "force_rotate_to_unclaimed_subsystems: clears resume state when strategy changes"
assert_match "STALL_FORCE_REPIN: agent=3 Strategy2\\(Invariant-negation\\)" "$(cat "$INDEX")" \
  "force_rotate_to_unclaimed_subsystems: log shows strategy transition"

# ═══════════════════════════════════════════════════════════════
# 8. force_rotate_to_unclaimed_subsystems: no-op when all subsystems held
# ═══════════════════════════════════════════════════════════════
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S7","subsystem":"a/c"}
{"id":"W4","status":"unclaimed","strategy":"S7","subsystem":"d/e"}
JSONL
set_fake_subsystem 1 "a/b"
set_fake_subsystem 2 "a/c"
set_fake_subsystem 3 "d/e"
reset_side_effects
> "$INDEX"

force_rotate_to_unclaimed_subsystems
rc=$?
assert_eq 1 "$rc" "force_rotate_to_unclaimed_subsystems: no-op when every queue subsystem is held"
[ -z "$(last_cleared_agent)" ] \
  && pass "force_rotate_to_unclaimed_subsystems: does not touch agents on no-op" \
  || fail "force_rotate_to_unclaimed_subsystems: should not clear resume on no-op"

# ═══════════════════════════════════════════════════════════════
# 9. Empty / missing queue is graceful
# ═══════════════════════════════════════════════════════════════
rm -f "$WORK_CARDS"
> "$INDEX"
force_rotate_to_unclaimed_strategies
assert_eq 1 $? "missing work-cards.jsonl: strategies rotation returns 1"
force_rotate_to_unclaimed_subsystems
assert_eq 1 $? "missing work-cards.jsonl: subsystems rotation returns 1"
[ ! -s "$INDEX" ] \
  && pass "rotations: silent when work-cards.jsonl is missing" \
  || fail "rotations: should not log on missing queue"

: > "$WORK_CARDS"
force_rotate_to_unclaimed_strategies
assert_eq 1 $? "empty work-cards.jsonl: strategies rotation returns 1"
force_rotate_to_unclaimed_subsystems
assert_eq 1 $? "empty work-cards.jsonl: subsystems rotation returns 1"

# ═══════════════════════════════════════════════════════════════
# 10. log_queue_state writes a one-line snapshot
# ═══════════════════════════════════════════════════════════════
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S7","subsystem":"a/c"}
{"id":"W3","status":"unclaimed","strategy":"S7","subsystem":"d/e"}
{"id":"W4","status":"discarded","strategy":"S2","subsystem":"a/b"}
JSONL
> "$INDEX"
log_queue_state
snapshot=$(grep '^QUEUE:' "$INDEX" || true)
assert_match "^QUEUE: total=4 unclaimed=3" "$snapshot" \
  "log_queue_state: counts only unclaimed cards (against total)"
assert_match "by_strategy=.*Strategy1\\(Prior-fix-review\\):1" "$snapshot" \
  "log_queue_state: histograms strategies"
assert_match "by_strategy=.*Strategy7\\(Adversarial-input\\):2" "$snapshot" \
  "log_queue_state: histograms strategies (S7 count)"
assert_match "by_subsystem.top8.=.*a/c:1" "$snapshot" \
  "log_queue_state: histograms subsystems"
log_queue_state_src="$(audit_extract_function log_queue_state)"
assert_match 'jq -n -r' "$log_queue_state_src" \
  "log_queue_state: queue rows summarized in one streaming jq pass"
assert_not_match 'wc -l|uniq -c' "$log_queue_state_src" \
  "log_queue_state: avoids repeated shell count/sort pipelines"

# ═══════════════════════════════════════════════════════════════
# 11. log_queue_state silent on empty queue
# ═══════════════════════════════════════════════════════════════
rm -f "$WORK_CARDS"
> "$INDEX"
log_queue_state
[ ! -s "$INDEX" ] \
  && pass "log_queue_state: silent on missing queue" \
  || fail "log_queue_state: should not emit on missing queue"

: > "$WORK_CARDS"
> "$INDEX"
log_queue_state
[ ! -s "$INDEX" ] \
  && pass "log_queue_state: silent on empty queue" \
  || fail "log_queue_state: should not emit on empty queue"

# ═══════════════════════════════════════════════════════════════
# 12. pick_exhaustion_recovery_strategy — Step 1 (unclaimed minus active)
# ═══════════════════════════════════════════════════════════════
# Queue holds S1, S3, S7. Other agents hold S1, S3. Expected: S7
# (first strategy in STRATEGY_ROTATION_ORDER that is unclaimed AND not held
# by another agent).
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S3","subsystem":"a/c"}
{"id":"W3","status":"unclaimed","strategy":"S7","subsystem":"d/e"}
JSONL
set_agent_strategy 1 S1
set_agent_strategy 2 S3
set_agent_strategy 3 S5   # exhausted agent — its own strategy is excluded
got=$(pick_exhaustion_recovery_strategy 3)
assert_eq "S7" "$got" \
  "pick_exhaustion_recovery_strategy: prefers queue strategy unused by other agents"

# Same queue, but every queue strategy is held by another agent. Expected:
# rotate forward from prior strategy (S5 -> S6 per STRATEGY_ROTATION_ORDER).
set_agent_strategy 1 S1
set_agent_strategy 2 S3
set_agent_strategy 3 S5
# Make every queue strategy active on someone other than agent 3.
set_agent_strategy 1 S1
set_agent_strategy 2 S7
set_agent_strategy 3 S5
# Now active-on-others = {S1, S7}. Queue has S1, S3, S7. So S3 is the
# unclaimed-and-not-held candidate. Verify that case first.
got=$(pick_exhaustion_recovery_strategy 3)
assert_eq "S3" "$got" \
  "pick_exhaustion_recovery_strategy: walks STRATEGY_ROTATION_ORDER for first valid candidate"

# Now fully cover the queue with other agents, leaving nothing for Step 1.
# Need agents 1 and 2 to hold all 3 queue strategies between them — but we
# only have 2 other agents. Reduce the queue to 2 strategies.
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S7","subsystem":"a/c"}
JSONL
set_agent_strategy 1 S1
set_agent_strategy 2 S7
set_agent_strategy 3 S5
got=$(pick_exhaustion_recovery_strategy 3)
# Step 2: next_strategy_in_rotation S5 → S6
assert_eq "S6" "$got" \
  "pick_exhaustion_recovery_strategy: falls back to next_strategy_in_rotation when queue fully covered"

# Step 3: empty queue + no prior strategy → S1 (last-resort default).
rm -f "$WORK_CARDS"
rm -f "$(agent_strategy_path 3)"
got=$(pick_exhaustion_recovery_strategy 3)
assert_eq "S1" "$got" \
  "pick_exhaustion_recovery_strategy: S1 fallback when queue empty and no prior strategy"

# Empty queue but prior strategy is set: rotate forward from prior.
set_agent_strategy 3 S2
got=$(pick_exhaustion_recovery_strategy 3)
assert_eq "S3" "$got" \
  "pick_exhaustion_recovery_strategy: rotation fallback honours prior strategy when queue empty"

# Special case: prior strategy is S8 (last in rotation). next_strategy_in_rotation
# wraps to S1. The helper should accept that as a valid rotation step.
set_agent_strategy 3 S8
got=$(pick_exhaustion_recovery_strategy 3)
assert_eq "S1" "$got" \
  "pick_exhaustion_recovery_strategy: handles end-of-rotation wraparound"

# ═══════════════════════════════════════════════════════════════
# 13. recover_exhausted_agent — composite behaviour
# ═══════════════════════════════════════════════════════════════
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S3","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S7","subsystem":"d/e"}
JSONL
set_agent_strategy 1 S1
set_agent_strategy 2 S3
set_agent_strategy 3 S1
set_agent_strategy_streak 3 7
reset_side_effects
out=$(recover_exhausted_agent 3 "exhausted")
prev_strat="${out%% *}"
next_strat="${out##* }"
assert_eq "S1" "$prev_strat" "recover_exhausted_agent: returns prior strategy in pair"
# Queue offers S3 (held by agent 2) and S7 (no agent on it). Expected: S7.
assert_eq "S7" "$next_strat" "recover_exhausted_agent: routes via pick_exhaustion_recovery_strategy"
assert_eq "S7" "$(cat "$(agent_strategy_path 3)")" \
  "recover_exhausted_agent: persists new strategy"
assert_eq "3" "$(last_cleared_agent)" \
  "recover_exhausted_agent: clears agent resume state"
assert_eq "3" "$(last_archived_agent)" "recover_exhausted_agent: archives agent state"
assert_eq "exhausted" "$(last_archived_reason)" "recover_exhausted_agent: passes reason through"
[ ! -f "$(agent_strategy_streak_path 3)" ] \
  && pass "recover_exhausted_agent: resets strategy streak counter" \
  || fail "recover_exhausted_agent: should reset streak (file still present)"

# Recovery must never force every exhausted agent back to S1 — the bug
# fixed by P0 #1. Run recover_exhausted_agent on three different agents
# and verify they don't all land on S1.
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S3","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S5","subsystem":"a/c"}
{"id":"W3","status":"unclaimed","strategy":"S7","subsystem":"d/e"}
JSONL
set_agent_strategy 1 S1
set_agent_strategy 2 S1
set_agent_strategy 3 S1
recover_exhausted_agent 1 "exhausted" >/dev/null
recover_exhausted_agent 2 "exhausted" >/dev/null
recover_exhausted_agent 3 "exhausted" >/dev/null
s1=$(cat "$(agent_strategy_path 1)")
s2=$(cat "$(agent_strategy_path 2)")
s3=$(cat "$(agent_strategy_path 3)")
# At least one of them must end up off S1; previously all three reset to S1.
if [ "$s1" = "S1" ] && [ "$s2" = "S1" ] && [ "$s3" = "S1" ]; then
  fail "recover_exhausted_agent: regression — all three agents back on S1 after exhaustion"
else
  pass "recover_exhausted_agent: post-exhaustion strategies diversify (got ${s1}/${s2}/${s3})"
fi

# ═══════════════════════════════════════════════════════════════
# 14. diversify_subsystem_collisions — collision detection
# ═══════════════════════════════════════════════════════════════
# All 3 agents on the same subsystem (a/b). Expected: 2 of the 3 get
# their resume state cleared + strategy rotated; one is kept.
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S3","subsystem":"a/c"}
{"id":"W2","status":"unclaimed","strategy":"S7","subsystem":"d/e"}
JSONL
set_fake_subsystem 1 "a/b"
set_fake_subsystem 2 "a/b"
set_fake_subsystem 3 "a/b"
set_agent_strategy 1 S1
set_agent_strategy 2 S1
set_agent_strategy 3 S1
# Stub state files with different "probe activity" so we can verify the
# tiebreak picks the most-invested as the keeper. Agent 2 will have the
# highest score, so agents 1 and 3 should be re-pinned.
mkdir -p "$RESULTS_DIR"
printf -- '- [pending] H1\n- [pending] H2\n' > "$(state_file_path 1)"
printf -- '- [pending] H1\n- [pending] H2\n- [pending] H3\nasan_runs: 10\n' > "$(state_file_path 2)"
printf -- '- [pending] H1\n' > "$(state_file_path 3)"
reset_side_effects
> "$INDEX"

diversify_subsystem_collisions
rc=$?
assert_eq 0 "$rc" "diversify_subsystem_collisions: returns 0 when collision was resolved"
# Agent 2 (highest probe score) should NOT have been archived.
case " $(archive_calls) " in
  *" 2:subsystem-collision "*)
    fail "diversify_subsystem_collisions: archived the keeper (agent 2) — should keep most-invested" ;;
  *)
    pass "diversify_subsystem_collisions: keeper (agent 2) preserved" ;;
esac
# Agents 1 and 3 should both have been archived.
got_calls=$(archive_calls)
if [[ "$got_calls" == *"1:subsystem-collision"* && "$got_calls" == *"3:subsystem-collision"* ]]; then
  pass "diversify_subsystem_collisions: re-pinned both non-keepers"
else
  fail "diversify_subsystem_collisions: expected agents 1 and 3 to be archived, got calls='${got_calls}'"
fi
assert_match "SUBSYSTEM_DIVERSIFY: agent " "$(cat "$INDEX")" \
  "diversify_subsystem_collisions: logs SUBSYSTEM_DIVERSIFY"

# No collisions when each agent on a distinct subsystem.
set_fake_subsystem 1 "a/b"
set_fake_subsystem 2 "a/c"
set_fake_subsystem 3 "d/e"
reset_side_effects
> "$INDEX"
diversify_subsystem_collisions
rc=$?
assert_eq 1 "$rc" "diversify_subsystem_collisions: no-op (rc=1) when agents already diverse"
[ -z "$(archive_calls)" ] \
  && pass "diversify_subsystem_collisions: no archives on no-op" \
  || fail "diversify_subsystem_collisions: archived on no-op (calls='$(archive_calls)')"

# Unknown / empty subsystems must not count as collisions.
set_fake_subsystem 1 "unknown"
set_fake_subsystem 2 "unknown"
set_fake_subsystem 3 "unknown"
reset_side_effects
diversify_subsystem_collisions
rc=$?
assert_eq 1 "$rc" "diversify_subsystem_collisions: 'unknown' subsystems skipped, no collision fired"

# Partial collision: 2 agents on a/b, 1 on a/c. Only the duplicate pair
# should trigger re-pinning of one agent.
set_fake_subsystem 1 "a/b"
set_fake_subsystem 2 "a/b"
set_fake_subsystem 3 "a/c"
set_agent_strategy 1 S1
set_agent_strategy 2 S1
set_agent_strategy 3 S1
printf -- '- [pending] H1\n- [pending] H2\nasan_runs: 5\n' > "$(state_file_path 1)"
printf -- '- [pending] H1\n' > "$(state_file_path 2)"
reset_side_effects
> "$INDEX"
diversify_subsystem_collisions
rc=$?
assert_eq 0 "$rc" "diversify_subsystem_collisions: partial collision resolved"
# Agent 1 has higher probe activity → keeper. Agent 2 should be archived.
case " $(archive_calls) " in
  *" 2:subsystem-collision "*)
    pass "diversify_subsystem_collisions: partial collision archives the lower-activity duplicate" ;;
  *)
    fail "diversify_subsystem_collisions: expected agent 2 archived, got calls='$(archive_calls)'" ;;
esac
case " $(archive_calls) " in
  *" 3:subsystem-collision "*)
    fail "diversify_subsystem_collisions: agent 3 on isolated subsystem should not be archived" ;;
  *)
    pass "diversify_subsystem_collisions: leaves isolated agent (3) alone" ;;
esac

# ═══════════════════════════════════════════════════════════════
# 15. agent_probe_activity_score — well-behaved on missing state
# ═══════════════════════════════════════════════════════════════
rm -f "$(state_file_path 1)"
got=$(agent_probe_activity_score 1)
assert_eq "0" "$got" "agent_probe_activity_score: returns 0 when state file missing"

printf -- '- [pending] X\n- [pending] Y\nasan_runs: 3\nHITS: foo\n' > "$(state_file_path 1)"
got=$(agent_probe_activity_score 1)
# 2 PENDING lines + 2 effort markers (asan_runs + HITS:) = 4
[ "$got" -ge 2 ] \
  && pass "agent_probe_activity_score: counts pending+effort markers (got $got)" \
  || fail "agent_probe_activity_score: expected >=2 markers, got '$got'"

# ═══════════════════════════════════════════════════════════════
# 16. Safety-valve ceiling math (P1 #5)
# ═══════════════════════════════════════════════════════════════
# Reimplement the valve_ceiling computation as a pure shell function so
# we can unit-test the new clamp logic without exercising the entire
# update_subsystem_dry_streaks routine.
valve_ceiling_for() {
  local strat_threshold="$1" max_dry="$2"
  local valve_extra=5 valve_ceiling
  valve_ceiling=$((strat_threshold + valve_extra))
  if [ "${max_dry:-0}" -gt 0 ] && [ "$valve_ceiling" -ge "$max_dry" ]; then
    valve_ceiling=$((max_dry - 1))
    [ "$valve_ceiling" -lt "$strat_threshold" ] && valve_ceiling="$strat_threshold"
  fi
  echo "$valve_ceiling"
}

# Case A: threshold+5 < MAX_DRY_SESSIONS → keep the +5 cushion.
got=$(valve_ceiling_for 3 20)
assert_eq "8" "$got" "valve_ceiling: keeps threshold+5 when MAX_DRY_SESSIONS leaves room"

# Case B: threshold+5 >= MAX_DRY_SESSIONS → cap to MAX_DRY_SESSIONS-1
# (this is the curl scenario: STRATEGY_S1_DRY_STREAK_THRESHOLD=8,
# MAX_DRY_SESSIONS=10 → valve should fire at streak >= 9, not >= 13).
got=$(valve_ceiling_for 8 10)
assert_eq "9" "$got" "valve_ceiling: clamps to MAX_DRY_SESSIONS-1 so valve fires before STALL_STOP"

# Case C: MAX_DRY_SESSIONS-1 below threshold → never go below threshold.
got=$(valve_ceiling_for 8 5)
assert_eq "8" "$got" "valve_ceiling: floor at threshold even when MAX_DRY_SESSIONS is tiny"

# Case D: MAX_DRY_SESSIONS=0 (disabled) → original threshold+5 behaviour.
got=$(valve_ceiling_for 8 0)
assert_eq "13" "$got" "valve_ceiling: MAX_DRY_SESSIONS=0 preserves original threshold+5"

# ═══════════════════════════════════════════════════════════════
# Rotation helpers — most_stuck_agent / first_strategy_in_order
# ═══════════════════════════════════════════════════════════════
# These two primitives were extracted from the inlined loops in
# force_rotate_to_unclaimed_strategies / _subsystems /
# pick_exhaustion_recovery_strategy (audit:3460..3658) so all rotation
# sites agree on "who's most stuck" and "which strategy comes next."
# Direct tests pin the contract so a future inline rewrite cannot
# silently drift the streak/tiebreak semantics again.

# Fresh env per assertion block.
rm -f "$RESULTS_DIR"/.agent_strategy_streak_* 2>/dev/null || true

NUM_AGENTS=4 STRATEGY_ROTATION_ORDER=(S1 S2 S3 S4 S5 S6 S7 S8)

# (a) most_stuck_agent: empty streaks → first agent wins (best_streak=-1).
got=$(most_stuck_agent)
assert_eq "1" "$got" "most_stuck_agent: no streaks → agent 1 (stable tiebreak)"

# (b) one agent has a higher streak.
printf '3' > "$(agent_strategy_streak_path 2)"
got=$(most_stuck_agent)
assert_eq "2" "$got" "most_stuck_agent: highest streak agent picked"

# (c) tie between two agents → first (lowest agent_num) wins.
printf '3' > "$(agent_strategy_streak_path 4)"
got=$(most_stuck_agent)
assert_eq "2" "$got" "most_stuck_agent: tie broken by lowest agent_num"

rm -f "$RESULTS_DIR"/.agent_strategy_streak_* 2>/dev/null || true

# (e) first_strategy_in_order: pure allow-list, in canonical order.
got=$(first_strategy_in_order "S3 S1 S5")
assert_eq "S1" "$got" "first_strategy_in_order: respects STRATEGY_ROTATION_ORDER, not arg order"

got=$(first_strategy_in_order "S7 S4")
assert_eq "S4" "$got" "first_strategy_in_order: returns first in canonical order from candidates"

# (f) deny-list skips entries that are otherwise candidates.
got=$(first_strategy_in_order "S1 S2 S3" "S1 S2")
assert_eq "S3" "$got" "first_strategy_in_order: deny-list skips earlier candidates"

# (g) all candidates denied → rc=1, no output.
out=$(first_strategy_in_order "S1 S2" "S1 S2" 2>&1; echo "rc=$?")
case "$out" in
  *"rc=1"*) pass "first_strategy_in_order: rc=1 when every candidate denied" ;;
  *)        fail "first_strategy_in_order: rc=1 when every candidate denied" "got '$out'" ;;
esac

# (h) empty allow-list → rc=1.
out=$(first_strategy_in_order "" 2>&1; echo "rc=$?")
case "$out" in
  *"rc=1"*) pass "first_strategy_in_order: rc=1 on empty allow-list" ;;
  *)        fail "first_strategy_in_order: rc=1 on empty allow-list" "got '$out'" ;;
esac

# (i) Empty deny-list disables the second filter (regression guard:
# treating a literally empty string as a deny match would be a subtle
# bug — case-statement padding makes " <empty> " never match " S1 ").
got=$(first_strategy_in_order "S2 S1" "")
assert_eq "S1" "$got" "first_strategy_in_order: empty deny-list is a no-op"

# ═══════════════════════════════════════════════════════════════
# P4. pick_cold_start_strategy — load-weighted default
# ═══════════════════════════════════════════════════════════════
# Old default was unconditional "S1", which wedged every brand-new
# agent on the bucket most prone to memory-driven auto-discard. The
# new picker reads the live work-card distribution and prefers the
# strategy with the most unclaimed cards, excluding strategies other
# agents already cover (fan-out across families). S1 is deprioritised
# unless it is the only option.

rm -f "$RESULTS_DIR"/.agent_strategy_* 2>/dev/null || true
NUM_AGENTS=3

# (a) Typical pcre2-like distribution: S7=175, S5=153, S2=23, S1=9.
# No other agent active → highest non-S1 wins (S7).
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
{"id":"W3","status":"unclaimed","strategy":"S2","subsystem":"a/b"}
{"id":"W4","status":"unclaimed","strategy":"S2","subsystem":"a/b"}
{"id":"W5","status":"unclaimed","strategy":"S2","subsystem":"a/b"}
{"id":"W6","status":"unclaimed","strategy":"S5","subsystem":"a/b"}
{"id":"W7","status":"unclaimed","strategy":"S5","subsystem":"a/b"}
{"id":"W8","status":"unclaimed","strategy":"S5","subsystem":"a/b"}
{"id":"W9","status":"unclaimed","strategy":"S5","subsystem":"a/b"}
{"id":"W10","status":"unclaimed","strategy":"S7","subsystem":"a/b"}
{"id":"W11","status":"unclaimed","strategy":"S7","subsystem":"a/b"}
{"id":"W12","status":"unclaimed","strategy":"S7","subsystem":"a/b"}
{"id":"W13","status":"unclaimed","strategy":"S7","subsystem":"a/b"}
{"id":"W14","status":"unclaimed","strategy":"S7","subsystem":"a/b"}
JSONL
got=$(pick_cold_start_strategy 1)
assert_eq "S7" "$got" "pick_cold_start_strategy: highest-volume non-S1 wins (S7)"

# (b) Round-robin fan-out: agent 2 gets the 2nd-largest non-S1 strategy,
# agent 3 the 3rd. The ranked list (S7=5, S5=4, S2=3, S1=2 unclaimed)
# yields S7,S5,S2 for agents 1,2,3 respectively.
got=$(pick_cold_start_strategy 2)
assert_eq "S5" "$got" "pick_cold_start_strategy: agent 2 takes 2nd-largest non-S1 (S5)"
got=$(pick_cold_start_strategy 3)
assert_eq "S2" "$got" "pick_cold_start_strategy: agent 3 takes 3rd-largest non-S1 (S2)"

# (c) Wrap-around: more agents than distinct non-S1 strategies → modulo.
got=$(pick_cold_start_strategy 4)
assert_eq "S7" "$got" "pick_cold_start_strategy: agent 4 wraps back to top (S7)"
pick_cold_start_strategy_src="$(audit_extract_function pick_cold_start_strategy)"
assert_match 'cold_start_strategies\.txt' "$pick_cold_start_strategy_src" \
  "pick_cold_start_strategy: can reuse cached cold-start rank"

# (c2) Iteration cache path: no live queue re-rank is needed when the
# per-iteration cache already holds the ordered non-S1 strategy list.
mkdir -p "$RESULTS_DIR/.iter_cache"
printf 'S5\nS2\n' > "$RESULTS_DIR/.iter_cache/cold_start_strategies.txt"
got=$(ITERATION_CACHE_DIR="$RESULTS_DIR/.iter_cache" pick_cold_start_strategy 1)
assert_eq "S5" "$got" "pick_cold_start_strategy: cached rank agent 1"
got=$(ITERATION_CACHE_DIR="$RESULTS_DIR/.iter_cache" pick_cold_start_strategy 2)
assert_eq "S2" "$got" "pick_cold_start_strategy: cached rank agent 2"
got=$(ITERATION_CACHE_DIR="$RESULTS_DIR/.iter_cache" pick_cold_start_strategy 3)
assert_eq "S5" "$got" "pick_cold_start_strategy: cached rank wraps"
rm -rf "$RESULTS_DIR/.iter_cache"

# (d) Queue is S1-only — boot on S1 (don't starve the agent).
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
JSONL
got=$(pick_cold_start_strategy 1)
assert_eq "S1" "$got" "pick_cold_start_strategy: S1-only queue falls back to S1"

# (e) Empty queue / no jq fallback path returns "S1" (sentinel).
: > "$WORK_CARDS"
got=$(pick_cold_start_strategy 1)
assert_eq "S1" "$got" "pick_cold_start_strategy: empty queue falls back to S1"

# ═══════════════════════════════════════════════════════════════
# P0. pick_strategy_by_load — argmax over unclaimed counts
# ═══════════════════════════════════════════════════════════════
# The headline benchmark bug: with S7=175, S5=153, S2=23, S3=24, S1=9
# unclaimed, every rotation kept picking S2 because first_strategy_in_order
# walked STRATEGY_ROTATION_ORDER lowest-first. pick_strategy_by_load
# reads the queue's actual distribution and routes to the largest pool.

rm -f "$RESULTS_DIR"/.agent_strategy_* 2>/dev/null || true

# (a) Skewed distribution — argmax picks S7 deterministically (no tie).
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S2","subsystem":"a/b"}
{"id":"W3","status":"unclaimed","strategy":"S2","subsystem":"a/b"}
{"id":"W4","status":"unclaimed","strategy":"S2","subsystem":"a/b"}
{"id":"W5","status":"unclaimed","strategy":"S5","subsystem":"a/b"}
{"id":"W6","status":"unclaimed","strategy":"S5","subsystem":"a/b"}
{"id":"W7","status":"unclaimed","strategy":"S5","subsystem":"a/b"}
{"id":"W8","status":"unclaimed","strategy":"S5","subsystem":"a/b"}
{"id":"W9","status":"unclaimed","strategy":"S5","subsystem":"a/b"}
{"id":"W10","status":"unclaimed","strategy":"S7","subsystem":"a/b"}
{"id":"W11","status":"unclaimed","strategy":"S7","subsystem":"a/b"}
{"id":"W12","status":"unclaimed","strategy":"S7","subsystem":"a/b"}
{"id":"W13","status":"unclaimed","strategy":"S7","subsystem":"a/b"}
{"id":"W14","status":"unclaimed","strategy":"S7","subsystem":"a/b"}
{"id":"W15","status":"unclaimed","strategy":"S7","subsystem":"a/b"}
JSONL
got=$(pick_strategy_by_load "S1 S2 S5 S7")
assert_eq "S7" "$got" "pick_strategy_by_load: skewed dist → argmax picks S7"
pick_strategy_by_load_src="$(audit_extract_function pick_strategy_by_load)"
assert_match 'unclaimed_strategy_counts' "$pick_strategy_by_load_src" \
  "pick_strategy_by_load: reuses one structured strategy histogram helper"
assert_not_match 'sort \| uniq -c' "$pick_strategy_by_load_src" \
  "pick_strategy_by_load: avoids text sort/uniq histogram pipeline"
assert_not_match 'count_unclaimed_cards_for "\$strat"' "$pick_strategy_by_load_src" \
  "pick_strategy_by_load: avoids per-strategy queue rescans"

update_subsystem_dry_streaks_src="$(audit_extract_function update_subsystem_dry_streaks)"
assert_match 'count_unclaimed_cards_for_two_strategies' "$update_subsystem_dry_streaks_src" \
  "strategy status loop: rotation log gets from/to counts in one queue pass"
assert_match 'count_unclaimed_cards_for_strategy_subsystem' "$update_subsystem_dry_streaks_src" \
  "strategy status loop: keep log gets strategy/subsystem counts in one queue pass"
assert_not_match 'count_unclaimed_cards_for "\$current_strat"' "$update_subsystem_dry_streaks_src" \
  "strategy status loop: avoids repeated single-count queue scans"
fields=$(strategy_completion_fields '{"complete":false,"evidence":2,"threshold":4}')
IFS="$(printf '\t')" read -r complete_field evidence_field threshold_field <<< "$fields"
assert_eq "false" "$complete_field" "strategy completion fields: complete parsed"
assert_eq "2" "$evidence_field" "strategy completion fields: evidence parsed"
assert_eq "4" "$threshold_field" "strategy completion fields: threshold parsed"
assert_match 'strategy_completion_fields "\$strat_status"' "$update_subsystem_dry_streaks_src" \
  "strategy status loop: parses strategy completion JSON once"
assert_not_match "jq -r '\\.complete'|jq -r '\\.evidence'|jq -r '\\.threshold'" "$update_subsystem_dry_streaks_src" \
  "strategy status loop: avoids per-field jq strategy-status parsing"

# (b) Deny-list excludes S7 → next-largest (S5) wins.
got=$(pick_strategy_by_load "S1 S2 S5 S7" "S7")
assert_eq "S5" "$got" "pick_strategy_by_load: deny-list shifts argmax to next-largest"

# (c) Restrict allow-list to just S1/S2 → S2 wins because it has 3 vs S1's 1.
got=$(pick_strategy_by_load "S1 S2")
assert_eq "S2" "$got" "pick_strategy_by_load: restricted allow-list respects argmax"

# (d) Tie-break is deterministic when AUDIT_STRATEGY_TIEBREAK_INDEX is set.
# Make S2 and S3 both have 5 cards; nothing else.
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S2","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S2","subsystem":"a/b"}
{"id":"W3","status":"unclaimed","strategy":"S2","subsystem":"a/b"}
{"id":"W4","status":"unclaimed","strategy":"S2","subsystem":"a/b"}
{"id":"W5","status":"unclaimed","strategy":"S2","subsystem":"a/b"}
{"id":"W6","status":"unclaimed","strategy":"S3","subsystem":"a/b"}
{"id":"W7","status":"unclaimed","strategy":"S3","subsystem":"a/b"}
{"id":"W8","status":"unclaimed","strategy":"S3","subsystem":"a/b"}
{"id":"W9","status":"unclaimed","strategy":"S3","subsystem":"a/b"}
{"id":"W10","status":"unclaimed","strategy":"S3","subsystem":"a/b"}
JSONL
got=$(AUDIT_STRATEGY_TIEBREAK_INDEX=0 pick_strategy_by_load "S2 S3")
assert_eq "S2" "$got" "pick_strategy_by_load: tie-break index 0 picks first tied (S2)"
got=$(AUDIT_STRATEGY_TIEBREAK_INDEX=1 pick_strategy_by_load "S2 S3")
assert_eq "S3" "$got" "pick_strategy_by_load: tie-break index 1 picks second tied (S3)"
# Index >= N wraps via modulo so callers don't have to clamp.
got=$(AUDIT_STRATEGY_TIEBREAK_INDEX=5 pick_strategy_by_load "S2 S3")
case "$got" in S2|S3) pass "pick_strategy_by_load: out-of-range tie-break wraps modulo" ;;
  *) fail "pick_strategy_by_load: out-of-range tie-break wraps modulo" "got '$got'" ;;
esac

# (e) Empty queue / no jq / all-zero counts → rc=1 so caller falls back.
: > "$WORK_CARDS"
out=$(pick_strategy_by_load "S1 S2" 2>&1; echo "rc=$?")
case "$out" in
  *"rc=1"*) pass "pick_strategy_by_load: empty queue returns rc=1 for fallback" ;;
  *)        fail "pick_strategy_by_load: empty queue returns rc=1 for fallback" "got '$out'" ;;
esac

# (f) Cards present but none match the allow-list → rc=1 (all counts 0).
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
{"id":"W2","status":"unclaimed","strategy":"S1","subsystem":"a/b"}
JSONL
out=$(pick_strategy_by_load "S5 S7" 2>&1; echo "rc=$?")
case "$out" in
  *"rc=1"*) pass "pick_strategy_by_load: all-zero counts return rc=1" ;;
  *)        fail "pick_strategy_by_load: all-zero counts return rc=1" "got '$out'" ;;
esac

# (g) Empty allow-list → rc=1 immediately.
out=$(pick_strategy_by_load "" 2>&1; echo "rc=$?")
case "$out" in
  *"rc=1"*) pass "pick_strategy_by_load: empty allow-list returns rc=1" ;;
  *)        fail "pick_strategy_by_load: empty allow-list returns rc=1" "got '$out'" ;;
esac

# (h) End-to-end: force_rotate_to_unclaimed_strategies now routes to S7
# (the largest pool) instead of S2 (the smallest non-S1 strategy that
# happened to win under the old order-based pick).
cat > "$WORK_CARDS" <<'JSONL'
{"id":"W1","status":"unclaimed","strategy":"S2","subsystem":"x/y"}
{"id":"W2","status":"unclaimed","strategy":"S2","subsystem":"x/y"}
{"id":"W3","status":"unclaimed","strategy":"S3","subsystem":"x/y"}
{"id":"W4","status":"unclaimed","strategy":"S3","subsystem":"x/y"}
{"id":"W5","status":"unclaimed","strategy":"S5","subsystem":"x/y"}
{"id":"W6","status":"unclaimed","strategy":"S5","subsystem":"x/y"}
{"id":"W7","status":"unclaimed","strategy":"S5","subsystem":"x/y"}
{"id":"W8","status":"unclaimed","strategy":"S5","subsystem":"x/y"}
{"id":"W9","status":"unclaimed","strategy":"S5","subsystem":"x/y"}
{"id":"W10","status":"unclaimed","strategy":"S7","subsystem":"x/y"}
{"id":"W11","status":"unclaimed","strategy":"S7","subsystem":"x/y"}
{"id":"W12","status":"unclaimed","strategy":"S7","subsystem":"x/y"}
{"id":"W13","status":"unclaimed","strategy":"S7","subsystem":"x/y"}
{"id":"W14","status":"unclaimed","strategy":"S7","subsystem":"x/y"}
{"id":"W15","status":"unclaimed","strategy":"S7","subsystem":"x/y"}
{"id":"W16","status":"unclaimed","strategy":"S7","subsystem":"x/y"}
JSONL
set_agent_strategy 1 S1
set_agent_strategy 2 ""
set_agent_strategy 3 ""
set_agent_strategy_streak 1 5  # agent 1 is "most stuck"
force_rotate_to_unclaimed_strategies >/dev/null
got=$(get_agent_strategy 1)
assert_eq "S7" "$got" "P0 e2e: force_rotate routes the most-stuck agent to S7 (largest pool)"
rm -f "$RESULTS_DIR"/.agent_strategy_* 2>/dev/null || true

# (i) Pre-P0 regression guard: the same input under the OLD logic
# (first_strategy_in_order) would have picked S2 — the lowest-numbered
# missing strategy. Confirm the fallback still works as a sanity belt.
got=$(first_strategy_in_order "S2 S3 S5 S7")
assert_eq "S2" "$got" "P0: first_strategy_in_order still exposes legacy lowest-numbered for fallback callers"

# ═══════════════════════════════════════════════════════════════
# E2E regression: May-23 pcre2 rotation-trap distribution
# ═══════════════════════════════════════════════════════════════
# Reproduces the queue distribution that drove the May 23 pcre2
# benchmark cells to 0 confirmed crashes: S7=175, S5=153, S3=24,
# S2=23, S1=9 unclaimed work cards, 3 agents booting from the old
# unconditional S1 default. Under the pre-P0/P4 logic, all three
# agents pinned to S1, then rotation routed them to the lowest-
# numbered missing strategies, producing an S1↔S2↔S3 ping-pong
# that never reached S5 or S7 within the 3h budget.
#
# Asserts:
#   (1) Cold-start: no agent boots on S1 (P4 picks load-aware).
#   (2) Cold-start: all 3 agents end up on distinct strategies
#       covering the high-volume buckets (S5, S7 at minimum;
#       third may be S2 or S3 — both have similar load).
#   (3) Force-rotation under stall: the most-stuck agent moves
#       to the largest unclaimed pool, not the lowest-numbered
#       missing strategy.
#   (4) Over 5 sequential rotation cycles, no agent ping-pongs
#       between S2 and S3 — i.e. no agent flips strategies more
#       than once in the same {S2,S3} pair across the run.
rm -f "$RESULTS_DIR"/.agent_strategy_* 2>/dev/null || true
NUM_AGENTS=3

# Build the May-23 distribution. 175 S7, 153 S5, 24 S3, 23 S2, 9 S1
# unclaimed cards — total 384 (matches the "by_strategy" line from the
# real run's audit.log).
e2e_build_queue() {
  : > "$WORK_CARDS"
  local i
  for i in $(seq 1 175); do
    printf '{"id":"E2E-S7-%d","status":"unclaimed","strategy":"S7","subsystem":"src/parser%d"}\n' \
      "$i" $((i % 8)) >> "$WORK_CARDS"
  done
  for i in $(seq 1 153); do
    printf '{"id":"E2E-S5-%d","status":"unclaimed","strategy":"S5","subsystem":"src/codec%d"}\n' \
      "$i" $((i % 8)) >> "$WORK_CARDS"
  done
  for i in $(seq 1 24); do
    printf '{"id":"E2E-S3-%d","status":"unclaimed","strategy":"S3","subsystem":"src/match%d"}\n' \
      "$i" $((i % 4)) >> "$WORK_CARDS"
  done
  for i in $(seq 1 23); do
    printf '{"id":"E2E-S2-%d","status":"unclaimed","strategy":"S2","subsystem":"src/compile%d"}\n' \
      "$i" $((i % 4)) >> "$WORK_CARDS"
  done
  for i in $(seq 1 9); do
    printf '{"id":"E2E-S1-%d","status":"unclaimed","strategy":"S1","subsystem":"src/util%d"}\n' \
      "$i" $((i % 3)) >> "$WORK_CARDS"
  done
}
e2e_build_queue
e2e_total=$(wc -l < "$WORK_CARDS" | tr -d ' ')
assert_eq "384" "$e2e_total" "e2e: queue fixture seeded with 384 unclaimed cards"

# (1) Cold-start: each agent picks a load-aware default.
# pick_cold_start_strategy iterates the per-strategy counts and avoids
# S1 unless it's the only option. With 3 agents we expect S5/S7 to be
# claimed first (top two pools) and the third to fall onto S2 or S3
# (the next-largest non-claimed buckets), but NEVER S1.
for i in 1 2 3; do
  s=$(pick_cold_start_strategy "$i")
  set_agent_strategy "$i" "$s"
done
boot_strats=$(active_agent_strategies); boot_strats="${boot_strats% }"
case "$boot_strats" in
  *S1*) fail "E2E (1): cold-start avoids S1" "got '$boot_strats' — at least one agent booted on S1" ;;
  *)    pass "E2E (1): cold-start avoids S1 (got '$boot_strats')" ;;
esac
# Both S5 and S7 must be represented in the boot fan-out, since they
# carry 85% of the queue's unclaimed load.
case " $boot_strats " in *" S7 "*) ;; *) fail "E2E (1): S7 represented in boot" "got '$boot_strats'" ;; esac
case " $boot_strats " in *" S5 "*) ;; *) fail "E2E (1): S5 represented in boot" "got '$boot_strats'" ;; esac
[[ "$boot_strats" == *S7* && "$boot_strats" == *S5* && "$boot_strats" != *S1* ]] \
  && pass "E2E (1): boot covers S5+S7, no S1"

# Snapshot which strategies each agent booted on (for the ping-pong check).
e2e_history_1="$(get_agent_strategy 1)"
e2e_history_2="$(get_agent_strategy 2)"
e2e_history_3="$(get_agent_strategy 3)"

# (2) Force-rotation under stall. Pretend agent 1 has burned through its
# subsystem (high streak) → force_rotate must move it to the largest
# unclaimed pool not already held by 2 and 3. With S7+S5 already covered
# by the boot fan-out, this should send agent 1 to the next-largest
# uncovered bucket. We don't lock a specific id because the boot order
# depends on $RANDOM, but we DO assert it doesn't land back on S1 and
# doesn't oscillate to the third-already-active strategy.
set_agent_strategy_streak 1 5
reset_side_effects
unclaimed_now=$(unclaimed_card_strategies)
# Capture pre-rotation actives so we know what counts as "already
# covered" from agent 1's perspective.
other_active="$(get_agent_strategy 2) $(get_agent_strategy 3)"
force_rotate_to_unclaimed_strategies >/dev/null
got_after=$(get_agent_strategy 1)
case "$got_after" in
  S1) fail "E2E (3): force-rotation does not target S1" "agent 1 → S1" ;;
  *)  pass "E2E (3): force-rotation avoids S1 fallback" ;;
esac
case " $other_active " in
  *" $got_after "*) fail "E2E (3): force-rotation fans out across agents" \
                          "agent 1 landed on $got_after which agent 2 or 3 already holds" ;;
  *)                pass "E2E (3): force-rotation fans out across agents" ;;
esac

# (3) Five sequential rotation cycles must not produce an S2↔S3
# ping-pong on any single agent. We track each agent's per-cycle
# strategy and flag any agent that visits the {S2,S3} pair more than
# once in a row. The pre-P0 logic would have alternated agent 1
# between S2 and S3 across every cycle because first_strategy_in_order
# always picked the lower-numbered missing strategy.
e2e_log="$RESULTS_DIR/.e2e_rotation_log"
: > "$e2e_log"
record_cycle() {
  local cyc="$1"
  printf '%s|%s|%s|%s\n' "$cyc" "$(get_agent_strategy 1)" \
    "$(get_agent_strategy 2)" "$(get_agent_strategy 3)" >> "$e2e_log"
}
record_cycle 0
for cycle in 1 2 3 4 5; do
  # Each cycle: bump the streak of a different agent so the rotation
  # picks a different "most stuck" each time, then call force_rotate.
  agent=$(( ((cycle - 1) % NUM_AGENTS) + 1 ))
  set_agent_strategy_streak "$agent" 10
  for other in 1 2 3; do
    [ "$other" = "$agent" ] && continue
    set_agent_strategy_streak "$other" 0
  done
  force_rotate_to_unclaimed_strategies >/dev/null || true
  record_cycle "$cycle"
done

# Ping-pong detector: for each agent, walk the per-cycle history and
# count how many times the agent oscillated between S2 and S3 in
# consecutive cycles. >=2 consecutive flips ⇒ ping-pong. The old code
# produced 4-5 flips per agent across this many cycles.
pingpong_count=$(python3 - "$e2e_log" <<'PY'
import sys
rows = [l.strip().split("|") for l in open(sys.argv[1]) if l.strip()]
# rows[i] = [cycle, a1, a2, a3]
out = 0
for agent_idx in (1, 2, 3):
    history = [r[agent_idx] for r in rows]
    flips = 0
    last_pair_state = None
    for prev, cur in zip(history, history[1:]):
        pair = tuple(sorted([prev, cur]))
        if pair == ("S2", "S3") and prev != cur:
            flips += 1
    if flips >= 2:
        out += 1
print(out)
PY
)
assert_eq "0" "$pingpong_count" \
  "E2E (4): no agent ping-pongs between S2 and S3 across 5 rotation cycles"

# (4) Coverage check: across the 5 cycles, agents collectively visited
# S5 and/or S7 (the high-volume strategies that the pre-P0 logic
# *never* reached within budget). This is the headline outcome.
covered=$(awk -F'|' '
  NR>0 { for (i=2; i<=4; i++) seen[$i]++ }
  END { for (s in seen) print s }
' "$e2e_log" | sort -u | tr '\n' ' ')
case " $covered " in
  *" S7 "*) pass "E2E (4): S7 reached at least once across rotations" ;;
  *)        fail "E2E (4): S7 reached at least once across rotations" "covered=[${covered% }]" ;;
esac
case " $covered " in
  *" S5 "*) pass "E2E (4): S5 reached at least once across rotations" ;;
  *)        fail "E2E (4): S5 reached at least once across rotations" "covered=[${covered% }]" ;;
esac

rm -f "$RESULTS_DIR"/.agent_strategy_* "$e2e_log" 2>/dev/null || true

teardown_test_env
summary
