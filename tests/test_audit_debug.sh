#!/usr/bin/env bash
# Tests for audit observability helpers: plan/status logs, subsystem claims,
# subsystem suggestions, and prompt artifact files.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

source "$SCRIPT_ROOT/lib/audit_debug.sh"

ACTIVE_BACKEND="codex"
MODEL="test-model"
export ACTIVE_BACKEND MODEL

count_verified_asan_runs() { echo 3; }
export -f count_verified_asan_runs

get_agent_subsystem() {
  case "$1" in
    1) echo "src/lib" ;;
    2) echo "js/src/jit" ;;
    *) echo "unknown" ;;
  esac
}
export -f get_agent_subsystem

# ═══════════════════════════════════════════════════════════════
# 1. Prompt artifact files
# ═══════════════════════════════════════════════════════════════

prompt_file=$(write_prompt_artifacts "20260508_010203" "cold-start-1-generic" 1 "cold-start" "hello prompt" 12)
# meta_file remained in the test surface for log_agent_plan compatibility
# (it tolerates an empty meta arg) but is no longer produced by
# write_prompt_artifacts — its contents are folded into the index.jsonl
# row at session-finish time.
meta_file=""

assert_file_exists "$prompt_file" "prompt artifact: prompt markdown written"
assert_file_contains "$prompt_file" "hello prompt" "prompt artifact: prompt body preserved"
# The metadata stash is consumed by run_agent's finish handler and folded
# into the index.jsonl row. Verify the stash records every field that the
# old session_*.prompt.meta.json carried.
stash="$LOGDIR/.prompt_meta_1"
assert_file_exists "$stash" "prompt artifact: metadata stash written for finish-handler pickup"
assert_file_contains "$stash" "^subsystem=src/lib$"      "prompt artifact: subsystem in stash"
assert_file_contains "$stash" "^strategy=S1$"            "prompt artifact: strategy in stash"
assert_file_contains "$stash" "^prompt_tokens_est=12$"   "prompt artifact: token estimate in stash"
assert_file_contains "$stash" "^launch=cold-start$"      "prompt artifact: launch in stash"
# A legacy session_*.prompt.meta.json file MUST NOT be written anymore.
legacy_meta="$LOGDIR/session_20260508_010203_cold-start-1-generic.prompt.meta.json"
[ ! -f "$legacy_meta" ] \
  && pass "prompt artifact: legacy json sidecar not written (data folded into index.jsonl)" \
  || fail "prompt artifact: legacy json sidecar not written" "found $legacy_meta"

# ═══════════════════════════════════════════════════════════════
# 2. SUBSYSTEM_SUGGEST and PLAN lines
# ═══════════════════════════════════════════════════════════════

echo "HIT: js.src.jit testcase" > "$(hits_log_path 1)"
cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: src/lib
| 1 | H1 | src/lib/A.cpp | shape | guard | bounds | S1 | PENDING |
| 2 | H2 | src/lib/B.cpp | shape | guard | bounds | S1 | DISCARDED |
EOF

record_subsystem_suggest 1 generic "src/lib" "coverage-cache" "src/net" "third_party/rust" 2>/dev/null
log_agent_plan 1 "cold-start" "cold-start-1-generic" 12 "$prompt_file" "$meta_file" 2>/dev/null

assert_file_contains "$INDEX" "SUBSYSTEM_SUGGEST: agent=1 mode=generic selected=src/lib" "suggest: line logged"
assert_file_contains "$INDEX" "skipped_claimed=\"src/net\"" "suggest: claimed skip logged"
assert_file_contains "$INDEX" "PLAN: agent=1 launch=cold-start" "plan: line logged"
assert_file_contains "$INDEX" "subsystem=src/lib" "plan: subsystem logged"
assert_file_contains "$INDEX" "suggested=src/lib" "plan: latest suggestion logged"
assert_file_contains "$INDEX" "strategy=S1" "plan: strategy logged"
assert_file_contains "$INDEX" "active=1 pending=1 discards=1 asan_runs=3 hits=1" "plan: critical counts logged"
assert_file_contains "$(audit_events_path)" '"event":"subsystem-suggest"' "events: subsystem suggest event written"
assert_file_contains "$(audit_events_path)" '"event":"agent-plan"' "events: plan event written"

# ═══════════════════════════════════════════════════════════════
# 3. SUBSYSTEM_CLAIM
# ═══════════════════════════════════════════════════════════════

record_subsystem_claim 1 "deep_investigation" "deep_investigation-1-generic" "unknown" "src/lib" 2>/dev/null

assert_file_contains "$INDEX" "SUBSYSTEM_CLAIM: agent=1 launch=deep_investigation" "claim: line logged"
assert_file_contains "$INDEX" "before=unknown after=src/lib changed=1" "claim: before/after logged"
assert_file_contains "$(audit_events_path)" '"event":"subsystem-claim"' "events: claim event written"

# ═══════════════════════════════════════════════════════════════
# 4. STRATEGY_STATUS and STRATEGY_ROTATION
# ═══════════════════════════════════════════════════════════════

log_strategy_status 1 "src/lib" "S1" 2 8 0 "keep" 2>/dev/null
log_strategy_rotation 1 "src/lib" "S1" "S2" 8 8 "llm" "S1 exhausted" 2>/dev/null

assert_file_contains "$INDEX" "STRATEGY_STATUS: agent=1 subsystem=src/lib strategy=S1 dry=2/8 productive=0 action=keep" "strategy status: line logged"
assert_file_contains "$INDEX" "STRATEGY_ROTATION: agent=1 subsystem=src/lib from=S1 to=S2 dry=8/8 picker=llm reason=\"S1 exhausted\"" "strategy rotation: line logged"
assert_file_contains "$(audit_events_path)" '"event":"strategy-status"' "events: strategy status event written"
assert_file_contains "$(audit_events_path)" '"event":"strategy-rotation"' "events: strategy rotation event written"

# ═══════════════════════════════════════════════════════════════
# 5. assign_subsystem_from_coverage logs without contaminating stdout
# ═══════════════════════════════════════════════════════════════

source "$SCRIPT_ROOT/lib/prompt.sh"

IS_BROWSER_TARGET=1
ITERATION_CACHE_DIR="$LOGDIR/.iter_cache"
mkdir -p "$ITERATION_CACHE_DIR"
printf '%s\n' "js/src/jit" "js/src/wasm" > "$ITERATION_CACHE_DIR/coverage_shell.txt"

get_agent_subsystem() {
  case "$1" in
    1) echo "js/src/jit" ;;
    *) echo "unknown" ;;
  esac
}
export -f get_agent_subsystem

suggested=$(assign_subsystem_from_coverage 2 2>/dev/null)
assert_eq "js/src/wasm" "$suggested" "assign: stdout contains only selected subsystem"
assert_file_contains "$INDEX" "SUBSYSTEM_SUGGEST: agent=2 mode=shell selected=js/src/wasm source=coverage-cache" "assign: suggestion logged"
assert_file_contains "$INDEX" "skipped_claimed=\"js/src/jit\"" "assign: claimed subsystem skip logged"

teardown_test_env
summary
