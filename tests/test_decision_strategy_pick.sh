#!/usr/bin/env bash
# tests/test_decision_strategy_pick.sh — bin/audit:llm_pick_next_strategy.
#
# Verifies:
#   1. LLM-supplied strategy letter is returned.
#   2. Invalid letter falls back (rc=1).
#   3. Disabled mode → rc=1, caller falls back to round-robin.

set -uo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/llm_decide.sh"
source "$SCRIPT_ROOT/lib/prompt.sh"

setup_test_env

# Pull just the function we need without sourcing all of bin/audit
# (which would try to do CLI parsing and exit). Use bash function copy.
audit_extract_function() {
  local fn="$1"
  awk -v fn="$fn" '
    $0 ~ "^"fn"\\(\\) \\{" { in_fn=1 }
    in_fn { print }
    in_fn && $0 == "}" { exit }
  ' "$SCRIPT_ROOT/bin/audit"
}

eval "$(audit_extract_function llm_pick_next_strategy)"

# Output contract: `<letter>\t<reason>` — caller splits on the tab to log
# the picker's reason alongside the letter. Tests assert on the letter.
strat_letter() { printf '%s' "${1%%$'\t'*}"; }

# 1. Valid strategy letter passes through.
export LLM_DECIDE_MOCK_STRATEGY_PICK='{"strategy":"S5","reason":"lifetime hot in this subsystem"}'
out=$(llm_pick_next_strategy 1 S1 dom/canvas 5 2>/dev/null)
assert_eq "S5" "$(strat_letter "$out")" "LLM picked S5"
unset LLM_DECIDE_MOCK_STRATEGY_PICK

# 2. Invalid letter → rc=1
export LLM_DECIDE_MOCK_STRATEGY_PICK='{"strategy":"S99","reason":"nope"}'
out=$(llm_pick_next_strategy 1 S1 dom/canvas 5 2>/dev/null) && rc=0 || rc=$?
assert_eq "1" "$rc" "invalid strategy → rc=1"
assert_eq "" "$out" "invalid strategy → empty stdout"
unset LLM_DECIDE_MOCK_STRATEGY_PICK

# 3. Lowercase / whitespace handling: still must match S1..S8.
unset rc
export LLM_DECIDE_MOCK_STRATEGY_PICK='{"strategy":"s1","reason":"oops"}'
out=$(llm_pick_next_strategy 1 S1 dom/canvas 5 2>/dev/null) && rc=0 || rc=$?
assert_eq "1" "${rc:-0}" "lowercase strategy rejected"
unset LLM_DECIDE_MOCK_STRATEGY_PICK

# 4. Disabled → rc=1, caller falls back.
unset rc
out=$(LLM_DECIDE_DISABLE=1 llm_pick_next_strategy 1 S1 dom/canvas 5 2>/dev/null) && rc=0 || rc=$?
assert_eq "1" "${rc:-0}" "disabled → rc=1"
assert_eq "" "$out" "disabled → empty stdout"

# 5. Each valid letter in S1..S8 is accepted.
for s in S1 S2 S3 S4 S5 S6 S7 S8; do
  export LLM_DECIDE_MOCK_STRATEGY_PICK="{\"strategy\":\"$s\",\"reason\":\"x\"}"
  out=$(llm_pick_next_strategy 1 S1 dom/canvas 5 2>/dev/null)
  assert_eq "$s" "$(strat_letter "$out")" "valid letter $s accepted"
  unset LLM_DECIDE_MOCK_STRATEGY_PICK
done

teardown_test_env
summary
