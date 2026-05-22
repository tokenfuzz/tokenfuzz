#!/usr/bin/env bash
# tests/test_decision_cluster_expand.sh — expand_cluster_for_crash.
#
# 1. After a CRASH lands, sibling rows are appended to the state file.
# 2. Already-expanded crashes are skipped (idempotent).
# 3. Disabled mode → no rows appended.
# 4. Empty/no top frames → no LLM call, no append.

set -uo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/llm_decide.sh"
source "$SCRIPT_ROOT/lib/triage.sh"

setup_test_env

mk_state_file() {
  local sf="$RESULTS_DIR/AUDIT_STATE-1.md"
  cat > "$sf" <<'EOF'
# Audit State (agent 1)
## Hypotheses
| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |
|---|-----------|--------------------|-------------|-----------|--------------------|----------|--------|
| 1 | base hyp | x.cpp:foo:1 | none | none | bounds | S1 | DISCARDED |
EOF
  echo "$sf"
}

mk_crash_with_frames() {
  local id="$1"
  local d="$RESULTS_DIR/crashes/$id"
  mkdir -p "$d"
  cat > "$d/asan-output.txt" <<EOF
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 8
    #0 0x100 in mozilla::Foo::parse() src/foo/Foo.cpp:142
    #1 0x200 in mozilla::Foo::dispatch() src/foo/Foo.cpp:88
    #2 0x300 in main() src/main.cpp:1
EOF
  cat > "$d/report.md" <<EOF
# $id stub
heap-buffer-overflow
EOF
  echo "$d"
}

state_file=$(mk_state_file)
mk_crash_with_frames CRASH-AA >/dev/null

# 1. LLM provides 3 sibling rows
export LLM_DECIDE_MOCK_CLUSTER_EXPAND=$(cat <<'EOF'
{
  "rows": [
    {"file":"src/foo/Foo.cpp","function":"parseAlt","line":160,"hypothesis":"sibling parser shares the bound","category":"bounds"},
    {"file":"src/foo/Foo.cpp","function":"parseHeader","line":50,"hypothesis":"caller passes truncated len","category":"size"},
    {"file":"src/foo/Bar.cpp","function":"forward","line":12,"hypothesis":"forwarding skips the same check","category":"bounds"}
  ]
}
EOF
)

AGENT_CLUSTER_STATE="$state_file" expand_cluster_for_crash "$RESULTS_DIR/crashes/CRASH-AA" >/dev/null 2>&1

assert_file_contains "$state_file" "Cluster expansion from CRASH-AA" "header appended"
assert_file_contains "$state_file" "parseAlt" "sibling 1 appended"
assert_file_contains "$state_file" "parseHeader" "sibling 2 appended"
assert_file_contains "$state_file" "Bar.cpp:forward" "sibling 3 appended"
assert_file_exists   "$RESULTS_DIR/crashes/CRASH-AA/.cluster_expanded" "marker written"

# 2. Idempotent: a second call must NOT add another section
before_lines=$(wc -l < "$state_file")
expand_cluster_for_crash "$RESULTS_DIR/crashes/CRASH-AA" "$state_file" >/dev/null 2>&1
after_lines=$(wc -l < "$state_file")
assert_eq "$before_lines" "$after_lines" "idempotent: no second append"
unset LLM_DECIDE_MOCK_CLUSTER_EXPAND

# 3. Disabled → no append
mk_crash_with_frames CRASH-BB >/dev/null
before_lines=$(wc -l < "$state_file")
LLM_DECIDE_DISABLE=1 expand_cluster_for_crash "$RESULTS_DIR/crashes/CRASH-BB" "$state_file" >/dev/null 2>&1
after_lines=$(wc -l < "$state_file")
assert_eq "$before_lines" "$after_lines" "disabled: state unchanged"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-BB/.cluster_expanded" "disabled: no marker"

# 4. No frames → no append. Build a CRASH-CC with empty asan output.
d="$RESULTS_DIR/crashes/CRASH-CC"
mkdir -p "$d"
printf 'no frames here\n' > "$d/asan-output.txt"
before_lines=$(wc -l < "$state_file")
export LLM_DECIDE_MOCK_CLUSTER_EXPAND='{"rows":[{"file":"x","function":"y","line":1,"hypothesis":"a","category":"bounds"},{"file":"x","function":"y","line":2,"hypothesis":"b","category":"bounds"},{"file":"x","function":"y","line":3,"hypothesis":"c","category":"bounds"}]}'
expand_cluster_for_crash "$d" "$state_file" >/dev/null 2>&1
after_lines=$(wc -l < "$state_file")
assert_eq "$before_lines" "$after_lines" "no frames: state unchanged"
unset LLM_DECIDE_MOCK_CLUSTER_EXPAND

# 5. Malformed JSON → no append, no marker
mk_crash_with_frames CRASH-DD >/dev/null
before_lines=$(wc -l < "$state_file")
export LLM_DECIDE_MOCK_CLUSTER_EXPAND='not json'
expand_cluster_for_crash "$RESULTS_DIR/crashes/CRASH-DD" "$state_file" >/dev/null 2>&1
after_lines=$(wc -l < "$state_file")
assert_eq "$before_lines" "$after_lines" "malformed: state unchanged"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-DD/.cluster_expanded" "malformed: no marker"
unset LLM_DECIDE_MOCK_CLUSTER_EXPAND

teardown_test_env
summary
