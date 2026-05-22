#!/usr/bin/env bash
# Regression tests for properties of `structured_state_agent_counts_load`
# that the parity test (`test_agent_counts.sh`) does NOT cover.
#
# The parity test proves the loader returns the same numbers as the legacy
# jq counters — a correctness guarantee. These tests guard the *non-
# correctness* properties whose regressions silently degrade the harness:
#
#   1. Perf: the loader must not shell out to python3/bin/state. The first
#      draft of this migration did, and the python startup cost (~150ms,
#      dominated by importing workqueue.py) was net-slower than the 6 jq
#      counters it replaced. We assert this two ways: structurally (the
#      function source contains no bin/state/python3 references) and
#      behaviorally (a PATH-shimmed python3 is never invoked).
#
#   2. Stderr cleanliness: when a unit test sources lib/quality.sh or
#      lib/prompt.sh without first sourcing lib/structured_state.sh, the
#      loader call must not leak "command not found" to stderr. The
#      legacy single-counter calls had `2>/dev/null` redirects that
#      naturally suppressed this; the migrated call sites must too.
#
# A failure in (1) means agent state-count gathering has gotten slower.
# A failure in (2) means dev-environment runs spam stderr. Neither breaks
# bug-finding, but both are quiet rot — exactly the kind of thing a
# regression test catches before it ships.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

source "$SCRIPT_ROOT/lib/structured_state.sh"

# ═══════════════════════════════════════════════════════════════
# 1. Structural perf-guard: function source must not call python3
# ═══════════════════════════════════════════════════════════════
loader_src=$(declare -f structured_state_agent_counts_load)
if grep -qE 'bin/state|python3|python ' <<<"$loader_src"; then
  offending=$(printf '%s' "$loader_src" | grep -nE 'bin/state|python3|python ' | head -3)
  fail "perf-guard: loader source references bin/state or python3" "$offending"
else
  pass "perf-guard: loader source contains no bin/state/python3 references"
fi

# ═══════════════════════════════════════════════════════════════
# 2. Behavioral perf-guard: PATH-shimmed python3 is never invoked
# ═══════════════════════════════════════════════════════════════
mkdir -p "$RESULTS_DIR/state"
cat > "$RESULTS_DIR/state/hypotheses.jsonl" <<'EOF'
{"id":"H1","agent":"1","status":"PENDING","file":"a.cpp"}
{"id":"H2","agent":"1","status":"INVESTIGATING","file":"b.cpp"}
{"id":"H3","agent":"1","status":"DISCARDED","file":"c.cpp"}
EOF

shim_dir="$TEST_TMPDIR/shim"
mkdir -p "$shim_dir"
probe="$TEST_TMPDIR/python_calls.log"
: > "$probe"

# Shim records every invocation. If the loader ever spawns python3, the
# probe captures it. Exit 1 from the shim would also break the loader
# (which we then notice as a non-zero rc) — belt-and-suspenders.
cat > "$shim_dir/python3" <<SHIM
#!/bin/sh
echo "python3 invoked: \$*" >> "$probe"
exit 1
SHIM
chmod +x "$shim_dir/python3"

orig_path="$PATH"
export PATH="$shim_dir:$PATH"
p=0 a=0 d=0 e=0 n=0 r=0 i=0
structured_state_agent_counts_load 1 p a d e n r i
load_rc=$?
export PATH="$orig_path"

assert_eq "0" "$load_rc" "perf-guard: loader returns 0 with shimmed python3 (proves no python dependency)"
assert_eq "" "$(cat "$probe")" "perf-guard: shimmed python3 was never invoked"
# Sanity: real jq path produced correct counts despite the shim.
assert_eq "1" "$p" "perf-guard: pending=1 (jq path active)"
assert_eq "2" "$a" "perf-guard: active=2 (jq path active)"
assert_eq "1" "$d" "perf-guard: discards=1 (jq path active)"

# ═══════════════════════════════════════════════════════════════
# 3. Stderr-clean: focused probes for call sites that intentionally run
#    without structured_state.sh in some tests. Do not run whole test
#    suites from this regression test: that duplicates expensive coverage
#    and hides the actual dependency being checked.
# ═══════════════════════════════════════════════════════════════
check_no_command_not_found_snippet() {
  local label="$1" snippet="$2"
  local stderr_log="$TEST_TMPDIR/${label}.stderr.log"
  SCRIPT_ROOT="$SCRIPT_ROOT" bash -c "$snippet" >/dev/null 2>"$stderr_log" || true
  if grep -q 'command not found' "$stderr_log"; then
    local hits
    hits=$(grep 'command not found' "$stderr_log" | head -3)
    fail "stderr-clean: $label leaked 'command not found'" "$hits"
  else
    pass "stderr-clean: $label does not leak 'command not found'"
  fi
}

check_no_command_not_found_snippet quality_check_agent_quality '
source "$SCRIPT_ROOT/tests/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/platform.sh"
source "$SCRIPT_ROOT/lib/quality.sh"
printf "%s\n" "| H1 | src/a.c:f:1 | bytes | guard | clean | PENDING |" > "$(state_file_path 1)"
check_agent_quality 1
teardown_test_env
'

check_no_command_not_found_snippet prompt_session_directive '
source "$SCRIPT_ROOT/tests/helpers.sh"
setup_test_env
count_verified_asan_runs() { echo 0; }
export -f count_verified_asan_runs
source "$SCRIPT_ROOT/lib/prompt.sh"
printf "%s\n" "| H1 | src/a.c:f:1 | bytes | guard | clean | PENDING |" > "$(state_file_path 1)"
build_session_directive 1
teardown_test_env
'

check_no_command_not_found_snippet prompt_iteration_cache '
source "$SCRIPT_ROOT/tests/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/prompt.sh"
cache_iteration_data
teardown_test_env
'

check_no_command_not_found_snippet prompt_cross_agent_summary '
source "$SCRIPT_ROOT/tests/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/prompt.sh"
printf "%s\n" "| H2 | src/b.c:f:1 | bytes | guard | clean | NEEDS_TESTCASE |" > "$(state_file_path 2)"
build_cross_agent_summary 1
teardown_test_env
'

check_no_command_not_found_snippet vocab_neutralizer '
source "$SCRIPT_ROOT/tests/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/platform.sh"
source "$SCRIPT_ROOT/lib/vocab.sh"
printf "%s\n" "exploit header" > "$(state_file_path 1)"
neutralize_qa_vocab
teardown_test_env
'

teardown_test_env
summary
