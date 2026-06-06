#!/usr/bin/env bash
# Tests for tests/run-tests.sh itself: discovery filters and suite exit handling.
set -o pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
setup_test_env

RUNNER="$TESTS_DIR/run-tests.sh"
tmp_script="$TESTS_DIR/test_runner_tmp_$$.sh"
tmp_fail_script="$TESTS_DIR/test_runner_tmp_fail_$$.sh"
trap 'rm -f "$tmp_script" "$tmp_fail_script"; teardown_test_env' EXIT

cat > "$tmp_script" <<'EOF'
#!/usr/bin/env bash
exit 7
EOF

rc=0
output=$(bash "$RUNNER" --jobs 1 "$(basename "$tmp_script")" 2>&1) || rc=$?
assert_eq "1" "$rc" "runner: nonzero suite without assertion marks fails run"
assert_match "Failed suites: test_runner_tmp_" "$output" "runner: nonzero suite is named"
assert_match "Suite exit code: 7" "$output" "runner: nonzero suite exit code is printed"
assert_match "RESULTS: .*0 passed.*, .*0 failed" "$output" "runner: assertion count stays separate from suite errors"
assert_match "Total time:.*[0-9]+[hms0-9]* \\([0-9]+s\\)" "$output" \
  "runner: summary prints total wall time"
green=$'\033[0;32m'
red=$'\033[0;31m'
nc=$'\033[0m'
if [[ "$output" == *"${green}0 failed${nc}"* ]]; then
  pass "runner: zero failed count is green"
else
  fail "runner: zero failed count is green" "$output"
fi

cat > "$tmp_fail_script" <<'EOF'
#!/usr/bin/env bash
printf '  ✗ synthetic assertion failure\n'
EOF

rc=0
output=$(bash "$RUNNER" --jobs 1 "$(basename "$tmp_fail_script")" 2>&1) || rc=$?
assert_eq "1" "$rc" "runner: assertion failure marks run failed"
if [[ "$output" == *"${red}1 failed${nc}"* ]]; then
  pass "runner: nonzero failed count is red"
else
  fail "runner: nonzero failed count is red" "$output"
fi

rc=0
output=$(bash "$RUNNER" --jobs 1 "__no_such_test__.sh" 2>&1) || rc=$?
assert_eq "2" "$rc" "runner: no matched tests is usage failure"
assert_match "no tests matched" "$output" "runner: no-match diagnostic is clear"

list=$(bash "$RUNNER" --list --category wrapper)
if printf '%s\n' "$list" | awk 'NF && $1 != "wrapper" { bad=1 } END { exit bad ? 1 : 0 }'; then
  pass "runner: category list contains only requested category"
else
  fail "runner: category list contains only requested category" "$list"
fi
assert_match "test_rg_wrapper.sh" "$list" "runner: wrapper category includes wrapper tests"
assert_not_match "test_decision_" "$list" "runner: wrapper category excludes decision tests"

# ── parallel scheduling: weights + longest-processing-time-first order ──
# Pull the scheduler helpers out of the runner (sourcing the whole script
# would execute the suite). Then drive them directly.
eval "$(awk '/^test_category\(\) \{/,/^}/' "$RUNNER")"
eval "$(awk '/^bootstrap_weight\(\) \{/,/^}/' "$RUNNER")"
eval "$(awk '/^test_weight\(\) \{/,/^}/' "$RUNNER")"
eval "$(awk '/^load_prior_timings\(\) \{/,/^}/' "$RUNNER")"
eval "$(awk '/^prioritize_parallel_tests\(\) \{/,/^}/' "$RUNNER")"

# --- cold start (no timing artifact): bootstrap leads, rest is coarse ---
PRIOR_TIMINGS=""
heavy_w=$(test_weight test_benchmark.sh)
light_w=$(test_weight test_argparse_need_arg.sh)
if [ "$heavy_w" -gt "$light_w" ] && [ "$heavy_w" -ge 15 ]; then
  pass "runner: cold-start bootstrap ranks a known-slow suite above a trivial one"
else
  fail "runner: cold-start bootstrap ranks a known-slow suite above a trivial one" \
    "benchmark=$heavy_w argparse=$light_w"
fi
assert_eq "1" "$(test_weight test_audit_helpers_py.py)" \
  "runner: python suites weigh 1 by category fallback"

# --- self-calibration: measured seconds from the artifact override all ---
# A suite with NO bootstrap entry, given a large recorded time, must
# outrank a bootstrap-heavy suite — proving weights track real timings.
tmp_timings="$TEST_TMPDIR/test-timings.tsv"
printf 'suite\tcategory\tpassed\tfailed\trc\tseconds\tweight\tpath\n' > "$tmp_timings"
printf 'test_argparse_need_arg\tunit\t5\t0\t0\t999\t2\tx\n' >> "$tmp_timings"
printf 'test_benchmark\tunit\t9\t0\t0\t3\t69\tx\n' >> "$tmp_timings"
PRIOR_TIMINGS=""
TEST_TIMINGS_FILE="$tmp_timings" load_prior_timings
assert_eq "999" "$(test_weight test_argparse_need_arg.sh)" \
  "runner: recorded seconds become the weight (self-calibrating)"
assert_eq "3" "$(test_weight test_benchmark.sh)" \
  "runner: a recorded fast time overrides the heavy bootstrap value"

# prioritize_parallel_tests must emit suites in non-increasing weight
# order (LPT): the launcher consumes TEST_FILES in order as slots free,
# so a heavier suite appearing after a lighter one would start late.
PRIOR_TIMINGS=""   # back to bootstrap weights for a predictable order
TEST_FILES=(
  "$TESTS_DIR/test_argparse_need_arg.sh"   # light
  "$TESTS_DIR/test_benchmark.sh"           # heaviest (bootstrap)
  "$TESTS_DIR/test_prompt.sh"              # mid (category)
  "$TESTS_DIR/test_workqueue.sh"           # heavy (bootstrap)
)
prioritize_parallel_tests
order_ok=1
prev=1000000
for tf in "${TEST_FILES[@]}"; do
  w=$(test_weight "$tf")
  [ "$w" -le "$prev" ] || order_ok=0
  prev="$w"
done
if [ "$order_ok" -eq 1 ]; then
  pass "runner: prioritize_parallel_tests orders suites longest-first (LPT)"
else
  fail "runner: prioritize_parallel_tests orders suites longest-first (LPT)" \
    "got: ${TEST_FILES[*]##*/}"
fi
assert_eq "test_benchmark.sh" "${TEST_FILES[0]##*/}" \
  "runner: the heaviest suite is scheduled first"

summary
