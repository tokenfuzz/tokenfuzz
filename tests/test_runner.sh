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

summary
