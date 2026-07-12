#!/usr/bin/env bash
# Minimal shared support for the two suites that test real shell behavior.

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
export SCRIPT_ROOT

export LLM_DECIDE_DISABLE="${LLM_DECIDE_DISABLE:-1}"
unset AUDIT_BUILD_SUFFIX

_SUITE_PASS=0
_SUITE_FAIL=0

setup_test_env() {
  TEST_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/audit-test-XXXXXXXX") || return
  export TEST_TMPDIR
}

teardown_test_env() {
  [ -n "${TEST_TMPDIR:-}" ] && rm -rf "$TEST_TMPDIR"
}

pass() {
  _SUITE_PASS=$((_SUITE_PASS + 1))
  printf "  \033[0;32m✓\033[0m %s\n" "$1"
}

fail() {
  _SUITE_FAIL=$((_SUITE_FAIL + 1))
  printf "  \033[0;31m✗\033[0m %s\n" "$1"
  [ -n "${2:-}" ] && printf "    %s\n" "$2"
}

assert_eq() {
  local expected="$1" actual="$2" name="$3"
  if [ "$expected" = "$actual" ]; then
    pass "$name"
  else
    fail "$name" "expected='$expected' actual='$actual'"
  fi
}

assert_match() {
  local pattern="$1" actual="$2" name="$3"
  if grep -qE -- "$pattern" <<< "$actual"; then
    pass "$name"
  else
    fail "$name" "pattern='$pattern' not found in: $(head -3 <<< "$actual")"
  fi
}

assert_not_match() {
  local pattern="$1" actual="$2" name="$3"
  if grep -qE -- "$pattern" <<< "$actual"; then
    fail "$name" "pattern='$pattern' unexpectedly found in output"
  else
    pass "$name"
  fi
}

summary() {
  local total=$((_SUITE_PASS + _SUITE_FAIL))
  if [ "$_SUITE_FAIL" -eq 0 ]; then
    printf "  \033[0;32m%d/%d passed\033[0m\n" "$_SUITE_PASS" "$total"
    return 0
  fi
  printf "  \033[0;31m%d/%d passed, %d failed\033[0m\n" \
    "$_SUITE_PASS" "$total" "$_SUITE_FAIL"
  return 1
}
