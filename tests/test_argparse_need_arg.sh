#!/usr/bin/env bash
# tests/test_argparse_need_arg.sh — Regression: value-bearing flags must
# fail with a controlled usage error (exit 2, "<tool> <flag> requires a
# value"), not crash with an unbound-variable trace from `set -u` when
# the operator types `bin/<tool> --flag` with no value behind it.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# Each row: TOOL <space> FLAG <space> EXPECTED-EXIT-CODE.
# coverage-summary / hits / audit-recon all use exit 2 for argparse;
# validate-finding uses exit 4 (its existing convention).
ROWS=(
  "coverage-summary  --slug          2"
  "coverage-summary  --depth         2"
  "coverage-summary  --min-edges     2"
  "coverage-summary  --format        2"
  "coverage-summary  --out           2"
  "coverage-summary  --results-dir   2"
  "hits              --testcase      2"
  "hits              --want          2"
  "hits              --mode          2"
  "hits              --timeout       2"
  "hits              --save          2"
  "hits              --log           2"
  "hits              --slug          2"
  "hits              --agent         2"
  "audit-recon       --target        2"
  "audit-recon       --target-path   2"
  "audit-recon       --backend       2"
  "audit-recon       --concurrency   2"
  "audit-recon       --out           2"
  "audit-recon       --report        2"
  "audit-recon       --timeout       2"
  "audit-recon       --validate      2"
  "audit-recon       --scope         2"
  "audit-recon       --path          2"
  "audit-recon       --recon-lookback 2"
  "validate-finding  --finding       2"
  "validate-finding  --target-path   2"
  "validate-finding  --backend       2"
  "validate-finding  --model         2"
  "validate-finding  --gate          2"
  "validate-finding  --output        2"
  "validate-finding  --timeout       2"
)

for row in "${ROWS[@]}"; do
  set -- $row
  tool="$1"; flag="$2"; expected_rc="$3"
  out=$("$SCRIPT_ROOT/bin/$tool" "$flag" 2>&1) || rc=$?
  rc="${rc:-0}"
  if [ "$rc" -eq "$expected_rc" ] \
     && { grep -qF -- "$flag requires a value" <<<"$out" \
          || grep -qE -- "argument .*${flag#--}.*: expected one argument" <<<"$out"; }; then
    pass "$tool $flag: returns rc=$expected_rc with usage error"
  else
    fail "$tool $flag: expected rc=$expected_rc + usage error" \
         "got rc=$rc, out=$out"
  fi
  unset rc
done

out=$("$SCRIPT_ROOT/bin/coverage-summary" --depth 0 2>&1) || rc=$?
rc="${rc:-0}"
if [ "$rc" -eq 2 ] && grep -qF -- '--depth must be a positive integer' <<<"$out"; then
  pass "coverage-summary rejects zero grouping depth"
else
  fail "coverage-summary rejects zero grouping depth" "got rc=$rc, out=$out"
fi
unset rc

teardown_test_env
summary
