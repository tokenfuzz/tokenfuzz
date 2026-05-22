#!/usr/bin/env bash
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

source "$SCRIPT_ROOT/lib/platform.sh"

sample="$TEST_TMPDIR/platform-sample.txt"
printf 'alpha\nbeta\n' > "$sample"

_CURRENT_TEST="platform: stat key includes mtime and size"
key="$(audit_stat_key "$sample" 2>/dev/null || true)"
if [[ "$key" =~ ^[0-9]+:[0-9]+$ ]]; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "unexpected key: $key"
fi

_CURRENT_TEST="platform: in-place sed works"
audit_sed_in_place 's/beta/gamma/' "$sample"
assert_file_contains "$sample" '^gamma$' "$_CURRENT_TEST"

_CURRENT_TEST="platform: sha1 helper returns output"
sha="$(audit_sha1 "$sample" 2>/dev/null | awk '{print $1}')"
if [ -n "$sha" ]; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "empty hash"
fi

_CURRENT_TEST="platform: sha256 helper returns output"
sha256="$(audit_sha256 "$sample" 2>/dev/null | awk '{print $1}')"
if [[ "$sha256" =~ ^[0-9a-f]{64}$ ]]; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "unexpected hash: $sha256"
fi

_CURRENT_TEST="platform: CPU count helper returns a positive integer"
cpu_count="$(audit_cpu_count)"
if [[ "$cpu_count" =~ ^[0-9]+$ ]] && [ "$cpu_count" -ge 1 ]; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "unexpected count: $cpu_count"
fi

_CURRENT_TEST="platform: epoch formatter ignores same-named files"
epoch=1700000000
touch "$TEST_TMPDIR/$epoch"
year="$(cd "$TEST_TMPDIR" && audit_format_epoch_local "$epoch" '%Y')"
assert_eq "2023" "$year" "$_CURRENT_TEST"

_CURRENT_TEST="platform: epoch formatter rejects non-numeric input"
if audit_format_epoch_local "not-an-epoch" '%Y' >/dev/null 2>&1; then
  fail "$_CURRENT_TEST" "formatter accepted invalid input"
else
  pass "$_CURRENT_TEST"
fi

_CURRENT_TEST="platform: LLVM lookup returns requested tool name when absent"
tool="$(PATH=/no/such/path LLVM_PREFIX= audit_llvm_tool definitely-not-a-real-llvm-tool)"
assert_eq "definitely-not-a-real-llvm-tool" "$tool" "$_CURRENT_TEST"

teardown_test_env
summary
