#!/usr/bin/env bash
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/housekeeping.sh"

mkdir -p "$TEST_TMPDIR/input"
printf 'a\n' > "$TEST_TMPDIR/input/file.txt"
CALLS="$TEST_TMPDIR/calls"

tracked_task() {
  printf 'run\n' >> "$CALLS"
}

mutating_task() {
  printf 'run\n' >> "$CALLS"
  printf 'generated\n' > "$TEST_TMPDIR/input/generated.txt"
}

failing_task() {
  printf 'fail\n' >> "$CALLS"
  return 7
}

housekeeping_run_if_dirty sample-task tracked_task "$TEST_TMPDIR/input"
housekeeping_run_if_dirty sample-task tracked_task "$TEST_TMPDIR/input"
assert_eq "1" "$(wc -l < "$CALLS" | tr -d ' ')" "housekeeping: unchanged inputs skip second run"

printf 'b\n' >> "$TEST_TMPDIR/input/file.txt"
housekeeping_run_if_dirty sample-task tracked_task "$TEST_TMPDIR/input"
housekeeping_run_if_dirty sample-task tracked_task "$TEST_TMPDIR/input"
assert_eq "2" "$(wc -l < "$CALLS" | tr -d ' ')" "housekeeping: input change reruns once"

: > "$CALLS"
rm -rf "$RESULTS_DIR/.housekeeping-cache"
housekeeping_run_if_dirty mutating-task mutating_task "$TEST_TMPDIR/input"
housekeeping_run_if_dirty mutating-task mutating_task "$TEST_TMPDIR/input"
assert_eq "1" "$(wc -l < "$CALLS" | tr -d ' ')" "housekeeping: post-run signature handles task output mutation"

: > "$CALLS"
rm -rf "$RESULTS_DIR/.housekeeping-cache"
housekeeping_run_if_dirty failing-task failing_task "$TEST_TMPDIR/input" >/dev/null 2>&1
housekeeping_run_if_dirty failing-task failing_task "$TEST_TMPDIR/input" >/dev/null 2>&1
assert_eq "2" "$(wc -l < "$CALLS" | tr -d ' ')" "housekeeping: failed task is not marked clean"

: > "$CALLS"
rm -rf "$RESULTS_DIR/.housekeeping-cache"
housekeeping_run_if_dirty ttl-task tracked_task "$TEST_TMPDIR/input"
stamp=$(housekeeping_stamp_path ttl-task)
sig=$(sed -n '1p' "$stamp")
printf '%s\n1\n' "$sig" > "$stamp"
HOUSEKEEPING_UNCHANGED_RERUN_SECS=3600 housekeeping_run_if_dirty ttl-task tracked_task "$TEST_TMPDIR/input"
assert_eq "2" "$(wc -l < "$CALLS" | tr -d ' ')" "housekeeping: old clean stamp reruns periodically"

teardown_test_env
summary
