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

# The signature is metadata-only and must never read file contents: a sparse
# repro (here 1 TiB logical, a few blocks on disk) must not cost a payload read,
# yet size+mtime must still dirty-detect a change. If content-hashing is ever
# reintroduced, this pass goes from instant to minutes and surfaces loudly here.
LARGE_DIR="$TEST_TMPDIR/large"
mkdir -p "$LARGE_DIR"
if truncate -s 1T "$LARGE_DIR/big.input" 2>/dev/null \
   || dd if=/dev/null of="$LARGE_DIR/big.input" bs=1 seek=1099511627776 count=0 2>/dev/null; then
  sig_before=$(housekeeping_signature large-skip "$LARGE_DIR")
  assert_eq "0" "$?" "housekeeping: signature over large sparse file succeeds"
  assert_neq "" "$sig_before" "housekeeping: signature over large sparse file is non-empty"
  # Growing the file (size change) must still flip the signature.
  truncate -s 2T "$LARGE_DIR/big.input" 2>/dev/null \
    || dd if=/dev/null of="$LARGE_DIR/big.input" bs=1 seek=2199023255552 count=0 2>/dev/null
  sig_after=$(housekeeping_signature large-skip "$LARGE_DIR")
  assert_neq "$sig_before" "$sig_after" "housekeeping: large file change is still dirty-detected by size"
else
  echo "SKIP: cannot create sparse file on this filesystem" >&2
fi

teardown_test_env
summary
