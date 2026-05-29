#!/usr/bin/env bash
# Unit tests for the bin/audit output-dir instance lock.
# Covers: fresh acquire, double-acquire refusal, --allow-concurrent bypass,
# stale-PID reclamation, release-on-exit.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

audit_extract_function() {
  local name="$1"
  awk -v name="$name" '
    $0 ~ "^" name "\\(\\) \\{" { in_func=1 }
    in_func { print }
    in_func && $0 == "}" { exit }
  ' "$SCRIPT_ROOT/bin/audit"
}

# Pull the two helpers out of bin/audit into the test scope.
eval "$(audit_extract_function audit_acquire_instance_lock)"
eval "$(audit_extract_function audit_release_instance_lock)"

# log() is a bin/audit primitive; provide a quiet stub so the helpers'
# FATAL-path log call doesn't blow up the test on missing function.
log() { echo "$*" >&2; }

# ── Fresh acquire creates the lock dir and the PID file ───────────
LOGDIR_FRESH="$TEST_TMPDIR/fresh-logs"
mkdir -p "$LOGDIR_FRESH"
(
  LOGDIR="$LOGDIR_FRESH"
  ALLOW_CONCURRENT_AUDIT=0
  INSTANCE_LOCK_DIR=""
  INSTANCE_LOCK_ACQUIRED=0
  audit_acquire_instance_lock
  echo "$INSTANCE_LOCK_DIR" > "$LOGDIR/.echoed-dir"
  echo "$INSTANCE_LOCK_ACQUIRED" > "$LOGDIR/.echoed-flag"
)
fresh_rc=$?
assert_eq "0" "$fresh_rc" "fresh acquire returns 0"
assert_dir_exists "$LOGDIR_FRESH/.instance.lock.d" "lock dir created"
assert_file_exists "$LOGDIR_FRESH/.instance.lock.d/pid" "PID file created"
assert_file_contains "$LOGDIR_FRESH/.echoed-flag" "1" "INSTANCE_LOCK_ACQUIRED=1"

# ── Second acquire on the same LOGDIR with a LIVE holder is refused ───
# Plant a PID file pointing at a process that's guaranteed alive: $$ (the
# test runner itself). The lock dir already exists from the fresh-acquire
# block above; we just need to ensure the PID inside is alive.
echo "$$" > "$LOGDIR_FRESH/.instance.lock.d/pid"
(
  LOGDIR="$LOGDIR_FRESH"
  ALLOW_CONCURRENT_AUDIT=0
  INSTANCE_LOCK_DIR=""
  INSTANCE_LOCK_ACQUIRED=0
  audit_acquire_instance_lock
) 2>"$TEST_TMPDIR/refuse.stderr"
refuse_rc=$?
assert_neq "0" "$refuse_rc" "second acquire with live holder exits non-zero"
assert_file_contains "$TEST_TMPDIR/refuse.stderr" "another bin/audit instance" "FATAL message names another instance"
assert_file_contains "$TEST_TMPDIR/refuse.stderr" "allow-concurrent" "FATAL message mentions the override flag"

# ── --allow-concurrent (ALLOW_CONCURRENT_AUDIT=1) bypasses the lock ──
# The lock dir from the fresh acquire is still present; with the bypass
# we expect no error, no FATAL, and INSTANCE_LOCK_ACQUIRED stays at 0.
(
  LOGDIR="$LOGDIR_FRESH"
  ALLOW_CONCURRENT_AUDIT=1
  INSTANCE_LOCK_DIR=""
  INSTANCE_LOCK_ACQUIRED=0
  audit_acquire_instance_lock
  echo "$INSTANCE_LOCK_ACQUIRED" > "$LOGDIR/.bypass-flag"
) 2>"$TEST_TMPDIR/bypass.stderr"
bypass_rc=$?
assert_eq "0" "$bypass_rc" "--allow-concurrent returns 0 even when locked"
assert_file_contains "$LOGDIR_FRESH/.bypass-flag" "0" "INSTANCE_LOCK_ACQUIRED stays 0 under bypass"
if grep -q "another bin/audit instance" "$TEST_TMPDIR/bypass.stderr" 2>/dev/null; then
  fail "no FATAL emitted under bypass" "bypass.stderr contained FATAL message"
else
  pass "no FATAL emitted under bypass"
fi

# ── Stale-PID reclamation: lock held by a dead PID is reclaimed ──────
LOGDIR_STALE="$TEST_TMPDIR/stale-logs"
mkdir -p "$LOGDIR_STALE/.instance.lock.d"
# Pick a PID that's guaranteed dead. PID 1 is always alive; PID 99999 is
# almost certainly free, but to be robust pick a PID we know was never
# allocated this session by forking and reading the child's PID after
# the child exits.
(
  exec sh -c 'echo $$'
) > "$TEST_TMPDIR/dead.pid"
dead_pid=$(cat "$TEST_TMPDIR/dead.pid")
# Wait briefly to make sure the kernel has reaped the PID.
sleep 0.1
if kill -0 "$dead_pid" 2>/dev/null; then
  # PID got reused — pick a clearly-unallocated one as fallback.
  dead_pid=99999
  while kill -0 "$dead_pid" 2>/dev/null; do
    dead_pid=$((dead_pid - 1))
    [ "$dead_pid" -lt 1000 ] && break
  done
fi
echo "$dead_pid" > "$LOGDIR_STALE/.instance.lock.d/pid"
(
  LOGDIR="$LOGDIR_STALE"
  ALLOW_CONCURRENT_AUDIT=0
  INSTANCE_LOCK_DIR=""
  INSTANCE_LOCK_ACQUIRED=0
  audit_acquire_instance_lock
  echo "$INSTANCE_LOCK_ACQUIRED" > "$LOGDIR/.reclaim-flag"
) 2>"$TEST_TMPDIR/reclaim.stderr"
reclaim_rc=$?
assert_eq "0" "$reclaim_rc" "stale-PID reclaim returns 0"
assert_file_contains "$LOGDIR_STALE/.reclaim-flag" "1" "INSTANCE_LOCK_ACQUIRED=1 after reclaim"
assert_file_contains "$TEST_TMPDIR/reclaim.stderr" "reclaimed stale lock" "stale-reclaim log emitted"

# ── Release removes the lock dir when we own it ──────────────────────
LOGDIR_REL="$TEST_TMPDIR/rel-logs"
mkdir -p "$LOGDIR_REL"
(
  LOGDIR="$LOGDIR_REL"
  ALLOW_CONCURRENT_AUDIT=0
  INSTANCE_LOCK_DIR=""
  INSTANCE_LOCK_ACQUIRED=0
  audit_acquire_instance_lock
  audit_release_instance_lock
)
release_rc=$?
assert_eq "0" "$release_rc" "release returns 0"
assert_dir_not_exists "$LOGDIR_REL/.instance.lock.d" "lock dir removed after release"

# ── Release is a no-op when we did not acquire ───────────────────────
LOGDIR_NOOP="$TEST_TMPDIR/noop-logs"
mkdir -p "$LOGDIR_NOOP/.instance.lock.d"
echo "$$" > "$LOGDIR_NOOP/.instance.lock.d/pid"   # someone else owns it
(
  LOGDIR="$LOGDIR_NOOP"
  INSTANCE_LOCK_ACQUIRED=0
  INSTANCE_LOCK_DIR=""
  audit_release_instance_lock
)
assert_dir_exists "$LOGDIR_NOOP/.instance.lock.d" "release does not touch others' lock"

teardown_test_env
summary
