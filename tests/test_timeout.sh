#!/usr/bin/env bash
# tests/test_timeout.sh — Portable timeout helper behavior.

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/timeout.sh"
source "$SCRIPT_ROOT/lib/process_tree.sh"

setup_test_env

marker_stays_absent_for() {
  local marker="$1" seconds="$2" start
  start=$SECONDS
  while [ $((SECONDS - start)) -lt "$seconds" ]; do
    [ ! -f "$marker" ] || return 1
    perl -e 'select undef, undef, undef, 0.1'
  done
  [ ! -f "$marker" ]
}

audit_timeout_run 2 bash -c 'exit 7'
assert_eq 7 $? "audit_timeout_run preserves command exit code"

audit_timeout_run 1 bash -c 'sleep 5'
assert_eq 124 $? "audit_timeout_run returns 124 on timeout"

escaped_marker="$TEST_TMPDIR/escaped-marker"
rm -f "$escaped_marker"
audit_timeout_run 1 bash -c 'perl -e "setpgrp(0,0); sleep 2; open my \$fh, q(>), shift; print \$fh q(leaked)" "'"$escaped_marker"'"'
assert_eq 124 $? "audit_timeout_run times out escaped child process group"
marker_stays_absent_for "$escaped_marker" 2 \
  && pass "audit_timeout_run reaps descendant process groups on timeout" \
  || fail "audit_timeout_run reaps descendant process groups on timeout" \
          "descendant survived after changing process group"

interrupt_marker="$TEST_TMPDIR/interrupt-marker"
interrupt_rc="$TEST_TMPDIR/interrupt-rc"
interrupt_trigger="$TEST_TMPDIR/interrupt-trigger"
rm -f "$interrupt_marker" "$interrupt_rc" "$interrupt_trigger"
(
  rc=0
  audit_timeout_run 20 bash -c 'trap "" TERM INT; (trap "" TERM INT; while [ ! -f "$2" ]; do sleep 0.1; done; echo leaked > "$1"; sleep 10) & wait' _ "$interrupt_marker" "$interrupt_trigger" || rc=$?
  printf '%s' "$rc" > "$interrupt_rc"
) &
interrupt_shell=$!
sleep 1
interrupt_perl="$(pgrep -P "$interrupt_shell" 2>/dev/null | head -1 || true)"
[ -n "$interrupt_perl" ] && kill -INT "$interrupt_perl" 2>/dev/null || true
wait "$interrupt_shell" 2>/dev/null || true
assert_eq 130 "$(cat "$interrupt_rc" 2>/dev/null || echo missing)" \
  "audit_timeout_run returns 130 on interrupt"
touch "$interrupt_trigger"
marker_stays_absent_for "$interrupt_marker" 1 \
  && pass "audit_timeout_run reaps detached child session on interrupt" \
  || fail "audit_timeout_run reaps detached child session on interrupt" \
          "child session survived after timeout wrapper interrupt"

tree_marker="$TEST_TMPDIR/tree-marker"
tree_trigger="$TEST_TMPDIR/tree-trigger"
rm -f "$tree_marker" "$tree_trigger"
bash -c '(trap "" TERM INT; while [ ! -f "$2" ]; do sleep 0.1; done; echo leaked > "$1"; sleep 10) & wait' _ "$tree_marker" "$tree_trigger" 2>/dev/null &
tree_root=$!
sleep 1
process_tree_kill_descendants "$tree_root" TERM 1
kill "$tree_root" 2>/dev/null || true
wait "$tree_root" 2>/dev/null || true
touch "$tree_trigger"
marker_stays_absent_for "$tree_marker" 1 \
  && pass "process_tree_kill_descendants reaps descendants that ignore TERM" \
  || fail "process_tree_kill_descendants reaps descendants that ignore TERM" \
          "descendant survived process-tree cleanup"

audit_timeout_kill 1 bash -c 'trap "exit 42" TERM; sleep 5'
assert_eq 124 $? "audit_timeout_kill returns 124 on timeout"

# Regression: a child that touches the inherited stdin must not be stopped
# by SIGTTIN/SIGTTOU. Before the setsid fix, a background-pgrp child reading
# from an inherited tty stdin got STOPPED and waitpid blocked until the
# wall-clock alarm — `claude auth status` silently burned a 7200s harness
# cell budget this way. With setsid the child has no controlling tty, so
# the read just returns EOF or data and the command exits cleanly.
ttyless_rc_file="$TEST_TMPDIR/ttyless-rc"
rm -f "$ttyless_rc_file"
audit_timeout_run 5 bash -c 'cat >/dev/null; echo $? > "'"$ttyless_rc_file"'"' </dev/null
assert_eq 0 $? "audit_timeout_run does not stop a child that reads stdin"
[ -f "$ttyless_rc_file" ] && [ "$(cat "$ttyless_rc_file")" = "0" ] \
  && pass "audit_timeout_run child completed its stdin read" \
  || fail "audit_timeout_run child completed its stdin read" \
          "child did not finish (likely SIGTTIN-stopped)"

# audit_timeout_kill sweeps the command's process group on exit, so a
# backgrounded grandchild that outlives the main command is reaped. The
# fuzz runners rely on this to clean up orphaned browser content
# processes without a name-pattern pkill that could hit a sibling agent.
reap_marker="$TEST_TMPDIR/reap-marker"
rm -f "$reap_marker"
audit_timeout_kill 5 bash -c '( sleep 1; echo leaked > "'"$reap_marker"'" ) & exit 0'
marker_stays_absent_for "$reap_marker" 2 \
  && pass "audit_timeout_kill reaps backgrounded grandchildren on normal exit" \
  || fail "audit_timeout_kill reaps backgrounded grandchildren on normal exit" \
          "grandchild survived the process-group sweep"

teardown_test_env
summary
