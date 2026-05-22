#!/usr/bin/env bash
# tests/test_timeout.sh — Portable timeout helper behavior.

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/timeout.sh"

setup_test_env

audit_timeout_run 2 bash -c 'exit 7'
assert_eq 7 $? "audit_timeout_run preserves command exit code"

audit_timeout_run 1 bash -c 'sleep 5'
assert_eq 124 $? "audit_timeout_run returns 124 on timeout"

escaped_marker="$TEST_TMPDIR/escaped-marker"
rm -f "$escaped_marker"
audit_timeout_run 1 bash -c 'perl -e "setpgrp(0,0); sleep 30; open my \$fh, q(>), shift; print \$fh q(leaked)" "'"$escaped_marker"'"'
assert_eq 124 $? "audit_timeout_run times out escaped child process group"
sleep 3
[ ! -f "$escaped_marker" ] \
  && pass "audit_timeout_run reaps descendant process groups on timeout" \
  || fail "audit_timeout_run reaps descendant process groups on timeout" \
          "descendant survived after changing process group"

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
audit_timeout_kill 5 bash -c '( sleep 30; echo leaked > "'"$reap_marker"'" ) & exit 0'
sleep 3
[ ! -f "$reap_marker" ] \
  && pass "audit_timeout_kill reaps backgrounded grandchildren on normal exit" \
  || fail "audit_timeout_kill reaps backgrounded grandchildren on normal exit" \
          "grandchild survived the process-group sweep"

teardown_test_env
summary
