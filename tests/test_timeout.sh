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
    python3 -c 'import time; time.sleep(0.1)'
  done
  [ ! -f "$marker" ]
}

audit_timeout_run 2 bash -c 'exit 7'
assert_eq 7 $? "audit_timeout_run preserves command exit code"

audit_timeout_run 1 bash -c 'sleep 5'
assert_eq 124 $? "audit_timeout_run returns 124 on timeout"

escaped_marker="$TEST_TMPDIR/escaped-marker"
rm -f "$escaped_marker"
# A descendant that escapes into its OWN session/process group then writes a
# marker after the wrapper's deadline. audit_timeout_run must find it via the
# descendant ps-scan and kill it before the marker lands. The escapee forks a
# child and calls setsid() there: a fresh fork is never a session leader, so
# the new session always succeeds regardless of any exec optimization above
# it. A temp .py file keeps the fixture free of nested-quote escaping.
escapee_py="$TEST_TMPDIR/escapee.py"
cat > "$escapee_py" <<'PY'
import os, sys, time
if os.fork() == 0:
    os.setsid()
    time.sleep(2)
    with open(sys.argv[1], "w") as fh:
        fh.write("leaked")
    os._exit(0)
os.wait()
PY
audit_timeout_run 1 python3 "$escapee_py" "$escaped_marker"
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
interrupt_wrapper="$(pgrep -P "$interrupt_shell" 2>/dev/null | head -1 || true)"
[ -n "$interrupt_wrapper" ] && kill -INT "$interrupt_wrapper" 2>/dev/null || true
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

# RSS watchdog: a 0 cap is byte-identical to audit_timeout_run (no watch path).
audit_timeout_run_rss 2 0 bash -c 'exit 7'
assert_eq 7 $? "audit_timeout_run_rss with 0 cap preserves exit code"
audit_timeout_run_rss 1 0 bash -c 'sleep 5'
assert_eq 124 $? "audit_timeout_run_rss with 0 cap still times out (124)"

# A ballooning child is SIGKILLed once its RSS crosses the cap, well before the
# generous wall-clock timeout — the host-protection path. The marker line the
# watchdog prints is what triage/reachability classify as the OOM class.
rss_done="$TEST_TMPDIR/rss-done"
rss_out="$TEST_TMPDIR/rss-out"
rm -f "$rss_done" "$rss_out"
rss_rc=0
# Balloon with INCOMPRESSIBLE bytes from /dev/urandom. A run of identical bytes
# ("x" x N) is collapsed by the macOS memory compressor once the host is under
# RAM pressure, so its RSS never crosses the cap, the watchdog never fires, and
# the run instead hits the wall-clock timeout (124) rather than the RSS kill
# (137) — green on a roomy dev box, red on a low-RAM CI runner. Random pages
# stay resident and cross the cap within a tick, exercising the watchdog
# deterministically on every host.
balloon_py="$TEST_TMPDIR/balloon.py"
cat > "$balloon_py" <<'PY'
import sys, time
chunks = []
with open("/dev/urandom", "rb") as u:
    while True:
        chunks.append(u.read(10 * 1024 * 1024))
        time.sleep(0.05)
# Unreachable before the RSS cap kills us; kept so the fixture reads as a
# program that would otherwise finish and drop the marker.
with open(sys.argv[1], "w") as f:
    f.write("done")
PY
audit_timeout_run_rss 30 200 python3 "$balloon_py" "$rss_done" >"$rss_out" 2>&1 || rss_rc=$?
assert_eq 137 "$rss_rc" "audit_timeout_run_rss SIGKILLs a child that exceeds the RSS cap"
[ ! -f "$rss_done" ] \
  && pass "RSS-killed child did not run to completion" \
  || fail "RSS-killed child did not run to completion" "child finished despite the cap"
grep -qE 'rss limit (exhausted|exceeded)' "$rss_out" \
  && pass "RSS watchdog prints the OOM/host-protection marker" \
  || fail "RSS watchdog prints the OOM/host-protection marker" "$(cat "$rss_out" 2>/dev/null)"

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

# A child killed by a signal (not the wrapper, not a timeout) exits 128+sig,
# and the wrapper logs which signal hit the child — the fingerprint an external
# kill needs, since macOS records no ordinary SIGTERM. This is the path that a
# `kill`/`pkill` landing on an agent process would take.
sigchild_out="$TEST_TMPDIR/sigchild-out"
sigchild_rc=0
audit_timeout_run 10 bash -c 'kill -TERM $$' >"$sigchild_out" 2>&1 || sigchild_rc=$?
assert_eq 143 "$sigchild_rc" "audit_timeout_run reports 128+SIGTERM for a signal-killed child"
grep -qE 'child pid=[0-9]+ .* killed by SIGTERM' "$sigchild_out" \
  && pass "timeout wrapper logs a child killed directly by a signal" \
  || fail "timeout wrapper logs a child killed directly by a signal" \
          "$(cat "$sigchild_out" 2>/dev/null)"

# The wrapper itself taking a signal logs distinctly ("received … forwarding"),
# so an operator can tell a kill that entered via the wrapper/parent apart from
# one that hit the child directly (above).
fwd_out="$TEST_TMPDIR/fwd-out"
fwd_rc_file="$TEST_TMPDIR/fwd-rc"
rm -f "$fwd_out" "$fwd_rc_file"
(
  rc=0
  audit_timeout_run 20 bash -c 'trap "" TERM; sleep 10' >"$fwd_out" 2>&1 || rc=$?
  printf '%s' "$rc" > "$fwd_rc_file"
) &
fwd_shell=$!
sleep 1
fwd_wrapper="$(pgrep -P "$fwd_shell" 2>/dev/null | head -1 || true)"
[ -n "$fwd_wrapper" ] && kill -TERM "$fwd_wrapper" 2>/dev/null || true
wait "$fwd_shell" 2>/dev/null || true
assert_eq 143 "$(cat "$fwd_rc_file" 2>/dev/null || echo missing)" \
  "audit_timeout_run returns 143 when the wrapper itself is SIGTERMed"
grep -qE 'wrapper pid=[0-9]+ ppid=[0-9]+ received SIGTERM' "$fwd_out" \
  && pass "timeout wrapper logs a signal it received and forwarded" \
  || fail "timeout wrapper logs a signal it received and forwarded" \
          "$(cat "$fwd_out" 2>/dev/null)"

# A child that exits with a signal-range status (128+N) but was NOT itself
# signaled — the propagated-status case. This is the shape bin/audit takes when
# it aborts under set -e after an inner command was killed; the first pass
# (WIFSIGNALED-only) missed it, so it produced no breadcrumb at all.
propagated_out="$TEST_TMPDIR/propagated-out"
propagated_rc=0
audit_timeout_run 10 bash -c 'exit 143' >"$propagated_out" 2>&1 || propagated_rc=$?
assert_eq 143 "$propagated_rc" "audit_timeout_run preserves a signal-range exit code (143)"
grep -qE 'exited 143 .*signal range' "$propagated_out" \
  && pass "timeout wrapper labels a propagated signal-range exit" \
  || fail "timeout wrapper labels a propagated signal-range exit" \
          "$(cat "$propagated_out" 2>/dev/null)"

# harness-r1 shape end-to-end: an inner foreground command under set -e is
# SIGTERMed, so the wrapped script exits 143 by propagation (WIFEXITED 143), not
# by being signaled itself. The wrapper must still leave a breadcrumb.
nested_out="$TEST_TMPDIR/nested-out"
nested_rc_file="$TEST_TMPDIR/nested-rc"
nested_pidfile="$TEST_TMPDIR/nested-inner-pid"
rm -f "$nested_out" "$nested_rc_file" "$nested_pidfile"
(
  rc=0
  audit_timeout_run 20 bash -c 'set -e; sleep 30 & echo $! > "$1"; wait "$!"' \
    _ "$nested_pidfile" >"$nested_out" 2>&1 || rc=$?
  printf '%s' "$rc" > "$nested_rc_file"
) &
nested_shell=$!
nested_inner=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [ -s "$nested_pidfile" ] && { nested_inner="$(cat "$nested_pidfile")"; break; }
  python3 -c 'import time; time.sleep(0.2)'
done
[ -n "$nested_inner" ] && kill -TERM "$nested_inner" 2>/dev/null || true
wait "$nested_shell" 2>/dev/null || true
assert_eq 143 "$(cat "$nested_rc_file" 2>/dev/null || echo missing)" \
  "audit_timeout_run: an inner-command SIGTERM propagates to a 143 script exit"
grep -qE 'exited 143 .*signal range' "$nested_out" \
  && pass "timeout wrapper logs a signal-range WIFEXITED child (harness-r1 shape)" \
  || fail "timeout wrapper logs a signal-range WIFEXITED child (harness-r1 shape)" \
          "$(cat "$nested_out" 2>/dev/null)"

# A program can deliberately use an arbitrary high exit code. Do not invent
# fake signals for values whose 128+N component is not a real signal on this
# platform (for example 255 -> 127 on macOS/Linux).
high_exit_out="$TEST_TMPDIR/high-exit-out"
high_exit_rc=0
audit_timeout_run 10 bash -c 'exit 255' >"$high_exit_out" 2>&1 || high_exit_rc=$?
assert_eq 255 "$high_exit_rc" "audit_timeout_run preserves a high non-signal exit code"
grep -q 'signal range' "$high_exit_out" \
  && fail "timeout wrapper does not label non-signal high exit codes as signal range" \
          "$(cat "$high_exit_out" 2>/dev/null)" \
  || pass "timeout wrapper does not label non-signal high exit codes as signal range"

teardown_test_env
summary
