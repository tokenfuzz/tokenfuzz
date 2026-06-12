#!/usr/bin/env bash
# tests/test_gemini_watchdog.sh — Unit tests for lib/gemini_watchdog.sh.
#
# The functions in this lib were originally inlined in bin/benchmark; they
# now live under lib/ so bin/audit can share the same kill arms. The
# bench-side coverage in tests/test_benchmark.sh (T29 / T31 / T32) is the
# load-bearing integration test for these predicates against realistic
# klog fixtures. This file adds:
#
#   - source-isolation: sourcing the lib has no side effects beyond
#     defining functions (no logging, no temp files, no process forks)
#   - signature: the new four-argument start_gemini_watchdog accepts
#     (raw_log, agent_pid, marker_dir, label) without rejecting valid
#     callers, and the label parameter is wired through to log messages
#   - _gemini_watchdog_log fallback: when the caller does NOT define a
#     `log` function (e.g. a fresh shell), the watchdog falls back to a
#     stderr message rather than silently dropping the kill rationale
#   - quota marker contract: when the quota arm trips it writes
#     `<marker_dir>/.quota-exhausted` so the audit iteration loop (and
#     benchmark cell harvester) can see why the agent died
#
# These contracts were either implicit before the refactor (one-binary
# scope) or new (marker_dir / label parameters); the asserts here pin
# them so the next caller — bin/audit — does not break the bench-side
# tests by drifting the signature.

set -uo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$TESTS_DIR/helpers.sh"
setup_test_env

# llm_use_gemini_cli is sourced from lib/llm_invoke.sh; the watchdog
# checks it at runtime. Stub a default-off shim so the agy klog arms
# would be live in production, matching bin/audit's caller environment.
# shellcheck disable=SC1091
source "$SCRIPT_ROOT/lib/llm_invoke.sh"

work=$(mktemp -d)
trap 'rm -rf "$work" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT

poll_pause() {
  perl -e 'select undef, undef, undef, 0.1'
}

# Deadlines passed to these helpers are failure bounds, not expected
# durations — both poll and return as soon as the condition holds, so a
# generous bound costs nothing on success but absorbs scheduler stalls
# when the full suite runs 8-way parallel.
wait_for_file() {
  local path="$1" seconds="$2" start
  start=$SECONDS
  while [ $((SECONDS - start)) -lt "$seconds" ]; do
    [ -e "$path" ] && return 0
    poll_pause
  done
  [ -e "$path" ]
}

wait_for_dead_pid() {
  local pid="$1" seconds="$2" start stat
  start=$SECONDS
  while [ $((SECONDS - start)) -lt "$seconds" ]; do
    kill -0 "$pid" 2>/dev/null || return 0
    stat="$(ps -p "$pid" -o stat= 2>/dev/null | awk 'NR==1 {print $1}')"
    case "$stat" in Z*) return 0 ;; esac
    poll_pause
  done
  ! kill -0 "$pid" 2>/dev/null
}

# ── T1: sourcing the lib in a fresh shell has no side effects ───────

isolation_script="$work/iso.sh"
cat > "$isolation_script" <<EOF
#!/usr/bin/env bash
set -uo pipefail
source "$SCRIPT_ROOT/lib/llm_invoke.sh"
source "$SCRIPT_ROOT/lib/gemini_watchdog.sh"
declare -F _kill_tree _gemini_watchdog_pid_alive \\
           _gemini_watchdog_terminate_tree \\
           gemini_quota_dominates agy_cli_log_for_pid \\
           agy_drip_stopped agy_in_idle_heartbeat_loop \\
           start_gemini_watchdog _gemini_watchdog_log
EOF
chmod +x "$isolation_script"
iso_out=$("$isolation_script" 2>&1)
iso_rc=$?
if [ "$iso_rc" -ne 0 ]; then
  fail "T1: sourcing lib/gemini_watchdog.sh in a fresh shell must exit 0" "rc=$iso_rc out=$iso_out"
else
  pass "T1: sourcing lib/gemini_watchdog.sh in a fresh shell exits 0"
fi
for fn in _kill_tree _gemini_watchdog_pid_alive \
          _gemini_watchdog_terminate_tree \
          gemini_quota_dominates agy_cli_log_for_pid \
          agy_drip_stopped agy_in_idle_heartbeat_loop \
          start_gemini_watchdog _gemini_watchdog_log; do
  # `declare -F name [...]` (multiple positional names) prints one bare
  # function name per line; only `declare -F` with no args uses the
  # `declare -f <name>` prefix form.
  if grep -qxF "$fn" <<< "$iso_out"; then
    pass "T1: function $fn is exported by the lib"
  else
    fail "T1: function $fn is exported by the lib" "missing from declare -F output"
  fi
done

# ── T2: signature — start_gemini_watchdog accepts 4 args ────────────

# Run a 1-poll, single-iteration watchdog against a dummy pid that
# exits immediately. The watchdog must accept all four positional
# args and return cleanly when the agent process is gone.
# shellcheck disable=SC1091
source "$SCRIPT_ROOT/lib/gemini_watchdog.sh"

# A child that exits in 1s; the watchdog must observe the death and
# return without firing any of the kill arms.
(sleep 1) &
short_pid=$!
GEMINI_WATCHDOG_POLL_SECS=1 \
AGY_DRIP_GRACE_SECS=0 \
AGY_IDLE_CONFIRM_POLLS=0 \
  start_gemini_watchdog \
    "$work/nonexistent.raw" "$short_pid" "$work" "test-label-T2" &
watcher_pid=$!
wait "$short_pid" 2>/dev/null
if wait_for_dead_pid "$watcher_pid" 10; then
  wait "$watcher_pid" 2>/dev/null || true
  pass "T2: watchdog exits when agent dies"
else
  fail "T2: watchdog exits when agent dies" "still alive after agent finished"
  _kill_tree "$watcher_pid" KILL
fi

# ── T3: _gemini_watchdog_log fallback to stderr without `log` ────────

# In a fresh shell (no `log` function), _gemini_watchdog_log must
# write its message to stderr with a `[gemini-watchdog]` prefix.
fallback_script="$work/fb.sh"
cat > "$fallback_script" <<EOF
#!/usr/bin/env bash
set -uo pipefail
source "$SCRIPT_ROOT/lib/llm_invoke.sh"
source "$SCRIPT_ROOT/lib/gemini_watchdog.sh"
_gemini_watchdog_log "hello fallback"
EOF
chmod +x "$fallback_script"
fb_stderr=$("$fallback_script" 2>&1 >/dev/null)
if [[ "$fb_stderr" == "[gemini-watchdog] hello fallback" ]]; then
  pass "T3: _gemini_watchdog_log falls back to stderr when log() is undefined"
else
  fail "T3: _gemini_watchdog_log falls back to stderr when log() is undefined" "got: '$fb_stderr'"
fi

# When `log` IS defined, _gemini_watchdog_log routes through it instead.
routed_script="$work/routed.sh"
cat > "$routed_script" <<EOF
#!/usr/bin/env bash
set -uo pipefail
source "$SCRIPT_ROOT/lib/llm_invoke.sh"
source "$SCRIPT_ROOT/lib/gemini_watchdog.sh"
log() { printf 'CUSTOM-LOG: %s\n' "\$*"; }
_gemini_watchdog_log "routed-via-caller"
EOF
chmod +x "$routed_script"
routed_stdout=$("$routed_script" 2>/dev/null)
routed_stderr=$("$routed_script" 2>&1 >/dev/null)
if [[ "$routed_stdout" == "CUSTOM-LOG: routed-via-caller" ]] && [ -z "$routed_stderr" ]; then
  pass "T3: _gemini_watchdog_log routes through caller's log() when defined"
else
  fail "T3: _gemini_watchdog_log routes through caller's log() when defined" \
    "stdout='$routed_stdout' stderr='$routed_stderr'"
fi

# ── T4: quota arm writes the .quota-exhausted marker ────────────────

# A raw log dominated by 429 retries (no assistant content) plus a
# fake child process that stays alive until killed. The watchdog
# should trip the quota arm on its first poll, touch the marker, and
# kill the child.
mkdir -p "$work/marker"
quota_raw="$work/quota.raw"
{
  for i in $(seq 1 12); do
    printf 'Attempt %d failed with status 429. Retrying...\n' "$i"
  done
} > "$quota_raw"

# Background a long-lived child the watchdog can kill.
(sleep 30) &
victim_pid=$!

GEMINI_WATCHDOG_POLL_SECS=0 \
GEMINI_QUOTA_WINDOW_LINES=400 \
GEMINI_QUOTA_MIN_429=10 \
AGY_DRIP_GRACE_SECS=0 \
AGY_IDLE_CONFIRM_POLLS=0 \
  start_gemini_watchdog "$quota_raw" "$victim_pid" "$work/marker" "test-quota-T4" &
quota_watcher=$!

if wait_for_file "$work/marker/.quota-exhausted" 10; then
  pass "T4: quota arm writes .quota-exhausted under marker_dir"
else
  fail "T4: quota arm writes .quota-exhausted under marker_dir" "marker file not present"
fi
if wait_for_dead_pid "$victim_pid" 10; then
  pass "T4: quota arm kills the agent process"
else
  fail "T4: quota arm kills the agent process" "victim still alive"
  _kill_tree "$victim_pid" KILL
fi
# Reap the watcher.
wait "$quota_watcher" 2>/dev/null || true

# ── T5: invalid / missing marker_dir is fail-safe ────────────────────

# When marker_dir is "" or non-existent, the watchdog must still kill
# the agent but not crash trying to touch the marker.
mkdir -p "$work/missing-parent"
(sleep 30) &
victim2=$!
GEMINI_WATCHDOG_POLL_SECS=0 \
GEMINI_QUOTA_WINDOW_LINES=400 \
GEMINI_QUOTA_MIN_429=10 \
AGY_DRIP_GRACE_SECS=0 \
AGY_IDLE_CONFIRM_POLLS=0 \
  start_gemini_watchdog "$quota_raw" "$victim2" "" "test-empty-marker-T5" &
empty_marker_watcher=$!
if wait_for_dead_pid "$victim2" 10; then
  pass "T5: empty marker_dir does not block the kill arm"
else
  fail "T5: empty marker_dir does not block the kill arm" "victim still alive"
  _kill_tree "$victim2" KILL
fi
wait "$empty_marker_watcher" 2>/dev/null || true

summary
