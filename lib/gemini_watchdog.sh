#!/usr/bin/env bash
# lib/gemini_watchdog.sh — shared agy / gemini-cli health watchdog.
#
# Sourced by bin/audit and bin/benchmark. Provides one entry point —
# start_gemini_watchdog — that polls a running gemini agent for the
# three known failure modes (sustained 429 quota exhaustion, post-Drip
# hang, and post-generation idle heartbeat loop) and SIGTERMs the
# process tree when any of them is confirmed. All triggers are
# fail-safe: missing klog, missing lsof, awk/date errors, and future
# log-format drift all return false so the caller falls through to the
# outer wall-clock budget — never a worse outcome than running with no
# watchdog at all.
#
# Functions:
#   _kill_tree <pid> <sig>
#       Send <sig> to <pid> and every descendant, leaf-first.
#       Necessary because the agent sits several subshells deep
#       (driver → background function → audit_timeout_run wrapper →
#       gemini-cli) and on macOS SIGHUP-on-exit is not the default,
#       so a plain `kill` or `pkill -P` leaves grandchildren behind.
#
#   gemini_quota_dominates <raw_log>
#       True when the recent tail of the agent's raw transcript is
#       dominated by "Attempt N failed with status 429. Retrying..."
#       lines with zero assistant or result events between them.
#       Tunables:
#         GEMINI_QUOTA_WINDOW_LINES   tail size to inspect       [400]
#         GEMINI_QUOTA_MIN_429        429 lines needed to trigger [10]
#
#   agy_cli_log_for_pid <pid>
#       Echo the path to the agy klog file (cli-*.log) the process
#       has open under ~/.gemini/antigravity-cli/log/. Empty if lsof
#       is missing or the file isn't open yet — caller skips.
#
#   agy_drip_stopped <cli_log>
#       True if the agy klog shows "text_drip.go:NNN] Drip stopped"
#       — the event agy emits when its --print stream is fully
#       buffered. Usually agy exits within ~1s; rarely it hangs in a
#       polling loop and never exits.
#
#   agy_in_idle_heartbeat_loop <cli_log> [window_secs]
#       True if the klog shows the documented post-generation idle
#       loop: zero streamGenerateContent / :generateContent calls in
#       the recent window, but at least one fetchAvailableModels or
#       loadCodeAssist keepalive. Window default 600s
#       (AGY_IDLE_WINDOW_SECS); largest observed legitimate gap is
#       73s, so this gives ~8x headroom.
#
#   start_gemini_watchdog <raw_log> <agent_pid> <marker_dir> <label>
#       Background watchdog loop. Polls every GEMINI_WATCHDOG_POLL_SECS
#       (default 10s). On trigger:
#         - quota:       touches "$marker_dir/.quota-exhausted" then
#                        TERM/sleep5/KILL the process tree.
#         - drip-hang:   waits AGY_DRIP_GRACE_SECS (default 60s, poll
#                        for early exit) then TERM/KILL.
#         - idle-loop:   requires AGY_IDLE_CONFIRM_POLLS (default 2)
#                        consecutive positive polls before TERM/KILL
#                        — guards against a transient mid-conversation
#                        pause tripping the arm.
#       <label> is a short string ("Agent1·cold·S7" or "cell foo")
#       used in the `log` messages so operators can map a kill back
#       to the right agent. The caller is responsible for providing
#       `log` and `index_log` shell functions (both bin/audit and
#       bin/benchmark already do).
#       Tunables (override in the environment):
#         GEMINI_WATCHDOG_POLL_SECS   poll interval, all triggers  [10]
#         AGY_DRIP_GRACE_SECS         post-Drip wait before kill   [60]
#                                     Set 0 to skip the drip check.
#         AGY_IDLE_WINDOW_SECS        idle-loop detection window   [600]
#         AGY_IDLE_CONFIRM_POLLS      consecutive positive polls   [2]
#                                     to kill. Set 0 to skip the
#                                     idle-loop arm.
#
# USE_GEMINI_CLI=1 selects Google Gemini CLI which uses stream-json
# output and exits cleanly. Both agy-klog arms (drip + idle) are
# skipped automatically when llm_use_gemini_cli returns 0; only the
# quota arm stays armed (gemini-cli also receives 429s).
#
# Callers must source lib/llm_invoke.sh before this file so
# llm_use_gemini_cli is in scope.

# ── Process-tree kill ────────────────────────────────────────────────

_kill_tree() {
  local pid="$1" sig="$2" child
  for child in $(pgrep -P "$pid" 2>/dev/null); do
    _kill_tree "$child" "$sig"
  done
  kill -"$sig" "$pid" 2>/dev/null || true
}

_gemini_watchdog_pid_alive() {
  local pid="$1" stat
  kill -0 "$pid" 2>/dev/null || return 1
  stat="$(ps -p "$pid" -o stat= 2>/dev/null | awk 'NR==1 {print $1}')"
  case "$stat" in
    Z*) return 1 ;;
  esac
  return 0
}

_gemini_watchdog_terminate_tree() {
  local pid="$1" grace="${2:-5}" elapsed=0
  _kill_tree "$pid" TERM
  while [ "$elapsed" -lt "$grace" ]; do
    sleep 1
    _gemini_watchdog_pid_alive "$pid" || return 0
    elapsed=$((elapsed + 1))
  done
  _kill_tree "$pid" KILL
}

# ── Quota-dominated detector ─────────────────────────────────────────

gemini_quota_dominates() {
  local raw_log="$1"
  local window="${GEMINI_QUOTA_WINDOW_LINES:-400}"
  local min_429="${GEMINI_QUOTA_MIN_429:-10}"
  [ -f "$raw_log" ] || return 1
  local tail_text n_429 n_progress
  tail_text="$(tail -n "$window" "$raw_log" 2>/dev/null)"
  n_429="$(printf '%s\n' "$tail_text" \
    | grep -cE 'Attempt [0-9]+ failed with status 429' 2>/dev/null || true)"
  n_progress="$(printf '%s\n' "$tail_text" \
    | grep -cE '"role":"assistant"|"type":"result"' 2>/dev/null || true)"
  [ "${n_429:-0}" -ge "$min_429" ] && [ "${n_progress:-0}" -eq 0 ]
}

# ── agy klog locator + predicates ────────────────────────────────────

agy_cli_log_for_pid() {
  local pid="$1"
  command -v lsof >/dev/null 2>&1 || return 0
  kill -0 "$pid" 2>/dev/null || return 0
  lsof -p "$pid" 2>/dev/null \
    | awk '$NF ~ /\/antigravity-cli\/log\/cli-.*\.log$/ {print $NF; exit}'
}

agy_drip_stopped() {
  local cli_log="$1"
  [ -f "$cli_log" ] || return 1
  grep -qE 'text_drip\.go:[0-9]+\] Drip stopped' "$cli_log" 2>/dev/null
}

agy_in_idle_heartbeat_loop() {
  local cli_log="$1"
  local window_secs="${2:-${AGY_IDLE_WINDOW_SECS:-600}}"
  [ -f "$cli_log" ] || return 1

  # BSD date (macOS) vs GNU date (Linux) — both forms tried so the
  # detector works on operator workstations and CI runners alike.
  local cutoff_hhmm
  cutoff_hhmm="$(date -v-"${window_secs}"S +%H:%M 2>/dev/null \
              || date -d "${window_secs} seconds ago" +%H:%M 2>/dev/null)"
  [ -n "$cutoff_hhmm" ] || return 1

  # Klog timestamp format: `IMMDD HH:MM:SS.us`. $2 holds HH:MM:SS;
  # substr(,1,5) isolates HH:MM. Comparison is lexicographic over
  # HH:MM strings, correct within a single UTC day. Across the
  # midnight boundary the cutoff may end up "in the future"
  # textually; the awk filter then returns 0 stream calls (under-
  # counts), biasing toward NOT killing — the safe direction.
  local stream_calls heartbeat_calls
  stream_calls="$(awk -v cut="$cutoff_hhmm" '
    { t=substr($2,1,5) }
    t < cut { next }
    /streamGenerateContent|:generateContent[^A-Za-z]/ { c++ }
    END { print c+0 }
  ' "$cli_log" 2>/dev/null)"

  heartbeat_calls="$(awk -v cut="$cutoff_hhmm" '
    { t=substr($2,1,5) }
    t < cut { next }
    /fetchAvailableModels|loadCodeAssist/ { c++ }
    END { print c+0 }
  ' "$cli_log" 2>/dev/null)"

  [ "${stream_calls:-0}" = "0" ] && [ "${heartbeat_calls:-0}" -ge 1 ]
}

# ── Background watchdog loop ─────────────────────────────────────────

start_gemini_watchdog() {
  local raw_log="$1" agent_pid="$2" marker_dir="$3" label="$4"
  local interval="${GEMINI_WATCHDOG_POLL_SECS:-10}"
  local drip_grace="${AGY_DRIP_GRACE_SECS:-60}"
  local idle_confirm="${AGY_IDLE_CONFIRM_POLLS:-2}"
  local check_drip=0
  local check_idle=0
  if [ "$drip_grace" -gt 0 ] 2>/dev/null; then
    llm_use_gemini_cli || check_drip=1
  fi
  if [ "$idle_confirm" -gt 0 ] 2>/dev/null; then
    llm_use_gemini_cli || check_idle=1
  fi
  local cli_log=""
  local idle_strikes=0

  while sleep "$interval"; do
    kill -0 "$agent_pid" 2>/dev/null || return 0

    if gemini_quota_dominates "$raw_log"; then
      _gemini_watchdog_log "${label} — gemini quota exhausted (sustained 429s with no assistant progress); aborting"
      [ -n "$marker_dir" ] && [ -d "$marker_dir" ] \
        && touch "$marker_dir/.quota-exhausted" 2>/dev/null || true
      _gemini_watchdog_terminate_tree "$agent_pid" 5
      return 0
    fi

    # Lazily resolve the cli-log path once for both klog-based arms.
    # agy creates it shortly after start, so first few polls may see
    # nothing. Once located, the path is sticky for the rest of the
    # session.
    if [ "$check_drip" = 1 ] || [ "$check_idle" = 1 ]; then
      [ -n "$cli_log" ] || cli_log="$(agy_cli_log_for_pid "$agent_pid")"
    fi

    if [ "$check_drip" = 1 ] && [ -n "$cli_log" ] && agy_drip_stopped "$cli_log"; then
      # Give agy a grace period to flush --print and exit cleanly
      # (it does, in the healthy case). Poll for early exit so a
      # clean run doesn't pay the full grace.
      local elapsed=0
      while [ "$elapsed" -lt "$drip_grace" ]; do
        sleep 2
        elapsed=$((elapsed + 2))
        kill -0 "$agent_pid" 2>/dev/null || return 0
      done
      _gemini_watchdog_log "${label} — agy hung ${drip_grace}s after 'Drip stopped'; aborting (cli-log: $cli_log)"
      _gemini_watchdog_terminate_tree "$agent_pid" 5
      return 0
    fi

    if [ "$check_idle" = 1 ] && [ -n "$cli_log" ]; then
      if agy_in_idle_heartbeat_loop "$cli_log"; then
        idle_strikes=$((idle_strikes + 1))
        if [ "$idle_strikes" -ge "$idle_confirm" ]; then
          _gemini_watchdog_log "${label} — agy idle-heartbeat loop (no streamGenerateContent in ${AGY_IDLE_WINDOW_SECS:-600}s, confirmed ${idle_strikes}x); aborting (cli-log: $cli_log)"
          _gemini_watchdog_terminate_tree "$agent_pid" 5
          return 0
        fi
      else
        idle_strikes=0
      fi
    fi
  done
}

# Internal: route a watchdog kill notice to whichever logger the
# caller defines. Both bin/audit and bin/benchmark provide `log`; tests
# can stub it. Falls back to stderr so missing-logger doesn't lose the
# kill rationale.
_gemini_watchdog_log() {
  local msg="$1"
  if declare -F log >/dev/null 2>&1; then
    log "$msg"
  else
    printf '[gemini-watchdog] %s\n' "$msg" >&2
  fi
}
