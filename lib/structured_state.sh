#!/usr/bin/env bash
# Structured JSONL state helpers. Markdown state remains a fallback for
# legacy sessions, but JSONL is preferred whenever rows exist for an agent.
#
# ── Why this is bash, not Python ─────────────────────────────────────
# This module wraps `jq` to query JSONL state files. It is sourced by
# bin/audit and called from 60+ hot-path sites per agent iteration. Each
# call is one bash function dispatch + one `jq` subprocess (~10 ms warm).
#
# A Python port would replace each call with a `python3` subprocess
# cold-start (~80–150 ms) plus the same JSON parse cost. Across 28 hot
# callers per iteration, that is the difference between sub-second and
# multi-second per-agent overhead. Keeping this in bash is a deliberate
# performance choice, not legacy tech debt.
#
# Callers that need this state from Python should use lib/workqueue.py
# (which talks to JSONL directly with fcntl locking), not subprocess to
# this file.

structured_state_hypotheses_path() {
  printf '%s/state/hypotheses.jsonl' "${RESULTS_DIR:-}"
}

structured_state_available() {
  local f
  f=$(structured_state_hypotheses_path)
  [ -n "${RESULTS_DIR:-}" ] && [ -s "$f" ] && command -v jq >/dev/null 2>&1
}

structured_state_agent_has_rows() {
  local agent_num="$1" f
  structured_state_available || return 1
  f=$(structured_state_hypotheses_path)
  jq -s -e --arg agent "$agent_num" 'any(.[]; (.agent // "") == $agent)' "$f" >/dev/null 2>&1
}

structured_state_count_agent_status_regex() {
  local agent_num="$1" regex="$2" f
  structured_state_agent_has_rows "$agent_num" || return 1
  f=$(structured_state_hypotheses_path)
  jq -s -r --arg agent "$agent_num" --arg re "$regex" '
    [ .[]
      | select((.agent // "") == $agent)
      | (.status // "")
      | select(test($re))
    ] | length
  ' "$f" 2>/dev/null
}

structured_state_count_all_status_regex() {
  local regex="$1" f
  structured_state_available || return 1
  f=$(structured_state_hypotheses_path)
  jq -s -r --arg re "$regex" '
    [ .[] | (.status // "") | select(test($re)) ] | length
  ' "$f" 2>/dev/null
}

structured_state_agent_pending_count() {
  structured_state_count_agent_status_regex "$1" '^PENDING$'
}

structured_state_agent_active_count() {
  structured_state_count_agent_status_regex "$1" '^(PENDING|INVESTIGATING|NEEDS_TESTCASE)$'
}

structured_state_agent_discard_count() {
  structured_state_count_agent_status_regex "$1" '^DISCARDED$'
}

structured_state_agent_env_blocked_count() {
  structured_state_count_agent_status_regex "$1" '^ENV-BLOCKED$'
}

structured_state_agent_needs_testcase_count() {
  structured_state_count_agent_status_regex "$1" '^NEEDS_TESTCASE$'
}

structured_state_agent_result_count() {
  structured_state_count_agent_status_regex "$1" '^(CRASH|CRASH-|FIND|FIND-)'
}

structured_state_actionable_count() {
  structured_state_count_all_status_regex '^(CRASH|CRASH-|FIND|FIND-|NEEDS_TESTCASE)$'
}

# One-shot status histogram for one agent. Replaces 6 separate jq counter
# calls with a single jq invocation that computes every status bucket in
# one pass over hypotheses.jsonl.
#
# Why bash+jq, not bin/state? jq cold-start on this platform is ~10–15ms,
# python3 + importing workqueue.py is ~150ms. Six jq calls (~75ms) is
# faster than one python call. The Python `agent_counts()` helper still
# exists for external tools (bin/state agent-counts) — both paths share
# semantics enforced by tests/test_agent_counts.sh.
#
# On success, sets the named variables in the caller's scope. Returns 1
# when the agent has no rows in hypotheses.jsonl (or when the file/jq is
# missing) so callers can fall through to the legacy markdown grep path
# unchanged. The ENTIRE migration's safety net rides on this contract.
#
# Bucket semantics MUST match structured_state.sh's individual counters:
#   * pending        = exact ^PENDING$
#   * investigating  = exact ^INVESTIGATING$
#   * needs_testcase = exact ^NEEDS_TESTCASE$
#   * active         = pending + investigating + needs_testcase
#   * discards       = exact ^DISCARDED$
#   * env_blocked    = exact ^ENV-BLOCKED$
#   * result         = prefix ^(CRASH|FIND) — includes CRASH-DEDUPED, FIND-LOWPRIO
#
# Usage:
#   local p=0 a=0 d=0 e=0 n=0 r=0 i=0
#   if structured_state_agent_counts_load "$agent_num" p a d e n r i; then
#     # vars now hold structured counts
#   fi
structured_state_agent_counts_load() {
  local agent_num="$1"
  local _v_pending="${2:-_ssac_pending}"
  local _v_active="${3:-_ssac_active}"
  local _v_discards="${4:-_ssac_discards}"
  local _v_env_blocked="${5:-_ssac_env_blocked}"
  local _v_needs_tc="${6:-_ssac_needs_tc}"
  local _v_result="${7:-_ssac_result}"
  local _v_investigating="${8:-_ssac_investigating}"

  structured_state_available || return 1
  local f
  f=$(structured_state_hypotheses_path)

  # Single jq pass: filter to this agent, classify each status, return
  # pipe-delimited counts plus a row-count sentinel for the no-rows check.
  local out
  out=$(jq -s -r --arg agent "$agent_num" '
    [ .[] | select((.agent // "") == $agent) ] as $rows
    | ($rows | length) as $n
    | "\($n)|\(
        [ $rows[] | select((.status // "") == "PENDING") ] | length
      )|\(
        [ $rows[] | select((.status // "") == "INVESTIGATING") ] | length
      )|\(
        [ $rows[] | select((.status // "") == "NEEDS_TESTCASE") ] | length
      )|\(
        [ $rows[] | select((.status // "") == "DISCARDED") ] | length
      )|\(
        [ $rows[] | select((.status // "") == "ENV-BLOCKED") ] | length
      )|\(
        [ $rows[] | select((.status // "") | test("^(CRASH|FIND)")) ] | length
      )"
  ' "$f" 2>/dev/null) || return 1
  [ -n "$out" ] || return 1

  # Use prefix-mangled internals — printf -v writes to the caller's named
  # variables, but if a local here had the same name (e.g. `p`) it would
  # shadow the caller and the assignment would silently land in our scope.
  local __ssac_rc __ssac_p __ssac_inv __ssac_ntc __ssac_disc __ssac_env __ssac_res
  IFS='|' read -r __ssac_rc __ssac_p __ssac_inv __ssac_ntc __ssac_disc __ssac_env __ssac_res <<< "$out"
  local __ssac_v
  for __ssac_v in "$__ssac_rc" "$__ssac_p" "$__ssac_inv" "$__ssac_ntc" "$__ssac_disc" "$__ssac_env" "$__ssac_res"; do
    case "$__ssac_v" in ''|*[!0-9]*) return 1 ;; esac
  done
  # No rows for this agent → return 1 so caller falls through to its
  # markdown-state grep path. Matches the old structured_state_agent_has_rows
  # gate semantics exactly.
  [ "$__ssac_rc" -gt 0 ] || return 1

  local __ssac_active=$((__ssac_p + __ssac_inv + __ssac_ntc))
  printf -v "$_v_pending"       '%s' "$__ssac_p"
  printf -v "$_v_active"        '%s' "$__ssac_active"
  printf -v "$_v_discards"      '%s' "$__ssac_disc"
  printf -v "$_v_env_blocked"   '%s' "$__ssac_env"
  printf -v "$_v_needs_tc"      '%s' "$__ssac_ntc"
  printf -v "$_v_result"        '%s' "$__ssac_res"
  printf -v "$_v_investigating" '%s' "$__ssac_inv"
  return 0
}

structured_state_agents_with_rows() {
  local f
  structured_state_available || return 1
  f=$(structured_state_hypotheses_path)
  jq -s -r '[ .[] | (.agent // empty) ] | unique | .[]' "$f" 2>/dev/null
}

structured_state_subsystem_from_file() {
  local file="$1"
  [ -n "$file" ] || return 1
  local lib_dir
  lib_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  local args=()
  if [ "${IS_BROWSER_TARGET:-0}" -eq 1 ]; then
    args+=(--subsystems "${lib_dir}/subsystems/${TARGET_SLUG:-firefox}.txt")
  fi
  python3 "${lib_dir}/parse_state.py" subsystem-from-path "$file" \
    ${args[@]+"${args[@]}"} 2>/dev/null
}

structured_state_agent_subsystem() {
  local agent_num="$1" f file
  structured_state_agent_has_rows "$agent_num" || return 1
  f=$(structured_state_hypotheses_path)
  file=$(jq -s -r --arg agent "$agent_num" '
    [ .[] | select((.agent // "") == $agent) ] as $rows
    | (
        [ $rows[]
          | select((.status // "") | test("^(PENDING|INVESTIGATING|NEEDS_TESTCASE|ENV-BLOCKED|CRASH|CRASH-|FIND|FIND-)"))
        ] | last
      ) // ($rows | last) // {}
    | .file // ""
  ' "$f" 2>/dev/null)
  [ -n "$file" ] && [ "$file" != "null" ] || return 1
  structured_state_subsystem_from_file "$file"
}

structured_state_latest_strategy() {
  local agent_num="$1" f
  structured_state_agent_has_rows "$agent_num" || return 1
  f=$(structured_state_hypotheses_path)
  jq -s -r --arg agent "$agent_num" '
    [ .[]
      | select((.agent // "") == $agent)
      | select((.status // "") != "DISCARDED")
      | (.strategy // "")
      | select(. != "")
    ] | last // empty
  ' "$f" 2>/dev/null
}
