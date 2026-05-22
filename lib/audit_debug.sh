#!/usr/bin/env bash
# Debug/observability helpers for bin/audit.
#
# ── Why this is bash, not Python ─────────────────────────────────────
# The agent-count and strategy lookups in this module use bash's
# `declare -F` to dispatch to whichever helper (real runtime or test
# stub) is sourced into the calling shell at the moment of invocation.
# That late-binding is fundamental to how the unit tests inject mocks
# without touching production code. A Python port would force each
# count/strategy lookup to subprocess back to bash to resolve the
# helper, which costs ~80–150 ms per call on top of the bash dispatch
# that would still have to happen.
#
# The pure JSON-event emission half of this module IS in Python now —
# see `audit_emit_event` below, which delegates to lib/audit_helpers.py
# (subcommand `emit-event`) and replaces the prior pair-of-jq-spawns
# per event. The bash that remains is the late-binding glue.

# Locate the harness root once so we can call the Python helper without
# depending on SCRIPT_ROOT being exported by the caller.
_audit_debug_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_AUDIT_HELPERS_PY="$_audit_debug_dir/audit_helpers.py"
unset _audit_debug_dir

audit_debug_log() {
  if declare -F log >/dev/null 2>&1; then
    log "$@"
  else
    printf '[audit-debug] %s\n' "$*"
  fi
}

audit_emit_log() {
  local line
  line=$(audit_debug_log "$@")
  [ -n "${INDEX:-}" ] && printf '%s\n' "$line" >> "$INDEX" 2>/dev/null || true
  printf '%s\n' "$line" >&2
}

audit_events_path() {
  printf '%s/state/events.jsonl' "${RESULTS_DIR:-}"
}

# Emit one observability event as a JSONL row.
#
# Usage:
#   audit_emit_event <event-name> [k=v ...] [--int k=v] [--bool k=v]
#
# String keys are passed as plain `k=v`. Numeric keys (counters, depths)
# use `--int k=v` so the emitted JSON keeps them as numbers; boolean
# keys use `--bool`. created_at + event are filled by the helper.
# No-op if RESULTS_DIR is unset (best-effort, matches prior behavior).
audit_emit_event() {
  local event="$1"; shift
  [ -n "${RESULTS_DIR:-}" ] || return 0
  command -v python3 >/dev/null 2>&1 || return 0
  local events
  events=$(audit_events_path)
  python3 "$_AUDIT_HELPERS_PY" emit-event "$events" "$event" "$@" 2>/dev/null || true
}

audit_count_pending_for_agent() {
  local agent_num="$1" sf c
  if declare -F structured_state_agent_pending_count >/dev/null 2>&1 \
     && structured_state_agent_has_rows "$agent_num" 2>/dev/null; then
    structured_state_agent_pending_count "$agent_num" 2>/dev/null || echo 0
    return
  fi
  sf=$(state_file_path "$agent_num" 2>/dev/null || true)
  [ -f "$sf" ] || { echo 0; return; }
  c=$(grep -c "PENDING" "$sf" 2>/dev/null || true)
  echo "${c:-0}"
}

audit_count_active_for_agent() {
  local agent_num="$1" sf c
  if declare -F structured_state_agent_active_count >/dev/null 2>&1 \
     && structured_state_agent_has_rows "$agent_num" 2>/dev/null; then
    structured_state_agent_active_count "$agent_num" 2>/dev/null || echo 0
    return
  fi
  if declare -F count_active_hypotheses_for_agent >/dev/null 2>&1; then
    count_active_hypotheses_for_agent "$agent_num" 2>/dev/null || echo 0
    return
  fi
  sf=$(state_file_path "$agent_num" 2>/dev/null || true)
  [ -f "$sf" ] || { echo 0; return; }
  c=$(grep -cE "PENDING|INVESTIGATING|NEEDS_TESTCASE" "$sf" 2>/dev/null || true)
  echo "${c:-0}"
}

audit_count_discards_for_agent() {
  local agent_num="$1" sf c
  if declare -F structured_state_agent_discard_count >/dev/null 2>&1 \
     && structured_state_agent_has_rows "$agent_num" 2>/dev/null; then
    structured_state_agent_discard_count "$agent_num" 2>/dev/null || echo 0
    return
  fi
  sf=$(state_file_path "$agent_num" 2>/dev/null || true)
  [ -f "$sf" ] || { echo 0; return; }
  c=$(grep -c "DISCARDED" "$sf" 2>/dev/null || true)
  echo "${c:-0}"
}

audit_count_asan_runs_for_agent() {
  local agent_num="$1"
  if declare -F count_verified_asan_runs >/dev/null 2>&1; then
    count_verified_asan_runs "$(scratch_dir_path "$agent_num")" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

audit_count_hits_for_agent() {
  local agent_num="$1" hits_log n
  hits_log=$(hits_log_path "$agent_num" 2>/dev/null || true)
  [ -f "$hits_log" ] || { echo 0; return; }
  n=$(grep -c '^HIT:' "$hits_log" 2>/dev/null || true)
  echo "${n:-0}"
}

audit_strategy_for_agent() {
  local agent_num="$1"
  if declare -F get_agent_strategy >/dev/null 2>&1; then
    get_agent_strategy "$agent_num" 2>/dev/null || echo "S1"
  else
    echo "S1"
  fi
}

audit_strategy_streak_for_agent() {
  local agent_num="$1"
  if declare -F get_agent_strategy_streak >/dev/null 2>&1; then
    get_agent_strategy_streak "$agent_num" 2>/dev/null || echo 0
  else
    echo 0
  fi
}

audit_strategy_threshold_for_strategy() {
  local strategy="$1"
  if [ "$strategy" = "S1" ]; then
    echo "${STRATEGY_S1_DRY_STREAK_THRESHOLD:-8}"
  else
    echo "${STRATEGY_DRY_STREAK_THRESHOLD:-3}"
  fi
}

audit_latest_subsystem_suggestion() {
  local agent_num="$1" f
  f="${LOGDIR:-}/.subsystem_suggest_${agent_num}"
  [ -f "$f" ] && cat "$f" 2>/dev/null || echo ""
}

write_prompt_artifacts() {
  # Writes the per-session prompt markdown and stashes (subsystem,
  # suggested_subsystem, strategy, prompt_tokens_est, launch) for the
  # finish handler to pull into the index.jsonl row. The legacy
  # session_*.prompt.meta.json sidecar is no longer written — every
  # field it carried is now in the index.jsonl row written by
  # lib/audit_log_summary.py.
  local timestamp="$1" role_name="$2" agent_num="$3" launch="$4" prompt="$5" prompt_tokens="$6"
  [ -n "${LOGDIR:-}" ] || return 0
  local prompt_file subsystem strategy suggestion stash
  prompt_file="$LOGDIR/session_${timestamp}_${role_name}.prompt.md"
  subsystem=$(get_agent_subsystem "$agent_num" 2>/dev/null || echo "unknown")
  strategy=$(audit_strategy_for_agent "$agent_num")
  suggestion=$(audit_latest_subsystem_suggestion "$agent_num")

  mkdir -p "$LOGDIR" 2>/dev/null || true
  printf '%s\n' "$prompt" > "$prompt_file"

  # Per-agent stash file picked up by run_agent's finish handler so the
  # index.jsonl row can record build-time prompt metadata without
  # exporting cross-cutting globals.
  stash="$LOGDIR/.prompt_meta_${agent_num}"
  {
    printf 'subsystem=%s\n' "$subsystem"
    printf 'suggested_subsystem=%s\n' "$suggestion"
    printf 'strategy=%s\n' "$strategy"
    printf 'prompt_tokens_est=%s\n' "${prompt_tokens:-0}"
    printf 'launch=%s\n' "$launch"
  } > "$stash" 2>/dev/null || true

  printf '%s\n' "$prompt_file"
}

log_agent_plan() {
  local agent_num="$1" launch="$2" role_name="$3" prompt_tokens="$4" prompt_file="$5" meta_file="$6"
  local mode role subsystem strategy streak threshold active pending discards asan_runs hits suggestion
  mode=$(agent_mode "$agent_num" 2>/dev/null || echo "unknown")
  role=$(agent_role "$agent_num" 2>/dev/null || echo "unknown")
  subsystem=$(get_agent_subsystem "$agent_num" 2>/dev/null || echo "unknown")
  strategy=$(audit_strategy_for_agent "$agent_num")
  streak=$(audit_strategy_streak_for_agent "$agent_num")
  threshold=$(audit_strategy_threshold_for_strategy "$strategy")
  active=$(audit_count_active_for_agent "$agent_num")
  pending=$(audit_count_pending_for_agent "$agent_num")
  discards=$(audit_count_discards_for_agent "$agent_num")
  asan_runs=$(audit_count_asan_runs_for_agent "$agent_num")
  hits=$(audit_count_hits_for_agent "$agent_num")
  suggestion=$(audit_latest_subsystem_suggestion "$agent_num")

  local prompt_basename meta_basename
  prompt_basename=$(basename "${prompt_file:-}" 2>/dev/null)
  meta_basename=$(basename "${meta_file:-}" 2>/dev/null)
  audit_emit_log "PLAN: agent=${agent_num} launch=${launch} strategy=${strategy} strat_streak=${streak}/${threshold} subsystem=${subsystem} suggested=${suggestion:-none} mode=${mode} role=${role} active=${active} pending=${pending} discards=${discards} asan_runs=${asan_runs} hits=${hits} role_name=${role_name} prompt=${prompt_basename} meta=${meta_basename}"

  audit_emit_event "agent-plan" \
    "agent=$agent_num" "launch=$launch" "role_name=$role_name" \
    "mode=$mode" "role=$role" "subsystem=$subsystem" \
    "suggested_subsystem=${suggestion:-}" "strategy=$strategy" \
    "prompt_file=$prompt_file" "meta_file=$meta_file" \
    --int "prompt_tokens_est=${prompt_tokens:-0}" \
    --int "strategy_streak=${streak:-0}" \
    --int "strategy_threshold=${threshold:-0}" \
    --int "active=${active:-0}" --int "pending=${pending:-0}" \
    --int "discards=${discards:-0}" --int "asan_runs=${asan_runs:-0}" \
    --int "hits=${hits:-0}"
}

record_subsystem_suggest() {
  local agent_num="$1" mode="$2" selected="$3" source="$4" skipped_claimed="${5:-}" skipped_blocklisted="${6:-}"
  [ -n "${LOGDIR:-}" ] && printf '%s' "${selected:-none}" > "$LOGDIR/.subsystem_suggest_${agent_num}" 2>/dev/null || true
  audit_emit_log "SUBSYSTEM_SUGGEST: agent=${agent_num} mode=${mode} selected=${selected:-none} source=${source:-unknown} skipped_claimed=\"${skipped_claimed:-none}\" skipped_blocklisted=\"${skipped_blocklisted:-none}\""

  audit_emit_event "subsystem-suggest" \
    "agent=$agent_num" "mode=$mode" "selected=${selected:-}" \
    "source=${source:-unknown}" \
    "skipped_claimed=${skipped_claimed:-}" \
    "skipped_blocklisted=${skipped_blocklisted:-}"
}

record_subsystem_claim() {
  local agent_num="$1" launch="$2" role_name="$3" before="$4" after="$5"
  local changed=0
  [ "${before:-unknown}" != "${after:-unknown}" ] && changed=1
  audit_emit_log "SUBSYSTEM_CLAIM: agent=${agent_num} launch=${launch} before=${before:-unknown} after=${after:-unknown} changed=${changed} role_name=${role_name}"

  audit_emit_event "subsystem-claim" \
    "agent=$agent_num" "launch=$launch" "role_name=$role_name" \
    "before=${before:-unknown}" "after=${after:-unknown}" \
    "source=state" \
    --int "changed=$changed"
}

log_strategy_status() {
  local agent_num="$1" subsystem="$2" strategy="$3" streak="$4" threshold="$5" productive="$6" action="${7:-keep}" extras="${8:-}"
  audit_emit_log "STRATEGY_STATUS: agent=${agent_num} subsystem=${subsystem:-unknown} strategy=${strategy:-unknown} dry=${streak:-0}/${threshold:-0} productive=${productive:-0} action=${action}${extras:+ ${extras}}"

  audit_emit_event "strategy-status" \
    "agent=$agent_num" "subsystem=${subsystem:-unknown}" \
    "strategy=${strategy:-unknown}" "action=$action" \
    --int "dry_streak=${streak:-0}" --int "threshold=${threshold:-0}" \
    --int "productive=${productive:-0}"
}

log_strategy_rotation() {
  local agent_num="$1" subsystem="$2" from_strategy="$3" to_strategy="$4" streak="$5" threshold="$6" picker="$7" reason="${8:-}" extras="${9:-}"
  audit_emit_log "STRATEGY_ROTATION: agent=${agent_num} subsystem=${subsystem:-unknown} from=${from_strategy:-unknown} to=${to_strategy:-unknown} dry=${streak:-0}/${threshold:-0} picker=${picker:-unknown} reason=\"${reason:-none}\"${extras:+ ${extras}}"

  audit_emit_event "strategy-rotation" \
    "agent=$agent_num" "subsystem=${subsystem:-unknown}" \
    "from_strategy=${from_strategy:-unknown}" \
    "to_strategy=${to_strategy:-unknown}" \
    "picker=${picker:-unknown}" "reason=${reason:-}" \
    --int "dry_streak=${streak:-0}" --int "threshold=${threshold:-0}"
}
