#!/usr/bin/env bash
# lib/prompt.sh — Prompt builders for agent sessions.
# Sourced by bin/audit. Generates cold-start and deep-investigation
# prompts with priority-ordered session directives.
#
# ── Architecture ────────────────────────────────────────────────────
# The top-level prompt bodies and larger reusable prompt fragments live
# as readable markdown templates under lib/prompts/ (extension .md.j2 —
# Jinja2-flavoured `{{ name }}` placeholders, no Jinja2 runtime required,
# see lib/prompt_render.py). This file is the orchestrator: it
# pre-computes the per-launch context (agent role/mode, strategy
# assignment, conditional role-guidance blocks, work-card directives, …)
# and hands the dict to the renderer.
#
# The 24 smaller helper functions in this file stay in bash because each
# one resolves against the audit runtime's late-bound helpers
# ($(state_file_path "$agent_num"), $(scratch_dir_path "$agent_num"),
# $(get_agent_subsystem "$agent_num"), …). Their outputs are pure
# markdown fragments — the renderer receives them as opaque strings, so
# the template is the human-readable shape and the bash glue keeps
# resolving runtime values at call time.

_prompt_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_PROMPT_RENDER_PY="$_prompt_dir/prompt_render.py"
_PROMPTS_DIR="$_prompt_dir/prompts"
unset _prompt_dir

if ! declare -F render_prompt_template >/dev/null 2>&1; then
  # shellcheck disable=SC1090
  source "${SCRIPT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}/lib/prompt_template.sh"
fi

# Emit the curated session-rules digest inline. The full session-rules.md is
# ~22 KB and 365 lines; the digest is ~6 KB and covers all load-bearing
# rules. Embedding the digest into every prompt saves the per-session
# round-trip that historically read the long file (256 reads observed across
# 152 recent sessions). Agents drill into the full file only when the digest
# is ambiguous — see the "Drill-down" section at the digest's tail.
#
# Cached on first call so repeated emits in the same bin/audit invocation
# are free. Returns silently when the digest file is missing so test
# environments that don't ship .agents/references/ still build prompts.
_SESSION_RULES_DIGEST_CACHE=""
build_session_rules_digest() {
  if [ -z "$_SESSION_RULES_DIGEST_CACHE" ]; then
    local digest="${REFERENCE_DIR}/session-rules.digest.md"
    if [ -r "$digest" ]; then
      _SESSION_RULES_DIGEST_CACHE=$(cat "$digest")
    else
      # Fallback: point at the long file. Keeps test envs and partially
      # provisioned trees working while still avoiding a hard failure.
      _SESSION_RULES_DIGEST_CACHE="(session-rules digest missing — read ${REFERENCE_DIR}/session-rules.md once if needed)"
    fi
  fi
  printf '%s\n' "$_SESSION_RULES_DIGEST_CACHE"
}

build_guide_section() {
  local phase="${1:-deep}"
  [ -n "${AGENT_GUIDE_CACHED:-}" ] || return 0
  if [ "$phase" != "cold" ]; then
    cat <<EOF

## AGENT GUIDE

Follow \`${AGENT_GUIDE_PATH:-AGENTS.md}\`. Do not re-read it unless the structured
resume or this prompt explicitly conflicts with the remembered workflow.
EOF
    return 0
  fi
  printf '\n## AGENT GUIDE\n\n%s\n' "$AGENT_GUIDE_CACHED"
}

build_strategy_brief() {
  local strategy="${1:-}"
  strategy=$(printf '%s' "$strategy" | tr '[:lower:]' '[:upper:]')
  [ -n "$strategy" ] || return 0

  local ref_file
  ref_file=$(strategy_file_for_letter "$strategy" 2>/dev/null || true)
  [ -n "$ref_file" ] || return 0

  local summary probes
  case "$strategy" in
    S1)
      summary="Prior-fix regression: inspect the named fix commit(s), identify the invariant that was repaired, then test nearby code paths for unfixed variants."
      probes="Start with \`bin/show-patch <fix-hash>\`, then \`bin/find-seed <file>[:Function]\` before mutating inputs."
      ;;
    S2)
      summary="Invariant negation: find asserts/checks/preconditions, then craft inputs that violate the guarded assumption through the public boundary."
      probes="Search for assertion/check families and turn the most reachable guard into one testcase plus variants."
      ;;
    S3)
      summary="Spec-vs-implementation: compare documented format/API rules against parser fast paths, normalization, and edge-case shortcuts."
      probes="Use seed+delta inputs that cross boundary values, duplicate fields, alternate encodings, or fast-path eligibility."
      ;;
    S4)
      summary="Advanced differential: compare execution modes, tiers, builds, or feature flags and treat stable behavioral divergence as the oracle."
      probes="For JS/Wasm, use \`MODE: js-diff\`; otherwise pick two documented configurations and keep the input identical."
      ;;
    S5)
      summary="Lifetime/state: target re-entrancy, error-path rollback, races, and state-machine sequences where valid calls arrive in a harmful order."
      probes="Build one explicit call/input sequence: setup state, trigger transition/error/callback/race, then touch the stale or inconsistent state."
      ;;
    S6)
      summary="Cross-project variant mining: map peer-project security fixes onto this target's analogous parser, allocator, state, or API surface."
      probes="Use the peer fix as a bug-class template, not as target-specific truth; confirm reachability with a local testcase."
      ;;
    S7)
      summary="Adversarial input engineering: start from a real seed and mutate parser/decoder boundaries, lengths, nesting, dictionaries, and checksums."
      probes="Run \`bin/find-seed <file>[:Function]\` first; from-scratch inputs only after seed search returns nothing."
      ;;
    S8)
      summary="Property oracle: test security-relevant invariants such as inverse operations, injectivity, idempotence, canonicalization, and numeric domains."
      probes="Write small oracle drivers that compare two equivalent paths or round trips; file FIND only for concrete security impact."
      ;;
    REF)
      summary="Pattern library: use broad target-agnostic grep patterns to support the active strategy, then turn hits into concrete hypotheses."
      probes="Keep searches capped and immediately read 2-3 matching files rather than expanding the grep surface."
      ;;
    *)
      return 0
      ;;
  esac

  cat <<STRAT

Strategy brief (${strategy}): ${summary}
Probe shape: ${probes}
Full playbook: \`${REFERENCE_DIR}/strategies/${ref_file}\` — the brief is orientation only; open the file for the taxonomy, mining commands, and proven patterns it cannot hold, before you commit to hypotheses.
STRAT
}

# Context framing shared by all agent prompts. Kept as a template because
# it is large, mostly static, and reviewed as user-facing prompt text.
# results_dir is interpolated so every reference to crashes/ and findings/
# expands to the absolute path under the current run — a bare `crashes/`
# resolves against the agent's cwd, which may have drifted after a `cd`
# into the source tree. Refusing to render with an empty RESULTS_DIR is
# load-bearing: an empty {{ results_dir }} would expand `{{ results_dir }}/findings/`
# to `/findings/` (an absolute path under the filesystem root), which is
# the worst possible failure mode of this template.
build_safety_framing() {
  if [ -z "${RESULTS_DIR:-}" ]; then
    echo "FATAL: build_safety_framing called with empty RESULTS_DIR — would render dangerous /findings, /crashes paths" >&2
    return 1
  fi
  render_prompt_template safety_framing.md.j2 \
    --var "results_dir=${RESULTS_DIR}"
}

# ─── Unified session directive (replaces 7 separate builders) ─────
# Priority order: blocklist > guard-saturation > rotation-gate >
#   reverse-turn-budget > tenure-cap > crash-improvement > quality-feedback
# Emits ONE directive block with ONE primary action.

build_session_directive() {
  local agent_num="$1"
  local state_file
  state_file=$(state_file_path "$agent_num")
  [ -f "$state_file" ] || structured_state_agent_has_rows "$agent_num" 2>/dev/null || return 0

  local my_subsystem my_pending=0 my_active=0 my_discards=0 my_asan_runs=0 my_hits_count=0 my_env_blocked=0
  local _ntc_unused=0 _result_unused=0 _invest_unused=0
  my_subsystem=$(cached_agent_subsystem "$agent_num")
  if ! structured_state_agent_counts_load "$agent_num" \
         my_pending my_active my_discards my_env_blocked \
         _ntc_unused _result_unused _invest_unused 2>/dev/null; then
    [ -f "$state_file" ] \
      && prompt_markdown_state_counts_load "$state_file" \
           my_pending my_active my_discards my_env_blocked \
           _ntc_unused _result_unused
  fi
  my_asan_runs=$(count_verified_asan_runs "$(scratch_dir_path "$agent_num")" 2>/dev/null)
  my_hits_count=0
  local hits_log
  hits_log=$(hits_log_path "$agent_num")
  [ -f "$hits_log" ] && { my_hits_count=$(grep -c '^HIT:' "$hits_log" 2>/dev/null) || true; }
  my_pending=${my_pending:-0}; my_active=${my_active:-0}; my_discards=${my_discards:-0}
  my_hits_count=${my_hits_count:-0}; my_env_blocked=${my_env_blocked:-0}

  # Collect other agents' subsystems
  local claimed_subsystems=""
  for other in $(seq 1 "$NUM_AGENTS"); do
    [ "$other" -eq "$agent_num" ] && continue
    local other_sub
    other_sub=$(cached_agent_subsystem "$other")
    [ "$other_sub" != "unknown" ] && claimed_subsystems="${claimed_subsystems:+$claimed_subsystems, }${other_sub}"
  done

  local blocklist_text
  blocklist_text=$(cached_blocklist_description)

  # ── P1: Blocklist violation ─────────────────────────────────────
  if subsystem_is_blocklisted "$my_subsystem" 2>/dev/null; then
    cat <<DIRECTIVE

## SESSION DIRECTIVE: ROTATE (blocklisted subsystem)

\`${my_subsystem}\` is on the blocklist: **${blocklist_text}**
Pick a subsystem OUTSIDE the blocklist that no other agent claims.
Other agents: ${claimed_subsystems:-none}
DIRECTIVE
    return 0
  fi

  # ── P2: Guard-chain saturation ──────────────────────────────────
  local guard_saturation=""
  [ "$my_subsystem" != "unknown" ] && guard_saturation=$(detect_guard_saturation "$my_subsystem" 2>/dev/null || true)
  if [ -n "$guard_saturation" ]; then
    local guard_count="${guard_saturation%%:*}" guard_string="${guard_saturation#*:}"
    cat <<DIRECTIVE

## SESSION DIRECTIVE: GUARD SATURATION on \`${my_subsystem}\`

Last ${guard_count} hypotheses all died to: \`${guard_string}\`
**Options:** (1) find a code path past the guard, (2) audit the guard itself for weaknesses, (3) rotate subsystem.
Other agents: ${claimed_subsystems:-none}. Blocklist: ${blocklist_text}
DIRECTIVE
    return 0
  fi

  # ── P3: Effort-gated rotation ──────────────────────────────────
  local effort_ok=0 effort_reason=""
  if [ "${my_discards:-0}" -ge "$MIN_DISCARDS_BEFORE_ROTATE" ] \
     && [ "${my_asan_runs:-0}" -ge "$MIN_ASAN_RUNS_BEFORE_ROTATE" ]; then
    effort_ok=1; effort_reason="normal"
  elif [ "${my_env_blocked:-0}" -ge "$ENV_BLOCKED_BEFORE_ROTATE" ]; then
    effort_ok=1; effort_reason="env-blocked"
  fi

  if [ "${my_active:-0}" -eq 0 ]; then
    # Suggest a coverage-gap subsystem if available
    local suggested_sub=""
    suggested_sub=$(assign_subsystem_from_coverage "$agent_num" 2>/dev/null || true)
    local rotation_reason="active queue empty"
    [ "$effort_ok" -eq 1 ] && rotation_reason="effort gate passed: ${effort_reason}"
    cat <<DIRECTIVE

## SESSION DIRECTIVE: ROTATE (${rotation_reason})

\`${my_subsystem}\` has no active PENDING/INVESTIGATING/NEEDS_TESTCASE rows: ${my_discards}D ${my_asan_runs}A ${my_hits_count}H ${my_env_blocked}E
${suggested_sub:+**Suggested next target (lowest coverage):** \`${suggested_sub}\`
}Pick a new subsystem or different files within the parent directory.
Other agents: ${claimed_subsystems:-none}. Blocklist: ${blocklist_text}
DIRECTIVE
    return 0
  fi

  # ── P4: Reverse turn budget ────────────────────────────────────
  local prev_tools_file="$LOGDIR/.prev_tools_${agent_num}"
  local prev_tools=0
  [ -f "$prev_tools_file" ] && prev_tools=$(cat "$prev_tools_file" 2>/dev/null || echo 0)
  if [ "${prev_tools:-0}" -ge "$PER_HYPOTHESIS_TURN_LIMIT" ]; then
    local prev_results_file="$LOGDIR/.prev_results_${agent_num}"
    local prev_results=0 curr_results
    [ -f "$prev_results_file" ] && prev_results=$(cat "$prev_results_file" 2>/dev/null || echo 0)
    curr_results=$(count_active_security_results 2>/dev/null || echo 0)
    if [ "${curr_results:-0}" -le "${prev_results:-0}" ]; then
      local top
      top=$(printf '%s' "$my_subsystem" | awk -F'/' '{if (NF>=2) print $1"/"$2; else print $1}')
      cat <<DIRECTIVE

## SESSION DIRECTIVE: CHANGE APPROACH (${prev_tools} tool calls, 0 new findings)

Prior session spent **${prev_tools}** tool calls on \`${my_subsystem}\` with no results.
**This session:** try different files within \`${top}\`, a different strategy, or rotate entirely.
DIRECTIVE
      return 0
    fi
  fi

  # ── P5: Tenure cap ─────────────────────────────────────────────
  local tenure_secs
  tenure_secs=$(get_agent_tenure_secs "$agent_num" 2>/dev/null || echo 0)
  if [ "${tenure_secs:-0}" -ge "$SUBSYSTEM_TENURE_CAP_SECS" ]; then
    local hours=$(( tenure_secs / 3600 ))
    cat <<DIRECTIVE

## SESSION DIRECTIVE: TENURE CAP (${hours}h on \`${my_subsystem}\`)

You have spent **${hours} hours** on \`${my_subsystem}\` without a confirmed finding.
**Strongly recommended:** rotate subsystem or switch to a fundamentally different strategy family.
DIRECTIVE
    return 0
  fi

  # ── P5b: Strategy rotation (forced by harness) ────────────────
  # When the harness detects an agent has been dry on the same strategy
  # for STRATEGY_DRY_STREAK_THRESHOLD iterations, it writes the next
  # strategy to the tracking file. Inject a directive telling the agent
  # to switch approach.
  local assigned_strategy=""
  local strategy_file
  strategy_file=$(agent_strategy_path "$agent_num")
  [ -f "$strategy_file" ] && assigned_strategy=$(cat "$strategy_file" 2>/dev/null || true)
  local current_strategy
  current_strategy=$(get_agent_strategy "$agent_num")
  if [ -n "$assigned_strategy" ] && [ "$assigned_strategy" != "$current_strategy" ]; then
    local strat_ref_file
    strat_ref_file=$(strategy_file_for_letter "$assigned_strategy")
    cat <<DIRECTIVE

## SESSION DIRECTIVE: SWITCH STRATEGY (${current_strategy} → ${assigned_strategy})

Strategy **${current_strategy}** has not produced findings on \`${my_subsystem}\` after multiple iterations.
**This session: use Strategy ${assigned_strategy}.** Orient with the brief below, then open \`${REFERENCE_DIR}/strategies/${strat_ref_file}\` for the full playbook before forming hypotheses.
$(build_strategy_brief "$assigned_strategy")
Stay on \`${my_subsystem}\` but change HOW you investigate — different strategy, same subsystem.
Generate 3-5 NEW hypotheses using the ${assigned_strategy} approach. Do NOT fall back to ${current_strategy}.
DIRECTIVE
    return 0
  fi

  # ── P6: Crash improvement (many discards, few ASan runs) ───────
  if [ "${my_discards:-0}" -ge 3 ] && [ "${my_asan_runs:-0}" -lt "$((my_discards / 2))" ]; then
    cat <<DIRECTIVE

## SESSION DIRECTIVE: REPRODUCE BEFORE DISCARDING

${my_discards} DISCARDED but only ${my_asan_runs} ASan runs.
**This session:** pick your most promising DISCARDED hypothesis, write a testcase, run the appropriate ASan wrapper, try 3+ variants. Only DISCARD after all variants run under ASan.
DIRECTIVE
    return 0
  fi

  # ── P7: Quality feedback (stats + overlap) ─────────────────────
  # Fall-through: show stats and any overlap warning
  local subsystem_overlap
  subsystem_overlap=$(detect_agent_overlap "$agent_num" 2>/dev/null || true)

  # Use cached quality feedback if available
  local cache
  cache=$(quality_feedback_path "$agent_num")
  local quality_stats=""
  if [ -f "$cache" ] && [ -s "$cache" ]; then
    quality_stats=$(cat "$cache")
  else
    quality_stats=$(check_agent_quality "$agent_num" 2>/dev/null || true)
  fi

  # 0 pending but effort gate not passed → stay deep
  local stay_deep=""
  if [ "${my_pending:-0}" -eq 0 ] && [ "${my_active:-0}" -gt 0 ] && [ "$effort_ok" -eq 0 ]; then
    stay_deep="0 PENDING but active non-terminal work remains (${my_discards}/${MIN_DISCARDS_BEFORE_ROTATE}D, ${my_asan_runs}/${MIN_ASAN_RUNS_BEFORE_ROTATE}A). **Finish active INVESTIGATING/NEEDS_TESTCASE rows on \`${my_subsystem}\`.**"
  fi

  if [ -n "$quality_stats" ] || [ -n "$subsystem_overlap" ] || [ -n "$stay_deep" ]; then
    echo ""
    echo "## SESSION STATUS"
    echo ""
    [ -n "$quality_stats" ] && echo -e "$quality_stats"
    [ -n "$stay_deep" ] && echo "$stay_deep"
    if [ -n "$subsystem_overlap" ]; then
      echo ""
      echo "**OVERLAP:** ${subsystem_overlap}. Switch to a different subsystem. Claimed: ${claimed_subsystems:-none}"
    fi
  fi
}

# ─── Per-iteration cache ─────────────────────────────────────────
# Pre-compute data that is identical across all agents within one
# iteration: blocklist description, per-agent summaries, coverage-gap
# rankings. Called once at iteration start; prompt builders read
# from cache files instead of re-scanning state/hits logs per agent.

ITERATION_CACHE_DIR=""  # set by cache_iteration_data()

cache_iteration_data() {
  ITERATION_CACHE_DIR="$LOGDIR/.iter_cache"
  mkdir -p "$ITERATION_CACHE_DIR"

  # 1. Blocklist (stable within an iteration)
  blocklist_description > "$ITERATION_CACHE_DIR/blocklist.txt" 2>/dev/null || true

  # 2. Per-agent summary lines (subsystem, mode, role, stats)
  for i in $(seq 1 "$NUM_AGENTS"); do
    local sub mode role sf pending crashes needs_tc
    sub=$(get_agent_subsystem "$i" 2>/dev/null || echo "unknown")
    mode=$(agent_mode "$i")
    role=$(agent_role "$i")
    sf=$(state_file_path "$i")
    pending=0; crashes=0; needs_tc=0
    local _act_unused=0 _disc_unused=0 _env_unused=0 _invest_unused=0
    if ! structured_state_agent_counts_load "$i" \
           pending _act_unused _disc_unused _env_unused \
           needs_tc crashes _invest_unused 2>/dev/null; then
      [ -f "$sf" ] \
        && prompt_markdown_state_counts_load "$sf" \
             pending _act_unused _disc_unused _env_unused \
             needs_tc crashes
    fi
    local line="- Agent ${i} (${mode}/${role}): subsystem=\`${sub}\`, ${pending} PENDING, ${crashes} findings"
    [ "${needs_tc:-0}" -gt 0 ] && line+=", ${needs_tc} NEEDS_TESTCASE"
    printf '%s\n' "$line" > "$ITERATION_CACHE_DIR/agent_${i}_summary.txt"
    printf '%s\n' "$sub" > "$ITERATION_CACHE_DIR/agent_${i}_subsystem.txt"
  done

  # 3. Cold-start strategy ranking. The ranking is identical for every
  # agent in this iteration, so compute it once instead of re-scanning the
  # effective work-card queue from pick_cold_start_strategy for each slot.
  rm -f "$ITERATION_CACHE_DIR/cold_start_strategies.txt" 2>/dev/null || true
  if declare -F effective_work_card_rows >/dev/null 2>&1 \
     && declare -F unclaimed_strategy_counts >/dev/null 2>&1 \
     && command -v jq >/dev/null 2>&1 \
     && [ -s "${RESULTS_DIR:-}/work-cards.jsonl" ]; then
    local strat _count
    while IFS="$(printf '\t')" read -r strat _count; do
      [ -n "$strat" ] && printf '%s\n' "$strat"
    done < <(unclaimed_strategy_counts '^S[2-9]$' 2>/dev/null || true) \
      > "$ITERATION_CACHE_DIR/cold_start_strategies.txt" 2>/dev/null || true
  fi

  # 4. Coverage-gap rankings per mode (sorted subsystems by ascending hit count)
  rm -f "$ITERATION_CACHE_DIR/coverage_browser.txt" "$ITERATION_CACHE_DIR/coverage_shell.txt" 2>/dev/null || true
  [ "${IS_BROWSER_TARGET:-0}" -eq 1 ] || return 0

  local all_hits=""
  for i in $(seq 1 "$NUM_AGENTS"); do
    local hl
    hl=$(hits_log_path "$i")
    [ -f "$hl" ] && all_hits+="$(grep '^HIT:' "$hl" 2>/dev/null || true)"$'\n'
  done

  local bl_cached
  bl_cached=$(cat "$ITERATION_CACHE_DIR/blocklist.txt" 2>/dev/null || true)

  for mode_name in browser shell; do
    local approved_list
    if [ "$mode_name" = "browser" ]; then
      approved_list=$(browser_mode_subsystems 2>/dev/null)
    else
      approved_list=$(shell_mode_subsystems 2>/dev/null)
    fi
    [ -n "$approved_list" ] || continue

    local ranked_inputs=""
    while IFS= read -r sub; do
      [ -n "$sub" ] || continue
      subsystem_is_blocklisted "$sub" 2>/dev/null && continue
      ranked_inputs+="${sub}"$'\n'
    done <<< "$approved_list"

    # Sort ascending by hit count; write subsystem names only.
    coverage_hit_ranked_subsystems "$ranked_inputs" "$all_hits" | awk -F '\t' '{print $2}' \
      > "$ITERATION_CACHE_DIR/coverage_${mode_name}.txt" 2>/dev/null || true
  done
}

# ─── Cached blocklist description ────────────────────────────────

cached_blocklist_description() {
  if [ -n "$ITERATION_CACHE_DIR" ] && [ -f "$ITERATION_CACHE_DIR/blocklist.txt" ]; then
    cat "$ITERATION_CACHE_DIR/blocklist.txt"
  else
    blocklist_description
  fi
}

cached_agent_subsystem() {
  local agent_num="$1"
  local cache_file="${ITERATION_CACHE_DIR:-}/agent_${agent_num}_subsystem.txt"
  if [ -n "${ITERATION_CACHE_DIR:-}" ] && [ -f "$cache_file" ]; then
    local sub
    IFS= read -r sub < "$cache_file" 2>/dev/null || sub=""
    if [ -n "$sub" ]; then
      printf '%s\n' "$sub"
      return 0
    fi
  fi
  get_agent_subsystem "$agent_num" 2>/dev/null || echo "unknown"
}

prompt_markdown_state_counts_load() {
  local state_file="$1"
  local _v_pending="${2:-_pmsc_pending}"
  local _v_active="${3:-_pmsc_active}"
  local _v_discards="${4:-_pmsc_discards}"
  local _v_env="${5:-_pmsc_env}"
  local _v_needs_tc="${6:-_pmsc_needs_tc}"
  local _v_results="${7:-_pmsc_results}"

  if [ ! -f "$state_file" ]; then
    printf -v "$_v_pending" '%s' 0
    printf -v "$_v_active" '%s' 0
    printf -v "$_v_discards" '%s' 0
    printf -v "$_v_env" '%s' 0
    printf -v "$_v_needs_tc" '%s' 0
    printf -v "$_v_results" '%s' 0
    return 1
  fi

  local counts
  counts=$(awk '
    /PENDING/ { pending++ }
    /PENDING|INVESTIGATING|NEEDS_TESTCASE/ { active++ }
    /DISCARDED/ { discards++ }
    /ENV-BLOCKED/ { env_blocked++ }
    /NEEDS_TESTCASE/ { needs_tc++ }
    /CRASH-|FIND-/ { results++ }
    END {
      printf "%d %d %d %d %d %d\n",
        pending, active, discards, env_blocked, needs_tc, results
    }
  ' "$state_file" 2>/dev/null) || counts="0 0 0 0 0 0"

  local __pmsc_pending __pmsc_active __pmsc_discards __pmsc_env __pmsc_needs_tc __pmsc_results
  read -r __pmsc_pending __pmsc_active __pmsc_discards __pmsc_env __pmsc_needs_tc __pmsc_results <<< "$counts"
  printf -v "$_v_pending" '%s' "${__pmsc_pending:-0}"
  printf -v "$_v_active" '%s' "${__pmsc_active:-0}"
  printf -v "$_v_discards" '%s' "${__pmsc_discards:-0}"
  printf -v "$_v_env" '%s' "${__pmsc_env:-0}"
  printf -v "$_v_needs_tc" '%s' "${__pmsc_needs_tc:-0}"
  printf -v "$_v_results" '%s' "${__pmsc_results:-0}"
  return 0
}

# Emit `hit_count<TAB>subsystem` rows sorted least-covered first.
# This replaces the older per-subsystem `sed` + `grep -c` loop in coverage
# assignment with one awk pass over the approved subsystem list.
coverage_hit_ranked_subsystems() {
  local approved_list="$1"
  local all_hits="${2:-}"
  [ -n "$approved_list" ] || return 0

  {
    printf '%s\n' "$all_hits"
    printf '\034\n'
    printf '%s' "$approved_list"
  } | awk '
    $0 == "\034" {
      reading_subsystems = 1
      next
    }
    !reading_subsystems {
      hit_lines[++hit_n] = $0
      next
    }
    $0 != "" {
      subsystem = $0
      slug = subsystem
      gsub("/", ".", slug)
      count = 0
      for (i = 1; i <= hit_n; i++) {
        if (hit_lines[i] ~ slug || hit_lines[i] ~ subsystem) {
          count++
        }
      }
      printf "%d\t%s\n", count, subsystem
    }
  ' | LC_ALL=C sort -n 2>/dev/null
}

# ─── Coverage-gap subsystem assignment (cached) ─────────────────
# Reads pre-computed coverage rankings; picks the least-covered
# subsystem not claimed by another agent.

assign_subsystem_from_coverage() {
  local agent_num="$1"
  [ "${IS_BROWSER_TARGET:-0}" -eq 1 ] || return 0

  local my_mode
  my_mode=$(agent_mode "$agent_num")

  local ranked_file="${ITERATION_CACHE_DIR:-}/coverage_${my_mode}.txt"

  # Fall back to live scan if cache unavailable
  if [ ! -f "$ranked_file" ]; then
    _assign_subsystem_from_coverage_live "$@"
    return
  fi

  # Collect claimed subsystems (by other agents)
  local claimed=()
  local skipped_claimed="" skipped_blocklisted=""
  for other in $(seq 1 "$NUM_AGENTS"); do
    [ "$other" -eq "$agent_num" ] && continue
    local other_sub
    other_sub=$(cached_agent_subsystem "$other")
    [ "$other_sub" != "unknown" ] && claimed+=("$other_sub")
  done

  # Walk ranked list (least-covered first), skip claimed
  while IFS= read -r sub; do
    [ -n "$sub" ] || continue
    if subsystem_is_blocklisted "$sub" 2>/dev/null; then
      skipped_blocklisted="${skipped_blocklisted:+$skipped_blocklisted,}${sub}"
      continue
    fi
    local is_claimed=0
    for c in "${claimed[@]:-}"; do
      [ "$c" = "$sub" ] && { is_claimed=1; break; }
    done
    if [ "$is_claimed" -eq 1 ]; then
      skipped_claimed="${skipped_claimed:+$skipped_claimed,}${sub}"
      continue
    fi
    if declare -F record_subsystem_suggest >/dev/null 2>&1; then
      record_subsystem_suggest "$agent_num" "$my_mode" "$sub" "coverage-cache" "$skipped_claimed" "$skipped_blocklisted"
    fi
    echo "$sub"
    return
  done < "$ranked_file"
  if declare -F record_subsystem_suggest >/dev/null 2>&1; then
    record_subsystem_suggest "$agent_num" "$my_mode" "" "coverage-cache" "$skipped_claimed" "$skipped_blocklisted"
  fi
}

# Live fallback (original implementation, used when cache is missing)
_assign_subsystem_from_coverage_live() {
  local agent_num="$1"
  local my_mode
  my_mode=$(agent_mode "$agent_num")

  local approved_list
  if [ "$my_mode" = "browser" ]; then
    approved_list=$(browser_mode_subsystems 2>/dev/null)
  else
    approved_list=$(shell_mode_subsystems 2>/dev/null)
  fi
  [ -n "$approved_list" ] || return 0

  local all_hits=""
  for i in $(seq 1 "$NUM_AGENTS"); do
    local hl
    hl=$(hits_log_path "$i")
    [ -f "$hl" ] && all_hits+="$(grep '^HIT:' "$hl" 2>/dev/null || true)"$'\n'
  done

  local claimed=()
  local skipped_claimed="" skipped_blocklisted=""
  for other in $(seq 1 "$NUM_AGENTS"); do
    [ "$other" -eq "$agent_num" ] && continue
    local other_sub
    other_sub=$(get_agent_subsystem "$other" 2>/dev/null || echo "unknown")
    [ "$other_sub" != "unknown" ] && claimed+=("$other_sub")
  done

  local ranked_inputs=""
  while IFS= read -r sub; do
    [ -n "$sub" ] || continue
    if subsystem_is_blocklisted "$sub" 2>/dev/null; then
      skipped_blocklisted="${skipped_blocklisted:+$skipped_blocklisted,}${sub}"
      continue
    fi
    local is_claimed=0
    for c in "${claimed[@]:-}"; do
      [ "$c" = "$sub" ] && { is_claimed=1; break; }
    done
    if [ "$is_claimed" -eq 1 ]; then
      skipped_claimed="${skipped_claimed:+$skipped_claimed,}${sub}"
      continue
    fi
    ranked_inputs+="${sub}"$'\n'
  done <<< "$approved_list"

  local best_sub=""
  best_sub=$(coverage_hit_ranked_subsystems "$ranked_inputs" "$all_hits" | awk -F '\t' 'NF { print $2; exit }' 2>/dev/null)
  if declare -F record_subsystem_suggest >/dev/null 2>&1; then
    record_subsystem_suggest "$agent_num" "$my_mode" "$best_sub" "coverage-live" "$skipped_claimed" "$skipped_blocklisted"
  fi
  [ -n "$best_sub" ] && echo "$best_sub"
}

# ─── Cross-agent summary (cached) ───────────────────────────────
# Reads pre-computed per-agent summary lines; excludes the
# requesting agent.

build_cross_agent_summary() {
  local agent_num="$1"
  local summary=""

  for other in $(seq 1 "$NUM_AGENTS"); do
    [ "$other" -eq "$agent_num" ] && continue
    local cache_file="${ITERATION_CACHE_DIR:-}/agent_${other}_summary.txt"
    if [ -f "$cache_file" ]; then
      summary+="$(cat "$cache_file")"$'\n'
    else
      # Fallback: compute live
      local other_sub other_mode other_role other_pending other_crashes other_needs_tc
      other_sub=$(cached_agent_subsystem "$other")
      other_mode=$(agent_mode "$other")
      other_role=$(agent_role "$other")
      local other_sf
      other_sf=$(state_file_path "$other")
      other_pending=0; other_crashes=0; other_needs_tc=0
      local _act_unused=0 _disc_unused=0 _env_unused=0 _invest_unused=0
      if ! structured_state_agent_counts_load "$other" \
             other_pending _act_unused _disc_unused _env_unused \
             other_needs_tc other_crashes _invest_unused 2>/dev/null; then
        [ -f "$other_sf" ] \
          && prompt_markdown_state_counts_load "$other_sf" \
               other_pending _act_unused _disc_unused _env_unused \
               other_needs_tc other_crashes
      fi
      summary+="- Agent ${other} (${other_mode}/${other_role}): subsystem=\`${other_sub}\`, ${other_pending} PENDING, ${other_crashes} findings"
      [ "${other_needs_tc:-0}" -gt 0 ] && summary+=", ${other_needs_tc} NEEDS_TESTCASE"
      summary+=$'\n'
    fi
  done
  echo "$summary"
}

# ─── Agent state instructions ────────────────────────────────────

build_agent_state_instructions() {
  local agent_num="$1"
  local my_mode my_role
  my_mode=$(agent_mode "$agent_num")
  my_role=$(agent_role "$agent_num")

  local cross_summary
  cross_summary=$(build_cross_agent_summary "$agent_num")
  local strategy_arg
  strategy_arg=$(state_strategy_arg "$agent_num")

  cat <<EOF

## AGENT IDENTITY — Agent ${agent_num} (role=${my_role}$([ "$IS_BROWSER_TARGET" -eq 1 ] && echo ", mode=${my_mode}"))

- **Structured resume:** \`bin/state resume --agent ${agent_num} --mode ${my_mode} --role ${my_role}${strategy_arg}\` — primary session state
- **Structured state:** use \`bin/state add-hyp\`, \`bin/state update-hyp\`, \`bin/state add-note\`, and \`bin/state update-card\`; \`bin/probe\` records runs automatically when testcase headers include \`HYPOTHESIS-ID:\`
- **Legacy state file:** $(state_file_path "$agent_num") — optional human-readable context only if it exists; do not create or maintain it manually
- **Scratch dir:** $(scratch_dir_path "$agent_num")/ — testcases, ASan output, harnesses
- **Scratch writes:** always write testcase and harness files under the absolute scratch dir above; never create repo-root \`scratch-${agent_num}/...\`
- **Crashes:** \`${RESULTS_DIR}/crashes/CRASH-NNN-${agent_num}/\` — security crash candidates only
- **Findings:** \`${RESULTS_DIR}/findings/FIND-NNN-<slug>/\` — confirmed SECURITY findings only. Crosses or weakens a security boundary (memory-safety, auth/authz bypass, injection, sandbox escape, info disclosure, crypto weakness, algorithmic DoS, etc.). Do **NOT** file pure correctness / data-integrity / robustness / spec-deviation bugs here — those are upstream quality issues, not security findings. The harness gate deletes non-security FINDs; save the cycles and don't file them in the first place.
$([ "$IS_BROWSER_TARGET" -eq 1 ] && echo "- **Source tree:** ${TARGET_ROOT}/ (Mercurial). Always \`cd ${TARGET_ROOT}\` before \`hg\` commands.")
$([ "$IS_BROWSER_TARGET" -ne 1 ] && echo "- **Source tree:** ${TARGET_ROOT} (${TARGET_REPO_TYPE}).")
- **Rules digest:** embedded below under "SESSION RULES DIGEST". Drill into \`${REFERENCE_DIR}/session-rules.md\` only when the digest is ambiguous.

## OTHER AGENTS (pick a DIFFERENT subsystem)

${cross_summary}
EOF
}

# ─── Subsystem targets ───────────────────────────────────────────

build_subsystem_targets() {
  local mode="${1:-}"
  if [ "$IS_BROWSER_TARGET" -eq 1 ]; then
    local blocklist_text
    blocklist_text=$(cached_blocklist_description)
    if [ "$mode" = "browser" ]; then
      local approved ranked_file
      ranked_file="${ITERATION_CACHE_DIR:-}/coverage_browser.txt"
      if [ -f "$ranked_file" ]; then
        approved=$(head -20 "$ranked_file" | paste -sd, - | sed 's/,/, /g')
      else
        approved=$(browser_mode_subsystems | paste -sd, - | sed 's/,/, /g')
      fi
      cat <<TARGETS

## HIGH-VALUE TARGETS — BROWSER MODE

Pick subsystems reachable from web content. Use the assigned strategy brief for approach details.

**BLOCKLISTED:** ${blocklist_text}
**Mode-compatible candidates:** ${approved}
TARGETS
    elif [ "$mode" = "shell" ]; then
      local approved ranked_file
      ranked_file="${ITERATION_CACHE_DIR:-}/coverage_shell.txt"
      if [ -f "$ranked_file" ]; then
        approved=$(head -20 "$ranked_file" | paste -sd, - | sed 's/,/, /g')
      else
        approved=$(shell_mode_subsystems | paste -sd, - | sed 's/,/, /g')
      fi
      cat <<TARGETS

## HIGH-VALUE TARGETS — SHELL MODE

Drive ASan js shell or xpcshell. Use the assigned strategy brief for approach details.

**BLOCKLISTED:** ${blocklist_text}
**Mode-compatible candidates:** ${approved}
TARGETS
    else
      local candidate_dirs
      candidate_dirs=$(list_candidate_subsystems 2>/dev/null | paste -sd, - | sed 's/,/, /g')
      cat <<TARGETS

## HIGH-VALUE TARGETS

Use the assigned work card first. If none is assigned, pick one analyzable slice from the target tree.
**BLOCKLISTED:** ${blocklist_text}
**Candidate directories:** ${candidate_dirs:-<no candidate directories found>}
TARGETS
    fi
  else
    local candidate_dirs
    candidate_dirs=$(list_candidate_subsystems 2>/dev/null)
    cat <<EOF

## HIGH-VALUE TARGETS FOR ${TARGET_SLUG}

Pick one analyzable slice. Focus on: parsers, decoders, custom allocators, FFI/unsafe boundaries, compression/crypto/media.

**Candidate directories:**
\`\`\`
${candidate_dirs:-<no candidate directories found>}
\`\`\`
EOF
  fi
}

# ─── Strategy assignment line for deep-investigation prompts ─────
# Shows the assigned strategy prominently, or falls back to the
# default priority order if no rotation has been triggered.

build_strategy_assignment_line() {
  local agent_num="$1"
  local assigned=""
  local strategy_file
  strategy_file=$(agent_strategy_path "$agent_num")
  [ -f "$strategy_file" ] && assigned=$(cat "$strategy_file" 2>/dev/null || true)

  if [ -n "$assigned" ]; then
    local strat_ref
    strat_ref=$(strategy_file_for_letter "$assigned")
    if [ -n "$strat_ref" ]; then
      if [ -n "${AUDIT_FIXED_STRATEGY:-}" ]; then
        printf '**Assigned strategy: %s.** This is a pinned smoke run; do not fall back to S1 work cards.\n%s\n' "$assigned" "$(build_strategy_brief "$assigned")"
      else
        printf '**Assigned strategy: %s.** Fallback priority: S1 > S2 > S3 > S4 > S5 > S6 > S7 > S8\n%s\n' "$assigned" "$(build_strategy_brief "$assigned")"
      fi
    else
      if [ -n "${AUDIT_FIXED_STRATEGY:-}" ]; then
        echo "**Assigned strategy: ${assigned}.** This is a pinned smoke run; do not fall back to S1 work cards."
      else
        echo "**Assigned strategy: ${assigned}.** Fallback priority: S1 > S2 > S3 > S4 > S5 > S6 > S7 > S8"
      fi
    fi
  else
    echo "**Strategy priority:** S1 > S2 > S3 > S4 > S5 > S6 > S7 > S8"
  fi
}

state_strategy_arg() {
  local agent_num="$1"
  local current_strategy
  current_strategy=$(get_agent_strategy "$agent_num" 2>/dev/null || true)
  [ -n "$current_strategy" ] && printf ' --strategy %s' "$current_strategy"
}

# ─── Common prompt suffix (hard rules) ──────���────────────────────

build_common_suffix() {
  local static_file="$RESULTS_DIR/.static-prompt-rules.md"
  # -s (exists AND non-empty), not -f: an empty static file — left by a
  # failed/raced/truncating write — would otherwise `cat` to nothing and
  # silently strip the ENTIRE session-rules digest (cheat sheet, search
  # discipline, CRASH/FIND gates) from every prompt that reads it. Fall
  # back to live computation so the suffix is never dropped.
  if [ -s "$static_file" ]; then
    cat "$static_file"
  else
    _build_common_suffix_inline
  fi
}

_build_common_suffix_inline() {
  local blocklist_text="${1:-$(cached_blocklist_description)}"
  render_prompt_template common_suffix.md.j2 \
    --var "blocklist_text=${blocklist_text:-<none>}" \
    --var "results_dir=${RESULTS_DIR}" \
    --var "fuzz_leads_path=$(fuzz_leads_path)" \
    --var "reference_dir=${REFERENCE_DIR}" \
    --var "tool_call_soft_target=${TOOL_CALL_SOFT_TARGET:-80}" \
    --var "tool_call_deep_soft_target=${TOOL_CALL_DEEP_SOFT_TARGET:-150}" \
    --var "session_rules_digest=$(build_session_rules_digest)"
}

write_static_prompt_file() {
  local static_file="$RESULTS_DIR/.static-prompt-rules.md"
  # Build into a per-process temp file, then atomically rename into place.
  # Writing directly to $static_file exposes a truncate-then-fill window in
  # which a concurrent prompt build reads an empty suffix (the bug that
  # stripped the digest from a whole resumed run). Only publish when the new
  # content is non-empty, so a failed neutralize pass never clobbers a good
  # cache with an empty file.
  local tmp="${static_file}.tmp.$$"
  if _build_common_suffix_inline | neutralize_qa_vocab_string > "$tmp" 2>/dev/null && [ -s "$tmp" ]; then
    mv -f "$tmp" "$static_file"
  else
    rm -f "$tmp" 2>/dev/null || true
  fi
}

# ─── File-FIND-first directive ───────────────────────────────────
#
# Emits an explicit "file the FIND immediately, attempt the reproducer
# afterwards" block. Source-only strategies (S2 invariant-negation,
# S3 spec-vs-impl, S5 lifetime/state, S8 property-based) routinely
# concretely identify a defect at file:function:line before any ASan
# crash exists. The reproducer may never land — coverage gap, build
# config, race window — and if the agent waits to file the FIND until
# the testcase crashes, the finding is lost when the agent rotates or
# the iteration ends.
#
# The directive is short and uniform; it is rendered into both the
# cold-start and deep-investigation prompts so every agent reads it
# regardless of role. The text is intentionally directive ("file …
# before") so the model treats it as a workflow step, not a hint.
build_find_first_directive() {
  # results_dir is the absolute write target for FIND directories. A bare
  # `findings/...` is cwd-relative and silently mis-routes the finding
  # when the agent has `cd`'d into the source tree. Refuse to render
  # with an empty RESULTS_DIR — `{{ results_dir }}/findings/` would
  # expand to `/findings/` (absolute path under filesystem root), which
  # would tell the agent to write there.
  if [ -z "${RESULTS_DIR:-}" ]; then
    echo "FATAL: build_find_first_directive called with empty RESULTS_DIR — would render dangerous /findings path" >&2
    return 1
  fi
  render_prompt_template find_first_directive.md.j2 \
    --var "results_dir=${RESULTS_DIR}"
}

# ─── Handoff directive ───────────────────────────────────────────

build_handoff_directive() {
  local target_agent="$1"
  local target_role
  target_role=$(agent_role "$target_agent")
  [ "$target_role" = "reproduce" ] || return 0

  local hf
  hf=$(handoff_file_path)
  [ -f "$hf" ] && [ -s "$hf" ] || return 0

  local handoff_rows
  handoff_rows=$(grep '^|' "$hf" 2>/dev/null | grep -v '^|[-]' | grep -v '^| Hypothesis') || true
  [ -n "$handoff_rows" ] || return 0

  local target_mode
  target_mode=$(agent_mode "$target_agent")

  cat <<HANDOFF

## HANDOFF FROM ANALYSIS AGENTS

These hypotheses need testcase reproduction. Pick the closest to your mode (${target_mode}):

| Hypothesis | File:Function:Line | Input Shape | Guard Gap | Diagnostic | Strategy | Source |
|-----------|-------------------|-------------|-----------|------------|----------|--------|
${handoff_rows}
HANDOFF
}

# ─── Structured work-card assignment ─────────────────────────────

build_work_card_directive() {
  local agent_num="$1"

  # Resolve bin/state to an absolute path. The function used to rely on
  # `bin/state` resolving relative to CWD, which is correct in production
  # (bin/audit fixes CWD to the project root) but fragile in tests and any
  # standalone caller. SCRIPT_ROOT is exported by both bin/audit and
  # tests/helpers.sh; we still fall back to deriving from BASH_SOURCE if
  # neither is set so the function works when sourced in isolation.
  local _state_bin _script_root
  if [ -n "${SCRIPT_ROOT:-}" ]; then
    _script_root="$SCRIPT_ROOT"
  else
    _script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  fi
  _state_bin="$_script_root/bin/state"

  # Each early-return point is silent by default — `return 0` with no stdout
  # is the contract that lets the caller embed this output unconditionally
  # in a heredoc. Under WORK_CARD_DIRECTIVE_DEBUG=1, every silent-return
  # path writes a one-line reason to stderr so flakes are self-diagnosing.
  _wcd_skip() {
    [ "${WORK_CARD_DIRECTIVE_DEBUG:-0}" = "1" ] \
      && printf '[build_work_card_directive agent=%s] skip: %s\n' "$agent_num" "$1" >&2
    return 0
  }

  [ -x "$_state_bin" ] || { _wcd_skip "bin/state not executable: $_state_bin"; return 0; }
  [ -s "${RESULTS_DIR:-}/work-cards.jsonl" ] || { _wcd_skip "work-cards.jsonl missing or empty under RESULTS_DIR=${RESULTS_DIR:-unset}"; return 0; }

  local sf active
  sf=$(state_file_path "$agent_num" 2>/dev/null || true)
  if [ "${WORK_CARD_FORCE_CLAIM:-0}" != "1" ]; then
    if structured_state_agent_has_rows "$agent_num" 2>/dev/null; then
      active=$(structured_state_agent_active_count "$agent_num" 2>/dev/null || echo 0)
      [ "${active:-0}" -gt 0 ] && { _wcd_skip "agent already has ${active} active hypothesis row(s)"; return 0; }
    elif [ -f "$sf" ]; then
      active=$(grep -cE "PENDING|INVESTIGATING|NEEDS_TESTCASE" "$sf" 2>/dev/null || true)
      [ "${active:-0}" -gt 0 ] && { _wcd_skip "agent state file shows ${active} active row(s)"; return 0; }
    fi
  fi

  local mode role card claim_rc strategy_arg
  mode=$(agent_mode "$agent_num" 2>/dev/null || echo "")
  role=$(agent_role "$agent_num" 2>/dev/null || echo "")
  strategy_arg=$(state_strategy_arg "$agent_num")
  # Prompt-time assignment must claim a short lease. Otherwise parallel
  # cold-start prompts all see the same top-ranked card and duplicate work
  # until one agent later records a hypothesis. Stale-claim release runs each
  # audit iteration, so cards that were assigned but never adopted return to
  # the pool without poisoning the queue.
  card=$("$_state_bin" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
          next-card --agent "$agent_num" --mode "$mode" --role "$role" ${strategy_arg} 2>/dev/null)
  claim_rc=$?
  if [ "$claim_rc" -ne 0 ]; then
    _wcd_skip "next-card returned rc=${claim_rc} (no eligible card for agent=${agent_num} mode=${mode} role=${role})"
    return 0
  fi
  [ -n "$card" ] || { _wcd_skip "next-card returned empty stdout"; return 0; }

  local id="" kind="" subsystem="" file="" strategy="" score="" seed="" reason="" patch_cards="" fix_hashes=""
  local r_class="" r_line="" r_verdict="" r_id="" r_find_id=""
  local field_assignments
  field_assignments=$(printf '%s' "$card" | jq -r '
    def emit($name; $value): "\($name)=\($value | @sh)";
    emit("id"; .id // ""),
    emit("kind"; .kind // ""),
    emit("subsystem"; .subsystem // ""),
    emit("file"; .file // ""),
    emit("strategy"; .strategy // ""),
    emit("score"; ((.score // "") | tostring)),
    emit("seed"; .seed // ""),
    emit("reason"; .reason // ""),
    emit("patch_cards"; ((.patch_cards // []) | join(", "))),
    emit("fix_hashes"; ((.fix_hashes // []) | join(", "))),
    emit("r_class"; .recon.class // ""),
    emit("r_line"; ((.recon.line // "") | tostring)),
    emit("r_verdict"; .recon.validator_verdict // ""),
    emit("r_id"; .recon.id // ""),
    emit("r_find_id"; .find_id // "")
  ' 2>/dev/null) || field_assignments=""
  [ -n "$field_assignments" ] && eval "$field_assignments"

  # Recon-hypothesis cards carry the validator's verdict + the original
  # finding's title/notes/class/line in a sub-object. The block was
  # being dropped on the floor here, leaving the agent to re-derive the
  # attack shape from scratch in a ~5-minute session window — defeating
  # the entire purpose of running recon up front. When present, render
  # a RECON HYPOTHESIS DETAIL section so the agent can lead with the
  # exact input shape recon validated. Empty for non-recon cards.
  local recon_detail=""
  if [ "$kind" = "recon-hypothesis" ]; then
    local r_title r_notes
    # title/notes don't live under .recon — recon_to_cards.py only
    # echoes them into .reason (truncated). Extract from .reason as a
    # best-effort split on " | " delimiters that recon_to_cards uses.
    r_title=$(printf '%s' "$reason" \
      | awk -F ' \\| ' '{for (i=1;i<=NF;i++) if ($i !~ /^(recon hypothesis|class=|validator=)/) {print $i; exit}}')
    r_notes=$(printf '%s' "$reason" \
      | awk -F ' \\| ' 'NF{print $NF}')
    [ "$r_notes" = "$r_title" ] && r_notes=""
    # If recon already materialized a FIND for this hypothesis, render a
    # PRE-FILED FIND block so the agent augments that dir instead of
    # creating a new FIND-NNN-* for the same defect. The augment-don't-
    # refile contract is what keeps the benchmark count from double-counting
    # when both recon-materialization AND agent-filing fire for the same
    # bug — see lib/recon_to_cards.py::materialize_find for the upstream
    # half of the contract.
    local find_block=""
    if [ -n "$r_find_id" ]; then
      find_block=$(cat <<FIND

### PRE-FILED FIND (augment, do not re-file)

A FIND has already been materialized for this hypothesis at
\`${RESULTS_DIR}/findings/${r_find_id}/report.md\` (or under
\`findings-rejected/${r_find_id}/\` if the validator rejected the lead).

**Your job is to AUGMENT that FIND, not create a new one.**

- Write your testcase / reproducer into that FIND dir alongside report.md.
- Append a "## Reproducer" or "## Sanitizer evidence" section to the
  existing report.md with the ASan/UBSan/MSan output and the exact
  testcase command.
- If your probe is sanitizer-CLEAN, do NOT discard the FIND. Append a
  "## Sanitizer evidence" section that records what you tried and the
  clean result. Recon already named the defect from source; ASan being
  silent only means this particular oracle did not fire — the security
  claim still stands and the FIND remains counted.
- Do NOT create \`findings/FIND-NNN-<slug>/\` for the same defect. The
  pre-filed id (\`${r_find_id}\`) is the canonical record.
FIND
)
    fi
    recon_detail=$(cat <<RECON

## RECON HYPOTHESIS DETAIL

The recon stage already triaged this file and validated a specific
attack shape. Read these fields before writing your first testcase —
they describe the exact input the validator confirmed reaches the
suspected bug. Start your first probe from this shape; only widen
after at least one ASan-verified run on the named line.

- **Recon ID:** ${r_id:-unknown}
- **Line:** ${r_line:-unknown}
- **Class:** ${r_class:-unspecified}
- **Validator verdict:** ${r_verdict:-unspecified}
- **Title:** ${r_title:-(none recorded)}
- **Notes:** ${r_notes:-(none recorded)}

If the validator verdict is **Promote**, treat the hypothesis as a
high-confidence lead — do not redo recon, write the testcase. If the
verdict is **Uncertain**, the validator could not finish in budget;
your probe is what closes it. Either way, ${file}:${r_line:-?} is the
suspected site — read 60 lines on each side first.
${find_block}
RECON
)
  fi

  cat <<EOF

## ASSIGNED WORK CARD

- **ID:** ${id}
- **Kind:** ${kind}
- **Subsystem:** \`${subsystem}\`
- **File:** \`${file}\`
- **Strategy:** ${strategy}
- **Score:** ${score}
- **Why ranked:** ${reason:-structural/code-feature score}
${seed:+- **Seed:** \`${seed}\`}
- **Fix commits:** ${fix_hashes:-none listed}
${patch_cards:+- **Related patch cards:** ${patch_cards}}
${recon_detail}

Use this card as the first concrete target unless your current state already has a higher-priority PENDING/NEEDS_TESTCASE row.
For S1 prior-fix cards, **PATCH-* is only the work-card id, not a VCS revision**. When fix commits are listed above, use those hashes with \`bin/show-patch <commit>\`; do not run \`git show\` or \`bin/show-patch\` on the PATCH-* card id.
When creating a structured hypothesis, include \`--card-id ${id}\`. Add \`CARD-ID: ${id}\` to testcase headers so \`bin/probe\` can close crash-producing cards automatically.
EOF
}

# ─── Session seed (compaction recovery) ─────────────────────────
# Reads $RESULTS_DIR/.session_seed_<agent>.md (produced by
# lib/build_session_seed.py at the END of the prior iteration). The
# seed lists files+ranges the agent has already Read, exact source searches
# already run, and testcases already Written. Injecting it into the next
# prompt prevents the agent from re-Reading/re-searching the same context
# after auto-compaction — which validation showed wastes ~33% of Read bytes.
#
# Silent on miss: first iteration, fresh agent, or empty prior log.

build_session_seed_section() {
  local agent_num="$1"
  [ -n "$agent_num" ] || return 0
  [ -n "${RESULTS_DIR:-}" ] || return 0
  local seed_path="${RESULTS_DIR}/.session_seed_${agent_num}.md"
  [ -f "$seed_path" ] && [ -s "$seed_path" ] || return 0

  cat <<SEED

## PRIOR SESSION SEED — files already on disk / already Read

The harness recorded what the *prior* iteration of this agent Read, Wrote,
and searched. Use this to avoid re-Reading the same ranges or repeating exact
source searches after compaction. To read a *different* range of the same file,
pass \`offset\`/\`limit\` outside the listed span.

\`\`\`
$(cat "$seed_path")
\`\`\`
SEED
}

build_agent_asan_loop_command() {
  local agent_num="$1"
  echo "\`bin/probe $(scratch_dir_path "$agent_num")/<testcase>\`"
}

# ─── Investigation continuation (open INVESTIGATING hypothesis) ───
# When an agent has an INVESTIGATING/NEEDS_TESTCASE hypothesis still
# open from a prior iteration, codex spawns a FRESH session — losing
# the agent's reasoning state and forcing a re-derivation of context.
# This section grabs the tail of the most recent session log so the
# resumed prompt carries the last few minutes of the agent's own
# narration into the new turn.
#
# Conservative bounds:
# - Only injects when there is an active hypothesis (skip first iteration).
# - Caps at 4 KB to stay within ~1 K tokens.
# - Pulls from the formatted .log (already human-readable) rather than
#   the raw JSONL, to keep the prompt diffable and self-documenting.
# - Silent on miss (no log, no active hyp, or fresh-prompt mode).

build_session_continuation_section() {
  local agent_num="$1"
  [ -n "$agent_num" ] || return 0
  [ -n "${RESULTS_DIR:-}" ] || return 0
  [ -n "${LOGDIR:-}" ] || return 0

  # Skip when there is no active hypothesis row — the agent is
  # starting fresh anyway, so a stale tail from a closed hypothesis
  # would mislead more than it helps.
  if declare -F structured_state_agent_has_rows >/dev/null 2>&1; then
    structured_state_agent_has_rows "$agent_num" 2>/dev/null || return 0
    local active
    active=$(structured_state_agent_active_count "$agent_num" 2>/dev/null || echo 0)
    [ "${active:-0}" -gt 0 ] || return 0
  fi

  # Most recent session log for this agent (cold-start or deep).
  local latest_log
  latest_log=$(ls -1t \
    "$LOGDIR"/session_*_cold-start-"${agent_num}"-*.log \
    "$LOGDIR"/session_*_deep_investigation-"${agent_num}"-*.log \
    2>/dev/null | head -1)
  [ -n "$latest_log" ] && [ -f "$latest_log" ] || return 0

  # Tail the last ~80 lines, then keep only the trailing 4 KB. Lines
  # from the formatted log carry the agent log prefix; keep them so
  # the model sees "this was MY prior output" attribution rather than
  # free-floating text. The two-stage tail bounds output by both line
  # count and byte count (whichever bites first).
  local tail_text
  tail_text=$(tail -n 80 "$latest_log" 2>/dev/null | tail -c 4096 2>/dev/null)
  [ -n "$tail_text" ] || return 0

  cat <<TAIL

## PRIOR SESSION TAIL — your own last words

The harness restarted your session while a hypothesis was still
active. Below is the last ~4 KB of YOUR previous session output, so
you can pick up where you left off instead of re-deriving context.
This is not a directive — read it, then continue investigation. If a
sentence ends mid-thought, finish that thought first.

\`\`\`
${tail_text}
\`\`\`
TAIL
}

# ─── Sanitizer build directive (generic targets) ─────────────────
# Tells agents where sanitizer builds live (or should be created) so they
# don't waste iterations rebuilding existing instrumented artifacts.

build_sanitizer_build_directive() {
  [ "$IS_BROWSER_TARGET" -eq 0 ] || return 0

  local enabled_csv="${TARGET_SANITIZERS_ENABLED_CSV:-}"
  if [ -z "$enabled_csv" ] && declare -F target_sanitizers_enabled_csv >/dev/null 2>&1; then
    enabled_csv="$(target_sanitizers_enabled_csv 2>/dev/null || true)"
  fi
  [ -n "$enabled_csv" ] || enabled_csv="asan"

  local summary="${SANITIZER_BUILD_SUMMARY:-}"
  local missing="${SANITIZER_BUILD_MISSING:-}"
  if [ -z "$summary" ] && [ "${ASAN_BUILD_AVAILABLE:-0}" -eq 1 ] && [ -n "${ASAN_BUILD_BINARY:-}" ]; then
    summary="- asan: \`${ASAN_BUILD_BINARY}\` (legacy detection)"
  fi

  if [ "${SANITIZER_BUILD_DISABLED:-0}" = "1" ]; then
    cat <<SANDIR

## SANITIZER BUILDS — DISABLED

\`target.toml\` sets \`[sanitizer].enabled = []\`; this target is in runner/findings mode.
Use \`bin/probe\` with the configured runner. Do not spend work building ASan/MSan/TSan/UBSan unless the target configuration changes.
SANDIR
    return 0
  fi

  if [ -n "$summary" ] && [ -n "$missing" ]; then
    cat <<SANDIR

## SANITIZER BUILDS — PARTIAL

Enabled sanitizers: \`${enabled_csv}\`

Detected:
${summary}

Missing:
${missing}

**Do NOT rebuild detected artifacts.** Use configured binaries/libraries for available sanitizer runs; mark missing configured artifacts as ENV-BLOCKED if they block the assigned work.
SANDIR
  elif [ -n "$summary" ]; then
    cat <<SANDIR

## SANITIZER BUILDS — ALREADY AVAILABLE

Enabled sanitizers: \`${enabled_csv}\`

Detected:
${summary}

**Do NOT rebuild.** Use these configured binaries/libraries for sanitizer runs. If an artifact is stale or broken, note it in your state file as ENV-BLOCKED.
SANDIR
  else
    case ",${enabled_csv}," in
      *,asan,*)
        cat <<SANDIR

## SANITIZER BUILDS — NOT FOUND

Enabled sanitizers: \`${enabled_csv}\`

Missing:
${missing:-- asan: set asan_bin/asan_lib in target.toml or build under ${ASAN_BUILD_DIR}/}

For ASan targets, the standard build directory is \`${ASAN_BUILD_DIR}/\`. Build with sanitizer flags only when the assigned work actually needs the missing artifact:
\`\`\`
jobs=\$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)
CC=clang CXX=clang++ CFLAGS="-fsanitize=address -O2 -g -DNDEBUG -fno-omit-frame-pointer" \\
  CXXFLAGS="\$CFLAGS" LDFLAGS="-fsanitize=address" \\
  ./configure --prefix=${ASAN_BUILD_DIR} && make -j"\$jobs" && make install
\`\`\`
**Sanitizer builds must mirror the release binary while keeping symbols.** Use optimized release profiles with explicit debug info: \`-O2 -g -DNDEBUG\` plus sanitizer flags in compile and link flags. Do NOT pass \`--enable-debug\` (autotools), \`-DCMAKE_BUILD_TYPE=Debug\` / \`RelWithDebInfo\` / \`-DENABLE_DEBUG=ON\` (cmake), \`--buildtype=debug\` / \`debugoptimized\` (meson), or \`ac_add_options --enable-debug\` (mozconfig). Prefer cmake \`-DCMAKE_BUILD_TYPE=Release\` and meson \`--buildtype=release -Db_ndebug=true\`. Debug toggles compile in \`DEBUGASSERT\` / \`MOZ_ASSERT\` / \`DCHECK\` / \`assert(...)\` aborts that are no-ops in shipped binaries — sanitizer hits on those are robustness signals, not security bugs.
Adapt the above to the target's actual build system (cmake, meson, cargo, go, etc.) and update \`target.toml\`.
SANDIR
        ;;
      *)
        cat <<SANDIR

## SANITIZER BUILDS — NOT FOUND

Enabled sanitizers: \`${enabled_csv}\`

Missing:
${missing:-- configure the target sanitizer binary in \`target.toml\`}

Build or locate the requested sanitizer artifacts, then set the matching \`[sanitizer].*_bin\` key in \`target.toml\`. Do not substitute an ASan build for non-ASan work.
SANDIR
        ;;
    esac
  fi
}

# Compact excerpt of the target.toml facts agents kept re-reading.
# Session transcripts showed repeated `bin/peek output/<slug>/target.toml`
# calls per session — one full LLM round-trip each — to recover the
# threat model, sanitizer matrix, and harness/runner flags the orchestrator
# has already parsed. Emit those facts inline and point agents away from
# re-reading the file. Values come from the exported config (no re-parse).
prompt_compact_list() {
  local limit=8 total="$#" count=0 omitted=0 out="" item clean
  for item in "$@"; do
    count=$((count + 1))
    if [ "$count" -gt "$limit" ]; then
      omitted=$((total - limit))
      break
    fi
    clean="${item//$'\n'/ }"
    if [ "${#clean}" -gt 120 ]; then
      clean="${clean:0:117}..."
    fi
    if [ -n "$out" ]; then
      out="${out}, ${clean}"
    else
      out="$clean"
    fi
  done
  if [ "$omitted" -gt 0 ]; then
    out="${out}, ... (+${omitted} more)"
  fi
  printf '%s' "$out"
}

build_target_config_directive() {
  [ "${IS_BROWSER_TARGET:-0}" -eq 0 ] || return 0

  local controls="${TARGET_ATTACKER_CONTROLS_CSV:-}"
  if [ -z "$controls" ] && declare -F target_attacker_controls_csv >/dev/null 2>&1; then
    controls="$(target_attacker_controls_csv 2>/dev/null || true)"
  fi
  local enabled="${TARGET_SANITIZERS_ENABLED_CSV:-}"
  if [ -z "$enabled" ] && declare -F target_sanitizers_enabled_csv >/dev/null 2>&1; then
    enabled="$(target_sanitizers_enabled_csv 2>/dev/null || true)"
  fi
  local includes="" defines="" link_libs="" runner_args="" runner_env=""
  includes="$(prompt_compact_list "${TARGET_INCLUDES[@]:-}")"
  defines="$(prompt_compact_list "${TARGET_DEFINES[@]:-}")"
  link_libs="$(prompt_compact_list "${TARGET_LINK_LIBS[@]:-}")"
  runner_args="$(prompt_compact_list "${TARGET_RUNNER_ARGS[@]:-}")"
  runner_env="$(prompt_compact_list "${TARGET_RUNNER_ENV[@]:-}")"
  local extra_lines=""
  [ -n "${TARGET_ASAN_LIB:-}" ] && extra_lines="${extra_lines}- \`asan_lib\`: \`${TARGET_ASAN_LIB}\`
"
  [ -n "$includes" ] && extra_lines="${extra_lines}- \`includes\`: \`${includes}\`
"
  [ -n "$defines" ] && extra_lines="${extra_lines}- \`defines\`: \`${defines}\`
"
  [ -n "$link_libs" ] && extra_lines="${extra_lines}- \`link_libs\`: \`${link_libs}\`
"
  [ -n "${TARGET_RUNNER_BIN:-}" ] && extra_lines="${extra_lines}- \`[runner].bin\`: \`${TARGET_RUNNER_BIN}\`
"
  [ -n "$runner_args" ] && extra_lines="${extra_lines}- \`[runner].args\`: \`${runner_args}\`
"
  [ -n "$runner_env" ] && extra_lines="${extra_lines}- \`[runner].env\`: \`${runner_env}\`
"
  [ -n "$controls" ] || [ -n "$enabled" ] || [ -n "${TARGET_ASAN_LIB:-}" ] \
    || [ -n "$includes" ] || [ -n "$defines" ] || [ -n "$link_libs" ] \
    || [ -n "${TARGET_RUNNER_BIN:-}" ] || [ -n "$runner_args" ] || [ -n "$runner_env" ] \
    || return 0

  cat <<CFGDIR

## TARGET CONFIG (already parsed from target.toml — do not re-read it)

- \`[threat_model] attacker_controls\` (the only valid Trigger sources): \`${controls:-bytes}\`
- \`[sanitizer] enabled\`: \`${enabled:-asan}\`
${extra_lines}

Beyond these, \`output/${TARGET_SLUG}/target.toml\` holds only advanced build/configure plumbing — open it only when editing the config, not to re-derive harness flags, runner args, or the threat model.
CFGDIR
}

build_asan_build_directive() {
  build_sanitizer_build_directive
  build_target_config_directive
  build_build_features_directive
}

# Surface the build-feature manifest (stub TUs / compiled-in features)
# to the agent. Empty output when no manifest exists or no stubs were
# detected — keeps prompts unchanged on healthy builds. Cached at first
# call to avoid spawning python3 per cache-replayed prompt render.
_BUILD_FEATURES_DIRECTIVE_CACHED=""
_BUILD_FEATURES_DIRECTIVE_LOADED=0
build_build_features_directive() {
  if [ "$_BUILD_FEATURES_DIRECTIVE_LOADED" -eq 0 ]; then
    _BUILD_FEATURES_DIRECTIVE_LOADED=1
    local features_json="${BUILD_FEATURES_JSON:-${RESULTS_DIR:-}/state/features.json}"
    if [ -f "$features_json" ] && command -v python3 >/dev/null 2>&1; then
      _BUILD_FEATURES_DIRECTIVE_CACHED="$(python3 "${SCRIPT_ROOT:-.}/lib/build_probe.py" summary --features "$features_json" 2>/dev/null || true)"
    fi
  fi
  [ -n "$_BUILD_FEATURES_DIRECTIVE_CACHED" ] || return 0
  printf '\n%s\n' "$_BUILD_FEATURES_DIRECTIVE_CACHED"
}

# Surface persistent harness build failures to the agent so it closes the
# build-fix loop itself instead of letting the operator notice. We only
# emit the section once enough failures have accumulated to indicate a
# systemic problem (toolchain mismatch, missing include path, wrong link
# flags) — single transient failures stay quiet so the section is signal
# rather than noise.
#
# The agent is explicitly authorized to edit output/<slug>/target.toml's
# `includes` / `link_libs` / `defines` keys when the cached build logs
# point at a config problem. Source/harness fixes still belong in the
# scratch testcase, not the target tree.
build_harness_build_failures_directive() {
  [ -d "${RESULTS_DIR:-/nonexistent}" ] || return 0
  local threshold="${HARNESS_BUILD_FAILURE_PROMPT_THRESHOLD:-3}"
  case "$threshold" in ''|*[!0-9]*) threshold=3 ;; esac

  local -a logs=()
  while IFS= read -r -d '' f; do
    [ -s "$f" ] && logs+=("$f")
  done < <(find "$RESULTS_DIR" -maxdepth 4 -path '*/.harness-cache/*.build.log' \
              -type f -print0 2>/dev/null)
  [ "${#logs[@]}" -ge "$threshold" ] || return 0

  # Sort by mtime descending, take up to 3. audit_stat_mtime_epoch is
  # the portable wrapper around stat — open-coded `stat -f || stat -c`
  # silently produced filesystem-info junk on GNU stat (Linux), which
  # then broke `sort -rn`.
  local sorted="" l m
  for l in "${logs[@]}"; do
    m=$(audit_stat_mtime_epoch "$l")
    sorted="${sorted}${m} ${l}"$'\n'
  done
  local top
  top=$(printf '%s' "$sorted" | sort -rn | head -3 | awk '{ $1=""; sub(/^ /,""); print }')

  local toml_path="${SCRIPT_ROOT:-..}/output/${TARGET_SLUG:-<slug>}/target.toml"
  if declare -F target_toml_from_results >/dev/null 2>&1; then
    toml_path="$(target_toml_from_results "${RESULTS_DIR:-}" 2>/dev/null || printf '%s' "$toml_path")"
  fi
  cat <<HBFD

## PERSISTENT HARNESS BUILD FAILURES — FIX THE LOOP YOURSELF

\`${#logs[@]}\` cached harness build failure log(s) exist under
\`${RESULTS_DIR}/scratch-*/.harness-cache/\`. Probes keep returning
"harness build failed" for the same root cause. Do not retry blindly.

Most recent failures (start with \`tail -120\`, not \`cat\`):
$(printf '%s\n' "$top" | sed 's|^|- `|; s|$|`|')

Triage and act, in this order:

1. **Read the latest build log tail** with \`tail -120 <log>\`. Identify
   whether the error is a missing header, type/define conflict, link symbol
   miss, or SDK clash. If the diagnostic is incomplete, widen the bounded
   read with \`tail -240 <log>\` or \`bin/peek <log>:1-200\`.
2. **If the harness source is wrong** (bad \`#include\` order, missing
   \`#define\` to avoid host-header conflict, missing forward decl), edit
   the scratch \`.c\`/\`.cc\` file and re-probe.
3. **If the target config is wrong**, edit \`${toml_path}\`:
   - \`includes = [...]\` — add the missing include directory.
   - \`link_libs = [...]\` — add the missing \`-l<name>\`, \`-L<path>\`,
     \`-Wl,-rpath,<path>\`, target-relative archive, or target-relative source
     file entry.
   - \`defines = [...]\` (optional) — add \`-D<NAME>=<val>\` flags.
   Re-source by re-running \`bin/probe\`; the cached failure under
   \`.harness-cache/\` will rebuild against the new config.
4. **If neither is fixable** (toolchain mismatch you can't paper over,
   sanitizer-runtime conflict), mark the hypothesis ENV-BLOCKED with
   \`bin/state update-hyp --status ENV-BLOCKED --note "<one-line build error>"\`
   and move on. Do not file a CRASH dir without a verified ASan run.

This is a self-service loop. The operator is not watching probe stderr —
if you don't fix it, no one will.
HBFD
}

prompt_agent_active_count() {
  local agent_num="$1" sf active
  if declare -F structured_state_agent_active_count >/dev/null 2>&1; then
    active=$(structured_state_agent_active_count "$agent_num" 2>/dev/null || echo 0)
    case "${active:-0}" in ''|*[!0-9]*) active=0 ;; esac
    echo "$active"
    return 0
  fi
  sf=$(state_file_path "$agent_num" 2>/dev/null || true)
  [ -f "$sf" ] || { echo 0; return 0; }
  active=$(grep -cE "PENDING|INVESTIGATING|NEEDS_TESTCASE" "$sf" 2>/dev/null || true)
  echo "${active:-0}"
}

# ─── Cold start prompt ────────────────────────────────────────────

build_cold_start_prompt() {
  local agent_num="$1"
  local mode role
  mode=$(agent_mode "$agent_num")
  role=$(agent_role "$agent_num")

  # Pre-compute every fragment the template needs. Each helper resolves
  # bash-runtime state at call time; the renderer receives the results
  # as opaque strings and substitutes them into the .md.j2 placeholders.
  local targets
  targets=$(build_subsystem_targets "$mode")

  local suggested_sub suggested_sub_line=""
  suggested_sub=$(assign_subsystem_from_coverage "$agent_num" 2>/dev/null || true)
  [ -n "$suggested_sub" ] && suggested_sub_line="
   **Suggested (lowest coverage):** \`${suggested_sub}\`"

  local audit_fixed_strategy_hint=""
  [ -n "${AUDIT_FIXED_STRATEGY:-}" ] && audit_fixed_strategy_hint="Pinned strategy smoke: still create one Strategy ${AUDIT_FIXED_STRATEGY} hypothesis and run one minimal probe before stopping."

  local assigned_strat="" strat_track_file
  strat_track_file=$(agent_strategy_path "$agent_num")
  [ -f "$strat_track_file" ] && assigned_strat=$(cat "$strat_track_file" 2>/dev/null || true)

  local strategy_a_block=""
  if [ -n "$assigned_strat" ] && [ "$assigned_strat" != "S1" ]; then
    local strat_ref
    strat_ref=$(strategy_file_for_letter "$assigned_strat")
    strategy_a_block="
## ASSIGNED STRATEGY — ${assigned_strat}

The harness has assigned Strategy **${assigned_strat}** based on prior rotation.
Orient with this inline brief, then open \`${REFERENCE_DIR}/strategies/${strat_ref}\` for the full playbook before forming hypotheses.
$(build_strategy_brief "$assigned_strat")
Generate 3-5 hypotheses using this strategy. Do NOT default to Strategy S1."
  fi

  local role_guidance=""
  local asan_loop_cmd
  asan_loop_cmd=$(build_agent_asan_loop_command "$agent_num")
  if [ "$role" = "analysis" ]; then
    role_guidance="
## ROLE: ANALYSIS AGENT (with validation requirement)

Focus on DEEP CODE UNDERSTANDING: prior-fix review, data-flow tracing, guard-gap identification.
Output: hypotheses with full data flow traces and concrete reproduction plans.
**NEW REQUIREMENT:** Before marking any hypothesis NEEDS_TESTCASE, you MUST write a minimal probe
testcase and run ${asan_loop_cmd}. If coverage misses or the testcase does not execute the target,
revise the hypothesis — don't hand off unvalidated targets to reproduce agents.
Aim for at least 3 ASan validation runs per session."
  elif [ "$role" = "reproduce" ]; then
    role_guidance="
## ROLE: REPRODUCTION AGENT

Focus on turning hypotheses into crashes.
Check \`bin/find-seed <file>[:<Function>]\` first — if it returns candidates, mutate one; otherwise write from scratch under \`$(scratch_dir_path "$agent_num")/\`. Run every testcase with \`bin/probe\`; it saves ASan output and coverage-gates browser/js inputs when possible.
Try 3+ variant inputs per hypothesis. First testcase within 20 tool calls."
  fi

  local mode_lock_line
  if [ "$IS_BROWSER_TARGET" -eq 1 ]; then
    mode_lock_line="**NO OVERLAP.** Mode lock: ${mode} only."
  else
    mode_lock_line="**NO OVERLAP.** Pick a different subsystem from every other agent."
  fi

  render_prompt_template cold_start.md.j2 \
    --var "agent_num=$agent_num" \
    --var "role=$role" \
    --var "mode=$mode" \
    --var "safety_framing=$SAFETY_FRAMING_CACHED" \
    --var "guide_section=$(build_guide_section cold)" \
    --var "state_strategy_arg=$(state_strategy_arg "$agent_num")" \
    --var "suggested_sub_line=$suggested_sub_line" \
    --var "audit_fixed_strategy_hint=$audit_fixed_strategy_hint" \
    --var "reference_dir=${REFERENCE_DIR}" \
    --var "strategy_a_block=$strategy_a_block" \
    --var "role_guidance=$role_guidance" \
    --var "work_card_directive=$(build_work_card_directive "$agent_num")" \
    --var "targets=$targets" \
    --var "asan_build_directive=$(build_asan_build_directive)" \
    --var "harness_build_failures_directive=$(build_harness_build_failures_directive)" \
    --var "find_first_directive=$(build_find_first_directive)" \
    --var "mode_lock_line=$mode_lock_line" \
    --var "agent_state_instructions=$(build_agent_state_instructions "$agent_num")" \
    --var "common_suffix=$(build_common_suffix)"
}

build_compact_fresh_prompt() {
  local agent_num="$1" mode role
  mode=$(agent_mode "$agent_num")
  role=$(agent_role "$agent_num")

  local audit_fixed_strategy_compact_clause=""
  [ -n "${AUDIT_FIXED_STRATEGY:-}" ] && audit_fixed_strategy_compact_clause="create one Strategy ${AUDIT_FIXED_STRATEGY} hypothesis from a small source/code-feature target, run one minimal \`bin/probe\`, then record the result. If no suitable source target exists, "

  render_prompt_template compact_fresh.md.j2 \
    --var "agent_num=$agent_num" \
    --var "role=$role" \
    --var "mode=$mode" \
    --var "safety_framing=$SAFETY_FRAMING_CACHED" \
    --var "guide_section=$(build_guide_section deep)" \
    --var "state_strategy_arg=$(state_strategy_arg "$agent_num")" \
    --var "scratch_dir=$(scratch_dir_path "$agent_num")" \
    --var "audit_fixed_strategy_compact_clause=$audit_fixed_strategy_compact_clause" \
    --var "strategy_assignment_line=$(build_strategy_assignment_line "$agent_num")" \
    --var "work_card_directive=$(build_work_card_directive "$agent_num")" \
    --var "asan_build_directive=$(build_asan_build_directive)" \
    --var "harness_build_failures_directive=$(build_harness_build_failures_directive)" \
    --var "agent_state_instructions=$(build_agent_state_instructions "$agent_num")" \
    --var "session_continuation_section=$(build_session_continuation_section "$agent_num")"
}

# ─── Deep investigation prompt ────────────────────────────────────

build_deep_investigation_prompt() {
  local agent_num agent_id mode
  if [ "$#" -ge 2 ]; then
    agent_id="$1"; agent_num="$2"
  else
    agent_num="$1"
    case "$agent_num" in
      1) agent_id=A;; 2) agent_id=B;; 3) agent_id=C;; 4) agent_id=D;;
      5) agent_id=E;; 6) agent_id=F;; 7) agent_id=G;; 8) agent_id=H;;
      *) agent_id="$agent_num";;
    esac
  fi
  mode=$(agent_mode "$agent_num")

  if [ ! -f "$(state_file_path "$agent_num")" ] && ! structured_state_agent_has_rows "$agent_num" 2>/dev/null; then
    build_cold_start_prompt "$agent_num"
    return 0
  fi

  if [ "$(prompt_agent_active_count "$agent_num")" -eq 0 ]; then
    build_compact_fresh_prompt "$agent_num"
    return 0
  fi

  # Single unified directive (replaces 7 separate directive builders)
  local directive
  directive=$(build_session_directive "$agent_num" 2>/dev/null || true)

  # Enforcement results from prior iteration
  local enforcement
  enforcement=$(build_enforcement_results_directive "$agent_num" 2>/dev/null || true)

  local role
  role=$(agent_role "$agent_num")
  local asan_loop_cmd
  asan_loop_cmd=$(build_agent_asan_loop_command "$agent_num")

  # Check assigned strategy for role guidance
  local assigned_strat_deep=""
  local strat_track_deep
  strat_track_deep=$(agent_strategy_path "$agent_num")
  [ -f "$strat_track_deep" ] && assigned_strat_deep=$(cat "$strat_track_deep" 2>/dev/null || true)

  # Role-specific guidance
  local role_block=""
  if [ "$role" = "analysis" ]; then
    role_block="**ROLE: ANALYSIS** — Deep code review, data-flow tracing, hypothesis generation.
**VALIDATION REQUIRED:** Before marking NEEDS_TESTCASE, write a minimal probe and run
${asan_loop_cmd} to confirm coverage/target execution. If it misses or does not execute, revise — don't hand off
unvalidated targets. Aim for 3+ ASan validation runs per session."
  else
    local default_action=""
    if [ -n "$assigned_strat_deep" ] && [ "$assigned_strat_deep" != "S1" ]; then
      local strat_ref_deep
      strat_ref_deep=$(strategy_file_for_letter "$assigned_strat_deep")
      default_action="**ASSIGNED STRATEGY: ${assigned_strat_deep}.** Orient with this brief, then open \`${REFERENCE_DIR}/strategies/${strat_ref_deep}\` for the full playbook before forming hypotheses.
$(build_strategy_brief "$assigned_strat_deep")
Generate hypotheses using that approach."
    fi
    role_block="**ROLE: REPRODUCE** — Write testcases that trigger sanitizer diagnostics.
${default_action}
Check \`bin/find-seed <file>[:<Function>]\` first — if it returns candidates, mutate one; otherwise write from scratch under \`$(scratch_dir_path "$agent_num")/\`. First testcase plus \`bin/probe\` output within ~20 tool calls."
  fi

  # Pre-compute the conditional fragments the template substitutes.
  local mode_lock_or_targets_block
  if [ "$IS_BROWSER_TARGET" -eq 1 ]; then
    mode_lock_or_targets_block="
**MODE LOCK:** ${mode}. Use \`bin/probe <testcase>\`; it chooses the correct runner.
$(build_subsystem_targets "$mode")"
  else
    mode_lock_or_targets_block="
$(build_subsystem_targets "$mode")
$(build_asan_build_directive)
$(build_harness_build_failures_directive)"
  fi

  local directive_block=""
  [ -n "$directive" ] && directive_block="
${directive}"

  local enforcement_block=""
  [ -n "$enforcement" ] && enforcement_block="
${enforcement}"

  local audit_fixed_strategy_clause=""
  [ -n "${AUDIT_FIXED_STRATEGY:-}" ] && audit_fixed_strategy_clause="create one Strategy ${AUDIT_FIXED_STRATEGY} hypothesis from a small source/code-feature target, run one minimal \`bin/probe\`, then record the result. If no suitable source target exists, "

  local wrong_mode_subsystem_line=""
  [ "$IS_BROWSER_TARGET" -eq 1 ] && wrong_mode_subsystem_line="- Wrong-mode subsystem? Discard it, pick a fresh ${mode}-mode target."

  render_prompt_template deep_investigation.md.j2 \
    --var "agent_num=$agent_num" \
    --var "agent_id=$agent_id" \
    --var "role=$role" \
    --var "mode=$mode" \
    --var "safety_framing=$SAFETY_FRAMING_CACHED" \
    --var "guide_section=$(build_guide_section deep)" \
    --var "state_strategy_arg=$(state_strategy_arg "$agent_num")" \
    --var "state_file_path=$(state_file_path "$agent_num")" \
    --var "asan_loop_cmd=$asan_loop_cmd" \
    --var "mode_lock_or_targets_block=$mode_lock_or_targets_block" \
    --var "directive_block=$directive_block" \
    --var "enforcement_block=$enforcement_block" \
    --var "session_seed_section=$(build_session_seed_section "$agent_num")" \
    --var "session_continuation_section=$(build_session_continuation_section "$agent_num")" \
    --var "audit_fixed_strategy_clause=$audit_fixed_strategy_clause" \
    --var "wrong_mode_subsystem_line=$wrong_mode_subsystem_line" \
    --var "role_block=$role_block" \
    --var "handoff_directive=$(build_handoff_directive "$agent_num")" \
    --var "work_card_directive=$(build_work_card_directive "$agent_num")" \
    --var "strategy_assignment_line=$(build_strategy_assignment_line "$agent_num")" \
    --var "strategy_roi_directive=$(build_strategy_roi_directive)" \
    --var "find_first_directive=$(build_find_first_directive)" \
    --var "agent_state_instructions=$(build_agent_state_instructions "$agent_num")" \
    --var "common_suffix=$(build_common_suffix)"
}
