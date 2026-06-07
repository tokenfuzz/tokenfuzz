#!/usr/bin/env bash
# lib/quality.sh — Quality gates, orphan detection, enforcement, corpus promotion.
# Sourced by bin/audit.
#
# ── Bash vs Python split ─────────────────────────────────────────────
# Pure file-system classification (which files are testcases? does this
# .asan.txt contain a verifiable run? how many orphan testcases live in
# this scratch dir?) lives in lib/quality.py — one os.scandir pass
# replaces N×grep subprocesses per call. See `python3 lib/quality.py
# --help` for the subcommands.
#
# The bash side keeps the orchestration that depends on the audit
# runtime: NUM_AGENTS / RESULTS_DIR / LOGDIR / INDEX globals, the
# state_file_path / scratch_dir_path / hits_log_path / corpus_dir_root
# helpers defined by bin/audit, and the ASAN_5X_BIN dispatch. Porting
# those would force a subprocess hop per path lookup; the architecture
# keeps the cheap glue cheap.

_quality_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
_QUALITY_PY="$_quality_dir/quality.py"
# Shared crash classifier — keeps the orphan-enforcement CRASH line in
# sync with bin/probe's verdict instead of carrying its own regex.
# shellcheck source=verdict.sh
source "$_quality_dir/verdict.sh"
unset _quality_dir

# ── Counting helpers (Python-backed) ──────────────────────────────

count_verified_asan_runs() {
  local dir="$1"
  [ -d "$dir" ] || { echo 0; return; }
  python3 "$_QUALITY_PY" count-asan-runs "$dir" 2>/dev/null || echo 0
}

testcase_mode_for_file() {
  # Classify $1 as a testcase mode (browser/js/generic) on stdout, or
  # return non-zero if it is not a testcase. Pure pattern + fs check.
  local mode
  mode=$(python3 "$_QUALITY_PY" testcase-mode "$1" 2>/dev/null) || return
  # Match bin/probe's default: JavaScript files exercise the JS shell only
  # for browser targets. Generic targets should run them through [runner].
  if [ "$mode" = "js" ] && [ "${TARGET_IS_BROWSER:-1}" = "0" ]; then
    mode="generic"
  fi
  printf '%s\n' "$mode"
}

list_scratch_testcases() {
  local dir="$1"
  [ -d "$dir" ] || return 0
  python3 "$_QUALITY_PY" list-testcases "$dir" 2>/dev/null
}

count_scratch_input_files() {
  local dir="$1"
  [ -d "$dir" ] || { echo 0; return; }
  python3 "$_QUALITY_PY" count-testcases "$dir" 2>/dev/null || echo 0
}

testcase_has_verified_asan_output() {
  python3 "$_QUALITY_PY" has-verified-asan "$1" 2>/dev/null
}

count_orphan_testcases() {
  local dir="$1"
  [ -d "$dir" ] || { echo 0; return; }
  python3 "$_QUALITY_PY" count-orphans "$dir" 2>/dev/null || echo 0
}

# ── Quality feedback loop ─────────────────────────────────────────

check_agent_quality() {
  local agent_num="$1"
  local state_file
  state_file=$(state_file_path "$agent_num")
  local feedback=""

  [ -f "$state_file" ] || structured_state_agent_has_rows "$agent_num" 2>/dev/null || return 0

  local discarded=0 total=0 needs_tc=0 asan_runs=0 crash_count=0 pending=0 tc_count=0
  local _act_unused=0 _env_unused=0 investigating=0
  if structured_state_agent_counts_load "$agent_num" \
       pending _act_unused discarded _env_unused needs_tc crash_count investigating 2>/dev/null; then
    # `total` keeps its legacy exact-match semantics — see structured_state.sh
    # (^(CRASH|CRASH-|FIND|FIND-)$ excludes CRASH-DEDUPED etc., unlike the
    # prefix-match used for `result`). Preserve exact behavior so the
    # depth-required gate stays calibrated to its historical values.
    total=$(structured_state_count_agent_status_regex "$agent_num" '^(PENDING|INVESTIGATING|NEEDS_TESTCASE|DISCARDED|CRASH|CRASH-|FIND|FIND-|ENV-BLOCKED)$' 2>/dev/null || echo 0)
  elif [ -f "$state_file" ]; then
    discarded=$(grep -c "DISCARDED" "$state_file" 2>/dev/null) || true
    needs_tc=$(grep -c "NEEDS_TESTCASE" "$state_file" 2>/dev/null) || true
    pending=$(grep -c "PENDING" "$state_file" 2>/dev/null) || true
    crash_count=$(grep -cE "CRASH-|FIND-" "$state_file" 2>/dev/null) || true
    total=$(grep -cE "PENDING|INVESTIGATING|NEEDS_TESTCASE|DISCARDED|CRASH-|FIND-|ENV-BLOCKED" "$state_file" 2>/dev/null) || true
    investigating=$(grep -c "INVESTIGATING" "$state_file" 2>/dev/null) || true
  fi
  discarded=${discarded:-0}; needs_tc=${needs_tc:-0}; total=${total:-0}
  pending=${pending:-0}; crash_count=${crash_count:-0}; investigating=${investigating:-0}

  asan_runs=0; tc_count=0
  if [ -d "$(scratch_dir_path "$agent_num")" ]; then
    asan_runs=$(count_verified_asan_runs "$(scratch_dir_path "$agent_num")")
    tc_count=$(count_scratch_input_files "$(scratch_dir_path "$agent_num")")
  fi

  feedback+="**Stats:** ${discarded} discarded, ${pending} pending, ${crash_count} findings, ${tc_count} testcases, ${asan_runs} ASan runs.\n"

  # Gate 1: Discarding without reproducing
  if [ "$discarded" -gt 3 ] && [ "$asan_runs" -lt 2 ]; then
    feedback+="**REPRODUCE FIRST:** ${discarded} DISCARDED but only ${asan_runs} ASan runs. Pick your best DISCARDED hypothesis, write a testcase in the first 10 tool calls, run ASan, try 3+ variants. No new hypotheses until you have ASan evidence.\n"
  fi

  # Gate 2: Surveying without depth (investigating already loaded above)
  local actionable=$((needs_tc + ${investigating:-0}))
  if [ "$total" -gt 5 ] && [ "$actionable" -eq 0 ]; then
    feedback+="**DEPTH REQUIRED:** ${total} hypotheses, 0 at testcase stage. Write and run a testcase within your first 15 tool calls. No new hypotheses until ASan runs.\n"
  fi

  # Gate 3: Orphan testcases
  local orphan_count=0
  if [ -d "$(scratch_dir_path "$agent_num")" ]; then
    orphan_count=$(count_orphan_testcases "$(scratch_dir_path "$agent_num")")
  fi
  if [ "${orphan_count:-0}" -ge 3 ]; then
    feedback+="**ORPHAN GATE:** ${orphan_count} testcase(s) have no .asan.txt. Run ASan on every existing testcase before writing new ones.\n"
  fi

  # Gate 4: Reproduce agent with zero ASan runs in prior session
  local prev_asan_file="$LOGDIR/.prev_asan_runs_${agent_num}"
  if [ -f "$prev_asan_file" ]; then
    local prev_asan_count
    prev_asan_count=$(cat "$prev_asan_file" 2>/dev/null || echo 0)
    local agent_role_val
    agent_role_val=$(agent_role "$agent_num" 2>/dev/null || echo "")
    if [ "$agent_role_val" = "reproduce" ] && [ "${prev_asan_count:-0}" -eq 0 ]; then
      feedback+="**ZERO-ASAN GATE:** Your prior session produced 0 ASan runs. Prioritize writing and running testcases early this session.\n"
    fi
  fi

  # Gate 5: NO_EXEC epidemic — testcases that hit coverage but don't actually run
  local tried_log
  tried_log=$(tried_inputs_log_path "$agent_num")
  if [ -f "$tried_log" ]; then
    local no_exec_count total_tried
    no_exec_count=$(grep -c 'verdict=NO_EXEC' "$tried_log" 2>/dev/null) || true
    total_tried=$(wc -l < "$tried_log" 2>/dev/null | tr -d ' ') || true
    no_exec_count=${no_exec_count:-0}; total_tried=${total_tried:-0}
    if [ "$no_exec_count" -gt 5 ] && [ "$total_tried" -gt 0 ]; then
      local no_exec_pct=$(( no_exec_count * 100 / total_tried ))
      if [ "$no_exec_pct" -ge 40 ]; then
        feedback+="**NO_EXEC ALERT:** ${no_exec_count}/${total_tried} (${no_exec_pct}%) of your testcases hit the target function but did NOT execute to completion. Your JS testcases likely have early exceptions, syntax errors, or uncaught throws. **Fix:** add \`print('TESTCASE_EXECUTED')\` at the end, wrap in try/catch to catch silent failures, and verify the testcase prints its sentinel before spending ASan budget.\n"
      fi
    fi
  fi

  echo -e "$feedback"
}

snapshot_quality_feedback() {
  for i in $(seq 1 "$NUM_AGENTS"); do
    check_agent_quality "$i" > "$(quality_feedback_path "$i")" 2>/dev/null || true
  done
}

# ── Orphan testcase warning ───────────────────────────────────────

warn_orphan_testcases() {
  for i in $(seq 1 "$NUM_AGENTS"); do
    local d
    d=$(scratch_dir_path "$i")
    [ -d "$d" ] || continue
    local tc_count asan_count orphan_count
    tc_count=$(count_scratch_input_files "$d")
    asan_count=$(count_verified_asan_runs "$d")
    orphan_count=$(count_orphan_testcases "$d")
    if [ "${tc_count:-0}" -gt 0 ] && [ "${orphan_count:-0}" -eq "${tc_count:-0}" ]; then
      audit_log "WARN: agent ${i} has ${tc_count} testcase(s) but 0 verified ASan outputs — all orphan!" | tee -a "$INDEX"
    elif [ "${orphan_count:-0}" -ge 3 ]; then
      audit_log "WARN: agent ${i} has ${orphan_count} unverified testcase(s) (${asan_count} verified)" | tee -a "$INDEX"
    fi
  done
}

# ── Enforcement pass (auto-run ASan on orphans) ──────────────────
# Also saves results to .enforcement_results_<agent>.md for prompt injection.

enforce_asan_for_orphans() {
  local asan_5x="${ASAN_5X_BIN:-bin/run-asan-multi}"
  [ -x "$asan_5x" ] || return 0
  local enforced=0
  local max_auto_runs="${ASAN_AUTOENFORCE_MAX:-3}"
  local auto_runs="${ASAN_AUTOENFORCE_RUNS:-1}"

  # Clear prior enforcement results
  for i in $(seq 1 "$NUM_AGENTS"); do
    : > "$RESULTS_DIR/.enforcement_results_${i}" 2>/dev/null || true
  done

  for i in $(seq 1 "$NUM_AGENTS"); do
    local d
    d=$(scratch_dir_path "$i")
    [ -d "$d" ] || continue
    local f
    while IFS= read -r -d '' f; do
      [ "$enforced" -ge "$max_auto_runs" ] && break 2
      local base="${f%.*}" stem="${f##*/}"
      [ -s "$f" ] || continue
      testcase_has_verified_asan_output "$f" && continue
      [ -f "${base}.enforced" ] && continue
      local mode
      mode=$(testcase_mode_for_file "$f" 2>/dev/null) || continue
      audit_log "enforce: running ASan 5x on orphan $stem (${enforced}/${max_auto_runs})" | tee -a "$INDEX"
      ASAN_RUNS="$auto_runs" ASAN_OUTPUT_FILE="${base}.asan.txt" ASAN_TIMEOUT="${ASAN_AUTOENFORCE_TIMEOUT:-30}" SKIP_COVERAGE_GATE=1 \
        "$asan_5x" "$mode" "$f" >/dev/null 2>&1 || true
      if grep -qE 'ASAN_RUN_HEADER:|CRASH_RATE:|EXECUTION_RATE:|\[run-asan\] CRASH DETECTED|\[run-asan\] (browser|js|js-diff|xpcshell|generic)? ?EXECUTION VERIFIED|ERROR: AddressSanitizer' "${base}.asan.txt" 2>/dev/null; then
        touch "${base}.enforced"
      fi
      enforced=$((enforced + 1))

      # Record enforcement result for prompt injection (task #5).
      # Crash detection uses the shared lib/verdict.sh classifier so a Go
      # race / Rust panic / SEGV in an orphan testcase is not silently
      # recorded as CLEAN; crash_class stays ASan-specific (empty → the
      # "unknown class" fallback) since only ASan prints a typed label.
      local result_line=""
      if verdict_file_has_crash "${base}.asan.txt"; then
        local crash_class
        crash_class=$(grep -oE 'AddressSanitizer: [a-z-]+' "${base}.asan.txt" 2>/dev/null | head -1 | sed 's/AddressSanitizer: //')
        result_line="- **CRASH** \`${stem}\` → ${crash_class:-unknown class}"
      elif verdict_file_is_clean "${base}.asan.txt"; then
        result_line="- CLEAN \`${stem}\` — executed without sanitizer diagnostic"
      elif grep -qE 'EXECUTION_RATE: [1-9]' "${base}.asan.txt" 2>/dev/null; then
        result_line="- EXEC_FAIL \`${stem}\` — testcase reached the runner but exited non-zero"
      else
        result_line="- NO_EXEC \`${stem}\` — testcase did not execute"
      fi
      echo "$result_line" >> "$RESULTS_DIR/.enforcement_results_${i}" 2>/dev/null || true

    done < <(list_scratch_testcases "$d")
  done
  [ "$enforced" -gt 0 ] && audit_log "enforce: ran ASan on ${enforced} orphan testcase(s)" | tee -a "$INDEX"
  return 0
}

# Build a prompt fragment showing enforcement results from the prior iteration.
# Returns empty string if no results. Called by prompt builders.
build_enforcement_results_directive() {
  local agent_num="$1"
  local results_file="$RESULTS_DIR/.enforcement_results_${agent_num}"
  [ -f "$results_file" ] && [ -s "$results_file" ] || return 0

  local crash_lines
  crash_lines=$(grep -c '^\- \*\*CRASH\*\*' "$results_file" 2>/dev/null || true)

  if [ "${crash_lines:-0}" -gt 0 ]; then
    cat <<EOF

## ENFORCEMENT RESULTS — INVESTIGATE CRASHES FIRST

The harness auto-ran ASan on your orphan testcases from the prior session.
**${crash_lines} crashed — investigate these BEFORE starting new hypotheses:**

$(cat "$results_file")

For each CRASH: read the .asan.txt, check if it's a real memory-safety issue (not null-deref/OOM/MOZ_CRASH), and if so promote to \`${RESULTS_DIR}/crashes/CRASH-NNN-${agent_num}/\` (absolute — a bare \`crashes/\` resolves against your current cwd, which may have drifted after a \`cd\`).
EOF
  else
    cat <<EOF

## ENFORCEMENT RESULTS (prior session orphans — all clean)

$(cat "$results_file")
EOF
  fi
}

# ── Corpus promotion ─────────────────────────────────────────────

promote_corpus_testcases() {
  local corpus_root
  corpus_root=$(corpus_dir_root)
  mkdir -p "$corpus_root" 2>/dev/null || true

  local promoted=0 skipped_no_asan=0 skipped_crashing=0 skipped_no_header=0
  local skipped_no_new_edges=0

  for i in $(seq 1 "$NUM_AGENTS"); do
    local d hits_log
    d=$(scratch_dir_path "$i")
    hits_log=$(hits_log_path "$i")
    [ -d "$d" ] || continue
    [ -f "$hits_log" ] || continue

    # One Python invocation per agent: walks hits_log, copies promotable
    # testcases + their .asan.txt into COVER-NNN-<i>/ under corpus_root,
    # writes metadata.md, and prints a single tally line we sum below.
    local tally
    tally=$(python3 "$_QUALITY_PY" promote-corpus "$hits_log" "$d" "$corpus_root" "$i" 2>/dev/null) || continue
    local agent_promoted agent_no_asan agent_crashing agent_no_header agent_no_new
    agent_promoted=$(printf '%s' "$tally" | sed -nE 's/.*\bpromoted=([0-9]+).*/\1/p')
    agent_no_asan=$(printf '%s' "$tally" | sed -nE 's/.*\bskipped_no_asan=([0-9]+).*/\1/p')
    agent_crashing=$(printf '%s' "$tally" | sed -nE 's/.*\bskipped_crashing=([0-9]+).*/\1/p')
    agent_no_header=$(printf '%s' "$tally" | sed -nE 's/.*\bskipped_no_header=([0-9]+).*/\1/p')
    agent_no_new=$(printf '%s' "$tally" | sed -nE 's/.*\bskipped_no_new_edges=([0-9]+).*/\1/p')
    promoted=$(( promoted + ${agent_promoted:-0} ))
    skipped_no_asan=$(( skipped_no_asan + ${agent_no_asan:-0} ))
    skipped_crashing=$(( skipped_crashing + ${agent_crashing:-0} ))
    skipped_no_header=$(( skipped_no_header + ${agent_no_header:-0} ))
    skipped_no_new_edges=$(( skipped_no_new_edges + ${agent_no_new:-0} ))
  done

  # Regenerate INDEX (Python rebuilds the table from each COVER-*/metadata.md).
  python3 "$_QUALITY_PY" regenerate-corpus-index "$corpus_root" 2>/dev/null || true

  [ "$promoted" -gt 0 ] && audit_log "corpus: promoted ${promoted} new coverage testcase(s) → ${corpus_root}" | tee -a "$INDEX"
  if [ "$promoted" -eq 0 ] && [ $((skipped_no_asan + skipped_crashing + skipped_no_header + ${skipped_no_new_edges:-0})) -gt 0 ]; then
    audit_log "corpus: 0 testcases promoted this iteration — skipped ${skipped_no_asan} without ASan output, ${skipped_crashing} that crash, ${skipped_no_header} missing required header, ${skipped_no_new_edges:-0} that didn't add new coverage edges" | tee -a "$INDEX"
  fi
  return 0
}
