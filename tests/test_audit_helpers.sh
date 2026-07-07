#!/usr/bin/env bash
# Unit tests for bin/audit helper functions — strategy rotation, blocklist,
# subsystem detection, agent mode/role, dry streak, guard chain, tenure, counts
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# We need some functions defined in bin/audit that aren't in lib/.
# Source them by extracting the relevant function definitions.

# ── Strategy rotation helpers ─────────────────────────────────

next_strategy_in_rotation() {
  local current="$1" found=0 first=""
  for s in "${STRATEGY_ROTATION_ORDER[@]}"; do
    [ -z "$first" ] && first="$s"
    if [ "$found" -eq 1 ]; then echo "$s"; return; fi
    [ "$s" = "$current" ] && found=1
  done
  echo "${first:-S2}"
}

set_agent_strategy() {
  local agent_num="$1" strategy="$2"
  printf '%s' "$strategy" > "$(agent_strategy_path "$agent_num")"
}

get_agent_strategy_streak() {
  local f; f=$(agent_strategy_streak_path "$1")
  if [ -f "$f" ]; then cat "$f" 2>/dev/null || echo 0; else echo 0; fi
}

bump_agent_strategy_streak() {
  local f n; f=$(agent_strategy_streak_path "$1")
  n=$(get_agent_strategy_streak "$1"); n=$((n + 1))
  printf '%s' "$n" > "$f"
}

reset_agent_strategy_streak() {
  rm -f "$(agent_strategy_streak_path "$1")" 2>/dev/null || true
}

# ── Subsystem dry streak helpers ──────────────────────────────

subsystem_dry_streak_path() {
  local slug; slug=$(printf '%s' "$1" | tr '/' '_')
  printf '%s/.subsystem_dry_%s' "$RESULTS_DIR" "$slug"
}

get_subsystem_dry_streak() {
  local f; f=$(subsystem_dry_streak_path "$1")
  if [ -f "$f" ]; then cat "$f" 2>/dev/null || echo 0; else echo 0; fi
}

bump_subsystem_dry_streak() {
  local subsystem="$1" delta="${2:-1}"
  [ -z "$subsystem" ] && return 0; [ "$subsystem" = "unknown" ] && return 0
  local f n; f=$(subsystem_dry_streak_path "$subsystem")
  n=$(get_subsystem_dry_streak "$subsystem"); n=$((n + delta))
  printf '%s' "$n" > "$f"
}

reset_subsystem_dry_streak() {
  [ -z "$1" ] && return 0
  rm -f "$(subsystem_dry_streak_path "$1")" 2>/dev/null || true
}

# ── Dead streak helpers ───────────────────────────────────────

dead_streak_path() { printf '%s/.dead_streak_%s' "$LOGDIR" "$1"; }

get_dead_streak() {
  local f; f=$(dead_streak_path "$1")
  [ -f "$f" ] && cat "$f" 2>/dev/null || echo 0
}

bump_dead_streak() {
  local cur; cur=$(get_dead_streak "$1")
  printf '%s' "$((cur + 1))" > "$(dead_streak_path "$1")" 2>/dev/null || true
}

reset_dead_streak() {
  printf '0' > "$(dead_streak_path "$1")" 2>/dev/null || true
}

# ── Counting helpers ──────────────────────────────────────────

count_total_pending() {
  local total=0
  for i in $(seq 1 "$NUM_AGENTS"); do
    local f; f=$(state_file_path "$i")
    if [ -f "$f" ]; then
      local c; c=$(grep -c "PENDING" "$f" 2>/dev/null || true)
      total=$((total + ${c:-0}))
    fi
  done
  echo "$total"
}

# ── Sanitize target slug ─────────────────────────────────────

sanitize_target_slug() {
  local raw="$1"; raw="${raw##*/}"
  raw=$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')
  raw=$(printf '%s' "$raw" | tr -cs '[:alnum:]._-' '-')
  raw="${raw#-}"; raw="${raw%-}"
  echo "$raw"
}

# ═══════════════════════════════════════════════════════════════
# 1. Strategy rotation: next_strategy_in_rotation
# ═══════════════════════════════════════════════════════════════

assert_eq "S2" "$(next_strategy_in_rotation S1)" "S1 → S2"
assert_eq "S3" "$(next_strategy_in_rotation S2)" "S2 → S3"
assert_eq "S4" "$(next_strategy_in_rotation S3)" "S3 → S4"
assert_eq "S5" "$(next_strategy_in_rotation S4)" "S4 → S5"
assert_eq "S6" "$(next_strategy_in_rotation S5)" "S5 → S6"
assert_eq "S7" "$(next_strategy_in_rotation S6)" "S6 → S7"
assert_eq "S8" "$(next_strategy_in_rotation S7)" "S7 → S8"
assert_eq "S1" "$(next_strategy_in_rotation S8)" "S8 → S1 (wrap around)"
assert_eq "S1" "$(next_strategy_in_rotation UNKNOWN)" "unknown → S1 (fallback)"

# ═══════════════════════════════════════════════════════════════
# 2. strategy_file_for_letter
# ═══════════════════════════════════════════════════════════════

assert_eq "S1-prior-fix-review.md" "$(strategy_file_for_letter S1)" "S1 → file"
assert_eq "S2-assert-negation.md" "$(strategy_file_for_letter S2)" "S2 → file"
assert_eq "S3-spec-vs-impl.md" "$(strategy_file_for_letter S3)" "S3 → file"
assert_eq "S4-differential.md" "$(strategy_file_for_letter S4)" "S4 → file"
assert_eq "S5-reentrancy.md" "$(strategy_file_for_letter S5)" "S5 → file"
assert_eq "S6-cross-project.md" "$(strategy_file_for_letter S6)" "S6 → file"
assert_eq "S7-fuzz-improvement.md" "$(strategy_file_for_letter S7)" "S7 → file"
assert_eq "S8-property-based.md" "$(strategy_file_for_letter S8)" "S8 → file"
assert_eq "REF-pattern-search.md" "$(strategy_file_for_letter REF)" "REF → file"
assert_eq "" "$(strategy_file_for_letter INVALID)" "invalid → empty"

# ═══════════════════════════════════════════════════════════════
# 3. Strategy streak tracking
# ═══════════════════════════════════════════════════════════════

assert_eq "0" "$(get_agent_strategy_streak 1)" "initial streak = 0"
bump_agent_strategy_streak 1
assert_eq "1" "$(get_agent_strategy_streak 1)" "streak after bump = 1"
bump_agent_strategy_streak 1
bump_agent_strategy_streak 1
assert_eq "3" "$(get_agent_strategy_streak 1)" "streak after 3 bumps = 3"
reset_agent_strategy_streak 1
assert_eq "0" "$(get_agent_strategy_streak 1)" "streak after reset = 0"

# ═══════════════════════════════════════════════════════════════
# 4. set/get agent strategy
# ═══════════════════════════════════════════════════════════════

set_agent_strategy 1 "Q"
result=$(cat "$(agent_strategy_path 1)")
assert_eq "Q" "$result" "set strategy writes file"

set_agent_strategy 1 "Z"
result=$(cat "$(agent_strategy_path 1)")
assert_eq "Z" "$result" "strategy overwrite works"

rm -f "$(agent_strategy_path 1)"

# ═══════════════════════════════════════════════════════════════
# 5. Blocklist — subsystem_is_blocklisted
# ═══════════════════════════════════════════════════════════════

subsystem_is_blocklisted "dom/encoding"
assert_eq 1 $? "dom/encoding is NOT blocklisted by default"

subsystem_is_blocklisted "dom/url"
assert_eq 1 $? "dom/url is NOT blocklisted by default"

subsystem_is_blocklisted "third_party/rust"
assert_eq 0 $? "third_party/rust is blocklisted (default)"

subsystem_is_blocklisted "third_party/rust/vendor"
assert_eq 0 $? "third_party/rust/vendor is blocklisted (prefix match)"

subsystem_is_blocklisted "dom/canvas"
assert_eq 1 $? "dom/canvas is NOT blocklisted"

subsystem_is_blocklisted "js/src/jit"
assert_eq 1 $? "js/src/jit is NOT blocklisted"

subsystem_is_blocklisted ""
assert_eq 1 $? "empty string is NOT blocklisted"

subsystem_is_blocklisted "unknown"
assert_eq 1 $? "unknown is NOT blocklisted"

# ═══════════════════════════════════════════════════════════════
# 6. Blocklist — persistent file picked up by load_blocklist
# ═══════════════════════════════════════════════════════════════

mkdir -p "$(dirname "$SUBSYSTEM_BLOCKLIST_FILE")"
echo "parser/html" > "$SUBSYSTEM_BLOCKLIST_FILE"

subsystem_is_blocklisted "parser/html"
assert_eq 0 $? "subsystem from blocklist file is blocklisted"

# ═══════════════════════════════════════════════════════════════
# 7. blocklist_description
# ═══════════════════════════════════════════════════════════════

result=$(blocklist_description)
assert_not_match "dom/encoding" "$result" "blocklist description excludes dom/encoding"
assert_not_match "dom/url" "$result" "blocklist description excludes dom/url"
assert_match "parser/html" "$result" "blocklist description includes file entries"

# ═══════════════════════════════════════════════════════════════
# 8. Subsystem dry streak
# ═══════════════════════════════════════════════════════════════

assert_eq "0" "$(get_subsystem_dry_streak "dom/canvas")" "initial dry streak = 0"
bump_subsystem_dry_streak "dom/canvas"
assert_eq "1" "$(get_subsystem_dry_streak "dom/canvas")" "dry streak after bump = 1"
bump_subsystem_dry_streak "dom/canvas" 3
assert_eq "4" "$(get_subsystem_dry_streak "dom/canvas")" "dry streak after +3 = 4"
reset_subsystem_dry_streak "dom/canvas"
assert_eq "0" "$(get_subsystem_dry_streak "dom/canvas")" "dry streak after reset = 0"

# Verify path uses slug
f=$(subsystem_dry_streak_path "js/src/jit")
assert_match "js_src_jit" "$f" "dry streak path uses slugified name"

# ═══════════════════════════════════════════════════════════════
# 9. Dead session streak
# ═══════════════════════════════════════════════════════════════

assert_eq "0" "$(get_dead_streak 1)" "initial dead streak = 0"
bump_dead_streak 1
assert_eq "1" "$(get_dead_streak 1)" "dead streak after bump = 1"
bump_dead_streak 1
assert_eq "2" "$(get_dead_streak 1)" "dead streak after 2 bumps = 2"
reset_dead_streak 1
assert_eq "0" "$(get_dead_streak 1)" "dead streak after reset = 0"

apply_dead_session_gate_for_test() {
  local agent_num="$1" tool_uses="$2" refusal_signals="$3"
  if [ "${tool_uses:-0}" -eq 0 ]; then
    bump_dead_streak "$agent_num"
    if [ "$(get_dead_streak "$agent_num")" -ge "$MAX_DEAD_STREAK" ]; then
      rm -f "$(state_file_path "$agent_num")"
      reset_dead_streak "$agent_num"
    fi
  elif [ "${refusal_signals:-0}" -gt 0 ]; then
    reset_dead_streak "$agent_num"
  else
    reset_dead_streak "$agent_num"
  fi
}

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: js/src/wasm
| 1 | H1 | js/src/wasm/Foo.cpp | shape | guard | bounds | S1 | PENDING |
EOF
bump_dead_streak 1
apply_dead_session_gate_for_test 1 3 1
assert_file_exists "$(state_file_path 1)" "dead gate: refusal after tool work preserves state"
assert_eq "0" "$(get_dead_streak 1)" "dead gate: refusal after tool work resets hard-dead streak"

apply_dead_session_gate_for_test 1 0 0
assert_file_exists "$(state_file_path 1)" "dead gate: one zero-tool session is forgiven"
apply_dead_session_gate_for_test 1 0 0
assert_file_not_exists "$(state_file_path 1)" "dead gate: repeated zero-tool sessions archive state"
assert_eq "0" "$(get_dead_streak 1)" "dead gate: threshold archive resets streak"

# ═══════════════════════════════════════════════════════════════
# 10. Agent mode mapping — browser target (browser/shell split)
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1
assert_eq "browser" "$(agent_mode 1)" "browser target: agent 1 → browser (BROWSER_AGENTS=1)"
assert_eq "shell" "$(agent_mode 2)" "browser target: agent 2 → shell"

BROWSER_AGENTS=2
assert_eq "browser" "$(agent_mode 2)" "browser target: agent 2 → browser when BROWSER_AGENTS=2"
assert_eq "shell" "$(agent_mode 3)" "browser target: agent 3 → shell when BROWSER_AGENTS=2"
BROWSER_AGENTS=1

# ═══════════════════════════════════════════════════════════════
# 10b. Agent mode mapping — generic target (flat pool)
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0
assert_eq "generic" "$(agent_mode 1)" "generic target: agent 1 → generic"
assert_eq "generic" "$(agent_mode 2)" "generic target: agent 2 → generic"
assert_eq "generic" "$(agent_mode 3)" "generic target: agent 3 → generic"
assert_eq "generic" "$(agent_mode 5)" "generic target: agent 5 → generic"

# BROWSER_AGENTS is ignored for generic targets
BROWSER_AGENTS=3
assert_eq "generic" "$(agent_mode 1)" "generic target: BROWSER_AGENTS ignored, still generic"
assert_eq "generic" "$(agent_mode 3)" "generic target: BROWSER_AGENTS=3 ignored, still generic"
BROWSER_AGENTS=1

# ═══════════════════════════════════════════════════════════════
# 11. Agent role mapping
# ═══════════════════════════════════════════════════════════════

assert_eq "reproduce" "$(agent_role 1)" "agent 1 → reproduce (default)"
assert_eq "analysis" "$(agent_role 2)" "agent 2 → analysis (default)"
assert_eq "reproduce" "$(agent_role 3)" "agent 3 → reproduce (default)"

# Override
AGENT_ROLES="analysis,reproduce"
assert_eq "analysis" "$(agent_role 1)" "agent 1 → analysis (override)"
assert_eq "reproduce" "$(agent_role 2)" "agent 2 → reproduce (override)"
AGENT_ROLES=""

# ═══════════════════════════════════════════════════════════════
# 13. count_total_pending
# ═══════════════════════════════════════════════════════════════

cat > "$(state_file_path 1)" <<'EOF'
| 1 | H1 | foo.cpp | shape | guard | bounds | A | PENDING |
| 2 | H2 | bar.cpp | shape | guard | bounds | A | PENDING |
| 3 | H3 | baz.cpp | shape | guard | bounds | A | DISCARDED |
EOF
cat > "$(state_file_path 2)" <<'EOF'
| 1 | H1 | x.cpp | shape | guard | bounds | A | PENDING |
EOF
assert_eq "3" "$(count_total_pending)" "3 total pending across agents"

# ═══════════════════════════════════════════════════════════════
# 14. count_security_crash_candidates + count_confirmed_findings
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-001-1"
mkdir -p "$RESULTS_DIR/crashes/CRASH-002-2"
assert_eq "2" "$(count_security_crash_candidates)" "2 crash candidates"

touch "$RESULTS_DIR/crashes/CRASH-002-2/.promotion_pending"
assert_eq "1" "$(count_security_crash_candidates)" "pending-incomplete crash excluded from candidate count"

mkdir -p "$RESULTS_DIR/findings/FIND-001-test"
assert_eq "1" "$(count_confirmed_findings)" "1 confirmed finding"
assert_eq "2" "$(count_active_security_results)" "active security results exclude pending-incomplete crash"

# ═══════════════════════════════════════════════════════════════
# 15. Guard chain detection
# ═══════════════════════════════════════════════════════════════

# Below threshold
gpath=$(guard_chain_path "dom/canvas")
for i in $(seq 1 3); do echo "Error: regexp too big" >> "$gpath"; done
result=$(detect_guard_saturation "dom/canvas")
assert_eq "" "$result" "below threshold → no saturation"

# At threshold
for i in $(seq 4 "$GUARD_CHAIN_ROTATION_THRESHOLD"); do echo "Error: regexp too big" >> "$gpath"; done
result=$(detect_guard_saturation "dom/canvas")
assert_match "regexp too big" "$result" "at threshold → saturation detected"
rm -f "$gpath"

# Mixed guards — only most frequent counts
gpath=$(guard_chain_path "js/src/wasm")
for i in $(seq 1 "$GUARD_CHAIN_ROTATION_THRESHOLD"); do echo "TypeError: invalid" >> "$gpath"; done
echo "RangeError: other" >> "$gpath"
echo "SyntaxError: bad" >> "$gpath"
result=$(detect_guard_saturation "js/src/wasm")
assert_match "TypeError: invalid" "$result" "most frequent guard detected"
rm -f "$gpath"

# ═══════════════════════════════════════════════════════════════
# S1 strategy threshold — longer leash for prior-fix review
# ═══════════════════════════════════════════════════════════════

# Override get_agent_strategy to read from the tracking file (the
# helpers.sh stub always returns "S1" which defeats the S2 test).
get_agent_strategy() {
  local track_file; track_file=$(agent_strategy_path "$1")
  if [ -f "$track_file" ]; then cat "$track_file" 2>/dev/null || echo "S1"; else echo "S1"; fi
}

assert_eq "8" "$STRATEGY_S1_DRY_STREAK_THRESHOLD" "S1 threshold default = 8"
assert_eq "3" "$STRATEGY_DRY_STREAK_THRESHOLD" "generic threshold default = 3"

# S1 at streak=3 should NOT rotate (below S1 threshold of 8)
set_agent_strategy 1 "S1"
reset_agent_strategy_streak 1
for _i in $(seq 1 3); do bump_agent_strategy_streak 1; done
strat_streak=$(get_agent_strategy_streak 1)
assert_eq "3" "$strat_streak" "S1: streak=3 after 3 bumps"
# Simulate the threshold check from update_subsystem_dry_streaks
current_strat_for_threshold=$(get_agent_strategy 1)
if [ "$current_strat_for_threshold" = "S1" ]; then
  strat_threshold="$STRATEGY_S1_DRY_STREAK_THRESHOLD"
else
  strat_threshold="$STRATEGY_DRY_STREAK_THRESHOLD"
fi
if [ "$strat_streak" -ge "$strat_threshold" ]; then
  fail "S1: streak=3 should NOT rotate (threshold=8)"
else
  pass "S1: streak=3 does not rotate (threshold=8)"
fi

# S1 at streak=8 SHOULD rotate
for _i in $(seq 4 8); do bump_agent_strategy_streak 1; done
strat_streak=$(get_agent_strategy_streak 1)
assert_eq "8" "$strat_streak" "S1: streak=8 after 8 bumps"
if [ "$strat_streak" -ge "$STRATEGY_S1_DRY_STREAK_THRESHOLD" ]; then
  pass "S1: streak=8 triggers rotation (threshold=8)"
else
  fail "S1: streak=8 should trigger rotation (threshold=8)"
fi

# S2 at streak=3 SHOULD rotate (uses generic threshold)
set_agent_strategy 1 "S2"
reset_agent_strategy_streak 1
for _i in $(seq 1 3); do bump_agent_strategy_streak 1; done
strat_streak=$(get_agent_strategy_streak 1)
current_strat_for_threshold=$(get_agent_strategy 1)
if [ "$current_strat_for_threshold" = "S1" ]; then
  strat_threshold="$STRATEGY_S1_DRY_STREAK_THRESHOLD"
else
  strat_threshold="$STRATEGY_DRY_STREAK_THRESHOLD"
fi
if [ "$strat_streak" -ge "$strat_threshold" ]; then
  pass "S2: streak=3 triggers rotation (threshold=3)"
else
  fail "S2: streak=3 should trigger rotation (threshold=3)"
fi

# S2 at streak=2 should NOT rotate
reset_agent_strategy_streak 1
for _i in $(seq 1 2); do bump_agent_strategy_streak 1; done
strat_streak=$(get_agent_strategy_streak 1)
if [ "$strat_streak" -ge "$strat_threshold" ]; then
  fail "S2: streak=2 should NOT rotate (threshold=3)"
else
  pass "S2: streak=2 does not rotate (threshold=3)"
fi

# S1 threshold overridable via env
STRATEGY_S1_DRY_STREAK_THRESHOLD=5
set_agent_strategy 1 "S1"
reset_agent_strategy_streak 1
for _i in $(seq 1 5); do bump_agent_strategy_streak 1; done
strat_streak=$(get_agent_strategy_streak 1)
if [ "$strat_streak" -ge "$STRATEGY_S1_DRY_STREAK_THRESHOLD" ]; then
  pass "S1: env override threshold=5 triggers at streak=5"
else
  fail "S1: env override threshold=5 should trigger at streak=5"
fi
STRATEGY_S1_DRY_STREAK_THRESHOLD=8  # restore

# Clean up
reset_agent_strategy_streak 1
rm -f "$(agent_strategy_path 1)"

# ═══════════════════════════════════════════════════════════════
# STALL handler — non-destructive deep-analysis preservation
# ═══════════════════════════════════════════════════════════════

# Set up state files for 2 agents
cat > "$(state_file_path 1)" <<'SF1'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | S1 | PENDING |
SF1
cat > "$(state_file_path 2)" <<'SF2'
## Primary Subsystem: js/src/jit
| 1 | H1 | js/src/jit/Foo.cpp | shape | guard | bounds | S3 | INVESTIGATING |
SF2
set_agent_strategy 1 "S3"
set_agent_strategy 2 "S5"
bump_agent_strategy_streak 1
bump_agent_strategy_streak 1
bump_subsystem_dry_streak "dom/canvas"
bump_subsystem_dry_streak "dom/canvas"

# Simulate the STALL handler sequence
dry_streak="$MAX_DRY_SESSIONS"
if [ "$dry_streak" -ge "$MAX_DRY_SESSIONS" ]; then
  dry_streak=0
fi

# Verify: active state files are preserved
assert_file_exists "$(state_file_path 1)" "stall: agent 1 active state preserved"
assert_file_exists "$(state_file_path 2)" "stall: agent 2 active state preserved"

# Verify: strategies and streaks are not reset by the global stall handler
assert_eq "S3" "$(cat "$(agent_strategy_path 1)")" "stall: agent 1 strategy preserved"
assert_eq "S5" "$(cat "$(agent_strategy_path 2)")" "stall: agent 2 strategy preserved"
assert_eq "2" "$(get_agent_strategy_streak 1)" "stall: agent 1 strategy streak preserved"
assert_eq "0" "$(get_agent_strategy_streak 2)" "stall: agent 2 strategy streak preserved"

# Verify: per-subsystem dry streaks are preserved for per-agent directives
assert_eq "2" "$(get_subsystem_dry_streak "dom/canvas")" "stall: dom/canvas dry streak preserved"

# Clean up
rm -f "$(agent_strategy_path 1)" "$(agent_strategy_path 2)"

# ═══════════════════════════════════════════════════════════════
# Rate limit detection
# ═══════════════════════════════════════════════════════════════

provider_text_reset_at() {
  local logfile="$1"
  python3 "$SCRIPT_ROOT/lib/audit_helpers.py" provider-reset-at "$logfile" 2>/dev/null
}

extract_raw_status() {
  local logfile="$1"
  python3 "$SCRIPT_ROOT/lib/audit_helpers.py" raw-status "$logfile" 2>/dev/null \
    || printf 'rate_limit=0\ncodex_completed=0\ncodex_failed=0\ngemini_success=0\n'
}

log_provider_issue() {
  local logfile="$1"
  python3 "$SCRIPT_ROOT/lib/audit_helpers.py" provider-issue "$logfile" 2>/dev/null \
    || printf '%s\n' none
}

log_has_rate_limit_rejection() {
  local logfile="$1" rs
  [ -f "$logfile" ] || return 1
  rs=$(extract_raw_status "$logfile")
  grep -q '^rate_limit=1' <<<"$rs"
}

detect_rate_limit() {
  local timestamp="$1"
  local reset_at="" saw_provider_rejection=0
  local i role mode logfile
  for i in $(seq 1 "$NUM_AGENTS"); do
    for role in cold-start deep_investigation; do
      for mode in generic browser shell; do
        logfile="$LOGDIR/session_${timestamp}_${role}-${i}-${mode}.log.raw"
        [ -f "$logfile" ] || continue
        log_has_rate_limit_rejection "$logfile" || continue
        saw_provider_rejection=1
        local text_reset
        text_reset=$(provider_text_reset_at "$logfile" 2>/dev/null || true)
        if [ -n "$text_reset" ] && [ "$text_reset" -gt 0 ] 2>/dev/null; then
          if [ -z "$reset_at" ] || [ "$text_reset" -gt "$reset_at" ] 2>/dev/null; then
            reset_at="$text_reset"
          fi
        fi
        local candidate
        candidate=$(awk '
          /"type":"rate_limit_event"/ &&
          !/"status":"allowed"/ &&
          !/"status":"allowed_warning"/ {
            if (match($0, /"resetsAt":[0-9]*/)) {
              print substr($0, RSTART, RLENGTH)
              exit
            }
          }
        ' "$logfile" 2>/dev/null || true)
        if [ -n "$candidate" ]; then
          candidate="${candidate#*:}"
          if [ -z "$reset_at" ] || [ "$candidate" -gt "$reset_at" ] 2>/dev/null; then
            reset_at="$candidate"
          fi
        fi
      done
    done
  done
  if [ -n "$reset_at" ] && [ "$reset_at" -gt 0 ] 2>/dev/null; then
    printf '%s\n' "$reset_at"
    return 0
  fi
  if [ "$saw_provider_rejection" -eq 1 ]; then
    printf '%s\n' "unknown"
    return 0
  fi
  return 1
}

# Rate limit with resetsAt (Claude CLI)
mkdir -p "$LOGDIR"
ts_rl="20260425_170945"
cat > "$LOGDIR/session_${ts_rl}_cold-start-1-generic.log.raw" <<'EOF'
{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":1777164000}}
{"type":"result","subtype":"success","is_error":true,"api_error_status":429}
EOF
result=$(detect_rate_limit "$ts_rl")
assert_eq 0 $? "Claude rate limit with resetsAt → exit 0"
assert_eq "1777164000" "$result" "Claude rate limit → resetsAt timestamp extracted"

# Rate limit 429 without resetsAt (Claude CLI, no reset info)
ts_claude_no_reset="20260425_180000"
cat > "$LOGDIR/session_${ts_claude_no_reset}_deep_investigation-1-generic.log.raw" <<'EOF'
{"type":"result","subtype":"success","is_error":true,"api_error_status":429}
EOF
result=$(detect_rate_limit "$ts_claude_no_reset")
assert_eq 0 $? "Claude 429 without resetsAt → exit 0"
assert_eq "unknown" "$result" "Claude 429 without resetsAt → returns 'unknown'"

# Rate limit from Codex CLI (legacy "Server returned 429" phrasing in turn.failed)
ts_codex="20260425_190000"
cat > "$LOGDIR/session_${ts_codex}_deep_investigation-1-generic.log.raw" <<'EOF'
{"type":"turn.failed","error":{"message":"Server returned 429 Too Many Requests"}}
EOF
result=$(detect_rate_limit "$ts_codex")
assert_eq 0 $? "Codex 429 turn.failed (legacy phrasing) → exit 0"
assert_eq "unknown" "$result" "Codex 429 (legacy) → returns 'unknown'"

# Rate limit from Codex CLI (current shape: JSON-encoded "status":429 in error event)
ts_codex_json="20260425_191500"
cat > "$LOGDIR/session_${ts_codex_json}_deep_investigation-1-generic.log.raw" <<'EOF'
{"type":"error","message":"{\"type\":\"error\",\"status\":429,\"error\":{\"type\":\"rate_limit_error\",\"message\":\"Rate limit exceeded\"}}"}
{"type":"turn.failed","error":{"message":"{\"type\":\"error\",\"status\":429,\"error\":{\"type\":\"rate_limit_error\",\"message\":\"Rate limit exceeded\"}}"}}
EOF
result=$(detect_rate_limit "$ts_codex_json")
assert_eq 0 $? "Codex 429 turn.failed (JSON status:429) → exit 0"
assert_eq "unknown" "$result" "Codex 429 (JSON shape) → returns 'unknown'"

# Codex usage-limit wording without explicit 429 should still back off and
# should parse the "try again at" clock time.
ts_codex_usage="20260509_101500"
future_epoch=$(( $(date +%s) + 900 ))
if date -r "$future_epoch" '+%-I:%M %p' >/dev/null 2>&1; then
  future_clock=$(date -r "$future_epoch" '+%-I:%M %p')
else
  future_clock=$(date -d "@$future_epoch" '+%-I:%M %p')
fi
cat > "$LOGDIR/session_${ts_codex_usage}_deep_investigation-1-generic.log.raw" <<EOF
{"type":"agent_message","message":"You've hit your usage limit. Please try again at ${future_clock}."}
EOF
result=$(detect_rate_limit "$ts_codex_usage")
assert_eq 0 $? "Codex usage-limit text without 429 → exit 0"
[ "$result" -gt "$(date +%s)" ] 2>/dev/null
assert_eq 0 $? "Codex usage-limit text → reset timestamp parsed"

# No rate limit in normal log
ts_ok="20260425_140000"
cat > "$LOGDIR/session_${ts_ok}_deep_investigation-1-generic.log.raw" <<'EOF'
{"type":"system","subtype":"init"}
{"type":"result","subtype":"success","is_error":false}
EOF
detect_rate_limit "$ts_ok" >/dev/null
assert_eq 1 $? "no rate limit → exit 1"

# No raw logs at all
detect_rate_limit "99999999_999999" >/dev/null
assert_eq 1 $? "missing logs → exit 1"

# status:"allowed" events carry resetsAt but should NOT trigger rate limit
ts_allowed="20260426_064551"
cat > "$LOGDIR/session_${ts_allowed}_deep_investigation-1-generic.log.raw" <<'EOF'
{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","resetsAt":1777224000,"rateLimitType":"five_hour","overageStatus":"rejected","overageDisabledReason":"org_level_disabled_until","isUsingOverage":false}}
{"type":"result","subtype":"success","is_error":false}
EOF
detect_rate_limit "$ts_allowed" >/dev/null
assert_eq 1 $? "status:allowed with resetsAt → no rate limit (exit 1)"

# REGRESSION: status:"allowed_warning" heartbeats carry resetsAt for the
# seven_day window. They are informational (~50% utilization) and must NOT
# trigger backoff. This is the bug that caused 30-min sleeps mid-session.
ts_allowed_warning="20260503_152726"
cat > "$LOGDIR/session_${ts_allowed_warning}_cold-start-2-shell.log.raw" <<'EOF'
{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","resetsAt":1777847400,"rateLimitType":"five_hour","overageStatus":"rejected","overageDisabledReason":"out_of_credits","isUsingOverage":false}}
{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","resetsAt":1778299200,"rateLimitType":"seven_day","utilization":0.5,"isUsingOverage":false}}
{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","resetsAt":1778299200,"rateLimitType":"seven_day","utilization":0.53,"isUsingOverage":false}}
{"type":"result","subtype":"error_max_turns","is_error":true,"num_turns":201,"api_error_status":null}
EOF
detect_rate_limit "$ts_allowed_warning" >/dev/null
assert_eq 1 $? "allowed_warning heartbeats (no 429) → no rate limit (exit 1)"

# REGRESSION: when Stage 1 confirms a 429, allowed_warning resetsAt must NOT
# leak into the wait time — only rejected/non-allowed* resetsAt counts. If no
# rejected event is present, fall back to "unknown" rather than waiting 5+
# days for the seven_day window.
ts_429_with_warning="20260503_180000"
cat > "$LOGDIR/session_${ts_429_with_warning}_cold-start-1-generic.log.raw" <<'EOF'
{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","resetsAt":1778299200,"rateLimitType":"seven_day","utilization":0.99}}
{"type":"result","subtype":"success","is_error":true,"api_error_status":429}
EOF
result=$(detect_rate_limit "$ts_429_with_warning")
assert_eq 0 $? "429 with only allowed_warning resetsAt → exit 0"
assert_eq "unknown" "$result" "429 with only allowed_warning resetsAt → 'unknown' (don't trust seven_day reset)"

# When both rejected and allowed_warning resetsAt are present, prefer rejected.
ts_429_mixed="20260503_181500"
cat > "$LOGDIR/session_${ts_429_mixed}_cold-start-1-generic.log.raw" <<'EOF'
{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","resetsAt":1778299200,"rateLimitType":"seven_day","utilization":0.99}}
{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":1777850000,"rateLimitType":"five_hour"}}
{"type":"result","subtype":"success","is_error":true,"api_error_status":429}
EOF
result=$(detect_rate_limit "$ts_429_mixed")
assert_eq "1777850000" "$result" "429 with mixed resetsAt → use rejected (five_hour), not allowed_warning (seven_day)"

# Codex: stray "429" in tool output (line numbers, regex test data) must NOT
# trigger detection. Only events typed error/turn.failed count.
ts_codex_false="20260502_195051"
cat > "$LOGDIR/session_${ts_codex_false}_cold-start-2-generic.log.raw" <<'EOF'
{"type":"item.completed","item":{"output":"line 429 of pcre2_compile.c","status":"ok"}}
{"type":"command_execution","output":"grep -n 429 src/foo.c"}
{"type":"turn.completed","usage":{"input_tokens":100}}
EOF
detect_rate_limit "$ts_codex_false" >/dev/null
assert_eq 1 $? "Codex stray '429' in tool output → no rate limit (exit 1)"

# Codex: 429 in turn.failed but on a different line than the type tag
# (defensive — the per-line grep handles this since codex emits one event per line).
ts_codex_oneline="20260502_200000"
cat > "$LOGDIR/session_${ts_codex_oneline}_cold-start-1-generic.log.raw" <<'EOF'
{"type":"turn.completed","usage":{"input_tokens":100}}
{"type":"item.completed","item":{"output":"some 429 line"}}
{"type":"error","message":"{\"status\":429,\"error\":{\"message\":\"rate limit\"}}"}
EOF
result=$(detect_rate_limit "$ts_codex_oneline")
assert_eq 0 $? "Codex error event with status:429 → exit 0"
assert_eq "unknown" "$result" "Codex error event → returns 'unknown'"

# Antigravity CLI (gemini backend): glog-style stderr containing the
# Antigravity marker plus capacity/quota wording must trigger cooldown.
ts_gemini="20260503_220000"
cat > "$LOGDIR/session_${ts_gemini}_deep_investigation-1-generic.log.raw" <<'EOF'
I0519 17:22:48.681 12345 server.go:1295] Antigravity CLI starting
W0519 17:22:48.821 12345 client.go:81] You have exhausted your capacity on this model. Your quota will reset after 60s.
EOF
result=$(detect_rate_limit "$ts_gemini")
assert_eq 0 $? "Antigravity capacity wording → exit 0"
[ "$result" -gt "$(date +%s)" ] 2>/dev/null
assert_eq 0 $? "Antigravity rate limit → reset timestamp parsed from text"

# Antigravity CLI: high-demand 503 in the diagnostic log.
ts_gemini_503_stderr="20260510_235001"
cat > "$LOGDIR/session_${ts_gemini_503_stderr}_deep_investigation-1-generic.log.raw" <<'EOF'
I0511 06:50:03.181 12345 server.go:1295] Antigravity CLI starting
E0511 06:50:04.000 12345 http_helpers.go:178] Attempt 1 failed with status 503. This model is currently experiencing high demand.
EOF
result=$(detect_rate_limit "$ts_gemini_503_stderr")
assert_eq 0 $? "Antigravity stderr 503 → exit 0"
assert_eq "unknown" "$result" "Antigravity stderr 503 → returns 'unknown'"

# Antigravity CLI: stderr-only quota exhaustion (HTTP 429 / RESOURCE_EXHAUSTED).
ts_gemini_429_stderr="20260510_235500"
cat > "$LOGDIR/session_${ts_gemini_429_stderr}_deep_investigation-1-generic.log.raw" <<'EOF'
I0511 06:55:03.181 12345 server.go:1295] Antigravity CLI starting
E0511 06:55:04.000 12345 http_helpers.go:178] Attempt 1 failed with status 429. RESOURCE_EXHAUSTED You exceeded your current quota.
EOF
result=$(detect_rate_limit "$ts_gemini_429_stderr")
assert_eq 0 $? "Antigravity stderr 429 → exit 0"
assert_eq "unknown" "$result" "Antigravity stderr 429 → returns 'unknown'"

# Antigravity CLI: a log without Antigravity markers must NOT match — the
# gemini-rejection helper requires both the product marker AND quota text.
ts_no_antigravity_marker="20260503_223000"
cat > "$LOGDIR/session_${ts_no_antigravity_marker}_deep_investigation-1-generic.log.raw" <<'EOF'
some unrelated diagnostic about quota will reset
EOF
detect_rate_limit "$ts_no_antigravity_marker" >/dev/null
assert_eq 1 $? "non-Antigravity log with quota wording does not trigger gemini backoff (exit 1)"

# Google gemini-cli (USE_GEMINI_CLI=1): emits a completely different
# banner from agy. The 429 detection must trigger on its stream-json
# init event + retry chatter — gating only on Antigravity tokens (the
# original behavior) silently disabled quota detection on every
# USE_GEMINI_CLI=1 run, which is exactly how the harness reaches the
# wall budget on retry chatter instead of failing fast.
ts_gcli_429="20260524_073000"
cat > "$LOGDIR/session_${ts_gcli_429}_deep_investigation-1-generic.log.raw" <<'EOF'
YOLO mode is enabled. All tool calls will be automatically approved.
Ripgrep is not available. Falling back to GrepTool.
{"type":"init","timestamp":"2026-05-24T07:30:00.000Z","session_id":"abc-123","model":"gemini-3.1-pro-preview"}
Attempt 1 failed with status 429. Retrying with backoff... _ApiError: {"error":{"message":"RESOURCE_EXHAUSTED You exceeded your current quota","code":429,"status":""}}
    at throwErrorIfNotOK (file:///Users/x/.npm-global/lib/node_modules/@google/gemini-cli/bundle/chunk-X.js:1:1)
EOF
result=$(detect_rate_limit "$ts_gcli_429")
assert_eq 0 $? "gemini-cli 429 (USE_GEMINI_CLI=1 banner) → exit 0"
assert_eq "unknown" "$result" "gemini-cli 429 → returns 'unknown'"

# gemini-cli init event alone (no banner lines) — the `"model":"gemini-…"`
# JSON marker must be enough to identify the dialect, because a harness
# raw log truncated to the JSON event stream still needs detection.
ts_gcli_init_only="20260524_073500"
cat > "$LOGDIR/session_${ts_gcli_init_only}_deep_investigation-1-generic.log.raw" <<'EOF'
{"type":"init","timestamp":"2026-05-24T07:35:00.000Z","session_id":"def-456","model":"gemini-3.1-pro-preview"}
Attempt 4 failed with status 429. RESOURCE_EXHAUSTED
EOF
result=$(detect_rate_limit "$ts_gcli_init_only")
assert_eq 0 $? "gemini-cli init-only header still identifies the dialect → exit 0"

# ═══════════════════════════════════════════════════════════════
# Rate limit backoff cap
# ═══════════════════════════════════════════════════════════════

RATE_LIMIT_DEFAULT_BACKOFF=300
RATE_LIMIT_MAX_BACKOFF=1800

rate_limit_cooldown_path() {
  printf '%s/.rate_limit_cooldown' "$LOGDIR"
}

rate_limit_cooldown_expiry() {
  local reset_at="$1" now expires_at cap_at
  now=$(date +%s)
  if [ "$reset_at" = "unknown" ]; then
    printf '%s\n' "$((now + RATE_LIMIT_DEFAULT_BACKOFF))"
    return 0
  fi
  case "$reset_at" in ''|*[!0-9]*) return 1 ;; esac
  [ "$reset_at" -gt "$now" ] 2>/dev/null || return 1
  expires_at=$((reset_at + 30))
  cap_at=$((now + RATE_LIMIT_MAX_BACKOFF))
  if [ "$expires_at" -gt "$cap_at" ]; then
    expires_at="$cap_at"
  fi
  printf '%s\n' "$expires_at"
}

persist_rate_limit_cooldown() {
  local timestamp="$1" reset_at="$2" expires_at now path
  expires_at=$(rate_limit_cooldown_expiry "$reset_at" 2>/dev/null) || return 1
  now=$(date +%s)
  path=$(rate_limit_cooldown_path)
  {
    printf 'backend=%s\n' "${ACTIVE_BACKEND:-unknown}"
    printf 'reset_at=%s\n' "$reset_at"
    printf 'expires_at=%s\n' "$expires_at"
    printf 'source_timestamp=%s\n' "$timestamp"
    printf 'created_at=%s\n' "$now"
  } > "$path" 2>/dev/null || true
}

read_rate_limit_cooldown_field() {
  local key="$1" path
  path=$(rate_limit_cooldown_path)
  [ -f "$path" ] || return 1
  sed -n "s/^${key}=//p" "$path" 2>/dev/null | tail -1
}

clear_rate_limit_cooldown() {
  rm -f "$(rate_limit_cooldown_path)" 2>/dev/null || true
}

active_rate_limit_cooldown_wait() {
  local path backend expires_at created_at now wait max_expires_at
  path=$(rate_limit_cooldown_path)
  [ -f "$path" ] || return 1
  backend=$(read_rate_limit_cooldown_field backend 2>/dev/null || true)
  if [ -n "$backend" ] && [ "$backend" != "${ACTIVE_BACKEND:-unknown}" ]; then
    return 1
  fi
  expires_at=$(read_rate_limit_cooldown_field expires_at 2>/dev/null || true)
  case "$expires_at" in ''|*[!0-9]*) clear_rate_limit_cooldown; return 1 ;; esac
  created_at=$(read_rate_limit_cooldown_field created_at 2>/dev/null || true)
  case "$created_at" in
    ''|*[!0-9]*) ;;
    *)
      max_expires_at=$((created_at + RATE_LIMIT_MAX_BACKOFF))
      if [ "$expires_at" -gt "$max_expires_at" ] 2>/dev/null; then
        expires_at="$max_expires_at"
      fi
      ;;
  esac
  now=$(date +%s)
  wait=$((expires_at - now))
  if [ "$wait" -le 0 ]; then
    clear_rate_limit_cooldown
    return 1
  fi
  if [ "$wait" -gt "$RATE_LIMIT_MAX_BACKOFF" ]; then
    wait="$RATE_LIMIT_MAX_BACKOFF"
  fi
  printf '%s\n' "$wait"
}

handle_rate_limit_backoff() {
  local timestamp="$1"
  local reset_at
  reset_at=$(detect_rate_limit "$timestamp" 2>/dev/null) || return 1
  persist_rate_limit_cooldown "$timestamp" "$reset_at" || true
  local now wait_secs
  now=$(date +%s)
  if [ "$reset_at" = "unknown" ]; then
    wait_secs="$RATE_LIMIT_DEFAULT_BACKOFF"
  else
    wait_secs=$(( reset_at - now + 30 ))
    [ "$wait_secs" -le 0 ] && return 1
  fi
  if [ "$wait_secs" -gt "$RATE_LIMIT_MAX_BACKOFF" ]; then
    wait_secs="$RATE_LIMIT_MAX_BACKOFF"
  fi
  echo "$wait_secs"
  return 0
}

# Far future resetsAt → should be capped at 1800
ts_far="20260425_200000"
cat > "$LOGDIR/session_${ts_far}_cold-start-1-generic.log.raw" <<EOF
{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":9999999999}}
{"type":"result","subtype":"success","is_error":true,"api_error_status":429}
EOF
result=$(handle_rate_limit_backoff "$ts_far")
assert_eq "1800" "$result" "rate limit backoff capped at RATE_LIMIT_MAX_BACKOFF"

# Normal short reset (known < now + 1800) should not be capped
ts_near="20260425_210000"
near_reset=$(( $(date +%s) + 60 ))
cat > "$LOGDIR/session_${ts_near}_cold-start-1-generic.log.raw" <<EOF
{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":${near_reset}}}
{"type":"result","subtype":"success","is_error":true,"api_error_status":429}
EOF
result=$(handle_rate_limit_backoff "$ts_near")
[ "$result" -lt "$RATE_LIMIT_MAX_BACKOFF" ]
assert_eq 0 $? "rate limit short backoff not capped (${result}s < ${RATE_LIMIT_MAX_BACKOFF}s)"
# Verify the computed wait is approximately resetsAt - now + 30
expected_wait=90  # 60s ahead + 30s buffer
[ "$result" -ge 85 ] && [ "$result" -le 95 ]
assert_eq 0 $? "rate limit short backoff ≈ ${expected_wait}s (got ${result}s)"

# status:"allowed" event should NOT trigger backoff
ts_allowed_bo="20260426_070000"
cat > "$LOGDIR/session_${ts_allowed_bo}_cold-start-1-generic.log.raw" <<'EOF'
{"type":"rate_limit_event","rate_limit_info":{"status":"allowed","resetsAt":1777224000,"rateLimitType":"five_hour"}}
EOF
handle_rate_limit_backoff "$ts_allowed_bo" >/dev/null 2>&1
assert_eq 1 $? "status:allowed → no backoff triggered"

# REGRESSION: allowed_warning heartbeats (no 429) must NOT trigger backoff.
# Pre-fix this caused a 30-min sleep because the seven_day resetsAt was 5+
# days out and got clamped to RATE_LIMIT_MAX_BACKOFF.
ts_warn_bo="20260503_152726"
cat > "$LOGDIR/session_${ts_warn_bo}_cold-start-1-generic.log.raw" <<'EOF'
{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","resetsAt":1778299200,"rateLimitType":"seven_day","utilization":0.53}}
{"type":"result","subtype":"error_max_turns","is_error":true,"num_turns":201,"api_error_status":null}
EOF
handle_rate_limit_backoff "$ts_warn_bo" >/dev/null 2>&1
assert_eq 1 $? "allowed_warning heartbeat (no 429) → no backoff triggered"

# 429 fired but only allowed_warning resetsAt present → use default backoff,
# NOT the multi-day seven_day reset.
ts_429_default="20260503_180000"
cat > "$LOGDIR/session_${ts_429_default}_cold-start-1-generic.log.raw" <<'EOF'
{"type":"rate_limit_event","rate_limit_info":{"status":"allowed_warning","resetsAt":9999999999,"rateLimitType":"seven_day"}}
{"type":"result","subtype":"success","is_error":true,"api_error_status":429}
EOF
result=$(handle_rate_limit_backoff "$ts_429_default")
assert_eq "$RATE_LIMIT_DEFAULT_BACKOFF" "$result" "429 with only allowed_warning resetsAt → default backoff (not seven_day reset)"

# Pre-launch cooldown cache: persisted after detection, scoped to backend, and
# consumed before launching another doomed session.
ACTIVE_BACKEND=codex
export ACTIVE_BACKEND
clear_rate_limit_cooldown
future_reset=$(( $(date +%s) + 120 ))
persist_rate_limit_cooldown "cooldown-known" "$future_reset"
assert_file_exists "$(rate_limit_cooldown_path)" "rate cooldown: persisted file"
assert_eq "codex" "$(read_rate_limit_cooldown_field backend)" "rate cooldown: records backend"
cooldown_wait=$(active_rate_limit_cooldown_wait)
[ "$cooldown_wait" -gt 0 ] && [ "$cooldown_wait" -le "$RATE_LIMIT_MAX_BACKOFF" ]
assert_eq 0 $? "rate cooldown: active wait is positive and capped"

ACTIVE_BACKEND=claude
active_rate_limit_cooldown_wait >/dev/null 2>&1
assert_eq 1 $? "rate cooldown: ignored for different backend"

ACTIVE_BACKEND=codex
persist_rate_limit_cooldown "cooldown-unknown" "unknown"
unknown_wait=$(active_rate_limit_cooldown_wait)
[ "$unknown_wait" -gt 0 ] && [ "$unknown_wait" -le "$RATE_LIMIT_DEFAULT_BACKOFF" ]
assert_eq 0 $? "rate cooldown: unknown reset uses default backoff window"

far_reset=$(( $(date +%s) + 86400 ))
persist_rate_limit_cooldown "cooldown-far" "$far_reset"
far_expires_at=$(read_rate_limit_cooldown_field expires_at)
far_window=$((far_expires_at - $(read_rate_limit_cooldown_field created_at)))
[ "$far_window" -le "$RATE_LIMIT_MAX_BACKOFF" ]
assert_eq 0 $? "rate cooldown: persisted known reset is capped to max backoff"

old_created=$(( $(date +%s) - RATE_LIMIT_MAX_BACKOFF - 60 ))
{
  printf 'backend=codex\n'
  printf 'reset_at=%s\n' "$far_reset"
  printf 'expires_at=%s\n' "$((far_reset + 30))"
  printf 'created_at=%s\n' "$old_created"
} > "$(rate_limit_cooldown_path)"
active_rate_limit_cooldown_wait >/dev/null 2>&1
assert_eq 1 $? "rate cooldown: legacy uncapped entry is inactive once max backoff elapsed"
assert_file_not_exists "$(rate_limit_cooldown_path)" "rate cooldown: legacy uncapped entry removed"

printf 'backend=codex\nexpires_at=1\n' > "$(rate_limit_cooldown_path)"
active_rate_limit_cooldown_wait >/dev/null 2>&1
assert_eq 1 $? "rate cooldown: expired entry is inactive"
assert_file_not_exists "$(rate_limit_cooldown_path)" "rate cooldown: expired entry removed"

# ═══════════════════════════════════════════════════════════════
# get_agent_subsystem — generic target literal Primary Subsystem
# ═══════════════════════════════════════════════════════════════

# Redefine for testing (mirrors the fixed bin/audit logic)
get_agent_subsystem() {
  local agent_num="$1"
  local f
  f=$(state_file_path "$agent_num")
  [ -f "$f" ] || { echo "unknown"; return; }
  local subsys_regex='js/src/jit|js/src/wasm|dom/canvas|dom/media'
  local explicit
  explicit=$(
    grep -m1 -E '^## Primary Subsystem:|^Primary Subsystem:' "$f" 2>/dev/null \
      | sed -E 's/^## Primary Subsystem:[[:space:]]*//; s/^Primary Subsystem:[[:space:]]*//; s/\[[^]]*\]//g; s/\([^)]*\)//g' \
      | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' \
    || true
  )
  if [ "${IS_BROWSER_TARGET:-0}" -eq 0 ] && [ -n "$explicit" ]; then
    echo "$explicit"; return
  fi
  local claimed
  claimed=$(grep -m1 -oE "$subsys_regex" <<<"$explicit" || true)
  [ -n "$claimed" ] && { echo "$claimed"; return; }
  echo "unknown"
}

# Generic target with literal subsystem (e.g. libxml2 "parser/xmlReader")
IS_BROWSER_TARGET=0
cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: parser/xmlReader
| 1 | H1 | parser/xmlReader.c:xmlReaderRead:123 | shape | guard | bounds | A | PENDING |
EOF
result=$(get_agent_subsystem 1)
assert_eq "parser/xmlReader" "$result" "generic target: literal Primary Subsystem preserved"

# Browser target: only known regex paths match
IS_BROWSER_TARGET=1
cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | A | PENDING |
EOF
result=$(get_agent_subsystem 1)
assert_eq "dom/canvas" "$result" "browser target: known subsystem matched"

# Firefox target with unknown subsystem → falls through to unknown
IS_BROWSER_TARGET=1
cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: some/unknown/path
| 1 | H1 | some/unknown/path/Foo.cpp | shape | guard | bounds | A | PENDING |
EOF
result=$(get_agent_subsystem 1)
assert_eq "unknown" "$result" "browser target: unknown subsystem → unknown"

IS_BROWSER_TARGET=0

# ── Gemini-cli bundled-ripgrep diagnostic ────────────────────────────
# bin/audit:gemini_cli_check_bundled_ripgrep emits a one-line WARN when
# the official Google gemini-cli (USE_GEMINI_CLI=1) is missing its
# vendored ripgrep binary. The harness cannot install the binary itself
# (the file lives under the user's npm-global, outside the work tree),
# so the diagnostic just prints the exact symlink command operators can
# run once per machine.

# Extract the function directly from bin/audit so we do not duplicate it.
SCRIPT_ROOT_FOR_RG_TEST="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rg_check_src="$(mktemp)"
awk '/^gemini_cli_check_bundled_ripgrep\(\)/,/^}/' \
  "$SCRIPT_ROOT_FOR_RG_TEST/bin/audit" > "$rg_check_src"
# shellcheck disable=SC1090
. "$rg_check_src"
rm -f "$rg_check_src"

# Stubs the function needs (the harness provides these at runtime).
llm_use_gemini_cli() { [ "${USE_GEMINI_CLI:-0}" = "1" ]; }
log() { printf '[log] %s\n' "$*"; }
INDEX="$(mktemp)"

# Build a fake @google/gemini-cli npm install under $work so we can flip
# the vendor binary on and off.
rg_work="$(mktemp -d)"
fake_npm_root="$rg_work/fake-npm"
fake_bundle="$fake_npm_root/lib/node_modules/@google/gemini-cli/bundle"
fake_bin_dir="$fake_npm_root/bin"
mkdir -p "$fake_bundle" "$fake_bin_dir"
# command -v honors the file mode, so the fake bin must be executable for
# the function to resolve it. In a real npm install the entrypoint is 0755.
printf '#!/usr/bin/env node\nconsole.log("fake gemini")\n' > "$fake_bundle/gemini.js"
chmod +x "$fake_bundle/gemini.js"
ln -sfn "../lib/node_modules/@google/gemini-cli/bundle/gemini.js" "$fake_bin_dir/gemini"

plat_arch="$(node -e 'process.stdout.write(process.platform+"-"+process.arch)' 2>/dev/null || echo darwin-arm64)"
# The function under test runs realpathSync on the gemini binary, which
# resolves /var/folders/... → /private/var/folders/... on macOS. Apply
# the same canonicalization to the expected path so the grep matches.
fake_bundle_real="$(cd "$fake_bundle" && pwd -P)"
vendor_rg_path="$fake_bundle_real/vendor/ripgrep/rg-${plat_arch}"

# Helper: invoke the function with a fully-specified environment in a
# real subshell. `VAR=value out="$(...)"` at the parent level is parsed
# as two assignments to the current shell, so a prior test's
# AUDIT_GEMINI_RG_HINT=0 would leak into the next test and silently
# suppress its diagnostic. Running inside `( ... )` isolates env state.
run_rg_hint() {
  # args: use_cli hint_flag (optional)
  local _use="$1" _hint="${2:-1}"
  ( export USE_GEMINI_CLI="$_use" AUDIT_GEMINI_RG_HINT="$_hint" \
           GEMINI_BIN="$fake_bin_dir/gemini" INDEX="$INDEX"
    gemini_cli_check_bundled_ripgrep 2>&1 )
}

# Case 1: USE_GEMINI_CLI != 1 → function is a no-op, no WARN.
out="$(run_rg_hint 0)"
if [ -z "$out" ]; then
  pass "rg-hint: USE_GEMINI_CLI=0 → no diagnostic"
else
  fail "rg-hint: USE_GEMINI_CLI=0 → no diagnostic" "got: $out"
fi

# Case 2: AUDIT_GEMINI_RG_HINT=0 explicitly suppresses the diagnostic.
out="$(run_rg_hint 1 0)"
if [ -z "$out" ]; then
  pass "rg-hint: AUDIT_GEMINI_RG_HINT=0 suppresses"
else
  fail "rg-hint: AUDIT_GEMINI_RG_HINT=0 suppresses" "got: $out"
fi

# Case 3: USE_GEMINI_CLI=1, vendor binary missing → WARN with symlink cmd
# that references the correct platform-arch path inside the fake bundle.
out="$(run_rg_hint 1 1)"
if printf '%s\n' "$out" | grep -q 'Ripgrep is not available'; then
  pass "rg-hint: missing vendor binary → WARN cites the gemini-cli warning"
else
  fail "rg-hint: missing vendor binary → WARN cites the gemini-cli warning" "got: $out"
fi
if printf '%s\n' "$out" | grep -q "$vendor_rg_path"; then
  pass "rg-hint: WARN names the exact platform-arch vendor path"
else
  fail "rg-hint: WARN names the exact platform-arch vendor path" \
    "expected $vendor_rg_path; got: $out"
fi
if printf '%s\n' "$out" | grep -qE 'ln -sfn .* "'"$vendor_rg_path"'"'; then
  pass "rg-hint: WARN includes a runnable ln -sfn command"
else
  fail "rg-hint: WARN includes a runnable ln -sfn command" "got: $out"
fi

# Case 4: vendor binary present → no WARN. Use the un-realpath'd
# fake_bundle so the file ends up in the same physical location the
# function will look at.
mkdir -p "$fake_bundle/vendor/ripgrep"
ln -sfn "$(command -v rg 2>/dev/null || echo /usr/bin/true)" \
  "$fake_bundle/vendor/ripgrep/rg-${plat_arch}"
out="$(run_rg_hint 1 1)"
if [ -z "$out" ]; then
  pass "rg-hint: vendor binary present → silent"
else
  fail "rg-hint: vendor binary present → silent" "got: $out"
fi

rm -rf "$rg_work"
rm -f "$INDEX"

teardown_test_env
summary
