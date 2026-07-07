#!/usr/bin/env bash
# Shared test helpers — sourced by every test_*.sh file.
# Provides: setup_test_env, teardown_test_env, assert_eq, assert_match,
#           assert_exit_code, assert_file_exists, assert_file_contains,
#           assert_file_not_contains, pass, fail, summary

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
export SCRIPT_ROOT

# Foundational shared lib (pure function defs, no source-time side effects).
# Production sources it before every other lib; load it here too so tests that
# source lib/triage.sh or lib/*.sh directly still get its helpers (audit_log,
# pool_run, …) without each test having to source it itself.
# shellcheck disable=SC1091
source "$SCRIPT_ROOT/lib/platform.sh"

# Block real Claude/Codex calls when a test is run directly (not via
# tests/run-tests.sh). Per-decision mocks override.
export LLM_DECIDE_DISABLE="${LLM_DECIDE_DISABLE:-1}"

_SUITE_PASS=0
_SUITE_FAIL=0
_CURRENT_TEST=""
# Dummy counters for compatibility (runner counts from stdout)
PASSED=0
FAILED=0

# ── Test environment setup ──────────────────────────────────────
# Creates a temp dir with the full directory structure expected by
# the audit harness, and exports all required env vars.
setup_test_env() {
  TEST_TMPDIR=$(mktemp -d "${TMPDIR:-/tmp}/audit-test-XXXXXXXX")
  export TEST_TMPDIR
  export RESULTS_DIR="$TEST_TMPDIR/results"
  export LOGDIR="$TEST_TMPDIR/logs"
  export INDEX="$LOGDIR/index.log"
  export COUNTER_FILE="$LOGDIR/.session_counter"
  export REFERENCE_DIR="$SCRIPT_ROOT/.agents/references"
  export TARGET_ROOT="$TEST_TMPDIR/target"
  export TARGET_SLUG="testproject"
  export TARGET_REPO_TYPE="none"
  export IS_BROWSER_TARGET=0
  export NUM_AGENTS=2
  export BROWSER_AGENTS=1
  export SHELL_AGENTS=1
  export ASAN_BUILD_DIR="$TEST_TMPDIR/target/build-asan"
  export ASAN_BUILD_AVAILABLE=0
  export ASAN_BUILD_BINARY=""
  export SANITIZER_BUILD_AVAILABLE=0
  export SANITIZER_BUILD_SUMMARY=""
  export SANITIZER_BUILD_MISSING=""
  export SANITIZER_BUILD_DISABLED=0
  export TARGET_SANITIZERS_ENABLED_CSV="asan"
  export AGENT_ROLES=""
  export SAFETY_FRAMING_CACHED="(test-framing)"
  export AGENT_GUIDE_CACHED="(test-guide-content)"
  export MIN_DISCARDS_BEFORE_ROTATE=6
  export MIN_ASAN_RUNS_BEFORE_ROTATE=15
  export ENV_BLOCKED_BEFORE_ROTATE=2
  export PER_HYPOTHESIS_TURN_LIMIT=120
  export MAX_DRY_SESSIONS=5
  export GUARD_CHAIN_ROTATION_THRESHOLD=6
  export SUBSYSTEM_TENURE_CAP_SECS=28800
  export STRATEGY_DRY_STREAK_THRESHOLD=3
  export STRATEGY_S1_DRY_STREAK_THRESHOLD=8
  STRATEGY_ROTATION_ORDER=(S1 S2 S3 S4 S5 S6 S7 S8)
  export SUBSYSTEM_BLOCKLIST_FILE="$RESULTS_DIR/.subsystem_blocklist"
  export MAX_STATE_LINES_PER_AGENT=120
  export COMBINED_STATE_MAX_LINES=320
  export ASAN_AUTOENFORCE_TIMEOUT=30
  export MAX_DEAD_STREAK=2
  SUBSYSTEM_BLOCKLIST_DEFAULT=(
    "third_party/rust"
    "third_party/encoding_rs"
    "third_party/url"
  )

  mkdir -p "$RESULTS_DIR/crashes" "$RESULTS_DIR/crashes-rejected" \
           "$RESULTS_DIR/findings" \
           "$RESULTS_DIR/corpus" \
           "$RESULTS_DIR/scratch-1" "$RESULTS_DIR/scratch-2" \
           "$LOGDIR" "$TARGET_ROOT"

  touch "$INDEX"
  echo "0" > "$COUNTER_FILE"

  # Stub helper functions that the libs expect from bin/audit
  state_file_path()      { printf '%s/AUDIT_STATE-%s.md' "$RESULTS_DIR" "$1"; }
  scratch_dir_path()     { printf '%s/scratch-%s' "$RESULTS_DIR" "$1"; }
  combined_state_path()  { printf '%s/AUDIT_STATE.md' "$RESULTS_DIR"; }
  hits_log_path()        { printf '%s/hits-%s.log' "$RESULTS_DIR" "$1"; }
  tried_inputs_log_path(){ printf '%s/tried-inputs-%s.log' "$RESULTS_DIR" "$1"; }
  quality_feedback_path(){ printf '%s/.quality_feedback_%s' "$RESULTS_DIR" "$1"; }
  corpus_dir_root()      { printf '%s/corpus' "$RESULTS_DIR"; }
  fuzz_leads_path()      { printf '%s/fuzz-leads.md' "$RESULTS_DIR"; }
  handoff_file_path()    { printf '%s/.handoff.md' "$RESULTS_DIR"; }
  agent_strategy_path()  { printf '%s/.agent_strategy_%s' "$RESULTS_DIR" "$1"; }
  agent_strategy_streak_path() { printf '%s/.agent_strategy_streak_%s' "$RESULTS_DIR" "$1"; }
  agent_tenure_path()    { printf '%s/.subsystem_tenure_%s' "$RESULTS_DIR" "$1"; }
  guard_chain_path() {
    local slug; slug=$(printf '%s' "$1" | tr '/' '_')
    printf '%s/.guard_chain_%s' "$RESULTS_DIR" "$slug"
  }
  asan_run_counter_path(){ printf '%s/.asan_runs_%s' "$LOGDIR" "$1"; }
  agent_mode() {
    if [ "$IS_BROWSER_TARGET" -eq 0 ]; then echo generic
    elif [ "$1" -le "$BROWSER_AGENTS" ]; then echo browser
    else echo shell; fi
  }
  agent_role() {
    if [ -n "${AGENT_ROLES:-}" ]; then
      local role; role=$(printf '%s' "$AGENT_ROLES" | cut -d',' -f"$1" 2>/dev/null)
      case "$role" in analysis|reproduce) echo "$role"; return ;; esac
    fi
    case "$1" in 2) echo "analysis" ;; *) echo "reproduce" ;; esac
  }
  get_agent_subsystem() { echo "unknown"; }
  count_active_security_results() {
    local count=0 d
    for d in "$RESULTS_DIR"/crashes/CRASH-*/ "$RESULTS_DIR"/findings/FIND-*/; do
      [ -d "$d" ] || continue
      [ -f "$d/.promotion_pending" ] && continue
      count=$((count + 1))
    done; echo "$count"
  }
  count_security_crash_candidates() {
    local count=0 d
    for d in "$RESULTS_DIR"/crashes/CRASH-*/; do
      [ -d "$d" ] || continue
      [ -f "$d/.promotion_pending" ] && continue
      count=$((count + 1))
    done; echo "$count"
  }
  count_confirmed_findings() {
    local count=0 d
    for d in "$RESULTS_DIR"/findings/FIND-*/; do
      [ -d "$d" ] || continue; count=$((count + 1))
    done; echo "$count"
  }
  blocklist_description() {
    local entries=() line
    while IFS= read -r line; do [ -n "$line" ] && entries+=("$line"); done < <(load_blocklist)
    if [ "${#entries[@]}" -gt 0 ]; then
      local IFS=', '; echo "${entries[*]}"
    else
      echo "<none>"
    fi
  }
  subsystem_is_blocklisted() {
    local subsystem="$1"
    [ -z "$subsystem" ] && return 1; [ "$subsystem" = "unknown" ] && return 1
    local entry
    while IFS= read -r entry; do
      [ -z "$entry" ] && continue
      case "$subsystem" in "$entry"|"$entry"/*) return 0 ;; esac
    done < <(load_blocklist)
    return 1
  }
  load_blocklist() {
    local p
    for p in "${SUBSYSTEM_BLOCKLIST_DEFAULT[@]:-}"; do [ -n "$p" ] && echo "$p"; done
    if [ -n "${SUBSYSTEM_BLOCKLIST_FILE:-}" ] && [ -f "$SUBSYSTEM_BLOCKLIST_FILE" ]; then
      while IFS= read -r line; do
        line="${line%%#*}"; line="${line## }"; line="${line%% }"
        [ -n "$line" ] && echo "$line"
      done < "$SUBSYSTEM_BLOCKLIST_FILE"
    fi
  }
  detect_guard_saturation() {
    local subsystem="$1"
    local gpath; gpath=$(guard_chain_path "$subsystem")
    [ -f "$gpath" ] || return 0
    local top_line; top_line=$(sort "$gpath" 2>/dev/null | uniq -c | sort -rn | head -1)
    [ -z "$top_line" ] && return 0
    local count guard
    count=$(awk '{print $1}' <<<"$top_line")
    guard=$(awk '{ $1=""; sub(/^ +/,""); print }' <<<"$top_line")
    if [ "${count:-0}" -ge "$GUARD_CHAIN_ROTATION_THRESHOLD" ]; then
      printf '%s:%s' "$count" "$guard"
    fi
  }
  get_agent_tenure_secs() { echo 0; }
  get_agent_strategy() { echo "S1"; }
  strategy_file_for_letter() {
    case "$1" in
      S1)  echo "S1-prior-fix-review.md";; S2) echo "S2-assert-negation.md";;
      S3)  echo "S3-spec-vs-impl.md";;     S4) echo "S4-differential.md";;
      S5)  echo "S5-reentrancy.md";;        S6) echo "S6-cross-project.md";;
      S7)  echo "S7-fuzz-improvement.md";;  S8) echo "S8-property-based.md";;
      REF) echo "REF-pattern-search.md";;
      *)   echo "";;
    esac
  }
  detect_agent_overlap() { true; }
  build_strategy_roi_directive() { true; }
  browser_mode_subsystems() { echo "dom/canvas"; echo "parser/html"; }
  shell_mode_subsystems()   { echo "js/src/jit"; echo "js/src/wasm"; }
  assign_subsystem_from_coverage() { true; }
  list_candidate_subsystems() { echo "src/lib"; echo "src/crypto"; echo "src/net"; }

  # Export all stubs so subshells see them
  export -f state_file_path scratch_dir_path combined_state_path hits_log_path
  export -f tried_inputs_log_path quality_feedback_path corpus_dir_root
  export -f fuzz_leads_path handoff_file_path
  export -f agent_strategy_path agent_strategy_streak_path agent_tenure_path
  export -f guard_chain_path asan_run_counter_path agent_mode agent_role
  export -f get_agent_subsystem count_active_security_results
  export -f count_security_crash_candidates count_confirmed_findings
  export -f blocklist_description subsystem_is_blocklisted load_blocklist
  export -f detect_guard_saturation get_agent_tenure_secs get_agent_strategy
  export -f strategy_file_for_letter detect_agent_overlap
  export -f build_strategy_roi_directive browser_mode_subsystems
  export -f shell_mode_subsystems assign_subsystem_from_coverage
  export -f list_candidate_subsystems
}

teardown_test_env() {
  [ -n "${TEST_TMPDIR:-}" ] && rm -rf "$TEST_TMPDIR"
}

# ── Assertion helpers ───────────────────────────────────────────
pass() {
  local name="${1:-$_CURRENT_TEST}"
  _SUITE_PASS=$((_SUITE_PASS + 1))
  # Also increment parent's PASSED counter
  PASSED=$((PASSED + 1))
  printf "  \033[0;32m✓\033[0m %s\n" "$name"
}

fail() {
  local name="${1:-$_CURRENT_TEST}"
  local detail="${2:-}"
  _SUITE_FAIL=$((_SUITE_FAIL + 1))
  FAILED=$((FAILED + 1))
  printf "  \033[0;31m✗\033[0m %s\n" "$name"
  [ -n "$detail" ] && printf "    %s\n" "$detail"
}

assert_eq() {
  local expected="$1" actual="$2" name="${3:-$_CURRENT_TEST}"
  if [ "$expected" = "$actual" ]; then
    pass "$name"
  else
    fail "$name" "expected='$expected' actual='$actual'"
  fi
}

assert_neq() {
  local not_expected="$1" actual="$2" name="${3:-$_CURRENT_TEST}"
  if [ "$not_expected" != "$actual" ]; then
    pass "$name"
  else
    fail "$name" "expected NOT '$not_expected' but got it"
  fi
}

assert_match() {
  # NOTE: we deliberately use a here-string (`<<<`) instead of
  # `echo "$actual" | grep ...`. Under `set -o pipefail` (set in most test
  # files), `grep -q` exits as soon as it finds a match, which SIGPIPEs the
  # upstream echo and turns the whole pipeline into a non-zero return —
  # making the assertion fail even though the pattern WAS matched. The flake
  # only surfaces under parallel load because echo's flush timing matters,
  # and it tripped intermittently across full-suite runs before this fix.
  # Here-strings have no pipeline, so no SIGPIPE / pipefail interaction.
  local pattern="$1" actual="$2" name="${3:-$_CURRENT_TEST}"
  # `--` lets patterns starting with a dash (e.g. CLI flag names like
  # `--max-turns`) reach grep as a pattern instead of being parsed as
  # an option.
  if grep -qE -- "$pattern" <<< "$actual"; then
    pass "$name"
  else
    fail "$name" "pattern='$pattern' not found in: $(head -3 <<< "$actual")"
  fi
}

assert_not_match() {
  # See assert_match for why this uses a here-string rather than echo|grep,
  # and for why `--` is required.
  local pattern="$1" actual="$2" name="${3:-$_CURRENT_TEST}"
  if ! grep -qE -- "$pattern" <<< "$actual"; then
    pass "$name"
  else
    fail "$name" "pattern='$pattern' unexpectedly found in output"
  fi
}

assert_exit_code() {
  local expected="$1" name="${2:-$_CURRENT_TEST}"
  local actual="$?"
  if [ "$expected" = "$actual" ]; then
    pass "$name"
  else
    fail "$name" "expected exit=$expected got exit=$actual"
  fi
}

assert_file_exists() {
  local path="$1" name="${2:-$_CURRENT_TEST}"
  if [ -f "$path" ]; then
    pass "$name"
  else
    fail "$name" "file not found: $path"
  fi
}

assert_dir_exists() {
  local path="$1" name="${2:-$_CURRENT_TEST}"
  if [ -d "$path" ]; then
    pass "$name"
  else
    fail "$name" "dir not found: $path"
  fi
}

assert_file_not_exists() {
  local path="$1" name="${2:-$_CURRENT_TEST}"
  if [ ! -f "$path" ]; then
    pass "$name"
  else
    fail "$name" "file unexpectedly exists: $path"
  fi
}

assert_dir_not_exists() {
  local path="$1" name="${2:-$_CURRENT_TEST}"
  if [ ! -d "$path" ]; then
    pass "$name"
  else
    fail "$name" "dir unexpectedly exists: $path"
  fi
}

assert_file_contains() {
  local path="$1" pattern="$2" name="${3:-$_CURRENT_TEST}"
  if [ ! -f "$path" ]; then
    fail "$name" "file not found: $path"
    return
  fi
  local err
  err=$(grep -E "$pattern" "$path" >/dev/null 2>&1; echo "$?")
  case "$err" in
    0) pass "$name" ;;
    1) fail "$name" "pattern='$pattern' not found in $path" ;;
    *) fail "$name" "grep error rc=$err for pattern='$pattern' in $path (malformed regex?)" ;;
  esac
}

assert_file_not_contains() {
  local path="$1" pattern="$2" name="${3:-$_CURRENT_TEST}"
  if [ ! -f "$path" ]; then
    fail "$name" "file not found: $path"
    return
  fi
  local err
  err=$(grep -E "$pattern" "$path" >/dev/null 2>&1; echo "$?")
  case "$err" in
    1) pass "$name" ;;
    0) fail "$name" "pattern='$pattern' unexpectedly found in $path" ;;
    *) fail "$name" "grep error rc=$err for pattern='$pattern' in $path (malformed regex?)" ;;
  esac
}

summary() {
  if [ "$_SUITE_FAIL" -eq 0 ]; then
    printf "  \033[0;32m%d/%d passed\033[0m\n" "$_SUITE_PASS" "$((_SUITE_PASS + _SUITE_FAIL))"
    return 0
  else
    printf "  \033[0;31m%d/%d passed, %d failed\033[0m\n" "$_SUITE_PASS" "$((_SUITE_PASS + _SUITE_FAIL))" "$_SUITE_FAIL"
    return 1
  fi
}
