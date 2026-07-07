#!/usr/bin/env bash
# Unit tests for bin/audit core functions — target resolution, slug sanitization,
# repo detection, backend resolution, model selection, usage extraction, guard init
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
unset USE_GEMINI_CLI
unset CLAUDE_MODEL_DEFAULT CODEX_MODEL_DEFAULT GEMINI_MODEL_DEFAULT AUDIT_LOCAL_BASE_URL AUDIT_LOCAL_API_KEY
source "$SCRIPT_ROOT/lib/platform.sh"
source "$SCRIPT_ROOT/lib/fmt.sh"
source "$SCRIPT_ROOT/lib/llm_invoke.sh"
source "$SCRIPT_ROOT/lib/prompt_template.sh"
source "$SCRIPT_ROOT/lib/target_config.sh"
source "$SCRIPT_ROOT/lib/structured_state.sh"

# ═══════════════════════════════════════════════════════════════
# Functions pulled from bin/audit (not sourced — isolated re-impl)
# ═══════════════════════════════════════════════════════════════

audit_extract_function() {
  local name="$1"
  awk -v name="$name" '
    $0 ~ "^" name "\\(\\) \\{" { in_func=1 }
    in_func { print }
    in_func && $0 == "}" { exit }
  ' "$SCRIPT_ROOT/bin/audit"
}

# Multi-function variant of audit_extract_function: one awk pass over
# bin/audit (~320KB) instead of one subprocess per function. The output is
# every requested function body (first definition wins, same as the
# single-function extractor), in bin/audit file order — eval'ing pure
# definitions is order-independent. This exists purely for speed: the
# original one-eval-per-function block spawned ~80 awk subshells and
# dominated this suite's startup time.
audit_extract_functions() {
  awk -v names="$*" '
    BEGIN { n = split(names, a, " "); for (i = 1; i <= n; i++) want[a[i]] = 1 }
    /^[A-Za-z0-9_]+\(\) \{/ {
      fname = $0
      sub(/\(\) \{.*/, "", fname)
      if (fname in want && !(fname in seen)) { in_func = 1; seen[fname] = 1 }
    }
    in_func { print }
    in_func && $0 == "}" { in_func = 0 }
  ' "$SCRIPT_ROOT/bin/audit"
}

eval "$(audit_extract_functions \
  _detect_free_ram_mb \
  backend_bin \
  backend_configured \
  oss_model_available \
  oss_local_base_url \
  oss_resolved_model_name \
  discover_ensemble_backends \
  init_backend_selection \
  apply_backend_decision_timeout_defaults \
  resolve_model \
  model_preflight_stamp_path \
  oss_tool_preflight \
  audit_one_time_backend_bootstrap \
  gemini_prune_stale_sessions \
  gemini_cli_check_bundled_ripgrep \
  gemini_capture_cli_log_diag \
  validate_model_for_backend \
  validate_active_model \
  extract_waste_telemetry \
  extract_raw_status \
  write_session_log_summary \
  count_structural_refusal_signals \
  log_has_rate_limit_rejection \
  _iteration_provider_status \
  _provider_status_value \
  extract_raw_status \
  handle_rate_limit_backoff \
  session_recovery_pause \
  record_session_pause \
  session_paused_path \
  codex_raw_has_completed_turn \
  codex_raw_has_failed_turn \
  gemini_raw_has_success_result \
  normalize_agent_exit_code \
  work_card_refresh_summary \
  fuzz_leads_signature_file \
  fuzz_leads_signature_exists \
  current_fuzz_leads_signature \
  fuzz_leads_changed_since_last_iteration \
  refresh_fuzz_leads_signature \
  target_source_signature_file \
  target_source_signature_exists \
  current_target_source_signature \
  target_source_unchanged_since_last_iteration \
  refresh_target_source_signature \
  launch_evidence_is_new \
  refresh_launch_evidence_signatures \
  resume_state_path \
  resume_state_read \
  resume_state_write \
  resume_bool_enabled \
  backend_resume_enabled \
  agent_active_card_id \
  latest_agent_resume_raw_log \
  should_disable_resume_for_cache \
  clear_agent_resume_state \
  target_exhausted_hard_stop_ready \
  audit_exit_trap \
  _audit_append_line \
  _audit_resolve_target_path \
  _audit_record_sanitizer_found \
  _audit_record_sanitizer_missing \
  _audit_nm_has_symbol \
  _audit_scan_sanitizer_build_dir \
  _audit_detect_configured_binary \
  _audit_detect_configured_file \
  _audit_detect_asan_build \
  _audit_detect_binary_sanitizer_build \
  _audit_runner_bin_available \
  _audit_detect_race_runner \
  detect_sanitizer_builds)"
run_agent_src="$(audit_extract_function run_agent)"
eval "$(audit_extract_functions \
  count_security_crash_candidates \
  count_confirmed_findings \
  _cluster_count_from_tool \
  count_security_crash_root_causes \
  count_confirmed_finding_root_causes \
  count_iteration_progress_snapshot \
  load_iteration_progress_snapshot)"

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

log() {
  echo "$*"
}

sanitize_target_slug() {
  local raw="$1"; raw="${raw##*/}"
  raw=$(printf '%s' "$raw" | tr '[:upper:]' '[:lower:]')
  raw=$(printf '%s' "$raw" | tr -cs '[:alnum:]._-' '-')
  raw="${raw#-}"; raw="${raw%-}"
  echo "$raw"
}

detect_repo_type() {
  local root="$1"
  if [ -d "$root/.hg" ]; then echo "hg"
  elif [ -e "$root/.git" ] && git -C "$root" rev-parse --git-dir >/dev/null 2>&1; then echo "git"
  else echo "none"; fi
}

resolve_guide_path() {
  echo "AGENTS.md"
}

init_guards_db() {
  local f="$1"
  [ -f "$f" ] && return 0
  cat > "$f" <<'GDB'
# Guards Database (append-only)
## Entries
GDB
}

reset_asan_run_counter() {
  local f="$1"
  printf '0' > "$f" 2>/dev/null || true
}

# extract_usage_field is pulled verbatim from bin/audit, not re-implemented,
# so the test exercises the real usage parser. An inlined copy drifted in
# the past (it grew a gemini `.stats` / `.cached` branch the real function
# never had — agy emits plain text, so bin/audit reads no usage from it).
eval "$(audit_extract_functions extract_usage_field extract_usage_fields extract_completed_item_count extract_tool_counts extract_raw_status extract_finish_fields extract_total_tool_uses)"

set_agent_strategy() {
  printf '%s' "$2" > "$(agent_strategy_path "$1")"
}

reset_agent_strategy_streak() {
  rm -f "$(agent_strategy_streak_path "$1")" 2>/dev/null || true
}

count_active_hypotheses_for_agent() {
  local f
  f=$(state_file_path "$1")
  [ -f "$f" ] || { echo 0; return; }
  local c
  c=$(grep -cE 'PENDING|INVESTIGATING|NEEDS_TESTCASE' "$f" 2>/dev/null || true)
  echo "${c:-0}"
}

count_total_pending() { echo "${TEST_PENDING:-0}"; }
count_total_active_hypotheses() { echo "${TEST_ACTIVE:-0}"; }
target_has_prior_audit_progress() { [ "${TEST_PRIOR_PROGRESS:-0}" -eq 1 ]; }
eligible_work_card_exists() { [ "${TEST_ELIGIBLE_WORK:-0}" -eq 1 ]; }
count_active_security_results() { echo "${TEST_SECURITY_RESULTS:-0}"; }
audit_timeout_run() { local _seconds="$1"; shift; "$@"; }

# ═══════════════════════════════════════════════════════════════
# Sanitizer build detection after target.toml load
# ═══════════════════════════════════════════════════════════════

assert_file_contains "$SCRIPT_ROOT/bin/audit" "grep -c" \
  "audit sanitizer scan consumes full nm output instead of grep -q"

mkdir -p "$TARGET_ROOT/build-asan" "$TARGET_ROOT/build-ubsan" \
  "$TARGET_ROOT/build-msan" "$TARGET_ROOT/build-tsan" "$TARGET_ROOT/tools"

TARGET_SANITIZERS_EXPLICITLY_DISABLED=0
TARGET_SANITIZERS_ENABLED=(asan)
TARGET_ASAN_BIN=""
TARGET_ASAN_LIB="build-asan/libtarget.a"
printf 'fake archive\n' > "$TARGET_ROOT/build-asan/libtarget.a"
detect_sanitizer_builds
assert_eq "1" "$SANITIZER_BUILD_AVAILABLE" "audit sanitizer detection: ASan library counts as available"
assert_eq "1" "$ASAN_BUILD_AVAILABLE" "audit sanitizer detection: legacy ASAN flag set for ASan library"
assert_match 'asan: .*configured library' "$SANITIZER_BUILD_SUMMARY" \
  "audit sanitizer detection: ASan summary names configured library"
assert_eq "" "$SANITIZER_BUILD_MISSING" "audit sanitizer detection: valid ASan config has no missing row"

cat > "$TARGET_ROOT/build-ubsan/demo" <<'SH'
#!/usr/bin/env sh
exit 0
SH
cat > "$TARGET_ROOT/build-msan/demo" <<'SH'
#!/usr/bin/env sh
exit 0
SH
cat > "$TARGET_ROOT/build-tsan/demo" <<'SH'
#!/usr/bin/env sh
exit 0
SH
chmod +x "$TARGET_ROOT/build-ubsan/demo" "$TARGET_ROOT/build-msan/demo" "$TARGET_ROOT/build-tsan/demo"
TARGET_SANITIZERS_ENABLED=(ubsan msan tsan)
TARGET_ASAN_BIN=""
TARGET_ASAN_LIB=""
TARGET_UBSAN_BIN="build-ubsan/demo"
TARGET_MSAN_BIN="build-msan/demo"
TARGET_TSAN_BIN="build-tsan/demo"
detect_sanitizer_builds
assert_eq "1" "$SANITIZER_BUILD_AVAILABLE" "audit sanitizer detection: non-ASan binaries count as available"
assert_eq "0" "$ASAN_BUILD_AVAILABLE" "audit sanitizer detection: ASAN legacy flag stays off for non-ASan-only config"
assert_match 'ubsan: .*configured binary' "$SANITIZER_BUILD_SUMMARY" \
  "audit sanitizer detection: UBSan binary detected"
assert_match 'msan: .*configured binary' "$SANITIZER_BUILD_SUMMARY" \
  "audit sanitizer detection: MSan binary detected"
assert_match 'tsan: .*configured binary' "$SANITIZER_BUILD_SUMMARY" \
  "audit sanitizer detection: TSan binary detected"
assert_eq "" "$SANITIZER_BUILD_MISSING" "audit sanitizer detection: valid non-ASan config has no missing rows"

cat > "$TARGET_ROOT/tools/run-race" <<'SH'
#!/usr/bin/env sh
exit 0
SH
chmod +x "$TARGET_ROOT/tools/run-race"
TARGET_SANITIZERS_ENABLED=(race)
TARGET_UBSAN_BIN=""
TARGET_MSAN_BIN=""
TARGET_TSAN_BIN=""
TARGET_RUNNER_BIN="tools/run-race"
TARGET_RUNNER_ARGS=("test" "-race" "{TESTCASE}")
detect_sanitizer_builds
assert_match 'race: .*runner' "$SANITIZER_BUILD_SUMMARY" \
  "audit sanitizer detection: race runner detected when args include -race"

TARGET_RUNNER_ARGS=("test" "{TESTCASE}")
detect_sanitizer_builds
assert_eq "0" "$SANITIZER_BUILD_AVAILABLE" "audit sanitizer detection: race without -race is unavailable"
assert_match 'runner args do not include -race' "$SANITIZER_BUILD_MISSING" \
  "audit sanitizer detection: race missing reason is explicit"

TARGET_SANITIZERS_ENABLED=()
TARGET_SANITIZERS_EXPLICITLY_DISABLED=1
TARGET_RUNNER_BIN=""
TARGET_RUNNER_ARGS=()
detect_sanitizer_builds
assert_eq "1" "$SANITIZER_BUILD_DISABLED" "audit sanitizer detection: explicit empty sanitizer set is disabled"
assert_eq "" "$SANITIZER_BUILD_SUMMARY" "audit sanitizer detection: disabled mode has no fake build summary"
TARGET_SANITIZERS_EXPLICITLY_DISABLED=0

# ═══════════════════════════════════════════════════════════════
# Dry-streak hard stop evidence gate
# ═══════════════════════════════════════════════════════════════

TARGET_REV="rev-a"
TARGET_REPO_TYPE="none"
TEST_PENDING=0
TEST_ACTIVE=0
TEST_PRIOR_PROGRESS=1
TEST_ELIGIBLE_WORK=1
dry_streak="$MAX_DRY_SESSIONS"

# A migrated/fresh run has no evidence baselines yet; allow one launch so the
# harness can establish signatures.
target_exhausted_hard_stop_ready
assert_eq 1 $? "hard stop: missing evidence baselines allow one launch"

refresh_launch_evidence_signatures
target_exhausted_hard_stop_ready
assert_eq 0 $? "hard stop: stale eligible work no longer bypasses dry-streak stop"

dry_streak=$((MAX_DRY_SESSIONS - 1))
target_exhausted_hard_stop_ready
assert_eq 1 $? "hard stop: eligible work can continue before dry threshold"
dry_streak="$MAX_DRY_SESSIONS"

TARGET_REV="rev-b"
target_exhausted_hard_stop_ready
assert_eq 1 $? "hard stop: target source change is new evidence"
refresh_launch_evidence_signatures

printf '# leads\nnew lead\n' > "$(fuzz_leads_path)"
target_exhausted_hard_stop_ready
assert_eq 1 $? "hard stop: fuzz lead content change is new evidence"
refresh_launch_evidence_signatures

target_exhausted_hard_stop_ready
assert_eq 0 $? "hard stop: unchanged fuzz lead becomes stale evidence"

AUDIT_FIXED_STRATEGY="S8"
target_exhausted_hard_stop_ready
assert_eq 1 $? "hard stop: fixed strategy smoke bypasses stale queue exhaustion"
AUDIT_FIXED_STRATEGY=""

TEST_ACTIVE=1
target_exhausted_hard_stop_ready
assert_eq 1 $? "hard stop: active hypotheses still allow launch"
TEST_ACTIVE=0

# Restore defaults so subsequent test sections start from a known state.
TEST_SECURITY_RESULTS=0
TEST_ELIGIBLE_WORK=1

archive_exhausted_agent_state() {
  local agent_num="$1" reason="${2:-exhausted}"
  local live archive_dir ts
  live=$(state_file_path "$agent_num")
  [ -f "$live" ] || return 0
  archive_dir="$RESULTS_DIR/.state_archive"
  mkdir -p "$archive_dir"
  ts=test
  mv "$live" "${archive_dir}/AUDIT_STATE-${agent_num}.${reason}.${ts}.md"
}

archive_prelaunch_exhausted_states() {
  local i active
  for i in $(seq 1 "$NUM_AGENTS"); do
    local sf
    sf=$(state_file_path "$i")
    [ -f "$sf" ] || continue
    active=$(count_active_hypotheses_for_agent "$i" 2>/dev/null || echo 0)
    if [ "${active:-0}" -eq 0 ]; then
      archive_exhausted_agent_state "$i" "prelaunch-exhausted"
      set_agent_strategy "$i" "S1"
      reset_agent_strategy_streak "$i"
    fi
  done
}

# ═══════════════════════════════════════════════════════════════
# 1. sanitize_target_slug — edge cases
# ═══════════════════════════════════════════════════════════════

assert_eq "firefox" "$(sanitize_target_slug "firefox")" "slug: simple"
assert_eq "firefox" "$(sanitize_target_slug "Firefox")" "slug: uppercase"
assert_eq "my-project" "$(sanitize_target_slug "My Project")" "slug: spaces"
assert_eq "firefox" "$(sanitize_target_slug "/path/to/firefox")" "slug: strips path"
assert_eq "hello-world" "$(sanitize_target_slug "Hello World!")" "slug: exclamation"
assert_eq "v1.2.3" "$(sanitize_target_slug "v1.2.3")" "slug: dots preserved"
assert_eq "foo-bar" "$(sanitize_target_slug "--foo--bar--")" "slug: leading/trailing dashes stripped"
assert_eq "test_project" "$(sanitize_target_slug "test_project")" "slug: underscores preserved"
assert_eq "a-b-c" "$(sanitize_target_slug "a@b#c")" "slug: special chars → hyphens"

# ═══════════════════════════════════════════════════════════════
# 2. detect_repo_type — hg, git, none
# ═══════════════════════════════════════════════════════════════

# Mercurial repo
hg_dir="$TEST_TMPDIR/hg_repo"
mkdir -p "$hg_dir/.hg"
assert_eq "hg" "$(detect_repo_type "$hg_dir")" "detect: hg repo"

# Git repo
git_dir="$TEST_TMPDIR/git_repo"
mkdir -p "$git_dir"
(cd "$git_dir" && git init --quiet 2>/dev/null)
assert_eq "git" "$(detect_repo_type "$git_dir")" "detect: git repo"

# No repo
plain_dir="$TEST_TMPDIR/plain"
mkdir -p "$plain_dir"
assert_eq "none" "$(detect_repo_type "$plain_dir")" "detect: no repo"

parent_repo="$TEST_TMPDIR/parent_repo"
nested_plain="$parent_repo/targets/plain"
mkdir -p "$nested_plain"
(cd "$parent_repo" && git init --quiet 2>/dev/null)
assert_eq "none" "$(detect_repo_type "$nested_plain")" "detect: parent repo does not make nested target a repo"

# ═══════════════════════════════════════════════════════════════
# 3. resolve_guide_path — browser vs generic target
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1
assert_eq "AGENTS.md" "$(resolve_guide_path)" "guide: browser target → AGENTS.md"
IS_BROWSER_TARGET=0
assert_eq "AGENTS.md" "$(resolve_guide_path)" "guide: generic target → AGENTS.md (unified)"

# ═══════════════════════════════════════════════════════════════
# 3a. default/all backend enables hosted ensemble cycle
# ═══════════════════════════════════════════════════════════════

fake_backend_dir="$TEST_TMPDIR/fake-backends"
mkdir -p "$fake_backend_dir"
cat > "$fake_backend_dir/claude-ok" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "auth" ] && [ "$2" = "status" ] && exit 0
exit 1
EOF
cat > "$fake_backend_dir/codex-ok" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "login" ] && [ "$2" = "status" ] && exit 0
exit 1
EOF
cat > "$fake_backend_dir/gemini-missing-auth" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "--list-sessions" ] && exit 41
exit 1
EOF
cat > "$fake_backend_dir/opencode" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "$fake_backend_dir/"*
OLD_PATH="$PATH"
PATH="$fake_backend_dir:$PATH"
oss_model_available() {
  [ "$(oss_resolved_model_name "$1")" = "qwen3-14b" ]
}

AUDIT_BACKEND=all
BACKEND_FLAG_PROVIDED=0
MODEL_FLAG_PROVIDED=0
AUDIT_MODEL=""
ENSEMBLE_MODE=0
ENSEMBLE_BACKENDS=()
ACTIVE_BACKEND=""
CLAUDE_BIN="$fake_backend_dir/claude-ok"
CODEX_BIN="$fake_backend_dir/codex-ok"
GEMINI_BIN="$fake_backend_dir/gemini-missing-auth"
init_backend_selection
assert_eq "1" "$ENSEMBLE_MODE" "backend: omitted backend enables ensemble mode"
assert_eq "claude" "$ACTIVE_BACKEND" "backend: ensemble starts with first configured backend"
assert_eq "claude codex" "${ENSEMBLE_BACKENDS[*]}" "backend: ensemble skips unconfigured gemini"

AUDIT_BACKEND=all
BACKEND_FLAG_PROVIDED=1
MODEL_FLAG_PROVIDED=0
AUDIT_MODEL=""
ENSEMBLE_MODE=0
ENSEMBLE_BACKENDS=()
ACTIVE_BACKEND=""
CLAUDE_BIN="$fake_backend_dir/gemini-missing-auth"
CODEX_BIN="$fake_backend_dir/codex-ok"
GEMINI_BIN="$fake_backend_dir/gemini-missing-auth"
init_backend_selection
assert_eq "1" "$ENSEMBLE_MODE" "backend: explicit --backend all enables ensemble mode"
assert_eq "codex" "$ACTIVE_BACKEND" "backend: explicit all starts with first configured backend"
assert_eq "codex" "${ENSEMBLE_BACKENDS[*]}" "backend: explicit all skips unconfigured hosted backends"

AUDIT_BACKEND=oss
BACKEND_FLAG_PROVIDED=1
MODEL_FLAG_PROVIDED=1
AUDIT_MODEL="qwen3-14b"
ENSEMBLE_MODE=0
ENSEMBLE_BACKENDS=()
ACTIVE_BACKEND=""
CLAUDE_BIN="$fake_backend_dir/gemini-missing-auth"
CODEX_BIN="$fake_backend_dir/codex-ok"
GEMINI_BIN="$fake_backend_dir/gemini-missing-auth"
OPENCODE_BIN="$fake_backend_dir/opencode"
init_backend_selection
assert_eq "oss" "$ACTIVE_BACKEND" "backend: oss selects local OpenCode path without hosted login check"

ACTIVE_BACKEND=codex
AUDIT_LLM_DECISION_TIMEOUT_USER_SET=""
LLM_DECISION_TIMEOUT=45
apply_backend_decision_timeout_defaults
assert_eq "45" "$LLM_DECISION_TIMEOUT" "decision timeout: hosted backend keeps shared default"

ACTIVE_BACKEND=oss
AUDIT_LLM_DECISION_TIMEOUT_USER_SET=""
LLM_DECISION_TIMEOUT=45
apply_backend_decision_timeout_defaults
assert_eq "180" "$LLM_DECISION_TIMEOUT" "decision timeout: oss backend raises shared default"
assert_eq "180" "$(bash -c 'printf "%s" "$LLM_DECISION_TIMEOUT"')" "decision timeout: applied value is exported to child tools"

ACTIVE_BACKEND=oss
AUDIT_LLM_DECISION_TIMEOUT_USER_SET=1
LLM_DECISION_TIMEOUT=240
apply_backend_decision_timeout_defaults
assert_eq "240" "$LLM_DECISION_TIMEOUT" "decision timeout: explicit operator override wins for oss"

AUDIT_BACKEND=oss
BACKEND_FLAG_PROVIDED=1
MODEL_FLAG_PROVIDED=0
AUDIT_MODEL=""
ACTIVE_BACKEND=""
OPENCODE_BIN="$fake_backend_dir/opencode"
oss_missing_model_output=$(init_backend_selection 2>&1)
oss_missing_model_rc=$?
assert_eq "1" "$oss_missing_model_rc" "backend: oss requires explicit model"
assert_match "requires --model" "$oss_missing_model_output" "backend: oss missing model explains requirement"

AUDIT_BACKEND=oss
BACKEND_FLAG_PROVIDED=1
MODEL_FLAG_PROVIDED=1
AUDIT_MODEL="missing-local-model"
ACTIVE_BACKEND=""
OPENCODE_BIN="$fake_backend_dir/opencode"
oss_unavailable_output=$(init_backend_selection 2>&1)
oss_unavailable_rc=$?
assert_eq "1" "$oss_unavailable_rc" "backend: oss requires a served local model"
assert_match "resolved to 'missing-local-model'.*127.0.0.1:8000/v1" "$oss_unavailable_output" "backend: oss unavailable model explains base URL"

# A model override is backend-specific. Implicit hosted cycling would pass the
# same model string to different CLIs, so require an explicit single backend.
AUDIT_BACKEND=all
BACKEND_FLAG_PROVIDED=0
MODEL_FLAG_PROVIDED=1
AUDIT_MODEL="custom-model"
ENSEMBLE_MODE=0
ENSEMBLE_BACKENDS=()
ACTIVE_BACKEND=""
model_all_output=$(init_backend_selection 2>&1)
model_all_rc=$?
assert_eq "1" "$model_all_rc" "backend: ensemble rejects model override"
assert_match "single backend" "$model_all_output" "backend: model override explains single-backend requirement"
PATH="$OLD_PATH"

# ═══════════════════════════════════════════════════════════════
# 3b. resolve_model — defaults and per-backend override
# ═══════════════════════════════════════════════════════════════

AUDIT_MODEL=""
ACTIVE_BACKEND=claude
assert_eq "claude-opus-4-8" "$(resolve_model)" "model: claude default"
CLAUDE_MODEL_DEFAULT="claude-opus-9-9"
assert_eq "claude-opus-9-9" "$(resolve_model)" "model: claude canonical default override"
unset CLAUDE_MODEL_DEFAULT
ACTIVE_BACKEND=codex
assert_eq "gpt-5.5" "$(resolve_model)" "model: codex default"
CODEX_MODEL_DEFAULT="gpt-6-test"
assert_eq "gpt-6-test" "$(resolve_model)" "model: codex canonical default override"
unset CODEX_MODEL_DEFAULT
ACTIVE_BACKEND=gemini
assert_eq "gemini-3.1-pro-preview" "$(resolve_model)" "model: gemini default"
GEMINI_MODEL_DEFAULT="gemini-3.1-flash-lite-canonical"
assert_eq "gemini-3.1-flash-lite-canonical" "$(resolve_model)" "model: gemini canonical default override"
unset GEMINI_MODEL_DEFAULT
(
  unset GEMINI_MODEL_DEFAULT AUDIT_MODEL
  USE_GEMINI_CLI=1
  ACTIVE_BACKEND=gemini
  assert_eq "gemini-3.1-pro-preview" "$(resolve_model)" "model: gemini CLI default"
  AUDIT_MODEL="gemini-cli-model"
  assert_eq "gemini-cli-model" "$(resolve_model)" "model: gemini CLI accepts launch-time override"
)

AUDIT_MODEL="custom-backend-model"
ACTIVE_BACKEND=claude
assert_eq "custom-backend-model" "$(resolve_model)" "model: override applies to claude"
ACTIVE_BACKEND=codex
assert_eq "custom-backend-model" "$(resolve_model)" "model: override applies to codex"
ACTIVE_BACKEND=gemini
# agy 1.0.5+ accepts --model (mapped to an `agy models` label downstream in
# llm_invoke.py), so resolve_model now passes the override through like the
# other backends instead of rejecting it.
assert_eq "custom-backend-model" "$(resolve_model)" "model: override applies to gemini"
ACTIVE_BACKEND=oss
assert_eq "custom-backend-model" "$(resolve_model)" "model: override applies to oss"

# IS_SANDBOX=1 must be exported on the claude path before the CLI is
# launched. Without it, root-uid containers (audit-container-shell, CI runners)
# hit Claude Code's safety check on --dangerously-skip-permissions and exit
# 4 before producing any tool output.
claude_branch_src=$(printf '%s\n' "$run_agent_src" \
  | sed -n '/ACTIVE_BACKEND" = "claude"/,/claude_flags=(/p')
assert_match 'export IS_SANDBOX=1' "$claude_branch_src" \
  "backend: claude launch exports IS_SANDBOX=1 before claude_flags (Docker root-uid guard)"

# Per-backend flag assembly now lives in lib/llm_invoke.sh — bin/audit
# delegates via `llm_agent_flags BACKEND flags_array model max_turns add_dirs`.
# These assertions verify the audit-side call shapes; flag content itself
# is covered by tests/test_llm_invoke.sh so the same defaults flow to
# bin/audit-recon, bin/validate-finding, and lib/llm_decide.sh.
assert_match 'llm_agent_flags claude claude_base_flags "\$model"'   "$run_agent_src" "model: claude launch delegates to llm_agent_flags with \$model"
assert_match 'llm_agent_flags gemini gemini_flags "\$model"'        "$run_agent_src" "model: gemini launch delegates to llm_agent_flags with \$model"
assert_match 'llm_agent_flags codex codex_flags "\$model"'          "$run_agent_src" "model: codex launch delegates to llm_agent_flags with \$model"
assert_match 'llm_agent_flags oss opencode_flags "\$model"'         "$run_agent_src" "backend: oss launch routes through llm_agent_flags oss"
# Gemini's full add-dirs CSV (script root, target tree, results dir)
# becomes repeated --add-dir flags inside llm_agent_flags. The harness
# call site still joins them verbatim from the add_dirs argument.
assert_match 'llm_agent_flags gemini gemini_flags "\$model" 80 "\$SCRIPT_ROOT,\$TARGET_ROOT,\$RESULTS_DIR"' \
  "$run_agent_src" "model: gemini launch passes script/target/results to llm_agent_flags"
assert_match 'verified_asan_runs=\$\(count_verified_asan_runs "\$\(scratch_dir_path "\$agent_num"\)"' \
  "$run_agent_src" "agent quality: verified ASan runs are counted once for telemetry"
run_agent_asan_count_calls=$(grep -cF 'count_verified_asan_runs "$(scratch_dir_path "$agent_num")"' <<< "$run_agent_src" || true)
assert_eq "2" "$run_agent_asan_count_calls" "agent quality: ASan runs counted once before launch and once after launch"
run_agent_result_count_calls=$(grep -cF 'count_active_security_results' <<< "$run_agent_src" || true)
assert_eq "2" "$run_agent_result_count_calls" "agent quality: security results counted once before launch and once after launch"
assert_match 'resume_results_after="\$active_security_results_after"' "$run_agent_src" "agent quality: resume dry-count reuses post-session result count"
assert_match 'resume_asan_after="\$verified_asan_runs"' "$run_agent_src" "agent quality: resume dry-count reuses post-session ASan count"
assert_match '\[ "\$\{tool_uses:-0\}" -eq 0 \] && \[ "\$\{command_count:-0\}" -eq 0 \] && \[ "\$\{verified_asan_runs:-0\}" -eq 0 \] && \[ "\$\{output_tokens:-0\}" -eq 0 \]' \
  "$run_agent_src" "agent quality: ASan + output_tokens gate prevents false dead-session rotation (output_tokens guard keeps agy source-only sessions alive)"
# agy's --print-timeout defaults to 5m0s and silently aborts a long
# agent session with "Error: timed out waiting for response" (0 tool
# calls). The launch must pin it to the harness agent budget so the
# two-phase watchdog stays the controlling timeout.
assert_match 'gemini_flags\+=\(--print-timeout "\$\{AGENT_TIMEOUT\}s"\)' \
  "$run_agent_src" "model: gemini launch pins agy --print-timeout to AGENT_TIMEOUT"
assert_match 'STREAM_IDLE_RETRY: agent=\$\{agent_num\} role=\$\{role\}' \
  "$run_agent_src" "backend: claude stream-idle retry logs the run_agent role argument"
assert_not_match 'STREAM_IDLE_RETRY: agent=\$\{agent_num\} role=\$\{role_name\}' \
  "$run_agent_src" "backend: claude stream-idle retry does not reference launcher-local role_name"

# Work-card refresh summary used to scan the newly-written queue three times:
# wc for total lines, jq/sort/uniq for strategy histogram, jq/sort/uniq for
# status histogram. Keep one jq reduction over work-cards plus one cheap patch
# line count so refresh logging stays out of the iteration critical path.
work_cards_summary="$TEST_TMPDIR/work-cards-summary.jsonl"
patch_cards_summary="$TEST_TMPDIR/patch-cards-summary.jsonl"
cat > "$work_cards_summary" <<'EOF'
{"id":"W1","strategy":"S7","status":"unclaimed"}
{"id":"W2","strategy":"S7","status":"unclaimed"}
{"id":"W3","strategy":"S5","status":"claimed"}
{"id":"W4","strategy":"S2","status":"blocked"}
EOF
cat > "$patch_cards_summary" <<'EOF'
{"id":"P1"}
{"id":"P2"}
EOF
summary=$(work_card_refresh_summary "$work_cards_summary" "$patch_cards_summary")
IFS="$(printf '\t')" read -r wc_lines pc_lines wc_by_strat wc_by_status <<< "$summary"
assert_eq "4" "$wc_lines" "work-card refresh summary: counts ranked cards"
assert_eq "2" "$pc_lines" "work-card refresh summary: counts patch cards"
assert_match 'Strategy7\(Adversarial-input\):2' "$wc_by_strat" \
  "work-card refresh summary: formats strategy histogram"
assert_match 'unclaimed:2' "$wc_by_status" "work-card refresh summary: status histogram"
refresh_src="$(audit_extract_function refresh_structured_work_cards)"
assert_match 'work_card_refresh_summary "\$work_file" "\$patch_file"' "$refresh_src" \
  "work-card refresh: log summary delegated to single-pass helper"
assert_not_match 'wc -l < "\$work_file"|sort \| uniq -c' "$refresh_src" \
  "work-card refresh: avoids repeated count/histogram scans"

# Iteration progress snapshot replaces four separate before/after counters.
# The structured path must count suffixed CRASH-* / FIND-* statuses as
# actionable, matching the state-template contract and avoiding dry-streak
# false negatives after a real result row lands.
rm -rf "$RESULTS_DIR/crashes" "$RESULTS_DIR/findings" "$RESULTS_DIR/state"
mkdir -p "$RESULTS_DIR/crashes/CRASH-001-1" \
         "$RESULTS_DIR/crashes/CRASH-002-pending" \
         "$RESULTS_DIR/findings/FIND-001-test"
touch "$RESULTS_DIR/crashes/CRASH-002-pending/.promotion_pending"
cat > "$(state_file_path 1)" <<'EOF'
| 1 | H1 | src/a.c | shape | guard | bounds | S1 | NEEDS_TESTCASE |
| 2 | H2 | src/b.c | shape | guard | bounds | S1 | CRASH-001 |
EOF
cat > "$(state_file_path 2)" <<'EOF'
| 1 | H3 | src/c.c | shape | guard | bounds | S1 | FIND-001 |
| 2 | H4 | src/d.c | shape | guard | bounds | S1 | ENV-BLOCKED |
EOF
snapshot=$(count_iteration_progress_snapshot)
assert_match '^confirmed_findings=1$' "$snapshot" "iteration snapshot: markdown path counts confirmed findings"
assert_match '^security_crashes=1$' "$snapshot" "iteration snapshot: markdown path excludes promotion-pending crashes"
assert_match '^actionable=3$' "$snapshot" "iteration snapshot: markdown path counts actionable state once"
assert_match '^env_blocked=1$' "$snapshot" "iteration snapshot: markdown path counts env-blocked state once"
confirmed=0 crashes=0 actionable=0 blocked=0
load_iteration_progress_snapshot confirmed crashes actionable blocked
assert_eq "1" "$confirmed" "iteration snapshot loader: confirmed findings assigned"
assert_eq "1" "$crashes" "iteration snapshot loader: crash candidates assigned"
assert_eq "3" "$actionable" "iteration snapshot loader: actionable assigned"
assert_eq "1" "$blocked" "iteration snapshot loader: env-blocked assigned"

mkdir -p "$RESULTS_DIR/state"
cat > "$RESULTS_DIR/state/hypotheses.jsonl" <<'EOF'
{"id":"H1","agent":"1","status":"NEEDS_TESTCASE","file":"src/a.c"}
{"id":"H2","agent":"1","status":"CRASH-001","file":"src/b.c"}
{"id":"H3","agent":"2","status":"FIND-LOWPRIO","file":"src/c.c"}
{"id":"H4","agent":"2","status":"ENV-BLOCKED","file":"src/d.c"}
{"id":"H5","agent":"2","status":"DISCARDED","file":"src/e.c"}
EOF
snapshot=$(count_iteration_progress_snapshot)
assert_match '^actionable=3$' "$snapshot" "iteration snapshot: structured path counts suffixed CRASH/FIND statuses"
assert_match '^env_blocked=1$' "$snapshot" "iteration snapshot: structured path counts ENV-BLOCKED rows"

rm -rf "$RESULTS_DIR/crashes" "$RESULTS_DIR/findings" "$RESULTS_DIR/state"
mkdir -p "$RESULTS_DIR/crashes/CRASH-001-1" "$RESULTS_DIR/crashes/CRASH-002-1" \
         "$RESULTS_DIR/findings/FIND-001-a" "$RESULTS_DIR/findings/FIND-002-a"
for d in "$RESULTS_DIR"/crashes/CRASH-00{1,2}-1; do
  cat > "$d/sanitizer.txt" <<'EOF'
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
    #0 0x1 in tool_resolve_entry catalog.c:42
    #1 0x2 in app_parse app.c:10
SUMMARY: AddressSanitizer: heap-buffer-overflow catalog.c:42 in tool_resolve_entry
EOF
  cat > "$d/REPORT.md" <<'EOF'
# Crash report

Strategy: S7
Boundary: library-api
Caller controls: bytes
Trigger source: testcase
EOF
done
for d in "$RESULTS_DIR"/findings/FIND-00{1,2}-a; do
  cat > "$d/report.md" <<'EOF'
# Finding report

Location: src/catalog.c:42
Issue class: memory-safety
Strategy: S7
Boundary: library-api
Caller controls: bytes
Trigger source: testcase
EOF
done
snapshot=$(count_iteration_progress_snapshot)
assert_match '^security_crashes=2$' "$snapshot" "iteration snapshot: raw crash dirs still counted"
assert_match '^security_crash_roots=1$' "$snapshot" "iteration snapshot: duplicate crash dirs collapse to one root cause"
assert_match '^confirmed_findings=2$' "$snapshot" "iteration snapshot: raw finding dirs still counted"
assert_match '^confirmed_finding_roots=1$' "$snapshot" "iteration snapshot: duplicate finding dirs collapse to one root cause"
finding_roots=0 crash_roots=0
load_iteration_progress_snapshot _c _sc _a _e finding_roots crash_roots
assert_eq "1" "$finding_roots" "iteration root loader: finding roots assigned"
assert_eq "1" "$crash_roots" "iteration root loader: crash roots assigned"

# The clusterer runs inside per-iteration accounting, so its call must be
# time-bounded — an unbounded re-cluster over thousands of dirs would stall
# the loop. On timeout the caller falls back to the raw dir count.
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'audit_timeout_run "\$cluster_timeout" python3 "\$tool" "\$root" --json' "root-count clusterer call is time-bounded"

# The gemini backend is no longer capped to a conservative 1-agent
# default — it takes the same generic pool as every other backend and is
# tuned with NUM_AGENTS. The old GEMINI_DEFAULT_AGENTS special-case must
# stay gone (a period-quota failure is concurrency-independent, so the cap
# never prevented it; RAM auto-tune + handle_rate_limit_backoff cover the rest).
assert_file_not_contains "$SCRIPT_ROOT/bin/audit" 'GEMINI_DEFAULT_AGENTS' "backend: gemini has no special-case agent cap"
assert_file_not_contains "$SCRIPT_ROOT/bin/audit" 'larger pools self-throttle' "backend: gemini self-throttle rationale removed with the cap"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'timeout.sh target_config.sh' "vcs signature: timeout helper is sourced before prelaunch housekeeping"
# llm_invoke.sh defines llm_agent_flags, which run_agent calls for every
# backend. If the shim is not sourced, every agent launch fails with
# "llm_agent_flags: command not found" and exits 127 (the regression
# observed after commit 2904432).
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'llm_invoke.sh llm_decide.sh' "llm: llm_invoke.sh is sourced before llm_decide.sh so llm_agent_flags is defined when run_agent calls it"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'AUDIT_VCS_SIGNATURE_TIMEOUT:-5' "vcs signature: timeout has a bounded default"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'audit_timeout_run "\$vcs_timeout" git -C "\$TARGET_ROOT" status --porcelain --untracked-files=no' "vcs signature: git status is bounded"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'audit_timeout_run "\$vcs_timeout" hg -R "\$TARGET_ROOT" status -mard' "vcs signature: hg status is bounded"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'RATE_LIMIT_DEFAULT_BACKOFF="\$\{RATE_LIMIT_DEFAULT_BACKOFF:-300\}"' "rate limit: default backoff is configurable"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'RATE_LIMIT_MAX_BACKOFF="\$\{RATE_LIMIT_MAX_BACKOFF:-1800\}"' "rate limit: max backoff is configurable"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'LLM_DECIDE_COUNTER_FILE="\$LOGDIR/\.llm_decisions_harness"' \
  "llm budget: harness counter is scoped to backend logdir"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'export ACTIVE_BACKEND MODEL CLAUDE_BIN CODEX_BIN GEMINI_BIN OPENCODE_BIN' \
  "backend env: backend/model/CLI-binary exported so child llm_decide tools (peer-fix-cards, rank-work rerank) resolve the same backend the audit uses"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'LLM_DECIDE_COUNTER_FILE="\$LOGDIR/\.llm_decisions_\$\{agent_num\}"' \
  "llm budget: agent counters are scoped per agent logdir"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'LLM_DECIDE_MAX_CALLS="\$\{LLM_DECIDE_MAX_CALLS:-1000\}"' \
  "llm budget: default cap allows deeper decisions"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'printf '\''0'\'' > "\$LLM_DECIDE_COUNTER_FILE"' \
  "llm budget: harness counter resets each iteration"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'printf '\''0'\'' > "\$LOGDIR/\.llm_decisions_\$\{i\}"' \
  "llm budget: agent counters reset each iteration"

# --new-target LLM bootstrap: after the deterministic seed, audit runs the
# suggest-threat-model / suggest-peers helpers to replace conservative
# defaults with real starting sections. Must be gated, opt-out-able, and
# non-fatal (the seed is already valid).
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'AUDIT_NEW_TARGET_BOOTSTRAP:-1' \
  "new-target: LLM bootstrap is gated by AUDIT_NEW_TARGET_BOOTSTRAP"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'LLM_DECIDE_DISABLE:-0.*!= "1"' \
  "new-target: only LLM_DECIDE_DISABLE=1 disables bootstrap"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'for _nt_helper in suggest-threat-model suggest-peers' \
  "new-target: bootstrap runs both the threat-model and peers helpers"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'bootstrap skipped \(rc=' \
  "new-target: a failed bootstrap is non-fatal and keeps the conservative seed"
# The bootstrap loop must come AFTER the deterministic seed — the helpers
# edit the target.toml that target_seed_toml writes.
_seed_ln=$(grep -n 'target_seed_toml "\$_nt_root"' "$SCRIPT_ROOT/bin/audit" | head -1 | cut -d: -f1)
_bootstrap_ln=$(grep -n 'for _nt_helper in suggest-threat-model' "$SCRIPT_ROOT/bin/audit" | head -1 | cut -d: -f1)
if [ -n "$_seed_ln" ] && [ -n "$_bootstrap_ln" ] && [ "$_seed_ln" -lt "$_bootstrap_ln" ]; then
  pass "new-target: deterministic seed@${_seed_ln} runs before LLM bootstrap@${_bootstrap_ln}"
else
  fail "new-target: seed must precede bootstrap" "seed=${_seed_ln} bootstrap=${_bootstrap_ln}"
fi

# --new-target exits before TARGET_SLUG is computed; the finishing log
# line must reference NEW_TARGET_SLUG, not the still-empty TARGET_SLUG.
# Previously this printed `bin/audit --target ` with no slug, sending the
# operator down a confused path.
_new_target_log_ln=$(grep -n 'Wrote a starter target config at' \
  "$SCRIPT_ROOT/bin/audit" | head -1 | cut -d: -f1)
if [ -n "$_new_target_log_ln" ]; then
  _line=$(sed -n "${_new_target_log_ln}p" "$SCRIPT_ROOT/bin/audit")
  if grep -q 'bin/audit --target \${NEW_TARGET_SLUG}' <<<"$_line"; then
    pass "new-target: finishing log references NEW_TARGET_SLUG (not TARGET_SLUG)"
  else
    fail "new-target: finishing log must reference \${NEW_TARGET_SLUG}" "$_line"
  fi
fi

# INDEX is populated by configure_active_backend. The script-scope "Agent pool:"
# log uses `tee -a "$INDEX"`, so the script-scope call to configure_active_backend
# MUST come before it. Previously the call was a few lines below the agent-pool
# log block, expanding to `tee -a ""` and emitting
#   tee: '': No such file or directory
# on every audit start. Regression-pin the ordering by line number.
_configure_call_ln=$(grep -n '^configure_active_backend "\$ACTIVE_BACKEND"' \
  "$SCRIPT_ROOT/bin/audit" | head -1 | cut -d: -f1)
_agent_pool_log_ln=$(grep -n '"Agent pool: flat pool of' \
  "$SCRIPT_ROOT/bin/audit" | head -1 | cut -d: -f1)
if [ -n "$_configure_call_ln" ] && [ -n "$_agent_pool_log_ln" ] \
   && [ "$_configure_call_ln" -lt "$_agent_pool_log_ln" ]; then
  pass "INDEX init: configure_active_backend@${_configure_call_ln} runs before agent-pool tee log@${_agent_pool_log_ln}"
else
  fail "INDEX init: configure_active_backend must run before agent-pool tee log to populate \$INDEX" \
    "configure_call_ln=$_configure_call_ln agent_pool_log_ln=$_agent_pool_log_ln"
fi

# ═══════════════════════════════════════════════════════════════
# 4. init_guards_db — creates if absent, no-op if present
# ═══════════════════════════════════════════════════════════════

guards_file="$TEST_TMPDIR/guards-db.md"
rm -f "$guards_file"
init_guards_db "$guards_file"
assert_file_exists "$guards_file" "guards-db created"
assert_file_contains "$guards_file" "Guards Database" "guards-db has header"
assert_file_contains "$guards_file" "Entries" "guards-db has entries section"

# Second call is no-op
echo "CUSTOM" >> "$guards_file"
init_guards_db "$guards_file"
assert_file_contains "$guards_file" "CUSTOM" "guards-db not overwritten"

# ═══════════════════════════════════════════════════════════════
# 4a. Real blocklist helpers tolerate empty defaults under bash -u
# ═══════════════════════════════════════════════════════════════

blocklist_funcs="$(
  audit_extract_function load_blocklist
  audit_extract_function blocklist_description
)"
output=$(
  SUBSYSTEM_BLOCKLIST_FILE="$TEST_TMPDIR/no-such-blocklist" \
  bash -u -c '
    set -u
    SUBSYSTEM_BLOCKLIST_DEFAULT=()
    eval "$1"
    load_blocklist
    printf "desc=%s\n" "$(blocklist_description)"
  ' _ "$blocklist_funcs"
)
assert_eq "desc=" "$output" "blocklist: empty defaults do not trip nounset"

# ═══════════════════════════════════════════════════════════════
# 5. reset_asan_run_counter
# ═══════════════════════════════════════════════════════════════

counter_file="$TEST_TMPDIR/asan_counter"
echo "15" > "$counter_file"
reset_asan_run_counter "$counter_file"
assert_eq "0" "$(cat "$counter_file")" "counter reset to 0"

# ═══════════════════════════════════════════════════════════════
# 5a. _detect_free_ram_mb — portable available-memory detection
# ═══════════════════════════════════════════════════════════════

cat > "$TEST_TMPDIR/meminfo-available" <<'EOF'
MemTotal:       32768000 kB
MemFree:         1000000 kB
MemAvailable:   12345678 kB
Buffers:          200000 kB
Cached:          3000000 kB
EOF
result=$(PROC_MEMINFO="$TEST_TMPDIR/meminfo-available" _detect_free_ram_mb)
assert_eq "12056" "$result" "free ram: Linux MemAvailable is preferred"

cat > "$TEST_TMPDIR/meminfo-fallback" <<'EOF'
MemTotal:       32768000 kB
MemFree:            1024 kB
Buffers:            2048 kB
Cached:             4096 kB
SReclaimable:       1024 kB
Shmem:               512 kB
EOF
result=$(PROC_MEMINFO="$TEST_TMPDIR/meminfo-fallback" _detect_free_ram_mb)
assert_eq "7" "$result" "free ram: Linux fallback approximates available memory"

cat > "$TEST_TMPDIR/meminfo-malformed-available" <<'EOF'
MemTotal:       32768000 kB
MemFree:            1024 kB
MemAvailable:        bad kB
Buffers:            2048 kB
Cached:             4096 kB
SReclaimable:       1024 kB
Shmem:               512 kB
EOF
result=$(PROC_MEMINFO="$TEST_TMPDIR/meminfo-malformed-available" _detect_free_ram_mb)
assert_eq "7" "$result" "free ram: malformed Linux MemAvailable falls back safely"

fake_bin="$TEST_TMPDIR/fake-bin"
mkdir -p "$fake_bin"
cat > "$fake_bin/vm_stat" <<'EOF'
#!/usr/bin/env bash
cat <<'VMSTAT'
Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                                  100.
Pages active:                                  1.
Pages inactive:                              200.
Pages speculative:                            20.
VMSTAT
EOF
chmod +x "$fake_bin/vm_stat"
result=$(PROC_MEMINFO="$TEST_TMPDIR/no-meminfo" PATH="$fake_bin:$PATH" _detect_free_ram_mb)
assert_eq "5" "$result" "free ram: macOS vm_stat uses page size and speculative pages"

cat > "$fake_bin/vm_stat" <<'EOF'
#!/usr/bin/env bash
cat <<'VMSTAT'
Mach Virtual Memory Statistics:
Pages free:                                  256.
Pages inactive:                               0.
VMSTAT
EOF
cat > "$fake_bin/getconf" <<'EOF'
#!/usr/bin/env bash
echo 4096
EOF
chmod +x "$fake_bin/vm_stat" "$fake_bin/getconf"
result=$(PROC_MEMINFO="$TEST_TMPDIR/no-meminfo" PATH="$fake_bin:$PATH" _detect_free_ram_mb)
assert_eq "1" "$result" "free ram: macOS falls back to getconf page size"

# ═══════════════════════════════════════════════════════════════
# 5b. pre-launch exhaustion archives only empty active queues
# ═══════════════════════════════════════════════════════════════

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: src/done
| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |
|---|------------|--------------------|-------------|-----------|---------------------|----------|--------|
| H1 | terminal | f.c:F:1 | shape | gap | bounds | S1 | DISCARDED |
EOF
cat > "$(state_file_path 2)" <<'EOF'
## Primary Subsystem: src/active
| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |
|---|------------|--------------------|-------------|-----------|---------------------|----------|--------|
| H2 | active | g.c:G:2 | shape | gap | bounds | S1 | PENDING |
EOF
printf '2' > "$(agent_strategy_streak_path 1)"
archive_prelaunch_exhausted_states
assert_file_not_exists "$(state_file_path 1)" "prelaunch exhaustion: empty state archived"
assert_file_exists "$RESULTS_DIR/.state_archive/AUDIT_STATE-1.prelaunch-exhausted.test.md" "prelaunch exhaustion: archive copy created"
assert_file_exists "$(state_file_path 2)" "prelaunch exhaustion: active state preserved"
assert_eq "S1" "$(cat "$(agent_strategy_path 1)")" "prelaunch exhaustion: strategy reset"
assert_file_not_exists "$(agent_strategy_streak_path 1)" "prelaunch exhaustion: strategy streak reset"

strategy_no_active=$(
  RESULTS_DIR="$TEST_TMPDIR/strategy-no-active"
  mkdir -p "$RESULTS_DIR"
  state_file_path() { printf '%s/AUDIT_STATE-%s.md' "$RESULTS_DIR" "$1"; }
  structured_state_latest_strategy() { echo "S1"; }
  count_active_hypotheses_for_agent() { echo 0; }
  eval "$(audit_extract_function agent_strategy_path)"
  eval "$(audit_extract_function get_agent_strategy)"
  eval "$(audit_extract_function set_agent_strategy)"
  set_agent_strategy 1 "S3"
  get_agent_strategy 1
)
assert_eq "S3" "$strategy_no_active" "strategy tracking file wins for exhausted agents"

strategy_active=$(
  RESULTS_DIR="$TEST_TMPDIR/strategy-active"
  mkdir -p "$RESULTS_DIR"
  state_file_path() { printf '%s/AUDIT_STATE-%s.md' "$RESULTS_DIR" "$1"; }
  structured_state_latest_strategy() { echo "S1"; }
  count_active_hypotheses_for_agent() { echo 1; }
  eval "$(audit_extract_function agent_strategy_path)"
  eval "$(audit_extract_function get_agent_strategy)"
  eval "$(audit_extract_function set_agent_strategy)"
  set_agent_strategy 1 "S3"
  get_agent_strategy 1
)
assert_eq "S1" "$strategy_active" "active hypothesis strategy wins over pending rotation"

# ═══════════════════════════════════════════════════════════════
# 5c. backend-neutral resume state gates
# ═══════════════════════════════════════════════════════════════

resume_state_write 1 session_id "session-new"
resume_state_write 1 backend "codex"
resume_state_write 1 mode "generic"
resume_state_write 1 subsystem "src/parser"
resume_state_write 1 strategy "S3"
resume_state_write 1 card "WORK-1"
resume_state_write 1 dry_count "1"
printf 'legacy-session' > "$LOGDIR/.session_id_1"
printf 'legacy-sub' > "$LOGDIR/.prev_subsystem_1"
assert_eq "session-new" "$(resume_state_read 1 session_id)" "resume state: reads namespaced session id"
clear_agent_resume_state 1
assert_file_not_exists "$(resume_state_path 1 session_id)" "resume state: clear removes namespaced session"
assert_file_not_exists "$(resume_state_path 1 backend)" "resume state: clear removes backend gate"
assert_file_not_exists "$(resume_state_path 1 mode)" "resume state: clear removes mode gate"
assert_file_not_exists "$(resume_state_path 1 subsystem)" "resume state: clear removes subsystem gate"
assert_file_not_exists "$(resume_state_path 1 strategy)" "resume state: clear removes strategy gate"
assert_file_not_exists "$(resume_state_path 1 card)" "resume state: clear removes card gate"
assert_file_not_exists "$(resume_state_path 1 dry_count)" "resume state: clear removes dry counter"
assert_file_not_exists "$LOGDIR/.session_id_1" "resume state: clear removes legacy session id"
assert_file_not_exists "$LOGDIR/.prev_subsystem_1" "resume state: clear removes legacy subsystem"

CLAUDE_RESUME=1 backend_resume_enabled claude
assert_eq 0 $? "resume enabled: claude defaults on"
CODEX_RESUME=1 backend_resume_enabled codex
assert_eq 0 $? "resume enabled: codex defaults on"
OSS_RESUME=0 backend_resume_enabled oss
assert_eq 1 $? "resume enabled: oss defaults off"
OSS_RESUME=1 backend_resume_enabled oss
assert_eq 0 $? "resume enabled: oss knob enables resume gate"
OSS_RESUME=0
unset USE_GEMINI_CLI
GEMINI_RESUME=1 backend_resume_enabled gemini
assert_eq 1 $? "resume enabled: gemini resume disabled for agy dialect"
USE_GEMINI_CLI=1 GEMINI_RESUME=1 backend_resume_enabled gemini
assert_eq 0 $? "resume enabled: gemini CLI defaults on"
USE_GEMINI_CLI=1 GEMINI_RESUME=0 backend_resume_enabled gemini
assert_eq 1 $? "resume enabled: gemini knob disables resume"
unset USE_GEMINI_CLI
GEMINI_RESUME=1

resume_meta_results="$TEST_TMPDIR/resume-meta-results"
resume_meta_logs="$TEST_TMPDIR/resume-meta-logs"
saved_results_dir="$RESULTS_DIR"
saved_logdir="$LOGDIR"
saved_raw_dir="${RAW_DIR:-}"
RESULTS_DIR="$resume_meta_results"
LOGDIR="$resume_meta_logs"
RAW_DIR="$resume_meta_logs/.raw"
mkdir -p "$RESULTS_DIR/state" "$RAW_DIR"
cat > "$RESULTS_DIR/state/hypotheses.jsonl" <<'EOF'
{"id":"H-old","agent":"1","card_id":"WORK-old","status":"DISCARDED","file":"old.c:f:1","strategy":"S1"}
{"id":"H-live","agent":"1","card_id":"WORK-live","status":"NEEDS_TESTCASE","file":"src/parser/token.c:parse:42","strategy":"S3"}
EOF
assert_eq "WORK-live" "$(agent_active_card_id 1)" "resume gate: active card id comes from structured state"
touch -t 202605020100.00 "$RAW_DIR/session_20260502_010000_cold-start-1-generic.log.raw"
assert_match 'cold-start-1-generic.log.raw' "$(latest_agent_resume_raw_log 1)" \
  "resume gate: latest raw log loop tolerates unmatched deep glob"
RESULTS_DIR="$saved_results_dir"
LOGDIR="$saved_logdir"
RAW_DIR="$saved_raw_dir"

assert_match 'RESUME_FALLBACK: Agent' "$run_agent_src" "run_agent: resume fallback path is present"
assert_match 'exec resume' "$run_agent_src" "run_agent: codex resume command is wired"
assert_match '_codex_drop_ephemeral' "$run_agent_src" "run_agent: codex fresh resumable sessions drop --ephemeral"
assert_match '--resume' "$run_agent_src" "run_agent: gemini/claude resume flags are wired"
assert_not_match '--session-id' "$run_agent_src" "run_agent: gemini fresh sessions omit unsupported session-id flag"

# ═══════════════════════════════════════════════════════════════
# 6. extract_usage_field — Claude JSON format
# ═══════════════════════════════════════════════════════════════

if command -v jq >/dev/null 2>&1; then
  cat > "$TEST_TMPDIR/claude_log.jsonl" <<'EOF'
{"usage":{"input_tokens":100,"output_tokens":50}}
{"usage":{"input_tokens":200,"output_tokens":80}}
{"usage":{"input_tokens":300,"output_tokens":120,"cache_read_input_tokens":50}}
EOF
  result=$(extract_usage_field "$TEST_TMPDIR/claude_log.jsonl" "input_tokens")
  assert_eq "300" "$result" "usage: max input_tokens"
  result=$(extract_usage_field "$TEST_TMPDIR/claude_log.jsonl" "output_tokens")
  assert_eq "120" "$result" "usage: max output_tokens"
  result=$(extract_usage_field "$TEST_TMPDIR/claude_log.jsonl" "cached_input_tokens")
  assert_eq "50" "$result" "usage: cached_input_tokens alias"
  result=$(extract_usage_fields "$TEST_TMPDIR/claude_log.jsonl")
  assert_match 'input_tokens=300' "$result" "usage: multi-field input_tokens"
  assert_match 'output_tokens=120' "$result" "usage: multi-field output_tokens"
  assert_match 'cached_input_tokens=50' "$result" "usage: multi-field cached_input_tokens"
  assert_match 'total_tokens=420' "$result" "usage: multi-field total_tokens"

  # Missing file
  result=$(extract_usage_field "$TEST_TMPDIR/nonexistent.jsonl" "input_tokens")
  assert_eq "" "$result" "usage: missing file → empty"
  result=$(extract_usage_fields "$TEST_TMPDIR/nonexistent.jsonl")
  assert_match '^input_tokens=$' "$result" "usage: multi-field missing file has empty input"
  assert_match '^duration_ms=$' "$result" "usage: multi-field missing file has empty duration"

  # Empty file
  : > "$TEST_TMPDIR/empty.jsonl"
  result=$(extract_usage_field "$TEST_TMPDIR/empty.jsonl" "input_tokens")
  assert_eq "" "$result" "usage: empty file → empty"

  cat > "$TEST_TMPDIR/claude_resume_small.jsonl" <<'EOF'
{"usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":1223180}}
EOF
  cat > "$TEST_TMPDIR/claude_resume_large.jsonl" <<'EOF'
{"usage":{"input_tokens":10,"output_tokens":5,"cache_read_input_tokens":3396667}}
EOF
  CLAUDE_RESUME_CACHE_CAP=2000000 should_disable_resume_for_cache claude "$TEST_TMPDIR/claude_resume_small.jsonl"
  assert_eq 1 $? "resume cap: 1.2M cache stays resumable"
  CLAUDE_RESUME_CACHE_CAP=2000000 should_disable_resume_for_cache claude "$TEST_TMPDIR/claude_resume_large.jsonl"
  assert_eq 0 $? "resume cap: 3.4M cache disables resume"
  CLAUDE_RESUME_CACHE_CAP=1 should_disable_resume_for_cache codex "$TEST_TMPDIR/claude_resume_large.jsonl"
  assert_eq 1 $? "resume cap: non-claude backends ignore Claude cache cap"
  unset CLAUDE_RESUME_CACHE_CAP

  # ═══════════════════════════════════════════════════════════════
  # 7. extract_completed_item_count — Claude tool_use counting
  # ═══════════════════════════════════════════════════════════════

  cat > "$TEST_TMPDIR/claude_tools.jsonl" <<'EOF'
{"message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"ls"}}]}}
{"message":{"content":[{"type":"tool_use","name":"Read","input":{"path":"foo"}}]}}
{"message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"pwd"}}]}}
{"message":{"content":[{"type":"text","text":"hello"}]}}
EOF
  result=$(extract_completed_item_count "$TEST_TMPDIR/claude_tools.jsonl" "command_execution")
  assert_eq "2" "$result" "tool count: 2 Bash invocations"
  result=$(extract_completed_item_count "$TEST_TMPDIR/claude_tools.jsonl" "all_tools")
  assert_eq "3" "$result" "tool count: 3 total tool_use"
  result=$(extract_tool_counts "$TEST_TMPDIR/claude_tools.jsonl")
  assert_match '^command_execution=2$' "$result" "tool count: multi-field Claude Bash invocations"
  assert_match '^all_tools=3$' "$result" "tool count: multi-field Claude total tool_use"

  # Missing file
  result=$(extract_completed_item_count "$TEST_TMPDIR/nonexistent.jsonl" "command_execution")
  assert_eq "0" "$result" "tool count: missing file → 0"
  result=$(extract_tool_counts "$TEST_TMPDIR/nonexistent.jsonl")
  assert_match '^command_execution=0$' "$result" "tool count: multi-field missing file command count"
  assert_match '^all_tools=0$' "$result" "tool count: multi-field missing file total count"

  # ═════════════════════════════════════════════════════════════
  # 7a. normalize_agent_exit_code — Codex completed turns
  # ═════════════════════════════════════════════════════════════

  cat > "$TEST_TMPDIR/codex_completed_with_failed_tool.jsonl" <<'EOF'
{"type":"thread.started","thread_id":"abc"}
{"type":"turn.started"}
{"type":"item.completed","item":{"type":"command_execution","exit_code":2,"status":"failed"}}
{"type":"item.completed","item":{"type":"agent_message","text":"done"}}
{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}
EOF
  result=$(normalize_agent_exit_code codex 5 "$TEST_TMPDIR/codex_completed_with_failed_tool.jsonl")
  assert_eq "0" "$result" "agent exit: codex completed turn normalizes failed tool aggregate status"
  result=$(normalize_agent_exit_code codex 5 "$TEST_TMPDIR/codex_completed_with_failed_tool.jsonl" 0 1 0 0)
  assert_eq "0" "$result" "agent exit: cached codex status flags normalize failed tool aggregate status"

  result=$(normalize_agent_exit_code oss 5 "$TEST_TMPDIR/codex_completed_with_failed_tool.jsonl")
  assert_eq "5" "$result" "agent exit: oss does not use codex turn normalization"

  cat > "$TEST_TMPDIR/gemini_success_result.jsonl" <<'EOF'
{"type":"message","role":"assistant","content":"done","delta":true}
{"type":"result","status":"success","stats":{"tool_calls":2}}
EOF
  result=$(normalize_agent_exit_code gemini 5 "$TEST_TMPDIR/gemini_success_result.jsonl")
  assert_eq "0" "$result" "agent exit: gemini success result normalizes failed tool aggregate status"
  result=$(normalize_agent_exit_code gemini 5 "$TEST_TMPDIR/gemini_success_result.jsonl" 1)
  assert_eq "5" "$result" "agent exit: cached rate-limit flag prevents gemini success normalization"

  cat > "$TEST_TMPDIR/codex_turn_failed.jsonl" <<'EOF'
{"type":"thread.started","thread_id":"abc"}
{"type":"turn.started"}
{"type":"turn.failed","error":{"message":"boom"}}
EOF
  result=$(normalize_agent_exit_code codex 5 "$TEST_TMPDIR/codex_turn_failed.jsonl")
  assert_eq "5" "$result" "agent exit: codex turn.failed preserves non-zero status"
  result=$(normalize_agent_exit_code codex 5 "$TEST_TMPDIR/codex_turn_failed.jsonl" 0 0 1 0)
  assert_eq "5" "$result" "agent exit: cached codex failed flag preserves non-zero status"

  cat > "$TEST_TMPDIR/codex_rate_limited.jsonl" <<'EOF'
{"type":"thread.started","thread_id":"abc"}
{"type":"turn.started"}
{"type":"error","message":"Server returned 429"}
{"type":"turn.completed","usage":{"input_tokens":1}}
EOF
  result=$(normalize_agent_exit_code codex 5 "$TEST_TMPDIR/codex_rate_limited.jsonl")
  assert_eq "5" "$result" "agent exit: codex rate limit preserves non-zero status"
  result=$(normalize_agent_exit_code codex 5 "$TEST_TMPDIR/codex_completed_with_failed_tool.jsonl" 1)
  assert_eq "5" "$result" "agent exit: cached rate-limit flag prevents codex completion normalization"

  result=$(normalize_agent_exit_code claude 5 "$TEST_TMPDIR/codex_completed_with_failed_tool.jsonl")
  assert_eq "5" "$result" "agent exit: non-codex backend does not normalize"

  assert_file_contains "$SCRIPT_ROOT/bin/audit" 'normalize_agent_exit_code "\$ACTIVE_BACKEND" "\$rc" "\$wait_raw"' \
    "agent exit: parent wait loop normalizes Codex aggregate status before warning"

  # ═════════════════════════════════════════════════════════════
  # Transient-rejection detection covers overload (5xx), not just 429,
  # across all backends. A 5xx/overload must read the same as a rate
  # limit so the run rides it out with a backoff instead of mistaking an
  # unreachable backend for "agent explored and found nothing".
  # ═════════════════════════════════════════════════════════════
  # Claude: 529 Overloaded on the terminal result event.
  printf '%s\n' '{"type":"result","is_error":true,"api_error_status":529,"result":"API Error: 529 Overloaded"}' \
    > "$TEST_TMPDIR/claude_529.jsonl"
  if log_has_rate_limit_rejection "$TEST_TMPDIR/claude_529.jsonl"; then
    pass "rate-limit detect: claude 529 overload recognized as transient rejection"
  else
    fail "rate-limit detect: claude 529 overload recognized as transient rejection" "not detected"
  fi
  # Claude: 429 still recognized (regression guard).
  printf '%s\n' '{"type":"result","is_error":true,"api_error_status":429}' \
    > "$TEST_TMPDIR/claude_429.jsonl"
  if log_has_rate_limit_rejection "$TEST_TMPDIR/claude_429.jsonl"; then
    pass "rate-limit detect: claude 429 still recognized"
  else
    fail "rate-limit detect: claude 429 still recognized" "not detected"
  fi
  # Codex: 5xx inside an error event.
  printf '%s\n' '{"type":"error","message":"Server returned 503"}' \
    > "$TEST_TMPDIR/codex_503.jsonl"
  if log_has_rate_limit_rejection "$TEST_TMPDIR/codex_503.jsonl"; then
    pass "rate-limit detect: codex 5xx server error recognized as transient rejection"
  else
    fail "rate-limit detect: codex 5xx server error recognized as transient rejection" "not detected"
  fi
  # Gemini: 5xx in a gemini-cli transcript (dialect marker + status).
  printf '%s\n%s\n' \
    '{"type":"init","model":"gemini-3.1-pro"}' \
    'Attempt 2 failed with status 500. Retrying.' \
    > "$TEST_TMPDIR/gemini_500.jsonl"
  if log_has_rate_limit_rejection "$TEST_TMPDIR/gemini_500.jsonl"; then
    pass "rate-limit detect: gemini 5xx overload recognized as transient rejection"
  else
    fail "rate-limit detect: gemini 5xx overload recognized as transient rejection" "not detected"
  fi
  # No false positive: a 5xx mentioned in prose tool output (no structured
  # api_error_status field, not inside an error event) must NOT match.
  printf '%s\n%s\n' \
    '{"type":"result","is_error":false,"subtype":"success"}' \
    '{"type":"user","message":{"content":[{"type":"tool_result","content":"curl said: HTTP 503 Service Unavailable from example.com"}]}}' \
    > "$TEST_TMPDIR/clean_with_503_prose.jsonl"
  if log_has_rate_limit_rejection "$TEST_TMPDIR/clean_with_503_prose.jsonl"; then
    fail "rate-limit detect: prose '503' in tool output is not a rejection" "false positive"
  else
    pass "rate-limit detect: prose '503' in tool output is not a rejection"
  fi
  # No false positive, GEMINI path: a gemini-dialect session whose *tool
  # output* contains overload-shaped text (status:500 / UNAVAILABLE) must NOT
  # be classified as a backend rejection — detection is event-scoped.
  printf '%s\n%s\n' \
    '{"type":"init","model":"gemini-3.1-pro"}' \
    '{"type":"user","message":{"content":[{"type":"tool_result","content":"grep hit: if (code == 503 || status:500) return UNAVAILABLE;"}]}}' \
    > "$TEST_TMPDIR/gemini_tooloutput_503.jsonl"
  if log_has_rate_limit_rejection "$TEST_TMPDIR/gemini_tooloutput_503.jsonl"; then
    fail "rate-limit detect: gemini tool-output 5xx text is not a backend rejection" "false positive"
  else
    pass "rate-limit detect: gemini tool-output 5xx text is not a backend rejection"
  fi
  # SIGPIPE robustness: a 5xx in an error event near the TOP of a very large
  # raw log must still be detected (the old grep|grep -q could SIGPIPE the
  # producer under pipefail and miss it). Detection now streams through the
  # Python parser, so a match early in a big file is found regardless of size.
  {
    printf '%s\n' '{"type":"error","message":"Server returned 503"}'
    for _n in $(seq 1 40000); do
      printf '%s\n' '{"type":"assistant","message":{"content":[{"type":"text","text":"benign padding line"}]}}'
    done
  } > "$TEST_TMPDIR/codex_big_503.jsonl"
  if log_has_rate_limit_rejection "$TEST_TMPDIR/codex_big_503.jsonl"; then
    pass "rate-limit detect: 5xx near top of a large log is detected (no SIGPIPE false negative)"
  else
    fail "rate-limit detect: 5xx near top of a large log is detected (no SIGPIPE false negative)" "missed"
  fi

  # ═════════════════════════════════════════════════════════════
  # Sustained-overload halt (#3): after MAX_RATE_LIMIT_BACKOFFS consecutive
  # backoffs, handle_rate_limit_backoff returns 2 so the caller stops with a
  # BACKEND_UNAVAILABLE outcome instead of burning the budget or misreading
  # the run as a clean exhaustion. A recovery iteration resets the streak.
  # Isolated in a subshell so the stubs/globals don't leak.
  (
    INDEX=/dev/null
    ACTIVE_BACKEND=claude
    RATE_LIMIT_DEFAULT_BACKOFF=0   # no real sleep
    RATE_LIMIT_MAX_BACKOFF=1800
    MAX_RATE_LIMIT_BACKOFFS=2
    RATE_LIMIT_BACKOFF_STREAK=0
    persist_rate_limit_cooldown() { :; }
    log() { :; }
    fmt_secs() { printf '%ss' "$1"; }
    # Overload present this iteration → "unknown" reset → default backoff.
    _iteration_provider_status() { printf 'rate_limit=1\nissue=transient\nreset_at=unknown\n'; }

    rc=0; handle_rate_limit_backoff ts1 || rc=$?
    [ "$rc" -eq 0 ] && [ "$RATE_LIMIT_BACKOFF_STREAK" -eq 1 ] \
      && echo "B1_OK" || echo "B1_BAD rc=$rc streak=$RATE_LIMIT_BACKOFF_STREAK"
    rc=0; handle_rate_limit_backoff ts2 || rc=$?
    [ "$rc" -eq 2 ] && [ "$RATE_LIMIT_BACKOFF_STREAK" -eq 2 ] \
      && echo "B2_HALT" || echo "B2_BAD rc=$rc streak=$RATE_LIMIT_BACKOFF_STREAK"

    # Recovery: no rejection → streak resets, returns 1 (proceed normally).
    _iteration_provider_status() { printf 'rate_limit=0\nissue=none\nreset_at=\n'; }
    rc=0; handle_rate_limit_backoff ts3 || rc=$?
    [ "$rc" -eq 1 ] && [ "$RATE_LIMIT_BACKOFF_STREAK" -eq 0 ] \
      && echo "RECOVER_OK" || echo "RECOVER_BAD rc=$rc streak=$RATE_LIMIT_BACKOFF_STREAK"
  ) > "$TEST_TMPDIR/rl_streak.out" 2>/dev/null
  assert_match 'B1_OK' "$(cat "$TEST_TMPDIR/rl_streak.out")" \
    "sustained halt: first overload backoff returns 0 (continue) and bumps the streak"
  assert_match 'B2_HALT' "$(cat "$TEST_TMPDIR/rl_streak.out")" \
    "sustained halt: streak at MAX_RATE_LIMIT_BACKOFFS returns 2 (BACKEND_UNAVAILABLE)"
  assert_match 'RECOVER_OK' "$(cat "$TEST_TMPDIR/rl_streak.out")" \
    "sustained halt: a clean iteration resets the backoff streak"

  (
    # The scan globs session_<ts>_*.log.raw, so a refill's -rN log is covered
    # with no agent enumeration (NUM_AGENTS is irrelevant to the detector).
    RAW_DIR="$TEST_TMPDIR/refill-raw"
    mkdir -p "$RAW_DIR"
    cat > "$RAW_DIR/session_tsref_deep_investigation-1-generic-r1.log.raw" <<'JSON'
{"type":"result","api_error_status":429}
{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":2000}}
JSON
    status="$(_iteration_provider_status tsref 2>/dev/null || true)"
    reset="$(_provider_status_value "$status" reset_at)"
    issue="$(_provider_status_value "$status" issue)"
    printf 'reset=%s issue=%s\n' "$reset" "$issue"
  ) > "$TEST_TMPDIR/refill-rate-limit.out" 2>/dev/null
  assert_match 'reset=2000 issue=capacity_limited' "$(cat "$TEST_TMPDIR/refill-rate-limit.out")" \
    "rate limit: iteration detector scans refill raw logs (-rN), not only initial agent logs"

  # Call sites stop the run (break) on the sustained-halt return code.
  assert_file_contains "$SCRIPT_ROOT/bin/audit" 'handle_rate_limit_backoff "\$timestamp" 2>/dev/null \|\| rl_rc=\$\?' \
    "sustained halt: call sites capture the backoff return code set-e-safely"
  assert_file_contains "$SCRIPT_ROOT/bin/audit" 'MAX_RATE_LIMIT_BACKOFFS="\$\{MAX_RATE_LIMIT_BACKOFFS:-6\}"' \
    "sustained halt: consecutive-backoff cap is configurable"

  # ═════════════════════════════════════════════════════════════
  # Session-recovery pause: an account/session usage limit (any backend — this
  # subshell uses codex to prove it is not Claude-specific) waits out the reset
  # window (excluded from the productive budget) instead of the short backoff,
  # does NOT count as an unhealthy-backend streak, and stops as
  # backend-unavailable once the cumulative pause cap is spent.
  (
    INDEX=/dev/null
    LOGDIR="$TEST_TMPDIR"
    ACTIVE_BACKEND=codex
    SESSION_PAUSE_CHUNK=7            # re-probe step; sleep is stubbed out below
    SESSION_PAUSE_MAX_TOTAL=100
    SESSION_PAUSED_TOTAL=0
    RATE_LIMIT_BACKOFF_STREAK=5
    sleep() { :; }
    log() { :; }
    fmt_secs() { printf '%ss' "$1"; }
    audit_format_epoch_local() { printf 'sometime'; }
    mark_run_quality() { :; }
    mark_backend_unavailable() { echo UNAVAIL > "$TEST_TMPDIR/sp_unavail"; }
    clear_rate_limit_cooldown() { :; }
    persist_rate_limit_cooldown() { :; }
    # Unknown reset → one 7s chunk of pause (sleep stubbed), streak reset, rc 0.
    _iteration_provider_status() { printf 'rate_limit=1\nissue=capacity_limited\nreset_at=unknown\n'; }
    rc=0; handle_rate_limit_backoff ts1 || rc=$?
    [ "$rc" -eq 0 ] && [ "$RATE_LIMIT_BACKOFF_STREAK" -eq 0 ] \
      && echo "PAUSE_OK paused=$SESSION_PAUSED_TOTAL" \
      || echo "PAUSE_BAD rc=$rc streak=$RATE_LIMIT_BACKOFF_STREAK"
    # Cumulative cap spent → stops as backend-unavailable.
    SESSION_PAUSED_TOTAL=100
    rc=0; session_recovery_pause unknown || rc=$?
    [ "$rc" -eq 2 ] && [ -f "$TEST_TMPDIR/sp_unavail" ] \
      && echo "BUDGET_HALT" || echo "BUDGET_BAD rc=$rc"
  ) > "$TEST_TMPDIR/sp.out" 2>/dev/null
  assert_match 'PAUSE_OK paused=7' "$(cat "$TEST_TMPDIR/sp.out")" \
    "session pause: capacity limit pauses, resets the backoff streak, returns 0 (continue)"
  assert_match 'BUDGET_HALT' "$(cat "$TEST_TMPDIR/sp.out")" \
    "session pause: cumulative pause cap spent returns 2 (backend-unavailable)"
  assert_file_contains "$SCRIPT_ROOT/bin/audit" 'Press Ctrl\+C to stop waiting' \
    "session pause: unknown-reset pause tells the user how to stop waiting"

  # Productive-wall deadline excludes paused time and is wired at the loop top.
  assert_file_contains "$SCRIPT_ROOT/bin/audit" '_wall_now - RUN_START_EPOCH - SESSION_PAUSED_TOTAL' \
    "session pause: productive wall deadline subtracts paused time"
  # bin/benchmark always hands the cell its productive budget and widens the
  # outer wall timeout by the pause backstop (Finding 1: no opt-out overrun).
  assert_file_contains "$SCRIPT_ROOT/bin/benchmark" 'AUDIT_WALL_BUDGET_SECS=\$BUDGET_WALL' \
    "session pause: benchmark passes the per-cell productive budget to bin/audit"
  assert_file_contains "$SCRIPT_ROOT/bin/benchmark" 'BUDGET_WALL \+ SESSION_PAUSE_BACKSTOP' \
    "session pause: benchmark widens the outer wall timeout by the pause backstop"

  # ═════════════════════════════════════════════════════════════
  # 7b. extract_usage_field — agy (gemini) plain-text estimator
  # ═════════════════════════════════════════════════════════════
  # extract_usage_field now delegates to lib/llm_usage.py — the same
  # estimator the benchmark uses. For an agy plain-text transcript with
  # no usage telemetry, output_tokens is estimated from assistant prose
  # length (chars/4). This output-side signal is load-bearing: it keeps
  # the dead-streak gate (bin/audit ~L5935) from false-flagging
  # productive S2/S3/S5/S8 source-only sessions that wrote a FIND but
  # ran no ASan probe.
  #
  # input_tokens stays 0 unless the caller passes a prompt path (audit
  # does for live sessions; this minimal test does not).

  printf 'Here is the agy reply in plain prose, with no JSON usage block.\nIt is several lines long so the byte-count estimator returns a nonzero output.\n' \
    > "$TEST_TMPDIR/gemini_plain.log"
  ACTIVE_BACKEND=gemini result=$(extract_usage_field "$TEST_TMPDIR/gemini_plain.log" "input_tokens")
  assert_eq "0" "$result" "usage: agy plain-text input_tokens stays 0 without a prompt path"
  ACTIVE_BACKEND=gemini result=$(extract_usage_field "$TEST_TMPDIR/gemini_plain.log" "output_tokens")
  if [ -z "$result" ] || [ "$result" -le 0 ] 2>/dev/null; then
    fail "usage: agy plain-text output_tokens must estimate > 0 (regression: tokens=0 silent pin)" "got '$result'"
  else
    pass "usage: agy plain-text output_tokens estimates > 0 (regression: tokens=0 silent pin)"
  fi
  ACTIVE_BACKEND=gemini result=$(extract_usage_fields "$TEST_TMPDIR/gemini_plain.log")
  assert_match '^input_tokens=0$' "$result" "usage: multi-field agy input_tokens stays 0 without prompt"
  if ! printf '%s\n' "$result" | grep -Eq '^output_tokens=[1-9][0-9]*$'; then
    fail "usage: multi-field agy output_tokens estimates > 0" "got '$result'"
  else
    pass "usage: multi-field agy output_tokens estimates > 0"
  fi

  # ═════════════════════════════════════════════════════════════
  # 7c. extract_completed_item_count — Gemini tool_use events
  # ═════════════════════════════════════════════════════════════

  cat > "$TEST_TMPDIR/gemini_tools.jsonl" <<'EOF'
{"type":"init","session_id":"x","model":"gemini-3-flash-preview"}
{"type":"tool_use","tool_name":"run_shell_command","tool_id":"t1","parameters":{"command":"ls"}}
{"type":"tool_use","tool_name":"read_file","tool_id":"t2","parameters":{"path":"foo"}}
{"type":"tool_use","tool_name":"run_shell_command","tool_id":"t3","parameters":{"command":"pwd"}}
{"type":"message","role":"assistant","content":"done","delta":true}
EOF
  result=$(extract_completed_item_count "$TEST_TMPDIR/gemini_tools.jsonl" "command_execution")
  assert_eq "2" "$result" "tool count: 2 gemini run_shell_command invocations"
  result=$(extract_completed_item_count "$TEST_TMPDIR/gemini_tools.jsonl" "all_tools")
  assert_eq "3" "$result" "tool count: 3 gemini tool_use total"
  result=$(extract_tool_counts "$TEST_TMPDIR/gemini_tools.jsonl")
  assert_match '^command_execution=2$' "$result" "tool count: multi-field Gemini shell invocations"
  assert_match '^all_tools=3$' "$result" "tool count: multi-field Gemini total tool_use"
else
  pass "jq not available — skipping usage extraction tests"
  pass "jq not available — skipping tool count tests"
fi

cat > "$TEST_TMPDIR/mixed_backend_tools.jsonl" <<'EOF'
{"type":"item.completed","item":{"type":"command_execution","command":"ls"}}
{"message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"pwd"}},{"type":"tool_use","name":"Read","input":{"path":"foo"}}]}}
{"type":"tool_use","tool_name":"run_shell_command","tool_id":"g1","parameters":{"command":"bin/probe scratch-1/t.c"}}
{"type":"tool_use","tool_name":"read_file","tool_id":"g2","parameters":{"path":"foo"}}
{"type":"tool_use","part":{"type":"tool","tool":"bash","callID":"o1","state":{"status":"completed","input":{"command":"bin/probe scratch-1/opencode.c"},"output":"HIT"}}}
{"type":"tool_use","part":{"type":"tool","tool":"read","callID":"o2","state":{"status":"completed","input":{"filePath":"targets/sample/main.c"},"output":"source"}}}
EOF
result=$(extract_completed_item_count "$TEST_TMPDIR/mixed_backend_tools.jsonl" "command_execution")
assert_eq "4" "$result" "tool count: command executions are parsed through audit_helpers.py"
result=$(extract_total_tool_uses "$TEST_TMPDIR/mixed_backend_tools.jsonl")
assert_eq "7" "$result" "tool count: total tool uses are parsed through audit_helpers.py"
result=$(extract_tool_counts "$TEST_TMPDIR/mixed_backend_tools.jsonl")
assert_match '^command_execution=4$' "$result" "tool count: one-pass mixed command executions"
assert_match '^all_tools=7$' "$result" "tool count: one-pass mixed total tool uses"

# ═══════════════════════════════════════════════════════════════
# 7d. extract_waste_telemetry — backend-neutral output attribution
# ═══════════════════════════════════════════════════════════════

big_output=$(head -c 9000 < /dev/zero | tr '\0' 'X')

cat > "$TEST_TMPDIR/codex_waste.jsonl" <<EOF
{"type":"item.completed","item":{"type":"command_execution","command":"/bin/zsh -lc 'ls -l output/foo/codex/results/scratch-1'","aggregated_output":"abc"}}
{"type":"item.completed","item":{"type":"command_execution","command":"bin/probe scratch-1/testcase.html","aggregated_output":"$big_output"}}
EOF
result=$(extract_waste_telemetry "$TEST_TMPDIR/codex_waste.jsonl")
assert_match 'tool_bytes=9003' "$result" "waste: codex sums command output bytes"
assert_match 'max_output=9000' "$result" "waste: codex records largest output"
assert_match 'over8k=1' "$result" "waste: codex counts oversized outputs"
assert_match 'native_tools=Read:0,Grep:0,Glob:0' "$result" "waste: codex has no Claude native tools"
assert_match 'top_cmds=ls:1,probe:1' "$result" "waste: codex normalizes command patterns"
assert_match 'largest="probe: bin/probe scratch-1/testcase.html"' "$result" "waste: codex names largest command"

cat > "$TEST_TMPDIR/codex_error_message_string.jsonl" <<EOF
{"type":"item.completed","item":{"type":"command_execution","command":"sed -n '1,20p' file.cc","aggregated_output":"abc"}}
{"type":"error","message":"backend rejected the turn"}
{"type":"turn.failed","error":{"message":"backend rejected the turn"}}
EOF
result=$(extract_waste_telemetry "$TEST_TMPDIR/codex_error_message_string.jsonl")
assert_match 'tool_bytes=3' "$result" "waste: codex error event with string message does not break parser"
assert_not_match 'parser-error' "$result" "waste: codex string message avoids parser-error fallback"

cat > "$TEST_TMPDIR/claude_waste.jsonl" <<EOF
{"type":"assistant","message":{"content":[{"type":"tool_use","id":"r1","name":"Read","input":{"file_path":"targets/foo.c"}},{"type":"tool_use","id":"g1","name":"Grep","input":{"pattern":"Thing"}},{"type":"tool_use","id":"gl1","name":"Glob","input":{"pattern":"*.c"}},{"type":"tool_use","id":"b1","name":"Bash","input":{"command":"grep -R Thing targets/foo.c"}}]}}
{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"b1","content":"abc"},{"type":"tool_result","tool_use_id":"r1","content":"$big_output"}]}}
EOF
result=$(extract_waste_telemetry "$TEST_TMPDIR/claude_waste.jsonl")
assert_match 'tool_bytes=9003' "$result" "waste: claude sums Bash and native tool output"
assert_match 'native_tools=Read:1,Grep:1,Glob:1' "$result" "waste: claude counts native Read/Grep/Glob"
assert_match 'top_cmds=grep:1' "$result" "waste: claude normalizes Bash command patterns"
assert_match 'largest="Read: Read"' "$result" "waste: claude names largest native output"

# The older Antigravity CLI emits plain text in --print mode, so those
# logs carry no JSON tool_use / tool_result events. extract_waste_telemetry
# naturally yields zero counters for agy logs; the parse never reaches a
# JSON branch.
cat > "$TEST_TMPDIR/gemini_waste.txt" <<'EOF'
agy plain stdout — no JSON envelope to count tool bytes against.
EOF
result=$(extract_waste_telemetry "$TEST_TMPDIR/gemini_waste.txt")
assert_match 'tool_bytes=0 max_output=0 over8k=0' "$result" "waste: gemini (agy) plain text → zero summary"

cat > "$TEST_TMPDIR/gemini_cli_waste.jsonl" <<EOF
{"type":"tool_use","tool_name":"run_shell_command","tool_id":"g1","parameters":{"command":"sed -n '1,20p' targets/libxml2/parser.c"}}
{"type":"tool_result","tool_id":"g1","status":"success","output":"abc"}
{"type":"tool_use","tool_name":"run_shell_command","tool_id":"g2","parameters":{"command":"bin/probe scratch-1/testcase.c"}}
{"type":"tool_result","tool_id":"g2","status":"success","output":"$big_output"}
EOF
result=$(extract_waste_telemetry "$TEST_TMPDIR/gemini_cli_waste.jsonl")
assert_match 'tool_bytes=9003' "$result" "waste: gemini stream-json sums tool_result output"
assert_match 'max_output=9000' "$result" "waste: gemini stream-json records largest output"
assert_match 'over8k=1' "$result" "waste: gemini stream-json counts oversized outputs"
assert_match 'top_cmds=sed:1,probe:1' "$result" "waste: gemini stream-json normalizes shell commands"
assert_match 'largest="probe: bin/probe scratch-1/testcase.c"' "$result" "waste: gemini stream-json names largest command"

cat > "$TEST_TMPDIR/opencode_waste.jsonl" <<EOF
{"type":"tool_use","part":{"type":"tool","tool":"bash","callID":"o1","state":{"status":"completed","input":{"command":"sed -n '1,20p' targets/sample/main.c"},"output":"abc"}}}
{"type":"tool_use","part":{"type":"tool","tool":"read","callID":"o2","state":{"status":"completed","input":{"filePath":"targets/sample/main.c"},"output":"$big_output"}}}
{"type":"tool_use","part":{"type":"tool","tool":"bash","callID":"o3","state":{"status":"completed","input":{"command":"bin/probe scratch-1/testcase.c"},"output":"HIT"}}}
EOF
result=$(extract_waste_telemetry "$TEST_TMPDIR/opencode_waste.jsonl")
assert_match 'tool_bytes=9006' "$result" "waste: opencode sums inline tool output"
assert_match 'native_tools=Read:1,Grep:0,Glob:0' "$result" "waste: opencode counts lowercase read as native Read"
assert_match 'top_cmds=sed:1,probe:1' "$result" "waste: opencode normalizes bash commands"
assert_match 'largest="Read: read"' "$result" "waste: opencode names largest native output"

printf '%s\n' 'last message' > "$TEST_TMPDIR/waste-parity.log"
for waste_fixture in codex_waste.jsonl claude_waste.jsonl gemini_cli_waste.jsonl opencode_waste.jsonl; do
  expected_waste=$(extract_waste_telemetry "$TEST_TMPDIR/$waste_fixture")
  actual_waste=$(
    SESSION_SUMMARY_PRINT_WASTE=1 \
    python3 "$SCRIPT_ROOT/lib/audit_log_summary.py" \
      "$TEST_TMPDIR/$waste_fixture" \
      "$TEST_TMPDIR/waste-parity.log" \
      "$TEST_TMPDIR/$waste_fixture.summary.md" \
      "$TEST_TMPDIR/$waste_fixture.index.jsonl"
  )
  assert_eq "$expected_waste" "$actual_waste" "summary: one-pass waste parity for $waste_fixture"
done

result=$(extract_waste_telemetry "$TEST_TMPDIR/no-such-log.jsonl")
assert_match 'tool_bytes=0 max_output=0 over8k=0' "$result" "waste: missing log returns zero summary"
cat > "$TEST_TMPDIR/raw_status.jsonl" <<'EOF'
{"type":"turn.completed"}
{"type":"result","status":"success"}
EOF
raw_status_out=$(extract_raw_status "$TEST_TMPDIR/raw_status.jsonl")
assert_match 'codex_completed=1' "$raw_status_out" "raw-status shell helper: codex completion surfaced"
assert_match 'gemini_success=1' "$raw_status_out" "raw-status shell helper: gemini success surfaced"
raw_status_missing=$(extract_raw_status "$TEST_TMPDIR/no-such-raw-status.jsonl")
assert_match 'rate_limit=0' "$raw_status_missing" "raw-status shell helper: missing log has zero rate-limit flag"

cat > "$TEST_TMPDIR/finish_fields.jsonl" <<'EOF'
{"type":"item.completed","item":{"type":"command_execution","command":"ls","aggregated_output":"x"}}
{"type":"tool_use","tool_name":"run_shell_command","tool_id":"g1","parameters":{"command":"bin/probe scratch-1/t.c"}}
{"type":"tool_use","tool_name":"read_file","tool_id":"g2","parameters":{"path":"foo"}}
{"type":"tool_use","part":{"type":"tool","tool":"bash","callID":"o1","state":{"status":"completed","input":{"command":"bin/probe scratch-1/opencode.c"},"output":"HIT"}}}
{"type":"turn.completed","usage":{"input_tokens":10,"cached_input_tokens":3,"cache_creation_input_tokens":2,"output_tokens":5},"duration_ms":123}
{"type":"result","status":"success"}
EOF
finish_fields=$(extract_finish_fields "$TEST_TMPDIR/finish_fields.jsonl" codex)
assert_match '^input_tokens=10$' "$finish_fields" "finish-fields: input tokens surfaced"
assert_match '^cached_input_tokens=3$' "$finish_fields" "finish-fields: cache-read tokens surfaced"
assert_match '^cache_creation_input_tokens=2$' "$finish_fields" "finish-fields: cache-creation tokens surfaced"
assert_match '^output_tokens=5$' "$finish_fields" "finish-fields: output tokens surfaced"
assert_match '^total_tokens=15$' "$finish_fields" "finish-fields: total tokens matches usage helper"
assert_match '^duration_ms=123$' "$finish_fields" "finish-fields: duration surfaced"
assert_match '^command_execution=3$' "$finish_fields" "finish-fields: command count matches tool helper"
assert_match '^all_tools=4$' "$finish_fields" "finish-fields: total tool count matches tool helper"
assert_match '^codex_completed=1$' "$finish_fields" "finish-fields: codex completion surfaced"
assert_match '^gemini_success=1$' "$finish_fields" "finish-fields: gemini success surfaced"

mkdir -p "$TEST_TMPDIR/bad-helper-root/lib"
cat > "$TEST_TMPDIR/bad-helper-root/lib/audit_helpers.py" <<'PY'
raise SystemExit(1)
PY
old_script_root="$SCRIPT_ROOT"
SCRIPT_ROOT="$TEST_TMPDIR/bad-helper-root"
finish_fields_failed=$(extract_finish_fields "$TEST_TMPDIR/finish_fields.jsonl" codex)
SCRIPT_ROOT="$old_script_root"
assert_match '^command_execution=0$' "$finish_fields_failed" "finish-fields failure: command count has safe default"
assert_match '^rate_limit=$' "$finish_fields_failed" "finish-fields failure: blank rate-limit re-enables shell fallback"
assert_match '^codex_completed=$' "$finish_fields_failed" "finish-fields failure: blank codex completion re-enables shell fallback"
assert_match '^gemini_success=$' "$finish_fields_failed" "finish-fields failure: blank gemini success re-enables shell fallback"

assert_match 'Agent \$_role_display waste: \$\{waste_telemetry\}' "$run_agent_src" "run_agent: writes waste telemetry to index"
assert_match 'finish_fields=\$\(extract_finish_fields "\$raw_logfile" "\$ACTIVE_BACKEND"\)' "$run_agent_src" "run_agent: extracts finish fields in one raw-log read"
assert_not_match 'usage_fields=\$\(extract_usage_fields "\$raw_logfile"\)' "$run_agent_src" "run_agent: avoids separate usage raw-log scan"
assert_not_match 'extract_usage_field "\$raw_logfile" total_tokens' "$run_agent_src" "run_agent: avoids per-field usage raw-log scans"
assert_not_match 'tool_counts=\$\(extract_tool_counts "\$raw_logfile"\)' "$run_agent_src" "run_agent: avoids separate tool-count raw-log scan"
assert_not_match 'extract_completed_item_count "\$raw_logfile" command_execution' "$run_agent_src" "run_agent: avoids per-field tool-count raw-log scans"
assert_not_match 'raw_status=\$\(extract_raw_status "\$raw_logfile"\)' "$run_agent_src" "run_agent: avoids separate raw-status raw-log scan"
assert_match 'raw_codex_completed' "$run_agent_src" "run_agent: passes cached backend status into exit normalization"
assert_match 'normalize_agent_exit_code "\$ACTIVE_BACKEND" "\$exit_code" "\$raw_logfile"' "$run_agent_src" "run_agent: passes cached rate-limit status into exit normalization"
assert_match 'if \[ -z "\$rate_limit_rejected" \]' "$run_agent_src" "run_agent: helper failure re-enables rate-limit fallback"
assert_match 'waste_telemetry=\$\(write_session_log_summary "\$raw_logfile"' "$run_agent_src" "run_agent: gets waste telemetry from summary raw-log pass"
assert_match 'write_session_log_summary "\$raw_logfile"' "$run_agent_src" "run_agent: writes compact log summaries"
assert_match 'pkill -TERM -P "\$watchdog_pid"' "$run_agent_src" "run_agent: watchdog child sleep is killed before watchdog shell"
assert_match 'pkill -TERM -P "\$turncap_pid"' "$run_agent_src" "run_agent: turn-cap child sleep is killed before turn-cap shell"
assert_match 'agent_start_epoch=\$\(date \+%s\)' "$run_agent_src" "run_agent: records agent wall-clock start"
assert_match 'duration_ms=.*agent_start_epoch' "$run_agent_src" "run_agent: duration falls back to measured wall clock"

cat > "$TEST_TMPDIR/session_summary.raw" <<EOF
{"type":"item.completed","item":{"type":"command_execution","command":"bin/probe scratch-1/testcase.html","aggregated_output":"[probe] mode=asan\n=== Run 1/5 ===\nEXECUTION VERIFIED\n"}}
{"type":"item.completed","item":{"type":"command_execution","command":"sed -n '1,20p' parser.c","aggregated_output":"small"}}
EOF
printf '%s\n' 'last message' > "$TEST_TMPDIR/session_summary.log"
summary_waste=$(extract_waste_telemetry "$TEST_TMPDIR/session_summary.raw")
summary_writer_src="$(audit_extract_function write_session_log_summary)"
assert_not_match "sed -n 's/\\^subsystem=//p'" "$summary_writer_src" "summary: prompt metadata stash parsed without per-field sed scans"
assert_match "while IFS='=' read -r stash_key stash_value" "$summary_writer_src" "summary: prompt metadata stash parsed in one shell loop"
# Drop a prompt-meta stash where the finish handler expects it, so the
# index.jsonl row gets the folded fields (subsystem, strategy, launch,
# suggested_subsystem, prompt_tokens_est).
mkdir -p "$LOGDIR"
{
  printf 'subsystem=%s\n' "src/lib"
  printf 'suggested_subsystem=%s\n' "src/net"
  printf 'strategy=%s\n' "S1"
  printf 'prompt_tokens_est=%s\n' "11500"
  printf 'launch=%s\n' "deep_investigation"
} > "$LOGDIR/.prompt_meta_2"
computed_summary_waste=$(write_session_log_summary \
  "$TEST_TMPDIR/session_summary.raw" \
  "$TEST_TMPDIR/session_summary.log" \
  "$TEST_TMPDIR/session_summary.computed.summary.md" \
  "$TEST_TMPDIR/computed-index.jsonl" \
  "analysis" "2" "codex" "gpt-test" "generic" "0" \
  "123" "1000" "900" "50" "1050" "222" "2" "2" "" "50")
assert_eq "$summary_waste" "$computed_summary_waste" "summary: shell wrapper returns computed waste when no precomputed waste is passed"
write_session_log_summary \
  "$TEST_TMPDIR/session_summary.raw" \
  "$TEST_TMPDIR/session_summary.log" \
  "$TEST_TMPDIR/session_summary.summary.md" \
  "$TEST_TMPDIR/index.jsonl" \
  "analysis" "2" "codex" "gpt-test" "generic" "0" \
  "123" "1000" "900" "50" "1050" "222" "2" "2" "$summary_waste"
assert_file_exists "$TEST_TMPDIR/session_summary.summary.md" "summary: markdown sidecar written"
assert_file_exists "$TEST_TMPDIR/index.jsonl" "summary: index.jsonl written"
# *.summary.json was removed — its fields were verified byte-identical
# to the index.jsonl row, so we assert against the index now and ensure
# the json sidecar is NOT written.
[ ! -f "$TEST_TMPDIR/session_summary.summary.json" ] \
  && pass "summary: json sidecar not written (redundant with index.jsonl)" \
  || fail "summary: json sidecar not written" "json sidecar still present"
python3 - "$TEST_TMPDIR/index.jsonl" <<'PY'
import json, sys
rows = [json.loads(line) for line in open(sys.argv[1], encoding="utf-8") if line.strip()]
row = rows[-1]
assert row["backend"] == "codex"
assert row["tokens"]["cached_input"] == 900
assert row["tools"]["output_bytes"] > 0
assert row["tools"]["top_commands"]["probe"] == 1
assert row["probe"]["commands"] == 1
assert row["probe"]["asan_invocations"] == 1
assert row["probe"]["verdicts"]["clean"] == 1
assert "hit" not in row["probe"]["verdicts"], "HIT is not a real verdict marker; must not be counted"
assert "summary_json" not in row["files"], "files.summary_json field should be dropped from schema"
assert row["files"]["summary_md"] == "session_summary.summary.md"
# Fields folded in from the dropped *.prompt.meta.json sidecar.
assert row["subsystem"] == "src/lib", f"expected subsystem=src/lib, got {row['subsystem']!r}"
assert row["suggested_subsystem"] == "src/net"
assert row["strategy"] == "S1"
assert row["launch"] == "deep_investigation"
assert row["tokens"]["prompt_estimate_build"] == 11500
# Row-size sanity: must stay well under PIPE_BUF (4096) so concurrent
# appends to index.jsonl remain byte-atomic even without the explicit
# flock guard added in audit_log_summary.py. flock is the belt; this is
# the suspenders.
row_size = len(json.dumps(row, sort_keys=True, separators=(",", ":")))
assert row_size < 3500, f"index.jsonl row size {row_size} >= 3500 — splitting unsafe without flock"
PY
assert_eq "0" "$?" "summary: index.jsonl row is parseable and excludes summary_json field"
assert_file_contains "$TEST_TMPDIR/session_summary.summary.md" 'Raw log retained for explicit post-mortem use' "summary: markdown tells readers not to default to raw logs"

# Gemini stream-json: a run_shell_command tool_result carrying probe/ASan
# output must feed the probe/verdict scan, exactly like the codex
# command_execution and claude tool_result paths. Without it, gemini runs
# report probe/asan/verdict counts as false-low.
cat > "$TEST_TMPDIR/gemini_probe.jsonl" <<'EOF'
{"type":"tool_use","tool_name":"run_shell_command","tool_id":"g1","parameters":{"command":"bin/probe scratch-1/testcase.html"}}
{"type":"tool_result","tool_id":"g1","status":"success","output":"[probe] mode=asan\n=== Run 1/5 ===\nERROR: ThreadSanitizer: data race\nCRASHES FOUND\n"}
EOF
printf '%s\n' 'last message' > "$TEST_TMPDIR/gemini_probe.log"
write_session_log_summary \
  "$TEST_TMPDIR/gemini_probe.jsonl" \
  "$TEST_TMPDIR/gemini_probe.log" \
  "$TEST_TMPDIR/gemini_probe.summary.md" \
  "$TEST_TMPDIR/gemini_probe.index.jsonl" \
  "analysis" "3" "gemini" "gemini-test" "generic" "0" \
  "0" "0" "0" "0" "0" "0" "0" "0" ""
python3 - "$TEST_TMPDIR/gemini_probe.index.jsonl" <<'PY'
import json, sys
row = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()][-1]
assert row["backend"] == "gemini"
assert row["probe"]["commands"] == 1, row["probe"]
assert row["probe"]["outputs"] >= 1, row["probe"]
assert row["probe"]["asan_invocations"] == 1, row["probe"]
assert row["probe"]["verdicts"]["crash"] >= 1, row["probe"]
assert "hit" not in row["probe"]["verdicts"], row["probe"]
PY
assert_eq "0" "$?" "summary: gemini stream-json run_shell_command output feeds probe/verdict scan"

# OpenCode emits completed shell tool calls as inline tool_use records.
# They must feed the same probe/verdict scan as codex, claude, and gemini
# logs; otherwise OSS runs show false-low probe.commands/asan_invocations.
cat > "$TEST_TMPDIR/opencode_probe.jsonl" <<'EOF'
{"type":"tool_use","part":{"type":"tool","tool":"bash","callID":"o1","state":{"status":"completed","input":{"command":"bin/probe scratch-1/testcase.c"},"output":"[probe] mode=generic\nASAN_RUN_HEADER: sanitizer=asan runs=2 mode=generic testcase=scratch-1/testcase.c\n=== Run 1/2 ===\n=== Run 2/2 ===\n[probe] verdict=CRASH\n"}}}
EOF
printf '%s\n' 'last message' > "$TEST_TMPDIR/opencode_probe.log"
write_session_log_summary \
  "$TEST_TMPDIR/opencode_probe.jsonl" \
  "$TEST_TMPDIR/opencode_probe.log" \
  "$TEST_TMPDIR/opencode_probe.summary.md" \
  "$TEST_TMPDIR/opencode_probe.index.jsonl" \
  "analysis" "4" "oss" "opencode-test" "generic" "0" \
  "0" "0" "0" "0" "0" "0" "0" "0" ""
python3 - "$TEST_TMPDIR/opencode_probe.index.jsonl" <<'PY'
import json, sys
row = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()][-1]
assert row["backend"] == "oss"
assert row["probe"]["commands"] == 1, row["probe"]
assert row["probe"]["outputs"] == 1, row["probe"]
assert row["probe"]["asan_invocations"] == 2, row["probe"]
assert row["probe"]["verdicts"]["crash"] == 1, row["probe"]
assert row["tools"]["observed_command_patterns"]["probe"] == 1, row["tools"]
PY
assert_eq "0" "$?" "summary: OpenCode inline tool_use output feeds probe/verdict scan"

# OSS agents also inspect saved sanitizer artifacts with ordinary shell
# commands. ASAN_RUN_HEADER/verdict markers in that output are probe
# telemetry even when the command itself is not bin/probe.
cat > "$TEST_TMPDIR/opencode_saved_asan.jsonl" <<'EOF'
{"type":"tool_use","part":{"type":"tool","tool":"bash","callID":"o2","state":{"status":"completed","input":{"command":"cat output/sample/oss/results/scratch-7/testcase.asan.txt"},"output":"ASAN_RUN_HEADER: sanitizer=asan runs=1 mode=generic testcase=scratch-7/testcase.c\nNO CRASHES\n2026-06-20T01:02:03Z verdict=CLEAN mode=generic testcase=scratch-7/testcase.c hash=abc runs=1 crashes=0 execs=1\n"}}}
EOF
printf '%s\n' 'last message' > "$TEST_TMPDIR/opencode_saved_asan.log"
write_session_log_summary \
  "$TEST_TMPDIR/opencode_saved_asan.jsonl" \
  "$TEST_TMPDIR/opencode_saved_asan.log" \
  "$TEST_TMPDIR/opencode_saved_asan.summary.md" \
  "$TEST_TMPDIR/opencode_saved_asan.index.jsonl" \
  "analysis" "5" "oss" "opencode-test" "generic" "0" \
  "0" "0" "0" "0" "0" "0" "0" "0" ""
python3 - "$TEST_TMPDIR/opencode_saved_asan.index.jsonl" <<'PY'
import json, sys
row = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()][-1]
assert row["probe"]["commands"] == 0, row["probe"]
assert row["probe"]["outputs"] == 1, row["probe"]
assert row["probe"]["asan_invocations"] == 1, row["probe"]
assert row["probe"]["verdicts"]["clean"] == 1, row["probe"]
assert row["tools"]["observed_command_patterns"]["cat"] == 1, row["tools"]
PY
assert_eq "0" "$?" "summary: OpenCode saved ASan artifact output feeds probe/verdict scan"

cat > "$TEST_TMPDIR/opencode_non_probe_verdict.jsonl" <<'EOF'
{"type":"tool_use","part":{"type":"tool","tool":"bash","callID":"o3","state":{"status":"completed","input":{"command":"cat findings/FIND-001/report.md"},"output":"triage detail: verdict=contract-flag\n"}}}
EOF
printf '%s\n' 'last message' > "$TEST_TMPDIR/opencode_non_probe_verdict.log"
write_session_log_summary \
  "$TEST_TMPDIR/opencode_non_probe_verdict.jsonl" \
  "$TEST_TMPDIR/opencode_non_probe_verdict.log" \
  "$TEST_TMPDIR/opencode_non_probe_verdict.summary.md" \
  "$TEST_TMPDIR/opencode_non_probe_verdict.index.jsonl" \
  "analysis" "6" "oss" "opencode-test" "generic" "0" \
  "0" "0" "0" "0" "0" "0" "0" "0" ""
python3 - "$TEST_TMPDIR/opencode_non_probe_verdict.index.jsonl" <<'PY'
import json, sys
row = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()][-1]
assert row["probe"]["commands"] == 0, row["probe"]
assert row["probe"]["outputs"] == 0, row["probe"]
assert row["probe"]["asan_invocations"] == 0, row["probe"]
assert row["probe"]["verdicts"] == {}, row["probe"]
PY
assert_eq "0" "$?" "summary: unrelated verdict text does not become probe telemetry"

# Raw sanitizer-looking text from an arbitrary helper is not probe telemetry
# unless it carries a probe/sanitizer artifact marker. This avoids filling
# probe.verdicts from copied reports or ad-hoc repro scripts.
cat > "$TEST_TMPDIR/non_probe_asan_text.jsonl" <<'EOF'
{"type":"item.completed","item":{"type":"command_execution","command":"python3 scratch-1/manual-repro.py","aggregated_output":"ERROR: AddressSanitizer: heap-buffer-overflow\nCRASHES FOUND\n"}}
EOF
printf '%s\n' 'last message' > "$TEST_TMPDIR/non_probe_asan_text.log"
write_session_log_summary \
  "$TEST_TMPDIR/non_probe_asan_text.jsonl" \
  "$TEST_TMPDIR/non_probe_asan_text.log" \
  "$TEST_TMPDIR/non_probe_asan_text.summary.md" \
  "$TEST_TMPDIR/non_probe_asan_text.index.jsonl" \
  "analysis" "7" "codex" "gpt-test" "generic" "0" \
  "0" "0" "0" "0" "0" "0" "0" "0" ""
python3 - "$TEST_TMPDIR/non_probe_asan_text.index.jsonl" <<'PY'
import json, sys
row = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()][-1]
assert row["probe"]["commands"] == 0, row["probe"]
assert row["probe"]["outputs"] == 0, row["probe"]
assert row["probe"]["asan_invocations"] == 0, row["probe"]
assert row["probe"]["verdicts"] == {}, row["probe"]
PY
assert_eq "0" "$?" "summary: raw ASan text from non-probe command is not probe telemetry"

# Legacy bin/probe output without a structured header is still probe telemetry
# because the command itself supplies the context for fallback markers.
cat > "$TEST_TMPDIR/legacy_probe_output.jsonl" <<'EOF'
{"type":"item.completed","item":{"type":"command_execution","command":"bin/probe scratch-8/testcase.html","aggregated_output":"=== Run 1/5 ===\nNO CRASHES\n"}}
EOF
printf '%s\n' 'last message' > "$TEST_TMPDIR/legacy_probe_output.log"
write_session_log_summary \
  "$TEST_TMPDIR/legacy_probe_output.jsonl" \
  "$TEST_TMPDIR/legacy_probe_output.log" \
  "$TEST_TMPDIR/legacy_probe_output.summary.md" \
  "$TEST_TMPDIR/legacy_probe_output.index.jsonl" \
  "analysis" "8" "codex" "gpt-test" "generic" "0" \
  "0" "0" "0" "0" "0" "0" "0" "0" ""
python3 - "$TEST_TMPDIR/legacy_probe_output.index.jsonl" <<'PY'
import json, sys
row = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()][-1]
assert row["probe"]["commands"] == 1, row["probe"]
assert row["probe"]["outputs"] == 1, row["probe"]
assert row["probe"]["asan_invocations"] == 1, row["probe"]
assert row["probe"]["verdicts"] == {"clean": 1}, row["probe"]
PY
assert_eq "0" "$?" "summary: legacy bin/probe output keeps fallback verdict telemetry"

# One differential marker is one diff verdict, not two matches for
# DIFFERENTIAL and outputs DIFFER on the same line.
cat > "$TEST_TMPDIR/diff_probe_output.jsonl" <<'EOF'
{"type":"item.completed","item":{"type":"command_execution","command":"cat output/sample/oss/results/scratch-9/testcase.asan.txt","aggregated_output":"ASAN_RUN_HEADER: sanitizer=asan runs=1 mode=js testcase=scratch-9/testcase.js\n[run-asan] DIFFERENTIAL: outputs DIFFER - potential issue\n"}}
EOF
printf '%s\n' 'last message' > "$TEST_TMPDIR/diff_probe_output.log"
write_session_log_summary \
  "$TEST_TMPDIR/diff_probe_output.jsonl" \
  "$TEST_TMPDIR/diff_probe_output.log" \
  "$TEST_TMPDIR/diff_probe_output.summary.md" \
  "$TEST_TMPDIR/diff_probe_output.index.jsonl" \
  "analysis" "9" "codex" "gpt-test" "generic" "0" \
  "0" "0" "0" "0" "0" "0" "0" "0" ""
python3 - "$TEST_TMPDIR/diff_probe_output.index.jsonl" <<'PY'
import json, sys
row = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()][-1]
assert row["probe"]["outputs"] == 1, row["probe"]
assert row["probe"]["asan_invocations"] == 1, row["probe"]
assert row["probe"]["verdicts"] == {"diff": 1}, row["probe"]
PY
assert_eq "0" "$?" "summary: differential fallback counts one verdict per marker"

# Verdict scanning is robust across backends: an explicit verdict= token is
# honoured case-insensitively, while sanitizer/verdict words embedded in
# ordinary prose (UNCLEAN, "cache HIT", "we MISSED it") must not be counted.
cat > "$TEST_TMPDIR/verdict_robustness.jsonl" <<'EOF'
{"type":"item.completed","item":{"type":"command_execution","command":"bin/probe scratch-9/testcase.c","aggregated_output":"[probe] mode=generic\n[probe] VERDICT=Clean\n"}}
{"type":"item.completed","item":{"type":"command_execution","command":"sed -n '1,40p' notes.txt","aggregated_output":"the run left the tree UNCLEAN; cache HIT rate was high and we MISSED nothing.\n"}}
EOF
printf '%s\n' 'last message' > "$TEST_TMPDIR/verdict_robustness.log"
write_session_log_summary \
  "$TEST_TMPDIR/verdict_robustness.jsonl" \
  "$TEST_TMPDIR/verdict_robustness.log" \
  "$TEST_TMPDIR/verdict_robustness.summary.md" \
  "$TEST_TMPDIR/verdict_robustness.index.jsonl" \
  "analysis" "10" "codex" "gpt-test" "generic" "0" \
  "0" "0" "0" "0" "0" "0" "0" "0" ""
python3 - "$TEST_TMPDIR/verdict_robustness.index.jsonl" <<'PY'
import json, sys
row = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()][-1]
# Explicit VERDICT=Clean wins (case-insensitive) and prose words are ignored.
assert row["probe"]["verdicts"] == {"clean": 1}, row["probe"]
PY
assert_eq "0" "$?" "summary: verdict scan is case-insensitive and ignores prose look-alikes"

cat > "$TEST_TMPDIR/codex_immediate_failed_turn.jsonl" <<EOF
{"type":"thread.started","thread_id":"t1"}
{"type":"turn.started"}
{"type":"error","message":"backend rejected the turn"}
{"type":"turn.failed","error":{"message":"backend rejected the turn"}}
EOF
assert_eq "1" "$(count_structural_refusal_signals "$TEST_TMPDIR/codex_immediate_failed_turn.jsonl")" "refusal signals: codex immediate failed turn is counted"

cat > "$TEST_TMPDIR/codex_mid_session_failed_turn.jsonl" <<EOF
{"type":"thread.started","thread_id":"t1"}
{"type":"turn.started"}
{"type":"item.completed","item":{"type":"command_execution","command":"ls","aggregated_output":"x"}}
{"type":"error","message":"backend rejected the turn"}
{"type":"turn.failed","error":{"message":"backend rejected the turn"}}
EOF
assert_eq "1" "$(count_structural_refusal_signals "$TEST_TMPDIR/codex_mid_session_failed_turn.jsonl")" "refusal signals: codex failed turn after work is counted"

cat > "$TEST_TMPDIR/codex_explicit_refusal.jsonl" <<'EOF'
{"type":"refusal","message":"no"}
{"stop_reason":"refusal","message":"no"}
EOF
assert_eq "2" "$(count_structural_refusal_signals "$TEST_TMPDIR/codex_explicit_refusal.jsonl")" "refusal signals: explicit refusal marker lines are counted"

cat > "$TEST_TMPDIR/codex_brief_text_only.jsonl" <<'EOF'
{"type":"item.completed","item":{"type":"agent_message","text":"brief"}}
EOF
assert_eq "1" "$(count_structural_refusal_signals "$TEST_TMPDIR/codex_brief_text_only.jsonl")" "refusal signals: brief text-only topology is counted"

{
  printf '{"type":"item.completed","item":{"type":"agent_message","text":"'
  head -c 9000 < /dev/zero | tr '\0' 'x'
  printf '"}}\n'
} > "$TEST_TMPDIR/codex_large_text_only.jsonl"
assert_eq "0" "$(count_structural_refusal_signals "$TEST_TMPDIR/codex_large_text_only.jsonl")" "refusal signals: large text-only topology is ignored"

refusal_src="$(audit_extract_function count_structural_refusal_signals)"
assert_match '^  awk -v log_bytes=' "$refusal_src" "refusal signals: shell wrapper uses one awk scan"
assert_not_match 'grep -cF' "$refusal_src" "refusal signals: shell wrapper avoids repeated grep scans"

# ═══════════════════════════════════════════════════════════════
# 7e. Model preflight validates selected backend/model before launch
# ═══════════════════════════════════════════════════════════════

model_preflight_bin="$TEST_TMPDIR/model-preflight-bin"
mkdir -p "$model_preflight_bin"
cat > "$model_preflight_bin/claude-preflight" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "auth" ] && [ "${2:-}" = "status" ]; then
  exit 0
fi
model=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --model) model="$2"; shift 2 ;;
    *) shift ;;
  esac
done
if [ "$model" = "bad-claude-model" ]; then
  echo "unknown model: $model" >&2
  exit 42
fi
printf '{"type":"assistant","message":{"content":[{"type":"text","text":"MODEL_PREFLIGHT_OK"}]}}\n'
EOF
cat > "$model_preflight_bin/codex-preflight" <<'EOF'
#!/usr/bin/env bash
if [ "${1:-}" = "login" ] && [ "${2:-}" = "status" ]; then
  exit 0
fi
[ "${1:-}" = "exec" ] || exit 2
shift
model=""
message_file=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --model) model="$2"; shift 2 ;;
    --output-last-message) message_file="$2"; shift 2 ;;
    -) shift ;;
    *) shift ;;
  esac
done
if [ "$model" = "bad-codex-model" ]; then
  echo "unsupported model: $model" >&2
  exit 43
fi
[ -n "$message_file" ] && printf 'MODEL_PREFLIGHT_OK\n' > "$message_file"
printf '{"type":"thread.started","thread_id":"preflight"}\n'
EOF
cat > "$model_preflight_bin/gemini-preflight" <<'EOF'
#!/usr/bin/env bash
if [ -n "${PREFLIGHT_ARGS_FILE:-}" ]; then
  printf '%s\n' "$@" > "$PREFLIGHT_ARGS_FILE"
fi
# Mimic the gemini backend's two CLI dialects:
#   - agy (default): `agy changelog` is the lightweight "installed" probe;
#     `agy --dangerously-skip-permissions -p "<prompt>"` runs --print and
#     does NOT accept a launch-time --model flag.
#   - Google Gemini CLI (USE_GEMINI_CLI=1): accepts --model and writes its
#     errors to stderr rather than a private log dir.
if [ "${1:-}" = "changelog" ]; then
  printf '1.0.0:\n· stub\n'
  exit 0
fi
# agy 1.0.5+ accepts --model and --log-file. With AGY_MODEL_UNRESOLVED=1,
# emulate agy failing to resolve the model: write the unresolved-flag signature
# to the --log-file, but still echo the token and exit 0 below (silent fallback
# to the persistent /model — the case the audit preflight must catch from the
# log, since the echoed token alone looks like success).
if [ "${USE_GEMINI_CLI:-0}" != "1" ] && [ "${AGY_MODEL_UNRESOLVED:-0}" = "1" ]; then
  prev=""
  for arg in "$@"; do
    [ "$prev" = "--log-file" ] && printf 'Failed to resolve model flag\n' >> "$arg"
    prev="$arg"
  done
fi
if [ "${AGY_FAIL:-0}" = "1" ]; then
  echo "agy: failed to reach service" >&2
  exit 44
fi
# AGY_EMPTY mimics an upstream quota/429 rejection: agy exits 0 but the
# error goes only to its private log dir, so stdout is empty.
if [ "${AGY_EMPTY:-0}" = "1" ]; then
  exit 0
fi
if [ "${USE_GEMINI_CLI:-0}" = "1" ]; then
  printf '{"type":"message","role":"assistant","content":"MODEL_PREFLIGHT_OK"}\n'
else
  printf 'MODEL_PREFLIGHT_OK\n'
fi
EOF
cat > "$model_preflight_bin/opencode-preflight" <<'EOF'
#!/usr/bin/env bash
model=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --model) model="$2"; shift 2 ;;
    *) shift ;;
  esac
done
case "$model" in
  */oss-no-tool)
    printf '{"type":"text","part":{"type":"text","text":"OSS_TOOL_PREFLIGHT_OK_without_tool"}}\n'
    exit 0
    ;;
esac
if [ ! -f oss-tool-sentinel.txt ]; then
  echo "missing oss preflight sentinel" >&2
  exit 47
fi
token=$(cat oss-tool-sentinel.txt)
printf '{"type":"tool_use","part":{"type":"tool","tool":"read","state":{"status":"completed"}}}\n'
printf '{"type":"text","part":{"type":"text","text":"%s"}}\n' "$token"
EOF
chmod +x "$model_preflight_bin/"*

CLAUDE_BIN="$model_preflight_bin/claude-preflight"
CODEX_BIN="$model_preflight_bin/codex-preflight"
GEMINI_BIN="$model_preflight_bin/gemini-preflight"
OPENCODE_BIN="$model_preflight_bin/opencode-preflight"
LOGDIR="$TEST_TMPDIR/model-preflight-logs"
INDEX="$LOGDIR/index.log"
mkdir -p "$LOGDIR"
touch "$INDEX"
AUDIT_MODEL_PREFLIGHT=1
AUDIT_MODEL_PREFLIGHT_TIMEOUT=5

validate_model_for_backend claude "claude-good"
assert_file_exists "$(model_preflight_stamp_path claude "claude-good")" "model preflight: claude accepted model writes stamp"
assert_file_contains "$INDEX" "Model preflight passed: claude backend can reach model='claude-good'" "model preflight: claude pass logged"
# Success path must not leave model-preflight-*.{raw,message} sidecars
# behind. The .ok stamp above is the only on-disk evidence we keep on
# success; .raw/.message are only retained on failure (asserted below).
shopt -s nullglob
pf_sidecars=( "$LOGDIR"/model-preflight-claude.*.raw "$LOGDIR"/model-preflight-claude.*.message )
shopt -u nullglob
assert_eq "0" "${#pf_sidecars[@]}" "model preflight: claude success leaves no .raw/.message sidecars"

validate_model_for_backend codex "codex-good"
assert_file_exists "$(model_preflight_stamp_path codex "codex-good")" "model preflight: codex accepted model writes stamp"
assert_file_contains "$INDEX" "Model preflight passed: codex backend can reach model='codex-good'" "model preflight: codex pass logged"

validate_model_for_backend gemini "gemini-good"
assert_file_exists "$(model_preflight_stamp_path gemini "gemini-good")" "model preflight: gemini accepted model writes stamp"
assert_file_contains "$INDEX" "Model preflight passed: gemini backend can reach model='gemini-good'" "model preflight: gemini pass logged"

validate_model_for_backend oss "oss-good"
assert_file_exists "$(model_preflight_stamp_path oss "oss-good")" "model preflight: oss accepted tool-capable model writes stamp"
assert_file_contains "$INDEX" "Model preflight passed: oss backend can reach model='oss-good'" "model preflight: oss pass logged"

# Regression: agy can exit 0 AND echo MODEL_PREFLIGHT_OK while silently
# running a different model (handed a name it cannot resolve to a label). The
# preflight must read agy's log, see the unresolved-flag signature, and fail
# hard — even with AUDIT_MODEL_PREFLIGHT_OPTIONAL=1, since a wrong model
# corrupts a benchmark cell's cost/identity rather than being a transient blip.
gemini_unresolved_rc=0
( AGY_MODEL_UNRESOLVED=1 AUDIT_MODEL_PREFLIGHT_OPTIONAL=1 AUDIT_MODEL_PREFLIGHT_ATTEMPTS=1 \
    validate_model_for_backend gemini "gemini-unresolved" ) >/dev/null 2>&1 || gemini_unresolved_rc=$?
assert_eq "1" "$gemini_unresolved_rc" "model preflight: gemini agy silent fallback fails hard despite OPTIONAL"
if [ -e "$(model_preflight_stamp_path gemini "gemini-unresolved")" ]; then
  fail "model preflight: gemini silent fallback must not write a pass stamp"
else
  pass "model preflight: gemini silent fallback writes no pass stamp"
fi

gemini_cli_preflight_args="$TEST_TMPDIR/gemini-cli-preflight.args"
USE_GEMINI_CLI=1 PREFLIGHT_ARGS_FILE="$gemini_cli_preflight_args" \
  validate_model_for_backend gemini "gemini-cli-good"
gemini_cli_preflight_flags=$(tr '\n' ' ' < "$gemini_cli_preflight_args")
assert_match '--approval-mode=yolo' "$gemini_cli_preflight_flags" \
  "model preflight: Gemini CLI uses agent launch approval mode"
assert_not_match '--approval-mode=plan' "$gemini_cli_preflight_flags" \
  "model preflight: Gemini CLI avoids plan mode"
assert_match '--output-format stream-json' "$gemini_cli_preflight_flags" \
  "model preflight: Gemini CLI uses stream-json output"

saved_model_preflight_timeout="$AUDIT_MODEL_PREFLIGHT_TIMEOUT"
unset AUDIT_MODEL_PREFLIGHT_TIMEOUT
: > "$INDEX"
USE_GEMINI_CLI=1 validate_model_for_backend gemini "gemini-cli-default-timeout"
assert_file_contains "$INDEX" 'timeout per attempt=5m00s' \
  "model preflight: Gemini CLI default timeout allows slow startup"
AUDIT_MODEL_PREFLIGHT_TIMEOUT="$saved_model_preflight_timeout"
unset USE_GEMINI_CLI

ACTIVE_BACKEND=codex
MODEL="active-good"
validate_active_model
assert_file_exists "$(model_preflight_stamp_path codex "active-good")" "model preflight: active backend helper validates resolved model"

# Per-process preflight short-circuit: once a backend/model pair has
# passed preflight inside this audit process, subsequent calls must not
# re-invoke the backend CLI. Verify by counting "Model preflight passed"
# lines for the same pair across two back-to-back calls. The earlier
# preflight assertions in this file already set the guard for
# claude/claude-good, so use a fresh model name for a clean baseline
# (the stub claude-preflight binary accepts any model whose name does
# not start with "bad").
cat > "$model_preflight_bin/claude-preflight" <<'EOF'
#!/usr/bin/env bash
# Stub claude CLI: succeed for any model except those whose name starts
# with "bad". Used by the short-circuit test below — earlier in this
# file we wrote a different stub but it accepted only "claude-good";
# replace it so models like claude-good-sc/claude-good-sc2 succeed too.
model=""
while [ $# -gt 0 ]; do
  case "$1" in
    --model) model="$2"; shift 2 ;;
    *) shift ;;
  esac
done
case "$model" in
  bad-*) echo "unknown model: $model" >&2; exit 1 ;;
  *) printf '{"type":"completion","result":"MODEL_PREFLIGHT_OK"}\n' ;;
esac
EOF
chmod +x "$model_preflight_bin/claude-preflight"

: > "$INDEX"
validate_model_for_backend claude "claude-good-sc"
short_circuit_passes_first=$(grep -c "Model preflight passed: claude backend can reach model='claude-good-sc'" "$INDEX" || true)
validate_model_for_backend claude "claude-good-sc"
short_circuit_passes_second=$(grep -c "Model preflight passed: claude backend can reach model='claude-good-sc'" "$INDEX" || true)
assert_eq 1 "$short_circuit_passes_first" "preflight short-circuit: first call logs pass"
assert_eq 1 "$short_circuit_passes_second" "preflight short-circuit: second call for same backend+model is silent"

# Different model for the same backend must still preflight — guards
# are keyed by backend+model, not backend alone.
validate_model_for_backend claude "claude-good-sc2" 2>/dev/null || true
short_circuit_other_model_passes=$(grep -c "Model preflight passed: claude backend can reach model='claude-good-sc2'" "$INDEX" || true)
assert_eq 1 "$short_circuit_other_model_passes" \
  "preflight short-circuit: different model on same backend still preflights"

# audit_one_time_backend_bootstrap is idempotent — the per-process guard
# means repeat calls are free no-ops. Verified by checking the guard env
# variable lifecycle.
unset AUDIT_BACKEND_BOOTSTRAP_DONE_GEMINI 2>/dev/null || true
audit_one_time_backend_bootstrap gemini
assert_eq 1 "${AUDIT_BACKEND_BOOTSTRAP_DONE_GEMINI:-0}" \
  "audit_one_time_backend_bootstrap: gemini guard set after first call"
# A second call must not re-run the helpers (idempotent). Idempotency is
# verified by the guard staying set — the helpers themselves are no-ops
# (gemini_prune_stale_sessions) or filesystem-checks (ripgrep) without
# easily-observable side effects in this stubbed test environment.
audit_one_time_backend_bootstrap gemini
assert_eq 1 "${AUDIT_BACKEND_BOOTSTRAP_DONE_GEMINI:-0}" \
  "audit_one_time_backend_bootstrap: gemini guard remains set on second call"

# Non-gemini backends are bootstrap no-ops today but the guard must
# still flip so future side-effect additions inherit the same
# idempotent path.
unset AUDIT_BACKEND_BOOTSTRAP_DONE_CODEX 2>/dev/null || true
audit_one_time_backend_bootstrap codex
assert_eq 1 "${AUDIT_BACKEND_BOOTSTRAP_DONE_CODEX:-0}" \
  "audit_one_time_backend_bootstrap: codex guard set even when no side effects ship today"

: > "$INDEX"
exit_trap_output=$( ( false; audit_exit_trap 424 "$?" ) 2>&1 )
assert_match 'SCRIPT EXITING \(line=424 rc=1\)' "$exit_trap_output" \
  "audit exit trap: stderr preserves original nonzero rc"
assert_file_contains "$INDEX" 'SCRIPT EXITING \(line=424 rc=1\)' \
  "audit exit trap: index preserves original nonzero rc"
assert_not_match 'rc=0' "$exit_trap_output" \
  "audit exit trap: stderr does not report the append command rc"

# Override the retry knobs so deterministic failure tests don't sit
# through the production 3-attempt, 5s-then-15s backoff. ATTEMPTS=1
# makes these single-shot.
AUDIT_MODEL_PREFLIGHT_ATTEMPTS=1
AUDIT_MODEL_PREFLIGHT_BACKOFF=1
# Per-backend rejection assertions verify the FATAL path; opt out of the
# default OPTIONAL=1 fallback so a rejection raises rc=1.
AUDIT_MODEL_PREFLIGHT_OPTIONAL=0
bad_output=$(validate_model_for_backend claude "bad-claude-model" 2>&1)
bad_rc=$?
assert_eq "1" "$bad_rc" "model preflight: claude rejected model exits early"
assert_match 'model preflight failed.*bad-claude-model' "$bad_output" "model preflight: claude rejected model names backend model"
assert_match 'unknown model: bad-claude-model' "$bad_output" "model preflight: claude rejected model includes CLI output"
# Failure path keeps a .raw sidecar so the error evidence isn't lost.
shopt -s nullglob
pf_failure_raw=( "$LOGDIR"/model-preflight-claude.*.raw )
shopt -u nullglob
[ "${#pf_failure_raw[@]}" -ge 1 ] \
  && pass "model preflight: claude failure preserves .raw evidence" \
  || fail "model preflight: claude failure preserves .raw evidence" "no .raw retained under $LOGDIR"

bad_output=$(validate_model_for_backend codex "bad-codex-model" 2>&1)
bad_rc=$?
assert_eq "1" "$bad_rc" "model preflight: codex rejected model exits early"
assert_match 'model preflight failed.*bad-codex-model' "$bad_output" "model preflight: codex rejected model names backend model"
assert_match 'unsupported model: bad-codex-model' "$bad_output" "model preflight: codex rejected model includes CLI output"

printf 'legacy echo-only approval\n' > "$LOGDIR/.model_preflight_oss_oss-no-tool.ok"
bad_output=$(validate_model_for_backend oss "oss-no-tool" 2>&1)
bad_rc=$?
assert_eq "1" "$bad_rc" "model preflight: oss rejects model without required read tool"
assert_match 'did not use the required read tool' "$bad_output" "model preflight: oss names missing tool-use failure"
assert_file_not_exists "$(model_preflight_stamp_path oss "oss-no-tool")" "model preflight: oss missing tool use writes no .ok stamp"

# The fake agy rejects through AGY_FAIL=1 so this exercises the harness's
# failure path while recording the resolved harness model label.
bad_output=$(AGY_FAIL=1 validate_model_for_backend gemini "gemini-3.1-flash-lite" 2>&1)
bad_rc=$?
assert_eq "1" "$bad_rc" "model preflight: gemini failure exits early"
assert_match 'model preflight failed.*gemini-3.1-flash-lite' "$bad_output" "model preflight: gemini failure names backend model"
assert_match 'agy: failed to reach service' "$bad_output" "model preflight: gemini failure includes CLI output"

# agy exits 0 on an upstream rejection but prints nothing on stdout. With
# no diagnosable agy CLI log to consult, the gemini preflight must still
# treat empty output as a failure so a broken account does not false-pass
# and waste a recon phase. Point AUDIT_GEMINI_CLI_LOG_DIR at an empty dir
# so this exercises the no-log branch deterministically (not whatever agy
# logs happen to exist on the host running the test suite).
empty_log_dir="$TEST_TMPDIR/agy-cli-log-empty"
mkdir -p "$empty_log_dir"
AUDIT_MODEL_PREFLIGHT_OPTIONAL=0
empty_output=$(AGY_EMPTY=1 AUDIT_GEMINI_CLI_LOG_DIR="$empty_log_dir" \
  validate_model_for_backend gemini "gemini-3.1-flash-lite" 2>&1)
empty_rc=$?
assert_eq "1" "$empty_rc" "model preflight: gemini empty output exits early"
assert_match 'produced no output' "$empty_output" "model preflight: gemini empty output names the empty-output failure"
assert_file_not_exists "$(model_preflight_stamp_path gemini "gemini-3.1-flash-lite")" "model preflight: gemini empty output writes no .ok stamp"
unset AUDIT_MODEL_PREFLIGHT_OPTIONAL

# agy surfaces a 429 / RESOURCE_EXHAUSTED account-quota rejection only in
# its private CLI log. The gemini preflight must read that log, report the
# quota cause instead of a generic "check the model name" FATAL, and skip
# the remaining retry attempts since a quota does not clear within backoff.
agy_log_dir="$TEST_TMPDIR/agy-cli-log"
mkdir -p "$agy_log_dir"
# One python3 invocation instead of a 200-iteration shell loop (which
# forked ~600 subprocesses for printf/touch). Same files, same contents,
# same mtimes (2026-05-21 23:37:SS local time, SS = i % 60).
python3 - "$agy_log_dir" <<'PY'
import os, sys, time
d = sys.argv[1]
base = time.mktime(time.strptime("202605212337", "%Y%m%d%H%M"))
for i in range(1, 201):
    p = os.path.join(d, "cli-20260521_2337%02d.log" % i)
    with open(p, "w") as f:
        f.write("I0521 23:37:%02d ordinary agy log\n" % (i % 60))
    mtime = base + (i % 60)
    os.utime(p, (mtime, mtime))
PY
no_diag="$TEST_TMPDIR/agy-no-diag.raw"
AUDIT_GEMINI_CLI_LOG_DIR="$agy_log_dir" gemini_capture_cli_log_diag "$no_diag"
assert_eq "0" "$?" "model preflight: gemini private-log diagnostic ignores logs without matching errors"
if [ -s "$no_diag" ]; then
  fail "model preflight: gemini private-log diagnostic does not write header-only output" \
    "unexpected content: $(cat "$no_diag")"
else
  pass "model preflight: gemini private-log diagnostic does not write header-only output"
fi
cat > "$agy_log_dir/cli-20260521_233915.log" <<'EOF'
I0521 23:39:17.366 printmode.go:130 sending message
E0521 23:39:17.828 log.go:398 agent executor error: RESOURCE_EXHAUSTED (code 429): Individual quota reached. Resets in 137h39m19s.
EOF
touch -t 202605212339.15 "$agy_log_dir/cli-20260521_233915.log" 2>/dev/null || true
quota_diag="$TEST_TMPDIR/agy-quota-diag.raw"
AUDIT_GEMINI_CLI_LOG_DIR="$agy_log_dir" gemini_capture_cli_log_diag "$quota_diag"
assert_eq "0" "$?" "model preflight: gemini private-log diagnostic survives many agy logs under pipefail"
assert_file_contains "$quota_diag" "RESOURCE_EXHAUSTED" "model preflight: gemini private-log diagnostic captures newest quota log"
quota_attempts_saved="$AUDIT_MODEL_PREFLIGHT_ATTEMPTS"
quota_backoff_saved="$AUDIT_MODEL_PREFLIGHT_BACKOFF"
AUDIT_MODEL_PREFLIGHT_ATTEMPTS=3
AUDIT_MODEL_PREFLIGHT_BACKOFF=1
AUDIT_MODEL_PREFLIGHT_OPTIONAL=0
quota_output=$(AGY_EMPTY=1 AUDIT_GEMINI_CLI_LOG_DIR="$agy_log_dir" \
  validate_model_for_backend gemini "gemini-3.1-flash-lite" 2>&1)
quota_rc=$?
AUDIT_MODEL_PREFLIGHT_ATTEMPTS="$quota_attempts_saved"
AUDIT_MODEL_PREFLIGHT_BACKOFF="$quota_backoff_saved"
unset AUDIT_MODEL_PREFLIGHT_OPTIONAL
assert_eq "1" "$quota_rc" "model preflight: gemini quota exhaustion exits early"
assert_match 'account quota is exhausted' "$quota_output" "model preflight: gemini quota failure names the quota cause"
assert_match 'RESOURCE_EXHAUSTED' "$quota_output" "model preflight: gemini quota failure includes the agy CLI log tail"
quota_warns=$(printf '%s\n' "$quota_output" | grep -c 'agy reports the account quota is exhausted')
assert_eq "1" "$quota_warns" "model preflight: gemini quota exhaustion skips the remaining retry attempts"

# USE_GEMINI_CLI=1 swaps agy for the Google Gemini CLI, which writes errors
# to stderr (captured in $raw) and does not use agy's private log dir. The
# preflight must NOT scrape that log under USE_GEMINI_CLI=1 — doing so would
# mis-attribute a stale agy quota error to a CLI that never produced it.
AUDIT_MODEL_PREFLIGHT_ATTEMPTS=1
AUDIT_MODEL_PREFLIGHT_BACKOFF=1
AUDIT_MODEL_PREFLIGHT_OPTIONAL=0
cli_output=$(USE_GEMINI_CLI=1 AGY_EMPTY=1 AUDIT_GEMINI_CLI_LOG_DIR="$agy_log_dir" \
  validate_model_for_backend gemini "gemini-3.1-flash-lite" 2>&1)
cli_rc=$?
unset AUDIT_MODEL_PREFLIGHT_OPTIONAL
assert_eq "1" "$cli_rc" "model preflight: USE_GEMINI_CLI empty output exits early"
assert_match 'produced no output' "$cli_output" "model preflight: USE_GEMINI_CLI empty output reports generic empty-output failure"
assert_not_match 'account quota is exhausted' "$cli_output" "model preflight: USE_GEMINI_CLI does not mis-attribute a stale agy quota error"

# Retry-with-backoff: a transient failure on attempt 1 followed by a
# successful attempt 2 must yield a passing preflight. Without this,
# a single API/network blip takes the whole audit down before any
# work begins. Use a state-file stub that fails on the first call and
# succeeds on subsequent ones.
retry_state="$TEST_TMPDIR/retry-state"
cat > "$model_preflight_bin/claude-retry" <<EOF
#!/usr/bin/env bash
state="$retry_state"
attempts=0
[ -f "\$state" ] && attempts=\$(cat "\$state")
attempts=\$((attempts + 1))
echo "\$attempts" > "\$state"
if [ "\$attempts" -lt 2 ]; then
  echo "transient: try again" >&2
  exit 19
fi
printf '{"type":"assistant","message":{"content":[{"type":"text","text":"MODEL_PREFLIGHT_OK"}]}}\n'
EOF
chmod +x "$model_preflight_bin/claude-retry"
rm -f "$retry_state"
SAVED_CLAUDE_BIN="$CLAUDE_BIN"
CLAUDE_BIN="$model_preflight_bin/claude-retry"
AUDIT_MODEL_PREFLIGHT_ATTEMPTS=3
AUDIT_MODEL_PREFLIGHT_BACKOFF=1
# The retry assertions check attempt counts and log lines, not wall-clock
# backoff, and validate_model_for_backend clamps BACKOFF to >=1s — so stub
# `sleep` inside the capture subshell to keep each retrying call instant.
# (The stub is scoped to the $(...) subshell; the preflight stub CLIs are
# separate processes and never see a shell function.)
retry_output=$(sleep() { :; }; validate_model_for_backend claude "retry-good" 2>&1)
retry_rc=$?
assert_eq "0" "$retry_rc" "model preflight retry: succeeds after one transient failure"
assert_match 'attempt 1/3 .* failed' "$retry_output" "model preflight retry: attempt 1 failure logged"
assert_match "Model preflight passed: claude backend can reach model='retry-good'" "$retry_output" \
  "model preflight retry: success line logged after retry"
assert_file_exists "$(model_preflight_stamp_path claude "retry-good")" \
  "model preflight retry: stamp written after retry success"
[ "$(cat "$retry_state" 2>/dev/null)" = "2" ] \
  && pass "model preflight retry: exactly 2 attempts consumed (1 fail + 1 succeed)" \
  || fail "model preflight retry: exactly 2 attempts consumed" \
        "attempts file = $(cat "$retry_state" 2>/dev/null)"
# Persistent failures across all retries still exit 1.
cat > "$model_preflight_bin/claude-always-fail" <<'EOF'
#!/usr/bin/env bash
echo "always transient" >&2
exit 19
EOF
chmod +x "$model_preflight_bin/claude-always-fail"
CLAUDE_BIN="$model_preflight_bin/claude-always-fail"
AUDIT_MODEL_PREFLIGHT_ATTEMPTS=2
AUDIT_MODEL_PREFLIGHT_BACKOFF=1
persistent_output=$(sleep() { :; }; validate_model_for_backend claude "never-good" 2>&1)
persistent_rc=$?
assert_eq "1" "$persistent_rc" "model preflight retry: persistent failure exits 1 by default"
assert_match 'after 2 attempt' "$persistent_output" \
  "model preflight retry: fatal log records attempt count"
CLAUDE_BIN="$SAVED_CLAUDE_BIN"
unset AUDIT_MODEL_PREFLIGHT_ATTEMPTS AUDIT_MODEL_PREFLIGHT_BACKOFF AUDIT_MODEL_PREFLIGHT_OPTIONAL

# AUDIT_MODEL_PREFLIGHT_OPTIONAL=1 downgrades persistent failure to WARN
# and returns 0 without writing a stamp, so scheduled runs survive
# transient preflight failures.
CLAUDE_BIN="$model_preflight_bin/claude-always-fail"
AUDIT_MODEL_PREFLIGHT_ATTEMPTS=2
AUDIT_MODEL_PREFLIGHT_BACKOFF=1
AUDIT_MODEL_PREFLIGHT_OPTIONAL=1
optional_stamp=$(model_preflight_stamp_path claude "optional-never-good")
rm -f "$optional_stamp"
optional_output=$(sleep() { :; }; validate_model_for_backend claude "optional-never-good" 2>&1)
optional_rc=$?
assert_eq "0" "$optional_rc" \
  "model preflight optional: persistent failure returns 0 when AUDIT_MODEL_PREFLIGHT_OPTIONAL=1"
assert_match 'WARN: model preflight failed' "$optional_output" \
  "model preflight optional: WARN line emitted instead of FATAL"
assert_match 'AUDIT_MODEL_PREFLIGHT_OPTIONAL=1' "$optional_output" \
  "model preflight optional: WARN message cites the opt-in flag"
[ ! -f "$optional_stamp" ] \
  && pass "model preflight optional: no stamp written when preflight skipped" \
  || fail "model preflight optional: stamp must not be written on skipped preflight" \
        "stamp file present: $optional_stamp"
unset AUDIT_MODEL_PREFLIGHT_OPTIONAL AUDIT_MODEL_PREFLIGHT_ATTEMPTS AUDIT_MODEL_PREFLIGHT_BACKOFF

# Default behaviour: with AUDIT_MODEL_PREFLIGHT_OPTIONAL unset, persistent
# failures must stop the audit before any agent launch. This is the backend
# CLI/auth litmus test: a backend that cannot complete the one-token
# preflight is not usable for unattended agent work.
CLAUDE_BIN="$model_preflight_bin/claude-always-fail"
AUDIT_MODEL_PREFLIGHT_ATTEMPTS=2
AUDIT_MODEL_PREFLIGHT_BACKOFF=1
default_fail_output=$(sleep() { :; }; validate_model_for_backend claude "default-never-good" 2>&1)
default_fail_rc=$?
assert_eq "1" "$default_fail_rc" \
  "model preflight default: persistent failure exits before agent launch"
assert_match 'FATAL: model preflight failed' "$default_fail_output" \
  "model preflight default: FATAL line emitted by default on persistent failure"
unset AUDIT_MODEL_PREFLIGHT_ATTEMPTS AUDIT_MODEL_PREFLIGHT_BACKOFF
CLAUDE_BIN="$SAVED_CLAUDE_BIN"

AUDIT_MODEL_PREFLIGHT=0
validate_model_for_backend claude "bad-claude-model"
assert_eq "0" "$?" "model preflight: explicit disable bypasses validation"
AUDIT_MODEL_PREFLIGHT=1

# ═══════════════════════════════════════════════════════════════
# 8. Generic target: agent_mode returns generic
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0
assert_eq "generic" "$(agent_mode 1)" "generic target: agent 1 → generic"
assert_eq "generic" "$(agent_mode 2)" "generic target: agent 2 → generic"
assert_eq "generic" "$(agent_mode 5)" "generic target: agent 5 → generic"

IS_BROWSER_TARGET=1
assert_eq "browser" "$(agent_mode 1)" "browser target: agent 1 → browser"
assert_eq "shell" "$(agent_mode 2)" "browser target: agent 2 → shell"
IS_BROWSER_TARGET=0

# ═══════════════════════════════════════════════════════════════
# 12. Generic target: agent_role unchanged (independent of target)
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0
assert_eq "reproduce" "$(agent_role 1)" "generic target: agent 1 → reproduce"
assert_eq "analysis" "$(agent_role 2)" "generic target: agent 2 → analysis"
assert_eq "reproduce" "$(agent_role 3)" "generic target: agent 3 → reproduce"

AGENT_ROLES="analysis,reproduce,analysis"
assert_eq "analysis" "$(agent_role 1)" "generic target: agent 1 → analysis (override)"
assert_eq "reproduce" "$(agent_role 2)" "generic target: agent 2 → reproduce (override)"
assert_eq "analysis" "$(agent_role 3)" "generic target: agent 3 → analysis (override)"
AGENT_ROLES=""

# ═══════════════════════════════════════════════════════════════
# 14. trim_state.py — hypothesis table capping (basic)
# ═══════════════════════════════════════════════════════════════

TRIMMER="$SCRIPT_ROOT/lib/trim_state.py"

# 14a. 30 terminal + 2 active → terminal capped at 15, active preserved
_trim_state="$RESULTS_DIR/AUDIT_STATE-1.md"
{
  echo "# Audit State Journal"
  echo "Mode: shell"
  echo "## Primary Subsystem: js/src/jit"
  echo ""
  echo "## Current Hypothesis Queue"
  echo "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |"
  echo "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|"
  for i in $(seq 1 25); do
    printf '| H%d | test hyp %d | f.cpp:F:%d | shape | gap | bounds | S1 | CLEAN |\n' "$i" "$i" "$i"
  done
  echo '| H26 | active hyp | f.cpp:F:26 | shape | gap | bounds | S2 | PENDING |'
  echo '| H27 | dead hyp | f.cpp:F:27 | shape | gap | bounds | S1 | DEAD_END |'
  echo '| H28 | dead hyp 2 | f.cpp:F:28 | shape | gap | bounds | S3 | DEAD_END |'
  echo '| H29 | dead hyp 3 | f.cpp:F:29 | shape | gap | bounds | S1 | DEAD_END |'
  echo '| H30 | dead hyp 4 | f.cpp:F:30 | shape | gap | bounds | S1 | DEAD_END |'
  echo '| H31 | dead hyp 5 | f.cpp:F:31 | shape | gap | bounds | S1 | DEAD_END |'
  echo '| H32 | investigating | f.cpp:F:32 | shape | gap | bounds | S2 | INVESTIGATING |'
  echo ""
  echo "## Completed Investigations"
  echo "none"
  echo ""
  echo "## Dead Ends"
  echo "none"
} > "$_trim_state"

_before_lines=$(wc -l < "$_trim_state" | tr -d ' ')
python3 "$TRIMMER" "$_trim_state"
_after_lines=$(wc -l < "$_trim_state" | tr -d ' ')
_active_count=$(grep -cE 'PENDING|INVESTIGATING' "$_trim_state" || true)
_terminal_count=$(grep -cE '^\| H[0-9]+.*\| (CLEAN|DEAD_END) \|' "$_trim_state" || true)

assert_eq "2" "$_active_count" "trim basic: active rows preserved"
if [ "$_terminal_count" -le 15 ]; then
  pass "trim basic: terminal capped at 15 (got $_terminal_count)"
else
  fail "trim basic: terminal capped at 15" "got $_terminal_count"
fi
if [ "$_after_lines" -lt "$_before_lines" ]; then
  pass "trim basic: file shrank ($_before_lines → $_after_lines)"
else
  fail "trim basic: file shrank" "$_before_lines → $_after_lines"
fi

# ═══════════════════════════════════════════════════════════════
# 15. trim_state.py — keeps most recent terminal rows (not oldest)
# ═══════════════════════════════════════════════════════════════

{
  echo "## Current Hypothesis Queue"
  echo "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |"
  echo "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|"
  for i in $(seq 1 20); do
    printf '| H%d | old hyp | f.cpp:F:%d | shape | gap | bounds | S1 | CLEAN |\n' "$i" "$i"
  done
  printf '| H21 | newest terminal | f.cpp:F:21 | shape | gap | bounds | S1 | DEAD_END |\n'
} > "$_trim_state"

python3 "$TRIMMER" "$_trim_state"
# H1 (oldest) should be trimmed; H21 (newest) should survive
assert_file_not_contains "$_trim_state" '[|] H1 [|]' "trim recency: oldest row H1 removed"
assert_file_contains "$_trim_state" 'H21.*newest terminal' "trim recency: newest row H21 kept"

# ═══════════════════════════════════════════════════════════════
# 16. trim_state.py — all terminal statuses recognized
# ═══════════════════════════════════════════════════════════════

{
  echo "## Current Hypothesis Queue"
  echo "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |"
  echo "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|"
  # 20 CLEAN rows to push past the 15 cap
  for i in $(seq 1 20); do
    printf '| H%d | filler | f.cpp:F:%d | shape | gap | bounds | S1 | CLEAN |\n' "$i" "$i"
  done
  echo '| H21 | tested clean | f.cpp:F:21 | shape | gap | bounds | S2 | TESTED-CLEAN |'
  echo '| H22 | env blocked | f.cpp:F:22 | shape | gap | bounds | S3 | ENV-BLOCKED (oomTest unavailable) |'
  echo '| H23 | needs tc | f.cpp:F:23 | shape | gap | bounds | S2 | NEEDS_TESTCASE |'
  echo '| H24 | pending | f.cpp:F:24 | shape | gap | bounds | S1 | PENDING |'
  echo '| H25 | investigating | f.cpp:F:25 | shape | gap | bounds | S1 | INVESTIGATING |'
} > "$_trim_state"

python3 "$TRIMMER" "$_trim_state"
# All 3 active-status rows must survive
assert_file_contains "$_trim_state" 'NEEDS_TESTCASE' "trim statuses: NEEDS_TESTCASE preserved"
assert_file_contains "$_trim_state" 'H24.*PENDING' "trim statuses: PENDING preserved"
assert_file_contains "$_trim_state" 'H25.*INVESTIGATING' "trim statuses: INVESTIGATING preserved"
# TESTED-CLEAN and ENV-BLOCKED are terminal (not active) but recent, so they should survive the 15-cap
assert_file_contains "$_trim_state" 'TESTED-CLEAN' "trim statuses: TESTED-CLEAN treated as terminal"
assert_file_contains "$_trim_state" 'ENV-BLOCKED' "trim statuses: ENV-BLOCKED treated as terminal"

# ═══════════════════════════════════════════════════════════════
# 17. trim_state.py — all-active table (nothing trimmed)
# ═══════════════════════════════════════════════════════════════

{
  echo "## Current Hypothesis Queue"
  echo "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |"
  echo "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|"
  for i in $(seq 1 5); do
    printf '| H%d | active | f.cpp:F:%d | shape | gap | bounds | S1 | PENDING |\n' "$i" "$i"
  done
} > "$_trim_state"

_before=$(wc -l < "$_trim_state" | tr -d ' ')
python3 "$TRIMMER" "$_trim_state"
_after=$(wc -l < "$_trim_state" | tr -d ' ')
_active=$(grep -c 'PENDING' "$_trim_state" || true)
assert_eq "5" "$_active" "trim all-active: all 5 PENDING rows preserved"
assert_eq "$_before" "$_after" "trim all-active: file unchanged"

# ═══════════════════════════════════════════════════════════════
# 18. trim_state.py — exactly 15 terminal rows (boundary, no trim)
# ═══════════════════════════════════════════════════════════════

{
  echo "## Current Hypothesis Queue"
  echo "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |"
  echo "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|"
  for i in $(seq 1 15); do
    printf '| H%d | boundary | f.cpp:F:%d | shape | gap | bounds | S1 | CLEAN |\n' "$i" "$i"
  done
} > "$_trim_state"

_before=$(wc -l < "$_trim_state" | tr -d ' ')
python3 "$TRIMMER" "$_trim_state"
_after=$(wc -l < "$_trim_state" | tr -d ' ')
_count=$(grep -c '| H[0-9]' "$_trim_state" || true)
assert_eq "15" "$_count" "trim boundary: exactly 15 terminal rows untouched"
assert_eq "$_before" "$_after" "trim boundary: file unchanged at exactly 15"

# ═══════════════════════════════════════════════════════════════
# 19. trim_state.py — table at end of file (no trailing sections)
# ═══════════════════════════════════════════════════════════════

{
  echo "# Audit State"
  echo "## Current Hypothesis Queue"
  echo "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |"
  echo "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|"
  for i in $(seq 1 20); do
    printf '| H%d | eof test | f.cpp:F:%d | shape | gap | bounds | S1 | CLEAN |\n' "$i" "$i"
  done
} > "$_trim_state"

python3 "$TRIMMER" "$_trim_state"
_count=$(grep -c '| H[0-9]' "$_trim_state" || true)
assert_eq "15" "$_count" "trim table-at-eof: capped to 15 with no trailing sections"
assert_file_contains "$_trim_state" 'H20.*eof test' "trim table-at-eof: last row H20 preserved"
assert_file_not_contains "$_trim_state" '[|] H1 [|]' "trim table-at-eof: oldest row H1 removed"

# ═══════════════════════════════════════════════════════════════
# 20. trim_state.py — empty hypothesis table
# ═══════════════════════════════════════════════════════════════

{
  echo "# Audit State"
  echo "## Current Hypothesis Queue"
  echo "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |"
  echo "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|"
  echo ""
  echo "## Dead Ends"
  echo "none"
} > "$_trim_state"

_before=$(wc -l < "$_trim_state" | tr -d ' ')
python3 "$TRIMMER" "$_trim_state"
_after=$(wc -l < "$_trim_state" | tr -d ' ')
assert_eq "$_before" "$_after" "trim empty table: file unchanged"

# ═══════════════════════════════════════════════════════════════
# 21. trim_state.py — table header rows preserved
# ═══════════════════════════════════════════════════════════════

{
  echo "## Current Hypothesis Queue"
  echo "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |"
  echo "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|"
  for i in $(seq 1 20); do
    printf '| H%d | header test | f.cpp:F:%d | shape | gap | bounds | S1 | CLEAN |\n' "$i" "$i"
  done
  echo ""
  echo "## Dead Ends"
} > "$_trim_state"

python3 "$TRIMMER" "$_trim_state"
assert_file_contains "$_trim_state" 'Expected Diagnostic' "trim headers: column header row preserved"
assert_file_contains "$_trim_state" '[|]---' "trim headers: separator row preserved"

# ═══════════════════════════════════════════════════════════════
# 22. trim_state.py — Completed Investigations section capped
# ═══════════════════════════════════════════════════════════════

{
  echo "# State"
  echo "## Completed Investigations"
  for i in $(seq 1 30); do
    echo "- subsystem $i exhausted"
  done
  echo ""
  echo "## Dead Ends"
  echo "none"
} > "$_trim_state"

python3 "$TRIMMER" "$_trim_state"
_ci_lines=$(sed -n '/## Completed/,/## Dead/p' "$_trim_state" | grep -c 'subsystem' || true)
if [ "$_ci_lines" -le 20 ]; then
  pass "trim CI section: capped at 20 (got $_ci_lines)"
else
  fail "trim CI section: capped at 20" "got $_ci_lines"
fi
assert_file_contains "$_trim_state" 'older entries trimmed' "trim CI section: trimmed marker present"

# ═══════════════════════════════════════════════════════════════
# 23. trim_state.py — Dead Ends section capped at 5
# ═══════════════════════════════════════════════════════════════

{
  echo "# State"
  echo "## Dead Ends"
  for i in $(seq 1 10); do
    echo "- dead end $i"
  done
  echo ""
  echo "## Working Context"
  echo "context line"
} > "$_trim_state"

python3 "$TRIMMER" "$_trim_state"
_de_lines=$(sed -n '/## Dead Ends/,/## Working/p' "$_trim_state" | grep -c 'dead end' || true)
if [ "$_de_lines" -le 5 ]; then
  pass "trim DE section: capped at 5 (got $_de_lines)"
else
  fail "trim DE section: capped at 5" "got $_de_lines"
fi

# ═══════════════════════════════════════════════════════════════
# 24. trim_state.py — Working Context capped at 30 recent lines
# ═══════════════════════════════════════════════════════════════

{
  echo "# State"
  echo "## Working Context"
  for i in $(seq 1 45); do
    echo "| src/file.c:$i | snippet $i | reason $i |"
  done
  echo ""
  echo "## Cross-File Traces"
  echo "- FLOW: x"
} > "$_trim_state"

python3 "$TRIMMER" "$_trim_state"
_wc_lines=$(sed -n '/## Working Context/,/## Cross-File/p' "$_trim_state" | grep -c 'snippet' || true)
if [ "$_wc_lines" -le 30 ]; then
  pass "trim WC section: capped at 30 (got $_wc_lines)"
else
  fail "trim WC section: capped at 30" "got $_wc_lines"
fi
assert_file_not_contains "$_trim_state" 'src/file[.]c:1 [|] snippet 1 [|]' "trim WC section: oldest context removed"
assert_file_contains "$_trim_state" 'snippet 45' "trim WC section: newest context preserved"

# ═══════════════════════════════════════════════════════════════
# 25. trim_state.py — excessive active rows capped
# ═══════════════════════════════════════════════════════════════

{
  echo "## Current Hypothesis Queue"
  echo "| # | Hypothesis | File:Function:Line | Input Shape | Guard Gap | Expected Diagnostic | Strategy | Status |"
  echo "|---|-----------|-------------------|-------------|-----------|---------------------|----------|--------|"
  for i in $(seq 1 12); do
    printf '| H%d | active %d | f.cpp:F:%d | shape | gap | bounds | S1 | PENDING |\n' "$i" "$i" "$i"
  done
} > "$_trim_state"

python3 "$TRIMMER" "$_trim_state"
_active=$(grep -c 'PENDING' "$_trim_state" || true)
assert_eq "8" "$_active" "trim active: capped at 8"
assert_file_not_contains "$_trim_state" '[|] H1 [|]' "trim active: oldest active row removed"
assert_file_contains "$_trim_state" 'H12.*active 12' "trim active: newest active row preserved"

# ═══════════════════════════════════════════════════════════════
# Logs README is written once at LOGDIR init and is idempotent.
# ═══════════════════════════════════════════════════════════════
readme_logdir="$TEST_TMPDIR/readme-test"
mkdir -p "$readme_logdir"
eval "$(audit_extract_function audit_write_logdir_readme)"
audit_write_logdir_readme "$readme_logdir"
assert_file_exists "$readme_logdir/README.md" "logs README: written at init"
assert_file_contains "$readme_logdir/README.md" "High-signal entry points" "logs README: points at the right files"
size_before=$(wc -c < "$readme_logdir/README.md" | tr -d ' ')
audit_write_logdir_readme "$readme_logdir"
size_after=$(wc -c < "$readme_logdir/README.md" | tr -d ' ')
assert_eq "$size_before" "$size_after" "logs README: idempotent (no rewrite if present)"

# ═══════════════════════════════════════════════════════════════
# Subsystem mode lists: read from the lib/subsystems/<slug>.txt overlay,
# not hardcoded heredocs. Extract the real functions and exercise them.
# ═══════════════════════════════════════════════════════════════
eval "$(audit_extract_functions _mode_subsystems browser_mode_subsystems shell_mode_subsystems)"

_saved_slug="${TARGET_SLUG:-}"
TARGET_SLUG=firefox
_bw=$(browser_mode_subsystems)
_sh=$(shell_mode_subsystems)
assert_match "dom/canvas" "$_bw" "browser_mode_subsystems: reads browser entries from overlay"
assert_not_match "js/src/jit" "$_bw" "browser_mode_subsystems: excludes shell entries"
assert_match "third_party/libwebrtc" "$_bw" "browser_mode_subsystems: libwebrtc is a browser pick (drift resolved)"
assert_match "js/src/jit" "$_sh" "shell_mode_subsystems: reads shell entries from overlay"
assert_not_match "dom/canvas" "$_sh" "shell_mode_subsystems: excludes browser entries"

# A slug with no overlay file yields an empty candidate set — no Firefox
# paths leak onto an unrelated browser target.
TARGET_SLUG=no-such-target-xyz
assert_eq "" "$(browser_mode_subsystems)" "mode subsystems: missing overlay → empty candidate set"
TARGET_SLUG="$_saved_slug"

# The Firefox subsystem paths must no longer be hardcoded in bin/audit.
assert_file_not_contains "$SCRIPT_ROOT/bin/audit" '^dom/canvas$' \
  "bin/audit: subsystem paths are not hardcoded heredoc lines"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'lib/subsystems/\$\{TARGET_SLUG' \
  "bin/audit: subsystem candidates come from the per-target overlay"

# ═══════════════════════════════════════════════════════════════
# Cold-start strategy picker: must not mutually recurse with
# get_agent_strategy. Regression test for the fork-bomb that wedged
# the prompt-build pipeline (`get(N)` falls back to `pick(N)`, which
# (before the fix) looked up peer strategies by calling `get(M)` on
# every other agent, each of which also has no state and falls back
# to `pick(M)` — every level forks a fresh $(...) subshell, so a
# 3-agent cold start exploded into 900+ nested bash subshells before
# the wall-budget killer reaped it. The bug had been latent since
# the initial commit because helpers.sh stubs `get_agent_strategy`
# in every other test, so the real fallback path was never exercised.
# ═══════════════════════════════════════════════════════════════
eval "$(audit_extract_functions agent_strategy_path agent_strategy_streak_path get_agent_strategy effective_work_card_rows unclaimed_strategy_counts pick_cold_start_strategy)"

# Minimal stubs for the deps get_agent_strategy normally calls.
# All return values that force the fallback to pick_cold_start_strategy
# — that is the path the bug lived on. Cold-start agents legitimately
# hit this branch because no agent has any state yet.
structured_state_latest_strategy() { return 1; }
count_active_hypotheses_for_agent() { echo 0; }
state_file_path() { echo "/nonexistent/AUDIT_STATE-$1.md"; }

_csps_tmp=$(mktemp -d -t csps-regress.XXXXXX)
RESULTS_DIR="$_csps_tmp"
NUM_AGENTS=3
unset AUDIT_FIXED_STRATEGY AUDIT_COLD_START_STRATEGY

# Seed a minimal work-cards.jsonl so the jq pass inside
# pick_cold_start_strategy has something to score. The exact strategy
# returned does not matter — only that the call returns at all and
# the surrounding subshell tree stays small.
cat >"$RESULTS_DIR/work-cards.jsonl" <<'CARDS'
{"id":"c1","strategy":"S2","status":"unclaimed","mode":"auto"}
{"id":"c2","strategy":"S5","status":"unclaimed","mode":"auto"}
{"id":"c3","strategy":"S7","status":"unclaimed","mode":"auto"}
CARDS

# Time-bounded execution: the buggy version of pick_cold_start_strategy
# never returned, so we cap the call. A passing fix completes in well
# under one second; we allow 5 seconds of headroom for slow CI.
_csps_started=$(date +%s)
_csps_pick=$(python3 "$SCRIPT_ROOT/lib/timeout.py" 5 KILL 0 bash -c "
  $(declare -f agent_strategy_path agent_strategy_streak_path get_agent_strategy effective_work_card_rows unclaimed_strategy_counts pick_cold_start_strategy structured_state_latest_strategy count_active_hypotheses_for_agent state_file_path)
  RESULTS_DIR='$RESULTS_DIR' NUM_AGENTS=3 pick_cold_start_strategy 1
" 2>/dev/null) || _csps_rc=$?
_csps_elapsed=$(( $(date +%s) - _csps_started ))

assert_eq "" "${_csps_rc:-}" "pick_cold_start_strategy: returns rc=0 (does not recurse / timeout)"
[ "$_csps_elapsed" -lt 5 ] && _csps_fast=ok || _csps_fast="slow:${_csps_elapsed}s"
assert_eq "ok" "$_csps_fast" "pick_cold_start_strategy: completes in <5s (no mutual recursion with get_agent_strategy)"
assert_match "^(S[0-9]+|REF)$" "$_csps_pick" "pick_cold_start_strategy: returns a strategy token"

rm -rf "$_csps_tmp"

# ── build freshness preflight: lazy, audit-owned, fail-open ───────────
# bin/audit (re)builds a missing/stale native ASan tree before agents spawn so
# a moved checkout is never audited against an older binary. It MUST be
# fail-open — a target with no convergeable recipe (language/read-only) warns
# and the run continues — and MUST run before the harness canary check.
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'preflight_build_freshness()' \
  "build-freshness: bin/audit defines the preflight"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'build-freshness "\$TARGET_ROOT" asan' \
  "build-freshness: preflight probes the asan tree via target_config.py"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'setup-target" "\$TARGET_SLUG" --build' \
  "build-freshness: a stale/missing tree is (re)built via setup-target --build"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'PREFLIGHT WARN: ASan build is still' \
  "build-freshness: a build that stays stale warns and the audit continues (fail-open)"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'Re-probe rather than trust the exit status' \
  "build-freshness: success is re-probed, not inferred from setup-target exit code"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'fresh|skip) return 0' \
  "build-freshness: fresh or skip short-circuits without building"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'target_git_is_shallow_checkout "\$TARGET_ROOT"' \
  "startup warning: bin/audit checks for shallow git targets"
assert_file_contains "$SCRIPT_ROOT/bin/audit" 'S1 prior-fix history and patch-card queues may be incomplete' \
  "startup warning: bin/audit explains shallow checkout impact"
# Must run BEFORE the harness canary (which would otherwise smoke-test a stale
# build).
_bf_ln=$(grep -n '^preflight_build_freshness$' "$SCRIPT_ROOT/bin/audit" | tail -1 | cut -d: -f1)
_canary_ln=$(grep -n 'if ! preflight_harness_check;' "$SCRIPT_ROOT/bin/audit" | head -1 | cut -d: -f1)
if [ -n "$_bf_ln" ] && [ -n "$_canary_ln" ] && [ "$_bf_ln" -lt "$_canary_ln" ]; then
  pass "build-freshness: preflight@${_bf_ln} runs before the harness canary@${_canary_ln}"
else
  fail "build-freshness: preflight runs before the harness canary" "bf=$_bf_ln canary=$_canary_ln"
fi

# audit_exit_trap: a 128+N exit is annotated so the script's own last line names
# a signal-driven abort (the harness-r1 shape, otherwise a bare "rc=143"); a
# normal exit is left unannotated.
exit_trap_index="$TEST_TMPDIR/exit-trap-index.log"
: > "$exit_trap_index"
(
  INDEX="$exit_trap_index"
  log() { printf '%s\n' "$*"; }
  wait_for_background_housekeeping() { :; }
  audit_release_instance_lock() { :; }
  eval "$(audit_extract_function signal_name_for_exit_status)"
  eval "$(audit_extract_function audit_exit_trap)"
  audit_exit_trap 6981 143 2>/dev/null
  audit_exit_trap 200 255 2>/dev/null
  audit_exit_trap 100 0 2>/dev/null
)
assert_file_contains "$exit_trap_index" 'rc=143.*128\+SIGTERM' \
  "audit_exit_trap: annotates a 128+N signal-range exit"
assert_file_contains "$exit_trap_index" 'rc=255' \
  "audit_exit_trap: still logs high non-signal exits"
assert_file_not_contains "$exit_trap_index" 'rc=255.*128\+SIG' \
  "audit_exit_trap: does not annotate high non-signal exits as signal range"
assert_file_contains "$exit_trap_index" 'rc=0' \
  "audit_exit_trap: still logs a normal exit"
assert_file_not_contains "$exit_trap_index" 'rc=0.*128\+SIG' \
  "audit_exit_trap: leaves a normal exit unannotated"

teardown_test_env
summary
