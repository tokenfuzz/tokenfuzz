#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/helpers.sh"
setup_test_env

AUDIT_BIN="$SCRIPT_ROOT/bin/audit"

help_out=$(bash "$AUDIT_BIN" --help 2>&1)
assert_match "--experiment <name>" "$help_out" "audit help documents --experiment flag"

funcs="$TEST_TMPDIR/audit-funcs.sh"
awk '
  /^configure_active_backend\(\) / {emit=1}
  emit {print}
  emit && /^}$/ {emit=0}
' "$AUDIT_BIN" > "$funcs"

# Stubs for configure_active_backend dependencies; the test only covers path
# derivation and session-env placement.
resolve_model() { echo "test-model"; }
audit_write_logdir_readme() { :; }
target_detect_rev() { echo "test-rev"; }
target_write_session_env() {
  local dir="$1" results="$2" target_root="$3" slug="$4" rev="$5" logdir="$6"
  mkdir -p "$dir"
  {
    echo "RESULTS_DIR=$results"
    echo "TARGET_ROOT=$target_root"
    echo "TARGET_SLUG=$slug"
    echo "TARGET_REV=$rev"
    echo "LOGDIR=$logdir"
  } > "$dir/.session-env"
}

log() { echo "$*"; }

source "$SCRIPT_ROOT/lib/target_config.sh"
# shellcheck source=/dev/null
source "$funcs"

SCRIPT_ROOT="$TEST_TMPDIR/root"
TARGET_ROOT="$TEST_TMPDIR/target"
TARGET_SLUG="demo"
TARGET_OUTPUT_SLUG="demo-exp-a"
mkdir -p "$SCRIPT_ROOT" "$TARGET_ROOT"

sanitized=$(target_output_sanitize_experiment "Exp A")
assert_eq "exp-a" "$sanitized" "experiment name is normalized for output path"
assert_eq "demo-exp-a" "$(target_output_slug demo "Exp A" "")" "target output slug appends normalized experiment"

configure_active_backend codex
assert_eq "$SCRIPT_ROOT/output/demo-exp-a/codex/results" "$RESULTS_DIR" "experiment results path gets target suffix"
assert_eq "$SCRIPT_ROOT/output/demo-exp-a/codex/logs" "$LOGDIR" "experiment logs path gets target suffix"
assert_file_exists "$SCRIPT_ROOT/output/demo-exp-a/.session-env" "experiment session env written under suffixed output root"
assert_file_contains "$SCRIPT_ROOT/output/demo-exp-a/.session-env" "RESULTS_DIR=$SCRIPT_ROOT/output/demo-exp-a/codex/results" \
  "experiment session env points probe at isolated results"
assert_file_exists "$SCRIPT_ROOT/output/demo-exp-a/codex/results/.session-env" \
  "backend-local session env written under results dir"
assert_file_contains "$SCRIPT_ROOT/output/demo-exp-a/codex/results/.session-env" "RESULTS_DIR=$SCRIPT_ROOT/output/demo-exp-a/codex/results" \
  "backend-local session env points probe at isolated results"
assert_eq "$SCRIPT_ROOT/output/demo-exp-a/target.toml" "$TARGET_TOML" "experiment target.toml path is in suffixed output root"
expected_toml="$(cd "$SCRIPT_ROOT/output/demo-exp-a" && pwd)/target.toml"
assert_eq "$expected_toml" "$(target_toml_from_results "$RESULTS_DIR")" \
  "target.toml can be derived from backend results dir"
assert_eq "$expected_toml" "$(target_toml_from_session_dir "$RESULTS_DIR")" \
  "target.toml can be derived from backend-local session dir"

printf 'target = "demo"\n' > "$TARGET_TOML"
mkdir -p "$RESULTS_DIR/scratch-1"
tc="$RESULTS_DIR/scratch-1/tc.txt"
printf '// testcase\n' > "$tc"
target_load "$tc"
assert_eq "$SCRIPT_ROOT/output/demo-exp-a/codex/results" "$RESULTS_DIR" \
  "target_load discovers backend-local experiment session env from testcase path"

teardown_test_env
summary
