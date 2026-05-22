#!/usr/bin/env bash
# Unit tests for bin/show-exclusions — current result layout reporting.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

SHOW_EXCLUSIONS="$SCRIPT_ROOT/bin/show-exclusions"

mkdir -p "$RESULTS_DIR/crashes/CRASH-001-alpha"
mkdir -p "$RESULTS_DIR/findings/FIND-010-state"
mkdir -p "$RESULTS_DIR/crashes-rejected/CRASH-002-null"
mkdir -p "$RESULTS_DIR/fuzz-crashes/FuzzerA/shutdown-noise"

cat > "$RESULTS_DIR/crashes-rejected/CRASH-002-null/.autodiscard" <<'EOF'
# Auto-rejected by triage
# Reason: null-deref
EOF
printf 'shutdown noise\n' > "$RESULTS_DIR/fuzz-crashes/FuzzerA/shutdown-noise/crash-da39"

output=$(bash "$SHOW_EXCLUSIONS" "$RESULTS_DIR" 2>&1)
rc=$?

assert_eq "0" "$rc" "show-exclusions: exits successfully"
assert_match "Active crash candidates" "$output" "show-exclusions: active section present"
assert_match "CRASH-001-alpha" "$output" "show-exclusions: lists current CRASH layout"
assert_match "FIND-010-state" "$output" "show-exclusions: lists current FIND layout"
assert_match "CRASH-002-null[[:space:]]+null-deref" "$output" "show-exclusions: rejected reason"
assert_match "fuzz-crashes/FuzzerA/shutdown-noise/crash-da39" "$output" "show-exclusions: shutdown-noise entry"
assert_match "active crashes:[[:space:]]+1" "$output" "show-exclusions: active count"
assert_match "confirmed findings:[[:space:]]+1" "$output" "show-exclusions: finding count"
assert_match "rejected crashes:[[:space:]]+1" "$output" "show-exclusions: rejected count"
assert_match "fuzz noise moved:[[:space:]]+1" "$output" "show-exclusions: noise count"
assert_not_match "VULN-" "$output" "show-exclusions: no stale VULN layout"

teardown_test_env
summary
