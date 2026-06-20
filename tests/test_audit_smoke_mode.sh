#!/usr/bin/env bash
# Single-iteration bin/audit runs are smoke tests: no recon and one worker.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

AUDIT_SRC="$SCRIPT_ROOT/bin/audit"

_CURRENT_TEST="bin/audit documents single-iteration smoke mode"
assert_file_contains "$AUDIT_SRC" "1 is" "$_CURRENT_TEST: usage mentions max_iterations=1"
assert_file_contains "$AUDIT_SRC" "treated as a smoke test" "$_CURRENT_TEST: usage describes smoke behavior"

_CURRENT_TEST="bin/audit treats max_iterations=1 as smoke mode"
assert_file_contains "$AUDIT_SRC" 'MAX_ITERATIONS" -eq 1' "$_CURRENT_TEST: positional one enables smoke mode"

_CURRENT_TEST="bin/audit clamps smoke mode to one agent"
assert_file_contains "$AUDIT_SRC" 'MAX_ITERATIONS" -eq 1' "$_CURRENT_TEST: smoke mode branch present"
assert_file_contains "$AUDIT_SRC" "NUM_AGENTS=1" "$_CURRENT_TEST: total workers clamped"
assert_file_contains "$AUDIT_SRC" "BROWSER_AGENTS=1" "$_CURRENT_TEST: browser smoke uses one browser worker"
assert_file_not_contains "$AUDIT_SRC" "SHELL_AGENTS=1" "$_CURRENT_TEST: generic smoke only clamps NUM_AGENTS"

_CURRENT_TEST="bin/audit skips recon seeding in smoke mode"
assert_file_contains "$AUDIT_SRC" "skipped for smoke test mode" "$_CURRENT_TEST: recon skip is logged"
assert_file_contains "$AUDIT_SRC" "return 0" "$_CURRENT_TEST: recon helper exits cleanly"

_CURRENT_TEST="bin/audit supports hidden skip-recon for benchmark experiments"
assert_file_contains "$AUDIT_SRC" "AUDIT_SKIP_RECON=0" "$_CURRENT_TEST: flag state is initialized"
assert_file_contains "$AUDIT_SRC" "skip-recon)" "$_CURRENT_TEST: parser accepts the hidden flag"
assert_file_contains "$AUDIT_SRC" "skipped by --skip-recon" "$_CURRENT_TEST: recon helper skips only seeding"
assert_file_not_contains "$AUDIT_SRC" "Skip breadth-first recon seeding" \
  "$_CURRENT_TEST: hidden flag is not advertised in usage"

summary
