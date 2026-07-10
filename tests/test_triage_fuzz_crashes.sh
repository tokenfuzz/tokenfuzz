#!/usr/bin/env bash
# Unit tests for bin/triage-fuzz-crashes artifact filtering and bounds.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

TRIAGE="$SCRIPT_ROOT/bin/triage-fuzz-crashes"
LEADS="$RESULTS_DIR/fuzz-leads.md"

# No fuzz directory still materializes the stable marker file.
"$TRIAGE" "$RESULTS_DIR"
assert_file_exists "$LEADS" "triage fuzz: no-run marker is written"
assert_file_contains "$LEADS" '^# Fuzz Crash Leads$' "triage fuzz: marker has heading"
assert_file_contains "$LEADS" 'run a fuzz target first' "triage fuzz: marker explains next step"

mkdir -p "$RESULTS_DIR/fuzz-crashes/ParserA" \
  "$RESULTS_DIR/fuzz-crashes/ParserB" \
  "$RESULTS_DIR/fuzz-crashes/ParserB/shutdown-noise"
printf 'older input\n' > "$RESULTS_DIR/fuzz-crashes/ParserA/timeout-old"
printf 'newer input\n' > "$RESULTS_DIR/fuzz-crashes/ParserA/crash-new"
: > "$RESULTS_DIR/fuzz-crashes/ParserA/oom-empty"
printf 'noise\n' > "$RESULTS_DIR/fuzz-crashes/ParserB/shutdown-noise/crash-noise"
touch -t 202601010101 "$RESULTS_DIR/fuzz-crashes/ParserA/timeout-old"
touch -t 202602020202 "$RESULTS_DIR/fuzz-crashes/ParserA/crash-new"

run_out=$("$TRIAGE" "$RESULTS_DIR" 1 2>&1)
assert_match '1 leads' "$run_out" "triage fuzz: reports bounded lead count"
assert_file_contains "$LEADS" '^## ParserA / crash-new$' "triage fuzz: newest candidate wins"
assert_file_not_contains "$LEADS" 'timeout-old' "triage fuzz: max limit excludes older candidate"
assert_file_not_contains "$LEADS" 'oom-empty' "triage fuzz: empty artifact excluded"
assert_file_not_contains "$LEADS" 'crash-noise' "triage fuzz: shutdown noise excluded"
assert_file_contains "$LEADS" 'FUZZER=ParserA bin/run-asan fuzz-repro' \
  "triage fuzz: reproduction command includes fuzzer"

zero_out=$("$TRIAGE" "$RESULTS_DIR" 0 2>&1)
assert_match '0 leads' "$zero_out" "triage fuzz: zero limit emits no leads"
assert_file_not_contains "$LEADS" '^## ' "triage fuzz: zero limit has no lead sections"
assert_file_contains "$LEADS" 'No non-noise fuzz crashes found' \
  "triage fuzz: zero limit writes empty marker"

invalid_rc=0
invalid_out=$("$TRIAGE" "$RESULTS_DIR" invalid 2>&1) || invalid_rc=$?
assert_eq 2 "$invalid_rc" "triage fuzz: invalid limit exits 2"
assert_match 'max_leads must be a non-negative integer' "$invalid_out" \
  "triage fuzz: invalid limit reports usage error"

teardown_test_env
summary
