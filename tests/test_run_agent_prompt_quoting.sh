#!/usr/bin/env bash
# Regression test for run_agent's prompt_with_budget assembly.
#
# Bug (introduced by 2a9766d): the SESSION/PROBE-RUN-BUDGET block was built
# with a double-quoted assignment, prompt_with_budget="${prompt} ... ", whose
# body carried *literal, unescaped* double-quotes:
#
#     - **A "safe / no-bug" verdict is a probe result ... "well-guarded" ...
#
# Inside a "..." assignment the first inner " closes the string, the next
# bareword ("safe") concatenates onto the value, and the SPACE after it ends
# the assignment word — so the following ` / ` was parsed as a *command*. The
# agent subshell died with `bin/audit: line NNNN: /: is a directory` (exit 126)
# before running a single turn. Every claude harness launch hit it.
#
# bash -n / CI never caught it: the construct is valid *syntax* (the failure is
# runtime word-splitting), and no unit test launches a real backend, so the
# prompt-assembly path was never executed. This test executes it directly.
#
# The fix escapes the inner quotes (\"...\"), matching how the same block
# already escapes its backticks. This test re-evaluates the live assignment
# from bin/audit under the same `set -euo pipefail` the harness uses and
# asserts it produces one clean string with the inner quotes intact — so a
# future unescaped quote in that block fails here instead of in production.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

AUDIT="$SCRIPT_ROOT/bin/audit"
assert_file_exists "$AUDIT" "bin/audit present"

# Extract the live prompt_with_budget assignment: from the assignment line
# through its closing `... past the budget."` line. Anchored on stable text,
# not line numbers, so the test follows edits to the block.
block="$(awk '
  /prompt_with_budget="/        { capture=1 }
  capture                       { print }
  capture && /past the budget\."/ { exit }
' "$AUDIT")"

assert_match 'prompt_with_budget=' "$block" "extracted the prompt_with_budget assignment block"
assert_match 'past the budget\."' "$block" "extraction reached the closing quote"

# Evaluate the real assignment with stub interpolated vars, under the exact
# shell flags bin/audit's agent subshell runs with. If an inner quote is
# unescaped, eval splits the word and tries to run a stray command — nonzero
# rc and/or a `/: is a directory` style message on stderr.
out="$TEST_TMPDIR/pwb.out"
err="$TEST_TMPDIR/pwb.err"
(
  set -euo pipefail
  prompt="SENTINEL_PROMPT_BODY"
  max_turns=42
  agent_asan_budget=60
  agent_mode_kind=generic
  eval "$block"
  printf '%s' "$prompt_with_budget" > "$out"
) 2> "$err"
rc=$?

assert_eq "0" "$rc" "evaluating the prompt_with_budget assignment must not spawn a stray command (exit 126 = the quoting bug)"
assert_eq "" "$(cat "$err")" "no stderr from the assignment (a '/: is a directory' here means an inner quote is unescaped)"
assert_file_contains "$out" "SENTINEL_PROMPT_BODY" "the base prompt is interpolated into prompt_with_budget"
assert_file_contains "$out" "PROBE RUN BUDGET" "the probe-budget block is present in prompt_with_budget"
# The inner-quoted phrases must survive verbatim — proof the quotes are escaped,
# not breaking the string. If the bug returns, the value is truncated before here.
assert_file_contains "$out" '"safe / no-bug"' "inner double-quoted phrase survives intact in the rendered prompt"
assert_file_contains "$out" '"well-guarded"' "later inner double-quoted phrase survives intact too"

teardown_test_env
summary
