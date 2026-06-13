#!/usr/bin/env bash
# Tests for Fix 1 — soft turn-cap watchdog.
#
# The watchdog lives inside bin/audit's run_agent function and triggers
# a SIGTERM cascade against a long-running codex session when the count
# of completed command_execution items in the raw JSON stream crosses
# TURN_SOFT_CAP. End-to-end testing the watchdog would require a fake
# codex binary plus the full audit harness around it; instead, we test
# the load-bearing pieces in isolation:
#
#   1. The counter heuristic — the grep that bin/audit uses to count
#      completed command_executions in the codex .log.raw stream — gives
#      the same answer as the canonical jq-backed
#      extract_completed_item_count helper on representative fixtures.
#      That's the contract that determines when the cap fires.
#   2. TURN_SOFT_CAP and TURN_SOFT_CAP_POLL_SECS are declared with
#      sensible defaults and a 0-disable contract.
#   3. The kill cascade only runs for codex (not Claude / Gemini —
#      they each have their own session-shape and would be harmed by a
#      duplicate cap mechanism).
#   4. The prompt-side TURN BUDGET directive is present in the common
#      suffix so agents know the cap exists and can checkpoint before
#      it fires.

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

AUDIT="$SCRIPT_ROOT/bin/audit"
PROMPT_SH="$SCRIPT_ROOT/lib/prompt.sh"

bash -n "$AUDIT" 2>/dev/null
assert_eq 0 $? "bin/audit: syntax check passes"

# ── 1) Counter heuristic agrees with the canonical jq helper ──────
#
# Build a fake codex .log.raw stream. The format mirrors what codex
# emits: one JSON object per line, item.completed events for each shell
# command. We synthesize 8 command_executions plus 3 non-command items
# (assistant_message, file_change, etc.) — the watchdog must count 8.
RAWLOG="$TEST_TMPDIR/fake.log.raw"
> "$RAWLOG"
for i in 1 2 3 4 5 6 7 8; do
  printf '{"type":"item.completed","item":{"id":"item_%d","type":"command_execution","command":"echo %d","aggregated_output":"%d","exit_code":0,"status":"completed"}}\n' \
    "$i" "$i" "$i" >> "$RAWLOG"
done
# Noise: assistant messages and a non-command item — should NOT count.
printf '{"type":"item.completed","item":{"id":"item_msg1","type":"agent_message","text":"thinking"}}\n' >> "$RAWLOG"
printf '{"type":"item.completed","item":{"id":"item_msg2","type":"agent_message","text":"more thinking"}}\n' >> "$RAWLOG"
printf '{"type":"item.completed","item":{"id":"item_other","type":"file_change","path":"foo"}}\n' >> "$RAWLOG"

# Canonical answer: the jq-backed helper bin/audit uses for telemetry.
canonical=$(bash -c "
  set -u
  # Source enough of bin/audit to get the helper. We pull just the
  # extract_completed_item_count function with awk, avoiding bin/audit's
  # giant main body.
  awk '/^extract_completed_item_count\(\)/,/^}$/' '$AUDIT' > '$TEST_TMPDIR/_extract.sh'
  source '$TEST_TMPDIR/_extract.sh'
  extract_completed_item_count '$RAWLOG' command_execution
")
assert_eq 8 "$canonical" "canonical helper counts 8 command_executions"

# Watchdog's grep heuristic. This is the exact pattern from bin/audit's
# turn-cap watcher — it has to match the same set of items.
heuristic=$(grep -c '"type":"item.completed".*"type":"command_execution"' "$RAWLOG" 2>/dev/null | head -1)
heuristic="${heuristic:-0}"
assert_eq "$canonical" "$heuristic" \
  "watchdog grep heuristic agrees with canonical helper ($heuristic vs $canonical)"

# Noise items must not inflate the count.
assert_eq 8 "$heuristic" "watchdog heuristic does not count agent_message items"

# ── 2) Defaults and the 0-disable contract ────────────────────────
#
# TURN_SOFT_CAP and the poll knob are defined near the top of bin/audit.
# Defaults must be present (so an operator who doesn't export anything
# gets the documented behavior) AND the script must accept the override
# form (so a future operator can set TURN_SOFT_CAP=0 to disable).
#
# Uses grep -F because the patterns contain ${...} bash expansion and ":"
# characters that ERE would interpret. The assert_file_contains helper
# uses ERE, so we shell out directly here.
_grep_fixed_in_file() {
  local needle="$1" file="$2" name="$3"
  if grep -qF -- "$needle" "$file" 2>/dev/null; then
    pass "$name"
  else
    fail "$name" "fixed-string needle not found: $needle"
  fi
}
_grep_fixed_in_file 'TURN_SOFT_CAP="${TURN_SOFT_CAP:-75}"' "$AUDIT" \
  "bin/audit declares TURN_SOFT_CAP default of 75"
_grep_fixed_in_file 'TURN_SOFT_CAP_POLL_SECS="${TURN_SOFT_CAP_POLL_SECS:-10}"' "$AUDIT" \
  "bin/audit declares TURN_SOFT_CAP_POLL_SECS default of 10"

# The watcher block must include the 0-disable short-circuit so the
# operator escape hatch actually works.
_grep_fixed_in_file '"${TURN_SOFT_CAP:-0}" -gt 0' "$AUDIT" \
  "bin/audit gates the watcher on TURN_SOFT_CAP > 0"

# ── 3) Codex-only gating ──────────────────────────────────────────
#
# The watcher block must check that ACTIVE_BACKEND == codex. If we ever
# accidentally fire it for Claude (which has its own --max-turns) or
# Gemini (which self-paces), we'd kill agents mid-turn for no benefit.
# We match on the exact gate line so a future refactor that drops the
# check shows up as a test failure.
_grep_fixed_in_file '"$ACTIVE_BACKEND" = "codex"' "$AUDIT" \
  "bin/audit gates the watcher on the codex backend"

# ── 4) Prompt-side TURN BUDGET directive ──────────────────────────
#
# Agents need to know the cap exists and to checkpoint state proactively
# before it fires. Without the prompt directive, a session at turn 74
# would get SIGTERMed mid-hypothesis with no state-checkpoint signal.
#
# Build the common suffix in a contained shell. We need RESULTS_DIR set
# (for the rejected-crashes path), REFERENCE_DIR (for the rules digest),
# plus a couple of stub helpers the common suffix calls into.
#
# The stubs MUST be defined AFTER sourcing prompt.sh — sourcing redefines
# cached_blocklist_description, which would otherwise clobber a stub that
# was defined earlier. We also stub the deeper blocklist_description that
# cached_blocklist_description falls through to when ITERATION_CACHE_DIR
# is empty (the default in test envs).
RES="$TEST_TMPDIR/results"
mkdir -p "$RES/crashes-rejected"
output=$(
  RESULTS_DIR="$RES" \
  REFERENCE_DIR="$SCRIPT_ROOT/.agents/references" \
  ITERATION_CACHE_DIR="" \
  bash -c '
    source "'"$PROMPT_SH"'"
    cached_blocklist_description() { echo "test-blocklist"; }
    blocklist_description()        { echo "test-blocklist"; }
    fuzz_leads_path()              { echo "/tmp/fuzz-leads.md"; }
    _build_common_suffix_inline
  '
)
assert_match 'TURN BUDGET' "$output" "common suffix advertises the turn budget"
assert_match 'TURN_SOFT_CAP' "$output" \
  "common suffix names the env knob agents/operators can tune"
assert_match 'Checkpoint frequently' "$output" \
  "common suffix instructs agents to checkpoint state proactively"
assert_match 'soft turn budget of ~75' "$output" \
  "common suffix names the actual default value"

# The directive must signal that the cap is not user-overridable from
# inside the session — otherwise agents will try to disable it.
# We match a single-line fragment to avoid asserting on wrapped text.
assert_match 'harness is the only' "$output" \
  "common suffix signals the cap is harness-owned, not agent-overridable"

# Perf guidance: agents must be told NOT to read the harness's own tool SOURCE
# (bin/*, lib/*) to learn how a tool works — that dumps irrelevant bytes that
# every later turn re-sends (measured ~18% of agent output bytes on a sample
# run). The fix points them at `<tool> --help` instead. Lock both halves in so
# the instruction can't silently regress.
assert_match "harness's own tool source" "$output" \
  "common suffix tells agents not to read harness bin/*,lib/* tool source"
assert_match 'bin/probe --help' "$output" \
  "common suffix points agents to <tool> --help instead of reading source"

# ── 5) The watchdog grep handles realistic codex outputs ──────────
#
# Defensive: real codex output may include nested JSON inside aggregated_output
# (commands that emit JSON, or codex echoing back tool args). The watcher
# heuristic must not over-count when those nested strings happen to include
# the pattern fragments. We embed a fake command whose output itself
# contains the substring "type":"command_execution" and confirm we still
# count just the one real completion.
RAW2="$TEST_TMPDIR/nested.log.raw"
{
  echo '{"type":"item.started","item":{"id":"item_99","type":"command_execution","command":"cat data.json","status":"in_progress"}}'
  # The aggregated_output happens to contain a string that looks like our
  # marker. We want exactly 1 completion counted.
  printf '{"type":"item.completed","item":{"id":"item_99","type":"command_execution","aggregated_output":"{\\"type\\":\\"command_execution\\":\\"fake\\"}","status":"completed"}}\n'
} > "$RAW2"
nested_count=$(grep -c '"type":"item.completed".*"type":"command_execution"' "$RAW2" 2>/dev/null | head -1)
nested_count="${nested_count:-0}"
# One real completion, regardless of nested-string false-friends.
assert_eq 1 "$nested_count" \
  "watchdog heuristic resists nested-JSON false positives"

# ── 6) Regression: watcher must not use `grep -c ... || echo 0` ───
#
# grep -c exits 1 with "0" on stdout when there are zero matches; the
# naive `|| echo 0` fallback then yields "0\n0" and the next `[ -eq ]`
# comparison fails with `integer expression expected`. We extract just
# the TURN_SOFT_CAP watcher block (the `if [ "$ACTIVE_BACKEND" = "codex" ]`
# guard through its closing `fi`) and assert the bad pattern is absent.
watcher_block=$(awk '
  /if \[ "\$ACTIVE_BACKEND" = "codex" \] && \[ "\${TURN_SOFT_CAP:-0}" -gt 0 \]; then/ { in_blk=1 }
  in_blk { print; depth += gsub(/\<if\>|\<while\>|\<for\>|\<case\>/, "&"); depth -= gsub(/\<fi\>|\<done\>|\<esac\>/, "&") }
  in_blk && depth == 0 { exit }
' "$AUDIT")
if grep -q 'grep -c.*|| *echo' <<<"$watcher_block"; then
  fail "watcher block free of 'grep -c ... || echo' poison-fallback" \
       "watcher still uses the multi-line 'grep -c ... || echo N' pattern (see bin/audit comment at agent_probe_activity_score)"
else
  pass "watcher block free of 'grep -c ... || echo' poison-fallback"
fi

teardown_test_env
summary
