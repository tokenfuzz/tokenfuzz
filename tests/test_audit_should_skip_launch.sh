#!/usr/bin/env bash
# Unit tests for audit_should_skip_launch — the orchestrator-side
# eligibility check that prevents bin/audit from paying a full LLM
# round-trip just to discover the agent has nothing to do.
#
# Returns 0 (skip) only when ALL three sources of work are dry for
# THIS agent. Slot 1 always launches (return 1) so cold-start
# discovery survives even when counters look empty.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

audit_extract_function() {
  local name="$1"
  awk -v name="$name" '
    $0 ~ "^" name "\\(\\) \\{" { in_func=1 }
    in_func { print }
    in_func && $0 == "}" { exit }
  ' "$SCRIPT_ROOT/bin/audit"
}

eval "$(audit_extract_function audit_should_skip_launch)"

# The helper calls count_active_hypotheses_for_agent and fuzz_leads_empty
# and shells out to bin/state. Provide minimal stubs so the test stays
# hermetic and doesn't depend on a real target.
NUM_AGENTS=3
export NUM_AGENTS

# Per-test toggles set by the cases below.
__active_for_agent=""
count_active_hypotheses_for_agent() { echo "${__active_for_agent:-0}"; }
agent_mode() { echo "generic"; }
agent_role() { echo "reproduce"; }
get_agent_subsystem() { echo "unknown"; }
state_strategy_arg() { printf '%s\n' "${__strategy_arg:-}"; }
__fuzz_empty=1
fuzz_leads_empty() { return "${__fuzz_empty:-0}"; }
# bin/state stub — controlled per-test via __peek_exit.
mkdir -p "$TEST_TMPDIR/binstub"
cat > "$TEST_TMPDIR/binstub/state" <<'STUB'
#!/usr/bin/env bash
[ -n "${STATE_ARGS_LOG:-}" ] && printf '%s\n' "$*" >> "$STATE_ARGS_LOG"
if [ "${REQUIRE_STRATEGY:-0}" = "1" ]; then
  case " $* " in
    *" --strategy S7 "*) exit 0 ;;
    *) exit 1 ;;
  esac
fi
# Exit code is read from $PEEK_EXIT (default 1: no eligible card).
exit "${PEEK_EXIT:-1}"
STUB
chmod +x "$TEST_TMPDIR/binstub/state"
PATH="$TEST_TMPDIR/binstub:$PATH"
export PATH
# Make work-cards.jsonl non-empty so the file-size check passes.
mkdir -p "$RESULTS_DIR"
echo '{"id":"WORK-x","status":"unclaimed"}' > "$RESULTS_DIR/work-cards.jsonl"
# bin/state is consulted only when the path is "bin/state" inside the
# helper. The PATH override doesn't catch that — instead, the helper
# tests `[ -x "bin/state" ]`. cd to a dir where ./bin/state exists.
mkdir -p "$TEST_TMPDIR/wd/bin"
cp "$TEST_TMPDIR/binstub/state" "$TEST_TMPDIR/wd/bin/state"
cd "$TEST_TMPDIR/wd"

# ── Slot 1 ALWAYS launches, regardless of all-empty signals ─────
__active_for_agent=0
__fuzz_empty=0
PEEK_EXIT=1
if audit_should_skip_launch 1; then
  fail "slot 1 always launches" "audit_should_skip_launch returned 0 for agent 1"
else
  pass "slot 1 always launches even when all counters are dry"
fi

# ── All-dry slot 2: should be skipped (return 0) ────────────────
__active_for_agent=0
__fuzz_empty=0    # 0 = empty (fuzz_leads_empty returns 0)
PEEK_EXIT=1       # 1 = no eligible card
export PEEK_EXIT
if audit_should_skip_launch 2; then
  pass "all-dry slot 2 is skipped"
else
  fail "all-dry slot 2 should be skipped"
fi

# ── Active hypothesis: do NOT skip (return 1) ────────────────────
__active_for_agent=1
__fuzz_empty=0
PEEK_EXIT=1
if audit_should_skip_launch 2; then
  fail "active hypothesis should keep slot alive"
else
  pass "active hypothesis keeps slot alive"
fi

# ── Eligible work card: do NOT skip ──────────────────────────────
__active_for_agent=0
__fuzz_empty=0
PEEK_EXIT=0       # peek succeeds
export PEEK_EXIT
if audit_should_skip_launch 2; then
  fail "eligible card should keep slot alive"
else
  pass "eligible card keeps slot alive"
fi

# ── Strategy filter: same next-card lane as prompt construction ───
STATE_ARGS_LOG="$TEST_TMPDIR/state-args.log"
: > "$STATE_ARGS_LOG"
REQUIRE_STRATEGY=1
export STATE_ARGS_LOG REQUIRE_STRATEGY
__strategy_arg="--strategy S7"
__active_for_agent=0
__fuzz_empty=0
PEEK_EXIT=1       # ignored by REQUIRE_STRATEGY
export PEEK_EXIT
if audit_should_skip_launch 2; then
  fail "strategy-compatible card should keep slot alive"
else
  pass "strategy-compatible card keeps slot alive"
fi
assert_file_contains "$STATE_ARGS_LOG" 'strategy S7' \
  "audit_should_skip_launch passes current strategy to next-card"
REQUIRE_STRATEGY=0
__strategy_arg=""
export REQUIRE_STRATEGY

# ── Fuzz leads present: do NOT skip ──────────────────────────────
__active_for_agent=0
__fuzz_empty=1    # 1 = not empty
PEEK_EXIT=1
export PEEK_EXIT
if audit_should_skip_launch 2; then
  fail "fuzz leads should keep slot alive"
else
  pass "fuzz leads keep slot alive"
fi

# ── Missing agent number argument: do NOT skip (return 1) ────────
if audit_should_skip_launch ""; then
  fail "missing agent_num should not skip"
else
  pass "missing agent_num returns no-skip"
fi

# ── work-cards.jsonl missing: behave as if no eligible card ──────
rm -f "$RESULTS_DIR/work-cards.jsonl"
__active_for_agent=0
__fuzz_empty=0
PEEK_EXIT=0    # would succeed but file missing short-circuits
export PEEK_EXIT
if audit_should_skip_launch 2; then
  pass "no work-cards.jsonl => skip when other sources dry"
else
  fail "no work-cards.jsonl should still allow skip when all other sources dry"
fi

teardown_test_env
summary
