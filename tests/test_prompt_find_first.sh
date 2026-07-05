#!/usr/bin/env bash
# Tests for the "file FIND first, reproduce second" workflow directive.
#
# The harness has two complementary artifact dirs:
#   - findings/FIND-*  for concrete security defects (reproducer NOT required)
#   - crashes/CRASH-*  for sanitizer reproducers
#
# Source-only strategies (S2/S3/S5/S8) routinely identify real defects before,
# or without ever achieving, an ASan crash. If the agent waits to file the
# FIND until the testcase crashes, the finding is lost when the agent rotates
# or the iteration ends. The directive added in lib/prompt.sh forces the FIND
# to be filed eagerly. These tests lock that behaviour in.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

source "$SCRIPT_ROOT/lib/prompt.sh"

# Stubs for functions provided by other libs / bin/audit at runtime.
count_verified_asan_runs() { echo 0; }
export -f count_verified_asan_runs
check_agent_quality() { echo ""; }
export -f check_agent_quality
build_enforcement_results_directive() { echo ""; }
export -f build_enforcement_results_directive
neutralize_qa_vocab_string() { cat; }
export -f neutralize_qa_vocab_string

# ═══════════════════════════════════════════════════════════════
# 1. build_find_first_directive — content contract
# ═══════════════════════════════════════════════════════════════
#
# The directive is read by every agent on every prompt. The three
# REQUIRED-content bullets are the canonical FIND filing contract
# (mirrored in .agents/references/session-rules.md). If either side
# drifts, agents and the gate fall out of sync.

directive=$(build_find_first_directive)

assert_match "FILE FIND FIRST, REPRODUCE SECOND" "$directive" \
  "directive: header present"
assert_match "findings/FIND-NNN-<slug>/report.md" "$directive" \
  "directive: names the exact FIND path agents must write"
assert_match "immediately" "$directive" \
  "directive: filing is immediate, not deferred"
assert_match "not.* contingent on a sanitizer crash" "$directive" \
  "directive: FIND not contingent on reproducer"
assert_match "file:function:line" "$directive" \
  "directive: required location format named"
assert_match "issue class" "$directive" \
  "directive: required issue-class bullet"
assert_match "Rationale" "$directive" \
  "directive: required rationale bullet"
assert_match "S2 invariant-negation" "$directive" \
  "directive: names source-only strategy S2"
assert_match "S3 spec-vs-impl" "$directive" \
  "directive: names source-only strategy S3"
assert_match "S5 lifetime/state" "$directive" \
  "directive: names source-only strategy S5"
assert_match "S8 property-based" "$directive" \
  "directive: names source-only strategy S8"
assert_match "non-security FINDs" "$directive" \
  "directive: warns about non-security FIND quarantine"
# Patch guidance: the directive carries only a short best-effort nudge and
# delegates the capture/validation mechanics to the canonical session-rules
# doc (asserted in section 9). Best-effort = never gates a finding.
assert_match "Fix Direction" "$directive" \
  "directive: nudges a one-line Fix Direction"
assert_match "best-effort" "$directive" \
  "directive: patch/fix is best-effort, never blocks filing"
assert_match "session-rules.md" "$directive" \
  "directive: delegates patch mechanics to canonical session-rules"

# Negative — the directive must not promote non-security correctness bugs.
assert_not_match "pure correctness.*are findings" "$directive" \
  "directive: does not invite correctness-only filings"

# ═══════════════════════════════════════════════════════════════
# 2. Cold-start prompt embeds the directive (reproduce role)
# ═══════════════════════════════════════════════════════════════
#
# Cold-start agents start work fresh; they must see the directive before
# the reproducer loop so the very first concrete defect they identify
# gets filed immediately.

IS_BROWSER_TARGET=0
result=$(build_cold_start_prompt 1)
assert_match "COLD START.*Agent 1.*role=reproduce" "$result" \
  "cold start reproduce: header"
assert_match "FILE FIND FIRST, REPRODUCE SECOND" "$result" \
  "cold start reproduce: directive embedded"
assert_match "findings/FIND-NNN-<slug>/report.md" "$result" \
  "cold start reproduce: FIND path present"

# ═══════════════════════════════════════════════════════════════
# 3. Cold-start prompt embeds the directive (analysis role)
# ═══════════════════════════════════════════════════════════════

result=$(build_cold_start_prompt 2)
assert_match "COLD START.*Agent 2.*role=analysis" "$result" \
  "cold start analysis: header"
assert_match "FILE FIND FIRST, REPRODUCE SECOND" "$result" \
  "cold start analysis: directive embedded"

# ═══════════════════════════════════════════════════════════════
# 4. Cold-start directive position — before HARD RULES
# ═══════════════════════════════════════════════════════════════
#
# The directive must appear in the agent-facing body of the prompt,
# above the static "HARD RULES" suffix, so it isn't pushed past the
# model's attention by the trailing rules block.

result=$(build_cold_start_prompt 1)
dir_line=$(printf '%s\n' "$result" | grep -n "FILE FIND FIRST, REPRODUCE SECOND" | head -1 | cut -d: -f1)
rules_line=$(printf '%s\n' "$result" | grep -n "^## HARD RULES" | head -1 | cut -d: -f1)
if [ -n "$dir_line" ] && [ -n "$rules_line" ] && [ "$dir_line" -lt "$rules_line" ]; then
  pass "cold start: directive precedes HARD RULES suffix"
else
  fail "cold start: directive must appear before HARD RULES (directive=$dir_line rules=$rules_line)"
fi

# ═══════════════════════════════════════════════════════════════
# 5. Deep-investigation prompt embeds the directive
# ═══════════════════════════════════════════════════════════════

sf1=$(state_file_path 1)
cat > "$sf1" <<'EOF'
## Primary Subsystem: src/lib
| 1 | H1 | src/lib/Foo.cpp:Bar:42 | shape | guard | bounds | S2 | PENDING |
EOF

result=$(build_deep_investigation_prompt 1)
assert_match "DEEP INVESTIGATION.*Agent A.*role=reproduce" "$result" \
  "deep reproduce: header"
assert_match "FILE FIND FIRST, REPRODUCE SECOND" "$result" \
  "deep reproduce: directive embedded"
assert_match "findings/FIND-NNN-<slug>/report.md" "$result" \
  "deep reproduce: FIND path present"

# Analysis role on the same prompt builder.
cat > "$(state_file_path 2)" <<'EOF'
## Primary Subsystem: src/lib
| 1 | H1 | src/lib/Foo.cpp:Bar:42 | shape | guard | bounds | S5 | PENDING |
EOF
result=$(build_deep_investigation_prompt 2)
assert_match "DEEP INVESTIGATION.*Agent B.*role=analysis" "$result" \
  "deep analysis: header"
assert_match "FILE FIND FIRST, REPRODUCE SECOND" "$result" \
  "deep analysis: directive embedded"

# ═══════════════════════════════════════════════════════════════
# 6. Deep-investigation directive position — before WRITE-RUN-EVALUATE
# ═══════════════════════════════════════════════════════════════
#
# The directive's whole point is that the FIND lands before the
# reproducer loop. If the directive ever drifts below the loop, the
# agent will read "promote to crashes/ immediately" first and file the
# FIND late — exactly the failure mode we are preventing.

result=$(build_deep_investigation_prompt 1)
dir_line=$(printf '%s\n' "$result" | grep -n "FILE FIND FIRST, REPRODUCE SECOND" | head -1 | cut -d: -f1)
loop_line=$(printf '%s\n' "$result" | grep -n "MANDATORY WRITE-RUN-EVALUATE LOOP" | head -1 | cut -d: -f1)
if [ -n "$dir_line" ] && [ -n "$loop_line" ] && [ "$dir_line" -lt "$loop_line" ]; then
  pass "deep: directive precedes MANDATORY WRITE-RUN-EVALUATE LOOP"
else
  fail "deep: directive must appear before WRITE-RUN-EVALUATE (directive=$dir_line loop=$loop_line)"
fi

# ═══════════════════════════════════════════════════════════════
# 7. WRITE-RUN-EVALUATE loop carries the inline FIND-first reminder
# ═══════════════════════════════════════════════════════════════
#
# Even if the top-of-prompt directive scrolls past the model's working
# memory mid-session, the mandatory loop itself must remind the agent
# to file the FIND before starting reproducer iterations.

result=$(build_deep_investigation_prompt 1)
# Extract the MANDATORY WRITE-RUN-EVALUATE LOOP section: from the line
# *after* the heading up to (but not including) the next H2. `awk`'s
# range syntax `/A/,/B/` collapses when A also matches B, so we toggle
# an `in_section` flag manually instead.
loop_block=$(printf '%s\n' "$result" | awk '
  /^## MANDATORY WRITE-RUN-EVALUATE LOOP/ { in_section=1; next }
  in_section && /^## / { exit }
  in_section { print }
')

assert_match "File the FIND first" "$loop_block" \
  "deep loop: inline FIND-first reminder at top of loop"
assert_match "preserved whether or not the reproducer lands" "$loop_block" \
  "deep loop: explains the preservation guarantee"

# ═══════════════════════════════════════════════════════════════
# 8. Browser-target prompt still carries the directive
# ═══════════════════════════════════════════════════════════════
#
# Browser-mode agents work source-only just as often (DOM/IDL/Servo
# audits with no driveable harness yet) and need the same guarantee.

IS_BROWSER_TARGET=1
result=$(build_cold_start_prompt 1)
assert_match "FILE FIND FIRST, REPRODUCE SECOND" "$result" \
  "cold start browser: directive embedded"

result=$(build_deep_investigation_prompt 1)
assert_match "FILE FIND FIRST, REPRODUCE SECOND" "$result" \
  "deep browser: directive embedded"
IS_BROWSER_TARGET=0

# ═══════════════════════════════════════════════════════════════
# 9. session-rules.md ships the canonical policy text
# ═══════════════════════════════════════════════════════════════
#
# The prompt directive is the per-session reminder; session-rules.md
# is the canonical policy agents read once at session start. The two
# must agree or agents get contradictory guidance.

rules="$SCRIPT_ROOT/.agents/references/session-rules.md"
assert_file_exists "$rules" "session-rules.md exists"
assert_file_contains "$rules" "File FIND first, reproduce second" \
  "session-rules: subsection header present"
assert_file_contains "$rules" "before, or in parallel with, the reproducer loop" \
  "session-rules: parallel-filing guidance present"
assert_file_contains "$rules" "Source-only strategies" \
  "session-rules: names source-only strategies"
assert_file_contains "$rules" "the FIND still ships" \
  "session-rules: states the preservation guarantee"

# session-rules.md owns the canonical patch capture/validation mechanics
# (moved here so the per-iteration directive stays a short pointer).
assert_file_contains "$rules" "apply --check" \
  "session-rules: patch validation uses git apply --check"
assert_file_contains "$rules" "non-mutating" \
  "session-rules: describes apply --check as non-mutating"
assert_file_contains "$rules" "not a dry run" \
  "session-rules: corrects the hg import --no-commit dry-run myth"
assert_file_contains "$rules" "never blocks or" \
  "session-rules: patch/fix is best-effort, never gates a finding"

# ═══════════════════════════════════════════════════════════════
# 10. session-rules.md FIND cap is conditional, not blanket
# ═══════════════════════════════════════════════════════════════
#
# The old "Max 1 FIND per agent per iteration" cap throttled source-only
# audit sessions that legitimately surface multiple defects. The new
# rule scopes the cap to iterations where a CRASH was also promoted.

assert_file_contains "$rules" "Max 1 FIND per agent per iteration" \
  "session-rules: cap line still present"
assert_file_contains "$rules" "when you also promoted a CRASH this iteration" \
  "session-rules: cap is conditional on CRASH-this-iteration"
assert_file_contains "$rules" "up to 3 distinct FINDs are allowed" \
  "session-rules: relaxed ceiling stated"
assert_file_contains "$rules" "distinct .file:function:line. locations" \
  "session-rules: distinct-location requirement stated"

# ═══════════════════════════════════════════════════════════════
# 11. FIND Quality Bar still says reproducer NOT required
# ═══════════════════════════════════════════════════════════════
#
# Regression guard: the existing "reproducer is a bonus, not a
# requirement" rule is the foundation of file-FIND-first. If a future
# edit removes it, this test fires.

assert_file_contains "$rules" "sanitizer reproducer, runnable testcase, or web-reachable trigger is NOT required" \
  "session-rules: reproducer-not-required line preserved"
assert_file_contains "$rules" "A reproducer / testcase / ASan output is a bonus, not a requirement" \
  "session-rules: reproducer-is-a-bonus line preserved"

# ═══════════════════════════════════════════════════════════════
# 12. Compact-fresh prompt embeds the directive (post-compaction)
# ═══════════════════════════════════════════════════════════════
#
# compact_fresh is the continuation prompt after a context compaction —
# precisely the moment an un-filed source finding is most at risk of
# being lost. It must carry the FIND-first directive, and the directive
# must precede the "write one testcase / bin/probe" FIRST ACTION so the
# agent files the FIND before entering the reproducer loop.

IS_BROWSER_TARGET=0
result=$(build_compact_fresh_prompt 1)
assert_match "COMPACT FRESH START.*Agent 1.*role=reproduce" "$result" \
  "compact fresh: header"
assert_match "FILE FIND FIRST, REPRODUCE SECOND" "$result" \
  "compact fresh: directive embedded"
assert_match "findings/FIND-NNN-<slug>/report.md" "$result" \
  "compact fresh: FIND path present"

dir_line=$(printf '%s\n' "$result" | grep -n "FILE FIND FIRST, REPRODUCE SECOND" | head -1 | cut -d: -f1)
action_line=$(printf '%s\n' "$result" | grep -n "^## FIRST ACTION" | head -1 | cut -d: -f1)
if [ -n "$dir_line" ] && [ -n "$action_line" ] && [ "$dir_line" -lt "$action_line" ]; then
  pass "compact fresh: directive precedes FIRST ACTION reproducer step"
else
  fail "compact fresh: directive must appear before FIRST ACTION (directive=$dir_line action=$action_line)"
fi

teardown_test_env
summary
