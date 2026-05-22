#!/usr/bin/env bash
# Tests for build_session_directive priority chain (lib/prompt.sh).
# Validates the P1-P7 priority ordering of session directives.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# Source the library under test
source "$SCRIPT_ROOT/lib/prompt.sh"

# Stub count_verified_asan_runs (from lib/quality.sh, not sourced here)
count_verified_asan_runs() { echo 0; }
export -f count_verified_asan_runs

# Stub check_agent_quality
check_agent_quality() { echo ""; }
export -f check_agent_quality

# Stub build_enforcement_results_directive
build_enforcement_results_directive() { echo ""; }
export -f build_enforcement_results_directive

# Stub neutralize_qa_vocab_string (from lib/vocab.sh)
neutralize_qa_vocab_string() { cat; }
export -f neutralize_qa_vocab_string

# ═══════════════════════════════════════════════════════════════
# Setup: create state files for agents
# ═══════════════════════════════════════════════════════════════

sf1=$(state_file_path 1)
sf2=$(state_file_path 2)

# ═══════════════════════════════════════════════════════════════
# 1. P1: Blocklist violation — agent on blocklisted subsystem
# ═══════════════════════════════════════════════════════════════

cat > "$sf1" <<'EOF'
## Primary Subsystem: third_party/rust
| 1 | H1 | third_party/rust/Foo.cpp | shape | guard | bounds | S1 | PENDING |
EOF
# Override get_agent_subsystem to return blocklisted subsystem
get_agent_subsystem() { echo "third_party/rust"; }
export -f get_agent_subsystem

result=$(build_session_directive 1)
assert_match "ROTATE.*blocklisted" "$result" "P1: blocklist violation emits ROTATE directive"
assert_match "third_party/rust" "$result" "P1: names the blocklisted subsystem"

# ═══════════════════════════════════════════════════════════════
# 2. P2: Guard-chain saturation
# ═══════════════════════════════════════════════════════════════

get_agent_subsystem() { echo "dom/canvas"; }
export -f get_agent_subsystem

cat > "$sf1" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | S1 | PENDING |
EOF

gpath=$(guard_chain_path "dom/canvas")
for i in $(seq 1 "$GUARD_CHAIN_ROTATION_THRESHOLD"); do
  echo "Error: regexp too big" >> "$gpath"
done

result=$(build_session_directive 1)
assert_match "GUARD SATURATION" "$result" "P2: guard saturation detected"
assert_match "regexp too big" "$result" "P2: names the saturated guard"
rm -f "$gpath"

# ═══════════════════════════════════════════════════════════════
# 3. P3: Effort-gated rotation — 0 pending + effort passed
# ═══════════════════════════════════════════════════════════════

get_agent_subsystem() { echo "dom/canvas"; }
export -f get_agent_subsystem

# Make count_verified_asan_runs return enough runs
count_verified_asan_runs() { echo "$MIN_ASAN_RUNS_BEFORE_ROTATE"; }
export -f count_verified_asan_runs

cat > "$sf1" <<EOF
## Primary Subsystem: dom/canvas
$(for i in $(seq 1 "$MIN_DISCARDS_BEFORE_ROTATE"); do
  echo "| H$i | hyp $i | f.cpp:F:$i | shape | gap | bounds | S1 | DISCARDED |"
done)
EOF

result=$(build_session_directive 1)
assert_match "ROTATE.*effort gate passed" "$result" "P3: effort-gated rotation"
assert_match "dom/canvas" "$result" "P3: names the exhausted subsystem"

# ═══════════════════════════════════════════════════════════════
# 4. P3b: Effort-gated rotation via ENV-BLOCKED
# ═══════════════════════════════════════════════════════════════

count_verified_asan_runs() { echo 0; }
export -f count_verified_asan_runs

cat > "$sf1" <<EOF
## Primary Subsystem: dom/canvas
| H1 | hyp 1 | f.cpp:F:1 | shape | gap | bounds | S1 | ENV-BLOCKED |
| H2 | hyp 2 | f.cpp:F:2 | shape | gap | bounds | S1 | ENV-BLOCKED |
| H3 | hyp 3 | f.cpp:F:3 | shape | gap | bounds | S1 | DISCARDED |
EOF

result=$(build_session_directive 1)
assert_match "ROTATE.*env-blocked" "$result" "P3b: ENV-BLOCKED triggers rotation"

# ═══════════════════════════════════════════════════════════════
# 4b. P3c: Empty active queue rotates even before effort gate
# ═══════════════════════════════════════════════════════════════

cat > "$sf1" <<EOF
## Primary Subsystem: dom/canvas
| H1 | hyp 1 | f.cpp:F:1 | shape | gap | bounds | S1 | DISCARDED |
EOF

result=$(build_session_directive 1)
assert_match "ROTATE.*active queue empty" "$result" "P3c: no active rows triggers rotation"

# ═══════════════════════════════════════════════════════════════
# 5. P4: Reverse turn budget — many tool calls, no new findings
# ═══════════════════════════════════════════════════════════════

count_verified_asan_runs() { echo 0; }
export -f count_verified_asan_runs

cat > "$sf1" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | S1 | PENDING |
EOF

# Set up prior tool count exceeding the limit
mkdir -p "$LOGDIR"
echo "$PER_HYPOTHESIS_TURN_LIMIT" > "$LOGDIR/.prev_tools_1"
echo "0" > "$LOGDIR/.prev_results_1"

result=$(build_session_directive 1)
assert_match "CHANGE APPROACH" "$result" "P4: reverse turn budget fires"
assert_match "tool calls" "$result" "P4: mentions tool call count"
rm -f "$LOGDIR/.prev_tools_1" "$LOGDIR/.prev_results_1"

# ═══════════════════════════════════════════════════════════════
# 6. P5: Tenure cap
# ══════════���════════════════════════════════════════════════════

cat > "$sf1" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | S1 | PENDING |
EOF

get_agent_tenure_secs() { echo "$SUBSYSTEM_TENURE_CAP_SECS"; }
export -f get_agent_tenure_secs

result=$(build_session_directive 1)
assert_match "TENURE CAP" "$result" "P5: tenure cap directive"
assert_match "hours" "$result" "P5: mentions hours on subsystem"

get_agent_tenure_secs() { echo 0; }
export -f get_agent_tenure_secs

# ═══════════════════════════════════════════════════════════════
# 7. P5b: Strategy rotation — assigned != current
# ═══════════════════════════════════════════════════════════════

cat > "$sf1" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | S1 | PENDING |
EOF

# Write a different strategy assignment
echo "S3" > "$(agent_strategy_path 1)"

get_agent_strategy() { echo "S1"; }
export -f get_agent_strategy

result=$(build_session_directive 1)
assert_match "SWITCH STRATEGY.*S1.*S3" "$result" "P5b: strategy rotation directive"
assert_match "S3" "$result" "P5b: mentions target strategy"

rm -f "$(agent_strategy_path 1)"

get_agent_strategy() { echo "S1"; }
export -f get_agent_strategy

# ═══════════════════════════════════════════════════════════════
# 8. P6: Crash improvement — many discards, few ASan runs
# ═══════════════════════════════════════════════════════════════

cat > "$sf1" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | S1 | DISCARDED |
| 2 | H2 | dom/canvas/Bar.cpp | shape | guard | bounds | S1 | DISCARDED |
| 3 | H3 | dom/canvas/Baz.cpp | shape | guard | bounds | S1 | DISCARDED |
| 4 | H4 | dom/canvas/Qux.cpp | shape | guard | bounds | S1 | PENDING |
EOF

count_verified_asan_runs() { echo 0; }
export -f count_verified_asan_runs

result=$(build_session_directive 1)
assert_match "REPRODUCE BEFORE DISCARDING" "$result" "P6: crash improvement directive"
assert_match "DISCARDED" "$result" "P6: mentions discard count"

# ═══════════════════════════════════════════════════════════════
# 9. P7: Quality feedback fallthrough — shows SESSION STATUS
# ═══════════════════════════════════════════════════════════════

cat > "$sf1" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | S1 | PENDING |
| 2 | H2 | dom/canvas/Bar.cpp | shape | guard | bounds | S1 | PENDING |
EOF

count_verified_asan_runs() { echo 5; }
export -f count_verified_asan_runs

check_agent_quality() { echo "**Stats:** 0 discarded, 2 pending, 0 findings"; }
export -f check_agent_quality

result=$(build_session_directive 1)
assert_match "SESSION STATUS" "$result" "P7: fallthrough shows SESSION STATUS"

# ═══════════════════════════════════════════════════════════════
# 10. P7: Stay-deep — no pending but non-pending active work remains
# ═══════════════════════════════════════════════════════════════

cat > "$sf1" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | S1 | DISCARDED |
| 2 | H2 | dom/canvas/Bar.cpp | shape | guard | bounds | S1 | INVESTIGATING |
EOF

count_verified_asan_runs() { echo 0; }
export -f count_verified_asan_runs

result=$(build_session_directive 1)
# With no PENDING rows but one INVESTIGATING row, the agent must finish the
# in-flight hypothesis rather than cold-rotate or open a new one.
assert_match "Finish active INVESTIGATING/NEEDS_TESTCASE" "$result" "P7: stay-deep message for active non-pending work"

# ═══════════════════════════════════════════════════════════════
# 11. Priority ordering — P1 wins over P2
# ═══════════════════════════════════════════════════════════════

get_agent_subsystem() { echo "third_party/rust"; }
export -f get_agent_subsystem

cat > "$sf1" <<'EOF'
## Primary Subsystem: third_party/rust
| 1 | H1 | third_party/rust/Foo.cpp | shape | guard | bounds | S1 | PENDING |
EOF

# Also saturate guard chain
gpath=$(guard_chain_path "third_party/rust")
for i in $(seq 1 "$GUARD_CHAIN_ROTATION_THRESHOLD"); do
  echo "Error: guard hit" >> "$gpath"
done

result=$(build_session_directive 1)
assert_match "ROTATE.*blocklisted" "$result" "P1 beats P2: blocklist wins over guard saturation"
assert_not_match "GUARD SATURATION" "$result" "P1 beats P2: guard saturation NOT shown"
rm -f "$gpath"

# Reset to non-blocklisted
get_agent_subsystem() { echo "dom/canvas"; }
export -f get_agent_subsystem

# ═══════════════════════════════════════════════════════════════
# 12. No state file → no directive (empty output)
# ═══════════════════════════════════════════════════════════════

rm -f "$sf1"
result=$(build_session_directive 1)
assert_eq "" "$result" "no state file → empty directive"

# ═══════════════════════════════════════════════════════════════
# 13. build_strategy_assignment_line — no assigned strategy
# ═══════════════════════════════════════════════════════════════

rm -f "$(agent_strategy_path 1)"
result=$(build_strategy_assignment_line 1)
assert_match "Strategy priority.*S1.*S2.*S3.*S4.*S5.*S6.*S7" "$result" \
  "no assignment: shows default priority order"

# ═══════════════════════════════════════════════════════════════
# 14. build_strategy_assignment_line — with assigned strategy
# ═══════════════════════════════════════════════════════════════

echo "S4" > "$(agent_strategy_path 1)"
result=$(build_strategy_assignment_line 1)
assert_match "Assigned strategy: S4" "$result" "assigned: shows S4"
assert_match "S4-differential.md" "$result" "assigned: references strategy file"
rm -f "$(agent_strategy_path 1)"

# ═══════════════════════════════════════════════════════════════
# 15. build_cross_agent_summary — excludes self
# ═══════════════════════════════════════════════════════════════

cat > "$sf2" <<'EOF'
## Primary Subsystem: js/src/jit
| 1 | H1 | js/src/jit/Foo.cpp | shape | guard | bounds | S1 | PENDING |
| 2 | H2 | js/src/jit/Bar.cpp | shape | guard | bounds | S1 | CRASH-001-2 |
EOF

result=$(build_cross_agent_summary 1)
assert_match "Agent 2" "$result" "cross-agent summary: includes other agent"
assert_not_match "Agent 1" "$result" "cross-agent summary: excludes self"
assert_match "PENDING" "$result" "cross-agent summary: shows pending count"

# ═══════════════════════════════════════════════════════════════
# 16. build_subsystem_targets — generic target
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0
result=$(build_subsystem_targets "generic")
assert_match "HIGH-VALUE TARGETS" "$result" "generic target: has HIGH-VALUE header"
assert_match "Candidate directories" "$result" "generic target: lists candidate dirs"

# ═══════════════════════════════════════════════════════════════
# 17. build_subsystem_targets — browser mode
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1
result=$(build_subsystem_targets "browser")
assert_match "BROWSER MODE" "$result" "browser mode: has BROWSER MODE header"
assert_match "BLOCKLISTED" "$result" "browser mode: shows blocklist"

# ═══════════════════════════════════════════════════════════════
# 18. build_subsystem_targets — shell mode
# ═══════════════════════════════════════════════════════════════

result=$(build_subsystem_targets "shell")
assert_match "SHELL MODE" "$result" "shell mode: has SHELL MODE header"
assert_match "BLOCKLISTED" "$result" "shell mode: shows blocklist"
IS_BROWSER_TARGET=0

# ═══════════════════════════════════════════════════════════════
# 19. build_common_suffix — has required hard rules
# ═══════════════════════════════════════════════════════════════

result=$(_build_common_suffix_inline)
assert_match "HARD RULES" "$result" "common suffix: has HARD RULES header"
assert_match "BLOCKLISTED" "$result" "common suffix: mentions blocklist"
assert_match "Guard-chain rule" "$result" "common suffix: mentions guard chain"
assert_match "SEARCH DISCIPLINE" "$result" "common suffix: has SEARCH DISCIPLINE"
assert_match "No OR-chain" "$result" "common suffix: no OR-chain rule"

# ═══════════════════════════════════════════════════════════════
# 20. build_handoff_directive — no handoff for analysis agents
# ═══════════════════════════════════════════════════════════════

agent_role() { echo "analysis"; }
export -f agent_role

result=$(build_handoff_directive 1)
assert_eq "" "$result" "handoff: empty for analysis agents"

# ═══════════════════════════════════════════════════════════════
# 21. build_handoff_directive — shows handoff for reproduce agents
# ═══════════════════════════════════════════════════════════════

agent_role() {
  case "$1" in 2) echo "analysis" ;; *) echo "reproduce" ;; esac
}
export -f agent_role

hf=$(handoff_file_path)
cat > "$hf" <<'EOF'
| Hypothesis | File:Function:Line | Input Shape | Guard Gap | Diagnostic | Strategy | Source |
|-----------|-------------------|-------------|-----------|------------|----------|--------|
| H5 UAF in Parser | parser.cpp:Parse:42 | crafted HTML | none | heap-use-after-free | S1 | Agent 2 |
EOF

result=$(build_handoff_directive 1)
assert_match "HANDOFF FROM ANALYSIS" "$result" "handoff: shows header for reproduce agent"
assert_match "H5 UAF in Parser" "$result" "handoff: includes hypothesis row"

# ═══════════════════════════════════════════════════════════════
# 22. build_asan_build_directive — generic target, build available
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0
ASAN_BUILD_AVAILABLE=1
ASAN_BUILD_BINARY="$ASAN_BUILD_DIR/bin/testproject"

result=$(build_asan_build_directive)
assert_match "ALREADY AVAILABLE" "$result" "Sanitizer build: shows already available"
assert_match "Do NOT rebuild" "$result" "Sanitizer build: warns not to rebuild"

# ═══════════════════════════════════════════════════════════════
# 23. build_asan_build_directive — generic target, no build
# ═══════════════════════════════════════════════════════════════

ASAN_BUILD_AVAILABLE=0
ASAN_BUILD_BINARY=""

result=$(build_asan_build_directive)
assert_match "NOT FOUND" "$result" "Sanitizer build: shows not found"
assert_match "fsanitize=address" "$result" "Sanitizer build: shows build instructions"

# ═══════════════════════════════════════════════════════════════
# 24. build_asan_build_directive — browser target → empty
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1
result=$(build_asan_build_directive)
assert_eq "" "$result" "Sanitizer build: empty for browser target"
IS_BROWSER_TARGET=0

teardown_test_env
summary
