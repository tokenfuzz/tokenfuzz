#!/usr/bin/env bash
# Tests for build_cold_start_prompt and build_deep_investigation_prompt
# in lib/prompt.sh — validates prompt structure, role guidance, strategy
# assignment, and mode-specific content.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# Source the library under test
source "$SCRIPT_ROOT/lib/prompt.sh"

# Stubs for functions from other libs
count_verified_asan_runs() { echo 0; }
export -f count_verified_asan_runs
check_agent_quality() { echo ""; }
export -f check_agent_quality
build_enforcement_results_directive() { echo ""; }
export -f build_enforcement_results_directive
neutralize_qa_vocab_string() { cat; }
export -f neutralize_qa_vocab_string

# ═══════════════════════════════════════════════════════════════
# 1. Cold start — generic target, reproduce role
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0

result=$(build_cold_start_prompt 1)
assert_match "COLD START.*Agent 1.*role=reproduce" "$result" "cold start: header with agent+role"
assert_match "bin/state resume" "$result" "cold start: starts from structured resume"
assert_match "bin/state add-hyp" "$result" "cold start: writes structured hypotheses"
assert_match "session-rules.md" "$result" "cold start: references session rules"
assert_match "HIGH-VALUE TARGETS" "$result" "cold start: includes targets section"
assert_match "HARD RULES" "$result" "cold start: includes hard rules"
assert_match "AGENT IDENTITY" "$result" "cold start: includes agent identity"
assert_match "OTHER AGENTS" "$result" "cold start: includes other agents section"
assert_match "NO OVERLAP" "$result" "cold start: includes overlap warning"

# ═══════════════════════════════════════════════════════════════
# 2. Cold start — generic target, analysis role
# ═══════════════════════════════════════════════════════════════

result=$(build_cold_start_prompt 2)
assert_match "COLD START.*Agent 2.*role=analysis" "$result" "cold start analysis: header"
assert_match "ANALYSIS AGENT" "$result" "cold start analysis: role guidance"
assert_match "validation requirement" "$result" "cold start analysis: validation requirement"

# ═══════════════════════════════════════════════════════════════
# 3. Cold start — browser target, browser mode
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1
result=$(build_cold_start_prompt 1)
assert_match "COLD START.*Agent 1" "$result" "cold start browser: header"
assert_match "mode=browser" "$result" "cold start browser: mode field"
assert_match "Mercurial" "$result" "cold start browser: mentions Mercurial"
IS_BROWSER_TARGET=0

# ═══════════════════════════════════════════════════════════════
# 4. Cold start — non-S1 assigned strategy
# ═══════════════════════════════════════════════════════════════

echo "S4" > "$(agent_strategy_path 1)"
result=$(build_cold_start_prompt 1)
assert_match "ASSIGNED STRATEGY.*S4" "$result" "cold start: non-default strategy shown"
assert_match "Do NOT default to Strategy S1" "$result" "cold start: warns against S1 fallback"
rm -f "$(agent_strategy_path 1)"

# ═══════════════════════════════════════════════════════════════
# 5. Cold start — Sanitizer build available (generic target)
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0
ASAN_BUILD_AVAILABLE=1
ASAN_BUILD_BINARY="$ASAN_BUILD_DIR/bin/testproject"
result=$(build_cold_start_prompt 1)
assert_match "SANITIZER BUILDS.*ALREADY AVAILABLE" "$result" "cold start generic: Sanitizer build shown"
ASAN_BUILD_AVAILABLE=0
ASAN_BUILD_BINARY=""

# ═══════════════════════════════════════════════════════════════
# 5b. Cold start — TARGET CONFIG excerpt replaces target.toml peeks
# ═══════════════════════════════════════════════════════════════
# Transcripts showed agents spending one LLM round-trip per session (or
# more) on `bin/peek output/<slug>/target.toml` to recover the threat
# model and sanitizer matrix the orchestrator already parsed. The prompt
# must carry both facts and steer agents away from re-reading the file.

IS_BROWSER_TARGET=0
TARGET_ATTACKER_CONTROLS_CSV="bytes,api-args"
TARGET_SANITIZERS_ENABLED_CSV="asan,ubsan"
result=$(build_cold_start_prompt 1)
assert_match "TARGET CONFIG" "$result" "cold start generic: target-config excerpt present"
assert_match "attacker_controls.*bytes,api-args" "$result" "target-config: threat model inlined"
assert_match "enabled.*asan,ubsan" "$result" "target-config: sanitizer matrix inlined"
assert_match "do not re-read it" "$result" "target-config: steers agents off re-peeking target.toml"
IS_BROWSER_TARGET=1
result=$(build_target_config_directive)
assert_eq "" "$result" "browser target: no target-config excerpt"
IS_BROWSER_TARGET=0
TARGET_ATTACKER_CONTROLS_CSV=""
TARGET_SANITIZERS_ENABLED_CSV=""

# ═══════════════════════════════════════════════════════════════
# 6. Cold start — Sanitizer build NOT shown for browser target
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1
ASAN_BUILD_AVAILABLE=1
ASAN_BUILD_BINARY="$ASAN_BUILD_DIR/bin/firefox"
result=$(build_cold_start_prompt 1)
assert_not_match "SANITIZER BUILDS" "$result" "cold start browser: no Sanitizer build section"
IS_BROWSER_TARGET=0
ASAN_BUILD_AVAILABLE=0
ASAN_BUILD_BINARY=""

# ═══════════════════════════════════════════════════════════════
# 7. Cold start — safety framing included
# ═══════════════════════════════════════════════════════════════

result=$(build_cold_start_prompt 1)
assert_match "test-framing" "$result" "cold start: safety framing present"

# ═══════════════════════════════════════════════════════════════
# 8. Cold start — agent guide section
# ═══════════════════════════════════════════════════════════════

assert_match "AGENT GUIDE" "$result" "cold start: agent guide section present"
assert_match "test-guide-content" "$result" "cold start: guide content included"

# ═══════════════════════════════════════════════════════════════
# 9. Deep investigation — basic structure
# ═══════════════════════════════════════════════════════════════

sf1=$(state_file_path 1)
cat > "$sf1" <<'EOF'
## Primary Subsystem: src/lib
| 1 | H1 | src/lib/Foo.cpp:Bar:42 | shape | guard | bounds | S1 | PENDING |
EOF

IS_BROWSER_TARGET=0
result=$(build_deep_investigation_prompt 1)
assert_match "DEEP INVESTIGATION.*Agent A.*role=reproduce" "$result" "deep: header with agent ID + role"
assert_match "FIRST ACTION.*Structured Resume" "$result" "deep: first action is structured resume"
assert_match "bin/state resume --agent 1" "$result" "deep: includes resume command"
assert_match "Read .*AUDIT_STATE-1.md.*only if it exists" "$result" "deep: legacy markdown is optional"
assert_match "PENDING.*Continue immediately" "$result" "deep: pending → continue guidance"
assert_match "MISSION" "$result" "deep: has MISSION section"
assert_match "MANDATORY WRITE-RUN-EVALUATE LOOP" "$result" "deep: has write-run-evaluate loop"
assert_match "HARD RULES" "$result" "deep: has hard rules"

# ═══════════════════════════════════════════════════════════════
# 10. Deep investigation — analysis role
# ═══════════════════════════════════════════════════════════════

cat > "$(state_file_path 2)" <<'EOF'
## Primary Subsystem: src/lib
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF

result=$(build_deep_investigation_prompt 2)
assert_match "DEEP INVESTIGATION.*Agent B.*role=analysis" "$result" "deep analysis: header"
assert_match "ROLE: ANALYSIS" "$result" "deep analysis: role block"
assert_match "VALIDATION REQUIRED" "$result" "deep analysis: validation requirement"

# ═══════════════════════════════════════════════════════════════
# 11. Deep investigation — browser target shows mode lock
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1
result=$(build_deep_investigation_prompt 1)
assert_match "MODE LOCK.*browser" "$result" "deep browser: mode lock shown"
assert_match "BROWSER MODE" "$result" "deep browser: browser targets shown"
IS_BROWSER_TARGET=0

# ═══════════════════════════════════════════════════════════════
# 12. Deep investigation — agent ID mapping
# ═══════════════════════════════════════════════════════════════

for n in 1 2 3 4 5 6 7 8; do
  cat > "$(state_file_path "$n")" <<EOF
## Primary Subsystem: src/lib
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF
done

result=$(build_deep_investigation_prompt 1)
assert_match "Agent A" "$result" "agent ID: 1 → A"
result=$(build_deep_investigation_prompt 2)
assert_match "Agent B" "$result" "agent ID: 2 → B"
result=$(build_deep_investigation_prompt 3)
assert_match "Agent C" "$result" "agent ID: 3 → C"

# With explicit agent_id override
result=$(build_deep_investigation_prompt X 1)
assert_match "Agent X" "$result" "agent ID: explicit override to X"

# ═══════════════════════════════════════════════════════════════
# 13. Deep investigation — with session directive injected
# ═══════════════════════════════════════════════════════════════

get_agent_subsystem() { echo "third_party/rust"; }
export -f get_agent_subsystem

IS_BROWSER_TARGET=1
cat > "$sf1" <<'EOF'
## Primary Subsystem: third_party/rust
| 1 | H1 | third_party/rust/foo.rs | shape | guard | bounds | S1 | PENDING |
EOF

result=$(build_deep_investigation_prompt 1)
assert_match "ROTATE.*blocklisted" "$result" "deep: session directive injected into prompt"
IS_BROWSER_TARGET=0

get_agent_subsystem() { echo "unknown"; }
export -f get_agent_subsystem

# ═══════════════════════════════════════════════════════════════
# 14. Deep investigation — enforcement results injected
# ═══════════════════════════════════════════════════════════════

cat > "$sf1" <<'EOF'
## Primary Subsystem: src/lib
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF

build_enforcement_results_directive() {
  local agent_num="$1"
  if [ "$agent_num" -eq 1 ]; then
    echo "## ENFORCEMENT RESULTS — INVESTIGATE CRASHES FIRST"
    echo "**1 crashed**"
  fi
}
export -f build_enforcement_results_directive

result=$(build_deep_investigation_prompt 1)
assert_match "ENFORCEMENT RESULTS" "$result" "deep: enforcement results injected"
assert_match "1 crashed" "$result" "deep: enforcement crash count shown"

build_enforcement_results_directive() { echo ""; }
export -f build_enforcement_results_directive

# ═══════════════════════════════════════════════════════════════
# 15. Deep investigation — assigned strategy in role block
# ═══════════════════════════════════════════════════════════════

echo "S5" > "$(agent_strategy_path 1)"
cat > "$sf1" <<'EOF'
## Primary Subsystem: src/lib
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF

result=$(build_deep_investigation_prompt 1)
assert_match "ASSIGNED STRATEGY: S5" "$result" "deep: assigned strategy in role block"
assert_match "S5-reentrancy.md" "$result" "deep: strategy file reference"
rm -f "$(agent_strategy_path 1)"

# ═══════════════════════════════════════════════════════════════
# 16. build_agent_state_instructions — generic vs browser
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0
result=$(build_agent_state_instructions 1)
assert_match "AGENT IDENTITY.*Agent 1.*role=reproduce" "$result" "state instructions generic: identity"
assert_not_match "mode=" "$result" "state instructions generic: mode omitted (generic targets)"
assert_not_match "Mercurial" "$result" "state instructions generic: no Mercurial"

IS_BROWSER_TARGET=1
result=$(build_agent_state_instructions 1)
assert_match "mode=browser" "$result" "state instructions browser: mode in identity"
assert_match "Mercurial" "$result" "state instructions browser: Mercurial mentioned"
IS_BROWSER_TARGET=0

# ═══════════════════════════════════════════════════════════════
# 17. Deep investigation — JS testcase sentinel rule present
# ═══════════════════════════════════════════════════════════════

cat > "$sf1" <<'EOF'
## Primary Subsystem: src/lib
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF

result=$(build_deep_investigation_prompt 1)
assert_match "TESTCASE_EXECUTED" "$result" "deep: JS sentinel rule present"

# ═══════════════════════════════════════════════════════════════
# 17a. Deep investigation — missing state falls back to cold start
# ═══════════════════════════════════════════════════════════════

rm -f "$(state_file_path 3)"
result=$(build_deep_investigation_prompt 3)
assert_match "COLD START.*Agent 3" "$result" "deep: missing state cold-starts this agent"

# ═══════════════════════════════════════════════════════════════
# 17b. Deep investigation — session seed section
# ═══════════════════════════════════════════════════════════════

# Without a seed file → section is silent
result=$(build_deep_investigation_prompt 1)
assert_not_match "PRIOR SESSION SEED" "$result" "deep: no seed section when seed file missing"

# Empty seed file → still silent (don't inject blank section)
seed_path="$RESULTS_DIR/.session_seed_1.md"
: > "$seed_path"
result=$(build_deep_investigation_prompt 1)
assert_not_match "PRIOR SESSION SEED" "$result" "deep: no seed section when seed file empty"

# Populated seed file → section appears, content embedded
cat > "$seed_path" <<'EOF'
# Already Read this session — do NOT re-Read these ranges
  lib/foo.sh: 1-200
EOF
result=$(build_deep_investigation_prompt 1)
assert_match "PRIOR SESSION SEED" "$result" "deep: seed section header present"
assert_match "lib/foo.sh: 1-200" "$result" "deep: seed body embedded"
assert_match "offset.*limit" "$result" "deep: seed instructs use of offset/limit for new ranges"
rm -f "$seed_path"

# build_session_seed_section — direct unit test
result=$(build_session_seed_section "")
assert_eq "" "$result" "seed section: empty agent_num → empty output"

result=$(build_session_seed_section 99)  # nonexistent agent
assert_eq "" "$result" "seed section: missing seed file → empty output"

# Terminal-only state should not get the full deep prompt or prior-session seed.
# It gets a compact fresh prompt that tells the agent to use structured state
# only: assigned card, last 3 runs, last terminal reason, and guard notes.
cat > "$sf1" <<'EOF'
## Primary Subsystem: src/lib
| 1 | H1 | src/lib/Foo.cpp:Bar:42 | shape | guard | bounds | S1 | DISCARDED |
EOF
cat > "$seed_path" <<'EOF'
huge stale seed body
EOF
result=$(build_deep_investigation_prompt 1)
assert_match "COMPACT FRESH START" "$result" "deep: terminal-only state uses compact fresh prompt"
assert_match "assigned card, recent runs \\(last 3\\), last terminal reason, and guard notes" "$result" \
  "deep: compact prompt names structured-only resume fields"
assert_not_match "PRIOR SESSION SEED|MANDATORY WRITE-RUN-EVALUATE LOOP|SESSION DIRECTIVE" "$result" \
  "deep: compact prompt omits cached seed and full deep-investigation blocks"
rm -f "$seed_path"

# ═══════════════════════════════════════════════════════════════
# 18. Cold start — coverage-suggested subsystem shown
# ═══════════════════════════════════════════════════════════════

assign_subsystem_from_coverage() { echo "js/src/wasm"; }
export -f assign_subsystem_from_coverage

result=$(build_cold_start_prompt 1)
assert_match "Suggested.*lowest coverage.*js/src/wasm" "$result" "cold start: coverage suggestion shown"

assign_subsystem_from_coverage() { true; }
export -f assign_subsystem_from_coverage

# ═══════════════════════════════════════════════════════════════
# 19. cache_iteration_data — populates cache files
# ═══════════════════════════════════════════════════════════════

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: src/lib
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF
cat > "$(state_file_path 2)" <<'EOF'
## Primary Subsystem: src/net
| 1 | H1 | g.cpp | shape | guard | bounds | S2 | INVESTIGATING |
EOF

cache_iteration_data
assert_file_exists "$ITERATION_CACHE_DIR/blocklist.txt" "cache: blocklist.txt created"
assert_file_exists "$ITERATION_CACHE_DIR/agent_1_summary.txt" "cache: agent 1 summary created"
assert_file_exists "$ITERATION_CACHE_DIR/agent_2_summary.txt" "cache: agent 2 summary created"
assert_file_exists "$ITERATION_CACHE_DIR/agent_1_subsystem.txt" "cache: agent 1 subsystem created"

# ═══════════════════════════════════════════════════════════════
# 20. cached_blocklist_description — uses cache when available
# ═══════════════════════════════════════════════════════════════

result=$(cached_blocklist_description)
assert_match "third_party/rust" "$result" "cached blocklist: includes default entry"

teardown_test_env
summary
