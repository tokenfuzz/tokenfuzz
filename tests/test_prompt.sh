#!/usr/bin/env bash
# Unit tests for lib/prompt.sh — session directive priority gates and prompt builders
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/triage.sh"
source "$SCRIPT_ROOT/lib/quality.sh"
source "$SCRIPT_ROOT/lib/prompt.sh"

# ═══════════════════════════════════════════════════════════════
# 1. P1: Blocklist violation
# ═══════════════════════════════════════════════════════════════

# Override get_agent_subsystem to return a blocklisted subsystem
get_agent_subsystem() { echo "third_party/rust"; }
export -f get_agent_subsystem

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: third_party/rust
| 1 | H1 | third_party/rust/Foo.cpp | shape | guard | bounds | A | PENDING |
EOF

result=$(build_session_directive 1)
assert_match "ROTATE.*blocklisted" "$result" "P1: blocklist violation triggers rotation"
assert_match "third_party/rust" "$result" "P1: blocklisted subsystem named"

# ═══════════════════════════════════════════════════════════════
# 2. P2: Guard-chain saturation
# ═══════════════════════════════════════════════════════════════

get_agent_subsystem() { echo "js/src/irregexp"; }
export -f get_agent_subsystem

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: js/src/irregexp
| 1 | H1 | js/src/irregexp/Foo.cpp | shape | guard | bounds | A | DISCARDED |
EOF

# Write enough guard chain entries to trigger saturation
gpath=$(guard_chain_path "js/src/irregexp")
for i in $(seq 1 "$GUARD_CHAIN_ROTATION_THRESHOLD"); do
  echo "Error: regexp too big" >> "$gpath"
done

result=$(build_session_directive 1)
assert_match "GUARD SATURATION" "$result" "P2: guard saturation detected"
assert_match "regexp too big" "$result" "P2: guard string shown"

# Clean up for next test
rm -f "$gpath"

# ═══════════════════════════════════════════════════════════════
# 3. P3: Effort-gated rotation (normal path)
# ═══════════════════════════════════════════════════════════════

get_agent_subsystem() { echo "dom/canvas"; }
export -f get_agent_subsystem

# State with 0 PENDING, enough DISCARDED + ASan runs
{
  echo "## Primary Subsystem: dom/canvas"
  for i in $(seq 1 "$MIN_DISCARDS_BEFORE_ROTATE"); do
    echo "| $i | H$i | dom/canvas/F$i.cpp | shape | guard | bounds | A | DISCARDED |"
  done
} > "$(state_file_path 1)"

# Create enough verified ASan runs
d="$(scratch_dir_path 1)"
rm -rf "$d"; mkdir -p "$d"
for i in $(seq 1 "$MIN_ASAN_RUNS_BEFORE_ROTATE"); do
  cat > "$d/tc_H${i}.asan.txt" <<EOF
ASAN_RUN_HEADER: browser tc_H${i}.html
CRASH_RATE: 0/5
EOF
done

result=$(build_session_directive 1)
assert_match "ROTATE.*effort gate passed" "$result" "P3: effort-gated rotation"

# ═══════════════════════════════════════════════════════════════
# 4. P3: ENV-BLOCKED carve-out
# ═══════════════════════════════════════════════════════════════

# State with 0 PENDING, 2+ ENV-BLOCKED but NOT enough discards/ASan
{
  echo "## Primary Subsystem: dom/canvas"
  echo "| 1 | H1 | dom/canvas/A.cpp | shape | guard | bounds | A | ENV-BLOCKED |"
  echo "| 2 | H2 | dom/canvas/B.cpp | shape | guard | bounds | A | ENV-BLOCKED |"
} > "$(state_file_path 1)"
rm -rf "$d"; mkdir -p "$d"

result=$(build_session_directive 1)
assert_match "ROTATE.*env-blocked" "$result" "P3: ENV-BLOCKED carve-out rotation"

# ═══════════════════════════════════════════════════════════════
# 5. P4: Reverse turn budget
# ═══════════════════════════════════════════════════════════════

get_agent_subsystem() { echo "dom/canvas"; }
export -f get_agent_subsystem

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | A | PENDING |
EOF
rm -rf "$(scratch_dir_path 1)"; mkdir -p "$(scratch_dir_path 1)"

# Simulate prior session with many tool calls but no results
echo "$PER_HYPOTHESIS_TURN_LIMIT" > "$LOGDIR/.prev_tools_1"
echo "0" > "$LOGDIR/.prev_results_1"

result=$(build_session_directive 1)
assert_match "CHANGE APPROACH" "$result" "P4: reverse turn budget"
assert_match "$PER_HYPOTHESIS_TURN_LIMIT tool calls" "$result" "P4: shows tool count"

# Clean up
rm -f "$LOGDIR/.prev_tools_1" "$LOGDIR/.prev_results_1"

# ═══════════════════════════════════════════════════════════════
# 6. P5: Tenure cap
# ═══════════════════════════════════════════════════════════════

get_agent_subsystem() { echo "dom/canvas"; }
export -f get_agent_subsystem

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | A | PENDING |
EOF
rm -rf "$(scratch_dir_path 1)"; mkdir -p "$(scratch_dir_path 1)"

# Override tenure to return > cap
get_agent_tenure_secs() { echo "$((SUBSYSTEM_TENURE_CAP_SECS + 3600))"; }
export -f get_agent_tenure_secs

result=$(build_session_directive 1)
assert_match "TENURE CAP" "$result" "P5: tenure cap triggers"

# Reset
get_agent_tenure_secs() { echo 0; }
export -f get_agent_tenure_secs

# ═══════════════════════════════════════════════════════════════
# 7. P5b: Strategy rotation
# ═══════════════════════════════════════════════════════════════

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | A | PENDING |
EOF

# Write strategy tracking file with a different strategy than current
echo "S2" > "$(agent_strategy_path 1)"
get_agent_strategy() { echo "S1"; }
export -f get_agent_strategy

result=$(build_session_directive 1)
assert_match "SWITCH STRATEGY.*S1.*S2" "$result" "P5b: strategy rotation directive"
assert_match "S2-assert-negation.md" "$result" "P5b: references strategy file"
assert_match "Strategy brief \\(S2\\)" "$result" "P5b: inlines strategy brief"
assert_not_match "Read .*S2-assert-negation\\.md" "$result" "P5b: no mandatory strategy file read"

# Reset
rm -f "$(agent_strategy_path 1)"
get_agent_strategy() { echo "S1"; }
export -f get_agent_strategy

# ═══════════════════════════════════════════════════════════════
# 8. P6: Crash improvement
# ═══════════════════════════════════════════════════════════════

get_agent_subsystem() { echo "dom/canvas"; }
export -f get_agent_subsystem

{
  echo "## Primary Subsystem: dom/canvas"
  echo "| 1 | H1 | dom/canvas/A.cpp | shape | guard | bounds | A | DISCARDED |"
  echo "| 2 | H2 | dom/canvas/B.cpp | shape | guard | bounds | A | DISCARDED |"
  echo "| 3 | H3 | dom/canvas/C.cpp | shape | guard | bounds | A | DISCARDED |"
  echo "| 4 | H4 | dom/canvas/D.cpp | shape | guard | bounds | A | PENDING |"
} > "$(state_file_path 1)"
rm -rf "$(scratch_dir_path 1)"; mkdir -p "$(scratch_dir_path 1)"
# 0 ASan runs, 3 discards → triggers P6

result=$(build_session_directive 1)
assert_match "REPRODUCE BEFORE DISCARDING" "$result" "P6: crash improvement"

# ═══════════════════════════════════════════════════════════════
# 9. P7: Quality feedback (stats + stay deep)
# ═══════════════════════════════════════════════════════════════

{
  echo "## Primary Subsystem: dom/canvas"
  echo "| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | A | PENDING |"
} > "$(state_file_path 1)"
rm -rf "$(scratch_dir_path 1)"; mkdir -p "$(scratch_dir_path 1)"

result=$(build_session_directive 1)
assert_match "SESSION STATUS" "$result" "P7: session status shown"

# ═══════════════════════════════════════════════════════════════
# 10. build_strategy_assignment_line
# ═══════════════════════════════════════════════════════════════

# Default (no assigned strategy)
rm -f "$(agent_strategy_path 1)"
result=$(build_strategy_assignment_line 1)
assert_match "Strategy priority.*S1 > S2 > S3" "$result" "default strategy priority shown"
assert_match "S5 > S6 > S7 > S8$" "$result" "priority string ends at S8"
assert_match "S8" "$result" "priority string includes S8"

# With assigned strategy
echo "S4" > "$(agent_strategy_path 1)"
result=$(build_strategy_assignment_line 1)
assert_match "Assigned strategy: S4" "$result" "assigned strategy S4 shown"
assert_match "S4-differential.md" "$result" "strategy reference file shown"
assert_match "S5 > S6 > S7 > S8$" "$result" "assigned: fallback ends at S8"

# Strategy S6 (cross-project variant mining; renamed from cross-browser to
# reflect generalized peer-project taxonomy)
echo "S6" > "$(agent_strategy_path 1)"
result=$(build_strategy_assignment_line 1)
assert_match "Assigned strategy: S6" "$result" "assigned strategy S6 shown"
assert_match "S6-cross-project.md" "$result" "S6 maps to cross-project file"

# With renumbered strategy S7 (was S8 fuzz)
echo "S7" > "$(agent_strategy_path 1)"
result=$(build_strategy_assignment_line 1)
assert_match "Assigned strategy: S7" "$result" "assigned strategy S7 shown"
assert_match "S7-fuzz-improvement.md" "$result" "S7 maps to fuzz file"
rm -f "$(agent_strategy_path 1)"

# ═══════════════════════════════════════════════════════════════
# 11. build_cross_agent_summary
# ═══════════════════════════════════════════════════════════════

# Set up agent 2 state
cat > "$(state_file_path 2)" <<'EOF'
## Primary Subsystem: js/src/jit
| 1 | H1 | js/src/jit/WarpBuilder.cpp | shape | guard | bounds | A | PENDING |
| 2 | H2 | js/src/jit/CacheIR.cpp | shape | guard | bounds | A | CRASH-001 |
EOF
get_agent_subsystem() {
  case "$1" in 1) echo "dom/canvas";; 2) echo "js/src/jit";; *) echo "unknown";; esac
}
export -f get_agent_subsystem

result=$(build_cross_agent_summary 1)
assert_match "Agent 2.*js/src/jit" "$result" "cross-agent shows agent 2 subsystem"
assert_match "1 PENDING" "$result" "cross-agent shows pending count"
assert_match "1 findings" "$result" "cross-agent shows findings count"

# ═══════════════════════════════════════════════════════════════
# 12. build_agent_state_instructions
# ═══════════════════════════════════════════════════════════════

result=$(build_agent_state_instructions 1)
assert_match "AGENT IDENTITY.*Agent 1" "$result" "agent identity block"
assert_match "role=reproduce" "$result" "role shown"
assert_match "Structured resume:" "$result" "structured resume command shown"
assert_match "Legacy state file:" "$result" "legacy state file path shown"
assert_match "Scratch dir:" "$result" "scratch dir shown"
assert_match "OTHER AGENTS" "$result" "other agents section"

# ═══════════════════════════════════════════════════════════════
# 13. build_common_suffix
# ═══════════════════════════════════════════════════════════════

result=$(_build_common_suffix_inline)
assert_match "HARD RULES" "$result" "hard rules section present"
assert_match "BLOCKLISTED" "$result" "blocklist mentioned"
assert_match "SEARCH DISCIPLINE" "$result" "search discipline present"
assert_match "bin/probe" "$result" "probe run rule"

# ═══════════════════════════════════════════════════════════════
# 14. build_handoff_directive
# ═══════════════════════════════════════════════════════════════

# Agent 1 is reproduce role, should get handoff
cat > "$(handoff_file_path)" <<'EOF'
| H5 | js/src/jit/WarpBuilder.cpp:Build:123 | nested array | MOZ_ASSERT | bounds | AA | Agent 2 |
EOF

result=$(build_handoff_directive 1)
assert_match "HANDOFF FROM ANALYSIS" "$result" "handoff directive present"
assert_match "WarpBuilder" "$result" "handoff hypothesis shown"

# Agent 2 is analysis role, should NOT get handoff
result=$(build_handoff_directive 2)
assert_eq "" "$result" "analysis agent gets no handoff"

# ═══════════════════════════════════════════════════════════════
# 15. build_subsystem_targets — browser target browser mode
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1
export IS_BROWSER_TARGET

result=$(build_subsystem_targets "browser")
assert_match "HIGH-VALUE TARGETS.*BROWSER" "$result" "browser targets heading"
assert_match "BLOCKLISTED" "$result" "blocklist in targets"

result=$(build_subsystem_targets "shell")
assert_match "HIGH-VALUE TARGETS.*SHELL" "$result" "shell targets heading"

IS_BROWSER_TARGET=0
export IS_BROWSER_TARGET

# ═══════════════════════════════════════════════════════════════
# 16. build_cold_start_prompt
# ═══════════════════════════════════════════════════════════════

# Test with browser target to verify mode is shown
IS_BROWSER_TARGET=1
export IS_BROWSER_TARGET
BROWSER_AGENTS=1

# Remove state file to trigger cold start
rm -f "$(state_file_path 1)"
result=$(build_cold_start_prompt 1 2>/dev/null)
assert_match "COLD START.*Agent 1.*role=reproduce" "$result" "cold start header"
assert_match "AGENT IDENTITY" "$result" "agent identity in cold start"
assert_match "HARD RULES" "$result" "hard rules in cold start"
assert_not_match "MANDATORY WRITE-RUN-EVALUATE LOOP" "$result" "cold start: write-run-evaluate NOT in cold start"
assert_match "AGENT GUIDE" "$result" "cold start: guide section injected"
assert_match "test-guide-content" "$result" "cold start: guide content present"

# ═══════════════════════════════════════════════════════════════
# 17. build_deep_investigation_prompt
# ═══════════════════════════════════════════════════════════════

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | A | PENDING |
EOF

result=$(build_deep_investigation_prompt 1 2>/dev/null)
assert_match "DEEP INVESTIGATION.*Agent A.*role=reproduce" "$result" "deep investigation header"
assert_match "FIRST ACTION" "$result" "first action section"
assert_match "MISSION" "$result" "mission section"
assert_match "AGENT IDENTITY" "$result" "agent identity in deep"
assert_match "HARD RULES" "$result" "hard rules in deep"
assert_match "MANDATORY WRITE-RUN-EVALUATE LOOP" "$result" "deep: write-run-evaluate section present"
assert_match "NO_EXEC" "$result" "deep: NO_EXEC instruction present"
assert_match "TESTCASE_EXECUTED" "$result" "deep: JS sentinel mentioned"
assert_match "NEVER write a second testcase" "$result" "deep: strict loop rule present"
assert_match "AGENT GUIDE" "$result" "deep: guide section injected"
assert_match 'Follow `AGENTS.md`' "$result" "deep: guide pointer present"
assert_not_match "test-guide-content" "$result" "deep: guide content not repeated"

# ═══════════════════════════════════════════════════════════════
# 18. build_guide_section — direct tests
# ═══════════════════════════════════════════════════════════════

result=$(build_guide_section cold)
assert_match "AGENT GUIDE" "$result" "build_guide_section: header present"
assert_match "test-guide-content" "$result" "build_guide_section cold: content present"

result=$(build_guide_section deep)
assert_match "AGENT GUIDE" "$result" "build_guide_section deep: header present"
assert_match 'Follow `AGENTS.md`' "$result" "build_guide_section deep: pointer present"
assert_not_match "test-guide-content" "$result" "build_guide_section deep: content not repeated"

# Empty guide → empty output
_saved_guide="$AGENT_GUIDE_CACHED"
AGENT_GUIDE_CACHED=""
result=$(build_guide_section)
assert_eq "" "$result" "build_guide_section: empty when AGENT_GUIDE_CACHED unset"
AGENT_GUIDE_CACHED="$_saved_guide"

# ═══════════════════════════════════════════════════════════════
# 19. Priority ordering — P1 preempts P7
# ═══════════════════════════════════════════════════════════════

get_agent_subsystem() { echo "third_party/rust"; }
export -f get_agent_subsystem

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: third_party/rust
| 1 | H1 | third_party/rust/Foo.cpp | shape | guard | bounds | A | PENDING |
EOF

result=$(build_session_directive 1)
# Should be ROTATE (blocklist), NOT session status
assert_match "ROTATE.*blocklisted" "$result" "P1 preempts lower priorities"
assert_not_match "SESSION STATUS" "$result" "P7 not reached when P1 fires"

# ═══════════════════════════════════════════════════════════════
# 20. Generic target: agent identity omits mode
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0
export IS_BROWSER_TARGET
BROWSER_AGENTS=0
SHELL_AGENTS=2
NUM_AGENTS=2

result=$(build_agent_state_instructions 1)
assert_match "AGENT IDENTITY.*Agent 1" "$result" "generic target identity: agent number"
assert_match "role=reproduce" "$result" "generic target identity: role shown"
assert_not_match "mode=" "$result" "generic target identity: no mode= field"
assert_match "Source tree:.*${TARGET_ROOT}" "$result" "generic target identity: source tree shown"
assert_not_match "Mercurial" "$result" "generic target identity: no Mercurial reference"

# ═══════════════════════════════════════════════════════════════
# 21. Generic target: cold start — no mode lock, generic instructions
# ═══════════════════════════════════════════════════════════════

rm -f "$(state_file_path 1)"
get_agent_subsystem() { echo "unknown"; }
export -f get_agent_subsystem

result=$(build_cold_start_prompt 1 2>/dev/null)
assert_match "COLD START.*Agent 1.*role=reproduce" "$result" "generic cold start: header"
assert_match "bin/state resume --agent 1 --mode generic" "$result" "generic cold start: structured resume uses generic mode"
assert_not_match "Mode lock:.*browser" "$result" "generic cold start: no browser mode lock"
assert_not_match "Mode lock:.*shell" "$result" "generic cold start: no shell mode lock"
assert_match "different subsystem" "$result" "generic cold start: overlap avoidance instruction"
assert_match "AGENT IDENTITY" "$result" "generic cold start: agent identity block"
assert_match "HARD RULES" "$result" "generic cold start: hard rules"
assert_match "HIGH-VALUE TARGETS" "$result" "generic cold start: targets section"
assert_match "Candidate directories" "$result" "generic cold start: candidate dirs listed"

# ═══════════════════════════════════════════════════════════════
# 22. Generic target: deep investigation — no MODE LOCK
# ═══════════════════════════════════════════════════════════════

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: src/crypto
| 1 | H1 | src/crypto/Foo.c | shape | guard | bounds | A | PENDING |
EOF

result=$(build_deep_investigation_prompt 1 2>/dev/null)
assert_match "DEEP INVESTIGATION.*Agent A.*role=reproduce" "$result" "generic deep: header"
assert_not_match "MODE LOCK" "$result" "generic deep: no MODE LOCK"
assert_not_match "run-asan browser" "$result" "generic deep: no run-asan browser"
assert_not_match "run-asan shell" "$result" "generic deep: no run-asan shell"
assert_not_match "Wrong-mode subsystem" "$result" "generic deep: no wrong-mode warning"
assert_match "FIRST ACTION" "$result" "generic deep: first action section"
assert_match "MISSION" "$result" "generic deep: mission section"
assert_match "MANDATORY WRITE-RUN-EVALUATE LOOP" "$result" "generic deep: write-run-evaluate"
assert_match "bin/probe" "$result" "generic deep: write-run loop uses probe"
assert_match "records runs automatically" "$result" "generic deep: structured run recording mentioned"
assert_match "HIGH-VALUE TARGETS" "$result" "generic deep: targets section"

# ═══════════════════════════════════════════════════════════════
# 23. Generic target: build_asan_build_directive — not found
# ═══════════════════════════════════════════════════════════════

ASAN_BUILD_AVAILABLE=0
ASAN_BUILD_BINARY=""

result=$(build_asan_build_directive)
assert_match "SANITIZER BUILDS.*NOT FOUND" "$result" "sanitizer directive: not found heading"
assert_match "fsanitize=address" "$result" "sanitizer directive: build flags shown"
assert_match "$ASAN_BUILD_DIR" "$result" "sanitizer directive: build dir path shown"

# ═══════════════════════════════════════════════════════════════
# 24. Generic target: build_asan_build_directive — already available
# ═══════════════════════════════════════════════════════════════

ASAN_BUILD_AVAILABLE=1
ASAN_BUILD_BINARY="$ASAN_BUILD_DIR/bin/myproject"

result=$(build_asan_build_directive)
assert_match "SANITIZER BUILDS.*ALREADY AVAILABLE" "$result" "sanitizer directive: found heading"
assert_match "Do NOT rebuild" "$result" "sanitizer directive: no-rebuild instruction"
assert_match "$ASAN_BUILD_DIR" "$result" "sanitizer directive: build dir in found msg"
assert_match "bin/myproject" "$result" "sanitizer directive: binary path shown"

# Reset
ASAN_BUILD_AVAILABLE=0
ASAN_BUILD_BINARY=""

TARGET_SANITIZERS_ENABLED_CSV="ubsan,msan"
SANITIZER_BUILD_SUMMARY="- ubsan: \`$TARGET_ROOT/build-ubsan/demo\` (configured binary)"
SANITIZER_BUILD_MISSING="- msan: set [sanitizer].msan_bin in target.toml"
result=$(build_sanitizer_build_directive)
assert_match "SANITIZER BUILDS.*PARTIAL" "$result" "sanitizer directive: mixed sanitizer state shown as partial"
assert_match "ubsan,msan" "$result" "sanitizer directive: non-ASan enabled set shown"
assert_match "build-ubsan/demo" "$result" "sanitizer directive: non-ASan detected binary shown"
assert_match "msan_bin" "$result" "sanitizer directive: non-ASan missing reason shown"
SANITIZER_BUILD_SUMMARY=""
SANITIZER_BUILD_MISSING=""
TARGET_SANITIZERS_ENABLED_CSV="asan"

TARGET_SANITIZERS_ENABLED_CSV="ubsan"
SANITIZER_BUILD_MISSING="- ubsan: set [sanitizer].ubsan_bin in target.toml"
result=$(build_sanitizer_build_directive)
assert_match "SANITIZER BUILDS.*NOT FOUND" "$result" "sanitizer directive: non-ASan missing heading"
assert_match "ubsan_bin" "$result" "sanitizer directive: non-ASan missing config key shown"
assert_not_match "fsanitize=address" "$result" "sanitizer directive: non-ASan missing path avoids ASan build recipe"
assert_match "Do not substitute an ASan build" "$result" "sanitizer directive: non-ASan missing path warns against ASan substitution"
SANITIZER_BUILD_MISSING=""
TARGET_SANITIZERS_ENABLED_CSV="asan"

SANITIZER_BUILD_DISABLED=1
result=$(build_sanitizer_build_directive)
assert_match "SANITIZER BUILDS.*DISABLED" "$result" "sanitizer directive: findings-only mode shown as disabled"
assert_match "runner/findings mode" "$result" "sanitizer directive: disabled mode points to runner workflow"
SANITIZER_BUILD_DISABLED=0

# ═══════════════════════════════════════════════════════════════
# 25. build_asan_build_directive — not emitted for browser targets
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1
export IS_BROWSER_TARGET
result=$(build_asan_build_directive)
assert_eq "" "$result" "sanitizer directive: empty for browser target"
IS_BROWSER_TARGET=0
export IS_BROWSER_TARGET

# ═══════════════════════════════════════════════════════════════
# 26. Generic target: cold start injects Sanitizer build directive
# ═══════════════════════════════════════════════════════════════

rm -f "$(state_file_path 1)"
ASAN_BUILD_AVAILABLE=0
result=$(build_cold_start_prompt 1 2>/dev/null)
assert_match "SANITIZER BUILDS.*NOT FOUND" "$result" "generic cold start: asan not-found directive injected"

ASAN_BUILD_AVAILABLE=1
ASAN_BUILD_BINARY="$ASAN_BUILD_DIR/bin/test"
result=$(build_cold_start_prompt 1 2>/dev/null)
assert_match "SANITIZER BUILDS.*ALREADY AVAILABLE" "$result" "generic cold start: asan found directive injected"
assert_match "Do NOT rebuild" "$result" "generic cold start: no-rebuild in cold start"
ASAN_BUILD_AVAILABLE=0
ASAN_BUILD_BINARY=""

# ═══════════════════════════════════════════════════════════════
# 27. Generic target: deep investigation injects Sanitizer build directive
# ═══════════════════════════════════════════════════════════════

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: src/crypto
| 1 | H1 | src/crypto/Foo.c | shape | guard | bounds | A | PENDING |
EOF
ASAN_BUILD_AVAILABLE=1
ASAN_BUILD_BINARY="$ASAN_BUILD_DIR/bin/test"
result=$(build_deep_investigation_prompt 1 2>/dev/null)
assert_match "SANITIZER BUILDS.*ALREADY AVAILABLE" "$result" "generic deep: asan found directive injected"
ASAN_BUILD_AVAILABLE=0
ASAN_BUILD_BINARY=""

# ═══════════════════════════════════════════════════════════════
# 28. Compact fresh prompt preserves assigned strategy
# ═══════════════════════════════════════════════════════════════

rm -f "$(state_file_path 1)"
printf '%s' "S8" > "$(agent_strategy_path 1)"
result=$(build_compact_fresh_prompt 1 2>/dev/null)
assert_match "Assigned strategy: S8" "$result" "compact fresh: assigned strategy retained"
assert_match "S8-property-based.md" "$result" "compact fresh: strategy reference retained"
rm -f "$(agent_strategy_path 1)"

# ═══════════════════════════════════════════════════════════════
# 29. Generic target: subsystem targets — candidate dirs, not browser/shell
# ═══════════════════════════════════════════════════════════════

TARGET_SLUG="openssl"
result=$(build_subsystem_targets "generic")
assert_match "HIGH-VALUE TARGETS FOR openssl" "$result" "generic targets: slug in heading"
assert_match "Candidate directories" "$result" "generic targets: has candidate dirs"
assert_match "src/lib" "$result" "generic targets: lists candidate subdirs"
assert_not_match "BROWSER MODE" "$result" "generic targets: no browser mode heading"
assert_not_match "SHELL MODE" "$result" "generic targets: no shell mode heading"
TARGET_SLUG="testproject"

teardown_test_env
summary
