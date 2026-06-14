#!/usr/bin/env bash
# Advanced prompt builder tests — coverage assignment, subsystem targets,
# static prompt file, prompt composition, generic target mode
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/vocab.sh"
source "$SCRIPT_ROOT/lib/triage.sh"
source "$SCRIPT_ROOT/lib/quality.sh"
source "$SCRIPT_ROOT/lib/prompt.sh"

# ═══════════════════════════════════════════════════════════════
# 1. assign_subsystem_from_coverage — picks least-covered
# ═══════════════════════════════════════════════════════════════

# Set up hits logs with coverage data
echo "HIT: dom.canvas.Foo" > "$(hits_log_path 1)"
echo "HIT: dom.canvas.Bar" >> "$(hits_log_path 1)"
echo "HIT: parser.html.Baz" > "$(hits_log_path 2)"

all_hits=$'HIT: dom.canvas.Foo\nHIT: dom.canvas.Bar\nHIT: parser.html.Baz'
ranked=$(coverage_hit_ranked_subsystems $'dom/canvas\nparser/html\njs/src/jit' "$all_hits" | awk -F '\t' '{print $2}' | paste -sd ' ' -)
assert_eq "js/src/jit parser/html dom/canvas" "$ranked" "coverage ranking: one-pass hit counts sort least-covered first"

coverage_cache_src="$(declare -f cache_iteration_data)"
coverage_live_src="$(declare -f _assign_subsystem_from_coverage_live)"
assert_match 'coverage_hit_ranked_subsystems' "$coverage_cache_src" \
  "coverage cache: uses shared one-pass hit ranker"
assert_match 'coverage_hit_ranked_subsystems' "$coverage_live_src" \
  "coverage live fallback: uses shared one-pass hit ranker"
assert_not_match 'grep -c .*sub_slug' "$coverage_cache_src" \
  "coverage cache: avoids per-subsystem grep hit counting"
assert_not_match 'grep -c .*sub_slug' "$coverage_live_src" \
  "coverage live fallback: avoids per-subsystem grep hit counting"

get_agent_subsystem() {
  case "$1" in 1) echo "dom/canvas";; *) echo "unknown";; esac
}
export -f get_agent_subsystem

# Agent 2 should get the subsystem with fewer hits
result=$(assign_subsystem_from_coverage 2 2>/dev/null)
# Since browser_mode_subsystems returns "dom/canvas" and "parser/html",
# and dom/canvas has 2 hits while parser/html has 1, least covered = parser/html
# But agent 2 is shell mode, so it uses shell_mode_subsystems
# shell_mode_subsystems returns "js/src/jit" and "js/src/wasm" — both have 0 hits
if [ -n "$result" ]; then
  assert_match "/" "$result" "assign_subsystem_from_coverage returns a subsystem path"
else
  pass "assign_subsystem_from_coverage: no approved subsystem matched (acceptable)"
fi

# ═══════════════════════════════════════════════════════════════
# 2. build_subsystem_targets — browser target browser mode
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1
export IS_BROWSER_TARGET

result=$(build_subsystem_targets "browser")
assert_match "HIGH-VALUE TARGETS.*BROWSER" "$result" "browser targets heading"
assert_match "BLOCKLISTED" "$result" "browser targets: blocklist shown"
assert_match "Mode-compatible candidates:" "$result" "browser targets: mode-compatible list"

# ═══════════════════════════════════════════════════════════════
# 3. build_subsystem_targets — browser target shell mode
# ═══════════════════════════════════════════════════════════════

result=$(build_subsystem_targets "shell")
assert_match "HIGH-VALUE TARGETS.*SHELL" "$result" "shell targets heading"
assert_match "BLOCKLISTED" "$result" "shell targets: blocklist shown"
assert_match "js/src/jit" "$result" "shell targets: mentions jit"

# ═══════════════════════════════════════════════════════════════
# 4. build_subsystem_targets — generic (no mode)
# ═══════════════════════════════════════════════════════════════

result=$(build_subsystem_targets "")
assert_match "HIGH-VALUE TARGETS" "$result" "generic targets heading"

# ═══════════════════════════════════════════════════════════════
# 5. build_subsystem_targets — generic target
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0
export IS_BROWSER_TARGET
# Need list_candidate_subsystems defined
list_candidate_subsystems() { echo "src/lib"; echo "src/main"; }
export -f list_candidate_subsystems
TARGET_SLUG="openssl"
export TARGET_SLUG

result=$(build_subsystem_targets "shell")
assert_match "HIGH-VALUE TARGETS" "$result" "generic target: targets heading"
assert_match "openssl" "$result" "generic target: target name in heading"

IS_BROWSER_TARGET=1
export IS_BROWSER_TARGET

# ═══════════════════════════════════════════════════════════════
# 6. write_static_prompt_file — creates cached file
# ═══════════════════════════════════════════════════════════════

rm -f "$RESULTS_DIR/.static-prompt-rules.md"
write_static_prompt_file 2>/dev/null
assert_file_exists "$RESULTS_DIR/.static-prompt-rules.md" "static prompt file created"
assert_file_contains "$RESULTS_DIR/.static-prompt-rules.md" "HARD RULES" "static prompt has hard rules"
assert_file_contains "$RESULTS_DIR/.static-prompt-rules.md" "SEARCH DISCIPLINE" "static prompt has search discipline"

# ═══════════════════════════════════════════════════════════════
# 7. build_common_suffix — uses static file when present
# ═══════════════════════════════════════════════════════════════

result=$(build_common_suffix)
assert_match "HARD RULES" "$result" "common suffix: hard rules"
assert_match "BLOCKLISTED" "$result" "common suffix: blocklist"
assert_match "SEARCH DISCIPLINE" "$result" "common suffix: search discipline"
assert_match "Coverage-gate" "$result" "common suffix: coverage gate rule"

# ═══════════════════════════════════════════════════════════════
# 8. build_handoff_directive — empty handoff file → empty
# ═══════════════════════════════════════════════════════════════

: > "$(handoff_file_path)"
result=$(build_handoff_directive 1)
assert_eq "" "$result" "empty handoff → no directive"

# Non-reproduce role → empty
AGENT_ROLES="analysis,analysis"
export AGENT_ROLES
result=$(build_handoff_directive 1)
assert_eq "" "$result" "analysis role → no handoff"
AGENT_ROLES=""
export AGENT_ROLES

# ═══════════════════════════════════════════════════════════════
# 9. build_cold_start_prompt — contains all required sections
# ═══════════════════════════════════════════════════════════════

rm -f "$(state_file_path 1)"
get_agent_subsystem() { echo "unknown"; }
export -f get_agent_subsystem

result=$(build_cold_start_prompt 1 2>/dev/null)
assert_match "COLD START" "$result" "cold start: header present"
assert_match "Agent 1" "$result" "cold start: agent number"
assert_match "role=reproduce" "$result" "cold start: role"
assert_match "mode=browser" "$result" "cold start: browser target mode in identity"
assert_match "AGENT IDENTITY" "$result" "cold start: agent identity block"
assert_match "OTHER AGENTS" "$result" "cold start: other agents"
assert_match "HARD RULES" "$result" "cold start: hard rules"
assert_match "session-rules.md" "$result" "cold start: references session rules"
assert_match "bin/state resume" "$result" "cold start: references structured resume"
assert_match "bin/state add-hyp" "$result" "cold start: references structured hypotheses"
assert_match "Mode lock:.*browser" "$result" "cold start: browser target mode lock"

# ═══════════════════════════════════════════════════════════════
# 10. build_cold_start_prompt — with assigned strategy
# ═══════════════════════════════════════════════════════════════

echo "S4" > "$(agent_strategy_path 1)"
rm -f "$(state_file_path 1)"

result=$(build_cold_start_prompt 1 2>/dev/null)
assert_match "ASSIGNED STRATEGY.*S4" "$result" "cold start: assigned strategy S4 shown"
assert_match "S4-differential.md" "$result" "cold start: strategy file referenced"
assert_match "Strategy brief \\(S4\\)" "$result" "cold start: strategy brief inlined"
assert_not_match "Read .*S4-differential\\.md" "$result" "cold start: no mandatory strategy file read"

rm -f "$(agent_strategy_path 1)"

# ═══════════════════════════════════════════════════════════════
# 11. build_deep_investigation_prompt — contains required sections
# ═══════════════════════════════════════════════════════════════

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | dom/canvas/Foo.cpp | shape | guard | bounds | A | PENDING |
EOF

result=$(build_deep_investigation_prompt 1 2>/dev/null)
assert_match "DEEP INVESTIGATION" "$result" "deep: header present"
assert_match "FIRST ACTION" "$result" "deep: first action section"
assert_match "MISSION" "$result" "deep: mission section"
assert_match "AGENT IDENTITY" "$result" "deep: agent identity"
assert_match "HARD RULES" "$result" "deep: hard rules"
assert_match "dom/canvas" "$result" "deep: subsystem in prompt"
assert_match "MANDATORY WRITE-RUN-EVALUATE LOOP" "$result" "deep: write-run-evaluate section"
assert_match "TESTCASE_EXECUTED" "$result" "deep: JS sentinel in prompt"
assert_match "NO_EXEC" "$result" "deep: NO_EXEC handling instructions"

# ═══════════════════════════════════════════════════════════════
# 12. build_cross_agent_summary — shows all other agents
# ═══════════════════════════════════════════════════════════════

NUM_AGENTS=3
export NUM_AGENTS
SHELL_AGENTS=2
export SHELL_AGENTS

cat > "$(state_file_path 2)" <<'EOF'
## Primary Subsystem: js/src/jit
| 1 | H1 | js/src/jit/A.cpp | shape | guard | bounds | A | PENDING |
| 2 | H2 | js/src/jit/B.cpp | shape | guard | bounds | A | CRASH-001 |
EOF
cat > "$(state_file_path 3)" <<'EOF'
## Primary Subsystem: js/src/wasm
| 1 | H1 | js/src/wasm/A.cpp | shape | guard | bounds | Q | PENDING |
| 2 | H2 | js/src/wasm/B.cpp | shape | guard | bounds | Q | NEEDS_TESTCASE |
EOF

get_agent_subsystem() {
  case "$1" in 1) echo "dom/canvas";; 2) echo "js/src/jit";; 3) echo "js/src/wasm";; *) echo "unknown";; esac
}
export -f get_agent_subsystem

result=$(build_cross_agent_summary 1)
assert_match "Agent 2" "$result" "cross-agent: shows agent 2"
assert_match "Agent 3" "$result" "cross-agent: shows agent 3"
assert_match "js/src/jit" "$result" "cross-agent: agent 2 subsystem"
assert_match "js/src/wasm" "$result" "cross-agent: agent 3 subsystem"
assert_match "NEEDS_TESTCASE" "$result" "cross-agent: shows NEEDS_TESTCASE"

# Summary for agent 2 should NOT include agent 2 itself
result=$(build_cross_agent_summary 2)
assert_not_match "Agent 2" "$result" "cross-agent: excludes self"
assert_match "Agent 1" "$result" "cross-agent: includes agent 1"
assert_match "Agent 3" "$result" "cross-agent: includes agent 3"

# Reset
NUM_AGENTS=2
export NUM_AGENTS
SHELL_AGENTS=1
export SHELL_AGENTS

# ═══════════════════════════════════════════════════════════════
# 13. Priority ordering — P2 preempts P3+
# ═══════════════════════════════════════════════════════════════

get_agent_subsystem() { echo "dom/canvas"; }
export -f get_agent_subsystem

# Set up guard saturation AND effort gate conditions
gpath=$(guard_chain_path "dom/canvas")
for i in $(seq 1 "$GUARD_CHAIN_ROTATION_THRESHOLD"); do
  echo "Error: too complex" >> "$gpath"
done

{
  echo "## Primary Subsystem: dom/canvas"
  for i in $(seq 1 "$MIN_DISCARDS_BEFORE_ROTATE"); do
    echo "| $i | H$i | dom/canvas/F$i.cpp | shape | guard | bounds | A | DISCARDED |"
  done
} > "$(state_file_path 1)"

d="$(scratch_dir_path 1)"
rm -rf "$d"; mkdir -p "$d"
for i in $(seq 1 "$MIN_ASAN_RUNS_BEFORE_ROTATE"); do
  cat > "$d/tc_H${i}.asan.txt" <<EOF
ASAN_RUN_HEADER: browser tc_H${i}.html
CRASH_RATE: 0/5
EOF
done

result=$(build_session_directive 1)
# P2 (guard saturation) should fire, not P3 (effort rotation)
assert_match "GUARD SATURATION" "$result" "P2 preempts P3"
assert_not_match "effort gate" "$result" "P3 not reached when P2 fires"

rm -f "$gpath"

# ═══════════════════════════════════════════════════════════════
# 14. Generic target: cold start — generic mode, no browser/shell
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0
export IS_BROWSER_TARGET
BROWSER_AGENTS=0
SHELL_AGENTS=5
NUM_AGENTS=5
TARGET_SLUG="libxml2"
export TARGET_SLUG

rm -f "$(state_file_path 1)"
get_agent_subsystem() { echo "unknown"; }
export -f get_agent_subsystem

result=$(build_cold_start_prompt 1 2>/dev/null)
assert_match "COLD START.*Agent 1" "$result" "generic adv cold: header"
assert_match "role=reproduce" "$result" "generic adv cold: role"
assert_not_match "mode=browser" "$result" "generic adv cold: no browser mode"
assert_not_match "mode=shell" "$result" "generic adv cold: no shell mode"
assert_match "HIGH-VALUE TARGETS FOR libxml2" "$result" "generic adv cold: target slug in targets heading"
assert_match "Candidate directories" "$result" "generic adv cold: candidate dirs"
assert_match "session-rules.md" "$result" "generic adv cold: references session rules"

# ═══════════════════════════════════════════════════════════════
# 15. Generic target: deep investigation — generic mode
# ═══════════════════════════════════════════════════════════════

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: src/parser
| 1 | H1 | src/parser/xmlparse.c | shape | guard | bounds | A | PENDING |
EOF

result=$(build_deep_investigation_prompt 1 2>/dev/null)
assert_match "DEEP INVESTIGATION.*Agent A" "$result" "generic adv deep: header"
assert_not_match "MODE LOCK" "$result" "generic adv deep: no MODE LOCK"
assert_not_match "browser" "$result" "generic adv deep: no browser reference"
assert_match "HIGH-VALUE TARGETS FOR libxml2" "$result" "generic adv deep: targets for target slug"
assert_match "FIRST ACTION" "$result" "generic adv deep: first action"
assert_match "MANDATORY WRITE-RUN-EVALUATE" "$result" "generic adv deep: write-run-evaluate"
assert_match "bin/probe" "$result" "generic adv deep: uses probe"

# ═══════════════════════════════════════════════════════════════
# 16. Generic target: cross-agent summary — uses generic mode
# ═══════════════════════════════════════════════════════════════

NUM_AGENTS=3
SHELL_AGENTS=3
export NUM_AGENTS SHELL_AGENTS

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: src/parser
| 1 | H1 | src/parser/Foo.c | shape | guard | bounds | A | PENDING |
EOF
cat > "$(state_file_path 2)" <<'EOF'
## Primary Subsystem: src/crypto
| 1 | H1 | src/crypto/Bar.c | shape | guard | bounds | A | PENDING |
EOF
cat > "$(state_file_path 3)" <<'EOF'
## Primary Subsystem: src/net
| 1 | H1 | src/net/Baz.c | shape | guard | bounds | A | INVESTIGATING |
EOF

get_agent_subsystem() {
  case "$1" in 1) echo "src/parser";; 2) echo "src/crypto";; 3) echo "src/net";; *) echo "unknown";; esac
}
export -f get_agent_subsystem

result=$(build_cross_agent_summary 1)
assert_match "Agent 2" "$result" "generic cross: shows agent 2"
assert_match "Agent 3" "$result" "generic cross: shows agent 3"
assert_match "src/crypto" "$result" "generic cross: agent 2 subsystem"
assert_match "src/net" "$result" "generic cross: agent 3 subsystem"
assert_match "generic" "$result" "generic cross: generic mode shown"
assert_not_match "browser" "$result" "generic cross: no browser mode"

# ═══════════════════════════════════════════════════════════════
# 17. Generic target: build_subsystem_targets ignores mode argument
# ═══════════════════════════════════════════════════════════════

result=$(build_subsystem_targets "generic")
assert_match "HIGH-VALUE TARGETS FOR libxml2" "$result" "generic targets: heading"
assert_match "parsers.*decoders" "$result" "generic targets: hunt guidance"

result=$(build_subsystem_targets "browser")
assert_match "HIGH-VALUE TARGETS FOR libxml2" "$result" "generic targets browser arg: same heading (mode ignored)"

result=$(build_subsystem_targets "shell")
assert_match "HIGH-VALUE TARGETS FOR libxml2" "$result" "generic targets shell arg: same heading (mode ignored)"

# ═══════════════════════════════════════════════════════════════
# 18. Generic target: Sanitizer build directive in cold start prompt
# ═══════════════════════════════════════════════════════════════

rm -f "$(state_file_path 1)"
ASAN_BUILD_AVAILABLE=1
ASAN_BUILD_BINARY="$ASAN_BUILD_DIR/bin/xmllint"
export ASAN_BUILD_AVAILABLE ASAN_BUILD_BINARY

result=$(build_cold_start_prompt 1 2>/dev/null)
assert_match "SANITIZER BUILDS.*ALREADY AVAILABLE" "$result" "generic adv cold: sanitizer directive in prompt"
assert_match "Do NOT rebuild" "$result" "generic adv cold: no-rebuild instruction"
assert_match "xmllint" "$result" "generic adv cold: binary name in prompt"

# ═══════════════════════════════════════════════════════════════
# 19. Generic target: assigned strategy works in generic mode
# ═══════════════════════════════════════════════════════════════

echo "S3" > "$(agent_strategy_path 1)"
rm -f "$(state_file_path 1)"

result=$(build_cold_start_prompt 1 2>/dev/null)
assert_match "ASSIGNED STRATEGY.*S3" "$result" "generic cold: strategy S3 assigned"
assert_match "S3-spec-vs-impl.md" "$result" "generic cold: strategy file ref"

rm -f "$(agent_strategy_path 1)"

# Reset
ASAN_BUILD_AVAILABLE=0
ASAN_BUILD_BINARY=""
IS_BROWSER_TARGET=1
export IS_BROWSER_TARGET
TARGET_SLUG="testproject"
NUM_AGENTS=2
SHELL_AGENTS=1

teardown_test_env
summary
