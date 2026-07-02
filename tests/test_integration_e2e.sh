#!/usr/bin/env bash
# End-to-end integration test — exercises the full pipeline:
# mock target → state file → triage → vocab neutralize → index rebuild
# Verifies that the audit framework's components work together correctly.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/triage.sh"
source "$SCRIPT_ROOT/lib/quality.sh"
source "$SCRIPT_ROOT/lib/vocab.sh"
source "$SCRIPT_ROOT/lib/prompt.sh"

MOCK_TARGET="$SCRIPT_ROOT/tests/fixtures/mock-target"
export TARGET_ROOT="$MOCK_TARGET"
export IS_BROWSER_TARGET=1

# ═══════════════════════════════════════════════════════════════
# 1. Cold start prompt references the target
# ═══════════════════════════════════════════════════════════════

rm -f "$(state_file_path 1)"
prompt=$(build_cold_start_prompt 1 2>/dev/null)
assert_match "COLD START" "$prompt" "e2e: cold start generated"
assert_match "Agent 1" "$prompt" "e2e: agent identity in cold start"

# ═══════════════════════════════════════════════════════════════
# 2. State files with planted crashes → triage classifies correctly
# ═══════════════════════════════════════════════════════════════

# Real security crash: heap-buffer-overflow from PNG decoder
mkdir -p "$RESULTS_DIR/crashes/CRASH-E2E-001-1"
cat > "$RESULTS_DIR/crashes/CRASH-E2E-001-1/asan.txt" <<EOF
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
READ of size 4 at 0x60200000abcd thread T0
#0 0x7fff12345678 in image::nsPNGDecoder::ProcessChunk()
#1 0x7fff12345688 in image::ImageRequest::OnData()
EOF
cat > "$RESULTS_DIR/crashes/CRASH-E2E-001-1/report.md" <<EOF
# Heap buffer overflow in PNG decoder
Triggered by <img> tag with crafted PNG palette index via web content.
Category: bounds
EOF
echo '<html><body><img src="test.png">crafted testcase content</body></html>' > "$RESULTS_DIR/crashes/CRASH-E2E-001-1/testcase.html"

# Junk crash: null-deref → should be auto-discarded
mkdir -p "$RESULTS_DIR/crashes/CRASH-E2E-002-1"
cat > "$RESULTS_DIR/crashes/CRASH-E2E-002-1/asan.txt" <<EOF
==12345==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
Hint: address points to the zero page
SCARINESS: 10 (null-deref)
#0 0x7fff12345678 in gfx::Compositor::Init()
EOF
echo "report" > "$RESULTS_DIR/crashes/CRASH-E2E-002-1/report.md"
echo '<html><body>test testcase content here</body></html>' > "$RESULTS_DIR/crashes/CRASH-E2E-002-1/testcase.html"

# Non-web crash: memory safety but no web reachability → rejected
mkdir -p "$RESULTS_DIR/crashes/CRASH-E2E-003-1"
cat > "$RESULTS_DIR/crashes/CRASH-E2E-003-1/asan.txt" <<EOF
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x60300000dcba
#0 0x7fff12345678 in js::gc::Nursery::Collect()
EOF
cat > "$RESULTS_DIR/crashes/CRASH-E2E-003-1/report.md" <<EOF
# UAF in GC nursery
Internal engine crash during garbage collection.
Not reachable from any known input path.
EOF
echo 'function tickle(){ for (var i=0;i<1000;i++) gc(); } tickle();' > "$RESULTS_DIR/crashes/CRASH-E2E-003-1/testcase.js"

export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"web image input boundary"}'
triage_crash_dirs 2>/dev/null
unset LLM_DECIDE_MOCK_LEGIT_CRASH

rm -f "$RESULTS_DIR/crashes/CRASH-E2E-003-1/.llm-legit-crash.json"
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":false,"reason":"missing plausible web/content reachability evidence"}'
triage_crash_dirs 2>/dev/null
unset LLM_DECIDE_MOCK_LEGIT_CRASH

# Security crash kept
assert_dir_exists "$RESULTS_DIR/crashes/CRASH-E2E-001-1" "e2e: real security crash kept"

# Null-deref rejected
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-E2E-002-1" "e2e: null-deref rejected"
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-E2E-002-1" "e2e: null-deref → rejected dir"

# Non-web rejected
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-E2E-003-1" "e2e: non-web crash rejected"
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-E2E-003-1" "e2e: non-web → rejected dir"

# ═══════════════════════════════════════════════════════════════
# 3. State files with sensitive vocab → neutralized
# ═══════════════════════════════════════════════════════════════

cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: dom/canvas
| 1 | H1 | The exploit targets the vulnerability via malicious input | PENDING |
EOF
cat > "$(state_file_path 2)" <<'EOF'
## Primary Subsystem: js/src/jit
| 1 | H1 | attacker-controlled drive past the guard | PENDING |
EOF
cat > "$(combined_state_path)" <<'EOF'
Combined view: exploit the vulnerability
EOF

neutralize_qa_vocab

assert_file_contains "$(state_file_path 1)" "reproducer" "e2e: state-1 neutralized (exploit→reproducer)"
assert_file_not_contains "$(state_file_path 1)" "exploit" "e2e: exploit removed from state-1"
assert_file_contains "$(state_file_path 2)" "caller-controlled" "e2e: state-2 neutralized (attacker→caller)"
assert_file_contains "$(combined_state_path)" "reproducer" "e2e: combined state neutralized"

# ═══════════════════════════════════════════════════════════════
# 4. Cluster summaries regenerated after triage
# ═══════════════════════════════════════════════════════════════

maintain_indexes 2>/dev/null

assert_file_exists "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "e2e: crash clusters generated"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" "CRASH-E2E-001-1" "e2e: kept crash in clusters"
assert_file_not_exists "$RESULTS_DIR/crashes/INDEX.md" "e2e: crash index not generated"
assert_file_exists "$RESULTS_DIR/crashes-rejected/INDEX.md" "e2e: rejected index generated"
assert_file_exists "$RESULTS_DIR/crashes-rejected/REJECTED-CRASHES.md" \
  "e2e: rejected crashes report generated"
assert_file_contains "$RESULTS_DIR/crashes-rejected/INDEX.md" "CRASH-E2E-002-1" "e2e: null-deref in rejected index"
assert_file_contains "$RESULTS_DIR/crashes-rejected/REJECTED-CRASHES.md" "CRASH-E2E-002-1" \
  "e2e: null-deref in rejected crashes report"

# ═══════════════════════════════════════════════════════════════
# 5. Deep investigation prompt builds on current state
# ═══════════════════════════════════════════════════════════════

prompt=$(build_deep_investigation_prompt 1 2>/dev/null)
assert_match "DEEP INVESTIGATION" "$prompt" "e2e: deep investigation builds"
assert_match "dom/canvas" "$prompt" "e2e: subsystem in deep prompt"
assert_match "MISSION" "$prompt" "e2e: mission section present"

# ═══════════════════════════════════════════════════════════════
# 6. Session directive respects post-triage state
# ═══════════════════════════════════════════════════════════════

result=$(build_session_directive 1)
assert_match "SESSION STATUS" "$result" "e2e: session directive shows status"

# ═══════════════════════════════════════════════════════════════
# 7. Quality gate on post-triage state
# ═══════════════════════════════════════════════════════════════

result=$(check_agent_quality 1)
assert_match "Stats:" "$result" "e2e: quality check includes stats"

# ═══════════════════════════════════════════════════════════════
# 8. Finding with description → neutralized + clustered
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/findings/FIND-E2E-001-canvas"
cat > "$RESULTS_DIR/findings/FIND-E2E-001-canvas/description.md" <<'EOF'
This vulnerability allows arbitrary code execution via malicious input.
EOF

neutralize_qa_vocab
assert_file_contains "$RESULTS_DIR/findings/FIND-E2E-001-canvas/description.md" "security issue" "e2e: finding description neutralized (vulnerability→security issue)"
assert_file_not_contains "$RESULTS_DIR/findings/FIND-E2E-001-canvas/description.md" "vulnerability" "e2e: vulnerability removed from finding"

maintain_indexes 2>/dev/null
assert_file_contains "$RESULTS_DIR/findings/FINDING-CLUSTERS.md" "FIND-E2E-001" "e2e: finding in clusters"
assert_file_not_exists "$RESULTS_DIR/findings/INDEX.md" "e2e: findings index not generated"

# ═══════════════════════════════════════════════════════════════
# 9. Scratch file header-only neutralization
# ═══════════════════════════════════════════════════════════════

d="$(scratch_dir_path 1)"
cat > "$d/tc_H1.html" <<'EOF'
<!-- exploit the vulnerability -->
<!-- malicious payload -->
line 3
line 4
line 5
line 6
line 7
line 8
line 9
line 10
line 11
line 12
line 13 exploit should stay
line 14
EOF

# Reset marker to force re-neutralization
rm -f "$LOGDIR/.last_neutralize"
neutralize_qa_vocab
assert_file_contains "$d/tc_H1.html" "reproducer" "e2e: scratch header neutralized"
# Line 13+ should be preserved (header-only mode)
assert_file_contains "$d/tc_H1.html" "line 13 exploit should stay" "e2e: scratch body preserved"

# ═══════════════════════════════════════════════════════════════
# 10. Generic target e2e: cold start + deep investigation
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=0
export IS_BROWSER_TARGET
BROWSER_AGENTS=0
SHELL_AGENTS=3
NUM_AGENTS=3
TARGET_SLUG="openssl"
export TARGET_SLUG
ASAN_BUILD_AVAILABLE=0
ASAN_BUILD_BINARY=""
ASAN_BUILD_DIR="$TARGET_ROOT/build-asan"
export ASAN_BUILD_AVAILABLE ASAN_BUILD_BINARY ASAN_BUILD_DIR

rm -f "$(state_file_path 1)"
prompt=$(build_cold_start_prompt 1 2>/dev/null)
assert_match "COLD START" "$prompt" "generic e2e: cold start generated"
assert_match "Agent 1" "$prompt" "generic e2e: agent identity"
assert_not_match "MODE LOCK" "$prompt" "generic e2e: no mode lock in cold start"
assert_match "bin/state resume --agent 1 --mode generic" "$prompt" "generic e2e: structured resume uses generic mode"
assert_match "SANITIZER BUILDS.*NOT FOUND" "$prompt" "generic e2e: asan not-found in cold start"

# Deep investigation with generic target state
cat > "$(state_file_path 1)" <<'EOF'
## Primary Subsystem: src/crypto
| 1 | H1 | src/crypto/evp_enc.c | shape | guard | bounds | A | PENDING |
EOF

prompt=$(build_deep_investigation_prompt 1 2>/dev/null)
assert_match "DEEP INVESTIGATION" "$prompt" "generic e2e: deep investigation generated"
assert_not_match "MODE LOCK" "$prompt" "generic e2e: no mode lock in deep"
assert_not_match "Wrong-mode" "$prompt" "generic e2e: no wrong-mode warning"
assert_match "FIRST ACTION" "$prompt" "generic e2e: first action in deep"
assert_match "MISSION" "$prompt" "generic e2e: mission in deep"

# Session directive works for generic targets
result=$(build_session_directive 1)
assert_match "SESSION STATUS" "$result" "generic e2e: session directive works"

# Quality gate still works
result=$(check_agent_quality 1)
assert_match "Stats:" "$result" "generic e2e: quality check works"

teardown_test_env
summary
