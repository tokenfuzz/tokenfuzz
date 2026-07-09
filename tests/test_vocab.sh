#!/usr/bin/env bash
# Unit tests for lib/vocab_rules.py and lib/vocab.sh
#
# Scope mirrors lib/vocab_rules.py: only safety-classifier-sensitive
# vocabulary (exploit/attack/attacker/malicious/weaponize/vulnerability).
# Pure technical jargon (UAF, OOB, type confusion, etc.) is NOT
# rewritten — those terms pass through verbatim.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/platform.sh"
source "$SCRIPT_ROOT/lib/vocab.sh"

# ── Helper: run a string through the core neutralizer ──────────
neutralize_core() {
  printf '%s' "$1" | python3 "$SCRIPT_ROOT/lib/vocab_rules.py" line-core
}

neutralize_prompt() {
  printf '%s' "$1" | python3 "$SCRIPT_ROOT/lib/vocab_rules.py" line-prompt
}

# ═══════════════════════════════════════════════════════════════
# 1. exploit family — grammar-aware split
# ═══════════════════════════════════════════════════════════════

assert_eq "reproducer" "$(neutralize_core "exploit")" "exploit (bare noun) → reproducer"
assert_eq "reproducers" "$(neutralize_core "exploits")" "exploits (plural noun) → reproducers"
assert_eq "reachable" "$(neutralize_core "exploitable")" "exploitable (adj) → reachable"
assert_eq "reproduction" "$(neutralize_core "exploitation")" "exploitation (noun) → reproduction"
assert_eq "could reach" "$(neutralize_core "could exploit")" "could exploit (verb) → could reach"
assert_eq "may reach" "$(neutralize_core "may exploit")" "may exploit (verb) → may reach"
assert_eq "can reach" "$(neutralize_core "can exploit")" "can exploit (verb) → can reach"
assert_eq "might reach" "$(neutralize_core "might exploit")" "might exploit (verb) → might reach"
assert_eq "to reach" "$(neutralize_core "to exploit")" "to exploit (verb) → to reach"
assert_eq "reproducer" "$(neutralize_core "Exploit")" "Exploit (capitalized) → reproducer"

# ═══════════════════════════════════════════════════════════════
# 2. attack / attacker family
# ═══════════════════════════════════════════════════════════════

assert_eq "externally-controlled" "$(neutralize_core "attacker-controlled")" "attacker-controlled → externally-controlled (kept distinct from caller)"
assert_eq "externally-Controlled" "$(neutralize_core "Attacker-Controlled")" "mixed case attacker- prefix neutralized"
assert_eq "externally-shaped" "$(neutralize_core "attacker-shaped")" "attacker-shaped → externally-shaped"
assert_eq "externally-reachable" "$(neutralize_core "attacker-reachable")" "attacker-reachable → externally-reachable (compound coverage)"
assert_eq "input vector" "$(neutralize_core "attack vector")" "attack vector → input vector"
assert_eq "input surface" "$(neutralize_core "attack surface")" "attack surface → input surface"
# Bare attack — preserves grammatical form (verb tenses + plural).
assert_eq "reach" "$(neutralize_core "attack")" "attack (bare) → reach"
assert_eq "reaches" "$(neutralize_core "attacks")" "attacks (plural/3sg) → reaches"
assert_eq "reached" "$(neutralize_core "attacked")" "attacked (past) → reached"
assert_eq "reaching" "$(neutralize_core "attacking")" "attacking (gerund) → reaching"
# Bare attacker(s).
assert_eq "external party" "$(neutralize_core "attacker")" "bare attacker → external party (distinct from caller)"
assert_eq "external parties" "$(neutralize_core "attackers")" "bare attackers → external parties"
# Field-name protection: attacker_controls must survive (underscore is
# a regex word char, so \b does not fire between r and _).
assert_eq "attacker_controls = [\"bytes\"]" "$(neutralize_core "attacker_controls = [\"bytes\"]")" "passthrough: attacker_controls field name"
assert_eq "_normalize_attacker_control(item)" "$(neutralize_core "_normalize_attacker_control(item)")" "passthrough: attacker_control function name"
assert_eq "TARGET_ATTACKER_CONTROLS_CSV" "$(neutralize_core "TARGET_ATTACKER_CONTROLS_CSV")" "passthrough: ATTACKER_CONTROLS env var"

# ═══════════════════════════════════════════════════════════════
# 3. hostile-intent vocabulary
# ═══════════════════════════════════════════════════════════════

assert_eq "hand-crafted" "$(neutralize_core "malicious")" "malicious → hand-crafted"
assert_eq "hand-crafted" "$(neutralize_core "MALICIOUS")" "MALICIOUS (upper) → hand-crafted"
assert_eq "reproduce" "$(neutralize_core "weaponize")" "weaponize → reproduce"
assert_eq "reproduced" "$(neutralize_core "weaponized")" "weaponized → reproduced (preserves tense)"

# ═══════════════════════════════════════════════════════════════
# 4. vulnerability → security issue
# ═══════════════════════════════════════════════════════════════

assert_eq "security issue" "$(neutralize_core "vulnerability")" "vulnerability → security issue"
assert_eq "security issues" "$(neutralize_core "vulnerabilities")" "vulnerabilities → security issues"
# Dedup: "security vulnerabilities" expands then collapses.
assert_eq "security issue" "$(neutralize_core "security vulnerability")" "security vulnerability → security issue (deduped)"
assert_eq "security issues" "$(neutralize_core "security vulnerabilities")" "security vulnerabilities → security issues (deduped)"
assert_eq "security issue" "$(neutralize_core "security-vulnerability")" "security-vulnerability (hyphenated) → security issue (deduped)"

# ═══════════════════════════════════════════════════════════════
# 5. Passthrough — technical vocabulary the rules deliberately do NOT touch
# ═══════════════════════════════════════════════════════════════

# Bug-class names — these are neutral programming jargon, no
# classifier blocks them, rewriting them only mangles meaning.
assert_eq "use-after-free" "$(neutralize_core "use-after-free")" "passthrough: use-after-free"
assert_eq "double-free" "$(neutralize_core "double-free")" "passthrough: double-free"
assert_eq "out-of-bounds read" "$(neutralize_core "out-of-bounds read")" "passthrough: out-of-bounds read"
assert_eq "OOB" "$(neutralize_core "OOB")" "passthrough: OOB"
assert_eq "UAF" "$(neutralize_core "UAF")" "passthrough: UAF"
assert_eq "type confusion" "$(neutralize_core "type confusion")" "passthrough: type confusion"
assert_eq "integer overflow" "$(neutralize_core "integer overflow")" "passthrough: integer overflow"
assert_eq "race condition" "$(neutralize_core "race condition")" "passthrough: race condition"
assert_eq "null pointer dereference" "$(neutralize_core "null pointer dereference")" "passthrough: null pointer dereference"
assert_eq "null-deref" "$(neutralize_core "null-deref")" "passthrough: null-deref label"
assert_eq "memory corruption" "$(neutralize_core "memory corruption")" "passthrough: memory corruption"
assert_eq "memory-safety bugs" "$(neutralize_core "memory-safety bugs")" "passthrough: memory-safety bugs"
assert_eq "arbitrary code execution" "$(neutralize_core "arbitrary code execution")" "passthrough: arbitrary code execution"
# Programmer slang.
assert_eq "drive" "$(neutralize_core "drive")" "passthrough: drive"
assert_eq "drives" "$(neutralize_core "drives")" "passthrough: drives"
assert_eq "driver" "$(neutralize_core "driver")" "passthrough: driver"
assert_eq "clobber" "$(neutralize_core "clobber")" "passthrough: clobber"
assert_eq "clobbered" "$(neutralize_core "clobbered")" "passthrough: clobbered"
assert_eq "UB" "$(neutralize_core "UB")" "passthrough: UB"
assert_eq "trigger" "$(neutralize_core "trigger")" "passthrough: trigger"
assert_eq "triggers" "$(neutralize_core "triggers")" "passthrough: triggers"
assert_eq "reads outside" "$(neutralize_core "reads outside")" "passthrough: reads outside"
# Bug / fix terminology.
assert_eq "security fix" "$(neutralize_core "security fix")" "passthrough: security fix"
assert_eq "security patch" "$(neutralize_core "security patch")" "passthrough: security patch"
assert_eq "security bug" "$(neutralize_core "security bug")" "passthrough: security bug"
assert_eq "bug-rich" "$(neutralize_core "bug-rich")" "passthrough: bug-rich"
assert_eq "sanitizer-visible defects" "$(neutralize_core "sanitizer-visible defects")" "passthrough: sanitizer-visible defects"
assert_eq "malformed" "$(neutralize_core "malformed")" "passthrough: malformed"
# Prompt-only rules removed — these now pass through too.
assert_eq "patch-mining" "$(neutralize_prompt "patch-mining")" "passthrough: patch-mining (file already renamed)"
assert_eq "defensive security" "$(neutralize_prompt "defensive security")" "passthrough: defensive security"
assert_eq "find bugs" "$(neutralize_prompt "find bugs")" "passthrough: find bugs"
assert_eq "memory errors caught by ASan" "$(neutralize_prompt "memory errors caught by ASan")" "passthrough: memory errors caught by"
# ASan literal classifier output must always pass through.
assert_eq "AddressSanitizer: heap-buffer-overflow" "$(neutralize_core "AddressSanitizer: heap-buffer-overflow")" "passthrough: ASan output"
assert_eq "AddressSanitizer: heap-use-after-free" "$(neutralize_core "AddressSanitizer: heap-use-after-free")" "passthrough: ASan UAF output"
assert_eq "AddressSanitizer: stack-use-after-return" "$(neutralize_core "AddressSanitizer: stack-use-after-return")" "passthrough: ASan stack-use-after-return"
assert_eq "AddressSanitizer: stack-buffer-overflow" "$(neutralize_core "AddressSanitizer: stack-buffer-overflow")" "passthrough: ASan stack-buffer-overflow"
assert_eq "SCARINESS: 10 (null-deref)" "$(neutralize_core "SCARINESS: 10 (null-deref)")" "passthrough: ASan SCARINESS line"
assert_eq "safe string" "$(neutralize_core "safe string")" "passthrough: no match"

# Prompt mode includes core rules.
assert_eq "reproducer" "$(neutralize_prompt "exploit")" "prompt mode includes core: exploit → reproducer"

# ═══════════════════════════════════════════════════════════════
# 6. neutralize_qa_vocab_file — file mode
# ═══════════════════════════════════════════════════════════════

cat > "$TEST_TMPDIR/test_full.md" <<'EOF'
This exploit targets the vulnerability.
The attacker-controlled input shapes an attack.
This triggers a crash via malicious payload.
EOF
neutralize_qa_vocab_file "$TEST_TMPDIR/test_full.md" 0
assert_file_contains "$TEST_TMPDIR/test_full.md" "reproducer" "file mode: exploit → reproducer"
assert_file_contains "$TEST_TMPDIR/test_full.md" "security issue" "file mode: vulnerability → security issue"
assert_file_contains "$TEST_TMPDIR/test_full.md" "externally-controlled" "file mode: attacker-controlled → externally-controlled"
assert_file_contains "$TEST_TMPDIR/test_full.md" "hand-crafted" "file mode: malicious → hand-crafted"
assert_file_not_contains "$TEST_TMPDIR/test_full.md" "exploit" "file mode: exploit fully removed"
assert_file_not_contains "$TEST_TMPDIR/test_full.md" "attacker" "file mode: attacker fully removed"
assert_file_not_contains "$TEST_TMPDIR/test_full.md" "malicious" "file mode: malicious fully removed"
assert_file_not_contains "$TEST_TMPDIR/test_full.md" "vulnerability" "file mode: vulnerability fully removed"

# File mode rewrites via temp+replace; preserve the original mode instead of
# turning rewritten artifacts into mkstemp's 0600 files.
cat > "$TEST_TMPDIR/test_mode.md" <<'EOF'
exploit
EOF
chmod 755 "$TEST_TMPDIR/test_mode.md"
mode_before=$(python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o7777))' "$TEST_TMPDIR/test_mode.md")
neutralize_qa_vocab_file "$TEST_TMPDIR/test_mode.md" 0
mode_after=$(python3 -c 'import os, sys; print(oct(os.stat(sys.argv[1]).st_mode & 0o7777))' "$TEST_TMPDIR/test_mode.md")
assert_eq "$mode_before" "$mode_after" "file mode: preserves permissions across atomic replace"

# Header-only mode (only first 12 lines)
{
  for i in $(seq 1 12); do echo "line $i: exploit"; done
  for i in $(seq 13 20); do echo "line $i: exploit"; done
} > "$TEST_TMPDIR/test_header.md"
neutralize_qa_vocab_file "$TEST_TMPDIR/test_header.md" 1
assert_file_contains "$TEST_TMPDIR/test_header.md" "line 1: reproducer" "header-only: line 1 neutralized"
assert_file_contains "$TEST_TMPDIR/test_header.md" "line 13: exploit" "header-only: line 13 preserved"

# Binary file should be skipped.
printf '\x00\x01\x02\x03' > "$TEST_TMPDIR/test_binary.bin"
neutralize_qa_vocab_file "$TEST_TMPDIR/test_binary.bin" 0
pass "binary file safely skipped"

# Non-existent file should be a no-op.
neutralize_qa_vocab_file "$TEST_TMPDIR/nonexistent.md" 0
pass "nonexistent file safely skipped"

# ═══════════════════════════════════════════════════════════════
# 7. neutralize_qa_vocab_string — pipe mode
# ═══════════════════════════════════════════════════════════════

result=$(echo "The exploit targets the vulnerability." | neutralize_qa_vocab_string)
assert_match "reproducer" "$result" "pipe mode: exploit neutralized"
assert_match "security issue" "$result" "pipe mode: vulnerability neutralized"

# ═══════════════════════════════════════════════════════════════
# 8. neutralize_qa_vocab — batch mode with marker
# ═══════════════════════════════════════════════════════════════

cat > "$RESULTS_DIR/AUDIT_STATE-1.md" <<'EOF'
## Primary Subsystem: dom/canvas
| H1 | exploit the vulnerability | PENDING |
EOF
cat > "$RESULTS_DIR/AUDIT_STATE-2.md" <<'EOF'
## Primary Subsystem: js/src/jit
| H1 | reach past the attacker-controlled guard | PENDING |
EOF
cat > "$RESULTS_DIR/AUDIT_STATE.md" <<'EOF'
Combined: exploit
EOF
mkdir -p "$RESULTS_DIR/scratch-1"
cat > "$RESULTS_DIR/scratch-1/tc_H1.html" <<'EOF'
<!-- TARGET: dom/canvas/Foo.cpp:Bar:123 -->
<!-- HYPOTHESIS-ID: H1 -->
<!-- CATEGORY: bounds -->
exploit line 4
exploit line 5
exploit line 6
exploit line 7
exploit line 8
exploit line 9
exploit line 10
exploit line 11
exploit line 12
exploit line 13 (should stay in header-only)
line 14 no match
EOF
mkdir -p "$RESULTS_DIR/findings/FIND-001-test"
cat > "$RESULTS_DIR/findings/FIND-001-test/description.md" <<'EOF'
This vulnerability is reachable from caller-controlled input.
EOF

neutralize_qa_vocab
assert_file_contains "$RESULTS_DIR/AUDIT_STATE-1.md" "reproducer" "batch: state-1 neutralized"
assert_file_contains "$RESULTS_DIR/AUDIT_STATE-2.md" "externally-controlled" "batch: state-2 neutralized"
assert_file_contains "$RESULTS_DIR/AUDIT_STATE.md" "reproducer" "batch: combined neutralized"
assert_file_contains "$RESULTS_DIR/findings/FIND-001-test/description.md" "security issue" "batch: finding description neutralized (vulnerability→security issue)"
assert_file_contains "$RESULTS_DIR/scratch-1/tc_H1.html" "reproducer" "batch: scratch header neutralized"

assert_file_exists "$LOGDIR/.last_neutralize" "batch: marker file created"

# Running again should skip files not newer than marker.
cat > "$RESULTS_DIR/AUDIT_STATE-1.md" <<'EOF'
## Primary Subsystem: dom/canvas
| H1 | exploit the vulnerability | PENDING |
EOF
touch "$LOGDIR/.last_neutralize"
neutralize_qa_vocab
assert_file_contains "$RESULTS_DIR/AUDIT_STATE-1.md" "exploit" "batch: re-run skips files older than marker"

# ═══════════════════════════════════════════════════════════════
# 9. Compound expressions — multiple substitutions in one line
# ═══════════════════════════════════════════════════════════════

result=$(neutralize_core "The exploit targets the vulnerability via malicious input")
assert_match "reproducer" "$result" "compound: exploit → reproducer"
assert_match "security issue" "$result" "compound: vulnerability → security issue"
assert_match "hand-crafted" "$result" "compound: malicious → hand-crafted"
assert_not_match "exploit" "$result" "compound: exploit fully removed"
assert_not_match "malicious" "$result" "compound: malicious fully removed"

# ═══════════════════════════════════════════════════════════════
# 10. Empty string passthrough
# ═══════════════════════════════════════════════════════════════

result=$(neutralize_core "")
assert_eq "" "$result" "empty string: passthrough"

teardown_test_env
summary
