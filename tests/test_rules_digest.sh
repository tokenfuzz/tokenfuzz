#!/usr/bin/env bash
# Tests for Fix 5 — rules digest embed.
#
# Coverage:
#   - .agents/references/session-rules.digest.md is meaningfully smaller
#     than the full session-rules.md (so embedding it is a win).
#   - The digest covers every load-bearing section heading from the full
#     file (so agents don't lose coverage by dropping the long file read).
#   - build_session_rules_digest emits the digest content.
#   - build_common_suffix embeds the digest under the SESSION RULES DIGEST
#     heading.
#   - The old "Read … session-rules.md ONCE at session start" instruction
#     is GONE from the prompt builders (would otherwise re-trigger the
#     per-session re-read the fix is meant to eliminate).
#   - A missing digest file degrades gracefully (test envs with partial
#     trees still build prompts).

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

PROMPT_SH="$SCRIPT_ROOT/lib/prompt.sh"
FULL_RULES="$SCRIPT_ROOT/.agents/references/session-rules.md"
DIGEST="$SCRIPT_ROOT/.agents/references/session-rules.digest.md"

assert_file_exists "$DIGEST" "digest file exists at expected path"
assert_file_exists "$FULL_RULES" "full rules file exists (drill-down target)"

# ── Size: digest is at least 2x smaller than the full file ────────
# The point of the digest is to cut per-session bytes paid for "read the
# rules" tool calls. If the digest is the same size as the full file, it's
# not buying anything.
full_bytes=$(wc -c < "$FULL_RULES" | tr -d ' ')
digest_bytes=$(wc -c < "$DIGEST" | tr -d ' ')
ratio_ok=$([ "$digest_bytes" -lt $(( full_bytes / 2 )) ] && echo 1 || echo 0)
assert_eq 1 "$ratio_ok" \
  "digest is at least 2x smaller (digest=$digest_bytes vs full=$full_bytes)"

# Also: digest shouldn't be trivially short. If it's under 2 KB it
# probably doesn't actually cover the load-bearing rules.
[ "$digest_bytes" -gt 2000 ]
assert_eq 0 $? "digest is substantive (got $digest_bytes bytes, want > 2000)"

# ── Coverage: the digest must mention every section heading from the
# full file. Heading drift is the main maintenance hazard — if a new
# section lands in session-rules.md and the digest doesn't mirror it,
# agents lose that rule entirely.
#
# We match on the topic keywords, not the exact heading string, since
# the digest deliberately rephrases (e.g. "Coverage-Gated Reproduction" →
# "Reproduction wrapper"). The keyword list below picks tokens that have
# to appear in any honest digest of the same rules.
expected_topics=(
  "bin/probe"                          # Coverage-Gated Reproduction
  "TARGET:"                            # Testcase Header Coupling
  "find-seed"                          # Seed Corpus First
  "guards-db"                          # Guards Database
  "tried-inputs"                       # Tried-Inputs Memory
  "rg-safe"                            # Search Discipline
  "bin/peek"                           # Search Discipline (peek subsection)
  "show-patch"                         # Search Discipline (show-patch subsection)
  "NEUTRAL"                            # State File Management
  "Working Context"                    # After Context Compression
  "crashes-rejected"                   # Rejected Crashes
  "FINDING-CLUSTERS"                   # Rejected Findings
  "Caller contract"                    # CRASH Promotion Gate
  "Trigger source"                     # CRASH Promotion Gate
  "Parameter control"                  # CRASH Promotion Gate
  "FIND"                               # FIND Quality Bar
  "patch.diff"                         # FIND patch optional
  "three validation attempts"           # FIND patch validation loop
  "Patch: builds"                       # validated patch status
  "differential"                       # Differential Testing (case-insensitive ok)
)
for topic in "${expected_topics[@]}"; do
  if grep -qiF -- "$topic" "$DIGEST"; then
    pass "digest covers topic: $topic"
  else
    fail "digest missing topic: $topic" "expected '$topic' in $DIGEST"
  fi
done

# ── The digest must point at the full file for drill-down ────────
# Agents need a way to reach the long file when the digest is ambiguous.
# We require an explicit mention of the long-file path AND a "drill-down"
# style instruction, so the digest isn't a dead-end.
assert_file_contains "$DIGEST" "session-rules.md" \
  "digest points at the full file for drill-down"
assert_file_contains "$DIGEST" "Drill-down" \
  "digest has an explicit drill-down section"
assert_file_contains "$FULL_RULES" "up to three attempts" \
  "full rules document patch validation retry budget"
assert_file_contains "$FULL_RULES" "apply check and build pass within the three attempts" \
  "full rules document requires apply/build before recommending patch.diff"
assert_file_contains "$FULL_RULES" "revise the diff" \
  "full rules tell the agent to revise the patch between failed attempts"

# ── Prompt builder integration ────────────────────────────────────
# Source the prompt builder in a contained shell so its globals don't
# leak. We can't fully drive build_common_suffix without the rest of
# bin/audit's setup, so we test the digest emitter directly — that's the
# function the suffix calls.
output=$(REFERENCE_DIR="$SCRIPT_ROOT/.agents/references" bash -c "
  set -u
  source '$PROMPT_SH'
  build_session_rules_digest
")
assert_match 'Session Rules — Digest' "$output" \
  "build_session_rules_digest emits the digest header"
assert_match 'bin/probe' "$output" \
  "build_session_rules_digest emits digest content"
assert_match 'Drill-down' "$output" \
  "build_session_rules_digest emits drill-down section"

# Caching: a second call within the same shell must return identical
# bytes (the cache variable should hold).
output2=$(REFERENCE_DIR="$SCRIPT_ROOT/.agents/references" bash -c "
  set -u
  source '$PROMPT_SH'
  build_session_rules_digest
  build_session_rules_digest
")
# Two emissions should be exactly 2x the bytes of one emission (no leading
# initialization output, no per-call slack).
single_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
double_bytes=$(printf '%s' "$output2" | wc -c | tr -d ' ')
expected=$(( single_bytes * 2 ))
# Allow ±2 bytes for trailing-newline accounting.
diff=$(( double_bytes - expected ))
[ "$diff" -lt 0 ] && diff=$(( -diff ))
[ "$diff" -le 2 ]
assert_eq 0 $? \
  "build_session_rules_digest cache: 2 calls = 2x bytes (got $double_bytes vs $expected)"

# ── Graceful degradation when digest file is missing ──────────────
# Test envs and partially provisioned trees should still build prompts.
output=$(REFERENCE_DIR="$TEST_TMPDIR/no-such-refs" bash -c "
  set -u
  source '$PROMPT_SH'
  build_session_rules_digest
")
assert_match 'digest missing' "$output" \
  "missing digest: graceful fallback message"
# The fallback should still point at the long file so agents know where to look.
assert_match 'session-rules.md' "$output" \
  "missing digest: fallback names the long file"

# ── No regression: the dropped 'Read … ONCE at session start' line ──
# The whole point of this fix is that agents stop re-reading the long
# file every session. If any prompt builder still emits that instruction,
# the per-session re-read returns and the fix is moot.
#
# We grep the prompt builders for the dropped sentence shape. The new
# code emits "drill into … session-rules.md only when the digest is
# ambiguous" — that's an allowed mention. The old shape was
# "read … session-rules.md ONCE at session start" — that one must be gone.
# grep -c exits 1 when the pattern isn't found; we don't want the `|| echo 0`
# trick because it emits a second line on top of grep's "0", which then trips
# integer-equality assertions. `grep -c | head -1` keeps a single number.
old_count=$(grep -c 'session-rules\.md.*ONCE at session start' "$PROMPT_SH" 2>/dev/null | head -1)
old_count="${old_count:-0}"
assert_eq 0 "$old_count" \
  "prompt.sh no longer instructs agents to re-read session-rules.md once per session"

teardown_test_env
summary
