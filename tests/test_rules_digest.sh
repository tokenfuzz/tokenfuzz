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
  "single writer"                      # enrich-report owns ## Patch section
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
assert_file_contains "$FULL_RULES" "apply --check" \
  "full rules name git apply --check as the patch.diff save floor"
assert_file_contains "$FULL_RULES" "non-mutating" \
  "full rules describe apply --check as non-mutating"
assert_file_contains "$FULL_RULES" "not a dry run" \
  "full rules correct the hg import --no-commit dry-run myth"
assert_file_contains "$DIGEST" "apply --check" \
  "digest names git apply --check as the patch.diff save floor"
assert_file_contains "$DIGEST" "not a dry run" \
  "digest corrects the hg import --no-commit dry-run myth"

# ── The digest must inline the bin/state cheat sheet ────────────────
# Agents historically burned ~5 `bin/state … --help` round-trips per
# session because the cheat sheet lived only in the long (non-embedded)
# file. The compact argument-shape reference must live in the digest so it
# ships in every prompt. We sample a few subcommands that appeared as
# --help calls in real transcripts.
assert_file_contains "$DIGEST" "bin/state cheat sheet" \
  "digest inlines the bin/state cheat sheet (kills --help round-trips)"
for sub in add-hyp update-hyp add-note update-card; do
  assert_file_contains "$DIGEST" "$sub" \
    "digest cheat sheet documents bin/state $sub"
done
for sub in show-recent dump-queue list-notes recent-claims recent-tried; do
  assert_file_contains "$DIGEST" "$sub" \
    "digest cheat sheet documents compact state accessor $sub"
done
assert_file_contains "$DIGEST" "explain-queue" \
  "digest cheat sheet documents resume-shaped explain-queue flags"
assert_file_contains "$DIGEST" "strategy S" \
  "digest cheat sheet documents explain-queue strategy flag"
assert_file_contains "$DIGEST" "bin/state recent-tried --agent N --limit 40" \
  "digest tells compressed sessions to use recent-tried instead of raw tail"
assert_file_contains "$DIGEST" 'Do not run `bin/rank-work` just to browse cards' \
  "digest steers agents away from rank-work dumps"
assert_file_contains "$DIGEST" "bin/scratch-status --agent N" \
  "digest steers agents away from raw scratch ls listings"
if grep -q 'tail -40 <RESULTS_DIR>/tried-inputs-N.log' "$DIGEST"; then
  fail "digest no longer recommends raw tail for tried-inputs" \
    "found stale tail -40 tried-inputs guidance in $DIGEST"
else
  pass "digest no longer recommends raw tail for tried-inputs"
fi

# ── The digest must warn against reverse-engineering the harness ────
# Transcripts showed agents grepping bin/ and lib/ for the testcase-header
# and probe contract. The digest carries that contract, so it must tell
# agents not to dig into harness source for it.
assert_file_contains "$DIGEST" "reverse-engineer the harness" \
  "digest warns agents off grepping bin/lib for the contract"
assert_file_contains "$FULL_RULES" "single writer" \
  "full rules tell the agent that enrich-report is the sole ## Patch writer"
assert_file_contains "$FULL_RULES" "Fix Direction" \
  "full rules name ## Fix Direction as the advisory case"

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

# ── Regression: an empty static cache must NOT strip the digest ─────
# A failed/raced/truncating write left .static-prompt-rules.md at 0 bytes;
# build_common_suffix's old `-f` test cat'd it to nothing, silently
# dropping the entire digest from every deep-investigation prompt for a
# whole resumed run. build_common_suffix must fall back to live
# computation when the cache is empty, and write_static_prompt_file must
# publish atomically (no empty/partial reads, no leftover temp files).
suffix_probe=$(REFERENCE_DIR="$SCRIPT_ROOT/.agents/references" bash -c '
  set -u
  source "'"$PROMPT_SH"'"
  cached_blocklist_description(){ echo "<none>"; }
  fuzz_leads_path(){ echo "/tmp/fl"; }
  neutralize_qa_vocab_string(){ cat; }
  RESULTS_DIR=$(mktemp -d); export RESULTS_DIR
  sf="$RESULTS_DIR/.static-prompt-rules.md"
  : > "$sf"                                   # 0-byte cache (the bug trigger)
  empty_out=$(build_common_suffix)
  printf "EMPTY_DIGEST=%s\n" "$(printf "%s" "$empty_out" | grep -c "PATH CONVENTION")"
  printf "SUFFIX_DIGEST_API=%s\n" "$(printf "%s" "$empty_out" | grep -c "digest below is the API for .bin/probe. and .bin/state")"
  printf "SUFFIX_PROBE_HELP_EXAMPLE=%s\n" "$(printf "%s" "$empty_out" | grep -c "bin/probe --help")"
  write_static_prompt_file                    # atomic publish
  printf "STATIC_NONEMPTY=%s\n" "$([ -s "$sf" ] && echo 1 || echo 0)"
  printf "TMP_LEFTOVER=%s\n" "$(ls "$sf".tmp.* 2>/dev/null | wc -l | tr -d " ")"
  cached_out=$(build_common_suffix)
  printf "CACHED_DIGEST=%s\n" "$(printf "%s" "$cached_out" | grep -c "PATH CONVENTION")"
  rm -rf "$RESULTS_DIR"
')
assert_match 'EMPTY_DIGEST=[1-9]' "$suffix_probe" \
  "build_common_suffix falls back to live digest when static cache is empty"
assert_match 'SUFFIX_DIGEST_API=[1-9]' "$suffix_probe" \
  "build_common_suffix tells agents the digest is the bin/probe/bin/state API"
assert_match 'SUFFIX_PROBE_HELP_EXAMPLE=0' "$suffix_probe" \
  "build_common_suffix no longer nudges agents toward bin/probe --help"
assert_match 'STATIC_NONEMPTY=1' "$suffix_probe" \
  "write_static_prompt_file publishes a non-empty static cache"
assert_match 'TMP_LEFTOVER=0' "$suffix_probe" \
  "write_static_prompt_file leaves no temp files behind"
assert_match 'CACHED_DIGEST=[1-9]' "$suffix_probe" \
  "build_common_suffix serves the digest from a populated cache"

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

# Same regression guard for the runtime-loaded AGENTS.md: its SESSION START
# step must not tell agents to read the long session-rules.md unconditionally
# ("ONCE"). The digest is embedded in the prompt; the long file is a
# drill-down only. An unconditional read re-sends ~22 KB on every later turn.
AGENTS_MD="$SCRIPT_ROOT/AGENTS.md"
agents_old=$(grep -c 'session-rules\.md.*ONCE' "$AGENTS_MD" 2>/dev/null | head -1)
agents_old="${agents_old:-0}"
assert_eq 0 "$agents_old" \
  "AGENTS.md no longer instructs agents to read session-rules.md ONCE per session"
# It should still name the file as a conditional drill-down so agents know
# where to look when the embedded digest is ambiguous.
assert_match 'session-rules\.md' "$(cat "$AGENTS_MD")" \
  "AGENTS.md still names session-rules.md as a drill-down"

teardown_test_env
summary
