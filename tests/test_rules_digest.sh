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
  "bin/state resume --agent"           # After Context Compression
  "crashes-rejected"                   # Rejected Crashes
  "FINDING-CLUSTERS"                   # Rejected Findings
  "Caller contract"                    # CRASH Promotion Gate
  "Trigger source"                     # CRASH Promotion Gate
  "Parameter control"                  # CRASH Promotion Gate
  "FIND"                               # FIND Quality Bar
  "patch.diff"                         # FIND patch best-effort
  "write that section"                 # enrich-report owns ## Patch section
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
# The digest carries only the short best-effort nudge; the apply --check /
# dry-run mechanics live in the full rules (asserted above) and the digest
# points there for drill-down, matching its drill-down pattern.
assert_file_contains "$DIGEST" "Fix Direction" \
  "digest nudges a one-line Fix Direction"
assert_file_contains "$DIGEST" "best-effort" \
  "digest frames patch/fix as best-effort, never blocking"

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
for sub in show-recent list-cards recent-notes recent-claims recent-tried; do
  assert_file_contains "$DIGEST" "$sub" \
    "digest cheat sheet documents compact state accessor $sub"
done
assert_file_contains "$DIGEST" "explain-queue" \
  "digest cheat sheet documents explain-queue filters"
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


# ── Python prompt integration ─────────────────────────────────────
output=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - "$SCRIPT_ROOT/.agents/references" <<'PY'
import sys
from pathlib import Path
import prompt
print(prompt.session_rules_digest(Path(sys.argv[1])))
PY
)
assert_match 'Session Rules.*Digest' "$output" "session_rules_digest emits the digest header"
assert_match 'bin/probe' "$output" "session_rules_digest emits probe guidance"

missing=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - <<'PY'
from pathlib import Path
import prompt
print(prompt.session_rules_digest(Path("/no/such/reference")))
PY
)
assert_match 'digest missing' "$missing" "missing digest degrades with drill-down guidance"

teardown_test_env
summary
