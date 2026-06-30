#!/usr/bin/env bash
# tests/test_confirm_crash.sh — Tests for the LLM confirm-agent that runs
# as the final pre-promotion gate in triage_crash_dirs (lib/triage.sh).
#
# Coverage:
#   1. accept=true   → returns 2, writes accept cache, leaves dir in crashes/.
#   2. accept=false  → returns 0 + reason, writes reject cache, dir is moved
#                       to crashes-rejected/ with .autodiscard.
#   3. cached accept (matching SHA-1) → no LLM call, dir stays.
#   4. cached reject (matching SHA-1) → no LLM call, dir gets rejected.
#   5. asymmetric accept reuse: harness-stamped enrichment (Severity
#      rationale / Cluster / Contract concern) keeps a
#      cached accept while the sanitizer evidence is byte-identical; a
#      substantive (agent-narrative) edit or changed evidence re-litigates.
#   6. malformed JSON / LLM unavailable → undecided → dir kept (fall-through).
#   7. CRASH_CONFIRM_AUTO=0 → gate disabled entirely.
#   8. Concerns array round-trips when present.

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/llm_decide.sh"
source "$SCRIPT_ROOT/lib/triage.sh"

setup_test_env

# Block any real LLM call. Per-test mocks (LLM_DECIDE_MOCK_*) still flow.
export LLM_DECIDE_DISABLE=1

confirm_cache="$RESULTS_DIR/confirm-cache-fields.json"
cat > "$confirm_cache" <<'EOF'
{"content_sha1":"abc123","accept":false,"reason":"cached reason with spaces","votes":3,"evidence_sha1":"ev456","semantic_sha1":"sem789"}
EOF
cache_fields=$(_triage_confirm_cache_fields "$confirm_cache")
eval "set -- $cache_fields"
assert_eq "abc123" "${1:-}" "confirm cache fields: content sha"
assert_eq "false" "${2:-}" "confirm cache fields: accept false preserved"
assert_eq "cached reason with spaces" "${3:-}" "confirm cache fields: reason preserved"
assert_eq "3" "${4:-}" "confirm cache fields: votes"
assert_eq "ev456" "${5:-}" "confirm cache fields: evidence sha"
assert_eq "sem789" "${6:-}" "confirm cache fields: semantic sha"

confirm_src="$(declare -f llm_confirm_crash_report)"
assert_match '_triage_confirm_cache_fields "\$cache"' "$confirm_src" \
  "confirm cache: parses sidecar fields in one helper call"
assert_not_match "jq -r '\\.accept'" "$confirm_src" \
  "confirm cache: avoids per-field jq accept reads"
assert_not_match "jq -r '\\.evidence_sha1" "$confirm_src" \
  "confirm cache: avoids per-field jq asymmetric accept reads"

mk_promotable_crash() {
  # Builds a CRASH-* dir whose ASan trace + report would survive every
  # earlier triage stage. The confirm gate is the only thing that can
  # reject it.
  local id="$1"
  local d="$RESULTS_DIR/crashes/$id"
  mkdir -p "$d"

  cat > "$d/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
WRITE of size 4 at 0x60200000abcd thread T0
    #0 0x100 in Parse(unsigned char*, unsigned long) src/parser.cpp:42
    #1 0x200 in Run() src/main.cpp:9
SUMMARY: AddressSanitizer: heap-buffer-overflow src/parser.cpp:42 in Parse
EOF

  cat > "$d/REPORT.md" <<'EOF'
# CRASH: heap-buffer-overflow in Parse

## Summary
heap-buffer-overflow WRITE of size 4 in Parse() at src/parser.cpp:42 — caller-controlled length field overflows the destination buffer.

## Classification
- **Type**: Buffer Overflow
- **Severity**: High
- **Location**: src/parser.cpp:42
- **Confidence**: High

## Trigger Surface
Boundary: file bytes (CLI parser entry)
Caller controls: length field, payload bytes
Trusted caller actions: read file, hand bytes to Parse()
Caller contract: obeyed
Trigger source: bytes

## Root Cause
A length prefix is read from the input without validation against the
fixed-size destination buffer. Crafted input with a length value larger
than the buffer triggers the overwrite.

## Reproduction
- Reproducer: testcase.bin
- Command: ./build-asan/parse testcase.bin
- Crash type: heap-buffer-overflow WRITE, address 0x60200000abcd

## Data Flow Trace
file_bytes → Run() (main.cpp:9) → Parse() (parser.cpp:42) → memcpy past dst

## Patch
Bounds-check the length prefix against sizeof(dst) before memcpy.
EOF
  # Validation requires testcase > 16 bytes; pad past that floor.
  printf '0123456789abcdef0123456789abcdef\n' > "$d/testcase.bin"
  echo "$d"
}

# ── 1. accept=true → confirmed, dir stays in crashes/ ──────────────
mk_promotable_crash CRASH-CONF-001 >/dev/null
export LLM_DECIDE_MOCK_CRASH_CONFIRM='{"accept":true,"reason":"clean OOB write with bytes trigger","concerns":[]}'
report="$RESULTS_DIR/crashes/CRASH-CONF-001/REPORT.md"
out=$(llm_confirm_crash_report "$report" 2>/dev/null)
rc=$?
assert_eq 2 "$rc" "accept=true returns rc=2"
assert_eq "" "$out" "accept path emits no stdout payload"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-CONF-001/.llm-confirm.json" "accept path writes cache"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CONF-001/.llm-confirm.json" '"accept":[[:space:]]*true' "cache records accept"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CONF-001/.llm-confirm.json" '"content_sha1"' "cache records report SHA-1"
unset LLM_DECIDE_MOCK_CRASH_CONFIRM

# ── 2. accept=false → rejected, reason printed ─────────────────────
mk_promotable_crash CRASH-CONF-002 >/dev/null
export LLM_DECIDE_MOCK_CRASH_CONFIRM='{"accept":false,"reason":"data flow trace is hand-wavy","concerns":["no-dataflow"]}'
report="$RESULTS_DIR/crashes/CRASH-CONF-002/REPORT.md"
out=$(llm_confirm_crash_report "$report" 2>/dev/null)
rc=$?
assert_eq 0 "$rc" "accept=false returns rc=0"
assert_match "hand-wavy" "$out" "reject reason printed to stdout"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-CONF-002/.llm-confirm.json" "reject path writes cache"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CONF-002/.llm-confirm.json" '"accept":[[:space:]]*false' "cache records reject"
unset LLM_DECIDE_MOCK_CRASH_CONFIRM

# ── 3. cached accept hits without LLM call ─────────────────────────
# CRASH-CONF-001 already has an accept cache from step 1. Disable the LLM
# entirely; the cache must still produce rc=2.
unset LLM_DECIDE_MOCK_CRASH_CONFIRM
report="$RESULTS_DIR/crashes/CRASH-CONF-001/REPORT.md"
out=$(LLM_DECIDE_DISABLE=1 llm_confirm_crash_report "$report" 2>/dev/null)
rc=$?
assert_eq 2 "$rc" "cached accept honored with LLM disabled"

# ── 4. cached reject hits without LLM call ─────────────────────────
report="$RESULTS_DIR/crashes/CRASH-CONF-002/REPORT.md"
out=$(LLM_DECIDE_DISABLE=1 llm_confirm_crash_report "$report" 2>/dev/null)
rc=$?
assert_eq 0 "$rc" "cached reject honored with LLM disabled"
assert_match "hand-wavy" "$out" "cached reject reason replayed from disk"

# ── 5a. harness-stamped enrichment keeps a cached accept ────────────
# bin/severity, bin/cluster-crashes, and the contract-concern
# annotator rewrite report.md between triage passes without changing
# what the gate judges. A cached ACCEPT must survive those stamps while
# the sanitizer evidence is byte-identical — re-asking the gate every
# sweep was pure LLM waste.
report="$RESULTS_DIR/crashes/CRASH-CONF-001/REPORT.md"
cat >> "$report" <<'EOF'

Cluster: CL-20260611-1
Dedup frames: app_parse|main
## Severity rationale
- **Severity**: High (auto: CVSS-BTE 4.0: 8.7)
Derived from reach=High and primitive=oob-write.
## Patch
<!-- enrich:patch-diff -->
--- a/src/app.c
+++ b/src/app.c
<!-- /enrich:patch-diff -->
<!-- enrich:tldr -->
TL;DR: enricher-generated summary block.
<!-- /enrich:tldr -->
EOF
out=$(LLM_DECIDE_DISABLE=1 llm_confirm_crash_report "$report" 2>/dev/null)
rc=$?
assert_eq 2 "$rc" "harness-stamped enrichment keeps cached accept (evidence + substance unchanged)"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CONF-001/.llm-confirm.json" '"evidence_sha1"' \
  "accept cache records the sanitizer-evidence SHA-1"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CONF-001/.llm-confirm.json" '"semantic_sha1"' \
  "accept cache records the agent-substance SHA-1"

# ── 5b. substantive (agent-narrative) edit re-litigates ─────────────
# An edit outside the harness-stamped sections changes the substance the
# gate judged — the cached accept must NOT be reused. With the LLM
# disabled and no mock, the gate falls to rc=1.
echo "## Note" >> "$report"
echo "impact rewritten: actually this needs an unrealistic 3-call setup" >> "$report"
out=$(LLM_DECIDE_DISABLE=1 llm_confirm_crash_report "$report" 2>/dev/null)
rc=$?
assert_eq 1 "$rc" "substantive report edit re-litigates: treated as undecided when LLM is unavailable"

# ── 5c. reverting the substantive edit restores the cached accept ───
# The reuse key is content-derived, not order/time-derived: restoring the
# judged substance (harness stamps may differ) makes the accept valid again.
python3 - "$report" <<'PY'
import sys
p = sys.argv[1]
lines = open(p).read().splitlines(True)
open(p, "w").writelines(lines[:-2])  # drop the "## Note" block
PY
out=$(LLM_DECIDE_DISABLE=1 llm_confirm_crash_report "$report" 2>/dev/null)
rc=$?
assert_eq 2 "$rc" "reverting the substantive edit restores the cached accept"

# ── 5d. changed sanitizer evidence re-litigates ─────────────────────
# New evidence means a different crash — the cached accept must NOT be
# reused even though the report substance is unchanged.
echo "    #2 0x300 in Extra() src/extra.cpp:7" >> "$RESULTS_DIR/crashes/CRASH-CONF-001/asan.txt"
out=$(LLM_DECIDE_DISABLE=1 llm_confirm_crash_report "$report" 2>/dev/null)
rc=$?
assert_eq 1 "$rc" "changed evidence re-litigates: stale cache treated as undecided when LLM is unavailable"

# ── 6. malformed LLM output → rc=1 (undecided) ─────────────────────
mk_promotable_crash CRASH-CONF-003 >/dev/null
export LLM_DECIDE_MOCK_CRASH_CONFIRM='not actually json at all'
report="$RESULTS_DIR/crashes/CRASH-CONF-003/REPORT.md"
out=$(llm_confirm_crash_report "$report" 2>/dev/null)
rc=$?
assert_eq 1 "$rc" "malformed LLM output → undecided"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-CONF-003/.llm-confirm.json" \
  "no cache written on malformed response"
unset LLM_DECIDE_MOCK_CRASH_CONFIRM

# ── 7. integration: triage_crash_dirs respects confirm reject ──────
# Build a fresh dir that survives all earlier stages; mock the confirm
# agent to reject; assert it lands in crashes-rejected/ with the right
# autodiscard text. CRASH_CONFIRM_AUTO defaults on. Disable the
# needs-review purgatory so the legacy fast-path is exercised here;
# section 7b below asserts the default purgatory behavior.
#
# Fixture cleanup (wall-time): CRASH-CONF-001..003 are fully asserted by
# sections 1–6 (which drive llm_confirm_crash_report directly) and nothing
# below references them. Remove 001/002 so the integration triage passes
# below don't re-gate every leftover dir; 003 (no confirm cache) stays for
# the first pass so it still walks more than one dir with heterogeneous
# cache states — a loop abort mid-pass fails CONF-004's assertions.
rm -rf "$RESULTS_DIR/crashes/CRASH-CONF-001" \
       "$RESULTS_DIR/crashes/CRASH-CONF-002"
mk_promotable_crash CRASH-CONF-004 >/dev/null
export CRASH_REJECT_NEEDS_REVIEW=0
export LLM_DECIDE_MOCK_CRASH_CONFIRM='{"accept":false,"reason":"trigger source declared bytes but testcase needs chrome-only API","concerns":["self-contradictory"]}'
# Avoid triggering the regex auto-discard branch on this clean trace.
export LLM_DECIDE_MOCK_CRASH_TRIAGE='{"keep":true,"reason":"clean overflow"}'
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"public input boundary"}'
triage_crash_dirs >/dev/null 2>&1 || true
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-CONF-004" \
  "confirm-reject removes dir from crashes/"
rejected_dir=$(find "$RESULTS_DIR/crashes-rejected" -maxdepth 1 -name 'CRASH-CONF-004*' -type d | head -1)
assert_dir_exists "$rejected_dir" "confirm-reject lands in crashes-rejected/"
assert_file_exists "$rejected_dir/.autodiscard" "confirm-reject writes .autodiscard"
assert_file_contains "$rejected_dir/.autodiscard" "LLM-CONFIRM:" \
  ".autodiscard tags the LLM-CONFIRM gate"
assert_file_contains "$rejected_dir/.autodiscard" "chrome-only API" \
  ".autodiscard preserves the LLM reason"
unset CRASH_REJECT_NEEDS_REVIEW
unset LLM_DECIDE_MOCK_CRASH_CONFIRM
unset LLM_DECIDE_MOCK_CRASH_TRIAGE
unset LLM_DECIDE_MOCK_LEGIT_CRASH

# ── 7b. integration: confirm reject defaults to needs-review purgatory ───
# Default behavior (CRASH_REJECT_NEEDS_REVIEW unset → "1"): a single
# uncertain LLM judgement routes the dir to crashes-needs-review/ rather
# than destructively to crashes-rejected/. The dir survives so the next
# triage iteration can re-evaluate it.
mk_promotable_crash CRASH-CONF-004B >/dev/null
export LLM_DECIDE_MOCK_CRASH_CONFIRM='{"accept":false,"reason":"description does not name a public boundary","concerns":["vague"]}'
export LLM_DECIDE_MOCK_CRASH_TRIAGE='{"keep":true,"reason":"clean overflow"}'
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"public input boundary"}'
triage_crash_dirs >/dev/null 2>&1 || true
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-CONF-004B" \
  "needs-review: removes dir from crashes/"
review_dir=$(find "$RESULTS_DIR/crashes-needs-review" -maxdepth 1 -name 'CRASH-CONF-004B*' -type d | head -1)
assert_dir_exists "$review_dir" "needs-review: lands in crashes-needs-review/"
assert_file_exists "$review_dir/.needs-review" "needs-review: writes .needs-review marker"
assert_file_contains "$review_dir/.needs-review" "Reason: LLM-CONFIRM:" \
  ".needs-review names the LLM-CONFIRM gate"
unset LLM_DECIDE_MOCK_CRASH_CONFIRM
unset LLM_DECIDE_MOCK_CRASH_TRIAGE
unset LLM_DECIDE_MOCK_LEGIT_CRASH

# Second pass: needs-review is not a dead-letter queue. It is moved back into
# crashes/, the stale rejection cache is removed, and a fresh confirm decision
# can keep it.
export LLM_DECIDE_MOCK_CRASH_CONFIRM='{"accept":true,"reason":"second reviewer accepts","concerns":[]}'
export LLM_DECIDE_MOCK_CRASH_TRIAGE='{"keep":true,"reason":"clean overflow"}'
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"public input boundary"}'
triage_crash_dirs >/dev/null 2>&1 || true
requeued_dir=$(find "$RESULTS_DIR/crashes" -maxdepth 1 -name 'CRASH-CONF-004B*' -type d | head -1)
assert_dir_exists "$requeued_dir" "needs-review: second pass requeues to crashes/"
assert_file_exists "$requeued_dir/.review-requeued" "needs-review: writes requeue marker"
assert_file_not_exists "$requeued_dir/.needs-review" "needs-review: old marker removed on requeue"
assert_file_exists "$requeued_dir/.llm-confirm.json" "needs-review: second pass writes fresh confirm cache"
assert_file_contains "$requeued_dir/.llm-confirm.json" "second reviewer accepts" \
  "needs-review: second pass used fresh confirm decision"
unset LLM_DECIDE_MOCK_CRASH_CONFIRM
unset LLM_DECIDE_MOCK_CRASH_TRIAGE
unset LLM_DECIDE_MOCK_LEGIT_CRASH

# Fixture cleanup (wall-time): the requeued CRASH-CONF-004B is fully
# asserted; remove it so the next triage calls don't re-gate it.
rm -rf "$requeued_dir"
mkdir -p "$RESULTS_DIR/crashes-needs-review/CRASH-CONF-SECOND"
touch "$RESULTS_DIR/crashes-needs-review/CRASH-CONF-SECOND/.review-requeued"
triage_crash_dirs >/dev/null 2>&1 || true
assert_dir_exists "$RESULTS_DIR/crashes-needs-review/CRASH-CONF-SECOND" \
  "needs-review: already requeued crash stays for manual review"

# ── 8. integration: triage_crash_dirs honors confirm accept ────────
# Same setup, but confirm says yes. Dir must remain in crashes/.
mk_promotable_crash CRASH-CONF-005 >/dev/null
export LLM_DECIDE_MOCK_CRASH_CONFIRM='{"accept":true,"reason":"clean fileable OOB write","concerns":[]}'
export LLM_DECIDE_MOCK_CRASH_TRIAGE='{"keep":true,"reason":"clean overflow"}'
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"public input boundary"}'
triage_crash_dirs >/dev/null 2>&1 || true
assert_dir_exists "$RESULTS_DIR/crashes/CRASH-CONF-005" \
  "confirm-accept keeps dir in crashes/"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-CONF-005/.llm-confirm.json" \
  "confirm-accept writes cache during triage_crash_dirs"
unset LLM_DECIDE_MOCK_CRASH_CONFIRM
unset LLM_DECIDE_MOCK_CRASH_TRIAGE
unset LLM_DECIDE_MOCK_LEGIT_CRASH

# ── 9. CRASH_CONFIRM_AUTO=0 disables the gate entirely ─────────────
# Fixture cleanup (wall-time): CRASH-CONF-005 is fully asserted above.
rm -rf "$RESULTS_DIR/crashes/CRASH-CONF-005"
mk_promotable_crash CRASH-CONF-006 >/dev/null
# Mock would reject if the gate ran.
export LLM_DECIDE_MOCK_CRASH_CONFIRM='{"accept":false,"reason":"would reject if gate ran"}'
export LLM_DECIDE_MOCK_CRASH_TRIAGE='{"keep":true,"reason":"clean overflow"}'
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"public input boundary"}'
CRASH_CONFIRM_AUTO=0 triage_crash_dirs >/dev/null 2>&1 || true
assert_dir_exists "$RESULTS_DIR/crashes/CRASH-CONF-006" \
  "CRASH_CONFIRM_AUTO=0 bypasses the confirm gate"
unset LLM_DECIDE_MOCK_CRASH_CONFIRM
unset LLM_DECIDE_MOCK_CRASH_TRIAGE
unset LLM_DECIDE_MOCK_LEGIT_CRASH

# ── 10. concerns array survives JSON round-trip ────────────────────
# A reject with a populated concerns array shouldn't break the cache
# writer (the bash-side jq invocation only persists accept/reason but
# must still succeed when the LLM payload includes other keys).
mk_promotable_crash CRASH-CONF-007 >/dev/null
export LLM_DECIDE_MOCK_CRASH_CONFIRM='{"accept":false,"reason":"copy-pasted from sibling finding","concerns":["duplicate-stale","other"]}'
report="$RESULTS_DIR/crashes/CRASH-CONF-007/REPORT.md"
out=$(llm_confirm_crash_report "$report" 2>/dev/null)
rc=$?
assert_eq 0 "$rc" "concerns array does not break reject path"
assert_match "copy-pasted" "$out" "reason intact when concerns present"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CONF-007/.llm-confirm.json" \
  '"accept":[[:space:]]*false' "cache stored despite extra concerns key"
unset LLM_DECIDE_MOCK_CRASH_CONFIRM

# ── 11. split vote is fail-open: one reject then accept KEEPS the crash ──
# A single skeptical vote must not sink a real crash. The gate keeps polling
# until a vote accepts (short-circuit) or `quorum` rejects stack up. Drive it
# with a queue mock: reject first, accept second.
mk_promotable_crash CRASH-CONF-Q1 >/dev/null
qfile="$RESULTS_DIR/.q-confirm-split"
cat > "$qfile" <<'EOF'
{"accept":false,"reason":"first reviewer is unsure"}
---
{"accept":true,"reason":"second reviewer confirms the OOB write"}
EOF
rm -f "$qfile.idx"
export LLM_DECIDE_MOCK_CRASH_CONFIRM_QUEUE="$qfile"
report="$RESULTS_DIR/crashes/CRASH-CONF-Q1/REPORT.md"
out=$(llm_confirm_crash_report "$report" 2>/dev/null); rc=$?
assert_eq 2 "$rc" "split vote (reject then accept) confirms — one reject can't sink a crash"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CONF-Q1/.llm-confirm.json" \
  '"accept":[[:space:]]*true' "split vote: accept cached"
unset LLM_DECIDE_MOCK_CRASH_CONFIRM_QUEUE

# ── 12. a quorum of rejects sticks, and the cache records the vote count ──
mk_promotable_crash CRASH-CONF-Q2 >/dev/null
qfile="$RESULTS_DIR/.q-confirm-reject"
# Single entry → it "sticks" past the end, so every independent vote rejects.
cat > "$qfile" <<'EOF'
{"accept":false,"reason":"trigger needs an undocumented caller action"}
EOF
rm -f "$qfile.idx"
export LLM_DECIDE_MOCK_CRASH_CONFIRM_QUEUE="$qfile"
report="$RESULTS_DIR/crashes/CRASH-CONF-Q2/REPORT.md"
out=$(llm_confirm_crash_report "$report" 2>/dev/null); rc=$?
assert_eq 0 "$rc" "quorum of rejects rejects the crash"
votes=$(jq -r '.votes' "$RESULTS_DIR/crashes/CRASH-CONF-Q2/.llm-confirm.json" 2>/dev/null)
assert_eq 2 "$votes" "reject cache records the quorum vote count"
unset LLM_DECIDE_MOCK_CRASH_CONFIRM_QUEUE

# ── 13. a legacy sub-quorum reject cache is re-litigated, not honored ──
# CRASH-CONF-Q2 now carries a quorum-backed reject cache (votes=2). With the
# LLM disabled it is honored (rc=0). Rewriting it to votes=1 — the shape an
# older single-vote gate wrote — must force a fresh decision instead.
report="$RESULTS_DIR/crashes/CRASH-CONF-Q2/REPORT.md"
out=$(LLM_DECIDE_DISABLE=1 llm_confirm_crash_report "$report" 2>/dev/null); rc=$?
assert_eq 0 "$rc" "votes>=quorum reject cache honored with LLM disabled"
cache="$RESULTS_DIR/crashes/CRASH-CONF-Q2/.llm-confirm.json"
tmp=$(jq '.votes = 1' "$cache"); printf '%s\n' "$tmp" > "$cache"
out=$(LLM_DECIDE_DISABLE=1 llm_confirm_crash_report "$report" 2>/dev/null); rc=$?
assert_eq 1 "$rc" "sub-quorum (votes=1) reject cache is re-litigated, not honored"

teardown_test_env
summary
