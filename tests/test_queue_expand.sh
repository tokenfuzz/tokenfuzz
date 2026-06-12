#!/usr/bin/env bash
# tests/test_queue_expand.sh — the BATCH_EXHAUSTED queue-expansion path
# (bin/audit expand_structured_work_cards_if_exhausted).
#
# Coverage:
#   1. First exhaustion grows the queue once via bin/rank-work and records
#      the (requested, produced) pair in state/.rank-expand-marker.
#   2. Futility skip: when the last expansion requested more cards than
#      the generator produced and the queue is unchanged, the re-rank is
#      skipped entirely (no rank-work subprocess, no LLM rerank behind it).
#   3. A queue-size change (recon/patch cards landing) reopens expansion.
#   4. The failed-expansion path no longer writes the queue-exhaustion
#      report internally (the caller owns the single write).

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/platform.sh"

setup_test_env

# ── Extract the function under test from bin/audit ──────────────────
eval "$(awk '
  $0 ~ "^expand_structured_work_cards_if_exhausted\\(\\) \\{" { in_func=1 }
  in_func { print }
  in_func && $0 == "}" { exit }
' "$SCRIPT_ROOT/bin/audit")"

# ── Stub collaborators ──────────────────────────────────────────────
# The function consults relative bin/ paths, so run from a sandbox root
# with counting stubs.
sandbox="$TEST_TMPDIR/expand-sandbox"
mkdir -p "$sandbox/bin"
RANK_CALLS="$sandbox/rank-calls.log"
: > "$RANK_CALLS"
cat > "$sandbox/bin/rank-work" <<EOF
#!/bin/bash
# Stub generator: always produces exactly 12 cards regardless of --limit.
# created_at varies per invocation, exactly like the real ranker — the
# futility marker must be insensitive to that churn.
echo run >> "$RANK_CALLS"
runs=\$(grep -c run "$RANK_CALLS")
out=""
while [ \$# -gt 0 ]; do
  [ "\$1" = "--output" ] && out="\$2"
  shift
done
for i in \$(seq 1 12); do
  echo "{\"id\":\"CARD-\$i\",\"created_at\":\"2026-06-12T00:00:\${runs}Z\"}"
done > "\$out"
EOF
cat > "$sandbox/bin/state" <<'EOF'
#!/bin/bash
exit 0
EOF
chmod 755 "$sandbox/bin/rank-work" "$sandbox/bin/state" 2>/dev/null || chmod +x "$sandbox/bin/rank-work" "$sandbox/bin/state"

eligible_work_card_exists() { return 1; }
target_has_prior_audit_progress() { return 0; }
work_cards_path() { printf '%s/work-cards.jsonl' "$RESULTS_DIR"; }
patch_cards_path() { printf '%s/patch-cards.jsonl' "$RESULTS_DIR"; }
write_queue_exhaustion_report() { echo "exhaustion-report" >> "$INDEX"; }
current_target_source_signature() { cat "$sandbox/src-sig" 2>/dev/null || echo rev0; }
log() { printf '%s\n' "$*"; }
TARGET_ROOT="$TEST_TMPDIR" TARGET_SLUG="sampleproj"
echo rev0 > "$sandbox/src-sig"

mkdir -p "$RESULTS_DIR/state"
for i in $(seq 1 12); do
  echo "{\"id\":\"CARD-$i\",\"created_at\":\"2026-06-12T00:00:00Z\"}"
done > "$RESULTS_DIR/work-cards.jsonl"

cd "$sandbox"

# ── 1. first exhaustion: expansion runs and records the marker ──────
out=$(expand_structured_work_cards_if_exhausted 2>&1)
rc=$?
assert_eq 1 "$rc" "expansion that surfaces nothing eligible returns 1"
assert_match 'growing the ranked queue' "$out" "first exhaustion grows the queue"
assert_eq 1 "$(grep -c run "$RANK_CALLS")" "first exhaustion invoked rank-work once"
assert_file_exists "$RESULTS_DIR/state/.rank-expand-marker" "expansion records requested/produced marker"
marker_content=$(cat "$RESULTS_DIR/state/.rank-expand-marker")
assert_match '^[0-9]+ 12 [0-9a-f]+$' "$marker_content" \
  "marker records produced count and queue content sha"

# ── 2. unchanged queue: futile re-rank is skipped ───────────────────
# The per-iteration refresh rewrites the queue with fresh created_at
# stamps; simulate that before re-checking — the timestamp-only change
# must NOT defeat the skip.
python3 - "$RESULTS_DIR/work-cards.jsonl" <<'PY'
import json, sys
p = sys.argv[1]
# Preserve key order: jq's normalization keeps input order, so only the
# timestamp value may differ here.
rows = [json.loads(l) for l in open(p)]
for r in rows:
    r["created_at"] = "2026-06-12T11:11:11Z"
open(p, "w").write("".join(json.dumps(r) + "\n" for r in rows))
PY
out=$(expand_structured_work_cards_if_exhausted 2>&1)
rc=$?
assert_eq 1 "$rc" "futile expansion still reports failure to the caller"
assert_match 'generator is exhausted' "$out" "futility skip names the exhausted generator"
assert_eq 1 "$(grep -c run "$RANK_CALLS")" "futility skip survives created_at churn (no rank-work re-run)"

# ── 3. queue change reopens expansion ───────────────────────────────
echo '{"id":"CARD-recon-extra"}' >> "$RESULTS_DIR/work-cards.jsonl"
out=$(expand_structured_work_cards_if_exhausted 2>&1)
assert_match 'growing the ranked queue' "$out" "queue growth reopens expansion"
assert_eq 2 "$(grep -c run "$RANK_CALLS")" "changed queue re-invokes rank-work"

# ── 3b. same line count, different content also reopens ─────────────
# A status flip or re-score keeps the queue length identical; the marker
# keys on content, so it must still reopen the attempt.
out=$(expand_structured_work_cards_if_exhausted 2>&1)
assert_eq 2 "$(grep -c run "$RANK_CALLS")" "baseline: unchanged content skips"
python3 - "$RESULTS_DIR/work-cards.jsonl" <<'PY'
import sys
p = sys.argv[1]
lines = open(p).read().splitlines(True)
lines[0] = '{"id":"CARD-1","status":"blocked"}\n'
open(p, "w").writelines(lines)
PY
out=$(expand_structured_work_cards_if_exhausted 2>&1)
assert_match 'growing the ranked queue' "$out" "same-count content change reopens expansion"
assert_eq 3 "$(grep -c run "$RANK_CALLS")" "same-count content change re-invokes rank-work"

# ── 3c. target source change reopens even with an unchanged queue ────
# rank-work scans the target tree; a pulled commit or local edit must
# reopen expansion even when the queue files happen not to move.
out=$(expand_structured_work_cards_if_exhausted 2>&1)
assert_eq 3 "$(grep -c run "$RANK_CALLS")" "baseline: stable source + queue skips"
echo rev1 > "$sandbox/src-sig"
out=$(expand_structured_work_cards_if_exhausted 2>&1)
assert_match 'growing the ranked queue' "$out" "target source change reopens expansion"
assert_eq 4 "$(grep -c run "$RANK_CALLS")" "target source change re-invokes rank-work"

# ── 4. failed expansion does not write the report internally ────────
report_writes=$(grep -c 'exhaustion-report' "$INDEX" 2>/dev/null || true)
assert_eq 0 "$report_writes" "expansion path leaves the queue-exhaustion report to its caller"

cd "$SCRIPT_ROOT"
teardown_test_env
summary
