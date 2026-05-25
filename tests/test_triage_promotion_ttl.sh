#!/usr/bin/env bash
# Tests for the .promotion_pending TTL demotion path added to
# lib/triage.sh: when a crash dir stays incomplete with the same
# missing-set across CRASH_PROMOTION_PENDING_MAX triage passes,
# triage_crash_dirs moves it to crashes-rejected/ with a
# `never-reproduced-under-sanitizer:` reason.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/triage.sh"

# Make the threshold small so the test is fast.
export CRASH_PROMOTION_PENDING_MAX=3

# ═══════════════════════════════════════════════════════════════
# 1. Stale missing asan.txt → demoted after N passes
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-TTL-1"
echo "report body" > "$RESULTS_DIR/crashes/CRASH-TTL-1/report.md"
echo "int main(void){return 0;}" > "$RESULTS_DIR/crashes/CRASH-TTL-1/repro.c"
# No asan.txt — the dir is permanently incomplete.

for i in 1 2; do
  triage_crash_dirs 2>/dev/null
  assert_dir_exists "$RESULTS_DIR/crashes/CRASH-TTL-1" "pass $i: still in crashes/"
  assert_file_exists "$RESULTS_DIR/crashes/CRASH-TTL-1/.promotion_pending" "pass $i: marker present"
  assert_file_exists "$RESULTS_DIR/crashes/CRASH-TTL-1/.promotion_pending.sig" "pass $i: sig sidecar present"
  count_now=$(cat "$RESULTS_DIR/crashes/CRASH-TTL-1/.promotion_pending.count")
  assert_eq "$i" "$count_now" "pass $i: counter == $i"
done

# Third pass crosses the threshold → demoted.
triage_crash_dirs 2>/dev/null
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-TTL-1" "after threshold: dir moved out of crashes/"
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-TTL-1" "after threshold: dir in crashes-rejected/"
assert_file_exists "$RESULTS_DIR/crashes-rejected/CRASH-TTL-1/.autodiscard" "autodiscard marker written"
if grep -q "never-reproduced-under-sanitizer" \
     "$RESULTS_DIR/crashes-rejected/CRASH-TTL-1/.autodiscard" 2>/dev/null; then
  pass "autodiscard reason mentions never-reproduced-under-sanitizer"
else
  fail "autodiscard reason mentions never-reproduced-under-sanitizer" "missing keyword"
fi
# Index log records the REJECT line.
if grep -q "REJECT: crashes/CRASH-TTL-1" "$INDEX" 2>/dev/null; then
  pass "index.log records REJECT entry"
else
  fail "index.log records REJECT entry" "not in $INDEX"
fi

# ═══════════════════════════════════════════════════════════════
# 2. Counter resets when the missing-set changes (progress)
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-TTL-2"
echo "int main(void){return 0;}" > "$RESULTS_DIR/crashes/CRASH-TTL-2/repro.c"
# Pass 1: missing report.md AND asan.txt
triage_crash_dirs 2>/dev/null
count1=$(cat "$RESULTS_DIR/crashes/CRASH-TTL-2/.promotion_pending.count")
assert_eq "1" "$count1" "first pass count is 1"

# Pass 2: same missing-set → bumps to 2
triage_crash_dirs 2>/dev/null
count2=$(cat "$RESULTS_DIR/crashes/CRASH-TTL-2/.promotion_pending.count")
assert_eq "2" "$count2" "second identical pass count is 2"

# Pass 3: agent finally adds report.md → missing-set shrinks → counter
# resets to 1, dir stays in crashes/.
echo "now I have a report" > "$RESULTS_DIR/crashes/CRASH-TTL-2/report.md"
triage_crash_dirs 2>/dev/null
assert_dir_exists "$RESULTS_DIR/crashes/CRASH-TTL-2" "after progress: still in crashes/"
count3=$(cat "$RESULTS_DIR/crashes/CRASH-TTL-2/.promotion_pending.count")
assert_eq "1" "$count3" "after progress: counter reset to 1"

# ═══════════════════════════════════════════════════════════════
# 3. Complete dir clears all sidecars on its happy path
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-TTL-3"
cat > "$RESULTS_DIR/crashes/CRASH-TTL-3/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead
#0 0x7fff in foo
EOF
echo "report" > "$RESULTS_DIR/crashes/CRASH-TTL-3/report.md"
echo "int main(void){return 0;}" > "$RESULTS_DIR/crashes/CRASH-TTL-3/repro.c"
# Pre-seed sidecars from a stale prior pass; they must be cleared once
# triage validates this dir successfully.
echo "missing:x" > "$RESULTS_DIR/crashes/CRASH-TTL-3/.promotion_pending.sig"
echo "5"        > "$RESULTS_DIR/crashes/CRASH-TTL-3/.promotion_pending.count"
echo "stale"    > "$RESULTS_DIR/crashes/CRASH-TTL-3/.promotion_pending"
# Pre-seed .audit/-level sidecars too. bin/export-repro's migration step
# moves any non-bundle dotfile from root into .audit/ on its first pass —
# the .promotion_pending sidecars get swept along and become stale state
# that the clear function never reached before. Regression for that gap.
mkdir -p "$RESULTS_DIR/crashes/CRASH-TTL-3/.audit"
echo "stale-audit"   > "$RESULTS_DIR/crashes/CRASH-TTL-3/.audit/.promotion_pending"
echo "missing:audit" > "$RESULTS_DIR/crashes/CRASH-TTL-3/.audit/.promotion_pending.sig"
echo "4"             > "$RESULTS_DIR/crashes/CRASH-TTL-3/.audit/.promotion_pending.count"

triage_crash_dirs 2>/dev/null
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-TTL-3/.promotion_pending" "marker cleared on success"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-TTL-3/.promotion_pending.sig" "sig sidecar cleared on success"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-TTL-3/.promotion_pending.count" "count sidecar cleared on success"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-TTL-3/.audit/.promotion_pending" "audit-side marker cleared on success"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-TTL-3/.audit/.promotion_pending.sig" "audit-side sig sidecar cleared on success"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-TTL-3/.audit/.promotion_pending.count" "audit-side count sidecar cleared on success"

# ═══════════════════════════════════════════════════════════════
# 4. Bundle-scope counter advances across passes when step-2
#    validation succeeds every time (regression for the
#    “stuck at pass 1/10” bug — clearing sidecars between step-2
#    and step-3 used to wipe the bundle counter).
#
# Set up a crash dir that passes step-2 (report.md + asan.txt valid +
# testcase present) but FAILS step-3 (export-repro refuses to bundle).
# We force the failure by pointing bin/export-repro at a stub that
# always exits non-zero — so REPORT.md, reproduce.sh, input.* never
# appear, and _triage_bundle_missing_artifacts keeps returning the
# same missing set.
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/crashes/CRASH-BUNDLE-1"
cat > "$RESULTS_DIR/crashes/CRASH-BUNDLE-1/asan.txt" <<'EOF'
==42==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead
#0 0x7fff in foo
EOF
echo "report" > "$RESULTS_DIR/crashes/CRASH-BUNDLE-1/report.md"
echo "abcd"  > "$RESULTS_DIR/crashes/CRASH-BUNDLE-1/testcase.txt"

# Force the bundle step to fail by overriding the real
# _triage_bundle_crash_dir with a stub that simulates an
# export-repro failure (leaves the crash dir without REPORT.md /
# reproduce.sh / input.*, mirroring the production bug).
_orig_bundle=$(declare -f _triage_bundle_crash_dir)
_triage_bundle_crash_dir() {
  local d="$1"
  mkdir -p "$d/.audit" 2>/dev/null || true
  printf '[stub] simulated internal-ref leak\n' > "$d/.audit/export-repro.err"
  : > "$d/.audit/export-repro.out"
  # Intentionally do NOT create REPORT.md / reproduce.sh / input.*
  return 0
}

for pass in 1 2; do
  triage_crash_dirs 2>/dev/null
  assert_dir_exists "$RESULTS_DIR/crashes/CRASH-BUNDLE-1" "bundle-pass-$pass: still in crashes/"
  count_now=$(cat "$RESULTS_DIR/crashes/CRASH-BUNDLE-1/.promotion_pending.count" 2>/dev/null)
  assert_eq "$pass" "$count_now" "bundle-pass-$pass: counter == $pass (not stuck at 1)"
done

# Third pass crosses CRASH_PROMOTION_PENDING_MAX=3 and the dir is
# moved to crashes-rejected/ — proving the TTL escape hatch now
# actually fires for export-repro failures.
triage_crash_dirs 2>/dev/null
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-BUNDLE-1" "bundle-ttl: moved out of crashes/"
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-BUNDLE-1" "bundle-ttl: now in crashes-rejected/"
if grep -q "bundle-incomplete" \
     "$RESULTS_DIR/crashes-rejected/CRASH-BUNDLE-1/.autodiscard" 2>/dev/null; then
  pass "bundle-ttl: autodiscard reason cites bundle-incomplete"
else
  fail "bundle-ttl: autodiscard reason cites bundle-incomplete" "missing keyword"
fi

# Restore the original bundle helper so other tests aren't affected.
eval "$_orig_bundle"
unset _orig_bundle

# ═══════════════════════════════════════════════════════════════
# P5. _triage_record_card_reject_skip — reject writes do-not-revisit
# ═══════════════════════════════════════════════════════════════
# When _triage_move_to_rejected runs, it should call bin/state
# mark-card-reject-skip with the rejected crash id. The CLI resolves
# the originating hypothesis row and appends the (card_id, agent)
# marker to state/card-reject-skips.jsonl. Verifies the end-to-end
# shell→CLI→workqueue path.
mkdir -p "$RESULTS_DIR/state"
: > "$RESULTS_DIR/state/hypotheses.jsonl"
: > "$RESULTS_DIR/state/claims.jsonl"
: > "$RESULTS_DIR/state/runs.jsonl"
: > "$RESULTS_DIR/state/events.jsonl"
: > "$RESULTS_DIR/state/notes.jsonl"
cat > "$RESULTS_DIR/work-cards.jsonl" <<'JSONL'
{"id":"WORK-REJ-1","kind":"ranked-source","target_slug":"testproject","subsystem":"src/a","file":"src/a/x.c","mode":"generic","strategy":"S2","score":50,"status":"unclaimed"}
JSONL
cat > "$RESULTS_DIR/state/hypotheses.jsonl" <<'JSONL'
{"id":"H-rej","agent":"1","card_id":"WORK-REJ-1","status":"CRASH-REJ-1","file":"src/a/x.c","hypothesis":"caller-misuse","updated_at":"2026-05-23T00:00:00Z"}
JSONL
mkdir -p "$RESULTS_DIR/crashes/CRASH-REJ-1"
echo "report" > "$RESULTS_DIR/crashes/CRASH-REJ-1/report.md"

_triage_move_to_rejected "$RESULTS_DIR/crashes/CRASH-REJ-1" "CRASH-REJ-1" "caller-misuse" 2>/dev/null
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-REJ-1" "P5: dir moved on reject"
assert_file_exists "$RESULTS_DIR/state/card-reject-skips.jsonl" "P5: reject-skip ledger created"
if grep -q '"card_id": "WORK-REJ-1"' "$RESULTS_DIR/state/card-reject-skips.jsonl" 2>/dev/null \
   && grep -q '"agent": "1"' "$RESULTS_DIR/state/card-reject-skips.jsonl" 2>/dev/null; then
  pass "P5: reject-skip row recorded with card_id and agent"
else
  fail "P5: reject-skip row recorded with card_id and agent" \
       "got: $(cat "$RESULTS_DIR/state/card-reject-skips.jsonl" 2>/dev/null)"
fi
if grep -q "REJECT-SKIP: card WORK-REJ-1" "$INDEX" 2>/dev/null; then
  pass "P5: index.log records REJECT-SKIP audit line"
else
  fail "P5: index.log records REJECT-SKIP audit line" "not in $INDEX"
fi

# Opt-out path: CRASH_REJECT_SKIP_DO_NOT_REVISIT=0 skips the call.
rm -f "$RESULTS_DIR/state/card-reject-skips.jsonl" 2>/dev/null
mkdir -p "$RESULTS_DIR/crashes/CRASH-REJ-2"
echo "report" > "$RESULTS_DIR/crashes/CRASH-REJ-2/report.md"
cat >> "$RESULTS_DIR/state/hypotheses.jsonl" <<'JSONL'
{"id":"H-rej2","agent":"2","card_id":"WORK-REJ-1","status":"CRASH-REJ-2","file":"src/a/x.c","hypothesis":"second misuse","updated_at":"2026-05-23T00:00:00Z"}
JSONL
CRASH_REJECT_SKIP_DO_NOT_REVISIT=0 _triage_move_to_rejected \
  "$RESULTS_DIR/crashes/CRASH-REJ-2" "CRASH-REJ-2" "caller-misuse-2" 2>/dev/null
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-REJ-2" "P5 opt-out: dir still moved"
if [ -f "$RESULTS_DIR/state/card-reject-skips.jsonl" ]; then
  fail "P5 opt-out: CRASH_REJECT_SKIP_DO_NOT_REVISIT=0 suppresses ledger write" \
       "ledger created when opted out: $(cat "$RESULTS_DIR/state/card-reject-skips.jsonl")"
else
  pass "P5 opt-out: CRASH_REJECT_SKIP_DO_NOT_REVISIT=0 suppresses ledger write"
fi

summary
