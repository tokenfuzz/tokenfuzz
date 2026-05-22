#!/usr/bin/env bash
# Tests for lib/platform.sh's stat wrappers — they must return a
# clean integer (epoch seconds for mtime, byte count for size) on
# both GNU stat (Linux) and BSD stat (macOS). The pre-fix code
# tried `stat -f '%m'` first and fell back to `stat -c '%Y'`, but
# `stat -f` on GNU stat prints filesystem status (multi-line junk)
# AND exits 0, so the fallback never ran and `[ -gt ]` choked.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/platform.sh"

# ─── audit_stat_mtime_epoch returns an integer ─────────────────
f="$TEST_TMPDIR/probe.txt"
echo "hello" > "$f"
mtime=$(audit_stat_mtime_epoch "$f")
if [[ "$mtime" =~ ^[0-9]+$ ]] && [ "$mtime" -gt 0 ]; then
  pass "audit_stat_mtime_epoch: returns positive integer"
else
  fail "audit_stat_mtime_epoch: returns positive integer" "got: $mtime"
fi

# Must be usable directly in `[ -gt ]` — the original triage.sh bug
# was that the helper returned multi-line junk that broke this.
older_file="$TEST_TMPDIR/older.txt"
echo "old" > "$older_file"
# Touch with a deterministic past mtime so the comparison is robust
# even if file creation times are very close.
touch -t 200001010000 "$older_file" 2>/dev/null || true
newer_mtime=$(audit_stat_mtime_epoch "$f")
older_mtime=$(audit_stat_mtime_epoch "$older_file")
if [ "$newer_mtime" -gt "$older_mtime" ] 2>/dev/null; then
  pass "audit_stat_mtime_epoch: arithmetic comparison works"
else
  fail "audit_stat_mtime_epoch: arithmetic comparison works" "new=$newer_mtime old=$older_mtime"
fi

# Missing file → 0 (not an error spill). This guards the helper from
# returning empty strings that callers might pass into `[ -gt 0 ]`.
missing_mtime=$(audit_stat_mtime_epoch "$TEST_TMPDIR/does-not-exist")
assert_eq "0" "$missing_mtime" "audit_stat_mtime_epoch: missing file → 0"

# ─── audit_stat_size returns an integer ─────────────────────────
size=$(audit_stat_size "$f")
if [[ "$size" =~ ^[0-9]+$ ]]; then
  pass "audit_stat_size: returns integer"
else
  fail "audit_stat_size: returns integer" "got: $size"
fi
# 'hello\n' is 6 bytes; exact value sanity check.
assert_eq "6" "$size" "audit_stat_size: counts bytes correctly"

# ─── triage.sh consumes the helper without choking ──────────────
# Regression for the specific stack trace the user pasted:
#   lib/triage.sh: line 1699: [: <multi-line stat junk>: integer expression expected
source "$SCRIPT_ROOT/lib/triage.sh"
mkdir -p "$RESULTS_DIR/scratch-1/.harness-cache"
for n in 1 2 3 4; do
  echo "error: foo $n" > "$RESULTS_DIR/scratch-1/.harness-cache/log-$n.deadbeef.build.log"
done
export BUILD_FAILURE_WARN_THRESHOLD=3
# Silently invoke the function and capture stderr — any `integer
# expression expected` chatter would land here.
err=$(warn_persistent_harness_build_failures 2>&1 >/dev/null)
if grep -q "integer expression expected" <<<"$err"; then
  fail "warn_persistent_harness_build_failures: no stat parse errors" "stderr: $err"
else
  pass "warn_persistent_harness_build_failures: no stat parse errors"
fi
# And the warn line itself reached index.log.
if grep -q "persistent harness build failures" "$INDEX"; then
  pass "warn_persistent_harness_build_failures: WARN emitted"
else
  fail "warn_persistent_harness_build_failures: WARN emitted" "missing in $INDEX"
fi

summary
