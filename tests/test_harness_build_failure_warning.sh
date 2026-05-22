#!/usr/bin/env bash
# Tests for warn_persistent_harness_build_failures (lib/triage.sh).
# Verifies the audit emits a single user-facing WARN to index.log
# once cached harness build failures cross the configured threshold,
# and includes a link to the most recent build log.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/triage.sh"

export BUILD_FAILURE_WARN_THRESHOLD=3

mkdir -p "$RESULTS_DIR/scratch-1/.harness-cache" \
         "$RESULTS_DIR/scratch-2/.harness-cache"

# ═══════════════════════════════════════════════════════════════
# 1. Below threshold → silent
# ═══════════════════════════════════════════════════════════════

cat > "$RESULTS_DIR/scratch-1/.harness-cache/foo.deadbeef.build.log" <<'EOF'
foo.c:1:10: error: missing header
EOF
cat > "$RESULTS_DIR/scratch-1/.harness-cache/bar.cafebabe.build.log" <<'EOF'
bar.c:5:1: error: undefined reference
EOF

warn_persistent_harness_build_failures
if grep -q "persistent harness build failures" "$INDEX" 2>/dev/null; then
  fail "below-threshold: no warn emitted" "WARN found in index.log"
else
  pass "below-threshold: no warn emitted"
fi

# ═══════════════════════════════════════════════════════════════
# 2. At threshold → warn with most-recent log path
# ═══════════════════════════════════════════════════════════════

# Use sleep to guarantee a strictly newer mtime than the earlier logs.
sleep 1
latest="$RESULTS_DIR/scratch-2/.harness-cache/baz.feedface.build.log"
cat > "$latest" <<'EOF'
baz.c:10:5: error: redefinition of 'timeval'
ld: symbol(s) not found for architecture arm64
EOF

warn_persistent_harness_build_failures
if grep -q "persistent harness build failures — 3 cached log" "$INDEX" 2>/dev/null; then
  pass "at-threshold: warn emitted with count"
else
  fail "at-threshold: warn emitted with count" "missing or wrong count in $INDEX"
fi
if grep -qF "most recent failure: $latest" "$INDEX" 2>/dev/null; then
  pass "warn includes link to most recent log"
else
  fail "warn includes link to most recent log" "missing path in $INDEX"
fi
if grep -q "redefinition of 'timeval'" "$INDEX" 2>/dev/null; then
  pass "warn includes a digest of the latest log"
else
  fail "warn includes a digest of the latest log" "missing digest"
fi
if grep -q "edit .*target.toml" "$INDEX" 2>/dev/null; then
  pass "warn tells operator/LLM to edit target.toml"
else
  fail "warn tells operator/LLM to edit target.toml" "missing hint"
fi

# ═══════════════════════════════════════════════════════════════
# 3. Re-running with same count → no duplicate warn
# ═══════════════════════════════════════════════════════════════

prev_warn_count=$(grep -c "persistent harness build failures" "$INDEX" 2>/dev/null || echo 0)
warn_persistent_harness_build_failures
new_warn_count=$(grep -c "persistent harness build failures" "$INDEX" 2>/dev/null || echo 0)
assert_eq "$prev_warn_count" "$new_warn_count" "same-count: not re-emitted"

# ═══════════════════════════════════════════════════════════════
# 4. Crossing next threshold band → warn again
# ═══════════════════════════════════════════════════════════════

# Add 3 more logs to push total to 6 (next band at 2 * threshold).
for n in 1 2 3; do
  cat > "$RESULTS_DIR/scratch-1/.harness-cache/extra${n}.$(printf %08x $n).build.log" <<EOF
extra${n}.c:1:1: error: another failure
EOF
done

warn_persistent_harness_build_failures
new_count=$(grep -c "persistent harness build failures" "$INDEX" 2>/dev/null || echo 0)
if [ "$new_count" -gt "$prev_warn_count" ]; then
  pass "next-band: warn re-emitted"
else
  fail "next-band: warn re-emitted" "expected $new_count > $prev_warn_count"
fi

summary
