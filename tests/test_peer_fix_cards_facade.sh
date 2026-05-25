#!/usr/bin/env bash
# tests/test_peer_fix_cards_facade.sh — pin ROOT resolution inside a
# benchmark-cell-style facade for bin/peer-fix-cards.
#
# peer-fix-cards reads ROOT/output/<slug>/target.toml every audit
# iteration. With Path(__file__).resolve() the bin/ symlink in the cell
# facade was chased, ROOT collapsed to the real tree, and the tool
# silently logged "target.toml not found" every loop — bin/audit's
# soft-fail handler masked it. Two guards:
#   1. .absolute() (not .resolve()) in the file-based ROOT fallback so
#      the symlink isn't chased.
#   2. bin/audit exports SCRIPT_ROOT so the env-override branch in
#      peer-fix-cards actually kicks in for real audit runs.
# This test exercises both branches.

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

trap 'teardown_test_env' EXIT

# ─── Build a benchmark-cell-style facade ───────────────────────────────
FACADE="$TEST_TMPDIR/facade"
mkdir -p "$FACADE"
for name in bin lib .agents docs schema targets; do
  [ -e "$SCRIPT_ROOT/$name" ] && ln -s "$SCRIPT_ROOT/$name" "$FACADE/$name"
done

# Unique slug → guaranteed to not exist in the real tree, so a wrongly
# resolved ROOT (= real tree) would always 404 on target.toml.
SLUG="pfc-facade-$$-$RANDOM"
FACADE_SLUG_DIR="$FACADE/output/$SLUG"
RESULTS="$FACADE_SLUG_DIR/backend/results"
mkdir -p "$FACADE_SLUG_DIR" "$RESULTS"

# Stub target tree so workqueue.context_from_args has a real path to
# realpath() against.
SRC="$TEST_TMPDIR/fake-src"
mkdir -p "$SRC/.git"

# target.toml with NO [s6_peers] section: peer-fix-cards exits early
# with rc=0 after writing an empty JSONL (no OSV/LLM calls). The point
# of the test is which target.toml gets *read*, not what the LLM does.
cat > "$FACADE_SLUG_DIR/target.toml" <<EOF
slug = "$SLUG"
upstream_url = "https://example.com/facade-cell-url"
build_system = "cmake"
pinned_rev = "facadebeef"
includes = []
link_libs = []
is_browser = "0"

[threat_model]
attacker_controls = ["bytes"]
EOF

# ─── Branch 1: file-based ROOT (no SCRIPT_ROOT env) ────────────────────
# bin/peer-fix-cards must read the facade-local target.toml via
# Path(__file__).absolute().parent.parent, not chase the symlink.
( cd "$FACADE" && env -u SCRIPT_ROOT \
    TARGET_ROOT="$SRC" \
    TARGET_SLUG="$SLUG" \
    "$FACADE/bin/peer-fix-cards" \
      --target-path "$SRC" \
      --target-slug "$SLUG" \
      --results-dir "$RESULTS" \
      --output "$RESULTS/s6-peer-cards.jsonl" \
) > "$TEST_TMPDIR/pfc-file.out" 2> "$TEST_TMPDIR/pfc-file.err"
pfc_file_rc=$?

if [ "$pfc_file_rc" -eq 0 ]; then
  pass "peer-fix-cards (file-based ROOT) exits 0"
else
  fail "peer-fix-cards (file-based ROOT) exits 0" \
       "rc=$pfc_file_rc err=$(tail -c 600 "$TEST_TMPDIR/pfc-file.err")"
  summary
  exit 1
fi

# The "no peers configured" message references the toml peer-fix-cards
# actually loaded. If ROOT chased the symlink, this would be the real
# tree's path (and the file wouldn't exist → rc=1, caught above). On a
# correct ROOT it must reference the facade path.
# The "no peers configured" message references the toml peer-fix-cards
# actually loaded. Match by the unique SLUG (path normalization on macOS
# collapses TEST_TMPDIR's // into /, so don't lock to a full prefix).
# If ROOT had chased the symlink we would have either gotten "not found"
# (caught above) or a SCRIPT_ROOT-rooted path with no $SLUG component.
assert_file_contains "$TEST_TMPDIR/pfc-file.err" "facade/output/$SLUG/target.toml" \
  "file-based ROOT: peer-fix-cards read facade-local target.toml"
assert_file_not_contains "$TEST_TMPDIR/pfc-file.err" 'target.toml not found' \
  "file-based ROOT: peer-fix-cards did NOT 404 on target.toml"
assert_file_exists "$RESULTS/s6-peer-cards.jsonl" \
  "file-based ROOT: empty JSONL written for downstream callers"

# ─── Branch 2: SCRIPT_ROOT env wins ────────────────────────────────────
# bin/audit now exports SCRIPT_ROOT; peer-fix-cards must honor it.
# Point SCRIPT_ROOT at the facade explicitly and confirm the right
# target.toml is still read.
rm -f "$RESULTS/s6-peer-cards.jsonl"
( cd "$FACADE" && env \
    SCRIPT_ROOT="$FACADE" \
    TARGET_ROOT="$SRC" \
    TARGET_SLUG="$SLUG" \
    "$FACADE/bin/peer-fix-cards" \
      --target-path "$SRC" \
      --target-slug "$SLUG" \
      --results-dir "$RESULTS" \
      --output "$RESULTS/s6-peer-cards.jsonl" \
) > "$TEST_TMPDIR/pfc-env.out" 2> "$TEST_TMPDIR/pfc-env.err"
pfc_env_rc=$?

if [ "$pfc_env_rc" -eq 0 ]; then
  pass "peer-fix-cards (SCRIPT_ROOT env) exits 0"
else
  fail "peer-fix-cards (SCRIPT_ROOT env) exits 0" \
       "rc=$pfc_env_rc err=$(tail -c 600 "$TEST_TMPDIR/pfc-env.err")"
  summary
  exit 1
fi
assert_file_contains "$TEST_TMPDIR/pfc-env.err" "facade/output/$SLUG/target.toml" \
  "SCRIPT_ROOT env: peer-fix-cards read facade-local target.toml"
assert_file_exists "$RESULTS/s6-peer-cards.jsonl" \
  "SCRIPT_ROOT env: empty JSONL written for downstream callers"

# ─── Branch 3: bin/audit exports SCRIPT_ROOT ───────────────────────────
# Direct asserts on the audit script — if anyone reverts the export
# line, child Python tools fall back to file-based ROOT (which the
# .absolute() fix now also makes safe, but the export is the primary
# guarantee bin/audit relies on).
assert_file_contains "$SCRIPT_ROOT/bin/audit" '^export SCRIPT_ROOT$' \
  "bin/audit exports SCRIPT_ROOT so child Python tools see the facade path"

summary
