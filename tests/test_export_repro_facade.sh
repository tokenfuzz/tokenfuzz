#!/usr/bin/env bash
# tests/test_export_repro_facade.sh — pin SCRIPT_ROOT resolution inside
# a benchmark-cell-style facade.
#
# bin/benchmark creates per-cell facades that symlink bin/ and lib/ into
# the real tree. If bin/export-repro resolves __file__ via .resolve(),
# SCRIPT_ROOT collapses to the real tree and the tool reads the wrong
# output/<slug>/target.toml — silently emitting URL=FILL_ME (or stale
# includes) into reproduce.sh. The fix uses .absolute() so SCRIPT_ROOT
# stays the facade. This test fails if anyone reverts that.

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

# A slug nobody else has touched, so SCRIPT_ROOT/output/<slug>/ is
# guaranteed not to exist in the real tree. That is the failure mode
# the symlink bug produced: bin/export-repro looked at the real tree,
# found nothing, and emitted FILL_ME.
SLUG="exr-facade-$$-$RANDOM"
FACADE_SLUG_DIR="$FACADE/output/$SLUG"
RESULTS="$FACADE_SLUG_DIR/backend/results"
CRASH_DIR="$RESULTS/crashes/CRASH-FACADE-1"
mkdir -p "$FACADE_SLUG_DIR" "$CRASH_DIR"

# Mock target source — reproduce.sh checks for $src/.git so the embedded
# clone is skipped at generation time. We never actually run the script
# here; we only assert on the generated content.
SRC="$TEST_TMPDIR/fake-src"
mkdir -p "$SRC/.git"

FACADE_URL="https://example.com/facade-cell-url"
cat > "$FACADE_SLUG_DIR/target.toml" <<EOF
slug = "$SLUG"
upstream_url = "$FACADE_URL"
build_system = "cmake"
pinned_rev = "facadebeef"
asan_bin = "build-asan/unused"
asan_lib = ""
includes = ["sentinel-include-only-in-facade"]
link_libs = []
is_browser = "0"

[threat_model]
attacker_controls = ["bytes"]
EOF

cat > "$RESULTS/.session-env" <<EOF
RESULTS_DIR=$RESULTS
TARGET_ROOT=$SRC
TARGET_SLUG=$SLUG
TARGET_REV=facadebeef
LOGDIR=$TEST_TMPDIR/logs
EOF

# Minimal crash dir: a harness, a testcase, an ASan log, a report.
cat > "$CRASH_DIR/harness.c" <<'EOF'
#include <stdio.h>
int main(int argc, char **argv) { (void)argc; (void)argv; return 0; }
EOF

printf 'AAAA' > "$CRASH_DIR/input.bin"

cat > "$CRASH_DIR/sanitizer.txt" <<'EOF'
ASAN_RUN_HEADER: runs=1 mode=generic testcase=output/x/scratch/x.bin started=x
=== Run 1/1 ===
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead at pc 0xface
READ of size 1 at 0xdead thread T0
    #0 0xdead in main /src/harness.c:2
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/harness.c:2 in main
CRASH_RATE: 1/1
EOF

cat > "$CRASH_DIR/report.md" <<'EOF'
# CRASH-FACADE-1

## Summary

Fixture for tests/test_export_repro_facade.sh.

Trigger source: bytes
Caller contract: obeyed
Boundary: input file
Caller controls: bytes
EOF

# ─── Invoke export-repro through the facade's symlinked bin/ ───────────
# This is the key step: __file__ inside the script becomes
# $FACADE/bin/export-repro, a symlink to $SCRIPT_ROOT/bin/export-repro.
# .resolve() would chase the symlink and break the test; .absolute()
# preserves the facade path and makes target.toml lookup land here.
( cd "$FACADE" && env \
    RESULTS_DIR="$RESULTS" \
    TARGET_ROOT="$SRC" \
    TARGET_SLUG="$SLUG" \
    TARGET_REV="facadebeef" \
    LOGDIR="$TEST_TMPDIR/logs" \
    "$FACADE/bin/export-repro" CRASH-FACADE-1 \
      --slug "$SLUG" \
      --crash-dir "$CRASH_DIR" \
) > "$TEST_TMPDIR/exr.out" 2>&1
exr_rc=$?

if [ "$exr_rc" -eq 0 ]; then
  pass "export-repro through facade exits 0"
else
  fail "export-repro through facade exits 0" \
       "rc=$exr_rc out=$(tail -c 600 "$TEST_TMPDIR/exr.out")"
  summary
  exit 1
fi

assert_file_exists "$CRASH_DIR/reproduce.sh" "facade: reproduce.sh emitted"

# The smoking gun: URL must come from the FACADE-LOCAL target.toml, not
# from a real-tree target.toml (which doesn't exist for $SLUG) and not
# from the FILL_ME default. If SCRIPT_ROOT was incorrectly resolved
# through the bin/ symlink, this assertion fails.
assert_file_contains "$CRASH_DIR/reproduce.sh" "URL=$FACADE_URL" \
  "facade: reproduce.sh URL came from facade-local target.toml"
assert_file_not_contains "$CRASH_DIR/reproduce.sh" 'URL=FILL_ME' \
  "facade: reproduce.sh URL is not the FILL_ME placeholder"

# Belt-and-suspenders: includes from the facade toml must also land in
# the script. Catches a future regression where URL is loaded by some
# different path but includes still come from the real-tree toml.
assert_file_contains "$CRASH_DIR/reproduce.sh" 'sentinel-include-only-in-facade' \
  "facade: reproduce.sh includes came from facade-local target.toml"

summary
