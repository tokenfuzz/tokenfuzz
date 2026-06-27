#!/usr/bin/env bash
# tests/test_crash_bundle.sh — Unit tests for lib/crash_bundle.sh, the helper
# bin/probe calls to materialize a maintainer-facing crash bundle the instant a
# sanitizer diagnostic is confirmed.
#
# Coverage:
#   1. A confirmed crash materializes CRASH-001-<agent> with report.md +
#      sanitizer.txt + the reproducer (the product invariant: never strand a
#      confirmed reproducer in scratch).
#   2. report.md carries the bare-label gate fields the triager parses.
#   3. Re-probing the SAME probe (same testcase + sanitizer + mode) reuses the
#      bundle (DUP), never spawns a duplicate (precision-safe).
#   4. A DISTINCT reproducer always gets its own next slot (recall-safe).
#   5. Per-agent slot numbering is independent across agents.
#   6. The harness source is copied in when supplied.
#   7. The SAME testcase bytes under a DIFFERENT sanitizer/mode is a distinct
#      crash and gets its own bundle — execution identity, not bytes alone.

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/platform.sh"
source "$SCRIPT_ROOT/lib/crash_bundle.sh"

setup_test_env

# ── 0. auto-file policy gate: only confirmed sanitizer crashes ─────
# A single exploratory run (ASAN_RUNS=1) must not auto-file; runner mode never
# files crash bundles; a multi-run (--confirm) sanitizer crash does.
crash_bundle_should_file CRASH asan 5  && pass "gate: confirmed asan crash files"        || fail "gate: confirmed asan crash files"
crash_bundle_should_file CRASH asan 1  && fail "gate: one-run crash must NOT auto-file"   || pass "gate: one-run crash must NOT auto-file"
crash_bundle_should_file CLEAN asan 5  && fail "gate: non-crash verdict must NOT file"    || pass "gate: non-crash verdict must NOT file"
crash_bundle_should_file CRASH runner 5 && fail "gate: runner/findings-only must NOT file" || pass "gate: runner/findings-only must NOT file"
crash_bundle_should_file CRASH asan ""  && fail "gate: missing run count must NOT file"   || pass "gate: missing run count must NOT file"

CRASHES="$RESULTS_DIR/crashes"
mk_scratch() { mkdir -p "$RESULTS_DIR/scratch-$1"; }

# A realistic ASan heap-use-after-free trace — neutral placeholder symbols.
write_uaf() {
  cat > "$1" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010
READ of size 4 at 0x602000000010 thread T0
    #0 0x100 in app_consume child.c:91
    #1 0x200 in main harness.c:12
SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in app_consume
EOF
}

# ── 1. confirmed crash materializes a bundle ───────────────────────
mk_scratch 1
tc="$RESULTS_DIR/scratch-1/H-aaaa_reuse.txt"
san="$RESULTS_DIR/scratch-1/H-aaaa_reuse.asan.txt"
printf '// TARGET: child.c:app_consume:91\nreuse-after-free\n' > "$tc"
write_uaf "$san"

out=$(crash_bundle_materialize --results-dir "$RESULTS_DIR" --agent 1 \
  --testcase "$tc" --sanitizer "$san" --san-name asan --mode generic \
  --target "child.c:app_consume:91" \
  --hyp "H-aaaa" --card "WORK-1" --strategy "S5")
rc=$?
assert_eq 0 "$rc" "materialize returns 0 on success"
assert_eq "FILED CRASH-001-1" "$out" "first crash files CRASH-001-1"
assert_dir_exists "$CRASHES/CRASH-001-1" "bundle dir created"
assert_file_exists "$CRASHES/CRASH-001-1/report.md" "bundle has report.md"
assert_file_exists "$CRASHES/CRASH-001-1/sanitizer.txt" "bundle has canonical sanitizer.txt"
assert_file_exists "$CRASHES/CRASH-001-1/H-aaaa_reuse.txt" "bundle has the reproducer"
assert_file_contains "$CRASHES/CRASH-001-1/sanitizer.txt" "heap-use-after-free" \
  "sanitizer.txt carries the real trace (clears triage KEEP short-circuit)"

# ── 2. report.md carries the gate fields the triager parses ────────
for field in "Boundary:" "Caller controls:" "Trusted caller actions:" \
             "Caller contract:" "Trigger source:" "Strategy: S5"; do
  assert_file_contains "$CRASHES/CRASH-001-1/report.md" "$field" \
    "report.md has bare-label field: $field"
done
assert_file_contains "$CRASHES/CRASH-001-1/report.md" "heap-use-after-free" \
  "report.md summary names the crash class"
assert_file_contains "$CRASHES/CRASH-001-1/report.md" "auto-filed by bin/probe" \
  "report.md is clearly marked as an auto-filed skeleton"

# ── 3. re-probing the SAME probe (probe then --confirm) reuses the bundle ─
out=$(crash_bundle_materialize --results-dir "$RESULTS_DIR" --agent 1 \
  --testcase "$tc" --sanitizer "$san" --san-name asan --mode generic --hyp "H-aaaa")
assert_eq "DUP CRASH-001-1" "$out" "same execution identity reuses the bundle"
count=$(find "$CRASHES" -maxdepth 1 -type d -name 'CRASH-*-1' | wc -l | tr -d ' ')
assert_eq "1" "$count" "no duplicate bundle created for same execution identity"

# ── 4. a DISTINCT reproducer gets its own next slot ────────────────
tc2="$RESULTS_DIR/scratch-1/H-bbbb_array.txt"
san2="$RESULTS_DIR/scratch-1/H-bbbb_array.asan.txt"
printf '// TARGET: child.c:app_consume:91\narray-variant-distinct\n' > "$tc2"
write_uaf "$san2"
out=$(crash_bundle_materialize --results-dir "$RESULTS_DIR" --agent 1 \
  --testcase "$tc2" --sanitizer "$san2" --hyp "H-bbbb")
assert_eq "FILED CRASH-002-1" "$out" "distinct reproducer takes the next slot"
assert_dir_exists "$CRASHES/CRASH-002-1" "distinct bundle created (recall preserved)"

# ── 5. per-agent slot numbering is independent ─────────────────────
mk_scratch 2
tc3="$RESULTS_DIR/scratch-2/H-cccc.txt"
san3="$RESULTS_DIR/scratch-2/H-cccc.asan.txt"
printf '// TARGET: child.c:app_consume:91\nagent-2-first\n' > "$tc3"
write_uaf "$san3"
out=$(crash_bundle_materialize --results-dir "$RESULTS_DIR" --agent 2 \
  --testcase "$tc3" --sanitizer "$san3" --hyp "H-cccc")
assert_eq "FILED CRASH-001-2" "$out" "agent 2 starts its own slot sequence"

# ── 6. harness source is copied in when supplied ───────────────────
harness="$RESULTS_DIR/scratch-1/harness.c"
printf 'int main(void){return 0;}\n' > "$harness"
tc4="$RESULTS_DIR/scratch-1/H-dddd.txt"
san4="$RESULTS_DIR/scratch-1/H-dddd.asan.txt"
printf '// TARGET: child.c:app_consume:91\nwith-harness\n' > "$tc4"
write_uaf "$san4"
out=$(crash_bundle_materialize --results-dir "$RESULTS_DIR" --agent 1 \
  --testcase "$tc4" --sanitizer "$san4" --harness "$harness" --hyp "H-dddd")
assert_eq "FILED CRASH-003-1" "$out" "third agent-1 crash files CRASH-003-1"
assert_file_exists "$CRASHES/CRASH-003-1/harness.c" "harness source copied into bundle"
assert_file_contains "$CRASHES/CRASH-003-1/report.md" "Harness: \`harness.c\`" \
  "report.md references the harness"

# ── 7. same testcase bytes, DIFFERENT sanitizer → distinct bundle ──
# Regression guard: keying dedup on testcase bytes alone suppressed a real
# second diagnostic (e.g. the same input crashing under UBSan as well as ASan).
# Re-file tc (filed under asan in step 1) under ubsan — it must NOT be a DUP.
out=$(crash_bundle_materialize --results-dir "$RESULTS_DIR" --agent 1 \
  --testcase "$tc" --sanitizer "$san" --san-name ubsan --mode generic --hyp "H-aaaa")
assert_eq "FILED CRASH-004-1" "$out" "same bytes under a different sanitizer is a distinct crash"
assert_dir_exists "$CRASHES/CRASH-004-1" "distinct-sanitizer bundle created (no false-dup suppression)"

teardown_test_env
summary
