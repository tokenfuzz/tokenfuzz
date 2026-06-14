#!/usr/bin/env bash
# Tests for lib/quality.sh — counting helpers, quality gates,
# enforcement results directive, corpus promotion, orphan detection.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# Source the library under test (platform.sh provides audit_log helper)
source "$SCRIPT_ROOT/lib/platform.sh"
source "$SCRIPT_ROOT/lib/quality.sh"

# ═══���══════════════════════════��═════════════════════════════���══
# 1. count_verified_asan_runs — files with ASan markers
# ══════════���════════════════════════════════════════════════════

scratch="$RESULTS_DIR/scratch-1"
mkdir -p "$scratch"

# No files → 0
result=$(count_verified_asan_runs "$scratch")
assert_eq "0" "$result" "count_verified_asan_runs: empty dir → 0"

# Non-ASan txt file
echo "some random text" > "$scratch/foo.txt"
result=$(count_verified_asan_runs "$scratch")
assert_eq "0" "$result" "count_verified_asan_runs: non-ASan txt → 0"

# File with ASan header marker
echo "ASAN_RUN_HEADER: run 1 of 5" > "$scratch/test1.asan.txt"
result=$(count_verified_asan_runs "$scratch")
assert_eq "1" "$result" "count_verified_asan_runs: ASAN_RUN_HEADER → 1"

cat > "$scratch/missed.asan.txt" <<'EOF'
ASAN_RUN_HEADER: runs=1 mode=browser testcase=miss.html
COVERAGE_GATE: MISSED — ASan skipped. Revise testcase.
EOF
result=$(count_verified_asan_runs "$scratch")
assert_eq "1" "$result" "count_verified_asan_runs: coverage miss is not ASan"

# File with CRASH_RATE marker
echo "CRASH_RATE: 0/5" > "$scratch/test2.asan.txt"
result=$(count_verified_asan_runs "$scratch")
assert_eq "2" "$result" "count_verified_asan_runs: CRASH_RATE adds → 2"

# File with EXECUTION_RATE marker
echo "EXECUTION_RATE: 5/5" > "$scratch/test3.asan.txt"
result=$(count_verified_asan_runs "$scratch")
assert_eq "3" "$result" "count_verified_asan_runs: EXECUTION_RATE adds → 3"

# File with ASan error
echo "ERROR: AddressSanitizer: heap-buffer-overflow" > "$scratch/test4.asan.txt"
result=$(count_verified_asan_runs "$scratch")
assert_eq "4" "$result" "count_verified_asan_runs: ASan error adds → 4"

# File with execution verified marker
echo "[run-asan] EXECUTION VERIFIED" > "$scratch/asan_output_5.txt"
result=$(count_verified_asan_runs "$scratch")
assert_eq "5" "$result" "count_verified_asan_runs: alt filename pattern → 5"

# Non-existent dir → 0
result=$(count_verified_asan_runs "/tmp/nonexistent_dir_$$")
assert_eq "0" "$result" "count_verified_asan_runs: missing dir → 0"

# ═══════════════════════════════════════════════════════════════
# 2. count_scratch_input_files — counts non-metadata files
# ═════════════════════��═════════════════════════════════════════

input_dir="$TEST_TMPDIR/inputs"
mkdir -p "$input_dir"

result=$(count_scratch_input_files "$input_dir")
assert_eq "0" "$result" "count_scratch_input_files: empty dir → 0"

echo "<html></html>" > "$input_dir/test.html"
echo "print('test');" > "$input_dir/test.js"
echo "/a/" > "$input_dir/test.pcre2test"
printf '#!/bin/sh\nexit 0\n' > "$input_dir/reproducer"
chmod +x "$input_dir/reproducer"
echo "int main(void){return 0;}" > "$input_dir/reproducer.c"
echo "some log" > "$input_dir/output.txt"
echo "log line" > "$input_dir/debug.log"
echo "raw data" > "$input_dir/data.raw"
echo "# notes" > "$input_dir/notes.md"
mkdir -p "$input_dir/reproducer.dSYM/Contents/Resources/DWARF"
printf 'binary debug data' > "$input_dir/reproducer.dSYM/Contents/Resources/DWARF/reproducer"
touch "$input_dir/.DS_Store"

result=$(count_scratch_input_files "$input_dir")
assert_eq "4" "$result" "count_scratch_input_files: counts runnable inputs, skips source/build/debug output"

scan_asan=0; scan_tc=0; scan_orphans=0
scan_scratch_counts_load "$input_dir" scan_asan scan_tc scan_orphans
assert_eq "4" "$scan_tc" "scan_scratch_counts_load: testcase count matches standalone helper"
assert_eq "0" "$scan_asan" "scan_scratch_counts_load: ASan count from combined scan"
assert_eq "4" "$scan_orphans" "scan_scratch_counts_load: orphan count from combined scan"

assert_eq "browser" "$(testcase_mode_for_file "$input_dir/test.html")" "testcase mode: html → browser"
assert_eq "js" "$(testcase_mode_for_file "$input_dir/test.js")" "testcase mode: js → js"
assert_eq "generic" "$(testcase_mode_for_file "$input_dir/test.pcre2test")" "testcase mode: pcre2test → generic"
assert_eq "generic" "$(testcase_mode_for_file "$input_dir/reproducer")" "testcase mode: executable → generic"
if testcase_mode_for_file "$input_dir/reproducer.c" >/dev/null 2>&1; then
  fail "testcase mode: c source skipped" "C source should not be auto-enforced without compile args"
else
  pass "testcase mode: c source skipped"
fi

# ════���══════════════��═══════════════════════════════��═══════════
# 3. check_agent_quality — Gate 1: Discarding without reproducing
# ═══════════════════════════════════════════════════════════════

sf1=$(state_file_path 1)
cat > "$sf1" <<'EOF'
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 2 | H2 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 3 | H3 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 4 | H4 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 5 | H5 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF
# Ensure scratch has 0 ASan runs
rm -rf "$RESULTS_DIR/scratch-1"
mkdir -p "$RESULTS_DIR/scratch-1"

result=$(check_agent_quality 1)
assert_match "REPRODUCE FIRST" "$result" "gate 1: 4 discarded + 0 ASan → REPRODUCE FIRST"

# ═════���══════════════════��══════════════════════════════════════
# 4. check_agent_quality — Gate 2: Surveying without depth
# ══════════════════════════��════════════════════════════════════

cat > "$sf1" <<'EOF'
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 2 | H2 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 3 | H3 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 4 | H4 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 5 | H5 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 6 | H6 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
EOF

result=$(check_agent_quality 1)
assert_match "DEPTH REQUIRED" "$result" "gate 2: 6 hypotheses + 0 actionable → DEPTH REQUIRED"

# ═════════��═════════════════���═══════════════════════════════════
# 5. check_agent_quality — Gate 3: Orphan testcases
# ════��═══════════���═════════════════════════════���════════════════

cat > "$sf1" <<'EOF'
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF

scratch="$RESULTS_DIR/scratch-1"
rm -rf "$scratch"
mkdir -p "$scratch"
# Create 4 testcases but only 1 ASan output → 3 orphans
echo "<html></html>" > "$scratch/test1.html"
echo "<html></html>" > "$scratch/test2.html"
echo "<html></html>" > "$scratch/test3.html"
echo "<html></html>" > "$scratch/test4.html"
echo "ASAN_RUN_HEADER: run 1" > "$scratch/test1.asan.txt"

result=$(check_agent_quality 1)
assert_match "ORPHAN GATE" "$result" "gate 3: 3 orphan testcases → ORPHAN GATE"

orphan_count=$(count_orphan_testcases "$scratch")
assert_eq "3" "$orphan_count" "count_orphan_testcases: exact sibling matching"

quality_src=$(declare -f check_agent_quality)
assert_match "scan_scratch_counts_load" "$quality_src" "check_agent_quality: uses combined scratch scan"
assert_not_match "count_verified_asan_runs" "$quality_src" "check_agent_quality: avoids standalone ASan scan"
assert_not_match "count_scratch_input_files" "$quality_src" "check_agent_quality: avoids standalone testcase scan"
assert_not_match "count_orphan_testcases" "$quality_src" "check_agent_quality: avoids standalone orphan scan"

# ═══════════════════════════════════════════════════════════════
# 6. check_agent_quality — Gate 4: Zero-ASan gate for reproduce agent
# ═══���═══════════════════���═══════════════════════════════════��═══

cat > "$sf1" <<'EOF'
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF
rm -rf "$scratch"
mkdir -p "$scratch"

echo "0" > "$LOGDIR/.prev_asan_runs_1"

result=$(check_agent_quality 1)
assert_match "ZERO-ASAN GATE" "$result" "gate 4: reproduce agent + 0 prior ASan → ZERO-ASAN GATE"
rm -f "$LOGDIR/.prev_asan_runs_1"

# ════════��══════════════��═════════════════════════════════���═════
# 7. check_agent_quality — Gate 5: NO_EXEC epidemic
# ═════��═══════════════════════��════════════════════��════════════

cat > "$sf1" <<'EOF'
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF

tried_log=$(tried_inputs_log_path 1)
{
  for i in $(seq 1 8); do echo "2026-04-27T10:00:00Z verdict=NO_EXEC mode=js testcase=t$i.js"; done
  echo "2026-04-27T10:00:00Z verdict=HIT mode=js testcase=t9.js"
  echo "2026-04-27T10:00:00Z verdict=CLEAN mode=js testcase=t10.js"
} > "$tried_log"

result=$(check_agent_quality 1)
assert_match "NO_EXEC ALERT" "$result" "gate 5: 80% NO_EXEC → NO_EXEC ALERT"
assert_match "8/10" "$result" "gate 5: shows NO_EXEC count/total"

# ��═══════════��══════════════════════════════════���═══════════════
# 8. check_agent_quality — no gates triggered
# ═══��═══════════════════════════════════════════════════════════

cat > "$sf1" <<'EOF'
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | PENDING |
| 2 | H2 | f.cpp | shape | guard | bounds | S1 | INVESTIGATING |
EOF
rm -rf "$scratch"
mkdir -p "$scratch"
echo "ASAN_RUN_HEADER: run 1" > "$scratch/test1.asan.txt"
echo "<html></html>" > "$scratch/test1.html"
rm -f "$tried_log" "$LOGDIR/.prev_asan_runs_1"

result=$(check_agent_quality 1)
assert_not_match "REPRODUCE FIRST" "$result" "clean agent: no REPRODUCE FIRST"
assert_not_match "DEPTH REQUIRED" "$result" "clean agent: no DEPTH REQUIRED"
assert_not_match "ORPHAN GATE" "$result" "clean agent: no ORPHAN GATE"
assert_not_match "ZERO-ASAN GATE" "$result" "clean agent: no ZERO-ASAN GATE"
assert_not_match "NO_EXEC ALERT" "$result" "clean agent: no NO_EXEC ALERT"
assert_match "Stats:" "$result" "clean agent: still shows stats line"

# ═���═════════════════════════════════════════════════════════════
# 9. build_enforcement_results_directive — crash results
# ═════════���════════════════════��════════════════════════════════

results_file="$RESULTS_DIR/.enforcement_results_1"
cat > "$results_file" <<'EOF'
- **CRASH** `test1.html` → heap-buffer-overflow
- CLEAN `test2.html` — executed without sanitizer diagnostic
- NO_EXEC `test3.js` — testcase did not execute
EOF

result=$(build_enforcement_results_directive 1)
assert_match "ENFORCEMENT RESULTS.*INVESTIGATE CRASHES" "$result" "enforcement: crash results shown"
assert_match "1 crashed" "$result" "enforcement: crash count correct"
assert_match "heap-buffer-overflow" "$result" "enforcement: crash class shown"

# ════════════════════════════════════════════════════════���══════
# 10. build_enforcement_results_directive — all clean
# ═��════════════════════���════════════════════════════════════════

cat > "$results_file" <<'EOF'
- CLEAN `test1.html` — executed without sanitizer diagnostic
- CLEAN `test2.js` — executed without sanitizer diagnostic
EOF

result=$(build_enforcement_results_directive 1)
assert_match "all clean" "$result" "enforcement: all-clean message"
assert_not_match "INVESTIGATE CRASHES" "$result" "enforcement: no crash investigation prompt"

# ═══════════════════════════════════════════════════════════════
# 11. build_enforcement_results_directive — no results file
# ═══════════════════════════════════════════════════════════════

rm -f "$results_file"
result=$(build_enforcement_results_directive 1)
assert_eq "" "$result" "enforcement: no results file → empty"

# ════���════════════════════════════════��═════════════════════════
# 12. build_enforcement_results_directive — empty results file
# ═══════════════════════════════════════════════════════════════

: > "$results_file"
result=$(build_enforcement_results_directive 1)
assert_eq "" "$result" "enforcement: empty results file → empty"

# ═════���═══════════════════════════════════════���═════════════════
# 13. warn_orphan_testcases — emits warning for orphan TCs
# ═��══════════════════════���══════════════════════════════════════

scratch="$RESULTS_DIR/scratch-1"
rm -rf "$scratch"
mkdir -p "$scratch"
echo "<html></html>" > "$scratch/test1.html"
echo "<html></html>" > "$scratch/test2.html"

result=$(warn_orphan_testcases 2>&1)
assert_match "WARN.*agent 1.*orphan" "$result" "warn: detects orphan testcases"

# ═════════════════════════��════════════════════════════════���════
# 14. warn_orphan_testcases — no warning when ASan outputs exist
# ══════════��══════════════��═════════════════════════════════════

echo "ASAN_RUN_HEADER: run 1" > "$scratch/test1.asan.txt"
echo "ASAN_RUN_HEADER: run 1" > "$scratch/test2.asan.txt"

result=$(warn_orphan_testcases 2>&1)
assert_not_match "orphan" "$result" "warn: no warning when ASan outputs present"

echo "<html></html>" > "$scratch/test3.html"
cat > "$scratch/test3.asan.txt" <<'EOF'
ASAN_RUN_HEADER: runs=1 mode=browser testcase=test3.html
COVERAGE_GATE: MISSED — ASan skipped. Revise testcase.
EOF
if testcase_has_verified_asan_output "$scratch/test3.html"; then
  fail "testcase_has_verified_asan_output: coverage miss rejected" "coverage miss should not count as verified ASan"
else
  pass "testcase_has_verified_asan_output: coverage miss rejected"
fi

# ═══════════════════════════════════════════════════════════════
# 14b. enforce_asan_for_orphans — uses ASAN_OUTPUT_FILE and valid modes
# ═══════════════════════════════════════════════════════════════

scratch="$RESULTS_DIR/scratch-1"
rm -rf "$scratch"
mkdir -p "$scratch"
echo "/a/" > "$scratch/sample.pcre2test"
fake_asan="$TEST_TMPDIR/fake-run-asan-multi"
cat > "$fake_asan" <<'EOF'
#!/usr/bin/env bash
mode="$1"
tc="$2"
if [ -z "${ASAN_OUTPUT_FILE:-}" ]; then
  echo "missing ASAN_OUTPUT_FILE" >&2
  exit 9
fi
{
  echo "ASAN_RUN_HEADER: fake mode=$mode testcase=$tc"
  echo "EXECUTION_RATE: 1/1"
} > "$ASAN_OUTPUT_FILE"
printf 'mode=%s testcase=%s runs=%s\n' "$mode" "$tc" "${ASAN_RUNS:-}" >> "${ASAN_OUTPUT_FILE}.seen"
EOF
chmod +x "$fake_asan"
ASAN_5X_BIN="$fake_asan" ASAN_AUTOENFORCE_MAX=1 ASAN_AUTOENFORCE_RUNS=1 enforce_asan_for_orphans >/dev/null
unset ASAN_5X_BIN ASAN_AUTOENFORCE_MAX ASAN_AUTOENFORCE_RUNS

assert_file_contains "$scratch/sample.asan.txt" "ASAN_RUN_HEADER" "enforce: writes verified ASan output file"
assert_file_contains "$scratch/sample.asan.txt.seen" "mode=generic" "enforce: pcre2test runs in generic mode"
assert_file_exists "$scratch/sample.enforced" "enforce: marker only after verified output"

scratch="$RESULTS_DIR/scratch-1"
rm -rf "$scratch"
mkdir -p "$scratch"
echo 'console.log("TESTCASE_EXECUTED")' > "$scratch/repro.js"
rm -f "$scratch/repro.asan.txt.seen"
TARGET_IS_BROWSER=0 ASAN_5X_BIN="$fake_asan" ASAN_AUTOENFORCE_MAX=1 ASAN_AUTOENFORCE_RUNS=1 enforce_asan_for_orphans >/dev/null
unset TARGET_IS_BROWSER ASAN_5X_BIN ASAN_AUTOENFORCE_MAX ASAN_AUTOENFORCE_RUNS

assert_file_contains "$scratch/repro.asan.txt.seen" "mode=generic" "enforce: non-browser .js routes through generic runner"

# ═════��═════════════════���═══════════════════════════════════���═══
# 15. check_agent_quality — Gate 5 threshold: 39% NO_EXEC → no alert
# ═══════��══════════════════════��════════════════════════════════

cat > "$sf1" <<'EOF'
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF
rm -rf "$RESULTS_DIR/scratch-1"
mkdir -p "$RESULTS_DIR/scratch-1"

tried_log=$(tried_inputs_log_path 1)
{
  for i in $(seq 1 6); do echo "2026-04-27 verdict=NO_EXEC mode=js testcase=t$i.js"; done
  for i in $(seq 7 16); do echo "2026-04-27 verdict=CLEAN mode=js testcase=t$i.js"; done
} > "$tried_log"

result=$(check_agent_quality 1)
assert_not_match "NO_EXEC ALERT" "$result" "gate 5 boundary: 6/16=37% → no alert (threshold 40%)"

# ═════���═════════════���═══════════════════════════════════════════
# 16. check_agent_quality — Gate 1 boundary: exactly 3 discards → no gate
# ══════════════════════���════════════════════════════════════════

rm -f "$tried_log"
cat > "$sf1" <<'EOF'
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 2 | H2 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 3 | H3 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 4 | H4 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF

result=$(check_agent_quality 1)
assert_not_match "REPRODUCE FIRST" "$result" "gate 1 boundary: 3 discards → no gate (needs >3)"

# ═══════════════════════════════════════════════════════��═══════
# 17. check_agent_quality — Gate 1 passes with adequate ASan runs
# ════════════════════════════════════════════════���══════════════

cat > "$sf1" <<'EOF'
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 2 | H2 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 3 | H3 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 4 | H4 | f.cpp | shape | guard | bounds | S1 | DISCARDED |
| 5 | H5 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF
scratch="$RESULTS_DIR/scratch-1"
rm -rf "$scratch"
mkdir -p "$scratch"
echo "ASAN_RUN_HEADER: run 1" > "$scratch/test1.asan.txt"
echo "ASAN_RUN_HEADER: run 2" > "$scratch/test2.asan.txt"

result=$(check_agent_quality 1)
assert_not_match "REPRODUCE FIRST" "$result" "gate 1: 4 discards + 2 ASan runs → no gate"

# ═════════════════════════��═════════════════════════════��═══════
# 18. snapshot_quality_feedback — writes cache files
# ══════════���══════════════════════════════════════���═════════════

cat > "$sf1" <<'EOF'
| 1 | H1 | f.cpp | shape | guard | bounds | S1 | PENDING |
EOF
cat > "$(state_file_path 2)" <<'EOF'
| 1 | H1 | g.cpp | shape | guard | bounds | S2 | PENDING |
EOF

snapshot_quality_feedback
assert_file_exists "$(quality_feedback_path 1)" "snapshot: cache file for agent 1 created"
assert_file_exists "$(quality_feedback_path 2)" "snapshot: cache file for agent 2 created"
assert_file_contains "$(quality_feedback_path 1)" "Stats:" "snapshot: agent 1 has stats"

# ═══════════════════════════════════════════════════════════════
# 19. Gate 1 + Gate 2 interaction — both fire simultaneously
# ═══════════════════════════════════════════════════════════════

{
  echo "## Primary Subsystem: dom/canvas"
  for i in $(seq 1 6); do
    echo "| $i | H$i | dom/canvas/F$i.cpp | shape | guard | bounds | A | DISCARDED |"
  done
} > "$sf1"
rm -rf "$RESULTS_DIR/scratch-1"; mkdir -p "$RESULTS_DIR/scratch-1"

result=$(check_agent_quality 1)
assert_match "REPRODUCE FIRST" "$result" "gate1+2: REPRODUCE FIRST fires"
assert_match "DEPTH REQUIRED" "$result" "gate1+2: DEPTH REQUIRED also fires"

# ═══════════════════════════════════════════════════════════════
# 20. Gate 2 not triggered when INVESTIGATING present
# ═══════════════════════════════════════════════════════════════

{
  echo "## Primary Subsystem: dom/canvas"
  for i in $(seq 1 5); do
    echo "| $i | H$i | dom/canvas/F$i.cpp | shape | guard | bounds | A | DISCARDED |"
  done
  echo "| 6 | H6 | dom/canvas/G.cpp | shape | guard | bounds | A | INVESTIGATING |"
} > "$sf1"
rm -rf "$RESULTS_DIR/scratch-1"; mkdir -p "$RESULTS_DIR/scratch-1"

result=$(check_agent_quality 1)
assert_not_match "DEPTH REQUIRED" "$result" "gate2: not triggered with INVESTIGATING present"

# ═══════════════════════════════════════════════════════════════
# 21. Gate 4 only fires for reproduce role (not analysis)
# ═══════════════════════════════════════════════════════════════

cat > "$(state_file_path 2)" <<'EOF'
## Primary Subsystem: js/src/jit
| 1 | H1 | js/src/jit/Foo.cpp | shape | guard | bounds | A | PENDING |
EOF
rm -rf "$(scratch_dir_path 2)"; mkdir -p "$(scratch_dir_path 2)"
echo "0" > "$LOGDIR/.prev_asan_runs_2"

result=$(check_agent_quality 2)
assert_not_match "ZERO-ASAN GATE" "$result" "gate4: not triggered for analysis role"

rm -f "$LOGDIR/.prev_asan_runs_2"

teardown_test_env
summary
