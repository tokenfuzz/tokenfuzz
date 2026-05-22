#!/usr/bin/env bash
# Integration tests — bin/run-asan-multi wrapper (mocked run-asan)
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# ═══════════════════════════════════════════════════════════════
# Mock bin/run-asan to simulate crash / clean / no-exec outcomes
# ═══════════════════════════════════════════════════════════════

MOCK_BIN="$TEST_TMPDIR/mock-bin"
mkdir -p "$MOCK_BIN"

# Default: clean execution
cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
case "${MOCK_ASAN_BEHAVIOR:-clean}" in
  crash)
    echo "==12345==ERROR: AddressSanitizer: heap-buffer-overflow"
    echo "[run-asan] CRASH DETECTED: ASan error found"
    ;;
  noexec)
    echo "[run-asan] WARNING: no crash and no execution evidence"
    ;;
  *)
    echo "TESTCASE_EXECUTED"
    echo "[run-asan] browser EXECUTION VERIFIED (post-run, marker=TESTCASE_EXECUTED)"
    ;;
esac
MOCK
chmod +x "$MOCK_BIN/run-asan"

# Stub hits script (coverage gate) — default to HIT
cat > "$MOCK_BIN/hits" <<'MOCK'
#!/bin/bash
echo "HIT: mock_function"
exit 0
MOCK
chmod +x "$MOCK_BIN/hits"

# Copy run-asan-multi into the mock bin so $SCRIPT_DIR resolves to $MOCK_BIN,
# which is where our mock run-asan lives.
cp "$SCRIPT_ROOT/bin/run-asan-multi" "$MOCK_BIN/run-asan-multi"
chmod +x "$MOCK_BIN/run-asan-multi"
RUN_5X="$MOCK_BIN/run-asan-multi"

# Create a dummy testcase
echo "<html><body>test</body></html>" > "$TEST_TMPDIR/tc.html"

# ═══════════════════════════════════════════════════════════════
# 1. Clean runs — CRASH_RATE: 0/N, EXECUTION_RATE: N/N
# ═══════════════════════════════════════════════════════════════

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out1.asan.txt"
export MOCK_ASAN_BEHAVIOR="clean"
export PATH="$MOCK_BIN:$PATH"
export ASAN_RUNS=3
unset WANT SKIP_COVERAGE_GATE ASAN_RUN_COUNTER_FILE TRIED_INPUTS_LOG SKIP_AUTO_DIFF
export ASAN_OUTPUT_FILE_OPTIONAL=1

output=$(ASAN_RUNS=3 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1)
assert_match "CRASH_RATE: 0/3" "$output" "clean: CRASH_RATE 0/3"
assert_match "EXECUTION_RATE: 3/3" "$output" "clean: EXECUTION_RATE 3/3"
assert_match "NO CRASHES" "$output" "clean: summary says no crashes"

# ═══════════════════════════════════════════════════════════════
# 1b. Coverage gate only skips ASan for a real MISS; env/exec failures
#     proceed ungated so coverage problems cannot hide sanitizer findings.
# ═══════════════════════════════════════════════════════════════

cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
echo "TESTCASE_EXECUTED"
echo "[run-asan] browser EXECUTION VERIFIED (post-run, marker=TESTCASE_EXECUTED)"
MOCK
chmod +x "$MOCK_BIN/run-asan"

cat > "$MOCK_BIN/hits" <<'MOCK'
#!/bin/bash
echo "MISSED — closest reached: Mock::near_target"
exit 1
MOCK
chmod +x "$MOCK_BIN/hits"

export WANT="Mock::target"
export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out_cov_miss.asan.txt"
output=$(ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1)
rc=$?
assert_eq "1" "$rc" "coverage miss: exits with no-hit status"
assert_match "COVERAGE GATE: MISSED" "$output" "coverage miss: reports missed gate"
assert_not_match "TESTCASE_EXECUTED" "$output" "coverage miss: ASan not run"
assert_file_contains "$ASAN_OUTPUT_FILE" "COVERAGE_GATE: MISSED" "coverage miss: marker written"

cat > "$MOCK_BIN/hits" <<'MOCK'
#!/bin/bash
echo "NO_COVERAGE: sancov data missing"
exit 2
MOCK
chmod +x "$MOCK_BIN/hits"

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out_cov_env_fail.asan.txt"
output=$(ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1)
rc=$?
assert_eq "0" "$rc" "coverage env fail: ASan result decides exit"
assert_match "COVERAGE GATE: COVERAGE_ENV_FAIL" "$output" "coverage env fail: distinct marker"
assert_match "TESTCASE_EXECUTED" "$output" "coverage env fail: ASan still runs"
assert_file_contains "$ASAN_OUTPUT_FILE" "COVERAGE_GATE: COVERAGE_ENV_FAIL" "coverage env fail: marker written"

cat > "$MOCK_BIN/hits" <<'MOCK'
#!/bin/bash
echo "EXEC_FAIL: coverage browser failed"
exit 3
MOCK
chmod +x "$MOCK_BIN/hits"

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out_cov_exec_fail.asan.txt"
output=$(ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1)
rc=$?
assert_eq "0" "$rc" "coverage exec fail: ASan result decides exit"
assert_match "COVERAGE GATE: COVERAGE_EXEC_FAIL" "$output" "coverage exec fail: distinct marker"
assert_match "TESTCASE_EXECUTED" "$output" "coverage exec fail: ASan still runs"
assert_file_contains "$ASAN_OUTPUT_FILE" "COVERAGE_GATE: COVERAGE_EXEC_FAIL" "coverage exec fail: marker written"

cat > "$MOCK_BIN/hits" <<'MOCK'
#!/bin/bash
echo "HIT: mock_function"
exit 0
MOCK
chmod +x "$MOCK_BIN/hits"

cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
case "${MOCK_ASAN_BEHAVIOR:-clean}" in
  crash)
    echo "==12345==ERROR: AddressSanitizer: heap-buffer-overflow"
    echo "[run-asan] CRASH DETECTED: ASan error found"
    ;;
  noexec)
    echo "[run-asan] WARNING: no crash and no execution evidence"
    ;;
  *)
    echo "TESTCASE_EXECUTED"
    echo "[run-asan] browser EXECUTION VERIFIED (post-run, marker=TESTCASE_EXECUTED)"
    ;;
esac
MOCK
chmod +x "$MOCK_BIN/run-asan"
unset WANT

# ═══════════════════════════════════════════════════════════════
# 2. Crash runs — CRASH_RATE: N/N
# ═══════════════════════════════════════════════════════════════

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out2.asan.txt"
export MOCK_ASAN_BEHAVIOR="crash"

output=$(ASAN_RUNS=2 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1)
assert_match "CRASH_RATE: 2/2" "$output" "crash: CRASH_RATE 2/2"
assert_match "CRASHES FOUND" "$output" "crash: summary reports crashes"

# ═══════════════════════════════════════════════════════════════
# 3. No-exec runs — EXECUTION_RATE: 0/N, warning
# ═══════════════════════════════════════════════════════════════

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out3.asan.txt"
export MOCK_ASAN_BEHAVIOR="noexec"

output=$(ASAN_RUNS=2 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1)
assert_match "EXECUTION_RATE: 0/2" "$output" "noexec: EXECUTION_RATE 0/2"
assert_match "may not have executed" "$output" "noexec: warning shown"

# Raw testcase self-reporting is not enough; only wrapper-issued post-run
# markers count as execution evidence.
cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
echo "TESTCASE_EXECUTED"
echo "target failed after printing its own sentinel" >&2
exit 7
MOCK
chmod +x "$MOCK_BIN/run-asan"

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out3b.asan.txt"
output=$(ASAN_RUNS=1 bash "$RUN_5X" generic "$TEST_TMPDIR/tc.html" 2>&1)
assert_match "EXECUTION_RATE: 0/1" "$output" "raw sentinel: does not count as execution"
assert_match "may not have executed" "$output" "raw sentinel: warning shown"

cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
case "${MOCK_ASAN_BEHAVIOR:-clean}" in
  crash)
    echo "==12345==ERROR: AddressSanitizer: heap-buffer-overflow"
    echo "[run-asan] CRASH DETECTED: ASan error found"
    ;;
  noexec)
    echo "[run-asan] WARNING: no crash and no execution evidence"
    ;;
  *)
    echo "TESTCASE_EXECUTED"
    echo "[run-asan] browser EXECUTION VERIFIED (post-run, marker=TESTCASE_EXECUTED)"
    ;;
esac
MOCK
chmod +x "$MOCK_BIN/run-asan"

# ═══════════════════════════════════════════════════════════════
# 4. ASAN_OUTPUT_FILE gets ASAN_RUN_HEADER
# ═══════════════════════════════════════════════════════════════

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out4.asan.txt"
export MOCK_ASAN_BEHAVIOR="clean"

ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1 >/dev/null
assert_file_contains "$TEST_TMPDIR/out4.asan.txt" "ASAN_RUN_HEADER" "output file has header"
assert_file_contains "$TEST_TMPDIR/out4.asan.txt" "CRASH_RATE" "output file has crash rate"
assert_file_contains "$TEST_TMPDIR/out4.asan.txt" "EXECUTION_RATE" "output file has exec rate"

# ═══════════════════════════════════════════════════════════════
# 5. ASAN_OUTPUT_FILE auto-derives from testcase when unset
# ═══════════════════════════════════════════════════════════════

unset ASAN_OUTPUT_FILE ASAN_OUTPUT_FILE_OPTIONAL
ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" >/dev/null 2>&1 || true
assert_file_exists "$TEST_TMPDIR/tc.asan.txt" "output file derived from testcase path"

# ═══════════════════════════════════════════════════════════════
# 6. Budget accounting
# ═══════════════════════════════════════════════════════════════

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out6.asan.txt"
export ASAN_OUTPUT_FILE_OPTIONAL=1
export ASAN_RUN_COUNTER_FILE="$TEST_TMPDIR/budget_counter"
export ASAN_RUN_BUDGET=3
export MOCK_ASAN_BEHAVIOR="clean"

ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1 >/dev/null
assert_eq "1" "$(cat "$ASAN_RUN_COUNTER_FILE")" "budget: counter = 1 after first run"

ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1 >/dev/null
assert_eq "2" "$(cat "$ASAN_RUN_COUNTER_FILE")" "budget: counter = 2 after second run"

output=$(ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1)
output2=$(ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1)
assert_match "EXCEEDED" "$output2" "budget: exceeded warning at 4/3"

unset ASAN_RUN_COUNTER_FILE ASAN_RUN_BUDGET

# ═══════════════════════════════════════════════════════════════
# 6b. Input validation — missing mode and missing testcase
# ═══════════════════════════════════════════════════════════════

export ASAN_OUTPUT_FILE_OPTIONAL=1
output=$(bash "$RUN_5X" 2>&1) || true
assert_match "mode argument required" "$output" "validation: no mode argument"

output=$(ASAN_OUTPUT_FILE="$TEST_TMPDIR/val.asan.txt" bash "$RUN_5X" browser "$TEST_TMPDIR/nonexistent.html" 2>&1) || true
assert_match "testcase not found" "$output" "validation: missing testcase file"

# ═══════════════════════════════════════════════════════════════
# 7. TRIED_INPUTS_LOG written on clean and crash
# ═══════════════════════════════════════════════════════════════

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out7.asan.txt"
export TRIED_INPUTS_LOG="$TEST_TMPDIR/tried.log"
export MOCK_ASAN_BEHAVIOR="clean"
: > "$TRIED_INPUTS_LOG"

ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1 >/dev/null
assert_file_contains "$TRIED_INPUTS_LOG" "verdict=CLEAN" "tried log: CLEAN verdict"

export MOCK_ASAN_BEHAVIOR="crash"
ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1 >/dev/null
assert_file_contains "$TRIED_INPUTS_LOG" "verdict=CRASH" "tried log: CRASH verdict"

unset TRIED_INPUTS_LOG

# ═══════════════════════════════════════════════════════════════
# 8. stdout digest — drops headless/framebuffer noise; file keeps full output
# ═══════════════════════════════════════════════════════════════

cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
echo "*** You are running in headless mode."
echo "Crash Annotation GraphicsCriticalError: |[0][GFX1-]: RenderCompositorSWGL failed mapping default framebuffer, no dt (t=1.7) [GFX1-]: RenderCompositorSWGL failed mapping default framebuffer, no dt"
echo "TESTCASE_EXECUTED"
echo "[run-asan] browser EXECUTION VERIFIED (post-run, marker=TESTCASE_EXECUTED)"
MOCK
chmod +x "$MOCK_BIN/run-asan"

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out8.asan.txt"
export ASAN_OUTPUT_FILE_OPTIONAL=1
unset ASAN_NO_DIGEST

output=$(ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1)
assert_not_match "headless mode" "$output" "digest: stdout drops headless-mode noise"
assert_not_match "RenderCompositorSWGL" "$output" "digest: stdout drops framebuffer noise"
assert_match "TESTCASE_EXECUTED" "$output" "digest: stdout keeps execution signal"
assert_match "EXECUTION VERIFIED" "$output" "digest: stdout keeps verification signal"
assert_file_contains "$ASAN_OUTPUT_FILE" "headless mode" "digest: file preserves headless line"
assert_file_contains "$ASAN_OUTPUT_FILE" "RenderCompositorSWGL" "digest: file preserves framebuffer line"

# Shadow-bytes block — stdout elides, file preserves; signal lines around it stay.
cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
echo "==99==ERROR: AddressSanitizer: heap-buffer-overflow"
echo "    #0 0x123 in foo file.cpp:42"
echo "SUMMARY: AddressSanitizer: heap-buffer-overflow file.cpp:42 in foo"
echo "Shadow bytes around the buggy address:"
echo "  0x123: 00 00 fa fa"
echo "  0x124: fa fa fa fa"
echo "Shadow byte legend (one shadow byte represents 8 application bytes):"
echo "  Addressable:           00"
echo "==99==ABORTING"
echo "[run-asan] CRASH DETECTED: ASan error found"
MOCK
chmod +x "$MOCK_BIN/run-asan"

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out9.asan.txt"
output=$(ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1)
assert_match "ERROR: AddressSanitizer" "$output" "digest: stdout keeps ERROR line"
assert_match "SUMMARY: AddressSanitizer" "$output" "digest: stdout keeps SUMMARY line"
assert_match "Shadow bytes block elided" "$output" "digest: stdout shows elided marker"
assert_not_match "00 00 fa fa" "$output" "digest: stdout drops shadow hex"
assert_not_match "Shadow byte legend" "$output" "digest: stdout drops legend"
assert_match "ABORTING" "$output" "digest: stdout resumes after ABORTING"
assert_match "CRASH DETECTED" "$output" "digest: stdout keeps post-shadow crash marker"
assert_file_contains "$ASAN_OUTPUT_FILE" "00 00 fa fa" "digest: file preserves shadow hex"
assert_file_contains "$ASAN_OUTPUT_FILE" "Shadow byte legend" "digest: file preserves legend"

# Multi-crash output (halt_on_error=0 fuzz mode shape): two ERROR blocks
# separated by a "Shadow bytes" elision boundary, only one ABORTING at the
# end. Without the awk reset on the next ERROR header, the second crash is
# silently consumed by `skip { next }` until ABORTING.
cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
echo "==99==ERROR: AddressSanitizer: heap-buffer-overflow"
echo "    #0 0x123 in foo file.cpp:42"
echo "SUMMARY: AddressSanitizer: heap-buffer-overflow file.cpp:42 in foo"
echo "Shadow bytes around the buggy address:"
echo "  0x123: 00 00 fa fa"
echo "Shadow byte legend (one shadow byte represents 8 application bytes):"
echo "  Addressable:           00"
echo "================================================================="
echo "==99==ERROR: AddressSanitizer: heap-use-after-free"
echo "    #0 0x456 in bar other.cpp:88"
echo "SUMMARY: AddressSanitizer: heap-use-after-free other.cpp:88 in bar"
echo "Shadow bytes around the buggy address:"
echo "  0x456: fd fd fd fd"
echo "==99==ABORTING"
echo "[run-asan] CRASH DETECTED: ASan error found"
MOCK
chmod +x "$MOCK_BIN/run-asan"

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out9_multi.asan.txt"
output=$(ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1)
assert_match "heap-buffer-overflow" "$output" "digest multi-crash: stdout keeps first ERROR class"
assert_match "heap-use-after-free" "$output" "digest multi-crash: stdout keeps second ERROR class"
assert_match "in foo file.cpp:42" "$output" "digest multi-crash: stdout keeps first stack frame"
assert_match "in bar other.cpp:88" "$output" "digest multi-crash: stdout keeps second stack frame"
assert_match "ABORTING" "$output" "digest multi-crash: stdout still resumes at ABORTING"
# Both shadow blocks elide cleanly.
assert_not_match "00 00 fa fa" "$output" "digest multi-crash: stdout drops first shadow hex"
assert_not_match "fd fd fd fd" "$output" "digest multi-crash: stdout drops second shadow hex"

# Opt-out via ASAN_NO_DIGEST passes everything through.
export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out10.asan.txt"
export ASAN_NO_DIGEST=1
output=$(ASAN_RUNS=1 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1)
assert_match "Shadow byte legend" "$output" "digest: ASAN_NO_DIGEST disables filtering"
unset ASAN_NO_DIGEST

# ═══════════════════════════════════════════════════════════════
# 8b. Clean-run head/tail truncation — protects context from flooded
#     testcase output (e.g., printf in a tight loop). Crash runs must
#     stay full so the diagnostic isn't clipped.
# ═══════════════════════════════════════════════════════════════

# Mock that floods stdout with a clean run (no ASan markers).
cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
echo "[run-asan] generic EXECUTION VERIFIED (pre-run)"
i=1
while [ "$i" -le 600 ]; do
  echo "MIDDLE_LINE_$i parseJob"
  i=$((i + 1))
done
echo "TESTCASE_EXECUTED"
echo "[run-asan] generic EXECUTION VERIFIED (post-run, rc=0)"
MOCK
chmod +x "$MOCK_BIN/run-asan"

# Tiny head/tail so the test corpus comfortably exceeds the threshold.
export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out_trunc.asan.txt"
export ASAN_DIGEST_HEAD=10
export ASAN_DIGEST_TAIL=15
output=$(ASAN_RUNS=1 bash "$RUN_5X" generic "$TEST_TMPDIR/tc.html" 2>&1)
assert_match 'DIGEST: clean run' "$output" "digest-trunc: stdout shows elision marker"
assert_match 'middle line\(s\) elided' "$output" "digest-trunc: marker reports elided count"
assert_match "$ASAN_OUTPUT_FILE" "$output" "digest-trunc: marker references full output file"
assert_match 'MIDDLE_LINE_1 parseJob' "$output" "digest-trunc: keeps head — first middle line"
assert_match 'MIDDLE_LINE_600 parseJob' "$output" "digest-trunc: keeps tail — last middle line"
assert_not_match 'MIDDLE_LINE_300 parseJob' "$output" "digest-trunc: drops middle line"
assert_match 'TESTCASE_EXECUTED' "$output" "digest-trunc: keeps execution signal in tail"
# Full file preserves every middle line — the elision is stdout-only.
assert_file_contains "$ASAN_OUTPUT_FILE" 'MIDDLE_LINE_300 parseJob' "digest-trunc: file preserves elided middle"
assert_file_contains "$ASAN_OUTPUT_FILE" 'MIDDLE_LINE_500 parseJob' "digest-trunc: file preserves more middle"

# Crash run must NOT truncate even when total > head+tail. The diagnostic
# (ERROR / SUMMARY / stack) needs to survive intact for the agent to triage.
cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
i=1
while [ "$i" -le 600 ]; do
  echo "MIDDLE_LINE_$i parseJob"
  i=$((i + 1))
done
echo "==99==ERROR: AddressSanitizer: heap-buffer-overflow"
echo "    #0 0x123 in foo file.cpp:42"
echo "SUMMARY: AddressSanitizer: heap-buffer-overflow file.cpp:42 in foo"
echo "==99==ABORTING"
echo "[run-asan] CRASH DETECTED: ASan error found"
MOCK
chmod +x "$MOCK_BIN/run-asan"

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out_trunc_crash.asan.txt"
output=$(ASAN_RUNS=1 bash "$RUN_5X" generic "$TEST_TMPDIR/tc.html" 2>&1)
assert_not_match 'DIGEST: clean run' "$output" "digest-trunc: crash run is not clipped"
assert_match 'MIDDLE_LINE_300 parseJob' "$output" "digest-trunc: crash keeps middle line"
assert_match 'ERROR: AddressSanitizer' "$output" "digest-trunc: crash keeps ERROR"
assert_match 'SUMMARY: AddressSanitizer' "$output" "digest-trunc: crash keeps SUMMARY"
unset ASAN_DIGEST_HEAD ASAN_DIGEST_TAIL

# UBSan-only diagnostic ("runtime error:") also gates the crash path so its
# trace doesn't get clipped if it happens to fall in the middle of stdout.
cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
i=1
while [ "$i" -le 600 ]; do
  echo "MIDDLE_LINE_$i parseJob"
  i=$((i + 1))
done
echo "file.cpp:42:7: runtime error: load of misaligned address 0x7f"
echo "TESTCASE_EXECUTED"
MOCK
chmod +x "$MOCK_BIN/run-asan"

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out_trunc_ubsan.asan.txt"
export ASAN_DIGEST_HEAD=10
export ASAN_DIGEST_TAIL=15
output=$(ASAN_RUNS=1 bash "$RUN_5X" generic "$TEST_TMPDIR/tc.html" 2>&1)
assert_not_match 'DIGEST: clean run' "$output" "digest-trunc: UBSan runtime-error not clipped"
assert_match 'MIDDLE_LINE_300 parseJob' "$output" "digest-trunc: UBSan keeps middle line"
assert_match 'runtime error: load of misaligned address' "$output" "digest-trunc: UBSan keeps diagnostic"
unset ASAN_DIGEST_HEAD ASAN_DIGEST_TAIL

# Disabling truncation: ASAN_DIGEST_HEAD=0 keeps full stream even on clean runs.
cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
echo "[run-asan] generic EXECUTION VERIFIED (pre-run)"
i=1
while [ "$i" -le 200 ]; do
  echo "MIDDLE_LINE_$i parseJob"
  i=$((i + 1))
done
echo "TESTCASE_EXECUTED"
MOCK
chmod +x "$MOCK_BIN/run-asan"

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out_trunc_disabled.asan.txt"
export ASAN_DIGEST_HEAD=0
export ASAN_DIGEST_TAIL=15
output=$(ASAN_RUNS=1 bash "$RUN_5X" generic "$TEST_TMPDIR/tc.html" 2>&1)
assert_not_match 'DIGEST: clean run' "$output" "digest-trunc: HEAD=0 disables truncation"
assert_match 'MIDDLE_LINE_100 parseJob' "$output" "digest-trunc: HEAD=0 keeps middle line"
unset ASAN_DIGEST_HEAD ASAN_DIGEST_TAIL

# Short clean output stays whole (no marker, no clipping).
cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
echo "[run-asan] generic EXECUTION VERIFIED (pre-run)"
echo "small body line 1"
echo "small body line 2"
echo "TESTCASE_EXECUTED"
MOCK
chmod +x "$MOCK_BIN/run-asan"

export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out_trunc_small.asan.txt"
export ASAN_DIGEST_HEAD=10
export ASAN_DIGEST_TAIL=15
output=$(ASAN_RUNS=1 bash "$RUN_5X" generic "$TEST_TMPDIR/tc.html" 2>&1)
assert_not_match 'DIGEST: clean run' "$output" "digest-trunc: short clean run prints no marker"
assert_match 'small body line 1' "$output" "digest-trunc: short clean run keeps full body"
assert_match 'small body line 2' "$output" "digest-trunc: short clean run keeps every line"
unset ASAN_DIGEST_HEAD ASAN_DIGEST_TAIL

# ═══════════════════════════════════════════════════════════════
# 9. Auto differential divergence is a finding verdict
# ═══════════════════════════════════════════════════════════════

cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
if [ "$1" = "js-diff" ]; then
  echo "[run-asan] DIFFERENTIAL: outputs DIFFER — potential JIT issue"
  exit 1
fi
echo "TESTCASE_EXECUTED"
echo "[run-asan] browser EXECUTION VERIFIED (post-run, marker=TESTCASE_EXECUTED)"
MOCK
chmod +x "$MOCK_BIN/run-asan"

echo "print('TESTCASE_EXECUTED');" > "$TEST_TMPDIR/tc.js"
export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out-diff.asan.txt"
export TRIED_INPUTS_LOG="$TEST_TMPDIR/tried-diff.log"
: > "$TRIED_INPUTS_LOG"
output=$(ASAN_RUNS=1 bash "$RUN_5X" js "$TEST_TMPDIR/tc.js" 2>&1)
rc=$?
assert_eq "1" "$rc" "auto-diff: divergence exits nonzero"
assert_match "DIFFERENTIAL FINDING" "$output" "auto-diff: divergence summarized"
assert_file_contains "$TRIED_INPUTS_LOG" "verdict=DIFF" "auto-diff: tried log records DIFF"
unset TRIED_INPUTS_LOG

# ═══════════════════════════════════════════════════════════════
# 10. Generic mode ignores WANT auto-coverage gate
# ═══════════════════════════════════════════════════════════════

cat > "$MOCK_BIN/hits" <<'MOCK'
#!/bin/bash
for arg in "$@"; do
  if [ "$arg" = "generic" ]; then
    echo "hits should not be called for generic mode" >&2
    exit 99
  fi
done
echo "HIT: mock_function"
exit 0
MOCK
chmod +x "$MOCK_BIN/hits"

cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
echo "TESTCASE_EXECUTED"
echo "[run-asan] browser EXECUTION VERIFIED (post-run, marker=TESTCASE_EXECUTED)"
MOCK
chmod +x "$MOCK_BIN/run-asan"

echo "/abc/" > "$TEST_TMPDIR/tc.pcre2test"
export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out11.asan.txt"
export WANT="some_symbol"
output=$(ASAN_RUNS=1 bash "$RUN_5X" generic "$TEST_TMPDIR/tc.pcre2test" 2>&1)
assert_match "CRASH_RATE: 0/1" "$output" "generic WANT: ASan still runs"
assert_not_match "hits should not be called" "$output" "generic WANT: coverage gate skipped"
unset WANT

# ═══════════════════════════════════════════════════════════════
# 12. Dedup of matching reruns — runs 2..N collapse to a one-liner
#     when crash signature matches run 1 (addresses/thread ids vary,
#     top-3 interesting frames match). Runs 2..N stay byte-identical
#     in $OUTPUT_FILE so triage still sees every trace.
# ═══════════════════════════════════════════════════════════════

# Make lib/stack_frames.py reachable to the mock-bin run-asan-multi. The
# script computes _STACK_FRAMES_PY as $SCRIPT_DIR/../lib/stack_frames.py,
# so creating $MOCK_BIN/../lib/ pointed at the real file activates the
# dedup path. Without this the wrapper falls back to full-digest-each-run.
mkdir -p "$MOCK_BIN/../lib"
ln -sf "$SCRIPT_ROOT/lib/stack_frames.py" "$MOCK_BIN/../lib/stack_frames.py"

# Crash mock that varies addresses but keeps frame functions stable.
# A run counter file lets us inject divergence on an arbitrary run.
cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
RUN_NUM=$(cat "${MOCK_RUN_COUNTER:-/dev/null}" 2>/dev/null || echo 0)
RUN_NUM=$((RUN_NUM + 1))
[ -n "${MOCK_RUN_COUNTER:-}" ] && echo "$RUN_NUM" > "$MOCK_RUN_COUNTER"

if [ "$RUN_NUM" = "${MOCK_DIVERGE_AT:-0}" ]; then
  TOP_FUNC='different_top_frame_for_divergence'
else
  TOP_FUNC='nlohmann::detail::lexer::scan_string'
fi

cat <<EOF
==99999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60d000${RUN_NUM}aabbcc
READ of size 1 at 0x60d000${RUN_NUM}aabbcc thread T${RUN_NUM}
    #0 0x10c0a${RUN_NUM}40 in $TOP_FUNC /tmp/json/lexer.h:152
    #1 0x10c0a${RUN_NUM}44 in nlohmann::detail::parser::parse_internal /tmp/json/parser.h:284
    #2 0x10c0a${RUN_NUM}48 in nlohmann::basic_json::parse /tmp/json/json.hpp:6234
SUMMARY: AddressSanitizer: heap-buffer-overflow /tmp/json/lexer.h:152 in $TOP_FUNC
[run-asan] CRASH DETECTED: ASan error found
EOF
MOCK
chmod +x "$MOCK_BIN/run-asan"

# Case A — all 5 runs reproduce the same crash. Runs 2..5 should be
# one-liners; full stack appears only for run 1.
export MOCK_RUN_COUNTER="$TEST_TMPDIR/dedup-counter"
: > "$MOCK_RUN_COUNTER"
unset MOCK_DIVERGE_AT
export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out12-match.asan.txt"
output=$(ASAN_RUNS=5 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1 || true)
verified_count=$(printf '%s\n' "$output" | grep -c 'VERIFIED — same crash signature')
assert_eq "4" "$verified_count" "dedup: 4/5 reruns collapse to VERIFIED one-liner"
assert_match 'nlohmann::detail::lexer::scan_string' "$output" "dedup: top frame echoed in VERIFIED line"
# Stack frame body ("READ of size 1") should appear exactly once on stdout — for run 1.
read_count=$(printf '%s\n' "$output" | grep -c 'READ of size 1')
assert_eq "1" "$read_count" "dedup: full stack body emitted only for run 1 on stdout"
# But $OUTPUT_FILE must keep all 5 stacks for triage / later sed reads.
file_read_count=$(grep -c 'READ of size 1' "$ASAN_OUTPUT_FILE")
assert_eq "5" "$file_read_count" "dedup: \$OUTPUT_FILE preserves all 5 raw stacks"
assert_match "CRASH_RATE: 5/5" "$output" "dedup: CRASH_RATE counts every run"

# Case B — run 3 has a different top frame. It must NOT collapse; runs 2,4,5
# still match run 1.
: > "$MOCK_RUN_COUNTER"
export MOCK_DIVERGE_AT=3
export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out12-diverge.asan.txt"
output=$(ASAN_RUNS=5 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1 || true)
assert_match 'Run 3/5: DIVERGED' "$output" "dedup: divergent rerun flagged DIVERGED"
assert_match 'different_top_frame_for_divergence' "$output" "dedup: divergent run shows full stack"
verified_count=$(printf '%s\n' "$output" | grep -c 'VERIFIED — same crash signature')
assert_eq "3" "$verified_count" "dedup: 3 matching reruns still collapse around the divergent one"
unset MOCK_DIVERGE_AT MOCK_RUN_COUNTER

# Case C — ASAN_NO_DIGEST=1 disables dedup; every run gets full digest.
: > "$TEST_TMPDIR/dedup-counter"
export MOCK_RUN_COUNTER="$TEST_TMPDIR/dedup-counter"
export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out12-nodigest.asan.txt"
output=$(ASAN_NO_DIGEST=1 ASAN_RUNS=3 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1 || true)
verified_count=$(printf '%s\n' "$output" | grep -c 'VERIFIED — same crash')
assert_eq "0" "$verified_count" "dedup: ASAN_NO_DIGEST=1 disables collapse"
read_count=$(printf '%s\n' "$output" | grep -c 'READ of size 1')
assert_eq "3" "$read_count" "dedup: ASAN_NO_DIGEST=1 keeps full body for every run"
unset MOCK_RUN_COUNTER

# Case D — broken stack_frames.py must fail closed (no false VERIFIED).
# A python error must not collapse divergent reruns: regression guard for
# the "_run_signature swallows errors → empty sig matches empty sig"
# foot-gun. Replace the symlinked module with one that raises, and confirm
# every run still gets a full digest.
broken_lib_dir="$TEST_TMPDIR/broken-lib"
mkdir -p "$broken_lib_dir"
cat > "$broken_lib_dir/stack_frames.py" <<'PY'
raise SystemExit("simulated module failure")
PY
ln -sf "$broken_lib_dir/stack_frames.py" "$MOCK_BIN/../lib/stack_frames.py"
: > "$TEST_TMPDIR/dedup-counter"
export MOCK_RUN_COUNTER="$TEST_TMPDIR/dedup-counter"
export ASAN_OUTPUT_FILE="$TEST_TMPDIR/out12-broken.asan.txt"
output=$(ASAN_RUNS=3 bash "$RUN_5X" browser "$TEST_TMPDIR/tc.html" 2>&1 || true)
verified_count=$(printf '%s\n' "$output" | grep -c 'VERIFIED — same crash')
assert_eq "0" "$verified_count" "dedup: broken signature helper does NOT produce false VERIFIED"
read_count=$(printf '%s\n' "$output" | grep -c 'READ of size 1')
assert_eq "3" "$read_count" "dedup: broken signature helper falls back to full digest each run"
unset MOCK_RUN_COUNTER

# Restore the working signature module for any subsequent tests.
ln -sf "$SCRIPT_ROOT/lib/stack_frames.py" "$MOCK_BIN/../lib/stack_frames.py"

# Restore the simpler crash mock so subsequent tests (none today, but
# keep the seam clean) see the original behavior.
cat > "$MOCK_BIN/run-asan" <<'MOCK'
#!/bin/bash
case "${MOCK_ASAN_BEHAVIOR:-clean}" in
  crash)
    echo "==12345==ERROR: AddressSanitizer: heap-buffer-overflow"
    echo "[run-asan] CRASH DETECTED: ASan error found"
    ;;
  noexec)
    echo "[run-asan] WARNING: no crash and no execution evidence"
    ;;
  *)
    echo "TESTCASE_EXECUTED"
    echo "[run-asan] browser EXECUTION VERIFIED (post-run, marker=TESTCASE_EXECUTED)"
    ;;
esac
MOCK
chmod +x "$MOCK_BIN/run-asan"

teardown_test_env
summary
