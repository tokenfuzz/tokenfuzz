#!/usr/bin/env bash
# tests/test_verdict.sh — the shared crash/clean classifier, lib/verdict.sh.
#
# verdict.sh is the single source of truth for CRASH / CLEAN classification
# of sanitizer output; bin/probe, bin/scratch-status and lib/quality.sh all
# route through it. These tests pin the runtime-fatal coverage (so a Go
# race / Rust panic / SEGV is never silently read as CLEAN) and the strict
# CLEAN gate (wrapper-issued evidence only).
set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/verdict.sh"

# mk <name> <line...> — write a file under TEST_TMPDIR, echo its path.
mk() {
  local f="$TEST_TMPDIR/$1"; shift
  printf '%s\n' "$@" > "$f"
  printf '%s' "$f"
}

# ── CRASH detection spans every supported runtime ───────────────────
f=$(mk asan.txt "==1==ERROR: AddressSanitizer: heap-buffer-overflow")
verdict_file_has_crash "$f" && pass "crash: AddressSanitizer" || fail "crash: AddressSanitizer"
f=$(mk go.txt "panic: runtime error: index out of range [3]")
verdict_file_has_crash "$f" && pass "crash: Go runtime panic" || fail "crash: Go runtime panic"
f=$(mk rust.txt "thread 'main' panicked at src/lib.rs:9:5")
verdict_file_has_crash "$f" && pass "crash: Rust panic" || fail "crash: Rust panic"
f=$(mk rust-modern.txt "thread 'main' (4734029) panicked at src/lib.rs:9:5")
verdict_file_has_crash "$f" && pass "crash: Rust panic with thread id" || fail "crash: Rust panic with thread id"
f=$(mk tsan.txt "WARNING: ThreadSanitizer: data race")
verdict_file_has_crash "$f" && pass "crash: ThreadSanitizer" || fail "crash: ThreadSanitizer"
f=$(mk segv.txt "==42==SEGV on unknown address 0x000000000000")
verdict_file_has_crash "$f" && pass "crash: SEGV trap" || fail "crash: SEGV trap"
f=$(mk wrap.txt "[run-asan] CRASH DETECTED")
verdict_file_has_crash "$f" && pass "crash: run-asan wrapper marker" || fail "crash: wrapper marker"

# ── Benign / non-fatal output is NOT a crash ────────────────────────
f=$(mk ok.txt "parsed 12 nodes" "AssertionError: harmless test assert" "done")
verdict_file_has_crash "$f" && fail "benign: plain AssertionError must not be CRASH" \
  || pass "benign: non-fatal output is not a crash"
empty="$TEST_TMPDIR/empty.txt"; : > "$empty"
verdict_file_has_crash "$empty" && fail "empty file must not be a crash" \
  || pass "benign: empty file is not a crash"

# ── Per-target crash patterns union in at match time ────────────────
f=$(mk tgt.txt "the device reported WIDGET_FAULT during teardown")
verdict_file_has_crash "$f" && fail "target marker must be off without target.toml" \
  || pass "target marker: inert by default"
TARGET_RUNNER_CRASH_PATTERNS=("WIDGET_FAULT")
verdict_file_has_crash "$f" && pass "target marker: TARGET_RUNNER_CRASH_PATTERNS honored" \
  || fail "target marker: TARGET_RUNNER_CRASH_PATTERNS honored"
unset TARGET_RUNNER_CRASH_PATTERNS

# ── CLEAN requires wrapper-issued execution evidence ────────────────
f=$(mk clean1.txt "[run-asan-multi] EXECUTION_RATE: 5/5")
verdict_file_is_clean "$f" && pass "clean: run-asan-multi execution rate" \
  || fail "clean: run-asan-multi execution rate"
f=$(mk success.txt "[run-sanitizer-multi] SUCCESS_RATE: 5/5")
verdict_file_is_clean "$f" && pass "clean: run-sanitizer-multi success rate" \
  || fail "clean: run-sanitizer-multi success rate"
f=$(mk reached.txt "[run-sanitizer-multi] EXECUTION_RATE: 5/5")
verdict_file_is_clean "$f" && fail "clean: run-sanitizer-multi execution rate alone is not CLEAN" \
  || pass "clean: run-sanitizer-multi execution rate alone is not CLEAN"
f=$(mk clean2.txt "[run-asan] generic EXECUTION VERIFIED (post-run, rc=0)")
verdict_file_is_clean "$f" && pass "clean: run-asan post-run marker" \
  || fail "clean: run-asan post-run marker"
f=$(mk inconclusive.txt "[run-asan] generic EXECUTION INCONCLUSIVE (post-run, rc=7)")
verdict_file_is_clean "$f" && fail "clean: inconclusive marker must not count" \
  || pass "clean: inconclusive marker must not count"
f=$(mk raw.txt "TESTCASE_EXECUTED")
verdict_file_is_clean "$f" && fail "clean: raw TESTCASE_EXECUTED must not count" \
  || pass "clean: ignores raw testcase stdout"
f=$(mk zero.txt "[run-asan-multi] EXECUTION_RATE: 0/5")
verdict_file_is_clean "$f" && fail "clean: a 0/N execution rate is not CLEAN" \
  || pass "clean: zero execution rate is not CLEAN"

# ── All verdict consumers route through the shared classifier ───────
for consumer in bin/probe bin/scratch-status lib/quality.sh; do
  if grep -q 'verdict\.sh' "$SCRIPT_ROOT/$consumer"; then
    pass "$consumer sources lib/verdict.sh"
  else
    fail "$consumer sources lib/verdict.sh"
  fi
done

teardown_test_env
summary
