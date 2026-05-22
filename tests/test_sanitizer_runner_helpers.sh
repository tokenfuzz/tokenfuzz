#!/usr/bin/env bash
# Verifies the four runner helpers extracted from
# bin/run-{asan,ubsan,msan,tsan} into lib/sanitizer.sh in the #3
# refactor: _fuzz_timeout, _fuzz_default_crash_dir,
# _validate_fuzzer_name, filter_browser_output. These were previously
# duplicated verbatim in each runner; centralizing means a fix in one
# place can no longer silently drift across the four entry points.
#
# Behavior is asserted directly against lib/sanitizer.sh so the four
# bin/ entry points can keep their familiar names without four near-
# identical test files.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# shellcheck disable=SC1090
source "$SCRIPT_ROOT/lib/timeout.sh"
# shellcheck disable=SC1090
source "$SCRIPT_ROOT/lib/sanitizer.sh"

WORK="$TEST_TMPDIR/sanitizer-helpers"
mkdir -p "$WORK"

# ── _validate_fuzzer_name ─────────────────────────────────────────

FUZZER="ImagePNG" _validate_fuzzer_name && pass "_validate_fuzzer_name: accepts identifier" \
  || fail "_validate_fuzzer_name: accepts identifier"

FUZZER="Wasm_decoder" _validate_fuzzer_name && pass "_validate_fuzzer_name: accepts underscores" \
  || fail "_validate_fuzzer_name: accepts underscores"

if ! FUZZER="foo;rm -rf /" _validate_fuzzer_name 2>/dev/null; then
  pass "_validate_fuzzer_name: rejects shell metachars"
else
  fail "_validate_fuzzer_name: rejects shell metachars"
fi

if ! FUZZER="" _validate_fuzzer_name 2>/dev/null; then
  pass "_validate_fuzzer_name: rejects empty"
else
  fail "_validate_fuzzer_name: rejects empty"
fi

if ! FUZZER="1startswithdigit" _validate_fuzzer_name 2>/dev/null; then
  pass "_validate_fuzzer_name: rejects leading digit"
else
  fail "_validate_fuzzer_name: rejects leading digit"
fi

# ── _fuzz_default_crash_dir ───────────────────────────────────────

got=$(RESULTS_DIR="$WORK/r" FUZZER=ImagePNG _fuzz_default_crash_dir)
assert_eq "$WORK/r/fuzz-crashes/ImagePNG" "$got" \
  "_fuzz_default_crash_dir: composes RESULTS_DIR/fuzz-crashes/<FUZZER>"

got=$(unset RESULTS_DIR; FUZZER=Wasm _fuzz_default_crash_dir)
assert_eq "results/fuzz-crashes/Wasm" "$got" \
  "_fuzz_default_crash_dir: falls back to 'results' when RESULTS_DIR unset"

# ── _fuzz_timeout ─────────────────────────────────────────────────
# Delegates to audit_timeout_kill (lib/timeout.sh). Verify it forwards
# args + exits non-zero on timeout. Use a trivial command that completes
# instantly to confirm the pass-through path; SIGKILL semantics are
# already covered by the test_timeout suite.

out=$(_fuzz_timeout 5 true)
assert_eq "0" "$?" "_fuzz_timeout: success exit propagates rc=0"
assert_eq ""  "$out" "_fuzz_timeout: passes stdout through unchanged"

# ── filter_browser_output ─────────────────────────────────────────
# Drops the Firefox noise lines; keeps everything else verbatim.

cat > "$WORK/noisy.log" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow at 0xdeadbeef
console.debug: "Registering new SmartBlock shim content scripts"
Nightly GPU Helper[12345]: starting
real output line
console.debug: "Enabled" 42 "webcompat"
another real line
Exiting due to channel error.
SUMMARY: AddressSanitizer: heap-buffer-overflow
EOF

filtered=$(filter_browser_output "$WORK/noisy.log")
case "$filtered" in
  *"AddressSanitizer: heap-buffer-overflow at 0xdeadbeef"*) pass "filter_browser_output: keeps ASan diagnostic" ;;
  *) fail "filter_browser_output: keeps ASan diagnostic" "got '$filtered'" ;;
esac
case "$filtered" in
  *"real output line"*) pass "filter_browser_output: keeps unrelated lines" ;;
  *) fail "filter_browser_output: keeps unrelated lines" ;;
esac
case "$filtered" in
  *"SmartBlock"*)            fail "filter_browser_output: drops SmartBlock noise" "leaked SmartBlock line" ;;
  *) pass "filter_browser_output: drops SmartBlock noise" ;;
esac
case "$filtered" in
  *"Nightly GPU Helper"*)    fail "filter_browser_output: drops GPU helper noise" ;;
  *) pass "filter_browser_output: drops GPU helper noise" ;;
esac
case "$filtered" in
  *"Exiting due to channel error"*) fail "filter_browser_output: drops channel-error line" ;;
  *) pass "filter_browser_output: drops channel-error line" ;;
esac

# Source-of-truth invariant: the four bin/run-* runners must NOT
# redefine the helpers locally — otherwise the lib version is shadowed
# and the drift bug returns silently.
for runner in run-asan run-ubsan run-msan run-tsan; do
  count=$(grep -cE "^_validate_fuzzer_name\(\)|^_fuzz_timeout\(\)|^_fuzz_default_crash_dir\(\)|^filter_browser_output\(\)" \
            "$SCRIPT_ROOT/bin/$runner" || true)
  assert_eq "0" "$count" "no local redefinitions of helpers in bin/$runner"
done

summary
