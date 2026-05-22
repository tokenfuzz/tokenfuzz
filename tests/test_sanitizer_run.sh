#!/usr/bin/env bash
# Verifies the shared standalone-sanitizer dispatch helpers in
# lib/sanitizer_run.sh. bin/run-msan and bin/run-tsan are thin shims over
# these helpers and bin/run-ubsan delegates its non-browser generic/js
# modes here; centralizing the dispatch means a fix can no longer drift
# across the entry points. Behavior is asserted directly against the lib.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# shellcheck disable=SC1090
source "$SCRIPT_ROOT/lib/timeout.sh"
# shellcheck disable=SC1090
source "$SCRIPT_ROOT/lib/sanitizer.sh"
# shellcheck disable=SC1090
source "$SCRIPT_ROOT/lib/target_config.sh"
# shellcheck disable=SC1090
source "$SCRIPT_ROOT/lib/sanitizer_run.sh"

WORK="$TEST_TMPDIR/sanitizer-run"
mkdir -p "$WORK"

# Fake instrumented binary: prints a marker, exits with $FAKE_RC.
FAKE_BIN="$WORK/fake-bin"
cat > "$FAKE_BIN" <<'EOF'
#!/usr/bin/env bash
echo "fake-bin ran: $*"
exit "${FAKE_RC:-0}"
EOF
chmod +x "$FAKE_BIN"

# ── _sanitizer_run_upper ──────────────────────────────────────────
assert_eq "MSAN" "$(_sanitizer_run_upper msan)" "_sanitizer_run_upper uppercases msan"
assert_eq "TSAN" "$(_sanitizer_run_upper tsan)" "_sanitizer_run_upper uppercases tsan"

# ── generic: usage when no testcase ───────────────────────────────
out=$(sanitizer_run_generic msan "halt_on_error=1" 5 2>&1); rc=$?
assert_eq 1 "$rc" "generic: no testcase → rc 1"
assert_match "Usage:" "$out" "generic: no testcase → usage line"

# ── generic: unresolved binary → exit 2 + actionable guidance ─────
out=$(sanitizer_run_generic msan "halt_on_error=1" 5 /dev/null 2>&1); rc=$?
assert_eq 2 "$rc" "generic: unresolved bin → rc 2"
assert_match "set \[sanitizer\].msan_bin" "$out" "generic: unresolved bin → names msan_bin"

# ── generic: resolves <SAN>_GENERIC_BIN override, clean run ───────
out=$(MSAN_GENERIC_BIN="$FAKE_BIN" FAKE_RC=0 \
      sanitizer_run_generic msan "x=1" 5 /dev/null 2>&1); rc=$?
assert_eq 0 "$rc" "generic: clean run → rc 0"
assert_match "EXECUTION VERIFIED" "$out" "generic: clean run → VERIFIED marker"

# ── generic: non-zero child exit propagates ───────────────────────
out=$(MSAN_GENERIC_BIN="$FAKE_BIN" FAKE_RC=3 \
      sanitizer_run_generic msan "x=1" 5 /dev/null 2>&1); rc=$?
assert_eq 3 "$rc" "generic: failing child → propagates rc"
assert_match "INCONCLUSIVE" "$out" "generic: failing child → INCONCLUSIVE marker"

# ── js: honours <SAN>_JS override, clean run ──────────────────────
out=$(TSAN_JS="$FAKE_BIN" FAKE_RC=0 \
      sanitizer_run_js tsan "x=1" 5 /dev/null 2>&1); rc=$?
assert_eq 0 "$rc" "js: clean run → rc 0"

# ── js: non-zero child exit propagates ────────────────────────────
out=$(TSAN_JS="$FAKE_BIN" FAKE_RC=4 \
      sanitizer_run_js tsan "x=1" 5 /dev/null 2>&1); rc=$?
assert_eq 4 "$rc" "js: failing child → propagates rc"

# ── fuzz: missing FUZZER env var ──────────────────────────────────
out=$(sanitizer_run_fuzz msan "x=1" 5 2>&1); rc=$?
assert_eq 1 "$rc" "fuzz: no FUZZER → rc 1"
assert_match "FUZZER env var must be set" "$out" "fuzz: no FUZZER → guidance"

# ── fuzz-repro: missing crash file ────────────────────────────────
out=$(sanitizer_run_fuzz_repro msan "x=1" 5 2>&1); rc=$?
assert_eq 1 "$rc" "fuzz-repro: no crash file → rc 1"
assert_match "provide a crash file" "$out" "fuzz-repro: no crash file → guidance"

# ── runner delegation: shims actually route through the shared lib ─
for r in run-msan run-tsan; do
  if grep -q 'lib/sanitizer_run.sh' "$SCRIPT_ROOT/bin/$r"; then
    pass "bin/$r sources lib/sanitizer_run.sh"
  else
    fail "bin/$r sources lib/sanitizer_run.sh"
  fi
  if grep -q "sanitizer_run_generic $(printf '%s' "$r" | sed 's/run-//')" "$SCRIPT_ROOT/bin/$r"; then
    pass "bin/$r delegates generic dispatch to the shared helper"
  else
    fail "bin/$r delegates generic dispatch to the shared helper"
  fi
done

if grep -q 'sanitizer_run_generic ubsan' "$SCRIPT_ROOT/bin/run-ubsan" \
   && grep -q 'sanitizer_run_js ubsan' "$SCRIPT_ROOT/bin/run-ubsan"; then
  pass "bin/run-ubsan delegates generic + js dispatch to the shared helper"
else
  fail "bin/run-ubsan delegates generic + js dispatch to the shared helper"
fi

summary
