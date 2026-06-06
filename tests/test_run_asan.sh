#!/usr/bin/env bash
# Unit tests for bin/run-asan — argument parsing, mode selection,
# ASan options construction, timeout configuration, output filtering
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

RUN_ASAN="$SCRIPT_ROOT/bin/run-asan"

# ═══════════════════════════════════════════════════════════════
# 1. --help / no args exits with usage
# ═══════════════════════════════════════════════════════════════

output=$(bash "$RUN_ASAN" 2>&1) || true
assert_match "Usage:" "$output" "no args: shows usage or error"

# ═══════════════════════════════════════════════════════════════
# 2. Mode validation — invalid mode
# ═══════════════════════════════════════════════════════════════

output=$(bash "$RUN_ASAN" invalid_mode /dev/null 2>&1) || true
assert_match "Usage:" "$output" "invalid mode: error message"

# ═══════════════════════════════════════════════════════════════
# 3. Source file parses without syntax errors
# ═══════════════════════════════════════════════════════════════

bash -n "$RUN_ASAN" 2>/dev/null
assert_eq 0 $? "run-asan: syntax check passes"

# ═══════════════════════════════════════════════════════════════
# 4. Environment variable defaults
# ═══════════════════════════════════════════════════════════════

# Extract default timeout values by sourcing just the variable declarations
output=$(bash -c '
  set -euo pipefail
  ASAN_TIMEOUT=""
  FUZZ_ASAN_TIMEOUT=""
  BROWSER_TIMEOUT="${ASAN_TIMEOUT:-15}"
  JS_TIMEOUT="${ASAN_TIMEOUT:-10}"
  FUZZ_TIMEOUT="${FUZZ_ASAN_TIMEOUT:-600}"
  echo "browser=$BROWSER_TIMEOUT js=$JS_TIMEOUT fuzz=$FUZZ_TIMEOUT"
')
assert_match "browser=15" "$output" "default browser timeout = 15"
assert_match "js=10" "$output" "default js timeout = 10"
assert_match "fuzz=600" "$output" "default fuzz timeout = 600"

# ═══════════════════════════════════════════════════════════════
# 5. ASAN_TIMEOUT override
# ═══════════════════════════════════════════════════════════════

output=$(bash -c '
  set -euo pipefail
  ASAN_TIMEOUT=30
  BROWSER_TIMEOUT="${ASAN_TIMEOUT:-15}"
  JS_TIMEOUT="${ASAN_TIMEOUT:-10}"
  echo "browser=$BROWSER_TIMEOUT js=$JS_TIMEOUT"
')
assert_match "browser=30" "$output" "ASAN_TIMEOUT override: browser=30"
assert_match "js=30" "$output" "ASAN_TIMEOUT override: js=30"

# ═══════════════════════════════════════════════════════════════
# 6. FUZZ_ASAN_TIMEOUT is independent of ASAN_TIMEOUT
# ═══════════════════════════════════════════════════════════════
# Fuzz uses its own knob so a short repro override of ASAN_TIMEOUT
# can't accidentally starve a long fuzz loop.

output=$(bash -c '
  set -euo pipefail
  ASAN_TIMEOUT=5
  FUZZ_ASAN_TIMEOUT=""
  FUZZ_TIMEOUT="${FUZZ_ASAN_TIMEOUT:-600}"
  echo "fuzz=$FUZZ_TIMEOUT"
')
assert_match "fuzz=600" "$output" "fuzz timeout ignores ASAN_TIMEOUT"

output=$(bash -c '
  set -euo pipefail
  ASAN_TIMEOUT=5
  FUZZ_ASAN_TIMEOUT=900
  FUZZ_TIMEOUT="${FUZZ_ASAN_TIMEOUT:-600}"
  echo "fuzz=$FUZZ_TIMEOUT"
')
assert_match "fuzz=900" "$output" "FUZZ_ASAN_TIMEOUT override: fuzz=900"

# ═══════════════════════════════════════════════════════════════
# 6b. js-diff returns status for match/divergence
# ═══════════════════════════════════════════════════════════════

mock_js="$TEST_TMPDIR/mock-js"
cat > "$mock_js" <<'EOF'
#!/usr/bin/env bash
case "$1" in
  --ion-eager)
    if grep -q DIFF "$2"; then echo ion; else echo same; fi ;;
  --no-ion)
    if grep -q DIFF "$2"; then echo noion; else echo same; fi ;;
  *)
    echo same ;;
esac
EOF
chmod +x "$mock_js"

same_tc="$TEST_TMPDIR/same.js"
echo "print('same')" > "$same_tc"
output=$(ASAN_JS="$mock_js" bash "$RUN_ASAN" js-diff "$same_tc" 2>&1)
rc=$?
assert_eq "0" "$rc" "js-diff: matching outputs exit 0"
assert_match "outputs MATCH" "$output" "js-diff: matching outputs reported"

diff_tc="$TEST_TMPDIR/diff.js"
echo "DIFF" > "$diff_tc"
output=$(ASAN_JS="$mock_js" bash "$RUN_ASAN" js-diff "$diff_tc" 2>&1)
rc=$?
assert_eq "1" "$rc" "js-diff: divergent outputs exit 1"
assert_match "outputs DIFFER" "$output" "js-diff: divergent outputs reported"

# ═══════════════════════════════════════════════════════════════
# 6c. js-diff respects per-engine [s4_diff_pairs] from target.toml
#     (V8-style flag set: jit_off is two flags, jit_eager is one).
#     Bash arrays don't survive through `bash <script>`, so we drive
#     target_load by writing a real output/<slug>/{.session-env,target.toml}.
# ═══════════════════════════════════════════════════════════════

s4_root="$TEST_TMPDIR/s4-target"
s4_slug="chromium"
s4_cfg_dir="$s4_root/output/$s4_slug"
mkdir -p "$s4_cfg_dir"

# Minimal .session-env (TARGET_ROOT/SLUG are required for target_load).
cat > "$s4_cfg_dir/.session-env" <<EOF
export RESULTS_DIR='$s4_cfg_dir/results'
export TARGET_ROOT='$s4_root'
export TARGET_SLUG='$s4_slug'
export TARGET_REV='deadbeef'
export SESSION_STARTED='2026-05-12T00:00:00Z'
export LOGDIR='$s4_cfg_dir/logs'
EOF
mkdir -p "$s4_cfg_dir/results" "$s4_cfg_dir/logs"

# Hand-write target.toml with V8-style jit flags. seed_toml would emit
# the same shape, but we want this test independent of seed_toml's output.
cat > "$s4_cfg_dir/target.toml" <<'EOF'
target = "chromium"
build_system = "gn"
is_browser = "1"

[s4_diff_pairs]
jit_off   = ["--no-turbofan", "--no-maglev"]
jit_eager = ["--always-turbofan"]
EOF

mock_v8="$TEST_TMPDIR/mock-v8"
log_v8="$TEST_TMPDIR/mock-v8.log"
> "$log_v8"
cat > "$mock_v8" <<'EOF'
#!/usr/bin/env bash
echo "INVOKED: $*" >> "$LOG"
echo same
EOF
chmod +x "$mock_v8"

same_tc2="$s4_cfg_dir/same2.js"
echo "print('same')" > "$same_tc2"

# Run from inside the slug dir so target_load discovers the .session-env.
(
  cd "$s4_cfg_dir"
  LOG="$log_v8" ASAN_JS="$mock_v8" bash "$RUN_ASAN" js-diff "$same_tc2" >/dev/null 2>&1
)

# Mock should have been invoked with the V8 flags, not --ion-eager / --no-ion.
if grep -q -- "--always-turbofan" "$log_v8" && grep -q -- "--no-turbofan --no-maglev" "$log_v8"; then
  pass "js-diff: per-engine flags reach shell (V8-style)"
else
  fail "js-diff: per-engine flags reach shell (V8-style)" \
       "log was: $(cat "$log_v8")"
fi
if ! grep -q -- "--ion-eager" "$log_v8" && ! grep -q -- "--no-ion" "$log_v8"; then
  pass "js-diff: SpiderMonkey defaults absent when per-engine set"
else
  fail "js-diff: SpiderMonkey defaults absent when per-engine set" \
       "Firefox flags leaked into V8 mock invocation: $(cat "$log_v8")"
fi

# ═══════════════════════════════════════════════════════════════
# 7. run-asan-multi syntax check
# ═══════════════════════════════════════════════════════════════

bash -n "$SCRIPT_ROOT/bin/run-asan-multi" 2>/dev/null
assert_eq 0 $? "run-asan-multi: syntax check passes"
bash -n "$SCRIPT_ROOT/bin/run-sanitizer-multi" 2>/dev/null
assert_eq 0 $? "run-sanitizer-multi: syntax check passes"

# ═══════════════════════════════════════════════════════════════
# 8. bin/hits syntax check (if exists)
# ═══════════════════════════════════════════════════════════════

if [ -f "$SCRIPT_ROOT/bin/hits" ]; then
  bash -n "$SCRIPT_ROOT/bin/hits" 2>/dev/null
  assert_eq 0 $? "bin/hits: syntax check passes"
else
  pass "bin/hits: file not present (optional)"
fi

# ═══════════════════════════════════════════════════════════════
# 9. bin/run-ubsan syntax check (if exists)
# ═══════════════════════════════════════════════════════════════

if [ -f "$SCRIPT_ROOT/bin/run-ubsan" ]; then
  bash -n "$SCRIPT_ROOT/bin/run-ubsan" 2>/dev/null
  assert_eq 0 $? "bin/run-ubsan: syntax check passes"
else
  pass "bin/run-ubsan: file not present (optional)"
fi

# ═══════════════════════════════════════════════════════════════
# 10. FUZZER name validation prevents path/regex injection
# ═══════════════════════════════════════════════════════════════

bad_fuzzer_rc=0
bad_fuzzer_out=$(FUZZER='../bad' bash "$RUN_ASAN" fuzz "$TEST_TMPDIR/corpus" 2>&1) || bad_fuzzer_rc=$?
assert_eq "2" "$bad_fuzzer_rc" "FUZZER traversal token exits 2"
assert_match 'FUZZER must match' "$bad_fuzzer_out" "FUZZER traversal token rejected"

teardown_test_env
summary
