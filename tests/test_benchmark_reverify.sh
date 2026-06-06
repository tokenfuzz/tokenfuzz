#!/usr/bin/env bash
# Tests for the bin/benchmark pool reverification pass
# (_reverify_pool_crash_rates / _reverify_one_crash).
#
# The model-direct floor condition writes sanitizer.txt from a single run, so
# those crashes carry no CRASH_RATE footer and otherwise render "?" for the
# Reproduction rate. The reverification pass re-runs each footer-less crash 5x
# through bin/run-sanitizer-multi — the same normalizer the harness path uses
# — so every pooled crash gets a uniformly measured rate. Harness crashes
# (already carrying a footer) are skipped; a crash that no longer reproduces
# records an honest 0/5; an unresolvable crash keeps "?" (never fabricated).
#
# We extract the two functions and source them directly (mirrors
# tests/test_asan_crash_outputcap.sh extracting _digest_asan), then drive them
# with a fixtured pool + target_root + a stub sanitizer binary. SCRIPT_ROOT is
# the real repo so $SCRIPT_ROOT/bin/run-sanitizer-multi and lib/ resolve.

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

BENCH="$SCRIPT_ROOT/bin/benchmark"

# Extract the two reverify functions into a sourceable file. Each function's
# body has no standalone `}` line before its real closing brace, so a
# first-`^}$`-ends-the-function capture is exact.
REVERIFY_FNS="$TEST_TMPDIR/reverify_fns.sh"
awk '
  /^_reverify_one_crash\(\) \{/    { c=1 }
  /^_reverify_pool_crash_rates\(\) \{/ { c=1 }
  c { print }
  c && /^\}$/ { c=0 }
' "$BENCH" > "$REVERIFY_FNS"
fn_lines=$(wc -l < "$REVERIFY_FNS" | tr -d ' ')
[ "$fn_lines" -gt 40 ]
assert_eq 0 $? "fixture: reverify functions extracted (${fn_lines} lines)"

# A stub "sanitizer binary". CRASH_MODE=1 emits an ASan diagnostic and exits
# non-zero; otherwise it runs clean. run-sanitizer-multi → run-asan generic
# invokes it as `stub <testcase>`.
_make_target_root() { # <root> <crash|clean>
  local root="$1" behavior="$2"
  mkdir -p "$root/build-asan/src"
  cat > "$root/target.toml" <<TOML
target = "reverify-stub"
asan_bin = "src/stub"
[sanitizer]
enabled = ["asan"]
TOML
  if [ "$behavior" = "crash" ]; then
    cat > "$root/build-asan/src/stub" <<'SH'
#!/usr/bin/env bash
echo "==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010"
echo "SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free"
exit 1
SH
  else
    cat > "$root/build-asan/src/stub" <<'SH'
#!/usr/bin/env bash
echo "ran clean"
exit 0
SH
  fi
  chmod +x "$root/build-asan/src/stub"
}

# A footer-less model-direct-style crash dir: a raw one-shot ASan trace (no
# CRASH_RATE) plus an input file.
_make_footerless_crash() { # <crash_dir>
  local cdir="$1"
  mkdir -p "$cdir"
  cat > "$cdir/sanitizer.txt" <<'TXT'
==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010
READ of size 8 at 0x602000000010 thread T0
SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free
TXT
  printf 'poc-bytes\n' > "$cdir/poc.bin"
}

# Provide a no-op log() and source the extracted functions.
log() { :; }
# shellcheck source=/dev/null
source "$REVERIFY_FNS"

# ── T1: footer-less crash that reproduces → measured CRASH_RATE: 5/5 ──
pool1="$TEST_TMPDIR/pool1"; tgt1="$TEST_TMPDIR/tgt1"
_make_target_root "$tgt1" crash
_make_footerless_crash "$pool1/crashes/CRASH-0001"
_reverify_pool_crash_rates "$pool1" "$tgt1" test
assert_file_contains "$pool1/crashes/CRASH-0001/sanitizer.txt" '^CRASH_RATE: 5/5' \
  "T1: reproducing footer-less crash gets a measured 5/5 footer"

# ── T2: footer-less crash that no longer reproduces → honest 0/5, diagnostic kept ──
pool2="$TEST_TMPDIR/pool2"; tgt2="$TEST_TMPDIR/tgt2"
_make_target_root "$tgt2" clean
_make_footerless_crash "$pool2/crashes/CRASH-0001"
_reverify_pool_crash_rates "$pool2" "$tgt2" test
assert_file_contains "$pool2/crashes/CRASH-0001/sanitizer.txt" '^CRASH_RATE: 0/5' \
  "T2: non-reproducing crash records an honest 0/5"
assert_file_contains "$pool2/crashes/CRASH-0001/sanitizer.txt" 'heap-use-after-free child.c:91' \
  "T2b: non-reproducing crash keeps its original diagnostic (evidence preserved)"

# ── T3: a crash already carrying a measured footer is left untouched ──
pool3="$TEST_TMPDIR/pool3"; tgt3="$TEST_TMPDIR/tgt3"
_make_target_root "$tgt3" crash
mkdir -p "$pool3/crashes/CRASH-0001"
cat > "$pool3/crashes/CRASH-0001/sanitizer.txt" <<'TXT'
==4242==ERROR: AddressSanitizer: heap-use-after-free
SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free
CRASH_RATE: 3/5
TXT
before3="$(cat "$pool3/crashes/CRASH-0001/sanitizer.txt")"
_reverify_pool_crash_rates "$pool3" "$tgt3" test
assert_eq "$before3" "$(cat "$pool3/crashes/CRASH-0001/sanitizer.txt")" \
  "T3: a crash with a measured footer is never re-run (cost guard)"

# ── T4: unresolvable binary → sanitizer.txt unchanged, rate stays '?' ──
pool5="$TEST_TMPDIR/pool5"; tgt5="$TEST_TMPDIR/tgt5"
mkdir -p "$tgt5"                              # target.toml present but no build-asan/stub
cat > "$tgt5/target.toml" <<'TOML'
target = "reverify-stub"
asan_bin = "src/stub"
[sanitizer]
enabled = ["asan"]
TOML
_make_footerless_crash "$pool5/crashes/CRASH-0001"
before5="$(cat "$pool5/crashes/CRASH-0001/sanitizer.txt")"
rc5=0
_reverify_pool_crash_rates "$pool5" "$tgt5" test || rc5=$?
assert_eq "0" "$rc5" "T4: the pass exits 0 even when a crash cannot be reverified"
assert_eq "$before5" "$(cat "$pool5/crashes/CRASH-0001/sanitizer.txt")" \
  "T4b: an unresolvable crash is left untouched (rate stays '?', never fabricated)"

# ── T5: bundle skip-guard distinguishes a real rate from a stale one ──
# rebuild_pool_artifacts re-bundles a canonical report ONLY when its
# Reproduction rate is not a real measured number, so reverify's freshly
# written CRASH_RATE reaches an old "?"/"—" report instead of being skipped.
# This mirrors the guard predicate in bin/benchmark (Finding-1 regression).
_report_has_real_rate() { # <report.md> → 0 when a measured n/m rate is shown
  grep -q '^## Expected sanitizer output' "$1" 2>/dev/null \
    && grep -Eiq '^\|[[:space:]]*Reproduction rate[[:space:]]*\|[^|]*[0-9]+/[0-9]+' "$1" 2>/dev/null
}
_write_report() { # <path> <rate-cell>
  mkdir -p "$(dirname "$1")"
  printf '# CRASH\n\n## Fields\n\n| Field | Value |\n| :--- | :--- |\n| Reproduction rate | %s |\n\n## Expected sanitizer output\n' \
    "$2" > "$1"
}
_write_report "$TEST_TMPDIR/rep-real/REPORT.md" "5/5"
_report_has_real_rate "$TEST_TMPDIR/rep-real/REPORT.md"
assert_eq 0 $? "T5: canonical report with a measured 5/5 rate is left untouched (skipped)"
_write_report "$TEST_TMPDIR/rep-q/REPORT.md" "?"
rc_q=0; _report_has_real_rate "$TEST_TMPDIR/rep-q/REPORT.md" || rc_q=$?
assert_eq 1 "$rc_q" "T5b: canonical report with a stale '?' rate is re-bundled"
_write_report "$TEST_TMPDIR/rep-dash/REPORT.md" "—"
rc_d=0; _report_has_real_rate "$TEST_TMPDIR/rep-dash/REPORT.md" || rc_d=$?
assert_eq 1 "$rc_d" "T5c: canonical report with a stale '—' rate is re-bundled"

# Guard against drift: the predicate above must match the live guard in
# bin/benchmark (same Reproduction-rate regex).
grep -Eq 'Reproduction rate\[\[:space:\]\]\*\\\|\[\^\|\]\*\[0-9\]\+/\[0-9\]\+' "$BENCH"
assert_eq 0 $? "T5d: bin/benchmark bundle guard uses the same measured-rate regex"

teardown_test_env
summary
