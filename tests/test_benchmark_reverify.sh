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
# We drive the public resolver with a fixtured pool, target_root, and stub
# sanitizer binary. SCRIPT_ROOT is
# the real repo so $SCRIPT_ROOT/bin/run-sanitizer-multi and lib/ resolve.

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

BENCH_RUNNER="$SCRIPT_ROOT/lib/benchmark_runner.py"

_reverify_pool_crash_rates() {
  AUDIT_BUILD_SUFFIX="${AUDIT_BUILD_SUFFIX:-}" PYTHONPATH="$SCRIPT_ROOT/lib" \
    python3 - "$1" "$2" "${TARGET_SLUG:-}" "$3" <<'PY'
import sys
from pathlib import Path
from benchmark_runner import reverify_pool_crash_rates
reverify_pool_crash_rates(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3], sys.argv[4])
PY
}

# A stub "sanitizer binary". CRASH_MODE=1 emits an ASan diagnostic and exits
# non-zero; otherwise it runs clean. run-sanitizer-multi → run-asan generic
# invokes it as `stub <testcase>`.
_make_target_root() { # <root> <crash|clean>
  local root="$1" behavior="$2"
  mkdir -p "$root/build-asan/src"
  # asan_bin is relative to target_root and includes the build dir, matching the
  # real convention (brotli: build-asan/brotli) and how bin/run-asan resolves it.
  cat > "$root/target.toml" <<TOML
target = "reverify-stub"
asan_bin = "build-asan/src/stub"
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
  elif [ "$behavior" = "invalid" ]; then
    cat > "$root/build-asan/src/stub" <<'SH'
#!/usr/bin/env bash
echo "usage: missing required option" >&2
exit 2
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

# Provide a no-op shell log for the fixture helpers.
log() { :; }

# ── Speed: every reverify case below drives bin/run-sanitizer-multi 5x through
# run-asan (~3s each) and the cases are independent — each writes only to its
# own pool/tgt dir. So set up all fixtures, launch every reverify in parallel,
# wait once, then assert on the written sanitizer.txt files. This is the same
# launch-then-assert pattern used in test_benchmark.sh and
# test_multilang_support.sh, and turns a ~25s sequential suite into ~6s.
# `before*` snapshots and the T4 rc are captured before/at launch so the
# post-wait assertions see exactly what each case produced.

# ── T1 fixture: footer-less crash that reproduces → measured 5/5 ──
pool1="$TEST_TMPDIR/pool1"; tgt1="$TEST_TMPDIR/tgt1"
_make_target_root "$tgt1" crash
_make_footerless_crash "$pool1/crashes/CRASH-0001"
_reverify_pool_crash_rates "$pool1" "$tgt1" test &

# ── T2 fixture: footer-less crash that no longer reproduces → honest 0/5 ──
pool2="$TEST_TMPDIR/pool2"; tgt2="$TEST_TMPDIR/tgt2"
_make_target_root "$tgt2" clean
_make_footerless_crash "$pool2/crashes/CRASH-0001"
_reverify_pool_crash_rates "$pool2" "$tgt2" test &

# ── T2c fixture: invalid execution leaves rate unset, not false 0/5 ──
pool2c="$TEST_TMPDIR/pool2c"; tgt2c="$TEST_TMPDIR/tgt2c"
_make_target_root "$tgt2c" invalid
_make_footerless_crash "$pool2c/crashes/CRASH-0001"
before2c="$(cat "$pool2c/crashes/CRASH-0001/sanitizer.txt")"
_reverify_pool_crash_rates "$pool2c" "$tgt2c" test &

# ── T2d fixture: source harness crash does not fall back to target CLI ──
pool2d="$TEST_TMPDIR/pool2d"; tgt2d="$TEST_TMPDIR/tgt2d"
_make_target_root "$tgt2d" clean
_make_footerless_crash "$pool2d/crashes/CRASH-0001"
printf 'int main(void){return 0;}\n' > "$pool2d/crashes/CRASH-0001/harness.c"
before2d="$(cat "$pool2d/crashes/CRASH-0001/sanitizer.txt")"
_reverify_pool_crash_rates "$pool2d" "$tgt2d" test &

# ── T3 fixture: a crash already carrying a measured footer is left untouched
# (the cost guard skips it, so this launch returns fast) ──
pool3="$TEST_TMPDIR/pool3"; tgt3="$TEST_TMPDIR/tgt3"
_make_target_root "$tgt3" crash
mkdir -p "$pool3/crashes/CRASH-0001"
cat > "$pool3/crashes/CRASH-0001/sanitizer.txt" <<'TXT'
==4242==ERROR: AddressSanitizer: heap-use-after-free
SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free
CRASH_RATE: 3/5
TXT
before3="$(cat "$pool3/crashes/CRASH-0001/sanitizer.txt")"
_reverify_pool_crash_rates "$pool3" "$tgt3" test &

# ── T4 fixture: unresolvable binary → sanitizer.txt unchanged, rate stays '?'.
# The pass must still exit 0, so capture its rc from the background job. ──
pool5="$TEST_TMPDIR/pool5"; tgt5="$TEST_TMPDIR/tgt5"
mkdir -p "$tgt5"                              # target.toml present but no build-asan/stub
cat > "$tgt5/target.toml" <<'TOML'
target = "reverify-stub"
asan_bin = "build-asan/src/stub"
[sanitizer]
enabled = ["asan"]
TOML
_make_footerless_crash "$pool5/crashes/CRASH-0001"
before5="$(cat "$pool5/crashes/CRASH-0001/sanitizer.txt")"
( _reverify_pool_crash_rates "$pool5" "$tgt5" test; echo $? > "$TEST_TMPDIR/rc5.out" ) &

# ── T6 fixture: split layout — target.toml in output/<slug>, build in
# target_root. reverify reads the toml from the CONFIG dir keyed by TARGET_SLUG
# and resolves asan_bin under target_root (no double build-asan). ──
slug6="reverify-split-$$"
cfgdir6="$SCRIPT_ROOT/output/$slug6"
tgt6="$TEST_TMPDIR/tgt6"; pool6="$TEST_TMPDIR/pool6"
mkdir -p "$cfgdir6" "$tgt6/build-asan/src"
cat > "$cfgdir6/target.toml" <<'TOML'
target = "reverify-split"
asan_bin = "build-asan/src/stub"
[sanitizer]
enabled = ["asan"]
TOML
cat > "$tgt6/build-asan/src/stub" <<'SH'
#!/usr/bin/env bash
echo "==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010"
echo "SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free"
exit 1
SH
chmod +x "$tgt6/build-asan/src/stub"
_make_footerless_crash "$pool6/crashes/CRASH-0001"
( TARGET_SLUG="$slug6"; _reverify_pool_crash_rates "$pool6" "$tgt6" test ) &

# ── T7 fixture: split layout with AUDIT_BUILD_SUFFIX rewrites bare build-asan/ ──
slug7="reverify-suffix-$$"
cfgdir7="$SCRIPT_ROOT/output/$slug7"
tgt7="$TEST_TMPDIR/tgt7"; pool7="$TEST_TMPDIR/pool7"
mkdir -p "$cfgdir7" "$tgt7/build-asan-img42/src"
cat > "$cfgdir7/target.toml" <<'TOML'
target = "reverify-suffix"
asan_bin = "build-asan/src/stub"
[sanitizer]
enabled = ["asan"]
TOML
cat > "$tgt7/build-asan-img42/src/stub" <<'SH'
#!/usr/bin/env bash
echo "==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010"
echo "SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free"
exit 1
SH
chmod +x "$tgt7/build-asan-img42/src/stub"
_make_footerless_crash "$pool7/crashes/CRASH-0001"
( TARGET_SLUG="$slug7"; AUDIT_BUILD_SUFFIX="-img42"; _reverify_pool_crash_rates "$pool7" "$tgt7" test ) &

# ── T8 fixture: middle .. components are refused, matching target_resolve_path
# (asan_bin never resolves → sanitizer.txt unchanged, fast) ──
slug8="reverify-middle-dotdot-$$"
cfgdir8="$SCRIPT_ROOT/output/$slug8"
tgt8="$TEST_TMPDIR/tgt8"; pool8="$TEST_TMPDIR/pool8"
mkdir -p "$cfgdir8" "$tgt8/build-asan/src"
cat > "$cfgdir8/target.toml" <<'TOML'
target = "reverify-middle-dotdot"
asan_bin = "subdir/../build-asan/src/stub"
[sanitizer]
enabled = ["asan"]
TOML
cat > "$tgt8/build-asan/src/stub" <<'SH'
#!/usr/bin/env bash
echo "==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010"
echo "SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free"
exit 1
SH
chmod +x "$tgt8/build-asan/src/stub"
_make_footerless_crash "$pool8/crashes/CRASH-0001"
before8="$(cat "$pool8/crashes/CRASH-0001/sanitizer.txt")"
( TARGET_SLUG="$slug8"; _reverify_pool_crash_rates "$pool8" "$tgt8" test ) &

# ── T9 fixture: a crash that only fires under recorded CLI args (repro.cmd).
# The stub crashes ONLY when invoked with --boom; bare `stub <testcase>` runs
# clean. repro.cmd carries the args-only argv with {TESTCASE} at the position
# the bug needs. T9b reuses this same tgt9 stub WITHOUT repro.cmd. ──
pool9="$TEST_TMPDIR/pool9"; tgt9="$TEST_TMPDIR/tgt9"
mkdir -p "$tgt9/build-asan/src"
cat > "$tgt9/target.toml" <<'TOML'
target = "reverify-args"
asan_bin = "build-asan/src/stub"
[sanitizer]
enabled = ["asan"]
TOML
cat > "$tgt9/build-asan/src/stub" <<'SH'
#!/usr/bin/env bash
for a in "$@"; do [ "$a" = "--boom" ] && {
  echo "==4242==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010"
  echo "SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free"
  exit 1
}; done
echo "ran clean"; exit 0
SH
chmod +x "$tgt9/build-asan/src/stub"
_make_footerless_crash "$pool9/crashes/CRASH-0001"
printf -- '--boom {TESTCASE}\n' > "$pool9/crashes/CRASH-0001/repro.cmd"
_reverify_pool_crash_rates "$pool9" "$tgt9" test &

# ── T9b fixture: same crash WITHOUT repro.cmd → bare invocation, honest 0/5.
# Reuses tgt9's stub (created synchronously above, read-only here). ──
pool9b="$TEST_TMPDIR/pool9b"
_make_footerless_crash "$pool9b/crashes/CRASH-0001"
_reverify_pool_crash_rates "$pool9b" "$tgt9" test &

# All reverify passes launched; block until every one has written its footer.
wait
rc5="$(cat "$TEST_TMPDIR/rc5.out" 2>/dev/null)"

# ── Assertions (sanitizer.txt files are now fully written) ────────────────
# T1
assert_file_contains "$pool1/crashes/CRASH-0001/sanitizer.txt" '^CRASH_RATE: 5/5' \
  "T1: reproducing footer-less crash gets a measured 5/5 footer"

# T2
assert_file_contains "$pool2/crashes/CRASH-0001/sanitizer.txt" '^CRASH_RATE: 0/5' \
  "T2: non-reproducing crash records an honest 0/5"
assert_file_contains "$pool2/crashes/CRASH-0001/sanitizer.txt" 'heap-use-after-free child.c:91' \
  "T2b: non-reproducing crash keeps its original diagnostic (evidence preserved)"

# T2c
assert_eq "$before2c" "$(cat "$pool2c/crashes/CRASH-0001/sanitizer.txt")" \
  "T2c: invalid runner execution is left unmeasured (no fabricated 0/5)"

# T2d
assert_eq "$before2d" "$(cat "$pool2d/crashes/CRASH-0001/sanitizer.txt")" \
  "T2d: uncompiled source harness is not reverified through the CLI fallback"

# T3
assert_eq "$before3" "$(cat "$pool3/crashes/CRASH-0001/sanitizer.txt")" \
  "T3: a crash with a measured footer is never re-run (cost guard)"

# T4
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
grep -Eq 'CRASH_RATE.*\[0-9\].*\[0-9\]' "$BENCH_RUNNER"
assert_eq 0 $? "T5d: bin/benchmark bundle guard uses the same measured-rate regex"

# T6
assert_file_contains "$pool6/crashes/CRASH-0001/sanitizer.txt" '^CRASH_RATE: 5/5' \
  "T6: split layout (toml in output/<slug>) resolves build under target_root and measures 5/5"

# T7
assert_file_contains "$pool7/crashes/CRASH-0001/sanitizer.txt" '^CRASH_RATE: 5/5' \
  "T7: AUDIT_BUILD_SUFFIX rewrites target.toml build-asan path for reverify"

# T8
assert_eq "$before8" "$(cat "$pool8/crashes/CRASH-0001/sanitizer.txt")" \
  "T8: reverify refuses middle '..' components in asan_bin"

# T9
assert_file_contains "$pool9/crashes/CRASH-0001/sanitizer.txt" '^CRASH_RATE: 5/5' \
  "T9: repro.cmd argv is replayed through reverify (flag-dependent crash → 5/5)"

# T9b: guards that the argv path is the cause of T9's 5/5, not the stub
# crashing unconditionally.
assert_file_contains "$pool9b/crashes/CRASH-0001/sanitizer.txt" '^CRASH_RATE: 0/5' \
  "T9b: without repro.cmd the bare invocation runs clean (0/5)"

# The split-layout cases wrote their config under the real repo output/ tree.
rm -rf "$cfgdir6" "$cfgdir7" "$cfgdir8"

teardown_test_env
summary
