#!/usr/bin/env bash
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
PROBE="$SCRIPT_ROOT/bin/probe"

CXX_BIN="${CXX:-clang++}"
if ! command -v "$CXX_BIN" >/dev/null 2>&1 || ! command -v ar >/dev/null 2>&1; then
  pass "probe: C++ harness cache skipped (compiler/ar unavailable)"
  teardown_test_env
  summary
  exit 0
fi

mkdir -p "$RESULTS_DIR/scratch-1" "$TARGET_ROOT/build"
printf 'void audit_dummy_symbol(void) {}\n' > "$TARGET_ROOT/build/dummy.c"
"${CC:-clang}" -c "$TARGET_ROOT/build/dummy.c" -o "$TARGET_ROOT/build/dummy.o"
ar rcs "$TARGET_ROOT/build/libtarget.a" "$TARGET_ROOT/build/dummy.o"

cat > "$RESULTS_DIR/scratch-1/harness.cpp" <<'CPP'
#include <fstream>
#include <iostream>
#include <string>
int main(int argc, char **argv) {
  if (argc < 2) return 2;
  std::ifstream in(argv[1]);
  std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  std::cout << s.size() << "\n";
  return 0;
}
CPP

cat > "$RESULTS_DIR/scratch-1/testcase.txt" <<'EOF'
// TARGET: native/api.cpp:Parse:1
// HYPOTHESIS-ID: H-cpp
// CATEGORY: bounds
// MODE: generic
// HARNESS: harness.cpp
abc
EOF

export TARGET_ASAN_LIB="$TARGET_ROOT/build/libtarget.a"

first=$("$PROBE" --dry-run "$RESULTS_DIR/scratch-1/testcase.txt" 2>&1)
# Cache file name was renamed from `.asan` to `.bin` when probe gained
# support for compiled-language harnesses (Rust/Go/Swift) that are
# not ASan-instrumented unless the operator opts in.
assert_match 'built harness: .*harness\.cpp\..*\.bin' "$first" "probe: builds C++ HARNESS through cache"
assert_match 'mode=generic' "$first" "probe: C++ HARNESS routes through generic mode"

second=$("$PROBE" --dry-run "$RESULTS_DIR/scratch-1/testcase.txt" 2>&1)
assert_not_match 'built harness:' "$second" "probe: unchanged C++ HARNESS reuses cached binary"

cache_count=$(find "$RESULTS_DIR/scratch-1/.harness-cache" -type f -perm -111 -name 'harness.cpp.*.bin' | wc -l | tr -d ' ')
assert_eq "1" "$cache_count" "probe: C++ HARNESS cache key is stable"

cat > "$RESULTS_DIR/scratch-1/race-harness.cpp" <<'CPP'
int main(int, char **) { return 0; }
CPP

cat > "$RESULTS_DIR/scratch-1/race-testcase.txt" <<'EOF'
// TARGET: native/api.cpp:Parse:1
// HYPOTHESIS-ID: H-cpp-race
// CATEGORY: bounds
// MODE: generic
// HARNESS: race-harness.cpp
abc
EOF

fake_slow_cxx="$TEST_TMPDIR/fake-slow-cxx"
cat > "$fake_slow_cxx" <<'SH'
#!/usr/bin/env sh
count="${FAKE_CXX_COUNT:?}"
n=0
[ -f "$count" ] && n=$(cat "$count" 2>/dev/null || echo 0)
printf '%s\n' "$((n + 1))" > "$count"
out=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-o" ]; then
    shift
    out="$1"
  fi
  shift
done
[ -n "$out" ] || exit 2
python3 -c 'import time; time.sleep(0.2)'
cat > "$out" <<'BIN'
#!/usr/bin/env sh
exit 0
BIN
chmod +x "$out"
SH
chmod +x "$fake_slow_cxx"
race_count="$TEST_TMPDIR/fake-slow-cxx-count"
printf '0\n' > "$race_count"
race_out1="$TEST_TMPDIR/race-probe-1.out"
race_out2="$TEST_TMPDIR/race-probe-2.out"
CXX="$fake_slow_cxx" FAKE_CXX_COUNT="$race_count" \
  "$PROBE" --dry-run "$RESULTS_DIR/scratch-1/race-testcase.txt" >"$race_out1" 2>&1 &
race_pid1=$!
CXX="$fake_slow_cxx" FAKE_CXX_COUNT="$race_count" \
  "$PROBE" --dry-run "$RESULTS_DIR/scratch-1/race-testcase.txt" >"$race_out2" 2>&1 &
race_pid2=$!
race_rc1=0; wait "$race_pid1" || race_rc1=$?
race_rc2=0; wait "$race_pid2" || race_rc2=$?
race_built_count=$(cat "$race_count")
race_cache_count=$(find "$RESULTS_DIR/scratch-1/.harness-cache" -type f -perm -111 -name 'race-harness.cpp.*.bin' | wc -l | tr -d ' ')
assert_eq "0" "$race_rc1" "probe: first concurrent HARNESS build succeeds"
assert_eq "0" "$race_rc2" "probe: second concurrent HARNESS build succeeds"
assert_eq "1" "$race_built_count" "probe: concurrent HARNESS probes share one locked build"
assert_eq "1" "$race_cache_count" "probe: concurrent HARNESS probes leave one cached binary"

# ── Stale lock reaping: a lock whose owner process has died must not wedge
#    later probes for the full lock timeout.
race_bin=$(find "$RESULTS_DIR/scratch-1/.harness-cache" -type f -name 'race-harness.cpp.*.bin' | head -1)
stale_lock="${race_bin%.bin}.lock"

# Dead-owner case: owner file names a pid that has already exited.
rm -f "$race_bin"
mkdir "$stale_lock"
( exec true ) & stale_dead_pid=$!
wait "$stale_dead_pid" 2>/dev/null || true
printf 'pid=%s\nstarted=2020-01-01T00:00:00+0000\n' "$stale_dead_pid" > "$stale_lock/owner"
stale_out=$(CXX="$fake_slow_cxx" FAKE_CXX_COUNT="$race_count" \
  "$PROBE" --dry-run "$RESULTS_DIR/scratch-1/race-testcase.txt" 2>&1)
stale_rc=$?
assert_eq "0" "$stale_rc" "probe: reaps stale harness lock with dead owner and rebuilds"
assert_match 'reaped stale harness build lock' "$stale_out" "probe: announces stale-lock reap"
[ -x "$race_bin" ] && stale_rebuilt=1 || stale_rebuilt=0
assert_eq "1" "$stale_rebuilt" "probe: rebuilds harness after reaping dead-owner lock"
[ -d "$stale_lock" ] && stale_left=1 || stale_left=0
assert_eq "0" "$stale_left" "probe: stale lock directory removed after reap"

# Ownerless case: a lock dir with no owner file is reaped once it is older
# than the grace window (PROBE_HARNESS_LOCK_STALE_MIN=0 forces this).
rm -f "$race_bin"
mkdir "$stale_lock"
ownerless_out=$(PROBE_HARNESS_LOCK_STALE_MIN=0 CXX="$fake_slow_cxx" FAKE_CXX_COUNT="$race_count" \
  "$PROBE" --dry-run "$RESULTS_DIR/scratch-1/race-testcase.txt" 2>&1)
ownerless_rc=$?
assert_eq "0" "$ownerless_rc" "probe: reaps ownerless stale lock under zero grace"
assert_match 'reaped stale harness build lock' "$ownerless_out" "probe: announces ownerless stale-lock reap"

fake_success_cxx="$TEST_TMPDIR/fake-success-cxx"
cat > "$fake_success_cxx" <<'SH'
#!/usr/bin/env sh
args="${FAKE_CXX_ARGS:?}"
out=""
: > "$args"
while [ "$#" -gt 0 ]; do
  printf '%s\n' "$1" >> "$args"
  if [ "$1" = "-o" ]; then
    shift
    out="$1"
    printf '%s\n' "$1" >> "$args"
  fi
  shift
done
[ -n "$out" ] || exit 2
cat > "$out" <<'BIN'
#!/usr/bin/env sh
echo TESTCASE_EXECUTED
BIN
chmod +x "$out"
SH
chmod +x "$fake_success_cxx"

slug_dir="$TEST_TMPDIR/defined-session/output/defined-target"
defined_results="$slug_dir/codex/results"
defined_target="$TEST_TMPDIR/defined-target-root"
mkdir -p "$defined_results/scratch-1" "$defined_target/build" "$slug_dir" "$TEST_TMPDIR/logs-defined"
printf 'void audit_defined_symbol(void) {}\n' > "$defined_target/build/dummy.c"
"${CC:-clang}" -c "$defined_target/build/dummy.c" -o "$defined_target/build/dummy.o"
ar rcs "$defined_target/build/libtarget.a" "$defined_target/build/dummy.o"
cat > "$slug_dir/.session-env" <<EOF_ENV
RESULTS_DIR=$defined_results
TARGET_ROOT=$defined_target
TARGET_SLUG=defined-target
TARGET_REV=test
LOGDIR=$TEST_TMPDIR/logs-defined
EOF_ENV
cat > "$slug_dir/target.toml" <<EOF_TOML
target = "defined-target"
asan_lib = "build/libtarget.a"
includes = ["include"]
defines = ["-DPROBE_TARGET_DEFINE=1", "-DSECOND_DEFINE=2"]
link_libs = ["-lm"]
[sanitizer]
enabled = ["asan"]
EOF_TOML
cat > "$defined_results/scratch-1/defined-harness.cpp" <<'CPP'
#ifndef PROBE_TARGET_DEFINE
#error missing target define
#endif
int main(int, char **) { return SECOND_DEFINE == 2 ? 0 : 1; }
CPP
cat > "$defined_results/scratch-1/defined-testcase.txt" <<'EOF_TC'
// TARGET: native/api.cpp:Parse:1
// HYPOTHESIS-ID: H-cpp-defines
// CATEGORY: bounds
// MODE: generic
// HARNESS: defined-harness.cpp
abc
EOF_TC
defined_args="$TEST_TMPDIR/fake-defined-args"
defined_out=$(env \
  CXX="$fake_success_cxx" \
  FAKE_CXX_ARGS="$defined_args" \
  "$PROBE" --dry-run "$defined_results/scratch-1/defined-testcase.txt" 2>&1)
assert_match 'built harness:' "$defined_out" "probe: target.toml defines allow C++ HARNESS build"
assert_file_contains "$defined_args" "^-DPROBE_TARGET_DEFINE=1$" \
  "probe: C++ HARNESS receives target.toml defines"
assert_file_contains "$defined_args" "^-DSECOND_DEFINE=2$" \
  "probe: C++ HARNESS receives all target.toml defines"

for san in ubsan msan tsan; do
  case "$san" in
    ubsan) upper=UBSAN; flag=undefined ;;
    msan)  upper=MSAN;  flag=memory ;;
    tsan)  upper=TSAN;  flag=thread ;;
  esac
  san_build="$TARGET_ROOT/build-$san"
  mkdir -p "$san_build"
  san_lib="$san_build/libtarget-$san.a"
  printf 'fake archive for %s\n' "$san" > "$san_lib"
  args_file="$TEST_TMPDIR/fake-${san}-args"
  out=$(env \
    CXX="$fake_success_cxx" \
    FAKE_CXX_ARGS="$args_file" \
    PROBE_SANITIZER="$san" \
    PROBE_ALLOW_DISABLED_SANITIZER=1 \
    "TARGET_${upper}_LIB=$san_lib" \
    "$PROBE" --dry-run "$RESULTS_DIR/scratch-1/testcase.txt" 2>&1)
  assert_file_contains "$args_file" "fsanitize=$flag" \
    "probe: C++ HARNESS ${san} uses selected sanitizer flag"
  assert_file_contains "$args_file" "libtarget-${san}\\.a" \
    "probe: C++ HARNESS ${san} links selected sanitizer lib"
  assert_match "sanitizer=${san}" "$out" "probe: C++ HARNESS ${san} dry-run records selected sanitizer"
  assert_match "run-sanitizer-multi ${san} generic" "$out" "probe: C++ HARNESS ${san} routes through the generic multi-run wrapper"
  assert_not_match "run-asan-multi" "$out" "probe: C++ HARNESS ${san} does not use the legacy ASan-only wrapper"
done

# Missing sanitizer-lib fallback: when ubsan_lib/msan_lib/tsan_lib is
# configured but the file does not exist on disk, probe must WARN and
# continue with `-fsanitize=<flag>` alone — many real bugs are catchable
# from just the runtime hooks, and agents should not conclude
# "sanitizer unsupported" when the operator simply hasn't built an
# instrumented archive of the target. ASan remains a hard failure
# because without asan_lib there's nothing to link.
for san in ubsan msan tsan; do
  case "$san" in
    ubsan) upper=UBSAN; flag=undefined ;;
    msan)  upper=MSAN;  flag=memory ;;
    tsan)  upper=TSAN;  flag=thread ;;
  esac
  san_build="$TARGET_ROOT/build-$san"
  missing_lib="$san_build/libtarget-${san}-MISSING.a"
  # Ensure the file is genuinely absent.
  rm -f "$missing_lib"
  args_file="$TEST_TMPDIR/fake-${san}-missing-args"
  rm -f "$args_file"
  out=$(env \
    CXX="$fake_success_cxx" \
    FAKE_CXX_ARGS="$args_file" \
    PROBE_SANITIZER="$san" \
    PROBE_ALLOW_DISABLED_SANITIZER=1 \
    "TARGET_${upper}_LIB=$missing_lib" \
    "$PROBE" --dry-run "$RESULTS_DIR/scratch-1/testcase.txt" 2>&1)
  assert_match "${san}_lib missing" "$out" \
    "probe: missing ${san} lib emits warning instead of hard-failing"
  assert_match "building with -fsanitize=$flag only" "$out" \
    "probe: missing ${san} lib message names fallback strategy"
  assert_file_contains "$args_file" "fsanitize=$flag" \
    "probe: missing ${san} lib still passes -fsanitize=$flag to compiler"
  if grep -q "libtarget-${san}-MISSING\\.a" "$args_file" 2>/dev/null; then
    fail "probe: missing ${san} lib not linked when absent" "compiler args include missing path"
  else
    pass "probe: missing ${san} lib not linked when absent"
  fi
done

# PROBE_REQUIRE_SANITIZER_LIB=1 restores the strict behavior for users
# who want to guarantee the target is instrumented.
missing_lib="$TARGET_ROOT/build-ubsan/libtarget-ubsan-STRICT.a"
rm -f "$missing_lib"
strict_rc=0
strict_out=$(env \
  CXX="$fake_success_cxx" \
  FAKE_CXX_ARGS="$TEST_TMPDIR/fake-ubsan-strict-args" \
  PROBE_SANITIZER=ubsan \
  PROBE_ALLOW_DISABLED_SANITIZER=1 \
  PROBE_REQUIRE_SANITIZER_LIB=1 \
  TARGET_UBSAN_LIB="$missing_lib" \
  "$PROBE" --dry-run "$RESULTS_DIR/scratch-1/testcase.txt" 2>&1) || strict_rc=$?
assert_eq "2" "$strict_rc" "probe: PROBE_REQUIRE_SANITIZER_LIB=1 makes missing ubsan_lib a hard fail"
assert_match "ubsan_lib missing" "$strict_out" "probe: strict-mode error names the missing lib"

# Missing ASan lib remains a hard failure regardless of the require flag
# (without asan_lib there is no instrumented archive to link).
missing_asan_lib="$TARGET_ROOT/build/libtarget-asan-MISSING.a"
rm -f "$missing_asan_lib"
asan_strict_rc=0
asan_strict_out=$(env \
  CXX="$fake_success_cxx" \
  FAKE_CXX_ARGS="$TEST_TMPDIR/fake-asan-strict-args" \
  PROBE_SANITIZER=asan \
  PROBE_ALLOW_DISABLED_SANITIZER=1 \
  TARGET_ASAN_LIB="$missing_asan_lib" \
  "$PROBE" --dry-run "$RESULTS_DIR/scratch-1/testcase.txt" 2>&1) || asan_strict_rc=$?
assert_eq "2" "$asan_strict_rc" "probe: missing asan_lib is still a hard fail (no fallback)"
assert_match "asan_lib missing" "$asan_strict_out" "probe: missing asan_lib error logged"

cat > "$RESULTS_DIR/scratch-1/bad-harness.txt" <<'EOF'
// TARGET: native/api.cpp:Parse:1
// HYPOTHESIS-ID: H-cpp-bad
// CATEGORY: bounds
// MODE: generic
// HARNESS: ../harness.cpp
abc
EOF
bad_rc=0
bad_out=$("$PROBE" --dry-run "$RESULTS_DIR/scratch-1/bad-harness.txt" 2>&1) || bad_rc=$?
assert_eq "2" "$bad_rc" "probe: HARNESS traversal exits 2"
assert_match 'HARNESS must stay under the testcase directory' "$bad_out" \
  "probe: HARNESS traversal rejected before build"

cat > "$RESULTS_DIR/scratch-1/fail-harness.cpp" <<'CPP'
int main(void) { return 0; }
CPP

cat > "$RESULTS_DIR/scratch-1/fail-testcase.txt" <<'EOF'
// TARGET: native/api.cpp:Parse:1
// HYPOTHESIS-ID: H-cpp-fail
// CATEGORY: bounds
// MODE: generic
// HARNESS: fail-harness.cpp
abc
EOF

fake_cxx="$TEST_TMPDIR/fake-cxx"
cat > "$fake_cxx" <<'SH'
#!/usr/bin/env sh
count="${FAKE_CXX_COUNT:?}"
n=0
[ -f "$count" ] && n=$(cat "$count" 2>/dev/null || echo 0)
printf '%s\n' "$((n + 1))" > "$count"
i=1
while [ "$i" -le 220 ]; do
  printf 'FAKE-COMPILER-LINE-%03d ' "$i" >&2
  printf '%080d\n' "$i" >&2
  i=$((i + 1))
done
exit 1
SH
chmod +x "$fake_cxx"
fake_count="$TEST_TMPDIR/fake-cxx-count"
printf '0\n' > "$fake_count"

fail_rc=0
fail_out=$(CXX="$fake_cxx" FAKE_CXX_COUNT="$fake_count" \
  PROBE_BUILD_LOG_HEAD_BYTES=700 PROBE_BUILD_LOG_TAIL_BYTES=700 \
  "$PROBE" --dry-run "$RESULTS_DIR/scratch-1/fail-testcase.txt" 2>&1) || fail_rc=$?
assert_eq "2" "$fail_rc" "probe: failed HARNESS build exits 2"
assert_match 'full compiler log:' "$fail_out" "probe: failed HARNESS build prints full log path"
assert_match 'compiler log elided' "$fail_out" "probe: failed HARNESS build prints capped digest"
assert_match 'FAKE-COMPILER-LINE-001' "$fail_out" "probe: failed HARNESS digest includes compiler log head"
assert_match 'FAKE-COMPILER-LINE-220' "$fail_out" "probe: failed HARNESS digest includes compiler log tail"
assert_not_match 'FAKE-COMPILER-LINE-120' "$fail_out" "probe: failed HARNESS digest omits middle of huge compiler log"
fail_log=$(printf '%s\n' "$fail_out" | sed -n 's/^.*full compiler log: //p' | tail -1)
assert_file_exists "$fail_log" "probe: failed HARNESS build saves full compiler log"
assert_file_contains "$fail_log" 'FAKE-COMPILER-LINE-120' \
  "probe: saved full compiler log retains omitted middle"

cached_rc=0
cached_out=$(CXX="$fake_cxx" FAKE_CXX_COUNT="$fake_count" \
  PROBE_BUILD_LOG_HEAD_BYTES=700 PROBE_BUILD_LOG_TAIL_BYTES=700 \
  "$PROBE" --dry-run "$RESULTS_DIR/scratch-1/fail-testcase.txt" 2>&1) || cached_rc=$?
assert_eq "2" "$cached_rc" "probe: cached HARNESS build failure exits 2"
assert_match 'cached harness build failure' "$cached_out" "probe: failed HARNESS build is cached by config hash"
assert_eq "1" "$(cat "$fake_count")" "probe: cached HARNESS build failure does not rerun compiler"

teardown_test_env
summary
