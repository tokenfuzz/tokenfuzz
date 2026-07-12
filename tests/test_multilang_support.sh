#!/usr/bin/env bash
# Tests for the multi-language audit pipeline:
#   * [sanitizer] enabled = [] is honored (findings-only mode)
#   * [runner] table is parsed and exposed via TARGET_RUNNER_* vars
#   * target_runner_args_for_testcase substitutes {TESTCASE}
#   * bin/probe routes through [runner] when no asan_bin is configured
#   * bin/probe --dry-run prints the right command for compiled +
#     interpreted // HARNESS: extensions (.rs, .go, .py, .rb, .js, .ts,
#     .java, .kt, .kts, .pl, .php, .sh)
#   * bin/run-asan generic invokes a runner binary without ASAN_OPTIONS
#     when the target is findings-only
#   * The 'race' sanitizer slug is accepted
#   * bin/find-seed picks up language file globs
#   * lib/target_config.py.language_runner_defaults covers every
#     supported build_system
#   * setup-target / seed_toml emits [sanitizer] enabled = [] for
#     non-native build systems
#   * Python runner and sanitizer dispatch cover findings-only targets

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# ───────────────────────────────────────────────────────────────────
# 4. bin/find-seed includes language file globs
# ───────────────────────────────────────────────────────────────────

# Verify the find-seed source mentions all the language globs we added.
# This is a structural check — we don't run the script because seed-root
# discovery needs a populated TARGET_ROOT tree.
assert_file_contains "$SCRIPT_ROOT/bin/find-seed" "\\*\\.py" "find-seed: Python glob"
assert_file_contains "$SCRIPT_ROOT/bin/find-seed" "\\*\\.rb" "find-seed: Ruby glob"
assert_file_contains "$SCRIPT_ROOT/bin/find-seed" "\\*\\.go" "find-seed: Go glob"
assert_file_contains "$SCRIPT_ROOT/bin/find-seed" "\\*\\.rs" "find-seed: Rust glob"
assert_file_contains "$SCRIPT_ROOT/bin/find-seed" "\\*\\.java" "find-seed: Java glob"
assert_file_contains "$SCRIPT_ROOT/bin/find-seed" "\\*\\.kt" "find-seed: Kotlin glob"
assert_file_contains "$SCRIPT_ROOT/bin/find-seed" "\\*\\.kts" "find-seed: Kotlin script glob"
assert_file_contains "$SCRIPT_ROOT/bin/find-seed" "\\*\\.swift" "find-seed: Swift glob"
assert_file_contains "$SCRIPT_ROOT/bin/find-seed" "\\*\\.ts" "find-seed: TypeScript glob"
assert_file_contains "$SCRIPT_ROOT/bin/find-seed" "spec_\\*" "find-seed: spec_ prefix recognized"

# ───────────────────────────────────────────────────────────────────
# 5. bin/probe // HARNESS: extension whitelist
# ───────────────────────────────────────────────────────────────────

# Use --dry-run to assert the dispatch decision without actually
# building / running anything. The session-env fixture lives under
# RESULTS_DIR so probe's auto-discovery finds it.
#
# Speed: every bin/probe invocation costs ~0.2-0.9s (config discovery +
# python3 helpers) and sections 5-6 make ~38 of them, which dominated
# this suite's wall clock when run sequentially. So all fixtures are
# written first, every probe call is launched in parallel (calls that
# need different target.toml contents get their own isolated session
# tree via mk_probe_tree, so concurrent probes never observe another
# case's config), and the assertions then read the captured outputs.
# Assertion names, patterns, and meanings are identical to the
# sequential version.
RESULTS_DIR="$TEST_TMPDIR/output/multilang/codex/results"
export RESULTS_DIR
slug_dir="$TEST_TMPDIR/output/multilang"
mkdir -p "$RESULTS_DIR/scratch-1" "$slug_dir"
cat > "$RESULTS_DIR/.session-env" <<EOF
RESULTS_DIR=$RESULTS_DIR
TARGET_ROOT=$TARGET_ROOT
TARGET_SLUG=multilang
TARGET_REV=HEAD
LOGDIR=$LOGDIR
EOF
cat > "$slug_dir/target.toml" <<'EOF'
target = "multilang"
build_system = "python"
[sanitizer]
enabled = []
[runner]
bin = "python3"
args = ["{TESTCASE}"]
EOF

PROBE_OUT_DIR="$TEST_TMPDIR/probe-out"
mkdir -p "$PROBE_OUT_DIR"

# mk_probe_tree <name>: build an isolated output/<slug> session tree
# (own backend results session, scratch-1, logs) with target.toml read from
# stdin. probe discovers the nearest session tree above its testcase, so
# testcases placed inside the tree see only that tree's config.
mk_probe_tree() {
  local root="$TEST_TMPDIR/pt-$1"
  mkdir -p "$root/output/multilang/codex/results/scratch-1" "$root/logs"
  cat > "$root/output/multilang/target.toml"
  cat > "$root/output/multilang/codex/results/.session-env" <<EOF
RESULTS_DIR=$root/output/multilang/codex/results
TARGET_ROOT=$TARGET_ROOT
TARGET_SLUG=multilang
TARGET_REV=HEAD
LOGDIR=$root/logs
EOF
}

pt_scratch() { printf '%s/pt-%s/output/multilang/codex/results/scratch-1' "$TEST_TMPDIR" "$1"; }

real_path_of() {
  printf '%s/%s' "$(cd "$(dirname "$1")" && pwd -P)" "$(basename "$1")"
}

# launch_probe <id> [VAR=VAL ...] <probe-arg>... — run bin/probe in the
# background with optional extra environment; stdout+stderr land in
# $PROBE_OUT_DIR/<id>.out and the exit code in $PROBE_OUT_DIR/<id>.rc.
launch_probe() {
  local id="$1"; shift
  local envs=()
  while [ $# -gt 0 ]; do
    case "$1" in
      *=*) envs+=("$1"); shift ;;
      *)   break ;;
    esac
  done
  (
    if [ "${#envs[@]}" -gt 0 ]; then
      env "${envs[@]}" "$SCRIPT_ROOT/bin/probe" "$@" \
        > "$PROBE_OUT_DIR/$id.out" 2>&1
    else
      "$SCRIPT_ROOT/bin/probe" "$@" > "$PROBE_OUT_DIR/$id.out" 2>&1
    fi
    echo "$?" > "$PROBE_OUT_DIR/$id.rc"
  ) &
}

probe_out() { cat "$PROBE_OUT_DIR/$1.out"; }
probe_rc()  { cat "$PROBE_OUT_DIR/$1.rc"; }

probe_dry_check() {
  local label="$1" id="$2" expect="$3"
  out=$(probe_out "$id")
  if grep -qE "$expect" <<<"$out"; then
    pass "$label"
  else
    fail "$label" "out: $out"
  fi
}

# ── Fixtures for every probe call in sections 5-6 (no probes yet) ──

# Findings-only target: probe should route through the runner
cat > "$RESULTS_DIR/scratch-1/tc.py" <<'EOF'
# TARGET: demo:main:1
# HYPOTHESIS-ID: H1
# CATEGORY: state
print("ok")
EOF

mkdir -p "$TARGET_ROOT/node_modules/.bin"
cat > "$TARGET_ROOT/node_modules/.bin/ts-node" <<'SH'
#!/usr/bin/env bash
echo "TS_NODE_ARGV=$*"
SH
chmod +x "$TARGET_ROOT/node_modules/.bin/ts-node"
mk_probe_tree ts <<'EOF'
target = "multilang"
build_system = "npm"
[sanitizer]
enabled = []
[runner]
bin = "node"
args = ["{TESTCASE}"]
EOF
cat > "$(pt_scratch ts)/tc.ts" <<'EOF'
TARGET: demo:main:1
HYPOTHESIS-ID: H_ts_runner
CATEGORY: state
console.log("TESTCASE_EXECUTED");
EOF
# Dry-run probe gets its own copy: both probes materialize the stripped
# testcase at .probe-exec/<name>.<sha1>.exec.ts, and two concurrent
# writers of the same exec path would race.
cp "$(pt_scratch ts)/tc.ts" "$(pt_scratch ts)/tc-dry.ts"

# A runner binary containing a slash is target-relative. Keep the committed
# Rust sample on that normal resolution path instead of putting argument-only
# placeholders in [runner].bin.
mkdir -p "$TARGET_ROOT/target/release"
cat > "$TARGET_ROOT/target/release/sample-rust" <<'SH'
#!/usr/bin/env bash
echo "RUST_RUNNER_ARG=$1"
echo "TESTCASE_EXECUTED"
SH
chmod +x "$TARGET_ROOT/target/release/sample-rust"
mk_probe_tree rustrel < "$SCRIPT_ROOT/output/samples/sample-rust/target.toml"
cat > "$(pt_scratch rustrel)/tc.txt" <<'EOF'
TARGET: demo:main:1
HYPOTHESIS-ID: H_rust_relative_runner
CATEGORY: state
payload
EOF

for san in ubsan msan tsan; do
  san_bin="$TARGET_ROOT/${san}-runner"
  cat > "$san_bin" <<'SH'
#!/usr/bin/env bash
echo "TESTCASE_EXECUTED"
SH
  chmod +x "$san_bin"
  mk_probe_tree "sandry-${san}" <<EOF
target = "multilang"
[sanitizer]
enabled = ["$san"]
${san}_bin = "$san_bin"
EOF
  cat > "$(pt_scratch "sandry-${san}")/${san}-tc.dat" <<EOF
TARGET: demo:main:1
HYPOTHESIS-ID: H_${san}
CATEGORY: state
payload
EOF
done

cat > "$TARGET_ROOT/asan-runner" <<'SH'
#!/usr/bin/env bash
echo "TESTCASE_EXECUTED"
SH
chmod +x "$TARGET_ROOT/asan-runner"
mk_probe_tree multisan <<EOF
target = "multilang"
asan_bin = "$TARGET_ROOT/asan-runner"
[sanitizer]
enabled = ["tsan", "asan"]
tsan_bin = "$TARGET_ROOT/tsan-runner"
EOF
# Each tree below gets its own copy of the multi-sanitizer payload so
# concurrent runs each write their own multi-san.asan.txt.
multi_san_body='TARGET: demo:main:1
HYPOTHESIS-ID: H_multi_san
CATEGORY: state
payload'
printf '%s\n' "$multi_san_body" > "$(pt_scratch multisan)/multi-san.dat"

for san in ubsan msan tsan; do
  san_bin="$TARGET_ROOT/${san}-exec-runner"
  cat > "$san_bin" <<'SH'
#!/usr/bin/env bash
for name in ASAN_OPTIONS UBSAN_OPTIONS MSAN_OPTIONS TSAN_OPTIONS; do
  if [ "${!name+x}" = "x" ]; then
    case "${!name}" in
      *halt_on_error=1*) echo "${name}_SET"; echo "${name}_VALUE=${!name}" ;;
      *)                 echo "${name}_PRESENT=${!name}" ;;
    esac
  else
    echo "${name}_UNSET"
  fi
done
echo "ARG1=$1"
echo "TESTCASE_EXECUTED"
SH
  chmod +x "$san_bin"
  mk_probe_tree "sanexec-${san}" <<EOF
target = "multilang"
[sanitizer]
enabled = ["$san"]
${san}_bin = "$san_bin"
${san}_options = "${san}_extra=1"
EOF
  printf '%s\n' "$multi_san_body" > "$(pt_scratch "sanexec-${san}")/multi-san.dat"
done

cat > "$TARGET_ROOT/swift-token-runner" <<'SH'
#!/usr/bin/env bash
echo "ARGV=$*"
echo "SWIFT_SAN=${SWIFT_SAN:-}"
echo "ACTIVE_SAN=${ACTIVE_SAN:-}"
echo "TESTCASE_EXECUTED"
SH
chmod +x "$TARGET_ROOT/swift-token-runner"
for san in asan ubsan tsan; do
  mk_probe_tree "swift-${san}" <<EOF
target = "multilang"
build_system = "swift"
[sanitizer]
enabled = ["$san"]
[runner]
bin = "$TARGET_ROOT/swift-token-runner"
args = ["-sanitize={SWIFT_SANITIZER}", "{SANITIZER}", "{TESTCASE}"]
env = ["SWIFT_SAN={SWIFT_SANITIZER}", "ACTIVE_SAN={SANITIZER}"]
EOF
  printf '%s\n' "$multi_san_body" > "$(pt_scratch "swift-${san}")/multi-san.dat"
done
mk_probe_tree swiftmsan <<EOF
target = "multilang"
build_system = "swift"
[sanitizer]
enabled = ["msan"]
[runner]
bin = "$TARGET_ROOT/swift-token-runner"
args = ["-sanitize={SWIFT_SANITIZER}", "{TESTCASE}"]
EOF
printf '%s\n' "$multi_san_body" > "$(pt_scratch swiftmsan)/multi-san.dat"

cat > "$TARGET_ROOT/race-exec-runner" <<'SH'
#!/usr/bin/env bash
for name in ASAN_OPTIONS UBSAN_OPTIONS MSAN_OPTIONS TSAN_OPTIONS; do
  if [ "${!name+x}" = "x" ]; then
    echo "${name}_PRESENT=${!name}"
  else
    echo "${name}_UNSET"
  fi
done
[ "${1:-}" = "-race" ] && echo "RACE_FLAG_SET" || echo "RACE_FLAG_MISSING"
echo "ARG2=${2:-}"
echo "TESTCASE_EXECUTED"
SH
chmod +x "$TARGET_ROOT/race-exec-runner"
mk_probe_tree race <<EOF
target = "multilang"
[sanitizer]
enabled = ["race"]
[runner]
bin = "$TARGET_ROOT/race-exec-runner"
args = ["-race", "{TESTCASE}"]
EOF
printf '%s\n' "$multi_san_body" > "$(pt_scratch race)/multi-san.dat"

# Harness-extension fixtures (run against the main findings-only tree).
# We can't actually build them, but the dry-run path validates the
# extension whitelist via a trivially-resolvable harness file.
for ext in py rb pl php js mjs ts java kt kts sh; do
  cat > "$RESULTS_DIR/scratch-1/harness.${ext}" <<'EOF'
# noop harness
EOF
  cat > "$RESULTS_DIR/scratch-1/tc-${ext}.txt" <<EOF
// TARGET: demo:main:1
// HYPOTHESIS-ID: Hx
// CATEGORY: state
// HARNESS: harness.${ext}
EOF
done

cat > "$RESULTS_DIR/scratch-1/sidecar-harness.sh" <<'EOF'
#!/usr/bin/env bash
echo "HARNESS_ARG1=$1"
echo "TESTCASE_EXECUTED"
EOF
cat > "$RESULTS_DIR/scratch-1/tc-sidecar.txt" <<'EOF'
// TARGET: demo:main:1
// HYPOTHESIS-ID: H_sidecar
// CATEGORY: state
// HARNESS: sidecar-harness.sh
EOF

# Unsupported extension fixture
cat > "$RESULTS_DIR/scratch-1/harness.bogus" <<'EOF'
EOF
cat > "$RESULTS_DIR/scratch-1/tc-bogus.txt" <<'EOF'
// TARGET: demo:main:1
// HYPOTHESIS-ID: H1
// CATEGORY: state
// HARNESS: harness.bogus
EOF

# End-to-end runner fixtures (section 6 assertions; main tree).
cat > "$RESULTS_DIR/scratch-1/runtest.py" <<'EOF'
# TARGET: demo:main:1
# HYPOTHESIS-ID: H_runner
# CATEGORY: state
print("TESTCASE_EXECUTED")
EOF
cat > "$RESULTS_DIR/scratch-1/bare-header.py" <<'EOF'
TARGET: demo:main:1
HYPOTHESIS-ID: H_runner_bare
CATEGORY: state
print("TESTCASE_EXECUTED")
EOF
cat > "$RESULTS_DIR/scratch-1/huge-output.py" <<'EOF'
# TARGET: demo:main:1
# HYPOTHESIS-ID: H_huge_output
# CATEGORY: state
print("A" * 4096)
print("TESTCASE_EXECUTED")
EOF
cat > "$RESULTS_DIR/scratch-1/huge-crash.py" <<'EOF'
# TARGET: demo:main:1
# HYPOTHESIS-ID: H_huge_crash
# CATEGORY: state
print("A" * 2048)
print("ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdeadbeef")
print("B" * 2048)
print("TESTCASE_EXECUTED")
EOF
cat > "$RESULTS_DIR/scratch-1/crashtest.py" <<'EOF'
# TARGET: demo:main:1
# HYPOTHESIS-ID: H_crash
# CATEGORY: state
raise RecursionError("forced")
EOF

# Runner args without {TESTCASE}: probe should append the testcase after
# configured args, matching docs/reference/target-toml.md.
cat > "$TEST_TMPDIR/argv-printer.sh" <<'SH'
#!/usr/bin/env bash
echo "ARGV=$*"
echo "TESTCASE_EXECUTED"
SH
chmod +x "$TEST_TMPDIR/argv-printer.sh"
mk_probe_tree notoken <<EOF
target = "multilang"
build_system = "custom"
[sanitizer]
enabled = []
[runner]
bin = "$TEST_TMPDIR/argv-printer.sh"
args = ["--flag"]
EOF
mk_probe_tree embtoken <<EOF
target = "multilang"
build_system = "custom"
[sanitizer]
enabled = []
[runner]
bin = "$TEST_TMPDIR/argv-printer.sh"
args = ["--input={TESTCASE}", "--flag"]
EOF
no_token_body='TARGET: runner
HYPOTHESIS-ID: H_runner_no_token
CATEGORY: state
payload'
printf '%s\n' "$no_token_body" > "$(pt_scratch notoken)/no-token.txt"
printf '%s\n' "$no_token_body" > "$(pt_scratch embtoken)/no-token.txt"

# ── Launch every probe call in parallel, then assert below ─────────

launch_probe pydry --dry-run "$RESULTS_DIR/scratch-1/tc.py"
launch_probe tsdry --dry-run "$(pt_scratch ts)/tc-dry.ts"
launch_probe tsreal "$(pt_scratch ts)/tc.ts"
launch_probe rustrel "$(pt_scratch rustrel)/tc.txt"
for san in ubsan msan tsan; do
  launch_probe "sandry-${san}" --dry-run "$(pt_scratch "sandry-${san}")/${san}-tc.dat"
done
launch_probe msdry --dry-run "$(pt_scratch multisan)/multi-san.dat"
launch_probe msasan PROBE_SANITIZER=asan --dry-run "$(pt_scratch multisan)/multi-san.dat"
launch_probe msbad PROBE_SANITIZER=msan --dry-run "$(pt_scratch multisan)/multi-san.dat"
launch_probe sanexec-ubsan ASAN_OPTIONS=leak UBSAN_OPTIONS=ubsan_env=1 \
  MSAN_OPTIONS=leak TSAN_OPTIONS=leak "$(pt_scratch sanexec-ubsan)/multi-san.dat"
launch_probe sanexec-msan ASAN_OPTIONS=leak UBSAN_OPTIONS=leak \
  MSAN_OPTIONS=msan_env=1 TSAN_OPTIONS=leak "$(pt_scratch sanexec-msan)/multi-san.dat"
launch_probe sanexec-tsan ASAN_OPTIONS=leak UBSAN_OPTIONS=leak \
  MSAN_OPTIONS=leak TSAN_OPTIONS=tsan_env=1 "$(pt_scratch sanexec-tsan)/multi-san.dat"
for san in asan ubsan tsan; do
  launch_probe "swift-${san}" SANITIZER_RUNS=1 "$(pt_scratch "swift-${san}")/multi-san.dat"
done
launch_probe swiftmsan "$(pt_scratch swiftmsan)/multi-san.dat"
launch_probe racedry --dry-run "$(pt_scratch race)/multi-san.dat"
launch_probe racereal ASAN_OPTIONS=leak UBSAN_OPTIONS=leak \
  MSAN_OPTIONS=leak TSAN_OPTIONS=leak "$(pt_scratch race)/multi-san.dat"
for ext in py rb pl php js mjs ts java kt kts sh; do
  launch_probe "ext-${ext}" --dry-run "$RESULTS_DIR/scratch-1/tc-${ext}.txt"
done
launch_probe sidecar PROBE_SANITIZER=runner "$RESULTS_DIR/scratch-1/tc-sidecar.txt"
launch_probe bogus --dry-run "$RESULTS_DIR/scratch-1/tc-bogus.txt"
launch_probe runtest "$RESULTS_DIR/scratch-1/runtest.py"
launch_probe bare "$RESULTS_DIR/scratch-1/bare-header.py"
launch_probe hugeout PROBE_ASAN_OUTPUT_MAX_BYTES=1024 PROBE_ASAN_OUTPUT_HEAD_BYTES=256 \
  PROBE_ASAN_OUTPUT_TAIL_BYTES=256 "$RESULTS_DIR/scratch-1/huge-output.py"
launch_probe hugecrash PROBE_ASAN_OUTPUT_MAX_BYTES=1024 PROBE_ASAN_OUTPUT_HEAD_BYTES=256 \
  PROBE_ASAN_OUTPUT_TAIL_BYTES=256 "$RESULTS_DIR/scratch-1/huge-crash.py"
launch_probe notoken "$(pt_scratch notoken)/no-token.txt"
launch_probe embtoken "$(pt_scratch embtoken)/no-token.txt"
launch_probe crashtest "$RESULTS_DIR/scratch-1/crashtest.py"
wait

# ── Section 5 assertions ───────────────────────────────────────────

probe_dry_check "probe runner: python3 routing" pydry "mode=generic"

rust_relative_out=$(probe_out rustrel)
assert_match "TESTCASE_EXECUTED" "$rust_relative_out" \
  "probe resolves committed Rust runner relative to target root"
assert_match "RUST_RUNNER_ARG=$(real_path_of "$(pt_scratch rustrel)/tc.txt")" \
  "$rust_relative_out" "probe passes testcase to target-relative Rust runner"

ts_dry=$(probe_out tsdry)
assert_match 'original_testcase=.*/tc-dry\.ts' "$ts_dry" \
  "probe keeps original TypeScript testcase path in dry-run metadata"
ts_real=$(probe_out tsreal)
assert_match 'TS_NODE_ARGV=--transpile-only --skip-project --compiler-options .* .*.exec\.ts' "$ts_real" \
  "probe routes TypeScript testcase through target-local ts-node when runner is node"

for san in ubsan msan tsan; do
  out=$(probe_out "sandry-${san}")
  assert_match "sanitizer=${san}" "$out" "probe sanitizer routing: ${san} selected from target.toml"
  assert_match "run-sanitizer-multi ${san} generic" "$out" "probe sanitizer routing: ${san} routed through the generic multi-run wrapper"
done

out=$(probe_out msdry)
assert_match "sanitizer=tsan" "$out" "probe sanitizer routing: first configured sanitizer wins by default"
assert_match "run-sanitizer-multi tsan generic" "$out" "probe sanitizer routing: default sanitizer routed through the generic multi-run wrapper"
out=$(probe_out msasan)
assert_match "sanitizer=asan" "$out" "probe sanitizer routing: PROBE_SANITIZER override selects ASan"
assert_match "run-sanitizer-multi asan generic" "$out" "probe sanitizer routing: ASan override routed through the generic multi-run wrapper"
bad_rc=$(probe_rc msbad)
bad_out=$(probe_out msbad)
assert_eq "2" "$bad_rc" "probe sanitizer routing: disabled sanitizer override exits 2"
assert_match "not enabled" "$bad_out" "probe sanitizer routing: disabled sanitizer override explains mismatch"

for san in ubsan msan tsan; do
  upper=$(printf '%s' "$san" | tr '[:lower:]' '[:upper:]')
  multi_san_real=$(real_path_of "$(pt_scratch "sanexec-${san}")/multi-san.dat")
  out=$(probe_out "sanexec-${san}")
  assert_match "${upper}_OPTIONS_SET" "$out" "probe sanitizer env: ${san} receives its own options"
  assert_match "${upper}_OPTIONS_VALUE=.*halt_on_error=1" "$out" "probe sanitizer env: ${san} options include halt_on_error"
  assert_match "${upper}_OPTIONS_VALUE=.*${san}_extra=1" "$out" "probe sanitizer env: ${san} options include target.toml extras"
  assert_match "${upper}_OPTIONS_VALUE=.*${san}_env=1" "$out" "probe sanitizer env: ${san} options append same-sanitizer env extras"
  case "$san" in
    ubsan)
      assert_match "UBSAN_OPTIONS_VALUE=.*print_stacktrace=1" "$out" "probe sanitizer env: ubsan options include stack traces"
      assert_match "UBSAN_OPTIONS_VALUE=.*print_summary=1" "$out" "probe sanitizer env: ubsan options include summaries"
      ;;
    msan)
      assert_match "MSAN_OPTIONS_VALUE=.*print_stats=0" "$out" "probe sanitizer env: msan options suppress stats"
      ;;
    tsan)
      assert_match "TSAN_OPTIONS_VALUE=.*second_deadlock_stack=1" "$out" "probe sanitizer env: tsan options include deadlock context"
      ;;
  esac
  for opt in ASAN UBSAN MSAN TSAN; do
    [ "$opt" = "$upper" ] && continue
    assert_match "${opt}_OPTIONS_UNSET" "$out" "probe sanitizer env: ${san} clears ${opt}_OPTIONS"
  done
  assert_match "ARG1=$multi_san_real" "$out" "probe sanitizer routing: ${san} execution receives testcase first"
  assert_file_contains "$(pt_scratch "sanexec-${san}")/multi-san.asan.txt" \
    "SANITIZER_RUN_HEADER: sanitizer=$san" \
    "probe sanitizer routing: ${san} output records selected sanitizer"
done

for san_pair in "asan address" "ubsan undefined" "tsan thread"; do
  san="${san_pair%% *}"
  swift_san="${san_pair#* }"
  multi_san_real=$(real_path_of "$(pt_scratch "swift-${san}")/multi-san.dat")
  out=$(probe_out "swift-${san}")
  assert_match "ARGV=-sanitize=${swift_san} ${san} ${multi_san_real}" "$out" \
    "probe runner tokens: ${san} expands Swift sanitizer flag"
  assert_match "SWIFT_SAN=${swift_san}" "$out" \
    "probe runner env tokens: ${san} expands SWIFT_SANITIZER"
  assert_match "ACTIVE_SAN=${san}" "$out" \
    "probe runner env tokens: ${san} expands SANITIZER"
done
swift_msan_rc=$(probe_rc swiftmsan)
swift_msan_out=$(probe_out swiftmsan)
assert_eq "2" "$swift_msan_rc" "probe runner tokens: Swift msan exits 2"
assert_match "Swift runner does not support sanitizer 'msan'" "$swift_msan_out" \
  "probe runner tokens: Swift msan reports unsupported sanitizer"

out=$(probe_out racedry)
assert_match "sanitizer=race" "$out" "probe sanitizer routing: race selected from target.toml"
assert_match "run-sanitizer-multi race generic" "$out" "probe sanitizer routing: race routed through the generic multi-run wrapper"
out=$(probe_out racereal)
for opt in ASAN UBSAN MSAN TSAN; do
  assert_match "${opt}_OPTIONS_UNSET" "$out" "probe sanitizer routing: race runner clears ${opt}_OPTIONS"
done
assert_match "RACE_FLAG_SET" "$out" "probe sanitizer routing: race runner receives race arg"
race_tc_real=$(real_path_of "$(pt_scratch race)/multi-san.dat")
assert_match "ARG2=$race_tc_real" "$out" "probe sanitizer routing: race runner receives testcase from runner args"

# Verify probe accepts each new harness extension: the routing must get
# past the extension whitelist (a later harness BUILD failure is fine —
# this machine may lack the toolchain — but it proves the extension was
# accepted). An empty capture means the probe never ran and must not
# pass as "accepted".
for ext in py rb pl php js mjs ts java kt kts sh; do
  out=$(probe_out "ext-${ext}")
  if grep -q 'unsupported extension' <<<"$out"; then
    fail "probe accepts // HARNESS: .${ext}" "out: $out"
  elif [ -z "$out" ]; then
    fail "probe accepts // HARNESS: .${ext}" \
      "probe produced no output at all (rc=$(probe_rc "ext-${ext}"))"
  else
    pass "probe accepts // HARNESS: .${ext}"
  fi
done

sidecar_real="$(cd "$(dirname "$RESULTS_DIR/scratch-1/tc-sidecar.txt")" && pwd -P)/tc-sidecar.txt"
out=$(probe_out sidecar)
assert_match "HARNESS_ARG1=$sidecar_real" "$out" "probe interpreted HARNESS receives testcase as first arg"
assert_match "TESTCASE_EXECUTED" "$out" "probe interpreted HARNESS executes sidecar, not testcase"

# Unsupported extension is rejected with a clear error
out=$(probe_out bogus)
assert_match "unsupported extension" "$out" "probe rejects // HARNESS: .bogus"

# ───────────────────────────────────────────────────────────────────
# 6. End-to-end: probe runs a Python testcase via the runner
# ───────────────────────────────────────────────────────────────────

real_out=$(probe_out runtest)
assert_match "TESTCASE_EXECUTED" "$real_out" "probe runs Python testcase end-to-end"
assert_match "EXECUTION VERIFIED" "$real_out" "probe records EXECUTION VERIFIED for clean run"

bare_out=$(probe_out bare)
assert_match "TESTCASE_EXECUTED" "$bare_out" "probe strips bare audit headers before runner execution"
bare_tc_real="$(cd "$(dirname "$RESULTS_DIR/scratch-1/bare-header.py")" && pwd -P)/bare-header.py"
if grep -Fq "testcase=$bare_tc_real" "$RESULTS_DIR/scratch-1/bare-header.asan.txt"; then
  pass "probe records original testcase path after bare-header stripping"
else
  fail "probe records original testcase path after bare-header stripping" \
    "ASAN header did not reference $bare_tc_real"
fi

huge_out=$(probe_out hugeout)
huge_asan="$RESULTS_DIR/scratch-1/huge-output.asan.txt"
huge_size=$(wc -c < "$huge_asan" | tr -d ' ')
[ "$huge_size" -lt 1200 ]
assert_eq 0 $? "probe caps oversized ASan output artifact for storage"
assert_file_contains "$huge_asan" "ASAN_OUTPUT_FILE truncated for storage after verdict classification" \
  "probe cap marker preserved in ASan output"
assert_match "NO CRASHES" "$huge_out" "probe still classifies capped clean output"

# Regression (FN): a crash marker buried in the omitted middle of an
# oversized log must still classify as CRASH. The verdict reads the full
# raw output; only the saved artifact is capped. Pre-fix the cap ran first
# and the buried diagnostic became NO_EXEC/CLEAN.
huge_crash_out=$(probe_out hugecrash)
huge_crash_asan="$RESULTS_DIR/scratch-1/huge-crash.asan.txt"
huge_crash_size=$(wc -c < "$huge_crash_asan" | tr -d ' ')
[ "$huge_crash_size" -lt 1200 ]
assert_eq 0 $? "probe still caps the stored artifact even when a buried crash is detected"
assert_match "verdict=CRASH" "$huge_crash_out" \
  "probe classifies crash buried in oversized output's omitted middle"

# Runner args without {TESTCASE}: probe should append the testcase after
# configured args, matching docs/reference/target-toml.md.
no_token_tc="$(pt_scratch notoken)/no-token.txt"
no_token_out=$(probe_out notoken)
no_token_tc_real=$(real_path_of "$no_token_tc")
if grep -Fq "ARGV=--flag $no_token_tc_real" <<< "$no_token_out"; then
  pass "probe appends canonical testcase after runner args without token"
else
  fail "probe appends canonical testcase after runner args without token" \
    "expected ARGV=--flag $no_token_tc_real in: $(head -3 <<< "$no_token_out")"
fi

embedded_token_out=$(probe_out embtoken)
emb_token_tc_real=$(real_path_of "$(pt_scratch embtoken)/no-token.txt")
if grep -Fq "ARGV=--input=$emb_token_tc_real --flag" <<< "$embedded_token_out"; then
  pass "probe does not append duplicate testcase when {TESTCASE} is embedded in a runner arg"
else
  fail "probe does not append duplicate testcase when {TESTCASE} is embedded in a runner arg" \
    "expected ARGV=--input=$emb_token_tc_real --flag in: $(head -3 <<< "$embedded_token_out")"
fi

# A testcase that raises a runtime error → INCONCLUSIVE (rc != 0).
crash_out=$(probe_out crashtest)
assert_match "Traceback" "$crash_out" "Python traceback in probe output"

# ───────────────────────────────────────────────────────────────────
# 7. lib/target_config.py language_runner_defaults coverage
# ───────────────────────────────────────────────────────────────────

# Every language slug in the LANGUAGE_RUNNERS map should produce a non-empty
# dict containing 'bin' + 'args' keys.
python3 - <<'PY'
import sys, pathlib
sys.path.insert(0, str(pathlib.Path("lib").resolve()))
import target_config as tc
languages = ["cargo","go","swift",
             "maven","gradle","kotlin","python","npm",
             "bundler","composer","rlang","perl"]
fail = 0
for lang in languages:
    d = tc.language_runner_defaults(lang)
    if not d.get("bin") or not d.get("args"):
        print(f"  \033[0;31m✗\033[0m {lang} missing bin/args: {d!r}")
        fail += 1
    else:
        print(f"  \033[0;32m✓\033[0m language_runner_defaults({lang!r}) has bin+args")
empty = tc.language_runner_defaults("nonexistent-build-sys")
if empty == {}:
    print("  \033[0;32m✓\033[0m language_runner_defaults(unknown) returns {}")
else:
    print(f"  \033[0;31m✗\033[0m language_runner_defaults(unknown) returned {empty!r}")
    fail += 1
py_env = tc.language_runner_defaults("python").get("env", [])
if any("PYTHONPATH={TARGET_ROOT}:{TARGET_ROOT}/src:{TARGET_ROOT}/lib" == x for x in py_env):
    print("  \033[0;32m✓\033[0m language_runner_defaults('python') sets target PYTHONPATH")
else:
    print(f"  \033[0;31m✗\033[0m python runner env missing target PYTHONPATH: {py_env!r}")
    fail += 1
go_env = tc.language_runner_defaults("go").get("env", [])
if "GOFLAGS=-mod=mod" in go_env and "GORACE=halt_on_error=1" in go_env:
    print("  \033[0;32m✓\033[0m language_runner_defaults('go') sets module and race runner env")
else:
    print(f"  \033[0;31m✗\033[0m go runner env missing GOFLAGS/GORACE: {go_env!r}")
    fail += 1
cargo_args = tc.language_runner_defaults("cargo").get("args", [])
if "--manifest-path" in cargo_args and "{TARGET_ROOT}/Cargo.toml" in cargo_args:
    print("  \033[0;32m✓\033[0m language_runner_defaults('cargo') pins the target manifest path")
else:
    print(f"  \033[0;31m✗\033[0m cargo runner args missing manifest path: {cargo_args!r}")
    fail += 1
swift_args = tc.language_runner_defaults("swift").get("args", [])
if (
    "--package-path" in swift_args
    and "{TARGET_ROOT}" in swift_args
    and "{TARGET_SLUG}" in swift_args
    and "-sanitize={SWIFT_SANITIZER}" in swift_args
):
    print("  \033[0;32m✓\033[0m language_runner_defaults('swift') runs the selected sanitizer package executable")
else:
    print(f"  \033[0;31m✗\033[0m swift runner args missing sanitizer package runner shape: {swift_args!r}")
    fail += 1
sys.exit(1 if fail else 0)
PY

python3 - <<'PY'
import os, pathlib, stat, sys, tempfile
sys.path.insert(0, str(pathlib.Path("lib").resolve()))
import target_config as tc

old_audit = os.environ.get("AUDIT_JAVA_HOME")
old_java = os.environ.get("JAVA_HOME")
try:
    fake_home = pathlib.Path(tempfile.mkdtemp(prefix="fake-jdk-"))
    bin_dir = fake_home / "bin"
    bin_dir.mkdir()
    java = bin_dir / "java"
    java.write_text("#!/usr/bin/env sh\necho 'openjdk version \"17\"' >&2\nexit 0\n")
    java.chmod(java.stat().st_mode | stat.S_IXUSR)
    os.environ["AUDIT_JAVA_HOME"] = str(fake_home)
    os.environ.pop("JAVA_HOME", None)
    d = tc.language_runner_defaults("maven")
    if d.get("bin") == str(java) and d.get("env") == [f"JAVA_HOME={fake_home}"]:
        print("  \033[0;32m✓\033[0m Java runner defaults prefer AUDIT_JAVA_HOME")
    else:
        print(f"  \033[0;31m✗\033[0m Java runner defaults did not use fake JDK: {d!r}")
        sys.exit(1)
finally:
    if old_audit is None:
        os.environ.pop("AUDIT_JAVA_HOME", None)
    else:
        os.environ["AUDIT_JAVA_HOME"] = old_audit
    if old_java is None:
        os.environ.pop("JAVA_HOME", None)
    else:
        os.environ["JAVA_HOME"] = old_java
PY

# ───────────────────────────────────────────────────────────────────
# 8. _detect_build_system: every recognized manifest maps to a slug
# ───────────────────────────────────────────────────────────────────

python3 - <<'PY'
import os, sys, tempfile, pathlib
sys.path.insert(0, str(pathlib.Path("lib").resolve()))
import target_config as tc

CASES = {
    "Cargo.toml": "cargo", "go.mod": "go",
    "Package.swift": "swift",
    "pom.xml": "maven", "build.gradle": "gradle",
    "build.gradle.kts": "gradle", "settings.gradle": "gradle",
    "Main.kts": "kotlin", "pyproject.toml": "python",
    "setup.py": "python",
    "package.json": "npm",
    "Gemfile": "bundler", "composer.json": "composer",
    "DESCRIPTION": "rlang", "Makefile.PL": "perl",
}
fail = 0
for manifest, expected_slug in CASES.items():
    d = pathlib.Path(tempfile.mkdtemp(prefix="bs-"))
    (d / manifest).write_text("")
    got = tc._detect_build_system(d)
    if got == expected_slug:
        print(f"  \033[0;32m✓\033[0m _detect_build_system({manifest}) = {got!r}")
    else:
        print(f"  \033[0;31m✗\033[0m _detect_build_system({manifest}): expected {expected_slug!r}, got {got!r}")
        fail += 1
# Native-build precedence: when CMakeLists.txt + Cargo.toml both present,
# cmake should win (most binding crates live inside a CMake-driven tree).
d = pathlib.Path(tempfile.mkdtemp(prefix="bs-poly-"))
(d / "CMakeLists.txt").write_text("")
(d / "Cargo.toml").write_text("")
if tc._detect_build_system(d) == "cmake":
    print("  \033[0;32m✓\033[0m _detect_build_system: cmake wins over cargo when both present")
else:
    print(f"  \033[0;31m✗\033[0m _detect_build_system: cmake should win over cargo")
    fail += 1
sys.exit(1 if fail else 0)
PY

# ───────────────────────────────────────────────────────────────────
# 9. seed_toml emits findings-only mode for language ecosystems
# ───────────────────────────────────────────────────────────────────

python3 - <<'PY'
import sys, pathlib, tempfile
sys.path.insert(0, str(pathlib.Path("lib").resolve()))
import target_config as tc

CASES = [
    ("python", "pyproject.toml"),
    ("cargo",  "Cargo.toml"),
    ("go",     "go.mod"),
    ("npm",    "package.json"),
    ("bundler","Gemfile"),
    ("composer","composer.json"),
    ("maven",  "pom.xml"),
    ("kotlin", "Main.kts"),
]
fail = 0
for slug, manifest in CASES:
    d = pathlib.Path(tempfile.mkdtemp(prefix=f"seed-{slug}-"))
    (d / manifest).write_text("")
    out = d / "target.toml"
    tc.seed_toml(d, out, "")
    text = out.read_text()
    if "enabled = []" in text and "[runner]" in text:
        print(f"  \033[0;32m✓\033[0m seed_toml({slug}) emits enabled=[] + [runner]")
    else:
        print(f"  \033[0;31m✗\033[0m seed_toml({slug}) missing enabled=[] or [runner]")
        fail += 1
    cfg = tc.Config()
    tc.load_toml_into(cfg, out)
    if cfg.sanitizers_explicitly_disabled and cfg.runner_bin:
        print(f"  \033[0;32m✓\033[0m {slug} round-trip: explicit disable + runner_bin set")
    else:
        print(f"  \033[0;31m✗\033[0m {slug} round-trip: explicit_disabled={cfg.sanitizers_explicitly_disabled} runner_bin={cfg.runner_bin!r}")
        fail += 1

# Native build systems and sanitizer-capable language runners (Swift, whose
# default runner drives a selected sanitizer build) keep the ["asan"]
# default.
for slug, manifest in [
    ("cmake", "CMakeLists.txt"),
    ("meson", "meson.build"),
    ("swift", "Package.swift"),
]:
    d = pathlib.Path(tempfile.mkdtemp(prefix=f"seed-native-{slug}-"))
    (d / manifest).write_text("")
    out = d / "target.toml"
    tc.seed_toml(d, out, "")
    text = out.read_text()
    if 'enabled = ["asan"]' in text and (slug != "swift" or "[runner]" in text):
        print(f"  \033[0;32m✓\033[0m seed_toml({slug}) keeps enabled=['asan']")
    else:
        print(f"  \033[0;31m✗\033[0m seed_toml({slug}) should default to asan; got: {text[text.find('[sanitizer]'):text.find('[sanitizer]')+200]!r}")
        fail += 1

sys.exit(1 if fail else 0)
PY


summary
