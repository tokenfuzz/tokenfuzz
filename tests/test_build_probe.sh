#!/usr/bin/env bash
# Tests for lib/build_probe.py — the target-agnostic build feature probe
# that detects stub TUs (compilation units whose source was guarded out
# by configure flags, producing only sanitizer-runtime ctor symbols).
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

PROBE="$SCRIPT_ROOT/lib/build_probe.py"

# ── Helpers ─────────────────────────────────────────────────────────

# Build a synthetic build tree: a real TU with a public function, a
# stub TU with only an asan runtime symbol, and an unknown TU with no
# nm signal. Source files in target_root mirror the .o basenames so
# the source-mapping heuristic resolves.
make_synth_build() {
  local target_root="$1" build_dir="$2"
  mkdir -p "$target_root/src" "$build_dir/CMakeFiles/lib.dir/src"

  cat > "$target_root/src/realtu.c" <<'C'
int realtu_compute(int x) { return x * 2; }
C
  cat > "$target_root/src/stubtu.c" <<'C'
/* stub: feature compiled out */
C

  # Compile each TU. Use cc (or clang/gcc) — skip the test if no compiler.
  local cc=""
  for cand in cc clang gcc; do
    if command -v "$cand" >/dev/null 2>&1; then cc="$cand"; break; fi
  done
  if [ -z "$cc" ]; then
    echo "SKIP: no C compiler available"
    return 1
  fi

  # Real TU: emit a deterministic external, non-runtime symbol. Using
  # assembly keeps the fixture independent of compiler defaults such as
  # function/data sectioning or visibility flags on CI images.
  cat > "$build_dir/_real.s" <<'S'
        .text
        .globl  realtu_compute
realtu_compute:
        .byte 0
S
  "$cc" -c "$build_dir/_real.s" -o "$build_dir/CMakeFiles/lib.dir/src/realtu.c.o" 2>/dev/null || return 1

  # Stub TU: an empty translation unit produces an object file with no
  # defined symbols. Our classifier treats empty defined-symbol sets as
  # "unknown" (fail-open), so to test stub detection we need a file
  # that *has* defined symbols but all of them match sanitizer-runtime
  # prefixes. Hand-craft one by assembling a tiny .s that defines only
  # such a symbol.
  cat > "$build_dir/_stub.s" <<'S'
        .text
        .globl  asan.module_ctor_x
asan.module_ctor_x:
        .byte 0
S
  "$cc" -c "$build_dir/_stub.s" -o "$build_dir/CMakeFiles/lib.dir/src/stubtu.c.o" 2>/dev/null || return 1

  return 0
}

# ── Test 1: --help works ───────────────────────────────────────────

if python3 "$PROBE" --help >/dev/null 2>&1; then
  pass "probe --help: succeeds"
else
  fail "probe --help: succeeds" "exit non-zero"
fi

# ── Test 2: probe a synthetic build ────────────────────────────────

synth_target="$TEST_TMPDIR/synth-target"
synth_build="$TEST_TMPDIR/synth-build"
mkdir -p "$synth_target" "$synth_build"

if make_synth_build "$synth_target" "$synth_build"; then
  features_json="$TEST_TMPDIR/features.json"
  if python3 "$PROBE" probe \
       --target-root "$synth_target" \
       --build-dir "$synth_build" \
       --sanitizer asan \
       --output "$features_json" >/dev/null 2>&1; then
    pass "probe: writes features.json"
  else
    fail "probe: writes features.json" "probe exited non-zero"
  fi
  assert_file_exists "$features_json" "features.json: file exists"

  if [ -f "$features_json" ]; then
    schema_version=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["schema_version"])' "$features_json" 2>/dev/null || echo "")
    assert_eq "1" "$schema_version" "features.json: schema_version=1"

    stub_count=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["stub_tus"]))' "$features_json" 2>/dev/null || echo "")
    if [ "${stub_count:-0}" -ge 1 ]; then
      pass "features.json: detected at least one stub TU"
    else
      fail "features.json: detected at least one stub TU" "stub_count=${stub_count}"
    fi

    real_count=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["compiled_tus"]))' "$features_json" 2>/dev/null || echo "")
    if [ "${real_count:-0}" -ge 1 ]; then
      pass "features.json: detected at least one compiled TU"
    else
      fail "features.json: detected at least one compiled TU" "real_count=${real_count}"
    fi
  fi
else
  echo "SKIP: synthetic build setup failed (no compiler or assembly failed)"
fi

# ── Test 3: is_tu_stub consumer API ────────────────────────────────

mkdir -p "$TEST_TMPDIR/consumer"
cat > "$TEST_TMPDIR/consumer/features.json" <<'JSON'
{
  "schema_version": 1,
  "probed_at": "2026-05-24T00:00:00Z",
  "target_root": "/fake",
  "build_dir": "/fake/build",
  "sanitizer": "asan",
  "binary": {"path": "", "version_output": "", "help_output": "", "features": [], "protocols": []},
  "configure_summary": "",
  "stub_tus": ["lib/vtls/openssl.c", "lib/vssh/libssh.c"],
  "compiled_tus": ["lib/url.c"],
  "probed_object_count": 3,
  "notes": []
}
JSON

stub_result=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - "$TEST_TMPDIR/consumer/features.json" <<'PY'
import sys
import build_probe as bp
features = bp.load_features(sys.argv[1])
checks = [
    ("openssl-stub", bp.is_tu_stub(features, "lib/vtls/openssl.c")),
    ("libssh-stub", bp.is_tu_stub(features, "lib/vssh/libssh.c")),
    ("url-real", not bp.is_tu_stub(features, "lib/url.c")),
    ("missing-real", not bp.is_tu_stub(features, "lib/never_heard_of.c")),
    # Absolute-path suffix match: caller passes /abs/path/to/lib/vtls/openssl.c.
    ("abs-suffix", bp.is_tu_stub(features, "/abs/path/to/lib/vtls/openssl.c")),
    ("empty-path", not bp.is_tu_stub(features, "")),
    ("none-features", not bp.is_tu_stub(None, "lib/vtls/openssl.c")),
]
for name, ok in checks:
    print(f"{name}={'ok' if ok else 'FAIL'}")
PY
)
assert_match 'openssl-stub=ok' "$stub_result" "is_tu_stub: detects stub by path"
assert_match 'libssh-stub=ok' "$stub_result" "is_tu_stub: detects second stub by path"
assert_match 'url-real=ok' "$stub_result" "is_tu_stub: real TU is not flagged"
assert_match 'missing-real=ok' "$stub_result" "is_tu_stub: unknown path is not flagged"
assert_match 'abs-suffix=ok' "$stub_result" "is_tu_stub: absolute-path suffix matches stub"
assert_match 'empty-path=ok' "$stub_result" "is_tu_stub: empty path returns False"
assert_match 'none-features=ok' "$stub_result" "is_tu_stub: None manifest returns False (fail-open)"

# ── Test 4: fail-open on missing/malformed manifest ────────────────

missing_result=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - <<'PY'
import build_probe as bp
m1 = bp.load_features("/nonexistent/path/features.json")
m2 = bp.load_features("")
print(f"missing={'None' if m1 is None else 'NOT-None'}")
print(f"empty={'None' if m2 is None else 'NOT-None'}")
PY
)
assert_match 'missing=None' "$missing_result" "load_features: missing path → None"
assert_match 'empty=None' "$missing_result" "load_features: empty path → None"

malformed_path="$TEST_TMPDIR/malformed.json"
echo 'this-is-not-json' > "$malformed_path"
malformed_result=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - "$malformed_path" <<'PY'
import sys, build_probe as bp
m = bp.load_features(sys.argv[1])
print(f"malformed={'None' if m is None else 'NOT-None'}")
PY
)
assert_match 'malformed=None' "$malformed_result" "load_features: malformed JSON → None (fail-open)"

wrong_schema="$TEST_TMPDIR/wrong-schema.json"
cat > "$wrong_schema" <<'JSON'
{"schema_version": 999, "stub_tus": ["x.c"]}
JSON
wrong_result=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - "$wrong_schema" <<'PY'
import sys, build_probe as bp
m = bp.load_features(sys.argv[1])
print(f"wrong_schema={'None' if m is None else 'NOT-None'}")
PY
)
assert_match 'wrong_schema=None' "$wrong_result" "load_features: unknown schema_version → None"

# ── Test 5: summarise_for_prompt produces a usable block ───────────

summary_text=$(python3 "$PROBE" summary --features "$TEST_TMPDIR/consumer/features.json")
assert_match 'Build feature manifest' "$summary_text" "summary: emits manifest header"
assert_match 'lib/vtls/' "$summary_text" "summary: lists stub directory"
assert_match 'tu-not-compiled' "$summary_text" "summary: names the queue gate reason"

empty_summary=$(python3 "$PROBE" summary --features /nonexistent/features.json)
assert_eq "" "$empty_summary" "summary: missing manifest → empty output (fail-open)"

# ── Test 6: classification is conservative ─────────────────────────
# An empty-symbol .o is unknown, not stub. Header-only TUs and TUs
# whose entire content was inlined should not be flagged.

# Build a deliberately-empty .o that nm reports with zero symbols.
if command -v "${cc:-cc}" >/dev/null 2>&1; then
  empty_target="$TEST_TMPDIR/empty-target"
  empty_build="$TEST_TMPDIR/empty-build"
  mkdir -p "$empty_target/src" "$empty_build"
  echo '/* truly empty */' > "$empty_target/src/empty.c"
  cc_cmd="${cc:-cc}"
  if "$cc_cmd" -c "$empty_target/src/empty.c" -o "$empty_build/empty.c.o" 2>/dev/null; then
    empty_features="$TEST_TMPDIR/empty-features.json"
    python3 "$PROBE" probe \
      --target-root "$empty_target" \
      --build-dir "$empty_build" \
      --sanitizer asan \
      --output "$empty_features" >/dev/null 2>&1 || true
    if [ -f "$empty_features" ]; then
      empty_stubs=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["stub_tus"]))' "$empty_features")
      assert_eq "0" "$empty_stubs" "empty .o is classified as unknown, not stub (fail-open)"
    fi
  fi
fi

# ── Test 7: duplicate basenames don't block a real TU ──────────────
# Two sources share a basename: dirA/parse.c (real) and dirB/parse.c
# (stub). The object tree mirrors the source layout. The stub verdict
# for dirB must NOT leak onto dirA, and dirA must stay auditable.

if command -v "${cc:-cc}" >/dev/null 2>&1; then
  cc_cmd="${cc:-cc}"
  dup_target="$TEST_TMPDIR/dup-target"
  dup_build="$TEST_TMPDIR/dup-build"
  mkdir -p "$dup_target/dirA" "$dup_target/dirB"
  mkdir -p "$dup_build/CMakeFiles/lib.dir/dirA" "$dup_build/CMakeFiles/lib.dir/dirB"

  # dirA/parse.c: a legitimate audit surface whose object exposes no
  # *global* symbols (all-static module, reached via pointers). It
  # classifies as "unknown", so the `stub_set -= real_set` guard cannot
  # rescue it — this is exactly the case where a wrong basename mapping
  # would let dirB's stub verdict block dirA.
  echo 'static int parse_a(int x){return x+1;}' > "$dup_target/dirA/parse.c"
  # dirB/parse.c: source exists but its object is a sanitizer-runtime stub.
  echo '/* parse.c stub: feature compiled out */' > "$dup_target/dirB/parse.c"

  ok=1
  "$cc_cmd" -c "$dup_target/dirA/parse.c" \
    -o "$dup_build/CMakeFiles/lib.dir/dirA/parse.c.o" 2>/dev/null || ok=0
  cat > "$dup_build/_dupstub.s" <<'S'
        .text
        .globl  asan.module_ctor_dup
asan.module_ctor_dup:
        .byte 0
S
  "$cc_cmd" -c "$dup_build/_dupstub.s" \
    -o "$dup_build/CMakeFiles/lib.dir/dirB/parse.c.o" 2>/dev/null || ok=0

  if [ "$ok" = 1 ]; then
    dup_features="$TEST_TMPDIR/dup-features.json"
    python3 "$PROBE" probe \
      --target-root "$dup_target" \
      --build-dir "$dup_build" \
      --sanitizer asan \
      --output "$dup_features" >/dev/null 2>&1 || true

    if [ -f "$dup_features" ]; then
      dup_check=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - "$dup_features" <<'PY'
import sys, build_probe as bp
f = bp.load_features(sys.argv[1])
print("dirA-stub=" + ("FAIL" if bp.is_tu_stub(f, "dirA/parse.c") else "ok"))
print("dirB-stub=" + ("ok" if bp.is_tu_stub(f, "dirB/parse.c") else "ok-failopen"))
PY
)
      # The real TU must never be flagged as a stub — this is the bug
      # the location-based disambiguation closes.
      assert_match 'dirA-stub=ok' "$dup_check" "duplicate basename: real TU (dirA) is not blocked"
    fi
  else
    echo "SKIP: duplicate-basename build setup failed"
  fi
fi

# ── Test 8: missing build dir returns a well-formed ObjectScan ─────
# probe_objects returns an ObjectScan dataclass with named fields, so
# every branch yields the same shape. The missing-build-dir branch used
# to return a 3-value tuple where the normal path returned 4, raising
# ValueError at the caller's unpack site and aborting the probe on
# incomplete setups. Named fields make that mismatch impossible.

missing_build_result=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 - <<'PY'
from pathlib import Path
import build_probe as bp
try:
    scan = bp.probe_objects(Path("/nonexistent/build/dir"), Path("/nonexistent/target"))
    # Read named fields — raises AttributeError if the shape is wrong.
    print(f"crash=no count={scan.probed_object_count} stubs={len(scan.stub_tus)} "
          f"reals={len(scan.compiled_tus)} ambiguous={scan.ambiguous}")
except Exception as e:  # noqa: BLE001 — any exception is a failure here
    print(f"crash={type(e).__name__}")

# build_manifest reads the same ObjectScan; must not raise either.
m = bp.build_manifest(Path("/nonexistent/target"), Path("/nonexistent/build/dir"), "asan")
print(f"manifest_count={m.probed_object_count} manifest_stubs={len(m.stub_tus)}")
PY
)
assert_match 'crash=no count=0 stubs=0 reals=0 ambiguous=0' "$missing_build_result" "probe_objects: missing build dir returns empty ObjectScan"
assert_match 'manifest_count=0 manifest_stubs=0' "$missing_build_result" "build_manifest: missing build dir → empty, fail-open"

# ── Content-addressed probe skip (bin/audit run_build_feature_probe) ─
# The manifest is a pure function of the build artifacts; the harness
# used to re-run the nm sweep at every iteration boundary. The probe
# must run once, skip while the binary/build-log identity (mtime:size)
# is unchanged, and re-run after a rebuild touches the anchor.

audit_extract_function() {
  awk -v name="$1" '
    $0 ~ "^" name "\\(\\) \\{" { in_func=1 }
    in_func { print }
    in_func && $0 == "}" { exit }
  ' "$SCRIPT_ROOT/bin/audit"
}
eval "$(audit_extract_function run_build_feature_probe)"
source "$SCRIPT_ROOT/lib/platform.sh"
log() { printf '%s\n' "$*"; }

sig_target="$TEST_TMPDIR/sig-target"
sig_build="$TEST_TMPDIR/sig-build"
mkdir -p "$sig_target" "$sig_build"
printf '#!/bin/sh\necho tool 1.0\n' > "$sig_build/tool"
chmod +x "$sig_build/tool" 2>/dev/null || true

PROBE_CALL_LOG="$TEST_TMPDIR/probe-calls.log"
: > "$PROBE_CALL_LOG"
# Shadow python3 to count actual build_probe.py invocations; everything
# else (summary, queue gate) passes through untouched.
python3() {
  case "$*" in
    *build_probe.py*) echo probe >> "$PROBE_CALL_LOG" ;;
  esac
  command python3 "$@"
}

run_probe_once() {
  IS_BROWSER_TARGET=0 SANITIZER_BUILD_DISABLED=0 \
  ASAN_BUILD_AVAILABLE=1 ASAN_BUILD_DIR="$sig_build" \
  ASAN_BUILD_BINARY="$sig_build/tool" \
  TARGET_ROOT="$sig_target" SCRIPT_ROOT="$SCRIPT_ROOT" \
  RESULTS_DIR="$RESULTS_DIR" LOGDIR="$LOGDIR" INDEX="$INDEX" \
  run_build_feature_probe >/dev/null 2>&1 || true
}

run_probe_once
probe_runs=$(grep -c probe "$PROBE_CALL_LOG" 2>/dev/null || true)
assert_eq 1 "$probe_runs" "probe-sig: first call runs the probe"
assert_file_exists "$RESULTS_DIR/state/features.json" "probe-sig: manifest written"
assert_file_exists "$RESULTS_DIR/state/.features.probe-sig" "probe-sig: signature stamp written"

run_probe_once
probe_runs=$(grep -c probe "$PROBE_CALL_LOG" 2>/dev/null || true)
assert_eq 1 "$probe_runs" "probe-sig: unchanged build skips the re-probe"

# A rebuild changes the binary's content → the signature misses → re-probe.
printf '#!/bin/sh\necho tool 1.1\n' > "$sig_build/tool"
run_probe_once
probe_runs=$(grep -c probe "$PROBE_CALL_LOG" 2>/dev/null || true)
assert_eq 2 "$probe_runs" "probe-sig: rebuilt binary re-runs the probe"

# An object file changing WITHOUT a relink must also miss: stub_tus come
# from sweeping every .o under the build dir, including TUs the probed
# binary does not link. A stale skip here gates work cards on old data.
printf 'obj-v1' > "$sig_build/extra.o"
run_probe_once
probe_runs=$(grep -c probe "$PROBE_CALL_LOG" 2>/dev/null || true)
assert_eq 3 "$probe_runs" "probe-sig: new object file re-runs the probe (binary unchanged)"
run_probe_once
probe_runs=$(grep -c probe "$PROBE_CALL_LOG" 2>/dev/null || true)
assert_eq 3 "$probe_runs" "probe-sig: unchanged object tree skips again"
printf 'obj-v2-longer' > "$sig_build/extra.o"
run_probe_once
probe_runs=$(grep -c probe "$PROBE_CALL_LOG" 2>/dev/null || true)
assert_eq 4 "$probe_runs" "probe-sig: changed object file re-runs the probe (binary unchanged)"

# A configured-but-MISSING binary must never cache (audit_stat_key
# prints "0:0" for missing paths — caching on that would freeze a stale
# manifest while the object tree changes underneath it). Every call
# re-probes.
rm -f "$sig_build/tool" "$RESULTS_DIR/state/.features.probe-sig"
run_probe_once
run_probe_once
probe_runs=$(grep -c probe "$PROBE_CALL_LOG" 2>/dev/null || true)
assert_eq 6 "$probe_runs" "probe-sig: missing binary always re-probes (no 0:0 cache)"
if [ -f "$RESULTS_DIR/state/.features.probe-sig" ]; then
  fail "probe-sig: no signature stamped for a missing binary" "stamp exists"
else
  pass "probe-sig: no signature stamped for a missing binary"
fi
unset -f python3

teardown_test_env
summary
