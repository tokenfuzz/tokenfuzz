#!/usr/bin/env bash
# Tests for bin/probe's auto-fallback to alternate sanitizer builds.
# When a probe against the canonical build emits a feature-disabled
# sentinel, bin/probe sweeps $TARGET_ROOT/build-*/ for siblings with the
# same binary name and re-runs against each. First candidate whose
# output drops the sentinel wins; the route is cached for future probes.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

PROBE="$SCRIPT_ROOT/bin/probe"
BR="$SCRIPT_ROOT/lib/build_routes.py"

# ── Two fake build trees ────────────────────────────────────────────
# build-asan/bin/myrunner — emits the feature-disabled sentinel always.
# build-asan-jit/bin/myrunner — succeeds (no sentinel).
mkdir -p "$TARGET_ROOT/build-asan/bin" "$TARGET_ROOT/build-asan-jit/bin"

cat > "$TARGET_ROOT/build-asan/bin/myrunner" <<'SH'
#!/usr/bin/env bash
# Canonical binary — JIT not compiled into this build.
echo "myrunner v1.0"
echo "FAIL: No just-in-time compiler support"
exit 1
SH
chmod +x "$TARGET_ROOT/build-asan/bin/myrunner"

cat > "$TARGET_ROOT/build-asan-jit/bin/myrunner" <<'SH'
#!/usr/bin/env bash
# JIT-enabled sibling — runs clean.
echo "myrunner v1.0 (JIT enabled)"
echo "OK: pattern executed"
exit 0
SH
chmod +x "$TARGET_ROOT/build-asan-jit/bin/myrunner"

# Sibling whose binary is missing — must be skipped by enumerate.
mkdir -p "$TARGET_ROOT/build-asan-empty/bin"

# Point the canonical asan_bin at the failing build via target.toml.
cat > "$TARGET_ROOT/target.toml" <<EOF
target       = "testproject"
upstream_url = "https://example.invalid/testproject"
build_system = "make"
asan_bin     = "build-asan/bin/myrunner"
is_browser   = "0"
[threat_model]
attacker_controls = ["bytes"]
[sanitizer]
enabled = ["asan"]
EOF
# bin/probe reads the session env file rather than target.toml directly
# in some paths; both should agree.
session_env="$RESULTS_DIR/.session-env"
mkdir -p "$RESULTS_DIR"
cat > "$session_env" <<EOF
export RESULTS_DIR="$RESULTS_DIR"
export TARGET_ROOT="$TARGET_ROOT"
export TARGET_SLUG="testproject"
EOF

# A testcase referencing a file under the JIT subsystem.
mkdir -p "$RESULTS_DIR/scratch-1"
cat > "$RESULTS_DIR/scratch-1/tc.txt" <<'EOF'
// TARGET: src/pcre2_jit_compile.c:compile:42
// HYPOTHESIS-ID: H-route
// CATEGORY: state
// MODE: generic
EOF

# ── Helper-level coverage: the sentinel regex catches our fake phrase ──
out_file="$TEST_TMPDIR/canonical.out"
"$TARGET_ROOT/build-asan/bin/myrunner" > "$out_file" 2>&1 || true
if python3 "$BR" sentinel "$out_file" >/dev/null; then
  pass "sentinel: helper detects 'No just-in-time compiler support'"
else
  fail "sentinel: helper detects 'No just-in-time compiler support'" \
    "got=$(cat "$out_file")"
fi

# enumerate must surface build-asan-jit (binary exists) and NOT
# build-asan-empty (binary missing) NOR build-asan (canonical).
cands=$(python3 "$BR" enumerate "$TARGET_ROOT" \
  "$TARGET_ROOT/build-asan/bin/myrunner")
assert_match 'build-asan-jit/bin/myrunner' "$cands" \
  "enumerate: JIT-enabled sibling listed"
assert_not_match 'build-asan-empty' "$cands" \
  "enumerate: sibling with missing binary not listed"
# The canonical build appears in the candidate listing if and only if
# it has a /bin/myrunner — which it does. The shell helper passes the
# canonical-build name on the CLI, so this defaults to excluding it.
assert_not_match 'build-asan/bin/myrunner' "$cands" \
  "enumerate: canonical build excluded from candidates"

# ── End-to-end: bin/probe auto-routes ───────────────────────────────
# Run probe directly. PROBE_AUTO_ROUTE defaults to 1.
probe_out="$TEST_TMPDIR/probe-route.log"
ASAN_GENERIC_BIN="$TARGET_ROOT/build-asan/bin/myrunner" \
  PROBE_SANITIZER=asan \
  "$PROBE" "$RESULTS_DIR/scratch-1/tc.txt" >"$probe_out" 2>&1 || true
if grep -q "^\[probe\] ROUTED: " "$probe_out"; then
  pass "auto-route: probe emits ROUTED line when canonical hits the sentinel"
else
  fail "auto-route: probe emits ROUTED line when canonical hits the sentinel" \
    "got: $(grep -E '\[probe\]' "$probe_out" | head -3)"
fi
assert_match 'build-asan-jit/bin/myrunner' "$(cat "$probe_out")" \
  "auto-route: ROUTED log names the JIT-enabled sibling"

# Cache must now hold a route keyed by the testcase file.
if [ -s "$RESULTS_DIR/build-routes.jsonl" ]; then
  pass "auto-route: route cache file is written"
else
  fail "auto-route: route cache file is written" "missing $RESULTS_DIR/build-routes.jsonl"
fi
cached=$(python3 "$BR" lookup "$RESULTS_DIR" \
  "file:src/pcre2_jit_compile.c" 2>/dev/null || true)
assert_match 'build-asan-jit/bin/myrunner' "$cached" \
  "auto-route: cache lookup returns the routed binary"

# ── Escape hatch: PROBE_AUTO_ROUTE=0 disables routing ───────────────
# Wipe the cache so the off-switch path can't hit it accidentally.
rm -f "$RESULTS_DIR/build-routes.jsonl"
off_out="$TEST_TMPDIR/probe-route-off.log"
ASAN_GENERIC_BIN="$TARGET_ROOT/build-asan/bin/myrunner" \
  PROBE_SANITIZER=asan PROBE_AUTO_ROUTE=0 \
  "$PROBE" "$RESULTS_DIR/scratch-1/tc.txt" >"$off_out" 2>&1 || true
assert_not_match 'ROUTED' "$(cat "$off_out")" \
  "auto-route: PROBE_AUTO_ROUTE=0 suppresses ROUTED log"

# ── ROUTE_MISS: no sibling has the feature ──────────────────────────
# Make the JIT-enabled sibling also emit the sentinel.
cat > "$TARGET_ROOT/build-asan-jit/bin/myrunner" <<'SH'
#!/usr/bin/env bash
echo "myrunner v1.0"
echo "FAIL: No just-in-time compiler support"
exit 1
SH
chmod +x "$TARGET_ROOT/build-asan-jit/bin/myrunner"
miss_out="$TEST_TMPDIR/probe-route-miss.log"
rm -f "$RESULTS_DIR/build-routes.jsonl"
ASAN_GENERIC_BIN="$TARGET_ROOT/build-asan/bin/myrunner" \
  PROBE_SANITIZER=asan \
  "$PROBE" "$RESULTS_DIR/scratch-1/tc.txt" >"$miss_out" 2>&1 || true
assert_match 'ROUTE_MISS' "$(cat "$miss_out")" \
  "auto-route: every candidate hits the sentinel → ROUTE_MISS log"
assert_not_match '^\[probe\] ROUTED:' "$(cat "$miss_out")" \
  "auto-route: no ROUTED line when every candidate also feature-disables"

teardown_test_env
summary
