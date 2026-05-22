#!/usr/bin/env bash
# Unit tests for the [threat_model] section of target.toml.
# Covers: section parsing in lib/target_config.sh, attacker_controls
# defaults, alias normalization, invalid-token rejection, CSV helper,
# and the existing target.toml files in output/<slug>/.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/target_config.sh"

# ───────────────────────────────────────────────────────────────────
# 1. Default attacker_controls when [threat_model] is absent
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/no-tm.toml" <<'EOF'
slug = "demo"
asan_bin = "build-asan/demo"
EOF
TARGET_ATTACKER_CONTROLS=()
target_load_toml "$TEST_TMPDIR/no-tm.toml"
assert_eq 1 "${#TARGET_ATTACKER_CONTROLS[@]}" "no [threat_model] → defaults to one entry"
assert_eq "bytes" "${TARGET_ATTACKER_CONTROLS[0]:-}" "no [threat_model] → defaults to bytes"
csv=$(target_attacker_controls_csv)
assert_eq "bytes" "$csv" "csv helper returns bytes when defaulted"

# ───────────────────────────────────────────────────────────────────
# 2. Single-token attacker_controls (libxml2-shape)
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/libxml2.toml" <<'EOF'
slug = "libxml2"
asan_bin = "build-asan/xmlcatalog"

[threat_model]
attacker_controls = ["bytes"]
EOF
TARGET_ATTACKER_CONTROLS=()
target_load_toml "$TEST_TMPDIR/libxml2.toml"
assert_eq 1 "${#TARGET_ATTACKER_CONTROLS[@]}" "libxml2-shape: one entry parsed"
assert_eq "bytes" "${TARGET_ATTACKER_CONTROLS[0]}" "libxml2-shape: bytes parsed"
assert_eq "bytes" "$(target_attacker_controls_csv)" "libxml2-shape: csv = bytes"

# ───────────────────────────────────────────────────────────────────
# 3. Multi-token attacker_controls (firefox-shape)
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/firefox.toml" <<'EOF'
slug = "firefox"
is_browser = "1"

[threat_model]
attacker_controls = ["bytes", "call-sequence", "timing"]
EOF
TARGET_ATTACKER_CONTROLS=()
target_load_toml "$TEST_TMPDIR/firefox.toml"
assert_eq 3 "${#TARGET_ATTACKER_CONTROLS[@]}" "firefox-shape: three entries parsed"
assert_eq "bytes,call-sequence,timing" "$(target_attacker_controls_csv)" "firefox-shape: csv preserves order"

# ───────────────────────────────────────────────────────────────────
# 4. call-order is normalized to call-sequence
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/aliased.toml" <<'EOF'
slug = "aliased"
[threat_model]
attacker_controls = ["bytes", "call-order"]
EOF
TARGET_ATTACKER_CONTROLS=()
target_load_toml "$TEST_TMPDIR/aliased.toml"
assert_eq "bytes,call-sequence" "$(target_attacker_controls_csv)" "call-order alias normalized to call-sequence"

# ───────────────────────────────────────────────────────────────────
# 5. Invalid tokens are rejected (warning printed, token dropped)
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/bogus.toml" <<'EOF'
slug = "bogus"
[threat_model]
attacker_controls = ["bytes", "magic-pony", "timing"]
EOF
# Two passes: a $(...) capture would run target_load_toml in a subshell,
# losing the array assignment. Run once with a stderr redirect to a
# tempfile to capture the warning, then check the array in the current
# shell from the second invocation.
warnfile="$TEST_TMPDIR/bogus.warn"
TARGET_ATTACKER_CONTROLS=()
target_load_toml "$TEST_TMPDIR/bogus.toml" 2>"$warnfile"
warn=$(cat "$warnfile")
assert_eq 2 "${#TARGET_ATTACKER_CONTROLS[@]}" "invalid token dropped, others kept"
assert_eq "bytes,timing" "$(target_attacker_controls_csv)" "csv excludes invalid token"
assert_match "magic-pony" "$warn" "warning mentions the bad token"

# ───────────────────────────────────────────────────────────────────
# 6. Empty attacker_controls = [] also defaults to ["bytes"]
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/empty.toml" <<'EOF'
slug = "empty"
[threat_model]
attacker_controls = []
EOF
TARGET_ATTACKER_CONTROLS=()
target_load_toml "$TEST_TMPDIR/empty.toml"
assert_eq 1 "${#TARGET_ATTACKER_CONTROLS[@]}" "empty array → defaults to ['bytes']"
assert_eq "bytes" "${TARGET_ATTACKER_CONTROLS[0]}" "empty array → defaults to bytes"

# ───────────────────────────────────────────────────────────────────
# 7. Section parser rejects bad sections by default; legacy lenient mode is explicit
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/malformed-section.toml" <<'EOF'
slug = "malformed"
[bad section name with spaces]
asan_bin = "build-asan/post-bad-section"
EOF
TARGET_ASAN_BIN=""
if target_load_toml "$TEST_TMPDIR/malformed-section.toml" >/dev/null 2>&1; then
  fail "bad [section] header rejected by default" "target_load_toml succeeded unexpectedly"
else
  pass "bad [section] header rejected by default"
fi
export TARGET_TOML_LENIENT=1
target_load_toml "$TEST_TMPDIR/malformed-section.toml"
unset TARGET_TOML_LENIENT
assert_eq "build-asan/post-bad-section" "$TARGET_ASAN_BIN" "bad [section] header requires TARGET_TOML_LENIENT=1"

# ───────────────────────────────────────────────────────────────────
# 8. target_seed_toml emits a [threat_model] section
# ───────────────────────────────────────────────────────────────────

mkdir -p "$TEST_TMPDIR/seed-target"
target_seed_toml "$TEST_TMPDIR/seed-target" "$TEST_TMPDIR/seeded.toml" "https://example.com/repo"
assert_file_contains "$TEST_TMPDIR/seeded.toml" '\[threat_model\]' "seeded toml has [threat_model] header"
assert_file_contains "$TEST_TMPDIR/seeded.toml" 'attacker_controls = \["bytes"\]' "seeded toml has bytes-only default for non-browser"

# Browser slug → wider threat model
mkdir -p "$TEST_TMPDIR/firefox"
target_seed_toml "$TEST_TMPDIR/firefox" "$TEST_TMPDIR/seeded-browser.toml" ""
assert_file_contains "$TEST_TMPDIR/seeded-browser.toml" 'call-sequence' "browser seed includes call-sequence"
assert_file_contains "$TEST_TMPDIR/seeded-browser.toml" 'timing' "browser seed includes timing"

# Round-trip: a freshly seeded toml must parse back to the same set.
TARGET_ATTACKER_CONTROLS=()
target_load_toml "$TEST_TMPDIR/seeded-browser.toml"
assert_eq "bytes,call-sequence,timing" "$(target_attacker_controls_csv)" "seeded browser toml round-trips through loader"

TARGET_ATTACKER_CONTROLS=()
target_load_toml "$TEST_TMPDIR/seeded.toml"
assert_eq "bytes" "$(target_attacker_controls_csv)" "seeded generic toml round-trips through loader"

# Known library slugs get target-specific starter threat models.
for slug_expected in \
  "json:bytes,call-sequence" \
  "libxml2:bytes,call-sequence" \
  "curl:bytes,call-sequence,protocol-state" \
  "c-ares:bytes,call-sequence,protocol-state" \
  "pcre2:bytes" \
  "zlib:bytes"; do
  slug="${slug_expected%%:*}"
  expected="${slug_expected#*:}"
  mkdir -p "$TEST_TMPDIR/threat-targets/$slug"
  target_seed_toml "$TEST_TMPDIR/threat-targets/$slug" "$TEST_TMPDIR/threat-$slug.toml" ""
  TARGET_ATTACKER_CONTROLS=()
  target_load_toml "$TEST_TMPDIR/threat-$slug.toml"
  assert_eq "$expected" "$(target_attacker_controls_csv)" "seeded $slug threat model round-trips through loader"
done

# ───────────────────────────────────────────────────────────────────
# 8b. target_seed_toml emits [s4_diff_pairs] for browser engines, and
#     target_load_toml populates TARGET_S4_JIT_OFF / TARGET_S4_JIT_EAGER
# ───────────────────────────────────────────────────────────────────

# Firefox seed → expect --no-ion / --ion-eager
TARGET_S4_JIT_OFF=()
TARGET_S4_JIT_EAGER=()
target_load_toml "$TEST_TMPDIR/seeded-browser.toml"
assert_eq "--no-ion" "${TARGET_S4_JIT_OFF[*]}" "firefox seed: TARGET_S4_JIT_OFF populated"
assert_eq "--ion-eager" "${TARGET_S4_JIT_EAGER[*]}" "firefox seed: TARGET_S4_JIT_EAGER populated"

# Chromium seed (multi-flag JIT off list)
mkdir -p "$TEST_TMPDIR/chromium"
target_seed_toml "$TEST_TMPDIR/chromium" "$TEST_TMPDIR/seeded-chromium.toml" ""
assert_file_contains "$TEST_TMPDIR/seeded-chromium.toml" '\[s4_diff_pairs\]' "chromium seed has [s4_diff_pairs]"
assert_file_contains "$TEST_TMPDIR/seeded-chromium.toml" 'no-turbofan' "chromium seed has turbofan flag"
TARGET_S4_JIT_OFF=()
TARGET_S4_JIT_EAGER=()
target_load_toml "$TEST_TMPDIR/seeded-chromium.toml"
assert_eq "--no-turbofan --no-maglev" "${TARGET_S4_JIT_OFF[*]}" "chromium: multi-flag jit_off populated"
assert_eq "--always-turbofan" "${TARGET_S4_JIT_EAGER[*]}" "chromium: jit_eager populated"

# WebKit seed
mkdir -p "$TEST_TMPDIR/webkit"
target_seed_toml "$TEST_TMPDIR/webkit" "$TEST_TMPDIR/seeded-webkit.toml" ""
TARGET_S4_JIT_OFF=()
TARGET_S4_JIT_EAGER=()
target_load_toml "$TEST_TMPDIR/seeded-webkit.toml"
assert_eq "--useJIT=false" "${TARGET_S4_JIT_OFF[*]}" "webkit: jit_off populated"
assert_eq "--thresholdForJITAfterWarmUp=0" "${TARGET_S4_JIT_EAGER[*]}" "webkit: jit_eager populated"

# Non-browser target: no [s4_diff_pairs] → arrays stay empty.
TARGET_S4_JIT_OFF=()
TARGET_S4_JIT_EAGER=()
target_load_toml "$TEST_TMPDIR/seeded.toml"
assert_eq "0" "${#TARGET_S4_JIT_OFF[@]}" "non-browser: TARGET_S4_JIT_OFF stays empty"
assert_eq "0" "${#TARGET_S4_JIT_EAGER[@]}" "non-browser: TARGET_S4_JIT_EAGER stays empty"

# ───────────────────────────────────────────────────────────────────
# 8c. target_seed_toml does not emit [s6_peers]; output/<slug>/target.toml
#     is the only source for TARGET_S6_PEERS / TARGET_S6_DOMAIN.
# ───────────────────────────────────────────────────────────────────

# libxml2 used to be bundled; seeding now leaves peers empty until
# bin/suggest-peers writes [s6_peers].
mkdir -p "$TEST_TMPDIR/libxml2"
target_seed_toml "$TEST_TMPDIR/libxml2" "$TEST_TMPDIR/seeded-libxml2.toml" ""
assert_file_not_contains "$TEST_TMPDIR/seeded-libxml2.toml" '\[s6_peers\]' "libxml2 seed has no implicit [s6_peers]"
TARGET_S6_PEERS=()
TARGET_S6_DOMAIN=""
target_load_toml "$TEST_TMPDIR/seeded-libxml2.toml"
assert_eq "0" "${#TARGET_S6_PEERS[@]}" "libxml2: TARGET_S6_PEERS stays empty without target.toml section"
assert_eq "" "$TARGET_S6_DOMAIN" "libxml2: TARGET_S6_DOMAIN stays empty without target.toml section"

# Unbundled slug (e.g., the throwaway "seed-target" dir): no live section,
# stays as a commented stub. Round-trip leaves arrays empty.
TARGET_S6_PEERS=()
TARGET_S6_DOMAIN=""
target_load_toml "$TEST_TMPDIR/seeded.toml"
assert_eq "0" "${#TARGET_S6_PEERS[@]}" "unbundled: TARGET_S6_PEERS stays empty"
assert_eq "" "$TARGET_S6_DOMAIN" "unbundled: TARGET_S6_DOMAIN stays empty"

# ───────────────────────────────────────────────────────────────────
# 9. Existing checked-in target.toml files parse successfully
# ───────────────────────────────────────────────────────────────────

# These files are gitignored at the repo level but are present on a
# normal developer checkout. Test only those that exist on this machine.
for slug in libxml2 pcre2 firefox; do
  toml="$SCRIPT_ROOT/output/$slug/target.toml"
  [ -f "$toml" ] || continue
  TARGET_ATTACKER_CONTROLS=()
  if target_load_toml "$toml" 2>/dev/null; then
    n=${#TARGET_ATTACKER_CONTROLS[@]}
    if [ "$n" -ge 1 ]; then
      pass "target.toml ($slug) parses with attacker_controls=$(target_attacker_controls_csv)"
    else
      fail "target.toml ($slug) parses but attacker_controls is empty"
    fi
  else
    fail "target.toml ($slug) failed to parse"
  fi
done

# ───────────────────────────────────────────────────────────────────
# 10. Duplicate tokens in attacker_controls are de-duplicated by csv helper
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/dup.toml" <<'EOF'
slug = "dup"
[threat_model]
attacker_controls = ["bytes", "timing", "bytes"]
EOF
TARGET_ATTACKER_CONTROLS=()
target_load_toml "$TEST_TMPDIR/dup.toml"
assert_eq "bytes,timing" "$(target_attacker_controls_csv)" "duplicate tokens collapsed in csv output"

teardown_test_env
summary
