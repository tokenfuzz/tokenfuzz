#!/usr/bin/env bash
# Unit tests for the [sanitizer] section of target.toml.
# Covers: enabled list parsing + defaulting, per-sanitizer suppressions,
# per-sanitizer extra options, ubsan/msan/tsan binary/library overrides, helper
# functions (target_sanitizer_is_enabled, target_sanitizer_suppressions_path,
# target_sanitizer_extra_options, target_sanitizers_enabled_csv), invalid-
# token warning behavior, the sanitizer_compose_options helper, and that
# back-compat target.toml files (no [sanitizer] section) still load.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/target_config.sh"
source "$SCRIPT_ROOT/lib/sanitizer.sh"

# ───────────────────────────────────────────────────────────────────
# 1. Default sanitizers when [sanitizer] is absent
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/no-san.toml" <<'EOF'
slug = "demo"
asan_bin = "build-asan/demo"
EOF
TARGET_SANITIZERS_ENABLED=()
target_load_toml "$TEST_TMPDIR/no-san.toml"
assert_eq 1 "${#TARGET_SANITIZERS_ENABLED[@]}" "no [sanitizer] → defaults to one entry"
assert_eq "asan" "${TARGET_SANITIZERS_ENABLED[0]:-}" "no [sanitizer] → defaults to asan"
assert_eq "asan" "$(target_sanitizers_enabled_csv)" "csv helper returns asan when defaulted"

# ───────────────────────────────────────────────────────────────────
# 2. ASan-only declared explicitly
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/asan-only.toml" <<'EOF'
slug = "asan-only"
[sanitizer]
enabled = ["asan"]
EOF
TARGET_SANITIZERS_ENABLED=()
target_load_toml "$TEST_TMPDIR/asan-only.toml"
assert_eq "asan" "$(target_sanitizers_enabled_csv)" "asan-only declared parses"
target_sanitizer_is_enabled asan && pass "target_sanitizer_is_enabled asan = true" || fail "asan should be enabled"
target_sanitizer_is_enabled msan && fail "msan should NOT be enabled" || pass "target_sanitizer_is_enabled msan = false"

# ───────────────────────────────────────────────────────────────────
# 3. Multi-sanitizer enabled (all four)
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/all-san.toml" <<'EOF'
slug = "all-san"
[sanitizer]
enabled = ["asan", "ubsan", "msan", "tsan"]
EOF
TARGET_SANITIZERS_ENABLED=()
target_load_toml "$TEST_TMPDIR/all-san.toml"
assert_eq 4 "${#TARGET_SANITIZERS_ENABLED[@]}" "all four sanitizers parsed"
assert_eq "asan,ubsan,msan,tsan" "$(target_sanitizers_enabled_csv)" "all-san csv preserves order"

# ───────────────────────────────────────────────────────────────────
# 4. Unknown sanitizer token: stderr warning + drop
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/bogus-san.toml" <<'EOF'
slug = "bogus-san"
[sanitizer]
enabled = ["asan", "blortsan", "ubsan"]
EOF
warnfile="$TEST_TMPDIR/bogus-san.warn"
TARGET_SANITIZERS_ENABLED=()
target_load_toml "$TEST_TMPDIR/bogus-san.toml" 2>"$warnfile"
warn=$(cat "$warnfile")
assert_eq 2 "${#TARGET_SANITIZERS_ENABLED[@]}" "unknown sanitizer dropped, others kept"
assert_eq "asan,ubsan" "$(target_sanitizers_enabled_csv)" "csv excludes unknown sanitizer"
assert_match "blortsan" "$warn" "warning mentions the bad sanitizer token"

# ───────────────────────────────────────────────────────────────────
# 5. Empty enabled = [] is honored as findings-only mode
# ───────────────────────────────────────────────────────────────────
#
# Historic behavior was to default `enabled = []` back to ["asan"];
# this regressed non-C/C++ targets that opted out of sanitizer builds.
# The new semantics distinguish "section absent" (legacy default) from
# "explicitly empty" (findings-only). The bash loader sets
# TARGET_SANITIZERS_EXPLICITLY_DISABLED=1 for the explicit-empty case.

cat > "$TEST_TMPDIR/empty-san.toml" <<'EOF'
slug = "empty-san"
[sanitizer]
enabled = []
EOF
TARGET_SANITIZERS_ENABLED=()
TARGET_SANITIZERS_EXPLICITLY_DISABLED=0
target_load_toml "$TEST_TMPDIR/empty-san.toml"
assert_eq 0 "${#TARGET_SANITIZERS_ENABLED[@]}" "empty enabled → no sanitizers"
assert_eq 1 "$TARGET_SANITIZERS_EXPLICITLY_DISABLED" "empty enabled → explicit-disable flag set"
assert_eq "" "$(target_sanitizers_enabled_csv)" "csv helper returns empty for findings-only mode"
target_has_any_sanitizer && fail "target_has_any_sanitizer should be false for empty enabled" || pass "target_has_any_sanitizer false for empty enabled"

# Section absent (legacy): still defaults to ["asan"] and the flag stays 0.
cat > "$TEST_TMPDIR/no-section.toml" <<'EOF'
slug = "no-section"
asan_bin = "build-asan/demo"
EOF
TARGET_SANITIZERS_ENABLED=()
TARGET_SANITIZERS_EXPLICITLY_DISABLED=0
target_load_toml "$TEST_TMPDIR/no-section.toml"
assert_eq "asan" "$(target_sanitizers_enabled_csv)" "[sanitizer] absent → still defaults to asan"
assert_eq 0 "$TARGET_SANITIZERS_EXPLICITLY_DISABLED" "[sanitizer] absent → explicit-disable flag stays 0"

# ───────────────────────────────────────────────────────────────────
# 6. Suppressions paths parsed and resolved relative to TARGET_ROOT
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/sup.toml" <<'EOF'
slug = "sup"
[sanitizer]
enabled = ["asan", "ubsan", "msan", "tsan"]
asan_suppressions  = "build-asan/asan-suppressions.txt"
ubsan_suppressions = "build-ubsan/ubsan-suppressions.txt"
msan_suppressions  = "/abs/path/to/msan.txt"
tsan_suppressions  = "build-tsan/tsan.txt"
EOF
TARGET_ROOT="/fake/root"
target_load_toml "$TEST_TMPDIR/sup.toml"
assert_eq "build-asan/asan-suppressions.txt" "$TARGET_ASAN_SUPPRESSIONS" "asan_suppressions stored raw"
assert_eq "/fake/root/build-asan/asan-suppressions.txt" \
  "$(target_sanitizer_suppressions_path asan)" "asan suppressions resolved relative to TARGET_ROOT"
assert_eq "/fake/root/build-ubsan/ubsan-suppressions.txt" \
  "$(target_sanitizer_suppressions_path ubsan)" "ubsan suppressions resolved"
assert_eq "/abs/path/to/msan.txt" \
  "$(target_sanitizer_suppressions_path msan)" "msan absolute suppressions passed through unchanged"
assert_eq "/fake/root/build-tsan/tsan.txt" \
  "$(target_sanitizer_suppressions_path tsan)" "tsan suppressions resolved"

# Unset suppressions returns empty
cat > "$TEST_TMPDIR/no-sup.toml" <<'EOF'
slug = "no-sup"
EOF
target_load_toml "$TEST_TMPDIR/no-sup.toml"
assert_eq "" "$(target_sanitizer_suppressions_path asan)" "no asan suppressions → empty string"
assert_eq "" "$(target_sanitizer_suppressions_path ubsan)" "no ubsan suppressions → empty string"

# ───────────────────────────────────────────────────────────────────
# 7. Per-sanitizer extra options
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/opts.toml" <<'EOF'
slug = "opts"
[sanitizer]
enabled = ["asan", "ubsan"]
asan_options  = "detect_stack_use_after_return=1"
ubsan_options = "report_error_type=1"
EOF
target_load_toml "$TEST_TMPDIR/opts.toml"
assert_eq "detect_stack_use_after_return=1" "$(target_sanitizer_extra_options asan)" "asan_options parsed"
assert_eq "report_error_type=1" "$(target_sanitizer_extra_options ubsan)" "ubsan_options parsed"
assert_eq "" "$(target_sanitizer_extra_options msan)" "msan_options empty when not set"

# ───────────────────────────────────────────────────────────────────
# 8. Per-sanitizer binary and C/C++ harness library overrides
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/bins.toml" <<'EOF'
slug = "bins"
asan_bin = "build-asan/foo"
asan_lib = "build-asan/libfoo.a"
[sanitizer]
enabled = ["asan", "ubsan", "msan", "tsan"]
ubsan_bin = "build-ubsan/foo"
msan_bin  = "build-msan/foo"
tsan_bin  = "build-tsan/foo"
ubsan_lib = "build-ubsan/libfoo.a"
msan_lib  = "build-msan/libfoo.a"
tsan_lib  = "build-tsan/libfoo.a"
EOF
TARGET_ROOT="/fake/root"
target_load_toml "$TEST_TMPDIR/bins.toml"
assert_eq "build-asan/foo" "$TARGET_ASAN_BIN" "top-level asan_bin still works"
assert_eq "build-asan/libfoo.a" "$TARGET_ASAN_LIB" "top-level asan_lib still works"
assert_eq "build-ubsan/foo" "$TARGET_UBSAN_BIN" "[sanitizer].ubsan_bin parsed"
assert_eq "build-msan/foo" "$TARGET_MSAN_BIN" "[sanitizer].msan_bin parsed"
assert_eq "build-tsan/foo" "$TARGET_TSAN_BIN" "[sanitizer].tsan_bin parsed"
assert_eq "build-ubsan/libfoo.a" "$TARGET_UBSAN_LIB" "[sanitizer].ubsan_lib parsed"
assert_eq "build-msan/libfoo.a" "$TARGET_MSAN_LIB" "[sanitizer].msan_lib parsed"
assert_eq "build-tsan/libfoo.a" "$TARGET_TSAN_LIB" "[sanitizer].tsan_lib parsed"
assert_eq "/fake/root/build-asan/libfoo.a" "$(target_sanitizer_lib_path asan)" "asan lib resolves via helper"
assert_eq "/fake/root/build-ubsan/libfoo.a" "$(target_sanitizer_lib_path ubsan)" "ubsan lib resolves via helper"
assert_eq "/fake/root/build-msan/libfoo.a" "$(target_sanitizer_lib_path msan)" "msan lib resolves via helper"
assert_eq "/fake/root/build-tsan/libfoo.a" "$(target_sanitizer_lib_path tsan)" "tsan lib resolves via helper"

# ── target_sanitizer_rpath_args ──────────────────────────────────────
# Convention shared with bin/export-repro's reproduce.sh template: the
# rpath dir is the dirname side of the resolved sanitizer_lib path. The
# helper is what bin/probe uses at audit time; the template uses the
# equivalent ${san_lib%/*} shell expression at repro time.
assert_eq "-Wl,-rpath,/abs/build-asan/lib" \
  "$(target_sanitizer_rpath_args /abs/build-asan/lib/libcjson.so.1)" \
  "target_sanitizer_rpath_args: emits -Wl,-rpath,<dirname>"
assert_eq "-Wl,-rpath,/abs/build-asan" \
  "$(target_sanitizer_rpath_args /abs/build-asan/libfoo.a)" \
  "target_sanitizer_rpath_args: works with static archive"
assert_eq "" \
  "$(target_sanitizer_rpath_args "")" \
  "target_sanitizer_rpath_args: empty input → empty output"
assert_eq "" \
  "$(target_sanitizer_rpath_args libfoo.a)" \
  "target_sanitizer_rpath_args: no directory component → empty output"

# ───────────────────────────────────────────────────────────────────
# 9. sanitizer_compose_options: appends suppressions when file exists
# ───────────────────────────────────────────────────────────────────

mkdir -p "$TEST_TMPDIR/root/build-asan"
echo "fun:safe_*" > "$TEST_TMPDIR/root/build-asan/sup.txt"
cat > "$TEST_TMPDIR/compose.toml" <<EOF
slug = "compose"
[sanitizer]
enabled = ["asan"]
asan_suppressions = "build-asan/sup.txt"
asan_options      = "verbosity=1"
EOF
TARGET_ROOT="$TEST_TMPDIR/root"
target_load_toml "$TEST_TMPDIR/compose.toml"
composed="$(sanitizer_compose_options asan "halt_on_error=1")"
assert_match "halt_on_error=1" "$composed" "compose preserves base options"
assert_match "suppressions=$TEST_TMPDIR/root/build-asan/sup.txt" "$composed" "compose appends suppressions= for existing file"
assert_match "verbosity=1" "$composed" "compose appends extra options"

ASAN_OPTIONS="allocator_may_return_null=1"
runtime_opts="$(sanitizer_runtime_options asan "$composed")"
assert_match "halt_on_error=1" "$runtime_opts" "runtime options preserve composed base"
assert_match "verbosity=1" "$runtime_opts" "runtime options preserve target extras"
assert_match "allocator_may_return_null=1" "$runtime_opts" "runtime options append explicit env extras"
unset ASAN_OPTIONS

# ───────────────────────────────────────────────────────────────────
# 10. sanitizer_compose_options: warns and skips missing suppression file
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/missing-sup.toml" <<EOF
slug = "missing-sup"
[sanitizer]
enabled = ["ubsan"]
ubsan_suppressions = "build-ubsan/does-not-exist.txt"
EOF
TARGET_ROOT="$TEST_TMPDIR/root"
target_load_toml "$TEST_TMPDIR/missing-sup.toml"
warnfile="$TEST_TMPDIR/missing-sup.warn"
composed="$(sanitizer_compose_options ubsan "halt_on_error=1" 2>"$warnfile")"
warn=$(cat "$warnfile")
assert_match "halt_on_error=1" "$composed" "missing suppressions: base options still present"
assert_not_match "suppressions=" "$composed" "missing suppressions: no suppressions= appended"
assert_match "WARNING.*does-not-exist.txt" "$warn" "missing suppressions: prints warning"

# ───────────────────────────────────────────────────────────────────
# 11. sanitizer_warn_if_disabled: warns when sanitizer not in enabled list
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/asan-only2.toml" <<'EOF'
slug = "asan-only2"
[sanitizer]
enabled = ["asan"]
EOF
target_load_toml "$TEST_TMPDIR/asan-only2.toml"
warnfile="$TEST_TMPDIR/disabled.warn"
sanitizer_warn_if_disabled msan 2>"$warnfile"
warn=$(cat "$warnfile")
assert_match "not in \[sanitizer\].enabled" "$warn" "warns when invoking disabled sanitizer"

# Enabled sanitizer: no warning
sanitizer_warn_if_disabled asan 2>"$warnfile"
warn=$(cat "$warnfile")
assert_eq "" "$warn" "no warning when sanitizer is enabled"

# ───────────────────────────────────────────────────────────────────
# 11b. sanitizer_prepare_runtime_env: selected sanitizer env is exclusive
# ───────────────────────────────────────────────────────────────────

ASAN_OPTIONS=asan-keep
UBSAN_OPTIONS=ubsan-drop
MSAN_OPTIONS=msan-drop
TSAN_OPTIONS=tsan-drop
sanitizer_prepare_runtime_env asan
assert_eq "asan-keep" "${ASAN_OPTIONS:-}" "prepare env: ASAN_OPTIONS preserved for asan"
assert_eq "" "${UBSAN_OPTIONS+x}" "prepare env: UBSAN_OPTIONS cleared for asan"
assert_eq "" "${MSAN_OPTIONS+x}" "prepare env: MSAN_OPTIONS cleared for asan"
assert_eq "" "${TSAN_OPTIONS+x}" "prepare env: TSAN_OPTIONS cleared for asan"

ASAN_OPTIONS=asan-drop
UBSAN_OPTIONS=ubsan-keep
MSAN_OPTIONS=msan-drop
TSAN_OPTIONS=tsan-drop
sanitizer_prepare_runtime_env ubsan
assert_eq "" "${ASAN_OPTIONS+x}" "prepare env: ASAN_OPTIONS cleared for ubsan"
assert_eq "ubsan-keep" "${UBSAN_OPTIONS:-}" "prepare env: UBSAN_OPTIONS preserved for ubsan"
assert_eq "" "${MSAN_OPTIONS+x}" "prepare env: MSAN_OPTIONS cleared for ubsan"
assert_eq "" "${TSAN_OPTIONS+x}" "prepare env: TSAN_OPTIONS cleared for ubsan"

ASAN_OPTIONS=asan-drop
UBSAN_OPTIONS=ubsan-drop
MSAN_OPTIONS=msan-keep
TSAN_OPTIONS=tsan-drop
sanitizer_prepare_runtime_env msan
assert_eq "" "${ASAN_OPTIONS+x}" "prepare env: ASAN_OPTIONS cleared for msan"
assert_eq "" "${UBSAN_OPTIONS+x}" "prepare env: UBSAN_OPTIONS cleared for msan"
assert_eq "msan-keep" "${MSAN_OPTIONS:-}" "prepare env: MSAN_OPTIONS preserved for msan"
assert_eq "" "${TSAN_OPTIONS+x}" "prepare env: TSAN_OPTIONS cleared for msan"

ASAN_OPTIONS=asan-drop
UBSAN_OPTIONS=ubsan-drop
MSAN_OPTIONS=msan-drop
TSAN_OPTIONS=tsan-keep
sanitizer_prepare_runtime_env tsan
assert_eq "" "${ASAN_OPTIONS+x}" "prepare env: ASAN_OPTIONS cleared for tsan"
assert_eq "" "${UBSAN_OPTIONS+x}" "prepare env: UBSAN_OPTIONS cleared for tsan"
assert_eq "" "${MSAN_OPTIONS+x}" "prepare env: MSAN_OPTIONS cleared for tsan"
assert_eq "tsan-keep" "${TSAN_OPTIONS:-}" "prepare env: TSAN_OPTIONS preserved for tsan"

ASAN_OPTIONS=asan-drop
UBSAN_OPTIONS=ubsan-drop
MSAN_OPTIONS=msan-drop
TSAN_OPTIONS=tsan-drop
sanitizer_prepare_runtime_env none
assert_eq "" "${ASAN_OPTIONS+x}" "prepare env: ASAN_OPTIONS cleared for none"
assert_eq "" "${UBSAN_OPTIONS+x}" "prepare env: UBSAN_OPTIONS cleared for none"
assert_eq "" "${MSAN_OPTIONS+x}" "prepare env: MSAN_OPTIONS cleared for none"
assert_eq "" "${TSAN_OPTIONS+x}" "prepare env: TSAN_OPTIONS cleared for none"

# ───────────────────────────────────────────────────────────────────
# 12. Back-compat: existing target.toml without [sanitizer] still loads
# ───────────────────────────────────────────────────────────────────

cat > "$TEST_TMPDIR/legacy.toml" <<'EOF'
slug = "legacy"
upstream_url = "https://example.org/legacy.git"
asan_bin = "build-asan/legacy"
asan_lib = "build-asan/libleg.a"
includes = ["include"]

[threat_model]
attacker_controls = ["bytes"]
EOF
TARGET_SANITIZERS_ENABLED=()
target_load_toml "$TEST_TMPDIR/legacy.toml"
assert_eq "asan" "$(target_sanitizers_enabled_csv)" "legacy toml defaults to asan"
assert_eq "build-asan/legacy" "$TARGET_ASAN_BIN" "legacy asan_bin preserved"
assert_eq "bytes" "$(target_attacker_controls_csv)" "legacy threat model preserved"

# ───────────────────────────────────────────────────────────────────
# 13. target_seed_toml emits [sanitizer] with enabled = ["asan"]
# ───────────────────────────────────────────────────────────────────

mkdir -p "$TEST_TMPDIR/seed-san"
target_seed_toml "$TEST_TMPDIR/seed-san" "$TEST_TMPDIR/seeded-san.toml" ""
assert_file_contains "$TEST_TMPDIR/seeded-san.toml" '\[sanitizer\]' "seeded toml has [sanitizer] header"
assert_file_contains "$TEST_TMPDIR/seeded-san.toml" 'enabled = \["asan"\]' "seeded toml defaults enabled to asan only"

TARGET_SANITIZERS_ENABLED=()
target_load_toml "$TEST_TMPDIR/seeded-san.toml"
assert_eq "asan" "$(target_sanitizers_enabled_csv)" "seeded toml round-trips through loader"

# ───────────────────────────────────────────────────────────────────
# 14. Runner scripts source the helper without error
# ───────────────────────────────────────────────────────────────────

bash -n "$SCRIPT_ROOT/bin/run-msan" 2>/dev/null
assert_eq 0 $? "bin/run-msan: syntax check passes"

bash -n "$SCRIPT_ROOT/bin/run-tsan" 2>/dev/null
assert_eq 0 $? "bin/run-tsan: syntax check passes"

# No-args invocations show usage
out=$(bash "$SCRIPT_ROOT/bin/run-msan" 2>&1) || true
assert_match "Usage:" "$out" "run-msan no-args shows usage"

out=$(bash "$SCRIPT_ROOT/bin/run-tsan" 2>&1) || true
assert_match "Usage:" "$out" "run-tsan no-args shows usage"

# Invalid mode rejected
out=$(bash "$SCRIPT_ROOT/bin/run-msan" bogus_mode /dev/null 2>&1) || true
assert_match "Usage:" "$out" "run-msan invalid mode rejected"

out=$(bash "$SCRIPT_ROOT/bin/run-tsan" bogus_mode /dev/null 2>&1) || true
assert_match "Usage:" "$out" "run-tsan invalid mode rejected"

# generic without TARGET_MSAN_BIN / MSAN_GENERIC_BIN refuses
out=$(env -i PATH="$PATH" bash "$SCRIPT_ROOT/bin/run-msan" generic /dev/null 2>&1) || true
assert_match "set \[sanitizer\].msan_bin" "$out" "run-msan generic: clear error message for missing binary"

out=$(env -i PATH="$PATH" bash "$SCRIPT_ROOT/bin/run-tsan" generic /dev/null 2>&1) || true
assert_match "set \[sanitizer\].tsan_bin" "$out" "run-tsan generic: clear error message for missing binary"

teardown_test_env
summary
