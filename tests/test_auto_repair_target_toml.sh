#!/usr/bin/env bash
# Tests for bin/auto-repair-target-toml — LLM-based target.toml
# auto-repair on persistent harness build failures.
#
# The script must:
#   * honor TARGET_TOML_AUTO_REPAIR=0 (disabled → rc=1, no write)
#   * honor LLM_DECIDE_DISABLE=1 unless a mock is set
#   * only edit the whitelisted top-level arrays (includes / link_libs /
#     defines) and refuse proposals that touch other fields
#   * reject entries with shell metacharacters / suspicious flags
#   * de-duplicate against existing values (no-op when LLM repeats)
#   * back up the original to target.toml.bak.<ts> before write
#   * write a marker so a second run on the same digest is a no-op
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

HELPER="$SCRIPT_ROOT/bin/auto-repair-target-toml"
[ -x "$HELPER" ] || { echo "missing $HELPER" >&2; exit 1; }

fixture_dir="$TEST_TMPDIR/fixture"
mkdir -p "$fixture_dir"

base_toml() {
  cat > "$fixture_dir/target.toml" <<'EOF'
target        = "zlib"
upstream_url  = "https://example.invalid/zlib"
build_system  = "cmake"
pinned_rev    = "deadbeef"

includes      = [".", "include"]
link_libs     = ["/path/to/adler32.c"]
defines       = ["-DNOCRYPT"]

[sanitizer]
enabled = ["asan"]
EOF
}

write_build_log() {
  cat > "$fixture_dir/H-stub-harness.c.deadbeefdeadbeefdeadbeef.build.log" <<'EOF'
/usr/bin/ld: /tmp/infback9.o: in function `inflateBack9Init_':
infback9.c:(.text+0x180): undefined reference to `zcalloc'
/usr/bin/ld: infback9.c:(.text+0x230): undefined reference to `zcfree'
clang: error: linker command failed with exit code 1 (use -v to see invocation)
EOF
}

# ═══════════════════════════════════════════════════════════════
# 1. TARGET_TOML_AUTO_REPAIR=0 → rc=1, no write
# ═══════════════════════════════════════════════════════════════

base_toml
write_build_log
toml_sha_before=$(shasum "$fixture_dir/target.toml" | awk '{print $1}')
TARGET_TOML_AUTO_REPAIR=0 \
  "$HELPER" --toml "$fixture_dir/target.toml" \
            --build-log "$fixture_dir/H-stub-harness.c.deadbeefdeadbeefdeadbeef.build.log" \
            --logdir "$TEST_TMPDIR/logs" >/dev/null 2>&1
rc=$?
assert_eq "1" "$rc" "TARGET_TOML_AUTO_REPAIR=0 → rc=1"
toml_sha_after=$(shasum "$fixture_dir/target.toml" | awk '{print $1}')
assert_eq "$toml_sha_before" "$toml_sha_after" "disabled: target.toml unchanged"

# ═══════════════════════════════════════════════════════════════
# 2. LLM_DECIDE_DISABLE=1 with no mock → rc=1, no write
# ═══════════════════════════════════════════════════════════════

LLM_DECIDE_DISABLE=1 \
  "$HELPER" --toml "$fixture_dir/target.toml" \
            --build-log "$fixture_dir/H-stub-harness.c.deadbeefdeadbeefdeadbeef.build.log" \
            --logdir "$TEST_TMPDIR/logs" >/dev/null 2>&1
rc=$?
assert_eq "1" "$rc" "LLM_DECIDE_DISABLE=1 + no mock → rc=1"

# ═══════════════════════════════════════════════════════════════
# 3. Mock proposing safe additions → applies, backs up, marker
# ═══════════════════════════════════════════════════════════════

base_toml
write_build_log
rm -f "$fixture_dir"/target.toml.bak.* 2>/dev/null
export LLM_DECIDE_MOCK_TARGET_TOML_REPAIR='{"link_libs":["/path/to/zutil.c","/path/to/infback9.c"],"defines":["-DZ_INTERNAL"]}'
"$HELPER" --toml "$fixture_dir/target.toml" \
          --build-log "$fixture_dir/H-stub-harness.c.deadbeefdeadbeefdeadbeef.build.log" \
          --logdir "$TEST_TMPDIR/logs" >/dev/null 2>&1
rc=$?
assert_eq "0" "$rc" "mock with safe additions → rc=0"
assert_file_contains "$fixture_dir/target.toml" "zutil.c" "mock additions present in target.toml"
assert_file_contains "$fixture_dir/target.toml" "Z_INTERNAL" "mock define present in target.toml"
if ls "$fixture_dir"/target.toml.bak.* >/dev/null 2>&1; then
  pass "backup target.toml.bak.<ts> exists"
else
  fail "backup target.toml.bak.<ts> exists" "no backup found in $fixture_dir"
fi
# Marker prevents replay.
marker_count=$(find "$TEST_TMPDIR/logs" -name '.target-toml-auto-repair-*' -type f 2>/dev/null | wc -l | tr -d ' ')
assert_eq "1" "$marker_count" "single repair marker written"
# Log line exists.
if grep -q "APPLY:" "$TEST_TMPDIR/logs/target-toml-auto-repair.log" 2>/dev/null; then
  pass "audit log records APPLY"
else
  fail "audit log records APPLY" "no APPLY line in target-toml-auto-repair.log"
fi

# ═══════════════════════════════════════════════════════════════
# 4. Second run on same digest → no-op (rc=0, no new backup)
# ═══════════════════════════════════════════════════════════════

prev_backup_count=$(ls "$fixture_dir"/target.toml.bak.* 2>/dev/null | wc -l | tr -d ' ')
"$HELPER" --toml "$fixture_dir/target.toml" \
          --build-log "$fixture_dir/H-stub-harness.c.deadbeefdeadbeefdeadbeef.build.log" \
          --logdir "$TEST_TMPDIR/logs" >/dev/null 2>&1
rc=$?
new_backup_count=$(ls "$fixture_dir"/target.toml.bak.* 2>/dev/null | wc -l | tr -d ' ')
# After the first apply, the marker for the (build_log, toml) digest
# changes (because the toml changed). The new digest is fresh, so the
# helper consults the mock again. The mock proposes the SAME entries —
# which now already exist in target.toml — so we go down the
# "no new entries" path. That returns rc=1 and writes no backup.
if [ "$rc" -eq 0 ] || [ "$rc" -eq 1 ]; then
  pass "second run: returns rc 0 or 1 (no error)"
else
  fail "second run: returns rc 0 or 1 (no error)" "rc=$rc"
fi
assert_eq "$prev_backup_count" "$new_backup_count" "second run: no extra backups"

# ═══════════════════════════════════════════════════════════════
# 5. Unsafe entries are rejected (shell metachars, bad -D form)
# ═══════════════════════════════════════════════════════════════

base_toml
write_build_log
rm -f "$fixture_dir"/target.toml.bak.* "$TEST_TMPDIR/logs/.target-toml-auto-repair-"* 2>/dev/null
export LLM_DECIDE_MOCK_TARGET_TOML_REPAIR='{"link_libs":["`touch /tmp/PWN`","-fno-something"],"defines":["/abs/path","-DGOOD"]}'
"$HELPER" --toml "$fixture_dir/target.toml" \
          --build-log "$fixture_dir/H-stub-harness.c.deadbeefdeadbeefdeadbeef.build.log" \
          --logdir "$TEST_TMPDIR/logs" >/dev/null 2>&1
rc=$?
# At least -DGOOD survives → rc=0, target.toml updated. The backtick
# entry must NOT appear.
assert_eq "0" "$rc" "partial-safe proposal: at least one entry applied"
assert_file_contains "$fixture_dir/target.toml" "DGOOD" "safe define applied"
if grep -qF '`touch /tmp/PWN`' "$fixture_dir/target.toml"; then
  fail "shell-metachar entry refused" "the dangerous entry leaked into target.toml"
else
  pass "shell-metachar entry refused"
fi
if grep -qF '/abs/path' "$fixture_dir/target.toml"; then
  fail "bad-define-form entry refused" "non-flag /abs/path leaked into defines"
else
  pass "bad-define-form entry refused"
fi

# ═══════════════════════════════════════════════════════════════
# 6. Mock returning {} (LLM declines) → rc=1, no change
# ═══════════════════════════════════════════════════════════════

base_toml
write_build_log
rm -f "$fixture_dir"/target.toml.bak.* "$TEST_TMPDIR/logs/.target-toml-auto-repair-"* 2>/dev/null
toml_sha_before=$(shasum "$fixture_dir/target.toml" | awk '{print $1}')
export LLM_DECIDE_MOCK_TARGET_TOML_REPAIR='{}'
"$HELPER" --toml "$fixture_dir/target.toml" \
          --build-log "$fixture_dir/H-stub-harness.c.deadbeefdeadbeefdeadbeef.build.log" \
          --logdir "$TEST_TMPDIR/logs" >/dev/null 2>&1
rc=$?
assert_eq "1" "$rc" "empty proposal → rc=1"
toml_sha_after=$(shasum "$fixture_dir/target.toml" | awk '{print $1}')
assert_eq "$toml_sha_before" "$toml_sha_after" "empty proposal: target.toml unchanged"

# ═══════════════════════════════════════════════════════════════
# 7. Cap enforcement: > _MAX_NEW_ENTRIES_TOTAL refused
# ═══════════════════════════════════════════════════════════════

base_toml
write_build_log
rm -f "$fixture_dir"/target.toml.bak.* "$TEST_TMPDIR/logs/.target-toml-auto-repair-"* 2>/dev/null
toml_sha_before=$(shasum "$fixture_dir/target.toml" | awk '{print $1}')
# 9 + 9 + 9 = 27 entries > MAX_NEW_ENTRIES_TOTAL=16. Note: each field
# also has its own cap at 8, so per-field accepts 8 each → 24 total →
# triggers the total cap on the third field.
mock_arr() {
  local prefix="$1" n="$2" i out=""
  for i in $(seq 1 "$n"); do
    out="${out}\"${prefix}${i}\","
  done
  echo "${out%,}"
}
export LLM_DECIDE_MOCK_TARGET_TOML_REPAIR="{\"includes\":[$(mock_arr inc_ 9)],\"link_libs\":[$(mock_arr /lib/ 9)],\"defines\":[$(mock_arr -Dflag 9)]}"
"$HELPER" --toml "$fixture_dir/target.toml" \
          --build-log "$fixture_dir/H-stub-harness.c.deadbeefdeadbeefdeadbeef.build.log" \
          --logdir "$TEST_TMPDIR/logs" >/dev/null 2>&1
rc=$?
assert_eq "2" "$rc" "over-cap proposal → rc=2 (refused)"
toml_sha_after=$(shasum "$fixture_dir/target.toml" | awk '{print $1}')
assert_eq "$toml_sha_before" "$toml_sha_after" "over-cap proposal: target.toml unchanged"

summary
