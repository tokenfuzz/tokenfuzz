#!/usr/bin/env bash
# Integration-style tests for the PLAN-time subsystem-claim ledger (#4)
# and the canonical-key path through diversify_subsystem_collisions
# (#11). Verifies that two agents reporting different forms of the same
# (file, function) — e.g. "Store::write_selected:247" and
# "write_selected:241" — are detected as collisions even though their
# raw subsystem strings differ.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

audit_extract_function() {
  local name="$1"
  awk -v name="$name" '
    $0 ~ "^" name "\\(\\) \\{" { in_func=1 }
    in_func { print }
    in_func && $0 == "}" { exit }
  ' "$SCRIPT_ROOT/bin/audit"
}

eval "$(audit_extract_function _normalize_subsystem_key)"
eval "$(audit_extract_function _subsystem_keys_collide)"
eval "$(audit_extract_function diversify_subsystem_collisions)"
eval "$(audit_extract_function recover_exhausted_agent)"
eval "$(audit_extract_function agent_probe_activity_score)"

# Minimal stubs — diversify_subsystem_collisions needs these.
NUM_AGENTS=3
export NUM_AGENTS

log() { printf '%s\n' "$*" >> "$INDEX"; }
audit_log() { log "$@"; }
strategy_tag() { printf 'Strategy%s' "${1#S}"; }

# Fake per-agent subsystem (set with set_fake_subsystem N "<str>").
get_agent_subsystem() {
  local var="FAKE_SUBSYSTEM_$1"
  echo "${!var:-unknown}"
}
set_fake_subsystem() { eval "FAKE_SUBSYSTEM_$1=\"\$2\""; }

# Track which agents got their resume state cleared.
CLEAR_LOG="$TEST_TMPDIR/clear-log"
: > "$CLEAR_LOG"
clear_agent_resume_state() {
  printf '%s\n' "$1" >> "$CLEAR_LOG"
}

# Track archive (re-pin) calls.
ARCHIVE_LOG="$TEST_TMPDIR/archive-log"
: > "$ARCHIVE_LOG"
archive_agent_subsystem() {
  printf '%s:%s\n' "$1" "$2" >> "$ARCHIVE_LOG"
  # Echo a recovery pair so recover_exhausted_agent works.
  printf 'S1 S5'
}
# recover_exhausted_agent shells out via the rotation helpers, but for
# this test we only care that diversify_subsystem_collisions identifies
# the collision and calls recover_exhausted_agent. Stub it directly.
recover_exhausted_agent() {
  # Touch the archive log so the test sees the call.
  printf '%s:%s\n' "$1" "$2" >> "$ARCHIVE_LOG"
  printf 'S1 S5'
}

# State files (some tests check probe activity score).
mkdir -p "$RESULTS_DIR"
state_file_path() { printf '%s/AUDIT_STATE-%s.md' "$RESULTS_DIR" "$1"; }
printf 'asan_runs: 0\n' > "$(state_file_path 1)"
printf 'asan_runs: 10\n' > "$(state_file_path 2)"
printf 'asan_runs: 0\n' > "$(state_file_path 3)"

archive_calls() {
  cat "$ARCHIVE_LOG" 2>/dev/null | tr '\n' ' '
}

# ── Case 1: same literal subsystem (regression — pre-fix already caught) ─
set_fake_subsystem 1 "src/sampledb.cpp"
set_fake_subsystem 2 "src/sampledb.cpp"
set_fake_subsystem 3 "src/other.cpp"
: > "$ARCHIVE_LOG"; : > "$INDEX"
diversify_subsystem_collisions
rc=$?
assert_eq 0 "$rc" "literal collision detected (rc=0)"
got=$(archive_calls)
if [[ "$got" == *"1:"* ]] || [[ "$got" == *"2:"* ]]; then
  pass "one of the colliding agents was archived (literal case)"
else
  fail "literal-string collision: expected agent 1 or 2 archived; got='$got'"
fi

# ── Case 2: SAME canonical key, DIFFERENT raw form (the bug we're fixing) ─
# Pre-fix: literal string comparison treats these as distinct, no
# collision detected, both agents continue on the same bug.
# Post-fix: canonical keys are file|last_q|func; the wildcard rule in
# _subsystem_keys_collide treats an empty last_q as matching any other,
# so 'src/sampledb.cpp|Store|write_selected' and 'src/sampledb.cpp||write_selected'
# collide.
set_fake_subsystem 1 "src/sampledb.cpp:Store::write_selected:247"
set_fake_subsystem 2 "src/sampledb.cpp:write_selected:241"
set_fake_subsystem 3 "src/other.cpp:helper:10"
: > "$ARCHIVE_LOG"; : > "$INDEX"
diversify_subsystem_collisions
rc=$?
assert_eq 0 "$rc" "canonical-key collision detected across different raw forms"
got=$(archive_calls)
if [[ "$got" == *"1:"* ]] || [[ "$got" == *"2:"* ]]; then
  pass "canonical-key path: one of the colliding agents was archived"
else
  fail "canonical-key collision: expected agent 1 or 2 archived; got='$got'"
fi
# The log line names both agents' raw subsystem displays — at least the
# bare form 'src/sampledb.cpp:write_selected:241' is grep-friendly.
assert_file_contains "$INDEX" "src/sampledb.cpp:write_selected:241" \
  "log line names at least one of the colliding agents' raw subsystem"

# ── Case 3: DIFFERENT functions in the same file — NO collision ──
# alias_user and write_selected are distinct bugs even in the same file.
set_fake_subsystem 1 "src/sampledb.cpp:Store::alias_user:227"
set_fake_subsystem 2 "src/sampledb.cpp:Store::write_selected:247"
set_fake_subsystem 3 "src/sampledb.cpp:Store::render:266"
: > "$ARCHIVE_LOG"; : > "$INDEX"
diversify_subsystem_collisions
rc=$?
assert_eq 1 "$rc" "different (file, function) tuples are not a collision (rc=1)"
got=$(archive_calls)
assert_eq "" "$got" "no archive calls when all three agents on distinct functions"

# ── Case 4: chained class qualifiers (Store::Engine::render) ─────
set_fake_subsystem 1 "src/x.cpp:Store::Engine::render:100"
set_fake_subsystem 2 "src/x.cpp:Engine::render:120"
set_fake_subsystem 3 "src/y.cpp:other:1"
: > "$ARCHIVE_LOG"; : > "$INDEX"
diversify_subsystem_collisions
rc=$?
assert_eq 0 "$rc" "chained qualifiers collapse to same canonical key"
got=$(archive_calls)
if [[ "$got" == *"1:"* ]] || [[ "$got" == *"2:"* ]]; then
  pass "chained qualifier collision detected"
else
  fail "chained qualifier: no archive call (got='$got')"
fi

# ── Case 5: unknown / empty subsystems are ignored ─────────────
set_fake_subsystem 1 "unknown"
set_fake_subsystem 2 "unknown"
set_fake_subsystem 3 ""
: > "$ARCHIVE_LOG"; : > "$INDEX"
diversify_subsystem_collisions
rc=$?
assert_eq 1 "$rc" "unknown/empty subsystems do not count as a collision"
assert_eq "" "$(archive_calls)" "no archive calls for unknown/empty"

# ── Case 6: distinct nested-class methods in the same file ─────
# This is the false-positive that motivated picking (b) over strip-all.
# Foo::bar and Foo::Baz::bar both name a function 'bar' in src/x.cpp but
# are different methods (one on Foo, one on the nested class Foo::Baz).
# Under strip-all both would canonicalize to 'src/x.cpp:bar' and the
# diversifier would falsely displace one agent; under (b) the innermost
# qualifiers are 'Foo' and 'Baz' (both non-empty AND different), so the
# wildcard rule reports NO collision.
set_fake_subsystem 1 "src/x.cpp:Foo::bar:50"
set_fake_subsystem 2 "src/x.cpp:Foo::Baz::bar:80"
set_fake_subsystem 3 "src/y.cpp:other:1"
: > "$ARCHIVE_LOG"; : > "$INDEX"
diversify_subsystem_collisions
rc=$?
assert_eq 1 "$rc" "distinct nested-class methods are NOT a collision (rc=1)"
assert_eq "" "$(archive_calls)" \
  "no archive calls when nested-class methods share only the leaf name"

# ── Case 7: two distinct classes with the same method name in same file ─
# Foo::bar and Baz::bar are different functions even with one qualifier
# level each. Strip-all would falsely collide them; (b) treats both
# qualifiers as non-empty AND different so no collision.
set_fake_subsystem 1 "src/x.cpp:Foo::bar:30"
set_fake_subsystem 2 "src/x.cpp:Baz::bar:200"
set_fake_subsystem 3 "src/y.cpp:other:1"
: > "$ARCHIVE_LOG"; : > "$INDEX"
diversify_subsystem_collisions
rc=$?
assert_eq 1 "$rc" "Foo::bar and Baz::bar in same file are NOT a collision"
assert_eq "" "$(archive_calls)" \
  "no archive calls when distinct classes share a method-leaf name"

teardown_test_env
summary
