#!/usr/bin/env bash
# Unit tests for _normalize_subsystem_key and _subsystem_keys_collide —
# the canonical (file, last_qualifier, function) key and wildcard-match
# rule used to detect cross-agent subsystem collisions and queue-side
# overlap, independent of how the agent reported the line number or the
# C++ class qualifier in its raw subsystem string.
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

check() {
  local raw="$1" expected="$2" name="$3"
  local got
  got=$(_normalize_subsystem_key "$raw")
  assert_eq "$expected" "$got" "$name"
}

collide() {
  local a="$1" b="$2" name="$3"
  if _subsystem_keys_collide "$a" "$b"; then
    pass "$name (collide)"
  else
    fail "$name: expected '$a' and '$b' to collide"
  fi
}

no_collide() {
  local a="$1" b="$2" name="$3"
  if _subsystem_keys_collide "$a" "$b"; then
    fail "$name: expected '$a' and '$b' NOT to collide"
  else
    pass "$name (no collide)"
  fi
}

# ── Canonical key format: file|last_q|func ───────────────────────
check "src/sampledb.cpp:write_selected:247" "src/sampledb.cpp||write_selected" \
  "bare function + line → file||func"
check "src/sampledb.cpp:write_selected:241" "src/sampledb.cpp||write_selected" \
  "different :line collapses to same key (bare)"
check "src/sampledb.cpp:render:266:42" "src/sampledb.cpp||render" \
  "strips multiple trailing line-numbers"

# ── C++ class qualifier kept in middle slot ──────────────────────
check "src/sampledb.cpp:Store::write_selected:247" "src/sampledb.cpp|Store|write_selected" \
  "single qualifier preserved as last_q"
check "src/sampledb.cpp:Store::Engine::render:266" "src/sampledb.cpp|Engine|render" \
  "chained qualifiers: only innermost kept as last_q"
check "Store::render:266" "|Store|render" \
  "qualifier without file path: empty file slot"
check "Store::Engine::Inner::render" "|Inner|render" \
  "deep chain: innermost qualifier kept"

# ── _subsystem_keys_collide: the wildcard match rule ────────────
# Same canonical key → collide.
k1=$(_normalize_subsystem_key "src/sampledb.cpp:Store::alias_user:227")
k2=$(_normalize_subsystem_key "src/sampledb.cpp:Store::alias_user:221")
collide "$k1" "$k2" \
  "two qualifier+line forms of alias_user (same qualifier)"

# Bare + qualified → collide (wildcard on empty qualifier).
k3=$(_normalize_subsystem_key "src/sampledb.cpp:alias_user:228")
collide "$k1" "$k3" \
  "qualified Store::alias_user collides with bare alias_user"

# Chained-qualifier same-function: Store::Engine::render and Engine::render.
ke1=$(_normalize_subsystem_key "src/x.cpp:Store::Engine::render:100")
ke2=$(_normalize_subsystem_key "src/x.cpp:Engine::render:120")
collide "$ke1" "$ke2" \
  "chained Store::Engine::render collides with Engine::render (same innermost)"

# DIFFERENT nested classes, same leaf name → must NOT collide.
# This is the false-negative case (b) is designed to prevent: methods
# Foo::bar and Foo::Baz::bar in the same file are distinct functions and
# must NOT be treated as a subsystem collision.
kn1=$(_normalize_subsystem_key "src/x.cpp:Foo::bar:50")
kn2=$(_normalize_subsystem_key "src/x.cpp:Foo::Baz::bar:80")
no_collide "$kn1" "$kn2" \
  "Foo::bar and Foo::Baz::bar in same file (distinct nested-class methods)"

# Two distinct classes with same method name in same file → must NOT collide.
kc1=$(_normalize_subsystem_key "src/x.cpp:Foo::bar:10")
kc2=$(_normalize_subsystem_key "src/x.cpp:Baz::bar:200")
no_collide "$kc1" "$kc2" \
  "Foo::bar and Baz::bar in same file (distinct classes, same leaf name)"

# Different files, same canonical → must NOT collide.
kf1=$(_normalize_subsystem_key "src/foo.cpp:bar:50")
kf2=$(_normalize_subsystem_key "src/baz.cpp:bar:50")
no_collide "$kf1" "$kf2" \
  "same function name in different files"

# Empty / unknown never collide with anything.
no_collide "unknown" "src/x.cpp||bar" "unknown vs anything"
no_collide "" "src/x.cpp||bar" "empty vs anything"
no_collide "malformed" "src/x.cpp||bar" "malformed (no pipes) vs anything"

# ── Identity / edge cases ─────────────────────────────────────────
check "src/main.cpp" "||src/main.cpp" \
  "plain file path (no func segment): becomes ||<path>"
check "src/sampledb.cpp:render" "src/sampledb.cpp||render" \
  "file:func without line: bare-function form"
check "" "unknown" \
  "empty input maps to unknown sentinel"
check "unknown" "unknown" \
  "literal unknown stays unknown"

# ── Edge cases: numbers that are NOT line numbers ────────────────
# A C++ function named "foo123" is a valid identifier; we should not
# accidentally strip the trailing digits.
check "src/x.cpp:foo123" "src/x.cpp||foo123" \
  "trailing digits inside an identifier are not stripped"
# A path like "v8/src/code-stub-assembler.h:Foo::bar:123" should
# yield canonical (v8/src/code-stub-assembler.h, Foo, bar).
check "v8/src/code-stub-assembler.h:Foo::bar:123" "v8/src/code-stub-assembler.h|Foo|bar" \
  "real v8-style qualifier+line collapses cleanly"

# ── Whitespace tolerance ──────────────────────────────────────────
# Subsystem strings always reach this helper trimmed (the producer is
# get_agent_subsystem -> structured_state which serializes JSON). We
# document the unbleached behavior: trailing whitespace defeats the
# line-number strip because the anchor is "end of string". Caller's
# responsibility to trim; we never see whitespace in practice.
check " src/x.cpp:foo:1 " "|| src/x.cpp:foo:1 " \
  "trailing whitespace defeats line-number strip (documented)"

teardown_test_env
summary
