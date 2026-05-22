#!/usr/bin/env bash
# Direct tests for the two LLM-cache plumbing helpers extracted from
# lib/triage.sh in the #6 refactor: _triage_cache_sha1_matches and
# _triage_cache_write_envelope. The four gates that use them already
# have integration coverage (test_decision_triage, test_confirm_crash,
# test_decision_find_quality, test_triage), but those exercise the
# helpers through the gate API only. This file pins the helper contract
# directly so future edits cannot silently drift the cache semantics.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# shellcheck disable=SC1090
source "$SCRIPT_ROOT/lib/triage.sh"

WORK="$TEST_TMPDIR/triage-cache"
mkdir -p "$WORK"

# ── _triage_cache_write_envelope ──────────────────────────────────

cache="$WORK/case-write.json"
printf '{"keep": false, "reason": "redacted PII"}' \
  | _triage_cache_write_envelope "$cache" "crash_triage" "content_sha1" "deadbeef"

assert_eq "crash_triage" "$(jq -r '.decision' "$cache")"           "envelope stamps decision name"
assert_eq "deadbeef"     "$(jq -r '.content_sha1' "$cache")"       "envelope stamps content_sha1"
assert_eq "false"        "$(jq -r '.keep' "$cache")"               "envelope preserves caller .keep field"
assert_eq "redacted PII" "$(jq -r '.reason' "$cache")"             "envelope preserves caller .reason field"
cached_at=$(jq -r '.cached_at' "$cache")
[ -n "$cached_at" ] && [ "$cached_at" != "null" ]
assert_eq 0 $? "envelope stamps cached_at timestamp"

# Custom sha1 field name (legit gate uses evidence_sha1).
cache2="$WORK/case-evidence.json"
printf '{"legitimate": true, "reason": "ok"}' \
  | _triage_cache_write_envelope "$cache2" "legit_crash" "evidence_sha1" "abc123"
assert_eq "abc123" "$(jq -r '.evidence_sha1' "$cache2")"           "envelope honors custom sha1 field"
assert_eq ""       "$(jq -r '.content_sha1 // empty' "$cache2")"   "envelope does not leak content_sha1 when caller uses evidence_sha1"

# No-op when sha1 is empty.
cache3="$WORK/case-empty-sha.json"
printf '{"x":1}' | _triage_cache_write_envelope "$cache3" "noop" "content_sha1" ""
if [ ! -e "$cache3" ]; then
  pass "envelope skips write when sha1 is empty"
else
  fail "envelope skips write when sha1 is empty" "cache was written"
fi

# ── _triage_cache_sha1_matches ────────────────────────────────────

if _triage_cache_sha1_matches "$cache" "content_sha1" "deadbeef"; then
  pass "matches: returns 0 on matching sha1"
else
  fail "matches: returns 0 on matching sha1" "got non-zero"
fi

if ! _triage_cache_sha1_matches "$cache" "content_sha1" "feedface"; then
  pass "matches: returns non-zero on sha1 mismatch"
else
  fail "matches: returns non-zero on sha1 mismatch"
fi

if ! _triage_cache_sha1_matches "$WORK/nonexistent.json" "content_sha1" "anything"; then
  pass "matches: returns non-zero when cache is missing"
else
  fail "matches: returns non-zero when cache is missing"
fi

if ! _triage_cache_sha1_matches "$cache" "content_sha1" ""; then
  pass "matches: returns non-zero when expected sha1 is empty"
else
  fail "matches: returns non-zero when expected sha1 is empty"
fi

# Legacy schema fallback: caches written by older code may use
# `signature_sha1` or bare `sha1` — upgrading must not invalidate them.
legacy1="$WORK/legacy-sig.json"
printf '{"decision":"x","signature_sha1":"legacysig","keep":true}' > "$legacy1"
if _triage_cache_sha1_matches "$legacy1" "content_sha1" "legacysig"; then
  pass "matches: signature_sha1 legacy fallback honored"
else
  fail "matches: signature_sha1 legacy fallback honored"
fi

legacy2="$WORK/legacy-bare.json"
printf '{"decision":"x","sha1":"legacybare","keep":true}' > "$legacy2"
if _triage_cache_sha1_matches "$legacy2" "content_sha1" "legacybare"; then
  pass "matches: bare sha1 legacy fallback honored"
else
  fail "matches: bare sha1 legacy fallback honored"
fi

# Canonical field wins over legacy when both are present and differ.
both="$WORK/both.json"
printf '{"content_sha1":"new","signature_sha1":"old","sha1":"older","keep":true}' > "$both"
if _triage_cache_sha1_matches "$both" "content_sha1" "new"; then
  pass "matches: canonical sha1 field preferred over legacy"
else
  fail "matches: canonical sha1 field preferred over legacy"
fi
if ! _triage_cache_sha1_matches "$both" "content_sha1" "old"; then
  pass "matches: legacy field not used when canonical disagrees"
else
  fail "matches: legacy field not used when canonical disagrees"
fi

summary
