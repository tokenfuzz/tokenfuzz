#!/usr/bin/env bash
# Direct tests for the LLM-cache plumbing helpers extracted from
# lib/triage.sh in the #6 refactor: _triage_cache_sha1_matches and
# _triage_cache_write_envelope, plus the field readers that keep cache
# hits to one jq pass. The gates already have integration coverage
# (test_decision_triage, test_confirm_crash, test_decision_find_quality,
# test_triage), but those exercise the helpers through the gate API only.
# This file pins the helper contract directly so future edits cannot
# silently drift the cache semantics.
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

# ── _triage_crash_triage_cache_fields ─────────────────────────────

crash_triage_cache="$WORK/crash-triage-fields.json"
cat > "$crash_triage_cache" <<'EOF'
{"content_sha1":"crashsha","keep":false,"reason":"cached trace discard","votes":3}
EOF
crash_triage_fields=$(_triage_crash_triage_cache_fields "$crash_triage_cache")
eval "set -- $crash_triage_fields"
assert_eq "crashsha" "${1:-}" "crash-triage fields: content sha"
assert_eq "false" "${2:-}" "crash-triage fields: keep false preserved"
assert_eq "cached trace discard" "${3:-}" "crash-triage fields: reason preserved"
assert_eq "3" "${4:-}" "crash-triage fields: votes"

crash_triage_legacy="$WORK/crash-triage-fields-legacy.json"
printf '{"signature_sha1":"legacycrash","keep":true}' > "$crash_triage_legacy"
crash_triage_fields=$(_triage_crash_triage_cache_fields "$crash_triage_legacy")
eval "set -- $crash_triage_fields"
assert_eq "legacycrash" "${1:-}" "crash-triage fields: legacy sha fallback"
assert_eq "true" "${2:-}" "crash-triage fields: keep true preserved"

crash_triage_src="$(declare -f llm_triage_crash_decision)"
assert_match '_triage_crash_triage_cache_fields "\$cache_candidate"' "$crash_triage_src" \
  "crash-triage cache: parses sidecar fields in one helper call"
assert_not_match 'cached_keep=.*jq' "$crash_triage_src" \
  "crash-triage cache: avoids per-field jq keep reads"
assert_not_match 'cached_votes=.*jq' "$crash_triage_src" \
  "crash-triage cache: avoids per-field jq votes reads"
assert_not_match 'jq -r.*cached LLM discard' "$crash_triage_src" \
  "crash-triage cache: avoids per-field jq reason reads"

# ── _triage_legit_cache_fields ────────────────────────────────────

legit_cache="$WORK/legit-fields.json"
cat > "$legit_cache" <<'EOF'
{"evidence_sha1":"ev123","require_web":"1","legitimate":false,"reason":"cached promotion rejection","votes":3}
EOF
legit_fields=$(_triage_legit_cache_fields "$legit_cache")
eval "set -- $legit_fields"
assert_eq "ev123" "${1:-}" "legit fields: evidence sha"
assert_eq "1" "${2:-}" "legit fields: require_web"
assert_eq "false" "${3:-}" "legit fields: legitimate false preserved"
assert_eq "cached promotion rejection" "${4:-}" "legit fields: reason preserved"
assert_eq "3" "${5:-}" "legit fields: votes"

legit_legacy="$WORK/legit-fields-legacy.json"
printf '{"sha1":"legacysha","require_web":"0","legitimate":true}' > "$legit_legacy"
legit_fields=$(_triage_legit_cache_fields "$legit_legacy")
eval "set -- $legit_fields"
assert_eq "legacysha" "${1:-}" "legit fields: legacy sha fallback"
assert_eq "true" "${3:-}" "legit fields: legitimate true preserved"

legit_src="$(declare -f llm_crash_legitimacy_decision)"
assert_match '_triage_legit_cache_fields "\$cache"' "$legit_src" \
  "legit cache: parses sidecar fields in one helper call"
assert_not_match "jq -r '\\.legitimate'" "$legit_src" \
  "legit cache: avoids per-field jq legitimate reads"
assert_not_match "jq -r '\\.require_web" "$legit_src" \
  "legit cache: avoids per-field jq require_web reads"

# ── _triage_find_quality_cache_fields ─────────────────────────────

find_quality_cache="$WORK/find-quality-fields.json"
cat > "$find_quality_cache" <<'EOF'
{"decision_version":"v13","accept":false,"reason":"cached non-security reason","reject_count":2,"content_sha1":"findsha"}
EOF
find_quality_fields=$(_triage_find_quality_cache_fields "$find_quality_cache")
eval "set -- $find_quality_fields"
assert_eq "v13" "${1:-}" "find-quality fields: decision version"
assert_eq "false" "${2:-}" "find-quality fields: accept false preserved"
assert_eq "cached non-security reason" "${3:-}" "find-quality fields: reason preserved"
assert_eq "2" "${4:-}" "find-quality fields: reject count"
assert_eq "findsha" "${5:-}" "find-quality fields: content sha"
assert_eq "0" "${6:-}" "find-quality fields: accept count defaults to 0 when absent"

find_quality_accept="$WORK/find-quality-fields-accept.json"
cat > "$find_quality_accept" <<'EOF'
{"decision_version":"v13","accept":true,"reason":"cached accept reason","reject_count":0,"content_sha1":"acceptsha","accept_count":2}
EOF
find_quality_fields=$(_triage_find_quality_cache_fields "$find_quality_accept")
eval "set -- $find_quality_fields"
assert_eq "true" "${2:-}" "find-quality fields: accept true preserved"
assert_eq "2" "${6:-}" "find-quality fields: accept count parsed"

find_quality_legacy="$WORK/find-quality-fields-legacy.json"
printf '{"decision_version":"v13","accept":true,"sha1":"legacyfind"}' > "$find_quality_legacy"
find_quality_fields=$(_triage_find_quality_cache_fields "$find_quality_legacy")
eval "set -- $find_quality_fields"
assert_eq "true" "${2:-}" "find-quality fields: accept true preserved"
assert_eq "legacyfind" "${5:-}" "find-quality fields: legacy sha fallback"

find_quality_src="$(declare -f llm_find_quality_decision)"
find_mover_src="$(declare -f _validate_one_find_dir)"
assert_match '_triage_find_quality_cache_fields "\$cache"' "$find_quality_src" \
  "find-quality decision: parses sidecar fields in one helper call"
assert_match '_triage_find_quality_cache_fields "\$cache"' "$find_mover_src" \
  "find-quality mover: parses sidecar fields in one helper call"
assert_not_match "jq -r '\\.decision_version" "$find_quality_src" \
  "find-quality decision: avoids per-field jq decision_version reads"
assert_not_match 'cached_accept=.*jq' "$find_quality_src" \
  "find-quality decision: avoids per-field jq cached accept reads"
assert_not_match "jq -r '\\.accept'" "$find_mover_src" \
  "find-quality mover: avoids per-field jq accept reads"

summary
