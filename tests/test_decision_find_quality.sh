#!/usr/bin/env bash
# tests/test_decision_find_quality.sh — LLM substance + classification gate.
#
# The LLM verdict is written inline to .llm-find-quality.json. The gate
# only keeps security findings: non-security verdicts move the FIND
# directory to findings-rejected/ at quorum (override: .keep / .reviewed).
#
# 1. LLM accepts → cache stored with class+severity, FIND kept.
# 2. LLM rejects → FIND directory moved to findings-rejected/.
# 3. LLM unavailable / undecided → no cache, FIND kept as-is.
# 4. Malformed LLM JSON → treated as undecided.

set -uo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/llm_decide.sh"
source "$SCRIPT_ROOT/lib/triage.sh"

setup_test_env
# Reachability would phone home — block it for the unit test.
export REACHABILITY_AUTO=0
export FIND_CLUSTER_DISABLE=1
export LLM_FIELD_FILL_DISABLE=1
# Mock LLM is deterministic; the budget cap exists to bound real-backend
# spend, not mock test coverage. Disable it so this test can grow its
# fixture set without bumping into the 40-call default.
export LLM_DECIDE_MAX_CALLS=0

reset_findings() {
  rm -rf "$RESULTS_DIR/findings" "$RESULTS_DIR/findings-rejected"
  mkdir -p "$RESULTS_DIR/findings"
}

mk_find() {
  local id="$1" body="$2"
  local d="$RESULTS_DIR/findings/$id"
  mkdir -p "$d"
  printf '%s\n' "$body" > "$d/description.md"
  echo "$d"
}

# Vacuous body — the LLM-mock decides.
VACUOUS=$(cat <<'EOF'
# FIND-V1 — Suspicious code

The function looks suspicious. We should look at it more carefully.
EOF
)

# Substantive body — concrete location, named issue class, rationale.
SUBSTANTIVE=$(cat <<'EOF'
# FIND-S1 — Authorization bypass in admin/users handler

## Location
server/handlers/admin.go:HandleListUsers:42

## Issue class
Authorization bypass / info disclosure.

## Rationale
The handler reads the requester role from a caller-controlled cookie
without checking against the server-side session store. Any logged-in
user can set role=admin and enumerate the email addresses of other users.
EOF
)

# 1. LLM accepts → FIND stays, cache written with class label.
mk_find FIND-V1 "$VACUOUS" >/dev/null
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"clear authz bypass","class":"auth:bypass","severity":"high"}'
validate_find_gate >/dev/null 2>&1
assert_dir_exists "$RESULTS_DIR/findings/FIND-V1" "LLM accept: FIND stays in findings/"
assert_file_exists "$RESULTS_DIR/findings/FIND-V1/.llm-find-quality.json" "LLM accept: cache written"
assert_file_contains "$RESULTS_DIR/findings/FIND-V1/.llm-find-quality.json" "auth:bypass" \
  "LLM accept: class label cached"
assert_file_contains "$RESULTS_DIR/findings/FIND-V1/.llm-find-quality.json" "high" \
  "LLM accept: severity cached"
[ ! -d "$RESULTS_DIR/findings-rejected" ] \
  && pass "LLM accept: no findings-rejected/ created" \
  || fail "LLM accept: no findings-rejected/ created" "findings-rejected/ exists"
unset LLM_DECIDE_MOCK_FIND_QUALITY

# Re-running with LLM disabled keeps the cached accept.
LLM_DECIDE_DISABLE=1 validate_find_gate >/dev/null 2>&1
assert_dir_exists "$RESULTS_DIR/findings/FIND-V1" "LLM disabled: cached FIND accept stays"
reset_findings

# 2. LLM rejects ONCE → FIND stays (pending-drop marker). A single LLM
#    verdict is not enough to drop a FIND — a false-reject would
#    permanently hide a real bug. After a SECOND independent reject on
#    the same content, the FIND is QUARANTINED (moved to
#    findings-rejected/) rather than deleted, so QA can audit
#    false-rejects.
mk_find FIND-V2 "$VACUOUS" >/dev/null
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":false,"reason":"correctness bug, no security impact","class":"","severity":""}'
validate_find_gate >/dev/null 2>&1
assert_dir_exists "$RESULTS_DIR/findings/FIND-V2" "LLM reject (1/2): FIND stays pending second verdict"
assert_file_exists "$RESULTS_DIR/findings/FIND-V2/.pending-drop" "LLM reject (1/2): pending-drop marker written"
assert_file_contains "$RESULTS_DIR/findings/FIND-V2/.llm-find-quality.json" '"reject_count": *1' \
  "LLM reject (1/2): reject_count incremented to 1"
# Second pass with the same mock → reject_count reaches 2 → quarantine.
validate_find_gate >/dev/null 2>&1
assert_dir_not_exists "$RESULTS_DIR/findings/FIND-V2" "LLM reject (2/2): FIND moved out of findings/"
assert_dir_exists "$RESULTS_DIR/findings-rejected/FIND-V2" "LLM reject (2/2): FIND quarantined to findings-rejected/"
unset LLM_DECIDE_MOCK_FIND_QUALITY
reset_findings

# 2a. Quorum override via FIND_GATE_QUORUM=1 (e.g. for legacy callers that
#     want the old single-verdict behavior). One reject → straight to
#     quarantine.
mk_find FIND-V2-Q1 "$VACUOUS" >/dev/null
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":false,"reason":"non-security","class":"","severity":""}'
FIND_GATE_QUORUM=1 validate_find_gate >/dev/null 2>&1
assert_dir_not_exists "$RESULTS_DIR/findings/FIND-V2-Q1" "FIND_GATE_QUORUM=1: single verdict quarantines"
assert_dir_exists "$RESULTS_DIR/findings-rejected/FIND-V2-Q1" "FIND_GATE_QUORUM=1: quarantined under findings-rejected/"
unset LLM_DECIDE_MOCK_FIND_QUALITY
reset_findings

# 2b. Verdict flip mid-quorum: first call rejects, second call accepts
#     → FIND stays, pending-drop marker cleared.
mk_find FIND-V2-FLIP "$VACUOUS" >/dev/null
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":false,"reason":"reviewer 1 unsure","class":"","severity":""}'
validate_find_gate >/dev/null 2>&1
assert_file_exists "$RESULTS_DIR/findings/FIND-V2-FLIP/.pending-drop" "flip: pending-drop after first reject"
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"reviewer 2 confirms security impact","class":"auth:bypass","severity":"high"}'
validate_find_gate >/dev/null 2>&1
assert_dir_exists "$RESULTS_DIR/findings/FIND-V2-FLIP" "flip: FIND stays after accept"
assert_file_not_exists "$RESULTS_DIR/findings/FIND-V2-FLIP/.pending-drop" "flip: pending-drop cleared on accept"
unset LLM_DECIDE_MOCK_FIND_QUALITY
reset_findings

# 2b. .keep override prevents deletion even when the LLM rejects.
mk_find FIND-V2-KEEP "$VACUOUS" >/dev/null
touch "$RESULTS_DIR/findings/FIND-V2-KEEP/.keep"
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":false,"reason":"non-security","class":"","severity":""}'
validate_find_gate >/dev/null 2>&1
assert_dir_exists "$RESULTS_DIR/findings/FIND-V2-KEEP" ".keep pins FIND despite LLM reject"
unset LLM_DECIDE_MOCK_FIND_QUALITY
reset_findings

# 2c. .reviewed override also pins the dir.
mk_find FIND-V2-REVIEWED "$VACUOUS" >/dev/null
touch "$RESULTS_DIR/findings/FIND-V2-REVIEWED/.reviewed"
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":false,"reason":"non-security","class":"","severity":""}'
validate_find_gate >/dev/null 2>&1
assert_dir_exists "$RESULTS_DIR/findings/FIND-V2-REVIEWED" ".reviewed pins FIND despite LLM reject"
unset LLM_DECIDE_MOCK_FIND_QUALITY
reset_findings

# 3. LLM disabled on an uncached FIND → no cache, FIND kept as-is
#    (gate is a no-op beyond "found a report file"; deletion only fires
#    when the LLM has rendered an accept=false verdict).
mk_find FIND-V3 "$SUBSTANTIVE" >/dev/null
LLM_DECIDE_DISABLE=1 validate_find_gate >/dev/null 2>&1
assert_dir_exists "$RESULTS_DIR/findings/FIND-V3" "LLM disabled: FIND kept"
assert_file_not_exists "$RESULTS_DIR/findings/FIND-V3/.llm-find-quality.json" \
  "LLM disabled: no cache written"
reset_findings

# 4. Malformed LLM JSON → undecided, no cache, FIND kept.
mk_find FIND-V4 "$VACUOUS" >/dev/null
export LLM_DECIDE_MOCK_FIND_QUALITY='not json'
validate_find_gate >/dev/null 2>&1
assert_dir_exists "$RESULTS_DIR/findings/FIND-V4" "malformed LLM: FIND stays"
assert_file_not_exists "$RESULTS_DIR/findings/FIND-V4/.llm-find-quality.json" \
  "malformed LLM: no cache"
unset LLM_DECIDE_MOCK_FIND_QUALITY
reset_findings

# 5. Stale-cache invalidation: an older decision_version cache must NOT
#    short-circuit the gate. The new decision should be written.
mk_find FIND-STALE "$SUBSTANTIVE" >/dev/null
# Pre-seed a v2 verdict that DISAGREES with what the current mock will
# return. The mock will accept; the stale v2 cache says reject. If the
# version check works, the gate must call the LLM again and overwrite
# the cache with accept=true. Use the correct content_sha1 — otherwise
# the hash mismatch alone would force re-evaluation and we wouldn't be
# testing the version field specifically.
substantive_hash=$(_triage_file_sha1 "$RESULTS_DIR/findings/FIND-STALE/description.md" 2>/dev/null || true)
cat > "$RESULTS_DIR/findings/FIND-STALE/.llm-find-quality.json" <<EOF
{"decision":"find_quality","decision_version":"v2","content_sha1":"$substantive_hash","accept":false,"reason":"stale v2 rubric rejection","class":"","severity":"","cached_at":"2026-04-24T00:00:00Z"}
EOF
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"current reviewer accepts","class":"auth:bypass","severity":"high"}'
validate_find_gate >/dev/null 2>&1
assert_file_contains "$RESULTS_DIR/findings/FIND-STALE/.llm-find-quality.json" '"decision_version": *"v7"' \
  "stale v2 cache: re-evaluated under v7"
assert_file_contains "$RESULTS_DIR/findings/FIND-STALE/.llm-find-quality.json" "auth:bypass" \
  "stale v2 cache: new class label written"
assert_file_contains "$RESULTS_DIR/findings/FIND-STALE/.llm-find-quality.json" '"accept": *true' \
  "stale v2 cache: new verdict overrides old reject"
unset LLM_DECIDE_MOCK_FIND_QUALITY
reset_findings

# 6. Open-ended classification: an unusual class label the gate has never
#    seen must round-trip through the cache without normalisation. This is
#    the contract that lets the LLM invent labels for unfamiliar issue
#    classes (e.g. "side-channel:cache-timing", "config:permissive-cors").
mk_find FIND-CLASS "$SUBSTANTIVE" >/dev/null
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"clear ReDoS","class":"side-channel:cache-timing","severity":"low","dedup_key":"redos-regex-timing"}'
validate_find_gate >/dev/null 2>&1
assert_file_contains "$RESULTS_DIR/findings/FIND-CLASS/.llm-find-quality.json" \
  "side-channel:cache-timing" \
  "open-ended class label survives cache write/read"
assert_file_contains "$RESULTS_DIR/findings/FIND-CLASS/.llm-find-quality.json" \
  '"severity": *"low"' \
  "severity field captured verbatim"
assert_file_contains "$RESULTS_DIR/findings/FIND-CLASS/.llm-find-quality.json" \
  '"dedup_key": *"redos-regex-timing"' \
  "valid dedup_key persisted in cache"
unset LLM_DECIDE_MOCK_FIND_QUALITY
reset_findings

# 6b. dedup_key validation — too-short / single-token / invalid chars are
#     dropped and the cache stores an empty dedup_key (Layer 1 fallback).
mk_find FIND-BADKEY "$SUBSTANTIVE" >/dev/null
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"ok","class":"auth:bypass","severity":"low","dedup_key":"oops"}'
validate_find_gate >/dev/null 2>&1
assert_file_contains "$RESULTS_DIR/findings/FIND-BADKEY/.llm-find-quality.json" \
  '"dedup_key": *""' \
  "single-token dedup_key rejected (must contain hyphen/underscore)"
unset LLM_DECIDE_MOCK_FIND_QUALITY
reset_findings

mk_find FIND-BADKEY2 "$SUBSTANTIVE" >/dev/null
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"ok","class":"auth:bypass","severity":"low","dedup_key":"Has Spaces And UPPER"}'
validate_find_gate >/dev/null 2>&1
assert_file_contains "$RESULTS_DIR/findings/FIND-BADKEY2/.llm-find-quality.json" \
  '"dedup_key": *"has-spaces-and-upper"' \
  "dedup_key spaces lowercased and hyphenated"
unset LLM_DECIDE_MOCK_FIND_QUALITY
reset_findings

# 6c. Stale v4 cache: bumping the rubric must re-evaluate even when
#     the content sha1 still matches. v7 flips the polarity of the
#     ALL-hold gate and drops the hedging auto-reject, so old verdicts
#     under earlier rubrics must be re-evaluated under the new rules.
mk_find FIND-STALEV4 "$SUBSTANTIVE" >/dev/null
substantive_hash=$(_triage_file_sha1 "$RESULTS_DIR/findings/FIND-STALEV4/description.md" 2>/dev/null || true)
cat > "$RESULTS_DIR/findings/FIND-STALEV4/.llm-find-quality.json" <<EOF
{"decision":"find_quality","decision_version":"v4","content_sha1":"$substantive_hash","accept":true,"reason":"v4 acceptance under looser rubric","class":"auth:bypass","severity":"high","dedup_key":"old-key","cached_at":"2026-04-24T00:00:00Z"}
EOF
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"v7 reviewer confirms","class":"auth:bypass","severity":"high","dedup_key":"missing-server-side-check"}'
validate_find_gate >/dev/null 2>&1
assert_file_contains "$RESULTS_DIR/findings/FIND-STALEV4/.llm-find-quality.json" '"decision_version": *"v7"' \
  "stale v4 cache: re-evaluated under v7"
assert_file_contains "$RESULTS_DIR/findings/FIND-STALEV4/.llm-find-quality.json" \
  '"dedup_key": *"missing-server-side-check"' \
  "stale v4 cache: dedup_key updated on re-evaluation"
unset LLM_DECIDE_MOCK_FIND_QUALITY
reset_findings

# 7. Regression guard: the legacy bucket helpers are gone. If anyone
#    re-introduces them, this test fails loudly.
for fn in _reject_find_dir _needs_review_find_dir _requeue_find_needs_review_dirs; do
  if declare -f "$fn" >/dev/null 2>&1; then
    fail "legacy helper $fn must not exist" "function is defined"
  else
    pass "legacy helper $fn is gone"
  fi
done

# FIND_REJECT_NEEDS_REVIEW is a legacy env var that no longer affects the
# gate. The current gate uses FIND_GATE_QUORUM (default 2) and
# FIND_GATE_QUARANTINE_DIR; this env var must be ignored.
mk_find FIND-NOENV "$VACUOUS" >/dev/null
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":false,"reason":"non-security correctness bug","class":"","severity":""}'
# Two passes (default quorum=2) to reach the drop threshold.
FIND_REJECT_NEEDS_REVIEW=0 validate_find_gate >/dev/null 2>&1
FIND_REJECT_NEEDS_REVIEW=0 validate_find_gate >/dev/null 2>&1
assert_dir_not_exists "$RESULTS_DIR/findings/FIND-NOENV" \
  "FIND_REJECT_NEEDS_REVIEW=0 is ignored: non-security FIND still quarantined after quorum"
assert_dir_exists "$RESULTS_DIR/findings-rejected/FIND-NOENV" \
  "FIND_REJECT_NEEDS_REVIEW=0: drop bucket is findings-rejected/"
unset LLM_DECIDE_MOCK_FIND_QUALITY

teardown_test_env
summary
