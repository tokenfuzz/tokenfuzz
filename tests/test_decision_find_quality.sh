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
assert_file_contains "$RESULTS_DIR/findings/FIND-STALE/.llm-find-quality.json" '"decision_version": *"v10"' \
  "stale v2 cache: re-evaluated under v10"
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
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"clear ReDoS","class":"side-channel:cache-timing","severity":"low"}'
validate_find_gate >/dev/null 2>&1
assert_file_contains "$RESULTS_DIR/findings/FIND-CLASS/.llm-find-quality.json" \
  "side-channel:cache-timing" \
  "open-ended class label survives cache write/read"
assert_file_contains "$RESULTS_DIR/findings/FIND-CLASS/.llm-find-quality.json" \
  '"severity": *"low"' \
  "severity field captured verbatim"
# Identity (dedup_key) is NOT produced by the quality gate any more — it is
# assigned at cluster time by lib/finding_keyer.py (see test_finding_keyer.sh),
# so the gate cache must NOT carry a dedup_key field.
assert_file_not_contains "$RESULTS_DIR/findings/FIND-CLASS/.llm-find-quality.json" \
  'dedup_key' \
  "quality gate cache carries no dedup_key (identity moved to the keyer)"
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
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"v7 reviewer confirms","class":"auth:bypass","severity":"high"}'
validate_find_gate >/dev/null 2>&1
assert_file_contains "$RESULTS_DIR/findings/FIND-STALEV4/.llm-find-quality.json" '"decision_version": *"v10"' \
  "stale v4 cache: re-evaluated under v10"
assert_file_contains "$RESULTS_DIR/findings/FIND-STALEV4/.llm-find-quality.json" \
  '"reason": *"v7 reviewer confirms"' \
  "stale v4 cache: verdict updated on re-evaluation"
unset LLM_DECIDE_MOCK_FIND_QUALITY
reset_findings

# 6d. Stamp-invariance: after an accept verdict is cached, cluster-findings
#     stamps `Cluster:`/`Dedup key:` lines and report_enrich injects
#     `<!-- enrich:* -->` blocks into report.md. Those mutations must NOT bust
#     the verdict cache — otherwise the gate re-asks the LLM on every
#     housekeeping pass forever. The short-circuit keys on the cached verdict
#     (decision_version + accept), never on report content, so an accepted
#     finding stays short-circuited no matter how report.md is rewritten.
mk_find FIND-STAMP "$SUBSTANTIVE" >/dev/null
# Gate selects report.md ahead of description.md — write the narrative there
# so the stamping below lands on the file the gate actually hashes.
cp "$RESULTS_DIR/findings/FIND-STAMP/description.md" "$RESULTS_DIR/findings/FIND-STAMP/report.md"
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"first reviewer accepts","class":"auth:bypass","severity":"high","dedup_key":"missing-server-side-check"}'
validate_find_gate >/dev/null 2>&1
assert_file_contains "$RESULTS_DIR/findings/FIND-STAMP/.llm-find-quality.json" "auth:bypass" \
  "stamp-invariance: initial accept cached"
sha_before=$(jq -r '.content_sha1' "$RESULTS_DIR/findings/FIND-STAMP/.llm-find-quality.json" 2>/dev/null)
# Simulate cluster-findings + report_enrich stamping the report AFTER the
# verdict was cached: a leading Cluster:/Dedup key: pair and an enrich block.
report="$RESULTS_DIR/findings/FIND-STAMP/report.md"
{ printf 'Cluster: FCL-deadbeef (3 reports: x, y) (canonical)\n'; printf 'Dedup key: [llm] missing-server-side-check\n\n'; cat "$report"; \
  printf '\n<!-- enrich:tldr -->\n**Reviewer TL;DR** derived junk\n<!-- /enrich:tldr -->\n'; } > "$report.stamped"
mv "$report.stamped" "$report"
# Re-run with a mock that would change the class IF the LLM were re-asked.
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"SECOND reviewer — different verdict","class":"WRONG-CLASS-SHOULD-NOT-APPEAR","severity":"low","dedup_key":"some-other-key"}'
validate_find_gate >/dev/null 2>&1
assert_file_contains "$RESULTS_DIR/findings/FIND-STAMP/.llm-find-quality.json" "auth:bypass" \
  "stamp-invariance: accept short-circuited across stamps (LLM not re-asked)"
if grep -q "WRONG-CLASS-SHOULD-NOT-APPEAR" "$RESULTS_DIR/findings/FIND-STAMP/.llm-find-quality.json" 2>/dev/null; then
  fail "stamp-invariance: cache must not be re-evaluated after stamping" "re-asked LLM and overwrote verdict"
else
  pass "stamp-invariance: stamps did not trigger an LLM re-ask"
fi
sha_after=$(jq -r '.content_sha1' "$RESULTS_DIR/findings/FIND-STAMP/.llm-find-quality.json" 2>/dev/null)
[ -n "$sha_before" ] && [ "$sha_before" = "$sha_after" ] \
  && pass "stamp-invariance: verdict cache not rewritten on short-circuit" \
  || fail "stamp-invariance: verdict cache not rewritten on short-circuit" "before=$sha_before after=$sha_after"
unset LLM_DECIDE_MOCK_FIND_QUALITY
reset_findings

# 6e. Structural guard against the report.md re-judge loop EVER returning:
#     run the REAL stampers (bin/cluster-findings + bin/enrich-report) over a
#     keyed finding, then re-gate and assert ZERO further find_quality LLM
#     calls. 6d simulates a stamp; this exercises the actual tools — including
#     report_enrich's in-place Fields-table reformatting, which is exactly the
#     mutation a content-keyed cache could not survive. The verdict-keyed
#     short-circuit makes it immune to any report.md rewrite.
BIN_DIR="$SCRIPT_ROOT/bin"
llm_log="$RESULTS_DIR/llm-trace.log"
: > "$llm_log"
mkdir -p "$RESULTS_DIR/findings/FIND-REAL"
# A report WITH an unpadded Fields table — report_enrich reformats this table
# in place (column padding), the exact in-place narrative rewrite that a
# content-keyed cache could not survive.
cat > "$RESULTS_DIR/findings/FIND-REAL/report.md" <<'EOF'
# Authorization bypass in admin handler

## Location
server/handlers/admin.go:HandleListUsers:42

## Fields
| Field | Value |
| :-- | :-- |
| Class | auth:bypass |
| Severity | High |

## Rationale
Reads the requester role from a caller-controlled cookie without checking the
server-side session store, so any logged-in user can read other users' PII.
EOF
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"first reviewer","class":"auth:bypass","severity":"high","dedup_key":"missing-server-side-check"}'
LLM_DECIDE_LOG="$llm_log" validate_find_gate >/dev/null 2>&1
calls1=$(grep -c "find_quality MOCK" "$llm_log" 2>/dev/null || true)
[ "${calls1:-0}" -ge 1 ] \
  && pass "real-stamp: find_quality ran on the first gate pass (${calls1} call(s))" \
  || fail "real-stamp: find_quality ran on the first gate pass" "calls1=${calls1:-0}"
# Run the REAL stampers that mutate report.md AFTER the verdict is cached.
python3 "$BIN_DIR/cluster-findings" "$RESULTS_DIR" >/dev/null 2>&1 || true
python3 "$BIN_DIR/enrich-report" --quiet "$RESULTS_DIR/findings/FIND-REAL/report.md" >/dev/null 2>&1 || true
# Non-vacuousness: the stampers actually mutated report.md — both a Cluster:
# stamp (cluster-findings) and the in-place table reformat (report_enrich pads
# the cells), which together are the mutations that defeat a content hash.
real_report="$RESULTS_DIR/findings/FIND-REAL/report.md"
grep -q '^Cluster:' "$real_report" \
  && pass "real-stamp: cluster-findings stamped report.md (Cluster: line present)" \
  || fail "real-stamp: cluster-findings stamped report.md" "no Cluster: line written"
grep -q '| Class    | auth:bypass |' "$real_report" \
  && pass "real-stamp: report_enrich reformatted the Fields table (in-place rewrite)" \
  || fail "real-stamp: report_enrich reformatted the Fields table" "table not padded"
: > "$llm_log"
# Re-gate with a DIFFERENT mock — a re-judge would both log a call AND flip
# the cached class. Neither must happen.
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"SECOND reviewer","class":"WRONG-CLASS","severity":"low","dedup_key":"other-key"}'
LLM_DECIDE_LOG="$llm_log" validate_find_gate >/dev/null 2>&1
calls2=$(grep -c "find_quality MOCK" "$llm_log" 2>/dev/null || true)
assert_eq "0" "${calls2:-0}" \
  "real-stamp: re-gate after real cluster+enrich stamping makes ZERO find_quality calls"
if grep -q "WRONG-CLASS" "$RESULTS_DIR/findings/FIND-REAL/.llm-find-quality.json" 2>/dev/null; then
  fail "real-stamp: cached verdict must not be recomputed after real stamping" "class flipped to WRONG-CLASS"
else
  pass "real-stamp: cached verdict survived real cluster+enrich stamping"
fi
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
