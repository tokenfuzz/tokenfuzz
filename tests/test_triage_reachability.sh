#!/usr/bin/env bash
# Tests for the integration between lib/triage.sh and bin/reachability:
#   1. triage_crash_dirs auto-invokes bin/reachability after evidence checks
#   2. maintain_indexes surfaces the auto-Severity in crashes/CRASH-CLUSTERS.md
#   3. REACHABILITY_AUTO=0 env disables the hook
#   4. Reachability failures don't block crash preservation
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/target_config.sh"
source "$SCRIPT_ROOT/lib/llm_decide.sh" 2>/dev/null || true
source "$SCRIPT_ROOT/lib/triage.sh"

# Mock the LLM triage decision to keep crashes (rc=2 = KEEP, bypass regex).
llm_triage_crash_decision() { return 2; }
crash_dir_security_rejection_reason() { return 0; }  # never reject
export -f llm_triage_crash_decision crash_dir_security_rejection_reason

# Set up reachability mocks. Automatic triage defaults to external mode
# (REACHABILITY_AUTO=external, the default for OSS targets) so these mocks
# are consulted for every promotion. Tests that need the older
# --severity-only behaviour set REACHABILITY_AUTO=local explicitly.
mkdir -p "$TEST_TMPDIR/reach-mock"
export REACHABILITY_MOCK_DIR="$TEST_TMPDIR/reach-mock"
export REACHABILITY_CACHE_DIR="$TEST_TMPDIR/reach-cache"

sha1_short() { printf '%s' "$1" | shasum -a 1 | awk '{print substr($1,1,16)}'; }

# Mock for the symbol the report will reference.
H_SYM=$(sha1_short "demo_triage_decode")
cat > "$REACHABILITY_MOCK_DIR/sourcegraph-${H_SYM}.json" <<'EOF'
{"status":"ok","hits":[{"repo":"third-party-app","path":"src/uses_demo.c"}]}
EOF
cat > "$REACHABILITY_MOCK_DIR/gh-${H_SYM}.json" <<'EOF'
{"status":"unavailable","error":"n/a"}
EOF

# Build a complete maintainer bundle for triage_crash_dirs to promote.
make_promotable_crash() {
  local id="$1"
  local d="$RESULTS_DIR/crashes/$id"
  mkdir -p "$d"
  cat > "$d/REPORT.md" <<'EOF'
# CRASH-INTEG: integration demo
## Classification
- **Severity**: TBD
- **Type**: Bounds (out-of-range write)
- **Location**: demo.c:42
## Trigger Surface
- Entry: `demo_triage_decode()` → `demo_match()`
- WRITE of size 8 — caller-controlled offset.
## Reproduction
- Reproducer: input.bin
- Crash: WRITE of size 8
## Reachability Notes
narrative
EOF
  cat > "$d/asan.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 8 at 0xdeadbeef
SUMMARY: AddressSanitizer: heap-buffer-overflow demo.c:42 in demo_triage_decode
EOF
  # Need a testcase file >16 bytes that isn't .txt/.log/.md.
  printf 'TESTCASEDATA-XXXXXXXXXXXXXXX' > "$d/input.bin"
  cat > "$d/reproduce.sh" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
}

# ───────────────────────────────────────────────────────────────────
# 1. triage_crash_dirs invokes local severity recomputation and writes reachability.json
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="triage promotion auto-invokes local reachability"
make_promotable_crash CRASH-INTEG-1
triage_crash_dirs >/dev/null 2>&1
assert_file_exists "$RESULTS_DIR/crashes/CRASH-INTEG-1/reachability.json" \
  "reachability.json written during triage"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-INTEG-1/REPORT.md" \
  "Severity\*\*: (Critical|High|Medium|Low|None) \(CVSS(-[A-Z]+)? 4\\.0:" \
  "report Severity line was rewritten during triage"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-INTEG-1/REPORT.html" \
  "report HTML is not rendered before final maintain_indexes pass"

# ───────────────────────────────────────────────────────────────────
# 2. REACHABILITY_AUTO=external opts automatic triage into public-caller search
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="REACHABILITY_AUTO=external opts into external caller search"
make_promotable_crash CRASH-INTEG-EXT
REACHABILITY_AUTO=external _triage_run_reachability \
  "$RESULTS_DIR/crashes/CRASH-INTEG-EXT" "CRASH-INTEG-EXT" "$SCRIPT_ROOT/bin" \
  >/dev/null 2>&1 || true
assert_file_contains "$RESULTS_DIR/crashes/CRASH-INTEG-EXT/reachability.json" \
  '"external_callers": 1' \
  "external opt-in records mocked caller"

# ───────────────────────────────────────────────────────────────────
# 3. maintain_indexes surfaces Severity + Callers columns
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="maintain_indexes carries Severity + Callers columns"
maintain_indexes >/dev/null 2>&1
assert_file_contains "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" '\| Severity +\| Callers' \
  "CRASH-CLUSTERS.md header includes Severity + Callers"
# The row for CRASH-INTEG-1 should have the level + score and caller count.
# Each row's ID is now hyperlinked, so the row marker is `[CRASH-INTEG-1]`
# rather than `| CRASH-INTEG-1 |`.
row=$(grep -E '\[CRASH-INTEG-1\]' "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" || true)
[ -n "$row" ] && pass "$_CURRENT_TEST: row present" || fail "$_CURRENT_TEST" "no cluster row for CRASH-INTEG-1"
grep -qE '\| (Critical|High|Medium|Low) \(CVSS [0-9.]+\) \|' <<<"$row" \
  && pass "$_CURRENT_TEST: severity column populated" \
  || fail "$_CURRENT_TEST" "severity column missing/malformed: $row"
# Caller count is a cluster-level maximum. CRASH-INTEG-EXT shares the same
# root signature and was explicitly run with external reachability, so the
# grouped row carries that one external caller.
grep -qE '\| +1 \|' <<<"$row" \
  && pass "$_CURRENT_TEST: caller count = 1 for grouped cluster" \
  || fail "$_CURRENT_TEST" "caller count column wrong: $row"
assert_file_contains "$RESULTS_DIR/crashes/CRASH-INTEG-1/REPORT.html" \
  "Reachability — external callers" \
  "maintain_indexes renders final report HTML after reachability"

# ───────────────────────────────────────────────────────────────────
# 4. REACHABILITY_AUTO=0 disables the hook
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="REACHABILITY_AUTO=0 disables auto-invocation"
make_promotable_crash CRASH-INTEG-2
REACHABILITY_AUTO=0 triage_crash_dirs >/dev/null 2>&1
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-INTEG-2/reachability.json" \
  "reachability.json NOT written when REACHABILITY_AUTO=0"

# ───────────────────────────────────────────────────────────────────
# 5. A failing reachability run does not block triage
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="reachability failure does not block triage"
make_promotable_crash CRASH-INTEG-3
# Wipe mocks so the script still runs but its sub-process can't load any data.
# In practice the script will still succeed (returning all-unavailable) — the
# stronger test is to point REACHABILITY_AUTO at a non-existent script via
# PATH manipulation. Here we just verify the crash is still considered
# promoted (no .promotion_pending file) regardless of reachability outcome.
triage_crash_dirs >/dev/null 2>&1
[ ! -f "$RESULTS_DIR/crashes/CRASH-INTEG-3/.promotion_pending" ] \
  && pass "$_CURRENT_TEST" \
  || fail "$_CURRENT_TEST" ".promotion_pending lingered after triage"

_CURRENT_TEST="reachability failure records non-blocking marker"
make_promotable_crash CRASH-INTEG-4
mkdir -p "$TEST_TMPDIR/failing-bin"
cat > "$TEST_TMPDIR/failing-bin/reachability" <<'MOCK'
#!/bin/bash
echo "mock reachability failure" >&2
exit 9
MOCK
chmod +x "$TEST_TMPDIR/failing-bin/reachability"
_triage_run_reachability "$RESULTS_DIR/crashes/CRASH-INTEG-4" "CRASH-INTEG-4" "$TEST_TMPDIR/failing-bin" >/dev/null 2>&1 || true
assert_dir_exists "$RESULTS_DIR/crashes/CRASH-INTEG-4" \
  "reachability failure: crash dir stays preserved"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-INTEG-4/.reachability_failed" \
  "reachability failure: marker written"

_CURRENT_TEST="disabled reachability records pending marker"
make_promotable_crash CRASH-INTEG-5
REACHABILITY_AUTO=0 _triage_run_reachability "$RESULTS_DIR/crashes/CRASH-INTEG-5" "CRASH-INTEG-5" "$SCRIPT_ROOT/bin" >/dev/null 2>&1 || true
assert_file_exists "$RESULTS_DIR/crashes/CRASH-INTEG-5/.reachability_pending" \
  "disabled reachability: pending marker written"

# ───────────────────────────────────────────────────────────────────
# 6. Security-rejected crashes are rejected before optional reachability.
#    Reachability is post-processing for preserved crash candidates, not
#    a prerequisite for rejecting invalid crash directories.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="security-rejected dir does not require reachability"
# Override the reject mock for this one block: reject everything.
crash_dir_security_rejection_reason() {
  printf '%s\n' "test-only injected rejection"
  return 0
}
export -f crash_dir_security_rejection_reason
make_promotable_crash CRASH-INTEG-REJ
triage_crash_dirs >/dev/null 2>&1
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-INTEG-REJ" \
  "rejected crash removed from crashes/"
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-INTEG-REJ" \
  "rejected crash → crashes-rejected/"
assert_file_not_exists "$RESULTS_DIR/crashes-rejected/CRASH-INTEG-REJ/reachability.json" \
  "rejected dir: reachability not required before rejection"
# Restore the broad no-reject mock for subsequent tests.
crash_dir_security_rejection_reason() { return 0; }
export -f crash_dir_security_rejection_reason

# ───────────────────────────────────────────────────────────────────
# 7. Crash with no auto-Severity line still appears in CRASH-CLUSTERS.md (with —)
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="CRASH-CLUSTERS.md tolerates crash dirs without auto-Severity"
mkdir -p "$RESULTS_DIR/crashes/CRASH-NOSEVERITY"
cat > "$RESULTS_DIR/crashes/CRASH-NOSEVERITY/report.md" <<'EOF'
# CRASH-NOSEVERITY
## Classification
- **Type**: Unknown
EOF
maintain_indexes >/dev/null 2>&1
row=$(grep -E '\[CRASH-NOSEVERITY\]|\| CRASH-NOSEVERITY \|' "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" || true)
[ -n "$row" ] && pass "$_CURRENT_TEST: row present" || fail "$_CURRENT_TEST" "no row for CRASH-NOSEVERITY"
# Em-dash placeholder appears in the cell (possibly padded with spaces).
grep -qE '\| +— +\|' <<<"$row" && pass "$_CURRENT_TEST: em-dash placeholder" \
  || fail "$_CURRENT_TEST" "expected em-dash placeholder: $row"

# ───────────────────────────────────────────────────────────────────
# 8. validate_find_gate auto-invokes local reachability on findings/.
#    Findings get the same severity annotation as crashes.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="validate_find_gate auto-invokes reachability on FIND"

# Prime an LLM mock so we don't depend on a live model.
export LLM_DECIDE_MOCK_FIND_QUALITY='{"accept":true,"reason":"clear","class":"memory-safety:bounds","severity":"medium"}'

# Build a FIND with a symbol that matches the reachability mocks above
# (demo_triage_decode → sha1 H_SYM, already populated under reach-mock).
mkdir -p "$RESULTS_DIR/findings/FIND-REACH-1"
cat > "$RESULTS_DIR/findings/FIND-REACH-1/report.md" <<'EOF'
# FIND-REACH-1: integration demo

## Classification
- **Severity**: TBD
- **Type**: Bounds (out-of-range write)
- **Location**: demo.c:42

## Trigger Surface
- Entry: `demo_triage_decode()` → `demo_match()`
- WRITE of size 8 — caller-controlled offset.

## Reachability Notes
narrative
EOF

validate_find_gate >/dev/null 2>&1

assert_file_exists "$RESULTS_DIR/findings/FIND-REACH-1/reachability.json" \
  "reachability.json written during FIND triage"
assert_file_exists "$RESULTS_DIR/findings/FIND-REACH-1/.reachability_ok" \
  "FIND triage marks reachability_ok"
assert_file_contains "$RESULTS_DIR/findings/FIND-REACH-1/report.md" \
  "Severity\*\*: (Critical|High|Medium|Low|None) \(CVSS(-[A-Z]+)? 4\\.0:" \
  "FIND report Severity line rewritten by reachability"

# ───────────────────────────────────────────────────────────────────
# 9. REACHABILITY_AUTO=0 disables the FIND-side hook too
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="REACHABILITY_AUTO=0 disables reachability for findings"
mkdir -p "$RESULTS_DIR/findings/FIND-REACH-2"
cat > "$RESULTS_DIR/findings/FIND-REACH-2/report.md" <<'EOF'
# FIND-REACH-2
Issue class: info-disclosure. Location: srv/leak.go:Emit:7.
EOF
REACHABILITY_AUTO=0 validate_find_gate >/dev/null 2>&1
assert_file_not_exists "$RESULTS_DIR/findings/FIND-REACH-2/reachability.json" \
  "reachability.json NOT written when REACHABILITY_AUTO=0 (findings)"
assert_file_exists "$RESULTS_DIR/findings/FIND-REACH-2/.reachability_pending" \
  "FIND with REACHABILITY_AUTO=0 carries .reachability_pending marker"

# ───────────────────────────────────────────────────────────────────
# 10. Reachability failure does not block FIND preservation
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="reachability failure leaves FIND in findings/"
mkdir -p "$RESULTS_DIR/findings/FIND-REACH-3"
cat > "$RESULTS_DIR/findings/FIND-REACH-3/report.md" <<'EOF'
# FIND-REACH-3
Issue class: crypto:weak-hash. Location: util/hash.go:Hash:12.
EOF
_triage_run_reachability "$RESULTS_DIR/findings/FIND-REACH-3" "FIND-REACH-3" \
  "$TEST_TMPDIR/failing-bin" >/dev/null 2>&1 || true
assert_dir_exists "$RESULTS_DIR/findings/FIND-REACH-3" \
  "reachability failure: FIND dir stays preserved"
assert_file_exists "$RESULTS_DIR/findings/FIND-REACH-3/.reachability_failed" \
  "reachability failure: marker written on FIND"

unset LLM_DECIDE_MOCK_FIND_QUALITY

# ───────────────────────────────────────────────────────────────────
# 11. LLM hybrid field-fill writes .llm_fields.json sidecar
# ───────────────────────────────────────────────────────────────────
# When the agent omits structured fields (no Surface / Caller controls /
# Primitive), _triage_llm_fill_fields asks the LLM to classify the
# report and persists the JSON for bin/reachability to consume.
_CURRENT_TEST="llm-fill: writes .llm_fields.json when fields missing"
mkdir -p "$RESULTS_DIR/findings/FIND-LLMFILL-1"
cat > "$RESULTS_DIR/findings/FIND-LLMFILL-1/report.md" <<'EOF'
# FIND-LLMFILL-1
## Summary
Open redirect via startsWith prefix check on members signin redirect.
EOF
LLM_DECIDE_MOCK_REACHABILITY_FIELDS='{"surface":"library-api — members signin","primitive":"open_redirect","caller_contract":"obeyed","caller_controls":"bytes"}' \
  _triage_llm_fill_fields "$RESULTS_DIR/findings/FIND-LLMFILL-1" "FIND-LLMFILL-1"
assert_file_exists "$RESULTS_DIR/findings/FIND-LLMFILL-1/.llm_fields.json" \
  "sidecar JSON written"
assert_file_contains "$RESULTS_DIR/findings/FIND-LLMFILL-1/.llm_fields.json" \
  '"primitive"' "sidecar carries primitive key"
assert_file_contains "$RESULTS_DIR/findings/FIND-LLMFILL-1/.llm_fields.json" \
  '"open_redirect"' "sidecar carries open_redirect value"

# Skip the call entirely when all four fields are already present in the
# report — no LLM budget should be spent.
_CURRENT_TEST="llm-fill: skipped when agent already populated fields"
mkdir -p "$RESULTS_DIR/findings/FIND-LLMFILL-2"
cat > "$RESULTS_DIR/findings/FIND-LLMFILL-2/report.md" <<'EOF'
# FIND-LLMFILL-2
| Field             | Value |
|:------------------|:------|
| Surface           | library-api |
| Primitive         | open_redirect |
| Caller contract   | obeyed |
| Caller controls   | bytes |
EOF
# The mock should NOT be consulted; if the function fires it would still
# pass because the mock is set, but the sidecar would be created. Assert
# the sidecar is absent.
LLM_DECIDE_MOCK_REACHABILITY_FIELDS='{"surface":"network","primitive":"sqli"}' \
  _triage_llm_fill_fields "$RESULTS_DIR/findings/FIND-LLMFILL-2" "FIND-LLMFILL-2"
assert_file_not_exists "$RESULTS_DIR/findings/FIND-LLMFILL-2/.llm_fields.json" \
  "sidecar NOT written when all fields are already in the report"

# LLM_FIELD_FILL_DISABLE=1 disables the pass even when fields are missing.
_CURRENT_TEST="llm-fill: LLM_FIELD_FILL_DISABLE=1 short-circuits"
mkdir -p "$RESULTS_DIR/findings/FIND-LLMFILL-3"
cat > "$RESULTS_DIR/findings/FIND-LLMFILL-3/report.md" <<'EOF'
# FIND-LLMFILL-3
## Summary
SSRF in image proxy that fetches user-supplied URLs server-side.
EOF
LLM_FIELD_FILL_DISABLE=1 \
LLM_DECIDE_MOCK_REACHABILITY_FIELDS='{"surface":"network","primitive":"ssrf"}' \
  _triage_llm_fill_fields "$RESULTS_DIR/findings/FIND-LLMFILL-3" "FIND-LLMFILL-3"
assert_file_not_exists "$RESULTS_DIR/findings/FIND-LLMFILL-3/.llm_fields.json" \
  "sidecar NOT written when LLM_FIELD_FILL_DISABLE=1"

# A bogus LLM response (not a JSON object) must not produce a sidecar.
_CURRENT_TEST="llm-fill: rejects non-object JSON response"
mkdir -p "$RESULTS_DIR/findings/FIND-LLMFILL-4"
cat > "$RESULTS_DIR/findings/FIND-LLMFILL-4/report.md" <<'EOF'
# FIND-LLMFILL-4
## Summary
SQL injection in users.id query parameter.
EOF
LLM_DECIDE_MOCK_REACHABILITY_FIELDS='["not","an","object"]' \
  _triage_llm_fill_fields "$RESULTS_DIR/findings/FIND-LLMFILL-4" "FIND-LLMFILL-4"
assert_file_not_exists "$RESULTS_DIR/findings/FIND-LLMFILL-4/.llm_fields.json" \
  "sidecar NOT written for array LLM response (object required)"

# A *partial* sidecar (missing caller_controls — the field whose absence
# collapses severity to Low) must be RE-filled and merged, not cached as
# final. This is the regression behind high→low flips on un-triaged findings.
_CURRENT_TEST="llm-fill: partial sidecar is re-filled and merged"
mkdir -p "$RESULTS_DIR/findings/FIND-LLMFILL-5"
cat > "$RESULTS_DIR/findings/FIND-LLMFILL-5/report.md" <<'EOF'
# FIND-LLMFILL-5
## Summary
Use-after-free in delete walks freed sibling pointers.
EOF
printf '%s' '{"surface":"library-api — delete","primitive":"double_free"}' \
  > "$RESULTS_DIR/findings/FIND-LLMFILL-5/.llm_fields.json"
LLM_DECIDE_MOCK_REACHABILITY_FIELDS='{"caller_controls":"bytes","caller_contract":"obeyed"}' \
  _triage_llm_fill_fields "$RESULTS_DIR/findings/FIND-LLMFILL-5" "FIND-LLMFILL-5"
assert_file_contains "$RESULTS_DIR/findings/FIND-LLMFILL-5/.llm_fields.json" \
  '"caller_controls"' "partial sidecar retried: caller_controls now present"
assert_file_contains "$RESULTS_DIR/findings/FIND-LLMFILL-5/.llm_fields.json" \
  '"double_free"' "merge preserves the previously-captured primitive"
assert_file_contains "$RESULTS_DIR/findings/FIND-LLMFILL-5/.llm_fields.json" \
  '"_fill_attempts"' "retry records an attempt counter"

# A COMPLETE sidecar (surface + primitive + caller_controls) must be left
# untouched — no LLM budget spent, no risk of clobbering good fields.
_CURRENT_TEST="llm-fill: complete sidecar left untouched"
mkdir -p "$RESULTS_DIR/findings/FIND-LLMFILL-6"
cat > "$RESULTS_DIR/findings/FIND-LLMFILL-6/report.md" <<'EOF'
# FIND-LLMFILL-6
## Summary
SSRF via user-controlled fetch URL.
EOF
printf '%s' '{"surface":"network","primitive":"ssrf","caller_controls":"bytes"}' \
  > "$RESULTS_DIR/findings/FIND-LLMFILL-6/.llm_fields.json"
_fill6_before=$(cat "$RESULTS_DIR/findings/FIND-LLMFILL-6/.llm_fields.json")
LLM_DECIDE_MOCK_REACHABILITY_FIELDS='{"surface":"OVERWRITTEN","primitive":"x","caller_controls":"x"}' \
  _triage_llm_fill_fields "$RESULTS_DIR/findings/FIND-LLMFILL-6" "FIND-LLMFILL-6"
_fill6_after=$(cat "$RESULTS_DIR/findings/FIND-LLMFILL-6/.llm_fields.json")
assert_eq "$_fill6_before" "$_fill6_after" "complete sidecar unchanged (LLM not consulted)"

# Once the attempt cap is reached, an unfillable sidecar stops re-filling so
# a field the narrative simply does not carry can't re-burn budget forever.
_CURRENT_TEST="llm-fill: attempt cap stops re-filling"
mkdir -p "$RESULTS_DIR/findings/FIND-LLMFILL-7"
cat > "$RESULTS_DIR/findings/FIND-LLMFILL-7/report.md" <<'EOF'
# FIND-LLMFILL-7
## Summary
Heap overflow with no caller-control detail in the narrative.
EOF
printf '%s' '{"surface":"library-api","primitive":"heap_write","_fill_attempts":2}' \
  > "$RESULTS_DIR/findings/FIND-LLMFILL-7/.llm_fields.json"
_fill7_before=$(cat "$RESULTS_DIR/findings/FIND-LLMFILL-7/.llm_fields.json")
LLM_FIELD_FILL_MAX_ATTEMPTS=2 \
LLM_DECIDE_MOCK_REACHABILITY_FIELDS='{"caller_controls":"bytes"}' \
  _triage_llm_fill_fields "$RESULTS_DIR/findings/FIND-LLMFILL-7" "FIND-LLMFILL-7"
_fill7_after=$(cat "$RESULTS_DIR/findings/FIND-LLMFILL-7/.llm_fields.json")
assert_eq "$_fill7_before" "$_fill7_after" "sidecar at attempt cap is left untouched"

# ───────────────────────────────────────────────────────────────────
# 12. Pool pass: triage_fill_reach_fields_tree fills model-direct-style
# findings that never ran a per-cell triage. REACHABILITY_AUTO=0 keeps the
# scoring side a no-op so the test exercises only the field-fill.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="pool pass: fills reach fields for findings under a pooled tree"
POOL_TREE="$TEST_TMPDIR/pool-tree"
mkdir -p "$POOL_TREE/findings/FIND-0001"
cat > "$POOL_TREE/findings/FIND-0001/report.md" <<'EOF'
# FIND-0001
## Summary
Integer overflow underallocates a buffer in the parser.
EOF
REACHABILITY_AUTO=0 \
LLM_DECIDE_MOCK_REACHABILITY_FIELDS='{"surface":"library-api","primitive":"heap_write","caller_controls":"length"}' \
  triage_fill_reach_fields_tree "$POOL_TREE" "$SCRIPT_ROOT/bin"
assert_file_exists "$POOL_TREE/findings/FIND-0001/.llm_fields.json" \
  "pool pass wrote a reach-field sidecar for the pooled finding"
assert_file_contains "$POOL_TREE/findings/FIND-0001/.llm_fields.json" \
  '"caller_controls"' "pool pass captured caller_controls"

teardown_test_env
summary
