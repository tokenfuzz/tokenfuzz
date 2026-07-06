#!/usr/bin/env bash
# Integration tests — validate_find_gate end-to-end
#
# findings/ keeps only concrete security findings. With LLM disabled,
# the gate is a structural-only pass: FINDs with a report file are
# kept, FINDs without one get a .needs-content marker. The non-security
# DROP behavior (LLM rejects → findings-rejected/) is exercised in
# test_decision_find_quality.sh.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/triage.sh"

# Disable the LLM pre-check so verdicts depend only on the "has report
# file" structural rule. The LLM path is covered by
# test_decision_find_quality.sh.
export LLM_DECIDE_DISABLE=1

# ═══════════════════════════════════════════════════════════════
# 1. FIND with a description.md → kept, no markers
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/findings/FIND-001-logic"
cat > "$RESULTS_DIR/findings/FIND-001-logic/description.md" <<'EOF'
# Authorization bypass in admin handler

The /admin/users endpoint at server/handlers/admin.go:HandleListUsers:42
reads the session role from a caller-controlled cookie without
re-validating it against the server-side session store. A logged-in
user can set role=admin to enumerate the email addresses of other users.

Issue class: authorization bypass / info disclosure.
Impact: any authenticated user can read PII for the entire user table.
EOF

validate_find_gate 2>/dev/null

assert_dir_exists "$RESULTS_DIR/findings/FIND-001-logic" "logic FIND kept (no sanitizer)"
assert_file_not_exists "$RESULTS_DIR/findings/FIND-001-logic/.needs-content" "logic FIND has no needs-content marker"
[ ! -d "$RESULTS_DIR/findings-rejected" ] \
  && pass "no findings-rejected/ created for accepted FIND" \
  || fail "no findings-rejected/ created for accepted FIND" "findings-rejected/ exists"

# ═══════════════════════════════════════════════════════════════
# 2. FIND with a report.md only → kept
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/findings/FIND-002-report-only"
cat > "$RESULTS_DIR/findings/FIND-002-report-only/report.md" <<'EOF'
# Weak password hashing in user signup

users/signup.py:hash_password:18 uses md5() for password hashes.
Issue class: cryptographic weakness. Impact: precomputed-table attacks.
EOF

validate_find_gate 2>/dev/null

assert_dir_exists "$RESULTS_DIR/findings/FIND-002-report-only" "report.md-only FIND kept"
assert_file_not_exists "$RESULTS_DIR/findings/FIND-002-report-only/.needs-content" \
  "report.md-only FIND has no needs-content marker"

# ═══════════════════════════════════════════════════════════════
# 3. FIND with no report at all → kept in place, marked needs-content
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/findings/FIND-003-empty"
# Deliberately empty: no markdown, no html

validate_find_gate 2>/dev/null

assert_dir_exists "$RESULTS_DIR/findings/FIND-003-empty" "empty FIND stays in findings/"
assert_file_exists "$RESULTS_DIR/findings/FIND-003-empty/.needs-content" "empty FIND gets needs-content marker"
assert_file_contains "$RESULTS_DIR/findings/FIND-003-empty/.needs-content" "no report file" \
  "needs-content marker explains the issue"
[ ! -d "$RESULTS_DIR/findings-rejected" ] \
  && pass "no findings-rejected/ created for empty FIND" \
  || fail "no findings-rejected/ created for empty FIND" "findings-rejected/ exists"

# Adding a report on a re-run clears the marker.
cat > "$RESULTS_DIR/findings/FIND-003-empty/report.md" <<'EOF'
# Now has a report

Issue class: info-disclosure.
Location: log/handler.py:emit:55 — logs raw session tokens to stdout.
EOF
validate_find_gate 2>/dev/null
assert_file_not_exists "$RESULTS_DIR/findings/FIND-003-empty/.needs-content" \
  "needs-content marker cleared after report.md is added"

# ═══════════════════════════════════════════════════════════════
# 4. FIND with only an HTML report → kept
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/findings/FIND-004-html"
cat > "$RESULTS_DIR/findings/FIND-004-html/report.html" <<'EOF'
<html><body>
<h1>SQL injection in search endpoint</h1>
<p>app/search.py:run_search:73 concatenates the query parameter into a raw SQL
string. Issue class: injection. Impact: full database read.</p>
</body></html>
EOF

validate_find_gate 2>/dev/null

assert_dir_exists "$RESULTS_DIR/findings/FIND-004-html" "HTML-only FIND kept"
assert_file_not_exists "$RESULTS_DIR/findings/FIND-004-html/.needs-content" \
  "HTML-only FIND has no needs-content marker"

# ═══════════════════════════════════════════════════════════════
# 5. FIND with .reviewed override → kept regardless of content
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/findings/FIND-005-override"
# No description, but reviewed marker
touch "$RESULTS_DIR/findings/FIND-005-override/.reviewed"

validate_find_gate 2>/dev/null

assert_dir_exists "$RESULTS_DIR/findings/FIND-005-override" ".reviewed FIND kept"
assert_file_not_exists "$RESULTS_DIR/findings/FIND-005-override/.needs-content" \
  ".reviewed FIND not marked even without report"

# ═══════════════════════════════════════════════════════════════
# 6. FIND with .keep override → kept regardless
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/findings/FIND-006-keep"
touch "$RESULTS_DIR/findings/FIND-006-keep/.keep"

validate_find_gate 2>/dev/null

assert_dir_exists "$RESULTS_DIR/findings/FIND-006-keep" ".keep FIND kept"
assert_file_not_exists "$RESULTS_DIR/findings/FIND-006-keep/.needs-content" \
  ".keep FIND not marked even without report"

# ═══════════════════════════════════════════════════════════════
# 7. Browser target makes no difference — no web-gate any more
# ═══════════════════════════════════════════════════════════════

IS_BROWSER_TARGET=1 mkdir -p "$RESULTS_DIR/findings/FIND-007-nonweb"
cat > "$RESULTS_DIR/findings/FIND-007-nonweb/description.md" <<'EOF'
# Race condition in IPC actor lifetime

ipc/glue/MessageChannel.cpp:Close:380 frees the actor while a
sibling thread is still dispatching to it. Issue class: race / lifetime.
Reachable only from xpcshell today.
EOF

IS_BROWSER_TARGET=1 validate_find_gate 2>/dev/null

assert_dir_exists "$RESULTS_DIR/findings/FIND-007-nonweb" "non-web FIND kept under browser target"

# ═══════════════════════════════════════════════════════════════
# 8. Live find gate reconciles the caller-only contract flag, so a kept
#    caller-only finding localises and floors exactly like its crash twin.
#    (Crashes get this in triage_crash_dirs; findings must get it here too —
#    a triage_fill_reach_fields_tree test alone would miss the live path.)
# ═══════════════════════════════════════════════════════════════

mkdir -p "$RESULTS_DIR/findings/FIND-008-calleronly"
cat > "$RESULTS_DIR/findings/FIND-008-calleronly/report.md" <<'EOF'
# heap-use-after-free WRITE via foreign-pointer detach

Surface: library-api
Caller controls: input bytes and the public detach/add call sequence
Caller contract: unspecified
Trigger source: both
Reproduction rate: 5/5
EOF

TARGET_ATTACKER_CONTROLS_CSV="bytes" validate_find_gate 2>/dev/null

assert_dir_exists "$RESULTS_DIR/findings/FIND-008-calleronly" "caller-only FIND kept"
assert_file_exists "$RESULTS_DIR/findings/FIND-008-calleronly/.contract-flagged" \
  "live find gate reconciles the caller-only contract flag (not just the pooled path)"
assert_file_contains "$RESULTS_DIR/findings/FIND-008-calleronly/report.md" \
  "requires \[call-sequence\] outside attacker_controls=\[bytes\]" \
  "finding carries the same oob set-difference a crash twin gets"

# ═══════════════════════════════════════════════════════════════
# 9. Drain resume across a provider usage limit (opt-in).
#    FIND_GATE_RESUME_ON_LIMIT=1 makes validate_find_gate re-run the gate,
#    pausing for the reset, until a pass records no provider cap — so a cap hit
#    mid-drain no longer leaves findings permanently un-adjudicated. Bounded so
#    a backend that never recovers still terminates. Default (no opt-in) runs a
#    single pass and never blocks (the bin/audit background-sweeper contract).
#    The pool worker is stubbed to simulate the decide path recording a cap, so
#    the drain's control flow is exercised without a backend.
# ═══════════════════════════════════════════════════════════════

_triage_dir_pool_size() { echo 1; }

( # opt-in: cap on pass 1 clears on pass 2 → exactly two passes, then stop
  export RESULTS_DIR="$TEST_TMPDIR/drain-resume"
  mkdir -p "$RESULTS_DIR/findings/FIND-x"
  export FIND_GATE_RESUME_ON_LIMIT=1 FIND_GATE_PAUSE_CHUNK=1 \
         FIND_GATE_PAUSE_MAX_TOTAL=10 FIND_GATE_MAX_PAUSES=5 FIND_CLUSTER_DISABLE=1
  _P=0
  _validate_find_pool_worker() {
    _P=$((_P + 1))
    [ "$_P" -eq 1 ] && printf 'unknown\n' >> "$LLM_DECIDE_LIMIT_FILE"
  }
  validate_find_gate 2>/dev/null
  printf '%s\n' "$_P" > "$TEST_TMPDIR/drain-resume-passes"
  [ -e "$RESULTS_DIR/.find-gate-limit" ] && echo LEFT > "$TEST_TMPDIR/drain-resume-leftover"
)
assert_eq "2" "$(cat "$TEST_TMPDIR/drain-resume-passes")" \
  "drain resume: re-judges after a cap clears (initial pass + one retry)"
assert_file_not_exists "$TEST_TMPDIR/drain-resume-leftover" \
  "drain resume: cleans up the transient limit file"

( # opt-in but cap never clears → bounded by FIND_GATE_MAX_PAUSES, still exits
  export RESULTS_DIR="$TEST_TMPDIR/drain-stuck"
  mkdir -p "$RESULTS_DIR/findings/FIND-x"
  export FIND_GATE_RESUME_ON_LIMIT=1 FIND_GATE_PAUSE_CHUNK=1 \
         FIND_GATE_PAUSE_MAX_TOTAL=100 FIND_GATE_MAX_PAUSES=3 FIND_CLUSTER_DISABLE=1
  _P=0
  _validate_find_pool_worker() { _P=$((_P + 1)); printf 'unknown\n' >> "$LLM_DECIDE_LIMIT_FILE"; }
  validate_find_gate 2>/dev/null
  printf '%s\n' "$_P" > "$TEST_TMPDIR/drain-stuck-passes"
)
assert_eq "4" "$(cat "$TEST_TMPDIR/drain-stuck-passes")" \
  "drain resume: an unrecovering cap terminates at FIND_GATE_MAX_PAUSES (1 + 3)"

( # default (no opt-in): a single pass, never loops even if a cap is recorded
  export RESULTS_DIR="$TEST_TMPDIR/drain-default"
  mkdir -p "$RESULTS_DIR/findings/FIND-x"
  export FIND_CLUSTER_DISABLE=1
  _P=0
  _validate_find_pool_worker() {
    _P=$((_P + 1))
    [ -n "${LLM_DECIDE_LIMIT_FILE:-}" ] && printf 'unknown\n' >> "$LLM_DECIDE_LIMIT_FILE"
  }
  validate_find_gate 2>/dev/null
  printf '%s\n' "$_P" > "$TEST_TMPDIR/drain-default-passes"
)
assert_eq "1" "$(cat "$TEST_TMPDIR/drain-default-passes")" \
  "drain default: no opt-in → single pass, never blocks (background-sweeper contract)"

teardown_test_env
summary
