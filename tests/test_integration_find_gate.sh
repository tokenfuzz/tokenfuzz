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
# test_decision_find_quality.sh. Disable reachability too so we don't
# call out to the network during tests.
export LLM_DECIDE_DISABLE=1
export REACHABILITY_AUTO=0

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

teardown_test_env
summary
