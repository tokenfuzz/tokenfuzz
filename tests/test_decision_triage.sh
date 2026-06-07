#!/usr/bin/env bash
# tests/test_decision_triage.sh — Wires lib/triage.sh:triage_crash_dirs to LLM
# with a mock and verifies override semantics.
#
# Three pillars:
#   1. LLM says "keep" → regex-discardable crash IS NOT discarded (override).
#   2. LLM says "discard" → crash IS discarded with LLM reason in .autodiscard.
#   3. LLM unavailable → regex fallback runs (existing behavior).

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/llm_decide.sh"
source "$SCRIPT_ROOT/lib/triage.sh"

# This suite focuses on the LLM-triage override path, not on reachability.
# Disable the post-triage reachability hook so the assertions don't depend
# on network state. Other suites (test_triage_reachability.sh) exercise
# the reachability integration explicitly.
export REACHABILITY_AUTO=0

setup_test_env

mk_crash_dir() {
  local id="$1" content="$2"
  local d="$RESULTS_DIR/crashes/$id"
  mkdir -p "$d"
  printf '%s\n' "$content" > "$d/asan-output.txt"
  printf 'tc body\n' > "$d/repro.html"
  cat > "$d/report.md" <<EOF
# $id stub
heap-buffer-overflow READ in worker. memory-safety implication.
fetch() invoked from web-content. file:src/foo.cpp:42
EOF
  echo "$d"
}

# ── 0. LLM helper works when GNU timeout is absent/unneeded ─────────
FAKE_CODEX="$TEST_TMPDIR/fake-codex"
cat > "$FAKE_CODEX" <<'EOF'
#!/usr/bin/env bash
cat >/dev/null
printf '{"keep":true,"reason":"fake backend ok"}\n'
EOF
chmod +x "$FAKE_CODEX"
OLD_ACTIVE_BACKEND="${ACTIVE_BACKEND:-}"
OLD_CODEX_BIN="${CODEX_BIN:-}"
# Exercise the real-backend path of llm_decide via fake-codex. The test
# infra defaults to LLM_DECIDE_DISABLE=1; drop it locally so this call
# reaches the backend branch.
OLD_LLM_DECIDE_DISABLE="${LLM_DECIDE_DISABLE-}"
unset LLM_DECIDE_DISABLE
ACTIVE_BACKEND=codex
CODEX_BIN="$FAKE_CODEX"
decision_json=$(printf 'prompt' | llm_decide crash_triage "keep,reason" 2)
printf '%s\n' "$decision_json" > "$TEST_TMPDIR/fake-codex-decision.json"
assert_file_contains "$TEST_TMPDIR/fake-codex-decision.json" '"keep":true' "llm_decide: codex backend works without requiring timeout"
ACTIVE_BACKEND="$OLD_ACTIVE_BACKEND"
CODEX_BIN="$OLD_CODEX_BIN"
[ -n "$OLD_LLM_DECIDE_DISABLE" ] && export LLM_DECIDE_DISABLE="$OLD_LLM_DECIDE_DISABLE"

# ── 1. LLM override: regex would discard, LLM says keep ─────────────
# Build a SEGV-on-zero trace that the regex would auto-discard, but
# instruct the LLM mock to say keep.
NULL_DEREF_TRACE=$(cat <<'EOF'
==12345==ERROR: AddressSanitizer: SEGV on unknown address 0x0000000000
SCARINESS: 10 (null-deref)
    #0 0x100 in foo() /a/b.c:10
EOF
)
mk_crash_dir CRASH-001 "$NULL_DEREF_TRACE" >/dev/null
export LLM_DECIDE_MOCK_CRASH_TRIAGE='{"keep":true,"reason":"hidden UAF"}'
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"web content input boundary"}'
triage_crash_dirs >/dev/null 2>&1
assert_dir_exists     "$RESULTS_DIR/crashes/CRASH-001"           "LLM keep: crash not discarded"
assert_dir_not_exists "$RESULTS_DIR/crashes-rejected/CRASH-001"  "LLM keep: not in rejected/"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-001/.llm-triage.json" "LLM keep: cache written"
unset LLM_DECIDE_MOCK_CRASH_TRIAGE
unset LLM_DECIDE_MOCK_LEGIT_CRASH
LLM_DECIDE_DISABLE=1 triage_crash_dirs >/dev/null 2>&1
assert_dir_exists "$RESULTS_DIR/crashes/CRASH-001" "LLM disabled: exact cached keep prevents regex discard"

# After export-repro normalizes the bundle, the canonical sanitizer file
# is sanitizer.txt at root (asan.txt is a fallback, asan-output.txt is
# migrated under .audit/). The cache is keyed off whichever file
# find_primary_asan_in_crash_dir returns, so overwrite that one to
# invalidate.
asan_cache_target="$RESULTS_DIR/crashes/CRASH-001/sanitizer.txt"
[ -s "$asan_cache_target" ] || asan_cache_target="$RESULTS_DIR/crashes/CRASH-001/asan.txt"
[ -s "$asan_cache_target" ] || asan_cache_target="$RESULTS_DIR/crashes/CRASH-001/asan-output.txt"
cat > "$asan_cache_target" <<'EOF'
==67890==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
SCARINESS: 10 (null-deref)
    #0 0x7fff0000aaaa in foo() /a/b.c:10
EOF
LLM_DECIDE_DISABLE=1 triage_crash_dirs >/dev/null 2>&1
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-001" "LLM disabled: changed ASan output invalidates cache"

# ── 2. LLM marks discard on a non-memory-safety trace → still discards ─
# The LLM gate still rejects classes the sanitizer did NOT confirm as a
# memory-safety bug. A null-deref SEGV-on-zero is such a class, so the
# LLM-named reason flows through to .autodiscard.
mk_crash_dir CRASH-002 "$NULL_DEREF_TRACE" >/dev/null
export LLM_DECIDE_MOCK_CRASH_TRIAGE='{"keep":false,"reason":"test-only stub harness, not product code"}'
triage_crash_dirs >/dev/null 2>&1
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-002"          "LLM discard: removed from crashes/"
# Find the rejected dir (may be timestamp-suffixed if re-run).
rejected_dir=$(find "$RESULTS_DIR/crashes-rejected" -maxdepth 1 -name 'CRASH-002*' -type d | head -1)
assert_dir_exists  "$rejected_dir"               "LLM discard: in crashes-rejected/"
assert_file_exists "$rejected_dir/.autodiscard"  "LLM discard: .autodiscard written"
assert_file_contains "$rejected_dir/.autodiscard" "LLM:" "autodiscard mentions LLM"
assert_file_contains "$rejected_dir/.autodiscard" "test-only stub harness" "autodiscard has LLM reason"
unset LLM_DECIDE_MOCK_CRASH_TRIAGE

# ── 2b. Sanitizer-keep veto: LLM discard MUST NOT drop a UAF ─────────
# A deterministic, sanitizer-confirmed memory-safety class beats the LLM's
# probabilistic discard (the LLM only sees a bounded prefix of the trace). This
# regression-guards the FN where an LLM "discard" silently dropped a real
# heap-use-after-free. The crash stays in crashes/ for the downstream
# caller-contract / severity gates to judge with full context.
UAF_TRACE=$(cat <<'EOF'
==12345==ERROR: AddressSanitizer: heap-use-after-free
READ of size 8 at 0x602000000010
    #0 0x100 in junk() /a/b.c:5
EOF
)
mk_crash_dir CRASH-002B "$UAF_TRACE" >/dev/null
export LLM_DECIDE_MOCK_CRASH_TRIAGE='{"keep":false,"reason":"looks benign to me"}'
triage_crash_dirs >/dev/null 2>&1
assert_dir_exists "$RESULTS_DIR/crashes/CRASH-002B" \
  "sanitizer-keep veto: UAF survives LLM discard"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-002B/.autodiscard" \
  "sanitizer-keep veto: UAF not auto-discarded"
unset LLM_DECIDE_MOCK_CRASH_TRIAGE

# ── 3. LLM unavailable → regex fallback ─────────────────────────────
mk_crash_dir CRASH-003 "$NULL_DEREF_TRACE" >/dev/null
LLM_DECIDE_DISABLE=1 triage_crash_dirs >/dev/null 2>&1
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-003"          "LLM disabled: regex still discards null-deref"
rejected_dir=$(find "$RESULTS_DIR/crashes-rejected" -maxdepth 1 -name 'CRASH-003*' -type d | head -1)
assert_dir_exists "$rejected_dir" "LLM disabled: rejected via regex"
assert_file_contains "$rejected_dir/.autodiscard" "non-finding class" \
  "autodiscard reflects regex reason"

# ── 4. LLM returns malformed JSON → regex fallback ──────────────────
mk_crash_dir CRASH-004 "$NULL_DEREF_TRACE" >/dev/null
export LLM_DECIDE_MOCK_CRASH_TRIAGE='this is not json'
triage_crash_dirs >/dev/null 2>&1
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-004" \
  "malformed LLM: regex fallback discards"
unset LLM_DECIDE_MOCK_CRASH_TRIAGE

# ── 5. LLM legitimate crash gate can keep a crash despite sparse text ────────
WEBLESS_DIR="$RESULTS_DIR/crashes/CRASH-REACH-1"
mkdir -p "$WEBLESS_DIR"
cat > "$WEBLESS_DIR/asan-output.txt" <<'EOF'
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x60200000abcd
SUMMARY: AddressSanitizer: heap-buffer-overflow parser.cpp:42 in Parse
EOF
cat > "$WEBLESS_DIR/report.md" <<'EOF'
# parser crash
heap-buffer-overflow in parser.cpp:42.
EOF
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"report omitted path but testcase is content-loadable"}'
reason=$(crash_dir_security_rejection_reason "$WEBLESS_DIR" 1 2>/dev/null || true)
assert_eq "" "$reason" "LLM legitimate crash gate keeps sparse but valid crash"
unset LLM_DECIDE_MOCK_LEGIT_CRASH

# ── 6. Deterministic UBSan routing ──────────────────────────────────
# Non-memory-safety UBSan (signed integer overflow) is demoted straight to
# findings/ — NOT left in crashes/ and NOT sent to crashes-rejected/. This
# runs before the LLM gates, so it is deterministic regardless of LLM state.
UBSAN_SIO_TRACE=$(cat <<'EOF'
/src/calc.c:18:18: runtime error: signed integer overflow: 21475 * 100000 cannot be represented in type 'int'
    #0 0x100 in app_compute calc.c:18
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/calc.c:18:18
EOF
)
mk_crash_dir CRASH-UBSAN-SIO "$UBSAN_SIO_TRACE" >/dev/null
LLM_DECIDE_DISABLE=1 triage_crash_dirs >/dev/null 2>&1
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-UBSAN-SIO" \
  "UBSan signed-overflow: removed from crashes/"
sio_rejected=$(find "$RESULTS_DIR/crashes-rejected" -maxdepth 1 -name 'CRASH-UBSAN-SIO*' -type d 2>/dev/null | head -1)
assert_eq "" "$sio_rejected" "UBSan signed-overflow: NOT sent to crashes-rejected/"
assert_dir_exists "$RESULTS_DIR/findings/FIND-UBSAN-SIO" \
  "UBSan signed-overflow: demoted to findings/ as an accepted finding"

# An INCOMPLETE non-security UBSan dir (sanitizer trace only — no report.md,
# no testcase) must NOT be demoted. It goes through the same completeness
# gate as any crash and stays promotion-pending in crashes/ until the agent
# finishes it (or TTL-rejects). This guards the invariant that a demoted
# UBSan finding has a substantive report AND a reproducing testcase.
INC_DIR="$RESULTS_DIR/crashes/CRASH-UBSAN-INCOMPLETE"
mkdir -p "$INC_DIR"
printf '%s\n' "$UBSAN_SIO_TRACE" > "$INC_DIR/sanitizer.txt"
LLM_DECIDE_DISABLE=1 triage_crash_dirs >/dev/null 2>&1
assert_dir_exists "$INC_DIR" "incomplete UBSan: stays in crashes/ (not demoted while incomplete)"
assert_dir_not_exists "$RESULTS_DIR/findings/FIND-UBSAN-INCOMPLETE" \
  "incomplete UBSan: NOT demoted to findings/ without report.md + testcase"
assert_file_exists "$INC_DIR/.promotion_pending" \
  "incomplete UBSan: marked promotion-pending in crashes/"

# A non-security UBSan dir WITH a report but NO testcase must also stay
# pending — a reproducing testcase is required for UBSan findings, so the
# completeness gate keeps it in crashes/ until the testcase lands.
NOTC_DIR="$RESULTS_DIR/crashes/CRASH-UBSAN-NOTESTCASE"
mkdir -p "$NOTC_DIR"
printf '%s\n' "$UBSAN_SIO_TRACE" > "$NOTC_DIR/sanitizer.txt"
printf '# Signed overflow in app_compute\n\nReport body.\n' > "$NOTC_DIR/report.md"
LLM_DECIDE_DISABLE=1 triage_crash_dirs >/dev/null 2>&1
assert_dir_exists "$NOTC_DIR" "report-but-no-testcase UBSan: stays pending in crashes/"
assert_dir_not_exists "$RESULTS_DIR/findings/FIND-UBSAN-NOTESTCASE" \
  "report-but-no-testcase UBSan: NOT demoted to findings/ without a testcase"
assert_file_exists "$NOTC_DIR/.promotion_pending" \
  "report-but-no-testcase UBSan: marked promotion-pending in crashes/"

# A security-class UBSan crash (vptr / Bad-cast) is NOT demoted at step 0 —
# it stays in the crash pipeline (here: kept in crashes/ for the downstream
# gates to judge), so it must never land in findings/ via demotion.
UBSAN_VPTR_TRACE=$(cat <<'EOF'
/src/poly.cpp:12:5: runtime error: member call on address 0x602000000010 which does not point to an object of type 'Shape'
    #0 0x100 in app_dispatch poly.cpp:12
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/poly.cpp:12:5
EOF
)
mk_crash_dir CRASH-UBSAN-VPTR "$UBSAN_VPTR_TRACE" >/dev/null
LLM_DECIDE_DISABLE=1 triage_crash_dirs >/dev/null 2>&1
assert_dir_not_exists "$RESULTS_DIR/findings/FIND-UBSAN-VPTR" \
  "UBSan vptr/Bad-cast: NOT demoted to findings/ (security class stays a crash)"

teardown_test_env
summary
