#!/usr/bin/env bash
# tests/test_decision_triage.sh — Wires lib/triage.sh:triage_crash_dirs to LLM
# with a mock and verifies override semantics.
#
# Three pillars:
#   1. LLM says "keep" → regex-discardable crash IS NOT discarded (override),
#      EXCEPT the hard-reject classes (null-deref / stack-exhaustion), which are
#      rejected regardless of the LLM vote (pillar 1b).
#   2. LLM says "discard" → crash IS discarded with LLM reason in .autodiscard.
#   3. LLM unavailable → regex fallback runs (existing behavior).

set -uo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/llm_decide.sh"
source "$SCRIPT_ROOT/lib/triage.sh"

# This suite focuses on the LLM-triage override path, not on severity
# scoring. Severity runs offline and deterministically, so the assertions
# here don't depend on it; test_triage_severity.sh exercises the scoring
# integration explicitly.

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
# Build an OOM trace that the regex would auto-discard. Unlike null-deref /
# stack-exhaustion (hard-rejected — pillar 1b), OOM stays LLM-rescuable, so a
# "keep" vote overrides the regex discard. This exercises the override path.
OOM_TRACE=$(cat <<'EOF'
==12345==ERROR: AddressSanitizer: allocation-size-too-big (0xffffffffffff)
    #0 0x100 in foo() /a/b.c:10
EOF
)
# A hard-reject class (null-deref) reused by pillar 1b below.
NULL_DEREF_TRACE=$(cat <<'EOF'
==12345==ERROR: AddressSanitizer: SEGV on unknown address 0x0000000000
SCARINESS: 10 (null-deref)
    #0 0x100 in foo() /a/b.c:10
EOF
)
mk_crash_dir CRASH-001 "$OOM_TRACE" >/dev/null
export LLM_DECIDE_MOCK_CRASH_TRIAGE='{"keep":true,"reason":"bounded by caller; real DoS lead"}'
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
==67890==ERROR: AddressSanitizer: out-of-memory: allocator is trying to allocate 0x80000000 bytes
    #0 0x7fff0000aaaa in foo() /a/b.c:10
EOF
LLM_DECIDE_DISABLE=1 triage_crash_dirs >/dev/null 2>&1
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-001" "LLM disabled: changed ASan output invalidates cache"

# ── 1b. Hard-reject exception: LLM keep does NOT rescue null-deref ───
# null-deref / stack-exhaustion are recoverable, low-value process crashes;
# they are rejected regardless of the LLM vote, so the pillar-1 override must
# NOT apply. (Autodiscard-classifier coverage lives in test_triage.sh §8c; this
# asserts the policy through the full llm_decide→triage path with a keep mock.)
mk_crash_dir CRASH-001B "$NULL_DEREF_TRACE" >/dev/null
export LLM_DECIDE_MOCK_CRASH_TRIAGE='{"keep":true,"reason":"insists this is interesting"}'
export LLM_DECIDE_MOCK_LEGIT_CRASH='{"legitimate":true,"reason":"web content input boundary"}'
triage_crash_dirs >/dev/null 2>&1
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-001B" "hard-reject: LLM keep does NOT rescue null-deref"
hr_rejected=$(find "$RESULTS_DIR/crashes-rejected" -maxdepth 1 -name 'CRASH-001B*' -type d | head -1)
assert_dir_exists "$hr_rejected" "hard-reject: null-deref sent to crashes-rejected despite keep"
unset LLM_DECIDE_MOCK_CRASH_TRIAGE
unset LLM_DECIDE_MOCK_LEGIT_CRASH

# ── 2. LLM marks discard on a non-memory-safety trace → still discards ─
# The LLM gate still rejects classes the sanitizer did NOT confirm as a
# memory-safety bug. OOM is such a class (and, unlike null-deref, is not
# hard-rejected first), so the LLM-named reason flows through to .autodiscard.
mk_crash_dir CRASH-002 "$OOM_TRACE" >/dev/null
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
mk_crash_dir CRASH-003 "$OOM_TRACE" >/dev/null
LLM_DECIDE_DISABLE=1 triage_crash_dirs >/dev/null 2>&1
assert_dir_not_exists "$RESULTS_DIR/crashes/CRASH-003"          "LLM disabled: regex still discards OOM"
rejected_dir=$(find "$RESULTS_DIR/crashes-rejected" -maxdepth 1 -name 'CRASH-003*' -type d | head -1)
assert_dir_exists "$rejected_dir" "LLM disabled: rejected via regex"
assert_file_contains "$rejected_dir/.autodiscard" "non-finding class" \
  "autodiscard reflects regex reason"

# ── 4. LLM returns malformed JSON → regex fallback ──────────────────
mk_crash_dir CRASH-004 "$OOM_TRACE" >/dev/null
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

# An auto-filed bin/probe skeleton (report.md still carries the
# `_TODO (agent):` markers from lib/crash_bundle.sh) must be held as
# promotion-pending — a placeholder report must not satisfy the completeness
# gate and ship as a maintainer-facing bundle when LLM confirmation is off.
# The same crash with a real (enriched) report passes the gate.
UAF_TRACE=$(cat <<'EOF'
==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010
READ of size 4 at 0x602000000010 thread T0
    #0 0x100 in app_consume child.c:91
SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in app_consume
EOF
)
SKEL_DIR="$RESULTS_DIR/crashes/CRASH-SKELETON"
mkdir -p "$SKEL_DIR"
printf '%s\n' "$UAF_TRACE" > "$SKEL_DIR/sanitizer.txt"
printf 'reuse-after-free testcase bytes\n' > "$SKEL_DIR/testcase.tc"
cat > "$SKEL_DIR/report.md" <<'EOF'
# CRASH-SKELETON: AddressSanitizer: heap-use-after-free (auto-filed by bin/probe)
## Root Cause
_TODO (agent): describe the defect and why the sanitizer fires._
## Data Flow
_TODO (agent): step: func (file:line) — desc._
Boundary:
Trigger source:
EOF
ENR_DIR="$RESULTS_DIR/crashes/CRASH-ENRICHED"
mkdir -p "$ENR_DIR"
printf '%s\n' "$UAF_TRACE" > "$ENR_DIR/sanitizer.txt"
printf 'reuse-after-free testcase bytes\n' > "$ENR_DIR/testcase.tc"
cat > "$ENR_DIR/report.md" <<'EOF'
# CRASH-ENRICHED: heap-use-after-free in app_consume
## Root Cause
The parent retains a stale pointer to a child freed during cleanup, so a later
read dereferences freed memory.
## Data Flow
read: app_consume (child.c:91) — dereferences the freed child node.
Boundary: public API call sequence
Trigger source: call-sequence
EOF
# Enriched sections but a mid-line mention of the marker in the intro note
# (e.g. "REPLACE the _TODO (agent): sections") must NOT keep the crash pending:
# the sentinel check is anchored to line start, where only unreplaced
# placeholders live.
NOTE_DIR="$RESULTS_DIR/crashes/CRASH-ENRICHED-NOTE"
mkdir -p "$NOTE_DIR"
printf '%s\n' "$UAF_TRACE" > "$NOTE_DIR/sanitizer.txt"
printf 'reuse-after-free testcase bytes\n' > "$NOTE_DIR/testcase.tc"
cat > "$NOTE_DIR/report.md" <<'EOF'
# CRASH-ENRICHED-NOTE: heap-use-after-free
> Note: replace the `_TODO (agent):` sections before filing.
## Root Cause
The parent retains a stale pointer to a freed child, read during cleanup.
## Data Flow
read: app_consume (child.c:91) — dereferences the freed child node.
Boundary: public API call sequence
Trigger source: call-sequence
EOF
LLM_DECIDE_DISABLE=1 CRASH_CONFIRM_AUTO=0 CLUSTER_AUTO=0 triage_crash_dirs >/dev/null 2>&1
assert_dir_exists "$SKEL_DIR" "auto-filed skeleton: held in crashes/ (not exported/rejected)"
assert_file_exists "$SKEL_DIR/.promotion_pending" \
  "auto-filed skeleton: marked promotion-pending until enriched"
assert_file_not_exists "$ENR_DIR/.promotion_pending" \
  "enriched report: passes the completeness gate (no skeleton markers)"
assert_file_not_exists "$NOTE_DIR/.promotion_pending" \
  "enriched report with a mid-line marker mention: not held (sentinel is line-anchored)"

teardown_test_env
summary
