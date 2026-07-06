#!/usr/bin/env bash
# Crash-side trigger-provenance gate — demote-only, recall-safe, uniform across
# trigger kinds, with a two-vote quorum and verdict-aware caching.
#
# Covers _triage_crash_trigger_provenance_gate (the step-5.5 gate that closes
# the verdict-matrix blind spot where a `bytes`-labelled trigger is kept at full
# severity even when the bytes are self-produced internal state):
#   - no backend → no-op (kept, no call); CRASH_TRIGGER_GATE=0 → no-op
#   - a sanitizer-confirmed crash needs TWO independent Rejects to be hard-moved
#     to crashes-rejected/ — for `bytes` AND `call-sequence` triggers alike
#   - a single / disagreeing Reject KEEPS the crash (recall-safe quorum)
#   - a first non-Reject keeps without seeking a second opinion (one call)
#   - a ParseFailure vote is NOT a final done-marker: the gate retries it
#     (a transient backend error must not permanently disable the gate)
#   - a conclusive verdict IS the done-marker: a resume does not re-run
# The real validate-finding is replaced by a vote-driven stub (exit code derived
# from the vote, per-call votes via STUB_VOTE<n>), as tests/test_trigger_gate.sh
# does for findings.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/triage.sh"

unset LLM_DECIDE_DISABLE                     # helpers.sh defaults it to 1
export CRASH_REJECT_SKIP_DO_NOT_REVISIT=0    # skip the bin/state side-effect
export INDEX="$RESULTS_DIR/index.log"
mkdir -p "$RESULTS_DIR/crashes" "$RESULTS_DIR/crashes-rejected"

TARGET_ROOT="$RESULTS_DIR/src"; mkdir -p "$TARGET_ROOT"; export TARGET_ROOT
export TARGET_SLUG="sample"
FAKEBIN="$RESULTS_DIR/bin"; mkdir -p "$FAKEBIN"
export STUB_CALLS="$RESULTS_DIR/stub-calls.log"; : > "$STUB_CALLS"
cat > "$FAKEBIN/validate-finding" <<'STUB'
#!/usr/bin/env bash
out=""
while [ $# -gt 0 ]; do case "$1" in --output) out="$2"; shift 2 ;; *) shift ;; esac; done
n=$(grep -c call "$STUB_CALLS" 2>/dev/null); n=$((n + 1))
echo "call $n" >> "$STUB_CALLS"
eval "v=\${STUB_VOTE$n:-}"; [ -n "$v" ] || v="${STUB_VOTE:-Uncertain}"
[ -n "$out" ] && printf '{"vote":"%s","disproof":"x"}\n' "$v" > "$out"
case "$v" in Promote) exit 0 ;; Reject) exit 1 ;; Uncertain) exit 2 ;; ParseFailure) exit 3 ;; *) exit 2 ;; esac
STUB
chmod +x "$FAKEBIN/validate-finding"

# $1=id, $2=trigger source → crashes/$1 with a REPORT.md; echoes the dir path.
mkcrash() {
  local p="$RESULTS_DIR/crashes/$1"; mkdir -p "$p"
  printf '# %s: heap-buffer-overflow\n\nSummary: a crash.\nTrigger source: %s\n' \
    "$1" "$2" > "$p/REPORT.md"
  printf '%s' "$p"
}
run_gate() { _triage_crash_trigger_provenance_gate "$1" "$(basename "$1")" "$1/REPORT.md" "$FAKEBIN"; }
ncalls() { local n; n=$(grep -c call "$STUB_CALLS" 2>/dev/null); printf '%s' "${n:-0}"; }

# ── 1. No backend resolved → gate no-ops, crash kept ───────────────
unset ACTIVE_BACKEND
: > "$STUB_CALLS"
d1=$(mkcrash CRASH-0001 bytes); rc=0; run_gate "$d1" || rc=$?
assert_eq 1 "$rc" "no backend: gate keeps (rc=1)"
assert_dir_exists "$d1" "no backend: crash kept"
assert_eq 0 "$(ncalls)" "no backend: gate not invoked"

# ── 2. CRASH_TRIGGER_GATE=0 → gate disabled, crash kept ────────────
export ACTIVE_BACKEND=stub STUB_VOTE=Reject
: > "$STUB_CALLS"
CRASH_TRIGGER_GATE=0 run_gate "$(mkcrash CRASH-0002 bytes)" && fail "opt-out: gate must keep" "rejected"
assert_dir_exists "$RESULTS_DIR/crashes/CRASH-0002" "opt-out: crash kept"
assert_eq 0 "$(ncalls)" "opt-out: gate not invoked"

# ── 3. TWO Rejects route to crashes-rejected/ — BYTES trigger ──────
# The blind spot the fix closes: a forged-own-state crash labelled `bytes` is
# promoted by the set-difference, but two independent validators reject it.
export STUB_VOTE=Reject; : > "$STUB_CALLS"
d3=$(mkcrash CRASH-0003 bytes); rc=1; run_gate "$d3" && rc=0
assert_eq 0 "$rc" "bytes 2×Reject: gate acts (rc=0)"
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-0003" "bytes 2×Reject: routed to crashes-rejected/"
assert_file_contains "$RESULTS_DIR/crashes-rejected/CRASH-0003/.autodiscard" \
  "trigger-provenance" \
  "bytes 2×Reject: rejected dir records index reason"
_maintain_rejected_indexes
assert_file_contains "$RESULTS_DIR/crashes-rejected/REJECTED-CRASHES.md" \
  "trigger-provenance" \
  "bytes 2×Reject: rejected-crashes index surfaces reason"
assert_eq 2 "$(ncalls)" "bytes 2×Reject: quorum sought a second vote"

# ── 4. TWO Rejects route the same way for a CALL-SEQUENCE trigger ──
# Proves the gate is uniform across trigger kinds (no asymmetry).
: > "$STUB_CALLS"
d4=$(mkcrash CRASH-0004 call-sequence); rc=1; run_gate "$d4" && rc=0
assert_eq 0 "$rc" "call-sequence 2×Reject: gate acts (rc=0)"
assert_dir_exists "$RESULTS_DIR/crashes-rejected/CRASH-0004" "call-sequence 2×Reject: routed to crashes-rejected/"

# ── 5. A single / disagreeing Reject KEEPS (recall-safe quorum) ────
# One validator must not be enough to drop a sanitizer-confirmed crash.
export STUB_VOTE1=Reject STUB_VOTE2=Uncertain; unset STUB_VOTE; : > "$STUB_CALLS"
d5=$(mkcrash CRASH-0005 bytes); run_gate "$d5" && fail "Reject+Uncertain: must keep" "rejected"
assert_dir_exists "$RESULTS_DIR/crashes/CRASH-0005" "Reject+Uncertain: crash kept"
[ ! -d "$RESULTS_DIR/crashes-rejected/CRASH-0005" ] \
  && pass "Reject+Uncertain: not rejected" || fail "Reject+Uncertain: not rejected" "was rejected"
assert_eq 2 "$(ncalls)" "Reject+Uncertain: a second opinion was sought"
unset STUB_VOTE1 STUB_VOTE2

# ── 6. A first non-Reject keeps with NO second vote ────────────────
export STUB_VOTE=Uncertain; : > "$STUB_CALLS"
d6=$(mkcrash CRASH-0006 bytes); run_gate "$d6" && fail "Uncertain: must keep" "rejected"
assert_dir_exists "$RESULTS_DIR/crashes/CRASH-0006" "Uncertain: crash kept"
assert_eq 1 "$(ncalls)" "Uncertain: no quorum vote when the first is not a Reject"

# ── 7. ParseFailure is retryable, never a permanent done-marker ────
export STUB_VOTE=ParseFailure; : > "$STUB_CALLS"
d7=$(mkcrash CRASH-0007 bytes); run_gate "$d7" && fail "ParseFailure: must keep" "rejected"
assert_dir_exists "$RESULTS_DIR/crashes/CRASH-0007" "ParseFailure: crash kept"
assert_file_exists "$d7/.trigger-gate.json" "ParseFailure: vote file written"
n_before=$(ncalls)
export STUB_VOTE=Promote                                   # a conclusive verdict now
run_gate "$d7" && fail "ParseFailure retry: must keep on Promote" "rejected"
[ "$(ncalls)" -gt "$n_before" ] \
  && pass "ParseFailure: retried (not cached as a done-marker)" \
  || fail "ParseFailure: retried" "gate short-circuited on the ParseFailure record"

# ── 8. A conclusive verdict IS the done-marker: resume does not re-run ──
export STUB_VOTE=Uncertain; : > "$STUB_CALLS"
d8=$(mkcrash CRASH-0008 bytes); run_gate "$d8"            # 1st pass: one call, KEEP
assert_file_exists "$d8/.trigger-gate.json" "verdict recorded after first pass"
export STUB_VOTE=Reject                                    # would reject if re-called
run_gate "$d8" && fail "resume must keep (cached verdict)" "re-rejected"
assert_eq 1 "$(ncalls)" "resume short-circuits on the cached verdict (one call total)"
assert_dir_exists "$d8" "resume: crash still kept"

teardown_test_env
summary
