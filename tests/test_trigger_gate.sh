#!/usr/bin/env bash
# Trigger-provenance gate wiring — demote-only, recall-safe, cached.
#
# Covers _triage_trigger_provenance_gate inside _validate_one_find_dir:
#   - no backend resolved → no-op (finding kept, no backend call)
#   - rc=1 Reject demotes the finding to findings-rejected/
#   - Promote / Uncertain / parse-failure all KEEP
#   - the vote file is the done-marker so a resume does not re-run
# The real validate-finding is replaced by a stub whose vote + exit code the
# test drives via env. (The "empty disproof downgrades Reject→Uncertain" rule
# lives inside bin/validate-finding itself; the prompt-render test asserts the
# rule is present.)
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env
source "$SCRIPT_ROOT/lib/triage.sh"

export REACHABILITY_AUTO=0                 # no network on the KEEP path
# helpers.sh defaults LLM_DECIDE_DISABLE=1, and the gate honours it (no-op) —
# unset it here so the gate actually runs. The only LLM caller on this path is
# llm_find_quality_decision, neutralised below, so no real backend is hit.
unset LLM_DECIDE_DISABLE
llm_find_quality_decision() { :; }

TARGET_ROOT="$RESULTS_DIR/src"; mkdir -p "$TARGET_ROOT"; export TARGET_ROOT
export TARGET_SLUG="sample"
FAKEBIN="$RESULTS_DIR/bin"; mkdir -p "$FAKEBIN"
export STUB_CALLS="$RESULTS_DIR/stub-calls.log"
export STUB_ARGS="$RESULTS_DIR/stub-args.log"
cat > "$FAKEBIN/validate-finding" <<'STUB'
#!/usr/bin/env bash
echo "$*" >> "$STUB_ARGS"
out=""
while [ $# -gt 0 ]; do case "$1" in --output) out="$2"; shift 2 ;; *) shift ;; esac; done
echo call >> "$STUB_CALLS"
[ -n "$out" ] && printf '{"vote":"%s","disproof":"x"}\n' "${STUB_VOTE:-Uncertain}" > "$out"
exit "${STUB_RC:-2}"
STUB
printf '#!/usr/bin/env bash\nexit 0\n' > "$FAKEBIN/state"
chmod +x "$FAKEBIN/validate-finding" "$FAKEBIN/state"

mkfind() {  # $1=id → findings/$1 with a report; echoes the path
  local p="$RESULTS_DIR/findings/$1"; mkdir -p "$p"
  printf '# report\nLocation: src/x.c:f:1\nIssue class: memory-safety.\n' > "$p/report.md"
  printf '%s' "$p"
}

# ── 1. No backend resolved → gate no-ops, finding kept ─────────────
unset ACTIVE_BACKEND
: > "$STUB_CALLS"
d1=$(mkfind FIND-1); _validate_one_find_dir "$d1" "$FAKEBIN" 2>/dev/null
assert_dir_exists "$d1" "no backend: finding kept"
[ ! -s "$STUB_CALLS" ] && pass "no backend: gate not invoked" || fail "no backend: gate not invoked" "stub called"

# ── 2. Reject demotes to findings-rejected/ ────────────────────────
export ACTIVE_BACKEND=stub STUB_RC=1 STUB_VOTE=Reject
d2=$(mkfind FIND-2); _validate_one_find_dir "$d2" "$FAKEBIN" 2>/dev/null
[ ! -d "$d2" ] && pass "Reject: removed from findings/" || fail "Reject: removed from findings/" "still present"
assert_dir_exists "$RESULTS_DIR/findings-rejected/FIND-2" "Reject: demoted to findings-rejected/"

# ── 3. Uncertain / Promote / parse-failure all KEEP ────────────────
for spec in "Uncertain 2" "Promote 0" "ParseFailure 3"; do
  set -- $spec; v="$1"; rcc="$2"
  export STUB_VOTE="$v" STUB_RC="$rcc"
  dk=$(mkfind "FIND-keep-$v"); _validate_one_find_dir "$dk" "$FAKEBIN" 2>/dev/null
  assert_dir_exists "$dk" "$v: finding kept"
  [ ! -d "$RESULTS_DIR/findings-rejected/FIND-keep-$v" ] \
    && pass "$v: not demoted" || fail "$v: not demoted" "was demoted"
done

# ── 4. Vote file is the done-marker: a resume does not re-run ──────
export STUB_VOTE=Uncertain STUB_RC=2
d4=$(mkfind FIND-4); : > "$STUB_CALLS"
_validate_one_find_dir "$d4" "$FAKEBIN" 2>/dev/null        # 1st pass: one call, KEEP
assert_file_exists "$d4/.trigger-gate.json" "verdict recorded after first pass"
export STUB_RC=99 STUB_VOTE=BOOM                           # would demote/err if called again
_validate_one_find_dir "$d4" "$FAKEBIN" 2>/dev/null        # 2nd pass: must short-circuit
[ "$(grep -c call "$STUB_CALLS")" = "1" ] \
  && pass "resume short-circuits on the vote-file marker (one call total)" \
  || fail "resume short-circuits" "stub called more than once"
assert_dir_exists "$d4" "resume: finding still kept"

# ── 5. The run's --model is forwarded to validate-finding ─────────
export ACTIVE_BACKEND=stub STUB_RC=2 STUB_VOTE=Uncertain MODEL=my-model
: > "$STUB_ARGS"
dm=$(mkfind FIND-model); _validate_one_find_dir "$dm" "$FAKEBIN" 2>/dev/null
assert_file_contains "$STUB_ARGS" "model my-model" "gate forwards run --model to validate-finding"
unset MODEL

# ── 6. validate-finding itself: empty-disproof Reject → Uncertain ──
# Drive the REAL validate-finding with a stub claude backend so the recall-safe
# downgrade (a Reject with no affirmative disproof becomes Uncertain) is proven.
VF="$SCRIPT_ROOT/bin/validate-finding"
vtgt="$RESULTS_DIR/vtgt"; mkdir -p "$vtgt"; echo 'int main(){return 0;}' > "$vtgt/x.c"
vfind="$RESULTS_DIR/vfind.md"
printf '# r\nLocation: x.c:f:1\nIssue class: memory-safety.\n' > "$vfind"
write_claude_stub() {  # $1 = disproof string (may be empty)
  python3 - "$1" "$RESULTS_DIR/claude_out.json" <<'PY'
import json, sys
vote = json.dumps({"vote": "Reject", "disproof": sys.argv[1]})
open(sys.argv[2], "w").write(json.dumps({"type": "result", "result": vote}) + "\n")
PY
  printf '#!/usr/bin/env bash\ncat %q\n' "$RESULTS_DIR/claude_out.json" > "$RESULTS_DIR/claude"
  chmod +x "$RESULTS_DIR/claude"
}
write_claude_stub ""
rc=0; CLAUDE_BIN="$RESULTS_DIR/claude" "$VF" --finding "$vfind" --target-path "$vtgt" \
  --backend claude --gate trigger --output "$RESULTS_DIR/v1.json" >/dev/null 2>&1 || rc=$?
assert_eq 2 "$rc" "empty-disproof Reject downgraded to Uncertain (exit 2 = keep)"
write_claude_stub "src/foo.c:bar enforces the bound on every path"
rc=0; CLAUDE_BIN="$RESULTS_DIR/claude" "$VF" --finding "$vfind" --target-path "$vtgt" \
  --backend claude --gate trigger --output "$RESULTS_DIR/v2.json" >/dev/null 2>&1 || rc=$?
assert_eq 1 "$rc" "disproof-backed Reject honoured (exit 1 = demote)"

teardown_test_env
summary
