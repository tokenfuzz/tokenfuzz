#!/usr/bin/env bash
# Tests for the batched recon-validation pipeline:
#   - lib/recon_triage.py        cluster / parse-batch / survivors / finalize
#   - lib/triage_validate.sh     single-validator mode (TRIAGE_VALIDATE_VOTES=1)
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$TESTS_DIR/helpers.sh"

setup_test_env

RT="$SCRIPT_ROOT/lib/recon_triage.py"
work="$(mktemp -d)"
trap 'rm -rf "$work" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT

# ── Stage 1: cluster ──────────────────────────────────────────────────────
# Four hypotheses: two are the same defect (same file/function/class, lines
# 12 lines apart -> same 15-line bucket), one is distinct, one is AUDIT-CLEAN.
cat > "$work/hyps.jsonl" <<'EOF'
{"file":"/t/src/buf.c","line":390,"function":"buf_fetch","class":"OOB-read","title":"underflow","notes":"the longer and more detailed note wins the representative slot"}
{"file":"/t/src/buf.c","line":402,"function":"buf_fetch","class":"OOB-read","title":"underflow variant","notes":"short"}
{"file":"/t/src/dns.c","line":1200,"function":"dns_parse","class":"UAF","title":"uaf","notes":"a use after free"}
{"file":"/t/src/x.c","line":5,"function":"f","class":"style","title":"doc","notes":"cleanup","confidence":"AUDIT-CLEAN"}
EOF

cluster_out=$(python3 "$RT" cluster --in "$work/hyps.jsonl" \
  --reps "$work/reps.jsonl" --clusters "$work/clusters.json" \
  --passthrough "$work/pass.jsonl" --validate-mode all)
assert_eq "3 2 1" "$cluster_out" "cluster: 3 to-validate -> 2 reps, 1 passthrough"

reps_n=$(grep -c . "$work/reps.jsonl")
assert_eq "2" "$reps_n" "cluster: two structural clusters become two representatives"

# The representative is the member with the richest notes.
rep_note=$(grep buf.c "$work/reps.jsonl" | python3 -c 'import json,sys; print(json.loads(sys.stdin.readline())["notes"][:9])')
assert_eq "the longe" "$rep_note" "cluster: representative is the most-detailed cluster member"

pass_conf=$(python3 -c 'import json;print(json.loads(open("'"$work"'/pass.jsonl").readline())["confidence"])')
assert_eq "AUDIT-CLEAN" "$pass_conf" "cluster: AUDIT-CLEAN rows go to passthrough, not validation"

# Deterministic ids: same input -> same RECON-<sha> id on every run.
id_a=$(python3 -c 'import json;print(json.loads(open("'"$work"'/reps.jsonl").readline())["id"])')
case "$id_a" in
  RECON-????????????????) pass "cluster: assigns deterministic RECON-<16hex> ids" ;;
  *) fail "cluster: bad id format: $id_a" ;;
esac

# confirmed mode: NEEDS-VERIFICATION rows are not validated, they pass through.
python3 "$RT" cluster --in "$work/hyps.jsonl" \
  --reps "$work/reps2.jsonl" --clusters "$work/clusters2.json" \
  --passthrough "$work/pass2.jsonl" --validate-mode confirmed >/dev/null
reps2_n=$(grep -c . "$work/reps2.jsonl" 2>/dev/null || true)
assert_eq "0" "$reps2_n" "cluster: --validate-mode confirmed skips NEEDS-VERIFICATION rows"

# ── Stage 2: parse-batch ──────────────────────────────────────────────────
rep1=$(sed -n '1p' "$work/reps.jsonl" | python3 -c 'import json,sys;print(json.loads(sys.stdin.readline())["id"])')
rep2=$(sed -n '2p' "$work/reps.jsonl" | python3 -c 'import json,sys;print(json.loads(sys.stdin.readline())["id"])')

# A messy transcript: prose around one bare triage JSON object.
cat > "$work/transcript.txt" <<EOF
Let me review these hypotheses one by one.
I read the source and here is my verdict.
{"triage": [{"id": "$rep1", "verdict": "likely-real", "duplicate_of": null, "rationale": "real"}, {"id": "$rep2", "verdict": "reject", "duplicate_of": null, "rationale": "guarded"}]}
Done.
EOF
parse_out=$(python3 "$RT" parse-batch --reps "$work/reps.jsonl" --out "$work/verdicts.json" < "$work/transcript.txt")
assert_eq "2 0" "$parse_out" "parse-batch: both reps triaged, none defaulted"

v1=$(python3 -c 'import json;print(json.load(open("'"$work"'/verdicts.json"))["verdicts"]["'"$rep1"'"]["verdict"])')
assert_eq "likely-real" "$v1" "parse-batch: extracts verdict from a prose-wrapped transcript"

# A transcript with no JSON at all -> every rep defaults to needs-deep-check.
echo "I could not complete the review." > "$work/empty.txt"
parse_empty=$(python3 "$RT" parse-batch --reps "$work/reps.jsonl" --out "$work/verdicts_empty.json" < "$work/empty.txt")
assert_eq "2 2" "$parse_empty" "parse-batch: un-triaged reps default (never silently dropped)"
ve=$(python3 -c 'import json;print(json.load(open("'"$work"'/verdicts_empty.json"))["verdicts"]["'"$rep1"'"]["verdict"])')
assert_eq "needs-deep-check" "$ve" "parse-batch: default verdict is needs-deep-check"

# ── Stage 3: survivors ────────────────────────────────────────────────────
# likely-real + needs-deep-check are survivors; reject is not.
survivors=$(python3 "$RT" survivors --verdicts "$work/verdicts.json" | sort)
assert_eq "$rep1" "$survivors" "survivors: only the non-rejected rep needs a deep validator"

# A duplicate must not be validated twice — it inherits its canonical rep.
python3 - "$work/verdicts_dup.json" "$rep1" "$rep2" <<'PY'
import json, sys
out, a, b = sys.argv[1:4]
json.dump({"verdicts": {
    a: {"verdict": "likely-real", "duplicate_of": None, "rationale": ""},
    b: {"verdict": "likely-real", "duplicate_of": a, "rationale": "same bug"},
}}, open(out, "w"))
PY
dup_survivors=$(python3 "$RT" survivors --verdicts "$work/verdicts_dup.json")
assert_eq "$rep1" "$dup_survivors" "survivors: a duplicate rep is not deep-verified separately"

# --limit caps how many survivors are deep-verified, likely-real first, so a
# recall-heavy recon cannot spend the whole budget in Stage 3.
python3 - "$work/verdicts_many.json" <<'PY'
import json, sys
v = {}
for i in range(6):
    v["RECON-dc%02d" % i] = {"verdict": "needs-deep-check", "duplicate_of": None, "rationale": ""}
for i in range(3):
    v["RECON-lr%02d" % i] = {"verdict": "likely-real", "duplicate_of": None, "rationale": ""}
json.dump({"verdicts": v}, open(sys.argv[1], "w"))
PY
all_surv=$(python3 "$RT" survivors --verdicts "$work/verdicts_many.json" --limit 0 | grep -c .)
assert_eq "9" "$all_surv" "survivors --limit 0: no cap, all 9 survivors emitted"
cap_surv=$(python3 "$RT" survivors --verdicts "$work/verdicts_many.json" --limit 4)
assert_eq "4" "$(printf '%s\n' "$cap_surv" | grep -c .)" "survivors --limit 4: capped to 4"
cap_lr=$(printf '%s\n' "$cap_surv" | grep -c 'RECON-lr' || true)
assert_eq "3" "$cap_lr" "survivors --limit: likely-real reps are prioritised under the cap"

# ── Stage 3: finalize ─────────────────────────────────────────────────────
printf '%s\tPromote\tdeep ok\n' "$rep1" > "$work/stage3.tsv"
fin_out=$(python3 "$RT" finalize --reps "$work/reps.jsonl" --passthrough "$work/pass.jsonl" \
  --verdicts "$work/verdicts.json" --stage3 "$work/stage3.tsv" --out "$work/final.jsonl")
assert_eq "1 1 0" "$fin_out" "finalize: 1 promoted (deep), 1 rejected (batch), 0 uncertain"

final_n=$(grep -c . "$work/final.jsonl")
assert_eq "3" "$final_n" "finalize: 2 reps + 1 passthrough row written"

# rep1: batch likely-real + deep Promote -> Promote
fv1=$(grep "$rep1" "$work/final.jsonl" | python3 -c 'import json,sys;print(json.loads(sys.stdin.readline())["validator_verdict"])')
assert_eq "Promote" "$fv1" "finalize: deep-validated survivor carries the deep verdict"
# rep2: batch reject -> Reject, never sent to a deep validator
fv2=$(grep "$rep2" "$work/final.jsonl" | python3 -c 'import json,sys;print(json.loads(sys.stdin.readline())["validator_verdict"])')
assert_eq "Reject" "$fv2" "finalize: batch-rejected rep is Reject without a deep validator"

# A survivor with no stage-3 result stays Uncertain (kept in play, not dropped).
: > "$work/stage3_empty.tsv"
python3 "$RT" finalize --reps "$work/reps.jsonl" --passthrough "$work/pass.jsonl" \
  --verdicts "$work/verdicts.json" --stage3 "$work/stage3_empty.tsv" --out "$work/final2.jsonl" >/dev/null
fv1u=$(grep "$rep1" "$work/final2.jsonl" | python3 -c 'import json,sys;print(json.loads(sys.stdin.readline())["validator_verdict"])')
assert_eq "Uncertain" "$fv1u" "finalize: survivor with no deep result stays Uncertain"

# Duplicate inheritance: rep2 duplicate-of rep1, rep1 deep-Promoted -> rep2 Promote.
python3 "$RT" finalize --reps "$work/reps.jsonl" --passthrough "$work/pass.jsonl" \
  --verdicts "$work/verdicts_dup.json" --stage3 "$work/stage3.tsv" --out "$work/final3.jsonl" >/dev/null
fv2d=$(grep "$rep2" "$work/final3.jsonl" | python3 -c 'import json,sys;print(json.loads(sys.stdin.readline())["validator_verdict"])')
assert_eq "Promote" "$fv2d" "finalize: a duplicate inherits its canonical rep's deep verdict"

# ── triage_validate.sh: single-validator mode ─────────────────────────────
# A fake validate-finding lets us exercise TRIAGE_VALIDATE_VOTES=1 without a
# backend: it exits with whatever code FAKE_VALIDATOR_RC names, and records
# how many times it was called.
fake_root="$work/fakeroot"
mkdir -p "$fake_root/bin"
cat > "$fake_root/bin/validate-finding" <<'SH'
#!/usr/bin/env bash
echo "$$" >> "$FAKE_VALIDATOR_CALLS"
out=""
while [ $# -gt 0 ]; do
  case "$1" in --output) out="$2"; shift 2 ;; *) shift ;; esac
done
[ -n "$out" ] && printf '{"vote":"x"}\n' > "$out"
exit "${FAKE_VALIDATOR_RC:-0}"
SH
chmod +x "$fake_root/bin/validate-finding"

mkdir -p "$work/finding_dir"
echo '{"id":"RECON-test","class":"OOB-read"}' > "$work/finding_dir/finding.json"

# Source triage_validate with SCRIPT_ROOT pointed at the fake tree.
(
  SCRIPT_ROOT="$fake_root"
  # shellcheck disable=SC1090
  source "$SCRIPT_ROOT/../lib/triage_validate.sh" 2>/dev/null \
    || source "$work/../triage_validate_copy.sh" 2>/dev/null || true
) 2>/dev/null || true

# triage_validate.sh resolves validator_bin from SCRIPT_ROOT; source it
# directly with SCRIPT_ROOT set so the fake binary is picked up.
export FAKE_VALIDATOR_CALLS="$work/calls.log"
: > "$FAKE_VALIDATOR_CALLS"

run_single_validator() {
  local rc_want="$1"
  : > "$FAKE_VALIDATOR_CALLS"
  (
    SCRIPT_ROOT="$fake_root"
    # shellcheck disable=SC1090
    source "$SCRIPT_ROOT/lib/triage_validate.sh"
    export FAKE_VALIDATOR_RC="$rc_want"
    export TRIAGE_VALIDATE_VOTES=1
    triage_validate_finding "$work/finding_dir/finding.json" "/t" "$work" 2>/dev/null
    echo "RC=$?"
  )
}
# Make the real triage_validate.sh visible under the fake root.
ln -snf "$SCRIPT_ROOT/lib" "$fake_root/lib" 2>/dev/null || cp -R "$SCRIPT_ROOT/lib" "$fake_root/lib"

out_promote=$(run_single_validator 0)
calls_promote=$(grep -c . "$FAKE_VALIDATOR_CALLS" 2>/dev/null || echo 0)
assert_match "RC=0" "$out_promote" "votes=1: a Promote vote returns rc 0"
assert_eq "1" "$calls_promote" "votes=1: exactly one validator runs (no quorum)"

out_reject=$(run_single_validator 1)
assert_match "RC=1" "$out_reject" "votes=1: a Reject vote returns rc 1"

# ── triage_validate_confirm_findings: route a findings/ tree by verdict ──
# Reuses the fake validate-finding above. Two candidates: FIND-001 carries
# a report (verdict driven by FAKE_VALIDATOR_RC), FIND-002 has none and
# must be auto-rejected without a validator call.
conf_root="$work/confirm"
run_confirm() {
  local rc_want="$1"
  rm -rf "$conf_root"
  mkdir -p "$conf_root/findings/FIND-001" "$conf_root/findings/FIND-002"
  echo "a plausible security finding narrative" \
    > "$conf_root/findings/FIND-001/report.md"
  (
    SCRIPT_ROOT="$fake_root"
    # shellcheck disable=SC1090
    source "$SCRIPT_ROOT/lib/triage_validate.sh"
    export FAKE_VALIDATOR_RC="$rc_want"
    export TRIAGE_VALIDATE_VOTES=1
    triage_validate_confirm_findings "$conf_root/findings" "/t" \
      "$conf_root/findings-rejected" 2>/dev/null
  )
}

# Validator promotes the reported finding; the report-less one is rejected.
out_conf=$(run_confirm 0)
assert_match 'confirmed=1 rejected=1 of=2' "$out_conf" \
  "confirm-findings: promote kept, no-report candidate rejected"
assert_dir_exists "$conf_root/findings/FIND-001" \
  "confirm-findings: a promoted finding stays in findings/"
assert_dir_exists "$conf_root/findings-rejected/FIND-002" \
  "confirm-findings: a candidate with no report is quarantined"

# A Reject vote quarantines even a finding that has a report.
out_conf=$(run_confirm 1)
assert_match 'confirmed=0 rejected=2 of=2' "$out_conf" \
  "confirm-findings: a Reject vote moves the finding out of findings/"
assert_dir_exists "$conf_root/findings-rejected/FIND-001" \
  "confirm-findings: rejected finding lands in findings-rejected/"

# ── validate-finding: Markdown reports must not become empty facts ─────
vf_root="$work/validate-md"
mkdir -p "$vf_root/target" "$vf_root/FIND-1"
cat > "$vf_root/FIND-1/report.md" <<'MD'
# FIND-1: sample

File and function: `src/tool_doswin.c:714`, `win_stdin_thread_func`.

Bug class: info-leak / protocol-state.

Input shape and reach path: a local process reaches the loopback relay.

Guards passed: loopback-only, but no peer authentication.

Primitive: stdin bytes can be written to the wrong local peer.
MD

fake_codex_validator="$vf_root/codex"
cat > "$fake_codex_validator" <<'SH'
#!/usr/bin/env bash
last=""
for arg in "$@"; do
  last="$arg"
done
printf '%s' "$last" > "${CAPTURE_PROMPT:?}"
cat <<'JSON'
{"type":"item.completed","item":{"id":"x","type":"agent_message","text":"{\"vote\":\"Reject\",\"rationale\":\"test vote\",\"verified\":{\"reachability\":false,\"guards\":false,\"primitive\":false},\"caveats\":\"test\"}"}}
JSON
SH
chmod +x "$fake_codex_validator"

set +e
CODEX_BIN="$fake_codex_validator" CAPTURE_PROMPT="$vf_root/prompt.txt" \
  "$SCRIPT_ROOT/bin/validate-finding" \
    --backend codex \
    --finding "$vf_root/FIND-1/report.md" \
    --target-path "$vf_root/target" \
    --output "$vf_root/vote.json" \
    --timeout 5 >/dev/null 2>&1
vf_rc=$?
set -e

assert_eq "1" "$vf_rc" "validate-finding fake Reject vote returns rc 1"
assert_file_contains "$vf_root/prompt.txt" '"format": "markdown-report"' \
  "validate-finding markdown fallback marks report format"
assert_file_contains "$vf_root/prompt.txt" '"report_text":' \
  "validate-finding markdown fallback preserves full report text"
assert_file_contains "$vf_root/prompt.txt" '"location": "`src/tool_doswin.c:714`, `win_stdin_thread_func`."' \
  "validate-finding markdown fallback extracts file/function label"
assert_file_contains "$vf_root/prompt.txt" '"class": "info-leak / protocol-state."' \
  "validate-finding markdown fallback extracts bug class label"
assert_file_not_contains "$vf_root/prompt.txt" '^[[:space:]]*\{[[:space:]]*\}[[:space:]]*$' \
  "validate-finding markdown fallback does not send empty facts"

teardown_test_env 2>/dev/null || true
echo "All recon-triage tests passed."
