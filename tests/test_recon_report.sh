#!/usr/bin/env bash
# Tests for lib/recon_report.py and the recon/ relocation:
#   - per-RECON REPORT.md rendering from finding.json + validator votes
#   - results-dir / recon-root discovery modes
#   - idempotency and --no-html
#   - bin/audit-recon writes RECON-* dirs under recon/, not findings/
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$TESTS_DIR/helpers.sh"

setup_test_env

RECON_REPORT="$SCRIPT_ROOT/lib/recon_report.py"

# ── Fixture: a results dir with one recon/RECON-* candidate ──────────────
work=$(mktemp -d)
trap 'rm -rf "$work" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT

recon_dir="$work/results/recon/RECON-deadbeefcafe0001"
mkdir -p "$recon_dir"

cat > "$recon_dir/finding.json" <<'JSON'
{"id":"RECON-deadbeefcafe0001","slice":"slice-1-parsers","title":"URL decoder allocates length+1 without guarding SIZE_MAX","file":"/home/x/work/targets/curl/lib/escape.c","line":116,"function":"Curl_urldecode","class":"integer-overflow","notes":"alloc is used as malloc(alloc + 1) without a wrap check.","confidence":"NEEDS-VERIFICATION","validator_verdict":"Reject","validator_details":"verdict=Reject"}
JSON

cat > "$recon_dir/validator-vote-1.json" <<'JSON'
{"vote":"Reject","rationale":"No attacker-reachable path supplies SIZE_MAX; the exported API caps length at INT_MAX.","verified":{"reachability":false,"guards":false,"primitive":false},"caveats":"Source tracing only; no dynamic reproducer."}
JSON

cat > "$recon_dir/validator-vote-2.json" <<'JSON'
{"vote":"Reject","rationale":"Curl_urldecode is internal; confirmed not exported.","verified":{"reachability":false}}
JSON

# ── T1: single-dir mode renders REPORT.md ────────────────────────────────
out=$(python3 "$RECON_REPORT" "$recon_dir" 2>&1) || true
assert_file_exists "$recon_dir/REPORT.md" "T1: REPORT.md written for a RECON dir"

# ── T2: REPORT.md content ────────────────────────────────────────────────
assert_file_contains "$recon_dir/REPORT.md" \
  "RECON-deadbeefcafe0001 — URL decoder allocates" "T2a: title heading present"
assert_file_contains "$recon_dir/REPORT.md" \
  "UNVERIFIED" "T2b: unverified-claim warning present"
# Location is target-relative — the absolute /home/x/.../targets/curl/
# prefix is stripped, leaving just the in-tree path.
assert_file_not_contains "$recon_dir/REPORT.md" \
  '/home/x/work/targets' "T2d: absolute path prefix stripped"
assert_file_contains "$recon_dir/REPORT.md" \
  'lib/escape.c:116' "T2e: relative file:line rendered"
assert_file_contains "$recon_dir/REPORT.md" \
  'Vote 1 — Reject' "T2f: validator vote 1 rendered"
assert_file_contains "$recon_dir/REPORT.md" \
  'Vote 2 — Reject' "T2g: validator vote 2 rendered"
assert_file_contains "$recon_dir/REPORT.md" \
  'No attacker-reachable path' "T2h: validator rationale included"
assert_file_contains "$recon_dir/REPORT.md" \
  'reachability=no' "T2i: verified checks rendered"

# ── T3: idempotency — second run produces identical output ───────────────
sum1=$(shasum "$recon_dir/REPORT.md" | awk '{print $1}')
python3 "$RECON_REPORT" "$recon_dir" >/dev/null 2>&1 || true
sum2=$(shasum "$recon_dir/REPORT.md" | awk '{print $1}')
assert_eq "$sum1" "$sum2" "T3: REPORT.md render is idempotent"

# ── T4: results-dir discovery mode finds recon/RECON-* ───────────────────
rm -f "$recon_dir/REPORT.md"
out=$(python3 "$RECON_REPORT" "$work/results" 2>&1) || true
assert_file_exists "$recon_dir/REPORT.md" "T4a: results-dir mode discovers recon/RECON-*"
assert_match "wrote 1 REPORT" "$out" "T4b: report count surfaced on stdout"

# ── T5: recon-root discovery mode ────────────────────────────────────────
rm -f "$recon_dir/REPORT.md"
python3 "$RECON_REPORT" "$work/results/recon" >/dev/null 2>&1 || true
assert_file_exists "$recon_dir/REPORT.md" "T5: recon/ root mode discovers RECON-*"

# ── T6: --no-html suppresses the HTML sibling ────────────────────────────
rm -f "$recon_dir/REPORT.md" "$recon_dir/REPORT.html"
python3 "$RECON_REPORT" "$recon_dir" --no-html >/dev/null 2>&1 || true
assert_file_exists "$recon_dir/REPORT.md" "T6a: --no-html still writes REPORT.md"
assert_file_not_exists "$recon_dir/REPORT.html" "T6b: --no-html skips REPORT.html"

# ── T7: missing path exits non-zero ──────────────────────────────────────
set +e
python3 "$RECON_REPORT" "$work/does-not-exist" >/dev/null 2>&1
rc=$?
set -e
assert_eq "1" "$rc" "T7: missing path argument exits 1"

# ── T8: a dir with no recon candidates is a no-op success ────────────────
empty=$(mktemp -d)
set +e
python3 "$RECON_REPORT" "$empty" >/dev/null 2>&1
rc=$?
set -e
rm -rf "$empty"
assert_eq "0" "$rc" "T8: empty dir is a clean no-op (exit 0)"

# ── T9: bin/audit-recon files RECON-* under recon/, not findings/ ────────
if grep -qE 'finding_dir="\$RESULTS_DIR/recon/\$fid"' "$SCRIPT_ROOT/bin/audit-recon"; then
  pass "T9a: audit-recon writes RECON dirs under recon/"
else
  fail "T9a: audit-recon writes RECON dirs under recon/" \
    "expected finding_dir to point at \$RESULTS_DIR/recon/\$fid"
fi
if grep -qE 'finding_dir="\$RESULTS_DIR/findings/\$fid"' "$SCRIPT_ROOT/bin/audit-recon"; then
  fail "T9b: audit-recon no longer files RECON dirs under findings/" \
    "stale findings/\$fid path still present"
else
  pass "T9b: audit-recon no longer files RECON dirs under findings/"
fi

# ── T10: optional strict-schema fields render when present ───────────────
rich_dir="$work/results/recon/RECON-deadbeefcafe0002"
mkdir -p "$rich_dir"
cat > "$rich_dir/finding.json" <<'JSON'
{"id":"RECON-deadbeefcafe0002","title":"rich row","file":"targets/x/a.c","line":5,"function":"f","class":"bounds","notes":"n","confidence":"NEEDS-VERIFICATION","reach_path":["entry","mid","sink"],"input_shape":"oversized header","guards_passed":["len>0","not-null"],"primitive":"oob-write","falsification":"tried small input, clean"}
JSON
python3 "$RECON_REPORT" "$rich_dir" --no-html >/dev/null 2>&1 || true
assert_file_contains "$rich_dir/REPORT.md" 'entry → mid → sink' "T10a: reach_path rendered"
assert_file_contains "$rich_dir/REPORT.md" 'oversized header' "T10b: input_shape rendered"
assert_file_contains "$rich_dir/REPORT.md" 'oob-write' "T10c: primitive rendered"
assert_file_contains "$rich_dir/REPORT.md" 'not run through the validation gate' \
  "T10d: missing-votes note rendered when no votes on disk"

summary
