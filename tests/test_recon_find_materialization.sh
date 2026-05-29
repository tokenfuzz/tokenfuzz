#!/usr/bin/env bash
# Tests for lib/recon_to_cards.py FIND materialization (root-cause fix
# for benchmark undercount: every non-AUDIT-CLEAN recon row that names a
# concrete defect at file:function:line gets a FIND-RECON-* dir at card-
# generation time so the benchmark count no longer depends on whether
# the linked work card was claimed or whether ASan reproduced a crash).
#
# Properties under test:
#   1. Non-Promote recon rows with full fields materialize a FIND under
#      findings/ and emit cards with find_id pointing at it.
#   2. validator_verdict == "reject" skips materialization entirely.
#      The work card still flows; agent can file from scratch if a probe
#      proves the validator wrong. This avoids: (a) inflating
#      findings_rejected metric across the change boundary, (b) burying
#      a sanitizer-confirmed bug in findings-rejected/, (c) prompt
#      paths that point at the wrong bucket.
#   3. AUDIT-CLEAN rows produce no FIND and no card.
#   4. Field-incomplete rows (missing function/line/notes/class) produce
#      a card but no FIND and no find_id.
#   5. Re-running recon_to_cards is idempotent: same FIND id, report.md
#      is not overwritten (an agent augmentation between runs survives).
#   6. Without --results-dir (back-compat caller), no FINDs are
#      materialized and no card carries find_id.
#   7. Multi-sanitizer fan-out shares one find_id across cards.
#   8. Dedup signature includes class — distinct bug classes in the
#      same function do NOT collapse, preserving bug-finding capability
#      when a function harbors multiple distinct defects.

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$TESTS_DIR/helpers.sh"

setup_test_env
trap 'teardown_test_env 2>/dev/null || true' EXIT

cd "$SCRIPT_ROOT"

# ── Shared fixture: a recon JSONL covering every routing branch ────────
tmp=$(mktemp -d)
recon_jsonl="$tmp/recon-hypotheses.jsonl"
work_cards="$tmp/work-cards.jsonl"
results_dir="$tmp/results"
target_path="/synthetic/target"
mkdir -p "$results_dir"

cat > "$recon_jsonl" <<JSONL
{"id":"REC-promote-uaf","slice":"slice-1","title":"UAF when callback frees query","file":"$target_path/src/lib/proc.c","line":1477,"function":"end_query","class":"UAF","notes":"Deferred callback frees query state but caller still dereferences it on the next loop iteration.","confidence":"CONFIRMED-HIGH","validator_verdict":"Promote","validator_details":"deep-validator: verdict=Promote votes=2/2"}
{"id":"REC-needsver-intover","slice":"slice-2","title":"size_t multiplication wraps to 0","file":"$target_path/src/lib/record/rec.c","line":1249,"function":"set_bin","class":"integer-overflow","notes":"len * sizeof(struct) wraps on 32-bit count, allocator returns small buffer.","confidence":"NEEDS-VERIFICATION"}
{"id":"REC-reject-bson","slice":"slice-3","title":"BSON document size not validated","file":"$target_path/src/lib/json.hpp","line":10127,"function":"parse_bson_internal","class":"protocol-state","notes":"BSON document_size is read and discarded; under-declared lengths parsed by scanning until zero element.","confidence":"NEEDS-VERIFICATION","validator_verdict":"Reject","validator_details":"deep-validator: verdict=Reject votes=0/2"}
{"id":"REC-uncertain-leak","slice":"slice-4","title":"cookie key collision","file":"$target_path/src/lib/cache.c","line":125,"function":"key","class":"info-leak","notes":"Delimiter-based key concatenation lets a crafted hostname collide with a cookie-bearing entry.","confidence":"CONFIRMED-MEDIUM","validator_verdict":"Uncertain"}
{"id":"REC-sparse-noline","slice":"slice-5","title":"missing line","file":"$target_path/src/lib/sparse.c","function":"f","class":"UAF","notes":"present","confidence":"NEEDS-VERIFICATION"}
{"id":"REC-sparse-nofn","slice":"slice-6","title":"missing function","file":"$target_path/src/lib/sparse.c","line":10,"class":"UAF","notes":"present","confidence":"NEEDS-VERIFICATION"}
{"id":"REC-sparse-nonotes","slice":"slice-7","title":"missing notes","file":"$target_path/src/lib/sparse.c","line":10,"function":"f","class":"UAF","confidence":"NEEDS-VERIFICATION"}
{"id":"REC-audit-clean","slice":"slice-8","confidence":"AUDIT-CLEAN","notes":"nothing here"}
JSONL

run_with_results_dir() {
  python3 lib/recon_to_cards.py \
    --target-slug testproject \
    --target-path "$target_path" \
    --recon-jsonl "$recon_jsonl" \
    --work-cards "$work_cards" \
    --results-dir "$results_dir" --quiet
}

run_with_results_dir

# ── Helpers ────────────────────────────────────────────────────────────
find_id_for_rec() {
  python3 -c "
import json, sys
target = sys.argv[1]
for line in open('$work_cards'):
    line = line.strip()
    if not line: continue
    c = json.loads(line)
    if c.get('recon', {}).get('id') == target:
        print(c.get('find_id', ''))
        break
" "$1"
}

count_cards_for_rec() {
  python3 -c "
import json, sys
target = sys.argv[1]
n = 0
for line in open('$work_cards'):
    line = line.strip()
    if not line: continue
    c = json.loads(line)
    if c.get('recon', {}).get('id') == target:
        n += 1
print(n)
" "$1"
}

# ── 1. Promote row materializes a FIND under findings/ ─────────────────
promote_find=$(find_id_for_rec REC-promote-uaf)
if [ -n "$promote_find" ]; then
  pass "Promote row gets find_id: $promote_find"
else
  fail "Promote row missing find_id on emitted card"
fi
if [ -d "$results_dir/findings/$promote_find" ] \
    && [ -s "$results_dir/findings/$promote_find/report.md" ]; then
  pass "Promote row materializes findings/$promote_find/report.md"
else
  fail "Promote row did NOT create $results_dir/findings/$promote_find/report.md"
fi
# report.md must carry the actual recon content so the LLM-quality gate
# and validator quorum have something substantive to judge.
report="$results_dir/findings/$promote_find/report.md"
assert_file_contains "$report" "UAF when callback frees query" "report carries recon title"
assert_file_contains "$report" "end_query" "report carries function"
assert_file_contains "$report" "1477" "report carries line"
assert_file_contains "$report" "REC-promote-uaf" "report carries recon id"
assert_file_contains "$report" "validator verdict: Promote" "report records validator verdict"

# ── 2. NEEDS-VERIFICATION (no validator verdict) ALSO materializes ─────
# This is the core fix — pre-fix this row would only emit work cards
# and a benchmark count of FIND-* would miss it entirely.
ver_find=$(find_id_for_rec REC-needsver-intover)
if [ -n "$ver_find" ] && [ -d "$results_dir/findings/$ver_find" ]; then
  pass "NEEDS-VERIFICATION row materializes a FIND ($ver_find)"
else
  fail "NEEDS-VERIFICATION row failed to materialize (got find_id='$ver_find')"
fi

# ── 3. Uncertain validator verdict still materializes under findings/ ──
unc_find=$(find_id_for_rec REC-uncertain-leak)
if [ -n "$unc_find" ] && [ -d "$results_dir/findings/$unc_find" ]; then
  pass "Uncertain-verdict row materializes under findings/ ($unc_find)"
else
  fail "Uncertain-verdict row failed to materialize (got find_id='$unc_find')"
fi

# ── 4. Reject row: NO FIND materialized; work card still emitted ──────
# Validator-Reject is a substantive negative judgment. Materializing
# would (a) inflate the findings_rejected metric across the change
# boundary, (b) bury a sanitizer-confirmed bug in findings-rejected/
# if the agent later proves the validator wrong, (c) point the agent
# prompt at the wrong bucket. Better: skip FIND, keep work card so
# the agent can file from scratch if probe confirms.
reject_find=$(find_id_for_rec REC-reject-bson)
n_reject=$(count_cards_for_rec REC-reject-bson)
if [ -z "$reject_find" ] && [ "$n_reject" -gt 0 ]; then
  pass "Reject row emits cards ($n_reject) but no find_id (skip-Reject policy)"
else
  fail "Reject row: expected cards>0 and no find_id; got cards=$n_reject find_id='$reject_find'"
fi
if ls -d "$results_dir/findings/"FIND-RECON-*bson* >/dev/null 2>&1 \
    || ls -d "$results_dir/findings-rejected/"FIND-RECON-*bson* >/dev/null 2>&1; then
  fail "Reject row materialized a FIND somewhere — should be skipped entirely"
else
  pass "Reject row materializes no FIND in findings/ or findings-rejected/"
fi

# ── 5. Field-incomplete rows: cards yes, FIND no, find_id no ───────────
for rec in REC-sparse-noline REC-sparse-nofn REC-sparse-nonotes; do
  n=$(count_cards_for_rec "$rec")
  fid=$(find_id_for_rec "$rec")
  if [ "$n" -gt 0 ] && [ -z "$fid" ]; then
    pass "$rec: emits cards ($n) but no find_id (sparse-field gate)"
  else
    fail "$rec: expected cards>0 and no find_id; got cards=$n find_id='$fid'"
  fi
done

# ── 6. AUDIT-CLEAN rows produce nothing ────────────────────────────────
n_clean=$(count_cards_for_rec REC-audit-clean)
assert_eq "$n_clean" "0" "AUDIT-CLEAN row produces no cards"
if ls "$results_dir/findings/"FIND-RECON-*-nothing* >/dev/null 2>&1 \
    || ls "$results_dir/findings/"FIND-RECON-*audit-clean* >/dev/null 2>&1; then
  fail "AUDIT-CLEAN row leaked a FIND dir"
else
  pass "AUDIT-CLEAN row materializes no FIND"
fi

# ── 7. Multi-sanitizer fan-out shares ONE find_id per recon row ────────
# A NEEDS-VERIFICATION row with 2 sanitizers × 2 strategies = 4 cards,
# all carrying the SAME find_id (they augment the same FIND).
multi_dir=$(mktemp -d)
multi_jsonl="$multi_dir/r.jsonl"
multi_cards="$multi_dir/work-cards.jsonl"
multi_results="$multi_dir/results"
mkdir -p "$multi_results"
cat > "$multi_jsonl" <<JSONL
{"id":"REC-multi","title":"size mul wrap","file":"$target_path/src/x.c","line":42,"function":"alloc","class":"integer-overflow","notes":"size_t mul wraps","confidence":"NEEDS-VERIFICATION"}
JSONL
python3 lib/recon_to_cards.py \
  --target-slug testproject --target-path "$target_path" \
  --recon-jsonl "$multi_jsonl" --work-cards "$multi_cards" \
  --results-dir "$multi_results" --sanitizers "asan,ubsan" --quiet
distinct_find_ids=$(python3 -c "
import json
ids = set()
for line in open('$multi_cards'):
    line = line.strip()
    if not line: continue
    c = json.loads(line)
    if c.get('recon', {}).get('id') == 'REC-multi':
        ids.add(c.get('find_id', ''))
print(len(ids), '|', ','.join(sorted(ids)))
")
distinct_count=$(printf '%s' "$distinct_find_ids" | awk -F'\\|' '{print $1}' | tr -d ' ')
assert_eq "$distinct_count" "1" "multi-sanitizer fan-out maps to ONE find_id ($distinct_find_ids)"
dir_count=$(ls -d "$multi_results"/findings/FIND-RECON-* 2>/dev/null | wc -l | tr -d ' ')
assert_eq "$dir_count" "1" "multi-sanitizer fan-out creates ONE FIND dir"
rm -rf "$multi_dir"

# ── 8. Idempotence — re-run preserves report.md and dir id ─────────────
# Simulate an agent augmenting report.md between recon runs. The second
# recon_to_cards invocation must NOT overwrite the augmentation.
echo "" >> "$report"
echo "## Sanitizer evidence (agent-added)" >> "$report"
echo "ASan output redacted for test." >> "$report"
augmented_sha_before=$(shasum "$report" | awk '{print $1}')

run_with_results_dir
# Re-run must produce the same find_id for the same recon row.
promote_find_again=$(find_id_for_rec REC-promote-uaf)
assert_eq "$promote_find" "$promote_find_again" "find_id is stable across re-runs"
augmented_sha_after=$(shasum "$report" | awk '{print $1}')
assert_eq "$augmented_sha_before" "$augmented_sha_after" \
  "agent augmentation in report.md survives a recon_to_cards re-run"

# ── 9. Back-compat: no --results-dir ⇒ no FINDs, no find_id on cards ──
nodir_cards="$tmp/work-cards-nodir.jsonl"
python3 lib/recon_to_cards.py \
  --target-slug testproject --target-path "$target_path" \
  --recon-jsonl "$recon_jsonl" --work-cards "$nodir_cards" --quiet
has_any_find_id=$(python3 -c "
import json
for line in open('$nodir_cards'):
    line = line.strip()
    if not line: continue
    c = json.loads(line)
    if c.get('find_id'):
        print('yes'); break
else:
    print('no')
")
assert_eq "$has_any_find_id" "no" "no --results-dir ⇒ no find_id on any card (back-compat)"

# ── 10. bin/audit wires --results-dir through to recon_to_cards.py ────
if grep -q -- '--results-dir "$RESULTS_DIR"' "$SCRIPT_ROOT/bin/audit"; then
  pass "bin/audit passes --results-dir to recon_to_cards.py"
else
  fail "bin/audit missing --results-dir flag in _seed_cards_from_recon"
fi

# ── 11. prompt.sh renders the PRE-FILED FIND block when find_id set ───
if grep -qF "PRE-FILED FIND" "$SCRIPT_ROOT/lib/prompt.sh" \
    && grep -qF "find_id" "$SCRIPT_ROOT/lib/prompt.sh"; then
  pass "lib/prompt.sh renders PRE-FILED FIND augment-don't-refile contract"
else
  fail "lib/prompt.sh missing PRE-FILED FIND block for find_id-bearing cards"
fi
if grep -qF "PRE-FILED FIND" "$SCRIPT_ROOT/lib/prompts/find_first_directive.md.j2"; then
  pass "find_first_directive carves out the pre-filed FIND case"
else
  fail "find_first_directive missing PRE-FILED FIND exception"
fi

# ── 11b. Materialized report.md uses canonical Location form ──────────
# The dedup sweep's recon-side index is populated by running
# finding_signature.extract_location over each FIND-RECON-* report.md.
# If the materialized report doesn't produce a usable (file, function)
# tuple, no dedup will ever fire — guarding against a silent regression.
canonical_check=$(python3 -c "
import sys
sys.path.insert(0, 'lib')
from finding_signature import extract_location
text = open('$report').read()
f, fn = extract_location(text, '')
print('|'.join([f, fn]))
")
canonical_file="${canonical_check%|*}"
canonical_func="${canonical_check#*|}"
if [ -n "$canonical_file" ] && [ -n "$canonical_func" ]; then
  pass "materialized report parses canonically via finding_signature.extract_location: $canonical_check"
else
  fail "materialized report.md missing file or function in canonical extraction: '$canonical_check'"
fi

rm -rf "$tmp"

# ── 12. Materialized report carries an extractable Issue class ────────
# Clustering keys on (class, file, func) when a finding has no dedup_key, so
# materialize_find must keep emitting a parseable class line; if it stops, the
# class silently degrades to "other" and same-class findings stop bucketing.
issue_class_check=$(python3 -c "
import sys
sys.path.insert(0, 'lib')
from finding_signature import extract_class, normalize_class
import recon_to_cards as rtc
finding = {
    'id':'REC-x','title':'Sample','file':'src/x.c','line':1,
    'function':'f','class':'UAF','notes':'demo',
    'confidence':'NEEDS-VERIFICATION',
}
text = rtc._render_find_report(finding, 'src/x.c', 1, 'tp')
raw = extract_class(text)
norm = normalize_class(raw) if raw else ''
print(f'{raw}|{norm}')
")
raw_class="${issue_class_check%|*}"
norm_class="${issue_class_check#*|}"
if [ -n "$raw_class" ] && [ -n "$norm_class" ]; then
  pass "materialized report emits parseable Issue class (raw=$raw_class norm=$norm_class)"
else
  fail "materialized report missing parseable class — dedup would silently degrade"
fi

summary
