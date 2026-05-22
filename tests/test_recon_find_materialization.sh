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

# ── 12. Mechanical dedup: agent-filed FIND with same (file,function) ──
# moves to findings-rejected/ on the next validate sweep. This is the
# guarantee the prompt instruction alone cannot make: if an agent
# ignores the augment-don't-refile rule and files a fresh FIND-NNN-*
# for a defect that already has a FIND-RECON-*, the headline count
# stays bounded.
dedup_dir=$(mktemp -d)
dedup_results="$dedup_dir/results"
mkdir -p "$dedup_results/findings"

# Recon-materialized FIND (the canonical record). Carries canonical
# Location and Issue class — both required by the (file, function,
# class) dedup signature.
recon_find="$dedup_results/findings/FIND-RECON-aaaaaaaaaa-uaf-end-query"
mkdir -p "$recon_find"
cat > "$recon_find/report.md" <<MD
# UAF when callback frees query

## Location

\`src/lib/proc.c:end_query:1477\`

## Classification

- **Class**: UAF
MD

# Agent-filed FIND for the SAME (file, function, class) — should be moved.
agent_dup="$dedup_results/findings/FIND-007-also-uaf"
mkdir -p "$agent_dup"
cat > "$agent_dup/report.md" <<MD
# Duplicate UAF in end_query

The deferred callback in src/lib/proc.c frees the query state, but
end_query keeps dereferencing it. ASan reproducer attached.

## Location

\`src/lib/proc.c:end_query:1477\`

## Classification

- **Class**: UAF
MD

# Agent-filed FIND for a DIFFERENT defect — should NOT be moved.
agent_unique="$dedup_results/findings/FIND-008-distinct-overflow"
mkdir -p "$agent_unique"
cat > "$agent_unique/report.md" <<MD
# Integer overflow in size calculation

## Location

\`src/lib/alloc.c:compute_size:88\`

## Classification

- **Class**: integer-overflow
MD

# Operator-pinned FIND (also same signature) — must NOT be moved.
agent_pinned="$dedup_results/findings/FIND-009-pinned-dup"
mkdir -p "$agent_pinned"
cat > "$agent_pinned/report.md" <<MD
# Pinned duplicate

## Location

\`src/lib/proc.c:end_query:1477\`

## Classification

- **Class**: UAF
MD
touch "$agent_pinned/.keep"

python3 lib/recon_to_cards.py --dedupe-only \
  --results-dir "$dedup_results" --quiet

if [ ! -d "$agent_dup" ] && [ -d "$dedup_results/findings-rejected/FIND-007-also-uaf" ]; then
  pass "agent-filed duplicate moved to findings-rejected/ (mechanical dedup)"
else
  fail "agent-filed duplicate was NOT moved (recon FIND should win)"
fi
if [ -d "$recon_find" ]; then
  pass "recon-materialized FIND stays canonical (not moved)"
else
  fail "recon-materialized FIND got moved — should never happen"
fi
if [ -d "$agent_unique" ]; then
  pass "agent-filed unique FIND survives dedup (different signature)"
else
  fail "agent-filed unique FIND incorrectly moved"
fi
if [ -d "$agent_pinned" ]; then
  pass "operator-pinned (.keep) duplicate is left alone"
else
  fail ".keep duplicate was moved — operator pin must be respected"
fi
# Audit trail: the moved dir carries .duplicate-of-recon sentinel
moved_path="$dedup_results/findings-rejected/FIND-007-also-uaf"
if [ -s "$moved_path/.duplicate-of-recon" ]; then
  pass "moved dir carries .duplicate-of-recon sentinel for audit trail"
else
  fail "moved dir missing audit-trail sentinel"
fi
assert_file_contains "$moved_path/.duplicate-of-recon" \
  "FIND-RECON-aaaaaaaaaa-uaf-end-query" \
  "sentinel names the canonical FIND-RECON-*"

# Re-run is a no-op (idempotent)
ls_before=$(ls "$dedup_results/findings/" "$dedup_results/findings-rejected/" 2>/dev/null | sort)
python3 lib/recon_to_cards.py --dedupe-only \
  --results-dir "$dedup_results" --quiet
ls_after=$(ls "$dedup_results/findings/" "$dedup_results/findings-rejected/" 2>/dev/null | sort)
assert_eq "$ls_before" "$ls_after" "dedup re-run is idempotent (no further moves)"

# Without ANY recon-materialized FIND, dedup is a no-op even with
# duplicate-shaped reports — the canonical authority is recon, not
# "first to file wins".
empty_recon_dir=$(mktemp -d)
mkdir -p "$empty_recon_dir/findings"
mkdir -p "$empty_recon_dir/findings/FIND-010-no-recon-equivalent"
cat > "$empty_recon_dir/findings/FIND-010-no-recon-equivalent/report.md" <<MD
# Some agent finding

## Location

\`src/x.c:f:1\`

## Classification

- **Class**: UAF
MD
python3 lib/recon_to_cards.py --dedupe-only \
  --results-dir "$empty_recon_dir" --quiet
if [ -d "$empty_recon_dir/findings/FIND-010-no-recon-equivalent" ]; then
  pass "no recon FINDs ⇒ dedup is a no-op (agent FINDs untouched)"
else
  fail "dedup wrongly moved an agent FIND when no recon FIND exists"
fi
rm -rf "$empty_recon_dir"

# ── 13. validate_find_gate invokes the dedup sweep ─────────────────────
if grep -qE 'recon_to_cards\.py[^[:space:]]*[[:space:]]+--dedupe-only' "$SCRIPT_ROOT/lib/triage.sh"; then
  pass "validate_find_gate calls recon_to_cards.py --dedupe-only"
else
  fail "validate_find_gate not wired to invoke dedup sweep"
fi

rm -rf "$dedup_dir"

# ── 14. Class-aware dedup: distinct bug classes in same function ──────
# Capability-preservation test: if recon names a UAF on parse_packet
# and an agent independently finds an integer-overflow ALSO in
# parse_packet, the dedup must NOT collapse them. Without class in
# the signature this would actively HIDE a real bug.
class_dir=$(mktemp -d)
class_results="$class_dir/results"
mkdir -p "$class_results/findings"

# Recon-materialized: UAF in parse_packet. Uses canonical Location +
# Issue class line so finding_signature.extract_class can pick it up.
class_recon="$class_results/findings/FIND-RECON-bbbbbbbbbb-uaf-parse-packet"
mkdir -p "$class_recon"
cat > "$class_recon/report.md" <<MD
# UAF in parse_packet

## Location

\`src/lib/net.c:parse_packet:100\`

## Classification

- **Class**: UAF
MD

# Agent-filed: integer overflow in the SAME function but DIFFERENT class.
# Must survive the dedup sweep — it's a distinct security defect.
class_agent="$class_results/findings/FIND-099-intover-parse-packet"
mkdir -p "$class_agent"
cat > "$class_agent/report.md" <<MD
# Integer overflow in parse_packet length calc

## Location

\`src/lib/net.c:parse_packet:150\`

## Classification

- **Class**: integer-overflow
MD

# Agent-filed: ALSO a UAF in parse_packet (true duplicate; same class).
# Must be moved — class matches AND function matches AND file matches.
class_agent_dup="$class_results/findings/FIND-100-uaf-parse-packet-dup"
mkdir -p "$class_agent_dup"
cat > "$class_agent_dup/report.md" <<MD
# Another UAF in parse_packet

## Location

\`src/lib/net.c:parse_packet:100\`

## Classification

- **Class**: UAF
MD

python3 lib/recon_to_cards.py --dedupe-only \
  --results-dir "$class_results" --quiet

if [ -d "$class_agent" ]; then
  pass "distinct class (int-overflow vs UAF) in same function survives dedup"
else
  fail "CAPABILITY REGRESSION: distinct bug class was wrongly moved by dedup"
fi
if [ ! -d "$class_agent_dup" ] && \
    [ -d "$class_results/findings-rejected/FIND-100-uaf-parse-packet-dup" ]; then
  pass "true duplicate (same class + function) is still moved"
else
  fail "true duplicate not deduped: dedup is over-conservative now"
fi
if [ -d "$class_recon" ]; then
  pass "recon FIND stays canonical even with class-aware signature"
else
  fail "recon FIND was incorrectly moved"
fi

rm -rf "$class_dir"

# ── 15. Materialized report carries an extractable Issue class ────────
# The dedup sweep's recon-side signature needs file+function+class. If
# materialize_find ever stops emitting a parseable class line, every
# subsequent dedup pass silently degrades to "no class → no match" and
# the augment-don't-refile guarantee evaporates.
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
