#!/usr/bin/env bash
# tests/test_decision_cluster_expand.sh — crash-cluster expansion.
#
# After a CRASH lands, sibling hypotheses are routed into structured state
# (bin/state add-cluster-hyps) as PENDING leads owned by the crash's agent, and
# the dir is marked so a crash is expanded at most once. Covers: routing +
# ownership, idempotence, cross-crash dedup, disabled/no-frames/empty-rows
# marker semantics, agent clamping, the subcommand's own guards, and the
# parallel driver.

set -uo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$TESTS_DIR/helpers.sh"
source "$SCRIPT_ROOT/lib/llm_decide.sh"
source "$SCRIPT_ROOT/lib/triage.sh"

setup_test_env   # NUM_AGENTS=2

hyp_file="$RESULTS_DIR/state/hypotheses.jsonl"
migrated="$RESULTS_DIR/state/.cluster-expand-backlog-done"   # one-time migration sentinel
hyp_count() { [ -f "$hyp_file" ] && grep -c . "$hyp_file" 2>/dev/null || echo 0; }

mk_crash_with_frames() {
  local id="$1"
  local d="$RESULTS_DIR/crashes/$id"
  mkdir -p "$d"
  cat > "$d/asan-output.txt" <<EOF
==12345==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 8
    #0 0x100 in app_parse() src/foo/Foo.cpp:142
    #1 0x200 in app_dispatch() src/foo/Foo.cpp:88
    #2 0x300 in main() src/main.cpp:1
EOF
  echo "$d"
}

three_rows='{"rows":[
  {"file":"src/foo/Foo.cpp","function":"parseAlt","line":160,"hypothesis":"sibling parser shares the bound","category":"bounds"},
  {"file":"src/foo/Foo.cpp","function":"parseHeader","line":50,"hypothesis":"caller passes truncated len","category":"size"},
  {"file":"src/foo/Bar.cpp","function":"forward","line":12,"hypothesis":"forwarding skips the same check","category":"bounds"}
]}'

# 1. Rows route into structured state as PENDING hypotheses owned by the
#    crash's agent (suffix -2), strategy S5, sibling input shape. Marker written.
mk_crash_with_frames CRASH-014-2 >/dev/null
export LLM_DECIDE_MOCK_CLUSTER_EXPAND="$three_rows"
expand_cluster_for_crash "$RESULTS_DIR/crashes/CRASH-014-2" >/dev/null 2>&1
assert_file_exists "$RESULTS_DIR/crashes/CRASH-014-2/.cluster_expanded" "marker written"
assert_eq 3 "$(hyp_count)" "three siblings routed to hypotheses.jsonl"
assert_file_contains "$hyp_file" "parseAlt" "sibling 1 routed"
assert_file_contains "$hyp_file" "Bar.cpp:forward" "sibling 3 routed with folded file:function"
assert_file_contains "$hyp_file" '"agent": "2"' "owned by the crash's agent (suffix)"
assert_file_contains "$hyp_file" '"strategy": "S5"' "cluster strategy stamped"
assert_file_contains "$hyp_file" '"diagnostic": "bounds"' "canonical category is preserved, not over-normalized"
assert_file_contains "$hyp_file" '"input_shape": "sibling of CRASH-014-2"' "sibling provenance stamped"
assert_file_contains "$hyp_file" '"status": "PENDING"' "routed as a PENDING lead"

# 2. Idempotent: a second call on an already-marked dir adds nothing.
before=$(hyp_count)
expand_cluster_for_crash "$RESULTS_DIR/crashes/CRASH-014-2" >/dev/null 2>&1
assert_eq "$before" "$(hyp_count)" "idempotent: marked dir is not re-expanded"

# 3. Cross-crash dedup: a second crash in the same file yields the same
#    surfaces → nothing new is added, but the dir still marks (write succeeded).
mk_crash_with_frames CRASH-015-2 >/dev/null
expand_cluster_for_crash "$RESULTS_DIR/crashes/CRASH-015-2" >/dev/null 2>&1
assert_eq 3 "$(hyp_count)" "duplicate siblings from a sibling crash are deduped"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-015-2/.cluster_expanded" "deduped expansion still marks"
unset LLM_DECIDE_MOCK_CLUSTER_EXPAND

# 4. Disabled → no LLM call, no routing, no marker.
mk_crash_with_frames CRASH-020-1 >/dev/null
before=$(hyp_count)
LLM_DECIDE_DISABLE=1 expand_cluster_for_crash "$RESULTS_DIR/crashes/CRASH-020-1" >/dev/null 2>&1
assert_eq "$before" "$(hyp_count)" "disabled: nothing routed"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-020-1/.cluster_expanded" "disabled: no marker"

# 5. No top frames → no LLM call, no routing, no marker.
d="$RESULTS_DIR/crashes/CRASH-021-1"; mkdir -p "$d"
printf 'no frames here\n' > "$d/asan-output.txt"
export LLM_DECIDE_MOCK_CLUSTER_EXPAND="$three_rows"
before=$(hyp_count)
expand_cluster_for_crash "$d" >/dev/null 2>&1
assert_eq "$before" "$(hyp_count)" "no frames: nothing routed"
assert_file_not_exists "$d/.cluster_expanded" "no frames: no marker"

# 6. Valid empty rows → "no siblings" is a completed expansion: mark, add nothing.
mk_crash_with_frames CRASH-022-1 >/dev/null
export LLM_DECIDE_MOCK_CLUSTER_EXPAND='{"rows":[]}'
before=$(hyp_count)
expand_cluster_for_crash "$RESULTS_DIR/crashes/CRASH-022-1" >/dev/null 2>&1
assert_eq "$before" "$(hyp_count)" "empty rows: nothing routed"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-022-1/.cluster_expanded" "empty rows: marked (expansion complete)"

# 7. Agent clamp: a crash filed by an agent above the live NUM_AGENTS is owned
#    by a real agent (5 → ((5-1)%2)+1 = 1), never an agent that won't resume.
mk_crash_with_frames CRASH-030-5 >/dev/null
export LLM_DECIDE_MOCK_CLUSTER_EXPAND='{"rows":[{"file":"src/zeta/Q.cpp","function":"qux","line":9,"hypothesis":"clamp-owner sibling","category":"state"}]}'
expand_cluster_for_crash "$RESULTS_DIR/crashes/CRASH-030-5" >/dev/null 2>&1
assert_file_contains "$hyp_file" "clamp-owner sibling" "clamp case routed a sibling"
clamp_line=$(grep "clamp-owner sibling" "$hyp_file")
case "$clamp_line" in
  *'"agent": "1"'*) pass "out-of-range agent clamped into the live range" ;;
  *) fail "out-of-range agent clamped into the live range (got: $clamp_line)" ;;
esac
unset LLM_DECIDE_MOCK_CLUSTER_EXPAND

# 8. Subcommand guards directly: malformed stdin → exit 2 (dir would stay
#    unmarked); a well-formed empty payload → exit 0 with added=0.
state_bin="$SCRIPT_ROOT/bin/state"
printf 'not json\n' | "$state_bin" --results-dir "$RESULTS_DIR" \
  --target-slug "$TARGET_SLUG" --target-path "$TARGET_ROOT" \
  add-cluster-hyps --crash-id CRASH-099-1 >/dev/null 2>&1
assert_eq 2 "$?" "malformed stdin → exit 2"
out=$(printf '{"rows":[]}\n' | "$state_bin" --results-dir "$RESULTS_DIR" \
  --target-slug "$TARGET_SLUG" --target-path "$TARGET_ROOT" \
  add-cluster-hyps --crash-id CRASH-099-1 2>&1)
assert_eq 0 "$?" "empty payload → exit 0"
case "$out" in *"added=0"*) pass "empty payload reports added=0" ;; *) fail "empty payload reports added=0 (got: $out)" ;; esac

# 8b. Indexed-ids helper falls open on a present-but-empty index. grep's no-match
#     exit must not surface as a helper failure under pipefail, or the migration's
#     command substitution could abort under set -e.
rm -rf "$RESULTS_DIR"/crashes/CRASH-*
cat > "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" <<'EOF'
# Crash clusters
_(no crashes indexed yet)_
EOF
rc=0; out=$(_cluster_indexed_crash_ids) || rc=$?
assert_eq 0 "$rc" "indexed-ids helper succeeds on a present-but-empty index"
assert_eq "" "$out" "present-but-empty index yields no ids"

# 9. One-time backlog migration. Crashes indexed before the structured-state path
#    existed (indexed, but no .cluster_expanded marker) are marked once on the
#    first run without an LLM call — don't replay history. Exact-id match: a
#    longer indexed id (CRASH-039-10) must not mark a shorter crash (CRASH-039-1).
rm -rf "$RESULTS_DIR"/crashes/CRASH-* "$hyp_file" "$migrated"
mk_crash_with_frames CRASH-039-1 >/dev/null   # unindexed → must NOT be treated as backlog
mk_crash_with_frames CRASH-040-1 >/dev/null   # indexed at migration → backlog
cat > "$RESULTS_DIR/crashes/CRASH-CLUSTERS.md" <<'EOF'
# Crash clusters
- [CRASH-039-10](CRASH-039-10/REPORT.md)
- [CRASH-040-1](CRASH-040-1/REPORT.md)
EOF
before=$(hyp_count)
LLM_DECIDE_DISABLE=1 expand_clusters_for_new_crashes >/dev/null 2>&1
assert_file_exists "$migrated" "migration sentinel is written on the first run"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-040-1/.cluster_expanded" "pre-indexed backlog crash is marked without LLM"
assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-039-1/.cluster_expanded" "backlog migration matches exact crash IDs"
assert_eq "$before" "$(hyp_count)" "backlog crash adds no sibling hypotheses"

# 10. Crash-id reuse regression: ids are recycled once a higher-numbered crash is
#    rejected out of crashes/ (allocation is max+1 over current dirs). A new crash
#    that reuses a backlog id (CRASH-040-1) is a fresh dir with no marker, so it
#    must still expand — the migration marks physical dirs, never a permanent id
#    list that would suppress the reused id forever. Sentinel stays set (not reset).
rm -rf "$RESULTS_DIR"/crashes/CRASH-* "$hyp_file"
mk_crash_with_frames CRASH-040-1 >/dev/null   # fresh dir reusing a backlog id
export LLM_DECIDE_MOCK_CLUSTER_EXPAND='{"rows":[{"file":"src/foo/Foo.cpp","function":"decode","line":99,"hypothesis":"reused-id crash still expands","category":"bounds"}]}'
TRIAGE_DIR_PARALLEL=1 expand_clusters_for_new_crashes >/dev/null 2>&1
unset LLM_DECIDE_MOCK_CLUSTER_EXPAND
assert_file_exists "$RESULTS_DIR/crashes/CRASH-040-1/.cluster_expanded" "reused backlog crash id is expanded"
assert_eq 1 "$(hyp_count)" "reused backlog crash id routes a real sibling, not skipped as backlog"

# 11. Parallel driver: fresh crashes fan out for precompute, apply serially.
#    Every dir marks, no decision tmp is left behind, and identical siblings
#    across the batch dedupe to a single routed hypothesis.
rm -rf "$RESULTS_DIR"/crashes/CRASH-* "$hyp_file"
mk_crash_with_frames CRASH-041-1 >/dev/null
mk_crash_with_frames CRASH-042-1 >/dev/null
mk_crash_with_frames CRASH-043-1 >/dev/null
export LLM_DECIDE_MOCK_CLUSTER_EXPAND='{"rows":[{"file":"src/foo/Foo.cpp","function":"parseAlt","line":160,"hypothesis":"pool-driver sibling row","category":"bounds"}]}'
TRIAGE_DIR_PARALLEL=3 expand_clusters_for_new_crashes >/dev/null 2>&1
unset LLM_DECIDE_MOCK_CLUSTER_EXPAND
for n in 041 042 043; do
  assert_file_exists "$RESULTS_DIR/crashes/CRASH-$n-1/.cluster_expanded" "parallel driver expanded CRASH-$n-1"
  assert_file_not_exists "$RESULTS_DIR/crashes/CRASH-$n-1/.cluster_rows.json.tmp" "no leftover decision tmp for CRASH-$n-1"
done
assert_eq 1 "$(hyp_count)" "identical siblings across the batch dedupe to one routed lead"

# 12. Driver never re-expands. The original hang was housekeeping replaying
#     cluster_expand for the same crashes every pass; a second pass over
#     already-marked crashes must spend zero further LLM calls.
rm -rf "$RESULTS_DIR"/crashes/CRASH-* "$hyp_file"
mk_crash_with_frames CRASH-051-1 >/dev/null
mk_crash_with_frames CRASH-052-1 >/dev/null
calls="$RESULTS_DIR/expand_calls.log"; : > "$calls"
llm_decide() { echo x >> "$calls"; printf '%s' '{"rows":[{"file":"src/foo/Foo.cpp","function":"parseAlt","line":160,"hypothesis":"idempotence sibling","category":"bounds"}]}'; }
TRIAGE_DIR_PARALLEL=1 expand_clusters_for_new_crashes >/dev/null 2>&1
first=$(grep -c . "$calls")
TRIAGE_DIR_PARALLEL=1 expand_clusters_for_new_crashes >/dev/null 2>&1
second=$(grep -c . "$calls")
# Restore the real llm_decide (later env-mock tests depend on it); a bare
# unset -f would delete the sourced function, not just this stub.
unset -f llm_decide; source "$SCRIPT_ROOT/lib/llm_decide.sh"
assert_eq 2 "$first"  "first pass expands each new crash exactly once"
assert_eq 2 "$second" "second pass over marked crashes spends zero further LLM calls"

# 13. add-cluster-hyps never blocks on an interactive stdin: with stdin left as
#     the controlling terminal it must fail fast (rc 2), not hang waiting for EOF.
if { : </dev/tty; } 2>/dev/null; then
  rc=0
  "$SCRIPT_ROOT/bin/state" --results-dir "$RESULTS_DIR" \
    --target-slug "$TARGET_SLUG" --target-path "$TARGET_ROOT" \
    add-cluster-hyps --crash-id CRASH-051-1 </dev/tty >/dev/null 2>&1 || rc=$?
  assert_eq 2 "$rc" "interactive stdin is rejected, not blocked"
else
  pass "interactive stdin guard (skipped: no controlling tty)"
fi

# 14. A non-canonical category never discards a real sibling, but it also never
#     leaks into structured state: the row with a valid file+hypothesis is routed
#     (kept) and the crash marks expanded, while the off-taxonomy label (here a
#     sanitizer-class term) is folded to the canonical "state" bucket.
rm -rf "$RESULTS_DIR"/crashes/CRASH-* "$hyp_file"
mk_crash_with_frames CRASH-060-1 >/dev/null
export LLM_DECIDE_MOCK_CLUSTER_EXPAND='{"rows":[{"file":"src/foo/Foo.cpp","function":"decode","line":77,"hypothesis":"peer decoder shares the unchecked length","category":"heap-buffer-overflow"}]}'
expand_cluster_for_crash "$RESULTS_DIR/crashes/CRASH-060-1" >/dev/null 2>&1
unset LLM_DECIDE_MOCK_CLUSTER_EXPAND
assert_eq 1 "$(hyp_count)" "off-taxonomy category is kept, not dropped"
assert_file_contains "$hyp_file" "peer decoder shares the unchecked length" "the real sibling is routed"
assert_file_contains "$hyp_file" '"diagnostic": "state"' "off-taxonomy label is normalized to the canonical state bucket"
assert_file_not_contains "$hyp_file" "heap-buffer-overflow" "off-taxonomy label does not leak into structured state"
assert_file_exists "$RESULTS_DIR/crashes/CRASH-060-1/.cluster_expanded" "crash marks expanded once the sibling is routed"

# 15. Strategy attribution: when the crash came from a structured hypothesis,
#     sibling leads inherit that producing strategy instead of skewing ROI to the
#     cluster-expansion fallback.
rm -rf "$RESULTS_DIR"/crashes/CRASH-* "$hyp_file"
mkdir -p "$RESULTS_DIR/state"
printf '%s\n' '{"id":"H-origin","agent":"1","card_id":"WORK-origin","hypothesis":"origin","file":"src/foo/Foo.cpp:app_parse:142","input_shape":"bytes","guard_gap":"missing check","diagnostic":"bounds","strategy":"S2","status":"CRASH-070-1","created_at":"2026-06-01T00:00:00Z","updated_at":"2026-06-01T00:00:00Z"}' \
  > "$hyp_file"
mk_crash_with_frames CRASH-070-1 >/dev/null
export LLM_DECIDE_MOCK_CLUSTER_EXPAND='{"rows":[{"file":"src/foo/Foo.cpp","function":"parseNext","line":190,"hypothesis":"strategy inheritance sibling","category":"bounds"}]}'
expand_cluster_for_crash "$RESULTS_DIR/crashes/CRASH-070-1" >/dev/null 2>&1
unset LLM_DECIDE_MOCK_CLUSTER_EXPAND
assert_file_contains "$hyp_file" "strategy inheritance sibling" "origin-strategy case routed a sibling"
strategy_line=$(grep "strategy inheritance sibling" "$hyp_file")
case "$strategy_line" in
  *'"strategy": "S2"'*) pass "cluster sibling inherits origin strategy for ROI attribution" ;;
  *) fail "cluster sibling inherits origin strategy for ROI attribution (got: $strategy_line)" ;;
esac

# 16. Timeout floor: cluster_expand investigates the tree and runs far longer
#     than the classification gates, so _cluster_expand_decide sends a ceiling
#     well above the shared default — while still honoring a higher operator value.
mk_crash_with_frames CRASH-050-1 >/dev/null
llm_decide() { echo "timeout=$3"; }   # stub: echo the timeout arg it was handed
LLM_DECISION_TIMEOUT=45 \
  got=$(_cluster_expand_decide "$RESULTS_DIR/crashes/CRASH-050-1")
assert_eq "timeout=600" "$got" "shared default is floored to 600 for cluster_expand"
LLM_DECISION_TIMEOUT=900 \
  got=$(_cluster_expand_decide "$RESULTS_DIR/crashes/CRASH-050-1")
assert_eq "timeout=900" "$got" "a higher operator override still wins over the floor"
unset -f llm_decide

# 17. _triage_decision_timeout floors: agentic gates read the report/tree before
#     voting; non-reading gates keep the base; a higher operator value wins.
LLM_DECISION_TIMEOUT=45
assert_eq 600 "$(_triage_decision_timeout cluster_expand)" "cluster_expand floors to 600"
assert_eq 180 "$(_triage_decision_timeout crash_confirm)"  "crash_confirm floors to 180"
assert_eq 180 "$(_triage_decision_timeout legit_crash)"    "legit_crash floors to 180"
assert_eq 45  "$(_triage_decision_timeout crash_triage)"   "crash_triage keeps the base timeout (no floor)"
assert_eq 45  "$(_triage_decision_timeout find_quality)"   "find_quality keeps the base timeout (no floor)"
LLM_DECISION_TIMEOUT=300
assert_eq 300 "$(_triage_decision_timeout crash_confirm)"  "operator timeout above the floor still wins"

teardown_test_env
summary
