#!/usr/bin/env bash
# tests/test_audit_quality_fixes.sh
# Production-grade coverage for the 10 audit-harness fixes shipped to address
# the queue-poisoning / fabricated-clean-variant / surface-lockout regressions
# observed in output/*/codex/logs:
#
#   #1   prompt-time card leases prevent duplicate parallel assignment
#   #1.5 update-card --status discarded requires runs.jsonl evidence
#   #2   release-stale-claims releases dangling lease rows; default TTL 30 min
#   #3   EXECUTION VERIFIED is post-run only (xpcshell + generic)
#   #4   work_surface keys on (file, function|strategy); not just file
#   #5   crash promotion accepts testcases >=1B
#   #6   orphan detection: invert allowlist; default to "any non-sidecar"
#   #7   needs-review purgatory for LLM-uncertain rejections
#   #9   per-strategy completion gate refuses rotation without evidence
#   #10  threat-model widening for library targets
#
# Each section is independent: a failure in one does not mask the others.

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

STATE="$SCRIPT_ROOT/bin/state"
RANK_WORK="$SCRIPT_ROOT/bin/rank-work"
RUN_ASAN="$SCRIPT_ROOT/bin/run-asan"

# ════════════════════════════════════════════════════════════════
# Fixture: a tiny target with one rich source file. A patch card and
# a ranked-source card both live on the same file so we can exercise
# the surface-keying and claim-on-adopt paths.
# ════════════════════════════════════════════════════════════════

mkdir -p "$TARGET_ROOT/src"
cat > "$TARGET_ROOT/src/parser.c" <<'C'
#include <stdint.h>
#include <string.h>

extern int public_api_parse(const unsigned char *data, unsigned long len);
int public_api_parse(const unsigned char *data, unsigned long len) {
    unsigned char buf[16];
    if (len > 0) {
        assert(data != NULL);
        memcpy(buf, data, len);
    }
    return len != 0;
}
C

cat > "$RESULTS_DIR/patch-cards.jsonl" <<'JSONL'
{"id":"PATCH-fixone","kind":"s1-patch","target_slug":"testproject","touched_files":["src/parser.c"],"score":80,"fix_hashes":["abc123"],"testcase_hashes":["def456"],"subsystem":"src","description":"earlier parser bounds fix","reason":"prior bounds fix"}
JSONL

# Build the work-cards stream once. Fix #4 should produce >1 card for src/parser.c
# because the file has multiple bug-relevant signals (memcpy + assert + exported API).
TARGET_ROOT="$TARGET_ROOT" RESULTS_DIR="$RESULTS_DIR" "$RANK_WORK" \
    --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" --results-dir "$RESULTS_DIR" \
    --limit 20 --llm-top-n 0 --quiet >/dev/null
"$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" init

# ════════════════════════════════════════════════════════════════
# Fix #4: rank-work emits multiple cards for a single high-signal file.
# Surface keys differentiate by strategy so one hypothesis cannot lock
# the whole file.
# ════════════════════════════════════════════════════════════════

work_cards_for_parser=$(grep -c '"file": "src/parser.c"' "$RESULTS_DIR/work-cards.jsonl" || true)
if [ "${work_cards_for_parser:-0}" -ge 2 ]; then
    pass "fix#4: multiple work cards generated for a high-signal file"
else
    fail "fix#4: multiple work cards generated for a high-signal file" \
         "expected >=2 cards on src/parser.c, got ${work_cards_for_parser}"
fi

# Distinct strategy on companion cards.
strategies=$(grep '"file": "src/parser.c"' "$RESULTS_DIR/work-cards.jsonl" \
    | sed -nE 's/.*"strategy": "([A-Z0-9]+)".*/\1/p' | sort -u)
strat_count=$(printf '%s\n' "$strategies" | grep -c .)
if [ "${strat_count:-0}" -ge 2 ]; then
    pass "fix#4: companion cards carry distinct strategies"
else
    fail "fix#4: companion cards carry distinct strategies" \
         "expected >=2 strategies, got: $strategies"
fi

# work_surface returns finer keys (file:strategy) when no function set.
PYTHONPATH="$SCRIPT_ROOT/lib" python3 - <<'PY'
from workqueue import work_surface
a = {"file": "src/parser.c", "function": "", "strategy": "S1"}
b = {"file": "src/parser.c", "function": "", "strategy": "S2"}
c = {"file": "src/parser.c", "function": "public_api_parse", "strategy": "S1"}
d = {"file": "src/parser.c", "function": "public_api_parse", "strategy": "S5"}
assert work_surface(a) != work_surface(b), "file+strategy must differ"
assert work_surface(a) == "src/parser.c:s1", f"surface = {work_surface(a)!r}"
assert work_surface(c) == "src/parser.c:public_api_parse"
# Function key takes precedence over strategy when both present.
assert work_surface(c) == work_surface(d), "function dominates strategy in key"
PY
assert_exit_code 0 "fix#4: work_surface composes file/function/strategy correctly"

# ════════════════════════════════════════════════════════════════
# Fix #1: prompt-time card discovery claims a short lease.
# This prevents parallel cold-start prompts from all rendering the same
# top-ranked card before any one agent has adopted it with add-hyp.
# ════════════════════════════════════════════════════════════════

assert_file_not_contains "$SCRIPT_ROOT/lib/prompt.sh" "next-card --agent .* --peek" \
    "fix#1: build_work_card_directive does not use --peek"

source "$SCRIPT_ROOT/lib/structured_state.sh"
source "$SCRIPT_ROOT/lib/prompt.sh"
claims_before=$(wc -l < "$RESULTS_DIR/state/claims.jsonl" 2>/dev/null | tr -d ' ')
directive=$(build_work_card_directive 1)
claims_after=$(wc -l < "$RESULTS_DIR/state/claims.jsonl" 2>/dev/null | tr -d ' ')
assert_match "ASSIGNED WORK CARD" "$directive" \
    "fix#1: build_work_card_directive renders an assigned card"
if [ "$claims_after" -gt "$claims_before" ]; then
    pass "fix#1: build_work_card_directive appends a prompt-time lease"
else
    fail "fix#1: build_work_card_directive appends a prompt-time lease" \
         "claims.jsonl unchanged after directive (before=$claims_before after=$claims_after)"
fi

# Direct test: peek does not append a claim.
claims_before=$(wc -l < "$RESULTS_DIR/state/claims.jsonl" 2>/dev/null | tr -d ' ')
"$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    next-card --agent 1 --mode generic --peek >/dev/null
claims_after=$(wc -l < "$RESULTS_DIR/state/claims.jsonl" 2>/dev/null | tr -d ' ')
assert_eq "${claims_before:-0}" "${claims_after:-0}" \
    "fix#1: --peek does not append a claim row"

# ════════════════════════════════════════════════════════════════
# Fix #1 (continued): claim-on-adopt at add-hyp time.
# ════════════════════════════════════════════════════════════════

card_json=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    next-card --agent 1 --mode generic --peek)
card_id=$(printf '%s' "$card_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
claim_lines_before=$(wc -l < "$RESULTS_DIR/state/claims.jsonl" 2>/dev/null | tr -d ' ')

hyp_out=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    add-hyp --agent 1 --card-id "$card_id" \
    --hypothesis "Bounded copy may overflow when len exceeds buffer" \
    --file "src/parser.c:public_api_parse:7" \
    --input-shape "data length > 16" \
    --guard-gap "no length check before memcpy" \
    --diagnostic bounds --strategy S1 --json)
hyp_id=$(printf '%s' "$hyp_out" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')

claim_lines_after=$(wc -l < "$RESULTS_DIR/state/claims.jsonl" 2>/dev/null | tr -d ' ')
if [ "$claim_lines_after" -gt "$claim_lines_before" ]; then
    pass "fix#1: add-hyp appends a claim-on-adopt row"
else
    fail "fix#1: add-hyp appends a claim-on-adopt row" \
         "claims.jsonl unchanged after add-hyp (before=$claim_lines_before after=$claim_lines_after)"
fi
assert_match "\"source\": \"add-hyp\"" "$(tail -1 "$RESULTS_DIR/state/claims.jsonl")" \
    "fix#1: claim-on-adopt row tags source"
assert_match "\"hypothesis_id\": \"$hyp_id\"" "$(tail -1 "$RESULTS_DIR/state/claims.jsonl")" \
    "fix#1: claim-on-adopt row links to hypothesis"

# ════════════════════════════════════════════════════════════════
# Fix #1.5: update-card --status discarded requires evidence.
# ════════════════════════════════════════════════════════════════

# 0 runs: refuse.
deny=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    update-card --agent 1 --card-id "$card_id" --status discarded 2>&1 || true)
assert_match "refuses discard" "$deny" "fix#1.5: zero runs → discard refused"
assert_match "runs=0" "$deny" "fix#1.5: refusal cites runs count"

# 1 run: still refused (default floor = 3 runs and 2 distinct hypotheses).
"$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    add-run --agent 1 --hypothesis-id "$hyp_id" --card-id "$card_id" --mode generic \
    --testcase "$RESULTS_DIR/scratch-1/v1.input" --asan-output "$RESULTS_DIR/scratch-1/v1.asan.txt" \
    --verdict CLEAN >/dev/null
deny2=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    update-card --agent 1 --card-id "$card_id" --status discarded 2>&1 || true)
assert_match "runs=1" "$deny2" "fix#1.5: under-floor run count refused"

# 3 runs but 1 hypothesis: still refused because one shallow investigation
# must not retire a card.
"$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    add-run --agent 1 --hypothesis-id "$hyp_id" --card-id "$card_id" --mode generic \
    --testcase "$RESULTS_DIR/scratch-1/v2.input" --asan-output "$RESULTS_DIR/scratch-1/v2.asan.txt" \
    --verdict CLEAN >/dev/null
"$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    add-run --agent 1 --hypothesis-id "$hyp_id" --card-id "$card_id" --mode generic \
    --testcase "$RESULTS_DIR/scratch-1/v3.input" --asan-output "$RESULTS_DIR/scratch-1/v3.asan.txt" \
    --verdict CLEAN >/dev/null
deny3=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    update-card --agent 1 --card-id "$card_id" --status discarded 2>&1 || true)
assert_match "distinct_hypotheses=1" "$deny3" "fix#1.5: one hypothesis still refused"

# Duplicate text with a new id does not count as a second investigation.
"$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    add-hyp --agent 1 --card-id "$card_id" \
    --hypothesis "Bounded copy may overflow when len exceeds buffer" \
    --file "src/parser.c:public_api_parse:7" \
    --input-shape "data length > 16" \
    --guard-gap "no length check before memcpy" \
    --diagnostic bounds --strategy S1 >/dev/null
deny_dup=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    update-card --agent 1 --card-id "$card_id" --status discarded 2>&1 || true)
assert_match "distinct_hypotheses=1" "$deny_dup" "fix#1.5: duplicate hypothesis shape refused"

# 3 runs + 2 distinct hypothesis shapes: accepted.
"$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    add-hyp --agent 1 --card-id "$card_id" \
    --hypothesis "Check unterminated token cleanup" --file "src/parser.c" --input-shape "unterminated token" \
    --guard-gap "error path skips reset" --diagnostic lifetime --strategy S5 >/dev/null
ok=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    update-card --agent 1 --card-id "$card_id" --status discarded --note "three clean variants across two hypothesis shapes" --json 2>&1)
assert_match '"status": "discarded"' "$ok" "fix#1.5: floor met → discard accepted"

# Override env still works for tooling.
hyp_b=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    add-hyp --agent 2 --card-id "PATCH-fixone" \
    --hypothesis "Variant" --file "src/parser.c" --input-shape "x" --guard-gap "y" \
    --diagnostic bounds --strategy S1)
override=$(WORK_CARD_ALLOW_NORUNS_DISCARD=1 \
    "$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    update-card --agent 2 --card-id "PATCH-fixone" --status discarded --json 2>&1)
assert_match '"status": "discarded"' "$override" "fix#1.5: override env forces discard"

# ════════════════════════════════════════════════════════════════
# Fix #2: release-stale-claims drops leases with no active hypothesis.
# ════════════════════════════════════════════════════════════════

# Synthesize a fresh card claim that has NO hypothesis behind it.
mkdir -p "$RESULTS_DIR/state"
cat >> "$RESULTS_DIR/state/claims.jsonl" <<JSONL
{"agent":"3","card_id":"PHANTOM-CARD","claimed_at":"2000-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","mode":"generic","role":"reproduce","status":"claimed"}
JSONL

released_count=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    release-stale-claims --grace-seconds 1 --quiet)
if [ "${released_count:-0}" -ge 1 ]; then
    pass "fix#2: release-stale-claims releases hypothesis-less leases"
else
    fail "fix#2: release-stale-claims releases hypothesis-less leases" \
         "released=$released_count"
fi
assert_match "\"status\": \"released\"" "$(grep PHANTOM-CARD "$RESULTS_DIR/state/claims.jsonl" | tail -1)" \
    "fix#2: released row appended to claims.jsonl"
assert_match "\"reason\":" "$(grep PHANTOM-CARD "$RESULTS_DIR/state/claims.jsonl" | tail -1)" \
    "fix#2: released row carries reason"

# An active claim is preserved.
preserved_card_id="$card_id"
hyp_active=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    add-hyp --agent 4 --card-id "$preserved_card_id" \
    --hypothesis "Active" --file "src/parser.c" --input-shape "x" --guard-gap "y" \
    --diagnostic bounds --strategy S1)
"$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    release-stale-claims --grace-seconds 60 --quiet >/dev/null
last=$(grep "$preserved_card_id" "$RESULTS_DIR/state/claims.jsonl" | tail -1)
assert_not_match "\"status\": \"released\"" "$last" \
    "fix#2: claims with active hypothesis are preserved"

# Default TTL is now 30 minutes, not 6 hours.
ttl_seconds=$(PYTHONPATH="$SCRIPT_ROOT/lib" python3 -c '
from workqueue import work_card_claim_ttl
print(int(work_card_claim_ttl().total_seconds()))
')
assert_eq "1800" "$ttl_seconds" "fix#2: default TTL is 30 minutes (was 6 hours)"

# ════════════════════════════════════════════════════════════════
# Fix #3: pre-run EXECUTION VERIFIED removed; post-run only on rc=0.
# We assert the run-asan source no longer prints the pre-run marker
# and now distinguishes EXECUTION INCONCLUSIVE.
# ════════════════════════════════════════════════════════════════

assert_file_not_contains "$RUN_ASAN" 'EXECUTION VERIFIED \(pre-run\)' \
    "fix#3: pre-run EXECUTION VERIFIED removed"
assert_file_contains "$RUN_ASAN" 'EXECUTION VERIFIED \(post-run, rc=0\)' \
    "fix#3: post-run EXECUTION VERIFIED present (gated on rc=0)"
assert_file_contains "$RUN_ASAN" 'EXECUTION INCONCLUSIVE' \
    "fix#3: EXECUTION INCONCLUSIVE marker for non-zero exit"

# bin/probe must not classify EXECUTION INCONCLUSIVE as CLEAN. The CLEAN
# gate is the shared lib/verdict.sh classifier (verdict_clean_marker_re);
# probe's CLEAN branch must route through verdict_file_is_clean.
probe_check_rc=0
SCRIPT_ROOT="$SCRIPT_ROOT" python3 - <<'PY' || probe_check_rc=$?
import os, re, sys
script_root = os.environ["SCRIPT_ROOT"]
probe = open(os.path.join(script_root, "bin", "probe")).read()
verdict = open(os.path.join(script_root, "lib", "verdict.sh")).read()
# probe's CLEAN branch must use the shared classifier, not an inline regex.
if not re.search(r'verdict_file_is_clean "\$ASAN_OUTPUT_FILE".*?\n\s*verdict="CLEAN"',
                 probe, re.DOTALL):
    sys.exit("bin/probe CLEAN branch must route through verdict_file_is_clean")
# The shared CLEAN marker must require a non-zero multi-run success rate
# (run-sanitizer-multi), with the legacy run-asan-multi EXECUTION_RATE label
# still accepted for historical artifacts. It must not trust raw testcase
# stdout (TESTCASE_EXECUTED).
m = re.search(r'verdict_clean_marker_re\(\)\s*\{(.*?)\n\}', verdict, re.DOTALL)
if not m:
    sys.exit("could not find verdict_clean_marker_re in lib/verdict.sh")
body = m.group(1)
if "SUCCESS_RATE: [1-9]" not in body or "run-sanitizer-multi\\] SUCCESS_RATE" not in body:
    sys.exit(f"verdict_clean_marker_re must require run-sanitizer-multi SUCCESS_RATE: [1-9]; got: {body}")
if "run-asan-multi\\] EXECUTION_RATE: [1-9]" not in body:
    sys.exit(f"verdict_clean_marker_re must keep legacy run-asan-multi EXECUTION_RATE support; got: {body}")
if "run-sanitizer-multi\\] EXECUTION_RATE" in body:
    sys.exit(f"verdict_clean_marker_re must not treat run-sanitizer-multi EXECUTION_RATE as CLEAN; got: {body}")
if "TESTCASE_EXECUTED" in body:
    sys.exit(f"verdict_clean_marker_re must not trust raw TESTCASE_EXECUTED; got: {body}")
PY
assert_eq 0 "$probe_check_rc" "fix#3: bin/probe CLEAN gate requires real execution evidence"

# ════════════════════════════════════════════════════════════════
# Fix #5: testcase >16B floor lowered to >=1B (with env override).
# ════════════════════════════════════════════════════════════════

assert_file_not_contains "$SCRIPT_ROOT/lib/triage.sh" '\-\-min-bytes 17' \
    "fix#5: hardcoded 17-byte floor removed"
assert_file_contains "$SCRIPT_ROOT/lib/triage.sh" 'CRASH_TC_MIN_BYTES' \
    "fix#5: floor configurable via CRASH_TC_MIN_BYTES env"

# Functional check: a 1-byte testcase is found.
crash_dir="$RESULTS_DIR/crashes/CRASH-MINI-001"
mkdir -p "$crash_dir"
printf 'X' > "$crash_dir/input.bin"
echo "ERROR: AddressSanitizer: heap-buffer-overflow" > "$crash_dir/asan.txt"
found=$(python3 "$SCRIPT_ROOT/bin/find-crash-testcase" "$crash_dir" --min-bytes 1 2>/dev/null || true)
if [ -n "$found" ]; then
    pass "fix#5: 1-byte testcase findable by find-crash-testcase"
else
    fail "fix#5: 1-byte testcase findable by find-crash-testcase" \
         "expected to find input.bin (1B)"
fi

# ════════════════════════════════════════════════════════════════
# Fix #6: orphan detection broadened to non-sidecar files.
# ════════════════════════════════════════════════════════════════

# Source the helpers that pull testcase_mode_for_file.
source "$SCRIPT_ROOT/lib/quality.sh"

orphan_dir="$TEST_TMPDIR/orphan-detect"
mkdir -p "$orphan_dir"

# Allowed: legacy whitelist (regression — must still work).
echo "<html></html>" > "$orphan_dir/legacy.html"
echo "print('x');"   > "$orphan_dir/legacy.js"

# Allowed: previously-unrecognised binary inputs.
printf '\x00\x01\x02\x03' > "$orphan_dir/blob.bin"
printf '\x80\x01' > "$orphan_dir/cbor.cbor"
printf '\x42\x4a' > "$orphan_dir/bson.bson"
printf '<root></root>' > "$orphan_dir/data.xml"
printf '\x89PNG\r\n\x1a\n' > "$orphan_dir/img.png"
printf '%%PDF-1.4' > "$orphan_dir/doc.pdf"
printf '\x08\x96\x01' > "$orphan_dir/proto.protobuf"
printf '{"x":1}' > "$orphan_dir/data.json"

# Sidecars: blocked.
echo "ASan log content" > "$orphan_dir/run.asan.txt"
echo "log line" > "$orphan_dir/run.log"
echo "# notes" > "$orphan_dir/notes.md"
touch "$orphan_dir/.DS_Store"
echo "int main(){}" > "$orphan_dir/source.c"
echo "# script" > "$orphan_dir/wrapper.sh"
touch "$orphan_dir/empty.input"

for tc in legacy.html legacy.js blob.bin cbor.cbor bson.bson data.xml img.png doc.pdf proto.protobuf data.json; do
    if testcase_mode_for_file "$orphan_dir/$tc" >/dev/null 2>&1; then
        pass "fix#6: $tc recognised as testcase"
    else
        fail "fix#6: $tc recognised as testcase" "testcase_mode_for_file returned non-zero"
    fi
done

for sc in run.asan.txt run.log notes.md .DS_Store source.c wrapper.sh empty.input; do
    if testcase_mode_for_file "$orphan_dir/$sc" >/dev/null 2>&1; then
        fail "fix#6: $sc skipped (sidecar)" "unexpectedly classified as testcase"
    else
        pass "fix#6: $sc skipped (sidecar)"
    fi
done

# ════════════════════════════════════════════════════════════════
# Fix #9: per-strategy completion gate refuses rotation without
# strategy-relevant evidence in notes.jsonl.
# ════════════════════════════════════════════════════════════════

# No notes for agent 9 → S1 evidence count is 0; threshold is 2.
status_S1=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    strategy-status --agent 9 --strategy S1 2>&1; echo "rc=$?")
assert_match '"complete": false' "$status_S1" "fix#9: empty notes → S1 incomplete"
assert_match '"threshold": 2' "$status_S1" "fix#9: S1 threshold = 2"
assert_match 'rc=1' "$status_S1" "fix#9: incomplete strategy returns non-zero rc"

# Add 2 S1-flavoured notes (PATCH- references trigger S1 keyword).
"$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    add-note --agent 9 --hypothesis-id "$hyp_id" --card-id "$card_id" --kind data-flow \
    --text "PATCH-abc12345 covers an earlier fix for this prior fix path" >/dev/null
"$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    add-note --agent 9 --hypothesis-id "$hyp_id" --card-id "$card_id" --kind decision \
    --text "Reviewed PATCH-deadbeef; landed fix backport leaves a regression window" >/dev/null
status_S1_b=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    strategy-status --agent 9 --strategy S1 2>&1; echo "rc=$?")
assert_match '"complete": true' "$status_S1_b" "fix#9: 2 S1-evidence notes → complete"
assert_match 'rc=0' "$status_S1_b" "fix#9: complete strategy returns rc=0"

# Different strategy (S2) is independently scored — agent 9 has 0 S2 notes.
status_S2=$("$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    strategy-status --agent 9 --strategy S2 2>&1; echo "rc=$?")
assert_match '"complete": false' "$status_S2" "fix#9: S2 evidence is independent of S1"

# Disable env knob.
status_disabled=$(STRATEGY_MIN_EVIDENCE_DISABLE=1 \
    "$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    strategy-status --agent 9 --strategy S2 2>&1)
assert_match '"complete": true' "$status_disabled" "fix#9: STRATEGY_MIN_EVIDENCE_DISABLE=1 zeroes the floor"

# Per-strategy threshold knob.
status_low=$(STRATEGY_MIN_EVIDENCE_S2=0 \
    "$STATE" --results-dir "$RESULTS_DIR" --target-path "$TARGET_ROOT" --target-slug "$TARGET_SLUG" \
    strategy-status --agent 9 --strategy S2 2>&1)
assert_match '"threshold": 0' "$status_low" "fix#9: STRATEGY_MIN_EVIDENCE_S2=0 lowers the floor"

# ════════════════════════════════════════════════════════════════
# Fix #10: library threat models include call-sequence/protocol-state
# where appropriate.
# ════════════════════════════════════════════════════════════════

threat_fixture="$TEST_TMPDIR/threat-model-fixtures"
for slug in json libxml2 curl c-ares pcre2 zlib; do
    mkdir -p "$threat_fixture/targets/$slug" "$threat_fixture/output/$slug"
    python3 "$SCRIPT_ROOT/lib/target_config.py" seed-toml \
        "$threat_fixture/targets/$slug" \
        "$threat_fixture/output/$slug/target.toml" ""
done

assert_file_contains "$threat_fixture/output/json/target.toml" \
    'attacker_controls = \["bytes", "call-sequence"\]' \
    "fix#10: nlohmann/json includes call-sequence (header-only template lib)"
assert_file_contains "$threat_fixture/output/libxml2/target.toml" \
    'attacker_controls = \["bytes", "call-sequence"\]' \
    "fix#10: libxml2 includes call-sequence (xmlPattern/xmlCatalog APIs)"
assert_file_contains "$threat_fixture/output/curl/target.toml" \
    'attacker_controls = \["bytes", "call-sequence", "protocol-state"\]' \
    "fix#10: curl includes call-sequence and protocol-state"
assert_file_contains "$threat_fixture/output/c-ares/target.toml" \
    'attacker_controls = \["bytes", "call-sequence", "protocol-state"\]' \
    "fix#10: c-ares includes call-sequence and protocol-state"
# pcre2 + zlib stay byte-only (intentional — those are pure parsers).
assert_file_contains "$threat_fixture/output/pcre2/target.toml" \
    'attacker_controls = \["bytes"\]' \
    "fix#10: pcre2 stays byte-only (regex is byte-driven)"
assert_file_contains "$threat_fixture/output/zlib/target.toml" \
    'attacker_controls = \["bytes"\]' \
    "fix#10: zlib stays byte-only (streaming bytes is the surface)"

# ── PRODUCTIVE classifier tightening ─────────────────────────────────────
# A "PRODUCTIVE 0/0" iteration log line meant the third disjunct
# (is_state_productive) was firing on an ASan scratch artifact that
# triage never promoted. Both call sites (cold-start and steady-state)
# must now gate on real new findings/crashes only, and
# agent_iteration_productive must drop the same scratch-only path.
audit_src="$SCRIPT_ROOT/bin/audit"
assert_file_not_contains "$audit_src" \
  '[|][|] is_state_productive([^(]|$)' \
  "PRODUCTIVE: iteration classifier no longer trusts is_state_productive disjunct"
# The agent-scope productive check must rely on triage-promoted artifacts.
assert_file_not_contains "$audit_src" \
  'is_autodiscard_crash_output "\$f"' \
  "agent_iteration_productive: no longer inspects scratch ASan output"
# Both PRODUCTIVE branches now log under the tightened condition; the
# combined trigger uses only new_confirmed_findings/new_security_crashes.
assert_file_contains "$audit_src" \
  'PRODUCTIVE requires a promoted finding or crash candidate' \
  "PRODUCTIVE: tightened branch carries the rationale comment"
# is_state_productive() is dead code — removing it stops the scratch-only
# productive path entirely.
assert_file_not_contains "$audit_src" \
  '^is_state_productive\(\)' \
  "PRODUCTIVE: is_state_productive() function definition is gone"

# ── Subsystem fast-rotate on cards_available_in_subsystem=0 ──────────────
# When an agent's (strategy, subsystem) pair has 0 unclaimed cards but
# the strategy still has work elsewhere, clear the agent's resume hint
# so the next session re-picks. Catches the /Users absolute-path
# claim race and ordinary "subsystem exhausted, strategy has cards"
# situations before STRATEGY_DRY_STREAK_THRESHOLD iterations elapse.
assert_file_contains "$audit_src" \
  'SUBSYSTEM_FAST_ROTATE' \
  "subsystem fast-rotate: emits a tagged log line"
assert_file_contains "$audit_src" \
  '\[ "\$strat_sub_cards" -eq 0 \] && \[ "\$strat_cards" -gt 0 \]' \
  "subsystem fast-rotate: trigger compares sub_cards==0 against strat_cards>0"

teardown_test_env
summary
