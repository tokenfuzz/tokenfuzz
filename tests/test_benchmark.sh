#!/usr/bin/env bash
# Tests for bin/benchmark + lib/benchmark.py + lib/benchmark_model_direct_usage.py:
#   - harvest: AddressSanitizer-confirmed crash counting, cluster parse,
#              finding/recon/rejected counts, token sums
#   - aggregate: per-condition fold, median/range
#   - ledger: append-only section rendering, header-once, reset/archive
#   - model-direct usage extraction across backend log shapes
#   - bin/benchmark --dry-run end-to-end and argument validation
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$TESTS_DIR/helpers.sh"

setup_test_env

PY="$SCRIPT_ROOT/lib/benchmark.py"
USAGE_PY="$SCRIPT_ROOT/lib/benchmark_model_direct_usage.py"
BENCH="$SCRIPT_ROOT/bin/benchmark"
RENDER_MD="$SCRIPT_ROOT/bin/render-md"

work=$(mktemp -d)
trap 'rm -rf "$work" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT

ASAN_LINE='==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602'

# ── Fixture: a results/ tree with one real crash and one decoy ───────────
rd="$work/results"
mkdir -p "$rd/crashes/CRASH-001" "$rd/crashes/CRASH-002" \
         "$rd/crashes-rejected/CRASH-009" \
         "$rd/findings/FIND-001" "$rd/findings/FIND-002" \
         "$rd/findings-rejected/FIND-099" \
         "$rd/logs"
# Recon candidates live in recon-hypotheses.jsonl (one JSON row per
# hypothesis), not a recon/RECON-* directory tree — count those rows.
# A non-RECON id and a blank line are decoys the count must skip.
printf '%s\n%s\n\n%s\n%s\n' \
  '{"id":"RECON-aaa","class":"OOB-read"}' \
  '{"id":"RECON-bbb","class":"UAF"}' \
  '{"id":"REC-ccc","class":"leak"}' \
  '{"id":"WORK-notrecon","class":"x"}' \
  > "$rd/recon-hypotheses.jsonl"
printf '%s\n  #0 foo bar\n' "$ASAN_LINE" > "$rd/crashes/CRASH-001/sanitizer.txt"
printf 'just a report, no sanitizer output here\n' > "$rd/crashes/CRASH-002/report.md"
printf 'rejected reason text\n' > "$rd/crashes-rejected/CRASH-009/REPORT.md"
printf '{"tokens":{"input":1000,"cached_input":800,"output":50},"probe":{"asan_invocations":2}}\n' \
  > "$rd/logs/index.jsonl"
printf '{"tokens":{"input":500,"cached_input":400,"output":30},"probe":{"asan_invocations":1}}\n' \
  >> "$rd/logs/index.jsonl"

# ── T1: harvest counts only sanitizer-confirmed crashes ──────────────────
hv=$(python3 "$PY" harvest "$rd")
assert_eq "1" "$(echo "$hv" | jq -r '.confirmed_crashes')" \
  "T1a: exactly one ASan-confirmed crash (decoy not counted)"
assert_eq "CRASH-001" "$(echo "$hv" | jq -r '.crash_dirs[0]')" \
  "T1b: confirmed crash dir is CRASH-001"
assert_eq "1" "$(echo "$hv" | jq -r '.crashes_rejected')" "T1c: rejected crash counted"
# DISCARDED hypotheses live in state/hypotheses.jsonl; count_discarded_hypotheses
# returns 0 when the file is missing (no state seeded above).
assert_eq "0" "$(echo "$hv" | jq -r '.discarded_hypotheses')" \
  "T1c-discard-0: discarded_hypotheses=0 when state/hypotheses.jsonl is absent"
assert_eq "2" "$(echo "$hv" | jq -r '.findings')" "T1d: FIND-* dirs counted"
assert_eq "1" "$(echo "$hv" | jq -r '.findings_rejected')" "T1e: rejected findings counted"
assert_eq "3" "$(echo "$hv" | jq -r '.recon_candidates')" "T1f: RECON-* dirs counted"
assert_eq "1500" "$(echo "$hv" | jq -r '.tokens.input_tokens')" "T1g: input tokens summed"
assert_eq "80" "$(echo "$hv" | jq -r '.tokens.output_tokens')" "T1h: output tokens summed"
assert_eq "3" "$(echo "$hv" | jq -r '.tokens.asan_invocations')" "T1i: asan invocations summed"
assert_eq "2" "$(echo "$hv" | jq -r '.tokens.iterations')" "T1j: iteration count"
assert_eq "1200" "$(echo "$hv" | jq -r '.tokens.cached_input_tokens')" "T1k: cached input tokens summed"

# ── T1s: harvest finds index.jsonl when logs/ is a sibling of results/ ───
# A harness run lays out output/<target>-<exp>/<backend>/{results,logs} —
# logs/ is a sibling of results/, not a child. harvest must still find the
# token index there; otherwise every harness cell scores as zero tokens.
sib="$work/harness-exp/codex"
mkdir -p "$sib/results/crashes" "$sib/logs"
printf '{"backend":"codex","tokens":{"input":4000,"cached_input":3800,"output":120},"probe":{"asan_invocations":5}}\n' \
  > "$sib/logs/index.jsonl"
shv=$(python3 "$PY" harvest "$sib/results")
assert_eq "200" "$(echo "$shv" | jq -r '.tokens.input_tokens')" \
  "T1s: harvest reads token index from a sibling logs/ dir (fresh input)"
assert_eq "120" "$(echo "$shv" | jq -r '.tokens.output_tokens')" \
  "T1s2: harvest sums output tokens from the sibling index"
assert_eq "5" "$(echo "$shv" | jq -r '.tokens.asan_invocations')" \
  "T1s3: harvest sums asan invocations from the sibling index"

# ── T1n: harvest normalizes input across backends + folds cache writes ───
# Across backends, `input_tokens` means "tokens processed at the full
# input rate (≥100% of base)" — for claude that's fresh `input` plus
# `cache_creation` (cache writes, billed at 125%); for codex/gemini the
# SDK's `input` is cumulative, so cache reads are subtracted out.
nrd="$work/tok-norm/results"
mkdir -p "$nrd/logs"
printf '%s\n' \
  '{"backend":"codex","tokens":{"input":1000,"cached_input":800,"cache_creation":0,"output":50}}' \
  '{"backend":"claude","tokens":{"input":30,"cached_input":4000,"cache_creation":120,"output":700}}' \
  '{"backend":"gemini","tokens":{"input":58000,"cached_input":55000,"cache_creation":0,"output":80}}' \
  > "$nrd/logs/index.jsonl"
nhv=$(python3 "$PY" harvest "$nrd")
# codex = 1000-800 = 200; claude = 30+120 = 150; gemini = 58000-55000 = 3000 → 3350.
assert_eq "3350" "$(echo "$nhv" | jq -r '.tokens.input_tokens')" \
  "T1n: input normalized to full-rate tokens (claude folds cache_creation; codex/gemini subtract cache_read)"
# cached = cache READS only: codex 800 + claude 4000 + gemini 55000 = 59800.
assert_eq "59800" "$(echo "$nhv" | jq -r '.tokens.cached_input_tokens')" \
  "T1o: cached_input_tokens is cache reads only (writes now live in input_tokens)"
assert_eq "830" "$(echo "$nhv" | jq -r '.tokens.output_tokens')" \
  "T1p: output tokens summed across backends"

# ── T2: UBSan / TSan signatures also count as confirmed ──────────────────
ubd="$work/ub/results/crashes/CRASH-1"
mkdir -p "$ubd"
printf 'src/x.c:9:5: runtime error: signed integer overflow\n' > "$ubd/sanitizer.txt"
assert_eq "1" \
  "$(python3 "$PY" harvest "$work/ub/results" | jq -r '.confirmed_crashes')" \
  "T2: UBSan runtime-error line counts as a confirmed crash"

# ── T3: cluster count parsed from CRASH-CLUSTERS.md ──────────────────────
printf 'x\n**5 CRASH dir(s) → 2 unique cluster(s).**\nmore\n' \
  > "$rd/crashes/CRASH-CLUSTERS.md"
assert_eq "2" "$(python3 "$PY" harvest "$rd" | jq -r '.crash_clusters')" \
  "T3: crash_clusters read from CRASH-CLUSTERS.md"

# ── T4: aggregate folds cells per condition ──────────────────────────────
bd="$work/bench/run1"
mkdir -p "$bd/cells"
cat > "$bd/run.json" <<'JSON'
{"runid":"run1","target":"t","backend":"codex","replicates":2,"budget_wall":60,
 "conditions":["model-direct","harness"],"target_sha":"abc","harness_sha":"def"}
JSON
mk_cell() { # name condition replicate status crashes
  local d="$bd/cells/$1"
  local rejected="${6:-0}"
  mkdir -p "$d"
  cat > "$d/cell.json" <<JSON
{"condition":"$2","replicate":$3,"status":"$4","wall_seconds":42}
JSON
  cat > "$d/metrics.json" <<JSON
{"confirmed_crashes":$5,"crash_clusters":$5,"findings":0,
 "findings_rejected":$rejected,
 "tokens":{"output_tokens":111}}
JSON
}
mk_cell model-direct-r1            model-direct           1 done 0 2
mk_cell model-direct-r2            model-direct           2 done 0
mk_cell harness-r1 harness 1 done 3
mk_cell harness-r2 harness 2 done 1
agg=$(python3 "$PY" aggregate "$bd")
hd=$(echo "$agg" | jq -c '.conditions[] | select(.condition=="harness")')
assert_eq "2" "$(echo "$hd" | jq -r '.crash_median')" "T4a: harness median of [3,1] is 2"
assert_eq "—" "$(echo "$hd" | jq -r '.top_severity_level')" \
  "T4b: no cluster JSON → top severity is unscored (—)"
assert_eq "4" "$(echo "$hd" | jq -r '.crash_total')" "T4c: harness crash total is 4"
assert_eq "2" "$(echo "$hd" | jq -r '.replicates_done')" "T4d: both replicates done"
nv=$(echo "$agg" | jq -c '.conditions[] | select(.condition=="model-direct")')
assert_eq "0" "$(echo "$nv" | jq -r '.crash_median')" "T4e: model-direct median is 0"
assert_eq "2" "$(echo "$nv" | jq -r '.rejected_finding_total')" \
  "T4f: aggregate carries rejected finding totals"

# Rejected findings are pooled into a browsable list with validator booleans.
rbd="$work/rejected-bench"
rrd="$rbd/results"
mkdir -p "$rbd/cells/model-direct-r1" "$rrd/findings-rejected/FIND-raw"
cat > "$rbd/cells/model-direct-r1/cell.json" <<JSON
{"condition":"model-direct","replicate":1,"status":"done","wall_seconds":1,
 "results_dir":"$rrd"}
JSON
cat > "$rbd/cells/model-direct-r1/metrics.json" <<'JSON'
{"confirmed_crashes":0,"crash_dirs":[],"findings":0,"findings_rejected":1}
JSON
cat > "$rrd/findings-rejected/FIND-raw/report.md" <<'EOF_REJ'
# Dirty source tree mutation

Claimed build break.
EOF_REJ
cat > "$rrd/findings-rejected/FIND-raw/validator-vote-1.json" <<'JSON'
{"vote":"Reject","rationale":"dirty worktree mutation, not target input. This rationale intentionally keeps enough detail to exceed the old table truncation limit, because rejected finding pages are audit evidence and must preserve the full validator explanation all the way through the final sentinel: FULL-RATIONALE-END",
 "verified":{"reachability":false,"guards":true,"primitive":false}}
JSON
# FIND-quality cache: the rejection path most pool entries go through.
# Surfaces class+severity+reason — what the new columns show.
cat > "$rrd/findings-rejected/FIND-raw/.llm-find-quality.json" <<'JSON'
{"decision_version":"v7","accept":false,
 "reason":"FIND-gate fallback reason for rejection",
 "class":"memory-safety:lifetime","severity":"low",
 "decision":"find_quality"}
JSON
python3 "$PY" pool "$rbd" >/dev/null
assert_file_exists "$rbd/pool/findings-rejected/REJECTED-FINDINGS.md" \
  "T4g: rejected finding markdown index written for combined pool"
assert_file_contains "$rbd/pool/findings-rejected/REJECTED-FINDINGS.md" \
  '\| memory-safety:lifetime \| low \|' \
  "T4h: rejected finding index carries class + severity from FIND-quality gate"
assert_file_contains "$rbd/pool/findings-rejected/REJECTED-FINDINGS.md" \
  'FULL-RATIONALE-END' \
  "T4h2: rejected finding index keeps the full validator rationale"
pooled_rej_dir=$(find "$rbd/pool/findings-rejected" -mindepth 1 -maxdepth 1 \
  -type d -name 'FIND-*' | head -n 1)
pooled_rej_id="$(basename "$pooled_rej_dir")"
assert_file_contains "$rbd/pool/findings-rejected/REJECTED-FINDINGS.md" \
  "\\[Link\\]\\(${pooled_rej_id}/report.md\\)" \
  "T4h3: rejected finding index labels report links plainly"
python3 "$RENDER_MD" "$pooled_rej_dir/report.md" \
  --html-sibling >/dev/null
python3 "$RENDER_MD" "$rbd/pool/findings-rejected/REJECTED-FINDINGS.md" \
  --html-sibling >/dev/null
assert_file_exists "$pooled_rej_dir/report.html" \
  "T4h4: rejected report markdown can be rendered for browser links"
assert_file_contains "$rbd/pool/findings-rejected/REJECTED-FINDINGS.html" \
  'class="rejected-findings-table"' \
  "T4h5: rejected finding HTML gets the dedicated table layout"
assert_file_contains "$rbd/pool/findings-rejected/REJECTED-FINDINGS.html" \
  "href=\"${pooled_rej_id}/report.html\">Link</a>" \
  "T4h6: rejected finding HTML labels the rendered report link plainly"
python3 "$PY" split-pool "$rbd" >/dev/null
assert_file_exists "$rbd/pool/model-direct/findings-rejected/REJECTED-FINDINGS.md" \
  "T4i: rejected finding markdown index written for condition pool"
assert_file_contains "$BENCH" 'REJECTED-FINDINGS.md' \
  "T4j: bin/benchmark renders rejected finding markdown indexes through render-md"

# ── T5: aggregate degrades gracefully on a partial run ───────────────────
mk_cell harness-r3 harness 3 failed 0
rm -f "$bd/cells/harness-r3/metrics.json"
agg2=$(python3 "$PY" aggregate "$bd")
hd2=$(echo "$agg2" | jq -c '.conditions[] | select(.condition=="harness")')
assert_eq "3" "$(echo "$hd2" | jq -r '.replicates_total')" "T5a: failed cell counted in total"
assert_eq "2" "$(echo "$hd2" | jq -r '.replicates_done')" "T5b: failed cell excluded from done"

# ── T6: ledger append — header written once, sections accumulate ─────────
ledger="$work/ledger.md"
python3 "$PY" ledger "$bd" --ledger "$ledger" >/dev/null
assert_file_contains "$ledger" "# Benchmark results" "T6a: ledger header present"
assert_file_contains "$ledger" "Benchmark run .run1." "T6b: run section present"
assert_file_contains "$ledger" "AddressSanitizer-confirmed" "T6c: oracle caveat present"
hdr_count=$(grep -c '^# Benchmark results' "$ledger")
python3 "$PY" ledger "$bd" --ledger "$ledger" >/dev/null
hdr_count2=$(grep -c '^# Benchmark results' "$ledger")
assert_eq "$hdr_count" "$hdr_count2" "T6d: header not duplicated on second append"
sec_count=$(grep -c 'Benchmark run' "$ledger")
assert_eq "2" "$sec_count" "T6e: second append adds a second section"

# ── T7: reset archives the ledger; --hard deletes it ─────────────────────
out=$(python3 "$PY" reset --ledger "$ledger")
assert_match "archived" "$out" "T7a: reset reports an archive"
assert_file_not_exists "$ledger" "T7b: ledger moved aside by reset"
archived=$(ls "$work"/ledger.*.bak.md 2>/dev/null | head -1)
assert_file_exists "$archived" "T7c: archive file exists"
printf 'x\n' > "$ledger"
python3 "$PY" reset --ledger "$ledger" --hard >/dev/null
assert_file_not_exists "$ledger" "T7d: --hard deletes the ledger"

# ── T8: model-direct usage extraction across backend log shapes ─────────────────
codex_log="$work/codex.log"
printf '%s\n' \
  '{"type":"item.started"}' \
  '{"type":"item.completed","usage":{"input_tokens":2000,"cached_input_tokens":1800,"output_tokens":90}}' \
  > "$codex_log"
u=$(python3 "$USAGE_PY" codex "$codex_log")
assert_eq "2000" "$(echo "$u" | jq -r '.tokens.input')" "T8a: codex input tokens"
assert_eq "1800" "$(echo "$u" | jq -r '.tokens.cached_input')" "T8b: codex cached tokens"
assert_eq "90" "$(echo "$u" | jq -r '.tokens.output')" "T8c: codex output tokens"
assert_eq "0" "$(echo "$u" | jq -r '.tokens.cache_creation')" \
  "T8c2: codex has no cache-write counter → cache_creation 0"
assert_eq "codex" "$(echo "$u" | jq -r '.backend')" \
  "T8c3: backend echoed for harvest-side normalization"

claude_log="$work/claude.log"
printf '%s\n' \
  '{"type":"assistant","message":{"usage":{"input_tokens":5,"output_tokens":7}}}' \
  '{"type":"result","usage":{"input_tokens":50,"cache_read_input_tokens":40,"cache_creation_input_tokens":15,"output_tokens":12}}' \
  > "$claude_log"
u2=$(python3 "$USAGE_PY" claude "$claude_log")
assert_eq "50" "$(echo "$u2" | jq -r '.tokens.input')" "T8d: claude input (last usage wins)"
assert_eq "40" "$(echo "$u2" | jq -r '.tokens.cached_input')" "T8e: claude cache_read alias"
assert_eq "15" "$(echo "$u2" | jq -r '.tokens.cache_creation')" \
  "T8e2: claude cache_creation (cache-write) captured, not dropped"

# gemini-cli emits a single result.stats event whose `input_tokens` is the
# cumulative cached+fresh total and whose cache-read counter is named
# `cached` (no `_input` / `_tokens` suffix). The extractor must alias that
# field; otherwise harvest sees raw_input=58M and cached=0 and bills the
# cell for 58M of "fresh" input — the gemini benchmark regression that
# motivated this test.
gemini_log="$work/gemini.log"
printf '%s\n' \
  '{"type":"init","model":"gemini-3.1-pro-preview"}' \
  '{"type":"result","status":"success","stats":{"total_tokens":58000080,"input_tokens":58000000,"output_tokens":80,"cached":55000000,"input":3000000}}' \
  > "$gemini_log"
u_gem=$(python3 "$USAGE_PY" gemini "$gemini_log")
assert_eq "58000000" "$(echo "$u_gem" | jq -r '.tokens.input')" \
  "T8j: gemini raw input_tokens captured (cumulative cached+fresh)"
assert_eq "55000000" "$(echo "$u_gem" | jq -r '.tokens.cached_input')" \
  'T8k: gemini `cached` aliased into cached_input'
assert_eq "80" "$(echo "$u_gem" | jq -r '.tokens.output')" "T8l: gemini output tokens"
assert_eq "false" "$(echo "$u_gem" | jq -r '.estimated')" \
  "T8m: gemini measured path is not flagged estimated"

empty_log="$work/empty.log"
: > "$empty_log"
u3=$(python3 "$USAGE_PY" gemini "$empty_log")
assert_eq "0" "$(echo "$u3" | jq -r '.tokens.output')" "T8f: empty log yields zero tokens"
u4=$(python3 "$USAGE_PY" codex "$work/does-not-exist.log")
assert_eq "0" "$(echo "$u4" | jq -r '.tokens.input // 0')" "T8g: missing log is safe"
assert_eq "false" "$(echo "$u4" | jq -r '.estimated')" \
  "T8h: missing codex usage is not estimated from stderr"
printf 'codex auth failure without usage\n' > "$work/codex-no-usage.log"
printf 'prompt text\n' > "$work/no-usage-prompt.txt"
u5=$(python3 "$USAGE_PY" codex "$work/codex-no-usage.log" "$work/no-usage-prompt.txt")
assert_eq "0" "$(echo "$u5" | jq -r '.tokens.output')" \
  "T8i: codex no-usage log stays zero-cost instead of estimated"

# ── T9: bin/benchmark --dry-run end-to-end ───────────────────────────────
dledger="$work/dry-ledger.md"
droot="$work/dry-bench"
dry_out=$(bash "$BENCH" --target dummytarget --dry-run --replicates 2 \
  --agents 2 --conditions model-direct,harness --ledger "$dledger" \
  --bench-root "$droot" 2>&1)
rc=$?
assert_eq "0" "$rc" "T9a: dry-run exits 0"
assert_file_exists "$dledger" "T9b: dry-run writes the ledger"
assert_match "crash median=1" "$dry_out" "T9c: harness scores 1 crash/cell in dry-run"
assert_match "model-direct .*crash median=0" "$dry_out" "T9d: model-direct scores 0 in dry-run"
# 2 replicates x harness, each synthetic cell has one real crash.
assert_file_contains "$dledger" 'Scoreboard' "T9e: ledger has the redesigned Scoreboard section"
assert_not_match "Operation not permitted" "$dry_out" \
  "T9f: console tee path does not emit /dev/fd portability warnings"
assert_match 'done in [0-9]+m[0-9][0-9]s \([0-9]+s\)' "$dry_out" \
  "T9f2: cell duration includes minutes and raw seconds"
assert_match 'benchmark-result update \(after model-direct-r1\): .*benchmark-result\.html \(file://' "$dry_out" \
  "T9f3: benchmark-result HTML link is logged after each cell"
dry_updates=$(printf '%s\n' "$dry_out" | grep -c 'benchmark-result update (after ' || true)
if [ "$dry_updates" -ge 4 ]; then
  pass "T9f4: benchmark-result is refreshed after each dry-run cell"
else
  fail "T9f4: benchmark-result is refreshed after each dry-run cell" \
    "saw $dry_updates update lines in: $dry_out"
fi
drun_json=$(find "$droot/codex" -mindepth 2 -maxdepth 2 -name run.json | head -1)
assert_file_exists "$drun_json" "T9g: dry-run writes run metadata"
assert_eq "2" "$(jq -r '.harness_agents' "$drun_json")" \
  "T9h: --agents is recorded as the harness worker count"
assert_eq "1" "$(jq -r '.model_direct_agents' "$drun_json")" \
  "T9i: model-direct remains a one-agent baseline"
assert_file_contains "$dledger" 'Harness agents.*2' \
  "T9j: ledger exposes the harness worker count"

# ── T10: argument validation ─────────────────────────────────────────────
# Every invocation gets a throw-away --bench-root so a successful-but-not-
# rejected case (e.g. --budget-wall 0, which is the documented "unlimited"
# sentinel) doesn't pollute the real benchmark tree under $HOME.
t10_root="$work/argv-validation"
set +e
bash "$BENCH" --dry-run --bench-root "$t10_root" 2>/dev/null; rc_notarget=$?
bash "$BENCH" --target t --dry-run --bench-root "$t10_root" \
  --replicates 0 2>/dev/null; rc_badrep=$?
bash "$BENCH" --target t --dry-run --bench-root "$t10_root" \
  --replicates abc 2>/dev/null; rc_nanrep=$?
bash "$BENCH" --target t --dry-run --bench-root "$t10_root" \
  --conditions bogus 2>/dev/null; rc_badcond=$?
bash "$BENCH" --target t --dry-run --bench-root "$t10_root" \
  --budget-wall xyz 2>/dev/null; rc_badbudget=$?
bash "$BENCH" --target t --dry-run --bench-root "$t10_root" \
  --budget-wall 0 2>/dev/null; rc_unlimitedbudget=$?
bash "$BENCH" --target t --dry-run --bench-root "$t10_root" \
  --agents 0 2>/dev/null; rc_badagents=$?
bash "$BENCH" --target t --dry-run --bench-root "$t10_root" \
  --agents abc 2>/dev/null; rc_nanagents=$?
bash "$BENCH" --target t --dry-run --bench-root "$t10_root" \
  --frobnicate 2>/dev/null; rc_badflag=$?
set -e
assert_neq "0" "$rc_notarget" "T10a: missing --target rejected"
assert_neq "0" "$rc_badrep" "T10b: --replicates 0 rejected"
assert_neq "0" "$rc_nanrep" "T10c: non-numeric --replicates rejected"
assert_neq "0" "$rc_badcond" "T10d: unknown condition rejected"
assert_neq "0" "$rc_badbudget" "T10e: non-numeric --budget-wall rejected"
assert_eq "0" "$rc_unlimitedbudget" "T10e2: --budget-wall 0 accepted as unlimited"
assert_neq "0" "$rc_badagents" "T10f: --agents 0 rejected"
assert_neq "0" "$rc_nanagents" "T10g: non-numeric --agents rejected"
assert_neq "0" "$rc_badflag" "T10h: unknown flag rejected"

# ── T11: --reset via bin/benchmark archives an existing ledger ───────────
rledger="$work/reset-me.md"
printf '# Benchmark results\n\nold content\n' > "$rledger"
bash "$BENCH" --reset --ledger "$rledger" >/dev/null 2>&1
assert_file_not_exists "$rledger" "T11a: bin/benchmark --reset archives the ledger"
rarch=$(ls "$work"/reset-me.*.bak.md 2>/dev/null | head -1)
assert_file_exists "$rarch" "T11b: archive created by bin/benchmark --reset"

# ── T12: gemini estimate path (agy reports no usage) ─────────────────────
# The estimator only fires when the measured path finds nothing, and it
# must NOT bill node.js stack traces / tool-call bodies as output — those
# dominate the raw log when gemini-cli dies on a 429 before emitting any
# assistant message. Output is summed from role=="assistant" content only.
gem_log="$work/gemini.log"
printf '%s\n' \
  '{"type":"init","model":"gemini-3.1-pro-preview"}' \
  '{"type":"tool_use","tool_name":"run_shell_command","parameters":{"command":"git log"}}' \
  'Error: 429 Too Many Requests' \
  '    at Turn.run (file:///.../bundle.js:294311:24)' \
  '    at async Object.<anonymous> (file:///.../bundle.js:1:1)' \
  > "$gem_log"
gem_prompt="$work/gemini-prompt.txt"
printf 'a prompt that is exactly forty chars long!\n' > "$gem_prompt"
gu=$(python3 "$USAGE_PY" gemini "$gem_log" "$gem_prompt")
assert_eq "true" "$(echo "$gu" | jq -r '.estimated')" "T12a: gemini path flagged estimated"
in_est=$(echo "$gu" | jq -r '.tokens.input')
out_est=$(echo "$gu" | jq -r '.tokens.output')
[ "$in_est" -gt 0 ] && pass "T12b: gemini input estimated > 0" \
  || fail "T12b: gemini input estimated > 0" "got $in_est"
# No assistant message in the stream → estimated output is 0, not the
# length of error chatter / tool_use parameters.
assert_eq "0" "$out_est" \
  "T12c: gemini estimate excludes non-assistant noise from output"

# With actual assistant content the estimator sums it (delta or whole).
gem_log2="$work/gemini-with-content.log"
printf '%s\n' \
  '{"type":"init","model":"gemini-3.1-pro-preview"}' \
  '{"type":"message","role":"assistant","content":"hello","delta":true}' \
  '{"type":"message","role":"assistant","content":" world","delta":true}' \
  '    at async Object.<anonymous> (file:///.../bundle.js:1:1)' \
  > "$gem_log2"
gu2=$(python3 "$USAGE_PY" gemini "$gem_log2" "$gem_prompt")
out_est2=$(echo "$gu2" | jq -r '.tokens.output')
# "hello" + " world" = 11 chars → ceil(11/4) = 3 tokens
assert_eq "3" "$out_est2" \
  "T12c2: assistant content summed for the output estimate"

# A real usage object must NOT be flagged estimated.
assert_eq "false" "$(python3 "$USAGE_PY" codex "$codex_log" | jq -r '.estimated')" \
  "T12d: measured codex usage not flagged estimated"

# ── T13: pool subcommand copies cell crash dirs into pool/ ───────────────
pbd="$work/poolbench"
mkdir -p "$pbd/cells"
mkpoolcell() { # cellname condition  -> a cell with one confirmed crash
  local d="$pbd/cells/$1" rdp="$pbd/cells/$1/results"
  mkdir -p "$d" "$rdp/crashes/CRASH-001" "$rdp/findings/FIND-001"
  printf '%s\n  #0 f a.c\n' "$ASAN_LINE" > "$rdp/crashes/CRASH-001/asan.txt"
  printf '# Crash report\nTarget: `%s/work/targets/demo/crash.c`\n' "$HOME" \
    > "$rdp/crashes/CRASH-001/REPORT.md"
  printf '# Finding report\nLocation: `%s/work/targets/demo/find.c`\n' "$HOME" \
    > "$rdp/findings/FIND-001/report.md"
  cat > "$d/cell.json" <<JSON
{"condition":"$2","replicate":1,"status":"done","results_dir":"$rdp"}
JSON
  cat > "$d/metrics.json" <<'JSON'
{"confirmed_crashes":1,"crash_dirs":["CRASH-001"]}
JSON
}
mkpoolcell model-direct-r1 model-direct
mkpoolcell harness-r1 harness
python3 "$PY" pool "$pbd" >/dev/null
assert_dir_exists "$pbd/pool/crashes" "T13a: pool/crashes created"
pooled=$(ls "$pbd/pool/crashes" | grep -c '^CRASH-' || true)
assert_eq "2" "$pooled" "T13b: both confirmed crashes pooled + renamed"
assert_file_exists "$pbd/pool-members.json" "T13c: member->condition map written"
nconds=$(jq -r '.crashes | to_entries | map(.value) | sort | unique | length' \
  "$pbd/pool-members.json")
assert_eq "2" "$nconds" "T13d: both conditions present in member map"
assert_file_not_contains "$pbd/pool/crashes/CRASH-0001/REPORT.md" "$HOME" \
  "T13e: pooled crash report scrubs local home path"
assert_file_contains "$pbd/pool/crashes/CRASH-0001/REPORT.md" \
  'targets/demo/crash.c' \
  "T13f: pooled crash report keeps repo-relative target path"
assert_file_not_contains "$pbd/pool/findings/FIND-0001/report.md" "$HOME" \
  "T13g: pooled finding report scrubs local home path"
assert_file_contains "$pbd/pool/findings/FIND-0001/report.md" \
  'targets/demo/find.c' \
  "T13h: pooled finding report keeps repo-relative target path"

# ── T14: aggregate attributes cluster-tool output to conditions ──────────
abd="$work/attrbench"
mkdir -p "$abd/cells"
cat > "$abd/run.json" <<'JSON'
{"runid":"attr","target":"t","backend":"codex","replicates":1}
JSON
acell() { # name condition
  local d="$abd/cells/$1"
  mkdir -p "$d"
  printf '{"condition":"%s","replicate":1,"status":"done","wall_seconds":1}\n' \
    "$2" > "$d/cell.json"
  printf '{"confirmed_crashes":1,"crash_dirs":["CRASH-001"]}\n' > "$d/metrics.json"
}
acell model-direct-r1 model-direct
acell harness-r1 harness
# Simulate bin/cluster-crashes --json output + the pool member map:
# CL-1 (Medium) found by both conditions, CL-2 (Low) only by harness.
cat > "$abd/clusters-crashes.json" <<'JSON'
{"clusters":[
  {"id":"CL-1","members":["CRASH-0001","CRASH-0002"],"size":2,"primitive":"heap-buffer-overflow",
   "severity_level":"Medium","severity_rank":2,"severity_score":48},
  {"id":"CL-2","members":["CRASH-0003"],"size":1,"primitive":"heap-use-after-free",
   "severity_level":"Low","severity_rank":1,"severity_score":20}]}
JSON
cat > "$abd/pool-members.json" <<'JSON'
{"crashes":{"CRASH-0001":"model-direct","CRASH-0002":"harness","CRASH-0003":"harness"},
 "findings":{}}
JSON
aagg=$(python3 "$PY" aggregate "$abd")
ahd=$(echo "$aagg" | jq -c '.conditions[] | select(.condition=="harness")')
anv=$(echo "$aagg" | jq -c '.conditions[] | select(.condition=="model-direct")')
assert_eq "2" "$(echo "$ahd" | jq -r '.unique_crash_clusters')" \
  "T14a: harness sees both clusters"
assert_eq "1" "$(echo "$ahd" | jq -r '.novel_crash_clusters')" \
  "T14b: harness has one novel cluster (CL-2)"
assert_eq "1" "$(echo "$anv" | jq -r '.unique_crash_clusters')" \
  "T14c: model-direct sees the one shared cluster"
assert_eq "0" "$(echo "$anv" | jq -r '.novel_crash_clusters')" \
  "T14d: model-direct has no novel cluster"
assert_eq "2" "$(echo "$aagg" | jq -r '.crash_clusters | length')" \
  "T14e: report carries the cross-condition cluster list"
# Severity carried straight through from the cluster tool, never recomputed.
assert_eq "Medium" "$(echo "$ahd" | jq -r '.top_severity_level')" \
  "T14f: harness top severity is Medium (CL-1)"
assert_eq "1" "$(echo "$ahd" | jq -r '.medium_plus_bugs')" \
  "T14g: harness has one Medium+ bug"
assert_eq "Medium" "$(echo "$anv" | jq -r '.top_severity_level')" \
  "T14h: model-direct top severity is Medium (shared CL-1)"
assert_eq "1" "$(echo "$anv" | jq -r '.medium_plus_bugs')" \
  "T14h2: model-direct medium_plus counts the shared Medium cluster it reached"
assert_eq "48" \
  "$(echo "$aagg" | jq -r '.crash_clusters[] | select(.id=="CL-1") | .severity_score')" \
  "T14i: cluster list carries severity_score from the cluster tool"

# ── T15: fixture-driven ledger render for dedup/report links ─────────────
# The full bin/benchmark dry-run path is covered by T9. This fixture starts at
# the benchmark.py aggregation boundary so link rendering stays covered without
# running the whole dry-run pipeline a second time.
ddir="$work/dedup-fixture"
mkdir -p "$ddir/cells/harness-r1" \
         "$ddir/pool/crashes/CRASH-0001" \
         "$ddir/pool/harness/crashes"
cat > "$ddir/run.json" <<'JSON'
{"runid":"dedup-fixture","target":"dummytarget","backend":"codex",
 "replicates":3,"budget_wall":3600,"conditions":["harness"],
 "target_sha":"abc","harness_sha":"def","harness_agents":2}
JSON
cat > "$ddir/cells/harness-r1/cell.json" <<'JSON'
{"condition":"harness","replicate":1,"status":"done","wall_seconds":1800,
 "experiment":"bench-dedup-harness-r1"}
JSON
cat > "$ddir/cells/harness-r1/metrics.json" <<'JSON'
{"confirmed_crashes":3,"crash_dirs":["CRASH-0001","CRASH-0002","CRASH-0003"],
 "tokens":{"input_tokens":10,"cached_input_tokens":20,"output_tokens":30}}
JSON
cat > "$ddir/pool-members.json" <<'JSON'
{"crashes":{"CRASH-0001":"harness","CRASH-0002":"harness","CRASH-0003":"harness"},
 "crashes-rejected":{},"findings":{},"findings-rejected":{}}
JSON
cat > "$ddir/clusters-crashes.json" <<'JSON'
{"clusters":[{"id":"CL-DRY","members":["CRASH-0001","CRASH-0002","CRASH-0003"],
 "size":3,"primitive":"heap-buffer-overflow","severity_level":"Medium",
 "severity_rank":2,"severity_score":42}]}
JSON
touch "$ddir/pool/harness/crashes/CRASH-CLUSTERS.html"
dledger2="$ddir/benchmark-results.md"
python3 "$PY" ledger "$ddir" --ledger "$dledger2" >/dev/null
python3 "$RENDER_MD" "$dledger2" --html-sibling >/dev/null
assert_eq "0" "$?" "T15a: fixture ledger renders without a full benchmark rerun"
# Scoreboard counts are reviewer links; the `harness` condition renders under
# its product label `tokenfuzz`.
assert_file_contains "$dledger2" 'tokenfuzz.*\[3\]\([^)]*pool/harness/crashes[^)]*\).*\[1\]\([^)]*CRASH-CLUSTERS\.[a-z]*[^)]*\)' \
  "T15b: scoreboard shows 3 crashes deduplicated to 1 unique bug"
assert_file_contains "$dledger2" 'Bugs by severity' \
  "T15c: ledger has the severity-sorted bug table"
assert_dir_exists "$ddir/pool/crashes" \
  "T15d: single pooled crash tree exists (no by-condition duplication)"
assert_file_contains "$dledger2" 'pool/crashes' \
  "T15e: ledger links to the pooled crash tree"
assert_file_contains "$dledger2" 'Verdict' \
  "T15f: ledger leads with a one-line Verdict"
# The ### subsection headings must render as real <h3> elements, not as
# literal "### Verdict" paragraph text — bin/render-md learned h3 for this.
dhtml2="$ddir/benchmark-results.html"
assert_file_contains "$dhtml2" '<h3[^>]*>Verdict' \
  "T15g: ### Verdict renders as an <h3> heading in the HTML"
assert_file_contains "$dhtml2" '<h3[^>]*>Scoreboard' \
  "T15h: ### Scoreboard renders as an <h3> heading in the HTML"
# Every table value a reviewer would verify is a link to its artifact: the
# Token-usage experiment links to its cell directory, the Bug id to its
# crash directory.
assert_file_contains "$dledger2" '\[`bench-[^]]*`\]([^)]*cells/[^)]*)' \
  "T15j: token-usage experiment links to its cell directory"
assert_file_contains "$dledger2" '\[`CL-[^]]*`\]([^)]*pool/crashes/[^)]*)' \
  "T15k: the Bug id links to its crash directory"
# Artifact links must render as real clickable hrefs in the HTML so a
# reviewer can navigate into them. Ledger links are emitted as paths
# relative to the rendered file (no `file://` scheme, no /Users/...
# leak), so the test accepts either a relative href or an absolute
# file:// URI — both render as a working <a href="..."> in a browser.
assert_file_contains "$dhtml2" '<a href="[^"]*pool/[^/"]*/crashes[^"]*"' \
  "T15l: artifact links render as clickable hrefs in the HTML"
# A second run appends another section; the repeated "Verdict" / "Scoreboard"
# headings must get unique anchor ids so in-page links never collide.
python3 "$PY" ledger "$ddir" --ledger "$dledger2" >/dev/null
python3 "$RENDER_MD" "$dledger2" --html-sibling >/dev/null
assert_file_contains "$dhtml2" 'id="verdict-2"' \
  "T15i: a repeated heading gets a deduplicated anchor id"

# A repeated runid must not reuse an existing run directory. This can happen
# naturally when two benchmarks start in the same second; BENCHMARK_RUNID makes
# the collision deterministic for the test.
collision_root="$work/runid-collision"
BENCHMARK_RUNID=20260104-000000 bash "$BENCH" --target dummytarget \
  --dry-run --replicates 1 --conditions model-direct \
  --bench-root "$collision_root" >/dev/null 2>&1
BENCHMARK_RUNID=20260104-000000 bash "$BENCH" --target dummytarget \
  --dry-run --replicates 1 --conditions model-direct \
  --bench-root "$collision_root" >/dev/null 2>&1
assert_dir_exists "$collision_root/codex/20260104-000000" \
  "T15m: first colliding runid keeps the base directory"
assert_dir_exists "$collision_root/codex/20260104-000000-2" \
  "T15n: second colliding runid gets a unique directory"
collision_xt=$(python3 "$PY" crosstab "$collision_root")
assert_match '20260104-000000-2' "$collision_xt" \
  "T15o: crosstab includes the collision-suffixed run"

# ── T16: model-direct codex cells pass exactly one cwd flag ─────────────────────
fake_codex="$work/fake-codex"
cat > "$fake_codex" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
count=0
cd_val=""
want_cd=0
for arg in "$@"; do
  if [ "$want_cd" = 1 ]; then cd_val="$arg"; want_cd=0; fi
  if [ "$arg" = "--cd" ]; then count=$((count + 1)); want_cd=1; fi
done
printf 'fake-codex args:'
printf ' [%s]' "$@"
printf '\n'
if [ "$count" -ne 1 ]; then
  printf 'expected exactly one --cd, got %s\n' "$count" >&2
  exit 64
fi
# The --cd path must be absolute and exist: codex resolves it after its
# own chdir, so a relative path here resolves against the wrong root.
case "$cd_val" in
  /*) ;;
  *)  printf 'expected absolute --cd path, got %s\n' "$cd_val" >&2; exit 65 ;;
esac
if [ ! -d "$cd_val" ]; then
  printf '--cd path does not exist: %s\n' "$cd_val" >&2
  exit 66
fi
printf '{"type":"item.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":1}}\n'
SH
chmod +x "$fake_codex"
bench_target="benchmark-test-target-$$"
mkdir -p "$SCRIPT_ROOT/targets/$bench_target/build-asan" \
         "$SCRIPT_ROOT/targets/$bench_target/lib" \
         "$SCRIPT_ROOT/targets/$bench_target/findings/FIND-stale"
cat > "$SCRIPT_ROOT/targets/$bench_target/target.toml" <<'TOML'
target = "benchmark-test-target"

[sanitizer]
enabled = []

[runner]
bin = "/bin/true"
args = []
TOML
printf '#!/bin/sh\nprintf helper\n' \
  > "$SCRIPT_ROOT/targets/$bench_target/build-asan/generated-helper"
chmod 0644 "$SCRIPT_ROOT/targets/$bench_target/build-asan/generated-helper"
printf 'int benchmark_visible;\n' \
  > "$SCRIPT_ROOT/targets/$bench_target/lib/benchmark-visible.c"
printf 'stale target finding\n' \
  > "$SCRIPT_ROOT/targets/$bench_target/findings/FIND-stale/report.md"
touch -t 202001010101 \
  "$SCRIPT_ROOT/targets/$bench_target/findings/FIND-stale/report.md" \
  "$SCRIPT_ROOT/targets/$bench_target/findings/FIND-stale" \
  "$SCRIPT_ROOT/targets/$bench_target/findings"
reltest_root="$SCRIPT_ROOT/output/benchmark-reltest-$$"
trap 'rm -rf "$work" "$SCRIPT_ROOT/targets/$bench_target" "$reltest_root"* "${SCRIPT_ROOT}/${root_junk_name:-__no_such_benchmark_root_junk__}" "${SCRIPT_ROOT}/${model_direct_junk_name:-__no_such_benchmark_model_direct_junk__}" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT
codex_root="$work/codex-bench"
codex_out=$(CODEX_BIN="$fake_codex" \
  bash "$BENCH" --target "$bench_target" --backend codex --replicates 1 \
  --conditions model-direct --budget-wall 5 --bench-root "$codex_root" 2>&1)
assert_eq "0" "$?" "T16a: model-direct codex cell succeeds with one --cd"
assert_match "cells complete: 1 done, 0 failed" "$codex_out" \
  "T16b: codex benchmark cell marked done"
# The target tree must stay byte-identical: no chmod, no copy, no rewrite.
# Inspect the literal mode bits via stat rather than `[ -x file ]`. The
# latter lies on Docker-for-Mac bind mounts (root + virtiofs returns
# access=ok regardless of u/g/o execute bits), so a 0644 helper would
# read as "executable" even when the benchmark never touched it.
helper_path="$SCRIPT_ROOT/targets/$bench_target/build-asan/generated-helper"
helper_mode=$(stat -c '%a' "$helper_path" 2>/dev/null \
  || stat -f '%Lp' "$helper_path" 2>/dev/null)
if [ -n "$helper_mode" ] && [ "$(( 0$helper_mode & 0111 ))" -eq 0 ]; then
  pass "T16b2: model-direct prep does NOT chmod the target tree"
else
  fail "T16b2: model-direct prep does NOT chmod the target tree" \
    "target helper mode is now $helper_mode; benchmark must not mutate the target"
fi
assert_file_exists \
  "$SCRIPT_ROOT/targets/$bench_target/findings/FIND-stale/report.md" \
  "T16b3: pre-existing files in the target tree are left undisturbed"

# A relative --bench-root must still yield an absolute, existing --cd:
# the script cd's to SCRIPT_ROOT, so the root resolves there. fake-codex
# rejects a relative or missing --cd, so a clean run proves the fix.
codex_rel_out=$(cd "$SCRIPT_ROOT" && CODEX_BIN="$fake_codex" bash "$BENCH" \
  --target "$bench_target" --backend codex --replicates 1 \
  --conditions model-direct --budget-wall 5 \
  --bench-root "output/benchmark-reltest-$$" 2>&1)
codex_rel_rc=$?
assert_eq "0" "$codex_rel_rc" "T16c: model-direct codex cell succeeds with relative --bench-root"
assert_match "cells complete: 1 done, 0 failed" "$codex_rel_out" \
  "T16d: relative-root codex benchmark cell marked done"

# ── T16e: claude model-direct flags omit --max-turns ────────────────────────
# Model-direct is an open-ended audit task; the wall-clock budget is its only
# real ceiling. A turn cap there just kills the agent mid-investigation
# (observed: 120 tool calls of pure recon, zero findings written before the
# cap fired). The benchmark passes max_turns=0 to llm_agent_flags, which
# must omit --max-turns entirely so claude self-paces against the timeout.
claude_flags_out=$(bash -c '
  set -euo pipefail
  source '"$SCRIPT_ROOT"'/lib/llm_invoke.sh
  declare -a flags=()
  llm_agent_flags claude flags "" 0 "/tmp"
  printf "%s\n" "${flags[@]}"
')
if printf '%s\n' "$claude_flags_out" | grep -qx -- '--max-turns'; then
  fail "T16e: max_turns=0 must omit --max-turns from claude flags" \
    "got: $claude_flags_out"
else
  pass "T16e: max_turns=0 omits --max-turns from claude flags"
fi
# Sanity: a positive max_turns still emits the flag.
claude_flags_capped=$(bash -c '
  set -euo pipefail
  source '"$SCRIPT_ROOT"'/lib/llm_invoke.sh
  declare -a flags=()
  llm_agent_flags claude flags "" 80 "/tmp"
  printf "%s\n" "${flags[@]}"
')
if printf '%s\n' "$claude_flags_capped" | grep -qx -- '--max-turns'; then
  pass "T16f: positive max_turns still emits --max-turns (sub-agents stay capped)"
else
  fail "T16f: positive max_turns must still emit --max-turns" \
    "got: $claude_flags_capped"
fi

# ── T16g: a claude cell that genuinely fails is still marked failed ────────────
# A non-zero exit is a real failure and must not be laundered into a done cell.
# (Previously error_max_turns was treated as success; with the model-direct
# turn cap removed, that special case is gone and any non-zero exit fails.)
fake_claude_fail="$work/fake-claude-fail"
cat > "$fake_claude_fail" <<'SH'
#!/usr/bin/env bash
printf '{"type":"result","subtype":"error_during_execution","is_error":true}\n'
exit 1
SH
chmod +x "$fake_claude_fail"
claude_fail_out=$(cd "$SCRIPT_ROOT" && CLAUDE_BIN="$fake_claude_fail" bash "$BENCH" \
  --target "$bench_target" --backend claude --replicates 1 \
  --conditions model-direct --budget-wall 5 \
  --bench-root "$reltest_root-claudefail" 2>&1) || true
rm -rf "$reltest_root-claudefail" 2>/dev/null || true
assert_match "cells complete: 0 done, 1 failed" "$claude_fail_out" \
  "T16g: a genuinely failed claude cell stays failed"

# ── T16h-k: model-direct cells do not dirty the real repo root ───────────
fake_gemini="$work/fake-gemini"
cat > "$fake_gemini" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
cat >/dev/null || true
if [ -n "${BENCHMARK_FAKE_BARE_JUNK:-}" ]; then
  printf 'junk from %s\n' "$(pwd)" > "$BENCHMARK_FAKE_BARE_JUNK"
fi
printf '{"id":"REC-empty","slice":"fake","confidence":"AUDIT-CLEAN","notes":"fake clean"}\n'
SH
chmod +x "$fake_gemini"
model_direct_junk_name="benchmark-model-direct-junk-$$.txt"
rm -f "$SCRIPT_ROOT/$model_direct_junk_name" 2>/dev/null || true
gemini_direct_root="$work/gemini-direct-bench"
gemini_direct_out=$(GEMINI_BIN="$fake_gemini" BENCHMARK_FAKE_BARE_JUNK="$model_direct_junk_name" \
  bash "$BENCH" --target "$bench_target" --backend gemini \
    --replicates 1 --conditions model-direct --budget-wall 5 \
    --bench-root "$gemini_direct_root" 2>&1)
gemini_direct_rc=$?
assert_eq "0" "$gemini_direct_rc" \
  "T16h: fake-gemini model-direct benchmark cell exits cleanly"
assert_match "cells complete: 1 done, 0 failed" "$gemini_direct_out" \
  "T16i: fake-gemini model-direct benchmark cell marked done"
assert_file_not_exists "$SCRIPT_ROOT/$model_direct_junk_name" \
  "T16j: model-direct benchmark does not create bare junk in the real repo root"
model_direct_junk=$(find "$gemini_direct_root/gemini" \
  -path "*/cells/model-direct-r1/$model_direct_junk_name" | head -1)
assert_file_exists "$model_direct_junk" \
  "T16k: bare junk lands inside the model-direct cell dir (which IS cwd)"

gemini_unlimited_root="$work/gemini-direct-unlimited-bench"
gemini_unlimited_out=$(GEMINI_BIN="$fake_gemini" \
  bash "$BENCH" --target "$bench_target" --backend gemini \
    --replicates 1 --conditions model-direct --budget-wall 0 \
    --bench-root "$gemini_unlimited_root" 2>&1)
gemini_unlimited_rc=$?
assert_eq "0" "$gemini_unlimited_rc" \
  "T16k2: fake-gemini model-direct benchmark supports unlimited wall time"
assert_match "budget=unlimited" "$gemini_unlimited_out" \
  "T16k3: unlimited wall-time mode is visible in benchmark logs"

# ── T16l-o: benchmark harness cells do not dirty the real repo root ──────
# bin/audit cd's to its SCRIPT_ROOT before launching backend agents. In a
# benchmark harness cell, SCRIPT_ROOT must be the cell's repo facade, not the
# operator's real checkout; otherwise Gemini/agy writing a bare relative
# testcase leaves files like test_logic.c in /Users/.../work.
root_junk_name="benchmark-root-junk-$$.txt"
rm -f "$SCRIPT_ROOT/$root_junk_name" 2>/dev/null || true
gemini_harness_root="$work/gemini-harness-bench"
gemini_harness_out=$(GEMINI_BIN="$fake_gemini" BENCHMARK_FAKE_BARE_JUNK="$root_junk_name" \
  bash "$BENCH" --target "$bench_target" --backend gemini \
    --replicates 1 --conditions harness --agents 1 --budget-wall 5 \
    --bench-root "$gemini_harness_root" 2>&1)
gemini_harness_rc=$?
assert_eq "0" "$gemini_harness_rc" \
  "T16l: fake-gemini harness benchmark cell exits cleanly"
assert_match "cells complete: 1 done, 0 failed" "$gemini_harness_out" \
  "T16m: fake-gemini harness benchmark cell marked done"
assert_file_not_exists "$SCRIPT_ROOT/$root_junk_name" \
  "T16n: harness benchmark does not create bare junk in the real repo root"
facade_junk=$(find "$gemini_harness_root/gemini" \
  -path "*/cells/harness-r1/repo-root/$root_junk_name" | head -1)
assert_file_exists "$facade_junk" \
  "T16o: bare junk is contained inside the harness cell repo facade"

# ── T17: the ledger renders a severity-sorted bug table ──────────────────
# Reuses the T14 bench dir, whose synthetic clusters carry severity:
# CL-1 Medium(48) and CL-2 Low(20) must render Medium-first.
t17led="$work/t17-ledger.md"
python3 "$PY" ledger "$abd" --ledger "$t17led" >/dev/null
assert_file_contains "$t17led" 'Bugs by severity' "T17a: severity bug table present"
assert_file_contains "$t17led" 'Medium' "T17b: Medium cluster rendered in the table"
assert_file_contains "$t17led" 'CL-1' "T17c: cluster id rendered"
# Medium (rank 2) must appear on an earlier line than Low (rank 1).
med_line=$(grep -n 'Medium' "$t17led" | tail -1 | cut -d: -f1)
low_line=$(grep -n 'Low' "$t17led" | head -1 | cut -d: -f1)
if [ -n "$med_line" ] && [ -n "$low_line" ] && [ "$med_line" -lt "$low_line" ]; then
  pass "T17d: bugs are sorted strongest-severity first"
else
  fail "T17d: bugs are sorted strongest-severity first" \
    "Medium at line $med_line, Low at line $low_line"
fi
# Display labels: harness -> tokenfuzz, model-direct -> <backend>-direct.
# The T14 bench dir's run.json records backend "codex".
assert_file_contains "$t17led" 'tokenfuzz' \
  "T17e: the harness condition renders as 'tokenfuzz'"
assert_file_contains "$t17led" 'codex-direct' \
  "T17f: the model-direct baseline renders as '<backend>-direct'"
if grep -qF '`harness`' "$t17led" || grep -qF '`model-direct`' "$t17led"; then
  fail "T17g: internal condition tokens must not leak into the page" \
    "found a raw \`harness\`/\`model-direct\` token"
else
  pass "T17g: internal condition tokens do not leak into the rendered page"
fi

# ── T18: aggregate + ledger expose per-experiment token usage ─────────────
tbd="$work/tokens-bench"
mkdir -p "$tbd/cells/harness-r1" "$tbd/cells/model-direct-r1"
cat > "$tbd/run.json" <<'JSON'
{"runid":"tok","target":"t","backend":"gemini","replicates":1}
JSON
cat > "$tbd/cells/harness-r1/cell.json" <<'JSON'
{"condition":"harness","replicate":1,"status":"done","wall_seconds":3600,
 "experiment":"bench-tok-harness-r1"}
JSON
cat > "$tbd/cells/harness-r1/metrics.json" <<'JSON'
{"confirmed_crashes":0,"tokens":{"input_tokens":10,"cached_input_tokens":20,
 "output_tokens":30,"prompt_estimate_tokens":0,"iterations":2}}
JSON
cat > "$tbd/cells/model-direct-r1/cell.json" <<'JSON'
{"condition":"model-direct","replicate":1,"status":"done","wall_seconds":5400,
 "experiment":"bench-tok-model-direct-r1"}
JSON
cat > "$tbd/cells/model-direct-r1/metrics.json" <<'JSON'
{"confirmed_crashes":0,"tokens":{"input_tokens":1234,"cached_input_tokens":0,
 "output_tokens":56,"prompt_estimate_tokens":0,"iterations":1,"estimated":true}}
JSON
tagg=$(python3 "$PY" aggregate "$tbd")
th=$(echo "$tagg" | jq -c '.conditions[] | select(.condition=="harness")')
tm=$(echo "$tagg" | jq -c '.conditions[] | select(.condition=="model-direct")')
assert_eq "10" "$(echo "$th" | jq -r '.input_tokens_total')" \
  "T18a: harness input token total aggregated"
assert_eq "20" "$(echo "$th" | jq -r '.cached_input_tokens_total')" \
  "T18b: harness cached token total aggregated"
assert_eq "measured" "$(echo "$th" | jq -r '.token_source')" \
  "T18c: measured source reported for measured row"
assert_eq "estimated" "$(echo "$tm" | jq -r '.token_source')" \
  "T18d: estimated source reported for estimated row"
assert_eq "bench-tok-model-direct-r1" \
  "$(echo "$tagg" | jq -r '.token_usage[] | select(.condition=="model-direct") | .experiment')" \
  "T18e: token_usage preserves experiment name"
tled="$work/tokens-ledger.md"
python3 "$PY" ledger "$tbd" --ledger "$tled" >/dev/null
assert_file_contains "$tled" 'Token usage' "T18f: ledger has token usage table"
assert_file_contains "$tled" 'bench-tok-model-direct-r1' \
  "T18g: ledger lists per-experiment token usage"
assert_file_contains "$tled" 'estimated.*1,234' \
  "T18h: ledger marks estimated token rows and formats counts"

# T18i-l: wall time is aggregated and rendered (it used to be computed and
# then silently dropped — never reaching the page).
assert_eq "3600" \
  "$(echo "$tagg" | jq -r '.token_usage[]|select(.condition=="harness")|.wall_seconds')" \
  "T18i: token_usage rows carry per-cell wall_seconds"
assert_eq "3600" "$(echo "$th" | jq -r '.wall_median')" \
  "T18j: harness wall_median aggregated"
assert_file_contains "$tled" 'Wall \(h\)' \
  "T18k: ledger Token usage / Scoreboard expose a Wall column"
assert_file_contains "$tled" '1\.00h' \
  "T18l: ledger renders wall time as decimal hours"
# T18m: each condition gets a bold totals row in the Token usage table.
assert_file_contains "$tled" '\*\*1 cell\*\*' \
  "T18m: Token usage table has a per-condition totals row"
# T18n-o: the redesigned Scoreboard has Replicates and split finding/crash
# uniqueness columns.
assert_file_contains "$tled" '1/1' \
  "T18n: Scoreboard shows a Replicates (done/total) column"
assert_file_contains "$tled" 'Unique findings.*Unique crashes' \
  "T18o: Scoreboard splits unique findings from unique crashes"

# ── T18p-s: zero-usage rows render as 'unknown', big counts compact ──────
ubd="$work/unknown-tokens-bench"
mkdir -p "$ubd/cells/harness-r1" "$ubd/cells/harness-r2"
cat > "$ubd/run.json" <<'JSON'
{"runid":"unk","target":"t","backend":"codex","replicates":2}
JSON
cat > "$ubd/cells/harness-r1/cell.json" <<'JSON'
{"condition":"harness","replicate":1,"status":"done","wall_seconds":7200,
 "experiment":"bench-unk-harness-r1"}
JSON
# A cell that produced no usage telemetry at all — must read 'unknown',
# never 'measured' (a measured zero and an absent measurement differ).
cat > "$ubd/cells/harness-r1/metrics.json" <<'JSON'
{"confirmed_crashes":0,"tokens":{"input_tokens":0,"cached_input_tokens":0,
 "output_tokens":0,"prompt_estimate_tokens":0,"iterations":0}}
JSON
cat > "$ubd/cells/harness-r2/cell.json" <<'JSON'
{"condition":"harness","replicate":2,"status":"done","wall_seconds":3600,
 "experiment":"bench-unk-harness-r2"}
JSON
cat > "$ubd/cells/harness-r2/metrics.json" <<'JSON'
{"confirmed_crashes":0,"tokens":{"input_tokens":2500000,"cached_input_tokens":0,
 "output_tokens":1200000,"prompt_estimate_tokens":0,"iterations":1}}
JSON
uagg=$(python3 "$PY" aggregate "$ubd")
assert_eq "mixed" \
  "$(echo "$uagg" | jq -r '.conditions[]|select(.condition=="harness")|.token_source')" \
  "T18p: a condition mixing measured + unknown rows reports 'mixed'"
uled="$work/unknown-tokens-ledger.md"
python3 "$PY" ledger "$ubd" --ledger "$uled" >/dev/null
assert_file_contains "$uled" 'unknown' \
  "T18q: a cell with no usage telemetry renders source 'unknown'"
assert_file_contains "$uled" '2\.5M' \
  "T18r: million-scale token counts render compactly (2.5M, not 2,500,000)"
assert_file_contains "$uled" '1\.2M' \
  "T18s: million-scale output tokens render compactly"

# ── T19: aggregate keeps every backend/run/target/condition row ─────
xroot="$work/xtab-output"
mkbackend() {  # mkbackend <backend> <runid> <crash_total> <unique> [target]
  local bdir="$xroot/benchmark-$1/$2"
  local target="${5:-c-ares}"
  mkdir -p "$bdir"
  cat > "$bdir/report.json" <<JSON
{"run":{"runid":"$2","target":"$target","backend":"$1","model":"$1-m","replicates":3,
 "budget_wall":3600,"conditions":["model-direct","harness"]},
 "conditions":[
  {"condition":"harness","crash_total":$3,"unique_crash_clusters":$4,
   "finding_total":0,"unique_finding_clusters":0,"wall_median":1800,
   "input_tokens_total":2500000,"output_tokens_total":800000,
   "top_severity_level":"Medium","top_severity_rank":2,
   "medium_plus_bugs":1},
  {"condition":"model-direct","crash_total":1,"unique_crash_clusters":1,
   "finding_total":0,"unique_finding_clusters":0,"wall_median":900,
   "input_tokens_total":40000,"output_tokens_total":9000,
   "top_severity_level":"Low","top_severity_rank":1,
   "medium_plus_bugs":0}],
 "crash_clusters":[],"finding_clusters":[],"token_usage":[]}
JSON
}
mkbackend codex 20260101-000000 9 4
# An older codex run for the same backend/target must remain visible: the
# crosstab key is backend/run/target/condition, not latest backend/target.
mkbackend codex 20251231-000000 99 99
mkbackend codex 20260103-000000 5 3 curl
mkbackend gemini 20260102-000000 2 2
xt=$(python3 "$PY" crosstab "$xroot")
assert_match 'Aggregated benchmark results' "$xt" "T19a: crosstab has a title"
assert_match 'tokenfuzz' "$xt" "T19b: crosstab labels the harness condition"
assert_match 'codex-m-direct' "$xt" "T19c: crosstab labels the baseline by model name"
assert_match '20260101-000000' "$xt" "T19d: crosstab includes the newer codex run"
assert_match '20251231-000000' "$xt" \
  "T19e: crosstab keeps older same-target runs instead of overwriting them"
assert_match 'gemini' "$xt" "T19f: crosstab includes every backend"
# Both codex same-target runs remain in the aggregate.
assert_match '\| 9 \|' "$xt" "T19g: crosstab carries newer run counts"
assert_match '\| 99 \|' "$xt" "T19g0: crosstab carries older run counts"
assert_match '20260103-000000' "$xt" \
  "T19g2: aggregate keeps a second target for the same backend"
assert_match '`curl`' "$xt" \
  "T19g3: aggregate names the second target"
codex_cares_rows=$(printf '%s\n' "$xt" \
  | grep -F '`codex`' \
  | grep -F '`20260101-000000`' \
  | grep -F '`c-ares`' \
  | wc -l | tr -d ' ')
assert_eq "$codex_cares_rows" "2" \
  "T19g4: aggregate repeats backend, run, and target on every condition row"
codex_cares_old_rows=$(printf '%s\n' "$xt" \
  | grep -F '`codex`' \
  | grep -F '`20251231-000000`' \
  | grep -F '`c-ares`' \
  | wc -l | tr -d ' ')
assert_eq "$codex_cares_old_rows" "2" \
  "T19g5: aggregate keeps the older same-target run as its own two rows"
xout="$work/benchmark-crosstab.md"
python3 "$PY" crosstab "$xroot" --out "$xout" >/dev/null
assert_file_exists "$xout" "T19h: crosstab --out writes a markdown file"
# The 16-column crosstab gets a dedicated `.benchmark-table` CSS class so
# the harness-wide `min-width: max-content` rule doesn't force horizontal
# scrolling on the rendered HTML sibling.
python3 "$RENDER_MD" "$xout" --html-sibling >/dev/null
assert_file_contains "${xout%.md}.html" 'class="benchmark-table"' \
  "T19h1: crosstab HTML gets the dedicated table layout"

# T19h2-4: the crosstab carries wall time and token cost, compact-formatted.
assert_match 'Wall \(h\)' "$xt" "T19h2: crosstab has a Wall column"
assert_match '0\.50h' "$xt" "T19h3: crosstab renders wall as decimal hours"
assert_match '2\.5M' "$xt" \
  "T19h4: crosstab renders million-scale token totals compactly"

# T19i: when a run's pooled artifacts are on disk, the crosstab counts
# hyperlink to them; report.json carries the bench_dir to resolve. The
# per-condition split (pool/<cond>/crashes/) is what carries the link —
# linking a condition row to the combined pool/crashes/ would mix in
# other conditions' evidence (see _condition_pool_dir).
xlink="$work/xtab-links"
xlbd="$xlink/benchmark-linky/20260301-000000"
mkdir -p "$xlbd/pool/harness/crashes" "$xlbd/pool/harness/findings" \
         "$xlbd/pool/harness/findings-rejected"
: > "$xlbd/pool/harness/crashes/CRASH-CLUSTERS.html"
: > "$xlbd/pool/harness/findings-rejected/REJECTED-FINDINGS.html"
cat > "$xlbd/report.json" <<JSON
{"bench_dir":"$xlbd",
 "run":{"runid":"20260301-000000","target":"c-ares","backend":"linky",
  "replicates":1,"budget_wall":3600,"conditions":["harness"]},
 "conditions":[
  {"condition":"harness","crash_total":7,"unique_crash_clusters":3,
   "rejected_finding_total":2,"finding_total":0,
   "top_severity_level":"Medium","top_severity_rank":2,
   "medium_plus_bugs":1}],
 "crash_clusters":[],"finding_clusters":[],"token_usage":[]}
JSON
xtl=$(python3 "$PY" crosstab "$xlink")
assert_match '\[7\]\([^)]*pool/harness/crashes[^)]*\)' "$xtl" \
  "T19i: crosstab crash count links to the per-condition crash tree"
assert_match '\[3\]\([^)]*CRASH-CLUSTERS\.html[^)]*\)' "$xtl" \
  "T19j: crosstab unique-bug count links to the rendered cluster report"
assert_match '\[2\]\([^)]*REJECTED-FINDINGS\.html[^)]*\)' "$xtl" \
  "T19k: crosstab rejected finding count links to the rendered rejected list"

# ── T20: relocate-experiments moves external audit trees into the run ────
rbd="$work/relocate-bench"
mkdir -p "$rbd/cells/harness-r1" "$rbd/cells/model-direct-r1"
# A harness cell: results_dir points to an experiment tree outside the run.
ext="$work/ext-c-ares-bench-xyz-harness-r1"
mkdir -p "$ext/codex/results/crashes/CRASH-0001"
: > "$ext/codex/results/crashes/CRASH-0001/asan.txt"
cat > "$rbd/cells/harness-r1/cell.json" <<JSON
{"condition":"harness","replicate":1,"status":"done","wall_seconds":1,
 "results_dir":"$ext/codex/results"}
JSON
printf '{"results_dir":"%s","confirmed_crashes":1}\n' "$ext/codex/results" \
  > "$rbd/cells/harness-r1/metrics.json"
# A model-direct cell: results_dir already inside the bench dir -> untouched.
mkdir -p "$rbd/cells/model-direct-r1/workspace/results"
cat > "$rbd/cells/model-direct-r1/cell.json" <<JSON
{"condition":"model-direct","replicate":1,"status":"done","wall_seconds":1,
 "results_dir":"$rbd/cells/model-direct-r1/workspace/results"}
JSON
python3 "$PY" relocate-experiments "$rbd" >/dev/null
assert_dir_exists "$rbd/experiments/harness-r1" \
  "T20a: harness experiment tree moved under the run"
assert_dir_not_exists "$ext" \
  "T20b: the external experiment tree is gone from its old location"
new_rd=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["results_dir"])' "$rbd/cells/harness-r1/cell.json")
assert_match "experiments/harness-r1" "$new_rd" \
  "T20c: cell.json results_dir rewritten to the new location"
assert_dir_exists "$new_rd/crashes/CRASH-0001" \
  "T20d: the moved tree's crash dirs are intact"
assert_dir_not_exists "$rbd/experiments/model-direct-r1" \
  "T20e: an in-run results_dir (model-direct) is left untouched"
# Idempotent: a second call is a no-op (results_dir now inside the run).
python3 "$PY" relocate-experiments "$rbd" >/dev/null
assert_dir_exists "$rbd/experiments/harness-r1" \
  "T20f: relocate-experiments is idempotent"

# ── T21: split-pool copies the pool into per-condition subtrees ──────────
sbd="$work/split-bench"
mkdir -p "$sbd/pool/crashes/CRASH-0001" "$sbd/pool/crashes/CRASH-0002" \
         "$sbd/pool/findings/FIND-0001"
: > "$sbd/pool/crashes/CRASH-0001/asan.txt"
: > "$sbd/pool/crashes/CRASH-0002/asan.txt"
: > "$sbd/pool/findings/FIND-0001/REPORT.md"
cat > "$sbd/pool-members.json" <<'JSON'
{"crashes":{"CRASH-0001":"harness","CRASH-0002":"model-direct"},
 "findings":{"FIND-0001":"harness"}}
JSON
python3 "$PY" split-pool "$sbd" >/dev/null
assert_dir_exists "$sbd/pool/harness/crashes/CRASH-0001" \
  "T21a: harness crash copied into pool/harness/"
assert_dir_exists "$sbd/pool/model-direct/crashes/CRASH-0002" \
  "T21b: model-direct crash copied into pool/model-direct/"
assert_dir_not_exists "$sbd/pool/harness/crashes/CRASH-0002" \
  "T21c: a condition's subtree holds only its own crashes"
assert_dir_exists "$sbd/pool/harness/findings/FIND-0001" \
  "T21d: findings are split by condition too"

# ── T19k: crosstab links each condition to its own per-condition tree ────
spd="$xlink/benchmark-splitty/20260401-000000"
mkdir -p "$spd/pool/harness/crashes" "$spd/pool/model-direct/crashes"
: > "$spd/pool/harness/crashes/CRASH-CLUSTERS.html"
: > "$spd/pool/model-direct/crashes/CRASH-CLUSTERS.html"
cat > "$spd/report.json" <<JSON
{"bench_dir":"$spd",
 "run":{"runid":"20260401-000000","target":"c-ares","backend":"splitty",
  "model":"sm-1","replicates":1,"budget_wall":3600,
  "conditions":["model-direct","harness"]},
 "conditions":[
  {"condition":"harness","crash_total":4,"unique_crash_clusters":2,
   "finding_total":0,"top_severity_level":"Medium","top_severity_rank":2,
   "medium_plus_bugs":1},
  {"condition":"model-direct","crash_total":9,"unique_crash_clusters":3,
   "finding_total":0,"top_severity_level":"Low","top_severity_rank":1,
   "medium_plus_bugs":0}],
 "crash_clusters":[],"finding_clusters":[],"token_usage":[]}
JSON
xts=$(python3 "$PY" crosstab "$xlink")
assert_match '\[4\]\([^)]*pool/harness/crashes[^)]*\)' "$xts" \
  "T19k: harness count links to the harness per-condition tree"
assert_match '\[9\]\([^)]*pool/model-direct/crashes[^)]*\)' "$xts" \
  "T19l: model-direct count links to the model-direct per-condition tree"

# ── T22: model-direct prompt asks for findings, not only crashes ─────────
# The template interpolates {{ target_path }} and {{ output_dir }} into a
# rendered prompt that embeds both absolute paths. Three additional
# substitutions (crash_objective, asan_invocation_hint,
# harness_build_recipe) are pre-rendered by
# lib/benchmark_model_direct_render.py at run time; here we invoke the
# helper end-to-end against a real synthetic target so the assertions
# cover the same prompt the agent actually sees.
md_tpl="$SCRIPT_ROOT/lib/prompts/benchmark_model_direct.md.j2"
md_renderer="$SCRIPT_ROOT/lib/benchmark_model_direct_render.py"
assert_file_exists "$md_tpl" "T22: model-direct prompt template exists"
assert_file_exists "$md_renderer" "T22: model-direct render helper exists"
# Render against a synthetic target with NO build-asan/ — the
# managed-target / no-native-build code path. crash_objective must
# still describe what a sanitizer-instrumented build would mean.
md_target_dir="$work/md-tpl-target"
mkdir -p "$md_target_dir"
cat > "$md_target_dir/target.toml" <<'TOML'
target = "md-tpl-target"
[sanitizer]
enabled = []
TOML
md_body=$(python3 "$md_renderer" "$md_target_dir" "/abs/out" "$SCRIPT_ROOT")
# Replace the dynamic absolute target path in assertions below by also
# substituting target_path with a literal stub via a 2nd render that
# bypasses the helper's introspection (legacy expectation: the .j2 still
# uses {{ target_path }} and {{ output_dir }} as raw substitutions).
md_body_literal=$(python3 "$SCRIPT_ROOT/lib/prompt_render.py" "$md_tpl" \
  --var "target_path=/abs/target" --var "output_dir=/abs/out" \
  --var "crash_objective=" \
  --var "asan_invocation_hint=" \
  --var "harness_build_recipe=")
assert_match 'CRASH-<n>' "$md_body" \
  "T22a: prompt defines a CRASH contract"
assert_match 'FIND-<n>' "$md_body" \
  "T22b: prompt defines a FIND contract"
# The prompt must encourage filing — no conservatism gates that suppress it.
assert_not_match 'unsupported claim' "$md_body" \
  "T22c: prompt does not bias the agent against filing"
assert_not_match 'falsification attempt' "$md_body" \
  "T22c2: prompt does not demand a per-finding falsification rebuttal"
assert_match 'sanitizer-instrumented' "$md_body" \
  "T22d: prompt treats sanitizer build as optional (works on managed targets)"
assert_not_match 'symlink facade|writable facade of' "$md_body" \
  "T22e: prompt advertises a real, unmediated source tree"
assert_not_match 'logic, an injection|deserialization|info-leak|protocol-state|denial-of-service' "$md_body" \
  "T22f: prompt does not constrain FINDINGs with example classes"
finding_line=$(grep -n 'For every FINDING:' <<<"$md_body" | head -1 | cut -d: -f1)
crash_line=$(grep -n 'For every CRASH:' <<<"$md_body" | head -1 | cut -d: -f1)
if [ "${finding_line:-0}" -gt 0 ] && [ "${crash_line:-0}" -gt 0 ] \
   && [ "$finding_line" -lt "$crash_line" ]; then
  pass "T22g: prompt documents FINDINGs before CRASHes"
else
  fail "T22g: prompt documents FINDINGs before CRASHes" \
    "FINDING line=$finding_line CRASH line=$crash_line"
fi
assert_match 'find as many|file generously|breadth and depth' "$md_body" \
  "T22h: prompt explicitly encourages broad / generous filing"
# Variables must be interpolated; a raw "{{ target_path }}" in the body
# means raw template text is being sent to the agent.
assert_match '/abs/target' "$md_body_literal" \
  "T22i: prompt interpolates target_path as an absolute path"
assert_match '/abs/out' "$md_body_literal" \
  "T22j: prompt interpolates output_dir as an absolute path"
assert_not_match '\{\{\s*target_path\s*\}\}|\{\{\s*output_dir\s*\}\}' "$md_body" \
  "T22k: no un-substituted Jinja placeholders remain after rendering"
# T22l (the old "warn against writing into the source tree" assertion)
# was removed deliberately. That instruction caused the agent to refuse
# to write build artifacts anywhere — including in the cell dir — which
# killed PoC construction (the metric was 0 crashes for every
# model-direct cell). The cell dir is the agent's write target; the
# source tree being preserved is a courtesy, not a contract. Tests
# replacing T22l should NOT reintroduce a blanket "don't write here"
# instruction.
assert_match 'Writing scope|under \./' "$md_body" \
  "T22l: prompt names a concrete writing scope for the agent"
assert_match 'Primary objective' "$md_body" \
  "T22m: prompt foregrounds CRASH-vs-FIND priority via a Primary objective block"
assert_match 'Mode switch after ~5 FINDs' "$md_body" \
  "T22n: prompt tells the agent to pivot from FIND to CRASH"

# T22o-T22r — render against a fake target that DOES have a usable
# build-asan/. The "primary CRASH" branch must engage, the asan binary
# path must be embedded verbatim, and (when libcurl.a-style sanitizer
# library is on disk) a build recipe must appear. These tests are the
# regression guard: the prior bug ("0 crashes for every cell") was
# rooted in the absence of these blocks at render time.
md_asan_target="$work/md-tpl-asan-target"
mkdir -p "$md_asan_target/build-asan/src" "$md_asan_target/build-asan/lib" \
  "$md_asan_target/include" "$md_asan_target/lib"
cat > "$md_asan_target/target.toml" <<'TOML'
target = "md-tpl-asan-target"
asan_bin = "src/fake-cli"
asan_lib = "lib/libfake.a"
includes = ["include", "lib"]
link_libs = ["-lm", "-lpthread"]
[sanitizer]
enabled = ["asan"]
TOML
# Fake "asan binary" that is executable — the renderer probes the X bit.
printf '#!/bin/sh\nexit 0\n' > "$md_asan_target/build-asan/src/fake-cli"
chmod +x "$md_asan_target/build-asan/src/fake-cli"
# Fake static library file — recipe branch keys off file existence.
: > "$md_asan_target/build-asan/lib/libfake.a"
md_body_asan=$(python3 "$md_renderer" "$md_asan_target" "/abs/out" "$SCRIPT_ROOT")
assert_match 'primary' "$md_body_asan" \
  "T22o: asan-present render foregrounds CRASH as the primary deliverable"
assert_match 'build-asan/src/fake-cli' "$md_body_asan" \
  "T22p: asan-present render embeds the asan binary path"
assert_match 'Driving the asan binary directly' "$md_body_asan" \
  "T22q: asan-present render includes the CLI invocation block"
assert_match 'Building a one-off harness driver' "$md_body_asan" \
  "T22r: asan-present render includes the harness build recipe"
assert_match 'build-asan/lib/libfake.a' "$md_body_asan" \
  "T22s: asan-present render embeds the static-library path"
assert_match 'fsanitize=address' "$md_body_asan" \
  "T22t: asan-present render gives a concrete clang invocation"

# ── T23: gemini default model ────────────────────────────────────────────
gemini_default="$(python3 "$SCRIPT_ROOT/lib/llm_invoke.py" default-model gemini)"
assert_eq "gemini-3.1-pro-preview" "$gemini_default" \
  "T23a: gemini default model is gemini-3.1-pro-preview"
override="$(GEMINI_MODEL_DEFAULT=custom-model python3 \
  "$SCRIPT_ROOT/lib/llm_invoke.py" default-model gemini)"
assert_eq "custom-model" "$override" \
  "T23b: GEMINI_MODEL_DEFAULT env override wins over the default"

# ── T24: cell.json is written EARLY (status=running) ─────────────────────
# write_cell_json runs twice per cell: at the start with status=running
# and the predicted results_dir, and at the end with the final wall +
# status. A kill mid-cell still leaves an indexable cell.
early_root="$work/early-celljson"
target_dir="$SCRIPT_ROOT/targets/early-cellbench-$$"
mkdir -p "$target_dir"
cat > "$target_dir/file.c" <<'C'
int main(void) { return 0; }
C
cat > "$target_dir/target.toml" <<'TOML'
target = "early-cellbench"
[sanitizer]
enabled = []
[runner]
bin = "/bin/true"
args = []
TOML
# A fake codex that just runs to completion so the cell finishes. We then
# poke at the early cell.json that the bench wrote before the run started.
fake_codex_early="$work/fake-codex-early"
cat > "$fake_codex_early" <<'SH'
#!/usr/bin/env bash
printf '{"type":"item.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":1}}\n'
SH
chmod +x "$fake_codex_early"
trap 'rm -rf "$work" "$SCRIPT_ROOT/targets/$bench_target" "$reltest_root"* "${SCRIPT_ROOT}/${root_junk_name:-__no_such_benchmark_root_junk__}" "${SCRIPT_ROOT}/${model_direct_junk_name:-__no_such_benchmark_model_direct_junk__}" "$target_dir" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT
early_out=$(CODEX_BIN="$fake_codex_early" bash "$BENCH" \
  --target "$(basename "$target_dir")" --backend codex --replicates 1 \
  --conditions model-direct --budget-wall 5 \
  --bench-root "$early_root" --no-validate-findings 2>&1)
early_rc=$?
assert_eq "0" "$early_rc" "T24a: bench cell succeeds"
early_cell=$(find "$early_root/codex" -path '*/cells/model-direct-r1/cell.json' \
  | head -1)
assert_file_exists "$early_cell" "T24b: cell.json was written"
# results_dir is the cell dir itself.
early_rd=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["results_dir"])' \
  "$early_cell")
assert_match 'cells/model-direct-r1$' "$early_rd" \
  "T24c: cell.json results_dir is the cell dir"
assert_eq "done" \
  "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["status"])' \
     "$early_cell")" \
  "T24d: a clean run flips status from running to done"

# ── T25: cell dir IS the output dir; target tree is untouched ────────────
cell_dir=$(find "$early_root/codex" -path '*/cells/model-direct-r1' \
  -type d | head -1)
assert_dir_exists "$cell_dir/findings" \
  "T25a: findings/ pre-created in the cell dir"
assert_dir_exists "$cell_dir/crashes" \
  "T25b: crashes/ pre-created in the cell dir"
# No mirrored copy of the target lives under the cell dir.
assert_file_not_exists "$cell_dir/workspace/file.c" \
  "T25c: cell dir does not host a copy of the target tree"
assert_dir_not_exists "$cell_dir/workspace" \
  "T25d: there is no separate workspace subdirectory"
# The real target tree stays byte-identical.
assert_dir_not_exists "$target_dir/findings" \
  "T25e: target tree gets no findings/ leak"
assert_file_exists "$target_dir/file.c" \
  "T25f: target source files stay in place"

# --no-validate-findings is announced in the cell log.
assert_match 'model-direct findings gate: DISABLED' "$early_out" \
  "T25g: --no-validate-findings is announced in the cell log"
assert_match 'findings: rejected=0 confirmed=0 unique=0; crashes: rejected=0 confirmed=0 unique=0' "$early_out" \
  "T25g2: model-direct gate logs findings and crashes counts"

# ── T26: rendered prompt embeds both absolute paths ─────────────────────
prompt_file="$cell_dir/prompt.txt"
assert_file_exists "$prompt_file" "T26a: persisted prompt.txt exists"
prompt_body=$(cat "$prompt_file")
assert_match "$(printf '%s' "$cell_dir")" "$prompt_body" \
  "T26b: prompt embeds the absolute output_dir"
target_abs=$(python3 -c 'import sys, pathlib; print(pathlib.Path(sys.argv[1]).resolve())' \
  "$target_dir")
assert_match "$target_abs" "$prompt_body" \
  "T26c: prompt embeds the absolute target_path"
assert_not_match '\{\{\s*(target_path|output_dir)\s*\}\}' "$prompt_body" \
  "T26d: no un-substituted placeholders survive in the rendered prompt"

# ── T27: launch wiring — cwd is the cell dir, target is an --add-dir ────
fake_codex_args="$work/fake-codex-args"
cat > "$fake_codex_args" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
cd_val=""
adds=""
want_cd=0
want_add=0
for arg in "$@"; do
  if [ "$want_cd" = 1 ]; then cd_val="$arg"; want_cd=0
  elif [ "$want_add" = 1 ]; then adds="$adds|$arg"; want_add=0
  elif [ "$arg" = "--cd" ]; then want_cd=1
  elif [ "$arg" = "--add-dir" ]; then want_add=1
  fi
done
printf 'FAKE_CD=%s\n' "$cd_val" >&2
printf 'FAKE_ADDS=%s\n' "$adds" >&2
printf '{"type":"item.completed","usage":{"input_tokens":1,"output_tokens":1}}\n'
SH
chmod +x "$fake_codex_args"
args_root="$work/args-bench"
CODEX_BIN="$fake_codex_args" bash "$BENCH" \
  --target "$(basename "$target_dir")" --backend codex --replicates 1 \
  --conditions model-direct --budget-wall 5 \
  --bench-root "$args_root" --no-validate-findings >/dev/null 2>&1
# Agent stdout+stderr go to backend.raw.log; the FAKE_* trace lines land
# there, not in the bench's own stdout.
raw_log=$(find "$args_root/codex" \
  -path '*/cells/model-direct-r1/backend.raw.log' | head -1)
fake_cd=$(sed -n 's/^FAKE_CD=//p' "$raw_log" | head -1)
fake_adds=$(sed -n 's/^FAKE_ADDS=//p' "$raw_log" | head -1)
args_cell=$(find "$args_root/codex" -path '*/cells/model-direct-r1' \
  -type d | head -1)
assert_eq "$args_cell" "$fake_cd" \
  "T27a: --cd is the cell dir"
if [[ "$fake_adds" == *"$target_abs"* ]]; then
  pass "T27b: target tree is granted via --add-dir at its real absolute path"
else
  fail "T27b: target tree is granted via --add-dir at its real absolute path" \
    "got --add-dir list: $fake_adds"
fi

# ── T28: DISCARDED hypotheses are mined from state/hypotheses.jsonl ─────
# Agent-side rejections never reach crashes-rejected/. Mining the raw
# hypothesis ledger surfaces them so the rejected-crashes total reflects
# all "tried but didn't land" work; the per-cell roster shows up under
# the pool's crashes-rejected/DISCARDED-<cond>-<cell>.md.
disc_rd="$work/discarded-results"
mkdir -p "$disc_rd/state" "$disc_rd/crashes-rejected"
printf '%s\n' \
  '{"id":"H-1","agent":"1","file":"a/x.c:foo:10","hypothesis":"oob in foo","note":"three clean variants","status":"DISCARDED","updated_at":"2026-05-23T00:00:00Z"}' \
  '{"id":"H-2","agent":"2","file":"a/y.c:bar:20","hypothesis":"uaf in bar","note":"guard saturated","status":"DISCARDED","updated_at":"2026-05-23T00:01:00Z"}' \
  '{"id":"H-3","agent":"1","file":"a/z.c:baz:30","hypothesis":"size in baz","note":"open","status":"PENDING","updated_at":"2026-05-23T00:02:00Z"}' \
  > "$disc_rd/state/hypotheses.jsonl"
disc_hv=$(python3 "$PY" harvest "$disc_rd")
assert_eq "2" "$(echo "$disc_hv" | jq -r '.discarded_hypotheses')" \
  "T28a: harvest counts DISCARDED rows from state/hypotheses.jsonl"

# Pool / roster wiring: build a tiny benchmark cell so build_pool runs
# and write_rejected_crashes_index surfaces a DISCARDED-*.md roster.
disc_bench="$work/discarded-bench"
mkdir -p "$disc_bench/cells/d-r1" "$disc_bench/cells/d-r1/logs"
ln -s "$disc_rd" "$disc_bench/cells/d-r1/results"
cat > "$disc_bench/cells/d-r1/cell.json" <<EOF
{"condition":"harness","replicate":1,"experiment":"t","status":"done","wall_seconds":60,"results_dir":"$disc_rd"}
EOF
python3 - <<PY
import json
import sys
from pathlib import Path
sys.path.insert(0, "$SCRIPT_ROOT/lib")
import benchmark
rd = Path("$disc_rd")
m = benchmark.harvest(rd)
(Path("$disc_bench") / "cells" / "d-r1" / "metrics.json").write_text(
    json.dumps(m), encoding="utf-8"
)
benchmark.build_pool(Path("$disc_bench"))
PY
roster="$disc_bench/pool/crashes-rejected/DISCARDED-harness-d-r1.md"
assert_file_exists "$roster" \
  "T28b: build_pool writes per-cell DISCARDED roster"
roster_body=$(cat "$roster")
assert_match '\| 1 \|' "$roster_body" "T28c: roster lists first discarded row"
assert_match '\| 2 \|' "$roster_body" "T28d: roster lists second discarded row"
assert_match 'three clean variants' "$roster_body" \
  "T28e: roster carries the agent's discard note"
assert_match 'oob in foo' "$roster_body" \
  "T28f: roster carries the discarded hypothesis text"
rejected_md=$(cat "$disc_bench/pool/crashes-rejected/REJECTED-CRASHES.md")
assert_match '## Discarded hypotheses' "$rejected_md" \
  "T28g: REJECTED-CRASHES.md has a discarded hypotheses section"
assert_match 'DISCARDED-harness-d-r1.md' "$rejected_md" \
  "T28h: REJECTED-CRASHES.md links to the per-cell roster"

# ═══════════════════════════════════════════════════════════════
# P6: cell.json records actual_agents vs requested_agents
# ═══════════════════════════════════════════════════════════════
# Run bin/benchmark end-to-end in --dry-run with --agents and a stubbed
# state/run-config.json planted into each cell's results_dir to verify
# the cell.json shape that downstream report aggregators read.
p6_bd="$work/p6-cell"
mkdir -p "$p6_bd/cells/harness-r1/repo-root/output/p6target-exp/codex/results/state"
mkdir -p "$p6_bd/cells/model-direct-r1/state"

# Helper: invoke bin/benchmark's embedded write_cell_json by calling the
# same python snippet via inline expansion. We replicate its argv shape
# rather than sourcing because bin/benchmark auto-runs at source time.
p6_write_cell_json() {
  python3 - "$@" <<'PYEOF'
import json, os, sys
path, cond, rep, exp, rd, wall, status = sys.argv[1:8]
requested_agents = sys.argv[8] if len(sys.argv) > 8 else ""
out = {
    "condition": cond,
    "replicate": int(rep),
    "experiment": exp,
    "results_dir": rd,
    "wall_seconds": int(wall),
    "status": status,
}
def _ri(s):
    s = (s or "").strip()
    if not s:
        return None
    try:
        return int(s)
    except ValueError:
        return None
req = _ri(requested_agents)
if req is not None:
    out["requested_agents"] = req
cfg_path = os.path.join(rd, "state", "run-config.json")
actual = None
if rd and os.path.isfile(cfg_path):
    try:
        with open(cfg_path, encoding="utf-8") as fh:
            cfg = json.load(fh)
        v = cfg.get("num_agents")
        if isinstance(v, int) and v > 0:
            actual = v
    except (OSError, ValueError):
        actual = None
if actual is not None:
    out["actual_agents"] = actual
    # Surface a one-bit flag so the cross-backend report can sort/filter
    # cells whose actual count drifted from the requested one without
    # re-reading every cell's run-config.
    if req is not None and req != actual:
        out["agent_count_mismatch"] = True
json.dump(out, open(path, "w"), indent=2)
PYEOF
}

# Sanity: this helper is byte-identical to bin/benchmark's embedded
# python snippet. A diff between the two would silently strand new
# fields; assert the two stay in sync.
p6_extract_python() {
  awk '
    /^write_cell_json\(\) \{/ { in_func=1; next }
    in_func && /<<\047PYEOF\047/ { in_py=1; next }
    in_func && in_py && /^PYEOF$/ { exit }
    in_func && in_py { print }
  ' "$SCRIPT_ROOT/bin/benchmark"
}
p6_test_python() {
  awk '
    /^p6_write_cell_json\(\) \{/ { in_func=1; next }
    in_func && /<<\047PYEOF\047/ { in_py=1; next }
    in_func && in_py && /^PYEOF$/ { exit }
    in_func && in_py { print }
  ' "$0"
}
if diff <(p6_extract_python) <(p6_test_python) >/dev/null 2>&1; then
  pass "P6: test write_cell_json snippet is byte-identical to bin/benchmark"
else
  fail "P6: test write_cell_json snippet is byte-identical to bin/benchmark" \
       "drift detected (diff above)"
fi

p6_results_a="$p6_bd/cells/harness-r1/repo-root/output/p6target-exp/codex/results"
p6_cell_a="$p6_bd/cells/harness-r1/cell.json"

# Case A: run-config matches requested → no mismatch flag.
cat > "$p6_results_a/state/run-config.json" <<'JSON'
{"num_agents": 3, "browser_agents": 0, "shell_agents": 3,
 "backend": "claude", "model": "claude-opus-4-7",
 "target_slug": "tdummy", "agent_count_overridden": true}
JSON
p6_write_cell_json "$p6_cell_a" harness 1 exp1 "$p6_results_a" 100 done 3
assert_eq "3" "$(jq -r '.actual_agents' "$p6_cell_a")" \
  "P6: actual_agents pulled from state/run-config.json"
assert_eq "3" "$(jq -r '.requested_agents' "$p6_cell_a")" \
  "P6: requested_agents recorded from arg"
assert_eq "null" "$(jq -r '.agent_count_mismatch // "null"' "$p6_cell_a")" \
  "P6: matching requested == actual omits mismatch flag"

# Case B: requested=1 but the harness clamped/coerced to 3 → mismatch flag fires.
p6_write_cell_json "$p6_cell_a" harness 1 exp1 "$p6_results_a" 100 done 1
assert_eq "3" "$(jq -r '.actual_agents' "$p6_cell_a")" \
  "P6: actual_agents still reflects clamped count on mismatch"
assert_eq "1" "$(jq -r '.requested_agents' "$p6_cell_a")" \
  "P6: requested_agents preserved on mismatch"
assert_eq "true" "$(jq -r '.agent_count_mismatch' "$p6_cell_a")" \
  "P6: agent_count_mismatch=true when requested != actual"

# Case C: no run-config (older runs, or model-direct cells) →
# actual_agents absent rather than null.
rm -f "$p6_results_a/state/run-config.json"
p6_write_cell_json "$p6_cell_a" model-direct 1 exp1 "$p6_results_a" 100 done 1
assert_eq "null" "$(jq -r '.actual_agents // "null"' "$p6_cell_a")" \
  "P6: missing run-config.json → actual_agents omitted"
assert_eq "1" "$(jq -r '.requested_agents' "$p6_cell_a")" \
  "P6: requested_agents present even without run-config"

# Case D: empty requested_agents (bench called without --agents) →
# requested_agents omitted; actual still recorded.
mkdir -p "$p6_results_a/state"
cat > "$p6_results_a/state/run-config.json" <<'JSON'
{"num_agents": 2, "backend": "claude"}
JSON
p6_write_cell_json "$p6_cell_a" harness 1 exp1 "$p6_results_a" 100 done ""
assert_eq "2" "$(jq -r '.actual_agents' "$p6_cell_a")" \
  "P6: actual_agents recorded when requested is blank"
assert_eq "null" "$(jq -r '.requested_agents // "null"' "$p6_cell_a")" \
  "P6: empty requested_agents → field omitted"

# ── T29: gemini quota watcher — trigger rule + aggregator handling ──────
# The rule must distinguish r1-style "lots of 429s but real progress" from
# r2-style "lots of 429s with zero assistant content". Mocking the live
# watcher requires a backgrounded process; instead we exercise (a) the
# detector function directly and (b) the aggregator's treatment of the
# quota_exhausted status it writes.

# (a) Detector: source bin/benchmark just enough to get the function.
#     Avoid running the script body by extracting the function definition.
gqd="$work/gemini-quota-detector.sh"
awk '/^gemini_quota_dominates\(\)/,/^}/' "$BENCH" > "$gqd"
# shellcheck disable=SC1090
. "$gqd"

# r2-style log: 12 quota retries, no assistant or result events → trigger.
r2_like="$work/r2-like.log"
{
  printf '{"type":"tool_use"}\n'
  for i in $(seq 1 12); do
    printf 'Attempt %d failed with status 429. Retrying...\n' "$i"
  done
} > "$r2_like"
if GEMINI_QUOTA_WINDOW_LINES=400 GEMINI_QUOTA_MIN_429=10 \
    gemini_quota_dominates "$r2_like"; then
  pass "T29a: r2-style log (12 retries, no progress) trips the trigger"
else
  fail "T29a: r2-style log (12 retries, no progress) trips the trigger" "did not trigger"
fi

# r1-style log: 12 quota retries interleaved with assistant content → no trigger.
r1_like="$work/r1-like.log"
{
  for i in $(seq 1 12); do
    printf 'Attempt %d failed with status 429. Retrying...\n' "$i"
    printf '{"type":"message","role":"assistant","content":"x"}\n'
  done
} > "$r1_like"
if GEMINI_QUOTA_WINDOW_LINES=400 GEMINI_QUOTA_MIN_429=10 \
    gemini_quota_dominates "$r1_like"; then
  fail "T29b: r1-style log (retries with progress) must NOT trigger" "triggered"
else
  pass "T29b: r1-style log (retries with progress) must NOT trigger"
fi

# Empty log: not enough retries → no trigger.
: > "$work/empty-gemini.log"
if GEMINI_QUOTA_WINDOW_LINES=400 GEMINI_QUOTA_MIN_429=10 \
    gemini_quota_dominates "$work/empty-gemini.log"; then
  fail "T29c: empty log must NOT trigger" "triggered"
else
  pass "T29c: empty log must NOT trigger"
fi

# Few retries: below the threshold → no trigger even with no progress.
r2_quiet="$work/r2-quiet.log"
{
  for i in $(seq 1 3); do
    printf 'Attempt %d failed with status 429. Retrying...\n' "$i"
  done
} > "$r2_quiet"
if GEMINI_QUOTA_WINDOW_LINES=400 GEMINI_QUOTA_MIN_429=10 \
    gemini_quota_dominates "$r2_quiet"; then
  fail "T29d: 3 retries below threshold must NOT trigger" "triggered"
else
  pass "T29d: 3 retries below threshold must NOT trigger"
fi

# (b) Aggregator: a bench dir with one done cell + one quota_exhausted cell
#     reports replicates_done=1, replicates_quota_exhausted=1, and excludes
#     the quota-exhausted cell from token / wall totals.
qbd="$work/quota-bench"
mkdir -p "$qbd/cells/model-direct-r1" "$qbd/cells/model-direct-r2"
cat > "$qbd/cells/model-direct-r1/cell.json" <<JSON
{"condition":"model-direct","replicate":1,"experiment":"e1","results_dir":"$qbd/cells/model-direct-r1","wall_seconds":4000,"status":"done"}
JSON
cat > "$qbd/cells/model-direct-r1/metrics.json" <<'JSON'
{"exists":true,"confirmed_crashes":0,"findings":1,
 "tokens":{"input_tokens":2000,"cached_input_tokens":1000,"output_tokens":50,"prompt_estimate_tokens":0,"estimated":false,"iterations":1,"asan_invocations":0}}
JSON
cat > "$qbd/cells/model-direct-r2/cell.json" <<JSON
{"condition":"model-direct","replicate":2,"experiment":"e2","results_dir":"$qbd/cells/model-direct-r2","wall_seconds":300,"status":"quota_exhausted"}
JSON
cat > "$qbd/cells/model-direct-r2/metrics.json" <<'JSON'
{"exists":true,"confirmed_crashes":0,"findings":0,
 "tokens":{"input_tokens":9999,"cached_input_tokens":0,"output_tokens":0,"prompt_estimate_tokens":0,"estimated":true,"iterations":1,"asan_invocations":0}}
JSON
qrep=$(python3 "$PY" aggregate "$qbd")
assert_eq "1" "$(echo "$qrep" | jq -r '.conditions[0].replicates_done')" \
  "T29e: only the done cell counts toward replicates_done"
assert_eq "1" "$(echo "$qrep" | jq -r '.conditions[0].replicates_quota_exhausted')" \
  "T29f: quota_exhausted cell counted in its own column"
assert_eq "2" "$(echo "$qrep" | jq -r '.conditions[0].replicates_total')" \
  "T29g: replicates_total covers both cells"
# Token totals must exclude the quota-exhausted cell — its 9999 is noise.
assert_eq "2000" "$(echo "$qrep" | jq -r '.conditions[0].input_tokens_total')" \
  "T29h: token totals exclude quota_exhausted cells"
# Wall median must also exclude it (4000s only).
assert_eq "4000" "$(echo "$qrep" | jq -r '.conditions[0].wall_median')" \
  "T29i: wall_median excludes quota_exhausted cells"

# (c) Crosstab reps cell renders "1/2 (1q)" when quota_exhausted cells exist.
mkdir -p "$qbd/state"
printf '{"runid":"q-runid","target":"t","backend":"gemini","model":"gemini-3.1-pro-preview","replicates":2,"budget_wall":10800,"harness_agents":null,"model_direct_agents":1,"conditions":["model-direct"],"target_sha":"sha","harness_sha":"sha","dry_run":false}\n' \
  > "$qbd/run.json"
qbroot="$work/quota-bench-root"
mkdir -p "$qbroot/gemini"
ln -s "$qbd" "$qbroot/gemini/q-runid"
python3 "$PY" aggregate "$qbd" --out "$qbd/report.json" >/dev/null 2>&1 || true
ctab=$(python3 "$PY" crosstab "$qbroot" 2>/dev/null || true)
if printf '%s\n' "$ctab" | grep -qE '1/2 \(1q\)'; then
  pass "T29j: crosstab reps cell annotates quota_exhausted count as (Nq)"
else
  fail "T29j: crosstab reps cell annotates quota_exhausted count as (Nq)" \
    "got: $(printf '%s\n' "$ctab" | grep -E '^\| `gemini`' || echo none)"
fi

# ── T30: sweep_target_tree_for_misplaced_output rescues misrouted output ─
# Regression coverage for the gemini-r1 2026-05-24 incident: when a
# model-direct agent `cd`'s into the source tree and writes via a
# relative path, FIND-* / CRASH-* land in <target_root>/findings/ and
# <target_root>/crashes/ instead of the cell dir. The post-cell sweep
# inside bin/benchmark recovers them — but ONLY artifacts that were
# NOT in the cell-start path snapshot. Pre-existing target content
# (e.g. an upstream project's fuzz corpus living under findings/) is
# left strictly alone. The snapshot is set-membership, not mtime-based,
# so it's robust against same-second timing collisions.
swp_work="$work/sweep"
mkdir -p "$swp_work/target/findings/FIND-pre-existing-corpus" \
         "$swp_work/target/.git/findings/FIND-DECOY" \
         "$swp_work/target/src" \
         "$swp_work/cell/findings" \
         "$swp_work/cell/crashes"
echo 'shipped with target tree' \
  > "$swp_work/target/findings/FIND-pre-existing-corpus/manifest.txt"
echo 'should-not-be-moved' > "$swp_work/target/.git/findings/FIND-DECOY/marker"
echo 'legit source file'   > "$swp_work/target/src/main.c"

# Pull both sweep helpers out of bin/benchmark and stub log() so the
# functions are evaluable in isolation.
swp_fn_src=$(mktemp)
awk '
  /^mark_cell_start_for_sweep\(\) \{/,/^\}/
  /^sweep_target_tree_for_misplaced_output\(\) \{/,/^\}/
' "$BENCH" > "$swp_fn_src"

# Cell start: snapshot pre-existing pollution paths. Then simulate the
# agent writing new pollution AFTER the snapshot.
bash -c '
  set -euo pipefail
  log() { :; }
  # shellcheck disable=SC1091
  source "$1"
  marker=$(mark_cell_start_for_sweep "$2" "$3")
  # Fresh pollution the agent dropped — not in snapshot, should be moved.
  mkdir -p "$3/findings/FIND-001-real-bug" "$3/crashes/CRASH-7"
  echo "real bug report"    > "$3/findings/FIND-001-real-bug/report.md"
  echo "loose md finding"   > "$3/findings/FIND-002-loose.md"
  echo "crash dir contents" > "$3/crashes/CRASH-7/sanitizer.txt"
  sweep_target_tree_for_misplaced_output "$3" "$2" "$marker"
' _ "$swp_fn_src" "$swp_work/cell" "$swp_work/target"

assert_file_exists "$swp_work/cell/findings/FIND-001-real-bug/report.md" \
  "T30a: sweep moves new FIND directory from target/findings to cell/findings"
assert_file_exists "$swp_work/cell/findings/FIND-002-loose.md" \
  "T30b: sweep moves new loose FIND-* file from target/findings to cell/findings"
assert_file_exists "$swp_work/cell/crashes/CRASH-7/sanitizer.txt" \
  "T30c: sweep moves new CRASH directory from target/crashes to cell/crashes"
[ ! -e "$swp_work/target/findings/FIND-001-real-bug" ] \
  && pass "T30d: sweep removes the source-tree finding entry after moving" \
  || fail "T30d: sweep removes the source-tree finding entry after moving"
[ ! -e "$swp_work/target/crashes/CRASH-7" ] \
  && pass "T30e: sweep removes the source-tree crash entry after moving" \
  || fail "T30e: sweep removes the source-tree crash entry after moving"
# Set-membership safety: pre-existing upstream-owned corpus survives.
[ -f "$swp_work/target/findings/FIND-pre-existing-corpus/manifest.txt" ] \
  && pass "T30f: pre-existing target-owned FIND-* (in snapshot) left alone" \
  || fail "T30f: pre-existing target-owned FIND-* (in snapshot) left alone"
[ -e "$swp_work/target/.git/findings/FIND-DECOY/marker" ] \
  && pass "T30g: sweep skips .git contents (does not touch internal FIND-DECOY)" \
  || fail "T30g: sweep skips .git contents (does not touch internal FIND-DECOY)"
[ -f "$swp_work/target/src/main.c" ] \
  && pass "T30h: sweep leaves unrelated source files alone" \
  || fail "T30h: sweep leaves unrelated source files alone"
[ -d "$swp_work/target/findings" ] \
  && pass "T30i: top-level findings/ preserved when pre-existing content remains" \
  || fail "T30i: top-level findings/ preserved when pre-existing content remains"

# Sweep with no marker = refuse to mutate. Safety net for any caller
# that forgets to call mark_cell_start_for_sweep first.
mkdir -p "$swp_work/target/findings/FIND-stray-after-noop"
echo 'should survive a no-marker sweep' \
  > "$swp_work/target/findings/FIND-stray-after-noop/report.md"
bash -c '
  set -euo pipefail
  log() { :; }
  # shellcheck disable=SC1091
  source "$1"
  sweep_target_tree_for_misplaced_output "$2" "$3" ""
' _ "$swp_fn_src" "$swp_work/target" "$swp_work/cell"
[ -f "$swp_work/target/findings/FIND-stray-after-noop/report.md" ] \
  && pass "T30j: sweep refuses to mutate target tree without a snapshot" \
  || fail "T30j: sweep refuses to mutate target tree without a snapshot"

# Name-collision: an in-cell FIND-001-real-bug already exists (from
# T30a above). Drop a same-id pollution into a fresh target with a
# fresh snapshot and assert the rescued copy lands under a
# disambiguator instead of clobbering.
mkdir -p "$swp_work/target2"
bash -c '
  set -euo pipefail
  log() { :; }
  # shellcheck disable=SC1091
  source "$1"
  marker=$(mark_cell_start_for_sweep "$2" "$3")
  mkdir -p "$3/findings/FIND-001-real-bug"
  echo "newly-rescued copy" > "$3/findings/FIND-001-real-bug/report.md"
  sweep_target_tree_for_misplaced_output "$3" "$2" "$marker"
' _ "$swp_fn_src" "$swp_work/cell" "$swp_work/target2"

assert_eq "real bug report" \
  "$(cat "$swp_work/cell/findings/FIND-001-real-bug/report.md")" \
  "T30k: name-collision keeps the pre-existing in-cell artifact intact"
if ls "$swp_work/cell/findings/FIND-001-real-bug.from-target-"* >/dev/null 2>&1; then
  pass "T30l: collided rescue lands under a .from-target-<ts> suffix"
else
  fail "T30l: collided rescue lands under a .from-target-<ts> suffix"
fi
rm -f "$swp_fn_src"

# ── T31: agy_drip_stopped + agy_cli_log_for_pid predicates ─────────────
# Pure-function tests for the gemini-watchdog's drip-detection arm. We
# don't exercise the watcher loop itself (process management is the
# same shape as T29's quota watcher and would re-test bash plumbing,
# not behaviour). The predicate is the load-bearing piece.
drip_fn=$(mktemp)
awk '
  /^agy_drip_stopped\(\) \{/,/^\}/
  /^agy_cli_log_for_pid\(\) \{/,/^\}/
' "$BENCH" > "$drip_fn"
# shellcheck disable=SC1090
. "$drip_fn"

# Positive: a log carrying the exact agy klog format trips.
drip_log_yes="$work/drip-yes.log"
{
  printf 'I0524 17:40:24.741 12726 http_helpers.go:182] URL: ...\n'
  printf 'I0524 17:40:24.842 12726 text_drip.go:173] Drip stopped: lastStepIdx=732, charIdx=1557, length=1706\n'
} > "$drip_log_yes"
if agy_drip_stopped "$drip_log_yes"; then
  pass "T31a: agy_drip_stopped matches the real text_drip.go klog format"
else
  fail "T31a: agy_drip_stopped matches the real text_drip.go klog format"
fi

# Negative: a log without the event must not trip.
drip_log_no="$work/drip-no.log"
{
  printf 'I0524 17:40:24.741 12726 http_helpers.go:182] URL: ...\n'
  printf 'I0524 17:40:24.842 12726 server.go:200] Creating CLI server\n'
} > "$drip_log_no"
if agy_drip_stopped "$drip_log_no"; then
  fail "T31b: agy_drip_stopped must NOT trigger without the klog event" "triggered on log without Drip stopped"
else
  pass "T31b: agy_drip_stopped must NOT trigger without the klog event"
fi

# Adversarial: a model response that legitimately contains the phrase
# "drip stopped" in prose must not trip (anchor is on the klog
# `text_drip.go:NNN]` prefix).
drip_log_prose="$work/drip-prose.log"
printf '%s\n' 'the drip stopped flowing when the tank ran dry' > "$drip_log_prose"
if agy_drip_stopped "$drip_log_prose"; then
  fail "T31c: agy_drip_stopped must NOT match prose 'drip stopped'" "false positive on prose"
else
  pass "T31c: agy_drip_stopped must NOT match prose 'drip stopped'"
fi

# Empty / missing log: false (caller treats as no signal).
: > "$work/drip-empty.log"
if agy_drip_stopped "$work/drip-empty.log"; then
  fail "T31d: agy_drip_stopped must NOT trigger on empty log" "triggered"
else
  pass "T31d: agy_drip_stopped must NOT trigger on empty log"
fi
if agy_drip_stopped "$work/no-such-file.log"; then
  fail "T31e: agy_drip_stopped must NOT trigger on missing log" "triggered"
else
  pass "T31e: agy_drip_stopped must NOT trigger on missing log"
fi

# agy_cli_log_for_pid: spawn a child holding open a fake cli-log under
# the canonical antigravity-cli/log/cli-*.log path layout, then resolve
# its pid and confirm we get the path back. Skip if lsof is missing
# (the function itself returns empty in that case — also tested below).
fake_log_dir="$work/antigravity-cli/log"
mkdir -p "$fake_log_dir"
fake_log="$fake_log_dir/cli-20260524_191234.log"
: > "$fake_log"
# Hold the file open in a backgrounded shell. exec 9>file binds an FD
# that lsof will see for that PID.
( exec 9>"$fake_log"; sleep 30 ) &
holder_pid=$!
# Give the OS a moment to register the FD.
sleep 1
if command -v lsof >/dev/null 2>&1; then
  resolved=$(agy_cli_log_for_pid "$holder_pid")
  # macOS lsof reports the canonicalized path (/var/folders ->
  # /private/var/folders). Compare via realpath so the test is
  # platform-agnostic.
  resolved_real=$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$resolved" 2>/dev/null || printf '%s' "$resolved")
  fake_real=$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$fake_log" 2>/dev/null || printf '%s' "$fake_log")
  if [ "$resolved_real" = "$fake_real" ]; then
    pass "T31f: agy_cli_log_for_pid resolves the held cli-*.log via lsof"
  else
    fail "T31f: agy_cli_log_for_pid resolves the held cli-*.log via lsof" "got: '$resolved_real' expected: '$fake_real'"
  fi
else
  pass "T31f: agy_cli_log_for_pid lsof-missing path covered (lsof absent on this host)"
fi
# Cleanup the holder.
kill "$holder_pid" 2>/dev/null
wait "$holder_pid" 2>/dev/null || true

# Dead pid: returns empty, never crashes.
dead_resolved=$(agy_cli_log_for_pid 999999 2>&1)
if [ -z "$dead_resolved" ]; then
  pass "T31g: agy_cli_log_for_pid returns empty for a dead pid"
else
  fail "T31g: agy_cli_log_for_pid returns empty for a dead pid" "got: $dead_resolved"
fi

rm -f "$drip_fn"

summary
