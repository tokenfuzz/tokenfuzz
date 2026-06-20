#!/usr/bin/env bash
# Tests for bin/benchmark + lib/benchmark.py + lib/benchmark_model_direct_usage.py:
#   - harvest: AddressSanitizer-confirmed crash counting, cluster parse,
#              finding/recon/rejected counts, token sums
#   - aggregate: per-condition fold, median/range
#   - ledger: append-only section rendering, header-once, reset/archive
#   - model-direct usage extraction across backend log shapes
#   - bin/benchmark --dry-run end-to-end and argument validation
#
# This file covers T0–T9 (harvest / aggregate / ledger / usage / dry-run).
# The slower end-to-end blocks were split into sibling suites so they run
# in parallel under tests/run-tests.sh instead of pinning one core:
#   - test_benchmark_aggregate.sh  (T10–T19: validation, pool, crosstab)
#   - test_benchmark_report.sh     (T22–T32: prompt render, launch, watchdog)
set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$TESTS_DIR/helpers.sh"

setup_test_env

PY="$SCRIPT_ROOT/lib/benchmark.py"
USAGE_PY="$SCRIPT_ROOT/lib/llm_usage.py"
BENCH="$SCRIPT_ROOT/bin/benchmark"
RENDER_MD="$SCRIPT_ROOT/bin/render-md"

work=$(mktemp -d)
trap 'wait 2>/dev/null || true; rm -rf "$work" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT

# ── Speed: launch every independent bin/benchmark invocation up front ────
# Each `bash bin/benchmark ... --dry-run` spawns ~30 python subprocesses
# (2.5–9s each), so running them serially pinned this suite near 30s. The
# four T9* end-to-end runs are independent — separate bench roots, no shared
# state — so they are launched here as background jobs and their captured
# stdout/exit codes are consumed at the original T9/T9s/T9t/T9n assertion
# sites below. Assertions, ordering, and invocations are unchanged; only
# the wall-clock is overlapped (with the cheap T0–T8 checks too).

# T9 fixture: fake git shim proving benchmark passes safe.directory.
dledger="$work/dry-ledger.md"
droot="$work/dry-bench"
fake_git_bin="$work/fake-git-bin"
mkdir -p "$fake_git_bin"
real_git="$(command -v git)"
fake_git_log="$work/fake-git.log"
cat > "$fake_git_bin/git" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_GIT_LOG"
case "$*" in
  *"-c safe.directory="*) ;;
  *) exit 128 ;;
esac
exec "$REAL_GIT" "$@"
SH
chmod +x "$fake_git_bin/git"
(
  set +e
  REAL_GIT="$real_git" FAKE_GIT_LOG="$fake_git_log" \
    PATH="$fake_git_bin:$PATH" bash "$BENCH" --target dummytarget --dry-run --replicates 2 \
    --agents 2 --conditions model-direct,harness --skip-recon --ledger "$dledger" \
    --bench-root "$droot" > "$work/t9-dry.out" 2>&1
  echo $? > "$work/t9-dry.rc"
) &
t9_job=$!

# T9s fixture: two seed runs (different backend + target) under one root.
# Sequential WITHIN the job: both rebuild the same cross-backend page.
allroot="$work/regen-all"
(
  set +e
  bash "$BENCH" --target dummytarget --dry-run --replicates 1 --conditions harness \
    --backend codex --bench-root "$allroot" --run-id ra-codex >/dev/null 2>&1
  bash "$BENCH" --target othertarget --dry-run --replicates 1 --conditions harness \
    --backend gemini --bench-root "$allroot" --run-id ra-gemini >/dev/null 2>&1
) &
t9s_seed_job=$!

# T9t: the multi-target driver run.
multiroot="$work/multi-target"
(
  set +e
  bash "$BENCH" --target " dummytarget , othertarget " --dry-run \
    --replicates 1 --conditions harness --backend codex --skip-recon \
    --bench-root "$multiroot" --run-id mt > "$work/t9t-multi.out" 2>&1
  echo $? > "$work/t9t-multi.rc"
) &
t9t_job=$!

# T9n fixture: a pre-seeded incomplete resume cell, then its rerun.
resume_root="$work/dry-resume-bench"
resume_run="resume-$$"
resume_cell="$resume_root/codex/$resume_run/cells/harness-r1"
mkdir -p "$resume_cell/repo-root/output/dummytarget-bench-$resume_run-harness-r1/codex/results"
cat > "$resume_cell/cell.json" <<JSON
{"condition":"harness","replicate":1,"experiment":"bench-$resume_run-harness-r1","results_dir":"$resume_cell/repo-root/output/dummytarget-bench-$resume_run-harness-r1/codex/results","wall_seconds":0,"status":"running"}
JSON
printf 'stale result that must not survive in live cell\n' \
  > "$resume_cell/repo-root/output/dummytarget-bench-$resume_run-harness-r1/codex/results/stale-sentinel.txt"
(
  set +e
  bash "$BENCH" --target dummytarget --dry-run --backend codex \
    --replicates 1 --conditions harness --bench-root "$resume_root" \
    --run-id "$resume_run" > "$work/t9n-resume.out" 2>&1
  echo $? > "$work/t9n-resume.rc"
) &
t9n_job=$!

assert_file_contains "$BENCH" 'LLM_DECIDE_LOG="\$BENCH_DIR/llm-decisions\.log"' \
  "T0a: benchmark cluster-findings keeps keyer telemetry under the run dir"
assert_file_contains "$BENCH" 'ACTIVE_BACKEND="\$BACKEND" BACKEND="\$BACKEND" MODEL="\$model"' \
  "T0b: benchmark cluster-findings exports backend/model context"
assert_file_not_contains "$BENCH" 'cluster-findings".*2>/dev/null' \
  "T0c: benchmark cluster-findings stderr is not hidden"

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
printf 'WARN: MODEL_REFUSAL backend=codex refused to answer prompt: Review this project...\n' \
  > "$rd/backend.raw.log.refusals.log"
printf 'noise\nWARN: MODEL_REFUSAL backend=codex refused to answer prompt: Validate this finding...\n' \
  > "$rd/logs/refusals.log"

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
assert_eq "2" "$(echo "$hv" | jq -r '.model_refusals')" \
  "T1l: model refusal warning sidecars counted"

# ── T1s: harvest finds index.jsonl when logs/ is a sibling of results/ ───
# A harness run lays out output/<target>-<exp>/<backend>/{results,logs} —
# logs/ is a sibling of results/, not a child. harvest must still find the
# token index there; otherwise every harness cell scores as zero tokens.
sib="$work/harness-exp/codex"
mkdir -p "$sib/results/crashes" "$sib/logs"
printf '{"backend":"codex","tokens":{"input":4000,"cached_input":3800,"output":120},"probe":{"asan_invocations":5}}\n' \
  > "$sib/logs/index.jsonl"
printf 'WARN: MODEL_REFUSAL backend=codex refused to answer prompt: Harness prompt...\n' \
  > "$sib/logs/refusals.log"
shv=$(python3 "$PY" harvest "$sib/results")
assert_eq "200" "$(echo "$shv" | jq -r '.tokens.input_tokens')" \
  "T1s: harvest reads token index from a sibling logs/ dir (fresh input)"
assert_eq "120" "$(echo "$shv" | jq -r '.tokens.output_tokens')" \
  "T1s2: harvest sums output tokens from the sibling index"
assert_eq "5" "$(echo "$shv" | jq -r '.tokens.asan_invocations')" \
  "T1s3: harvest sums asan invocations from the sibling index"
assert_eq "1" "$(echo "$shv" | jq -r '.model_refusals')" \
  "T1s4: harvest reads model refusals from sibling logs/ dir"

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
assert_eq "120" "$(echo "$nhv" | jq -r '.tokens.cache_creation_tokens')" \
  "T1o2: harvest preserves cache-write tokens for pricing"
assert_eq "830" "$(echo "$nhv" | jq -r '.tokens.output_tokens')" \
  "T1p: output tokens summed across backends"

crd="$work/tok-cost/results"
mkdir -p "$crd/logs"
printf '%s\n' \
  '{"backend":"claude","model":"claude-opus-4-8","tokens":{"input":1000,"cached_input":2000,"cache_creation":400,"output":3000}}' \
  > "$crd/logs/index.jsonl"
chv=$(python3 "$PY" harvest "$crd" --backend claude --model claude-opus-4-8)
assert_eq "0.083500" "$(echo "$chv" | jq -r '.tokens.cost_usd')" \
  "T1q: harvest prices fresh input + cache writes + cache reads + output"

g5d="$work/gpt55-cost/results"
mkdir -p "$g5d/logs"
printf '%s\n' \
  '{"backend":"codex","model":"gpt-5.5","tokens":{"input":270000,"cached_input":260000,"output":1000}}' \
  '{"backend":"codex","model":"gpt-5.5","tokens":{"input":300000,"cached_input":290000,"output":1000}}' \
  > "$g5d/logs/index.jsonl"
g5v=$(python3 "$PY" harvest "$g5d" --backend codex --model gpt-5.5)
assert_eq "0.645000" "$(echo "$g5v" | jq -r '.tokens.cost_usd')" \
  "T1q2: harvest applies GPT-5.5 long-context pricing per Codex request"

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
  local refusals="${7:-0}"
  mkdir -p "$d"
  cat > "$d/cell.json" <<JSON
{"condition":"$2","replicate":$3,"status":"$4","wall_seconds":42}
JSON
  cat > "$d/metrics.json" <<JSON
{"confirmed_crashes":$5,"crash_clusters":$5,"findings":0,
 "findings_rejected":$rejected,
 "model_refusals":$refusals,
 "tokens":{"output_tokens":111}}
JSON
}
mk_cell model-direct-r1            model-direct           1 done 0 2 1
mk_cell model-direct-r2            model-direct           2 done 0
mk_cell harness-r1 harness 1 done 3 0 2
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
assert_eq "2" "$(echo "$hd" | jq -r '.model_refusal_total')" \
  "T4g: aggregate carries harness model refusal totals"
assert_eq "1" "$(echo "$nv" | jq -r '.model_refusal_total')" \
  "T4h: aggregate carries model-direct model refusal totals"

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

- **Source:** recon stage
- **Recon ID:** RECON-deadbeefcafef00d
- **Slice:** slice-1
EOF_REJ
cat > "$rrd/findings-rejected/FIND-raw/validator-vote-1.json" <<'JSON'
{"vote":"Reject","rationale":"dirty worktree mutation, not target input. This rationale intentionally keeps enough detail to exceed the old table truncation limit, because rejected finding pages are audit evidence and must preserve the full validator explanation all the way through the final sentinel: FULL-RATIONALE-END",
 "verified":{"reachability":false,"guards":true,"primitive":false}}
JSON
cat > "$rrd/findings-rejected/FIND-raw/.llm-find-quality.json" <<'JSON'
{"decision_version":"v7","accept":false,
 "reason":"FIND-gate fallback reason for rejection",
 "class":"memory-safety:lifetime","severity":"low",
 "decision":"find_quality"}
JSON
# Plant a recon REPORT for the linker to find — it should rewrite the
# bare "Recon ID:" line in the pooled report.md to a markdown link.
mkdir -p "$rrd/recon/RECON-deadbeefcafef00d"
echo "# RECON-deadbeefcafef00d — synthetic recon vote" \
  > "$rrd/recon/RECON-deadbeefcafef00d/REPORT.md"
python3 "$PY" pool "$rbd" >/dev/null
assert_file_exists "$rbd/pool/findings-rejected/REJECTED-FINDINGS.md" \
  "T4g: rejected finding markdown index written for combined pool"
assert_file_contains "$rbd/pool/findings-rejected/REJECTED-FINDINGS.md" \
  'FULL-RATIONALE-END' \
  "T4h: rejected finding index keeps the full validator rationale"
pooled_rej_dir=$(find "$rbd/pool/findings-rejected" -mindepth 1 -maxdepth 1 \
  -type d -name 'FIND-*' | head -n 1)
pooled_rej_id="$(basename "$pooled_rej_dir")"
assert_file_contains "$rbd/pool/findings-rejected/REJECTED-FINDINGS.md" \
  "\\[Link\\]\\(${pooled_rej_id}/report.md\\)" \
  "T4h2: rejected finding index labels report links plainly"
assert_file_contains "$rbd/pool/findings-rejected/REJECTED-FINDINGS.md" \
  '[|] *ID *[|] *Site *[|] *Reason *[|] *Report *[|]' \
  "T4h2b: rejected finding index uses the unified ID | Site | Reason | Report header"
# Recon ID linker: pooled report.md now hyperlinks to the source recon REPORT.
assert_file_contains "$pooled_rej_dir/report.md" \
  '\[RECON-deadbeefcafef00d\]' \
  "T4h3: pooled report.md hyperlinks the Recon ID to the recon REPORT"
python3 "$RENDER_MD" "$pooled_rej_dir/report.md" \
  --html-sibling >/dev/null
python3 "$RENDER_MD" "$rbd/pool/findings-rejected/REJECTED-FINDINGS.md" \
  --html-sibling >/dev/null
assert_file_exists "$pooled_rej_dir/report.html" \
  "T4h4: rejected report markdown can be rendered for browser links"
assert_file_contains "$rbd/pool/findings-rejected/REJECTED-FINDINGS.html" \
  'class="rejected-table"' \
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
assert_eq "1" "$sec_count" "T6e: re-rendering the same runid replaces its section (no duplicate)"
# A different runid still accumulates as a new section.
bd_b="$work/ledger-bd-b"
cp -r "$bd" "$bd_b"
jtmp="$(mktemp)"; jq '.runid="run2"' "$bd_b/run.json" > "$jtmp" && mv "$jtmp" "$bd_b/run.json"
python3 "$PY" ledger "$bd_b" --ledger "$ledger" >/dev/null
sec_count2=$(grep -c 'Benchmark run' "$ledger")
assert_eq "2" "$sec_count2" "T6f: a different runid accumulates as a new section"

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
# (Invocation + fake-git fixture launched in the background at the top of
# this file; collected here. Same flags, same assertions.)
wait "$t9_job" 2>/dev/null || true
dry_out=$(cat "$work/t9-dry.out")
rc=$(cat "$work/t9-dry.rc")
assert_eq "0" "$rc" "T9a: dry-run exits 0"
assert_file_exists "$dledger" "T9b: dry-run writes the ledger"
assert_match "crash median=1" "$dry_out" "T9c: harness scores 1 crash/cell in dry-run"
assert_match "model-direct .*crash median=0" "$dry_out" "T9d: model-direct scores 0 in dry-run"
assert_match "harness recon: skipped \\(--skip-recon\\)" "$dry_out" \
  "T9d2: --skip-recon is accepted and logged"
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
# Pins the update_benchmark_result change-guard: the pre-ledger + final passes
# follow no new cell, so their inputs are unchanged and the full rebuild must be
# skipped. Without the guard every one of the N+2 calls re-rendered the pool —
# the benchmark's recurring slowness. If this drops below 2, someone removed the
# guard or added unconditional work that re-dirties the inputs; the suite must
# go red BEFORE the slowness ships, not after the next person notices 90s tests.
dry_skips=$(printf '%s\n' "$dry_out" \
  | grep -c 'benchmark-result update (.*): inputs unchanged, skipped rebuild' || true)
if [ "$dry_skips" -ge 2 ]; then
  pass "T9f5: redundant pre-ledger/final re-renders are skipped (no N+2 rebuild bloat)"
else
  fail "T9f5: redundant pre-ledger/final re-renders must be skipped" \
    "expected >=2 'inputs unchanged' skips, saw $dry_skips in: $dry_out"
fi
drun_json=$(find "$droot/codex" -mindepth 2 -maxdepth 2 -name run.json | head -1)
assert_file_exists "$drun_json" "T9g: dry-run writes run metadata"
assert_eq "2" "$(jq -r '.harness_agents' "$drun_json")" \
  "T9h: --agents is recorded as the harness worker count"
assert_eq "1" "$(jq -r '.model_direct_agents' "$drun_json")" \
  "T9i: model-direct remains a one-agent baseline"
assert_match '^[0-9a-f]{40}$' "$(jq -r '.tokenfuzz_sha' "$drun_json")" \
  "T9i2: dry-run records the full TokenFuzz repo hash"
assert_eq "true" "$(jq -r '.skip_recon' "$drun_json")" \
  "T9i2b: --skip-recon is recorded in run metadata"
assert_file_contains "$fake_git_log" 'safe[.]directory=' \
  "T9i3: benchmark asks git to trust the mounted TokenFuzz checkout"
assert_file_contains "$dledger" 'Harness agents.*2' \
  "T9j: ledger exposes the harness worker count"

# Atomic pool swap: rebuild_pool_artifacts builds the whole tree in
# .pool.staging and swaps it into pool/ with one rename, so a reader never
# sees a half-rebuilt pool. After a clean run the live pool/ exists and no
# staging/backup dotdirs linger.
dbench="$(dirname "$drun_json")"
assert_dir_exists "$dbench/pool" \
  "T9k: end-to-end run lands a complete pool/ (atomic swap completed)"
assert_file_not_exists "$dbench/.pool.staging" \
  "T9l: staging dir does not linger after the swap"
assert_file_not_exists "$dbench/.pool.old" \
  "T9m: backup dir is cleaned up after the swap"

# ── T9r: --regenerate re-derives an existing run without launching cells ──
# After the T9 run, re-derive its results from the artifacts on disk. No
# cells must be launched, the export-repro REPORT bundle rebuild must be
# skipped, run.json must keep its original metadata, and benchmark-result.*
# must be refreshed. This is the "code changed, refresh the rollups" path.
regen_runid="$(basename "$dbench")"
cells_before=$(find "$dbench/cells" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
runjson_before=$(jq -rS . "$dbench/run.json")
# Overlap: T9s's regenerate-all (independent bench root, seeded at the top
# of the file) runs in the background while T9r's regenerate runs here.
# Its cells-before snapshot must precede its launch, so take it now.
wait "$t9s_seed_job" 2>/dev/null || true
codex_cells_before=$(find "$allroot/codex/ra-codex/cells" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
(
  set +e
  bash "$BENCH" --regenerate --bench-root "$allroot" > "$work/t9s-all.out" 2>&1
  echo $? > "$work/t9s-all.rc"
) &
t9s_all_job=$!
regen_out=$(bash "$BENCH" --target dummytarget --regenerate \
  --bench-root "$droot" --run-id "$regen_runid" 2>&1)
regen_rc=$?
assert_eq "0" "$regen_rc" "T9r-a: --regenerate exits 0"
assert_match 'no cells launched' "$regen_out" \
  "T9r-b: --regenerate does not launch cells"
# --regenerate now runs the bundle pass too, but it is strictly additive: the
# per-crash signature guard skips every already-bundled crash, so it never
# re-bundles or re-renders an existing good report. It DOES bundle a crash that
# has no canonical bundle yet — the freeform model-direct baseline in a real
# run — giving it the reproduce.sh / REPORT.md it otherwise never gets.
assert_not_match 'skipping export-repro REPORT bundle rebuild' "$regen_out" \
  "T9r-c: --regenerate no longer wholesale-skips the bundle pass"
assert_match 'reproducer bundles created' "$regen_out" \
  "T9r-c2: --regenerate bundles a crash that had no canonical bundle yet"
assert_file_exists "$dbench/pool/crashes/CRASH-0001/reproduce.sh" \
  "T9r-c3: the newly bundled crash gains a reproduce.sh under --regenerate"
assert_not_match 'cell .* — starting' "$regen_out" \
  "T9r-d: --regenerate prints no cell-start lines"
cells_after=$(find "$dbench/cells" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
assert_eq "$cells_before" "$cells_after" \
  "T9r-e: --regenerate adds no new cell directories"
runjson_after=$(jq -rS . "$dbench/run.json")
assert_eq "$runjson_before" "$runjson_after" \
  "T9r-f: --regenerate leaves run.json metadata untouched"
assert_file_exists "$droot/benchmark-result.md" \
  "T9r-g: --regenerate rebuilds the cross-backend benchmark-result.md"
assert_match 'benchmark-result update \(.*\): .*benchmark-result\.html' "$regen_out" \
  "T9r-h: --regenerate re-renders benchmark-result.html"

# --regenerate with no existing run under the backend is a clear error.
# Wrap in set +e: the command is expected to fail, and a bare failing
# command under `set -euo pipefail` aborts the whole suite before $? is read.
regen_empty="$work/regen-empty"
set +e
bash "$BENCH" --target dummytarget --regenerate --bench-root "$regen_empty" \
  >/dev/null 2>&1
regen_norun_rc=$?
set -e
assert_neq "0" "$regen_norun_rc" \
  "T9r-i: --regenerate with no run on disk is rejected"

# ── T9s: --regenerate with NO --target re-derives every run in the tree ──
# Two runs were built under one bench root — different backend + target each
# (seeded in the background at the top of this file) — then
# `bin/benchmark --regenerate` (no target, launched above alongside T9r's
# regenerate) must walk both, re-derive each from its run.json, launch no
# cells, and rebuild the cross-backend page.
wait "$t9s_all_job" 2>/dev/null || true
all_out=$(cat "$work/t9s-all.out")
all_rc=$(cat "$work/t9s-all.rc")
assert_eq "0" "$all_rc" "T9s-a: --regenerate (no target) exits 0"
assert_match 'regenerate-all: target=dummytarget backend=codex run=ra-codex' "$all_out" \
  "T9s-b: re-derives the codex run"
assert_match 'regenerate-all: target=othertarget backend=gemini run=ra-gemini' "$all_out" \
  "T9s-c: re-derives the gemini run"
assert_match 'regenerate-all: rebuilt .*benchmark-result\.md \(2 run\(s\), 0 failed\)' "$all_out" \
  "T9s-d: rebuilds the full cross-backend page over both runs"
assert_file_exists "$allroot/benchmark-result.html" \
  "T9s-e: cross-backend benchmark-result.html is rendered"
codex_cells_after=$(find "$allroot/codex/ra-codex/cells" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
assert_eq "$codex_cells_before" "$codex_cells_after" \
  "T9s-f: --regenerate (no target) launches no new cells"

# --regenerate (no target) on an empty tree is a clear error.
set +e
bash "$BENCH" --regenerate --bench-root "$work/regen-all-empty" >/dev/null 2>&1
all_empty_rc=$?
set -e
assert_neq "0" "$all_empty_rc" \
  "T9s-g: --regenerate with no runs anywhere is rejected"

# ── T9t: a comma list of --target slugs benchmarks each one in turn ──────
# `--target a,b` (spaces allowed around the comma) runs the benchmark once
# per slug, holding every other flag constant, and folds both into the same
# per-backend ledger + cross-backend page. Each child keeps its own run dir
# (keyed by run-id, suffixed per target when one is given) so they never
# collide. The driver exits 0 only when every target succeeds.
# (Invocation launched in the background at the top of this file.)
wait "$t9t_job" 2>/dev/null || true
multi_out=$(cat "$work/t9t-multi.out")
multi_rc=$(cat "$work/t9t-multi.rc")
assert_eq "0" "$multi_rc" "T9t-a: multi-target dry-run exits 0"
assert_match 'multi-target \(1\): target=dummytarget' "$multi_out" \
  "T9t-b: first slug runs (surrounding whitespace trimmed)"
assert_match 'multi-target \(2\): target=othertarget' "$multi_out" \
  "T9t-c: second slug runs after the first"
assert_match 'multi-target: complete — 2/2 target\(s\) succeeded' "$multi_out" \
  "T9t-d: driver reports an all-success summary"
# Each target lands its own resumable run dir, suffixed from the shared id.
assert_file_exists "$multiroot/codex/mt-dummytarget/run.json" \
  "T9t-e: first target gets a per-target run dir"
assert_file_exists "$multiroot/codex/mt-othertarget/run.json" \
  "T9t-f: second target gets a distinct per-target run dir"
assert_eq "dummytarget" "$(jq -r .target "$multiroot/codex/mt-dummytarget/run.json")" \
  "T9t-g: first run.json records the right target"
assert_eq "othertarget" "$(jq -r .target "$multiroot/codex/mt-othertarget/run.json")" \
  "T9t-h: second run.json records the right target"
assert_eq "true" "$(jq -r .skip_recon "$multiroot/codex/mt-dummytarget/run.json")" \
  "T9t-h2: multi-target forwards --skip-recon to child runs"
# Both targets fold into one cross-backend page.
assert_file_exists "$multiroot/benchmark-result.md" \
  "T9t-i: multi-target run rebuilds the shared cross-backend page"

# An empty/whitespace-only comma list is rejected, not silently a no-op.
set +e
bash "$BENCH" --target " , " --dry-run --replicates 1 --conditions harness \
  --bench-root "$work/multi-empty" >/dev/null 2>&1
multi_empty_rc=$?
set -e
assert_neq "0" "$multi_empty_rc" \
  "T9t-j: a comma list with no real slugs is rejected"

# Incomplete resume cells are fully cleared before rerun. A prior benchmark can
# leave cells/<name>/repo-root/output half-populated while an old child is
# still winding down. Deleting that tree in place can fail with "Directory not
# empty"; the rerun must verify the path is clean instead of mixing stale output
# into the new replicate.
# (Stale-cell fixture + rerun launched in the background at the top of
# this file; collected here.)
wait "$t9n_job" 2>/dev/null || true
resume_out=$(cat "$work/t9n-resume.out")
resume_rc=$(cat "$work/t9n-resume.rc")
assert_eq "0" "$resume_rc" \
  "T9n: dry-run resume reruns incomplete cell cleanly"
assert_file_not_exists \
  "$resume_cell/repo-root/output/dummytarget-bench-$resume_run-harness-r1/codex/results/stale-sentinel.txt" \
  "T9o: stale output is not left under the live rerun cell"
assert_file_exists "$resume_cell/results/crashes/CRASH-001/sanitizer.txt" \
  "T9p: rerun wrote fresh dry-run results after cleanup"


summary
