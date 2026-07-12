#!/usr/bin/env bash
# Tests for bin/benchmark + lib/benchmark.py + lib/benchmark_model_direct_render.py:
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
PY_BENCH="$PY"
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
    PATH="$fake_git_bin:$PATH" "$BENCH" --target dummytarget --dry-run --replicates 2 \
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
  "$BENCH" --target dummytarget --dry-run --replicates 1 --conditions harness \
    --backend codex --bench-root "$allroot" --run-id ra-codex >/dev/null 2>&1
  "$BENCH" --target othertarget --dry-run --replicates 1 --conditions harness \
    --backend gemini --bench-root "$allroot" --run-id ra-gemini >/dev/null 2>&1
) &
t9s_seed_job=$!

# T9t: the multi-target driver run.
multiroot="$work/multi-target"
(
  set +e
  "$BENCH" --target " dummytarget , othertarget " --dry-run \
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
mkdir -p "$resume_cell/results"
cat > "$resume_cell/cell.json" <<JSON
{"condition":"harness","replicate":1,"experiment":"bench-$resume_run-harness-r1","results_dir":"$resume_cell/repo-root/output/dummytarget-bench-$resume_run-harness-r1/codex/results","wall_seconds":0,"status":"running"}
JSON
printf 'stale result that must not survive in live cell\n' \
  > "$resume_cell/repo-root/output/dummytarget-bench-$resume_run-harness-r1/codex/results/stale-sentinel.txt"
printf '{"id":"RECON-stale","title":"must not survive"}\n' \
  > "$resume_cell/results/recon-hypotheses.jsonl"
printf 'stale marker\n' > "$resume_cell/results/.recon-cache-marker"
(
  set +e
  "$BENCH" --target dummytarget --dry-run --backend codex \
    --replicates 1 --conditions harness --bench-root "$resume_root" \
    --run-id "$resume_run" > "$work/t9n-resume.out" 2>&1
  echo $? > "$work/t9n-resume.rc"
) &
t9n_job=$!

assert_file_contains "$SCRIPT_ROOT/lib/benchmark_runner.py" 'LLM_DECIDE_LOG.*llm-decisions\.log' \
  "T0a: benchmark cluster-findings keeps keyer telemetry under the run dir"
assert_file_contains "$SCRIPT_ROOT/lib/benchmark_runner.py" '"ACTIVE_BACKEND": backend' \
  "T0b: benchmark cluster-findings exports backend/model context"
assert_file_not_contains "$SCRIPT_ROOT/lib/benchmark_runner.py" 'cluster-findings".*stderr=subprocess.DEVNULL' \
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
# FIND-001 passed the find-quality gate (accept:true); FIND-002 is un-gated
# recon output the gate never adjudicated. count_confirmed_findings counts
# only the former; the raw `findings` count keeps both.
printf '{"decision_version":1,"accept":true,"accept_count":2,"class":"memory-safety","severity":"High"}\n' \
  > "$rd/findings/FIND-001/.llm-find-quality.json"

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
assert_eq "1" "$(echo "$hv" | jq -r '.confirmed_findings')" \
  "T1d2: only the gate-accepted FIND counts as confirmed (un-gated FIND-002 excluded)"
assert_eq "FIND-001" "$(echo "$hv" | jq -r '.confirmed_finding_dirs[0]')" \
  "T1d3: confirmed finding dir is FIND-001"
assert_eq "1" "$(echo "$hv" | jq -r '.findings_rejected')" "T1e: rejected findings counted"
assert_eq "3" "$(echo "$hv" | jq -r '.recon_candidates')" "T1f: RECON-* dirs counted"
assert_eq "1500" "$(echo "$hv" | jq -r '.tokens.input_tokens')" "T1g: input tokens summed"
assert_eq "80" "$(echo "$hv" | jq -r '.tokens.output_tokens')" "T1h: output tokens summed"
assert_eq "3" "$(echo "$hv" | jq -r '.tokens.asan_invocations')" "T1i: asan invocations summed"
assert_eq "2" "$(echo "$hv" | jq -r '.tokens.iterations')" "T1j: iteration count"
assert_eq "1200" "$(echo "$hv" | jq -r '.tokens.cached_input_tokens')" "T1k: cached input tokens summed"
assert_eq "2" "$(echo "$hv" | jq -r '.model_refusals')" \
  "T1l: model refusal warning sidecars counted"

clustered="$work/confirmed-clusters/results"
mkdir -p "$clustered/findings/FIND-A" "$clustered/findings/FIND-B" \
         "$clustered/findings/FIND-PENDING"
for id in FIND-A FIND-B; do
  printf '{"accept":true}\n' > "$clustered/findings/$id/.llm-find-quality.json"
  printf 'Cluster: FCL-shared\n' > "$clustered/findings/$id/report.md"
done
printf 'Cluster: FCL-pending\n' > "$clustered/findings/FIND-PENDING/report.md"
clustered_v=$(python3 "$PY" harvest "$clustered")
assert_eq "1" "$(echo "$clustered_v" | jq -r '.finding_clusters')" \
  "T1l2: raw finding_clusters counts unique confirmed roots only"

# ── T1cf: confirmed-findings floor across every gate state ───────────────
# The mirror of T1's confirmed-crash floor: a FIND counts as confirmed only
# when the find-quality gate accepted it or a human pinned it. Un-gated and
# below-quorum-rejected FINDs (the shape a wall-clock-cut-off run leaves on
# disk) stay in the raw count but are excluded from confirmed.
cf="$work/cf/results"
mkdir -p "$cf/findings/FIND-A" "$cf/findings/FIND-B" "$cf/findings/FIND-C" \
         "$cf/findings/FIND-D" "$cf/findings/FIND-E"
printf '{"accept":true,"class":"dos","severity":"Medium"}\n' \
  > "$cf/findings/FIND-A/.llm-find-quality.json"     # gate-accepted
printf '{"accept":false,"reason":"robustness only"}\n' \
  > "$cf/findings/FIND-B/.llm-find-quality.json"     # rejected below quorum, still on disk
# FIND-C: un-gated (no verdict cache) — the leak case
: > "$cf/findings/FIND-D/.keep"                       # human pin (override)
: > "$cf/findings/FIND-E/.reviewed"                   # human pin (override)
cfv=$(python3 "$PY" harvest "$cf")
assert_eq "5" "$(echo "$cfv" | jq -r '.findings')" \
  "T1cf-a: raw findings count keeps every FIND-* dir"
assert_eq "3" "$(echo "$cfv" | jq -r '.confirmed_findings')" \
  "T1cf-b: confirmed = accept:true + .keep + .reviewed (un-gated + accept:false excluded)"
assert_eq "FIND-A FIND-D FIND-E" \
  "$(echo "$cfv" | jq -r '.confirmed_finding_dirs | join(" ")')" \
  "T1cf-c: confirmed dirs are the accepted FIND and the two pinned FINDs"
assert_eq "2" "$(echo "$cfv" | jq -r '.findings_unadjudicated')" \
  "T1cf-d: findings_unadjudicated = raw(5) - confirmed(3), the not-yet-confirmed remainder (matches the drain WARN)"
printf '%s\n' "$cfv" > "$cf/metrics.json"
assert_eq \
  "findings: rejected=0 confirmed=3 pending=2 roots=5; crashes: rejected=0 confirmed=0 unique=0" \
  "$(python3 "$PY" metric-gate-summary "$cf/metrics.json")" \
  "T1cf-e: gate summary distinguishes confirmed findings from pending raw roots"

# ── T1cl: the report findings cell renders the CONFIRMED count only. Any
# un-adjudicated remainder from a cut-off triage is resolved by the regenerate
# drain (or surfaced as a run-health WARN), never as a "(+N un-gated)" suffix on
# the comparison row. Missing confirmation metrics render as unknown rather
# than counting raw, unadjudicated FIND directories.
label() { python3 -c "import sys; sys.path.insert(0,'lib'); import benchmark; print(benchmark._finding_count_label($1))"; }
assert_eq "1" "$(label '{"finding_total":286,"confirmed_finding_total":1}')" \
  "T1cl-a: cut-off triage shows the confirmed count only, no un-gated suffix"
assert_eq "23" "$(label '{"finding_total":23,"confirmed_finding_total":23}')" \
  "T1cl-b: fully-gated run shows the confirmed count plainly (no remainder)"
assert_eq "—" "$(label '{"finding_total":286}')" \
  "T1cl-c: incomplete metrics do not count raw findings as confirmed"
assert_eq "0" "$(label '{"finding_total":0,"confirmed_finding_total":0}')" \
  "T1cl-d: zero findings render as 0"

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

# ── T1sa: model-direct sanitizer logs imply at least one ASan run ────────
# The model-direct baseline can run the sanitizer by hand and leave only
# crashes/CRASH-*/sanitizer.txt, with no harness probe telemetry in
# logs/index.jsonl. Count confirmed crash artifacts as a lower-bound effort
# floor so such a cell is not reported as zero sanitizer work.
mdsan="$work/model-direct-sanitizer"
mkdir -p "$mdsan/crashes/CRASH-001" "$mdsan/logs"
printf '%s\n  #0 foo bar\n' "$ASAN_LINE" > "$mdsan/crashes/CRASH-001/sanitizer.txt"
mdsan_hv=$(python3 "$PY" harvest "$mdsan")
assert_eq "1" "$(echo "$mdsan_hv" | jq -r '.tokens.asan_invocations')" \
  "T1sa: sanitizer artifact floors ASan invocation count when no probe index exists"
printf '{"backend":"codex","tokens":{"input":10,"cached_input":0,"output":1},"probe":{"asan_invocations":7}}\n' \
  > "$mdsan/logs/index.jsonl"
mdsan_hv=$(python3 "$PY" harvest "$mdsan")
assert_eq "7" "$(echo "$mdsan_hv" | jq -r '.tokens.asan_invocations')" \
  "T1sa2: explicit probe telemetry wins over sanitizer-artifact floor"

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

printf '%s\n' \
  '{"backend":"claude","model":"claude-opus-4-8","tokens":{"input":1000,"cached_input":2000,"cache_creation":400,"cache_creation_1h":400,"output":3000}}' \
  > "$crd/logs/index.jsonl"
chv_1h=$(python3 "$PY" harvest "$crd" --backend claude --model claude-opus-4-8)
assert_eq "0.085000" "$(echo "$chv_1h" | jq -r '.tokens.cost_usd')" \
  "T1q0: Claude one-hour cache writes use the reported 2x input rate"

printf '%s\n' \
  '{"backend":"claude","model":"claude-opus-4-8","cost_usd":0.123456,"cost_source":"backend-reported","tokens":{"input":1000,"cached_input":2000,"cache_creation":400,"cache_creation_1h":400,"output":3000}}' \
  > "$crd/logs/index.jsonl"
chv_native=$(python3 "$PY" harvest "$crd" --backend claude --model claude-opus-4-8)
assert_eq "0.123456" "$(echo "$chv_native" | jq -r '.tokens.cost_usd')" \
  "T1q0b: backend-reported invocation cost overrides reconstructed pricing"

grd="$work/grok-cost/results"
mkdir -p "$grd/logs"
printf '%s\n' \
  '{"backend":"grok","model":"grok-build-0.1","tokens":{"input":3000,"cached_input":2000,"output":3000}}' \
  > "$grd/logs/index.jsonl"
grv=$(python3 "$PY" harvest "$grd" --backend grok --model grok-build-0.1)
assert_eq "0.007400" "$(echo "$grv" | jq -r '.tokens.cost_usd')" \
  "T1q1: harvest applies xAI Grok Build token pricing"
assert_eq "xai-code-api-grok-build-0.1" "$(echo "$grv" | jq -r '.tokens.cost_source')" \
  "T1q1b: Grok cost identifies its public pricing source"

g5d="$work/gpt55-cost/results"
mkdir -p "$g5d/logs"
printf '%s\n' \
  '{"backend":"codex","model":"gpt-5.5","tokens":{"input":270000,"cached_input":260000,"output":1000}}' \
  '{"backend":"codex","model":"gpt-5.5","tokens":{"input":300000,"cached_input":290000,"output":1000}}' \
  > "$g5d/logs/index.jsonl"
g5v=$(python3 "$PY" harvest "$g5d" --backend codex --model gpt-5.5)
assert_eq "0.645000" "$(echo "$g5v" | jq -r '.tokens.cost_usd')" \
  "T1q2: harvest applies GPT-5.5 long-context pricing per Codex request"

# T1q3: a real multi-turn session has cumulative input in the millions, but the
# tier is a PER-REQUEST boundary — it must tier on the build-time prompt size,
# not the session sum, so a long session of small requests stays LOW-tier.
# input 5_000_000 (sum over requests), full-rate=200_000, prompt_estimate_build
# 16_000 < 272_000 → LOW: (200000*5 + 4800000*0.5 + 1000*30)/1e6 = 3.430000.
# Tiering on the cumulative 5M (the old bug) would force HIGH → 6.845000.
g5lo="$work/gpt55-tier-low/results"; mkdir -p "$g5lo/logs"
printf '%s\n' \
  '{"backend":"codex","model":"gpt-5.5","tokens":{"input":5000000,"cached_input":4800000,"output":1000,"prompt_estimate_build":16000}}' \
  > "$g5lo/logs/index.jsonl"
g5lov=$(python3 "$PY" harvest "$g5lo" --backend codex --model gpt-5.5)
assert_eq "3.430000" "$(echo "$g5lov" | jq -r '.tokens.cost_usd')" \
  "T1q3: GPT-5.5 tier follows per-request prompt size, not the session-cumulative input"

# T1q4: the per-request threshold still fires — a single genuinely long-context
# request (prompt_estimate_build 300_000 > 272_000) prices HIGH:
# (300000*10 + 0 + 1000*45)/1e6 = 3.045000.
g5hi="$work/gpt55-tier-high/results"; mkdir -p "$g5hi/logs"
printf '%s\n' \
  '{"backend":"codex","model":"gpt-5.5","tokens":{"input":300000,"cached_input":0,"output":1000,"prompt_estimate_build":300000}}' \
  > "$g5hi/logs/index.jsonl"
g5hiv=$(python3 "$PY" harvest "$g5hi" --backend codex --model gpt-5.5)
assert_eq "3.045000" "$(echo "$g5hiv" | jq -r '.tokens.cost_usd')" \
  "T1q4: GPT-5.5 high tier still applies when one request exceeds the threshold"

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
mk_cell() { # name condition replicate status crashes [rejected] [refusals] [confirmed_findings]
  local d="$bd/cells/$1"
  local rejected="${6:-0}"
  local refusals="${7:-0}"
  local confirmed="${8:-0}"
  mkdir -p "$d"
  cat > "$d/cell.json" <<JSON
{"condition":"$2","replicate":$3,"status":"$4","wall_seconds":42}
JSON
  cat > "$d/metrics.json" <<JSON
{"confirmed_crashes":$5,"crash_clusters":$5,"findings":0,
 "confirmed_findings":$confirmed,
 "findings_rejected":$rejected,
 "model_refusals":$refusals,
 "tokens":{"output_tokens":111}}
JSON
}
mk_cell model-direct-r1            model-direct           1 done 0 2 1
mk_cell model-direct-r2            model-direct           2 done 0
mk_cell harness-r1 harness 1 done 3 0 2 2
mk_cell harness-r2 harness 2 done 1 0 0 1
agg=$(python3 "$PY" aggregate "$bd")
hd=$(echo "$agg" | jq -c '.conditions[] | select(.condition=="harness")')
assert_eq "3" "$(echo "$hd" | jq -r '.confirmed_finding_total')" \
  "T4a0: harness confirmed_finding_total folds [2,1]"
assert_eq "2" "$(echo "$hd" | jq -r '.crash_median')" "T4a: harness median of [3,1] is 2"
assert_eq "—" "$(echo "$hd" | jq -r '.top_severity_level')" \
  "T4b: no cluster JSON → top crash severity is unscored (—)"
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

# Post-pool rejection gates may demote a pooled crash after pool-members.json
# was written. split/aggregate must follow the final artifact tree, not the
# stale pre-gate cell metric, so rejected crashes are counted and linkable.
pbd="$work/post-pool-demoted"
mkdir -p "$pbd/cells/model-direct-r1" \
         "$pbd/cells/model-direct-r2" \
         "$pbd/pool/crashes/CRASH-0002" \
         "$pbd/pool/crashes-rejected/CRASH-0001" \
         "$pbd/pool/model-direct/crashes/CRASH-0001"
cat > "$pbd/cells/model-direct-r1/cell.json" <<'JSON'
{"condition":"model-direct","replicate":1,"status":"done","wall_seconds":1}
JSON
cat > "$pbd/cells/model-direct-r1/metrics.json" <<'JSON'
{"confirmed_crashes":1,"crash_dirs":["CRASH-1"],"findings":0,
 "confirmed_findings":0,"crashes_rejected":0}
JSON
cat > "$pbd/cells/model-direct-r2/cell.json" <<'JSON'
{"condition":"model-direct","replicate":2,"status":"done","wall_seconds":1}
JSON
cat > "$pbd/cells/model-direct-r2/metrics.json" <<'JSON'
{"confirmed_crashes":3,"crash_dirs":["CRASH-2","CRASH-3","CRASH-4"],"findings":0,
 "confirmed_findings":0,"crashes_rejected":0}
JSON
cat > "$pbd/pool-members.json" <<'JSON'
{"crashes":{"CRASH-0001":"model-direct","CRASH-0002":"model-direct"},
 "crash_cells":{"CRASH-0001":"model-direct-r1","CRASH-0002":"model-direct-r2"},
 "crashes-rejected":{},
 "findings":{},"findings-rejected":{}}
JSON
cat > "$pbd/pool/crashes/CRASH-0002/report.md" <<'EOF_ACCEPTED_CRASH'
# Accepted crash
EOF_ACCEPTED_CRASH
cat > "$pbd/pool/crashes-rejected/CRASH-0001/report.md" <<'EOF_REJECTED_CRASH'
# Rejected crash
EOF_REJECTED_CRASH
cat > "$pbd/pool/model-direct/crashes/CRASH-0001/report.md" <<'EOF_STALE_ACCEPTED'
# Stale accepted crash copy
EOF_STALE_ACCEPTED
python3 "$PY" split-pool "$pbd" >/dev/null
pagg=$(python3 "$PY" aggregate "$pbd")
pd=$(echo "$pagg" | jq -c '.conditions[] | select(.condition=="model-direct")')
assert_eq "3" "$(echo "$pd" | jq -r '.crash_total')" \
  "T4i: post-pool demoted crash is subtracted from accepted total"
assert_eq "1" "$(echo "$pd" | jq -r '.rejected_crash_total')" \
  "T4j: post-pool demoted crash is counted as rejected"
assert_eq "model-direct" "$(jq -r '.["crashes-rejected"]["CRASH-0001"]' "$pbd/pool-members.json")" \
  "T4k: split-pool reconciles demoted crash membership"
assert_file_exists "$pbd/pool/model-direct/crashes-rejected/CRASH-0001/report.md" \
  "T4l: demoted rejected crash is split into condition link target"
assert_file_contains "$pbd/pool/model-direct/crashes-rejected/REJECTED-CRASHES.md" "CRASH-0001" \
  "T4m: rejected crash index links the demoted crash"
assert_eq "[0,3]" "$(echo "$pd" | jq -c '.crashes')" \
  "T4m2: post-pool demotion updates the source replicate crash vector"
assert_eq "1.5" "$(echo "$pd" | jq -r '.crash_median')" \
  "T4m3: post-pool demotion updates the accepted crash median"
assert_file_not_exists "$pbd/pool/model-direct/crashes/CRASH-0001" \
  "T4m4: split-pool removes stale accepted copy after demotion"
assert_file_exists "$pbd/pool/model-direct/crashes/CRASH-0002/report.md" \
  "T4m5: split-pool keeps current accepted crashes after stale cleanup"

# Auto-rejected crash signatures live only as named ledger rows (no crash dir), and
# only the cell metric counts them. Once split-pool has run for a condition that
# also has an accepted crash, the rejected total must still carry those rows —
# they have no demoted dir, so re-deriving from the pool tree would lose them.
ibd="$work/index-row-reject"
mkdir -p "$ibd/cells/model-direct-r1" "$ibd/pool/crashes/CRASH-0001" \
         "$ibd/pool/crashes-rejected"
cat > "$ibd/cells/model-direct-r1/cell.json" <<'JSON'
{"condition":"model-direct","replicate":1,"status":"done","wall_seconds":1}
JSON
cat > "$ibd/cells/model-direct-r1/metrics.json" <<'JSON'
{"confirmed_crashes":1,"crash_dirs":["CRASH-1"],"findings":0,
 "confirmed_findings":0,"crashes_rejected":3}
JSON
cat > "$ibd/pool/crashes/CRASH-0001/report.md" <<'EOF_ACCEPTED'
# Accepted crash
EOF_ACCEPTED
cat > "$ibd/pool/crashes-rejected/CELL-REJECTIONS-model-direct-r1.md" <<'EOF_INDEX'
| ID | Crash site | Rejected at |
| :-- | :-- | :-- |
| CR-a | app_parse.c:10 | t1 |
| CR-b | app_parse.c:20 | t2 |
| CR-c | app_parse.c:30 | t3 |
EOF_INDEX
cat > "$ibd/pool-members.json" <<'JSON'
{"crashes":{"CRASH-0001":"model-direct"},"crashes-rejected":{},
 "findings":{},"findings-rejected":{}}
JSON
python3 "$PY" split-pool "$ibd" >/dev/null
iagg=$(python3 "$PY" aggregate "$ibd")
id=$(echo "$iagg" | jq -c '.conditions[] | select(.condition=="model-direct")')
assert_eq "1" "$(echo "$id" | jq -r '.crash_total')" \
  "T4n: accepted pooled crash still counts when only rejections are INDEX rows"
assert_eq "3" "$(echo "$id" | jq -r '.rejected_crash_total')" \
  "T4o: INDEX-row auto-rejections survive split-pool in the rejected total"

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
assert_file_contains "$SCRIPT_ROOT/lib/benchmark_runner.py" 'REJECTED-FINDINGS.md' \
  "T4j: benchmark runner renders rejected finding markdown indexes through render-md"

# ── T5: aggregate degrades gracefully on a partial run ───────────────────
mk_cell harness-r3 harness 3 failed 0
rm -f "$bd/cells/harness-r3/metrics.json"
mk_cell harness-r4 harness 4 incomplete 0
jtmp="$(mktemp)"
jq '.confirmed_crashes=6 | .confirmed_findings=5' \
  "$bd/cells/harness-r4/metrics.json" > "$jtmp" \
  && mv "$jtmp" "$bd/cells/harness-r4/metrics.json"
agg2=$(python3 "$PY" aggregate "$bd")
hd2=$(echo "$agg2" | jq -c '.conditions[] | select(.condition=="harness")')
assert_eq "4" "$(echo "$hd2" | jq -r '.replicates_total')" "T5a: failed and incomplete cells counted in total"
assert_eq "2" "$(echo "$hd2" | jq -r '.replicates_done')" "T5b: failed cell excluded from done"
assert_eq "6/5" \
  "$(echo "$hd2" | jq -r '.incomplete_observed[0] | "\(.crashes)/\(.findings)"')" \
  "T5c: incomplete cell preserves observed counts outside aggregates"

# ── T6: ledger append — header written once, sections accumulate ─────────
ledger="$work/ledger.md"
python3 "$PY" ledger "$bd" --ledger "$ledger" >/dev/null
assert_file_contains "$ledger" "# Benchmark results" "T6a: ledger header present"
assert_file_contains "$ledger" "Benchmark run .run1." "T6b: run section present"
assert_file_contains "$ledger" "AddressSanitizer-confirmed" "T6c: oracle caveat present"
assert_file_contains "$ledger" \
  'Incomplete — observed 6 crashes / 5 findings; excluded from aggregate' \
  "T6c2: ledger surfaces incomplete-cell observed yield"
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
u=$(python3 "$USAGE_PY" extract-usage codex "$codex_log")
assert_eq "2000" "$(echo "$u" | jq -r '.tokens.input')" "T8a: codex input tokens"
assert_eq "1800" "$(echo "$u" | jq -r '.tokens.cached_input')" "T8b: codex cached tokens"
assert_eq "90" "$(echo "$u" | jq -r '.tokens.output')" "T8c: codex output tokens"
assert_eq "0" "$(echo "$u" | jq -r '.tokens.cache_creation')" \
  "T8c2: codex has no cache-write counter → cache_creation 0"
assert_eq "codex" "$(echo "$u" | jq -r '.backend')" \
  "T8c3: backend echoed for harvest-side normalization"

oss_log="$work/oss.log"
printf '%s\n' \
  '{"type":"text","part":{"type":"text","text":"done"}}' \
  '{"type":"step_finish","part":{"type":"step-finish","tokens":{"input":1200,"output":34,"reasoning":0,"cache":{"read":900,"write":25}}}}' \
  > "$oss_log"
u_oss=$(python3 "$USAGE_PY" extract-usage oss "$oss_log")
assert_eq "1200" "$(echo "$u_oss" | jq -r '.tokens.input')" \
  "T8c4: oss/OpenCode input tokens from step_finish"
assert_eq "900" "$(echo "$u_oss" | jq -r '.tokens.cached_input')" \
  "T8c5: oss/OpenCode cache.read captured"
assert_eq "25" "$(echo "$u_oss" | jq -r '.tokens.cache_creation')" \
  "T8c6: oss/OpenCode cache.write captured"
assert_eq "34" "$(echo "$u_oss" | jq -r '.tokens.output')" \
  "T8c7: oss/OpenCode output tokens from step_finish"

claude_log="$work/claude.log"
printf '%s\n' \
  '{"type":"assistant","message":{"usage":{"input_tokens":5,"output_tokens":7}}}' \
  '{"type":"result","usage":{"input_tokens":50,"cache_read_input_tokens":40,"cache_creation_input_tokens":15,"output_tokens":12}}' \
  > "$claude_log"
u2=$(python3 "$USAGE_PY" extract-usage claude "$claude_log")
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
u_gem=$(python3 "$USAGE_PY" extract-usage gemini "$gemini_log")
assert_eq "58000000" "$(echo "$u_gem" | jq -r '.tokens.input')" \
  "T8j: gemini raw input_tokens captured (cumulative cached+fresh)"
assert_eq "55000000" "$(echo "$u_gem" | jq -r '.tokens.cached_input')" \
  'T8k: gemini `cached` aliased into cached_input'
assert_eq "80" "$(echo "$u_gem" | jq -r '.tokens.output')" "T8l: gemini output tokens"
assert_eq "false" "$(echo "$u_gem" | jq -r '.estimated')" \
  "T8m: gemini measured path is not flagged estimated"

empty_log="$work/empty.log"
: > "$empty_log"
u3=$(python3 "$USAGE_PY" extract-usage gemini "$empty_log")
assert_eq "0" "$(echo "$u3" | jq -r '.tokens.output')" "T8f: empty log yields zero tokens"
u4=$(python3 "$USAGE_PY" extract-usage codex "$work/does-not-exist.log")
assert_eq "0" "$(echo "$u4" | jq -r '.tokens.input // 0')" "T8g: missing log is safe"
assert_eq "false" "$(echo "$u4" | jq -r '.estimated')" \
  "T8h: missing codex usage is not estimated from stderr"
printf 'codex auth failure without usage\n' > "$work/codex-no-usage.log"
printf 'prompt text\n' > "$work/no-usage-prompt.txt"
u5=$(python3 "$USAGE_PY" extract-usage codex "$work/codex-no-usage.log" "$work/no-usage-prompt.txt")
assert_eq "0" "$(echo "$u5" | jq -r '.tokens.output')" \
  "T8i: codex no-usage log stays zero-cost instead of estimated"

# T8n: a model-direct cell has no harness prompt stash in its index row, so
# harvest must derive the per-request tier basis from the cell's persisted
# prompt.txt. Cumulative input 3_000_000 (>272K) would pin the row HIGH on the
# session sum; the 16_000-token prompt (64_000 chars / 4) keeps it LOW.
# LOW: (200000*5 + 2800000*0.5 + 1000*30)/1e6 = 2.430000; the bug gives 4.845000.
md_res="$work/md-tier/results"; mkdir -p "$md_res/logs"
printf '%s\n' \
  '{"backend":"codex","model":"gpt-5.5","tokens":{"input":3000000,"cached_input":2800000,"output":1000}}' \
  > "$md_res/logs/index.jsonl"
head -c 64000 /dev/zero | tr '\0' 'x' > "$md_res/prompt.txt"
md_v=$(python3 "$PY" harvest "$md_res" --backend codex --model gpt-5.5)
assert_eq "2.430000" "$(echo "$md_v" | jq -r '.tokens.cost_usd')" \
  "T8n: model-direct tiers on its persisted prompt.txt, not the session-cumulative input"

# T8o: an in-row prompt_estimate_build (the harness path) wins over a present
# prompt.txt — the prompt.txt fallback only fills rows that lack an estimate, so
# it can never down-tier a request that legitimately declares a large prompt.
# build 300_000 > 272K → HIGH: (300000*10 + 0 + 1000*45)/1e6 = 3.045000, even
# though the tiny prompt.txt alone would say LOW.
mdp_res="$work/md-prec/results"; mkdir -p "$mdp_res/logs"
printf '%s\n' \
  '{"backend":"codex","model":"gpt-5.5","tokens":{"input":300000,"cached_input":0,"output":1000,"prompt_estimate_build":300000}}' \
  > "$mdp_res/logs/index.jsonl"
printf 'tiny prompt\n' > "$mdp_res/prompt.txt"
mdp_v=$(python3 "$PY" harvest "$mdp_res" --backend codex --model gpt-5.5)
assert_eq "3.045000" "$(echo "$mdp_v" | jq -r '.tokens.cost_usd')" \
  "T8o: in-row prompt_estimate_build takes precedence over the prompt.txt fallback"

# T8p: a run with neither an in-row estimate nor a prompt.txt (predates both)
# still falls back to raw_input — graceful, same as before the per-request fix.
# raw_input 300_000 > 272K → HIGH 3.045000.
mdn_res="$work/md-none/results"; mkdir -p "$mdn_res/logs"
printf '%s\n' \
  '{"backend":"codex","model":"gpt-5.5","tokens":{"input":300000,"cached_input":0,"output":1000}}' \
  > "$mdn_res/logs/index.jsonl"
mdn_v=$(python3 "$PY" harvest "$mdn_res" --backend codex --model gpt-5.5)
assert_eq "3.045000" "$(echo "$mdn_v" | jq -r '.tokens.cost_usd')" \
  "T8p: with no estimate and no prompt.txt, tier basis falls back to raw_input"

# ── T9: bin/benchmark --dry-run end-to-end ───────────────────────────────
# (Invocation + fake-git fixture launched in the background at the top of
# this file; collected here. Same flags, same assertions.)
wait "$t9_job" 2>/dev/null || true
dry_out=$(cat "$work/t9-dry.out")
rc=$(cat "$work/t9-dry.rc")
assert_eq "0" "$rc" "T9a: dry-run exits 0"
assert_file_exists "$dledger" "T9b: dry-run writes the ledger"
assert_match "crash median=1" "$dry_out" "T9c: harness scores 1 crash/cell in dry-run"
assert_match "model-direct: crash median=0" "$dry_out" "T9d: model-direct scores 0 in dry-run"
assert_match "Harness recon: skipped \\(--skip-recon\\)" "$dry_out" \
  "T9d2: --skip-recon is accepted and logged"
# 2 replicates x harness, each synthetic cell has one real crash.
assert_file_contains "$dledger" 'Scoreboard' "T9e: ledger has the redesigned Scoreboard section"
assert_not_match "Operation not permitted" "$dry_out" \
  "T9f: console tee path does not emit /dev/fd portability warnings"
assert_match 'done in [0-9]+m[0-9][0-9]s \([0-9]+s\)' "$dry_out" \
  "T9f2: cell duration includes minutes and raw seconds"
assert_match 'benchmark-result live update \(after model-direct-r1\): .*benchmark-result\.html' "$dry_out" \
  "T9f3: each saved cell refreshes the lightweight HTML report"
dry_updates=$(printf '%s\n' "$dry_out" \
  | grep -c 'benchmark-result update (pre-ledger): .*benchmark-result\.html' || true)
if [ "$dry_updates" -eq 1 ]; then
  pass "T9f4: benchmark-result is built once after all dry-run cells"
else
  fail "T9f4: benchmark-result is built once after all dry-run cells" \
    "saw $dry_updates final update lines in: $dry_out"
fi
# The live refresh must not restore pooled finalization after each cell.
saved_cells=$(printf '%s\n' "$dry_out" | grep -c 'metrics saved; pooled finalization deferred' || true)
if [ "$saved_cells" -eq 4 ]; then
  pass "T9f5: every dry-run cell persists metrics while pooled work stays deferred"
else
  fail "T9f5: every dry-run cell persists metrics while pooled work stays deferred" \
    "expected 4 saved cells, saw $saved_cells in: $dry_out"
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
assert_eq "high" "$(jq -r '.resolved_effort' "$drun_json")" \
  "T9i2c: dry-run records the resolved backend effort"
if find "$(dirname "$drun_json")/cells" -name index.jsonl -type f -exec jq -e \
    '.resolved_effort == "high"' {} + >/dev/null; then
  pass "T9i2d: every dry-run ledger event records resolved effort"
else
  fail "T9i2d: every dry-run ledger event records resolved effort"
fi
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
regen_harness_cell=$(find "$dbench/cells" -mindepth 1 -maxdepth 1 -type d -name 'harness-*' | sort | head -1)
regen_harness_results=$(jq -r '.results_dir' "$regen_harness_cell/cell.json")
mkdir -p "$regen_harness_results/findings/FIND-ACCEPTED" \
         "$regen_harness_results/findings/FIND-PENDING" \
         "$regen_harness_results/crashes/CRASH-STACK"
printf '# Accepted finding\n\nLocation: catalog.c:1\n' \
  > "$regen_harness_results/findings/FIND-ACCEPTED/report.md"
printf '{"accept":true,"accept_count":2,"class":"memory-safety","severity":"Medium"}\n' \
  > "$regen_harness_results/findings/FIND-ACCEPTED/.llm-find-quality.json"
printf '# Pending finding\n\nLocation: catalog.c:2\n' \
  > "$regen_harness_results/findings/FIND-PENDING/report.md"
printf '==1==ERROR: AddressSanitizer: stack-overflow on address 0x1234\n' \
  > "$regen_harness_results/crashes/CRASH-STACK/sanitizer.txt"
# Simulate a stale pre-confirmed-findings metrics file. --regenerate must
# reharvest before rebuilding the pool, otherwise both raw FIND dirs would be
# pooled and the headline finding count would stay inflated.
jq '.findings=2 | del(.confirmed_findings, .confirmed_finding_dirs)' \
  "$regen_harness_cell/metrics.json" > "$regen_harness_cell/metrics.json.tmp"
mv "$regen_harness_cell/metrics.json.tmp" "$regen_harness_cell/metrics.json"
# Overlap: T9s's regenerate-all (independent bench root, seeded at the top
# of the file) runs in the background while T9r's regenerate runs here.
# Its cells-before snapshot must precede its launch, so take it now.
wait "$t9s_seed_job" 2>/dev/null || true
codex_cells_before=$(find "$allroot/codex/ra-codex/cells" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
(
  set +e
  "$BENCH" --regenerate --bench-root "$allroot" > "$work/t9s-all.out" 2>&1
  echo $? > "$work/t9s-all.rc"
) &
t9s_all_job=$!
regen_out=$("$BENCH" --target dummytarget --regenerate \
  --bench-root "$droot" --run-id "$regen_runid" 2>&1)
regen_rc=$?
assert_eq "0" "$regen_rc" "T9r-a: --regenerate exits 0"
assert_match 'no cells launched' "$regen_out" \
  "T9r-b: --regenerate does not launch cells"
# The regenerate drain re-runs the find-gate before reharvest so a cut-off run
# converges to its confirmed count. With the LLM disabled in tests the drain
# fails open, leaving FIND-PENDING un-adjudicated — which must surface as a
# run-health WARN (the replacement for the dropped "(+N un-gated)" suffix),
# never a silent drop.
assert_match 'Regenerate: draining find-gate for' "$regen_out" \
  "T9r-b2: --regenerate drains the find-gate before reharvest"
assert_match 'Regenerate: completing crash triage for' "$regen_out" \
  "T9r-b2-crash: --regenerate completes crash triage before reharvest"
assert_dir_not_exists "$regen_harness_results/crashes/CRASH-STACK" \
  "T9r-b2-stack: regenerate removes an auto-quarantined crash from accepted metrics"
assert_dir_exists "$regen_harness_results/crashes-rejected/CRASH-STACK" \
  "T9r-b2-stack-rejected: regenerate preserves the auto-quarantined crash as rejected"
assert_match 'WARN: .* finding\(s\) still un-adjudicated after drain' "$regen_out" \
  "T9r-b3: --regenerate WARNs about findings the drain could not adjudicate"
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
assert_not_match 'Cell .* starting' "$regen_out" \
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
assert_eq "1" "$(jq -r '.confirmed_findings' "$regen_harness_cell/metrics.json")" \
  "T9r-j: --regenerate reharvests confirmed_findings from disk"
assert_eq "FIND-ACCEPTED" "$(jq -r '.confirmed_finding_dirs | join(" ")' "$regen_harness_cell/metrics.json")" \
  "T9r-k: --regenerate records only the accepted finding dir"
pooled_regen_findings=$(find "$dbench/pool/findings" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
assert_eq "1" "$pooled_regen_findings" \
  "T9r-l: --regenerate pool imports only confirmed findings"
assert_file_contains "$dbench/pool/findings/FIND-0001/report.md" 'Accepted finding' \
  "T9r-m: --regenerate pooled the accepted finding"
assert_file_not_contains "$dbench/pool/findings/FIND-0001/report.md" 'Pending finding' \
  "T9r-n: --regenerate did not pool the pending raw finding"
assert_file_exists "$dbench/pool/harness/findings/FINDING-CLUSTERS.html" \
  "T9r-n2: split harness findings have a condition-local cluster report"
assert_file_exists "$dbench/pool/harness/crashes/CRASH-CLUSTERS.html" \
  "T9r-n3: split harness crashes have a condition-local cluster report"

# A regenerate-only artifact tree can outlive the target checkout. In that
# case the model-direct find-gate points TARGET_ROOT at a missing tree, so its
# source-reading step self-guards and the LLM-disabled drain fails open: raw
# findings stay in place as unconfirmed, never moved to findings-rejected/.
missing_target_root="$work/regen-missing-target"
missing_slug="missing-target-t9r"
missing_run="missing-run"
missing_cell="$missing_target_root/codex/$missing_run/cells/model-direct-r1"
mkdir -p "$missing_cell/findings/FIND-RAW" "$missing_cell/crashes" "$missing_cell/logs"
cat > "$missing_target_root/codex/$missing_run/run.json" <<JSON
{"runid":"$missing_run","target":"$missing_slug","backend":"codex","replicates":1,
 "budget_wall":60,"conditions":["model-direct"],"target_sha":"abc","harness_sha":"def"}
JSON
cat > "$missing_cell/cell.json" <<JSON
{"condition":"model-direct","replicate":1,"status":"done","wall_seconds":60,
 "results_dir":"$missing_cell"}
JSON
cat > "$missing_cell/metrics.json" <<'JSON'
{"findings":1,"confirmed_findings":0,"confirmed_finding_dirs":[],
 "confirmed_crashes":0,"crash_dirs":[],"tokens":{"output_tokens":0}}
JSON
printf '# Raw model-direct finding\n\nLocation: catalog.c:3\n' \
  > "$missing_cell/findings/FIND-RAW/report.md"
missing_out=$("$BENCH" --target "$missing_slug" --backend codex \
  --run-id "$missing_run" --bench-root "$missing_target_root" --regenerate 2>&1)
missing_rc=$?
assert_eq "0" "$missing_rc" \
  "T9r-o: --regenerate succeeds even when the target checkout is absent"
assert_match 'Regenerate: draining find-gate for' "$missing_out" \
  "T9r-p: missing-target regenerate still drains the find-gate (no validator pre-gate)"
assert_dir_exists "$missing_cell/findings/FIND-RAW" \
  "T9r-q: missing-target regenerate leaves raw model-direct FIND in place"
assert_dir_not_exists "$missing_cell/findings-rejected/FIND-RAW" \
  "T9r-r: missing-target regenerate does not false-reject the raw FIND"
assert_eq "1" "$(jq -r '.findings' "$missing_cell/metrics.json")" \
  "T9r-s: missing-target regenerate preserves raw finding count"
assert_eq "0" "$(jq -r '.confirmed_findings' "$missing_cell/metrics.json")" \
  "T9r-t: missing-target regenerate does not confirm the raw finding"

# --regenerate with no existing run under the backend is a clear error.
# Wrap in set +e: the command is expected to fail, and a bare failing
# command under `set -euo pipefail` aborts the whole suite before $? is read.
regen_empty="$work/regen-empty"
set +e
"$BENCH" --target dummytarget --regenerate --bench-root "$regen_empty" \
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
assert_match 'Regenerate-all: target=dummytarget backend=codex run=ra-codex' "$all_out" \
  "T9s-b: re-derives the codex run"
assert_match 'Regenerate-all: target=othertarget backend=gemini run=ra-gemini' "$all_out" \
  "T9s-c: re-derives the gemini run"
assert_match 'Regenerate-all: rebuilt .*benchmark-result\.md \(2 run\(s\), 0 failed\)' "$all_out" \
  "T9s-d: rebuilds the full cross-backend page over both runs"
assert_file_exists "$allroot/benchmark-result.html" \
  "T9s-e: cross-backend benchmark-result.html is rendered"
codex_cells_after=$(find "$allroot/codex/ra-codex/cells" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')
assert_eq "$codex_cells_before" "$codex_cells_after" \
  "T9s-f: --regenerate (no target) launches no new cells"

# --regenerate (no target) on an empty tree is a clear error.
set +e
"$BENCH" --regenerate --bench-root "$work/regen-all-empty" >/dev/null 2>&1
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
assert_match 'Multi-target 1: dummytarget' "$multi_out" \
  "T9t-b: first slug runs (surrounding whitespace trimmed)"
assert_match 'Multi-target 2: othertarget' "$multi_out" \
  "T9t-c: second slug runs after the first"
assert_match 'Multi-target complete: 2/2 target\(s\) succeeded' "$multi_out" \
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

nestedroot="$work/nested-target"
set +e
nested_out=$("$BENCH" --target samples/sample-python --dry-run \
  --replicates 1 --conditions model-direct,harness --backend codex \
  --bench-root "$nestedroot" --run-id nested-smoke 2>&1)
nested_rc=$?
set -e
assert_eq "0" "$nested_rc" "T9u-a: nested target dry-run exits 0"
assert_file_exists "$nestedroot/codex/nested-smoke/run.json" \
  "T9u-b: nested target writes run metadata"
assert_eq "samples/sample-python" "$(jq -r .target "$nestedroot/codex/nested-smoke/run.json")" \
  "T9u-c: nested target slug is preserved in run.json"
assert_file_exists "$nestedroot/codex/nested-smoke/cells/harness-r1/cell.json" \
  "T9u-d: nested target harness cell is recorded"
assert_file_exists "$nestedroot/codex/nested-smoke/cells/model-direct-r1/cell.json" \
  "T9u-e: nested target model-direct cell is recorded"
[ ! -d "$nestedroot/codex/.run-samples" ] \
  && pass "T9u-f: nested target lock path is one safe component" \
  || fail "T9u-f: nested target lock path is one safe component" "$nested_out"

# An empty/whitespace-only comma list is rejected, not silently a no-op.
set +e
"$BENCH" --target " , " --dry-run --replicates 1 --conditions harness \
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
assert_file_not_exists "$resume_cell/results/recon-hypotheses.jsonl" \
  "T9o2: stale local recon output is not left under the live rerun cell"
assert_file_not_exists "$resume_cell/results/.recon-cache-marker" \
  "T9o3: stale local recon marker is not left under the live rerun cell"
assert_file_exists "$resume_cell/results/crashes/CRASH-001/sanitizer.txt" \
  "T9p: rerun wrote fresh dry-run results after cleanup"

# T9q: a committed benchmark target.toml must not name its .ground-truth.json
# answer key. bin/benchmark copies each config into the cell's repo-root facade,
# so any hidden-dotfile path written here becomes a breadcrumb an audited agent
# can follow — inflating recall/precision. The answer key stays outside the
# audited tree; the config must not point back at it.
gt_leak=""
for _cfg in "$SCRIPT_ROOT"/output/samples/*/target.toml "$SCRIPT_ROOT"/output/canary/target.toml; do
  [ -f "$_cfg" ] || continue
  if grep -q 'ground-truth' "$_cfg"; then
    gt_leak="$gt_leak $_cfg"
  fi
done
if [ -n "$gt_leak" ]; then
  fail "T9q: benchmark target.toml must not disclose the .ground-truth.json path" "$gt_leak"
else
  pass "T9q: no committed benchmark target.toml discloses its answer-key path"
fi

# ── T9u: cell_metrics_summary distinguishes an unavailable cell from a clean
# zero-yield one. A missing/corrupt metrics.json or the exists:false sentinel
# (written for a cell with no results dir) must not read as crashes=0/0. ──────
cell_metrics_summary() { python3 "$PY" cell-metrics-summary "$1"; }
cms_tmp="$work/cms"; mkdir -p "$cms_tmp"
printf '{"exists": false}\n' > "$cms_tmp/absent.json"
printf 'not json{{{\n' > "$cms_tmp/corrupt.json"
printf '{}\n' > "$cms_tmp/empty.json"
printf '{"confirmed_crashes":2,"crash_clusters":1,"confirmed_findings":3,"finding_clusters":2,"exists":true}\n' \
  > "$cms_tmp/real.json"
assert_eq "metrics=unavailable" "$(cell_metrics_summary "$cms_tmp/absent.json")" \
  "T9v: exists:false cell reads as unavailable, not crashes=0/0"
assert_eq "metrics=unavailable" "$(cell_metrics_summary "$cms_tmp/corrupt.json")" \
  "T9v2: corrupt metrics.json reads as unavailable"
assert_eq "metrics=unavailable" "$(cell_metrics_summary "$cms_tmp/empty.json")" \
  "T9v3: empty metrics.json reads as unavailable"
assert_eq "metrics=unavailable" "$(cell_metrics_summary "$cms_tmp/missing.json")" \
  "T9v4: missing metrics.json reads as unavailable"
assert_eq "crashes=2/1 unique | findings=3/2 unique" "$(cell_metrics_summary "$cms_tmp/real.json")" \
  "T9v5: a real cell still reports its crash/finding counts"


summary
