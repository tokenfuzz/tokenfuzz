#!/usr/bin/env bash
# Tests for bin/benchmark: argument validation, ledger, pool, crosstab (T10–T19).
#
# Carved out of test_benchmark.sh so the benchmark suite's ~150s of
# `bash bin/benchmark` dry-runs (each spawning ~30 python subprocesses)
# splits across cores under tests/run-tests.sh instead of pinning one.
#
# Wall-time layout: every expensive invocation (the bin/benchmark dry-runs
# and the lib/benchmark.py aggregate/ledger/pool/crosstab calls) runs
# exactly once, launched up front as a background job that writes its
# output into $work/. Each assertion block waits on the one job that feeds
# it and asserts against the captured output, so the suite costs the
# longest single chain rather than the sum of every python startup.
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
trap 'rm -rf "$work" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT

# Shared constant from the harvest suite (test_benchmark.sh): the ASan
# header line several fixtures below write into synthetic crash dirs.
ASAN_LINE='==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602'

# codex usage fixture, mirrored from test_benchmark.sh's T8 block. T12d
# below re-reads it to assert a measured (non-estimated) usage object, so
# this shard must recreate it standalone.
codex_log="$work/codex.log"
printf '%s\n' \
  '{"type":"item.started"}' \
  '{"type":"item.completed","usage":{"input_tokens":2000,"cached_input_tokens":1800,"output_tokens":90}}' \
  > "$codex_log"

# ═════════════════════════════════════════════════════════════════════════
# Fixtures (cheap heredocs, main shell) for every section, created before
# the background jobs that consume them are launched.
# ═════════════════════════════════════════════════════════════════════════

# T10 root: every invocation gets a throw-away --bench-root so a
# successful-but-not-rejected case (e.g. --budget-wall 0, the documented
# "unlimited" sentinel) doesn't pollute the real benchmark tree under $HOME.
t10_root="$work/argv-validation"

# T12 fixtures: gemini estimate path (agy reports no usage). The estimator
# only fires when the measured path finds nothing, and it must NOT bill
# node.js stack traces / tool-call bodies as output — those dominate the raw
# log when gemini-cli dies on a 429 before emitting any assistant message.
# Output is summed from role=="assistant" content only.
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
# With actual assistant content the estimator sums it (delta or whole).
gem_log2="$work/gemini-with-content.log"
printf '%s\n' \
  '{"type":"init","model":"gemini-3.1-pro-preview"}' \
  '{"type":"message","role":"assistant","content":"hello","delta":true}' \
  '{"type":"message","role":"assistant","content":" world","delta":true}' \
  '    at async Object.<anonymous> (file:///.../bundle.js:1:1)' \
  > "$gem_log2"
# agy --print emits plain markdown with no JSON event stream — the whole
# raw log IS the assistant reply (parity with extract_text's agy branch).
# The JSON-event scanner would return 0 here, pinning output to 0 for
# every successful agy cell; the plain-text fallback counts raw length.
gem_log3="$work/gemini-agy-plain.log"
printf 'I have completed the audit and identified two issues in cJSON.\nDetails follow below.\n' \
  > "$gem_log3"

# T13 fixture: a bench dir with one confirmed crash per condition.
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

# T14 fixture: aggregate attributes cluster-tool output to conditions.
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
   "severity_level":"Medium","severity_rank":2,"severity_score":6.5},
  {"id":"CL-2","members":["CRASH-0003"],"size":1,"primitive":"heap-use-after-free",
   "severity_level":"Low","severity_rank":1,"severity_score":3.3}]}
JSON
cat > "$abd/pool-members.json" <<'JSON'
{"crashes":{"CRASH-0001":"model-direct","CRASH-0002":"harness","CRASH-0003":"harness"},
 "findings":{}}
JSON

# T14j fixture: cross-condition severity scored per condition's OWN members.
abd2="$work/agg-bench-permember"
mkdir -p "$abd2/cells"
acell2() {
  mkdir -p "$abd2/cells/$1"
  cat > "$abd2/cells/$1/cell.json" <<JSON
{"condition":"$2","replicate":1,"status":"done","wall_seconds":60,"experiment":"e-$1"}
JSON
  cat > "$abd2/cells/$1/metrics.json" <<JSON
{"confirmed_crashes":1,"crash_dirs":[],"tokens":{"input_tokens":1,"output_tokens":1}}
JSON
}
acell2 model-direct-r1 model-direct
acell2 harness-r1 harness
cat > "$abd2/run.json" <<'JSON'
{"runid":"agg-permember","target":"dummytarget","backend":"codex","replicates":1,
 "conditions":["model-direct","harness"],"target_sha":"a","harness_sha":"b"}
JSON
cat > "$abd2/clusters-crashes.json" <<'JSON'
{"clusters":[
  {"id":"CL-SHARED","members":["CRASH-0005","CRASH-0006"],"size":2,"primitive":"heap-use-after-free",
   "severity_level":"Medium","severity_rank":2,"severity_score":6.4,
   "member_severity":{"CRASH-0005":{"level":"Medium","rank":2,"score":44},
                      "CRASH-0006":{"level":"Low","rank":1,"score":20}}}]}
JSON
cat > "$abd2/pool-members.json" <<'JSON'
{"crashes":{"CRASH-0005":"harness","CRASH-0006":"model-direct"},"findings":{}}
JSON

# T15 fixture: fixture-driven ledger render for dedup/report links. The full
# bin/benchmark dry-run path is covered by T9. This fixture starts at the
# benchmark.py aggregation boundary so link rendering stays covered without
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
 "severity_rank":2,"severity_score":6.4}]}
JSON
touch "$ddir/pool/harness/crashes/CRASH-CLUSTERS.html"
dledger2="$ddir/benchmark-results.md"
dhtml2="$ddir/benchmark-results.html"
ddir_b="$work/dedup-fixture-b"
dup_ledger="$work/dup-ledger.md"

# T15m/T15o resume fixture root + the half-finished replicate the resume
# chain plants between its two dry-runs.
resume_root="$work/resume"
bad_cell="$resume_root/codex/rerun01/cells/model-direct-r2"

# T15p–T15t concurrency-guard fixture root.
lock_root="$work/run-guard"
guard_lock="$lock_root/codex/.run-dummytarget.lock"
mkdir -p "$lock_root/codex"

# T17 ledger output path (renders the T14 bench dir, whose synthetic
# clusters carry severity: CL-1 Medium(48) and CL-2 Low(20)).
t17led="$work/t17-ledger.md"

# T18 fixture: aggregate + ledger expose per-experiment token usage.
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
 "cache_creation_tokens":4,"output_tokens":30,"prompt_estimate_tokens":0,
 "cost_usd":"1.234500","iterations":2}}
JSON
cat > "$tbd/cells/model-direct-r1/cell.json" <<'JSON'
{"condition":"model-direct","replicate":1,"status":"done","wall_seconds":5400,
 "experiment":"bench-tok-model-direct-r1"}
JSON
cat > "$tbd/cells/model-direct-r1/metrics.json" <<'JSON'
{"confirmed_crashes":0,"tokens":{"input_tokens":1234,"cached_input_tokens":0,
 "output_tokens":56,"prompt_estimate_tokens":0,"iterations":1,"estimated":true}}
JSON
tled="$work/tokens-ledger.md"

# T18p fixture: zero-usage rows render as 'unknown', big counts compact.
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
uled="$work/unknown-tokens-ledger.md"

# T19 fixture: aggregate keeps every backend/run/target/condition row.
xroot="$work/xtab-output"
mkbackend() {  # mkbackend <backend> <runid> <crash_total> <unique> [target]
  local bdir="$xroot/benchmark-$1/$2"
  local target="${5:-c-ares}"
  mkdir -p "$bdir"
  cat > "$bdir/report.json" <<JSON
{"run":{"runid":"$2","target":"$target","backend":"$1","model":"$1-m","replicates":3,
 "target_sha":"abcdef123456",
 "tokenfuzz_sha":"feedfacecafebeef1234567890abcdef12345678",
 "budget_wall":3600,"conditions":["model-direct","harness"]},
 "conditions":[
  {"condition":"harness","crash_total":$3,"unique_crash_clusters":$4,
   "finding_total":0,"unique_finding_clusters":0,"wall_median":1800,
   "input_tokens_total":2500000,"output_tokens_total":800000,
   "cost_usd_total":"123.560000",
   "top_severity_level":"Medium","top_severity_rank":2,
   "medium_plus_bugs":1},
  {"condition":"model-direct","crash_total":1,"unique_crash_clusters":1,
   "finding_total":0,"unique_finding_clusters":0,"wall_median":900,
   "input_tokens_total":40000,"output_tokens_total":9000,
   "cost_usd_total":"6.400000",
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
xout="$work/benchmark-crosstab.md"

# T19i fixture: pooled artifacts on disk so crosstab counts hyperlink to
# them; report.json carries the bench_dir to resolve. The per-condition
# split (pool/<cond>/crashes/) is what carries the link — linking a
# condition row to the combined pool/crashes/ would mix in other
# conditions' evidence (see _condition_pool_dir).
xlink="$work/xtab-links"
xlbd="$xlink/benchmark-linky/20260301-000000"
mkdir -p "$xlbd/pool/harness/crashes" "$xlbd/pool/harness/findings" \
         "$xlbd/pool/harness/findings-rejected"
: > "$xlbd/pool/harness/crashes/CRASH-CLUSTERS.html"
: > "$xlbd/pool/harness/findings/FINDING-CLUSTERS.html"
: > "$xlbd/pool/harness/findings-rejected/REJECTED-FINDINGS.html"
cat > "$xlbd/report.json" <<JSON
{"bench_dir":"$xlbd",
 "run":{"runid":"20260301-000000","target":"c-ares","backend":"linky",
  "replicates":1,"budget_wall":3600,"conditions":["harness"]},
 "conditions":[
  {"condition":"harness","crash_total":7,"unique_crash_clusters":3,
   "rejected_finding_total":2,"finding_total":5,
   "unique_finding_clusters":2,"medium_plus_findings":1,
   "top_severity_level":"Medium","top_severity_rank":2,
   "medium_plus_bugs":1}],
 "crash_clusters":[],"finding_clusters":[],"token_usage":[]}
JSON
# The T19k fixture (benchmark-splitty under the same $xlink root) is created
# INSIDE the crosstab job, after the T19i crosstab has been captured —
# adding it earlier would change what the T19i output represents.
spd="$xlink/benchmark-splitty/20260401-000000"

# T20 fixture: relocate-experiments moves external audit trees into the run.
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

# T21 fixture: split-pool copies the pool into per-condition subtrees.
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

# T21e fixture: --pool-name builds/splits into a staging dir.
pnb="$work/poolname-bench"
pnrd="$pnb/results"
mkdir -p "$pnb/cells/harness-r1" "$pnrd/crashes/CRASH-x"
: > "$pnrd/crashes/CRASH-x/asan.txt"
cat > "$pnb/cells/harness-r1/cell.json" <<JSON
{"condition":"harness","replicate":1,"status":"done","wall_seconds":1,
 "results_dir":"$pnrd"}
JSON
cat > "$pnb/cells/harness-r1/metrics.json" <<'JSON'
{"confirmed_crashes":1,"crash_dirs":["CRASH-x"],"findings":0,"findings_rejected":0}
JSON

# ═════════════════════════════════════════════════════════════════════════
# Background job launch — each chain preserves its internal sequencing;
# the chains are mutually independent (disjoint fixture roots).
# ═════════════════════════════════════════════════════════════════════════

# Chain U (T10e2): passes argv parsing and would otherwise launch the
# default 3×2 = 6 dry-run cells (~20s); the assertion only checks the exit
# code, so pin to a single cell.
( set +e
  bash "$BENCH" --target t --dry-run --bench-root "$t10_root" \
    --budget-wall 0 --replicates 1 --conditions harness >/dev/null 2>&1
  echo "$?" > "$work/t10e2.rc"
) &
pid_u=$!

# Chain R (T15m–T15o3): --run-id resume. Same id reuses the same dir (no -2
# fork), cells already done are preserved/skipped, and an incomplete cell is
# wiped and re-run so a half-finished replicate's artifacts never survive
# into the resumed result. Plant a half-finished SECOND replicate (failed,
# with a stale finding) between the runs, as an interrupted run would leave.
( set +e
  bash "$BENCH" --target dummytarget --run-id rerun01 \
    --dry-run --replicates 1 --conditions model-direct \
    --bench-root "$resume_root" >/dev/null 2>&1
  mkdir -p "$bad_cell/findings/FIND-STALE"
  cat > "$bad_cell/cell.json" <<'JSON'
{"condition":"model-direct","replicate":2,"status":"failed"}
JSON
  # Resume with replicates bumped to 2: r1 (done) is skipped, r2 (failed)
  # is wiped clean and re-run.
  bash "$BENCH" --target dummytarget --run-id rerun01 \
    --dry-run --replicates 2 --conditions model-direct \
    --bench-root "$resume_root" > "$work/resume.out" 2>&1
) &
pid_r=$!

# Chain L (T15p–T15t): concurrency guard — one run per (target, backend).
# Two live runs of the same target+backend racing on the shared ledger and
# root crosstab silently double the run — the failure mode that produced
# duplicate ledger rows when two commands were started close together. The
# lock is a single file holding the owner pid; a live owner blocks the
# second launch, and a stale lock left by a killed run is reclaimed.
# ($$ inside the ( ) subshell is still THIS test process — a live holder.)
( set +e
  printf '%s\n' "$$" > "$guard_lock"
  BENCHMARK_RUNID=20260104-010001 bash "$BENCH" --target dummytarget \
    --dry-run --replicates 1 --conditions model-direct \
    --bench-root "$lock_root" > "$work/lock.out" 2>&1
  echo "$?" > "$work/lock.rc"
  # An empty lock file (owner never recorded / process gone) is treated as
  # stale, reclaimed, and the run proceeds — then releases the lock on exit.
  : > "$guard_lock"
  BENCHMARK_RUNID=20260104-010002 bash "$BENCH" --target dummytarget \
    --dry-run --replicates 1 --conditions model-direct \
    --bench-root "$lock_root" >/dev/null 2>&1
) &
pid_l=$!

# J1 (T12): the four llm_usage.py probes.
( set +e
  python3 "$USAGE_PY" gemini "$gem_log"  "$gem_prompt" > "$work/gu1.json"
  python3 "$USAGE_PY" gemini "$gem_log2" "$gem_prompt" > "$work/gu2.json"
  python3 "$USAGE_PY" gemini "$gem_log3" "$gem_prompt" > "$work/gu3.json"
  python3 "$USAGE_PY" codex  "$codex_log"              > "$work/cu.json"
) &
pid_j1=$!

# J2 (T13): pool subcommand.
( set +e
  python3 "$PY" pool "$pbd" >/dev/null
) &
pid_j2=$!

# J3 (T14 + T17): aggregates over $abd/$abd2, then the T17 ledger render of
# the same $abd bench dir (kept in baseline order within the chain).
( set +e
  python3 "$PY" aggregate "$abd"  > "$work/aagg.json"
  python3 "$PY" aggregate "$abd2" > "$work/aagg2.json"
  python3 "$PY" ledger "$abd" --ledger "$t17led" >/dev/null
) &
pid_j3=$!

# J4 (T15): ledger + HTML render, the second-runid append (repeated heading
# anchors), and the same-runid double render (section replaced in place).
( set +e
  python3 "$PY" ledger "$ddir" --ledger "$dledger2" >/dev/null
  python3 "$RENDER_MD" "$dledger2" --html-sibling >/dev/null
  echo "$?" > "$work/t15a.rc"
  # A second run with a DIFFERENT runid appends another section; the
  # repeated "Verdict" / "Scoreboard" headings must get unique anchor ids
  # so in-page links never collide. (Re-rendering the SAME runid replaces
  # in place — see T15i2 — so two distinct runids produce two sections.)
  cp -r "$ddir" "$ddir_b"
  jtmp="$(mktemp)"; jq '.runid="dedup-fixture-b"' "$ddir_b/run.json" > "$jtmp" \
    && mv "$jtmp" "$ddir_b/run.json"
  python3 "$PY" ledger "$ddir_b" --ledger "$dledger2" >/dev/null
  python3 "$RENDER_MD" "$dledger2" --html-sibling >/dev/null
  # Re-rendering the same runid replaces its section instead of stacking a
  # duplicate — a resumed run yields one row, not the interrupted partial
  # plus the completed result.
  python3 "$PY" ledger "$ddir" --ledger "$dup_ledger" >/dev/null
  python3 "$PY" ledger "$ddir" --ledger "$dup_ledger" >/dev/null
) &
pid_j4=$!

# J5 (T18 + T18p): token-usage aggregates and their ledgers.
( set +e
  python3 "$PY" aggregate "$tbd" > "$work/tagg.json"
  python3 "$PY" ledger "$tbd" --ledger "$tled" >/dev/null
  python3 "$PY" aggregate "$ubd" > "$work/uagg.json"
  python3 "$PY" ledger "$ubd" --ledger "$uled" >/dev/null
) &
pid_j5=$!

# J6 (T19 + T19i + T19k): crosstabs. The splitty fixture is created only
# after the T19i crosstab is captured (see fixture note above).
( set +e
  python3 "$PY" crosstab "$xroot" > "$work/xt.md"
  python3 "$PY" crosstab "$xroot" --out "$xout" >/dev/null
  python3 "$RENDER_MD" "$xout" --html-sibling >/dev/null
  python3 "$PY" crosstab "$xlink" > "$work/xtl.md"
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
  python3 "$PY" crosstab "$xlink" > "$work/xts.md"
) &
pid_j6=$!

# J7 (T20): relocate-experiments twice — the second call must be a no-op
# (results_dir already inside the run), proving idempotence. Capture the
# second call's rc: its only directory assertion (T20f) is already true
# after the first call, so without the rc a crash in the idempotent path
# would go unnoticed.
( set +e
  python3 "$PY" relocate-experiments "$rbd" >/dev/null
  python3 "$PY" relocate-experiments "$rbd" >/dev/null
  echo $? > "$work/relocate-second.rc"
) &
pid_j7=$!

# J8 (T21 + T21e): split-pool, plus pool/split into a named staging dir.
( set +e
  python3 "$PY" split-pool "$sbd" >/dev/null
  python3 "$PY" pool "$pnb" --pool-name .pool.staging >/dev/null
  python3 "$PY" split-pool "$pnb" --pool-name .pool.staging >/dev/null
) &
pid_j8=$!

# ── T10: argument validation ─────────────────────────────────────────────
# These all fail at argv-parse so they're cheap; run them inline. The one
# case that passes parsing (--budget-wall 0) runs as chain U above and is
# asserted with the other dry-run chains at the bottom of the file.
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
wait "$pid_j1" || true
gu=$(cat "$work/gu1.json" 2>/dev/null || true)
assert_eq "true" "$(echo "$gu" | jq -r '.estimated')" "T12a: gemini path flagged estimated"
in_est=$(echo "$gu" | jq -r '.tokens.input')
out_est=$(echo "$gu" | jq -r '.tokens.output')
[ "$in_est" -gt 0 ] && pass "T12b: gemini input estimated > 0" \
  || fail "T12b: gemini input estimated > 0" "got $in_est"
# No assistant message in the stream → estimated output is 0, not the
# length of error chatter / tool_use parameters.
assert_eq "0" "$out_est" \
  "T12c: gemini estimate excludes non-assistant noise from output"

gu2=$(cat "$work/gu2.json" 2>/dev/null || true)
out_est2=$(echo "$gu2" | jq -r '.tokens.output')
# "hello" + " world" = 11 chars → ceil(11/4) = 3 tokens
assert_eq "3" "$out_est2" \
  "T12c2: assistant content summed for the output estimate"

gu3=$(cat "$work/gu3.json" 2>/dev/null || true)
out_est3=$(echo "$gu3" | jq -r '.tokens.output')
# 85 chars → ceil(85/4) = 22 tokens
assert_eq "22" "$out_est3" \
  "T12c3: agy plain-text raw log counted as assistant output"

# A real usage object must NOT be flagged estimated.
assert_eq "false" "$(jq -r '.estimated' "$work/cu.json")" \
  "T12d: measured codex usage not flagged estimated"

# ── T13: pool subcommand copies cell crash dirs into pool/ ───────────────
wait "$pid_j2" || true
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

# T13i-n: confirmed findings, not raw FIND dirs, drive the benchmark headline
# and pool. Raw volume stays in report.json for auditability, but a pending
# FIND the gate never accepted must not inflate Findings or Unique findings.
cfroot="$work/confirmed-findings-root"
cfbd="$cfroot/codex/cf-run"
cfrd="$cfbd/results"
mkdir -p "$cfbd/cells/harness-r1" "$cfrd/findings/FIND-A" \
         "$cfrd/findings/FIND-B"
cat > "$cfbd/run.json" <<'JSON'
{"runid":"cf-run","target":"sampleproj","backend":"codex","replicates":1,
 "budget_wall":60,"conditions":["harness"],"target_sha":"abc","harness_sha":"def"}
JSON
cat > "$cfbd/cells/harness-r1/cell.json" <<JSON
{"condition":"harness","replicate":1,"status":"done","wall_seconds":60,
 "results_dir":"$cfrd"}
JSON
cat > "$cfbd/cells/harness-r1/metrics.json" <<'JSON'
{"confirmed_crashes":0,"crash_dirs":[],"findings":2,
 "confirmed_findings":1,"confirmed_finding_dirs":["FIND-A"],
 "findings_rejected":0,"tokens":{"output_tokens":0}}
JSON
printf '# Accepted\n\nLocation: catalog.c:1\n' \
  > "$cfrd/findings/FIND-A/report.md"
printf '# Pending\n\nLocation: catalog.c:2\n' \
  > "$cfrd/findings/FIND-B/report.md"
python3 "$PY" pool "$cfbd" >/dev/null
assert_eq "1" "$(find "$cfbd/pool/findings" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" \
  "T13i: pool imports only confirmed finding dirs"
assert_file_contains "$cfbd/pool/findings/FIND-0001/report.md" 'Accepted' \
  "T13j: confirmed finding is pooled"
assert_file_not_contains "$cfbd/pool/findings/FIND-0001/report.md" 'Pending' \
  "T13k: unconfirmed finding is not pooled"
python3 "$PY" split-pool "$cfbd" >/dev/null
python3 "$PY" aggregate "$cfbd" --out "$cfbd/report.json" >/dev/null
assert_eq "2" "$(jq -r '.conditions[0].finding_total' "$cfbd/report.json")" \
  "T13l: aggregate preserves raw finding_total for auditability"
assert_eq "1" "$(jq -r '.conditions[0].confirmed_finding_total' "$cfbd/report.json")" \
  "T13m: aggregate carries confirmed_finding_total"
python3 "$PY" ledger "$cfbd" --ledger "$cfbd/benchmark-results.md" >/dev/null
assert_file_contains "$cfbd/benchmark-results.md" 'tokenfuzz.*\[1\]\([^)]*pool/harness/findings[^)]*\)' \
  "T13n: ledger Findings column renders the confirmed count (1) only, not raw (2) or an un-gated suffix"
assert_file_not_contains "$cfbd/benchmark-results.md" 'un-gated' \
  "T13n2: ledger Findings column carries no un-gated suffix"
python3 "$PY" crosstab "$cfroot" --out "$cfroot/benchmark-result.md" >/dev/null
assert_file_contains "$cfroot/benchmark-result.md" 'tokenfuzz.*\[1\]\([^)]*pool/harness/findings[^)]*\)' \
  "T13o: crosstab Findings column renders the confirmed count (1) only, not raw (2) or an un-gated suffix"
assert_file_not_contains "$cfroot/benchmark-result.md" 'un-gated' \
  "T13o2: crosstab Findings column carries no un-gated suffix"

# ── T14: aggregate attributes cluster-tool output to conditions ──────────
wait "$pid_j3" || true
aagg=$(cat "$work/aagg.json" 2>/dev/null || true)
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
# Without per-member severity (older cluster JSON) the cluster-level severity
# is carried straight through to every condition that reached the cluster.
assert_eq "Medium" "$(echo "$ahd" | jq -r '.top_severity_level')" \
  "T14f: harness top crash severity is Medium (CL-1)"
assert_eq "1" "$(echo "$ahd" | jq -r '.medium_plus_bugs')" \
  "T14g: harness has one Medium+ bug"
assert_eq "Medium" "$(echo "$anv" | jq -r '.top_severity_level')" \
  "T14h: model-direct top crash severity falls back to cluster-level Medium (no member_severity)"
assert_eq "1" "$(echo "$anv" | jq -r '.medium_plus_bugs')" \
  "T14h2: model-direct medium_plus falls back to the shared Medium cluster"
assert_eq "6.5" \
  "$(echo "$aagg" | jq -r '.crash_clusters[] | select(.id=="CL-1") | .severity_score')" \
  "T14i: cluster list carries severity_score from the cluster tool"

# T14j: cross-condition severity must be scored per condition's OWN members.
# A crash cluster shared by a harness Medium crash and a model-direct Low crash
# (same crash state) must NOT credit model-direct with the harness Medium — the
# real-world bug where the crosstab showed model-direct "Medium" while its only
# crash report was Low. With member_severity present, each condition is scored
# by its own member.
aagg2=$(cat "$work/aagg2.json" 2>/dev/null || true)
ahd2=$(echo "$aagg2" | jq -c '.conditions[] | select(.condition=="harness")')
anv2=$(echo "$aagg2" | jq -c '.conditions[] | select(.condition=="model-direct")')
assert_eq "Medium" "$(echo "$ahd2" | jq -r '.top_severity_level')" \
  "T14j: harness top crash severity is its own Medium crash"
assert_eq "Low" "$(echo "$anv2" | jq -r '.top_severity_level')" \
  "T14k: model-direct top crash severity is its OWN Low crash, not the harness Medium"
assert_eq "0" "$(echo "$anv2" | jq -r '.medium_plus_bugs')" \
  "T14l: model-direct has no Medium+ bug (its only crash is Low)"
assert_eq "1" "$(echo "$ahd2" | jq -r '.medium_plus_bugs')" \
  "T14m: harness counts its own Medium+ bug"

# ── T15: fixture-driven ledger render for dedup/report links ─────────────
wait "$pid_j4" || true
assert_eq "0" "$(cat "$work/t15a.rc" 2>/dev/null || true)" \
  "T15a: fixture ledger renders without a full benchmark rerun"
# Scoreboard counts are reviewer links; the `harness` condition renders under
# its product label `tokenfuzz`.
assert_file_contains "$dledger2" 'tokenfuzz.*\[3\]\([^)]*pool/harness/crashes[^)]*\).*\[1 \(1 M\+\)\]\([^)]*CRASH-CLUSTERS\.[a-z]*[^)]*\)' \
  "T15b: scoreboard shows 3 crashes deduplicated to 1 unique bug, annotated as 1 Medium+"
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
assert_file_contains "$dhtml2" 'id="verdict-2"' \
  "T15i: a repeated heading across runs gets a deduplicated anchor id"
heading_count="$(grep -c '^## Benchmark run `dedup-fixture`' "$dup_ledger" || true)"
assert_eq "1" "$heading_count" \
  "T15i2: re-rendering the same runid replaces its ledger section (no duplicate)"

# ── T17: the ledger renders a severity-sorted bug table ──────────────────
# Reuses the T14 bench dir, whose synthetic clusters carry severity:
# CL-1 Medium(48) and CL-2 Low(20) must render Medium-first. (Rendered by
# job J3, already waited on above.)
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
wait "$pid_j5" || true
tagg=$(cat "$work/tagg.json" 2>/dev/null || true)
th=$(echo "$tagg" | jq -c '.conditions[] | select(.condition=="harness")')
tm=$(echo "$tagg" | jq -c '.conditions[] | select(.condition=="model-direct")')
assert_eq "10" "$(echo "$th" | jq -r '.input_tokens_total')" \
  "T18a: harness input token total aggregated"
assert_eq "20" "$(echo "$th" | jq -r '.cached_input_tokens_total')" \
  "T18b: harness cached token total aggregated"
assert_eq "4" "$(echo "$th" | jq -r '.cache_creation_tokens_total')" \
  "T18b2: harness cache-write token total aggregated"
assert_eq "1.234500" "$(echo "$th" | jq -r '.cost_usd_total')" \
  "T18b3: harness cost total aggregated"
assert_eq "measured" "$(echo "$th" | jq -r '.token_source')" \
  "T18c: measured source reported for measured row"
assert_eq "estimated" "$(echo "$tm" | jq -r '.token_source')" \
  "T18d: estimated source reported for estimated row"
assert_eq "bench-tok-model-direct-r1" \
  "$(echo "$tagg" | jq -r '.token_usage[] | select(.condition=="model-direct") | .experiment')" \
  "T18e: token_usage preserves experiment name"
assert_file_contains "$tled" 'Token usage' "T18f: ledger has token usage table"
assert_file_contains "$tled" 'bench-tok-model-direct-r1' \
  "T18g: ledger lists per-experiment token usage"
assert_file_contains "$tled" 'estimated.*1,234' \
  "T18h: ledger marks estimated token rows and formats counts"
assert_file_contains "$tled" '\$1\.2345' \
  "T18h2: ledger renders token cost"

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
uagg=$(cat "$work/uagg.json" 2>/dev/null || true)
assert_eq "mixed" \
  "$(echo "$uagg" | jq -r '.conditions[]|select(.condition=="harness")|.token_source')" \
  "T18p: a condition mixing measured + unknown rows reports 'mixed'"
assert_file_contains "$uled" 'unknown' \
  "T18q: a cell with no usage telemetry renders source 'unknown'"
assert_file_contains "$uled" '2\.5M' \
  "T18r: million-scale token counts render compactly (2.5M, not 2,500,000)"
assert_file_contains "$uled" '1\.2M' \
  "T18s: million-scale output tokens render compactly"

# ── T19: aggregate keeps every backend/run/target/condition row ─────
wait "$pid_j6" || true
xt=$(cat "$work/xt.md" 2>/dev/null || true)
assert_match 'Aggregated benchmark results' "$xt" "T19a: crosstab has a title"
assert_match 'Input \| Output \| Cost' "$xt" "T19a2: crosstab has a cost column"
assert_match '\$124' "$xt" "T19a3: crosstab rounds cost to whole dollars"
assert_not_match '\$123\.5600' "$xt" \
  "T19a4: crosstab omits decimal cost to keep the table narrow"
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
assert_match '`c-ares`<br>`abcdef1`' "$xt" \
  "T19g3a: aggregate stacks the audited target short hash in the Target cell"
assert_match '`tokenfuzz`' "$xt" \
  "T19g3a2: aggregate shows tokenfuzz without its recorded repo hash"
assert_not_match '`tokenfuzz`<br>' "$xt" \
  "T19g3a2b: aggregate keeps the TokenFuzz repo hash out of the table"
assert_not_match '`20260101-000000` `abcdef1`' "$xt" \
  "T19g3a3: aggregate no longer duplicates the target hash in the Run cell"
# A stand-alone Commit column would push the table to a width that
# horizontally scrolls in the rendered HTML. Keep identity metadata in
# the Run cell so adding more identifiers does not grow column count.
commit_header_cells=$(printf '%s\n' "$xt" \
  | grep -c '^| Target | Backend | Condition | Run | Wall' || true)
assert_eq "$commit_header_cells" "1" \
  "T19g3b: aggregate has no dedicated Commit column"
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
assert_file_exists "$xout" "T19h: crosstab --out writes a markdown file"
# The wide crosstab gets a dedicated `.benchmark-table` CSS class so
# the harness-wide `min-width: max-content` rule doesn't force horizontal
# scrolling on the rendered HTML sibling.
assert_file_contains "${xout%.md}.html" 'class="benchmark-table"' \
  "T19h1: crosstab HTML gets the dedicated table layout"
assert_file_contains "${xout%.md}.html" 'td:nth-child\(1\) br \+ code' \
  "T19h1b: crosstab HTML styles stacked target hashes as secondary metadata"

# T19h2-4: the crosstab carries wall time and token cost, compact-formatted.
assert_match 'Wall \(h\)' "$xt" "T19h2: crosstab has a Wall column"
assert_match '0\.50h' "$xt" "T19h3: crosstab renders wall as decimal hours"
assert_match '2\.5M' "$xt" \
  "T19h4: crosstab renders million-scale token totals compactly"

# T19i: when a run's pooled artifacts are on disk, the crosstab counts
# hyperlink to them; report.json carries the bench_dir to resolve.
xtl=$(cat "$work/xtl.md" 2>/dev/null || true)
assert_match '\[7\]\([^)]*pool/harness/crashes[^)]*\)' "$xtl" \
  "T19i: crosstab crash count links to the per-condition crash tree"
assert_match '\[3 \(1 M\+\)\]\([^)]*CRASH-CLUSTERS\.html[^)]*\)' "$xtl" \
  "T19j: crosstab unique crash count is annotated with its Medium+ subset and links to the cluster report"
assert_match '\[2 \(1 M\+\)\]\([^)]*FINDING-CLUSTERS\.html[^)]*\)' "$xtl" \
  "T19j2: crosstab unique finding count is annotated with its Medium+ subset and links to the cluster report"
assert_match '\[2\]\([^)]*REJECTED-FINDINGS\.html[^)]*\)' "$xtl" \
  "T19k: crosstab rejected finding count links to the rendered rejected list"

# ── T20: relocate-experiments moves external audit trees into the run ────
wait "$pid_j7" || true
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
# Idempotent: the job's second call was a clean no-op (results_dir inside
# the run) — the tree is intact AND the call exited 0 rather than crashing.
if [ -d "$rbd/experiments/harness-r1" ] && [ "$(cat "$work/relocate-second.rc" 2>/dev/null)" = "0" ]; then
  pass "T20f: relocate-experiments is idempotent"
else
  fail "T20f: relocate-experiments is idempotent" \
    "tree=$([ -d "$rbd/experiments/harness-r1" ] && echo intact || echo missing) second_rc=$(cat "$work/relocate-second.rc" 2>/dev/null)"
fi

# ── T21: split-pool copies the pool into per-condition subtrees ──────────
wait "$pid_j8" || true
assert_dir_exists "$sbd/pool/harness/crashes/CRASH-0001" \
  "T21a: harness crash copied into pool/harness/"
assert_dir_exists "$sbd/pool/model-direct/crashes/CRASH-0002" \
  "T21b: model-direct crash copied into pool/model-direct/"
assert_dir_not_exists "$sbd/pool/harness/crashes/CRASH-0002" \
  "T21c: a condition's subtree holds only its own crashes"
assert_dir_exists "$sbd/pool/harness/findings/FIND-0001" \
  "T21d: findings are split by condition too"

# ── T21e: --pool-name builds/splits into a staging dir (atomic-swap support) ──
# bin/benchmark builds the whole pool in .pool.staging and renames it onto
# pool/ at the end, so build_pool/split_pool must honour a non-default pool
# dir name and never touch the live pool/ while staging.
assert_dir_exists "$pnb/.pool.staging/crashes" \
  "T21e: pool --pool-name builds into the named staging dir"
assert_dir_not_exists "$pnb/pool" \
  "T21f: pool --pool-name leaves the live pool/ untouched"
assert_dir_exists "$pnb/.pool.staging/harness/crashes" \
  "T21g: split-pool --pool-name splits within the staging dir"

# ── T19k: crosstab links each condition to its own per-condition tree ────
xts=$(cat "$work/xts.md" 2>/dev/null || true)
assert_match '\[4\]\([^)]*pool/harness/crashes[^)]*\)' "$xts" \
  "T19k: harness count links to the harness per-condition tree"
assert_match '\[9\]\([^)]*pool/model-direct/crashes[^)]*\)' "$xts" \
  "T19l: model-direct count links to the model-direct per-condition tree"

# ── T10e2 + T15m–T15t: the dry-run chains, asserted last so the bench
# invocations overlap the whole python/jq assertion phase above. ─────────
wait "$pid_u" || true
assert_eq "0" "$(cat "$work/t10e2.rc" 2>/dev/null || true)" \
  "T10e2: --budget-wall 0 accepted as unlimited"

wait "$pid_r" || true
assert_dir_exists "$resume_root/codex/rerun01" \
  "T15m: --run-id names the run directory"
assert_dir_not_exists "$resume_root/codex/rerun01-2" \
  "T15n: a repeated run-id reuses its dir instead of forking a -2 suffix"
resume_out=$(cat "$work/resume.out" 2>/dev/null || true)
assert_match 'already done — skipping' "$resume_out" \
  "T15o: resume skips a replicate already marked done"
assert_dir_not_exists "$bad_cell/findings/FIND-STALE" \
  "T15o2: resume wipes a half-finished replicate before re-running it"
assert_eq "done" "$(jq -r '.status' "$bad_cell/cell.json")" \
  "T15o3: the re-run replicate completes and is marked done"

wait "$pid_l" || true
lock_out=$(cat "$work/lock.out" 2>/dev/null || true)
assert_eq "1" "$(cat "$work/lock.rc" 2>/dev/null || true)" \
  "T15p: a concurrent run for the same target+backend is refused"
assert_match 'for target=dummytarget backend=codex is already running' "$lock_out" \
  "T15q: the refusal names the in-progress target+backend"
assert_dir_not_exists "$lock_root/codex/20260104-010001" \
  "T15r: a refused run creates no run directory"
assert_dir_exists "$lock_root/codex/20260104-010002" \
  "T15s: a stale lock is reclaimed and the run proceeds"
assert_file_not_exists "$guard_lock" \
  "T15t: the run releases its target+backend lock on exit"


summary
