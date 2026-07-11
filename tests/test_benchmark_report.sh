#!/usr/bin/env bash
# Tests for bin/benchmark: prompt rendering, launch wiring, gemini watchdog (T22–T32).
#
# Carved out of test_benchmark.sh so the benchmark suite's ~150s of
# `bash bin/benchmark` dry-runs (each spawning ~30 python subprocesses)
# splits across cores under tests/run-tests.sh instead of pinning one.
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
# bypasses the helper's introspection (the .j2 still
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
# asan_bin / asan_lib are TARGET_ROOT-relative and carry the build-asan/
# prefix in their value — the same convention as a real target.toml and as
# target_resolve_path (NOT relative to build-asan/, which doubled the prefix).
asan_bin = "build-asan/src/fake-cli"
asan_lib = "build-asan/lib/libfake.a"
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
# It ALSO traces its --cd/--add-dir argv to stderr (consumed by T27): the
# bench invocation here and the one T27 used to make were byte-identical
# apart from --bench-root, so a single run now serves T24–T27.
fake_codex_early="$work/fake-codex-early"
cat > "$fake_codex_early" <<'SH'
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
printf '{"type":"item.completed","usage":{"input_tokens":1,"cached_input_tokens":0,"output_tokens":1}}\n'
SH
chmod +x "$fake_codex_early"
trap 'rm -rf "$work" "$target_dir" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT
early_out=$(CODEX_BIN="$fake_codex_early" "$BENCH" \
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
usage_index="$cell_dir/logs/index.jsonl"
assert_eq "1" "$(jq -r '.tokens.input' "$usage_index")" \
  "T25f2: model-direct persists measured backend usage"
assert_eq "codex" "$(jq -r '.backend' "$usage_index")" \
  "T25f3: model-direct usage records the active backend"

# --no-validate-findings is announced in the cell log.
assert_match 'Cell model-direct-r1 validation: DISABLED' "$early_out" \
  "T25g: --no-validate-findings is announced in the cell log"
assert_match 'findings: rejected=0 confirmed=0 pending=0 roots=0; crashes: rejected=0 confirmed=0 unique=0' "$early_out" \
  "T25g2: model-direct gate logs findings and crashes counts"

# Regression: with validation enabled, the model-direct findings gate must be
# the find-quality MOVER (validate_find_gate), which quarantines a find-quality
# reject at quorum into findings-rejected/ — not the scoring-only coverage belt
# that leaves the reject in findings/ rendering forever as a "Pending" severity
# in the cluster. The harness reaches the same mover via bin/audit housekeeping;
# this keeps model-direct on par so rejected finds move (and counts settle).
assert_file_contains "$SCRIPT_ROOT/lib/benchmark_runner.py" 'counts = triage.validate_find_gate\(results, deadline=deadline\)' \
  "T25h: model-direct findings gate runs validate_find_gate (quarantines find-quality rejects)"
assert_file_contains "$SCRIPT_ROOT/lib/benchmark_runner.py" 'ACTIVE_BACKEND.*backend' \
  "T25j: model-direct find gate gets benchmark model for trigger gate"
assert_file_contains "$SCRIPT_ROOT/lib/benchmark_runner.py" '"TARGET_SLUG": target_slug' \
  "T25i: model-direct find gate threads TARGET_ROOT so the source-reading trigger step runs"

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
# Asserted against the T24 run: same bench flags, and the fake codex
# (see fake_codex_early above) traces the argv it received.
# Agent stdout+stderr go to backend.raw.log; the FAKE_* trace lines land
# there, not in the bench's own stdout.
raw_log=$(find "$early_root/codex" \
  -path '*/cells/model-direct-r1/backend.raw.log' | head -1)
fake_cd=$(sed -n 's/^FAKE_CD=//p' "$raw_log" | head -1)
fake_adds=$(sed -n 's/^FAKE_ADDS=//p' "$raw_log" | head -1)
assert_eq "$cell_dir" "$fake_cd" \
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

# Pool severity rescoring needs the same threat model as the source cell.
# build_pool preserves target.toml when every done cell belongs to the same
# target config, so pooled crashes are not scored from stale Contract concern
# prose after attacker_controls changes.
cfg_bench="$work/pool-config-bench"
cfg_rd="$cfg_bench/output/sampleproj/backend/results"
cfg_rd2="$cfg_bench/output/sampleproj-r2/backend/results"
mkdir -p "$cfg_rd" "$cfg_rd2" "$cfg_bench/cells/cfg-r1" "$cfg_bench/cells/cfg-r2"
cat > "$cfg_bench/output/sampleproj/target.toml" <<'TOML'
includes = ["/tmp/cell-one/generated"]
[threat_model]
attacker_controls = ["bytes", "call-sequence"]
TOML
cat > "$cfg_bench/output/sampleproj-r2/target.toml" <<'TOML'
includes = ["/tmp/cell-two/generated"]
[threat_model]
attacker_controls = ["bytes", "call-sequence"]
TOML
cat > "$cfg_bench/cells/cfg-r1/cell.json" <<EOF
{"condition":"harness","replicate":1,"experiment":"t","status":"done","wall_seconds":1,"results_dir":"$cfg_rd"}
EOF
cat > "$cfg_bench/cells/cfg-r2/cell.json" <<EOF
{"condition":"harness","replicate":2,"experiment":"t","status":"done","wall_seconds":1,"results_dir":"$cfg_rd2"}
EOF
cat > "$cfg_bench/cells/cfg-r1/metrics.json" <<'JSON'
{"crash_dirs":[]}
JSON
cat > "$cfg_bench/cells/cfg-r2/metrics.json" <<'JSON'
{"crash_dirs":[]}
JSON
python3 "$PY" pool "$cfg_bench" >/dev/null
assert_file_contains "$cfg_bench/pool/target.toml" 'attacker_controls = \["bytes", "call-sequence"\]' \
  "T28l: build_pool preserves matching attacker_controls for pooled rescoring"

# Cells whose configs differ only by an attacker_controls ALIAS (call-order vs
# call-sequence) or token ordering still agree after normalisation, so the pool
# gets a synthesized target.toml rather than going unscored.
nrm_bench="$work/pool-normalize-bench"
nrm_rd="$nrm_bench/output/sampleproj/backend/results"
nrm_rd2="$nrm_bench/output/sampleproj-r2/backend/results"
mkdir -p "$nrm_rd" "$nrm_rd2" "$nrm_bench/cells/n-r1" "$nrm_bench/cells/n-r2"
cat > "$nrm_bench/output/sampleproj/target.toml" <<'TOML'
includes = ["/tmp/cell-one/generated"]
[threat_model]
attacker_controls = ["call-order", "bytes"]
TOML
cat > "$nrm_bench/output/sampleproj-r2/target.toml" <<'TOML'
includes = ["/tmp/cell-two/generated"]
[threat_model]
attacker_controls = ["bytes", "call-sequence"]
TOML
cat > "$nrm_bench/cells/n-r1/cell.json" <<EOF
{"condition":"harness","replicate":1,"experiment":"t","status":"done","wall_seconds":1,"results_dir":"$nrm_rd"}
EOF
cat > "$nrm_bench/cells/n-r2/cell.json" <<EOF
{"condition":"harness","replicate":2,"experiment":"t","status":"done","wall_seconds":1,"results_dir":"$nrm_rd2"}
EOF
echo '{"crash_dirs":[]}' > "$nrm_bench/cells/n-r1/metrics.json"
echo '{"crash_dirs":[]}' > "$nrm_bench/cells/n-r2/metrics.json"
python3 "$PY" pool "$nrm_bench" >/dev/null
assert_file_contains "$nrm_bench/pool/target.toml" 'attacker_controls = \["bytes", "call-sequence"\]' \
  "T28m: build_pool normalises call-order→call-sequence so aliased cells still pool"

# T28n: the canonical live target.toml wins over a stale cell snapshot, so a
# re-score reflects the CURRENT threat model — not the model frozen at run time.
# (The threat model is target-level config; only the crash artifacts are
# run-level data.) Falls back to the cell snapshots when no live model exists.
tnp="$TEST_TMPDIR/pool-live-target"
mkdir -p "$tnp/pool" "$tnp/cells"
printf '[threat_model]\nattacker_controls = ["bytes", "call-sequence"]\n' > "$tnp/stale-cell.toml"
printf '[threat_model]\nattacker_controls = ["bytes"]\n' > "$tnp/live.toml"
python3 - "$tnp" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, "lib")
import benchmark
base = Path(sys.argv[1])
# live model present → it wins over the stale cell snapshot
benchmark._copy_pool_target_toml(base / "pool", [base / "stale-cell.toml"],
                                 live_target_toml=base / "live.toml")
PY
assert_file_contains "$tnp/pool/target.toml" 'attacker_controls = \["bytes"\]' \
  "T28n: live target.toml overrides stale cell snapshot on re-score"
rm -f "$tnp/pool/target.toml"
python3 - "$tnp" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, "lib")
import benchmark
base = Path(sys.argv[1])
# no live model → fall back to the cell snapshot
benchmark._copy_pool_target_toml(base / "pool", [base / "stale-cell.toml"],
                                 live_target_toml=None)
PY
assert_file_contains "$tnp/pool/target.toml" 'attacker_controls = \["bytes", "call-sequence"\]' \
  "T28n: falls back to cell snapshot when no live model is available"

# T28o: a nested target slug (output/samples/demo/...) resolves its target.toml
# from a cell results dir even though the target root is not a direct child of
# output/. Without this the pooled rescore silently loses its threat model.
tnest="$TEST_TMPDIR/pool-nested-toml"
mkdir -p "$tnest/output/samples/demo/backend/results/findings"
printf '[threat_model]\nattacker_controls = ["bytes"]\n' > "$tnest/output/samples/demo/target.toml"
found_nested=$(python3 - "$tnest/output/samples/demo/backend/results" <<'PY'
import sys
from pathlib import Path
sys.path.insert(0, "lib")
import benchmark
print(benchmark._find_output_target_toml(Path(sys.argv[1])) or "")
PY
)
assert_match '/output/samples/demo/target.toml$' "$found_nested" \
  "T28o: nested slug resolves target.toml from a cell results dir"

# A rejected crash directory must link to its rendered report, not the bare
# directory. The source markdown points at the .md (canonical path); the
# rendered HTML sibling rewrites it to .html so a click lands on the styled
# report rather than a directory listing.
rej_idx="$work/rejected-link"
mkdir -p "$rej_idx/CRASH-REJECTED-0001"
cat > "$rej_idx/CRASH-REJECTED-0001/REPORT.md" <<'EOF'
# Rejected crash one
Trigger source: bytes
EOF
python3 - <<PY
import sys
from pathlib import Path
sys.path.insert(0, "$SCRIPT_ROOT/lib")
import benchmark
benchmark.write_rejected_crashes_index(Path("$rej_idx"))
PY
rej_idx_md=$(cat "$rej_idx/REJECTED-CRASHES.md")
assert_match '\[Link\]\(CRASH-REJECTED-0001/REPORT\.md\)' "$rej_idx_md" \
  "T28i: REJECTED-CRASHES.md links a rejected crash to its REPORT.md, not the dir"
assert_match '\| ID \| Site \| Reason \| Report \|' "$rej_idx_md" \
  "T28i2: REJECTED-CRASHES.md uses the unified ID | Site | Reason | Report header"
assert_not_match '\[CRASH-REJECTED-0001/\]\(CRASH-REJECTED-0001/\)' "$rej_idx_md" \
  "T28j: REJECTED-CRASHES.md no longer links to the bare directory"
python3 "$RENDER_MD" "$rej_idx/REJECTED-CRASHES.md" --html-sibling >/dev/null 2>&1
rej_idx_html=$(cat "$rej_idx/REJECTED-CRASHES.html")
assert_match 'href="CRASH-REJECTED-0001/REPORT\.html"' "$rej_idx_html" \
  "T28k: rendered REJECTED-CRASHES.html href points to the report's HTML sibling"

# Cluster pages link to the named rejected-summary artifact in both layouts.
cluster_links="$work/rejected-cluster-links"
mkdir -p "$cluster_links/results/crashes" \
         "$cluster_links/results/crashes-rejected" \
         "$cluster_links/results/findings" \
         "$cluster_links/results/findings-rejected" \
         "$cluster_links/pool/harness/crashes" \
         "$cluster_links/pool/harness/crashes-rejected" \
         "$cluster_links/pool/harness/findings" \
         "$cluster_links/pool/harness/findings-rejected"
echo '# Rejected crash index' \
  > "$cluster_links/results/crashes-rejected/REJECTED-CRASHES.md"
echo '# Rejected finding index' \
  > "$cluster_links/results/findings-rejected/REJECTED-FINDINGS.md"
echo '# Rejected crash pool summary' \
  > "$cluster_links/pool/harness/crashes-rejected/REJECTED-CRASHES.md"
echo '# Rejected finding pool summary' \
  > "$cluster_links/pool/harness/findings-rejected/REJECTED-FINDINGS.md"
python3 "$SCRIPT_ROOT/bin/cluster-crashes" "$cluster_links/results" >/dev/null
python3 "$SCRIPT_ROOT/bin/cluster-findings" "$cluster_links/results" >/dev/null
python3 "$SCRIPT_ROOT/bin/cluster-crashes" "$cluster_links/pool/harness" >/dev/null
python3 "$SCRIPT_ROOT/bin/cluster-findings" "$cluster_links/pool/harness" >/dev/null
regular_crash_html=$(cat "$cluster_links/results/crashes/CRASH-CLUSTERS.html")
regular_finding_html=$(cat "$cluster_links/results/findings/FINDING-CLUSTERS.html")
pool_crash_html=$(cat "$cluster_links/pool/harness/crashes/CRASH-CLUSTERS.html")
pool_finding_html=$(cat "$cluster_links/pool/harness/findings/FINDING-CLUSTERS.html")
assert_match 'href="../crashes-rejected/REJECTED-CRASHES\.html"' "$regular_crash_html" \
  "T28r: regular crash clusters link to REJECTED-CRASHES.html"
assert_match 'href="../findings-rejected/REJECTED-FINDINGS\.html"' "$regular_finding_html" \
  "T28s: regular finding clusters link to REJECTED-FINDINGS.html"
assert_match 'href="../crashes-rejected/REJECTED-CRASHES\.html"' "$pool_crash_html" \
  "T28t: benchmark crash clusters link to REJECTED-CRASHES.html"
assert_match 'href="../findings-rejected/REJECTED-FINDINGS\.html"' "$pool_finding_html" \
  "T28u: benchmark finding clusters link to REJECTED-FINDINGS.html"

# ═══════════════════════════════════════════════════════════════
# P6: cell.json records actual_agents vs requested_agents
# ═══════════════════════════════════════════════════════════════
# Run bin/benchmark end-to-end in --dry-run with --agents and a stubbed
# state/run-config.json planted into each cell's results_dir to verify
# the cell.json shape that downstream report aggregators read.
p6_bd="$work/p6-cell"
mkdir -p "$p6_bd/cells/harness-r1/repo-root/output/p6target-exp/codex/results/state"
mkdir -p "$p6_bd/cells/model-direct-r1/state"

# Exercise the same structured command bin/benchmark invokes. The shell driver
# auto-runs when sourced, so its Python CLI is the stable test boundary.
p6_write_cell_json() {
  python3 "$SCRIPT_ROOT/lib/benchmark.py" write-cell "$@"
}

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

# Case C: model-direct cells have no run-config →
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

summary
