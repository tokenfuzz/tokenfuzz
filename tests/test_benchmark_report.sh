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

# Regression: with validation enabled, the model-direct findings gate must be
# the find-quality MOVER (validate_find_gate), which quarantines a find-quality
# reject at quorum into findings-rejected/ — not the scoring-only coverage belt
# that leaves the reject in findings/ rendering forever as a "Pending" severity
# in the cluster. The harness reaches the same mover via bin/audit housekeeping;
# this keeps model-direct on par so rejected finds move (and counts settle).
assert_file_contains "$BENCH" 'validate_find_gate >/dev/null 2>&1' \
  "T25h: model-direct findings gate runs validate_find_gate (quarantines find-quality rejects)"

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

# (a) Detector: source the shared watchdog lib. The detector used to be
#     a private function in bin/benchmark, extracted via awk from the
#     script body; it now lives in lib/gemini_watchdog.sh and is shared
#     with bin/audit. Source it directly — the lib has no side effects
#     beyond defining functions.
# shellcheck disable=SC1091
. "$SCRIPT_ROOT/lib/gemini_watchdog.sh"

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
mkdir -p "$qbd/cells/model-direct-r1/findings/FIND-DONE" \
         "$qbd/cells/model-direct-r2/findings/FIND-QUOTA"
printf '# done finding\n' > "$qbd/cells/model-direct-r1/findings/FIND-DONE/report.md"
printf '# quota finding\n' > "$qbd/cells/model-direct-r2/findings/FIND-QUOTA/report.md"
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
{"exists":true,"confirmed_crashes":0,"findings":1,
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
python3 "$PY" pool "$qbd" >/dev/null
assert_eq "1" "$(find "$qbd/pool/findings" -mindepth 1 -maxdepth 1 -type d | wc -l | tr -d ' ')" \
  "T29i2: pool excludes quota_exhausted findings so clusters match totals"

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

# The sweep helper runs inside cell runners whose stdout is command-substituted
# as the returned results_dir. Its diagnostics must stay off stdout or a
# successful cell harvests against a multi-line non-path string.
mkdir -p "$swp_work/target3"
swp_capture_out=$(bash -c '
  set -euo pipefail
  log() { echo "LOG:$*"; }
  # shellcheck disable=SC1091
  source "$1"
  marker=$(mark_cell_start_for_sweep "$2" "$3")
  mkdir -p "$3/findings/FIND-stdout-clean"
  echo "rescued" > "$3/findings/FIND-stdout-clean/report.md"
  sweep_target_tree_for_misplaced_output "$3" "$2" "$marker"
' _ "$swp_fn_src" "$swp_work/cell" "$swp_work/target3" 2>/dev/null)
assert_eq "" "$swp_capture_out" \
  "T30m: sweep diagnostics do not pollute stdout return values"
rm -f "$swp_fn_src"

# ── T31: agy_drip_stopped + agy_cli_log_for_pid predicates ─────────────
# Pure-function tests for the gemini-watchdog's drip-detection arm. We
# don't exercise the watcher loop itself (process management is the
# same shape as T29's quota watcher and would re-test bash plumbing,
# not behaviour). The predicate is the load-bearing piece.
# Functions now live in lib/gemini_watchdog.sh (sourced once above for T29).
# Re-sourcing is idempotent; keep an explicit call here so T31 stays
# runnable in isolation if a future refactor reorders test blocks.
# shellcheck disable=SC1091
. "$SCRIPT_ROOT/lib/gemini_watchdog.sh"

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
# its pid and confirm we get the path back. Linux containers use /proc;
# macOS and other POSIX hosts can fall back to lsof.
fake_log_dir="$work/antigravity-cli/log"
mkdir -p "$fake_log_dir"
fake_log="$fake_log_dir/cli-20260524_191234.log"
: > "$fake_log"
# Hold the file open in a backgrounded shell. exec 9>file binds an FD
# that lsof will see for that PID. `exec sleep` keeps holder_pid == the
# fd-holding process so the kill below reaps it (a plain `sleep` child
# would survive the kill of its parent subshell and, by inheriting this
# suite's stdout, hold the runner's pipe open for the full 30s). The
# /dev/null redirect makes even a leaked holder harmless to the pipe.
( exec 9>"$fake_log"; exec sleep 30 ) >/dev/null 2>&1 &
holder_pid=$!
# Poll until the OS has registered the FD for the pid (proc/lsof can lag
# behind the fork by a few ms; was a fixed `sleep 1`).
resolved=""
for _ in $(seq 1 40); do
  resolved=$(agy_cli_log_for_pid "$holder_pid")
  if [ -n "$resolved" ]; then break; fi
  sleep 0.05
done
# macOS lsof reports the canonicalized path (/var/folders ->
# /private/var/folders). Compare via realpath so the test is
# platform-agnostic.
resolved_real=$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$resolved" 2>/dev/null || printf '%s' "$resolved")
fake_real=$(python3 -c 'import os, sys; print(os.path.realpath(sys.argv[1]))' "$fake_log" 2>/dev/null || printf '%s' "$fake_log")
if [ "$resolved_real" = "$fake_real" ]; then
  pass "T31f: agy_cli_log_for_pid resolves the held cli-*.log via proc-or-lsof"
elif [ -d "/proc/$holder_pid/fd" ] || command -v lsof >/dev/null 2>&1; then
  fail "T31f: agy_cli_log_for_pid resolves the held cli-*.log via proc-or-lsof" "got: '$resolved_real' expected: '$fake_real'"
else
  pass "T31f: agy_cli_log_for_pid no proc/lsof path available on this host"
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

# (drip_fn cleanup retired: functions now live in lib/gemini_watchdog.sh,
# no temp file is materialized for T31.)

# ── T32: agy_in_idle_heartbeat_loop predicate ──────────────────────────
# Validates the new arm of the gemini watchdog. The function returns
# true when the klog shows the documented post-generation idle-loop
# signature: zero streamGenerateContent / :generateContent calls in
# the recent window, plus >=1 fetchAvailableModels / loadCodeAssist.
# Same fail-safe model as agy_drip_stopped — missing klog, awk
# errors, format drift all return false.
# Function now lives in lib/gemini_watchdog.sh (sourced above for T29/T31).
# shellcheck disable=SC1091
. "$SCRIPT_ROOT/lib/gemini_watchdog.sh"

# Fixtures use real "now" timestamps so the date-arithmetic in the
# function resolves correctly. Two HH:MM offsets are computed:
#   now_hhmm   — current minute (always inside any window)
#   old_hhmm   — 10 minutes ago (outside the 120s window used below)
#   old_mmdd   — the matching klog date for old_hhmm, which may be yesterday
now_hhmm=$(date +%H:%M)
old_hhmm=$(date -v-10M +%H:%M 2>/dev/null \
        || date -d '10 minutes ago' +%H:%M 2>/dev/null)
mmdd=$(date +%m%d)
old_mmdd=$(date -v-10M +%m%d 2>/dev/null \
        || date -d '10 minutes ago' +%m%d 2>/dev/null)

# Positive: broken-klog signature — old stream call (out of window),
# recent heartbeat (in window).
idle_log_yes="$work/idle-yes.log"
{
  printf 'I%s %s:42.123456 9999 http_helpers.go:182] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse Trace: 0xabc\n' "$old_mmdd" "$old_hhmm"
  printf 'I%s %s:00.123456 9999 http_helpers.go:182] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels Trace: 0xdef\n' "$mmdd" "$now_hhmm"
  printf 'I%s %s:00.234567 9999 http_helpers.go:182] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist Trace: 0x123\n' "$mmdd" "$now_hhmm"
} > "$idle_log_yes"
if agy_in_idle_heartbeat_loop "$idle_log_yes" 120; then
  pass "T32a: agy_in_idle_heartbeat_loop fires on broken-klog signature"
else
  fail "T32a: agy_in_idle_heartbeat_loop fires on broken-klog signature" "did not trigger on the documented idle-loop shape"
fi

# Negative: healthy klog — recent stream calls + recent heartbeat.
# The presence of any stream call in the window must veto the trigger.
idle_log_active="$work/idle-active.log"
{
  printf 'I%s %s:10.123456 9999 http_helpers.go:182] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse Trace: 0xabc\n' "$mmdd" "$now_hhmm"
  printf 'I%s %s:30.123456 9999 http_helpers.go:182] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels Trace: 0xdef\n' "$mmdd" "$now_hhmm"
} > "$idle_log_active"
if agy_in_idle_heartbeat_loop "$idle_log_active" 120; then
  fail "T32b: agy_in_idle_heartbeat_loop must NOT trigger when stream calls are recent" "false positive during active conversation"
else
  pass "T32b: agy_in_idle_heartbeat_loop must NOT trigger when stream calls are recent"
fi

# Negative: no recent heartbeat either — the function requires at
# least one heartbeat to confirm agy is still writing to the klog
# at all. A genuinely-dead agy (no writes of any kind) should fall
# back to the outer wall, not be picked up here.
idle_log_silent="$work/idle-silent.log"
{
  printf 'I%s %s:42.123456 9999 http_helpers.go:182] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent?alt=sse Trace: 0xabc\n' "$old_mmdd" "$old_hhmm"
} > "$idle_log_silent"
if agy_in_idle_heartbeat_loop "$idle_log_silent" 120; then
  fail "T32c: agy_in_idle_heartbeat_loop must NOT trigger without recent heartbeats" "false positive on silent klog"
else
  pass "T32c: agy_in_idle_heartbeat_loop must NOT trigger without recent heartbeats"
fi

# Negative: :generateContent (non-stream variant, lowercase g) also
# counts as activity — agy sometimes uses both URLs interchangeably.
# Without this match, a model that issues only :generateContent
# would be mis-classified as idle.
idle_log_nonstream="$work/idle-nonstream.log"
{
  printf 'I%s %s:10.123456 9999 http_helpers.go:182] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:generateContent Trace: 0xabc\n' "$mmdd" "$now_hhmm"
  printf 'I%s %s:30.123456 9999 http_helpers.go:182] URL: https://daily-cloudcode-pa.googleapis.com/v1internal:fetchAvailableModels Trace: 0xdef\n' "$mmdd" "$now_hhmm"
} > "$idle_log_nonstream"
if agy_in_idle_heartbeat_loop "$idle_log_nonstream" 120; then
  fail "T32d: agy_in_idle_heartbeat_loop must count :generateContent as activity" "treated non-stream variant as idle"
else
  pass "T32d: agy_in_idle_heartbeat_loop must count :generateContent as activity"
fi

# Fail-safe: missing log file returns false (caller skips the poll).
if agy_in_idle_heartbeat_loop "$work/no-such-idle.log" 120; then
  fail "T32e: agy_in_idle_heartbeat_loop must NOT trigger on missing log" "triggered"
else
  pass "T32e: agy_in_idle_heartbeat_loop must NOT trigger on missing log"
fi

# (idle_fn cleanup retired: functions now live in lib/gemini_watchdog.sh,
# no temp file is materialized for T32.)

summary
