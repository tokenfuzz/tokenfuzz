#!/usr/bin/env bash
# tests/test_export_benchmark.sh — bin/export-benchmark packages benchmark
# results into a self-contained, shareable bundle.
#
# Coverage (against a synthetic bench-root, no LLM, no real run):
#   1. No flags selects every backend/run; the archive root holds the
#      cross-backend benchmark-result.{md,html} entry page.
#   2. --backend confines to one backend subtree.
#   3. --target confines to runs whose run.json target matches (across
#      backends), reading the recorded slug — not the directory name.
#   4. --run-id requires --backend (run ids are not unique across backends).
#   5. cells/, recon-cache/, and per-crash .audit/ are excluded.
#   6. Compiled executables are dropped; the testcase input (the crash trigger,
#      binary or not) is kept.
#   7. Local /Users... paths are scrubbed from every shipped text file.
#   8. The crosstab is scoped to the staged runs (a filtered-out run does
#      not appear), and its links resolve inside the bundle.
#   9. An empty selection exits non-zero.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

EXPORT="$SCRIPT_ROOT/bin/export-benchmark"
[ -x "$EXPORT" ] || { echo "missing $EXPORT"; exit 1; }

# ── Fixture: a synthetic bench-root with two backends ──────────────────────
# codex has one sampleproj run; gemini has one sampleproj run + one apptool
# run. Each run carries a report.json (the only thing crosstab/ledger read), a
# pool/ with one rendered cluster report, plus the heavy/internal trees and a
# planted binary + /Users leak the exporter must strip.
ROOT="$TEST_TMPDIR/bench"

make_run() {  # <backend> <runid> <target>
  local be="$1" runid="$2" tgt="$3"
  local d="$ROOT/$be/$runid"
  mkdir -p "$d/pool/codeqcrashes" "$d/cells/harness-r1" \
           "$d/recon-cache" "$d/pool/crashes/CRASH-0001/.audit"
  cat > "$d/run.json" <<EOF
{"runid":"$runid","target":"$tgt","backend":"$be","conditions":["harness"]}
EOF
  cat > "$d/report.json" <<EOF
{"bench_dir":"/Users/someone/src/tokenfuzz/output/benchmark/$be/$runid",
 "run":{"runid":"$runid","target":"$tgt","backend":"$be"},
 "conditions":[]}
EOF
  # A pooled text report carrying the local workspace prefix — the same shape
  # an agent leaks in a real run, and the prefix the harness scrubber strips.
  cat > "$d/pool/crashes/CRASH-0001/report.md" <<EOF
# CRASH-0001
Testcase at $SCRIPT_ROOT/output/benchmark/$be/$runid/x.tc
EOF
  printf 'sanitizer output\n' > "$d/pool/crashes/CRASH-0001/asan.txt"
  # .audit/ internal state (excluded); a compiled executable (binary + exec bit
  # => dropped, it embeds an unscrubbable build path); and a binary testcase
  # INPUT (binary, no exec bit => kept, it is the crash trigger).
  printf 'internal audit log %s/secret\n' "$SCRIPT_ROOT" \
    > "$d/pool/crashes/CRASH-0001/.audit/promotion.log"
  printf '\x7fELF\x00\x00compiled exe build path %s\x00' "$SCRIPT_ROOT" \
    > "$d/pool/crashes/CRASH-0001/testcase_bin"
  chmod +x "$d/pool/crashes/CRASH-0001/testcase_bin"
  printf 'crash\x00input\x00bytes\x00' > "$d/pool/crashes/CRASH-0001/input.bin"
  printf 'cell internal %s/cell\n' "$SCRIPT_ROOT" > "$d/cells/harness-r1/log"
}

make_run codex  20260101-000000 sampleproj
make_run gemini 20260101-000001 sampleproj
make_run gemini 20260102-000000 apptool

run_export() { python3 "$EXPORT" --bench-root "$ROOT" --format dir "$@"; }

# ── 1. No flags: all runs, entry page at archive root ──────────────────────
OUT="$TEST_TMPDIR/all"
run_export --out "$OUT" >/dev/null 2>&1
assert_file_exists "$OUT/benchmark-result.html" "no-flag export: entry html"
assert_file_exists "$OUT/benchmark-result.md"   "no-flag export: entry md"
assert_dir_exists  "$OUT/codex"                 "no-flag export: codex included"
assert_dir_exists  "$OUT/gemini"                "no-flag export: gemini included"

# ── 5. Heavy/internal trees excluded ───────────────────────────────────────
assert_dir_not_exists "$OUT/codex/20260101-000000/cells" "cells/ excluded"
assert_dir_not_exists "$OUT/codex/20260101-000000/recon-cache" "recon-cache/ excluded"
assert_dir_not_exists "$OUT/codex/20260101-000000/pool/crashes/CRASH-0001/.audit" \
  ".audit/ excluded"

# ── 6. Executable dropped; report + testcase input kept ─────────────────────
CRASH="$OUT/codex/20260101-000000/pool/crashes/CRASH-0001"
assert_file_exists     "$CRASH/report.md"    "crash text report present"
assert_file_not_exists "$CRASH/testcase_bin" "compiled executable dropped"
assert_file_exists     "$CRASH/input.bin"    "binary testcase input kept (crash trigger)"

# ── 7. No local workspace-path leak in any shipped text file ───────────────
if grep -rlaF "$SCRIPT_ROOT" "$OUT" 2>/dev/null | grep -q .; then
  fail "no workspace-path leak" "found: $(grep -rlaF "$SCRIPT_ROOT" "$OUT" | head -1)"
else
  pass "no workspace-path leak in shipped bundle"
fi

# ── 2. --backend confines ──────────────────────────────────────────────────
OUTB="$TEST_TMPDIR/codex-only"
run_export --backend codex --out "$OUTB" >/dev/null 2>&1
assert_dir_exists     "$OUTB/codex"  "--backend codex: codex present"
assert_dir_not_exists "$OUTB/gemini" "--backend codex: gemini absent"

# ── 3. --target confines across backends (reads run.json slug) ─────────────
OUTT="$TEST_TMPDIR/sampleproj-only"
run_export --target sampleproj --out "$OUTT" >/dev/null 2>&1
assert_dir_exists     "$OUTT/codex/20260101-000000"  "--target: codex sampleproj kept"
assert_dir_exists     "$OUTT/gemini/20260101-000001" "--target: gemini sampleproj kept"
assert_dir_not_exists "$OUTT/gemini/20260102-000000" "--target: apptool run dropped"

# ── 8. Scoped crosstab + link integrity on the filtered bundle ─────────────
assert_file_not_contains "$OUTT/benchmark-result.md" "apptool" \
  "--target crosstab excludes filtered-out target"
python3 - "$OUTT" <<'PY' && pass "filtered bundle links resolve" \
  || fail "filtered bundle links resolve" "see broken list above"
import re,sys,pathlib,urllib.parse
root=pathlib.Path(sys.argv[1]); html=root/"benchmark-result.html"
bad=[]
for h in re.findall(r'href="([^"]+)"', html.read_text()):
    if h.startswith(('#','http','mailto')): continue
    if not (html.parent/urllib.parse.unquote(h.split('#')[0])).exists(): bad.append(h)
if bad: print("BROKEN:",bad); sys.exit(1)
PY

# ── 4 + 9. Error paths ─────────────────────────────────────────────────────
python3 "$EXPORT" --bench-root "$ROOT" --run-id 20260101-000000 \
  --format dir --out "$TEST_TMPDIR/err1" >/dev/null 2>&1
assert_neq "0" "$?" "--run-id without --backend is rejected"

python3 "$EXPORT" --bench-root "$ROOT" --target nope \
  --format dir --out "$TEST_TMPDIR/err2" >/dev/null 2>&1
assert_neq "0" "$?" "empty selection exits non-zero"

summary
