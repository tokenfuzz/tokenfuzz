#!/usr/bin/env bash
# Unit tests for bin/scratch-search — path-first output, sidecar exclusion, caps
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

SS="$SCRIPT_ROOT/bin/scratch-search"

# ── Fixtures ─────────────────────────────────────────────────────────
S1="$RESULTS_DIR/scratch-1"
S2="$RESULTS_DIR/scratch-2"
CORPUS="$RESULTS_DIR/corpus"
CRASHES="$RESULTS_DIR/crashes/CRASH-001-1"
FINDINGS="$RESULTS_DIR/findings/FIND-002-1"
mkdir -p "$S1" "$S2" "$CORPUS" "$CRASHES" "$FINDINGS"

# Plant the pattern "ALTSVC_NEEDLE" in scratch-1 (twice in one file, once in
# another) and in corpus (once). scratch-2 has no matches. crashes has it in
# a report. findings has nothing.
cat > "$S1/altsvc_harness.c" <<'EOF'
// Two references to ALTSVC_NEEDLE inside the same file.
int main(void) {
  /* ALTSVC_NEEDLE entry point */
  if (0) { /* second ALTSVC_NEEDLE for the search */ }
  return 0;
}
EOF
echo 'ALTSVC_NEEDLE seen here too' > "$S1/altsvc_notes.md"
echo 'no match here' > "$S2/aws_sigv4_harness.c"
echo 'ALTSVC_NEEDLE in promoted corpus' > "$CORPUS/altsvc-input-1.txt"
echo '## Summary  ALTSVC_NEEDLE in this crash report' > "$CRASHES/report.md"

# Sidecars that MUST be excluded by default — same needle, different file shape.
echo 'ALTSVC_NEEDLE in asan sidecar' > "$S1/altsvc_harness.asan.txt"
echo 'ALTSVC_NEEDLE in build log'    > "$S1/build.log"
mkdir -p "$S1/.harness-cache"
echo 'ALTSVC_NEEDLE in harness cache compile binary' > "$S1/.harness-cache/cache_marker"
echo 'ALTSVC_NEEDLE inside cache dir' > "$S1/.harness-cache/foo.c"

# ── 1. Help and basic invocation ─────────────────────────────────────
output=$(bash "$SS" --help 2>&1)
assert_match "scratch-search" "$output" "help: shows usage"

# Missing PATTERN should exit 2 with usage hint.
output=$(bash "$SS" 2>&1) ; rc=$?
assert_eq 2 "$rc" "missing pattern: exit code 2"
assert_match "PATTERN is required" "$output" "missing pattern: error message"

# Missing RESULTS_DIR should exit 2.
output=$(RESULTS_DIR="" bash "$SS" foo 2>&1) ; rc=$?
assert_eq 2 "$rc" "missing RESULTS_DIR: exit code 2"

# ── 2. Per-section labeling and counts ───────────────────────────────
if command -v rg >/dev/null 2>&1; then
  output=$(RESULTS_DIR="$RESULTS_DIR" bash "$SS" ALTSVC_NEEDLE 2>&1)
  assert_match '\[scratch-1\] 2 files' "$output" "scratch-1: default count is 2 matching files"
  assert_match '\[scratch-2\] no matches' "$output" "scratch-2: no-match label present"
  assert_match '\[corpus\] 1 file' "$output" "corpus: 1 matching file"
  assert_match '\[crashes\] 1 file' "$output" "crashes: 1 matching file"
  assert_match '\[findings\] no matches' "$output" "findings: no-match label present"
  assert_match 'paths only\. Re-run with --lines --section scratch-1 for match bodies' "$output" "default: footer explains --lines drilldown"
  if grep -q '/\* ALTSVC_NEEDLE' <<<"$output"; then
    fail "default: match body leaked"
  else
    pass "default: match body omitted"
  fi

  # ── 3. Sidecars MUST NOT appear by default ─────────────────────────
  if grep -q 'asan.txt' <<<"$output"; then
    fail "default: .asan.txt sidecar leaked into output"
  else
    pass "default: .asan.txt excluded"
  fi
  if grep -q 'build.log' <<<"$output"; then
    fail "default: build.log leaked into output"
  else
    pass "default: build.log excluded"
  fi
  if grep -q 'harness-cache' <<<"$output"; then
    fail "default: .harness-cache leaked into output"
  else
    pass "default: .harness-cache excluded"
  fi

  # ── 4. Output paths are RESULTS_DIR-relative ───────────────────────
  if grep -q "$RESULTS_DIR/scratch-1" <<<"$output"; then
    fail "paths: full RESULTS_DIR prefix should be stripped"
  else
    pass "paths: RESULTS_DIR prefix stripped"
  fi
  assert_match "scratch-1/altsvc_harness.c" "$output" "paths: relative path emitted"

  # ── 5. --section filter restricts output ───────────────────────────
  output_filt=$(RESULTS_DIR="$RESULTS_DIR" bash "$SS" --section scratch-1 ALTSVC_NEEDLE 2>&1)
  assert_match '\[scratch-1\]' "$output_filt" "section filter: scratch-1 present"
  if grep -q 'corpus' <<<"$output_filt"; then
    fail "section filter: corpus should not be searched"
  else
    pass "section filter: corpus omitted"
  fi

  # ── 6. --include-asan opts the sidecar back in ─────────────────────
  output_asan=$(RESULTS_DIR="$RESULTS_DIR" bash "$SS" --include-asan ALTSVC_NEEDLE 2>&1)
  assert_match 'asan.txt' "$output_asan" "--include-asan: sidecar appears"

  # ── 7. --files-only preserves the default path-only mode ───────────
  output_fo=$(RESULTS_DIR="$RESULTS_DIR" bash "$SS" --files-only ALTSVC_NEEDLE 2>&1)
  assert_match '\[scratch-1\] 2 files' "$output_fo" "--files-only: scratch-1 file count"
  # The match-line context body should NOT appear in files-only mode.
  if grep -q '/\*' <<<"$output_fo"; then
    fail "--files-only: match body leaked"
  else
    pass "--files-only: match body omitted"
  fi

  # ── 7b. --lines preserves the old file:line:body behavior ─────────
  output_lines=$(RESULTS_DIR="$RESULTS_DIR" bash "$SS" --lines ALTSVC_NEEDLE 2>&1)
  assert_match '\[scratch-1\] 4 matches in 2 files' "$output_lines" "--lines: old match count shown"
  assert_match 'scratch-1/altsvc_harness.c:[0-9]+:  /\* ALTSVC_NEEDLE entry point \*/' "$output_lines" "--lines: match body shown"
  assert_match '\[corpus\] 1 match in 1 file' "$output_lines" "--lines: singular match grammar"

  # ── 8. Pattern with no hits anywhere → exit 1 ──────────────────────
  output_miss=$(RESULTS_DIR="$RESULTS_DIR" bash "$SS" ZZZ_NEVER_THERE_ZZZ 2>&1) ; rc=$?
  assert_eq 1 "$rc" "no matches anywhere: exit 1"
  assert_match '\[scratch-1\] no matches' "$output_miss" "no matches: per-section label still printed"

  # ── 9. Output size remains compact ─────────────────────────────────
  size=$(printf '%s' "$output" | wc -c | tr -d ' ')
  if [ "$size" -lt 3072 ]; then
    pass "default output under 3 KB (was $size B)"
  else
    fail "default output bloated: $size B"
  fi

  # ── 10. Cap fires when section has many matches ────────────────────
  # Plant 50 matches in one file, set cap to 5.
  big="$S1/big_match.c"
  for i in $(seq 1 50); do echo "line $i ALTSVC_NEEDLE" >> "$big"; done
  output_cap=$(RESULTS_DIR="$RESULTS_DIR" bash "$SS" --lines --cap 5 ALTSVC_NEEDLE 2>&1)
  assert_match '\[scratch-1\] 54 matches' "$output_cap" "cap: total still shown in header"
  assert_match 'more matches in this section' "$output_cap" "cap: footer present when clipped"
else
  pass "rg not available — skipping scratch-search tests"
fi

teardown_test_env
summary
