#!/usr/bin/env bash
# tests/test_report_gate_bounds.sh — _triage_read_report_bounded contract.
#
# The find_quality and crash_confirm gates read the report/description
# through this helper instead of a fixed `head -c`. The contract that
# keeps the gate false-negative-safe:
#   1. A report at or under REPORT_GATE_MAX_BYTES is sent WHOLE — every
#      section reaches the LLM, never a headless prefix.
#   2. An oversize report is sliced head+tail (not blindly truncated) so the
#      opening structure AND the closing Impact/Reproduction survive.
#   3. The overflow notice goes to STDERR, never stdout — callers capture
#      this helper's stdout as the verdict body, so a log line there would
#      corrupt it.
#   4. REPORT_GATE_MAX_BYTES is an honoured operator knob.
#   5. Missing/empty input is rc=1, not a half-formed body.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

# shellcheck disable=SC1090
source "$SCRIPT_ROOT/lib/triage.sh"

WORK="$TEST_TMPDIR/report-gate-bounds"
mkdir -p "$WORK"

# ── 1. Small report (<= cap) is returned verbatim ───────────────────────
small="$WORK/small.md"
{
  printf 'HEAD_MARKER_TOKEN\n'
  printf 'middle body line\n'
  printf 'TAIL_MARKER_TOKEN\n'
} > "$small"
out=$(_triage_read_report_bounded "$small")
assert_match 'HEAD_MARKER_TOKEN' "$out" "small: head present"
assert_match 'TAIL_MARKER_TOKEN' "$out" "small: tail present"
assert_match 'middle body line' "$out" "small: middle present"
assert_not_match 'elided by REPORT_GATE_MAX_BYTES' "$out" "small: no elision marker"

# ── 2. Oversize report (> default 256 KB cap) keeps head AND tail ────────
# ~357 KB: marker at byte 0, a MID marker parked in the elided middle, and a
# marker at the very end. cap=256K → head 192K + tail 64K, so MID (~255K) lands
# in the elided window while HEAD and TAIL survive.
big="$WORK/big.md"
{
  printf 'HEAD_MARKER_TOKEN\n'
  head -c 255000 /dev/zero | tr '\0' 'x'
  printf '\nMID_MARKER_TOKEN\n'
  head -c 102000 /dev/zero | tr '\0' 'y'
  printf '\nTAIL_MARKER_TOKEN\n'
} > "$big"
out=$(_triage_read_report_bounded "$big" 2>/dev/null)
assert_match 'HEAD_MARKER_TOKEN' "$out" "oversize: head section kept"
assert_match 'TAIL_MARKER_TOKEN' "$out" "oversize: tail section kept"
assert_match 'elided by REPORT_GATE_MAX_BYTES' "$out" "oversize: elision marker present"
assert_not_match 'MID_MARKER_TOKEN' "$out" "oversize: elided middle dropped"

# ── 3. Overflow notice is on stderr, never stdout ───────────────────────
err=$(_triage_read_report_bounded "$big" 2>&1 >/dev/null)
assert_match 'POSSIBLE-FALSE-NEGATIVE' "$err" "oversize: warns on stderr"
assert_not_match 'POSSIBLE-FALSE-NEGATIVE' "$out" "oversize: stdout body stays clean"

# ── 4. REPORT_GATE_MAX_BYTES is honoured ────────────────────────────────
medium="$WORK/medium.md"
{
  printf 'CAP_HEAD_TOKEN\n'
  head -c 3000 /dev/zero | tr '\0' 'z'
  printf '\nCAP_MID_TOKEN\n'
  head -c 3000 /dev/zero | tr '\0' 'w'
  printf '\nCAP_TAIL_TOKEN\n'
} > "$medium"
# Whole file (~6 KB) fits under the default cap → returned verbatim.
out=$(REPORT_GATE_MAX_BYTES=262144 _triage_read_report_bounded "$medium")
assert_match 'CAP_MID_TOKEN' "$out" "knob: default cap sends whole medium report"
# A tiny cap forces the same file through the overflow path.
out=$(REPORT_GATE_MAX_BYTES=1000 _triage_read_report_bounded "$medium" 2>/dev/null)
assert_match 'CAP_HEAD_TOKEN' "$out" "knob: lowered cap keeps head"
assert_match 'CAP_TAIL_TOKEN' "$out" "knob: lowered cap keeps tail"
assert_match 'elided by REPORT_GATE_MAX_BYTES' "$out" "knob: lowered cap triggers overflow"

# ── 5. Missing / empty input is rc=1 ────────────────────────────────────
rc=0; _triage_read_report_bounded "$WORK/does-not-exist.md" >/dev/null 2>&1 || rc=$?
assert_eq 1 "$rc" "missing file → rc=1"
: > "$WORK/empty.md"
rc=0; _triage_read_report_bounded "$WORK/empty.md" >/dev/null 2>&1 || rc=$?
assert_eq 1 "$rc" "empty file → rc=1"

summary
