#!/usr/bin/env bash
# Tests for lib/output_cap.sh — the replacement-style head+tail cap helper.
#
# Coverage:
#   - Passthrough verbatim when input ≤ OUTCAP_MAX_BYTES.
#   - Replacement (head + marker + tail) when input > OUTCAP_MAX_BYTES.
#   - On-disk spill path is created and contains the full original.
#   - ASan-style crash headers are preserved in the head portion.
#   - Repeated runs of the same input produce the same spill filename
#     (content-addressed via sha1) so reruns don't accumulate.
#   - OUTCAP_MAX_BYTES=0 disables capping entirely.
#   - Invalid env values fail loudly rather than silently dropping output.
#   - cap_output_stdin pipeline form mirrors cap_output_file semantics.

set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

OUTCAP="$SCRIPT_ROOT/lib/output_cap.sh"

bash -n "$OUTCAP" 2>/dev/null
assert_eq 0 $? "output_cap.sh: syntax check passes"

# Run each assertion in a subshell so env-var resets are scoped.
_subshell_eval() {
  bash -c "
    set -u
    source '$OUTCAP'
    $1
  "
}

# ── Fixtures ──────────────────────────────────────────────────────
SMALL="$TEST_TMPDIR/small.txt"
seq 1 50 | sed 's/^/line /' > "$SMALL"
small_bytes=$(wc -c < "$SMALL" | tr -d ' ')

# Big fixture: ~120 KB of distinguishable lines. Each line has a unique
# index so head/tail content can be asserted without false positives.
BIG="$TEST_TMPDIR/big.txt"
for i in $(seq 1 15000); do printf 'fixture-line-%05d-aaaaaaaaaaaa\n' "$i"; done > "$BIG"
big_bytes=$(wc -c < "$BIG" | tr -d ' ')
assert_eq 1 "$([ "$big_bytes" -gt 60000 ] && echo 1 || echo 0)" \
  "fixture: big.txt is over the default cap (got $big_bytes bytes)"

SPILL_DIR="$TEST_TMPDIR/spill"
mkdir -p "$SPILL_DIR"

# ── Passthrough below cap ─────────────────────────────────────────
output=$(_subshell_eval "OUTCAP_SPILL_DIR='$SPILL_DIR' cap_output_file '$SMALL' test")
out_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
# Allow a 1-byte tolerance for trailing-newline accounting between the
# fixture writer and the cat passthrough.
diff_bytes=$(( small_bytes - out_bytes ))
[ "$diff_bytes" -lt 0 ] && diff_bytes=$(( -diff_bytes ))
[ "$diff_bytes" -le 1 ]
assert_eq 0 $? "passthrough: small input emitted byte-for-byte (got $out_bytes / $small_bytes)"
assert_not_match 'output_cap:' "$output" "passthrough: no truncation marker on small input"
# Spill must NOT exist when passthrough fires — no point writing a copy of
# something the agent already saw verbatim.
spill_count=$(find "$SPILL_DIR" -name 'outcap-*' | wc -l | tr -d ' ')
assert_eq 0 "$spill_count" "passthrough: no spill file written for small input"

# ── Replacement above cap ─────────────────────────────────────────
output=$(_subshell_eval "OUTCAP_SPILL_DIR='$SPILL_DIR' cap_output_file '$BIG' test-big")
assert_match 'output_cap: test-big truncated' "$output" "replacement: marker emitted"
assert_match 'head .* tail' "$output" "replacement: marker labels head/tail counts"
assert_match 'Full output:' "$output" "replacement: marker points at spill path"
assert_match 'bin/peek .*:1-200' "$output" "replacement: marker recommends bounded reread"
assert_not_match 'Re-read with `cat' "$output" "replacement: marker does not recommend catting the spill"
assert_match 'fixture-line-00001-' "$output" "replacement: head contains first lines"
assert_match 'fixture-line-15000-' "$output" "replacement: tail contains last lines"
# A middle line (somewhere around line 7500) MUST be elided. If it shows up,
# the cap is too generous and we're not actually truncating.
assert_not_match 'fixture-line-07500-' "$output" "replacement: middle lines elided"

# Total emitted bytes should be ≤ OUTCAP_MAX_BYTES + marker overhead.
out_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
# Default cap is 51200; allow up to 2 KB of marker / line-alignment slack.
[ "$out_bytes" -lt 53500 ]
assert_eq 0 $? "replacement: total bytes ($out_bytes) within cap + marker overhead"

# ── Spill file exists and matches the original ────────────────────
spill_count=$(find "$SPILL_DIR" -name 'outcap-test-big-*' | wc -l | tr -d ' ')
assert_eq 1 "$spill_count" "spill: one spill file written for big input"
spill_path=$(find "$SPILL_DIR" -name 'outcap-test-big-*' | head -1)
spill_bytes=$(wc -c < "$spill_path" | tr -d ' ')
assert_eq "$big_bytes" "$spill_bytes" "spill: full original preserved on disk"

# ── Content-addressed: rerun yields the same spill filename ───────
# Determinism is load-bearing — when an agent re-runs the same command,
# the spill path it sees in the marker should still be valid.
output2=$(_subshell_eval "OUTCAP_SPILL_DIR='$SPILL_DIR' cap_output_file '$BIG' test-big")
spill_count_after=$(find "$SPILL_DIR" -name 'outcap-test-big-*' | wc -l | tr -d ' ')
assert_eq 1 "$spill_count_after" "spill: rerun reuses the same filename"

# ── ASan-style header preservation ───────────────────────────────
# Synthesize a stack-overflow-like trace that's well over the cap. The
# critical signals — ERROR header, first frames, SUMMARY, ABORTING — must
# all survive head+tail truncation.
ASAN="$TEST_TMPDIR/asan-stack.txt"
{
  echo "==12345==ERROR: AddressSanitizer: stack-overflow on address 0x7fffXXXX"
  for i in $(seq 0 10000); do
    printf '    #%d 0x100%06x in recursive_fn(int) /target/recur.cc:42\n' "$i" "$i"
  done
  echo "SUMMARY: AddressSanitizer: stack-overflow (libxml2+0xdeadbeef)"
  echo "==12345==ABORTING"
} > "$ASAN"
asan_bytes=$(wc -c < "$ASAN" | tr -d ' ')
[ "$asan_bytes" -gt 100000 ]
assert_eq 0 $? "asan fixture: over 100 KB (got $asan_bytes)"

output=$(_subshell_eval "OUTCAP_SPILL_DIR='$SPILL_DIR' cap_output_file '$ASAN' asan-crash")
assert_match 'ERROR: AddressSanitizer: stack-overflow' "$output" \
  "asan: ERROR header preserved in head"
assert_match '#0 0x100000000 in recursive_fn' "$output" \
  "asan: first stack frame preserved in head"
assert_match 'SUMMARY: AddressSanitizer: stack-overflow' "$output" \
  "asan: SUMMARY line preserved in tail"
assert_match '==12345==ABORTING' "$output" \
  "asan: ABORTING line preserved in tail"
# A mid-range frame should be elided.
assert_not_match '#5000 0x100001388 in recursive_fn' "$output" \
  "asan: mid-range frames elided"

# ── OUTCAP_MAX_BYTES=0 disables capping entirely ──────────────────
output=$(_subshell_eval "OUTCAP_MAX_BYTES=0 OUTCAP_SPILL_DIR='$SPILL_DIR' cap_output_file '$BIG' nocap")
assert_not_match 'output_cap:' "$output" "disable: no marker when OUTCAP_MAX_BYTES=0"
assert_match 'fixture-line-07500-' "$output" \
  "disable: middle lines present when cap disabled"
out_bytes=$(printf '%s' "$output" | wc -c | tr -d ' ')
diff_bytes=$(( big_bytes - out_bytes ))
[ "$diff_bytes" -lt 0 ] && diff_bytes=$(( -diff_bytes ))
[ "$diff_bytes" -le 1 ]
assert_eq 0 $? "disable: full input emitted (got $out_bytes / $big_bytes)"
nocap_spill=$(find "$SPILL_DIR" -name 'outcap-nocap-*' | wc -l | tr -d ' ')
assert_eq 0 "$nocap_spill" "disable: no spill when cap is off"

# ── Invalid env values fail loudly ────────────────────────────────
# Bad env values should return non-zero rather than emit empty output
# (the worst possible silent failure mode for an agent).
output=$(_subshell_eval "OUTCAP_MAX_BYTES=not-a-number cap_output_file '$SMALL' bad" 2>&1)
rc=$?
[ "$rc" -ne 0 ]
assert_eq 0 $? "validation: bad OUTCAP_MAX_BYTES returns non-zero (got rc=$rc)"
assert_match 'OUTCAP_MAX_BYTES must be' "$output" \
  "validation: error message names the offending env var"

# ── Stdin pipeline form ───────────────────────────────────────────
output=$(cat "$BIG" | _subshell_eval "OUTCAP_SPILL_DIR='$SPILL_DIR' cap_output_stdin pipe-test")
assert_match 'output_cap: pipe-test truncated' "$output" \
  "stdin form: marker emitted for big input"
assert_match 'fixture-line-00001-' "$output" "stdin form: head preserved"
assert_match 'fixture-line-15000-' "$output" "stdin form: tail preserved"

# ── Missing input file is silent ──────────────────────────────────
# Tools that conditionally route through cap_output_file shouldn't blow up
# when the file isn't there (callers already report "not found" themselves).
output=$(_subshell_eval "cap_output_file /nonexistent/path missing")
rc=$?
assert_eq 0 "$rc" "missing input: returns 0"
assert_eq "" "$output" "missing input: emits no output"

# ── Line-alignment: no partial leading/trailing lines ─────────────
# After truncation, the head ends with a newline (no half-line at the cut)
# and the tail begins after a newline (no half-line at the join).
output=$(_subshell_eval "OUTCAP_SPILL_DIR='$SPILL_DIR' cap_output_file '$BIG' align")
# Pull the bytes immediately before the marker. The marker starts with
# `\n[output_cap:` so the byte at marker_start-1 must be `\n`.
head_block=$(printf '%s' "$output" | awk '/\[output_cap:/{exit} {print}')
last_char=$(printf '%s' "$head_block" | tail -c 1)
# `tail -c 1` of an empty string is empty, which would mean no head — fail.
[ -n "$last_char" ]
assert_eq 0 $? "alignment: head has at least one line"
# Specifically: the last data line in the head must look like a full
# fixture line (matches the expected suffix), not a truncation.
last_head_line=$(printf '%s' "$head_block" | grep '^fixture-line-' | tail -1)
assert_match 'aaaaaaaaaaaa$' "$last_head_line" \
  "alignment: head's last line is complete (got: $last_head_line)"
# And the first line of the tail (line after the marker) is also complete.
tail_block=$(printf '%s' "$output" | awk '/\[output_cap:/{seen=1; next} seen{print}')
first_tail_line=$(printf '%s' "$tail_block" | grep '^fixture-line-' | head -1)
assert_match 'aaaaaaaaaaaa$' "$first_tail_line" \
  "alignment: tail's first line is complete (got: $first_tail_line)"

teardown_test_env
summary
