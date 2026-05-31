#!/usr/bin/env bash
# tests/test_llm_usage.sh — Unit tests for lib/llm_usage.py extract-field.
#
# Background: bin/audit's extract_usage_field used to be an inline jq
# pipeline that returned EMPTY for any agy plain-text transcript,
# silently pinning agy sessions to tokens=0 and tripping the
# dead-streak false-positive on every productive source-only audit.
# It now delegates to lib/llm_usage.py — the same helper bin/benchmark
# uses — so the plain-text estimator is shared, not duplicated.
#
# The legacy `<backend> <raw>` invocation that bin/benchmark uses for
# extract-usage is covered by tests/test_benchmark.sh (T16-series + the
# explicit backward-compat path). This file covers extract-field
# specifically: the per-field CLI shape audit consumes.

set -uo pipefail
TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_ROOT="$(cd "$TESTS_DIR/.." && pwd)"
# shellcheck disable=SC1091
source "$TESTS_DIR/helpers.sh"
setup_test_env

USAGE_PY="$SCRIPT_ROOT/lib/llm_usage.py"
work=$(mktemp -d)
trap 'rm -rf "$work" 2>/dev/null || true; teardown_test_env 2>/dev/null || true' EXIT

# Tiny wrapper: extract-field <field> <backend> <raw> [--prompt path].
xf() {
  python3 "$USAGE_PY" extract-field "$@"
}

# ── Fixtures ────────────────────────────────────────────────────────

# Claude stream-json: each assistant message carries a usage object
# (running total). The MAX wins — last message ends up authoritative.
claude_raw="$work/claude.raw"
cat > "$claude_raw" <<'EOF'
{"type":"assistant","message":{"content":[{"type":"text","text":"hi"}]},"usage":{"input_tokens":500,"cache_read_input_tokens":300,"cache_creation_input_tokens":100,"output_tokens":25,"duration_ms":1200}}
{"type":"assistant","message":{"content":[{"type":"text","text":"more"}]},"usage":{"input_tokens":1500,"cache_read_input_tokens":1000,"cache_creation_input_tokens":100,"output_tokens":80,"duration_ms":3400}}
{"type":"result","duration_ms":3400}
EOF

# Codex item.completed: single summary event with usage.
codex_raw="$work/codex.raw"
cat > "$codex_raw" <<'EOF'
{"type":"item.completed","item":{"type":"command_execution"},"usage":{"input_tokens":900,"output_tokens":42}}
EOF

# Gemini-cli stream-json with result.stats final cumulative.
gemini_cli_raw="$work/gemini_cli.raw"
cat > "$gemini_cli_raw" <<'EOF'
{"type":"message","role":"assistant","content":"hi"}
{"type":"result","stats":{"input_tokens":2000,"output_tokens":150,"cached":800}}
EOF

# agy --print plain text (no JSON events at all).
agy_raw="$work/agy.raw"
cat > "$agy_raw" <<'EOF'
I'll start by inspecting the parser. Read main.c lines 1-120. The
function parse_input reads up to 4096 bytes into a fixed buffer. I
filed FIND-001 documenting an unchecked memcpy. End of session.
EOF

# An empty file (any backend): truly no telemetry.
empty_raw="$work/empty.raw"
: > "$empty_raw"

# A non-existent file: should never crash, return "".
ghost_raw="$work/does-not-exist.raw"

# A prompt file for the agy input-side estimate.
prompt_file="$work/prompt.md"
printf 'Pretend this is the rendered prompt — 64 chars roughly here.\n' > "$prompt_file"

# ── T1: Claude stream-json measured fields ──────────────────────────

assert_eq "1500" "$(xf input_tokens claude "$claude_raw")" \
  "T1a: claude input_tokens picks the running-max usage block"
assert_eq "80"   "$(xf output_tokens claude "$claude_raw")" \
  "T1b: claude output_tokens picks the running-max usage block"
assert_eq "1000" "$(xf cached_input_tokens claude "$claude_raw")" \
  "T1c: claude cached_input_tokens maps cache_read_input_tokens"
assert_eq "100"  "$(xf cache_creation_input_tokens claude "$claude_raw")" \
  "T1d: claude cache_creation_input_tokens maps the cache-write counter"
assert_eq "1580" "$(xf total_tokens claude "$claude_raw")" \
  "T1e: claude total_tokens sums input + output from the picked block"
assert_eq "3400" "$(xf duration_ms claude "$claude_raw")" \
  "T1f: claude duration_ms scans top-level event objects"

# ── T2: Codex item.completed measured fields ────────────────────────

assert_eq "900" "$(xf input_tokens codex "$codex_raw")" \
  "T2a: codex input_tokens read from the item.completed usage block"
assert_eq "42"  "$(xf output_tokens codex "$codex_raw")" \
  "T2b: codex output_tokens read from the item.completed usage block"
# codex has no cache_read counter; the field is absent from the input.
# Reporting "" (unknown) is more honest than "0" — audit's downstream
# uses ${var:-0} to floor for arithmetic.
assert_eq "0" "$(xf cached_input_tokens codex "$codex_raw")" \
  "T2c: codex cached_input_tokens is 0 (no cache-read counter on this backend)"

# ── T3: gemini-cli stream-json result.stats ─────────────────────────

assert_eq "2000" "$(xf input_tokens gemini "$gemini_cli_raw")" \
  "T3a: gemini-cli input_tokens read from result.stats"
assert_eq "150"  "$(xf output_tokens gemini "$gemini_cli_raw")" \
  "T3b: gemini-cli output_tokens read from result.stats"
assert_eq "800"  "$(xf cached_input_tokens gemini "$gemini_cli_raw")" \
  "T3c: gemini-cli cached_input_tokens reads the 'cached' alias"

# ── T4: agy plain-text estimator (the P0 fix) ────────────────────────

# No prompt: input stays 0, output estimated from raw bytes.
out_no_prompt=$(xf output_tokens gemini "$agy_raw")
if [ -z "$out_no_prompt" ] || [ "$out_no_prompt" -le 0 ] 2>/dev/null; then
  fail "T4a: agy plain-text output_tokens estimates > 0 (was 0/empty before the fix)" \
    "got '$out_no_prompt'"
else
  pass "T4a: agy plain-text output_tokens estimates > 0 (was 0/empty before the fix)"
fi
assert_eq "0" "$(xf input_tokens gemini "$agy_raw")" \
  "T4b: agy plain-text input_tokens stays 0 when no prompt is supplied"

# With a prompt: input is also estimated.
in_with_prompt=$(xf input_tokens gemini "$agy_raw" --prompt "$prompt_file")
if [ -z "$in_with_prompt" ] || [ "$in_with_prompt" -le 0 ] 2>/dev/null; then
  fail "T4c: agy plain-text input_tokens estimates > 0 when --prompt supplied" \
    "got '$in_with_prompt'"
else
  pass "T4c: agy plain-text input_tokens estimates > 0 when --prompt supplied"
fi

# ── T5: unknown-telemetry → empty string (preserves audit's
#         `extract_usage_field` "I don't know" semantic) ──────────────

# Empty file, non-gemini backend: nothing measured, no estimator path.
assert_eq "" "$(xf input_tokens claude "$empty_raw")" \
  "T5a: empty raw + claude backend → '' (unknown), not '0'"
assert_eq "" "$(xf output_tokens codex "$empty_raw")" \
  "T5b: empty raw + codex backend → '' (unknown), not '0'"

# Empty file, gemini backend: estimator runs but assistant_chars is 0,
# so the answer IS 0 (the agent really did produce no output).
assert_eq "0" "$(xf output_tokens gemini "$empty_raw")" \
  "T5c: empty raw + gemini backend → '0' (estimator says no output)"

# Non-existent file: no telemetry, no crash, empty string.
assert_eq "" "$(xf input_tokens claude "$ghost_raw")" \
  "T5d: missing raw file → '' for any backend"
assert_eq "" "$(xf output_tokens gemini "$ghost_raw")" \
  "T5e: missing raw file → '' for any backend (gemini path too)"

# ── T6: unknown field returns empty ─────────────────────────────────

assert_eq "" "$(xf this_field_does_not_exist claude "$claude_raw")" \
  "T6: unrecognised field name → '' (does not crash, no python traceback)"

# ── T7: missing args still exit 0 with empty stdout (cost extraction
#         must never fail an audit session) ──────────────────────────

py_out=$(python3 "$USAGE_PY" extract-field 2>/dev/null)
py_rc=$?
assert_eq "0" "$py_rc" "T7a: extract-field with no args exits 0"
assert_eq "" "$py_out" "T7a: extract-field with no args prints ''"

py_out=$(python3 "$USAGE_PY" extract-field output_tokens 2>/dev/null)
py_rc=$?
assert_eq "0" "$py_rc" "T7b: extract-field with only field name exits 0"
assert_eq "" "$py_out" "T7b: extract-field with only field name prints ''"

# ── T8: legacy form (benchmark backward-compat) still works ─────────

legacy_out=$(python3 "$USAGE_PY" claude "$claude_raw" 2>&1)
if [[ "$legacy_out" == *'"input": 1500'* ]] && [[ "$legacy_out" == *'"output": 80'* ]]; then
  pass "T8: legacy '<backend> <raw>' form still produces a full JSON usage object"
else
  fail "T8: legacy '<backend> <raw>' form still produces a full JSON usage object" \
    "got: $legacy_out"
fi

# ── T9: unknown subcommand → empty JSON, exit 0 ─────────────────────

unk_out=$(python3 "$USAGE_PY" some-unknown-subcommand foo bar 2>/dev/null)
unk_rc=$?
assert_eq "0" "$unk_rc" "T9: unknown subcommand exits 0"
assert_eq "{}" "$unk_out" "T9: unknown subcommand prints '{}'"

# ── T10: multiple terminal events (re-invoked / resumed agent) are
#         SUMMED, not last-wins. Regression for a real ~100x undercount
#         where a cell with two `result` events counted only the final
#         short invocation. Per-turn assistant deltas must NOT be added on
#         top of the cumulative `result` totals. ──────────────────────
multi_raw="$work/multi.raw"
cat > "$multi_raw" <<'EOF'
{"type":"assistant","message":{"content":[{"type":"text","text":"a"}]},"usage":{"input_tokens":5,"output_tokens":10}}
{"type":"result","usage":{"input_tokens":100,"cache_read_input_tokens":1000,"cache_creation_input_tokens":50,"output_tokens":900}}
{"type":"assistant","message":{"content":[{"type":"text","text":"b"}]},"usage":{"input_tokens":2,"output_tokens":3}}
{"type":"result","usage":{"input_tokens":10,"cache_read_input_tokens":200,"cache_creation_input_tokens":5,"output_tokens":30}}
EOF

assert_eq "930"  "$(xf output_tokens claude "$multi_raw")" \
  "T10a: two result events → output summed (900+30), not last-wins (30)"
assert_eq "110"  "$(xf input_tokens claude "$multi_raw")" \
  "T10b: two result events → input summed (100+10)"
assert_eq "1200" "$(xf cached_input_tokens claude "$multi_raw")" \
  "T10c: two result events → cache_read summed (1000+200)"
assert_eq "55"   "$(xf cache_creation_input_tokens claude "$multi_raw")" \
  "T10d: two result events → cache_creation summed (50+5)"

summary
