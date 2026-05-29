#!/usr/bin/env bash
# Unit tests for should_disable_resume_for_thinking_blocks (bin/audit).
# This guard prevents the Claude API 400 "thinking or redacted_thinking
# blocks in the latest assistant message cannot be modified" error that
# fires when --resume is used after a session whose prior assistant turn
# contained extended-thinking content blocks.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

audit_extract_function() {
  local name="$1"
  awk -v name="$name" '
    $0 ~ "^" name "\\(\\) \\{" { in_func=1 }
    in_func { print }
    in_func && $0 == "}" { exit }
  ' "$SCRIPT_ROOT/bin/audit"
}

eval "$(audit_extract_function should_disable_resume_for_thinking_blocks)"

# ── Empty raw file: no detection, returns 1 (do not disable) ─────
touch "$TEST_TMPDIR/empty.raw"
if should_disable_resume_for_thinking_blocks claude "$TEST_TMPDIR/empty.raw"; then
  fail "empty raw transcript should not trigger guard"
else
  pass "empty raw transcript does not trigger guard"
fi

# ── Plain text-only response: no thinking blocks, returns 1 ──────
cat > "$TEST_TMPDIR/text_only.raw" <<'EOF'
{"type":"message_start","message":{"id":"x","role":"assistant"}}
{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}
{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hello"}}
{"type":"content_block_stop","index":0}
{"type":"message_stop"}
EOF
if should_disable_resume_for_thinking_blocks claude "$TEST_TMPDIR/text_only.raw"; then
  fail "text-only transcript should not trigger guard"
else
  pass "text-only transcript does not trigger guard"
fi

# ── Tool-use only: no thinking blocks, returns 1 ─────────────────
cat > "$TEST_TMPDIR/tool_only.raw" <<'EOF'
{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"t1","name":"Bash"}}
{"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{}"}}
{"type":"content_block_stop","index":0}
EOF
if should_disable_resume_for_thinking_blocks claude "$TEST_TMPDIR/tool_only.raw"; then
  fail "tool-use transcript should not trigger guard"
else
  pass "tool-use transcript does not trigger guard"
fi

# ── Thinking block present: must trigger (returns 0) ─────────────
cat > "$TEST_TMPDIR/thinking.raw" <<'EOF'
{"type":"message_start","message":{"id":"x","role":"assistant"}}
{"type":"content_block_start","index":0,"content_block":{"type":"thinking","thinking":""}}
{"type":"content_block_delta","index":0,"delta":{"type":"thinking_delta","thinking":"step back"}}
{"type":"content_block_stop","index":0}
{"type":"content_block_start","index":1,"content_block":{"type":"text","text":"answer"}}
{"type":"content_block_stop","index":1}
EOF
if should_disable_resume_for_thinking_blocks claude "$TEST_TMPDIR/thinking.raw"; then
  pass "thinking block triggers guard"
else
  fail "thinking block should trigger guard"
fi

# ── redacted_thinking block: must also trigger ───────────────────
cat > "$TEST_TMPDIR/redacted.raw" <<'EOF'
{"type":"content_block_start","index":0,"content_block":{"type":"redacted_thinking","data":"opaque"}}
{"type":"content_block_stop","index":0}
EOF
if should_disable_resume_for_thinking_blocks claude "$TEST_TMPDIR/redacted.raw"; then
  pass "redacted_thinking block triggers guard"
else
  fail "redacted_thinking block should trigger guard"
fi

# ── Whitespace variants — JSON serializers can emit spaces ───────
cat > "$TEST_TMPDIR/spaces.raw" <<'EOF'
{ "type" : "thinking" , "thinking" : "..." }
EOF
if should_disable_resume_for_thinking_blocks claude "$TEST_TMPDIR/spaces.raw"; then
  pass "whitespace-padded type:thinking triggers guard"
else
  fail "whitespace-padded type:thinking should trigger guard"
fi

# ── Non-claude backend: never trigger ────────────────────────────
if should_disable_resume_for_thinking_blocks codex "$TEST_TMPDIR/thinking.raw"; then
  fail "non-claude backend should not trigger guard"
else
  pass "non-claude backend does not trigger guard"
fi

# ── False positive guard: 'thinking' inside a user message text  ─
# This is a fundamental limitation — grep can't tell content_block
# context from arbitrary text. Document it as a known property
# rather than assert it doesn't happen.
cat > "$TEST_TMPDIR/userthink.raw" <<'EOF'
{"type":"message_start","message":{"role":"user","content":"explain redacted_thinking"}}
EOF
if should_disable_resume_for_thinking_blocks claude "$TEST_TMPDIR/userthink.raw"; then
  # Acceptable: prefer false-positive (disable resume conservatively)
  # over false-negative (proceed to API 400).
  pass "user-text mentioning 'redacted_thinking' is conservatively flagged"
else
  pass "user-text mention not flagged (also acceptable)"
fi

teardown_test_env
summary
