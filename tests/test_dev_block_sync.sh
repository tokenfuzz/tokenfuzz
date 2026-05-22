#!/usr/bin/env bash
# AGENTS.md's leading <!-- harness-dev-only:begin -->…<!-- :end --> block
# mirrors CLAUDE.md so Codex/Gemini dev sessions auto-discover the same dev
# guidance Claude reads from CLAUDE.md. bin/audit strips that block before
# injecting the runtime guide into spawned agents (token-cost + relevance).
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

AGENTS="$SCRIPT_ROOT/AGENTS.md"
CLAUDE="$SCRIPT_ROOT/CLAUDE.md"

_CURRENT_TEST="AGENTS.md dev block matches CLAUDE.md verbatim"
extracted=$(sed -n '/<!-- harness-dev-only:begin/,/<!-- harness-dev-only:end/p' "$AGENTS" | sed '1d;$d' | sed -e '1{/^$/d;}' -e '${/^$/d;}')
canonical=$(cat "$CLAUDE")
if [ "$extracted" = "$canonical" ]; then
  pass
else
  diff_out=$(diff <(printf '%s' "$extracted") <(printf '%s' "$canonical") | head -20)
  fail "$_CURRENT_TEST" "AGENTS.md dev block diverges from CLAUDE.md — re-sync. Diff:
$diff_out"
fi

# Paranoia: if the strip filter ever silently disappears from bin/audit, the
# block above still passes — but spawned agents start eating ~2.5KB of dev
# guidance every prompt. Lock the wiring in place.
_CURRENT_TEST="bin/audit AGENT_GUIDE_CACHED strips the dev block"
if grep -q 'harness-dev-only:begin' "$SCRIPT_ROOT/bin/audit" \
   && grep -q 'harness-dev-only:end' "$SCRIPT_ROOT/bin/audit"; then
  pass
else
  fail "$_CURRENT_TEST" "bin/audit no longer references the harness-dev-only markers — the strip filter is gone, dev guidance is leaking into spawned agents"
fi

summary
