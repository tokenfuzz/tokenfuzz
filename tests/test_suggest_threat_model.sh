#!/usr/bin/env bash
# Integration tests for bin/suggest-threat-model.
#
# The binary calls lib/llm_decide through the Python bridge; we drive it
# with LLM_DECIDE_MOCK_<UPPER> for deterministic responses. The test
# harness sets LLM_DECIDE_DISABLE=1 globally — that gates only the real
# backend, so the per-decision mock still runs.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

SANDBOX="$TEST_TMPDIR/tm-sandbox"
mkdir -p "$SANDBOX/output/demo" "$SANDBOX/targets/demo/include"
ln -sfn "$SCRIPT_ROOT/lib" "$SANDBOX/lib"
ln -sfn "$SCRIPT_ROOT/bin" "$SANDBOX/bin"
ln -sfn "$SCRIPT_ROOT/.agents" "$SANDBOX/.agents"

cat > "$SANDBOX/targets/demo/README.md" <<'EOF'
demo — a stateful XML parser library with a public push/pull API.
EOF
echo "// demo public api" > "$SANDBOX/targets/demo/include/demo.h"

SUG="$SCRIPT_ROOT/bin/suggest-threat-model"
MOCK='{"attacker_controls":["bytes","call-sequence"],"reasoning":"stateful parser API"}'

# A freshly seeded target.toml: [threat_model] present with the byte-only
# placeholder, under its comment legend.
seed_toml() {
  cat > "$SANDBOX/output/demo/target.toml" <<'EOF'
target = "demo"
upstream_url = "https://example.com/demo"

# ── Threat model (drives lib/triage.py verdict matrix) ──
[threat_model]
attacker_controls = ["bytes"]
EOF
}

# ═══════════════════════════════════════════════════════════════
# 1. Print mode emits a [threat_model] snippet, leaves target.toml alone
# ═══════════════════════════════════════════════════════════════
seed_toml
out=$(SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_THREAT_MODEL_SUGGEST="$MOCK" \
      python3 "$SUG" demo 2>/dev/null)
assert_eq 0 "$?" "print mode exits 0"
assert_match '\[threat_model\]' "$out" "print: emits [threat_model] header"
assert_match 'call-sequence' "$out" "print: emits the suggested token"
assert_file_contains "$SANDBOX/output/demo/target.toml" 'attacker_controls = \["bytes"\]' \
  "print mode leaves target.toml unmodified"

# ═══════════════════════════════════════════════════════════════
# 2. --apply over the byte-only placeholder needs no --force
# ═══════════════════════════════════════════════════════════════
SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_THREAT_MODEL_SUGGEST="$MOCK" \
  python3 "$SUG" demo --apply >/dev/null 2>&1
assert_eq 0 "$?" "--apply over byte-only placeholder exits 0"
assert_file_contains "$SANDBOX/output/demo/target.toml" \
  'attacker_controls = \["bytes", "call-sequence"\]' \
  "--apply: rewrites attacker_controls in place"
assert_file_contains "$SANDBOX/output/demo/target.toml" '── Threat model' \
  "--apply: preserves the section comment legend"

# Written value must round-trip through the target.toml loader.
rt=$(python3 - "$SANDBOX/output/demo/target.toml" <<PY
import sys
sys.path.insert(0, "$SCRIPT_ROOT/lib")
import target_config as tc
cfg = tc.Config()
tc.load_toml_into(cfg, sys.argv[1])
print(cfg.attacker_controls_csv())
PY
)
assert_eq "bytes,call-sequence" "$rt" "--apply: written value round-trips through the loader"

# ═══════════════════════════════════════════════════════════════
# 3. A second --apply (model is now non-default) is refused without --force
# ═══════════════════════════════════════════════════════════════
SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_THREAT_MODEL_SUGGEST="$MOCK" \
  python3 "$SUG" demo --apply >/dev/null 2>&1
assert_eq 4 "$?" "--apply refuses to overwrite a non-default model without --force"

# ═══════════════════════════════════════════════════════════════
# 4. --force overwrites; the marker comment is replaced, not duplicated
# ═══════════════════════════════════════════════════════════════
MOCK_PROTO='{"attacker_controls":["bytes","protocol-state"],"reasoning":"network protocol"}'
SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_THREAT_MODEL_SUGGEST="$MOCK_PROTO" \
  python3 "$SUG" demo --apply --force >/dev/null 2>&1
assert_eq 0 "$?" "--apply --force overwrites a non-default model"
assert_file_contains "$SANDBOX/output/demo/target.toml" 'protocol-state' \
  "--force: new tokens written"
markers=$(grep -c 'set by bin/suggest-threat-model' "$SANDBOX/output/demo/target.toml")
assert_eq 1 "$markers" "--force: stale marker comment replaced, not duplicated"

# ═══════════════════════════════════════════════════════════════
# 5. Token normalization: call-order → call-sequence, unknown token dropped
# ═══════════════════════════════════════════════════════════════
seed_toml
NMOCK='{"attacker_controls":["bytes","call-order","magic-pony"],"reasoning":"x"}'
SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_THREAT_MODEL_SUGGEST="$NMOCK" \
  python3 "$SUG" demo --apply >/dev/null 2>&1
assert_file_contains "$SANDBOX/output/demo/target.toml" \
  'attacker_controls = \["bytes", "call-sequence"\]' \
  "normalization: call-order→call-sequence, unknown token dropped"

# ═══════════════════════════════════════════════════════════════
# 6. --apply with no [threat_model] section appends one
# ═══════════════════════════════════════════════════════════════
cat > "$SANDBOX/output/demo/target.toml" <<'EOF'
target = "demo"
EOF
SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_THREAT_MODEL_SUGGEST="$MOCK" \
  python3 "$SUG" demo --apply >/dev/null 2>&1
assert_eq 0 "$?" "--apply with no [threat_model] section exits 0"
assert_file_contains "$SANDBOX/output/demo/target.toml" '\[threat_model\]' \
  "--apply: appends a [threat_model] section when absent"

# ═══════════════════════════════════════════════════════════════
# 7. LLM unavailable → exit 2
# ═══════════════════════════════════════════════════════════════
seed_toml
SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_DISABLE=1 python3 "$SUG" demo >/dev/null 2>&1
assert_eq 2 "$?" "exits 2 when the LLM is unavailable"

# ═══════════════════════════════════════════════════════════════
# 8. Response with no valid tokens → exit 3
# ═══════════════════════════════════════════════════════════════
SCRIPT_ROOT="$SANDBOX" \
  LLM_DECIDE_MOCK_THREAT_MODEL_SUGGEST='{"attacker_controls":["magic-pony"],"reasoning":"x"}' \
  python3 "$SUG" demo >/dev/null 2>&1
assert_eq 3 "$?" "exits 3 when no valid attacker_controls tokens survive"

# ═══════════════════════════════════════════════════════════════
# 9. Unknown slug → exit 1
# ═══════════════════════════════════════════════════════════════
SCRIPT_ROOT="$SANDBOX" python3 "$SUG" nonexistent-slug >/dev/null 2>&1
assert_eq 1 "$?" "exits 1 on an unknown slug"

# ═══════════════════════════════════════════════════════════════
# 10. Hostile / quirky reasoning cannot break TOML parsing
#     A reasoning blob with embedded newlines, quotes, and backslashes
#     must survive --apply: the file must still parse, and the new
#     attacker_controls value must round-trip through the loader. Without
#     toml_comment_lines / toml_basic_string the second line of a
#     multiline reasoning blob would escape the # context and corrupt
#     the file (or `apply` would write invalid TOML that the next
#     `bin/audit` start refuses).
# ═══════════════════════════════════════════════════════════════
seed_toml
# Build the mock with python's json module so embedded quotes / backslashes
# / newlines reach the suggest-threat-model script as a single JSON string.
HOSTILE_MOCK=$(python3 -c '
import json
print(json.dumps({
    "attacker_controls": ["bytes", "race"],
    "reasoning": (
        "line one\n"
        "line two with \"quote\" and \\\\ backslash\n"
        "[fake_section]\n"
        "key = \"boom\""
    ),
}))')
SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_THREAT_MODEL_SUGGEST="$HOSTILE_MOCK" \
  python3 "$SUG" demo --apply >/dev/null 2>&1
assert_eq 0 "$?" "hostile reasoning: --apply still exits 0"

# Re-parse via the project's own loader: invalid TOML would raise.
ACTUAL_CTRLS=$(SCRIPT_ROOT="$SANDBOX" python3 - "$SANDBOX/output/demo/target.toml" \
              <<'PY'
import sys, os
from pathlib import Path
sys.path.insert(0, os.path.join(os.environ["SCRIPT_ROOT"], "lib"))
from target_config import Config, load_toml_into
c = Config()
load_toml_into(c, Path(sys.argv[1]))
print(",".join(c.attacker_controls))
PY
)
assert_eq "bytes,race" "$ACTUAL_CTRLS" \
  "hostile reasoning: written attacker_controls round-trip cleanly"
# Reasoning text containing what *looks* like a TOML section header must
# not have leaked into the file as a real section.
if grep -q '^\[fake_section\]' "$SANDBOX/output/demo/target.toml"; then
  fail "hostile reasoning: fake [fake_section] header leaked into TOML"
else
  pass "hostile reasoning: fake section header stayed inside a comment"
fi

# ═══════════════════════════════════════════════════════════════
# 11. Empty-prompt-style: a reasoning that is the empty string must not
#     wedge the comment rendering (regression guard for toml_comment_lines).
# ═══════════════════════════════════════════════════════════════
seed_toml
EMPTY_REASONING_MOCK='{"attacker_controls":["bytes"],"reasoning":""}'
SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_THREAT_MODEL_SUGGEST="$EMPTY_REASONING_MOCK" \
  python3 "$SUG" demo --apply >/dev/null 2>&1
assert_eq 0 "$?" "empty reasoning: --apply still exits 0"
SCRIPT_ROOT="$SANDBOX" python3 - "$SANDBOX/output/demo/target.toml" <<'PY' \
  && pass "empty reasoning: file round-trips through loader" \
  || fail "empty reasoning: file failed to re-parse"
import sys, os
from pathlib import Path
sys.path.insert(0, os.path.join(os.environ["SCRIPT_ROOT"], "lib"))
from target_config import Config, load_toml_into
load_toml_into(Config(), Path(sys.argv[1]))
PY

teardown_test_env
summary
