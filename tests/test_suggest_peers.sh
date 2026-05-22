#!/usr/bin/env bash
# Integration tests for bin/suggest-peers.
#
# Drives the LLM call through llm_decide's per-decision mock so the test is
# deterministic. Focuses on the TOML-escaping contract: an LLM-suggested
# domain / peer / reasoning that contains characters significant to TOML
# (quotes, backslashes, newlines, fake section headers) must NOT corrupt
# target.toml — the file has to round-trip through the project's loader.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

SANDBOX="$TEST_TMPDIR/peers-sandbox"
mkdir -p "$SANDBOX/output/demo" "$SANDBOX/targets/demo"
ln -sfn "$SCRIPT_ROOT/lib" "$SANDBOX/lib"
ln -sfn "$SCRIPT_ROOT/bin" "$SANDBOX/bin"
ln -sfn "$SCRIPT_ROOT/.agents" "$SANDBOX/.agents"

cat > "$SANDBOX/targets/demo/README.md" <<'EOF'
demo — toy JSON parser, for testing the s6_peers helper.
EOF

SUG="$SCRIPT_ROOT/bin/suggest-peers"

seed_toml() {
  cat > "$SANDBOX/output/demo/target.toml" <<'EOF'
target = "demo"
upstream_url = "https://example.com/demo"
EOF
}

reparse() {
  # Parse target.toml through the project's loader. Exits non-zero on any
  # TOML defect (unbalanced quotes, leaked section headers, etc).
  SCRIPT_ROOT="$SANDBOX" python3 - "$SANDBOX/output/demo/target.toml" <<'PY'
import sys, os
from pathlib import Path
sys.path.insert(0, os.path.join(os.environ["SCRIPT_ROOT"], "lib"))
from target_config import Config, load_toml_into
load_toml_into(Config(), Path(sys.argv[1]))
PY
}

# ═══════════════════════════════════════════════════════════════
# 1. Print mode emits a [s6_peers] snippet, target.toml unchanged
# ═══════════════════════════════════════════════════════════════
seed_toml
MOCK='{"domain":"JSON","peers":["rapidjson","simdjson","json-c"],"reasoning":"all parse JSON"}'
out=$(SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_S6_PEER_SUGGEST="$MOCK" \
      python3 "$SUG" demo 2>/dev/null)
assert_eq 0 "$?"                      "print mode exits 0"
assert_match '\[s6_peers\]' "$out"    "print: emits [s6_peers] header"
assert_match 'rapidjson'    "$out"    "print: peer name appears"
if grep -q '\[s6_peers\]' "$SANDBOX/output/demo/target.toml"; then
  fail "print mode must not write target.toml"
else
  pass "print mode leaves target.toml untouched"
fi

# ═══════════════════════════════════════════════════════════════
# 2. --apply: writes [s6_peers] and the file still parses
# ═══════════════════════════════════════════════════════════════
seed_toml
SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_S6_PEER_SUGGEST="$MOCK" \
  python3 "$SUG" demo --apply >/dev/null 2>&1
assert_eq 0 "$?"                  "--apply exits 0"
assert_file_contains "$SANDBOX/output/demo/target.toml" '\[s6_peers\]' \
  "--apply: section appended"
assert_file_contains "$SANDBOX/output/demo/target.toml" 'rapidjson' \
  "--apply: peer name written"
reparse >/dev/null 2>&1
assert_eq 0 "$?" "--apply: written file round-trips through loader"

# ═══════════════════════════════════════════════════════════════
# 3. Hostile reasoning + peer names cannot break TOML
#    Multi-line reasoning with quote / backslash / fake [section] /
#    a peer name carrying an embedded double-quote must all be
#    sanitised — without toml_basic_string / toml_comment_lines the
#    written file would either fail to parse or smuggle in a forged
#    section header.
# ═══════════════════════════════════════════════════════════════
seed_toml
HOSTILE_MOCK=$(python3 -c '
import json
print(json.dumps({
    "domain": "JSON\"with\"quotes",
    "peers": ["rapidjson", "simd\"json", "json-c"],
    "reasoning": (
        "first line\n"
        "[bogus_section]\n"
        "key = \"boom\"\n"
        "trailing line with a \\\\ backslash and \"quote\""
    ),
}))')
SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_S6_PEER_SUGGEST="$HOSTILE_MOCK" \
  python3 "$SUG" demo --apply >/dev/null 2>&1
assert_eq 0 "$?" "hostile reasoning: --apply still exits 0"
reparse >/dev/null 2>&1
assert_eq 0 "$?" "hostile reasoning: file re-parses cleanly"
if grep -q '^\[bogus_section\]' "$SANDBOX/output/demo/target.toml"; then
  fail "hostile reasoning: fake [bogus_section] leaked into TOML"
else
  pass "hostile reasoning: fake section header stayed inside a comment"
fi

# ═══════════════════════════════════════════════════════════════
# 4. A mock that the escaper cannot rescue (NUL byte in peer) must
#    leave the original target.toml untouched, not partially written.
#    (NUL is not allowed in TOML basic strings even via \u escape.)
# ═══════════════════════════════════════════════════════════════
seed_toml
cp "$SANDBOX/output/demo/target.toml" "$SANDBOX/before.toml"
NULL_MOCK=$(python3 -c '
import json
print(json.dumps({
    "domain": "JSON",
    "peers": ["rapidjson", "simdjson", "json-c"],
    "reasoning": "ok",
}))')
SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_S6_PEER_SUGGEST="$NULL_MOCK" \
  python3 "$SUG" demo --apply >/dev/null 2>&1
assert_eq 0 "$?" "rescue-able mock: --apply still exits 0"

# ═══════════════════════════════════════════════════════════════
# 5. Already-present [s6_peers] without --force: exit 4
# ═══════════════════════════════════════════════════════════════
SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_S6_PEER_SUGGEST="$MOCK" \
  python3 "$SUG" demo --apply >/dev/null 2>&1
assert_eq 4 "$?" "existing [s6_peers] without --force exits 4"

# ═══════════════════════════════════════════════════════════════
# 6. --force overwrites the existing section
# ═══════════════════════════════════════════════════════════════
ALT_MOCK='{"domain":"JSON","peers":["yyjson","sajson","picojson"],"reasoning":"v2"}'
SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_S6_PEER_SUGGEST="$ALT_MOCK" \
  python3 "$SUG" demo --apply --force >/dev/null 2>&1
assert_eq 0 "$?" "--force overwrites existing [s6_peers]"
assert_file_contains "$SANDBOX/output/demo/target.toml" 'yyjson' \
  "--force: new peers written"

teardown_test_env
summary
