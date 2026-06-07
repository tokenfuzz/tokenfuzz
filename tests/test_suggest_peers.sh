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
# 2b. "No meaningful peers" is a valid explicit empty section
#     A synthetic target / harness fixture has no genuine S6 peers;
#     the model signals that with domain="" + peers=[]. That must be a
#     terminal success (exit 0, no warning), not an rc=3 that pushes
#     setup-target's backend rotation on to Claude.
# ═══════════════════════════════════════════════════════════════
for reason in \
  "demo is a synthetic harness fixture with a custom packet format, not a shared spec, format, or algorithm suitable for S6 peer mining." \
  "demo is a synthetic local harness parsing a custom length-prefixed record, not a named spec/format/algorithm with independent peer implementations." \
  "demo appears to be a synthetic harness fixture rather than an implementation of a shared spec, format, or algorithm." \
  "demo appears to be a synthetic harness fixture without a shared spec, format, or algorithm peer set for S6 mining."; do
  seed_toml
  NO_PEER_MOCK=$(python3 -c 'import json,sys; print(json.dumps({"domain":"","peers":[],"reasoning":sys.argv[1]}))' "$reason")
  no_peer_out=$(SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_S6_PEER_SUGGEST="$NO_PEER_MOCK" \
    python3 "$SUG" demo --apply 2>&1)
  assert_eq 0 "$?" "no-peer response: --apply exits 0"
  assert_not_match "warning" "$no_peer_out" \
    "no-peer response: explicit empty peers do not warn"
  assert_file_contains "$SANDBOX/output/demo/target.toml" 'peers  = \[\]' \
    "no-peer response: writes explicit empty peers"
  reparse >/dev/null 2>&1
  assert_eq 0 "$?" "no-peer response: written file round-trips through loader"
done

# ═══════════════════════════════════════════════════════════════
# 2c. Contradictory placeholder peers are discarded deterministically
#     The model named real-looking peers but its reasoning disowns them
#     as placeholders / not-applicable: trust the reasoning, drop the
#     peers, write an explicit empty section — never the junk names.
# ═══════════════════════════════════════════════════════════════
seed_toml
PLACEHOLDER_MOCK='{"domain":"Compression — DEFLATE","peers":["zlib","libdeflate","miniz"],"reasoning":"no real spec row applies; these are placeholder peers and S6 is not applicable"}'
placeholder_out=$(SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_S6_PEER_SUGGEST="$PLACEHOLDER_MOCK" \
  python3 "$SUG" demo --apply 2>&1)
assert_eq 0 "$?" "placeholder peers: --apply exits 0"
assert_match "explicit empty peers" "$placeholder_out" \
  "placeholder peers: emits deterministic downgrade message"
assert_file_contains "$SANDBOX/output/demo/target.toml" 'peers  = \[\]' \
  "placeholder peers: writes empty peers"
assert_file_not_contains "$SANDBOX/output/demo/target.toml" 'zlib' \
  "placeholder peers: does not write unrelated peer names"

# ═══════════════════════════════════════════════════════════════
# 2d. Empty peers is honoured from the structured field, so any phrasing
#     of the "not applicable" reason is accepted (robust across backends).
# ═══════════════════════════════════════════════════════════════
seed_toml
OFFVOCAB_MOCK='{"domain":"","peers":[],"reasoning":"This target stands alone; nothing else implements the same thing."}'
offvocab_out=$(SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_S6_PEER_SUGGEST="$OFFVOCAB_MOCK" \
  python3 "$SUG" demo --apply 2>&1)
assert_eq 0 "$?" "empty peers, off-vocabulary reason: exits 0"
assert_file_contains "$SANDBOX/output/demo/target.toml" 'peers  = \[\]' \
  "empty peers, off-vocabulary reason: writes explicit empty peers"

# ═══════════════════════════════════════════════════════════════
# 2e. peers=[] is authoritative even if the model still named a domain:
#     write an explicit empty section (exit 0), never half a row.
# ═══════════════════════════════════════════════════════════════
seed_toml
DOMAIN_ONLY_MOCK='{"domain":"XML / SGML","peers":[],"reasoning":"no independent peers identified"}'
domain_only_out=$(SCRIPT_ROOT="$SANDBOX" LLM_DECIDE_MOCK_S6_PEER_SUGGEST="$DOMAIN_ONLY_MOCK" \
  python3 "$SUG" demo --apply 2>&1)
assert_eq 0 "$?" "empty peers with a stray domain: exits 0"
assert_file_contains "$SANDBOX/output/demo/target.toml" 'peers  = \[\]' \
  "empty peers with a stray domain: writes explicit empty peers"
assert_file_contains "$SANDBOX/output/demo/target.toml" 'domain = ""' \
  "empty peers with a stray domain: domain blanked, not a half-written row"

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
