#!/usr/bin/env bash
# Integration tests for bin/suggest-peers and bin/peer-fix-cards.
# Both binaries invoke lib/llm_decide.py; we
# use LLM_DECIDE_MOCK_<UPPER> to drive deterministic responses.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

SANDBOX="$TEST_TMPDIR/s6-sandbox"
mkdir -p "$SANDBOX/output/myxml/results" "$SANDBOX/targets/myxml"
ln -sfn "$SCRIPT_ROOT/lib" "$SANDBOX/lib"
ln -sfn "$SCRIPT_ROOT/bin" "$SANDBOX/bin"
ln -sfn "$SCRIPT_ROOT/.agents" "$SANDBOX/.agents"

# Sample target source files so the file listing for the LLM-map step is non-empty.
echo "// stub" > "$SANDBOX/targets/myxml/parser.c"
echo "// stub" > "$SANDBOX/targets/myxml/SAX2.c"
echo "// stub" > "$SANDBOX/targets/myxml/encoding.c"
cat > "$SANDBOX/targets/myxml/README.md" <<'EOF'
myxml — a toy XML library used for harness integration tests.
EOF

# ═══════════════════════════════════════════════════════════════
# 1. bin/suggest-peers prints a snippet and respects overwrite gate
# ═══════════════════════════════════════════════════════════════

cat > "$SANDBOX/output/myxml/target.toml" <<'EOF'
target = "myxml"
upstream_url = "https://example.com/myxml"
EOF

# Print-only (no --apply)
output=$(
  SCRIPT_ROOT="$SANDBOX" \
  LLM_DECIDE_MOCK_S6_PEER_SUGGEST='{"domain":"XML / SGML","peers":["expat","libxslt","html5ever"],"reasoning":"all XML parsers"}' \
  python3 "$SCRIPT_ROOT/bin/suggest-peers" myxml 2>&1
)
rc=$?
assert_eq 0 "$rc" "suggest-peers: exits 0 on success"
assert_match '\[s6_peers\]' "$output" "suggest-peers: prints [s6_peers] header"
assert_match 'expat' "$output" "suggest-peers: prints peers"
assert_match 'XML / SGML' "$output" "suggest-peers: prints domain"

# --apply appends to target.toml
SCRIPT_ROOT="$SANDBOX" \
LLM_DECIDE_MOCK_S6_PEER_SUGGEST='{"domain":"XML / SGML","peers":["expat","libxslt","html5ever"],"reasoning":"x"}' \
python3 "$SCRIPT_ROOT/bin/suggest-peers" myxml --apply >/dev/null 2>&1
assert_file_contains "$SANDBOX/output/myxml/target.toml" '\[s6_peers\]' "suggest-peers --apply: writes [s6_peers]"
assert_file_contains "$SANDBOX/output/myxml/target.toml" 'expat' "suggest-peers --apply: writes peer list"

# Second --apply without --force should refuse
SCRIPT_ROOT="$SANDBOX" \
LLM_DECIDE_MOCK_S6_PEER_SUGGEST='{"domain":"DNS","peers":["unbound","bind9","knot"],"reasoning":"x"}' \
python3 "$SCRIPT_ROOT/bin/suggest-peers" myxml --apply >/dev/null 2>&1
rc=$?
assert_eq 4 "$rc" "suggest-peers: --apply refuses to overwrite without --force"

# --force overwrites
SCRIPT_ROOT="$SANDBOX" \
LLM_DECIDE_MOCK_S6_PEER_SUGGEST='{"domain":"DNS","peers":["unbound","bind9","knot"],"reasoning":"x"}' \
python3 "$SCRIPT_ROOT/bin/suggest-peers" myxml --apply --force >/dev/null 2>&1
rc=$?
assert_eq 0 "$rc" "suggest-peers: --force overwrites existing section"
assert_file_contains "$SANDBOX/output/myxml/target.toml" 'unbound' "suggest-peers --force: new peers replaced old"

# LLM unavailable → exit 2
output=$(
  SCRIPT_ROOT="$SANDBOX" \
  LLM_DECIDE_DISABLE=1 \
  python3 "$SCRIPT_ROOT/bin/suggest-peers" myxml 2>&1
)
rc=$?
assert_eq 2 "$rc" "suggest-peers: exits 2 when LLM unavailable"

# LLM returns no peers → valid "S6 not applicable" answer (synthetic target /
# harness fixture): exit 0 with an explicit empty section, so setup-target's
# backend rotation stops here instead of falling through to another backend.
output=$(
  SCRIPT_ROOT="$SANDBOX" \
  LLM_DECIDE_MOCK_S6_PEER_SUGGEST='{"domain":"","peers":[],"reasoning":"synthetic fixture, no shared spec to mine"}' \
  python3 "$SCRIPT_ROOT/bin/suggest-peers" myxml 2>&1
)
rc=$?
assert_eq 0 "$rc" "suggest-peers: exits 0 on empty peers (S6 not applicable)"
assert_match 'peers  = \[\]' "$output" "suggest-peers: prints explicit empty peers"

# Unknown slug
output=$(
  SCRIPT_ROOT="$SANDBOX" \
  python3 "$SCRIPT_ROOT/bin/suggest-peers" nonexistent-slug 2>&1
)
rc=$?
assert_eq 1 "$rc" "suggest-peers: exits 1 on unknown slug"

# ═══════════════════════════════════════════════════════════════
# 2. bin/peer-fix-cards with empty s6_peers writes empty JSONL
# ═══════════════════════════════════════════════════════════════

# Reset target.toml to have no [s6_peers]
cat > "$SANDBOX/output/myxml/target.toml" <<'EOF'
target = "myxml"
EOF

rc=0
SCRIPT_ROOT="$SANDBOX" \
RESULTS_DIR="$SANDBOX/output/myxml/results" \
TARGET_ROOT="$SANDBOX/targets/myxml" \
TARGET_SLUG=myxml \
LLM_DECIDE_DISABLE=1 \
python3 "$SCRIPT_ROOT/bin/peer-fix-cards" --target-slug myxml --quiet >/dev/null 2>&1 || rc=$?
assert_eq 0 "$rc" "peer-fix-cards: empty s6_peers exits 0"
if [ -f "$SANDBOX/output/myxml/results/s6-peer-cards.jsonl" ]; then
  pass "peer-fix-cards: empty case writes empty jsonl"
else
  fail "peer-fix-cards: empty case writes empty jsonl" "file missing"
fi
assert_eq "0" "$(wc -l < "$SANDBOX/output/myxml/results/s6-peer-cards.jsonl" | tr -d ' ')" "peer-fix-cards: empty case produces 0-line jsonl"

# ═══════════════════════════════════════════════════════════════
# 3. bin/peer-fix-cards end-to-end with mocked OSV + LLM
# ═══════════════════════════════════════════════════════════════

# target.toml with one peer.
cat > "$SANDBOX/output/myxml/target.toml" <<'EOF'
target = "myxml"

[s6_peers]
domain = "XML / SGML"
peers = ["expat"]
EOF

# Drop a stand-in PEERS.toml so peer_sources doesn't try to query OSV
# for unknown slugs in other tests. (Harness PEERS.toml is symlinked
# already; we override here only the sandbox's targets dir.)
cp "$SCRIPT_ROOT/targets/PEERS.toml" "$SANDBOX/targets/PEERS.toml" 2>/dev/null || true

# Mock OSV so we don't hit the network. Wrap peer-fix-cards in a python
# shim that monkey-patches peer_sources.osv_query before main(), then
# falls through to the regular CLI path. This proves the orchestrator
# routes OSV data into cards correctly when given known input.
SHIM="$TEST_TMPDIR/peer-fix-cards-shim.py"
cat > "$SHIM" <<PYEOF
import os, sys
from pathlib import Path
SR = os.environ["SCRIPT_ROOT"]
sys.path.insert(0, f"{SR}/lib")
import peer_sources

def fake_osv_query(peer, **kwargs):
    return [{
        "source": "osv",
        "id": "CVE-2099-0001",
        "fix_hash": "deadbeef" * 5,
        "summary": "fix bounds check in entity parser",
        "url": "https://osv.dev/vulnerability/CVE-2099-0001",
        "modified": "2099-01-01T00:00:00Z",
    }]

peer_sources.osv_query = fake_osv_query

# Now run the CLI
sys.argv = ["peer-fix-cards", "--target-slug", "myxml", "--quiet"]
runpy_path = f"{SR}/bin/peer-fix-cards"
import runpy
runpy.run_path(runpy_path, run_name="__main__")
PYEOF

# LLM mocks for both LLM steps (distill + map). Names match the bash
# helper's per-decision env var convention: LLM_DECIDE_MOCK_<UPPER>
SCRIPT_ROOT="$SANDBOX" \
RESULTS_DIR="$SANDBOX/output/myxml/results" \
TARGET_ROOT="$SANDBOX/targets/myxml" \
TARGET_SLUG=myxml \
LLM_DECIDE_MOCK_S6_PEER_DISTILL='{"class":"bounds","summary":"entity expansion writes past buffer","shape":"adds bounds check"}' \
LLM_DECIDE_MOCK_S6_PEER_MAP='{"file":"parser.c","reason":"target equivalent of entity parser"}' \
python3 "$SHIM" >/dev/null 2>&1
rc=$?
assert_eq 0 "$rc" "peer-fix-cards: end-to-end with mocks exits 0"

# Verify card written
card_file="$SANDBOX/output/myxml/results/s6-peer-cards.jsonl"
if [ -s "$card_file" ]; then
  pass "peer-fix-cards: writes non-empty jsonl"
else
  fail "peer-fix-cards: writes non-empty jsonl" "got: $(cat "$card_file" 2>/dev/null)"
fi
assert_file_contains "$card_file" '"strategy":\s*"S6"' "peer-fix-cards: card has strategy=S6"
assert_file_contains "$card_file" '"kind":\s*"s6-peer-fix"' "peer-fix-cards: card has kind=s6-peer-fix"
assert_file_contains "$card_file" '"peer_project":\s*"expat"' "peer-fix-cards: card has peer_project"
assert_file_contains "$card_file" '"file":\s*"parser.c"' "peer-fix-cards: card.file is mapped target file"
assert_file_contains "$card_file" 'bounds' "peer-fix-cards: card.bug_class carries distillation"

# ═══════════════════════════════════════════════════════════════
# 4. Hallucination guard — LLM-mapped file outside listing is rejected
# ═══════════════════════════════════════════════════════════════

# Same setup, but the LLM-map mock returns a file that is NOT in the
# listing. The orchestrator must drop the card rather than emit garbage.
rm -f "$card_file"
SCRIPT_ROOT="$SANDBOX" \
RESULTS_DIR="$SANDBOX/output/myxml/results" \
TARGET_ROOT="$SANDBOX/targets/myxml" \
TARGET_SLUG=myxml \
LLM_DECIDE_MOCK_S6_PEER_DISTILL='{"class":"bounds","summary":"x","shape":"x"}' \
LLM_DECIDE_MOCK_S6_PEER_MAP='{"file":"fictitious-file-does-not-exist.c","reason":"hallucinated"}' \
python3 "$SHIM" >/dev/null 2>&1
rc=$?
assert_eq 0 "$rc" "peer-fix-cards: hallucination-guard run exits 0"
if [ -f "$card_file" ]; then
  assert_eq "0" "$(wc -l < "$card_file" | tr -d ' ')" "peer-fix-cards: hallucinated map drops card"
else
  fail "peer-fix-cards: empty jsonl exists after hallucination run" "no file"
fi

# ═══════════════════════════════════════════════════════════════
# 5. LLM verdict cache — identical re-run skips both LLM calls
# ═══════════════════════════════════════════════════════════════
# Fixes mined from OSV are stable between work-card refreshes; the
# distill + map verdicts must replay from .s6-cache instead of paying
# two LLM round-trips per fix on every refresh. The decision log counts
# actual engine invocations (cache hits don't log).

s6llm_log="$TEST_TMPDIR/s6-decisions.log"
rm -f "$s6llm_log" "$card_file"
rm -rf "$SANDBOX/output/myxml/results/.s6-cache"
for _pass in 1 2; do
  SCRIPT_ROOT="$SANDBOX" \
  RESULTS_DIR="$SANDBOX/output/myxml/results" \
  TARGET_ROOT="$SANDBOX/targets/myxml" \
  TARGET_SLUG=myxml \
  LLM_DECIDE_LOG="$s6llm_log" \
  LLM_DECIDE_MOCK_S6_PEER_DISTILL='{"class":"bounds","summary":"entity expansion writes past buffer","shape":"adds bounds check"}' \
  LLM_DECIDE_MOCK_S6_PEER_MAP='{"file":"parser.c","reason":"target equivalent of entity parser"}' \
  python3 "$SHIM" >/dev/null 2>&1
done
assert_file_contains "$card_file" '"file":\s*"parser.c"' \
  "peer-fix-cards: cached re-run still emits the mapped card"
distill_calls=$(grep -c 's6-peer-distill MOCK' "$s6llm_log" 2>/dev/null || true)
map_calls=$(grep -c 's6-peer-map MOCK' "$s6llm_log" 2>/dev/null || true)
assert_eq 1 "$distill_calls" "peer-fix-cards: distill verdict replayed from cache on re-run"
assert_eq 1 "$map_calls" "peer-fix-cards: map verdict replayed from cache on re-run"

# ── 5b. decider key resolves the backend default model ──────────────
# MODEL unset must key the cache by the backend's resolved default
# (config/models.toml), not by the empty string — otherwise a harness
# default-model bump would silently replay stale verdicts. Run 1 leaves
# MODEL empty; run 2 pins MODEL to the configured default (same key →
# cache hit); run 3 pins a different model (key changes → re-ask).
default_backend_model=$(python3 - <<PY
import sys
sys.path.insert(0, "$SCRIPT_ROOT/lib")
from llm_invoke import default_model
print(default_model("codex"))
PY
)
s6llm_log2="$TEST_TMPDIR/s6-decisions-model.log"
rm -f "$s6llm_log2" "$card_file"
rm -rf "$SANDBOX/output/myxml/results/.s6-cache"
for run_model in "" "$default_backend_model" "some-other-model"; do
  SCRIPT_ROOT="$SANDBOX" \
  RESULTS_DIR="$SANDBOX/output/myxml/results" \
  TARGET_ROOT="$SANDBOX/targets/myxml" \
  TARGET_SLUG=myxml \
  ACTIVE_BACKEND=codex \
  MODEL="$run_model" \
  LLM_DECIDE_LOG="$s6llm_log2" \
  LLM_DECIDE_MOCK_S6_PEER_DISTILL='{"class":"bounds","summary":"entity expansion writes past buffer","shape":"adds bounds check"}' \
  LLM_DECIDE_MOCK_S6_PEER_MAP='{"file":"parser.c","reason":"target equivalent of entity parser"}' \
  python3 "$SHIM" >/dev/null 2>&1
done
distill_calls=$(grep -c 's6-peer-distill MOCK' "$s6llm_log2" 2>/dev/null || true)
map_calls=$(grep -c 's6-peer-map MOCK' "$s6llm_log2" 2>/dev/null || true)
assert_eq 2 "$distill_calls" "peer-fix-cards: unset MODEL shares the resolved-default cache entry; model change re-asks"
assert_eq 2 "$map_calls" "peer-fix-cards: map cache keys on the resolved model too"

teardown_test_env
summary
