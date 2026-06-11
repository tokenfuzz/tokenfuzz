#!/usr/bin/env bash
# Tests for bin/reachability.
#
# Strategy: every backend honors REACHABILITY_MOCK_DIR=<dir> and reads its
# response from <dir>/<service>-<sha1(symbol)>.json instead of hitting the
# network. We seed those fixture files here, so tests are hermetic and the
# CI machine never touches Sourcegraph or the gh CLI.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

REACH="$SCRIPT_ROOT/bin/reachability"
[ -x "$REACH" ] || { echo "FATAL: $REACH not executable"; exit 1; }

# sha1 of a symbol — must match what bin/reachability computes.
sha1_short() {
  printf '%s' "$1" | shasum -a 1 | awk '{print substr($1,1,16)}'
}

mkdir -p "$TEST_TMPDIR/mock" "$TEST_TMPDIR/cache" "$TEST_TMPDIR/crashes/CRASH-EXAMPLE"
export REACHABILITY_MOCK_DIR="$TEST_TMPDIR/mock"
export REACHABILITY_CACHE_DIR="$TEST_TMPDIR/cache"

# ───────────────────────────────────────────────────────────────────
# Seed fixtures: one symbol "demo_decode", two backends.
#   - sourcegraph: 3 hits (one will be filtered)
#   - gh: backend "unavailable" (gh not installed in test env)
# ───────────────────────────────────────────────────────────────────
SYM_HASH=$(sha1_short "demo_decode")
cat > "$REACHABILITY_MOCK_DIR/sourcegraph-${SYM_HASH}.json" <<'EOF'
{ "status": "ok", "hits": [
  {"repo": "OtherProject/demo-fork", "path": "demo_decode.c"},
  {"repo": "alice/cool-tool",        "path": "src/main.c"},
  {"repo": "bob/another-consumer",   "path": "src/regex.cpp"}
]}
EOF
cat > "$REACHABILITY_MOCK_DIR/gh-${SYM_HASH}.json" <<'EOF'
{ "status": "unavailable", "error": "gh CLI not installed" }
EOF

# ───────────────────────────────────────────────────────────────────
# 1. Default human output (no ignore filter)
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="default human output names every backend"
out=$(python3 "$REACH" --symbol demo_decode --no-cache 2>&1) || \
  fail "$_CURRENT_TEST" "exit nonzero: $out"
assert_match "Reachability for: demo_decode" "$out" "human header present"
assert_match "External callers \(genuine\): +3" "$out" "3 callers when no ignore"
assert_match "sourcegraph +status=ok +hits=3" "$out" "sourcegraph count = 3"
assert_match "gh +status=unavailable +hits=0" "$out" "gh marked unavailable"

# ───────────────────────────────────────────────────────────────────
# 2. Ignore filter drops vendored copies and forks
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="ignore filter drops vendored and forks"
out=$(python3 "$REACH" --symbol demo_decode --no-cache \
        --ignore demo-vendored --ignore demo-fork 2>&1) || \
  fail "$_CURRENT_TEST" "exit nonzero: $out"
assert_match "External callers \(genuine\): +2" "$out" "3 - 1 ignored = 2"

# ───────────────────────────────────────────────────────────────────
# 3. JSON output is well-formed and carries union counts
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="json output shape"
out=$(python3 "$REACH" --symbol demo_decode --json --no-cache 2>&1) || \
  fail "$_CURRENT_TEST" "exit nonzero: $out"
echo "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin)
r = data["reachability"]
assert r["external_callers"] == 3, r["external_callers"]
assert set(r["services"]) == {"sourcegraph", "gh"}, r["services"]
assert r["services"]["sourcegraph"]["count"] == 3
assert r["services"]["gh"]["status"] == "unavailable"
assert r["schema_version"] in (1, 2), r["schema_version"]
assert "vendored_copies" in r, "vendored_copies field missing"
assert "demo_decode" in r["symbols"]
print("json OK")
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "json validation failed"

# ───────────────────────────────────────────────────────────────────
# 4. Cache: a second call uses cached results (delete the mock file
#    after the first call; second call must succeed from cache).
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="cache hit after mock removed"
rm -rf "$REACHABILITY_CACHE_DIR"
mkdir -p "$REACHABILITY_CACHE_DIR"
python3 "$REACH" --symbol demo_decode --json >/dev/null 2>&1
# The cache file should now exist for ok-status backends only. Filename
# is mtime-keyed (no date suffix) and the digest covers (language, symbol)
# — see _cache_path() in bin/reachability. With no resolvable target tree
# the language defaults to "c".
CACHE_HASH=$(sha1_short "c|demo_decode")
cache_file="$REACHABILITY_CACHE_DIR/sourcegraph-${CACHE_HASH}.json"
assert_file_exists "$cache_file" "sourcegraph cache file written"
unavail_cache="$REACHABILITY_CACHE_DIR/gh-${CACHE_HASH}.json"
[ ! -f "$unavail_cache" ] && pass "$_CURRENT_TEST: gh (unavailable) NOT cached" || \
  fail "$_CURRENT_TEST" "unavailable response was cached, should not be"
# Move mocks aside; cache must satisfy.
mv "$REACHABILITY_MOCK_DIR/sourcegraph-${SYM_HASH}.json" "$REACHABILITY_MOCK_DIR/sourcegraph-${SYM_HASH}.json.bak"
out=$(python3 "$REACH" --symbol demo_decode --json 2>&1)
mv "$REACHABILITY_MOCK_DIR/sourcegraph-${SYM_HASH}.json.bak" "$REACHABILITY_MOCK_DIR/sourcegraph-${SYM_HASH}.json"
echo "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin)
r = data["reachability"]
# Without cache the gh unavailable entry would still be present, but the ok
# backends must show their hit count from the cached response.
assert r["services"]["sourcegraph"]["count"] == 3, r["services"]["sourcegraph"]
print("cache hit OK")
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "cache did not satisfy second call"

# ───────────────────────────────────────────────────────────────────
# 4b. Parallel cache writers use unique temp files and leave valid JSON
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="cache writes are atomic under parallel writers"
python3 - "$REACH" "$REACHABILITY_CACHE_DIR" <<'PY' >/dev/null
import concurrent.futures
import importlib.machinery
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path

reach_path = sys.argv[1]
cache_dir = Path(sys.argv[2]) / "parallel"
shutil.rmtree(cache_dir, ignore_errors=True)
cache_dir.mkdir(parents=True)
os.environ["REACHABILITY_CACHE_DIR"] = str(cache_dir)

loader = importlib.machinery.SourceFileLoader("reachability_mod", reach_path)
spec = importlib.util.spec_from_loader("reachability_mod", loader)
mod = importlib.util.module_from_spec(spec)
loader.exec_module(mod)

def write_cache(i):
    mod._cache_write("sourcegraph", "parallel_symbol", {
        "status": "ok",
        "hits": [{"repo": f"r{i}", "path": "p.c"}],
        "writer": i,
    })

def write_negative(i):
    mod._negative_cache_write("gh", 403 if i % 2 else 429)

with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
    list(pool.map(write_cache, range(80)))
    list(pool.map(write_negative, range(80)))

payload = json.loads(mod._cache_path("sourcegraph", "parallel_symbol").read_text("utf-8"))
assert payload["status"] == "ok", payload
neg = json.loads(mod._negative_cache_path("gh").read_text("utf-8"))
assert neg["http_status"] in (403, 429), neg
leftovers = list(cache_dir.glob("*.tmp")) + list(cache_dir.glob(".*.tmp"))
assert not leftovers, leftovers
PY
if [ "$?" -eq 0 ]; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "parallel cache writer validation failed"
fi

# ───────────────────────────────────────────────────────────────────
# 5. All backends "unavailable" → reachability_adjust contributes 0
#    (no penalty, no boost). Severity should NOT collapse to Low solely
#    because callers couldn't be probed.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="all backends unavailable → no reachability signal"
DOWN_SYM="all_down_symbol"
DOWN_HASH=$(sha1_short "$DOWN_SYM")
for svc in sourcegraph gh; do
  cat > "$REACHABILITY_MOCK_DIR/${svc}-${DOWN_HASH}.json" <<EOF
{"status": "unavailable", "error": "simulated outage for ${svc}"}
EOF
done
out=$(python3 "$REACH" --symbol "$DOWN_SYM" --json --no-cache 2>&1)
echo "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin)
r = data["reachability"]
assert all(s["status"] == "unavailable" for s in r["services"].values())
assert r["external_callers"] == 0
print("all-down OK")
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "did not handle all-backends-down"

# ───────────────────────────────────────────────────────────────────
# 6. Multi-symbol union: hits from two symbols merge into one count
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="multi-symbol union dedupes by (repo,path)"
SYM2="demo_decode_8"
SYM2_HASH=$(sha1_short "$SYM2")
# Same hit "alice/cool-tool/src/main.c" as demo_decode → should not double-count.
cat > "$REACHABILITY_MOCK_DIR/sourcegraph-${SYM2_HASH}.json" <<'EOF'
{"status": "ok", "hits": [
  {"repo": "alice/cool-tool", "path": "src/main.c"},
  {"repo": "extra-consumer", "path": "src/x.c"}
]}
EOF
cat > "$REACHABILITY_MOCK_DIR/gh-${SYM2_HASH}.json" <<'EOF'
{"status": "unavailable", "error": "n/a"}
EOF
out=$(python3 "$REACH" --symbol demo_decode --symbol "$SYM2" --json --no-cache 2>&1)
echo "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin)
r = data["reachability"]
# demo_decode: 3 hits, demo_decode_8 adds (extra-consumer/src/x.c), shared one collapses.
# So union = 3 + 1 = 4.
assert r["external_callers"] == 4, ("expected 4, got", r["external_callers"])
print("multi-symbol union OK")
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "union miscount"

# ───────────────────────────────────────────────────────────────────
# 7. --report mode: refreshes Severity and adds Reachability section
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="--report mode rewrites Severity + adds Reachability section"
CRASH_DIR="$TEST_TMPDIR/crashes/CRASH-EXAMPLE"
cat > "$CRASH_DIR/report.md" <<'EOF'
# CRASH-EXAMPLE: bounds issue in demo_decode

## Fields

| Field | Value |
| :---- | :---- |
| Severity | Low (12) |
| Surface | library-api |
| Caller contract | obeyed |
| Caller controls | bytes |
| Reproduction rate | 5/5 |

## Summary
Crafted input causes heap-buffer-overflow WRITE of 8 bytes.

## Classification
- **Severity**: Medium
- **Type**: Bounds issue (out-of-range write)
- **Location**: demo.c:42

## Trigger Surface
- Entry: `demo_decode()` → `demo_match()`
- Trigger: Crafted top_bracket field
- Impact: Heap-buffer-overflow WRITE of 8 bytes
- ASan: WRITE of size 8 — attacker-controlled offset, attacker-controlled value
- ASan SCARINESS: 52 (8-byte-write-heap-buffer-overflow-far-from-bounds)

## Reachability Notes
Narrative about which apps load this surface.
EOF
out=$(python3 "$REACH" --report "$CRASH_DIR" --json 2>&1) || \
  fail "$_CURRENT_TEST" "report mode failed: $out"
# reachability.json should be written.
assert_file_exists "$CRASH_DIR/reachability.json" "reachability.json written"
# Severity line should be rewritten to High or Critical (write + attacker-ctrl).
assert_file_contains "$CRASH_DIR/report.md" "^- \*\*Severity\*\*: (Critical|High|Medium|Low|None) \(CVSS(-[A-Z]+)? 4\\.0:" "Severity line rewritten with CVSS v4.0"
assert_file_not_contains "$CRASH_DIR/report.md" '^\| Severity \| Low \(12\)' "structured Severity field is no longer stale"
assert_file_contains "$CRASH_DIR/report.md" '^\| Severity \| (Critical|High|Medium|Low|None) \(CVSS(-[A-Z]+)? 4\.0 [0-9.]+\)' "structured Severity field rewritten"
# Reachability section should be present.
assert_file_contains "$CRASH_DIR/report.md" "^## Reachability — external callers" "auto Reachability section added"
# Original narrative section is preserved (idempotent placement under it).
assert_file_contains "$CRASH_DIR/report.md" "^## Reachability Notes" "narrative section preserved"

# ───────────────────────────────────────────────────────────────────
# 7b. Bundled reports use REPORT.md; --report must accept those too
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="--report accepts bundled REPORT.md"
UPPER_CRASH_DIR="$TEST_TMPDIR/crashes/CRASH-UPPER"
mkdir -p "$UPPER_CRASH_DIR"
cp "$CRASH_DIR/report.md" "$UPPER_CRASH_DIR/REPORT.md"
out=$(python3 "$REACH" --report "$UPPER_CRASH_DIR" --json --no-cache 2>&1) || \
  fail "$_CURRENT_TEST" "REPORT.md mode failed: $out"
assert_file_exists "$UPPER_CRASH_DIR/reachability.json" "reachability.json written for REPORT.md"
assert_file_contains "$UPPER_CRASH_DIR/REPORT.md" "^- \*\*Severity\*\*: (Critical|High|Medium|Low|None) \(CVSS(-[A-Z]+)? 4\\.0:" \
  "REPORT.md Severity line rewritten"

# ───────────────────────────────────────────────────────────────────
# 7c. Reports with no extractable symbols still get reachability.json
#     and a recomputed Severity line instead of failing rc=3.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="--report no-symbol mode writes artifact"
NOSYM_DIR="$TEST_TMPDIR/crashes/CRASH-NOSYM"
mkdir -p "$NOSYM_DIR"
cat > "$NOSYM_DIR/report.md" <<'EOF'
# CRASH-NOSYM
## Classification
- **Severity**: TBD
- **Type**: bounds
## Trigger Surface
Entry: command-line bytes only, no public API call token.
Boundary: maint tool bytes
Caller controls: bytes
Caller contract: obeyed
Trigger source: bytes
EOF
cat > "$NOSYM_DIR/asan.txt" <<'EOF'
==1==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 1
    #0 0x100 in main maint/tool.c:1
EOF
out=$(python3 "$REACH" --report "$NOSYM_DIR" --json --no-cache 2>&1) || \
  fail "$_CURRENT_TEST" "no-symbol report mode failed: $out"
assert_file_exists "$NOSYM_DIR/reachability.json" "no-symbol reachability.json written"
echo "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
assert d["reachability"]["status"] == "no_symbols", d["reachability"]
assert d["reachability"]["external_callers"] == 0
assert "severity" in d
print("no-symbol OK")
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "no-symbol JSON shape bad"

# ───────────────────────────────────────────────────────────────────
# 7d. ASan fallback symbols from dev/test paths are recorded but do not
#     spend backend queries.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="ASan dev-tool fallback skips external search"
LOCALSYM_DIR="$TEST_TMPDIR/crashes/CRASH-LOCALSYM"
mkdir -p "$LOCALSYM_DIR"
cat > "$LOCALSYM_DIR/report.md" <<'EOF'
# CRASH-LOCALSYM
## Classification
- **Severity**: TBD
- **Type**: bounds
## Trigger Surface
Entry: CLI argument processing without a call-shaped API symbol.
Boundary: maint tool bytes
Caller controls: bytes
Caller contract: obeyed
Trigger source: bytes
EOF
cat > "$LOCALSYM_DIR/asan.txt" <<'EOF'
==1==ERROR: AddressSanitizer: stack-buffer-overflow
WRITE of size 1
    #0 0x100 in utf8_tool_main maint/utf8.c:361
    #1 0x200 in main utf8_cli_harness.c:27
EOF
out=$(python3 "$REACH" --report "$LOCALSYM_DIR" --json --no-cache 2>&1) || \
  fail "$_CURRENT_TEST" "local-symbol report mode failed: $out"
echo "$out" | python3 -c '
import json, sys
d = json.load(sys.stdin)
r = d["reachability"]
assert r["status"] == "local_symbols_only", r
assert r["symbols"] == ["utf8_tool_main"], r["symbols"]
assert all(svc["status"] == "not_run" for svc in r["services"].values()), r["services"]
print("local-symbol OK")
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "local-symbol JSON shape bad"

# ───────────────────────────────────────────────────────────────────
# 8. --report mode is idempotent: a second run does not duplicate the section
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="--report mode is idempotent"
python3 "$REACH" --report "$CRASH_DIR" --json >/dev/null 2>&1
n=$(grep -c "^## Reachability — external callers" "$CRASH_DIR/report.md")
assert_eq "1" "$n" "Reachability section appears exactly once after second run"
n_sev=$(grep -c "^- \*\*Severity\*\*:" "$CRASH_DIR/report.md")
assert_eq "1" "$n_sev" "Severity line appears exactly once after second run"

# ───────────────────────────────────────────────────────────────────
# 9. --severity-only re-uses adjacent reachability.json without network
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="--severity-only does not call backends"
# Wipe mocks: any backend call would now fail to read, returning unavailable.
rm -rf "$REACHABILITY_MOCK_DIR"
out=$(python3 "$REACH" --report "$CRASH_DIR" --severity-only --json 2>&1) || \
  fail "$_CURRENT_TEST" "severity-only failed: $out"
echo "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin)
assert "severity" in data
assert data["reachability"]["external_callers"] >= 0
print("severity-only OK")
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "severity-only output bad"
# Restore mocks for subsequent tests.
mkdir -p "$REACHABILITY_MOCK_DIR"

# ───────────────────────────────────────────────────────────────────
# 10. target.toml ignore list is auto-loaded by --report mode
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="--report auto-loads reachability_ignore from target.toml"
# Set up: output/<slug>/target.toml with ignore list, with the crash dir below it.
TGT_DIR="$TEST_TMPDIR/output/demoslug"
TGT_CRASH="$TGT_DIR/results/crashes/CRASH-FROM-TARGET"
mkdir -p "$TGT_CRASH"
cat > "$TGT_DIR/target.toml" <<'EOF'
slug = "demoslug"
upstream_url = "https://example.com/demo"
reachability_ignore = ["demo-vendored", "demo-fork"]
EOF
cat > "$TGT_CRASH/report.md" <<'EOF'
# CRASH-FROM-TARGET: demo
## Classification
- **Severity**: Medium
- **Type**: Bounds (out-of-range read)
- **Location**: demo.c:1
## Trigger Surface
- Entry: `demo_decode()`
- ASan: READ of size 1
EOF
# Re-seed mocks for the symbol bin/reachability will extract.
SYMS_USED=$(python3 "$REACH" --symbol demo_decode --json --no-cache 2>/dev/null | python3 -c '
import json, sys; print(",".join(json.load(sys.stdin)["reachability"]["symbols"]))
')
SYM_HASH=$(sha1_short "demo_decode")
cat > "$REACHABILITY_MOCK_DIR/sourcegraph-${SYM_HASH}.json" <<'EOF'
{"status":"ok","hits":[{"repo":"OtherProject/demo-fork","path":"d.c"},{"repo":"alice/cool","path":"m.c"}]}
EOF
cat > "$REACHABILITY_MOCK_DIR/gh-${SYM_HASH}.json" <<'EOF'
{"status":"unavailable","error":"n/a"}
EOF
out=$(python3 "$REACH" --report "$TGT_CRASH" --json --no-cache 2>&1)
echo "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin)
r = data["reachability"]
# 2 raw hits from sourcegraph, 1 dropped by ignore list, union = 1.
assert r["external_callers"] == 1, ("expected 1, got", r["external_callers"], r["external_caller_hits"])
assert "demo-vendored" in r["ignore"] and "demo-fork" in r["ignore"]
print("target ignore OK")
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "target.toml ignore not applied"

# ───────────────────────────────────────────────────────────────────
# 11. Tightened symbol extraction: identifiers without `(` after them
#     are excluded. Struct fields and bytecode opcodes must NOT be
#     extracted as probable API symbols.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="tightened symbol extraction excludes struct fields and opcodes"
EXTR_DIR="$TEST_TMPDIR/extract-test"
mkdir -p "$EXTR_DIR"
cat > "$EXTR_DIR/report.md" <<'EOF'
# CRASH-EXTRACT: demo
## Summary
Corrupted top_bracket field combined with OP_CBRA causes wild write.

## Classification
- **Severity**: TBD
- **Location**: resolve_entry.c:42

## Trigger Surface
- Entry: `decode_blob()` → `resolve_entry()`
- Trigger: capture group corruption referencing OP_CBRA, OP_KET
- The Fovector array is sized by re->top_bracket and start_subject.

## Data Flow Trace
decode_blob (decode_blob.c:204) →
  match() reaches OP_CBRA with corrupted top_bracket = 0x7FFF →
  Fovector[65532] = ...
EOF
# Seed mocks for the symbols we EXPECT to be extracted (the call-shape ones).
for sym in decode_blob resolve_entry; do
  h=$(sha1_short "$sym")
  cat > "$REACHABILITY_MOCK_DIR/sourcegraph-${h}.json" <<EOF
{"status":"ok","hits":[{"repo":"demo-consumer","path":"src/use_${sym}.c"}]}
EOF
  cat > "$REACHABILITY_MOCK_DIR/gh-${h}.json" <<'EOF'
{"status":"unavailable","error":"n/a"}
EOF
done
# If extraction were too liberal it would also probe OP_CBRA/OP_KET/top_bracket/start_subject.
# Verify the symbols list contains ONLY call-shape identifiers.
out=$(python3 "$REACH" --report "$EXTR_DIR" --json --no-cache 2>&1)
echo "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin)
syms = data["reachability"]["symbols"]
forbidden = {"OP_CBRA", "OP_KET", "top_bracket", "start_subject", "Fovector"}
bad = [s for s in syms if s in forbidden]
assert not bad, ("forbidden non-call symbols extracted:", bad, "from", syms)
assert "decode_blob" in syms or "resolve_entry" in syms, syms
print("symbol extraction OK; got:", syms)
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "symbol extraction picked non-call identifiers"

# ───────────────────────────────────────────────────────────────────
# 11a. Macro-shaped call tokens in report prose are not external API
#      symbols. If they are the only call-shaped report tokens, fall back to
#      the primary ASan stack.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="symbol extraction ignores macro call tokens"
MACRO_DIR="$TEST_TMPDIR/macro-token-test"
mkdir -p "$MACRO_DIR"
cat > "$MACRO_DIR/report.md" <<'EOF'
# CRASH-MACRO-TOKEN
Root Cause: product code invokes `FD_SET(conn->fd, read_fds)` without a guard.
EOF
cat > "$MACRO_DIR/asan.txt" <<'EOF'
==1==ERROR: AddressSanitizer: heap-buffer-overflow
READ of size 4
    #0 0x100 in ares_fds ares_fds.c:65
    #1 0x200 in main harness.c:221
EOF
out=$(python3 "$REACH" --report "$MACRO_DIR" --json --no-cache 2>&1) || \
  fail "$_CURRENT_TEST" "macro-token report mode failed: $out"
echo "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin)
syms = data["reachability"]["symbols"]
assert "FD_SET" not in syms, syms
assert syms == ["ares_fds"], syms
print("macro token extraction OK; got:", syms)
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "macro token leaked into symbols"

# ───────────────────────────────────────────────────────────────────
# 11b. Sanitizer runtime frames in report snippets must not become
#      reachability symbols. If the narrative has no call-shaped public API
#      token, fall back to the adjacent ASan file and query the deepest
#      primary-stack product frame.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="symbol extraction ignores asan runtime frames"
ASANFRAME_DIR="$TEST_TMPDIR/asan-frame-test"
mkdir -p "$ASANFRAME_DIR"
cat > "$ASANFRAME_DIR/report.md" <<'EOF'
# CRASH-ASAN-FRAME
Summary: internal wait frame reaches AddressSanitizer.

## Expected sanitizer output
```
==1==ERROR: AddressSanitizer: stack-buffer-overflow
    #0 0x100 in ares_evsys_select_wait ares_event_select.c:98
    #1 0x200 in ares_event_thread ares_event_thread.c:353
    #2 0x300 in asan_thread_start(void*)+0x4c (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3dd64)
```
EOF
cat > "$ASANFRAME_DIR/asan.txt" <<'EOF'
==1==ERROR: AddressSanitizer: stack-buffer-overflow
READ of size 4
    #0 0x100 in ares_evsys_select_wait ares_event_select.c:98
    #1 0x200 in ares_event_thread ares_event_thread.c:353
    #2 0x300 in asan_thread_start(void*)+0x4c (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3dd64)
    #3 0x400 in _pthread_start+0x84 (libsystem_pthread.dylib:arm64e+0x6c54)

Thread T1 created by T0 here:
    #0 0x500 in pthread_create+0x60 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x39198)
    #1 0x600 in ares_thread_create ares_threads.c:601
EOF
out=$(python3 "$REACH" --report "$ASANFRAME_DIR" --json --no-cache 2>&1) || \
  fail "$_CURRENT_TEST" "asan-frame report mode failed: $out"
echo "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin)
syms = data["reachability"]["symbols"]
assert "asan_thread_start" not in syms, syms
assert "ares_thread_create" not in syms, syms
assert syms == ["ares_event_thread"], syms
print("asan frame extraction OK; got:", syms)
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "asan runtime frame leaked into symbols"

# ───────────────────────────────────────────────────────────────────
# 11b-cpp. Entrypoint-first: when a sanitizer stack is present, caller
#      popularity is probed at one caller-entry symbol from the primary fault
#      stack, not at narrative helpers or scoring labels. For a C++ crash the
#      probe keeps one qualifier level (Engine::apply_line), so common method
#      names do not collide across unrelated projects.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="entrypoint-first: C++ frame, no prose helpers, no scoring labels"
CPPSTATE_DIR="$TEST_TMPDIR/cpp-crash-state"
mkdir -p "$CPPSTATE_DIR"
cat > "$CPPSTATE_DIR/report.md" <<'EOF'
# CRASH-CPP-STATE: heap overflow in sampledb
## Classification
- **Severity**: Medium (CVSS-BTE 4.0: 5.3 Medium; primitive=heap WRITE; surface=cli_production)
## Data Flow
- step2: apply_line dispatches blob, calls `decode_hex(fields[2])` and `parse_id(fields[1])`
- step4: assign computes `frame_capacity(bytes.size())` truncated to uint16_t
EOF
cat > "$CPPSTATE_DIR/sanitizer.txt" <<'EOF'
==1==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 1
    #0 0x100 in sampledb::Engine::Store::set_blob(unsigned int, std::__1::vector<unsigned char>) sampledb.cpp:213
    #1 0x200 in sampledb::Engine::apply_line(std::__1::basic_string<char> const&) sampledb.cpp:367
    #2 0x300 in sampledb::Engine::run(std::__1::basic_istream<char>&) sampledb.cpp:342
    #3 0x400 in main main.cpp:13
EOF
out=$(python3 "$REACH" --report "$CPPSTATE_DIR" --json --no-cache 2>&1) || \
  fail "$_CURRENT_TEST" "cpp entrypoint report mode failed: $out"
echo "$out" | python3 -c '
import json, sys
syms = json.load(sys.stdin)["reachability"]["symbols"]
# Caller popularity probes the deepest usable primary-stack entry symbol.
assert syms == ["Engine::apply_line"], syms
# Self-poisoned scoring label and Data-Flow helper names never get probed.
forbidden = {"cli_production", "decode_hex", "parse_id", "frame_capacity",
             "set_blob", "Store::set_blob"}
bad = [s for s in syms if s in forbidden]
assert not bad, ("non-entrypoint symbol probed:", bad, "from", syms)
print("cpp entrypoint extraction OK; got:", syms)
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "cpp entrypoint symbols wrong"

# ───────────────────────────────────────────────────────────────────
# 11b-entry. Entrypoint popularity: external callers are counted at the
#      PUBLIC entry point (the deepest primary-stack product frame), any-frame. A real
#      dependant calls the entry point only — it never contains the target's
#      internal frames above it. The entry may be deeper than the top-three
#      crash-state window used for deduplication.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="entrypoint: callers of the public entry count"
ENTRY_DIR="$TEST_TMPDIR/entrypoint"
mkdir -p "$ENTRY_DIR"
cat > "$ENTRY_DIR/report.md" <<'EOF'
# CRASH-ENTRY
## Summary
heap overflow in sampledb
EOF
# #0-#2 are internal frames, #3 is the public API the harness called into,
# #4 is the harness (filtered). The entry point is deeper than the capped
# ClusterFuzz crash-state window.
cat > "$ENTRY_DIR/sanitizer.txt" <<'EOF'
==1==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 1
    #0 0x100 in sampledb::Engine::set_blob(unsigned int) sampledb.cpp:213
    #1 0x150 in sampledb::Engine::apply_line(char const*) sampledb.cpp:300
    #2 0x180 in sampledb::Engine::decode_inner(char const*) internal.cpp:318
    #3 0x200 in sampledb::Engine::public_decode(char const*) api.cpp:42
    #4 0x300 in LLVMFuzzerTestOneInput harness.cpp:13
EOF
# downstream-app calls ONLY public_decode. Internal frames are not queried.
PD_HASH=$(sha1_short "Engine::public_decode")
cat > "$REACHABILITY_MOCK_DIR/sourcegraph-${PD_HASH}.json" <<'EOF'
{"status":"ok","hits":[{"repo":"downstream-app","path":"src/main.cpp"}]}
EOF
echo '{"status":"unavailable","error":"n/a"}' > "$REACHABILITY_MOCK_DIR/gh-${PD_HASH}.json"
out=$(python3 "$REACH" --report "$ENTRY_DIR" --json --no-cache 2>&1) || \
  fail "$_CURRENT_TEST" "entrypoint report mode failed: $out"
echo "$out" | python3 -c '
import json, sys
r = json.load(sys.stdin)["reachability"]
assert r["match_mode"] == "entrypoint", r["match_mode"]
assert r["entry_symbol"] == "Engine::public_decode", r["entry_symbol"]
# The public-API caller counts even though it lacks the internal chain.
repos = sorted({h["repo"] for h in r["external_caller_hits"]})
assert repos == ["downstream-app"], ("expected [downstream-app], got", repos)
assert r["external_callers"] == 1, ("expected 1, got", r["external_callers"])
print("entrypoint popularity OK")
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "entrypoint popularity miscounted"

# ───────────────────────────────────────────────────────────────────
# 11b-uaf. UAF reports contain secondary context stacks ("freed by",
#      "previously allocated by"). Caller popularity must use the primary
#      fault stack, not the cleanup/allocation context.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="entrypoint: UAF freed-by context is not the caller entry"
UAFENTRY_DIR="$TEST_TMPDIR/uaf-entrypoint"
mkdir -p "$UAFENTRY_DIR"
cat > "$UAFENTRY_DIR/report.md" <<'EOF'
# CRASH-UAF-ENTRY
## Summary
UAF write after a stale object link.
EOF
cat > "$UAFENTRY_DIR/sanitizer.txt" <<'EOF'
==1==ERROR: AddressSanitizer: heap-use-after-free
WRITE of size 8
    #0 0x100 in samplelib_add_number samplelib.c:2201
    #1 0x200 in main harness.c:93

freed by thread T0 here:
    #0 0x300 in free sanitizer_malloc.cpp:52
    #1 0x400 in samplelib_delete samplelib.c:273
    #2 0x500 in main harness.c:92

previously allocated by thread T0 here:
    #0 0x600 in malloc sanitizer_malloc.cpp:30
    #1 0x700 in samplelib_parse samplelib.c:1172
    #2 0x800 in main harness.c:84

SUMMARY: AddressSanitizer: heap-use-after-free samplelib.c:2201 in samplelib_add_number
EOF
ADD_HASH=$(sha1_short "samplelib_add_number")
cat > "$REACHABILITY_MOCK_DIR/sourcegraph-${ADD_HASH}.json" <<'EOF'
{"status":"ok","hits":[{"repo":"primary-caller","path":"src/use_samplelib.c"}]}
EOF
echo '{"status":"unavailable","error":"n/a"}' > "$REACHABILITY_MOCK_DIR/gh-${ADD_HASH}.json"
out=$(python3 "$REACH" --report "$UAFENTRY_DIR" --json --no-cache 2>&1) || \
  fail "$_CURRENT_TEST" "uaf entrypoint report mode failed: $out"
echo "$out" | python3 -c '
import json, sys
r = json.load(sys.stdin)["reachability"]
assert r["match_mode"] == "entrypoint", r["match_mode"]
assert r["entry_symbol"] == "samplelib_add_number", r["entry_symbol"]
assert r["symbols"] == ["samplelib_add_number"], r["symbols"]
repos = sorted({h["repo"] for h in r["external_caller_hits"]})
assert repos == ["primary-caller"], ("expected primary-caller, got", repos)
print("uaf primary-stack entrypoint OK")
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "uaf entrypoint miscounted"

# ───────────────────────────────────────────────────────────────────
# 11b-sanitizer. The entry parser is sanitizer-family agnostic as long as
#      the report carries symbolized #N frames (TSan/MSan/UBSan-style stacks).
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="entrypoint: non-ASan sanitizer stack uses primary frames"
SANENTRY_DIR="$TEST_TMPDIR/sanitizer-entrypoint"
mkdir -p "$SANENTRY_DIR"
cat > "$SANENTRY_DIR/report.md" <<'EOF'
# CRASH-SAN-ENTRY
## Summary
Thread sanitizer report with a public processing entry.
EOF
cat > "$SANENTRY_DIR/sanitizer.txt" <<'EOF'
WARNING: ThreadSanitizer: data race
  Write of size 4 at 0x1234 by thread T1:
    #0 0x100 in samplelib_store samplelib.c:87
    #1 0x200 in samplelib_public_process samplelib.c:205
    #2 0x300 in main harness.c:41

  Thread T1 created by main thread at:
    #0 0x400 in pthread_create tsan_interceptors.cpp:100
    #1 0x500 in samplelib_spawn samplelib.c:55
EOF
PROC_HASH=$(sha1_short "samplelib_public_process")
cat > "$REACHABILITY_MOCK_DIR/sourcegraph-${PROC_HASH}.json" <<'EOF'
{"status":"ok","hits":[{"repo":"tsan-caller","path":"src/process.c"}]}
EOF
echo '{"status":"unavailable","error":"n/a"}' > "$REACHABILITY_MOCK_DIR/gh-${PROC_HASH}.json"
out=$(python3 "$REACH" --report "$SANENTRY_DIR" --json --no-cache 2>&1) || \
  fail "$_CURRENT_TEST" "sanitizer entrypoint report mode failed: $out"
echo "$out" | python3 -c '
import json, sys
r = json.load(sys.stdin)["reachability"]
assert r["entry_symbol"] == "samplelib_public_process", r["entry_symbol"]
assert r["symbols"] == ["samplelib_public_process"], r["symbols"]
repos = sorted({h["repo"] for h in r["external_caller_hits"]})
assert repos == ["tsan-caller"], ("expected tsan-caller, got", repos)
print("non-ASan sanitizer entrypoint OK")
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "non-ASan sanitizer entrypoint wrong"

# ───────────────────────────────────────────────────────────────────
# 11c. Symbol extraction also accepts lowerCamelCase (libxml2 / htmllib /
#      Win32-style entry points). read_line-shaped names have no
#      underscore but ARE library APIs with external callers. Plain
#      lowercase identifiers (usershell, malloc) and StartsWithUpper
#      tokens (SomeClass) must still be rejected to keep probe noise
#      down.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="symbol extraction accepts lowerCamelCase (libxml2-style)"
CAMEL_DIR="$TEST_TMPDIR/camel-test"
mkdir -p "$CAMEL_DIR"
cat > "$CAMEL_DIR/report.md" <<'EOF'
# CRASH-CAMEL: libxml2 stack overflow demo
## Classification
- **Severity**: TBD
- **Location**: xmlcatalog.c:usershell
## Trigger Surface
- Entry: `read_line()` → `usershell()` → `convert_entry()`
- Trigger: oversized stdin line; `scan_table()` walks past end.
- Reference to SomeClass and FOO_MACRO in narrative; ignore both.
## Data Flow
convert_catalog() invokes the parser then hands off to malloc().
EOF
# Seed mocks for the lowerCamelCase symbols we EXPECT to be extracted.
for sym in read_line convert_entry scan_table convert_catalog; do
  h=$(sha1_short "$sym")
  cat > "$REACHABILITY_MOCK_DIR/sourcegraph-${h}.json" <<EOF
{"status":"ok","hits":[{"repo":"demo-libxml-consumer","path":"src/use_${sym}.c"}]}
EOF
  cat > "$REACHABILITY_MOCK_DIR/gh-${h}.json" <<'EOF'
{"status":"unavailable","error":"n/a"}
EOF
done
out=$(python3 "$REACH" --report "$CAMEL_DIR" --json --no-cache 2>&1)
echo "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin)
syms = data["reachability"]["symbols"]
# At least one of the libxml2-style symbols must come through.
expected_any = {"read_line", "convert_entry",
                "scan_table", "convert_catalog"}
got = expected_any & set(syms)
assert got, ("no lowerCamelCase symbols extracted:", syms)
# Plain lowercase (usershell, malloc) and StartsWithUpper (SomeClass,
# FOO_MACRO is uppercase-leading despite the underscore — but FOO_MACRO
# does match the snake_case branch, so we expect it could be extracted
# IF it appeared with a trailing "(". It does not in this fixture.)
forbidden = {"usershell", "malloc", "SomeClass"}
bad = [s for s in syms if s in forbidden]
assert not bad, ("non-library identifiers extracted:", bad, "from", syms)
print("camelCase extraction OK; got:", sorted(got))
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "camelCase extraction failed"

# ───────────────────────────────────────────────────────────────────
# 12. Sourcegraph schema mismatch → backend marked unavailable
#     (NOT silently reported as 0 hits, which would penalize severity).
#     A 200 with no SSE event frames at all (e.g. a HTML challenge page)
#     is the canonical "drift" we need to detect.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="sourcegraph schema mismatch is unavailable, not 0 hits"
cat > "$TEST_TMPDIR/parser_test.py" <<PY
import importlib.util, os, sys
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("reach", "$REACH")
spec = importlib.util.spec_from_loader("reach", loader)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
def fake_http(url, timeout, accept="application/json"):
    # 200 OK but the body is plain HTML — no event:/data: lines anywhere.
    # query_sourcegraph must NOT report this as "ok with 0 hits".
    return 200, "<html><body>nothing here</body></html>"
m._http_with_retry = fake_http
os.environ.pop("REACHABILITY_MOCK_DIR", None)
r = m.query_sourcegraph("schema_drift_demo", 5.0)
assert r["status"] == "unavailable", ("expected unavailable, got", r)
assert "schema mismatch" in r["error"], r
print("sourcegraph schema-mismatch OK")
PY
out=$(python3 "$TEST_TMPDIR/parser_test.py" 2>&1)
[ $? -eq 0 ] && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "$out"

# ───────────────────────────────────────────────────────────────────
# 12b. Sourcegraph SSE parser: well-formed stream with no `matches` event
#      is a legitimate "0 hits" answer (Sourcegraph emits progress + done
#      even when matchCount is 0), so query_sourcegraph must return ok.
#      Also exercises the matches frame: repository + path are extracted
#      and deduped.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="sourcegraph SSE parser handles matches and 0-hit streams"
cat > "$TEST_TMPDIR/sg_parser_test.py" <<PY
import importlib.util, os
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("reach", "$REACH")
spec = importlib.util.spec_from_loader("reach", loader)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
os.environ.pop("REACHABILITY_MOCK_DIR", None)

# 1. Well-formed stream with two content matches (one duplicated by repo+path).
stream_with_matches = (
    "event: filters\n"
    "data: []\n"
    "\n"
    "event: matches\n"
    'data: [{"type":"content","repository":"github.com/a/b","path":"src/x.c"},'
        '{"type":"content","repository":"github.com/c/d","path":"src/y.c"}]\n'
    "\n"
    "event: matches\n"
    'data: [{"type":"content","repository":"github.com/a/b","path":"src/x.c"}]\n'
    "\n"
    "event: progress\n"
    'data: {"done":true,"matchCount":3}\n'
    "\n"
    "event: done\n"
    "data: {}\n"
    "\n"
)
def fake_http_matches(url, timeout, accept="application/json"):
    return 200, stream_with_matches
m._http_with_retry = fake_http_matches
r = m.query_sourcegraph("demo_with_matches", 5.0)
assert r["status"] == "ok", r
hit_keys = sorted((h["repo"], h["path"]) for h in r["hits"])
assert hit_keys == [("github.com/a/b", "src/x.c"), ("github.com/c/d", "src/y.c")], hit_keys

# 2. Well-formed stream with progress+done but no matches event.
stream_zero = (
    "event: filters\n"
    "data: []\n"
    "\n"
    "event: progress\n"
    'data: {"done":true,"matchCount":0}\n'
    "\n"
    "event: done\n"
    "data: {}\n"
    "\n"
)
def fake_http_zero(url, timeout, accept="application/json"):
    return 200, stream_zero
m._http_with_retry = fake_http_zero
r = m.query_sourcegraph("demo_zero", 5.0)
assert r["status"] == "ok" and r["hits"] == [], r
print("sourcegraph SSE parser OK")
PY
out=$(python3 "$TEST_TMPDIR/sg_parser_test.py" 2>&1)
[ $? -eq 0 ] && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "$out"

# ───────────────────────────────────────────────────────────────────
# 13. Retry status set covers 429/502/503/504; 403/429 enter cooldown
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="retry and cooldown status sets are correct"
cat > "$TEST_TMPDIR/retry_const_test.py" <<PY
import importlib.util, sys
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("reach", "$REACH")
spec = importlib.util.spec_from_loader("reach", loader)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
expected = {429, 502, 503, 504}
got = set(m.RETRY_STATUS)
assert got == expected, (got, expected)
assert 403 not in got, "403 must NOT be in retry set (auth/secondary-rate ambiguity)"
assert set(m.NEGATIVE_CACHE_STATUS) == {403, 429}, m.NEGATIVE_CACHE_STATUS
print("retry status OK")
PY
out=$(python3 "$TEST_TMPDIR/retry_const_test.py" 2>&1)
[ $? -eq 0 ] && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "$out"

# ───────────────────────────────────────────────────────────────────
# 13b. _http_with_retry actually retries on RETRY_STATUS exactly once.
#      Verifies: 503 → second HTTP call + one sleep. 200 → no retry.
#      Stub the inner getter and time.sleep to count interactions.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="_http_with_retry retries once on 503 and not on 200"
cat > "$TEST_TMPDIR/retry_behavior_test.py" <<PY
import importlib.util, sys
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("reach", "$REACH")
spec = importlib.util.spec_from_loader("reach", loader)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

calls = {"http": 0, "sleep": 0}
def fake_sleep(s): calls["sleep"] += 1
m.time.sleep = fake_sleep

def make_http(status):
    def f(url, timeout, accept="application/json"):
        calls["http"] += 1
        return status, None
    return f

# 503 → retry path: 2 fetches, 1 sleep.
m._http_get = make_http(503)
calls["http"] = calls["sleep"] = 0
m._http_with_retry("http://x", 1.0)
assert calls["http"] == 2 and calls["sleep"] == 1, ("503 retry counts", calls)

# 200 → no retry: 1 fetch, 0 sleeps.
m._http_get = make_http(200)
calls["http"] = calls["sleep"] = 0
m._http_with_retry("http://x", 1.0)
assert calls["http"] == 1 and calls["sleep"] == 0, ("200 retry counts", calls)

# 403 (deliberately excluded from RETRY_STATUS) → no retry.
m._http_get = make_http(403)
calls["http"] = calls["sleep"] = 0
m._http_with_retry("http://x", 1.0)
assert calls["http"] == 1 and calls["sleep"] == 0, ("403 retry counts (must NOT retry)", calls)

print("retry behavior OK")
PY
out=$(python3 "$TEST_TMPDIR/retry_behavior_test.py" 2>&1)
[ $? -eq 0 ] && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "$out"

# ───────────────────────────────────────────────────────────────────
# 13c. Sourcegraph 403 creates a short backend cooldown so a follow-up
#      symbol probe in the same run skips the HTTP call. Also verifies
#      query_sourcegraph requests Accept: text/event-stream and includes
#      the lang:c filter + count cap in the URL.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="sourcegraph SSE accept + 403 cooldown"
cat > "$TEST_TMPDIR/sg_cooldown_test.py" <<PY
import importlib.util, os, shutil, urllib.parse
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("reach", "$REACH")
spec = importlib.util.spec_from_loader("reach", loader)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

cache_dir = "$TEST_TMPDIR/neg-cache-sg"
shutil.rmtree(cache_dir, ignore_errors=True)
os.environ.pop("REACHABILITY_MOCK_DIR", None)
os.environ["REACHABILITY_CACHE_DIR"] = cache_dir
os.environ["REACHABILITY_NEGATIVE_TTL_SECS"] = "300"

calls = {"http": 0}
seen = []
def fake_http(url, timeout, accept="application/json"):
    calls["http"] += 1
    seen.append((url, accept))
    return 403, None
m._http_get = fake_http

r1 = m._query_one("sourcegraph", "demo_first_symbol", 1.0, True)
assert r1["status"] == "unavailable" and r1.get("http_status") == 403, r1
url0, accept0 = seen[0]
assert accept0 == "text/event-stream", accept0
qs = urllib.parse.parse_qs(urllib.parse.urlparse(url0).query)
q = (qs.get("q") or [""])[0]
assert "lang:c" in q, q
assert "count:" in q, q

r2 = m._query_one("sourcegraph", "demo_second_symbol", 1.0, True)
assert calls["http"] == 1, ("cooldown should avoid second HTTP call", calls, r2)
assert "cooldown" in r2["error"], r2
print("sourcegraph cooldown OK")
PY
out=$(python3 "$TEST_TMPDIR/sg_cooldown_test.py" 2>&1)
[ $? -eq 0 ] && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "$out"

# ───────────────────────────────────────────────────────────────────
# 13d. Language-aware search: the lang filter is derived from the target
#      tree's majority source extension (lib/languages.py registry), the
#      backends honour it, and an empty language disables the filter.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="language filter derived from target tree + applied to query"
# Quoted heredoc: the body is literal (REACH/TEST_TMPDIR arrive via env), so
# backticks in comments are not run as shell command substitutions.
cat > "$TEST_TMPDIR/lang_filter_test.py" <<'PY'
import importlib.util, os, urllib.parse
from pathlib import Path
from importlib.machinery import SourceFileLoader
TMP = Path(os.environ["TEST_TMPDIR"])
loader = SourceFileLoader("reach", os.environ["REACH"])
spec = importlib.util.spec_from_loader("reach", loader)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

# Majority-extension detection: a JS tree maps to javascript, a C tree to c,
# a C++ tree to the linguist token c++, and an empty/missing root falls back
# to c (the historical default).
root = TMP / "langdet"
for rel in ("a/index.js", "a/util.js", "a/x.test.js", "README.md"):
    p = root / "js" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x\n")
for rel in ("src/core.cc", "src/core.hh", "include/api.hpp"):
    p = root / "cxx" / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("x\n")
assert m._detect_target_language(root / "js") == "javascript"
assert m._detect_target_language(root / "cxx") == "c++"
assert m._detect_target_language(root / "missing") == "c"
assert m._detect_target_language(None) == "c"

# Header-neutral C-vs-C++ vote: a C++ lib that is mostly headers and a few .cc
# files must still detect as c++ (headers do not decide the language).
hh = TMP / "hdrlib"
(hh / "include").mkdir(parents=True, exist_ok=True)
for i in range(20):
    (hh / "include" / f"h{i}.h").write_text("//\n")
for i in range(3):
    (hh / f"impl{i}.cc").write_text("//\n")
assert m._detect_target_language(hh) == "c++", "header-heavy C++ tree must stay c++"

# Vendored/dependency subtrees are skipped: a Go service with a large
# third_party/native/*.c blob must not be detected as C.
gv = TMP / "go-vendored"
(gv / "third_party" / "native").mkdir(parents=True, exist_ok=True)
for i in range(3):
    (gv / f"m{i}.go").write_text("package main\n")
for i in range(20):
    (gv / "third_party" / "native" / f"c{i}.c").write_text("int x;\n")
assert m._detect_target_language(gv) == "go", "vendored C must not flip a Go target to c"

# Structured build_system token outranks file counting for non-native
# languages, and a native 'c' declaration still defers to the C/C++ vote.
assert m._detect_target_language(gv, "rust") == "rust", "declared rust wins"
assert m._detect_target_language(hh, "c") == "c++", "native 'c' declaration still votes c++"

# Regression: a target tree under a `build`-named ancestor (or a tmpdir whose
# name merely contains "build") must NOT collapse to "c". The earlier
# absolute-substring skip ("/build" in str(path)) discarded every file and
# fell back to c, which also disabled PascalCase Go-symbol probing.
buildy = TMP / "build_run01" / "go-svc"
buildy.mkdir(parents=True, exist_ok=True)
for fn in ("main.go", "parse.go", "handler.go"):
    (buildy / fn).write_text("package main\n")
assert m._detect_target_language(buildy) == "go", \
    "language collapsed to c under a build-named ancestor"
# A genuine generated subdir IS still skipped (relative parts), so a Go tree
# with a big vendored C blob under build/ stays go.
(buildy / "build").mkdir(exist_ok=True)
for i in range(5):
    (buildy / "build" / f"gen{i}.c").write_text("int x;\n")
assert m._detect_target_language(buildy) == "go", \
    "generated build/ subdir should be skipped, not counted"

# The Sourcegraph query carries the derived lang filter; empty disables it.
os.environ.pop("REACHABILITY_MOCK_DIR", None)
os.environ["REACHABILITY_CACHE_DIR"] = str(TMP / "lang-cache")
seen = []
def fake_http(url, timeout, accept="application/json"):
    seen.append(url)
    return 500, None  # availability is irrelevant; we only check the URL
m._http_get = fake_http
m.BACKOFF_SECS = 0.0
m.query_sourcegraph("demo_lang_sym", 1.0, "go")
q = urllib.parse.parse_qs(urllib.parse.urlparse(seen[-1]).query)["q"][0]
assert "lang:go" in q, q
m.query_sourcegraph("demo_lang_sym", 1.0, "")
q = urllib.parse.parse_qs(urllib.parse.urlparse(seen[-1]).query)["q"][0]
assert "lang:" not in q, q

# Cache keys are language-scoped: same symbol, different language, different file.
assert m._cache_path("sourcegraph", "demo_lang_sym", "c") != \
       m._cache_path("sourcegraph", "demo_lang_sym", "go")

# Symbol shapes are language-aware. PascalCase is a public-function convention
# for Go/Java/Kotlin/Swift/JS/TS, so those accept it; C/C++ reject it (type
# names), and Rust/Python reject it too (there PascalCase is a type/class, not
# a callable). snake_case / lowerCamel stay valid everywhere. ALL_CAPS macros
# stay rejected.
line = "- Entry: `ParseDocument()` calls `decodeChunk()` then `FREE_LIST()`"
assert m._extract_symbols_from_report(line, "go") == ["ParseDocument", "decodeChunk"]
assert m._extract_symbols_from_report(line, "c") == ["decodeChunk"]
for lang in ("go", "java", "kotlin", "swift", "javascript", "typescript"):
    assert m._symbol_shape_ok("NewDecoder", lang), lang
for lang in ("c", "c++", "rust", "python", "php", "ruby"):
    assert not m._symbol_shape_ok("NewDecoder", lang), lang
assert m._symbol_shape_ok("pcre2_match", "c")
assert m._symbol_shape_ok("parse_doc", "rust")  # snake_case still ok for rust
print("language filter OK")
PY
out=$(REACH="$REACH" TEST_TMPDIR="$TEST_TMPDIR" python3 "$TEST_TMPDIR/lang_filter_test.py" 2>&1)
[ $? -eq 0 ] && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "$out"

# ───────────────────────────────────────────────────────────────────
# 15. --batch mode walks crashes/CRASH-*/ and produces a summary table
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="--batch mode summarises every crash dir under <results>/crashes/"
BATCH_RESULTS="$TEST_TMPDIR/batch-results"
mkdir -p "$BATCH_RESULTS/crashes/CRASH-A" "$BATCH_RESULTS/crashes/CRASH-B"
for cdir in "$BATCH_RESULTS/crashes/CRASH-A" "$BATCH_RESULTS/crashes/CRASH-B"; do
  cat > "$cdir/report.md" <<'EOF'
# CRASH: demo
## Classification
- **Severity**: TBD
## Trigger Surface
- Entry: `demo_batch_decode()`
- WRITE of size 8 — caller-controlled offset.
EOF
done
# Mock backends for the symbol that will be auto-extracted.
H_BATCH=$(sha1_short "demo_batch_decode")
cat > "$REACHABILITY_MOCK_DIR/sourcegraph-${H_BATCH}.json" <<'EOF'
{"status":"ok","hits":[{"repo":"consumer","path":"src/x.c"}]}
EOF
cat > "$REACHABILITY_MOCK_DIR/gh-${H_BATCH}.json" <<'EOF'
{"status":"unavailable","error":"n/a"}
EOF
out=$(python3 "$REACH" --batch "$BATCH_RESULTS" --no-cache 2>&1)
assert_match "Reachability batch summary" "$out" "batch summary header present"
assert_match "CRASH-A" "$out" "CRASH-A in batch summary"
assert_match "CRASH-B" "$out" "CRASH-B in batch summary"
# Each crash dir got reachability.json written.
assert_file_exists "$BATCH_RESULTS/crashes/CRASH-A/reachability.json" "batch wrote CRASH-A/reachability.json"
assert_file_exists "$BATCH_RESULTS/crashes/CRASH-B/reachability.json" "batch wrote CRASH-B/reachability.json"

# ───────────────────────────────────────────────────────────────────
# 16. Cache freshness is mtime-based, not date-suffix-based:
#     a stale cache file (mtime older than the 7-day TTL) is ignored.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="cache TTL is mtime-based"
SYM_TTL="ttl_demo"
H_TTL=$(sha1_short "$SYM_TTL")
cat > "$REACHABILITY_MOCK_DIR/sourcegraph-${H_TTL}.json" <<'EOF'
{"status":"ok","hits":[{"repo":"fresh-hit","path":"src/x.c"}]}
EOF
cat > "$REACHABILITY_MOCK_DIR/gh-${H_TTL}.json" <<'EOF'
{"status":"unavailable","error":"n/a"}
EOF
# Pre-populate cache with a stale entry (different content).
cache_stale="$REACHABILITY_CACHE_DIR/sourcegraph-${H_TTL}.json"
cat > "$cache_stale" <<'EOF'
{"status":"ok","hits":[{"repo":"STALE-CACHE","path":"src/old.c"}]}
EOF
# Touch it 8 days into the past (past the 7-day TTL).
touch -t "$(date -v-8d +%Y%m%d%H%M 2>/dev/null || date -d '8 days ago' +%Y%m%d%H%M)" "$cache_stale"
out=$(python3 "$REACH" --symbol "$SYM_TTL" --json 2>&1)
echo "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin)
hits = data["reachability"]["services"]["sourcegraph"]["hits"]
assert any(h.get("repo") == "fresh-hit" for h in hits), ("stale cache returned, should be expired", hits)
assert not any(h.get("repo") == "STALE-CACHE" for h in hits), ("stale cache leaked through", hits)
print("mtime TTL OK")
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "stale cache leaked"

# ───────────────────────────────────────────────────────────────────
# 16b. Vendored-copy classifier separates re-included sources from genuine
#      callers. Two bucket criteria cover both common cases:
#        * vendored prefix path segment (third_party/, vendor/, contrib/, …)
#        * upstream filename + a directory segment naming the audited
#          project (e.g. somerepo/libxml2/xmlschemas.c). The project name
#          is derived at runtime — no hardcoded per-project list — so a
#          version-suffixed dir (libxml2-2.9.14) matches too, while a bare
#          filename collision with NO project segment stays genuine.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="vendored copies are bucketed separately from genuine callers"
cat > "$TEST_TMPDIR/vendored_test.py" <<PY
import importlib.util
from importlib.machinery import SourceFileLoader
loader = SourceFileLoader("reach", "$REACH")
spec = importlib.util.spec_from_loader("reach", loader)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)

# Project-name variants: bare name + version-stripped form. A trailing
# digit that is part of the name itself (pcre2) is preserved.
nv = m._target_name_variants("libxml2-2.9.14")
assert nv == {"libxml2-2.9.14", "libxml2"}, nv
assert m._target_name_variants("pcre2") == {"pcre2"}, m._target_name_variants("pcre2")

basenames = {"pcre2_substring.c", "xmlschemas.c"}
target_names = {"libxml2"}
hits = [
    # Genuine callers — keep:
    {"repo": "real-consumer", "path": "src/regex_glue.c"},
    {"repo": "another-consumer", "path": "lib/wrapper.cpp"},
    # Genuine: basename collides with a target file but NO directory
    # segment names the project — a real consumer that happens to ship a
    # file called xmlschemas.c. Must stay in the genuine bucket.
    {"repo": "name-collision", "path": "src/xmlschemas.c"},
    # Vendored: well-known vendoring prefix segments.
    {"repo": "BigApp/foo", "path": "third_party/pcre2/src/pcre2_substring.c"},
    {"repo": "OtherApp/bar", "path": "vendor/pcre2/src/pcre2_substring.c"},
    {"repo": "Yet/another", "path": "contrib/poco/Foundation/src/pcre2_substring.c"},
    # Vendored: upstream filename + a segment naming the audited project,
    # with no vendoring-prefix dir — only the project-name match catches it.
    {"repo": "someport", "path": "libxml2/xmlschemas.c"},
    # Vendored: version-suffixed project directory.
    {"repo": "distro", "path": "pkgs/libxml2-2.9.14/xmlschemas.c"},
]
genuine, vendored = m._split_vendored(hits, basenames, target_names)
assert {h["repo"] for h in genuine} == {"real-consumer", "another-consumer", "name-collision"}, genuine
assert len(vendored) == 5, vendored
print("vendored split OK")
PY
out=$(python3 "$TEST_TMPDIR/vendored_test.py" 2>&1)
[ $? -eq 0 ] && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "$out"

# ───────────────────────────────────────────────────────────────────
# 16c. End-to-end: reachability.json carries vendored_copies + emits
#      "External callers (genuine, ...)" wording in the report section.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="reachability JSON v2 carries vendored_copies field"
SYM_VEND="vend_decode"
SYM_VEND_HASH=$(sha1_short "$SYM_VEND")
cat > "$REACHABILITY_MOCK_DIR/sourcegraph-${SYM_VEND_HASH}.json" <<'EOF'
{ "status": "ok", "hits": [
  {"repo": "real-consumer", "path": "src/foo.c"},
  {"repo": "BigApp/foo",    "path": "third_party/pcre2/src/pcre2_substring.c"}
]}
EOF
cat > "$REACHABILITY_MOCK_DIR/gh-${SYM_VEND_HASH}.json" <<'EOF'
{ "status": "unavailable", "error": "n/a" }
EOF
out=$(python3 "$REACH" --symbol "$SYM_VEND" --json --no-cache 2>&1)
echo "$out" | python3 -c '
import json, sys
data = json.load(sys.stdin)
r = data["reachability"]
assert r["schema_version"] == 2, r["schema_version"]
assert r["external_callers"] == 1, ("genuine count", r["external_callers"])
assert r["vendored_copies"] == 1, ("vendored count", r["vendored_copies"])
print("v2 reachability shape OK")
' >/dev/null && pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "v2 fields missing"

# ───────────────────────────────────────────────────────────────────
# 17. reachability.json conforms to the published JSON schema (when jsonschema is installed)
# ───────────────────────────────────────────────────────────────────
# Always-on, dependency-free guard: every key the tool writes must be a
# declared property of the schema (additionalProperties is false). This is
# what catches "code added a field, schema not updated" even where the
# jsonschema package is absent — the gap that previously let `language` /
# `external_caller_repos` drift in undetected.
_CURRENT_TEST="reachability.json keys are all declared in the schema (no drift)"
python3 - <<PY
import json, sys
schema = json.load(open("$SCRIPT_ROOT/tests/schema/reachability.schema.json"))
declared = set(schema["properties"])
errors = []
for rel in ("crashes/CRASH-A/reachability.json",):
    doc = json.load(open("$BATCH_RESULTS/" + rel))
    undeclared = set(doc) - declared
    if undeclared:
        errors.append((rel, sorted(undeclared)))
if errors:
    print("UNDECLARED KEYS:", errors); sys.exit(1)
print("no schema drift")
PY
if [ $? -eq 0 ]; then pass "$_CURRENT_TEST"; else fail "$_CURRENT_TEST" "doc carries keys absent from schema"; fi

_CURRENT_TEST="reachability.json matches tests/schema/reachability.schema.json"
if python3 -c 'import jsonschema' 2>/dev/null; then
  python3 - <<PY
import json, sys, jsonschema
schema = json.load(open("$SCRIPT_ROOT/tests/schema/reachability.schema.json"))
doc = json.load(open("$BATCH_RESULTS/crashes/CRASH-A/reachability.json"))
jsonschema.validate(doc, schema)
print("schema OK")
PY
  if [ $? -eq 0 ]; then pass "$_CURRENT_TEST"; else fail "$_CURRENT_TEST" "schema validation failed"; fi
else
  pass "$_CURRENT_TEST: skipped (jsonschema not installed)"
fi

# ───────────────────────────────────────────────────────────────────
# 18. popularity-rescue gate — an un-triaged report (no structured reach
#     fields) must NOT be promoted to library_popular on caller count
#     alone, so it cannot reach Medium on impact alone. A triaged report
#     with a lazily-unset Surface field still gets the rescue.
# ───────────────────────────────────────────────────────────────────
# A use-after-free narrative whose crashing symbol is a hugely popular
# public library symbol — the external probe finds many callers. Names
# below are placeholders, not from a real upstream finding (see the
# testing discipline rule in docs/development.md).
GATE_UNTRIAGED=$'# CRASH-1\n==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x60\nREAD of size 8 at 0x60 thread T0\n    #0 node_free node.c:100\nSUMMARY: AddressSanitizer: heap-use-after-free node.c:100 in node_free\nFile: node.c\nFunction: node_free\nBug class: lifetime / heap-use-after-free\n'

run_gate_py() { # _CURRENT_TEST set by caller; stdin = python body
  python3 - "$REACH" "$GATE_UNTRIAGED"
}

_CURRENT_TEST="popularity-rescue gate: _classify_surface un-triaged + many callers → unknown"
if run_gate_py <<'PY' 2>/dev/null
import importlib.util, sys
from importlib.machinery import SourceFileLoader
_loader = SourceFileLoader("reachability", sys.argv[1])
mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("reachability", _loader))
_loader.exec_module(mod)
lbl, _ = mod._classify_surface("", "", "narrative text", 500, report_triaged=False)
assert lbl == "unknown", f"un-triaged should stay unknown, got {lbl!r}"
lbl2, _ = mod._classify_surface("", "", "narrative text", 500, report_triaged=True)
assert lbl2 == "library_popular", f"triaged + many callers should rescue, got {lbl2!r}"
PY
then pass "$_CURRENT_TEST"; else fail "$_CURRENT_TEST" "classification gate wrong"; fi

_CURRENT_TEST="popularity-rescue gate: _report_is_triaged detects structured reach fields"
if run_gate_py <<'PY' 2>/dev/null
import importlib.util, sys
from importlib.machinery import SourceFileLoader
_loader = SourceFileLoader("reachability", sys.argv[1])
mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("reachability", _loader))
_loader.exec_module(mod)
assert mod._report_is_triaged({"surface": "library-api"}) is True
assert mod._report_is_triaged({"trigger_source": "bytes"}) is True
assert mod._report_is_triaged({"caller_contract": "violated"}) is True
assert mod._report_is_triaged({"caller_controls": "bytes"}) is True
assert mod._report_is_triaged({"surface": "", "trigger_source": " ",
                               "caller_contract": "", "caller_controls": ""}) is False
assert mod._report_is_triaged({}) is False
PY
then pass "$_CURRENT_TEST"; else fail "$_CURRENT_TEST" "triage detection wrong"; fi

# Under CVSS-as-severity, an un-triaged UAF is still scored by its CVSS class
# (a use-after-free is a severe class) — the popularity rescue is suppressed so
# the surface stays `unknown` (it is NOT promoted to library_popular on caller
# count alone), but the un-triaged-ness no longer *suppresses* the severity.
# Reachability/popularity uncertainty is a priority concern reported separately,
# not a severity reducer. The caller count must not flip the surface tier.
_CURRENT_TEST="popularity-rescue gate: un-triaged report's surface stays unknown (not promoted)"
if run_gate_py <<'PY' 2>/dev/null
import importlib.util, sys
from importlib.machinery import SourceFileLoader
_loader = SourceFileLoader("reachability", sys.argv[1])
mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("reachability", _loader))
_loader.exec_module(mod)
reach = {"services": {"sourcegraph": {"status": "ok"}},
         "external_callers": 500, "vendored_copies": 0}
sev = mod.compute_severity(sys.argv[2], reach, cluster_size=17)
# Caller count does NOT promote an un-triaged report's surface.
assert sev["surface_label"] == "unknown", sev["surface_label"]
# Severity is the CVSS class score — a UAF is High/Critical, not artificially Low.
assert sev["level"] in ("High", "Critical"), f"UAF should score by class, got {sev['level']} ({sev['score']})"
PY
then pass "$_CURRENT_TEST"; else fail "$_CURRENT_TEST" "un-triaged surface promotion or scoring wrong"; fi

_CURRENT_TEST="popularity-rescue gate: triaged library-api UAF report still scores Medium+"
if run_gate_py <<'PY' 2>/dev/null
import importlib.util, sys
from importlib.machinery import SourceFileLoader
_loader = SourceFileLoader("reachability", sys.argv[1])
mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("reachability", _loader))
_loader.exec_module(mod)
reach = {"services": {"sourcegraph": {"status": "ok"}},
         "external_callers": 500, "vendored_copies": 0}
structured = sys.argv[2] + ("Surface: library-api — public entry point on caller bytes\n"
                             "Trigger source: bytes\n")
sev = mod.compute_severity(structured, reach, cluster_size=2)
assert sev["surface_label"] == "library_popular", sev["surface_label"]
assert sev["level"] in ("Medium", "High", "Critical"), \
    f"triaged library bug must not be Low, got {sev['level']} ({sev['score']})"
PY
then pass "$_CURRENT_TEST"; else fail "$_CURRENT_TEST" "triaged genuine bug under-scored"; fi

# ───────────────────────────────────────────────────────────────────
# 19. Reach fields are surfaced into the Fields table for a report that
# omits them (model-direct style), sourced from the .llm_fields.json
# sidecar — so model-direct reports read like harness crashes.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="--report surfaces missing reach fields from the sidecar"
MD_DIR="$TEST_TMPDIR/crashes/CRASH-MODELDIRECT"
mkdir -p "$MD_DIR"
cat > "$MD_DIR/report.md" <<'EOF'
# CRASH-MODELDIRECT: heap overflow

| Field    | Value          |
| :------- | :------------- |
| Class    | use-after-free |
| Severity | Low (10)       |
| File     | cJSON.c        |

## Summary
Crafted JSON triggers a heap-use-after-free READ.
EOF
cat > "$MD_DIR/.llm_fields.json" <<'EOF'
{"surface":"library-api — cJSON public parse API","primitive":"uaf_read",
 "caller_contract":"obeyed","caller_controls":"bytes","trigger_source":"api",
 "boundary":"untrusted JSON buffer handed to app_parse"}
EOF
python3 "$REACH" --report "$MD_DIR" --severity-only --no-cache --json >/dev/null 2>&1 \
  || fail "$_CURRENT_TEST" "report mode failed"
assert_file_contains "$MD_DIR/report.md" '^\| Surface \| library-api' \
  "Surface row inserted from sidecar"
assert_file_contains "$MD_DIR/report.md" '^\| Caller controls \| bytes' \
  "Caller controls row inserted from sidecar"
assert_file_contains "$MD_DIR/report.md" '^\| Boundary \| untrusted JSON' \
  "Boundary row inserted from sidecar"

# Idempotent: a second run must not duplicate the inserted rows.
_CURRENT_TEST="--report reach-field surfacing is idempotent"
python3 "$REACH" --report "$MD_DIR" --severity-only --no-cache --json >/dev/null 2>&1 \
  || fail "$_CURRENT_TEST" "second report run failed"
n_surface=$(grep -c '^| Surface |' "$MD_DIR/report.md")
assert_eq "1" "$n_surface" "Surface row not duplicated on re-run"

# Agent-authored rows win: an existing Surface value is never overwritten.
_CURRENT_TEST="--report never overwrites an agent-authored reach field"
AUTH_DIR="$TEST_TMPDIR/crashes/CRASH-AUTHORED"
mkdir -p "$AUTH_DIR"
cat > "$AUTH_DIR/report.md" <<'EOF'
# CRASH-AUTHORED

| Field    | Value          |
| :------- | :------------- |
| Severity | Low (10)       |
| Surface  | AGENT-AUTHORED SURFACE |
| File     | cJSON.c        |

## Summary
Heap-use-after-free READ.
EOF
cp "$MD_DIR/.llm_fields.json" "$AUTH_DIR/.llm_fields.json"
python3 "$REACH" --report "$AUTH_DIR" --severity-only --no-cache --json >/dev/null 2>&1 \
  || fail "$_CURRENT_TEST" "report mode failed"
assert_file_contains "$AUTH_DIR/report.md" '^\| Surface  \| AGENT-AUTHORED SURFACE' \
  "agent-authored Surface preserved"
n_surface2=$(grep -c '^| Surface' "$AUTH_DIR/report.md")
assert_eq "1" "$n_surface2" "sidecar Surface not added alongside the authored one"

# ───────────────────────────────────────────────────────────────────
# 20. A report with NO Fields table (bare-label / model-direct style)
# gets one synthesized, so it reads like a harness crash.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="--report synthesizes a Fields table when the report has none"
BARE_DIR="$TEST_TMPDIR/crashes/CRASH-BARE"
mkdir -p "$BARE_DIR"
cat > "$BARE_DIR/report.md" <<'EOF'
## Classification
- **Severity**: Medium (auto: score=31)

Boundary: curl public API
Caller controls: parameter string length and content
Trusted caller actions: calls app_set_option
Caller contract: obeyed
Trigger source: call-sequence

# Summary
A heap-use-after-free READ occurs in app_get_info after the option is freed.
EOF
cat > "$BARE_DIR/.llm_fields.json" <<'EOF'
{"surface":"library-api — curl public API","primitive":"uaf_read",
 "caller_contract":"obeyed","caller_controls":"bytes","trigger_source":"call-sequence",
 "boundary":"curl public API"}
EOF
python3 "$REACH" --report "$BARE_DIR" --severity-only --no-cache --json >/dev/null 2>&1 \
  || fail "$_CURRENT_TEST" "report mode failed"
assert_file_contains "$BARE_DIR/report.md" '^## Fields$' \
  "table is emitted under a canonical ## Fields heading"
assert_file_contains "$BARE_DIR/report.md" '^\| Field \| Value \|' \
  "a Fields table was synthesized"
assert_file_contains "$BARE_DIR/report.md" '^\| Surface \| library-api' \
  "synthesized table carries Surface"
assert_file_contains "$BARE_DIR/report.md" '^\| Caller controls \|' \
  "synthesized table carries Caller controls"
# Bare labels are KEPT below the table: the harness duplicates the Fields table
# as bare labels so downstream regex parsers (export-repro, cluster-crashes,
# triage.sh) keep working; render-md hides them from HTML. Removing them would
# make these fields invisible to export.
assert_file_contains "$BARE_DIR/report.md" '^Caller controls:' \
  "bare Caller controls: line preserved for downstream parsers"
assert_file_contains "$BARE_DIR/report.md" '^Boundary:' \
  "bare Boundary: line preserved for downstream parsers"
# A non-tabled bare field (not one of the surfaced six) is left untouched.
assert_file_contains "$BARE_DIR/report.md" '^Trusted caller actions:' \
  "unrelated bare field preserved"

_CURRENT_TEST="--report table synthesis is idempotent"
n_before=$(grep -c '^| Field | Value |' "$BARE_DIR/report.md")
python3 "$REACH" --report "$BARE_DIR" --severity-only --no-cache --json >/dev/null 2>&1 \
  || fail "$_CURRENT_TEST" "second run failed"
n_after=$(grep -c '^| Field | Value |' "$BARE_DIR/report.md")
assert_eq "$n_before" "$n_after" "no second table synthesized on re-run"

# ───────────────────────────────────────────────────────────────────
# 21. A report whose only table is an evidence table (first column `File`)
# must NOT be mistaken for the Fields table: synthesis still happens, and the
# evidence table is not polluted with reach rows.
# ───────────────────────────────────────────────────────────────────
_CURRENT_TEST="--report does not mistake an evidence table for the Fields table"
EV_DIR="$TEST_TMPDIR/crashes/CRASH-EV"
mkdir -p "$EV_DIR"
cat > "$EV_DIR/report.md" <<'EOF'
## Classification
- **Severity**: Medium (auto: score=31)

Boundary: curl public API
Caller controls: parameter string length and content

# Evidence
| File | Note |
| :--- | :--- |
| catalog.c:42 | tool_resolve_entry frees here |
| catalog.c:91 | child_free reuse |

# Summary
A heap-use-after-free READ occurs after free.
EOF
cat > "$EV_DIR/.llm_fields.json" <<'EOF'
{"surface":"library-api — curl public API","primitive":"uaf_read",
 "caller_contract":"obeyed","caller_controls":"bytes","trigger_source":"call-sequence",
 "boundary":"curl public API"}
EOF
python3 "$REACH" --report "$EV_DIR" --severity-only --no-cache --json >/dev/null 2>&1 \
  || fail "$_CURRENT_TEST" "report mode failed"
assert_file_contains "$EV_DIR/report.md" '^## Fields$' \
  "a Fields table is synthesized even when an evidence table is present"
assert_file_contains "$EV_DIR/report.md" '^\| Surface \| library-api' \
  "synthesized Fields table carries Surface"
# The evidence table keeps exactly its two original data rows — no reach rows
# were appended into it (pre-fix, the reach rows landed under the `File` table
# and no `## Fields` table was synthesized at all).
n_ev=$(grep -c '^| catalog.c' "$EV_DIR/report.md")
assert_eq "2" "$n_ev" "evidence table rows unchanged"

teardown_test_env
summary
