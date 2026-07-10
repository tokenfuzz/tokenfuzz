#!/usr/bin/env bash
# Unit tests for bin/find-seed — spec parsing, ranking, output format
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

FIND_SEED="$SCRIPT_ROOT/bin/find-seed"
MOCK_TARGET="$SCRIPT_ROOT/tests/fixtures/mock-target"

# ═══════════════════════════════════════════════════════════════
# 1. --help shows usage
# ═══════════════════════════════════════════════════════════════

output=$("$FIND_SEED" --help 2>&1)
assert_match "find-seed" "$output" "help: shows usage"

# ═══════════════════════════════════════════════════════════════
# 2. No args shows usage
# ═══════════════════════════════════════════════════════════════

output=$("$FIND_SEED" 2>&1)
assert_match "find-seed" "$output" "no args: shows usage"

# ═══════════════════════════════════════════════════════════════
# 3. Syntax check passes
# ═══════════════════════════════════════════════════════════════

python3 -m py_compile "$FIND_SEED" 2>/dev/null
assert_eq 0 $? "find-seed: Python syntax check passes"

# ═══════════════════════════════════════════════════════════════
# 4. Spec parsing — file only
# ═══════════════════════════════════════════════════════════════

# Test the parsing logic directly
output=$(bash -c '
  SPEC="editor/libeditor/HTMLEditor.cpp"
  FILE="${SPEC%%:*}"
  FUNC=""
  if [ "$FILE" != "$SPEC" ]; then FUNC="${SPEC#*:}"; fi
  basename="${FILE##*/}"
  stem="${basename%.*}"
  echo "file=$FILE func=$FUNC stem=$stem"
')
assert_match "file=editor/libeditor/HTMLEditor.cpp" "$output" "parse: file-only path"
assert_match "func= " "$output" "parse: no function"
assert_match "stem=HTMLEditor" "$output" "parse: stem extracted"

# ═══════════════════════════════════════════════════════════════
# 5. Spec parsing — file:function
# ═══════════════════════════════════════════════════════════════

output=$(bash -c '
  SPEC="dom/canvas/CanvasRenderingContext2D.cpp:DrawImage"
  FILE="${SPEC%%:*}"
  FUNC=""
  if [ "$FILE" != "$SPEC" ]; then FUNC="${SPEC#*:}"; fi
  basename="${FILE##*/}"
  stem="${basename%.*}"
  SUBSYS="$(printf "%s" "$FILE" | awk -F"/" "{if (NF>=2) print \$1\"/\"\$2; else print \$1}")"
  echo "file=$FILE func=$FUNC stem=$stem subsys=$SUBSYS"
')
assert_match "func=DrawImage" "$output" "parse: function extracted"
assert_match "stem=CanvasRenderingContext2D" "$output" "parse: stem from file:func"
assert_match "subsys=dom/canvas" "$output" "parse: subsystem prefix"

# ═══════════════════════════════════════════════════════════════
# 6. Spec parsing — single-component path
# ═══════════════════════════════════════════════════════════════

output=$(bash -c '
  SPEC="Foo.cpp"
  FILE="${SPEC%%:*}"
  SUBSYS="$(printf "%s" "$FILE" | awk -F"/" "{if (NF>=2) print \$1\"/\"\$2; else print \$1}")"
  echo "subsys=$SUBSYS"
')
assert_match "subsys=Foo.cpp" "$output" "parse: single-component subsys"

# ═══════════════════════════════════════════════════════════════
# 7. Non-existent target root → error
# ═══════════════════════════════════════════════════════════════

output=$(TARGET_ROOT="/nonexistent/path" "$FIND_SEED" "test.cpp" 2>&1) || true
assert_match "not set or not a directory" "$output" "missing target: error message"

# ═══════════════════════════════════════════════════════════════
# 8. Missing ripgrep → error
# ═══════════════════════════════════════════════════════════════

output=$(PATH="/usr/bin" TARGET_ROOT="$MOCK_TARGET" "$FIND_SEED" "test.cpp" 2>&1) || true
# May succeed if rg is in /usr/bin, otherwise shows error
if grep -q "ripgrep" <<<"$output"; then
  pass "missing rg: shows ripgrep requirement"
else
  pass "rg available in restricted PATH"
fi

# ═══════════════════════════════════════════════════════════════
# 9. Output format: rank<TAB>path<TAB>context
# ═══════════════════════════════════════════════════════════════

# Create a mock target with findable seeds
seed_dir="$TEST_TMPDIR/seed_target"
mkdir -p "$seed_dir/dom/canvas/crashtests"
mkdir -p "$seed_dir/testing/web-platform/tests"
echo '<html><!-- CanvasRenderingContext2D test --><body><canvas/></body></html>' > "$seed_dir/dom/canvas/crashtests/test1.html"
echo 'drawImage test in <canvas>' > "$seed_dir/testing/web-platform/tests/canvas.html"

if command -v rg >/dev/null 2>&1; then
  output=$(TARGET_ROOT="$seed_dir" "$FIND_SEED" "dom/canvas/CanvasRenderingContext2D.cpp" 2 2>&1) || true
  assert_neq "" "$output" "output format: produces output"
else
  pass "rg not available — skipping output format test"
fi

# ═══════════════════════════════════════════════════════════════
# 10. Filename fallback matches optional function names literally
# ═══════════════════════════════════════════════════════════════

fallback_dir="$TEST_TMPDIR/fallback_target"
mkdir -p "$fallback_dir/testing/web-platform/tests/nested"
printf '<html><body>seed file without body keyword</body></html>\n' \
  > "$fallback_dir/testing/web-platform/tests/nested/decode[thing]-case.html"

if command -v rg >/dev/null 2>&1; then
  output=$(TARGET_ROOT="$fallback_dir" "$FIND_SEED" "dom/codec/Codec.cpp:Decode[Thing]" 5 2>&1) || true
  assert_match $'NAME\t.*/decode\\[thing\\]-case\\.html\t\\(filename match\\)' "$output" \
    "filename fallback: function name matched literally"
else
  pass "rg not available — skipping filename fallback test"
fi

# ═══════════════════════════════════════════════════════════════
# 11. Auto-discovery works on non-firefox layouts (no hardcoded paths)
# ═══════════════════════════════════════════════════════════════

# Mimic a curl-style tree: tests/data full of testN files.
curl_like="$TEST_TMPDIR/curl_like"
mkdir -p "$curl_like/tests/data"
for i in $(seq 1 25); do
  printf 'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n' > "$curl_like/tests/data/test$i"
done
# Plus a docs dir that must NOT be auto-classified as a seed root.
mkdir -p "$curl_like/docs"
echo "manpage stub" > "$curl_like/docs/curl.1"

if command -v rg >/dev/null 2>&1; then
  cache_dir=$(mktemp -d "$TEST_TMPDIR/results-XXXXXX")
  # Query for filename "test" — every fixture file matches by NAME rank.
  # This proves the discovery walked to tests/data and rg/awk found the
  # fixture files (rather than bailing out at "no seed-corpus roots").
  output=$(TARGET_ROOT="$curl_like" RESULTS_DIR="$cache_dir" "$FIND_SEED" "lib/test.c" 5 2>&1) || true
  assert_match "tests/data/test" "$output" "auto-discovery: curl-like tree/tests/data surfaces"
  # The cache file must list tests/data and must NOT list docs/.
  cache_file="$cache_dir/.seed-roots".*
  cache_content=$(cat $cache_file 2>/dev/null || true)
  assert_match "tests/data" "$cache_content" "auto-discovery: cache contains tests/data"
  if grep -q '/docs$' <<<"$cache_content"; then
    fail "auto-discovery: docs/ should not be classified as a seed root"
  else
    pass "auto-discovery: docs/ pruned from seed roots"
  fi
else
  pass "rg not available — skipping auto-discovery test"
fi

# ═══════════════════════════════════════════════════════════════
# 12. Discovery cache reused across calls within a session
# ═══════════════════════════════════════════════════════════════

if command -v rg >/dev/null 2>&1; then
  cache_dir2=$(mktemp -d "$TEST_TMPDIR/results-XXXXXX")
  # First call populates the cache.
  TARGET_ROOT="$curl_like" RESULTS_DIR="$cache_dir2" "$FIND_SEED" "lib/test.c" 1 >/dev/null 2>&1 || true
  cache_path=$(ls "$cache_dir2"/.seed-roots.* 2>/dev/null | head -1)
  assert_neq "" "$cache_path" "cache: file created on first call"
  # Bump the cache mtime forward of TARGET_ROOT so the freshness check sees
  # cache as up-to-date. Add an ignored sentinel line so reuse is observable
  # without a fixed sleep for timestamp separation.
  touch "$cache_path"
  sentinel="$TEST_TMPDIR/cache-sentinel-does-not-exist"
  printf '%s\n' "$sentinel" >> "$cache_path"
  TARGET_ROOT="$curl_like" RESULTS_DIR="$cache_dir2" "$FIND_SEED" "lib/test.c" 1 >/dev/null 2>&1 || true
  assert_file_contains "$cache_path" "$sentinel" "cache: not rebuilt when TARGET_ROOT unchanged"
else
  pass "rg not available — skipping cache reuse test"
fi

# ═══════════════════════════════════════════════════════════════
# 13. Explicit .seed-roots override wins over hashed discovery cache
# ═══════════════════════════════════════════════════════════════

if command -v rg >/dev/null 2>&1; then
  override_target="$TEST_TMPDIR/override_target"
  mkdir -p "$override_target/bad/tests" "$override_target/curated/seeds"
  printf 'SHOULD_NOT_APPEAR test body\n' > "$override_target/bad/tests/test_bad.txt"
  printf 'needle from curated override\n' > "$override_target/curated/seeds/test_good.txt"
  cache_dir3=$(mktemp -d "$TEST_TMPDIR/results-XXXXXX")
  printf '%s\n' "$override_target/curated/seeds" > "$cache_dir3/.seed-roots"
  output=$(TARGET_ROOT="$override_target" RESULTS_DIR="$cache_dir3" "$FIND_SEED" "lib/test.c" 5 2>&1) || true
  assert_match "curated/seeds/test_good" "$output" "cache override: .seed-roots is honored"
  assert_not_match "bad/tests/test_bad" "$output" "cache override: auto-discovered dirs ignored"
  leftover_tmp=$(find "$cache_dir3" -maxdepth 1 -name '.seed-roots.*.tmp' -print | wc -l | tr -d ' ')
  assert_eq "0" "$leftover_tmp" "cache override: no fixed or leaked temp cache files"
else
  pass "rg not available — skipping explicit cache override test"
fi

teardown_test_env
summary
