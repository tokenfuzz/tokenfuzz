#!/usr/bin/env bash
# Tests for bin/docs - local MkDocs helper.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

DOCS_BIN="$SCRIPT_ROOT/bin/docs"
DOCS_TEST_LOG="$TEST_TMPDIR/docs-helper.log"
export DOCS_TEST_LOG

fake_venv="$TEST_TMPDIR/docs-venv"
mkdir -p "$fake_venv/bin"

cat > "$fake_venv/bin/python" <<'SH'
#!/usr/bin/env bash
printf 'PY %s\n' "$*" >> "$DOCS_TEST_LOG"
SH
chmod +x "$fake_venv/bin/python"

cat > "$fake_venv/bin/mkdocs" <<'SH'
#!/usr/bin/env bash
printf 'MK %s\n' "$*" >> "$DOCS_TEST_LOG"
SH
chmod +x "$fake_venv/bin/mkdocs"

help_out=$(bash "$DOCS_BIN")
assert_match "bin/docs serve" "$help_out" "docs: no args prints help"
assert_eq "" "$(cat "$DOCS_TEST_LOG" 2>/dev/null || true)" \
  "docs: no-arg help does not install deps"

out=$(DOCS_VENV="$fake_venv" DOCS_SITE_DIR="$TEST_TMPDIR/missing-site" \
  bash "$DOCS_BIN" serve --dev-addr 127.0.0.1:4100 2>&1)
assert_eq "" "$out" "docs: serve is quiet with fake tools"
assert_file_contains "$DOCS_TEST_LOG" "PY -m pip install -r $SCRIPT_ROOT/requirements.txt" \
  "docs: installs pinned requirements before serving"
assert_file_contains "$DOCS_TEST_LOG" "MK build --strict" \
  "docs: serve builds when site output is missing"
assert_file_contains "$DOCS_TEST_LOG" "MK serve --dev-addr 127.0.0.1:4100" \
  "docs: serve runs MkDocs preview"

: > "$DOCS_TEST_LOG"
mkdir -p "$TEST_TMPDIR/existing-site"
touch "$TEST_TMPDIR/existing-site/index.html"
DOCS_VENV="$fake_venv" DOCS_SITE_DIR="$TEST_TMPDIR/existing-site" \
  bash "$DOCS_BIN" --dev-addr 127.0.0.1:4101 >/dev/null 2>&1
assert_file_not_contains "$DOCS_TEST_LOG" "MK build --strict" \
  "docs: option-leading serve skips bootstrap build when site exists"
assert_file_contains "$DOCS_TEST_LOG" "MK serve --dev-addr 127.0.0.1:4101" \
  "docs: option-leading invocation still serves"

: > "$DOCS_TEST_LOG"
DOCS_VENV="$fake_venv" bash "$DOCS_BIN" build --site-dir "$TEST_TMPDIR/site" >/dev/null 2>&1
assert_file_contains "$DOCS_TEST_LOG" "MK build --strict --site-dir $TEST_TMPDIR/site" \
  "docs: build runs strict MkDocs build"

flag_help_out=$(bash "$DOCS_BIN" --help)
assert_match "bin/docs serve" "$flag_help_out" "docs: help documents serve"
assert_match "bin/docs build" "$flag_help_out" "docs: help documents build"

bad_rc=0
bad_out=$(DOCS_VENV="$fake_venv" bash "$DOCS_BIN" nope 2>&1) || bad_rc=$?
assert_eq "2" "$bad_rc" "docs: unknown command exits 2"
assert_match "unknown command: nope" "$bad_out" "docs: unknown command explains error"

assert_file_contains "$SCRIPT_ROOT/docs/development.md" "bin/docs" \
  "development docs: local preview uses bin/docs"

teardown_test_env
summary
