#!/usr/bin/env bash
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

ROOT="$TEST_TMPDIR/root"
REMOTE="$TEST_TMPDIR/remote"
mkdir -p "$ROOT/bin"
ln -s "$SCRIPT_ROOT/lib" "$ROOT/lib"
ln -s "$SCRIPT_ROOT/.agents" "$ROOT/.agents"

git init "$REMOTE" >/dev/null
printf 'cmake_minimum_required(VERSION 3.16)\nproject(demo C)\n' > "$REMOTE/CMakeLists.txt"
git -C "$REMOTE" add CMakeLists.txt >/dev/null
git -C "$REMOTE" -c user.name=test -c user.email=test@example.invalid commit -m initial >/dev/null

_CURRENT_TEST="setup-target clones source and seeds target.toml"
out=$(AUDIT_ROOT="$ROOT" "$SCRIPT_ROOT/bin/setup-target" demo "$REMOTE" 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   [ -d "$ROOT/targets/demo/.git" ] &&
   [ -f "$ROOT/output/demo/target.toml" ] &&
   grep -q 'build_system  = "cmake"' "$ROOT/output/demo/target.toml"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target preserves reviewed target.toml by default"
# A reviewed config — parses, no FILL_ME — must survive a re-run without
# --force. Documented at docs/reference/target-toml.md (the generated-plus-
# review-layer model) and depended on by routine "refresh source then re-run
# setup" workflows.
printf 'target = "demo"\nbuild_system = "cmake"\n# operator edit\n' \
  > "$ROOT/output/demo/target.toml"
out=$(AUDIT_ROOT="$ROOT" "$SCRIPT_ROOT/bin/setup-target" demo 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q '# operator edit' "$ROOT/output/demo/target.toml" &&
   ! grep -q 'asan_bin' "$ROOT/output/demo/target.toml" &&
   grep -q 'Keeping reviewed output/demo/target.toml' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target refreshes invalid existing target.toml"
# Bad TOML (unterminated array) → re-seed. We do not want a half-edited
# file to silently shadow a working seed when the operator re-runs setup.
printf 'target = "demo"\ninvalid = [\n' > "$ROOT/output/demo/target.toml"
out=$(AUDIT_ROOT="$ROOT" "$SCRIPT_ROOT/bin/setup-target" demo 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q 'target        = "demo"' "$ROOT/output/demo/target.toml" &&
   grep -q 'Refreshing output/demo/target.toml because it no longer parses' \
        <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target refreshes placeholder config by default"
printf 'target        = "demo"\nasan_bin      = "build-asan/FILL_ME"\n' > "$ROOT/output/demo/target.toml"
out=$(AUDIT_ROOT="$ROOT" "$SCRIPT_ROOT/bin/setup-target" demo 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q 'target        = "demo"' "$ROOT/output/demo/target.toml" &&
   grep -q 'Refreshing output/demo/target.toml because generated placeholders remain' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target force-config regenerates target.toml"
printf '# local edit\n' > "$ROOT/output/demo/target.toml"
out=$(AUDIT_ROOT="$ROOT" "$SCRIPT_ROOT/bin/setup-target" demo "$REMOTE" --no-update --force-config 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q 'target        = "demo"' "$ROOT/output/demo/target.toml" &&
   ! grep -q '# local edit' "$ROOT/output/demo/target.toml"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target force alias regenerates target.toml"
printf '# local edit\n' > "$ROOT/output/demo/target.toml"
out=$(AUDIT_ROOT="$ROOT" "$SCRIPT_ROOT/bin/setup-target" demo "$REMOTE" --no-update --force 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q 'target        = "demo"' "$ROOT/output/demo/target.toml" &&
   ! grep -q '# local edit' "$ROOT/output/demo/target.toml" &&
   grep -q 'Regenerating output/demo/target.toml (--force)' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target bootstraps S6 peers after regenerating config"
ln -sf "$SCRIPT_ROOT/bin/suggest-threat-model" "$ROOT/bin/suggest-threat-model"
ln -sf "$SCRIPT_ROOT/bin/suggest-peers" "$ROOT/bin/suggest-peers"
fake_codex="$TEST_TMPDIR/setup-target-fake-codex"
cat > "$fake_codex" <<'EOF'
#!/usr/bin/env bash
prompt=$(cat)
case "$prompt" in
  *attacker_controls*)
    printf '{"attacker_controls":["bytes"],"reasoning":"demo parses byte input"}\n'
    ;;
  *)
    printf '{"domain":"JSON","peers":["rapidjson","simdjson","json-c"],"reasoning":"all parse JSON data"}\n'
    ;;
esac
EOF
chmod +x "$fake_codex"
out=$(
  AUDIT_ROOT="$ROOT" \
  LLM_DECIDE_DISABLE=0 \
  LLM_DECIDE_MAX_CALLS=0 \
  CLAUDE_BIN="$TEST_TMPDIR/no-such-claude" \
  CODEX_BIN="$fake_codex" \
  GEMINI_BIN="$TEST_TMPDIR/no-such-gemini" \
  "$SCRIPT_ROOT/bin/setup-target" demo "$REMOTE" --no-update --force-config 2>&1
)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q '\[s6_peers\]' "$ROOT/output/demo/target.toml" &&
   grep -q 'rapidjson' "$ROOT/output/demo/target.toml" &&
   grep -q 'config bootstrap: suggest-peers failed with claude' <<<"$out" &&
   grep -q 'config bootstrap: updated output/demo/target.toml via suggest-peers using codex' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target force-config overwrites existing S6 peers"
python3 - "$ROOT/output/demo/target.toml" <<'PY'
from pathlib import Path
path = Path(__import__("sys").argv[1])
text = path.read_text()
if "[s6_peers]" not in text:
    text += '\n[s6_peers]\ndomain = "Old"\npeers = ["old1", "old2", "old3"]\n'
path.write_text(text.replace("rapidjson", "oldjson"))
PY
out=$(
  AUDIT_ROOT="$ROOT" \
  LLM_DECIDE_DISABLE=0 \
  LLM_DECIDE_MAX_CALLS=0 \
  CLAUDE_BIN="$TEST_TMPDIR/no-such-claude" \
  CODEX_BIN="$fake_codex" \
  GEMINI_BIN="$TEST_TMPDIR/no-such-gemini" \
  "$SCRIPT_ROOT/bin/setup-target" demo "$REMOTE" --no-update --force-config 2>&1
)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q 'rapidjson' "$ROOT/output/demo/target.toml" &&
   ! grep -q 'oldjson' "$ROOT/output/demo/target.toml" &&
   grep -q 'config bootstrap: updated output/demo/target.toml via suggest-peers using codex' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target without repo URL does not update checkout"
rm -f "$ROOT/targets/demo/demo.c"
printf 'int skipped(void) { return 0; }\n' > "$REMOTE/skipped.c"
git -C "$REMOTE" add skipped.c >/dev/null
git -C "$REMOTE" -c user.name=test -c user.email=test@example.invalid commit -m add-skipped >/dev/null
out=$(AUDIT_ROOT="$ROOT" "$SCRIPT_ROOT/bin/setup-target" demo 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && [ ! -f "$ROOT/targets/demo/skipped.c" ]; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target updates a clean existing git checkout"
printf 'int main(void) { return 0; }\n' > "$REMOTE/demo.c"
git -C "$REMOTE" add demo.c >/dev/null
git -C "$REMOTE" -c user.name=test -c user.email=test@example.invalid commit -m add-demo >/dev/null
out=$(AUDIT_ROOT="$ROOT" "$SCRIPT_ROOT/bin/setup-target" demo "$REMOTE" 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && [ -f "$ROOT/targets/demo/demo.c" ]; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

teardown_test_env
summary
