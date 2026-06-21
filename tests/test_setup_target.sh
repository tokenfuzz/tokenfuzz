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
   grep -q 'Refreshing output/demo/target.toml to fill placeholders' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target placeholder refresh preserves curated threat_model/s6_peers"
# Regression: filling one unrelated FILL_ME (active asan_lib) must NOT discard a
# hand/LLM-curated [threat_model] or [s6_peers]. Before the fix, the placeholder
# re-seed full-rewrote the file, resetting attacker_controls to the default and
# DELETING [s6_peers] (which a plain seed never emits). LLM disabled so nothing
# can regenerate them — preservation is the only thing keeping them.
cat > "$ROOT/output/demo/target.toml" <<'EOF'
target        = "demo"
build_system  = "cmake"
asan_lib      = "build-asan/FILL_ME.a"

[threat_model]
attacker_controls = ["bytes", "call-sequence", "protocol-state"]

[s6_peers]
domain = "JSON"
peers = ["rapidjson", "simdjson", "json-c"]
EOF
out=$(AUDIT_ROOT="$ROOT" LLM_DECIDE_DISABLE=1 "$SCRIPT_ROOT/bin/setup-target" demo 2>&1)
rc=$?
_demo_toml="$ROOT/output/demo/target.toml"
if [ "$rc" -eq 0 ] &&
   grep -q 'attacker_controls = \["bytes", "call-sequence", "protocol-state"\]' "$_demo_toml" &&
   grep -q '\[s6_peers\]' "$_demo_toml" &&
   grep -q 'peers = \["rapidjson", "simdjson", "json-c"\]' "$_demo_toml" &&
   grep -q 'preserving curated' <<<"$out" &&
   ! grep -qE '^asan_lib.*FILL_ME' "$_demo_toml" &&
   ! python3 "$SCRIPT_ROOT/lib/target_config.py" config-needs-reseed "$_demo_toml" 2>/dev/null; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "rc=$rc out=$out cfg=$(cat "$_demo_toml")"
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
   grep -qE 'config bootstrap: suggest-peers returned rc=[0-9]+ on backend=claude' <<<"$out" &&
   grep -q 'config bootstrap: suggest-peers succeeded on backend=codex' <<<"$out" &&
   ! grep -q 'LLM call failed or unavailable' <<<"$out" &&
   ! grep -q 'backend=claude returned no usable response' <<<"$out"; then
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
   grep -q 'config bootstrap: suggest-peers succeeded on backend=codex' <<<"$out"; then
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

_CURRENT_TEST="setup-target accepts an existing plain source tree inside a harness repo"
git -C "$ROOT" init >/dev/null
plain_root="$ROOT/targets/plain-cpp"
mkdir -p "$plain_root"
cat > "$plain_root/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(plain_cpp CXX)
add_executable(plain main.cpp)
EOF
printf 'int main() { return 0; }\n' > "$plain_root/main.cpp"
out=$(AUDIT_ROOT="$ROOT" LLM_DECIDE_DISABLE=1 "$SCRIPT_ROOT/bin/setup-target" plain-cpp --build 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   [ -f "$ROOT/output/plain-cpp/target.toml" ] &&
   grep -q 'pinned_rev    = "norev"' "$ROOT/output/plain-cpp/target.toml" &&
   grep -q 'Using existing targets/plain-cpp as a plain source tree' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target ignores update inputs for a plain source tree"
out=$(AUDIT_ROOT="$ROOT" LLM_DECIDE_DISABLE=1 "$SCRIPT_ROOT/bin/setup-target" plain-cpp "$REMOTE" --ref main 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   [ ! -d "$plain_root/.git" ] &&
   grep -q 'repo URL/ref ignored' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target symlinks a local non-VCS source dir as a no-VCS target"
# A local directory with no VCS metadata, passed as the source argument, is
# symlinked in place (not cloned/copied) and seeds a local-only target
# (FILL_ME / norev), so the generated reproduce.sh asks for a checkout path
# instead of cloning. The symlink is never pulled or fetched.
link_src="$TEST_TMPDIR/external-plain"
mkdir -p "$link_src"
cat > "$link_src/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(external_plain C)
EOF
out=$(AUDIT_ROOT="$ROOT" LLM_DECIDE_DISABLE=1 "$SCRIPT_ROOT/bin/setup-target" extlink "$link_src" 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   [ -L "$ROOT/targets/extlink" ] &&
   [ -f "$ROOT/targets/extlink/CMakeLists.txt" ] &&
   grep -q 'upstream_url  = "FILL_ME"' "$ROOT/output/extlink/target.toml" &&
   grep -q 'pinned_rev    = "norev"' "$ROOT/output/extlink/target.toml" &&
   grep -q 'Symlinking targets/extlink' <<<"$out" &&
   grep -q 'non-VCS source' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target clones a local git checkout rather than symlinking it"
# A local directory that IS its own git checkout keeps the existing clone
# behaviour — an isolated checkout under targets/, not a symlink.
git_co="$TEST_TMPDIR/external-git"
git clone "$REMOTE" "$git_co" >/dev/null 2>&1
out=$(AUDIT_ROOT="$ROOT" LLM_DECIDE_DISABLE=1 "$SCRIPT_ROOT/bin/setup-target" gitclone "$git_co" 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   [ ! -L "$ROOT/targets/gitclone" ] &&
   [ -d "$ROOT/targets/gitclone/.git" ]; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target symlink seeds an honest no-VCS upstream (not the ignored arg)"
# A plain local source must record upstream_url = FILL_ME, never the local path
# passed as the source arg — recording it would produce dishonest export-repro
# metadata pointing reproduce.sh at the wrong source.
grep -q 'upstream_url  = "FILL_ME"' "$ROOT/output/extlink/target.toml" &&
  ! grep -q "$link_src" "$ROOT/output/extlink/target.toml" &&
  pass "$_CURRENT_TEST" || fail "$_CURRENT_TEST" "$(cat "$ROOT/output/extlink/target.toml")"

_CURRENT_TEST="setup-target does not re-seed a local-only config on rerun (preserves edits)"
# The seed always leaves commented FILL_ME example lines and a local-only target
# keeps upstream_url = "FILL_ME"; the structured re-seed trigger must NOT fire on
# those, or a rerun would wipe operator edits. Append a marker and rerun.
printf '\n# OPERATOR_EDIT_MARKER\nlink_libs = ["-lm", "-lcustom"]\n' >> "$ROOT/output/extlink/target.toml"
out=$(AUDIT_ROOT="$ROOT" LLM_DECIDE_DISABLE=1 "$SCRIPT_ROOT/bin/setup-target" extlink "$link_src" 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q 'OPERATOR_EDIT_MARKER' "$ROOT/output/extlink/target.toml" &&
   grep -q -- '-lcustom' "$ROOT/output/extlink/target.toml" &&
   grep -q 'Keeping reviewed' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="setup-target rejects --repo-type for a plain local source"
# An explicit --repo-type git|hg contradicts a plain (no-VCS) source dir; fail
# clearly rather than silently symlinking it as no-VCS.
out=$(AUDIT_ROOT="$ROOT" "$SCRIPT_ROOT/bin/setup-target" rejecttype "$link_src" --repo-type git 2>&1)
rc=$?
if [ "$rc" -ne 0 ] &&
   [ ! -e "$ROOT/targets/rejecttype" ] &&
   grep -q 'plain source tree, not a git repo' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "rc=$rc $out"
fi

_CURRENT_TEST="setup-target --build builds every enabled sanitizer (asan + ubsan)"
# When [sanitizer].enabled lists more than asan, --build must converge a
# recipe and materialize a build tree for EACH sanitizer, not just asan. We
# pre-place trivial per-sanitizer recipes (.audit/build.sh + .audit/build-
# ubsan.sh) so convergence is skipped ("keeping existing") and no LLM/clang is
# needed; the materialize loop then runs both, proving the loop iterates over
# the enabled set. Field-detection from a real instrumented binary is covered
# by refresh-build-fields' own tests.
# auto-build-script must be reachable under the harness root so the
# convergence loop runs (and, with recipes already present, logs the
# per-sanitizer "keeping existing" skip rather than bailing wholesale).
ln -sf "$SCRIPT_ROOT/bin/auto-build-script" "$ROOT/bin/auto-build-script"
multisan_root="$ROOT/targets/multisan"
mkdir -p "$multisan_root/.audit"
cat > "$multisan_root/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(multisan C)
add_executable(multisan main.c)
EOF
printf 'int main(void){return 0;}\n' > "$multisan_root/main.c"
# Fake recipe: contract is `recipe <src> <build>`. Just create the build dir
# and a stub binary so the materialize step has something to do without a
# real toolchain.
for _r in "$multisan_root/.audit/build.sh" "$multisan_root/.audit/build-ubsan.sh"; do
  cat > "$_r" <<'EOF'
#!/usr/bin/env bash
set -eu
mkdir -p "$2"
: > "$2/multisan"
chmod +x "$2/multisan"
EOF
  chmod +x "$_r"
done
# Reviewed config (parses, no uncommented FILL_ME) so setup-target preserves
# it; enabled lists both sanitizers.
mkdir -p "$ROOT/output/multisan"
cat > "$ROOT/output/multisan/target.toml" <<'EOF'
target = "multisan"
build_system = "cmake"
asan_bin = "build-asan/multisan"

[sanitizer]
enabled = ["asan", "ubsan"]
EOF
out=$(AUDIT_ROOT="$ROOT" LLM_DECIDE_DISABLE=1 \
  "$SCRIPT_ROOT/bin/setup-target" multisan --build 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   [ -d "$multisan_root/build-asan" ] &&
   [ -d "$multisan_root/build-ubsan" ] &&
   grep -q 'bootstrap: keeping existing .*\.audit/build\.sh' <<<"$out" &&
   grep -q 'bootstrap: keeping existing .*\.audit/build-ubsan\.sh' <<<"$out" &&
   grep -q 'bootstrap: materializing ubsan build' <<<"$out" &&
   grep -q 'bootstrap: ubsan build complete' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "rc=$rc out=$out"
fi

_CURRENT_TEST="setup-target --build default config builds asan only"
# With no [sanitizer] block (default enabled=["asan"]), the loop must not try
# to build ubsan/msan/tsan trees.
asanonly_root="$ROOT/targets/asanonly"
mkdir -p "$asanonly_root/.audit"
cat > "$asanonly_root/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(asanonly C)
add_executable(asanonly main.c)
EOF
printf 'int main(void){return 0;}\n' > "$asanonly_root/main.c"
cat > "$asanonly_root/.audit/build.sh" <<'EOF'
#!/usr/bin/env bash
set -eu
mkdir -p "$2"
: > "$2/asanonly"
chmod +x "$2/asanonly"
EOF
chmod +x "$asanonly_root/.audit/build.sh"
mkdir -p "$ROOT/output/asanonly"
cat > "$ROOT/output/asanonly/target.toml" <<'EOF'
target = "asanonly"
build_system = "cmake"
asan_bin = "build-asan/asanonly"
EOF
out=$(AUDIT_ROOT="$ROOT" LLM_DECIDE_DISABLE=1 \
  "$SCRIPT_ROOT/bin/setup-target" asanonly --build 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   [ -d "$asanonly_root/build-asan" ] &&
   [ ! -d "$asanonly_root/build-ubsan" ] &&
   ! grep -q 'materializing ubsan' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "rc=$rc out=$out"
fi

_CURRENT_TEST="setup-target --build never re-seeds a config with placeholders"
# bin/audit and bin/benchmark shell `setup-target --build` to build lazily at
# preflight. That must NOT rewrite a reviewed target.toml as a side effect of
# an audit: a config holding an active FILL_ME placeholder (which a plain
# setup-target rerun WOULD re-seed) is left byte-for-byte intact under --build,
# so hand-curated [threat_model]/attacker_controls cannot be clobbered.
ph_root="$ROOT/targets/phtarget"
mkdir -p "$ph_root/.audit"
cat > "$ph_root/CMakeLists.txt" <<'EOF'
cmake_minimum_required(VERSION 3.16)
project(phtarget C)
EOF
printf 'int main(void){return 0;}\n' > "$ph_root/main.c"
cat > "$ph_root/.audit/build.sh" <<'EOF'
#!/usr/bin/env bash
set -eu
mkdir -p "$2"
: > "$2/phtarget"
EOF
chmod +x "$ph_root/.audit/build.sh"
mkdir -p "$ROOT/output/phtarget"
# Active FILL_ME placeholder (asan_bin) + a curated [threat_model] section that
# the placeholder re-seed would discard. (A surgical refresh-build-fields may
# still fill asan_bin from the fresh build tree — that is the curated-preserving
# path; what must NOT happen is a full re-seed that rewrites [threat_model].)
cat > "$ROOT/output/phtarget/target.toml" <<'EOF'
target = "phtarget"
build_system = "cmake"
asan_bin = "build-asan/FILL_ME"

[threat_model]
attacker_controls = ["hand-curated-token"]
EOF
out=$(AUDIT_ROOT="$ROOT" LLM_DECIDE_DISABLE=1 \
  "$SCRIPT_ROOT/bin/setup-target" phtarget --build 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q 'attacker_controls = \["hand-curated-token"\]' "$ROOT/output/phtarget/target.toml" &&
   grep -q -- '--build does not re-seed' <<<"$out" &&
   ! grep -q 'because generated placeholders remain' <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "rc=$rc out=$out cfg=$(cat "$ROOT/output/phtarget/target.toml")"
fi

teardown_test_env
summary
