#!/usr/bin/env bash
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

ROOT="$TEST_TMPDIR/root"
HOST_HOME="$TEST_TMPDIR/home"
mkdir -p "$ROOT/.codex" "$ROOT/.gemini" "$HOST_HOME/.claude"
: >"$HOST_HOME/.claude.json"

_CURRENT_TEST="audit-container-shell help describes container shell"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" "$SCRIPT_ROOT/bin/audit-container-shell" --help 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q "mounts this" <<<"$out" &&
   grep -q "repository at /root/work" <<<"$out" &&
   grep -q "opens an interactive shell" <<<"$out" &&
   grep -q "It does not run" <<<"$out" &&
   grep -q "bin/audit" <<<"$out" &&
   grep -q "node:lts-bookworm" <<<"$out" &&
   grep -q -- "--image <image>" <<<"$out" &&
   grep -q -- "--tag <name>" <<<"$out" &&
   grep -q -- "--gvisor" <<<"$out" &&
   grep -q -- "--docker-runtime <name>" <<<"$out" &&
   grep -q -- "--forward-credentials" <<<"$out" &&
   grep -q "starts logged out" <<<"$out" &&
   grep -q "# codex login" <<<"$out" &&
   grep -q "# codex login status" <<<"$out" &&
   grep -q '# claude -p "Reply exactly: tokenfuzz-claude-auth-ok"' <<<"$out" &&
   grep -q '# agy -p "Reply exactly: tokenfuzz-gemini-auth-ok"' <<<"$out" &&
   grep -q "press Ctrl+C" <<<"$out" &&
   ! grep -q "AUDIT_CONTAINER_CLAUDE_JSON" <<<"$out" &&
   ! grep -q -- "--skip-git-repo-check" <<<"$out" &&
   ! grep -q -- "--version" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell --rebuild dry-run prints build args without credential mounts"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" "$SCRIPT_ROOT/bin/audit-container-shell" \
  --dry-run --rebuild --tag test/audit-shell:latest 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q "BASE_IMAGE=node:lts-bookworm" <<<"$out" &&
   ! grep -q "COPY tests/run-tests.sh" "$SCRIPT_ROOT/bin/audit-container-shell" &&
   grep -q "tests/run-tests.sh\" --install-container-deps" "$SCRIPT_ROOT/bin/audit-container-shell" &&
   ! grep -q "packages=\"bash" "$SCRIPT_ROOT/bin/audit-container-shell" &&
   grep -q "command -v yum" "$SCRIPT_ROOT/bin/audit-container-shell" &&
   grep -q "command -v yum" "$SCRIPT_ROOT/tests/run-tests.sh" &&
   grep -q "@anthropic-ai/claude-code@latest" <<<"$out" &&
   grep -q "@openai/codex@latest" <<<"$out" &&
   grep -q "@google/gemini-cli@latest" <<<"$out" &&
   grep -q "AGY_INSTALL_URL=https://antigravity.google/cli/install.sh" <<<"$out" &&
   grep -q -- "-v $ROOT:/root/work" <<<"$out" &&
   ! grep -q -- ":/root/.claude:ro" <<<"$out" &&
   ! grep -q -- ":/root/.claude.json:ro" <<<"$out" &&
   ! grep -q -- ":/root/.codex:ro" <<<"$out" &&
   ! grep -q -- ":/root/.gemini:ro" <<<"$out" &&
   grep -q -- "-e GEMINI_CLI_TRUST_WORKSPACE=true" <<<"$out" &&
   grep -q -- "-e IS_SANDBOX=1" <<<"$out" &&
   grep -q -- "--security-opt no-new-privileges" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell default dry-run also forwards IS_SANDBOX=1"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" "$SCRIPT_ROOT/bin/audit-container-shell" \
  --dry-run 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && grep -q -- "-e IS_SANDBOX=1" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell help explains IS_SANDBOX rationale"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" "$SCRIPT_ROOT/bin/audit-container-shell" --help 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q "IS_SANDBOX=1" <<<"$out" &&
   grep -q "dangerously-skip-permissions" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell --rebuild dry-run honors package and docker runtime overrides"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" \
  CLAUDE_NPM_SPEC="claude-test@latest" \
  CODEX_NPM_SPEC="codex-test@latest" \
  GEMINI_CLI_NPM_SPEC="gemini-cli-test@latest" \
  AGY_INSTALL_URL="https://example.test/agy-install.sh" \
  "$SCRIPT_ROOT/bin/audit-container-shell" \
  --dry-run --rebuild --docker-runtime runsc --image node:22-bookworm 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q "docker build" <<<"$out" &&
   grep -q -- "--runtime runsc" <<<"$out" &&
   grep -q "BASE_IMAGE=node:22-bookworm" <<<"$out" &&
   grep -q "claude-test@latest" <<<"$out" &&
   grep -q "codex-test@latest" <<<"$out" &&
   grep -q "gemini-cli-test@latest" <<<"$out" &&
   grep -q "AGY_INSTALL_URL=https://example.test/agy-install.sh" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell normalizes official distro image aliases"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" "$SCRIPT_ROOT/bin/audit-container-shell" \
  --dry-run --rebuild --image ubuntu 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && grep -q "BASE_IMAGE=ubuntu:latest" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" "$SCRIPT_ROOT/bin/audit-container-shell" \
  --dry-run --rebuild --base-image fedora 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && grep -q "BASE_IMAGE=fedora:latest" <<<"$out"; then
  pass "audit-container-shell keeps --base-image as alias"
else
  fail "audit-container-shell keeps --base-image as alias" "$out"
fi

_CURRENT_TEST="audit-container-shell does not forward credentials by default"
ADC_FILE="$TEST_TMPDIR/google-adc.json"
printf '{}\n' > "$ADC_FILE"
mkdir -p "$HOST_HOME/.config/gcloud"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" GEMINI_API_KEY="test-key" USE_GEMINI_CLI=1 \
  GOOGLE_APPLICATION_CREDENTIALS="$ADC_FILE" \
  "$SCRIPT_ROOT/bin/audit-container-shell" --dry-run 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   ! grep -q -- "-e GEMINI_API_KEY" <<<"$out" &&
   ! grep -q -- "-e USE_GEMINI_CLI" <<<"$out" &&
   ! grep -q -- "GOOGLE_APPLICATION_CREDENTIALS=/root/.config/audit-google-application-credentials.json" <<<"$out" &&
   ! grep -q -- ":/root/.config/gcloud:ro" <<<"$out" &&
   grep -q -- "--forward-credentials" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell forwards selected credentials when requested"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" GEMINI_API_KEY="test-key" USE_GEMINI_CLI=1 \
  GOOGLE_APPLICATION_CREDENTIALS="$ADC_FILE" \
  "$SCRIPT_ROOT/bin/audit-container-shell" --dry-run --forward-credentials 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q -- "-e GEMINI_API_KEY" <<<"$out" &&
   grep -q -- "-e USE_GEMINI_CLI" <<<"$out" &&
   grep -q -- "-e GOOGLE_APPLICATION_CREDENTIALS=/root/.config/audit-google-application-credentials.json" <<<"$out" &&
   grep -q -- "$ADC_FILE:/root/.config/audit-google-application-credentials.json:ro" <<<"$out" &&
   grep -q -- "$HOST_HOME/.config/gcloud:/root/.config/gcloud:ro" <<<"$out" &&
   grep -q "Forwarding host env vars:.*GEMINI_API_KEY" <<<"$out" &&
   grep -q "Mounting GOOGLE_APPLICATION_CREDENTIALS read-only" <<<"$out" &&
   ! grep -q "log in inside the container or use --forward-credentials" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell --forward-credentials with nothing to forward says so"
EMPTY_HOME="$TEST_TMPDIR/empty-home"
mkdir -p "$EMPTY_HOME"
out=$(AUDIT_ROOT="$ROOT" HOME="$EMPTY_HOME" \
  env -u ANTHROPIC_API_KEY -u CLAUDE_CODE_OAUTH_TOKEN -u OPENAI_API_KEY \
  -u GEMINI_API_KEY -u USE_GEMINI_CLI -u GOOGLE_API_KEY \
  -u GOOGLE_CLOUD_PROJECT -u GOOGLE_CLOUD_QUOTA_PROJECT \
  -u GOOGLE_APPLICATION_CREDENTIALS \
  "$SCRIPT_ROOT/bin/audit-container-shell" --dry-run --forward-credentials 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q -- "--forward-credentials set but no host credential" <<<"$out" &&
   ! grep -q "log in inside the container or use --forward-credentials" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell default still emits log-in-or-forward hint"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" \
  "$SCRIPT_ROOT/bin/audit-container-shell" --dry-run 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q "log in inside the container or use --forward-credentials" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell forwards selected credentials via env knob"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" OPENAI_API_KEY="test-key" \
  AUDIT_FORWARD_CREDENTIALS=1 \
  "$SCRIPT_ROOT/bin/audit-container-shell" --dry-run 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q -- "-e OPENAI_API_KEY" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell default dry-run does not emit build args"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" "$SCRIPT_ROOT/bin/audit-container-shell" \
  --dry-run 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   ! grep -q "build command" <<<"$out" &&
   ! grep -q "BASE_IMAGE=" <<<"$out" &&
   grep -q "run command" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell rejects removed --no-cache flag"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" "$SCRIPT_ROOT/bin/audit-container-shell" \
  --dry-run --no-cache 2>&1)
rc=$?
if [ "$rc" -ne 0 ] && grep -q "unknown option: --no-cache" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell rejects removed --reuse-image flag"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" "$SCRIPT_ROOT/bin/audit-container-shell" \
  --dry-run --reuse-image 2>&1)
rc=$?
if [ "$rc" -ne 0 ] && grep -q "unknown option: --reuse-image" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell rejects removed --no-reuse-image flag"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" "$SCRIPT_ROOT/bin/audit-container-shell" \
  --dry-run --no-reuse-image 2>&1)
rc=$?
if [ "$rc" -ne 0 ] && grep -q "unknown option: --no-reuse-image" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell rejects removed --no-build flag"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" "$SCRIPT_ROOT/bin/audit-container-shell" \
  --dry-run --no-build 2>&1)
rc=$?
if [ "$rc" -ne 0 ] && grep -q "unknown option: --no-build" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell --gvisor dry-run selects runsc"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" "$SCRIPT_ROOT/bin/audit-container-shell" \
  --dry-run --gvisor 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q "Using Docker OCI runtime: runsc" <<<"$out" &&
   grep -q -- "--runtime runsc" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell honors AUDIT_DOCKER_RUNTIME"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" AUDIT_DOCKER_RUNTIME=runsc \
  "$SCRIPT_ROOT/bin/audit-container-shell" --dry-run 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && grep -q -- "--runtime runsc" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell reports docker missing"
STUB_DIR="$TEST_TMPDIR/stub-empty"
mkdir -p "$STUB_DIR"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" PATH="$STUB_DIR" \
  /bin/bash "$SCRIPT_ROOT/bin/audit-container-shell" --runtime docker 2>&1)
rc=$?
if [ "$rc" -ne 0 ] &&
   grep -q "docker not installed" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell reports daemon-unreachable with platform hint"
STUB_DIR="$TEST_TMPDIR/stub-dead-docker"
mkdir -p "$STUB_DIR"
cat >"$STUB_DIR/docker" <<'STUB'
#!/usr/bin/env bash
[ "$1" = "info" ] && exit 1
exit 0
STUB
chmod +x "$STUB_DIR/docker"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" PATH="$STUB_DIR:/usr/bin:/bin" \
  AUDIT_CONTAINER_AUTO_START=0 \
  "$SCRIPT_ROOT/bin/audit-container-shell" --runtime docker 2>&1)
rc=$?
if [ "$rc" -ne 0 ] &&
   grep -q "docker installed but daemon not reachable" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell auto-start logs attempt and recovers when daemon comes up"
STUB_DIR="$TEST_TMPDIR/stub-autostart"
STATE_DIR="$TEST_TMPDIR/autostart-state"
mkdir -p "$STUB_DIR" "$STATE_DIR"
# Fake docker: 'info' fails until $STATE_DIR/up exists. 'run'/'build' succeed.
cat >"$STUB_DIR/docker" <<STUB
#!/usr/bin/env bash
case "\$1" in
  info)  [ -f "$STATE_DIR/up" ] && exit 0 || exit 1 ;;
  *)     exit 0 ;;
esac
STUB
chmod +x "$STUB_DIR/docker"
# Fake systemctl that "starts" the daemon by creating the marker file.
cat >"$STUB_DIR/systemctl" <<STUB
#!/usr/bin/env bash
touch "$STATE_DIR/up"
exit 0
STUB
chmod +x "$STUB_DIR/systemctl"
# Force the Linux start path regardless of host OS by stubbing uname.
cat >"$STUB_DIR/uname" <<'STUB'
#!/usr/bin/env bash
[ "$1" = "-s" ] && { echo Linux; exit 0; }
exec /usr/bin/uname "$@"
STUB
chmod +x "$STUB_DIR/uname"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" PATH="$STUB_DIR:/usr/bin:/bin" \
  AUDIT_CONTAINER_START_TIMEOUT=10 \
  "$SCRIPT_ROOT/bin/audit-container-shell" --runtime docker 2>&1)
rc=$?
if [ "$rc" -eq 0 ] &&
   grep -q "daemon not reachable; attempting auto-start" <<<"$out" &&
   grep -q "Attempting to start docker: systemctl" <<<"$out" &&
   grep -q "docker daemon is now reachable" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell rejects unsupported runtime"
STUB_DIR="$TEST_TMPDIR/stub-only-docker"
mkdir -p "$STUB_DIR"
cat >"$STUB_DIR/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  info) exit 0 ;;
  run|build) exit 0 ;;
  *) exit 0 ;;
esac
STUB
chmod +x "$STUB_DIR/docker"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" PATH="$STUB_DIR:/usr/bin:/bin" \
  "$SCRIPT_ROOT/bin/audit-container-shell" --runtime nerdctl 2>&1)
rc=$?
if [ "$rc" -ne 0 ] &&
   grep -q -- "--runtime must be docker" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

_CURRENT_TEST="audit-container-shell default does not build when image already exists"
STUB_DIR="$TEST_TMPDIR/stub-image-exists"
STATE_DIR="$TEST_TMPDIR/image-exists-state"
mkdir -p "$STUB_DIR" "$STATE_DIR"
cat >"$STUB_DIR/docker" <<STUB
#!/usr/bin/env bash
case "\$1" in
  info)  exit 0 ;;
  image) shift; [ "\$1" = "inspect" ] && exit 0 || exit 0 ;;
  build) touch "$STATE_DIR/built"; exit 0 ;;
  run)   exit 0 ;;
  *)     exit 0 ;;
esac
STUB
chmod +x "$STUB_DIR/docker"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" PATH="$STUB_DIR:/usr/bin:/bin" \
  "$SCRIPT_ROOT/bin/audit-container-shell" --runtime docker 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && [ ! -f "$STATE_DIR/built" ]; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out (built marker: $([ -f "$STATE_DIR/built" ] && echo yes || echo no))"
fi

_CURRENT_TEST="audit-container-shell --rebuild builds even when image exists"
STUB_DIR="$TEST_TMPDIR/stub-rebuild"
STATE_DIR="$TEST_TMPDIR/rebuild-state"
mkdir -p "$STUB_DIR" "$STATE_DIR"
cat >"$STUB_DIR/docker" <<STUB
#!/usr/bin/env bash
case "\$1" in
  info)  exit 0 ;;
  image) shift; [ "\$1" = "inspect" ] && exit 0 || exit 0 ;;
  build) touch "$STATE_DIR/built"; exit 0 ;;
  run)   exit 0 ;;
  *)     exit 0 ;;
esac
STUB
chmod +x "$STUB_DIR/docker"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" PATH="$STUB_DIR:/usr/bin:/bin" \
  "$SCRIPT_ROOT/bin/audit-container-shell" --runtime docker --rebuild 2>&1)
rc=$?
if [ "$rc" -eq 0 ] && [ -f "$STATE_DIR/built" ]; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out (built marker: $([ -f "$STATE_DIR/built" ] && echo yes || echo no))"
fi

_CURRENT_TEST="audit-container-shell default fails with --rebuild hint when image is missing"
STUB_DIR="$TEST_TMPDIR/stub-image-missing"
mkdir -p "$STUB_DIR"
cat >"$STUB_DIR/docker" <<'STUB'
#!/usr/bin/env bash
case "$1" in
  info)  exit 0 ;;
  image) shift; [ "$1" = "inspect" ] && exit 1 || exit 0 ;;
  *)     exit 0 ;;
esac
STUB
chmod +x "$STUB_DIR/docker"
out=$(AUDIT_ROOT="$ROOT" HOME="$HOST_HOME" PATH="$STUB_DIR:/usr/bin:/bin" \
  "$SCRIPT_ROOT/bin/audit-container-shell" --runtime docker 2>&1)
rc=$?
if [ "$rc" -ne 0 ] &&
   grep -q "image audit-cli-shell:latest does not exist locally" <<<"$out" &&
   grep -q "run with --rebuild" <<<"$out"; then
  pass "$_CURRENT_TEST"
else
  fail "$_CURRENT_TEST" "$out"
fi

teardown_test_env
summary
