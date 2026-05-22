#!/usr/bin/env bash
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

WRAPPERS="$SCRIPT_ROOT/lib/wrappers"
fake_bin="$TEST_TMPDIR/fake-bin"
mkdir -p "$fake_bin" "$RESULTS_DIR/scratch-1"

src="$TEST_TMPDIR/input.c"
printf 'int main(void) { return 0; }\n' > "$src"

cat > "$fake_bin/clang" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$@" > "${FAKE_COMPILER_LOG:?}"
while [ "$#" -gt 0 ]; do
  case "$1" in
    -o)
      shift
      [ "$#" -gt 0 ] && : > "$1"
      ;;
    -o?*)
      : > "${1#-o}"
      ;;
  esac
  shift || break
done
exit 0
SH
chmod +x "$fake_bin/clang"

root_bin="compile-guard-root-$$"
rm -f "$SCRIPT_ROOT/$root_bin"
reject_rc=0
reject_out=$(cd "$SCRIPT_ROOT" && \
  PATH="$WRAPPERS:$fake_bin:$PATH" FAKE_COMPILER_LOG="$TEST_TMPDIR/fake.log" \
  clang -o "$root_bin" "$src" 2>&1) || reject_rc=$?
assert_eq "2" "$reject_rc" "compile-guard: root basename output exits 2"
assert_match 'refusing compiler output in audit repo root' "$reject_out" \
  "compile-guard: root basename output explains refusal"
[ ! -e "$SCRIPT_ROOT/$root_bin" ] \
  && pass "compile-guard: root basename output not created" \
  || fail "compile-guard: root basename output not created" "$SCRIPT_ROOT/$root_bin exists"

scratch_rc=0
scratch_out=$(cd "$SCRIPT_ROOT" && \
  PATH="$WRAPPERS:$fake_bin:$PATH" FAKE_COMPILER_LOG="$TEST_TMPDIR/fake.log" \
  clang -o scratch-1/bad-bin "$src" 2>&1) || scratch_rc=$?
assert_eq "2" "$scratch_rc" "compile-guard: top-level scratch output exits 2"
assert_match 'top-level scratch-N' "$scratch_out" \
  "compile-guard: top-level scratch output explains active scratch requirement"

no_o_rc=0
no_o_out=$(cd "$SCRIPT_ROOT" && \
  PATH="$WRAPPERS:$fake_bin:$PATH" FAKE_COMPILER_LOG="$TEST_TMPDIR/fake.log" \
  clang "$src" 2>&1) || no_o_rc=$?
assert_eq "2" "$no_o_rc" "compile-guard: implicit a.out exits 2"
assert_match 'no explicit safe -o path' "$no_o_out" \
  "compile-guard: implicit a.out explains missing output path"

good_out="$RESULTS_DIR/scratch-1/good-bin"
allow_rc=0
allow_out=$(cd "$SCRIPT_ROOT" && \
  PATH="$WRAPPERS:$fake_bin:$PATH" FAKE_COMPILER_LOG="$TEST_TMPDIR/fake.log" \
  clang -o "$good_out" "$src" 2>&1) || allow_rc=$?
assert_eq "0" "$allow_rc" "compile-guard: RESULTS_DIR scratch output allowed"
assert_eq "" "$allow_out" "compile-guard: allowed output is quiet"
assert_file_exists "$good_out" "compile-guard: allowed compiler was invoked"

override_out="$SCRIPT_ROOT/$root_bin"
override_rc=0
override_msg=$(cd "$SCRIPT_ROOT" && \
  AUDIT_ALLOW_ROOT_COMPILER_OUTPUT=1 PATH="$WRAPPERS:$fake_bin:$PATH" FAKE_COMPILER_LOG="$TEST_TMPDIR/fake.log" \
  clang -o "$override_out" "$src" 2>&1) || override_rc=$?
assert_eq "0" "$override_rc" "compile-guard: explicit override allows root output"
assert_eq "" "$override_msg" "compile-guard: override output is quiet"
rm -f "$override_out"

teardown_test_env
summary
