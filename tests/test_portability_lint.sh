#!/usr/bin/env bash
# Portability lint for production Python entrypoints and remaining generated shell.
set -uo pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

cd "$SCRIPT_ROOT" || exit 1

realpath_hits=$(rg -n 'realpath[[:space:]]+--relative-to|readlink[[:space:]]+-f' bin lib 2>/dev/null || true)
assert_eq "" "$realpath_hits" "production code does not require GNU realpath/readlink"
find_printf_hits=$(rg -n 'find[^\n]*[[:space:]]-printf[[:space:]]' bin lib 2>/dev/null || true)
assert_eq "" "$find_printf_hits" "production code does not use non-portable find -printf"

shell_entrypoints=""
while IFS= read -r candidate; do
  first=$(head -1 "$candidate" 2>/dev/null || true)
  case "$first" in *bash*) shell_entrypoints="${shell_entrypoints}${shell_entrypoints:+$'\n'}$candidate" ;; esac
done < <(find bin lib .agents -type f -perm -111)
assert_eq "" "$shell_entrypoints" "production entrypoints contain no Bash implementations"

python3 -m compileall -q bin lib .agents/skills/ff-bsan/scripts
assert_eq 0 $? "all production Python entrypoints compile"

for script in bin/audit bin/audit-recon bin/benchmark bin/hits bin/probe \
  bin/run-asan bin/run-msan bin/run-tsan bin/run-ubsan bin/setup-target bin/validate-finding; do
  first=$(head -1 "$script")
  assert_match 'python3' "$first" "$script uses the Python runtime"
done

teardown_test_env
summary
