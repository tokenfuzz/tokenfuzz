#!/usr/bin/env bash
# Regression tests for the Python Firefox sanitizer build helper.
set -o pipefail
source "$(dirname "$0")/helpers.sh"
setup_test_env

BUILD_PY="$SCRIPT_ROOT/.agents/skills/ff-bsan/scripts/build.py"
assert_file_exists "$BUILD_PY" "build.py present"
assert_file_contains "$BUILD_PY" 'def llvm_prefix' "ff-bsan resolves LLVM dynamically"
assert_file_contains "$BUILD_PY" 'clobber required for' "ff-bsan retries clobber-required builds"
assert_file_contains "$BUILD_PY" 'def msan_supported' "ff-bsan preflights MSan"
assert_file_contains "$BUILD_PY" 'skipping msan requested through all' "ff-bsan all mode tolerates unavailable MSan"
assert_file_not_contains "$BUILD_PY" 'LLVM_PREFIX="/opt/homebrew/opt/llvm"' "generated config does not hardcode Homebrew LLVM"

CBIN="$TEST_TMPDIR/many_syms"
SRC="$TEST_TMPDIR/many_syms.c"
{
  echo '#include <stdio.h>'
  for i in $(seq 1 100); do echo "int __probe_marker_${i}(void){return ${i};}"; done
  echo 'int main(void){return 0;}'
} > "$SRC"
cc -O0 -o "$CBIN" "$SRC" || fail "could not compile fixture binary"

PYTHONPATH="$SCRIPT_ROOT/.agents/skills/ff-bsan/scripts" python3 - "$CBIN" <<'PY'
import sys
from pathlib import Path
from build import has_symbol
binary = Path(sys.argv[1])
assert has_symbol(binary, b"__probe_marker_1")
assert not has_symbol(binary, b"__definitely_absent")
PY
assert_eq 0 $? "has_symbol handles present and absent symbols without a pipeline"

teardown_test_env
summary
