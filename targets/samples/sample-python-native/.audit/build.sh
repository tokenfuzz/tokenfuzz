#!/usr/bin/env bash
# Build the reportnative AddressSanitizer harness for sample-python-native.
#
# An ASan-instrumented .so cannot be imported under a stock (non-ASan) Python —
# the runtime aborts on link order, and macOS SIP strips DYLD_INSERT_LIBRARIES —
# so ASan drives the extension's native C core (reportnative_core.c) through a
# standalone harness instead. -O0 keeps the pack_cells frame un-inlined so a
# crash names it and stops dead-store elimination from removing the planted
# out-of-bounds fill loop; the importable module itself is built by the Python
# bootstrap (setup.py) so the `native` op is reachable through the interpreter.
set -euo pipefail

src="${1:?source root required}"
build="${2:?build dir required}"

cc_bin="${CC:-clang}"
if ! command -v "$cc_bin" >/dev/null 2>&1; then
  cc_bin="cc"
fi

mkdir -p "$build"
"$cc_bin" \
  -O0 -g -fno-omit-frame-pointer -fsanitize=address \
  "$src/reportnative_harness.c" "$src/reportnative_core.c" \
  -o "$build/reportnative_harness"
