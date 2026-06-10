#!/usr/bin/env bash
# Build the canary ground-truth target with AddressSanitizer.
#
# Asserts stay ENABLED (no -DNDEBUG): the debug-only-assert trap relies on
# the assert firing so the pipeline classifies it as a non-security ABRT
# rather than a real overflow. -fno-omit-frame-pointer keeps the planted
# bug's own frame at the top of the sanitizer stack so the ground-truth
# manifest can match it by symbol.
set -euo pipefail

src="${1:?source root required}"
build="${2:?build dir required}"

cc_bin="${CC:-clang}"
if ! command -v "$cc_bin" >/dev/null 2>&1; then
  cc_bin="cc"
fi

mkdir -p "$build"
"$cc_bin" \
  -O1 -g -fno-omit-frame-pointer -fsanitize=address \
  -I"$src/src" \
  "$src/src/canary.c" \
  -o "$build/canary"
