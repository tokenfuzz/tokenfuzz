#!/usr/bin/env bash
# Build the sample-c RCF decoder with AddressSanitizer.
#
# Asserts stay ENABLED (no -DNDEBUG): the CHECK field's debug-only invariant
# relies on assert() firing so an over-long CHECK field is reported as a
# non-security ABRT rather than a memory-safety overflow. -O0 keeps every
# handler frame on the sanitizer stack (no inlining) so a crash names the
# planted function directly, and -fno-omit-frame-pointer keeps that frame at
# the top of the report.
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
  -I"$src/include" \
  "$src/src/rcfg.c" "$src/src/rcfg_cli.c" \
  -o "$build/rcfg"
