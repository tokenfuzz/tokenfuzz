#!/usr/bin/env bash
# Build the sample-c-uninit GAU frame decoder with MemorySanitizer.
#
# MSan only answers for bytes produced by instrumented code, so this recipe
# compiles the whole (self-contained, dependency-free) target in one clang
# invocation and links nothing else. -fsanitize-memory-track-origins=2 makes
# the report name the stack slot the uninitialized value came from, which is
# the difference between "somewhere in this frame" and a located bug. -O0
# keeps every handler frame on the sanitizer stack (no inlining) so a report
# names the planted function directly, and -fno-omit-frame-pointer keeps that
# frame at the top.
#
# MSan has no Darwin runtime — upstream clang supports it on Linux (and a few
# other hosts) only. Refuse the build loudly when the host compiler cannot take
# the flag: silently dropping it would produce an uninstrumented binary that
# reads as a clean run of the very bug this target plants.
set -euo pipefail

src="${1:?source root required}"
build="${2:?build dir required}"

cc_bin="${CC:-clang}"
if ! command -v "$cc_bin" >/dev/null 2>&1; then
  cc_bin="cc"
fi

probe_dir="$(mktemp -d)"
trap 'rm -rf "$probe_dir"' EXIT
printf 'int main(void) { return 0; }\n' >"$probe_dir/probe.c"
if ! "$cc_bin" -fsanitize=memory "$probe_dir/probe.c" -o "$probe_dir/probe" \
    >"$probe_dir/probe.log" 2>&1; then
  {
    echo "sample-c-uninit: $cc_bin cannot compile and link -fsanitize=memory on" \
         "$(uname -s) $(uname -m)."
    echo "MemorySanitizer needs a clang with an MSan runtime for this host;" \
         "there is no Darwin runtime."
    echo "Compiler output:"
    sed 's/^/  /' "$probe_dir/probe.log"
  } >&2
  exit 1
fi

mkdir -p "$build"
"$cc_bin" \
  -O0 -g -fno-omit-frame-pointer \
  -fsanitize=memory -fsanitize-memory-track-origins=2 \
  -I"$src/include" \
  "$src/src/gauge.c" "$src/src/gauge_cli.c" \
  -o "$build/gauge"
