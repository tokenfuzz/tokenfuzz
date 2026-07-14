#!/usr/bin/env bash
# Build the sample-rust reportkit CLI with AddressSanitizer.
#
# Rust ASan needs the nightly toolchain plus rust-src to rebuild std with
# instrumentation (-Zbuild-std), so this is a per-target opt-in recipe rather
# than the findings-only `cargo build --release` in lib/languages.py. The
# release profile keeps overflow-checks/debug-assertions off so a planted unsafe
# fault is a real memory error, not a debug panic; -Copt-level=0 keeps every
# reportkit frame un-inlined so a crash names the planted function; -Cub-checks
# is left off so the nightly get_unchecked precondition check does not turn the
# unsound read into a clean panic before ASan observes the out-of-bounds access.
set -euo pipefail

src="${1:?source root required}"
build="${2:?build dir required}"

toolchain="${RUST_ASAN_TOOLCHAIN:-nightly}"
if ! rustc "+${toolchain}" -vV >/dev/null 2>&1; then
  echo "sample-rust ASan build needs the '${toolchain}' toolchain (rustup toolchain install ${toolchain})" >&2
  exit 1
fi
triple="$(rustc "+${toolchain}" -vV | sed -n 's/^host: //p')"
if [ -z "$triple" ]; then
  echo "could not determine host target triple from rustc +${toolchain}" >&2
  exit 1
fi
# -Zbuild-std rebuilds std from source; install rust-src once if it is absent.
if command -v rustup >/dev/null 2>&1; then
  rustup component add rust-src --toolchain "$toolchain" >/dev/null 2>&1 || true
fi

mkdir -p "$build"
export RUSTFLAGS="-Zsanitizer=address -Copt-level=0 -Cdebug-assertions=off -Coverflow-checks=off -Cforce-frame-pointers=yes"
cargo "+${toolchain}" build --manifest-path "$src/Cargo.toml" \
  --release -Zbuild-std --target "$triple"
cp "$src/target/${triple}/release/sample-rust" "$build/sample-rust"
