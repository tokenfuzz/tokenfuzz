#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: build.sh [--binaries] [asan|ubsan|msan|coverage|all ...]

Examples:
  bash .agents/skills/ff-bsan/scripts/build.sh asan
  bash .agents/skills/ff-bsan/scripts/build.sh msan
  bash .agents/skills/ff-bsan/scripts/build.sh --binaries asan ubsan msan
  bash .agents/skills/ff-bsan/scripts/build.sh all

Environment:
  FIREFOX_ROOT  Firefox source path, default targets/firefox
  PYTHON        Python executable, default python3.12
  BUILD_MODE    build or binaries, default build
USAGE
}

mode="${BUILD_MODE:-build}"
kinds=()
optional_msan=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --binaries) mode="binaries" ;;
    --build) mode="build" ;;
    -h|--help) usage; exit 0 ;;
    all) kinds+=(asan ubsan msan coverage); optional_msan=1 ;;
    asan|ubsan|msan|coverage) kinds+=("$1") ;;
    *) echo "unknown sanitizer build: $1" >&2; usage; exit 2 ;;
  esac
  shift
done

if [ "${#kinds[@]}" -eq 0 ]; then
  kinds=(asan)
fi

case "$mode" in
  build) mach_args=(build) ;;
  binaries) mach_args=(build binaries) ;;
  *) echo "BUILD_MODE must be build or binaries" >&2; exit 2 ;;
esac

python="${PYTHON:-python3.12}"
target_root="${FIREFOX_ROOT:-targets/firefox}"
clobber_re='Clobbering can be performed automatically|The CLOBBER file has been updated'

resolve_llvm_prefix() {
  local prefix clang_path
  if [ -n "${LLVM_PREFIX:-}" ] && [ -x "${LLVM_PREFIX}/bin/clang" ]; then
    printf '%s\n' "$LLVM_PREFIX"
    return 0
  fi
  for prefix in /opt/homebrew/opt/llvm /usr/local/opt/llvm /usr/lib/llvm-* /usr/local; do
    if [ -x "${prefix}/bin/clang" ]; then
      printf '%s\n' "$prefix"
      return 0
    fi
  done
  clang_path=$(command -v clang 2>/dev/null || true)
  if [ -n "$clang_path" ]; then
    prefix="$(cd "$(dirname "$clang_path")/.." && pwd)"
    if [ -x "$prefix/bin/clang" ]; then
      printf '%s\n' "$prefix"
      return 0
    fi
  fi
  return 1
}

msan_supported() {
  local llvm_prefix tmp rc
  llvm_prefix="$(resolve_llvm_prefix)" || return 1
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/ff-bsan-msan-check.XXXXXX")" || return 1
  printf 'int main(void) { return 0; }\n' \
    | "${llvm_prefix}/bin/clang" -fsanitize=memory -x c - -o "$tmp/a.out" >"$tmp/check.log" 2>&1
  rc=$?
  if [ "$rc" -ne 0 ]; then
    sed 's/^/msan preflight: /' "$tmp/check.log" >&2
  fi
  rm -rf "$tmp"
  return "$rc"
}

run_mach() {
  local mozconfig="$1"
  shift
  if [ "$mozconfig" = ".mozconfig" ]; then
    (cd "$target_root" && "$python" ./mach "$@")
  else
    (cd "$target_root" && MOZCONFIG="$mozconfig" "$python" ./mach "$@")
  fi
}

require_config() {
  local name="$1" mozconfig="$2"
  shift 2
  test -f "$target_root/$mozconfig" || {
    echo "missing $target_root/$mozconfig for $name" >&2
    exit 1
  }
  (cd "$target_root" && "$@") || {
    echo "$mozconfig has the wrong flags for $name" >&2
    exit 1
  }
}

ensure_msan_config() {
  local mozconfig="$target_root/.mozconfig-msan"
  if [ -f "$mozconfig" ]; then
    return 0
  fi

  local llvm_prefix
  llvm_prefix="$(resolve_llvm_prefix)" || {
    echo "could not locate LLVM clang for MSan config; set LLVM_PREFIX" >&2
    exit 1
  }

  cat > "$mozconfig" <<EOF
mk_add_options MOZ_OBJDIR=@TOPSRCDIR@/build-msan

export PATH="${llvm_prefix}/bin:/usr/bin:/usr/local/bin:\$PATH"

LLVM_PREFIX="${llvm_prefix}"
export CC="\${LLVM_PREFIX}/bin/clang"
export CXX="\${LLVM_PREFIX}/bin/clang++"
mk_add_options "export LIBCLANG_PATH=\${LLVM_PREFIX}/lib"

ac_add_options --enable-memory-sanitizer
ac_add_options --disable-jemalloc
ac_add_options --enable-fuzzing

ac_add_options --enable-optimize="-O2"
ac_add_options --disable-debug
ac_add_options --enable-debug-symbols

ac_add_options --disable-crashreporter
ac_add_options --without-wasm-sandboxed-libraries
ac_add_options --enable-js-shell
EOF
  echo "created $mozconfig"
}

has_symbol() {
  # Use grep -c (counts all matches, reads full stdin) instead of grep -q
  # (exits on first match). Under set -euo pipefail, grep -q causes nm to
  # receive SIGPIPE and exit 141, which pipefail reports as failure even
  # when the symbol is present. grep -c avoids the race.
  local bin="$1" pattern="$2" count
  count=$(nm "$bin" 2>/dev/null | grep -c "$pattern" || true)
  [ "${count:-0}" -gt 0 ]
}

verify_build() {
  local name="$1"
  case "$name" in
    asan)
      local browser="$target_root/build-asan/dist/Nightly.app/Contents/MacOS/firefox"
      test -x "$browser" || browser="$target_root/build-asan/dist/bin/firefox"
      test -x "$browser" || { echo "ASan browser missing" >&2; exit 1; }
      has_symbol "$browser" "__asan_" || { echo "ASan browser not instrumented" >&2; exit 1; }
      has_symbol "$target_root/build-asan/dist/bin/js" "__asan_" || { echo "ASan JS shell not instrumented" >&2; exit 1; }
      ;;
    ubsan)
      local browser="$target_root/build-ubsan/dist/Nightly.app/Contents/MacOS/firefox"
      test -x "$browser" || browser="$target_root/build-ubsan/dist/bin/firefox"
      test -x "$browser" || { echo "UBSan browser missing" >&2; exit 1; }
      test -f "$target_root/build-ubsan/dist/bin/js" || { echo "UBSan JS shell missing" >&2; exit 1; }
      ;;
    msan)
      local browser="$target_root/build-msan/dist/Nightly.app/Contents/MacOS/firefox"
      test -x "$browser" || browser="$target_root/build-msan/dist/bin/firefox"
      test -x "$browser" || { echo "MSan browser missing" >&2; exit 1; }
      test -f "$target_root/build-msan/dist/bin/js" || { echo "MSan JS shell missing" >&2; exit 1; }
      ;;
    coverage)
      local xul="$target_root/build-asan-cov/dist/Nightly.app/Contents/MacOS/XUL"
      test -f "$xul" || xul="$target_root/build-asan-cov/dist/bin/libxul.so"
      test -f "$xul" || { echo "coverage XUL/libxul missing" >&2; exit 1; }
      local cov_count
      cov_count=$( (otool -l "$xul" 2>/dev/null || readelf -WS "$xul" 2>/dev/null) | grep -c "__sancov_guards" || true)
      [ "${cov_count:-0}" -gt 0 ] || { echo "coverage build lacks sancov guards" >&2; exit 1; }
      ;;
  esac
}

build_one() {
  local name="$1" mozconfig objdir log
  case "$name" in
    asan)
      mozconfig=".mozconfig"
      objdir="build-asan"
      log="/tmp/ff-bsan-asan.log"
      require_config "$name" "$mozconfig" \
        sh -c 'grep -q enable-address-sanitizer .mozconfig && grep -q enable-fuzzing .mozconfig && grep -q disable-debug .mozconfig'
      ;;
    ubsan)
      mozconfig=".mozconfig-ubsan"
      objdir="build-ubsan"
      log="/tmp/ff-bsan-ubsan.log"
      require_config "$name" "$mozconfig" \
        sh -c 'grep -q enable-undefined-sanitizer .mozconfig-ubsan && grep -q enable-fuzzing .mozconfig-ubsan && grep -q disable-debug .mozconfig-ubsan'
      ;;
    msan)
      mozconfig=".mozconfig-msan"
      objdir="build-msan"
      log="/tmp/ff-bsan-msan.log"
      ensure_msan_config
      require_config "$name" "$mozconfig" \
        sh -c 'grep -q enable-memory-sanitizer .mozconfig-msan && grep -q enable-fuzzing .mozconfig-msan && grep -q disable-debug .mozconfig-msan'
      if ! msan_supported; then
        echo "MSan is not supported by the selected LLVM clang on this host" >&2
        if [ "$optional_msan" -eq 1 ]; then
          echo "skipping msan requested through all; continue with remaining builds" >&2
          return 0
        fi
        exit 1
      fi
      ;;
    coverage)
      mozconfig=".mozconfig-asan-cov"
      objdir="build-asan-cov"
      log="/tmp/ff-bsan-coverage.log"
      require_config "$name" "$mozconfig" \
        sh -c 'grep -q enable-address-sanitizer .mozconfig-asan-cov && grep -q build-asan-cov .mozconfig-asan-cov && grep -q trace-pc-guard .mozconfig-asan-cov && ! grep -E "^[^#]*ac_add_options.*enable-fuzzing" .mozconfig-asan-cov >/dev/null'
      ;;
  esac

  echo "building $name with $mozconfig -> $objdir"
  if ! run_mach "$mozconfig" "${mach_args[@]}" 2>&1 | tee "$log"; then
    if ! grep -qE "$clobber_re" "$log"; then
      exit 1
    fi
    echo "clobber required for $objdir; retrying once"
    run_mach "$mozconfig" clobber
    run_mach "$mozconfig" "${mach_args[@]}" 2>&1 | tee "$log"
  fi

  if [ "$name" != "coverage" ]; then
    run_mach "$mozconfig" gtest build 2>&1 | tee -a "$log"
  fi

  verify_build "$name"
}

for name in "${kinds[@]}"; do
  build_one "$name"
done
