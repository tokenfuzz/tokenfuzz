#!/usr/bin/env bash
set -eu

src="$1"
build="$2"
if [ "$(uname -s)" = Darwin ] && [ -d /Applications/Xcode.app/Contents/Developer ]; then
    export DEVELOPER_DIR="${DEVELOPER_DIR:-/Applications/Xcode.app/Contents/Developer}"
    xcrun --find metal >/dev/null 2>&1 || {
        echo "Chromium requires Xcode with the Metal toolchain" >&2
        exit 1
    }
fi
export PATH="$src/third_party/depot_tools:$PATH"
export DEPOT_TOOLS_UPDATE=0
mkdir -p "$build"
gn_bin=""
for candidate in "$src"/buildtools/*/gn "$src"/buildtools/gn; do
    if [ -x "$candidate" ]; then
        gn_bin="$candidate"
        break
    fi
done
[ -n "$gn_bin" ] || { echo "gn: command not found" >&2; exit 127; }
"$gn_bin" gen "$build" --root="$src" \
    --args='is_asan=true is_debug=false dcheck_always_on=false symbol_level=1'
autoninja -C "$build" chrome
