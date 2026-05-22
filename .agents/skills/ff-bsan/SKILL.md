---
name: ff-bsan
description: "Build Firefox sanitizer configurations. Use with asan, ubsan, msan, coverage, or all to rebuild build-asan, build-ubsan, build-msan, and/or build-asan-cov after source changes."
---

# Build Firefox Sanitizers

Build one or more Firefox sanitizer configurations under `targets/firefox`.

## Arguments

Use the requested build type from the user prompt:
- `asan`: `build-asan`, ASan + fuzzing. Default when no type is specified.
- `ubsan`: `build-ubsan`, UBSan + fuzzing.
- `msan`: `build-msan`, MSan + fuzzing.
- `coverage`: `build-asan-cov`, ASan + sancov, no fuzzing. This backs `bin/hits`.
- `all`: build `asan`, `ubsan`, `msan`, then `coverage` sequentially.

Use `--binaries` or `BUILD_MODE=binaries` for an incremental `mach build
binaries`; otherwise run the full `mach build`. Do not run multiple Firefox
`mach build` commands in parallel in the same source tree.

## Build Command

```bash
bash .agents/skills/ff-bsan/scripts/build.sh asan
bash .agents/skills/ff-bsan/scripts/build.sh ubsan
bash .agents/skills/ff-bsan/scripts/build.sh msan
bash .agents/skills/ff-bsan/scripts/build.sh coverage
bash .agents/skills/ff-bsan/scripts/build.sh all
bash .agents/skills/ff-bsan/scripts/build.sh --binaries asan ubsan msan
```

## Verification

ASan:
```bash
browser=targets/firefox/build-asan/dist/Nightly.app/Contents/MacOS/firefox
test -x "$browser" || browser=targets/firefox/build-asan/dist/bin/firefox
nm "$browser" 2>/dev/null | grep -q "__asan_" && echo "ASan browser OK: $browser"
nm targets/firefox/build-asan/dist/bin/js 2>/dev/null | grep -q "__asan_" && echo "ASan JS shell OK"
FUZZER=list bin/run-asan fuzz
```

UBSan:
```bash
browser=targets/firefox/build-ubsan/dist/Nightly.app/Contents/MacOS/firefox
test -x "$browser" || browser=targets/firefox/build-ubsan/dist/bin/firefox
test -x "$browser" && echo "UBSan browser OK: $browser"
test -f targets/firefox/build-ubsan/dist/bin/js && echo "UBSan JS shell OK"
```

MSan:
```bash
browser=targets/firefox/build-msan/dist/Nightly.app/Contents/MacOS/firefox
test -x "$browser" || browser=targets/firefox/build-msan/dist/bin/firefox
test -x "$browser" && echo "MSan browser OK: $browser"
test -f targets/firefox/build-msan/dist/bin/js && echo "MSan JS shell OK"
```

Coverage:
```bash
xul=targets/firefox/build-asan-cov/dist/Nightly.app/Contents/MacOS/XUL
test -f "$xul" || xul=targets/firefox/build-asan-cov/dist/bin/libxul.so
(otool -l "$xul" 2>/dev/null || readelf -WS "$xul" 2>/dev/null) | grep -q '__sancov_guards' && echo "sancov edges OK: $xul"
mkdir -p /tmp/ff-bsan-coverage-smoke && rm -f /tmp/ff-bsan-coverage-smoke/*.sancov
ASAN_OPTIONS="detect_leaks=0:coverage=1:coverage_dir=/tmp/ff-bsan-coverage-smoke:coverage_pcs=1" \
  bash -lc 'source lib/timeout.sh; b=targets/firefox/build-asan-cov/dist/Nightly.app/Contents/MacOS/firefox; test -x "$b" || b=targets/firefox/build-asan-cov/dist/bin/firefox; audit_timeout_run 8 "$b" about:blank --headless' 2>/dev/null || true
ls /tmp/ff-bsan-coverage-smoke/*.sancov 2>/dev/null | head -3
```

## Notes

- All configs must use `--disable-debug`; debug assertions hide release-build
  behavior that sanitizer audits need to observe.
- `coverage` intentionally omits `--enable-fuzzing`; libFuzzer intercepts
  sancov callbacks and prevents plain browser runs from writing `.sancov`.
- `msan` creates `targets/firefox/.mozconfig-msan` if it is missing. MSan
  builds are sensitive to uninstrumented dependencies; use `bin/run-msan` for
  JS shell, standalone fuzz, and generic harness modes. On hosts whose LLVM
  clang rejects `-fsanitize=memory`, explicit `msan` fails during preflight;
  `all` warns, skips MSan, and continues with the remaining builds.
- Build logs are `/tmp/ff-bsan-asan.log`, `/tmp/ff-bsan-ubsan.log`,
  `/tmp/ff-bsan-msan.log`, and `/tmp/ff-bsan-coverage.log`.
