# Browser Targets

Browser targets use the same work queue, probe contract, triage gates, and
artifact layout as every other target. What changes is the product route: a
full browser needs a temporary profile and page input, while a JavaScript or
Wasm runtime usually behaves like a generic shell.

| Shape | `is_browser` | `{PROFILE}` in runner args | Execution |
| --- | --- | --- | --- |
| Full browser | `"1"` | yes | Browser/page route with browser agents. |
| JS/Wasm engine or browser-like runtime | `"1"` | no | Generic shell route with shell agents. |
| Ordinary library or CLI | `"0"` | no | Generic route. |

## Enable browser mode

`bin/setup-target` sets `is_browser = "1"` from a browser-specific build driver
such as `mach`, independent of the target slug. GN also builds shells and
general native projects, so select browser mode explicitly for a GN browser:

```bash
bin/setup-target my-gn-browser /path/to/source --browser --build
```

Both browser and generic targets share the same `build-asan/` layout.
`mach` writes its object directory there; CMake / autotools
targets install there with `-DCMAKE_INSTALL_PREFIX` or `--prefix`.
Inside `bin/audit-container-shell`, `AUDIT_BUILD_SUFFIX` makes the
actual build directory `build-asan-<image-id>/`; relative `build-asan/`
paths in `target.toml` resolve through that suffix.

Build a supported browser through the normal target setup path:

```bash
bin/setup-target firefox --build
bin/setup-target chromium --browser --build
```

Chromium and Chrome need a `depot_tools` checkout and register a nested source
slug; see
[Chromium and Chrome checkouts](../getting-started/add-a-target.md#chromium-and-chrome-checkouts)
before the first setup.

The generated recipe is stored under `targets/<target>/.audit/`, uses a clean
release-mode sanitizer object directory, and is reused by audit preflight when
the source moves. `mach` and GN are native adapters; neither adapter branches
on a target or product name. GN builds its graph's default target. Browser
projects with another build system can use `--browser` and provide the same
`.audit/build.sh <source> <build-dir>` contract.

The browser runner's `{PROFILE}` argument is the page-route declaration. A
browser-mode target without that token is treated as a script engine: it uses
the generic `asan_bin` / `[runner].args` contract and receives shell agents
only. This keeps `is_browser = "1"` useful for JIT- and GC-oriented runtimes
without trying to feed them HTML or browser command-line flags.

On non-bundle platforms, set the top-level `asan_bin` field when a browser
build emits multiple instrumented top-level executables. Setup accepts a sole
executable or a target-named product under `dist`; it does not guess among
ambiguous helpers by file size.

Existing browser object directories created outside TokenFuzz have no
`.audit-build-stamp`. The first setup or audit preflight therefore treats them
as stale and performs one clean build before recording freshness; it does not
assume an untracked binary matches the current source revision.

The source tree must already be complete enough for its native driver. In
particular, a GN checkout that uses an external dependency client must be
synced before setup; TokenFuzz does not replace project-specific source
bootstrap tooling.

Coverage gating (`bin/hits`) currently speaks only the Firefox command line
and looks for `dist/Nightly.app/Contents/MacOS/XUL` on macOS or
`dist/bin/libxul.so` on Linux — override with `COV_XUL`. Other browser targets
run without the coverage pre-check; every probe spends a sanitizer run
directly.

## Attacker surface

Browser threat models typically include:

- `bytes` — web content;
- `call-sequence` — Web API call order;
- `timing` — event-loop, GC, JIT tier-up.

Add `protocol-state` only if the target genuinely accepts adversarial
network state.

Triage uses `attacker_controls` when deciding whether a reproducible defect is
security-reportable through a normal product boundary. Keep it tight. A crash
that needs a browser-only setup no real page or script can recreate may remain
as `not-reportable` engineering evidence, but it receives no security score.

## Keep reports product-reachable

Browser targets expose rich controls, but a crash report still needs
a product path. That means one of:

- web content bytes;
- a Web API call sequence;
- JS or Wasm execution;
- event-loop or GC timing;
- protocol or resource-loading state.

If the observation is security-relevant but has no sanitizer reproducer, file a
substantive report under `findings/`. Do not manufacture a crash-only harness
state to move it into `crashes/`; the finding lane does not require a runnable
testcase.

## Validate before a long browser run

```bash
bin/audit --target <target> --backend <backend> 1
```

Check `logs/index.log` for the resolved product executable and mode, then
inspect the first scratch directory. A full browser route should create a fresh
profile for each probe. A script-engine route should not acquire browser flags
or a profile it never declared.
