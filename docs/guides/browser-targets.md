# Browser Targets

Browser targets use the same harness contract as generic targets, but
their build layout and threat surface are different.

Use browser mode for:

- browsers;
- script engines;
- browser-like runtimes — anything with HTML, JS, event-loop, GC, or
  JIT behaviour.

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

The browser runner's `{PROFILE}` argument is also the page-route declaration.
A browser-mode target without that token is treated as a script engine: it
uses the generic `asan_bin` / `[runner].args` contract and receives shell
agents only. This keeps `is_browser = "1"` useful for JIT- and GC-oriented
runtimes without trying to feed them HTML or browser command-line flags.

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

Triage uses `attacker_controls` to decide whether a crash trigger is
reachable through a normal product input boundary. **Keep it tight.**
A browser-only setup that no real web page can recreate does not
belong in `crashes/`.

## Keep reports product-reachable

Browser targets expose rich controls, but a crash report still needs
a product path. That means one of:

- web content bytes;
- a Web API call sequence;
- JS or Wasm execution;
- event-loop or GC timing;
- protocol or resource-loading state.

If the observation is security-relevant but not crash-reproducible or
not web-reachable, it belongs in `findings/` with the right boundary
language — not in `crashes/`.
