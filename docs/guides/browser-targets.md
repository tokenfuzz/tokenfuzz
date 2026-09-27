# Browser targets

Use this page to audit a full browser (Firefox, Chromium, or another browser
build) or a standalone JavaScript engine or WebAssembly runtime. Only the
product route differs from other targets: a full browser loads each testcase
as a page in a fresh profile, while an engine or runtime is a shell that
takes the testcase as input.

The shortest safe path for each browser build:

```bash
# Firefox: an executable `mach` selects browser mode by itself.
bin/setup-target firefox /path/to/firefox --build

# Chromium: the bundled overlay fetches the gclient workspace and selects
# browser mode. Put depot_tools on PATH first.
bin/setup-target chromium --build

# Any other GN browser: GN also builds shells and plain native projects,
# so ask for browser mode explicitly.
bin/setup-target my-gn-browser /path/to/source --browser --build

# Then a one-worker smoke test.
bin/audit --target <target> --backend <backend> 1
```

Omit the source argument to re-inspect an existing `targets/<target>/`
checkout. Read
[Chromium and Chrome checkouts](../getting-started/add-a-target.md#chromium-and-chrome-checkouts)
before the first Chromium setup: it registers the nested target
`chromium/src`.

## Choose the route

| Target | `is_browser` | `{PROFILE}` in `[runner].args` | Route |
| --- | --- | --- | --- |
| Full browser | `"1"` | yes | Page route: each run gets a fresh temporary profile; browser and shell workers. |
| Script engine in browser mode | `"1"` | no | Generic shell route with shell workers only. |
| Library, CLI, or standalone engine or runtime | `"0"` | no | Generic native route. |

`{PROFILE}` is what declares a page route; without it, no profile or browser
flags are invented. Write `is_browser` as `"1"` or `"0"`. Setup sets it to
`"1"` for a `mach` build driver and in the `chromium` and `chrome` overlays;
for any other build system pass `--browser`, or `--no-browser` to turn it
off.

### What browser mode changes

Compared with a generic target, `is_browser = "1"`:

- seeds `attacker_controls = ["bytes", "call-sequence", "timing"]` instead of
  the byte-only default;
- detects the product executable for `asan_bin`, and leaves the field unset
  for you to fill in rather than guess among several candidates;
- skips build widening and the `build-asan+cov` and `build-asan+fuzz`
  siblings that native targets get;
- makes audit preflight run a product canary before any worker starts: a
  page that must load in the browser on the page route, or a `.js` file that
  calls `print('TESTCASE_EXECUTED')` on the shell route;
- lets a page route run browser workers beside shell workers (see
  `BROWSER_AGENTS` and `SHELL_AGENTS` in the
  [environment reference](../reference/environment.md));
- limits maintainer bundles to `.html`, `.htm`, `.xhtml`, `.svg`, `.js`, and
  `.mjs` testcases.

### Script engines and Wasm runtimes

Several browser-mode paths assume a Firefox build, whose JavaScript shell is
`build-asan/dist/bin/js`. For any other engine or runtime, check these limits
before choosing browser mode:

- The shell canary is JavaScript, so a runtime must execute a `.js` file that
  calls `print`.
- With `asan_bin` set, `bin/probe` runs `asan_bin <testcase>` and ignores
  `[runner].args` on a browser-mode target, although the preflight canary
  applies them.
- A crash whose testcase is not `.html`, `.htm`, `.xhtml`, `.svg`, `.js`, or
  `.mjs` (a `.wasm` module, for example) cannot be exported, so its bundle
  stays incomplete and triage eventually rejects it.
- The exported `reproduce.sh` for a `.js` crash runs `build-asan/dist/bin/js`,
  the Firefox layout, whatever shell the target actually uses.

When one of these applies, configure the engine or runtime as a generic
native target instead: `is_browser = "0"`, the instrumented shell as
`asan_bin`, its argument list in `[runner].args`, and `attacker_controls` set
by hand (for example `["bytes", "call-sequence", "timing"]`). See
[Target configuration](configure-target.md).

## Build the browser

`bin/setup-target --build` writes the build recipe to `.audit/build.sh`
under the source root and builds into a clean `build-asan/`. Audit preflight
reuses the recipe and rebuilds when the source or recipe changes. Plain
`bin/setup-target` writes configuration but does not build.

| Driver | Generated recipe |
| --- | --- |
| `mach` | A `.mozconfig` for an optimized sanitizer build with fuzzing interfaces, the JS shell, and line-table debug info, and with debug builds, jemalloc, and the crash reporter off. |
| GN | `gn gen` with `is_asan=true is_debug=false dcheck_always_on=false symbol_level=1`, then `autoninja` (or `ninja`) for the graph's default target. |
| Chromium overlay | The same GN arguments, building the `chrome` target from the gclient workspace. |
| Anything else | Pass `--browser` and supply `.audit/build.sh <source> <build-dir>` yourself. |

The source tree must already be complete for its driver: a GN checkout that
uses an external dependency client must be synced before setup. An object
directory created outside TokenFuzz has no build stamp, so the first setup
or audit preflight treats it as stale and does one clean build.

Inside `bin/audit-container-shell`, the physical build directory is
`build-asan-<image-id>/`, and relative `build-asan/` paths in `target.toml`
resolve through that suffix.

## How a page probe runs

`bin/probe` picks the mode from the testcase extension:

| Testcase | Page route | Script-engine route |
| --- | --- | --- |
| `.html`, `.htm`, `.xhtml`, `.svg` | `browser` mode | `browser` mode, which fails: the target declares no page route |
| `.js`, `.mjs` | `js` mode: the JS shell at `build-asan/dist/bin/js` (`ASAN_JS` overrides it for ASan) | `generic` mode: `asan_bin <testcase>` |
| Anything else | `browser` mode | `generic` mode |

A `MODE:` header or `bin/probe --mode` overrides the choice. Browser mode
supports only the `asan` and `ubsan` sanitizers. `js` mode expects the shell
a Firefox build produces; for a browser without one, use page testcases.

Each browser-mode run creates a fresh temporary profile, expands `{PROFILE}`
to it, and passes the testcase as a `file://` URL. Setup seeds the launch
arguments from the build driver:

| Driver | Seeded `[runner].args` |
| --- | --- |
| `mach` | `--profile {PROFILE} --no-remote {TESTCASE}`, plus a prefs file in the profile and headless mode |
| GN | `--user-data-dir={PROFILE} --no-first-run --no-default-browser-check --headless=new --dump-dom --enable-logging=stderr --no-sandbox {TESTCASE}`, plus `--use-mock-keychain` on macOS |

On Linux the GN route also sets `G_SLICE=always-malloc`,
`NSS_DISABLE_ARENA_FREE_LIST=1`, and `NSS_DISABLE_UNLOAD=1` in
`[runner].env`. The run deadline is `ASAN_TIMEOUT` (15 seconds by default).

The browser writes sanitizer reports to dedicated log files, and the probe
reads the crash only from there. `--no-sandbox` keeps renderer processes able
to write those files, so the audit's own isolation is the boundary. Page
output cannot forge a crash: when the launch arguments dump the DOM, as the
GN defaults do, sanitizer-looking text in it is neutralised.

### Coverage gating

Browser-mode coverage gating (`bin/hits --mode browser`) is Firefox-specific.
It needs a separately prepared `build-asan-cov/` tree, which TokenFuzz does
not build, and reads coverage from its `libxul` (`COV_XUL` and `COV_BROWSER`
override the paths). When that tree is missing, as it is for Chromium, the
gate records `COVERAGE_ENV_FAIL` and the sanitizer run proceeds ungated.

When the gate runs and the testcase misses the code named in its `TARGET:`
header, the sanitizer run is skipped in `browser` and `js` modes. Revise the
testcase rather than rerunning it.

## Attacker surface and reachable reports

Browser threat models typically include `bytes` (web content),
`call-sequence` (Web API call order), and `timing` (event-loop, GC, and JIT
tier-up timing). Add `protocol-state` only if the target really accepts
adversarial network state.

Triage compares a reproducible crash's trigger with `attacker_controls`.
When reviewers place the trigger outside it, for example setup that no real
page or script can recreate, the crash is rejected with a `threat-model:`
reason and receives no security score; see
[Triage and review](triage-results.md#common-rejection-reasons).

A crash report needs a product path: web content bytes, a Web API call
sequence, JS or Wasm execution, event-loop or GC timing, or protocol or
resource-loading state. If an observation is security-relevant but has no
sanitizer reproducer, file a substantive report under `findings/`, which
does not require a runnable testcase. Do not manufacture a crash-only harness
state to move it into `crashes/`.

## Validate before a long browser run

```bash
bin/audit --target <target> --backend <backend> 1
```

The run starts one worker: a browser worker on a page route, a shell worker
otherwise. Its preflight canary must observe the product executing, or the
audit stops before any worker starts. On a page route, if the configured
`asan_bin` fails the canary but setup's product detection finds a different
executable that passes, preflight rewrites `asan_bin` in
`output/<target>/target.toml` and logs the repair in `logs/index.log`.

Then check the pinned `output/<target>/<backend>/results/.target.toml` for
the resolved `asan_bin`, `is_browser`, and `[runner].args`, and inspect the
first scratch directory. A page route should create a fresh profile for each
run; a script-engine route should not acquire browser flags or a profile.
