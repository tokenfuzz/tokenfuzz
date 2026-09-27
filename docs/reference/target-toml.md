# Target config reference

Each target has one reviewed configuration file,
`output/<target>/target.toml`. This page is the exact contract for its
fields, tokens, defaults, and path rules. For the review workflow and the
reasoning behind each value, read the
[target configuration guide](../guides/configure-target.md).

```bash
bin/setup-target <target> <repo-url>   # clone the source and generate the file
bin/setup-target <target>              # re-inspect; a reviewed file is kept
```

`bin/audit --target <target>` also generates the file when it is missing.

## Where the file lives

| Run | Configuration it reads |
| --- | --- |
| `bin/audit --target <target>` | `output/<target>/target.toml` |
| `bin/audit --target <target> --experiment <name>` | `output/<target>-<name>/target.toml`, copied from `output/<target>/target.toml` the first time it is missing. Later edits to the base file do not reach the copy. |
| `bin/audit --target-path <dir>` | `output/<basename of dir>/target.toml`, generated when missing. |

A slug can contain `/`: `samples/sample-python` reads
`output/samples/sample-python/target.toml`.

A running audit reads a pinned copy, so edit the shared file between runs;
see [Session snapshot and revision](#session-snapshot-and-revision).

### When setup rewrites the file

`bin/setup-target` keeps a reviewed file and regenerates it only in these
cases:

| Condition | Result |
| --- | --- |
| The file is missing. | Generated from detection. |
| The file does not parse as TOML. | Regenerated from detection. Nothing is carried over, because nothing could be read. |
| `--force` | Regenerated, carrying over the values listed below. |
| An active (uncommented) value still contains `FILL_ME`, and `--build` was not passed. | Regenerated, carrying over the values listed below. `upstream_url = "FILL_ME"` does not count on a target whose tree is not a Git or Mercurial checkout. With `--build`, add `--force` to regenerate. |
| `--build`, detection now finds a different `build_system`, and the file sets neither `[runner]` `bin` or `args` nor a top-level `asan_bin` or `asan_lib`. | Regenerated, carrying over the values listed below. |

A regeneration carries over `[threat_model].attacker_controls`, the whole
`[s6_peers]` table, `build_widening` and every `[[build_config]]` row, a
`[runner]` table that sets `bin` or `args`, `[sanitizer].enabled`, and every
configured `<san>_bin` and `<san>_lib`. It carries over `build_system` and
`upstream_url` only when detection finds nothing to replace them. Any other
hand edit is lost.

After a regeneration from a missing, unparsable, forced, or re-detected
file (not a `FILL_ME` refresh), setup runs
`bin/suggest-threat-model --apply --force`, which replaces the carried-over
`attacker_controls` whenever a model backend answers, and
`bin/suggest-peers --apply`, which overwrites `[s6_peers]` only under
`--force`. `--no-llm-config` skips both. Setup flags are in
[Commands](commands.md).

A kept file still gets these surgical updates on every setup run of a
native target:

- `<san>_bin` and `<san>_lib` are checked against the build trees on disk
  and corrected when stale ([rules](#execution-artifacts)).
- Public include roots and published link dependencies found in the build
  are merged into `includes` and `link_libs`.
- `defines` gains the build's dominant C++ `-std=` flag when it has none.
- `--browser` or `--no-browser` rewrites only `is_browser`.

## Parsing rules

- The file is TOML. A syntax error stops `bin/audit`, while
  `bin/setup-target` regenerates an unparsable file and discards every edit.
  Check a hand edit before rerunning setup; the
  [guide](../guides/configure-target.md#validate-the-reviewed-config) has a
  one-line check.
- Unknown keys and tables are ignored without a warning. A value of the
  wrong type is ignored too, and the field keeps its default: for example,
  `includes = "include"` (a string, not an array) leaves `includes` empty.
  One exception: a non-boolean `build_widening`, such as the string
  `"true"`, turns widening off rather than keeping the default. Check
  spelling and types against this page.
- Unknown `attacker_controls` tokens and unknown sanitizer slugs are dropped
  with a warning on stderr.
- These fail loudly: an invalid `[sweep]` value, an invalid
  `[[build_config]]` row, or an invalid `source_subdir` when the file is
  loaded, and a relative path that climbs out of the source root when it is
  used.
- Python 3.11 and later use the standard `tomllib`. On Python 3.10 without
  the `tomli` package, a simplified parser accepts only strings, arrays of
  strings, and booleans, so integers such as `[runner].success_codes` or
  `[sweep]` numbers fail there.

## Path rules

- A relative path resolves under the target's source root:
  `targets/<target>/`, or `targets/<target>/<source_subdir>/` when
  `source_subdir` is set. An absolute path is used as written.
- A relative path must not climb out of the source root with `..`. Use an
  absolute path for a file outside the tree.
- A relative path whose first segment is `build-asan`, `build-ubsan`,
  `build-msan`, or `build-tsan` resolves through the active build suffix
  (`AUDIT_BUILD_SUFFIX`). Inside `bin/audit-container-shell` the suffix names
  the per-image tree (`build-asan-<image-id>/`); a selected
  [build configuration](#build-configurations) adds `+cfg-<id>`. Always
  write the canonical `build-<san>/...` form: setup treats a `<san>_bin` or
  `<san>_lib` that names a suffixed tree as stale and replaces it.
- When the file is loaded, an absolute path under the source root is
  rewritten as a relative one for `asan_bin`, `asan_lib`, the
  `[sanitizer]` binaries and libraries, and path entries in `link_libs`.

## A complete generic example

A generated native configuration after a successful build, with most
generated comments removed:

```toml
target        = "sampleproj"
upstream_url  = "https://example.org/sampleproj.git"
build_system  = "cmake"
build_widening = true

asan_bin      = "build-asan/sample-cli"
asan_lib      = "build-asan/libsample.a"
includes      = ["include", "build-asan/include", "build-asan"]
defines       = []
link_libs     = ["-lm", "-lpthread"]

is_browser    = "0"

[threat_model]
attacker_controls = ["bytes"]

[sanitizer]
enabled = ["asan"]
# ubsan_bin = "build-ubsan/sampleproj"
# ubsan_lib = "build-ubsan/FILL_ME.a"

[runner]
args          = ["{TESTCASE}"]
success_codes = [0, 1]
```

The `[runner]` table has no `bin`: it describes how the ASan binary
consumes a testcase and records exit 1 as a normal completion, the shape
`bin/suggest-runner` writes for a native CLI.

<span id="generated-fields-to-review"></span>

## Top-level fields

| Field | Type | When absent | Meaning |
| --- | --- | --- | --- |
| `target` | string | empty | Target slug. Setup writes the name passed to it; keep it equal to the `targets/` and `output/` directory names. `slug` is accepted as an alias. |
| `upstream_url` | string | empty | Upstream repository. Exported reproducers clone it and report source links are built from it. `FILL_ME` or empty means there is none. Setup writes the repository source passed to it, or reads the checkout's Git `origin` or Mercurial `default` path. |
| `source_subdir` | string | checkout root | Project root inside the checkout. It must be a non-empty relative path to an existing directory, without `..`, that stays inside the checkout. Setup writes it only when the checkout root has no build manifest and exactly one immediate child is buildable, or one buildable child is named after the target; several unmatched buildable children fail setup. |
| `build_system` | string | empty | Selects the build adapter, the seeded `[runner]`, the `reproduce.sh` build template, and whether native build widening applies. Detected values: `mach`, `gn`, `cmake`, `meson`, `autotools`, `cargo`, `go`, `swift`, `maven`, `gradle`, `kotlin`, `python`, `npm`, `bundler`, `composer`, `rlang`, `perl`; `unknown` when nothing matched. |
| `build_widening` | boolean | `true` for a non-browser `cmake`, `meson`, `autotools`, `mach`, or `gn` target; otherwise `false` | Adds one cached, widened ASan sibling build. Forced to `false` when `[sanitizer] enabled = []`. See [Build configurations](#build-configurations). |
| `asan_bin` | path | empty | ASan-instrumented executable for generic runs, or the product executable in browser mode. |
| `asan_lib` | path | empty | ASan-instrumented library linked into compiled C/C++ `HARNESS:` testcases. |
| `includes` | array of paths | `[]` | Include directories for harness builds, each passed as `-I <path>`. |
| `defines` | array of strings | `[]` | Compiler arguments for harness builds, passed verbatim: `-D` macros, `-std=` flags, and similar. |
| `link_libs` | array of strings | `[]` | Linker arguments and extra inputs for harness builds. See [Harness build inputs](#harness-build-inputs). |
| `cmake_target` | string | empty | CMake target passed as `--target` when an exported `reproduce.sh` falls back to the generic CMake build template. Ignored when the bundle inlines the audit's converged build recipe. |
| `is_browser` | string | `"0"` | `"1"` selects browser mode, `"0"` generic mode. A TOML boolean is converted to `"1"` or `"0"`; do not use other spellings. See [Browser mode](#browser-mode). |

`asan_bin` and `asan_lib` are top-level fields. Inside `[sanitizer]` the
loader ignores them.

### Execution artifacts

`bin/setup-target` detects `<san>_bin` and `<san>_lib` from the build
trees. Before the first build they are written as commented placeholders.
Each later setup run of a native target re-checks every field:

- A configured executable is kept when it is an executable file inside the
  matching `build-<san>/` tree, or an executable elsewhere whose sanitizer
  runtime symbols can be verified.
- A configured library is kept when the file exists and does not belong to a
  different sanitizer's build tree. A vendored or prebuilt instrumented
  library is therefore kept.
- A value is treated as stale, and replaced by detection or commented out,
  when its path is missing, names a suffixed build tree, passes through a
  build-internal directory (`CMakeFiles`, `test`, `tests`, `_deps`,
  `third_party`, `third-party`, `3rdparty`, `subprojects`), fails the checks
  above, or, in browser mode, names a helper executable rather than the
  product.

A generic CLI audit needs only a correct executable. Compiled API harnesses
need the selected sanitizer's library (`asan_lib`, or
`[sanitizer].ubsan_lib`, `msan_lib`, or `tsan_lib`) plus the harness inputs
below. An S4 fuzz campaign needs an enabled native sanitizer with a
library.

### Harness build inputs

A compiled C/C++ harness is compiled with `defines` and one `-I` per
`includes` entry, then linked against the selected sanitizer's library
followed by `link_libs`.

`link_libs` is an argument list, not a path list. An entry is resolved as a
target-relative path when it starts with `/` or `.`, contains a `/`, or ends
in a library, object, or source suffix (`.a`, `.so`, `.dylib`, `.tbd`, `.o`,
`.obj`, `.lo`, `.c`, `.cc`, `.cpp`, `.cxx`, `.m`, `.mm`, `.s`, `.asm`, or a
versioned `.so.N`). The value after `-L`, `-F`, `-isysroot`, or `--sysroot`
is resolved the same way. Every other entry, such as `-lm` or a bare
framework name after `-framework`, is passed unchanged. An entry containing
`$` is never resolved. A source file in `link_libs` is compiled into the
harness.

An entry inside a `build-<san>` tree is swapped for its twin in the tree of
the library actually linked, such as a coverage, fuzz, alternate, or
other-sanitizer build, when that twin exists.

Setup seeds `includes` from the source layout plus public include roots
from CMake or Meson install metadata, and seeds `link_libs` with
`["-lm", "-lpthread"]` plus what the build publishes; see
[C harness readiness](../guides/configure-target.md#c-harness-readiness).

### Header-only libraries

A header-only C++ library has no archive to link. Leave `asan_lib` as the
generated commented `FILL_ME` line, or set it to an empty string;
`includes`, `defines`, and `link_libs` apply as usual. Setup accepts a CMake
build that produced only headers as complete. An exported `reproduce.sh`
with no configured library links whatever instrumented library the build
produced, or nothing when there is none.

## Build configurations

The canonical `build-asan/` tree is always the regular-configuration
control. Build configurations add isolated ASan sibling trees; they never
replace the control or add UBSan, MSan, or TSan trees.

```toml
build_widening = true

[[build_config]]
name = "compact"
label = "compact table representation"
flags = ["-DENABLE_COMPACT=ON", "-DTABLE_BITS=8"]
features = ["compact tables"]
```

| Key | Type | Rule |
| --- | --- | --- |
| `name` | string | Required. A lowercase letter followed by up to 31 lowercase letters, digits, `_`, or `-`. Unique within the file. |
| `label` | string | Optional description. Defaults to `name`. |
| `flags` | array of strings | Configure arguments passed to the build recipe, in order. Each is a non-empty single line of at most 1024 characters. Order and duplicates are part of the configuration's identity. |
| `features` | array of strings | Surfaces the configuration adds, shown to agents assigned to it. |
| `widen` | boolean | `true` asks a model to derive the configuration from the primary recipe instead of from `flags`. |

A row needs either non-empty `flags` or `widen = true`, not both.

`build_widening = true` adds a row named `widened` with `widen = true`,
unless the file already declares one by that name. It enables the project's
advertised in-tree optional features while keeping the primary recipe's
sanitizer and build contract; with no such options, no sibling is built.

Each row's identity is `<name>-<10 hex digits>`, derived from `name`,
`flags`, and `widen`. Its tree is `build-asan+cfg-<identity>/` and its
recipe `.audit/configs/<identity>.asan.sh`, both under the source root.
Findings-only mode ignores build configurations. During an audit one
reproducer slot at a time rotates through the ready configurations while
the others stay on the control; benchmark runs use only the control.

## Sanitizers

`[sanitizer]` declares which sanitizers the target intentionally enables and
where each one's suppression file and extra options live. For when to enable
each one, see
[Sanitizer policy](../guides/configure-target.md#sanitizer-policy).

The supported slugs are `asan`, `ubsan`, `msan`, `tsan`, and `race` (Go's
runtime race detector). Slugs are case-insensitive and duplicates are
dropped. The order matters: `bin/probe` uses the first entry unless
`PROBE_SANITIZER` selects another enabled one (see
[Environment variables](environment.md)).

| `enabled` in the file | Effective policy |
| --- | --- |
| `[sanitizer]` or `enabled` absent | `["asan"]` |
| A list with at least one valid slug | The valid slugs, in order |
| A non-empty list with no valid slug | `["asan"]` |
| `enabled = []` | Findings-only mode: no sanitizer |

Setup writes an explicit policy: `["asan"]` for a native or unrecognised
build system, a browser, or a target where it found an ASan binary;
`["race"]` for Go and `["asan"]` for Swift, from the language registry; `[]`
for other language targets. A regeneration keeps an existing `enabled`
list.

### Findings-only mode (no sanitizer)

For a target with no sanitizer build, typically an interpreted or managed
language, set an explicit empty list:

```toml
[sanitizer]
enabled = []
```

With `enabled = []`:

- `bin/probe` selects the `runner` route and runs testcases through
  `[runner].bin`; a configured `asan_bin` is not used.
- Sanitizer option variables such as `ASAN_OPTIONS` are removed from the
  runner's environment.
- Language-runtime diagnostics (tracebacks, panics, uncaught exceptions) are
  routed to `findings/` as candidates rather than published as sanitizer
  crashes. A genuine sanitizer or race-detector report still goes to
  `crashes/`. See
  [Crash and finding routing](../guides/multi-language.md#crash-and-finding-routing).
- Build configurations and build widening are disabled.

### Per-sanitizer keys

| Key | Type | Meaning |
| --- | --- | --- |
| `enabled` | array of strings | The policy above. |
| `asan_suppressions`, `ubsan_suppressions`, `msan_suppressions`, `tsan_suppressions` | path | Suppression file, added to the runtime options as `suppressions=<absolute path>`. A missing file prints a warning and the run continues. |
| `asan_options`, `ubsan_options`, `msan_options`, `tsan_options` | string | Extra colon-separated runtime options. |
| `ubsan_bin`, `msan_bin`, `tsan_bin` | path | Instrumented executable for that sanitizer's generic runs. ASan uses top-level `asan_bin`. |
| `ubsan_lib`, `msan_lib`, `tsan_lib` | path | Instrumented library for that sanitizer's compiled harnesses. ASan uses top-level `asan_lib`. |

The runtime option variable (`ASAN_OPTIONS` and so on) is composed in this
order, and the last occurrence of a key wins: the harness defaults for the
run mode, `suppressions=...`, the `<san>_options` string, any value already
in the environment (including `[runner].env`), then harness invariants such
as `symbolize=0`.

`race` has no binary, library, suppression, or options key. It runs through
`[runner]`; set race-detector options with `GORACE` in `[runner].env`.

### Example

```toml
asan_bin = "build-asan/sample-cli"

[sanitizer]
enabled = ["asan", "msan"]
asan_suppressions  = "build-asan/asan-suppressions.txt"
msan_suppressions  = "build-msan/msan-suppressions.txt"
msan_bin           = "build-msan/sample-cli"
msan_lib           = "build-msan/libsample.a"
```

UBSan and TSan follow the same shape. Suppression paths follow the
[path rules](#path-rules).

`bin/probe` refuses a sanitizer that is not enabled. The standalone
runners (`bin/run-asan`, `bin/run-ubsan`, `bin/run-msan`, `bin/run-tsan`)
print a note and continue, so one-off debugging commands keep working.

## Language runner

`[runner]` describes how a testcase is invoked: through a language
interpreter or driver (`bin` set), as the argument template of a native
sanitizer executable (`args` without `bin`), or as browser launch arguments
in browser mode.

| Key | Type | When absent | Meaning |
| --- | --- | --- | --- |
| `bin` | string | empty | Interpreter, driver, or wrapper to run. A name is looked up on `PATH` first; otherwise the value is resolved as a path under the source root. It runs with the source root as its working directory, and testcase paths reach it as absolute paths. |
| `args` | array of strings | `[]` | Argument template. [Runner tokens](#runner-tokens) are expanded at run time. Non-string items are dropped. |
| `env` | array of `KEY=VALUE` strings | `[]` | Variables layered over the environment of every execution through the sanitizer runners, including native binaries and browser launches. Tokens are expanded. An entry without `=` is dropped. |
| `crash_patterns` | array of strings | `[]` | Extra Python regular expressions, searched one output line at a time, that make `bin/probe` report `CRASH`. They add to the built-in sanitizer and runtime markers; filing and triage still apply their own evidence rules. |
| `success_codes` | array of integers | `[0]` | Exit codes that mean the configured program completed normally. See below. |

`success_codes` rules:

- Accepted values are 0 to 123 and 160 to 255; others are silently dropped,
  and `0` is always included. Codes 124 to 159 belong to the timeout
  wrapper, exec failures, and deaths by POSIX signals 1 to 31. A program
  returning a negative error code from `main` exits with its low byte,
  often above that band.
- Output with a sanitizer diagnostic is a crash whatever the exit code.
- The set applies to the configured program only; a compiled `HARNESS:`
  testcase counts only `0` as success.
- `bin/setup-target` and `bin/suggest-runner` record the exit observed while
  validating a native CLI's input route. A nonzero code is recorded only
  after review confirms the program opened and rejected the disposable
  input, rather than failing in argument parsing or startup.

`bin` is optional. When it is set, `bin/audit` and `bin/benchmark` check it
before any model budget is spent, and stop on failure: it must resolve to an
executable file, a standard interpreter must run an empty program (build
tools print their version), and a runner that still matches the language
registry's own invocation must pass a canary testcase proving it reaches
the audited tree.

### How bin/probe chooses the program

For a generic run without a `HARNESS:` header:

1. **Sanitizer.** `PROBE_SANITIZER` when set, otherwise `runner` when
   `enabled = []`, otherwise the first entry of `enabled`.
2. **Sanitizer binary.** If that sanitizer has a configured binary
   (`asan_bin` or `[sanitizer].<san>_bin`), it runs. When `[runner].bin` is
   unset and the target is not in browser mode, `[runner].args` is its
   argument template.
3. **Configured runner.** Otherwise `[runner].bin` runs with
   `[runner].args`. The `runner` and `race` routes always take this path.
4. **No route.** With neither, nothing can run. A findings-only target
   without `bin` is audited by source review only; audit preflight logs that
   testcase execution is disabled.

A compiled `HARNESS:` testcase, and a direct source testcase that a compiled
language runner builds itself, run their own program; `[runner].args` does
not apply to them. In browser page mode the product is `asan_bin`, and
`[runner].args` are its launch arguments.

### Runner tokens

| Token | Expands to |
| --- | --- |
| `{TESTCASE}` | Absolute path of the testcase being run. In a browser page launch, a file testcase becomes its `file://` URL. |
| `{TARGET_ROOT}` | The source root: `targets/<target>/`, plus `source_subdir` when set. |
| `{RESULTS_DIR}` | This session's `results/` directory. |
| `{TARGET_SLUG}` | The target slug. |
| `{SANITIZER}` | The selected route: `asan`, `ubsan`, `msan`, `tsan`, `race`, or `runner`. |
| `{SWIFT_SANITIZER}` | The Swift spelling of the selected sanitizer: `address`, `undefined`, or `thread`. Any other route is a hard error, not an empty value. |
| `{NULL_DEVICE}` | The platform null device (`/dev/null`). |
| `{PROFILE}` | A fresh temporary browser profile directory. Valid only in browser execution; anywhere else it is an error. |

`{TESTCASE}` can stand alone or sit inside an argument, such as
`--input={TESTCASE}`. Present in `args`, it is replaced in place; absent,
the path is appended after the expanded arguments. Put it in `args`, not
`env`: generic runs expand it to an empty string in `env`.

### Examples

```toml
# Interpreted language, findings-only: interpreter plus development mode.
[sanitizer]
enabled = []

[runner]
bin            = "python3"
args           = ["{TESTCASE}"]
env            = [
  "PYTHONDEVMODE=1",
  "PYTHONPATH={TARGET_ROOT}:{TARGET_ROOT}/src:{TARGET_ROOT}/lib",
]
crash_patterns = ["Traceback \\(most recent call last\\):"]
```

```toml
# Native CLI that reads its input through a flag and needs an output sink.
asan_bin = "build-asan/sample-cli"

[runner]
args          = ["--input", "{TESTCASE}", "--output", "{NULL_DEVICE}"]
success_codes = [0, 2]
```

```toml
# Project wrapper script with its own crash marker.
[runner]
bin            = "./tools/run-testcase.sh"
args           = ["{TESTCASE}"]
crash_patterns = ['^DEFENSIVE-ASSERT-FAILED:']
```

`bin/setup-target` seeds `[runner]` from the language registry for the
detected build system. With no registry runner (native C/C++ or an unknown
build system), the block is written commented out. Per-ecosystem defaults,
including the Go, Rust, Swift, and Java routes, are in the
[language runners guide](../guides/multi-language.md). To print the
registry's current answer:

```bash
python3 lib/languages.py runner-block <build_system> --pretty
```

## Threat model

`[threat_model].attacker_controls` lists what an external actor can supply
through a normal product boundary. Every agent prompt includes it, and
triage compares each crash's required trigger with it: a defect that source
review confirms needs a control outside the list is rejected with a
`threat-model:` reason, and its evidence is kept. See
[Triage and review](../guides/triage-results.md).

| Token | Meaning |
| --- | --- |
| `bytes` | Input bytes: a file, stream, packet, archive, media, regular expression, or similar data. |
| `call-sequence` | The actor chooses which public API, script, plugin, or Web API calls run, and in what order. |
| `timing` | Event-loop scheduling, garbage-collection timing, JIT tier-up, or similar timing. |
| `race` | Thread or process interleaving. |
| `protocol-state` | State accumulated across several protocol messages. |
| `env` | Process environment variables. |
| `fs-state` | Filesystem paths, presence, permissions, or layout. |

Tokens are case-insensitive. `call-order` is accepted and normalised to
`call-sequence`. Unknown tokens are dropped with a warning. An absent or empty
list, or one with no valid token, becomes `["bytes"]`.

Setup seeds `["bytes"]` for a generic target and
`["bytes", "call-sequence", "timing"]` in browser mode, then, unless
`--no-llm-config` is given, asks `bin/suggest-threat-model` for a
target-specific list. To choose tokens, see
[Review the threat model](../guides/configure-target.md#review-the-threat-model).

## Browser mode

```toml
is_browser = "1"   # a browser or Firefox's JS shell; "0" for everything else
```

Setup sets `"1"` for a `mach` build, for a target overlay that declares a
browser, and when `--browser` is passed; a GN browser needs `--browser`.

A browser-mode target is a page browser when its `[runner].args` contain
`{PROFILE}`, or, when `args` is empty, when its build system has default
launch arguments:

| `build_system` | Default launch arguments |
| --- | --- |
| `mach` | `--profile {PROFILE} --no-remote {TESTCASE}` |
| `gn` | `--user-data-dir={PROFILE} --no-first-run --no-default-browser-check --headless=new --dump-dom --enable-logging=stderr --no-sandbox`, plus `--use-mock-keychain` on macOS, then `{TESTCASE}`. On Linux, setup also seeds `env` with `G_SLICE=always-malloc`, `NSS_DISABLE_ARENA_FREE_LIST=1`, and `NSS_DISABLE_UNLOAD=1`. |

Any other browser-mode target is a script engine: it gets the generic
route and shell agents only. Several script-engine paths assume Firefox's
shell layout, so configure other engines and Wasm runtimes with
`is_browser = "0"`; see
[Script engines and Wasm runtimes](../guides/browser-targets.md#script-engines-and-wasm-runtimes).
For another browser, set the launch arguments explicitly:

```toml
asan_bin = "build-asan/MyBrowser.app/Contents/MacOS/MyBrowser"

[runner]
args = ["--user-data-dir={PROFILE}", "--headless=new", "--dump-dom", "{TESTCASE}"]
```

See [Browser targets](../guides/browser-targets.md) for build drivers,
coverage, and product reachability.

## Strategy hints: `[s6_peers]`

`[s6_peers]` names upstream peer projects whose security fixes S6
(cross-project variant) work cards are mined from:

```toml
[s6_peers]
domain = "xml-parser"
peers  = ["libexpat", "Xerces-C++", "rapidxml"]
```

| Key | Type | Meaning |
| --- | --- | --- |
| `domain` | string | Short label for the problem domain. Informational. |
| `peers` | array of strings | Peer project names. Empty entries are dropped. |

The table is optional. Without peers there are no S6 peer cards, and a
run pinned with `--strategy S6` stops at startup. Re-derive it with
`bin/suggest-peers <target> --apply --force`. See the
[strategy model](../concepts/strategy-model.md).

## The budgeted sweep: `[sweep]`

`[sweep]` turns on the breadth pass described in
[Review coverage](../concepts/coverage.md#the-budgeted-sweep):

```toml
[sweep]
token_budget = 200000   # estimated prompt and reply tokens; 0 = off
model = ""              # model for its one-shot decisions; empty = backend default
unit_lines = 120        # maximum source lines in one decision
```

| Key | Type | Default | Rule |
| --- | --- | --- | --- |
| `token_budget` | integer | `0` (off) | Must be 0 or more. The sweep runs only when it is positive. |
| `model` | string | empty | Must be a string. Empty uses the backend's default model. |
| `unit_lines` | integer | `120` | Must be 20 or more. |

A value that breaks a rule fails the load. Spend is carried across
resumes in `state/sweep.json`. The sweep never starts a call whose known
prompt cost exceeds what is left, but that call's reply can take the total
past the budget. Delta audits (`--since`) and runs pinned with `--strategy`
never start a sweep.

<span id="session-environment"></span>
<span id="the-audited-revision"></span>

## Session snapshot and revision

At startup `bin/audit` writes
`output/<target>/<backend>/results/.session-env` with the run's paths and
identifiers, including the audited revision as `TARGET_REV`. After build
preflight it copies the configuration to `results/.target.toml` and records
its SHA-256 digest in `.session-env` as `TARGET_CONFIG_SHA256`.

- Probes, sanitizer runners, severity, and report enrichment in that
  session read the snapshot, so an edit to the shared file applies to the
  next run.
- Editing or removing the snapshot fails the run loudly.
- Gates run later against that results tree judge with the threat model it
  pinned.
- `target.toml` records no revision. Reports and exported bundles use
  `TARGET_REV`, falling back to the checkout's current revision when no
  session recorded one.

[Artifact layout](artifacts.md) lists both files.
