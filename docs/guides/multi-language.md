# Language runners

Use this page when the target is not plain C/C++: a Rust, Go, Swift, JVM,
Python, Node, Ruby, PHP, Perl, or R project. It covers how a testcase reaches
the audited package, which diagnostics each route can turn into a crash
bundle, and what stays a finding.

The shortest safe path is the same as for any target:

```bash
bin/setup-target <target> /path/to/checkout --build
bin/audit --target <target> --backend <backend> 1
```

`--build` installs dependencies, builds what the runner needs, and proves the
seeded runner reaches the checkout. Review the generated
`output/<target>/target.toml` before a long run; see
[Target configuration](configure-target.md).

## Choose the runtime posture

```text
Does the target have a sanitizer route?
├── Yes  → [sanitizer] enabled = ["asan", …]   (or ["race"] for Go)
│         confirmed sanitizer or race evidence becomes a crash bundle
│         non-crash security issues are findings
│
└── No   → [sanitizer] enabled = []            (findings-only mode)
          the configured [runner] executes testcases
          runtime diagnostics guide investigation but are never auto-filed
          the agent files a finding only after establishing security impact
```

An exception, panic, or traceback is neither sanitizer evidence nor a
security finding by itself.

`bin/setup-target` picks a conservative default. Go and Swift seed the
sanitizer their runner drives (`race` and `asan`); every other recognised
language ecosystem starts findings-only with a starter `[runner]`. A tree setup cannot
classify gets `build_system = "unknown"`, `enabled = ["asan"]`, and a
commented-out `[runner]` template, so configure its route yourself. To change
the posture, edit `output/<target>/target.toml` between runs.

## The language matrix

| Ecosystem | Detected from | `build_system` | Seeded `enabled` | Crash-class evidence |
| --- | --- | --- | --- | --- |
| C / C++ | `mach`, `.gn`, `CMakeLists.txt`, `meson.build`, `configure`, `configure.ac`, `autogen.sh` | `mach`, `gn`, `cmake`, `meson`, `autotools` | `["asan"]` | ASan, UBSan, MSan, and TSan reports from the native build |
| Rust | `Cargo.toml` | `cargo` | `[]` | ASan, only after you add an instrumented `asan_bin` ([Rust](#rust)) |
| Go | `go.mod` | `go` | `["race"]` | `WARNING: DATA RACE`, `fatal error: checkptr:`, a corroborated native fault |
| Swift | `Package.swift` | `swift` | `["asan"]` | ASan, UBSan, and TSan reports from `-sanitize=` builds |
| Java | `pom.xml`; `build.gradle`, `settings.gradle` (or `.kts`) | `maven`, `gradle` | `[]` | None built in |
| Kotlin | `.kt` or `.kts` files at the root or under `src/`, with no Gradle build | `kotlin` | `[]` | None built in |
| Python | `pyproject.toml`, `setup.py`, `setup.cfg` | `python` | `[]` | ASan through an ASan Python host or native harness ([Python](#python)) |
| JavaScript, TypeScript | `package.json` | `npm` | `[]` | None built in |
| Ruby | `Gemfile` or a root `*.gemspec` | `bundler` | `[]` | None built in |
| PHP | `composer.json` | `composer` | `[]` | None built in |
| R | `DESCRIPTION` | `rlang` | `[]` | None built in |
| Perl | `Makefile.PL`, `dist.ini`, or `*.pm` at the root or under `lib/` | `perl` | `[]` | None built in |

Detection runs top to bottom and the first match wins. Native build files
come first, so a Rust binding inside a CMake library is a `cmake` target.
Two CMake trees are handed to their language instead: one whose CMake
project enables Swift beside a `Package.swift`, and one that has no compiled
CMake target of its own and only builds and installs a Go program.

"None built in" means setup seeds no sanitizer. Any ecosystem can still opt
in the way a native CLI does: build an instrumented executable, enable the
sanitizer, and point the matching `<san>_bin` at it.

To list the registry, with source extensions, harness extensions, and build
systems per language, run `python3 lib/languages.py list`.

## Seeded runners

A findings-only target has `[sanitizer] enabled = []` plus a `[runner]` block
naming the interpreter or driver. The runner executes from the target root
(`targets/<target>/`, or the `source_subdir` below it), so module resolvers
that read the working directory find the audited package. `{TARGET_ROOT}` in
`[runner]` values expands to the same path. A Python target:

```toml
target       = "demo"
build_system = "python"

[sanitizer]
enabled = []           # findings-only mode

[runner]
bin            = "python3"
args           = ["{TESTCASE}"]
env            = [
  "PYTHONDEVMODE=1",
  "PYTHONPATH={TARGET_ROOT}:{TARGET_ROOT}/src:{TARGET_ROOT}/lib",
]
crash_patterns = [     # seeded from the language registry
  "Traceback \\(most recent call last\\):",
  "MemoryError",
  "RecursionError",
  "SystemError",
  "Fatal Python error:",
  "==\\d+==ERROR: AddressSanitizer",
]
```

The ecosystems differ in the `[runner]` fields:

| Ecosystem | `bin` | `args` | `env` |
| --- | --- | --- | --- |
| Python | `python3` | `["{TESTCASE}"]` | `PYTHONDEVMODE=1`, `PYTHONPATH={TARGET_ROOT}:{TARGET_ROOT}/src:{TARGET_ROOT}/lib` |
| Go | `go` | `["run", "-race", "{TESTCASE}"]` | `GOFLAGS=-mod=readonly`, `GORACE=halt_on_error=1`, `GOCACHE` and `GOMODCACHE` under `{TARGET_ROOT}/.audit` |
| Rust | `cargo` | One unambiguous binary: `run --quiet --manifest-path <manifest> --bin <name> -- {TESTCASE}`. Otherwise `["{TESTCASE}"]`, for direct `.rs` testcases | `CARGO_HOME={TARGET_ROOT}/.audit/cargo-home`, `CARGO_NET_OFFLINE=true` |
| Swift | `swift` | A package with a library product: `["{TESTCASE}"]`, for direct `.swift` testcases. One executable product: a `swift run --skip-build … <product> {TESTCASE}` route | `CLANG_MODULE_CACHE_PATH` and `SWIFTPM_MODULECACHE_OVERRIDE` under `{TARGET_ROOT}/.audit` |
| Java | `java` | After `--build`: `["@{TARGET_ROOT}/.audit/java-runner.args", "{TESTCASE}"]`. Before: `["{TESTCASE}"]` | `JAVA_HOME` when discovered |
| Kotlin | `kotlinc` | `["-script", "{TESTCASE}"]` | `JAVA_HOME` when discovered |
| Node | `node` | `["{TESTCASE}"]` | none |
| Ruby | newest discovered `ruby` | `["{TESTCASE}"]` | `RUBYLIB={TARGET_ROOT}/lib`, `BUNDLE_GEMFILE`, `BUNDLE_PATH={TARGET_ROOT}/vendor/bundle`, `RUBYOPT=-rbundler/setup` |
| PHP | `php` | `["{TESTCASE}"]` | none |
| R | `Rscript` | `["{TESTCASE}"]` | `R_LIBS_USER={TARGET_ROOT}/.audit/r-library` |
| Perl | newest discovered `perl` | `["{TESTCASE}"]` | `PERL5LIB` with the target's `blib/lib`, `blib/arch`, an ABI-specific `.audit/perl5/<version>-<arch>/lib/perl5`, and `lib` |

`python3 lib/languages.py runner-block <build_system> --pretty` prints the
static registry block. Setup refines it for the checkout: the Ruby and Perl
interpreter and Perl's library path, the Java argument file and `JAVA_HOME`,
and the Cargo and SwiftPM product routes.

!!! tip "There is a worked example for every language"
    Rather than starting from the table, copy a config that is known to run.
    Each ecosystem has a synthetic target under `targets/samples/sample-*`,
    with its `target.toml` committed at `output/samples/sample-*/target.toml`.
    See [Sample targets](../getting-started/sample-targets.md).

### How the runner is proved

`bin/setup-target --build` runs one generated testcase in the target's own
language through `bin/probe`. Setup fails if the runner executed outside the
target root, if none of the runtime's import paths is inside it, if the
canary never ran, or if the harness did not count the run. `bin/audit` and
`bin/benchmark` repeat the check before spending a model on the target, so a
runner that loads an installed copy of the audited package is rejected rather
than auditing the wrong code.

The check stands aside, and setup prints why, when it cannot make that
claim: every enabled sanitizer has its own `<san>_bin`, `[runner].bin` or
`args` differ from the registry's invocation, a Cargo workspace exposes no
library for the canary to depend on, or a Swift package has only an
executable product.

Before the canary, audit preflight starts the runner once: an interpreter
runs an empty program, so a broken loader fails here rather than on every
probe, and a build tool reports its version. When `[runner].args` name a
`.ts` entry point, preflight also checks that the configured Node can run
TypeScript.

## Ecosystem notes

Read the entry for your language.

### Python

Plain Python targets need no build step. When the tree has a `setup.py`,
`--build` creates `.audit/venv` and installs the project editable there, so C
extensions are built for the running interpreter. Setup also forces a build
when it finds extension modules built for a different interpreter ABI.

Two routes give Python ASan evidence. A CMake or Meson project whose native
products are Python extension modules is a native target: setup stages the
package with an ASan-linked Python host and writes a `[runner]` for it (see
[Review the execution route](configure-target.md#review-the-execution-route)).
Otherwise, drive the extension's C code with an instrumented native harness
configured as `asan_bin`, as `samples/sample-python-native` does.

### Node and TypeScript

Node setup picks npm, pnpm, or Yarn from the lockfile, the `packageManager`
field, or use of the `workspace:` protocol. After installing, it runs the
root `build` script when one is declared, so package exports that point to
generated files work.

TypeScript projects are detected as `npm` and get the Node runner. Node 22.18
and later run `.ts` sources directly by stripping their types, so a
TypeScript entry point needs no loader when its imports name the `.ts`
extension; `samples/sample-typescript` works this way.

A `.ts` or `.tsx` testcase on a `node` runner runs through
`ts-node --transpile-only --skip-project` as CommonJS, with no type checking,
when the target has `node_modules/.bin/ts-node` or one is on `PATH`. A
project that needs another loader sets `[runner].bin` to it. When that loader
is `ts-node`, preflight runs it on an empty program first.

??? note "TypeScript resolution hooks"
    Every generic runner route, findings-only included, preloads
    `lib/typescript_hooks.cjs` through `NODE_OPTIONS` (after any the target
    sets) whenever it launches a binary named `node`. The hooks need Node
    22.15 or later and act only on TypeScript source:

    - An import Node cannot resolve from a `.ts` file is resolved with the
      target's own `typescript` package and nearest `tsconfig.json`, so
      `paths` aliases, extensionless imports, and `.js` specifiers for `.ts`
      files work.
    - Each `.ts` file is transpiled with that compiler, so decorators,
      parameter properties, and enums load. Decorator metadata is not
      emitted.
    - A project that declares `isolatedModules` or `verbatimModuleSyntax`
      gets the module format Node would give it; any other project's files
      are CommonJS unless they use top-level `await` or `import.meta`.
    - A target without `typescript` keeps Node's type stripping, plus a
      retry of a failed file-path import with `.ts`, `.tsx`, `/index.ts`, or
      `/index.tsx` appended.

    Before Node 24.18 and 26.2 (and on 25), a CommonJS file that an ES module
    imports resolves its own `require()` calls without the hooks
    ([nodejs/node#62920](https://github.com/nodejs/node/pull/62920)).

### PHP

Composer setup first installs the full dependency set. If a PHP extension
required only by the root package's `require-dev` blocks that, setup retries
with `--no-dev` and ignores only those development-only extension
requirements. Extensions that production dependencies need stay mandatory.

### Ruby

Setup reads the root gemspec through RubyGems. If it declares a native
extension, `--build` runs `bundle exec rake compile` after Bundler installs
dependencies into `vendor/bundle`. `CONFIGURE_ARGS` passed to setup are saved
in `.audit/bootstrap.sh` for extensions that need an external prefix. An
explicit `RUBY` selects the interpreter; otherwise setup takes the newest
Ruby on `PATH` or from Homebrew.

### Go

Setup seeds `go run -race` with `[sanitizer] enabled = ["race"]`. The
`--build` bootstrap runs `go build std` and `go build -race -trimpath ./...`
with the runner's target-local caches, so the first probe does not compile
the standard library inside its deadline. If the race build fails (it needs
cgo, and so a C compiler), setup falls back to a build without `-race`. You
can instead point `[runner].bin` at a prebuilt `go build -race` binary, as
`samples/sample-go` does.

A direct `.go` testcase runs through `go run -race` from the target root; if
`go run` fails to build it, the probe records `NO_EXEC`. A `.go` sidecar
harness is built with plain `go build`, so it runs without the race
detector. When a Go source embeds an asset directory that an adjacent
JavaScript package generates, `--build` runs that package's `build` script
first, while the embedded path is absent.

### Rust

A library-only crate has no `cargo run` route. Write the testcase as a
direct `.rs` file calling the crate's public API, or as a
`// HARNESS: <name>.rs` driver beside an opaque input. `bin/probe` builds
either in a detached package that depends on the audited crate by path, in
release mode, so `debug_assert!` and overflow checks do not fire on
conditions a shipped build lacks.

In a workspace, a testcase links the member crates it names. If the
workspace has several binaries and neither a declared default nor one named
like the target, setup does not guess, and opaque input needs a named Rust
harness. `--build` runs `cargo fetch` into `.audit/cargo-home`, which later
builds read offline.

To get ASan evidence, set `[sanitizer] enabled = ["asan"]`, point `asan_bin`
at the instrumented binary, and add a `.audit/build.sh` that produces it
with a nightly `-Zsanitizer=address -Zbuild-std` build; `samples/sample-rust`
shows the shape. With `asan_bin` configured, probes run that binary on the
testcase instead of compiling `.rs` testcases. A Rust panic under a
sanitizer route is rejected by triage as `runtime panic`.

### Swift

Swift probes compile with `-sanitize=`, so a sanitizer report routes to
`crashes/` as it would for C/C++. The `{SWIFT_SANITIZER}` runner token
expands to `address`, `undefined`, or `thread` for `asan`, `ubsan`, or
`tsan`; other sanitizers are refused.

For a package with a library product, a direct `.swift` testcase is compiled
in a detached SwiftPM package that depends on every exported library product.
Compilation runs before the testcase's execution deadline, and the setup
canary imports a real exported module, so a library-only package cannot
pass with an invented executable.

For a package with only executable products, setup selects the product named
like the target slug, or the only one, and refuses to guess among several.
Audit preflight builds that `swift run --skip-build` route once per enabled
sanitizer. SwiftPM's caches and state live under the target's `.audit/`, so
the route works inside a restricted agent workspace.

### Java

A direct `.java` testcase runs as a single-file source program. For Maven,
`--build` compiles the reactor and records each module's runtime classpath;
for Gradle, it runs an injected `tokenfuzzPrepare` task that records each
project's classes, resources, and runtime classpath. The result stays in
`.audit/java-runner.args`, outside `target.toml` and model context.

Each direct testcase gets the classpath of the module its `TARGET:` source
location, or failing that its imports, points to. The setup canary loads a
class whose code source is inside the checkout. JDK discovery tries
`AUDIT_JAVA_HOME`, `JAVA_HOME`, and `PATH`, then asks a working Maven or
Gradle which runtime it uses.

### Kotlin

A Gradle project, Kotlin or not, is detected as `gradle` and gets the Java
runner, whose classpath includes compiled Kotlin classes. Write testcases for
such a target in Java, calling Kotlin code by its JVM names: the Java runner
does not execute `.kt` or `.kts` source.

`build_system = "kotlin"` is detected only without a Gradle build. It seeds
`kotlinc -script {TESTCASE}` for `.kts` testcases. A `.kt` sidecar harness
compiles through `kotlinc -include-runtime` and runs with `java -jar`,
without the project's classpath.

### R

`--build` installs a package with a `DESCRIPTION` file, and its hard
dependencies, into `.audit/r-library`, so a compiled component is built
rather than skipped. The seeded runner points `R_LIBS_USER` at that library.
The install is a snapshot: a later `bin/setup-target` without `--build`
reinstalls it when the checkout has moved.

### Perl

Setup uses the newest Perl on `PATH` or from Homebrew; an explicit `PERL`
wins. For a `Makefile.PL`, `Build.PL`, or Dist::Zilla (`dist.ini`)
distribution, `--build` installs declared dependencies with cpanm into an
ABI-specific directory under `.audit/perl5`, builds the native modules, and
installs the result there, from the standard CPAN mirror. An existing
generated `Makefile` is cleaned first, so a Perl upgrade cannot reuse stale
objects. The canary imports a real module from `lib/` and verifies that Perl
loaded the built copy inside the audited checkout.

## Crash and finding routing

Keep three stages separate: the probe verdict, the agent's filing decision,
and triage's publication decision. A `CRASH` verdict is an observation, not a
filing decision.

`bin/probe` files a bundle itself only on a sanitizer route (`asan`,
`ubsan`, `msan`, `tsan`, or `race`), and only after confirmation:
`bin/probe --confirm` runs the testcase five times, and any explicit run
count of two or more also qualifies. The confirmed crash is copied into
`crashes/CRASH-<n>-<agent>/` with a `report.md` skeleton for the agent to
enrich, unless the same crash state is already filed through the same probe
route (see [Deduplication](../concepts/deduplication.md)). With an
interpreted sidecar harness, the probe prints the `crashes/` path and the
agent files the bundle. On the `runner` route (`[sanitizer] enabled = []`)
nothing is ever filed automatically.

| Saved output | Probe result | What happens next |
| --- | --- | --- |
| ASan, UBSan, MSan, or TSan report | `CRASH` | Filed on confirmation. Triage reviews a memory-safety class as a crash; another sanitizer class (for example a non-security UBSan check) moves to `findings/`. |
| Go `WARNING: DATA RACE` or `fatal error: checkptr:` | `CRASH` | Filed on confirmation on the `race` route. Triage treats both as memory-safety evidence. |
| Go `unexpected fault address`, `fatal error: fault`, and a SIGSEGV or SIGBUS line naming the same address | `CRASH` when the address is at least `0x1000` | Filed on confirmation. An address inside the null page is rejected as `null-deref`. |
| Traceback, panic, exception, or fatal-error banner on the `runner` route | `CRASH` | Never filed. The agent traces it to source and writes `findings/FIND-*` only for a concrete issue that crosses a security boundary. A complete bundle placed in `crashes/` by hand moves to `findings/`. |
| The same kind of banner on a sanitizer route (a Go panic under `race`, a Rust panic under ASan) | `CRASH` | Filed on confirmation, then rejected by triage: a Rust panic as `runtime panic`, the rest because the bundle never gains a valid sanitizer diagnostic. |
| A genuine sanitizer or race report emitted on the `runner` route | `CRASH` | Not filed by the probe. The agent may file the bundle under `crashes/` by hand, and triage treats it like any other sanitizer crash. |
| On the `runner` route, a missing module, class, or package the testcase needs | `NO_EXEC` | Fix the runner or the testcase; nothing reached the target. An `AssertionError` raised by the testcase itself is `EXEC_FAIL`. |
| No recognised diagnostic | `CLEAN`, `EXEC_FAIL`, `NO_EXEC`, or `TIMEOUT` | Read the verdict and its coverage column, then revise the testcase. |

Triage then decides the lane for every bundle. An incomplete bundle (no
enriched report, no valid diagnostic, or no testcase or harness) is held
pending and eventually rejected. On a findings-only target, a complete bundle
whose only evidence is a runtime diagnostic moves to `findings/`.
[Triage and review](triage-results.md#crash-review) has the full sequence
and the rejection reasons.

## Writing harnesses in non-C/C++ languages

Name a sidecar driver with a `HARNESS:` header in the testcase's native
comment syntax: `# HARNESS:` in Python, `// HARNESS:` in C or JavaScript,
`<!-- HARNESS: … -->` in HTML. `bin/probe` reads header fields (`HARNESS:`,
`TARGET:`, `MODE:`, `PROPERTY:`) from the first 16 lines, after any comment
prefix without letters (`//`, `#`, `;`, `--`, `/*`, `<!--`). The harness must
sit in the testcase's directory or below it.

The harness file's extension, not the header, picks how it runs:

| Extension | How `bin/probe` runs it |
| --- | --- |
| `.c`, `.cc`, `.cpp`, `.cxx` | Compiled with `clang` or `clang++` and the probe's sanitizer, linked against `<san>_lib`, `includes`, and `link_libs`, and cached per agent. |
| `.rs` | Built in release mode in a detached Cargo package that depends on the crate's library. |
| `.swift` | Built in a detached SwiftPM package against the exported library products, with `-sanitize=` for `asan`, `ubsan`, or `tsan`. |
| `.go` | Built with `go build` from the target root, without `-race`. |
| `.kt` | Compiled with `kotlinc -include-runtime` and run with `java -jar`. |
| `.py`, `.rb`, `.pl`, `.php`, `.js`, `.mjs`, `.ts`, `.tsx`, `.java`, `.kts`, `.r`, `.sh`, `.bash` | Run by `python3`, `ruby`, `perl`, `php`, `node`, `ts-node`, `java`, `kotlinc -script`, `Rscript`, or `bash`. The variables `PYTHON3`, `RUBY`, `PERL`, `PHP`, `NODE`, `TSNODE`, `JAVA`, `KOTLINC`, `RSCRIPT`, and `BASH` override the interpreter. |

A harness receives the testcase path as its argument and runs with the
`[runner].env` entries. In a script testcase, `bin/probe` removes any header
line written without a comment prefix before running it, so a bare
`TARGET: …` line does not break the program.

## Crash patterns

If your target prints a project-specific runtime banner (for example `[BUG]`
from a custom panic handler, or `ASSERTION FAILED:` from a debug build), add
it under `[runner].crash_patterns`:

```toml
[runner]
bin            = "python3"
args           = ["{TESTCASE}"]
crash_patterns = [
  "^Internal compiler error:",
  "^=== ABORT ===",
]
```

Setup seeds this list with the language's own runtime markers (`Traceback`,
`panic:`, `Exception in thread`, and so on). Patterns change only the probe's
`CRASH` verdict. Triage keeps its own fixed list of acceptable diagnostics, so
a custom pattern never makes a crash bundle publishable by itself.

## `reproduce.sh` templates

`bin/export-repro` writes a runnable `reproduce.sh` for crashes driven by a
browser page or JS shell, a CLI input, a direct `.go` testcase, a shell
wrapper (`harness.sh` or `harness.bash`), or a C/C++ sidecar harness. Direct
`.rs` and `.swift` testcases and sidecar harnesses in other languages have no
template of their own. [Reproduce a crash](reproduce-a-crash.md) describes
the script's checkout and build contract.

Use the language's temporary-directory API for files a testcase creates. The
exporter refuses a bundle whose harness or input embeds a path into the
audit's own workspace, because a maintainer could not run it.

## Call-graph context per language

With the optional
[call-neighbourhood analysis](../getting-started/prerequisites.md#experimental-call-neighbourhood-context)
installed, every registry language except Perl and R gets a parsed call graph.
That section explains how entry points are chosen per language and why a
missing edge never means unreachable.

## See also

- [Target config reference](../reference/target-toml.md): the full
  `target.toml` schema.
- [Target configuration](configure-target.md): the operator review workflow.
- [Browser targets](browser-targets.md): browsers, JavaScript engines, and
  Wasm runtimes.
- [`AGENTS.md`](https://github.com/tokenfuzz/tokenfuzz/blob/main/AGENTS.md)
  (repository root): the agent-facing audit workflow.
