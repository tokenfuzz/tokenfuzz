# Language Runners

TokenFuzz supports C/C++, Rust, Go, Python, Java, and other ecosystems behind
one probe and triage contract. This page covers the part that changes outside
ordinary C/C++: how a testcase reaches the audited package, and which runtime
diagnostics count as crash evidence.

The registered ecosystems are:

- Rust, Go, Swift;
- Java, Kotlin;
- Python, Ruby, PHP;
- JavaScript / TypeScript (Node);
- Perl, R;
- any other ecosystem with an explicit `[runner]` command.

## Choose the runtime posture

```text
Does the target have a sanitizer build?
├── Yes  → [sanitizer] enabled = ["asan", …]
│         confirmed sanitizer/race evidence can become a crash bundle
│         non-crash security issues remain findings
│
└── No   → [sanitizer] enabled = []
          the configured runner executes testcases
          runtime diagnostics guide investigation but are not auto-filed
          the agent files a finding only after establishing security impact
```

A genuine sanitizer or race diagnostic is still crash-class evidence when a
runner emits it, but it must satisfy the same confirmation and bundle
requirements as any other crash. An ordinary exception, panic, or traceback is
not sanitizer evidence and is not a security finding by itself.

`bin/setup-target` picks a conservative default by introspecting the source
tree (`Cargo.toml`, `go.mod`, `pyproject.toml`, `package.json`, and so on). For
a recognized non-native ecosystem with no maintained sanitizer runner, that
default is findings-only. Go and Swift instead seed their registry-provided
race/ASan routes. Other ecosystems receive:

- `[sanitizer] enabled = []`;
- a starter `[runner]`.

Opt into `race` or another sanitizer by editing the shared
`output/<target>/target.toml` between runs, then start a new session. A running
session reads its pinned `.target.toml` snapshot.

## What sanitizers exist per language

| Language | Compile-time flag | Sanitizer slug |
| --- | --- | --- |
| C / C++ | `-fsanitize=address` / `undefined` / `memory` / `thread` | `asan`, `ubsan`, `msan`, `tsan` |
| Rust | `RUSTFLAGS="-Z sanitizer=address"` (nightly) | `asan`; also `tsan` and `msan` on supported targets |
| Go | `go build -race` | `race` |
| Swift | SwiftPM overlay or `swift run … -Xswiftc -sanitize={SWIFT_SANITIZER}` | `asan`, `ubsan`, `tsan` |
| Java / JVM | None for JVM code; a JNI library can be built with ASan and driven separately | None for the JVM. Substantive security issues use `findings/`. |
| Python | An ASan-built C extension driven by a standalone harness (see `samples/sample-python-native`) | Optional `asan` for native extensions |
| Node / V8 | No compile-time sanitizer for ordinary JavaScript; native add-ons can link ASan | Optional `asan` for native add-ons |
| Everything else | None; findings-only mode is the right choice | n/a |

When a sanitizer is available, enable the slug and configure its execution
route. Swift selects its sanitizer through runner tokens, and Go `race` uses
the runner; neither follows the ordinary native `<name>_bin` rule.

## What `target.toml` looks like for each ecosystem

`bin/setup-target` seeds these automatically for ecosystems in its language
registry. A configured findings-only target has the same outer shape:
`[sanitizer] enabled = []` plus a `[runner]` block naming the interpreter or
driver. A Python target, fully annotated:

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

The other ecosystems differ only in the `[runner]` fields:

| Ecosystem | `build_system` | `bin` | `args` | Notable `env` |
| --- | --- | --- | --- | --- |
| Python | `python` | `python3` | `["{TESTCASE}"]` | `PYTHONDEVMODE=1`, `PYTHONPATH={TARGET_ROOT}:{TARGET_ROOT}/src:{TARGET_ROOT}/lib` |
| Go | `go` | `go` | `["run", "-race", "{TESTCASE}"]` | module and build caches under `{TARGET_ROOT}/.audit`, `GOFLAGS=-mod=mod`, `GORACE=halt_on_error=1` |
| Rust | `cargo` | `cargo` | An unambiguous declared binary uses `cargo run`; a library or virtual workspace uses direct `.rs` testcases | `CARGO_HOME={TARGET_ROOT}/.audit/cargo-home`, `CARGO_NET_OFFLINE=true` |
| Swift library | `swift` | `swift` | `["{TESTCASE}"]` | module cache under `{TARGET_ROOT}/.audit` |
| Ruby | `bundler` | newest discovered `ruby` | `["{TESTCASE}"]` | target `RUBYLIB` and vendored Bundler environment |
| Java / JVM | `maven` or `gradle` | `java` | Maven uses `["@{TARGET_ROOT}/.audit/java-runner.args", "{TESTCASE}"]`; an unbuilt tree starts with `["{TESTCASE}"]` | `JAVA_HOME` when discovered |
| Kotlin | `kotlin` | `kotlinc` | `["-script", "{TESTCASE}"]` | none |
| Node | `npm` | `node` | `["{TESTCASE}"]` | none |
| PHP | `composer` | `php` | `["{TESTCASE}"]` | none |
| R | `rlang` | `Rscript` | `["{TESTCASE}"]` | `R_LIBS_USER={TARGET_ROOT}/.audit/r-library` |
| Perl | `perl` | newest discovered `perl` | `["{TESTCASE}"]` | target `blib`, ABI-isolated `.audit/perl5`, and source `lib` paths |

TypeScript projects are detected as `npm` and receive the Node runner. A
project whose testcases must be TypeScript sets `bin` to its own loader; the
committed `samples/sample-typescript` uses `ts-node`.

For a Swift library, a direct `.swift` testcase is compiled in a detached
SwiftPM package that path-depends on every exported library product. Compilation
runs before the 15-second execution budget and the per-agent package cache
reuses dependencies. Setup builds and runs a canary that imports a real
exported module, so a library-only package cannot pass with an invented
executable. For an executable-only package, structured SwiftPM metadata selects
the declared product; the generated `swift run` route is prepared once per
sanitizer in `.audit/swift-build-<sanitizer>`. SwiftPM's cache, configuration,
security state, and clang module cache live under the target's `.audit/` tree,
so the same route works inside a restricted audit-agent workspace.

`bin/setup-target` writes the matching starter `[runner]` block for each
recognized registry ecosystem, and `--build` then proves that block reaches the
target: it runs one generated testcase in the target's own language through
`bin/probe`, and fails setup if the runner executed outside `targets/<slug>/`
or resolved its imports entirely outside it. `bin/audit` and `bin/benchmark`
repeat that check before spending a model on the target, so a runner that
starts but loads an installed copy of the audited package is rejected instead
of auditing the wrong code. The check stands aside, and says so, when it cannot
make that claim: a Cargo package or workspace that exposes no library for the
canary to depend on, a changed `[runner].bin` or `args`, or configured `[sanitizer]`
binaries that own every enabled testcase route, because the registry's
generated source is then no longer proof of what runs. An unrecognized build
system does not receive a guessed runner; configure its `[runner]` explicitly.

Composer setup first installs the full dependency set. If that is blocked by a
PHP extension declared only in the root package's `require-dev` section, setup
retries with production dependencies and ignores only those development-only
extension requirements. Extensions required by production dependencies remain
mandatory.

Node setup uses the checkout's lockfile and `packageManager` metadata to choose
npm, pnpm, or Yarn. After installation it runs the conventional root `build`
script when one is declared, so package exports that point to generated files
are usable before the runner canary and audit begin.

To print the registry's current answer for any build system:

```bash
python3 lib/languages.py runner-block <build_system> --pretty
```

!!! tip "There is a worked example for every language here"
    Rather than starting from the table, copy a config that is known to run.
    The repository ships a configured synthetic target for each of these
    ecosystems under `targets/samples/sample-*`, with its hand-authored
    `target.toml` committed at `output/samples/sample-*/target.toml`. See
    [Sample targets](../getting-started/sample-targets.md).

A few ecosystem notes:

- **Ruby** setup reads the root gemspec through RubyGems. If it declares a
  native extension, `--build` runs the project's standard `rake compile` task
  after Bundler installs dependencies. When the gem has a conventional root
  entrypoint, the runner canary requires that exact checkout file; otherwise it
  verifies the target-local load path. Standard `CONFIGURE_ARGS` supplied to
  setup are saved in `.audit/bootstrap.sh` for extensions that need an external
  prefix.
- **Go** seeds `go run -race` with `[sanitizer] enabled = ["race"]`; the setup
  bootstrap primes the matching race build cache before the runner canary.
  You can instead point the `[runner]` at a pre-built `go build -race` binary
  (the `samples/sample-go` target demonstrates that route).
  When a checked-in Go source embeds an asset directory generated by an
  adjacent JavaScript package, `bin/setup-target --build` runs that package's
  declared `build` script through its lockfile-selected package manager before
  compiling Go. It does this only while the declared embed input is absent.
- **Rust**: a library-only crate has no `cargo run` route. Write the testcase
  as a direct `.rs` file calling the crate's public API, or a
  `// HARNESS: <name>.rs` driver beside an opaque input; `bin/probe` builds
  either against the audited crate in release mode (matching the bootstrap
  build, so `debug_assert!` is not mistaken for a finding).
  Virtual workspaces follow the same route: Cargo metadata supplies the member
  libraries, and a testcase is linked to the crates it names. If the workspace
  exposes several binaries without one declared default or a unique slug
  match, setup does not guess among them; opaque input requires a named Rust
  harness.
  `bin/setup-target --build` prefetches dependencies into
  `.audit/cargo-home`, which those builds then read offline.
- **Rust** can opt into an AddressSanitizer build: set
  `[sanitizer] enabled = ["asan"]`, point `asan_bin` at the instrumented
  binary, and commit a `.audit/build.sh` that produces it with a nightly
  `-Zsanitizer=address -Zbuild-std` build. `bin/setup-target --build`
  materializes it (see the `samples/sample-rust` target).
- **Swift** is the exception to the "non-native means findings-only" rule in
  the decision tree: its seeded `[runner]` compiles the package with
  `-sanitize={SWIFT_SANITIZER}`, so a sanitizer diagnostic routes to
  `crashes/` like a C/C++ target rather than staying findings-only.
- **Java**: single-file Java is supported (JEP 330). For Maven targets,
  `bin/setup-target --build` compiles the reactor and asks Maven's dependency
  plugin for each module's classpath. The generated Java argument file stays
  under `.audit/`, outside `target.toml` and model context. A direct testcase's
  `TARGET:` source location selects the nearest module; when that location is
  incomplete, imports map back to compiled module classes. Maven's dependency
  receipts then expand the local reactor and external runtime closure without
  activating unrelated modules or test providers. The setup canary loads a
  class whose code source is inside the checkout, so starting a JVM in the
  target directory is not enough to pass. JDK discovery tries
  `AUDIT_JAVA_HOME`, `JAVA_HOME`, and `PATH`, then reuses the runtime already
  reported by a working Maven or Gradle.
- **Kotlin**: `build_system = "kotlin"` seeds script-style `.kts` probes.
  Plain `.kt` sidecar harnesses compile through `kotlinc -include-runtime`. A
  detected `gradle` build currently receives the Java JEP 330 runner
  (`java {TESTCASE}`), not the Kotlin script runner. For a Gradle/Kotlin
  target, either use a Java-interoperable testcase with the required target
  classpath or configure a project-specific Kotlin/Gradle runner explicitly;
  do not assume the generated Java command loads Kotlin application code.
- **R**: `bin/setup-target --build` installs a package with a `DESCRIPTION`
  manifest and its declared hard dependencies into `.audit/r-library`, so a
  compiled component is built rather than skipped and development-only
  packages do not inflate setup. The seeded runner points `R_LIBS_USER` at
  that target-local library. The install is a snapshot, so a later
  `bin/setup-target` without `--build` reinstalls it when the checkout has
  moved since.
- **Perl**: a repository with `Makefile.PL` uses the newest installed Perl,
  installs declared dependencies into an ABI-specific directory under
  `.audit/perl5`, builds its native modules, and installs the result there.
  cpanm reads the standard CPAN mirror index and keeps its working state under
  the target's `.audit` directory, avoiding a separate metadata service and
  user-global installer state. A repository transfer that cpanm explicitly
  reports as failed gets one unchanged retry, reusing completed work from that
  local cache. Dependency tests run without the operator's
  `NO_COLOR` display preference, which can otherwise alter expected output in
  unrelated packages. A Dist::Zilla author checkout with `dist.ini`
  uses `dzil authordeps` to install the build dependencies declared by the
  project, generates a release tree under `.audit`, then installs that tree
  through the same target-local cpanm environment. If
  a repository checkout has no release `META` file and cpanm cannot execute
  `Makefile.PL` before its configure prerequisites exist, setup installs the
  prerequisite names from cpanm's own diagnostic and retries dependency
  discovery. This includes a module that `Makefile.PL` or `Build.PL` imports
  before metadata is available. An existing generated Makefile is cleaned before rebuilding, so
  a Perl upgrade cannot retain generated C or objects from the prior API. The
  canary requires and imports a real module from `lib/`, then verifies that
  Perl loaded its built copy from inside the audited checkout.

## Crash and finding routing

Keep three stages separate: the probe verdict, the agent's filing decision,
and triage's publication decision.

| Saved output | What `bin/probe` establishes | Filing action |
| --- | --- | --- |
| ASan, TSan, MSan, UBSan, or another accepted sanitizer diagnostic | Sanitizer-class evidence was observed on this execution route. | Confirm with `bin/probe --confirm`. On a native sanitizer route (CLI or compiled harness) the confirmed crash is filed under `crashes/` automatically; for an interpreted sidecar harness or the `runner` route, the probe prints the `crashes/` path and the agent files it. |
| Go `WARNING: DATA RACE` | Race-detector evidence was observed. | Same as a sanitizer diagnostic when `race` is enabled. |
| A registered traceback, panic, exception, or fatal-error banner with `[sanitizer] enabled = []` | The runner produced a diagnostic worth investigating. | Trace it to source. The agent authors `findings/FIND-*` only for a concrete issue that crosses a security boundary. |
| No recognized diagnostic | Nothing to file. | Read the probe verdict (`CLEAN`, `NO_EXEC`, `EXEC_FAIL`) and its coverage column, then revise the testcase. |

In findings-only mode the probe route is `runner`. `bin/probe` still prints a
`CRASH` verdict for a recognised runtime banner so the investigator does not
miss it, but it never files a crash bundle for that route; the verdict is not a
filing decision.

Triage keeps the lanes honest afterwards. A crash directory that holds only a
managed-runtime diagnostic is relocated to `findings/` when it carries a
substantive report and a reproducer; otherwise it is held pending and then
rejected. A crash directory on a sanitizer target that lacks the sanitizer
signal ends up in `crashes-rejected/`.

## Writing harnesses in non-C/C++ languages

Name the sidecar with a `HARNESS:` header in the file's native comment syntax:
`# HARNESS:` in Python, `// HARNESS:` in C or JavaScript,
`<!-- HARNESS: … -->` in HTML. `bin/probe` reads the header fields from the
first 16 lines of the file, and any comment prefix without letters works
(`//`, `#`, `;`, `--`, `/*`, `<!--`). The same rule applies to `TARGET:`,
`MODE:`, and `PROPERTY:`.

The file extension, not the header, picks the build-or-interpret path.

For the authoritative table, one row per language with its harness extensions
and build systems, run:

```bash
python3 lib/languages.py list
```

The harness extensions split into two buckets:

```text
# Compiled (cached binary):    .c .cc .cpp .cxx .C .go .kt .rs .swift
# Interpreted (no build step): .py .rb .pl .php .js .mjs .ts .tsx
#                              .java .kts .r .R .sh .bash
```

## Crash patterns

If your target has a project-specific runtime banner (for example, `[BUG]`
from a custom panic handler, or `ASSERTION FAILED:` from a debug build), add it
under `[runner].crash_patterns`:

```toml
[runner]
bin            = "python3"
args           = ["{TESTCASE}"]
crash_patterns = [
  "^Internal compiler error:",
  "^=== ABORT ===",
]
```

`bin/setup-target` seeds this list with the language's own runtime markers
(`Traceback`, `panic:`, `Exception in thread`, and so on), layered on top of
the built-in sanitizer patterns. Add to it only for a banner specific to your
project.

## `reproduce.sh` templates

`bin/export-repro` writes a runnable `reproduce.sh` for crashes driven by a
browser/JS page, a CLI input (including Go `race` binaries), a recorded shell
wrapper, or a C/C++ sidecar harness. Sidecar harnesses in other languages
(`.go`, `.rs`, `.swift`, `.kt`, and the interpreted extensions above) run
through `bin/probe` but are not yet packaged by the exporter. See
[Reproduce a crash](reproduce-a-crash.md) for the script's checkout and build
contract.

## See also

- [Target config reference](../reference/target-toml.md): the full
  `target.toml` schema.
- [Target configuration](configure-target.md): the operator review workflow.
- [`AGENTS.md`](https://github.com/tokenfuzz/tokenfuzz/blob/main/AGENTS.md)
  (repository root): the agent-facing audit workflow, covering both browser
  and generic targets.
