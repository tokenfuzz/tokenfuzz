# Auditing Non-C/C++ Targets

The harness is language-agnostic. C/C++ targets stay the headline
case because AddressSanitizer is the highest-signal tool we have, but
the same pipeline works for many other ecosystems:

- Rust, Go, Swift;
- Java, Kotlin;
- Python, Ruby, PHP;
- JavaScript / TypeScript (Node);
- Perl, R;
- any other ecosystem with an explicit `[runner]` command.

This guide collects the moving parts in one place.

## Decision tree

```text
Does the target have a sanitizer build?
├── Yes  → [sanitizer] enabled = ["asan", …]
│         crashes/ keeps memory-safety crashes
│         findings/ keeps non-crash security issues
│
└── No   → [sanitizer] enabled = []
          crashes/ is unused; runtime crashes auto-demoted to findings/
          findings/ also keeps non-crash security issues
```

`bin/setup-target` picks a conservative default by introspecting the
source tree (`Cargo.toml`, `go.mod`, `pyproject.toml`,
`package.json`, …). For non-native ecosystems with no ASan binary
detected, that default is findings-only:

- `[sanitizer] enabled = []`;
- a starter `[runner]`.

Opt into `race` or another sanitizer by editing
`output/<target>/target.toml`.

## What sanitizers exist per language

| Language | Compile-time flag | Sanitizer slug |
| --- | --- | --- |
| C / C++ | `-fsanitize=address` / `undefined` / `memory` / `thread` | `asan`, `ubsan`, `msan`, `tsan` |
| Rust | `RUSTFLAGS="-Z sanitizer=address"` (nightly) | `asan`; also `tsan` and `msan` on supported targets |
| Go | `go build -race` | `race` |
| Swift | `swift build -Xswiftc -sanitize=address` | `asan`; also `tsan`, `ubsan` |
| Java / JVM | JFR plus JNI ASan when auditing native bindings | none; use `crash_patterns` |
| Python | `PYTHONMALLOC=malloc` plus CPython-ASan for C extensions | optional `asan` for native extensions |
| Node / V8 | `--abort-on-uncaught-exception`; native modules can link ASan | optional `asan` for native add-ons |
| Everything else | None; findings-only mode is the right choice | n/a |

When a sanitizer is available, treat it like ASan: set the
appropriate `<name>_bin` and enable the slug.

## What `target.toml` looks like for each ecosystem

`bin/setup-target` seeds these automatically. Every findings-only
target has the same shape — `[sanitizer] enabled = []` plus a
`[runner]` block naming the interpreter or driver. A Python target,
fully annotated:

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
| Python | `python` | `python3` | `["{TESTCASE}"]` | `PYTHONDEVMODE=1` |
| Go | `go` | `go` | `["run", "{TESTCASE}"]` | `GORACE=halt_on_error=1` |
| Rust | `cargo` | `cargo` | `["run", "--quiet", "--", "{TESTCASE}"]` | — |
| Ruby | `bundler` | `ruby` | `["{TESTCASE}"]` | — |
| Java / JVM | `maven` or `gradle` | `java` | `["{TESTCASE}"]` | — |
| Kotlin | `kotlin` | `kotlinc` | `["-script", "{TESTCASE}"]` | — |
| Node | `npm` | `node` | `["{TESTCASE}"]` | — |
| PHP | `composer` | `php` | `["{TESTCASE}"]` | — |

The same shape applies to `swift`, `rlang`, and `perl`;
`bin/setup-target` writes a starter `[runner]` block for each.

A few ecosystem notes:

- **Go** seeds findings-only `go run`. To use the runtime race
  detector, set `[sanitizer] enabled = ["race"]` and
  `args = ["run", "-race", "{TESTCASE}"]`.
- **Rust** can opt into a sanitizer build later — set
  `[sanitizer] enabled = ["asan"]` once you have a nightly+sanitizer
  build.
- **Java** — single-file Java is supported (JEP 330): `java <file.java>`
  compiles and runs in one shot. This is the seeded default. When seeding,
  `bin/setup-target`
  prefers a working JDK from `AUDIT_JAVA_HOME` or `JAVA_HOME`, then a
  working `java` on `PATH`.
- **Kotlin** — the seeded default is for script-style `.kts` probes.
  Plain `.kt` sidecar harnesses compile through
  `kotlinc -include-runtime`. Gradle-driven Kotlin apps should keep
  the generated `gradle` build system and runner.

## Crash vs finding routing

Once the runtime is wired up, the triager decides where each artifact
lands:

| Signal in `asan.txt` | Sanitizer enabled? | Destination |
| --- | --- | --- |
| `ERROR: AddressSanitizer: ...` | yes / no | `crashes/CRASH-*` |
| `WARNING: ThreadSanitizer: data race` | yes (`tsan`) | `crashes/CRASH-*` |
| `WARNING: MemorySanitizer: ...` | yes (`msan`) | `crashes/CRASH-*` |
| `WARNING: DATA RACE` (Go runtime) | yes (`race`) | `crashes/CRASH-*` |
| Python traceback | no | demoted to `findings/FIND-*` |
| Go `panic: runtime error:` | no | demoted to `findings/FIND-*` |
| Java `Exception in thread "main"` | no | demoted to `findings/FIND-*` |
| Node allocation fatal error | no | demoted to `findings/FIND-*` |
| Rust `thread 'main' panicked at` | no | demoted to `findings/FIND-*` |
| PHP `PHP Fatal error:` | no | demoted to `findings/FIND-*` |
| None of the above | n/a | `crashes-rejected/` |

When a target has a sanitizer enabled
(`[sanitizer] enabled = ["asan", …]`) but a particular crash
directory does **not** have a sanitizer signal, it goes to
`crashes-rejected/`. Demote-to-findings is reserved for the
`[sanitizer] enabled = []` case, where the lack of an ASan trace is
*expected*.

## Writing harnesses in non-C/C++ languages

Use `// HARNESS:` (or `# HARNESS:` for languages whose comment
delimiter is `#`; the parser is permissive about the prefix). The
extension picks the build/interpret path.

The supported set is the registry in [`lib/languages.py`](https://github.com/tokenfuzz/tokenfuzz/blob/main/lib/languages.py); run
`python3 lib/languages.py list` for the authoritative table (one row per
language, with its harness extensions and build systems). The harness
extensions split into two buckets:

```text
# Compiled (cached binary):    .c .cc .cpp .cxx .C .go .kt .rs .swift
# Interpreted (no build step): .py .rb .pl .php .js .mjs .ts .tsx
#                              .java .kts .r .R .sh .bash
```

## Crash patterns

If your target has a project-specific runtime banner (for example,
`[BUG]` in a custom panic handler, `ASSERTION FAILED:` from a debug
build), add it under `[runner].crash_patterns`:

```toml
[runner]
bin            = "python3"
args           = ["{TESTCASE}"]
crash_patterns = [
  "^Internal compiler error:",
  "^=== ABORT ===",
]
```

These patterns layer on top of the built-in language-agnostic
markers (`Traceback`, `panic:`, `Exception in thread`, …) that
[`lib/triage.sh`](https://github.com/tokenfuzz/tokenfuzz/blob/main/lib/triage.sh) already recognises.

## `reproduce.sh` templates

`bin/export-repro` emits a runnable `reproduce.sh` for every
language with a `build_system` entry. The maintainer runs
`./reproduce.sh /path/to/upstream-src` and the script:

1. Clones or checks out upstream at the pinned revision.
2. Runs the language's canonical build step (`cargo build`,
   `go build`, `npm install`, `mvn package`, …).
3. Invokes the captured testcase via the recorded runner.

If the language has no compile step (Python, Ruby, …), step 2 is a
no-op or a virtual-env / dependency install.

## See also

- [Target config reference](../reference/target-toml.md) — the full
  `target.toml` schema.
- [Configure a target](configure-target.md) — the operator review
  workflow.
- [`AGENTS.md`](https://github.com/tokenfuzz/tokenfuzz/blob/main/AGENTS.md) (repository root) — the agent-facing audit workflow,
  covering both browser and generic targets.
