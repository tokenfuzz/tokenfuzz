# Sample targets

TokenFuzz ships eighteen small synthetic targets with their configuration
already written: `canary` and seventeen `samples/sample-*` trees. They are the
fastest way to see a real run, with nothing to clone and no `target.toml` to
review. The quickest needs only Python:

```bash
bin/audit --target samples/sample-python --backend <backend> 1
```

Use them to prove that your host, backend, and toolchain work together, to
watch the whole pipeline on code small enough to read, and to measure the
harness against each sample's **answer key**. Sample results say nothing about
performance on an unfamiliar production codebase.

## What is shipped

| Target | Language / build | Mode | Host needs | Planted bugs | FP traps |
| --- | --- | --- | --- | --- | --- |
| `canary` | C / cmake | ASan | LLVM, CMake | 7 | 2 |
| `samples/sample-c` | C / cmake | ASan | LLVM, CMake | 6 | 2 |
| `samples/sample-cpp` | C++ / cmake | ASan | LLVM, CMake | 12 | 2 |
| `samples/sample-c-doublefree` | C / cmake | ASan | LLVM, CMake | 2 | 2 |
| `samples/sample-c-uninit` | C / cmake | MSan | Linux clang with MSan | 1 | 2 |
| `samples/sample-rust` | Rust / cargo | ASan (nightly `build-std`) | nightly Rust, `rust-src` | 3 | 4 |
| `samples/sample-swift` | Swift / SwiftPM | ASan (via `[runner]`) | Swift toolchain | 3 | 4 |
| `samples/sample-go` | Go / `go build -race` | `race` | Go, a C compiler | 3 | 5 |
| `samples/sample-python-native` | Python C extension | ASan | Python, clang | 1 | 0 |
| `samples/sample-python` | Python | findings-only | `python3` | 24 | 7 |
| `samples/sample-java` | Java / maven | findings-only | JDK (`java`) | 3 | 5 |
| `samples/sample-kotlin` | Kotlin | findings-only | `kotlinc` | 3 | 5 |
| `samples/sample-javascript` | Node / npm | findings-only | `node` | 3 | 4 |
| `samples/sample-typescript` | TypeScript / npm | findings-only | `node` that runs `.ts` directly | 3 | 4 |
| `samples/sample-ruby` | Ruby / bundler | findings-only | `ruby` | 3 | 4 |
| `samples/sample-php` | PHP / composer | findings-only | `php` | 6 | 4 |
| `samples/sample-perl` | Perl | findings-only | `perl` | 4 | 3 |
| `samples/sample-r` | R | findings-only | `Rscript` | 4 | 5 |

**Findings-only** means no sanitizer build: agents file source findings, and
testcases run through the language runner. The macOS steps for `java` and
`kotlinc` are under
[Target-specific tools](prerequisites.md#3-target-specific-tools).

Each sample is a small tool that reads one attacker-supplied input file and
acts on it, so runner behavior stays comparable while each language shows the
vulnerabilities natural to its ecosystem. Most samples also carry
**false-positive traps**: code that looks dangerous but is safe, or an
operation that crosses no independent security boundary because the same
input chooses both sides of it. A run that promotes a trap loses precision.

`samples/sample-c-doublefree` and `samples/sample-c-uninit` each isolate one
bug class so its recall can be read directly. The uninitialized-read sample
needs MemorySanitizer, which has no macOS runtime; without an MSan runtime its
build refuses rather than produce an uninstrumented binary that would read as
a clean run. The C, C++, and double-free samples also plant a stack overflow
that only a release build reaches.

These are the only trees committed under `targets/`. Under `output/`, only
each sample's `target.toml` and `.ground-truth.json` are committed; the rest
of both directories is a gitignored working area.

## Run one

Findings-only samples need only their runtime. Sanitizer samples need an
instrumented build, which audit preflight produces for most of them:

| Sample | Before the first audit |
| --- | --- |
| `canary`, `sample-c`, `sample-cpp`, `sample-c-doublefree` | Nothing. Preflight builds the ASan tree from the committed recipe. |
| `sample-c-uninit` | Use a Linux host whose clang has an MSan runtime. Preflight builds it there. |
| `sample-rust`, `sample-python-native` | Nothing. Preflight runs the committed `.audit/build.sh`. |
| `sample-swift` | Nothing. Preflight builds the package under ASan at the start of each audit, and every probe replays through that product. |
| `sample-go` | Build it once yourself (below). Its runner is the binary that `go build -race` produces, which preflight does not build. |

To build a sample up front, which also surfaces a missing toolchain before a
model starts:

```bash
bin/setup-target samples/sample-go --build --no-llm-config
bin/audit --target samples/sample-go --backend <backend> 1
```

The committed recipes and configuration need no model, so `--no-llm-config`
skips the suggestions; dependency installation may still use the network.
Never pass `--force` to a sample: it regenerates the committed `target.toml`.
Results land in `output/<slug>/<backend>/results/` and read as
[First audit](first-audit.md) describes.

## Vulnerability coverage

Every class in the Anthropic Red
[CVD dashboard](https://red.anthropic.com/2026/cvd/) vocabulary (as of
2026-08-26) and every TokenFuzz
[harness-native class](../reference/bug-classes.md#harness-native-classes)
has at least one planted sample bug, except the denial-of-service family
(`stack-overflow`, `denial-of-service`, `uncaught-exception`). Denial of
service is [not scored](../concepts/benchmark.md#denial-of-service-is-not-scored),
so those classes appear only as false-positive traps: the Python sample's
resource-exhaustion examples and the Java and Kotlin allocation and
plugin-timer examples. A report there that claims only availability loss
counts against the run.

The sanitizer targets cover memory bounds, arithmetic, lifetime,
uninitialized state, invalid frees, and races; the Python sample adds
authorization, injection, cryptography, filesystem and network boundaries,
and web security.

## The answer keys

Every sample ships a manifest at `output/<slug>/.ground-truth.json`, outside
the target tree handed to the agents. That separates scoring data from
audited source; it is not an access control on other files the backend can
read. Each entry pins one planted bug (its primitive, source symbol, classes,
and triggering input) or one trap and the benign outcome it expects.

A bug's `primitive` is the one label its diagnostic or finding is scored
against; its `classes` list every root cause and consequence, so an eight-bit
subtraction can count as both `integer-underflow` and `heap-buffer-overflow`.
`tests/test_sample_bug_classes.py` keeps each key consistent with its target
and with the counts on this page.

To score a finished run against its key:

```bash
bin/benchmark score output/samples/sample-c/<backend>/results \
  --ground-truth output/samples/sample-c/.ground-truth.json
```

The scorer is deterministic and reads different evidence for each lane:

- **Crash lane:** sanitizer artifacts. Naming a crash in prose earns nothing.
- **Findings lane:** the fault location in confirmed FIND reports. A report
  that does not name the planted function earns nothing.

Two answer-key flags keep a bug out of the crash lane:

- `findings_only: true` marks a bug no configured sanitizer can catch, such
  as a path traversal or a command injection. It is scored in the findings
  lane only.
- `auto_quarantined: true` marks a site whose crash shape the harness
  quarantines, such as the C++ sample's zero-page `null-deref`: a null
  dereference alone establishes no memory-safety impact. The site scores in
  neither lane, because `AGENTS.md` tells agents not to file those shapes and
  scoring it would read obedience as a miss. The C++ sample's unknown-address
  `segv`, whose address the input chooses, is a sanitizer-confirmed SEGV and
  scores as an ordinary crash.

On a findings-only target the empty crash lane is reported as not scored,
while the findings lane still reports recall and precision. The mixed
sanitizer samples split like this:

| Sample | Crash-scored bugs | The rest |
| --- | --- | --- |
| `samples/sample-c` | 5 of 6 | 1 findings-only |
| `samples/sample-cpp` | 10 of 12 | 1 findings-only, 1 auto-quarantined |
| `samples/sample-c-doublefree` | 1 of 2 | 1 findings-only |
| `samples/sample-go` | 1 of 3 | 2 findings-only |
| `samples/sample-rust` | 2 of 3 | 1 findings-only |
| `samples/sample-swift` | 2 of 3 | 1 findings-only |

`targets/canary/run-benchmark.sh` wires the whole thing together: it builds
the canary, runs a one-replicate benchmark with a 900-second budget per cell,
and leaves the ground-truth block in the ledger. Extra arguments go to
`bin/benchmark`, whose default backend is `codex`:

```bash
targets/canary/run-benchmark.sh --backend claude
```

[Benchmarking](../concepts/benchmark.md#ground-truth-precision-and-recall)
explains how precision and recall are computed and how to point the same
machinery at a real target.

## Then move to a real target

A sample proves the machinery runs, not that the harness finds bugs in code
that was not written to contain them. When the smoke test is green, go to
[Add a target](add-a-target.md) and point TokenFuzz at something you are
authorised to audit.
