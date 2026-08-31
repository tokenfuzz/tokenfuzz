# Sample Targets

TokenFuzz ships sixteen small synthetic targets, committed in the repository
with their configuration already written. They are the fastest way to see a
real run — no upstream project to pick, no `target.toml` to review, no clone.

Use them to:

- prove your host, backend, and toolchain work together before you spend a long
  run on a real project;
- watch the whole pipeline once — work cards, probes, triage, clustering,
  reports — on a target small enough to read in a sitting;
- measure the harness itself, because each one ships an **answer key**.

They are *not* evidence about real-world difficulty. A synthetic bug is planted
to be findable; an upstream parser is not.

## What is shipped

These sixteen trees are the only ones committed under `targets/`; everything
else there, and everything else under `output/` (beyond the committed `target.toml` and
`.ground-truth.json` answer keys), is a gitignored working area.

| Target | Language / build | Mode | Planted bugs | FP traps |
| --- | --- | --- | --- | --- |
| `canary` | C / cmake | ASan | 3 | 2 |
| `samples/sample-c` | C / cmake | ASan | 5 | 2 |
| `samples/sample-cpp` | C++ / cmake | ASan | 5 | 2 |
| `samples/sample-rust` | Rust / cargo | ASan (nightly `build-std`) | 3 | 4 |
| `samples/sample-swift` | Swift / SwiftPM | ASan (via `[runner]`) | 3 | 4 |
| `samples/sample-go` | Go / `go build -race` | `race` | 3 | 5 |
| `samples/sample-python-native` | Python C extension | ASan | 1 | 0 |
| `samples/sample-python` | Python | findings-only | 3 | 4 |
| `samples/sample-java` | Java / maven | findings-only | 4 | 5 |
| `samples/sample-kotlin` | Kotlin | findings-only | 4 | 5 |
| `samples/sample-javascript` | Node / npm | findings-only | 2 | 5 |
| `samples/sample-typescript` | TypeScript / npm | findings-only | 2 | 5 |
| `samples/sample-ruby` | Ruby / bundler | findings-only | 2 | 5 |
| `samples/sample-php` | PHP / composer | findings-only | 6 | 5 |
| `samples/sample-perl` | Perl | findings-only | 4 | 3 |
| `samples/sample-r` | R | findings-only | 2 | 5 |

Each one is a small tool built around the same idea — read one attacker-supplied
job file, do something with it — so the same bug classes can be planted in every
language and compared fairly. Most also carry deliberate **false-positive
traps**: code that looks dangerous to a quick scan but is safe, or an operation
that crosses no independent security boundary because the same job chooses
both sides of it. A run that promotes a trap is a precision failure, and the
answer key says so.

!!! note "Crash and finding scores are separate"
    The crash scorer trusts runtime diagnostics, not an agent's description of
    a crash. A planted bug that no configured sanitizer can catch — a path
    traversal or command injection, for example — is marked
    `findings_only: true` and stays out of the crash-recall denominator. A
    separate findings scorer credits a confirmed FIND when its report names the
    planted fault function. On the three hybrid sanitizer samples,
    `samples/sample-go` counts 1 of its 3 planted bugs toward crash recall;
    `samples/sample-rust` and `samples/sample-swift` each count 2 of 3. Their
    remaining bugs exercise the finding path.

## Run one

**Findings-only samples** need their configured runtime or toolchain, but no
sanitizer build. Their configuration is already committed, so go straight to a
one-iteration smoke test:

```bash
bin/audit --target samples/sample-python --backend <backend> 1
```

**Sanitizer samples** need their instrumented build first. The C and C++
samples build automatically during audit preflight. The Rust, Go, and
C-extension samples use an ecosystem bootstrap; preflight runs it only where
the sample commits a `.audit/build.sh` recipe (Rust and the C extension do,
Go does not), so run it yourself before the first audit:

```bash
bin/setup-target samples/sample-rust --build --no-llm-config
bin/audit --target samples/sample-rust --backend <backend> 1
```

`--no-llm-config` needs no backend. A forced build keeps the sample's
hand-authored `target.toml` and build recipe, and rematerializes only the build
output. Running `bin/setup-target ... --force` without `--build` still
regenerates the derived fields but keeps the curated threat model, peer
list, and build-widening settings.

`samples/sample-swift` is the exception that needs no build step — runner
preflight builds the package under AddressSanitizer once and every run
replays through that product, so a sanitizer diagnostic routes to `crashes/`
like a C target would.

Results land in the usual place — `output/samples/sample-rust/<backend>/results/`
— and are read exactly as [Triage and review](../guides/triage-results.md)
describes.

## The answer keys

Every sample ships a manifest at `output/<slug>/.ground-truth.json`. Note the
path: it lives under `output/`, **not** inside the target tree handed to the
agents, so a run is scored blind. Each entry pins one planted bug — its
primitive, the symbol it faults in, and the input that reaches it — and each
trap declares the benign outcome it expects.

```bash
python3 lib/benchmark.py score output/samples/sample-c/<backend>/results \
  --ground-truth output/samples/sample-c/.ground-truth.json
```

The scorer is deterministic but uses different evidence for the two lanes. The
crash oracle reads sanitizer artifacts, so merely naming a crash in prose earns
nothing. The findings oracle reads the fault location from confirmed FIND
reports; a vague mention without the exact function earns nothing. On a
findings-only target, the empty crash lane is reported as not scored while the
findings lane still reports recall and precision.

`targets/canary/run-benchmark.sh` wires the whole thing together — build, short
benchmark, ground-truth block in the ledger:

```bash
targets/canary/run-benchmark.sh --backend codex
```

See [Benchmarking](../concepts/benchmark.md#ground-truth-precision-and-recall)
for how precision and recall are computed and how to point the same machinery
at a real target.

## Then move to a real target

A sample proves the machinery runs. It cannot tell you whether the harness
finds bugs in code that was not written to contain them. When the smoke test is
green, go to [Add a target](add-a-target.md) and point TokenFuzz at something
you are authorised to audit.
