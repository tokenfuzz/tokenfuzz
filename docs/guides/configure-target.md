# Target configuration

Use this guide to review `output/<target>/target.toml` after
`bin/setup-target` or a first `bin/audit` has generated it, and before a long
run. Most targets need a review, not a hand-written file. This page explains
the decisions in order; the
[target config reference](../reference/target-toml.md) defines every field,
token, and default.

```bash
bin/setup-target <target>                           # re-detect once the build exists
bin/audit --target <target> --backend <backend> 1   # smoke-test the reviewed file
```

The file answers three questions:

1. What executable, library, or language runner carries a testcase into the
   target?
2. Which diagnostics can that route actually observe?
3. Which parts of a trigger may an external actor control?

The first two decide what an audit can execute and prove. The third decides
what agents aim for and which crashes triage treats as security issues.

!!! warning "Edit only between runs"
    Audit preflight pins a copy of the file as
    `output/<target>/<backend>/results/.target.toml`, and a running audit
    reads only that snapshot. Edit the shared `output/<target>/target.toml`
    for the next run; never edit the snapshot.

Re-running `bin/setup-target <target>` keeps a reviewed file unless it no
longer parses (then nothing survives), still holds an active `FILL_ME` on a
run without `--build`, or you pass `--force`. A regeneration keeps the
curated sections listed in
[When setup rewrites the file](../reference/target-toml.md#when-setup-rewrites-the-file)
and loses other hand edits. `--force` also asks a model to re-derive the
threat model, replacing yours, unless you add `--no-llm-config`.

<span id="native-cli-or-library"></span>
<span id="findings-only-language-target"></span>

## Start with the target shape

Identify which route should carry a testcase, then check the fields that
route depends on.

| Target shape | What runs a testcase | Fields to verify |
| --- | --- | --- |
| Native CLI | The instrumented executable | `asan_bin`; `[runner].args` if it needs flags; `[sanitizer].enabled` |
| Native library with public-API harnesses | A harness compiled for each testcase | The CLI fields, plus the sanitizer's library, `includes`, `defines`, and `link_libs` |
| Interpreted or managed language | The interpreter or driver, with no sanitizer ([findings-only mode](../reference/target-toml.md#findings-only-mode-no-sanitizer)) | `[sanitizer] enabled = []`; `[runner].bin`, `args`, and `env` |
| Go with the race detector | `go run -race` through `[runner]` | `[sanitizer] enabled = ["race"]`; `[runner]` |
| Full browser | The browser product with a fresh profile | `is_browser = "1"`; `asan_bin`; `[runner].args` with `{PROFILE}` |
| Firefox's JavaScript shell | The engine shell | `is_browser = "1"`; `asan_bin`; no `{PROFILE}` |
| Another JavaScript engine or a Wasm runtime | The engine shell as a native CLI | `is_browser = "0"`; `asan_bin`; `[runner].args`; see [Script engines and Wasm runtimes](browser-targets.md#script-engines-and-wasm-runtimes) |

A CLI-only audit needs only a correct `asan_bin`. The library fields matter
when agents compile API harnesses and for
[S4](../concepts/strategy-model.md) fuzz campaigns, which need a sanitizer
library. Relative paths resolve under the target's source root:
`targets/<target>/`, plus `source_subdir` when it is set.

The [language runners guide](multi-language.md) shows the generated
`[runner]` for each ecosystem, and every
[sample target](../getting-started/sample-targets.md) ships a working
`target.toml`.

## Review the execution route

Detection can only find what exists, so refresh it after the build with
`bin/setup-target <target>`, or build and detect in one step with `--build`.
Then check that:

- `asan_bin` starts the intended product, not a test helper, benchmark, or
  fuzzer binary;
- `[runner].bin`, `args`, and `env` load code from the target's source root,
  not an installed copy elsewhere on the host;
- `{TESTCASE}` appears where the program expects its input (without it, the
  testcase path is appended last);
- a documented normal nonzero exit, such as a parser's exit code for rejected
  input, is listed in `[runner].success_codes`;
- a browser page route has `{PROFILE}` and `{TESTCASE}` in `[runner].args`;
- each optional `<san>_bin` belongs to the matching `build-<san>/` tree.

When both are set, the selected sanitizer's binary wins over `[runner].bin`
([full order](../reference/target-toml.md#how-binprobe-chooses-the-program)).

Setup already proves part of the route, which tells you what is left to judge:

- `--build` rejects a sanitizer executable that dies in the dynamic loader.
- Setup warns when a `<san>_bin` gives the same exit status and output with
  and without a testcase. A parser may read its input silently, so confirm
  that the program consumes the testcase, or reselect it.
- A language runner that still matches the registry's invocation must pass a
  canary in `bin/setup-target --build`, `bin/audit`, and `bin/benchmark`. One
  that runs outside the target or imports an installed copy of the audited
  package is rejected. A customised `[runner]` is not canary-checked, so
  review it by hand.
- For a CMake or Meson project whose native product is a Python extension
  module rather than a CLI, `--build` stages the package with an ASan-linked
  Python host and writes that host into `[runner]` only after the package
  imports.

Reselect a native CLI only when the generated route is wrong:

```bash
bin/suggest-runner <target> --force           # print a validated proposal
bin/suggest-runner <target> --apply --force   # write it
```

The helper picks among up to eight instrumented executables, checks that the
launch depends on its input, records the observed normal exit in
`success_codes`, and retargets the other enabled sanitizers' binaries to
match.

## C harness readiness

A compiled `HARNESS:` testcase is built from the selected sanitizer's library
(`asan_lib`, or `[sanitizer].<san>_lib` for UBSan, MSan, and TSan), plus
`includes` for the public and generated headers, `defines` for the macros and
language standard those headers need, and `link_libs` for every other
library, archive, or source file the link needs.

Setup fills most of this in, so review rather than write:

- `includes` is seeded from the source layout, and after a build gains the
  public include roots from CMake or Meson install metadata. Setup checks that
  it declares at least one symbol the library exports; if not, it repairs
  `includes` from the detected public headers or logs a warning.
- `defines` gains the build's dominant C++ `-std=` flag from
  `compile_commands.json` when it has none.
- `link_libs` starts as `["-lm", "-lpthread"]`. When `asan_lib` is set, setup
  merges the link dependencies the build publishes (CMake package config,
  pkg-config files, or the other shared libraries beside a shared
  `asan_lib`), so a harness can call any of the project's public libraries.
  A shared peer is kept only if an empty harness linked with it starts, and
  setup logs each one it leaves out.

Build-local paths stay relative, so the same file works in container build
trees. The [path and argument rules](../reference/target-toml.md#harness-build-inputs)
are in the reference.

After repeated harness build failures, `bin/auto-repair-target-toml` can
propose an additive repair to `includes`, `defines`, or `link_libs`:

```bash
bin/auto-repair-target-toml --toml output/<target>/target.toml \
  --build-log <path/to/harness.build.log> --dry-run
```

Drop `--dry-run` to write it; the original is saved beside the config as
`target.toml.bak.<UTC timestamp>`. No audit runs this command for you. Review
the proposal: a compile fix is not evidence that a harness is faithful to the
public API contract.

Harnesses can also be written in other registered languages; see
[Writing harnesses in non-C/C++ languages](multi-language.md#writing-harnesses-in-non-cc-languages).

## Sanitizer policy

`[sanitizer].enabled` is ordered, and `bin/probe` uses the first entry. For
one probe, `PROBE_SANITIZER=<name>` selects another sanitizer that is also
enabled. Persistent policy belongs in the file.

| Slug | Use it when | Main cost |
| --- | --- | --- |
| `asan` | Native memory-safety work; the default. | Moderate runtime and memory overhead. |
| `ubsan` | Undefined-behaviour classes that matter for the target, such as bounds, vptr, object size, or shifts. | Mature projects may use patterns deliberately; expect triage or suppressions. |
| `msan` | A self-contained native library whose dependencies can all be instrumented. | Uninstrumented dependencies create noise; impractical at browser scale. No macOS runtime, and `bin/benchmark` refuses to start while an enabled MSan build is missing or stale. |
| `tsan` | Native concurrency work with a maintained suppression policy. | High overhead and frequent benign reports. |
| `race` | A Go target run with `-race`. | Runs through `[runner]`; it has no binary, library, or suppression key. |

Example:

```toml
asan_bin = "build-asan/sample-cli"

[sanitizer]
enabled = ["asan", "ubsan"]
asan_suppressions  = "build-asan/asan-suppressions.txt"
ubsan_bin          = "build-ubsan/sample-cli"
ubsan_lib          = "build-ubsan/libsample.a"
ubsan_suppressions = "build-ubsan/ubsan-suppressions.txt"
```

For a native target, `bin/setup-target <target> --build` builds the ASan tree
(even when `asan` is not listed) and then each other enabled native
sanitizer, exiting nonzero if any fails. Audit preflight rebuilds missing or
stale trees the same way but logs a failure and continues. `race` needs no
build tree: the Go runner compiles each testcase with `-race`.

A target with no sanitizer build uses
[findings-only mode](../reference/target-toml.md#findings-only-mode-no-sanitizer).
Runtime tracebacks and panics there are diagnostic signals, not sanitizer
proof: the agent files a report under `findings/` only when source analysis
establishes an issue.
[Crash and finding routing](multi-language.md#crash-and-finding-routing)
explains the probe, filing, and triage stages, and the
[reference](../reference/target-toml.md#sanitizers) has the keys, defaults,
suppressions, and path rules.

## Review the threat model

`[threat_model].attacker_controls` states what an external actor can supply
through a normal product boundary. It matters twice:

- Every agent prompt carries it, so agents aim at triggers those controls
  reach.
- Triage compares each crash's required trigger components with it. A crash
  that source review confirms needs a control outside the list is rejected
  with a `threat-model:` reason; its evidence is kept, but it earns no
  security credit. See [Triage and review](triage-results.md).

Setup seeds `["bytes"]`, or `["bytes", "call-sequence", "timing"]` in
browser mode, then asks a model for a target-specific list when it generates
the file, unless you pass `--no-llm-config`. To see or apply a suggestion:

```bash
bin/suggest-threat-model <target>                   # print a proposal
bin/suggest-threat-model <target> --apply           # replace the default ["bytes"]
bin/suggest-threat-model <target> --apply --force   # replace a curated list
```

Treat the suggestion as a draft. Add a token only when an outsider really
controls it in the shipped product:

| Token | Add it when | Not when |
| --- | --- | --- |
| `bytes` | The product consumes files, streams, packets, or other data an outsider supplies. Almost every parser and codec. | The value is an API parameter only the calling application chooses. |
| `call-sequence` | The outsider chooses which public calls run and in what order: a script or plugin engine running their code, or an RPC or IPC surface. | An application drives a library in a fixed order over untrusted bytes, even when the API is stateful or fuzzed call by call. |
| `timing` | The outsider influences scheduling, garbage collection, or JIT tier-up, as in browsers and JS engines. | Only a harness sleeps, loops, or reorders work. |
| `race` | The outsider can drive concurrent threads or processes, as in servers and runtimes. | Only a harness spawns the threads. |
| `protocol-state` | The product implements a network protocol whose peer drives state across messages. | Input is a single self-contained message or file. |
| `env` | Environment variables are part of the attack surface, as in shells or init code. Rare. | Only the operator sets them. |
| `fs-state` | The outsider shapes filesystem paths or layout, as in archive extractors and path-handling tools. Rare. | Only the harness creates the files. |

Typical shapes:

| Target | `attacker_controls` |
| --- | --- |
| File parser, codec, or format library | `["bytes"]` |
| Scriptable browser or JavaScript runtime | `["bytes", "call-sequence", "timing"]` |
| Network protocol implementation | `["bytes", "protocol-state"]` |

Keep the list narrow. A harness can choose arbitrary offsets, lengths, object
states, or cleanup order; that does not make those choices
attacker-controlled in the product. Over-claiming turns robustness bugs into
false security reports, so do not widen the list merely to change a
`threat-model:` decision. A change applies from the next run: gates re-run
against an existing results tree judge with the threat model that run pinned.

## Decide on build variants

For a non-browser native target, `build_widening` defaults to `true`:
`bin/setup-target --build` asks a model for one cached ASan sibling with the
project's advertised optional in-tree features enabled, while `build-asan/`
stays the control. Audit preflight rebuilds a prepared widened recipe but
never asks a model to create one. Set `build_widening = false` to audit only
the canonical build.

Declare [`[[build_config]]`](../reference/target-toml.md#build-configurations)
rows only for meaningful, mutually exclusive build modes that widening cannot
combine, such as two incompatible table layouts. During an audit, one
reproducer slot at a time rotates through the ready configurations while the
others stay on the control.

## Browser mode

Set `is_browser = "1"` for a browser or browser-like runtime. A `{PROFILE}`
token in `[runner].args` declares a page route; for `mach` and GN, empty
`args` fall back to launch arguments that include it. Without a page route
the target is a script engine: generic execution, shell agents only, and no
browser profile. The [browser guide](browser-targets.md) covers the product
executable, launch arguments, coverage, and product reachability.

## Optional sections

- `[s6_peers]` names peer projects whose security fixes seed S6
  cross-project variant cards; without it there are no S6 peer cards. Fill it
  with `bin/suggest-peers <target> --apply`.
- `[sweep]` gives the budgeted breadth pass a token budget. It is off until
  `token_budget` is positive.

Both are defined in the [reference](../reference/target-toml.md).

## Validate the reviewed config

After a hand edit, load the file through the harness's own loader before
re-running setup, which would regenerate a file that does not parse:

```bash
python3 -c 'import sys; sys.path.insert(0, "lib"); import target_config as t; t.load_toml_into(t.Config(target_root="targets/" + sys.argv[1]), "output/" + sys.argv[1] + "/target.toml")' <target>
```

It exits nonzero on a TOML syntax error or an invalid `[sweep]`,
`[[build_config]]`, or `source_subdir` value, and warns for each dropped
threat-model token or sanitizer slug. It does not catch a misspelled key,
which the loader ignores.

Then run a one-worker smoke test:

```bash
bin/audit --target <target> --backend <backend> 1
```

A successful smoke test proves that the configuration loads, the runner
passes its startup checks, and the backend can create state under the results
tree. If startup stops before `results/work-cards.jsonl` appears, read
`output/<target>/<backend>/logs/index.log`.

## Common failures

| Symptom | Check |
| --- | --- |
| The wrong program runs. | Fix `asan_bin`, or reselect with `bin/suggest-runner <target> --apply --force`. |
| Every probe reports `EXEC_FAIL` on input the CLI clearly read. | The CLI exits nonzero on rejected input. If `[runner].args` is set without `success_codes`, run `bin/suggest-runner <target> --apply` (or re-run `bin/setup-target <target>`) to record the observed exit without reselecting the CLI; otherwise add the code by hand. |
| A compiled harness is missing headers, macros, or link inputs. | Fix `includes`, `defines`, or `link_libs`, and check the selected sanitizer library; see [C harness readiness](#c-harness-readiness). |
| Every language probe misses the audited package. | Fix `[runner].args` or the import-path variables in `[runner].env`, such as `PYTHONPATH`, so the runtime loads the source root. Never accept a globally installed copy. |
| The audit stops with `configured [runner].bin ... was not found`. | Install the runtime, or fix `[runner].bin`. A findings-only target can also omit `bin` and audit by source review only. |
| `bin/probe` reports that a sanitizer is not enabled for this target. | Add it to `[sanitizer].enabled`, or unset `PROBE_SANITIZER`. |
| `bin/setup-target` replaced hand edits. | The file stopped parsing, an active value still held `FILL_ME`, or `--force` was passed. Validate edits before re-running setup. |
| A real crash was rejected with `threat-model:`. | Compare its actual trigger with `attacker_controls`. Broaden the list only if the product exposes that control. |
