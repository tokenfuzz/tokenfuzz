# Boundary-directed fuzzing

Strategy S4 is the only TokenFuzz strategy that runs a fuzzer. It finds a
published API that takes input the threat model's attacker controls and that
no existing harness drives, builds or improves a libFuzzer harness for it,
and spends one bounded campaign on it. Hand-written parser or decoder inputs
belong to S7, which may use a minimal deterministic driver to deliver one but
never builds a fuzz harness or runs a campaign.

This page is for operators deciding whether to let S4 run and how to steer
it, and for anyone running `bin/fuzz` by hand. The agent-facing playbook is
`.agents/references/strategies/S4-directed-fuzzing.md`; the
[Strategy model](../concepts/strategy-model.md) places S4 among the other
strategies.

## When S4 runs

There is no separate switch. The queue carries one S4 campaign card per
target whenever the target enables a native sanitizer (`asan`, `ubsan`,
`msan`, or `tsan`) and configures that sanitizer's library, such as
`asan_lib`, in [`target.toml`](../reference/target-toml.md). A delta run
(`bin/audit --since`) and a run pinned to another strategy carry no campaign
card.

- **Who runs it.** With more than one agent, the harness gives the S4 lane
  to the highest-numbered reproduce agent while the campaign card is
  claimable; like any lane, it can later be rotated away after dry
  iterations. With a single agent, S4 is reached through
  [strategy rotation](../concepts/strategy-model.md#strategy-rotation) or a
  pin.
- **Pinning.** `bin/audit --strategy S4` runs a queue holding only the
  campaign card. On a findings-only or CLI-only target it stops with
  `LANE_UNAVAILABLE: S4 requires a native sanitizer library; use S7 for this
  findings-only or CLI-only target` in `index.log`.
- **How long.** One campaign per iteration, five minutes by default (see
  [Bounded on purpose](#bounded-on-purpose)). The agent then records the
  result and goes back to the queue.
- **What it can build.** `template`, `build`, and `run` handle C and C++
  harnesses only. `inventory` also recognises cargo-fuzz, Go, Atheris, and
  Jazzer harnesses, so it can report what they drive.

You steer S4 through the target's configuration, not through S4 settings:
the threat model decides what is admitted, a coverage sibling build decides
whether the campaign is guided, and seed inputs decide where it starts.

## The workflow

```bash
export RESULTS_DIR=output/<slug>/<backend>/results

bin/fuzz inventory          # harnesses the target already ships, and their gaps
bin/fuzz candidates         # APIs that earn a new harness, ranked
bin/fuzz template <symbol>  # skeleton in $RESULTS_DIR/fuzz/src/
bin/fuzz build              # out-of-tree compile of every harness in fuzz/src/
bin/fuzz run                # one bounded campaign
bin/fuzz status             # what each harness did, and what to do next
bin/fuzz doctor             # prove the shared build is unaffected
```

`bin/fuzz` finds the session from `--results-dir`, else `RESULTS_DIR`, else
by walking up from the current directory. During an audit the variable is
already set. By hand, it needs a results tree that an earlier
`bin/audit --target <slug>` created; otherwise it exits with
`no output/<slug>/<backend>/results/.session-env above …`. The global
options `--results-dir`, `--sanitizer` (default: the target's first enabled
native sanitizer), and `--json` go before the subcommand:

```bash
bin/fuzz --results-dir output/<slug>/<backend>/results status
```

Full syntax is in the [command reference](../reference/commands.md).
Everything a campaign writes (harness sources, built fuzzers and their
manifests, corpora, libFuzzer artifacts, slice logs, and campaign state)
stays under `$RESULTS_DIR/fuzz/`, laid out in
[Artifacts](../reference/artifacts.md#fuzzing-campaign). The one exception is
a replay: the artifact and a copy of its harness source go to
`$RESULTS_DIR/scratch-<agent>/` for `bin/probe`.

## Three structural checks admit a candidate

`bin/fuzz candidates` runs every exported symbol that a public header
declares through three checks and admits it only when all three hold. They
establish structural fit, not that the product routes untrusted input to
the symbol:

1. **Published.** The symbol is exported by `<san>_lib` or a library
   configured beside it (`link_libs`), and its declared name does not start
   with an underscore (in a static archive every cross-file helper looks
   global, and C reserves `_` names for the implementation).
2. **Input-shape compatible.** Its declaration has a parameter shape the
   target's `[threat_model].attacker_controls` can supply. Headers come from
   the configured `includes`, or from the whole source tree when none are
   configured.

    | `attacker_controls` token | Parameter shapes it admits |
    | --- | --- |
    | `bytes` | buffer and length, NUL-terminated string, stream handle |
    | `protocol-state` | buffer and length, stream handle |
    | `fs-state` | filesystem path, stream handle |
    | `call-sequence`, `call-order` | opaque state handle |
    | `timing`, `race`, `env` | nothing |

3. **Uncovered.** No harness in the target tree, and none this session
   already wrote, has an identifiable call to it. A covered symbol is
   reported as work for the existing harness instead.

Admitted symbols are ranked by how many controls reach them, their strongest
shape, whether the name carries an input-consuming verb (`parse`, `read`,
`decode`, …), and whether the call graph knows an entry route to them. The
call graph only ranks; a missing route never keeps a candidate out, because
a syntactic graph cannot see indirect dispatch.

```console
$ bin/fuzz candidates
1 admitted of 4 declared exported symbols in sampleproj (attacker_controls: bytes, call-sequence)

Admission checks the declaration's input shape, not product reachability. Trace a product input route to the selected API before building a harness.

  app_parse
    int app_parse(struct app_ctx *ctx, const unsigned char *data, size_t len);
    shape compatible with: bytes, call-sequence via buffer+length, opaque state handle
```

When nothing is admitted, the command lists symbols (up to `--limit`,
default 25) with the first reason each failed, so an empty result is
diagnostic; `--json` always includes rejected symbols with every reason. It
exits with status 3 when it can read no exported symbols at all, which
usually means the library is not built.

Widening `attacker_controls` in `target.toml` widens what is admitted, which
is the point: a target whose threat model is `bytes` should not get a
harness that fuzzes filenames.

Before writing a harness, trace a product input route to the chosen symbol.
For a vendored API, an exported header and the function's own definition do
not establish one. If no product caller or documented entry leads to it,
pick another candidate and keep the lead for source review.

## Ground the harness in local callers

`bin/fuzz template <symbol>` refuses a symbol the checks did not admit
(`--force` overrides) and writes `fuzz_<symbol>.c`, or `.cc` for a C++
target, under `fuzz/src/`. It looks for an exact call to the symbol in the
target's own fuzz sources, examples, samples, and tests, in that order, and
records up to two in the harness's `S4-RECEIPT` comment block. Those callers
usually show the constructors, related length and capacity arguments,
ownership, and teardown that a declaration cannot express. They are
construction evidence, not proof of reachability: test code may do trusted
setup an attacker cannot. With no caller found, the receipt says
`UNRESOLVED`.

The harness author fills the receipt's `INPUT-BUFFER`, `CONSTRUCTOR`,
`ARG-RELATIONS`, `RESOURCE-FLOW`, and `TEARDOWN` fields with source-anchored
facts. `INPUT-BUFFER` matters most: libFuzzer hands over an exact-size
buffer, so if every real caller adds padding or a terminator, the harness
must too (the template's `FZ_INPUT_PADDING`), or a read into that padding
becomes a crash no caller can cause.

`bin/fuzz build` binds the receipt to the exact harness source, and
`bin/fuzz status` shows which fields are still unresolved. Receipt text
never admits a target, changes scheduling, or counts as a finding.

## Real targets, not fake ones

`bin/fuzz build` refuses three shapes that reach the target as no caller
could, and names the repair for each:

- casting the fuzzer's buffer into a typed object (`(struct ctx *)data`);
- including a quoted header by a `../` path, from an `internal`,
  `private`, or `impl` directory, or named `*_internal.h`, `*_private.h`,
  or `*_impl.h`;
- hand-declaring a target function with an `extern` prototype instead of
  including its header.

A crash through any of these is a crash in the harness's fiction. Passing
the checks does not prove the setup valid; a reviewer still reads the
harness.

No fuzz artifact is filed directly. Each is copied into scratch beside its
harness source and replayed with `bin/probe --confirm --harness <harness>`
under the campaign's sanitizer. From there it is an ordinary testcase:
confirmed across five runs, deduplicated, gated, and bundled like a
hand-written one. A `timeout-` artifact is probed once first and confirmed
only if that run crashes. The replay compiles the harness's standalone
`main` (the template's `#ifndef FUZZ_CAMPAIGN_BUILD` branch), so keep both
entry points working.

## Build isolation, and why it matters across backends

**Nothing a campaign writes lands in the target's source tree or in
`build-<san>/`.** That is what lets a `claude` run and a `codex` run audit
the same checkout at once. One stray harness file in the checkout would:

- change the checkout's source signature, because build freshness counts
  untracked files (git-ignored files excepted);
- make the shared `build-<san>/` read as stale for every backend on that
  checkout;
- stall their runs for up to 15 minutes waiting for an exclusive build lease
  that no live peer will yield;
- get the divergent run refused by the source pin, because two runs reading
  one checkout at different source states are not comparable.

So `bin/fuzz build` refuses a source inside the checkout (copy a harness the
project ships into `fuzz/src/` to improve it); `build` and `run` hold only a
*shared* lease on the tree they link; and `bin/fuzz run` warns if the
checkout's source signature changed during the campaign.

`bin/fuzz doctor` checks the contract on demand (paths shortened):

```console
$ bin/fuzz doctor
target root:    targets/sampleproj
linked build:   targets/sampleproj/build-asan+fuzz
library:        targets/sampleproj/build-asan+fuzz/libsampleproj.a
feedback:       guided (SanitizerCoverage present)
campaign root:  output/sampleproj/claude/results/fuzz
build lease:    targets/sampleproj/.audit/build-locks/build-asan+fuzz.lock
writer pending: False
other readers:  False
isolation:      OK — every campaign artifact is outside the checkout
```

It exits non-zero with a `PROBLEM:` line when a harness in the checkout is
not tracked by the VCS, or when the results tree sits inside the checkout.
When the build is blind, it also prints the rebuild recipe below.

## Giving it coverage feedback

libFuzzer guides mutations through target code only when a linked target
library carries SanitizerCoverage counters. An ordinary `build-<san>/`
usually has none, so a fuzzer linked against it is **blind to target
internals**: it may still find shallow faults, and its totals can move on
the harness's own counters, but that does not mean the target is guiding
anything. `guided` status means at least one linked library has counters;
check the build if the API under test lives in a different library.

The shared tree is never rebuilt for this. When a target enables ASan,
`bin/setup-target <slug> --build` and audit preflight (for targets under
`targets/`) build two **siblings** beside `build-asan/`:

- `build-asan+fuzz`, compiled with `-fsanitize=fuzzer-no-link`, which
  `bin/fuzz` links harnesses against;
- `build-asan+cov`, compiled with `-fsanitize-coverage=trace-pc-guard`, in
  which `bin/hits --mode generic` replays testcases to report the coverage a
  probe reached (see [the audit lifecycle](../concepts/audit-lifecycle.md)).
  They cannot be one tree: libFuzzer refuses to start when any loaded object
  carries `trace-pc-guard`.

Each sibling needs `asan_lib` (the coverage sibling also accepts `asan_bin`)
to point inside `build-asan/`. It reruns the target's own `.audit/build.sh`
with `CC` and `CXX`, and `cc`, `gcc`, `clang`, `c++`, `g++`, and `clang++`
on `PATH`, pointed at shims that add the flag and hand off to an LLVM clang
that ships libFuzzer. A sibling is built only beside a fresh primary build,
is verified and stamped like it, and is rebuilt when the source or recipe
changes. Other sanitizers get no automatic siblings.

A sibling cannot stale anything: `build-<san>+…` is excluded from the
freshness walk, and its build lease is separate from `build-<san>/`'s. One
stamped from different source than the primary build is not linked;
`bin/fuzz` falls back to the plain build, and `build` and `doctor` say why.
A hand-built sibling with no stamp is used as offered.

A recipe that calls a compiler by absolute path gets no instrumentation.
Setup then reports the sibling unavailable, with its log at
`.audit/build-materialize-asan+fuzz.log` (or `…asan+cov.log`), and does not
retry until the source, recipe, or toolchain changes, or you run
`bin/setup-target <slug> --build --force`.

To build the fuzz sibling by hand, for example with a different toolchain,
put the library at the same path relative to the tree as `asan_lib` has
under `build-asan/`; `bin/fuzz` finds it by swapping the directory name. For
a CMake target:

```bash
cmake -S targets/<slug> -B targets/<slug>/build-asan+fuzz \
  -DCMAKE_C_COMPILER=/path/to/llvm/bin/clang \
  -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++ \
  -DCMAKE_C_FLAGS="-fsanitize=address,fuzzer-no-link -g -O1" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,fuzzer-no-link -g -O1"
cmake --build targets/<slug>/build-asan+fuzz
```

Use the LLVM compiler, not the target's usual one; `bin/fuzz build` and
`bin/fuzz doctor` print its exact path in their rebuild recipe. A sanitizer
runtime is version-locked to the code it instrumented, and only one runtime
can own a process. libFuzzer ships only with a full LLVM (the macOS Command
Line Tools clang has none), so where targets are built by the platform
compiler the two toolchains differ by default.

## When the toolchains differ anyway

`bin/fuzz build` starts each linked binary once with `-help=1`, so a binary
that cannot start is a build error with the runtime's own message, not a
`dead` slice. A version-lock link failure (`__asan_version_mismatch_check…`)
names the toolchain to rebuild the library with.

When the library brings its own runtime and refuses to share the process
("Interceptors are not working"), the harness is relinked without the
sanitizer. The target stays instrumented, but the harness's own stack and
globals lose their redzones, so a target overrunning a buffer its caller
owns goes unreported. The build says so, the manifest records
`sanitized: false`, and `bin/fuzz status` shows `target-only sanitizer`.

A built binary is reused until its source, compiler, sanitizer, linked
libraries, include paths, defines, or `LDFLAGS` change.

## Bounded on purpose

S4 shares an audit iteration with seven other strategies, so a campaign is a
turn, not a shift:

- The default budget is 300 seconds (`--budget-seconds`), in slices of 60
  seconds (`--slice-seconds`).
- The budget covers the **whole** campaign: first replaying artifacts left
  from an earlier campaign, then slices, new replays, and corpus merges. A
  quarter of the budget, between 10 and 45 seconds, is held back for
  replays. The last slice shrinks to fit, and the campaign stops once less
  than 10 seconds of slice would be left.
- Only one campaign runs per results tree at a time. A second agent
  assigned S4 logs "another agent is already running the campaign for this
  target; leaving the wall to it" and returns its wall to other strategies.
- S4 owns exactly one work card per target, so it cannot crowd the queue.
- The campaign ends early when every harness is quarantined, and reports
  how much budget it handed back.

After each slice the harness gets a verdict. `productive` (new edges, enough
feature growth, or a crash that is not yet a repeat) and `dry` keep it in
rotation. These quarantine it, and the budget moves to another harness:

| Verdict | Meaning | Returns |
| --- | --- | --- |
| `saturated` | No new target coverage for three slices: no new edge, and total feature growth across them of 2% or less of the harness's high-water mark. An unguided harness's own edges never count. | Automatically, when its corpus grows. |
| `blocked-on-crash` | Crashed with no new coverage for two slices running. libFuzzer stops at its first crash, so the harness cannot get past a bug already filed. | Automatically, when its corpus grows. |
| `dead` | Two or fewer executions and never reached libFuzzer's `INITED`. The verdict quotes the binary's first output line, or points you to the build log. | After you fix the harness or build. |
| `startup-crash` | Crashed while loading the initial corpus. A crashing seed is removed, the slice counts as productive, and the artifact is replayed. Otherwise read the artifact's replay verdict before editing: it tells faulty harness setup from an input that already reproduces a bug. | After you fix the harness. |
| `noise-flood` | Two slices running ended in an out-of-memory, timeout, or leak report with no new coverage. The crash gate accepts none of these. | After you bound or free the harness's allocations. |

Adding inputs to a quarantined harness's `fuzz/corpus/<harness>/` is
therefore how you put a saturated or blocked harness back in rotation.

Slices go to the harness with the best new coverage per second, plus an
exploration term, so every harness runs before any runs twice. Corpora
persist and are minimised with a libFuzzer merge every eight slices of a
harness when the budget allows. Rebuilding a harness resets its campaign
history but keeps its corpus. Progress counts libFuzzer's `ft` as well as
`cov`, because value profiling, switched on once a harness goes dry, reports
through `ft` alone.

### Seeds

An empty corpus is seeded before the first slice from small files (at most
256, each at most 64 KiB, source and build files skipped) in the target's
`seeds`, `seed_corpus`, `corpus`, `testdata`, `test-data`, `fuzz`,
`fuzzing`, `test`, `tests`, `testsuite`, and `examples` directories. A
corpus the fuzzer has already built is never re-seeded. To add more:

- point [`FUZZ_SEED_CORPUS_DIR`](../reference/environment.md#directed-fuzzing)
  at a locally staged OSS-Fuzz or ClusterFuzz corpus (nothing is fetched
  over the network);
- run `bin/find-seed <file>[:<function>]` to list in-tree inputs likely to
  reach a function, and copy them into the harness's corpus directory.

The project's own `.dict` file is passed to libFuzzer when its name matches
the harness, or when the target ships exactly one.

## Reading `bin/fuzz status`

`bin/fuzz status` joins each harness's build manifest and receipt with its
campaign state and ends every row with a `next:` recommendation: rebuild a
binary whose source changed, run a first campaign, or act on the last
verdict. It keeps the first slice (executions, edge and feature deltas,
artifacts, verdict, and log path) apart from later totals, because that is
the quickest check that a new harness really executed and that guidance
moved.

When a guided harness saturates, `next` first asks for any unresolved
receipt fields, then suggests at most one contract-preserving derivative
harness for the next iteration (one caller-controlled argument change or
one source-grounded public call), with up to three admitted **compatible
APIs** that share a non-generic parameter type, typically a struct or
handle, with the boundary. These are
hints, not scheduler rules; a derivative has its own campaign state, so its
failure never quarantines the parent. Blind harnesses and harnesses with no
receipt get generic widen-or-re-seed advice.

## Artifacts a campaign did not replay

A campaign that runs out of budget leaves the rest of its artifacts in
`fuzz/artifacts/<harness>/`, and the next campaign replays them before any
new slice. Between iterations the audit also rewrites `fuzz-leads.md` in the
results tree (`bin/triage-fuzz-crashes <results_dir> [max_leads]` by hand),
listing the newest unreplayed `crash-`, `oom-`, and `timeout-` artifacts, 20
by default. While that index holds a lead and no other agent holds the S4
card, an otherwise idle agent slot is launched to replay it.

## What the coverage numbers mean

Coverage totals are counts, not a percentage of the target reviewed.
libFuzzer's instrumented-counter total spans every loaded module, including
the harness, so `bin/fuzz status` shows it as context ("1961 edges of 84213
instrumented"), never as a fraction. It does not say how much code is
reachable from an entry point or how well that code has been tested.
