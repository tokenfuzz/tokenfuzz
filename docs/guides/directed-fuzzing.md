# Boundary-directed fuzzing

Strategy S4 is the only part of TokenFuzz that runs a fuzzer. It exists to
answer a narrow question well: *which published API can an attacker reach
directly, and does one exist that no harness already drives?* Everything else
about it — the campaign scheduler, the health verdicts, the build isolation —
follows from keeping that answer honest and cheap.

For the agent-facing playbook see
`.agents/references/strategies/S4-directed-fuzzing.md`. This page is for
operators: what it will and will not do to your checkout, and how to give it
coverage feedback.

## The workflow

```bash
RESULTS=output/<slug>/<backend>/results

bin/fuzz inventory        # what the target already ships
bin/fuzz candidates       # what earns a new harness
bin/fuzz template <sym>   # skeleton in $RESULTS/fuzz/src/
bin/fuzz build            # out-of-tree compile
bin/fuzz run              # one bounded campaign
```

Everything lands under `$RESULTS/fuzz/`:

| Path | Contents |
| --- | --- |
| `fuzz/src/` | Harness sources. Never in the target checkout. |
| `fuzz/bin/` | Built fuzzers and their compiler logs. |
| `fuzz/corpus/<harness>/` | The corpus, which survives across campaigns. |
| `fuzz/artifacts/<harness>/` | libFuzzer's crash/OOM/timeout artifacts. |
| `fuzz/logs/<harness>/` | One log per slice. |
| `fuzz/campaign.jsonl` | Every slice's verdict and measurements. |
| `fuzz/state.json` | Per-harness history and quarantine state. |

## Only three facts admit an API

`bin/fuzz candidates` admits a symbol when all three hold, each read from a
structured source rather than guessed:

1. **Published** — present in the sanitizer build's exported symbol table and
   not a reserved (`_`-prefixed) identifier. That second half matters for a
   target whose `<san>_lib` is a static archive: an archive has no export
   list, so `nm` reports every cross-file helper as global.
2. **Untrusted-reachable** — its declaration in a public header carries a
   parameter shape the target's `[threat_model].attacker_controls` can supply.
   `bytes` reaches a buffer+length, a string, or a stream; `fs-state` reaches
   a path; `call-sequence` reaches an opaque handle.
3. **Uncovered** — no harness in the tree already drives it.

Rejections are reported with their reason, so an empty result is diagnostic:

```console
$ bin/fuzz candidates
2 admitted of 5 declared exported symbols in vulnlib (attacker_controls: bytes, call-sequence)

  vl_parse
    int vl_parse(struct vl_ctx *c, const unsigned char *data, size_t len);
    reachable by: bytes, call-sequence via buffer+length, opaque state handle
```

Widening `attacker_controls` in `target.toml` widens what is admitted — which
is the point. A target whose threat model is `bytes` should not get a harness
that fuzzes filenames.

## Real targets, not fake ones

`bin/fuzz build` refuses three shapes that reach the target as no caller
could: casting fuzzer bytes into a typed object, including a private header,
or hand-declaring a symbol. Each refusal names the repair. A crash found
through any of those is a crash in the harness's fiction, and triaging one
costs a reviewer a session.

These are lints, not proofs. Passing them does not establish that a harness
built its state legitimately or called only public APIs — they catch the
common forgeries, and the reviewer still reads the harness.

Every artifact a campaign produces is replayed with
`bin/probe --confirm --harness <harness>`, so a fuzz crash is coverage-gated,
confirmed across five runs, deduplicated, gated, and bundled exactly like a
hand-written one. The generated harness template carries a standalone `main`
under `#ifndef FUZZ_CAMPAIGN_BUILD` to make that replay possible — keep it.

## Build isolation, and why it matters across backends

**Nothing S4 does writes to the target checkout or to `build-<san>/`.**

That is a hard requirement, not a style preference, and it is what lets a
claude run and a codex run audit the same checkout at once:

- Build freshness is derived from the checkout's VCS state **including
  untracked paths**. A harness file left in the tree changes the source
  signature.
- A changed signature makes the shared `build-<san>/` read as stale for *every
  backend on that checkout*.
- The rebuild that follows needs the exclusive build lease, which no live peer
  will yield, so runs stall for up to `LEASE_WAIT_SECONDS` (15 minutes).
- `build_lease.claim_source_pin` then refuses the divergent run outright,
  because two runs reading one checkout at different source states are not
  comparable.

So one stray harness file can stall a whole concurrent benchmark cell.
`bin/fuzz build` refuses an in-tree source for that reason, a campaign holds
only a *shared* build lease, and `bin/fuzz run` compares the checkout's source
signature before and after and warns loudly if anything changed.

```console
$ bin/fuzz doctor
target root:    targets/vulnlib/src
linked build:   targets/vulnlib/src/build-asan+fuzz
feedback:       guided (SanitizerCoverage present)
campaign root:  output/vulnlib/claude/results/fuzz
build lease:    targets/vulnlib/src/.audit/build-locks/build-asan+fuzz.lock
writer pending: False
other readers:  False
isolation:      OK — every campaign artifact is outside the checkout
```

## Giving it coverage feedback

libFuzzer guides itself with SanitizerCoverage counters *inside the target
library*. An ordinary `build-<san>/` usually has none, so a fuzzer linked
against one runs **blind** — it still finds shallow faults, but it cannot tell
that an input reached new code, and every coverage number stays flat.

Do not rebuild the shared tree to fix that. Build a **sibling**:

```bash
# However this target normally builds, with coverage added, a different output
# directory, and the compiler that links the harnesses. For a cmake target:
cmake -S targets/<slug>/src -B targets/<slug>/src/build-asan+fuzz \
  -DCMAKE_C_COMPILER=/path/to/llvm/bin/clang \
  -DCMAKE_CXX_COMPILER=/path/to/llvm/bin/clang++ \
  -DCMAKE_C_FLAGS="-fsanitize=address,fuzzer-no-link -g -O1" \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,fuzzer-no-link -g -O1"
cmake --build targets/<slug>/src/build-asan+fuzz
```

Use that compiler and not the target's usual one — `bin/fuzz build` prints its
exact path when it needs it. A sanitizer runtime is version-locked to the code
it instrumented, and only one runtime can own a process, so a library built by
a different toolchain either fails the harness link outright or forces the
harness to give up its own instrumentation. libFuzzer ships only with a full
LLVM, so on a machine whose targets are built by the platform compiler the two
differ by default.

## When the toolchains differ anyway

`bin/fuzz build` links every harness with the sanitizer, then runs the binary
once with `-help=1` — enough to load the libraries and start the runtime, and
not enough to execute an input. A binary that cannot start is a build error
carrying the runtime's own message, rather than a campaign slice reported as
`dead`.

One failure has a fallback: when the library brings its own runtime and refuses
to share the process ("Interceptors are not working"), the harness is relinked
without the sanitizer, which leaves one runtime and a target that is still
fully instrumented. What it loses is the redzones around the *harness's* own
stack and globals, so a target overrunning a buffer its caller owns goes
unreported. `bin/fuzz build` says so and prints the rebuild recipe above; the
binary's manifest records `sanitized: false`.

`bin/fuzz` finds `build-<san>+fuzz` automatically and links against it. A
sibling is safe for the same two reasons the plain tree is not: the
`build-<san>+…` name is already pruned from the source walk that decides build
freshness, so it cannot stale anything, and the build lease keys on the
directory name, so building or reading it never contends with `build-<san>/`.

## Bounded on purpose

S4 shares an audit iteration with seven other strategies, so a campaign is a
turn rather than a shift:

- The default budget is five minutes; `--budget-seconds` changes it.
- The budget covers the **whole** campaign — slices, artifact replays, and
  corpus merges — not just the fuzzing. A slice that cannot finish inside the
  remaining budget is never started, and a budget shorter than one slice
  shrinks the slice rather than overrunning.
- Only one campaign runs per results tree at a time. A second agent assigned
  S4 finds the lock held and returns its wall to the other strategies rather
  than queueing.
- S4 owns exactly one work card per target, so it cannot crowd the queue the
  way a per-file strategy does.
- The campaign ends early when every harness is quarantined, and reports how
  much of the budget it handed back.

A harness is quarantined — and the budget moves to another — as soon as it
stops paying:

| Verdict | Meaning |
| --- | --- |
| `saturated` | No new coverage for three slices. Revived automatically when its corpus grows. |
| `blocked-on-crash` | Crashing with no new coverage; libFuzzer stops at its first crash, so it cannot get past a filed bug. |
| `dead` | Zero executions — usually the library failed to load. |
| `startup-crash` | Crashed before the corpus finished loading. The harness is broken, not the target. |
| `noise-flood` | Only OOM/timeout/leak artifacts, which are auto-rejected downstream anyway. |

Slices are allocated by measured new-edges-per-second with a UCB1 exploration
term, so every harness runs before any runs twice and a quiet one is revisited
rather than written off. Corpora persist and are periodically minimised, which
is what makes many short slices as good as one long run.

An empty corpus is seeded automatically from the target's own test data before
the first slice — on libxml2 that is the difference between ~1900 edges and
318 in the first slice. Point
[`FUZZ_SEED_CORPUS_DIR`](../reference/environment.md#directed-fuzzing) at a
locally staged OSS-Fuzz or ClusterFuzz corpus to seed from it too; the harness
never fetches one over the network. A corpus the fuzzer has already built is
left alone, and the project's own `.dict` is attached when one matches the
harness name.

Progress counts libFuzzer's `ft` as well as `cov`. Value profiling — switched
on once a harness goes dry, which is when a magic-byte comparison is the
likely wall — reports through `ft` alone, so a campaign watching edges only
would call the harness mined out exactly when it started making progress.

Coverage totals are reported, never divided. libFuzzer's instrumented-counter
total spans every loaded module including the harness's own translation unit;
it is not the code reachable from this entry point, so it cannot say whether a
harness is narrow or nearly done.
