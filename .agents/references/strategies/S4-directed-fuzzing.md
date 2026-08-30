# Strategy S4: Boundary-Directed Fuzzing

Build a fuzz target **only** where untrusted input reaches a published API
directly, run it in short slices, and hand every artifact back to `bin/probe`.

This is the only strategy that runs a fuzzer. The other seven write testcases
by hand; if you find yourself wanting a fuzzer under S1, S2, S3, S5, S6, S7, or
S8, the answer is a work card here, not a detour there.

**Review gate:** one campaign per iteration. When `bin/fuzz run` returns,
S4 is done for this iteration — read the summary, act on it, and go back to
the queue. It exits early on purpose so the other strategies get the rest of
the wall.

---

## Why most fuzz targets are worthless, and what this does about it

Three failure modes account for nearly every wasted fuzzing hour. Each has a
countermeasure here, and the countermeasure is enforced by a tool rather than
by your good intentions.

| Failure | What it looks like | Countermeasure |
|---|---|---|
| **Fuzzing the wrong thing** | A harness on an internal helper no caller can reach with untrusted data. Runs forever, finds "bugs" nobody can trigger. | The admission gate (below). `bin/fuzz candidates` will not admit it. |
| **Fake targets** | The harness casts fuzzer bytes into a struct, includes a private header, or hand-declares a symbol. Every crash is fiction. | `bin/fuzz build` **refuses** those three shapes and names the repair. A lint, not a proof — it catches the common forgeries, not every one. |
| **Unverifiable crashes** | A fuzzer artifact filed as a finding with no confirmation, no dedup, no gate. | Every artifact is replayed by `bin/probe --confirm`. Nothing is filed any other way. |

---

## The admission gate

`bin/fuzz candidates` runs every exported symbol through three facts. All
three must hold. Each comes from a structured source, not a guess:

1. **Published** — the symbol is in the sanitizer build's exported symbol
   table, and is not a reserved identifier. An internal the linker happened to
   emit is not the boundary, and a static archive publishes every
   cross-file helper it has, so a leading underscore is taken at its word: C
   reserves that spelling for the implementation.
2. **Untrusted-reachable** — the declaration in a public header carries a
   parameter shape that this target's `[threat_model].attacker_controls` can
   actually supply. `bytes` reaches a buffer+length, a NUL-terminated string,
   or a stream; `fs-state` reaches a path; `call-sequence` reaches an opaque
   handle. A function taking only integers is reachable by nobody.
   The shape is read from the declaration, so a non-`const` pointer that is
   really an *output* buffer can still be admitted — check the direction
   before writing the harness.
3. **Uncovered** — no harness already in the tree drives it. If one does, the
   work is *improvement*, not generation. See below.

A rejected candidate is reported with the reason it failed, so "nothing was
admitted" is an answer you can act on rather than a silence.

The call graph ranks admitted candidates and never gates them. A syntactic
graph is blind to indirect dispatch, so "no path" is not evidence of
unreachability — the same rule the work-card call-neighbourhood block obeys.

---

## The workflow

```bash
bin/fuzz inventory                    # what exists, and what each one can't reach
bin/fuzz candidates                   # what earns a new harness, ranked
bin/fuzz template <symbol>            # skeleton under RESULTS_DIR/fuzz/src/
#   ... fill it in ...
bin/fuzz build                        # out-of-tree, refuses unfaithful harnesses
bin/fuzz run --budget-seconds 300     # slices, recovery, artifacts -> bin/probe
bin/fuzz status                       # what each harness did, and why it stopped
```

### 1. Inventory before you write anything

Most real targets already ship harnesses — `fuzz/`, `tests/fuzz/`,
`oss-fuzz/`. `bin/fuzz inventory` finds them (libFuzzer, cargo-fuzz, Go native
and go-fuzz, Atheris, Jazzer), reports which exported symbols each one drives,
and names its structural gaps. Inventory covers all of those ecosystems;
`template`/`build`/`run` are C/C++ only, so a Rust or Go harness is something
to read and improve in its own tree, not something this campaign builds:

| Gap | What it costs | The fix |
|---|---|---|
| `magic-gate` | An exact-match check the mutator cannot guess rejects everything. | Seed the corpus with a conforming prefix, or split the input so the magic is drawn rather than mutated. |
| `size-floor` | A large minimum length discards the entire early corpus. | Lower it, or generate seeds above the floor. |
| `single-call` | One call shape only, so lifetime and state defects are unreachable. | Draw a call sequence from the input (the template shows how). |
| `no-teardown` | Never frees, so leak reports describe the harness. | Release everything the harness allocated. |

**Improving an existing harness usually beats writing a new one.** A harness
with a `magic-gate` has been running blind in OSS-Fuzz for years on some
projects; fixing it is a few lines and opens a subsystem.

### 2. Write a faithful harness

`bin/fuzz template <symbol>` writes a skeleton carrying two entry points on
purpose: `LLVMFuzzerTestOneInput` for the campaign, and a standalone `main`
compiled only when `FUZZ_CAMPAIGN_BUILD` is undefined. The second is what lets
`bin/probe` replay one artifact against the same code. **Keep both working** —
without the `main`, a crash this target finds cannot enter the crash pipeline.

The template also records at most two exact-symbol local caller examples from
the target's tests, examples, samples, or existing fuzz sources. Read those
locations with `bin/peek` before filling the harness. Local usage is evidence
for construction, argument relationships, and teardown.
It does not prove external-party reachability or override the admission gate.
Do not search an external code index or copy an unrelated project's calling
convention.

Complete the `S4-RECEIPT` comments at the top of the source:

- `SOURCE-USAGE` — the local caller locations actually read;
- `CONSTRUCTOR` — the public operation that creates required state;
- `ARG-RELATIONS` — length/capacity/option relationships the caller preserves;
- `RESOURCE-FLOW` — ownership or state passed between public calls;
- `TEARDOWN` — the public cleanup operation and when it is valid; and
- `UNRESOLVED` — anything else source did not establish. Leave a field reading
  `UNRESOLVED` and it lists itself; this line is for the rest.

Follow a named definition for at most three call-graph or `bin/peek` hops when
one of those fields is unresolved. Leave a field `UNRESOLVED` when source
remains ambiguous: an unknown warns the next agent but never blocks build/run,
closes a card, or licenses a guessed private call. `bin/fuzz build` binds the
completed receipt to the exact harness source, and `bin/fuzz status` shows the
receipt, build state, and first-slice feedback after resume.

Fill it in in this order:

1. Draw configuration with `fz_u8` / `fz_u32`. A harness with a fixed config
   cannot find a config-dependent bug, and options are caller-influenced far
   more often than they look.
2. Construct state with the API's **own constructor**. Never fabricate it.
3. Call the admitted symbol with `fz_rest` as its payload.
4. Optionally loop two or three more calls driven by `fz_u8`. This is what
   turns a parser fuzzer into one that can reach `call-sequence` defects —
   double-free, use-after-free on teardown, state-machine confusion.
5. Free everything.

**The rules `bin/fuzz build` enforces.** These are lints over the harness
source, not a proof of faithfulness — passing them does not establish that
state was built legitimately. They catch the three shapes that produce most
fake crashes. It refuses a harness that:

- **casts fuzzer bytes to a typed object** (`(struct ctx *)data`) — no caller
  can hand the target a struct it did not build, so the crash is fiction;
- **includes a private header** (`../src/internal.h`) — what an internal
  header reaches is not the untrusted input surface;
- **hand-declares a target function** — that is how an unexported internal
  gets called, and an internal has no caller contract to violate.

These are the same fake-crash shapes that waste a reviewer's session. If a
build is refused, restructure the harness; do not work around the check.

### 3. Seed the corpus — usually already done for you

An empty corpus makes the first slices guess at the format, and on a short
budget that is most of the budget. Measured on libxml2: the same harness
reached ~1900 edges in its first slice from the target's own test files and
318 from nothing.

`bin/fuzz run` therefore seeds any *empty* corpus from the target's test data
(`seeds/`, `corpus/`, `testdata/`, `test/`, `fuzz/`) before its first slice,
and says how many inputs it copied. A corpus it has already built is never
re-seeded — that would undo the minimisation keeping slices fast.

Add better seeds by hand when the automatic ones miss the format you want:

```bash
bin/find-seed <file>[:<Function>]     # ranked real inputs already in the tree
cp <seeds> "${RESULTS_DIR}/fuzz/corpus/<harness>/"
```

A corpus survives across campaigns and across iterations, so seeding once pays
every later slice.

### 4. Run, and let it stop

`bin/fuzz run` cuts the budget into short slices and allocates them by what
each harness actually produced per second, with an exploration term that
guarantees **every harness runs before any runs twice**. After each slice it
classifies the result and moves on when a harness stops paying:

| Verdict | Meaning | What you do |
|---|---|---|
| `productive` | New edges, or a crash. | Nothing — it keeps its share. |
| `dry` | No new coverage yet. | Nothing — one or two are normal. |
| `saturated` | No new coverage for three slices. | Widen the harness, or seed it. Returns automatically when its corpus grows. |
| `blocked-on-crash` | Crashing with no new coverage. libFuzzer stops at its first crash, so it cannot get past a filed bug. | Nothing — the crash is filed. Move on. |
| `dead` | Zero executions, never reached `INITED`. | Read the build log; the library probably does not load. |
| `startup-crash` | Crashed before the corpus finished loading. | **Your harness is broken**, not the target. Fix it before believing the artifact. |
| `noise-flood` | Only OOM / timeout / leak artifacts. | Bound the allocation, or free what the harness allocates. These are auto-rejected downstream. |

The campaign ends when the budget is spent **or every harness is
quarantined**, and it refuses to start a slice it cannot finish inside the
budget. Time it does not need goes back to the other strategies — that is the
point. Do not raise the budget to keep a saturated harness running; fix the
harness, or file what you have and rotate.

For a guided harness that saturated with its receipt resolved, make at most one
derivative — and make it the *next* iteration's harness, not a second campaign
in this one. The review gate above still holds: when `bin/fuzz run` returns, S4
is done for this iteration. Preserve the admitted boundary, constructor,
teardown, and recorded argument relationships; change one caller-controlled
fixed argument or add one source-grounded public call, and rebuild. A blind
build, unresolved lifecycle, failed derivative, or CLEAN result is no evidence
that the parent API is safe and never quarantines the parent by itself. Do not
generate a batch or edit a harness automatically.

### 5. Crashes file themselves

Every artifact is copied into scratch alongside the harness source and
replayed with `bin/probe --confirm --harness <harness>`. From there it is an
ordinary crash: coverage-gated, confirmed across five runs, deduplicated,
gated, triaged, bundled. **Never file a fuzz artifact by hand** — an
unconfirmed artifact is a claim, not a finding.

If a campaign finds nothing, that is still a result. Record it with
`bin/state add-note` naming the harness, its edge count, and its verdict.

---

## Build isolation — read this before you build anything

Harness sources go under `${RESULTS_DIR}/fuzz/src/`. **Never in the target
checkout.** `bin/fuzz build` refuses an in-tree source, and the reason is not
tidiness:

- Build freshness is derived from the checkout's VCS state *including
  untracked paths*. A harness file in the tree changes the source signature.
- A changed signature makes the shared `build-<san>/` read as **stale for
  every backend on that checkout** — your claude run stales codex's build and
  vice versa.
- The rebuild that follows needs the *exclusive* build lease, which no live
  peer will yield, so runs stall for up to fifteen minutes.
- `build_lease.claim_source_pin` then refuses the divergent run outright,
  because two runs reading one checkout at different source states are not
  comparable.

One stray file stalls a whole concurrent benchmark cell. Everything S4 writes
— sources, binaries, corpora, artifacts, logs — lives under `RESULTS_DIR`,
which is per-backend, so two backends fuzz the same pinned build at the same
time and neither disturbs the other. `bin/fuzz doctor` proves it.

### Coverage feedback without touching the shared build

libFuzzer guides itself with SanitizerCoverage counters *inside the target
library*. An ordinary `build-<san>/` usually has none, and a fuzzer linked
against one runs **blind** — it still finds shallow faults but cannot tell
that an input reached new code.

The fix is a **sibling** tree, never a replacement, and the harness builds it
for you: `bin/setup-target <slug> --build` and audit preflight rerun the
target's own recipe with coverage flags into

```
targets/<slug>/build-asan+fuzz/     # same build, plus -fsanitize=fuzzer-no-link
```

so it is normally already there when your session starts (`bin/fuzz doctor`
says `guided`). The rest of this section is for building one by hand when it
is reported unavailable — a recipe that ignores `CC`/`CXX`, say.

Build it with the compiler `bin/fuzz build` names, not the one the target
normally uses: a sanitizer runtime is version-locked to the code it
instrumented, and only one can own a process. When they differ, `bin/fuzz
build` either refuses the link or relinks the harness without its own
instrumentation and tells you what that costs.

`bin/fuzz` picks it up automatically when it exists. A sibling is free of both
hazards: `build-<san>+fuzz` matches the sanitizer-build pattern that is pruned
from the source walk, so it cannot stale anything, and the build lease keys on
the directory name, so building or reading it never contends with
`build-<san>/`. `bin/fuzz doctor` reports whether the campaign is guided or
blind, and prints the recipe when it is blind.

---

## When S4 is the wrong strategy

- **The target has no native sanitizer build** (`[sanitizer] enabled = []`).
  There is nothing to link and no sanitizer to catch anything. Use S7.
- **Nothing is admitted.** Read the reasons. If the target's whole surface is
  behind `fs-state` and the threat model says `bytes`, the boundary you would
  fuzz is out of scope — that is a real answer, not a blocker to route around.
- **The bug you are chasing needs a specific multi-step setup.** A fuzzer
  reaches shapes, not plans. Write the testcase by hand under S5.
- **You have no coverage build and the API is behind a format check.** Blind
  fuzzing will not guess a container header. Seed the corpus first, or use S7.

## Attribution

Reports produced this way carry `Strategy: S4`. Note the harness path and the
campaign's edge count in the report — a crash found at 14 edges and one found
at 40,000 are very different claims about how well the surface was explored.
