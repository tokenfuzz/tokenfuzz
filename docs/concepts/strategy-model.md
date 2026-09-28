# Strategy model

A *strategy* is a named investigation method: how an agent picks a
hypothesis, where it looks for an input, and what counts as a result. Every
work card, claim, and hypothesis records one, so the harness can steer
agents toward methods that still have work and the next session can see what
the last one tried.

There are eight active strategies, S1 through S8, plus REF, a pattern-search
library used alongside any of them. Strategies are **methods, not bug
categories**. One bounds bug can be reached by S1 (a nearby recent fix), S5
(an object-state sequence), or S7 (an input-shape boundary), depending on
which clue is strongest.

## The catalog

Indexes and report pages show these labels (the registry in
`lib/strategies.py` follows this table). Each strategy's playbook in
`.agents/references/strategies/` has a *stop rule* that tells the agent when
to give up on the method within a session; the harness's own
[rotation](#strategy-rotation) is separate.

| ID and label | Method | Playbook stop rule |
| --- | --- | --- |
| **S1** Prior-fix variant | Mine the target's own fixes and large refactors for partial or reverted patches, unfixed sibling code paths, and checks a refactor removed. | After 10 or more patches across fixes and refactors with no unfixed analogue. |
| **S2** Invariant negation | Collect debug assertions, stated algorithm assumptions, multi-precondition gates, and binding contracts; ask whether untrusted input can make one false while release code continues. | After 20 invariants classified with none reachable from untrusted input with security impact. |
| **S3** Spec vs. implementation | Hold a rule (a security invariant, a published spec requirement, or the equivalence of a fast path and a general path) beside the code that must enforce it, and show where they diverge. | After 5 relevant enforcement sites all satisfy their rules. |
| **S4** Boundary fuzzing | Build or improve one faithful fuzz harness for a published API that no harness drives, whose input the declared attacker controls, and that a product input route reaches; then run one bounded campaign. Every artifact replays through `bin/probe`. The only strategy that runs a fuzzer; see [Boundary-directed fuzzing](../guides/directed-fuzzing.md). | One campaign per iteration; at most one derivative harness, built for the next iteration. |
| **S5** Lifetime and state | Callbacks that fire while a raw reference is held, error paths that skip part of their rollback, threads racing on shared state, unverified call order, and chains of legitimate calls that build a chosen primitive. | After 8 paths examined with no testcase lead. |
| **S6** Cross-project variant | Distill fixes from peer projects that implement the same spec, format, protocol, or algorithm, and look for the unfixed analogue in the target. | After 5 source-verified peer fixes with no target analogue. |
| **S7** Adversarial input | Reason backwards from parser or decoder code to one hand-crafted input that reaches a specific error path. A minimal public-API driver may deliver it; fuzzers, harness generation, and corpora belong to S4. | After 6 targeted inputs with no crash and no lead. |
| **S8** Property oracles | Sanitizer-free oracles for silent corruption: inverse, idempotence, injectivity, numerical domain, format compliance, and semantic equivalence. In scope only where the output reaches a security decision. | Once the card's discard floor is met, discard it and end the session. |
| **REF** Pattern reference | Grep recipes (size math, type-conversion chains, sentinel collisions, dangerous sinks, and more) used beside the assigned strategy. Not a strategy. | — |

S1 is the **fallback**, not the default first move: a file that signals no
other strategy is labelled S1, and an unpinned agent starts on the S1 lane
only when no other lane has claimable cards, though rotation can move a dry
agent there. Prior fixes still carry concrete
information (what changed, which assumption was wrong), which is why patch
cards keep a large share of the window.

## How a strategy gets assigned to a card

An agent does not choose its strategy freely: the strategy is baked into
the work card it receives. When the harness ranks a source file, it matches
**families of code features** (verb stems, macro shapes, libc and POSIX
calls, language keywords), never project-specific types or filenames. The
rows below are in precedence order: the first row a file matches decides its
*primary* strategy.

| What the file contains | Primary strategy | Why |
| --- | --- | --- |
| A security decision: access control, identity or origin, credential or signature verification, query or template construction, outbound-request destination, filesystem path effect, command or injection sink, deserialization sink, or XML external-entity parser | **S3** | The defect is a wrong answer to a rule, not a malformed byte. |
| An input-consumption entry point (a `read`, `parse`, `decode`, `scan`, `recv`, … call) or a socket or TLS endpoint | **S7** | Byte- and shape-driven code with an input route. Raw memory and allocation calls raise the file's rank, but do not make it S7 work on their own. |
| Lifetime or ownership operations, `unsafe` escape hatches, concurrency primitives, or state-machine transitions | **S5** | The interesting input is a sequence, teardown path, callback order, or interleaving. |
| Assert, check, or precondition macros | **S2** | The code already states the condition to challenge. |
| Cast-heavy paths, size arithmetic, or an exported API surface | **S3** | Contract, type, and size-boundary surfaces. |
| An inverse pair (encode/decode, serialize/deserialize, encrypt/decrypt, …), an idempotent normaliser (normalise, canonicalise, sanitise, escape, …), an identity or cache-key generator, or a declared numerical domain | **S8** | The code carries its own oracle. A one-way codec counts only when its inverse exists somewhere in the target. |
| Nothing distinctive | **S1** | The file is still auditable; see the diversity floor below. |

Most real files match several rows. The file then gets a *primary* card for
the first row and a *companion* card for every other strategy its code
signals, so two agents can work one file from different angles. A parser
file with input-consumption calls, casts, and asserts becomes an S7 card with
S2 and S3 companions; a file touched by a prior-fix commit also gets an S1
companion. An S7 companion needs the same input route an S7 primary does.

Each angle is its own card, closed on its own evidence, so a dry S7 pass
cannot retire an untried S5 angle. Every fired angle gets a card, because
real parser files fire four or five rows, and dropping the lowest-priority
ones would leave that strategy with no cards anywhere in the queue.

### Other card sources

- **Patch cards** (always S1) come from the target's commit history. Each
  card is one fix commit, sited at its first touched file that still exists;
  when several commits share that file, a normal run keeps the
  highest-ranked. Commits whose message names a defect class rank first;
  CI, build, and documentation commits are skipped. Older fixes lose rank,
  and fixes to recently changed files gain it.
- **Peer-fix cards** (always S6) come from the peer projects declared in
  [`[s6_peers]`](../reference/target-toml.md). Audit sessions have no
  network, so the fix diff or advisory excerpt is fetched beforehand and
  rides on the card. An advisory with no evidence link, excerpt, or local
  clone is skipped; clone the peer under `targets/` to make it usable. A run
  pinned to S6 whose peers yield no card stops with `LANE_UNAVAILABLE`.
- **The S4 campaign card** is one target-wide fuzzing campaign rather than a
  card per file, because one campaign covers every admitted API with one
  corpus. It exists only when the target enables a native sanitizer and
  configures that sanitizer's library, and never in a delta run or a run
  pinned to another strategy. A dry campaign does not retire it: one
  harness proves nothing about the APIs no harness drives yet.
- **Call-edge cards** (always S3) are the second pass over files whose
  functions have all been examined. File cards cover functions; these cover
  the contract between caller and callee, where a size, lifetime, or
  encoding assumption changes hands. See
  [Review coverage](coverage.md#the-second-pass).

??? note "Patch-card ranking values"
    `bin/patch-cards` reads the last five years of history by default, at
    most 25,000 commits. A fix loses 3 points per year of age, at most 30,
    and gains 20 when its files changed in the last 180 days.

### How the visible window is filled

A run hands agents a bounded window of `RANK_WORK_LIMIT` ranked files (120
by default; see [Environment
variables](../reference/environment.md#worker-pool)), with every card of a
selected file riding along. A file's score adds its code-feature points,
path shape, and boosts for sitting near a prior fix, in an under-covered
subsystem, or where a clean seed already reaches it. A file under a
vendored-dependency directory (`3rdparty/`, `third_party/`, `vendor/`,
`subprojects/`, and their spellings) has its score halved outside a delta
run: it stays in scope, but its upstream usually fuzzes it already.

Scores are not comparable across strategies, because some rows score once on
presence and others multiply per match. Ordering by score alone would hand
the window to whichever strategy scores highest, so it is filled in steps:

1. **Buildable first.** Cards whose file has a compiled object in a
   sanitizer build come before the rest.
2. **Patch cards next.** Within a tier, patch cards take their slots first,
   capped at half the window (but at least 10).
3. **Strategies take turns.** The remaining slots rotate across strategies,
   each taking its highest-ranked card on a file the window does not already
   hold, so every strategy keeps a share and the slots buy distinct files.
   S1-labelled source cards take no turn; they fill whatever is left.
4. **Quiet files still get sampled.** Files scoring zero or less form a
   separate **diversity floor**, labelled S1. Up to 12 slots
   (`RANK_WORK_DIVERSITY_FLOOR`, never more than a fifth of the window) go
   to them, round-robin across subsystems, so the ranking rules do not
   define the audit's scope.

When no agent can be offered an unworked card, the harness logs
`BATCH_EXHAUSTED` and ranks again with the window grown by another
`RANK_WORK_LIMIT` files. Growth stops once ranking returns fewer files than
the window holds, and never happens in a delta run or a run pinned to S4 or
S6.

A run pinned with `--strategy` keeps only that lane's cards, led by those
whose own reasons carry the lane's evidence (for S3, a security decision
rather than size arithmetic alone). A delta run fills no window at all; see
[Delta audits](audit-lifecycle.md#delta-audits). The model rerank then
orders the window by how directly the declared attacker controls reach each
file ([`RANK_WORK_LLM_MODE`](../reference/environment.md#model-decisions));
it reorders cards, and never adds or hides one.

## How a card gets to an agent

Three steps put a card in front of an agent. The harness repeats the first
two at the start of every iteration, and at every steward tick in a
continuous run.

1. **The harness materializes the queue** (`work-cards.jsonl`) from all the
   card sources above, rebuilding it only when a ranking input (source,
   configuration, ranking code, coverage or seed state) changes or the
   window grows.
2. **The harness gives each agent a strategy lane.** Lanes go out in order
   of claimable card count, with ties broken by measured yield (S3, S7, S5,
   S2, S8, then numbering). An agent keeps its lane until rotation moves it,
   or until the lane runs out of claimable cards while the agent holds no
   work in it. When there is more than one agent and the campaign card is
   claimable, the highest-numbered reproduce agent gets the S4 lane, since a
   campaign is execution work and only one can run at a time. A
   `--strategy` pin puts every agent on one lane and suspends rotation.
3. **The agent claims the next eligible card in its lane.** Companion cards
   carry their own strategy, so an S2 agent can claim the S2 companion of a
   file whose primary card is S7.

A card is skipped when:

- it is closed for the run (see below);
- it has an active hypothesis, or another agent holds a live claim on it;
- its work surface (for a source card, the same file under the same
  strategy) has an active hypothesis or a live claim;
- its mode is incompatible with the agent's mode.

Cards close differently by kind. A concrete card (a patch, peer-fix, or
call-edge card) closes on `done`, `discarded`, or `blocked`, though one
concluded as a crash or finding stays open until it has been concluded more
times than it has distinct hypotheses. A ranked source card and the S4
campaign card close only on `blocked`, because a dry pass cannot prove a
whole file, or every undriven API, exhausted. `ENV-BLOCKED` follows the same
split: it closes a concrete card, but on a broad source card it demotes only
the failed route, so other routes on the same file stay eligible.

A generic-mode agent also softly prefers subsystems no other agent is
working. The preference yields when nothing else is eligible, and in two
other cases:

- **Bugs cluster.** An agent that confirmed a crash or finding in a
  subsystem may keep picking cards there, until agents working that
  subsystem go two scored iterations in a row without a new result. A new
  result there resets the count.
- **Fresh work beats diversity.** When every card outside the occupied
  subsystems has already been worked and the occupied ones still hold
  untouched cards, the untouched cards are offered instead.

Among eligible cards, the claimer offers first a card the agent already
holds, then, for a reproduce agent, a file with a compiled object. After
that it prefers the lane's own work (patch cards in the S1 lane, primary
cards before companions, unworked cards whose reasons carry the lane's
evidence), then the card with the least prior work and, among broad cards,
the file with the smallest examined share (see
[Review coverage](coverage.md)). Queue rank breaks the remaining ties.

Claims expire after 30 minutes by default (`WORK_CARD_CLAIM_TTL_SECONDS`),
so a wedged or killed agent cannot poison the queue. Between sessions the
harness also releases a claim no active hypothesis backs (at once when every
hypothesis on the card is terminal, after a five-minute grace when none was
opened), so a card an agent looked at but did not adopt returns to the
queue. A running session's claims are never released this way.

To see why cards are not being offered, run
`bin/state --results-dir "$RESULTS" explain-queue`, adding `--strategy <S>`
to test one lane. It groups the queue by reason, such as
`terminal:<status>`, `active-hypothesis`, `claimed-surface`,
`claimed-subsystem`, or `strategy-incompatible:<strategy>`.

## Strategy rotation

In an unpinned run, the harness moves an agent to another strategy when its
current one stops paying, but only after structured state shows the method
was actually tried.

An agent's *dry streak* grows by one for each iteration in which it adds no
new crash or finding (a duplicate of an already filed bug does not count),
and resets on a productive one. In a continuous run an iteration is one
steward tick, and only agents that ended a session during it are scored; the
cohort scheduler scores every agent at the end of each iteration. The agent
rotates when all of these hold:

- the streak has reached **3** iterations, or **8** for S1, since patch
  review often takes several iterations to bear fruit;
- the agent has no active hypothesis; and
- its evidence for the current strategy has reached the threshold (**2**,
  or 1 for S6). Evidence is the agent's notes that use that strategy's
  vocabulary, plus cards it claimed and closed in that lane. Without this
  check, a strategy the agent never actually worked would be rotated away.

An agent that never produces the evidence is rotated anyway after five more
dry iterations, so a stuck method cannot stall the run.

The new strategy is one with claimable cards, preferring one no other agent
holds, then the one with the most claimable cards; when no other strategy
has cards, the agent moves to the next in numbering. The fleet therefore
spreads across methods instead of converging on one. Each rotation is logged
in `logs/index.log` as
`STRATEGY_ROTATION: agent=<N> <old>-><new> dry=<streak> evidence=<count>/<threshold> cards=<count>`.
To check an agent's evidence count, run
`bin/state --results-dir "$RESULTS" strategy-status --agent <N> --strategy <S>`.

Separately, an agent whose lane has no claimable card is reassigned the next
time lanes are handed out, without waiting for a streak (step 2 of
[How a card gets to an agent](#how-a-card-gets-to-an-agent)).

The rule of thumb agents follow (`AGENTS.md`): **switch strategy first, not
subsystem.** An agent keeps its active hypotheses across rotations and moves
to another subsystem only after a confirmed crash or finding opens
neighbouring cards to it, or when the queue hands it a card elsewhere.

## A good hypothesis

A hypothesis row (`bin/state add-hyp`) names:

- a specific `file:function:line`;
- the input shape that should reach it;
- the guard or assumption it is trying to violate;
- the expected diagnostic, as one of the neutral categories `bounds`,
  `lifetime`, `type`, `size`, `uninit`, or `state`;
- the strategy it is worked under.

It is narrow enough to name a falsifiable trigger. One clean probe can close
a deterministic hypothesis, but only when the testcase directly exercises
every named boundary value or call step. Allocator-, scheduler-, race-, GC-,
timing-, re-entrancy-, and state-dependent hypotheses need repetition or
distinct shapes.

Closing a hypothesis is not the same as retiring its card. Before a dry card
can be discarded, it needs three `CLEAN` probe runs across two distinct
hypotheses by default (`WORK_CARD_MIN_RUNS_BEFORE_DISCARD`,
`WORK_CARD_MIN_HYPS_BEFORE_DISCARD`): a minimum per card, not a quota per
hypothesis. A `CLEAN` run whose coverage check reported `MISSED` does not
count. Even then, a broad whole-file card stays reofferable after its dry
pass, because finite probes cannot exhaust its unexamined functions.

## Attribution

Every crash and finding report carries a `Strategy:` field (`S1` through
`S8`, or `REF` when the pattern library led to it), and cluster tables and
evidence pages credit the bug to that method. Probe runs are attributed
through their hypothesis: `bin/state --results-dir "$RESULTS" strategy-yield`
reports runs, crash yield, and probe seconds per strategy. Read the seconds,
not only the run count: one run of a looping harness can stand for thousands
of calls, and a run with no recorded duration counts as untimed, not free.
