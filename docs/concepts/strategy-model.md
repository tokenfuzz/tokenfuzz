# Strategy Model

A *strategy* in TokenFuzz is a small, named recipe an agent follows
to turn a chunk of source into evidence. Each strategy specifies:

- how to pick a hypothesis;
- where to look for an input;
- how to mutate it;
- what the result means.

There are eight active strategies and a shared pattern-search reference.
Strategies are **methods, not bug categories** — a single bounds bug
can be reached by S1 (the recent fix nearby), S5 (an object-state
sequence), or S7 (an input-shape boundary), depending on which clue
is strongest.

They exist for one reason:

- to keep agents from drifting into open-ended browsing;
- to make the next session's "what did the last one try?" question
  answerable from disk.

## The catalog

| ID | Recipe | What success looks like |
| --- | --- | --- |
| **S1** Prior-fix and regression variant | Mine recent fixes and large refactors for incomplete patches, removed checks, and unfixed sibling code paths. | A regression testcase adapted from the changed or neighbouring code. |
| **S2** Invariant negation | Break asserts, preconditions, and algorithm assumptions one at a time. | An input that challenges one precise guard or state assumption. |
| **S3** Spec vs. implementation | Compare what the spec or doc requires against what the code (especially optimisation fast paths) actually does. | A testcase comparing required behaviour against the implementation shortcut. |
| **S4** Boundary-directed fuzzing | Build or improve a fuzz target, but only for a published API that untrusted input reaches and no harness drives. Ground setup/teardown in bounded local callers, retain build and first-slice receipts, run short slices, and hand every artifact to `bin/probe`. | An admitted, source-grounded harness, a coverage figure, and a confirmed crash — or a recorded reason the harness stopped paying. |
| **S5** Lifetime and state | Probe re-entrancy, error-path cleanup, ordering, and timing transitions on the same object. | A multi-step sequence that reaches a lifetime or state transition. |
| **S6** Cross-project variant mining | Take a recent fix in a peer project that implements the same spec/format/algorithm, look for the unfixed analogue here. | An adapted testcase against the local implementation. |
| **S7** Adversarial input | Build parser/decoder boundary inputs by hand. Fuzzers and harnesses belong to S4. | A targeted testcase or a minimised input. |
| **S8** Property-based oracles | Check inverse, idempotence, injectivity, numerical-domain, or format properties — silent corruption that no sanitizer catches. | A generated input with a minimised property counter-example. |
| **REF** Pattern search | Shared grep recipes used alongside any strategy. | Candidate sites and guard shapes. |

S1 is the **fallback** default, not a directive to always start with patch
mining. Prior fixes happen to carry concrete information — what changed, what
assumption was wrong, what input shape reached the code, and what nearby code
may still share that shape — but a high-signal parser surface or a peer-project
fix can outrank ordinary S1 work. The agent follows the assigned card.

## How a strategy gets assigned to a card

Strategy is not free-form. It is baked into the work card the agent
receives. When the harness ranks a source file it matches **families of
code features** — not project-specific types or filenames — and picks
the strategy that fits:

| What the file looks like | Primary strategy | Why |
| --- | --- | --- |
| Input consumers, deserializers, allocation/resize paths, raw memory calls | **S7** Adversarial input | Byte- and shape-driven code. Existing seeds and hand-written boundary inputs pay off; fuzz harnesses belong to S4. |
| Lifetime / ownership operations, unsafe escape hatches, concurrency primitives | **S5** Lifetime and state | The interesting input is a sequence, teardown path, callback order, or interleaving. |
| Assert / check / panic / precondition families | **S2** Invariant negation | The code already states the condition to challenge. |
| Exported APIs, cast-heavy paths, size arithmetic, command-injection or XXE surfaces | **S3** Spec vs. implementation | Contract, type, and size-boundary surfaces. |
| Encode/decode, compress/inflate, marshal/unmarshal, encrypt/decrypt, normalise/canonicalise/sanitise/dedupe pairs, hashers / fingerprinters / id-key generators, and declared numerical-domain functions (non-negative / finite / probability / clamp) | **S8** Property-based oracles | The code carries its own inverse, idempotence, injectivity, or numerical-domain oracle. |
| Prior-fix patch card | **S1** Prior-fix and regression variant | The fix tells you the old wrong assumption and the likely sibling sites. |
| Peer-project fix card | **S6** Cross-project variant mining | Another implementation already disclosed the shape worth checking. |
| Nothing distinctive matches | **S1** Prior-fix and regression variant | The diversity floor still samples quiet source files instead of letting regexes define scope. |

Most real files hit more than one row. When that happens, the file
gets:

- a *primary* card with the highest-priority strategy;
- a *companion* card for every other angle its own code signals.

So two agents can attack the same file from different directions
without one starving the other. A parser function with
input-consumption verbs, casts, and asserts becomes an S7 card with
S2 and S3 companions.

### Why every fired angle gets a card

Dropping the lowest-priority angles would starve that strategy across the
*whole queue*, not just on one file. Real parser files fire four or five rows
at once, so the last row would produce no card on any target — and a strategy
that owns no cards can never be assigned to an agent.

### How the visible window is filled

Scores are not comparable across strategies: S8 scores once on presence, while
S7 multiplies per match. Ordering the bounded window by score alone would
therefore order it by whichever strategy scores highest, and the window would
arrive on a handful of dense files carrying every angle of each.

Instead the window is filled by **rotating the strategies**, each taking its
highest-ranked card on a file the window does not already hold, one
buildability tier at a time. Every strategy keeps a share, and the slots buy
distinct files.

Each angle a file signals is its own card: a file that reads as both S7 and
S5 material yields one card per strategy, and each is claimed, worked, and
closed on its own evidence. Collapsing them into one card made their
completion state inseparable — a dry S7 pass retired the S5 angle with it.
Two agents can therefore hold the same file under different strategies at
once; the subsystem preference (below) keeps that from becoming the norm.

A delta run (`bin/audit --since <rev>`) fills no window at all: every card
on a file changed in `<rev>..HEAD`, or on a one-hop caller of one, is
emitted, the diversity floor is off, and the queue never expands — the
delta is the scope.

### Two card sources on top of the ranked list

- **Patch cards** (always S1) — one per recent fix commit, with the
  touched files, severity, and any testcase revisions recorded in
  the issue tracker. Old fixes receive a mild age penalty; recently
  touched fix sites get a boost.
- **Peer-fix cards** (always S6) — appended when `target.toml`
  declares peer projects, so a fix landing in one project becomes a
  probe against the unfixed analogue here.

## How a card gets to an agent

Each iteration:

1. The harness builds the ranked card list (source-feature cards,
   patch cards, peer-fix cards).
2. Each agent pulls the next eligible one.

A card is skipped if it is:

- already done or already claimed by another agent's hypothesis;
- on the same active surface another agent owns;
- incompatible with the agent's mode;
- environment-blocked — an agent already proved this compilation unit
  cannot be built or imported in the current environment;
- in a subsystem already owned by another generic-mode agent —
  *unless* the current agent has confirmed a crash or finding there.

That last exception implements "bugs cluster": once an agent proves
a subsystem productive, the diversity rule stops blocking it from
neighbouring cards in the same area. The relaxation decays after the
agent goes dry for a while, so a mined-out subsystem is eventually
released back to the normal rotation.

Claims live as append-only rows in `state/claims.jsonl`. They expire
on a timer *and* are released when the associated hypothesis closes,
so a wedged or killed agent does not poison the queue.

The net effect: agents work different angles of the same target
without duplicating effort, and a card the agent peeks at but does
not adopt stays available for the next iteration.

## Strategy rotation

An agent rotates off its current strategy after a run of dry iterations
(three by default) once its notes carry that strategy's evidence keywords —
so a strategy the agent never actually worked is not rotated away from. S1
is held longer (eight dry iterations), since patch review often takes
several iterations to bear fruit.

When it does rotate, the agent moves to the method with the most
unclaimed work that no other agent is currently running, so the fleet
spreads across strategies instead of converging on one. An agent that
never manages to produce evidence is rotated anyway, so a stuck method
cannot stall the run.

The rule of thumb: **rotate the method, not the subsystem.** A
subsystem should not be abandoned merely because notes were
written. There must be probe runs, discarded variants, or
environment blockers on disk first.

## A good hypothesis

A hypothesis:

- names a specific `file:function:line`;
- names the input shape that should reach it;
- names the guard or assumption it is trying to violate;
- names the expected diagnostic.

It is narrow enough that a single testcase resolves it. Anything
broader is a note, not a hypothesis.

## Strategy quality bar

A strategy is useful when it ends in a runnable artifact on disk:

- a saved seed;
- a testcase;
- a recorded probe verdict;
- a documented variant on a clean hit;
- an accepted crash;
- a substantive finding report.

Broad source summaries are not output.
