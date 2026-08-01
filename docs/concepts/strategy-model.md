# Strategy Model

A *strategy* in TokenFuzz is a small, named recipe an agent follows
to turn a chunk of source into evidence. Each strategy specifies:

- how to pick a hypothesis;
- where to look for an input;
- how to mutate it;
- what the result means.

There are seven active strategies, one reserved identifier, and a shared
pattern-search reference. S4 is intentionally unused; keeping the gap preserves
the meaning of the strategy codes already stored in reports and resumable state.
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
| **S4** Reserved | Unused and not assignable. | No cards, assignments, or report attribution. |
| **S5** Lifetime and state | Probe re-entrancy, error-path cleanup, ordering, and timing transitions on the same object. | A multi-step sequence that reaches a lifetime or state transition. |
| **S6** Cross-project variant mining | Take a recent fix in a peer project that implements the same spec/format/algorithm, look for the unfixed analogue here. | An adapted testcase against the local implementation. |
| **S7** Adversarial input and fuzz engineering | Build parser/decoder boundary inputs and smarter seeds. | A targeted seed, a minimised input, or a corpus variant. |
| **S8** Property-based oracles | Check inverse, idempotence, injectivity, numerical-domain, or format properties — silent corruption that no sanitizer catches. | A generated input with a minimised property counter-example. |
| **REF** Pattern search | Shared grep recipes used alongside any strategy. | Candidate sites and guard shapes. |

S1 is the **fallback** default, not a directive to always start with
patch mining. Prior fixes happen to carry concrete information — what
changed, what assumption was wrong, what input shape reached the
code, and what nearby code may still share that shape — but a
high-signal parser surface or a peer-project fix can outrank ordinary
S1 work. The agent follows
the assigned card.

## How a strategy gets assigned to a card

Strategy is not free-form. It is baked into the work card the agent
receives. When the harness ranks a source file it matches **families of
code features** — not project-specific types or filenames — and picks
the strategy that fits:

| What the file looks like | Primary strategy | Why |
| --- | --- | --- |
| Input consumers, deserializers, allocation/resize paths, command-injection or XXE surfaces, raw memory calls | **S7** Adversarial input and fuzz engineering | Byte- and shape-driven code. Seeds, minimisation, and boundary inputs pay off. |
| Lifetime / ownership operations, unsafe escape hatches, concurrency primitives | **S5** Lifetime and state | The interesting input is a sequence, teardown path, callback order, or interleaving. |
| Assert / check / panic / precondition families | **S2** Invariant negation | The code already states the condition to challenge. |
| Exported APIs, cast-heavy paths, size arithmetic | **S3** Spec vs. implementation | Contract, type, and size-boundary surfaces. |
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

Every fired angle gets a card, because dropping the lowest-priority
ones starves that strategy across the whole queue rather than on one
file: real parser files fire four or five rows at once, so the last
row produced no card on any target, and a strategy that owns no cards
can never be assigned to an agent.

Scores mean different things per strategy — S8 scores once on presence
while S7 multiplies per match — so ordering the bounded window by score
alone orders it by whichever strategy scores highest, and the window
arrives on a handful of dense files carrying every angle of each. The
window is instead filled by rotating the strategies, each taking its
highest-ranked card on a file the window does not already hold, inside
one buildability tier at a time. Every strategy keeps a share and the
slots buy distinct files.

The angles those companions carried are not lost. A selected card lists
the strategies its dropped same-file siblings held, so an agent on any of
them can claim that file — one card, every angle the file signalled. This
matters because nothing recreates a dropped card later: the claim path
reads only persisted cards, and the productive-agent relaxation lifts a
subsystem restriction on cards that exist rather than minting new ones.
Without the carried list a file would stay reachable under exactly one
strategy for the whole run.

What does change is concurrency: two agents can no longer hold the same
file under different strategies at the same time, because there is one
card to claim rather than several.

Two other card sources sit on top of the ranked list:

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

Rotation is **effort-gated, not iteration-gated** — the harness only
rotates an agent off its current strategy once it has actually done
work on it and come up dry. "Done work" means concrete evidence in
structured state: discarded hypotheses, recorded probe runs,
environment blockers, and strategy-specific output. *Notes alone do
not complete a strategy.* S1 is held longer than the other
strategies before rotation, since patch review often takes several
iterations to bear fruit.

When it does rotate, the agent moves to the method with the most
unclaimed work that no other agent is currently running, so the fleet
spreads across strategies instead of converging on one. An agent that
never manages to produce evidence is rotated anyway, so a stuck method
cannot stall the run.

S4 is reserved. The CLI rejects it, the rotation never assigns it, and reports
must not attribute new work to it.

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
