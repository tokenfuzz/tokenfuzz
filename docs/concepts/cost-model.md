# Cost model

Audit cost is model input and output, testcase execution, and automated
review. Larger contexts increase latency and input-token spend; more workers
multiply concurrent demand. TokenFuzz records these costs, and limits
repeated context, oversized output, and duplicate work.

This page explains what drives cost, which levers you control, and how far
to trust the recorded numbers. Use the
[environment reference](../reference/environment.md) for exact limits and
[Benchmarking](benchmark.md) to compare cost against reviewed results.

<span id="what-scales-with-cost"></span>

## What drives cost

| Cost driver | Why it grows | How TokenFuzz contains it |
| --- | --- | --- |
| Worker slots | Each slot runs sessions back to back until the wall, so the pool multiplies token spend directly. | A fixed default pool of three workers rather than one sized to the machine. |
| Cached input per turn | Every turn replays the conversation, so cost grows with session length times the cache-read price. | Turn-cap rollover to fresh context; compact state views; provider prefix caching where prompts match. |
| New input per turn | Source dumps, raw logs, repeated reads. | Capped search and read wrappers; structured state views; the **Examined so far** block and session seeds. |
| Output tokens | Long prose and narration. | Session efficiency rules in the prompt. There is no output-token cap. |
| Sanitizer runs | Each run takes wall-clock time and RAM; browsers cost more. | A per-agent launch budget per iteration; coverage checks before or beside the sanitizer. |
| Redundant work | Two agents re-exploring one surface, or re-filing one crash. | Work-card leases; examined-line receipts; duplicate crash states refused at filing; recorded route disproofs. |
| Breadth on a large tree | The window buys depth on the files the scorer likes; the rest is never opened. | The optional budgeted sweep, and `bin/state coverage` to show what remains. |
| Harness model calls | Rerank, review votes, sweep units, and cluster expansion are model calls too. | Cached verdicts reused across passes; a per-iteration cap on one-shot decisions; a fixed tool-call budget for trigger review; the sweep's own token budget. |

Two principles explain most of these choices:

- **Reuse context that still applies.** Compact state and session seeds let
  the next session continue without reconstructing the run from raw logs.
- **Reuse evidence that still holds.** Claims, recorded probes, receipts,
  and cached review verdicts reduce duplicate work, while leaving room for
  confirmation runs and fresh review when the source or evidence changes.

The aim is to spend the budget on investigation and verification. A smaller
transcript is useful only if it keeps the information that work needs.

## The levers you control

| Lever | Default | Effect |
| --- | --- | --- |
| Pool size (`NUM_AGENTS`, `SHELL_AGENTS`, `BROWSER_AGENTS`) | 3 workers | Concurrent spend, and how fast a shared provider quota drains. |
| Wall budget (`AUDIT_WALL_BUDGET_SECS`) or an iteration count | off | A hard stop for a continuous run. |
| Model and effort (`--model`, `config/models.toml`) | per backend | The per-token price and how much each turn does; see [Backends](../guides/backends.md). |
| Turn cap (`TURN_SOFT_CAP`) | 128 turns | How much history a session carries before it rolls over to fresh context. |
| Context cap (`CONTEXT_SOFT_CAP`) | off | A context-size rollover, only on backends that report per-request usage. |
| Window size (`RANK_WORK_LIMIT`) | 120 files | How much of the tree the ranked queue offers. |
| Sweep budget (`[sweep] token_budget`, `[sweep] model`) | off | Estimated tokens spent on tool-less breadth review. |
| Sanitizer budgets (`SHELL_SANITIZER_RUN_BUDGET`, `BROWSER_SANITIZER_RUN_BUDGET`) | 60 and 25 | Sanitizer launches per agent per iteration. |

Each variable is documented in the
[environment reference](../reference/environment.md), and the sweep in the
[target config reference](../reference/target-toml.md#the-budgeted-sweep-sweep).

The wall budget counts productive time: provider quota pauses are excluded,
and housekeeping is included. Once it is spent, a continuous run launches no
new session, and each session is already clamped to the wall that remained
when it started. That is how you leave an overnight audit running with a
hard stop.

A long session is checkpointed at the turn cap and continued with fresh
context; each backend's transport decides exactly how turns are counted.
Carrying an unbounded tool history forward costs more every turn and buys
nothing that structured state does not already hold.

## How token dollars are calculated

A positive cost reported by the backend CLI takes precedence. Otherwise the
harness applies public standard API token rates to the served model's usage.
A reported $0 is not treated as a price, because it cannot be told apart
from a CLI that does not price its model or plan. These are comparison
dollars: subscription fees, negotiated discounts, regional or fast-mode
premiums, tool fees, and cache-storage charges are not reconstructed.

The rate table lives in `lib/benchmark.py` (`_pricing_rates`), and its
docstring names the provider pages and the date the rates were last checked.
It holds the prices in force, including active promotions; retired model IDs
keep their last published rates. Recomputing an old ledger without reported
costs therefore uses today's table, not the historical invoice.

Three rules shape the estimate:

- **Cache writes** count as non-cache-hit input, priced at the provider's
  cache-write rate where one is published.
- **Long-context tiers** apply per request and count the whole prompt, but
  the ledger holds session totals. The harness picks the tier from the
  rendered session prompt size, which can miss growth within a long session,
  and marks any tiered cost as estimated (`~`).
- **Unknown models** have unknown dollars. When other rows are priced, their
  subtotal is marked `~` because it omits that spend. The OpenCode (`oss`)
  backend reports no cost the harness reads, so its models, local ones
  included, have dollars only when the table recognises the model ID.

## What prompt caching can reuse

Session prompts begin with the same safety framing and the audit guide
(`AGENTS.md`, or a pointer to it on backends that load it themselves),
followed by agent-, card-, and state-specific material, with the long common
rules in a suffix at the end.

That stable suffix keeps behaviour consistent, but it does not by itself
create a cross-agent cache hit: provider caching reuses matching prefixes,
and the material before the suffix differs between agents. The shared
safety-and-guide prefix may still qualify where a backend supports
automatic prefix caching. It names the results directory, so it matches only
between sessions writing to the same results tree.

Three choices reduce duplicated context and cache-write cost:

- Codex and Grok load the repo-root `AGENTS.md` themselves, so their prompts
  refer to that copy instead of embedding it again, and carry a shorter
  rules suffix.
- Claude launches default to the five-minute prompt-cache tier, for agent
  sessions and one-shot decisions alike. An explicit operator setting takes
  precedence; see `CLAUDE_CODE_PROMPT_CACHE_TTL` in the
  [environment reference](../reference/environment.md#claude-code-settings-tokenfuzz-applies).
- Claude and Google Gemini CLI sessions are invited to hand a mapping
  question (every caller of a function, where a value is set) to a read-only
  delegate, so that reading does not replay on every later turn of the main
  session. The invitation is made only where the delegate's spend lands in
  the session's own usage.

Cache reuse depends on the provider, the prompt prefix, the time between
requests, and, for local servers, their configuration and capacity. The
harness cannot guarantee a cache hit or a fixed discount; use the recorded
cache usage and actual costs to assess savings.

## Capped source reading

Agents read source through capping commands:

- `bin/rg-safe` caps search output at 20 KiB and, when it truncates,
  appends a per-file digest of the hits;
- `bin/peek` caps a line range or file at about 50 KiB;
- `bin/show-patch` caps a diff at 1,500 lines or 32 KiB and caches it, so a
  repeat call returns only the cached path and a 40-line preview.

The `grep`, `rg`, and `sed` on an agent's `PATH` carry the same ~50 KiB cap.
Other commands, and a backend's native read tool, are not capped; the prompt
steers agents to the capped ones.

Probe output follows the same principle. The agent sees a digest of each run
rather than the full log. `bin/probe` classifies the whole sanitizer log
before storing it, and truncates only a log over 8 MiB, keeping the head and
the tail where the summary lives.

Agents and operators read the run through compact state views, not raw
JSON rows or transcripts: the default `bin/state show-recent` shows ten rows
each of hypotheses, runs, and claims. The harness reads transcripts itself,
to enforce turn and context caps while a session runs and to extract usage,
the session seed, and observed file reads after it ends.

## Receipts and the budgeted sweep

An agent's receipt of the lines it read is reused by every later session on
the same file, so a pickup after compaction or by another agent starts from
the unexamined functions instead of paying to re-read the file. Breadth has
its own opt-in budget: `[sweep] token_budget` is in *estimated* tokens, each
call's reported usage also lands in the usage ledger, and a completed unit
is never bought twice. See
[The budgeted sweep](coverage.md#the-budgeted-sweep).

<span id="session-seeds-across-compaction"></span>

## Session seeds

After each session ends, the harness writes a small seed of the files and
line ranges the session read, the searches it ran, and the testcases it
wrote. It aims for 2 KiB: the oldest reads, then the oldest searches, are
dropped to fit, while the testcases written are always kept. When the same
slot next resumes an active hypothesis, its prompt carries that seed as
`PRIOR SESSION SEED` and tells it not to re-read those ranges or repeat
those searches, so an interrupted investigation does not pay twice for the
same source.

## Per-agent sanitizer budget

Each agent gets a per-iteration budget of real sanitizer launches: **60 for
shell and generic agents** and **25 for browser agents**. In a continuous
run, an iteration is a scored steward generation. Coverage-gate dry runs do
not count, and a multi-run request is clamped to what remains.

When the budget runs out, further probes return `NO_EXEC` with
`budget-exhausted`, and the agent is told to reason from source and the
output it already has and to save runs for the next iteration. In-flight
work is not killed.

This bounds one agent's spend: without it, an agent in a tight retry loop
can burn an evening and produce nothing. To cap the *whole* run, set
`AUDIT_WALL_BUDGET_SECS` or pass an iteration count.

Coverage checks protect the budget too. Browser and JS-shell targets run
each testcase against a coverage build first, and only a testcase that
reaches the named code spends a sanitizer run. A native target gets the same
measurement as **feedback rather than a gate**: its replay costs
milliseconds, so a miss is recorded with the closest reached frame and the
sanitizer still runs. See
[Coverage replay](../reference/commands.md#coverage-replay).

<span id="work-card-leases-prevent-duplicate-spend"></span>
<span id="rejected-indexes-prevent-refiling"></span>

## Leases and duplicates prevent repeat spend

Several guards stop the run paying twice for the same work:

- **Card claims** expire after 30 minutes by default, so a wedged agent does
  not hold its card for a whole shift, and agents softly prefer subsystems
  no one else is working. [Strategy
  model](strategy-model.md#how-a-card-gets-to-an-agent) has the full rules.
- **A proven unexecutable route** closes a concrete patch or site card. On a
  broad source card it demotes only the failed route, so the card can be
  reoffered for another route.
- **A duplicate crash** is refused at filing when its crash state and probe
  route match a bundle already under `crashes/`, whatever that bundle's
  review state, so agents do not re-derive and re-review one crash while
  review catches up. A materially different route is still filed; see
  [Deduplication](deduplication.md#filing-time-refusal).
- **Low-value crash classes** are rejected mechanically every time, without
  a model review.

## What to monitor

Each session's usage is recorded in `logs/index.jsonl`: one row per agent
launch, with a `tokens` object and the session's probe counts (`probes`,
`probe_seconds`, `probe_diagnostics`, `first_probe_seconds`). One-shot
harness decisions, including sweep units, append rows to the same ledger.
Two numbers tell you most of what you need:

- **`tokens.cached_input`** shows how much input was served from cache.
  Compare sessions of similar length: a larger value can reflect more turns,
  a larger context, or better cache reuse.
- **`tokens.output` beside useful artifacts.** Compare it with saved
  reports, probe results, and completed reviews. A source-review session can
  produce useful evidence without writing a testcase.

The row also records `turn_soft_cap` and `turn_capped`, to separate natural
completions from sessions rolled over to fresh context; `prompt_chars`, the
rendered prompt size the long-context tier uses; and `served_model` when the
provider billed the session to a model other than the one requested.

For ensembling, compare these numbers across backends. A backend that
produces the same evidence with half the cached input tokens is a meaningful
operational signal, whatever its prose quality.

### Why some numbers are marked estimated

Backends report usage differently, and the harness never presents an
estimate as a measurement:

| Backend | What it reports |
| --- | --- |
| Claude | Terminal counts on a normal finish. When stopped early, exact cache buckets are recovered from its per-request events, but the row is marked `estimated: true` because fresh input and output are then lower bounds. |
| Codex | Usage only at turn completion, which a session stopped at the turn cap or the wall never emits. The harness therefore reads each thread's session rollout, whose last token count recovers measured usage even for an unfinished session. |
| Google Gemini CLI | Terminal counts on a normal finish; its native turn-limit result keeps them. |
| Grok | Measured session usage from the terminal event, or from its per-request usage rows when the session was capped. |
| OpenCode (`oss`) | Structured usage events when the transport emits them; completeness is recorded rather than assumed. |
| Antigravity | No native usage in the current transport. Rows are estimated from prompt and transcript size. |

A row is also flagged estimated when a backend leaves only one turn's
counters standing in for a session (the counters are real, the coverage is a
floor), and when a Codex or OpenCode session delegated work to a subagent
whose spend is not attributed to it. Grok rows get the same flag when
delegation is seen, but Grok's delegation may not appear in its stream at
all, so its rows are also marked as unable to show it. One-shot decisions
follow the same rules; Antigravity and Grok decisions return plain text and
stay estimated.

A cell's source is `unknown` only when a session reported no usage at all,
and an `unknown` total is missing that session's whole spend, so it reads
low. Token and cost figures carry at most one marker, `~`, meaning "not
exact"; the `Source` column beside them says why. `≥` is reserved for the
unjudged remainder on finding and crash counts, so the two never appear on
one number.

!!! warning "Codex session rollouts are audit-sensitive"
    To read usage, the harness runs Codex without `--ephemeral`, so Codex
    writes a session rollout. Between a session ending and the harness
    extracting it, a full transcript of the audit (prompts, messages, tool
    activity) sits under `CODEX_HOME`. The rollouts are deleted once every
    thread of the session has been read, but a harness killed in that
    window, or an unreadable rollout, leaves the files in place. Treat
    `CODEX_HOME/sessions` as audit-sensitive, and sweep it after an aborted
    run.
