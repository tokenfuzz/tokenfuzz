# Cost Model

Audit cost includes model input and output, testcase execution, and automated
review. Larger contexts usually increase latency and input-token spend;
additional workers multiply concurrent demand. TokenFuzz records these costs
and limits repeated context, oversized output, and duplicate work.

Use the [environment reference](../reference/environment.md) for worker,
wall-time, and session limits. Use [Benchmarking](benchmark.md) to compare
cost against reviewed results.

## What scales with cost

| Cost driver | Why it grows | How TokenFuzz contains it |
| --- | --- | --- |
| Cached input tokens per turn | Conversation length × cache-read price | Provider prefix caching where prompts match; compact state views; session seeds across compactions. |
| New input tokens per turn | Source dumps, raw logs, transcripts | Capped source-reading commands; structured state views. |
| Output tokens | Long model prose, narration | Strategy quality bar: agents are graded on concrete evidence saved, not words. |
| Sanitizer runs | Each run takes wall-clock and RAM; browsers cost more | Per-agent launch budget; browser/JS coverage gate; native coverage feedback. |
| Redundant work | Two agents re-exploring the same surface | Work-card leases, per-agent input memory, rejected indexes. |

Two principles explain most of these choices:

- **Reuse context that still applies.** Compact state and session seeds help
  the next agent continue without reconstructing the run from raw logs.
- **Reuse evidence that still holds.** Claims, recorded probes, and review
  receipts reduce duplicate work while leaving room for confirmation runs and
  fresh review when the source or evidence changes.

The aim is to spend the budget on investigation and verification. A smaller
transcript is useful only if it preserves the information that work needs.

## What prompt caching can reuse

Cold-start and deep-investigation prompts begin with safety framing and the
task-specific guide, followed by agent-, card-, and state-specific material.
Their long common rules are centralized in a stable suffix; compact
continuation prompts use a smaller suffix.

That stable suffix keeps prompt behavior consistent, but it does not by itself
create a cross-agent cache hit: provider caching generally reuses matching
prefixes, and the dynamic material before the suffix differs between agents.
The shared safety-and-guide prefix may still qualify where a backend supports
automatic prefix caching. Availability and price are provider-specific, so run
logs record what the backend actually reports rather than assuming a discount.

Both benchmark conditions use the same backend tool and delegation policy.
The execution boundary and available controls differ by backend; see the
[backends guide](../guides/backends.md#one-isolation-policy-for-every-launch).

Two implementation choices reduce duplicated context and cache-write cost:

- Codex loads the repo-root `AGENTS.md`, so its cold-start prompt refers to
  that copy instead of embedding it again.
- TokenFuzz defaults Claude launches to a five-minute prompt-cache tier,
  including agent sessions and one-shot decisions in both benchmark
  conditions. An explicit operator cache setting takes precedence; see
  `CLAUDE_CODE_PROMPT_CACHE_TTL` in the
  [environment reference](../reference/environment.md#model-selection).

Cache reuse depends on the provider, prompt prefix, and time between requests.
A shared rules suffix is not a reusable prefix. Local-server caching also
depends on server configuration and available capacity. Use recorded cache
usage and actual costs to assess savings; the harness cannot guarantee a
cache hit or a fixed discount.

## Capped source reading

Agents read source through capping wrappers:

- line and byte ceilings on search;
- clamped ranges on file peeks;
- per-session caches for patch diffs.

Focused reads stay bounded by the wrapper's line and byte caps. Agents that
bypass the wrappers get the same output ceiling applied automatically.

The same principle applies to probe output: `bin/probe` classifies the whole
sanitizer log, then truncates an oversized one for storage, keeping the head
and tail where the summary lives, so a multi-megabyte log never lands in the
conversation.

## Structured state over transcripts

Agents and operators read the run through compact state views rather than raw
JSON rows. The default `show-recent` view caps hypotheses, runs, and claims at
ten rows each; it is row-bounded rather than byte-bounded, so long paths can
make it larger than 4 KiB. Shell and file-reading wrappers separately cap raw
output at roughly 50 KiB. Nothing rereads a transcript to work out what
happened.

## Session seeds across compaction

When a backend compacts the conversation, or a fresh agent launches, the
harness hands it a short seed of the source ranges and testcases the last
iteration already covered, and tells it not to re-read them. An interrupted
agent does not pay twice for the same source.

## Per-agent sanitizer budget

Each agent gets a per-iteration budget of real sanitizer launches: **60 for
shell agents** and **25 for browser agents**. Coverage-gate dry runs do not
count. When the budget runs out the agent is told to wrap up its current
hypothesis; in-flight work is not killed.

This bounds one agent's spend. Without it, an agent in a tight retry loop can
burn an evening and produce nothing. To cap the *whole* continuous run
instead, set `AUDIT_WALL_BUDGET_SECS`. The loop stops launching iterations
once that budget is spent, which is how you leave an overnight audit running
with a hard stop.

A long backend session is checkpointed at the configured turn cap and
continued with fresh context. The default cap is 128 agent/tool turns,
although each backend's transport determines exactly how turns are counted.
Carrying an unbounded tool history forward costs more every turn and buys
nothing that structured state does not already hold.

## Coverage before the sanitizer

For browser and JS-shell targets with a sancov-instrumented build:

1. `bin/probe` first runs the testcase against the coverage build.
2. Only testcases that reach the named target code spend a sanitizer run.
3. Testcases that miss never spend the more expensive budget; the agent
   revises the input instead.

A native target gets the same measurement as **feedback rather than a gate**.
`bin/setup-target --build` and audit preflight build a coverage sibling,
`build-asan+cov`, by rerunning the target's own ASan recipe with
`-fsanitize-coverage=trace-pc-guard`; it never replaces the shared
`build-asan`. When a testcase names a `WANT` symbol, `bin/hits --mode generic`
replays it there (the configured CLI, or for a `// HARNESS:` route a twin of
that harness linked against the sibling's library), maps the covered PCs to
source, and writes the same HIT/MISSED rows, closest frame, and edge journal
browser mode does. A native replay costs milliseconds, so a miss does not
withhold the sanitizer: the run proceeds, the `.asan.txt` and tried-inputs row
carry `MISSED` and the closest frame, and the agent revises the input with
that evidence. When no instrumented sibling exists (a recipe that hardcodes an
absolute compiler path, or a tree outside `targets/`), coverage is reported
**unavailable** and the run proceeds; an unmeasurable input is never counted
as a miss.

## Work-card leases prevent duplicate spend

Two agents probing the same source file with the same strategy is wasted work.

- Card claims expire after 30 minutes, so a wedged agent does not poison the
  queue for an entire shift.
- A diversity gate also blocks two agents from sharing a subsystem at the same
  time.
- [Strategy model](strategy-model.md#how-a-card-gets-to-an-agent) has the
  full exclusion rules.

A second kind of duplicate spend is a proven unexecutable route. On a concrete
patch or site card, `ENV-BLOCKED` closes that card. On a broad source card it
records and demotes only the failed route; the card can be reoffered for
another route, and independent cards on the same file are not blocked by
propagation. A fresh run with a repaired toolchain starts with fresh state.

## Rejected indexes prevent refiling

Every crash candidate that fails triage is recorded with the reason in a
rejected index. Future sessions check this index before promoting a crash, so
a null-deref that gets rejected on Monday does not cost a triage round on
Tuesday and Wednesday too.

## What to monitor

Each session's usage is recorded in `logs/index.jsonl`, one row per agent
launch with a `tokens` object and the session's probe counts (`probes`,
`probe_seconds`, `probe_diagnostics`, `first_probe_seconds`). Two numbers tell
you most of what you need:

- **`tokens.cached_input`** shows how much input was served from cache.
  Compare sessions of similar length: a larger value can reflect more turns,
  a larger context, or better cache reuse.
- **`tokens.output` alongside useful artifacts.** Compare it with saved
  reports, probe results, and completed reviews. A source-review session can
  produce useful evidence without writing a testcase.

The row also records `turn_soft_cap` and `turn_capped`, so cost comparisons
can separate natural completions from sessions rolled over to fresh context,
and `served_model` when the provider billed the session to a model other than
the one requested.

For ensembling, compare these numbers across backends. A backend that produces
the same evidence with half the cached input tokens is a meaningful
operational signal, regardless of model prose quality.

### Why some numbers are marked estimated

Backends report usage differently, and the harness never presents an estimate
as a measurement:

| Backend | What it reports |
| --- | --- |
| Claude | Terminal counts on a normal finish. When stopped early, exact cache buckets are recovered from its per-request events, but the row is marked `estimated: true` because fresh input and output are then lower bounds. |
| Codex | Usage only in `turn.completed`, which a session stopped at the turn cap or the wall deadline never emits. The harness therefore runs Codex without `--ephemeral` and reads the session rollout instead; its last `token_count` recovers measured usage for the recorded session even when it did not finish. Separate delegated threads are not included in the parent's total. |
| Google Gemini CLI | Terminal counts on a normal finish; its native turn-limit result retains them. |
| OpenCode (`oss`) | Structured usage events when the transport emits them; completeness is recorded rather than assumed. |
| Antigravity, Grok | No native usage in the current transports. Rows are estimated from prompt and transcript size. |

Where a backend leaves only one turn's counters standing in for a session,
that row is flagged estimated: the counters are real, the coverage is a floor.

A cell's source is `unknown` only when a session reported no usage at all, not
when a session exited nonzero after reporting it. An `unknown` total is
missing that session's whole spend and reads low. Token and cost figures carry
at most one marker, `~`, meaning "not exact"; the `Source` column beside them
says which reason applies. `≥` is reserved for the unjudged remainder on
finding and crash counts, so the two never appear on one number.

One-shot harness decisions use the same ledger. Claude, Codex, native Gemini,
and OpenCode keep their structured usage transport, then separate the
assistant's answer before parsing the verdict. Antigravity and Grok decisions
remain explicitly estimated.

!!! warning "Codex session rollouts are audit-sensitive"
    Reading the rollout is not the same as the `--ephemeral` flag, which
    suppressed the file outright. Between a session ending and the harness
    extracting it, a full transcript of the audit (prompts, messages, tool
    activity) sits under `CODEX_HOME`. Each rollout is deleted as it is read,
    but a harness killed in that window, or an unreadable rollout, leaves the
    file in place. Treat `CODEX_HOME/sessions` as audit-sensitive, and sweep
    it after an aborted run.
