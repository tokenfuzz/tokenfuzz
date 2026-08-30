# Cost Model

Long, useful LLM-based audit runs are mostly a **context-economy problem**.
Backends account for context differently, but later turns generally carry an
accumulated prompt or compacted summary. More source, logs, and narration in
that context means more latency and usually more input-token cost.

A naive agent that dumps raw logs into context turns a $20 session
into a $200 session without finding anything extra. TokenFuzz treats
context size as a first-class resource and gives the harness concrete
levers to keep it bounded.

A long run, in practice, is just the audit command without an
iteration count:

```bash
bin/audit --target <target> --backend <backend>
```

The rest of this page is what keeps that run cheap enough to leave
running.

## What scales with cost

| Cost driver | Why it grows | How TokenFuzz contains it |
| --- | --- | --- |
| Cached input tokens per turn | Conversation length × cache-read price | Shared prompt cache; capped state views; session seeds across compactions. |
| New input tokens per turn | Source dumps, raw logs, transcripts | Capped source-reading commands; structured state views. |
| Output tokens | Long model prose, narration | Strategy quality bar: agents are graded on testcases written, not words. |
| Sanitizer runs | Each run takes wall-clock + RAM; browsers cost more | Per-agent sanitizer-run budget; coverage gate before sanitizer run. |
| Redundant work | Two agents re-exploring the same surface | Work-card leases, per-agent input memory, rejected indexes. |

The two anchors are simple. **Avoid re-reading**: every byte the
agent has already seen should not be sent again. **Avoid re-running**:
every probe that has already happened should not be repeated by
another agent. Every mechanism below is a specific application of one
of those — the columns of the table above map onto these two rules.

## Cache-friendly prompt prefix

Every agent's prompt begins with an identical fixed prefix (the shared rules
and safety framing). Hosted backends that expose prompt caching can reuse that
stable prefix; other transports still benefit from keeping the changing tail
small. Cache availability and price are provider-specific, so run logs record
what the backend actually reports rather than assuming a discount.

Only the parts that genuinely differ per agent — coverage-gap
suggestions, cross-agent summaries, the agent's own state — come after
that prefix. The cost win is the stable prefix, not any sharing of the
dynamic tail.

## Capped source reading

Agents read source through capping wrappers:

- line and byte ceilings on search;
- clamped ranges on file peeks;
- per-session caches for patch diffs.

A typical "look at this function" turn stays under a few KiB of new
context. Agents that bypass the wrappers get the same output ceiling
applied automatically.

The same principle applies to probe output: `bin/probe` truncates an
oversized sanitizer log before classification, keeping the head and
tail where the summary lives, so a multi-megabyte log never lands in
the conversation.

## Structured state over transcripts

Agents and operators read the run through compact state views rather
than raw JSON rows — roughly a tenth of the bytes for the same
information. Nothing rereads a transcript to work out what happened.

## Session seeds across compaction

When a backend compacts the conversation, or a fresh agent launches,
the harness hands it a short seed of the source ranges and testcases
the last iteration already covered, and tells it not to re-read them.
An interrupted agent does not pay twice for the same source.

## Per-agent sanitizer budget

Each agent gets a per-iteration budget of real sanitizer launches:
**60 for shell agents** and **25 for browser agents**. Coverage-gate
dry runs do not count. When the budget runs out the agent is told to
wrap up its current hypothesis; in-flight work is not killed.

This bounds one agent's spend. Without it, an agent in a tight retry
loop can burn an evening and produce nothing. To cap the *whole*
continuous run instead, set `AUDIT_WALL_BUDGET_SECS` — the loop stops
launching iterations once that budget is spent, which is how you leave
an overnight audit running with a hard stop.

A long backend session is also checkpointed once it has run a few dozen
commands, and continued with fresh context. Carrying hundreds of tool
calls forward costs more every turn and buys nothing that structured
state does not already hold.

## Coverage before the sanitizer

For browser and JS-shell targets with a sancov-instrumented build:

1. `bin/probe` first runs the testcase against the coverage build.
2. Only testcases that reach the named target code spend a
   sanitizer run.
3. Testcases that miss never spend the more expensive budget — the
   agent revises the input instead.

A native target gets the same measurement as **feedback rather than a gate**.
`bin/setup-target --build` and audit preflight build a coverage sibling,
`build-<san>+fuzz`, by rerunning the target's own recipe with
`-fsanitize-coverage=trace-pc-guard`; it never replaces the shared
`build-<san>`. When a testcase names a `WANT` symbol, `bin/hits --mode
generic` replays it there — the configured CLI, or for a `// HARNESS:` route a
twin of that harness linked against the sibling's library — maps the covered
PCs to source, and writes the same HIT/MISSED rows, closest frame, and edge
journal browser mode does. A native replay costs milliseconds, so a miss does
not withhold the sanitizer: the run proceeds, the `.asan.txt` and tried-inputs
row carry `MISSED` and the closest frame, and the agent revises the input with
that evidence. When no instrumented sibling exists (a recipe that ignores
`CC`/`CXX`, or a tree outside `targets/`), coverage is reported
**unavailable** and the run proceeds; an unmeasurable input is never counted as
a miss.

## Work-card leases prevent duplicate spend

Two agents probing the same source file with the same strategy is
wasted work.

- Card claims expire after 30 minutes, so a wedged agent does not
  poison the queue for an entire shift.
- A diversity gate also blocks two agents from sharing a subsystem at
  the same time.
- See
  [Strategy model](strategy-model.md#how-a-card-gets-to-an-agent)
  for the full exclusion rules.

A second kind of duplicate spend is the unbuildable surface. Once an
agent proves that a file cannot be built or imported in this
environment, its card and the neighbouring cards on the same
compilation unit are marked blocked, so later agents do not rediscover
the same wall. A fresh run with a fixed toolchain re-evaluates them.

## Rejected indexes prevent refiling

Every crash candidate that fails triage is recorded with the reason
in a rejected index. Future sessions check this index before
promoting a crash — so a null-deref that gets rejected on Monday
does not cost a triage round on Tuesday and Wednesday too.

## What to monitor

Each iteration's usage is recorded in `logs/index.jsonl`, one row per
agent launch with a `tokens` object. Two numbers tell you most of what
you need:

- **`tokens.cached_input`** should be roughly stable per iteration.
  Rising without more output means an agent is pulling logs or source
  dumps into context.
- **`tokens.output` against testcases written.** Lots of output and few
  testcases is the "model wrote an essay" smell.

The row also records `turn_soft_cap` and `turn_capped`, so cost comparisons can
separate natural completions from sessions rolled over to fresh context.

For ensembling, compare these numbers across backends. A backend that produces
the same evidence with half the cached input tokens is a meaningful operational
signal — regardless of model prose quality.

### Why some numbers are marked estimated

Backends report usage differently, and the harness never presents an estimate
as a measurement:

| Backend | What it reports |
| --- | --- |
| Claude | Terminal counts on a normal finish. Stopped early, exact cache buckets are recovered from its per-request events, but the row is marked `estimated: true` because fresh input and output are then lower bounds. |
| Codex | Usage only in `turn.completed`, which a session stopped at the turn cap or the wall deadline never emits. The harness therefore runs Codex without `--ephemeral` and reads the session rollout instead — its last `token_count` is measured, and covers every thread rather than only the ones that finished. |
| Google Gemini CLI | Terminal counts on a normal finish; its native turn-limit result retains them. |
| Antigravity, Grok | No native usage in the current transports. Rows are estimated from prompt and transcript size. |

Where a backend leaves only one turn's counters standing in for a session, that
row is flagged estimated: the counters are real, the coverage is a floor.

A cell's source is `unknown` only when a session reported no usage at all — not
when a session exited nonzero after reporting it. An `unknown` total is missing
that session's whole spend and reads low. Token and cost figures carry at most
one marker, `~`, meaning "not exact"; the `Source` column beside them says
which reason applies. `≥` is reserved for the unjudged remainder on finding and
crash counts, so the two never appear on one number.

One-shot harness decisions use the same ledger. Claude, Codex, native Gemini,
and OpenCode keep their structured usage transport, then separate the
assistant's answer before parsing the verdict. Antigravity and Grok decisions
remain explicitly estimated.

!!! warning "Codex session rollouts are audit-sensitive"
    Reading the rollout is not the same as the `--ephemeral` flag, which
    suppressed the file outright. Between a session ending and the harness
    extracting it, a full transcript of the audit — prompts, messages, tool
    activity — sits under `CODEX_HOME`. Each rollout is deleted as it is read,
    but a harness killed in that window, or an unreadable rollout, leaves the
    file in place. Treat `CODEX_HOME/sessions` as audit-sensitive, and sweep it
    after an aborted run.
