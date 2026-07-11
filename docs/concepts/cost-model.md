# Cost Model

Long, useful LLM-based audit runs are mostly a **context-economy
problem.** Every assistant turn re-reads the entire prior
conversation as cached input. Anything that grows the conversation
grows the per-turn cost.

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
| Cold-start recon | Breadth-first survey of the in-scope source set | Cached on target source SHA so subsequent audits against the same commit skip recon entirely. |

The two anchors are simple. **Avoid re-reading**: every byte the
agent has already seen should not be sent again. **Avoid re-running**:
every probe that has already happened should not be repeated by
another agent. Every mechanism below is a specific application of one
of those — the columns of the table above map onto these two rules.

## Cache-friendly prompt prefix

The harness writes a fixed-suffix file (`.static-prompt-rules.md`)
once per iteration, plus a safety-framing block computed once per
audit process. Every agent's prompt begins with that identical
prefix, so each backend's prompt cache absorbs the prefix on every
turn and the harness pays the cache-hit price (a fraction of the
normal input price) instead of the full prefill price.

The dynamic parts of the prompt (coverage-gap suggestions, cross-agent
summaries, the agent's own state snippets) are computed per agent
during prompt assembly — they are not shared across agents. The cost
win is from the static prefix, not from sharing dynamic content.

## Capped source reading

Agents read source through capping wrappers:

- line and byte ceilings on search;
- clamped ranges on file peeks;
- per-session caches for patch diffs.

A typical "look at this function" turn stays under a few KiB of new
context. Agents that bypass the wrappers get the same output ceiling
applied automatically.

The same principle applies to probe output. `bin/probe` caps
oversized sanitizer logs before classification, keeping the head and
tail where the actual sanitizer summary lives. Operators can override
the cap for trusted local reruns; the default protects the
conversation from pulling multi-megabyte logs into context.

## Structured state over transcripts

Tailing raw state files is expensive — each row is multi-KB JSON.
The state views the agent and operator both use emit pipe-delimited
slim rows.

Representative ratio from a real run: 40 raw state rows returned 26
KB; the equivalent slim view was about 3 KB.

## Session seeds across compaction

After each completed agent launch, the harness extracts a small seed from
the structured transcript. The seed records source searches, file ranges,
and testcase paths already used. The next iteration combines it with
`bin/state resume --agent <n>` and tells the agent not to repeat those reads.

Net effect: an agent that has been compacted does not pay for
re-reading the last iteration's source after a fresh launch or compaction.

## Per-agent sanitizer budget

Each agent has a per-iteration budget of actual sanitizer launches.
The defaults are **25 for browser-mode agents** and **60 for shell-mode
agents**.

- Coverage-gate dry-runs (browser/JS only) do not count.
- When the budget is exhausted, the harness warns the agent and
  directs it to wrap up the active hypothesis. The enforcement is
  soft — in-flight work is not killed mid-turn.

This is the lever that bounds long unattended runs. Without it, one
agent in a tight retry loop can burn an evening of wall-clock time
and produce nothing.

Long backend sessions also have an automatic command-count guard. The
watcher ends an oversized session cleanly so the next iteration can resume
from structured state instead of carrying hundreds of tool calls forward.

## Coverage gate before sanitizer (browser/JS only)

For browser and JS-shell targets with sancov-instrumented builds:

1. `bin/probe` first runs the testcase against the coverage build.
2. Only testcases that reach the named target code spend a
   sanitizer run.
3. Testcases that miss never spend the more expensive budget — the
   agent revises the input instead.

For generic CLI targets (most non-browser audits) the coverage gate
is **not** used: every probe runs the sanitizer directly. The savings
on those targets come from the per-agent budget and from rejected
indexes, not from a coverage pre-check.

## Work-card leases prevent duplicate spend

Two agents probing the same source file with the same strategy is
wasted work.

- Card claims expire on a timer, so a wedged
  agent does not poison the queue for an entire shift.
- A diversity gate also blocks two agents from sharing a subsystem at
  the same time.
- See
  [Strategy model](strategy-model.md#how-a-card-gets-to-an-agent)
  for the full exclusion rules.

Build-feature gating prevents a different kind of duplicate spend.
When the sanitizer build compiles a translation unit as a stub, the
queue marks its cards `blocked` in this result set. Future agents
don't rediscover the same "not in this build" wall until the
operator rebuilds or starts a fresh run.

## Rejected indexes prevent refiling

Every crash candidate that fails triage is recorded with the reason
in a rejected index. Future sessions check this index before
promoting a crash — so a null-deref that gets rejected on Monday
does not cost a triage round on Tuesday and Wednesday too.

## What to monitor

The harness records each iteration's usage in the structured session
index (`logs/index.jsonl`). Backends report usage differently — Claude
and Codex emit real token counts, while the `gemini` backend (`agy`)
surfaces no usage telemetry, so its token counts are **estimated** from
the prompt bytes and transcript length (roughly 4 characters per token)
and flagged `estimated: true` rather than measured. Treat those rows as
approximate, not exact.

The numbers to watch in `logs/index.jsonl`:

- **`tokens.cache_read` per iteration.** Should be stable. Rising
  without growing output means the agent is dumping logs into
  context.
- **`tokens.output` vs. testcases written.** High output with no
  testcases is a "model wrote a lot of prose" smell.
- **Sanitizer runs vs. budget.** Chronic budget exhaustion suggests
  the agent is stuck in a guard chain (see
  [Strategy model](strategy-model.md#strategy-rotation)).
- **Claims released vs. claims taken.** A high ratio means agents
  adopt cards but do not finish hypotheses. The work-card surface
  keeps expiring.

For ensembling, compare these numbers across backends. A backend
that produces the same evidence with half the cached input tokens
is a meaningful operational signal — regardless of model prose
quality.
