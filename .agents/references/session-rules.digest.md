# Session Rules — Digest

Embedded in every session prompt. Covers load-bearing rules only; full
rationale, examples, and the bin/state cheat sheet live in
`.agents/references/session-rules.md` — read that file only when a rule
below is ambiguous for your situation. Do NOT read the full file as a
session-start step.

## PATH CONVENTION

Every `findings/`, `crashes/`, `state/`, `scratch-*/`, and
`crashes-rejected/` reference below is a subdir of `${RESULTS_DIR}`,
where `${RESULTS_DIR}` is the absolute results path the AGENT IDENTITY
block names at the top of your session prompt. **When you write,
always use the absolute path** — `${RESULTS_DIR}/findings/FIND-1/...`,
not `findings/FIND-1/...`. A bare relative path resolves against your
shell cwd, which drifts whenever you `cd` (e.g. into the source tree
to read), and a relative `findings/FIND-1/report.md` after `cd <target>`
silently lands in the source tree instead of your results dir. The
harness's harvester only looks under `${RESULTS_DIR}`.

## Reproduction wrapper

- Default reproducer: `bin/probe <testcase>`. Reads TARGET / HYPOTHESIS-ID /
  HARNESS from the testcase header. For opaque byte inputs, preserve the bytes
  and pass `--hypothesis-id H-...`; target/card come from state. No env vars.
  - Write testcases and sibling harnesses under `${RESULTS_DIR}/scratch-N/`.
  - `bin/probe "${RESULTS_DIR}/scratch-N/tc.html"` → 1 run; `--confirm` → 5 runs.
  - Do not create repo-root `scratch-N/` dirs; a bare relative path writes to
    the shell cwd, not the active audit scratch dir.
  - MISSED → revise input, don't discard. Don't burn ASan budget.
  - Generic C/C++ falls back to `bin/run-sanitizer-multi asan generic` + `.asan.txt`.
- Clean runs over ~200 lines auto-truncate to head+tail with a
  `[run-sanitizer-multi] DIGEST: …` marker pointing at the full `.asan.txt`.
- Crash output over ~50 KB also truncates (head+tail+spill, full trace in
  `.asan.txt`). Override per-call: `SANITIZER_DIGEST_HEAD/TAIL`, `SANITIZER_NO_DIGEST=1`,
  or `OUTCAP_MAX_BYTES=0`.

## Testcase header (mandatory)

```
// TARGET: file:function:line
// HYPOTHESIS-ID: Hn
// CATEGORY: bounds|lifetime|type|size|uninit|state
// HARNESS: harness.c            (OPTIONAL — sibling harness source)
```

Use native comments: `# TARGET:` for Python, `// TARGET:` for C/C++/JS,
and `<!-- TARGET: ... -->` for HTML. Orphan testcases (missing header) are discarded.
`bin/probe` builds C/C++ harnesses from `output/<slug>/target.toml`.

## Memory before action

- `bin/find-seed <file>[:<Function>]` before writing a fresh testcase.
- `grep -A4 "SUBSYSTEM: <subsystem>" <RESULTS_DIR>/guards-db.md` before
  building a hypothesis. Append a new entry on a reproducible guard string.
- `bin/state recent-tried --agent N --limit 40` after compression. Never
  rerun identical inputs.
- If recent-tried shows `closest`, mutate around that near-miss frame before
  restarting from a broader seed.
- `bin/probe-history <testcase>` before re-probing — if a confirmed
  verdict exists, reuse it; only re-run when state has shifted.
- Do not run `bin/rank-work` just to browse cards. It rewrites the queue and
  can dump tens of KB; use `bin/state explain-queue` or
  `bin/state list-cards --limit N` for inspection.

## Search discipline (output cap is enforced)

- Every `rg`/`grep` scoped with `--glob` or a narrow directory. Scanning
  the full repo from `.` is BANNED. OR-chains (`foo|bar|baz`) are banned.
- Commands returning >200 lines are a misfire — re-scope.
- NEVER grep `output/<slug>/<backend>/logs/` or `*.log.raw`. `bin/rg-safe`
  excludes them by default.
- Don't grep `bin/`, `lib/`, or `.agents/` to reverse-engineer the harness
  (testcase headers, probe contract, CLI flags). That contract is fully
  specified in this digest — the header block, the `bin/state` cheat sheet,
  and the `bin/probe` rules above are the API. Harness source is not.
- Append-only non-state logs: `tail -50`, never `cat`. JSONL state files
  (`state/hypotheses.jsonl`, `runs.jsonl`, `tried-inputs-N.log`): use
  `bin/state show-recent` or
  `recent-hyps|recent-runs|recent-claims|recent-tried|recent-notes`, never
  `tail`/`sed`/`cat` directly.
- Crash/finding reports: `bin/state show-crash|show-finding|list-*` first;
  read full `REPORT.md` only when editing it.
- Source ranges: `bin/peek <FILE>:<start>-<end>` (exact range + 50 KB byte cap),
  or `bin/peek -A N -B M PAT FILE` (A clamped to 30, B to 8). Bare `sed`
  is also output-capped. `--no-cap` or `OUTCAP_MAX_BYTES=0` to widen.
- Prior-fix patches: `bin/show-patch <commit> [<path>]` (10-line ctx,
  1500-line / 32 KiB cap). `PATCH_CONTEXT=80` widens.
- Scratch dirs: `bin/scratch-status --agent N` instead of raw `ls -la
  output/<slug>/<backend>/results/scratch-N`; add `--files --file-limit 20`
  for a bounded newest-file inventory. Use raw `ls` only for exact
  permission/link details.
- Output cap behavior: any tool output past ~50 KB is replaced with
  head + elision marker + tail; the full original spills to
  `$TMPDIR/outcap-<label>-<sha>.txt`. Inspect it with bounded reads such
  as `bin/peek <path>:1-200` or `tail -50 <path>`. Do not `cat` spills
  unless you intentionally want the full output in the transcript. Disable
  with `OUTCAP_MAX_BYTES=0`.
- Don't run `bin/state … --help` — the cheat sheet below is the argument
  shape for every subcommand you need.
- Scratch helpers: `bin/scratch-status --agent N` for status; add
  `--files --file-limit 20` for a bounded recent file inventory.

## bin/state cheat sheet (use instead of `--help`)

```
resume        --agent N [--mode MODE] [--role reproduce|analysis] [--strategy S1..S8]
next-card     --agent N [--mode MODE] [--peek]
show-card     CARD_ID [--mode MODE]                     # compact JSON
list-cards    [--mode MODE] [--status eligible] [--strategy S] [--subsystem TEXT] [--contains TEXT] [--limit N] [--verbose]
show-crash    CRASH-ID ;  list-crashes [--status OK|NEW] [--limit N]
show-finding  FIND-ID ;  list-findings [--status OK|NEW] [--limit N]
add-hyp       --agent N --card-id ID --hypothesis 'desc' --file path:func:line \
              --input-shape 'shape' --guard-gap 'gap' \
              --diagnostic bounds|lifetime|type|size|uninit|state --strategy S1
update-hyp    --id H-... --status STATUS [--note NOTE]
update-card   --card-id ID --status claimed|done|discarded|crash|find|blocked [--note NOTE]
add-run       --agent N --hypothesis-id H-... --mode MODE --testcase TC \
              --asan-output ASAN --verdict VERDICT       # bin/probe sets these for you
add-note      --agent N --hypothesis-id H-... --kind data-flow|guard|variants|decision|context --text '...'
show-recent   [--agent N] [--hyps N] [--runs N] [--claims N] [--notes N]
recent-hyps   [--agent N] [--card-id ID] [--status REGEX] [--strategy S] [--limit N]
recent-runs   [--agent N] [--hypothesis-id H-...] [--verdict REGEX] [--limit N]
recent-notes  [--agent N] [--hypothesis-id H-...] [--kind KIND] [--limit N]
recent-tried  --agent N|all [--verdict REGEX] [--target SUBSTR] [--limit N]
explain-queue [--mode MODE] [--strategy S] [--top N] [--all]
```

`resume` Runtime Feedback is next-mutation or harness-repair guidance from
recent probe artifacts. It is not filing or discard evidence.

Card discard uses the configured floor (default: three card-linked CLEAN rows
across two actually-probed hypothesis shapes). MISSED, NO_EXEC, CRASH, and
DIFF do not count. A surface unavailable in every configured sibling
build/mode exits through ENV-BLOCKED (which soft-blocks its owning card), or a
proven mode-incompatible, stale, or non-public card may be marked `blocked`
with a precise note. MISSED alone is not proof of unreachability.

## Structured state discipline

- NEUTRAL vocabulary, describe by LOCATION (`File:Function:Line`).
- Expected Diagnostic: lifetime / bounds / type / size / uninit / state.
- Max 3 NEEDS_TESTCASE, max 3 ENV-BLOCKED concurrently.
- Before ENV-BLOCKING on **feature-disabled** ("not compiled in",
  "JIT not available", "not supported in this build"), try sibling
  builds: `ls $TARGET_ROOT/build-*` and re-run with
  `ASAN_GENERIC_BIN=…/build-asan-XYZ/bin/<binary>`. The harness also
  auto-routes; look for `[probe] ROUTED:`. Missing library / header is
  true ENV-BLOCKED — no alternate build helps.
- After context compression: run `bin/state resume --agent N`, resume the top
  PENDING item before claiming new work, and do not re-read `PRIOR SESSION SEED`
  ranges.

## CRASH promotion gate

`crashes/CRASH-*` only for legitimate sanitizer diagnostics:

1. Trusted caller uses normal public APIs; obeys ownership / lifetime /
   callback / allocator / threading / cleanup contracts.
2. Untrusted part is a normal input boundary: file/packet/web bytes,
   regex pattern, media stream, archive, IPC, CLI input.
3. Testcase does NOT mutate target-owned internals, include private APIs,
   free active callback state, switch allocators mid-flight, or free
   owners before dependents.
4. If the crash depends on a specific offset/length/index/callback
   return/lifetime/order, prove that value is reachable through the
   normal product boundary — input bytes ≠ "library exposes caller
   control of iterator offset N."

Required fields in every report:

```
Boundary:
Caller controls:
Trusted caller actions:
Caller contract: obeyed|violated|unspecified
Trigger source: bytes|call-sequence|timing|race|protocol-state|env|fs-state|both
Strategy: S1|S2|S3|S4|S5|S6|S7|S8|REF
```

`Strategy` is the investigation strategy actually in use when the
testcase was filed (S1..S8 from the strategy index, or REF for the
pattern-search library). Same field for findings/FIND-*.

`Entry` (optional, recommended): the public API function an external caller
invokes to reach the bug, call-shaped, e.g. ``Entry: pcre2_match()``.
Reachability *reports* caller reach at this entry point (prioritisation only;
not a CVSS input); otherwise it infers the entry from the deepest product frame
in the sanitizer stack.

`Parameter control` (when value-dependent): direct / mapped /
harness-only / none. The triage matrix demotes when `Trigger source`
falls outside the target's `attacker_controls` (target.toml) — a
**severity** demotion (security→robustness) that KEEPS the crash in
`crashes/`, not a move to `findings/`. File any reproducing sanitizer
crash that clears conditions 1–3 under `crashes/` regardless of trigger
source and let triage score severity; do not pre-demote a
`call-sequence`/`env`/`race` crash to `findings/` on a bytes-only target.
Caller contract violations always reject.

## FIND quality bar

A FIND is ANY concrete security issue. Reproducer not required.

Required: concrete location (`file:function:line` or equivalent),
explicit issue class (memory-safety / auth / injection / info-disclosure
/ crypto / race / boundary-violation / logic), reviewer-actionable
rationale.

NOT a FIND: pure correctness / data-integrity / robustness /
spec-deviation. Harness gate deletes non-security FINDs — don't file.

**File FIND first, reproduce second.** When analysis names a concrete
defect, file `${RESULTS_DIR}/findings/FIND-NNN-<slug>/report.md`
immediately (absolute path — see PATH CONVENTION above). Don't wait
for a sanitizer crash. S2/S3/S5/S8 strategies routinely surface defects
without an ASan crash.

Operational caps: 1 FIND/agent/iteration when you also promote a CRASH;
up to 3 FINDs/iteration in source-only mode. Distinct `file:function:line`
with independent rationales.

Point at the fix (best-effort, never blocks filing): always end `report.md`
with a `## Fix Direction` heading (on its own line) + a one-sentence body.
When the fix is a surgical diff, save it
as `patch.diff` in the FIND/CRASH dir instead — `bin/enrich-report` inlines
it as `## Patch`, so don't write that section yourself. Capture/validation
mechanics: `.agents/references/session-rules.md`.

## Pre-file checks

- Before `crashes/CRASH-*/`: check `crashes-rejected/REJECTED-CRASHES.md`.
- Before `findings/FIND-*/`: confirm security (above), scan
  `findings/FINDING-CLUSTERS.md` for existing FINDs on same location
  (Status `NEEDS CONTENT` means fix in place, don't open a duplicate).

## Differential testing (JIT/Wasm)

Browser-mode only. For `js/src/jit`, `js/src/wasm`, `js/src/irregexp`:
use `bin/probe` `MODE: js-diff` testcases; the differential harness flags
output divergence as DIFF, not CRASH.

## Drill-down

Read `.agents/references/session-rules.md` only when:
- A rule above is ambiguous for your situation
- You need the bin/state CLI cheat sheet for an unusual subcommand
- You're reviewing CRASH/FIND classification edge cases

Otherwise rely on this digest. Do NOT read the full file as a routine
session-start step.
