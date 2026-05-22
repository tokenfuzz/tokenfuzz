# Session Rules — Digest

Embedded in every session prompt. Covers load-bearing rules only; full
rationale, examples, and the bin/state cheat sheet live in
`.agents/references/session-rules.md` — read that file only when a rule
below is ambiguous for your situation. Do NOT read the full file as a
session-start step.

## PATH CONVENTION

Every `findings/`, `crashes/`, `recon/`, `state/`, `scratch-*/`, and
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
  HARNESS from the testcase header. No env vars to set.
  - `bin/probe scratch-N/tc.html` → 1 run; `--confirm` → 5 runs.
  - MISSED → revise input, don't discard. Don't burn ASan budget.
  - Generic C/C++ falls back to `bin/run-asan-multi generic` + `.asan.txt`.
- Clean runs over ~200 lines auto-truncate to head+tail with a
  `[run-asan-multi] DIGEST: …` marker pointing at the full `.asan.txt`.
- Crash output over ~50 KB also truncates (head+tail+spill, full trace in
  `.asan.txt`). Override per-call: `ASAN_DIGEST_HEAD/TAIL`, `ASAN_NO_DIGEST=1`,
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
- `tail -40 <RESULTS_DIR>/tried-inputs-N.log` after compression. Never
  rerun identical inputs.
- `bin/probe-history <testcase>` before re-probing — if a confirmed
  verdict exists, reuse it; only re-run when state has shifted.

## Search discipline (output cap is enforced)

- Every `rg`/`grep` scoped with `--glob` or a narrow directory. Scanning
  the full repo from `.` is BANNED. OR-chains (`foo|bar|baz`) are banned.
- Commands returning >200 lines are a misfire — re-scope.
- NEVER grep `output/<slug>/<backend>/logs/` or `*.log.raw`. `bin/rg-safe`
  excludes them by default.
- Append-only logs: `tail -50`, never `cat`. JSONL state files
  (`state/hypotheses.jsonl`, `runs.jsonl`, `tried-inputs-N.log`): use
  `bin/state recent-hyps|recent-runs|recent-tried|recent-notes`, never
  `tail`/`sed`/`cat` directly.
- Crash/finding reports: `bin/state show-crash|show-finding|list-*` first;
  read full `REPORT.md` only when editing it.
- Source ranges: `bin/peek <FILE>:<start>-<end>` (line + 50 KB byte cap),
  or `bin/peek -A N -B M PAT FILE` (A clamped to 30, B to 8). Bare `sed`
  is also output-capped. `--no-cap` or `OUTCAP_MAX_BYTES=0` to widen.
- Prior-fix patches: `bin/show-patch <commit> [<path>]` (10-line ctx,
  1500-line / 32 KiB cap). `PATCH_CONTEXT=80` widens.
- Output cap behavior: any tool output past ~50 KB is replaced with
  head + elision marker + tail; the full original spills to
  `$TMPDIR/outcap-<label>-<sha>.txt`. Recover with `cat <path>`. Disable
  with `OUTCAP_MAX_BYTES=0`.
- Don't run `bin/state … --help` repeatedly — full cheat sheet is in the
  long session-rules.md.

## State file discipline

- NEUTRAL vocabulary, describe by LOCATION (`File:Function:Line`).
- Expected Diagnostic: lifetime / bounds / type / size / uninit / state.
- Max 3 NEEDS_TESTCASE, max 3 ENV-BLOCKED concurrently.
- Before ENV-BLOCKING on **feature-disabled** ("not compiled in",
  "JIT not available", "not supported in this build"), try sibling
  builds: `ls $TARGET_ROOT/build-*` and re-run with
  `ASAN_GENERIC_BIN=…/build-asan-XYZ/bin/<binary>`. The harness also
  auto-routes; look for `[probe] ROUTED:`. Missing library / header is
  true ENV-BLOCKED — no alternate build helps.
- After context compression: read Working Context, resume top PENDING,
  no new recon, do not re-read files already in Working Context.

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

`Parameter control` (when value-dependent): direct / mapped /
harness-only / none. The triage matrix demotes when `Trigger source`
falls outside the target's `attacker_controls` (target.toml). Caller
contract violations always reject.

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

Optional but encouraged: `patch.diff` in the FIND/CRASH dir, captured
via `git diff` / `hg diff` of the surgical fix. Recommend it only after
a bounded loop of up to three validation attempts — revising the diff
between failures — shows it applies cleanly and builds with the best
available target build command (sanitizer `build-*` dir if available,
otherwise the regular build), reverting only the patched files (`git
checkout -- <file>` / `hg revert <file>`, never a whole-tree reset)
before further probes. Mark `Patch: builds` or `Patch: confirms-fix` in
report.md. If validation fails, omit `patch.diff` and write
`## Fix Direction` prose.

## Pre-file checks

- Before `crashes/CRASH-*/`: check `crashes-rejected/INDEX.md`.
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
