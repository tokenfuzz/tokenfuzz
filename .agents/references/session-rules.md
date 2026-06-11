# Session Rules Reference

Read this file ONCE at session start. Do NOT re-read it every iteration.

## PATH CONVENTION

Every `findings/`, `crashes/`, `recon/`, `state/`, `scratch-*/`,
`crashes-rejected/`, and `findings-rejected/` reference in this file
is a subdir of `${RESULTS_DIR}`, where `${RESULTS_DIR}` is the
absolute results path the AGENT IDENTITY block names at the top of
your session prompt. **When you write, always use the absolute path**
— `${RESULTS_DIR}/findings/FIND-1/...`, not `findings/FIND-1/...`. A
bare relative path resolves against your shell cwd, which drifts
whenever you `cd` (e.g. into the source tree to read); a relative
`findings/FIND-1/report.md` after `cd <target>` silently lands in the
source tree, and the harness's harvester only looks under
`${RESULTS_DIR}`.

## Browser-Mode Environment Limits

The ASan browser runs under `MOZ_HEADLESS=1`. WebGL context creation (`canvas.getContext("webgl")`) and WebGPU adapter requests (`navigator.gpu.requestAdapter()`) return null/fail in this configuration. Do not write hypotheses that depend on GPU context creation — mark them ENV-BLOCKED immediately instead of spending ASan budget discovering this. Subsystems that are fully reachable in headless mode (2D canvas, ImageEncoder, DOM, fetch, streams, etc.) are unaffected.

## Alternate Sanitizer Builds (try sibling `build-*` before ENV-BLOCKED)

Many targets ship more than one ASan build directory because different
code paths need different configure flags. pcre2's JIT lives in
`build-asan-jit/`, not `build-asan/`. zlib's gz code may live under a
suffixed build. A probe that fails with a **feature-disabled** signature
(*not* a missing library / missing header) is routable, not env-blocked.

If a probe returns a phrase like `not compiled in`, `not supported in
this build`, `feature disabled`, `JIT not available`, `not enabled at
configure time`, or a feature-disabled return code, **before** marking
the hypothesis ENV-BLOCKED:

1. `ls $TARGET_ROOT/build-*` — these are alternate sanitizer builds.
2. For each candidate whose `bin/<same-binary-name>` exists, re-run the
   probe with `ASAN_GENERIC_BIN=$TARGET_ROOT/build-asan-XYZ/bin/<binary>
   bin/probe …`.
3. Only ENV-BLOCK after at least one alternate build was tried and also
   failed with the same feature-disabled signature.

The harness will also auto-route at `bin/probe` time (see the
`[probe] ROUTED:` log line), so you may never see a feature-disabled
diagnostic in the first place. The rule above is the manual fallback for
edge cases the auto-router misses (custom binaries, exotic features).

Missing libraries / missing headers / unable to load shared library are
true ENV-BLOCKED — no alternate build helps; mark them ENV-BLOCKED
immediately.

## Coverage-Gated Reproduction (MANDATORY WORKFLOW)

Default reproduction wrapper is `bin/probe <testcase>`. It chooses the cheapest
correct runner from the testcase's header: coverage-gated ASan for browser/js
when possible, generic ASan for generic targets, and differential mode when the
testcase has `MODE: js-diff`. **No env vars to set** — TARGET, HYPOTHESIS-ID,
HARNESS, and (derived) WANT all come from the header. RESULTS_DIR / TARGET_ROOT
are discovered by walking up to `output/<slug>/.session-env`.

```
bin/probe scratch-N/tc.html               # 1 run (exploration)
bin/probe --confirm scratch-N/tc.html     # 5 runs (after first crash)
bin/probe scratch-N/tc.xml -- 8 100       # trailing args go to the harness
```

- `scratch-N/...` is resolved against the active `RESULTS_DIR`; do not create
  top-level repo `scratch-N/` dirs. Native harness outputs belong under
  `RESULTS_DIR/scratch-N/` and should normally be built by `bin/probe`.
- MISSED → revise input, don't discard. Don't spend ASan budget.
- Generic C/C++ targets do not support coverage gating; `bin/probe` falls back
  to `bin/run-asan-multi generic` and saves a sibling `.asan.txt`.
- Clean (no-crash) runs whose stdout exceeds ~200 lines are auto-truncated to
  first 80 + last 120, with a `[run-asan-multi] DIGEST: …` marker pointing at the
  full `.asan.txt`. Crash runs are never truncated. Override per-call with
  `ASAN_DIGEST_HEAD=N ASAN_DIGEST_TAIL=M bin/probe …` or `ASAN_NO_DIGEST=1`.

## Testcase Header Coupling

Every testcase MUST begin with native comment lines containing these fields:
```
// TARGET: file:function:line
// HYPOTHESIS-ID: Hn
// CATEGORY: bounds|lifetime|type|size|uninit|state
// HARNESS: harness.c            (OPTIONAL — sibling harness source)
```

Use the source language's comment syntax so the testcase remains executable:
Python uses `# TARGET: ...`, C/C++/JS use `// TARGET: ...`, and HTML uses
`<!-- TARGET: ... -->`. Orphan testcases (missing headers) are discarded.

`// HARNESS:` points to a sibling source under the testcase directory.
`bin/probe` builds C/C++ harnesses on demand against
`output/<slug>/target.toml`'s `asan_lib` + includes + link_libs, and also
supports compiled `.rs/.go/.swift` harnesses plus interpreted language
harnesses by extension. Replaces hand-written `testcase.sh` shell wrappers.

## Seed Corpus First

Check for in-tree seeds before writing from scratch:
```
bin/find-seed <file>[:<Function>]
```
If it returns candidates, read the top 2-3 and start from seed + delta.
If it returns nothing, write from scratch — seeds bootstrap mutation,
they aren't a prerequisite.

## Guards Database (Cross-Session Memory)

Before building a hypothesis:
```
grep -A4 "SUBSYSTEM: <your-subsystem>" <RESULTS_DIR>/guards-db.md
```
If a guard is listed, plan the documented bypass or pick a different target.
When your testcase dies to a reproducible guard string, append a new entry.

## Tried-Inputs Memory (Survives Compression)

Every `bin/probe` / `bin/run-asan-multi` run appends to `TRIED_INPUTS_LOG`. After context compression:
```
tail -40 <RESULTS_DIR>/tried-inputs-N.log
```
Don't rerun identical inputs.

## Search Discipline

- Every `rg`/`grep` call MUST be scoped with `--glob` or a narrow directory.
- Scanning `output/` or the full repo from `.` is BANNED.
- OR-chain patterns (`foo|bar|baz`) are banned — split them.
- Commands returning >200 lines are a misfire. Re-scope.
- Use `tail -50` on append-only logs. Never `cat` them.
- NEVER grep `output/<slug>/<backend>/logs/` or `*.log.raw` files. Those are
  agent transcripts containing prior tool outputs — matching inside them
  poisons your context with self-quoted JSON. `bin/rg-safe` excludes them
  by default; the only escape hatch is `--include-logs` (audit work only).
- For `state/hypotheses.jsonl`, `state/runs.jsonl`, `tried-inputs-N.log`:
  never `tail`/`sed`/`cat` them directly. Use the slim accessors:
  - `bin/state recent-hyps  [--agent N] [--card-id ID] [--status REGEX] [--limit N]`
  - `bin/state recent-runs  [--agent N] [--hypothesis-id H-...] [--verdict REGEX]`
  - `bin/state recent-tried --agent N|all [--verdict REGEX] [--hypothesis H-...]`
  Each is ~6–10× smaller than the equivalent `tail` and returns only the
  columns triage actually needs. The full files stay on disk; reach for
  `--no-cap`/`--limit 0`/raw `tail` only when you genuinely need every field.
- For `crashes/CRASH-*/REPORT.md` and `findings/FIND-*/REPORT.md`: use
  `bin/state show-crash`, `list-crashes`, `show-finding`, and
  `list-findings` first. Read the full `REPORT.md` only when editing that
  report or reproducing that specific artifact.
- For broad source/repo searches, use `bin/rg-safe <rg args>` instead of bare
  `rg`. It enforces TWO caps (200 lines + 128 KiB) and excludes log paths
  by default. Override with `--no-cap` / `RG_CAP=0`, `--no-cap-bytes` /
  `RG_BYTES=0`, or `--include-logs` only when you really need them.
- For viewing source ranges, prefer `bin/peek <FILE>:<start>-<end>` or
  `bin/peek -A N -B M PATTERN FILE` over `sed -n 'X,Yp'` and `grep -A 95`.
  `bin/peek` clamps `-A` to 30 and `-B` to 8 by default (the values that
  cover normal function-context viewing); pass `--no-cap` to widen.
  Bare `sed` is also output-capped (200 lines / 128 KiB) so a stray
  `sed -n '1,500p' BIG_FILE` no longer floods context. Set
  `CAP_LINES=0 CAP_BYTES=0 sed …` for the rare full-stream case.
- For viewing prior-fix patches, use `bin/show-patch <commit> [<path>]`
  instead of `git show --unified=80`. Default context is 10 lines
  (`PATCH_CONTEXT=80` to widen). Bad/unknown hashes return a single-line
  error, not a multi-line splat. 80-line context is rarely necessary and
  burns 50–90 KB per call.
- Don't run `bin/state … --help` repeatedly. The cheat-sheet below covers
  every subcommand's argument shape. This file is the single source of
  truth — resume payloads no longer ship a copy.

## bin/state CLI Quick Reference

Use these instead of `--help`. Sized for one-shot recall, not exhaustive
documentation.

```
bin/state resume        --agent N [--mode browser|js|generic] [--role reproduce|analysis]
bin/state next-card     --agent N [--mode browser|js|generic] [--peek]
bin/state show-card     CARD_ID|--card-id ID [--mode MODE]       # compact JSON
bin/state explain-card  CARD_ID|--card-id ID [--mode MODE]       # alias
bin/state list-cards    [--mode MODE] [--status eligible] [--limit N]
bin/state show-crash    CRASH-ID|--crash-id ID                  # compact JSON
bin/state list-crashes  [--status OK|NEW|...] [--limit N]
bin/state show-finding  FIND-ID|--finding-id ID                 # compact JSON
bin/state list-findings [--status OK|NEW|...] [--limit N]
bin/state add-hyp       --agent N --card-id ID --hypothesis 'desc' --file path:func:line \
                        --input-shape 'shape' --guard-gap 'gap' \
                        --diagnostic {bounds|lifetime|type|size|uninit|state} --strategy S1
bin/state update-hyp    --id H-... --status STATUS [--note NOTE]
bin/state update-card   --card-id PATCH-... --status {claimed|done|discarded|crash|find|blocked}
bin/state add-run       --agent N --hypothesis-id H-... --mode MODE --testcase TC \
                        --asan-output ASAN --verdict VERDICT \
                        [--testcase-sha1 HEX] [--asan-runs N]   # bin/probe sets these
bin/state add-note      --agent N --hypothesis-id H-... \
                        --kind data-flow|guard|variants|decision|context --text '...'
bin/state recent-hyps   [--agent N] [--card-id ID] [--status REGEX] [--strategy S] [--limit N]
bin/state recent-runs   [--agent N] [--hypothesis-id H-...] [--card-id ID] [--verdict REGEX] [--limit N]
bin/state recent-notes  [--agent N] [--hypothesis-id H-...] [--kind KIND] [--limit N]
bin/state recent-tried  --agent N|all [--verdict REGEX] [--hypothesis H-...] [--target SUBSTR] [--limit N]
```

Search & diff helpers:

```
bin/rg-safe <rg args>            source search under targets/; line+byte caps
bin/scratch-search PATTERN       audit-artifact path inventory under $RESULTS_DIR
                                 (scratch-*, corpus, crashes, findings; per-
                                 section labeled output). Default is paths only.
bin/scratch-search --lines --section SECTION PATTERN
                                 old file:line:body behavior for a narrow section
bin/probe-history TESTCASE       read-only digest of prior bin/probe runs for
                                 a testcase (by path AND content sha1); also
                                 --hypothesis-id / --card-id / --all. Does
                                 NOT run anything — `bin/probe --confirm` to
                                 refresh evidence.
bin/peek <FILE>:<start>-<end>    show a clamped line range
bin/peek -A N -B M PAT FILE      grep with clamped -A / -B (defaults: A=30 B=8)
bin/show-patch <commit> [path]   git show with --unified=10, 1500-line cap,
                                 and 32 KiB byte cap; clipped diffs append a
                                 per-file --stat tail so you can drill in
                                 with `bin/show-patch <commit> -- <file>`.
```

Do NOT pass `targets/` and `output/` roots to the same `rg-safe` call.
Use `rg-safe` for source code, `scratch-search` for audit artifacts. Treat
plain `scratch-search PATTERN` as an inventory step: it tells you which files
match without dumping bodies. When the body matters, drill into one section
with `bin/scratch-search --lines --section <section> PATTERN` or inspect one
file with `bin/peek`.
Before re-probing reflexively, check `bin/probe-history <testcase>` — if a
confirmed verdict (asan_runs=5) exists in this session, you already have the
evidence; only re-run when state has shifted (binary rebuilt, harness edited,
or you want to refute a flaky single-run result).

Resume payload tuning (env vars, set per call when needed):

```
STATE_RESUME_RECENT_LIMIT=N      max rows in each Recent-* section (default 3)
STATE_RESUME_INCLUDE_TRIED=1     add Recent Tried Inputs section back to resume
STATE_RESUME_QUEUE_HEALTH_LIMIT  max queue-health rows (default 8)
RG_CAP=N | RG_BYTES=N            override rg-safe line / byte caps
CAP_LINES=N | CAP_BYTES=N        override generic rg/grep/sed wrapper caps
PEEK_GREP_AFTER=N | _BEFORE=N    override bin/peek -A / -B clamps
PEEK_MAX_LINES=N                 override bin/peek line-range clip
PATCH_CONTEXT=N | PATCH_MAX_LINES=N | PATCH_MAX_BYTES=N   widen show-patch
                                 (defaults: ctx=10, lines=1500, bytes=32 KiB;
                                 either clip fires a per-file --stat tail)
```

## State File Management

- Use NEUTRAL vocabulary. Describe by LOCATION: "issue in File:Function:Line".
- Expected Diagnostic column uses ONLY: lifetime / bounds / type / size / uninit / state.
- Keep `## Primary Subsystem: <path>` at the top, updated on every rotation.
- Max 3 NEEDS_TESTCASE, max 3 ENV-BLOCKED at any time.
- Write Working Context after each investigation milestone.

## After Context Compression

1. Read your state file's Working Context section first
2. Resume top PENDING hypothesis
3. No new recon
4. Do NOT re-read files already in Working Context

## Rejected Crashes & Findings

Before filing `crashes/CRASH-*/`, check `crashes-rejected/INDEX.md`.
Before filing `findings/FIND-*/`, do BOTH:
1. Confirm the issue is a SECURITY finding — crosses or weakens a security boundary, lets an caller read/write/escalate/bypass/leak/corrupt. Pure correctness, data-integrity, robustness, or spec-deviation bugs are NOT security findings; log them as state notes only. The harness gate moves rejected FINDs to `findings-rejected/`.
2. Scan `findings/FINDING-CLUSTERS.md` for an existing FIND on the same location. The Status column flags content-less directories (NEEDS CONTENT) — fix those in place instead of opening a duplicate.

Don't re-file already-rejected crash classes.

## CRASH Promotion Gate (Legitimate Crashes Only)

`crashes/CRASH-*` is only for legitimate sanitizer diagnostics:

1. Trusted caller code uses normal public APIs and obeys ownership, lifetime, callback, allocator, threading, and cleanup contracts.
2. The untrusted part is a normal input boundary: file bytes, packet bytes, web content, regex pattern, media stream, archive, IPC/message bytes, CLI input, or equivalent.
3. The testcase does not directly mutate target-owned object internals, include private/test-only target code, free active callback state, switch allocators after target allocations exist, return impossible callback lengths, or free an owner before using a dependent object.
4. If the crash depends on an API parameter, offset, length, index, callback return value, object lifetime, or call order, the testcase must prove that this value or sequence is exposed through the normal product boundary. Input bytes becoming a parsed application variable is not enough by itself. Do not equate "JSON contains index=6" with "the JSON library exposes caller control of iterator offset 6" unless a real public API path legitimately maps that field to that offset while obeying contracts.

Do not file caller-misuse or harness-artifact crashes in `crashes/` (item 3 above
is the exact list of what those are). API-hardening crashes — an in-domain typed
value the docs do not forbid, reproduced through a public boundary — DO belong in
`crashes/`; they are the dominant bug class in mature C/C++ libraries, not a
contract violation. For a borderline caller-misuse / harness-artifact case, keep
iterating toward a legitimate input boundary or mark the hypothesis DISCARDED.

Every crash report must include these exact fields:

```
Boundary:
Caller controls:
Trusted caller actions:
Caller contract: obeyed
Trigger source: bytes
Strategy: S<N>
```

`Strategy` is the investigation strategy that produced this report —
one of `S1`..`S8` (see `.agents/references/strategies/README.md`),
or `REF` when only the pattern-search library was used. This is the
strategy the agent was actually running when the testcase was filed,
not the strategy the work card was originally tagged with. Findings
under `findings/FIND-*` carry the same field.

`Caller contract` ∈ {obeyed, violated, unspecified}. Use `unspecified` when
the public docs are silent about the call ordering you depend on — defaulting
to `obeyed` inflates verdicts.

`Entry` is optional but recommended: the public API function an external
caller invokes to reach the bug, written call-shaped on its own line, e.g.
``Entry: pcre2_match()``. Reachability scoring measures external-caller
popularity at this entry point; without it the scorer falls back to inferring
the entry from the deepest product frame in the sanitizer stack.

`Parameter control` is optional but required when the finding depends on a
specific offset, size, index, count, callback return, lifetime transition, or
call order. State one of:

- `direct` — external input is consumed by the target API as that parameter
  under normal contracts, for example a file length field used by the parser's
  own copy loop.
- `mapped` — trusted product code deliberately maps input to a public API
  parameter as part of normal behavior, and the report names that product path.
- `harness-only` — the testcase/harness reads input and then supplies an
  out-of-contract parameter/offset/lifetime transition; this is robustness, not
  a security crash for a bytes-only target.
- `none` — no caller-controlled parameter is involved.

`Trigger source` lists what an external caller must supply to reach the
crash. Comma-separated tokens, normalized to the same vocabulary as
`attacker_controls`: `bytes` (`data` is an accepted alias), `call-sequence`
(synonyms: `call-order`, `sequence`), `timing`, `race`, `protocol-state`,
`env`, `fs-state`, or `both` (expands to `bytes,call-sequence`).

The triage matrix demotes a crash from security to robustness when any
component is outside the target's `attacker_controls` (declared in
`output/<slug>/target.toml`'s `[threat_model]` section). Examples:

| Target           | attacker_controls               | Trigger source | Verdict      |
|------------------|---------------------------------|----------------|--------------|
| libxml2          | bytes                           | bytes          | security     |
| libxml2          | bytes                           | call-sequence  | robustness   |
| firefox          | bytes, call-sequence, timing    | call-sequence  | security     |
| firefox          | bytes, call-sequence, timing    | bytes          | security     |
| openssl (parser) | bytes                           | bytes          | security     |
| openssl (parser) | bytes                           | race           | robustness   |

`Caller contract: violated` always rejects regardless of trigger.

The verdict above is a **severity** outcome triage applies, not a filing decision
for you. A `robustness` verdict KEEPS the crash in `crashes/` (triage flags it and
the reachability scorer deprioritizes it) — it is not moved to `findings/`. So when
a testcase reproduces a sanitizer diagnostic through a public boundary and clears
conditions 1–3, file it under `crashes/` regardless of trigger source. Do not
pre-demote a `call-sequence`/`env`/`race` crash to `findings/` just because the
target is bytes-only; triage does that math once.

## FIND Quality Bar

A FIND is ANY concrete security issue in the target. A sanitizer reproducer, runnable testcase, or web-reachable trigger is NOT required. Memory safety, logic flaws, auth bypass, injection, info disclosure, crypto weakness, races, sandbox / privilege boundary violations all qualify.

Required content (whatever file you put it in — `report.md` / `description.md`):
1. Concrete location — `file:function:line`, endpoint, config key, or equivalent
2. Issue class named explicitly (memory-safety / auth / injection / info-disclosure / crypto / race / boundary-violation / logic / …)
3. Rationale a reviewer can act on — what is wrong, impact, caller control

### File FIND first, reproduce second

When your analysis already names a concrete defect at `file:function:line`
with a security rationale, **file `${RESULTS_DIR}/findings/FIND-NNN-<slug>/report.md`
immediately** (absolute — see PATH CONVENTION at top) — before, or in parallel with, the reproducer loop. Do not
wait for a sanitizer crash before opening the FIND. Source-only strategies
(S2 invariant-negation, S3 spec-vs-impl, S5 lifetime/state, S8
property-based) routinely identify real defects without ever achieving an
ASan crash; deferring the FIND until reproduction succeeds loses the
finding when the agent rotates, the iteration ends, or the testcase hits a
coverage/build wall.

The reproducer loop in your prompt still applies: continue attempting a
testcase that promotes to `crashes/CRASH-*/`. The two artifacts are
complementary:

- `findings/FIND-NNN-<slug>/` records the defect for upstream review
  regardless of reproduction outcome.
- `crashes/CRASH-NNN-<agent>/` records a sanitizer reproducer that
  strengthens the FIND (link the testcase into the FIND directory or open
  a CRASH whose report references the FIND id).

If the reproducer never lands, the FIND still ships. If the reproducer
does land, the FIND already exists and the CRASH becomes the evidence
attachment — no rewrite needed.

Optional but encouraged:
- **`patch.diff`** — a surgical patch saved as a file named exactly
  `patch.diff` in the FIND directory (alongside `report.md`), or in
  the CRASH directory for CRASH reports. The format must match the
  target's VCS so maintainers can apply it directly. See
  `.agents/references/vcs-commands.md` for the capture command; the
  short forms are:

  ```bash
  # git target:
  git -C "$TARGET_ROOT" diff -- path/to/file.cpp > "$FIND_DIR/patch.diff"
  # hg target (Firefox / mozilla-central):
  hg -R "$TARGET_ROOT" diff path/to/file.cpp > "$FIND_DIR/patch.diff"
  ```

  Keep the patch surgical — only the missing check or corrected line,
  no surrounding refactoring or whitespace churn. Save `patch.diff`
  whenever it applies cleanly under
  `git -C "$TARGET_ROOT" apply --check` — a non-mutating check that
  never touches the source. (`hg import --no-commit` is not a dry run;
  it applies to the working tree, so for Mercurial targets just save
  the `hg diff` and skip apply-validation rather than modify the
  source.) Build/repro confirmation is optional and improves quality
  but is not required:
  prefer an existing sanitizer build dir
  (`build-asan${AUDIT_BUILD_SUFFIX:-}/`, see `AGENTS.md`), fall back to
  any other `build-*/` dir, then the regular project build. If you
  apply the fix to build-test it, revert only the files you touched
  (`git -C "$TARGET_ROOT" checkout -- path/to/file.cpp` or `hg -R
  "$TARGET_ROOT" revert path/to/file.cpp` — never a whole-tree reset)
  immediately so later probes run against unmodified source. **Do not
  write a `## Patch` section in `report.md`** — `bin/enrich-report` is
  the single writer of that section and inserts the diff from the
  sibling file on render.
  Whatever validation you ran (applies, builds, confirms the
  diagnostic stops) can be noted in your narrative prose; there is no
  required label vocabulary.

  **Advisory bundles (no patch).** Some classes of fix can't be
  captured as a surgical diff — ABI-impacting renames, signature
  changes that break extern users, replacing a raw `char *` extractor
  with a capacity-aware API, etc. In that case **omit `patch.diff`**
  entirely and add a `## Fix Direction` section to `report.md`
  describing the maintainer-facing change. The bundle exporter
  detects the heading and marks the report with `Advisory: yes` so
  triage and downstream readers know the omission is intentional. Do
  **not** invent a non-surgical patch just to fill the file —
  reviewers prefer prose to a misleading diff.

Operational caps:
- Max 1 FIND per agent per iteration **when you also promoted a CRASH this iteration**. If no CRASH was promoted, up to 3 distinct FINDs are allowed — pure source-only audit sessions must be able to surface multiple defects before rotation. FINDs must be at distinct `file:function:line` locations with independent rationales; the dedup cluster gate will collapse duplicates.
- `report.html` is generated automatically — do not hand-write it
- A reproducer / testcase / ASan output is a bonus, not a requirement

## Differential Testing (JIT/Wasm)

For js/src/jit, js/src/wasm, js/src/irregexp:
```
bin/probe testcase.js   # with MODE: js-diff in the testcase header
```
Runs `--ion-eager` vs `--no-ion` and diffs output. A textual divergence = wrong JIT tier.
Convert to CRASH candidate by reducing until diff is minimal.
**Value-corruption bugs don't need ASan crashes — a diff IS the finding.**
