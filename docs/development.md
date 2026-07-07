# Development

This page is for people and development agents changing TokenFuzz itself.
Runtime audit agents use `AGENTS.md` plus the harness-rendered prompt; keep
root auto-loaded instruction files safe for spawned audit runs.

PRs land at
[github.com/tokenfuzz/tokenfuzz/pulls](https://github.com/tokenfuzz/tokenfuzz/pulls);
issues and feature pitches at
[github.com/tokenfuzz/tokenfuzz/issues](https://github.com/tokenfuzz/tokenfuzz/issues).

## Development agents

Start your coding agent (`claude`, `codex`, `gemini`) from the repository
root, then send:

```text
Read docs/development.md first, then help me with: <task>
```

## Working discipline

An LLM agent's characteristic failures are *fluent*: wrong output that reads
correctly, passes a skim, and often passes tests. These rules exist to catch
them, in the order a change actually happens.

### Before writing a line

- **Verify every reference exists in this tree.** Never name a helper, flag,
  path, function, or env var from plausibility — `rg` it or open the file. If
  you have not read it this session, you do not know it. An invented
  identifier is worse than "let me check" because it looks authoritative.
- **Question the premise.** A bug report's stated cause or a requested fix can
  be wrong. Reproduce the failure and confirm the mechanism first; if the
  framing is off, say so and stop — do not implement a fix for a non-bug, and
  do not agree because agreeing is smoother. When a requirement is unclear,
  ask rather than guess, and state the assumptions you do make.
- **Your first hypothesis is a lead, not a diagnosis.** Pattern-matching a
  symptom to a familiar bug class tells you where to look, not where to stop.
  Trace the actual control and data flow to the specific cause in *this* code
  before changing a line; a fix aimed at the wrong cause buries the real one.

### While changing

- **Smallest change that fully solves it.** No speculative feature, flag,
  abstraction, or compatibility shim the task did not ask for; replace code
  rather than leaving old and new paths side by side. If 200 lines can be 50,
  write the 50. The characteristic model error is over-production — a change
  that keeps growing is the signal to stop and find the smaller shape. Prefer
  deleting to adding.
- **Reuse before writing.** Find the existing helper (`lib/workqueue.py`,
  platform/timeout helpers, prompt renderers) before adding logic; if you
  write the same shape twice, factor it.
- **Handle real failure modes, not imaginary ones.** This harness runs many
  agents in parallel against flaky backends over long sessions: handle
  concurrent writers, partial or corrupt state, timeouts, and unhealthy
  backends atomically, and fall open rather than crash a live audit. Do not
  guard states that cannot happen — and falling open is not a license to hide
  failures: no `|| true`, no bare `except:`, no silent fallback that masks an
  unhealthy backend. Where a human must see a failure, fail loud and legibly.
- **Finish the change everywhere it reaches.** Sweep a rename, signature
  change, new prompt field, or new artifact shape through every caller, test,
  `lib/prompts/*.md.j2` template, and doc in the same change. Half-applied
  edits read fine and typecheck — they break in the one caller you did not
  open.
- **Touch only what you must.** Match existing style, clean up the orphans
  *your* change created, and leave unrelated code and working-tree changes
  alone.
- **When stuck, revert — do not stack fixes.** Piling guards, `try`s, and
  fallbacks on a change you do not understand buries the cause. Return to the
  last state you understood and re-derive; two clean attempts beat one
  four-layered patch.

### Before claiming done

Report what you ran, not what should be true — an honest "untested" is worth
more than a confident "done" that never ran. Done means every check below was
executed, not assumed:

- `bash tests/run-tests.sh` (or the specific probe) ran and you saw it pass.
- The fix has a test that failed before the change and passes after.
- `rg` for every renamed or removed symbol finds no orphaned reference.
- The diff contains the task and its orphans — nothing unrelated.
- The non-obvious *why* — options rejected, the failure mode a guard defends
  against — is in the commit message and a short comment where it matters.
  Never narrate the edit itself; prefer deleting a wart to documenting it.

## Testing discipline

1. **Run the full suite:** `bash tests/run-tests.sh`.
2. **Update tests when behaviour changes** in `bin/`, `lib/`, or `.agents/`:
   new functions, renamed symbols, changed output, new prompt fields, and new
   artifact shapes all need matching assertions.
3. **Assert behaviour, not implementation.** A test that mirrors the code's
   internals or mocks away everything real cannot fail when the code is wrong
   — worse than no test.
4. **Change assertions only once you know** whether the test or the code is
   wrong.
5. **Keep fixtures neutral — never disclose a target bug.** A fixture must
   not pin a real defect to a real symbol.
    - **Allowed:** a target's name or slug (`curl`, `pcre2`) and its
      `targets/<slug>/` path.
    - **Not allowed:** target function/symbol names, stack frames or crash
      `file:func:line` signatures, sanitizer reports, real source filenames
      tied to a finding, or any unreleased bug detail.

    Use neutral placeholders (`child_free child.c:91`, `app_parse`,
    `sampleproj`), kept consistent within a file so fixtures and assertions
    still match. The same rule applies to docs.

Tests live in
[`tests/`](https://github.com/tokenfuzz/tokenfuzz/tree/main/tests); shared
fixtures and assertions in
[`tests/helpers.sh`](https://github.com/tokenfuzz/tokenfuzz/blob/main/tests/helpers.sh).

## Coding discipline

- **Use structured sources first.** Prefer parsers, schemas, project APIs, or
  focused LLM decisions over brittle text scraping; avoid regexes for data
  that already has reliable structure.
- **Keep shared code target-agnostic.** Target-specific means *belongs to one
  codebase under audit*: types, headers, paths, subsystem boundaries, internal
  macros. None of it belongs in shared `bin/`, `lib/`, or `.agents/` code —
  derive it from the target tree, `target.toml`, work cards, or structured
  state. If a per-target value is unavoidable, put it in a target overlay or
  opt-in config.
- **Use broad, stable rules.** Industry-wide vocabulary is fair game
  (`Cargo.toml`, `CMakeLists.txt`, `assert`, `DCHECK`, sanitizer names).
  Prefer structural patterns such as `[A-Z]+_(?:ASSERT|CHECK)` over exhaustive
  lists that rot; where a small named list is unavoidable, document its
  inclusion criterion above it.
- **Keep prompts centralized.** Prompt bodies live in `lib/prompts/*.md.j2`
  and render through the shared prompt helpers — never inline them in `bin/`,
  `lib/`, or `.agents/`. Keep `AGENTS.md` runtime-safe for spawned audit
  agents; harness development guidance belongs here.
- **Avoid hidden knobs.** No hardcoded exploration caps or defensive env-var
  toggles. Make real operator choices visible, documented, and test-covered;
  add an env var only when an operator genuinely varies it across routine
  runs.
- **Use shared helpers.** Shell code uses the existing platform and timeout
  helpers; shared JSONL state goes through `lib/workqueue.py`; parallel logs
  are per-agent or uniquely named.
- **Avoid early-exit pipe failures.** Under `set -euo pipefail`, do not pipe
  long-running producers into `grep -q` — it exits early and can turn a
  successful match into a producer `SIGPIPE`. Use `grep -c` or another
  full-consuming check.

## Logging discipline

Files under `output/<target>/<backend>/logs/` without `${agent_num}` in the
path are shared across parallel agents and the orchestrator; concurrent writes
can corrupt or lose lines.

1. **Prefer per-agent paths**, keyed by `${agent_num}` or a unique session
   timestamp.
2. **Keep forensic dumps under `logs/.raw/`** (`session_*.log.raw`,
   `recon_*.raw`) so agent file scans do not pull them in.

For genuinely shared mutable state, use `lib/workqueue.py` helpers
(`jsonl_lock`, `append_jsonl`, `write_jsonl`); they serialize via
`fcntl.flock`.

## Documentation discipline

Handbook pages live under `docs/`. Each page has one job — overviews orient,
guides walk through actions, concept pages explain design, reference pages
define exact commands and fields. If a topic appears in more than one place,
link to the canonical page instead of restating it.

Page-level rules:

- lead with the user's task, not implementation history;
- show the shortest safe command path before advanced variants;
- name the files to inspect next, and the expected output shape when it helps
  recognise success;
- keep examples copy-pasteable from the repository root;
- update command references in the same change as CLI behaviour;
- prefer short sentences and bullets over dense paragraphs.

Good documentation makes a failed run diagnosable without reading raw logs and
a successful run easy to hand to a maintainer.

### Previewing the handbook

The site is built with
[MkDocs Material](https://squidfunk.github.io/mkdocs-material/); `mkdocs.yml`
lives at the repository root and `docs/` is the source tree.

```bash
bin/docs build           # one-shot strict build matching CI; output in site/
bin/docs serve           # install deps, then preview at http://127.0.0.1:4000/
```

`--strict` is what the Pages workflow runs, so any broken internal link,
missing nav entry, or unrecognised reference fails the build. Fix those before
opening a docs PR.

## Product invariants

These should continue to hold:

- A target can be added without changing harness source.
- A run can be resumed from state without reading raw logs.
- Harness-authored testcases go through `bin/probe`, which chooses the runner
  or sanitizer, records structured run state, and writes output beside the
  testcase.
- Accepted crashes have a testcase or input, saved diagnostic output, and a
  maintainer-facing bundle on disk.
- `findings/` records every concrete security issue, even without a sanitizer
  reproducer or runnable testcase; a substantive report is the requirement.
- `crashes/` stays focused on reproducible crashes that can be confirmed,
  clustered, exported, and prioritised.
- Rejected results are indexed with reasons.
- Hosted and local model backends use the same audit contract.
- Token-control features preserve bug-finding capability: trim duplicated
  context, not investigation depth.

## Non-goals

- A hosted fuzzing service.
- An automatic public-disclosure pipeline.
- A replacement for conventional fuzzing, code review, or maintainer judgment.
- A place where unverified model claims become findings.
- A tool for testing software you have no authorisation to test.
