# Contributing

This page captures the rules contributors should preserve when
they change the harness or its documentation. It is short on
purpose — the project overview lives in
[the handbook home page](index.md).

PRs land at
[github.com/tokenfuzz/tokenfuzz/pulls](https://github.com/tokenfuzz/tokenfuzz/pulls).
Issues — including new-feature pitches — land at
[github.com/tokenfuzz/tokenfuzz/issues](https://github.com/tokenfuzz/tokenfuzz/issues).

## Before opening a change

1. **Run the full test suite:** `bash tests/run-tests.sh`.
2. **Update tests when behaviour changes** in `bin/`, `lib/`, or
   `.agents/`. New functions, renamed symbols, changed output —
   update test assertions. Do not leave stale tests passing by
   accident.
3. **Fix broken tests only with reason.** Determine whether the
   test or the code is wrong before changing assertions to make
   them green.

Tests live in `tests/`. Shared fixtures and assertions live in
`tests/helpers.sh`; it sets up the temp `RESULTS_DIR`/`LOGDIR`
layout that `bin/audit` and `lib/prompt.sh` consume, so renaming
or restructuring those env vars means updating `helpers.sh` in
the same change.

If you edit docs, note that the repository ships
`.markdownlint-cli2.jsonc`. There is no CI workflow that runs it
today, but the config is the canonical style for this codebase —
run `npx markdownlint-cli2 'docs/**/*.md'` locally if you want to
catch lint issues before review.

## Coding discipline

- **Prefer a focused LLM call over brittle regex extraction**
  when the LLM call is simpler, more complete, and robust enough
  without meaningful cost. The harness itself makes LLM calls
  during triage and ranking (see `lib/llm_decide.sh` and
  `lib/llm_decide.py`); reach for one of those before adding a brittle
  regex. Prefer structured parsers, schemas, and project APIs where
  they fit.
- **Avoid hardcoded constants** — especially caps and thresholds
  that limit bug exploration. Make exploration depth configurable,
  visible, and easy to run.
- **Keep the harness target-agnostic.** Target-specific means
  *belongs to one codebase under audit* — its types, headers,
  file paths, subsystem boundaries, internal macros. Those must
  not appear in `bin/` or `lib/`. Derive them at runtime from
  the live target tree, the work-card pool, or structured state.
  If a per-target value is truly unavoidable, isolate it in a
  target overlay (`targets/<name>/` or an opt-in config file),
  never in the shared harness.

  Industry-wide vocabulary is fair game:

  - build-manifest filenames (`Cargo.toml`, `Package.swift`,
    `CMakeLists.txt`);
  - standard or widely-adopted assert macros (`assert`,
    `static_assert`, `DCHECK`);
  - sanitizer names (`asan`, `ubsan`);
  - spec keywords (`RFC`, `WHATWG`).

  Prefer prefix or structural rules that catch the family
  (e.g. `[A-Z]+_(?:ASSERT|CHECK)`) over exhaustive enumerations
  that rot as new projects appear.

## Operating principles

Properties the project tries to preserve regardless of what gets
built next. Each has a docs implication (D) and an
implementation implication (I).

- **Evidence over commentary.**
  *D:* explain how to run and verify, not only how to reason.
  *I:* promote only artifacts that have a testcase and saved
  output.
- **Local-first operation.**
  *D:* document paths and files clearly.
  *I:* keep durable artifacts in the local results tree and call out
  any hosted-backend or reachability-check data flow explicitly.
- **Backend independence.**
  *D:* describe model backends as interchangeable runners.
  *I:* keep strategy, probing, state, and triage outside
  provider-specific code.
- **Sanitizer breadth.**
  *D:* document the evidence contract, not a single sanitizer.
  *I:* support per-target sanitizer configurations behind the
  same probe and triage path.
- **Small, deep investigations.**
  *D:* teach users to finish one hypothesis before pivoting.
  *I:* preserve compact state and rotate strategies only after
  useful effort.
- **Context economy.**
  *D:* explain how to inspect state without dumping logs.
  *I:* cap search output, seed resumed sessions, keep prompts
  focused (see [Cost model](concepts/cost-model.md)).
- **Stable target boundaries.**
  *D:* keep `targets/` and `output/` responsibilities obvious.
  *I:* do not write audit state into upstream source.
- **Maintainer-quality handoff.**
  *D:* show report fields, bundle layout, reproduction commands.
  *I:* export clean bundles with `REPORT.md`, `reproduce.sh`,
  input, and output.

## Product invariants

These should continue to hold:

- A target can be added without changing harness source.
- A run can be resumed from state without reading raw logs.
- Every testcase goes through `bin/probe` before promotion.
- Accepted crashes and findings reproduce from files on disk.
- `findings/` records every concrete security issue, even when
  no sanitizer reproducer exists.
- `crashes/` stays focused on reproducible crashes that can be
  confirmed, clustered, exported, and prioritised.
- Rejected results are indexed with reasons.
- Hosted and local model backends use the same audit contract.
- Token-control features preserve bug-finding capability — trim
  duplicated context, not investigation depth.

## Non-goals

- A hosted fuzzing service.
- An automatic public-disclosure pipeline.
- A replacement for conventional fuzzing, code review, or
  maintainer judgment.
- A place where unverified model claims become findings.
- A tool for testing software you have no authorisation to test.

## Documentation discipline

Each page has one job:

- overviews orient;
- guides walk through actions;
- concept pages explain design;
- reference pages define exact commands and fields.

If a topic shows up in more than one place, the canonical page
should be linked, not restated.

Page-level rules:

- lead with the user's task, not the implementation history;
- show the shortest safe command path before any advanced
  variants;
- name the files and directories the user should inspect next;
- include expected output shape when it helps recognise success;
- keep examples copy-pasteable from the repository root;
- update command references in the same change as CLI behaviour;
- prefer short sentences and bullet lists over dense paragraphs.

Good documentation should make a failed run diagnosable without
reading raw logs first, and a successful run easy to hand to a
maintainer.

### Previewing the handbook

The site is built with
[MkDocs Material](https://squidfunk.github.io/mkdocs-material/).
`mkdocs.yml` lives at the repository root and `docs/` is the
source tree.

```bash
bin/docs serve           # install deps, then preview at http://127.0.0.1:4000/
bin/docs build           # one-shot strict build matching CI; output in site/
```

`--strict` is what the Pages workflow runs, so any broken
internal link, missing nav entry, or unrecognised reference will
fail the build. Fix those before opening a docs PR.
