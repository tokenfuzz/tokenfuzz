# Contributing

This page captures the rules contributors should preserve when they
change TokenFuzz. It is short on purpose: the project overview lives
on [the handbook home page](index.md), and exact command syntax lives
in the [reference](reference/index.md).

PRs land at
[github.com/tokenfuzz/tokenfuzz/pulls](https://github.com/tokenfuzz/tokenfuzz/pulls).
Issues — including new-feature pitches — land at
[github.com/tokenfuzz/tokenfuzz/issues](https://github.com/tokenfuzz/tokenfuzz/issues).

## Before opening a change

1. **Run the full test suite:** `bash tests/run-tests.sh`.
2. **Update tests when behaviour changes** in `bin/`, [`lib/`](https://github.com/tokenfuzz/tokenfuzz/tree/main/lib), or
   [`.agents/`](https://github.com/tokenfuzz/tokenfuzz/tree/main/.agents). New functions, renamed symbols, changed output, new
   prompt fields, and new artifact shapes need matching assertions.
3. **Fix broken tests only with reason.** Determine whether the
   test or the code is wrong before changing assertions to make
   them green.
4. **Build the handbook when docs change:** `bin/docs build`.

Tests live in [`tests/`](https://github.com/tokenfuzz/tokenfuzz/tree/main/tests). Shared fixtures and assertions live in
[`tests/helpers.sh`](https://github.com/tokenfuzz/tokenfuzz/blob/main/tests/helpers.sh). Keep fixtures neutral: do not copy private stack
frames, sanitizer reports, signatures, or unreleased target details
into tests or docs.

## Product invariants

These should continue to hold:

- A target can be added without changing harness source.
- A run can be resumed from state without reading raw logs.
- Harness-authored testcases go through `bin/probe`, which chooses the
  runner or sanitizer, records structured run state, and writes output
  beside the testcase.
- Accepted crashes have a testcase or input, saved diagnostic output,
  and a maintainer-facing bundle on disk.
- `findings/` records every concrete security issue, even when
  no sanitizer reproducer or runnable testcase exists. A substantive
  report is the requirement.
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

## Coding discipline

- **Use structured sources first.** Prefer parsers, schemas, project
  APIs, or focused LLM decisions over brittle text scraping. Avoid
  regexes for data that already has a reliable structure.
- **Keep shared code target-agnostic.** Target-specific means
  *belongs to one codebase under audit* — types, headers, paths,
  subsystem boundaries, or internal macros. Those do not belong in
  shared `bin/`, [`lib/`](https://github.com/tokenfuzz/tokenfuzz/tree/main/lib), or [`.agents/`](https://github.com/tokenfuzz/tokenfuzz/tree/main/.agents) code. Derive them from the
  target tree, `target.toml`, work cards, or structured state. If a
  per-target value is unavoidable, put it in a target overlay or
  opt-in config.
- **Use broad, stable rules.** Industry-wide names are fine:
  `Cargo.toml`, `Package.swift`, `CMakeLists.txt`, `assert`,
  `static_assert`, `DCHECK`, sanitizer names, and common spec terms.
  Prefer structural patterns such as `[A-Z]+_(?:ASSERT|CHECK)` over
  exhaustive lists that rot as new projects appear.
- **Keep prompts and agent guidance centralized.** Prompt bodies live
  in `lib/prompts/*.md.j2` and are rendered through the shared prompt
  helpers. Do not inline prompts in `bin/`, [`lib/`](https://github.com/tokenfuzz/tokenfuzz/tree/main/lib), or [`.agents/`](https://github.com/tokenfuzz/tokenfuzz/tree/main/.agents).
  When editing agent guidance, keep the [`AGENTS.md`](https://github.com/tokenfuzz/tokenfuzz/blob/main/AGENTS.md) / [`CLAUDE.md`](https://github.com/tokenfuzz/tokenfuzz/blob/main/CLAUDE.md)
  mirror and the related tests in sync.
- **Avoid hidden knobs.** Do not add hardcoded exploration caps or
  defensive environment-variable toggles. Make real operator choices
  visible, documented, and test-covered.
- **Use shared helpers.** Shell code should use the existing platform
  and timeout helpers. Shared JSONL state should use
  [`lib/workqueue.py`](https://github.com/tokenfuzz/tokenfuzz/blob/main/lib/workqueue.py); parallel logs should be per-agent or uniquely
  named.

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
[`mkdocs.yml`](https://github.com/tokenfuzz/tokenfuzz/blob/main/mkdocs.yml) lives at the repository root and [`docs/`](https://github.com/tokenfuzz/tokenfuzz/tree/main/docs) is the
source tree.

```bash
bin/docs serve           # install deps, then preview at http://127.0.0.1:4000/
bin/docs build           # one-shot strict build matching CI; output in site/
```

`--strict` is what the Pages workflow runs, so any broken
internal link, missing nav entry, or unrecognised reference will
fail the build. Fix those before opening a docs PR.
