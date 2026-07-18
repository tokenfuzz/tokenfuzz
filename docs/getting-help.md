# Getting Help

This page is the entry point for when something is not working or
you have a question the docs do not answer.

If any of the terms below (target, backend, sanitizer build,
`target.toml`, work card) are unfamiliar, the
[Glossary](reference/glossary.md) has one-line definitions —
read those first.

## Where to file what

| You want to… | Use |
| --- | --- |
| Report a bug in TokenFuzz itself | [GitHub Issues](https://github.com/tokenfuzz/tokenfuzz/issues) on this repository. |
| Ask a usage question | GitHub Issues, labelled `question`. |
| Suggest a feature or investigation strategy | GitHub Issues, labelled `enhancement`. See [Development](development.md) before opening a PR. |
| Report a security issue **in TokenFuzz** | [SECURITY.md](https://github.com/tokenfuzz/tokenfuzz/blob/main/SECURITY.md). Do **not** open a public issue. |
| Report a security issue **TokenFuzz found in another project** | The upstream project's normal security-disclosure process, not this repository. |
| Share accepted impact from a TokenFuzz run | Open an issue with the public details, or use the private path in [`SECURITY.md`](https://github.com/tokenfuzz/tokenfuzz/blob/main/SECURITY.md) if disclosure timing is sensitive. |

## Before filing a support issue

Run through this list first. It catches most setup and run problems
quickly.

1. **Did the test suite pass?** Run `bash tests/run-tests.sh`
   from the repository root. The output names the failing test.
2. **Did `bin/audit … 1` complete startup?** A one-iteration
   smoke test is the cheapest way to confirm that prerequisites,
   `target.toml`, and the backend CLI are wired up.
3. **Have you checked
   [Troubleshooting](reference/troubleshooting.md)?** Common
   failure modes — missing tools, sanitizer build mismatches,
   backend authentication, stalled agents — are covered there.
4. **Have you read your logs?** `output/<target>/<backend>/logs/`
   contains the run timeline and per-agent logs. Start with the
   `README.md` inside that directory, then `index.log`.

## What to include in a bug report

A good bug report gives a maintainer enough context to reproduce the
failure without guessing.

Set this once while collecting evidence:

```bash
export LOGS="output/<target>/<backend>/logs"
```

Include:

1. **TokenFuzz revision** — `git rev-parse HEAD` (run from inside
   the repository).
2. **Host details** — OS name and version, Python version, and
   `clang --version`.
3. **The exact command you ran** — copy-paste, not paraphrased.
4. **The smoke-test output** — save it without cutting off the audit process:

   ```bash
   bin/audit --target <target> --backend <backend> 1 2>&1 | tee audit-smoke.log
   sed -n '1,80p' audit-smoke.log
   ```
5. **Your `target.toml`** — redact upstream URLs if private.
6. **What you expected** vs. **what you got**.
7. **Relevant logs** — paste the useful part of `$LOGS/index.log`.
   If it points at one agent session, include the matching
   `$LOGS/session_<TS>_<launch>-<n>.log` — where `<launch>` is
   `cold-start` or `deep_investigation` and `<n>` is the agent
   number. Reach for the raw transcript under `$LOGS/.raw/` only as a
   last resort, and trim it to the failing section.

A minimal template:

```text
TokenFuzz: <git rev-parse HEAD output>
OS: <uname -a>
Python: <python3 --version>
Clang: <clang --version | head -1>

Command:
  bin/audit --target <target> --backend <backend> 1

Expected: run completes, results/ contains state/ and work-cards.jsonl.
Got:      `FATAL: …`

Relevant log:
  <paste from $LOGS/index.log,
   plus the session log it points at>

target.toml:
  <paste, redact private URLs if needed>
```

## What not to include

- **Full raw backend transcripts or prompt dumps.** They are huge,
  expensive to read, and almost never the first thing needed. Start
  with `index.log` and the session log it points at.
- **Target source code.** We do not need it; pointing at the
  upstream revision is enough.
- **API keys, tokens, or anything from `~/.config/<backend>/`.**
  The harness does not read them; the backend CLI does.

## Reaching maintainers privately

For coordinated disclosure of a vulnerability found by a
TokenFuzz run, or for a sensitive operational question, the
contact path is in
[SECURITY.md](https://github.com/tokenfuzz/tokenfuzz/blob/main/SECURITY.md).

Please do not use private channels for ordinary support
questions — they do not scale and the answer cannot help the
next person.

## Helping the project

If TokenFuzz gave you a confirmed sanitizer crash or a security
finding that an upstream maintainer accepted, that is the
highest-leverage thing you can do for the project: **tell us.**

Saying "Found using TokenFuzz" in the upstream advisory, issue, or
acknowledgement is enough.
