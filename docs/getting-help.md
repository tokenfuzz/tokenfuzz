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
| Report a bug in TokenFuzz itself | Search [GitHub Issues](https://github.com/tokenfuzz/tokenfuzz/issues), then open one. A focused pull request with a tested fix is welcome too. |
| Ask a usage question | Check [Troubleshooting](reference/troubleshooting.md) and existing issues first, then open an issue labelled `question`. |
| Suggest a feature or investigation strategy | Open an issue labelled `enhancement`. Read [Development](development.md) before opening a PR. |
| Report a security issue **in TokenFuzz** | [SECURITY.md](https://github.com/tokenfuzz/tokenfuzz/blob/main/SECURITY.md). Do **not** open a public issue. |
| Report a security issue **TokenFuzz found in another project** | The upstream project's normal security-disclosure process, not this repository. |
| Share accepted impact from a TokenFuzz run | Follow the upstream disclosure process first. Once details are public, attribution in the upstream advisory, issue, or acknowledgement is enough. |

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
2. **Host details** — OS name and version and Python version. For a native
   sanitizer target, include `clang --version` as well.
3. **The exact command you ran** — copy-paste, not paraphrased.
4. **The smoke-test output** — save it without cutting off the audit process:

   ```bash
   bin/audit --target <target> --backend <backend> 1 2>&1 | tee audit-smoke.log
   sed -n '1,80p' audit-smoke.log
   ```
5. **The target config** — include `output/<target>/target.toml`. Redact private
   upstream URLs, local source paths, runner environment values, and sensitive
   threat-model details.
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
Clang (native targets only): <first line of clang --version>

Command:
  bin/audit --target <target> --backend <backend> 1

Expected: run completes, results/ contains state/ and work-cards.jsonl.
Got:      `FATAL: …`

Relevant log:
  <paste from $LOGS/index.log,
   plus the session log it points at>

target.toml:
  <paste output/<target>/target.toml; redact private paths and values>
```

## What not to include

- **Full raw backend transcripts or prompt dumps.** They are huge,
  expensive to read, and almost never the first thing needed. Start
  with `index.log` and the session log it points at.
- **Target source code.** We do not need it; pointing at the
  upstream revision is enough.
- **API keys, tokens, or anything from a backend CLI's config directory**
  (`~/.claude`, `~/.codex`, `~/.gemini`, …). A support report never needs
  them.

## Reaching maintainers privately

Use the private path in
[SECURITY.md](https://github.com/tokenfuzz/tokenfuzz/blob/main/SECURITY.md)
only for a vulnerability in TokenFuzz itself. A vulnerability found in an
audited target belongs with that target's security team or documented
disclosure contact.

There is no private support channel. For a question that involves private
target details, reduce it to a sanitized reproducer before filing publicly.

## Helping the project

If TokenFuzz gave you a confirmed sanitizer crash or a security
finding that an upstream maintainer accepted, that is the
highest-leverage thing you can do for the project: **tell us.**

Saying "Found using TokenFuzz" in the upstream advisory, issue, or
acknowledgement is enough.
