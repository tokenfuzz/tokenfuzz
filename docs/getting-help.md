# Getting Help

This page is the entry point for when something is not working or
you have a question the docs do not answer.

If any of the terms below (target, backend, sanitizer build,
`target.toml`, work card) are unfamiliar, the
[Glossary](reference/glossary.md) has one-line definitions —
read those first; most "I don't know what to file" questions are
really vocabulary gaps.

## Before filing anything

Run through this list first — it catches most issues in under a
minute.

1. **Did the test suite pass?** Run `bash tests/run-tests.sh`
   from the repository root. Test failures are almost always one
   of: a missing dependency (`clang`, `llvm`, `jq`, `ripgrep`,
   `python3`, `perl`), a stale checkout, or — rarely — a
   regression in the harness. The output names the failing test
   so you can tell which.
2. **Did `bin/audit … 1` complete startup?** A one-iteration
   smoke test is the cheapest way to confirm that prerequisites,
   `target.toml`, and the backend CLI are wired up.
3. **Have you checked
   [Troubleshooting](reference/troubleshooting.md)?** Common
   failure modes — missing tools, sanitizer build mismatches,
   backend authentication, stalled agents — are covered there.
4. **Have you read your logs?** `output/<target>/<backend>/logs/`
   contains the backend's stderr. Agent stalls and CLI
   authentication failures show up in `index.log` (per-iteration
   timeline) and `session_<TS>_*.log` (per-agent transcript)
   before they show up in any summary.

## Where to file what

| You want to… | Use |
| --- | --- |
| Report a bug in TokenFuzz itself | [GitHub Issues](https://github.com/tokenfuzz/tokenfuzz/issues) on this repository. |
| Suggest a feature or new investigation strategy | GitHub Issues, labelled `enhancement`. See [Contributing](contributing.md) before opening a PR. |
| Report a security vulnerability **in TokenFuzz** | [SECURITY.md](https://github.com/tokenfuzz/tokenfuzz/blob/main/SECURITY.md) — do **not** open a public issue. |
| Report a vulnerability **a TokenFuzz run found in another project** | The upstream project's normal security-disclosure process, not this repository. |
| Ask a usage question | GitHub Issues, labelled `question`. |
| Discuss research direction or share a finding | Open a discussion on the repository, or contact the maintainers privately if disclosure timing is sensitive. |

## What to include in a bug report

A good bug report turns into a fix the same day. Include all of
these:

1. **TokenFuzz revision** — `git rev-parse HEAD` (run from inside
   the repository).
2. **Host details** — OS name and version, Bash version, Python
   version, `clang --version`.
3. **The exact command you ran** — copy-paste, not paraphrased.
4. **The smoke-test output** —
   `bin/audit --target <target> --backend <backend> 1 2>&1 | head -80`.
5. **Your `target.toml`** — redact upstream URLs if private.
6. **What you expected** vs. **what you got**.
7. **Relevant log file** — `output/<target>/<backend>/logs/index.log`
   for the per-iteration timeline, plus the matching
   `session_<TS>_<role>-<n>-<mode>.log` for one agent's trimmed
   transcript. If the trimmed log is not enough, use the matching
   `.raw/session_<TS>_<role>-<n>-<mode>.log.raw` file and trim it to
   the failing section; do not paste 50 MB.

A minimal template:

```text
TokenFuzz: <git rev-parse HEAD output>
OS: <uname -a>
Bash: <bash --version | head -1>
Python: <python3 --version>
Clang: <clang --version | head -1>

Command:
  bin/audit --target <target> --backend <backend> 1

Expected: run completes, results/ contains state/ and work-cards.jsonl.
Got:      `FATAL: …`

Relevant log:
  <paste from output/<target>/<backend>/logs/index.log,
   plus the session_<TS>_*.log it points at>

target.toml:
  <paste, redact private URLs if needed>
```

## What not to include

- **Full backend transcripts.** They are huge, expensive to read,
  and almost never the cause of the bug. Start with the log
  instead.
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

A line in an issue ("found CVE-YYYY-NNNNN in <project> using
strategy S<n>") is enough. See [Contributing](contributing.md)
for the rest.
