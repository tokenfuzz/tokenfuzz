# Prerequisites

Before an audit, prepare the host, one model backend, and the target's own
build dependencies. TokenFuzz supports macOS and Linux.

Hosted backends receive the prompts, source excerpts, state, and reports needed
for the run. Use `--backend oss` with a local model server when policy requires
source and audit context to stay on the machine.

## 1. Host tools

TokenFuzz itself needs:

| Tool | Purpose |
| --- | --- |
| Python 3.10+ | Orchestration, state, runners, triage, and report generation. `venv` support is also needed by `bin/docs` and some target bootstraps. |
| Git | Source setup and revision tracking for Git targets. Install Mercurial as well for an hg target. |
| ripgrep (`rg`) | Bounded source search. |
| `file` | Testcase and executable classification. |
| LLVM (`clang`, `clang++`, `llvm-symbolizer`) | Building and diagnosing native sanitizer targets. |
| `sancov` | Coverage-gated browser and JavaScript probes, when supported. |
| [`trailmark`](https://github.com/trailofbits/trailmark) (experimental, optional) | Adds a static call map to each work-card prompt. `pip install trailmark` into any Python 3.12+ on `PATH`. See [below](#experimental-call-neighbourhood-context). |

`bash` is needed by the repository test runner and its two shell-behavior suites.
Your target may also need CMake, Meson, an archiver, a language runtime, or
other upstream build dependencies. Optional strategy-specific tools are named
where they are used; they are not TokenFuzz or test-suite prerequisites.

### macOS

```bash
xcode-select --install
brew install llvm ripgrep
```

Apple's command-line tools provide Git, `file`, `nm`, `otool`, and compiler
support. If `python3 -m venv` does not create a working environment, install
Homebrew Python as well:

```bash
brew install python
```

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
  bash binutils clang file git libclang-rt-dev llvm \
  python3 python3-venv ripgrep
```

The distro `llvm` package may omit `sancov`. Coverage-gated probes can still be
unavailable even when ASan works; use a complete LLVM installation from
[apt.llvm.org](https://apt.llvm.org/) when that capability matters.

### Fedora / RHEL

```bash
sudo dnf install -y \
  bash binutils clang compiler-rt file git llvm \
  python3 python3-pip ripgrep
```

Minimal containers may also need CA certificates and standard process/text
utilities. The test driver can install its known container dependencies with
`bash tests/run-tests.sh --install-container-deps`.

## 2. One agent backend

Install and authenticate at least one supported CLI:

| Backend | CLI | Notes |
| --- | --- | --- |
| Claude | `claude` | Install and authenticate Claude Code. |
| Codex | `codex` | Install and authenticate Codex CLI. |
| Gemini | `agy` by default | Install Antigravity CLI and authenticate. Google Gemini CLI is available with `USE_GEMINI_CLI=1`. |
| Grok | `grok` | Install Grok Build and configure its credentials. |
| OpenCode / local model | `opencode` | Pass an OpenCode catalog id as `--backend oss --model opencode/<id>`, or serve an OpenAI-compatible model through vLLM, Ollama, or another compatible server and pass its exact served id. |

Verify the chosen CLI directly before asking TokenFuzz to launch it. Exact
installation links, authentication checks, model selection, local vLLM/Ollama
setup, and ensemble behavior live in
[Backends and ensembling](../guides/backends.md).

### Cyber access for security research

For authorised defensive research through a hosted model, register the
organisation and use case through the provider's applicable trusted-access
program before a long run. OpenAI offers
[Trusted Access for Cyber](https://openai.com/index/trusted-access-for-cyber/),
and Anthropic offers a
[Cyber Verification Program](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude).

Provider registration does not replace target authorisation or the provider's
usage policy. Use a local backend when hosted-model data flow is not acceptable.

## 3. Target-specific tools

Follow the target project's build instructions. TokenFuzz drives the build; it
does not replace the target's toolchain.

- C/C++ targets commonly need CMake, Meson, autotools, Ninja, or project
  libraries in addition to LLVM.
- Rust, Go, Python, Java, and other ecosystems need their normal compiler,
  interpreter, package manager, and development headers.
- Browser targets can require Mercurial, large SDKs, and project-specific
  bootstrap tooling.

The goal is a source tree that can be built and run normally before sanitizer
instrumentation is introduced.

## 4. Verify the harness

From the repository root:

```bash
bash tests/run-tests.sh
```

The suite uses stubbed backend invocations; it does not spend model tokens or
require backend authentication. It exercises config parsing, state, triage,
runner dispatch, reporting, and shell/Python portability.

Optional Linux image checks run the same suite in a clean Docker container:

```bash
bash tests/run-tests.sh --image ubuntu:24.04
bash tests/run-tests.sh --image fedora:latest
```

## 5. Verify the audit pipeline end-to-end

After adding a target, run one bounded iteration:

```bash
bin/audit --target <target> --backend <backend> 1
```

A healthy run creates:

```text
output/<target>/<backend>/logs/index.log
output/<target>/<backend>/results/state/
output/<target>/<backend>/results/work-cards.jsonl
output/<target>/<backend>/results/scratch-1/
```

`crashes/` and `findings/` may be empty after a smoke test. The point is to
verify config, build preflight, backend launch, state, and result paths. Continue
with [First audit](first-audit.md) to inspect the run.

## Container runtime (recommended)

Target build scripts and agent-driven testcases execute code from the audited
tree. Run audits in a disposable container or on an isolated machine without
long-lived credentials.

TokenFuzz's helper currently supports Docker:

```bash
bin/audit-container-shell --rebuild   # first use
bin/audit-container-shell             # reuse the image
```

Install Docker through the normal package for your host and verify `docker
info` first. The helper builds the backend CLI image, mounts this repository at
`/root/work`, and opens a shell; it never starts an audit automatically.

### Optional gVisor runtime

On a Linux Docker host with `runsc` registered, add another sandbox boundary:

```bash
docker run --runtime=runsc --rm hello-world
bin/audit-container-shell --gvisor
```

`--gvisor` is shorthand for `--docker-runtime runsc`. Do not run the audit
container as privileged or mount the Docker socket into it.

## macOS notes

- GNU coreutils are not required; production commands use portable Python
  filesystem and process APIs.
- System Bash is sufficient for the test driver and generated recipes.
- Homebrew LLVM is auto-detected at `/opt/homebrew/opt/llvm` and
  `/usr/local/opt/llvm`. Set `LLVM_PREFIX` only to select another installation.

## Experimental: call-neighbourhood context

This is optional. Skip it on a first install; the audit is unchanged without
it.

With [trailmark](https://github.com/trailofbits/trailmark) installed, every
work-card prompt gains a static call map for the card's file: which files call
into it, which files it calls, and the shortest call path from the binary named
in `target.toml`. trailmark is a tree-sitter code-graph library from
[Trail of Bits](https://www.trailofbits.com/), Apache-2.0 licensed, and
TokenFuzz treats it as an optional dependency you install yourself.

```bash
pip install trailmark
```

That is the whole setup. TokenFuzz is stdlib-only and does not run in a
virtualenv, so install trailmark wherever your `python3` already is. If that
Python is externally managed — Homebrew, or a distro `python3` — `pip` answers
`error: externally-managed-environment`; add `--break-system-packages`. A
virtualenv works too, but then TokenFuzz has to be run from it.

`bin/rank-work` asks the interpreter running the harness, then `python3.15`
down to `python3.12` and plain `python3` on `PATH`, whether each can run the
analysis (`bin/callgraph --probe`), and uses the first that answers. Every run
records the outcome in `logs/index.log`, so a run without the context says so
rather than looking like one that found nothing:

```text
Source call-graph context: enabled via python3.14 (trailmark=0.5.0 tree-sitter=0.25.2)
WARN: source call-graph context unavailable — trailmark is not importable ...
```

Verify in three steps:

```bash
python3 bin/callgraph --probe                       # installed and usable?
bin/rank-work --target <target>                     # appends "(call neighbourhood: built)"
python3 lib/callgraph.py --target <target> <file>   # print one file's block
```

`bin/audit --strategy S<N>` passes that pin through to ranking, so the bounded
window and optional model rerank contain only cards that lane can claim.

The middle line reports only states worth acting on, so a later run that
rebuilt nothing stays quiet — an unchanged graph is `fresh`, and an absent
trailmark is the default rather than a fault. The last line prints the exact
text a work card carries for that file, and on failure names the check that
stopped it: not installed, artifact not built yet, file absent from the parsed
graph, or nothing resolved to report.

### What the map will not tell you

The map is context an agent may act on, never a verdict the harness acts on.
Two limits are stated in the block itself, because both would otherwise read as
findings:

- **Indirect dispatch is invisible** — callback tables, function pointers,
  macro-generated names. A missing path is reported as a missing path, and
  nothing ranks, filters, discards, or downgrades on it.
- **Export-macro declarations are not extracted**, and those are often a C
  library's public entry points. `bin/callgraph` measures itself against the
  symbol table of the build in `target.toml`; below 75% coverage it withholds
  the entry boundary and its paths, keeping only the caller and callee lists a
  partial parse can still state truthfully.

Only syntactically resolved calls are counted, so the block is densest on
native targets and thins out where dispatch goes through a receiver the parser
cannot type — most calls in a method-dispatch language. A card whose file has
no resolved caller, callee, or route gets no block at all rather than an empty
one.

### Cost and caching

The artifact is `<results>/state/callgraph.json`, rebuilt only when something
the graph depends on changes: source content, the configured sanitizer route,
the built artifact, or the parser version. Only the files `bin/rank-work`
considers auditable are parsed, and any repo-local `.trailmark/` configuration
in the target is ignored — the audited tree does not get to declare its own
call edges.

Parsing five measured native targets took 0.1–12s each. Trees over 5,000
auditable files — browser checkouts — are declined outright, because staging
and parsing one costs minutes and has never produced a block. A refusal or a
parse failure is recorded against the same fingerprint so it is not retried
every iteration; delete `<results>/state/callgraph.json` to force one.

## If preflight fails

`bin/audit` names missing tools and invalid configuration before launching an
agent. Install the named dependency, verify the target can build outside the
harness, then rerun the one-iteration command. See
[Troubleshooting](../reference/troubleshooting.md) for sanitizer, runner, and
backend failures.
