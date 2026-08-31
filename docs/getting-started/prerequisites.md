# Prerequisites

Before an audit, prepare the host, one model backend, and the target's own
build dependencies. TokenFuzz supports macOS and Linux. If you only want to
prove the orchestration works, start with the pure-Python sample; it avoids a
native target build while you verify the backend and result paths.

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
| `sancov` (optional) | Coverage feedback for native probes and the coverage gate for browser/JS probes. Everything runs without it. |
| [`trailmark`](https://github.com/trailofbits/trailmark) (experimental, optional) | Adds a static call map to each work-card prompt. Needs Python 3.12+. See [below](#experimental-call-neighbourhood-context). |

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

The package lists above cover the core harness and sanitizer tooling. To run the
full test suite without skipping its Node.js and Go runner checks, install
`node` and `go` as well. The container dependency installer does this for you;
read the suite's `SKIP` lines when those toolchains are absent.

## 2. One agent backend

Install and authenticate at least one supported CLI:

| Backend | CLI | Notes |
| --- | --- | --- |
| Claude | `claude` | Install and authenticate Claude Code. |
| Codex | `codex` | Install and authenticate Codex CLI. |
| Gemini | `agy` by default | Install Antigravity CLI and authenticate. Google Gemini CLI is available with `USE_GEMINI_CLI=1`. |
| Grok | `grok` | Install Grok Build and configure its credentials. |
| OpenCode | `opencode` | Use an OpenCode catalog id (`opencode/<id>`) or the exact id served by a local OpenAI-compatible endpoint. Both routes use `--backend oss`. |

The `oss` backend has no default model; every audit command that selects it
needs `--model`.

Verify the chosen CLI directly before asking TokenFuzz to launch it. Exact
installation links, authentication checks, model selection, local vLLM/Ollama
setup, and ensemble behavior live in
[Backends and isolation](../guides/backends.md).

Codex sandboxing on Linux and WSL2 needs the distribution's `bubblewrap`
package; see the
[Codex sandboxing prerequisites](https://learn.chatgpt.com/docs/sandboxing?sandbox-os=ubuntu-debian#prerequisites)
for the Ubuntu AppArmor notes.

### Cyber access for security research

For authorised defensive research through a hosted model, register the
organisation and use case through the provider's applicable trusted-access
program before a long run. OpenAI documents Daybreak and Trusted Access for
Cyber under
[Models and Trusted Access](https://learn.chatgpt.com/docs/cyber-safety), and
Anthropic offers a
[Cyber Verification Program](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude-opus-and-sonnet).

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

Optional Linux image checks run the same suite in a clean Docker container;
`ubuntu:24.04` is the image the CI container job runs:

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

## If preflight fails

`bin/audit` names an uninstalled backend and invalid configuration before
launching an agent. Install the named dependency, verify the target can build outside the
harness, then rerun the one-iteration command. See
[Troubleshooting](../reference/troubleshooting.md) for sanitizer, runner, and
backend failures.

## Experimental: call-neighbourhood context

This dependency is optional; skip it for a first install. With
[trailmark](https://github.com/trailofbits/trailmark) available to Python
3.12+, work cards can include a static caller/callee neighbourhood and a small
source pack for resolved functions:

```bash
python3 -m pip install trailmark   # any Python 3.12+; bin/callgraph finds it
python3 bin/callgraph --probe
```

The generated `<results>/state/callgraph.json` is context for an agent, never
reachability proof or a filter. Indirect calls, callback tables, macro-generated
names, and some exported declarations are invisible to the parser. If exported
symbol coverage is below 75%, TokenFuzz withholds the inferred entry boundary
rather than presenting a partial graph as complete. Trees above 5,000 auditable
files are skipped.

`bin/rank-work` caches both successful graphs and failures against their source,
build, and parser fingerprint. The run log says whether call-neighbourhood
context was enabled or unavailable. To inspect the exact block for one file:

```bash
python3 lib/callgraph.py --target <target> <target-relative-file>
```

Delete `<results>/state/callgraph.json` only when you deliberately want to
force a rebuild. Any `.trailmark/` configuration inside the audited target is
ignored because the target is untrusted input.
