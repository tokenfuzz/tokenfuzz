# Prerequisites

Before you run an audit, install three things:

- a handful of host tools;
- an LLVM toolchain for sanitizer builds;
- one authenticated agent backend.

The harness itself is mostly shell and Python, and it writes state, logs,
and reports to the local results directory. Hosted backends receive the
prompts, source excerpts, state, and reports needed for the run, and
optional reachability checks may query public code search. Use
`--backend oss` when policy requires model data flow to stay local.

This page walks through each piece in order. Install commands are given
for macOS, Debian / Ubuntu, and Fedora / RHEL. The last two sections
verify the install before you point the harness at a real target.

## 1. Host tools

These are the everyday tools the harness invokes during normal operation
and during sanitizer builds.

| Tool | Why it is needed |
| --- | --- |
| `bash` 3.2+ | Runs the orchestrator and shell wrappers. macOS system Bash is fine. |
| `python3` 3.9+ | Parses target config and structured state. No extra packages. |
| `perl` | Runs vocabulary normalization and timeout fallbacks. |
| `git` | Clones, updates, and identifies revisions for most targets. |
| `gh` | Lets reachability checks query GitHub Code Search when scoring crash exposure. |
| `jq` | Reads and writes JSONL state records. |
| `rg` | Fast, bounded source search through helper commands. |
| `file` | Distinguishes testcase inputs from scripts and compiled artifacts. |
| `curl`, CA certificates | Fetch backend installers and remote metadata over HTTPS. |
| `node`, `npm` | Install npm-based backend CLIs and run backend diagnostics. |

`bin/audit` preflight-checks `jq`, `python3`, and `perl` at startup and
exits with a clear "FATAL: missing required tool(s): ..." message if
any are absent. The remaining tools are required by individual commands
(`bash` runs every shell wrapper, `git` is invoked by `bin/setup-target`,
`rg` by `bin/rg-safe`, `file` by triage classification) but are not
gated centrally — install them all up front to avoid scattered failures
mid-run.

For sanitizer builds, you also need LLVM:

| Tool | Why it is needed |
| --- | --- |
| `clang`, `clang++` | Build target code with sanitizer instrumentation. |
| `llvm-ar` | Build and test static-library sanitizer harnesses. |
| `llvm-symbolizer` | Turn sanitizer PCs into readable stack traces. |
| `sancov` | Enable coverage-gated probes on supported targets. |
| `nm` | Detect candidate sanitizer binaries in build trees. |
| `otool` (macOS) | Inspect the dynamic loader's view of an instrumented binary. |
| `readelf`, `llvm-readelf`, or `objdump` (Linux) | Inspect ELF sections in coverage-instrumented binaries. |

The LLVM tools ship with LLVM. On macOS, `otool` comes from Apple's
command-line tools. On Linux, section-inspection tools come from
binutils or LLVM packages. Distro LLVM packages are usually fine;
install LLVM-project packages directly only when your target needs a
newer compiler than the distro provides.

### macOS

```bash
xcode-select --install
brew install gh jq node ripgrep llvm
```

`xcode-select --install` provides Apple's command-line tools (Git, Clang
support files, `python3`, `nm`, and `otool`). macOS already includes
Bash, Perl, `curl`, CA certificates, and `file`. If the command-line
tools are already installed, macOS will say so. Git is not guaranteed on
a fresh macOS install until those command-line tools are installed.

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
  bash binutils ca-certificates clang curl file gh git jq libclang-rt-dev \
  llvm nodejs npm perl procps python3 ripgrep
```

Notes:

- `libclang-rt-dev` provides the compiler-rt sanitizer runtimes used
  when the test suite builds small sanitizer-instrumented C/C++
  harnesses.
- The meta package tracks the default `clang` / `llvm` version on
  apt-based distros. If you install a non-default LLVM major version,
  also install the matching `libclang-rt-<N>-dev`, `clang-<N>`, and
  `llvm-<N>`.
- Standard POSIX/GNU utilities — `awk`, `sed`, `grep`, `find`, `sort`,
  `head`, `tail`, `stat`, `wc` — are already present in Debian/Ubuntu
  base images.
- `file` is called out explicitly because the harness uses it to
  distinguish compiled reproducers from scripts.
- `nodejs` and `npm` are needed by the npm-based backend CLIs
  (`codex`, `@google/gemini-cli`) and by a few harness diagnostics
  that call `node`.
### Fedora / RHEL

```bash
sudo dnf install -y \
  bash binutils ca-certificates clang coreutils curl diffutils file findutils \
  compiler-rt gawk gh git grep jq llvm nodejs npm perl procps-ng python3 \
  ripgrep sed which
```

No extra Perl or Python packages are needed. The command includes
standard userland packages that full Fedora/RHEL hosts usually already
have, because minimal container images often do not.

## 2. One agent backend

Agents run through an external CLI. Install and authenticate one of the
supported backends before pointing TokenFuzz at a real target.

Backend CLIs have their own install and authentication steps. The OS
commands above already include their common installer prerequisites:

- Codex and Google Gemini CLI use npm-based installers; the host-tool
  commands above install Node.js and npm for that path.
- The default Gemini path uses the Antigravity installer, which needs
  `curl` and valid CA certificates, also installed above.
- The local `oss` backend needs Codex plus Ollama.

| Backend | Install and authenticate | Audit command |
| --- | --- | --- |
| Claude Code | Install from the [Claude Code docs](https://docs.claude.com/en/docs/claude-code), then authenticate the `claude` CLI (`claude` will prompt on first use). Pass `--model <id>` to override the default model. | `bin/audit --backend claude` |
| Codex | `npm install -g @openai/codex`, then authenticate the `codex` CLI. Pass `--model <id>` to override the default model. | `bin/audit --backend codex` |
| Gemini | Default: install [Antigravity CLI](https://github.com/google-antigravity/antigravity-cli) with `curl -fsSL https://antigravity.google/cli/install.sh \| bash`, then run `agy` once to authenticate. `agy` has no `--model` selector; use its interactive `/model` command. Alternative: install Google Gemini CLI, set `USE_GEMINI_CLI=1`, and pass `--model <id>` when needed. | `bin/audit --backend gemini --target <name>` |
| Local model (`oss`) | The `oss` backend reuses the Codex CLI with its `--oss` switch, so install Codex first. Then install [Ollama](https://ollama.com), `ollama pull <model>`, and confirm it appears in `ollama list`. `--model` is **required** for `oss`. | `bin/audit --backend oss --model <ollama-model>` |

When you pass `--backend all` (or omit `--backend` entirely), `bin/audit`
cycles installed hosted backends in `claude → codex → gemini` order,
iteration by iteration. Each backend writes to its own
`output/<target>/<backend>/results/` tree, so you can ensemble without
overlap. See [Backends and ensembling](../guides/backends.md) for
the full set of tradeoffs.

### Cyber access for security research

If you use a hosted model for legitimate defensive security research,
the provider's trusted-access programs can reduce false-positive
interruptions during dual-use work. Register your organisation and use
case before you start long sessions:

- **Codex** — verify or request OpenAI
  [Trusted Access for Cyber](https://chatgpt.com/cyber). Background:
  OpenAI's [Trusted Access for Cyber](https://openai.com/index/trusted-access-for-cyber/)
  announcement.
- **Claude Code** — apply through Anthropic's
  [Cyber Verification Program](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude)
  using the [Cyber Use Case Form](https://claude.com/form/cyber-use-case).

These programs are not a substitute for actual target authorisation or
for following the provider's usage policy. They give the provider
clearer context that your work is defensive, authorised research.

If you would rather keep target source on the local machine, use the
`oss` backend through Ollama. It avoids hosted-model data flow
entirely, runs on the same audit contract, but tends to need shorter
sessions and more hands-on review of results.

## 3. Target-specific tools

Most C and C++ targets need only their normal build dependencies plus
the host tools above. A `libxml2` audit, for example, starts with the
base harness tools and adds whatever the upstream `libxml2` build
instructions require on your host.

Browser targets, Mercurial-hosted projects, and very large codebases may
need extra compilers, package managers, language runtimes, or source
control tools. Follow the target project's own build documentation for
those dependencies. TokenFuzz needs the resulting sanitizer binary,
library, or harness configuration — it does not replace the target's
build system.

## 4. Verify the harness

From the repository root:

```bash
bash tests/run-tests.sh
bash tests/run-tests.sh --image ubuntu:24.04
bash tests/run-tests.sh --image fedora:latest
```

The suite does **not** call out to any real LLM backend — it stubs the
agent invocations in [`tests/helpers.sh`](https://github.com/tokenfuzz/tokenfuzz/blob/main/tests/helpers.sh) so it can run before you
configure any backend CLI. It exercises the local shell, Python, Perl,
jq, target config parsing, triage logic, state handling, search
wrappers, and testcase classification.

The `--image` forms are a portability sanity check: they re-run the
same tests inside a clean Linux Docker container, which is the easiest
way to catch a missing dependency without rebuilding your host. Image
mode installs the baseline Linux tools inside the container before
running the suite. For apt-based images such as `ubuntu:24.04`, that
includes the Debian / Ubuntu package set above, including
`libclang-rt-dev`.

## 5. Verify the audit pipeline end-to-end

Once you have a target and an ASan build, run one bounded audit
iteration:

```bash
bin/audit --target <target> --backend <backend> 1
```

A healthy startup writes a timestamped startup block to the index log.
Check `Agent pool:` first; it records the worker count the harness
actually chose after target detection and any RAM / sibling-audit
autotuning. The same run should populate `state/`, `work-cards.jsonl`,
and `scratch-N/` under `output/<target>/<backend>/results/`. An empty
`crashes/` and `findings/` is normal after one iteration.

[First audit](first-audit.md) walks through this run in full — the
startup block, what each result and log file means, and how to read the
output. Once the bounded iteration looks healthy, drop the iteration
count to run continuously:

```bash
bin/audit --target <target> --backend <backend>
```

## Container runtime (recommended)

We recommend running audits inside a container — see [Where to run the
audit](first-audit.md#where-to-run-the-audit) for the reasoning. You
need Docker installed yourself; the harness will not install Docker,
Colima, or gVisor for you.

| Platform | Install command |
| --- | --- |
| macOS | [Docker Desktop](https://www.docker.com/products/docker-desktop/) (`brew install --cask docker`) or `brew install colima docker` |
| Debian / Ubuntu | `sudo apt-get update && sudo apt-get install -y docker.io` |
| Fedora | `sudo dnf install -y moby-engine` |

After installation, make sure `docker info` works. Start Docker Desktop,
run `colima start`, or start the Linux service with
`sudo systemctl start docker` if needed. On RHEL-family hosts where
`moby-engine` is not available from your enabled repositories, install a
Docker-compatible engine using your distro's standard package source.

### Optional gVisor runtime

On a Linux Docker host, gVisor adds another sandbox layer around the
audit container. The required-tools commands above do not install or
register `runsc`; follow gVisor's Docker setup first. Verify that Docker
can run with `runsc`:

```bash
docker run --runtime=runsc --rm hello-world
```

Then enable it for the audit container:

```bash
bin/audit-container-shell --gvisor
```

That is shorthand for `--docker-runtime runsc`. The image build still
uses normal Docker; only the interactive audit container runs under
gVisor.

## macOS notes

A few things worth knowing on macOS:

- You do not need GNU coreutils. Scripts work with BSD `stat`, `date`,
  `sed`, and `mktemp`, and tolerate a missing `realpath`.
- System Bash 3.2 is sufficient — no need to install a newer Bash.
- Homebrew LLVM is auto-detected at `/opt/homebrew/opt/llvm` and
  `/usr/local/opt/llvm`. Set `LLVM_PREFIX` only when you want to force a
  different LLVM install.

## If preflight fails

`bin/audit` exits with a message like:

```text
FATAL: missing required tool(s): ...
```

Install the named tools and try again. For other recurring setup or
runtime failures, see
[Troubleshooting](../reference/troubleshooting.md).
