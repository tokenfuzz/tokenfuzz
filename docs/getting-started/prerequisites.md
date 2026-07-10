# Prerequisites

Before you run an audit, install three things:

- a handful of host tools;
- an LLVM toolchain for sanitizer builds;
- one authenticated agent backend.

The harness uses Python for orchestration, structured data, filesystem
operations, sanitizer launchers, and triage. It writes state, logs, and reports to the local results
directory. Hosted backends receive the
prompts, source excerpts, state, and reports needed for the run. Use
`--backend oss` when policy requires model data flow to stay local.

This page walks through each piece in order. Install commands are given
for macOS, Debian / Ubuntu, and Fedora / RHEL. Sections 4 and 5 verify
the install before you point the harness at a real target.

## 1. Host tools

These are the everyday tools the harness invokes during normal operation
and during sanitizer builds.

| Tool | Why it is needed |
| --- | --- |
| `python3` 3.10+ with `venv` support | Runs every TokenFuzz orchestration, sanitizer, state, reporting, and triage command. `venv` is used by `bin/docs`, Python-target bootstraps, and the vLLM quick path below. |
| `git` | Clones, updates, and identifies revisions for most targets. |
| `rg` | Fast, bounded source search through helper commands. |
| `file` | Distinguishes testcase inputs from scripts and compiled artifacts. |

Optional host tools are workload-specific:

| Tool | When it is needed |
| --- | --- |
| `gh` | Cross-project advisory queries (`gh api`) used by Strategy S6. |
| `bash` | Running `tests/run-tests.sh`, generated `reproduce.sh`/build recipes, or auditing a shell-language target. |
| `jq` | Running the repository's Bash-based test suites; production commands parse JSON in Python. |

`bin/audit` itself requires Python. Individual workflows invoke `git`, `rg`,
`file`, LLVM tools, or optional `gh` only when that capability is used.

For sanitizer builds, you also need LLVM:

| Tool | Why it is needed |
| --- | --- |
| `clang`, `clang++` | Build target code with sanitizer instrumentation. |
| `llvm-symbolizer` | Turn sanitizer PCs into readable stack traces. |
| `sancov` | Enable coverage-gated probes on supported targets. |
| `nm` | Detect candidate sanitizer binaries in build trees. |
| `otool` (macOS) | Inspect Mach-O sections in coverage-instrumented binaries. |
| `readelf`, `llvm-readelf`, or `objdump` (Linux) | Inspect ELF sections in coverage-instrumented binaries. |

The LLVM-specific tools (`llvm-symbolizer`, `sancov`, `llvm-readelf`)
ship with LLVM. On macOS, `otool` and `atos` come from Apple's
command-line tools. On Linux, `nm`, `readelf`, `objdump`, and
`addr2line` come from binutils. Distro LLVM packages are usually fine;
install LLVM-project packages directly only when your target needs a
newer compiler than the distro provides.

One gap to know about: the Debian / Ubuntu `llvm` package omits
`sancov`, so coverage-gated probes (`bin/hits`) exit 2 there. Fedora's
`llvm`, Homebrew's `llvm`, and [apt.llvm.org](https://apt.llvm.org/) all
ship it.

Tools your *target's* build needs — an archiver, a package manager, a
language runtime — come from the target's own build requirements, not
from TokenFuzz.

### macOS

```bash
xcode-select --install
brew install gh ripgrep llvm
```

`xcode-select --install` provides Apple's command-line tools (Git, Clang
support files, `python3`, `nm`, and `otool`). macOS already includes
`curl`, CA certificates, and `file`. If the command-line
tools are already installed, macOS will say so. Git is not guaranteed on
a fresh macOS install until those command-line tools are installed.
If `python3 -m venv` is unavailable or creates an environment without
`pip`, install Homebrew Python with `brew install python`.

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
  binutils clang file gh git libclang-rt-dev llvm python3 python3-venv ripgrep
```

Notes:

- `binutils` provides `nm`, `readelf`, `objdump`, and `addr2line`; the
  `llvm` package provides `llvm-symbolizer` and `llvm-readelf`.
- `libclang-rt-dev` supplies the compiler-rt sanitizer runtimes.
- The meta packages track the default `clang` / `llvm` version. If you
  install a non-default LLVM major version, also install the matching
  `libclang-rt-<N>-dev`, `clang-<N>`, and `llvm-<N>`.
- `python3-venv` is needed by `bin/docs`, Python-target bootstraps, and
  the vLLM setup commands shown below.
- Minimal container images also need `ca-certificates` and `procps`; add
  `bash` and `jq` when running the repository test suite.

### Fedora / RHEL

```bash
sudo dnf install -y \
  binutils clang compiler-rt file gh git llvm python3 python3-pip ripgrep
```

`compiler-rt` supplies the sanitizer runtimes that `libclang-rt-dev`
provides on Debian / Ubuntu. `python3-pip` is included so environments
created with `python3 -m venv` get a working `pip`.

Minimal container images also need `ca-certificates`,
`coreutils`, `diffutils`, `findutils`, `gawk`, `grep`, `procps-ng`, and
`sed`; add `bash` and `jq` for the repository test suite.

## 2. One agent backend

Agents run through an external CLI. Install and authenticate one of the
supported backends before pointing TokenFuzz at a real target.

Backend CLIs have their own install and authentication steps:

- Install `curl` only when you choose an installer command that pipes an
  HTTPS script, such as the direct Codex, Antigravity, Grok Build, OpenCode, or
  Ollama install snippets below.
- Install Node.js and npm only when you choose an npm-based backend CLI
  install path, such as `npm install -g @openai/codex`,
  `@google/gemini-cli`, or `opencode-ai`. They are also needed for
  JavaScript / TypeScript audit targets.
- The default Gemini path uses the Antigravity installer, which needs
  `curl` and valid CA certificates.
- The local `oss` backend needs OpenCode plus a local model server.
  vLLM is the recommended default for fast GPU inference; Ollama is the
  simple desktop fallback.

| Backend | Install and authenticate | Audit command |
| --- | --- | --- |
| Claude Code | Install from the [Claude Code docs](https://docs.claude.com/en/docs/claude-code), then authenticate the `claude` CLI (`claude` will prompt on first use). Pass `--model <id>` to override the default model. | `bin/audit --backend claude --target <name>` |
| Codex | Follow the [Codex CLI setup](https://developers.openai.com/codex/cli#cli-setup), or install directly with `curl -fsSL https://chatgpt.com/codex/install.sh \| sh`, then authenticate the `codex` CLI. Alternatives: `npm install -g @openai/codex` or `brew install --cask codex`. Pass `--model <id>` to override the default model. | `bin/audit --backend codex --target <name>` |
| Gemini | Default: install [Antigravity CLI](https://github.com/google-antigravity/antigravity-cli) with `curl -fsSL https://antigravity.google/cli/install.sh \| bash`, then run `agy` once to authenticate. Pass `--model` as a config slug or an exact `agy models` label to override the default. Alternative: install Google Gemini CLI, set `USE_GEMINI_CLI=1` (this path also needs `GEMINI_API_KEY` or `GOOGLE_API_KEY`), and pass `--model <id>` when needed. If Gemini CLI logs `Ripgrep is not available`, apply the [bundled ripgrep symlink](../guides/backends.md#google-gemini-cli-ripgrep). | `bin/audit --backend gemini --target <name>` |
| Grok Build | Follow xAI's [Grok Build setup](https://docs.x.ai/build/overview), or install directly with `curl -fsSL https://x.ai/cli/install.sh \| bash`, then export `XAI_API_KEY`. Pass `--model <id>` to override the `grok-build-0.1` default. | `bin/audit --backend grok --target <name>` |
| Local model (`oss`) | Install [OpenCode](https://opencode.ai/download). Then run a local model through [vLLM](https://docs.vllm.ai/en/latest/getting_started/installation/) (recommended for larger GPU-backed models) or [Ollama](https://ollama.com/download). `--model` is **required** for `oss` and must match the served model name. | `bin/audit --backend oss --model qwen3-8b --target <name>` |

Local model quick paths:

```bash
# OpenCode terminal CLI.
curl -fsSL https://opencode.ai/install | bash
# Alternative installers: npm i -g opencode-ai, or brew install anomalyco/tap/opencode.
```

```bash
# vLLM, recommended for fast Linux GPU inference.
python3 -m venv .venv-vllm
. .venv-vllm/bin/activate
pip install -U vllm
vllm serve <hf-model-or-local-path> --served-model-name qwen3-8b

bin/audit --backend oss --model qwen3-8b --target <name> 1
```

The served model name is the exact string TokenFuzz checks against the
local server's `/v1/models` endpoint — pass the same value to `--model`.

Examples:

```bash
vllm serve google/gemma-4-26B-A4B --served-model-name gemma4-26b-a4b
bin/audit --backend oss --model gemma4-26b-a4b --target <name> 1

vllm serve Qwen/Qwen3.6-35B-A3B --served-model-name qwen3.6-35b-a3b
bin/audit --backend oss --model qwen3.6-35b-a3b --target <name> 1

vllm serve zai-org/GLM-5.2 --served-model-name glm5.2
bin/audit --backend oss --model glm5.2 --target <name> 1
```

```bash
# Ollama, useful for macOS and smaller local models.
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:8b
ollama serve

export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:11434/v1
bin/audit --backend oss --model qwen3:8b --target <name> 1
```

Ollama examples:

```bash
export AUDIT_LOCAL_BASE_URL=http://127.0.0.1:11434/v1

ollama pull gemma4:26b
bin/audit --backend oss --model gemma4:26b --target <name> 1

ollama pull qwen3.6:35b-a3b
bin/audit --backend oss --model qwen3.6:35b-a3b --target <name> 1

# Ollama's GLM-5.2 tag is cloud-backed today. Use vLLM for fully local GLM-5.2.
ollama pull glm-5.2:cloud
bin/audit --backend oss --model glm-5.2:cloud --target <name> 1
```

When you pass `--backend all` (or omit `--backend` entirely), `bin/audit`
cycles installed hosted backends in `claude → codex → gemini → grok` order,
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
`oss` backend through OpenCode and a local model server. It avoids
hosted-model data flow entirely, runs on the same audit contract, but
tends to need shorter sessions and more hands-on review of results.

## 3. Target-specific tools

Most C and C++ targets need only their normal build dependencies plus
the host tools above. A `libxml2` audit, for example, starts with the
base harness tools and adds whatever the upstream `libxml2` build
instructions require on your host.

Browser targets, Mercurial-hosted projects, and very large codebases may
need extra compilers, package managers, language runtimes, or source
control tools. Follow the target project's own build documentation for
those dependencies. For example, Perl-language targets need `perl`.
TokenFuzz needs the resulting sanitizer binary,
library, or harness configuration — it does not replace the target's
build system.

## 4. Verify the harness

From the repository root:

The test driver and several shell fixtures use Bash and `jq`. Install
those two development-only tools before running this section.

```bash
bash tests/run-tests.sh
bash tests/run-tests.sh --image ubuntu:24.04
bash tests/run-tests.sh --image fedora:latest
```

The suite does **not** call out to any real LLM backend — it stubs the
agent invocations in [`tests/helpers.sh`](https://github.com/tokenfuzz/tokenfuzz/blob/main/tests/helpers.sh) so it can run before you
configure any backend CLI. It exercises the Python runtime, shell fixtures,
target config parsing, triage logic, state handling, search commands,
and testcase classification.

The `--image` forms are a portability sanity check: they re-run the
same tests inside a clean Linux Docker container, which is the easiest
way to catch a missing dependency without rebuilding your host. Image
mode provisions the container with
`tests/run-tests.sh --install-container-deps` before running the suite.
For apt-based images such as `ubuntu:24.04`, that installs the Debian /
Ubuntu package set above, including `libclang-rt-dev` and
`python3-venv`.

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

- You do not need GNU coreutils. Production commands use Python filesystem
  and process APIs instead of platform-specific `stat`, `sed`, or `realpath` forms.
- System Bash is sufficient for the test driver and generated recipes.
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
