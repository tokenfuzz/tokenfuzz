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
| `python3` | Parses target config and structured state. No extra packages. |
| `perl` | Runs vocabulary normalization and timeout fallbacks. |
| `git` | Clones, updates, and identifies revisions for most targets. |
| `jq` | Reads and writes JSONL state records. |
| `rg` | Fast, bounded source search through helper commands. |
| `file` | Distinguishes testcase inputs from scripts and compiled artifacts. |

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
| `llvm-symbolizer` | Turn sanitizer PCs into readable stack traces. |
| `sancov` | Enable coverage-gated probes on supported targets. |
| `otool` (macOS) | Inspect the dynamic loader's view of an instrumented binary. |
| `readelf`, `llvm-readelf`, or `objdump` (Linux) | Inspect ELF sections in coverage-instrumented binaries. |

The LLVM tools ship with LLVM. On macOS, `otool` comes from Apple's
command-line tools. On Linux, section-inspection tools come from
binutils or LLVM packages. Distro LLVM packages are usually fine;
install LLVM-project packages directly only when your target needs a
newer compiler than the distro provides.

### macOS

```bash
brew install jq ripgrep llvm
xcode-select --install
```

`xcode-select --install` provides Apple's command-line tools (Git, Clang
support files, `python3`, and `otool`). macOS already includes Bash,
Perl, and `file`. If the command-line tools are already installed,
macOS will say so.

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
  bash ca-certificates clang curl file git jq libclang-rt-dev llvm \
  nodejs npm perl procps python3 ripgrep
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
- `nodejs` (and `npm`) are needed by `bin/audit` itself — its
  `gemini_cli_check_bundled_ripgrep` diagnostic uses `node` for portable
  realpath and platform/arch detection — and by the npm-based backends
  (`codex`, `@google/gemini-cli`). The same packages cover both.

### Fedora / RHEL

```bash
sudo dnf install -y \
  bash ca-certificates clang curl file git jq llvm nodejs npm perl \
  procps-ng python3 ripgrep
```

No extra Perl packages are needed — the harness uses Perl core modules
only. Python needs no extra packages on 3.11+ (which ships the `tomllib`
parser in the standard library); on Python 3.9/3.10 install `tomli`, which
the harness imports to read `target.toml` and the model config. Minimal
Fedora/RHEL container
images may also need the standard userland packages that full hosts
already have, such as `coreutils`, `diffutils`, `findutils`, `gawk`,
`grep`, `sed`, and `which`.

## 2. One agent backend

Agents run through an external CLI. Install and authenticate one of the
supported backends before pointing TokenFuzz at a real target.

Backend installer prerequisites are separate from the harness runtime
tools above:

- Codex and Google Gemini CLI use npm-based installers; install
  Node.js and npm first when using those CLIs directly (`brew install
  node`, `sudo apt-get install -y nodejs npm`, or `sudo dnf install -y
  nodejs npm`).
- The default Gemini path uses the Antigravity installer, which needs
  `curl` and valid CA certificates.
- The local `oss` backend needs Codex plus Ollama.

| Backend | Install and authenticate | Audit command |
| --- | --- | --- |
| Claude Code | Install from the [Claude Code docs](https://docs.claude.com/en/docs/claude-code), then authenticate the `claude` CLI (`claude` will prompt on first use). Default model: `claude-opus-4-8`; pass `--model <id>` to override. | `bin/audit --backend claude` |
| Codex | `npm install -g @openai/codex`, then authenticate the `codex` CLI. Default model: `gpt-5.5`; pass `--model <id>` to override. | `bin/audit --backend codex` |
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

Browser targets and very large projects often need extra setup. Firefox
is the canonical example:

- Its source lives in Mercurial.
- Its build system pins a Python minor version.
- You need both `hg` and Python 3.12.

### macOS

```bash
brew install mercurial python@3.12
```

### Debian / Ubuntu

```bash
sudo apt-get install -y mercurial python3.12
```

### Fedora / RHEL

```bash
sudo dnf install -y mercurial python3.12
```

Once Firefox is cloned into `targets/firefox`, run Mozilla's bootstrap
once from inside the checkout:

```bash
(cd targets/firefox && python3.12 ./mach bootstrap)
```

Use `python3.12` here — Firefox `mach` is pinned to a Python minor
version. For the full upstream setup flow, see the
[Firefox source documentation](https://firefox-source-docs.mozilla.org/setup/).

In general, follow each target project's own build documentation.
TokenFuzz needs the resulting sanitizer binary, library, or harness
configuration — it does not replace the target's build system.

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
| Debian / Ubuntu | `sudo apt-get install -y docker.io` |
| Fedora / RHEL | `sudo dnf install -y docker` |

You usually do not need to start the daemon yourself.
`bin/audit-container-shell` detects when the daemon is down and tries
the appropriate launcher (`open -a Docker`, `colima start`, or
`systemctl --user start docker`), then polls reachability for up to 60
seconds. If your Linux install requires a system service instead, start
Docker manually, for example with `sudo systemctl start docker`. Set
`AUDIT_CONTAINER_AUTO_START=0` to opt out or
`AUDIT_CONTAINER_START_TIMEOUT=<seconds>` to wait longer.

### Optional gVisor runtime

On a Linux Docker host, gVisor adds another sandbox layer around the
audit container. Once `runsc` is installed and registered with Docker,
enable it like this:

```bash
bin/audit-container-shell --gvisor --rebuild
```

That is shorthand for `--docker-runtime runsc`. You can also set
`AUDIT_DOCKER_RUNTIME=runsc`. The image build still uses normal Docker;
only the interactive audit container runs under gVisor.

## Optional tools

Only two extras are actually consulted by the harness:

| Tool | What it unlocks |
| --- | --- |
| `gh` | `bin/reachability` queries GitHub Code Search to estimate external caller exposure when scoring crash severity. |
| `hg` | Mercurial-hosted targets such as Firefox. |

Install both on whichever distribution you use:

```bash
brew install gh mercurial                              # macOS
sudo apt-get install -y gh mercurial                   # Debian / Ubuntu
sudo dnf install -y gh mercurial                       # Fedora / RHEL
```

## macOS notes

A few things worth knowing on macOS:

- You do not need GNU coreutils. Scripts work with BSD `stat`, `date`,
  `sed`, and `mktemp`, and tolerate a missing `realpath`.
- System Bash 3.2 is sufficient — no need to install a newer Bash.
- If Homebrew LLVM is installed but the sanitizer tools are not found,
  make sure the Homebrew LLVM `bin` directory is on your `PATH`.

## If preflight fails

`bin/audit` exits with a message like:

```text
FATAL: missing required tool(s): ...
```

Install the named tools and try again. For other recurring setup or
runtime failures, see
[Troubleshooting](../reference/troubleshooting.md).
