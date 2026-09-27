# Prerequisites

An audit needs three things: host tools, one authenticated model backend, and
the target project's own build toolchain. TokenFuzz runs on macOS and Linux.
To check an installation before you build anything, audit the pure-Python
[sample target](sample-targets.md); it needs no native build.

Hosted backends receive the prompts, source excerpts, state, and reports a run
needs. When source and audit context must stay on the machine, use
`--backend oss` with a local OpenAI-compatible model server.

## 1. Host tools

| Tool | What uses it |
| --- | --- |
| Python 3.11 or newer, with `venv` | Every `bin/` command, `bin/docs`, and Python target bootstraps. Python 3.10, the oldest version CI tests, also needs `python3 -m pip install tomli`; without it some `target.toml` files, including the C and C++ samples', fail to parse. |
| Git | Cloning and revision tracking. Add Mercurial (`hg`) for an hg target. |
| ripgrep (`rg`) | Bounded source search by agents. |
| `file` | Testcase and executable classification. |
| LLVM: `clang`, `clang++`, `llvm-symbolizer` | Native sanitizer builds and symbolized reports. |
| `sancov` (optional) | Probe coverage feedback (HIT or MISSED). Without it, probes still run, ungated. |
| [`trailmark`](https://github.com/trailofbits/trailmark) (optional, experimental) | A static call map in work-card prompts. Needs Python 3.12 or newer. See [below](#experimental-call-neighbourhood-context). |

`bin/` commands run under the first `python3` on `PATH`, so check that one
with `python3 --version`. Your target may also need CMake, Meson, Ninja, a
language runtime, or other upstream dependencies; see
[Target-specific tools](#3-target-specific-tools).

### macOS

```bash
xcode-select --install
brew install llvm ripgrep python
```

The Command Line Tools provide Git, `file`, and Apple clang, but their
`python3` (3.9 in current releases) is too old: put Homebrew Python first on
`PATH`. Homebrew LLVM supplies `llvm-symbolizer`, `sancov`, and the clang with
libFuzzer that coverage and fuzzing builds use. TokenFuzz finds it without a
`PATH` change; see [macOS notes](#macos-notes).

### Debian / Ubuntu

```bash
sudo apt-get update
sudo apt-get install -y \
  bash binutils clang file git libclang-rt-dev llvm \
  python3 python3-venv ripgrep
```

The distribution `llvm` package may omit `sancov`, so probes run without
coverage feedback even though ASan works. When that matters, install a
complete LLVM from [apt.llvm.org](https://apt.llvm.org/); its
`/usr/lib/llvm-*` layout is detected automatically.

### Fedora / RHEL

```bash
sudo dnf install -y \
  bash binutils clang compiler-rt file git llvm \
  python3 python3-pip ripgrep
```

Minimal containers may also need CA certificates and the standard process and
text utilities.

## 2. One agent backend

Install and authenticate at least one supported CLI:

| Backend | CLI | Notes |
| --- | --- | --- |
| `claude` | `claude` | Claude Code. Agents load none of your Claude settings files, so authenticate by login or environment variable, not through an `apiKeyHelper` or `env` block in `settings.json`. |
| `codex` | `codex` | Codex CLI. On Linux and WSL2 its sandbox needs the `bubblewrap` package; see the [Codex sandboxing prerequisites](https://learn.chatgpt.com/docs/sandboxing?sandbox-os=ubuntu-debian#prerequisites) for the Ubuntu AppArmor notes. |
| `gemini` | `agy` | Antigravity CLI. Set `USE_GEMINI_CLI=1` to use Google Gemini CLI (`gemini`) instead. |
| `grok` | `grok` | Grok Build, with its credentials configured. |
| `oss` | `opencode` | OpenCode. It has no default model, so every audit command needs `--model` with an OpenCode catalog id (`opencode/<id>`) or the exact id a local OpenAI-compatible endpoint serves. |

For an executable outside `PATH`, set `CLAUDE_BIN`, `CODEX_BIN`,
`GEMINI_BIN`, `GROK_BIN`, or `OPENCODE_BIN`.

Only `claude` and `codex` can run inside their own CLI sandbox, which is the
default. `gemini` and `grok` refuse to start that way, and `oss` defaults to
`--agent-security external-bypass`. Run those three inside a container or VM
you administer, such as the [container shell](#container-runtime-recommended);
[Agent security modes](../guides/backends.md#agent-security-modes) explains
why.

Run the chosen CLI once by hand before TokenFuzz launches it: a backend
waiting for a login can look like a stalled agent.
[Backends and isolation](../guides/backends.md) covers installation,
authentication checks, model selection, local vLLM and Ollama setup, and
ensembles.

### Cyber access for security research

For authorised defensive research through a hosted model, register the
organisation and use case with the provider's trusted-access program before a
long run. OpenAI documents Daybreak and Trusted Access for Cyber under
[Models and Trusted Access](https://learn.chatgpt.com/docs/cyber-safety), and
Anthropic offers a
[Cyber Verification Program](https://support.claude.com/en/articles/14604842-real-time-cyber-safeguards-on-claude-opus-and-sonnet).
Registration does not replace target authorisation or the provider's usage
policy.

If the provider serves a different model than the one requested, including
when that model's safeguards decline the workload, model preflight stops the
run and names the served model and any declared refusal category; see
[Troubleshooting](../reference/troubleshooting.md#preflight-fails).

## 3. Target-specific tools

TokenFuzz drives the target's build; it does not replace the target's
toolchain. Install what the project's own build instructions ask for:

- C and C++: often CMake, Meson, autotools, Ninja, or project libraries, on
  top of LLVM.
- Rust, Go, Python, Java, and other ecosystems: the normal compiler,
  interpreter, package manager, and development headers.
- Browsers: possibly Mercurial, `depot_tools`, large SDKs (Chromium on macOS
  needs Xcode with the Metal toolchain), and project bootstrap tooling.

Confirm that the project builds and runs with its documented toolchain
first. That separates a dependency problem from an instrumentation or
harness problem.

Every audit and benchmark starts the configured `[runner].bin` before it
launches an agent, and stops, naming the command, when the runner cannot
start or does not reach the audited checkout.
[How the runner is proved](../guides/multi-language.md#how-the-runner-is-proved)
has the details.

On macOS, `/usr/bin/java` is a stub that works only once a JDK is registered
under `/Library/Java/JavaVirtualMachines`. Homebrew's `openjdk` is keg-only,
so link it, then add the Kotlin compiler if you need it:

```bash
brew install openjdk kotlin
sudo ln -sfn "$(brew --prefix openjdk)/libexec/openjdk.jdk" \
  /Library/Java/JavaVirtualMachines/openjdk.jdk
/usr/bin/java -version
kotlinc -version
```

## 4. Verify the harness

From the repository root:

```bash
bash tests/run-tests.sh
```

The suite stubs backend calls, so it needs no authentication or model tokens.
Read its `SKIP` lines: the Node.js and Go runner checks skip when `node` or
`go` is missing, and the live backend sandbox checks skip unless
`TOKENFUZZ_LIVE_BACKENDS` names backends.

To run the suite in a clean Docker container, which installs its dependencies
first unless you pass `--no-install-deps`:

```bash
bash tests/run-tests.sh --image ubuntu:24.04
bash tests/run-tests.sh --image fedora:latest
```

The container lane runs on CI's `linux/amd64` platform, emulated on an arm64
host, unless you pass `--platform`. Inside a container you provision
yourself, `bash tests/run-tests.sh --install-container-deps` installs
everything the suite knows about through `apt-get`, `dnf`, `microdnf`, or
`yum`.

## 5. Run a smoke audit

Once a target is configured, one bounded iteration proves that the config,
build preflight, backend launch, state, and result paths work together:

```bash
bin/audit --target samples/sample-python --backend <backend> 1
```

[First audit](first-audit.md) explains what the run should produce and how to
inspect it.

## Container runtime (recommended)

Target build scripts and agent-driven testcases execute code from the
audited tree. Run audits in a disposable container or on an isolated machine
without long-lived credentials. The helper supports Docker only; check
`docker info` first:

```bash
bin/audit-container-shell --rebuild   # first use: build the image
bin/audit-container-shell             # later: reuse the image
```

`--rebuild` builds an image (default base `node:lts-bookworm`) with Claude
Code, Codex, Antigravity CLI, Google Gemini CLI, Grok Build, and OpenCode.
Without it, the helper refuses to start until that image exists. Each start
mounts this repository at `/root/work`, installs the harness's host tools,
and opens a shell. It never starts an audit for you.

The container starts logged out: host `~/.claude`, `~/.codex`, `~/.gemini`,
`~/.grok`, and OpenCode directories are never mounted. Log in inside it, or
pass `--forward-credentials` to forward supported credential environment
variables and Google Cloud config. The helper sets `IS_SANDBOX=1`, the
assertion `--agent-security external-bypass` expects.
`bin/audit-container-shell --help` lists every flag and the login commands.

### Optional gVisor runtime

On a Linux Docker host with `runsc` registered, add another sandbox boundary:

```bash
docker run --runtime=runsc --rm hello-world
bin/audit-container-shell --gvisor
```

`--gvisor` is shorthand for `--docker-runtime runsc`. Never run the audit
container as privileged, and never mount the Docker socket into it.

## macOS notes

- GNU coreutils are not required, and the system Bash is enough for the test
  driver and generated build recipes.
- LLVM tools are found through `LLVM_PREFIX` when set, then Homebrew's
  `/opt/homebrew/opt/llvm` and `/usr/local/opt/llvm`, before `PATH`. Set
  `LLVM_PREFIX` only to select another installation.
- Generated build recipes compile with `$CC` and `$CXX`, or `clang` and
  `clang++` from `PATH` (Apple clang on a default setup). Generated CMake and
  Meson recipes append Homebrew's `$(brew --prefix)/opt` tree to
  `CMAKE_PREFIX_PATH`; paths you set explicitly keep precedence.

## If preflight fails

`bin/audit` stops before launching an agent when the backend is not installed
or configured, the runner fails its startup check, or the model preflight
fails. Install the named dependency, verify the target builds outside the
harness, then rerun the one-iteration command.
[Troubleshooting](../reference/troubleshooting.md) covers sanitizer, runner,
and backend failures.

## Experimental: call-neighbourhood context

Skip this for a first install. With
[trailmark](https://github.com/trailofbits/trailmark) importable by Python
3.12 or newer, each work card can carry the file's static callers and callees,
the shortest routes from the build's entry boundary to its most-called
functions, and a pack of key caller and callee definitions capped at 600
tokens.

```bash
python3 -m pip install trailmark   # into any Python 3.12+ interpreter
bin/callgraph --probe              # prints "callgraph: ready ..." when usable
```

There is no flag to set. TokenFuzz tries the interpreter running it, then
`python3.15` down to `python3.12`, then `python3` on `PATH`, and uses the
first one that passes `bin/callgraph --probe`. The audit's `index.log` records
the outcome: `Source call-graph context: enabled via ...`, or a `WARN` that it
is unavailable.

The graph is context for an agent, never proof of reachability and never a
filter. Indirect calls, callback tables, function pointers, and
macro-generated names are invisible to the parser, so a missing edge is never
grounds to discard a card. Perl and R have no trailmark grammar, and trees
with more than 5,000 auditable files are skipped. The audited target is
untrusted input, so any `.trailmark/` configuration inside it is ignored: the
parser reads a mirror holding only the auditable source files.

To see the block one file would carry:

```bash
python3 lib/callgraph.py --target <target> <target-relative-file>
```

The graph is stored at `<results>/state/callgraph.json` and never enters a
prompt; it also gives [coverage receipts](../concepts/coverage.md) each
function's line range. `bin/rank-work` caches it, and any failure, per
revision of the source, build, and parser, so delete the file only to force a
rebuild.

??? note "How calls and the entry boundary are resolved"
    A call resolves when trailmark matches it to a definition, or when its
    qualifier names exactly one parsed module, class, or other container that
    holds the function (`reportkit.parse_config(...)`, `SliceRead::new(...)`).
    `self`, `this`, `super`, a typed parameter, and a Go package name resolve
    to their container. A receiver that matches no unique callee stays
    unresolved rather than guessed. This is structural context, not name
    resolution: a local variable spelled like a container can still bind to
    it.

    The entry boundary comes from the sanitizer build's symbol table,
    demangled for C++ and Rust, and a symbol counts only where the parser saw
    a same-named definition in the same namespace, class, or module. If the
    parser saw less than 75% of the built target's own symbols, TokenFuzz
    omits the boundary and routes rather than present a partial map; the
    neighbour lists still appear.

    Without a build (a findings-only target), the boundary is the entry
    points trailmark detects plus definitions that are public together with
    every enclosing type: `pub`, Java `public`, `export`, a capitalised Go
    name, and the equivalents in other parsed languages. C, C++, and Ruby
    declare visibility away from the definition, so without a build they get
    detected entry points only.
