# Add a Target

Adding a target means giving the harness three things:

- source code under `targets/<target>/`;
- sanitizer artifacts built from that source (C/C++ only);
- a `output/<target>/target.toml` that describes how to run and triage
  the target.

Once those are in place, TokenFuzz can build a ranked work queue,
launch agents, and write all audit evidence under
`output/<target>/<backend>/results/`.

## What makes a good first target

Pick something with:

- a source checkout you are authorised to audit;
- a reproducible default ASan build;
- a command-line binary or public C API the harness can drive;
- existing tests, samples, or corpus files that agents can mutate;
- a clear external input boundary — bytes, protocol state, script
  calls, filesystem state;
- enough source structure for the ranker to find real implementation
  files (not just tests, generated code, or build glue).

Get one target clean and finishing healthy runs before adding more.

## 1. Sync the source

Create or update the checkout and seed the config:

```bash
bin/setup-target <target> <repo-url>
```

A few real examples:

```bash
bin/setup-target libxml2 https://gitlab.gnome.org/GNOME/libxml2.git
bin/setup-target zlib    https://github.com/madler/zlib.git
bin/setup-target firefox https://hg.mozilla.org/mozilla-unified --repo-type hg
bin/setup-target samples/sample-python /path/to/local/source
```

`<target>` may include path components. For example,
`samples/sample-python` creates `targets/samples/sample-python/` and
`output/samples/sample-python/target.toml`.

Three useful variants:

```bash
bin/setup-target <target>                                   # re-inspect existing checkout
bin/setup-target <target> <repo-url> --ref <branch-or-rev>  # clone + pin to a revision
bin/setup-target <target> --ref <branch-or-rev>             # switch the existing checkout
bin/setup-target <target> /path/to/local/source            # use a local source directory
```

Notes:

- The source argument can be a local directory instead of a URL. A local
  git/hg checkout is cloned as usual. A plain directory with no VCS
  metadata is symlinked into `targets/<target>/` (never copied, pulled, or
  fetched) and audited in place as a local-only "no VCS" target — its
  `target.toml` records `upstream_url = "FILL_ME"` and `pinned_rev =
  "norev"`, and the generated `reproduce.sh` asks for a checkout path
  instead of trying to clone.
- If a checkout already exists under `targets/<target>/`, the no-URL
  form normally seeds or refreshes the generated config without touching
  source. It can still force a build when it detects stale ABI-tagged
  extension modules.
- Re-running `setup-target` refreshes generated config fields from the
  current checkout and build outputs. (`--no-llm-config` skips the
  LLM-backed threat-model and peer suggestions if you must stay
  offline.)
- The full list of advanced flags is in
  [Commands](../reference/commands.md). The normal setup flow does not
  need them.

## 2. The build happens automatically

You do not run a separate build step. `bin/audit` builds the target on
its first run and rebuilds it whenever the source changes, so a checkout
you just pulled is never audited against an older binary. The build is
**fail-open**: if it cannot run or does not converge, the audit warns and
continues rather than blocking.

What that build does depends on the detected `build_system`:

- **C/C++ (`cmake` / `autotools` / `meson`)** — `bin/auto-build-script`
  iterates on a vanilla ASan recipe until it produces a working build,
  then writes the validated script to `targets/<target>/.audit/build.sh`.
  `bin/export-repro` inlines that script verbatim into every
  `reproduce.sh`, so maintainers get the same build the audit used. If
  `[sanitizer].enabled` lists more than ASan, each extra sanitizer gets
  its own `.audit/build-<san>.sh` and `build-<san>/` tree — ASan is
  required, the others are best-effort and only warn on failure.
- **Python / Node / PHP / Ruby / Rust / Go / Swift** — runs the
  language's native install step (`setup.py build_ext --inplace`,
  `npm install`, `composer install`, `bundle install`, `cargo build`,
  `go build ./...`, `swift build`). Required when the runner will
  `import` (or `require`, …) something the source tree builds or
  downloads.
- **Anything else (Java, Kotlin, Perl, R, Shell, …)** — no-op.

UBSan, MSan, and TSan are optional add-ons enabled later through
`target.toml`'s `[sanitizer]` block.

### Building up front (optional)

If you would rather pay the build cost at setup time — for example to
verify the target compiles before launching a long audit — run:

```bash
bin/setup-target <target> --build
```

This does the same build `bin/audit` would, now instead of at audit
time. It skips silently when its inputs aren't present (no LLM backend,
no manifest, no recognised build system, recipe already current). It is
never required.

### Targets with no sanitizer build

Pure-Python / pure-Ruby / pure-JS scripts with no native extensions or
vendored dependencies, and non-C/C++ targets where you are happy to
run testcases through the language's own interpreter without a
sanitizer build. `bin/setup-target` writes a runner-only config
(`[sanitizer] enabled = []`) for those — diagnostics land under
`findings/` instead of `crashes/`. See
[Auditing non-C/C++ targets](../guides/multi-language.md) for the
per-language matrix.

### Inside `bin/audit-container-shell`

The container helper sets `AUDIT_BUILD_SUFFIX` so build directories
are isolated per image (`build-asan-<image-id>/`). Harness path
resolution applies it to relative `build-asan/`, `build-ubsan/`,
`build-msan/`, and `build-tsan/` paths automatically; outside the
container the suffix is empty.

### Writing the build recipe by hand

`auto-build-script` is the supported path. If you need to override —
no LLM backend available, exotic build system, in-tree patches — drop
a shell script with the contract `argv = <src> <build>` at
`targets/<target>/.audit/build.sh` and `bin/export-repro` will inline
it the same way.

## 3. Refresh and review the generated config

With the ASan build in place, ask the harness to look again:

```bash
bin/setup-target <target>
```

This re-inspects `build-asan${AUDIT_BUILD_SUFFIX:-}/` and updates
`output/<target>/target.toml` when generated placeholders remain.
Then open the file and edit only:

- placeholder values such as `FILL_ME`;
- artifact paths the generator guessed incorrectly;
- target-specific `defines`;
- target-specific `link_libs`;
- `attacker_controls`, when the default input boundary is too narrow
  or too broad. Valid tokens are `bytes`, `call-sequence`, `timing`,
  `race`, `env`, `protocol-state`, and `fs-state` (see
  [`lib/target_config.sh`](https://github.com/tokenfuzz/tokenfuzz/blob/main/lib/target_config.sh) / [`lib/target_config.py`](https://github.com/tokenfuzz/tokenfuzz/blob/main/lib/target_config.py)).

For the review checklist, see
[Configure a target](../guides/configure-target.md). For complete
field definitions, see
[Target config reference](../reference/target-toml.md).

### Where the agent guide lives

When `bin/audit` launches an agent, it injects the long-form guide
[`AGENTS.md`](https://github.com/tokenfuzz/tokenfuzz/blob/main/AGENTS.md) into the prompt. The same guide covers browser and generic
targets — it describes the testcase format, strategy priority, and
crash quality bar that the agent is expected to follow. If you want to
tune agent behaviour for your target, that file is the right place to
look first — it is read at audit start and embedded into every agent
prompt.

## 4. Validate before long runs

Run one iteration:

```bash
bin/audit --target <target> --backend <backend> 1
```

Both `bin/setup-target` and `bin/audit` validate `target.toml`
themselves. If startup succeeds, you should see:

```text
output/<target>/<backend>/results/.session-env
output/<target>/<backend>/results/
output/<target>/<backend>/logs/
```

Also check that the first run produced `work-cards.jsonl` and
`state/`. Those two files show whether the target is schedulable, even
when the bounded run did not make it as far as a crash.

## 5. Keep it updated

To refresh source while preserving configuration:

```bash
bin/setup-target <target> <repo-url>
bin/audit --target <target> --backend <backend> 1
```

If ASan paths change after an upstream update, run
`bin/setup-target <target>` again after rebuilding, then review only
the affected artifact fields. Reviewed config is preserved unless
generated placeholders remain.

## Ready checklist

A target is ready when:

- `targets/<target>/` is a Git or Mercurial checkout, or a symlink to a
  local source tree;
- the default ASan artifacts exist and start cleanly outside the
  harness;
- `output/<target>/target.toml` exists. `bin/audit --target <target>`
  creates it if it is missing. `bin/setup-target` can refresh it from
  source;
- the fields you actually need have no placeholder values;
- `asan_bin` is correct for CLI or browser runs;
- `asan_lib`, `includes`, `defines`, and `link_libs` are correct if
  ASan C harnesses will be used. UBSan / MSan / TSan harnesses use
  their own optional `[sanitizer].*_lib` entries;
- `is_browser` matches the target's execution model;
- `attacker_controls` matches the real external input boundary;
- `bin/audit --target <target> --backend <backend> 1` finishes
  startup and writes state under
  `output/<target>/<backend>/results/`;
- `work-cards.jsonl` exists and points at implementation files worth
  auditing;
- `findings/` and `crashes/` both exist — either may be empty after a
  smoke run.
