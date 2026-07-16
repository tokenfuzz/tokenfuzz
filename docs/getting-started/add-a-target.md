# Add a Target

Adding a target gives the harness three things:

- source code under `targets/<target>/`;
- an executable test path: sanitizer artifacts or a language runner;
- an `output/<target>/target.toml` that describes how to run and triage
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

## 2. Establish the build or runner

Build behavior depends on the target:

- **Native C/C++ sanitizer targets.** On audit startup, TokenFuzz checks the
  configured non-browser sanitizer trees. If one is missing or stale,
  `bin/audit` calls `bin/setup-target --build` to converge and run a reusable
  recipe under `targets/<target>/.audit/`. Failure is visible in the log but
  fail-open: source analysis can continue while sanitizer-dependent work is
  unavailable. The canonical `build-asan` remains the regular-configuration
  control. By default, setup also prepares one cached widened ASan sibling when
  the project advertises compatible optional in-tree features. One minority
  reproducer slot explores ready alternates while another stays on the control.
- **Rust, Go, Swift, Python, Node, PHP, Ruby, and other registered language
  builds.** Run `bin/setup-target <target> --build` when the runner depends on
  compiled code or installed packages. Audit preflight does not automatically
  run these ecosystem bootstrap commands. Such a target opts into a sanitizer
  build by shipping a committed `targets/<target>/.audit/build.sh` that emits an
  instrumented binary into `build-<san>/`; `--build` materializes it alongside
  the ecosystem bootstrap (the `samples/sample-rust` and
  `samples/sample-python-native` benchmark targets do this for an ASan build, and
  `samples/sample-go` enables the race detector through its `go build -race`
  bootstrap).
- **Browser targets.** Build through the browser project's supported tooling,
  then point `target.toml` at the result. The generic native auto-builder does
  not build browsers.
- **Findings-only scripts.** No build is needed when the configured interpreter
  can execute the testcase directly and the target has no dependencies to
  install.

For a native build, the generated `.audit/build.sh` (and
`.audit/build-<san>.sh` for enabled secondary sanitizers) is also reused by
`bin/export-repro` when it creates a maintainer bundle.

### Building up front (optional)

If you would rather pay the build cost at setup time — for example to
verify the target compiles before launching a long audit — run:

```bash
bin/setup-target <target> --build
```

For native targets, this performs the same refresh audit preflight would do.
That includes configured ASan alternates, so initial setup can take one or more
additional builds; later runs reuse them until the source or exact recipe
changes. Set `build_widening = false` in `target.toml` if widening is unsuitable.
For registered non-native build systems, it runs the language bootstrap plan.
It skips when there is no applicable manifest or build plan.

### Targets with no sanitizer build

Pure-Python / pure-Ruby / pure-JS scripts with no native extensions or
vendored dependencies, and other targets that run testcases through a language
runtime without sanitizer instrumentation, need no sanitizer build.
`bin/setup-target` writes a runner-only config
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

`auto-build-script` is the supported path for ordinary native projects. If you
need to override it—an exotic build system or required local patches—drop
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
  [`lib/target_config.py`](https://github.com/tokenfuzz/tokenfuzz/blob/main/lib/target_config.py)).

For the review checklist, see
[Configure a target](../guides/configure-target.md). For complete
field definitions, see
[Target config reference](../reference/target-toml.md).

### The shared agent contract

When `bin/audit` launches an agent, it injects the shared runtime guide
[`AGENTS.md`](https://github.com/tokenfuzz/tokenfuzz/blob/main/AGENTS.md).
It defines testcase headers, evidence requirements, strategy discipline, and
the crash quality bar for every target. Target-specific choices belong in
`target.toml` or the target source/build—not in the shared guide. Change
`AGENTS.md` only when changing the audit contract for all targets.

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
