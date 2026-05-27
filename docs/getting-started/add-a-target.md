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
```

Three useful variants:

```bash
bin/setup-target <target>                                   # re-inspect existing checkout
bin/setup-target <target> <repo-url> --ref <branch-or-rev>  # clone + pin to a revision
bin/setup-target <target> --ref <branch-or-rev>             # switch the existing checkout
```

Notes:

- If a checkout already exists under `targets/<target>/`, the no-URL
  form normally seeds or refreshes the generated config without touching
  source. It can still force the Python bootstrap when it detects stale
  ABI-tagged extension modules.
- Re-running `setup-target` refreshes generated config fields from the
  current checkout and build outputs. `--no-llm-config` skips the
  best-effort threat-model and S6 lookalike project suggestions; not
  recommended unless you have a specific reason to stay offline.
- The full list of advanced flags is in
  [Commands](../reference/commands.md). The normal setup flow does not
  need them.

## 2. Bootstrap the build

Run once per target:

```bash
bin/setup-target <target> --bootstrap
```

`--bootstrap` does whatever the detected `build_system` needs:

- **C/C++ (`cmake` / `autotools` / `meson`)** — `bin/auto-build-script`
  iterates on a vanilla ASan recipe until it produces a working build,
  then writes the validated script to `targets/<target>/.audit/build.sh`.
  `bin/export-repro` inlines that script verbatim into every
  `reproduce.sh`, so maintainers get the same build the audit used.
- **Python / Node / PHP / Ruby / Rust / Go / Swift** — runs the
  language's native install step (`setup.py build_ext --inplace`,
  `npm install`, `composer install`, `bundle install`, `cargo build`,
  `go build ./...`, `swift build`). Required when the runner will
  `import` (or `require`, …) something the source tree builds or
  downloads.
- **Anything else (Java, Kotlin, Perl, R, Shell, …)** — no-op.

Skips silently when its inputs aren't present (no LLM backend, no
manifest, no recognised build system, recipe already exists). Safe to
pass on any target.

UBSan, MSan, and TSan are optional add-ons enabled later through
`target.toml`'s `[sanitizer]` block.

### When you do not need `--bootstrap`

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
  `lib/target_config.sh` / `lib/target_config.py`).

For the review checklist, see
[Configure a target](../guides/configure-target.md). For complete
field definitions, see
[Target config reference](../reference/target-toml.md).

### Where the agent guide lives

When `bin/audit` launches an agent, it injects the long-form guide
`AGENTS.md` into the prompt. The same guide covers browser and generic
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

- `targets/<target>/` is a Git or Mercurial checkout;
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
