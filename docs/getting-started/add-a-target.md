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
  current checkout and build outputs. Use `--no-llm-config` when you
  want to skip the best-effort threat-model and S6 lookalike project suggestions.
- The full list of advanced flags is in
  [Commands](../reference/commands.md). The normal setup flow does not
  need them.

## 2. Build a sanitizer artifact (required for C/C++)

If your target is C or C++, this step is mandatory for sanitizer
crash evidence. Native targets default to ASan; without a configured
sanitizer binary or runner, probes will fail setup rather than
silently becoming findings-only. Non-C/C++ projects (Python, Ruby,
Go, Node, Java, PHP, …) can genuinely skip it — jump to the
[next section](#non-cc-targets-skip-the-sanitizer-build).

ASan is the preferred default — it gives the clearest crash evidence
for prioritisation. UBSan, MSan, and TSan are optional add-ons you can
enable later through `target.toml`'s `[sanitizer]` block.

Build the target with its native build system. Keep the artifacts in a
stable location — usually:

```text
targets/<target>/build-asan/
```

When you work inside `bin/audit-container-shell`, the helper sets
`AUDIT_BUILD_SUFFIX` so sanitizer build directories are isolated per
container image, for example `build-asan-<image-id>/`. Harness path
resolution applies that suffix to relative `build-asan/`,
`build-ubsan/`, `build-msan/`, and `build-tsan/` paths; outside the
container the suffix is empty.

The exact build command belongs to the target project, not the
harness. A minimal sanitizer flag set for any C/C++ build:

```bash
export CFLAGS="-fsanitize=address -g -O1 -fno-omit-frame-pointer"
export LDFLAGS="-fsanitize=address"
```

For a CMake-based project, that looks like:

```bash
build_dir="targets/<target>/build-asan${AUDIT_BUILD_SUFFIX:-}"
cmake -S "targets/<target>" -B "$build_dir" \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER=clang \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_C_FLAGS="$CFLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$LDFLAGS"
jobs="$(getconf _NPROCESSORS_ONLN 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 1)"
cmake --build "$build_dir" -j"$jobs"
```

For Meson, autotools, mach, or other systems, follow the upstream docs
and inject the sanitizer flags through whatever variable that build
system exposes. For browser-specific layouts, see
[Browser targets](../guides/browser-targets.md).

After the build finishes, the config generator looks under
`build-asan${AUDIT_BUILD_SUFFIX:-}/` for the usual artifacts:

- an executable for `asan_bin`;
- a static library for `asan_lib` (when C harnesses are useful);
- source and generated include directories;
- compiler define flags needed by small harness programs;
- linker flags required by small harness programs.

### Non-C/C++ targets — skip the sanitizer build

For Python, Ruby, Go, Node, Java, PHP, and similar projects,
`bin/setup-target` automatically writes:

- `[sanitizer] enabled = []`;
- a starter `[runner]` block keyed on the detected build system.

The harness runs testcases through the language's interpreter or
driver. Diagnostics land under `findings/` instead of `crashes/`.

You do **not** need a `build-asan/` directory for those targets. See
[Auditing non-C/C++ targets](../guides/multi-language.md) for the full
per-language matrix and `target.toml` examples.

#### Building native extensions or vendored deps with `--bootstrap`

Pure-Python (or pure-Ruby / pure-JS) targets need no build step. But
some projects ship native extensions or vendored dependencies that
must be built or installed before any code runs — PyYAML's `_yaml.so`,
Node modules under `node_modules/`, PHP packages under `vendor/`,
native gems. For those, run the optional language bootstrap:

```bash
bin/setup-target <target> --bootstrap
```

**Rule of thumb:** if your runner is going to `import` (or `require`,
`use`, …) something the source tree builds or downloads, you need
`--bootstrap`. If it just executes a script directly with no native or
vendored deps, you do not.

The action is chosen from the manifest in the checkout:

| `build_system` | Manifest gate | When you need it |
| --- | --- | --- |
| `python`   | `setup.py`      | **Required** when the project ships a C extension. |
| `npm`      | `package.json`  | **Required** when the project imports from `node_modules/`. |
| `composer` | `composer.json` | **Required** when the project autoloads from `vendor/`. |
| `bundler`  | `Gemfile`       | **Required** when the project depends on bundled gems. |
| `cargo` / `go` / `swift` | `Cargo.toml` / `go.mod` / `Package.swift` | Optional — primes the build cache and surfaces compile errors early. |

Bootstrap is opt-in and safe to pass on any target: if the gating
manifest is absent, or the language has no registered step (C/C++,
Java, Kotlin, Perl, R, Shell), it skips silently. C/C++ targets build
`build-asan${AUDIT_BUILD_SUFFIX:-}/` separately with the [sanitizer step
above](#2-build-a-sanitizer-artifact-required-for-cc).
One exception is automatic repair for stale Python extension builds:
if `bin/setup-target` sees `*.cpython-<tag>-*.so` files for a
different Python ABI, it forces the Python bootstrap so later probes
do not all fail on an ABI mismatch.

You can still wire in a sanitizer build later (Go's `-race`, Rust's
nightly `-Z sanitizer=address`, Swift's `-sanitize=address`, …) by
editing `[sanitizer].enabled` and pointing the matching `<name>_bin`
at the instrumented build.

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
