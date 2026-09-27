# Add a target

To audit your own project, give TokenFuzz its source, prove it can build or
run the project, review the generated configuration, and run one iteration:

```bash
bin/setup-target <target> <repo-url> --build
bin/audit --target <target> --backend <backend> 1
```

A target has three parts:

```text
targets/<target>/                   source checkout and build artifacts
output/<target>/target.toml         reviewed execution and threat-model config
output/<target>/<backend>/results/  evidence produced by an audit
```

The [command reference](../reference/commands.md#set-up-a-target) lists every
`bin/setup-target` flag, and the
[target config reference](../reference/target-toml.md) every `target.toml`
field.

## Choose a useful target

A good first real target has:

- a source tree you are authorised to audit;
- a documented file, byte, protocol, CLI, or public-API boundary;
- a reproducible build or interpreter route;
- tests, sample files, or corpus inputs agents can mutate;
- enough implementation source for the ranker to work with.

If you are still validating the installation, run a
[sample target](sample-targets.md) first. That keeps TokenFuzz setup separate
from the project-specific work of making a build reproducible.

## 1. Add the source

```bash
bin/setup-target <target> <repo-url>                         # Git repository
bin/setup-target <target> <repo-url> --ref <branch-or-rev>   # branch, tag, or revision
bin/setup-target <target> <hg-url> --repo-type hg            # Mercurial (hg.mozilla.org is detected)
bin/setup-target <target> /path/to/local/source              # local checkout or directory
bin/setup-target <target> --pull                             # update an existing checkout
```

The target slug may contain path components: `samples/sample-python` maps to
`targets/samples/sample-python/` and `output/samples/sample-python/target.toml`.
Each component may use only letters, digits, `.`, `_`, and `-`, may not start
with a dot, and may not be `output` or `benchmark`.

A local Git or Mercurial tree is cloned into `targets/`. A plain directory is
symlinked and audited in place; it is never copied, pulled, or fetched. Its
config keeps `upstream_url = "FILL_ME"`, and exported reproducers ask the
maintainer for a checkout path instead of inventing a clone URL.

Running `bin/setup-target <target>` again with no source re-inspects the
checkout without fetching. Passing the URL or `--ref` again, or `--pull`,
updates it unless you add `--no-update`; a checkout with tracked local
changes is never updated. With `--build`, a Git checkout's submodules are
initialised as well.

A re-run keeps a reviewed `target.toml`. `--no-llm-config` skips the model's
threat-model, peer, and runner suggestions and recipe repair; it does not make
checkout or dependency installation offline. Read
[When setup rewrites the file](../reference/target-toml.md#when-setup-rewrites-the-file)
before you pass `--force`, which regenerates the configuration.

### Chromium and Chrome checkouts

Chromium uses the upstream `depot_tools` and `gclient` layout. Put
`depot_tools` on `PATH`, then:

```bash
bin/setup-target chromium --build
```

The bundled overlay fetches a gclient workspace into `targets/chromium/`,
selects browser mode, and registers the `src` checkout as the target
`chromium/src`. `chrome` is an alias for the same overlay. A target you
already configured at `output/chromium/target.toml` keeps its existing
identity. On macOS the build needs Xcode with the Metal toolchain.

Chromium probes run with `--no-sandbox`, so the audit's own isolation is the
boundary, and have no `bin/hits` coverage route yet; see
[Browser targets](../guides/browser-targets.md).

## 2. Establish an execution route

What to do next depends on the target:

| Target shape | What to do |
| --- | --- |
| Native C/C++ (CMake, Meson, autotools) | Nothing up front. Audit preflight builds each enabled sanitizer tree from a generated recipe, plus `build-asan+cov` for probe HIT/MISSED feedback and, when the build publishes a library, `build-asan+fuzz` for libFuzzer. Run `--build` now to prove the build before you spend model time. |
| Rust, Go, Swift, a Python extension, or another registered language | Run `bin/setup-target <target> --build` whenever the runner needs compiled code, installed packages, or a primed toolchain cache. Audit preflight repeats it only for a target with a `.audit/build.sh` recipe; otherwise re-run it after the source changes. |
| Findings-only script or managed runtime | No sanitizer build. Setup writes `[sanitizer] enabled = []` and a language runner when it can identify one. |
| Browser | A `mach` tree is detected as a browser. Pass `--browser` for GN, which also builds non-browser programs. Other browser build systems need a reusable `.audit/build.sh`. |

The normal up-front check:

```bash
bin/setup-target <target> --build
```

`--build` fails when the requested build cannot be produced, or when a newly
seeded config ends up with no runner, sanitizer binary, or sanitizer library
to execute. It also checks that a seeded language runner reaches the
checkout.

For a custom native build, put a reusable script at
`targets/<target>/.audit/build.sh`, called as
`build.sh <source-root> <build-directory>`. `bin/auto-build-script` generates
this recipe for ordinary native projects. Exported crash bundles embed it, so
it must work from a clean build directory with documented dependencies.

### What native builds guarantee

When setup or audit preflight builds a native tree, it:

- builds into a clean `build-<sanitizer>` directory, and restores the
  previous tree if the new build fails or its binary dies in the dynamic
  loader;
- after a failed clean build, asks the model backend to repair the recipe (up
  to three candidate builds per backend), and installs a repair only after it
  builds and starts;
- rebuilds when the source content or the recipe changes;
- keeps `build-asan` as the control and, for compatible CMake, Meson, and
  autotools targets, adds one widened ASan sibling with optional in-tree
  features enabled (`build_widening = false` skips it).

A failed build is loud but does not stop the audit; source review still runs.

Inside `bin/audit-container-shell`, build directories get an image-specific
suffix (for example `build-asan-<image-id>`) through `AUDIT_BUILD_SUFFIX`, so
host and container builds do not overwrite each other. Do not set that value
yourself.

## 3. Review `target.toml`

If you built outside `bin/setup-target`, run `bin/setup-target <target>` once
without `--build` so it detects the new artifacts. Then open
`output/<target>/target.toml` and check:

1. `asan_bin`, or `[runner].bin` and `args`, starts the intended product.
2. `asan_lib`, `includes`, `defines`, and `link_libs` are correct, if agents
   will compile API harnesses.
3. `is_browser` matches the execution model.
4. `[sanitizer].enabled` lists only diagnostics the target can really emit.
5. `[threat_model].attacker_controls` describes the external boundary,
   without widening it to cover a harness-only action.
6. `upstream_url` and `build_system` are useful enough for a maintainer
   bundle.

[Target configuration](../guides/configure-target.md) explains each decision,
including the [threat-model boundary test](../guides/configure-target.md#review-the-threat-model).

Target-specific paths, build flags, and threat-model choices belong in
`target.toml` or a target overlay, not in the root
[`AGENTS.md`](https://github.com/tokenfuzz/tokenfuzz/blob/main/AGENTS.md),
which is the shared runtime contract for every audit agent.

## 4. Run one iteration

```bash
bin/audit --target <target> --backend <backend> 1
```

After preflight, the audit pins the configuration for the whole session in
`output/<target>/<backend>/results/.target.toml` and `.session-env`. Never
edit either file. Change `output/<target>/target.toml` between runs; the next
invocation pins the new version.

Continue with [First audit](first-audit.md) to check and inspect the run.

## Ready checklist

The target is ready for a longer run when:

- the source tree is the project and revision you intended;
- the configured sanitizer binary or language runner starts outside the
  audit, and a runner canary, where supported, shows that imports resolve
  inside `targets/<target>/` rather than to an installed copy;
- enabled sanitizer artifacts match their configured routes, and harness
  fields are correct for any compiled harnesses you expect;
- the threat model matches the real external boundary;
- one audit iteration writes state and work cards without a preflight error.

An empty result lane is not a setup failure. A missing work queue, an
unusable runner, or a failed preflight is.
