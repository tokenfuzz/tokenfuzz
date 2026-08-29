# Add a Target

A TokenFuzz target has three parts:

```text
targets/<target>/                   source checkout and build artifacts
output/<target>/target.toml         reviewed execution and threat-model config
output/<target>/<backend>/results/  evidence produced by an audit
```

This guide gets those pieces to a one-iteration smoke test. The
[target config schema](../reference/target-toml.md) documents every field;
the [configuration guide](../guides/configure-target.md) explains the review
decisions.

## Choose a useful target

A good first real target has:

- a source tree you are authorised to audit;
- a documented file, byte, protocol, CLI, or public-API boundary;
- a reproducible build or interpreter route;
- tests, sample files, or corpus inputs agents can mutate;
- enough implementation source for the ranker to work with.

If you are still validating the installation, use a
[sample target](sample-targets.md) first. It separates TokenFuzz setup from the
project-specific work of making a build reproducible.

## 1. Add or inspect the source

For a remote Git repository:

```bash
bin/setup-target <target> <repo-url>
```

The target slug may contain path components. For example,
`samples/sample-python` maps to `targets/samples/sample-python/` and
`output/samples/sample-python/target.toml`.

Other supported source forms:

```bash
# Pin a Git or Mercurial checkout.
bin/setup-target <target> <repo-url> --ref <branch-or-revision>

# Re-inspect an existing checkout without fetching it.
bin/setup-target <target> --no-update

# Update an existing VCS checkout without repeating its URL.
bin/setup-target <target> --pull

# Use a local checkout or plain source directory.
bin/setup-target <target> /path/to/local/source
```

A local Git or Mercurial tree is cloned into `targets/`. A plain directory is
symlinked and audited in place; it is never copied, pulled, or fetched. Its
generated config keeps `upstream_url = "FILL_ME"`, and exported reproducers ask
the maintainer for a checkout path instead of inventing a clone URL.

Re-running `bin/setup-target` preserves reviewed values unless generated
placeholders remain. `--no-llm-config` skips the best-effort threat-model and
peer suggestions when setup must stay offline. See the
[command reference](../reference/commands.md#set-up-a-target) before using
`--force`, because its behavior intentionally differs with and without
`--build`.

### Chromium and Chrome checkouts

Chromium-family checkouts use the upstream `depot_tools` and `gclient` layout.
Put `depot_tools` on `PATH` before the first setup:

```bash
bin/setup-target chromium --browser --build
```

The helper creates `targets/chromium/src` and registers the effective nested
target as `chromium/src`. An ordinary target already configured at
`output/chromium/target.toml` keeps its existing identity.

Chromium probes enable stderr logging, use a temporary profile, and pass
`--no-sandbox` so child sanitizer logs remain writable inside the audit's own
isolation boundary. On macOS they also use the mock Keychain. Chromium does not
currently have a `bin/hits` coverage-gating route; its probes run the sanitizer
directly.

## 2. Establish an execution route

What happens next depends on the target:

| Target shape | What to do |
| --- | --- |
| Ordinary native C/C++ | Nothing is required up front. Audit preflight refreshes missing or stale enabled sanitizer builds. Use `bin/setup-target <target> --build` when you want to prove the build before launching a model. |
| Rust, Go, Swift, Python extensions, or another registered ecosystem build | Run `bin/setup-target <target> --build` when the runner needs compiled code, installed packages, or a primed toolchain cache. Audit preflight does not run these ecosystem bootstraps automatically. |
| Findings-only script or managed runtime | No sanitizer build is needed. Setup writes `[sanitizer] enabled = []` and a language runner when it can identify one. |
| Browser | `mach` is detected as browser-specific. Pass `--browser` for GN, which also builds non-browser programs. Other browser build systems need a reusable `.audit/build.sh`. |

The normal up-front check is:

```bash
bin/setup-target <target> --build
```

For a custom native build, put a reusable script at
`targets/<target>/.audit/build.sh`. Its argument contract is:

```text
build.sh <source-root> <build-directory>
```

`bin/auto-build-script` is the supported generator for ordinary native
projects. The same recipe is later embedded into exported crash bundles, so it
must converge from a clean build directory rather than depend on unstated host
state.

### What native auto-build guarantees

The native builder:

- refreshes into a clean canonical build directory and restores the previous
  tree if the replacement fails;
- treats a binary that dies in the dynamic loader as a failed build;
- may revise a broken generated recipe up to three times, installing only a
  revision that builds and starts;
- invalidates freshness when source content or the recipe changes;
- keeps the canonical `build-asan` as the control and, by default, prepares one
  compatible widened ASan sibling for optional in-tree features.

A failed build is loud but does not erase source-review work. Disable alternate
build exploration with `build_widening = false` in `target.toml` when it is not
appropriate for the project.

Inside `bin/audit-container-shell`, relative `build-asan/`, `build-ubsan/`,
`build-msan/`, and `build-tsan/` paths resolve to image-specific directories
through `AUDIT_BUILD_SUFFIX`. Do not set that internal value yourself.

## 3. Review `target.toml`

After the build or runner exists, refresh detection once:

```bash
bin/setup-target <target>
```

Open `output/<target>/target.toml` and verify:

1. `asan_bin`, or `[runner].bin` and `args`, starts the intended product.
2. `asan_lib`, `includes`, `defines`, and `link_libs` are correct if agents
   will compile API harnesses.
3. `is_browser` matches the execution model.
4. `[sanitizer].enabled` describes the diagnostics the target can really emit.
5. `[threat_model].attacker_controls` describes the external boundary without
   widening it to accommodate a harness-only action.
6. `upstream_url` and `build_system` are useful enough for a maintainer bundle.

Valid attacker-control tokens are `bytes`, `call-sequence`, `timing`, `race`,
`protocol-state`, `env`, and `fs-state`. The
[configuration guide](../guides/configure-target.md#review-the-threat-model)
has examples and the boundary test to apply.

The root [`AGENTS.md`](https://github.com/tokenfuzz/tokenfuzz/blob/main/AGENTS.md)
is the shared runtime contract for every audit agent. Target-specific paths,
build flags, and threat-model choices belong in `target.toml` or a target
overlay, not in that global file.

## 4. Run one iteration

```bash
bin/audit --target <target> --backend <backend> 1
```

Startup validates the target and pins the post-preflight config to:

```text
output/<target>/<backend>/results/.target.toml
output/<target>/<backend>/results/.session-env
```

Do not edit either file during the session. Change the shared
`output/<target>/target.toml` between runs; the next invocation will pin the new
version.

A schedulable smoke test creates `work-cards.jsonl`, `state/`, the result lanes,
and a per-agent scratch directory even if it finds nothing. Continue with
[First audit](first-audit.md) to inspect them.

## Ready checklist

The target is ready for a longer run when:

- the source tree resolves to the project and revision you intended;
- the configured sanitizer binary or language runner starts outside the audit;
- a runner canary, when supported, proves imports resolve inside
  `targets/<target>/` rather than to an installed copy;
- enabled sanitizer artifacts match their configured routes;
- public-API harness fields are correct for any compiled harnesses you expect;
- the threat model matches the real external boundary;
- one audit iteration writes state and work cards without a preflight error.

An empty result lane is not a setup failure. A missing work queue, unusable
runner, or failed preflight is.
