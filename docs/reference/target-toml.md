# Target Config Reference

Each target has one static configuration file:

```text
output/<target>/target.toml
```

Create or refresh it with:

```bash
bin/setup-target <target> <repo-url>
bin/setup-target <target>
```

`bin/audit --target <target>` also creates this file when it is
missing. Runtime values such as `RESULTS_DIR` and `TARGET_REV` are
written separately to `.session-env`.

Treat `target.toml` as **generated config plus a small review
layer.** The tooling infers:

- source metadata;
- build system;
- browser mode for known browser slugs;
- common ASan executables;
- common static libraries;
- default include paths;
- default sanitizer policy;
- default threat model controls.

Your job is to edit only values that remain unresolved or are
wrong for this target.

The config is also part of triage:

- `attacker_controls` is read when deciding whether a crash
  trigger is a legitimate product input.
- Reproduction export uses the repository URL, revision, build
  fields, and sanitizer paths to build a clean maintainer bundle.

## A complete generic example

```toml
target       = "libxml2"
upstream_url = "https://gitlab.gnome.org/GNOME/libxml2.git"
build_system = "cmake"
pinned_rev   = "HEAD"

asan_bin     = "build-asan/xmllint"
asan_lib     = "build-asan/libxml2.a"
includes     = ["include", "build-asan/include"]
defines      = []
link_libs    = ["-lz", "-llzma", "-lm"]

is_browser   = "0"

reachability_ignore = ["GNOME/libxml2"]

[threat_model]
attacker_controls = ["bytes"]
```

## Generated fields to review

| Field | Meaning |
| --- | --- |
| `target` | Target slug. It should match `targets/<target>` and `output/<target>`. |
| `upstream_url` | Source repository URL used as metadata in exported bundles. |
| `build_system` | Informational build-system label such as `cmake`, `meson`, `autotools`, or `mach`. |
| `pinned_rev` | Revision recorded when the config was created. The live revision is captured at audit startup. |
| `asan_bin` | ASan executable used by generic or browser runs. Relative paths resolve under `targets/<target>/`. |
| `asan_lib` | ASan library used when compiling C harness testcases. |
| `includes` | Include directories for C harness builds. Relative paths resolve under `targets/<target>/`. |
| `defines` | Compiler define flags for C/C++ harness builds, such as `-DFOO=1`. |
| `link_libs` | Extra linker flags for C harness builds. |
| `is_browser` | `"1"` for browser mode, `"0"` for generic mode. |

Which fields you need depends on what the run will do:

- A generic CLI audit needs `asan_bin`.
- C harness testcases also need the selected sanitizer's library,
  `includes`, `defines`, and `link_libs`.
- ASan uses top-level `asan_lib`. UBSan / MSan / TSan harnesses
  use `[sanitizer].ubsan_lib`, `msan_lib`, or `tsan_lib`.

If only the executable path is correct, a CLI-first audit can
still run. Leave the C harness fields unresolved until you
actually need public API harnesses.

### Header-only libraries

Some C++ libraries ship only headers — no static archive to link
against.

- Leave `asan_lib` as the generated `FILL_ME` comment placeholder,
  or set it to an empty string.
- `bin/export-repro` will emit a `reproduce.sh` that compiles the
  harness directly against the target sources without a library
  link.
- `includes`, `defines`, and `link_libs` still apply normally.
- If the harness later starts needing a real archive, replace
  `FILL_ME` with the path — the rest of the config does not
  change.

## Optional fields

| Field | Meaning |
| --- | --- |
| `cmake_target` | CMake target name used when a generated bundle can rebuild a specific target. |
| `reachability_ignore` | Substrings removed from external caller search results, such as the project itself or vendored copies. |

`target.toml` is parsed as strict TOML. Invalid section headers
or malformed arrays fail fast instead of silently falling back to
top-level keys.

## Sanitizers

The `[sanitizer]` section declares which sanitizer runners are
intentionally enabled for this target, and where to find each
sanitizer's optional suppression file.

Only ASan is enabled by default. The supported sanitizer slugs
are `asan`, `ubsan`, `msan`, `tsan`, and `race`; everything except
`asan` is opt-in per target. For when to enable each one and the
false-positive trade-offs, see
[Configure a target](../guides/configure-target.md#sanitizer-policy).

### Findings-only mode (no sanitizer)

For targets that have no sanitizer build — typical for
interpreted languages (Python, Ruby, PHP, …) or JVM runtimes
(Java, Kotlin) — set `enabled` to an explicit empty list:

```toml
[sanitizer]
enabled = []
```

With `enabled = []`:

- `bin/probe` routes testcases through `[runner].bin` instead of
  expecting an ASan binary.
- `bin/run-asan generic` skips `ASAN_OPTIONS` injection so the
  language runtime sees a clean environment.
- The triager auto-demotes runtime-diagnostic crashes (Python
  tracebacks, Go panics, Ruby exceptions, Java stack traces, Node
  fatal errors, Rust panics, …) from `crashes/` to `findings/`
  instead of rejecting them. Genuine sanitizer-class
  memory-safety signals (ASan, TSan, MSan, Go race detector)
  still stay in `crashes/`.

When `[sanitizer]` is **absent entirely** from `target.toml`, the
default — `["asan"]` — kicks in. Only an explicit empty list opts the
target out.

### Per-sanitizer keys

| Key | Meaning |
| --- | --- |
| `enabled` | List of sanitizer slugs intentionally enabled for this target. Defaults to `["asan"]`. |
| `<name>_suppressions` | Path to a suppression file. Appended via `<NAME>_OPTIONS=suppressions=…` at runner startup. Missing files emit a warning but do not abort. |
| `<name>_options` | Additional colon-separated runtime options appended to `<NAME>_OPTIONS`. |
| `ubsan_bin` / `msan_bin` / `tsan_bin` | Per-sanitizer binary overrides for opt-in runners. `asan_bin` is the top-level ASan binary field. |
| `ubsan_lib` / `msan_lib` / `tsan_lib` | Optional per-sanitizer library used when compiling C/C++ `HARNESS:` testcases. ASan uses top-level `asan_lib`. |

### Example

```toml
asan_bin = "build-asan/xmllint"

[sanitizer]
enabled = ["asan", "msan"]
asan_suppressions  = "build-asan/asan-suppressions.txt"
msan_suppressions  = "build-msan/msan-suppressions.txt"
msan_bin           = "build-msan/xmllint"
msan_lib           = "build-msan/libxml2.a"
```

UBSan and TSan follow the same shape — add the slug to `enabled` and
set the matching `<name>_bin` / `<name>_lib` / `<name>_suppressions`
keys.

Notes:

- Paths are relative to `targets/<target>/` unless absolute.
- Relative paths whose first segment is `build-asan`, `build-ubsan`,
  `build-msan`, or `build-tsan` are `AUDIT_BUILD_SUFFIX`-aware. Inside
  `bin/audit-container-shell`, those paths resolve to the per-image
  suffixed build directory; outside the container the suffix is empty.
- Unknown sanitizer slugs in `enabled` are logged on stderr and
  dropped. The loader falls back to `["asan"]` if `[sanitizer]`
  was absent and nothing valid remains.
- An **explicit** empty list (`enabled = []`) is honoured as
  findings-only mode and is *not* re-defaulted to `["asan"]`.
- Runner scripts warn when invoked for a sanitizer that is not
  listed in `enabled` but do not abort. That keeps one-off
  reproduction and debugging commands usable.

## Language runner

The `[runner]` section is the language-agnostic invocation
contract. It is used by `bin/probe` and `bin/run-asan generic`
whenever no sanitizer binary is configured. Most commonly when
`[sanitizer] enabled = []`, but also for compiled-language
targets that want to plug in a custom driver script.

| Key | Meaning |
| --- | --- |
| `bin` | Interpreter or driver program (`python3`, `node`, `cargo`, `ruby`, an absolute path to a wrapper script, …). |
| `args` | Literal argument list. `{TESTCASE}` is substituted with the testcase path — see note below. |
| `env` | Extra `KEY=VAL` strings layered on the runtime environment (e.g. `["GORACE=halt_on_error=1"]`, `["PYTHONDEVMODE=1"]`). `{TARGET_ROOT}`, `{RESULTS_DIR}`, and `{TARGET_SLUG}` are substituted at run time. |
| `crash_patterns` | Additional regex strings the triager treats as crash signals beyond its built-in language-agnostic markers. Use sparingly. |

`{TESTCASE}` substitution rules:

- When `{TESTCASE}` appears in `args`, it is replaced in place
  and the runner does *not* also append the testcase path.
- When `{TESTCASE}` is absent, the runner adds the testcase path
  after the expanded args, in the conventional last position.

### Examples

```toml
# Pure Python target — interpreter + dev-mode env.
[runner]
bin            = "python3"
args           = ["{TESTCASE}"]
env            = [
  "PYTHONDEVMODE=1",
  "PYTHONPATH={TARGET_ROOT}:{TARGET_ROOT}/src:{TARGET_ROOT}/lib",
]
crash_patterns = []
```

```toml
# Go target — findings-only driver via `go run`.
[runner]
bin            = "go"
args           = ["run", "{TESTCASE}"]
env            = ["GORACE=halt_on_error=1"]
crash_patterns = []
```

To enable the Go runtime race detector, set
`[sanitizer] enabled = ["race"]` and use
`args = ["run", "-race", "{TESTCASE}"]`.

```toml
# Rust target — cargo run with stdin-fed testcase.
[runner]
bin            = "cargo"
args           = ["run", "--quiet", "--", "{TESTCASE}"]
env            = []
crash_patterns = []
```

```toml
# Custom wrapper script — useful for Java/Kotlin builds that need
# a classpath or a wrapper that pre-configures JNI agents.
[runner]
bin            = "./tools/run-testcase.sh"
args           = ["{TESTCASE}"]
env            = []
crash_patterns = ['^DEFENSIVE-ASSERT-FAILED:']
```

`bin/setup-target` emits a starter `[runner]` block driven by
the detected build system. The seeded values are commented when
the build system is unknown so the file is safe to parse before
the operator fills it in.

## Threat model

`attacker_controls` describes what an external caller can
legitimately control. Triage compares crash report
`Trigger source` values against this list.

| Token | Meaning |
| --- | --- |
| `bytes` | Caller-controlled bytes: file, stream, packet, archive, media, regex, or similar data. |
| `call-sequence` | Ordered public API, script, plugin, or Web API calls. |
| `timing` | Event-loop scheduling, GC timing, JIT tier-up, or similar timing. |
| `race` | Thread or process interleaving. |
| `protocol-state` | Multi-message protocol state. |
| `env` | Process environment variables. |
| `fs-state` | Filesystem paths, presence, permissions, or layout. |

Unknown tokens are logged on stderr and ignored; if the resulting list
is empty, the loader defaults to `["bytes"]`.

Examples:

```toml
[threat_model]
attacker_controls = ["bytes"]
```

```toml
[threat_model]
attacker_controls = ["bytes", "call-sequence", "timing"]
```

```toml
[threat_model]
attacker_controls = ["bytes", "call-sequence", "protocol-state"]
```

## Browser mode

Generic targets:

```toml
is_browser = "0"
```

Browser or browser-like runtime targets:

```toml
is_browser = "1"
```

Browser mode enables:

- browser and JS testcase assumptions;
- coverage-gated browser or shell runs when available;
- JS differential mode.

For browser targets, triage can also require plausible
web / content reachability before a crash stays in `crashes/`.
Shell-only or privileged-only crashes may still be useful
engineering evidence, but they should not be presented as
web-reachable security crashes without a real product path.

Firefox path conventions differ by platform. macOS builds
normally use:

```toml
asan_bin = "build-asan/dist/Nightly.app/Contents/MacOS/firefox"
```

Linux builds normally use:

```toml
asan_bin = "build-asan/dist/bin/firefox"
```

Coverage-ASan browser gating follows the same platform split,
checking XUL on macOS or `libxul.so` on Linux for
`__sancov_guards`.

## Session environment

At audit startup, `bin/audit` writes the active session file:

```text
output/<target>/<backend>/results/.session-env
```

It contains dynamic values:

- `RESULTS_DIR`;
- `TARGET_ROOT`;
- `TARGET_SLUG`;
- `TARGET_REV`;
- `LOGDIR`;
- `SESSION_STARTED`.

`bin/probe` discovers the nearest `.session-env` by walking upward
from the testcase path and current directory. Scratch testcases under
`results/` therefore do not need manual environment setup.

## Strategy hints: `[s4_diff_pairs]` and `[s6_peers]`

`bin/setup-target` and `bin/audit --new-target` seed two optional
strategy-hint sections. Most operators leave them as generated — you
can also hand-edit or delete them, and the audit still runs.

`[s4_diff_pairs]` lists pairs of execution modes the harness can diff
for S4 (differential testing). Only browser/JS engine targets carry
meaningful defaults:

```toml
[s4_diff_pairs]
jit_off   = ["--no-ion"]
jit_eager = ["--ion-eager"]
```

`[s6_peers]` lists upstream peer projects to mine for S6
(cross-project variant):

```toml
[s6_peers]
domain = "xml-parser"
peers  = ["libexpat", "Xerces-C++", "rapidxml"]
```

Empty or missing values are fine — both sections only suggest
additional strategy material. `bin/audit --new-target` can also
LLM-bootstrap a real `[threat_model]` and `[s6_peers]` instead of the
conservative defaults; you can re-run that derivation at any time:

```bash
bin/suggest-threat-model <slug> --apply --force-config   # re-derive attacker_controls
bin/suggest-peers <slug> --apply --force-config          # re-derive [s6_peers]
```

`bin/setup-target` accepts `--no-llm-config` to keep the deterministic
seed and skip LLM enrichment — not recommended unless you have a
specific reason to stay offline.

## Generated versus live revision

`pinned_rev` in `target.toml` is metadata captured at setup
time. At audit startup, the live source revision is written to
`.session-env` as `TARGET_REV`.

Use the live revision in reports and exported bundles when the
two differ. This lets you refresh a target without rewriting
reviewed config on every source update.
