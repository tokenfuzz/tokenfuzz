# Target Configuration

Use this guide after `bin/setup-target` or `bin/audit --target <target>` creates
`output/<target>/target.toml`. Most targets need review, not a config written
from scratch.

The file answers three operational questions:

1. What executable, library, or language runner carries a testcase into the
   target?
2. Which diagnostics can that route actually observe?
3. Which parts of the trigger may an external actor control?

Those answers affect both execution and later reportability. Review them before
a long run.

!!! warning "Edit only between runs"
    Audit preflight copies the reviewed config to
    `output/<target>/<backend>/results/.target.toml` and records its digest in
    `.session-env`. The session reads that immutable snapshot. Change the
    shared `output/<target>/target.toml` for the next run; never edit the pinned
    copy.

## Start with the target shape

### Native CLI or library

A minimal native config identifies the executable and, when API harnesses are
useful, the library and compile inputs:

```toml
target         = "sampleproj"
upstream_url   = "https://example.org/sampleproj.git"
build_system   = "cmake"
build_widening = true

asan_bin = "build-asan/bin/sample"
asan_lib = "build-asan/lib/libsample.a"
includes = ["include", "build-asan/include"]
defines  = []
link_libs = ["-lm"]

is_browser = "0"

[threat_model]
attacker_controls = ["bytes"]
```

Relative paths resolve under the target root — `targets/<target>/`, or the
overlay's `source_subdir` for nested layouts such as Chromium's `src/`. A
CLI-only audit can proceed with a correct `asan_bin`; the library fields matter
only when `bin/probe` compiles an API harness.

### Findings-only language target

When there is no sanitizer build, declare that explicitly and provide the
runner that executes a testcase:

```toml
target       = "samplepy"
build_system = "python"
is_browser   = "0"

[sanitizer]
enabled = []

[runner]
bin  = "python3"
args = ["{TESTCASE}"]
env  = [
  "PYTHONDEVMODE=1",
  "PYTHONPATH={TARGET_ROOT}:{TARGET_ROOT}/src:{TARGET_ROOT}/lib",
]
crash_patterns = []

[threat_model]
attacker_controls = ["bytes"]
```

Runtime tracebacks and panics from a findings-only target are diagnostic
signals, not sanitizer proof. `bin/probe` does not auto-file a crash bundle for
the `runner` route; the agent writes a substantive security report under
`findings/` when source analysis establishes one. The
[language-runner guide](multi-language.md#crash-and-finding-routing) explains
the probe, filing, and triage stages.

## Review the execution route

Run setup after the relevant build exists so detection sees the final
artifacts:

```bash
bin/setup-target <target>
```

Then check:

- `asan_bin` starts the intended product, not a test helper or fuzzer binary;
- `[runner].bin` and `args` load code from the target root, not an installed
  copy elsewhere on the host;
- `{TESTCASE}` appears where the program expects input (when omitted, TokenFuzz
  appends it);
- any documented normal nonzero exit is listed in `[runner].success_codes`;
- browser page routes include `{PROFILE}` and `{TESTCASE}`;
- optional sanitizer binaries belong to the matching build.

For registered language runners, `bin/setup-target --build` and audit
preflight run a canary when the registry can prove target ownership. A runner
that starts but imports only an installed package is rejected rather than
silently auditing the wrong code.

Use `bin/suggest-runner <target> --apply --force` only when the generated native
CLI route is wrong. The helper selects from instrumented executables declared
by the build, validates input-dependent behavior, and updates matching enabled
sanitizer routes together.

## C harness readiness

A compiled `HARNESS:` testcase uses:

- the selected sanitizer library (`asan_lib`, or the matching
  `[sanitizer].<name>_lib`);
- `includes` and `defines`;
- `link_libs`, including target-relative archives or source files;
- the target source root.

After repeated C/C++ harness build failures, `bin/auto-repair-target-toml`
proposes a conservative additive repair to `includes`, `defines`, or
`link_libs`:

```bash
bin/auto-repair-target-toml --toml output/<target>/target.toml \
  --build-log <path/to/harness.build.log> --dry-run
```

Drop `--dry-run` to write it; a timestamped backup is saved beside the config
and the decision is logged. It is run by hand — nothing in an audit invokes it.
Review the proposal: a compile fix is not evidence that the harness is faithful
to a public API contract.

Harnesses may also be written in the other compiled or interpreted languages
registered by `lib/languages.py`. Run `python3 lib/languages.py list` for the
authoritative extension table.

## Sanitizer policy

`[sanitizer].enabled` is ordered. `bin/probe` selects the first enabled entry by
default; a one-off `PROBE_SANITIZER=<name>` override can select another without
changing persistent policy.

| Slug | Use it when | Main cost |
| --- | --- | --- |
| `asan` | Native memory-safety work; the default. | Moderate runtime and memory overhead. |
| `ubsan` | Undefined-behavior classes relevant to the target, such as bounds, vptr, object size, or shifts. | Mature projects may intentionally use patterns that need triage or suppressions. |
| `msan` | A self-contained native library whose dependencies can all be instrumented. | Uninstrumented dependencies create noise; browser-scale use is usually impractical. |
| `tsan` | Native concurrency work with a maintained suppression policy. | High overhead and frequent benign reports. |
| `race` | A Go runner or binary built with `-race`. | Routes through `[runner]`; there is no `race_bin`, `race_lib`, or suppression key. |

Example:

```toml
asan_bin = "build-asan/bin/sample"

[sanitizer]
enabled = ["asan", "ubsan"]
asan_suppressions  = "build-asan/asan-suppressions.txt"
ubsan_bin          = "build-ubsan/bin/sample"
ubsan_lib          = "build-ubsan/lib/libsample.a"
ubsan_suppressions = "build-ubsan/ubsan-suppressions.txt"
```

Ordinary non-browser C/C++ preflight converges every enabled native sanitizer.
ASan is required for that route; optional sanitizer failures warn without
destroying the canonical ASan build. Ecosystem bootstraps and Go `race` remain
explicit `bin/setup-target <target> --build` work.

The exact keys, defaults, suffix-aware path rules, and runtime-option fields are
in the [target config schema](../reference/target-toml.md#sanitizers).

## Review the threat model

`[threat_model].attacker_controls` describes what an external actor may supply
through a normal product boundary:

| Token | External control |
| --- | --- |
| `bytes` | Files, streams, packets, archives, media, regexes, or other input bytes. |
| `call-sequence` | Ordered public API, script, plugin, or Web API calls. |
| `timing` | Event-loop scheduling, GC timing, JIT tier-up, or similar timing. |
| `race` | Thread or process interleaving. |
| `protocol-state` | State accumulated across several protocol messages. |
| `env` | Process environment variables. |
| `fs-state` | Filesystem paths, presence, permissions, or layout. |

Typical shapes:

```toml
# File parser or decoder.
[threat_model]
attacker_controls = ["bytes"]

# Scriptable browser/runtime surface.
[threat_model]
attacker_controls = ["bytes", "call-sequence", "timing"]

# Stateful network protocol.
[threat_model]
attacker_controls = ["bytes", "call-sequence", "protocol-state"]
```

Keep the list narrow. A harness can choose arbitrary offsets, lengths, object
states, or cleanup order; that does not make those choices attacker-controlled
in the product. When a reproducible crash needs a control outside the list,
triage keeps the engineering evidence but can classify it `not-reportable`.
Do not widen the config merely to change that decision.

## Browser mode

Set `is_browser = "1"` for a browser or browser-like runtime. A `{PROFILE}`
token in `[runner].args` declares a page-capable browser route. Without it, the
target is treated as a script engine: generic execution, shell agents, and no
invented browser profile.

Verify the product executable, temporary-profile argument, testcase position,
and the controls the web or script surface really exposes. The
[browser guide](browser-targets.md) covers `mach`, GN, Chromium, coverage, and
product reachability.

## Validate the reviewed config

```bash
bin/audit --target <target> --backend <backend> 1
```

Both setup and audit parse and validate `target.toml`. A successful smoke test
also proves that the selected backend can create state under the result tree.
Inspect `logs/index.log` if startup stops before `work-cards.jsonl` appears.

## Common failures

| Symptom | Check |
| --- | --- |
| The wrong program runs | Fix `asan_bin` or re-run `bin/suggest-runner <target> --apply --force`. |
| Every probe reports `EXEC_FAIL` on input the CLI clearly read | Re-run `bin/setup-target <target>` (or `bin/suggest-runner <target> --apply`). It replays the configured argv and records the reviewed malformed-input exit in `[runner].success_codes`, without reselecting the CLI. |
| Headers are missing | Add source or generated include directories to `includes`. |
| Macros are missing | Add the required compiler arguments to `defines`. |
| Harness linking fails | Check the selected sanitizer library and add required system, archive, or source inputs to `link_libs`. |
| Every language probe misses the audited package | Fix `[runner]` cwd/import paths; do not accept a globally installed copy. |
| A real crash is `not-reportable` | Compare its actual trigger with `attacker_controls`; do not broaden the threat model unless the product exposes that control. |

For field-by-field syntax, continue to the
[target config schema](../reference/target-toml.md).
