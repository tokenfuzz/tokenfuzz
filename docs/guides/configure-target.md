# Configure a Target

Use this guide after `bin/setup-target` or `bin/audit --target <target>`
has generated `output/<target>/target.toml`.

Most of the work is review, not hand-authoring. The harness infers a
reasonable default config. Your job is to keep the values that are
correct and edit only the ones that are unresolved or specific to this
target.

## What the config has to answer

`output/<target>/target.toml` should answer these questions clearly:

- Where is the ASan executable?
- Are optional sanitizer binaries or suppressions configured for the
  runners you intend to use?
- Can the harness compile C harnesses for this target?
- Is this a generic target or a browser target?
- What can external input legitimately control?
- How should exported reproduction bundles rebuild or rerun the target?

These answers drive testcase execution at run time and triage at
result time. They decide:

- which sanitizer binary to launch;
- which library to link against;
- whether a crash trigger fits the declared attacker surface.

## A minimal generic config

```toml
target       = "libxml2"
upstream_url = "https://gitlab.gnome.org/GNOME/libxml2.git"
build_system = "cmake"
pinned_rev   = "HEAD"

asan_bin     = "build-asan/xmllint"
asan_lib     = "build-asan/libxml2.a"
includes     = ["include", "build-asan/include"]
link_libs    = ["-lz", "-llzma", "-lm"]

is_browser   = "0"

[threat_model]
attacker_controls = ["bytes"]
```

Relative paths resolve under `targets/<target>/`.

## A minimal findings-only config (Python, Ruby, Go, Node, …)

For interpreted or managed-runtime targets that have no sanitizer
build, seed an explicit empty `[sanitizer].enabled` list. Then let the
harness drive testcases through a language-specific `[runner]` block:

```toml
target       = "my-py-tool"
upstream_url = "https://example.org/my-py-tool.git"
build_system = "python"
pinned_rev   = "HEAD"

is_browser   = "0"

[threat_model]
attacker_controls = ["bytes"]

[sanitizer]
enabled = []           # findings-only mode

[runner]
bin            = "python3"
args           = ["{TESTCASE}"]
env            = [
  "PYTHONDEVMODE=1",
  "PYTHONPATH={TARGET_ROOT}:{TARGET_ROOT}/src:{TARGET_ROOT}/lib",
]
crash_patterns = []    # builtin Python tracebacks are already recognised
```

The harness runs `python3 <testcase>` against the interpreter on
`PATH`. Runtime tracebacks land under `findings/` rather than
`crashes/`. See [Auditing non-C/C++ targets](multi-language.md) for
the full per-language matrix.

## Review checklist

1. Build the default ASan target.
2. Refresh the generated config before making local edits:

   ```bash
   bin/setup-target <target>
   ```

   Note: `setup-target` refreshes generated fields from the current
   checkout and build outputs. `--no-llm-config` skips the best-effort
   threat-model and S6 lookalike project suggestions; not recommended
   unless you have a specific reason to stay offline.

3. Confirm `asan_bin` points to the ASan executable you want generic
   or browser runs to start.
4. If agents will compile C harnesses, confirm `asan_lib`, `includes`,
   `defines`, and `link_libs`. You can leave these unresolved if you
   do not plan to use C harness testcases yet.
5. Confirm `is_browser = "0"` for generic libraries and CLIs, or
   `is_browser = "1"` for browser or JS-runtime targets.
6. Confirm `attacker_controls` matches the real external input
   boundary.
7. If you intend to run UBSan, MSan, or TSan, add those slugs and
   binary paths under `[sanitizer]`.
8. Start one bounded session:

   ```bash
   bin/audit --target <target> --backend <backend> 1
   ```

Both `bin/setup-target` and `bin/audit` validate `target.toml`
themselves before continuing.

## Threat-model choices

`attacker_controls` is read by triage. **Keep it conservative.**

This field does not decide whether a report is *interesting*. It
decides whether a crash trigger is reachable through a normal input
boundary for this target. Other concrete security issues can still be
recorded in `findings/` even when they are not sanitizer crashes.

| Token | Use when external input controls |
| --- | --- |
| `bytes` | File, stream, packet, archive, media, regex, or other input bytes. |
| `call-sequence` | Ordered public API calls, script calls, plugin calls, or Web API calls. |
| `timing` | Event-loop scheduling, GC timing, JIT tier-up, or similar timing. |
| `race` | Thread or process interleaving. |
| `protocol-state` | Multi-message protocol state. |
| `env` | Process environment variables. |
| `fs-state` | Filesystem paths, presence, permissions, or layout. |

A few examples:

```toml
# Parser, decoder, archive, codec, regex engine.
[threat_model]
attacker_controls = ["bytes"]

# Browser engine or scriptable runtime.
[threat_model]
attacker_controls = ["bytes", "call-sequence", "timing"]

# Network protocol implementation.
[threat_model]
attacker_controls = ["bytes", "call-sequence", "protocol-state"]
```

Do not reach for broad controls to make harness-only behaviour look in
scope. If a harness reads an input value and then calls a target API
with an offset or index no real product path would pass, that is
caller-contract misuse — not attacker control. Fix the testcase, or
keep the result outside `crashes/`. Do not widen the threat model to
push the artifact through triage.

## C harness readiness

If you expect agents to exercise the target through a small C/C++
harness program (rather than only the CLI binary), the harness
compilation pulls its inputs from `target.toml`:

- the selected sanitizer's library (`asan_lib` for ASan; `[sanitizer]`
  entries for UBSan / MSan / TSan);
- `includes`;
- `defines`;
- `link_libs`;
- the target source root.

If C harness compilation fails, those are the fields to check.

After repeated C/C++ harness build failures, the audit may make a
conservative additive repair to `includes`, `defines`, or `link_libs`.
It writes a `target.toml.bak.<timestamp>` backup and logs the action
under the run's `logs/` directory.

Harnesses are not limited to C. Sibling
`.cc/.cpp/.cxx/.C/.rs/.go/.swift/.kt` harnesses compile, and
`.py/.rb/.pl/.php/.js/.mjs/.ts/.tsx/.java/.kts/.r/.R/.sh/.bash`
harnesses run through their interpreter.

## Browser mode readiness

For browser targets:

```toml
is_browser = "1"
```

Confirm:

- `asan_bin` points to the browser executable.
- macOS Firefox builds usually use
  `build-asan/dist/Nightly.app/Contents/MacOS/firefox`.
- Linux Firefox builds usually use `build-asan/dist/bin/firefox`.
- Browser ASan runtime dependencies are present.
- JS shell or browser wrappers work for the target.
- Expected controls include `bytes`, `call-sequence`, and only the
  timing or state dimensions the product actually exposes.

See [Browser targets](browser-targets.md) for the longer walkthrough.

## Sanitizer policy

The harness runs ASan by default. Other supported sanitizer runners
are opt-in per target through the `[sanitizer]` block in
`target.toml`. The valid slugs are `asan`, `ubsan`, `msan`, `tsan`,
and `race`.

```toml
[sanitizer]
enabled = ["asan"]
asan_suppressions  = "build-asan/asan-suppressions.txt"
# ubsan_suppressions = "build-ubsan/ubsan-suppressions.txt"
# msan_suppressions  = "build-msan/msan-suppressions.txt"
# tsan_suppressions  = "build-tsan/tsan-suppressions.txt"
# ubsan_bin = "build-ubsan/xmllint"
# msan_bin  = "build-msan/xmllint"
# tsan_bin  = "build-tsan/xmllint"
# ubsan_lib = "build-ubsan/libtarget.a"
# msan_lib  = "build-msan/libtarget.a"
# tsan_lib  = "build-tsan/libtarget.a"
```

Recommended posture for each:

- **ASan** — enabled by default. Highest signal, lowest noise.
- **MSan** — recommended for self-contained libraries (parsers,
  codecs, archives). Catches uninitialized reads, but every dependency
  must be MSan-instrumented. That makes it impractical at browser
  scale.
- **UBSan** — optional. Useful subset: `vptr`, `object-size`, `shift`,
  `bounds`, `signed-integer-overflow`. Expect to triage false
  positives from `pointer-overflow`, `unsigned-integer-overflow`, and
  `alignment` — mature C/C++ projects often rely on these patterns
  intentionally.
- **TSan** — optional and demanding. Plan to maintain a suppressions
  file for the project's threading model. Benign atomics and racy
  counters fire frequently. Only enable when you can invest in the
  triage.
- **race** — Go's runtime race detector. Enable for Go targets built
  or run with `-race`. Reports containing `WARNING: DATA RACE` are
  treated like TSan-class evidence.

See
[Target config reference](../reference/target-toml.md#sanitizers)
for the full field list and per-sanitizer binary overrides.

Even when another sanitizer is enabled, ASan remains the usual first
pass for crash prioritisation. It produces the clearest reproduction
bundles, and the triage rules are tuned around that workflow.

## Reproduction bundle fields

Add this when it helps:

```toml
reachability_ignore = ["GNOME/libxml2"]
```

It filters external-caller reachability results to drop the project's
own sources and known vendored copies. It is not a substitute for
correct sanitizer binary paths.

## When the generated values need review

Local edits should be small and easy to explain. Common cases:

- the ASan executable has a project-specific name the generator could
  not infer;
- the useful static library is not the first archive under
  `build-asan/`;
- generated headers live outside the default include directories;
- C harnesses need extra system libraries;
- the target exposes controls beyond raw bytes, such as API call
  sequence or protocol state.

Do not pre-fill fields for features you are not using. A CLI-only
first audit can proceed with a correct `asan_bin` while C harness
fields are refined later.

## Common misconfigurations

| Symptom | Likely fix |
| --- | --- |
| `bin/audit` cannot find target config | Seed it with `bin/audit --target <target> --backend <backend> 1` or `bin/setup-target <target>`. Confirm `--target` matches the directory name. |
| Generic testcase runs the wrong binary | Fix `asan_bin`. Paths are relative to `targets/<target>/`. |
| C harness compile fails on missing headers | Add source or build include directories to `includes`. |
| C harness compile fails on missing macros | Add required compiler flags to `defines`. |
| Link fails during harness compile | Add the ASan library and required system libraries to `asan_lib` and `link_libs`. |
| Triage rejects a report as out of scope | Recheck `attacker_controls` and report `Trigger source`. Do not widen the model unless the product actually exposes that control. |

For field-by-field details, see
[Target config reference](../reference/target-toml.md).
