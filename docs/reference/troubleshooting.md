# Troubleshooting

Search this page for the message you saw. Each entry gives the message, its
cause, and the fix. `<target>`, `<backend>`, `<path>`, and similar
placeholders stand for the values in your message.

## Where messages appear

| You saw | Printed by | Where to find it again |
| --- | --- | --- |
| `FATAL: ...` and the command exited | `bin/audit` or `bin/benchmark` refusing to start | The terminal (stderr) only; `bin/audit` does not write these to `index.log`. Capture them with `2>&1 | tee <file>`. |
| `[HH:MM:SS] ...` progress lines | The audit loop | The terminal and `output/<target>/<backend>/logs/index.log` |
| `[setup-target] ...` | `bin/setup-target` | The terminal. `[setup-target] FATAL:` exits 1. |
| `[probe] ...` | `bin/probe` | The terminal. A refused testcase exits 2. |
| `WARN: Cell ...` and other benchmark lines | `bin/benchmark` | The terminal and, once the run directory exists, `output/benchmark/<backend>/<run-id>/console.log` |

For a run that produced results, the indexes under `crashes/`, `findings/`,
`crashes-rejected/`, and `findings-rejected/` are a better first stop than
raw logs. For a question about one result, read its report,
`validation.json`, and any rejection reason.

## Preflight fails

`bin/audit` runs these checks in order before any agent starts. The first
failure prints `FATAL: <reason>` and exits 1.

1. Command line, target path, backend, and agent security mode.
2. `target.toml` loads (see
   [Target config does not parse](#target-config-does-not-parse)).
3. No other `bin/audit` holds this results tree.
4. Runner preflight, when `[runner].bin` is set. Success logs
   `Runner preflight OK: ...`.
5. Model preflight: one short agent launch must write a file into the
   target tree. Success logs `Model preflight passed: backend=<b> model=<m>`.
6. Build preflight: missing or stale sanitizer builds are rebuilt, and
   browser targets run a canary.

Startup is complete when `index.log` shows
`LLM backend: provider=<backend> model=<model>`. Otherwise, the last success
line in `index.log` shows how far it got.

### Backend and command line

<span id="backend-cli-fails"></span>

| Message | Cause | Fix |
| --- | --- | --- |
| `FATAL: target path does not exist: <path>` | `targets/<target>/` (or the `--target-path`) is missing. | Run `bin/setup-target <target> <source>`, or correct the slug. |
| `FATAL: backend '<name>' is not installed or configured` | The CLI is not on `PATH` or at its `*_BIN` override, or its readiness check failed: `claude auth status`, `codex login status`, `grok models`, `agy changelog` (`gemini --version` with `USE_GEMINI_CLI=1`), or `opencode --version`. | Install the CLI and log in, then run that check yourself until it succeeds. Or pick another `--backend`. |
| `FATAL: no installed and configured hosted backend found` | `--backend all`, the default when neither `--backend` nor `AUDIT_BACKEND` is set, found none of `claude`, `codex`, `gemini`, or `grok` ready. `oss` is never chosen automatically. | Install and authenticate one hosted CLI, or pass `--backend oss --model <model>`. |
| `FATAL: --backend oss requires --model` | OpenCode has no default model. | Pass the model your provider or local endpoint serves. |
| `FATAL: --model requires a single backend` | `--model` was combined with `--backend all`. | Name one backend. |
| `FATAL: backend '<name>' cannot use agent security 'sandboxed': <reason>` | The Gemini and Grok CLI sandboxes cannot contain an audit, and OpenCode has no sandbox. Every backend except `oss` defaults to `sandboxed`. In an ensemble the backend is skipped with `WARN: skipping backend ...` instead. | Run inside a container or VM you administer with `--agent-security external-bypass` and `IS_SANDBOX=1`. See [Agent security modes](../guides/backends.md#agent-security-modes). |
| `FATAL: no backend can run under agent security '<mode>'` | Every ensemble backend was skipped for the reason above. | As above. |

The readiness check does not prove the model works; model preflight does.
When a backend misbehaves, run its CLI by hand outside the harness to
confirm authentication and basic execution, and debug with one explicit
backend and one iteration:

```bash
bin/audit --target <target> --backend <backend> 1
```

For a local model, confirm the endpoint serves the expected model
(`--backend oss` uses `http://127.0.0.1:8000/v1` unless
`AUDIT_LOCAL_BASE_URL` says otherwise):

```bash
curl http://127.0.0.1:8000/v1/models
curl http://127.0.0.1:11434/v1/models   # Ollama
```

### Another run owns this results tree

| Message | Cause | Fix |
| --- | --- | --- |
| `FATAL: another bin/audit instance is writing to <logs> (holder PID=<pid>)` | A live `bin/audit` for the same target, backend, and experiment holds `logs/.instance.lock.d`. A dead process's lock is cleared automatically. | Wait for that run or stop it. For a second concurrent run, pass `--experiment <name>` to get a separate tree. `--allow-concurrent` skips the lock and makes both runs append to one state tree. |
| `FATAL: this results tree's delta scope changed: ...` | The tree was started with a different `--since`, or none, or at a different `HEAD`. | Restore the recorded checkout and pass the same `--since`, or use `--experiment <name>`. |
| `FATAL: --since cannot be combined with --strategy S4: ...` (or `S6`) | Those lanes draw cards from outside the changed range. | Drop one of the two flags. |

### Runner preflight

Only when `target.toml` sets `[runner].bin`.

| Message | Cause | Fix |
| --- | --- | --- |
| `FATAL: configured [runner].bin '<bin>' was not found on PATH or at <path>` | The interpreter or driver is not installed, or the path is wrong. | Install it, or correct `[runner].bin`. |
| `FATAL: configured [runner].bin is not executable: <path>` | The file lacks execute permission. | `chmod +x` it, or point `[runner].bin` at the real executable. |
| ``FATAL: configured [runner].bin failed startup check `<command>`: exited <n>: <output>`` (or `timed out after 10s`) | The language runtime is missing or cannot start. Known runtimes get a short startup command, such as `java -version` or `python3 -c pass`. | Run the quoted command yourself until it succeeds. The macOS Java stub needs a registered JDK; see [Target-specific tools](../getting-started/prerequisites.md#3-target-specific-tools). |
| ``FATAL: configured [runner].bin cannot prepare the <sanitizer> target context `<command>`: ...`` | A Swift `--skip-build` runner route could not build its product first. | Run the quoted command in the target checkout and fix the build. |
| `FATAL: configured [runner] starts but cannot reach the audited tree: <detail>` | The runtime resolves an installed copy of the package instead of the checkout. | Run `bin/setup-target <target> --build` (the message spells it `--target <slug>`, which `bin/setup-target` does not accept), or fix the `[runner]` working directory or import path. See [Review the execution route](../guides/configure-target.md#review-the-execution-route). |

### Model preflight

Model preflight launches the selected model once through the real agent
path and requires it to write into `.audit/` in the target tree.
[Model preflight](../guides/backends.md#model-preflight) explains attempts
and timeouts.

```text
FATAL: model preflight refused for backend=<name>: requested model=<a> but the provider served <b>
```

The provider served a different model, and retrying cannot change that.
Pick a model the provider serves, or drop `--model` for the configured
default. If the message adds
`The provider declared a safeguard refusal [<category>], so the requested model declined this workload rather than being unavailable.`,
it is an access question: check the provider's
[access requirements](../getting-started/prerequisites.md#cyber-access-for-security-research)
and permitted-use policy. Another model name does not lift an access
restriction.

```text
FATAL: model preflight: provider rejected backend=<name> model=<model> on attempt <n>: provider said "<reason>"; check the model name, CLI credentials and model access. Transcript: <path>
```

The provider refused the request, and `<reason>` is its own explanation: a
model name it does not serve (often a typo in `--model`), an expired login,
no access to that model, or a safeguard refusal. Fix the name, or log in
again and confirm the account can use the model. The harness stops after
the first refusal instead of retrying. On every backend, a failed launch
whose provider error names the requested model and says it is not found,
unknown, or not supported counts as a refusal, whatever the rest of the
CLI's wording. A tool's own error, such as a missing file, is never read as
one. A safeguard refusal also logs `WARN: MODEL_REFUSAL`, with the
category when the provider gives one
(`WARN: MODEL_REFUSAL: CYBER CLASSIFIER DETECTED backend=<name> provider_reason=<reason>`);
treat that as an access question, as above.

```text
FATAL: model preflight failed for backend=<name> model=<model> after <n> attempt(s) (last exit=<rc>); no command of its own reached <path>, ...
```

The agent launched but never wrote its marker file into the target tree.
When the provider gave a reason, the message quotes it after the exit
code as `: provider said "<reason>"`; start there. Otherwise read the named
transcript, then run the backend CLI by hand from the
repository root. Usual causes:

- The model name is invalid, and the CLI's error does not name it. A
  refusal that names the requested model reports as `provider rejected`
  above instead.
- The sandbox denied the write. Check the
  [agent security mode](../guides/backends.md#agent-security-modes).
- The CLI is too old. When a Codex transcript says the provider requires a
  newer Codex, the harness retries with a newer `codex` on `PATH` (unless
  `CODEX_BIN` is set); otherwise upgrade it.
- A slow local model timed out. Raise `AUDIT_MODEL_PREFLIGHT_TIMEOUT`
  (default 60 seconds, 300 under Google Gemini CLI).
- The model declined. Look for a `MODEL_REFUSAL` warning above the `FATAL`
  line.

```text
FATAL: model preflight refused for backend=gemini: Gemini CLI ignored the harness admin policies
```

Google Gemini CLI only (`USE_GEMINI_CLI=1`). A system policies directory
holding any policy makes the CLI discard every `--admin-policy` file,
leaving cross-run memory and web tools on. Remove or empty that directory,
or unset `USE_GEMINI_CLI` to use Antigravity. A benchmark cell reports the
same condition as `ERROR: Gemini CLI ignored the harness admin policies`,
exits 46, and counts as failed.

### Build preflight

| Message | Cause | Fix |
| --- | --- | --- |
| `Sanitizer build stale/missing (<sanitizers>); running bin/setup-target --build (fail-open)` | Normal. Source or recipe changed since the last build, so the audit rebuilds before any agent starts. | Nothing. Build output goes to `logs/setup-build.log`. |
| `WARN: sanitizer builds still stale/missing (<sanitizer>=<state>); sanitizer-dependent work may be unavailable | log=<path>` | The rebuild did not produce a current build. The audit continues without it. | Read the named log, then see [Target setup fails](#target-setup-fails). |
| `WARN: sanitizer build is stale/missing for an external --target-path; run its build recipe manually before continuing` | A `--target-path` outside `targets/` is never rebuilt automatically. | Build it yourself, then rerun. |
| `FATAL: sanitizer harness canary did not observe target execution; see <path>` | Browser targets only. A canary page (or script, for a script engine with no page route) did not run in the configured product. | Read the named output (`results/.preflight/canary-asan.txt`) and check that `asan_bin` is the instrumented browser or shell. See [Browser targets](../guides/browser-targets.md). |
| `FATAL: browser product <path> passed preflight but <config> declares no active asan_bin to point at it; set asan_bin and rerun` | Preflight found a working browser build, but the config has no `asan_bin` line to update. | Add `asan_bin` to `target.toml` and rerun. |

## Target setup fails

`bin/setup-target` prints `[setup-target] FATAL: <reason>` and exits 1.

| Message | Cause | Fix |
| --- | --- | --- |
| `[setup-target] FATAL: <sanitizer> build failed: <reason>` | With `--build`, the build failed, including after any model-guided recipe repair. An earlier `bootstrap: <sanitizer> clean build failed (...; see <log>)` line names the log, normally `targets/<target>/.audit/build-materialize-<sanitizer>.log`. | Read the log. Fix the host toolchain or the recipe (`targets/<target>/.audit/build.sh`, or `build-<sanitizer>.sh` for other sanitizers), then rerun `bin/setup-target <target> --build`. |
| `[setup-target] FATAL: <sanitizer> is unsupported by the host toolchain (...)` | With `--build`, the host compiler cannot build that sanitizer at all; MemorySanitizer, for example, has no macOS runtime. | Remove it from `[sanitizer].enabled`, or build on a host or container whose compiler supports it. `bin/benchmark` exits 3 when this is its only problem. |
| `[setup-target] FATAL: <sanitizer> build has no usable recipe for build_system=<system>` | With `--build`, no deterministic recipe exists for that build system and none was generated. | Write the recipe by hand, or rerun without `--no-llm-config`. |
| `[setup-target] FATAL: sanitizer executable <path> failed before program startup:` | The built program dies in the dynamic loader (a missing shared library or wrong architecture), tested under the target's `[runner].env`. | See [Sanitizer binary does not run](#sanitizer-binary-does-not-run). |
| `[setup-target] FATAL: setup produced no runnable target: target.toml has no runner, sanitizer binary, or sanitizer library` | The build succeeded, but no execution route was found. | Set `asan_bin`, `asan_lib`, or `[runner]` by hand; see the [target config reference](target-toml.md). |
| `[setup-target] FATAL: the seeded [runner] cannot reach <target>: <detail>` | The generated language runner resolves an installed copy of the package instead of the checkout. | Fix the `[runner]` working directory or import path. |
| `[setup-target] FATAL: checkout root has multiple buildable child projects (<names>); ...` | The checkout root has no build manifest and several subdirectories do. | Name the target after the subdirectory to audit (a child whose name matches the target is selected), or, for a local source, pass that subdirectory as the source. |
| `[setup-target] FATAL: bootstrap refused for <target>: the configured runner is in use by another audit or benchmark` | Setup would replace a runner a live run holds. It refuses at once. | Wait for that run, or use a separate checkout. |
| `[setup-target] bootstrap: <sanitizer> build not replaced (another run is using build-<sanitizer>); ...` | Not an error: a live run holds that build. | Nothing. The existing build stays for that run. |

## Target config does not parse

A TOML syntax error stops `bin/audit` with the parser's message, which gives
a position but not the file name:

```text
FATAL: <TOML error> (at line <n>, column <m>)
```

The file is `output/<target>/target.toml`, or
`output/<target>-<experiment>/target.toml` for an `--experiment` run. Fix
the syntax by hand at that position: quote strings, close arrays, keep
section headers such as `[runner]` well formed, and do not repeat a key. Do
not rerun setup to fix it: `bin/setup-target <target>` regenerates an
unparsable file from scratch and discards your reviewed edits.

Other problems it reports:

- A value that still contains `FILL_ME`: `bin/setup-target <target>`
  regenerates the file and keeps `[threat_model]` and `[s6_peers]`
  ([what else it keeps](target-toml.md#when-setup-rewrites-the-file)).
  With `--build` it leaves placeholders alone unless you also pass
  `--force`.
- A typed field with the wrong type or range, such as
  `<path>: [sweep] token_budget must be an integer >= 0 (got ...)`, or a
  `source_subdir` that is absolute, contains `..`, leaves the checkout, or
  does not exist.
- `[target] ignored unknown attacker_controls token in <path>: '<token>'`
  and `[target] ignored unknown sanitizer in <path>: '<name>'` are warnings:
  the value is dropped, the run continues, and the message lists the valid
  values.

Field syntax is in the [target config reference](target-toml.md).

## The run paused, or the backend went unavailable

A provider usage limit does not end a run. `bin/audit` pauses and
retries, and `logs/index.log` says so:

```text
Provider capacity limited; pausing 1800s before retry
```

A pause lasts until the provider's reset time plus 30 seconds, or 30
minutes when none is reported, up to six hours per backend, and does
**not** count against `AUDIT_WALL_BUDGET_SECS`. Other lines you may see:

- `Transient provider failure; retrying in <n>s (<k>/6)`: a non-quota
  failure backing off.
- `slot <n>: reported <issue>; no further launches, finishing in-flight sessions first`:
  the first slot of a continuous run to hit a limit.

[Capacity pauses and provider failures](../guides/backends.md#capacity-pauses-and-provider-failures)
has the full policy.

If the backend never comes back, `index.log` records one of these and
`bin/audit` exits 1:

```text
BACKEND_UNAVAILABLE: provider did not recover within the pause budget
BACKEND_UNAVAILABLE: transient provider failures did not clear
BACKEND_UNAVAILABLE: provider refused the request; retrying cannot clear it
```

A refusal is never retried: usually the login expired or the account lost
access to the model. Fix that and rerun the same command; it resumes from
saved state. In ensemble mode (`--backend all`) a capacity-limited backend
leaves the rotation while another still works, only the last one pauses,
and the run exits 1 only when every backend has failed, with its own
`BACKEND_UNAVAILABLE: ...` wording.

## The run stopped on its own

These `index.log` lines end a run normally, without a provider problem:

| Line | Meaning | What to do |
| --- | --- | --- |
| `STALL_STOP: no promoted results or active hypotheses remain` | `MAX_DRY_SESSIONS` iterations in a row (default 10, never fewer than 9) produced no new result and left no hypothesis open. In a continuous run each iteration is a steward generation. | Raise `MAX_DRY_SESSIONS` for a target you expect to be slow, or revisit the threat model and work queue. |
| `EXHAUSTED_STOP: no active hypothesis, handoff, claimable card, or fuzz lead remains after queue expansion` | A continuous run ran out of work. | Nothing, or widen the threat model or queue if you expected more. |
| `Reached productive wall budget: ...` | `AUDIT_WALL_BUDGET_SECS` is spent. | Nothing. |
| `LANE_EXHAUSTED: no open <strategy> card or hypothesis remains` | A `--strategy` run finished its lane. | Nothing, or drop the pin. |
| `LANE_UNAVAILABLE: S4 requires a native sanitizer library; use S7 for this findings-only or CLI-only target` | S4 needs a harness-linkable sanitizer library. | Use `--strategy S7`, or drop the pin. |
| `LANE_UNAVAILABLE: S6 requires configured peer projects; ...` or `LANE_UNAVAILABLE: S6 peer mining produced no cards: ...` | S6 has no peers, or its peers yielded nothing minable. | Run `bin/suggest-peers`, clone a peer under `targets/`, or drop the pin. |
| `DELTA_EXHAUSTED: ...` | A `--since` run finished its scope. | Nothing. |
| `DELTA_STOPPED: the scoped queue could not be refreshed (<reason>); ...` | The delta queue could not be rebuilt, so the run stopped rather than audit outside the range. | Fix the named reason and rerun with the same `--since`. |

## An agent looks stuck

A running session writes its live transcript under `logs/.raw/`; the
trimmed `logs/session_*.log` appears only after the session ends. Check the
timeline and the newest transcript:

```bash
tail -5 output/<target>/<backend>/logs/index.log
ls -lt output/<target>/<backend>/logs/.raw/*.log.raw | head -3
```

A long sanitizer build or a slow backend turn can leave a transcript quiet
for minutes. Every session is hard-stopped at `AGENT_TIMEOUT` (default 7200
seconds). A killed agent needs no cleanup: the slot's next session resumes
its open hypotheses, a claim with no active hypothesis is released at the
next iteration, and any claim expires after `WORK_CARD_CLAIM_TTL_SECONDS`
(default 30 minutes).

## bin/probe refuses a testcase

`bin/probe` prints `[probe] <reason>` and exits 2 without running anything.

| Message | Cause | Fix |
| --- | --- | --- |
| `testcase must live under RESULTS_DIR/scratch-N: <path>` | Probes run only testcases in an agent scratch directory. | Move the testcase to `output/<target>/<backend>/results/scratch-<n>/`. |
| ``could not locate output/<slug>/<backend>/results/.session-env above <path>; run `bin/audit --target <slug>` first`` | No audit has created a results tree for this testcase. | Start the audit once, or put the testcase under an existing results tree. |
| `testcase not found: <path>` | The path is wrong. | Check it; a bare `scratch-N/...` path resolves under `RESULTS_DIR`. |
| `sanitizer '<name>' is not enabled for this target; enabled sanitizers: <list>` | `PROBE_SANITIZER` named a sanitizer `target.toml` does not enable. | Use an enabled one, or enable it in `[sanitizer].enabled` and build it. |
| `target.toml has [sanitizer].enabled = []; use PROBE_SANITIZER=runner or enable a sanitizer` | A findings-only target has no sanitizer build. | Probe through the configured runner. |
| `build config '<name>' is not ready; run bin/build-configs --target <slug> --config <name>` | `PROBE_BUILD_CONFIG` named an alternate build that is not built. | Run the quoted command. |
| `HARNESS source not found: <path>`, `HARNESS must stay under the testcase directory: <name>` | The `HARNESS:` header names a missing file or one outside the testcase's directory. | Put the harness beside the testcase and name it relatively. |

## Every probe reports EXEC_FAIL

`bin/probe` prints the failure class beside the verdict:

```text
[probe] EXEC_FAIL class=<class>: <hint>
```

| Class | Meaning | Fix |
| --- | --- | --- |
| `loader` | The program could not be loaded (missing shared library, wrong architecture), so no input was read. | See [Sanitizer binary does not run](#sanitizer-binary-does-not-run). |
| `usage` | The program rejected its command line, not the input. | Fix `[runner].args` or the `HARNESS` invocation. For a native sanitizer CLI, `bin/suggest-runner <target> --apply --force` re-derives the argv from the program's help. |
| `input-rejected` | The program refused the input before the code under test. | Usually the testcase: shape it past the parser with `bin/find-seed`, keeping magic, length, checksum, and nesting. If the program exits nonzero on every malformed input by design, record that exit in `[runner].success_codes`; see [Common failures](../guides/configure-target.md#common-failures). |
| `aborted` | The process died on a signal or assertion with no sanitizer report. | Read the saved output. An assertion alone is not a memory-safety bug. |
| `unverified-exit` | The process exited 0, but the run's success marker never appeared, so nothing proves the input was processed. | Check `[runner].success_codes` and that the configured argv runs the program on the testcase. |
| `exit` | The process exited nonzero with no recognised diagnostic. | Read the tail of the saved output and compare the exit with the program's documented behaviour. |

Two `NO_EXEC` classes look like failures but need different handling:

- `NO_EXEC class=budget-exhausted`: this agent's sanitizer budget for the
  iteration is spent (`SHELL_SANITIZER_RUN_BUDGET`, default 60;
  `BROWSER_SANITIZER_RUN_BUDGET`, default 25), so nothing ran. The testcase
  is fine; the budget renews at the next iteration or steward tick.
- `NO_EXEC class=input-independent`: the same route crashed with an
  identical crash state on an empty input, so the binary faults whatever it
  reads, usually at startup, and the testcase is not evidence. The saved
  output keeps the diagnostic. Make the route start cleanly (a runtime
  option such as an `ASAN_OPTIONS` entry, another build, or CLI flags after
  `--`), then probe again.

## Sanitizer binary does not run

A loader failure shows up as `[probe] EXEC_FAIL class=loader`, as
`[setup-target] FATAL: sanitizer executable ... failed before program startup`,
or as a `stamped asan build no longer starts, rebuilding` warning during
build preflight. Run the configured binary by hand from the repository
root, for example:

```bash
targets/<target>/build-asan/path/to/binary
```

Common fixes:

- Rebuild with `bin/setup-target <target> --build`. Native recipes build
  with `clang` and the sanitizer flag, such as `-fsanitize=address`.
- Set `asan_bin` to the actual executable, or `[sanitizer].<name>_bin` for
  the opt-in UBSan, MSan, and TSan routes.
- Make runtime libraries discoverable, for example through the library path
  in `[runner].env`.
- Install `llvm-symbolizer` so diagnostics are readable.

## C harness compilation fails

`bin/probe` prints where the compiler output is:

```text
[probe] harness build failed: <harness source>
[probe] full compiler log: <path>
```

A later probe of the same source may say `cached harness build failure`
instead. Check these fields in `output/<target>/target.toml`:

```toml
asan_lib = "build-asan/path/to/libtarget.a"
includes = ["include", "build-asan/include"]
defines = ["-DPROJECT_FEATURE=1"]
link_libs = ["-lm", "-lpthread"]
```

Common fixes:

- Rebuild so setup refreshes generated include directories and link
  libraries: `bin/setup-target <target> --build`.
- Add missing include directories, compiler defines, or system libraries.
- Use the selected sanitizer's static library, not a release library or a
  different sanitizer's build. A missing one is reported as
  `target.toml <sanitizer>_lib missing: <path>`.

`bin/auto-repair-target-toml` can propose these edits from the compiler log.
Read [C harness readiness](../guides/configure-target.md#c-harness-readiness)
before accepting a proposal:

```bash
bin/auto-repair-target-toml --toml output/<target>/target.toml \
  --build-log <compiler log> --dry-run
```

## Triage rejects a crash

Open the rejected index in a browser:

```text
output/<target>/<backend>/results/crashes-rejected/rejected-crashes.html
```

Each rejected directory holds a `rejection.md` with its reason. The usual
ones (full list in
[Common rejection reasons](../guides/triage-results.md#common-rejection-reasons)):

- An automatically rejected diagnostic: null dereference, stack exhaustion,
  out-of-memory or allocation-size failure, intentional or debug assertion,
  runtime panic, or an abort with no sanitizer diagnostic. A timeout is a
  probe verdict and is never filed.
- `threat-model:`: the trigger needs a control outside `attacker_controls`.
  `unsettled-scope:`: completed review could not settle scope. Either way
  the evidence stays intact, with no security credit and no numeric CVSS.
- Two source-anchored reviews disproved the route.
- The bundle never completed (below).

A crash under `crashes/` with a `.promotion_pending` file is waiting on the
items that file lists, such as `report.md`, `reproduce.sh`, a valid
`sanitizer.txt`, or the testcase. Supply them; the next triage pass of a
running or resumed audit re-checks the crash. Leave the
`.promotion_pending.sig` and `.promotion_pending.count` counters alone.
After 10 passes with the same items missing (`CRASH_PROMOTION_PENDING_MAX`),
the crash moves to `crashes-rejected/` with a `bundle-incomplete:` or
`never-reproduced-under-sanitizer:` reason, and triage warns:

```text
POSSIBLE-FALSE-NEGATIVE: crashes/<id> aged out of crashes/ after <n>/<max> incomplete triage passes; missing artifact(s): <list>. ...
```

The sanitizer signal may still be real; read the preserved directory before
dismissing it.

If the result is genuinely in scope, fix the evidence; otherwise leave it
rejected so later sessions do not repeat it. An out-of-model trigger is
still worth reporting to maintainers as an engineering bug, but do not
refile the same mechanism under `findings/`. A separate FIND fits only a
distinct security-boundary violation that does not depend on the rejected
trigger.

## FIND is marked needs-content or pending-drop

Open the finding cluster table in a browser, then the FIND directory's
marker file:

```text
output/<target>/<backend>/results/findings/finding-clusters.html
```

- `.needs-content`: the FIND directory has no non-empty report. Write
  `report.md`.
- `.pending-drop`: the substance gate has Reject votes but not yet a
  quorum; the file shows the count and latest reason. A quorum (two by
  default) moves the directory to `findings-rejected/`, where
  `rejected-findings.html` records the reason. Nothing is deleted.

Add the missing concrete location, security impact, and reviewer-actionable
rationale; the edited report gets fresh votes. To keep a terse report a
human has reviewed, create `.reviewed` or `.keep` in the FIND directory. It
still needs complete boundary and trigger fields before it can receive a
final receipt.

## A build was not replaced, or a cell refuses to start

One rule drives these messages: a build a live run uses is never replaced,
because that run's evidence was measured against it. Most come from
`bin/benchmark`; the first row and `bootstrap refused` also affect ordinary
audits.

| Message | Meaning | What to do |
| --- | --- | --- |
| `build not replaced (another run is using ...)` | Another audit or benchmark holds this build. | Nothing. Work continues on the existing build. |
| `pinned benchmark build is not usable: <route> changed ...` | A route in the run snapshot no longer has the bytes its parent pinned. Cells verify; they never build. | Stop whatever rebuilds the named path, then start a new run id. This run stays valid only if that exact generation is restored. |
| `WARN: Cell <cell>: target source changed during the cell (<paths>); ...` | Tracked source changed during the cell (untracked testcases and generated output do not count). Artifacts are kept; the cell leaves the headline comparison. | See `cells/<cell>/source-drift.json`. Agents must not leave tracked target edits in place. |
| `WARN: Cell <cell>: target build changed during the cell (<problems>); ...` | A pinned build artifact changed. Artifacts are kept; the cell leaves the comparison and skips crash triage. | Find what rebuilt the target, and rerun in a new run id. |
| `WARN: Regenerate: crash triage skipped for <cell> — <reason>; ...` | Replay would execute a different pinned artifact. The cell keeps the verdicts reached on its own build; the rest stay unconfirmed. | Restore the named artifact generation and regenerate, or rerun the cell in a new run. |
| `targets/<target> is at a different source state than a live run (...)` | Another live run pinned a different source state of the same checkout. | Use a separate checkout, or wait. `--isolate-build` cannot help: both runs read one checkout. |
| `build-<sanitizer> is stale (changed: <paths>)` | A fresh run found source or a recipe newer than the native build, even after a rebuild attempt. Untracked, unignored files count, since they may be build inputs. A pinned resume never runs this check. | Delete a named path that an earlier run left behind; for a real source or recipe change, run `bin/setup-target <target> --build`. Then rerun. |
| `<route> changed since this run pinned it (<path>)` | A `--run-id` resume found different bytes than its completed cells used. | Start a new run id, or restore the named artifact and build stamp. |
| `<route> now selects ... instead of ...`, `<route> is no longer selected by target.toml` | The run-owned `target.toml` route no longer matches its build pin. | Restore the original run snapshot, or start a new run id. |
| `bootstrap refused ... the configured runner is in use` | `bin/setup-target` would replace a runner a live run holds. | Wait for that run, or use a separate checkout. |
| `WARN: Cell <cell>: target-tree artifacts have no benchmark owner (...)` | An agent wrote finding or crash evidence into the shared checkout, where no run can prove ownership. It is excluded from the cell's metrics; independent cell evidence still counts. | Move a report into the right cell's results only when its provenance is known. Agents must write to `RESULTS_DIR`. |
| `WARN: model-direct backend exited rc=<rc> after writing substantive evidence; ...` | The direct backend exited nonzero after producing valid evidence. The cell counts as an early terminal outcome, marked `(Nt)`, with its shorter wall, unless a stronger exclusion applies. | Read `backend.raw.log`. `--regenerate` recovers an older cell marked failed for this reason. |
| `<setting> was X for this run and is now Y` | A resume changed what defines the experiment: model, reasoning effort, agent security mode, `--budget-wall`, `--agents`, `--hold-direct`, target revision, or TokenFuzz revision. | Resume with the original settings, or start a new run id. `--replicates`, `--conditions`, and the finalize settings may change. |

## Still unsure

The fastest baseline:

```bash
bash tests/run-tests.sh                                   # does the harness work?
bin/setup-target <target>                                 # does target setup validate?
bin/audit --target <target> --backend <backend> 1         # does the orchestrator start?
ls output/<target>/<backend>/results/crashes output/<target>/<backend>/results/findings   # any artifacts?
```

If that does not settle it, [Getting help](../getting-help.md) says what to
include in a bug report.
