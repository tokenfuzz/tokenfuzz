# Troubleshooting

Most TokenFuzz failures fall into a small number of categories:

- missing host tools;
- target config that does not match the build;
- sanitizer binaries that do not run on their own;
- backend CLIs that are not authenticated.

This page is organised by symptom. Find the heading closest to what
you see, and start there.

For normal audit progress, the index files under `crashes/`,
`findings/`, and `crashes-rejected/` are the right first stop. Raw
logs are usually only useful when a backend CLI or wrapper itself
failed.

## Preflight fails

Symptom:

```text
FATAL: missing required tool(s): ...
```

Fix:

1. Install the named tools.
2. Re-run:

   ```bash
   bash tests/run-tests.sh
   ```

3. Start the audit again.

## Target config does not parse

Common fixes:

- Refresh with `bin/setup-target <target>` after the ASan build
  exists.
- Remove placeholder values for fields needed by this run.
- Quote string values. Keep arrays valid TOML.
- Remove invalid section headers — the loader fails fast on them.
- Confirm `target` matches the directory slug.

## Sanitizer binary does not run

Run the configured binary by hand from the target root. For the
default ASan path:

```bash
cd targets/<target>
./build-asan/path/to/binary
```

Common fixes:

- Rebuild with `clang` and `-fsanitize=address`.
- Refresh generated config with `bin/setup-target <target>`.
- Set `asan_bin` to the actual executable, or set
  `[sanitizer].<name>_bin` for opt-in UBSan, MSan, or TSan
  runners.
- Ensure runtime libraries are discoverable.
- Install `llvm-symbolizer` so diagnostics are readable.

## A build was not replaced, or a cell refuses to start

These messages all come from one rule: a build in use by a live run is never
replaced, because the evidence that run already recorded was measured against
it.

| Message | Meaning | What to do |
| --- | --- | --- |
| `build not replaced (another run is using ...)` | Another audit or benchmark holds this build. | Nothing. The existing build stays and work continues on it. |
| `pinned benchmark build is not usable: <route> changed ...` | A cell found that a route selected by the run snapshot no longer has the bytes its parent pinned. Cells verify and never build. | The message names the path. Stop the process rebuilding it, then start a new run id; this run remains valid only if that exact generation is restored. |
| `target source changed during the cell` | The revision or tracked source differs at the end-of-cell boundary. Untracked testcases and generated output do not trigger this. Artifacts are kept; the cell leaves the headline comparison. | Check `cells/<cell>/source-drift.json` for the paths. Agents must not leave tracked target edits in place. |
| `crash triage skipped ... <route> changed` | Replay would execute a different pinned target artifact, so finalization kept the original evidence untouched. | Restore the named artifact generation or rerun the cell in a new run. |
| `is at a different source state than a live run` | A benchmark refused to start: another live run pinned a different source state. | Use a separate checkout, or wait for that run. `--isolate-build` cannot fix this — both runs read one checkout. |
| `build-<san> is stale (changed: <paths>)` | A fresh run found source or a build recipe newer than the available native build. This check is never used for a pinned resume. | Remove an accidental generated path, or run `bin/setup-target <target> --build` for a real source/recipe change, then rerun the fresh benchmark. |
| `<route> changed since this run pinned it (<path>)` | A `--run-id` resume found different bytes than its completed cells used. | Start a new run id, or restore the named artifact and build stamp. The refusal leaves the recorded pin unchanged. |
| `<route> now selects ... instead of ...`, `<route> is no longer selected by target.toml` | The run-owned `target.toml` execution route no longer matches its build pin. A missing or unexecutable file is reported as that artifact instead, not as this. | Restore the run snapshot from the original run, or start a new run id with the new configuration. |
| `bootstrap refused ... the configured runner is in use` | `bin/setup-target` would replace a runner an audit or benchmark is holding. It refuses immediately rather than waiting out the lease. | Wait for that run, or use a separate checkout. |
| `target-tree artifacts have no benchmark owner` | An agent wrote a finding or crash into the shared target checkout, where no run can prove ownership. The evidence remains on disk and the observing cell leaves the comparison. | Move the report into the correct cell results directory only when its provenance is known; agents should always use `RESULTS_DIR`. |
| `<setting> was X for this run and is now Y` | A resume changed something that defines the experiment (model, effort, budget, agents, target revision). | Resume with the original settings, or start a new run id. `--replicates` and `--conditions` may still change. |

Initial build freshness conservatively includes non-ignored untracked files,
because they may be build inputs; ignored output and reverted edits leave it
fresh. A build reported stale names the paths that made it so, which is what
separates a by-product a previous run wrote into the checkout — delete it — from
a real source edit — rebuild. Once a benchmark pins a build, its cells and
resumes use only the run-owned config snapshot and exact recorded bytes. They
do not call freshness, so those by-products cannot make an unchanged pinned
build read as stale.

## C harness compilation fails

Check `output/<target>/target.toml`:

```toml
asan_lib = "build-asan/path/to/libtarget.a"
includes = ["include", "build-asan/include"]
defines = ["-DPROJECT_FEATURE=1"]
link_libs = ["-lm", "-lpthread"]
```

Common fixes:

- Refresh generated config after the ASan build exists.
- Add generated include directories.
- Add required compile-time defines.
- Add required system libraries.
- Use the selected sanitizer's static library, not a release
  library or a different sanitizer build.

## Triage rejects a crash

Open the rejected index in a browser:

```text
output/<target>/<backend>/results/crashes-rejected/REJECTED-CRASHES.html
```

Common reasons:

- Report fields are missing.
- The crash is OOM, assertion-only abort, timeout-only behaviour,
  or a plain null dereference.
- The testcase violates a caller contract that real product input
  cannot violate.

If the crash is still under `crashes/` with `.promotion_pending`, read that
marker first. Triage is waiting for an enriched report, a valid sanitizer
diagnostic, a testcase, or a complete exported bundle. Fix the named artifact
and rerun triage. The adjacent signature and count files are internal progress
state; do not delete or edit them.

A trigger source outside `attacker_controls` is **not** a rejection
reason — such crashes stay in `crashes/` as `not-reportable` engineering
defects, without security credit or numeric CVSS. See
[Triage results](../guides/triage-results.md#common-rejection-reasons).

Fix the evidence if the result is genuinely in scope. Otherwise
leave it rejected so future sessions do not repeat it.

If the underlying issue is real but the crash is rejected for
caller-contract or trigger-source reasons, keep a substantive
report in `findings/` instead of trying to force the crash
through `crashes/`.

## FIND is marked needs-content or pending-drop

Open the finding cluster table in a browser:

```text
output/<target>/<backend>/results/findings/FINDING-CLUSTERS.html
```

Then open the FIND directory and read the marker file:

- `.needs-content` — the FIND directory has no `report.md` or
  `description.md`. Write one.
- `.pending-drop` — a substance-gate pass ended with Reject votes below
  quorum. Reaching quorum moves the directory to `findings-rejected/`.

Add the missing concrete location, security impact, and
reviewer-actionable rationale, then rerun triage. If a human has
reviewed the terse report and wants to keep it as-is, `touch
.reviewed` or `.keep` inside the FIND directory.

## An agent looks stuck

Check the timestamp on the agent's most recent log line:

```bash
ls -lt output/<target>/<backend>/logs/session_*.log | head -3
tail -5 output/<target>/<backend>/logs/index.log
```

A long-running sanitizer build or a slow backend turn can look like
a hang for several minutes; that is normal. If an agent genuinely
wedges or is killed, the run self-heals: work-card claims expire on
a timer, so the next iteration reclaims its card and resumes from
structured state. You do not need to clean anything up by hand.

## The run paused, or the backend went unavailable

A hosted account or session usage limit does not end a run. `bin/audit` pauses
and retries, and `logs/index.log` says so:

```text
Provider capacity limited; pausing 1800s before retry
```

What to expect:

- The pause lasts until the provider's reported reset time, or 30 minutes if
  the backend reports none. Waiting is capped at six hours.
- Paused time does **not** count against `AUDIT_WALL_BUDGET_SECS`, so a quota
  pause never eats an overnight budget.
- Transient (non-quota) failures are retried separately with backoff.

If the backend never comes back, the run exits with status `2` after logging
`BACKEND_UNAVAILABLE`. In ensemble mode (`--backend all`) the exhausted backend
is dropped from the rotation and the others keep working.

Nothing needs cleaning up. Rerunning the same command resumes from the run's
saved state.

A continuous run can also stop on its own without any provider problem. If
`index.log` ends with `STALL_STOP`, ten iterations in a row produced nothing
and no hypothesis was left open — the run decided it was done rather than
burning budget. Raise `MAX_DRY_SESSIONS` if you expect the target to be that
slow, or take it as a signal to revisit the threat model and work queue.

## Backend CLI fails

Check:

```text
output/<target>/<backend>/logs/
```

Then run the backend CLI outside the harness to confirm authentication
and basic execution. For local models, confirm the selected provider is
running and serving the expected model:

```bash
curl http://127.0.0.1:8000/v1/models
# or, for Ollama:
curl http://127.0.0.1:11434/v1/models
```

Use an explicit backend while debugging:

```bash
bin/audit --target <target> --backend <backend> 1
```

## Still unsure

The fastest baseline is:

```bash
bash tests/run-tests.sh
bin/setup-target <target>
bin/audit --target <target> --backend <backend> 1
ls output/<target>/<backend>/results/crashes output/<target>/<backend>/results/findings
```

Those four commands answer:

- Does the harness work?
- Does target setup validate?
- Does the orchestrator start?
- Did the run produce artifacts?
