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

A trigger source outside `attacker_controls` is **not** a rejection
reason — such crashes stay in `crashes/` with a contract concern and
a lower severity. See
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
- `.pending-drop` — the LLM substance gate has rejected the report
  once. A second reject moves the directory to `findings-rejected/`.

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
