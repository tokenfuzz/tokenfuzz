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
- Remove invalid section headers (for one-off migration of existing
  configs, run with `TARGET_TOML_LENIENT=1`).
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
output/<target>/<backend>/results/crashes-rejected/INDEX.html
```

Common reasons:

- The trigger source is outside `attacker_controls`.
- Report fields are missing.
- The crash is OOM, assertion-only abort, timeout-only behaviour,
  or a plain null dereference.
- The testcase violates a caller contract that real product input
  cannot violate.

Fix the evidence if the result is genuinely in scope. Otherwise
leave it rejected so future sessions do not repeat it.

If the underlying issue is real but the crash is rejected for
caller-contract or trigger-source reasons, keep a substantive
report in `findings/` instead of trying to force the crash
through `crashes/`.

## FIND is marked needs-attention

Open the finding cluster table in a browser:

```text
output/<target>/<backend>/results/findings/FINDING-CLUSTERS.html
```

Then open the FIND directory's `.needs-attention` or
`.needs-content` marker. The directory is not rejected or
deleted.

Add the missing concrete location, security impact, and
reviewer-actionable rationale, then rerun triage. If a human has
reviewed the terse report and wants to keep it as-is, add
`.reviewed` or `.keep`.

## Backend CLI fails

Check:

```text
output/<target>/<backend>/logs/
```

Then run the backend CLI outside the harness to confirm
authentication and basic execution. For local models, confirm
Ollama is running:

```bash
ollama list
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
