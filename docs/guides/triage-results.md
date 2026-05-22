# Triage Results

Triage keeps the output of a run useful to a maintainer. The rule is
simple:

- **Record every concrete security issue.**
- **Be strict about what stays in `crashes/`.**

A reproducible crash is the strongest kind of prioritisation evidence
there is. A non-crashing issue, or a security issue without a
sanitizer reproducer, belongs in `findings/` with a clear report.

## The four kinds of result

| Type | Directory | Use when |
| --- | --- | --- |
| Crash | `crashes/CRASH-NNN-N/` | A testcase produces sanitizer evidence or an accepted security-boundary violation. |
| Finding | `findings/FIND-NNN/` | Any concrete security issue — see below. |
| Rejected crash | `crashes-rejected/` | A crash candidate is low value, out of scope, or incomplete. |
| Needs-review crash | `crashes-needs-review/` | A borderline LLM-confirm rejection is requeued for another pass before hard rejection. |

`findings/` accepts any concrete security class — memory safety,
logic, auth, injection, info disclosure, crypto, race, boundary
violation, and so on. A sanitizer reproducer is *not* required.

`crashes-rejected/` is still part of the workflow — it stops the
harness from refiling the same low-value crash. Findings have a
separate substance gate:

- vacuous candidates get a `.needs-attention` marker;
- no-content directories get `.needs-content`.
- one LLM reject leaves the FIND in place with `.pending-drop`;
- once the reject quorum is reached, the FIND is quarantined under
  `findings-rejected/` instead of being deleted.

The in-place markers are visible as a `Status` column in
`findings/FINDING-CLUSTERS.html`. Address the marker, or touch
`.reviewed` to override. Quarantined FIND directories move out to
`findings-rejected/`.

## What a strong crash looks like

A strong crash artifact has:

- a runnable testcase;
- saved sanitizer output;
- a confirmation run when applicable;
- a report explaining the boundary and caller controls;
- a trigger source that fits `target.toml`;
- a root cause in target code, not in harness-only misuse.

The crash path is intentionally stricter than the finding path.
`crashes/` should help maintainers prioritise issues they can rerun
quickly. If the underlying concern is real but the crash evidence is
weak, keep the report as a FIND instead of forcing it through crash
triage.

Sanitizer classes that typically belong in `crashes/`:

- out-of-range read or write;
- container-overflow;
- stack-buffer-overflow;
- heap-buffer-overflow;
- heap-use-after-free;
- alloc-dealloc-mismatch;
- similar memory-safety diagnostics.

## Common rejection reasons

| Reason | Why it is rejected |
| --- | --- |
| Null dereference only | Usually no memory-safety impact unless a boundary violation is also shown. |
| OOM | Resource exhaustion alone is not the evidence this harness promotes. |
| Assertion-only abort | Debug assertion failures need a security boundary or sanitizer diagnostic. |
| Timeout-only behaviour | A hang needs a stronger impact story and reproduction discipline. |
| Harness-only misuse | The testcase violates a contract no real caller can violate. |
| Out-of-scope trigger | `Trigger source` is not listed in `attacker_controls`. |
| Missing files | No testcase, no sanitizer output, or an incomplete report. |

Before filing a similar crash, check:

```text
<RESULTS_DIR>/crashes-rejected/INDEX.html
```

For findings, scan `<RESULTS_DIR>/findings/FINDING-CLUSTERS.html` and
look for `NEEDS ATTENTION`. Those are FIND directories the LLM
substance review flagged as vacuous. Their `.needs-attention` files
explain why.

## Crash report fields

Every crash report is written in two formats side by side:

- `REPORT.md` — the source of truth.
- `REPORT.html` — auto-generated sibling, easiest to read in a
  browser (same content with the field table aligned, severity
  badge, and external links resolved).

Open either. Hand-edit `REPORT.md` only.

Crash reports include the human explanation and a `## Fields` table.
The rows are also emitted as bare-label lines. Triage reads the
bare-label form, and `REPORT.html` renders the table. The fields:

```text
Surface: network|library-api|library_popular|file|cli|tests|maint|internal|unknown
Trigger source: bytes|call-sequence|timing|race|protocol-state|env|fs-state
Caller contract: obeyed|violated|unspecified
Boundary:
Caller controls:
Trusted caller actions:
Parameter control: direct|mapped|harness-only|none
```

Notes:

- `Surface` describes where the crash is reachable from. You can
  write a short prefix (`library-api`, `cli`, `maint`, `tests`,
  `internal`, `network`, `file`) and `bin/reachability` will normalise
  it before computing the advisory severity. Canonical tiers are
  `network`, `library_popular`, `library`, `file`, `cli_production`,
  `dev_tool`, `internal`, and `unknown`. The short prefixes above are
  what you actually write in the field. An unset
  `Surface` defaults the calibration toward `unknown` and under-scores
  real findings, so make sure it is set.
- `Trigger source` must be one of the tokens listed in
  `attacker_controls` for the crash to stay in `crashes/`.
- `Parameter control` is especially important for C harnesses. It
  tells triage whether a value is externally controlled or only
  invented by the harness.

A typical exported `REPORT.md` looks like:

````markdown
# CRASH-001-1

## Fields

| Field                  | Value                                       |
|:-----------------------|:--------------------------------------------|
| Primitive              | heap-buffer-overflow READ of size 4         |
| Severity               | High                                        |
| Surface                | library-api (C harness calls xmlParseDoc)   |
| Trigger source         | bytes                                       |
| Caller contract        | obeyed                                      |
| Boundary               | Untrusted XML bytes parsed by libxml2.      |
| Caller controls        | XML document contents.                      |
| Parameter control      | direct                                      |
| Trusted caller actions | none                                        |
| Cluster                | C1                                          |
| Reproduction rate      | 5/5                                         |

Surface: library-api
Trigger source: bytes
Caller contract: obeyed
…

## Expected sanitizer output

==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address …
    #0 0x… in xmlNextChar parser.c:225
    #1 0x… in xmlParseCharRef parser.c:2403
…

## Reproduce

Run `./reproduce.sh /path/to/clean/libxml2`.
````

## Finding requirements

Findings live under:

```text
<RESULTS_DIR>/findings/FIND-NNN/
```

What every FIND needs:

- A report file at the FIND root: `report.md` or `description.md`.
- A concrete location — `file:function:line`, an endpoint, a config
  key, ….
- The security issue class — memory safety, auth bypass, injection,
  info disclosure, crypto, race, boundary violation, logic flaw, ….
- A rationale a reviewer can act on (impact, caller control, what
  is wrong).

A typical non-crashing FIND `report.md` looks like:

````markdown
# FIND-007

## Fields

| Field          | Value                                                  |
|:---------------|:-------------------------------------------------------|
| Class          | logic / authorization bypass                           |
| Severity       | Medium                                                 |
| Surface        | library-api                                            |
| Location       | src/policy.c:check_acl:142                             |
| Caller control | request bytes                                          |
| Cluster        | F3                                                     |

Class: authorization bypass
Surface: library-api
Caller controls: request bytes

## Issue

`check_acl` short-circuits to ALLOW when `policy_count == 0`, which is the
default for an uninitialised handle. A caller that obtains a handle without
calling `policy_load()` first will pass any ACL check.

## Impact

Untrusted clients can reach privileged operations before policy is loaded.

## How to verify

Trace `check_acl` callers; no testcase needed.
````

Findings do not need a runnable reproducer — the report is the
evidence. If you do have a testcase or saved sanitizer output,
include it alongside.

`report.html` is generated automatically as a sibling of `report.md`
and is usually the easiest way to read a finding — open it in a
browser. Do not hand-write it.

Optional but encouraged:

- `affected-files.txt`;
- a testcase;
- captured sanitizer output;
- screenshots;
- any other supporting artifact.

What does not belong:

- vague suspicion;
- "looks suspicious" without a nameable location;
- provably unreachable code.

Triage asks an LLM to filter out vacuous reports. Substantive
findings without a reproducer are kept.

When the LLM substance gate rejects a FIND once, the directory stays
put with `.pending-drop`. A later accept clears that marker. If the
reject quorum is reached, the directory moves to `findings-rejected/`
so QA can audit false rejects and recover anything worth keeping. Add
`.reviewed` or `.keep` when a human has confirmed the report is
intentionally terse.

## Exported crash bundle

Accepted crashes are converted into:

```text
CRASH-001-1/
  REPORT.md
  REPORT.html
  reproduce.sh
  input.<ext>
  harness.{c,cc,cpp,cxx} # when applicable
  sanitizer.txt
  .audit/
```

The audit-side originals move under `.audit/` for provenance. The
root files are the maintainer-facing interface. As above, hand-edit
`REPORT.md` only — `REPORT.html` is regenerated on every triage pass.

### Run a bundle

A maintainer can reproduce a bundle against their own clean
checkout:

```bash
cd path/to/CRASH-001-1
./reproduce.sh /path/to/clean/source
```

`reproduce.sh` is self-contained. It compiles or launches the right
ASan runner against the input next to it, prints the running
command, and exits with the ASan exit code. The last line is always
`[repro] exit=<n>`. For a crashing bundle, a non-zero exit
accompanied by ASan output in stderr is a successful reproduction.

The script needs:

- a clean source checkout at the revision recorded in `REPORT.md`
  (or a close-enough revision — small drift is usually fine);
- a working `clang` / `clang++` with ASan support on `PATH`;
- whatever build-system dependencies the target needs (CMake,
  Mercurial, …). The script may rebuild the ASan target on first
  run.

For browser targets, `reproduce.sh` launches the configured ASan
browser binary against a `file://` URL pointing at the bundled
`input.html`. For C harness bundles, it compiles `harness.c` against
the target's static library before invoking it against
`input.<ext>`. Header-only C++ libraries omit the static-library
link automatically (see
[Target config reference](../reference/target-toml.md#header-only-libraries)).

## Clusters and duplicates

Crashes and findings are clustered after triage. A maintainer
looking at the result tree sees families rather than a wall of
independent entries.

```text
crashes/
  CRASH-CLUSTERS.md
  CRASH-CLUSTERS.html
  CRASH-001-1/REPORT.md          ← Cluster: C1
  CRASH-001-1/REPORT.html
  CRASH-001-2/REPORT.md          ← Cluster: C1, .dup-of -> CRASH-001-1
  CRASH-002-1/REPORT.md          ← Cluster: C2
findings/
  FINDING-CLUSTERS.md
  FINDING-CLUSTERS.html
  FIND-001/report.md             ← Cluster: F1, Dedup key: [llm] auth/check-acl-zero-policy
  FIND-001/report.html
  FIND-007/report.md             ← Cluster: F1, .dup-of -> FIND-001
```

How the cluster files and markers work:

- `CRASH-CLUSTERS.html` and `FINDING-CLUSTERS.html` are the browser
  review pages — one row per cluster, with severity, member count, and
  the canonical member. The `.md` siblings are generated source files.
- Each report has a `Cluster: <ID>` line. For FINDs, a second line
  `Dedup key: [<source>] <token>` records the signature that grouped
  it. `[layer1]` is the deterministic (class, file, function) key.
  `[llm]` is the LLM-chosen canonical token shared across reports of
  the same root cause filed from different surface sites.
- Non-canonical members carry a `.dup-of` file naming the canonical
  member. They are **not** deleted — a duplicate may still carry a
  useful variant or a clearer reproducer. Treat the canonical member
  as the primary report.

Review a cluster top-down:

1. Open `CRASH-CLUSTERS.html` or `FINDING-CLUSTERS.html`.
2. Follow the canonical member.
3. Skim the `.dup-of` siblings only if you need additional
   reproducers or variant inputs.

Use the backend-local HTML tables when reviewing one run:

```text
output/<target>/<backend>/results/crashes/CRASH-CLUSTERS.html
output/<target>/<backend>/results/findings/FINDING-CLUSTERS.html
```

Use the target-root HTML tables when comparing every backend for a
target:

```text
output/<target>/CRASH-CLUSTERS.html
output/<target>/FINDING-CLUSTERS.html
```

## Maintenance Commands

These are maintenance commands for regenerating or enriching artifacts
after manual edits. They are not needed for normal review; read the
generated HTML pages first.

```bash
export RESULTS=output/<target>/<backend>/results
bin/cluster-crashes "$RESULTS"
bin/cluster-findings "$RESULTS"
bin/cluster-crashes output/<target>
bin/cluster-findings output/<target>
bin/show-exclusions "$RESULTS"
bin/export-repro CRASH-001-1 --slug <target>
bin/reachability --report "$RESULTS/crashes/CRASH-001-1/" --severity-only
bin/reachability --batch "$RESULTS"
```

What each command does:

- `bin/export-repro` — builds the handoff bundle.
- `bin/reachability --severity-only` — updates severity metadata
  without public code-search queries. Run without that flag only
  when external caller context is intended.
- `bin/cluster-crashes` and `bin/cluster-findings` — group reports
  that share a root cause, write the cluster summaries, and stamp
  `Cluster:` and `Dedup key:` lines into each report. Both run
  automatically during triage. Rerun them by hand after manually
  editing reports or moving artifacts.

## Triage mindset

**Promote evidence, not ideas.**

- A crash should be easy for a maintainer to rerun, understand, and
  map back to a real input boundary.
- A finding should be concrete enough that a reviewer knows what
  code or behaviour to inspect.
- Everything else belongs in state, scratch, or rejected indexes
  until it becomes real evidence.
