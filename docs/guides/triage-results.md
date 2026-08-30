# Triage and Review

TokenFuzz preserves evidence in four result lanes. Triage decides which lane an
artifact belongs in and records the decision beside the files it judged. It
does not replace a security team's review or the upstream project's disclosure
process.

Start with the generated HTML indexes:

```text
output/<target>/<backend>/results/findings/FINDING-CLUSTERS.html
output/<target>/<backend>/results/crashes/CRASH-CLUSTERS.html
output/<target>/<backend>/results/findings-rejected/REJECTED-FINDINGS.html
output/<target>/<backend>/results/crashes-rejected/REJECTED-CRASHES.html
```

Do not begin with a raw model transcript. The indexes join the report, current
review state, severity, evidence signature, and canonical cluster member.

## The four result lanes

| Lane | Directory | Contract |
| --- | --- | --- |
| Finding | `findings/FIND-*/` | A concrete security report with a location, issue class, and actionable rationale. A testcase is optional. |
| Crash | `crashes/CRASH-*/` | A reproducible sanitizer or runtime-race diagnostic with saved input and output. |
| Rejected finding | `findings-rejected/` | A FIND whose evidence lost at the substance or source-review gates. |
| Rejected crash | `crashes-rejected/` | A crash candidate that was incomplete, low-value, contradicted by source, or rooted in harness-only misuse. |

Nothing is silently deleted. Rejected directories move with their evidence and
gain an index entry explaining why. A crash may also stay under `crashes/` as
`not-reportable`: review accepted the engineering defect but found that its
trigger crosses no configured security boundary.

## A practical review order

For each canonical row in a cluster index:

1. Read the Status or publication state.
2. Open `REPORT.html` for a crash or `report.html` for a finding.
3. Check the root `Location`, boundary, caller controls, trigger source, and
   caller contract against the source.
4. For a crash, run `reproduce.sh` in an isolated build environment and compare
   the new diagnostic with `sanitizer.txt`.
5. Read the severity rationale only after the technical claim holds.
6. Skim duplicate members only when they provide a better input, another
   carrier, or useful variant evidence.

The generated CVSS v4.0 score is advisory. It derives from report and review
fields; it does not know deployment-specific privileges, asset value, or the
upstream maintainer's threat model.

## How automated review works

Crashes and findings start from different evidence, so they do not use the same
first gate.

| Stage | Crash | Finding |
| --- | --- | --- |
| Mechanical or substance gate | Checks diagnostic class, reproduction files, report fields, caller contract, and auto-rejection classes. | Independent readers judge whether the report names a concrete security issue. Two accepts admit it; two rejects quarantine it. |
| Source review | Reads the trigger and caller contract. Two source-anchored Reject votes are required to quarantine sanitizer-confirmed evidence. | Reads both the trigger and the exact claimed consequence. Two source-anchored Reject votes are required to quarantine an admitted FIND. |
| Final state | `reportable`, `not-reportable`, `pending`, or `rejected`. | The same four states. |

Both source-review paths fail open: missing, malformed, or inconclusive model
output cannot destroy an artifact. Fail-open means *preserved and unsettled*,
not confirmed. A first `Uncertain` vote or a split review gets one focused
resolver that sees the prior rationales. If the resolver still cannot settle
the question, the artifact remains pending.

Review receipts are content-addressed. Changing the authored report, testcase,
harness, diagnostic, invocation evidence, target revision, config, or threat
model invalidates the old decision and reopens review. Generated cluster,
severity, patch-rendering, and enrichment annotations do not.

## Publication state

Open `validation.json` when the index is not enough:

| State | Final? | Meaning |
| --- | --- | --- |
| `reportable` | yes | Review found real security impact inside the declared attacker surface. This is the only state with a numeric severity or security-yield credit. |
| `not-reportable` | yes | A real engineering defect needs a control outside the threat model or violates an admitted caller contract. It stays visible and unscored. |
| `pending` | no | Review did not settle the claim. It is neither credited nor written off. |
| `rejected` | yes | The evidence did not hold. The artifact is preserved in a rejected tree. |

“Filed,” “admitted,” and “reportable” are deliberately different. An agent can
file a FIND; the substance gate can admit it; only a current final receipt says
whether it is a security result to report.

### The finding Status column

`findings/FINDING-CLUSTERS.html` presents common working states in a compact
column:

| Status | Meaning |
| --- | --- |
| `OK` | A report is present and no content, attention, or severity marker is active. Check `validation.json` for publication state. |
| `NOT-REPORTABLE (no security credit)` | A current receipt retains the engineering evidence outside the security total. |
| `NEEDS CONTENT` | No `report.md` or `description.md` exists (`.needs-content`). |
| `NEEDS REVIEW` | The issue class is too vague for a trustworthy severity vector. |
| `NEEDS ATTENTION` | A human-created `.needs-attention` marker requests review. |
| `OK (override)` | A `.reviewed` or `.keep` marker requests a human override. |

`.pending-drop` is working state: at least one finding-quality Reject exists,
but reject quorum has not been reached. Fix the report and let it receive fresh
votes. A human override can pin an intentionally terse report past the quality
gate, but complete boundary and trigger fields are still required before a
final receipt is written.

## Common rejection reasons

### Crash candidates

Three non-reportable outcomes require different operator action:

| Disposition | Typical reason | What happens |
| --- | --- | --- |
| Hard rejection | Near-null dereference, OOM only, assertion or panic only, plain stack overflow, a fault rooted in the audit harness, or two source-anchored reviews disproving the route | The directory moves to `crashes-rejected/` with the reason. |
| Promotion pending | The testcase, saved diagnostic, report, required fields, or exported invocation is incomplete; source review may also remain unsettled | The directory stays under `crashes/` with a pending receipt. Repeatedly incomplete promotion work eventually ages into rejection. |
| Retained `not-reportable` defect | The report admits a caller-contract violation or harness-only parameter, or source review places the required trigger outside `attacker_controls` | The reproducible engineering evidence stays under `crashes/`, final and unscored. |

An out-of-model trigger is not itself a hard rejection. Keep a retained defect
where it is rather than filing the same mechanism again as a security issue.

### Finding candidates

A FIND needs a security boundary and a concrete consequence, not merely a
dangerous-looking API. Common rejected shapes include:

| Rejected shape | Evidence that would make it substantive |
| --- | --- |
| Correctness or spec deviation | The independent security boundary the target is responsible for enforcing. |
| Path escape where one untrusted value chooses both base and child | A separately trusted root, authorization decision, or different capability reached by the escape. |
| Loading an outside file the attacker cannot place | A shipped effectful module or attacker-controlled placement inside the threat model. |
| Deserialization or reflection reaches only a sink | A reachable gadget, hook, authorization effect, or memory consequence in the actual environment. |
| Resource exhaustion from a caller-controlled count | Quantified amplification that survives the product's own input ceiling. |
| Residual-memory disclosure with no source allocation | The buffer, field, allocation, or prior operation the bytes came from. |
| Caller-owned pointer or lifetime misuse | A public product path through which untrusted input drives the parameter into that state. |

A thin but concrete security case should remain visible. These gates reject
missing substance, not imperfect writing.

## Review a crash

A strong crash contains:

```text
CRASH-*/
  REPORT.md
  REPORT.html
  reproduce.sh
  input.<ext>
  harness.*             # when an API harness is required
  sanitizer.txt
  validation.json
  severity.json         # only for a currently reportable artifact
  patch.diff             # optional candidate fix
  .audit/                # audit-side originals
```

Check that the saved output names a sanitizer class and faults in target code,
that the bundled input or harness can be rerun, and that the report explains
how a normal product entry reaches the fault. A confirmation rate is useful,
but it does not turn harness-only state into attacker reachability.

The maintainer-side procedure is in
[Reproduce a crash](reproduce-a-crash.md). Treat `reproduce.sh` and the target's
build system as untrusted code: inspect them and run them in an isolated
environment without credentials.

## Review a finding

A FIND needs a Markdown report at its root (`report.md` or `description.md`).
The minimum useful report contains:

- exactly one bare `Location:` naming the root-cause operation, endpoint,
  config key, or protocol step;
- an explicit security issue class;
- the boundary, caller-controlled input, trusted setup, caller contract, and
  trigger source;
- a short explanation of what is wrong and what capability or data is lost;
- the strategy that produced it.

A reproducer, captured output, `affected-files.txt`, or a small generator is
welcome but optional. Do not use symlinks inside a FIND bundle.

The shared report narrative is Summary, Root Cause, Data Flow, Impact, and Fix
Direction. The exact order and word budgets are in
[Artifact layout](../reference/artifacts.md#report-narrative). Generated
`report.html` is the easiest reading view; edit the Markdown source only.

## Structured report fields

Triage parses bare-label fields from crash and finding reports. Important ones
include:

```text
Location: path/to/file.ext:function:line
Surface: network|library-api|file-format|cli|dev-tool|internal|unknown
Reproducer carrier: network|library-api|file-format|cli|harness|runner|unknown
Trigger source: bytes|both|call-sequence|timing|race|protocol-state|env|fs-state
Caller contract: obeyed|violated|unspecified
Boundary:
Caller controls:
Trusted caller actions:
Parameter control: direct|indirect|application-supplied|trusted|harness-only
Strategy: S1|S2|S3|S4|S5|S6|S7|S8|REF
```

`Surface` names the vulnerable product boundary; `Reproducer carrier` names
the program or harness used to reach it. `Trigger source` records what actually
decides the fault, not every setup call the driver makes. `Parameter control`
matters when a compiled harness supplies a value the external input does not
directly choose.

`Cluster`, `Dedup frames`, severity text, and patch rendering are written by
the harness. Do not hand-author those generated sections.

## Clusters and duplicates

The two accepted lanes use different deterministic signatures:

- crashes cluster by sanitizer primitive and normalized top stack frames;
- findings cluster by an exact normalized `(class, file, line)` site or a
  matching crash state.

Each cluster has a canonical member. Non-canonical members remain on disk with
a `.dup-of` marker because they may carry a useful input or route variant. A
cluster is a review aid, not proof that every member shares one fix.

Use backend-local indexes for one run and target-root indexes to compare all
backends:

```text
output/<target>/<backend>/results/crashes/CRASH-CLUSTERS.html
output/<target>/<backend>/results/findings/FINDING-CLUSTERS.html
output/<target>/CRASH-CLUSTERS.html
output/<target>/FINDING-CLUSTERS.html
```

[Deduplication](../concepts/deduplication.md) documents the exact signatures
and canonical-member rules.

## Maintenance commands

Normal triage performs validation, export, severity, rendering, and clustering
automatically. After a deliberate manual edit, these commands regenerate the
derived views:

```bash
export RESULTS=output/<target>/<backend>/results

bin/export-repro CRASH-001-1 --slug <target>
bin/severity --report "$RESULTS/crashes/CRASH-001-1"
bin/severity --batch "$RESULTS"
bin/cluster-crashes "$RESULTS"
bin/cluster-findings "$RESULTS"
bin/show-exclusions "$RESULTS"
```

`bin/severity --batch` scores reportable crashes and findings. Pending and
not-reportable artifacts remain unscored. Re-run clustering after changing a
root location or other identity field.

When the evidence is ready for upstream, send the report and bundle through the
project's coordinated-disclosure process. TokenFuzz never publishes or files
an upstream advisory automatically.
