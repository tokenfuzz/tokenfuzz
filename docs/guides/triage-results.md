# Triage and review

This page is for the reviewer who decides which TokenFuzz results are ready
for a human security decision or an upstream report. By the time you look,
the harness has already reviewed every artifact: it checked the evidence,
had independent model reviewers read the report and the target source, and
recorded a publication state beside each artifact. Your job is to confirm
that the claim holds and to decide what to send upstream.

Start with the generated HTML indexes, not a raw model transcript:

```text
output/<target>/<backend>/results/findings/finding-clusters.html
output/<target>/<backend>/results/crashes/crash-clusters.html
output/<target>/<backend>/results/findings-rejected/rejected-findings.html
output/<target>/<backend>/results/crashes-rejected/rejected-crashes.html
```

Each index joins the report, its review state, severity, evidence
signature, and cluster, and has a Markdown twin (`.md`) beside it.
`output/<target>/finding-clusters.html` and
`output/<target>/crash-clusters.html` combine every backend's accepted
results; the rejected indexes exist per backend only.

TokenFuzz never publishes or files anything upstream. The security team and
the upstream maintainer decide what to fix and how to disclose it.

## The four result lanes

| Lane | Directory | Contract |
| --- | --- | --- |
| Finding | `findings/FIND-*/` | A concrete security report with a location, an issue class, and an actionable rationale. A testcase is optional. |
| Crash | `crashes/CRASH-*/` | A reproducible sanitizer or race-detector diagnostic with the saved input and output. |
| Rejected finding | `findings-rejected/` | A FIND that failed substance, source, or publication review. The reason separates a disproved claim from an out-of-scope or unsettled one. |
| Rejected crash | `crashes-rejected/` | A crash candidate that was a non-security class, rooted in the audit's own harness, never completed, disproved by source review, or outside the threat model. |

Nothing is deleted. A rejected directory keeps its evidence, gains a
`rejection.md` whose `Reason:` line says why, and appears in the rejected
index. A real defect that crosses no configured security boundary is
rejected the same way, with a `threat-model:` reason, so the active lanes
hold only security results and work still under review. The exception is a
human-pinned FIND (see [The Status column](#the-status-column)); trees
written by older versions can also carry a `not-reportable` artifact in
place.

Triage also moves artifacts between the active lanes. The first two moves
append a `## Triage disposition` note to the report:

- A FIND with its own memory-safety sanitizer diagnostic and a runnable
  testcase moves to `crashes/`; without the testcase it stays a finding
  with a `.crash-lead.json` marker.
- A CRASH with no memory-safety signal (a language-runtime error, or an
  undefined-behaviour class that is not memory safety), or whose harness
  compiles target source instead of linking the pinned build, moves to
  `findings/` for good.
- A memory-safety FIND at the exact source line of a filed crash moves under
  it as `.companion/<FIND-id>/` and follows its verdict; a crash bundle that
  duplicates a reportable one moves to `crashes/.duplicates/` (see
  [Deduplication](../concepts/deduplication.md)).

## A practical review order

For each canonical row in a cluster index:

1. Read the Status column. Only `accepted` (`OK` in the Markdown index) is a
   current reportable result.
2. Open the artifact's `report.html`.
3. Check the root `Location`, `Boundary`, `Caller controls`,
   `Trigger source`, and `Caller contract` against the target source.
4. For a crash, run `reproduce.sh` in an isolated environment and compare
   the new diagnostic with `sanitizer.txt`
   ([Reproduce a crash](reproduce-a-crash.md) has the procedure).
5. Read the severity rationale only after the technical claim holds.
6. Open other cluster members only when they may carry a better input,
   another route, or useful variant evidence.

## How automated review works

Crashes and findings start from different evidence, so they pass different
first gates and then meet the same source review.

### Crash review

1. **Duplicate check.** A bundle with the same crash state through the same
   probe route as an already-reportable crash is folded into it.
2. **Diagnostic gate.** A non-security diagnostic class, or a fault rooted
   in the audit's own harness, is rejected at once (see
   [Crash candidates](#crash-candidates)).
3. **Completeness.** The bundle needs an enriched `report.md` (not the
   skeleton `bin/probe` filed), a valid sanitizer diagnostic, and a
   testcase or harness. An incomplete bundle stays pending; after ten
   passes with the same items missing (`CRASH_PROMOTION_PENDING_MAX`) it is
   rejected with a `POSSIBLE-FALSE-NEGATIVE` warning.
4. **Lane check.** A diagnostic without a memory-safety signal, or a harness
   that compiles target source, moves the artifact to `findings/`.
5. **Export and fields.** `bin/export-repro` builds the maintainer bundle,
   and a model fills missing [structured fields](#structured-report-fields).
   A report with neither `Caller contract` nor `Trigger source` stays
   pending and ages out like an incomplete bundle.
6. **Source review** (below). A crash that `bin/probe --confirm` reproduced
   5/5 through the target's plain byte-input invocation (no harness, no
   extra arguments, fault in target source) already has a machine proof of
   reachability and skips that question.
7. **Publication.** The receipt is written and a reportable crash scored.

### Finding review

1. **Companion check.** A memory-safety FIND at the exact line of a filed
   crash becomes that crash's companion.
2. **Availability check.** A denial-of-service class with no `Primitive`
   naming a stronger consequence is rejected before any vote, with an
   `out-of-scope:` reason.
3. **Substance gate.** Independent model reviewers read the report (not the
   source) and vote on whether it proves a concrete security issue. Two
   accepts admit it, two rejects move it to `findings-rejected/`, and at
   most three votes are cast. One reject without a quorum leaves a
   `.pending-drop` marker.
4. **Fields.** Missing fields are filled as for crashes. A report whose
   caller contract and trigger source still cannot be determined is
   rejected with an `unsettled-scope:` reason.
5. **Source review** (below).
6. **Publication.** The receipt is written and a reportable finding scored.

### Source review

The source reviewer is an independent agent session with read access to the
target source and a bounded tool budget. It asks whether an attacker can
actually reach the claimed trigger and whether the claimed consequence
survives reading the code. It votes `Promote`, `Reject`, or `Uncertain` and
records:

- source anchors (exact `path`, `line`, `symbol`, and excerpt), which the
  harness re-reads from the checkout; a `Promote` or `Reject` without
  verified anchors does not count;
- `trigger_controls_fit`: `within`, `outside`, or `unclear`, the reviewer's
  own comparison of the trigger with the target's `attacker_controls`. This,
  not the report's self-declared `Trigger source`, decides scope;
- for a Reject, a `rejection_kind`: `unreachable`, `contract-invalid`,
  `nonshipping`, `consequence-disproved`, or `no-added-boundary`.

| Situation | Outcome |
| --- | --- |
| Two anchored Rejects whose kinds are all disproofs (`unreachable`, `contract-invalid`, `nonshipping`; for a finding also `consequence-disproved`) | Rejected with a `trigger-provenance` reason. |
| Two reviewers agree on `no-added-boundary` | Rejected as `threat-model: real defect that crosses no security boundary`. |
| Settled scope is `outside` | Rejected with a `threat-model:` reason naming the controls. |
| Settled scope is `within` | `reportable`. |
| Crash: first vote is `Promote` with settled scope | Settles it. A crash is machine-reproduced, so one reader suffices. |
| Finding: first vote is `Promote` | A second reviewer reads it through a reachability lens before it publishes. |
| A split, an `Uncertain`, or a `Promote` that left scope `unclear` | A focused resolution review reads the prior reviews and settles their disagreement. |
| Every review has answered and scope is still open | Rejected with an `unsettled-scope:` reason. |
| Review output missing, malformed, or cut off by the wall | `pending`, evidence kept, retried on a later pass. |

A single Reject never removes an artifact, even from the resolution review.

### Receipts and re-review

Each decision is recorded in a content-addressed `validation.json`, bound to
the report, testcase, harness, sanitizer diagnostic, invocation evidence,
review files, target revision and configuration, the threat model
(`attacker_controls`), and the source lines the reviewers cited. Changing
any of them returns the artifact to review; a cited line invalidates the
receipt only when read against the checkout it was written for.
[Publication receipts](../reference/artifacts.md#publication-receipts) has
the exact binding.

Harness-generated report content does not reopen review: the `Cluster:`,
`Dedup key:`, and `Severity` lines, the `## Severity rationale`,
`## Patch`, and `## Contract concern` sections, and enrichment blocks.

## Publication state

`validation.json` holds one of four states. Only `pending` is still open.

| State | Meaning |
| --- | --- |
| `reportable` | Review found real security impact inside the declared attacker surface. The only state with a numeric severity or security credit. |
| `pending` | Required content or review is incomplete. No security credit while it waits. |
| `rejected` | The claim failed a gate, lay outside the threat model, or could not be placed inside it after every review answered. The artifact is kept in a rejected tree. |
| `not-reportable` | A real defect that crosses no security boundary, kept in place without security credit or numeric severity. Current triage writes it only for a human-pinned finding; older trees may also carry it. Review-settled out-of-model results are `rejected` instead. |

The fields worth reading:

| Key | Content |
| --- | --- |
| `state` | One of the four states above. |
| `detail` | Why, in one line: for example `source review placed the trigger within attacker_controls=bytes`, or the missing item that keeps it pending. |
| `validated_at` | When this verdict was first written for this evidence (Unix time). |
| `evidence.attacker_controls` | The threat model the decision was made under. |
| `evidence.review_facts` | What the reviewers agreed on: `vulnerable_boundary_surface`, `reproducer_carrier`, `trigger_controls_fit`, and, for a rejection, `rejection_kind`. |
| `evidence.source_attestations` | The verified source anchors behind the decision. |
| `evidence.artifacts` | SHA-256 and size of every file the decision covers. |

"Filed", "admitted", and "reportable" mean different things. An agent can
file a FIND, and the substance gate can admit it, but only a current final
receipt says whether it is a security result to report.

### The Status column

The cluster indexes show each row's working state. The HTML page shows a
short label; the Markdown index and the label's tooltip show the full
status.

| HTML label | Markdown status | Meaning |
| --- | --- | --- |
| `accepted` | `OK` | A current `reportable` receipt, and no marker below is active. |
| `pending` | `PENDING REVIEW` | Filed and complete, but no current final receipt yet, for example because the wall ended before its review. `validation.json` names the reason once a pass reached it. |
| `pending` | `PENDING (missing: …)` | Crash only: an incomplete bundle, or a `bin/probe` skeleton the agent has not finished. |
| `stale review` | `STALE (validation no longer matches)` | Crash only: a final receipt exists, but the report or evidence changed after it was written. |
| `no security credit` | `NOT-REPORTABLE (no security credit)` | A current `not-reportable` receipt: retained engineering evidence. |
| `needs content` | `NEEDS CONTENT` | Finding only: no report file (`.needs-content`). |
| `needs attention` | `NEEDS ATTENTION` | Finding only: a person created a `.needs-attention` marker. |
| `needs review` | `NEEDS REVIEW` | Finding only: the accepted class has no trustworthy CVSS mapping. |
| `pinned` | `OK (override)` | Finding only: a `.keep` or `.reviewed` marker pins it. |
| `rejected` | `REJECTED` | Finding only: a `rejected` receipt on a directory that has not yet moved to `findings-rejected/`. |

A pin is a human decision, not a review, and applies to findings only. A
pinned FIND skips the substance gate and source review. Its state follows
the report's own fields and `attacker_controls`: `not-reportable` in place
when the report admits caller-contract misuse or a harness-only parameter or
declares a trigger outside the controls, otherwise `reportable`. It stays
pending while the report has neither a `Caller contract` nor a
`Trigger source` field.

## Common rejection reasons

The rejected index groups rejections by the prefix of their reason (the word
before the colon). A reason without one, such as a crash's diagnostic class
or a substance reviewer's own sentence, is grouped as "reviewer verdict".
The full reason is also in each directory's `rejection.md` and in
`validation.json` `detail`.

### Crash candidates

| Reason | What it means |
| --- | --- |
| `null-deref`, `stack exhaustion`, `resource exhaustion`, `intentional assertion crash`, `runtime panic`, `debug assertion abort`, `abort without sanitizer diagnostic` | The diagnostic is a class the harness does not treat as a security result. |
| `harness-rooted: …` | The faulting frame is a fuzz entry point, a `harness.c`-style driver, or scratch source from this run, and no target frame appears anywhere in the diagnostic, including the free and allocation stacks. |
| `bundle-incomplete: …`, `never-reproduced-under-sanitizer: …` | The bundle stayed incomplete for ten passes. The report gains a "Possible false negative" note: check whether a real crash was lost to a bundling failure. |
| `trigger-provenance (2 independent rejects): …` | Two anchored source reviews disproved the route. |
| `threat-model: …` | A real defect outside the threat model: the report admits caller-contract misuse or a harness-only parameter, reviewers placed the trigger outside `attacker_controls`, or both found no added security boundary. |
| `unsettled-scope: …` | Every review answered and none could place the trigger inside the threat model. |

An out-of-model crash is still a real defect worth reporting to the
maintainers as an engineering bug. Do not file the same mechanism again as a
security issue.

Duplicate bundles in `crashes/.duplicates/` are not rejections. Each holds a
`duplicate-of.txt` naming the bundle it duplicates, and neither the results
nor the rejected index counts it.

### Finding candidates

A substance-gate rejection records the rejecting reviewer's own sentence as
its reason. The prefixed reasons:

| Reason | What it means |
| --- | --- |
| `out-of-scope: availability-only impact …` | A denial-of-service class. Availability loss alone is not scored. |
| `trigger-provenance: triggering state not attacker-reachable` | Two anchored source reviews disproved the trigger. |
| `trigger-provenance: exact claimed security consequence is source-disproved` | Both reviewers found that source contradicts the claimed consequence. |
| `threat-model: …` | As for crashes. |
| `unsettled-scope: …` | Scope stayed open after every review, or the field fill could not determine the report's caller contract or trigger source. |

A FIND needs a security boundary and a concrete consequence, not merely a
dangerous-looking API. Common shapes the substance gate rejects:

| Rejected shape | Evidence that would make it substantive |
| --- | --- |
| Correctness or spec deviation | The independent security boundary the target is responsible for enforcing. |
| Path escape where one untrusted value chooses both base and child | A separately trusted root, authorization decision, or distinct capability reached by the escape. |
| Loading an outside file the attacker cannot place | A shipped effectful module, or attacker-controlled placement inside the threat model. |
| Deserialization or reflection that reaches only a sink | A reachable gadget, hook, authorization effect, or memory consequence in the actual environment. |
| Resource exhaustion from a caller-controlled count | A separate memory-safety, disclosure, injection, or authorization consequence. |
| Residual-memory disclosure with no source allocation | The buffer, field, allocation, or prior operation the bytes came from. |
| Caller-owned pointer or lifetime misuse | A public product path through which untrusted input drives the parameter into that state. |
| A debug-only assertion firing | The unchecked memory-safety or boundary consequence that follows in a release build. |
| A bug in code that does not ship (tests, fuzz drivers, generators, examples) | Evidence that the code ships or is reached from a shipped path. |

A thin but concrete security case is accepted. These gates reject missing
substance, not imperfect writing.

### Reopening a rejection

The next full triage pass returns a rejection to the active lane as
`pending` when the review behind it is no longer current:

- a substance-gate rejection, when the report was edited or the gate
  version changed;
- a `trigger-provenance` rejection, when the report, the threat model, or
  the review prompt version changed;
- a `threat-model:` or `unsettled-scope:` rejection, when its first source
  review is stale for those same reasons.

To contest one, fix the report where it is wrong and let the next pass
re-review it. Diagnostic-class, harness-rooted, incomplete-bundle, and
availability-only rejections are not reopened automatically.

## Review a crash

After export, a crash directory is the maintainer bundle:
`report.md` and `report.html`, `reproduce.sh`, the input or harness,
`sanitizer.txt`, `validation.json`, and, when present, `severity.json` and a
candidate `patch.diff`. [Bundle layout](reproduce-a-crash.md#bundle-layout)
describes each file.

Check that the saved output names a sanitizer class and faults in target
code, that the bundled input or harness can be rerun, and that the report
explains how a normal product entry reaches the fault. A confirmation rate
is useful, but it does not turn harness-only state into attacker
reachability.

A `## Contract concern` section in a reportable crash means the report's own
fields put the trigger outside the threat model while source review or a
machine proof placed it inside. Read both before you rely on either.

To change a crash's narrative, edit `.audit/report.md`, the audit-side
draft. Export rebuilds the root `report.md` from it, keeping the fields
already written there, so narrative edits made directly in the root
`report.md` are lost on the next export.

Treat `reproduce.sh` and the target's build system as untrusted code: read
them and run them in an isolated environment without credentials.

## Review a finding

A FIND's Markdown report (`report.md` or `description.md` at its root)
needs exactly one bare `Location:` naming the root-cause operation,
endpoint, config key, or protocol step; one canonical
[bug class](../reference/bug-classes.md) token in `Class`; the boundary,
caller-controlled input, trusted setup, caller contract, and trigger source;
what is wrong and what capability or data is lost; and the strategy that
produced it. A reproducer, captured output, `affected-files.txt`, or a small
generator is welcome but optional. Bundles hold regular files, never
symlinks.

The narrative is Summary, Root Cause, Data Flow, Impact, and Fix Direction
([Artifact layout](../reference/artifacts.md#report-narrative) has the
order and word budgets). Read the generated `report.html`, but edit only the
Markdown source.

## Structured report fields

Triage parses bare-label fields from crash and finding reports:

```text
Location: path/to/file.ext:function:line
Class: <canonical bug class, e.g. heap-buffer-overflow|auth-bypass|ssrf>
Surface: network|library-api|file-format|cli|dev-tool|internal|unknown
Reproducer carrier: network|library-api|file-format|cli|harness|runner|unknown
Trigger source: bytes|both|call-sequence|timing|race|protocol-state|env|fs-state
Caller contract: obeyed|violated|unspecified
Boundary: <short description of the attacker boundary>
Caller controls: bytes|length|number|flags|call-sequence|timing|none
Trusted caller actions: normal public call|private mutation|callback ordering|harness-only
Parameter control: direct|indirect|application-supplied|trusted|harness-only
Strategy: S1|S2|S3|S4|S5|S6|S7|S8|REF
```

When a report omits one, triage asks a model to fill it from the report's
own evidence and writes the answer into the report as a bare field. It never
overrides a value the author wrote.

`Surface` names the vulnerable product boundary; `Reproducer carrier` names
the program or harness used to reach it. When source review agrees on the
surface, severity uses the reviewers' answer. `Trigger source` records what
actually decides the fault, not every setup call the driver makes; `both`
means bytes and call sequence. `Caller contract: violated` or
`Parameter control: harness-only` is the report admitting misuse, which ends
in a `threat-model:` rejection.

Three optional fields refine severity. `Primitive:` names the scorer
primitive directly. `Disclosed content:` grades what a disclosure shows
reaching the attacker: `cross-principal`, `same-context`,
`attacker-derived`, `fixed-or-zero`, or `limited-metadata` (for example,
proved path existence). A `Boundary:` beginning with `Authenticated`
records a login precondition, so the score uses `PR:L` instead of the
unauthenticated worst case.

`Cluster`, `Dedup key`, `Dedup frames`, severity text, and the `## Patch`
section are written by the harness. Do not write them by hand.

## Severity

`bin/severity` computes an offline CVSS v4.0 score only for an artifact with
a current `reportable` receipt, and writes it into the report and
`severity.json`. The score is advisory. It derives from report and review
fields and the target's `attacker_controls`; it does not know
deployment-specific privileges, asset value, or the upstream maintainer's
threat model.

The primitive comes from the strongest available evidence: the sanitizer
diagnostic, then the report's `Primitive`, then its `Class`, and only when
none of those classifies it, the class the substance reviewers agreed on.
Exploit Maturity reflects local reproduction evidence, not public exploits:
a reproducer that fires gives `E:P`, an argued finding with no reproducer
`E:U`.

Other severity labels you will see:

| Label | Meaning |
| --- | --- |
| `Pending` | Finding index: no final verdict yet. |
| `Unknown (validation pending)` / `Unknown (validation stale)` | Report text: no current final receipt, or one that no longer matches. |
| `Needs review` | The class has no trustworthy CVSS mapping without a person. |
| `Not a security report` | A `not-reportable` artifact. |

## Clusters and duplicates

Crashes cluster by sanitizer primitive and normalized top stack frames;
findings cluster by an exact `(class family, file, line)` site or an
identical crash state. Each cluster's canonical member, shown in bold, is
the one to read first. The other members stay on disk because they may
carry a useful input or route variant; findings also get a `.dup-of`
marker. A cluster is a review aid, not proof that every member shares one
fix. [Deduplication](../concepts/deduplication.md) documents the exact
signatures, canonical-member rules, and duplicate folding.

## Maintenance commands

Normal triage performs validation, export, severity, rendering, and
clustering automatically. These commands regenerate one derived view by
hand:

| To | Run |
| --- | --- |
| Rebuild a crash bundle after changing its draft (`.audit/report.md`) or evidence | `bin/export-repro <CRASH-id> --crash-dir "$RESULTS_DIR/crashes/<CRASH-id>"` |
| Re-score one artifact, for example after a scorer update | `bin/severity --report <artifact-dir>` |
| Re-score the whole tree | `bin/severity --batch "$RESULTS_DIR"` |
| Regroup after changing a root `Location` or another identity field | `bin/cluster-crashes "$RESULTS_DIR"` and `bin/cluster-findings "$RESULTS_DIR"` |
| List crash, finding, and rejected-crash directories, with each rejection's reason (its headings do not reflect review state) | `bin/show-exclusions "$RESULTS_DIR"` |

`RESULTS_DIR` is `output/<target>/<backend>/results`. Naming the crash
directory lets `export-repro` use the session pinned above it; a bare crash
ID uses the nearest session above the working directory, and `--slug` alone
can select a different backend's session.

Review votes are bound to the report's content, so a substantive edit
sends the artifact back through review on the next triage pass. Full syntax
is in the [command reference](../reference/commands.md#review-results).

## Handing off a result

A result is ready to send when the next reviewer can tell from it what to
inspect and why it matters, what was established (saved diagnostics, source
reasoning, and a current receipt, kept apart from assumptions), and what to
do next (a reproduction route for a crash, and a fix direction where the
evidence allows). Send it through the project's coordinated-disclosure
process, with [Reproduce a crash](reproduce-a-crash.md) for the maintainer
who receives a bundle.
