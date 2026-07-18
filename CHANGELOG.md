# Changelog

## 1.2.0 - 2026-07-17

- **Alternate build-configuration coverage for native targets.** Auditing only
  the default build misses parser, protocol, compatibility, JIT, and
  representation code hidden behind configure-time options. `build-asan` stays
  the canonical control; ordinary native targets now also build one
  content-addressed widened ASan sibling, adopted from bounded,
  build-system-advertised options (`build_widening = true` by default, set
  `false` to opt out), and operators can declare a few named `[[build_config]]`
  rows for mutually exclusive modes. Setup and audit preflight cache siblings,
  bind readiness to the exact recipe, cap automatic preparation at ten minutes,
  and fail open to the primary. Only a minority reproducer slot explores
  alternates, and every confirmed alternate crash is replayed five times on the
  primary — a clean primary run becomes an Environmental MAT:P prerequisite
  rather than erasing the bug. Crash bundles record the alternate identity;
  benchmarks stay pinned to the primary so backend comparisons keep one compiled
  surface. Findings-only, non-native, and browser targets remain primary-only.

- **Severity taxonomy and sanitizer scoring gaps closed.** High-impact
  application findings are now classified by their proven consequence with
  pinned CVSS v4 vectors, while generic undefined behavior stays unscored until
  impact is established; ASan/UBSan admission and scoring gaps are closed and new
  finding classes are constrained to a stable taxonomy that preserves legacy
  labels. Independent scoring safeguards land with it: severity no longer
  localizes (`AV:L/AT:P`) a call-sequence trigger the target declares
  attacker-controlled, the trigger-review cache is bound to the threat model so a
  verdict is not reused after `attacker_controls` changes, and cluster size is
  read from the finding report's bare `Cluster:` line so finding metrics are
  correct.

- **Benchmark comparison is honest across the gate, with a time-to-discovery
  graph.** Rejected artifacts now cluster through the same deduplicators as
  accepted ones, so the two sides of the gate are finally comparable; where
  evidence is missing the report shows conservative bounds (`≤ N rejected`,
  `≥ N% kept`) instead of letting rejections silently vanish. A new
  time-to-discovery graph places each cluster at its earliest member, runs the
  curve flat to the cell wall so a quiet final hour no longer reads as an early
  stop, labels each row by the model that ran it, and explains every point on
  hover. Cell wall time now stops at productive audit work rather than trailing
  triage.

- **Benchmark pooling no longer crashes on validator scratch.** A regression had
  the finding validator anchor its working directory — a symlink farm into the
  target tree and build outputs — inside model-direct cells' `findings/FIND-*/`,
  which pooling then copied and removed, raising `shutil.Error` and `ENOTEMPTY`.
  The validator cwd now anchors at the results-tree root for every layout,
  pooling excludes `.validator-cwd`, and staging teardown renames aside before a
  best-effort remove so a concurrent writer cannot abort it; already-broken runs
  regenerate cleanly.

- **Faster ranking and compiler wrappers.** `bin/rank-work` samples 256 KB of
  each source file (up from 180 KB) and reads only that slice instead of loading
  the whole file, and the compiler-guard wrapper defers its heavier `file_tools`
  import so every compile skips work only the grep, sed, and rg wrappers use.

- **Documentation corrections.** Fixed the documented session-log filenames
  (`session_<TS>_<launch>-<n>.log`, with no `.log.summary.md`), removed
  references to `reachability.json` / `.reachability_ok` artifacts the harness
  never writes, corrected the `LLM_DECISION_TIMEOUT` default, and rewrote the
  finding-gate description to the real two-accepts / two-rejects contract.

## 1.1.1 - 2026-07-13

- **Recon leads stop inflating confirmed findings.** Recon pre-files a candidate
  finding per hypothesis and the prose quality gate accepted the report, so
  un-investigated recon guesses were counted as confirmed. Harvest now confirms a
  recon finding only when an agent actually investigated it — a work card reached
  find/crash in authoritative state, the directory holds non-empty agent
  artifacts, or a human pinned it — and surfaces the rest as leads, keyed by
  directory so lost state cannot silently re-confirm them. Pooled-run rejection
  reasons also survive report-identity rewrites, keeping the rejection index
  complete without weakening cache validation.

- **Crash gating rejects a caller's misuse of its own buffer.** Discovery and
  trigger prompts now reject a caller that misdescribes its own allocation —
  reading or writing past its buffer, or handing non-terminated storage to a
  documented C-string API — while still promoting genuine library over-reads,
  truthful-capacity overruns, and attacker-derived-but-truthful sizes. Rejection
  turns on truthfulness, not size provenance, closing a false-accept class
  without loosening recall.

- **Language sample targets gain real sanitizer surfaces.** Rust (nightly ASan
  build-std), Go (`-race` with a genuine concurrent merge race), and a new
  native-Python CPython C-extension ASan harness now build through a committed
  `.audit/build.sh` that `setup-target` materializes for language targets. The
  benchmark scorer scopes Rust frame demangling to Rust manifests so a C++ frame
  is never reduced to a colliding leaf, maps data-race reports to the data-race
  primitive, and excludes findings-only bugs from the crash-recall denominator.

- **Model-direct benchmark cells reflect each target's real capability.** The
  arbitrary five-finding mode switch is gone: findings-only controls deepen
  candidates through their configured runner, while sanitizer and race targets
  pursue crash artifacts only for source-backed candidates that reproduce a real
  diagnostic, using one shared classification of sanitizer-capable runner build
  systems instead of sniffing runner arguments. Comparison cells no longer
  inherit operator-installed backend workflows that duplicate orchestration —
  Codex plugins, OpenCode extras, and Gemini skills and extensions are disabled
  per run so the baseline measures the model, not the operator's local setup.

- **Unusable language runners fail fast instead of burning budget.** A configured
  `[runner].bin` is validated before model preflight and before benchmark cells,
  so launcher stubs and missing interpreters cannot silently waste an audit. A
  findings-only target with no runner still audits in code-review mode, and a
  per-target startup failure in a multi-target benchmark is isolated instead of
  crashing the whole grid with an uncaught traceback.

- **Finding validation is cached, resumable, and parallel.** Partial quality
  votes persist and independent review batches run with bounded concurrency, so
  an interrupted or slow provider never restarts completed work; peak fan-out is
  unchanged and a skip, timeout, or malformed response can never invent an
  acceptance. Verdicts bind to a shared semantic report identity checked by the
  gate and every downstream consumer, mechanical annotations stay cache-neutral,
  and substantive prose or reachability changes fail open to a fresh review. A
  pre-existing harness build-lock race — the probe staleness check crashing when
  a holder released the lock mid-check — is fixed alongside.

- **Provider cost accounting is complete and correct.** Explicit vendor rate
  tiers with dated snapshot matching replace overlapping model-name guesses across
  OpenAI, Claude, Gemini, and xAI, with corrected long-context and cache-write
  billing; estimated or corrupt usage rows fail open without double-counting
  output. New gpt-5.6 and Fable 5 rows restore the Codex dollar column — its
  default had moved to a model with no pricing row — and a test pins every default
  model to a rate row so a future model bump fails loudly instead of blanking the
  cost.

- **Live dashboard and test-suite cleanup.** The shared benchmark dashboard now
  regenerates when a cell starts, so a just-launched long-running cell is no
  longer absent from it for its whole run. The legacy shell harnesses around
  Python code are migrated to direct, portable Python tests — with restored
  benchmark-lifecycle coverage and correct unittest result counting — while shell
  coverage is retained for the runner and shell shim.

## 1.1.0 - 2026-07-12

- **Python-native orchestration replaces the legacy shell runtime.** Audit,
  benchmark, recon, probe, sanitizer, setup, triage, timeout, wrapper, and
  structured-state control paths now share direct Python implementations instead
  of parallel shell stacks. The migration keeps resumable evidence and artifact
  contracts intact while making deadlines, process cleanup, concurrent state,
  backend isolation, and failure handling explicit and testable across platforms.

- **Benchmark results now measure the complete, comparable workload.** Every cell
  includes preflight, recon, audit workers, and validation; records resolved backend
  effort and cost; and treats missing usage as unknown instead of zero. Confirmed,
  rejected, and unique result populations are now explicit and mathematically
  consistent, while incomplete artifacts are excluded individually instead of
  erasing an otherwise successful replicate. Both conditions receive the same
  target-aware triage, and replay-safe regeneration repairs legacy runs without
  consuming pending-artifact lifetime or launching new benchmark cells.

- **Benchmark reports stay useful while long runs are active.** The aggregate HTML
  is rebuilt after each completed cell and clearly labels provisional totals until
  final cross-cell deduplication. Operators no longer wait for the entire matrix to
  finish before inspecting results, while the final report retains the same gates
  and unique-root accounting.

- **Finalization is bounded and substantially cheaper without weakening gates.**
  Crash and finding validation now has an independent one-hour safety window.
  Newly confirmed crashes keep their work active, receive a watchdog-protected
  enrichment tail, and resume incomplete reports before new investigation; a
  provider limit or deadline leaves evidence visibly resumable rather than
  discarding it. Keyed batching, bounded local concurrency, one final pool pass,
  and selective reuse of stable sanitizer proof remove repeated model and report
  work while preserving full review for changed, ambiguous, and custom-harness
  evidence.

- **Grok Build joins the supported backend matrix.** Grok is available for full
  audits, ensembles, recon, focused decisions, validation, containers, cleanup,
  and benchmarks, with streaming output parsing and conservative token/cost
  estimates where native telemetry is absent. Claude, Codex, Gemini/Antigravity,
  and Grok now receive their CLI-native reasoning-effort controls consistently,
  and archived run and ledger metadata records the resolved setting.

- **Audit precision and recall safeguards are unified around target evidence.**
  Recon is grounded in the configured threat model and concrete falsifiable
  candidates; unknown evidence survives to source-backed tiebreaks; promotion
  distinguishes sanitizer-confirmed crashes, non-memory diagnostics, findings-only
  targets, and harness-owned faults. Productive work is deadline-aware and
  retryable, quota evidence outranks nominal process success, and bounded report
  and transcript reads fail visibly instead of silently dropping valid results.

- **Validated findings receive deterministic severity without invented scores.**
  Two-vote finding classes now enter the existing central CVSS primitive engine,
  while sanitizer evidence and explicit primitives retain precedence and advisory
  model severity is ignored. Accepted classes that remain ambiguous stay visible as
  `Needs review`, unscored and outside Medium+ totals, instead of appearing as a
  misleading generic `Unknown` report.

- **The operator surface is smaller and easier to diagnose.** The handbook now
  leads with first-run, maintainer-handoff, backend, and controlled-benchmark
  workflows; unused host dependencies and hidden compatibility paths are removed;
  container and Python 3.10 coverage are restored; and focused migration,
  portability, benchmark, triage, and startup regressions protect the rewritten
  runtime rather than preserving obsolete implementations.

- **Measured benchmark overhead fell without reducing observed yield.** In
  like-for-like reruns, Codex `samples/sample-c` wall time fell 29% (52m→37m),
  finalization 60%, reporting 74%, prompt traffic 28%, and output tokens 43%.
  Claude `samples/sample-cpp` wall time fell 13%, finalization 13%, reporting 26%,
  total token traffic 5%, and output tokens 15%; crash and finding yield held
  steady or improved. Independent post-change Codex/Rust and Claude/Python runs
  then completed all four cells in 36–37 minutes without provider limits or
  refusals, surfacing 11 and 12 pooled root causes respectively.

## 1.0.3 - 2026-07-08

- **Productive cards retire by scope-aware exhaustion.** Keep-alive re-offered
  already-cracked cards indefinitely on small or deep targets, grinding runs to
  the `MAX_DRY` cap re-mining their own findings. Concrete cards (recon-hypothesis,
  patch) now retire once conclusions exhaust their distinct hypotheses (C≥D), while
  broad ranked-source cards keep the file-level dry signal; mined cards are never
  reopened as work across the claim path, explain view, and work-card overlay.

- **Iteration progress gates on unique root causes.** Duplicate `CRASH-`/`FIND-`
  dirs for an already-clustered bug reset `dry_streak`, keeping small hot targets
  claimable forever. An iteration counts as productive only when a new unique root
  cause appears; duplicate-only rounds advance the streak. Fails open to raw
  counts if clustering fails or times out, so no finding is suppressed.

- **Source-proven reachability rejects.** Self-sabotage and unreachable-trigger
  rejection moves into the recall-safe trigger-provenance gate, which rejects only
  source-proven caller self-sabotage and preserves real, reachability-limited
  defects. Reachability wording is now threat-model-generic — keyed on the
  target's `attacker_controls`, not hard-coded to bytes — and vocabulary
  normalization maps "attacker" to "external", not "caller", so the
  untrusted-source vs trusted-application distinction survives rewriting.

- **Cluster siblings route to structured state.** Cluster expansion appended to
  per-agent `AUDIT_STATE-N.md`, which structured state no longer produces, so
  every call was discarded and housekeeping re-expanded every dir each pass
  (12 calls, 1517s, 0 results on a tiny target). Siblings now land as PENDING
  hypotheses via `bin/state add-cluster-hyps`, deduped under one lock; a one-time
  migration marks already-indexed crashes expanded, and off-taxonomy sibling
  labels fold into the canonical state bucket instead of being dropped.

- **Target scan stops following symlinked dirs.** `iter_target_roots` walked
  `output/` with a symlink-following `is_dir()`, so a benchmark repo-root facade
  (a symlink back to a source tree carrying its own `output/`) recursed without
  bound and hung `find_session_dir` and untargeted `run-asan`. Symlinked dirs are
  now skipped, delivering the exclusion the docstring already promised.

- **Rejected crashes keep their reason.** The trigger-provenance gate moved
  crashes to `crashes-rejected/` without writing `.autodiscard`, so
  `REJECTED-CRASHES.md`, `show-exclusions`, and the benchmark ledger all showed
  `—`. The reason is now backfilled at the common move chokepoint, covering every
  current and future rejection path; display-only, no count or severity changes.

- **Unified live-run status lines.** Rate-limit/pause, agent-pool, cell, and
  iteration-result output is reworked into one compact `Subject: key=val | group`
  style; per-session prompt dumps move under `logs/.raw` so default scans skip
  them, and `cell_metrics_summary` reports `metrics=unavailable` for missing or
  corrupt cells instead of a misleading `crashes=0/0`.

- **Dead code and a legacy knob removed.** Unreferenced functions, constants, a
  hidden untested env toggle, an orphan reference doc, and stale comments/tests
  are gone. No behavior change.

## 1.0.2 - 2026-07-05

- **Pause and resume through usage limits.** A backend usage cap (Claude session
  limit, Codex/Gemini quota, bare 429) now pauses the run — a plain sleep with no
  agents burning tokens — until the reported reset, or in 30-minute re-probe
  steps when none is reported, instead of hard-stopping cells or giving up after
  short backoffs. Detection is unified into one Python pass that also catches a
  cap surfacing only in a refill agent's log, and the post-run finding drain now
  resumes across caps (opt-in) rather than reporting zero confirmed findings when
  a cap lands mid-drain — with unadjudicated findings surfaced so a gate left
  unfinished no longer reads as nothing found. The wait is excluded from the
  productive wall budget, so it costs no investigation time and benchmark cells
  compare on paused-excluded wall.

- **Security findings, not just crashes, are the mission.** Per-agent sessions
  were still driven by crash-centric framing while the "find all security issues"
  goal reached only recon and model-direct. The mission is restated across
  `safety_framing`, `AGENTS.md`, and post-compaction — findings first, sanitizer
  reproducers where feasible — with file-the-finding steps added to the method;
  crash-promotion pressure is preserved.

- **Shared bug-quality floor for recon.** Reconnaissance drifted from the
  find-quality gate, emitting trusted-caller NULL-derefs, OOM-only, debug-assert,
  and non-product-surface noise (one slice: 965 raw leads → 2 promoted). A shared
  `audit_bug_contract` now renders one definitional floor into both recon and
  model-direct, cutting emission noise at the source while keeping the
  keep-on-unsure rule so auth/injection/DoS paths and unproven leads still surface.

- **Search hides output logs, not source.** The old wrappers excluded any `logs/`
  directory — hiding a target's own `src/logs/` source — and leaked harness prompt
  dumps and vendored chat logs that self-poisoned greppy searches. `rg`/`rg-safe`
  now exclude the harness tree by location (`**/output/**/logs/**`), keeping a
  target's `src/logs/` searchable, and `rg-safe` execs the real `rg` so
  `--include-logs` can't be silently defeated in agent shells.

- **No silent line-cap recall boundary.** The 200-line cap on `rg`/`grep`/`sed`/
  `peek` output was redundant with the ~50 KiB byte cap and clipped legitimate
  file views and explicit ranges below budget, spilling to a file agents never
  re-read. The byte cap is now the sole size guard; explicit ranges and searches
  pass through whole up to ~50 KiB.

- **Per-language benchmark targets.** A suite of synthetic "reportkit" targets
  across 14 languages (c, cpp, go, java, javascript, kotlin, perl, php, python, r,
  ruby, rust, swift, typescript) lands under `targets/samples/`, each seeding
  recent high-severity bug classes written innocuously plus false-positive traps,
  with answer keys hidden outside the audited tree. Supporting this, target slugs
  may now nest to arbitrary depth (`targets/a/b/c`) across setup, enumeration,
  cleanup, and benchmark cell staging.

- **Isolated Claude decision calls.** Claude Code runs under `--safe-mode` from
  the shared flag builder, so audit, recon, validation, and decision calls skip
  operator plugins, skills, hooks, and statusline context; one-shot decision calls
  also disable session persistence while full audit sessions stay resumable.

- **Always-fresh recon.** Cold-start seeding always runs reconnaissance instead of
  reusing per-results or shared benchmark cache state; the cache markers, wiring,
  and stale docs are removed.

- **ASan effort floored from crash artifacts.** Model-direct cells can run
  sanitizers outside `bin/probe`, leaving crashes without probe telemetry; harvest
  now treats confirmed crash artifacts as a lower-bound ASan-invocation floor while
  explicit probe counts still win when higher.

## 1.0.1 - 2026-07-03

- **Frame-ownership scoring.** Harness vs. target code is decided by source
  ownership, not function name, so a real `main`/`free_node`/`operator delete`
  fault is scored instead of zeroed as ClusterFuzz boilerplate.

- **Copy-overlap is a write.** ASan's `*-param-overlap` family prints no
  `WRITE of size N` line, so severity defaulted it to the read tier (an unbounded
  `strcpy` stack smash scored Low, not High) and clustering left it
  `unclassified` (skewing labels and grouping). Both now classify the copy
  destination as a WRITE — matched on the `cpy`/`cat` verbs so a comparison
  overlap can't, and anchored to the ASan headline so prose mentions can't.

- **Honest input trust class.** Fuzz input from file/argv/stdin is classified as
  bytes, not env/fs-state, removing a spurious Medium outlier from otherwise-Low
  clusters that share one root cause.

- **Source surface on tracked files only.** The audit reads just what the
  project's VCS tracks, so agents stop spending budget on generated output,
  vendored deps, and the harness's own venv; it falls open for non-VCS tarballs.

- **No build-based source hiding.** The build-feature probe and `features.json`
  card gate are removed; a missing sanitizer build flag should surface as a
  build-coverage problem, not silently remove critical source from audit scope.

- **Symmetric finding confirmation.** Model-direct findings are confirmed by the
  same single find-quality gate as harness findings. A redundant validator
  pre-gate — which could reject a finding the scorer would keep but never write
  the acceptance the count reads — is dropped, ending an asymmetric recall
  penalty and per-finding validator burn; the gate's source-reading reachability
  step now runs for both conditions.

- **Wider prior-fix window.** S1 mining scans a 5-year / 25k-commit lookback
  instead of a flat count, giving fast- and slow-moving histories comparable
  coverage at near-zero cost — richest history no longer starves lead generation.

- **Complete prior-fix vocabulary.** Ranking recognizes the full severity class
  set (stack exhaustion, DoS amplification, RCE phrasing), with a CI guard tying
  it to `bin/severity` so a new class can never silently go unranked.

- **Read-only source for decisions.** Every backend can read the code to judge
  reachability and clustering while staying sandboxed, bounded by the decision
  timeout rather than an arbitrary turn count.

- **Decision-class circuit breaker.** A gate that is fast-failing on a
  rate-limited or overloaded backend is paused, arming only on real backend
  errors — never a timeout or a one-off malformed reply — so a throttling storm
  stops paying dead round trips.

- **One wall-clock budget.** Confirm gates gain a 180s timeout floor so slow-but-
  valid votes aren't killed and retried, and claude, codex, and gemini all answer
  under the same clock rather than diverging on hidden turn caps.

- **Full-session Claude cost.** Benchmark and audit token accounting now read
  Claude Code's cumulative `modelUsage` when present; the per-result `usage`
  covers only the final turn, so multi-turn and recon sessions are no longer
  billed at a fraction of what they actually spent.

- **Non-prescriptive baseline.** The model-direct benchmark no longer nudges
  agents to build harnesses and corpora, and its scratch is reclaimed after
  harvest — dropping wasted setup that yielded no crashes and hundreds of MB.

- **Diagnosable external kills.** The layers closest to a kill log a stray
  SIGTERM's shape, so a cell that dies mid-run leaves a trail in state instead of
  vanishing and orphaning agents that keep writing.

- **Shallow-checkout warning.** A truncated git history raises a startup warning
  with the `--unshallow` remedy, surfacing quiet coverage loss that would
  otherwise never show up as an error.

- **Named rejection ledgers.** Rejected artifacts write semantic
  `REJECTED-CRASHES.md` / `REJECTED-FINDINGS.md` as canonical browsable targets,
  with `INDEX.md` kept as a compatibility alias so older runs still count.

- **Robust `scratch-status`.** It no longer aborts on harness-only scratch dirs
  under macOS Bash 3.2 with `set -u`, returning a file inventory instead of an
  unbound-variable crash.

- **Python-only runtime.** The harness and test suite depend only on `python3`
  outside Perl-language targets; the timeout shim and vocabulary neutralizer are
  ported off inline Perl, shrinking the install footprint.

- **Verified prerequisites.** Install lists now require `venv`/`pip` and every
  listed tool is checked against a real caller, so a fresh setup has exactly what
  the docs and vLLM path need.

- **Handbook trued up.** The docs are corrected and completed against current
  code — dedup and severity examples, operator env knobs, reachability
  artifacts — so a failed run is diagnosable without first reading raw logs.

## 1.0.0 - First Version Launch

TokenFuzz 1.0.0 is the first public release of the audit harness: a local,
evidence-driven way to put LLM agents to work on source code you are authorized
to test. It is designed to start from an unfamiliar target, find real security
issues, turn them into testcases and reports, and leave maintainers with
reproducible artifacts rather than model prose.

### Capabilities

- **Auditing without an answer key.** `bin/setup-target` checks out or refreshes
  a target and its `target.toml`, and the harness works only from the source and
  build you provide. No fixed bug list, expected crash, or ground truth is
  supplied; locating the issues is the agents' responsibility.

- **Discovery before a crash exists.** A cold-start reconnaissance pass surveys
  the source tree, an independent validator separates credible leads from noise,
  and ranked work cards turn the survey into concrete starting points. The
  pipeline is built to find candidates, not merely to triage a testcase another
  tool produced.

- **Method-driven investigation.** Agents proceed through eight named
  strategies — prior-fix review, invariant negation, spec-versus-implementation
  analysis, differential testing, lifetime-and-state sequencing, peer-project fix
  mining, adversarial input construction, and property-based oracles. Each
  attempt is recorded to disk, so a later run resumes with full knowledge of what
  has already been tried.

- **Coordinated multi-agent execution.** Work cards are claimed, leased,
  released, and resumed through structured on-disk state. Parallel agents divide
  the source, avoid pursuing the same lead twice, and recover cleanly from
  restarts or long-context resets without depending on prior conversation.

- **A single evidence gate.** Every testcase passes through `bin/probe`, which
  reads its header, selects the appropriate runner — browser, JS shell, generic
  CLI, sanitizer, differential, or language runner — records one verdict, and
  stores the output beside the input. Browser and JS probes coverage-gate first,
  so an input that never reaches the target spends none of the sanitizer budget.

- **Evidence over confidence.** A crash is promoted only when sanitizer or
  differential output is present on disk and survives triage. Low-signal
  outcomes — null dereferences, out-of-memory, assertion-only aborts, and
  timeouts — are held out of the accepted set.

- **Maintainer-ready reproducers.** Each accepted crash is exported as a
  self-contained bundle: a rendered report, the triggering input, sanitizer
  output, an optional API harness, severity metadata, and a `reproduce.sh` that
  runs against a clean upstream checkout.

- **Findings beyond crashes.** `findings/` records concrete, reviewer-actionable
  security issues that produce no crash at all — logic flaws, access-control
  gaps, injection, information disclosure, weak cryptography, races, and sandbox
  or privilege-boundary concerns.

- **Reachability-aware severity.** Every report carries structured fields for
  boundary, caller control, trusted-caller actions, caller contract, trigger
  source, and strategy. Severity combines CVSS v4.0 with the target's threat
  model, so internal misuse and attacker-reachable exposure are scored distinctly
  rather than treated alike.

- **Root-cause deduplication.** Crashes and findings are clustered by underlying
  cause, with per-backend and cross-backend summaries. Repeated rediscoveries of
  one problem collapse into a single actionable entry instead of accumulating as
  noise.

- **Broad language and target coverage.** C and C++ offer the clearest
  AddressSanitizer-first path, and the same workflow extends to Rust, Go, Swift,
  browser builds, JS shells, native extensions, generic CLIs, and library
  harnesses — with a findings-only mode for languages that provide no sanitizer.

- **Backend-agnostic execution.** Claude, OpenAI Codex, Google Gemini, and a
  local open-source model all operate behind the same probe, triage, severity,
  and clustering contract. Backends are interchangeable, and no single vendor is
  assumed.

- **Cost-aware long runs.** Prompt caching, capped source reads, per-agent probe
  budgets, and soft turn limits constrain the token cost of an extended session,
  keeping an overnight audit from becoming an expensive surprise.

- **Inspectable run state.** Structured state, probe history, coverage summaries,
  rendered reports, and indexed rejected artifacts make a run legible — what it
  did, and why a candidate was set aside — without recourse to raw session logs.

- **Isolation by default.** Cross-run backend memory is disabled unless you opt
  in, preventing a stale note from an earlier session from quietly steering a
  later audit away from code worth examining.

- **Built-in evaluation.** `bin/benchmark` runs the full pipeline and a direct
  "find vulnerabilities" prompt under identical target, backend, model, and
  wall-clock conditions, then compares validated findings and sanitizer-confirmed
  crashes rather than unverified model claims.

### Distinction From Benchmark Suites

Several recent cyber-agent benchmarks measure whether a model can reproduce or
exploit a *known* vulnerability under a fixed task definition. TokenFuzz includes
a benchmark mode, but the release itself is an audit system you run on live
source:

- **No known vulnerability to start from.** Agents receive no CVE, bug
  description, vulnerable function, or triggering input. They derive their own
  leads from the source, recent changes, peer fixes, strategy cards, and observed
  testcase behavior.

- **Output aimed at maintainers.** A run concludes at actionable security
  evidence — a report, a reproducer, sanitizer or differential output, a
  severity, a cluster, and a fix direction. Demonstrating arbitrary code
  execution or scoring exploit primitives is not the objective.

- **Operational pieces included.** Target setup, build discovery, sanitizer
  runners, coverage-gated probing, structured state, memory isolation, resume,
  rejection indexes, cross-backend clustering, and report export ship as part of
  the release — not as glue assembled around a benchmark.

### Running a First Audit

Set up a target, run a single bounded iteration, and inspect the resulting
artifacts:

```bash
export TARGET=yourlib
export BACKEND=codex              # claude, codex, gemini, or oss
export RESULTS="output/$TARGET/$BACKEND/results"

bin/setup-target "$TARGET" https://example.com/yourlib.git
bin/audit --target "$TARGET" --backend "$BACKEND" 1

ls "$RESULTS"/crashes "$RESULTS"/findings
```

The bounded run serves as a smoke test of target setup, backend authentication,
state persistence, and artifact layout. Once the configuration is sound, omit
the trailing `1` to launch a continuous audit.

### Evaluating the Harness

To measure the harness against a plain prompt on equal footing, run the
benchmark:

```bash
bin/benchmark --target "$TARGET" --backend "$BACKEND" \
  --replicates 3 --budget-wall 10800
```

Both conditions — TokenFuzz and the direct-prompt baseline — run under identical
wall-clock budgets. Their evidence is pooled, validated, and clustered, and the
resulting comparison is written under `output/benchmark/`.

### Responsible Use

Run TokenFuzz only on software you are authorized to test. It is not a hosted
fuzzing service, an automatic disclosure system, or a substitute for maintainer
judgment. All output remains in your local results directory unless you choose
to share it. Released under the Apache License 2.0.
