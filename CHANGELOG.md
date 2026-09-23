# Changelog

## 1.6.2 - 2026-09-22

Duplicate crash work was the largest waste in the last benchmark round: 141
crash bundles covered 63 distinct crash states, and every repeat paid for
its own enrichment and review. This release files a crash state once, tells
agents what is already taken before they rediscover it, and gives a finding
and a crash at the same line one verdict. Denial of service leaves the
scoring on both sides of the benchmark, a provider outage no longer leaves
the triage drain with reports it cannot judge, and the call graph reaches
beyond plain C. Benchmark cells now run on the configuration their preflight
built, with clocks and spend that cover what they claim, and the default
models move to Opus 5.5, GPT-6 Sol and grok 4.7.

### Duplicate crashes

- **A crash state is filed once.** `bin/probe --confirm` filed a bundle for
  every distinct reproducer, so across 38 benchmark cells 141 bundles
  covered 63 crash states, each buying its own enrichment, validation,
  reachability, expansion and severity sessions. Filing now refuses a
  reproducer whose crash state (sanitizer, fault kind and access direction,
  line-exact use stack, and the free stack for lifetime faults) and probe
  route (mode, harness, argv, alternate build) match any bundle under
  `crashes/`, and prints `CRASH DUPLICATE` with the id to close the
  hypothesis with. A single exploration run prints `CRASH STATE ALREADY
  FILED` so the five confirm runs are not spent, and records the owner as
  `duplicate_of` on its run row (`filed_state_repeats` in telemetry).
  `bin/state resume` lists every filed state with how far its review has
  got. A materially different route is still filed, since it can establish a
  different boundary, build dependency or severity.

- **Triage folds duplicates filed before the first was promoted.** The
  filing check cannot see a sibling filed moments earlier: in 36 cells, 44
  of 64 duplicate bundles landed before the first was promoted, a median 64
  seconds after it. The crash gate now moves a pending bundle whose state
  and route match a promoted one to `crashes/.duplicates/<name>/` with a
  `duplicate-of.txt`, and closes the filing hypothesis with the promoted
  `CRASH` id. Same-state pending siblings wait for the earliest one's
  verdict in the same pass, so nothing is left unjudged, and a bundle
  without a recorded route goes to ordinary review.

- **Agents see a taken site before opening it.** `bin/state add-hyp` now
  names any filed crash and any older hypothesis at the same function in the
  same file. It is advice, not a refusal, since a different mechanism at one
  function is a new bug, and only earlier ledger rows count, so two agents
  opening one site together do not both yield. Cluster expansion, which had
  re-proposed an already covered line for 84 of 135 benchmark siblings,
  sends one seed per crash state and lists the promoted crash frames.

- **A finding and a crash at the same line get one verdict.** Each got its
  own trigger review, and one run counted a single defect both as security
  yield and as a rejected report. The find gate now folds a memory-safety
  finding into the sanitizer crash filed at the same target-relative path,
  line and function, including a finding already rejected on its own, and
  the crash's verdict is the only one. A shared function alone is not a
  shared defect. Crash numbers also count bundles moved to
  `crashes-rejected/`, so no number is issued twice.

- **Promotion no longer waits on cluster expansion.** One 330-second
  expansion call inside the background sweep held back every promotion after
  minute 10 of a run. Expansion now runs on its own thread with a backlog
  that the sweep never waits on; its 800-second ceiling stays.

- **A crash state comes from one complete sanitizer report.** A confirmation
  transcript can open with a run cut off before its stack, and selection
  paired that run's READ with the next run's WRITE frames, inventing a crash
  state. The fault kind, access direction and frames now come from the first
  report that has a stack, and clustering, duplicate filing and replay
  matching all read them from there.

### Scope and strategy

- **Denial of service is not scored, on either side.** The bug contract
  asked agents to quantify resource amplification while the strategy
  references said a slowdown is never durable denial of service, and on one
  run the direct control scored nineteen quadratic-CPU findings against a
  harness that never opened one. Availability-only impact is now a stated
  limitation: the finding gate rejects a dos-family `FIND` before any review
  vote, the quality review rejects the same substance under another label,
  and the reach-field pass stops asking for `availability_loss`. A report
  whose primitive names a scorable consequence is still reviewed. The
  planted denial-of-service bugs in the Java, Kotlin and Python samples
  become false-positive traps.

- **Worker prompts state the threat model the direct control already had.**
  Harness workers saw `attacker_controls` only as a config fact, and in one
  hour three of four rejected crashes came from callback and lifecycle
  triggers outside the modelled input. Cold, compact, deep and browser
  prompts now render the control's threat-model section, still with the rule
  never to pre-filter a crash.

- **A card that already crashed is concluded, not discarded.** 88 of 188
  card discards were on cards that had already produced a crash, reached by
  probing in-range inputs to meet the three-CLEAN floor. AGENTS Rule 5 and
  the `update-card` refusal now point at `--status crash` or `--status
  find`, which need no CLEAN runs.

- **S7 reaches surfaces the runner cannot through a public-API harness.** S7
  refused a `HARNESS` whenever a runner was configured, which on one library
  stranded three option-gated surfaces for an hour. It now probes through
  the runner when the testcase bytes select the surface and through a
  minimal deterministic public-API driver otherwise, blocking only when
  neither exists. Fuzz harnesses, corpora and campaigns stay with S4.

- **S8 round-trip cards need an inverse in the target.** One-way codec words
  such as decode or inflate minted round-trip cards on a decode-only
  library, and agents spent a session on each proving the oracle absent. The
  card now needs an idempotent normaliser or an inverse pair in the file,
  or, for a one-way file, the inverse somewhere else in the target, so a
  codec split into encoder and decoder files keeps its cards.

- **S6 discovery cards need a local peer clone.** Agents have no network
  access, yet a discovery card asked them to find a fix in a peer's history;
  one cold start spent 11 minutes and 1.9M tokens on failed fetches.
  Discovery cards are now issued only over a local clone, which the card
  names, and a lane that is simply empty offline no longer reports a
  degraded source, so a pinned S6 run stops re-running the generator.

### Triage completion

- **A provider outage no longer spends a report's review attempts.** A
  capacity-limited drain left 29 of 38 findings unjudged, because each
  reach-field ask skipped under the provider cap still spent one of the
  report's two attempts. Only a verdict for the report spends an attempt
  now; a capped or timed-out call, a dropped id or unusable JSON does not. A
  report that has spent its batch budget gets one single-report ask, and one
  whose boundary no verdict could place is rejected with that reason instead
  of held pending. The drain repeats until nothing is pending, pausing on a
  recorded cap (now also when the cap arrives as a clean exit-0 error event)
  and stopping with the reason logged on a refusal or a pass that settles
  nothing; crash triage uses the same loop. Reach-field decisions move to
  v9, which releases sidecars stuck under the old accounting.

- **Review calls are not started into a closing wall.** Trigger, quality and
  expansion calls launched with 4 to 18 seconds left were killed without an
  answer and reported as failed reviews. A gate or expansion call now waits
  for the pass after the wall when less time remains than the fastest
  completed call of the same decision; before any has completed, nothing is
  held back.

### Call graph

- **The call graph serves C++, Rust, Swift, Java, Kotlin, Go and Python
  trees.** It had served plain C and little else: built C++ and Rust symbols
  were compared still mangled, so symbol coverage read near zero and the
  entry boundary was always withheld; anonymous namespaces were skipped and
  named ones flattened; qualified calls (`module.func`, `Class.method`,
  `Type::method`, `self.m`) went unresolved, leaving most non-C trees
  without a cross-file edge; Swift methods in `extension` blocks were
  missed; and a definition carried only its start line. Symbols from ELF and
  Mach-O builds are now demangled and matched within their own scope,
  namespaces keep containment, a qualified call resolves when its callee is
  unique across the containers the qualifier can name, and definitions
  record `[name, start, end]` (schema 8), so the coverage ledger stops
  running each function to the next and the sweep gives the lines between
  functions their own windows. A target without a build gets an entry
  boundary from definitions that are public along with every enclosing type.
  Sample symbol coverage rose from 0.45% to 95% on C++ and from 0.01% to
  100% on Rust.

### Agent time

- **Agent tools resolve the paths the harness prints.** Across 736 benchmark
  sessions, 151 `bin/peek` misses were target-relative source paths, the
  form `bin/state` prints, given from the harness root. `bin/peek` now falls
  back to the target, then the results tree; `mark-examined` records a read
  window that runs past the end of the file up to EOF; and
  `bin/probe-history` hashes a `scratch-N/` testcase where `bin/probe` finds
  it instead of printing `sha1=?`. The pre-file checks name
  `bin/scratch-search <function>` and `bin/state list-findings --limit 0`,
  which read the artifacts themselves, instead of indexes that are often not
  written yet mid-run.

- **A slot whose lane runs dry is reassigned at once.** When the one-card S4
  lane closed, the refill found nothing there and idled the slot until the
  steward tick, 1.5 to 3 minutes of a 30-minute wall. The refill now
  reassigns an empty lane before deciding the slot has no work.

- **A card names the alternate build its file needs.** Probes on a file only
  an alternate build compiles failed to link against the regular build until
  agents found `PROBE_BUILD_CONFIG` themselves. The card and the resume now
  name the ready configuration, and `bin/probe` also accepts the `cfg-<id>`
  spelling agents copy from the build tree's name.

- **A Claude session finishes its long commands.** Claude Code moves a Bash
  command still running at its 120-second default timeout to the
  background, and a headless session then exits without the result: one
  cell's fuzz lane restarted the same campaign in five sessions and never
  finished it. Every Claude launch now keeps harness commands in the
  foreground for up to an hour, bounded by the session wall; an operator's
  own `BASH_DEFAULT_TIMEOUT_MS` or `BASH_MAX_TIMEOUT_MS` wins.

- **A worked card is not handed back for subsystem diversity.** Diversity
  kept only cards in subsystems no other agent owned, so when the lone such
  card had already been discarded, the same agent got it back for twenty
  minutes while five untouched cards waited. Once every free-subsystem card
  has been worked, the claim offers the untouched cards instead.

- **A lane whose cards all fail its entry gate rotates.** Rotation off a
  strategy waited for notes in that strategy's vocabulary, so an S8 agent
  that blocked every card because no property reached a security consumer
  never wrote one: in a 30-minute cell it spent all of its 18 one-minute
  sessions re-blocking S8 cards and never rotated. A card the agent concluded
  in its lane now counts as that evidence, and an `update-card` row that
  omits `--agent` records the card's live claimant instead of nobody.

- **A testcase can load a TypeScript project's source.** Node strips only
  erasable types and resolves only the specifiers it is given, so on a
  TypeScript framework most cards stopped at the first decorator, `paths`
  alias or extensionless import and were blocked as unrunnable. Every Node
  runner execution now preloads hooks that resolve and transpile `.ts`
  source with the target's own `typescript` and `tsconfig.json`; a target
  without `typescript` keeps Node's behaviour.

- **A failed import is not a crash.** The runners' uncaught-exception crash
  patterns recorded every module-resolution failure as `CRASH`: 7 of 10
  runner crashes across two Node targets in one round were a testcase import
  path, an unbuilt `dist/` or an unwired workspace package, and a Kotlin
  target's run lacked a standard-library class. A Node resolution failure
  and a class missing from the JVM classpath are now `NO_EXEC`, like a
  Python `ModuleNotFoundError` in the testcase frame. Only the last error in
  the output decides, so a logged resolution failure cannot hide a later
  crash, and a program that logs one and then exits 0 records a clean run.

### Benchmark

- **A run pins the configuration its preflight built.** A fresh run
  snapshotted `target.toml` before the preflight's build filled `asan_bin`
  and `asan_lib`, so cells ran on a contract naming no binary: no build
  identity, coverage sibling or entry boundary. The snapshot is now taken
  after the build converges, verified, and leased as that exact copy.

- **Clocks and spend cover what they claim.** Every barrier rewrote a
  receipt's clock, so time to first admitted read as the end of every run; a
  receipt now keeps the clock of its first verdict, and first crash
  confirmed reads the first crash triage admitted rather than the first
  reproduced. A direct control's crash is clocked from its own file times
  when the session exits, before export rewrites them; it had read minutes
  after the session ended, and runs finalized earlier keep that reading
  because the original times are gone. Token and cost columns cover the wall
  only, with post-wall review of a cell's own reports, 62% of one control's
  input, recorded beside them, and cost per confirmed is shown, marked `~`
  when estimated, instead of withheld. Hypotheses join to bundles by
  resolved directory, so duplicate filing no longer reads zero; only the
  first hypothesis to close on a bundle judged on its own counts as
  productive, and the rest show as "confirmed, not filed". Failed review
  calls are counted with the wall they lost.

- **Results land where the evidence puts them.** The discovery curve could
  step on sites the table never credited; it now skips them, and reads a
  control's crash from its in-wall draft rather than the post-wall
  promotion. A finding counts as its condition's crash written up only when
  it embeds that crash's stack, or sits at the exact file and line of a
  crash frame with a class a sanitizer reports; one that shares only the
  function no longer folds. Sites written with a `targets/<slug>/` prefix no
  longer split a subsystem row, checkpoint columns follow the budget, and a
  run with an answer key shows its recall and precision on the page.

### Defaults and reports

- **The default models move to Opus 5.5, GPT-6 Sol and grok 4.7.** The
  claude, codex and grok backends now default to `claude-opus-5-5`,
  `gpt-6-sol` and `grok-4.7`. Opus 5.5 gets its own pricing row with cache
  reads at 0.05x of input; GPT-6 Astra, Sol and Luna each get a Standard row
  with the 272k long-context boundary, and a bare or look-alike `gpt-6` name
  stays unpriced rather than inheriting a tier by substring; grok 4.7 shares
  4.6's rates.

- **Reports have one title.** `bin/severity` placed its synthesized Fields
  table after the first heading of any level, which split an untitled
  report's Summary from its paragraph and dropped the TL;DR's Bug line. Only
  an H1 outside a code fence now anchors the table, CommonMark's indented
  headings included. `report_title` is the one title reading for the
  benchmark page and the evidence pages, the report contract asks for a
  `# <title>` line in both conditions, and the rejected-finding index takes
  a harness row's site from the clusterer's location parser instead of
  showing a dash.

## 1.6.1 - 2026-09-19

A run can now say what it looked at and what it never reached. Every
ranking pass writes a manifest of the auditable tree, sessions leave
receipts for the lines they read, the backend transcript is read as a
second witness, and `bin/state coverage` joins the three per directory,
least covered first. Two things spend that knowledge: a budgeted sweep
that buys breadth over the files the window never offered, and a second
pass that asks about the contract across each cross-file call once a file
is fully read. Around them, triage stops crediting crashes in drivers that
compile the target's own source, the canary benchmark reports recall per
bug class, and the prompts lose the rules that contradicted the guide.

### Measured review coverage

- **The tree is enumerated, and a file that left the window leaves a
  trace.** The ranked window (`RANK_WORK_LIMIT`, 120 by default) grew only
  once every card in it was worked, and the card file was rewritten on every
  refresh, so on a large tree most files never received a card and a clean
  run could not name them. `rank_target` now writes `state/manifest.jsonl`
  from the same enumeration that produces the cards: every auditable file
  with its line count, content hash, subsystem, deterministic card id, and a
  sticky "offered" flag. A preview ranked into another file no longer marks
  its window offered, a delta pass keeps the rows it does not touch, and the
  read-modify-write runs under the manifest's lock. The walk prunes the
  harness's own `.audit/` workspace and any directory Python marks as a
  virtualenv: pip's vendored code under a bootstrap venv had become 406
  work cards that agents spent sessions blocking.

- **Sessions record which lines they read.** `bin/state mark-examined
  --agent N --file F --lines A-B | --functions a,b` appends a verified
  receipt to `state/receipts.jsonl`: the file must be in the manifest, ranges
  must fit inside it, function names must be ones the call graph parsed
  there, and a name defined more than once is refused in favour of
  `--lines`. Receipts are pinned to the manifest's content identity, checked
  by stat triple first and by hash on a mismatch, so a receipt on changed
  content stops counting without refusing every receipt after a touch. Every
  card directive and resume brief carries an "Examined so far" block with
  the receipted ranges and the parsed functions no receipt reaches, which is
  what a post-compaction session or a second agent on the same broad card
  starts from; the claimer breaks ties among equally-mined broad cards
  toward the smallest receipted share. The call-graph artifact now keeps
  each file's function definitions (schema 6) so the unit exists without
  re-running the parser.

- **The transcript is the second witness.** Receipts are self-attested.
  After a session ends the runner scans its transcript for each backend's
  native read tool and the shell idioms the audit shell wraps (`sed -n`,
  `cat`, `head`, `tail`, `nl`, `bin/peek`), resolves each path into the
  target tree, and appends merged ranges to `state/reads.jsonl`. `tail -n
  +K` is no longer read as a count; byte windows and multi-script `sed`
  calls are skipped rather than recorded as a range they did not read.
  Coverage shows these as "read requested" beside "receipted", and joins
  receipts to reads so that attested lines no read requested is where an
  over-broad `mark-examined` shows. Sweep receipts stay out of that
  cross-check, since their source reaches the model through the decision
  prompt and no transcript read could corroborate them. Loaded is evidence,
  never a gate: a read the parser does not recognise is simply absent.

### The budgeted sweep

- **`bin/sweep` buys breadth the window cannot.** Every file a session
  opens is replayed on each later turn, so breadth was the expensive thing
  to buy and the coverage report could only name the gap. The sweep walks
  the unreceipted units, files the window never offered first, then the
  least-read, and hands each unit (a parsed function, a `unit_lines`
  window of a longer one, or a fixed window where nothing parsed) to a
  one-shot decision with no tools. A reply must attest the whole unit with
  exactly one verdict per parsed function; a partial or malformed reply
  leaves the unit open, and a lead must sit inside the unit at a non-clean
  function. Receipts land with `source: sweep`; leads become
  `NEEDS_TESTCASE` hypotheses owned by agent `sweep` and reach the
  reproduce lane through the ordinary handoff once the sweep has recorded
  state. It never probes, claims a card, or files a finding.

- **Spend is bounded, persisted, and survives interruption.** `[sweep]
  token_budget` in `target.toml` turns it on; the estimate counts prompt and
  reply tokens of every call, failed ones included, and is charged before
  each call and written to `state/sweep.json` after every unit. A call whose
  prompt alone exceeds the remainder is not started, corrupt state is an
  error rather than a zero, and one sweep owns a results tree at a time. The
  audit starts it as a background process beside the slots, its calls land
  in the usage ledger so the benchmark wall counts them, and delta and
  fixed-lane runs never start one; ensemble runs do. SIGTERM
  now finishes the current receipt and leads as one commit and undoes a
  charge for a call never dispatched, and the runner waits up to the sweep's
  decision ceiling, inside the productive wall, before killing the tree, so
  a paid in-flight decision is not lost and bought again on resume.

### The second pass

- **Cross-file call-edge cards ask what file cards cannot.** File cards
  cover functions; nothing covered the contract between a caller in one
  file and a callee in another, which is where a length, ownership,
  lifetime, or encoding assumption changes hands. Once every parsed
  function in a file carries a receipt, `rank_target` mints one `call-edge`
  card (strategy S3) per caller set from the call graph's certain edges,
  keyed to the callee's and every caller's content hash and seeded at the
  highest-count caller, so a callee with a thousand callers is one card
  rather than a thousand sessions. Edge cards ride the ranked window with
  their file like companion cards, buying no distinct-file slot, and also
  ride the diversity-floor pool so a quiet file the floor placed gets its
  second pass. Delta runs mint none. The coverage report states the
  sampling boundary, derives eligibility from the ledgers rather than the
  live queue (a concluded card had read as "no card"), and the queue
  refresh now reranks when a file completes its receipts even on a target
  without probe coverage.

### Triage and benchmark

- **A driver that compiles target source is not the pinned build.** A
  benchmark replicate credited every direct-condition crash to drivers that
  `#include`d a target module the pinned build had switched off, while the
  harness condition blocked the same cards with proof. Triage now asks the
  compiler (`clang -MM -MG`, `lib/build_scope.py`) which target units a
  driver compiles into itself and demotes such a crash to a finding, on
  either side. A scan that cannot run keeps the crash, a crash already
  published keeps its verdict, and the answer is cached beside the driver by
  digest. An accepted finding or crash also closes the hypotheses its
  headers name, so a row filed at the wall no longer reads `PENDING` to the
  next resume.

- **The canary plants a bug per strategy family and reports recall by
  class.** Three planted bugs, all overflow-shaped or a plain
  use-after-free, let a run score 100% while never finding a
  size-computation, off-by-one guard, or error-path lifetime bug. Four more
  are planted (an exact-length copy read one past its end, an allocation
  size computed in an 8-bit type, a double free on an error path, an index
  guard that admits the capacity), every entry names its strategy, and the
  scorer reports recall per sanitizer primitive and per strategy shape.
  `tests/test_canary_planted.py` builds the canary and checks every planted
  input reproduces at its symbol before a benchmark could mis-score.

### Prompts and documentation

- **Prompts stop contradicting the guide.** Both pacing hints told a dry
  agent to rotate subsystem, which Rule 7 forbids; they now say to switch
  strategy on the same card. The safety framing demanded exactly three
  header lines although `bin/probe` reads more, routed caller misuse to
  `findings/` against the FIND gate, and carried a third copy of the
  trigger-source rule; the digest listed a crash status that never exists.
  Codex and Grok, which auto-load `AGENTS.md`, now get a shorter common
  suffix (cold prompts shrink by roughly a sixth), compact sessions gain the
  digest's pre-file rules, and the auto-memory guard renders in every worker
  prompt that can persist a note, including Antigravity regardless of the
  memory setting.

- **The handbook is rewritten and checked against the code.** Every page
  under `docs/` is in plainer prose with each flag traced to `bin/`, `lib/`,
  `config/`, and `.agents/`; paths and anchors are unchanged. The README,
  index, architecture, cost-model, glossary, and first-audit pages now
  describe measured coverage, the sweep, and the second pass, and the
  development page keeps only what this repository does differently.

## 1.6.0 - 2026-09-16

The benchmark result is a new page. What was a Markdown crosstab that could
say how many is now a self-contained comparison built from every run's
report, clusters and state streams: a leaderboard of every model, harness and
plain, ranked by what each surfaced that the others did not; a race clock with
replay; a behaviour profile per condition; a convergence matrix of every
distinct problem against every condition as found, looked-and-missed or never
looked; and, for each harness cell, a trace of every hypothesis from written
to resolved in the agent's own words, beside the attention it cost. The
cluster, rejected and per-report evidence pages are rebuilt in the same
language, and a run is pinned to the code, gate versions and answer-key
classes it started with, so nothing landing mid-run can move a score.

Underneath, an audit spends its wall differently and proves more afterwards.
Slots refill the moment one finishes instead of waiting for the slowest peer,
and every turn replays less prompt. Findings share one bug-class vocabulary,
each is reviewed on its own evidence, and every review ends in a verdict.
Preflight catches a provider serving the wrong model, every launch shares one
isolation policy, and target setup keeps a route that already runs.

### Scheduling and session cost

- **Slots refill continuously.** The cohort pool held finished slots at a
  barrier for the slowest peer and ran every gate with the pool empty;
  measured cells idled 27–40% of the wall. A slot now refills as soon as it
  ends, a steward tick scores generations and re-ranks the queue beside the
  live sessions, and only the tree-wide sweep waits for the last slot, billing
  any tail past the last session as housekeeping. Fixed-lane, delta, ensemble
  and `--no-refill-workers` runs keep the cohort model; the pool stays a fixed
  3, since a machine-sized default drained a weekly provider quota in under
  three hours.

- **Findings are gated when their writers end, in batches.** A finding names
  no slot, so its seal waited for the longest concurrent session; the harness
  now reads which artifacts each session's commands and file writes touched,
  seals once every writer has ended, and never seals a crash bundle a slot's
  next session is still finishing. Findings without a first trigger vote wait
  for four sealed findings, 180 seconds or the wall instead of being reviewed
  one or two at a time — 68 review sessions for about 140 artifacts in one
  audit.

- **Every turn replays less prompt.** The crash promotion gate shrinks from
  10.9 KB to about 7 KB with every rule kept, each playbook's brief is rendered
  in place of a 10–24 KB read, `rg-safe` caps at 20 KiB with a per-file
  digest, `--confirm` prints one line for a repeat identical to run 1,
  `bin/state` renders results-relative paths, the sanitizer digest elides the
  middle of a generated classpath line (`SANITIZER_DIGEST_LINE_CHARS`), and a
  blocked card shows the proof a peer recorded to the cards behind it. Heavy stdlib imports move to their use sites, so `bin/state` starts 19%
  faster and `peek` and `scratch-search` 39%.

- **The agent guide reaches every session.** Non-codex sessions were told to
  follow `AGENTS.md` without seeing it — 39 of 41 claude deep sessions in one
  audit ran without the contract. It is embedded for every backend that does
  not auto-load it and dropped for codex and grok, which do; codex cold starts
  had replayed 5.4K duplicate tokens per request.

- **Sessions can delegate mapping, and can roll over on context.** Deep and
  compact prompts point caller and data-flow questions at a read-only delegate
  on backends whose delegated spend lands in the session's own usage (claude,
  Gemini CLI). `CONTEXT_SOFT_CAP` ends a session on the continue-from-state
  path once its reported context reaches the cap and no tool is in flight, on
  dialects that report usage per request; it defaults to off so it cannot bind
  one benchmark condition and not its comparison.

### Findings, review and evidence

- **One bug-class vocabulary.** Findings carried three class vocabularies that
  never met. `lib/bug_classes.py` is the one source — the 43 classes of
  Anthropic Red's public disclosure taxonomy plus eight harness-native classes
  with stated reasons — and every class belongs to a family that keys
  clusters, feeds breadth and the review rotation, and maps to a severity
  primitive; legacy labels resolve through aliases.

- **Each finding gets its own review, and a promoted one gets two.** The gate
  shared one verdict across every finding at a source site, so a distinct
  claim inherited its neighbour's; verdicts copied by site are cleared and
  requeued. A finding no probe reproduced now needs a second, reachability-lens
  reviewer to publish, a split going to the focused resolver, while crashes
  and findings with a machine-proved byte path keep the one-review flow and
  one reach-fields answer settles the conditional keys.

- **The gate prompts say what a shipped product is.** A reproducer's choice of
  base is not the product's, an effect on a platform the audited build does
  not run on is deployment-dependent, and a release configuration the
  project's own source or build docs name as supported is a shipping
  configuration, so an overflow behind a compiled-out assert can be reported
  through a source-proven path. The filing contract's exclusions are read as a
  clause, and every wording change bumps its decision version.

- **Every review ends in a verdict.** Artifacts left "unjudged" or "retained"
  for good now reject with a recorded reason once a lane has asked every
  review it asks for. A rejection the operator invalidated by widening
  attacker controls is requeued, a direct crash a replay can never measure
  demotes to a finding, and a replay whose every run hit its deadline is
  unmeasured, not a verdict.

- **Severity reads a negated caller action as the public path.** "No internal
  state mutated" matched the word and gained a caller-precondition metric,
  halving one crash's score against the same signature scored Medium on the
  other side. The rule uses the scorer's negation-aware search and bumps its
  decision version, so old receipts are re-derived on regenerate.

- **Evidence pages are built from the data.** The cluster, rejected and
  per-report pages were Markdown tables that never said when, where or by
  which lane a problem was found. `lib/evidence_pages.py` renders a discovery
  timeline per condition, subsystem bars, a lane-by-class heat table,
  rejections grouped by gate, and a report shell with an action card and an
  evidence rail.

- **Generated file names are lowercase.** The shipped sample linked
  `report.html` to a file named `REPORT.html`, which opens on the
  case-insensitive disk that generated it and is a dead link when served.
  Every artifact directory now holds `report.md` with a `report.html` twin,
  the indexes are `crash-clusters`, `finding-clusters`, `rejected-crashes`
  and `rejected-findings`, a rejection note is `rejection.md` and the corpus
  index `index.md`; readers locate a report through `report_identity`, a
  spelling that differs only in case is not a report, and a test holds the
  shipped example to exact-case links.

### Benchmark

- **The result page is rebuilt around the comparison.** The root page was a
  crosstab that could say how many, not which. `lib/benchmark_page.py` builds
  one data model from each run's report, clusters and state streams and
  renders a leaderboard splitting each condition's problems into the ones only
  it found and the ones others reached too; per target revision, one race
  clock with replay, a behaviour profile per condition and a convergence
  matrix of every distinct problem as found, looked-and-missed or never
  looked; and per harness cell, a mind trace of every hypothesis with the
  agent's own reasoning beside an attention table. Agent free text is scrubbed
  of workspace paths before it reaches the page. Every count comes from the
  report, a row says whether it is a crash or a finding and whether it is one
  side's alone, a bare file name from a stack frame joins its directory's row,
  links are relative so a bench root can move, and the crosstab shows the
  answer key its headline counts include.

- **A run is pinned to the code and gates it started with.** The control plane
  is frozen once per run, every cell facade is built from that copy, and the
  closing pass now runs from the same snapshot — `bin/validate-finding` and
  every prompt had run live, so an edit landing mid-run changed verdicts the
  run was still casting. The three gate decision versions are recorded in
  `run.json` and held across resumes, since a bump mid-run had stranded a
  whole cell as an unjudged remainder; a resume whose checkout no longer
  matches is refused, and `--regenerate` alone unpins.

- **Answer keys score by declared class.** A report earns a planted bug only
  through a class the key declares, so two bugs in one function can both be
  credited; a trap declares the one claim it refutes instead of swallowing
  every report at its symbol, which had cost the harness a third of sample-go's
  finding precision; an entry may pin its file, so same-named statics in two
  files stay distinct; and a key whose bug and trap overlap at one site is
  rejected at load. Where a symbol holds one bug and no trap, a sibling class
  from the same family earns it, and a site the agent contract says not to
  file scores in neither oracle.

- **One defect counts once.** A finding at the site of its condition's crash is
  that crash's write-up, the page counts the problems the ledger counts,
  lifetime crashes key on their "freed by" stack so a use-after-free and the
  double-frees it causes are one cluster, symbols compare on their leaf
  identifier, and ASan symbolizer warnings no longer open a diagnostic that
  scored a symbolized trace as an unexpected crash. Unjudged artifacts are out
  of every score, and a saved report is re-attributed on render, so
  `--rebuild-report` is enough for a run reported before this change.

- **A cell the provider served with another model is kept and named.** A
  safeguard refusal makes the Claude CLI switch models mid-session and carry
  on; the harness had read that as a refused backend, marked the cell
  unavailable, discarded its reproduced crashes and skipped every later cell.
  Substitution is now its own outcome: the cell is scored, `.served-model`
  travels with it, the record and run summary name the model that served, and
  only a genuinely unavailable backend stops the run.

- **The direct control survives the provider and can be held to the wall.**
  A direct session that exited on "model at capacity" cost the cell and
  skipped the run's other cells; it now waits the interval the harness does,
  excluded from its wall, and re-enters with a fresh prompt for the wall it
  has left. `--hold-direct` re-enters a direct session that stops early until
  the wall, labelled `<model>-direct-held` on every renderer, for an
  equal-spend comparison; each session writes its own usage row, and a direct
  cell is clocked from its own start rather than its finalization rows.

- **Report-only rebuild, cache pruning and an operator scorer.**
  `bin/benchmark --rebuild-report` renders the root pages from run state
  without rescoring, and `bin/benchmark score` exposes the answer-key scorer
  the handbook had pointed at through an unstable library CLI. One ffmpeg run
  held 20 GiB of rebuildable harness binaries and 16.8 GiB of macOS `.dSYM`
  bundles: harnesses now compile and link separately so no dSYM is written, a
  settled run prunes every cache entry no evidence names, and `--prune-cache`
  (`--dry-run`) does the same for runs on disk. A relative `--bench-root`
  lives under `output/` (default `benchmark`); one escaping it is refused.

- **Receipts say who scored what.** Each row's Medium+ count names the scorer
  that produced it, S4 authored, built, invoked and ad-hoc harnesses are
  separate facts, and per-lane telemetry records the share of ranked cards
  each run examined, so a queue change that starves a lane cannot hide as a
  quiet yield drop.

### Backends and provider accounting

- **A provider that will not serve the model is caught and named.** Fable
  5.1's safeguards flag the audit contract as `cyber` and Claude Code retries
  on Opus, so a run requested as Fable was served by Opus while its rows named
  Fable. Preflight now sends the audit guide under the same vocabulary
  transform real prompts get and fails the run naming the safeguard category;
  the shared launcher recognises structured refusals from Claude, Codex,
  OpenCode, Gemini and Grok in the completed log, prints one `CYBER CLASSIFIER
  DETECTED` line, and rows carry `served_model` and are priced by it.

- **One isolation policy for every launch.** Web tools are denied on every
  launch the harness makes — agents in both security modes and one-shot
  decisions — on Claude, Codex, Gemini CLI, Grok and OpenCode, and a Gemini
  launch that drops the admin policy fails loudly. Delegation stays at each
  CLI's default, the model-direct control included, with `delegation_events`
  recorded; a backend whose delegated spend is invisible reports a floor with
  `$/confirmed` withheld.

- **No launch can write into the harness tree.** One-shot decisions inherited
  the harness process's directory, so a reviewer's relative scratch file
  landed at `SCRIPT_ROOT/.audit`; every backend now gets a throwaway working
  directory, removed with the answer. Agents launch with a Git ceiling at
  `targets/` appended to any inherited one, so an in-tree sample cannot read
  the harness's own history, and the audit binds the canonical target root
  once — a facade symlink had made SwiftPM crash on a second spelling.

- **Provider failures are classified from trusted events only.** Structured
  capacity errors count as provider-withheld capacity and structured policy
  rejections as terminal refusals, including codex's second wording, its bare
  usage-limit notices and Ollama's `statusCode` quota errors, which had billed
  a spent plan to the wall as failed sessions. Matches stay inside backend
  error events where target output cannot reach, and a classified failure is
  not retried by validation.

- **Spend is measured at the right rate.** Over 122 sessions a Claude prefix
  was almost never idle five minutes, so launches bill the five-minute cache
  tier: 10% cheaper at Opus prices, 20% at Fable. Fable 5.1, Mythos 5.1 and
  the OpenAI cyber models are priced, every other row is rechecked against
  the vendors' pages, and Grok's usage, tool calls and cost are read from its
  stream instead of being filed as character estimates. The claude default
  stays `claude-opus-5`, which is not refused; gemini defaults to
  `gemini-3.8-flash`.

### Target setup, coverage and cards

- **A forced reseed keeps a route that already runs.** `setup-target --force`
  replaced working routes with the seed's guesses: MSan became ASan, two
  samples lost their ASan binary, and four CLI runners became a registry
  default that treats a testcase as a program. A configured `[runner]`, the
  `[sanitizer]` policy — an explicitly empty one included — and named
  sanitizer binaries survive a reseed, as do a hand-authored `build_system`,
  upstream URL and runner when detection comes back empty.

- **Setup proves the route it hands the agent.** Cargo workspaces, Swift
  products, Ruby entrypoints and JVM classpaths derive from project metadata,
  runner canaries prove the target-backed entrypoint, ambiguous opaque-input
  routes are rejected, CMake's install plan names the public library and
  modular header roots, and bounded deterministic remediation runs before any
  LLM fallback. Backends are tried in a fixed order with the requested one
  first and rotated only when a different model could change the outcome;
  `JAVA_HOME` comes from the JVM's own `java.home`, Maven starts only from a
  root POM, Ruby without a Gemfile skips `bundle install`, a Perl checkout
  with modules under `lib/` detects at the root, and a native build no longer
  pulls a venv in because its tree carries a `pyproject.toml`.

- **Preflight fails before model budget is spent.** Interpreters run an empty
  program — and a typed source when the runner names a `.ts` entry — so a
  loader failure surfaces before the first probe. A route the host compiler
  cannot build (MemorySanitizer has no Darwin runtime) had spent a five-round
  recipe repair loop before failing; the compiler is probed once, only for a
  route this run will build, and the benchmark exits 3 so a launcher does not
  retry on the same host.

- **One coverage sibling per consumer.** libFuzzer exits at startup when any
  loaded object carries `trace-pc-guard`, so the single `build-asan+fuzz`
  sibling served `bin/hits` and killed every `bin/fuzz` campaign; `+cov` is
  built for replay and `+fuzz` for libFuzzer from the same recipe. A coverage
  run names its failure (`COVERAGE_NO_SANCOV`, `COVERAGE_TIMEOUT`,
  `COVERAGE_SYMBOLIZE_FAIL`, `COVERAGE_HARNESS_ONLY`) instead of one
  `EXEC_FAIL`, and a run's PCs are symbolized in one `atos` call under a
  deadline.

- **S7 cards require an input route.** Raw allocation and memory operations do
  not establish that testcase bytes reach a file; a parser, decoder or
  remote-peer route is required, and the verb match admits lowerCamelCase and
  prefixed names so whole Swift, Go and JavaScript files are not demoted.

- **A whole-target `bin/cleanup_state` reset clears build state.** Without a
  backend filter it removes the generated `build-<sanitizer>*` trees and transient
  `.audit/` entries while preserving the build recipes, resolving the source
  root from session state so a same-named checkout is never cleaned.

### Command line, samples and documentation

- **Help states defaults and requirements.** A bare `bin/audit` or
  `bin/benchmark` exits 2 with help instead of failing on a default target,
  and every option prints its help and any informative default. Options that
  duplicated a documented path or had no docs and no test are gone:
  `--new-target`, the `--<backend>-bin` flags (the `*_BIN` environment
  variables remain), benchmark `--hard` and `--ledger`, and the
  `BENCHMARK_VALIDATE_FINDINGS` default behind `--no-validate-findings`.

- **Samples are regenerated and re-keyed.** Every sample config but
  `sample-c-uninit`'s, whose MSan route the generating host could not build,
  is the output of `bin/setup-target --build --force`, and every key extends its bugs and
  traps against the disclosure taxonomy with declared classes.
  `sample-c-doublefree` and `sample-c-uninit` plant the two classes no fixture
  measured, `sample-python` gains a service, declared in its threat model, so
  every planted decision has a consumer the gate can trace, `sample-typescript`
  runs natively under Node instead of a ts-node that failed every probe, and
  Java and Kotlin score an unfiltered `readObject` as the bug it is. The
  release-build overflow the C, C++ and doublefree samples plant behind a
  debug assert now survives the optimizer, the MSan sample refuses a build
  on a host without an MSan runtime rather than reporting a clean run of its
  bug, and the C++ arbitrary-write example encodes an address that is
  application memory in every ASan shadow layout — `0xdeadbeef` sits inside
  x86_64 Linux's shadow gap, so the store tripped ASan's own check and
  reported the shadow address as a read while aarch64 and macOS faulted where
  the key said.

- **The handbook is checked against the code.** Every page is rewritten
  against `bin/`, `lib/`, `.agents/` and `AGENTS.md` with paths and anchors
  kept, and the isolation policy, delegation and spend floors, the cache tier,
  and the macOS Java and Kotlin startup check are each stated once and linked.
  The benchmark page ships a finished sample-c result with every count link
  resolving, tests no longer sample host properties such as configured targets
  or an installed toolchain, and the container lane digests the harness by
  mode bits so a root bind mount no longer reads as an edited tree. The lane
  pins `linux/amd64`, the CI architecture, and prints the architecture it
  ran on: an arm64 host had resolved the multi-arch image to aarch64 and
  passed a sample CI failed on (`--platform` overrides). The runner now
  compares tracked-file metadata before and after the suites and fails the
  run naming any file that changed, an ordinary write-and-restore included:
  two tests had edited `lib/` in place to stage a mid-run change and raced
  every benchmark snapshot beside them, a race only a loaded CI runner lost.
  Probes that compile a target before running it get a build-sized deadline,
  since a cold sanitized Swift build exceeds 60 s there. The development page,
  which every development agent loads at session start, drops about 40% of
  its tokens with every section and repository-specific rule kept, and now
  says that documentation-only changes still need the suite: tests read
  `docs/` and `AGENTS.md`, and the consolidation itself shipped with only a
  docs build and failed every CI lane on a test that pinned the page's prose.
  That test now pins only the startup prompt contributors paste.
  Dependency bumps: pymdown-extensions 11.0.2, actions/deploy-pages 5.0.1.

## 1.5.3 - 2026-08-30

This release closes the distance between what a run observed and what it can
show for it. Native targets get execution coverage for the first time — every C
and C++ run on disk had reported it unavailable — and that coverage now feeds
directed fuzzing, the card ranker and the agent. Around it, probe verdicts name
which repair they mean, severity grades a bug by magnitude instead of labelling
it by class, and the benchmark scores only the cells it could actually run. An
audit can also be scoped to a single commit, and the orchestrator and the test
suite stop paying for subprocesses neither needed.

### Native coverage and directed fuzzing

- **C and C++ targets get execution coverage.** `bin/hits` spoke only
  browser/JS, so every native run on disk reported coverage unavailable — 612
  of 612. `--mode generic` replays a testcase in an instrumented
  `build-<san>+fuzz` sibling and turns sancov into HIT rows and an edge
  journal; `setup-target --build` and audit preflight build that sibling from
  the target's own recipe, verify its guards and startup, and remember a doomed
  build. A guard-less sibling is a clean "coverage unavailable" rather than a
  raised environment failure, and a generic MISSED is feedback, never a skipped
  sanitizer run.

- **The instrumentation shim answers to every compiler name a build reaches
  for.** Naming a shim in `CC`/`CXX` assumes the recipe honours them, and a
  hand-written configure need not: ffmpeg's records `CC=gcc` even when
  `CC=clang` is exported, so the shim never ran and the sibling came out with no
  sancov section — indistinguishable from a working one until `verify_tree`
  refuses it. ffmpeg, pcre2, snappy, fmt and leveldb all carried uninstrumented
  siblings. The shim is now written under `cc`, `gcc`, `clang` and the `++`
  forms, with that directory leading PATH for the sibling build alone. A build
  that hardcodes an absolute compiler still fails loudly rather than shipping an
  uninstrumented tree.

- **Coverage reaches the ranker and the agent.** Offline `atos` printed
  basenames, so `coverage_gap_score` matched no card path and every subsystem
  ranked uncovered, and a HIT never reached `runs.jsonl` at all. hits
  symbolizes with full paths, keys journal edges target-relative and drops
  out-of-tree frames — a system header is not target coverage — and probe stores
  coverage and the closest frame on the run row that recent-runs prints.

- **S4 harnesses are grounded in the target's own callers.** The `bin/fuzz`
  template points at the two most instructive target-local callers and carries
  an S4 receipt the build binds to that exact source; status joins it with
  first-slice feedback, so a resumed agent sees what to repair. A guided
  harness that saturates lists up to three compatible public APIs as reading
  order for its one contract-preserving derivative — hints, never cards.

- **A replay runs with probe's own compiler, and a stale sibling is not the
  campaign's library.** Forcing `CC`/`CXX` to the fuzzing clang put two ASan
  runtimes in one process: every replay aborted at load, read `EXEC_FAIL`, and
  that rc=1 marked the artifact seen for good. The override is gone, and only
  CRASH, CLEAN, TIMEOUT or PROPERTY retires an artifact. The campaign also
  linked a `+fuzz` sibling whose stamp differed from the primary build — code
  the replay never runs — and now checks the same staleness reason `bin/hits`
  does and falls back with it. A seed copied from the target's test data that
  already crashes leaves the corpus instead of quarantining the harness on every
  slice.

### Auditing one commit

- **`bin/audit --since REV` scopes a run to a change.** A full audit re-scans
  the whole tree after every commit, so a landed fix waits behind unrelated
  work. Delta mode restricts the queue to the files changed in `REV..HEAD`,
  their one-hop CERTAIN-edge callers, and S1 cards for exactly those commits:
  floor and window off, no peer or campaign lanes, scope diffed from the merge
  base, and the delta recorded so a resume with different scope is refused. A
  trigger Reject carries across the pin while its cited anchors still match,
  keyed by content rather than revision.

### Probe verdicts and runner calibration

- **A CLI that rejects malformed input can reach CLEAN.** Such a target exits
  nonzero by contract, so every generic probe reported `EXEC_FAIL` and nothing
  on it could ever be clean — the crash lane was unusable.
  `setup-target`/`suggest-runner` replay the configured argv once and record the
  reviewed exit in `[runner].success_codes` without re-selecting the CLI, with
  the accepted range held to 0–123 so a timeout status, an exec failure or a
  signal death can never be declared success. `--force --build` calibrates the
  reviewed runner instead of re-selecting it, and an exit observed alongside a
  sanitizer diagnostic is refused.

- **Calibration describes the configured program, not a harness.** The `[runner]`
  exit set was applied to every generic execution, so an agent-built harness that
  exited 1 on its own setup failure read `EXECUTION VERIFIED` and probe recorded
  CLEAN toward the card-discard floor. A harness-built execution keeps rc==0 as
  its only success.

- **`EXEC_FAIL` and `NO_EXEC` name the repair they mean.**
  `verdict.execution_failure_class` reads loader, usage, input-rejected,
  aborted, unverified-exit or exit out of the saved output; probe prints the
  repair each implies, records the class, and threads the child exit code onto
  the run row — a clean rejection at rc=69 and a loader that could not start at
  rc=126 used to record the same bare `EXEC_FAIL`. A run the sanitizer budget
  refused carries `class=budget-exhausted` and its own repair line where the
  agent reads it, rather than the "fix the testcase" advice that sent one
  measured cell through 511 probes mutating an input against a refusal no input
  could satisfy.

- **A timeout is read before a partial clean.** The orphan-enforcement twin
  checked the clean pattern before rc 124, and a clean-then-timeout repetition
  prints a partial success rate, so the agent-facing line said CLEAN for a run
  probe records as TIMEOUT. Under the language runner the same ordering bug hid
  an S8 counterexample: an oracle that printed `PROPERTY VIOLATION` and then
  exited by assertion recorded `EXEC_FAIL`.

- **The runner canary proves what it claims.** A `PERL5LIB` or `RUBYLIB` entry
  that does not exist resolved under the target root and passed the path claim,
  so a runtime that skipped it and loaded the installed copy read as reaching
  the audited tree. The deadline now kills the probe tree rather than
  `bin/probe` alone — a severed cargo build kept running in a directory that was
  then deleted — and an unreadable `target.toml` logs the skipped check and its
  cause instead of passing silently.

- **A shell expansion is not a target path.** `-isysroot $(xcrun
  --show-sdk-path)` was resolved under the target root and exported as a
  `link_lib` resolver; any `$`-bearing token stays verbatim.

### The work queue and cards

- **An unreachable route no longer retires a whole file.** `ENV-BLOCKED` wrote a
  terminal `blocked` claim on whatever card the hypothesis named, and `blocked`
  is the one status that closes a broad card — so one blocked route discarded
  every remaining function in the file, which is the proof `blocked` is
  documented to require. A broad ranked-source card records the failed route as
  `discarded`, re-offerable behind fresher work; a concrete site card still
  closes, and a card the queue no longer lists takes the re-offerable side too.

- **The discovery slot survives a dry queue.** Telling every cardless cold
  worker to end its session also ended agent 1 on a queue whose cards were all
  blocked or outside every lane — the one launch kept for exactly that case,
  spent every iteration until the dry-streak cap. A cold slot quits only when
  another worker holds a card lease, which is the duplication the exit exists to
  avoid.

- **The corpus was never being filled.** `bin/state add-hyp` mints `H-` plus a
  sha1 prefix, but the header pattern was `H[0-9]+`, which matches no id the
  harness has ever produced: every promotable testcase failed the header check,
  so the coverage hits recorded across every run on disk promoted nothing and
  `corpus/` has always been empty. The same pattern classified source-extension
  testcases, which were therefore never counted or swept for orphans. The
  fixtures used ids production never mints, which is what hid it. The id also
  ends on an alphanumeric now, so a comment closer written without a space no
  longer lands inside it.

- **A not-reportable finding is not card yield.** An accepted-artifact claim was
  recorded for every non-pending state, so a defect the reviewers placed outside
  the threat model kept its card open as productive while earning no credit.

- **Cards carry caller and callee source, and the model can score the window.**
  `RANK_WORK_LLM_MODE=primary` lets the model score the window's key rather than
  nudge scores it re-asked about on every drift, with tiers, floor and card set
  kept; the verdict cache keys on the VCS content signature and candidate ids.
  Work cards gain a ≤600-token pack of caller/callee definition excerpts.

### Triage and severity

- **Denial of service is graded by magnitude, not by class.**
  `dos_amplification`, `regex_dos` and `memory_leak` all mapped to high
  availability impact, so a quadratic scan measured in milliseconds scored
  Medium like a decompression bomb. An optional `Availability loss:
  total|degraded` report field, graded from the report's own numbers, mirrors
  the existing disclosed-content mechanism on the other impact axis: only
  `total` keeps the high rating. Per-request fatal signals are excluded — a
  diagnostic already proved that request died, so there is no spectrum to grade.

- **A library-API bug is not labelled a CLI bug.** Export-repro's surface
  override fired whenever the narrative named a shipped tool, dropping attack
  vector to local for a bug in the library. It is narrowed to the boundary and
  trusted-caller fields, with matching trigger-provenance guidance in the
  prompt.

- **Retained crashes are visible and rejected findings are counted once.**
  Crashes kept but not reportable showed as a bare `0`; the crash cell now
  carries a `K retained` term. A rejected-finding directory an agent created
  but never wrote a report into inflated both the rejected count and the pool,
  and now requires a report.

- **A Promote that left scope unsettled publishes.** A first-pass Promote with
  `trigger_controls_fit` unclear or missing was an absorbing pending state:
  publication withheld credit without scope, the cached resolution called the
  vote settled, and no path ran the resolver — so a reachable,
  consequence-verified defect never published. It is now asked the way an
  Uncertain is.

- **A validated class outranks a prose keyword guess, and the scored primitive
  is recorded.** Prose "leaks" or "uninitialized" routed to the small-read tier,
  and that key was not one the two-reviewer validated class could replace, so a
  validated disclosure finding scored Low for its wording. The receipt also
  wrote only level, score and vector, so every later read re-parsed mutable
  report prose and 13.4% of reportable artifacts carried no structured class;
  the primitive and its key are recorded now. Cached reach fields are re-keyed
  to the policy that made fixed pre-input shaping application setup, so stale
  answers no longer feed severity a trigger source the prompt has stopped
  producing.

- **`CRASH_TRIGGER_GATE=0` is honoured by the batched round.** The serial gate
  and the cached shortcut skip the review under the opt-out; the batched round
  still launched it, spending reviews and parking any crash whose vote came back
  malformed.

- **Publication claims are bound to host evidence.** Source anchors are
  re-verified against a pinned checkout, only identical verified claims survive
  a trusted bundle transform, class concentration is reported over unique
  clusters, and an agent scratch frame is classified only on exact run ownership
  with no target frame present.

### Benchmark measurement

- **The direct arm reproduces what it files.** The model-direct crash lane
  invited a source-review scan without ever asking for the probe that would
  settle it, so the control filed source findings the harness arm would have had
  to reproduce. It now asks for the smallest faithful probe, or a recorded
  reason no public route can run one, before the next broad scan, and for a
  distinct shape on allocator-, state-, race- and timing-dependent triggers.

- **Planted findings-only bugs are scored.** A findings oracle credits a
  confirmed finding whose at-fault function is the planted signature symbol,
  counts a trap's symbol against precision, and leaves every other confirmed
  finding open-world neutral, rendered beside the crash block and reachable via
  `bin/benchmark score --findings-dir`. A trap fires only on a clean outcome: a
  trap whose expected outcome is an abort refutes that crash's promotion, not a
  source finding at the same function.

- **A finding count says how much of it is one class.** A class count reads as
  breadth even when one cheap class supplies most of the total — a measured
  ffmpeg control filed 168 findings whose top two classes were 158 of them, and
  the cell rendered that as 22 classes. The per-class counts are kept, and a
  dominant class is rendered as a share; the noisy top-class term was then
  dropped from the cell itself, which named a bug class in the scoreboard and
  stretched the column on a one-finding row.

- **A cell that could not run is excluded rather than scored short.** A
  model-direct cell whose CLI exited under a capacity limit was counted at its
  truncated wall while the harness excludes provider pauses from its own; it is
  marked provider-limited, artifacts stay, and a resume reruns it. A replay that
  came back unmeasured for a host-side reason no longer writes pending over a
  reportable receipt a measured replay had reached, a compiled harness keeps its
  source-shaped testcase instead of replaying with no argument, and a cell that
  never started records no results tree — it used to record `Path()`, which
  reads back as the working directory and had `relocate_experiments` calling
  `shutil.move` on the repository.

- **The reap claims campaign supervisors a marker cannot see.** A model-direct
  cell left 40-odd fuzz processes running and the reap raised rather than
  measure the next cell against them: a severed process group hid an opaque
  supervisor above a marked driver, and a supervisor asleep between its marked
  children was invisible entirely. Both are claimed now, each uniquely to one
  cell of one run, and a path claim is what a process actually runs — the old
  argv match plus parent walk could claim an operator's own shell.

- **The reap reads the same ownership answer on every macOS host.**
  `KERN_PROCARGS2` returns the kernel's own `apple[]` strings after the
  environment, and reading those as environment made a process exec'd without
  one answer like a process that has entries. A SIP-protected mac blanks a
  platform binary's environment and a mac without SIP discloses it, so the same
  opaque supervisor was claimed on one host and left running on the other — and
  the macOS test lane had been red on every run since the case was added. The
  probe now ends the environment where it ends, so no entries means the same
  thing on macOS and Linux alike.

- **Where the wall goes is reported per cell.** Occupancy, blocked
  housekeeping, time-to-first and lane share were recoverable only by hand.
  Session rows carry start and end times, phases and dispositions stamp
  `state/events.jsonl`, and the harvest renders an Efficiency table with
  confirmed-per-seat-hour and cost-per-confirmed columns. `POOL_OVERTIME=any-peer`
  lets a drained slot fill the most common refill refusal — an in-flight peer
  that is itself overtime — with its one capped session.

### Orchestration cost and honest labels

- **The orchestrator and the suite stop paying for subprocesses.** Repeated
  Python spawns and duplicate analysis passes became importable helpers,
  batching and cheap prefilters, keeping disposable-process containment around
  untrusted crash output; the full suite fell from 73s to 53–61s on macOS and
  from 49s to 42s on Ubuntu 24.04. Reading a receipt cost four revision
  detections — 95% of the read — and discarded every one for a receipt written
  before source attestations existed: a read no longer mints a source claim, and
  `read_current` on a pinned tree went from 6.69ms to 0.14ms.

- **An iteration's label says what it did.** An iteration that filed candidates
  the result gate deferred past the deadline was logged env-blocked with zero
  findings; filing and env-blocking are independent and the label now carries
  both, with a filed-but-unadjudicated state of its own. Crash discovery is
  stamped before the deadline defer, so a crash filed on the last iteration
  keeps a first-seen stamp the way findings already did.

- **A plain 401 line must name the credential.** Reading any plain
  `ERROR ... 401 Unauthorized` line as a refused backend let an audited HTTP
  library's own test output halt the run and mark the cell provider-limited;
  a plain line now needs the provider's credential tokens, while structured
  error events keep the full rule. Served-model ranking also sums only token
  counters — `contextWindow` sat beside them, so a 200k constant outranked real
  tokens and preflight refused healthy sessions as substituted.

### Documentation

- **The handbook is task-focused and checked against the code.** Reader paths
  for operators, security reviewers, upstream maintainers and contributors, with
  page URLs preserved and one name per page in nav, heading and link text.
  Several claims were traced back to `bin/` and `lib/` and corrected — preflight
  text, ecosystem bootstrap, one card per strategy angle, resolved-path sandbox
  grants, coverage columns, `--slug` backend selection, and the crash-state and
  cluster-header wording — and each remaining caveat is stated once and linked.

## 1.5.2 - 2026-08-28

Mostly about where an audit's time and attention go: which lane each agent
works, how much of the wall the fleet spends investigating rather than waiting,
and what a run that produced no diagnostic is telling the agent to fix. The
language, identity, detection and scoring work behind those closes the gaps
that made the answers wrong on particular targets.

### Strategy lanes and the work queue

- **The opening lane is picked by measured yield.** `expected_yield_rank` read
  its order from the reason-to-strategy table, which answers a different
  question — which angle claims a file that signals several — and ranked S3
  fourth, so agent 1, the slot that always launches, opened every audit behind
  three other lanes. Measured over 162 audit trees on 29 targets, S3 leads on
  productive hypotheses per hypothesis whether pooled, pinned or unpinned. Only
  S3 moves; both tables now say which question they answer.

- **`--strategy S<N>` pins the queue, not just the labels on cards.** The pin
  never reached `bin/rank-work`, so a pinned lane drew the shared mixed queue:
  S2 on angular claimed 24 of 309 cards, and now claims 120 of 120. A lane with
  its own card source builds from that source alone — S1 from patch cards, S4
  from its own campaign card, behind an admission gate that stops reading
  `nPage`-style handle parameters as byte lengths. An empty card source stops
  the run instead of skipping agents for the whole wall.

- **A pin the target cannot host stops before preflight.** A findings-only
  target under S4, or an S6 pin with no `[s6_peers]`, no longer pays for a cold
  Swift or Cargo build before stopping. OSV returns `[]` for an outage exactly
  as it does for "no advisories", so an unreachable peer set no longer reads as
  a finished campaign.

- **S6 cards carry the peer's real fix, keyed by its advisory id.** Card
  generation asked the model to map each peer fix onto a file from a 200-file
  listing: 46 sequential calls, ~389s of startup, and invented mappings. Cards
  now carry the peer's revision and summary, and the agent maps it behind a
  source gate. Keying on the end of an affected range also merged unrelated
  bugs, and excerpt fetching now stops at a budget rather than paying peers ×
  15-second network reads on every refresh.

- **S8 declares the property it tests.** It filed exception shapes as denial of
  service and ranked ordinary hashers as injectivity surfaces, where a collision
  is the contract. Ranking is explicit identity and key generators only, a
  testcase must declare `PROPERTY:` from a fixed set, and a real `PROPERTY
  VIOLATION:` records a `PROPERTY` verdict instead of NO_EXEC.

- **Each angle on a file is its own card, and a dry conclusion cannot retire a
  broad one.** Companions collapsed onto a single card, so clean S5 work closed
  it and discarded the untried S3, S7 and S8 angles; separately, three CLEAN
  probes retired a whole-file card and left every other function untested. Only
  `blocked` is terminal on a whole-file card now; other conclusions record dry
  work that ranking demotes behind fresher cards.

- **Workers stop repeating each other.** A reoffered card carries every worker's
  history, so a new owner no longer re-derives the prior finding and re-probes
  the same location. A cold worker that lost the claim race started unassigned
  source review and duplicated the owner's work — it ends its session instead.

- **The rank window grows again, and worked lanes stop reporting starved.** Both
  consumers read raw claim status as fresh work, so expansion never grew past
  `RANK_WORK_LIMIT` and the fleet rotated onto its `["S1"]` fallback while the
  queue was still offering those agents cards; both ask the claimer for an
  unworked card now. Ranking also scans the promoted corpus once per pass
  instead of once per file: 2000 lookups drop from 11.2s to 0.1s at 40 corpus
  entries.

### Agent time and housekeeping

- **A finished agent slot no longer idles out the rest of the iteration.**
  Refills stopped when the last initial session ended, so a measured 5h cell
  left two of three slots idle for 90 minutes while a peer held the barrier
  open. Each slot now takes one overtime session, and only beside a cohort-era
  peer. The finding gate and cluster expansion also ran back to back with no
  agent running, for 13–29% of the wall; they touch disjoint trees and now share
  one span.

- **The orphan-testcase budget is spent across the fleet, not on agent 1.**
  Housekeeping probes up to three testcases an agent wrote but never ran, and it
  drained agent 1's queue first: on three measured 5h cells, 17 of 18, 5 of 6
  and 3 of 5 enforcements went to agent 1. The budget is taken round-robin now.

### Multi-language execution

- **A probe cannot report CLEAN against code that was never audited.** Preflight
  ran the interpreter's `--version`, which proves a runtime starts, not that a
  testcase reaches the target — plain `perl` resolved a module from the system
  library instead of the synced checkout. Each language now carries a canary
  asserting the runner executed in `TARGET_ROOT`, searched imports inside it,
  and was counted, and an unreachable runner hard-fails setup, audits and
  benchmark cells (13 pass, 3 skip across 16 language targets).

- **Go, Ruby, Perl and R load the audited checkout.** Testcases live under
  `output/`, so a configured runner ran outside the audited module.
  `[runner].bin` and a compiled Go `HARNESS` now run with `TARGET_ROOT` as their
  cwd, `PERL5LIB` and `RUBYLIB` point at the checkout, and an R package installs
  into `.audit/r-library`.

- **A Go target's bootstrap primes the build cache the runner uses.** Go ships
  no precompiled standard library, so on a cold host the first `go run` — the
  runner canary itself — compiled std inside the 15-second per-run deadline and
  the route read as unreachable. `go build std` now runs first; the -race build
  caches separately and never covered it, and because `-race` needs cgo, a host
  with no C compiler falls back to the plain release build rather than failing
  setup outright.

- **Rust testcases build against the audited crate.** A library-only crate has
  no `cargo run` route, and a raw-rustc `.rs` testcase could not import the
  target at all. A direct `.rs` testcase or `HARNESS: <name>.rs` driver now
  builds as a detached Cargo package path-depending on the crate, in release
  mode, carrying only the dev-dependencies it names.

- **Swift builds its sanitized product once, in preflight.** `swift --version`
  passed while the package did not build, and every testcase then re-entered
  SwiftPM planning inside its 15-second budget with all sanitizers overwriting
  one product. Each enabled sanitizer gets `.audit/swift-build-<san>`, and the
  product name comes from `[runner].args` rather than the slug.

- **macOS keeps the launcher's PATH order.** `path_helper` runs from
  `/etc/zprofile` in a login shell and could move `/usr/bin` ahead of the
  configured Java or Kotlin toolchain. The login shim restores launcher order
  and keeps genuinely new `/etc/paths.d` entries at the tail.

- **A cached harness binary cannot outlive its target revision.** The cache
  identity carries `TARGET_REV`, so a harness under `results/` no longer
  survives the checkout moving underneath it and judges the previous revision.

### Probe and runner verdicts

- **A timeout is its own outcome, never a clean run.** `run-sanitizer-multi`
  collapsed a timed-out run into "may not have executed", so a target that
  consumed its wall looked like one that never ran. It reports `verdict=TIMEOUT`
  and exits 124, reserved by `lib/timeout.py` and not configurable as a runner
  success, and `bin/probe` classifies that 124 ahead of the agent's own markers
  — an S8 oracle that printed its property marker and then hung is no longer
  credited with a counterexample. A concrete sanitizer diagnostic still wins: a
  sibling deadline cannot retract it.

- **A rejected input is not a broken harness.** A parser CLI that correctly
  rejects malformed input exits nonzero, and every such probe was recorded
  NO_EXEC. The new `[runner] success_codes` declares which exits mean a
  completed invocation, bounded to 0–123 so a timeout, a signal, or a sanitizer
  diagnostic can never be declared success.

- **`NO_EXEC` stopped meaning three different things.** It covered a run that
  never started, a run the target rejected, and a run the sanitizer budget
  refused — and its advice sends the agent to repair the harness, the wrong
  repair for two of the three. Over three measured 5h cells, 133 of 150
  `NO_EXEC` rows had in fact run. `bin/probe` and orphan enforcement now use the
  `EXEC_FAIL` split the runners already used, a refused run carries its own
  diagnosis, and the hint sends the agent to read the output. No gate moves:
  across 1631 saved sanitizer outputs, no CLEAN or CRASH classification changes.

- **A trusted execution marker starts on its own line.** A runner whose output
  ended without a newline had `EXECUTION VERIFIED` concatenated onto it, and
  every consumer anchors that match at a line start — so a real run read as
  `EXECUTION_RATE: 0/1` and repeated attempts marked the card
  environment-blocked.

### Crash and finding identity

- **One report supplies the whole crash signature.** A confirmation transcript
  concatenates every repetition, so attribution read the access line from the
  first report and the crash site from the last — a fault pair no run produced.
  Primitive, access, crash site, signature and the replay comparison now bind to
  the first complete diagnostic.

- **Inline expansion stops splitting and merging clusters.** ASan expands an
  inlined instruction into a frame per name while an offline `atos` pass over a
  `-g1` binary prints only the outermost, so requiring frame #0 to match split
  one crash by symbolizer. Clustering intersects the ordered leading inline
  group, and tolerant tail matching requires the same `top_func` so two faults
  behind a shared dispatcher stay apart. The symbolizer also stopped stripping
  parenthesised spans from an `atos` answer, which deleted C++ parameter lists.

- **A report opens with one bare `Location:` line.** Finding clustering keys on
  it, but the prose contract never asked for one and the two parsers carried
  separate extension lists — Kotlin, R, uppercase extensions and qualified
  method names degraded to duplicate-prone, line-less keys. Both read
  `languages.source_reference_ext_pattern()` now and match case-insensitively.

### Triage precision and cost

- **A dangerous API alone is not a security finding.** Seven shapes with no
  crossed boundary were being accepted, among them a path escape where the same
  input picks base and child, gadget-free deserialization, and a managed
  exception that only fails the current call. Each has an explicit reject bucket
  with a named escape, and the emit contract mirrors them. Control also comes
  from the traced entrypoint rather than a name: `hook`, `plugin` and an
  authored `Boundary` label were read as evidence of trust.

- **Fixed fallback setup is application setup, not an attacker call sequence.**
  Contract-obeying resource shaping before input consumption — filling a bounded
  cache, pool, or descriptor allowance — read as attacker-required, so a
  byte-decided fault reached through it landed outside a bytes threat model.
  Shaping the attacker must control or repeat per attempt is still a real
  trigger component.

- **A filing is not an acceptance.** `bin/state list-findings` reported OK for
  any directory holding a report, and clusters took severity from the report, so
  a retained not-reportable defect kept a stale High and could outrank a
  reportable duplicate. Status now comes from the content-addressed validation
  receipt, no-credit rows rank below every credited member, and the agent's own
  view calls a filing recorded and surfaces a triage rejection with its reason.

- **The review gates cost a bounded share of the wall.** One trigger reviewer
  spent ~1339s of an audit wall on a single finding; that gate now states a
  12 tool-call budget, refuses subagents, and stops at a hard cap above it,
  while the finding-quality gate stays unbounded as a full second opinion.
  Cluster expansion and the crash trigger rounds spend one session per group
  instead of one per artifact, and an id a batch omitted stays pending rather
  than publishing on an incomplete vote.

- **An adjudicated crash notices a bumped decision version.** A receipt binds
  its own report and gate files, so it could not see
  `TRIGGER_GATE_DECISION_VERSION` move under an unchanged vote — and the crash
  lane short-circuited on the receipt alone.

- **Live triage uses the identities finalization uses.** `post_iteration` ran
  both gates without the product-root identity, so a live run could reject a
  sample target's whole surface on its root-level documentation and reach the
  opposite verdict at finalization. Agent credit also joins on the canonical
  artifact id, so a renamed `FIND-004-<slug>` keeps its author.

### Build and target detection

- **Detection picks the product, not whatever sorted first.** A library-only
  CMake build could not say it had no CLI, so the free scan handed `asan_bin` a
  unit test, fuzzer driver or examples client. An installed executable is the
  product CLI now, while a project declaring no `install()` rule keeps its
  scanned route — across 20 built targets, three fake CLIs dropped, two
  reordered, none added. Sanitizer archives rank by the project's own identity
  for the same reason.

- **Build freshness reads the configured build system.** A Swift or Cargo
  package shipping an incidental `CMakeLists.txt` reported `build-asan` missing
  and preflight tried to converge a tree the target never uses. Freshness now
  covers a stamped tree this configuration still routes a sanitizer artifact
  through, so a stray build directory cannot refuse runs over a tree nothing
  executes.

- **The C-harness build route repairs and resolves itself.** `link_libs` archive
  and source entries reached the compiler verbatim while every sibling input was
  target-root resolved, so a probe or campaign build launched from another cwd
  failed to link; `Config.resolved_link_libs()` now serves every consumer.
  `setup-target` also merges detected public headers into a broken `includes`
  set when they agree with the configured library, instead of only warning.

### Benchmark scoring

- **A bug's alternate runtime shapes score as one bug.** A missing pointer
  invalidation reads as use-after-free or double-free depending on order, and an
  optimizer inlines a Swift READ and WRITE into one wrapper. Manifests may list
  `alternate_signatures` as aliases for one bug id; validation rejects an alias
  that overlaps another bug's key.

- **Two answer keys were scoring the wrong thing.** `sample-cpp` named bare
  `handle_table` where the crash-state symbol is `rbundle::handle_table`, so
  none of its five bugs could ever match, and every sample counted lexical path
  traversal as a planted bug when the same job file supplies both the root and
  the child name. Those are precision traps now. All 16 committed manifests
  validate.

### Test lanes

- **A test constructs the host property it needs.** Two suites sampled the host
  instead: one waited for a supervisor whose environment the process probe
  cannot read, and the Go route probed an unbootstrapped module, which passes on
  a warm developer machine and times out on a fresh CI runner. Both build the
  condition now.

- **The container lane runs the compiled routes it used to skip.**
  `--install-container-deps` installed no Go toolchain, so every container run
  reported green while skipping the Go probe route entirely; the entry command
  also went through a login shell, whose `/etc/profile` rebuilds PATH and drops
  what the image itself put on it. Go is installed and verified with the rest,
  and the image's PATH order is restored ahead of the profile's additions.

- **A container run leaves no bytecode in the checkout.** The tree is
  bind-mounted, so a run wrote `__pycache__` entries that the next run — a
  different image, a different Python — read as its own, and a partial write
  failed a suite with `EOFError` before a single test ran. The container caches
  bytecode under its own prefix now. The release checklist runs both lanes
  before notes are written.

## 1.5.1 - 2026-08-23

- **A benchmark row is priced and labelled by the model that actually served
  it.** A CLI answered `--model gemini-3.7-flash` with a cheerful OK while
  serving gemini-3.5-flash for 100% of tokens, so every row named a model that
  never ran and priced $1.50/$9 traffic at $0.75/$3.75.
  `llm_usage.substituted_model()` now gates the `bin/audit` preflight and ranks
  ahead of the quota marker in `bin/benchmark`: a substitution is settled
  evidence that the cell measured something else, while a capacity limit only
  means it was cut short. It judges on the busiest served model, since one
  session legitimately bills a small helper model beside the one it asked for
  while a token of the requested model beside a million of another is still a
  mislabelled row; it reads exact telemetry positions so a "models" object in
  tool output cannot trip it, and absent telemetry falls open. A TTL-shaped
  `[1m]` decoration is stripped and an arbitrary bracket is not, so flash and
  flash-lite stay distinct and `claude-opus-5[1m]` still gets its real price
  row. The preflight records a refusal through the provider markers, so a
  harness-only run recognises it instead of retrying a deterministic rejection
  every replicate.

  The rate card is the cross-backend denominator, and four of its rows were
  wrong. The whole GPT-5.6 family carried the previous generation's rates —
  Sol, the codex default, billing 5/0.50/30 where OpenAI publishes 4/0.40/20,
  and Luna out by 5x; Gemini 3.6 Flash was pinned at its post-promotion rate
  while it is on the same promotion as 3.7; Sonnet 5 stepped up on an announced
  increase that was cancelled; and Sonnet 4/4.5 carried a >200k premium that
  existed only under the retired 1M-context beta, where no real request can
  reach the threshold. No row keys on a date any more and the machinery for it
  is gone with them: an announced future change is not a rate — Sonnet 5 is the
  standing proof — and a dated table restates a completed run's spend on a day
  nothing actually happened. When a price changes, change the row.

  Token counts were wrong on one backend in the same direction. `harvest_tokens`
  normalized oss as cumulative-input and subtracted cache reads, but OpenCode
  reports `input` disjoint from `cache.read`, so a real ffmpeg cell reported
  64,939 input tokens instead of 2,886,075.

- **Regeneration no longer rewrites a finished cell as incomplete.** A rebuilt
  target tree failed the run's build pin, and `--regenerate` scored that as a
  fresh measurement of cell quality — dropping a done/clean cell out of its own
  aggregate even though its finalized receipts still described evidence produced
  under the pinned build. An unavailable replay build is a replay limitation:
  status and `run_quality` are preserved, the reason is recorded in
  `build_finalization_error` and removed if the pinned generation becomes
  available again, and unresolved evidence stays unadjudicated. The conservative
  gate itself is unchanged — replay still fails closed, only current
  content-addressed receipts earn credit, `finalizers_ok` still keeps a
  genuinely incomplete cell from being promoted, and no unavailable build can
  manufacture a verdict.

- **A cell stops spending its wall idle.** An agent on a lane with no claimable
  card was never reassigned: `initialize_agent_strategies` wrote only when the
  value was unrecognised, and post-iteration rotation never runs on a
  provider-interrupted iteration, so one cell held an agent idle for 88% of the
  run beside 104 unclaimed cards. Rotation now happens at assignment time, after
  the rank pass that mints companions, and only when the agent holds neither a
  live claim nor an open hypothesis in that lane — counted across the card's
  primary strategy and its `allowed_strategies`, since a claim taken through a
  carried-over companion angle is still that agent's work. An operator
  `--strategy` pin still wins.

  The direct condition wasted its wall a different way: the prompt banned
  ps/pgrep-driven kills without saying how to keep a PID, so jobs started as
  `( ... & )` held slots to the deadline and one cell spent 52% of its wall
  asleep at the concurrency cap. The guidance now appends the PID to a rendered
  absolute path under the cell's own output dir, because a shell variable does
  not survive between tool calls. `benchmark_model_direct_render.main()` also
  dropped `argv[4]` and rendered a CLI prompt with no deadline line at all.

- **`--backend oss` starts an audit without a hand-typed security flag.**
  `sandboxed` was the default for every backend and OpenCode is refused under
  it, so even inside a proper container every oss launch needed
  `--agent-security external-bypass` spelled out. The default now resolves per
  backend: oss picks external-bypass, the only profile it can actually run
  under. OpenCode's permissions were verified against its CLI and its own docs
  to be an in-process approval gate rather than an OS sandbox — there is no
  sandbox flag anywhere in its command tree — so `sandboxed` has nothing to run
  it inside. Hosted backends are untouched and `--backend all` still resolves
  sandboxed.

  An unasserted bypass now warns rather than refusing, which relaxes the gate
  1.4.1 shipped. `IS_SANDBOX=1` is the operator's assertion that an outer
  container or VM exists, not a measurement of one, and gating the oss default
  on it only moves the refusal — the fallback is the profile OpenCode cannot
  use. Its absence prints one warning per process naming exactly what is
  unconfined: no CLI sandbox confines the agent, nothing has asserted that a
  container does, and agents run target build scripts and harness-authored
  testcases with this account's filesystem, credentials and network. Capability
  refusals are a different claim and are unchanged — no flag grants a CLI a
  sandbox it does not have — and that reasoning now lives in
  `--agent-security`'s help so the guides state it once.

  Defaults moved with it. gemini is gemini-3.7-flash and grok is grok-4.6, with
  the new Gemini slug mapped to its exact `agy` display label: agy selects by
  label and silently falls back to its remembered `/model` when handed anything
  it cannot resolve, so an unmapped slug means every gemini run quietly audits
  under whatever the CLI last used. An `opencode/<id>` catalog model is passed
  through untouched instead of being rewritten to `local/opencode/<id>` and
  handed a synthetic provider pointed at 127.0.0.1, while a served model id that
  merely contains a slash still routes to the local adapter. The container shell
  installs OpenCode, so the boundary it asserts has something to hold.

- **A crash that reproduces reaches a verdict instead of stalling as unjudged.**
  Three defects each held a reproducing crash unadjudicated: replay substituted
  only an argument equal to the bare token, so `scheme:{TESTCASE}` stayed
  literal; the bundle contract asked for `harness.c` while the gate reruns a
  compiled binary; and UBSan/TSan/MSan named their checks from fixed lists that
  had rotted, leaving division by zero and MSan's own SEGV with no fault key, so
  a replay that reproduced 5/5 read the same as one that never ran. The kind is
  now read from what the report states, anchored to the sanitizer's own line so
  target output cannot supply it, with the fatal-signal ERROR line as the
  fallback. A CLI replay also dropped the configured `[runner]` block when no
  `[runner] bin` was set and substituted `asan_bin` for a sanitizer the binary
  is not built with — the run is then clean whatever the input does, and
  `not-reproduced` disqualifies the crash. The block now applies on `bin/probe`'s
  carrier rule, where it belongs to `runner_bin`, and no contract resolves where
  the binary cannot be shown to carry the instrumentation. Three ffmpeg bundles
  that had stalled now replay 5/5.

- **A stuck trigger review is settled instead of staying pending forever.** A
  lone Uncertain vote and a Reject/Promote split were both treated as
  cache-complete while publication correctly kept them pending, so regeneration
  had no path to adjudicate the unjudged remainder that marks a benchmark count
  a floor, and the state was absorbing. Independent reviewers also never saw
  each other's evidence, so a Reject naming a disproved consequence and a
  Promote arguing a reachable trigger answered different questions and could not
  converge. One focused resolution review now runs for exactly those two states:
  it receives the prior rationales, is asked to settle their specific
  disagreement rather than review blind, and emits a verdict only when source
  anchors establish which prior reading is correct — otherwise it stays
  Uncertain and names the open fact. It owns the verdict and the question it was
  asked, not the facts the reviews already agreed on: `vulnerable_boundary_surface`
  overrides the Surface that severity scores, and the split reviewers agreed on
  it every time while disagreeing only about scope, so consensus stands there
  and the resolution fills the rest. Its cache is bound to the report, the
  evidence, the prompt version and the exact prior reviews it adjudicated, and
  carries its own decision version so changing resolver policy never invalidates
  the first-pass votes. The two-Reject suppression rule is unchanged, and
  genuinely unresolved cases still stay pending. On the artifacts on disk, 16 of
  321 reach the new review, and only in states that previously had no path to a
  verdict.

- **A work card cannot be hard-closed outside the evidence gate.** `done`
  closes a card exactly like `discarded` but was missing from
  `update_card_status`'s status list, so one benchmark cell retired 18 cards
  that way — 11 of them never probed. The gated set is derived from
  `PERMANENT_TERMINAL_CARD_STATUSES`, and `bin/state` maps `done` onto
  `discarded`.

- **A report's rendered sibling survives a case-insensitive filesystem.**
  `find_report` probed `directory / name`, which APFS — or a Docker Desktop bind
  mount over one — answers for whichever spelling it is asked. Triage hands that
  path to `render-md --html-sibling`, which names the sibling after it, so a
  `report.md` artifact published `REPORT.html` that the exact-name link lookup
  then missed. The exact-case lookup three modules had each grown privately now
  lives once in `report_identity` beside `REPORT_NAMES`, reading the directory
  with `scandir` so the correct answer costs tens of microseconds in triage's
  per-iteration passes rather than hundreds.

- **The handbook says what the code does.** Every concrete claim in `docs/` was
  checked against `bin/`, `lib/`, `.agents/` and `AGENTS.md`, and eight were
  wrong in ways a reader would act on: cluster ids are `CL-<8 hex>` and
  `FCL-<8 hex>` hashes of the cluster signature, not `C1`/`F3`; an out-of-scope
  crash takes no numeric score at all rather than a downgrade; the glossary had
  the Validator ranking the work queue and made attacker reachability a
  promotion gate rather than a reportability one; and Java sanitizer support was
  credited to a component that appears nowhere in the tree.
  `findings-rejected/REJECTED-FINDINGS.html` is written on every triage pass and
  was documented nowhere, so a reviewer had no way to audit a rejected finding;
  it is now named everywhere its crash-side twin is, along with the fourth
  result lane it implies, `validation.json` in every bundle listing,
  `--allow-concurrent`, `--no-alternates`, `AUDIT_MODEL_PREFLIGHT_TIMEOUT`,
  `AUDIT_FORWARD_CREDENTIALS`, the `{NULL_DEVICE}` runner token,
  `TARGET_CONFIG_SHA256`, and the rlang/perl runner rows. Counting policy, the
  triage gate rules and the prerequisites tool table were restructured rather
  than trimmed, with anchors preserved and nav labels matching the page titles
  they disagreed with.

## 1.5.0 - 2026-08-21

- **S4 is now boundary-directed fuzzing, and it actually runs.** S4 was a
  reserved identifier no generator could feed, and S7 carried a seed-and-harness
  half its own playbook told agents not to run, so nothing fuzzed. `bin/fuzz`
  admits an API only when the build publishes it, the declared threat model
  reaches its parameters, and no harness already drives it; it lints out the
  three harness shapes that forge state or reach past public headers, runs
  bounded slices with health quarantine, and replays every artifact through
  `bin/probe` with its hypothesis, sanitizer and build compiler attached.
  Progress counts features as well as edges, because value profiling reports
  through `ft` alone and a campaign watching `cov` would quarantine the harness
  it had just switched on; coverage totals are reported, never divided, since
  the instrumented total spans every loaded module.

  Minting the card was not enough to run it. Strategies are assigned by
  descending card supply, and S4 owns one target-level campaign card by
  construction — one corpus, one lock, one campaign per iteration — so a lane
  holding a whole iteration of work sorted behind every lane holding a list of
  files, and came last on all four benchmark targets. Supply is breadth and a
  campaign's is depth, so it is no longer ranked at all: it is reserved on the
  highest-numbered reproduce worker, and ranked lanes compact over the agents
  that remain. `bin/probe --harness` names the harness an opaque fuzz artifact
  came from, which its bytes cannot carry, and harnesses build out of tree so a
  campaign cannot stale the shared build for a peer backend.

  A harness linked `-fsanitize=fuzzer,address` against a library that already
  loads its own runtime got two runtimes in one process and aborted before the
  first input — 6 of 12 native targets, every campaign dead at slice 1. The
  link stays sanitized, because those redzones are what report a target
  overrunning a buffer its *caller* owns: `bin/fuzz build` proves the binary
  starts before a campaign spends anything, and only a duplicate-runtime abort
  earns a relink without the sanitizer, with a remedy naming what that costs
  and how to undo it. Anything else that cannot start is a build error carrying
  the runtime's own message, not a slice reported as `dead`.

- **Security yield now requires a trigger inside the threat model.** Every kept
  artifact counted as security yield even when its trigger fell outside the
  model, so out-of-scope defects earned Medium+ severity. Only `reportable`
  counts; the other lane is `not-reportable`, never "Low" — a CVSS Low is a
  real report with small impact and the two must not share a word. Scope no
  longer comes from the report's own `Trigger source`, which the finder writes
  and which is wrong in both directions: judging on it punished the work that
  builds reproducers. The trigger reviewer reads source and cites verified
  anchors, so it answers the scope question itself, and `not-reportable` may
  only assert what a review established — an `Uncertain` verdict or two
  disagreeing reviewers stay `pending` and are counted in the unadjudicated
  remainder that marks a benchmark count a floor. A decided out-of-model call
  from an anchor-verified `Uncertain` vote is kept rather than dropped, since
  that direction can only withhold, never publish; its citations are re-read
  against current source first, because `not-reportable` is terminal.

  Impact stops being minted by vocabulary in the same move. A bare
  "uninitialized", "leak" or "internal representation" in report prose returned
  the `info_leak` row, whose VC:H granted High confidentiality with no evidence
  anything reached an attacker; prose alone now lands in the conservative
  small-read tier, while the MSan diagnostic, an explicit disclosure claim and
  a structured `Primitive` field still classify. One real finding whose
  observed effect was a hang drops from Medium 4.8 to Low 1.1.

- **A run that cannot act stops instead of publishing a clean zero.** Codex
  0.149 refuses to create any process while a writable root contains a symlink
  component, so a benchmark cell's facade target grant killed every command in
  110 of 127 agent sessions — that harness row scored 0 crashes where Claude
  found 5 on the same target and build, and the wall was spent publishing
  silence. Granted directories are now resolved once, for every backend, since
  granting both spellings fails just as hard.

  The startup probe should have caught it and could not: it asked the model to
  reply, under a narrower set of directories than the audit uses, so a backend
  unable to create a single process passed. It now runs under the audit's own
  grants and must write through them, into the target `.audit/` where the build
  lease already lives, which also catches a grant that arrives readable but
  silently unwritable. One probe for every backend; each attempt clears its
  sentinel first, so an attempt that wrote and then failed cannot pass the next
  one on evidence it did not produce. Sessions also record a tool tally in
  `index.jsonl` — telemetry, not a verdict, since a count cannot separate a
  blocked agent from one that read its state and concluded.

  A backend that refuses the request is now its own class. A revoked OAuth
  token matched none of the capacity or transient patterns, so every dead
  session read as an ordinary dry iteration: the run stopped early and the cell
  published as clean and done, which a same-run-id resume then skipped as a
  valid measurement. A refusal — a turned-down credential, or a model the
  installed CLI cannot serve — marks the cell unavailable and never pauses or
  retries, so no wall is subtracted for capacity that was never coming back. It
  is read from a backend's own error field as well as its CLI error lines, and
  threaded rather than collapsed, so `rate_limit` keeps meaning retryable.

- **Crashes stop being unmade between capture and replay.** Four layers each
  kept their own ASan class list and all four omitted `stack-buffer-underflow`,
  so a crash that replayed 5/5 against its own fault scored a mismatch and
  published as an unjudged remainder; the vocabulary now lives in one place, as
  the exact names the runtime prints, anchored to the runtime's own
  ERROR/SUMMARY headline. Replay answers one question — did the same fault
  happen again — and no longer consults the crash gate's admission policy, so a
  future omission cannot unmake a reproduction. Fault identity matches the
  leading inline group, because a crash captured with the in-process symbolizer
  keeps an inlined name the offline pass does not. A bundle whose harness had
  migrated into `.audit/` matched the leftover `.dSYM/` directory and exec'd it;
  resolution now requires a regular file. `no-contract` no longer demotes: it is
  reported for a build that is gone as readily as for a real answer, and on one
  ffmpeg set it had moved 17 reproducing crashes into `findings/` permanently.
  A `main()`-bearing API driver picked by name alone resolves as the uncompiled
  harness it is, rather than being fed to the target as CLI input.

- **Clusters group again.** A real cluster stamp carries a per-report member
  summary naming the *other* members, so every member produced a different key
  and nothing ever grouped — 22 pooled crashes read as 22 clusters where there
  are 14. Both row forms are now read as their stamp, and the placeholder
  `bin/cluster-crashes` writes before an id exists has one definition shared by
  the writer, the renderer and the clusterer. The stamp also anchored on the
  first `^# ` anywhere in a report, so an untitled finding took it inside a
  repro fence where identity is byte-sensitive: a severity receipt written
  moments earlier read as stale and the pre-swap pool audit refused to publish
  the whole run. Report metadata split by blank lines above `Summary` is
  recognised by position rather than by label, so author-defined fields render
  in the report's Fields grid instead of falling through to the generic
  renderer.

- **Benchmark cells keep evidence that was never in doubt.** Cells were excluded
  whenever tracked bytes under `AGENTS.md`, `bin/`, `lib/` or `.agents/`
  differed from a run-start pin, and ordinary development on the checkout
  tripped it — a libxml2 run lost both 5h cells to a pin taken on a dirty tree.
  That pin is gone; the target source and build pins, which do decide what a
  cell measured, are unchanged. An empty `FIND-*` shell no longer counts as
  unowned evidence, and a direct backend that exits nonzero after hours of
  productive work is retained behind an `(Nt)` marker and its shorter actual
  wall. Batched review inherited the single-item prompt's text but not its
  answer contract, so every positive review stalled unresolved on the in-run
  gate and the post-cell drain alike; the shared contract moved above the split
  and schema parity is asserted so the two cannot diverge again. Crash replay
  ranked the extensionless name the direct contract mandates below any sibling
  beside it, reporting clean on a derived file, and a run stopped inside
  unbounded finalization now checkpoints its wall instead of needing a fresh
  audit to be scored. The unadjudicated warning stops promising a
  `--regenerate` that cannot move a review which ran and could not settle.

- **Sandboxed Claude gets its Bash back.** Launches ran with no allow rules, so
  whatever the rules left undecided was denied — `;`-chained and multi-line
  commands, about 9% of harness Bash calls, including `bin/peek`, `bin/state`
  and `bin/probe`. Bash is now allowed, since the sandbox is what arbitrates it:
  writes stay inside the `--add-dir` grants, egress stays blocked, and `deny`
  still wins. Only Bash — nothing here grants the file tools. Out-of-model
  crashes stop being steered at: the index names that state and the filing rules
  say it, while expansion still runs on such a seed and now carries
  `attacker_controls` so the neighbours it proposes are ones the model reaches.

- **`setup-target` seeds a config the audit can actually use.** A `--force`
  re-seed dropped the curated threat model and peer set and left replacing them
  to LLM helpers that do not always run, so an operator's `attacker_controls`
  and peers could vanish with nothing to recover them from; they now carry
  across. Generated headers land in the build root rather than under `include/`,
  which was the only build entry for one target and left it unable to compile a
  harness at all. A computed program name is no longer treated as a complete
  manifest read — cjson resolved 2 of its 21 executables that way — and the
  binary already in the config is probed after the builds, against the route the
  audit will use, reporting rather than repairing because neither answer is
  proof. Runner selection repeats a launch on one input before comparing
  anything, after a throughput benchmark passed as a reader on timing noise
  alone and moved one audit's surface from a TLS client to hashing bytes.
  Library and include detection ranks depth over name order and stays advisory,
  reporting a stronger detected pair for review rather than overwriting operator
  provenance.

- **Sessions stopped before their terminal event are priced.** A backend that
  reports usage only in a terminal event reported none when the turn cap or the
  wall deadline stopped the session first, so a run's longest sessions —
  including every model-direct cell, which always ends at its deadline — priced
  as zero. Spend is recovered from the backend's own session record, and a cell
  is classified on whether a row reported usage rather than on how it exited.

- **The test suite stops paying a process where a call would do.** It is
  process-startup bound: every `bin/` entry point costs 120–260ms of interpreter
  and import, and the same chains run in an audit. `lib/timeout.py` paced its
  reap poll and its `ps` sampler on one 0.5s tick, billing every sanitizer run
  half a second of sleep after its command had already exited; the reverify
  resolver re-entered `lib/benchmark` as a subprocess per crash to call a
  function already in memory; and pool rebuild asked each cluster tool twice,
  once for JSON and once for reports, clustering the same tree twice. On an idle
  machine the four slowest suites go 146s to 99s, with crash reverification
  halving. Only a whole-suite run may write the scheduler's timing artifact — a
  filtered run left it holding a few rows and the next full run packed badly.

- **macOS and container runs stop failing on their environment.** Process-tree
  inspection shelled out to a `ps` mode macOS denies unprivileged callers, and a
  captured command still inherited a live caller pipe, so an argument-driven
  decision backend could wait out its whole timeout; there is now a Darwin
  `sysctl` fallback and every no-input launch gets `DEVNULL`. Contributed in
  [#2](https://github.com/tokenfuzz/tokenfuzz/pull/2) — thanks to
  [@Dor1s](https://github.com/Dor1s). Symbolizer teardown no longer discards a
  stacktrace it had already symbolized when `addr2line` exits on a binary that
  is not there, and two fixtures stop depending on the host — an unwritable
  lease fixture that root could still open, and a broken-pipe payload larger
  than the default write buffer on everything but Python 3.14.

## 1.4.1 - 2026-08-10

- **A work card carries the source call graph instead of asking for a grep.**
  An assigned card had no structural context, so every agent re-derived who
  calls this and how input reaches it by hand. The card block now shows the
  file's callers, its callees, and the shortest route from the binary named
  in `target.toml`. The parsing and graph queries are
  [trailmark](https://github.com/trailofbits/trailmark) by
  [Trail of Bits](https://www.trailofbits.com/), Apache-2.0 — the same
  licence as TokenFuzz, and an optional dependency the operator installs
  rather than vendored code. Support is discovered, never configured: with
  trailmark absent nothing changes, and every run records which case it was
  in so a run without the context is not mistaken for one that found
  nothing.

  The audited tree does not get to author this evidence. trailmark reads a
  link file from the root it parses, and an entry there may declare any call
  edge at "certain" confidence — a target-supplied file minted a route from
  the entry point to a sensitive sink that the entry point never calls. The
  parse now runs against a mirror of exactly the files rank-work considers
  auditable, which drops that config and stops a test driver or example
  becoming an entry root in the same move. Reachability is context and never
  a filter: counting direct call edges alone leaves most of a C tree looking
  unreachable until callback roots are folded in, so an unobserved edge is
  reported as unobserved and nothing gates on it. Only edges resolved
  syntactically are counted, and where symbol coverage is too low to speak
  for the boundary the entry route is withheld while the caller lists —
  which a partial parse can still state truthfully — remain.

- **Agent backends run inside an OS sandbox by default.** Every launch passed
  the backend CLI's blanket permission bypass unconditionally, so a
  prompt-injected agent reading untrusted source held the operator's account.
  Launches now default to `--agent-security sandboxed`, which puts the
  backend's own OS sandbox — Seatbelt on macOS, Landlock/seccomp or bubblewrap
  on Linux — between the agent and the machine: the target tree is readable
  and the results tree writable, while writes elsewhere, DNS and outbound
  network are denied. Approval prompts are turned off rather than relied on,
  because a headless run cannot answer one and a boundary the model can ask
  past is not a boundary; a tool the CLI cannot sandbox is denied outright.
  Claude keeps loopback binding, since the network targets here drive local
  client/server harnesses and without it those probes fail as environment
  errors and count as clean. `--agent-security external-bypass` drops the CLI
  boundary in favour of an outer container or VM you administer, and is
  refused unless the environment asserts `IS_SANDBOX=1`.

  The sandbox buys integrity and process containment, not confidentiality:
  these sandboxes still read the whole filesystem, and what a model reads
  reaches its provider by design. A backend is credited with a boundary only
  where its sandbox was measured doing both things an audit needs — reading
  the target tree and writing results — while still containing the agent.
  Claude Code and Codex do. Antigravity runs commands in a scratch directory
  and auto-denies its file-writing tool headless; the Gemini CLI mounts only
  the launch directory, leaving the target unmounted; Grok reads `$HOME` and
  reaches the network; OpenCode has no OS sandbox at all. Those four are
  refused rather than filed as contained, and all stay available under
  external-bypass. `bin/benchmark` applies one mode to both conditions and
  records it, and `--regenerate` inherits the mode a run was measured under
  instead of re-scoring its artifacts beneath a boundary they never ran with.

  Turning the sandbox on then broke the tooling it contains, and that is
  fixed in the same release. Claude Code matches its write rules against the
  resolved path, so a target tree reached through a symlink came out readable
  and silently unwritable; the build lease raised `EPERM` instead of falling
  open, killing `bin/probe`, `run-asan` and `run-ubsan` before they ran a
  testcase in every agent session of a sandboxed run. Each `--add-dir` is now
  granted in both spellings, and a lease that cannot be opened at all warns
  rather than raises.

- **A crash frame keeps its source line, whatever produced it.** Agents cut
  off from the runner had hand-compiled their sanitizer runs, and the sandbox
  also denies ASan's in-process symbolizer, so frames arrived naming a
  function and no file or line — and three defects in the offline path then
  kept them that way. A location-less frame was unrecognized by both the
  raw-frame test and the symbolizer's own parser, so a report full of them
  was declared nothing-to-do; recognition now anchors on the trailing
  module and offset and treats the symbol text as opaque, matched greedily
  so a build directory containing a `+` cannot truncate it. A frame is also
  never traded down for an answer that resolved nothing — `atos` returning
  the address alone and `??` from llvm-symbolizer or addr2line were each
  rendered as a symbol, discarding the module path, architecture and offset
  that were all such a frame had left — and a failure is no longer silent.
  Coverage no longer depends on which mode ran: one shared execution helper
  captures and symbolizes for every mode of every runner, browser modes
  symbolize before persisting, and a pool pass repairs every pooled crash and
  finding, accepted or rejected, including a model-direct cell that drove the
  binary itself. That repair is gated on build identity, since symbolizing
  against a build that has moved on would name a different function and line:
  it runs after the build gate, skips blocked crashes, and refuses outright
  when the run's pinned build cannot be verified. A repaired artifact's
  validation receipt is rebound as the representation-only transform it is,
  rather than going stale and refusing to publish a pool whose reports never
  changed meaning.

- **A model-direct cell shows whether it worked the sanitizer, and its
  teardown stops destroying it.** An ffmpeg cell scored 0 crashes beside the
  harness's 6 and nothing on disk could say whether it had ever run the
  target: model-direct writes no `state/runs.jsonl`, and the usage-ledger
  fallback it fell through to was only ever written by the dry-run fixture, so
  every such row reported zero. The sanitizer runtimes named in the cell's own
  transcript are now counted — 227 on that row — and published as
  `sanitizer_command_requests`, beside the exact counters and never inside
  them. It is inexact in both directions and documents which: a command that
  only writes a script naming the option matches, while `./runfuzz.sh` names
  none and may run the target thousands of times. What it answers is whether
  the crash lane was worked at all, which a bare zero could not.

  Two costs fell on that lane alone. A sandbox denies a sanitizer runtime the
  process spawn its own symbolizer needs, so the baseline read
  `module+offset` where the harness read source lines through `bin/run-asan`,
  and an address-only trace cannot be told apart from one raised inside the
  agent's own driver. The prompt turns in-process symbolization off where it
  owns the environment and names `bin/symbolize`, the same offline pass, in
  one block reaching the native, harness-driver and `[runner]` paths alike.

  And the reap missed exactly what it existed for: macOS will not disclose a
  platform binary's environment, so a leaked `/bin/sh` supervisor was
  invisible while the driver it respawned was not. The sweep killed the
  driver, the supervisor replaced it, and scratch reclaim then deleted the
  binaries of campaigns still running, which spent the next ten minutes
  logging a missing driver over their own results. Process group and parent
  links are readable and inherited alike, so ownership widens over both to a
  fixed point — never onto the runner's own group. The sweep repeats until
  the marker clears, a probe that cannot see this process refuses to report a
  clean reap, and a marker that will not clear marks the cell noncomparable
  and stops the run: measuring the next cell against work the last one is
  still doing measures the contention.

  The direct prompt also caps concurrent executions at half the CPUs the
  process may actually use, container quota included. Left unbounded, the
  baseline drove a benchmark machine to a load average of 108, at which point
  its own `timeout`-based oracles began reporting load as hits it then spent
  real budget disproving.

- **Model-direct crashes are measured, not assumed.** Harness replay of a
  model-direct cell could not run end to end: the runner ignored the skip
  flag for a driver carrying its own input, the loader path was lost at each
  `#!/usr/bin/env` hop, and a driver never received its saved testcase. All
  three are fixed, with the older no-argument invocation retried so existing
  bundles keep reproducing, and crashes an earlier version filed as findings
  rejoin crash triage. Replay outcomes are also distinct at last: a fault
  that does not come back demotes, while a replay that *could not run* keeps
  the crash under `crashes/` and is reported as an unjudged remainder through
  the cell, the condition and the crosstab, instead of silently reading as a
  clean zero.

- **Every report field renders inside the Fields grid, and rendering no
  longer invalidates a receipt.** `render-md` matched bare `Label: value`
  lines against a private list that had rotted against the writers and could
  never cover an author-invented label, so fields across the corpus rendered
  loose beside the grid, some reports had no grid at all, and ordering was
  author-dependent. Field-ness now comes from the run a label sits in, seeded
  by the report's own grid and a shared vocabulary, and a label is hidden
  only once the page shows its value somewhere else. `severity` and
  `render-md` identify the table through one shared predicate, settling a
  disagreement between two lookalike separator patterns, and no value visible
  on a parent's page goes missing from the rendered one. Separately, a raw
  `|` in an authored value reads as a cell break and padded the whole table a
  column wider, and report identity canonicalized padding but not column
  count — so clustering's re-render invalidated the severity receipt written
  minutes earlier and the pool audit failed a finished run. Canonical width now
  ignores padding-only cells, identity recognizes the same separators
  `render-md` pads, and prior identities are carried as legacy candidates so
  older reports still reproduce what wrote them.

## 1.4.0 - 2026-08-07

- **Chromium is a supported target, and browser support is structural.**
  Browser handling is now derived from the build driver instead of four
  hardcoded slugs and one objdir layout, so forks and renames get full
  treatment: the product executable comes from bundle role metadata, page
  products must load an HTML canary before a route counts as usable, and the
  post-preflight configuration is frozen per backend so a concurrent edit
  cannot change runner selection mid-session. Chromium lands as a gclient
  workspace overlay with a curated full-product ASan recipe, resolved
  consistently across setup, audit, benchmark, state, build, export and
  cleanup.

- **Audit coverage now reaches security-boundary code, not just memory
  handling.** Card ranking scored only memory primitives, so an authorization
  check, a cookie-scoping rule, or a path effect never became a work card
  under any strategy. Seven boundary surface families — access control,
  identity and origin, credential verification, query and template
  construction, outbound-request policy, path effects, and remote peers — now
  route directly to the rule-vs-implementation playbook, keyed on the
  security decision rather than domain vocabulary, with every measured fire
  rate at or below 9.1% and no memory work displaced.

- **Every ranked strategy holds work, and the rank window spreads across
  files.** Two lanes could never run — one held zero cards on all benchmarked
  targets, another owned no card generator and is now retired as reserved. A
  card is emitted for every strategy a file's own signals fire, the window is
  filled by rotating strategies rather than by score alone (reaching 120
  files where score ordering reached 30), a surviving card carries its
  same-file siblings' strategies so no angle is lost, and buildability is
  decided before truncation so compiled work still leads every window.

- **Published results are bound to verifiable evidence — and stay bound.** A
  content-addressed validation receipt is now the publication authority
  across triage, severity, benchmark counting and export: it binds the
  report, testcase, diagnostic, harness, invocation, build, revision and
  threat model, and an artifact whose evidence changes returns to pending
  instead of keeping stale credit. Verdicts survive the harness's own
  severity rewrite, inferred report fields survive regeneration, and
  primitives classify from the first complete runtime diagnostic so narrative
  prose can no longer outrank the sanitizer. Pooling honors the receipts too:
  reach fields converge before a receipt is cut, a rebuild pass skips any
  artifact under a current final receipt, and a stale receipt blocks
  publication rather than warning past it.

- **A finding must prove its claimed consequence, not just its trigger.** The
  independent source-reading review asked one question — can an attacker
  reach the triggering state — so a reachable finding was promoted whatever
  consequence it claimed; 63% of one cell's corpus took that path. Promote
  now requires source support for the exact claimed consequence under four
  language-neutral modes, source that affirmatively contradicts the claim
  rejects it, and a residual-memory disclosure must name the allocation the
  bytes live in — the claim's own evidence, not its polish. Merely unproven
  or deployment-dependent stays Uncertain, and a sanitizer diagnostic remains
  concrete crash evidence however much its report overstates impact.

- **A forged crash is refused before it costs anything.** An agent-built
  carrier that injects a loader module into a version-only process, or hands
  control to a binary the probe never built, produced real sanitizer traces
  about the wrong program. Conclusive carriers are now rejected before the
  compiler runs, a fault whose module lives in the agent's own scratch tree
  and was not built by the probe is not a crash, and export reads the probe
  receipt as authoritative for the testcase and harness that actually ran.

- **The finding gate delivers verdicts and runs to completion.** Bounded
  groups are carried through quality, reach fields, both trigger rounds and
  finalization before the next opens — same votes, same quorum, same batch
  sizes — and a review killed at its wall banks the items it completed.
  `--finalize-wall` now defaults to unlimited, since the artifact set is
  frozen when the audit wall ends, and the drain repeats while its pending
  remainder falls, paying only for what cached receipts do not already
  cover. Two reviewers who each anchored a disproof also no longer disagree
  a dead finding back into the totals: the three reject kinds that all say
  "the claimed defect is not one" satisfy the quorum together.

- **A findings count says what it covers.** An unfinished gate reports its
  remainder — `0 (172 unjudged)`, with `≥N` when the remainder outnumbers
  the verdicts — instead of folding into "found nothing", and a live run
  warns while an operator can still act. The review queue rotates bug
  classes, so a gate cut short leaves a sample of the corpus rather than one
  whole class, and the findings column carries its class spread:
  `≥57 (41 M+, 3 classes, 194 unjudged)` and `30 (23 M+, 21 classes)` are
  not the same result.

- **An agent that finishes early keeps working.** A finished slot is now
  relaunched repeatedly for the rest of the iteration, gated on evidence of
  remaining work rather than elapsed time, and every session is clamped to
  one epoch deadline. One five-hour run had left 4.9 of 15 possible
  agent-hours idle at the iteration barrier; that capacity now goes to the
  audit.

- **A disproved route reaches the session that would repeat it.** The
  provenance gate's anchored disproofs now render, newest first, on later
  work cards for the same file and against the rejected artifact itself —
  previously 55% of trigger rejections re-derived an answer the run already
  had, each paying a fresh harness, confirmations, bundle and report. The
  note is advisory, rules out a route rather than a file, and a requeue
  retracts it by moving the artifact.

- **Benchmark conditions compare on the same evidence bar, the same clock,
  and the same prose contract.** A model-direct finding now needs four named
  facts — location, class, reaching input with caller control, attacker gain
  — and resource exhaustion needs quantified amplification that survives the
  project's own ceiling, replacing a filing-rate target both backends farmed.
  The baseline names a UTC deadline with a clock check, and the Wall column
  reads `spent/granted` so an early stop is disclosed where the comparison is
  read. One narrative contract covers every backend's reports, so a
  prose-quality difference is a result rather than an artifact, and refuted
  findings and stale severities are no longer credited.

- **A benchmark run pins one immutable execution contract.** A fresh run
  converges once, then pins the exact runner, executable, library, stamp
  generation, route and tracked source state it selected; cell startup,
  completion, resume and both replay paths verify against that pin. A
  runtime by-product left in the target tree no longer reads as a source
  change that kills the next cell, and parallel runs safely share one
  checkout under build leases.

- **Severity records preconditions without inventing or losing reach.**
  `application-supplied` joins the Parameter control vocabulary, so a crash
  gated on a non-default mode carries that precondition to MAT:P while
  staying remotely reachable. Detector-confirmed races keep the
  code-execution reading and source-only ones score the integrity consequence
  they defeat, and a mixed trigger — attacker bytes plus a public call
  sequence — keeps its public attack vector instead of a zero-impact floor.
  A new optional `disclosed_content` field records what a disclosure
  actually leaked and is wired to lower only, so zeroed or caller-local
  bytes stop rating as a cross-principal leak while silence can never
  under-rate a finding.

- **Runner selection lands on a program that reads the input.** Bootstrap
  picked the first binary in the build tree, so a project whose install list
  is led by a test-suite driver got a runner that ignores the testcase and
  replays every crash as CLEAN. CMake `ALIAS`/`IMPORTED` entries — a
  reference, not a binary — no longer count as executables or suppress the
  fallback that holds the real programs, and every instrumented CLI is
  offered with its help text so the one that consumes attacker-supplied
  input is the one chosen.

- **Setup proves a build can start and lets finished builds converge.** A
  selected sanitizer binary must survive one bounded launch, so a recipe that
  compiled but dies in the dynamic loader is rebuilt — and a persistent
  loader diagnostic reaches the recipe-repair loop instead of steering the
  agent toward configuration changes that cannot help. Artifact discovery
  works at any depth, so completed header-only builds stop being rebuilt
  forever, and `--pull` ignores untracked build output instead of reading
  every target as dirty.

- **Concurrent runs are protected from each other's cleanup.** Every
  tool-using backend gets a refusal path for `pkill`/`killall`, including
  composed and absolute-path variants — a name-based kill from one cell
  could SIGKILL a concurrent benchmark whose orchestrator argv carried the
  same target name.

- **Runs measure what they actually spend.** Probe wall time is recorded per
  run — a single record can hide hundreds of thousands of looped target
  calls — with unknown reported as unknown rather than zero. Housekeeping
  records one span per phase instead of an aggregate, every measured decision
  ceiling is sized from observed completions instead of a fixed guess, and
  trigger reviews get an equal wall whether batched or single.

- **The delivery pipeline is pinned and patched.** Every CI action is pinned
  by commit SHA with the publish scopes isolated to the deploy job, weekly
  grouped dependency updates keep those pins current, and the handbook
  toolchain moves to pymdown-extensions 11, off the b64 path-traversal line
  (CVE-2026-61632).

- Internal: per-phase housekeeping timing, discovery-curve points that name
  their source site, Mercurial parity for recency ranking and peer scans,
  promotion sidecars cleared where pooling and export read them, a dangling
  reproducer link that no longer aborts a finished run, the documented rule
  for what the benchmark wall counts, and a hermetic plain-target build
  test.

## 1.3.0 - 2026-07-27

- **The cold-start recon stage is gone.** It emitted candidate leads before any
  investigation existed, unbounded and scaling with target size: ~40% of a run's
  cost on large trees, 3 of 56 accepted crashes, and none of ~1,200 candidates
  ever validator-confirmed. Deleted rather than capped — audits start from
  deterministic strategy cards, and source review becomes a finding only through
  the normal agent, probe and validation flow.

- **One build generation per run, and no more phantom rebuilds.** A target's own
  ignored test output counted as a source edit, so a concurrent benchmark
  replaced the shared `build-asan` mid-cell and finalization then refused valid
  crash evidence. Freshness is now content-based over VCS working-tree state, a
  VCS that cannot answer reports "unknown" rather than fresh, and every build
  carries a lease so it is never replaced under a live run. A benchmark pins one
  build generation, source state and settings for its whole run and refuses to
  start or resume outside them; drift compares tracked product source only, so a
  model-direct cell's crafted inputs no longer read as drift.

- **Crash replay happens under the build the crash was found on.** Pooled replay
  ran against whatever build was live at finalization, silently re-measuring old
  evidence with a new binary. Cells now record content identities for the
  binaries and libraries a replay would execute and skip — loudly, per crash,
  evidence untouched — when they no longer match. Reproduction rates count only
  diagnostics agreeing on sanitizer family, primitive, function, path and line.

- **The program under test is the one that reads attacker input.** Setup could
  bootstrap a project's test-suite driver as the runner, or none at all, and
  every backend then refused its argv. Detection alone cannot decide when a
  project ships several CLIs, so each instrumented CLI is offered with its help
  text for the model to choose and the launch check confirms it. The choice is
  written into every enabled sanitizer's `<san>_bin` or setup refuses, and a
  target's sanitizer invocation is proven to consume the input — so a target that
  never parsed its testcase can no longer run clean.

- **Long sessions roll over instead of dying at the provider's ceiling.** A
  session that exhausts a backend's context or turn limit now continues in a
  fresh session with its state intact, across every hosted backend, so a
  multi-hour investigation is no longer capped by one session's limits. One
  visible `TURN_SOFT_CAP` replaces the per-backend mix of watchdogs and native
  flags and defaults to 128, which models about 28% lower cache reads on the
  recorded sessions; fresh sessions start from a compact self-contained runtime
  contract instead of replaying a ~22 KB prompt suffix.

- **Reports say only what their evidence proves.** Pooled enrichment could
  annotate a report with source borrowed from another target, render an
  unfinished skeleton as OK, and let a source-only finding inherit CVSS
  worst-case `E:X`. Enrichment now uses only a checkout matching the recorded
  audited revision, unproven filed findings score `E:U`, and severity resolves
  conflicting primitive signals in evidence order — sanitizer diagnostic, then
  the structured `Primitive` field, then narrative wording — so prose about a
  neighbouring write can no longer inflate a confirmed read.

- **A race is scored on what proved it.** "Race" names two different bugs
  sharing a word, and an asserted `data_race` bought the code-execution impact
  only a detector's verdict earns — so a report-only classifier picking the
  memory-safety name turned a logic race into a High, where every unconfirmed
  race in the benchmark landed. A detector-confirmed race keeps that reading; one
  argued from source scores as the integrity consequence it defeats. Saved
  reproducers are recognised by the shared artifact classifier, so a bundle with
  a numbered input and a replay command no longer grades as having none.

- **Benchmark reporting states what it can prove.** Rejected-crash reasons come
  from the rejection artifact rather than a marker nothing wrote, live progress
  shows raw totals so a gate-rejected cell no longer reads as zero, and a resumed
  run retries only the cells that need it. Crash filing time is recorded
  write-once so discovery graphs do not inherit preserved mtimes. Finding
  validation gets its own bounded budget so a crash-heavy cell cannot starve it —
  one 57-minute crash pass had left 115 quality-accepted findings scoring zero.

- **Model-direct cells are told their budget.** The prompt said only that a
  wall-clock budget existed and never named it, so both backends paced to a
  default short audit and stopped at 4–19% of a five-hour budget. The duration
  and target scale are now stated in the prompt; harness runs, which already
  consume the full budget through the iteration loop, are unchanged.

- **Token use is measured, not estimated.** Provider input, cache writes, cache
  reads and output were summed into one `tokens=` figure despite different
  semantics, prices and overlap; the ledger now reports each separately and marks
  rows estimated only when they are. One-shot decisions threw away their
  backend's reported usage — each metered backend is now asked for its
  usage-bearing transport. Tier ceilings and decision timeouts resolve from one
  place, with defaults that fit a full agent launch.

- **Refreshed backend defaults and rate cards.** Claude defaults to Opus 5,
  Gemini to `gemini-3.6-flash`, and Grok to `grok-4.5`, with vendor pricing
  verified against current rate cards so cost reporting matches what a run
  actually costs.

- **Investigation quality.** Deep investigation rotates off a cold hypothesis
  after one CLEAN probe but keeps repeating the timing, allocator, GC and
  multi-step state conditions that need it; the queue prefers work whose units
  exist in the sanitizer build; truncated trigger-vote batches are recovered
  rather than adjudicated to zero; and finding validation no longer re-reviews
  settled findings because table padding shifted a report hash.

- **Reproducers name the revision they were audited at.** The stale `pinned_rev`
  field is gone: a report or bundle uses the session's recorded revision, else
  the checkout's own, and `reproduce.sh` stops with exit 3 rather than building a
  different commit and reporting "does not reproduce" for a real bug. Stale
  sanitizer recipes rebuild from a clean canonical path with bounded repair attempts and
  keep the previous usable tree on failure.

- **Runs no longer leak processes or scratch files.** A backgrounded fuzzer that
  outlived its agent survived into later cells with stale corpora; cell and agent
  descendants are now reaped by an inherited ownership marker — proof, not a
  path or tty heuristic — on both normal and abnormal exit, the session watchdog
  no longer mislabels a natural finish as a forced checkpoint, and agent working
  files stay inside the results tree instead of shared `/tmp`.

- **A finished run still reports its results.** An agent linked its reproducer
  into a scratch directory that housekeeping later pruned; pooling resolved the
  dangling path, hit `ENOENT` and aborted after every cell had completed — a
  whole run producing nothing over one absent file. Pooling now skips a dangling
  link and a symlinked artifact directory, naming each, while a live link is
  still materialised into the bundle as the regular file every replay path
  needs.

- Internal: hot re-reads, re-parses and report source lookups are cached across a
  pass with stat-signature invalidation and bounded memory, and the handbook is
  corrected against the code with harness internals removed and the development
  guide tightened around explicit review and security discipline.

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
