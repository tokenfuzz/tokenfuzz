# Reproduce a crash

You received a crash bundle, a directory such as `CRASH-001-1/`, from
someone who audited your project with TokenFuzz, an LLM-assisted
security-audit harness. Every crash it reports was confirmed under a
sanitizer, such as AddressSanitizer, before it was sent. You need the bundle
and a source checkout of your project, not TokenFuzz itself.

In a disposable VM or container with no credentials, run:

```bash
CRASH-001-1/reproduce.sh /path/to/your/checkout
```

The script pins your checkout to the audited revision, builds it with the
sanitizer, and replays the saved input. It reproduced when:

- a sanitizer report prints on stderr with the same error class and
  crashing function as the report's `## Expected sanitizer output` (and the
  bundle's `sanitizer.txt`), for example
  `ERROR: AddressSanitizer: heap-buffer-overflow` in `app_parse`;
- the last line is `[repro] exit=<status>`, normally non-zero.

Read `report.md` for the bug, its root cause, and a fix direction. Skim
`reproduce.sh` before you run it: it runs your build system and may clone
the repository or install dependencies (see
[Before you run it](#before-you-run-it)). If you run TokenFuzz yourself,
see [Triage and review](triage-results.md) instead.

## Bundle layout

The directory is named after the crash id. A benchmark export renumbers its
copies (`CRASH-0001`); the report title keeps the original id.

```text
CRASH-001-1/
├── report.md          # the write-up: bug, root cause, fix direction
├── report.html        # browser rendering of report.md
├── reproduce.sh       # ./reproduce.sh /path/to/checkout
├── input.<ext>        # the testcase bytes
├── harness.{c,cc,cpp,cxx}  # only when the crash needs a C/C++ API harness
├── repro.cmd          # the argument list, when one was recorded
├── sanitizer.txt      # sanitizer output saved when the crash was confirmed
├── patch.diff         # optional: candidate fix from the audit
├── validation.json    # TokenFuzz's review decision, bound to these files
├── severity.json      # advisory CVSS v4.0 score, when one exists
└── .audit/            # audit-side originals, kept for provenance
```

- `input.<ext>` keeps the original testcase's extension, or is `input.bin`.
  TokenFuzz's own header lines in a script testcase (`TARGET:`,
  `HYPOTHESIS-ID:`, and similar) are stripped, as they were when the crash
  was confirmed.
- `repro.cmd` holds the arguments passed after the binary or harness, with
  `{TESTCASE}` standing for the input file. `reproduce.sh` already includes
  them.
- `patch.diff` is the auditing agent's suggested fix. The agent is asked to
  save one only when it applies cleanly (`git apply --check`) to the
  audited revision; the export does not re-check it.
- `validation.json` and `severity.json` are TokenFuzz's review records, not
  needed to reproduce. A crash sent to you as an ordinary engineering bug
  has no `severity.json`.
- `.audit/` and hidden dot-files at the root (review caches such as
  `.trigger-gate.json`) are TokenFuzz internals you can ignore.

### The report

`report.md` is the write-up, and `report.html` renders it with a summary
card on top. It opens with a title such as
`# CRASH-001-1: heap-buffer-overflow in app_parse`, a short TL;DR, and a
`## Fields` table of the structured claims (primitive, severity, surface,
trigger source, caller contract, boundary, caller controls, reproduction
rate). The narrative follows: root cause, data flow with source snippets,
impact, and a fix direction. Then come `## Expected sanitizer output`, the
symbolized diagnostic to look for, `## Reproduce`, the command for this
bundle, and, when present, `## Patch` and the severity rationale. The
issue class uses TokenFuzz's
[bug-class vocabulary](../reference/bug-classes.md); the severity is an
advisory CVSS v4.0 estimate (see
[What the report does not claim](#what-the-report-does-not-claim)).

## Before you run it

Treat the bundle and your project's build as untrusted code. Read
`reproduce.sh`, then run it in a disposable VM or container without
credentials. Depending on the project, the script can clone the upstream
repository and its submodules, move your checkout to the audited revision,
install project-local dependencies through the project's package manager,
and run your build system, writing build output into your checkout.

A stub `reproduce.sh` lists the bundle's files, explains what is missing,
prints `stub reproducer: manual reproduction required (see above)`, and
exits 2. That happens when the audit captured no runnable route (testcase,
harness, or wrapper). The report and saved diagnostic remain, but the stub
does not show that the crash reproduces.

## What `reproduce.sh` does

```bash
./reproduce.sh /path/to/your/checkout
```

1. **Chooses the source tree.** A path argument always wins. Without one,
   the script uses a directory next to itself, cloning the recorded
   upstream there (`--recurse-submodules`) if it is missing. A bundle with
   no real upstream URL and revision cannot clone, so it stops with exit 2
   and asks for a checkout path.
2. **Pins the revision.** A Git checkout is moved to the recorded revision
   with `git checkout` (Mercurial: `hg update`); if that fails, the script
   stops with exit 3 rather than build a different commit. It then updates
   Git submodules and stops with exit 3 if any is missing or at the wrong
   commit. A plain source tree without VCS metadata is used as supplied, so
   check its revision yourself. If the audit recorded no revision, the
   script says so and builds the tree as it stands.
3. **Builds with the sanitizer.** When the audit converged on a build
   recipe, the script inlines it verbatim, writes it to
   `$src/.audit-build.sh`, and runs it. Otherwise a generic section for your
   build system runs: CMake, autotools, and Meson get `-fsanitize=<mode>`
   release builds with debug info; Cargo, npm, pip, Maven, and other
   ecosystem builds run normally with no sanitizer flags, except
   `go build -race`. A C/C++ harness is compiled with
   `clang`/`clang++ -fsanitize=<mode> -g -O1`.
4. **Replays the testcase** against the rebuilt binary or harness. It sets
   the sanitizer's options variable (for example `ASAN_OPTIONS`) to the
   options the audit used, appends any value you already set, and unsets
   the other sanitizers' variables. A C/C++ harness sees `TARGET_ROOT` set to
   the checkout and, when the project has a sanitizer executable,
   `TOKENFUZZ_TARGET_BIN` set to the rebuilt one.
5. **Exits with the replayed run's status**, after printing
   `[repro] exit=<status>` on stderr.

Before the replay it prints `=== compiling harness: harness.c ===` for a
harness bundle and `=== running ASan repro: <input> ===` (with the bundle's
sanitizer name). A failing build step stops the script under `set -eu`
with no `[repro]` line. A bundle whose route was an audit-side shell
wrapper runs that wrapper instead, prints neither line, and exits with the
wrapper's status.

| Exit | Meaning |
| --- | --- |
| The replayed run's status | Normally non-zero when the diagnostic fires; compare the output with `sanitizer.txt`. |
| 2 | A stub, no source tree and nothing to clone, or a build section that cannot proceed (for example an unknown build system or a binary it cannot find). |
| 3 | The checkout could not be pinned to the recorded revision, or its submodules do not match. |
| Other, with no `[repro]` line | A build or setup command failed. |

The script writes into the checkout: a `build-<sanitizer>-repro/` directory
(for example `build-asan-repro`), the `.audit-build.sh` recipe when there is
one, and for Firefox a `.mozconfig-*-repro` file. Every run rebuilds, and a
CMake build discards its cache first; only a Firefox build reuses an
existing sanitizer object directory.

### Prerequisites on the build host

You need the tools you normally use to build the project from source, plus a
Clang/LLVM toolchain that supports the recorded `-fsanitize=<mode>` (ASan,
UBSan, MSan, or TSan), or, for Go `race`, a Go toolchain with race-detector
support and whatever C compiler or cgo support your platform requires.

The script does not install operating-system packages. It may run package
managers such as npm, pip, Bundler, Composer, Maven, Gradle, R, or cpanm,
which use their normal cache and install locations; pip installs into a
virtual environment under the build directory when it can. An offline or
proxied environment may need its usual preparation first.

### Common overrides

```bash
PATH=/opt/llvm-18/bin:$PATH ./reproduce.sh /path/to/checkout      # choose the clang the script calls
CC=clang-18 CXX=clang++-18 ./reproduce.sh /path/to/checkout       # generic CMake section only
ASAN_OPTIONS=quarantine_size_mb=1 ./reproduce.sh /path/to/checkout # yours win: appended last
REPRO_AUTO_CLONE=1 ./reproduce.sh                                 # Firefox/mach bundles only
```

Which compiler runs depends on the build section, so read it. The generic
CMake section honours `CC` and `CXX`; the autotools and Meson sections and
the harness compile call `clang` or `clang++` by name, so `PATH` decides; an
inlined audit recipe follows its own rules.

A Firefox/`mach` bundle needs a checkout path unless you set
`REPRO_AUTO_CLONE=1`, which clones the recorded upstream with `hg` next to
the script (slow) and pins it. A checkout you pass to a `mach` bundle is
used as supplied, without pinning. `REPRO_AUTO_CLONE` has no effect on other
bundles.

### Run the testcase against your own build

To skip the script's build, use your own sanitizer build of the same
revision. Copy the options string from the `*_OPTIONS=` line in
`reproduce.sh` and the command from the line after it (`repro.cmd` shows the
same arguments, with `{TESTCASE}` for `input.<ext>`):

```bash
ASAN_OPTIONS='<options from reproduce.sh>' /path/to/your/asan-build/app input.bin
```

For a harness bundle, compile `harness.*` against your build as the
`=== compiling harness ===` step in `reproduce.sh` does, then run it the
same way.

## Reading the sanitizer output

`sanitizer.txt` is normally the raw output saved when TokenFuzz confirmed
the crash by running it several times:

```text
ASAN_RUN_HEADER: sanitizer=asan runs=5 mode=generic testcase=... started=...
=== Run 1/5 ===
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address ...
    #0 ... in app_parse parse.c:91
    ...
SUMMARY: AddressSanitizer: heap-buffer-overflow ...
=== Run 2/5 ===
...
=== SUMMARY ===
CRASH_RATE: 5/5
```

The first line records how the crash was run (other sanitizers write
`SANITIZER_RUN_HEADER:`). Each run's output follows its `=== Run i/N ===`
marker. The diagnostic class is on the `ERROR:` (or `WARNING:`) and
`SUMMARY:` lines, and `CRASH_RATE` says how many runs crashed. Frames may be
unsymbolized addresses; the symbolized trace is in `report.md` under
`## Expected sanitizer output`. A capture over 8 MiB is trimmed to its first
and last 256 KiB, starting with a
`[probe] ASAN_OUTPUT_FILE truncated for storage` line and marking the gap.

The class names and report layout are AddressSanitizer's own; its
[documentation](https://clang.llvm.org/docs/AddressSanitizer.html) explains
them. Below the `ERROR:` line come the stack of the bad access, the free and
allocation stacks for a use-after-free or double-free, and a shadow-memory
dump whose legend names each byte code. TokenFuzz does not report null-page
dereferences, so a `SEGV` in a bundle is a wild access to a non-null
address.

## Verifying your fix

`reproduce.sh` checks the checkout out at the audited revision, which leaves
Git in a detached-HEAD state, so a fix committed on a branch is left behind.
Test the fix as uncommitted changes instead; non-conflicting local
modifications are carried across the checkout.

1. Apply your patch to the checkout without committing it.
2. Re-run `./reproduce.sh /path/to/checkout`.
3. Confirm the build succeeds.
4. Confirm the run completes **without** the diagnostic, typically with
   `[repro] exit=0` or the program's normal output.

If the sanitizer still fires at a materially different root operation, keep
the new trace and send it back to the reporter. Similar top frames can still
belong to the original mechanism, so compare the full access, free, and
allocation stacks before treating it as a separate issue.

If you cannot reproduce at the recorded revision, the usual causes are:

- **A different compiler or sanitizer version.** Some heap-layout-dependent
  bugs need a specific Clang. Put it first on `PATH` (or set `CC`/`CXX` for
  a generic CMake section) and retry.
- **A configure-time option that disables the affected code path**
  (`--without-zlib`, `--disable-foo`). Compare your configure flags with
  the build section of `reproduce.sh`.
- **A lifetime bug that needs a specific allocator state.** The bundle's ASan
  options normally include `quarantine_size_mb=256`. Lowering it (through
  `ASAN_OPTIONS`) encourages earlier address reuse; raising it keeps freed
  allocations quarantined longer. Record which setting reproduces.

## What the report does not claim

- That the affected code is reachable from every public entry point. The
  `Trigger source` field names what kind of input decides the fault
  (`bytes`, `call-sequence`, `timing`, and so on); `Boundary` and
  `Caller controls` describe the entry point and input the audit used.
  Reachability from other entry points is your call.
- That the candidate fix is the right one. It is a suggestion from the
  audit; you decide the actual patch.
- That the severity is final. It is an advisory CVSS v4.0 estimate computed
  from the report's fields; your project's security team is authoritative.

## Privacy and provenance

The bundle holds the files its reproduction route needs and is not meant to
include model transcripts, but review it before sharing it further:

- `report.md` and `reproduce.sh` have host paths rewritten to
  target-relative ones. `sanitizer.txt` and the JSON files can still carry
  absolute paths from the machine that ran the audit.
- Hidden review files such as `.trigger-gate.json` hold the automated
  reviewers' rationale.
- `.audit/` keeps the audit-side originals for provenance; reproduction
  does not need it.

If you would like to credit TokenFuzz in your advisory or commit message, a
neutral attribution is:

> Discovered with TokenFuzz (LLM-assisted security audit).

Follow the project's normal coordinated-disclosure and embargo process.

## Got a question or want to challenge the report?

Reply on whatever channel the report came in on (security inbox, issue
tracker, and so on). The TokenFuzz repository's own issue tracker is for bugs
and questions about the harness itself, not for triage of findings in your
project; see [Getting help](../getting-help.md).
