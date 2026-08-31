# Reproduce a Crash

This page is for an upstream maintainer or security engineer who received a
TokenFuzz crash bundle. The shortest path is: read `REPORT.md`, inspect
`reproduce.sh`, run it against a disposable checkout, and compare the new
diagnostic with `sanitizer.txt`.

If you are the operator running TokenFuzz, see
[Triage and review](triage-results.md) instead.

Accepted crashes are exported in place during triage. The directory under
`output/.../crashes/CRASH-*` is therefore the same self-contained shape an
operator sends upstream. Older or interrupted runs may still contain the
audit-side `report.md`; the operator can finish those with `bin/export-repro`
(see [Maintenance commands](triage-results.md#maintenance-commands)).

## Bundle layout

The directory is named after the crash id. After unpacking you normally get:

```
CRASH-001-1/
├── REPORT.md          # one-page summary: bug, root cause, candidate fix
├── REPORT.html        # browser-friendly render of REPORT.md
├── reproduce.sh       # ./reproduce.sh /path/to/checkout
├── input.<ext>        # the testcase bytes
├── harness.{c,cc,cpp,cxx} # only when the bug uses a C/C++ harness
├── sanitizer.txt      # saved sanitizer output captured during discovery
├── patch.diff         # optional: candidate fix, verified to apply cleanly
├── validation.json    # the publication decision, bound to this evidence
├── severity.json      # only when a current reportable score exists
└── .audit/            # audit-side originals, kept for provenance
```

`validation.json` records the publication decision. `severity.json` exists
only for a reportable result with a current score. Neither file is needed to
reproduce; both let a reviewer trace generated claims back to the evidence
that produced them.

Read `REPORT.md` first. `REPORT.html` presents the same content with its field
table and severity annotation rendered for a browser.

It opens with a **Reviewer TL;DR** — one line each for the bug, its trigger,
and the suggested fix — then the severity badge, a `## Summary` paragraph, and a
`## Fields` table of the structured claims triage parsed. Between them they
name:

- the affected `file:function:line`;
- the issue class (bounds / lifetime / type / size / uninit / state);
- the data flow;
- a candidate fix direction.

It is normalized from the agent-authored report, sanitizer output, and
structured fields gathered during triage. Hand-edit `REPORT.md` only —
`REPORT.html` is regenerated automatically.

## Before you run it

Treat the bundle and target checkout as untrusted code. Read `reproduce.sh`,
then run it in a disposable VM or container without credentials. Depending on
the target, it can clone source, fetch submodules, install project-local
dependencies, and execute the target's build system. Review those network and
build steps under your own policy.

If no runnable route (testcase, harness, or wrapper) was captured,
`reproduce.sh` is a stub: it names what is missing and exits 2. The report and
saved diagnostic are still valid evidence; reproduction then needs a route you
author yourself.

## Reproduce in one command

Pass a source checkout:

```bash
./reproduce.sh /path/to/your/checkout
```

The argument may be omitted only when the bundle records a real upstream URL
and a pinned revision, in which case the script clones next to itself (or when
it runs in place on the machine that produced it). A local-only or unpinned
target has no other fallback. Firefox/`mach` bundles
always need the path unless you set `REPRO_AUTO_CLONE=1`, because that clone is
very slow.

What it does:

1. Selects the source tree to build against. A Git or Mercurial checkout you
   pass is moved to the recorded revision; if that fails the script stops with
   exit 3 rather than build a different commit. A plain source tree, or any
   checkout given to a Firefox/`mach` bundle, is used as supplied — check its
   revision yourself. Local modifications that do not conflict are kept, so you
   can test an applied candidate patch.
2. Configures and builds the project with the same sanitizer flags
   TokenFuzz used during discovery.
3. Runs the recorded testcase against the resulting binary or
   harness.
4. Prints the run output and exits with the reproduced run's status.

### Prerequisites on the build host

The build steps in `reproduce.sh` depend on the project's build
system — CMake, Meson, autotools, mach, cargo, go, npm, python, etc.
You need:

- the same compiler and build tools you would normally use to build
  the project from source;
- for ASan, UBSan, MSan, or TSan, a compatible LLVM toolchain that supports the
  recorded `-fsanitize=<name>` mode;
- for Go `race`, a Go toolchain with race-detector support and the C compiler /
  cgo support required by that platform. Go `race` is not an LLVM sanitizer
  mode.

Generated recipes do not provision operating-system packages for you. They may
invoke package managers such as npm, pip, Bundler, Composer, Maven, Gradle, R,
or cpanm; those tools use their normal configured cache and install locations.
Use a disposable account or container if those locations are not already
isolated. An offline or proxied environment may need its normal
project-specific preparation first.

### Common one-off overrides

```bash
CC=clang-18 ./reproduce.sh /path/to/checkout                   # pin compiler (CMake bundles; other recipes pin clang)
REPRO_AUTO_CLONE=1 ./reproduce.sh                              # fresh clone
ASAN_OPTIONS="abort_on_error=1" ./reproduce.sh /path/to/co     # extra runtime opts
```

`reproduce.sh` runs with `set -eu` and prints a banner for each major
step (`=== compiling harness ... ===`, `=== running ... ===`). If a
build step fails, the trailing few lines name the step and the error.

## Reading the sanitizer output

`sanitizer.txt` contains the sanitizer report from discovery with full stack
traces. Output over 8 MiB is truncated in the middle for storage and says so
with a marker; the head and tail are always kept. The top of the file names the
diagnostic class. For ASan, that is one of:

| Class | Meaning |
| --- | --- |
| `heap-buffer-overflow` | Read or write past the end of a heap allocation. |
| `heap-use-after-free` | Access to memory after `free()`. |
| `stack-buffer-overflow` | Read or write past the end of a stack array. |
| `container-overflow` | Access past the end of a container's logical size but within capacity. |
| `alloc-dealloc-mismatch` | `delete` / `free` mismatch with the allocator that produced the pointer. |
| `SEGV` (non-null) | Memory access at a non-null address the OS rejected. |
| `negative-size-param` | Negative size passed to a memory routine. |

Below the diagnostic line, the report has:

- **the first stack** — where the bad access happened;
- for use-after-free or alloc-dealloc-mismatch, **the freeing stack**
  and **the allocating stack**;
- a **shadow memory dump** with the byte preceding / at / following
  the access marked. The character at the access site
  (e.g. `fa` = heap-left-redzone, `fd` = freed-heap) tells you what
  was hit.

`REPORT.md` normally points you at the line that matters. The full trace is in
`sanitizer.txt` if you want the rest.

## Verifying your fix

After applying your patch:

1. Re-run `./reproduce.sh /path/to/checkout`.
2. Confirm the build step succeeds.
3. Confirm the run completes **without** the diagnostic.

A clean run typically looks like the binary or harness running
silently to exit code 0 — or, for a parser, emitting its normal
output.

If the sanitizer still fires at a materially different root operation, keep
the new trace and send it back to the reporter. Similar top frames can still
belong to the original mechanism, so compare the full allocation/free and
fault stacks before treating it as a separate issue.

If you cannot reproduce against your checkout but the bundle's
recorded revision *is* affected, the most common causes are:

- **A compiler or sanitizer version different from the recorded
  one.** Some heap-layout-dependent bugs need a specific Clang. Try
  the Clang the bundle's `reproduce.sh` selects (`clang` on `PATH`, or
  `CC` for a CMake bundle) at the recorded target revision.
- **A configure-time option that disables the affected code path**
  (`--without-zlib`, `--disable-foo`). Diff your configure flags
  against the ones in `reproduce.sh`.
- **A lifetime bug that needs a specific allocator state.** Vary ASan's
  `quarantine_size_mb`: lowering it encourages earlier address reuse, while
  increasing it keeps freed allocations quarantined longer. Record which
  setting reproduces rather than assuming that a smaller value preserves the
  allocation longer.

## What the report does **not** claim

- That the affected code path is reachable from every public entry
  point. The recorded "Trigger source" in `REPORT.md` is the specific
  input shape that fired the diagnostic. Reachability from other
  entry points is your call.
- That the candidate fix in `REPORT.md` is the right one. It is a
  reviewer-actionable suggestion based on the audit run. The
  maintainer decides the actual patch.
- That the recorded severity is final. Severity is advisory; your
  project's security team is authoritative.

## Privacy and provenance

The bundle is self-contained:

- It contains no model transcript or TokenFuzz telemetry.
- The script may use the network to clone the recorded upstream source, fetch
  submodules, or install project dependencies.
- `.audit/` retains audit-side source artifacts for provenance; it is not
  needed for reproduction.

If you would like to credit TokenFuzz in your advisory or commit
message, a neutral attribution is:

> Discovered with TokenFuzz (LLM-assisted security audit).

Follow the project's normal coordinated-disclosure and embargo process.

## Got a question or want to challenge the report?

Reply on whatever channel the report came in on (security inbox,
issue tracker, etc.). The TokenFuzz repository's own issue tracker
is for bugs and questions about the harness itself, not for triage
of findings in your project — see
[Getting help](../getting-help.md).
