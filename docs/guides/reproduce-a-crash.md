# Reproduce a Crash

This page is for an upstream maintainer or security engineer who received a
TokenFuzz crash bundle. The shortest path is: read `REPORT.md`, inspect
`reproduce.sh`, run it against a disposable checkout, and compare the new
diagnostic with `sanitizer.txt`.

If you are the operator running TokenFuzz, see
[Triage results](triage-results.md) instead.

Accepted crashes are exported in place during triage. The directory under
`output/.../crashes/CRASH-*` is therefore the same self-contained shape an
operator sends upstream. Older or interrupted runs may still contain the
audit-side `report.md`; the operator can finish those with `bin/export-repro`.

## Bundle layout

The directory is named after the crash id. After unpacking you normally get:

```
CRASH-001-1/
├── REPORT.md          # one-page summary: bug, root cause, candidate fix
├── REPORT.html        # browser-friendly render of REPORT.md
├── reproduce.sh       # single command, no env vars
├── input.<ext>        # the testcase bytes
├── harness.{c,cc,cpp,cxx} # only when the bug uses a C/C++ harness
├── sanitizer.txt      # full sanitizer output captured during discovery
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

It opens with a **Reviewer TL;DR** — two lines giving the bug and its trigger —
then the severity badge, a `## Summary` paragraph, and a `## Fields` table of
the structured claims triage parsed. Between them they name:

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

## Reproduce in one command

`reproduce.sh` takes a source-checkout argument. For generic targets
it is optional because the script can clone the recorded upstream URL;
for Firefox/`mach` bundles it is mandatory unless you explicitly set
`REPRO_AUTO_CLONE=1`.

```bash
./reproduce.sh /path/to/your/checkout
```

What it does:

1. Selects the source tree to build against. For generic targets
   (every non-`mach` project), running with no argument clones the
   recorded upstream URL at the recorded revision into a directory
   next to the script. Running with a path uses that checkout
   instead, checked out at the recorded revision — if that revision
   cannot be checked out the script stops with exit 3 rather than build
   a different commit. Local modifications in a checkout you pass are
   preserved, so you can test an applied candidate patch; the recorded
   revision fixes the commit, not the working tree.
   **For Firefox/`mach` bundles**, the checkout path is
   mandatory — pass it explicitly, or set `REPRO_AUTO_CLONE=1` to
   `hg clone` the recorded upstream repository next to the script
   (very slow).
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
- an LLVM that supports `-fsanitize=<name>` for the sanitizer
  recorded in the bundle (ASan, UBSan, MSan, TSan, or Go's `race`).

Generated recipes do not provision operating-system packages for you. They may
invoke package managers such as npm, pip, Bundler, Composer, Maven, Gradle, R,
or cpanm; those tools use their normal configured cache and install locations.
Use a disposable account or container if those locations are not already
isolated. An offline or proxied environment may need its normal
project-specific preparation first.

### Common one-off overrides

```bash
CC=clang-18 ./reproduce.sh /path/to/checkout                   # pin compiler
REPRO_AUTO_CLONE=1 ./reproduce.sh                              # fresh clone
ASAN_OPTIONS="abort_on_error=1" ./reproduce.sh /path/to/co     # extra runtime opts
```

`reproduce.sh` runs with `set -eu` and prints a banner for each major
step (`=== compiling harness ... ===`, `=== running ... ===`). If a
build step fails, the trailing few lines name the step and the error.

## Reading the sanitizer output

`sanitizer.txt` contains the original sanitizer report from
discovery — unfiltered, with full stack traces. The top of the file
names the diagnostic class. For ASan, that is one of:

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

`REPORT.md` normally points you at the line that matters. The full
trace is in `sanitizer.txt` if you want the rest.

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
  the version named in `REPORT.md`'s "Build" section.
- **A configure-time option that disables the affected code path**
  (`--without-zlib`, `--disable-foo`). Diff your configure flags
  against the ones in `reproduce.sh`.
- **A racy lifetime bug that needs a specific allocator state.** Try
  `ASAN_OPTIONS=quarantine_size_mb=1` (forces freed memory to stay
  freed long enough to fire the diagnostic).

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

> Discovered with TokenFuzz (LLM-based sanitizer-regression
> harness).

Follow the project's normal coordinated-disclosure and embargo process.

## Got a question or want to challenge the report?

Reply on whatever channel the report came in on (security inbox,
issue tracker, etc.). The TokenFuzz repository's own issue tracker
is for bugs and questions about the harness itself, not for triage
of findings in your project — see
[Getting help](../getting-help.md).
