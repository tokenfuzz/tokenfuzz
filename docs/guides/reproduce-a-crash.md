# Reproduce a Crash

This page is for the **upstream maintainer** who received a TokenFuzz
crash artifact. It walks through:

- confirming the issue against your own checkout;
- reading the sanitizer output;
- verifying a fix.

If you are the operator running TokenFuzz, see
[Triage results](triage-results.md) instead.

## What you may have received

You can be handed two shapes of artifact:

- **A raw crash directory** copied out of
  `output/.../crashes/CRASH-*`. Every accepted crash includes
  `reproduce.sh`, the input, and `sanitizer.txt`, so this is enough to
  reproduce on its own.
- **An export bundle** produced by `bin/export-repro`. This packages
  the same files into a self-contained directory with a generated
  `REPORT.md` on top.

Both shapes use the same `reproduce.sh` contract. The instructions
below apply to either.

## Bundle layout

If you were handed an export bundle, the directory is named after the
crash id. After unpacking you get:

```
CRASH-001-1/
├── REPORT.md          # one-page summary: bug, root cause, candidate fix
├── REPORT.html        # browser-friendly render of REPORT.md
├── reproduce.sh       # single command, no env vars
├── input.<ext>        # the testcase bytes
├── harness.{c,cc,cpp,cxx} # present iff the bug uses a C/C++ harness
├── sanitizer.txt      # full sanitizer output captured during discovery
└── reachability.json  # optional: caller search + advisory severity
```

`REPORT.md` is what to read first. For an even easier read, open
`REPORT.html` in a browser — same content with the field table
aligned, severity badge, and external links resolved.

The report names:

- the affected `file:function:line`;
- the issue class (bounds / lifetime / type / size / uninit / state);
- the data flow;
- a candidate fix direction.

It is normalized from the agent-authored report, sanitizer output, and
structured fields gathered during triage. Hand-edit `REPORT.md` only —
`REPORT.html` is regenerated automatically.

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
   (every non-Firefox project), running with no argument clones the
   recorded upstream URL at the recorded revision into a directory
   next to the script. Running with a path uses that checkout
   instead. **For Firefox/`mach` bundles**, the checkout path is
   mandatory — pass it explicitly, or set `REPRO_AUTO_CLONE=1` to
   clone `mozilla-unified` next to the script (very slow).
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

The script does **not** install anything system-wide and does **not**
modify your environment.

### Common one-off overrides

```bash
CC=clang-18 ./reproduce.sh /path/to/checkout                   # pin compiler
REPRO_AUTO_CLONE=1 ./reproduce.sh                              # fresh clone
ASAN_OPTIONS="abort_on_error=1" ./reproduce.sh /path/to/co     # extra runtime opts
```

`reproduce.sh` runs with `set -eu` and prints every command it
executes. If a build step fails, the trailing few lines name exactly
which step and why.

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

After landing your patch:

1. Re-run `./reproduce.sh /path/to/checkout`.
2. Confirm the build step succeeds.
3. Confirm the run completes **without** the diagnostic.

A clean run typically looks like the binary or harness running
silently to exit code 0 — or, for a parser, emitting its normal
output.

If the sanitizer is still firing on a different stack, that is a new
finding adjacent to the original one. Please respond to the reporter
rather than closing the issue.

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

- It does not phone home.
- It does not contain audit-internal vocabulary.
- It does not embed model transcripts.

The audit-side originals — operator's `report.md`, `reproduce.sh`,
H-prefixed scratch artifacts — live in `.audit/` inside the bundle
for provenance. They are not needed to reproduce.

If you would like to credit TokenFuzz in your advisory or commit
message, the appropriate phrasing is something like:

> Discovered with TokenFuzz (LLM-based sanitizer-regression
> harness).

There is no embargo on disclosure other than the one you set as the
maintainer.

## Got a question or want to challenge the report?

Reply on whatever channel the report came in on (security inbox,
issue tracker, etc.). The TokenFuzz repository's own issue tracker
is for bugs and questions about the harness itself, not for triage
of findings in your project — see
[Getting help](../getting-help.md).
