#!/usr/bin/env python3
"""tests/test_export_repro_py.py — exercise the Python export-repro
internals plus an end-to-end run that diffs against a frozen golden bundle.

The companion tests/test_export_repro_template.sh keeps the original
fixture-driven assertions for the strip/awk logic. This file:
  - imports bin/export-repro as a module and tests strip_audit_sections,
    rewrite_audit_script_body, ext_of, infer_surface, infer_primitive_label
  - runs the full tool end-to-end against a fabricated crash dir and
    checks that the produced bundle has the expected structure
"""

from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# ─── Pass/fail bookkeeping (same ✓/✗ marks as helpers.sh) ─────────

_PASSED = 0
_FAILED = 0
_GREEN = "\033[0;32m"
_RED = "\033[0;31m"
_NC = "\033[0m"


def passed(name: str) -> None:
    global _PASSED
    _PASSED += 1
    print(f"  {_GREEN}✓{_NC} {name}")


def failed(name: str, detail: str = "") -> None:
    global _FAILED
    _FAILED += 1
    print(f"  {_RED}✗{_NC} {name}")
    if detail:
        print(f"    {detail}")


def assert_eq(expected, actual, name: str) -> None:
    if expected == actual:
        passed(name)
    else:
        failed(name, f"expected={expected!r} actual={actual!r}")


def assert_in(needle: str, haystack: str, name: str) -> None:
    if needle in haystack:
        passed(name)
    else:
        failed(name, f"{needle!r} not in: {haystack[:200]!r}")


def assert_not_in(needle: str, haystack: str, name: str) -> None:
    if needle not in haystack:
        passed(name)
    else:
        failed(name, f"{needle!r} unexpectedly in haystack")


# ─── Load bin/export-repro as a module ──────────────────────────────

sys.path.insert(0, str(ROOT / "lib"))
loader = importlib.machinery.SourceFileLoader("export_repro_mod", str(ROOT / "bin" / "export-repro"))
spec = importlib.util.spec_from_loader("export_repro_mod", loader)
er = importlib.util.module_from_spec(spec)
spec.loader.exec_module(er)


# ─── Direct unit tests on strip / inference helpers ─────────────────

# 0. Shell-template substitutions are quoted and bundle extensions are safe.
assert_eq("bin", er.ext_of("test.$(id)"),
          "ext_of: unsafe unknown extension falls back to bin")
assert_eq("bin", er.ext_of("no-extension"),
          "ext_of: extensionless testcase falls back to bin")
pre = er.emit_preamble("cmake", "https://example.invalid/repo;id",
                       "rev $(id)", "bad slug;id", "bin/ignored")
assert_in("URL='https://example.invalid/repo;id'", pre,
          "emit_preamble: upstream URL shell-quoted")
assert_in("REV='rev $(id)'", pre,
          "emit_preamble: revision shell-quoted")
assert_in('default_src="$(dirname "$0")"/bad-slug-id', pre,
          "emit_preamble: auto-clone slug sanitized")
bin_resolve = er.emit_bin_resolve("build-asan/bin/x$(id)")
assert_in('san_bin="$build"/\'bin/x$(id)\'', bin_resolve,
          "emit_bin_resolve: build path shell-quoted")

# Make/Bazel build templates: even though we don't auto-detect Make or
# Bazel as standalone "languages", C/C++ test corpora frequently ship
# with ad-hoc Makefiles or BUILD files for their fixtures. Exported
# repros must be able to opt into either via target.toml
# `build_system = "make"` / `"bazel"`. UNKNOWN_BUILD here would silently
# break those fixtures.
make_build = er.emit_build("make")
assert_in("make", make_build, "emit_build: 'make' returns make template")
assert_eq(False, make_build == er.UNKNOWN_BUILD,
          "emit_build: 'make' is not UNKNOWN_BUILD")
bazel_build = er.emit_build("bazel")
assert_in("bazel build", bazel_build, "emit_build: 'bazel' returns bazel template")
assert_eq(False, bazel_build == er.UNKNOWN_BUILD,
          "emit_build: 'bazel' is not UNKNOWN_BUILD")
assert_in("make", er._LANGUAGE_BUILD_TEMPLATES,
          "_LANGUAGE_BUILD_TEMPLATES registers 'make'")
assert_in("bazel", er._LANGUAGE_BUILD_TEMPLATES,
          "_LANGUAGE_BUILD_TEMPLATES registers 'bazel'")
cfg_for_leak = er.target_config.Config()
cfg_for_leak.results_dir = str(ROOT / "output" / "demo" / "codex" / "results")
assert_eq(True, er._bundle_text_has_internal_ref(f"path={cfg_for_leak.results_dir}", cfg_for_leak),
          "leak scan: dynamic RESULTS_DIR path is forbidden")

# Hardcoded host-path prefixes are no longer the gate — only env-var
# tokens and the cfg.* prefix loop. Verify the old /Users-only regex
# no longer fires on container layouts (Docker /root/work, CI
# /workspace, etc.) when cfg is unrelated to them.
cfg_unrelated = er.target_config.Config()
cfg_unrelated.results_dir = "/some/audit/dir"
for host_path in (
    "/root/work/output/zlib/codex/results/scratch-2/H-abc.txt",
    "/workspace/output/foo/codex/results/scratch/H.txt",
    "/Users/alice/projects/output/demo/codex/results/H.txt",
):
    assert_eq(False, er._bundle_text_has_internal_ref(host_path, cfg_unrelated),
              f"leak scan: bare host path {host_path[:30]}… is no longer flagged")

# Env-var-style tokens still trip the regex regardless of host layout.
for token_line in (
    "RESULTS_DIR=/srv/audit/results",
    "TARGET_ROOT=/var/audit/targets/zlib",
    "TARGET_SLUG=zlib",
    "AUDIT_AGENT_NUM=2",
    "HYPOTHESIS_ID=H-abc",
    "TRIED_INPUTS_LOG=/foo/tried-inputs-1.log",
    "ASAN_OUTPUT_FILE=/tmp/asan.txt",
    "HITS_LOG_PATH=/tmp/hits.log",
):
    assert_eq(True, er._bundle_text_has_internal_ref(token_line, cfg_unrelated),
              f"leak scan: token leak still caught — {token_line.split('=')[0]}")
# But the bare keyword without `=` is allowed (it's normal prose).
assert_eq(False, er._bundle_text_has_internal_ref(
    "see RESULTS_DIR conventions in the audit guide", cfg_unrelated),
    "leak scan: bare keyword in prose is not flagged")

# ─── Path normalization ─────────────────────────────────────────
# A REPORT.md inside Docker carries /root/work/... paths verbatim.
# The normalizer should rewrite target_root → targets/<slug> and
# strip the results_dir prefix so the leak scan no longer fires.
cfg_docker = er.target_config.Config()
cfg_docker.target_root = "/root/work/targets/zlib"
cfg_docker.results_dir = "/root/work/output/zlib/codex/results"
cfg_docker.logdir = "/root/work/output/zlib/codex/logs"
cfg_docker.slug = "zlib"
sample_report = (
    "Dedup frames: gz_read /root/work/targets/zlib/gzread.c:343:13 -> "
    "gzread /root/work/targets/zlib/gzread.c:419:21\n"
    "bin/probe --confirm /root/work/output/zlib/codex/results/scratch-2/H-xyz.txt\n"
    "logs at /root/work/output/zlib/codex/logs/index.log\n"
)
normalized = er._normalize_bundle_paths(sample_report, cfg_docker)
assert_in("targets/zlib/gzread.c:343:13", normalized,
          "normalize: target_root rewritten to targets/<slug>")
assert_not_in("/root/work/targets/zlib", normalized,
          "normalize: raw target_root prefix gone")
assert_in("scratch-2/H-xyz.txt", normalized,
          "normalize: results_dir prefix stripped but scratch tail preserved")
assert_not_in("/root/work/output/zlib/codex/results", normalized,
          "normalize: raw results_dir prefix gone")
assert_in("logs/index.log", normalized,
          "normalize: logdir rewritten to logs/")
# And after rewriting, the leak scan should NOT fire on this cfg.
assert_eq(False, er._bundle_text_has_internal_ref(normalized, cfg_docker),
          "normalize+leak-scan: normalized text passes")
# Idempotency: applying twice produces the same result.
assert_eq(normalized, er._normalize_bundle_paths(normalized, cfg_docker),
          "normalize: idempotent on already-rewritten text")
# Empty / None-equivalent cfg fields are no-ops.
cfg_empty = er.target_config.Config()
assert_eq("foo /root/x bar", er._normalize_bundle_paths("foo /root/x bar", cfg_empty),
          "normalize: empty cfg fields → no rewrite")

# _normalize_bundle_file: skips binary inputs (NUL byte heuristic).
with tempfile.TemporaryDirectory() as td:
    p = Path(td) / "input.bin"
    payload = b"\x00\x01\x02\x03/root/work/targets/zlib/gzread.c"
    p.write_bytes(payload)
    er._normalize_bundle_file(p, cfg_docker)
    assert_eq(payload, p.read_bytes(), "normalize: binary file untouched (NUL guard)")

    q = Path(td) / "REPORT.md"
    q.write_text("see /root/work/targets/zlib/gzread.c\n", encoding="utf-8")
    er._normalize_bundle_file(q, cfg_docker)
    assert_in("targets/zlib/gzread.c", q.read_text(encoding="utf-8"),
              "normalize: text file rewritten in place")
    assert_not_in("/root/work/targets/zlib", q.read_text(encoding="utf-8"),
              "normalize: text file no longer leaks raw prefix")

# _install_with_exact_case: guard against case-insensitive FS leaving
# the bundled REPORT.md visible under the agent's lowercase report.md.
# On macOS APFS (case-insensitive but case-preserving) and Docker
# Desktop bind mounts that ride on top of it, writing to "REPORT.md"
# when a "report.md" entry already exists silently overwrites the bytes
# but leaves the directory entry under the original lowercase case. The
# exact-case bundle gate in lib/triage.sh:_triage_has_exact_file then
# reports "missing REPORT.md" and recycles the crash, eventually
# auto-rejecting it after CRASH_PROMOTION_PENDING_MAX passes. This test
# locks in the install helper that unlinks any case-different sibling
# before copying and falls back to os.rename if the FS still serves the
# old case.
with tempfile.TemporaryDirectory() as td:
    out_dir = Path(td) / "out"
    out_dir.mkdir()
    # Pre-seed the lowercase entry that would defeat a naive copy.
    (out_dir / "report.md").write_text("stale agent draft\n", encoding="utf-8")
    src = Path(td) / "stage" / "REPORT.md"
    src.parent.mkdir()
    src.write_text("# canonical bundled report\n", encoding="utf-8")

    # Detect host case-sensitivity by seeing whether the lowercase
    # sibling above is even visible under the uppercase name. On
    # case-sensitive filesystems the two are independent entries; on
    # case-insensitive filesystems they resolve to one.
    case_insensitive = (out_dir / "REPORT.md").is_file()

    er._install_with_exact_case(src, out_dir / "REPORT.md")
    entries = sorted(p.name for p in out_dir.iterdir())
    assert_in("REPORT.md", entries,
              "install_with_exact_case: canonical case present after install")
    assert_not_in("report.md", entries,
                  "install_with_exact_case: lowercase sibling cleared")
    if case_insensitive:
        assert_eq(["REPORT.md"], entries,
                  "install_with_exact_case: exactly one entry on "
                  "case-insensitive FS (the staged bundle file)")
    assert_in("canonical bundled report",
              (out_dir / "REPORT.md").read_text(encoding="utf-8"),
              "install_with_exact_case: staged content installed")

    # Re-running on a clean dir is a no-op (idempotent).
    er._install_with_exact_case(src, out_dir / "REPORT.md")
    assert_eq(["REPORT.md"], sorted(p.name for p in out_dir.iterdir()),
              "install_with_exact_case: idempotent on clean dir")

# ─── Advisory detection ─────────────────────────────────────────
with tempfile.TemporaryDirectory() as td:
    rpt = Path(td) / "report.md"
    rpt.write_text(
        "## Summary\nSome bug.\n\n## Fix Direction\nDeprecate the raw char* API.\n",
        encoding="utf-8",
    )
    patch = Path(td) / "patch.diff"
    # No patch → advisory yes.
    assert_eq("yes", er.detect_advisory_status(rpt, patch),
              "advisory: Fix Direction without patch.diff → yes")
    # Patch present → advisory no.
    patch.write_text("--- a/x\n+++ b/x\n@@\n+1\n", encoding="utf-8")
    assert_eq("no", er.detect_advisory_status(rpt, patch),
              "advisory: patch.diff present → no")
    # No Fix Direction heading + no patch → unknown ('').
    patch.unlink()
    rpt.write_text("## Summary\nSome bug.\n", encoding="utf-8")
    assert_eq("", er.detect_advisory_status(rpt, patch),
              "advisory: missing Fix Direction → unspecified")
    # Variant headings should all count.
    for heading in ("Suggested Fix", "Recommended Fix", "Mitigation", "Remediation"):
        rpt.write_text(f"## {heading}\nDo X.\n", encoding="utf-8")
        assert_eq("yes", er.detect_advisory_status(rpt, patch),
                  f"advisory: heading variant '{heading}' detected")

# ─── extract_summary_section (Summary-before-Fields layout) ─────────
# The Summary section (plus any leading enrichment blocks) is split off the
# front of the body so build_report_md can place it ABOVE the Fields table.
full_body = (
    "<!-- enrich:tldr -->\n**TLDR**\n<!-- /enrich:tldr -->\n\n"
    "## Summary\n\nThe real summary prose.\n\n"
    "## Classification\n\nCategory: lifetime\n\n"
    "## Root Cause\n\nDeep cause here.\n")
head, rest = er.extract_summary_section(full_body)
assert "<!-- enrich:tldr -->" in head and "## Summary" in head and "real summary prose" in head, \
    "extract_summary_section: head carries leading enrich block + Summary section"
assert "## Classification" not in head and "## Root Cause" not in head, \
    "extract_summary_section: later sections stay out of the head"
assert "## Classification" in rest and "## Root Cause" in rest and "## Summary" not in rest, \
    "extract_summary_section: rest carries the post-Summary narrative only"
assert_eq(("", rest), er.extract_summary_section(rest),
          "extract_summary_section: idempotent on the remainder")
# `###` subsections stay attached to Summary.
sub = "## Summary\n\nLead.\n\n### Detail\n\nMore.\n\n## Classification\n\nx\n"
h2, r2 = er.extract_summary_section(sub)
assert "### Detail" in h2 and "## Classification" in r2, \
    "extract_summary_section: H3 subsection stays with Summary, H2 ends it"
# No Summary → no-op (Fields stays first).
assert_eq(("", "## Root Cause\n\nx\n"), er.extract_summary_section("## Root Cause\n\nx\n"),
          "extract_summary_section: no ## Summary → no-op")
# Another section before Summary → no-op (don't drag it along).
assert er.extract_summary_section("## Classification\n\nc\n\n## Summary\n\ns\n")[0] == "", \
    "extract_summary_section: Summary not leading → no-op"
# Summary-only body (model-direct) → rest is empty.
h3, r3 = er.extract_summary_section("## Summary\n\nOnly summary.\n")
assert "Only summary." in h3 and r3.strip() == "", \
    "extract_summary_section: summary-only body leaves an empty remainder"

# 1. strip_audit_sections
sample = """\
# CRASH-X-1

| Field | Value |
|:------|:------|
| Surface | library-api |

Surface: library-api
Trigger source: bytes

## Summary
Body prose.

## Reproduce

```sh
./reproduce.sh
```

## Expected sanitizer output

```
==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow
```

Full original output: `asan.txt`.
"""

stripped = er.strip_audit_sections(sample)
assert_not_in("# CRASH-X-1", stripped, "strip_audit_sections: h1 dropped")
assert_not_in("## Reproduce", stripped, "strip_audit_sections: ## Reproduce dropped")
assert_not_in("## Expected sanitizer output", stripped, "strip_audit_sections: ## Expected ... dropped")
assert_not_in("Full original output:", stripped, "strip_audit_sections: 'Full original output:' line dropped")
assert_not_in("Surface: library-api", stripped, "strip_audit_sections: bare-label Surface dropped")
assert_not_in("Trigger source: bytes", stripped, "strip_audit_sections: bare-label Trigger source dropped")
assert_in("## Summary", stripped, "strip_audit_sections: ## Summary preserved")
assert_in("Body prose.", stripped, "strip_audit_sections: narrative preserved")
# Idempotent: a second pass is a no-op.
stripped2 = er.strip_audit_sections(stripped)
assert_eq(stripped, stripped2, "strip_audit_sections is idempotent")


# 2. rewrite_audit_script_body
TMP = Path(tempfile.mkdtemp(prefix="er-py-"))
sample_sh = TMP / "wrapper.sh"
sample_sh.write_text("""#!/bin/sh
# TARGET: foo.c:42
# HARNESS: harness.c
set -eu
ROOT="$(pwd)"
SRC="$ROOT/src"
HARNESS_BIN="$SRC/h"
if [ ! -x "$HARNESS_BIN" ]; then
  echo "build me first" >&2
  exit 1
fi
"$HARNESS_BIN" -- arg1 arg2
"$BIN" -- arg
""", encoding="utf-8")

rewritten = er.rewrite_audit_script_body(sample_sh)
assert_not_in("#!/bin/sh", rewritten, "rewrite: shebang stripped")
assert_not_in("set -eu\n", rewritten, "rewrite: 'set -eu' line stripped")
assert_not_in("# TARGET:", rewritten, "rewrite: # TARGET header stripped")
assert_not_in('HARNESS_BIN="$SRC/h"', rewritten, "rewrite: HARNESS_BIN= init stripped")
assert_not_in('echo "build me first"', rewritten,
              "rewrite: 'if [ ! HARNESS_BIN' guard block stripped through fi")
assert_in('"$san_bin"', rewritten,
          "rewrite: $HARNESS_BIN call rewritten to $san_bin")

# Hardcoded build-asan/<binary> absolute path must be rewritten regardless
# of which host prefix the audit ran under. Regression for the
# /Users-only anchor that left Docker/CI paths leaking through.
for host_prefix in ("/Users/alice/work", "/root/work", "/workspace",
                    "/srv/audit", "/mnt/c/Users/bob/work"):
    sample = TMP / "wrapper-host.sh"
    sample.write_text(
        f'#!/bin/sh\nexec "{host_prefix}/build-asan/parse" "$@"\n',
        encoding="utf-8")
    out = er.rewrite_audit_script_body(sample)
    assert_not_in(host_prefix, out,
                  f"rewrite: host prefix {host_prefix} stripped from build-asan/<bin>")
    assert_in('"$san_bin"', out,
              f"rewrite: build-asan/<bin> under {host_prefix} rewritten to $san_bin")

# Self-compiling shell harnesses reference upstream sources via the audit-side
# target_root (and may have been pre-normalized to slug-relative form by
# _normalize_bundle_paths). Both forms must end up as $repro_src so the
# reproducer's cloned upstream tree is used at runtime.
self_compile_sh = TMP / "self-compile.sh"
self_compile_sh.write_text(
    '#!/usr/bin/env bash\n'
    'clang -fsanitize=address \\\n'
    '  -I/Users/alice/work/targets/sampleproj \\\n'
    '  /Users/alice/work/targets/sampleproj/core.c \\\n'
    '  targets/sampleproj/helper.c \\\n'
    '  -o /tmp/repro\n',
    encoding="utf-8")
slug_out = er.rewrite_audit_script_body(
    self_compile_sh, slug="sampleproj",
    target_root="/Users/alice/work/targets/sampleproj"
)
assert_in('-I"$repro_src"', slug_out,
          "rewrite: absolute target_root prefix (with -I attached) rewritten to $repro_src")
assert_in('"$repro_src"/core.c', slug_out,
          "rewrite: absolute target_root + source file rewritten to $repro_src/...")
assert_in('"$repro_src"/helper.c', slug_out,
          "rewrite: slug-relative targets/<slug>/file rewritten to $repro_src/...")
assert_not_in('/Users/alice/work/targets/sampleproj', slug_out,
              "rewrite: absolute target_root prefix fully stripped")
assert_not_in('targets/sampleproj/', slug_out,
              "rewrite: slug-relative form fully stripped")

# Word boundary on the prefix — don't trip a longer sibling slug.
sibling_sh = TMP / "sibling.sh"
sibling_sh.write_text(
    '#!/usr/bin/env bash\n'
    'echo /Users/alice/work/targets/sampleproj_old/file.c\n'
    'echo targets/sampleproj_old/file.c\n',
    encoding="utf-8")
sibling_out = er.rewrite_audit_script_body(
    sibling_sh, slug="sampleproj",
    target_root="/Users/alice/work/targets/sampleproj"
)
assert_in('targets/sampleproj_old/file.c', sibling_out,
          "rewrite: sibling slug 'sampleproj_old' is NOT rewritten")
assert_not_in('"$repro_src"_old', sibling_out,
              "rewrite: sibling slug must not glue onto $repro_src")

# emit_link_libs_with_resolves: each path-shaped entry produces a
# basename-fallback resolver block and a $-quoted variable reference in
# the link line; flag entries pass through verbatim.
resolves, args = er.emit_link_libs_with_resolves(
    ["build-asan/lib/libsample.a", "-lm", "-lpthread"], "asan"
)
assert_in('link_lib_0="$build"/lib/libsample.a', resolves,
          "link_libs: first resolver block uses $build + stripped tail")
assert_in("-name libsample.a", resolves,
          "link_libs: basename fallback emitted")
assert_in('"$link_lib_0"', args,
          "link_libs: link args reference resolver variable")
assert_in('-lm', args, "link_libs: -lm flag passes through")
assert_in('-lpthread', args, "link_libs: -lpthread flag passes through")
# Numbering increments for multiple archives.
resolves2, args2 = er.emit_link_libs_with_resolves(
    ["build-asan/lib/libfoo.a", "build-asan/lib/libbar.a"], "asan"
)
assert_in("link_lib_0=", resolves2, "link_libs: numbering starts at 0")
assert_in("link_lib_1=", resolves2, "link_libs: second archive numbered 1")
assert_in('"$link_lib_0" "$link_lib_1"', args2,
          "link_libs: both vars referenced in link line")
resolves_src, args_src = er.emit_link_libs_with_resolves(
    ["cJSON_Utils.c", "src/extra.cc"], "asan"
)
assert_in('link_lib_0="$src"/cJSON_Utils.c', resolves_src,
          "link_libs: C source inputs resolve from $src, not $build")
assert_in('link source not found under $src', resolves_src,
          "link_libs: source resolver emits a source-specific error")
assert_in("-name cJSON_Utils.c", resolves_src,
          "link_libs: source resolver has basename fallback")
assert_not_in('link archive not found under $build: cJSON_Utils.c', resolves_src,
              "link_libs: source inputs are not treated as build archives")
assert_in('"$link_lib_0" "$link_lib_1"', args_src,
          "link_libs: source vars are referenced in link line")
resolves_spaced, args_spaced = er.emit_link_libs_with_resolves(
    ["source dir/extra file.c", "build dir/lib sample.a"], "asan"
)
assert_in('link_lib_0="$src"/\'source dir/extra file.c\'', resolves_spaced,
          "link_libs: source relative paths are shell-quoted after $src")
assert_in('link_lib_1="$build"/\'build dir/lib sample.a\'', resolves_spaced,
          "link_libs: archive relative paths are shell-quoted after $build")
assert_in('"$link_lib_0" "$link_lib_1"', args_spaced,
          "link_libs: quoted-path vars are referenced in link line")
resolves_diag, _args_diag = er.emit_link_libs_with_resolves(
    ['weird "`name`".c'], "asan"
)
assert_in('link_lib_0="$src"/\'weird "`name`".c\'', resolves_diag,
          "link_libs: shell path uses single-quoted literal for metacharacters")
assert_in('link source not found under $src: weird \\"\\`name\\`\\".c',
          resolves_diag,
          "link_libs: diagnostic text escapes double-quoted shell metacharacters")


# find_shell_wrapper: harness.sh and harness.bash are first-class
# (lib/languages.py convention), alongside the legacy testcase.sh /
# reproducer.sh names. Each name is recognized when present.
for wrapper_name in ("harness.sh", "harness.bash", "testcase.sh", "reproducer.sh"):
    d = Path(tempfile.mkdtemp(prefix="er-shfind-"))
    (d / wrapper_name).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    found = er.find_shell_wrapper([d])
    assert_eq(d / wrapper_name, found,
              f"find_shell_wrapper picks up {wrapper_name}")

runner_input_dir = Path(tempfile.mkdtemp(prefix="er-shfind-runner-input-"))
(runner_input_dir / "testcase.sh").write_text(
    "TARGET: targets/sample-go-asan/auth.go:exerciseAuthorizationRace:53\n"
    "HYPOTHESIS-ID: H1\n"
    "CATEGORY: state\n"
    "race:2\n",
    encoding="utf-8",
)
assert_eq(None, er.find_shell_wrapper([runner_input_dir]),
          "find_shell_wrapper ignores .sh runner testcase with bare audit headers")
runner_input = runner_input_dir / "testcase.sh"
runner_bytes = er.read_testcase_bytes(runner_input).decode("utf-8")
assert_not_in("TARGET:", runner_bytes,
              "read_testcase_bytes strips bare TARGET header from runner testcase")
assert_not_in("HYPOTHESIS-ID:", runner_bytes,
              "read_testcase_bytes strips bare HYPOTHESIS-ID header from runner testcase")
assert_in("race:2", runner_bytes,
          "read_testcase_bytes preserves runner testcase payload")

text_payload = runner_input_dir / "input.txt"
text_payload.write_text(
    "// TARGET: targets/sample-swift-asan/Sources/sample-swift-asan/main.swift:18\n"
    + ("A" * 64) + "\n",
    encoding="utf-8",
)
text_payload_bytes = er.read_testcase_bytes(text_payload).decode("utf-8")
assert_in("// TARGET:", text_payload_bytes,
          "read_testcase_bytes preserves comment-style bytes in data testcase")
assert_in("AAAAAAAA", text_payload_bytes,
          "read_testcase_bytes preserves text data testcase payload")

swift_repro = runner_input_dir / "swift-reproduce.sh"
er.write_cli_with_input_template(
    swift_repro,
    build_system="swift",
    upstream_url="FILL_ME",
    pinned_rev="HEAD",
    slug="sample-swift-asan",
    san_bin_rel="",
    cmake_target="",
    input_name="input.txt",
    sanitizer="asan",
)
swift_repro_text = swift_repro.read_text(encoding="utf-8")
assert_in("swift run --quiet -c release", swift_repro_text,
          "Swift export uses swift run when no asan_bin is configured")
assert_in("-sanitize=address", swift_repro_text,
          "Swift export enables ASan through -Xswiftc")
assert_in('sample-swift-asan "$testcase"', swift_repro_text,
          "Swift export runs the package executable with the staged input")
assert_not_in("ASan binary not configured", swift_repro_text,
              "Swift export does not emit missing-binary stub")


# 3. ext_of
assert_eq("html", er.ext_of("foo.html"), "ext_of: .html")
assert_eq("js", er.ext_of("foo.mjs"), "ext_of: .mjs maps to js")
assert_eq("xml", er.ext_of("foo.xml"), "ext_of: .xml")
assert_eq("dat", er.ext_of("foo.dat"), "ext_of: .dat")
assert_eq("pcre2", er.ext_of("foo.pcre2"), "ext_of: unknown extension passes through")


# 4. infer_primitive_label
assert_eq("heap-buffer-overflow",
          er.infer_primitive_label("==<pid>==ERROR: AddressSanitizer: heap-buffer-overflow on address ..."),
          "infer_primitive_label: heap-buffer-overflow")
assert_eq("double-free",
          er.infer_primitive_label("==<pid>==ERROR: AddressSanitizer: attempting double-free on 0x602000000010"),
          "infer_primitive_label: attempting double-free → double-free")
assert_eq("bad-free",
          er.infer_primitive_label("==<pid>==ERROR: AddressSanitizer: attempting free on address which was not malloc()-ed"),
          "infer_primitive_label: attempting invalid free → bad-free")
assert_eq("wild-address-read",
          er.infer_primitive_label("==<pid>==ERROR: AddressSanitizer: SEGV on unknown address 0x4141414141414141\nREAD of size 8 at 0x4141414141414141 thread T0\nHint: this fault was caused by a dereference of a high value address"),
          "infer_primitive_label: high-address SEGV read → wild-address-read")
assert_eq("use-of-uninitialized-value",
          er.infer_primitive_label("WARNING: MemorySanitizer: use-of-uninitialized-value"),
          "infer_primitive_label: MSan uninit → use-of-uninitialized-value")
assert_eq("data-race",
          er.infer_primitive_label("WARNING: ThreadSanitizer: data race"),
          "infer_primitive_label: TSan data race → data-race")
assert_eq("ubsan-out-of-bounds",
          er.infer_primitive_label("parser.c:77:5: runtime error: index 4 out of bounds for type 'int[4]'"),
          "infer_primitive_label: UBSan bounds → ubsan-out-of-bounds")
assert_eq("unclassified", er.infer_primitive_label(""),
          "infer_primitive_label: empty asan_top → unclassified")

ubsan_diag = TMP / "ubsan.txt"
ubsan_diag.write_text("""\
parser.c:77:5: runtime error: index 4 out of bounds for type 'int[4]'
    #0 0x1 in parse parser.c:77
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior parser.c:77:5
""", encoding="utf-8")
assert_eq("parser.c:77:5: runtime error: index 4 out of bounds for type 'int[4]'",
          er.extract_asan_top(ubsan_diag),
          "extract_asan_top: UBSan runtime error line accepted")
assert_eq("SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior parser.c:77:5",
          er.extract_asan_summary(ubsan_diag),
          "extract_asan_summary: UBSan summary accepted")
assert_in("UndefinedBehaviorSanitizer",
          er.extract_asan_diagnostic(ubsan_diag),
          "extract_asan_diagnostic: UBSan block retained")
assert_eq("ubsan",
          er.infer_sanitizer_from_text("SANITIZER_RUN_HEADER: sanitizer=ubsan runs=1 mode=generic testcase=x started=y\n"),
          "infer_sanitizer_from_text: SANITIZER_RUN_HEADER wins")
assert_eq("msan",
          er.infer_sanitizer_from_text("WARNING: MemorySanitizer: use-of-uninitialized-value"),
          "infer_sanitizer_from_text: MSan diagnostic")
assert_eq("tsan",
          er.infer_sanitizer_from_text("WARNING: ThreadSanitizer: data race"),
          "infer_sanitizer_from_text: TSan diagnostic")
assert_eq("race",
          er.infer_sanitizer_from_text("WARNING: DATA RACE\nRead at 0x00 by goroutine 1"),
          "infer_sanitizer_from_text: Go race diagnostic")
assert_eq("asan",
          er.infer_sanitizer_from_text("ASAN_RUN_HEADER: sanitizer=asan runs=5 mode=generic testcase=x started=y\n"),
          "infer_sanitizer_from_text: ASAN_RUN_HEADER legacy")
assert_eq("allocator_may_return_null=1",
          er.decode_header_b64("YWxsb2NhdG9yX21heV9yZXR1cm5fbnVsbD0x"),
          "decode_header_b64: recorded env options decode")
env_block = er.sanitizer_runtime_env_block(
    "asan",
    extra_options="target_extra=1",
    mode="generic",
    recorded_env_options="allocator_may_return_null=1",
)
assert_in("quarantine_size_mb=256:redzone=64", env_block,
          "sanitizer_runtime_env_block: ASan replay keeps run-asan redzone/quarantine")
assert_in("target_extra=1", env_block,
          "sanitizer_runtime_env_block: target options are included")
assert_in("allocator_may_return_null=1", env_block,
          "sanitizer_runtime_env_block: recorded env options are included")


# 5. infer_surface heuristics
asan_path = TMP / "asan.txt"
asan_path.write_text("""==12345==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x100 in resolve_entry /src/sampleproj/catalog.c:42
    #1 0x200 in main /src/sampleproj/apptool.c:88
""", encoding="utf-8")
# The CLI tool name comes from cfg.asan_bin's basename — no hardcoded
# project list. A frame inside that binary's own source → cli.
cli_cfg = types.SimpleNamespace(
    asan_bin="targets/sampleproj/build-asan/apptool",
    is_browser="0", target_root="/src/sampleproj")
v, why = er.infer_surface(None, asan_path, cli_cfg)
assert_eq("cli", v, "infer_surface: cfg-derived tool name frame → cli")

# Library-api harness with public include
harness = TMP / "harness.c"
harness.write_text('#include "pcre2.h"\nint main(void){return 0;}\n', encoding="utf-8")
block_report = TMP / "block-report.md"
block_report.write_text("""\
Boundary:
Public c-ares channel and query APIs.

Caller controls:
DNS query name bytes and public channel lifecycle sequence.

Parameter control:
mapped through a documented resolver option.

Trusted caller actions:
Initialize a channel, duplicate it, destroy the original, enqueue a query.
""", encoding="utf-8")
assert_eq("Public c-ares channel and query APIs.",
          er.read_bare_field(block_report, "Boundary"),
          "read_bare_field: label block Boundary")
assert_eq("DNS query name bytes and public channel lifecycle sequence.",
          er.read_bare_field(block_report, "Caller controls"),
          "read_bare_field: label block Caller controls")
assert_eq("mapped through a documented resolver option.",
          er.read_bare_field(block_report, "Parameter control"),
          "read_bare_field: label block Parameter control")
v2, _ = er.infer_surface(harness, asan_path)
assert_eq("library-api", v2,
          "infer_surface: harness #include of pcre2.h → library-api")
v3, why3 = er.adjust_surface_from_report(
    "library-api", "C harness calls a public library entry point",
    "## Summary\napptool accepts commands on stdin.",
    "apptool --shell stdin",
    "",
)
assert_eq("cli", v3,
          "adjust_surface_from_report: explicit apptool boundary → cli")
assert_in("command-line", why3,
          "adjust_surface_from_report: cli reason is readable")
v4, _ = er.adjust_surface_from_report(
    "library-api", "C harness calls a public library entry point",
    "## Summary\nThe public parser API consumes bytes.",
    "Public parser API byte input",
    "call parser_parse_memory",
)
assert_eq("library-api", v4,
          "adjust_surface_from_report: public API boundary stays library-api")

# 5c. Generic targets: surface inference must work for ANY project, not a
# hardcoded library family. The signals are cfg-derived (tool names) and
# structural (target_root, maint/test path segments).
brotli_asan = TMP / "brotli_asan.txt"
brotli_asan.write_text(
    "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
    "    #0 0x1 in BrotliDecoderDecompress /src/brotli/c/dec/decode.c:9\n"
    "    #1 0x2 in main /src/brotli/c/tools/brotli.c:42\n",
    encoding="utf-8")
brotli_cfg = types.SimpleNamespace(asan_bin="out/brotli", is_browser="0",
                                   target_root="/src/brotli")
gv, _ = er.infer_surface(None, brotli_asan, brotli_cfg)
assert_eq("cli", gv,
          "infer_surface: non-listed project, cfg tool name frame → cli")

# Library-api by structure: frames inside the target tree, no shipped CLI
# binary (asan_bin empty — e.g. a header-only / archive target).
miniz_asan = TMP / "miniz_asan.txt"
miniz_asan.write_text(
    "==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
    "    #0 0x1 in mz_inflate /work/targets/miniz/miniz.c:1200\n",
    encoding="utf-8")
miniz_cfg = types.SimpleNamespace(asan_bin="", is_browser="0",
                                  target_root="/work/targets/miniz")
lv, _ = er.infer_surface(None, miniz_asan, miniz_cfg)
assert_eq("library-api", lv,
          "infer_surface: frames under target_root → library-api")

# With no cfg and no usable target_root, classification is honest "unknown"
# rather than a wrong guess.
uv, _ = er.infer_surface(None, miniz_asan, None)
assert_eq("unknown", uv,
          "infer_surface: no cfg, no target_root → unknown (no false guess)")

# Browser targets are applications, not CLIs — their binary name must not
# be treated as a shipped command-line tool.
ff_cfg = types.SimpleNamespace(asan_bin="build-asan/dist/bin/firefox",
                               is_browser="1", target_root="/src/ff")
assert_eq(set(), er._target_tool_names(ff_cfg),
          "_target_tool_names: browser target yields no CLI tool names")

# adjust_surface_from_report: a cfg-derived tool name in the boundary text
# flips to cli even without a generic CLI keyword.
v5, _ = er.adjust_surface_from_report(
    "library-api", "reason",
    "## Summary\nThe brotli program compresses a file.",
    "brotli file input", "", brotli_cfg,
)
assert_eq("cli", v5,
          "adjust_surface_from_report: cfg tool name in boundary → cli")

# 5b. read_field_from_fields_table + read_bare_field table fallback.
#
# Why these tests exist: agent reports increasingly use a `## Fields`
# Markdown table instead of bare-label `Field: value` lines. Without a
# fallback, build_report_md emits an auto Fields table with `—` in every
# slot, and the rendered HTML carries those empty placeholders. The
# regression that surfaced this — multiple `Caller contract` /
# `Boundary` rows showing `—` in REPORT.html — must not return.
table_report = TMP / "table-report.md"
table_report.write_text("""\
# CRASH-T-1

## Fields

| Field                  | Value                                              |
|:-----------------------|:---------------------------------------------------|
| Primitive              | heap-use-after-free (read of size 8)               |
| Severity               | TBD                                                |
| Surface                | library-api — public tree-API entry points         |
| Boundary               | call-sequence: trusted caller adds, replaces, frees |
| Caller controls        | The call ordering and the entity name              |
| Trusted caller actions | `root_new`, `root_attach_child`, `replace_node`   |
| Caller contract        | obeyed                                             |
| Trigger source         | call-sequence                                      |
| Reproduction rate      | 5/5                                                |

## Summary
Body prose.
""", encoding="utf-8")

# Direct lookups against the table.
assert_eq("call-sequence: trusted caller adds, replaces, frees",
          er.read_field_from_fields_table(table_report, "Boundary"),
          "read_field_from_fields_table: Boundary")
assert_eq("The call ordering and the entity name",
          er.read_field_from_fields_table(table_report, "Caller controls"),
          "read_field_from_fields_table: Caller controls")
assert_eq("obeyed",
          er.read_field_from_fields_table(table_report, "Caller contract"),
          "read_field_from_fields_table: Caller contract")
assert_eq("call-sequence",
          er.read_field_from_fields_table(table_report, "Trigger source"),
          "read_field_from_fields_table: Trigger source")
assert_eq("5/5",
          er.read_field_from_fields_table(table_report, "Reproduction rate"),
          "read_field_from_fields_table: Reproduction rate")
assert_eq("`root_new`, `root_attach_child`, `replace_node`",
          er.read_field_from_fields_table(table_report, "Trusted caller actions"),
          "read_field_from_fields_table: Trusted caller actions (placeholder symbols)")
# Case-insensitive label match (defensive: agents sometimes lowercase).
assert_eq("obeyed",
          er.read_field_from_fields_table(table_report, "caller contract"),
          "read_field_from_fields_table: case-insensitive label match")
# Absent label returns "" (not None, not crash).
assert_eq("",
          er.read_field_from_fields_table(table_report, "Cluster"),
          "read_field_from_fields_table: absent label → empty string")
# Non-existent file returns "" (defensive).
assert_eq("",
          er.read_field_from_fields_table(TMP / "no-such-file.md", "Boundary"),
          "read_field_from_fields_table: missing file → empty string")
# read_bare_field falls back to the table when bare label is absent.
assert_eq("obeyed",
          er.read_bare_field(table_report, "Caller contract"),
          "read_bare_field: table fallback for Caller contract")
assert_eq("call-sequence",
          er.read_bare_field(table_report, "Trigger source"),
          "read_bare_field: table fallback for Trigger source")
assert_eq("call-sequence: trusted caller adds, replaces, frees",
          er.read_bare_field(table_report, "Boundary"),
          "read_bare_field: table fallback for Boundary")
# read_confidence picks up Reproduction rate from the table when the
# bare-label form is absent.
fake_asan = TMP / "table-asan-empty.txt"
fake_asan.write_text("(no rate header)\n", encoding="utf-8")
assert_eq("5/5",
          er.read_confidence(table_report, fake_asan),
          "read_confidence: table fallback for Reproduction rate")

# read_confidence returns the MEASURED rate from a sanitizer.txt CRASH_RATE
# footer (the only sanitizer-derived source). The multi-run normalizer
# writes this footer for every sanitizer; reverification backfills it for
# model-direct one-shots.
measured_asan = TMP / "measured-crashrate.txt"
measured_asan.write_text(
    "==99==ERROR: AddressSanitizer: heap-use-after-free\n"
    "SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free\n"
    "CRASH_RATE: 3/5\n",
    encoding="utf-8",
)
assert_eq("3/5",
          er.read_confidence(None, measured_asan),
          "read_confidence: measured CRASH_RATE footer wins")

stale_rate_report = TMP / "stale-rate-report.md"
stale_rate_report.write_text("""\
# CRASH-STALE

## Fields

| Field             | Value |
|:------------------|:------|
| Reproduction rate | 5/5   |
""", encoding="utf-8")
assert_eq("3/5",
          er.read_confidence(stale_rate_report, measured_asan),
          "read_confidence: measured CRASH_RATE footer wins over stale report rate")

# A footer-less raw one-shot trace is NOT guessed — read_confidence returns
# "?" rather than fabricating a rate that was never measured. Reverification
# (not inference) is what supplies a real rate.
footerless_asan = TMP / "footerless-oneshot.txt"
footerless_asan.write_text(
    "==99==ERROR: AddressSanitizer: heap-use-after-free\n"
    "SUMMARY: AddressSanitizer: heap-use-after-free child.c:91 in child_free\n",
    encoding="utf-8",
)
assert_eq("?",
          er.read_confidence(None, footerless_asan),
          "read_confidence: footer-less one-shot trace is not guessed (stays '?')")

# 5c. Bare-label still wins when present (no regression for legacy form).
mixed_report = TMP / "mixed-report.md"
mixed_report.write_text("""\
# CRASH-T-2

## Fields

| Field           | Value          |
|:----------------|:---------------|
| Caller contract | unspecified    |

Caller contract: obeyed
""", encoding="utf-8")
assert_eq("obeyed",
          er.read_bare_field(mixed_report, "Caller contract"),
          "read_bare_field: bare label wins over table when both present")

with tempfile.TemporaryDirectory() as td:
    sev_report = Path(td) / "REPORT.md"
    sev_report.write_text(
        "- **Severity**: High (CVSS-BTE 4.0: 8.7 High; "
        "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N; primitive=x)\n",
        encoding="utf-8",
    )
    assert_eq("High (CVSS-BTE 4.0: 8.7)",
              er.read_severity_from(sev_report),
              "read_severity_from: preserves CVSS-BTE 4.0 score token")

    vector_only = Path(td) / "VECTOR_ONLY.md"
    vector_only.write_text(
        "- **Severity**: High (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)\n",
        encoding="utf-8",
    )
    assert_eq("High",
              er.read_severity_from(vector_only),
              "read_severity_from: does not treat vector version as score")

    # "None" is the CVSS band for a scored 0.0 (internal-surface code whose
    # modified impacts are all N) — a real level, not a missing one.
    none_report = Path(td) / "NONE_LEVEL.md"
    none_report.write_text(
        "- **Severity**: None (CVSS-BTE 4.0: 0.0 None; "
        "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
        "/E:P/CR:L/IR:L/AR:L/MVC:N/MVI:N/MVA:N; primitive=x)\n",
        encoding="utf-8",
    )
    assert_eq("None (CVSS-BTE 4.0: 0.0)",
              er.read_severity_from(none_report),
              "read_severity_from: scored-0.0 band None parsed")

# 5d. strip_audit_sections drops the agent's `## Fields` heading + table.
table_strip_input = """\
# CRASH-T-1

## Fields

| Field            | Value          |
|:-----------------|:---------------|
| Primitive        | heap-uaf       |
| Boundary         | input file     |
| Caller controls  | bytes          |
| Caller contract  | obeyed         |

## Summary
Body prose.
"""
# 5e. strip_audit_sections also strips a `## Fields` section that appears
# AFTER body prose (not in the H1 preamble). Some agents put a one-paragraph
# intro between the H1 and the Fields section — without this rule, the
# auto-header's `## Fields` plus the agent's leftover heading produce a
# duplicate `## Fields` in the bundled REPORT.md.
prose_then_fields_input = """\
# CRASH-X-3 — short title

ASan SEGV null-deref in foo.c. One-paragraph intro before
the structured fields.

## Fields

Boundary: catalog file bytes
Caller controls: file path
Caller contract: obeyed
Trigger source: bytes

## Reproduction

`./reproduce.sh`

## Root Cause

Body prose continues here.
"""
stripped_prose = er.strip_audit_sections(prose_then_fields_input)
assert_not_in("## Fields", stripped_prose,
              "strip_audit_sections (prose-then-fields): ## Fields heading dropped")
assert_not_in("Boundary: catalog file bytes", stripped_prose,
              "strip_audit_sections (prose-then-fields): Boundary bare-label dropped")
assert_not_in("Caller controls: file path", stripped_prose,
              "strip_audit_sections (prose-then-fields): Caller controls bare-label dropped")
assert_not_in("## Reproduction", stripped_prose,
              "strip_audit_sections (prose-then-fields): ## Reproduction dropped")
assert_in("ASan SEGV null-deref in foo.c.", stripped_prose,
          "strip_audit_sections (prose-then-fields): intro prose preserved")
assert_in("## Root Cause", stripped_prose,
          "strip_audit_sections (prose-then-fields): ## Root Cause preserved")
assert_in("Body prose continues here.", stripped_prose,
          "strip_audit_sections (prose-then-fields): body prose preserved")
# Idempotent.
stripped_prose_2 = er.strip_audit_sections(stripped_prose)
assert_eq(stripped_prose, stripped_prose_2,
          "strip_audit_sections (prose-then-fields): idempotent")

stripped_table = er.strip_audit_sections(table_strip_input)
assert_not_in("# CRASH-T-1", stripped_table,
              "strip_audit_sections (table form): h1 dropped")
assert_not_in("## Fields", stripped_table,
              "strip_audit_sections (table form): ## Fields heading dropped")
assert_not_in("| Primitive", stripped_table,
              "strip_audit_sections (table form): table rows dropped")
assert_not_in("| Boundary", stripped_table,
              "strip_audit_sections (table form): Boundary row dropped")
assert_in("## Summary", stripped_table,
          "strip_audit_sections (table form): ## Summary preserved")
assert_in("Body prose.", stripped_table,
          "strip_audit_sections (table form): narrative preserved")
# Idempotent: a second pass is a no-op.
stripped_table_2 = er.strip_audit_sections(stripped_table)
assert_eq(stripped_table, stripped_table_2,
          "strip_audit_sections (table form): idempotent")

# 5f. Narrative prose AFTER the `## Fields` table must survive.
#
# Why this test exists: some agents (notably weaker instruction-followers)
# write the root-cause narrative as loose prose right after their Fields
# table, under an H1 like `# Mechanism` or no heading at all — never under a
# canonical `## Summary` / `## Root Cause` H2. The old `## Fields` kill set a
# skip flag that only reset at the next H2, so that prose was swallowed whole
# (everything up to `## Reachability`), shipping a bundle with an empty body.
# The Fields kill must now eat ONLY the heading + table and stop at the first
# non-table line.
fields_then_prose_input = """\
Boundary: sqlite3
Strategy: S7

# Mechanism

## Fields

| Field     | Value     |
| :-------- | :-------- |
| Primitive | uaf_write |
| Severity  | Low (26)  |

A trusted caller frees the cached result object; the later write to it
is a use-after-free. This is the whole point of the report.

## Reachability — external callers

callers: 136

## Severity rationale

score=26
"""
rendered_body = er.render_agent_body(fields_then_prose_input)
assert_in("use-after-free. This is the whole point", rendered_body,
          "render_agent_body: narrative after Fields table preserved")
assert_not_in("| Primitive | uaf_write", rendered_body,
              "render_agent_body: Fields table still stripped (no duplicate)")
assert_not_in("| Severity  | Low (26)", rendered_body,
              "render_agent_body: Fields severity row stripped")
assert_not_in("callers: 136", rendered_body,
              "render_agent_body: Reachability section stripped")
assert_not_in("score=26", rendered_body,
              "render_agent_body: Severity rationale section stripped")
# The stray H1 is demoted to an H2 subsection (no second top-level heading).
assert_in("## Mechanism", rendered_body,
          "render_agent_body: stray body H1 demoted to H2")
assert_not_in("\n# Mechanism", "\n" + rendered_body,
              "render_agent_body: no bare H1 left in body")
# Idempotent.
assert_eq(rendered_body, er.render_agent_body(rendered_body),
          "render_agent_body: idempotent")

# 5g. demote_body_headings leaves headings inside fenced code blocks alone
# (a `# comment` in a shell snippet is not a Markdown heading).
fenced = "## Root Cause\n\n```sh\n# not a heading, a shell comment\necho hi\n```\n\n# Real Heading\n"
demoted = er.demote_body_headings(fenced)
assert_in("# not a heading, a shell comment", demoted,
          "demote_body_headings: fenced '# comment' untouched")
assert_not_in("## not a heading", demoted,
              "demote_body_headings: fenced comment not demoted")
assert_in("## Real Heading", demoted,
          "demote_body_headings: real body H1 demoted to H2")

# 5h. _body_has_prose distinguishes narrative from structured-only bodies.
assert_eq(True, er._body_has_prose("## Summary\n\nReal narrative line.\n"),
          "_body_has_prose: narrative detected")
assert_eq(False, er._body_has_prose("## Fields\n\n| A | B |\n| :- | :- |\n| x | y |\n"),
          "_body_has_prose: table-only body has no prose")
assert_eq(False, er._body_has_prose("Boundary: x\nSurface: y\n- **Severity**: 5\n"),
          "_body_has_prose: bare-label/severity-only body has no prose")

# 5i. recover_agent_prose (the auto-repair fallback) keeps narrative verbatim
# while dropping the auto-emitted sections, independent of strip's logic.
recovered = er.recover_agent_prose(
    "# CRASH-Z-1\n\n## Description\n\nThe defect is X.\n\n## Reachability\n\nc:9\n"
)
assert_in("The defect is X.", recovered,
          "recover_agent_prose: narrative kept")
assert_in("## Description", recovered,
          "recover_agent_prose: non-auto heading kept")
assert_not_in("CRASH-Z-1", recovered,
              "recover_agent_prose: crash-title H1 dropped")
assert_not_in("c:9", recovered,
              "recover_agent_prose: Reachability auto-section dropped")

# 5j. render_agent_body falls back to recovery when strip yields no prose.
# Guard against future strip regressions: if strip_audit_sections ever
# over-strips a body to headings-only, the original narrative is still
# surfaced rather than shipped empty.
_real_strip = er.strip_audit_sections
try:
    er.strip_audit_sections = lambda _t: "## Mechanism\n"  # simulate over-strip
    salvaged = er.render_agent_body("## Mechanism\n\nLoad-bearing narrative.\n")
    assert_in("Load-bearing narrative.", salvaged,
              "render_agent_body: fallback recovers prose when strip empties body")
finally:
    er.strip_audit_sections = _real_strip

# 5k. Location/bug-class labels an agent restates as loose lines after the
# Fields table are redundant with the auto table (Dedup frames = file:func:line,
# Primitive = bug class) and must be stripped from the body — never left as
# orphaned `Label: value` lines ahead of the narrative. The narrative stays.
restated_labels_input = """\
## Fields

| Field     | Value          |
| :-------- | :------------- |
| Primitive | heap-uaf       |

File: ext/misc/closure.c
Function: closureDequote
Line: 445
Bug Class: heap-buffer-overflow (read)
Class: memory-safety

The `closureDequote` function fails to null-terminate the output buffer.
"""
stripped_labels = er.render_agent_body(restated_labels_input)
for lab in ("File:", "Function:", "Line:", "Bug Class:", "Class:"):
    assert_not_in(lab, stripped_labels,
                  f"render_agent_body: restated `{lab}` label dropped from body")
assert_in("fails to null-terminate", stripped_labels,
          "render_agent_body: narrative kept after dropping restated labels")
assert_not_in("| Primitive", stripped_labels,
              "render_agent_body: Fields table still stripped")
assert_eq(False, er._body_has_prose("File: a.c\nFunction: f\nBug Class: uaf\n"),
          "_body_has_prose: a body of only restated labels has no prose")

# 5l. Duplicate sanitizer dumps. Agents copy the sanitizer output into the body
# under arbitrary headings (`## Observed`, `## ASan Evidence`, ...) or inside a
# narrative section; the bundle re-emits the authoritative `## Expected
# sanitizer output`, so the agent's copy must be dropped by CONTENT (the
# sanitizer signature in the fence), not by heading name. Surrounding prose and
# non-sanitizer code blocks stay.
dup_sanitizer_input = """\
## Observed (sanitizer.txt)

```
==123==ERROR: AddressSanitizer: stack-buffer-overflow on address 0xdead
    #0 0x1 in strcat
SUMMARY: AddressSanitizer: stack-buffer-overflow harness.c:59 in main
```

The write of 2001 bytes overflows the 500-byte `cmdbuf`.

## Patch

```c
strncat(cmdbuf, s, sizeof(cmdbuf) - strlen(cmdbuf) - 1);
```
"""
sd = er.render_agent_body(dup_sanitizer_input)
assert_not_in("AddressSanitizer", sd,
              "render_agent_body: duplicate sanitizer dump dropped from body")
assert_in("The write of 2001 bytes overflows", sd,
          "render_agent_body: prose around the sanitizer dump preserved")
assert_in("strncat(cmdbuf", sd,
          "render_agent_body: non-sanitizer (patch) code block kept")
assert_eq(sd, er.render_agent_body(sd),
          "render_agent_body: sanitizer-dedup is idempotent")
# strip_sanitizer_blocks in isolation: only the sanitizer fence goes.
only_blocks = er.strip_sanitizer_blocks(
    "```\nrun: ./reproduce.sh\n```\n\n```\nAddressSanitizer: heap-buffer-overflow\n```\n")
assert_in("run: ./reproduce.sh", only_blocks,
          "strip_sanitizer_blocks: keeps a non-sanitizer code block")
assert_not_in("AddressSanitizer", only_blocks,
              "strip_sanitizer_blocks: drops the sanitizer code block")

# 5m. A heading that restates the crash id/title (the bundle supplies the real
# `# CRASH-NNNN: ...` title) is dropped; its body content stays.
dup_title_input = """\
## Classification

## CRASH-1: heap-buffer-overflow in the decimal extension

### Trigger

A crafted decimal literal.
"""
dt = er.render_agent_body(dup_title_input)
assert_not_in("CRASH-1:", dt,
              "render_agent_body: restated CRASH-id title heading dropped")
assert_in("A crafted decimal literal.", dt,
          "render_agent_body: body under the restated title preserved")
assert_in("Trigger", dt,
          "render_agent_body: subsection headings under the title preserved")

# 5n. Headingless narrative gets a canonical `## Summary`. Agents (esp. freeform
# model-direct) often write the whole writeup as bare prose with no heading, or
# the only heading they wrote restated the crash title (dropped above). Either
# way the narrative must not render without a section heading.
noheading_input = """\
## Fields

| Field     | Value          |
| :-------- | :------------- |
| Primitive | heap-uaf       |

ASan confirms a heap-buffer-overflow in closureDequote when a caller passes
a malformed bracket-quoted argument.
"""
nh = er.render_agent_body(noheading_input)
assert nh.lstrip().startswith("## Summary"), \
    f"render_agent_body: headingless narrative gets a ## Summary heading (got {nh[:40]!r})"
assert_in("ASan confirms a heap-buffer-overflow", nh,
          "render_agent_body: the narrative itself is preserved under the heading")
assert_eq(nh, er.render_agent_body(nh),
          "render_agent_body: heading insertion is idempotent")
# A body that already leads with a heading is NOT given a second one.
headed = er.render_agent_body("## Root Cause\n\nThe parser overflows the stack buffer here.\n")
assert_not_in("## Summary", headed,
              "render_agent_body: no spurious ## Summary when body already has a heading")
# A Strategy: metadata line is skipped, not treated as the narrative.
strat = er.render_agent_body("Strategy: S5\n\nThe overflow occurs because the loop never bounds-checks.\n")
assert strat.count("## Summary") == 1 and "Strategy: S5" in strat, \
    "render_agent_body: Strategy line kept, Summary heads the real narrative"
# A body with no narrative at all gets no heading (nothing to head).
assert_not_in("## Summary", er.render_agent_body("## Fields\n\n| A | B |\n| :- | :- |\n| x | y |\n"),
              "render_agent_body: no ## Summary when there is no narrative")
# A leading `<!-- enrich:NAME -->...<!-- /enrich:NAME -->` block is harness-owned
# metadata (lib/report_enrich.py prepends it; bin/render-md renders it as the
# hero/snippet cards), not agent narrative. The inserted ## Summary must land
# AFTER the block, before the real prose — otherwise the comment marker becomes
# the first paragraph of Summary and bin/render-md's hero escapes it into the
# triage panel (`<!-- enrich:tldr --> Reviewer TL;DR`).
enrich_lead = er.render_agent_body(
    "<!-- enrich:tldr -->\n**Reviewer TL;DR**\n\n- Trigger — caller bytes\n"
    "<!-- /enrich:tldr -->\n\n"
    "`decode()` copies past the end of a short serialized buffer.\n")
assert enrich_lead.count("## Summary") == 1, \
    f"render_agent_body: exactly one ## Summary for enrich-led body (got {enrich_lead!r})"
assert enrich_lead.index("<!-- enrich:tldr -->") < enrich_lead.index("## Summary") \
    < enrich_lead.index("`decode()`"), \
    "render_agent_body: ## Summary sits after the enrich block, before the prose"
assert_eq(enrich_lead, er.render_agent_body(enrich_lead),
          "render_agent_body: enrich-led heading placement is idempotent")
# Multiple stacked enrich blocks (cluster-siblings + tldr + severity-badge) are
# all skipped; the heading still heads the first real prose line, exactly once.
multi_enrich = er.render_agent_body(
    "<!-- enrich:cluster-siblings -->\n**Cluster siblings**: 1 other\n<!-- /enrich:cluster-siblings -->\n\n"
    "<!-- enrich:tldr -->\n**Reviewer TL;DR**\n<!-- /enrich:tldr -->\n\n"
    "<!-- enrich:severity-badge -->\nSeverity: Low\n<!-- /enrich:severity-badge -->\n\n"
    "Strategy: S7\n\n"
    "The reference string is rendered as a NUL-terminated C string and overruns.\n")
assert multi_enrich.count("## Summary") == 1, \
    f"render_agent_body: one ## Summary across stacked enrich blocks (got {multi_enrich!r})"
assert "Strategy: S7" in multi_enrich and \
    multi_enrich.index("## Summary") < multi_enrich.index("The reference string"), \
    "render_agent_body: heading heads the real prose after stacked enrich + Strategy metadata"
# An orphan metadata line (`Linked FIND:`, a recon cross-reference) above the
# agent's OWN `## Summary` must not trigger a second inserted `## Summary` —
# the body is already headed under Summary. Without the guard, the orphan line
# reads as the first unheaded narrative and the bundle grows a duplicate
# heading (`## Summary` … Strategy … `## Summary`).
orphan_before_summary = er.render_agent_body(
    "Strategy: S7\n\n"
    "Linked FIND: `FIND-RECON-deadbeef-some-finding`\n\n"
    "## Summary\n\n"
    "`add_item_to_array` accepts an item already linked into another array.\n")
assert orphan_before_summary.count("## Summary") == 1, \
    f"render_agent_body: no duplicate ## Summary when body already has one (got {orphan_before_summary!r})"
assert "Linked FIND:" in orphan_before_summary and "Strategy: S7" in orphan_before_summary, \
    "render_agent_body: orphan metadata lines are preserved, not dropped"
assert_eq(orphan_before_summary, er.render_agent_body(orphan_before_summary),
          "render_agent_body: existing-Summary guard is idempotent")

# 5o. Robustness hardening — narrative must never be lost to over-eager rules.
# (a) A sentence that begins with a label word is narrative, not a restated
#     field — keep it. Real single-token restatements still go.
labels_prose = er.render_agent_body(
    "## Summary\n\nFile: the parser reads one element past the end of buf.\n"
    "Class: this is an instance of a broader unchecked-length pattern.\n")
assert_in("the parser reads one element past", labels_prose,
          "5o-a: narrative sentence starting 'File:' is kept")
assert_in("broader unchecked-length pattern", labels_prose,
          "5o-a: narrative sentence starting 'Class:' is kept")
assert_not_in("ext/misc/closure.c", er.render_agent_body("## Summary\n\nx\n\nFile: ext/misc/closure.c\n"),
              "5o-a: single-token File: restatement still dropped")

# (b) An UNCLOSED sanitizer fence must not swallow the rest of the document.
unclosed = er.render_agent_body(
    "## Observed\n\n```\n==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
    "## Root Cause\n\nThe real narrative that explains the bug.\n")
assert_in("real narrative that explains", unclosed,
          "5o-b: narrative after an unclosed sanitizer fence is preserved")

# (c) A non-sanitizer code block that merely MENTIONS a sanitizer / 'runtime
#     error:' is kept; a real dump is dropped.
mention = er.render_agent_body(
    "## Summary\n\n```c\n// guard against the runtime error: divide by zero\n"
    "if (d) q = n / d;\n```\n")
assert_in("divide by zero", mention,
          "5o-c: code block merely mentioning 'runtime error:' is kept")
assert_in("q = n / d;", mention, "5o-c: its code is kept")
realdump = er.render_agent_body(
    "## Observed\n\n```\n    #0 0x55 in foo bar.c:9\nSUMMARY: AddressSanitizer: heap-buffer-overflow\n```\n\nNote.\n")
assert_not_in("AddressSanitizer", realdump, "5o-c: a real sanitizer dump is still dropped")

# (d) `## CRASH-<word>` (a real heading) is kept; only `CRASH-<digit>` ids drop.
assert_in("CRASH-resistant", er.render_agent_body("## CRASH-resistant design\n\nNarrative.\n"),
          "5o-d: a 'CRASH-word' heading is not mistaken for a crash-id title")
assert_not_in("CRASH-2", er.render_agent_body("## CRASH-2: heap overflow in foo\n\nNarrative.\n"),
              "5o-d: a 'CRASH-<digit>' restated title is dropped")

# (e) Auto-emitted sections written as an H1 (`# Reproduction`, `# Reachability`)
#     are killed like their H2 form — no duplicate section leaks, and the
#     result is idempotent.
h1dup = er.render_agent_body(
    "# Reproduction\n\n1. call foo()\n2. call bar()\n\n# Root Cause\n\nThe pointer is freed early.\n")
assert_not_in("call foo()", h1dup, "5o-e: an H1 '# Reproduction' section is dropped")
assert_in("The pointer is freed early", h1dup, "5o-e: the narrative section is kept")
assert_eq(h1dup, er.render_agent_body(h1dup), "5o-e: H1-section handling is idempotent")

cpp_harness_dir = TMP / "cpp-harness"
cpp_harness_dir.mkdir()
(cpp_harness_dir / "harness.cpp").write_text("#include <iostream>\nint main(int,char**){return 0;}\n",
                                             encoding="utf-8")
found_cpp = er.find_harness([cpp_harness_dir])
assert_eq("harness.cpp", found_cpp.name if found_cpp else "",
          "find_harness: discovers C++ harness source")


# 5f. C-harness reproduce.sh handles missing / placeholder asan_lib.
#
# Regression: when output/<slug>/target.toml carries the FILL_ME
# placeholder (or asan_lib is unset entirely — e.g. header-only C++
# libs), reproduce.sh used to be emitted with a broken
# `asan_lib="$build/FILL_ME.a"` resolve block and `"$asan_lib"` literally
# spliced into the link line. Running it failed with "ASan static
# library not found". The fix: skip the resolve block AND drop the
# `"$asan_lib"` arg when asan_lib is unset or contains FILL_ME, and warn
# loudly on FILL_ME so users notice the stale config.

# Case A: asan_lib set to a real path → unchanged behavior.
harness_dir_a = TMP / "harness-lib-set"
harness_dir_a.mkdir()
repro_a = harness_dir_a / "reproduce.sh"
er.write_c_harness_template(
    repro_a, build_system="cmake", upstream_url="https://x/y",
    pinned_rev="abc", slug="x", san_bin_rel="build-asan/foo",
    san_lib_rel="build-asan/libfoo.a",
    includes_args=' -I "$src/include"', link_libs=" -lm -lpthread",
    input_name="input.bin", harness_name="harness.c", harness_compiler="clang",
)
text_a = repro_a.read_text(encoding="utf-8")
assert_in('san_lib="$build"/libfoo.a', text_a,
          "c-harness asan_lib SET: emits asan_lib resolve block")
assert_in('"$here/harness.c" ${san_lib:+"$san_lib"} ${san_lib_dir:+-Wl,-rpath,"$san_lib_dir"} -lm -lpthread', text_a,
          'c-harness asan_lib SET: link line gates "$san_lib" + rpath on non-empty san_lib')
assert_in('san_lib_dir="${san_lib%/*}"', text_a,
          "c-harness asan_lib SET: derives lib dir for loader hints")
assert_in('export LD_LIBRARY_PATH="$san_lib_dir', text_a,
          "c-harness asan_lib SET: env block exports LD_LIBRARY_PATH")
assert_in('export DYLD_LIBRARY_PATH="$san_lib_dir', text_a,
          "c-harness asan_lib SET: env block exports DYLD_LIBRARY_PATH for macOS")
assert_in('if [ -n "$san_lib_dir" ]; then', text_a,
          "c-harness asan_lib SET: env block guarded by san_lib_dir non-empty test")
assert_in("quarantine_size_mb=256:redzone=64", text_a,
          "c-harness ASan defaults: reproducer keeps run-asan redzone/quarantine")
# Header-only placeholder degrade: LIB_RESOLVE no longer hard-exits when
# every fallback misses. The block blanks `san_lib` + `san_lib_dir` so
# the `${san_lib:+...}` link-line expansion drops the archive (and the
# rpath flag) cleanly. Real header-only libraries whose audit-time anchor
# archive doesn't reproduce on a fresh maintainer build need exactly
# this graceful path.
assert_in('WARNING:', text_a,
          "c-harness LIB_RESOLVE: degrades to warning when archive missing")
assert_in('san_lib=""', text_a,
          "c-harness LIB_RESOLVE: blanks san_lib so link-line expansion drops it")
assert_not_in('static library not found:" >&2; exit 2', text_a,
              "c-harness LIB_RESOLVE: no longer exits 2 on missing archive")

# Case B: asan_lib empty → the reproducer discovers the instrumented
# library the build just produced and links it through the same guarded
# ${san_lib:+...} expansion. A genuinely header-only target finds nothing,
# and the guard then drops the archive cleanly — so the link line stays
# well-formed either way.
harness_dir_b = TMP / "harness-lib-empty"
harness_dir_b.mkdir()
repro_b = harness_dir_b / "reproduce.sh"
er.write_c_harness_template(
    repro_b, build_system="cmake", upstream_url="https://x/y",
    pinned_rev="abc", slug="x", san_bin_rel="build-asan/foo",
    san_lib_rel="",
    includes_args=' -I "$src/include"', link_libs=" -lm -lpthread -lc++",
    input_name="input.bin", harness_name="harness.cpp", harness_compiler="clang++",
)
text_b = repro_b.read_text(encoding="utf-8")
assert_in("linking auto-discovered library", text_b,
          "c-harness asan_lib EMPTY: emits library-discovery block")
assert_in("-type f -name '*.a'", text_b,
          "c-harness asan_lib EMPTY: discovery scans $build for the library")
assert_in("-iname tests", text_b,
          "c-harness asan_lib EMPTY: discovery prunes CMakeFiles/test/_deps helper archives")
assert_in('${san_lib:+"$san_lib"}', text_b,
          'c-harness asan_lib EMPTY: link line links the discovered lib when present')
assert_in('${san_lib_dir:+-Wl,-rpath,"$san_lib_dir"}', text_b,
          'c-harness asan_lib EMPTY: rpath flag guarded by discovered san_lib_dir')
assert_in('export LD_LIBRARY_PATH="$san_lib_dir', text_b,
          'c-harness asan_lib EMPTY: loader path exported when a lib is discovered')
assert_in('${san_lib_dir:+-Wl,-rpath,"$san_lib_dir"} -lm -lpthread -lc++', text_b,
          "c-harness asan_lib EMPTY: configured link_libs still follow the lib")

# Case C: asan_lib still carries FILL_ME placeholder → same discovery
# emission as empty, plus a stderr warning so the user knows the field was
# never filled and discovery is being relied on.
harness_dir_c = TMP / "harness-lib-fillme"
harness_dir_c.mkdir()
repro_c = harness_dir_c / "reproduce.sh"
err_buf = io.StringIO()
with contextlib.redirect_stderr(err_buf):
    er.write_c_harness_template(
        repro_c, build_system="cmake", upstream_url="https://x/y",
        pinned_rev="abc", slug="x", san_bin_rel="build-asan/foo",
        san_lib_rel="build-asan/FILL_ME.a",
        includes_args=' -I "$src/include"', link_libs=" -lm -lpthread",
        input_name="input.bin", harness_name="harness.c", harness_compiler="clang",
    )
text_c = repro_c.read_text(encoding="utf-8")
# Guard the specific leak: the placeholder library PATH (build-asan/FILL_ME.a)
# must never reach a resolve/link line — discovery replaces it. We can't assert
# the bare token "FILL_ME" is absent because the generic preamble now matches it
# as a clone-skip sentinel (URL=FILL_ME → local-only target), so the word
# legitimately appears in the case guard / its comment.
assert_not_in("FILL_ME.a", text_c,
              "c-harness asan_lib FILL_ME: placeholder library path never reaches output")
assert_in("linking auto-discovered library", text_c,
          "c-harness asan_lib FILL_ME: emits library-discovery block")
assert_in("FILL_ME", err_buf.getvalue(),
          "c-harness asan_lib FILL_ME: stderr warns about stale placeholder")

# Case D: non-ASan harnesses use the selected sanitizer flag, lib, and env.
harness_dir_d = TMP / "harness-ubsan"
harness_dir_d.mkdir()
repro_d = harness_dir_d / "reproduce.sh"
er.write_c_harness_template(
    repro_d, build_system="cmake", upstream_url="https://x/y",
    pinned_rev="abc", slug="x", san_bin_rel="build-ubsan/foo",
    san_lib_rel="build-ubsan/libfoo.a",
    includes_args=' -I "$src/include"', link_libs=" -lm",
    input_name="input.bin", harness_name="harness.c", harness_compiler="clang",
    sanitizer="ubsan", extra_options="report_error_type=1",
)
text_d = repro_d.read_text(encoding="utf-8")
assert_in("-fsanitize=undefined", text_d,
          "c-harness UBSan: compile line uses undefined sanitizer")
assert_in('san_lib="$build"/libfoo.a', text_d,
          "c-harness UBSan: resolves build-ubsan lib under repro build")
assert_in("UBSAN_OPTIONS=", text_d,
          "c-harness UBSan: sets UBSAN_OPTIONS")
assert_in("print_stacktrace=1:halt_on_error=1:print_summary=1", text_d,
          "c-harness UBSan: replay keeps run-ubsan generic defaults")
assert_in("report_error_type=1", text_d,
          "c-harness UBSan: target ubsan_options included")
assert_not_in("ASAN_OPTIONS=", text_d,
              "c-harness UBSan: does not set ASAN_OPTIONS")

# emit_lib_resolve unit checks — directly exercise the helper.
assert_eq("", er.emit_lib_resolve(""),
          "emit_lib_resolve: empty input → empty block")
assert_eq("", er.emit_lib_resolve("build-asan/FILL_ME.a"),
          "emit_lib_resolve: FILL_ME placeholder → empty block")
assert_in('san_lib="$build"/libfoo.a',
          er.emit_lib_resolve("build-asan/libfoo.a"),
          "emit_lib_resolve: real path → emits resolve block")
zlib_resolve = er.emit_lib_resolve("build-asan/lib/libz.a")
assert_in('san_lib="$build"/lib/libz.a', zlib_resolve,
          "emit_lib_resolve: preserves configured lib/ path first")
assert_in('san_lib_name="${san_lib##*/}"', zlib_resolve,
          "emit_lib_resolve: computes archive basename")
assert_in('find "$build" \\( -type f -o -type l \\) -name "$san_lib_name"', zlib_resolve,
          "emit_lib_resolve: searches fresh build tree by archive basename (accepts symlinks)")
assert_in('match_count=', zlib_resolve,
          "emit_lib_resolve: counts basename matches")
assert_in('ASan static library name is ambiguous', zlib_resolve,
          "emit_lib_resolve: rejects ambiguous archive basename matches")

assert_eq(' -I "$src"/. -I "$src"/contrib/minizip -I "$build"/include -I "$build"',
          er.emit_include_args([".", "contrib/minizip", "build-asan/include"]),
          "emit_include_args: build-asan/include maps to fresh build dir")

# rewrite_harness_repo_paths — strip audit-machine repo prefixes from
# `#include` directives so the bundled harness resolves against $src.
# Each case below documents one shape of mistake the agent can make.
assert_eq('#include "cJSON_Utils.c"',
          er.rewrite_harness_repo_paths('#include "targets/cjson/cJSON_Utils.c"'),
          "rewrite_harness_repo_paths: targets/<slug>/ prefix stripped")
assert_eq('#include "include/curl/curl.h"',
          er.rewrite_harness_repo_paths('#include "targets/curl/include/curl/curl.h"'),
          "rewrite_harness_repo_paths: preserves nested in-source path under target")
assert_eq('#include <bar.h>',
          er.rewrite_harness_repo_paths('#include <targets/foo/bar.h>'),
          "rewrite_harness_repo_paths: handles angle-bracket include form")
assert_eq('#include "cJSON.h"',
          er.rewrite_harness_repo_paths('#include "/abs/audit/host/targets/cjson/cJSON.h"'),
          "rewrite_harness_repo_paths: absolute path with embedded targets/ prefix stripped")
assert_eq('#include "scratch/x.h"',
          er.rewrite_harness_repo_paths('#include "output/cjson/scratch/x.h"'),
          "rewrite_harness_repo_paths: output/<slug>/ prefix stripped too")
assert_eq('#include "cJSON.h"',
          er.rewrite_harness_repo_paths('#include "cJSON.h"'),
          "rewrite_harness_repo_paths: bundle-local include passes through")
assert_eq('#include <stdio.h>',
          er.rewrite_harness_repo_paths('#include <stdio.h>'),
          "rewrite_harness_repo_paths: system header passes through")
assert_eq('#include "libcurl/foo.h"',
          er.rewrite_harness_repo_paths('#include "libcurl/foo.h"'),
          "rewrite_harness_repo_paths: non-prefixed path passes through")
# Multi-line: only the targeted lines get rewritten; everything else is verbatim.
_multi_in = (
    '#include <stdio.h>\n'
    '#include "targets/cjson/cJSON.h"\n'
    'int main(void) { return 0; }\n'
)
_multi_out = (
    '#include <stdio.h>\n'
    '#include "cJSON.h"\n'
    'int main(void) { return 0; }\n'
)
assert_eq(_multi_out, er.rewrite_harness_repo_paths(_multi_in),
          "rewrite_harness_repo_paths: multi-line preserves non-include content verbatim")


# 6. Shared testcase discovery used by export-repro.
tc_crash = TMP / "tc-crash"
tc_crash.mkdir()
(tc_crash / "notes.txt").write_text("this is long enough to be metadata, not a testcase\n",
                                    encoding="utf-8")
(tc_crash / "input.txt").write_text("list " + ("A" * 64), encoding="utf-8")
pick = er.find_testcase([tc_crash], tc_crash, tc_crash / ".audit")
assert_eq("input.txt", pick.name if pick else None,
          "find_testcase: canonical input.txt is accepted")

# Relaxed last-resort: a real text reproducer under a non-canonical name is
# found rather than lost; a prose-named .txt alone is still not a testcase.
tc_payload = TMP / "tc-payload"
tc_payload.mkdir()
(tc_payload / "payload.txt").write_text("non-canonical reproducer " + ("A" * 64),
                                        encoding="utf-8")
pick = er.find_testcase([tc_payload], tc_payload, tc_payload / ".audit")
assert_eq("payload.txt", pick.name if pick else None,
          "find_testcase: non-canonical payload.txt found via relaxed pass")

tc_prose = TMP / "tc-prose"
tc_prose.mkdir()
(tc_prose / "notes.txt").write_text("just some prose about the crash\n" * 4,
                                    encoding="utf-8")
pick = er.find_testcase([tc_prose], tc_prose, tc_prose / ".audit")
assert_eq(None, pick.name if pick else None,
          "find_testcase: prose-named notes.txt alone is not a testcase")

tc_header = TMP / "tc-header"
tc_header.mkdir()
scratch = TMP / "scratch-1"
scratch.mkdir()
(scratch / "from-header.txt").write_text("H" * 32, encoding="utf-8")
(tc_header / "asan.txt").write_text(
    f"ASAN_RUN_HEADER: runs=5 mode=generic testcase={scratch / 'from-header.txt'} started=x\n"
    "ERROR: AddressSanitizer: stack-buffer-overflow\n",
    encoding="utf-8",
)
pick = er.find_testcase([tc_header], tc_header, tc_header / ".audit")
assert_eq("from-header.txt", pick.name if pick else None,
          "find_testcase: ASAN_RUN_HEADER testcase fallback is accepted")

# 6a0. Regression for CRASH-0010.20260531: ASAN_RUN_HEADER points at the
# scratch path that crashed, but scratch dirs can be reused before the bundle
# is exported. If .audit/testcase.* was preserved with the crash, it is the
# immutable source of truth and must beat an existing-but-stale scratch path.
tc_header_stale = TMP / "tc-header-stale"
tc_header_stale.mkdir()
audit_header_stale = tc_header_stale / ".audit"
audit_header_stale.mkdir()
scratch_stale = TMP / "scratch-stale"
scratch_stale.mkdir()
(scratch_stale / "testcase.xml").write_text("<stale />\n", encoding="utf-8")
(audit_header_stale / "testcase.xml").write_text("<crashing />\n", encoding="utf-8")
(tc_header_stale / "sanitizer.txt").write_text(
    f"ASAN_RUN_HEADER: runs=5 mode=generic testcase={scratch_stale / 'testcase.xml'} started=x\n"
    "ERROR: AddressSanitizer: heap-use-after-free\n",
    encoding="utf-8",
)
pick = er.find_testcase([audit_header_stale, tc_header_stale], tc_header_stale, audit_header_stale)
assert_eq(str(audit_header_stale / "testcase.xml"), str(pick) if pick else None,
          "find_testcase: .audit testcase beats stale ASAN_RUN_HEADER scratch path")

# 6a. Regression for CRASH-002-1.20260509: when .audit/ holds the
# reachability prose summary that lib/triage.sh writes
# (.audit/reachability.out) AND the crash dir has the real testcase, the
# selector picked reachability.out by alphabetic order, export-repro
# staged it as input.out, and the bundled reproduce.sh fed prose to the
# harness → silent zero-output run that looked like the bug had vanished.
# After the fix: .out / .err suffixes are audit-internal artifacts and
# never qualify as testcases.
tc_reach = TMP / "tc-reachability"
tc_reach.mkdir()
audit_reach = tc_reach / ".audit"
audit_reach.mkdir()
(audit_reach / "reachability.out").write_text(
    "Reachability for: foo, bar\n  External callers (genuine):  42\n"
    "  sourcegraph status=ok          hits=10\n"
    "Severity: Medium (score=31/100)\n", encoding="utf-8",
)
(audit_reach / "reachability.err").write_text("debug noise\n", encoding="utf-8")
# The scratch testcase the ASan header originally pointed at is gone
# (this is the production scenario — scratch dirs get reset between
# audits), so the selector must fall back to the crash dir.
(tc_reach / "asan.txt").write_text(
    "ASAN_RUN_HEADER: testcase=output/gone/missing.txt\n"
    "ERROR: AddressSanitizer: heap-use-after-free\n",
    encoding="utf-8",
)
(tc_reach / "input.txt").write_text('{"old":"x","value":"y","stop":true,"repeats":2}\n',
                                    encoding="utf-8")
pick = er.find_testcase([audit_reach, tc_reach], tc_reach, audit_reach)
assert_eq("input.txt", pick.name if pick else None,
          "find_testcase: .audit/reachability.out is NOT picked over input.txt")

# 6b. Stale `input.out` (left behind by a prior buggy bundle) next to
# the correct `input.txt` must also be skipped — the .out suffix filter
# applies to the crash dir scan, not just .audit/.
tc_stale = TMP / "tc-stale-input-out"
tc_stale.mkdir()
(tc_stale / "input.out").write_text("Reachability for: leftover\n", encoding="utf-8")
(tc_stale / "input.txt").write_text('{"value":"z","stop":true}\n', encoding="utf-8")
pick = er.find_testcase([tc_stale], tc_stale, tc_stale / ".audit")
assert_eq("input.txt", pick.name if pick else None,
          "find_testcase: stale input.out alongside input.txt is rejected")

# 6c. Sanitizer sidecars with non-ASan suffixes must not be selected as input.
tc_ubsan_sidecar = TMP / "tc-ubsan-sidecar"
tc_ubsan_sidecar.mkdir()
(tc_ubsan_sidecar / "input.ubsan.txt").write_text(
    "parser.c:77:5: runtime error: index 4 out of bounds\n", encoding="utf-8",
)
(tc_ubsan_sidecar / "input.txt").write_text('{"value":"san"}\n', encoding="utf-8")
pick = er.find_testcase([tc_ubsan_sidecar], tc_ubsan_sidecar, tc_ubsan_sidecar / ".audit")
assert_eq("input.txt", pick.name if pick else None,
          "find_testcase: UBSan sidecar is not selected over input.txt")

# 6d. Harness source files (e.g. .audit/to_json_throwing_string_harness.cpp)
# must not be selected as testcases. When the .audit/ dir has the
# agent-named harness next to the actual testcase whose name doesn't
# match a TESTCASE_PREFIX (the .txt-gate rejects it), the selector used
# to fall through and pick the .cpp. export-repro would then stage it as
# `input.cpp` and the bundled reproduce.sh would compile the harness
# twice and feed source code as its own input.
tc_harness = TMP / "tc-harness-source"
audit_h = tc_harness / ".audit"
audit_h.mkdir(parents=True)
(audit_h / "to_json_throwing_string_harness.cpp").write_text(
    "#include <cstdio>\nint main(int argc, char** argv) { return 0; }\n",
    encoding="utf-8",
)
(audit_h / "to-json-throwing-string-basic.txt").write_text(
    '{"value":"x"}\n', encoding="utf-8",
)
(tc_harness / "input.txt").write_text('{"value":"y"}\n', encoding="utf-8")
pick = er.find_testcase([audit_h, tc_harness], tc_harness, audit_h)
assert_eq("input.txt", pick.name if pick else None,
          "find_testcase: harness .cpp with main() is not selected as testcase")

# 6e. Self-contained `reproducer.c` IS still a testcase (matches a
# TESTCASE_PREFIX, so the main()-source heuristic must not reject it).
# This guards the existing tests/test_triage.sh behavior.
tc_repro_c = TMP / "tc-reproducer-c"
tc_repro_c.mkdir()
(tc_repro_c / "reproducer.c").write_text(
    "int main(void) { return 0; }\n", encoding="utf-8",
)
pick = er.find_testcase([tc_repro_c], tc_repro_c, tc_repro_c / ".audit")
assert_eq("reproducer.c", pick.name if pick else None,
          "find_testcase: reproducer.c with main() is still a valid testcase")


# ─── End-to-end run against a fabricated crash dir ──────────────────

# Build a fake target tree + session env + crash dir + minimal .toml.
target_root = TMP / "fake-target"
output_root = TMP / "output" / "exr-py-test"
if output_root.exists():
    shutil.rmtree(output_root)
output_root.mkdir(parents=True)
target_root.mkdir(parents=True)

(output_root / "target.toml").write_text("""\
slug = "exr-py-test"
upstream_url = "https://example.com/repo"
build_system = "cmake"
pinned_rev = "abc123"
asan_bin = "build-asan/demo"
asan_lib = "build-asan/libdemo.a"
includes = ["include"]
link_libs = ["-lm"]
is_browser = "0"

[threat_model]
attacker_controls = ["bytes"]
""", encoding="utf-8")

results_dir = TMP / "results"
crash_dir = results_dir / "crashes" / "CRASH-X-1"
crash_dir.mkdir(parents=True)

(output_root / ".session-env").write_text(f"""\
RESULTS_DIR={results_dir}
TARGET_ROOT={target_root}
TARGET_SLUG=exr-py-test
TARGET_REV=abc123
LOGDIR={TMP}/logs
""", encoding="utf-8")

# Drop a minimal asan.txt + an audit-side report.md + a testcase.
(crash_dir / "asan.txt").write_text("""\
=== Run 1/5 ===
==11111==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xaaaa at pc 0xbbbb
READ of size 16 at 0xaaaa thread T0
[run-asan] generic runner timed out after 15s

=== Run 2/5 ===
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xbeef at pc 0xcafe
READ of size 16 at 0xbeef thread T0
    #0 0xdead in foo /src/foo.c:1
    #1 0xfeed in bar /src/bar.c:2
    #2 0xbead in baz /src/baz.c:3
    #3 0xabcd in main /src/main.c:1

0xbeef is located 0 bytes after 4-byte region [0xbeeb,0xbeef)
allocated by thread T0 here:
    #0 0xf00d in malloc (/lib/libasan.so+0x1234)
    #1 0xabcd in make_input /src/alloc.c:7
SUMMARY: AddressSanitizer: heap-buffer-overflow /src/foo.c:1 in foo
Shadow bytes around the buggy address:
  0x1234: fa fa
CRASH_RATE: 5/5
""", encoding="utf-8")
(crash_dir / "report.md").write_text("""\
# CRASH-X-1

## Summary
Test crash.

Trigger source: bytes
Boundary: input file
Caller controls: bytes
Parameter control: direct
Caller contract: obeyed
""", encoding="utf-8")
(crash_dir / "input.bin").write_bytes(b"\x41\x42\x43")

# Run the tool.
env = os.environ.copy()
result = subprocess.run(
    [str(ROOT / "bin" / "export-repro"), "CRASH-X-1"],
    capture_output=True, text=True, env=env, cwd=output_root,
)
ok = result.returncode == 0
assert_eq(0, result.returncode,
          f"export-repro exits 0 (stdout={result.stdout[-200:]!r} stderr={result.stderr[-200:]!r})")

if ok:
    # Assert bundle files exist.
    for f in ("REPORT.md", "reproduce.sh", "sanitizer.txt"):
        if (crash_dir / f).is_file():
            passed(f"end-to-end: {f} written")
        else:
            failed(f"end-to-end: {f} written")
    if (crash_dir / "input.bin").is_file():
        passed("end-to-end: input.bin preserved at root")
    else:
        failed("end-to-end: input.bin preserved at root")
    if (crash_dir / ".audit").is_dir():
        passed("end-to-end: .audit/ subdir created")
    else:
        failed("end-to-end: .audit/ subdir created")

    # report.md gets migrated into .audit/.
    if (crash_dir / ".audit" / "report.md").is_file():
        passed("end-to-end: original report.md migrated into .audit/")
    else:
        failed("end-to-end: original report.md migrated into .audit/")

    # REPORT.md content shape.
    report_text = (crash_dir / "REPORT.md").read_text(encoding="utf-8")
    assert_in("# CRASH-X-1", report_text, "end-to-end REPORT.md: h1 present")
    assert_in("## Fields", report_text, "end-to-end REPORT.md: ## Fields present")
    # Layout: the `## Summary` section leads the report, placed ABOVE the
    # Fields table (matching the finding-report layout). Field lookups read by
    # label, not position, so the reorder is purely cosmetic.
    if 0 <= report_text.find("## Summary") < report_text.find("## Fields"):
        passed("end-to-end REPORT.md: Summary section precedes Fields")
    else:
        failed("end-to-end REPORT.md: Summary section precedes Fields")
    assert_in("| Primitive", report_text, "end-to-end REPORT.md: Primitive row present")
    assert_in("Surface: ", report_text, "end-to-end REPORT.md: bare Surface label present")
    assert_in("Trigger source: bytes", report_text, "end-to-end REPORT.md: trigger source carried over")
    assert_in("Caller contract: obeyed", report_text, "end-to-end REPORT.md: caller contract carried over")
    assert_in("Parameter control: direct", report_text, "end-to-end REPORT.md: parameter control carried over")
    assert_in("Dedup frames", report_text, "end-to-end REPORT.md: dedup frames row present")
    assert_in("foo /src/foo.c:1 -> bar /src/bar.c:2 -> baz /src/baz.c:3",
              report_text, "end-to-end REPORT.md: top-three dedup frames present")
    assert_in("## Expected sanitizer output", report_text, "end-to-end REPORT.md: expected sanitizer block")
    assert_in("==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xbeef at pc 0xcafe",
              report_text, "end-to-end REPORT.md: raw ASan top line retained")
    assert_in("READ of size 16 at 0xbeef thread T0",
              report_text, "end-to-end REPORT.md: raw ASan access line retained")
    assert_in("allocated by thread T0 here:",
              report_text, "end-to-end REPORT.md: allocation stack section retained")
    assert_in("#1 0xabcd in make_input /src/alloc.c:7",
              report_text, "end-to-end REPORT.md: raw ASan stack section retained")
    assert_not_in("Shadow bytes around the buggy address:",
                  report_text, "end-to-end REPORT.md: shadow dump omitted from excerpt")
    assert_not_in("[run-asan] generic runner timed out",
                  report_text, "end-to-end REPORT.md: incomplete pre-summary run omitted")
    assert_in("Reproduction rate", report_text,
              "end-to-end REPORT.md: reproduction rate present")
    assert_in("5/5", report_text,
              "end-to-end REPORT.md: 5/5 from CRASH_RATE captured")
    assert_in("(set by bin/cluster-crashes)", report_text,
              "end-to-end REPORT.md: cluster placeholder present")

    # reproduce.sh content: cli-with-input template (cmake build, asan_bin resolve)
    repro = (crash_dir / "reproduce.sh").read_text(encoding="utf-8")
    assert_in("cmake -S \"$src\" -B \"$build\"", repro, "reproduce.sh: cmake build present")
    assert_in('"$san_bin" "$testcase"', repro, "reproduce.sh: runs $san_bin against $testcase")
    assert_in("input.bin", repro, "reproduce.sh: references input.bin")
    # Stream-visibility regression guards (see CRASH-002-1.20260509 incident):
    # reproduce.sh used to `exec` the binary, so the user got zero diagnostic
    # when the wrong input file was passed and the harness silently caught
    # the parse error. The script must now print a banner before the run
    # and surface the exit code so a no-op run is loud.
    assert_in('echo "=== running ASan repro:', repro,
              "reproduce.sh: prints running-testcase banner before invocation")
    assert_in("quarantine_size_mb=256:redzone=64", repro,
              "reproduce.sh: ASan CLI preserves run-asan redzone/quarantine defaults")
    assert_in('echo "[repro] exit=$rc"', repro,
              "reproduce.sh: prints exit code after the run")
    assert_not_in('exec "$san_bin"', repro,
                  "reproduce.sh: no bare 'exec' that hides exit status from the user")
    if os.access(crash_dir / "reproduce.sh", os.X_OK):
        passed("reproduce.sh: executable bit set")
    else:
        failed("reproduce.sh: executable bit set")

    # promotion.log got an entry.
    plog = crash_dir / ".audit" / "promotion.log"
    if plog.is_file() and "exported" in plog.read_text():
        passed("promotion.log: exported entry appended")
    else:
        failed("promotion.log: exported entry appended")


# ─── End-to-end with TABLE-FORMAT agent report ──────────────────────
#
# Why this test exists: the original end-to-end fixture above uses the
# legacy bare-label form (`Boundary: ...`). Recent agents put fields in
# a `## Fields` Markdown table instead. A regression in build_report_md
# / strip_audit_sections caused the auto Fields header to render with
# `—` for every caller field and `?` for Reproduction rate, while a
# duplicate `## Fields` table from the agent leaked through unstripped.
# This block asserts the harness handles both forms.

table_crash_dir = results_dir / "crashes" / "CRASH-T-1"
table_crash_dir.mkdir(parents=True)
(table_crash_dir / "asan.txt").write_text("""\
=== Run 1/5 ===
==22222==ERROR: AddressSanitizer: heap-use-after-free on address 0xc0de at pc 0xface
READ of size 8 at 0xc0de thread T0
    #0 0xdead in child_free /src/child.c:91
    #1 0xfeed in table_free /src/table.c:236
    #2 0xbead in root_free /src/root.c:868
    #3 0xabcd in main /src/harness.c:58
freed by thread T0 here:
    #0 0xdead in free
    #1 0xabcd in main /src/harness.c:55
previously allocated by thread T0 here:
    #0 0xf00d in malloc
    #1 0xabcd in child_alloc /src/child.c:123
SUMMARY: AddressSanitizer: heap-use-after-free /src/child.c:91 in child_free
CRASH_RATE: 5/5
""", encoding="utf-8")

# Agent's report.md uses the modern `## Fields` table form, NO bare-label
# duplicates below. This is exactly the shape that previously yielded
# empty `—` values + a duplicated Fields section in REPORT.html.
(table_crash_dir / "report.md").write_text("""\
# CRASH-T-1

## Fields

| Field                  | Value                                                     |
|:-----------------------|:----------------------------------------------------------|
| Primitive              | heap-use-after-free (read of size 8)                       |
| Severity               | TBD                                                        |
| Surface                | library-api — public tree-API entry points                 |
| Boundary               | call-sequence: trusted caller adds, replaces, frees        |
| Caller controls        | The call ordering and the entity name                      |
| Trusted caller actions | `root_new`, `root_attach_child`, `replace_node`           |
| Caller contract        | obeyed                                                     |
| Trigger source         | call-sequence                                              |
| Reproduction rate      | 5/5                                                        |

## Summary

Test summary body for table-form reports.

## Suggested fix

Mirror the unlink path.
""", encoding="utf-8")
(table_crash_dir / "input.bin").write_bytes(b"\x01\x02\x03")

result_t = subprocess.run(
    [str(ROOT / "bin" / "export-repro"), "CRASH-T-1"],
    capture_output=True, text=True, env=env, cwd=output_root,
)
assert_eq(0, result_t.returncode,
          f"export-repro (table form) exits 0 (stdout={result_t.stdout[-200:]!r} stderr={result_t.stderr[-200:]!r})")

if result_t.returncode == 0:
    report_t = (table_crash_dir / "REPORT.md").read_text(encoding="utf-8")

    # Single Fields section (no duplication of the agent's table).
    assert_eq(1, report_t.count("## Fields"),
              "table form REPORT.md: exactly one ## Fields section")

    # All required field rows are populated — no `—` placeholders, no `?`.
    required_rows = (
        "Trigger source",
        "Caller contract",
        "Boundary",
        "Caller controls",
        "Trusted caller actions",
        "Reproduction rate",
    )
    fields_block = report_t.split("## Fields", 1)[1].split("\n\n", 2)
    fields_table_text = "\n\n".join(fields_block[:2]) if fields_block else ""
    for label in required_rows:
        # Row exists.
        assert_in(f"| {label}", report_t,
                  f"table form REPORT.md: '{label}' row present")
        # Row is NOT empty (no `| Label ... | — |` and no `| ? |`).
        empty_re = re.compile(
            rf"^\|\s*{re.escape(label)}\s*\|\s*[—?]\s*\|\s*$",
            re.MULTILINE,
        )
        if empty_re.search(report_t):
            failed(f"table form REPORT.md: '{label}' row is non-empty",
                   f"row matched the empty pattern (— or ?)")
        else:
            passed(f"table form REPORT.md: '{label}' row is non-empty")

    # Specific values flow through from the agent's table to the auto-
    # generated header.
    assert_in("call-sequence", report_t,
              "table form REPORT.md: 'call-sequence' trigger flows through")
    assert_in("obeyed", report_t,
              "table form REPORT.md: 'obeyed' contract flows through")
    assert_in("trusted caller adds, replaces, frees", report_t,
              "table form REPORT.md: Boundary text flows through")
    assert_in("call ordering and the entity name", report_t,
              "table form REPORT.md: Caller controls text flows through")
    assert_in("root_attach_child", report_t,
              "table form REPORT.md: Trusted caller actions text flows through")
    # Reproduction rate populated, not '?'.
    assert_in("| Reproduction rate     | 5/5 |", report_t,
              "table form REPORT.md: Reproduction rate is 5/5 (not '?')")

    # Agent's body content survives.
    assert_in("Test summary body for table-form reports.", report_t,
              "table form REPORT.md: agent's Summary body preserved")
    assert_in("## Suggested fix", report_t,
              "table form REPORT.md: agent's Suggested fix preserved")
    assert_in("Mirror the unlink path.", report_t,
              "table form REPORT.md: agent's Suggested fix prose preserved")

    # ── Render REPORT.html and check the same fields are non-empty ──
    render_proc = subprocess.run(
        [str(ROOT / "bin" / "render-md"), "--html-sibling",
         str(table_crash_dir / "REPORT.md")],
        capture_output=True, text=True, env=env,
    )
    assert_eq(0, render_proc.returncode,
              f"render-md exits 0 (stderr={render_proc.stderr[-200:]!r})")
    html_path = table_crash_dir / "REPORT.html"
    if html_path.is_file():
        passed("table form REPORT.html: emitted by render-md")
        report_html = html_path.read_text(encoding="utf-8")
        # No row in the Fields table should render as just `—` or `?` for
        # the required fields. Match the rendered HTML row pattern:
        #   <td class="left">Boundary</td>
        #   <td class="left">—</td>
        for label in required_rows:
            empty_html_re = re.compile(
                rf'<td class="left">{re.escape(label)}</td>\s*'
                rf'<td class="left">\s*[—?]\s*</td>',
            )
            if empty_html_re.search(report_html):
                failed(f"table form REPORT.html: '{label}' row is non-empty",
                       "row rendered as empty (— or ?)")
            else:
                passed(f"table form REPORT.html: '{label}' row is non-empty")
        # Specific value assertions in the HTML.
        assert_in("obeyed", report_html,
                  "table form REPORT.html: 'obeyed' contract rendered")
        assert_in("call-sequence", report_html,
                  "table form REPORT.html: 'call-sequence' trigger rendered")
        assert_in("5/5", report_html,
                  "table form REPORT.html: '5/5' reproduction rate rendered")
        # No more than one fields-table is emitted (count of <th>Field</th>).
        # The collapsible Severity rationale section also has a Field-style
        # table header, so allow ≤2; the duplicate-bug variant produced ≥3.
        field_table_headers = report_html.count('<th class="left">Field</th>')
        if field_table_headers <= 1:
            passed("table form REPORT.html: single Fields table (no duplicate)")
        else:
            failed("table form REPORT.html: single Fields table (no duplicate)",
                   f"found {field_table_headers} '<th>Field</th>' occurrences")
    else:
        failed("table form REPORT.html: emitted by render-md",
               f"missing {html_path}")


# ─── End-to-end: cached reachability.json is replayed on re-bundle ──
#
# Regression: bin/export-repro rebuilds REPORT.md from the agent's
# report.md, which never carries the auto sections written by
# bin/reachability. Without the replay step a second bundle drops the
# `## Reachability — external callers` and `## Severity rationale`
# sections even though reachability.json is still on disk. This block
# fabricates that cached JSON and asserts the rebuilt REPORT.md picks
# it up via the --severity-only re-injection.

reach_crash_dir = results_dir / "crashes" / "CRASH-R-1"
reach_crash_dir.mkdir(parents=True)
(reach_crash_dir / "asan.txt").write_text("""\
=== Run 1/5 ===
==33333==ERROR: AddressSanitizer: heap-use-after-free on address 0xc0de at pc 0xface
READ of size 8 at 0xc0de thread T0
    #0 0xdead in child_free /src/child.c:91
    #1 0xfeed in table_free /src/table.c:236
    #2 0xbead in root_free /src/root.c:868
    #3 0xabcd in main /src/harness.c:58
SUMMARY: AddressSanitizer: heap-use-after-free /src/child.c:91 in child_free
CRASH_RATE: 5/5
""", encoding="utf-8")
(reach_crash_dir / "report.md").write_text("""\
# CRASH-R-1

## Summary

Reachability replay regression fixture.

Trigger source: call-sequence
Caller contract: obeyed
Boundary: trusted caller frees a node twice
Caller controls: bytes
""", encoding="utf-8")
(reach_crash_dir / "input.bin").write_bytes(b"\x01\x02\x03")

# Cached reachability.json from a prior successful probe. The values
# match the on-disk shape bin/reachability writes (see _format_reachability_section).
import json as _json
(reach_crash_dir / "reachability.json").write_text(_json.dumps({
    "queried_at": "2026-05-10T00:00:00+00:00",
    "symbols": ["child_free", "root_free"],
    "ignore": [],
    "external_callers": 7,
    "vendored_copies": 2,
    "services": {
        "sourcegraph": {"status": "ok", "count": 3, "vendored_count": 1, "errors": []},
        "gh": {"status": "ok", "count": 4, "vendored_count": 1, "errors": []},
    },
    "external_caller_hits": [
        {"repo": "github.com/example/proj-a", "path": "src/foo.c", "matched_symbol": "child_free"},
        {"repo": "github.com/example/proj-b", "path": "lib/bar.c", "matched_symbol": "root_free"},
    ],
    "vendored_copy_hits": [
        {"repo": "github.com/vendor/copy-a", "path": "deps/sampleproj/root.c"},
    ],
}, indent=2, sort_keys=True), encoding="utf-8")

result_r = subprocess.run(
    [str(ROOT / "bin" / "export-repro"), "CRASH-R-1"],
    capture_output=True, text=True, env=env, cwd=output_root,
)
assert_eq(0, result_r.returncode,
          f"export-repro (reachability replay) exits 0 "
          f"(stdout={result_r.stdout[-200:]!r} stderr={result_r.stderr[-200:]!r})")

if result_r.returncode == 0:
    report_r = (reach_crash_dir / "REPORT.md").read_text(encoding="utf-8")
    assert_in("## Reachability — external callers", report_r,
              "reachability replay: REPORT.md carries '## Reachability' section")
    assert_in("External callers (genuine", report_r,
              "reachability replay: callers count line emitted")
    assert_in("github.com/example/proj-a", report_r,
              "reachability replay: cached caller hits flow into REPORT.md")
    assert_in("## Severity rationale", report_r,
              "reachability replay: '## Severity rationale' section emitted")
    # reachability.json must remain at root (bundle filename, not migrated).
    if (reach_crash_dir / "reachability.json").is_file():
        passed("reachability replay: reachability.json kept at bundle root")
    else:
        failed("reachability replay: reachability.json kept at bundle root")

    # A second bundle must remain idempotent — the section is still
    # present (replay re-applies on every run; no duplication either).
    result_r2 = subprocess.run(
        [str(ROOT / "bin" / "export-repro"), "CRASH-R-1"],
        capture_output=True, text=True, env=env, cwd=output_root,
    )
    assert_eq(0, result_r2.returncode,
              f"export-repro (second pass) exits 0 "
              f"(stderr={result_r2.stderr[-200:]!r})")
    if result_r2.returncode == 0:
        report_r2 = (reach_crash_dir / "REPORT.md").read_text(encoding="utf-8")
        assert_in("## Reachability — external callers", report_r2,
                  "reachability replay: section preserved on second bundle")
        assert_eq(1, report_r2.count("## Reachability — external callers"),
                  "reachability replay: section not duplicated on second bundle")
        assert_eq(1, report_r2.count("## Severity rationale"),
                  "reachability replay: rationale not duplicated on second bundle")


# ─── write_stub_reproduce: fail-open bundle (no runnable template) ───
# Regression for the model-direct unification: export-repro used to
# die("could not determine template") for a self-contained harness
# (harness.c with main() but no separate testcase input), dropping the
# whole bundle — REPORT.md included. Now it writes a stub reproduce.sh
# and continues. The stub must be a valid shell script that exits
# non-zero (never mistaken for a working reproducer) and names the
# harness so a human knows how to reproduce by hand.
stub_dir = TMP / "stub-repro"
stub_dir.mkdir()
stub_path = stub_dir / "reproduce.sh"
er.write_stub_reproduce(
    stub_path, crash_id="CRASH-STUB-1", sanitizer="asan",
    harness_name="harness.c", input_name="",
    reason="self-contained harness, no separate testcase",
)
stub_text = stub_path.read_text(encoding="utf-8")
assert_in("#!/usr/bin/env bash", stub_text,
          "write_stub_reproduce: emits a bash shebang")
assert_in("exit 2", stub_text,
          "write_stub_reproduce: stub exits non-zero (not a real reproducer)")
assert_in("harness.c", stub_text,
          "write_stub_reproduce: names the harness for manual reproduction")
assert_eq(True, os.access(stub_path, os.X_OK),
          "write_stub_reproduce: stub is executable")
# No-harness variant: still valid, still exits 2, points at REPORT.md.
stub2 = stub_dir / "reproduce2.sh"
er.write_stub_reproduce(
    stub2, crash_id="CRASH-STUB-2", sanitizer="asan",
    harness_name="", input_name="", reason="no harness/testcase/wrapper captured",
)
stub2_text = stub2.read_text(encoding="utf-8")
assert_in("exit 2", stub2_text,
          "write_stub_reproduce: no-harness stub also exits non-zero")
assert_in("REPORT.md", stub2_text,
          "write_stub_reproduce: no-harness stub points at REPORT.md")


# ─── build_report_title: complete sentence, no dangling clause ───────
# The headline used to append "when <trigger>", which read as a fragment
# whenever the trigger was a bare noun ("... when bytes"). The trigger is
# already a Fields row, so the title must stay a clean, complete phrase.
_title = er.build_report_title(
    "CRASH-001-1", "stack-buffer-overflow",
    "sample_process_record parser.c:28", "bytes",
)
assert_eq("CRASH-001-1: stack-buffer-overflow in sample_process_record", _title,
          "build_report_title: no trailing 'when <trigger>' clause")
assert_eq(False, " when " in _title,
          "build_report_title: title has no dangling 'when' clause")
# Falls back to a placeholder primitive but stays well-formed when inputs
# are sparse.
assert_in("sanitizer diagnostic", er.build_report_title("CRASH-9", "", "", ""),
          "build_report_title: blank primitive falls back without breaking")

# ─── _rev_is_pinned: real shas pin, sentinels do not ─────────────────
# Delegates to target_config.is_unpinned_rev (single source of truth).
for _rev in ("norev", "NoRev", "no-vcs", "unknown", "?", ""):
    assert_eq(False, er._rev_is_pinned(_rev),
              f"_rev_is_pinned: sentinel {_rev!r} is not pinned")
assert_eq(True, er._rev_is_pinned("abcdef1234567890"),
          "_rev_is_pinned: a concrete sha is pinned")
# HEAD is a deliberate, documented exception: it clones / resolves to a
# forge default branch, so it counts as a usable (pinned) ref.
assert_eq(True, er._rev_is_pinned("HEAD"),
          "_rev_is_pinned: HEAD is treated as a usable ref")
assert_eq(True, er._rev_is_pinned("v1.2.3"),
          "_rev_is_pinned: a tag is a usable ref")


# ─── build_report_md Reproduce hint mirrors reproduce.sh ────────────
# The report's Reproduce block must advertise the same invocation the bundled
# reproduce.sh actually supports: clone for a pinned upstream, the no-argument
# in-place form for a local-only target with a recorded source, and the
# path-only form when neither applies.
def _repro_hint(pinned_rev: str, local_src: str) -> str:
    return er.build_report_md(
        crash_id="CRASH-H-1", primitive_label="stack-buffer-overflow",
        severity_value="Medium", surface_value="cli", surface_reason="",
        trigger_value="bytes", caller_contract_value="obeyed",
        boundary_value="", caller_controls_value="", parameter_control_value="",
        trusted_actions_value="", confidence_value="", strategy_value="",
        crash_dir=TMP, report_md=None,
        asan_top="", asan_summary="", dedup_frames="fn file.c:1",
        asan_expected="", pinned_rev=pinned_rev, local_src=local_src,
    )

_h = _repro_hint("abc123def456", "")
assert_in("clones upstream@abc123def456", _h,
          "build_report_md: pinned rev advertises clone")
_h = _repro_hint("norev", "targets/x")
assert_in("against the in-place audit source", _h,
          "build_report_md: local-only with source advertises no-arg repro")
assert_not_in("clones upstream@", _h,
              "build_report_md: local-only does not advertise a clone")
_h = _repro_hint("norev", "")
assert_in("/path/to/src", _h,
          "build_report_md: no source falls back to the path form")
assert_not_in("in-place audit source", _h,
              "build_report_md: no recorded source omits the in-place hint")


# ─── Cleanup ────────────────────────────────────────────────────────

shutil.rmtree(TMP, ignore_errors=True)
shutil.rmtree(output_root, ignore_errors=True)

total = _PASSED + _FAILED
if _FAILED == 0:
    print(f"  {_GREEN}{_PASSED}/{total} passed{_NC}")
    sys.exit(0)
else:
    print(f"  {_RED}{_PASSED}/{total} passed, {_FAILED} failed{_NC}")
    sys.exit(1)
