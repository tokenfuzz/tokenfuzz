#!/usr/bin/env python3
"""Regression tests for lib/finding_signature.py.

Exercises:
  * normalize_class — neutral vocab, "top:sub" labels, *overflow* → memory-safety
  * extract_class   — every layout we've seen in real reports
  * extract_location — explicit Location:, inline file:func:line, no func
  * extract_line — | Line | Fields row, inline fallback, none → ""
  * path canonicalization — abs vs rel, target_root prefix, trailing parens
  * finding_signature — (class, file, line) key, kind switching, line field
  * cluster_id — stable across permutations of the same key
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import finding_signature as fs  # noqa: E402

PASSED = 0
FAILED = 0


def ok(cond: bool, name: str, detail: str = "") -> None:
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        FAILED += 1
        print(f"  \033[0;31m✗\033[0m {name}")
        if detail:
            print(f"    {detail}")


def assert_eq(expected, actual, name: str) -> None:
    ok(expected == actual, name, f"expected={expected!r} actual={actual!r}")


# ── normalize_class ────────────────────────────────────────────────
print("normalize_class")
assert_eq("memory-safety", fs.normalize_class("memory-safety:bounds"), "top:sub strip")
assert_eq("memory-safety", fs.normalize_class("bounds"), "neutral 'bounds' → memory-safety")
assert_eq("memory-safety", fs.normalize_class("state"), "neutral 'state' → memory-safety")
assert_eq("memory-safety", fs.normalize_class("uninit"), "neutral 'uninit' → memory-safety")
assert_eq("memory-safety", fs.normalize_class("uaf"), "alias 'uaf' → memory-safety")
assert_eq("memory-safety", fs.normalize_class("heap-use-after-free"), "asan-class → memory-safety")
assert_eq("memory-safety", fs.normalize_class("Lifetime"), "case-insensitive Lifetime")
assert_eq("auth", fs.normalize_class("auth:bypass"), "auth:bypass")
assert_eq("auth", fs.normalize_class("authorization"), "authorization synonym")
assert_eq("injection", fs.normalize_class("xss"), "xss → injection")
assert_eq("injection", fs.normalize_class("SQLI"), "SQLI → injection (case)")
assert_eq("info-disclosure", fs.normalize_class("info-leak"), "info-leak alias")
assert_eq("race", fs.normalize_class("toctou"), "toctou → race")
assert_eq("boundary", fs.normalize_class("boundary:csp-bypass"), "boundary:csp-bypass")
assert_eq("config", fs.normalize_class("config:permissive-default"), "config")
assert_eq("logic", fs.normalize_class("logic:business-rule"), "logic")
assert_eq("side-channel", fs.normalize_class("side-channel:cache-timing"), "side-channel")
assert_eq("dos", fs.normalize_class("dos:algorithmic"), "dos:algorithmic")
# Any *overflow* label is a memory-safety mechanism — collapse the whole family
# so a finding's mechanism and its consequence cluster together.
assert_eq("memory-safety", fs.normalize_class("integer-overflow"), "integer-overflow → memory-safety")
assert_eq("memory-safety", fs.normalize_class("buffer-overflow"), "buffer-overflow → memory-safety")
assert_eq("memory-safety", fs.normalize_class("stack-overflow"), "stack-overflow → memory-safety")
assert_eq("memory-safety", fs.normalize_class("integer-overflow:arithmetic"),
          "integer-overflow:sub → memory-safety")
assert_eq("network", fs.normalize_class("network:dns-response-validation"),
          "unknown top retained (network)")
assert_eq("input-validation", fs.normalize_class("input-validation:hostname"),
          "unknown top retained (input-validation)")
assert_eq("other", fs.normalize_class(""), "empty → other")
assert_eq("other", fs.normalize_class(None), "None → other")
assert_eq("other", fs.normalize_class("null"), "literal 'null' → other")


# ── extract_class ──────────────────────────────────────────────────
print("\nextract_class")
assert_eq("logic:business-rule",
          fs.extract_class("body\n## Classification\n- **Class**: logic:business-rule\n"),
          "- **Class**: form")
assert_eq("memory-safety",
          fs.extract_class("body\nClass: memory-safety\n"),
          "Class: form")
assert_eq("size",
          fs.extract_class("body\n- Category: size\n"),
          "- Category: form")
assert_eq("state",
          fs.extract_class("body\nClassification: state\n"),
          "Classification: form")
assert_eq("heap-use-after-free",
          fs.extract_class("- Memory-safety class: heap-use-after-free, READ\n"),
          "- Memory-safety class: form")
assert_eq("Lifetime",
          fs.extract_class("- **Type**: Lifetime issue — heap-use-after-free, READ of size 1+\n"),
          "- **Type**: form (first word)")
assert_eq("Authorization bypass",
          fs.extract_class("Issue class: Authorization bypass\n"),
          "Issue class: form (multi-word retained)")
assert_eq("auth",
          fs.normalize_class(fs.extract_class("Issue class: Authorization bypass\n")),
          "Issue class: form → normalize → auth")
# Bare-prompt / model-direct reports label the class as "Bug class:" etc.
assert_eq("stack-buffer-overflow",
          fs.extract_class("Bug class: stack-buffer-overflow / command construction overflow\n"),
          "Bug class: form (leading token captured)")
assert_eq("memory-safety",
          fs.normalize_class(fs.extract_class(
              "Bug class: stack-buffer-overflow / command construction overflow\n")),
          "Bug class: stack-buffer-overflow → normalize → memory-safety")
assert_eq("memory-safety",
          fs.normalize_class(fs.extract_class("Vulnerability type: heap-buffer-overflow\n")),
          "Vulnerability type: form → normalize → memory-safety")
assert_eq("memory-safety", fs.normalize_class("out-of-bounds"), "out-of-bounds → memory-safety")


# ── path normalization ─────────────────────────────────────────────
print("\nnormalize_path")
assert_eq("src/foo.c", fs.normalize_path("src/foo.c"), "relative as-is")
assert_eq("src/foo.c", fs.normalize_path("`src/foo.c`"), "backticks stripped")
assert_eq("src/foo.c", fs.normalize_path("/Users/x/work/src/foo.c", target_root="/Users/x/work"),
          "TARGET_ROOT prefix stripped")
assert_eq("src/sampledb.cpp",
          fs.normalize_path("targets/sample-cplusplus/src/sampledb.cpp",
                            target_root="targets/sample-cplusplus"),
          "relative target_root strips relative citation → target-relative path")
# The audit passes an ABSOLUTE target_root but reports cite repo-relative
# paths — must still collapse to the target-relative path (regression).
assert_eq("src/sampledb.cpp",
          fs.normalize_path("targets/sample-cplusplus/src/sampledb.cpp",
                            target_root="/Users/x/work/targets/sample-cplusplus"),
          "absolute target_root strips repo-relative citation (mixed forms)")
assert_eq("src/sampledb.cpp",
          fs.normalize_path("/Users/x/work/targets/sample-cplusplus/src/sampledb.cpp",
                            target_root="targets/sample-cplusplus"),
          "relative target_root strips absolute citation (mixed forms)")
assert_eq("src/foo.c",
          fs.normalize_path("src/foo.c", target_root="/Users/x/work/targets/sample-cplusplus"),
          "already target-relative path is unchanged under absolute target_root")
assert_eq("very/deep/path/with/many/a/b/c/d",
          fs.normalize_path("very/deep/path/with/many/a/b/c/d"),
          "full path kept — no segment truncation (distinct leaf-name files stay distinct)")
assert_eq("src/foo.c", fs.normalize_path("src/foo.c  (line 42)"),
          "trailing annotation removed")
assert_eq("", fs.normalize_path(""), "empty → empty")
# Structural fallback: a leading `targets/<slug>/` is stripped even with NO
# target_root — the benchmark output layout can't supply the slug, so derivation
# mis-fires and the prefix must be removed structurally.
assert_eq("src/pcre2grep.c",
          fs.normalize_path("targets/pcre2/src/pcre2grep.c"),
          "leading targets/<slug>/ stripped with no target_root (benchmark layout)")
assert_eq("src/pcre2grep.c",
          fs.normalize_path("targets/pcre2/src/pcre2grep.c", target_root="targets/benchmark"),
          "mis-derived target_root: structural strip still normalizes the path")


# ── extract_location ───────────────────────────────────────────────
print("\nextract_location")

# Pattern 1 — explicit Location:
text1 = """# Auth bypass
## Location
`src/lib/foo.c:HandleListUsers:42`
"""
assert_eq(("src/lib/foo.c", "HandleListUsers"),
          fs.extract_location(text1), "## Location header with backticked file:func:line")

text1b = """# foo
- Location: `lib/options.c:set_string_option:189`
"""
assert_eq(("lib/options.c", "set_string_option"),
          fs.extract_location(text1b), "- Location: bullet form")

text1c = """# foo
Location: src/parser.c:parse_main
"""
assert_eq(("src/parser.c", "parse_main"),
          fs.extract_location(text1c), "Location: bare, no backticks, no line")

# Pattern 2 — inline file:func:line
text2 = """# Issue
The bug is in `src/lib/net_parse.c:parse_inet6_net:406` where
the destination buffer is left partially uninitialized.
"""
assert_eq(("src/lib/net_parse.c", "parse_inet6_net"),
          fs.extract_location(text2), "inline backticked file:func:line")

# Pattern 3 — file only (no func, no line)
text3 = """# Issue
A bug exists in `src/lib/net_parse.c` that mishandles tails.
"""
assert_eq(("src/lib/net_parse.c", ""),
          fs.extract_location(text3), "file-only inline")

# Code-fence frames should NOT win — the bug site goes first.
text4 = """# Issue
## Location
`real/path.c:real_func:1`

## Repro
```
crash inside fake/path.c:fake_func:99
```
"""
assert_eq(("real/path.c", "real_func"),
          fs.extract_location(text4), "Location: wins over fenced code")

# Function names with namespace operators / templates.
text5 = """# foo
## Location
`dom/foo.cc:nsFoo::Bar<int>:55`
"""
file, func = fs.extract_location(text5)
assert_eq("dom/foo.cc", file, "namespaced func: file extracted")
ok(func.startswith("nsFoo::Bar"), "namespaced func: namespace preserved", f"got {func!r}")

# Line-only fallback.
text6 = """# foo
The issue is at src/handler.c:142 in initialization.
"""
file, func = fs.extract_location(text6)
assert_eq("src/handler.c", file, "file:line fallback (file)")
assert_eq("", func, "file:line fallback (no func)")

# Empty body returns empty.
assert_eq(("", ""), fs.extract_location(""), "empty body → empty pair")


# ── Canonical-source extraction: Fields table + ASan frame #0 ──────
print("\nextract_location — canonical sources")

# The | File | row (full target path) beats the basename in prose/frames;
# frame #0 (demangled symbol) beats the fuzzy | Function | label.
report_fields = """# Integer truncation in blob frame length

| Field    | Value |
|----------|-------|
| File     | `targets/sampleproj/src/store.cpp` |
| Function | `assign` |

The subsequent memcpy (store.cpp:183) overflows.

```
    #0 proj::Engine::Store::set_blob(unsigned int) store.cpp:213
    #1 proj::Engine::apply_line(...) store.cpp:367
```
SUMMARY: AddressSanitizer: heap-buffer-overflow store.cpp:213
"""
file, func = fs.extract_location(report_fields, target_root="targets/sampleproj")
assert_eq("src/store.cpp", file, "| File | row wins, target_root stripped → relative path")
assert_eq("proj::Engine::Store::set_blob", func,
          "ASan frame #0 demangled symbol wins over fuzzy | Function | label")

# Same crash site, a DIFFERENT report whose | Function | label drifts —
# frame #0 makes both resolve to the same canonical func.
report_fields2 = """# Frame capacity truncates size

| File     | `targets/sampleproj/src/store.cpp` |
| Function | `frame_capacity/Blob::assign` |

```
    #0 proj::Engine::Store::set_blob(unsigned int) store.cpp:213
```
"""
file2, func2 = fs.extract_location(report_fields2, target_root="targets/sampleproj")
assert_eq((file, func), (file2, func2),
          "drifting | Function | labels collapse via frame #0 → identical loc")

# No crash / no frame #0 → fall back to the | Function | label.
report_no_stack = """# Logic flaw

| File     | `targets/sampleproj/src/store.cpp` |
| Function | `Store::upsert_user` |

upsert_user never clears the secret on re-insert.
"""
file3, func3 = fs.extract_location(report_no_stack, target_root="targets/sampleproj")
assert_eq("src/store.cpp", file3, "source-only finding: | File | row used")
assert_eq("Store::upsert_user", func3,
          "source-only finding: | Function | label used (no frame #0 to prefer)")


# ── extract_line ───────────────────────────────────────────────────
# Feeds the (class, file, line) merge edge in lib/finding_dedup.py.
print("\nextract_line")
assert_eq("213", fs.extract_line("| Line | 213 |\n"), "| Line | Fields row")
assert_eq("213", fs.extract_line("| Line | `213` |\n"), "| Line | row, backticked")
assert_eq("2491", fs.extract_line("| Line | L2491 (cmdbuf) |\n"),
          "| Line | row, first integer run past a prefix")
assert_eq("42", fs.extract_line("## Location\n`src/lib/foo.c:HandleListUsers:42`\n"),
          "inline file:func:line fallback")
assert_eq("142", fs.extract_line("The issue is at src/handler.c:142 in init.\n"),
          "inline file:line fallback")
# A reproducer line inside a fence must NOT win over a real site line.
assert_eq("", fs.extract_line("# Issue\n```\ncrash at fake/path.c:999\n```\n"),
          "fenced reproducer line is masked out")
assert_eq("", fs.extract_line("no line anywhere in this body\n"), "no line → empty")
# When a line is present, it IS the third element of the merge key:
# (class, file, line).
sig_line = fs.finding_signature(
    "## Location\n`src/lib/foo.c:HandleListUsers:42`\n\nClass: memory-safety\n")
assert_eq("42", sig_line["line"], "finding_signature exposes line field")
assert_eq(("memory-safety", "src/lib/foo.c", "42"), sig_line["key"],
          "merge key is (class, file, line) when a line is present")

# bin/cluster-findings stamps `Cluster:` / `Dedup key:` lines into a report
# after it clusters. A `Dedup key: [loc] file:func` stamp injects a file:func
# token that the inline scanners must ignore — otherwise re-clustering a stamped
# report shifts (file, line) and silently changes the dedup site edge (the
# stamped `[loc] file:func` shadowed the real inline `file:func:line`).
_inline_site = "Crafted pattern in pkg/regex/match.go:Compile:120 backtracks.\n"
_stamped_site = ("# Algorithmic DoS\n\nCluster: FCL-deadbeef (singleton)\n"
                 "Dedup key: [loc] pkg/regex/match.go:Compile\n" + _inline_site)
assert_eq(fs.extract_line(_inline_site), fs.extract_line(_stamped_site),
          "extract_line ignores harness Cluster:/Dedup key: stamps")
assert_eq("120", fs.extract_line(_stamped_site),
          "stamped inline finding keeps its real line")
assert_eq(fs.extract_location(_inline_site), fs.extract_location(_stamped_site),
          "extract_location ignores harness stamps")


# ── finding_signature: key selection ───────────────────────────────
print("\nfinding_signature — key selection")

text_loc = """# Boundary issue
## Location
`src/handlers/admin.go:HandleListUsers:42`

## Classification
- **Class**: auth:bypass
"""
sig = fs.finding_signature(text_loc)
assert_eq("loc", sig["kind"], "file+line → loc kind")
assert_eq(("auth", "src/handlers/admin.go", "42"),
          sig["key"], "merge key is (class, file, line)")

# A site with a file but NO line degrades to (class, file, func) — display
# only, never a merge edge.
text_no_line = """# Boundary issue
## Location
`src/handlers/admin.go:HandleListUsers`

## Classification
- **Class**: auth:bypass
"""
sig_no_line = fs.finding_signature(text_no_line)
assert_eq("loc", sig_no_line["kind"], "file, no line → loc kind")
assert_eq(("auth", "src/handlers/admin.go", "HandleListUsers"),
          sig_no_line["key"], "no line → display key (class, file, func)")

# No file:func at all → title slug.
text_no_loc = """# CSP allows unsafe-inline in default config

The default Content-Security-Policy emitted by the framework permits
'unsafe-inline' in `script-src`, which negates the XSS mitigation.
"""
sig_title = fs.finding_signature(text_no_loc)
assert_eq("title", sig_title["kind"], "no loc → title slug")
ok(sig_title["key"][2].startswith("csp-allows"),
   "title slug derived from H1", f"slug={sig_title['key'][2]!r}")

# Class extracted from LLM cache overrides extract_class.
sig_class_override = fs.finding_signature(text_loc, llm_class="logic:override")
assert_eq("logic", sig_class_override["class"], "LLM class overrides report class")


# ── Same site → same key; different site → different key ───────────
print("\nsite-keyed identity")

text_a = """# UAF in match path
## Location
`src/resolve_entry.c:resolve_helper:1234`

## Classification
- **Class**: memory-safety:lifetime
"""
text_a2 = """# Same UAF, re-discovered
## Location
`src/resolve_entry.c:resolve_helper:1234`

## Classification
- **Class**: integer-overflow
"""
# Same file+line, and integer-overflow normalizes to memory-safety, so the two
# re-discoveries land on the SAME key — mechanism vs consequence collapse.
sig_a = fs.finding_signature(text_a)
sig_a2 = fs.finding_signature(text_a2)
assert_eq(sig_a["key"], sig_a2["key"],
          "same file+line, *overflow* folded to memory-safety → same key")
assert_eq(fs.cluster_id(sig_a["key"]), fs.cluster_id(sig_a2["key"]),
          "same site → same cluster id")

# Different surface sites do NOT collapse — distinct sites are distinct bugs
# (no cross-site LLM key invents a merge).
text_b = """# UAF reached from DFA matcher
## Location
`src/scan_records.c:scan_helper:5678`

## Classification
- **Class**: memory-safety:lifetime
"""
sig_b = fs.finding_signature(text_b)
ok(sig_a["key"] != sig_b["key"],
   "two different sites → different keys (no cross-site over-merge)")


# ── Mass-scanner-style: don't over-collapse 50 strcpy sites ─────────
print("\nmass-scanner safety")

# Three distinct strcpy sites at the same class, different file and line.
# They MUST stay separate.
sites = [
    fs.finding_signature("Location: `a/x.c:f1:1`\nClass: memory-safety:bounds\n"),
    fs.finding_signature("Location: `b/y.c:f2:2`\nClass: memory-safety:bounds\n"),
    fs.finding_signature("Location: `c/z.c:f3:3`\nClass: memory-safety:bounds\n"),
]
keys = {s["key"] for s in sites}
assert_eq(3, len(keys), "three distinct sites stay distinct")


# ── cluster_id stability ───────────────────────────────────────────
print("\ncluster_id")
k = ("auth", "src/foo.go", "Bar")
ok(fs.cluster_id(k) == fs.cluster_id(k), "deterministic")
ok(fs.cluster_id(k).startswith("FCL-"), "FCL- prefix")
ok(len(fs.cluster_id(k)) == 12, "8 hex chars after FCL-")
ok(fs.cluster_id(("auth", "src/foo.go", "Bar"))
   != fs.cluster_id(("logic", "src/foo.go", "Bar")),
   "different class → different cluster id")


# ── extract_severity ───────────────────────────────────────────────
# The report is the source of truth for scored severity; both cluster
# tables read it through this parser so their rows match the linked report.
print("\nextract_severity")
assert_eq(("Low", 1, 3.1), fs.extract_severity("| Severity | Low (CVSS-BTE 4.0: 3.1) |"),
          "Fields-table row with CVSS-BTE 4.0 score")
# Backward compatibility: the pre-colon Fields form still parses, so already
# persisted reports keep their scores after the format change.
assert_eq(("Low", 1, 3.1), fs.extract_severity("| Severity | Low (CVSS-BTE 4.0 3.1) |"),
          "legacy no-colon Fields-table row still parses")
assert_eq(("High", 3, 8.7),
          fs.extract_severity("- **Severity**: High (CVSS-BTE 4.0: 8.7 High; "
                              "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N; primitive=x)"),
          "bare line: CVSS score read past the vector's own tokens")
assert_eq(("Low", 1, 1.9),
          fs.extract_severity("- **Severity**: Low (CVSS-BTE 4.0: 1.9 Low; "
                              "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:L/IR:L/AR:L/MVC:L/MVI:L/MVA:L; primitive=x)"),
          "CVSS-BTE line parsed with Environmental score")
assert_eq(("Medium", 2, 0.0), fs.extract_severity("| Severity | Medium |"),
          "Fields-table row without a score")
assert_eq(("Unknown", 0, 0.0),
          fs.extract_severity("- **Severity**: Unknown (unclassified — no CVSS vector)"),
          "unclassified crash → Unknown, no score")
assert_eq(("—", 0, 0.0), fs.extract_severity("no severity recorded yet"),
          "unscored report → em-dash sentinel")
both = ("| Severity | Low (CVSS-BTE 4.0: 3.1) |\n"
        "- **Severity**: Critical (CVSS-BTE 4.0: 9.3 Critical; primitive=x)")
ok(fs.extract_severity(both)[0] == "Critical",
   "bare line preferred over Fields row")
# Level "None" is the CVSS band for a scored 0.0 (e.g. internal-surface
# code whose modified impacts are all N) — parsed, rank 0.
assert_eq(("None", 0, 0.0),
          fs.extract_severity("- **Severity**: None (CVSS-BTE 4.0: 0.0 None; "
                              "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P/CR:L/IR:L/AR:L/MVC:N/MVI:N/MVA:N; primitive=x)"),
          "scored-0.0 band: bare None line parsed")
assert_eq(("None", 0, 0.0), fs.extract_severity("| Severity | None (CVSS-BTE 4.0: 0.0) |"),
          "scored-0.0 band: Fields-table None row parsed")
# A hand-written line carrying only the vector must not misread the
# vector's own "4.0" as a score.
assert_eq(("High", 3, 0.0),
          fs.extract_severity("- **Severity**: High (CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/"
                              "VC:H/VI:H/VA:H/SC:N/SI:N/SA:N)"),
          "vector-only line: no score scraped from the vector version")


print()
if FAILED:
    print(f"\033[0;31m{FAILED} failed, {PASSED} passed\033[0m")
    sys.exit(1)
print(f"\033[0;32m{PASSED}/{PASSED} passed\033[0m")
