#!/usr/bin/env python3
"""Regression tests for lib/finding_signature.py.

Exercises:
  * normalize_class — neutral vocab, "top:sub" labels, unknown LLM tops
  * extract_class   — every layout we've seen in real reports
  * extract_location — explicit Location:, inline file:func:line, no func
  * path canonicalization — abs vs rel, target_root prefix, trailing parens
  * is_valid_dedup_key — char set, length, multi-token requirement
  * finding_signature — Layer 1 vs Layer 2 selection, kind switching
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


# ── is_valid_dedup_key ─────────────────────────────────────────────
print("\nis_valid_dedup_key")
ok(fs.is_valid_dedup_key("code_start-unbounded"), "underscore + hyphen multi-token")
ok(fs.is_valid_dedup_key("tls13-skip-verify"), "hyphen-joined tokens")
ok(fs.is_valid_dedup_key("ipv4-trailing-garbage"), "three tokens")
ok(not fs.is_valid_dedup_key(""), "empty rejected")
ok(not fs.is_valid_dedup_key("oops"), "single token rejected")
ok(not fs.is_valid_dedup_key("a"), "too short rejected")
ok(not fs.is_valid_dedup_key("Has Spaces"), "spaces rejected")
ok(not fs.is_valid_dedup_key("UPPER-CASE"), "uppercase rejected")
ok(not fs.is_valid_dedup_key("with.dot"), "dot rejected")
ok(not fs.is_valid_dedup_key("a-" * 40), "too long rejected")


# ── finding_signature: Layer selection ─────────────────────────────
print("\nfinding_signature — layer selection")

text_loc = """# Boundary issue
## Location
`src/handlers/admin.go:HandleListUsers:42`

## Classification
- **Class**: auth:bypass
"""
sig = fs.finding_signature(text_loc)
assert_eq("loc", sig["kind"], "no LLM key → loc kind")
assert_eq(("auth", "src/handlers/admin.go", "HandleListUsers"),
          sig["key"], "loc key tuple")

sig_with_llm = fs.finding_signature(text_loc, llm_class="auth:bypass",
                                    llm_dedup_key="role-cookie-trusted")
assert_eq("llm", sig_with_llm["kind"], "valid LLM key → llm kind")
assert_eq(("auth", "", "role-cookie-trusted"), sig_with_llm["key"], "llm key tuple")

# LLM emits an invalid key → fall back to loc.
sig_bad_llm = fs.finding_signature(text_loc, llm_class="auth:bypass",
                                   llm_dedup_key="oops")
assert_eq("loc", sig_bad_llm["kind"], "invalid LLM key → loc fallback")
assert_eq(sig_bad_llm["key"], sig["key"], "fallback key matches no-LLM key")

# No file:func and no LLM key → title slug.
text_no_loc = """# CSP allows unsafe-inline in default config

The default Content-Security-Policy emitted by the framework permits
'unsafe-inline' in `script-src`, which negates the XSS mitigation.
"""
sig_title = fs.finding_signature(text_no_loc)
assert_eq("title", sig_title["kind"], "no loc + no LLM key → title slug")
ok(sig_title["key"][2].startswith("csp-allows"),
   "title slug derived from H1", f"slug={sig_title['key'][2]!r}")

# Class extracted from LLM cache overrides extract_class.
sig_class_override = fs.finding_signature(text_loc, llm_class="logic:override")
assert_eq("logic", sig_class_override["class"], "LLM class overrides report class")


# ── Same root cause, different surface sites — Layer 2 collapses ───
print("\ncross-caller Layer 2 collapse")

text_match = """# UAF in match path
## Location
`src/pcre2_match.c:match_internal:1234`

## Classification
- **Class**: memory-safety:lifetime
"""
text_dfa = """# UAF reached from DFA matcher
## Location
`src/pcre2_dfa_match.c:dfa_match_internal:5678`

## Classification
- **Class**: memory-safety:lifetime
"""
sig_match = fs.finding_signature(text_match, llm_class="memory-safety:lifetime",
                                 llm_dedup_key="code_start-unbounded")
sig_dfa = fs.finding_signature(text_dfa, llm_class="memory-safety:lifetime",
                               llm_dedup_key="code_start-unbounded")
assert_eq(sig_match["key"], sig_dfa["key"],
          "two callers, same dedup_key → same cluster key")
assert_eq(fs.cluster_id(sig_match["key"]), fs.cluster_id(sig_dfa["key"]),
          "two callers, same dedup_key → same cluster id")

# Layer 1 alone would split them (different file:func) — the test that
# Layer 2 is the value-add.
sig_match_no_llm = fs.finding_signature(text_match, llm_class="memory-safety:lifetime")
sig_dfa_no_llm = fs.finding_signature(text_dfa, llm_class="memory-safety:lifetime")
ok(sig_match_no_llm["key"] != sig_dfa_no_llm["key"],
   "Layer 1 alone splits different callers — Layer 2 is needed to collapse")


# ── Mass-scanner-style: don't over-collapse 50 strcpy sites ─────────
print("\nmass-scanner safety")

# Three distinct strcpy sites at the same class, different file/func,
# no LLM key. They MUST stay separate.
sites = [
    fs.finding_signature("Location: `a/x.c:f1:1`\nClass: memory-safety:bounds\n"),
    fs.finding_signature("Location: `b/y.c:f2:1`\nClass: memory-safety:bounds\n"),
    fs.finding_signature("Location: `c/z.c:f3:1`\nClass: memory-safety:bounds\n"),
]
keys = {s["key"] for s in sites}
assert_eq(3, len(keys), "three distinct file:func sites stay distinct")


# ── cluster_id stability ───────────────────────────────────────────
print("\ncluster_id")
k = ("auth", "src/foo.go", "Bar")
ok(fs.cluster_id(k) == fs.cluster_id(k), "deterministic")
ok(fs.cluster_id(k).startswith("FCL-"), "FCL- prefix")
ok(len(fs.cluster_id(k)) == 12, "8 hex chars after FCL-")
ok(fs.cluster_id(("auth", "src/foo.go", "Bar"))
   != fs.cluster_id(("logic", "src/foo.go", "Bar")),
   "different class → different cluster id")


print()
if FAILED:
    print(f"\033[0;31m{FAILED} failed, {PASSED} passed\033[0m")
    sys.exit(1)
print(f"\033[0;32m{PASSED}/{PASSED} passed\033[0m")
