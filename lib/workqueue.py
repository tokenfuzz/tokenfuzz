#!/usr/bin/env python3
"""Structured work queue helpers for the audit harness.

Ranking is target-agnostic: it derives priority from repository structure,
code features, prior-fix cards, saved coverage seeds, and coverage gaps.
Target-specific knowledge belongs in optional data files, not in this module.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable

import languages
import report_identity
from audit_scope import is_excluded_path_part
# target_config (only detect_repo_type, below) and prompt_render.render_template
# (only the work_rerank gate) are imported lazily inside their single call sites:
# workqueue backs bin/state, which agents invoke 30+ times per session, and each
# of these modules adds ~3-4 ms of import (target_config pulls shutil; together
# ~5 ms) that the common state ops (resume/add-hyp/update-hyp) never use —
# detect_repo_type runs only when TARGET_REPO_TYPE is unset, which the audit
# always sets. Each is referenced in exactly one function, so deferring the
# import there cannot raise NameError elsewhere.
# Audit-rankable source extensions. The registry in lib/languages.py is
# the single source of truth — adding a new language there (Python,
# Ruby, Go, Java, ...) automatically widens iter_source_files and
# is_auditable_source_path here. The historic hardcoded literal in
# this module silently excluded every non-C/C++/Rust/JS target from
# work-card ranking; see lib/languages.py for the fix rationale.
SOURCE_EXTS: frozenset[str] = languages.all_source_exts()

# Directory-name exclusions live in lib/audit_scope.py — the same set is
# rendered into the model-direct prompt so both audit modes use one
# scoping rule. See that module's docstring for why the set is narrow
# (only doc/example/test/fuzz families) and what stays scanner-internal.
# Re-exported above; this comment is the breadcrumb for readers looking
# for the literal list.

EXCLUDED_FILE_NAMES = {
    "config.h",
    "config.h.cmake",
    "config.h.in",
}

NON_AUDIT_PATCH_TERMS = (
    "spdx",
    "reuse",
    "license",
    "copyright",
    "typo",
    "doc",
    "docs",
    "documentation",
    "readme",
    "changelog",
    "formatting",
    "clang-format",
    "deprecation warning",
    "compiler warning",
    "whitespace",
    "maint:",
    "maintenance",
    "build fix",
    "build system",
    "cmake",
    "autotools",
    "configure",
    "pkg-config",
    "code coverage",
    "coverage",
    "tests:",
    "test:",
    "test code",
    "test harness",
    "test program",
    "test suite",
    # Release/version bumps — touch the version header only and provide no
    # defect surface for review. Real fixes mention the bug class, not the
    # release.
    "release-",
    "release ",
    "version bump",
    "bump version",
    "next release",
    "prepare release",
    "prepare for release",
    "post-release",
    "tag ",
)

# Commit-message patterns that strongly indicate a real defect fix.
#
# Goal: cover the full vulnerability landscape across languages (memory
# safety + web + protocol + crypto + DoS + injection + auth + supply chain),
# not just C/C++ memory bugs. When any pattern matches the lowercased
# commit description, patch-card score gets boosted so the work card
# surfaces above release bumps and doc-only changes.
#
# Patterns are case-insensitive and use word boundaries where needed so a
# 3-letter acronym like "uaf" doesn't accidentally match inside an
# unrelated word. Patterns are compiled once at import time.
AUDIT_PATCH_BOOST_PATTERNS = tuple(re.compile(p, re.IGNORECASE) for p in (
    # ── External identifiers (CVE, advisories) ──────────────────────
    r"\bcve[-_ ]?\d{4}[-_]\d{3,7}\b",
    r"\bghsa[-_][a-z0-9-]{4,}\b",
    r"\bcwe[-_ ]?\d{2,4}\b",
    r"\b(?:security|sec|safety)[ -](?:fix|patch|update|advisory|issue|bug)\b",

    # ── Memory safety primitives ─────────────────────────────────────
    r"\buse[- ]?after[- ]?(?:free|return|scope|poison)\b",
    r"\bdouble[- ]?free\b",
    r"\b(?:heap|stack|buffer|global)[- ]?(?:over[- ]?(?:flow|read|write)|under[- ]?(?:flow|read|write))\b",
    r"\bbuffer (?:over|under)[- ]?(?:flow|read|write|run)\b",
    r"\bout[- ]?of[- ]?bound(?:s|ed)?\b",
    r"\b(?:integer|signed|unsigned)[- ]?(?:over|under)[- ]?flow\b",
    r"\bnull[- ]?(?:pointer )?(?:deref|dereference)\b",
    r"\b(?:memory|resource|heap) corruption\b",
    r"\buninitiali[sz]ed (?:memory|read|value|access)\b",
    r"\btype[- ]?confusion\b",
    r"\b(?:wild|invalid) (?:pointer|free)\b",
    r"\b(?:uaf|oob|use[- ]?after[- ]?free)\b(?![a-z])",  # acronyms with word boundary

    # ── Concurrency / lifetime ───────────────────────────────────────
    r"\b(?:race condition|data race|toctou|time[- ]?of[- ]?check)\b",
    r"\b(?:dead[- ]?lock|live[- ]?lock|use[- ]?while[- ]?freed)\b",

    # ── Injection (all flavours) ─────────────────────────────────────
    r"\b(?:sql|command|os|shell|code|template|ssti|ldap|xpath|crlf|"
    r"header|log|http[- ]?header|nosql|expression|html|css)[- ]?injection\b",
    r"\brce\b|\bremote code execution\b",
    r"\bunsafe (?:eval|exec|spawn|deserialization|unserialize|pickle|yaml)\b",
    r"\b(?:insecure|unsafe) deserialization\b",
    r"\bpickle deserialization\b",

    # ── Auth / access control ────────────────────────────────────────
    r"\b(?:authn|authentication) bypass\b",
    r"\b(?:authz|authorization|access[- ]?control) bypass\b",
    r"\bprivilege[- ]?escalation\b",
    r"\b(?:sandbox|container|vm)[- ]?escape\b",
    r"\bidor\b|\binsecure direct object reference\b",
    r"\bsession (?:fixation|hijack(?:ing)?|reuse)\b",
    r"\b(?:jwt|token) (?:bypass|reuse|forgery|confusion)\b",
    r"\bmass[- ]?assignment\b",
    r"\bbroken (?:access[- ]?control|authentication|authorization)\b",

    # ── SSRF, traversal, file inclusion ──────────────────────────────
    r"\bssrf\b|\bserver[- ]?side request forgery\b",
    r"\b(?:path|directory) traversal\b",
    r"\barbitrary (?:file|path) (?:read|write|delete|disclosure|access)\b",
    r"\b(?:local|remote) file inclusion\b|\blfi\b|\brfi\b",
    r"\bzip[- ]?slip\b|\btar[- ]?slip\b",
    r"\b(?:xxe|xml external entit(?:y|ies))\b",

    # ── XSS / CSRF / redirect ────────────────────────────────────────
    r"\bxss\b|\bcross[- ]?site scripting\b",
    r"\bcsrf\b|\bcross[- ]?site request forgery\b",
    r"\bopen[- ]?redirect\b|\bunvalidated redirect\b",
    r"\b(?:dom|reflected|stored|persistent) (?:xss|scripting)\b",
    r"\bprototype pollution\b",

    # ── Crypto / secrets ─────────────────────────────────────────────
    r"\b(?:weak|broken|insecure) (?:crypto(?:graphy)?|cipher|hash|prng|rng|random)\b",
    r"\b(?:timing|side[- ]?channel) (?:attack|leak)\b",
    # "hard-coded API key" / "hard-coded admin password" — allow one
    # optional qualifier between "hard-coded" and the noun.
    r"\bhard[- ]?coded (?:\w+ )?(?:credential|secret|key|password|token)\b",
    r"\b(?:credential|secret|token|api[- ]?key|password) (?:leak|exposure|disclosure)\b",
    r"\bsignature (?:bypass|forgery|spoofing)\b",
    r"\b(?:padding|oracle) (?:attack|leak)\b",
    r"\btls (?:downgrade|stripping|confusion)\b",

    # ── Info disclosure ──────────────────────────────────────────────
    r"\b(?:info|information) (?:leak|disclosure|exposure)\b",
    r"\bsensitive data (?:leak|exposure|disclosure)\b",
    r"\bmemory (?:disclosure|leak through)\b",

    # ── Protocol / state ─────────────────────────────────────────────
    r"\b(?:dns|cache|cookie) (?:poisoning|spoofing)\b",
    r"\b(?:tcp|tls|protocol) downgrade\b",
    r"\b(?:smuggling|smuggle) (?:request|response)\b",
    r"\brequest smuggling\b",
    r"\bhost header (?:attack|spoofing)\b",

    # ── DoS (algorithmic + amplification) ────────────────────────────
    r"\bregex(?:p)? (?:dos|denial[- ]?of[- ]?service)\b|\bredos\b",
    r"\bcatastrophic backtracking\b",
    r"\b(?:zip|decompression) bomb\b",
    r"\balgorithmic (?:complexity|amplification)\b",
    r"\b(?:hash|collision)[- ]?flood(?:ing)?\b",
    r"\b(?:dos|denial[- ]?of[- ]?service) (?:vector|amplifier|amplification)\b",
    r"\bstack exhaustion\b|\b(?:unbounded|uncontrolled|infinite|excessive|deep) recursion\b",

    # ── Supply chain ─────────────────────────────────────────────────
    r"\b(?:malicious|backdoor(?:ed)?|compromised) (?:dependency|package|crate|gem|module)\b",
    r"\btyposquat(?:ting)?\b",
    r"\bdependency confusion\b",

    # ── Sanitizer / fuzzer hits (strong signal a real bug was fixed) ─
    r"\b(?:asan|ubsan|msan|tsan|address[- ]?sanitizer|memory[- ]?sanitizer|"
    r"thread[- ]?sanitizer|undefined[- ]?behavior[- ]?sanitizer) (?:hit|crash|finding|report)?\b",
    r"\b(?:libfuzzer|oss[- ]?fuzz|afl(?:\+\+|plusplus)?) (?:crash|finding|repro)\b",
    r"\b(?:fuzz(?:er|ing)?) (?:crash|finding|hit)\b",

    # ── Hardening / mitigation ───────────────────────────────────────
    r"\b(?:harden(?:ing)?|sanitize(?:r)? (?:input|output))\b",
    r"\b(?:bounds|length|size) (?:check|validation)\b.*\b(?:add|fix|missing)\b",
    r"\b(?:add|fix|missing) (?:bounds|length|size) (?:check|validation)\b",
))


def matches_audit_boost(desc: str) -> int:
    """Return number of distinct boost patterns matched in desc."""
    if not desc:
        return 0
    return sum(1 for pat in AUDIT_PATCH_BOOST_PATTERNS if pat.search(desc))

# Files that are version-bump-only surfaces. If a patch touches exactly this
# set (no real source files), it has no defect surface for review.
VERSION_ONLY_FILE_PATTERNS = (
    re.compile(r"(?:^|/)(?:[A-Za-z_][A-Za-z0-9_]*_)?version\.h$", re.IGNORECASE),
    re.compile(r"(?:^|/)version$", re.IGNORECASE),
    re.compile(r"(?:^|/)VERSION$"),
    re.compile(r"(?:^|/)RELEASE-NOTES(?:\.md|\.txt)?$", re.IGNORECASE),
    re.compile(r"(?:^|/)CHANGELOG(?:\.md|\.txt)?$", re.IGNORECASE),
    re.compile(r"(?:^|/)CHANGES(?:\.md|\.txt)?$", re.IGNORECASE),
    re.compile(r"(?:^|/)NEWS(?:\.md|\.txt)?$", re.IGNORECASE),
)


def is_version_only_file_set(touched: list[str]) -> bool:
    """All touched files are version-bump / release-notes only."""
    if not touched:
        return False
    for f in touched:
        if not any(pat.search(f) for pat in VERSION_ONLY_FILE_PATTERNS):
            return False
    return True


def patch_audit_boost(desc: str) -> int:
    """Score bonus for commit descriptions that name a real defect class.

    The boost reflects how clearly the commit names a security-relevant
    defect (across memory safety, web vulns, protocol bugs, crypto, DoS,
    supply chain). +20 for any match, +5 per additional unique class
    pattern, capped at +35 so boosted cards lead the queue without
    drowning out higher-base-score cards entirely.
    """
    matches = matches_audit_boost(desc)
    if matches == 0:
        return 0
    return min(20 + (matches - 1) * 5, 35)


# Most of what the next-action hint needs — crash, no-exec, coverage miss,
# timeout, clean — is already in the structured `verdict`, so we route on that
# instead of re-grepping it out of text. Only two text signals add information
# the verdict cannot, so only these two are scanned:
#   - crash-signal: a known crash/sanitizer banner is present although the
#     verdict is not a crash (a possible missed crash — inspect before
#     discarding). The banners are the shared per-language crash_patterns from
#     lib/languages.py, so this stays in sync with every sanitizer and runtime
#     the harness supports instead of a local, rot-prone copy.
#   - format-reject: the input was rejected at parse/format time rather than
#     reaching deeper code (reseed instead of mutating).
RUNTIME_SIGNAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "crash-signal",
        re.compile(
            "|".join(f"(?:{p})" for p in languages.all_crash_patterns()) or r"(?!)"
        ),
    ),
    (
        "format-reject",
        re.compile(
            r"\b(?:parse|syntax|decode|format|magic|checksum|length)\s+"
            r"(?:error|fail|invalid|mismatch|rejected?)\b",
            re.IGNORECASE,
        ),
    ),
)
# Coverage near-miss: the probe's coverage gate prints the closest reached frame
# when a testcase ran near, but not at, the suspicious point.
NEAR_MISS_RE = re.compile(
    r"(?:closest reached:|closest:)\s*(?!<none>|NO_PROXIMITY)([^\n\r;)]+)",
    re.IGNORECASE,
)

CI_PATCH_TERMS = (
    "ci",
    "workflow",
    "github action",
    "build action",
    "fix ci",
)

# Assertion / check family — a structural rule, not an enumeration.
# Matches the all-caps macro family where ASSERT/CHECK/VERIFY/REQUIRE is
# a whole underscore-delimited segment, optionally namespaced (MOZ_ASSERT,
# JS_ASSERT, CHECK_EQ, DCHECK, BOOST_ASSERT, G_ASSERT, RELEASE_ASSERT,
# ...), plus the C/C++ standard assert/static_assert, Rust's
# assert!/debug_assert!/unreachable! macros, and the abort-on-invariant
# constructs of the other supported languages. Segment anchoring keeps
# CHECKSUM-style identifiers out. Kept as a family rule on purpose so it
# does not rot or accrete target-specific macro names over time.
_ASSERT_RE = re.compile(
    r"\b(?:[A-Z][A-Z0-9]*_)*(?:ASSERT|D?CHECK|VERIFY|REQUIRE)(?:_[A-Z0-9]+)*\b"
    r"|\b(?:debug_|static_)?assert(?:_eq|_ne)?\b"
    r"|\b_Static_assert\b|\bunreachable!"
    # Go `panic(`, Rust `panic!`, Swift `precondition(`/`fatalError(`.
    r"|\bpanic\s*[(!]|\bprecondition\s*\(|\bfatalError\s*\("
)

# Verb stems that mark a function as consuming or interpreting input.
# The input-consumption regex is built from this list in both snake_case
# and CamelCase form, so a verb is declared exactly once (no drift).
_CONSUME_VERBS = (
    "read", "parse", "decode", "scan", "lex", "tokeniz", "compile",
    "match", "deserializ", "unmarshal", "decompress", "inflate",
    "recv", "demangl",
)
# snake_case alt: verb is a whole `_`-delimited segment, so `thread` /
# `spread` / `pthread_create` do not match. CamelCase alt: verb is a
# capitalised segment at any position, including leading (`ReadBuffer`).
# Both casings are needed — snake_case C and CamelCase C++ alike.
_INPUT_CONSUMPTION_RE = re.compile(
    r"\b(?:[a-z0-9]+_)*(?:" + "|".join(_CONSUME_VERBS) + r")[a-z0-9_]*"
    r"|\b[A-Za-z0-9]*(?:" + "|".join(v.capitalize() for v in _CONSUME_VERBS)
    + r")[A-Za-z0-9]*\b"
)

# ── Code-feature signal table ──────────────────────────────────────
#
# Each row is (compiled_regex, points, reason). `code_feature_reasons`
# adds `points` (saturating) to a file's rank score and records
# `reason`; `strategy_for` / `complementary_strategies` map the reason
# set to an audit strategy S1..S8.
#
# Discipline (docs/development.md): these run against EVERY target's source, so
# every row must be target-agnostic — it matches a *family* (verb stems,
# macro shapes, libc/POSIX symbols, language keywords), never one
# project's types/headers/internal macros. A loose pattern costs
# ranking noise, not exploration depth (a file is flagged once
# regardless of hit count past the cap), so we prefer breadth. Rows
# span C/C++/Rust/Go/Swift/Java/Python; a row that cannot match a
# given language simply contributes nothing there.
#
# Inclusion criterion for a new row: it must (a) plausibly match across
# ≥3 unrelated codebases, and (b) map cleanly to one primary strategy
# via _STRATEGY_BUCKETS. The wiring favours strategies an LLM auditor is
# effective at and that carry an objective oracle: S7 adversarial-input
# and S5 lifetime/state are sanitizer-checked; S2 invariant-negation and
# S3 spec-vs-impl are grounded in code the agent can read; S8 needs no
# sanitizer.
CODE_PATTERNS: tuple[tuple[re.Pattern[str], int, str], ...] = (
    # S7 — untrusted-input entrypoint: an identifier carrying a
    # consume-verb segment, snake_case or CamelCase, at any position.
    (_INPUT_CONSUMPTION_RE, 16, "input-consumption entrypoint"),
    # S7 — deserialization sink: untrusted serialized data reaching an
    # object-graph reconstructor (RCE class; Java/Python/Go).
    (re.compile(
        r"\bObjectInputStream\b|\breadObject\b|\breadUnshared\b|\bXMLDecoder\b"
        r"|\b__reduce__\b|\bpickle\.loads?\b|\byaml\.(?:unsafe_)?load\b"
        r"|\bgob\.NewDecoder\b"
    ), 15, "deserialization sink"),
    # S3 — exported API surface: spec-vs-impl angle on the public contract.
    (re.compile(
        r"\bextern\s+\"C\"|__attribute__\s*\(\(\s*visibility\s*\(\s*\"default\""
        r"|__declspec\s*\(\s*dllexport"
        r"|\b[A-Z][A-Z0-9_]*(?:API|EXPORT|PUBLIC|EXTERN)[A-Z0-9_]*\b"
        r"|\bpub\s+(?:unsafe\s+)?fn\b|\b(?:public|open)\s+func\b"
    ), 14, "exported API surface"),
    # S7 — command / injection surface: untrusted data reaching a shell,
    # process spawn, dynamic class load, or JNDI/naming lookup.
    (re.compile(
        r"\b(?:system|popen)\s*\(|\bexec[lv]?[pe]*\s*\("
        r"|\bProcessBuilder\b|\bRuntime\.getRuntime\b|\bexec\.Command(?:Context)?\b"
        r"|\b(?:process::)?Command::new\b"
        r"|\bos\.system\b|\bsubprocess\.(?:Popen|call|run|check_output|check_call)\b"
        r"|\bClass\.forName\b|\bInitialContext\b|\b\w*[Cc]ontext\.lookup\b"
        r"|\bdlopen\s*\("
    ), 13, "command/injection surface"),
    # S7 — raw memory / unbounded-format operation (libc + format family).
    (re.compile(
        r"\bmem(?:cpy|move|set|cmp)\s*\("
        r"|\bstr(?:n?cpy|n?cat|n?cmp|n?dup)\s*\("
        r"|\bv?sn?printf\s*\(|\bgets\s*\(|\b[fs]?scanf\s*\("
    ), 12, "raw memory operation"),
    # S5 — lifetime / ownership operation: free, delete, refcount drop,
    # destructor-style teardown, and the C error-path `goto cleanup` idiom.
    (re.compile(
        r"\bfree\s*\(|\bdelete\s*(?:\[\s*\])?\s+[\w*]"
        r"|\b\w*(?:[Ff]ree|[Dd]estroy|[Rr]elease|[Dd]ealloc|[Uu]nref)\w*\s*\("
        r"|\bPy_X?DECREF\b|->\s*(?:release|Release|unref|Unref)\b"
        r"|\bgoto\s+\w*(?:err|fail|clean|done|bail)\w*"
    ), 12, "lifetime/ownership operation"),
    # S7 — external-entity surface: XML parsers reachable by XXE.
    (re.compile(
        r"\bDocumentBuilderFactory\b|\bSAXParser(?:Factory)?\b|\bXMLReader\b"
        r"|\bXMLInputFactory\b|\bTransformerFactory\b|\bSchemaFactory\b"
        r"|\bEntityResolver\b|\bresolveEntity\b|\bDTDHandler\b"
        r"|\bACCESS_EXTERNAL_(?:DTD|SCHEMA)\b|\bsetExpandEntityReferences\b"
        r"|\betree\.(?:parse|fromstring)\b"
    ), 11, "external-entity surface"),
    # S7 — allocation / resize: integer-overflow-into-undersized-buffer site.
    (re.compile(
        r"\b(?:m|c|re|aligned_)?alloc\s*\(|\balloca\s*\(|\breallocarray\s*\("
        r"|\bmmap\s*\(|\bnew\s+[A-Za-z_][\w:]*\s*[\[({]|\bnew\s*\["
        r"|\b(?:resize|reserve)\s*\(|\bwith_capacity\s*\(|\bmake\s*\(\s*\[\]"
    ), 10, "allocation/resize"),
    # S5 — unmanaged escape hatch: the memory-unsafe islands of an
    # otherwise-safe language (Rust `unsafe`, Go `unsafe.Pointer`, ...).
    (re.compile(
        r"\bunsafe\s*\{|\bunsafe\s+(?:fn|impl|trait)\b|\bunsafe\.Pointer\b"
        r"|\btransmute\b|\bget_unchecked(?:_mut)?\b|\bfrom_raw(?:_parts)?\b"
        r"|\bMaybeUninit\b|\bset_len\s*\(|\bptr::(?:read|write|copy)\b"
    ), 10, "unmanaged escape hatch"),
    # S3 — cast / type-pun path: type-confusion candidate.
    (re.compile(
        r"\b(?:static_cast|reinterpret_cast|const_cast|dynamic_cast)\s*<"
        r"|\bunion\s+(?:\w+\s*)?\{|\bas\s+\*(?:const|mut)\b"
        r"|\(\s*(?:u?int(?:8|16|32|64)_t|size_t|void\s*\*)\s*\)\s*[&*\w]"
    ), 9, "cast-heavy path"),
    # S2 — asserted invariant: a ready-made negation target.
    (_ASSERT_RE, 8, "asserted invariant"),
    # S8 — round-trip / property surface: code with an inverse operation
    # (encode/decode, compress/inflate) or an idempotent normaliser
    # (normalise/canonicalise/sanitise/dedupe) carries its own oracle.
    (re.compile(
        r"\b\w*(?:[Ee]ncode|[Dd]ecode|[Ss]erializ|[Cc]ompress|[Dd]eflate"
        r"|[Ii]nflate|[Mm]arshal|[Ee]ncrypt|[Dd]ecrypt|[Nn]ormaliz"
        r"|[Cc]anonicaliz|[Ss]anitiz|[Dd]edup|[Ee]scape)\w*\b"
    ), 8, "round-trip property surface"),
    # S8 — injectivity surface: non-cryptographic hashers, fingerprinters,
    # and id/key generators carry a uniqueness oracle (collision → hash-
    # flooding DoS, cache poisoning, identity confusion). Three alternatives:
    #   1. distinctive hasher/fingerprint families — safe with any affix;
    #   2. the generic `hash`/`digest` token in a call (covers compute_hash,
    #      hash_bytes, hashString, digest_update, …), guarded by a negative
    #      lookahead so container plumbing (hashmap, hashtable, hash_table,
    #      hash_map, rehash) does NOT match;
    #   3. id/key/symbol generators (injective-by-contract).
    (re.compile(
        r"\b\w*(?:md[45]|sha[0-9]{1,3}|blake\w*|murmur\w*|xxhash|cityhash"
        r"|siphash|spooky\w*|fnv1?a?|adler32?|crc(?:16|32|64)|fingerprint"
        r"|checksum|digest)\w*\s*\("
        r"|\b(?!\w*(?:hashmap|hashtable|hash_table|hash_map|rehash))"
        r"\w*hash\w*\s*\("
        r"|\b(?:intern|symbol_id|cache_key|key_for|id_for"
        r"|(?:gen(?:erate)?|make|new|next|alloc(?:ate)?|create)_id)\w*\s*\(",
        re.IGNORECASE,
    ), 6, "hash/injectivity surface"),
    # S8 — numerical-domain surface: a declared output domain (non-negative,
    # finite, probability, [0,1]) or a range-enforcement call (clamp/saturate)
    # carries a domain oracle — an out-of-domain value feeding an allocation
    # size, index, length, or resource limit becomes an OOB or DoS primitive.
    # Keyed on declared-domain language and enforcement-fn names ONLY, never on
    # bare numeric return types or loose `>= 0` comparisons: an *asserted*
    # domain is S2's negation target, and a bare comparison is high-FP. `finite`
    # must sit in numeric context (isfinite(), `finite <number-noun>`, NaN) so
    # prose like "finite state machine" / "finite element" does not match.
    (re.compile(
        r"\bnon[-_ ]?negative\b|\bnonnegative\b|\bprobabilit\w*"
        r"|\bin \[0\s*,\s*1\]|\bmust be (?:positive|non[-_ ]?negative|finite)\b"
        r"|\bis(?:finite|nan|inf)\s*\(|\bNaN\b|\bsubnormal\s+(?:value|float|number|result)s?\b"
        r"|\bfinite\s+(?:value|float|double|number|result)s?\b"
        r"|\b(?:clamp|saturat)\w*\s*\(",
        re.IGNORECASE,
    ), 6, "numerical-domain surface"),
    # S5 — concurrency primitive: data-race / TOCTOU candidate.
    (re.compile(
        r"\bpthread_\w+|\bstd::(?:mutex|atomic|thread|lock_guard|shared_mutex"
        r"|condition_variable)\b|\b_Atomic\b|\batomic_\w+|\bvolatile\b"
        r"|\bstd::memory_order|\bsynchronized\b|\bReentrantLock\b"
        r"|\bsync\.(?:Mutex|RWMutex|WaitGroup|Once)\b|\bgo\s+func\b"
        r"|\bthread::spawn\b|\bMutex::new\b|\bRwLock\b"
    ), 7, "concurrency primitive"),
    # S3 — size / integer arithmetic: overflow, truncation, signedness.
    (re.compile(
        r"\b(?:u?int(?:8|16|32|64)_t|size_t|ssize_t|ptrdiff_t)\b[^;\n]{0,40}?[-+*]"
        r"|\b(?:len|size|count|length|offset|idx|nmemb)\b\s*[-+*]\s*\w"
        r"|\b__builtin_(?:add|sub|mul)_overflow\b|\bchecked_(?:add|mul|sub)\b"
        r"|\bSafeInt\b"
    ), 6, "size math"),
)

# Reason → strategy map. Single source of truth shared by strategy_for
# (returns the first matching bucket) and complementary_strategies
# (returns every matching bucket). Order is descending expected yield:
# S7 adversarial-input and S5 lifetime/state are sanitizer-checked so
# they lead; S2/S3 are code-grounded; S8 is the no-sanitizer oracle.
# S1 (prior-fix) and S4/S6 (cross-artifact) are not seedable from one
# file's code features — the rotation owns them, not this table.
_STRATEGY_BUCKETS: tuple[tuple[str, frozenset[str]], ...] = (
    ("S7", frozenset({
        "input-consumption entrypoint", "deserialization sink",
        "command/injection surface", "external-entity surface",
        "raw memory operation", "allocation/resize"})),
    ("S5", frozenset({
        "lifetime/ownership operation", "unmanaged escape hatch",
        "concurrency primitive"})),
    ("S2", frozenset({"asserted invariant"})),
    ("S3", frozenset({
        "cast-heavy path", "size math", "exported API surface"})),
    ("S8", frozenset({
        "round-trip property surface", "hash/injectivity surface",
        "numerical-domain surface"})),
)

# Reasons scored once per file regardless of match count (see
# code_feature_reasons). The S8 property surfaces are presence signals: a
# file either carries an inverse/idempotence/injectivity/domain oracle or it
# does not, and repeating the token does not raise confidence. Keeping them
# off the per-match ×4 multiplier is what holds the commit's intent that a
# repetition-dense S8 file cannot outrank a single high-signal S7 entrypoint.
_PRESENCE_ONLY_REASONS: frozenset[str] = frozenset({
    "round-trip property surface", "hash/injectivity surface",
    "numerical-domain surface",
})


@dataclass
class Context:
    script_root: Path
    target_root: Path
    target_slug: str
    results_dir: Path
    repo_type: str


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso_utc(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def work_card_claim_ttl() -> timedelta:
    """Default lease lifetime for an adopted work card.

    The audit loop iterates on a minute-scale cadence, so the TTL is
    primarily a safety net — release_stale_claims runs each iteration and
    expires claims whose hypotheses are gone or terminal long before the
    TTL kicks in. The default of 30 minutes is short enough that a wedged
    or kill -9'd run does not poison the queue for an entire shift.
    Override with WORK_CARD_CLAIM_TTL_SECONDS for long-lived cards.
    """
    raw = os.environ.get("WORK_CARD_CLAIM_TTL_SECONDS", "")
    try:
        seconds = int(raw) if raw else 30 * 60
    except ValueError:
        seconds = 30 * 60
    return timedelta(seconds=max(0, seconds))


def realpath(p: str | Path) -> Path:
    return Path(p).expanduser().resolve()


def sanitize_slug(raw: str) -> str:
    base = Path(raw).name.lower()
    slug = re.sub(r"[^a-z0-9._-]+", "-", base).strip("-")
    return slug or "target"


def detect_repo_type(root: Path) -> str:
    import target_config  # lazy: see import note at top of file
    return target_config.detect_repo_type(root)


def default_script_root() -> Path:
    return realpath(Path(__file__).parent.parent)


def context_from_args(args: argparse.Namespace) -> Context:
    script_root = realpath(getattr(args, "script_root", None) or os.environ.get("SCRIPT_ROOT") or default_script_root())
    target_given = bool(
        getattr(args, "target_path", None)
        or os.environ.get("TARGET_ROOT")
        or getattr(args, "target", None)
        or os.environ.get("TARGET_NAME")
    )
    if getattr(args, "target_path", None):
        target_root = realpath(args.target_path)
    elif os.environ.get("TARGET_ROOT"):
        target_root = realpath(os.environ["TARGET_ROOT"])
    elif getattr(args, "target", None) or os.environ.get("TARGET_NAME"):
        target_name = getattr(args, "target", None) or os.environ["TARGET_NAME"]
        target_root = realpath(script_root / "targets" / target_name)
    else:
        target_root = realpath(Path.cwd())
    slug_given = bool(getattr(args, "target_slug", None) or os.environ.get("TARGET_SLUG"))
    target_slug = getattr(args, "target_slug", None) or os.environ.get("TARGET_SLUG") or sanitize_slug(str(target_root))
    results_given = getattr(args, "results_dir", None) or os.environ.get("RESULTS_DIR")
    # A stateful results dir must be named, not guessed. With no RESULTS_DIR /
    # --results-dir AND no target identity (--target/--target-path/TARGET_ROOT/
    # TARGET_NAME/--target-slug/TARGET_SLUG), the only remaining fallback is
    # sanitize_slug(cwd) -> output/<basename(cwd)>/results: an arbitrary working
    # directory silently becomes a phantom "target" and state writes land in a
    # tree nothing reads back (observed: the bare model-direct baseline agent
    # poking bin/state created an empty output/<cell-name>/results/state). A
    # real audit always sets RESULTS_DIR (bin/audit) or names the target, so
    # this only fires for a stray call — fail loud instead of fabricating one.
    if not results_given and not target_given and not slug_given:
        raise SystemExit(
            "audit state: no results directory. Set RESULTS_DIR or pass "
            "--results-dir, or name the target with --target / --target-path / "
            "--target-slug (or TARGET_NAME / TARGET_SLUG). Refusing to derive "
            "output/<cwd>/results from the current directory."
        )
    results_dir = realpath(results_given or (script_root / "output" / target_slug / "results"))
    repo_type = os.environ.get("TARGET_REPO_TYPE") or detect_repo_type(target_root)
    return Context(script_root, target_root, target_slug, results_dir, repo_type)


def add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--script-root")
    parser.add_argument("--target")
    parser.add_argument("--target-path")
    parser.add_argument("--target-slug")
    parser.add_argument("--results-dir")


def relpath(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except Exception:
        return path.as_posix()


# Auto-detected partition depth for the current target. ``None`` selects the
# default depth of 2. Set once per process by
# :func:`init_subsystem_depth` after the source tree has been scanned;
# header-only / monolithic targets (where every source file lives under
# a single 2-component prefix like ``include/nlohmann``) get a deeper
# default so that rotation has somewhere to rotate to.
_AUTO_SUBSYSTEM_DEPTH: int | None = None
_DEFAULT_SUBSYSTEM_DEPTH = 2
_MAX_SUBSYSTEM_DEPTH = 5


def _subsystem_depth() -> int:
    global _AUTO_SUBSYSTEM_DEPTH
    if _AUTO_SUBSYSTEM_DEPTH is not None:
        return _AUTO_SUBSYSTEM_DEPTH
    env = os.environ.get("AUDIT_SUBSYSTEM_DEPTH")
    if env and env.isdigit():
        d = int(env)
        if d >= 1:
            return min(d, _MAX_SUBSYSTEM_DEPTH)
    results_dir = os.environ.get("RESULTS_DIR") or os.environ.get("AUDIT_RESULTS_DIR")
    if results_dir:
        persisted = load_persisted_subsystem_depth(Path(results_dir) / "state" / "subsystem-depth")
        if persisted is not None:
            _AUTO_SUBSYSTEM_DEPTH = persisted
            return persisted
    return _DEFAULT_SUBSYSTEM_DEPTH


def subsystem_for(path: str) -> str:
    # Absolute paths leak host-local prefixes into subsystem buckets.
    # Refuse them rather than fabricating buckets from machine-specific
    # path segments. Callers that pass target-relative paths will fall
    # back to "unknown", which is filtered out by the diversity guard.
    if not path:
        return "root"
    if path.startswith("/"):
        return "unknown"
    parts = [p for p in path.split("/") if p]
    if not parts:
        return "root"
    depth = _subsystem_depth()
    if len(parts) >= depth:
        return "/".join(parts[:depth])
    return "/".join(parts)


def auto_subsystem_depth(
    source_paths: Iterable[str],
    *,
    default: int = _DEFAULT_SUBSYSTEM_DEPTH,
    max_depth: int = _MAX_SUBSYSTEM_DEPTH,
    dominance_threshold: float = 0.7,
) -> int:
    """Pick the shallowest depth that gives reasonable partition spread.

    Header-only / monolithic targets — where every source file lives
    under a single ``include/<name>`` or ``src/`` prefix — collapse to
    one bucket at depth 2, which makes overlap detection and rotation
    useless. We keep increasing the depth while either (a) fewer than
    two distinct buckets emerge, or (b) one bucket holds more than
    ``dominance_threshold`` of all source files. Targets with naturally
    diverse 2-component prefixes (browsers, multi-binary repos) stay at
    depth 2.
    """
    paths = [str(p) for p in source_paths if p]
    if not paths:
        return default
    total = len(paths)
    for depth in range(default, max_depth + 1):
        buckets: dict[str, int] = {}
        for raw in paths:
            parts = [p for p in raw.split("/") if p]
            if not parts:
                continue
            bucket = "/".join(parts[: min(depth, len(parts))])
            buckets[bucket] = buckets.get(bucket, 0) + 1
        if len(buckets) < 2:
            continue
        largest = max(buckets.values())
        if largest / total <= dominance_threshold:
            return depth
        # One bucket dominates — try a deeper split unless we've hit the cap.
    return max_depth


def init_subsystem_depth(
    source_paths: Iterable[str],
    *,
    persist_to: Path | None = None,
) -> int:
    """Configure the module-level partition depth from a source-tree scan.

    Idempotent. The chosen depth is also exported via
    ``AUDIT_SUBSYSTEM_DEPTH`` so subprocesses inherit it. When
    ``persist_to`` is given, the depth is written to that file so later
    Python invocations (the shell harness spawns many) can pick it up
    without re-scanning the source tree.
    """
    global _AUTO_SUBSYSTEM_DEPTH
    depth = auto_subsystem_depth(source_paths)
    _AUTO_SUBSYSTEM_DEPTH = depth
    os.environ["AUDIT_SUBSYSTEM_DEPTH"] = str(depth)
    if persist_to is not None:
        try:
            persist_to.parent.mkdir(parents=True, exist_ok=True)
            persist_to.write_text(f"{depth}\n", encoding="utf-8")
        except Exception:
            pass
    return depth


def load_persisted_subsystem_depth(path: Path) -> int | None:
    """Read a persisted depth value written by :func:`init_subsystem_depth`."""
    try:
        raw = path.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    if raw.isdigit():
        d = int(raw)
        if 1 <= d <= _MAX_SUBSYSTEM_DEPTH:
            return d
    return None


def mode_for_file(path: str) -> str:
    return languages.mode_for_ext(Path(path).suffix)


def normalized_relpath(path: str | Path) -> str:
    return str(path).replace("\\", "/").lstrip("./")


def is_excluded_work_path(path: str | Path) -> bool:
    """Return true for support, test, generated, and build-only paths."""
    rel = normalized_relpath(path).lower()
    if not rel:
        return True
    parts = [p for p in rel.split("/") if p]
    if any(is_excluded_path_part(part) for part in parts[:-1]):
        return True
    name = parts[-1] if parts else rel
    stem = Path(name).stem.lower()
    if name in EXCLUDED_FILE_NAMES:
        return True
    if (
        stem.startswith(("test", "tests_", "unit_", "fixture_", "fuzz", "harness", "bench", "benchmark"))
        or stem.endswith(("test", "_test", "_tests", "_unittest", "_fixture", "_fixtures", "_fuzz", "_fuzzer", "_harness", "_bench", "_benchmark"))
        or any(token in stem for token in ("_test_", "test_", "_fuzz", "fuzz_", "_harness", "harness_", "_bench_", "_benchmark_", "_perf_"))
        or ".test." in name
        or ".spec." in name
        # `_perf_` (bounded both sides) reads as a benchmark/perf-test stem
        # (`run_perf_loop`). Deliberately NOT matched: `perf_*` / `*_perf` /
        # a bare `perf`/`performance` file, nor `debug*` / `*_debug` — those
        # are real shipping subsystem names (`perf_counter.c`,
        # `performance.c`, libxml2 `debugXML.c`, Linux perf), and a name
        # alone cannot tell a perf/debug *tool* from a perf/debug *feature*.
        # Scope doubt stays in scope; the find-quality gate judges by role.
    ):
        return True
    return False


def is_auditable_source_path(path: str | Path) -> bool:
    rel = normalized_relpath(path)
    return Path(rel).suffix.lower() in SOURCE_EXTS and not is_excluded_work_path(rel)


def is_non_audit_patch_description(desc: str, touched_files: list[str]) -> bool:
    low = (desc or "").lower()
    # A boost-pattern match overrides a non-audit-term match: a commit
    # titled "release 1.2: fix CVE-2025-XXXX heap overflow" is a real
    # defect even though "release" is on the non-audit list.
    if matches_audit_boost(desc) > 0:
        return False
    if any(term in low for term in NON_AUDIT_PATCH_TERMS):
        return True
    if any(term in low for term in CI_PATCH_TERMS) and not touched_files:
        return True
    # Touched files are exclusively version/release-notes — no defect surface.
    if touched_files and is_version_only_file_set(touched_files):
        return True
    return False


def work_surface(card: dict) -> str:
    """Source-surface key for work-card deduplication.

    The key is intentionally function-aware: a single file like
    `nlohmann/detected.hpp` carries 60+ public-API conversion paths that
    deserve independent investigation. Keying solely on the file path
    (the prior behavior) collapsed all those paths to one card and let a
    single hypothesis lock the entire surface for an audit cycle.

    Layering:
      * `file:function` — when both are known, finest grain.
      * `file:S<n>`     — same file, but the originating strategy
                          differentiates the angle of attack.
      * `file`          — fallback when neither function nor strategy
                          is available (matches file-only patch cards).
      * `touched[0]`    — vendored/multi-file patches.
      * `id`            — last resort, never lossy.
    """
    file = normalized_relpath(card.get("file", ""))
    function = (card.get("function") or "").strip()
    strategy = (card.get("strategy") or "").strip().upper()
    if file:
        if function:
            return f"{file.lower()}:{function.lower()}"
        if strategy:
            return f"{file.lower()}:{strategy.lower()}"
        return file.lower()
    touched = card.get("touched_files") or []
    if touched:
        return normalized_relpath(str(touched[0])).lower()
    return str(card.get("id", "")).lower()


def card_strategy_matches(card: dict, strategy: str = "") -> bool:
    """Return whether a work card is claimable under a requested strategy."""
    requested = str(strategy or "").strip().upper()
    if not requested:
        return True
    primary = str(card.get("strategy", "")).strip().upper()
    allowed_raw = card.get("allowed_strategies") or []
    allowed = {str(s).strip().upper() for s in allowed_raw if str(s).strip()}
    return primary == requested or requested in allowed


def is_auditable_work_card(card: dict) -> bool:
    file = card.get("file", "")
    if file and not is_auditable_source_path(file):
        return False
    touched = [f for f in card.get("touched_files", []) or [] if is_auditable_source_path(f)]
    if card.get("kind") == "s1-patch":
        if is_non_audit_patch_description(card.get("description", ""), touched or ([file] if file else [])):
            return False
        if not file and not touched:
            return False
    return True


def dedupe_work_cards(cards: list[dict]) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for card in cards:
        if not is_auditable_work_card(card):
            continue
        key = work_surface(card)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(card)
    return out


def strategy_for(reasons: list[str]) -> str:
    """Pick the *primary* audit strategy for a file from its code-feature
    reasons.

    Returns the first strategy bucket (highest expected yield first, see
    `_STRATEGY_BUCKETS`) that any reason falls into — the seed strategy
    for the file's first card. `complementary_strategies` emits the rest
    as companion cards. Falls back to S1 (prior-fix default) when no code
    feature fired.
    """
    rset = set(reasons)
    for strat, tags in _STRATEGY_BUCKETS:
        if rset & tags:
            return strat
    return "S1"


def complementary_strategies(reasons: list[str], primary: str) -> list[str]:
    """Strategies to try on this file beyond `primary`.

    Returns every strategy bucket the file's reasons fall into, excluding
    `primary`, ordered by expected yield (see `_STRATEGY_BUCKETS`).
    `rank_target` emits up to RANK_WORK_PER_FILE_COMPANIONS of them as
    companion cards so one file can be probed from several angles.
    """
    rset = set(reasons)
    out = [strat for strat, tags in _STRATEGY_BUCKETS
           if strat != primary and rset & tags]
    # S1 — a file next to a prior fix is explicit regression territory.
    if "near prior-fix card" in rset and primary != "S1":
        out.append("S1")
    return out


def iter_source_files(root: Path, max_files: int = 0) -> Iterable[Path]:
    # max_files <= 0 means "no cap" — yield every source file in the tree
    # (rank-work ranks the whole repo; it must not go blind past a fixed
    # walk position). A positive value bounds the walk for callers that
    # only need a sample (e.g. a bounded LLM file-listing prompt).
    #
    # Walker-level prune list — kept narrow on purpose. The audit-scope
    # rule lives in lib/audit_scope (consulted via is_excluded_path_part
    # below) so adding entries here would drift from what the
    # model-direct prompt enforces. Only VCS metadata and language
    # runtime caches make the cut: they are massive, contain no
    # auditable source by definition, and pruning them is purely a
    # walker-speed concern. Build outputs, vendored deps, tools,
    # scripts, generated code, etc. flow through the audit_scope
    # filter the same way they do in the model-direct prompt.
    # Sanitizer build trees (build-asan*, build-ubsan*, ...) are
    # filtered by is_excluded_path_part below.
    skip_dirs = {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
    }
    # When the target is a git/hg checkout, restrict the surface to VCS-tracked
    # files so untracked scratch (agent PoCs, prior-run leftovers) never becomes
    # a work card. None => not a checkout / probe failed => audit everything.
    import target_config  # lazy: see import note at top of file
    tracked = target_config.vcs_tracked_files(root)
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in skip_dirs
            and not is_excluded_path_part(normalized_relpath(d).lower())
            and not d.startswith(".cache")
        ]
        for name in filenames:
            path = Path(dirpath) / name
            if path.suffix.lower() not in SOURCE_EXTS:
                continue
            rel = relpath(path, root)
            if is_excluded_work_path(rel):
                continue
            if tracked is not None and rel not in tracked:
                continue
            seen += 1
            yield path
            if max_files > 0 and seen >= max_files:
                return


def read_sample(path: Path, max_bytes: int = 256_000) -> str:
    try:
        with path.open("rb") as source:
            data = source.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def load_patch_boosts(path: Path) -> dict[str, dict]:
    """Build a per-source-file boost map from the patch-card stream.

    Skips non-audit patches (CI, build, coverage, docs) so their hashes
    don't bleed into ranked-source cards' patch_cards lists. Without this
    filter, finer surface keying surfaces those IDs in rank-work output
    even though they were intended to be excluded.
    """
    boosts: dict[str, dict] = {}
    if not path.is_file():
        return boosts
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            card = json.loads(line)
            touched = [f for f in card.get("touched_files", []) or [] if is_auditable_source_path(f)]
            if not touched:
                continue
            if is_non_audit_patch_description(card.get("description", ""), touched):
                continue
            for f in touched:
                boosts.setdefault(f, {"score": 0, "cards": []})
                boosts[f]["score"] += max(10, int(card.get("score", 0)) // 4)
                boosts[f]["cards"].append(card.get("id", "patch"))
    except Exception:
        return boosts
    return boosts


def _patch_age_penalty(date_str: str) -> int:
    """Mild per-card age decay for s1-patch cards.

    Older fixes have had more time for follow-up fuzzing and downstream
    refactoring, so the expected value of sibling-mining them decreases
    over time. The penalty is intentionally mild — old code can still
    have variant bugs (sleeping patterns copy-pasted into recent code,
    cross-file propagations the original fix didn't address) — so we
    cap at -30 points, never zeroing the card.

    A 1-year-old fix loses 3 points; a 10+ year-old fix loses 30.
    Targets where the bulk of the patch corpus is decades old (e.g.,
    pcre2 whose 2014 cards are the PCRE2-from-PCRE fork import) end
    up with most s1-patch cards in the 107..140 band — still in the
    queue, but ranked below fresher structural work.
    """
    if not date_str or not isinstance(date_str, str):
        return 0
    # Accept YYYY-MM-DD or YYYY/MM/DD or bare YYYY.
    try:
        year_str = date_str[:4]
        if not (len(year_str) == 4 and year_str.isdigit()):
            return 0
        year = int(year_str)
        from datetime import datetime as _dt
        now_year = _dt.utcnow().year
        years_old = max(0, now_year - year)
        return -min(30, years_old * 3)
    except Exception:
        return 0


def _recent_touched_files(target_root: Path, days: int = 180) -> set[str]:
    """Files modified in the last `days` days, target-relative.

    Captures the real sibling-bug signal: "is the fix site still being
    actively edited?" A 2014 fix in code that was rewritten in 2024 is
    high-value (variant patterns may have been re-introduced); a 2014
    fix in dormant code is low-value (years of OSS-Fuzz on top of it).
    Best-effort: returns empty set on git failure or on a non-git tree.

    Cached at call site via _recent_touched_files_for; callers should
    use that wrapper, not this function, so the git invocation only
    fires once per workqueue load.
    """
    if not target_root or not target_root.is_dir():
        return set()
    git_dir = target_root / ".git"
    if not git_dir.exists():
        return set()
    try:
        import subprocess
        result = subprocess.run(
            ["git", "-C", str(target_root), "log",
             f"--since={int(days)}.days", "--name-only", "--pretty=format:"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return set()
        return {line.strip() for line in result.stdout.splitlines() if line.strip()}
    except Exception:
        return set()


def _recent_touched_files_for(ctx: Context | None) -> set[str]:
    """Memoised per-Context wrapper around _recent_touched_files."""
    if ctx is None:
        return set()
    cached = getattr(ctx, "_recent_touched_cache", None)
    if cached is not None:
        return cached
    out = _recent_touched_files(ctx.target_root)
    try:
        ctx._recent_touched_cache = out  # type: ignore[attr-defined]
    except Exception:
        pass
    return out


def load_patch_cards(path: Path, limit: int = 40, ctx: Context | None = None) -> list[dict]:
    cards = read_jsonl(path)
    recent_files = _recent_touched_files_for(ctx)
    out = []
    for card in cards:
        if card.get("kind") != "s1-patch":
            continue
        touched_files = [f for f in card.get("touched_files", []) or [] if is_auditable_source_path(f)]
        if is_non_audit_patch_description(card.get("description", ""), touched_files):
            continue
        if not touched_files:
            continue
        base_score = int(card.get("score", 0)) + 80
        # Age penalty: down-weight old fixes whose surrounding code has
        # been re-audited/fuzzed extensively. Capped at -30.
        age_penalty = _patch_age_penalty(card.get("date", ""))
        # Recency-of-touched-files boost: if any touched file has been
        # modified in the last 180 days, the fix site is still under
        # churn — sibling-bug probability is meaningfully higher.
        recency_boost = 20 if (recent_files and any(f in recent_files for f in touched_files)) else 0
        score = max(1, base_score + age_penalty + recency_boost)
        reason_extra = []
        if age_penalty:
            reason_extra.append(f"age penalty {age_penalty}")
        if recency_boost:
            reason_extra.append(f"recently-touched boost +{recency_boost}")
        reason_str = "prior-fix patch card; " + (card.get("reason") or "ranked from issue/VCS metadata")
        if reason_extra:
            reason_str = reason_str + "; " + "; ".join(reason_extra)
        work = {
            "id": card.get("id", ""),
            "kind": "s1-patch",
            "target_slug": card.get("target_slug", ""),
            "subsystem": subsystem_for(touched_files[0]),
            "file": touched_files[0],
            "function": "",
            "mode": "auto",
            "strategy": "S1",
            "score": score,
            "seed": "",
            "patch_cards": [card.get("id", "")],
            "reason": reason_str,
            "status": "unclaimed",
            "created_at": now_iso(),
            "description": card.get("description", ""),
            "fix_hashes": card.get("fix_hashes", []),
            "testcase_hashes": card.get("testcase_hashes", []),
            "invalid_fix_hashes": card.get("invalid_fix_hashes", []),
            "invalid_testcase_hashes": card.get("invalid_testcase_hashes", []),
            "touched_files": touched_files,
            "issue_id": card.get("issue_id", ""),
        }
        out.append(work)
    out.sort(key=lambda c: (-int(c["score"]), c["id"]))
    return dedupe_work_cards(out)[:limit]


def code_feature_reasons(text: str) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    for pattern, pts, reason in CODE_PATTERNS:
        matches = len(pattern.findall(text))
        if matches:
            # Presence-only reasons (the S8 property surfaces) score once,
            # not per match: one `clamp()` is as indicative as four, and the
            # per-match ×4 multiplier would otherwise let a repetition-dense
            # but low-confidence S8 file outrank a single high-signal S7
            # input-consumption entrypoint. Other rows keep the multiplier —
            # many memcpy/parse calls genuinely raise a file's interest.
            if reason in _PRESENCE_ONLY_REASONS:
                score += pts
            else:
                score += min(pts * matches, pts * 4)
            reasons.append(reason)
    return score, reasons


def corpus_seed_for(results_dir: Path, rel: str, subsystem: str) -> str:
    corpus = results_dir / "corpus"
    if not corpus.is_dir():
        return ""
    candidates: list[tuple[float, str]] = []
    rel_low = rel.lower()
    sub_low = subsystem.lower()
    for meta in corpus.glob("COVER-*/metadata.md"):
        try:
            body = meta.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        score = 0
        body_low = body.lower()
        if rel_low in body_low:
            score += 10
        if sub_low in body_low:
            score += 6
        if score == 0:
            continue
        tests = [p for p in meta.parent.iterdir() if p.name != "metadata.md" and p.is_file() and not p.name.endswith(".asan.txt")]
        if tests:
            candidates.append((score + meta.stat().st_mtime / 10_000_000_000, tests[0].as_posix()))
    if not candidates:
        return ""
    return sorted(candidates, reverse=True)[0][1]


def coverage_subsystem_counts(ctx: Context, depth: int | None = None) -> dict[str, int]:
    """Return observed coverage-edge counts grouped by source subsystem."""
    if depth is None:
        depth = _subsystem_depth()
    coverage_dir = ctx.results_dir / "coverage"
    if not coverage_dir.is_dir():
        return {}
    counts: dict[str, int] = {}
    for journal in sorted(coverage_dir.glob("edges-agent-*.journal")):
        try:
            lines = journal.read_text(encoding="utf-8", errors="replace").splitlines()
        except Exception:
            continue
        for line in lines:
            if "|" not in line:
                continue
            edge_file = line.split("|", 1)[1].rsplit(":", 1)[0]
            if not edge_file or edge_file == "??":
                continue
            path = Path(edge_file)
            if path.is_absolute():
                try:
                    edge_file = path.resolve().relative_to(ctx.target_root.resolve()).as_posix()
                except Exception:
                    edge_file = path.as_posix()
            rel = normalized_relpath(edge_file)
            parts = [p for p in rel.split("/") if p]
            if not parts:
                continue
            subsystem = "/".join(parts[: max(1, depth)])
            counts[subsystem] = counts.get(subsystem, 0) + 1
    return counts


def coverage_gap_score(counts: dict[str, int], subsystem: str) -> tuple[int, list[str]]:
    if not counts:
        return 0, []
    if subsystem not in counts:
        return 10, ["coverage gap subsystem"]
    low_water = max(1, min(counts.values()))
    if counts[subsystem] <= low_water:
        return 4, ["low-coverage subsystem"]
    return 0, []


def structural_path_score(rel: str) -> tuple[int, list[str]]:
    """Score path shape without target-specific names.

    Files near tests and shallow library directories tend to be easier to
    exercise. Deep paths get a small penalty unless code features or patch
    cards compensate.
    """
    parts = [p for p in rel.split("/") if p]
    score = 0
    reasons: list[str] = []
    depth = len(parts)
    if depth <= 3:
        score += 6
        reasons.append("shallow source path")
    elif depth >= 7:
        score -= 4
        reasons.append("deep source path")
    name = Path(rel).name
    stem = Path(rel).stem
    if any(ch.isupper() for ch in stem) or "_" in stem:
        score += 2
        reasons.append("named implementation unit")
    return score, reasons


def rank_target(ctx: Context, limit: int, patch_cards: Path | None = None) -> list[dict]:
    if not ctx.target_root.is_dir():
        raise SystemExit(f"[rank-work] target not found: {ctx.target_root}")
    patch_path = patch_cards or (ctx.results_dir / "patch-cards.jsonl")
    patch_boosts = load_patch_boosts(patch_path)
    # First pass: collect auditable source paths so we can auto-pick the
    # subsystem partition depth before any work-card builds a subsystem
    # label. Header-only / monolithic targets get a deeper default; targets
    # with diverse depth-2 prefixes keep the historical depth=2 behavior.
    source_paths: list[tuple[Path, str]] = []
    for path in iter_source_files(ctx.target_root):
        rel = relpath(path, ctx.target_root)
        if not is_auditable_source_path(rel):
            continue
        source_paths.append((path, rel))
    init_subsystem_depth(
        (rel for _, rel in source_paths),
        persist_to=ctx.results_dir / "state" / "subsystem-depth",
    )
    coverage_counts = coverage_subsystem_counts(ctx)
    cards: list[dict] = load_patch_cards(patch_path, max(10, limit // 2), ctx=ctx)
    floor_cards: list[dict] = []
    seen_ids = {c.get("id") for c in cards}
    seen_surfaces = {work_surface(c) for c in cards}
    diversity_floor = int(os.environ.get("RANK_WORK_DIVERSITY_FLOOR", "12") or "12")
    for path, rel in source_paths:
        text = read_sample(path)
        score = 0
        reasons: list[str] = []
        path_score, path_reasons = structural_path_score(rel)
        score += path_score
        reasons.extend(path_reasons)
        feature_score, feature_reasons = code_feature_reasons(text)
        score += feature_score
        reasons.extend(feature_reasons)
        patch_info = patch_boosts.get(rel)
        if patch_info:
            score += patch_info["score"]
            reasons.append("near prior-fix card")
        subsystem = subsystem_for(rel)
        gap_score, gap_reasons = coverage_gap_score(coverage_counts, subsystem)
        score += gap_score
        reasons.extend(gap_reasons)
        seed = corpus_seed_for(ctx.results_dir, rel, subsystem)
        if seed:
            score += 16
            reasons.append("has clean HIT seed")
        primary_strategy = strategy_for(reasons)
        h = hashlib.sha1(f"{ctx.target_slug}:{rel}".encode()).hexdigest()[:12]
        card = {
            "id": f"WORK-{h}",
            "kind": "ranked-source",
            "target_slug": ctx.target_slug,
            "subsystem": subsystem,
            "file": rel,
            "function": "",
            "mode": mode_for_file(rel),
            "strategy": primary_strategy,
            "score": score,
            "seed": seed,
            "patch_cards": (patch_info or {}).get("cards", []),
            "reason": "; ".join(dict.fromkeys(reasons)),
            "status": "unclaimed",
            "created_at": now_iso(),
        }
        surface = work_surface(card)
        if score <= 0:
            if diversity_floor > 0 and card["id"] not in seen_ids and surface not in seen_surfaces:
                card["score"] = 1
                card["strategy"] = "S1"
                card["reason"] = "diversity floor: source file outside regex scorer"
                floor_cards.append(card)
            continue
        if card["id"] not in seen_ids and surface not in seen_surfaces:
            cards.append(card)
            seen_ids.add(card["id"])
            seen_surfaces.add(surface)

            # Emit companion cards for high-value files: when several
            # diagnostic signals fire on the same file, generate a
            # separate card per strategy so one file supports multiple
            # angles of attack. Without this, work_surface keying on
            # strategy still collapses everything because rank_target
            # only ever produced one card per file. Companions inherit
            # the parent's score / patch boost minus a small offset so
            # the primary still leads the queue.
            companions = complementary_strategies(reasons, primary_strategy)
            companion_cap = _int_env("RANK_WORK_PER_FILE_COMPANIONS", 2)
            for idx, comp_strategy in enumerate(companions[:companion_cap]):
                ch = hashlib.sha1(
                    f"{ctx.target_slug}:{rel}:{comp_strategy}".encode()
                ).hexdigest()[:12]
                comp_id = f"WORK-{ch}"
                comp_card = dict(card)
                comp_card["id"] = comp_id
                comp_card["strategy"] = comp_strategy
                comp_card["score"] = max(1, int(card["score"]) - (idx + 1))
                comp_card["reason"] = (
                    f"companion strategy {comp_strategy} for {primary_strategy}; "
                    + str(card.get("reason", ""))
                )
                comp_surface = work_surface(comp_card)
                if comp_id in seen_ids or comp_surface in seen_surfaces:
                    continue
                cards.append(comp_card)
                seen_ids.add(comp_id)
                seen_surfaces.add(comp_surface)
        elif surface in seen_surfaces and feature_reasons:
            for existing in cards:
                if work_surface(existing) != surface:
                    continue
                existing_reasons = [r for r in str(existing.get("reason", "")).split("; ") if r]
                merged = list(dict.fromkeys([*existing_reasons, *feature_reasons]))
                existing["reason"] = "; ".join(merged)
                existing["score"] = int(existing.get("score", 0)) + min(feature_score, 20)
                break
    cards.sort(key=work_card_sort_key)
    if diversity_floor <= 0 or not floor_cards or len(cards) >= limit and limit <= 1:
        return cards[:limit]
    reserve = min(diversity_floor, max(1, limit // 5), len(floor_cards))
    selected_floor = select_diversity_floor(floor_cards, reserve, seen_ids)
    main_limit = max(0, limit - len(selected_floor))
    return dedupe_work_cards(cards[:main_limit] + selected_floor)


def select_diversity_floor(cards: list[dict], limit: int, excluded_ids: set[str]) -> list[dict]:
    """Pick low-scoring cards across subsystems so regexes don't define scope."""
    if limit <= 0:
        return []
    by_subsystem: dict[str, list[dict]] = {}
    for card in cards:
        cid = card.get("id", "")
        if not cid or cid in excluded_ids:
            continue
        by_subsystem.setdefault(card.get("subsystem", "unknown"), []).append(card)
    for rows in by_subsystem.values():
        rows.sort(key=lambda c: (c.get("id", ""), c.get("file", "")))
    out: list[dict] = []
    while len(out) < limit and by_subsystem:
        for subsystem in sorted(list(by_subsystem)):
            rows = by_subsystem.get(subsystem) or []
            if not rows:
                by_subsystem.pop(subsystem, None)
                continue
            out.append(rows.pop(0))
            if len(out) >= limit:
                break
    return out


def path_has_executable(name: str) -> bool:
    for directory in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return True
    return False


def llm_rerank_cards(ctx: Context, cards: list[dict], top_n: int = 160, timeout: int = 20) -> list[dict]:
    """Second-stage optional ranking over deterministic candidates.

    The first stage stays authoritative on availability: if the one-shot LLM
    decision is disabled, unavailable, times out, or returns malformed JSON,
    this returns the original cards unchanged.
    """
    if top_n <= 0 or not cards:
        return cards
    mock_present = "LLM_DECIDE_MOCK_WORK_RERANK" in os.environ or "LLM_DECIDE_MOCK" in os.environ
    # DISABLE blocks real backend calls but mocks still run — mirrors
    # lib/llm_decide.py so a test mock keeps working with the global default.
    if not mock_present and os.environ.get("LLM_DECIDE_DISABLE") == "1":
        return cards
    engine = ctx.script_root / "lib" / "llm_decide.py"
    if not engine.is_file():
        return cards
    # No vendor default — ACTIVE_BACKEND must be set explicitly (unset or
    # empty both bail). If only a mock is present (tests), the backend name
    # is irrelevant because llm_decide.py short-circuits to the mock before
    # touching any binary.
    backend = os.environ.get("ACTIVE_BACKEND", "")
    if not mock_present and not backend:
        return cards
    # An empty binary override falls through to the vendor default; otherwise
    # path_has_executable("") would silently fail the preflight.
    if not mock_present and backend == "claude" and not path_has_executable(os.environ.get("CLAUDE_BIN") or "claude"):
        return cards
    if not mock_present and backend == "codex" and not path_has_executable(os.environ.get("CODEX_BIN") or "codex"):
        return cards
    if not mock_present and backend == "oss" and not path_has_executable(os.environ.get("OPENCODE_BIN") or "opencode"):
        return cards

    top = cards[: min(top_n, len(cards))]
    candidate_lines = []
    for c in top:
        candidate_lines.append(
            json.dumps(
                {
                    "id": c.get("id", ""),
                    "kind": c.get("kind", ""),
                    "file": c.get("file", ""),
                    "subsystem": c.get("subsystem", ""),
                    "strategy": c.get("strategy", ""),
                    "score": c.get("score", 0),
                    "reason": c.get("reason", ""),
                },
                sort_keys=True,
            )
        )

    from prompt_render import render_template  # lazy: see import note at top
    max_boost = int(os.environ.get("RANK_WORK_LLM_MAX_BOOST", "30") or "30")
    prompt = render_template("work_rerank.md.j2", {
        "max_boost": str(max_boost),
        "candidate_lines": "\n".join(candidate_lines),
    })

    # Rerank verdicts are a function of the rendered prompt (the candidate
    # set + max_boost) AND of who answers it. The queue refresh runs every
    # iteration but the top-N candidate set is usually unchanged between
    # refreshes, and each miss costs a ~10-20s LLM round-trip in the
    # iteration boundary — so memoize the parsed boosts (including the
    # "no boosts" outcome) keyed by sha1 over the prompt plus the decider
    # identity. Any card mutation, re-scoring, reordering, backend swap,
    # or model swap changes the key and re-asks. The active mock value
    # (tests) keys the cache too, so swapping a mock verdict always
    # re-decides instead of replaying the previous mock's boosts.
    mock_key = os.environ.get("LLM_DECIDE_MOCK_WORK_RERANK") or os.environ.get("LLM_DECIDE_MOCK") or ""
    resolved_model = os.environ.get("MODEL", "")
    if not resolved_model:
        try:
            from llm_invoke import default_model
            resolved_model = default_model(backend)
        except Exception:
            resolved_model = ""
    decider_key = f"{backend}\x00{resolved_model}\x00{mock_key}"
    cache_path = state_dir(ctx.results_dir) / ".work-rerank-cache.json"
    prompt_sha = hashlib.sha1((prompt + "\x00" + decider_key).encode("utf-8", "replace")).hexdigest()
    boosts: dict[str, tuple[int, str]] | None = None
    try:
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        if cached.get("prompt_sha1") == prompt_sha and isinstance(cached.get("boosts"), dict):
            boosts = {
                str(cid): (int(pair[0]), str(pair[1]))
                for cid, pair in cached["boosts"].items()
            }
    except Exception:
        boosts = None

    if boosts is None:
        try:
            from llm_usage import find_usage_index

            raw = subprocess.check_output(
                [
                    sys.executable, str(engine), "decide", "work_rerank", "cards",
                    str(int(timeout)), "--usage-index",
                    str(find_usage_index(ctx.results_dir)),
                ],
                input=prompt,
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=timeout + 5,
            )
            data = json.loads(raw)
        except Exception:
            return cards

        boosts = {}
        for item in data.get("cards", []) if isinstance(data, dict) else []:
            cid = str(item.get("id", ""))
            if not cid:
                continue
            try:
                boost = int(item.get("boost", 0))
            except Exception:
                continue
            if boost <= 0:
                continue
            reason = str(item.get("reason", ""))[:100]
            boosts[cid] = (min(boost, max_boost), reason)

        try:
            cache_path.parent.mkdir(parents=True, exist_ok=True)
            # PID-unique temp name: two refreshes racing on the same
            # RESULTS_DIR must not interleave writes into one temp file.
            tmp = cache_path.with_name(f"{cache_path.name}.{os.getpid()}.tmp")
            tmp.write_text(
                json.dumps({"prompt_sha1": prompt_sha, "boosts": {k: list(v) for k, v in boosts.items()}}),
                encoding="utf-8",
            )
            tmp.replace(cache_path)
        except Exception:
            pass

    if not boosts:
        return cards
    out = []
    for card in cards:
        card = dict(card)
        cid = card.get("id", "")
        if cid in boosts:
            boost, reason = boosts[cid]
            card["score"] = int(card.get("score", 0)) + boost
            if reason:
                existing = card.get("reason", "")
                card["reason"] = (existing + "; " if existing else "") + "llm-rerank: " + reason
        out.append(card)
    out.sort(key=work_card_sort_key)
    return out


def work_card_sort_key(card: dict) -> tuple[int, int, str]:
    kind_priority = 0 if card.get("kind") == "s1-patch" else 1
    return (kind_priority, -int(card.get("score", 0)), card.get("file", ""))


def severity_score(sev: str) -> int:
    s = (sev or "").lower()
    if "critical" in s:
        return 50
    if "high" in s:
        return 40
    if "moderate" in s:
        return 25
    if "low" in s:
        return 10
    return 18


def commit_files(ctx: Context, rev: str) -> list[str]:
    if not rev or rev == "NOT_FOUND" or ctx.repo_type == "none":
        return []
    cmd: list[str]
    if ctx.repo_type == "hg":
        cmd = ["hg", "-R", str(ctx.target_root), "log", "-r", rev, "--template", "{files}\n"]
    else:
        cmd = ["git", "-C", str(ctx.target_root), "show", "--name-only", "--format=", rev]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True, timeout=8)
    except Exception:
        return []
    files = []
    for tok in re.split(r"[\s\r\n]+", out.strip()):
        if tok and is_auditable_source_path(tok):
            files.append(tok)
    return sorted(dict.fromkeys(files))


def revision_exists(ctx: Context, rev: str) -> bool | None:
    """Return True/False for known VCS repos, None when metadata is unavailable."""
    if not rev or rev == "NOT_FOUND":
        return False
    if ctx.repo_type == "none":
        return None
    if ctx.repo_type == "hg":
        cmd = ["hg", "-R", str(ctx.target_root), "log", "-r", rev, "--template", "{node}\n"]
    else:
        cmd = ["git", "-C", str(ctx.target_root), "cat-file", "-e", f"{rev}^{{commit}}"]
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True, timeout=8)
        return True
    except Exception:
        return False


def validate_revisions(ctx: Context, revisions: list[str]) -> tuple[list[str], list[str]]:
    valid: list[str] = []
    invalid: list[str] = []
    for rev in revisions:
        exists = revision_exists(ctx, rev)
        if exists is False:
            invalid.append(rev)
        else:
            # Keep revisions when VCS metadata is unavailable. Dropping them
            # would erase useful issue CSV context for source snapshots.
            valid.append(rev)
    return valid, invalid


def split_hashes(raw: str) -> list[str]:
    if not raw:
        return []
    return [h.strip() for h in re.split(r"[,;\s]+", raw) if h.strip() and h.strip() != "NOT_FOUND"]


def infer_subsystem_from_files(files: list[str], desc: str = "") -> str:
    if files:
        return subsystem_for(files[0])
    return "unknown"


def row_get(row: dict, aliases: Iterable[str]) -> str:
    normalized = {re.sub(r"[^a-z0-9]+", "", k.lower()): v for k, v in row.items()}
    for alias in aliases:
        key = re.sub(r"[^a-z0-9]+", "", alias.lower())
        val = normalized.get(key)
        if val:
            return str(val)
    return ""


def likely_hash_columns(row: dict) -> list[str]:
    cols = []
    for key in row:
        nk = re.sub(r"[^a-z0-9]+", "", key.lower())
        if "hash" in nk or "commit" in nk or "revision" in nk:
            cols.append(key)
    return cols


# S1 prior-fix scan window. build_patch_cards scores the commits in this
# window and emits only the top `limit`; the window must therefore be wider
# than the output count, or a repo whose tip is dominated by sync-bot / test
# churn (e.g. mozilla-unified) never reaches a real defect fix. The scan is one
# `git log` / `hg log` and per-row work is pure-Python — VCS-sourced commit
# hashes skip subprocess validation — so a wide window is cheap.
#
# The default is sized for *security* recall, not a fixed commit count. A flat
# count is the wrong axis: commit velocity varies by orders of magnitude across
# targets, so one count is a low-velocity project's entire history yet only a
# thin recent slice of a high-velocity one — starving prior-fix mining exactly
# where the history is richest. Instead the default scans the most recent
# _PATCH_SCAN_LOOKBACK_DAYS days, capped at _PATCH_SCAN_MAX_COUNT commits,
# whichever is smaller: a low-velocity target gets its full recent history, a
# high-velocity one gets multi-year coverage, and neither scans an unbounded
# backlog. The count cap is a scan-cost ceiling, not a recall target — it only
# binds for a repo whose 5-year history alone exceeds it. PATCH_SCAN_WINDOW (or
# --scan-window) still pins an absolute commit count, honoured verbatim with no
# date floor, as an escape hatch for an operator who wants a specific raw scan.
_PATCH_SCAN_MAX_COUNT = 25000
_PATCH_SCAN_LOOKBACK_DAYS = 5 * 365


def _patch_scan_window() -> tuple[int, int | None]:
    """Resolve the S1 scan bound as (max_commits, lookback_days).

    Default: the most recent _PATCH_SCAN_LOOKBACK_DAYS days, capped at
    _PATCH_SCAN_MAX_COUNT commits (whichever is smaller). PATCH_SCAN_WINDOW,
    when a positive integer, pins an absolute commit count used verbatim with
    no date floor (lookback_days None) — mirroring the --scan-window flag — so
    an operator can deliberately widen or narrow the raw scan.
    """
    raw = os.environ.get("PATCH_SCAN_WINDOW", "").strip()
    if raw.isdigit() and int(raw) > 0:
        return int(raw), None
    return _PATCH_SCAN_MAX_COUNT, _PATCH_SCAN_LOOKBACK_DAYS


# Subprocess ceiling for the `git`/`hg log` window scan. The 25k-commit default
# makes the log sizeable and hg is slow on a large history, so the old fixed 10s
# bound could time out on a mega repo and silently return no S1 cards (the empty
# scan then hits the dormant fallback, which also times out, leaving S1 blind).
# 60s is ample headroom for the default scan — git finishes in well under a
# second, hg in a few — while still failing fast on a genuinely stuck log rather
# than hanging the work-card refresh.
_VCS_LOG_TIMEOUT = 60


def _git_is_shallow(target_root: Path) -> bool:
    """True when `target_root` is a shallow git clone.

    Cheap path first: a normal (.git-directory) repo is shallow iff
    .git/shallow exists, so the common non-shallow case spawns nothing.
    Worktrees / submodules (.git is a file) fall back to `git rev-parse`.
    """
    git_dir = target_root / ".git"
    if git_dir.is_dir():
        return (git_dir / "shallow").is_file()
    if not git_dir.exists():
        return False
    try:
        out = subprocess.check_output(
            ["git", "-C", str(target_root), "rev-parse",
             "--is-shallow-repository"],
            stderr=subprocess.DEVNULL, text=True, timeout=8,
        ).strip()
    except Exception:
        return False
    return out == "true"


def _git_shallow_boundary(target_root: Path) -> set[str]:
    """Full SHAs of the shallow-boundary commits (their parent is truncated).

    `git show`/diff on a boundary commit treats the missing parent as the empty
    tree, so it reports every file that already existed as "added" — a fix card
    would then claim files it never touched (an S1 false positive on an
    externally-supplied shallow checkout). `.git/shallow` is the authoritative
    list; reading it is cheap and needs no subprocess. Empty when the repo is
    not shallow or the list can't be read, so a full clone (the harness default)
    costs nothing and the guard is a no-op.
    """
    git_dir = target_root / ".git"
    if not git_dir.is_dir():
        return set()
    shallow = git_dir / "shallow"
    try:
        return {ln.strip() for ln in shallow.read_text().splitlines() if ln.strip()}
    except OSError:
        return set()


def build_patch_cards(
    ctx: Context, limit: int, inspect_commits: int,
    scan_window: int | None = None,
) -> list[dict]:
    if scan_window is not None and scan_window > 0:
        count, lookback_days = scan_window, None   # explicit override: verbatim count
    else:
        count, lookback_days = _patch_scan_window()
    rows: list[dict] = vcs_log_rows(ctx, count, lookback_days)
    if not rows and lookback_days:
        # Dormant target: its newest commit predates the lookback, so the
        # date-bounded scan came back empty. Fall back to a count-only scan so
        # S1 still mines the (stale but real) prior fixes rather than silently
        # producing nothing and looking like a worthless strategy.
        rows = vcs_log_rows(ctx, count)

    # Surface a shallow clone: it silently caps S1 history depth, so the
    # operator should know the requested window could not be honoured. The
    # harness itself never shallow-clones (setup-target / export-repro both do
    # a full clone), so this only fires for an externally-supplied checkout;
    # deepening is left to the operator rather than run as network I/O in the
    # audit hot path.
    if ctx.repo_type == "git" and len(rows) < count \
            and _git_is_shallow(ctx.target_root):
        print(
            f"[patch-cards] {ctx.target_slug}: scanned {len(rows)} commit(s) "
            f"but a window of {count} was requested — repository is a "
            f"shallow clone, so S1 prior-fix history is truncated. Run "
            f"`git -C {ctx.target_root} fetch --unshallow` for full depth.",
            file=sys.stderr,
        )

    # Commit hashes read straight from `git log` / `hg log` provably
    # exist, so validate_revisions' per-row `git cat-file` / `hg log -r`
    # subprocess is pure waste — and on hg it costs ~0.5s/row, which is
    # what made a wide scan window unaffordable. Only externally-sourced
    # rows (none today; kept for a future CSV path) need validation.
    vcs_sourced = ctx.repo_type in ("git", "hg")

    # ── Pass 1: parse and pre-score every row without touching the VCS
    # for file metadata. The pre-score (severity + revision/date/defect-
    # keyword signal) decides which rows earn a commit_files lookup, so
    # the inspection budget lands on the highest-signal commits anywhere
    # in the window — not merely the newest, which on churn-heavy repos
    # are sync-bot noise.
    parsed: list[dict] = []
    for idx, row in enumerate(reversed(rows)):
        desc = row_get(row, ("description", "subject", "title", "summary"))
        severity = row_get(row, ("severity", "priority", "rating", "impact"))
        date = row_get(row, ("date", "fixed date", "published", "created", "when"))
        hashes: list[str] = []
        for col in likely_hash_columns(row):
            if "test" in col.lower():
                continue
            hashes.extend(split_hashes(str(row.get(col, ""))))
        hashes = list(dict.fromkeys(hashes))
        testcase_hashes: list[str] = []
        for key, val in row.items():
            if "test" in key.lower() and ("hash" in key.lower() or "commit" in key.lower() or "revision" in key.lower()):
                testcase_hashes.extend(split_hashes(str(val)))
        testcase_hashes = list(dict.fromkeys(testcase_hashes))
        if vcs_sourced:
            invalid_hashes: list[str] = []
            invalid_testcase_hashes: list[str] = []
        else:
            hashes, invalid_hashes = validate_revisions(ctx, hashes)
            testcase_hashes, invalid_testcase_hashes = validate_revisions(ctx, testcase_hashes)
        prescore = (
            severity_score(severity)
            + (12 if hashes else 0)
            + (8 if testcase_hashes else 0)
            + (4 if date else 0)
            + patch_audit_boost(desc)
            - (12 if invalid_hashes else 0)
            - (8 if invalid_testcase_hashes else 0)
        )
        parsed.append({
            "idx": idx, "row": row, "desc": desc, "severity": severity,
            "date": date, "hashes": hashes, "testcase_hashes": testcase_hashes,
            "invalid_hashes": invalid_hashes,
            "invalid_testcase_hashes": invalid_testcase_hashes,
            "prescore": prescore, "touched": [],
        })

    # ── Inspection: spend the commit_files budget on the top rows by
    # pre-score. Ties resolve by idx (recency) for deterministic output.
    # Skip file lookups on shallow-boundary commits: their diff-against-the-
    # empty-tree reports pre-existing files as touched, which would fabricate
    # the card's `touched_files` (empty for a full clone, so this is a no-op
    # there). The boundary card can still surface on its fix hash alone.
    shallow_boundary = (
        _git_shallow_boundary(ctx.target_root) if ctx.repo_type == "git" else set()
    )
    for entry in sorted(
        parsed, key=lambda e: (-e["prescore"], e["idx"]),
    )[:max(0, inspect_commits)]:
        touched: list[str] = []
        for h in entry["hashes"][:4]:
            if h in shallow_boundary:
                continue
            touched.extend(commit_files(ctx, h))
        entry["touched"] = sorted(dict.fromkeys(
            f for f in touched if is_auditable_source_path(f)))

    # ── Pass 2: finalize cards now that file metadata is known.
    cards: list[dict] = []
    for entry in parsed:
        desc = entry["desc"]
        touched = entry["touched"]
        hashes = entry["hashes"]
        testcase_hashes = entry["testcase_hashes"]
        invalid_hashes = entry["invalid_hashes"]
        invalid_testcase_hashes = entry["invalid_testcase_hashes"]
        if is_non_audit_patch_description(desc, touched):
            continue
        if not touched and not hashes and not testcase_hashes and not invalid_hashes and not invalid_testcase_hashes:
            continue
        reasons: list[str] = []
        score = severity_score(entry["severity"]) + min(30, len(touched) * 3)
        if hashes:
            score += 12
            reasons.append("has fix revision")
        if invalid_hashes:
            score -= 12
            reasons.append("invalid fix revision")
        if testcase_hashes:
            score += 8
            reasons.append("has testcase revision")
        if invalid_testcase_hashes:
            score -= 8
            reasons.append("invalid testcase revision")
        if entry["date"]:
            score += 4
            reasons.append("dated prior fix")
        if not touched:
            score -= 10
            reasons.append("no touched file metadata")
        if not hashes and not touched:
            score -= 10
        # Boost cards whose commit description names a real defect class.
        # This is what surfaces "fix UAF in X" above "release-1.34.0".
        boost = patch_audit_boost(desc)
        if boost:
            score += boost
            reasons.append("defect-class keyword in commit")
        subsystem = infer_subsystem_from_files(touched, desc)
        row = entry["row"]
        card_id_src = "|".join(hashes or invalid_hashes or testcase_hashes or invalid_testcase_hashes) or f"{entry['idx']}:{desc}"
        card = {
            "id": "PATCH-" + hashlib.sha1(card_id_src.encode()).hexdigest()[:12],
            "kind": "s1-patch",
            "target_slug": ctx.target_slug,
            "source": "vcs-log",
            "date": entry["date"],
            "issue_id": row_get(row, ("id", "issue", "ticket", "bug", "bug id", "bug ids", "cve", "advisory")),
            "description": desc,
            "severity": entry["severity"],
            "fix_hashes": hashes,
            "testcase_hashes": testcase_hashes,
            "invalid_fix_hashes": invalid_hashes,
            "invalid_testcase_hashes": invalid_testcase_hashes,
            "touched_files": touched,
            "subsystem": subsystem,
            "mode": "auto",
            "strategy": "S1",
            "score": score,
            "reason": "; ".join(reasons) or "prior-fix row",
            "status": "unclaimed",
            "created_at": now_iso(),
            "raw_columns": {k: row.get(k, "") for k in list(row.keys())[:12]},
        }
        cards.append(card)
    cards.sort(key=lambda c: (-int(c["score"]), c.get("date", ""), c["id"]))
    deduped: list[dict] = []
    seen: set[str] = set()
    for card in cards:
        if card.get("touched_files"):
            if not is_auditable_work_card(card):
                continue
            key = work_surface(card)
        else:
            key = str(card.get("id", ""))
        if not key or key in seen:
            continue
        seen.add(key)
        deduped.append(card)
        if len(deduped) >= limit:
            break
    return deduped


def vcs_log_rows(ctx: Context, limit: int,
                 lookback_days: int | None = None) -> list[dict]:
    # A positive lookback bounds the scan to commits on or after `since`, so the
    # window is min(most-recent `limit`, commits within lookback) — this is what
    # normalizes recall across commit velocity. `since` is an absolute date so
    # both VCSes parse it identically (git --since / hg -d ">…").
    since = None
    if lookback_days and lookback_days > 0:
        since = (datetime.now(timezone.utc)
                 - timedelta(days=lookback_days)).strftime("%Y-%m-%d")
    if ctx.repo_type == "hg":
        cmd = [
            "hg",
            "-R",
            str(ctx.target_root),
            "log",
            "-l",
            str(limit),
            "--template",
            "{node|short}\t{date|shortdate}\t{desc|firstline}\n",
        ]
        if since:
            cmd += ["-d", f">{since}"]
        try:
            out = subprocess.check_output(
                cmd,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=_VCS_LOG_TIMEOUT,
            )
        except Exception:
            return []
        rows = []
        for line in out.splitlines():
            parts = line.split("\t", 2)
            if len(parts) != 3:
                continue
            rows.append({"commit": parts[0], "Date": parts[1], "Description": parts[2], "Severity": ""})
        # hg log returns newest first. build_patch_cards() consumes rows from
        # the end so the inspection budget is spent on recent changes first.
        return list(reversed(rows))
    if ctx.repo_type != "git":
        return []
    git_cmd = [
        "git",
        "-C",
        str(ctx.target_root),
        "log",
        "--format=%H%x09%cs%x09%s",
        f"-n{limit}",
    ]
    if since:
        git_cmd.append(f"--since={since}")
    try:
        out = subprocess.check_output(
            git_cmd,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=_VCS_LOG_TIMEOUT,
        )
    except Exception:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3:
            continue
        rows.append({"commit": parts[0], "Date": parts[1], "Description": parts[2], "Severity": ""})
    # git log returns newest first. build_patch_cards() consumes rows from
    # the end so the inspection budget is spent on recent changes first.
    return list(reversed(rows))


def state_dir(results_dir: Path) -> Path:
    return results_dir / "state"


@contextlib.contextmanager
def jsonl_lock(path: Path):
    """Serialize writers for one JSONL state file.

    Atomic rename protects readers from partial files, but it does not protect
    read-modify-write callers from racing each other. A sibling lock file keeps
    those updates ordered without changing the append-only file format.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    with lock_path.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _read_jsonl_unlocked(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    out = []
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out


def _fsync_parent_dir(path: Path) -> None:
    try:
        fd = os.open(str(path.parent), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _write_jsonl_unlocked(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as f:
            tmp_name = f.name
            for row in rows:
                f.write(json.dumps(row, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, path)
        _fsync_parent_dir(path)
    finally:
        if tmp_name:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass


def _append_jsonl_unlocked(path: Path, obj: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def append_jsonl(path: Path, obj: dict) -> None:
    with jsonl_lock(path):
        _append_jsonl_unlocked(path, obj)


def _append_jsonl_many_unlocked(path: Path, rows: list[dict]) -> None:
    """Append a batch with one open/flush/fsync.

    Appending row by row costs a durability round-trip each time, which turns
    one housekeeping pass over a few hundred findings into a few hundred fsyncs.
    A caller that already holds the lock and the batch should pay for it once.
    """
    if not rows:
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        for obj in rows:
            f.write(json.dumps(obj, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def read_jsonl(path: Path) -> list[dict]:
    return _read_jsonl_unlocked(path)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with jsonl_lock(path):
        _write_jsonl_unlocked(path, rows)


def update_jsonl(path: Path, update_fn) -> tuple[list[dict], object]:
    """Read, mutate, and rewrite one JSONL file under the same advisory lock."""
    with jsonl_lock(path):
        rows = _read_jsonl_unlocked(path)
        result = update_fn(rows)
        _write_jsonl_unlocked(path, rows)
        return rows, result


def is_active_hypothesis_status(status: str) -> bool:
    return (status or "") in {"PENDING", "INVESTIGATING", "NEEDS_TESTCASE"}


# Canonical hypothesis bug-class taxonomy (the sanitizer-oriented `diagnostic`
# field). This is the sink axis — distinct from bin/severity's security-impact
# primitive classes (heap_write, uaf_read, …), which score an already-confirmed
# crash. It backs bin/state add-hyp's --diagnostic choices (a human-input
# guardrail); keep in sync with bin/probe / safety_framing.
HYPOTHESIS_DIAGNOSTIC_CATEGORIES = ("bounds", "lifetime", "type", "size", "uninit", "state")


# Status keys returned by agent_counts(). Kept as a constant so CLI callers
# and tests can rely on the exact key set.
AGENT_COUNT_KEYS = (
    "pending",
    "investigating",
    "needs_testcase",
    "active",
    "discards",
    "env_blocked",
    "result",
)


def _classify_hypothesis_status(status: str) -> list[str]:
    """Map a raw status string to the bucket names it contributes to.

    Mirrors the regex semantics of `lib/structured_state.py`:
      * pending           = ^PENDING$
      * investigating     = ^INVESTIGATING$
      * needs_testcase    = ^NEEDS_TESTCASE$
      * active            = ^(PENDING|INVESTIGATING|NEEDS_TESTCASE)$
      * discards          = ^DISCARDED$
      * env_blocked       = ^ENV-BLOCKED$
      * result            = ^(CRASH|CRASH-|FIND|FIND-)
        i.e. any status that begins with CRASH or FIND, including the
        suffixed forms CRASH-DEDUPED, FIND-LOWPRIO, etc.
    """
    s = status or ""
    out: list[str] = []
    if s == "PENDING":
        out += ["pending", "active"]
    elif s == "INVESTIGATING":
        out += ["investigating", "active"]
    elif s == "NEEDS_TESTCASE":
        out += ["needs_testcase", "active"]
    elif s == "DISCARDED":
        out += ["discards"]
    elif s == "ENV-BLOCKED":
        out += ["env_blocked"]
    if s.startswith("CRASH") or s.startswith("FIND"):
        # CRASH/CRASH-*/FIND/FIND-* all count as a finding-bucket result.
        out += ["result"]
    return out


def agent_counts(ctx: Context, agent: str) -> dict[str, int]:
    """Single-pass status histogram for one agent's hypotheses.

    Replaces N separate `structured_state_agent_*_count` shell-outs (each
    spawning jq + reparsing the whole hypotheses.jsonl). Returns every key
    in `AGENT_COUNT_KEYS` — values default to 0 when state is missing or
    empty so callers never have to handle "no data" specially.
    """
    counts: dict[str, int] = {k: 0 for k in AGENT_COUNT_KEYS}
    if not agent:
        return counts
    rows = read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl")
    for row in rows:
        if (row.get("agent", "") or "") != agent:
            continue
        for bucket in _classify_hypothesis_status(row.get("status", "") or ""):
            counts[bucket] += 1
    return counts


def init_state(ctx: Context) -> None:
    sd = state_dir(ctx.results_dir)
    sd.mkdir(parents=True, exist_ok=True)
    for name in ("hypotheses.jsonl", "runs.jsonl", "claims.jsonl", "events.jsonl", "notes.jsonl"):
        (sd / name).touch(exist_ok=True)


def work_cards_path(ctx: Context) -> Path:
    return ctx.results_dir / "work-cards.jsonl"


# Card statuses that are permanently terminal: the work is done (or
# explicitly discarded) and there is nothing for a future probe to learn.
# The rotator's claim-eligibility check uses THIS set so cards in these
# states are never re-picked.
PERMANENT_TERMINAL_CARD_STATUSES = {"done", "discarded", "crash", "find"}

# Soft-terminal: env_blocked is a "current environment couldn't build /
# import this compilation unit." That's transient across fresh audit
# result sets, because fixing the build or flipping a feature flag starts
# with new state. Within one result set, however, repeatedly re-offering
# the same blocked card just burns agent turns re-proving the same target
# configuration. Keep the status distinct from discarded, but suppress it
# from same-run claiming.
SOFT_TERMINAL_CARD_STATUSES = {"blocked"}

# Union — used by callers that need "is this card considered closed for
# any reason right now" (e.g. env-block propagation, which shouldn't
# re-flag an already-blocked sibling).
TERMINAL_CARD_STATUSES = PERMANENT_TERMINAL_CARD_STATUSES | SOFT_TERMINAL_CARD_STATUSES

# After this many consecutive dry iterations at a previously-productive
# subsystem, the bug-cluster relaxation in _claim_next_card_locked
# stops protecting that subsystem from the diversity gate. The agent
# then rotates to fresh territory instead of re-investigating an
# already-closed bug. The subsystem is re-admitted automatically on the
# next productive iteration (the streak file is reset by
# bin/audit:reset_subsystem_dry_streak).
_PRODUCTIVE_DECAY_AFTER_ITERS = 2

# crash/find are *productive* terminal conclusions, not dead ends: a
# verified bug means the surface may hold more (a large file:strategy card
# often spans many bugs, each a different hypothesis). These stay claimable
# while the surface keeps yielding new distinct hypotheses (see
# card_closed_for_run); done/discarded/blocked are hard-closed for the run.
# Keep this a strict subset of PERMANENT_TERMINAL_CARD_STATUSES.
_PRODUCTIVE_TERMINAL_CARD_STATUSES = {"crash", "find"}

# A concrete productive card is retired once it has been re-concluded more
# times than it has distinct hypotheses: the surplus conclusions are
# re-discoveries of an already-recorded bug, not new ones. A margin of 1
# tolerates a single unproductive re-conclusion before closing. Applies only
# to concrete cards (see _is_broad_file_card / card_closed_for_run).
_PRODUCTIVE_REDISCOVERY_MARGIN = 1


def _is_broad_file_card(card: dict) -> bool:
    """A whole-file/strategy card whose search space is the file, not the
    hypotheses opened against it.

    ``ranked-source`` cards rank a whole file for a strategy; their bugs live
    across functions never yet hypothesised, so re-discovery is not an
    exhaustion proof for them. Concrete cards (patch cards)
    name a specific site, so their opened hypotheses *are* their search space.
    """
    return str(card.get("kind", "")) == "ranked-source"


def active_hypothesis_card_ids(ctx: Context) -> set[str]:
    active: set[str] = set()
    for row in read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl"):
        cid = row.get("card_id", "")
        if cid and is_active_hypothesis_status(row.get("status", "")):
            active.add(cid)
    return active


def active_hypothesis_surfaces(ctx: Context) -> set[str]:
    """Return file/surface keys currently owned by active hypotheses."""
    cards_by_id = {c.get("id", ""): c for c in read_jsonl(work_cards_path(ctx))}
    surfaces: set[str] = set()
    for row in read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl"):
        if not is_active_hypothesis_status(row.get("status", "")):
            continue
        cid = row.get("card_id", "")
        if cid and cid in cards_by_id:
            surface = work_surface(cards_by_id[cid])
        else:
            surface = normalized_relpath(row.get("file", "").split(":", 1)[0]).lower()
        if surface:
            surfaces.add(surface)
    return surfaces


def active_hypothesis_subsystems(ctx: Context) -> set[str]:
    cards_by_id = {c.get("id", ""): c for c in read_jsonl(work_cards_path(ctx))}
    subsystems: set[str] = set()
    for row in read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl"):
        if not is_active_hypothesis_status(row.get("status", "")):
            continue
        subsystem = str(row.get("subsystem", "") or "")
        cid = row.get("card_id", "")
        card = cards_by_id.get(cid) if cid else None
        if not subsystem and card:
            subsystem = str(card.get("subsystem", "") or "")
        if not subsystem:
            file = row.get("file", "").split(":", 1)[0]
            if file:
                subsystem = subsystem_for(file)
        if subsystem and subsystem != "unknown":
            subsystems.add(subsystem)
    return subsystems


def card_reject_skips_path(ctx: Context) -> Path:
    """JSONL of (card_id, agent) pairs the rejection gate has marked as
    do-not-revisit for this agent.

    Each row: {card_id, agent, crash_id, reason, created_at}. The queue
    consults this list per claim and skips any matching pair so the same
    agent isn't re-offered a surface whose previous filing the gate
    already rejected as caller-misuse / wrong-shape.
    """
    return state_dir(ctx.results_dir) / "card-reject-skips.jsonl"


def record_card_reject_skip(
    ctx: Context,
    card_id: str,
    agent: str,
    crash_id: str = "",
    reason: str = "",
) -> dict:
    """Append a do-not-revisit marker for (card_id, agent).

    Idempotent across crash_id: a second filing on the same card by the
    same agent is recorded as an additional row (so the audit trail is
    preserved) but the queue-side check only needs the (card_id, agent)
    pair to be present at all. Returns the row that was written.
    """
    init_state(ctx)
    cid = (card_id or "").strip()
    ag = (agent or "").strip()
    if not cid or not ag:
        raise ValueError("record_card_reject_skip requires card_id and agent")
    row = {
        "card_id": cid,
        "agent": ag,
        "crash_id": (crash_id or "").strip(),
        "reason": (reason or "").strip(),
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    path = card_reject_skips_path(ctx)
    with jsonl_lock(path):
        _append_jsonl_unlocked(path, row)
    return row


def card_reject_skips_for_agent(ctx: Context, agent: str) -> set[str]:
    """Return the set of card_ids this agent must skip on future claims.

    Reads the do-not-revisit ledger and filters to the requesting agent.
    Empty for agents with no prior rejections. Used as a hard skip in
    _claim_next_card_locked so a rejected surface stops being re-offered
    to the agent that already filed against it.
    """
    if not agent:
        return set()
    ag = str(agent).strip()
    path = card_reject_skips_path(ctx)
    skipped: set[str] = set()
    for row in read_jsonl(path):
        if str(row.get("agent", "")).strip() != ag:
            continue
        cid = str(row.get("card_id", "")).strip()
        if cid:
            skipped.add(cid)
    return skipped


def _crash_origin_from_hyps(hyps: list[dict], crash_id: str) -> dict | None:
    """Find the hypothesis row (from an already-read list) that filed `crash_id`.

    Hypothesis filings store the crash id in the row's `status` field as
    "CRASH-<id>" (see bin/state update-hyp / add-hyp). Newest-row-wins per id.
    Split from `lookup_crash_origin` so callers holding hypotheses.jsonl in
    memory can reuse the match without a second read.
    """
    cid_target = (crash_id or "").strip()
    if not cid_target:
        return None
    latest: dict[str, dict] = {}
    for row in hyps:
        hid = str(row.get("id", "")).strip()
        if hid:
            latest[hid] = row
    cid_norm = cid_target.upper()
    for row in latest.values():
        status = str(row.get("status", "")).strip().upper()
        # Status is either an exact "CRASH-NNN-M" or starts with the id;
        # match either to tolerate "CRASH-001-1 (duplicate)" decorations.
        if status == cid_norm or status.startswith(cid_norm + " "):
            return row
    return None


def lookup_crash_origin(ctx: Context, crash_id: str) -> dict | None:
    """Find the hypothesis row that filed `crash_id`, if any.

    Walks hypotheses.jsonl and returns the matching row so callers (the
    rejection gate) can recover the originating card_id + agent without
    scanning the crash dir bundle.
    """
    return _crash_origin_from_hyps(
        read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl"), crash_id
    )


def claim_row_expiry(row: dict, ttl: timedelta) -> datetime | None:
    expires_at = parse_iso_utc(row.get("expires_at", ""))
    if expires_at is not None:
        return expires_at
    claimed_at = parse_iso_utc(row.get("claimed_at", "")) or parse_iso_utc(row.get("updated_at", ""))
    if claimed_at is None:
        return None
    return claimed_at + ttl


def claim_blocks_card(row: dict | None, ttl: timedelta, now: datetime) -> bool:
    if not row or row.get("status", "claimed") != "claimed":
        return False
    expires_at = claim_row_expiry(row, ttl)
    return expires_at is not None and expires_at > now


def latest_claims_by_card(ctx: Context) -> dict[str, dict]:
    latest: dict[str, dict] = {}
    for claim in read_jsonl(state_dir(ctx.results_dir) / "claims.jsonl"):
        cid = claim.get("card_id", "")
        if cid:
            latest[cid] = claim
    return latest


def latest_terminal_status_by_card(ctx: Context) -> dict[str, str]:
    """Per-card last real terminal status (crash/find/done/discarded/blocked).

    Ignores stale-lease bookkeeping rows. Used to resolve a card whose latest
    row is a lifecycle mask (``released``, or an expired ``claimed`` that reads
    back as ``unclaimed``) to the conclusion it hides, so status-only consumers
    do not mistake a mined card for available work.
    """
    out: dict[str, str] = {}
    for claim in read_jsonl(state_dir(ctx.results_dir) / "claims.jsonl"):
        cid = claim.get("card_id", "")
        st = str(claim.get("status", ""))
        if cid and st in TERMINAL_CARD_STATUSES and claim.get("source", "") != "release-stale-claims":
            out[cid] = st
    return out


def release_stale_claims(
    ctx: Context,
    grace: timedelta | None = None,
    now: datetime | None = None,
) -> list[dict]:
    """Release claims whose hypotheses no longer justify the lease.

    A claim is "stale" if it is in `claimed` status AND any of:
      * The card has no active hypothesis (PENDING, INVESTIGATING,
        NEEDS_TESTCASE) opened against it.
      * Every hypothesis opened against the card is terminal
        (DISCARDED/CRASH/FIND/etc.) — the card was explored and the
        agent moved on, so the surface should reopen.
      * The latest claim is older than `grace` and no run touched
        the card since (covers killed/wedged sessions).

    Returns the list of release rows appended to claims.jsonl. Pure
    bookkeeping: no card statuses change, only the `claimed` lease
    is dropped.
    """
    init_state(ctx)
    if grace is None:
        grace = timedelta(seconds=_int_env("WORK_CARD_CLAIM_GRACE_SECONDS", 5 * 60))
    if now is None:
        now = datetime.now(timezone.utc)

    claim_rows = read_jsonl(state_dir(ctx.results_dir) / "claims.jsonl")
    latest: dict[str, dict] = {}
    latest_terminal: dict[str, dict] = {}
    for claim in claim_rows:
        cid = claim.get("card_id", "")
        if not cid:
            continue
        latest[cid] = claim
        if claim.get("status", "") in TERMINAL_CARD_STATUSES:
            latest_terminal[cid] = claim
    if not latest:
        return []

    # Bucket hypotheses by card so we can answer "any active?" cheaply.
    hyps_by_card: dict[str, list[dict]] = {}
    for h in read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl"):
        cid = h.get("card_id", "")
        if cid:
            hyps_by_card.setdefault(cid, []).append(h)

    last_run_by_card: dict[str, datetime] = {}
    for r in read_jsonl(state_dir(ctx.results_dir) / "runs.jsonl"):
        cid = r.get("card_id", "")
        if not cid:
            continue
        ts = parse_iso_utc(r.get("created_at", ""))
        if ts is None:
            continue
        prev = last_run_by_card.get(cid)
        if prev is None or ts > prev:
            last_run_by_card[cid] = ts

    released: list[dict] = []
    for cid, claim in latest.items():
        if claim.get("status", "") != "claimed":
            continue  # already released or terminal
        hyps = hyps_by_card.get(cid, [])
        any_active = any(is_active_hypothesis_status(h.get("status", "")) for h in hyps)
        if any_active:
            continue
        # No active hypothesis. Decide release reason.
        reason: str
        if not hyps:
            claimed_at = parse_iso_utc(claim.get("claimed_at", "")) or parse_iso_utc(claim.get("updated_at", ""))
            if claimed_at is None or now - claimed_at < grace:
                # Brand-new claim; give the agent a moment to attach a hypothesis.
                continue
            last_run = last_run_by_card.get(cid)
            if last_run is not None and now - last_run < grace:
                continue
            reason = "no-hypothesis-after-grace"
        else:
            reason = "all-hypotheses-terminal"
        prior_terminal = latest_terminal.get(cid)
        row = {
            "card_id": cid,
            "agent": claim.get("agent", ""),
            "status": prior_terminal.get("status", "released") if prior_terminal else "released",
            "updated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "released_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "reason": reason,
            "source": "release-stale-claims",
        }
        if prior_terminal:
            row["preserved_terminal_status"] = prior_terminal.get("status", "")
        append_jsonl(state_dir(ctx.results_dir) / "claims.jsonl", row)
        released.append(row)
    return released


def claimed_card_surfaces(ctx: Context, ttl: timedelta, now: datetime) -> set[str]:
    cards_by_id = {c.get("id", ""): c for c in read_jsonl(work_cards_path(ctx))}
    surfaces: set[str] = set()
    for cid, claim in latest_claims_by_card(ctx).items():
        if not claim_blocks_card(claim, ttl, now):
            continue
        card = cards_by_id.get(cid)
        if not card:
            continue
        surface = work_surface(card)
        if surface:
            surfaces.add(surface)
    return surfaces


def claimed_card_subsystems(ctx: Context, ttl: timedelta, now: datetime) -> set[str]:
    cards_by_id = {c.get("id", ""): c for c in read_jsonl(work_cards_path(ctx))}
    subsystems: set[str] = set()
    for cid, claim in latest_claims_by_card(ctx).items():
        if not claim_blocks_card(claim, ttl, now):
            continue
        card = cards_by_id.get(cid)
        if not card:
            continue
        subsystem = str(card.get("subsystem", "") or "")
        if subsystem and subsystem != "unknown":
            subsystems.add(subsystem)
    return subsystems


def subsystem_dry_streak(ctx: Context, subsystem: str) -> int:
    """Read the global per-subsystem dry-iteration counter.

    The orchestrator maintains `.subsystem_dry_<slug>` flat files under
    ``RESULTS_DIR``. The file holds the number of consecutive iterations
    during which the subsystem produced no new CRASH/FIND. A productive
    iteration removes it.

    Returns 0 when the file is absent or unreadable (productive
    subsystem on the current iteration, or never tracked).
    """
    if not subsystem or subsystem == "unknown":
        return 0
    slug = subsystem.replace("/", "_")
    path = ctx.results_dir / f".subsystem_dry_{slug}"
    try:
        raw = path.read_text(encoding="utf-8", errors="ignore").strip()
    except (FileNotFoundError, OSError):
        return 0
    try:
        return max(0, int(raw))
    except ValueError:
        return 0


def record_subsystem_iteration(ctx: Context, subsystem: str, productive: bool) -> bool:
    """Reset or advance one subsystem's consecutive dry-iteration count.

    This is called once per touched subsystem, not once per agent. Two agents
    mining the same area therefore cannot age it twice as fast, while a result
    from either agent resets the shared count.
    """
    if not subsystem or subsystem == "unknown":
        return True
    slug = subsystem.replace("/", "_")
    path = ctx.results_dir / f".subsystem_dry_{slug}"
    if productive:
        try:
            path.unlink(missing_ok=True)
            return True
        except OSError:
            return False
    value = subsystem_dry_streak(ctx, subsystem) + 1
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(f"{value}\n", encoding="utf-8")
        os.replace(temporary, path)
        return True
    except OSError:
        return False
    finally:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass


def card_closed_for_run(
    ctx: Context,
    card: dict,
    status: str,
    *,
    conclusion_counts: dict[str, int] | None = None,
    distinct_counts: dict[str, int] | None = None,
    dry_streaks: dict[str, int] | None = None,
) -> bool:
    """Is a card at ``status`` closed for the *current* run (not re-offerable)?

    ``done``/``discarded``/``blocked`` are hard-closed. ``crash``/``find`` are
    productive conclusions whose retirement is **scope-aware**, because the
    right exhaustion signal depends on what the card covers:

    * **Concrete cards** (patch cards) name one specific
      site, so the hypotheses opened against them *are* their search space.
      They retire once re-concluded more times than they have distinct
      hypotheses (``conclusions - distinct >= _PRODUCTIVE_REDISCOVERY_MARGIN``)
      — the surplus conclusions are re-discoveries of an already-recorded bug.

    * **Broad ranked-source cards** cover a whole file/strategy, whose search
      space is far larger than the hypotheses tried so far. ``conclusions -
      distinct`` is NOT a valid exhaustion proof there: one bug plus a
      duplicate crash would close the whole file before its other functions
      are explored. These keep the file-level signal — retire once the
      subsystem has gone dry for ``_PRODUCTIVE_DECAY_AFTER_ITERS`` iterations
      (``subsystem_dry_streak``, reset only by triage-promoted artifacts on
      disk, so a fabricated crash cannot keep a dry file alive).

    An expired ``claimed`` lease can mask a prior productive conclusion by
    reading back as ``unclaimed``. When the card
    has a recorded productive conclusion, it is treated as productive-terminal
    so neither mask reopens a mined card. A *live* claim (status ``claimed``)
    is left open — the owner is still investigating. The anti-camp guarantee
    stays separate: ``card_conclusion_counts`` demotes an already-cracked card
    below fresher siblings so a still-open surface is revisited least-mined-
    first.

    ``conclusion_counts``/``distinct_counts``/``dry_streaks`` are optional
    per-call memos so a candidate loop reads state at most once.
    """
    cid = card.get("id", "")
    if conclusion_counts is None:
        conclusion_counts = card_conclusion_counts(ctx)
    concluded = conclusion_counts.get(cid, 0) if cid else 0
    # Resolve an expired-lease mask back to the conclusion it hides, but
    # leave a live "claimed" open — its owner is still investigating (docstring).
    is_productive = status in _PRODUCTIVE_TERMINAL_CARD_STATUSES or (
        status == "unclaimed" and concluded > 0
    )
    if not is_productive:
        # done/discarded/blocked hard-close; anything else stays claimable.
        return status in TERMINAL_CARD_STATUSES
    if not cid:
        return True
    if _is_broad_file_card(card):
        subsystem = str(card.get("subsystem", "") or "")
        if not subsystem or subsystem == "unknown":
            return True
        if dry_streaks is None:
            streak = subsystem_dry_streak(ctx, subsystem)
        else:
            streak = dry_streaks.get(subsystem)
            if streak is None:
                streak = subsystem_dry_streak(ctx, subsystem)
                dry_streaks[subsystem] = streak
        return streak >= _PRODUCTIVE_DECAY_AFTER_ITERS
    if distinct_counts is None:
        distinct = card_distinct_hypothesis_count(ctx, cid)
    else:
        distinct = distinct_counts.get(cid, 0)
    return concluded - distinct >= _PRODUCTIVE_REDISCOVERY_MARGIN


def agent_productive_subsystems(ctx: Context, agent: str) -> set[str]:
    """Subsystems where the given agent has a confirmed CRASH/FIND row.

    Used to relax the subsystem-ownership skip in
    ``_claim_next_card_locked``: "bugs cluster" is a real signal (a
    confirmed crash means the agent has working knowledge of the
    subsystem's data flow and parser quirks). After a hit, that agent
    should be allowed to expand to neighbouring files within the same
    subsystem (and even into other subsystems) even when other agents
    nominally "own" those areas — AGENTS.md says the agent should
    cluster, but without this relaxation the per-iteration subsystem
    lock prevents it.

    A subsystem ends up in this set when ANY of the agent's hypotheses
    in that subsystem resolved with a CRASH-* or FIND-* status. The claim
    path applies a short dry-iteration decay so this historical signal does
    not keep an exhausted area preferred forever.
    """
    if not agent:
        return set()
    agent_str = str(agent)
    cards_by_id = {c.get("id", ""): c for c in read_jsonl(work_cards_path(ctx))}
    subsystems: set[str] = set()
    for row in read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl"):
        if str(row.get("agent", "")) != agent_str:
            continue
        status = str(row.get("status", "") or "")
        if not (status.startswith("CRASH") or status.startswith("FIND")):
            continue
        subsystem = str(row.get("subsystem", "") or "")
        cid = row.get("card_id", "")
        card = cards_by_id.get(cid) if cid else None
        if not subsystem and card:
            subsystem = str(card.get("subsystem", "") or "")
        if not subsystem:
            file = row.get("file", "").split(":", 1)[0]
            if file:
                subsystem = subsystem_for(file)
        if subsystem and subsystem != "unknown":
            subsystems.add(subsystem)
    return subsystems


def agent_current_subsystem(ctx: Context, agent: str) -> str:
    """Return the subsystem represented by an agent's latest live/result row."""
    selected = [
        row for row in read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl")
        if str(row.get("agent", "")) == str(agent)
    ]
    if not selected:
        return ""
    relevant = [
        row for row in selected
        if str(row.get("status", "")).startswith(
            ("PENDING", "INVESTIGATING", "NEEDS_TESTCASE", "ENV-BLOCKED", "CRASH", "FIND")
        )
    ]
    row = relevant[-1] if relevant else selected[-1]
    subsystem = str(row.get("subsystem", "") or "")
    if not subsystem:
        card_id = str(row.get("card_id", "") or "")
        if card_id:
            cards = {
                str(card.get("id", "")): card
                for card in read_jsonl(work_cards_path(ctx))
            }
            subsystem = str((cards.get(card_id) or {}).get("subsystem", "") or "")
    if not subsystem:
        source = str(row.get("file", "") or "").split(":", 1)[0]
        subsystem = subsystem_for(source) if source else ""
    return "" if subsystem == "unknown" else subsystem


# Card `mode` describes the execution surface needed by the testcase. The
# agent `mode` describes the worker interface. Sanitizer-backed cards are
# still ordinary reproduce work for generic/shell workers; treating these as
# exact-match-only strands high-value sanitizer cards when bin/audit launches
# generic agents against an ASan target.
SANITIZER_WORK_CARD_MODES = frozenset({
    "asan",
    "ubsan",
    "msan",
    "tsan",
    "race",
    "runner",
})


def card_mode_matches(card_mode: str, agent_mode: str) -> bool:
    card_mode = card_mode or "auto"
    agent_mode = agent_mode or ""
    return (
        not agent_mode
        or card_mode in ("", "auto", agent_mode, "generic")
        or (agent_mode == "generic" and card_mode == "js")
        or (agent_mode == "shell" and card_mode == "js")
        or (agent_mode in ("generic", "shell") and card_mode in SANITIZER_WORK_CARD_MODES)
    )


def visible_card_status(row: dict | None, ttl: timedelta | None = None, now: datetime | None = None) -> str:
    if not row:
        return "unclaimed"
    status = row.get("status", "claimed") or "claimed"
    if status != "claimed":
        return status
    ttl = ttl or work_card_claim_ttl()
    now = now or datetime.now(timezone.utc)
    return "claimed" if claim_blocks_card(row, ttl, now) else "unclaimed"


def apply_latest_claim_status(ctx: Context, cards: list[dict]) -> list[dict]:
    latest = latest_claims_by_card(ctx)
    ttl = work_card_claim_ttl()
    now = datetime.now(timezone.utc)
    out: list[dict] = []
    for card in cards:
        updated = dict(card)
        updated["status"] = visible_card_status(latest.get(card.get("id", "")), ttl, now)
        out.append(updated)
    return out


def _active_hypothesis_queue_sets(
    cards_by_id: dict[str, dict],
    hypotheses: list[dict],
) -> tuple[set[str], set[str], set[str]]:
    active_cards: set[str] = set()
    active_surfaces: set[str] = set()
    active_subsystems: set[str] = set()
    for row in hypotheses:
        if not is_active_hypothesis_status(row.get("status", "")):
            continue
        cid = row.get("card_id", "")
        card = cards_by_id.get(cid) if cid else None
        if cid:
            active_cards.add(cid)
        if card:
            surface = work_surface(card)
        else:
            surface = normalized_relpath(row.get("file", "").split(":", 1)[0]).lower()
        if surface:
            active_surfaces.add(surface)
        subsystem = str(row.get("subsystem", "") or "")
        if not subsystem and card:
            subsystem = str(card.get("subsystem", "") or "")
        if not subsystem:
            file = row.get("file", "").split(":", 1)[0]
            if file:
                subsystem = subsystem_for(file)
        if subsystem and subsystem != "unknown":
            active_subsystems.add(subsystem)
    return active_cards, active_surfaces, active_subsystems


def _claimed_card_queue_sets(
    cards_by_id: dict[str, dict],
    latest_claims: dict[str, dict],
    ttl: timedelta,
    now: datetime,
) -> tuple[set[str], set[str]]:
    claimed_surfaces: set[str] = set()
    claimed_subsystems: set[str] = set()
    for cid, claim in latest_claims.items():
        if not claim_blocks_card(claim, ttl, now):
            continue
        card = cards_by_id.get(cid)
        if not card:
            continue
        surface = work_surface(card)
        if surface:
            claimed_surfaces.add(surface)
        subsystem = str(card.get("subsystem", "") or "")
        if subsystem and subsystem != "unknown":
            claimed_subsystems.add(subsystem)
    return claimed_surfaces, claimed_subsystems


def _queue_status_row(
    card: dict,
    *,
    ctx: Context,
    conclusion_counts: dict[str, int],
    distinct_counts: dict[str, int],
    dry_streaks: dict[str, int],
    latest: dict[str, dict],
    ttl: timedelta,
    now: datetime,
    active_cards: set[str],
    active_surfaces: set[str],
    claimed_surfaces: set[str],
    owned_subsystems: set[str],
    agent_modes: list[str],
    strategy: str = "",
) -> dict:
    cid = card.get("id", "")
    reason = "eligible"
    status = visible_card_status(latest.get(cid), ttl, now)
    surface = work_surface(card)
    if not is_auditable_work_card(card):
        reason = "not-auditable"
    elif card_closed_for_run(
        ctx, card, status,
        conclusion_counts=conclusion_counts, distinct_counts=distinct_counts,
        dry_streaks=dry_streaks,
    ):
        # done/discarded/blocked; a concrete crash/find re-concluded past its
        # distinct hypotheses; or a broad ranked-source crash/find whose
        # subsystem has gone dry. A productive card still yielding (concrete)
        # or on a still-hot file (broad) is NOT closed here — it stays
        # eligible so the run keeps mining the surface for other bugs.
        reason = f"terminal:{status}"
    elif strategy and not card_strategy_matches(card, strategy):
        reason = f"strategy-incompatible:{card.get('strategy') or 'none'}"
    elif cid in active_cards:
        reason = "active-hypothesis"
    elif surface and surface in active_surfaces:
        reason = "active-surface"
    elif status == "claimed":
        claim = latest.get(cid, {})
        expiry = claim_row_expiry(claim, ttl)
        expires_at = claim.get("expires_at", "") or (
            expiry.strftime("%Y-%m-%dT%H:%M:%SZ") if expiry is not None else ""
        )
        reason = "claimed"
        if expires_at:
            reason = f"claimed-until:{expires_at}"
    elif surface and surface in claimed_surfaces:
        reason = "claimed-surface"
    elif (card.get("mode") or "auto") in ("", "auto", "generic") and card.get("subsystem", "") in owned_subsystems:
        reason = "claimed-subsystem"
    elif agent_modes and not any(card_mode_matches(card.get("mode") or "auto", mode) for mode in agent_modes):
        reason = f"mode-incompatible:{card.get('mode') or 'auto'}"
    return {
        "id": cid,
        "kind": card.get("kind", ""),
        "file": card.get("file", ""),
        "subsystem": card.get("subsystem", ""),
        "mode": card.get("mode") or "auto",
        "status": status,
        "reason": reason,
    }


def explain_queue(
    ctx: Context,
    agent_modes: list[str],
    strategy: str = "",
    cards: list[dict] | None = None,
) -> list[dict]:
    cards = list(cards) if cards is not None else read_jsonl(work_cards_path(ctx))
    cards_by_id = {c.get("id", ""): c for c in cards}
    latest = latest_claims_by_card(ctx)
    hypotheses = read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl")
    ttl = work_card_claim_ttl()
    now = datetime.now(timezone.utc)
    active_cards, active_surfaces, active_subsystems = _active_hypothesis_queue_sets(cards_by_id, hypotheses)
    claimed_surfaces, claimed_subsystems = _claimed_card_queue_sets(cards_by_id, latest, ttl, now)
    owned_subsystems = active_subsystems | claimed_subsystems
    conclusion_counts = card_conclusion_counts(ctx)
    distinct_counts = card_distinct_hypothesis_counts(ctx)
    dry_streaks: dict[str, int] = {}
    rows: list[dict] = []
    for card in cards:
        rows.append(
            _queue_status_row(
                card,
                ctx=ctx,
                conclusion_counts=conclusion_counts,
                distinct_counts=distinct_counts,
                dry_streaks=dry_streaks,
                latest=latest,
                ttl=ttl,
                now=now,
                active_cards=active_cards,
                active_surfaces=active_surfaces,
                claimed_surfaces=claimed_surfaces,
                owned_subsystems=owned_subsystems,
                agent_modes=agent_modes,
                strategy=strategy,
            )
        )
    return rows


def claim_next_card(
    ctx: Context,
    agent: str,
    mode: str = "",
    role: str = "",
    claim: bool = True,
    strategy: str = "",
) -> dict | None:
    init_state(ctx)
    claims_path = state_dir(ctx.results_dir) / "claims.jsonl"
    if claim:
        with jsonl_lock(claims_path):
            return _claim_next_card_locked(ctx, agent, mode, role, claims_path, claim=True, strategy=strategy)
    return _claim_next_card_locked(ctx, agent, mode, role, claims_path, claim=False, strategy=strategy)


def _claim_next_card_locked(
    ctx: Context,
    agent: str,
    mode: str,
    role: str,
    claims_path: Path,
    claim: bool,
    strategy: str = "",
) -> dict | None:
    cards = read_jsonl(work_cards_path(ctx))
    latest: dict[str, dict] = {}
    for row in _read_jsonl_unlocked(claims_path):
        cid = row.get("card_id", "")
        if cid:
            latest[cid] = row
    active_cards = active_hypothesis_card_ids(ctx)
    now = datetime.now(timezone.utc)
    ttl = work_card_claim_ttl()
    owned_surfaces = active_hypothesis_surfaces(ctx) | claimed_card_surfaces(ctx, ttl, now)
    owned_subsystems = active_hypothesis_subsystems(ctx) | claimed_card_subsystems(ctx, ttl, now)
    # Per-claim memos for card_closed_for_run (and the demotion sort below)
    # so the candidate loops read claims/hypotheses/dry-streaks at most once.
    conclusion_counts = card_conclusion_counts(ctx)
    distinct_counts = card_distinct_hypothesis_counts(ctx)
    dry_streaks: dict[str, int] = {}
    # Agents that have already produced a confirmed CRASH/FIND are
    # "productive" — they have working data-flow context for that
    # subsystem and bugs cluster, so the subsystem-ownership skip
    # should NOT block them from picking neighbouring cards. Without
    # this relaxation, an agent that found one bug in pcre2_serialize
    # would be locked out of the other 3 sibling bugs in the same file
    # because the per-iteration claim is already counted as "owning"
    # that subsystem. This implements the AGENTS.md "bugs cluster"
    # guidance the rest of the harness already encourages in prose.
    productive_subsystems = agent_productive_subsystems(ctx, agent)
    # Time-decay the productive-subsystem relaxation: after the global
    # dry-iter counter for a subsystem reaches PRODUCTIVE_DECAY_AFTER,
    # treat the area as mined out and drop it from the relaxation so
    # the agent rotates to fresh subsystems instead of re-investigating
    # an already-closed bug. Threshold lives in code (not env) — it's a
    # semantic boundary, not an operator tuning knob. If the subsystem
    # becomes productive again, the streak resets and the subsystem
    # is re-admitted on the next claim.
    if productive_subsystems:
        productive_subsystems = {
            s
            for s in productive_subsystems
            if subsystem_dry_streak(ctx, s) < _PRODUCTIVE_DECAY_AFTER_ITERS
        }

    # P5: cards whose previous filing by *this agent* was rejected at
    # the triage gate (e.g. caller-misuse "crashes"). Skip them so the
    # agent stops re-probing the same wrong-shape surface and rotates
    # to a new card instead. Per-agent on purpose: a different agent
    # might come at the same card from a different angle and find a
    # legitimate bug, so we don't drop the card from the global pool.
    rejected_card_ids = card_reject_skips_for_agent(ctx, agent)

    strategy_filter = strategy.strip().upper()

    def _build_candidates() -> list[dict]:
        out: list[dict] = []
        for card in cards:
            cid = card.get("id", "")
            if not is_auditable_work_card(card):
                continue
            if cid and cid in rejected_card_ids:
                # P5: previously rejected for this agent — do not re-offer.
                continue
            if strategy_filter:
                if not card_strategy_matches(card, strategy_filter):
                    continue
            latest_claim = latest.get(cid)
            # Resolve through the visible status (an expired "claimed" reads back
            # as "unclaimed") so the claimer's closed/eligible decision matches
            # explain_queue and the effective-work-cards overlay — otherwise a
            # mined card whose lease expired is silently re-offered here.
            latest_status = visible_card_status(latest_claim, ttl, now)
            blocks_card = claim_blocks_card(latest_claim, ttl, now)
            own_active_claim = bool(blocks_card and latest_claim and str(latest_claim.get("agent", "")) == str(agent))
            # Blocked cards are retryable in a fresh result set, but not in
            # the same run where the target configuration has already proven
            # the surface unreachable.
            if card_closed_for_run(ctx, card, latest_status, conclusion_counts=conclusion_counts, distinct_counts=distinct_counts, dry_streaks=dry_streaks) or cid in active_cards or (blocks_card and not own_active_claim):
                continue
            surface = work_surface(card)
            if surface and surface in owned_surfaces and not own_active_claim:
                continue
            if not card_mode_matches(card.get("mode") or "auto", mode):
                continue
            out.append(card)
        return out

    # Subsystem ownership is a SOFT preference, not a hard skip, and it
    # only applies in GENERIC mode. A focused-mode agent assigned to a
    # hot subsystem must be allowed to co-investigate alongside a
    # sibling — multiple angles on the same surface are exactly where
    # parallel exploration finds the most bugs. For generic agents we
    # prefer disjoint subsystems even on small queues; the
    # spread work even when only a few cards remain.
    def _apply_diversity(candidates: list[dict]) -> list[dict]:
        preferred: list[dict] = []
        for card in candidates:
            cid = card.get("id", "")
            latest_claim = latest.get(cid)
            own_active_claim = bool(
                latest_claim
                and str(latest_claim.get("agent", "")) == str(agent)
                and claim_blocks_card(latest_claim, ttl, now)
            )
            subsystem = str(card.get("subsystem", "") or "")
            generic_mode = (mode in ("generic", "shell")) or ((card.get("mode") or "auto") in ("", "auto", "generic") and not mode)
            if generic_mode and subsystem:
                # Productive-agent relaxation: an agent that already has a
                # confirmed CRASH/FIND in this subsystem keeps picking from
                # it (bug-cluster expansion). Without this, the
                # owned_subsystems lock prevents the very behaviour
                # AGENTS.md asks for ("bugs cluster — search SAME FILE and
                # neighbors before moving on").
                if (
                    subsystem in owned_subsystems
                    and not own_active_claim
                    and subsystem not in productive_subsystems
                ):
                    continue
            preferred.append(card)
        if not preferred:
            preferred = candidates
        return preferred

    preferred = _apply_diversity(_build_candidates())

    # Diminishing-returns demotion: a card kept eligible *after* a verified
    # crash/find (card_closed_for_run) sinks below every fresher
    # (zero-conclusion) candidate so the agent spreads out instead of
    # re-hitting the same card sequentially. Hot-file siblings naturally
    # sort ahead of unrelated cold work because they carry the file's
    # higher base rank (the stable sort preserves rank within a tier), so
    # this still mines the hot surface before rotating; a still-hot card
    # resurfaces once the less-mined work is exhausted, and no card is
    # dropped. An active same-agent lease is exempt — it keeps top priority
    # so the agent continues its own in-flight card instead of pivoting and
    # stranding the lease until TTL. Skipped when nothing has been concluded
    # yet (the common early-run case).
    if len(preferred) > 1:
        if conclusion_counts:
            def _demotion_key(c: dict) -> tuple[int, int]:
                cid = c.get("id", "")
                lc = latest.get(cid)
                own_active_lease = bool(
                    lc
                    and str(lc.get("agent", "")) == str(agent)
                    and claim_blocks_card(lc, ttl, now)
                )
                return (0 if own_active_lease else 1, conclusion_counts.get(cid, 0))

            preferred.sort(key=_demotion_key)

    for card in preferred:
        cid = card.get("id", "")
        if claim:
            claim_time = datetime.now(timezone.utc)
            claimed_at = claim_time.strftime("%Y-%m-%dT%H:%M:%SZ")
            expires_at = (claim_time + ttl).strftime("%Y-%m-%dT%H:%M:%SZ")
            claim_row = {
                "card_id": cid,
                "agent": agent,
                "mode": mode,
                "role": role,
                "status": "claimed",
                "claimed_at": claimed_at,
                "expires_at": expires_at,
            }
            _append_jsonl_unlocked(claims_path, claim_row)
        return card
    return None


class HypothesisStateError(ValueError):
    pass


class DuplicateHypothesisIdError(HypothesisStateError):
    pass


class AmbiguousHypothesisUpdateError(HypothesisStateError):
    pass


def add_hypothesis(ctx: Context, args: argparse.Namespace) -> dict:
    init_state(ctx)
    seed = f"{args.agent}:{args.file}:{args.hypothesis}:{now_iso()}"
    explicit_id = bool(args.id)
    hid = args.id or "H-" + hashlib.sha1(seed.encode()).hexdigest()[:10]
    row = {
        "id": hid,
        "agent": args.agent,
        "card_id": args.card_id or "",
        "hypothesis": args.hypothesis,
        "file": args.file,
        "input_shape": args.input_shape,
        "guard_gap": args.guard_gap,
        "diagnostic": args.diagnostic,
        "strategy": args.strategy,
        "status": args.status,
        "created_at": now_iso(),
        "updated_at": now_iso(),
    }
    hyp_path = state_dir(ctx.results_dir) / "hypotheses.jsonl"
    with jsonl_lock(hyp_path):
        existing_ids = {str(r.get("id", "")) for r in _read_jsonl_unlocked(hyp_path)}
        if explicit_id and hid in existing_ids:
            raise DuplicateHypothesisIdError(
                f"hypothesis id already exists: {hid}; omit --id or use an agent-scoped id"
            )
        if not explicit_id:
            counter = 0
            while hid in existing_ids:
                counter += 1
                hid = "H-" + hashlib.sha1(f"{seed}:{counter}".encode()).hexdigest()[:10]
                row["id"] = hid
        _append_jsonl_unlocked(hyp_path, row)

    # Claim-on-adopt remains useful for manual callers and old prompts that
    # pass a card id without having reserved it first. Normal prompt-time
    # assignment already claims the card; this path is idempotent because
    # claims.jsonl is append-only and claim_blocks_card uses the latest row
    # per card_id.
    if args.card_id:
        ttl = work_card_claim_ttl()
        now = datetime.now(timezone.utc)
        claims_path = state_dir(ctx.results_dir) / "claims.jsonl"
        with jsonl_lock(claims_path):
            latest_for_card = None
            for claim in _read_jsonl_unlocked(claims_path):
                if claim.get("card_id", "") == args.card_id:
                    latest_for_card = claim
            active_claim = claim_blocks_card(latest_for_card, ttl, now)
            same_agent_claim = bool(latest_for_card and str(latest_for_card.get("agent", "")) == str(args.agent))
            adopted_claim = bool(
                active_claim
                and same_agent_claim
                and latest_for_card
                and latest_for_card.get("source") == "add-hyp"
                and latest_for_card.get("hypothesis_id")
            )
            if (not active_claim or same_agent_claim) and not adopted_claim:
                claimed_at = now.strftime("%Y-%m-%dT%H:%M:%SZ")
                expires_at = (now + ttl).strftime("%Y-%m-%dT%H:%M:%SZ")
                _append_jsonl_unlocked(
                    claims_path,
                    {
                        "card_id": args.card_id,
                        "agent": args.agent,
                        "mode": "",
                        "role": "",
                        "status": "claimed",
                        "claimed_at": claimed_at,
                        "expires_at": expires_at,
                        "source": "add-hyp",
                        "hypothesis_id": hid,
                    },
                )
    return row


def _cluster_owner_agent(crash_id: str, num_agents: int = 0) -> str:
    """Return the filing agent for a crash, clamped to the live worker set."""
    core = re.sub(r"^(?:CRASH|FIND)-", "", (crash_id or "").strip(), flags=re.IGNORECASE)
    numbers = [part for part in core.split("-") if part.isdigit()]
    agent = int(numbers[-1]) if len(numbers) >= 2 else 1
    if not num_agents:
        raw = os.environ.get("NUM_AGENTS", "")
        num_agents = int(raw) if raw.isdigit() and int(raw) >= 1 else 0
    if num_agents and not 1 <= agent <= num_agents:
        agent = (agent - 1) % num_agents + 1
    return str(agent)


def add_cluster_hypotheses(
    ctx: Context, crash_id: str, rows: list[dict], strategy: str = "",
    *, num_agents: int = 0,
) -> dict:
    """Route crash-sibling leads into structured state under one JSONL lock."""
    init_state(ctx)
    agent = _cluster_owner_agent(crash_id, num_agents)
    hyp_path = state_dir(ctx.results_dir) / "hypotheses.jsonl"

    def surface_key(file_field: str, hypothesis: str) -> str:
        return f"{file_field.strip().lower()}::{' '.join(hypothesis.split()).lower()}"

    added = skipped = 0
    now = now_iso()
    with jsonl_lock(hyp_path):
        existing = _read_jsonl_unlocked(hyp_path)
        if not strategy:
            origin = _crash_origin_from_hyps(existing, crash_id)
            strategy = str(origin.get("strategy", "")).strip() if origin else ""
        strategy = strategy or "S5"
        existing_ids = {str(row.get("id", "")) for row in existing}
        seen = {
            surface_key(str(row.get("file", "")), str(row.get("hypothesis", "")))
            for row in existing
            if is_active_hypothesis_status(row.get("status", ""))
        }
        for item in rows[:3]:
            file_path = str(item.get("file", "")).strip() if isinstance(item, dict) else ""
            hypothesis = str(item.get("hypothesis", "")).strip() if isinstance(item, dict) else ""
            category = str(item.get("category", "")).strip().lower() if isinstance(item, dict) else ""
            if not file_path or not hypothesis:
                skipped += 1
                continue
            category = category if category in HYPOTHESIS_DIAGNOSTIC_CATEGORIES else "state"
            function = str(item.get("function", "")).strip()
            line = str(item.get("line", "")).strip()
            if (function or line not in ("", "0")) and file_path.count(":") < 2:
                file_path = ":".join(
                    part for part in (file_path, function, line if line != "0" else "") if part
                )
            key = surface_key(file_path, hypothesis)
            if key in seen:
                skipped += 1
                continue
            seed = f"{agent}:{file_path}:{hypothesis}:{now}:{added}"
            hypothesis_id = "H-" + hashlib.sha1(seed.encode()).hexdigest()[:10]
            counter = 0
            while hypothesis_id in existing_ids:
                counter += 1
                hypothesis_id = "H-" + hashlib.sha1(f"{seed}:{counter}".encode()).hexdigest()[:10]
            existing_ids.add(hypothesis_id)
            seen.add(key)
            _append_jsonl_unlocked(
                hyp_path,
                {
                    "id": hypothesis_id,
                    "agent": agent,
                    "card_id": "",
                    "hypothesis": hypothesis,
                    "file": file_path,
                    "input_shape": f"sibling of {crash_id}",
                    "guard_gap": "unknown",
                    "diagnostic": category,
                    "strategy": strategy,
                    "status": "PENDING",
                    "created_at": now,
                    "updated_at": now,
                },
            )
            added += 1
    return {"agent": agent, "added": added, "skipped": skipped}


# Note fingerprints that indicate an environmental / build wall: the
# next hypothesis on the same compilation unit will hit the same wall,
# so blocking sibling cards saves wasted sessions. Kept tight on
# purpose — these phrases name the failure (the runner couldn't import
# the extension, a header is missing, the loader rejected the .so) so
# false matches in narrative testcase notes are unlikely.
ENV_BLOCK_FINGERPRINT_RE = re.compile(
    r"ModuleNotFoundError"
    r"|ImportError"
    r"|cannot find [^\n]*?\.h\b"
    r"|missing [^\n]*?\.h\b"
    r"|unable to load shared library"
    r"|library not loaded",
    re.IGNORECASE,
)


def _block_card_unconditional(
    ctx: Context,
    card_id: str,
    agent: str,
    note: str,
    source: str,
) -> bool:
    """Mark a specific work card terminal `blocked`, regardless of fingerprint.

    Used when a hypothesis transitions to ``ENV-BLOCKED``: the card the
    hypothesis is associated with is *known* unreachable in the current
    environment (the agent just proved it). Re-offering it to a sibling
    agent in the same run just burns turns re-proving the same wall.
    Returns ``True`` if a new blocked claim row was appended, ``False``
    if the card was already terminal or the input was empty.
    """
    if not card_id:
        return False
    latest = latest_claims_by_card(ctx)
    cur = latest.get(card_id)
    if cur and cur.get("status", "") in TERMINAL_CARD_STATUSES:
        return False
    claims_path = state_dir(ctx.results_dir) / "claims.jsonl"
    with jsonl_lock(claims_path):
        _append_jsonl_unlocked(
            claims_path,
            {
                "card_id": card_id,
                "agent": agent or "",
                "status": "blocked",
                "updated_at": now_iso(),
                "source": source,
                "note": note or "env-blocked hypothesis on this card",
            },
        )
    return True


def _propagate_env_block_to_sibling_cards(
    ctx: Context, hyp_file: str, note: str, agent: str
) -> int:
    """Mark unclaimed work cards sharing the env-blocked hypothesis's
    compilation unit as terminal `blocked`.

    Triggered when ``update_hypothesis`` transitions a row to
    ``ENV-BLOCKED`` and ``note`` matches ``ENV_BLOCK_FINGERPRINT_RE``.
    Sibling cards = same directory, same filename stem (the part before
    the extension). Concretely, a hypothesis at ``yaml/_yaml.pyx:foo:1``
    propagates to cards on ``yaml/_yaml.{c,h,pxd}`` because they share
    the ``yaml/_yaml`` stem. Cards in unrelated subsystems are untouched.

    The hypothesis's *own* card is blocked unconditionally by
    ``_block_card_unconditional`` in ``update_hypothesis`` — that path
    does not require a fingerprint match because the agent already
    proved that specific surface is unreachable. The fingerprint regex
    here gates only the sibling-propagation expansion, which is the
    riskier "this build is broken too" inference.

    Bug-finding impact: zero. The blocked cards are unreachable in the
    current environment by definition — every sibling on the same
    compilation unit will fail to import / build for the same reason.
    The block is recorded against the live results dir only; a fresh
    run with a fixed environment regenerates the queue and re-evaluates.
    """
    if not note or not ENV_BLOCK_FINGERPRINT_RE.search(note):
        return 0
    file_path = hyp_file.split(":", 1)[0].strip()
    if not file_path:
        return 0
    hyp_stem = Path(file_path).with_suffix("")
    if not hyp_stem.name:
        return 0
    latest = latest_claims_by_card(ctx)
    claims_path = state_dir(ctx.results_dir) / "claims.jsonl"
    blocked = 0
    with jsonl_lock(claims_path):
        for card in read_jsonl(work_cards_path(ctx)):
            cid = card.get("id", "")
            if not cid:
                continue
            cur = latest.get(cid)
            if cur and cur.get("status", "") in TERMINAL_CARD_STATUSES:
                continue
            card_file = card.get("file", "")
            if not card_file:
                continue
            if Path(card_file).with_suffix("") != hyp_stem:
                continue
            _append_jsonl_unlocked(claims_path, {
                "card_id": cid,
                "agent": agent or "",
                "status": "blocked",
                "updated_at": now_iso(),
                "source": "env-block-propagation",
                "note": f"sibling of env-blocked hypothesis on {file_path}",
            })
            blocked += 1
    return blocked


def update_hypothesis(
    ctx: Context,
    hid: str,
    status: str,
    note: str = "",
    agent: str = "",
) -> dict | None:
    path = state_dir(ctx.results_dir) / "hypotheses.jsonl"
    def mutate(rows: list[dict]) -> dict | None:
        matches = [
            row
            for row in rows
            if row.get("id") == hid and (not agent or str(row.get("agent", "")) == str(agent))
        ]
        if len(matches) > 1:
            agents = ", ".join(sorted({str(row.get("agent", "")) for row in matches}))
            scope = f" for agent {agent}" if agent else ""
            raise AmbiguousHypothesisUpdateError(
                f"hypothesis id {hid}{scope} is ambiguous across {len(matches)} rows"
                f"{f' (agents: {agents})' if agents else ''}; rerun with --agent or use unique ids"
            )
        found = matches[0] if matches else None
        if (
            found
            and str(status).upper().startswith("CRASH")
            and _unfinished_crash_reports_for_agent(ctx, str(found.get("agent", "")))
        ):
            raise HypothesisStateError(
                f"update-hyp refuses {status} for {hid}: this agent has an "
                "unfinished crash report. Complete its `_TODO (agent):` fields first."
            )
        for row in rows:
            if row is found:
                row["status"] = status
                row["updated_at"] = now_iso()
                if note:
                    row["note"] = note
        return found

    _rows, found = update_jsonl(path, mutate)
    if found and status == "ENV-BLOCKED":
        # The hypothesis's own card is blocked unconditionally — the
        # agent just proved this surface is unreachable in the current
        # environment, so re-offering it to a sibling agent is wasted
        # work even when the note doesn't match ENV_BLOCK_FINGERPRINT_RE.
        _block_card_unconditional(
            ctx,
            card_id=str(found.get("card_id", "") or ""),
            agent=str(found.get("agent", "") or ""),
            note=note or str(found.get("note", "") or ""),
            source="env-block-own-card",
        )
        # Sibling propagation (different cards on the same compilation
        # unit) still requires a fingerprint match — that's the broader
        # "this whole compilation unit is broken" inference, which
        # warrants extra evidence before flipping cards the agent
        # didn't directly touch.
        _propagate_env_block_to_sibling_cards(
            ctx,
            found.get("file", ""),
            note or found.get("note", ""),
            found.get("agent", ""),
        )
    return found


def card_run_count(ctx: Context, card_id: str, verdict: str = "") -> int:
    """How many runs.jsonl rows reference this card.

    When ``verdict`` is given (e.g. "CRASH"), count only rows with that
    verdict. The crash-close gate in update_card_status uses
    verdict="CRASH" as the harness-written evidence that a crash was
    actually reproduced; the separate report-completeness gate prevents
    closure while the filed bundle is still a skeleton. Card-discard evidence
    is stricter and goes through ``card_discard_evidence``.
    """
    if not card_id:
        return 0
    want = verdict.upper()
    n = 0
    for r in read_jsonl(state_dir(ctx.results_dir) / "runs.jsonl"):
        if r.get("card_id", "") != card_id:
            continue
        if want and str(r.get("verdict", "") or "").upper() != want:
            continue
        n += 1
    return n


def card_conclusion_counts(ctx: Context) -> dict[str, int]:
    """Per-card tally of productive terminal closures (crash/find) ever
    recorded in claims.jsonl.

    Used by the claim ranker to *demote* — never drop — a card that has
    already produced a bug. A verified crash/find keeps the surface
    claimable (card_closed_for_run), but re-offering the same high-scored
    card first every iteration would camp it sequentially instead of
    spreading across the file's other functions/siblings. Sorting eligible
    candidates by this count (ascending, stable on rank) makes the agent
    exhaust fresher surfaces first and revisit a cracked card only once the
    less-mined work is gone — diminishing returns without losing the card.
    """
    counts: dict[str, int] = {}
    for row in read_jsonl(state_dir(ctx.results_dir) / "claims.jsonl"):
        if row.get("source", "") == "release-stale-claims" and row.get("preserved_terminal_status", ""):
            continue
        if str(row.get("status", "")) in _PRODUCTIVE_TERMINAL_CARD_STATUSES:
            cid = str(row.get("card_id", ""))
            if cid:
                counts[cid] = counts.get(cid, 0) + 1
    return counts


def _hypothesis_shape(h: dict) -> str:
    """Stable identity for a hypothesis's investigative angle.

    Two hypotheses with the same shape are the same bug re-derived; a new
    shape is a genuinely new angle. Falls back to the row id when the shape
    fields are all empty, and to "" when even the id is missing (skipped).
    """
    shape = "\x1f".join(
        str(h.get(k, "")).strip().lower()
        for k in ("hypothesis", "input_shape", "guard_gap", "diagnostic", "strategy")
    )
    if shape.strip("\x1f"):
        return shape
    return str(h.get("id", ""))


def card_distinct_hypothesis_count(ctx: Context, card_id: str) -> int:
    """How many distinct hypothesis shapes have been opened against this card."""
    if not card_id:
        return 0
    seen: set[str] = set()
    for h in read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl"):
        if h.get("card_id", "") == card_id:
            key = _hypothesis_shape(h)
            if key:
                seen.add(key)
    return len(seen)


def card_distinct_hypothesis_counts(ctx: Context) -> dict[str, int]:
    """Per-card distinct-hypothesis-shape counts — the plural memo of
    ``card_distinct_hypothesis_count`` for candidate loops that would
    otherwise re-read hypotheses.jsonl once per card.
    """
    by_card: dict[str, set[str]] = {}
    for h in read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl"):
        cid = h.get("card_id", "")
        if not cid:
            continue
        key = _hypothesis_shape(h)
        if key:
            by_card.setdefault(cid, set()).add(key)
    return {cid: len(s) for cid, s in by_card.items()}


# ── Per-strategy completion gates (Fix #9) ─────────────────────────
#
# Each strategy has a *minimum-evidence floor* the agent must reach
# before the harness will rotate them off it. Without this, an agent
# can sit on S1 for one round, declare 3 clean variants, and rotate to
# S2 having never read a single prior-fix patch — exactly the pattern
# we saw in the json/libxml2 audit logs.
#
# Evidence is read from notes.jsonl (kind in {data-flow, guard, variants,
# decision, context}) for the given agent. Strategy match is heuristic:
# we look for keywords specific to the strategy in the note text. Tuned
# loose so the agent is rewarded for *describing* the work (which they
# already have to do) rather than passing some opaque counter.

STRATEGY_KEYWORDS: dict[str, tuple[re.Pattern[str], int]] = {
    # S1 — prior-fix patch mining: reference patch ids, fix hashes, or
    # "prior fix" / "regression" reasoning. `[\s_-]` matches a separator
    # so "fix-hash", "fix_hash", and "fix hash" all match.
    "S1": (
        re.compile(
            r"\b(?:PATCH-[0-9a-f]{6,}"
            r"|fix[\s_-]?hash"
            r"|prior[\s_-]?fix"
            r"|regression"
            r"|patch[\s_-]?card"
            r"|landed[\s_-]?fix"
            r"|backport"
            r"|incomplete[\s_-]?patch"
            r"|cve-?\d+"
            r"|bug[\s_-]?\d{4,})",
            re.IGNORECASE,
        ),
        2,
    ),
    # S2 — invariant negation: agent must have looked at asserts.
    # Vocab is project-agnostic. Matches:
    #   • `<PREFIX>_ASSERT/_CHECK/_VERIFY/…` style macros — covers
    #     MOZ_ASSERT, JSON_ASSERT, XML_ASSERT, RELEASE_ASSERT, DEBUG_ASSERT,
    #     and any future target's prefixed assertion convention without
    #     a target-specific list.
    #   • Bare DCHECK family (Abseil/Chromium pattern that has no
    #     underscore prefix so the rule above doesn't catch it).
    #   • C/C++ standard forms (assert(), static_assert, __builtin_assume,
    #     __builtin_unreachable, __builtin_trap, NDEBUG).
    #   • Generic invariant / debug-only / release-gap language.
    "S2": (
        re.compile(
            r"(?:\b[A-Z][A-Z0-9]*_(?:ASSERT|CHECK|ASSUME|VERIFY|ENSURE|REQUIRE|EXPECT)\b"
            r"|\bDCHECK(?:_(?:EQ|NE|GE|GT|LE|LT))?\b"
            r"|\bCHECK_(?:EQ|NE|GE|GT|LE|LT)\b"
            r"|\bassert\(|\bstatic_assert\b"
            r"|\b__builtin_(?:assume|unreachable|trap)\b"
            r"|\babort_if\b"
            r"|\binvariant\b|\bprecondition\b|\bpostcondition\b"
            r"|\bdebug[\s_-]?only\b"
            r"|\brelease[\s_-]?build[\s_-]?gap\b"
            r"|\bdisabled[\s_-]?in[\s_-]?release\b"
            r"|\bNDEBUG\b)",
            re.IGNORECASE,
        ),
        2,
    ),
    # S3 — spec-vs-impl + fast-path.
    "S3": (
        re.compile(
            r"\b(?:spec(?:ification)?"
            r"|rfc[\s_-]?\d+"
            r"|whatwg|w3c|standard"
            r"|fast[\s_-]?path|slow[\s_-]?path"
            r"|optimization[\s_-]?skip"
            r"|short[\s_-]?circuit|early[\s_-]?return"
            r"|undefined[\s_-]?behavi(?:o|ou)r"
            r"|conformance)",
            re.IGNORECASE,
        ),
        2,
    ),
    # S4 — differential / configuration-dependent divergence. Covers the
    # "same input, different result across configurations" surface:
    # optimization tiers / JIT pipelines, optimization levels, build
    # flags, conditional compilation, endianness, sanitizer vs
    # non-sanitizer, interpreter-vs-compiled execution paths.
    "S4": (
        re.compile(
            r"\b(?:differential|divergence|differs|inconsistent|mismatch"
            r"|interpreter[\s_-]?vs[\s_-]?(?:jit|compiled|optimi[sz]ed)"
            r"|jit[\s_-]?vs[\s_-]?(?:interpreter|interp)"
            r"|optimi[sz]ation[\s_-]?(?:level|tier|pipeline)"
            r"|opt[\s_-]?level|(?:^|[\s(=,])-O[0-3sg]\b"
            r"|compile[\s_-]?flag|build[\s_-]?flag|feature[\s_-]?flag"
            r"|conditional[\s_-]?compilation"
            r"|ifdef|#if[\s_-]?defined"
            r"|endian(?:ness)?|big[\s_-]?endian|little[\s_-]?endian"
            r"|architecture[\s_-]?dependent|platform[\s_-]?dependent"
            r"|configuration[\s_-]?dependent"
            r"|sanitizer[\s_-]?vs[\s_-]?(?:non[\s_-]?sanitizer|release)"
            r"|asan[\s_-]?only|ubsan[\s_-]?only)",
            re.IGNORECASE,
        ),
        1,
    ),
    # S5 — re-entrancy / lifetime / state.
    "S5": (
        re.compile(
            r"\b(?:re[\s_-]?entran(?:cy|t)"
            r"|life[\s_-]?time"
            r"|use[\s_-]?after"
            r"|cleanup[\s_-]?on[\s_-]?error"
            r"|state[\s_-]?machine"
            r"|destructor|drop[\s_-]?ord|dangling"
            r"|owner[\s_-]?ship|raii"
            r"|invalidat(?:e|ed|ion)"
            r"|race|concurren)",
            re.IGNORECASE,
        ),
        2,
    ),
    # S6 — cross-project variant mining (same spec/format/algorithm,
    # independent implementations). Keep this target-agnostic: concrete
    # peer lists live only in output/<slug>/target.toml [s6_peers].
    "S6": (
        re.compile(
            r"\b(?:peer[\s_-]?(?:project|impl(?:ementation)?|fix)"
            r"|sibling[\s_-]?(?:project|impl(?:ementation)?)"
            r"|upstream[\s_-]?(?:fix|patch|advisory)"
            r"|cross[\s_-]?(?:project|browser|engine|impl)"
            r"|same[\s_-]?(?:bug|class|pattern)[\s_-]?in"
            r"|analog(?:ue|ous)[\s_-]?(?:in|to)"
            r"|other[\s_-]?(?:engine|impl(?:ementation)?|library)"
            r"|oss[\s_-]?fuzz|cve[\s_-]?\d{4}"
            + r")",
            re.IGNORECASE,
        ),
        1,
    ),
    # S7 — adversarial / fuzz-improvement.
    "S7": (
        re.compile(
            r"\b(?:truncat|malformed|adversarial|crafted"
            r"|short[\s_-]?input|over[\s_-]?long"
            r"|encoding|surrogate|bom"
            r"|null[\s_-]?byte"
            r"|partial[\s_-]?read"
            r"|fuzz[\s_-]?seed|corpus[\s_-]?gap)",
            re.IGNORECASE,
        ),
        2,
    ),
    # S8 — property-based oracles (idempotence, injectivity, numerical
    # domain, format compliance, inverse operations). Evidence is the
    # agent describing the *property* it chose to exercise, not the bug
    # category — properties are oracles without sanitizers.
    "S8": (
        re.compile(
            r"\b(?:property[\s_-]?based"
            r"|round[\s_-]?trip|roundtrip"
            r"|idempoten(?:t|ce|cy)"
            r"|injectiv(?:e|ity)|collision[\s_-]?resistan"
            r"|numerical[\s_-]?(?:domain|bound|invariant)"
            r"|format[\s_-]?compliance"
            r"|inverse[\s_-]?(?:operation|function)"
            r"|encode.*decode|decode.*encode"
            r"|hypothesis[\s_-]?(?:library|strategy)"
            r"|quickcheck|proptest"
            r"|shrinker|shrinking"
            r"|fixed[\s_-]?point"
            r"|normaliz(?:e|ation)|canonical(?:ize|ization))",
            re.IGNORECASE,
        ),
        2,
    ),
}


def strategy_evidence_count(ctx: Context, agent: str, strategy: str) -> int:
    """Count notes that look like strategy-relevant evidence."""
    spec = STRATEGY_KEYWORDS.get(strategy.upper())
    if not spec:
        return 0
    pattern, _ = spec
    n = 0
    for note in read_jsonl(state_dir(ctx.results_dir) / "notes.jsonl"):
        if agent and str(note.get("agent", "")) != str(agent):
            continue
        text = str(note.get("text", ""))
        if pattern.search(text):
            n += 1
    return n


def strategy_completion_threshold(strategy: str) -> int:
    """Minimum evidence count before rotation off `strategy` is allowed."""
    spec = STRATEGY_KEYWORDS.get(strategy.upper())
    return spec[1] if spec else 0


def strategy_completion_status(ctx: Context, agent: str, strategy: str) -> dict:
    """Structured completion check for use by bin/audit's rotation gate.

    Returns a dict with `complete` (bool), `evidence` (count), and
    `threshold` (int). When complete is False, the audit should keep
    the agent on the current strategy and inject a directive into the
    next prompt asking for the missing evidence type.
    """
    threshold = strategy_completion_threshold(strategy)
    evidence = strategy_evidence_count(ctx, agent, strategy)
    return {
        "strategy": strategy,
        "agent": agent,
        "evidence": evidence,
        "threshold": threshold,
        "complete": evidence >= threshold,
    }


def strategy_yield(ctx: Context) -> dict:
    """Read-only attribution of probe outcomes to the strategy that drove them.

    Answers "which strategy actually converts leads into crashes?" purely by
    joining state already on disk: runs.jsonl (verdict + hypothesis_id +
    card_id) against hypotheses.jsonl (strategy) with a card fallback. No
    write path, no extra probe, so it cannot slow a live audit; run it
    post-hoc or between iterations.

    Each run is attributed to a strategy via its hypothesis (the agent stamps
    its working strategy on every hypothesis), falling back to the work
    card's strategy when the run has no hypothesis. `yield` is
    (CRASH+DIFF)/runs — the signal-producing fraction. Strategies with no
    runs are omitted; unattributable runs bucket under "(none)".
    """
    hyp_strategy = {
        str(h.get("id", "")): str(h.get("strategy", "") or "")
        for h in read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl")
    }
    cards_by_id = {
        str(c.get("id", "")): c for c in read_jsonl(work_cards_path(ctx))
    }
    buckets: dict[str, dict] = {}
    for run in read_jsonl(state_dir(ctx.results_dir) / "runs.jsonl"):
        card_id = str(run.get("card_id", ""))
        card = cards_by_id.get(card_id)
        strategy = hyp_strategy.get(str(run.get("hypothesis_id", "")), "")
        if not strategy and card:
            strategy = str(card.get("strategy", "") or "")
        strategy = strategy or "(none)"
        verdict = str(run.get("verdict", "") or "").upper()
        b = buckets.setdefault(
            strategy,
            {"strategy": strategy, "runs": 0, "crash": 0, "diff": 0,
             "clean": 0, "no_exec": 0, "other": 0},
        )
        b["runs"] += 1
        # Only CLEAN is a clean execution. Unknown/auxiliary verdicts
        # (EXEC_FAIL, REGEX, NO_HIT, MISSED, TIMEOUT, ...) bucket under
        # `other` rather than silently inflating `clean`.
        if verdict == "CRASH":
            b["crash"] += 1
        elif verdict == "DIFF":
            b["diff"] += 1
        elif verdict == "CLEAN":
            b["clean"] += 1
        elif verdict == "NO_EXEC":
            b["no_exec"] += 1
        else:
            b["other"] += 1
    rows = []
    for b in buckets.values():
        signal = b["crash"] + b["diff"]
        b["yield"] = round(signal / b["runs"], 3) if b["runs"] else 0.0
        rows.append(b)
    rows.sort(key=lambda r: (-r["yield"], -r["runs"], r["strategy"]))
    return {"strategies": rows}


class CardStatusUpdateError(ValueError):
    """Raised when update_card_status refuses to commit a status change."""


def card_discard_requirements() -> tuple[int, int]:
    """Return the configured card-discard evidence floor.

    Prompt rendering and enforcement share this helper so an operator override
    cannot make the agent follow a different policy from ``update-card``.
    """
    return (
        _int_env("WORK_CARD_MIN_RUNS_BEFORE_DISCARD", 3),
        _int_env("WORK_CARD_MIN_HYPS_BEFORE_DISCARD", 2),
    )


def card_discard_evidence(ctx: Context, card_id: str) -> tuple[int, int]:
    """Return CLEAN runs and actually-probed hypothesis shapes for a card."""
    hypothesis_shapes = {
        (str(row.get("agent", "")), str(row.get("id", ""))): _hypothesis_shape(row)
        for row in read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl")
        if str(row.get("card_id", "")) == str(card_id) and row.get("id")
    }
    clean_runs = 0
    probed_shapes: set[str] = set()
    for run in read_jsonl(state_dir(ctx.results_dir) / "runs.jsonl"):
        if str(run.get("card_id", "")) != str(card_id):
            continue
        if str(run.get("verdict", "")).upper() != "CLEAN":
            continue
        shape = hypothesis_shapes.get(
            (str(run.get("agent", "")), str(run.get("hypothesis_id", "")))
        )
        if not shape:
            continue
        clean_runs += 1
        probed_shapes.add(shape)
    return clean_runs, len(probed_shapes)


def update_card_status(ctx: Context, card_id: str, status: str, agent: str = "", note: str = "") -> dict:
    """Append a card-status row to claims.jsonl with evidence gates.

    Evidence-free *terminal* closures drain a finite, one-shot card queue
    before the wall budget, so the clean-close and crash conclusions must
    carry harness-written evidence:

      * `discarded` requires ≥WORK_CARD_MIN_RUNS_BEFORE_DISCARD (default 3)
        CLEAN runs.jsonl rows referencing the card and a real hypothesis AND
        ≥WORK_CARD_MIN_HYPS_BEFORE_DISCARD (default 2) distinct hypothesis
        shapes among those runs: MISSED/NO_EXEC probes and unprobed rows cannot
        retire a file/strategy surface.
      * `crash` requires ≥1 runs.jsonl row with a CRASH verdict for the
        card and no unfinished crash report owned by the agent. An
        `update-card --status crash` with no such row is bounced
        back to needs-verify instead of terminally consuming the card; the
        agent must run the testcase through bin/probe. Scope: this catches
        the observed failure mode (a card closed `crash` with no probe run
        at all — gemini filed CRASH dirs with no valid sanitizer output);
        it is an anti-fabrication gate, not proof the diagnostic is genuine
        (add-run is callable), so triage's artifact checks still apply.
      * `find` is intentionally NOT gated here: a finding's evidence is a
        substantive report dir that the separate finding/triage gate
        already validates (and the product allows findings with no
        sanitizer reproducer), so a second gate would only risk false
        negatives against real findings. Residual exposure is small and
        bounded: a fabricated find cannot reset its subsystem's dry streak
        (only triage-promoted artifacts do), so it can keep a card eligible
        only by riding a subsystem already hot from a *real* sibling
        artifact — and card_conclusion_counts then demotes the cracked card
        below fresher work. See card_closed_for_run.

    Note: `crash`/`find` are no longer *permanently* terminal for the
    queue. See card_closed_for_run: a verified crash/find keeps its
    surface claimable until the subsystem is mined out, so one bug no
    longer retires a whole (possibly very large) file.
    """
    init_state(ctx)
    if status == "discarded":
        min_runs, min_hyps = card_discard_requirements()
        runs, hyps = card_discard_evidence(ctx, card_id)
        ok = runs >= min_runs and hyps >= min_hyps
        if not ok:
            raise CardStatusUpdateError(
                f"update-card refuses discard for {card_id}: "
                f"clean_runs={runs} (need {min_runs}); "
                f"probed_distinct_hypotheses={hyps} (need {min_hyps}). "
                "Run bin/probe and add distinct hypotheses first."
            )
    elif status == "crash":
        if card_run_count(ctx, card_id, verdict="CRASH") < 1:
            raise CardStatusUpdateError(
                f"update-card refuses crash for {card_id}: no runs.jsonl "
                "CRASH verdict references this card. Run the testcase "
                "through bin/probe to verify the crash; it records the "
                "verdict and files the artifact."
            )
        owners = {str(agent)} if agent else set()
        owners.update(
            str(row.get("agent", ""))
            for row in read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl")
            if row.get("card_id") == card_id and row.get("agent") not in (None, "")
        )
        blocked_owners = sorted(
            owner for owner in owners
            if _unfinished_crash_reports_for_agent(ctx, owner)
        )
        if blocked_owners:
            raise CardStatusUpdateError(
                f"update-card refuses crash for {card_id}: agent(s) "
                f"{', '.join(blocked_owners)} have "
                "an unfinished crash report. Complete its `_TODO (agent):` fields first."
            )
    row = {
        "card_id": card_id,
        "agent": agent,
        "status": status,
        "updated_at": now_iso(),
    }
    if note:
        row["note"] = note
    append_jsonl(state_dir(ctx.results_dir) / "claims.jsonl", row)
    return row


def _int_env(name: str, default: int) -> int:
    raw = os.environ.get(name, "")
    try:
        return max(0, int(raw)) if raw else default
    except ValueError:
        return default


def add_run(ctx: Context, args: argparse.Namespace) -> dict:
    init_state(ctx)
    rid = "RUN-" + hashlib.sha1(f"{args.agent}:{args.testcase}:{now_iso()}".encode()).hexdigest()[:10]
    try:
        sanitizer_runs = int(getattr(args, "sanitizer_runs", "") or 0) or 1
    except (TypeError, ValueError):
        sanitizer_runs = 1
    row = {
        "id": rid,
        "agent": args.agent,
        "hypothesis_id": args.hypothesis_id,
        "card_id": args.card_id or "",
        "mode": args.mode,
        "testcase": args.testcase,
        "testcase_sha1": (getattr(args, "testcase_sha1", "") or "").lower(),
        "asan_output": args.asan_output,
        "verdict": args.verdict,
        "sanitizer_runs": sanitizer_runs,
        "created_at": now_iso(),
    }
    append_jsonl(state_dir(ctx.results_dir) / "runs.jsonl", row)
    return row


def add_note(ctx: Context, args: argparse.Namespace) -> dict:
    init_state(ctx)
    nid = "NOTE-" + hashlib.sha1(
        f"{args.agent}:{args.hypothesis_id}:{args.kind}:{args.text}:{now_iso()}".encode()
    ).hexdigest()[:10]
    row = {
        "id": nid,
        "agent": args.agent,
        "hypothesis_id": args.hypothesis_id,
        "card_id": args.card_id or "",
        "kind": args.kind,
        "text": args.text,
        "created_at": now_iso(),
    }
    append_jsonl(state_dir(ctx.results_dir) / "notes.jsonl", row)
    return row


def queue_health_reason(reason: str) -> str:
    """Normalize volatile queue reasons for compact resume output."""
    reason = reason or ""
    if reason.startswith("claimed-until:"):
        return "claimed-until"
    return reason


def queue_health_lines(ctx: Context, mode: str = "", limit: int | None = None) -> list[str]:
    """Bounded queue-health digest for state_resume.

    `explain_queue` is intentionally verbose for machine diagnostics. Resume
    output is model-facing context, so it aggregates volatile per-card reasons
    (notably claimed-until timestamps) and caps the number of rows.
    """
    rows = explain_queue(ctx, [mode] if mode else [])
    reason_counts: dict[str, int] = {}
    for row in rows:
        reason = queue_health_reason(str(row.get("reason", "")))
        reason_counts[reason] = reason_counts.get(reason, 0) + 1

    if not reason_counts:
        return ["- no work cards"]

    if limit is None:
        limit = _int_env("STATE_RESUME_QUEUE_HEALTH_LIMIT", 8)

    ordered = sorted(reason_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    out = [f"- {reason}: {count}" for reason, count in ordered[:limit]]
    remaining = ordered[limit:] if limit > 0 else ordered
    if remaining:
        out.append(f"- ... {len(remaining)} more reason(s), {sum(count for _, count in remaining)} card(s)")
    return out


def summarize_queue(ctx: Context, agent_modes: list[str], top: int, strategy: str = "") -> list[dict]:
    """Aggregated queue digest for `bin/state explain-queue`.

    Groups rows from `explain_queue` by normalized reason (volatile
    `claimed-until:<ts>` collapses to `claimed-until`), keeps the top N
    reasons by count, and appends a `_more` tail row when reasons are
    truncated. Each kept reason row carries one `sample_id` so an agent can
    eyeball a representative card.
    """
    rows = explain_queue(ctx, agent_modes, strategy=strategy)
    reason_counts: dict[str, int] = {}
    reason_samples: dict[str, str] = {}
    for row in rows:
        reason = queue_health_reason(str(row.get("reason", "")))
        reason_counts[reason] = reason_counts.get(reason, 0) + 1
        if reason not in reason_samples:
            reason_samples[reason] = str(row.get("id", ""))
    if not reason_counts:
        return []
    ordered = sorted(reason_counts.items(), key=lambda kv: (-kv[1], kv[0]))
    kept = ordered if top <= 0 else ordered[:top]
    out: list[dict] = [
        {"reason": reason, "count": count, "sample_id": reason_samples.get(reason, "")}
        for reason, count in kept
    ]
    remaining = ordered[len(kept):]
    if remaining:
        out.append(
            {
                "reason": "_more",
                "count": sum(count for _, count in remaining),
                "reasons_remaining": len(remaining),
            }
        )
    return out


def _clip_model_field(value: object, limit: int = 180) -> str:
    """Compact free-form card fields for model-facing JSON output."""
    text = str(value or "").replace("\n", " ").replace("|", "/").strip()
    if limit > 0 and len(text) > limit:
        return text[: max(0, limit - 3)] + "..."
    return text


def _status_rows_by_card(ctx: Context, mode: str = "", cards: list[dict] | None = None) -> dict[str, dict]:
    return {
        str(row.get("id", "")): row
        for row in explain_queue(ctx, [mode] if mode else [], cards=cards)
        if row.get("id", "")
    }


def _compact_card(ctx: Context, card: dict, status_row: dict | None = None, *, omit_empty: bool = False) -> dict:
    status_row = status_row or {}
    row = {
        "id": card.get("id", ""),
        "kind": card.get("kind", ""),
        "file": card.get("file", ""),
        "function": card.get("function", ""),
        "subsystem": card.get("subsystem", ""),
        "strategy": card.get("strategy", ""),
        "mode": card.get("mode") or "auto",
        "status": status_row.get("status", "unclaimed"),
        "reason": status_row.get("reason", ""),
        "score": card.get("score", ""),
        "why_ranked": _clip_model_field(card.get("reason", ""), 220),
        "description": _clip_model_field(card.get("description", ""), 220),
        "fix_hashes": (card.get("fix_hashes", []) or [])[:5],
        "invalid_fix_hashes": (card.get("invalid_fix_hashes", []) or [])[:5],
        "patch_cards": (card.get("patch_cards", []) or [])[:5],
        "testcase_hashes": (card.get("testcase_hashes", []) or [])[:5],
        "invalid_testcase_hashes": (card.get("invalid_testcase_hashes", []) or [])[:5],
        "seed": card.get("seed", ""),
    }
    if omit_empty:
        row = {k: v for k, v in row.items() if v not in ("", [], None)}
    return row


def _list_card_row(compact: dict, *, verbose: bool = False) -> dict:
    if verbose:
        return compact
    row = dict(compact)
    # list-cards is an overview/browse API. Keep enough to pick a card,
    # but leave prose-heavy ranking detail to show-card/--verbose.
    for key in ("why_ranked", "description", "testcase_hashes", "invalid_testcase_hashes"):
        row.pop(key, None)
    if row.get("mode") == "auto":
        row.pop("mode", None)
    return row


def show_work_card(ctx: Context, card_id: str, mode: str = "") -> dict | None:
    """Return compact JSON for one work card.

    Keep this read-only
    and bounded so they don't fall back to verbose `--help` or raw JSONL.
    """
    init_state(ctx)
    cards = read_jsonl(work_cards_path(ctx))
    for card in cards:
        if card.get("id", "") == card_id:
            status_rows = _status_rows_by_card(ctx, mode, cards=cards)
            return _compact_card(ctx, card, status_rows.get(card_id))

    # Direct PATCH-* lookups before work-cards have been refreshed do not
    # participate in queue status.
    for card in read_jsonl(ctx.results_dir / "patch-cards.jsonl"):
        if card.get("id", "") == card_id:
            return _compact_card(ctx, card, {"status": "unclaimed", "reason": "patch-card"})
    return None


def list_work_cards(
    ctx: Context,
    mode: str = "",
    status_filter: str = "",
    strategy_filter: str = "",
    subsystem_filters: Iterable[str] | None = None,
    contains_filters: Iterable[str] | None = None,
    limit: int = 20,
    verbose: bool = False,
) -> list[dict]:
    """Return a compact JSONL-friendly listing of work cards."""
    init_state(ctx)
    cards = read_jsonl(work_cards_path(ctx))
    cards_by_id = {c.get("id", ""): c for c in cards}
    latest = latest_claims_by_card(ctx)
    hypotheses = read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl")
    ttl = work_card_claim_ttl()
    now = datetime.now(timezone.utc)
    active_cards, active_surfaces, active_subsystems = _active_hypothesis_queue_sets(cards_by_id, hypotheses)
    claimed_surfaces, claimed_subsystems = _claimed_card_queue_sets(cards_by_id, latest, ttl, now)
    owned_subsystems = active_subsystems | claimed_subsystems
    agent_modes = [mode] if mode else []
    subsystem_needles = [str(s).strip().lower() for s in (subsystem_filters or []) if str(s).strip()]
    contains_needles = [str(s).strip().lower() for s in (contains_filters or []) if str(s).strip()]
    conclusion_counts = card_conclusion_counts(ctx)
    distinct_counts = card_distinct_hypothesis_counts(ctx)
    dry_streaks: dict[str, int] = {}
    rows: list[dict] = []
    for card in cards:
        if strategy_filter and not card_strategy_matches(card, strategy_filter):
            continue
        if subsystem_needles:
            subsystem = str(card.get("subsystem", "")).lower()
            if not any(needle in subsystem for needle in subsystem_needles):
                continue
        status_row = _queue_status_row(
            card,
            ctx=ctx,
            conclusion_counts=conclusion_counts,
            distinct_counts=distinct_counts,
            dry_streaks=dry_streaks,
            latest=latest,
            ttl=ttl,
            now=now,
            active_cards=active_cards,
            active_surfaces=active_surfaces,
            claimed_surfaces=claimed_surfaces,
            owned_subsystems=owned_subsystems,
            agent_modes=agent_modes,
        )
        visible_status = str(status_row.get("status", ""))
        reason = str(status_row.get("reason", ""))
        if status_filter and status_filter not in (visible_status, reason):
            continue
        compact = _compact_card(ctx, card, status_row, omit_empty=True)
        compact["why_ranked"] = _clip_model_field(card.get("reason", ""), 120)
        if contains_needles:
            haystack = json.dumps(compact, sort_keys=True).lower()
            if not any(needle in haystack for needle in contains_needles):
                continue
        rows.append(_list_card_row(compact, verbose=verbose))
        if limit > 0 and len(rows) >= limit:
            break
    return rows


def _markdown_cells(line: str) -> list[str]:
    line = line.strip()
    if not (line.startswith("|") and line.endswith("|")):
        return []
    return [cell.strip() for cell in line.strip("|").split("|")]


def _is_markdown_separator(cells: list[str]) -> bool:
    if not cells:
        return False
    return all(re.fullmatch(r":?-{2,}:?", cell.replace(" ", "")) for cell in cells)


def _plain_markdown_cell(value: str) -> str:
    value = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", value or "")
    value = value.replace("`", "").replace("\n", " ").strip()
    return re.sub(r"\s+", " ", value)


def _report_path(artifact_dir: Path) -> Path | None:
    for name in ("REPORT.md", "report.md", "description.md"):
        p = artifact_dir / name
        if p.is_file():
            return p
    return None


def _read_report_prefix(path: Path | None, max_bytes: int = 32_768) -> str:
    if path is None or not path.is_file():
        return ""
    try:
        return path.read_bytes()[:max_bytes].decode("utf-8", errors="replace")
    except Exception:
        return ""


def _report_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        cells = _markdown_cells(stripped)
        if len(cells) >= 2 and not _is_markdown_separator(cells):
            key = _plain_markdown_cell(cells[0]).rstrip(":")
            val = _plain_markdown_cell(cells[1])
            if key and key.lower() not in {"field", ""} and val.lower() != "value":
                fields.setdefault(key.lower(), val)
        m = re.match(r"^(Cluster|Dedup key|Surface|Severity|Location|Crash site):\s*(.+)$", stripped, re.I)
        if m:
            fields.setdefault(m.group(1).lower(), _plain_markdown_cell(m.group(2)))
        m = re.match(r"^-\s+\*\*(Location|Severity|Surface)\*\*:\s*(.+)$", stripped, re.I)
        if m:
            fields.setdefault(m.group(1).lower(), _plain_markdown_cell(m.group(2)))
    return fields


def _first_existing_artifact_path(artifact_dir: Path, names: Iterable[str]) -> str:
    for name in names:
        for p in sorted(artifact_dir.glob(name)):
            if p.is_file():
                return p.as_posix()
    return ""


def _compact_crash(ctx: Context, row: dict[str, str]) -> dict:
    cid = row.get("id", "")
    artifact_dir = ctx.results_dir / "crashes" / cid
    report = _report_path(artifact_dir)
    fields = _report_fields(_read_report_prefix(report))
    surface = row.get("surface", "") or fields.get("surface", "")
    surface = re.split(r"\s+(?:\u2013|\u2014|-)\s+", surface, maxsplit=1)[0]
    location = (
        row.get("crash site", "")
        or row.get("root signature", "")
        or fields.get("crash site", "")
        or fields.get("location", "")
        or fields.get("dedup frames", "").split(" -> ", 1)[0]
    )
    status = row.get("status", "")
    if not status:
        pending = artifact_dir / ".promotion_pending"
        if pending.is_file():
            try:
                missing = ",".join(line.strip() for line in pending.read_text(encoding="utf-8", errors="replace").splitlines() if line.strip())
            except OSError:
                missing = ""
            status = f"PENDING (missing: {missing})" if missing else "PENDING"
        else:
            status = "OK" if artifact_dir.is_dir() else ""
    return {
        "id": cid,
        "cluster": row.get("cluster", "") or fields.get("cluster", ""),
        "dedup": fields.get("dedup key", "") or fields.get("dedup frames", ""),
        "surface": surface,
        "severity": row.get("severity", "") or fields.get("severity", ""),
        "location": _clip_model_field(location, 180),
        "status": status,
        "repro": _first_existing_artifact_path(artifact_dir, ["reproduce.sh", "input.*", "harness.c"]),
    }


def list_crashes(ctx: Context, status_filter: str = "", limit: int = 20) -> list[dict]:
    rows = []
    for artifact_dir in sorted((ctx.results_dir / "crashes").glob("CRASH-*")):
        if not artifact_dir.is_dir():
            continue
        row = {"id": artifact_dir.name}
        fields = _report_fields(_read_report_prefix(_report_path(artifact_dir)))
        row["cluster"] = fields.get("cluster", "")
        row["severity"] = fields.get("severity", "")
        row["surface"] = fields.get("surface", "")
        row["status"] = "PENDING" if (artifact_dir / ".promotion_pending").is_file() else "OK"
        if status_filter and status_filter not in {row.get("status", ""), row.get("cluster", "")}:
            continue
        rows.append(_compact_crash(ctx, row))
        if limit > 0 and len(rows) >= limit:
            break
    return rows


def show_crash(ctx: Context, crash_id: str) -> dict | None:
    for row in list_crashes(ctx, limit=0):
        if row.get("id") == crash_id:
            return row
    artifact_dir = ctx.results_dir / "crashes" / crash_id
    if artifact_dir.is_dir():
        fields = _report_fields(_read_report_prefix(_report_path(artifact_dir)))
        return _compact_crash(ctx, {"id": crash_id, "status": "", "cluster": fields.get("cluster", "")})
    return None


def _agent_crash_dirs(ctx: Context, agent: str) -> list[Path]:
    suffix = re.compile(rf"-{re.escape(str(agent))}$")
    return [
        artifact_dir
        for artifact_dir in sorted((ctx.results_dir / "crashes").glob("CRASH-*"))
        if artifact_dir.is_dir() and suffix.search(artifact_dir.name)
    ]


def _crash_report_unfinished(artifact_dir: Path) -> bool:
    try:
        return "_TODO (agent):" in _report_path(artifact_dir).read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return True


def _unfinished_crash_reports_for_agent(ctx: Context, agent: str) -> list[Path]:
    return [
        artifact_dir for artifact_dir in _agent_crash_dirs(ctx, agent)
        if _crash_report_unfinished(artifact_dir)
    ]


def _pending_crashes_for_agent(ctx: Context, agent: str) -> list[Path]:
    """Return this agent's unfinished crash bundles in filing order."""
    return [
        artifact_dir for artifact_dir in _agent_crash_dirs(ctx, agent)
        if _crash_report_unfinished(artifact_dir)
        or (artifact_dir / ".promotion_pending").is_file()
    ]


def _compact_finding(ctx: Context, row: dict[str, str]) -> dict:
    fid = row.get("id", "")
    artifact_dir = ctx.results_dir / "findings" / fid
    fields = _report_fields(_read_report_prefix(_report_path(artifact_dir)))
    llm_class = ""
    llm_severity = ""
    cache_path = artifact_dir / ".llm-find-quality.json"
    if cache_path.is_file():
        try:
            data = json.loads(cache_path.read_text(encoding="utf-8", errors="replace"))
            cache_current = True
            if data.get("report_sha1"):
                cache_current = report_identity.quality_cache_matches_report(
                    artifact_dir, data,
                )
            if data.get("accept") is True and cache_current:
                llm_class = str(data.get("class") or "")
                llm_severity = str(data.get("severity") or "")
        except Exception:
            pass
    location = fields.get("location", "") or row.get("subject", "")
    status = row.get("status", "")
    if not status:
        if (artifact_dir / ".needs-content").is_file() or _report_path(artifact_dir) is None:
            status = "NEEDS CONTENT"
        elif (artifact_dir / ".needs-attention").is_file():
            status = "NEEDS ATTENTION"
        elif (artifact_dir / ".reviewed").is_file() or (artifact_dir / ".keep").is_file():
            status = "OK (override)"
        else:
            status = "OK"
    return {
        "id": fid,
        "cluster": fields.get("cluster", ""),
        "dedup": fields.get("dedup key", ""),
        "surface": fields.get("surface", ""),
        "severity": row.get("severity", "") or fields.get("severity", "") or llm_severity,
        "location": _clip_model_field(location, 180),
        "status": status,
        "repro": _first_existing_artifact_path(artifact_dir, ["reproduce.sh", "repro.*", "input.*", "*.driver"]),
        "class": row.get("class", "") or fields.get("class", "") or llm_class,
    }


def list_findings(ctx: Context, status_filter: str = "", limit: int = 20) -> list[dict]:
    rows = []
    for artifact_dir in sorted((ctx.results_dir / "findings").glob("FIND-*")):
        if not artifact_dir.is_dir():
            continue
        fid = artifact_dir.name
        fields = _report_fields(_read_report_prefix(_report_path(artifact_dir)))
        row = {
            "id": fid,
            "class": fields.get("class", ""),
            "severity": fields.get("severity", ""),
            "status": "",
        }
        if status_filter and status_filter not in {row.get("status", ""), row.get("class", "")}:
            compact = _compact_finding(ctx, row)
            if status_filter not in {compact.get("status", ""), compact.get("class", "")}:
                continue
            rows.append(compact)
        else:
            rows.append(_compact_finding(ctx, row))
        if limit > 0 and len(rows) >= limit:
            break
    return rows


def show_finding(ctx: Context, finding_id: str) -> dict | None:
    for row in list_findings(ctx, limit=0):
        if row.get("id") == finding_id:
            return row
    artifact_dir = ctx.results_dir / "findings" / finding_id
    if artifact_dir.is_dir():
        return _compact_finding(ctx, {"id": finding_id, "status": ""})
    return None


def state_resume(
    ctx: Context,
    agent: str,
    mode: str = "",
    role: str = "",
    claim: bool = True,
    strategy: str = "",
) -> str:
    """Compact, deterministic startup brief for an agent.

    This is the primary resume surface for prompts. It intentionally avoids
    dumping raw JSONL state files; agents get just enough
    context to continue active hypotheses or start the next work card.
    """
    init_state(ctx)
    hyps = read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl")
    active = [
        h for h in hyps
        if h.get("agent", "") == agent and is_active_hypothesis_status(h.get("status", ""))
    ]
    active.sort(key=lambda r: r.get("updated_at") or r.get("created_at") or "", reverse=True)
    pending_crashes = _pending_crashes_for_agent(ctx, agent)
    card = None if (pending_crashes or active) else claim_next_card(ctx, agent, mode, role, claim=claim, strategy=strategy)

    lines = [
        "# Structured Resume",
        f"- Target: `{ctx.target_slug}`",
        f"- Agent: `{agent}`",
        f"- Mode: `{mode or 'auto'}`",
        f"- Role: `{role or 'unspecified'}`",
        f"- Strategy filter: `{strategy.strip().upper()}`" if strategy.strip() else "",
        "",
        "## Pending Crash Completion",
    ]
    if pending_crashes:
        for crash_dir in pending_crashes:
            lines.append(f"- `{crash_dir.name}`: `{_report_path(crash_dir)}`")
        lines.extend([
            "",
            "Next action: finish the oldest pending crash bundle before any hypothesis or work card. Read `.promotion_pending` when present and replace every `_TODO (agent):` report field; after the report is complete, close its hypothesis/card in structured state.",
        ])
    else:
        lines.append("- none")
    lines.extend([
        "",
        "## Active Hypothesis",
    ])
    if active:
        h = active[0]
        lines.extend(
            [
                f"- ID: `{h.get('id','')}`",
                f"- Status: `{h.get('status','')}`",
                f"- File: `{h.get('file','')}`",
                f"- Strategy: `{h.get('strategy','')}`",
                f"- Card: `{h.get('card_id','') or 'none'}`",
                f"- Hypothesis: {h.get('hypothesis','')}",
                f"- Input Shape: {h.get('input_shape','')}",
                f"- Guard Gap: {h.get('guard_gap','')}",
                f"- Diagnostic: `{h.get('diagnostic','')}`",
                "",
                ("Next action after crash completion: continue this hypothesis."
                 if pending_crashes else
                 "Next action: continue this hypothesis. Write or revise one testcase, run `bin/probe`, then update structured state."),
            ]
        )
    else:
        lines.append("- none")
        lines.append("")
        lines.append("## Assigned Work Card")
        if card:
            fix_hashes = card.get("fix_hashes") or []
            invalid_fix_hashes = card.get("invalid_fix_hashes") or []
            patch_cards = card.get("patch_cards") or []
            fix_hash_text = ", ".join(str(h) for h in fix_hashes) or "none listed"
            invalid_fix_text = ", ".join(str(h) for h in invalid_fix_hashes)
            patch_card_text = ", ".join(str(c) for c in patch_cards)
            lines.extend(
                [
                    f"- ID: `{card.get('id','')}`",
                    f"- Kind: `{card.get('kind','')}`",
                    f"- File: `{card.get('file','')}`",
                    f"- Subsystem: `{card.get('subsystem','')}`",
                    f"- Strategy: `{card.get('strategy','')}`",
                    f"- Reason: {card.get('reason','')}",
                    f"- Fix commits: {fix_hash_text}",
                ]
            )
            if invalid_fix_text:
                lines.append(f"- Invalid fix commits: {invalid_fix_text}")
            if patch_card_text:
                lines.append(f"- Related patch cards: {patch_card_text}")
            if str(card.get("kind", "")) == "s1-patch" or str(card.get("strategy", "")).upper() == "S1":
                lines.extend(
                    [
                        "",
                        "For S1 prior-fix cards, `PATCH-*` is only the work-card id, not a VCS revision. Use the `Fix commits` hashes with `bin/show-patch <commit>`; do not run `git show` or `bin/show-patch` on the PATCH-* card id.",
                    ]
                )
            lines.extend(
                [
                    "",
                    "Next action: create one structured hypothesis for this card, write one testcase, and run `bin/probe`.",
                ]
            )
        else:
            lines.append("- none")
            lines.append("")
            if pending_crashes:
                lines.append(
                    "Next action: work-card assignment is deferred until the pending crash report is complete."
                )
            else:
                lines.append(
                    "Next action: no eligible work card is available. Use `bin/state explain-queue` to record why no launchable work exists; do not run `bin/rank-work` interactively to expand or rerank the queue."
                )

    if active:
        hyp_id = active[0].get("id", "")
        card_id = active[0].get("card_id", "")
    else:
        hyp_id = ""
        card_id = card.get("id", "") if card else ""

    # Resume payload sizing: each Recent-* digest is bytes the agent re-reads
    # at every iteration. limit=5 keeps the agent's working memory wide
    # enough to see prior near-miss signals across a typical 7-iteration
    # probe loop. Trimming below 5 saved a few hundred tokens per resume
    # but cost two iterations of context — the agent would re-do work it
    # had already ruled out. Cost-tune via per-note truncation (see
    # recent_runs), not via shortening the count. Recent Tried Inputs is
    # opt-in via STATE_RESUME_INCLUDE_TRIED=1 because Recent Runs already
    # reports the verdict-by-testcase view that matters for triage; the
    # tried-inputs log is a hash-dedupe surface that agents can reach via
    # `bin/state recent-tried` on demand. The cheat sheet has been moved
    # to `.agents/references/session-rules.md` (read once at session start)
    # so we don't bill it every resume.
    resume_limit = _int_env("STATE_RESUME_RECENT_LIMIT", 5)
    include_tried = os.environ.get("STATE_RESUME_INCLUDE_TRIED", "0") == "1"
    runs = read_jsonl(state_dir(ctx.results_dir) / "runs.jsonl")
    notes = read_jsonl(state_dir(ctx.results_dir) / "notes.jsonl")
    lines.extend(
        [
            "",
            "## Recent Hypotheses",
            recent_hypotheses(ctx, limit=resume_limit, agent=agent, rows=hyps).strip(),
            "",
            "## Recent Runs",
            recent_runs(ctx, limit=resume_limit, agent=agent, hypothesis_id=hyp_id, card_id=card_id, rows=runs).strip(),
            "",
            "## Runtime Feedback",
            runtime_feedback(ctx, limit=resume_limit, agent=agent, hypothesis_id=hyp_id, card_id=card_id, rows=runs).strip(),
        ]
    )
    if active:
        lines.extend(
            [
                "",
                "## Recent Notes",
                recent_notes(ctx, limit=resume_limit, agent=agent, hypothesis_id=hyp_id, rows=notes).strip(),
            ]
        )
    else:
        lines.extend(
            [
                "",
                "## Last Terminal Reason",
                last_terminal_reason(ctx, agent, rows=hyps).strip(),
                "",
                "## Guard Notes",
                recent_notes(ctx, limit=resume_limit, agent=agent, hypothesis_id=hyp_id, kind="guard", rows=notes).strip(),
            ]
        )
    if include_tried:
        lines.extend(
            [
                "",
                "## Recent Tried Inputs",
                recent_tried(ctx, agent=agent, limit=resume_limit, hypothesis=hyp_id).strip(),
            ]
        )
    lines.extend(["", "## Queue Health"])
    lines.extend(queue_health_lines(ctx, mode))
    return "\n".join(lines).rstrip() + "\n"


def recent_hypotheses(
    ctx: Context,
    limit: int = 20,
    agent: str = "",
    card_id: str = "",
    status_regex: str = "",
    strategy: str = "",
    rows: list[dict] | None = None,
) -> str:
    """Slim, agent-friendly digest of hypotheses.jsonl.

    Returns one row per line: id|status|agent|strategy|file|card_id|hypothesis(80c).
    Replaces `tail -80 hypotheses.jsonl`, which dumps ~60KB of full JSON when
    only the columns above are needed for triage.
    """
    import re

    rows = list(rows) if rows is not None else read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl")
    if status_regex:
        try:
            sre = re.compile(status_regex)
        except re.error as e:
            return f"[recent-hyps] invalid --status regex: {e}\n"
        rows = [r for r in rows if sre.search(r.get("status", ""))]
    if agent:
        rows = [r for r in rows if r.get("agent", "") == agent]
    if card_id:
        rows = [r for r in rows if r.get("card_id", "") == card_id]
    if strategy:
        rows = [r for r in rows if r.get("strategy", "") == strategy]

    rows.sort(key=lambda r: r.get("updated_at") or r.get("created_at") or "", reverse=True)
    if limit > 0:
        rows = rows[:limit]

    out = ["id|status|agent|strategy|file|card_id|hypothesis"]
    for r in rows:
        h = (r.get("hypothesis") or "").replace("|", "/").replace("\n", " ")
        if len(h) > 80:
            h = h[:77] + "..."
        out.append(
            f"{r.get('id','')}|{r.get('status','')}|{r.get('agent','')}|"
            f"{r.get('strategy','')}|{r.get('file','')}|{r.get('card_id','')}|{h}"
        )
    return "\n".join(out) + "\n"


def recent_runs(
    ctx: Context,
    limit: int = 20,
    agent: str = "",
    hypothesis_id: str = "",
    card_id: str = "",
    verdict_regex: str = "",
    rows: list[dict] | None = None,
) -> str:
    """Slim digest of runs.jsonl.

    Returns id|verdict|mode|agent|hypothesis_id|card_id|testcase. Replaces
    `tail -80 runs.jsonl`, which dumps ~30 KB of full JSON when triaging
    typically only needs the verdict and which testcase produced it.
    """
    import re

    rows = list(rows) if rows is not None else read_jsonl(state_dir(ctx.results_dir) / "runs.jsonl")
    if verdict_regex:
        try:
            vre = re.compile(verdict_regex)
        except re.error as e:
            return f"[recent-runs] invalid --verdict regex: {e}\n"
        rows = [r for r in rows if vre.search(r.get("verdict", ""))]
    if agent:
        rows = [r for r in rows if r.get("agent", "") == agent]
    if hypothesis_id:
        rows = [r for r in rows if r.get("hypothesis_id", "") == hypothesis_id]
    if card_id:
        rows = [r for r in rows if r.get("card_id", "") == card_id]

    rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    if limit > 0:
        rows = rows[:limit]

    out = ["id|verdict|mode|agent|hypothesis_id|card_id|testcase"]
    for r in rows:
        tc = (r.get("testcase") or "").replace("|", "/").replace("\n", " ")
        out.append(
            f"{r.get('id','')}|{r.get('verdict','')}|{r.get('mode','')}|"
            f"{r.get('agent','')}|{r.get('hypothesis_id','')}|{r.get('card_id','')}|{tc}"
        )
    return "\n".join(out) + "\n"


def runtime_feedback(
    ctx: Context,
    limit: int = 20,
    agent: str = "",
    hypothesis_id: str = "",
    card_id: str = "",
    rows: list[dict] | None = None,
) -> str:
    """Summarize recent probe outcomes into report-only next-action hints."""
    rows = list(rows) if rows is not None else read_jsonl(state_dir(ctx.results_dir) / "runs.jsonl")
    if agent:
        rows = [r for r in rows if r.get("agent", "") == agent]
    if hypothesis_id:
        rows = [r for r in rows if r.get("hypothesis_id", "") == hypothesis_id]
        scope = f"hypothesis `{hypothesis_id}`"
    elif card_id:
        rows = [r for r in rows if r.get("card_id", "") == card_id]
        scope = f"card `{card_id}`"
    else:
        scope = "agent recent runs"

    rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    if limit > 0:
        rows = rows[:limit]

    out = ["scope|recent_verdicts|runtime_signals|diagnosis|feedback"]
    if not rows:
        out.append(
            f"{scope}|none|none|needs-first-probe|"
            "write one testcase, run bin/probe, then update structured state"
        )
        return "\n".join(out) + "\n"

    verdict_counts: dict[str, int] = {}
    signal_counts: dict[str, int] = {}
    for row in rows:
        verdict = (row.get("verdict") or "UNKNOWN").strip().upper() or "UNKNOWN"
        verdict_counts[verdict] = verdict_counts.get(verdict, 0) + 1
        for signal in _runtime_row_signals(ctx, row):
            signal_counts[signal] = signal_counts.get(signal, 0) + 1

    verdict_text = ", ".join(
        f"{verdict}={verdict_counts[verdict]}"
        for verdict in sorted(verdict_counts)
    )
    signal_text = ", ".join(
        f"{signal}={signal_counts[signal]}"
        for signal in sorted(signal_counts)
    ) or "none"
    diagnosis, feedback = _runtime_feedback_decision(
        verdict_counts, sum(verdict_counts.values()), signal_counts
    )
    out.append(f"{scope}|{verdict_text}|{signal_text}|{diagnosis}|{feedback}")
    return "\n".join(out) + "\n"


def _runtime_row_signals(ctx: Context, row: dict) -> list[str]:
    text = _runtime_artifact_text(ctx, row)
    if not text:
        return []
    signals = [
        label
        for label, pattern in RUNTIME_SIGNAL_PATTERNS
        if pattern.search(text)
    ]
    if _runtime_has_near_miss(text):
        signals.append("coverage-near-miss")
    return signals


def _runtime_artifact_text(ctx: Context, row: dict) -> str:
    """Read the head of the saved sanitizer/runner output for one run.

    runs.jsonl stores `asan_output` as a path. The signals we scan for —
    sanitizer banners, parse/format errors, and the coverage gate's closest
    frame — all appear at the top of the output, so we read only a bounded
    prefix rather than the whole file. The file is not always size-capped:
    bin/probe caps only very large outputs, and rows can also come from older
    state, `bin/state add-run`, or external tooling that capped nothing. If the
    value is not a readable file, treat it as inline text.
    """
    value = str(row.get("asan_output") or "").strip()
    if not value:
        return ""
    path = Path(value)
    if not path.is_absolute():
        path = ctx.results_dir / path
    try:
        if path.is_file():
            # 64 KiB comfortably covers the head signals above without slurping
            # a multi-megabyte log into memory on every `state resume`.
            with open(path, "rb") as fh:
                return fh.read(65536).decode("utf-8", errors="replace")
    except OSError:
        pass
    return value


def _runtime_has_near_miss(text: str) -> bool:
    for match in NEAR_MISS_RE.finditer(text):
        closest = match.group(1).strip().strip("'\"")
        if closest and closest.lower() not in {"<none>", "none", "no_proximity"}:
            return True
    return False


def _runtime_feedback_decision(
    verdicts: dict[str, int],
    total: int,
    signals: dict[str, int],
) -> tuple[str, str]:
    if any(v in verdicts for v in ("CRASH", "DIFF", "FIND")):
        return (
            "productive-artifact",
            "productive signal exists; confirm, file, and cluster nearby before pivoting",
        )
    if signals.get("crash-signal", 0):
        return (
            "artifact-mismatch",
            "crash or sanitizer text appears in saved output; inspect artifact before discarding",
        )
    if verdicts.get("NO_EXEC", 0):
        return (
            "harness-setup",
            "runs are not executing; fix testcase header, harness build, runner path, or target.toml before mutating inputs",
        )
    if signals.get("coverage-near-miss", 0):
        return (
            "near-miss-targeting",
            "coverage near-miss seen; mutate around the closest reached frame before broadening seeds",
        )
    # format-reject is the more specific diagnosis: a parse/format rejection is
    # often also recorded as a NO_HIT/MISSED verdict, so check it before the
    # generic coverage-routing fallback or its precise seed advice gets masked.
    if signals.get("format-reject", 0) >= max(1, total // 2):
        return (
            "seed-format",
            "format rejects dominate; start from bin/find-seed output and preserve magic, length, checksum, and nesting",
        )
    miss_count = verdicts.get("NO_HIT", 0) + verdicts.get("MISSED", 0)
    if miss_count >= max(1, total // 2):
        return (
            "coverage-routing",
            "coverage misses dominate; use bin/find-seed or a broader valid seed before spending more sanitizer budget",
        )
    timeout_count = verdicts.get("TIMEOUT", 0) + verdicts.get("TIMEOUT_ONLY", 0)
    if timeout_count >= max(1, total // 2):
        return (
            "timeout-budget",
            "timeout signal dominates; minimize input and isolate runner budget before filing",
        )
    if verdicts.get("CLEAN", 0) == total and total >= 2:
        return (
            "clean-no-diagnostic",
            "CLEAN-only evidence; revise input shape or guard gap with seed, allocator, or state variants before discard",
        )
    return (
        "mixed-signal",
        "mixed runtime signal; compare testcase shapes and continue the highest-signal variant",
    )


def recent_notes(
    ctx: Context,
    limit: int = 20,
    agent: str = "",
    hypothesis_id: str = "",
    card_id: str = "",
    kind: str = "",
    rows: list[dict] | None = None,
) -> str:
    """Slim digest of notes.jsonl.

    Returns id|kind|agent|hypothesis_id|card_id|text. Notes hold the concise
    data-flow, guard, and variant context that used to live in markdown state.
    """
    rows = list(rows) if rows is not None else read_jsonl(state_dir(ctx.results_dir) / "notes.jsonl")
    if agent:
        rows = [r for r in rows if r.get("agent", "") == agent]
    if hypothesis_id:
        rows = [r for r in rows if r.get("hypothesis_id", "") == hypothesis_id]
    if card_id:
        rows = [r for r in rows if r.get("card_id", "") == card_id]
    if kind:
        rows = [r for r in rows if r.get("kind", "") == kind]

    rows.sort(key=lambda r: r.get("created_at") or "", reverse=True)
    if limit > 0:
        rows = rows[:limit]

    out = ["id|kind|agent|hypothesis_id|card_id|text"]
    for r in rows:
        text = (r.get("text") or "").replace("|", "/").replace("\n", " ")
        if len(text) > 120:
            text = text[:117] + "..."
        out.append(
            f"{r.get('id','')}|{r.get('kind','')}|{r.get('agent','')}|"
            f"{r.get('hypothesis_id','')}|{r.get('card_id','')}|{text}"
        )
    return "\n".join(out) + "\n"


def recent_claims(
    ctx: Context,
    limit: int = 20,
    agent: str = "",
    card_id: str = "",
    status: str = "",
) -> str:
    """Slim digest of claims.jsonl.

    Returns timestamp|status|agent|card_id|hypothesis_id|note. Replaces
    `tail -20 claims.jsonl`, which dumps ~14 KB of full JSON when the agent
    only needs to know which cards are currently held.
    """
    rows = read_jsonl(state_dir(ctx.results_dir) / "claims.jsonl")
    if agent:
        rows = [r for r in rows if r.get("agent", "") == agent]
    if card_id:
        rows = [r for r in rows if r.get("card_id", "") == card_id]
    if status:
        rows = [r for r in rows if r.get("status", "") == status]

    rows.sort(
        key=lambda r: r.get("updated_at") or r.get("claimed_at") or "",
        reverse=True,
    )
    if limit > 0:
        rows = rows[:limit]

    out = ["timestamp|status|agent|card_id|hypothesis_id|note"]
    for r in rows:
        ts = r.get("updated_at") or r.get("claimed_at") or ""
        note = (r.get("note") or "").replace("|", "/").replace("\n", " ")
        if len(note) > 80:
            note = note[:77] + "..."
        out.append(
            f"{ts}|{r.get('status','')}|{r.get('agent','')}|"
            f"{r.get('card_id','')}|{r.get('hypothesis_id','')}|{note}"
        )
    return "\n".join(out) + "\n"


def show_recent(
    ctx: Context,
    agent: str = "",
    hyps: int = 10,
    runs: int = 10,
    claims: int = 10,
    notes: int = 0,
) -> str:
    """One-call summary that replaces multi-`tail` shell pipelines.

    Each section is capped to its --N arg (0 disables the section). Default
    bundle (10 hyps + 10 runs + 10 claims) returns ≤4 KB versus ~50 KB for
    `tail -40 hypotheses.jsonl && tail -20 runs.jsonl && tail -20 claims.jsonl`.
    """
    parts: list[str] = []
    if hyps > 0:
        parts.append("# recent-hyps")
        parts.append(recent_hypotheses(ctx, limit=hyps, agent=agent).rstrip())
    if runs > 0:
        parts.append("\n# recent-runs")
        parts.append(recent_runs(ctx, limit=runs, agent=agent).rstrip())
    if claims > 0:
        parts.append("\n# recent-claims")
        parts.append(recent_claims(ctx, limit=claims, agent=agent).rstrip())
    if notes > 0:
        parts.append("\n# recent-notes")
        parts.append(recent_notes(ctx, limit=notes, agent=agent).rstrip())
    return "\n".join(parts) + "\n"


def last_terminal_reason(ctx: Context, agent: str = "", rows: list[dict] | None = None) -> str:
    """One-line summary of the latest terminal hypothesis for compact resumes."""
    rows = [
        r for r in (list(rows) if rows is not None else read_jsonl(state_dir(ctx.results_dir) / "hypotheses.jsonl"))
        if not is_active_hypothesis_status(r.get("status", ""))
    ]
    if agent:
        rows = [r for r in rows if r.get("agent", "") == agent]
    rows.sort(key=lambda r: r.get("updated_at") or r.get("created_at") or "", reverse=True)
    if not rows:
        return "- none\n"
    r = rows[0]
    note = (r.get("note") or r.get("reason") or "").replace("\n", " ").strip()
    if len(note) > 160:
        note = note[:157] + "..."
    parts = [
        f"- ID: `{r.get('id','')}`",
        f"Status: `{r.get('status','')}`",
        f"File: `{r.get('file','')}`",
    ]
    if note:
        parts.append(f"Reason: {note}")
    return " | ".join(parts) + "\n"


def _parse_tried_line(line: str) -> dict:
    """Parse a single tried-inputs line: 'TS key=val key=val ...'.

    Values may be %q-escaped (containing single quotes around them) — the
    target/closest fields can hold paths with spaces. Tolerant: unknown keys
    are kept; missing required keys default to empty string.
    """
    import shlex

    line = line.strip()
    if not line:
        return {}
    parts = line.split(None, 1)
    if not parts:
        return {}
    out: dict = {"timestamp": parts[0]}
    if len(parts) < 2:
        return out
    rest = parts[1]
    # shlex handles %q-escaped values produced by `printf '%q'`. POSIX shell
    # printf %q wraps tricky values in single quotes; shlex unwraps them.
    try:
        tokens = shlex.split(rest, posix=True)
    except ValueError:
        tokens = rest.split()
    for tok in tokens:
        if "=" not in tok:
            continue
        k, _, v = tok.partition("=")
        out[k] = v
    return out


def recent_tried(
    ctx: Context,
    agent: str,
    limit: int = 20,
    verdict_regex: str = "",
    hypothesis: str = "",
    target_substr: str = "",
) -> str:
    """Slim digest of tried-inputs-N.log (parsed key=value records).

    Returns timestamp|verdict|mode|hash|hypothesis|target|closest|testcase. Replaces
    `tail -80 tried-inputs-N.log` which returns ~22 KB per call when the agent
    only needs to confirm a hash isn't a duplicate. --agent picks the file;
    --agent all reads every per-agent log under RESULTS_DIR.
    """
    import re
    from pathlib import Path as _P

    if not agent:
        return "[recent-tried] --agent N (or --agent all) is required\n"

    paths: list[_P] = []
    if agent == "all":
        for p in sorted(ctx.results_dir.glob("tried-inputs-*.log")):
            paths.append(p)
    else:
        paths.append(ctx.results_dir / f"tried-inputs-{agent}.log")

    rows: list[dict] = []
    for p in paths:
        if not p.is_file():
            continue
        with p.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                rec = _parse_tried_line(line)
                if rec:
                    rec["_log"] = p.name
                    rows.append(rec)

    if verdict_regex:
        try:
            vre = re.compile(verdict_regex)
        except re.error as e:
            return f"[recent-tried] invalid --verdict regex: {e}\n"
        rows = [r for r in rows if vre.search(r.get("verdict", ""))]
    if hypothesis:
        rows = [r for r in rows if r.get("hypothesis", "") == hypothesis]
    if target_substr:
        rows = [r for r in rows if target_substr in r.get("target", "")]

    rows.sort(key=lambda r: r.get("timestamp") or "", reverse=True)
    if limit > 0:
        rows = rows[:limit]

    out = ["timestamp|verdict|mode|hash|hypothesis|target|closest|testcase"]
    for r in rows:
        tgt = (r.get("target") or "").replace("|", "/").replace("\n", " ")
        closest = (r.get("closest") or "").replace("|", "/").replace("\n", " ")
        if len(closest) > 120:
            closest = closest[:117] + "..."
        tc = (r.get("testcase") or "").replace("|", "/").replace("\n", " ")
        out.append(
            f"{r.get('timestamp','')}|{r.get('verdict','')}|{r.get('mode','')}|"
            f"{r.get('hash','')}|{r.get('hypothesis','')}|{tgt}|{closest}|{tc}"
        )
    return "\n".join(out) + "\n"


def write_cards(path: Path, cards: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    write_jsonl(path, cards)
