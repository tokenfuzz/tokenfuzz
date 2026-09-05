"""Canonical bug-class vocabulary for security findings.

One vocabulary, three consumers:

  * the find-quality gate labels every accepted finding with one canonical
    class (``.llm-find-quality.json`` ``class``);
  * finding clustering keys on the class *family* (``memory-safety``,
    ``auth``, ...) so a mechanism label and a consequence label for the same
    defect at one line still merge (see lib/finding_signature.py);
  * bin/severity translates the canonical class into a CVSS impact primitive
    when no sanitizer diagnostic or structured ``Primitive`` field supplies a
    stronger one, and holds that table itself.

The canonical tokens are the bug classes Anthropic Red's coordinated
vulnerability disclosure dashboard (https://red.anthropic.com/2026/cvd/,
``data/payload.json`` ``by_bug_class``) files findings under, so a class
breakdown here reads on the same axis as the public ledger. The harness keeps
a few classes of its own beside them (``HARNESS_CLASSES``): each is an
industry-standard name whose CVSS impact shape or detector lane differs from
every dashboard class, so folding it in would change a score or lose a
sanitizer-grade distinction. Anything else is ``other``.

This is the finding axis. It is distinct from the six neutral hypothesis
categories (lib/workqueue.py ``HYPOTHESIS_DIAGNOSTIC_CATEGORIES``), which
name a sanitizer sink for a testcase, and from bin/severity's primitive keys,
which score an already-confirmed defect.
"""

from __future__ import annotations

import re

# Cluster-key families. The merge edge for findings is (family, file, line),
# so a family only needs to be as fine as "would two reviewers of one defect
# disagree across this line". Ordered for prompt rendering.
FAMILIES = (
    "memory-safety",
    "dos",
    "injection",
    "deserialization",
    "auth",
    "crypto",
    "info-disclosure",
    "race",
    "boundary",
    "config",
    "logic",
    "other",
)

# Dashboard vocabulary: canonical class -> family. Every key is spelled as the
# dashboard spells it.
DASHBOARD_CLASSES: dict[str, str] = {
    "heap-buffer-overflow": "memory-safety",
    "stack-buffer-overflow": "memory-safety",
    "global-buffer-overflow": "memory-safety",
    "buffer-overflow": "memory-safety",
    "oob-read": "memory-safety",
    "oob-write": "memory-safety",
    "arbitrary-write": "memory-safety",
    "off-by-one": "memory-safety",
    "use-after-free": "memory-safety",
    "double-free": "memory-safety",
    "type-confusion": "memory-safety",
    "integer-overflow": "memory-safety",
    "integer-underflow": "memory-safety",
    "null-deref": "memory-safety",
    "segv": "memory-safety",
    # ASan's `stack-overflow` is recursion, not a stack buffer: availability.
    "stack-overflow": "dos",
    "denial-of-service": "dos",
    "uncaught-exception": "dos",
    "sql-injection": "injection",
    "command-injection": "injection",
    "code-injection": "injection",
    "rce": "injection",
    "xss": "injection",
    "deserialization": "deserialization",
    "auth-bypass": "auth",
    "broken-access-control": "auth",
    "privilege-escalation": "auth",
    "idor": "auth",
    "session-fixation": "auth",
    "confused-deputy": "auth",
    "crypto-failure": "crypto",
    "improper-cert-validation": "crypto",
    "signature-bypass": "crypto",
    "info-disclosure": "info-disclosure",
    "toctou": "race",
    "path-traversal": "boundary",
    "symlink-following": "boundary",
    "arbitrary-file-write": "boundary",
    "ssrf": "boundary",
    "open-redirect": "boundary",
    "cors-misconfig": "config",
    "logic-error": "logic",
    "other": "other",
}

# Harness-native classes: canonical class -> (family, why it is kept).
HARNESS_CLASSES: dict[str, tuple[str, str]] = {
    "invalid-free": (
        "memory-safety",
        "a source-argued free of the wrong allocator or address is an abort, "
        "not the code-execution row `double-free` scores",
    ),
    "uninitialized-read": (
        "memory-safety",
        "MemorySanitizer's use-of-uninitialized-value lane; scored as "
        "disclosure, but a distinct diagnostic from any dashboard class",
    ),
    "data-race": (
        "race",
        "a race-detector (ThreadSanitizer / Go `-race`) diagnostic is "
        "corruption-capable; a source-argued race is `toctou`",
    ),
    "ssti": (
        "injection",
        "template injection reaches the template engine's interpreter: "
        "full-compromise impact, not the L/L row of a generic injection",
    ),
    "xxe": (
        "injection",
        "external-entity expansion reads files and reaches internal hosts; "
        "its own detector regex and impact row in bin/severity",
    ),
    "csrf": (
        "auth",
        "a forged request acts with the victim's authority: integrity-only "
        "impact that no auth dashboard class carries",
    ),
    "prototype-pollution": (
        "deserialization",
        "untrusted keys mutate shared object state; scored as a low-impact "
        "primitive until a consumer turns it into another class",
    ),
    "sandbox-escape": (
        "boundary",
        "the escaped-to host is a subsequent system; `privilege-escalation` "
        "scores the vulnerable system only",
    ),
}

# Canonical class -> family, both vocabularies.
BUG_CLASSES: dict[str, str] = {
    **DASHBOARD_CLASSES,
    **{name: family for name, (family, _why) in HARNESS_CLASSES.items()},
}

# Synonyms, legacy sub-labels, sanitizer class names and neutral hypothesis
# categories -> canonical class. A value may also be a bare family name for a
# label that pins the family but no single class (``auth:bypass`` could be
# either authentication or authorization); the family still keys the cluster
# and severity leaves such a finding review-needed rather than guessing.
ALIASES: dict[str, str] = {
    # neutral hypothesis categories (AGENTS.md rule 9)
    "bounds": "buffer-overflow",
    "lifetime": "use-after-free",
    "type": "type-confusion",
    "size": "integer-overflow",
    "uninit": "uninitialized-read",
    "state": "memory-safety",
    # memory safety
    "memory_safety": "memory-safety",
    "memory-safety-class": "memory-safety",
    "memory-corruption": "memory-safety",
    "uaf": "use-after-free",
    "heap-use-after-free": "use-after-free",
    "use-after-poison": "use-after-free",
    "use-after-return": "use-after-free",
    "use-after-scope": "use-after-free",
    "stack-use-after-return": "use-after-free",
    "stack-use-after-scope": "use-after-free",
    "dangling-pointer": "use-after-free",
    "oob": "buffer-overflow",
    "out-of-bounds": "buffer-overflow",
    "out-of-bounds-read": "oob-read",
    "out-of-bounds-write": "oob-write",
    "oob-access": "buffer-overflow",
    "heap-overflow": "heap-buffer-overflow",
    "stack-buffer-underflow": "stack-buffer-overflow",
    "dynamic-stack-buffer-overflow": "stack-buffer-overflow",
    "container-overflow": "heap-buffer-overflow",
    "wild-read": "oob-read",
    "wild-write": "arbitrary-write",
    "wild-pointer": "segv",
    "int-overflow": "integer-overflow",
    "signed-integer-overflow": "integer-overflow",
    "unsigned-integer-overflow": "integer-overflow",
    "integer-truncation": "integer-overflow",
    "size-math": "integer-overflow",
    "bad-cast": "type-confusion",
    "bad-free": "invalid-free",
    "allocator-mismatch": "invalid-free",
    "alloc-dealloc-mismatch": "invalid-free",
    "null-pointer-dereference": "null-deref",
    "null-pointer-deref": "null-deref",
    "null-dereference": "null-deref",
    "nullptr-deref": "null-deref",
    "npe": "null-deref",
    "segfault": "segv",
    "sigsegv": "segv",
    "sigbus": "segv",
    "bus": "segv",
    "bus-error": "segv",
    "alignment": "segv",
    "misaligned-access": "segv",
    "use-of-uninitialized-value": "uninitialized-read",
    "uninitialized-memory": "uninitialized-read",
    "uninitialized-value": "uninitialized-read",
    # availability
    "dos": "denial-of-service",
    "denial-of-service-attack": "denial-of-service",
    "resource-exhaustion": "denial-of-service",
    "resource-amplification": "denial-of-service",
    "amplification": "denial-of-service",
    "algorithmic": "denial-of-service",
    "algorithmic-complexity": "denial-of-service",
    "decompression": "denial-of-service",
    "decompression-bomb": "denial-of-service",
    "hash-collision": "denial-of-service",
    "memory-leak": "denial-of-service",
    "oom": "denial-of-service",
    "out-of-memory": "denial-of-service",
    "regex-dos": "denial-of-service",
    "regex-complexity": "denial-of-service",
    "redos": "denial-of-service",
    "catastrophic-backtracking": "denial-of-service",
    "stack-exhaustion": "stack-overflow",
    "deep-recursion": "stack-overflow",
    "unbounded-recursion": "stack-overflow",
    "unhandled-exception": "uncaught-exception",
    "panic": "uncaught-exception",
    "traceback": "uncaught-exception",
    # injection
    "sql": "sql-injection",
    "sqli": "sql-injection",
    "nosql-injection": "injection",
    "command": "command-injection",
    "os-command-injection": "command-injection",
    "shell-injection": "command-injection",
    "argument-injection": "command-injection",
    "eval-injection": "code-injection",
    "python-code": "code-injection",
    "code-execution": "rce",
    "arbitrary-code-execution": "rce",
    "remote-code-execution": "rce",
    "template-injection": "ssti",
    "server-side-template-injection": "ssti",
    "cross-site-scripting": "xss",
    "mutation-xss": "xss",
    "dom-xss": "xss",
    "stored-xss": "xss",
    "reflected-xss": "xss",
    "xml-external-entity": "xxe",
    "terminal": "injection",
    "terminal-escape": "injection",
    "header-injection": "injection",
    "crlf-injection": "injection",
    "log-injection": "injection",
    # deserialization
    "unsafe-deserialization": "deserialization",
    "insecure-deserialization": "deserialization",
    "pickle": "deserialization",
    "object-injection": "deserialization",
    # auth
    "authz": "auth",
    "authn": "auth",
    "authorization": "auth",
    "authentication": "auth",
    "authn-bypass": "auth-bypass",
    "authentication-bypass": "auth-bypass",
    "login-bypass": "auth-bypass",
    "session-hijacking": "auth-bypass",
    "authz-bypass": "broken-access-control",
    "authorization-bypass": "broken-access-control",
    "access-control": "broken-access-control",
    "access-control-bypass": "broken-access-control",
    "missing-authorization": "broken-access-control",
    "privesc": "privilege-escalation",
    "insecure-direct-object-reference": "idor",
    "cross-site-request-forgery": "csrf",
    # crypto
    "crypto-weakness": "crypto-failure",
    "cryptographic-weakness": "crypto-failure",
    "weak-crypto": "crypto-failure",
    "weak-hash": "crypto-failure",
    "weak-cipher": "crypto-failure",
    "weak-random": "crypto-failure",
    "insecure-random": "crypto-failure",
    "reused-iv": "crypto-failure",
    "nonce-reuse": "crypto-failure",
    "padding-oracle": "crypto-failure",
    "cert-validation": "improper-cert-validation",
    "certificate-validation": "improper-cert-validation",
    "tls-validation": "improper-cert-validation",
    "hostname-verification": "improper-cert-validation",
    "signature-forgery": "signature-bypass",
    "signature-verification-bypass": "signature-bypass",
    "ld-signature-bypass": "signature-bypass",
    # disclosure
    "info_disclosure": "info-disclosure",
    "info-leak": "info-disclosure",
    "information-disclosure": "info-disclosure",
    "information-leak": "info-disclosure",
    "memory-disclosure": "info-disclosure",
    "secrets-exposure": "info-disclosure",
    "secret-exposure": "info-disclosure",
    "credential-leak": "info-disclosure",
    "credential-exposure": "info-disclosure",
    "hardcoded-credential": "info-disclosure",
    "pii": "info-disclosure",
    "side-channel": "info-disclosure",
    "timing": "info-disclosure",
    "timing-attack": "info-disclosure",
    "cache-timing": "info-disclosure",
    # race
    "race-condition": "toctou",
    "time-of-check": "toctou",
    "time-of-check-time-of-use": "toctou",
    "resource-selection": "toctou",
    # boundary
    "boundary-violation": "boundary",
    "directory-traversal": "path-traversal",
    "path-escape": "path-traversal",
    "zip-slip": "path-traversal",
    "arbitrary-file-read": "path-traversal",
    "path-traversal-read": "path-traversal",
    "local-file-read": "path-traversal",
    "lfi": "path-traversal",
    "uri-filter-bypass": "path-traversal",
    "symlink": "symlink-following",
    "link-following": "symlink-following",
    "path-traversal-write": "arbitrary-file-write",
    "file-write": "arbitrary-file-write",
    "arbitrary-file-delete": "arbitrary-file-write",
    "server-side-request-forgery": "ssrf",
    "unvalidated-redirect": "open-redirect",
    "container-escape": "sandbox-escape",
    "vm-escape": "sandbox-escape",
    # config
    "misconfiguration": "config",
    "permissive-default": "config",
    "cors": "cors-misconfig",
    "cors-misconfiguration": "cors-misconfig",
    # logic
    "logic": "logic-error",
    "business-logic": "logic-error",
    "business-rule": "logic-error",
    "validation-bypass": "logic-error",
    "context-confusion": "logic-error",
    "resource-substitution": "logic-error",
    "identifier-truncation": "logic-error",
    "logic-regression": "logic-error",
    "defense-in-depth": "logic-error",
    # other
    "unknown": "other",
    "unclassified": "other",
    "none": "other",
    "null": "other",
}

# Historical accepted labels whose `top:sub` reading is wrong when taken apart:
# the sub-label alone names a traversal but the top says it writes, or the top
# was a boundary/disclosure framing of a class that lives in another family.
_LEGACY_LABELS: dict[str, str] = {
    "file-write:path-traversal": "arbitrary-file-write",
    "integrity:path-traversal": "arbitrary-file-write",
    "filesystem:path-traversal-write": "arbitrary-file-write",
    "boundary:context-confusion": "logic-error",
    "boundary:resource-substitution": "logic-error",
    "info-disclosure:xxe": "xxe",
}

_TOKEN_JUNK_RE = re.compile(r"[^a-z0-9:\-]+")


def _token(raw: object) -> str:
    """Lowercase, kebab-case, trailing punctuation stripped."""
    if raw is None:
        return ""
    s = str(raw).strip().strip("`").lower()
    s = s.replace("_", "-")
    s = _TOKEN_JUNK_RE.sub("-", s)
    return s.strip("-:")


def _resolve_single(token: str) -> tuple[str, str]:
    """One colon-free token -> (canonical class, family), either may be ''."""
    if not token:
        return "", ""
    if token in ALIASES:
        token = ALIASES[token]
    if token in BUG_CLASSES:
        return token, BUG_CLASSES[token]
    if token in FAMILIES:
        return "", token
    if "overflow" in token:
        # An unknown *overflow* label is a bounds violation of unspecified
        # region: the mechanism and the consequence must land together.
        return "buffer-overflow", "memory-safety"
    return "", ""


def canonical_class(raw: object) -> str:
    """Map any class label to its canonical class.

    ``"heap-buffer-overflow"``          -> ``"heap-buffer-overflow"``
    ``"memory-safety:lifetime"``        -> ``"use-after-free"``
    ``"injection:sql"``                 -> ``"sql-injection"``
    ``"Bounds"`` (neutral vocabulary)   -> ``"buffer-overflow"``
    ``"auth:bypass"``                   -> ``"auth"`` (family only: authn or
                                            authz is undecided)
    ``"container-overflow:xyz"``        -> ``"heap-buffer-overflow"``
    ``""`` / ``None`` / unknown         -> ``"other"``

    A legacy ``top:sub`` label keeps the family its top named — the top was a
    closed list a reviewer chose, the sub a free mechanism note — and the
    sub-label refines the class only inside that family. A sub-label from
    another family cannot move the finding's cluster or impact shape;
    ``memory-safety:stack-overflow`` stays memory-safety rather than becoming
    a DoS. With no resolvable top, the sub-label decides.
    """
    s = _token(raw)
    if not s:
        return "other"
    if s in _LEGACY_LABELS:
        return _LEGACY_LABELS[s]
    top, _, sub = s.partition(":")
    top_class, top_family = _resolve_single(top)
    sub_class, sub_family = _resolve_single(sub)
    if top_family and sub_class and sub_family == top_family:
        return sub_class
    return top_class or top_family or sub_class or sub_family or "other"


def family_of(raw: object) -> str:
    """The cluster-key family for any class label; ``other`` when unknown."""
    resolved = canonical_class(raw)
    if resolved in BUG_CLASSES:
        return BUG_CLASSES[resolved]
    if resolved in FAMILIES:
        return resolved
    return "other"


def is_canonical(raw: object) -> bool:
    """Whether the label is already spelled as a canonical class."""
    return _token(raw) in BUG_CLASSES


def prompt_menu() -> str:
    """The canonical classes grouped by family, for prompt rendering."""
    groups: list[str] = []
    for family in FAMILIES:
        members = [
            name for name, fam in BUG_CLASSES.items()
            if fam == family and name != "other"
        ]
        if members:
            groups.append(f"{family}: {', '.join(members)}")
    return "; ".join(groups) + "; other"
