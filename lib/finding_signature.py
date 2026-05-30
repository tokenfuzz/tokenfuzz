"""Signature + clustering helpers for FIND-* reports.

Findings are heterogeneous: most are memory-safety bugs with a concrete
`file:function:line` site, but the harness also files auth, injection,
info-disclosure, crypto, race, config, and logic findings whose
"location" is an endpoint, config key, or design concept. One key shape
won't fit all, so the signature draws on, in precedence order:

  dedup_key — a short canonical token naming the ROOT CAUSE concept,
              independent of which surface site each FIND cites. Assigned
              by lib/finding_keyer.py from the report alone and cached in
              .finding-key.json (passed in here as `llm_dedup_key`). The
              primary signal: two reports of the same root cause from
              different sites collapse under it, the same way for every
              finding source (harness, recon, model-direct).

  (class, file, func) — the deterministic fallback site, with :line:col
              stripped (drift absorption — the trick bin/cluster-crashes
              uses on top frames). Used when no dedup_key was produced.

Cluster key:
  - If a well-formed dedup_key is present → (class, "", dedup_key)
  - Else if (file, func) extracted from report → (class, file, func)
  - Else → (class, "", title_slug) — last-resort tail
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Optional


# ── Class normalization ───────────────────────────────────────────
# Reports come from two vocabularies:
#   * Neutral 6 (from AGENTS.md): bounds / lifetime / type / size /
#     uninit / state. All of these are sub-classes of memory-safety.
#   * LLM "top:sub" labels: memory-safety:bounds, auth:bypass, etc.
#
# We collapse to a small top-level enum so the key doesn't fragment over
# label drift ("uaf" vs "memory-safety" vs "lifetime"). The sub-label is
# dropped from the key — same-class-different-sub findings still benefit
# from being clustered together, and the LLM dedup_key handles the rest.

_TOP_LEVEL_CLASSES = (
    "memory-safety",
    "auth",
    "injection",
    "info-disclosure",
    "crypto",
    "race",
    "boundary",
    "deserialization",
    "config",
    "logic",
    "side-channel",
    "dos",
    "other",
)

_NEUTRAL_TO_TOP = {
    "bounds": "memory-safety",
    "lifetime": "memory-safety",
    "type": "memory-safety",
    "size": "memory-safety",
    "uninit": "memory-safety",
    "state": "memory-safety",
    "uaf": "memory-safety",
    "use-after-free": "memory-safety",
    "heap-use-after-free": "memory-safety",
    "heap-buffer-overflow": "memory-safety",
    "double-free": "memory-safety",
    "buffer-overflow": "memory-safety",
    "stack-buffer-overflow": "memory-safety",
    "out-of-bounds": "memory-safety",
    "oob": "memory-safety",
    "memory_safety": "memory-safety",
    "memory-safety-class": "memory-safety",
    "authz": "auth",
    "authn": "auth",
    "authorization": "auth",
    "authentication": "auth",
    "xss": "injection",
    "sqli": "injection",
    "sql-injection": "injection",
    "rce": "injection",
    "info_disclosure": "info-disclosure",
    "info-leak": "info-disclosure",
    "information-disclosure": "info-disclosure",
    "toctou": "race",
    "data-race": "race",
    "csp-bypass": "boundary",
    "sandbox-escape": "boundary",
    "boundary-violation": "boundary",
    "unsafe-deserialization": "deserialization",
    "misconfiguration": "config",
    "permissive-default": "config",
    "business-logic": "logic",
    "timing": "side-channel",
    "algorithmic": "dos",
}


def normalize_class(raw: str) -> str:
    """Map any class label to a small canonical token.

    "memory-safety:bounds"      → "memory-safety"
    "state" (neutral vocab)     → "memory-safety"
    "auth:bypass"               → "auth"
    "network:dns-response-…"    → "network"     (unknown top retained)
    "input-validation:hostname" → "input-validation"
    "" or None                  → "other"

    Unknown labels keep their top segment instead of collapsing to
    "other" — the LLM's own taxonomy is more useful than forcing every
    unfamiliar class into one bucket, and two reports about the same
    root cause tend to use the same top label.
    """
    if not raw:
        return "other"
    s = str(raw).strip().lower()
    if not s or s in ("null", "none"):
        return "other"
    # "top:sub" → "top"
    top = s.split(":", 1)[0].strip()
    top = re.sub(r"[^a-z0-9\-]+", "-", top).strip("-")
    if not top:
        return "other"
    if top in _TOP_LEVEL_CLASSES:
        return top
    # Neutral-6 and common synonyms
    if top in _NEUTRAL_TO_TOP:
        return _NEUTRAL_TO_TOP[top]
    # Substring rescue for well-known classes (catches "memory_safety",
    # "auth-bypass", "info_disclosure" etc.)
    for alias, top_level in _NEUTRAL_TO_TOP.items():
        if alias in top:
            return top_level
    for top_level in _TOP_LEVEL_CLASSES:
        if top_level in top:
            return top_level
    # Keep the LLM's own top label — better than "other" for clustering.
    return top


# ── Class extraction from a report body ────────────────────────────
# Reports use a mix of forms — accept all of them. First match wins.
_CLASS_PATTERNS = [
    re.compile(r"^\s*-\s*\*\*Class(?:ification)?\*\*\s*:\s*`?([A-Za-z][\w:.\-]*)`?", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*Class(?:ification)?\s*:\s*`?([A-Za-z][\w:.\-]*)`?", re.MULTILINE | re.IGNORECASE),
    # `| Class | <value> |` — the Fields-table row. recon FIND reports
    # carry the canonical Class there (no `- **Class**` bullet) since
    # the section duplicating it was dropped from the template.
    re.compile(r"^\s*\|\s*Class(?:ification)?\s*\|\s*`?([A-Za-z][\w:.\-]*)`?\s*\|", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*-?\s*Category\s*:\s*`?([A-Za-z][\w:.\-]*)`?", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*-?\s*Memory[- ]safety\s+class\s*:\s*`?([A-Za-z][\w:.\-]*)`?", re.MULTILINE | re.IGNORECASE),
    re.compile(r"^\s*-?\s*Issue\s+class\s*:\s*`?([A-Za-z][\w:.\-/ ]*?)`?\s*$", re.MULTILINE | re.IGNORECASE),
    # "Bug class:", "Bug type:", "Vulnerability class:", "Weakness category:" —
    # bare-prompt / model-direct reports label the class this way instead of the
    # harness's `Class:` field. Structural family (<noun> class|type|category),
    # not an enumeration, so new noun phrasings don't rot it. The value capture
    # stops at the first whitespace so `stack-buffer-overflow / command …`
    # yields the leading canonical token, which normalize_class folds.
    re.compile(r"^\s*-?\s*(?:Bug|Vulnerability|Vuln|Defect|Weakness)\s+(?:class|type|category)\s*:\s*`?([A-Za-z][\w:.\-]*)`?", re.MULTILINE | re.IGNORECASE),
    # "- **Type**: Lifetime issue — heap-use-after-free, READ of size 1+"
    # We pull the first meaningful word (Lifetime / Bounds / heap-use-after-free).
    re.compile(r"^\s*-\s*\*\*Type\*\*\s*:\s*`?([A-Za-z][\w\-]*)", re.MULTILINE | re.IGNORECASE),
]


def extract_class(report_text: str) -> str:
    """Pull the class label from any of the supported report forms."""
    for pat in _CLASS_PATTERNS:
        m = pat.search(report_text or "")
        if m:
            return m.group(1).strip().rstrip(".,;")
    return ""


# ── Path normalization ─────────────────────────────────────────────
# Reports cite paths in three shapes that the deterministic key must
# collapse to ONE canonical target-relative form:
#   * relative: src/lib/foo.c
#   * absolute / repo-prefixed: <TARGET_ROOT>/targets/c-ares/src/lib/foo.c
#   * basename-only (from ASan stack frames): foo.c
#
# We strip the target_root prefix when supplied (auto-derived by
# bin/cluster-findings from the output/<slug> layout) and keep the FULL
# remaining path. We deliberately do NOT truncate to a basename or a
# fixed segment tail: two distinct files that share a leaf name
# (`parse.c` in two dirs) must stay distinct, so over-merging by
# truncation is worse than the drift it would absorb. Drift is instead
# removed at the source — extract_location prefers the canonical
# `| File |` Fields-table row, which every report writes identically.


def normalize_path(path: str, target_root: str = "") -> str:
    if not path:
        return ""
    p = path.strip().strip("`").strip("'\"")
    # Strip a `(some text)` trailing annotation the LLM sometimes attaches.
    p = re.sub(r"\s+\([^)]*\)\s*$", "", p)
    if target_root:
        tr = target_root.strip().rstrip("/")
        if tr and (p == tr or p.startswith(tr + "/")):
            # Same form (both absolute or both relative): plain prefix strip.
            p = p[len(tr):]
        elif tr:
            # Mixed forms — the audit passes an ABSOLUTE target_root
            # (/…/targets/<slug>) but reports cite repo-relative paths
            # (targets/<slug>/src/…), or vice versa. Strip up to and
            # including the target's own tail marker so either form lands on
            # the same target-relative path. Prefer the "targets/<slug>/"
            # tail; fall back to the bare basename dir.
            m = re.search(r"(?:^|/)(targets/[^/]+)$", tr)
            marker = (m.group(1) if m else tr.rsplit("/", 1)[-1]) + "/"
            idx = p.find(marker)
            if idx != -1:
                p = p[idx + len(marker):]
    # Collapse repeated slashes; keep the full target-relative path.
    p = re.sub(r"/+", "/", p).lstrip("/")
    # Structural fallback: reports universally cite the bug site as
    # `targets/<slug>/<path>`. Strip a leading `targets/<seg>/` so the key is
    # target-relative even when target_root was unset or mis-derived — e.g. the
    # benchmark output layout, whose cluster path does not carry the target slug
    # (output/benchmark/<backend>/…), so derivation can't supply it.
    p = re.sub(r"^targets/[^/]+/", "", p)
    parts = [seg for seg in p.split("/") if seg]
    return "/".join(parts)


# ── Location extraction ────────────────────────────────────────────
# Three families of report layout, in priority order:
#
#   1. Explicit Location line:
#        Location: `src/lib/foo.c:func_name:42`
#        - Location: `src/lib/foo.c:func_name`
#        ## Location\n`src/lib/foo.c:func_name`
#
#   2. file:func:line embedded anywhere in the body, optionally in
#      backticks. Source extension whitelist suppresses spurious hits.
#
#   3. file:func (no line) inside backticks under a Location heading.

# Extension alternation. CRITICAL: longest alternative first so the
# regex engine doesn't shortcut `foo.cc` to `foo.c` + leftover `c`.
_SRC_EXT = r"(?:cpp|cxx|cc|hpp|hxx|hh|mm|tsx|jsx|swift|java|kt|rs|go|py|js|ts|sh|pl|rb|php|c|h|m)"
_PATH_FRAG = rf"[A-Za-z0-9_./\-]+\.{_SRC_EXT}"
# Functions can include namespaces (foo::bar), destructors (~Foo), template
# brackets (Foo<T>), but never a colon followed by digits — that's the line
# number, which we strip aggressively.
_FUNC_FRAG = r"[A-Za-z_~][\w~]*(?:::[A-Za-z_~][\w~]*)*(?:<[^>]*>)?"

_LOCATION_HEADER_RE = re.compile(
    r"(?:^|\n)\s*(?:#{1,6}\s+Location|-\s+\*\*Location\*\*|-?\s*Location)\s*:?\s*\n?\s*`?"
    rf"(?P<file>{_PATH_FRAG})(?::(?P<func>{_FUNC_FRAG}))?(?::(?P<line>\d+))?`?",
    re.MULTILINE,
)
_INLINE_FILE_FUNC_LINE_RE = re.compile(
    rf"`?(?P<file>{_PATH_FRAG}):(?P<func>{_FUNC_FRAG})(?::(?P<line>\d+))?`?"
)
_INLINE_FILE_LINE_RE = re.compile(
    rf"`?(?P<file>{_PATH_FRAG}):(?P<line>\d+)`?"
)
_INLINE_FILE_ONLY_RE = re.compile(rf"`(?P<file>{_PATH_FRAG})`")


# ── Canonical-source extractors (Fields table + ASan frame #0) ─────
# A FIND report carries the bug site in up to three places of differing
# authority. We pick file and func INDEPENDENTLY from the most
# authoritative source that has each, because the best source differs
# per field:
#
#   * file — the `| File |` Fields-table row is the canonical, full,
#     target-relative path the report author intended. Stack frames and
#     prose cite the basename only, so the table wins for `file`.
#   * func — the ASan stack frame #0 carries the fully-qualified,
#     demangled compiler symbol (`ns::Class::method`), identical across
#     reports of the same crash. The `| Function |` row is a free-text
#     label that drifts (`assign` / `frame_capacity`), so frame #0 wins
#     for `func` when a crash exists.
#
# Findings with no crash (pure source analysis) have no frame #0; they
# fall through to the table row and then the legacy patterns.

_FIELDS_FILE_RE = re.compile(
    r"^\s*\|\s*File\s*\|\s*`?(?P<file>[^|`\n]+?)`?\s*\|", re.MULTILINE | re.IGNORECASE,
)
_FIELDS_FUNC_RE = re.compile(
    r"^\s*\|\s*Function\s*\|\s*`?(?P<func>[^|`\n]+?)`?\s*\|", re.MULTILINE | re.IGNORECASE,
)
# The `| Line |` Fields-table row — the canonical source line every harness
# report writes, identical across re-discoveries of one bug. The cell may carry
# a prefix/suffix ("L2491", "183 (the memcpy)"); capture the first integer run.
_FIELDS_LINE_RE = re.compile(
    r"^\s*\|\s*Line\s*\|\s*[^|\d]*(?P<line>\d+)", re.MULTILINE | re.IGNORECASE,
)
# An ASan/symbolized stack frame: `#0 [0xADDR in ]<symbol>[(args)] <file>:<line>[:col]`.
# The frame body lives inside ```fences``` in many reports, so this runs
# on the UNmasked text (unlike the inline prose patterns below).
_FRAME0_LINE_RE = re.compile(r"^\s*#0\s+(?P<body>.+?)\s*$", re.MULTILINE)
_FRAME0_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]+\s+in\s+")
_FRAME0_TAIL_RE = re.compile(rf"(?P<file>{_PATH_FRAG})(?::\d+){{0,2}}\s*$")


def _fields_row(text: str, rx: re.Pattern) -> str:
    m = rx.search(text or "")
    return m.group(1).strip() if m else ""


def _extract_frame0(text: str) -> tuple[str, str]:
    """Return (file, func) from the innermost ASan stack frame, or ("","").

    func is the demangled symbol with any `(args)` stripped; file is the
    basename ASan prints (caller prefers the Fields-table path for file).
    """
    for m in _FRAME0_LINE_RE.finditer(text or ""):
        body = _FRAME0_ADDR_RE.sub("", m.group("body").strip())
        tail = _FRAME0_TAIL_RE.search(body)
        if not tail:
            continue
        file = tail.group("file")
        head = body[:tail.start()].rstrip()
        func = head.split("(", 1)[0].strip()  # drop argument list
        return file, func
    return "", ""


def _clean_func(func: str) -> str:
    """Strip backticks, an argument list, and a trailing :line from a func."""
    f = (func or "").strip().strip("`").strip()
    f = f.split("(", 1)[0].strip()
    f = re.sub(r":\d+\s*$", "", f)
    return f


def _legacy_location(text: str) -> tuple[str, str]:
    """File/func from the Location: header or inline prose (raw, un-normalized)."""
    m = _LOCATION_HEADER_RE.search(text)
    if m:
        return (m.group("file") or "", (m.group("func") or "").strip())
    # Inline patterns skip fenced ```code``` blocks (reproducer snippets).
    masked = _prose_text(text)
    m = _INLINE_FILE_FUNC_LINE_RE.search(masked)
    if m:
        return (m.group("file") or "", (m.group("func") or "").strip())
    m = _INLINE_FILE_LINE_RE.search(masked)
    if m:
        return (m.group("file") or "", "")
    m = _INLINE_FILE_ONLY_RE.search(masked)
    if m:
        return (m.group("file") or "", "")
    return "", ""


def _first(*vals: str) -> str:
    for v in vals:
        if v:
            return v
    return ""


def extract_location(report_text: str, target_root: str = "") -> tuple[str, str]:
    """Return (file, func) — normalized, line/col stripped.

    file and func are chosen independently from the most authoritative
    source that supplies each (see the Fields/frame#0 note above):
      file: `| File |` row → Location/inline → frame #0 basename
      func: frame #0 symbol → `| Function |` row → Location/inline
    file is empty when no recognizable path is present; func is empty
    when the report cites a file but no function.
    """
    text = report_text or ""
    f0_file, f0_func = _extract_frame0(text)
    ft_file = _fields_row(text, _FIELDS_FILE_RE)
    ft_func = _fields_row(text, _FIELDS_FUNC_RE)
    lg_file, lg_func = _legacy_location(text)

    file = _first(ft_file, lg_file, f0_file)
    func = _first(f0_func, ft_func, lg_func)
    return normalize_path(file, target_root), _clean_func(func)


_CODE_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)


def _strip_code_fences(text: str) -> str:
    return _CODE_FENCE_RE.sub("", text)


# bin/cluster-findings stamps `Cluster:` and `Dedup key:` lines into a report
# after it clusters. Those are harness metadata, not authored content — and a
# `Dedup key: [loc] file:func` stamp injects a file:func token the inline
# scanners below would misread as the bug site on a re-run, shifting (file,
# line) and breaking clustering idempotency. Drop them before inline scanning so
# identity stays a pure function of the authored report.
_HARNESS_STAMP_RE = re.compile(
    r"^(?:Cluster|Dedup key):.*$", re.MULTILINE | re.IGNORECASE,
)


def _prose_text(text: str) -> str:
    """Report text for inline-site scanning: code fences and harness stamps removed."""
    return _strip_code_fences(_HARNESS_STAMP_RE.sub("", text or ""))


def extract_line(report_text: str) -> str:
    """Return the bug-site line number as a string, or "".

    Prefers the canonical `| Line |` Fields-table row (present and identical
    across every harness re-discovery of one bug); falls back to a line
    captured alongside an inline file:func:line / file:line site. Feeds the
    (class, file, line) merge edge in lib/finding_dedup.py — the line is the
    discriminator that makes a location edge safe where (file, func) alone
    would fuse distinct bugs sharing one large function. Reproducer line
    numbers inside ```fences``` are masked out for the inline fallback.
    """
    text = report_text or ""
    m = _FIELDS_LINE_RE.search(text)
    if m:
        return m.group("line")
    m = _LOCATION_HEADER_RE.search(text)
    if m and m.group("line"):
        return m.group("line")
    masked = _prose_text(text)
    for rx in (_INLINE_FILE_FUNC_LINE_RE, _INLINE_FILE_LINE_RE):
        m = rx.search(masked)
        if m and m.group("line"):
            return m.group("line")
    return ""


# ── Title slug (fallback when no file/func and no dedup_key) ────────

_TITLE_SLUG_RE = re.compile(r"[^a-z0-9]+")


def _title_slug(report_text: str, want_words: int = 6) -> str:
    """Take the first H1, lowercase, hyphen-join the first N words.

    Last-resort key — used when the LLM dedup_key is absent AND the
    report has no extractable file:function. Distinct enough to give
    each unique finding its own cluster, but matches on near-duplicate
    titles ("XSS in foo" vs "XSS in foo handler").
    """
    for line in (report_text or "").splitlines():
        line = line.strip()
        if line.startswith("# "):
            t = line.lstrip("#").strip().lower()
            t = _TITLE_SLUG_RE.sub("-", t).strip("-")
            words = [w for w in t.split("-") if w][:want_words]
            return "-".join(words)
    return ""


# ── dedup_key validation ───────────────────────────────────────────
# LLM-emitted token. Constraints (kept loose enough that the LLM has
# room to be canonical, tight enough that "the bug is in src/foo"
# doesn't masquerade as a key):
#   * 4–60 chars
#   * lowercase letters, digits, hyphens, underscores
#   * at least one hyphen or underscore (multi-token)

_DEDUP_KEY_RE = re.compile(r"^[a-z0-9]+(?:[-_][a-z0-9]+){1,8}$")


def is_valid_dedup_key(key: str) -> bool:
    """Strict validator — does NOT lowercase. Callers should pre-normalize."""
    if not key:
        return False
    k = str(key).strip()
    if len(k) < 4 or len(k) > 60:
        return False
    return bool(_DEDUP_KEY_RE.match(k))


# ── Composite signature ────────────────────────────────────────────


def finding_signature(
    report_text: str,
    llm_class: str = "",
    llm_dedup_key: str = "",
    target_root: str = "",
) -> dict:
    """Compute everything bin/cluster-findings needs in one pass."""
    cls_raw = llm_class or extract_class(report_text)
    cls = normalize_class(cls_raw)
    file, func = extract_location(report_text, target_root=target_root)
    line = extract_line(report_text)
    dedup_key = llm_dedup_key.strip().lower() if llm_dedup_key else ""
    if not is_valid_dedup_key(dedup_key):
        dedup_key = ""
    if dedup_key:
        kind = "llm"
        key = (cls, "", dedup_key)
    elif file or func:
        kind = "loc"
        key = (cls, file, func)
    else:
        kind = "title"
        key = (cls, "", _title_slug(report_text))
    return {
        "class": cls,
        "class_raw": cls_raw,
        "file": file,
        "func": func,
        "line": line,
        "dedup_key": dedup_key,
        "kind": kind,
        "key": key,
    }


def cluster_id(key: tuple) -> str:
    """Stable short id, FCL-<8 hex>. Mirrors bin/cluster-crashes' CL-<...>."""
    h = hashlib.sha1("|".join(str(p) for p in key).encode("utf-8")).hexdigest()[:8]
    return f"FCL-{h}"


# ── LLM cache reader ───────────────────────────────────────────────


def read_llm_cache(find_dir: Path) -> dict:
    """Return {class, severity, dedup_key} from .llm-find-quality.json.

    Returns {} if the cache is missing, unparseable, or accept=false.
    """
    p = find_dir / ".llm-find-quality.json"
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text("utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    if not data.get("accept"):
        return {}
    return {
        "class": data.get("class", "") or "",
        "severity": data.get("severity", "") or "",
        "dedup_key": data.get("dedup_key", "") or "",
    }


# ── CLI (for ad-hoc inspection / tests) ────────────────────────────


def _read_report(find_dir: Path) -> tuple[Optional[Path], str]:
    for name in ("REPORT.md", "report.md", "description.md", "analysis.md", "README.md"):
        p = find_dir / name
        if p.is_file():
            try:
                return p, p.read_text("utf-8", errors="replace")
            except OSError:
                continue
    return None, ""


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("find_dir", type=Path,
                    help="Path to a FIND-* directory")
    ap.add_argument("--target-root", default="",
                    help="Strip this prefix from absolute paths in the report")
    ap.add_argument("--json", action="store_true", help="Emit signature as JSON")
    args = ap.parse_args(argv)

    if not args.find_dir.is_dir():
        print(f"not a directory: {args.find_dir}", file=sys.stderr)
        return 1

    _, text = _read_report(args.find_dir)
    cache = read_llm_cache(args.find_dir)
    # dedup_key is owned by the keyer (.finding-key.json), not the quality
    # cache. Local import keeps finding_keyer's import of this module acyclic.
    import finding_keyer  # noqa: E402
    sig = finding_signature(
        text,
        llm_class=cache.get("class", ""),
        llm_dedup_key=finding_keyer.cached_key(args.find_dir),
        target_root=args.target_root,
    )
    sig["id"] = args.find_dir.name
    sig["cluster"] = cluster_id(sig["key"])

    if args.json:
        # Tuples aren't JSON; flatten.
        out = dict(sig)
        out["key"] = list(sig["key"])
        json.dump(out, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(f"id        : {sig['id']}")
        print(f"cluster   : {sig['cluster']}")
        print(f"class     : {sig['class']} (raw={sig['class_raw']!r})")
        print(f"file      : {sig['file']}")
        print(f"func      : {sig['func']}")
        print(f"dedup_key : {sig['dedup_key']}")
        print(f"kind      : {sig['kind']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
