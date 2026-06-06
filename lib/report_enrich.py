"""lib/report_enrich.py — make crash/finding reports easier to skim.

Mutates a `report.md` in place, inserting blocks that are tedious to
write by hand but trivial to derive from sibling artifacts and the
target source tree:

* Reviewer TL;DR card at the top (bug / trigger / fix).
* Severity badge under the title.
* Sibling-cluster line under the Cluster: field.
* Inlined `patch.diff` content under "Patch" (this module is the
  sole writer of that section; the sibling file is the canonical
  source, and any patch-aliased section the agent may have inlined
  is stripped and replaced).
* Source snippets under each `file:line` bullet in "Data Flow Trace"
  / "Affected" / "Affected files" sections.
* Annotated source snippets under frames in "Expected sanitizer output"
  (or any fenced ASan-style block).
* `file:line` → upstream source URL conversion (link rewrite, only when
  `upstream_url` + `pinned_rev` are known).

All blocks carry HTML-comment fence markers so re-running the
enrichment replaces (rather than duplicates) the previous insertion.
Each block is independent — a missing source tree or absent patch.diff
just skips that piece, the rest still lands.

Importantly: this stays **target-agnostic**. Nothing here knows about
any specific codebase. The only target-specific data it consumes
arrives via arguments (source_root, upstream_url, pinned_rev) resolved
by the caller from target.toml / session-env.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


# ── enrichment fence markers ───────────────────────────────────────
# Re-running enrichment strips the previous block and re-inserts.
# Markers are HTML comments so they vanish in rendered HTML.
_MARK_OPEN = "<!-- enrich:{name} -->"
_MARK_CLOSE = "<!-- /enrich:{name} -->"
_MARK_BLOCK_RE_TMPL = (
    r"<!-- enrich:{name} -->\n?.*?<!-- /enrich:{name} -->\n?"
)

_KNOWN_MARKS = (
    "tldr",
    "severity-badge",
    "cluster-siblings",
    "patch-diff",
    "data-flow-snippets",
    "affected-snippets",
    "asan-snippets",
    "reproduce-link",
)


# ── section / line patterns ────────────────────────────────────────

_H1_RE = re.compile(r"^#\s+(.+?)\s*$", re.MULTILINE)
_H2_RE = re.compile(r"^##\s+(.+?)\s*$", re.MULTILINE)
_FENCE_RE = re.compile(r"^\s*(?:```|~~~)")


def _fenced_line_indices(text: str) -> set:
    """Line indices (0-based) that sit inside a fenced code block, fence
    marker lines included. A `# foo` or `## bar` line inside ``` is shell /
    diff / source content, not a Markdown heading — heading scans must skip
    it (an unclosed reproducer fence otherwise swallows enrichment blocks)."""
    fenced: set = set()
    in_fence = False
    for i, line in enumerate(text.split("\n")):
        if _FENCE_RE.match(line):
            fenced.add(i)
            in_fence = not in_fence
        elif in_fence:
            fenced.add(i)
    return fenced


def _first_h1_outside_fence(text: str):
    """The first real H1 heading match, skipping `# ...` lines inside a
    fenced code block. Returns the `re.Match` or None."""
    fenced = _fenced_line_indices(text)
    for m in _H1_RE.finditer(text):
        if text.count("\n", 0, m.start()) not in fenced:
            return m
    return None
# Colon-label heading style — `Data Flow:` on its own line behaves as
# an H2 in render-md's _REPORT_LABEL_HEADING_RE. Mirror that here so
# reports that use either style get enriched. Restricted to the
# section names enrich-report actually cares about — overly liberal
# matching would eat bare-field lines like `Boundary: foo`.
_LABEL_H2_RE = re.compile(
    r"^(Summary|Classification|Root Cause|Reproduction|Data Flow|"
    r"Data Flow Trace|Affected|Affected files|Trigger Surface|"
    r"Expected sanitizer output|Sanitizer output|"
    r"Reachability Notes|Triage decision):\s*$",
    re.MULTILINE,
)
# A bare label like `Boundary:` / `Trigger source:` at column 0 — used
# to find paragraph-style metadata blocks the agent guide already
# documents.
_BARE_LABEL_RE = re.compile(r"^([A-Z][A-Za-z][A-Za-z0-9 _-]{0,40}):\s*(.*)$")

# file:line references — accept common source-file extensions used
# across the targets we audit. Kept as a prefix-friendly family rather
# than an exhaustive enum (per project docs/development.md guidance).
_SRC_EXTS = (
    r"c|cc|cpp|cxx|h|hpp|hxx|m|mm|"
    r"py|rb|js|jsx|ts|tsx|"
    r"rs|go|java|kt|scala|swift|"
    r"lua|php|cs|fs|ml|hs|"
    r"sh|bash|zsh|pl|pm"
)
_FILE_LINE_RE = re.compile(
    rf"""(?P<path>[\w./+\-]+?\.(?:{_SRC_EXTS}))   # path with allowed ext
         :(?P<line>\d+)                            # :NNN
         (?::\d+)?                                 # optional :col
    """,
    re.VERBOSE,
)

# ASan-style stack frame: `#3 0x... in func file.c:123:4`
_ASAN_FRAME_RE = re.compile(
    rf"""\#(?P<idx>\d+)\s+0x[0-9a-fA-F]+\s+in\s+
         (?P<func>[\w:~<>*&\-]+)\s+
         (?P<path>[\w./+\-]+?\.(?:{_SRC_EXTS})):(?P<line>\d+)
    """,
    re.VERBOSE,
)

_LIST_BULLET_RE = re.compile(r"^(?P<indent>\s*)(?P<bul>[-*]|\d+\.)\s+(?P<rest>.+?)\s*$")

_SEVERITY_RE = re.compile(
    r"^[-*]\s*\*\*Severity\*\*:\s*(?P<word>Critical|High|Medium|Low|TBD)\b",
    re.IGNORECASE | re.MULTILINE,
)

_CLUSTER_RE = re.compile(
    r"^(?:Cluster:|\|\s*Cluster\s*\|)\s*(?P<id>[A-Za-z0-9_\-]+)",
    re.MULTILINE,
)


@dataclass
class EnrichContext:
    """All target-derived inputs the enrichment needs. Any field may
    be empty; enrichment blocks degrade gracefully when their inputs
    are missing."""

    report_path: Path
    report_dir: Path
    source_root: Optional[Path] = None
    upstream_url: str = ""
    pinned_rev: str = ""
    # Optional: full text of the sibling sanitizer.txt / asan.txt so we
    # can mine ASan-frame snippets without re-reading from disk later.
    sanitizer_text: str = ""


# ── helpers ────────────────────────────────────────────────────────


def _strip_block(text: str, name: str) -> str:
    """Remove any previously-inserted enrichment block of this name."""
    pattern = re.compile(_MARK_BLOCK_RE_TMPL.format(name=re.escape(name)),
                         re.DOTALL)
    return pattern.sub("", text)


def _wrap_block(name: str, body: str) -> str:
    """Wrap rendered body with idempotency fence markers."""
    return (
        _MARK_OPEN.format(name=name) + "\n"
        + body.rstrip() + "\n"
        + _MARK_CLOSE.format(name=name) + "\n"
    )


def _strip_all_blocks(text: str) -> str:
    for name in _KNOWN_MARKS:
        text = _strip_block(text, name)
    return text


def _read_source_window(src: Path, line: int, context: int = 2) -> Optional[tuple[int, list[str]]]:
    """Return (start_line, lines) for a small window around `line`,
    or None if the file is unreadable."""
    try:
        text = src.read_text("utf-8", errors="replace")
    except OSError:
        return None
    lines = text.splitlines()
    if not lines or line < 1:
        return None
    line = min(line, len(lines))
    start = max(1, line - context)
    end = min(len(lines), line + context)
    return start, lines[start - 1:end]


def _format_snippet(rel_path: str, start: int, lines: list[str], target_line: int) -> str:
    """Format a fenced code block with line-number gutter and a caption."""
    out = [f"_From `{rel_path}` (lines {start}–{start + len(lines) - 1}):_"]
    out.append("")
    out.append("```text")
    width = len(str(start + len(lines) - 1))
    for i, line in enumerate(lines):
        ln = start + i
        marker = "▶" if ln == target_line else " "
        out.append(f"{ln:>{width}} {marker} {line}")
    out.append("```")
    return "\n".join(out)


def _resolve_source_file(ctx: EnrichContext, path_ref: str) -> Optional[Path]:
    """Resolve a `file.c` reference (possibly partial) against the target
    source root. Returns the first match if multiple exist (depth-first,
    shortest path wins)."""
    if not ctx.source_root or not ctx.source_root.is_dir():
        return None
    candidate = ctx.source_root / path_ref
    if candidate.is_file():
        return candidate
    # Fall back to a tail-match search — agents often write
    # `parser.c:1234` instead of `lib/xml/parser.c:1234`.
    base = os.path.basename(path_ref)
    if "/" in path_ref:
        # multi-component: match by suffix on the path
        matches = sorted(
            (p for p in ctx.source_root.rglob(base) if p.is_file()
             and str(p).endswith(path_ref)),
            key=lambda p: len(str(p)),
        )
    else:
        matches = sorted(
            (p for p in ctx.source_root.rglob(base) if p.is_file()),
            key=lambda p: len(str(p)),
        )
    return matches[0] if matches else None


def _rel_to_root(ctx: EnrichContext, path: Path) -> str:
    if not ctx.source_root:
        return str(path)
    try:
        return str(path.relative_to(ctx.source_root))
    except ValueError:
        return str(path)


def _source_url(ctx: EnrichContext, rel_path: str, line: int) -> Optional[str]:
    """Construct a viewable URL for path:line at the pinned rev when
    upstream_url + pinned_rev are both known. Best-effort across the
    common forges (GitHub, GitLab, cgit, hgweb, sourcehut)."""
    if not ctx.upstream_url or not ctx.pinned_rev:
        return None
    url = ctx.upstream_url.rstrip("/")
    rev = ctx.pinned_rev
    # Trim trailing .git
    if url.endswith(".git"):
        url = url[:-4]
    if "github.com" in url or "gitlab.com" in url or "codeberg.org" in url:
        return f"{url}/blob/{rev}/{rel_path}#L{line}"
    if "bitbucket.org" in url:
        return f"{url}/src/{rev}/{rel_path}#lines-{line}"
    if "git.sr.ht" in url:
        return f"{url}/tree/{rev}/{rel_path}#L{line}"
    if "/cgit/" in url or url.endswith("/cgit"):
        return f"{url}/tree/{rel_path}?id={rev}#n{line}"
    # Default: assume git-blob style — harmless if wrong, easy to
    # spot in review.
    return f"{url}/blob/{rev}/{rel_path}#L{line}"


# ── section utilities ──────────────────────────────────────────────


def _find_section_bounds(text: str, heading_name: str) -> Optional[tuple[int, int, int]]:
    """Locate `## <heading_name>` or `<heading_name>:` on its own line
    (case-insensitive). Returns (heading_start, body_start, body_end)
    byte offsets — body covers everything up to the next H2 / label
    heading / EOF. None if heading not present."""
    target = heading_name.lower()
    # Collect every section opener (both styles) so we can find the
    # next one regardless of which style closes our section.
    openers: list[tuple[int, int, str]] = []
    for m in _H2_RE.finditer(text):
        openers.append((m.start(), m.end(), m.group(1).strip().lower()))
    for m in _LABEL_H2_RE.finditer(text):
        openers.append((m.start(), m.end(), m.group(1).strip().lower()))
    openers.sort(key=lambda t: t[0])
    for i, (start, end, name) in enumerate(openers):
        if name == target:
            body_start = end
            if body_start < len(text) and text[body_start] == "\n":
                body_start += 1
            body_end = openers[i + 1][0] if i + 1 < len(openers) else len(text)
            return start, body_start, body_end
    return None


def _section_body(text: str, heading_name: str) -> str:
    bounds = _find_section_bounds(text, heading_name)
    if bounds is None:
        return ""
    _, body_start, body_end = bounds
    return text[body_start:body_end]


def _insert_patch_section(text: str, patch_section: str) -> str:
    """Insert the fix/patch block right before the reference-material
    tail (Reachability / Severity rationale) — i.e. AFTER the Reproduce
    section, so the reading order is Reproduce → Fix → Patch. Falls back
    to end-of-report only when no tail section exists.

    Matching is by lowercase prefix on the H2 name. Reproduce /
    Reproduction are deliberately NOT anchors: the patch (and the moved
    Fix narrative that precedes it) belong *after* the reproducer, next
    to the scoring sections. Per docs/development.md, prefix is preferred over an
    exhaustive enumeration of exact strings."""
    tail_prefixes = ("reachability", "severity rationale")
    earliest: Optional[int] = None
    for m in _H2_RE.finditer(text):
        name_lower = m.group(1).strip().lower()
        if any(name_lower.startswith(p) for p in tail_prefixes):
            if earliest is None or m.start() < earliest:
                earliest = m.start()
    if earliest is not None:
        head = text[:earliest].rstrip() + "\n\n"
        tail = text[earliest:]
        return head + patch_section.rstrip() + "\n\n" + tail
    return text.rstrip() + "\n\n" + patch_section.rstrip() + "\n"


# Prose fix-narrative sections the model writes (distinct from the
# enricher-owned `## Patch` diff and from `## Fix Direction`, which is
# the advisory-no-patch mechanism and must stay put). These get moved
# to sit directly above `## Patch` so the narrative flows into the diff.
_FIX_SECTION_NAMES = ("Fix", "Suggested fix", "Recommended fix", "Proposed fix")


def _extract_fix_section(text: str) -> tuple[str, str]:
    """Pull a prose `## Fix` (or near-variant) section out of `text`.

    Returns (text_without_fix, fix_section_markdown). The fix section is
    removed from its original position so the caller can re-place it
    immediately above `## Patch`. `## Fix Direction` is intentionally not
    matched — it is load-bearing for advisory detection and TL;DR mining.
    Idempotent: a second pass simply re-extracts and re-places it."""
    for name in _FIX_SECTION_NAMES:
        bounds = _find_section_bounds(text, name)
        if bounds is None:
            continue
        heading_start, _, body_end = bounds
        section = text[heading_start:body_end].rstrip() + "\n"
        without = text[:heading_start] + text[body_end:]
        return without, section
    return text, ""


def _strip_patch_sections(text: str) -> str:
    """Remove every `## Patch` section (heading + body). Sole-writer
    rule: this module owns the patch section, so any one already
    present — from a prior enrich pass or because the agent inlined
    one — is removed before the canonical `## Patch` is appended.
    Iterates until no patch heading remains so duplicates also go."""
    while True:
        bounds = _find_section_bounds(text, "Patch")
        if bounds is None:
            return text
        heading_start, _, body_end = bounds
        text = text[:heading_start] + text[body_end:]


def _insert_after_section(text: str, heading_name: str, block: str) -> str:
    """Append `block` at the END of the named section (just before the
    next H2 or EOF)."""
    bounds = _find_section_bounds(text, heading_name)
    if bounds is None:
        return text
    _, _, body_end = bounds
    # Trim trailing whitespace at insertion point to avoid run-on blank lines.
    head = text[:body_end].rstrip() + "\n\n"
    tail = text[body_end:]
    return head + block.rstrip() + "\n\n" + tail


def _insert_at_section_start(text: str, heading_name: str, block: str) -> str:
    """Insert `block` right after the heading line of the named section,
    before any existing body content. Used for callouts that should sit
    at the top of the section."""
    bounds = _find_section_bounds(text, heading_name)
    if bounds is None:
        return text
    _, body_start, _ = bounds
    return text[:body_start] + block.rstrip() + "\n\n" + text[body_start:]


def _insert_after_h1(text: str, block: str) -> str:
    """Insert `block` after the H1 title (or at the very top when no
    H1 is present)."""
    m = _first_h1_outside_fence(text)
    if m is None:
        return block.rstrip() + "\n\n" + text
    end = m.end()
    # Skip the newline after the title.
    if end < len(text) and text[end] == "\n":
        end += 1
    return text[:end] + "\n" + block.rstrip() + "\n\n" + text[end:]


# ── enrichment blocks ──────────────────────────────────────────────


def _build_severity_badge(text: str) -> Optional[str]:
    m = _SEVERITY_RE.search(text)
    if not m:
        return None
    word = m.group("word").title()
    if word == "Tbd":
        word = "TBD"
    # Emoji prefix is recognized everywhere (terminal preview, GitHub
    # renderer, render-md output) without needing custom CSS.
    icon_map = {
        "Critical": "🔴",
        "High":     "🟠",
        "Medium":   "🟡",
        "Low":      "🟢",
        "TBD":      "⚪",
    }
    icon = icon_map.get(word, "⚪")
    return f"{icon} **Severity: {word}**"


def _build_tldr(text: str) -> Optional[str]:
    """Three-line callout: bug / trigger / fix, mined from existing
    sections. The Fix line is sourced from `## Fix Direction` only —
    the advisory-case narrative section. The `## Patch` section is
    enricher-owned and holds the diff, not prose; mining it would
    capture the diff body (or whatever the agent inlined before being
    stripped) and would break TL;DR idempotency across re-runs."""
    summary = _section_body(text, "Summary").strip()
    fix_direction = _section_body(text, "Fix Direction").strip()
    # Trigger source / Boundary may be bare-label lines or in a Fields
    # table — try both.
    trigger = _extract_bare_field(text, "Trigger source")
    boundary = _extract_bare_field(text, "Boundary")
    caller_controls = _extract_bare_field(text, "Caller controls")

    if not summary and not fix_direction and not boundary:
        return None

    def _first_sentence(s: str, limit: int = 240) -> str:
        s = " ".join(s.split())
        if not s:
            return ""
        # Drop fenced code blocks / HTML comments before extracting.
        s = re.sub(r"```.*?```", "", s, flags=re.DOTALL)
        s = re.sub(r"<!--.*?-->", "", s, flags=re.DOTALL)
        s = s.strip()
        m = re.search(r"^(.+?[.!?])(?:\s|$)", s)
        line = m.group(1) if m else s
        return (line[: limit - 1] + "…") if len(line) > limit else line

    bug = _first_sentence(summary)
    fix = _first_sentence(fix_direction)
    trigger_line = ""
    if boundary or trigger or caller_controls:
        bits = []
        if boundary:
            bits.append(boundary)
        if caller_controls:
            bits.append(f"caller controls {caller_controls}")
        if trigger and trigger.lower() not in (boundary or "").lower():
            bits.append(f"trigger: {trigger}")
        trigger_line = " · ".join(bits)

    rows: list[str] = []
    if bug:
        rows.append(f"- **Bug** — {bug}")
    if trigger_line:
        rows.append(f"- **Trigger** — {trigger_line}")
    if fix:
        rows.append(f"- **Fix** — {fix}")
    if not rows:
        return None
    return "**📋 Reviewer TL;DR**\n\n" + "\n".join(rows)


def _extract_bare_field(text: str, label: str) -> str:
    """Pick up `Label: value` lines wherever they live in the report —
    bare-label paragraph, Fields markdown table, or both."""
    # Fields table row: `| Label | value |`
    table_re = re.compile(
        rf"^\|\s*{re.escape(label)}\s*\|\s*(?P<val>[^|]+?)\s*\|",
        re.MULTILINE | re.IGNORECASE,
    )
    m = table_re.search(text)
    if m:
        val = m.group("val").strip()
        # Table values sometimes include a trailing italic reason tail
        # like `value *(reason)*` — keep the leading value.
        val = re.sub(r"\s*\*\(.*?\)\*\s*$", "", val).strip()
        if val and val not in ("—", "-"):
            return val
    # Bare-label line: `Label: value`
    bare_re = re.compile(
        rf"^{re.escape(label)}:\s*(?P<val>.+?)\s*$",
        re.MULTILINE | re.IGNORECASE,
    )
    m = bare_re.search(text)
    if m:
        return m.group("val").strip()
    return ""


def _build_cluster_siblings(ctx: EnrichContext, text: str) -> Optional[str]:
    """List sibling crash/finding IDs in the same cluster — gives the
    reviewer the cluster shape at a glance."""
    m = _CLUSTER_RE.search(text)
    if not m:
        return None
    cluster_id = m.group("id").strip()
    # `singleton` cluster lines look like `CL-xxxxxxxx (singleton)` — skip.
    body_around = text[m.start():m.start() + 200]
    if "singleton" in body_around.lower():
        return None
    parent_dir = ctx.report_dir.parent  # …/crashes or …/findings
    if not parent_dir.is_dir():
        return None
    siblings: list[str] = []
    for sib in sorted(parent_dir.iterdir()):
        if not sib.is_dir():
            continue
        if sib.resolve() == ctx.report_dir.resolve():
            continue
        report = None
        for cand in ("report.md", "REPORT.md", "description.md"):
            if (sib / cand).is_file():
                report = sib / cand
                break
        if report is None:
            continue
        try:
            head = report.read_text("utf-8", errors="replace")[:4000]
        except OSError:
            continue
        sm = _CLUSTER_RE.search(head)
        if sm and sm.group("id").strip() == cluster_id:
            siblings.append(sib.name)
    if not siblings:
        return None
    # Plain-text link label (no backticks) — render-md's inline-code
    # placeholder leaks NULs when a code span sits inside a link's
    # anchor text, which downstream grep then sees as a binary file.
    # `../` prefix: the link lives inside the *report's own* directory
    # (findings/FIND-0104/report.md), so the sibling at
    # findings/FIND-0088/report.html is one level up, not one level
    # deeper. Dropping `../` was the original bug — every sibling href
    # resolved to .../FIND-0104/FIND-0088/report.html and 404'd.
    rows = [f"- [{s}](../{s}/report.html)" for s in siblings]
    return (
        f"**Cluster siblings** ({cluster_id}): {len(siblings)} other report(s)\n\n"
        + "\n".join(rows)
    )


def _build_reproduce_link(ctx: EnrichContext) -> Optional[str]:
    """Inject a sibling-file pointer at the top of the Reproduce section.
    Lets the reviewer click straight through to `reproduce.sh` from the
    rendered HTML report. Patch lives under its own section (linked
    there), and sanitizer.txt is referenced under Expected sanitizer
    output — duplicating them here just clutters the section.

    The line is placed *inside* the Reproduce section (via the caller),
    so re-running enrichment strips and replaces it cleanly using the
    standard `<!-- enrich:reproduce-link -->` fence."""
    repro = ctx.report_dir / "reproduce.sh"
    if not (repro.is_file() and repro.stat().st_size > 0):
        return None
    return "**Script** — [reproduce.sh](reproduce.sh)"


def _build_patch_diff_block(ctx: EnrichContext) -> Optional[str]:
    """Render the sibling `patch.diff` as the body of the `## Patch`
    section. Returns the block body (caption + fenced diff) without
    the heading itself — the caller composes the heading + enrichment
    fence markers.

    Searches the report directory first, then its `.audit/` subdir
    (where older export-repro runs demoted the patch), and finally the
    audit dir's siblings if we *are* the .audit/report.md being
    enriched. Filename is fixed — see .agents/references/session-rules.md."""
    search_dirs: list[Path] = [ctx.report_dir]
    audit_subdir = ctx.report_dir / ".audit"
    if audit_subdir.is_dir():
        search_dirs.append(audit_subdir)
    if ctx.report_dir.name == ".audit":
        search_dirs.append(ctx.report_dir.parent)
    patch_path: Optional[Path] = None
    for d in search_dirs:
        cand = d / "patch.diff"
        if cand.is_file() and cand.stat().st_size > 0:
            patch_path = cand
            break
    if patch_path is None:
        return None
    try:
        diff_text = patch_path.read_text("utf-8", errors="replace")
    except OSError:
        return None
    diff_text = diff_text.rstrip()
    if not diff_text:
        return None
    fence = "diff" if diff_text.lstrip().startswith(("diff ", "---", "@@")) else "text"
    # Linkify the filename: in HTML the reviewer gets a click-through to
    # the sibling file (open standalone, save, pipe to `git apply`); in
    # plain markdown the link text reads as the bare filename.
    return (
        f"**Captured patch** — [{patch_path.name}]({patch_path.name}) "
        f"({len(diff_text.splitlines())} lines)\n\n"
        f"```{fence}\n{diff_text}\n```"
    )


def _snippet_for_ref(ctx: EnrichContext, path_ref: str, line: int,
                     context: int = 2) -> Optional[str]:
    src = _resolve_source_file(ctx, path_ref)
    if src is None:
        return None
    window = _read_source_window(src, line, context=context)
    if window is None:
        return None
    start, lines = window
    rel = _rel_to_root(ctx, src)
    snippet = _format_snippet(rel, start, lines, line)
    url = _source_url(ctx, rel, line)
    if url:
        snippet = f"{snippet}\n\n[View at {ctx.pinned_rev[:12]} ↗]({url})"
    return snippet


def _build_section_snippets(ctx: EnrichContext, text: str,
                            heading_name: str) -> Optional[str]:
    """For each bullet under `heading_name` that names a file:line,
    emit a snippet block in source order."""
    body = _section_body(text, heading_name)
    if not body:
        return None
    out: list[str] = []
    seen: set[tuple[str, int]] = set()
    for raw_line in body.splitlines():
        line_stripped = raw_line.strip()
        if not line_stripped or line_stripped.startswith(("<!--", "```", "|", "_")):
            continue
        # Only act on bullets / sentences mentioning file:line — skip
        # the section's own narrative paragraphs unless they carry refs.
        for ref in _FILE_LINE_RE.finditer(line_stripped):
            path_ref = ref.group("path")
            lineno = int(ref.group("line"))
            key = (path_ref, lineno)
            if key in seen:
                continue
            seen.add(key)
            snippet = _snippet_for_ref(ctx, path_ref, lineno)
            if snippet is None:
                continue
            anchor = line_stripped if len(line_stripped) <= 140 else line_stripped[:137] + "…"
            # Strip a leading list bullet (`- `, `* `, `1. `) so the
            # anchor reads as prose, not a fresh list item.
            anchor = re.sub(r"^(?:[-*]|\d+\.)\s+", "", anchor)
            out.append(f"**↳ Referenced in:** {anchor}\n\n{snippet}")
    if not out:
        return None
    header = f"**Source snippets** referenced in _{heading_name}_:\n\n"
    return header + "\n\n---\n\n".join(out)


def _build_asan_snippets(ctx: EnrichContext, text: str) -> Optional[str]:
    """Pull frames from the Expected sanitizer output fenced block (or
    the sibling sanitizer.txt) and emit a snippet per unique frame in
    stack order."""
    sources: list[str] = []
    # Prefer the in-report block — it's already the curated subset.
    bounds = _find_section_bounds(text, "Expected sanitizer output")
    if bounds:
        _, body_start, body_end = bounds
        body = text[body_start:body_end]
        for fence_m in re.finditer(r"```[a-z]*\n(.*?)```", body, re.DOTALL):
            sources.append(fence_m.group(1))
    if not sources and ctx.sanitizer_text:
        sources.append(ctx.sanitizer_text)
    if not sources:
        return None
    seen: set[tuple[str, int]] = set()
    out: list[str] = []
    for src_text in sources:
        for fm in _ASAN_FRAME_RE.finditer(src_text):
            path_ref = fm.group("path")
            lineno = int(fm.group("line"))
            func = fm.group("func")
            idx = fm.group("idx")
            key = (path_ref, lineno)
            if key in seen:
                continue
            seen.add(key)
            snippet = _snippet_for_ref(ctx, path_ref, lineno)
            if snippet is None:
                continue
            out.append(f"**#{idx} `{func}`** — {path_ref}:{lineno}\n\n{snippet}")
            if len(out) >= 8:  # bound the depth — top-of-stack matters most
                break
        if len(out) >= 8:
            break
    if not out:
        return None
    header = "**Annotated stack frames** (top-of-stack source):\n\n"
    return header + "\n\n---\n\n".join(out)


# ── orchestration ──────────────────────────────────────────────────


def enrich_text(text: str, ctx: EnrichContext) -> str:
    """Apply every enrichment block. Pure function — no I/O on `text`.
    Caller decides whether to write it back to disk."""
    text = _strip_all_blocks(text)
    # Normalize trailing whitespace from previous run to keep diffs
    # minimal when nothing changed.
    text = re.sub(r"\n{3,}", "\n\n", text)

    # 1. Severity badge — right under the H1.
    badge = _build_severity_badge(text)
    if badge:
        text = _insert_after_h1(text, _wrap_block("severity-badge", badge))

    # 2. TL;DR card — right under the badge (or H1).
    tldr = _build_tldr(text)
    if tldr:
        text = _insert_after_h1(text, _wrap_block("tldr", tldr))

    # 3. Cluster siblings — append near top so reviewers see scope.
    siblings = _build_cluster_siblings(ctx, text)
    if siblings:
        text = _insert_after_h1(text, _wrap_block("cluster-siblings", siblings))

    # 4. Source snippets under Data Flow / Affected (per section).
    for heading in ("Data Flow Trace", "Data Flow", "Affected", "Affected files"):
        snippets = _build_section_snippets(ctx, text, heading)
        if snippets:
            mark = "data-flow-snippets" if "flow" in heading.lower() else "affected-snippets"
            text = _insert_after_section(text, heading, _wrap_block(mark, snippets))

    # 5. Annotated ASan stack frames — append at the end of the sanitizer
    # section so the raw output stays untouched directly above.
    asan = _build_asan_snippets(ctx, text)
    if asan:
        # Try the most-likely heading names in priority order.
        for heading in ("Expected sanitizer output", "Sanitizer output",
                        "Reproduction"):
            if _find_section_bounds(text, heading):
                text = _insert_after_section(text, heading,
                                             _wrap_block("asan-snippets", asan))
                break

    # 5b. Bundle-artifacts callout at the top of Reproduce — gives the
    # reviewer one-click access to reproduce.sh / patch.diff /
    # sanitizer.txt / input.txt without leaving the report. Tries
    # `Reproduce` first (current template), `Reproduction` second
    # (older agent-authored reports).
    repro_link = _build_reproduce_link(ctx)
    if repro_link:
        for heading in ("Reproduce", "Reproduction"):
            if _find_section_bounds(text, heading):
                text = _insert_at_section_start(
                    text, heading, _wrap_block("reproduce-link", repro_link)
                )
                break

    # 6. Fix narrative + Patch — single-writer rule for the diff. The
    # sibling `patch.diff` file is the canonical source; this enricher is
    # the sole writer of the `## Patch` section. Any existing `## Patch`
    # is stripped first. The reading order is Reproduce → Fix → Patch:
    # the model's prose `## Fix` section (when present) is lifted out of
    # its original position and re-placed directly above the `## Patch`
    # diff, and the combined block is inserted after the Reproduce
    # section (before Reachability / Severity rationale). End-of-report
    # placement is the fallback when no tail section exists.
    text = _strip_patch_sections(text)
    diff_block = _build_patch_diff_block(ctx)
    if diff_block:
        # Reorder only when there's a patch to anchor the Fix above. The
        # model's prose `## Fix` section (if any) is lifted to sit directly
        # above `## Patch`; a report with no patch keeps its Fix section
        # exactly where the author placed it (no surprise relocation).
        text, fix_section = _extract_fix_section(text)
        tail_parts: list[str] = []
        if fix_section:
            tail_parts.append(fix_section.rstrip())
        tail_parts.append("## Patch\n\n" + _wrap_block("patch-diff", diff_block).rstrip())
        text = _insert_patch_section(text, "\n\n".join(tail_parts))

    # The strip-and-splice in step 6 can leave a `\n\n\n` seam where
    # two `\n\n`-padded chunks meet. Collapse runs so the file stays
    # byte-stable across re-runs (idempotency requirement).
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


def enrich_file(report_path: Path, ctx: Optional[EnrichContext] = None,
                **ctx_overrides) -> bool:
    """Read, enrich, write — returns True iff the file changed."""
    if not report_path.is_file():
        return False
    if ctx is None:
        ctx = EnrichContext(
            report_path=report_path,
            report_dir=report_path.parent,
            **ctx_overrides,
        )
    original = report_path.read_text("utf-8", errors="replace")
    updated = enrich_text(original, ctx)
    if updated == original:
        return False
    report_path.write_text(updated, encoding="utf-8")
    return True
