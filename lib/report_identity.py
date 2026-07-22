"""Content identity for report verdict caches and read-only consumers."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path


FIND_QUALITY_DECISION_VERSION = "v13-python"
REPORT_NAMES = ("REPORT.md", "report.md", "description.md", "analysis.md", "README.md")

# Single source of truth for the harness-owned report vocabulary. Writers
# (triage's contract-concern setter, the report enricher) and this stripper
# share these so a renamed heading or boundary cannot silently desync them and
# start spending fresh reviews on mechanical edits.
CONTRACT_CONCERN_HEADING = "## Contract concern"
# A harness-inserted section runs until the next Markdown H2, a bare "Summary:"
# field, or end-of-report — matching the contract-concern setter's own regex.
SECTION_BOUNDARY_PREFIXES = ("## ", "Summary:")
_GENERATED_SECTIONS = {
    CONTRACT_CONCERN_HEADING,
    "## Patch",
    "## Severity rationale",
}
_CODE_FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")
_TABLE_ROW_RE = re.compile(r"^\s*\|.*\|\s*$")
_TABLE_SEP_RE = re.compile(r"^\s*\|?\s*:?-{3,}:?\s*(\|\s*:?-{3,}:?\s*)+\|?\s*$")
_ENRICH_OPEN_RE = re.compile(r"<!-- enrich:[A-Za-z0-9_-]+ -->")
_ENRICH_CLOSE_RE = re.compile(r"<!-- /enrich:[A-Za-z0-9_-]+ -->")
_GENERATED_LINE_RE = re.compile(
    r"^(?:Cluster|Dedup frames|Dedup key|Severity):"
    r"|^\|\s*(?:Cluster|Dedup frames|Dedup key|Severity)\s*\|"
    r"|^[-*]\s*\*\*Severity\*\*:",
)


def _canonicalize_tables(lines: list[str]) -> list[str]:
    """Remove renderer-only padding from recognized Markdown tables."""
    canonical: list[str] = []
    index = 0
    code_fence: str | None = None
    while index < len(lines):
        line = lines[index]
        fence = _CODE_FENCE_RE.match(line)
        if code_fence is not None:
            canonical.append(line)
            if fence and fence.group(1)[0] == code_fence:
                code_fence = None
            index += 1
            continue
        if fence:
            code_fence = fence.group(1)[0]
            canonical.append(line)
            index += 1
            continue
        following = lines[index + 1] if index + 1 < len(lines) else ""
        if _TABLE_ROW_RE.match(line) and _TABLE_SEP_RE.match(following):
            row = 0
            while index < len(lines) and _TABLE_ROW_RE.match(lines[index]):
                cells = lines[index].strip()[1:-1].split("|")
                cells = [cell.strip() for cell in cells]
                if row == 1:
                    cells = [
                        (":" if cell.startswith(":") else "")
                        + "---"
                        + (":" if cell.endswith(":") else "")
                        for cell in cells
                    ]
                canonical.append("|" + "|".join(cells) + "|")
                index += 1
                row += 1
            continue
        canonical.append(line)
        index += 1
    return canonical


def _semantic_report_text(report_text: str, *, canonicalize_tables: bool) -> str:
    """Remove only harness-owned annotations from report cache identity.

    Agent-authored prose and code fences remain byte-sensitive. Generated
    sections are stripped only outside Markdown fences, so an example that
    happens to contain ``## Patch`` cannot hide a substantive later edit.
    """
    stripped: list[str] = []
    enrich_fence = False
    code_fence: str | None = None
    skipped_section = False
    for line in report_text.splitlines():
        normalized = line.rstrip()
        fence = _CODE_FENCE_RE.match(line)
        if code_fence is not None:
            if not skipped_section and normalized:
                stripped.append(line)
            if fence and fence.group(1)[0] == code_fence:
                code_fence = None
            continue
        if fence:
            code_fence = fence.group(1)[0]
            if not skipped_section and normalized:
                stripped.append(line)
            continue
        if _ENRICH_OPEN_RE.fullmatch(normalized):
            enrich_fence = True
            continue
        if _ENRICH_CLOSE_RE.fullmatch(normalized):
            enrich_fence = False
            continue
        if enrich_fence:
            continue
        if skipped_section and normalized.startswith(SECTION_BOUNDARY_PREFIXES):
            skipped_section = False
        if skipped_section:
            continue
        if normalized in _GENERATED_SECTIONS:
            skipped_section = True
            continue
        if _GENERATED_LINE_RE.match(line):
            continue
        if normalized:
            stripped.append(line)
    if canonicalize_tables:
        stripped = _canonicalize_tables(stripped)
    return "\n".join(stripped) + ("\n" if stripped else "")


def semantic_report_text(report_text: str) -> str:
    return _semantic_report_text(report_text, canonicalize_tables=True)


def semantic_text_sha1(report_text: str) -> str:
    return hashlib.sha1(semantic_report_text(report_text).encode()).hexdigest()


def legacy_semantic_text_sha1(report_text: str) -> str:
    """Identity written before Markdown table padding became cache-neutral."""
    text = _semantic_report_text(report_text, canonicalize_tables=False)
    return hashlib.sha1(text.encode()).hexdigest()


def content_sha1_candidates(path: Path) -> frozenset[str]:
    """Current identity plus the one pre-table-canonicalization identity."""
    try:
        report_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset()
    return frozenset({
        semantic_text_sha1(report_text),
        legacy_semantic_text_sha1(report_text),
    })


def content_sha1(path: Path) -> str | None:
    """Hash the agent-authored substance in a report file."""
    try:
        return semantic_text_sha1(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None


def find_report(directory: Path) -> Path | None:
    return next(
        (directory / name for name in REPORT_NAMES if (directory / name).is_file()),
        None,
    )


def quality_cache_matches_report(directory: Path, payload: dict) -> bool:
    """Validate new content-addressed quality caches; tolerate legacy v13."""
    cached_sha1 = payload.get("report_sha1")
    if not isinstance(cached_sha1, str) or not cached_sha1:
        return True
    report = find_report(directory)
    return report is not None and cached_sha1 in content_sha1_candidates(report)
