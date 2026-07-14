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
_ENRICH_OPEN_RE = re.compile(r"<!-- enrich:[A-Za-z0-9_-]+ -->")
_ENRICH_CLOSE_RE = re.compile(r"<!-- /enrich:[A-Za-z0-9_-]+ -->")
_GENERATED_LINE_RE = re.compile(
    r"^(?:Cluster|Dedup frames|Dedup key|Severity):"
    r"|^\|\s*(?:Cluster|Dedup frames|Dedup key|Severity)\s*\|"
    r"|^[-*]\s*\*\*Severity\*\*:",
)


def semantic_report_text(report_text: str) -> str:
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
    return "\n".join(stripped) + ("\n" if stripped else "")


def semantic_text_sha1(report_text: str) -> str:
    return hashlib.sha1(semantic_report_text(report_text).encode()).hexdigest()


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
    return report is not None and content_sha1(report) == cached_sha1
