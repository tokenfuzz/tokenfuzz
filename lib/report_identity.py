"""Content identity for report verdict caches and read-only consumers."""

from __future__ import annotations

import functools
import hashlib
import os
import re
from collections.abc import Iterable
from pathlib import Path


FIND_QUALITY_DECISION_VERSION = "v18-effectful-primitives"
REPORT_NAMES = ("REPORT.md", "report.md", "description.md", "analysis.md", "README.md")
PLACEHOLDER_FIELD_VALUES = frozenset(
    {"", "-", "—", "?", "tbd", "unknown / not assessed"}
)
#: Stamped into a bundle's Cluster row before bin/cluster-crashes computes a
#: real id. It is a stamp, not a value: a reader that takes it for one gets a
#: cluster key every unclustered artifact shares, which merges unrelated bugs
#: into one duplicate group and collapses distinct artifact roots into a
#: single progress bucket.
CLUSTER_STAMP_PLACEHOLDER = "(set by bin/cluster-crashes)"


def field_value_is_placeholder(field: str, value: str) -> bool:
    """Whether a structured report value still needs a substantive value."""
    normalized = value.strip().casefold()
    label = field.strip().casefold()
    return (
        normalized in PLACEHOLDER_FIELD_VALUES
        or (normalized == "unspecified" and label != "caller contract")
        or (
            label == "cluster"
            and normalized == CLUSTER_STAMP_PLACEHOLDER.casefold()
        )
    )


# Structured report fields, written as bare `Label: value` lines below the
# `## Fields` table so regex consumers keep working, and promoted into that
# table for readers. Canonical for the writer (lib/triage.py), the promoter
# (bin/severity), the extractor (bin/export-repro) and the renderer
# (bin/render-md): each held its own copy, so a label added to the writers and
# missed by the renderer was neither recognized as a duplicate of the grid nor
# folded into it, and rendered as stray key/value text beside it.
FIELD_LABELS = {
    "surface": "Surface",
    "primitive": "Primitive",
    "class": "Class",
    "caller_contract": "Caller contract",
    "caller_controls": "Caller controls",
    "trigger_source": "Trigger source",
    "parameter_control": "Parameter control",
    "trusted_caller_actions": "Trusted caller actions",
    "boundary": "Boundary",
    "advisory": "Advisory",
    "reproducer_carrier": "Reproducer carrier",
    "disclosed_content": "Disclosed content",
    "availability_loss": "Availability loss",
    "strategy": "Strategy",
}
# Cluster, dedup and verification identity stamped into the same block. Table
# material like the fields above, but harness bookkeeping rather than authored
# evidence, so a renderer may drop them rather than surface them.
IDENTITY_FIELD_LABELS = (
    "Cluster", "Dedup key", "Dedup frames", "ClusterFuzz key frames",
    "Reproduction rate",
)
ALL_FIELD_LABELS = tuple(FIELD_LABELS.values()) + IDENTITY_FIELD_LABELS

# The one signature that marks a report's Fields table: a `| Field | Value |`
# header over a GFM separator. Shared by the writer (`bin/severity`, which
# appends scored rows) and the renderer (`bin/render-md`, which draws the
# grid) so the two cannot disagree about which table they mean — holding two
# lookalike regexes is how they came to disagree over `| : | : |`, a
# separator one accepted and the other rejected, leaving severity writing
# rows into a table that then rendered as no grid at all.
_FIELDS_HEADER_RE = re.compile(r"^\s*\|\s*field\s*\|\s*value\s*\|\s*$", re.IGNORECASE)
# GFM requires at least one dash per column, with optional alignment colons.
# The same predicate decides which tables identity canonicalizes below: a
# separator `bin/render-md` pads but this module does not recognize is a table
# whose padding moves report identity.
FIELDS_SEPARATOR_RE = re.compile(r"^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)+\|?\s*$")


def is_fields_table_header(line: str, following: str) -> bool:
    """True when `line`/`following` open the report's Fields table."""
    return bool(_FIELDS_HEADER_RE.match(line) and FIELDS_SEPARATOR_RE.match(following))

# Single source of truth for the harness-owned report vocabulary. Writers
# (triage's contract-concern setter, the report enricher) and this stripper
# share these so a renamed heading or boundary cannot silently desync them and
# start spending fresh reviews on mechanical edits.
CONTRACT_CONCERN_HEADING = "## Contract concern"
SEVERITY_RATIONALE_HEADING = "## Severity rationale"
# A harness-inserted section runs until the next Markdown H2, a bare "Summary:"
# field, or end-of-report — matching the contract-concern setter's own regex.
SECTION_BOUNDARY_PREFIXES = ("## ", "Summary:")
_GENERATED_SECTIONS = {
    CONTRACT_CONCERN_HEADING,
    "## Patch",
    SEVERITY_RATIONALE_HEADING,
}
_CODE_FENCE_RE = re.compile(r"^\s*(`{3,}|~{3,})")
_TABLE_ROW_RE = re.compile(r"^\s*\|.*\|\s*$")
_ENRICH_OPEN_RE = re.compile(r"<!-- enrich:[A-Za-z0-9_-]+ -->")
_ENRICH_CLOSE_RE = re.compile(r"<!-- /enrich:[A-Za-z0-9_-]+ -->")
_GENERATED_LINE_RE = re.compile(
    r"^(?:Cluster|Dedup frames|Dedup key|Severity):"
    r"|^\|\s*(?:Cluster|Dedup frames|Dedup key|Severity)\s*\|"
    r"|^[-*]\s*\*\*Severity\*\*:",
)


def code_fence_mask(lines: list[str]) -> list[bool]:
    """Per-line flag: True while inside a fenced code block, fences included.

    Identity keeps fenced content byte-sensitive, so a `Cluster:` stamp that
    lands inside a fence stops being strippable bookkeeping and becomes part
    of the report's content. Writers that anchor on a heading share this so
    they cannot mistake a repro block's `# comment` for the report title.
    """
    mask: list[bool] = []
    fence: str | None = None
    for line in lines:
        match = _CODE_FENCE_RE.match(line)
        mask.append(fence is not None or bool(match))
        if match:
            if fence is None:
                fence = match.group(1)[0]
            elif match.group(1)[0] == fence:
                fence = None
    return mask


def _table_columns(rows: list[list[str]]) -> int:
    """Columns a table carries content in, ignoring padding-only cells.

    `bin/render-md` pads a table to its widest row: shorter rows gain empty
    cells and the separator gains a bar. Width is therefore presentation, not
    content — and one row whose value holds a raw `|` (`FLAG_A | FLAG_B`, which
    Markdown reads as a cell break) widens the whole table, so counting cells
    would let that row rewrite every sibling row's identity the first time a
    padder ran.
    """
    columns = 0
    for position, cells in enumerate(rows):
        if position == 1:
            continue  # separator: bars are shape, never content
        for column, cell in enumerate(cells, start=1):
            if cell:
                columns = max(columns, column)
    return columns or max((len(cells) for cells in rows), default=0)


def _canonicalize_tables(lines: list[str], trim_padding: bool = True) -> list[str]:
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
        if _TABLE_ROW_RE.match(line) and FIELDS_SEPARATOR_RE.match(following):
            rows: list[list[str]] = []
            while index < len(lines) and _TABLE_ROW_RE.match(lines[index]):
                cells = lines[index].strip()[1:-1].split("|")
                rows.append([cell.strip() for cell in cells])
                index += 1
            columns = _table_columns(rows) if trim_padding else None
            for position, cells in enumerate(rows):
                if position == 1:
                    cells = [
                        (":" if cell.startswith(":") else "")
                        + "---"
                        + (":" if cell.endswith(":") else "")
                        for cell in cells
                    ]
                    filler = "---"
                else:
                    filler = ""
                if columns is not None:
                    cells = (cells + [filler] * columns)[:columns]
                canonical.append("|" + "|".join(cells) + "|")
            continue
        canonical.append(line)
        index += 1
    return canonical


# The find-gate re-derives a report's identity 4-6× in one process (quality
# votes, trigger votes, dedup, accept). This transform is pure in
# (report_text, canonicalize_tables), so a small locality cache returns
# byte-identical output while collapsing those repeated full-report scans to
# one. The gate validates findings in a 4-worker pool, so ~24 derivations are
# in flight at once; 48 entries covers that with headroom without turning a
# locality cache into a batch-wide retainer. Oversized reports skip the cache
# entirely, bounding what a batch of large inputs can hold to a few MiB.
_MAX_CACHED_REPORT_CHARS = 256 * 1024


def _semantic_report_text(
    report_text: str, *, canonicalize_tables: bool,
    strip_enrich_fenced_code: bool = True,
    trim_table_padding: bool = True,
) -> str:
    if len(report_text) > _MAX_CACHED_REPORT_CHARS:
        return _semantic_report_text_impl(
            report_text, canonicalize_tables, strip_enrich_fenced_code,
            trim_table_padding,
        )
    return _semantic_report_text_cached(
        report_text, canonicalize_tables, strip_enrich_fenced_code,
        trim_table_padding,
    )


@functools.lru_cache(maxsize=48)
def _semantic_report_text_cached(
    report_text: str, canonicalize_tables: bool,
    strip_enrich_fenced_code: bool, trim_table_padding: bool,
) -> str:
    return _semantic_report_text_impl(
        report_text, canonicalize_tables, strip_enrich_fenced_code,
        trim_table_padding,
    )


def _semantic_report_text_impl(
    report_text: str, canonicalize_tables: bool,
    strip_enrich_fenced_code: bool, trim_table_padding: bool = True,
) -> str:
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
            if (
                not skipped_section
                and (not enrich_fence or not strip_enrich_fenced_code)
                and normalized
            ):
                stripped.append(line)
            if fence and fence.group(1)[0] == code_fence:
                code_fence = None
            continue
        if fence:
            code_fence = fence.group(1)[0]
            if (
                not skipped_section
                and (not enrich_fence or not strip_enrich_fenced_code)
                and normalized
            ):
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
        stripped = _canonicalize_tables(stripped, trim_padding=trim_table_padding)
    return "\n".join(stripped) + ("\n" if stripped else "")


def semantic_report_text(report_text: str) -> str:
    return _semantic_report_text(report_text, canonicalize_tables=True)


def semantic_text_sha1(report_text: str) -> str:
    return hashlib.sha1(semantic_report_text(report_text).encode()).hexdigest()


def legacy_semantic_text_sha1(report_text: str) -> str:
    """Identity written before Markdown table padding became cache-neutral."""
    text = _semantic_report_text(report_text, canonicalize_tables=False)
    return hashlib.sha1(text.encode()).hexdigest()


def legacy_padded_table_semantic_text_sha1(report_text: str) -> str:
    """Identity written before padded table columns became cache-neutral."""
    text = _semantic_report_text(
        report_text, canonicalize_tables=True, trim_table_padding=False,
    )
    return hashlib.sha1(text.encode()).hexdigest()


def legacy_enrich_semantic_text_sha1(
    report_text: str, *, canonicalize_tables: bool = True,
) -> str:
    """Identity from before fenced enrich snippets were fully stripped.

    Padding trimming came after that change, so the identities this reproduces
    were all written with tables canonicalized at their padded width.
    """
    text = _semantic_report_text(
        report_text,
        canonicalize_tables=canonicalize_tables,
        strip_enrich_fenced_code=False,
        trim_table_padding=False,
    )
    return hashlib.sha1(text.encode()).hexdigest()


def content_sha1_candidates(path: Path) -> frozenset[str]:
    """Current identity plus bounded identities written by prior versions."""
    try:
        report_text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return frozenset()
    return frozenset({
        semantic_text_sha1(report_text),
        legacy_semantic_text_sha1(report_text),
        legacy_padded_table_semantic_text_sha1(report_text),
        legacy_enrich_semantic_text_sha1(report_text),
        legacy_enrich_semantic_text_sha1(
            report_text, canonicalize_tables=False,
        ),
    })


def content_sha1(path: Path) -> str | None:
    """Hash the agent-authored substance in a report file."""
    try:
        return semantic_text_sha1(path.read_text(encoding="utf-8", errors="replace"))
    except OSError:
        return None


def exact_child_files(parent: Path, names: Iterable[str]) -> tuple[Path, ...]:
    """Return exact-case file children in the requested priority order.

    A case-insensitive filesystem — APFS, or a Docker Desktop bind mount over
    one — answers `(directory / "REPORT.md").is_file()` for an on-disk
    `report.md`, so probing by name hands back a path spelled a way the
    directory does not contain. That spelling escapes: triage feeds it to
    `render-md --html-sibling`, which derives the sibling's name from it, and
    the consumers that link the pair look the name up exactly.

    Reading the directory costs more than probing five names did; scandir over
    iterdir keeps that at a few tens of microseconds per artifact for triage's
    per-iteration passes, which call this for every crash and finding.
    """
    try:
        with os.scandir(parent) as entries:
            children = {entry.name: entry for entry in entries}
    except OSError:
        return ()
    return tuple(
        Path(entry.path)
        for name in names
        if (entry := children.get(name)) is not None and entry.is_file()
    )


def exact_child_file(parent: Path, names: Iterable[str]) -> Path | None:
    """Return the first exact-case file child in the requested order."""
    return next(iter(exact_child_files(parent, names)), None)


def find_report(directory: Path) -> Path | None:
    """Return the artifact's report, spelled the way the directory spells it."""
    return exact_child_file(directory, REPORT_NAMES)


def quality_cache_matches_report(directory: Path, payload: dict) -> bool:
    """Validate new content-addressed quality caches; tolerate legacy v13."""
    cached_sha1 = payload.get("report_sha1")
    if not isinstance(cached_sha1, str) or not cached_sha1:
        return True
    report = find_report(directory)
    return report is not None and cached_sha1 in content_sha1_candidates(report)
