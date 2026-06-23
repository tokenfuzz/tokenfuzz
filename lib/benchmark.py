#!/usr/bin/env python3
"""benchmark.py — metric harvest + ledger rendering for bin/benchmark.

bin/benchmark runs the audit harness against a fixed model-direct baseline so an
operator can answer one question with evidence rather than opinion:

    does the harness find more real, reproducible bugs than a bare
    "find all vulnerabilities" CTF prompt, for the same budget?

This module is the *deterministic* half of that tool — everything that
does not involve launching an LLM. It is kept separate from bin/benchmark
precisely so it can be unit-tested without a backend:

  * harvest(results_dir)   — count confirmed crashes / findings / recon
                             candidates in a standard results/ tree, by
                             grepping for sanitizer signatures (the crash
                             oracle is AddressSanitizer, not an LLM vote).
  * aggregate(bench_dir)   — fold every cell's cell.json + metrics.json
                             into one per-condition report.
  * render_section(report) — one append-only markdown section.

Subcommands (see argparse at the bottom):
  harvest <results-dir> [--out metrics.json]
  aggregate <bench-runid-dir> [--out report.json]
  ledger <bench-runid-dir> --ledger <benchmark-results.md>
  reset --ledger <benchmark-results.md> [--hard]
  crosstab <bench-root> [--out benchmark-crosstab.md]
  relocate-experiments <bench-runid-dir>
  split-pool <bench-runid-dir>
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import shutil
import statistics
import sys
import urllib.parse
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timezone
from pathlib import Path

try:  # ClusterFuzz-normalized stack frames — reused, never reinvented.
    import stack_frames as _sf
except Exception:  # pragma: no cover - stack_frames should always import
    _sf = None

try:  # Shared sanitizer-artifact discovery — same policy as export/triage.
    import crash_artifacts as _ca
except Exception:  # pragma: no cover - crash_artifacts should always import
    _ca = None

SCRIPT_ROOT = Path(__file__).resolve().parent.parent

# ── sanitizer crash oracle ───────────────────────────────────────────────
#
# A "confirmed crash" is a directory holding at least one file whose text
# carries a sanitizer diagnostic. The signature set below is a deliberate
# mirror of the triager's gate in lib/triage.sh (search: "ERROR:
# (AddressSanitizer"). Inclusion criterion: a line a sanitizer runtime
# prints on a real memory-safety / UB / race fault — never a line an
# agent could fabricate in prose. Keep it in sync with triage.sh; this
# is the whole reason the benchmark number is trustworthy.
SANITIZER_SIGNATURE_RE = re.compile(
    r"ERROR: (AddressSanitizer|UndefinedBehaviorSanitizer)"
    r"|SUMMARY: (AddressSanitizer|UndefinedBehaviorSanitizer)"
    r"|WARNING: (ThreadSanitizer|MemorySanitizer):"
    r"|SUMMARY: (ThreadSanitizer|MemorySanitizer):"
    r"|^WARNING: DATA RACE$"
    r"|UndefinedBehaviorSanitizer:"
    r"|: runtime error:",
    re.MULTILINE,
)

# Files large enough to be a build artifact rather than a sanitizer log
# are skipped during the grep so harvest stays fast on big result trees.
_MAX_SCAN_BYTES = 2 * 1024 * 1024

_CLUSTER_COUNT_RE = re.compile(r"(\d+)\s+unique\s+cluster")
_MODEL_REFUSAL_RE = re.compile(r"\bMODEL_REFUSAL\b")


_RENDER_BASE_DIR: Path | None = None

_SCRUB_TEXT_SUFFIXES = {
    ".md",
    ".txt",
    ".json",
    ".log",
}
_SCRUB_TEXT_NAMES = {
    "REPORT",
    "report",
    "description",
    "analysis",
    "README",
}
_MAX_SCRUB_BYTES = 2 * 1024 * 1024


@contextlib.contextmanager
def _render_relative_to(base: Path | None):
    """Render artifact links relative to *base* inside the with-block.

    Markdown links written by `_md_link` consult this context: when a
    base is set, paths *under* it become bare relative URIs (no
    `file://`, no `/Users/...` prefix), so the rendered .md/.html is
    portable and does not leak the author's home directory. Paths that
    sit outside the base fall through to the absolute `file://` URI.
    Passing None (the default) disables relativization.
    """
    global _RENDER_BASE_DIR
    prev = _RENDER_BASE_DIR
    _RENDER_BASE_DIR = Path(base).resolve() if base else None
    try:
        yield
    finally:
        _RENDER_BASE_DIR = prev


def _path_uri(path: Path) -> str:
    """Return a browser-clickable URI for a local artifact path.

    When `_render_relative_to(base)` is active and *path* lives under
    that base, returns a percent-encoded relative path (no `file://`
    scheme). Browsers and markdown viewers resolve such hrefs against
    the rendered document's own URL, which keeps the link working
    after the run directory is moved or shared.
    """
    try:
        resolved = path.resolve()
    except (OSError, ValueError):
        resolved = path
    if _RENDER_BASE_DIR is not None:
        try:
            rel = resolved.relative_to(_RENDER_BASE_DIR)
        except ValueError:
            rel = None
        if rel is not None:
            return urllib.parse.quote(str(rel), safe="/:#?&=%")
    try:
        return resolved.as_uri()
    except ValueError:
        return urllib.parse.quote(str(resolved), safe="/:#?&=%")


def _md_link(label: object, path: Path | str | None) -> str:
    """Markdown link helper for local artifact paths.

    Returns the bare label (no link) when *path* is falsy or when it
    points to something that does not exist on disk. Suppressing a dead
    link is what keeps a "0 crashes" cell honest — it stays a plain `0`
    instead of linking to a sibling condition's evidence tree.
    """
    if not path:
        return str(label)
    p = Path(path)
    if not p.exists():
        return str(label)
    return f"[{label}]({_path_uri(p)})"


def _local_path_replacements() -> list[tuple[str, str]]:
    """Prefixes to remove from pooled benchmark review artifacts.

    Model-direct agents often write absolute paths from the local checkout
    (for example ``/Users/<name>/work/targets/...``) into reports. Pool
    artifacts are reviewer-facing and portable, so strip the workspace prefix
    to repo-relative paths and collapse any remaining home prefix to ``~/``.
    """
    replacements: list[tuple[str, str]] = []

    def add_prefix(path: Path, replacement: str) -> None:
        raw = str(path)
        if raw:
            replacements.append((raw + "/", replacement))
        try:
            replacements.append((path.as_uri() + "/", replacement))
        except ValueError:
            pass

    home = Path.home()
    workspace_roots = [
        SCRIPT_ROOT,
        home / "work",
    ]
    for root in workspace_roots:
        add_prefix(root, "")
        try:
            add_prefix(root.resolve(), "")
        except OSError:
            pass
    add_prefix(home, "~/")
    try:
        add_prefix(home.resolve(), "~/")
    except OSError:
        pass

    deduped = dict(replacements)
    return sorted(deduped.items(), key=lambda item: len(item[0]), reverse=True)


def _scrub_local_paths(text: str) -> str:
    for needle, replacement in _local_path_replacements():
        text = text.replace(needle, replacement)
    return text


def _should_scrub_pooled_file(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.name in _SCRUB_TEXT_NAMES:
        return True
    return path.suffix.lower() in _SCRUB_TEXT_SUFFIXES


def _scrub_pooled_tree(root: Path) -> None:
    """Best-effort scrub of local absolute paths from copied pool artifacts."""
    if not root.is_dir():
        return
    for path in root.rglob("*"):
        if not _should_scrub_pooled_file(path):
            continue
        try:
            if path.stat().st_size > _MAX_SCRUB_BYTES:
                continue
            original = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        scrubbed = _scrub_local_paths(original)
        if scrubbed == original:
            continue
        try:
            path.write_text(scrubbed, encoding="utf-8")
        except OSError:
            pass


# Recon-hash mentions in pooled FIND reports the linker turns into
# markdown links. Two narrow shapes (kept as a list so adding more
# patterns later — recon REPORT cross-refs, audit-log cites — is a
# one-line change). Each pattern's group 1 is the "RECON-<hash>" token
# to be wrapped; the surrounding context outside the group is preserved
# verbatim. Negative lookaheads/lookbehinds keep the linker idempotent
# by skipping hashes already inside a `[…](…)` markdown link.
_RECON_LINK_PATTERNS = (
    # `- **Recon ID:** RECON-<hash>` (legacy bolded form).
    re.compile(
        r"(?<!\[)(?<!\]\()"
        r"(?<=\*\*Recon ID:\*\*\s)"
        r"(RECON-[0-9a-f]+)"
        r"(?!\])",
    ),
    # Bare-label form `Recon ID: RECON-<hash>` — recon_to_cards now
    # emits this shape so render-md's bare-label suppression hides
    # the audit-only line from HTML while the markdown copy keeps
    # the linkified anchor.
    re.compile(
        r"(?<!\[)(?<!\]\()"
        r"(?<=(?<![\w*])Recon ID:\s)"
        r"(RECON-[0-9a-f]+)"
        r"(?!\])",
    ),
    # `Validator details: duplicate of RECON-<hash>` — the dedup parent
    # that survives even when the primary Recon ID was pruned, so the
    # linker still gives the reader a reachable recon vote.
    re.compile(
        r"(?<!\[)(?<!\]\()"
        r"(?<=duplicate of\s)"
        r"(RECON-[0-9a-f]+)"
        r"(?!\])",
    ),
)


def _link_pool_recon_ids(pool_finding_dir: Path,
                         source_results_dir: Path) -> None:
    """Hyperlink `RECON-<hash>` mentions in a pooled FIND's report.md.

    A pooled FIND records the recon hypothesis that promoted it
    (`- **Recon ID:** RECON-<hash>`) plus, when the recon was a
    duplicate, the surviving parent (`Validator details: duplicate of
    RECON-<hash>`). Both are bare text. The matching
    `recon/RECON-<hash>/REPORT.html` carries the independent-validator
    votes with `verified={reachability,guards,primitive}` — useful
    audit context that was otherwise unreachable from the rendered
    pool pages. Rewrite each hash to a relative markdown link when
    its recon dir exists; leave it alone when it was pruned.

    Runs *after* `_scrub_pooled_tree`, since the scrubber would strip
    the workspace prefix from any path the linker introduced.
    Idempotent: the patterns use lookbehind/lookahead to skip hashes
    already inside `[…](…)`.
    """
    if not pool_finding_dir.is_dir() or not source_results_dir.is_dir():
        return
    recon_root = source_results_dir / "recon"
    if not recon_root.is_dir():
        return
    for report in pool_finding_dir.rglob("report.md"):
        try:
            text = report.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        def _link(m: re.Match) -> str:
            token = m.group(1)  # "RECON-<hash>"
            recon_dir = recon_root / token
            # Prefer the rendered HTML sibling, fall back to .md; do
            # nothing if neither exists (an orphaned id from a stale or
            # purged recon tree).
            for name in ("REPORT.html", "REPORT.md"):
                candidate = recon_dir / name
                if candidate.is_file():
                    rel = os.path.relpath(candidate, report.parent)
                    return f"[{token}]({rel})"
            return token

        new_text = text
        for pat in _RECON_LINK_PATTERNS:
            new_text = pat.sub(_link, new_text)
        if new_text == text:
            continue
        try:
            report.write_text(new_text, encoding="utf-8")
        except OSError:
            pass


def _cluster_report_link(label: object, clusters_dir: Path,
                         basename: str) -> str:
    """Link a count to the rendered cluster report a regular run produces.

    bin/cluster-crashes / bin/cluster-findings write `<basename>.md` and a
    rendered `<basename>.html` sibling into the pool's crashes/ or findings/
    directory. Prefer the browsable HTML, fall back to the markdown, and
    finally to the directory itself if neither exists yet.
    """
    html = clusters_dir / f"{basename}.html"
    md = clusters_dir / f"{basename}.md"
    if html.exists():
        return _md_link(label, html)
    if md.exists():
        return _md_link(label, md)
    return _md_link(label, clusters_dir)


def _artifact_report_link(label: object, artifact_dir: Path,
                          basename: str) -> str:
    """Link a count to a rendered artifact index when one exists."""
    html_path = artifact_dir / f"{basename}.html"
    md_path = artifact_dir / f"{basename}.md"
    if html_path.exists():
        return _md_link(label, html_path)
    if md_path.exists():
        return _md_link(label, md_path)
    return _md_link(label, artifact_dir)


def _condition_pool_dir(bench_dir: Path, condition: str, kind: str) -> Path:
    """The per-condition pool subtree for *kind*.

    `benchmark.py split-pool` copies the combined pool into one subtree
    per condition (pool/<condition>/crashes/, .../findings/,
    .../findings-rejected/) so harness evidence and model-direct evidence
    are separate, linkable artifacts.

    Always returns the per-condition path, even when it does not exist on
    disk yet. Callers that hyperlink off this path must check
    `is_dir()`/`exists()` before emitting the link — link helpers do this
    via `_md_link`/`_crosstab_count`, so a missing per-condition subtree
    degrades to plain text rather than silently linking a sibling
    condition's evidence (which is what the old fallback to the combined
    `pool/<kind>/` did — it made a "0 crashes" cell point at another
    condition's loaded crash tree).
    """
    return bench_dir / "pool" / condition / kind


def _file_has_sanitizer_output(path: Path) -> bool:
    try:
        if path.stat().st_size > _MAX_SCAN_BYTES:
            return False
        text = path.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return False
    return bool(SANITIZER_SIGNATURE_RE.search(text))


def dir_has_sanitizer_output(d: Path) -> bool:
    """True iff any regular file under *d* carries a sanitizer signature."""
    if not d.is_dir():
        return False
    for path in d.rglob("*"):
        if path.is_file() and _file_has_sanitizer_output(path):
            return True
    return False


def count_confirmed_crashes(crashes_dir: Path) -> tuple[int, list[str]]:
    """Count crash subdirectories that contain genuine sanitizer output.

    Returns (count, sorted list of crash dir names). A claimed crash dir
    with no sanitizer text on disk is NOT counted — that is what keeps a
    model-direct condition honest: it gets credit for proof, not assertion.
    """
    if not crashes_dir.is_dir():
        return 0, []
    confirmed: list[str] = []
    for child in sorted(crashes_dir.iterdir()):
        if not child.is_dir():
            continue
        if child.name.startswith("."):
            continue
        if dir_has_sanitizer_output(child):
            confirmed.append(child.name)
    return len(confirmed), confirmed


def count_subdirs(parent: Path, prefix: str) -> int:
    """Count immediate subdirectories of *parent* whose name starts prefix."""
    if not parent.is_dir():
        return 0
    return sum(
        1
        for c in parent.iterdir()
        if c.is_dir() and c.name.startswith(prefix)
    )


# Markdown table row in the per-cell `crashes-rejected/INDEX.md` ledger.
# Triage writes one row per rejected crash (id, site, rejected-at) — these
# never get a CRASH-* subdir, so the row count is the only place they show
# up. Header rows ("| ID | ... |" / "| :-- | ... |") are skipped so they
# don't inflate the count.
_REJECTED_CRASH_ROW_RE = re.compile(r"^\|\s*[^|\s]+[^|]*\|")


def count_rejected_crash_rows(index_md: Path) -> int:
    """Count rejected-crash rows in a `crashes-rejected/INDEX.md` ledger.

    The harness writes one row per crash dir it auto-rejected from the
    main `crashes/` tree (runtime-diagnostic class, caller-misuse class,
    etc.); they never get a CRASH-* subdir, so the row count is the
    only signal of their existence.
    """
    if not index_md.is_file():
        return 0
    try:
        text = index_md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    count = 0
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        # Skip table separator rows (made of pipes, dashes, colons, spaces).
        if re.fullmatch(r"\|[\s\-:|]+\|", s):
            continue
        # Skip header row (first non-separator row whose cells are labels
        # like "ID", "Crash site", "Rejected at").
        cells = [c.strip() for c in s.strip("|").split("|")]
        if cells and cells[0].lower() in {"id", "crash id"}:
            continue
        count += 1
    return count


def count_crashes_rejected(rejected_dir: Path) -> int:
    """Total rejected-crash count for a cell's crashes-rejected/ tree.

    Two sources, both legitimate:
      * CRASH-* subdirs — full crash dirs the harness moved out of
        crashes/ after triage decided they were non-security.
      * INDEX.md rows — auto-rejected signatures (runtime-diagnostic
        class, etc.) that never got a CRASH-* dir, only a ledger row.
    Summing both is what makes the column total honest: a reader who
    sees 7 here can find 7 rejection records (subdir or row) below.
    """
    return (
        count_subdirs(rejected_dir, "CRASH-")
        + count_rejected_crash_rows(rejected_dir / "INDEX.md")
    )


def iter_discarded_hypotheses(results_dir: Path):
    """Yield DISCARDED rows from a results tree's hypotheses.jsonl.

    Agent-side rejections (a hypothesis the agent investigated and
    concluded was non-actionable) never reach `crashes-rejected/`,
    because triage only sees what the agent escalated. Mining the
    raw hypothesis ledger surfaces them so the benchmark can
    distinguish "0 wasted work" from "agent silently discarded 20
    leads but nothing escalated to triage".

    Each yielded row is the raw dict; callers project the fields
    they need (agent, file, hypothesis, note, updated_at).
    """
    hyp = Path(results_dir) / "state" / "hypotheses.jsonl"
    if not hyp.is_file():
        return
    try:
        text = hyp.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except (json.JSONDecodeError, AttributeError):
            continue
        if not isinstance(row, dict):
            continue
        if str(row.get("status", "") or "") != "DISCARDED":
            continue
        yield row


def count_discarded_hypotheses(results_dir: Path) -> int:
    """Count DISCARDED rows in a results tree's state/hypotheses.jsonl.

    See ``iter_discarded_hypotheses`` for the rationale. Exposed
    separately as ``discarded_hypothesis_total`` so callers can show
    dropped leads alongside — but not conflated with — triage-rejected
    crashes.
    """
    return sum(1 for _ in iter_discarded_hypotheses(results_dir))


def _count_discarded_roster_rows(roster_md: Path) -> int:
    """Count data rows in a DISCARDED-*.md roster.

    The roster table is rendered with a leading index column ("# | Agent
    | ..."); data rows have a numeric first cell, while the header and
    separator do not. This is the cheapest accurate row count without
    re-reading the original hypotheses.jsonl.
    """
    if not roster_md.is_file():
        return 0
    try:
        text = roster_md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    count = 0
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if not cells:
            continue
        if cells[0].isdigit():
            count += 1
    return count


def _format_discarded_hypotheses_roster(
    results_dir: Path, condition: str, cell: str
) -> str:
    """Render a markdown roster of DISCARDED hypotheses for one cell.

    Returns an empty string when nothing was discarded so the caller
    can skip writing a noise-only page. The roster is intended to live
    under the pool's `crashes-rejected/` directory and be linked from
    REJECTED-CRASHES.md so the bumped column total has a concrete
    landing page.
    """
    rows = list(iter_discarded_hypotheses(results_dir))
    if not rows:
        return ""
    lines = [
        f"# Discarded hypotheses — {condition} / {cell}",
        "",
        (
            "Agent-side rejections: leads the agent opened, investigated, "
            "and then closed as non-actionable (no crash, false positive, "
            "guard-saturated, etc.). One row per hypothesis."
        ),
        "",
        "| # | Agent | File | Hypothesis | Note | Updated |",
        "| ---: | --- | --- | --- | --- | --- |",
    ]
    for idx, row in enumerate(rows, 1):
        agent = _md_cell(row.get("agent", ""))
        file = _md_cell(row.get("file", ""))
        hyp = _md_cell(_short(str(row.get("hypothesis", "") or ""), 160))
        note = _md_cell(_short(str(row.get("note", "") or ""), 200))
        updated = _md_cell(row.get("updated_at", ""))
        lines.append(
            f"| {idx} | {agent} | `{file}` | {hyp} | {note} | {updated} |"
        )
    lines.append("")
    return "\n".join(lines)


def parse_cluster_count(clusters_md: Path, fallback: int) -> int:
    """Read 'N unique cluster(s)' out of a CRASH/FINDING-CLUSTERS.md file.

    The harness writes these during triage; when the file is absent (e.g.
    an un-triaged model-direct workspace) we fall back to the raw dir count.
    """
    try:
        text = clusters_md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return fallback
    m = _CLUSTER_COUNT_RE.search(text)
    return int(m.group(1)) if m else fallback


# Backends whose `input` token field already includes the cached prefix
# (cached + fresh). Codex reports a running total; local OpenCode/oss
# transcripts can follow the same cumulative shape when usage is present;
# gemini-cli's `result.stats.input_tokens` is likewise cumulative (it
# also emits a separate fresh-only `input`, but the priority order in
# _INPUT_KEYS picks `input_tokens` first, so the same subtract-cached
# normalization applies). Claude reports fresh input only and stays out
# of this list. harvest_tokens subtracts the cached part for these so
# the per-turn delta is comparable across backends. Backend names are
# industry vocabulary, not target-specific, so this list is
# harness-shared by design.
_INPUT_INCLUDES_CACHED = ("codex", "oss", "gemini")

_MILLION = Decimal("1000000")


def _money(value: str) -> Decimal:
    return Decimal(value)


def _pricing_rates(backend: str, model: str = "") -> dict | None:
    """Public USD-equivalent token rates per 1M tokens.

    Codex product billing uses credits, but the underlying model has public
    API-equivalent token rates. Those rates are the reproducible denominator
    for cross-backend benchmark dollars.
    """
    b = (backend or "").strip().lower()
    m = (model or "").strip().lower()

    if b == "claude":
        # Claude API pricing, standard global routing, 5-minute prompt cache.
        if any(x in m for x in ("opus-4-8", "opus-4.8", "opus 4.8")):
            return {
                "input": _money("5"),
                "cache_write": _money("6.25"),
                "cache_read": _money("0.50"),
                "output": _money("25"),
                "source": "claude-api-opus-4.8",
            }
        if any(x in m for x in (
            "opus-4-7", "opus-4.7", "opus-4-6", "opus-4.6",
            "opus-4-5", "opus-4.5",
        )):
            return {
                "input": _money("5"),
                "cache_write": _money("6.25"),
                "cache_read": _money("0.50"),
                "output": _money("25"),
                "source": "claude-api-opus-4.5+",
            }
        if "opus" in m:
            return {
                "input": _money("15"),
                "cache_write": _money("18.75"),
                "cache_read": _money("1.50"),
                "output": _money("75"),
                "source": "claude-api-opus-4.1/4",
            }
        if "sonnet" in m:
            return {
                "input": _money("3"),
                "cache_write": _money("3.75"),
                "cache_read": _money("0.30"),
                "output": _money("15"),
                "source": "claude-api-sonnet-4.x",
            }
        if "haiku" in m:
            return {
                "input": _money("1"),
                "cache_write": _money("1.25"),
                "cache_read": _money("0.10"),
                "output": _money("5"),
                "source": "claude-api-haiku-4.5",
            }

    if b in {"codex", "oss"}:
        if "gpt-5.5" in m:
            return {
                "tiered": True,
                "threshold": 272_000,
                "input_low": _money("5"),
                "input_high": _money("10"),
                "cache_read_low": _money("0.50"),
                "cache_read_high": _money("1"),
                "output_low": _money("30"),
                "output_high": _money("45"),
                "source": "openai-api-gpt-5.5",
            }
        if "gpt-5.4-mini" in m:
            return {
                "input": _money("0.75"),
                "cache_read": _money("0.075"),
                "output": _money("4.50"),
                "source": "openai-api-gpt-5.4-mini",
            }
        if "gpt-5.4" in m:
            return {
                "input": _money("2.50"),
                "cache_read": _money("0.25"),
                "output": _money("15"),
                "source": "openai-api-gpt-5.4",
            }

    if b == "gemini":
        if "gemini-3.1-pro-preview" in m or "gemini-3-pro" in m:
            return {
                "tiered": True,
                "threshold": 200_000,
                "input_low": _money("2"),
                "input_high": _money("4"),
                "cache_read_low": _money("0.20"),
                "cache_read_high": _money("0.40"),
                "output_low": _money("12"),
                "output_high": _money("18"),
                "source": "gemini-api-3.1-pro-preview-standard",
            }
        if "gemini-3.1-flash-lite" in m:
            return {
                "input": _money("0.25"),
                "cache_read": _money("0.025"),
                "output": _money("1.50"),
                "source": "gemini-api-3.1-flash-lite-standard",
            }
        if "gemini-3-flash" in m:
            return {
                "input": _money("0.50"),
                "cache_read": _money("0.05"),
                "output": _money("3"),
                "source": "gemini-api-3-flash-standard",
            }

    return None


def _cost_decimal(
    backend: str,
    model: str,
    *,
    input_tokens: int,
    cached_input_tokens: int,
    output_tokens: int,
    cache_creation_tokens: int = 0,
    prompt_tokens_for_tier: int | None = None,
) -> tuple[Decimal | None, str]:
    rates = _pricing_rates(backend, model)
    if not rates:
        return None, "unknown"

    inp = Decimal(max(0, int(input_tokens)))
    cached = Decimal(max(0, int(cached_input_tokens)))
    out = Decimal(max(0, int(output_tokens)))
    cache_create = Decimal(max(0, int(cache_creation_tokens)))

    if rates.get("tiered"):
        prompt = int(prompt_tokens_for_tier or input_tokens or 0)
        high = prompt > int(rates["threshold"])
        input_rate = rates["input_high" if high else "input_low"]
        cache_rate = rates["cache_read_high" if high else "cache_read_low"]
        output_rate = rates["output_high" if high else "output_low"]
        cost = (inp * input_rate + cached * cache_rate + out * output_rate) / _MILLION
        return cost, str(rates["source"])

    input_rate = rates["input"]
    cache_rate = rates.get("cache_read", Decimal("0"))
    output_rate = rates["output"]
    write_rate = rates.get("cache_write", input_rate)

    # `input_tokens` is the normalized full-rate bucket. For Claude it
    # includes cache writes for comparability; pricing needs the split
    # because cache writes are 1.25x base input.
    fresh_input = max(Decimal("0"), inp - cache_create)
    cost = (
        fresh_input * input_rate
        + cache_create * write_rate
        + cached * cache_rate
        + out * output_rate
    ) / _MILLION
    return cost, str(rates["source"])


def _decimal_text(value: Decimal | None) -> str:
    if value is None:
        return ""
    return format(value.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP), "f")


def _fmt_usd(value: object, estimated: bool = False) -> str:
    try:
        dec = Decimal(str(value))
    except Exception:
        return "—"
    prefix = "~" if estimated else ""
    amount = dec.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
    return f"{prefix}${amount:,.4f}"


def harvest_tokens(
    index_jsonl: Path,
    default_backend: str = "",
    default_model: str = "",
) -> dict:
    """Sum token usage + sanitizer invocations from a logs/index.jsonl.

    Counts are normalized so a field means the same thing on every
    backend, which is what makes a cross-condition cost comparison fair:

      * input_tokens — tokens the model processed this turn at the
        full input rate (≥100%). On Claude this is `input + cache_creation`
        (cache writes are billed at 125% of base input and represent
        genuinely new content the model just read). On codex/oss/gemini
        the SDK's `input` is cumulative — cache_read is subtracted so the
        remainder is the new content this turn. End result: one number
        meaning "non-cache-hit input the model paid full freight on,"
        comparable across backends.
      * cached_input_tokens — cache READS only (billed at ~10%). Kept
        separate so the headline Input column isn't inflated by the cheap
        amortized part. Cache writes used to be lumped in here too; they
        now live in input_tokens where they belong.
    """
    totals = {
        "iterations": 0,
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "cache_creation_tokens": 0,
        "output_tokens": 0,
        "asan_invocations": 0,
        # prompt_estimate is the only token signal the gemini backend
        # (Antigravity CLI) produces — agy surfaces no real usage, so the
        # harness estimates the prompt side. Summed here so a gemini cell
        # is not silently scored as zero-cost.
        "prompt_estimate_tokens": 0,
        "estimated": False,
        "cost_usd": "",
        "cost_source": "",
    }
    if not index_jsonl.is_file():
        return totals
    try:
        lines = index_jsonl.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return totals

    def _int(value: object) -> int:
        return int(value) if isinstance(value, (int, float)) else 0

    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        totals["iterations"] += 1
        backend = str(row.get("backend") or default_backend or "").strip().lower()
        model = str(row.get("model") or default_model or "").strip()
        tok = row.get("tokens") or {}
        raw_input = _int(tok.get("input"))
        # cache_read is written as `cached_input` by both the harness and
        # the model-direct extractor; `cache_read` is a harness-only alias.
        cache_read = _int(tok.get("cached_input")) or _int(tok.get("cache_read"))
        cache_creation = _int(tok.get("cache_creation"))
        if backend in _INPUT_INCLUDES_CACHED:
            full_rate_input = max(0, raw_input - cache_read)
        else:
            # Claude's `input` excludes both cache hits AND cache writes;
            # cache_creation is billed at 125% of base input rate and is
            # genuinely fresh content the model just processed, so it
            # belongs in the full-rate bucket alongside `input`.
            full_rate_input = raw_input + cache_creation
        output = _int(tok.get("output"))
        totals["input_tokens"] += full_rate_input
        totals["cached_input_tokens"] += cache_read
        totals["cache_creation_tokens"] += cache_creation
        totals["output_tokens"] += output
        event_cost, source = _cost_decimal(
            backend,
            model,
            input_tokens=full_rate_input,
            cached_input_tokens=cache_read,
            output_tokens=output,
            cache_creation_tokens=cache_creation,
            prompt_tokens_for_tier=raw_input,
        )
        if event_cost is not None:
            totals["cost_usd"] = _decimal_text(
                Decimal(totals["cost_usd"] or "0") + event_cost
            )
            totals["cost_source"] = source
        for field in ("prompt_estimate", "prompt_estimate_build"):
            val = tok.get(field)
            if isinstance(val, (int, float)):
                totals["prompt_estimate_tokens"] += int(val)
                if raw_input == 0 and backend == "gemini":
                    estimate_cost, source = _cost_decimal(
                        backend,
                        model,
                        input_tokens=int(val),
                        cached_input_tokens=0,
                        output_tokens=output,
                        prompt_tokens_for_tier=int(val),
                    )
                    if estimate_cost is not None:
                        totals["cost_usd"] = _decimal_text(
                            Decimal(totals["cost_usd"] or "0") + estimate_cost
                        )
                        totals["cost_source"] = source
                        totals["estimated"] = True
                break
        probe = row.get("probe") or {}
        totals["asan_invocations"] += _int(probe.get("asan_invocations"))
        if row.get("estimated") is True:
            totals["estimated"] = True
    return totals


def _find_index_jsonl(results_dir: Path) -> Path:
    """Locate the agent-log index for a results tree.

    Two layouts: a model-direct workspace keeps logs/ *inside* the results
    dir, while a harness run keeps results/ and logs/ as siblings under
    output/<target>-<exp>/<backend>/. Prefer the in-tree path; fall back to
    the sibling so harness cells' token telemetry is harvested too (without
    this, every harness row scored as zero tokens). Returns the in-tree
    path when neither exists — harvest_tokens handles a missing file.
    """
    inside = results_dir / "logs" / "index.jsonl"
    if inside.is_file():
        return inside
    sibling = results_dir.parent / "logs" / "index.jsonl"
    if sibling.is_file():
        return sibling
    return inside


def count_recon_candidates(results_dir: Path) -> int:
    """Count recon hypotheses emitted for one results/ tree.

    bin/audit-recon writes candidates to recon-hypotheses.jsonl (one JSON
    row per hypothesis), not to a recon/RECON-* directory tree. Count the
    JSONL rows whose id is a recon hypothesis so the metric reflects the
    actual recon volume rather than a directory layout that never exists.
    """
    hyp = Path(results_dir) / "recon-hypotheses.jsonl"
    if not hyp.is_file():
        return 0
    count = 0
    for line in hyp.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rid = json.loads(line).get("id", "")
        except (json.JSONDecodeError, AttributeError):
            continue
        if rid.startswith("RECON-") or rid.startswith("REC-"):
            count += 1
    return count


def count_model_refusals(results_dir: Path) -> int:
    """Count backend refusal warnings recorded for one benchmark cell.

    The LLM launch shim and custom audit launch paths write one-line
    ``*.refusals.log`` sidecars carrying ``MODEL_REFUSAL``. Model-direct cells
    keep those beside ``backend.raw.log`` inside *results_dir*; harness cells
    keep them under the sibling ``logs/`` tree next to ``results/``.
    """
    roots = [Path(results_dir)]
    sibling_logs = Path(results_dir).parent / "logs"
    if sibling_logs.is_dir():
        roots.append(sibling_logs)

    count = 0
    seen: set[Path] = set()
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*refusals.log"):
            try:
                resolved = path.resolve()
            except OSError:
                resolved = path
            if resolved in seen or not path.is_file():
                continue
            seen.add(resolved)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            count += sum(1 for line in text.splitlines()
                         if _MODEL_REFUSAL_RE.search(line))
    return count


# ── ground-truth scoring (precision / recall) ────────────────────────────
#
# count_confirmed_crashes makes the crash *count* trustworthy, but on an
# ordinary target there is no oracle for *which* planted bug a crash is, so
# a run's precision and recall are unknowable — and none of the triage gate
# thresholds can be calibrated against a labelled answer. The canary target
# ships a ground-truth manifest (targets/<slug>/ground-truth.json) that pins
# every planted bug to a stable (primitive, symbol) signature and every
# deliberate false-positive trap to its refutation. Scoring a results tree
# against that manifest converts the raw crash count into measured precision
# and recall: the numbers every gate threshold should be tuned against.


def load_ground_truth(path: Path) -> dict | None:
    """Parse a ground-truth manifest; return None if absent or malformed."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def manifest_errors(manifest: dict) -> list[str]:
    """Validate a ground-truth manifest before scoring.

    The scorer's identity is (primitive, symbol) for a real bug and
    (outcome, symbol) for a trap; a manifest typo that drops a field, mis-types
    the kind, or collides a match-key would silently weaken matching. So
    validate, up front and loudly, everything the matcher and the score_subset
    partition depend on:

    * unique non-empty ids;
    * the exact `kind` the scorer keys on — a planted bug whose kind is typoed
      away from "real" is dropped from the recall denominator (inflating
      recall), and a trap whose kind is not "fp" is never matched (a fired
      trap then counts as an unexpected crash, deflating precision);
    * the required match fields (signature_symbol, primitive for bugs,
      expected_outcome for traps);
    * a unique match-key per list, so a second entry sharing one entry's
      (primitive, symbol) / (outcome, symbol) is not left permanently
      unreachable (always 'missed' or 'unexpected').
    """
    errors: list[str] = []
    seen: set[str] = set()

    def check(entries, label: str, *, need_primitive: bool,
              need_outcome: bool, want_kind: str):
        if not isinstance(entries, list):
            errors.append(f"{label} must be a list")
            return
        keys: set[tuple[str, str]] = set()
        for i, e in enumerate(entries):
            where = f"{label}[{i}]"
            if not isinstance(e, dict):
                errors.append(f"{where} must be an object")
                continue
            eid = str(e.get("id", "")).strip()
            if not eid:
                errors.append(f"{where} is missing a non-empty id")
            elif eid in seen:
                errors.append(f"duplicate id {eid!r}")
            else:
                seen.add(eid)
            # kind defaults to the scorer's expectation; an explicit typo is
            # the silent-drop the scorer cannot otherwise see.
            kind = str(e.get("kind", want_kind)).strip()
            if kind != want_kind:
                errors.append(
                    f"{where} ({eid or '?'}) has kind {kind!r}, "
                    f"expected {want_kind!r}")
            sym = str(e.get("signature_symbol", "")).strip()
            if not sym:
                errors.append(f"{where} ({eid or '?'}) needs a signature_symbol")
            prim = str(e.get("primitive", "")).strip()
            if need_primitive and not prim:
                errors.append(f"{where} ({eid or '?'}) needs a primitive")
            # A trap must declare what a benign occurrence looks like, so the
            # scorer can tell a fired trap from a real crash in the same frame.
            outcome = str(e.get("expected_outcome", "")).strip()
            if need_outcome and not outcome:
                errors.append(f"{where} ({eid or '?'}) needs an expected_outcome")
            key = (prim, sym) if need_primitive else (outcome, sym)
            if sym and key in keys:
                errors.append(
                    f"{where} ({eid or '?'}) duplicates match key {key!r}")
            elif sym:
                keys.add(key)

    check(manifest.get("planted_bugs", []), "planted_bugs",
          need_primitive=True, need_outcome=False, want_kind="real")
    check(manifest.get("false_positive_traps", []), "false_positive_traps",
          need_primitive=False, need_outcome=True, want_kind="fp")
    return errors


def ground_truth_path_for(target: str, repo_root: Path | None = None) -> Path:
    """Manifest (answer key) location for a target slug.

    Deliberately under output/<slug>/ — NOT targets/<slug>/ — so it is not in
    the target tree handed to the audited agents (model-direct is granted the
    target root; see bin/benchmark), keeping the score blind on that side.
    output/* is gitignored, so a real-target answer key stays private by
    default; the synthetic canary's is the one committed exception. Only a
    target shipping this file is scored; everything else is unaffected.
    """
    root = Path(repo_root) if repo_root else Path(__file__).resolve().parent.parent
    return root / "output" / str(target) / "ground-truth.json"


# Evidence is read ONLY from the sanitizer runtime's own output, never from
# an agent's report.md, so a narrative that merely names a planted bug cannot
# spoof a ground-truth match.
#
# The token a sanitizer prints right after its name, e.g.
# "AddressSanitizer: heap-buffer-overflow" or "AddressSanitizer: ABRT".
# Upper-case classes (ABRT, SEGV) are captured too so a trap can be matched
# by its expected observed outcome, not by frame symbol alone.
_PRIMITIVE_RE = re.compile(
    r"(?:AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|"
    r"ThreadSanitizer):\s+([A-Za-z][A-Za-z0-9-]+)"
)

# A symbolized sanitizer stack frame: "    #3 0x... in <func> <loc>".
_FRAME_FUNC_RE = re.compile(r"^\s*#\d+\s+\S+\s+in\s+(\S+)", re.MULTILINE)

# Markers that end the crash-state stack and begin an allocation/free/context
# stack. Used only by the fallback frame parser (when lib/stack_frames is
# unimportable); the shared parser applies the same boundary itself.
_STACK_STATE_STOP_RE = re.compile(
    r"^\s*(?:allocated|freed|previously allocated) by", re.MULTILINE
)

# Sanitizer interceptor/runtime frames (e.g. __asan_memcpy, __tsan_read4).
# Used only by the fallback crash-site parser to skip past the interceptor to
# the real faulting function; the shared parser's ignore list does this
# itself. Structural prefix match, so a new interceptor needs no list edit.
_SAN_INTERCEPTOR_RE = re.compile(
    r"^(?:__asan|__hwasan|__msan|__tsan|__ubsan|__sanitizer|__interceptor)"
)


def _find_sanitizer_file(crash_dir: Path) -> Path | None:
    """Canonical sanitizer-output file in a crash dir, or None.

    Delegates to the shared crash-artifact policy so the benchmark accepts
    exactly the sanitizer filenames export/triage/cluster do (sanitizer.txt,
    asan.txt, asan_output.txt, asan-raw*, root msan/tsan/ubsan.txt, suffix
    files) and skips empty files in favour of a non-empty sibling — otherwise
    a dir the confirmed-crash oracle counts could yield no evidence and be
    mis-scored. The small fallback covers the (never-expected) case where the
    shared module is unimportable."""
    if _ca is not None:
        return _ca.find_primary_asan([crash_dir, crash_dir / ".audit"])
    for name in ("sanitizer.txt", "asan.txt", "asan-output.txt",
                 "asan_output.txt", "msan.txt", "tsan.txt", "ubsan.txt"):
        p = crash_dir / name
        if p.is_file() and p.stat().st_size > 0:
            return p
    return None


def _crash_site_functions(text: str) -> set[str]:
    """Function name(s) at the crash SITE — the first interesting frame, the
    same frame bin/cluster-crashes keys its signature on.

    Matching a planted symbol against the crash site (not against every frame
    in the stack) is what stops a crash whose real fault is elsewhere from
    being credited to a planted symbol that merely appears deeper as a caller,
    an allocator, or a freer. The shared ClusterFuzz parser skips sanitizer
    interceptor frames (e.g. __asan_memcpy) so the site is the true faulting
    function; the raw and normalized names are both returned so a manifest
    symbol written either way matches.

    Fallback (shared parser unimportable): the first frame line before any
    allocation/free marker that is not itself a sanitizer interceptor."""
    if _sf is not None:
        fr = _sf.first_interesting_frame(text)
        if fr is None:
            return set()
        return {f for f in (fr.function, fr.state_function) if f}
    head = _STACK_STATE_STOP_RE.split(text, maxsplit=1)[0]
    for fn in _FRAME_FUNC_RE.findall(head):
        if not _SAN_INTERCEPTOR_RE.match(fn):
            return {fn}
    return set()


def _attribution_evidence(crash_dir: Path) -> tuple[str, set[str]] | None:
    """Trusted runtime evidence for attribution, or None.

    `(primitive, crash-site function names)` parsed from a CANONICAL sanitizer
    artifact — the sanitizer runtime's own output file (find_primary_asan:
    sanitizer.txt, asan.txt, asan_output.txt, the .audit captures, …),
    content-verified to carry a real diagnostic.

    Attribution is NEVER read from an agent-authored report.md. Prose that
    pastes an ASan-shaped stack is a *claim*, not runtime proof, and must not
    manufacture a true positive — the benchmark measures detection backed by
    proof, not assertion. A confirmed crash with no canonical artifact returns
    None and is scored as *unattributed*: still counted as a confirmed crash,
    but never credited to a planted bug, so prose can lower precision and never
    inflate recall."""
    san = _find_sanitizer_file(crash_dir)
    if san is None or not _file_has_sanitizer_output(san):
        return None
    try:
        text = san.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    m = _PRIMITIVE_RE.search(text)
    return (m.group(1) if m else ""), _crash_site_functions(text)


# A trap's expected_outcome names what a *benign* occurrence looks like.
# "clean" means it should never be a confirmed crash at all; "abort" maps to
# the ASan ABRT class; any other value is taken as a literal sanitizer
# primitive. Anything else observed in the trap's frame is a real unexpected
# crash, not the trap firing.
_OUTCOME_PRIMITIVE = {"abort": "ABRT"}


def _match_real(primitive: str, crash_site: set[str],
                bugs: list[dict]) -> dict | None:
    """First planted bug whose (primitive, crash-site symbol) the evidence
    satisfies — both facts bin/cluster-crashes keys a crash on. *crash_site*
    is the faulting frame only, so a planted symbol that merely appears as a
    caller, allocator, or freer does not match."""
    for b in bugs:
        prim = str(b.get("primitive", ""))
        sym = str(b.get("signature_symbol", ""))
        if prim and prim != primitive:
            continue
        if sym and sym not in crash_site:
            continue
        if prim or sym:
            return b
    return None


def _match_trap(primitive: str, crash_site: set[str],
                traps: list[dict]) -> dict | None:
    """First trap whose crash-site symbol AND expected observed outcome match.
    A trap fires only when the observed sanitizer class is the benign one it
    predicts; a real memory-safety primitive at a trap's frame falls through
    to 'unexpected' instead of being excused as the trap."""
    for t in traps:
        sym = str(t.get("signature_symbol", ""))
        outcome = str(t.get("expected_outcome", ""))
        if outcome in ("", "clean"):
            continue  # clean trap: any confirmed crash here is unexpected
        if _OUTCOME_PRIMITIVE.get(outcome, outcome) != primitive:
            continue
        if sym and sym not in crash_site:
            continue
        return t
    return None


def score_ground_truth(
    crashes_dir: Path,
    manifest: dict,
    members: dict | None = None,
    conditions: list | None = None,
) -> dict:
    """Score confirmed crashes in a tree against a ground-truth manifest.

    *crashes_dir* may be a `crashes/` directory or a results/pool dir that
    contains one. *members* optionally maps each crash dir name to the
    condition that produced it (pool-members.json) so the score can be
    broken out per condition. *conditions* names every condition that should
    appear in the per-condition breakdown — pass the run's full list so a
    condition that found zero crashes still gets a 0%-recall row (the exact
    comparison the canary exists to surface); when omitted, the conditions
    are inferred from *members*. Recall is over the distinct real bugs found,
    each credited only from a canonical runtime sanitizer artifact at the
    crash site; precision is crash-level — every confirmed crash that is not a
    real planted bug (a fired trap, a novel/unexpected crash, or a confirmed
    crash with no canonical runtime artifact to attribute) is a false positive.
    """
    crashes_dir = Path(crashes_dir)
    if (crashes_dir / "crashes").is_dir():
        crashes_dir = crashes_dir / "crashes"
    members = members or {}
    real = [
        b for b in manifest.get("planted_bugs", [])
        if b.get("kind", "real") == "real"
    ]
    traps = manifest.get("false_positive_traps", [])

    confirmed: list[tuple[str, tuple[str, set] | None]] = []
    if crashes_dir.is_dir():
        for child in sorted(crashes_dir.iterdir()):
            if not child.is_dir() or child.name.startswith("."):
                continue
            # Membership in the scored set is the oracle's own gate (the same
            # one that produces the headline crash count). Attribution is then
            # read from a canonical runtime artifact; evidence is None when the
            # dir is confirmed but carries only prose (e.g. report.md) — scored
            # as unattributed, never a true positive.
            if not dir_has_sanitizer_output(child):
                continue
            confirmed.append((child.name, _attribution_evidence(child)))

    def score_subset(items: list) -> dict:
        detected: dict[str, list[str]] = {}
        traps_fired: dict[str, list[str]] = {}
        unexpected: list[str] = []
        unattributed: list[str] = []
        for name, evidence in items:
            if evidence is None:
                unattributed.append(name)
                continue
            primitive, crash_site = evidence
            hit = _match_real(primitive, crash_site, real)
            if hit:
                detected.setdefault(hit["id"], []).append(name)
                continue
            trap = _match_trap(primitive, crash_site, traps)
            if trap:
                traps_fired.setdefault(trap["id"], []).append(name)
            else:
                unexpected.append(name)
        tp_bugs = len(detected)
        tp_crashes = sum(len(v) for v in detected.values())
        fp_crashes = (sum(len(v) for v in traps_fired.values())
                      + len(unexpected) + len(unattributed))
        total = tp_crashes + fp_crashes
        return {
            "real_total": len(real),
            "detected": sorted(detected),
            "missed": sorted(b["id"] for b in real if b["id"] not in detected),
            "recall": round(tp_bugs / len(real), 4) if real else None,
            "confirmed_crashes": total,
            "true_positive_crashes": tp_crashes,
            "false_positive_crashes": fp_crashes,
            "false_positive_traps_fired": sorted(traps_fired),
            "unexpected_crashes": sorted(unexpected),
            "unattributed_crashes": sorted(unattributed),
            "precision": round(tp_crashes / total, 4) if total else None,
        }

    result = {"overall": score_subset(confirmed)}
    conds = list(conditions) if conditions is not None else sorted(set(members.values()))
    if conds:
        result["by_condition"] = {
            cond: score_subset([(n, e) for (n, e) in confirmed
                                if members.get(n) == cond])
            for cond in conds
        }
    return result


def harvest(
    results_dir: Path,
    default_backend: str = "",
    default_model: str = "",
) -> dict:
    """Compute the deterministic metric set for one results/ tree.

    Works identically for a harness results dir and a model-direct-condition
    workspace shaped the same way (crashes/, findings/, recon/, logs/) —
    the comparison is fair because both are measured by this one yardstick.
    """
    results_dir = Path(results_dir)
    crashes_dir = results_dir / "crashes"
    findings_dir = results_dir / "findings"

    crash_count, crash_dirs = count_confirmed_crashes(crashes_dir)
    crash_clusters = parse_cluster_count(
        crashes_dir / "CRASH-CLUSTERS.md", crash_count
    )
    finding_count = count_subdirs(findings_dir, "FIND-")
    finding_clusters = parse_cluster_count(
        findings_dir / "FINDING-CLUSTERS.md", finding_count
    )

    metrics = {
        "results_dir": str(results_dir),
        "confirmed_crashes": crash_count,
        "crash_clusters": crash_clusters,
        "crash_dirs": crash_dirs,
        "crashes_rejected": count_crashes_rejected(
            results_dir / "crashes-rejected"
        ),
        "discarded_hypotheses": count_discarded_hypotheses(results_dir),
        "findings": finding_count,
        "finding_clusters": finding_clusters,
        "findings_rejected": count_subdirs(
            results_dir / "findings-rejected", "FIND-"
        ),
        "recon_candidates": count_recon_candidates(results_dir),
        "model_refusals": count_model_refusals(results_dir),
        "exists": results_dir.is_dir(),
    }
    metrics["tokens"] = harvest_tokens(
        _find_index_jsonl(results_dir),
        default_backend=default_backend,
        default_model=default_model,
    )
    return metrics


# ── rejected finding indexes ─────────────────────────────────────────────

def _read_json(path: Path) -> dict:
    try:
        obj = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}
    return obj if isinstance(obj, dict) else {}


def _choose_vote(finding_dir: Path) -> dict:
    """Pick the validator vote that explains why a rejected FIND moved."""
    votes = []
    for path in sorted(finding_dir.glob("validator-vote-*.json")):
        obj = _read_json(path)
        if obj:
            obj["_path"] = path.name
            votes.append(obj)
    for vote in votes:
        if str(vote.get("vote") or "").lower() == "reject":
            return vote
    return votes[-1] if votes else {}


def _choose_find_quality(finding_dir: Path) -> dict:
    """Read the FIND-quality gate cache (lib/triage.sh) when present.

    Rejections via the FIND-quality LLM gate write
    `.llm-find-quality.json` with `accept/reason/class/severity` — not
    a `validator-vote-*.json`. Reading both keeps the page populated
    regardless of which gate flagged the finding.
    """
    cache = finding_dir / ".llm-find-quality.json"
    if not cache.is_file():
        return {}
    return _read_json(cache) or {}


def _bool_label(value: object) -> str:
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "?"


def _md_cell(value: object) -> str:
    text = str(value if value is not None else "").replace("\n", " ")
    return text.replace("|", "\\|").strip()


def _short(text: str, limit: int = 220) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def _exact_child_file(parent: Path, names: tuple[str, ...]) -> Path | None:
    """Return an exact-case child match, even on case-insensitive filesystems."""
    try:
        children = {child.name: child for child in parent.iterdir()}
    except OSError:
        return None
    for name in names:
        child = children.get(name)
        if child is not None and child.is_file():
            return child
    return None


def _report_link_name(finding_dir: Path) -> str:
    report = _exact_child_file(
        finding_dir,
        ("report.md", "REPORT.md", "description.md", "analysis.md",
         "report.html", "REPORT.html", "description.html"),
    )
    return report.name if report is not None else ""


# ── rejection-index cell helpers (shared schema with lib/triage.sh) ──────
# The audit writes crashes-rejected/INDEX.md + findings-rejected/INDEX.md via
# lib/triage.sh; these mirror its Site/Reason extraction so the benchmark
# pool's REJECTED-CRASHES.md / REJECTED-FINDINGS.md read identically.

_REJECT_FRAME_SKIP_RE = re.compile(
    r"__asan|__sanitizer|__interceptor|libc\+\+|libsystem_|libdyld|libobjc|"
    r"asan_interceptors|libsancov|libclang_rt|\bstart\+"
)
_REJECT_FRAME_PREFIX_RE = re.compile(r"^\s*#\d+\s+0[xX][0-9a-fA-F]+\s+in\s+")


def _first_crash_frame(text: str) -> str:
    """First interesting "func file:line" frame, skipping sanitizer/libc/
    runtime frames — the awk-fallback twin of lib/triage.sh's site column
    (lib/stack_frames.py returns nothing for UBSan traces)."""
    for line in text.splitlines():
        if not re.match(r"^\s*#\d+", line):
            continue
        if _REJECT_FRAME_SKIP_RE.search(line):
            continue
        return _REJECT_FRAME_PREFIX_RE.sub("", line).strip()[:70]
    return ""


def _crash_sanitizer_text(crash_dir: Path) -> str:
    direct = _exact_child_file(
        crash_dir,
        ("sanitizer.txt", "asan.txt", "msan.txt", "tsan.txt", "ubsan.txt"),
    )
    candidates: list[Path] = [direct] if direct is not None else []
    if not candidates:
        for pat in ("*.asan.txt", "*.msan.txt", "*.tsan.txt", "*.ubsan.txt"):
            candidates.extend(sorted(crash_dir.glob(pat)))
    for c in candidates:
        try:
            return c.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
    return ""


def _crash_site(crash_dir: Path) -> str:
    text = _crash_sanitizer_text(crash_dir)
    return _first_crash_frame(text) if text else ""


def _crash_reason(crash_dir: Path) -> str:
    """Triage's rejection rationale, recorded in the dir's .autodiscard."""
    marker = crash_dir / ".autodiscard"
    if not marker.is_file():
        return ""
    try:
        for line in marker.read_text(
                encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if s.startswith("# Reason:"):
                return s[len("# Reason:"):].strip()
    except OSError:
        pass
    return ""


def _finding_site(finding_dir: Path) -> str:
    """file:func:line for a rejected finding, read from its Fields table."""
    for name in ("REPORT.md", "report.md", "description.md", "analysis.md"):
        path = finding_dir / name
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        fields: dict[str, str] = {}
        for line in text.splitlines():
            m = re.match(r"^\|\s*(File|Function|Line)\s*\|\s*(.+?)\s*\|", line, re.I)
            if not m:
                continue
            key = m.group(1).lower()
            val = m.group(2).strip().strip("`").strip()
            if val and key not in fields:
                fields[key] = val
        parts = [fields[k] for k in ("file", "function", "line") if fields.get(k)]
        if parts:
            return ":".join(parts)
    return ""


def _finding_title(finding_dir: Path) -> str:
    for name in ("REPORT.md", "report.md", "description.md", "analysis.md"):
        path = finding_dir / name
        if not path.is_file():
            continue
        try:
            for line in path.read_text(
                    encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if line.startswith("#"):
                    return line.lstrip("#").strip() or finding_dir.name
        except OSError:
            pass
    return finding_dir.name


def _rejected_finding_rows(rejected_dir: Path) -> list[dict]:
    rows = []
    if not rejected_dir.is_dir():
        return rows
    for finding_dir in sorted(rejected_dir.iterdir()):
        if not finding_dir.is_dir() or not finding_dir.name.startswith("FIND-"):
            continue
        vote = _choose_vote(finding_dir)
        quality = _choose_find_quality(finding_dir)
        # Reason prefers the validator's long-form rationale (when a
        # recon-side vote exists), then falls back to the FIND-quality
        # gate's reason (the path most pool entries take).
        reason = (
            vote.get("rationale")
            or vote.get("reason")
            or quality.get("reason")
            or vote.get("caveats")
            or ""
        )
        rows.append({
            "id": finding_dir.name,
            "title": _finding_title(finding_dir),
            "site": _finding_site(finding_dir),
            "reason": reason,
            "report": _report_link_name(finding_dir),
        })
    return rows


def write_rejected_crashes_index(rejected_dir: Path) -> None:
    """Write a markdown summary for crashes rejected by triage.

    Two sources are stitched together so the column can link to a single
    artifact: (1) any pooled `CRASH-REJECTED-NNNN/` subdirs (crash dirs
    moved out of crashes/ during triage), and (2) the per-cell
    `INDEX-<cond>-<cell>.md` rosters (auto-rejected signatures that
    never got a full crash dir). Empty rosters still produce a page so
    the link target exists even when the count is 0.
    """
    rejected_dir = Path(rejected_dir)
    if not rejected_dir.is_dir():
        return
    subdirs = sorted(
        p for p in rejected_dir.iterdir()
        if p.is_dir() and p.name.startswith("CRASH-")
    )
    rosters = sorted(rejected_dir.glob("INDEX-*.md"))
    discarded_rosters = sorted(rejected_dir.glob("DISCARDED-*.md"))

    md = [
        "# Rejected crashes",
        "",
        (
            "Crashes the harness triaged out as non-security before "
            "promotion, plus agent-side discarded hypotheses. Three "
            "sources show up here: full crash directories moved out of "
            "`crashes/`, the per-cell rejection ledger (signatures that "
            "never got a CRASH-* directory, only a row), and the agent's "
            "own DISCARDED hypothesis log (leads investigated and dropped "
            "before reaching triage)."
        ),
        "",
    ]
    md.append("## Rejected crash directories")
    md.append("")
    if subdirs:
        # Shared schema with lib/triage.sh's crashes-rejected/INDEX.md and the
        # findings index below: ID | Site | Reason | Report.
        md.append("| ID | Site | Reason | Report |")
        md.append("| :--- | :--- | :--- | :--- |")
        for p in subdirs:
            # Link to the crash's report, not the directory. The source
            # markdown points at the .md so harness parsers and GitHub see
            # the canonical path; bin/render-md rewrites it to the .html
            # sibling in the rendered page, so a click lands on the styled
            # report instead of a bare directory listing. Falls back to the
            # directory only when no report file was pooled.
            report = _report_link_name(p)
            if report:
                target = (
                    f"{urllib.parse.quote(p.name)}/{urllib.parse.quote(report)}"
                )
                link = f"[Link]({target})"
            else:
                link = f"[{p.name}/]({urllib.parse.quote(p.name)}/)"
            site = re.sub(r"\s+", " ", _crash_site(p) or "—").strip()
            reason = re.sub(r"\s+", " ", _crash_reason(p) or "—").strip()
            md.append(
                f"| `{p.name}` | {_md_cell(site)} | {_md_cell(reason)} | {link} |"
            )
    else:
        md.append("_No rejected crash directories pooled._")
    md.append("")
    md.append("## Per-cell rejection ledgers")
    md.append("")
    if rosters:
        for r in rosters:
            md.append(f"### `{r.name}`")
            md.append("")
            try:
                body = r.read_text(encoding="utf-8", errors="replace").strip()
            except OSError:
                body = ""
            md.append(body or "_(empty ledger)_")
            md.append("")
    else:
        md.append("_No per-cell rejection ledgers were pooled._")
    md.append("")
    md.append("## Discarded hypotheses (agent-side)")
    md.append("")
    if discarded_rosters:
        md.append(
            "Leads the agent investigated and closed as non-actionable. "
            "Each link below is one cell's roster."
        )
        md.append("")
        md.append("| Cell | Discarded count | Roster |")
        md.append("| --- | ---: | --- |")
        for r in discarded_rosters:
            count = _count_discarded_roster_rows(r)
            md.append(
                f"| `{r.stem}` | {count} | "
                f"[{r.name}]({urllib.parse.quote(r.name)}) |"
            )
    else:
        md.append("_No DISCARDED hypotheses were pooled._")
    md.append("")
    (rejected_dir / "REJECTED-CRASHES.md").write_text(
        "\n".join(md), encoding="utf-8"
    )


def write_rejected_findings_index(rejected_dir: Path) -> None:
    """Write a markdown list for findings rejected by the validator gate.

    bin/benchmark renders the sibling HTML with bin/render-md, matching the
    rest of the benchmark artifacts and keeping formatting in one renderer.
    """
    rejected_dir = Path(rejected_dir)
    if not rejected_dir.is_dir():
        return
    rows = _rejected_finding_rows(rejected_dir)

    md_lines = [
        "# Rejected findings",
        "",
        (
            "Findings rejected by triage. **Reason** is the validator's "
            "rationale when a recon vote exists, otherwise the "
            "FIND-quality gate's rejection reason (`lib/triage.sh`)."
        ),
        "",
    ]
    if rows:
        md_lines.append("| ID | Site | Reason | Report |")
        md_lines.append("| :--- | :--- | :--- | :--- |")
        for row in rows:
            report = (
                f"[Link]({row['id']}/{row['report']})"
                if row["report"] else "—"
            )
            site = re.sub(r"\s+", " ", row.get("site") or "—").strip()
            reason = re.sub(r"\s+", " ", row["reason"] or "—").strip()
            md_lines.append(
                "| `{id}` | {site} | {reason} | {report} |".format(
                    id=_md_cell(row["id"]),
                    site=_md_cell(site),
                    reason=_md_cell(reason),
                    report=report,
                )
            )
    else:
        md_lines.append("_No rejected findings._")
    md_lines.append("")
    (rejected_dir / "REJECTED-FINDINGS.md").write_text(
        "\n".join(md_lines), encoding="utf-8"
    )


# ── aggregation across a benchmark run's cells ───────────────────────────


def _cell_dirs(bench_dir: Path) -> list[Path]:
    cells = bench_dir / "cells"
    if not cells.is_dir():
        return []
    return sorted(c for c in cells.iterdir() if c.is_dir())


def attribute_clusters(cluster_json: dict, member_conditions: dict) -> dict:
    """Attribute cross-condition clusters to the conditions that hit them.

    Deduplication itself is done by `bin/cluster-crashes` / `bin/cluster-findings`
    (run by bin/benchmark on a pooled directory of every cell's crash /
    finding dirs). This function does NO clustering — it just consumes the
    tool's `--json` output:

      cluster_json       — the `{"clusters": [{id, members:[...]}, ...]}`
                           object emitted by cluster-crashes/-findings.
      member_conditions  — {member-dir-name: condition} written by
                           bin/benchmark when it pooled the dirs.

    A cluster is *novel* to a condition when every member maps to that
    condition. Severity (level / rank / score) is carried straight through
    from the cluster tool — bin/cluster-crashes already reads it out of
    each report, which bin/reachability has scored. Returns:
      {
        "clusters": [{id, conditions, members, size, primitive,
                      severity_level, severity_rank, severity_score}],
        "by_condition": {cond: {unique_clusters, novel_clusters,
                                top_severity_level, top_severity_rank,
                                medium_plus}},
      }
    """
    out_clusters: list[dict] = []
    cond_clusters: dict[str, set] = {}
    for cl in cluster_json.get("clusters", []):
        cid = cl.get("id", "?")
        members = cl.get("members", []) or []
        conds = sorted(
            {member_conditions[m] for m in members if m in member_conditions}
        )
        out_clusters.append(
            {
                "id": cid,
                "conditions": conds,
                "members": members,
                "size": cl.get("size", len(members)),
                "primitive": cl.get("primitive", "") or cl.get("signature", ""),
                "severity_level": cl.get("severity_level") or "—",
                "severity_rank": int(cl.get("severity_rank", 0) or 0),
                "severity_score": float(cl.get("severity_score", 0) or 0),  # CVSS 4.0 score (0–10)
                # {member: {level, rank, score}} from the cluster tool; lets a
                # cross-condition cluster be scored per condition below.
                "member_severity": cl.get("member_severity") or {},
            }
        )
        for cond in conds:
            cond_clusters.setdefault(cond, set()).add(cid)

    def _cond_cluster_severity(c: dict, cond: str) -> tuple[int, int, str]:
        """Severity of *cond*'s own members in cluster *c*.

        A cluster can span conditions: e.g. a harness crash (Medium) and a
        model-direct crash (Low) sharing one crash state cluster together,
        and the cluster's canonical/overall severity is the harness Medium.
        Crediting model-direct with that Medium overstates the baseline — its
        Top severity must reflect the Low crash it actually produced. So score
        each condition by the max severity among ITS members. Falls back to the
        cluster's overall severity when per-member data is absent (older
        cluster JSON without member_severity)."""
        msev = c.get("member_severity") or {}
        best: tuple[int, int, str] | None = None
        for m in c["members"]:
            if member_conditions.get(m) != cond:
                continue
            s = msev.get(m)
            if not s:
                continue
            cand = (
                int(s.get("rank", 0) or 0),
                int(s.get("score", 0) or 0),
                s.get("level", "—") or "—",
            )
            if best is None or cand > best:
                best = cand
        if best is not None:
            return best
        return (c["severity_rank"], c["severity_score"], c["severity_level"])

    by_condition: dict[str, dict] = {}
    for cond, ids in cond_clusters.items():
        cond_cls = [c for c in out_clusters if c["id"] in ids]
        novel = [c["id"] for c in cond_cls if c["conditions"] == [cond]]
        # Score every cluster by THIS condition's own members, then take the
        # highest. Medium+ counts this condition's clusters at rank >= 2
        # (Critical=4, High=3, Medium=2, Low=1, unscored=0).
        cond_sevs = [_cond_cluster_severity(c, cond) for c in cond_cls]
        top = max(cond_sevs, default=(0, 0, "—"))
        by_condition[cond] = {
            "unique_clusters": len(ids),
            "novel_clusters": len(novel),
            "top_severity_level": top[2],
            "top_severity_rank": top[0],
            "medium_plus": sum(1 for s in cond_sevs if s[0] >= 2),
        }
    return {"clusters": out_clusters, "by_condition": by_condition}


def _median(values: list[float]) -> float | int:
    """Median of *values*, narrowed to int when the result is integral.

    Keeps the JSON / ledger clean: a median of [3, 1] reads `2`, not
    `2.0`, while a genuinely fractional median (e.g. [1, 2]) stays float.
    """
    if not values:
        return 0
    m = statistics.median(values)
    return int(m) if float(m).is_integer() else float(m)


def _tokens_for_cell(cell: dict) -> dict:
    """Return a normalized token row for one aggregated benchmark cell."""
    metrics = cell.get("metrics") or {}
    tokens = metrics.get("tokens") or {}
    input_tokens = int(tokens.get("input_tokens", 0) or 0)
    cached_input = int(tokens.get("cached_input_tokens", 0) or 0)
    cache_creation = int(tokens.get("cache_creation_tokens", 0) or 0)
    output_tokens = int(tokens.get("output_tokens", 0) or 0)
    prompt_estimate = int(tokens.get("prompt_estimate_tokens", 0) or 0)
    # `estimated` is explicit for model-direct rows. Harness-side gemini
    # rows often only have prompt_estimate_tokens because agy has no usage
    # surface; treat that as estimated too so reports do not imply measured
    # provider telemetry.
    estimated = bool(tokens.get("estimated")) or (
        prompt_estimate > 0
        and input_tokens == 0
        and cached_input == 0
        and output_tokens == 0
    )
    return {
        "condition": cell.get("condition", "unknown"),
        "replicate": cell.get("replicate"),
        "experiment": cell.get("experiment", ""),
        "cell": cell.get("cell"),
        "status": cell.get("status", "unknown"),
        "wall_seconds": int(cell.get("wall_seconds") or 0),
        "input_tokens": input_tokens,
        "cached_input_tokens": cached_input,
        "cache_creation_tokens": cache_creation,
        "output_tokens": output_tokens,
        "prompt_estimate_tokens": prompt_estimate,
        "cost_usd": str(tokens.get("cost_usd") or ""),
        "cost_source": str(tokens.get("cost_source") or ""),
        "iterations": int(tokens.get("iterations", 0) or 0),
        "estimated": estimated,
    }


def _row_token_source(row: dict) -> str:
    """Where one token row's numbers came from: measured/estimated/unknown.

    `measured`  — parsed from the backend's own usage telemetry.
    `estimated` — derived from character counts (a backend that reports no
                  usage at all, e.g. the gemini CLI).
    `unknown`   — the row carries no token signal of any kind, so it must
                  not be presented as a measurement of zero cost.
    """
    if row.get("estimated"):
        return "estimated"
    if (row.get("input_tokens") or row.get("cached_input_tokens")
            or row.get("output_tokens") or row.get("prompt_estimate_tokens")):
        return "measured"
    return "unknown"


def _token_source(rows: list[dict]) -> str:
    """Source label for a collection of token rows — `mixed` when they differ."""
    if not rows:
        return "none"
    kinds = {_row_token_source(r) for r in rows}
    if len(kinds) == 1:
        return next(iter(kinds))
    return "mixed"


def _sum_cost_usd(rows: list[dict]) -> str:
    total = Decimal("0")
    saw = False
    for row in rows:
        value = row.get("cost_usd")
        if value in (None, ""):
            continue
        try:
            total += Decimal(str(value))
            saw = True
        except Exception:
            continue
    return _decimal_text(total) if saw else ""


def _cost_source(rows: list[dict]) -> str:
    sources = {str(r.get("cost_source") or "").strip()
               for r in rows if str(r.get("cost_source") or "").strip()}
    if not sources:
        return "unknown"
    if len(sources) == 1:
        return next(iter(sources))
    return "mixed"


def aggregate(bench_dir: Path) -> dict:
    """Fold every cell into a per-condition report.

    Each cell directory is expected to hold a cell.json (run metadata,
    written by bin/benchmark) and a metrics.json (written by `harvest`).
    Missing files degrade gracefully so a partial/resumed run still
    aggregates what completed.
    """
    bench_dir = Path(bench_dir)
    run_meta = {}
    run_json = bench_dir / "run.json"
    if run_json.is_file():
        try:
            run_meta = json.loads(run_json.read_text(encoding="utf-8"))
        except ValueError:
            run_meta = {}

    by_condition: dict[str, list[dict]] = {}
    for cell_dir in _cell_dirs(bench_dir):
        cell = {}
        metrics = {}
        cj = cell_dir / "cell.json"
        mj = cell_dir / "metrics.json"
        if cj.is_file():
            try:
                cell = json.loads(cj.read_text(encoding="utf-8"))
            except ValueError:
                cell = {}
        if mj.is_file():
            try:
                metrics = json.loads(mj.read_text(encoding="utf-8"))
            except ValueError:
                metrics = {}
        cond = cell.get("condition") or "unknown"
        merged = {
            "cell": cell_dir.name,
            "condition": cond,
            "replicate": cell.get("replicate"),
            "experiment": cell.get("experiment", ""),
            "status": cell.get("status", "unknown"),
            "run_quality": cell.get("run_quality", "clean"),
            "wall_seconds": cell.get("wall_seconds"),
            "metrics": metrics,
        }
        by_condition.setdefault(cond, []).append(merged)

    # Cross-condition deduplication is done by bin/cluster-crashes /
    # bin/cluster-findings (run by bin/benchmark on a pooled directory);
    # we just read their --json output here. Absent on a partial run.
    def _load(name: str) -> dict:
        p = bench_dir / name
        if p.is_file():
            try:
                return json.loads(p.read_text(encoding="utf-8"))
            except ValueError:
                return {}
        return {}

    members = _load("pool-members.json")
    crash_attr = attribute_clusters(
        _load("clusters-crashes.json"), members.get("crashes", {})
    )
    finding_attr = attribute_clusters(
        _load("clusters-findings.json"), members.get("findings", {})
    )
    crash_by_cond = crash_attr["by_condition"]
    finding_by_cond = finding_attr["by_condition"]

    conditions = []
    token_usage = []
    for cond, cells in sorted(by_condition.items()):
        done = [c for c in cells if c["status"] == "done"]
        # incomplete is written when provider/account limits made the cell
        # unsuitable as a clean benchmark replicate. Older runs used
        # quota_exhausted for the Gemini-only variant; keep that status in
        # the same excluded bucket for regenerate/backward compatibility.
        incomplete = [
            c for c in cells if c["status"] in ("incomplete", "quota_exhausted")
        ]
        provider_limited = [
            c
            for c in incomplete
            if c.get("run_quality") == "provider_limited"
            or c["status"] == "quota_exhausted"
        ]
        quota_exhausted = [c for c in cells if c["status"] == "quota_exhausted"]
        # done cells that recovered from a provider blip mid-run. They ARE
        # counted in the clean totals (the run finished usefully), but surfaced
        # so a reader knows those metrics include a disrupted session.
        provider_recovered = [
            c for c in done if c.get("run_quality") == "provider_recovered"
        ]
        crashes = [c["metrics"].get("confirmed_crashes", 0) for c in done]
        findings = [c["metrics"].get("findings", 0) for c in done]
        rejected_findings = [
            c["metrics"].get("findings_rejected", 0) for c in done
        ]
        rejected_crashes = [
            c["metrics"].get("crashes_rejected", 0) for c in done
        ]
        # DISCARDED hypothesis rows are agent-side rejections — leads
        # the agent investigated and decided weren't actionable. They
        # never reach crashes-rejected/ because triage only sees what
        # the agent escalated. Tracked separately so the column total
        # for "Rejected crashes" only counts actual rejected crashes,
        # not hypotheses the agent walked through and dropped.
        discarded_hypotheses = [
            c["metrics"].get("discarded_hypotheses", 0) for c in done
        ]
        model_refusals = [
            c["metrics"].get("model_refusals", 0) for c in done
        ]
        walls = [c["wall_seconds"] for c in done if c.get("wall_seconds")]
        token_rows = [_tokens_for_cell(c) for c in done]
        token_usage.extend(token_rows)
        cb = crash_by_cond.get(cond, {})
        fb = finding_by_cond.get(cond, {})
        conditions.append(
            {
                "condition": cond,
                "replicates_total": len(cells),
                "replicates_done": len(done),
                "replicates_incomplete": len(incomplete),
                "replicates_provider_limited": len(provider_limited),
                "replicates_provider_recovered": len(provider_recovered),
                "replicates_quota_exhausted": len(quota_exhausted),
                "crashes": crashes,
                "crash_median": _median([float(x) for x in crashes]),
                "crash_total": sum(crashes),
                "rejected_crash_total": sum(rejected_crashes),
                "discarded_hypothesis_total": sum(discarded_hypotheses),
                "rejected_finding_total": sum(rejected_findings),
                "model_refusal_total": sum(model_refusals),
                "finding_total": sum(findings),
                "unique_crash_clusters": cb.get("unique_clusters", 0),
                "novel_crash_clusters": cb.get("novel_clusters", 0),
                "top_severity_level": cb.get("top_severity_level", "—"),
                "top_severity_rank": cb.get("top_severity_rank", 0),
                "medium_plus_bugs": cb.get("medium_plus", 0),
                "unique_finding_clusters": fb.get("unique_clusters", 0),
                "wall_median": _median([float(x) for x in walls]),
                "input_tokens_total": sum(r["input_tokens"] for r in token_rows),
                "cached_input_tokens_total": sum(
                    r["cached_input_tokens"] for r in token_rows
                ),
                "cache_creation_tokens_total": sum(
                    r["cache_creation_tokens"] for r in token_rows
                ),
                "output_tokens_total": sum(r["output_tokens"] for r in token_rows),
                "prompt_estimate_tokens_total": sum(
                    r["prompt_estimate_tokens"] for r in token_rows
                ),
                "cost_usd_total": _sum_cost_usd(token_rows),
                "cost_source": _cost_source(token_rows),
                "token_source": _token_source(token_rows),
                "cells": cells,
            }
        )

    report = {
        "bench_dir": str(bench_dir),
        "run": run_meta,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "conditions": conditions,
        "crash_clusters": crash_attr["clusters"],
        "finding_clusters": finding_attr["clusters"],
        "token_usage": token_usage,
    }

    # When the target ships a ground-truth manifest (the canary, or any
    # future labelled target), score the pooled crashes against it so the
    # report carries measured precision/recall, not just counts. Reuse the
    # member map aggregate already loaded (bench_dir/pool-members.json) and
    # pass every condition so a zero-crash condition still gets a 0% row.
    #
    # A manifest file that exists but is broken surfaces as an explicit
    # ground_truth_error — for a calibration target a silent "no block" would
    # hide a broken oracle. A valid manifest is scored only once the pool has
    # been built (bin/benchmark builds it before the ledger step); on a
    # partial/manual aggregate the block is simply absent ("not scored")
    # rather than a misleading 0% recall.
    pool_crashes = bench_dir / "pool" / "crashes"
    gt_path = ground_truth_path_for(run_meta.get("target", ""))
    if gt_path.is_file():
        manifest = load_ground_truth(gt_path)
        errs = (["manifest is not a JSON object"] if manifest is None
                else manifest_errors(manifest))
        if errs:
            report["ground_truth_error"] = errs
        elif pool_crashes.is_dir():
            report["ground_truth_scoring"] = score_ground_truth(
                pool_crashes,
                manifest,
                members.get("crashes", {}),
                conditions=[c["condition"] for c in conditions],
            )

    return report


# ── pooling for cross-condition clustering ───────────────────────────────


def build_pool(bench_dir: Path, pool_name: str = "pool") -> dict:
    """Copy every cell's confirmed crash + finding dirs into one pool.

    bin/benchmark then runs the SAME post-processing the harness uses —
    bin/reachability (severity), bin/export-repro (reproducer bundle) and
    bin/cluster-crashes / bin/cluster-findings (dedup) — over this one
    pool, so every condition is scored on an identical yardstick.

    Dirs are renamed CRASH-<NNNN> / FIND-<NNNN> (the tools glob those
    prefixes) and a member→condition map is written to
    bench_dir/pool-members.json for attribute_clusters().

    Each crash/finding is copied exactly once; the member map is what
    records its condition, so there is no second tree to keep in sync.

    Returns the member map. Idempotent: an existing pool dir is rebuilt.
    pool_name lets the caller build into a staging dir (e.g. ".pool.staging")
    so bin/benchmark can swap a fully-built tree into pool/ atomically instead
    of tearing pool/ down in place.
    """
    import shutil

    bench_dir = Path(bench_dir)
    pool = bench_dir / pool_name
    if pool.exists():
        shutil.rmtree(pool)
    (pool / "crashes").mkdir(parents=True)
    (pool / "crashes-rejected").mkdir(parents=True)
    (pool / "findings").mkdir(parents=True)
    (pool / "findings-rejected").mkdir(parents=True)

    members: dict[str, dict] = {
        "crashes": {},
        "crashes-rejected": {},
        "findings": {},
        "findings-rejected": {},
    }
    crash_n = 0
    rejected_crash_n = 0
    find_n = 0
    rejected_find_n = 0
    for cell_dir in _cell_dirs(bench_dir):
        cj = cell_dir / "cell.json"
        mj = cell_dir / "metrics.json"
        if not cj.is_file():
            continue
        try:
            cell = json.loads(cj.read_text(encoding="utf-8"))
        except ValueError:
            continue
        # Keep pooled cluster counts consistent with the headline totals:
        # aggregate() counts only status=done cells for confirmed findings /
        # crashes, so the cross-condition pool must not import artifacts from
        # failed or quota-shortened cells.
        if cell.get("status") != "done":
            continue
        cond = cell.get("condition") or "unknown"
        rd = Path(cell.get("results_dir") or "")
        if not rd.is_dir():
            continue
        metrics = {}
        if mj.is_file():
            try:
                metrics = json.loads(mj.read_text(encoding="utf-8"))
            except ValueError:
                metrics = {}
        # Only confirmed crashes are pooled, so the deduplicated count
        # stays consistent with the harvested confirmed_crashes metric.
        for name in metrics.get("crash_dirs", []):
            src = rd / "crashes" / name
            if not src.is_dir():
                continue
            crash_n += 1
            dst_name = f"CRASH-{crash_n:04d}"
            dst = pool / "crashes" / dst_name
            shutil.copytree(src, dst)
            _scrub_pooled_tree(dst)
            members["crashes"][dst_name] = cond
        findings_dir = rd / "findings"
        if findings_dir.is_dir():
            for src in sorted(findings_dir.iterdir()):
                if not src.is_dir() or not src.name.startswith("FIND-"):
                    continue
                find_n += 1
                dst_name = f"FIND-{find_n:04d}"
                dst = pool / "findings" / dst_name
                shutil.copytree(src, dst)
                _scrub_pooled_tree(dst)
                _link_pool_recon_ids(dst, rd)
                members["findings"][dst_name] = cond
        rejected_dir = rd / "findings-rejected"
        if rejected_dir.is_dir():
            for src in sorted(rejected_dir.iterdir()):
                if not src.is_dir() or not src.name.startswith("FIND-"):
                    continue
                rejected_find_n += 1
                dst_name = f"FIND-REJECTED-{rejected_find_n:04d}"
                dst = pool / "findings-rejected" / dst_name
                shutil.copytree(src, dst)
                _scrub_pooled_tree(dst)
                _link_pool_recon_ids(dst, rd)
                members["findings-rejected"][dst_name] = cond
        rejected_crashes_dir = rd / "crashes-rejected"
        if rejected_crashes_dir.is_dir():
            for src in sorted(rejected_crashes_dir.iterdir()):
                if not src.is_dir() or not src.name.startswith("CRASH-"):
                    continue
                rejected_crash_n += 1
                dst_name = f"CRASH-REJECTED-{rejected_crash_n:04d}"
                dst = pool / "crashes-rejected" / dst_name
                shutil.copytree(src, dst)
                _scrub_pooled_tree(dst)
                members["crashes-rejected"][dst_name] = cond
            # The per-cell INDEX.md is the human-readable rejection ledger
            # (rows for triage-rejected crash signatures that did NOT get a
            # full CRASH-* dir copied above — runtime-diagnostic dedups,
            # caller-misuse classes, etc.). Copy it alongside so the
            # reviewer can see *why* a cell counted N rejections even when
            # zero rejection dirs exist.
            index_md = rejected_crashes_dir / "INDEX.md"
            if index_md.is_file():
                dst = (pool / "crashes-rejected"
                       / f"INDEX-{cond}-{cell_dir.name}.md")
                shutil.copy2(index_md, dst)
        # DISCARDED hypotheses live in state/hypotheses.jsonl (one row
        # per investigated-then-dropped lead). Surface them in the
        # rejected-crashes pool as a per-cell markdown roster so the
        # reviewer can audit *why* the agent dropped each lead, not
        # just the count. The roster is also the link target for the
        # bumped rejected-crashes column total.
        discarded_md = _format_discarded_hypotheses_roster(
            rd, cond, cell_dir.name
        )
        if discarded_md:
            dst = (pool / "crashes-rejected"
                   / f"DISCARDED-{cond}-{cell_dir.name}.md")
            dst.write_text(discarded_md, encoding="utf-8")

    write_rejected_findings_index(pool / "findings-rejected")
    write_rejected_crashes_index(pool / "crashes-rejected")

    (bench_dir / "pool-members.json").write_text(
        json.dumps(members, indent=2) + "\n", encoding="utf-8"
    )
    return members


# ── ledger rendering ─────────────────────────────────────────────────────

def _severity_cell(level: str | None) -> str:
    """Render a severity level as a bare word for a table cell.

    The cell is just the word — no emoji prefix. The HTML renderer
    (bin/render-md) detects a bare `Critical`/`High`/`Medium`/`Low`/`—`
    cell and wraps it in a colour-coded pill badge; emitting only the
    word keeps the markdown clean in a terminal and lets that decoration
    apply in the browser.
    """
    return level or "—"


def _condition_label(condition: str, backend: str,
                     model: str = "") -> str:
    """Display label for a benchmark condition in the rendered page.

    Internal condition tokens stay stable — `harness` and `model-direct`
    are what `--conditions` accepts and what cell.json records, and they
    must not depend on the backend. The page shows product-facing names:
    the harness is **tokenfuzz**, and the bare baseline is named after
    what produced it — the model when known (`gpt-5.5-direct`), else the
    backend (`codex-direct`) — so a reader sees exactly what ran the row.
    """
    if condition == "harness":
        return "tokenfuzz"
    if condition == "model-direct":
        name = (model or "").strip() or (backend or "").strip()
        return f"{name}-direct" if name and name != "?" else "model-direct"
    return condition


def _hash_text(value: object) -> str:
    """Return a recorded revision string, or empty for missing sentinels."""
    text = str(value or "").strip()
    if not text or text in {"?", "no-vcs", "norev", "unknown"}:
        return ""
    return text


def _hash_suffix(value: object, *, stacked: bool = False) -> str:
    """Visible short-revision suffix for benchmark identity cells."""
    text = _hash_text(value)
    if not text:
        return ""
    short = text[:7]
    return f"<br>`{short}`" if stacked else f" (`{short}`)"


def _target_cell(target: object, target_sha: object, *,
                 stacked: bool = False) -> str:
    """Target table cell with the audited target revision appended."""
    name = str(target or "?")
    return f"`{name}`{_hash_suffix(target_sha, stacked=stacked)}"


def _tokenfuzz_sha(run: dict) -> str:
    """Full TokenFuzz revision when present; old reports fall back to harness_sha."""
    return _hash_text(run.get("tokenfuzz_sha")) or _hash_text(run.get("harness_sha"))


def _tokenfuzz_cell(tokenfuzz_sha: object, *, stacked: bool = False) -> str:
    """Render the TokenFuzz condition label with the repo revision appended."""
    return f"`tokenfuzz`{_hash_suffix(tokenfuzz_sha, stacked=stacked)}"


def _condition_cell(condition: str, backend: str, model: str = "") -> str:
    """Condition table cell label."""
    return f"`{_condition_label(condition, backend, model)}`"


def _fmt_tokens(value: object) -> str:
    """Compact token count for ledger tables: 1,234 / 47k / 2.1M.

    Provider token counts run into the millions; a raw `1,930,544` is
    hard to scan and compare at a glance. Exact figures below 10k are
    kept (they are still short); larger ones collapse to `k` (thousands)
    or `M` (millions) so a column of costs reads cleanly.
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        return "0"
    if n < 10_000:
        return f"{n:,}"
    if n < 1_000_000:
        return f"{round(n / 1000):,}k"
    return f"{n / 1_000_000:.1f}M"


def _fmt_input_cell(agg: dict) -> str:
    """Input column for the cross-backend rollup, with an estimated fallback.

    Backends that surface no usage telemetry (the gemini Antigravity CLI)
    sum to 0 measured input even when work happened. The harness still
    derives a character-count `prompt_estimate` per turn — fall back to
    that sum so a Gemini cell isn't scored as zero-cost. A `~` prefix
    flags the cell as estimated so it isn't mistaken for measured.
    """
    measured = int(agg.get("input_tokens_total") or 0)
    if measured > 0:
        return _fmt_tokens(measured)
    estimate = int(agg.get("prompt_estimate_tokens_total") or 0)
    if estimate > 0:
        return f"~{_fmt_tokens(estimate)}"
    return _fmt_tokens(measured)


def _fmt_output_cell(agg: dict) -> str:
    """Output column for the cross-backend rollup.

    When the backend reports no measured output (gemini) and we only
    have an input-side prompt estimate, render an em dash rather than
    `0` — there is no output estimate, and printing `0` falsely implies
    the model produced nothing.
    """
    measured = int(agg.get("output_tokens_total") or 0)
    if measured > 0:
        return _fmt_tokens(measured)
    if int(agg.get("prompt_estimate_tokens_total") or 0) > 0:
        return "—"
    return _fmt_tokens(measured)


def _fmt_cost_cell(agg: dict) -> str:
    return _fmt_usd(
        agg.get("cost_usd_total"),
        estimated=str(agg.get("token_source") or "") == "estimated",
    )


def _fmt_cost_compact_cell(agg: dict) -> str:
    try:
        dec = Decimal(str(agg.get("cost_usd_total")))
    except Exception:
        return "—"
    prefix = "~" if str(agg.get("token_source") or "") == "estimated" else ""
    amount = dec.quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    return f"{prefix}${amount:,}"


def _fmt_hours(seconds: object) -> str:
    """Wall-clock duration as decimal hours: 5400s -> `1.50h`.

    The benchmark's whole premise is a fixed per-cell time budget, which
    operators set in hours; decimal hours (not `90m` or `1h30m`) keep the
    Wall column on the same unit the budget is reasoned about in. A
    non-positive or unparseable duration renders as an em dash.
    """
    try:
        s = float(seconds)
    except (TypeError, ValueError):
        return "—"
    if s <= 0:
        return "—"
    return f"{s / 3600:.2f}h"


def _reproducer_link(bench_dir: Path, members: list[str]) -> str:
    """Markdown link to a cluster's representative reproducer.

    Prefers the rendered REPORT.html — bin/export-repro + bin/render-md
    produce a REPORT.md / REPORT.html / reproduce.sh bundle for every
    pooled crash — and falls back to the crash directory so the link is
    always live even if bundling was skipped (e.g. a --dry-run).
    """
    if not members:
        return "—"
    crash_dir = bench_dir / "pool" / "crashes" / members[0]
    html = crash_dir / "REPORT.html"
    if html.is_file():
        return _md_link("REPORT.html", html)
    return _md_link(members[0], crash_dir)


def _bug_link(bench_dir: Path, cid: str, members: list[str]) -> str:
    """Link a cluster id to its representative crash directory.

    The crash dir holds the full evidence — sanitizer output, input,
    harness, reachability score — so a reviewer can audit the bug from
    the id alone. Falls back to a plain code span if no member is known.
    """
    if members:
        return _md_link(f"`{cid}`", bench_dir / "pool" / "crashes" / members[0])
    return f"`{cid}`"


def _verdict_line(clusters: list[dict], backend: str) -> str:
    """One sentence naming the strongest bug and the condition that found it.

    *clusters* must already be sorted strongest-severity first; the
    per-condition spread is the Scoreboard immediately below.
    """
    if not clusters:
        return ("No AddressSanitizer-confirmed crashes this run — there is "
                "nothing to compare. Choose a target the harness can crack, "
                "or raise the per-cell budget.")
    top = clusters[0]
    by = " and ".join(
        _condition_label(c, backend) for c in top.get("conditions", [])
    ) or "an unattributed condition"
    if top.get("severity_rank", 0) >= 2:
        return (f"The strongest bug this run is **{top['severity_level']}** "
                f"`{top['id']}`, severity score {top['severity_score']}, "
                f"found by **{by}**.")
    return (f"No Medium-or-higher bug surfaced this run; the strongest crash "
            f"is **{top.get('severity_level', '—')}** `{top['id']}`, found "
            f"by **{by}**.")


def _fmt_ratio(value) -> str:
    """Render a precision/recall ratio as a percent, or — when undefined."""
    if value is None:
        return "—"
    return f"{round(float(value) * 100):d}%"


def _render_ground_truth(scoring: dict | None,
                         error: list | None = None) -> list[str]:
    """Render the precision/recall block for a ground-truth target.

    Empty when the run has no manifest, so non-canary runs are unchanged.
    A malformed manifest renders an explicit error block instead of a
    misleading score.
    """
    if error:
        lines = ["### Ground truth", "",
                 "> ⚠️ **Ground-truth manifest is invalid — not scored.** "
                 "Fix the answer key, then re-run the ledger step:", ""]
        lines += [f"> - {e}" for e in error]
        lines.append("")
        return lines
    if not scoring:
        return []
    overall = scoring.get("overall", {})
    by_cond = scoring.get("by_condition", {})
    lines = ["### Ground truth (precision / recall)", ""]
    lines.append(
        "| Condition | Recall | Detected | Missed | Precision "
        "| Confirmed | False positives | Traps fired |"
    )
    lines.append("| --- | --: | --: | --- | --: | --: | --: | --- |")

    def row(label: str, s: dict) -> str:
        missed = ", ".join(s.get("missed", [])) or "—"
        traps = ", ".join(s.get("false_positive_traps_fired", [])) or "—"
        return (
            f"| {label} "
            f"| {_fmt_ratio(s.get('recall'))} "
            f"| {len(s.get('detected', []))}/{s.get('real_total', 0)} "
            f"| {missed} "
            f"| {_fmt_ratio(s.get('precision'))} "
            f"| {s.get('confirmed_crashes', 0)} "
            f"| {s.get('false_positive_crashes', 0)} "
            f"| {traps} |"
        )

    for cond in sorted(by_cond):
        lines.append(row(f"`{cond}`", by_cond[cond]))
    lines.append(row("**overall**", overall))
    lines.append("")
    lines.append(
        "> **How to read this.** Scored against the target's "
        "`ground-truth.json` answer key. **Recall** is the share of planted "
        "real bugs confirmed at the crash site by a runtime sanitizer "
        "artifact; **Precision** is the share of confirmed crashes that are "
        "real planted bugs — a fired false-positive trap, an unexpected crash, "
        "or a confirmed crash with no runtime artifact to attribute "
        "(unattributed prose) all count against it. These are the labelled "
        "numbers the triage gate thresholds are tuned to."
    )
    lines.append("")
    return lines


def render_section(report: dict) -> str:
    """One append-only markdown section for a single benchmark run.

    Three blocks, in order of what a reader needs first: a one-line
    **Verdict**, a compact **Scoreboard**, and a severity-sorted
    **Bugs by severity** table that puts the strongest bug on top.
    """
    run = report.get("run", {})
    runid = run.get("runid", "?")
    target = run.get("target", "?")
    backend = run.get("backend", "?")
    budget = run.get("budget_wall", "?")
    replicates = run.get("replicates", "?")
    harness_agents = run.get("harness_agents")
    harness_agents_label = (
        str(harness_agents) if harness_agents not in (None, "") else "audit default"
    )
    target_sha = run.get("target_sha", "?")
    tokenfuzz_sha = _tokenfuzz_sha(run)
    bench_dir = Path(report.get("bench_dir", ""))
    conditions = report.get("conditions", [])
    # Strongest severity first; ties broken by score, then id for stability.
    clusters = sorted(
        report.get("crash_clusters", []),
        key=lambda c: (-c.get("severity_rank", 0), -c.get("severity_score", 0),
                       c.get("id", "")),
    )

    lines: list[str] = []
    lines.append(f"## Benchmark run `{runid}`")
    lines.append("")
    lines.append(
        f"- **Target** {_target_cell(target, target_sha)}  ·  "
        f"**Backend** `{backend}`  ·  "
        f"**TokenFuzz** {_tokenfuzz_cell(tokenfuzz_sha)}"
    )
    lines.append(
        f"- **Budget** {budget}s/cell  ·  "
        f"**Replicates** {replicates}/condition  ·  "
        f"**Harness agents** {harness_agents_label}  ·  "
        "**Direct agents** 1  ·  "
        f"**Generated** {report.get('generated_at', '?')}"
    )
    lines.append("")

    # ── Verdict ──────────────────────────────────────────────────────────
    lines.append("### Verdict")
    lines.append("")
    lines.append(_verdict_line(clusters, backend))
    lines.append("")

    # ── Scoreboard ───────────────────────────────────────────────────────
    # Every count links to the artifact a reviewer would open to verify it:
    # each condition's own per-condition crash/finding tree and cluster
    # reports. crashes_dir stays the combined pool — that is where the
    # reproducer bundles live (see the Bugs-by-severity footer).
    crashes_dir = bench_dir / "pool" / "crashes"
    lines.append("### Scoreboard")
    lines.append("")
    # Column order: identity, then how the run was set up (how many times
    # it ran, how long each took), then results grouped by evidence type —
    # findings (raw, deduplicated) followed by crashes (raw, deduplicated,
    # then the two severity columns). Severity is scored only for crashes,
    # so `Medium+ crashes` and `Top severity` close the crash group rather
    # than floating as if they applied to findings too.
    lines.append(
        "| Condition | Replicates | Wall (h) "
        "| Rejected findings | Findings | Unique findings "
        "| Rejected crashes | Crashes | Unique crashes "
        "| Medium+ crashes | Top severity |"
    )
    lines.append(
        "| --- | --: | --: | --: | --: | --: | --: | --: | --: | --: | :--: |"
    )
    for c in sorted(conditions,
                    key=lambda c: (-c.get("top_severity_rank", 0),
                                   c["condition"])):
        cond_crashes = _condition_pool_dir(bench_dir, c["condition"],
                                           "crashes")
        cond_findings = _condition_pool_dir(bench_dir, c["condition"],
                                            "findings")
        cond_rejected_findings = _condition_pool_dir(
            bench_dir, c["condition"], "findings-rejected"
        )
        cond_rejected_crashes = _condition_pool_dir(
            bench_dir, c["condition"], "crashes-rejected"
        )
        lines.append(
            "| {cond} | {rep} | {wall} | {rfi} | {fi} | {uf} "
            "| {rcr} | {cr} | {uc} | {mp} | {sev} |".format(
                cond=_condition_cell(c["condition"], backend),
                rep=(
                    "{d}/{t}".format(d=c.get("replicates_done", 0),
                                     t=c.get("replicates_total", 0))
                    + (
                        " ({r}r)".format(r=c.get("replicates_provider_recovered", 0))
                        if int(c.get("replicates_provider_recovered", 0) or 0) > 0
                        else ""
                    )
                    + (
                        " ({p}p)".format(p=c.get("replicates_provider_limited", 0))
                        if int(c.get("replicates_provider_limited", 0) or 0) > 0
                        else ""
                    )
                    + (
                        " ({q}q)".format(q=c.get("replicates_quota_exhausted", 0))
                        if int(c.get("replicates_quota_exhausted", 0) or 0) > 0
                        else ""
                    )
                ),
                wall=_fmt_hours(c.get("wall_median")),
                rfi=_artifact_report_link(
                    c.get("rejected_finding_total", 0),
                    cond_rejected_findings,
                    "REJECTED-FINDINGS",
                ),
                fi=_md_link(c.get("finding_total", 0), cond_findings),
                uf=_cluster_report_link(c.get("unique_finding_clusters", 0),
                                        cond_findings, "FINDING-CLUSTERS"),
                rcr=_artifact_report_link(
                    c.get("rejected_crash_total", 0),
                    cond_rejected_crashes,
                    "REJECTED-CRASHES",
                ),
                cr=_md_link(c.get("crash_total", 0), cond_crashes),
                uc=_cluster_report_link(c.get("unique_crash_clusters", 0),
                                        cond_crashes, "CRASH-CLUSTERS"),
                mp=c.get("medium_plus_bugs", 0),
                sev=_severity_cell(c.get("top_severity_level", "—")),
            )
        )
    lines.append("")
    baseline_label = _condition_label("model-direct", backend)
    lines.append(
        "> **How to read this.** Each condition ran **Replicates** times "
        "under the same per-cell time budget; **Wall (h)** is the median "
        "hours a cell actually spent. The result columns are grouped by "
        "evidence type. **Rejected findings** are FIND reports that failed "
        "the independent validator gate and link to a table showing the "
        "reachability / guards / primitive booleans. **Findings** are "
        "reported issues that survived triage but carry no on-disk crash; "
        "**Crashes** counts only crash "
        "directories with real AddressSanitizer output on disk — an agent "
        "claiming a crash in prose never counts. **Unique findings** and "
        "**Unique crashes** are those counts after `bin/cluster-crashes` "
        "merges duplicate signatures. **Medium+ crashes** and **Top "
        "severity** come from `bin/reachability`, which scores every crash "
        "of both conditions on one scale — severity is a crash-only metric. "
        f"`{baseline_label}` is a bare \"find the vulnerabilities\" prompt "
        "with no harness around it, so a large raw crash count there is "
        "mostly repeated noise. `tokenfuzz` is the audit harness — triage, "
        "deduplication, severity scoring, and reproducer bundles included — "
        "and the severity columns are what that extra work buys."
    )
    lines.append("")

    # ── Ground truth (precision / recall) ────────────────────────────────
    lines.extend(_render_ground_truth(report.get("ground_truth_scoring"),
                                      report.get("ground_truth_error")))

    # ── Token usage ──────────────────────────────────────────────────────
    token_rows = sorted(
        report.get("token_usage", []),
        key=lambda r: (
            str(r.get("condition", "")),
            int(r.get("replicate") or 0),
            str(r.get("experiment", "")),
        ),
    )
    if token_rows:
        # Per-condition aggregates carry the *_total token fields and the
        # rolled-up token_source; the totals row reads straight from them.
        cond_agg = {c["condition"]: c for c in conditions}
        lines.append("### Token usage")
        lines.append("")
        lines.append(
            "| Condition | Rep | Experiment | Wall (h) | Source "
            "| Input | Cache write | Cached input | Output | Prompt est. | Cost |"
        )
        lines.append(
            "| --- | --: | --- | --: | --- | --: | --: | --: | --: | --: | --: |"
        )
        by_cond: dict[str, list[dict]] = {}
        for row in token_rows:
            by_cond.setdefault(str(row.get("condition", "?")), []).append(row)
        for cond, rows in by_cond.items():
            label = _condition_cell(cond, backend)
            for row in rows:
                exp = row.get("experiment") or row.get("cell") or "?"
                cell = row.get("cell")
                # The experiment links to its cell directory — cell.json,
                # metrics.json, the agent workspace — so the row is auditable.
                exp_cell = (_md_link(f"`{exp}`", bench_dir / "cells" / cell)
                            if cell else f"`{exp}`")
                lines.append(
                    "| {cond} | {rep} | {exp} | {wall} | {source} "
                    "| {inp} | {create} | {cached} | {out} | {prompt} | {cost} |".format(
                        cond=label,
                        rep=row.get("replicate") or "—",
                        exp=exp_cell,
                        wall=_fmt_hours(row.get("wall_seconds")),
                        source=_row_token_source(row),
                        inp=_fmt_tokens(row.get("input_tokens")),
                        create=_fmt_tokens(row.get("cache_creation_tokens")),
                        cached=_fmt_tokens(row.get("cached_input_tokens")),
                        out=_fmt_tokens(row.get("output_tokens")),
                        prompt=_fmt_tokens(row.get("prompt_estimate_tokens")),
                        cost=_fmt_usd(
                            row.get("cost_usd"),
                            estimated=bool(row.get("estimated")),
                        ),
                    )
                )
            # Per-condition totals — the line an operator compares cost on.
            agg = cond_agg.get(cond, {})
            n = len(rows)
            lines.append(
                "| **{cond}** | — | **{n} cell{s}** | **{wall}** | {source} "
                "| **{inp}** | **{create}** | **{cached}** | **{out}** "
                "| **{prompt}** | **{cost}** |".format(
                    cond=label,
                    n=n,
                    s="" if n == 1 else "s",
                    wall=_fmt_hours(
                        sum(r.get("wall_seconds", 0) or 0 for r in rows)
                    ),
                    source=agg.get("token_source") or _token_source(rows),
                    inp=_fmt_tokens(agg.get("input_tokens_total")),
                    create=_fmt_tokens(agg.get("cache_creation_tokens_total")),
                    cached=_fmt_tokens(agg.get("cached_input_tokens_total")),
                    out=_fmt_tokens(agg.get("output_tokens_total")),
                    prompt=_fmt_tokens(agg.get("prompt_estimate_tokens_total")),
                    cost=_fmt_cost_cell(agg),
                )
            )
        lines.append("")
        lines.append(
            "> Each row is one cell. The **bold** row per condition is "
            "its total — the figure to compare cost on. `k` = thousands, "
            "`M` = millions."
        )
        lines.append(">")
        lines.append(
            "> - **Input** — tokens processed at the full input rate "
            "(≥100% of base). Claude: fresh `input` + `cache_creation` "
            "(cache writes at 125%). Codex/Gemini: SDK `input` minus "
            "cache hits. One number meaning \"non-cache-hit input the "
            "model paid full freight on,\" comparable across backends."
        )
        lines.append(
            "> - **Cached input** — cache READS only, billed at ~10% "
            "of base. Large numbers mean the harness is reusing a stable "
            "prefix — that's what keeps cost down."
        )
        lines.append(
            "> - **Cost** — USD-equivalent token cost at public provider "
            "rates: fresh input + cache writes + cache reads + output. "
            "Codex rows use OpenAI API-equivalent dollars, including "
            "GPT-5.5 long-context pricing when a request exceeds 272k "
            "input tokens; the Codex product also reports credits."
        )
        lines.append(
            "> - **Output** — tokens the model emitted (responses + "
            "tool-call payloads). Billed at the full output rate."
        )
        lines.append(
            "> - **Prompt est.** — character-count estimate of the "
            "prompt side. Populated only when a backend exposes no "
            "usage data (Antigravity CLI; `USE_GEMINI_CLI=1` produces "
            "measured numbers instead). Sanity check for cells whose "
            "**Input** reads `~<n>`."
        )
        lines.append(
            "> - **Source** — where the numbers came from: `measured` "
            "(backend telemetry), `estimated` (character counts), "
            "`unknown` (no usage signal), `mixed` across cells."
        )
        lines.append("")

    # ── Bugs by severity ─────────────────────────────────────────────────
    if clusters:
        lines.append("### Bugs by severity")
        lines.append("")
        lines.append(
            "| Severity | Score | Bug | Type | Found by | Crashes | Reproducer |"
        )
        lines.append("| :--- | --: | --- | --- | --- | --: | --- |")
        for cl in clusters:
            members = cl.get("members") or []
            lines.append(
                "| {sev} | {score} | {bug} | {typ} | {by} | {n} | {repro} |"
                .format(
                    sev=_severity_cell(cl.get("severity_level", "—")),
                    score=cl.get("severity_score") or "—",
                    bug=_bug_link(bench_dir, cl.get("id", "?"), members),
                    typ=cl.get("primitive", "") or "?",
                    by=", ".join(
                        _condition_label(x, backend)
                        for x in cl.get("conditions", [])
                    ) or "?",
                    n=cl.get("size", 0),
                    repro=_reproducer_link(bench_dir, members),
                )
            )
        lines.append("")
        lines.append(
            "The **Bug** id links to the crash directory; **Reproducer** "
            "links its rendered report. Each bug is bundled as `REPORT.md`, "
            "`REPORT.html`, and `reproduce.sh` under "
            f"{_md_link('pool/crashes/', crashes_dir)}."
        )
        lines.append("")

    lines.append("---")
    lines.append("")
    return "\n".join(lines)


# ── cross-backend crosstab ───────────────────────────────────────────────


def _benchmark_roots(bench_root: Path) -> list[Path]:
    """Per-backend benchmark roots under the shared *bench_root*.

    `bin/benchmark` places each backend's state in its own subdirectory
    (`output/benchmark/<backend>/`). A child counts as a backend root when
    it holds at least one timestamped run directory with a `report.json` —
    a structural test, so the layout is detected rather than name-matched.
    """
    if not bench_root.is_dir():
        return []
    roots: list[Path] = []
    for child in sorted(bench_root.iterdir()):
        if not child.is_dir():
            continue
        if any((d / "report.json").is_file()
               for d in child.iterdir() if d.is_dir()):
            roots.append(child)
    return roots


def _latest_report(bench_root: Path) -> dict | None:
    """The most recent run's report.json under a benchmark root, or None.

    Run directories are timestamp-named (`YYYYMMDD-HHMMSS`), so a plain
    name sort puts the newest last.
    """
    candidates = sorted(
        (d for d in bench_root.iterdir()
         if d.is_dir() and (d / "report.json").is_file()),
        key=lambda d: d.name,
    )
    for run_dir in reversed(candidates):
        try:
            return json.loads((run_dir / "report.json").read_text("utf-8"))
        except (OSError, ValueError):
            continue
    return None


def _reports_by_run_target(bench_root: Path) -> list[dict]:
    """Every report.json under a backend benchmark root.

    The crosstab is append-style evidence, not a "latest only" dashboard:
    each row is keyed by backend, run, target, and condition. Keeping every
    run visible prevents a new single-condition benchmark from hiding an
    earlier run for the same backend/target.
    """
    reports: list[tuple[str, str, dict]] = []
    candidates = sorted(
        (d for d in bench_root.iterdir()
         if d.is_dir() and (d / "report.json").is_file()),
        key=lambda d: d.name,
    )
    for run_dir in candidates:
        try:
            report = json.loads((run_dir / "report.json").read_text("utf-8"))
        except (OSError, ValueError):
            continue
        run = report.get("run", {})
        target = str(run.get("target") or "?")
        runid = str(run.get("runid") or run_dir.name)
        reports.append((target, runid, report))
    return [report for _, _, report in sorted(reports)]


def _crosstab_count(value: object, pool_dir: Path | None,
                    basename: str | None = None) -> str:
    """A crosstab count cell — hyperlinked to its artifact when on disk.

    With *basename* the count links to the rendered cluster report
    (`<basename>.html`/`.md`) inside *pool_dir*; without it, straight to
    *pool_dir*. When the pool is not on disk (an older run, or a run
    whose artifacts were pruned) the bare number is shown.
    """
    if pool_dir is None or not pool_dir.is_dir():
        return str(value)
    if basename is None:
        return _md_link(value, pool_dir)
    return _cluster_report_link(value, pool_dir, basename)


def _run_cell(runid: object) -> str:
    """Render the Run identity cell."""
    return f"`{runid}`"


def crosstab(bench_root: Path) -> str:
    """Render benchmark results for each backend/run/target/condition key."""
    bench_root = Path(bench_root)
    rows: list[dict] = []
    for root in _benchmark_roots(bench_root):
        ledger = root / "benchmark-results.html"
        if not ledger.exists():
            ledger = root / "benchmark-results.md"
        for report in _reports_by_run_target(root):
            bench_dir = report.get("bench_dir")
            rows.append({
                "run": report.get("run", {}),
                "ledger": ledger if ledger.exists() else None,
                "conditions": report.get("conditions", []),
                "bench_dir": Path(bench_dir) if bench_dir else None,
            })

    lines: list[str] = []
    lines.append("# Aggregated benchmark results")
    lines.append("")
    lines.append(
        "Aggregated comparison: every backend/run/target/condition result, "
        "folded into one table. Regenerated by "
        "`bin/benchmark` as cells complete and at the end of each run."
    )
    lines.append("")
    lines.append(
        f"_Generated "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}._"
    )
    lines.append("")
    if not rows:
        lines.append("_No benchmark runs found yet._")
        lines.append("")
        return "\n".join(lines)

    lines.append(
        "| Target | Backend | Condition | Run | Wall (h) | Replicates "
        "| Rejected findings | Findings | Unique findings "
        "| Rejected crashes | Crashes | Unique crashes "
        "| Medium+ crashes | Top severity "
        "| Input | Output | Cost |"
    )
    lines.append(
        "| --- | --- | --- | --- | --: | --: "
        "| --: | --: | --: "
        "| --: | --: | --: "
        "| --: | :--: "
        "| --: | --: | --: |"
    )

    # Flatten (run × condition) so each emitted row is one
    # target/backend/condition/run tuple. Sorted by (target, backend,
    # condition, run) — target-first so all rows for one project sit
    # together, then split by backend, then by condition (tokenfuzz vs
    # baseline), with reruns of the same cell adjacent. Empty
    # `conditions` lists still surface — they become a single placeholder
    # row carrying just the run's identity so partially-failed runs are
    # visible in the rollup.
    flat_rows: list[dict] = []
    for row in rows:
        run = row["run"]
        conds = row["conditions"] or [None]
        for c in conds:
            flat_rows.append({"row": row, "run": run, "cond": c})

    def _condition_sort_key(entry: dict) -> str:
        c = entry["cond"]
        if not c:
            return ""
        backend = str(entry["run"].get("backend", ""))
        model = str(entry["run"].get("model", ""))
        return _condition_label(str(c.get("condition", "?")), backend, model)

    flat_rows.sort(key=lambda e: (
        str(e["run"].get("target", "")),
        str(e["run"].get("backend", "")),
        _condition_sort_key(e),
        str(e["run"].get("runid", "")),
    ))

    for entry in flat_rows:
        run = entry["run"]
        c = entry["cond"]
        backend = run.get("backend", "?")
        model = run.get("model", "")
        backend_cell = (_md_link(f"`{backend}`", entry["row"]["ledger"])
                        if entry["row"]["ledger"] else f"`{backend}`")
        runid = run.get("runid", "?")
        target = run.get("target", "?")
        target_cell = _target_cell(target, run.get("target_sha"), stacked=True)
        bench_dir = entry["row"]["bench_dir"]
        run_cell = _run_cell(runid)
        if c is None:
            lines.append(
                f"| {target_cell} | {backend_cell} | — | {run_cell} "
                f"| — | — | — | — | — | — | — | — | — | · — | — | — | — |"
            )
            continue
        cond = c.get("condition", "?")
        # Counts link to each condition's own per-condition crash/finding
        # tree and cluster reports, so the crosstab is a jump board into
        # the evidence — harness and model-direct resolve separately.
        crashes_dir = (_condition_pool_dir(bench_dir, cond, "crashes")
                       if bench_dir else None)
        findings_dir = (_condition_pool_dir(bench_dir, cond, "findings")
                        if bench_dir else None)
        rejected_findings_dir = (
            _condition_pool_dir(bench_dir, cond, "findings-rejected")
            if bench_dir else None
        )
        rejected_crashes_dir = (
            _condition_pool_dir(bench_dir, cond, "crashes-rejected")
            if bench_dir else None
        )
        lines.append(
            "| {tgt} | {bk} | {cond} | {rid} | {wall} | {reps} "
            "| {rfi} | {fi} | {uf} "
            "| {rcr} | {cr} | {uc} "
            "| {mp} | {sev} | {inp} | {out} | {cost} |".format(
                bk=backend_cell,
                rid=run_cell,
                tgt=target_cell,
                cond=_condition_cell(cond, backend, model),
                wall=_fmt_hours(c.get("wall_median")),
                reps=(
                    "{d}/{t}".format(
                        d=int(c.get("replicates_done", 0) or 0),
                        t=int(c.get("replicates_total", 0) or 0),
                    )
                    + (
                        " ({r}r)".format(
                            r=int(c.get("replicates_provider_recovered", 0) or 0)
                        )
                        if int(c.get("replicates_provider_recovered", 0) or 0) > 0
                        else ""
                    )
                    + (
                        " ({p}p)".format(
                            p=int(c.get("replicates_provider_limited", 0) or 0)
                        )
                        if int(c.get("replicates_provider_limited", 0) or 0) > 0
                        else ""
                    )
                    + (
                        " ({q}q)".format(
                            q=int(c.get("replicates_quota_exhausted", 0) or 0)
                        )
                        if int(c.get("replicates_quota_exhausted", 0) or 0) > 0
                        else ""
                    )
                ),
                rfi=_crosstab_count(
                    c.get("rejected_finding_total", 0),
                    rejected_findings_dir,
                    "REJECTED-FINDINGS",
                ),
                fi=_crosstab_count(c.get("finding_total", 0),
                                   findings_dir),
                uf=_crosstab_count(c.get("unique_finding_clusters", 0),
                                   findings_dir, "FINDING-CLUSTERS"),
                rcr=_crosstab_count(
                    c.get("rejected_crash_total", 0),
                    rejected_crashes_dir,
                    "REJECTED-CRASHES",
                ),
                cr=_crosstab_count(c.get("crash_total", 0), crashes_dir),
                uc=_crosstab_count(c.get("unique_crash_clusters", 0),
                                   crashes_dir, "CRASH-CLUSTERS"),
                mp=c.get("medium_plus_bugs", 0),
                sev=_severity_cell(c.get("top_severity_level", "—")),
                inp=_fmt_input_cell(c),
                out=_fmt_output_cell(c),
                cost=_fmt_cost_compact_cell(c),
            )
        )
    lines.append("")
    lines.append(
        "Read each row as one completed experiment slice: one target, one "
        "backend, one condition, and one benchmark run. Reruns remain separate "
        "so a later experiment does not hide an earlier result."
    )
    lines.append("")

    lines.append("**Experiment identity.**")
    lines.append("")
    lines.append(
        "- **Target** — the audited open-source project, built with the target's "
        "sanitizer configuration and scored against its own work queue. The "
        "recorded target hash appears below the target name when available."
    )
    lines.append(
        "- **Backend** — the agent runtime that performed the work. The link "
        "opens that backend's run ledger, where individual cells and token "
        "details are listed."
    )
    lines.append(
        "- **Condition** — `tokenfuzz` is the full harness: recon, ranked work "
        "cards, multiple agents, sanitizer probing, triage, clustering, and "
        "reproducer export. The TokenFuzz repository hash is recorded in run "
        "metadata. `<model>-direct` is the control condition: the same model "
        "gets the bare vulnerability-finding prompt without the harness."
    )
    lines.append(
        "- **Run** — UTC run id. The table is append-style evidence, not a "
        "latest-only dashboard."
    )
    lines.append("")

    lines.append("**Effort.**")
    lines.append("")
    lines.append(
        "- **Wall (h)** — median wall-clock hours for completed replicates. "
        "Harness cells normally consume the configured time budget; direct "
        "cells may end early when the model stops."
    )
    lines.append(
        "- **Replicates** — `done/total`. A `(Nr)` suffix means N done replicates "
        "recovered from a provider blip and ARE counted (their metrics include a "
        "disrupted session); `(Np)` means N provider-limited replicates were "
        "excluded from clean totals; legacy `(Nq)` marks the older "
        "quota-exhausted subset."
    )
    lines.append("")

    lines.append("**Findings.**")
    lines.append("")
    lines.append(
        "A finding is a security report without an accepted sanitizer crash. "
        "It can still matter, but it is prose evidence and should be reviewed "
        "as a lead unless the linked report proves a concrete boundary issue."
    )
    lines.append("")
    lines.append(
        "- **Rejected findings** — reports rejected by the independent quality "
        "gate or validator. The linked index records the reason."
    )
    lines.append(
        "- **Findings** — reports that survived validation but do not have an "
        "accepted crash artifact."
    )
    lines.append(
        "- **Unique findings** — validated findings after signature clustering "
        "merges duplicate reports for the same issue."
    )
    lines.append("")

    lines.append("**Crashes.**")
    lines.append("")
    lines.append(
        "Crash counts are deliberately stricter than model claims: a crash "
        "must have sanitizer output on disk and pass triage before it counts "
        "as accepted evidence."
    )
    lines.append("")
    lines.append(
        "- **Rejected crashes** — crash candidates triage discarded, for "
        "example because they were not reproducible, were already known, or "
        "did not demonstrate a sanitizer-class issue."
    )
    lines.append(
        "- **Crashes** — accepted sanitizer crash directories with diagnostic "
        "output and reproducer material on disk."
    )
    lines.append(
        "- **Unique crashes** — accepted crashes after stack/signature "
        "clustering. This is the better volume metric when one issue produces "
        "many similar reports."
    )
    lines.append("")

    lines.append("**Severity.**")
    lines.append("")
    lines.append(
        "Severity is crash-only and comes from the shared reachability scorer. "
        "It lets a security team compare impact, not just raw report count."
    )
    lines.append("")
    lines.append(
        "- **Medium+ crashes** — unique accepted crashes scored Medium or "
        "higher. This is the headline security-yield column."
    )
    lines.append(
        "- **Top severity** — highest crash severity observed in the row, or "
        "`—` when no accepted crash was scored."
    )
    lines.append("")

    lines.append("**Tokens and dollars.**")
    lines.append("")
    lines.append(
        "`k` means thousands and `M` means millions. Token columns are "
        "normalized for comparison; the dollar column prices the original "
        "billing buckets."
    )
    lines.append("")
    lines.append(
        "- **Input** — full-rate input tokens only. Claude fresh input and "
        "cache writes are counted here for comparability; Codex and Gemini "
        "report cumulative input, so cache reads are subtracted."
    )
    lines.append(
        "- **Output** — generated tokens, including tool-call payloads when "
        "the backend reports them. `—` means output usage was not measurable."
    )
    lines.append(
        "- **Cost** — public USD-equivalent token cost: fresh input at input "
        "rate, cache writes at cache-write rate, cache reads at cache-read or "
        "context-cache rate, and output at output rate. Codex rows use "
        "OpenAI API-equivalent dollars; GPT-5.5 long-context requests use "
        "the higher >272k-token rates before aggregation. Codex product "
        "billing may also appear as credits in the workspace. This aggregate "
        "table rounds to whole dollars to stay readable; each backend ledger "
        "keeps the decimal amounts. Gemini Pro rows are priced per request so "
        "the 200k-token tier boundary is handled before aggregation."
    )
    lines.append(
        "- **Estimated values** — a `~` prefix means the row used a "
        "character-count estimate because the CLI did not expose reliable "
        "usage telemetry. Measured rows have no prefix."
    )
    lines.append("")
    return "\n".join(lines)


def relocate_experiments(bench_dir: Path) -> list[tuple[str, str]]:
    """Move each cell's external experiment tree under bench_dir/experiments/.

    A harness cell runs `bin/audit --experiment`, which writes its whole
    audit tree to output/<target>-<exp>/ at the output root. Left there,
    those trees clutter output/ and outlive the run. This moves each one
    to bench_dir/experiments/<cell>/ and rewrites the results_dir pointer
    in the cell's cell.json and metrics.json so they still resolve.

    Cells whose results_dir is already inside bench_dir — model-direct
    workspaces, dry-run cells, and trees moved by an earlier call — are
    left untouched, so the operation is idempotent. Returns the list of
    (cell, new_results_dir) pairs that were moved.
    """
    bench_dir = Path(bench_dir).resolve()
    cells_dir = bench_dir / "cells"
    exp_root = bench_dir / "experiments"
    moved: list[tuple[str, str]] = []
    if not cells_dir.is_dir():
        return moved
    for cell_dir in sorted(cells_dir.iterdir()):
        cj = cell_dir / "cell.json"
        if not cj.is_file():
            continue
        try:
            cell_data = json.loads(cj.read_text("utf-8"))
        except (OSError, ValueError):
            continue
        rd = str(cell_data.get("results_dir") or "")
        if not rd:
            continue
        rd_path = Path(rd)
        # results_dir already inside the run dir — nothing to move.
        try:
            rd_path.resolve().relative_to(bench_dir)
            continue
        except ValueError:
            pass
        # results_dir is <exp-tree>/<backend>/results; the experiment
        # tree is two levels up.
        exp_tree = rd_path.parent.parent
        if not exp_tree.is_dir():
            continue
        exp_root.mkdir(parents=True, exist_ok=True)
        dest = exp_root / cell_dir.name
        if dest.exists():
            shutil.rmtree(dest)
        shutil.move(str(exp_tree), str(dest))
        new_rd = str(dest / rd_path.parent.name / rd_path.name)
        cell_data["results_dir"] = new_rd
        cj.write_text(json.dumps(cell_data, indent=2) + "\n", encoding="utf-8")
        mj = cell_dir / "metrics.json"
        if mj.is_file():
            try:
                m = json.loads(mj.read_text("utf-8"))
                if m.get("results_dir") == rd:
                    m["results_dir"] = new_rd
                    mj.write_text(json.dumps(m, indent=2) + "\n",
                                  encoding="utf-8")
            except (OSError, ValueError):
                pass
        moved.append((cell_dir.name, new_rd))
    return moved


def split_pool(bench_dir: Path, pool_name: str = "pool") -> dict[str, int]:
    """Copy the combined pool into one subtree per condition.

    build_pool() pools every cell's crashes/findings into a single tree so
    the cross-condition cluster JSON can see all conditions at once (which
    clusters did the harness find that the baseline missed). The scoreboard
    and crosstab, though, need each condition's evidence to be a *separate*
    artifact a reader can open — harness crashes and model-direct crashes
    are different things and must not share a hyperlink.

    This reads pool-members.json (the crash/finding -> condition map) and
    copies each pooled dir into pool/<condition>/crashes|findings/. The
    combined pool is left intact. bin/benchmark then runs the same cluster
    tools over each subtree, giving every condition its own CRASH-CLUSTERS
    / FINDING-CLUSTERS report. Idempotent. Returns a {condition: count}.
    """
    bench_dir = Path(bench_dir)
    pool = bench_dir / pool_name
    members_path = bench_dir / "pool-members.json"
    if not pool.is_dir() or not members_path.is_file():
        return {}
    try:
        members = json.loads(members_path.read_text("utf-8"))
    except (OSError, ValueError):
        return {}
    tally: dict[str, int] = {}
    cleaned: set[Path] = set()
    for kind in ("crashes", "crashes-rejected", "findings", "findings-rejected"):
        for name, cond in sorted(members.get(kind, {}).items()):
            src = pool / kind / name
            if not src.is_dir():
                continue
            dest_root = pool / cond / kind
            if dest_root not in cleaned:
                if dest_root.exists():
                    shutil.rmtree(dest_root)
                dest_root.mkdir(parents=True)
                cleaned.add(dest_root)
            shutil.copytree(src, dest_root / name)
            tally[cond] = tally.get(cond, 0) + 1
    write_rejected_findings_index(pool / "findings-rejected")
    write_rejected_crashes_index(pool / "crashes-rejected")
    # split_pool only copies the CRASH-REJECTED-* dirs into the
    # per-condition tree. The per-cell INDEX-*.md rosters live in the
    # combined pool's crashes-rejected/ — partition them by condition
    # name embedded in the filename (INDEX-<cond>-<cell>.md) so each
    # condition's index reflects only its own rejection rows.
    combined_rejected = pool / "crashes-rejected"
    if combined_rejected.is_dir():
        for roster in sorted(combined_rejected.glob("INDEX-*.md")):
            # Filename: INDEX-<cond>-<cell>.md.  Take the longest known
            # condition prefix that matches so a hyphenated condition
            # name ("model-direct") is recognised correctly.
            stem = roster.name[len("INDEX-"):-len(".md")]
            cond_match = None
            for cond_dir in pool.iterdir():
                if not cond_dir.is_dir() or cond_dir.name in {
                    "crashes", "crashes-rejected",
                    "findings", "findings-rejected",
                }:
                    continue
                if (stem == cond_dir.name
                        or stem.startswith(cond_dir.name + "-")):
                    if (cond_match is None
                            or len(cond_dir.name) > len(cond_match.name)):
                        cond_match = cond_dir
            if cond_match is None:
                continue
            dest_root = cond_match / "crashes-rejected"
            dest_root.mkdir(parents=True, exist_ok=True)
            shutil.copy2(roster, dest_root / roster.name)
    for cond_dir in pool.iterdir():
        if cond_dir.is_dir() and cond_dir.name not in {
            "crashes", "crashes-rejected",
            "findings", "findings-rejected",
        }:
            write_rejected_findings_index(cond_dir / "findings-rejected")
            write_rejected_crashes_index(cond_dir / "crashes-rejected")
    return tally


_LEDGER_HEADER = """# Benchmark results

Append-only ledger written by `bin/benchmark`. Each section below is one
benchmark run: the audit harness measured against a bare CTF-prompt
baseline on the same target, backend, and budget. Newest runs are at the
bottom. Use `bin/benchmark --reset` to archive this file and start fresh.

"""


_RUN_HEADING_PREFIX = "## Benchmark run `"


def _section_runid(section: str) -> str | None:
    """The run-id from a rendered section's `## Benchmark run \\`id\\`` heading."""
    for line in section.splitlines():
        s = line.strip()
        if s.startswith(_RUN_HEADING_PREFIX) and s.endswith("`"):
            return s[len(_RUN_HEADING_PREFIX):-1]
    return None


def _drop_run_section(text: str, runid: str) -> str:
    """Remove the section for *runid* (heading to next run heading / EOF)."""
    target = f"{_RUN_HEADING_PREFIX}{runid}`"
    out, skipping = [], False
    for line in text.splitlines(keepends=True):
        if line.strip().startswith(_RUN_HEADING_PREFIX):
            skipping = line.strip() == target
        if not skipping:
            out.append(line)
    return "".join(out)


def append_to_ledger(ledger_path: Path, section: str) -> None:
    """Append *section*, replacing any existing section for the same run-id.

    A resumed run re-renders the same run-id; replacing its section in place
    keeps the ledger one-section-per-run instead of stacking the interrupted
    partial above the completed result.
    """
    ledger_path = Path(ledger_path)
    if not ledger_path.exists() or ledger_path.stat().st_size == 0:
        ledger_path.write_text(_LEDGER_HEADER, encoding="utf-8")
    runid = _section_runid(section)
    if runid is not None:
        existing = ledger_path.read_text(encoding="utf-8")
        pruned = _drop_run_section(existing, runid)
        if pruned != existing:
            ledger_path.write_text(pruned.rstrip("\n") + "\n", encoding="utf-8")
    with ledger_path.open("a", encoding="utf-8") as fh:
        if not section.startswith("\n"):
            fh.write("\n")
        fh.write(section)


def reset_ledger(ledger_path: Path, hard: bool = False) -> str | None:
    """Archive (or, with hard=True, delete) the ledger. Returns archive path."""
    ledger_path = Path(ledger_path)
    if not ledger_path.exists():
        return None
    if hard:
        ledger_path.unlink()
        # Also drop the rendered HTML sibling if present.
        html = ledger_path.with_suffix(".html")
        if html.exists():
            html.unlink()
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    archive = ledger_path.with_name(f"{ledger_path.stem}.{stamp}.bak.md")
    ledger_path.rename(archive)
    return str(archive)


# ── CLI ──────────────────────────────────────────────────────────────────


def _write_json(path: Path | None, obj: dict) -> None:
    text = json.dumps(obj, indent=2)
    if path is None:
        print(text)
    else:
        Path(path).write_text(text + "\n", encoding="utf-8")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_h = sub.add_parser("harvest", help="metric counts for one results dir")
    p_h.add_argument("results_dir", type=Path)
    p_h.add_argument("--out", type=Path, default=None)
    p_h.add_argument("--backend", default="")
    p_h.add_argument("--model", default="")

    p_rh = sub.add_parser(
        "reharvest-cells",
        help="refresh metrics.json for every cell in a benchmark run",
    )
    p_rh.add_argument("bench_dir", type=Path)
    p_rh.add_argument("--backend", default="")
    p_rh.add_argument("--model", default="")

    p_p = sub.add_parser(
        "pool", help="copy every cell's crash/finding dirs into pool/ for clustering"
    )
    p_p.add_argument("bench_dir", type=Path)
    p_p.add_argument("--pool-name", default="pool",
                     help="pool dir name under bench-dir (default: pool; a "
                          "staging name lets the caller swap atomically)")

    p_a = sub.add_parser("aggregate", help="fold a benchmark run's cells")
    p_a.add_argument("bench_dir", type=Path)
    p_a.add_argument("--out", type=Path, default=None)

    p_l = sub.add_parser("ledger", help="append a run to benchmark-results.md")
    p_l.add_argument("bench_dir", type=Path)
    p_l.add_argument("--ledger", type=Path, required=True)

    p_r = sub.add_parser("reset", help="archive or delete the ledger")
    p_r.add_argument("--ledger", type=Path, required=True)
    p_r.add_argument("--hard", action="store_true")

    p_x = sub.add_parser(
        "crosstab",
        help="fold the latest run of every backend/target pair into one table",
    )
    p_x.add_argument("bench_root", type=Path,
                     help="shared benchmark root holding per-backend subdirs")
    p_x.add_argument("--out", type=Path, default=None,
                     help="write the crosstab markdown here (default: stdout)")

    p_e = sub.add_parser(
        "relocate-experiments",
        help="move cells' external audit trees under <bench-dir>/experiments/",
    )
    p_e.add_argument("bench_dir", type=Path)

    p_s = sub.add_parser(
        "split-pool",
        help="copy the pool into per-condition crash/finding subtrees",
    )
    p_s.add_argument("bench_dir", type=Path)
    p_s.add_argument("--pool-name", default="pool",
                     help="pool dir name under bench-dir (default: pool)")

    p_sc = sub.add_parser(
        "score",
        help="score confirmed crashes against a ground-truth manifest",
    )
    p_sc.add_argument("crashes_dir", type=Path,
                      help="a crashes/ dir, or a results/pool dir holding one")
    p_sc.add_argument("--ground-truth", type=Path, required=True,
                      help="path to the target's ground-truth.json")
    p_sc.add_argument("--members", type=Path, default=None,
                      help="optional pool-members.json for per-condition scores")
    p_sc.add_argument("--conditions", default="",
                      help="comma-separated condition list; every one gets a "
                           "row even if it found zero crashes")
    p_sc.add_argument("--out", type=Path, default=None)

    args = ap.parse_args(argv)

    if args.cmd == "harvest":
        if not args.results_dir.is_dir():
            print(
                f"benchmark: results dir not found: {args.results_dir}",
                file=sys.stderr,
            )
            # Still emit a zeroed metrics object so a missing cell does
            # not abort the whole aggregation.
        _write_json(
            args.out,
            harvest(args.results_dir, args.backend, args.model),
        )
        return 0

    if args.cmd == "reharvest-cells":
        if not args.bench_dir.is_dir():
            print(f"benchmark: bench dir not found: {args.bench_dir}", file=sys.stderr)
            return 1
        refreshed = 0
        cells = args.bench_dir / "cells"
        for cell_dir in sorted(cells.iterdir() if cells.is_dir() else []):
            cell_json = cell_dir / "cell.json"
            if not cell_json.is_file():
                continue
            try:
                cell = json.loads(cell_json.read_text("utf-8"))
            except (OSError, ValueError):
                continue
            results_dir = Path(str(cell.get("results_dir") or ""))
            if not results_dir.is_dir():
                continue
            _write_json(
                cell_dir / "metrics.json",
                harvest(results_dir, args.backend, args.model),
            )
            refreshed += 1
        print(f"benchmark: reharvested {refreshed} cell(s)")
        return 0

    if args.cmd == "pool":
        if not args.bench_dir.is_dir():
            print(f"benchmark: bench dir not found: {args.bench_dir}", file=sys.stderr)
            return 1
        members = build_pool(args.bench_dir, args.pool_name)
        print(
            f"benchmark: pooled {len(members['crashes'])} crash + "
            f"{len(members['findings'])} finding + "
            f"{len(members['findings-rejected'])} rejected finding dir(s)"
        )
        return 0

    if args.cmd == "relocate-experiments":
        if not args.bench_dir.is_dir():
            print(f"benchmark: bench dir not found: {args.bench_dir}",
                  file=sys.stderr)
            return 1
        moved = relocate_experiments(args.bench_dir)
        print(f"benchmark: relocated {len(moved)} experiment tree(s)")
        return 0

    if args.cmd == "split-pool":
        if not args.bench_dir.is_dir():
            print(f"benchmark: bench dir not found: {args.bench_dir}",
                  file=sys.stderr)
            return 1
        tally = split_pool(args.bench_dir, args.pool_name)
        print(
            "benchmark: split pool into "
            + (", ".join(f"{c}={n}" for c, n in sorted(tally.items()))
               or "no conditions")
        )
        return 0

    if args.cmd == "aggregate":
        if not args.bench_dir.is_dir():
            print(f"benchmark: bench dir not found: {args.bench_dir}", file=sys.stderr)
            return 1
        _write_json(args.out, aggregate(args.bench_dir))
        return 0

    if args.cmd == "score":
        manifest = load_ground_truth(args.ground_truth)
        if manifest is None:
            print(
                f"benchmark: ground-truth manifest not found or malformed: "
                f"{args.ground_truth}",
                file=sys.stderr,
            )
            return 1
        errs = manifest_errors(manifest)
        if errs:
            print(
                f"benchmark: invalid ground-truth manifest {args.ground_truth}:",
                file=sys.stderr,
            )
            for e in errs:
                print(f"  - {e}", file=sys.stderr)
            return 1
        members = {}
        if args.members and args.members.is_file():
            try:
                pm_data = json.loads(args.members.read_text(encoding="utf-8"))
                members = pm_data.get("crashes", pm_data) if isinstance(pm_data, dict) else {}
            except (OSError, ValueError):
                members = {}
        conds = [c.strip() for c in args.conditions.split(",") if c.strip()] or None
        scoring = score_ground_truth(args.crashes_dir, manifest, members, conds)
        _write_json(args.out, scoring)
        return 0

    if args.cmd == "ledger":
        if not args.bench_dir.is_dir():
            print(f"benchmark: bench dir not found: {args.bench_dir}", file=sys.stderr)
            return 1
        report = aggregate(args.bench_dir)
        (args.bench_dir / "report.json").write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        # Section links live next to args.ledger, so artifact URIs render
        # relative to that directory (and stay portable when the run is
        # moved or shared).
        with _render_relative_to(args.ledger.parent):
            section = render_section(report)
        append_to_ledger(args.ledger, section)
        print(f"benchmark: appended run to {args.ledger}")
        return 0

    if args.cmd == "crosstab":
        if not args.bench_root.is_dir():
            print(f"benchmark: bench root not found: {args.bench_root}",
                  file=sys.stderr)
            return 1
        # The crosstab is conventionally written under bench_root (or
        # passed via --out next to it), so use that as the link base.
        out_base = args.out.parent if args.out else args.bench_root
        with _render_relative_to(out_base):
            md = crosstab(args.bench_root)
        if args.out is None:
            print(md)
        else:
            Path(args.out).write_text(md, encoding="utf-8")
            print(f"benchmark: wrote crosstab to {args.out}")
        return 0

    if args.cmd == "reset":
        archive = reset_ledger(args.ledger, hard=args.hard)
        if archive:
            print(f"benchmark: ledger archived to {archive}")
        elif args.hard:
            print("benchmark: ledger deleted")
        else:
            print("benchmark: no ledger to reset")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
