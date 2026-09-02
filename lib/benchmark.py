#!/usr/bin/env python3
"""benchmark.py — metric harvest + ledger rendering for bin/benchmark.

bin/benchmark runs the audit harness against a fixed model-direct baseline so an
operator can answer one question with evidence rather than opinion:

    does the harness find more real, reproducible bugs than a bare
    "find all vulnerabilities" CTF prompt, for the same budget?

This module is the *deterministic* half of that tool — everything that
does not involve launching an LLM. It is kept separate from bin/benchmark
precisely so it can be unit-tested without a backend:

  * harvest(results_dir)   — count confirmed crashes / findings in a
                             standard results/ tree, by
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
import tempfile
import urllib.parse
from decimal import Decimal, ROUND_HALF_UP
from datetime import datetime, timezone
from pathlib import Path

import audit_helpers
import cluster_common
import crash_artifacts
import crash_bundle
import finding_signature
import llm_usage
import report_identity
import severity_receipt
import telemetry
import triage_validate
import validation_receipt

try:  # ClusterFuzz-normalized stack frames — reused, never reinvented.
    import stack_frames as _sf
except Exception:  # pragma: no cover - stack_frames should always import
    _sf = None

try:  # Shared sanitizer-artifact discovery — same policy as export/triage.
    import crash_artifacts as _ca
except Exception:  # pragma: no cover - crash_artifacts should always import
    _ca = None

try:  # Target config parser for preserving benchmark-pool threat models.
    import target_config as _tc
except Exception:  # pragma: no cover - target_config should always import
    _tc = None

SCRIPT_ROOT = Path(__file__).resolve().parent.parent
FINDING_CONFIRMATION_VERSION = "quality-trigger-v1"
CELL_RUN_QUALITIES = frozenset({
    "clean", "incomplete", "provider_recovered", "provider_limited",
    "source_drift", "build_drift", "unowned_artifacts", "backend_terminated",
    "processes_unreaped",
})
NONCOMPARABLE_RUN_QUALITIES = frozenset({
    # A cell whose own work is still running was never bounded by its wall:
    # it kept spending CPU after the clock stopped, and it spends it against
    # whatever runs next.
    "provider_limited", "source_drift", "build_drift", "processes_unreaped",
})


def cell_results_dir(cell: dict) -> Path | None:
    """A cell record's results tree, or None when it never named one.

    A cell that was refused before it started records no results dir, and both
    "" and "." read back through ``Path`` as the *current working directory* —
    the repository root for every command here. A consumer that takes that at
    face value treats the whole checkout as the cell's evidence: build_pool
    would import it, and relocate_experiments computed its parent's parent and
    called ``shutil.move`` on it, which a real run only survived because the
    destination happened to sit inside the tree being moved.

    Every writer of a started cell records an absolute path, so an absolute
    path is the whole of what a results tree can look like.
    """
    value = str(cell.get("results_dir") or "").strip()
    if not value:
        return None
    path = Path(value)
    return path if path.is_absolute() else None


def cell_run_quality(cell_dir: Path, status: str) -> str:
    """Resolve persistent cell-quality evidence with stable precedence."""
    quality = "clean"
    if (cell_dir / ".processes-unreaped").is_file():
        # Outranks every other reason: whatever else was wrong with the cell,
        # its wall did not contain its work.
        return "processes_unreaped"
    try:
        candidate = (cell_dir / ".run-quality").read_text(
            encoding="utf-8",
        ).strip()
        if candidate in CELL_RUN_QUALITIES:
            quality = candidate
    except OSError:
        pass
    if (
        (cell_dir / ".target-artifacts-unowned").is_file()
        and quality not in {"provider_limited", "source_drift", "build_drift"}
    ):
        quality = "unowned_artifacts"
    if (
        (cell_dir / ".backend-terminated").is_file()
        and quality not in {
            "provider_limited", "source_drift", "build_drift", "unowned_artifacts",
        }
    ):
        quality = "backend_terminated"
    if status == "incomplete" and quality == "clean":
        quality = "incomplete"
    return quality


# ── sanitizer crash oracle ───────────────────────────────────────────────
#
# A "confirmed crash" is a directory holding at least one file whose text
# carries a sanitizer diagnostic. The signature set is the single source of
# truth in stack_frames.SANITIZER_SIGNATURE_RE — a deliberate mirror of the
# triager's gate in lib/triage.py (search: "_triage_has_sanitizer_diagnostic").
# Sourcing it here (rather than re-spelling the alternation) keeps the
# benchmark's confirmed-crash count, the severity scorer (bin/severity),
# and the triage gate in lockstep; this is the whole reason the benchmark
# number is trustworthy.
if _sf is not None:
    SANITIZER_SIGNATURE_RE = _sf.SANITIZER_SIGNATURE_RE
else:  # pragma: no cover - stack_frames should always import
    SANITIZER_SIGNATURE_RE = re.compile(
        r"^[^\s].*:\d+:\d+: runtime error:|ERROR: \w*Sanitizer",
        re.MULTILINE,
    )

# Files large enough to be a build artifact rather than a sanitizer log
# are skipped during the grep so harvest stays fast on big result trees.
_MAX_SCAN_BYTES = 2 * 1024 * 1024

_CLUSTER_COUNT_RE = re.compile(r"(\d+)\s+unique\s+cluster")
_MODEL_REFUSAL_RE = re.compile(r"\bMODEL_REFUSAL\b")
_ARTIFACT_REF_RE = re.compile(
    r"\b(?:FIND|CRASH)-[A-Za-z0-9]+(?:[._-][A-Za-z0-9]+)*\b"
)


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
        bare = needle[:-1]
        bare_replacement = (
            replacement[:-1] if replacement.endswith("/") else replacement
        )
        if not bare_replacement:
            bare_replacement = "."
        delimiter = r"[\s\"'`()\[\]{}<>|]"
        punctuation = rf"[.!?,:;](?=$|{delimiter})"
        uri_boundary = r"|[#?]" if bare.startswith("file:") else ""
        text = re.sub(
            re.escape(bare)
            + rf"(?=$|{delimiter}|{punctuation}{uri_boundary})",
            lambda _match: bare_replacement,
            text,
        )
    return text


def _should_scrub_pooled_file(path: Path) -> bool:
    if not path.is_file():
        return False
    if path.name in _SCRUB_TEXT_NAMES:
        return True
    return path.suffix.lower() in _SCRUB_TEXT_SUFFIXES


def _source_anchor_identity(value: object) -> tuple | None:
    """Comparable review fields for one host-verified source anchor."""
    if not isinstance(value, dict):
        return None
    try:
        line = int(value.get("line"))
    except (TypeError, ValueError):
        return None
    return (
        str(value.get("path") or "").strip(),
        line,
        str(value.get("symbol") or "").strip(),
        str(value.get("kind") or "").strip().lower(),
        str(value.get("excerpt") or "").strip(),
    )


def _attested_review_anchors(receipt: dict | None) -> dict[str, set[tuple]]:
    """Verified anchor identities that a pool scrub must leave unchanged."""
    if not isinstance(receipt, dict):
        return {}
    evidence = receipt.get("evidence")
    if not isinstance(evidence, dict):
        return {}
    protected: dict[str, set[tuple]] = {}
    for attestation in evidence.get("source_attestations") or []:
        if not isinstance(attestation, dict):
            continue
        review = str(attestation.get("review_artifact") or "")
        if not review:
            continue
        identities = {
            identity
            for anchor in (attestation.get("anchors") or [])
            if (identity := _source_anchor_identity(anchor)) is not None
        }
        if identities:
            protected.setdefault(review, set()).update(identities)
    return protected


def _scrub_json_value(value):
    if isinstance(value, str):
        return _scrub_local_paths(value)
    if isinstance(value, list):
        return [_scrub_json_value(item) for item in value]
    if isinstance(value, dict):
        return {
            _scrub_local_paths(str(key)): _scrub_json_value(item)
            for key, item in value.items()
        }
    return value


def _scrub_review_json(
    original: str, protected: set[tuple],
) -> str | None:
    """Scrub review metadata without rewriting verified anchor evidence."""
    duplicate_member = False

    def unique_object(pairs):
        nonlocal duplicate_member
        value = {}
        for key, item in pairs:
            if key in value:
                duplicate_member = True
            value[key] = item
        return value

    try:
        payload = json.loads(original, object_pairs_hook=unique_object)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        scrubbed_payload = _scrub_json_value(payload)
        if scrubbed_payload == payload and not duplicate_member:
            return original
        return json.dumps(scrubbed_payload, indent=2) + "\n"
    scrubbed = {}
    for key, value in payload.items():
        scrubbed_key = _scrub_local_paths(str(key))
        if key != "anchors" or not isinstance(value, list):
            scrubbed[scrubbed_key] = _scrub_json_value(value)
            continue
        anchors = []
        for anchor in value:
            identity = _source_anchor_identity(anchor)
            if identity not in protected or not isinstance(anchor, dict):
                anchors.append(_scrub_json_value(anchor))
                continue
            core_fields = {"path", "line", "symbol", "kind", "excerpt"}
            scrubbed_anchor = {
                field: item
                for field, item in anchor.items()
                if field in core_fields
            }
            for field, item in anchor.items():
                if field in core_fields:
                    continue
                scrubbed_field = _scrub_local_paths(str(field))
                # Unverified metadata may not shadow a verified field after
                # its key is made portable. Dropping that one colliding entry
                # preserves the source claim and removes the host path.
                if scrubbed_field in scrubbed_anchor:
                    continue
                scrubbed_anchor[scrubbed_field] = _scrub_json_value(item)
            anchors.append(scrubbed_anchor)
        scrubbed[scrubbed_key] = anchors
    if scrubbed == payload and not duplicate_member:
        return original
    return json.dumps(scrubbed, indent=2, sort_keys=True) + "\n"


def _scrub_pooled_tree(
    root: Path, prior_validation: dict | None = None,
) -> None:
    """Best-effort scrub of local paths without altering attested anchors."""
    if not root.is_dir():
        return
    protected_reviews = _attested_review_anchors(prior_validation)
    for path in root.rglob("*"):
        if not _should_scrub_pooled_file(path):
            continue
        try:
            if path.stat().st_size > _MAX_SCRUB_BYTES:
                continue
            original = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError:
            relative = ""
        protected = protected_reviews.get(relative)
        if protected is not None:
            scrubbed = _scrub_review_json(original, protected)
            # A current attestation implies valid JSON. If a concurrent writer
            # breaks that invariant, retain the evidence bytes rather than
            # destroying publication authority during a best-effort scrub.
            if scrubbed is None:
                continue
        else:
            scrubbed = _scrub_local_paths(original)
        if scrubbed == original:
            continue
        try:
            path.write_text(scrubbed, encoding="utf-8")
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


def _rejected_label(value: object, upper_bound: bool) -> object:
    """Show when an unclusterable rejection count is only a safe maximum."""
    return f"up to {value}" if upper_bound else value


def _unique_with_medium_plus(
    unique: int, medium_plus: int, unadjudicated: int = 0,
    classes: int = 0, floor: bool = False, retained: int = 0,
) -> str:
    """Label a unique-cluster count with its Medium+ subset: `6 (1 M+)`.

    The parenthetical surfaces how many of the deduplicated reports the
    severity scorer rated Medium or higher — the security-yield subset —
    without dropping the Low/unscored remainder from the headline count.
    A gate on the count itself would zero out findings whose severity is
    still blank/Pending (rank 0). An empty cell stays a bare `0`.

    Reports that never reached a verdict are carried alongside rather than
    folded into the count. A cell has no way to say "nothing survived review"
    and "review did not finish" with the same `0`, and the two support opposite
    conclusions about the condition — so an unjudged remainder is always
    shown, including next to a zero.

    `K classes` says how much of the target the count covers. A condition can
    reach the same number by finding one mechanism at many sites or many
    mechanisms at few, and those are different results; the class term is the
    only place the difference is visible. Findings only — crashes cluster by
    stack signature, which already carries it.

    `floor` prefixes `≥`. Every cell with an unjudged remainder is a floor, but
    a residue beside an adjudicated majority still reads as a measurement,
    while a remainder that outnumbers the verdicts does not: review stopped
    partway down a queue, and the part it never read is not a sample of the
    part it did. The count keeps its link and its artifacts either way — the
    mark says only that it cannot be compared as a measured yield.

    `K retained` names reproduced crashes a reviewer placed outside the
    declared attacker controls. They earn no credit and are not pooled, so
    without the term a condition that reproduced eight real defects on a
    bytes-only target reads exactly like one that reproduced none. Crashes
    only: a finding placed out of scope has no reproducer to retain.
    """
    trailing = [
        term for term, count in (
            ("unjudged", unadjudicated), ("retained", retained),
        ) if count > 0
        for term in (f"{count} {term}",)
    ]
    if not unique:
        return f"0 ({', '.join(trailing)})" if trailing else "0"
    inner = f"{medium_plus} M+"
    if classes > 0:
        inner += f", {classes} class{'es' if classes != 1 else ''}"
    if trailing:
        inner += ", " + ", ".join(trailing)
    return f"{'≥' if floor else ''}{unique} ({inner})"


def _finding_class_count(condition: dict) -> int:
    """Return the class count only for a complete unique-cluster decomposition."""
    histogram = condition.get("finding_class_histogram")
    unique = _as_int(condition.get("unique_finding_clusters"))
    if not isinstance(histogram, dict) or not histogram:
        return 0
    total = 0
    for name, count in histogram.items():
        if (
            not isinstance(name, str)
            or not name
            or isinstance(count, bool)
            or not isinstance(count, int)
            or count < 1
        ):
            return 0
        total += count
    if total != unique:
        return 0
    return len(histogram)


#: Stands in for a severity receipt that exists but cannot name its scorer.
#: It is never the current version, so such a row is marked rather than read
#: as though today's rules produced it.
UNKNOWN_SCORER = "unknown"


def harvest_fuzz_campaign(results_dir: Path) -> dict:
    """What S4 actually did, as separate facts rather than one verdict.

    S4 can file an accepted crash without the managed campaign ever starting:
    an agent compiles a one-shot harness through `bin/probe` and probes it
    directly. That is allowed, but the tree then looks identical whether the
    campaign machinery worked, was never reached, or was stepped around, and
    an operator cannot tell which from the artifacts.

    Each signal is reported on its own because they answer different
    questions and disagree in ways a single word would hide: a failed compile
    still leaves its build log, so attempts are not successes, and an authored
    harness that never built is not a campaign that found nothing. Naming them
    separately also keeps this honest about what the files can prove.

    Read only. `bin/fuzz run` is the sole writer of the campaign state keyed
    on here, so this reports what happened rather than adding a runtime path
    that could fail an audit.
    """
    results_dir = Path(results_dir)
    fuzz = results_dir / "fuzz"
    authored = sorted(
        path.name for path in (fuzz / "src").glob("*")
        if path.is_file() and path.suffix in (".c", ".cc", ".cpp", ".rs")
    )
    # A build log is written for a failed compile too, so it counts attempts.
    attempted = sorted(path.name for path in (fuzz / "bin").glob("*.build.log"))
    # What a successful link leaves behind. The compiled harness itself does
    # not survive the run, so it cannot serve as the receipt; debug output is
    # produced only after a link succeeds, and where a toolchain emits none
    # this reports 0 rather than claiming a failure.
    linked = sorted(path.name for path in (fuzz / "bin").glob("*.dSYM"))
    records = 0
    journal = fuzz / "campaign.jsonl"
    if journal.is_file():
        try:
            records = sum(
                1 for line in journal.read_text(
                    encoding="utf-8", errors="replace").splitlines() if line.strip()
            )
        except OSError:
            records = 0
    return {
        "harnesses_authored": len(authored),
        "builds_attempted": len(attempted),
        "builds_with_debug_output": len(linked),
        "campaign_invoked": (fuzz / "state.json").is_file() or records > 0,
        "campaign_slices_recorded": records,
        "probe_harnesses_observed": len([
            path for path in results_dir.glob("scratch-*/.harness-cache/*")
            if path.is_file() and path.suffix == ".bin"
        ]),
    }


def severity_scorer_versions(bench_dir: Path) -> list[str]:
    """Every severity scorer version behind this run's pooled artifacts.

    `M+` counts one thing: artifacts the scorer put at Medium or higher. When
    the scorer's own rules change, the same artifact set yields a different
    count, so two rows scored by different versions are not comparable even
    though the column header is identical. The page accumulates rows across
    months, which is exactly where that goes unnoticed, so record what scored
    the numbers rather than leaving a reader to assume one scale.

    Read from the artifacts themselves — the scorer stamps every severity.json
    — so a run regenerated under a newer scorer re-reports honestly and a
    partial aggregate with no pool yet simply says nothing.
    """
    versions: set[str] = set()
    pool = bench_dir / "pool"
    if not pool.is_dir():
        return []
    for receipt in pool.glob("*/*/severity.json"):
        # A receipt that cannot say what scored it is not evidence that the
        # current scorer did. Skipping it would let the row read as current,
        # which is the one answer the file does not support.
        try:
            payload = json.loads(receipt.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            versions.add(UNKNOWN_SCORER)
            continue
        version = payload.get("scorer_version")
        versions.add(version if isinstance(version, str) and version
                     else UNKNOWN_SCORER)
    return sorted(versions)


def _outdated_scorers(report: dict, bench_dir: "Path | None" = None) -> list[str]:
    """Scorer versions behind *report* that are not the one running now.

    A report written before the run recorded its scorer still has the receipts
    on disk, so fall back to reading them rather than showing a stale row as
    if it were current. Silence is reserved for the case where neither the
    report nor a pool can answer.
    """
    recorded = report.get("severity_scorers")
    if not isinstance(recorded, list):
        recorded = severity_scorer_versions(bench_dir) if bench_dir else []
    return sorted(
        version for version in recorded
        if isinstance(version, str)
        and version
        and version != severity_receipt.SCORER_DECISION_VERSION
    )


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


def _reconcile_demoted_pool_crashes(
    bench_dir: Path,
    pool_name: str = "pool",
) -> dict:
    """Move stale member entries for crashes demoted after pooling."""
    bench_dir = Path(bench_dir)
    members_path = bench_dir / "pool-members.json"
    if not members_path.is_file():
        return {}
    try:
        members = json.loads(members_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(members, dict):
        return {}
    if not isinstance(members.get("crashes"), dict):
        members["crashes"] = {}
    if not isinstance(members.get("crashes-rejected"), dict):
        members["crashes-rejected"] = {}
    if not isinstance(members.get("crash_cells"), dict):
        members["crash_cells"] = {}
    crashes = members["crashes"]
    rejected = members["crashes-rejected"]
    pool = bench_dir / pool_name
    changed = False
    for name, cond in list(crashes.items()):
        if (pool / "crashes" / name).is_dir():
            continue
        if not (pool / "crashes-rejected" / name).is_dir():
            continue
        del crashes[name]
        rejected[name] = cond
        changed = True
    if changed:
        # Best-effort persist: an archived/read-only bench dir must not crash
        # aggregate. The returned in-memory map is already reconciled either way.
        try:
            members_path.write_text(json.dumps(members, indent=2) + "\n",
                                    encoding="utf-8")
        except OSError:
            pass
    return members


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
    primary = d / "sanitizer.txt"
    if primary.is_file():
        try:
            rates = re.findall(
                r"^CRASH_RATE:\s*(\d+)\s*/\s*(\d+)\s*$",
                primary.read_text(encoding="utf-8", errors="replace"),
                re.MULTILINE,
            )
        except OSError:
            rates = []
        if rates and int(rates[-1][0]) == 0:
            return False
    for path in d.rglob("*"):
        if path.is_file() and _file_has_sanitizer_output(path):
            return True
    return False


def publication_state_names(
    parent: Path, *, kind: str, prefix: str, require_sanitizer: bool = False,
) -> tuple[list[str], list[str]]:
    """Return (security-credit names, all-final names) from one receipt pass."""
    if not parent.is_dir():
        return [], []
    security: list[str] = []
    finalized: list[str] = []
    for child in sorted(parent.iterdir()):
        if not child.is_dir() or not child.name.startswith(prefix):
            continue
        receipt = validation_receipt.read_current(child)
        if (
            receipt is None
            or receipt.get("kind") != kind
            or receipt.get("state") not in validation_receipt.FINAL_STATES
            or (require_sanitizer and not dir_has_sanitizer_output(child))
        ):
            continue
        finalized.append(child.name)
        if receipt.get("state") in validation_receipt.SECURITY_STATES:
            security.append(child.name)
    return security, finalized


def count_confirmed_crashes(crashes_dir: Path) -> tuple[int, list[str]]:
    """Count sanitizer-backed crashes with a current security-state receipt."""
    security, _ = publication_state_names(
        crashes_dir, kind="crash", prefix="CRASH-", require_sanitizer=True,
    )
    return len(security), security


def crash_is_pending(directory: Path) -> bool:
    return bool(cluster_common.promotion_pending_reasons(directory))


def count_pending_crashes(crashes_dir: Path) -> int:
    """Count proved crash bundles whose maintainer report is unfinished."""
    if not crashes_dir.is_dir():
        return 0
    return sum(
        dir_has_sanitizer_output(child) and crash_is_pending(child)
        for child in crashes_dir.iterdir()
        if child.is_dir() and not child.name.startswith(".")
    )


def _finding_is_pinned(finding_dir: Path) -> bool:
    """True iff a human pinned the FIND (.keep/.reviewed).

    A manual override that outranks the find-quality gate: a pinned FIND is
    confirmed even if never agent-investigated.
    """
    return (finding_dir / ".reviewed").is_file() or (finding_dir / ".keep").is_file()


def _finding_quality_accepted(finding_dir: Path) -> bool:
    """True iff the current report passed quality review."""
    cache = finding_dir / ".llm-find-quality.json"
    if not cache.is_file():
        return False
    payload = _read_json(cache) or {}
    if payload.get("accept") is not True:
        return False
    return report_identity.quality_cache_matches_report(finding_dir, payload)


def _finding_is_admitted(finding_dir: Path) -> bool:
    """True iff a FIND is substantive enough to count as audit progress."""
    receipt = validation_receipt.read_current(finding_dir)
    if receipt and receipt.get("state") in validation_receipt.FINAL_STATES:
        return receipt.get("state") in validation_receipt.SECURITY_STATES
    return _finding_is_pinned(finding_dir) or _finding_quality_accepted(finding_dir)


def _finding_trigger_kept(finding_dir: Path) -> bool:
    """True iff current trigger evidence keeps the finding in scope."""
    if _read_json(finding_dir / ".trigger-gate-bypass.json").get("bypass") is True:
        return True
    return _trigger_snapshot(finding_dir)[0] in {"bypass", "promote"}


def _current_trigger_vote(
    payload: dict, report_sha1s: frozenset[str], directory: Path,
) -> str | None:
    if payload.get("content_sha1") not in report_sha1s:
        return None
    vote = payload.get("vote")
    version = payload.get("decision_version")
    if (
        version in {
            triage_validate.TRIGGER_GATE_DECISION_VERSION,
            triage_validate.TRIGGER_RESOLUTION_DECISION_VERSION,
        }
        # Harvest is intentionally environment-free: it validates that the
        # current scoped schema recorded controls, while live triage is the
        # authority that compares them with target.toml and refreshes a stale
        # scope before benchmark metrics are written.
        and isinstance(payload.get("attacker_controls"), list)
        and vote in {"Promote", "Reject", "Uncertain"}
    ):
        if version == triage_validate.TRIGGER_RESOLUTION_DECISION_VERSION:
            prior_paths = _trigger_resolution_sources(
                report_sha1s, directory,
            )
            if not prior_paths:
                return None
            prior_sha256s = triage_validate.prior_review_sha256s(prior_paths)
            if payload.get("prior_review_sha256s") != prior_sha256s:
                return None
        if vote in {"Promote", "Reject"}:
            anchors = payload.get("anchors")
            if (
                payload.get("anchors_verified") is not True
                or not isinstance(anchors, list)
                or not anchors
            ):
                return None
        evidence = crash_bundle.recorded_evidence_context(directory)
        evidence_id = evidence.get("evidence_id") if evidence else None
        if evidence_id != payload.get("evidence_id"):
            return None
        return vote
    if (
        version in triage_validate.TRIGGER_GATE_ADVISORY_VERSIONS
        and vote in {"Promote", "Uncertain"}
    ):
        return "Uncertain"
    return None


def _trigger_resolution_sources(
    report_sha1s: frozenset[str], directory: Path,
) -> tuple[Path, ...]:
    first = directory / ".trigger-gate.json"
    first_vote = _current_trigger_vote(
        _read_json(first), report_sha1s, directory,
    )
    second = directory / ".trigger-gate-2.json"
    names = triage_validate.trigger_resolution_review_names(
        first_vote,
        _current_trigger_vote(_read_json(second), report_sha1s, directory),
    )
    return tuple(directory / name for name in names)


def _finding_is_confirmed(
    finding_dir: Path, *, require_trigger_confirmation: bool = True,
) -> bool:
    """True iff a FIND passed both gates, or is human-pinned.

    Findings carry no sanitizer reproducer — that is the crashes/ contract,
    not findings/ — so the finding analog of count_confirmed_crashes' "proof,
    not assertion" is complete quality and trigger adjudication. A quality
    quorum with missing or stale trigger evidence remains pending. A
    `.keep`/`.reviewed` pin is the explicit human override for both gates.
    """
    receipt = validation_receipt.read_current(finding_dir)
    if receipt is not None:
        return (
            receipt.get("kind") == "finding"
            and receipt.get("state") in validation_receipt.SECURITY_STATES
        )
    if require_trigger_confirmation:
        # Legacy positive votes are preserved as visible provisional evidence;
        # only the content-addressed publication receipt grants final credit.
        return False
    if not _finding_is_admitted(finding_dir):
        return False
    return (
        not require_trigger_confirmation
        or _finding_is_pinned(finding_dir)
        or _finding_trigger_kept(finding_dir)
    )


def _finding_has_terminal_reject(finding_dir: Path) -> bool:
    """True iff a rejected FIND is awaiting its final directory move."""
    receipt = validation_receipt.read_current(finding_dir)
    return (
        receipt is not None
        and receipt.get("kind") == "finding"
        and receipt.get("state") == "rejected"
    )


def _iter_jsonl(path: Path):
    """Yield dict rows from a JSONL file, tolerating a missing file and bad
    lines (a partial write from a live run). Read-only metric use."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            yield row


def count_confirmed_findings(
    findings_dir: Path, *, require_trigger_confirmation: bool = True,
) -> tuple[int, list[str]]:
    """Count fully adjudicated FIND-* subdirs (or human-pinned overrides).

    Returns (count, sorted list of FIND dir names). The mirror of
    count_confirmed_crashes for findings: an un-adjudicated FIND (the gate
    never rendered a verdict) is NOT counted, so a run whose triage was cut
    off cannot inflate its finding count with output the gate never
    looked at. The raw `count_subdirs(findings_dir, "FIND-")` total is kept
    in metrics (`findings`) for auditability; regenerate drains the gate so a
    cut-off run converges to its confirmed count, and any residual the drain
    cannot resolve surfaces as a run-health WARN rather than being silently
    dropped.

    """
    if not findings_dir.is_dir():
        return 0, []
    if require_trigger_confirmation:
        security, _ = publication_state_names(
            findings_dir, kind="finding", prefix="FIND-",
        )
        return len(security), security
    confirmed: list[str] = []
    for child in sorted(findings_dir.iterdir()):
        if not child.is_dir() or not child.name.startswith("FIND-"):
            continue
        if not _finding_is_confirmed(
            child, require_trigger_confirmation=require_trigger_confirmation,
        ):
            continue
        confirmed.append(child.name)
    return len(confirmed), confirmed


def count_admitted_findings(findings_dir: Path) -> tuple[int, list[str]]:
    """Count quality-accepted FINDs for live audit progress.

    Trigger review is benchmark adjudication, not a search-loop admission
    gate. A provider-delayed trigger vote must not turn a substantive new
    finding into a dry iteration and rotate or stop the investigation.
    """
    if not findings_dir.is_dir():
        return 0, []
    admitted = [
        child.name
        for child in sorted(findings_dir.iterdir())
        if child.is_dir()
        and child.name.startswith("FIND-")
        and _finding_is_admitted(child)
    ]
    return len(admitted), admitted


def _pool_finding_names(metrics: dict, findings_dir: Path) -> list[str]:
    """Finding directory names eligible for benchmark pooling.

    Metrics carry `confirmed_finding_dirs`, so the pool imports only
    gate-accepted or human-pinned findings. A missing or malformed field is
    treated as no confirmed membership; `bin/benchmark --regenerate` reharvests
    cells before rebuilding the pool.
    """
    raw_names = [
        child.name
        for child in sorted(findings_dir.iterdir() if findings_dir.is_dir() else [])
        if child.is_dir() and child.name.startswith("FIND-")
    ]
    names = metrics.get("confirmed_finding_dirs")
    if isinstance(names, list):
        wanted = {str(name) for name in names if str(name)}
        return [name for name in raw_names if name in wanted]
    return []


def rejected_finding_names(rejected_dir: Path) -> list[str]:
    """FIND-* directories under findings-rejected/ that hold a report.

    A directory an agent created and never wrote into is closed by the gate
    as `incomplete missing: missing report.md`; it is not a report review
    turned down, so it is neither counted nor pooled as one.
    """
    if not rejected_dir.is_dir():
        return []
    return [
        child.name
        for child in sorted(rejected_dir.iterdir())
        if child.is_dir()
        and child.name.startswith("FIND-")
        and _report_link_name(child)
    ]


def count_subdirs(parent: Path, prefix: str) -> int:
    """Count immediate subdirectories of *parent* whose name starts prefix."""
    if not parent.is_dir():
        return 0
    return sum(
        1
        for c in parent.iterdir()
        if c.is_dir() and c.name.startswith(prefix)
    )


def count_rejected_crash_rows(index_md: Path) -> int:
    """Count row-only rejection records in a rejected-crashes ledger.

    Legacy ledgers can contain rejection rows with no corresponding directory.
    A generated summary contains a row for every directory and must not be
    counted again beside those directories.
    """
    if not index_md.is_file():
        return 0
    try:
        text = index_md.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return 0
    if any(
        line.strip() == "## Rejected crash directories"
        for line in text.splitlines()
    ):
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
      * row-only legacy ledgers — auto-rejected signatures that never got a
        CRASH-* dir.
    Summing both is what makes the column total honest: a reader who
    sees 7 here can find 7 rejection records (subdir or row) below.

    """
    rosters = sorted(rejected_dir.glob("CELL-REJECTIONS-*.md"))
    if rosters:
        ledger_rows = sum(count_rejected_crash_rows(path) for path in rosters)
    else:
        ledger = rejected_dir / "REJECTED-CRASHES.md"
        if not ledger.is_file():
            ledger = rejected_dir / "INDEX.md"
        ledger_rows = count_rejected_crash_rows(ledger)
    return (
        count_subdirs(rejected_dir, "CRASH-")
        + ledger_rows
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
    the rejected index so the bumped column total has a concrete landing page.
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
            "blocked by a validated guard, etc.). One row per hypothesis."
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


def confirmed_finding_cluster_count(findings_dir: Path, names: list[str]) -> int:
    """Count roots represented by confirmed findings only."""
    clusters: set[str] = set()
    for name in names:
        directory = findings_dir / name
        cluster = cluster_common.artifact_cluster_id(directory)
        clusters.add(cluster or name)
    return len(clusters)


def confirmed_finding_class_histogram(
    findings_dir: Path, names: list[str],
) -> dict[str, int]:
    """How many confirmed findings fall in each bug class.

    Cluster identity is (class, file, line), so one mechanism restated at N
    locations is N countable findings -- correctly, since N sites need N fixes.
    That makes the finding count alone a poor read of what a condition covered:
    one cell reached 57 accepted findings across 3 classes while its peer
    reached 30 across 21, and the counts alone say the opposite of the
    coverage.

    Per-class counts are kept rather than a set so the report can check that
    the classes it prints decompose the same unique-cluster count. It ranks
    nothing and gates nothing.

    The reviewed class from the quality gate is preferred over the report's own
    free-text field, which varies per report for the same defect. A finding
    with neither is counted under its own name, so it reads as its own class
    rather than merging with every other unlabelled finding.
    """
    classes: dict[str, int] = {}
    for name in names:
        directory = findings_dir / name
        value = ""
        try:
            cache = json.loads(
                (directory / ".llm-find-quality.json").read_text(
                    encoding="utf-8",
                )
            )
            value = str(cache.get("class") or "")
        except (OSError, ValueError):
            value = ""
        if not value:
            report = next(
                (path for path in (directory / "report.md", directory / "REPORT.md")
                 if path.is_file()),
                None,
            )
            if report is not None:
                try:
                    text = report.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = ""
                match = re.search(
                    r"^(?:Class\s*:\s*|\|\s*Class\s*\|\s*)([^|\n]+)",
                    text, re.IGNORECASE | re.MULTILINE,
                )
                value = match.group(1) if match else ""
        normalized = " ".join(value.split()).lower()
        key = normalized if normalized and normalized not in {"—", "-"} else name
        classes[key] = classes.get(key, 0) + 1
    return classes


def confirmed_finding_class_count(findings_dir: Path, names: list[str]) -> int:
    """Distinct bug classes across confirmed findings."""
    return len(confirmed_finding_class_histogram(findings_dir, names))


# Backends whose `input` token field already includes the cached prefix
# (cached + fresh). Codex reports a running total; gemini-cli's
# `result.stats.input_tokens` is likewise cumulative (it
# also emits a separate fresh-only `input`, but the priority order in
# _INPUT_KEYS picks `input_tokens` first, so the same subtract-cached
# normalization applies). The xAI Responses API uses the same total-input
# convention if Grok Build exposes usage in a future CLI release. Claude
# and OpenCode/oss report fresh input only and stay out
# of this list. harvest_tokens subtracts the cached part for these so
# the per-turn delta is comparable across backends. Backend names are
# industry vocabulary, not target-specific, so this list is
# harness-shared by design.
# OpenCode is out by arithmetic: its per-request `tokens.total` equals
# input + output + reasoning + cache.read + cache.write, so `input` is
# disjoint from the cache buckets and subtracting floored oss cells at zero.
_INPUT_INCLUDES_CACHED = ("codex", "gemini", "grok")

_MILLION = Decimal("1000000")


def _money(value: str) -> Decimal:
    return Decimal(value)


# Shared with the served-model gate, which must decide "is this the model we
# asked for?" against the same rules the price table uses.
_model_id_is = llm_usage.model_id_matches


def _pricing_rates(
    backend: str, model: str = "",
) -> dict | None:
    """Public USD-equivalent token rates per 1M tokens.

    Codex product billing uses credits, but the underlying model has public
    API-equivalent token rates. Those rates are the reproducible denominator
    for cross-backend benchmark dollars. The benchmark CLIs make interactive
    standard-tier requests, so batch, flex, priority, fast-mode, and regional
    multipliers do not apply here.

    Every row is the rate in force, and none of them key on a date. An
    announced future change is not a rate: vendors routinely extend a
    promotion or drop an increase — Anthropic cancelled Sonnet 5's scheduled
    one outright — so encoding the announcement means the table restates a
    completed run's spend on a day nothing actually happened. When a price
    really changes, change the row. A backend that reports its own cost is
    believed ahead of this table either way; what this provides is one
    denominator applied uniformly to every condition in a comparison.
    """
    b = (backend or "").strip().lower()
    m = (model or "").strip().lower()

    if b == "claude":
        # Claude API pricing, standard global routing. Cache-write TTL is
        # carried per event: five-minute writes cost 1.25x, one-hour 2x.
        # Fable 5.1 and Mythos 5.1 keep Fable 5's per-token rates but read
        # their cache at 0.025x ($0.25/MTok), so they need their own row.
        if _model_id_is(m, "claude-fable-5-1", "claude-mythos-5-1"):
            return {
                "input": _money("10"),
                "cache_write": _money("12.50"),
                "cache_write_1h": _money("20"),
                "cache_read": _money("0.25"),
                "output": _money("50"),
                "source": "claude-api-fable-5.1",
            }
        if _model_id_is(m, "claude-fable-5", "claude-mythos-5"):
            return {
                "input": _money("10"),
                "cache_write": _money("12.50"),
                "cache_write_1h": _money("20"),
                "cache_read": _money("1"),
                "output": _money("50"),
                "source": "claude-api-fable-5",
            }
        # Announced as introductory pricing through 2026-08-31, then made the
        # standard price: Anthropic cancelled the scheduled $3/$15 increase,
        # so this is flat and no longer keys on the pricing day.
        if _model_id_is(m, "claude-sonnet-5"):
            return {
                "input": _money("2"),
                "cache_write": _money("2.50"),
                "cache_write_1h": _money("4"),
                "cache_read": _money("0.20"),
                "output": _money("10"),
                "source": "claude-api-sonnet-5-standard",
            }
        if _model_id_is(
            m,
            "claude-opus-5",
            "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6",
            "claude-opus-4-5",
        ):
            return {
                "input": _money("5"),
                "cache_write": _money("6.25"),
                "cache_write_1h": _money("10"),
                "cache_read": _money("0.50"),
                "output": _money("25"),
                "source": "claude-api-opus-4.5-5",
            }
        if _model_id_is(
            m,
            "claude-opus-4-1", "claude-opus-4", "claude-3-opus",
        ):
            return {
                "input": _money("15"),
                "cache_write": _money("18.75"),
                "cache_write_1h": _money("30"),
                "cache_read": _money("1.50"),
                "output": _money("75"),
                "source": "claude-api-opus-3/4/4.1",
            }
        # Sonnet 4 and 4.5 carried a >200k premium only under the retired 1M
        # context beta. Their context window is 200k again, so a real request
        # can no longer reach the threshold: every firing of that tier came
        # from the per-request estimate overshooting, which doubled the input
        # rate and marked the cell estimated. One flat rate, like every other
        # Sonnet.
        if _model_id_is(
            m,
            "claude-sonnet-4-6", "claude-sonnet-4-5", "claude-sonnet-4",
            "claude-3-7-sonnet", "claude-3-5-sonnet", "claude-3-sonnet",
        ):
            return {
                "input": _money("3"),
                "cache_write": _money("3.75"),
                "cache_write_1h": _money("6"),
                "cache_read": _money("0.30"),
                "output": _money("15"),
                "source": "claude-api-sonnet-3-4.6",
            }
        if _model_id_is(m, "claude-haiku-4-5"):
            return {
                "input": _money("1"),
                "cache_write": _money("1.25"),
                "cache_write_1h": _money("2"),
                "cache_read": _money("0.10"),
                "output": _money("5"),
                "source": "claude-api-haiku-4.5",
            }
        if _model_id_is(m, "claude-3-5-haiku"):
            return {
                "input": _money("0.80"),
                "cache_write": _money("1"),
                "cache_write_1h": _money("1.60"),
                "cache_read": _money("0.08"),
                "output": _money("4"),
                "source": "claude-api-haiku-3.5",
            }
        if _model_id_is(m, "claude-3-haiku"):
            return {
                "input": _money("0.25"),
                "cache_write": _money("0.30"),
                "cache_write_1h": _money("0.50"),
                "cache_read": _money("0.03"),
                "output": _money("1.25"),
                "source": "claude-api-haiku-3",
            }

    if b in {"codex", "oss"}:
        # GPT-5.6 renamed the former flagship/mini/nano tiers to
        # Sol/Terra/Luna. The unsuffixed alias routes to Sol.
        #
        # A rate keys on the pricing day only where the vendor publishes the
        # date, as Gemini Flash does below. Guessing one is worse than not
        # dating at all: a made-up boundary silently restates a completed run's
        # spend on the day it passes, and it reads as sourced. OpenAI says only
        # that Sol's promotional pricing runs "at least through November 21,
        # 2026" — a floor with no start, and no post-promotion rate published —
        # so there is nothing here to encode but the price in force.
        if _model_id_is(m, "gpt-5.6-luna"):
            return {
                "tiered": True,
                "threshold": 272_000,
                "input_low": _money("0.20"),
                "input_high": _money("0.40"),
                "cache_write_low": _money("0.25"),
                "cache_write_high": _money("0.50"),
                "cache_read_low": _money("0.02"),
                "cache_read_high": _money("0.04"),
                "output_low": _money("1.20"),
                "output_high": _money("1.80"),
                "source": "openai-api-gpt-5.6-luna-standard",
            }
        if _model_id_is(m, "gpt-5.6-terra"):
            return {
                "tiered": True,
                "threshold": 272_000,
                "input_low": _money("2"),
                "input_high": _money("4"),
                "cache_write_low": _money("2.50"),
                "cache_write_high": _money("5"),
                "cache_read_low": _money("0.20"),
                "cache_read_high": _money("0.40"),
                "output_low": _money("12"),
                "output_high": _money("18"),
                "source": "openai-api-gpt-5.6-terra-standard",
            }
        # Trusted-access cyber models: one flat rate, no long-context tier.
        # gpt-daybreak-red-latest is OpenAI's alias for the current cyber
        # model; gpt-daybreak-blue-latest aliases the flagship (Sol) below.
        if _model_id_is(m, "gpt-5.6-cyber", "gpt-daybreak-red-latest"):
            return {
                "input": _money("12.50"),
                "cache_write": _money("15.625"),
                "cache_read": _money("1.25"),
                "output": _money("75"),
                "source": "openai-api-gpt-5.6-cyber-standard",
            }
        if _model_id_is(m, "gpt-5.5-cyber"):
            return {
                "input": _money("12.50"),
                "cache_read": _money("1.25"),
                "output": _money("75"),
                "source": "openai-api-gpt-5.5-cyber-standard",
            }
        if _model_id_is(m, "gpt-5.6", "gpt-5.6-sol", "gpt-daybreak-blue-latest"):
            return {
                "tiered": True,
                "threshold": 272_000,
                "input_low": _money("4"),
                "input_high": _money("8"),
                "cache_write_low": _money("5"),
                "cache_write_high": _money("10"),
                "cache_read_low": _money("0.40"),
                "cache_read_high": _money("0.80"),
                "output_low": _money("20"),
                "output_high": _money("30"),
                "source": "openai-api-gpt-5.6-sol-standard",
            }
        if _model_id_is(m, "gpt-5.5-pro"):
            return {
                "tiered": True,
                "threshold": 272_000,
                "input_low": _money("30"),
                "input_high": _money("60"),
                "cache_read_low": _money("0"),
                "cache_read_high": _money("0"),
                "output_low": _money("180"),
                "output_high": _money("270"),
                "source": "openai-api-gpt-5.5-pro-standard",
            }
        if _model_id_is(m, "gpt-5.5"):
            return {
                "tiered": True,
                "threshold": 272_000,
                "input_low": _money("5"),
                "input_high": _money("10"),
                "cache_read_low": _money("0.50"),
                "cache_read_high": _money("1"),
                "output_low": _money("30"),
                "output_high": _money("45"),
                "source": "openai-api-gpt-5.5-standard",
            }
        if _model_id_is(m, "gpt-5.4-mini"):
            return {
                "input": _money("0.75"),
                "cache_read": _money("0.075"),
                "output": _money("4.50"),
                "source": "openai-api-gpt-5.4-mini",
            }
        if _model_id_is(m, "gpt-5.4-nano"):
            return {
                "input": _money("0.20"),
                "cache_read": _money("0.02"),
                "output": _money("1.25"),
                "source": "openai-api-gpt-5.4-nano",
            }
        if _model_id_is(m, "gpt-5.4-pro"):
            return {
                "tiered": True,
                "threshold": 272_000,
                "input_low": _money("30"),
                "input_high": _money("60"),
                "cache_read_low": _money("0"),
                "cache_read_high": _money("0"),
                "output_low": _money("180"),
                "output_high": _money("270"),
                "source": "openai-api-gpt-5.4-pro-standard",
            }
        if _model_id_is(m, "gpt-5.4"):
            return {
                "tiered": True,
                "threshold": 272_000,
                "input_low": _money("2.50"),
                "input_high": _money("5"),
                "cache_read_low": _money("0.25"),
                "cache_read_high": _money("0.50"),
                "output_low": _money("15"),
                "output_high": _money("22.50"),
                "source": "openai-api-gpt-5.4-standard",
            }
        # Remaining standard-tier text models on OpenAI's public rate card.
        # Specific snapshots with exceptional prices precede their aliases.
        openai_flat = (
            (("gpt-5.3-codex",), "1.75", "0.175", "14"),
            (("gpt-5.2-pro",), "21", None, "168"),
            (("gpt-5.2",), "1.75", "0.175", "14"),
            (("gpt-5.1",), "1.25", "0.125", "10"),
            (("gpt-5-pro",), "15", None, "120"),
            (("gpt-5-mini",), "0.25", "0.025", "2"),
            (("gpt-5-nano",), "0.05", "0.005", "0.40"),
            (("gpt-5",), "1.25", "0.125", "10"),
            (("gpt-4.1-mini",), "0.40", "0.10", "1.60"),
            (("gpt-4.1-nano",), "0.10", "0.025", "0.40"),
            (("gpt-4.1",), "2", "0.50", "8"),
            (("gpt-4o-2024-05-13",), "5", None, "15"),
            (("gpt-4o-mini",), "0.15", "0.075", "0.60"),
            (("gpt-4o",), "2.50", "1.25", "10"),
            (("o1-pro",), "150", None, "600"),
            (("o1-mini",), "1.10", "0.55", "4.40"),
            (("o1",), "15", "7.50", "60"),
            (("o3-pro",), "20", None, "80"),
            (("o3-mini",), "1.10", "0.55", "4.40"),
            (("o3",), "2", "0.50", "8"),
            (("o4-mini",), "1.10", "0.275", "4.40"),
            (("gpt-4-turbo", "gpt-4-turbo-2024-04-09"), "10", None, "30"),
            (("gpt-4-0125-preview", "gpt-4-1106-preview",
              "gpt-4-1106-vision-preview"), "10", None, "30"),
            (("gpt-4-0613", "gpt-4-0314"), "30", None, "60"),
            (("gpt-4-32k",), "60", None, "120"),
            (("gpt-3.5-turbo", "gpt-3.5-turbo-0125"), "0.50", None, "1.50"),
            (("gpt-3.5-turbo-1106",), "1", None, "2"),
            (("gpt-3.5-turbo-0613", "gpt-3.5-0301",
              "gpt-3.5-turbo-instruct"), "1.50", None, "2"),
            (("gpt-3.5-turbo-16k-0613",), "3", None, "4"),
            (("davinci-002",), "2", None, "2"),
            (("babbage-002",), "0.40", None, "0.40"),
        )
        for model_ids, input_rate, cache_rate, output_rate in openai_flat:
            if not _model_id_is(m, *model_ids):
                continue
            rates = {
                "input": _money(input_rate),
                "output": _money(output_rate),
                "source": f"openai-api-{model_ids[0]}-standard",
            }
            if cache_rate is not None:
                rates["cache_read"] = _money(cache_rate)
            return rates

    if b == "gemini":
        # Both Flash generations are on the same promotion, which Google says
        # runs through 2026-12-31.
        if _model_id_is(m, "gemini-3.7-flash", "gemini-3.6-flash"):
            generation = (
                "3.7" if _model_id_is(m, "gemini-3.7-flash") else "3.6"
            )
            return {
                "input": _money("0.75"),
                "cache_read": _money("0.075"),
                "output": _money("3.75"),
                "source": f"gemini-api-{generation}-flash-standard",
            }
        if _model_id_is(m, "gemini-3.5-flash"):
            return {
                "input": _money("1.50"),
                "cache_read": _money("0.15"),
                "output": _money("9"),
                "source": "gemini-api-3.5-flash-standard",
            }
        if _model_id_is(m, "gemini-3.5-flash-lite"):
            return {
                "input": _money("0.30"),
                "cache_read": _money("0.03"),
                "output": _money("2.50"),
                "source": "gemini-api-3.5-flash-lite-standard",
            }
        if _model_id_is(
            m,
            "gemini-3.1-pro-preview",
            "gemini-3.1-pro-preview-customtools",
            "gemini-3-pro-preview",
        ):
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
        if _model_id_is(m, "gemini-3.1-flash-lite"):
            return {
                "input": _money("0.25"),
                "cache_read": _money("0.025"),
                "output": _money("1.50"),
                "source": "gemini-api-3.1-flash-lite-standard",
            }
        if _model_id_is(m, "gemini-3-flash-preview"):
            return {
                "input": _money("0.50"),
                "cache_read": _money("0.05"),
                "output": _money("3"),
                "source": "gemini-api-3-flash-standard",
            }
        if _model_id_is(m, "gemini-2.5-pro"):
            return {
                "tiered": True,
                "threshold": 200_000,
                "input_low": _money("1.25"),
                "input_high": _money("2.50"),
                "cache_read_low": _money("0.125"),
                "cache_read_high": _money("0.25"),
                "output_low": _money("10"),
                "output_high": _money("15"),
                "source": "gemini-api-2.5-pro-standard",
            }
        if _model_id_is(m, "gemini-2.5-flash"):
            return {
                "input": _money("0.30"),
                "cache_read": _money("0.03"),
                "output": _money("2.50"),
                "source": "gemini-api-2.5-flash-standard",
            }
        if _model_id_is(
            m, "gemini-2.5-flash-lite", "gemini-2.5-flash-lite-preview-09-2025",
        ):
            return {
                "input": _money("0.10"),
                "cache_read": _money("0.01"),
                "output": _money("0.40"),
                "source": "gemini-api-2.5-flash-lite-standard",
            }
        if _model_id_is(m, "gemini-2.0-flash"):
            return {
                "input": _money("0.10"),
                "cache_read": _money("0.025"),
                "output": _money("0.40"),
                "source": "gemini-api-2.0-flash-standard-retired",
            }
        if _model_id_is(m, "gemini-2.0-flash-lite"):
            return {
                "input": _money("0.075"),
                "cache_read": _money("0"),
                "output": _money("0.30"),
                "source": "gemini-api-2.0-flash-lite-standard-retired",
            }

    if b == "grok":
        # xAI long-context pricing: a prompt at or past the threshold bills
        # every token in the request at the higher rate. xAI's low tier is
        # "< 200k", unlike Anthropic's and Google's "<= 200k", so the boundary
        # itself is billed high here and low there. Cache writes have no
        # separate rate and bill as base input.
        if _model_id_is(m, "grok-build-0.1"):
            return {
                "tiered": True,
                "threshold": 200_000,
                "threshold_inclusive": True,
                "input_low": _money("1"),
                "input_high": _money("2"),
                "cache_read_low": _money("0.20"),
                "cache_read_high": _money("0.40"),
                "output_low": _money("2"),
                "output_high": _money("4"),
                "source": "xai-code-api-grok-build-0.1",
            }
        if _model_id_is(m, "grok-4.6"):
            return {
                "tiered": True,
                "threshold": 200_000,
                "threshold_inclusive": True,
                "input_low": _money("2"),
                "input_high": _money("4"),
                "cache_read_low": _money("0.50"),
                "cache_read_high": _money("1"),
                "output_low": _money("6"),
                "output_high": _money("12"),
                "source": "xai-chat-api-grok-4.6",
            }
        if _model_id_is(m, "grok-4.5"):
            return {
                "tiered": True,
                "threshold": 200_000,
                "threshold_inclusive": True,
                "input_low": _money("2"),
                "input_high": _money("4"),
                "cache_read_low": _money("0.30"),
                "cache_read_high": _money("0.60"),
                "output_low": _money("6"),
                "output_high": _money("12"),
                "source": "xai-chat-api-grok-4.5",
            }
        if _model_id_is(
            m,
            "grok-4.3",
            "grok-4.20-multi-agent-0309",
            "grok-4.20-0309-reasoning",
            "grok-4.20-0309-non-reasoning",
        ):
            return {
                "tiered": True,
                "threshold": 200_000,
                "threshold_inclusive": True,
                "input_low": _money("1.25"),
                "input_high": _money("2.50"),
                "cache_read_low": _money("0.20"),
                "cache_read_high": _money("0.40"),
                "output_low": _money("2.50"),
                "output_high": _money("5"),
                "source": "xai-chat-api-grok-4.3/4.20",
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
    cache_creation_1h_tokens: int = 0,
    prompt_tokens_for_tier: int | None = None,
) -> tuple[Decimal | None, str]:
    rates = _pricing_rates(backend, model)
    if not rates:
        return None, "unknown"

    inp = Decimal(_as_nonnegative_int(input_tokens))
    cached = Decimal(_as_nonnegative_int(cached_input_tokens))
    out = Decimal(_as_nonnegative_int(output_tokens))
    cache_create = Decimal(_as_nonnegative_int(cache_creation_tokens))
    cache_create_1h = min(
        cache_create, Decimal(_as_nonnegative_int(cache_creation_1h_tokens))
    )

    if rates.get("tiered"):
        prompt = _as_nonnegative_int(prompt_tokens_for_tier or input_tokens)
        threshold = int(rates["threshold"])
        high = (
            prompt >= threshold
            if rates.get("threshold_inclusive")
            else prompt > threshold
        )
        input_rate = rates["input_high" if high else "input_low"]
        cache_rate = rates["cache_read_high" if high else "cache_read_low"]
        output_rate = rates["output_high" if high else "output_low"]
        write_rate = rates.get(
            "cache_write_high" if high else "cache_write_low",
            input_rate,
        )
        # A separately priced one-hour cache write is Anthropic-only, and no
        # Claude model is tiered, so the tiered branch has one write rate.
        write_1h_rate = write_rate
        fresh_input = max(Decimal("0"), inp - cache_create)
        cost = (
            fresh_input * input_rate
            + (cache_create - cache_create_1h) * write_rate
            + cache_create_1h * write_1h_rate
            + cached * cache_rate
            + out * output_rate
        ) / _MILLION
        return cost, str(rates["source"])

    input_rate = rates["input"]
    cache_rate = rates.get("cache_read", Decimal("0"))
    output_rate = rates["output"]
    write_rate = rates.get("cache_write", input_rate)
    write_1h_rate = rates.get("cache_write_1h", write_rate)

    # `input_tokens` is the normalized full-rate bucket. For Claude it
    # includes cache writes for comparability; pricing needs the split
    # because cache writes are 1.25x base input.
    fresh_input = max(Decimal("0"), inp - cache_create)
    cost = (
        fresh_input * input_rate
        + (cache_create - cache_create_1h) * write_rate
        + cache_create_1h * write_1h_rate
        + cached * cache_rate
        + out * output_rate
    ) / _MILLION
    return cost, str(rates["source"])


def _decimal_text(value: Decimal | None) -> str:
    if value is None or not value.is_finite():
        return ""
    return format(value.quantize(Decimal("0.000001"), rounding=ROUND_HALF_UP), "f")


def _fmt_usd(value: object, estimated: bool = False) -> str:
    try:
        dec = Decimal(str(value))
        if not dec.is_finite():
            return "—"
        amount = dec.quantize(Decimal("0.0001"), rounding=ROUND_HALF_UP)
    except Exception:
        return "—"
    prefix = "~" if estimated else ""
    return f"{prefix}${amount:,.4f}"


def harvest_finalization_tokens(
    index_jsonl: Path,
    default_backend: str = "",
    default_model: str = "",
) -> dict:
    """The measurement subset of a cell's token spend, or {} when unmarked.

    Post-cell adjudication writes to the same index the audit does, so a cell
    that re-reviews a large corpus reports a token and cost total dominated by
    work that found nothing -- one re-review moved a direct cell from 13.9M to
    24.9M input. The published columns stay combined on purpose: this is the
    breakdown, recorded beside them, not a second number in the table.

    Split by the `.finalization_started` stamp rather than by decision role,
    because in-run housekeeping decisions steer the audit and belong to it.
    Runs predating the stamp return {} rather than a guess.
    """
    marker = Path(index_jsonl).parent / ".finalization_started"
    try:
        started = marker.read_text(encoding="utf-8").strip()
    except OSError:
        return {}
    if not started:
        return {}
    rows: list[str] = []
    try:
        for line in Path(index_jsonl).read_text(
            encoding="utf-8", errors="replace",
        ).splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                row = json.loads(stripped)
            except ValueError:
                continue
            if isinstance(row, dict) and str(row.get("timestamp") or "") >= started:
                rows.append(stripped)
    except OSError:
        return {}
    if not rows:
        return {"started_at": started}
    totals = harvest_tokens(
        Path(index_jsonl), default_backend=default_backend,
        default_model=default_model, lines=rows,
    )
    totals["started_at"] = started
    return totals


def harvest_tokens(
    index_jsonl: Path,
    default_backend: str = "",
    default_model: str = "",
    prompt_estimate_fallback: int = 0,
    lines: list[str] | None = None,
) -> dict:
    """Sum token usage + sanitizer invocations from a logs/index.jsonl.

    Counts are normalized so a field means the same thing on every
    backend, which is what makes a cross-condition cost comparison fair:

      * input_tokens — tokens the model processed this turn at the
        full input rate (≥100%). On Claude this is `input + cache_creation`
        (cache writes are billed at 125% or 200% of base input and represent
        genuinely new content the model just read). On codex/oss/gemini/grok
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
        # One row per usage-bearing ledger entry: agent sessions plus the
        # harness's own LLM-decision and probe rows. Not a count of iterations
        # or of sessions -- a single iteration writes many rows.
        "usage_records": 0,
        "input_tokens": 0,
        "cached_input_tokens": 0,
        "cache_creation_tokens": 0,
        "cache_creation_1h_tokens": 0,
        "output_tokens": 0,
        # Sanitizer execution is counted in metrics["execution"] and copied
        # onto the audit tokens row; the cost ledger never carried it.
        "asan_invocations": 0,
        # prompt_estimate is the only input-token signal from backends whose
        # CLI omits usage (Antigravity and Grok Build), so the harness
        # estimates the prompt side. Summed here so such a cell
        # is not silently scored as zero-cost.
        "prompt_estimate_tokens": 0,
        # Subagent spawns the transcripts actually show (Claude `Agent`,
        # OpenCode `task`, Codex `spawn_agent` in its rollout). A cell is one
        # launch by contract; this says what that launch did with the CLI's
        # default delegation, so a seat-hour figure is read against it.
        "delegation_events": 0,
        # True when a row's delegated work ran where its usage cannot see it
        # (Codex threads, OpenCode sessions): the cell's spend is a floor.
        "spend_lower_bound": False,
        # False when a row's backend cannot show its fan-out at all (Grok);
        # the cell's seat capacity is then a floor whatever was counted.
        "delegation_observable": True,
        "estimated": False,
        "cost_estimated": False,
        "cost_usd": "",
        "cost_source": "",
        "token_source": "unknown",
    }
    if lines is None:
        if not index_jsonl.is_file():
            return totals
        try:
            lines = index_jsonl.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines()
        except OSError:
            return totals

    def _int(value: object) -> int:
        return _as_nonnegative_int(value)

    token_sources: set[str] = set()
    cost_sources: set[str] = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if not isinstance(row, dict):
            continue
        totals["usage_records"] += 1
        totals["delegation_events"] += _int(row.get("delegation_events"))
        if row.get("spend_lower_bound") is True:
            totals["spend_lower_bound"] = True
        if row.get("delegation_observable") is False:
            totals["delegation_observable"] = False
        backend = str(row.get("backend") or default_backend or "").strip().lower()
        model = str(row.get("model") or default_model or "").strip()
        # A row names the model it asked for; when the provider billed the
        # work to another (llm_usage.annotate_served_model), that one's rate
        # card is the honest denominator.
        model = str(row.get("served_model") or model).strip()
        tok = row.get("tokens") or {}
        if not isinstance(tok, dict):
            tok = {}
        raw_input = _int(tok.get("input"))
        # cache_read is written as `cached_input` by both the harness and
        # the model-direct extractor; `cache_read` is a harness-only alias.
        cache_read = _int(tok.get("cached_input")) or _int(tok.get("cache_read"))
        cache_creation = _int(tok.get("cache_creation"))
        cache_creation_1h = min(
            cache_creation, _int(tok.get("cache_creation_1h"))
        )
        if backend in _INPUT_INCLUDES_CACHED:
            full_rate_input = max(0, raw_input - cache_read)
        else:
            # Claude's `input` excludes both cache hits AND cache writes;
            # cache_creation is billed at 125%/200% of base input rate and is
            # genuinely fresh content the model just processed, so it
            # belongs in the full-rate bucket alongside `input`.
            full_rate_input = raw_input + cache_creation
        output = _int(tok.get("output"))
        prompt_estimate = (
            _int(tok.get("prompt_estimate"))
            or _int(tok.get("prompt_estimate_build"))
        )
        # Classify on whether the row CONTRIBUTED usage, not on how its
        # invocation exited. `usage_complete` is false for every nonzero exit,
        # including a timed-out session that still reported full counters and
        # a backend-reported cost — that spend is in the total, so calling the
        # total incomplete because of it marks a cell that is missing nothing.
        if row.get("estimated") is True:
            token_sources.add("estimated")
        elif any((raw_input, cache_read, cache_creation, output, prompt_estimate)):
            token_sources.add("measured")
        else:
            # A missing terminal usage event is unknown, even when later
            # validators in the same productive cell report measured usage.
            token_sources.add("unknown")
        totals["input_tokens"] += full_rate_input
        totals["cached_input_tokens"] += cache_read
        totals["cache_creation_tokens"] += cache_creation
        totals["cache_creation_1h_tokens"] += cache_creation_1h
        totals["output_tokens"] += output
        # Tiered long-context pricing (e.g. gpt-5.5 @272K) is a PER-REQUEST
        # boundary, but `raw_input` is the session's input summed across every
        # request, so it crosses the threshold on conversation length alone and
        # pins ~all multi-turn sessions to the high tier. Tier on the per-request
        # prompt size instead: prompt_chars is the rendered request captured by
        # audit_runner; fall back to legacy prompt estimates, then the caller's
        # prompt_estimate_fallback (model-direct has no harness stash, so harvest
        # derives this from the cell's persisted prompt.txt), then raw_input for
        # rows that predate every estimate. Underestimates within-session context
        # growth past the threshold, but errs far smaller than tiering on the
        # cumulative sum.
        tier_basis = (
            (_int(row.get("prompt_chars")) + 3) // 4
            or _int(tok.get("prompt_estimate_build"))
            or _int(tok.get("prompt_estimate"))
            or prompt_estimate_fallback
            or raw_input
        )
        if prompt_estimate:
            totals["prompt_estimate_tokens"] += prompt_estimate
        estimated_pricing = bool(
            raw_input == 0
            and prompt_estimate
            and backend in ("gemini", "grok")
        )
        pricing_input = prompt_estimate if estimated_pricing else full_rate_input
        try:
            event_cost = Decimal(str(row.get("cost_usd")))
        except Exception:
            event_cost = None
        if event_cost is not None and not event_cost.is_finite():
            event_cost = None
        source = str(row.get("cost_source") or "")
        used_rate_card = event_cost is None or event_cost < 0
        if used_rate_card:
            event_cost, source = _cost_decimal(
                backend,
                model,
                input_tokens=pricing_input,
                cached_input_tokens=cache_read,
                output_tokens=output,
                cache_creation_tokens=cache_creation,
                cache_creation_1h_tokens=cache_creation_1h,
                prompt_tokens_for_tier=tier_basis,
            )
        if event_cost is not None:
            totals["cost_usd"] = _decimal_text(
                Decimal(totals["cost_usd"] or "0") + event_cost
            )
            if source:
                cost_sources.add(source)
        if used_rate_card and event_cost is not None:
            rates = _pricing_rates(backend, model)
            # The threshold is per provider request, while CLI telemetry is an
            # invocation aggregate. The selected tier is the best available
            # reconstruction, not a backend-reported invoice amount.
            if estimated_pricing or row.get("estimated") is True or (
                rates is not None and rates.get("tiered")
            ):
                totals["cost_estimated"] = True
        if row.get("estimated") is True or estimated_pricing:
            totals["estimated"] = True
    if cost_sources:
        totals["cost_source"] = (
            next(iter(cost_sources)) if len(cost_sources) == 1 else "mixed"
        )
    if token_sources:
        # An `unknown` row is a productive session whose usage was never
        # recorded, so the cell total OMITS real cost. That must dominate the
        # rollup: otherwise it hides inside the estimated+measured `mixed` that
        # every normal cell already reports, and an understated total reads as
        # a clean measurement.
        if "unknown" in token_sources:
            totals["token_source"] = "unknown"
        elif len(token_sources) == 1:
            totals["token_source"] = next(iter(token_sources))
        else:
            totals["token_source"] = "mixed"
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
    return llm_usage.find_usage_index(results_dir)


def harvest_execution(
    results_dir: Path,
    *,
    raw_log: Path | None = None,
    crash_floor: int = 0,
) -> dict:
    """Read passive execution telemetry without influencing audit behavior.

    ``bin/probe`` records one row per sanctioned probe in ``state/runs.jsonl``
    and preserves the requested sanitizer repetition count.  A confirmed crash
    floors it, because a crash is proof of at least one run.  Both are exact
    and stay exact.

    ``sanitizer_command_requests`` is a separate, inexact signal and is never
    merged into them.  A model-direct cell drives the sanitizer build by hand
    and writes no probe state, so the exact counters are legitimately zero for
    it — but zero also used to be the answer for a cell that fuzzed for four
    hours, and the two are not the same claim.  The request count separates
    them without pretending to be an execution total; see
    ``audit_helpers.count_sanitizer_command_requests`` for both directions it
    is wrong in.
    """
    path = results_dir / "state" / "runs.jsonl"
    probe_records = 0
    structured_invocations = 0
    by_sanitizer: dict[str, int] = {}
    by_verdict: dict[str, int] = {}
    if path.is_file():
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            lines = []
        for line in lines:
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if not isinstance(row, dict):
                continue
            probe_records += 1
            runs = (
                _as_nonnegative_int(row.get("sanitizer_runs"))
                if "sanitizer_runs" in row else 1
            )
            structured_invocations += runs
            sanitizer = str(row.get("sanitizer") or "unknown").strip().lower()
            verdict = str(row.get("verdict") or "UNKNOWN").strip().upper()
            by_sanitizer[sanitizer] = by_sanitizer.get(sanitizer, 0) + runs
            by_verdict[verdict] = by_verdict.get(verdict, 0) + runs

    # Read only when there is no probe state to read: a harness cell's agents
    # export the same options through bin/probe, so the two describe the same
    # work and reporting both would invite adding them.
    command_requests = 0
    if not probe_records and raw_log is not None and raw_log.is_file():
        command_requests = audit_helpers.count_sanitizer_command_requests(raw_log)
    crash_floor = _as_nonnegative_int(crash_floor)
    sanitizer_invocations = max(structured_invocations, crash_floor)
    if probe_records:
        source = "state/runs.jsonl"
    elif crash_floor:
        source = "crash-floor"
    else:
        source = "none"
    return {
        "probe_records": probe_records,
        "sanitizer_invocations": sanitizer_invocations,
        "structured_sanitizer_invocations": structured_invocations,
        # Inexact and separately named on purpose — see the docstring.
        "sanitizer_command_requests": command_requests,
        "crash_floor": crash_floor,
        "by_sanitizer": dict(sorted(by_sanitizer.items())),
        "by_verdict": dict(sorted(by_verdict.items())),
        "source": source,
    }


def _read_metric_report(path: Path | None) -> str:
    """Read enough report text for passive metrics without unbounded I/O."""
    if path is None:
        return ""
    try:
        with path.open("rb") as stream:
            return stream.read(_MAX_SCAN_BYTES).decode("utf-8", errors="replace")
    except OSError:
        return ""


def harvest_artifact_links(
    results_dir: Path,
    finding_names: list[str],
    crash_names: list[str],
) -> dict:
    """Describe existing duplicate and cross-kind evidence without acting on it."""
    records: dict[str, tuple[str, str]] = {}
    clusters: dict[tuple[str, str], list[str]] = {}
    for kind, parent, names in (
        ("finding", results_dir / "findings", finding_names),
        ("crash", results_dir / "crashes", crash_names),
    ):
        for name in sorted(names):
            report = report_identity.find_report(parent / name)
            text = _read_metric_report(report)
            cluster = cluster_common.cluster_label(text)
            records[name] = (kind, text)
            if cluster:
                clusters.setdefault((kind, cluster), []).append(name)

    duplicate_groups = [
        {"kind": kind, "cluster": cluster, "members": sorted(members)}
        for (kind, cluster), members in sorted(clusters.items())
        if len(members) > 1
    ]
    cross_kind: set[tuple[str, str]] = set()
    for name, (kind, text) in records.items():
        for reference in _ARTIFACT_REF_RE.findall(text):
            other = records.get(reference)
            if other is None or other[0] == kind:
                continue
            finding, crash = (
                (name, reference) if kind == "finding" else (reference, name)
            )
            cross_kind.add((finding, crash))
    return {
        "duplicate_groups": duplicate_groups,
        "cross_kind": [
            {
                "finding": finding,
                "crash": crash,
                "evidence": "explicit-reference",
            }
            for finding, crash in sorted(cross_kind)
        ],
    }


def _trigger_snapshot(directory: Path) -> tuple[str, set[str]]:
    signals: set[str] = set()
    observed = False
    report = report_identity.find_report(directory)
    report_sha1s = (
        report_identity.content_sha1_candidates(report) if report else frozenset()
    )
    resolution_path = directory / ".trigger-gate-resolution.json"
    resolution_payload = _read_json(resolution_path)
    resolution_vote = _current_trigger_vote(
        resolution_payload, report_sha1s, directory,
    )
    if resolution_vote is not None:
        signals.add(resolution_vote)
        observed = True
    for name in (".trigger-gate.json", ".trigger-gate-2.json"):
        payload = _read_json(directory / name)
        if payload.get("vote") not in {"Promote", "Reject", "Uncertain"}:
            continue
        observed = True
        vote = _current_trigger_vote(payload, report_sha1s, directory)
        if vote is None:
            continue
        if resolution_vote is None:
            signals.add(vote)
    bypass = _read_json(directory / ".trigger-gate-bypass.json").get("bypass") is True
    if bypass:
        signals.add("Promote")
    if "Promote" in signals and "Reject" in signals:
        state = "conflict"
    elif "Reject" in signals:
        state = "reject"
    elif bypass:
        state = "bypass"
    elif "Promote" in signals:
        state = "promote"
    elif "Uncertain" in signals:
        state = "uncertain"
    elif observed:
        state = "stale"
    else:
        state = "missing"
    return state, signals


def harvest_gate_states(results_dir: Path) -> list[dict]:
    """Snapshot existing gate evidence without recomputing any disposition."""
    rows: list[dict] = []
    for kind, location, prefix, rejected in (
        ("finding", "findings", "FIND-", False),
        ("finding", "findings-rejected", "FIND-", True),
        ("crash", "crashes", "CRASH-", False),
        ("crash", "crashes-rejected", "CRASH-", True),
    ):
        parent = results_dir / location
        if not parent.is_dir():
            continue
        for directory in sorted(parent.iterdir()):
            if not directory.is_dir() or not directory.name.startswith(prefix):
                continue
            report = report_identity.find_report(directory)
            report_text = _read_metric_report(report)
            receipt = validation_receipt.read_current(directory)
            if receipt is not None and receipt.get("kind") != kind:
                receipt = None
            validation = (
                str(receipt.get("state"))
                if receipt is not None else "legacy-provisional"
            )
            trigger, trigger_signals = _trigger_snapshot(directory)
            conflicts: list[str] = []
            if "Promote" in trigger_signals and "Reject" in trigger_signals:
                conflicts.append("trigger-votes")

            if kind == "finding":
                cache = _read_json(directory / ".llm-find-quality.json")
                if _finding_is_pinned(directory):
                    quality = "override"
                elif cache and not report_identity.quality_cache_matches_report(
                    directory, cache,
                ):
                    quality = "stale"
                elif cache.get("accept") is True:
                    quality = "accept"
                elif cache.get("accept") is False:
                    quality = "reject"
                elif cache:
                    quality = "pending"
                else:
                    quality = "missing"
                accept_count = _as_nonnegative_int(cache.get("accept_count"))
                reject_count = _as_nonnegative_int(cache.get("reject_count"))
                if accept_count and reject_count:
                    conflicts.append("quality-votes")
                reproduced = False
                evidence_complete = (
                    quality in {"accept", "override"}
                    and (
                        trigger in {"promote", "reject", "bypass"}
                        or validation in (
                            validation_receipt.FINAL_STATES | {"rejected"}
                        )
                    )
                )
                pending = (
                    not rejected
                    and validation not in validation_receipt.FINAL_STATES
                )
            else:
                quality = "not-applicable"
                reproduced = dir_has_sanitizer_output(directory)
                sanitizer = crash_artifacts.find_primary_sanitizer(
                    (directory, directory / ".audit"),
                )
                evidence_complete = (
                    reproduced
                    and sanitizer is not None
                    and crash_artifacts.find_testcase(
                        (directory, directory / ".audit"),
                        sanitizer_files=(sanitizer,),
                    ) is not None
                )
                pending = (
                    not rejected
                    and (
                        validation not in validation_receipt.FINAL_STATES
                        or crash_is_pending(directory)
                    )
                )
            disposition = "rejected" if rejected else "pending" if pending else "accepted"
            rows.append({
                "id": directory.name,
                "kind": kind,
                "location": location,
                "disposition": disposition,
                "quality": quality,
                "trigger": trigger,
                "validation": validation,
                "reproduced": reproduced,
                "evidence_complete": evidence_complete,
                "pending": pending,
                "conflicts": conflicts,
                "_report_text": report_text,
                "_trigger_signals": trigger_signals,
            })

    by_id = {row["id"]: row for row in rows}
    for row in rows:
        for reference in _ARTIFACT_REF_RE.findall(row["_report_text"]):
            other = by_id.get(reference)
            if other is None or other["kind"] == row["kind"]:
                continue
            finding = row if row["kind"] == "finding" else other
            crash = other if row["kind"] == "finding" else row
            if crash["reproduced"]:
                finding["reproduced"] = True
            combined = row["_trigger_signals"] | other["_trigger_signals"]
            if "Promote" in combined and "Reject" in combined:
                for linked in (row, other):
                    if "linked-trigger" not in linked["conflicts"]:
                        linked["conflicts"].append("linked-trigger")
    for row in rows:
        row["conflicts"].sort()
        del row["_report_text"]
        del row["_trigger_signals"]
    return rows


def validation_waterfall(
    gate_states: list[dict], *, crash_signatures: int, finding_signatures: int,
) -> dict:
    """Expose evidence and publication stages without inventing root causes."""
    out: dict[str, dict] = {}
    for kind, singular, signatures in (
        ("crashes", "crash", crash_signatures),
        ("findings", "finding", finding_signatures),
    ):
        rows = [row for row in gate_states if row.get("kind") == singular]
        out[kind] = {
            "candidates": len(rows),
            "evidence_complete": sum(
                bool(row.get("evidence_complete")) for row in rows
            ),
            "validated": sum(
                row.get("disposition") == "rejected"
                or row.get("validation") in validation_receipt.FINAL_STATES
                for row in rows
            ),
            # Gate-state rows are harvested after deterministic routing into
            # the crash, finding, or rejected lane.
            "routed": len(rows),
            "reportable": sum(
                row.get("validation") in validation_receipt.SECURITY_STATES
                for row in rows
            ),
            "lanes": {
                state: sum(
                    (
                        "rejected"
                        if row.get("disposition") == "rejected"
                        else row.get("validation")
                    ) == state
                    for row in rows
                )
                for state in (
                    "reportable", "not-reportable",
                    "pending", "rejected", "legacy-provisional",
                )
            },
            "exact_signatures": signatures,
        }
    return out


def _sum_cell_waterfalls(cells: list[dict], kind: str) -> dict:
    """Sum condition-local occurrences; exact signatures are filled later."""
    stages = ("candidates", "evidence_complete", "validated", "routed", "reportable")
    lane_names = (
        "reportable", "not-reportable",
        "pending", "rejected", "legacy-provisional",
    )
    result = {stage: 0 for stage in stages}
    result["lanes"] = {name: 0 for name in lane_names}
    for cell in cells:
        metrics = cell.get("metrics") or {}
        waterfall = metrics.get("validation_waterfall") or {}
        row = waterfall.get(kind) or {}
        for stage in stages:
            result[stage] += _as_nonnegative_int(row.get(stage))
        lanes = row.get("lanes") or {}
        for name in lane_names:
            result["lanes"][name] += _as_nonnegative_int(lanes.get(name))
    return result


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
# ships a ground-truth manifest (output/<slug>/.ground-truth.json) that pins
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

    The scorer's identity is (primitive, symbol) for a real bug, optionally
    refined by READ/WRITE for an alternate runtime manifestation, and
    (outcome, symbol) for a trap. A manifest typo that drops a field, mis-types
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
        keys: list[tuple[tuple[str, str], dict]] = []
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
            # findings_only excludes a bug from the crash-recall denominator, so
            # a stray string like "false" (truthy) must not silently drop it.
            if "findings_only" in e and not isinstance(e["findings_only"], bool):
                errors.append(f"{where} ({eid or '?'}) findings_only must be true or false")
            # An optional file pins which source the symbol must be in, so a
            # same-named function elsewhere cannot claim this entry. A
            # non-string would be compared against a path and never match,
            # silently making the entry unreachable.
            if "file" in e and not (isinstance(e["file"], str) and e["file"].strip()):
                errors.append(f"{where} ({eid or '?'}) file must be a non-empty string")
            # A trap must declare what a benign occurrence looks like, so the
            # scorer can tell a fired trap from a real crash in the same frame.
            outcome = str(e.get("expected_outcome", "")).strip()
            if need_outcome and not outcome:
                errors.append(f"{where} ({eid or '?'}) needs an expected_outcome")
            # The file is part of the identity when an entry pins one, so two
            # entries sharing a symbol in different files are distinct rather
            # than a collision — and two that could share a site still are.
            key = (prim, sym) if need_primitive else (outcome, sym)
            if sym:
                clash = next(
                    (seen_entry for seen_key, seen_entry in keys
                     if seen_key == key and _entries_may_share_a_site(e, seen_entry)),
                    None,
                )
                if clash is not None:
                    errors.append(
                        f"{where} ({eid or '?'}) duplicates match key {key!r}")
                else:
                    keys.append((key, e))

    check(manifest.get("planted_bugs", []), "planted_bugs",
          need_primitive=True, need_outcome=False, want_kind="real")
    check(manifest.get("false_positive_traps", []), "false_positive_traps",
          need_primitive=False, need_outcome=True, want_kind="fp")

    # One source bug can legitimately surface under more than one sanitizer
    # signature (for example UAF versus double-free, or an inlined Swift READ
    # and WRITE at one wrapper). Keep those aliases explicit and exact. An
    # access-less key is a wildcard, so it overlaps either access-qualified
    # form and cannot belong to a second bug.
    bugs = manifest.get("planted_bugs", [])
    runtime_keys: list[tuple[tuple[str, str, str], str, dict]] = []
    if isinstance(bugs, list):
        for i, bug in enumerate(bugs):
            if not isinstance(bug, dict):
                continue
            bug_where = f"planted_bugs[{i}]"
            # A bug's alternates inherit its file: they are aliases for one
            # source defect, so they sit where it sits.
            candidates = [(
                str(bug.get("primitive", "")).strip(),
                str(bug.get("signature_symbol", "")).strip(),
                "",
                bug_where,
                bug,
            )]
            alternates = bug.get("alternate_signatures", [])
            if not isinstance(alternates, list):
                errors.append(f"{bug_where} alternate_signatures must be a list")
                alternates = []
            for j, alternate in enumerate(alternates):
                where = f"{bug_where}.alternate_signatures[{j}]"
                if not isinstance(alternate, dict):
                    errors.append(f"{where} must be an object")
                    continue
                unknown = sorted(
                    set(alternate) - {"primitive", "signature_symbol", "access"}
                )
                if unknown:
                    errors.append(
                        f"{where} has unknown field(s): {', '.join(unknown)}")
                prim = str(alternate.get("primitive", "")).strip()
                sym = str(alternate.get("signature_symbol", "")).strip()
                access = str(alternate.get("access", "")).strip()
                if not prim:
                    errors.append(f"{where} needs a primitive")
                if not sym:
                    errors.append(f"{where} needs a signature_symbol")
                if access not in {"", "READ", "WRITE"}:
                    errors.append(f"{where} access must be READ or WRITE")
                candidates.append((prim, sym, access, where, bug))
            for prim, sym, access, where, owner in candidates:
                if not prim or not sym:
                    continue
                key = (prim, sym, access)
                for prior, prior_where, prior_owner in runtime_keys:
                    same_surface = key[:2] == prior[:2]
                    access_overlaps = not key[2] or not prior[2] or key[2] == prior[2]
                    if (
                        same_surface and access_overlaps
                        and _entries_may_share_a_site(owner, prior_owner)
                    ):
                        errors.append(
                            f"{where} overlaps runtime match key from {prior_where}")
                        break
                runtime_keys.append((key, where, owner))
    return errors


def _finding_report_text(finding_dir: Path) -> str:
    for name in ("REPORT.md", "report.md", "description.md", "analysis.md"):
        path = finding_dir / name
        if path.is_file():
            try:
                return path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
    return ""


def _same_source_file(one: str, other: str) -> bool:
    """Whether two source references can name the same file.

    Both qualified — either carries a directory — is an exact comparison: the
    whole point is that `src/a/parse.c` and `src/b/parse.c` are different
    files, and matching their basenames would credit one for the other. Only
    when a side is genuinely basename-only is a basename comparison the best
    either side can support, which happens because the report extractor falls
    back to a bare frame basename when nothing richer is in the report.
    """
    if not one or not other:
        return False
    first, second = Path(one), Path(other)
    if first.parent != Path(".") and second.parent != Path("."):
        return first == second
    return first.name == second.name


def _manifest_file_allows(entry: dict, found: str) -> bool:
    """Whether *found* is the file this manifest entry names, if it names one.

    The findings oracle matched on the fault function alone, so a confirmed
    finding at `a.c:parse` credited a planted bug at `b.c:parse`. An entry may
    pin its file, and only a manifest that says so is held to it.

    An entry that pins a file and a report that names none do not match. This
    is ground truth: a report with no identity evidence is unattributed —
    open-world — rather than credited to a bug it never located.
    """
    declared = str(entry.get("file", "")).strip()
    if not declared:
        return True
    return _same_source_file(declared, found)


def _entries_may_share_a_site(one: dict, other: dict) -> bool:
    """Whether two manifest entries could be pinned to the same file.

    An unpinned entry is a wildcard: it could be anywhere, so it can collide
    with anything. Two pinned entries in different files cannot.
    """
    first = str(one.get("file", "")).strip()
    second = str(other.get("file", "")).strip()
    if not first or not second:
        return True
    return _same_source_file(first, second)


def _manifest_symbols(entry: dict) -> set[str]:
    symbols = {str(entry.get("signature_symbol", "")).strip()}
    alternates = entry.get("alternate_signatures", [])
    if isinstance(alternates, list):
        for alternate in alternates:
            if isinstance(alternate, dict):
                symbols.add(str(alternate.get("signature_symbol", "")).strip())
    return {s for s in symbols if s}


def _findings_only_bug(manifest: dict, bug: dict) -> bool:
    """A manifest-level ``findings_only`` flags every bug it does not flag itself."""
    return bool(bug.get("findings_only", manifest.get("findings_only")))


def score_findings_ground_truth(
    findings_dir: Path,
    manifest: dict,
    members: dict | None = None,
    conditions: list | None = None,
    target_root: str = "",
) -> dict:
    """Score confirmed findings against the manifest's findings-only bugs.

    The mirror of score_ground_truth for the artifacts the crash oracle
    cannot grade: a planted bug marked ``findings_only`` surfaces under
    ``findings/`` with no sanitizer artifact, so it is credited when a
    confirmed FIND names its ``signature_symbol`` as the function at fault
    (the same exact-site identity crashes use, read by finding_signature's
    location extractor from the report's own fields). A confirmed finding at
    a clean-outcome trap's symbol is a false positive (a trap expecting an
    abort refutes that crash, not a finding). Every other confirmed
    finding is *open-world*: real code has bugs the answer key never planted,
    so those are listed and kept neutral — they neither prove recall nor
    count against precision.
    """
    findings_dir = Path(findings_dir)
    if (findings_dir / "findings").is_dir():
        findings_dir = findings_dir / "findings"
    members = members or {}
    real = [
        b for b in manifest.get("planted_bugs", [])
        if isinstance(b, dict) and b.get("kind", "real") == "real"
        and _findings_only_bug(manifest, b)
    ]
    # Only a trap whose expected outcome is clean says "no artifact belongs
    # here". A trap that expects an abort or another benign crash refutes that
    # crash's promotion, not a source finding at the same function — the
    # manifest's own refute text calls the release-mode defect there real.
    traps = [
        t for t in manifest.get("false_positive_traps", [])
        if isinstance(t, dict)
        and str(t.get("expected_outcome", "")).strip() in ("", "clean")
    ]
    # A trap planted in the same function as a real bug cannot fire here: the
    # oracle keys on the function (refined by `file` where an entry pins one),
    # and a report's class vocabulary does not map onto the manifest's
    # primitives. Say so rather than score it.
    ambiguous = sorted(
        str(trap.get("id", "")) for trap in traps
        if any(
            _manifest_symbols(trap) & _manifest_symbols(bug)
            and _entries_may_share_a_site(trap, bug)
            for bug in real
        )
    )
    _count, names = count_confirmed_findings(findings_dir)
    evidence: list[tuple[str, str, str]] = []
    for name in names:
        text = _finding_report_text(findings_dir / name)
        file, func = finding_signature.extract_location(text, target_root)
        evidence.append((name, file, func))

    def score_subset(items: list[tuple[str, str, str]]) -> dict:
        detected: dict[str, list[str]] = {}
        traps_fired: dict[str, list[str]] = {}
        open_world: list[str] = []
        for name, file, func in items:
            hit = next((
                b for b in real
                if func and func in _manifest_symbols(b)
                and _manifest_file_allows(b, file)
            ), None)
            if hit:
                detected.setdefault(str(hit["id"]), []).append(name)
                continue
            trap = next((
                t for t in traps
                if func and func in _manifest_symbols(t)
                and _manifest_file_allows(t, file)
            ), None)
            if trap:
                traps_fired.setdefault(str(trap["id"]), []).append(name)
            else:
                open_world.append(name)
        tp = sum(len(v) for v in detected.values())
        fp = sum(len(v) for v in traps_fired.values())
        return {
            "real_total": len(real),
            "detected": sorted(detected),
            "missed": sorted(str(b["id"]) for b in real if str(b["id"]) not in detected),
            "recall": round(len(detected) / len(real), 4) if real else None,
            "confirmed_findings": len(items),
            "true_positive_findings": tp,
            "false_positive_findings": fp,
            "false_positive_traps_fired": sorted(traps_fired),
            "open_world_findings": sorted(open_world),
            "precision": round(tp / (tp + fp), 4) if (tp + fp) else None,
            "traps_sharing_a_real_symbol": ambiguous,
        }

    result = {"overall": score_subset(evidence)}
    conds = list(conditions) if conditions is not None else sorted(set(members.values()))
    if conds:
        result["by_condition"] = {
            cond: score_subset([row for row in evidence if members.get(row[0]) == cond])
            for cond in conds
        }
    return result


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
    return root / "output" / str(target) / ".ground-truth.json"


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

# ASan/MSan/TSan diagnostics name the fault direction independently of the
# primitive. It is used only by access-qualified alternate signatures; primary
# manifest signatures retain their historical (primitive, symbol) semantics.
_ACCESS_RE = re.compile(r"^(READ|WRITE) of size\b", re.MULTILINE)

# Go's race detector prints "WARNING: DATA RACE" rather than a
# "ThreadSanitizer: <primitive>" line, so it has no primitive for _PRIMITIVE_RE
# to capture. Map it to the canonical "data-race" primitive a Go race target's
# ground-truth names.
_DATA_RACE_RE = re.compile(r"WARNING: DATA RACE")

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
    exactly the sanitizer files export/triage/cluster do (sanitizer.txt and
    probe sidecars) and skips empty files in favour of a non-empty sibling — otherwise
    a dir the confirmed-crash oracle counts could yield no evidence and be
    mis-scored. The small fallback covers the (never-expected) case where the
    shared module is unimportable."""
    if _ca is not None:
        return _ca.find_primary_sanitizer([crash_dir, crash_dir / ".audit"])
    for name in ("sanitizer.txt",):
        p = crash_dir / name
        if p.is_file() and p.stat().st_size > 0:
            return p
    return None


# A Rust ASan frame carries a v0-mangled symbol whose embedded crate hash is not
# stable across builds (e.g. "_RNvNtCs<hash>_11sample_rust9reportkit10sum_window"),
# while a Linux llvm-symbolizer instead prints the demangled path
# ("sample_rust::reportkit::sum_window"). Both reduce to the same innermost
# identifier, which is what a ground-truth signature_symbol names. This reduction
# is applied ONLY to frames from a Rust target (_crash_site_functions), because a
# demangled "a::b::c" and a bare Itanium "_ZN…" are equally C++ and must stay
# whole for a C++ target — else an unrelated C++ crash could match a plain symbol.
_RUST_LEGACY_HASH_RE = re.compile(r"^h[0-9a-f]{16}$")
_LEN_PREFIX_RE = re.compile(r"\d+")
_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _mangled_components(fn: str) -> list[str]:
    """Length-prefixed identifiers of a `<len><ident>` mangled symbol, in order."""
    comps, i, n = [], 0, len(fn)
    while i < n:
        m = _LEN_PREFIX_RE.match(fn, i)
        if not m:
            i += 1
            continue
        start, end = m.end(), m.end() + int(m.group())
        if end <= n and _IDENT_RE.match(fn[start:end]):
            comps.append(fn[start:end])
            i = end
        else:
            i = m.end()
    return comps


def _rust_symbol_tail(fn: str) -> str:
    """Innermost identifier of a Rust symbol, or "" when *fn* is not one.

    Only ever applied to a frame from a Rust target (see _crash_site_functions),
    because a demangled "a::b::c" is equally a C++ name and must not be reduced
    for a C++ target. Handles the demangled path form ("a::b::c" -> "c") and the
    two Rust manglings: v0 ("_R…", crate hash leading, last component is the
    function) and legacy ("_ZN…" ending in a 17h<16hex> disambiguator). A bare
    "_ZN…" with no Rust hash is an ordinary C++ symbol and yields "" so it is
    never reduced even inside a Rust target's dependency frame."""
    fn = fn.split("+", 1)[0].strip()
    if "::" in fn:
        parts = [p for p in fn.split("::") if p]
        while parts and _RUST_LEGACY_HASH_RE.match(parts[-1]):
            parts.pop()
        return parts[-1] if parts else ""
    if fn.startswith("_R"):
        comps = _mangled_components(fn)
        return comps[-1] if comps else ""
    if fn.startswith("_ZN"):
        comps = _mangled_components(fn)
        if comps and _RUST_LEGACY_HASH_RE.match(comps[-1]):
            comps.pop()
            return comps[-1] if comps else ""
    return ""


def _crash_site_functions(text: str, rust: bool = False) -> set[str]:
    """Function name(s) at the crash SITE — the first interesting frame, the
    same frame bin/cluster-crashes keys its signature on.

    Matching a planted symbol against the crash site (not against every frame
    in the stack) is what stops a crash whose real fault is elsewhere from
    being credited to a planted symbol that merely appears deeper as a caller,
    an allocator, or a freer. The shared ClusterFuzz parser skips sanitizer
    interceptor frames (e.g. __asan_memcpy) so the site is the true faulting
    function; the raw and normalized names are both returned so a manifest
    symbol written either way matches. For a Rust target (*rust*) the demangled
    innermost identifier is added too, so a v0-mangled or path-qualified frame
    matches a plain signature_symbol; this is scoped to Rust so a C++ target's
    "a::b::c" or "_ZN…" frame is never reduced to a colliding leaf name.

    Fallback (shared parser unimportable): the first frame line before any
    allocation/free marker that is not itself a sanitizer interceptor."""
    if _sf is not None:
        fr = _sf.first_interesting_frame(text)
        if fr is None:
            return set()
        base = {f for f in (fr.function, fr.state_function) if f}
    else:
        base = set()
        head = _STACK_STATE_STOP_RE.split(text, maxsplit=1)[0]
        for fn in _FRAME_FUNC_RE.findall(head):
            if not _SAN_INTERCEPTOR_RE.match(fn):
                base = {fn}
                break
    if not rust:
        return base
    return base | {tail for tail in map(_rust_symbol_tail, base) if tail}


def _attribution_evidence(
    crash_dir: Path, rust: bool = False,
) -> tuple[str, set[str], str] | None:
    """Trusted runtime evidence for attribution, or None.

    `(primitive, crash-site function names, access)` parsed from a CANONICAL
    sanitizer artifact — the sanitizer runtime's own output file
    (find_primary_sanitizer: sanitizer.txt or a probe sidecar),
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
    # Bind primitive, access, and crash site to one runtime report. Confirmed
    # artifacts may concatenate several repetitions whose manifestations
    # differ; mixing fields across them manufactures an attribution key no run
    # actually produced.
    diagnostic = (
        _sf.first_sanitizer_diagnostic(text) if _sf is not None else None
    ) or text
    m = _PRIMITIVE_RE.search(diagnostic)
    # Preserve fatal signal tokens exactly: trap manifests intentionally use
    # ASan's uppercase ABRT/SEGV spelling, while the shared fault key
    # canonicalizes ordinary diagnostic classes to lowercase.
    if m and m.group(1).isupper():
        primitive = m.group(1)
    elif fault := (
        # Reads the same first diagnostic, and the run header names the family.
        _ca.sanitizer_fault_key(text) if _ca is not None else None
    ):
        _sanitizer, primitive = fault
    else:
        if m:
            primitive = m.group(1)
        else:
            primitive = "data-race" if _DATA_RACE_RE.search(diagnostic) else ""
    access_match = _ACCESS_RE.search(diagnostic)
    access = access_match.group(1) if access_match else ""
    return primitive, _crash_site_functions(diagnostic, rust), access


# A trap's expected_outcome names what a *benign* occurrence looks like.
# "clean" means it should never be a confirmed crash at all; "abort" maps to
# the ASan ABRT class; any other value is taken as a literal sanitizer
# primitive. Anything else observed in the trap's frame is a real unexpected
# crash, not the trap firing.
_OUTCOME_PRIMITIVE = {"abort": "ABRT"}


def _match_real(primitive: str, crash_site: set[str], access: str,
                bugs: list[dict]) -> dict | None:
    """First planted bug whose (primitive, crash-site symbol) the evidence
    satisfies — both facts bin/cluster-crashes keys a crash on. *crash_site*
    is the faulting frame only, so a planted symbol that merely appears as a
    caller, allocator, or freer does not match."""
    for b in bugs:
        signatures = [b, *(
            b.get("alternate_signatures", [])
            if isinstance(b.get("alternate_signatures", []), list) else []
        )]
        for signature in signatures:
            if not isinstance(signature, dict):
                continue
            prim = str(signature.get("primitive", ""))
            sym = str(signature.get("signature_symbol", ""))
            wanted_access = (
                str(signature.get("access", "")) if signature is not b else ""
            )
            if prim and prim != primitive:
                continue
            if sym and sym not in crash_site:
                continue
            if wanted_access and wanted_access != access:
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
    # The crash oracle grades only sanitizer-observable bugs. A hybrid target may
    # also plant findings-only bugs (command injection, path traversal) that
    # surface under findings/ and never as a crash; each carries findings_only=true
    # so it is not stranded permanently "missed" in the crash-recall denominator.
    real = [
        b for b in manifest.get("planted_bugs", [])
        if b.get("kind", "real") == "real" and not _findings_only_bug(manifest, b)
    ]
    traps = manifest.get("false_positive_traps", [])
    # Rust symbol demangling is applied only to a Rust target's frames (a
    # demangled C++ name is indistinguishable and must stay whole).
    rust = str(manifest.get("language", "")).lower() == "rust"

    confirmed: list[tuple[str, tuple[str, set, str] | None]] = []
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
            confirmed.append((child.name, _attribution_evidence(child, rust)))

    def score_subset(items: list) -> dict:
        detected: dict[str, list[str]] = {}
        traps_fired: dict[str, list[str]] = {}
        unexpected: list[str] = []
        unattributed: list[str] = []
        for name, evidence in items:
            if evidence is None:
                unattributed.append(name)
                continue
            primitive, crash_site, access = evidence
            hit = _match_real(primitive, crash_site, access, real)
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
    *,
    require_trigger_confirmation: bool = True,
    started_at: str = "",
) -> dict:
    """Compute the deterministic metric set for one results/ tree.

    Works identically for a harness results dir and a model-direct-condition
    workspace shaped the same way (crashes/, findings/, logs/) —
    the comparison is fair because both are measured by this one yardstick.
    """
    results_dir = Path(results_dir)
    crashes_dir = results_dir / "crashes"
    findings_dir = results_dir / "findings"

    crash_dirs, finalized_crash_dirs = publication_state_names(
        crashes_dir, kind="crash", prefix="CRASH-", require_sanitizer=True,
    )
    crash_count = len(crash_dirs)
    finalized_crash_count = len(finalized_crash_dirs)
    crash_clusters = confirmed_finding_cluster_count(crashes_dir, crash_dirs)
    crash_candidates = (
        sum(
            child.is_dir()
            and not child.name.startswith(".")
            and dir_has_sanitizer_output(child)
            for child in crashes_dir.iterdir()
        )
        if crashes_dir.is_dir() else 0
    )
    finding_count = count_subdirs(findings_dir, "FIND-")
    if require_trigger_confirmation:
        confirmed_finding_dirs, finalized_finding_dirs = publication_state_names(
            findings_dir, kind="finding", prefix="FIND-",
        )
        confirmed_finding_count = len(confirmed_finding_dirs)
        finalized_finding_count = len(finalized_finding_dirs)
    else:
        confirmed_finding_count, confirmed_finding_dirs = count_confirmed_findings(
            findings_dir, require_trigger_confirmation=False,
        )
        finalized_finding_count = confirmed_finding_count
    rejected_pending = (
        sum(
            _finding_has_terminal_reject(child)
            for child in findings_dir.iterdir()
            if child.is_dir() and child.name.startswith("FIND-")
        )
        if require_trigger_confirmation and findings_dir.is_dir()
        else 0
    )
    finding_clusters = confirmed_finding_cluster_count(
        findings_dir, confirmed_finding_dirs
    )

    metrics = {
        "results_dir": str(results_dir),
        "confirmed_crashes": crash_count,
        "crash_candidates": crash_candidates,
        "finalized_crashes": finalized_crash_count,
        "crashes_unadjudicated": max(
            0, crash_candidates - finalized_crash_count,
        ),
        # Promotion-pending is one reason a proved candidate lacks final credit.
        "crashes_pending": count_pending_crashes(crashes_dir),
        "crash_clusters": crash_clusters,
        "crash_dirs": crash_dirs,
        "crashes_rejected": count_crashes_rejected(
            results_dir / "crashes-rejected"
        ),
        "discarded_hypotheses": count_discarded_hypotheses(results_dir),
        "findings": finding_count,
        "confirmed_findings": confirmed_finding_count,
        "finalized_findings": finalized_finding_count,
        "finding_confirmation": (
            FINDING_CONFIRMATION_VERSION
            if require_trigger_confirmation else "legacy-quality"
        ),
        # A terminal reject can remain briefly in findings/ when the final
        # move missed its deadline. It is adjudicated and uncounted, not
        # pending review; keep it separate from genuinely missing votes.
        "findings_rejected_pending": rejected_pending,
        # FINDs still on disk for which the required gate never produced a
        # terminal verdict. Rejected FINDs already moved to
        # findings-rejected/, or are counted separately above.
        # Non-zero means the gate did not finish — usually a provider limit cut
        # the drain short — so a reader never mistakes an un-drained
        # 0-confirmed run for a clean "found nothing". Pure arithmetic on disk
        # state; no LLM call.
        "findings_unadjudicated": max(
            0, finding_count - finalized_finding_count - rejected_pending
        ),
        "confirmed_finding_dirs": confirmed_finding_dirs,
        "finding_clusters": finding_clusters,
        "finding_classes": confirmed_finding_class_count(
            findings_dir, confirmed_finding_dirs,
        ),
        "findings_rejected": len(
            rejected_finding_names(results_dir / "findings-rejected")
        ),
        "model_refusals": count_model_refusals(results_dir),
        "exists": results_dir.is_dir(),
    }
    metrics["tokens"] = harvest_tokens(
        _find_index_jsonl(results_dir),
        default_backend=default_backend,
        default_model=default_model,
        prompt_estimate_fallback=_model_direct_prompt_estimate(results_dir),
    )
    metrics["finalization_tokens"] = harvest_finalization_tokens(
        _find_index_jsonl(results_dir),
        default_backend=default_backend,
        default_model=default_model,
    )
    metrics["execution"] = harvest_execution(
        results_dir,
        raw_log=results_dir / "backend.raw.log",
        crash_floor=crash_count,
    )
    # Compatibility for existing metric consumers.  New code should use the
    # sanitizer-neutral execution object; the historical field name predates
    # UBSan/MSan/TSan and is retained so old ledgers do not read as zero.
    metrics["tokens"]["asan_invocations"] = metrics["execution"][
        "sanitizer_invocations"
    ]
    metrics["artifact_links"] = harvest_artifact_links(
        results_dir, confirmed_finding_dirs, crash_dirs
    )
    metrics["gate_states"] = harvest_gate_states(results_dir)
    metrics["validation_waterfall"] = validation_waterfall(
        metrics["gate_states"],
        crash_signatures=crash_clusters,
        finding_signatures=finding_clusters,
    )
    # Where the wall went: passive, fails open to None, never a disposition.
    metrics["s4_campaign"] = harvest_fuzz_campaign(results_dir)
    metrics["telemetry"] = telemetry.summary(results_dir, started_at)
    return metrics


def _model_direct_prompt_estimate(results_dir: Path) -> int:
    """Per-request prompt size for a model-direct cell, from its persisted
    prompt.txt (run_model_direct_cell writes it beside the results tree).

    The harness condition stamps prompt_estimate_build into each index row, but
    model-direct has no such stash — without this its tier basis falls back to
    the session-cumulative input and pins the baseline to the high tier. Sizing
    the prompt here re-prices both live and `--regenerate` runs (both go through
    harvest) from an artifact already on disk. Harness results dirs carry no
    root prompt.txt, so this is a no-op for them. The file is ASCII-dominant, so
    byte size / 4 matches bin/audit's chars/4 estimate_tokens closely enough to
    tier both conditions on the same yardstick — and stat avoids reading a large
    prompt into memory.
    """
    try:
        size = (results_dir / "prompt.txt").stat().st_size
        return (size + 3) // 4
    except OSError:
        return 0


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
    """Read the FIND-quality gate cache (lib/triage.py) when present.

    Rejections via the FIND-quality LLM gate write
    `.llm-find-quality.json` with `accept/reason/class/severity` — not
    a `validator-vote-*.json`. Reading both keeps the page populated
    regardless of which gate flagged the finding.
    """
    cache = finding_dir / ".llm-find-quality.json"
    if not cache.is_file():
        return {}
    payload = _read_json(cache) or {}
    return payload if report_identity.quality_cache_matches_report(
        finding_dir, payload,
    ) else {}


def _rejection_artifact_reason(artifact_dir: Path) -> str:
    """Read the final disposition triage recorded when it rejected an artifact.

    REJECTION.md is written on the reject path before the directory moves, so
    it is the one reason a pooled rejected crash or finding carries.
    """
    rejection = artifact_dir / "REJECTION.md"
    if not rejection.is_file():
        return ""
    try:
        lines = rejection.read_text(
            encoding="utf-8", errors="replace",
        ).splitlines()
    except OSError:
        return ""
    for line in lines:
        match = re.fullmatch(r"\s*(?:#\s*)?Reason:\s*(.+?)\s*", line, re.I)
        if match:
            return match.group(1)
    return ""


def _md_cell(value: object) -> str:
    text = str(value if value is not None else "").replace("\n", " ")
    return text.replace("|", "\\|").strip()


def _short(text: str, limit: int = 220) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)].rstrip() + "…"


def _report_link_name(finding_dir: Path) -> str:
    report = report_identity.exact_child_file(
        finding_dir,
        ("report.md", "REPORT.md", "description.md", "analysis.md",
         "report.html", "REPORT.html", "description.html"),
    )
    return report.name if report is not None else ""


# ── rejection-index cell helpers (shared schema with lib/triage.py) ──────
# These helpers mirror triage's Site/Reason extraction so benchmark pools
# expose the same named rejected-result artifacts.

_REJECT_FRAME_SKIP_RE = re.compile(
    r"__asan|__sanitizer|__interceptor|libc\+\+|libsystem_|libdyld|libobjc|"
    r"asan_interceptors|libsancov|libclang_rt|\bstart\+"
)
_REJECT_FRAME_PREFIX_RE = re.compile(r"^\s*#\d+\s+0[xX][0-9a-fA-F]+\s+in\s+")


def _first_crash_frame(text: str) -> str:
    """First interesting "func file:line" frame, skipping sanitizer/libc/
    runtime frames — the awk-fallback twin of lib/triage.py's site column
    (lib/stack_frames.py returns nothing for UBSan traces)."""
    for line in text.splitlines():
        if not re.match(r"^\s*#\d+", line):
            continue
        if _REJECT_FRAME_SKIP_RE.search(line):
            continue
        return _REJECT_FRAME_PREFIX_RE.sub("", line).strip()[:70]
    return ""


def _crash_sanitizer_text(crash_dir: Path) -> str:
    direct = report_identity.exact_child_file(
        crash_dir,
        ("sanitizer.txt",),
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
        # vote exists), then falls back to the FIND-quality gate's
        # reason (the path most pool entries take).
        reason = (
            vote.get("rationale")
            or vote.get("reason")
            # REJECTION.md records the final disposition and remains stable
            # when pool-only link rewrites invalidate the copied quality cache.
            or _rejection_artifact_reason(finding_dir)
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
    `CELL-REJECTIONS-<cond>-<cell>.md` rosters (auto-rejected signatures that
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
    rosters = sorted(rejected_dir.glob("CELL-REJECTIONS-*.md"))
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
        # Shared schema with lib/triage.py's rejected summaries and the findings
        # index below: ID | Site | Reason | Report.
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
            reason = re.sub(
                r"\s+", " ", _rejection_artifact_reason(p) or "—",
            ).strip()
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
    text = "\n".join(md)
    (rejected_dir / "REJECTED-CRASHES.md").write_text(text, encoding="utf-8")


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
            "rationale when a validator vote exists, otherwise the "
            "FIND-quality gate's rejection reason (`lib/triage.py`)."
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
    text = "\n".join(md_lines)
    (rejected_dir / "REJECTED-FINDINGS.md").write_text(text, encoding="utf-8")


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
    each report, which bin/severity has scored. Returns:
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
                "class": (
                    " ".join(str(cl.get("class") or "other").split()).lower()
                    or "other"
                ),
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
        Top crash severity must reflect the Low crash it actually produced. So score
        each condition by the max severity among ITS members. Missing
        per-member severity stays unscored; crediting the cluster's canonical
        severity to every condition would inflate weaker baselines."""
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
        return (0, 0, "—")

    cluster_by_id = {str(cluster["id"]): cluster for cluster in out_clusters}
    by_condition: dict[str, dict] = {}
    for cond, ids in cond_clusters.items():
        cond_cls = [cluster_by_id[cid] for cid in sorted(ids) if cid in cluster_by_id]
        novel = [c["id"] for c in cond_cls if c["conditions"] == [cond]]
        class_histogram: dict[str, int] = {}
        for cluster in cond_cls:
            finding_class = str(cluster.get("class") or "other")
            class_histogram[finding_class] = (
                class_histogram.get(finding_class, 0) + 1
            )
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
            "class_histogram": class_histogram,
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


_PRODUCTIVE_WALL = re.compile(r"Reached productive wall budget: (\d+)s productive")


def _declared_productive_wall(cell_dir: Path):
    """Seconds the audit itself reports spending on finding work, if it said.

    A cell's recorded wall used to run past the audit and over the triage that
    follows it, so a 3h budget reported as ~4h. The audit's own log is the
    authoritative statement of what it spent, so prefer it — that also repairs
    cells recorded before the clock was stopped at the right place.
    """
    log = Path(cell_dir) / "audit.log"
    if not log.is_file():
        return None
    try:
        with log.open(errors="replace") as stream:
            for line in stream:
                match = _PRODUCTIVE_WALL.search(line)
                if match:
                    return int(match.group(1))
    except OSError:
        return None
    return None


def _unique_rejected(
    clusters: int, pooled_dirs: int, raw_total: int,
) -> tuple[int, bool]:
    """Return (rejection count, is_upper_bound) for one condition.

    Two sources feed the raw total (see count_crashes_rejected): pooled
    directories, which cluster, and row-only ledger records, which have none of
    the evidence a clusterer keys on.

    Row-only records are counted one per record — an upper bound. A legacy
    ledger row carries an occurrence id, not an evidence signature, so two
    replicates rejecting the same issue can count twice. Deduplicating them
    would mean mining signatures out of legacy Markdown, which buys accuracy
    only for ledgers that modern runs no longer produce; carrying them is what
    matters, because dropping them made real rejections disappear entirely.

    Directories that produced no clusters means the clusterer did not run or
    failed (the runner turns a failure into empty cluster JSON). That is not
    "nothing was rejected": fall back to the raw upper bound so a tool failure
    never renders as a clean bill.
    """
    if pooled_dirs and not clusters:
        return raw_total, True
    row_only = max(0, raw_total - pooled_dirs)
    return clusters + row_only, bool(row_only)


def _cell_worker_seats(cell: dict) -> int | None:
    """Concurrent agent seats a cell ran, or None when it is not recorded.

    model-direct is one launch by contract, so its absent count is knowledge
    rather than a gap. That launch runs the CLI's default delegation, so it
    may have fanned out internally; `tokens.delegation_events` records how
    often it did, and a seat-hour figure for a cell with a non-zero count is
    a floor on the concurrency that produced it. A harness cell that recorded
    no count is a real gap — old or malformed — and defaulting it to one
    would silently report a multi-agent cell as single-agent.
    """
    agents = cell.get("actual_agents")
    if isinstance(agents, int) and agents > 0:
        return agents
    return 1 if cell.get("condition") == "model-direct" else None


def _cell_telemetry(cell: dict) -> dict:
    metrics = cell.get("metrics") or {}
    block = metrics.get("telemetry") if isinstance(metrics, dict) else None
    return block if isinstance(block, dict) else {}


def _ratio(numerator: object, denominator: object) -> float | None:
    try:
        top, bottom = float(numerator), float(denominator)
    except (TypeError, ValueError):
        return None
    if bottom <= 0:
        return None
    return top / bottom


def _efficiency_summary(done: list[dict]) -> dict:
    """Medians of the per-cell efficiency telemetry for one condition.

    Every value is None when no completed cell recorded it, so an old cell
    renders as an em dash rather than as a measured zero. Occupancy is
    occupied agent-seconds over seats × effective wall; blocked housekeeping
    is the fraction of the effective wall the pool sat empty; review seconds
    per artifact divides the crash-triage and result-gate spans by the
    artifacts those gates judged (validation-waterfall candidates).
    """
    occupancy: list[float] = []
    blocked: list[float] = []
    review: list[float] = []
    filed: list[float] = []
    confirmed: list[float] = []
    admitted: list[float] = []
    exec_fail: list[float] = []
    duplicates: list[float] = []
    sources: set[str] = set()
    for cell in done:
        block = _cell_telemetry(cell)
        if not block:
            continue
        wall = cell.get("wall_effective_seconds")
        seats = _cell_worker_seats(cell)
        occ = (block.get("occupancy") or {})
        value = _ratio(occ.get("occupied_seconds"), (wall or 0) * (seats or 0))
        if value is not None:
            occupancy.append(min(1.0, value))
            if occ.get("source"):
                sources.add(str(occ["source"]))
        house = block.get("housekeeping") or {}
        value = _ratio(house.get("blocked_seconds"), wall)
        if value is not None:
            blocked.append(value)
        phases = house.get("phases") or {}
        final_phases = (block.get("finalization") or {}).get("phases") or {}
        waterfall = ((cell.get("metrics") or {}).get("validation_waterfall") or {})
        judged = sum(
            _as_int((waterfall.get(kind) or {}).get("candidates"))
            for kind in ("crashes", "findings")
        )
        review_seconds = sum(
            float(phases.get(name) or 0.0) + float(final_phases.get(name) or 0.0)
            for name in ("crash_triage", "result_gates")
        )
        measured_review = house.get("source") or (block.get("finalization") or {}).get("source")
        value = _ratio(review_seconds, judged) if measured_review else None
        if value is not None:
            review.append(value)
        ttf = block.get("time_to_first") or {}
        for key, bucket in (
            ("filed_seconds", filed), ("crash_confirmed_seconds", confirmed),
            ("admitted_seconds", admitted),
        ):
            if isinstance(ttf.get(key), (int, float)):
                bucket.append(float(ttf[key]))
        share = (block.get("execution") or {}).get("exec_fail_share")
        if isinstance(share, (int, float)):
            exec_fail.append(float(share))
        rate = (block.get("duplicate_roots") or {}).get("rate")
        if isinstance(rate, (int, float)):
            duplicates.append(float(rate))

    def median(values: list[float]) -> float | None:
        return _median(values) if values else None

    return {
        "worker_occupancy_median": median(occupancy),
        "worker_occupancy_source": (
            "recorded" if sources == {"recorded"} else "file_mtime" if sources else None
        ),
        "housekeeping_blocked_fraction_median": median(blocked),
        "review_seconds_per_artifact_median": median(review),
        "time_to_first_filed_median": median(filed),
        "time_to_first_crash_confirmed_median": median(confirmed),
        "time_to_first_admitted_median": median(admitted),
        "exec_fail_share_median": median(exec_fail),
        "duplicate_root_rate_median": median(duplicates),
    }


def _fmt_fraction(value: object) -> str:
    if not isinstance(value, (int, float)):
        return "—"
    return f"{100 * float(value):.0f}%"


def _fmt_minutes(value: object) -> str:
    if not isinstance(value, (int, float)):
        return "—"
    return f"{float(value) / 60:.0f}m"


def _fmt_seconds(value: object) -> str:
    if not isinstance(value, (int, float)):
        return "—"
    return f"{float(value):.0f}s"


def _render_efficiency(conditions: list[dict], backend: str) -> list[str]:
    """The efficiency table: where each condition's wall went.

    Rendered only when some condition recorded any of it, so a ledger of old
    cells does not grow a table of dashes.
    """
    keys = (
        "worker_occupancy_median", "housekeeping_blocked_fraction_median",
        "review_seconds_per_artifact_median", "time_to_first_filed_median",
        "time_to_first_crash_confirmed_median", "time_to_first_admitted_median",
        "exec_fail_share_median", "duplicate_root_rate_median",
    )
    if not any(isinstance(c.get(key), (int, float)) for c in conditions for key in keys):
        return []
    lines = [
        "| Condition | Occupancy | Blocked housekeeping | Review s/artifact "
        "| First filed | First crash confirmed | First admitted "
        "| EXEC_FAIL share | Duplicate roots | Confirmed / seat-h | $ / confirmed |",
        "| --- | --: | --: | --: | --: | --: | --: | --: | --: | --: | --: |",
    ]
    for c in sorted(conditions, key=lambda item: item["condition"]):
        occupancy = _fmt_fraction(c.get("worker_occupancy_median"))
        if c.get("worker_occupancy_source") == "file_mtime" and occupancy != "—":
            occupancy += "†"
        confirmed_total = (
            _as_int(c.get("unique_finding_clusters")) + _as_int(c.get("unique_crash_clusters"))
        )
        # Yield is pooled across every completed replicate, so charge it the
        # matching total seat capacity. Dividing a pooled numerator by one
        # replicate's median made the displayed rate grow with replicate count.
        worker_wall = c.get("worker_wall_total")
        if worker_wall is None:
            worker_wall = c.get("worker_wall_median")  # old aggregate reports
        per_seat_hour = _ratio(confirmed_total, (worker_wall or 0) / 3600.0)
        # Seats count launches. A launch that delegated ran more workers than
        # that, so the true rate is at most the one computed here.
        seat_bound = (
            "≤" if _as_int(c.get("delegation_events_total")) > 0
            or c.get("delegation_observable") is False else ""
        )
        per_dollar = (
            None if c.get("cost_estimated")
            else _ratio(c.get("cost_usd_total"), confirmed_total)
        )
        lines.append(
            "| {cond} | {occ} | {blocked} | {review} | {filed} | {confirmed} "
            "| {admitted} | {exec_fail} | {dup} | {seat} | {dollar} |".format(
                cond=_condition_cell(c["condition"], backend),
                occ=occupancy,
                blocked=_fmt_fraction(c.get("housekeeping_blocked_fraction_median")),
                review=_fmt_seconds(c.get("review_seconds_per_artifact_median")),
                filed=_fmt_minutes(c.get("time_to_first_filed_median")),
                confirmed=_fmt_minutes(c.get("time_to_first_crash_confirmed_median")),
                admitted=_fmt_minutes(c.get("time_to_first_admitted_median")),
                exec_fail=_fmt_fraction(c.get("exec_fail_share_median")),
                dup=_fmt_fraction(c.get("duplicate_root_rate_median")),
                seat=("—" if per_seat_hour is None else f"{seat_bound}{per_seat_hour:.2f}"),
                dollar=("—" if per_dollar is None else f"${per_dollar:.0f}"),
            )
        )
    lines.append("")
    lines.append(
        "> **Efficiency.** **Occupancy** is occupied agent-seconds over seats × "
        "effective wall († derived from session file clocks on a cell that "
        "predates recorded spans); **Blocked housekeeping** is the share of the "
        "wall the pool sat empty at the iteration barrier; **Review s/artifact** "
        "is crash-triage plus result-gate seconds per artifact judged; the "
        "**First** columns are minutes from the run's first clock to the first "
        "artifact filed, the first sanitizer-confirmed crash, and the first "
        "receipt claiming reportable; **EXEC_FAIL share** is the fraction of "
        "probes whose command returned without completing cleanly (rejected "
        "input, loader, usage, or runner failure); **Duplicate "
        "roots** is the share of artifact signatures filed by more than one "
        "agent; **Confirmed / seat-h** is reportable clusters per worker-hour "
        "(so a wider pool is charged for its seats; `≤` marks a condition in "
        "which a launch delegated to subagents, or whose backend cannot show "
        "its fan-out at all, so its seat capacity is a floor and the rate an "
        "upper bound) and **$ / confirmed** is "
        "measured cost per reportable cluster, withheld when any cost is "
        "estimated or a spend floor. Medians over completed "
        "replicates; an em dash is unrecorded, never zero."
    )
    lines.append("")
    return lines


def _effective_wall(cell: dict):
    """Active wall: elapsed minus confirmed provider-recovery pauses.

    Uses cell.json's `wall_effective_seconds` when present, else derives it
    from elapsed wall and provider pauses. Housekeeping remains separately
    observable but is real harness work and therefore stays inside the budget.
    Old cells without timing fields fall back to raw `wall_seconds`.
    """
    wall = cell.get("wall_seconds")
    if wall is None:
        return None
    eff = cell.get("wall_effective_seconds")
    if eff is not None:
        try:
            return max(0, int(eff))
        except (TypeError, ValueError):
            pass
    try:
        paused = int(cell.get("paused_seconds", 0) or 0)
    except (TypeError, ValueError):
        paused = 0
    try:
        return max(0, int(wall) - paused)
    except (TypeError, ValueError):
        return wall


def _tokens_for_cell(cell: dict) -> dict:
    """Return a normalized token row for one aggregated benchmark cell."""
    metrics = cell.get("metrics") or {}
    if not isinstance(metrics, dict):
        metrics = {}
    tokens = metrics.get("tokens") or {}
    if not isinstance(tokens, dict):
        tokens = {}
    input_tokens = _as_nonnegative_int(tokens.get("input_tokens"))
    cached_input = _as_nonnegative_int(tokens.get("cached_input_tokens"))
    cache_creation = _as_nonnegative_int(tokens.get("cache_creation_tokens"))
    output_tokens = _as_nonnegative_int(tokens.get("output_tokens"))
    prompt_estimate = _as_nonnegative_int(tokens.get("prompt_estimate_tokens"))
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
        # `wall_seconds` here is productive wall (session-recovery pause excluded)
        # so token/throughput rows compare investigation time, not idle waiting.
        # `wall_elapsed_seconds` keeps the raw wall for reference.
        "wall_seconds": _as_nonnegative_int(_effective_wall(cell)),
        "wall_elapsed_seconds": _as_nonnegative_int(cell.get("wall_seconds")),
        "input_tokens": input_tokens,
        "cached_input_tokens": cached_input,
        "cache_creation_tokens": cache_creation,
        "output_tokens": output_tokens,
        "prompt_estimate_tokens": prompt_estimate,
        "cost_usd": str(tokens.get("cost_usd") or ""),
        "cost_source": str(tokens.get("cost_source") or ""),
        "cost_estimated": bool(tokens.get("cost_estimated")) or estimated,
        "usage_records": _as_nonnegative_int(tokens.get("usage_records")),
        # Observed subagent spawns for the cell; a seat-hour figure is a
        # floor when this is non-zero.
        "delegation_events": (
            None if tokens.get("delegation_events") is None
            else _as_nonnegative_int(tokens.get("delegation_events"))
        ),
        "spend_lower_bound": bool(tokens.get("spend_lower_bound")),
        "delegation_observable": tokens.get("delegation_observable") is not False,
        "estimated": estimated,
        "token_source": str(tokens.get("token_source") or ""),
    }


def _row_token_source(row: dict) -> str:
    """Where one token row's numbers came from: measured/estimated/unknown.

    `measured`  — parsed from the backend's own usage telemetry.
    `estimated` — a floor: derived from character counts (a backend that
                  reports no usage at all, e.g. Antigravity), recovered from
                  a terminal-less stream, or measured for a session whose
                  delegated work ran where its usage cannot see it.
    `unknown`   — the row carries no token signal of any kind, so it must
                  not be presented as a measurement of zero cost.
    """
    explicit = str(row.get("token_source") or "")
    if explicit in {"measured", "estimated", "unknown", "mixed"}:
        return explicit
    if row.get("estimated"):
        return "estimated"
    if (row.get("input_tokens") or row.get("cached_input_tokens")
            or row.get("output_tokens") or row.get("prompt_estimate_tokens")):
        return "measured"
    return "unknown"


def _token_source(rows: list[dict]) -> str:
    """Source label for a collection of token rows. `unknown` dominates: any
    row without a usage signal understates the total, so the collection cannot
    be read as measured. Otherwise the shared label, or `mixed` when they
    differ."""
    if not rows:
        return "none"
    kinds = {_row_token_source(r) for r in rows}
    if "unknown" in kinds:
        return "unknown"
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
            amount = Decimal(str(value))
            if not amount.is_finite():
                continue
            total += amount
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


def aggregate(bench_dir: Path, *, include_pool: bool = True) -> dict:
    """Fold every cell into a per-condition report.

    Each cell directory is expected to hold a cell.json (run metadata,
    written by bin/benchmark) and a metrics.json (written by `harvest`).
    Missing files degrade gracefully so a partial/resumed run still
    aggregates what completed. Live reporting passes ``include_pool=False``
    so it reads only finalized cell metadata and cannot mutate or reuse stale
    pooled state.
    """
    bench_dir = Path(bench_dir)
    run_meta = {}
    run_json = bench_dir / "run.json"
    if run_json.is_file():
        try:
            run_meta = json.loads(run_json.read_text(encoding="utf-8"))
        except ValueError:
            run_meta = {}
        if not isinstance(run_meta, dict):
            run_meta = {}

    # Every cell in a run is granted the same wall, so the run is the one
    # place that knows the denominator. 0 means unlimited: no share of the
    # budget is knowable, and none is reported.
    budget_wall = max(0, _as_int(run_meta.get("budget_wall")))

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
            if not isinstance(cell, dict):
                cell = {}
        if mj.is_file():
            try:
                metrics = json.loads(mj.read_text(encoding="utf-8"))
            except ValueError:
                metrics = {}
            if not isinstance(metrics, dict):
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
            "paused_seconds": cell.get("paused_seconds", 0) or 0,
            "wall_effective_seconds": (
                _declared_productive_wall(cell_dir) or _effective_wall(cell)
            ),
            "actual_agents": cell.get("actual_agents"),
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
                value = json.loads(p.read_text(encoding="utf-8"))
                return value if isinstance(value, dict) else {}
            except ValueError:
                return {}
        return {}

    members = _reconcile_demoted_pool_crashes(bench_dir) if include_pool else {}
    crash_attr = attribute_clusters(
        _load("clusters-crashes.json") if include_pool else {},
        members.get("crashes", {}),
    )
    finding_attr = attribute_clusters(
        _load("clusters-findings.json") if include_pool else {},
        members.get("findings", {}),
    )
    # The rejected side is clustered by the same tools (bin/benchmark points
    # them at pool/<kind>-rejected), so "unique cut" is counted like "unique
    # kept" instead of a raw dir tally.
    rejected_crash_attr = attribute_clusters(
        _load("clusters-crashes-rejected.json") if include_pool else {},
        members.get("crashes-rejected", {}),
    )
    rejected_finding_attr = attribute_clusters(
        _load("clusters-findings-rejected.json") if include_pool else {},
        members.get("findings-rejected", {}),
    )
    crash_by_cond = crash_attr["by_condition"]
    finding_by_cond = finding_attr["by_condition"]
    rejected_crash_by_cond = rejected_crash_attr["by_condition"]
    rejected_finding_by_cond = rejected_finding_attr["by_condition"]
    # Rejected crashes come from two legitimate sources (count_crashes_rejected):
    # CRASH-* dirs, and row-only ledger signatures that never got a dir. Only
    # the dirs can be clustered, so count how many there are per condition —
    # the remainder is row-only and must still reach the unique total, or real
    # rejections vanish from the table.
    pooled_rejected_crash_dirs: dict[str, int] = {}
    for cond_name in members.get("crashes-rejected", {}).values():
        pooled_rejected_crash_dirs[cond_name] = (
            pooled_rejected_crash_dirs.get(cond_name, 0) + 1
        )
    pooled_rejected_finding_dirs: dict[str, int] = {}
    for cond_name in members.get("findings-rejected", {}).values():
        pooled_rejected_finding_dirs[cond_name] = (
            pooled_rejected_finding_dirs.get(cond_name, 0) + 1
        )
    # The headline is a unique-cluster count, so its class decomposition must
    # use the same denominator. Counting pooled directories here made one
    # duplicated class occupy a larger displayed share even though clustering
    # had already collapsed those reports into one finding.
    finding_class_histogram_by_cond = {
        _cond: dict(_summary.get("class_histogram") or {})
        for _cond, _summary in finding_by_cond.items()
    }
    finding_classes_by_cond = {
        _cond: len(_hist)
        for _cond, _hist in finding_class_histogram_by_cond.items()
    }
    # Crashes a post-pool gate demoted out of the accepted pool keep their
    # pooled-accepted name (CRASH-NNNN); cell-level rejects are CRASH-REJECTED-*.
    # Reconcile re-files demoted entries under crashes-rejected, so a plain
    # CRASH-NNNN there is exactly one crash the cell metrics still book as
    # accepted. Count them per condition and, for new pools, by source cell so
    # the per-replicate crash vector/median moves with the headline total.
    demoted_crashes_by_cond: dict[str, int] = {}
    demoted_crashes_by_cell: dict[tuple[str, str], int] = {}
    crash_cells = members.get("crash_cells", {})
    if not isinstance(crash_cells, dict):
        crash_cells = {}
    for _name, _cond in members.get("crashes-rejected", {}).items():
        if _name.startswith("CRASH-") and not _name.startswith("CRASH-REJECTED-"):
            demoted_crashes_by_cond[_cond] = (
                demoted_crashes_by_cond.get(_cond, 0) + 1
            )
            _cell = crash_cells.get(_name)
            if isinstance(_cell, str) and _cell:
                key = (_cond, _cell)
                demoted_crashes_by_cell[key] = (
                    demoted_crashes_by_cell.get(key, 0) + 1
                )

    conditions = []
    token_usage = []
    for cond, cells in sorted(by_condition.items()):
        done = [c for c in cells if c["status"] == "done"]
        # incomplete is written when provider/account limits made the cell
        # unsuitable as a clean benchmark replicate.
        incomplete = [c for c in cells if c["status"] == "incomplete"]
        provider_limited = [
            c
            for c in incomplete
            if c.get("run_quality") == "provider_limited"
        ]
        incomplete_observed = [
            {
                "cell": c["cell"],
                "crashes": int(c["metrics"].get("confirmed_crashes", 0) or 0),
                "findings": int(c["metrics"].get("confirmed_findings", 0) or 0),
            }
            for c in incomplete
        ]
        # done cells that recovered from a provider blip mid-run. They ARE
        # counted in the clean totals (the run finished usefully on its full
        # budget), so the table shows no marker; the count is retained for
        # fairness auditing and surfaced to operators elsewhere.
        provider_recovered = [
            c for c in done if c.get("run_quality") == "provider_recovered"
        ]
        # Counted, but on a wall its peers did not stop at. With one repeat the
        # Wall column already shows that; with several, the median hides it.
        backend_terminated = [
            c for c in done if c.get("run_quality") == "backend_terminated"
        ]
        crashes = [c["metrics"].get("confirmed_crashes", 0) for c in done]
        # Reproduced sanitizer crashes a reviewer placed outside the declared
        # attacker controls: real defects kept in the cell, no security credit.
        # Finalized minus credited; a cell that predates the finalized counter
        # contributes nothing rather than a guess.
        retained_crashes = [
            max(
                0,
                _as_int(c["metrics"].get("finalized_crashes"))
                - _as_int(c["metrics"].get("confirmed_crashes")),
            )
            if "finalized_crashes" in c["metrics"] else 0
            for c in done
        ]
        pending_crashes = [c["metrics"].get("crashes_pending", 0) for c in done]
        unadjudicated_crashes = [
            _as_int(
                c["metrics"].get(
                    "crashes_unadjudicated",
                    max(
                        0,
                        _as_int(c["metrics"].get("crash_candidates"))
                        - _as_int(c["metrics"].get("finalized_crashes")),
                    ),
                ),
            )
            for c in done
        ]
        findings = [c["metrics"].get("findings", 0) for c in done]
        confirmed_findings = [
            c["metrics"].get("confirmed_findings", 0) for c in done
        ]
        rejected_findings = [
            _as_int(c["metrics"].get("findings_rejected"))
            + _as_int(c["metrics"].get("findings_rejected_pending"))
            for c in done
        ]
        unadjudicated_findings = [
            _as_int(
                c["metrics"].get(
                    "findings_unadjudicated",
                    max(
                        0,
                        _as_int(c["metrics"].get("findings"))
                        - _as_int(c["metrics"].get("confirmed_findings")),
                    ),
                ),
            )
            for c in done
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
        # Productive wall (session-recovery pause excluded) so the median wall
        # column reflects investigation time, not idle waiting on a reset.
        walls = [c["wall_effective_seconds"] for c in done
                 if c.get("wall_effective_seconds")]
        # Same wall buys a different amount of work per condition: the harness
        # runs its agents concurrently while model-direct is one session by
        # contract, so a wall-only column reads a 3-agent cell as costing what
        # a 1-agent cell cost. This is worker capacity — seats times time — and
        # therefore an upper bound: it counts a seat through housekeeping and
        # through any idle stretch. Real agent-hours need session accounting
        # the cells do not carry yet, so a harness cell that recorded no agent
        # count is left out rather than guessed at.
        # All or nothing against the same cells the wall median used. A median
        # over the subset that happens to record seats reads as the condition's
        # capacity while describing fewer replicates than the row claims, and
        # nothing in the table would show the difference.
        seats = [_cell_worker_seats(c) for c in done
                 if c.get("wall_effective_seconds")]
        worker_walls = (
            [wall * count for wall, count in zip(walls, seats)]
            if seats and all(seats) else []
        )
        token_rows = [_tokens_for_cell(c) for c in done]
        token_usage.extend(token_rows)
        cb = crash_by_cond.get(cond, {})
        fb = finding_by_cond.get(cond, {})
        rcb = rejected_crash_by_cond.get(cond, {})
        rfb = rejected_finding_by_cond.get(cond, {})
        crash_waterfall = _sum_cell_waterfalls(done, "crashes")
        finding_waterfall = _sum_cell_waterfalls(done, "findings")
        crash_waterfall["exact_signatures"] = cb.get("unique_clusters", 0)
        finding_waterfall["exact_signatures"] = fb.get("unique_clusters", 0)
        # Cell sums stay authoritative — they alone carry the rejection-ledger
        # auto-rejected signature rows that never get a crash dir. Only re-book
        # the post-pool demotions: subtract them from accepted, add to rejected.
        demoted = demoted_crashes_by_cond.get(cond, 0)
        if demoted:
            crashes = list(crashes)
            for idx, cell in enumerate(done):
                count = demoted_crashes_by_cell.get((cond, cell["cell"]), 0)
                if count <= 0:
                    continue
                removed = min(crashes[idx], count)
                crashes[idx] -= removed
        crash_total = sum(crashes)
        rejected_crash_total = sum(rejected_crashes) + demoted
        unique_rejected_crashes, rejected_crashes_upper_bound = _unique_rejected(
            rcb.get("unique_clusters", 0),
            pooled_rejected_crash_dirs.get(cond, 0),
            rejected_crash_total,
        )
        unique_rejected_findings, rejected_findings_upper_bound = _unique_rejected(
            rfb.get("unique_clusters", 0),
            pooled_rejected_finding_dirs.get(cond, 0),
            sum(rejected_findings),
        )
        conditions.append(
            {
                "condition": cond,
                "replicates_total": len(cells),
                "replicates_done": len(done),
                "replicates_incomplete": len(incomplete),
                "replicates_provider_limited": len(provider_limited),
                "replicates_provider_recovered": len(provider_recovered),
                "replicates_backend_terminated": len(backend_terminated),
                "incomplete_observed": incomplete_observed,
                "crashes": crashes,
                "crash_median": _median([float(x) for x in crashes]),
                "crash_total": crash_total,
                "pending_crash_total": sum(pending_crashes),
                "retained_crash_total": sum(retained_crashes),
                "unadjudicated_crash_total": sum(unadjudicated_crashes),
                "crash_total_is_floor": (
                    sum(unadjudicated_crashes)
                    > crash_total + rejected_crash_total
                ),
                "rejected_crash_total": rejected_crash_total,
                "discarded_hypothesis_total": sum(discarded_hypotheses),
                "rejected_finding_total": sum(rejected_findings),
                "model_refusal_total": sum(model_refusals),
                "finding_total": sum(findings),
                "confirmed_finding_total": sum(confirmed_findings),
                # Findings the gate never adjudicated (drain cut short, e.g. a
                # provider limit). Makes confirmed_finding_total=0 legible: 0
                # confirmed with a non-zero remainder is "gate unfinished", not
                # "nothing found". Mirrors the per-cell findings_unadjudicated.
                "unadjudicated_finding_total": sum(unadjudicated_findings),
                # A remainder that outnumbers the verdicts means review stopped
                # partway down the queue, so the count is a lower bound on this
                # condition rather than its measured yield. Kept as a flag on
                # the number instead of a status: dropping the cell would take
                # its confirmed crashes out of the comparison with it.
                "finding_total_is_floor": (
                    sum(unadjudicated_findings)
                    > sum(confirmed_findings) + sum(rejected_findings)
                ),
                "unique_crash_clusters": cb.get("unique_clusters", 0),
                "novel_crash_clusters": cb.get("novel_clusters", 0),
                "top_severity_level": cb.get("top_severity_level", "—"),
                "top_severity_rank": cb.get("top_severity_rank", 0),
                "medium_plus_bugs": cb.get("medium_plus", 0),
                "unique_finding_clusters": fb.get("unique_clusters", 0),
                "finding_class_histogram": finding_class_histogram_by_cond.get(
                    cond, {},
                ),
                "unique_finding_classes": finding_classes_by_cond.get(cond, 0),
                "medium_plus_findings": fb.get("medium_plus", 0),
                "unique_rejected_crash_clusters": unique_rejected_crashes,
                "rejected_crash_clusters_upper_bound": rejected_crashes_upper_bound,
                "unique_rejected_finding_clusters": unique_rejected_findings,
                "rejected_finding_clusters_upper_bound": rejected_findings_upper_bound,
                "validation_waterfall": {
                    "crashes": crash_waterfall,
                    "findings": finding_waterfall,
                },
                "wall_median": _median([float(x) for x in walls]),
                "wall_budget_seconds": budget_wall or None,
                # None, not 0: an absent capacity must render as the em dash
                # `_fmt_hours` gives an unparseable value, never as "0.00h".
                "worker_wall_median": (
                    _median([float(x) for x in worker_walls])
                    if worker_walls else None
                ),
                "worker_wall_total": (
                    sum(float(x) for x in worker_walls)
                    if worker_walls else None
                ),
                **_efficiency_summary(done),
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
                "cost_estimated": any(
                    bool(row.get("cost_estimated")) for row in token_rows
                ),
                # Observed subagent spawns across the condition's cells, and
                # whether any of them ran where the cell's usage cannot see
                # its spend. Seat capacity is a floor once anything delegated,
                # so the seat-hour rate is published as an upper bound.
                "delegation_events_total": sum(
                    _as_nonnegative_int(row.get("delegation_events"))
                    for row in token_rows
                ),
                "spend_lower_bound": any(
                    bool(row.get("spend_lower_bound")) for row in token_rows
                ),
                "delegation_observable": all(
                    row.get("delegation_observable") is not False for row in token_rows
                ),
                "token_source": _token_source(token_rows),
                "cells": cells,
            }
        )

    report = {
        "bench_dir": str(bench_dir),
        "run": run_meta,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        # What scored the M+ columns. A row scored by an older scorer is not
        # comparable with a newer one; the page says so rather than implying
        # one scale across every run it has accumulated.
        "severity_scorers": severity_scorer_versions(bench_dir),
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
    if include_pool and gt_path.is_file():
        manifest = load_ground_truth(gt_path)
        errs = (["manifest is not a JSON object"] if manifest is None
                else manifest_errors(manifest))
        if errs:
            report["ground_truth_error"] = errs
        elif manifest.get("findings_only"):
            # A findings-only target ships no sanitizer; its planted bugs
            # surface under findings/, which the deterministic crash oracle
            # cannot grade. Scoring its (empty) crashes would report a
            # misleading 0% recall, so mark them not-scored; the findings
            # oracle below still scores what the target does plant.
            report["ground_truth_scoring"] = {"not_scored": "findings-only"}
        elif pool_crashes.is_dir():
            report["ground_truth_scoring"] = score_ground_truth(
                pool_crashes,
                manifest,
                members.get("crashes", {}),
                conditions=[c["condition"] for c in conditions],
            )
        pool_findings = bench_dir / "pool" / "findings"
        if (
            not errs and manifest is not None and pool_findings.is_dir()
            and any(
                isinstance(b, dict) and _findings_only_bug(manifest, b)
                for b in manifest.get("planted_bugs", [])
            )
        ):
            scoring = report.setdefault("ground_truth_scoring", {})
            scoring["findings"] = score_findings_ground_truth(
                pool_findings,
                manifest,
                members.get("findings", {}),
                conditions=[c["condition"] for c in conditions],
            )

    return report


# ── pooling for cross-condition clustering ───────────────────────────────


def _find_output_target_toml(start: Path) -> Path | None:
    """Find output/<slug>/target.toml for a cell results directory."""
    cur = start.resolve()
    if cur.is_file():
        cur = cur.parent
    # The slug may be nested (output/samples/sample-python/...), so match the
    # target root by its target.toml at any depth rather than requiring it to
    # be a direct child of output/. Stop at the output/ boundary so we never
    # climb past it into an unrelated tree.
    for p in [cur, *cur.parents]:
        if (p / "target.toml").is_file():
            return p / "target.toml"
        if p.name == "output":
            break
    return None


def _target_attacker_controls(path: Path) -> tuple[str, ...] | None:
    if _tc is None:
        return None
    try:
        parsed = _tc.parse_toml(path)
    except Exception:
        return None
    threat = parsed.get("threat_model", {})
    raw = threat.get("attacker_controls", []) if isinstance(threat, dict) else []
    if not isinstance(raw, list):
        return None
    # Normalise (call-order → call-sequence), drop invalid tokens, and dedupe in
    # target_config's canonical order, so two cells that differ only by an alias
    # or token ordering still compare equal and pool correctly.
    norm = {
        _tc._normalize_attacker_control(str(v).strip())
        for v in raw if str(v).strip()
    }
    controls = tuple(
        t for t in _tc.ATTACKER_CONTROLS_VALID
        if t in norm and _tc._is_valid_attacker_control(t)
    )
    return controls or ("bytes",)


def _live_target_toml(bench_dir: Path) -> Path | None:
    """The canonical live target.toml for this run's target, if present.

    The threat model is target-level config, not run-level data: a pooled
    re-score should reflect our CURRENT understanding of what the attacker
    controls, not the snapshot frozen into the cell trees at run time. Resolve
    the run's target slug from run.json and return SCRIPT_ROOT/output/<slug>/
    target.toml when it exists; callers fall back to the cell snapshots.
    """
    try:
        run = json.loads((bench_dir / "run.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    slug = run.get("target")
    if not isinstance(slug, str) or not slug:
        return None
    live = SCRIPT_ROOT / "output" / slug / "target.toml"
    return live if live.is_file() else None


def _copy_pool_target_toml(pool: Path, candidates: list[Path],
                           live_target_toml: Path | None = None) -> None:
    """Provide target threat-model context for pooled severity rescoring.

    The severity scorer walks upward from a pooled crash dir to find
    target.toml, so the pool needs config at pool/target.toml. Prefer the
    canonical live model (live_target_toml) so a re-score reflects the current
    threat model rather than the snapshot frozen at run time. Falling back to
    the cell snapshots: copy the full file when every cell config is byte-
    identical; if only incidental paths differ, synthesize a minimal pool config
    when all cells agree on attacker_controls; mixed threat models stay unscored
    by target config rather than applying the wrong one.
    """
    if live_target_toml is not None and live_target_toml.is_file():
        shutil.copy2(live_target_toml, pool / "target.toml")
        return
    unique: dict[str, Path] = {}
    for path in candidates:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        unique.setdefault(text, path)
    if len(unique) != 1:
        controls = {_target_attacker_controls(path) for path in candidates}
        controls.discard(None)
        if len(controls) != 1:
            return
        rendered = ", ".join(json.dumps(v) for v in next(iter(controls)))
        (pool / "target.toml").write_text(
            "# benchmark pool target config: threat model preserved from cells\n"
            "[threat_model]\n"
            f"attacker_controls = [{rendered}]\n",
            encoding="utf-8",
        )
        return
    shutil.copy2(next(iter(unique.values())), pool / "target.toml")


def build_pool(bench_dir: Path, pool_name: str = "pool") -> dict:
    """Copy every cell's confirmed crash + finding dirs into one pool.

    bin/benchmark then runs the SAME post-processing the harness uses —
    bin/severity (severity), bin/export-repro (reproducer bundle) and
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

    # The finding validator's scratch view (.validator-cwd) is a symlink farm
    # into the target tree plus its build outputs. It is never evidence, and
    # copytree follows those symlinks into half-written build trees and raises.
    # Older runs embedded it inside model-direct finding dirs, so exclude it
    # when pooling regardless of where it landed.
    _ignore_names = shutil.ignore_patterns(".validator-cwd")

    def ignore_transient(directory, names):
        """Drop scratch views and dangling links, naming what was lost.

        Only DANGLING links are dropped. copytree dereferences a live one, so
        an agent's link into scratch lands in the pool as a regular file with
        the real bytes — exactly the self-contained bundle we want, and what
        every downstream reproducer path needs. Skipping live links instead
        would pool a finding stripped of its testcase. A link whose target
        housekeeping already pruned has no bytes to copy: copytree resolves it,
        hits ENOENT and aborts the whole pool build after every cell has
        finished, so skip it — but say so, since a finding that arrives without
        its reproducer must not look like one that never had it.
        """
        ignored = set(_ignore_names(directory, names))
        for name in names:
            path = os.path.join(directory, name)
            if (name not in ignored and os.path.islink(path)
                    and not os.path.exists(path)):
                print(
                    f"WARN: pooling {Path(directory).name}/{name}: symlink target "
                    f"{os.readlink(path)!r} is gone; evidence not pooled",
                    file=sys.stderr,
                )
                ignored.add(name)
        return ignored

    def is_artifact_dir(path: Path) -> bool:
        """Only a real directory can own an artifact bundle.

        Unlike a linked evidence file, a linked artifact ROOT is anomalous —
        the harness creates these directories itself — and following one can
        pull an unbounded tree (or a link cycle) into the pool. Skipping costs
        at most one artifact, loudly.
        """
        if path.is_symlink():
            print(
                f"WARN: pooling {path.parent.name}/{path.name}: artifact directory "
                f"is a symlink; not pooled",
                file=sys.stderr,
            )
            return False
        return path.is_dir()

    bench_dir = Path(bench_dir)
    pool = bench_dir / pool_name
    stem = pool_name.strip(".")
    # Sweep any skeleton a prior best-effort removal could not finish, so they
    # don't accumulate across regenerates; this also clears our target name.
    for leftover in bench_dir.glob(f".discard-{stem}-*"):
        shutil.rmtree(leftover, ignore_errors=True)
    if pool.exists():
        # Rename the stale tree aside before removing it. A direct rmtree walks
        # the tree and can fail with ENOTEMPTY when a concurrent writer
        # (Spotlight/Finder repopulating .DS_Store, an indexer touching a nested
        # build tree) creates a file in a directory rmtree just emptied. rename
        # is atomic and content-agnostic, so the swap always succeeds; the aside
        # removal is best-effort and never blocks the rebuild.
        stale = bench_dir / f".discard-{stem}-{os.getpid()}"
        pool.rename(stale)
        shutil.rmtree(stale, ignore_errors=True)
    (pool / "crashes").mkdir(parents=True)
    (pool / "crashes-rejected").mkdir(parents=True)
    (pool / "findings").mkdir(parents=True)
    (pool / "findings-rejected").mkdir(parents=True)

    members: dict[str, dict] = {
        "crashes": {},
        "crash_cells": {},
        "crashes-rejected": {},
        "findings": {},
        "findings-rejected": {},
    }
    crash_n = 0
    rejected_crash_n = 0
    find_n = 0
    rejected_find_n = 0
    target_toml_candidates: list[Path] = []
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
        rd = cell_results_dir(cell)
        if rd is None or not rd.is_dir():
            continue
        target_toml = _find_output_target_toml(rd)
        if target_toml is not None:
            target_toml_candidates.append(target_toml)
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
            if not is_artifact_dir(src):
                continue
            prior_validation = validation_receipt.read_current(src)
            crash_n += 1
            dst_name = f"CRASH-{crash_n:04d}"
            dst = pool / "crashes" / dst_name
            shutil.copytree(src, dst, ignore=ignore_transient,
                            ignore_dangling_symlinks=True)
            _scrub_pooled_tree(dst, prior_validation)
            if prior_validation is not None:
                validation_receipt.rewrite_after_equivalent_transform(
                    dst, prior_validation,
                )
            members["crashes"][dst_name] = cond
            members["crash_cells"][dst_name] = cell_dir.name
        findings_dir = rd / "findings"
        if findings_dir.is_dir():
            for name in _pool_finding_names(metrics, findings_dir):
                src = findings_dir / name
                if not is_artifact_dir(src):
                    continue
                prior_validation = validation_receipt.read_current(src)
                find_n += 1
                dst_name = f"FIND-{find_n:04d}"
                dst = pool / "findings" / dst_name
                shutil.copytree(src, dst, ignore=ignore_transient,
                            ignore_dangling_symlinks=True)
                _scrub_pooled_tree(dst, prior_validation)
                if prior_validation is not None:
                    validation_receipt.rewrite_after_equivalent_transform(
                        dst, prior_validation,
                    )
                members["findings"][dst_name] = cond
        rejected_dir = rd / "findings-rejected"
        if rejected_dir.is_dir():
            for name in rejected_finding_names(rejected_dir):
                src = rejected_dir / name
                if not is_artifact_dir(src):
                    continue
                rejected_find_n += 1
                dst_name = f"FIND-REJECTED-{rejected_find_n:04d}"
                dst = pool / "findings-rejected" / dst_name
                shutil.copytree(src, dst, ignore=ignore_transient,
                            ignore_dangling_symlinks=True)
                _scrub_pooled_tree(dst)
                members["findings-rejected"][dst_name] = cond
        rejected_crashes_dir = rd / "crashes-rejected"
        if rejected_crashes_dir.is_dir():
            for src in sorted(rejected_crashes_dir.iterdir()):
                if not src.name.startswith("CRASH-") or not is_artifact_dir(src):
                    continue
                rejected_crash_n += 1
                dst_name = f"CRASH-REJECTED-{rejected_crash_n:04d}"
                dst = pool / "crashes-rejected" / dst_name
                shutil.copytree(src, dst, ignore=ignore_transient,
                            ignore_dangling_symlinks=True)
                _scrub_pooled_tree(dst)
                members["crashes-rejected"][dst_name] = cond
            # The per-cell named report is the human-readable rejection ledger
            # (rows for triage-rejected crash signatures that did NOT get a
            # full CRASH-* dir copied above — runtime-diagnostic dedups,
            # caller-misuse classes, etc.). Copy it alongside so the
            # reviewer can see *why* a cell counted N rejections even when
            # zero rejection dirs exist.
            index_md = rejected_crashes_dir / "REJECTED-CRASHES.md"
            if not index_md.is_file():
                index_md = rejected_crashes_dir / "INDEX.md"
            if count_rejected_crash_rows(index_md):
                dst = (pool / "crashes-rejected"
                       / f"CELL-REJECTIONS-{cond}-{cell_dir.name}.md")
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

    _copy_pool_target_toml(pool, target_toml_candidates,
                           live_target_toml=_live_target_toml(bench_dir))
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


def _fmt_approx(rendered: str, source: object) -> str:
    """One marker, one meaning: `~` says the figure is not exact.

    A session that reported no usage omits its whole spend, so the total does
    read low rather than merely imprecise — but a second prefix does not buy
    that. It rendered as `≥~$46`, two warnings on one number, and reused `≥`
    against the unjudged artifact remainder it already means elsewhere in the
    report. The direction lives in the Source column, which names `unknown`
    beside the figure, and in the legend.
    """
    if source != "unknown" or rendered in ("—", "") or rendered[0] == "~":
        return rendered
    return f"~{rendered}"


def _fmt_token_approx(value: object, source: object) -> str:
    return _fmt_approx(_fmt_tokens(value), source)


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
        return _fmt_token_approx(measured, agg.get("token_source"))
    estimate = int(agg.get("prompt_estimate_tokens_total") or 0)
    if estimate > 0:
        return f"~{_fmt_tokens(estimate)}"
    return _fmt_token_approx(measured, agg.get("token_source"))


def _fmt_output_cell(agg: dict) -> str:
    """Output column for the cross-backend rollup.

    When the backend reports no measured output (gemini or grok) and we only
    have an input-side prompt estimate, render an em dash rather than
    `0` — there is no output estimate, and printing `0` falsely implies
    the model produced nothing.
    """
    measured = int(agg.get("output_tokens_total") or 0)
    if measured > 0:
        return _fmt_token_approx(measured, agg.get("token_source"))
    if int(agg.get("prompt_estimate_tokens_total") or 0) > 0:
        return "—"
    return _fmt_token_approx(measured, agg.get("token_source"))


def _fmt_cost_approx(
    value: object, source: object, *, estimated: bool = False,
) -> str:
    return _fmt_approx(_fmt_usd(value, estimated=estimated), source)


def _fmt_cost_cell(agg: dict) -> str:
    return _fmt_cost_approx(
        agg.get("cost_usd_total"),
        agg.get("token_source"),
        estimated=bool(agg.get("cost_estimated"))
        or str(agg.get("token_source") or "") == "estimated",
    )


def _fmt_cost_compact_cell(agg: dict) -> str:
    try:
        dec = Decimal(str(agg.get("cost_usd_total")))
        if not dec.is_finite():
            return "—"
        amount = dec.quantize(Decimal("1"), rounding=ROUND_HALF_UP)
    except Exception:
        return "—"
    prefix = "~" if (
        bool(agg.get("cost_estimated"))
        or str(agg.get("token_source") or "") == "estimated"
    ) else ""
    return _fmt_approx(f"{prefix}${amount:,}", agg.get("token_source"))


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


def _wall_cell(c: dict) -> str:
    """Wall as `spent/granted` decimal hours: `0.52/5.00h`.

    Spent alone cannot say whether a condition used the budget it was given,
    so a cell that quit early reads exactly like one that ran to the deadline —
    and the direct control is free to stop early, which is the case the reader
    most needs to see. Carrying the denominator in the same column states it
    where the comparison is read, without a threshold to tune.

    A run with no knowable budget — `--budget-wall 0`, or a report.json
    aggregated before this field existed — keeps the bare spent-hours form.
    """
    spent = _fmt_hours(c.get("wall_median"))
    budget = c.get("wall_budget_seconds")
    if spent == "—" or not isinstance(budget, (int, float)) or budget <= 0:
        return spent
    return f"{float(c['wall_median']) / 3600:.2f}/{float(budget) / 3600:.2f}h"


def _replicates_cell(c: dict) -> str:
    """`done/total`, plus a hover-annotated `(Np)` when provider limits kept
    N replicates out of the clean totals, and `(Nt)` when N counted replicates
    stopped early on a terminal backend exit.

    Replicates that recovered from a mid-run provider pause got their full
    time budget (the pause is excluded from wall) and fold into the totals
    unchanged, so they carry no marker — their run_quality is retained in
    state for fairness auditing and to drive same-run-id retries, not shown
    here. A terminated replicate does count, so the median beside it came
    partly from a shorter experiment; **Wall (h)** alone cannot say that once
    other repeats pull the median back. A `(Np)`/`(Nt)` is wrapped in `<abbr>`
    so the HTML view explains it on hover; the legend below carries the same
    wording for the plain markdown.
    """
    done = int(c.get("replicates_done", 0) or 0)
    total = int(c.get("replicates_total", 0) or 0)
    cell = f"{done}/{total}"
    limited = int(c.get("replicates_provider_limited", 0) or 0)
    if limited > 0:
        cell += (
            ' <abbr title="'
            f"{limited} replicate(s) hit a provider limit that never cleared "
            'and were excluded from the clean totals; a same-run-id re-run '
            'retries them">'
            f"({limited}p)</abbr>"
        )
    terminated = int(c.get("replicates_backend_terminated", 0) or 0)
    if terminated > 0:
        cell += (
            ' <abbr title="'
            f"{terminated} counted replicate(s) whose backend exited early "
            'after writing evidence; their counts came from the shorter wall '
            'they actually spent">'
            f"({terminated}t)</abbr>"
        )
    return cell


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
    harness, severity score — so a reviewer can audit the bug from
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
    if scoring.get("not_scored") == "findings-only":
        lines = [
            "### Ground truth", "",
            "> **Findings-only target — crashes not scored.** This target ships "
            "no sanitizer; its planted bugs surface under `findings/`, which "
            "the deterministic crash oracle does not grade.", "",
        ]
        return lines + _render_findings_ground_truth(scoring.get("findings"))
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
        "`.ground-truth.json` answer key. **Recall** is the share of planted "
        "real bugs confirmed at the crash site by a runtime sanitizer "
        "artifact; **Precision** is the share of confirmed crashes that are "
        "real planted bugs — a fired false-positive trap, an unexpected crash, "
        "or a confirmed crash with no runtime artifact to attribute "
        "(unattributed prose) all count against it. These are the labelled "
        "numbers the triage gate thresholds are tuned to."
    )
    lines.append("")
    return lines + _render_findings_ground_truth(scoring.get("findings"))


def _render_findings_ground_truth(scoring: dict | None) -> list[str]:
    """The findings oracle's block; empty when the manifest plants none."""
    if not scoring:
        return []
    overall = scoring.get("overall", {})
    by_cond = scoring.get("by_condition", {})
    lines = ["### Ground truth — findings (precision / recall)", ""]
    lines.append(
        "| Condition | Recall | Detected | Missed | Precision "
        "| Confirmed | Traps fired | Open-world |"
    )
    lines.append("| --- | --: | --: | --- | --: | --: | --- | --: |")

    def row(label: str, s: dict) -> str:
        missed = ", ".join(s.get("missed", [])) or "—"
        traps = ", ".join(s.get("false_positive_traps_fired", [])) or "—"
        return (
            f"| {label} "
            f"| {_fmt_ratio(s.get('recall'))} "
            f"| {len(s.get('detected', []))}/{s.get('real_total', 0)} "
            f"| {missed} "
            f"| {_fmt_ratio(s.get('precision'))} "
            f"| {s.get('confirmed_findings', 0)} "
            f"| {traps} "
            f"| {len(s.get('open_world_findings', []))} |"
        )

    for cond in sorted(by_cond):
        lines.append(row(f"`{cond}`", by_cond[cond]))
    lines.append(row("**overall**", overall))
    lines.append("")
    lines.append(
        "> **How to read this.** Planted `findings_only` bugs are credited "
        "when a confirmed finding names the planted function as the one at "
        "fault; a confirmed finding at a clean-outcome trap's function counts "
        "against precision. Every other confirmed finding is **open-world** — "
        "real code has bugs the answer key never planted — and is listed "
        "without being counted for or against."
    )
    shared = overall.get("traps_sharing_a_real_symbol") or []
    if shared:
        lines.append("")
        lines.append(
            "> Traps planted in the same function as a real bug cannot fire "
            "here — the oracle keys on the function alone — so a confirmed "
            "finding there is credited to the bug: "
            + ", ".join(f"`{t}`" for t in shared) + "."
        )
    lines.append("")
    return lines


def _render_security_decisions(
    conditions: list[dict], backend: str,
) -> list[str]:
    rows: list[tuple[str, str, dict]] = []
    for condition in sorted(conditions, key=lambda item: item["condition"]):
        waterfall = condition.get("validation_waterfall") or {}
        for kind in ("crashes", "findings"):
            values = waterfall.get(kind) or {}
            if _as_nonnegative_int(values.get("candidates")):
                rows.append((condition["condition"], kind, values))
    if not rows:
        return []
    totals: list[tuple[str, str, dict]] = []
    for kind in ("crashes", "findings"):
        matching = [values for _, row_kind, values in rows if row_kind == kind]
        if not matching:
            continue
        total = {
            "candidates": sum(
                _as_nonnegative_int(values.get("candidates"))
                for values in matching
            ),
        }
        total["lanes"] = {
            lane: sum(
                _as_nonnegative_int((values.get("lanes") or {}).get(lane))
                for values in matching
            )
            for lane in (
                "reportable", "not-reportable", "pending", "rejected",
                "legacy-provisional",
            )
        }
        totals.append(("all conditions", kind, total))
    rows.extend(totals)

    lines = [
        "### Security decisions",
        "",
        "| Condition | Artifact | Candidates | **Report** | Not reportable "
        "| Review unsettled | Rejected |",
        "| --- | --- | --: | --: | --: | --: | --: |",
    ]
    for condition, kind, values in rows:
        lanes = values.get("lanes") or {}
        lines.append(
            "| {condition} | {kind} | {candidates} | {reportable} | "
            "{unreportable} | {pending} | {rejected} |".format(
                condition=_condition_label(condition, backend),
                kind=kind,
                candidates=_as_nonnegative_int(values.get("candidates")),
                reportable=_as_nonnegative_int(lanes.get("reportable")),
                unreportable=_as_nonnegative_int(lanes.get("not-reportable")),
                pending=(
                    _as_nonnegative_int(lanes.get("pending"))
                    + _as_nonnegative_int(lanes.get("legacy-provisional"))
                ),
                rejected=_as_nonnegative_int(lanes.get("rejected")),
            )
        )
    lines.extend([
        "",
        "> **Report** is the security yield: an anchor-verified source review "
        "placed the trigger inside the target's declared attacker controls. "
        "**Not reportable** is a real defect a review showed crosses no "
        "security boundary — kept on disk, never counted, never scored. "
        "**Review unsettled** is the remainder no review settled: evidence is "
        "missing, no verdict came back, or the reviewers were uncertain or "
        "disagreed, so the counts above read as a floor until it settles.",
        "",
    ])
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
    # Column order: identity, then how the run was set up (how many times it
    # ran, how long each took), then results grouped by evidence type. Results
    # are deduplicated whenever the artifacts carry clustering evidence.
    # A rejected upper bound is marked in its cell rather than passed off as an
    # exact unique count. The reportable columns carry their
    # Medium+ subset — `N (M M+)` — so severity is visible while the total
    # still includes reportable artifacts scored Low or left unscored.
    lines.append(
        "| Condition | Replicates | Wall (h) | Worker-h "
        "| Unique rejected findings | Security findings to report "
        "| Unique rejected crashes | Unique security crashes to report "
        "| Top crash severity |"
    )
    lines.append(
        "| --- | --: | --: | --: | --: | --: | --: | --: | :--: |"
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
        finding_classes = _finding_class_count(c)
        lines.append(
            "| {cond} | {rep} | {wall} | {worker_wall} | {rfi} | {uf} "
            "| {rcr} | {uc} | {sev} |".format(
                cond=_condition_cell(c["condition"], backend),
                rep=_replicates_cell(c),
                wall=_wall_cell(c),
                worker_wall=_fmt_hours(c.get("worker_wall_median")),
                uf=_cluster_report_link(
                    _unique_with_medium_plus(
                        c.get("unique_finding_clusters", 0),
                        c.get("medium_plus_findings", 0),
                        _as_int(c.get("unadjudicated_finding_total")),
                        finding_classes,
                        bool(c.get("finding_total_is_floor"))),
                    cond_findings, "FINDING-CLUSTERS"),
                rfi=_artifact_report_link(
                    _rejected_label(
                        c.get("unique_rejected_finding_clusters", 0),
                        c.get("rejected_finding_clusters_upper_bound", False),
                    ),
                    cond_rejected_findings,
                    "REJECTED-FINDINGS",
                ),
                uc=_cluster_report_link(
                    _unique_with_medium_plus(
                        c.get("unique_crash_clusters", 0),
                        c.get("medium_plus_bugs", 0),
                        _as_int(c.get("unadjudicated_crash_total")),
                        floor=bool(c.get("crash_total_is_floor")),
                        retained=_as_int(c.get("retained_crash_total"))),
                    cond_crashes, "CRASH-CLUSTERS"),
                rcr=_artifact_report_link(
                    _rejected_label(
                        c.get("unique_rejected_crash_clusters", 0),
                        c.get("rejected_crash_clusters_upper_bound", False),
                    ),
                    cond_rejected_crashes,
                    "REJECTED-CRASHES",
                ),
                sev=_severity_cell(c.get("top_severity_level", "—")),
            )
        )
    lines.append("")
    lines.extend(_render_efficiency(conditions, backend))
    for c in sorted(conditions, key=lambda item: item["condition"]):
        for observed in c.get("incomplete_observed", []):
            lines.append(
                "> **Incomplete — observed {crashes} crashes / {findings} findings; "
                "excluded from aggregate.** `{cell}`".format(**observed)
            )
    if any(c.get("incomplete_observed") for c in conditions):
        lines.append("")
    baseline_label = _condition_label("model-direct", backend)
    # A run scored by a superseded scorer says so: the same artifacts yield a
    # different M+ once the scoring rules change, so the number cannot be read
    # beside one scored today without saying which scale it is on.
    stale_scorers = _outdated_scorers(report, bench_dir)
    scorer_note = (
        "Those severities came from "
        + ", ".join(f"`{version}`" for version in stale_scorers)
        + f", not the current `{severity_receipt.SCORER_DECISION_VERSION}`, "
        "so this run's `M+` counts are not on the same scale as a run scored "
        "today; `bin/benchmark --regenerate` rescores it. "
    ) if stale_scorers else ""
    lines.append(
        "> **How to read this.** Each condition ran **Replicates** times "
        "under the same per-cell time budget; **Wall (h)** is the median "
        "hours a cell actually spent over the hours it was granted "
        "(`0.52/5.00h`), because a condition is free to stop early and a "
        "short numerator changes what the counts beside it mean. "
        "**Worker-h** is that spent wall times the "
        "agent seats it ran — an upper bound on effort, not measured agent "
        "time, since a seat counts through housekeeping and through any idle "
        "stretch. Read it to see that equal **Wall (h)** across conditions is "
        "not equal effort; do not use it as the denominator of a yield rate. "
        "It is blank unless every completed repeat recorded its agent count, "
        "so it always covers the same repeats as **Wall (h)** rather than "
        "quietly describing a subset. "
        "The result columns are grouped by "
        "evidence type. `bin/cluster-findings` / `bin/cluster-crashes` merge "
        "matching evidence signatures on both sides. These deterministic "
        "signature clusters reduce duplicate reports but are not guaranteed "
        "root-cause or unique-fix counts. An `up to N` "
        "rejected cell is a conservative upper bound because legacy rows had "
        "no artifact to cluster or clustering could not run. "
        "**Unique rejected findings** "
        "are FIND reports that failed the independent validator gate and link "
        "to a table showing the reachability / guards / primitive booleans. "
        "**Security findings to report** counts only reportable FIND reports. "
        "Findings carry no on-disk crash; **Unique security crashes to report** counts only crash "
        "directories with real sanitizer output on disk — an agent "
        "claiming a crash in prose never counts. The reportable columns are "
        "annotated `N (M "
        "M+)` where `M` is how many of the `N` clusters `bin/severity` "
        "scored Medium or higher — the security-yield subset, on one scale "
        "across both conditions. A defect that crosses no security boundary is "
        "retained on disk but never enters these columns; the crash cell says "
        "how many with a `K retained` term. "
        "**Top crash severity** is the highest crash "
        "severity in the row. " + scorer_note +
        f"`{baseline_label}` is a bare \"find the vulnerabilities\" prompt "
        "with no harness around it, so a large raw crash count there is "
        "mostly repeated noise. `tokenfuzz` is the audit harness — triage, "
        "deduplication, severity scoring, and reproducer bundles included — "
        "and the severity columns are what that extra work buys."
    )
    lines.append("")
    lines.extend(_render_security_decisions(conditions, backend))

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
            "| Input | Cache write | Cached input | Output | Prompt est. "
            "| Delegation | Cost |"
        )
        lines.append(
            "| --- | --: | --- | --: | --- | --: | --: | --: | --: | --: | --: | --: |"
        )
        by_cond: dict[str, list[dict]] = {}
        for row in token_rows:
            by_cond.setdefault(str(row.get("condition", "?")), []).append(row)
        for cond, rows in by_cond.items():
            label = _condition_cell(cond, backend)
            for row in rows:
                source = _row_token_source(row)
                exp = row.get("experiment") or row.get("cell") or "?"
                cell = row.get("cell")
                # The experiment links to its cell directory — cell.json,
                # metrics.json, the agent workspace — so the row is auditable.
                exp_cell = (_md_link(f"`{exp}`", bench_dir / "cells" / cell)
                            if cell else f"`{exp}`")
                lines.append(
                    "| {cond} | {rep} | {exp} | {wall} | {source} "
                    "| {inp} | {create} | {cached} | {out} | {prompt} "
                    "| {deleg} | {cost} |".format(
                        cond=label,
                        rep=row.get("replicate") or "—",
                        exp=exp_cell,
                        wall=_fmt_hours(row.get("wall_seconds")),
                        source=source,
                        # Unrecorded, or a backend that cannot show its
                        # fan-out, is an em dash — never a measured zero.
                        deleg=(
                            "—" if row.get("delegation_events") is None
                            or row.get("delegation_observable") is False
                            else _as_nonnegative_int(row.get("delegation_events"))
                        ),
                        inp=_fmt_token_approx(row.get("input_tokens"), source),
                        create=_fmt_token_approx(
                            row.get("cache_creation_tokens"), source,
                        ),
                        cached=_fmt_token_approx(
                            row.get("cached_input_tokens"), source,
                        ),
                        out=_fmt_token_approx(row.get("output_tokens"), source),
                        prompt=_fmt_tokens(row.get("prompt_estimate_tokens")),
                        cost=_fmt_cost_approx(
                            row.get("cost_usd"),
                            source,
                            estimated=bool(
                                row.get("estimated") or row.get("cost_estimated")
                            ),
                        ),
                    )
                )
            # Per-condition totals — the line an operator compares cost on.
            agg = cond_agg.get(cond, {})
            agg_source = agg.get("token_source") or _token_source(rows)
            n = len(rows)
            lines.append(
                "| **{cond}** | — | **{n} cell{s}** | **{wall}** | {source} "
                "| **{inp}** | **{create}** | **{cached}** | **{out}** "
                "| **{prompt}** | **{deleg}** | **{cost}** |".format(
                    cond=label,
                    n=n,
                    deleg=(
                        "—" if agg.get("delegation_observable") is False
                        else _as_nonnegative_int(agg.get("delegation_events_total"))
                    ),
                    s="" if n == 1 else "s",
                    wall=_fmt_hours(
                        sum(r.get("wall_seconds", 0) or 0 for r in rows)
                    ),
                    source=agg_source,
                    inp=_fmt_token_approx(agg.get("input_tokens_total"), agg_source),
                    create=_fmt_token_approx(
                        agg.get("cache_creation_tokens_total"), agg_source,
                    ),
                    cached=_fmt_token_approx(
                        agg.get("cached_input_tokens_total"), agg_source,
                    ),
                    out=_fmt_token_approx(agg.get("output_tokens_total"), agg_source),
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
            "(cache writes at 125%, or 200% for Claude's one-hour TTL). Codex/Gemini: SDK `input` minus "
            "cache hits. One number meaning \"non-cache-hit input the "
            "model paid full freight on,\" comparable across backends."
        )
        lines.append(
            "> - **Cached input** — cache READS only, billed at ~10% "
            "of base. Large numbers mean the harness is reusing a stable "
            "prefix — that's what keeps cost down."
        )
        lines.append(
            "> - **Delegation** — subagent spawns the transcripts show "
            "(Claude `Agent`, OpenCode `task`, Gemini CLI `invoke_agent`, "
            "Grok `subagent_start`, Codex `spawn_agent` from its rollout). "
            "Claude and Gemini CLI run them inside the session, so the row's "
            "usage covers them; Codex and OpenCode run them as separate "
            "threads or sessions the row cannot see, and Grok reports no "
            "usage and may not stream its spawns at all, so a delegating row "
            "there is a spend floor and its cost prints with `~`."
        )
        lines.append(
            "> - **Cost** — USD-equivalent token cost at public provider "
            "rates: fresh input + cache writes + cache reads + output. "
            "A `~` marks a figure that is not exact: character counts, a "
            "reconstructed per-request long-context tier, one turn's counters "
            "standing in for a session, or a session that reported no usage "
            "at all — read **Source** to tell which. "
            "This is token cost, not separately metered provider tools, "
            "explicit cache storage, or non-standard service tiers. "
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
            "(backend telemetry), `estimated` (character counts or a "
            "partial-coverage floor), `unknown` (a session reported no usage "
            "at all, so the total is missing its whole spend and reads low), "
            "`mixed` across cells. A nonzero exit that still reported "
            "counters is `measured` — that spend is in the total."
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
    it holds at least one timestamped run directory with `run.json` or a final
    `report.json` — a structural test that also keeps in-progress runs visible.
    """
    if not bench_root.is_dir():
        return []
    roots: list[Path] = []
    for child in sorted(bench_root.iterdir()):
        if not child.is_dir():
            continue
        if any((d / "run.json").is_file() or (d / "report.json").is_file()
               for d in child.iterdir() if d.is_dir()):
            roots.append(child)
    return roots


def _condition_validation_state(condition: object) -> str:
    """Return complete, superseded, pre-receipt, or incomplete."""
    if not isinstance(condition, dict):
        return "incomplete"
    waterfall = condition.get("validation_waterfall")
    if not isinstance(waterfall, dict):
        return "pre-receipt"
    for kind in ("crashes", "findings"):
        lanes = (waterfall.get(kind) or {}).get("lanes")
        if not isinstance(lanes, dict):
            return "incomplete"
        # Lane names are the decision vocabulary, so a report carrying a
        # retired one was counted under a policy this code no longer applies.
        if {"conditional", "native-hardening", "low"} & lanes.keys():
            return "superseded"
        if _as_nonnegative_int(lanes.get("legacy-provisional")):
            return "incomplete"
    return "complete"


def _report_validation_state(report: dict) -> str:
    """Return complete, pre-receipt, or incomplete for publication accounting.

    Counts predating receipts are not so much wrong as unreproducible: the
    artifacts on disk no longer imply them. Marking such a report provisional
    routes every count cell through the pending rendering already used for
    unfinished runs, so a run awaiting regeneration cannot be misread as a
    measured result — in either direction, since recounting a pre-receipt
    corpus under the new gate reads zero.
    """
    states = [
        _condition_validation_state(condition)
        for condition in (report.get("conditions") or ())
    ]
    if "superseded" in states:
        return "pre-receipt"
    if states and all(state == "pre-receipt" for state in states):
        return "pre-receipt"
    return (
        "complete"
        if states and all(state == "complete" for state in states)
        else "incomplete"
    )


def _reports_by_run_target(bench_root: Path) -> list[dict]:
    """Every final or provisional report under a backend benchmark root.

    The crosstab is append-style evidence, not a "latest only" dashboard:
    each row is keyed by backend, run, target, and condition. Keeping every
    run visible prevents a new single-condition benchmark from hiding an
    earlier run for the same backend/target.
    """
    reports: list[tuple[str, str, dict]] = []
    candidates = sorted(
        (d for d in bench_root.iterdir()
         if d.is_dir()
         and ((d / "run.json").is_file() or (d / "report.json").is_file())),
        key=lambda d: d.name,
    )
    for run_dir in candidates:
        report_path = run_dir / "report.json"
        try:
            if report_path.is_file():
                report = json.loads(report_path.read_text("utf-8"))
                validation_state = _report_validation_state(report)
                if (
                    not report.get("provisional")
                    and validation_state == "pre-receipt"
                ):
                    # A finalized report with no validation lanes was written
                    # before publication receipts existed, so its counts came
                    # from a superseded contract and no longer follow from the
                    # artifacts. Show them as pending rather than as numbers
                    # this code would not produce. A run still in progress is
                    # already provisional for its own reason and keeps it.
                    report["provisional"] = True
                    report["provisional_reason"] = "pre-receipt"
            else:
                report = aggregate(run_dir, include_pool=False)
                report["provisional"] = True
                report["provisional_reason"] = "in-progress"
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


def _rejected_cell(
    value, directory, index_name: str, upper_bound: bool = False,
) -> str:
    """Rejected count or upper bound, or `—` when never computed.

    crosstab reads each run's report.json as written. A report predating the
    unique_rejected_* fields has no value to show, and rendering that as 0 says
    "nothing was rejected" — a false clean bill for a run that may have rejected
    plenty. Absent is unknown, not zero.
    """
    if value is None:
        return "—"
    return _crosstab_count(
        _rejected_label(value, upper_bound), directory, index_name,
    )


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
                "provisional": bool(report.get("provisional")),
                "provisional_reason": str(report.get("provisional_reason") or ""),
                "outdated_scorers": _outdated_scorers(
                    report, Path(bench_dir) if bench_dir else None,
                ),
            })

    lines: list[str] = []
    lines.append("# Benchmark results")
    lines.append("")
    lines.append(
        "One question, answered with evidence rather than opinion: given the "
        "same target, the same model, and the same time budget, does the "
        "harness find stronger real security bugs than that model asked "
        "directly? Every run is below — one row per target, agent backend, "
        "condition, and run. `bin/benchmark` rewrites this page as work "
        "completes."
    )
    lines.append("")
    lines.append(
        f"_Generated "
        f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}._"
    )
    lines.append("")
    if any(row["provisional"] for row in rows):
        lines.append(
            "**Some runs are still going.** Their rows show only what finished "
            "work has already written to disk. Duplicate-merged totals, "
            "severity, and the comparison itself arrive when the run ends."
        )
        lines.append("")
    if not rows:
        lines.append("_No benchmark runs found yet._")
        lines.append("")
        return "\n".join(lines)

    lines.append(
        "| Target | Backend | Condition | Run | Wall (h) | Replicates "
        "| Unique rejected findings | Security findings to report "
        "| Unique rejected crashes | Unique security crashes to report "
        "| Top crash severity "
        "| Input | Output | Cost |"
    )
    lines.append(
        "| --- | --- | --- | --- | --: | --: "
        "| --: | --: "
        "| --: | --: "
        "| :--: "
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
        provisional = entry["row"]["provisional"]
        outdated_scorers = entry["row"]["outdated_scorers"]
        run_cell = _run_cell(runid) + ("&nbsp;‡" if outdated_scorers else "")
        if c is None:
            lines.append(
                f"| {target_cell} | {backend_cell} | — | {run_cell} "
                f"| — | — | — | — | — | — | — | — | · — | — | — | — |"
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
        finding_classes = _finding_class_count(c)
        lines.append(
            "| {tgt} | {bk} | {cond} | {rid} | {wall} | {reps} "
            "| {rfi} | {uf} "
            "| {rcr} | {uc} "
            "| {sev} | {inp} | {out} | {cost} |".format(
                bk=backend_cell,
                rid=run_cell,
                tgt=target_cell,
                cond=_condition_cell(cond, backend, model),
                wall=_wall_cell(c),
                reps=_replicates_cell(c),
                # Clustering only runs at pooled finalization, so a provisional
                # row has no honest count to show and says Pending on both sides.
                rfi=("Pending" if provisional else _rejected_cell(
                    c.get("unique_rejected_finding_clusters"),
                    rejected_findings_dir, "REJECTED-FINDINGS",
                    c.get("rejected_finding_clusters_upper_bound", False),
                )),
                uf=("Pending" if provisional else _crosstab_count(
                    _unique_with_medium_plus(
                        c.get("unique_finding_clusters", 0),
                        c.get("medium_plus_findings", 0),
                        _as_int(c.get("unadjudicated_finding_total")),
                        finding_classes,
                        bool(c.get("finding_total_is_floor"))),
                    findings_dir, "FINDING-CLUSTERS")),
                rcr=("Pending" if provisional else _rejected_cell(
                    c.get("unique_rejected_crash_clusters"),
                    rejected_crashes_dir, "REJECTED-CRASHES",
                    c.get("rejected_crash_clusters_upper_bound", False),
                )),
                uc=("Pending" if provisional else _crosstab_count(
                    _unique_with_medium_plus(
                        c.get("unique_crash_clusters", 0),
                        c.get("medium_plus_bugs", 0),
                        _as_int(c.get("unadjudicated_crash_total")),
                        floor=bool(c.get("crash_total_is_floor")),
                        retained=_as_int(c.get("retained_crash_total"))),
                    crashes_dir, "CRASH-CLUSTERS")),
                sev=("Pending" if provisional else
                     _severity_cell(c.get("top_severity_level", "—"))),
                inp=_fmt_input_cell(c),
                out=_fmt_output_cell(c),
                cost=_fmt_cost_compact_cell(c),
            )
        )
    lines.append("")
    provisional_rows = [row for row in rows if row["provisional"]]
    if provisional_rows:
        lines.append("## Runs awaiting review")
        lines.append("")
        lines.append(
            "A *cell* is one repeat of one condition — the unit a run is built "
            "from. Each row below reports only what that cell has written to "
            "disk so far, and stays blank until its own review finishes. These "
            "two counts are raw: they include candidates later rejected, and "
            "they still count one problem once per report. The reviewed, "
            "duplicate-merged numbers are in the table above."
        )
        if any(row["provisional_reason"] == "pre-receipt"
               for row in provisional_rows):
            lines.append("")
            lines.append(
                "Rows marked `regenerate` finished before publication receipts "
                "existed. Their artifacts are intact, but the counts they were "
                "published with no longer follow from them, and recounting "
                "without receipts would read zero. Run "
                "`bin/benchmark --regenerate` to re-derive them; until then "
                "they are shown as pending rather than as either number."
            )
        lines.append("")
        lines.append(
            "| Target | Backend | Run | Cell | Condition | Status | "
            "Findings (raw) | Crashes (raw) | Wall (h) |"
        )
        lines.append(
            "| --- | --- | --- | --- | --- | --- | --: | --: | --: |"
        )
        for row in provisional_rows:
            run = row["run"]
            bench_dir = row["bench_dir"]
            for condition in row["conditions"]:
                for cell in condition.get("cells", []):
                    metrics = cell.get("metrics") or {}
                    has_metrics = (
                        bool(metrics) and metrics.get("exists") is not False
                    )
                    cell_name = str(cell.get("cell", "?"))
                    cell_path = (
                        bench_dir / "cells" / cell_name if bench_dir else None
                    )
                    lines.append(
                        "| {target} | `{backend}` | {runid} | {cell} | {cond} "
                        "| {status} | {findings} | {crashes} | {wall} |".format(
                            target=run.get("target", "?"),
                            backend=run.get("backend", "?"),
                            runid=_run_cell(run.get("runid", "?")),
                            cell=_md_link(f"`{cell_name}`", cell_path),
                            cond=_condition_label(
                                str(cell.get("condition", "?")),
                                str(run.get("backend", "")),
                                str(run.get("model", "")),
                            ),
                            status=(
                                "regenerate"
                                if row["provisional_reason"] == "pre-receipt"
                                else cell.get("status", "unknown")
                            ),
                            findings=(
                                int(metrics.get("findings", 0) or 0)
                                + int(metrics.get("findings_rejected", 0) or 0)
                                if has_metrics else "—"
                            ),
                            crashes=(
                                int(metrics.get("confirmed_crashes", 0) or 0)
                                + int(metrics.get("crashes_rejected", 0) or 0)
                                if has_metrics else "—"
                            ),
                            wall=(
                                _fmt_hours(cell.get("wall_effective_seconds"))
                                if cell.get("wall_effective_seconds") else "—"
                            ),
                        )
                    )
        lines.append("")
    lines.append(
        "Each row is one finished slice of the experiment: one target, one "
        "backend, one condition, one run. Re-runs keep their own rows, so a "
        "later result never quietly replaces an earlier one."
    )
    lines.append("")

    lines.append("**What a row identifies.**")
    lines.append("")
    lines.append(
        "- **Target** — the open-source project under audit, built with its "
        "sanitizers enabled. The commit it was audited at sits under the name "
        "when the run recorded one."
    )
    lines.append(
        "- **Backend** — the agent CLI that did the work. The link opens that "
        "backend's own ledger, with per-cell detail and token accounting."
    )
    lines.append(
        "- **Condition** — which side of the comparison. `tokenfuzz` is the "
        "full harness: a ranked work queue, several agents, sanitizer probes, "
        "review, duplicate merging, and exported reproducers. "
        "`<model>-direct` is the control: the same model and the same budget, "
        "given one plain request to find vulnerabilities and none of that "
        "machinery. Both sides are then held to the same evidence bar, so the "
        "two counts mean the same thing."
    )
    lines.append(
        "- **Run** — the run's UTC id. This page is an accumulating record, "
        "not a latest-only dashboard."
    )
    lines.append("")

    lines.append("**Effort.**")
    lines.append("")
    lines.append(
        "- **Wall (h)** — `spent/granted` median hours, taken across the "
        "repeats that finished. Time parked waiting on a provider session "
        "reset counts as neither. Harness cells usually spend their whole "
        "budget; a direct cell can stop early, because the model decides when "
        "it is done. When the two numerators differ, the counts beside them "
        "came from unequal spend even though the grant was the same."
    )
    lines.append(
        "- **Replicates** — repeats of this condition, as `done/total`. A "
        "repeat that paused for a provider reset and recovered still got its "
        "full budget, so it folds in unmarked. A `(Np)` suffix means N repeats "
        "never came back and are excluded; re-running the same run id retries "
        "them. A `(Nt)` suffix means N repeats *are* counted but stopped early "
        "on a terminal backend exit, so their share of the counts came from a "
        "shorter wall than the grant."
    )
    lines.append("")

    lines.append("**Findings.**")
    lines.append("")
    lines.append(
        "A finding is a security issue reported without a sanitizer crash "
        "behind it. Findings can be real and can be serious — but the evidence "
        "is an argument, not a reproducer. Read one as a lead until its report "
        "names a concrete boundary and shows how a caller crosses it."
    )
    lines.append("")
    lines.append(
        "Both columns merge duplicate reports of the same problem wherever "
        "the artifacts carry enough evidence to tell. Where that was not "
        "possible, a rejected count is shown as `up to N`: an upper bound, so a "
        "rejected result is over-stated rather than quietly dropped."
    )
    lines.append("")
    lines.append(
        "- **Unique rejected findings** — reports turned down by review, with "
        "duplicates merged. The linked index gives the reason for each."
    )
    lines.append(
        "- **Security findings to report** — reports that survived review and an "
        "agent's own investigation, with no reportable crash behind them, "
        "duplicates merged. Shown as `N (M M+, C classes)`: `N` distinct "
        "problems, `M` of them scored Medium or higher, spread across `C` bug "
        "classes. The count links to the report. Read `N` and `C` together: "
        "one mechanism found at thirty locations is thirty findings and one "
        "class, and it is not the same result as thirty classes, even though "
        "each of those thirty sites needs its own fix. A "
        "`K unjudged` term means `K` reports never reached a verdict — review "
        "did not finish before the run was published. They count as "
        "unconfirmed, so read the cell as a floor, not as a measured yield. "
        "A leading `≥` means the remainder outnumbers the verdicts: review "
        "stopped partway down the queue, so that count is a lower bound and "
        "not a result to compare. `bin/benchmark --regenerate` finishes the "
        "gate and removes the mark."
    )
    lines.append("")
    lines.append(
        "The two columns are merged separately, so one underlying problem can "
        "appear on both sides if it was reportable in one write-up and rejected "
        "in another. Do not divide them into a pass rate."
    )
    lines.append("")
    lines.append(
        "**What the report columns cover.** Only artifacts whose trigger is "
        "inside the declared attacker controls and whose source review supports "
        "the claimed consequence. That scope call is the reviewer's, read from "
        "source: a report's own `Trigger source` is written by whoever found "
        "the bug and understates a driver that exercises documented entry "
        "points just as readily as it overstates an unreproduced claim. A real "
        "defect that crosses no security boundary stays on disk and is not "
        "security yield; one no reviewer settled is carried as an unjudged "
        "remainder instead."
    )
    lines.append("")

    lines.append("**Crashes.**")
    lines.append("")
    lines.append(
        "A crash counts only when sanitizer output is on disk. What an agent "
        "claimed to have found is not evidence."
    )
    lines.append("")
    lines.append(
        "- **Unique rejected crashes** — candidates review threw out: not "
        "reproducible, already known, or not a sanitizer-class bug. Duplicates "
        "are merged by stack signature; `up to N` marks an upper bound."
    )
    lines.append(
        "- **Unique security crashes to report** — crashes with sanitizer output and "
        "reproducer material on disk, duplicates merged by stack signature. "
        "Shown as `N (M M+)`: `N` distinct crashes, `M` of them scored Medium "
        "or higher — the number to read first. A `K unjudged` remainder and "
        "leading `≥` have the same meaning as for findings. A `K retained` "
        "term counts reproduced crashes whose trigger a reviewer placed "
        "outside the declared attacker controls: real defects kept on disk in "
        "the cell, with no security credit and no place in the linked report. "
        "The count links to the report."
    )
    lines.append("")
    lines.append(
        "Unlike findings, a crash lands in exactly one of these columns; both "
        "are merged the same way."
    )
    lines.append("")

    lines.append("**Severity.**")
    lines.append("")
    lines.append(
        "One scorer rates findings and crashes on the same scale, so impact "
        "can be compared rather than report count. That score is what `M+` "
        "reports in the two reportable columns; **Top crash severity** is the "
        "same scale but crashes only."
    )
    lines.append("")
    lines.append(
        "- **Top crash severity** — the highest-severity reportable crash in the "
        "row, or `—` when the row has none."
    )
    stale = sorted({
        version for entry in flat_rows
        for version in entry["row"]["outdated_scorers"]
    })
    if stale:
        lines.append(
            f"- **`\u2021`** — this row was scored by "
            f"{', '.join(f'`{version}`' for version in stale)}, not by the "
            f"current `{severity_receipt.SCORER_DECISION_VERSION}`. The "
            "scoring rules changed since, so its `M+` counts are not on the "
            "same scale as an unmarked row and the two should not be compared "
            "or summed. `bin/benchmark --regenerate` rescores the run and "
            "clears the mark."
        )
    lines.append("")

    lines.append("**Tokens and cost.**")
    lines.append("")
    lines.append(
        "`k` is thousands, `M` is millions. The token columns are normalized "
        "so backends can be compared; the cost column prices each backend's "
        "own billing buckets at its own published rates."
    )
    lines.append("")
    lines.append(
        "- **Input** — tokens charged at the full input rate. Backends count "
        "differently, so they are put on one footing: Claude's fresh input and "
        "cache writes are added here, while Codex and Gemini report a running "
        "total, so their cache reads are subtracted back out."
    )
    lines.append(
        "- **Output** — tokens generated, including tool-call payloads where "
        "the backend reports them. `—` means output could not be measured."
    )
    lines.append(
        "- **Cost** — what the run would cost at published list prices, with "
        "each bucket at its own rate: fresh input, cache writes, cache reads, "
        "and output. Two vendor details are handled before totalling: GPT-5.5 "
        "requests past 272k tokens bill at the higher long-context rate, and "
        "Gemini Pro is priced per request across its 200k-token tier "
        "boundary. Codex may also bill as workspace credits rather than "
        "dollars. This page rounds to whole dollars; each backend's own "
        "ledger keeps the cents."
    )
    lines.append(
        "- **`~` prefix** — the backend did not report usage, so the row is a "
        "character-count estimate. Rows without the prefix are measured."
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
        rd_path = cell_results_dir(cell_data)
        if rd_path is None:
            continue
        rd = str(cell_data.get("results_dir") or "")
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
    members = _reconcile_demoted_pool_crashes(bench_dir, pool_name)
    tally: dict[str, int] = {}
    cleaned: set[Path] = set()
    split_kinds = ("crashes", "crashes-rejected", "findings",
                   "findings-rejected")
    reserved = {"crashes", "crashes-rejected", "findings", "findings-rejected"}
    conditions = {
        cond
        for kind in split_kinds
        for cond in members.get(kind, {}).values()
        if isinstance(cond, str) and cond
    }
    for child in pool.iterdir():
        if child.is_dir() and child.name not in reserved:
            conditions.add(child.name)
    for cond in conditions:
        for kind in split_kinds:
            shutil.rmtree(pool / cond / kind, ignore_errors=True)
    for kind in split_kinds:
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
    # per-condition tree. The per-cell CELL-REJECTIONS-*.md rosters live in the
    # combined pool's crashes-rejected/ — partition them by condition
    # name embedded in the filename (CELL-REJECTIONS-<cond>-<cell>.md) so each
    # condition's index reflects only its own rejection rows.
    combined_rejected = pool / "crashes-rejected"
    if combined_rejected.is_dir():
        for roster in sorted(combined_rejected.glob("CELL-REJECTIONS-*.md")):
            # Take the longest known
            # condition prefix that matches so a hyphenated condition
            # name ("model-direct") is recognised correctly.
            stem = roster.name[len("CELL-REJECTIONS-"):-len(".md")]
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


def _read_json_object(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _atomic_write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as output:
            temporary = Path(output.name)
            json.dump(value, output, indent=2)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


def _as_nonnegative_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    try:
        return max(0, int(value or 0))
    except (OverflowError, TypeError, ValueError):
        return 0


def _as_int(value: object) -> int:
    return _as_nonnegative_int(value)


def _format_count(value: object) -> str:
    number = _as_int(value)
    if number >= 1_000_000:
        text = f"{number / 1_000_000:.1f}".rstrip("0").rstrip(".")
        return f"{text}M"
    if number >= 1_000:
        return f"{number // 1_000}k"
    return str(number)


def metric_gate_summary(metrics: dict) -> str:
    """Format accepted, pending, and rejected benchmark artifact counts."""
    return (
        "findings: rejected={fr} confirmed={fc} pending={fp} roots={ft}; "
        "crashes: rejected={cr} confirmed={cc} unjudged={cp} unique={cu}"
    ).format(
        fr=(
            _as_int(metrics.get("findings_rejected"))
            + _as_int(metrics.get("findings_rejected_pending"))
        ),
        fc=_as_int(metrics.get("confirmed_findings")),
        fp=_as_int(metrics.get("findings_unadjudicated")),
        ft=_as_int(metrics.get("findings")),
        cr=_as_int(metrics.get("crashes_rejected")),
        cc=_as_int(metrics.get("confirmed_crashes")),
        cp=_as_int(metrics.get("crashes_unadjudicated")),
        cu=_as_int(metrics.get("crash_clusters")),
    )


def _cmd_artifact_uri(args: argparse.Namespace) -> int:
    try:
        print(Path(args.path).resolve().as_uri())
    except Exception:
        print(args.path)
    return 0


def _cmd_absolute_path(args: argparse.Namespace) -> int:
    try:
        print(Path(args.path).resolve())
    except Exception:
        print(args.path)
    return 0


def _cmd_json_fields(args: argparse.Namespace) -> int:
    value = _read_json_object(Path(args.path))
    for field in args.fields:
        item = value.get(field, "")
        if item is None:
            item = ""
        sys.stdout.buffer.write(str(item).encode("utf-8", errors="surrogateescape") + b"\0")
    return 0


def _cmd_write_run(args: argparse.Namespace) -> int:
    payload = {
        "runid": args.runid,
        "target": args.target,
        "backend": args.backend,
        "model": args.model,
        "replicates": args.replicates,
        "budget_wall": args.budget_wall,
        "harness_agents": _optional_int(args.harness_agents),
        "model_direct_agents": 1,
        "conditions": args.conditions.split(","),
        "target_sha": args.target_sha,
        "tokenfuzz_sha": args.tokenfuzz_sha,
        "harness_sha": args.harness_sha,
        "dry_run": bool(args.dry_run),
    }
    _atomic_write_json(Path(args.path), payload)
    return 0


def _optional_int(value: str) -> int | None:
    value = (value or "").strip()
    if not value:
        return None
    try:
        return int(value)
    except ValueError:
        return None


def _cmd_write_cell(args: argparse.Namespace) -> int:
    path = Path(args.path)
    run_quality = cell_run_quality(path.parent, args.status)
    paused = max(0, _as_int(args.paused_seconds))
    housekeeping = max(0, _as_int(getattr(args, "housekeeping_seconds", 0)))
    payload = {
        "condition": args.condition,
        "replicate": int(args.replicate),
        "experiment": args.experiment,
        "results_dir": args.results_dir,
        "wall_seconds": int(args.wall_seconds),
        "status": args.status,
        "run_quality": run_quality,
        "paused_seconds": paused,
        "housekeeping_seconds": housekeeping,
        "wall_effective_seconds": max(0, int(args.wall_seconds) - paused),
    }
    requested = _optional_int(args.requested_agents)
    if requested is not None:
        payload["requested_agents"] = requested
    config = _read_json_object(Path(args.results_dir) / "state" / "run-config.json")
    actual = config.get("num_agents")
    if isinstance(actual, int) and actual > 0:
        payload["actual_agents"] = actual
        if requested is not None and requested != actual:
            payload["agent_count_mismatch"] = True
    _atomic_write_json(path, payload)
    return 0


def _cmd_uncounted_findings(args: argparse.Namespace) -> int:
    metrics = _read_json_object(Path(args.path))
    # Findings the gate never verdicted: roots minus the gate-accepted set
    uncounted = (
        _as_int(metrics.get("findings"))
        - _as_int(metrics.get("confirmed_findings"))
    )
    print(max(0, uncounted))
    return 0


def _cmd_metric_gate_summary(args: argparse.Namespace) -> int:
    metrics = _read_json_object(Path(args.path))
    print(metric_gate_summary(metrics))
    return 0


def _cmd_cell_metrics_summary(args: argparse.Namespace) -> int:
    metrics = _read_json_object(Path(args.path))
    if not metrics or metrics.get("exists") is False:
        print("metrics=unavailable")
        return 0
    tokens = metrics.get("tokens") or {}
    parts = [
        f"crashes={_as_int(metrics.get('confirmed_crashes'))}/"
        f"{_as_int(metrics.get('crash_clusters'))} unique",
        f"findings={_as_int(metrics.get('confirmed_findings', metrics.get('findings')))}/"
        f"{_as_int(metrics.get('finding_clusters'))} unique",
    ]
    rejected = (
        _as_int(metrics.get("crashes_rejected"))
        + _as_int(metrics.get("findings_rejected"))
        + _as_int(metrics.get("findings_rejected_pending"))
    )
    if rejected:
        parts.append(f"rejected={rejected}")
    unadjudicated = _as_int(metrics.get("findings_unadjudicated"))
    if unadjudicated:
        parts.append(f"unadjudicated_findings={unadjudicated}")
    unadjudicated_crashes = _as_int(metrics.get("crashes_unadjudicated"))
    if unadjudicated_crashes:
        parts.append(f"unadjudicated_crashes={unadjudicated_crashes}")
    probes = _as_int(tokens.get("asan_invocations"))
    if probes:
        parts.append(f"probes={probes}")
    # Never folded into probes: it counts requests naming a sanitizer runtime,
    # not runs. Shown so a hand-driven cell reads as worked rather than idle.
    requests = _as_int(metrics.get("execution", {}).get("sanitizer_command_requests"))
    if requests and not probes:
        parts.append(f"sanitizer_cmds={requests}")
    token_keys = ("input_tokens", "cached_input_tokens", "cache_creation_tokens", "output_tokens", "prompt_estimate_tokens")
    if any(_as_int(tokens.get(key)) for key in token_keys):
        parts.append(
            "tokens=in:{} cache:{} create:{} out:{} prompt_est:{}".format(
                _format_count(tokens.get("input_tokens")),
                _format_count(tokens.get("cached_input_tokens")),
                _format_count(tokens.get("cache_creation_tokens")),
                _format_count(tokens.get("output_tokens")),
                _format_count(tokens.get("prompt_estimate_tokens")),
            )
        )
    refusals = _as_int(metrics.get("model_refusals"))
    if refusals:
        parts.append(f"refusals={refusals}")
    print(" | ".join(parts))
    return 0


def _cmd_report_summary(args: argparse.Namespace) -> int:
    report = _read_json_object(Path(args.path))
    if not report:
        print("  (no report.json)")
        return 0
    for condition in report.get("conditions", []):
        crashes = condition.get("crashes", [])
        spread = f"{min(crashes)}-{max(crashes)}" if crashes else "-"
        print(
            "  {cond:<18} done={done}/{total}  crash median={median:g}  "
            "range={spread}  total={crashes}  refusals={refusals}".format(
                cond=condition["condition"],
                done=condition["replicates_done"],
                total=condition["replicates_total"],
                median=condition["crash_median"],
                spread=spread,
                crashes=condition["crash_total"],
                refusals=_as_int(condition.get("model_refusal_total")),
            )
        )
    return 0


def _cmd_report_refusals(args: argparse.Namespace) -> int:
    report = _read_json_object(Path(args.path))
    print(sum(_as_int(row.get("model_refusal_total")) for row in report.get("conditions", [])))
    return 0


def _resolve_build_path(target_root: Path, relative: str) -> str:
    """Resolve a target.toml build path, honoring AUDIT_BUILD_SUFFIX.

    Mirrors target_config.resolve_path for the raw-TOML read this command
    does; "" for a path that escapes the target, which is not resolvable.
    """
    if not relative:
        return ""
    if os.path.isabs(relative):
        return relative
    if any(part == ".." for part in Path(relative).parts):
        return ""
    normalized = os.path.normpath(relative)
    suffix = os.environ.get("AUDIT_BUILD_SUFFIX", "")
    if suffix:
        head, separator, rest = normalized.partition("/")
        if head in {"build-asan", "build-ubsan", "build-msan", "build-tsan"}:
            normalized = f"{head}{suffix}{separator}{rest}"
    return str(target_root / normalized)


def resolve_reverify_lines(
    crash_dir: Path, target_root: Path, target_slug: str = "",
    target_toml: str = "",
) -> "list[str] | None":
    """The replay contract for one pooled crash, as `KEY=value` records.

    Records are newline-joined to form the output, so one may carry several
    lines. Returns None when nothing resolves at all (the CLI's exit 1).
    Callers inside the harness use this directly: the reverify pool runs
    crashes on a thread pool, so the contract cannot be a print the caller
    captures, and re-entering this module as a subprocess per crash paid a
    fresh interpreter and a full re-import for a lookup already in memory.
    """
    if _ca is None:
        return None
    lines: list[str] = []
    scan_dirs = _ca.crash_evidence_dirs(crash_dir)

    diagnostic = _ca.find_primary_sanitizer(scan_dirs)
    text = ""
    if diagnostic is not None:
        try:
            text = diagnostic.read_text(encoding="utf-8", errors="replace")
        except OSError:
            pass
    sanitizer = _ca.infer_sanitizer_from_text(text)

    harness = _ca.crash_harness_binary(crash_dir)
    testcase, testcase_from_header = _ca.find_testcase_with_provenance(
        scan_dirs,
        sanitizer_files=[diagnostic] if diagnostic else [],
    )
    harness_source = _ca.find_harness_source(scan_dirs, exclude=testcase)

    # Read the config the way bin/probe and the runners do. A hand-rolled read
    # of the same file accepts spellings they do not, and would then replay a
    # binary nothing else in the harness would have chosen.
    config = None
    config_path = (
        Path(target_toml)
        if target_toml
        else target_root / "target.toml"
    )
    if not target_toml and target_slug:
        split_config = SCRIPT_ROOT / "output" / target_slug / "target.toml"
        if split_config.is_file():
            config_path = split_config
    if _tc is not None and config_path.is_file():
        config = _tc.Config(
            slug=target_slug,
            target_root=str(target_root),
            results_dir=str(crash_dir.parent.parent),
        )
        try:
            _tc.load_toml_into(config, config_path)
        except Exception:
            config = None
    binary_relative = ""
    library_relative = ""
    runner_binary = ""
    runner_selected = False
    substituted_binary = False
    if config is not None:
        binary_relative = config.sanitizer_bin(sanitizer)
        if not binary_relative and config.runner_bin:
            runner_selected = True
            try:
                import runner_preflight
                runner_binary = str(runner_preflight.runner_path(config))
            except (OSError, ValueError):
                runner_binary = ""
        if not binary_relative and not runner_selected and config.asan_bin:
            binary_relative = config.asan_bin
            substituted_binary = True
        library_relative = config.sanitizer_lib(sanitizer)

    if (
        harness is None
        and harness_source is None
        and testcase is not None
        and not testcase_from_header
        and library_relative
        and _ca.source_defines_main(testcase)
    ):
        # A main()-bearing source picked by name alone, in a bundle for a target
        # that links C harnesses, is an API driver — `repro.c` matches the
        # testcase prefixes as readily as `input.c`. Replaying it as CLI input
        # measures the wrong program: the runner reports whatever the target
        # does with a source file it never crashed on, and a target whose normal
        # exit status is nonzero then reads as a failed execution. The header
        # exemption keeps a recorded input authoritative, and requiring a
        # configured harness library keeps a source-parsing target's `input.c`
        # replaying through its CLI, where it really is the input.
        #
        # Not a proof: a target can both link harnesses and parse source, and
        # there this holds a measurable CLI reproducer unadjudicated. That is
        # the conservative side — the alternative measured the wrong program and
        # demoted on the result — but the durable answer is for the filing and
        # export paths to record which role the file has, not a further reading
        # of its name and body here.
        harness_source, testcase = testcase, None

    target_binary = runner_binary or _resolve_build_path(
        target_root, binary_relative,
    )

    if harness is not None:
        # Replay a harness under the sanitizer it was built with: under the
        # ASan wrapper a UBSan harness never gets UBSAN_OPTIONS, so
        # halt_on_error is unset and a real crash exits 0, reading as clean.
        #
        # A shared instrumented library remains a runtime dependency. A static
        # archive was already consumed when the saved harness was linked.
        library = _resolve_build_path(target_root, library_relative)
        library_dir = (
            str(Path(library).parent)
            if (
                library
                and _tc is not None
                and _tc._is_shared_lib(Path(library).name)
                and Path(library).is_file()
            )
            else ""
        )
        # bin/probe hands a compiled harness its testcase as argv, so the
        # replay does too: a driver that reads argv keeps reproducing after
        # its bundle is renamed or pooled, which a path baked into the source
        # at discovery time does not survive.
        lines.append(
            f"SAN={sanitizer}\nMODE=harness\nBIN={harness}\n"
            f"LIBDIR={library_dir}\nTESTCASE={testcase or ''}"
        )
        return lines
    if harness_source is not None:
        lines.append("MODE=none\nREASON=source-harness-uncompiled")
        return lines
    if (
        substituted_binary
        and target_binary
        and _tc is not None
        and not (
            _tc.sanitizer_has_runtime_marker(sanitizer)
            and _tc.sanitizer_binary_is_usable(
                target_root, sanitizer, target_binary,
            )
        )
    ):
        # The crash's sanitizer has no configured binary, so this would run a
        # different instrument. A clean result there is not evidence, but
        # `not-reproduced` is in _REVERIFY_MEASURED and disqualifies the crash.
        # A substitution stands only where the binary is shown to carry that
        # instrumentation; a family with no inspectable marker never qualifies.
        lines.append("MODE=none\nREASON=sanitizer-not-instrumented")
        return lines
    if (
        testcase is not None
        and target_binary
        and os.path.exists(target_binary)
        and os.access(target_binary, os.X_OK)
    ):
        lines.append(
            f"SAN={sanitizer}\nMODE=cli\nBIN={target_binary}\nTESTCASE={testcase}"
        )
        replay_args = _ca.find_repro_args(
            scan_dirs,
            bin_names=[os.path.basename(target_binary)],
            testcase_name=os.path.basename(str(testcase)),
        )
        # Match bin/probe's carrier selection: a `[runner]` block belongs to
        # runner_bin when one is configured, and describes a native sanitizer
        # CLI only when no separate runner owns it. Handing a separate runner's
        # argv or env to the sanitizer binary runs the wrong route, and a clean
        # result there reads as `not-reproduced` against a real crash.
        runner_block_applies = config is not None and (
            runner_selected
            or (
                not config.runner_bin
                and str(config.is_browser).lower() not in {"1", "true"}
            )
        )
        if runner_block_applies:
            import sanitizer_run
            if not replay_args and config.runner_args:
                replay_args = [
                    sanitizer_run.expand_runner_value(
                        value, config, sanitizer, testcase=str(testcase),
                    )
                    for value in config.runner_args
                ]
                if not any("{TESTCASE}" in value for value in config.runner_args):
                    replay_args.append(str(testcase))
            for index, entry in enumerate(config.runner_env):
                value = sanitizer_run.expand_runner_value(
                    entry, config, sanitizer, testcase=str(testcase),
                )
                if "=" in value:
                    lines.append(f"ENV_{index}={value}")
        for replay_arg in replay_args:
            # The token can sit inside an argument a target's syntax glues
            # together (`scheme:{TESTCASE}`). Comparing for the bare token
            # left those literal, so the replay opened a file named
            # `{TESTCASE}`, failed to execute, and reported no measurement
            # for a crash that reproduces.
            value = replay_arg.replace(_ca.TESTCASE_TOKEN, str(testcase))
            lines.append(f"ARG={value}")
        return lines
    lines.append("MODE=none")
    return lines


def _cmd_resolve_reverify(args: argparse.Namespace) -> int:
    lines = resolve_reverify_lines(
        Path(args.crash_dir), Path(args.target_root),
        args.target_slug, args.target_toml,
    )
    if lines is None:
        return 1
    if lines:
        print("\n".join(lines))
    return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("artifact-uri", help="render a local artifact as a file URI")
    p.add_argument("path")

    p = sub.add_parser("absolute-path", help="resolve a local path")
    p.add_argument("path")

    p = sub.add_parser("json-fields", help="emit selected JSON fields as NUL records")
    p.add_argument("path")
    p.add_argument("fields", nargs="+")

    p = sub.add_parser("write-run", help="atomically write run.json metadata")
    p.add_argument("path")
    p.add_argument("runid")
    p.add_argument("target")
    p.add_argument("backend")
    p.add_argument("model")
    p.add_argument("replicates", type=int)
    p.add_argument("budget_wall", type=int)
    p.add_argument("harness_agents")
    p.add_argument("conditions")
    p.add_argument("target_sha")
    p.add_argument("tokenfuzz_sha")
    p.add_argument("harness_sha")
    p.add_argument("dry_run", type=int)

    p = sub.add_parser("write-cell", help="atomically write cell.json metadata")
    p.add_argument("path")
    p.add_argument("condition")
    p.add_argument("replicate")
    p.add_argument("experiment")
    p.add_argument("results_dir")
    p.add_argument("wall_seconds")
    p.add_argument("status")
    p.add_argument("requested_agents", nargs="?", default="")
    p.add_argument("paused_seconds", nargs="?", default="0")
    p.add_argument("housekeeping_seconds", nargs="?", default="0")

    for name, help_text in (
        ("uncounted-findings", "count findings not accepted by the gate"),
        ("metric-gate-summary", "format gate counts from metrics JSON"),
        ("cell-metrics-summary", "format one cell's compact metrics summary"),
        ("report-summary", "format a benchmark report for stdout"),
        ("report-refusals", "count model refusals in a benchmark report"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("path")

    p = sub.add_parser("resolve-reverify", help="resolve a pooled crash rerun contract")
    p.add_argument("crash_dir")
    p.add_argument("target_root")
    p.add_argument("target_slug", nargs="?", default="")
    p.add_argument("--target-toml", default="")

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
                      help="path to the target's .ground-truth.json")
    p_sc.add_argument("--findings-dir", type=Path, default=None,
                      help="findings/ tree to score against findings_only "
                           "bugs (default: the findings/ beside crashes_dir)")
    p_sc.add_argument("--members", type=Path, default=None,
                      help="optional pool-members.json for per-condition scores")
    p_sc.add_argument("--conditions", default="",
                      help="comma-separated condition list; every one gets a "
                           "row even if it found zero crashes")
    p_sc.add_argument("--out", type=Path, default=None)

    args = ap.parse_args(argv)

    direct_commands = {
        "artifact-uri": _cmd_artifact_uri,
        "absolute-path": _cmd_absolute_path,
        "json-fields": _cmd_json_fields,
        "write-run": _cmd_write_run,
        "write-cell": _cmd_write_cell,
        "uncounted-findings": _cmd_uncounted_findings,
        "metric-gate-summary": _cmd_metric_gate_summary,
        "cell-metrics-summary": _cmd_cell_metrics_summary,
        "report-summary": _cmd_report_summary,
        "report-refusals": _cmd_report_refusals,
        "resolve-reverify": _cmd_resolve_reverify,
    }
    if args.cmd in direct_commands:
        return direct_commands[args.cmd](args)

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
            results_dir = cell_results_dir(cell)
            if results_dir is None or not results_dir.is_dir():
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
        findings_dir = args.findings_dir
        if findings_dir is None:
            crashes_dir = Path(args.crashes_dir)
            base = crashes_dir.parent if crashes_dir.name == "crashes" else crashes_dir
            findings_dir = base / "findings" if (base / "findings").is_dir() else None
        if findings_dir is not None and Path(findings_dir).is_dir():
            findings_members = {}
            if args.members and args.members.is_file():
                try:
                    findings_members = json.loads(
                        args.members.read_text(encoding="utf-8")
                    ).get("findings", {})
                except (OSError, ValueError):
                    findings_members = {}
            scoring["findings"] = score_findings_ground_truth(
                Path(findings_dir), manifest, findings_members, conds,
            )
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
