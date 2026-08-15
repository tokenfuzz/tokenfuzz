"""cluster_common.py — shared helpers for bin/cluster-crashes + bin/cluster-findings.

Both clustering tools emit a `*-CLUSTERS.md` report, render an HTML
sibling next to it, and — when asked to aggregate a whole target root — serialize concurrent backends
behind an advisory file lock. That scaffolding is identical between the
two tools; only the signatures, file names, and stack-frame logic differ.
Keeping the scaffolding here means a fix (e.g. to the render timeout or
the lock semantics) lands in one place instead of drifting between two
near-identical copies.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable

import report_identity

_HSPACE_RE = re.compile(r"[ \t]+")
_CLUSTER_BARE_RE = re.compile(r"^Cluster:\s*(.*?)\s*$", re.IGNORECASE)
_CLUSTER_TABLE_RE = re.compile(
    r"^\|\s*Cluster\s*\|\s*([^|]+?)\s*\|", re.IGNORECASE
)


_PENDING_SIDECAR = ".promotion_pending"
_PENDING_TODO_MARKER = "_TODO (agent):"


def promotion_pending_reasons(directory: Path) -> list[str]:
    """Why this bundle is still an unfinished auto-filed skeleton, else [].

    Two independent sources, because either one alone misses real bundles:

      * the `.promotion_pending` sidecar triage writes — searched beside the
        report *and* under `.audit/`, where export and benchmark pooling move
        sidecars. Reading only the top level marks a pooled skeleton "OK";
      * the `_TODO (agent):` placeholders the skeleton ships with, which
        survive even when no sidecar travelled with the bundle.

    An unfinished report has no root cause and no data flow — it must never
    be presented as a triaged result, whatever the index it lands in.
    """
    reasons: list[str] = []
    marker_seen = False
    for base in (directory, directory / ".audit"):
        marker = base / _PENDING_SIDECAR
        if not marker.is_file():
            continue
        marker_seen = True
        try:
            text = marker.read_text("utf-8", errors="replace")
        except OSError:
            text = ""
        reasons.extend(line.strip() for line in text.splitlines() if line.strip())
    if marker_seen and not reasons:
        reasons.append(_PENDING_SIDECAR)
    report = report_identity.find_report(directory)
    if report is not None:
        try:
            if _PENDING_TODO_MARKER in report.read_text("utf-8", errors="replace"):
                reasons.append(f"{report.name}(unfilled _TODO sections)")
        except OSError:
            pass
    # De-duplicate while keeping order: sidecar and TODO scan often name the
    # same report file.
    seen: set[str] = set()
    return [r for r in reasons if not (r in seen or seen.add(r))]


def texts_differ_beyond_padding(old: str, new: str) -> bool:
    """True when *old* and *new* differ by more than horizontal whitespace.

    bin/render-md pads markdown table columns in place; the cluster
    stampers re-substitute table cells unpadded. Without this comparison
    the two ping-pong — every housekeeping pass rewrote each member
    report (same content modulo padding) and re-rendered its HTML.
    Collapsing runs of spaces/tabs before comparing treats padding-only
    drift as "unchanged" while any real cell/narrative change still wins.
    """
    return _HSPACE_RE.sub(" ", old) != _HSPACE_RE.sub(" ", new)


def exact_child_files(parent: Path, names: Iterable[str]) -> tuple[Path, ...]:
    """Return exact-case file children in the requested priority order."""
    try:
        children = {child.name: child for child in parent.iterdir()}
    except OSError:
        return ()
    return tuple(
        child
        for name in names
        if (child := children.get(name)) is not None and child.is_file()
    )


def exact_child_file(parent: Path, names: Iterable[str]) -> Path | None:
    """Return the first exact-case file child in the requested order."""
    return next(iter(exact_child_files(parent, names)), None)


def artifact_report_paths(directory: Path) -> tuple[Path, ...]:
    """Return recognized report files in their canonical priority order."""
    return exact_child_files(directory, report_identity.REPORT_NAMES)


def artifact_report_path(directory: Path) -> Path | None:
    """Return the report file used for cluster identity, if present."""
    return next(iter(artifact_report_paths(directory)), None)


def cluster_label(report_text: str) -> str:
    """Read the deterministic cluster stamp from report text.

    An unfilled stamp is not a label. Ask the shared report vocabulary rather
    than carrying a local list of blanks, which knew the dashes bin/severity
    writes but not the placeholder bin/export-repro writes — so every exported
    bundle awaiting its first clustering pass answered with the same key.
    """
    for line in report_text.splitlines():
        match = _CLUSTER_BARE_RE.match(line) or _CLUSTER_TABLE_RE.match(line)
        if match:
            value = match.group(1).strip()
            if not report_identity.field_value_is_placeholder("Cluster", value):
                # The stamp is the first token; parenthetical member summaries
                # differ per report and are descriptive, not identity.
                return value.split(maxsplit=1)[0]
    return ""


def artifact_cluster_id(directory: Path) -> str:
    """Read one artifact's deterministic cluster id without modifying it."""
    for report in artifact_report_paths(directory):
        try:
            with report.open(encoding="utf-8", errors="replace") as stream:
                for line in stream:
                    cluster = cluster_label(line)
                    if cluster:
                        return cluster
        except OSError:
            continue
    return ""


def render_md_sibling(md_path: Path, title: str | None = None) -> None:
    """Run bin/render-md on an emitted markdown file.

    Pads the table columns for the raw markdown view AND writes a stylish
    HTML sibling next to it for direct browser viewing. Best-effort —
    silent no-op when render-md or python3 is unavailable. Set
    ``CLUSTER_HTML=0`` to keep the markdown padding but skip HTML emission.
    """
    here = Path(__file__).resolve().parent.parent / "bin"
    render = here / "render-md"
    if not render.is_file() or not os.access(render, os.X_OK):
        return
    if shutil.which("python3") is None:
        return
    args = ["python3", str(render), str(md_path)]
    if os.environ.get("CLUSTER_HTML") != "0":
        args.append("--html-sibling")
    if title:
        args.extend(["--title", title])
    try:
        subprocess.run(args, capture_output=True, timeout=15, check=False)
    except (subprocess.SubprocessError, OSError):
        pass


def render_md_batch(md_paths: "list[Path]") -> None:
    """Render many markdown reports in ONE render-md process.

    render-md accepts multiple inputs and titles each by its parent dir under
    ``--title-from parent`` — identical to the per-file
    ``render_md_sibling(title=path.parent.name)`` it replaces. This turns the
    cold-cluster hotspot (one subprocess per member; profiled at ~40 ms/finding,
    5.5 s for 150 findings, all in subprocess wait) into a single spawn. Chunked
    so a very large finding set can never overflow ARG_MAX. Best-effort.
    """
    if not md_paths:
        return
    here = Path(__file__).resolve().parent.parent / "bin"
    render = here / "render-md"
    if not render.is_file() or not os.access(render, os.X_OK):
        return
    if shutil.which("python3") is None:
        return
    html = os.environ.get("CLUSTER_HTML") != "0"
    chunk = 400
    for start in range(0, len(md_paths), chunk):
        batch = md_paths[start:start + chunk]
        args = ["python3", str(render), *[str(p) for p in batch], "--title-from", "parent"]
        if html:
            args.append("--html-sibling")
        try:
            # Scale the timeout with batch size — one process renders many files.
            subprocess.run(args, capture_output=True, timeout=15 + len(batch), check=False)
        except (subprocess.SubprocessError, OSError):
            pass


def render_member_report_siblings(clusters: Iterable[dict]) -> None:
    """Render every markdown report referenced by *clusters*.

    Cluster indexes link to ``REPORT.md`` / ``report.md`` / ``description.md``.
    The HTML renderer rewrites those links to ``.html`` for browser use, so
    the member reports need matching HTML siblings in the same pass that emits
    the cluster index. Best-effort, like ``render_md_sibling``.
    """
    seen: set[Path] = set()
    stale: list[Path] = []
    for cluster in clusters:
        for member in cluster.get("_full", []):
            report = member.get("report") if isinstance(member, dict) else None
            if not report:
                continue
            path = Path(report)
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            # Make-style staleness guard: an HTML sibling strictly newer
            # than its markdown is already current. Clustering runs every
            # housekeeping pass, and re-rendering every member every pass
            # was pure subprocess churn. render-md writes the (possibly
            # padded) markdown BEFORE the html, so a fresh render always
            # leaves html strictly newer; any later md edit flips the
            # comparison and re-renders. On 1s-granularity filesystems an
            # equal mtime re-renders — the pre-guard behaviour, never stale.
            html = path.with_suffix(".html")
            try:
                if html.is_file() and html.stat().st_mtime > path.stat().st_mtime:
                    continue
            except OSError:
                pass
            stale.append(path)
    # One batched render-md process for all stale members (was one per member).
    render_md_batch(stale)


def run_under_aggregate_lock(
    target_root: Path,
    lock_name: str,
    tool: str,
    fn: Callable[[], int],
) -> int:
    """Run *fn* while holding an advisory flock on ``target_root/<lock_name>``.

    Two backends auditing the same target both reach a cross-agent
    aggregation from their own maintain-indexes loop. The lock serializes
    them: ``LOCK_NB`` means the loser skips this iteration (return 0)
    instead of stalling its audit loop, and the kernel releases the lock
    when the FD is closed — on a clean exit OR a SIGKILL — so no
    stale-lock cleanup is ever required.

    *tool* is the script name used in diagnostic messages (e.g.
    ``"cluster-crashes"``). Returns *fn*'s exit code, 0 if another
    aggregator holds the lock, or 1 if the lock file cannot be opened.
    """
    import fcntl

    lock_path = target_root / lock_name
    try:
        target_root.mkdir(parents=True, exist_ok=True)
        lock_fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o644)
    except OSError as exc:
        print(f"[{tool}] WARN: cannot open {lock_path}: {exc}", file=sys.stderr)
        return 1
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print(f"[{tool}] another aggregator holds {lock_path}; "
                  f"skipping this iteration", file=sys.stderr)
            return 0
        return fn()
    finally:
        try:
            os.close(lock_fd)
        except OSError:
            pass
