"""cluster_common.py — shared helpers for bin/cluster-crashes + bin/cluster-findings.

Both clustering tools emit a `*-CLUSTERS.md` report, render an HTML
sibling next to it, sweep away renamed legacy report files, and — when
asked to aggregate a whole target root — serialize concurrent backends
behind an advisory file lock. That scaffolding is identical between the
two tools; only the signatures, file names, and stack-frame logic differ.
Keeping the scaffolding here means a fix (e.g. to the render timeout or
the lock semantics) lands in one place instead of drifting between two
near-identical copies.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Callable, Iterable


def exact_child_file(parent: Path, names: Iterable[str]) -> Path | None:
    """Return an exact-case file child, even on case-insensitive filesystems."""
    try:
        children = {child.name: child for child in parent.iterdir()}
    except OSError:
        return None
    for name in names:
        child = children.get(name)
        if child is not None and child.is_file():
            return child
    return None


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


def render_member_report_siblings(clusters: Iterable[dict]) -> None:
    """Render every markdown report referenced by *clusters*.

    Cluster indexes link to ``REPORT.md`` / ``report.md`` / ``description.md``.
    The HTML renderer rewrites those links to ``.html`` for browser use, so
    the member reports need matching HTML siblings in the same pass that emits
    the cluster index. Best-effort, like ``render_md_sibling``.
    """
    seen: set[Path] = set()
    for cluster in clusters:
        for member in cluster.get("_full", []):
            report = member.get("report") if isinstance(member, dict) else None
            if not report:
                continue
            path = Path(report)
            if path in seen or not path.is_file():
                continue
            seen.add(path)
            render_md_sibling(path, title=path.parent.name)


def remove_legacy_cluster_files(paths: Iterable[Path]) -> None:
    """Delete renamed-away cluster report files (and their .html siblings).

    A clustering tool that once wrote ``CLUSTERS.md`` and now writes
    ``CRASH-CLUSTERS.md`` calls this with the old name so a stale report
    does not linger beside the current one.
    """
    for path in paths:
        for candidate in (path, path.with_suffix(".html")):
            try:
                candidate.unlink()
            except OSError:
                pass


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
