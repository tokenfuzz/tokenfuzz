#!/usr/bin/env python3
"""Review coverage: which auditable source a run was handed and touched.

The ranked queue is a bounded window over the tree, so "what was never
looked at" cannot be read from `work-cards.jsonl`: a file outside the window
has no card, and a card rewritten out of the window leaves no trace. The
manifest written here lists every auditable file the ranker enumerated, and
the report joins it to the claim ledger so an operator can see the untouched
share directly instead of inferring it from a clean result.

Ledger files under `state/`:

- `manifest.jsonl`: one row per auditable file with its size, line count,
  content hash, subsystem, primary card id, and whether it ever entered the
  ranked window. Rewritten atomically on every ranking pass; `offered` is
  sticky across rewrites because the window moves.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import strategies
import workqueue


MANIFEST_NAME = "manifest.jsonl"


def manifest_path(results_dir: Path) -> Path:
    return workqueue.state_dir(Path(results_dir)) / MANIFEST_NAME


def read_manifest(results_dir: Path) -> list[dict]:
    return workqueue.read_jsonl(manifest_path(results_dir))


def file_identity(path: Path) -> tuple[int, str]:
    """(line count, sha1) of a file's bytes; a trailing partial line counts."""
    digest = hashlib.sha1()
    lines = 0
    last = b"\n"
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(1 << 20)
            if not chunk:
                break
            digest.update(chunk)
            lines += chunk.count(b"\n")
            last = chunk[-1:]
    if last != b"\n":
        lines += 1
    return lines, digest.hexdigest()


def card_ids_for_file(target_slug: str, rel: str) -> set[str]:
    """Every card id the ranker can mint for one file.

    Ids are deterministic (`workqueue.ranked_card_id`), so claims on cards
    the current queue no longer lists still resolve to their file.
    """
    ids = {workqueue.ranked_card_id(target_slug, rel)}
    for strategy in strategies.ACTIVE:
        ids.add(workqueue.ranked_card_id(target_slug, rel, strategy))
    return ids


def write_manifest(
    ctx: workqueue.Context,
    source_paths: list[tuple[Path, str]],
    offered_files: set[str],
    scope: str = "tree",
) -> list[dict]:
    """Rewrite the manifest for this ranking pass.

    Size and mtime gate the hash so a rerank on a large tree does not re-read
    every file; `offered` is carried forward because a file that left the
    window was still handed to the run.
    """
    previous = {row.get("file", ""): row for row in read_manifest(ctx.results_dir)}
    rows: list[dict] = []
    for path, rel in source_paths:
        try:
            info = path.stat()
        except OSError:
            continue
        old = previous.get(rel)
        if (
            old is not None
            and old.get("bytes") == info.st_size
            and old.get("mtime_ns") == info.st_mtime_ns
            and old.get("sha1")
        ):
            lines, sha1 = int(old.get("lines") or 0), str(old["sha1"])
        else:
            try:
                lines, sha1 = file_identity(path)
            except OSError:
                continue
        rows.append({
            "file": rel,
            "lines": lines,
            "bytes": info.st_size,
            "mtime_ns": info.st_mtime_ns,
            "sha1": sha1,
            "subsystem": workqueue.subsystem_for(rel),
            "card_id": workqueue.ranked_card_id(ctx.target_slug, rel),
            "offered": bool(rel in offered_files or (old or {}).get("offered")),
            "scope": scope,
        })
    rows.sort(key=lambda row: row["file"])
    path = manifest_path(ctx.results_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    workqueue.write_jsonl(path, rows)
    return rows


def claimed_files(ctx: workqueue.Context, manifest: list[dict]) -> set[str]:
    """Files any session ever claimed a card on, by deterministic card id."""
    claimed_ids = {
        str(row.get("card_id") or "")
        for row in workqueue.read_jsonl(
            workqueue.state_dir(ctx.results_dir) / "claims.jsonl",
        )
    }
    claimed_ids.discard("")
    if not claimed_ids:
        return set()
    # Cards that carry a file the manifest may not list (patch cards on a
    # generated file, older queues) resolve through the current queue too.
    by_card_file: dict[str, str] = {}
    for card in workqueue.read_jsonl(workqueue.work_cards_path(ctx)):
        rel = workqueue.normalized_relpath(card.get("file", ""))
        if rel and card.get("id"):
            by_card_file[str(card["id"])] = rel
    out: set[str] = set()
    for row in manifest:
        rel = str(row.get("file") or "")
        if claimed_ids & card_ids_for_file(ctx.target_slug, rel):
            out.add(rel)
    for cid in claimed_ids:
        rel = by_card_file.get(cid)
        if rel:
            out.add(rel)
    return out


def coverage_report(ctx: workqueue.Context, depth: int = 2, untouched: int = 10) -> dict:
    """Per-directory buckets of the manifest joined to claims.

    `files` is what the ranker enumerated, `offered` what ever entered the
    window, `claimed` what a session picked up. A file can be claimed without
    being offered only through a non-ranked card (a patch card), so the two
    are counted independently rather than nested.
    """
    manifest = read_manifest(ctx.results_dir)
    claimed = claimed_files(ctx, manifest)
    buckets: dict[str, dict] = {}
    totals = {"files": 0, "offered": 0, "claimed": 0, "lines": 0}
    never: list[dict] = []
    for row in manifest:
        rel = str(row.get("file") or "")
        bucket = buckets.setdefault(
            workqueue.subsystem_bucket(rel, max(1, depth)),
            {"files": 0, "offered": 0, "claimed": 0, "lines": 0},
        )
        lines = int(row.get("lines") or 0)
        offered = bool(row.get("offered"))
        is_claimed = rel in claimed
        for target in (bucket, totals):
            target["files"] += 1
            target["lines"] += lines
            target["offered"] += int(offered)
            target["claimed"] += int(is_claimed)
        if not offered and not is_claimed:
            never.append({"file": rel, "lines": lines})
    never.sort(key=lambda item: (-item["lines"], item["file"]))
    return {
        "scope": (manifest[0].get("scope") if manifest else "") or "",
        "depth": depth,
        "totals": totals,
        "never_offered": len(never),
        "untouched": never[: max(0, untouched)],
        "directories": [
            {"directory": name, **stats}
            for name, stats in sorted(
                buckets.items(),
                key=lambda item: (item[1]["offered"] + item[1]["claimed"], item[0]),
            )
        ],
    }


def _pct(part: int, whole: int) -> str:
    return f"{part * 100.0 / whole:.0f}%" if whole else "-"


def render_coverage(report: dict, fmt: str = "md") -> str:
    if fmt == "json":
        return json.dumps(report, sort_keys=True) + "\n"
    totals = report["totals"]
    lines = [
        "# Review coverage",
        "",
        f"- Scope: `{report.get('scope') or 'tree'}`",
        f"- Files enumerated: {totals['files']} ({totals['lines']} lines)",
        f"- Ever offered in the ranked window: {totals['offered']} ({_pct(totals['offered'], totals['files'])})",
        f"- Ever claimed by a session: {totals['claimed']} ({_pct(totals['claimed'], totals['files'])})",
        f"- Never offered nor claimed: {report['never_offered']}",
        "",
        "| Directory | Files | Offered | Claimed | Lines |",
        "|---|--:|--:|--:|--:|",
    ]
    for row in report["directories"]:
        lines.append(
            f"| `{row['directory']}` | {row['files']} | {row['offered']} | "
            f"{row['claimed']} | {row['lines']} |"
        )
    if report["untouched"]:
        lines.extend(["", "Largest untouched files:", ""])
        lines.extend(
            f"- `{item['file']}` ({item['lines']} lines)" for item in report["untouched"]
        )
    if not report["totals"]["files"]:
        lines.extend(["", "No manifest yet: run `bin/rank-work` or start an audit."])
    return "\n".join(lines) + "\n"

