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
- `receipts.jsonl`: append-only. One row per `bin/state mark-examined` (or
  sweep) call naming the line ranges of a file a session actually read,
  pinned to the file's content hash so a receipt on stale content stops
  counting once the file changes. A claim says a card was handed out; a
  receipt says which lines were looked at.

The unit is a line range because every language has lines. Function names
are a view over that: when the call graph parsed the file, a receipt may name
functions and the ledger resolves them to ranges, and the unexamined
functions of a file can be listed back to the next session.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import callgraph
import strategies
import workqueue


MANIFEST_NAME = "manifest.jsonl"
RECEIPTS_NAME = "receipts.jsonl"
#: Unexamined functions named back to a session; more is a file listing.
UNEXAMINED_SHOWN = 8


class ReceiptError(ValueError):
    """A receipt that names lines or functions the manifest cannot verify."""


def manifest_path(results_dir: Path) -> Path:
    return workqueue.state_dir(Path(results_dir)) / MANIFEST_NAME


def read_manifest(results_dir: Path) -> list[dict]:
    return workqueue.read_jsonl(manifest_path(results_dir))


def receipts_path(results_dir: Path) -> Path:
    return workqueue.state_dir(Path(results_dir)) / RECEIPTS_NAME


def manifest_row(results_dir: Path, file: str) -> dict | None:
    rel = workqueue.normalized_relpath(file)
    for row in read_manifest(results_dir):
        if row.get("file") == rel:
            return row
    return None


def parse_ranges(text: str) -> list[tuple[int, int]]:
    """`10-80,90-120` or `42` (one line) into sorted, merged (start, end)."""
    ranges: list[tuple[int, int]] = []
    for piece in str(text or "").split(","):
        piece = piece.strip()
        if not piece:
            continue
        start, sep, end = piece.partition("-")
        try:
            first = int(start)
            last = int(end) if sep else first
        except ValueError as exc:
            raise ReceiptError(f"line range {piece!r} is not N or N-M") from exc
        if first < 1 or last < first:
            raise ReceiptError(f"line range {piece!r} is empty or starts before line 1")
        ranges.append((first, last))
    return merge_ranges(ranges)


def merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if merged and start <= merged[-1][1] + 1:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def function_ranges(results_dir: Path, file: str, lines: int) -> list[tuple[str, int, int]]:
    """(name, start, end) per parsed definition; a definition runs to the next.

    The parser records where a function starts, not where it ends, and
    languages disagree about what ends one. Running each to the line before
    the next definition (the last to end of file) over-counts only comments
    between functions, and never splits a body across two units.
    """
    definitions = callgraph.definitions_for(results_dir, file)
    out: list[tuple[str, int, int]] = []
    for index, (name, start) in enumerate(definitions):
        if start > lines:
            break
        end = definitions[index + 1][1] - 1 if index + 1 < len(definitions) else lines
        out.append((name, start, max(start, min(end, lines))))
    return out


def record_receipt(
    ctx: workqueue.Context,
    agent: str,
    file: str,
    *,
    lines: str = "",
    functions: str = "",
    card_id: str = "",
    source: str = "agent",
    note: str = "",
) -> dict:
    """Append a verified receipt: the file is in the manifest, every range is
    inside it, and every function named was parsed there. A receipt that
    cannot be checked is refused rather than recorded as coverage."""
    row = manifest_row(ctx.results_dir, file)
    rel = workqueue.normalized_relpath(file)
    if row is None:
        raise ReceiptError(f"{rel or file!r} is not in the manifest; run bin/rank-work or check the path")
    total = int(row.get("lines") or 0)
    ranges = parse_ranges(lines)
    names = [name.strip() for name in str(functions or "").split(",") if name.strip()]
    if names:
        known = {name: (start, end) for name, start, end in function_ranges(ctx.results_dir, rel, total)}
        missing = [name for name in names if name not in known]
        if missing:
            hint = (
                "the call graph parsed no definitions for this file; use --lines"
                if not known else f"parsed functions are: {', '.join(sorted(known))}"
            )
            raise ReceiptError(f"unknown function(s) {', '.join(missing)} in {rel}; {hint}")
        ranges = merge_ranges(ranges + [known[name] for name in names])
    if not ranges:
        raise ReceiptError("a receipt needs --lines or --functions")
    if ranges[-1][1] > total:
        raise ReceiptError(f"{rel} has {total} lines; range ends at {ranges[-1][1]}")
    receipt = {
        "file": rel,
        "ranges": [[start, end] for start, end in ranges],
        "functions": names,
        "sha1": row.get("sha1", ""),
        "agent": str(agent),
        "card_id": card_id or "",
        "source": source,
        "note": note,
        "at": workqueue.now_iso(),
    }
    workqueue.append_jsonl(receipts_path(ctx.results_dir), receipt)
    return receipt


def examined_ranges_by_file(results_dir: Path) -> dict[str, list[tuple[int, int]]]:
    """Merged receipted ranges per file, counting only receipts on the
    manifest's current content hash."""
    current = {row.get("file"): row.get("sha1") for row in read_manifest(results_dir)}
    collected: dict[str, list[tuple[int, int]]] = {}
    for receipt in workqueue.read_jsonl(receipts_path(results_dir)):
        rel = str(receipt.get("file") or "")
        if not rel or receipt.get("sha1") != current.get(rel):
            continue
        for pair in receipt.get("ranges") or []:
            if isinstance(pair, list) and len(pair) == 2:
                collected.setdefault(rel, []).append((int(pair[0]), int(pair[1])))
    return {rel: merge_ranges(ranges) for rel, ranges in collected.items()}


def examined_lines(ranges: list[tuple[int, int]]) -> int:
    return sum(end - start + 1 for start, end in ranges)


def examined_fraction_by_file(results_dir: Path) -> dict[str, float]:
    """Share of each manifest file's lines under a current receipt; files
    with no receipt are absent, which reads as zero."""
    by_file = examined_ranges_by_file(results_dir)
    out: dict[str, float] = {}
    for row in read_manifest(results_dir):
        rel = str(row.get("file") or "")
        total = int(row.get("lines") or 0)
        ranges = by_file.get(rel)
        if ranges and total:
            out[rel] = min(1.0, examined_lines(ranges) / total)
    return out


def file_examined(results_dir: Path, file: str) -> dict:
    """What the ledger knows about one file: receipted ranges, the share of
    lines they cover, and the parsed functions no receipt reaches."""
    rel = workqueue.normalized_relpath(file)
    row = manifest_row(results_dir, rel)
    total = int((row or {}).get("lines") or 0)
    ranges = examined_ranges_by_file(results_dir).get(rel, [])
    covered = examined_lines(ranges)
    unexamined = [
        (name, start, end)
        for name, start, end in function_ranges(results_dir, rel, total)
        if not any(rs <= start and end <= re for rs, re in ranges)
    ]
    return {
        "file": rel,
        "in_manifest": row is not None,
        "lines": total,
        "examined_lines": covered,
        "fraction": (covered / total) if total else 0.0,
        "ranges": ranges,
        "unexamined_functions": unexamined,
    }


def examined_markdown(results_dir: Path, file: str) -> list[str]:
    """Card and resume block: what was already read here, and what was not.

    Rendered on every pickup so a session after compaction, or a different
    agent on the same broad card, starts from the unexamined functions
    instead of re-reading the file from the top.
    """
    info = file_examined(results_dir, file)
    if not info["in_manifest"]:
        return []
    shown = ", ".join(f"{s}-{e}" for s, e in info["ranges"][:12])
    if len(info["ranges"]) > 12:
        shown += ", ..."
    lines = [
        f"- **Examined so far:** {info['fraction'] * 100:.0f}% of {info['lines']} lines"
        + (f" (lines {shown})" if shown else " (no receipt yet)"),
    ]
    pending = info["unexamined_functions"]
    if pending:
        named = ", ".join(f"`{name}` (l.{start})" for name, start, _ in pending[:UNEXAMINED_SHOWN])
        extra = f", +{len(pending) - UNEXAMINED_SHOWN} more" if len(pending) > UNEXAMINED_SHOWN else ""
        lines.append(f"- **Unexamined functions:** {named}{extra}")
    lines.append(
        "  Record what you read with `bin/state mark-examined --agent N --file "
        f"{info['file']} --lines A-B` (or `--functions a,b`); the next session "
        "on this file starts from what is left."
    )
    return lines


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
    window, `claimed` what a session picked up, and `receipted` what a session
    recorded reading (with `lines_examined` under those receipts). A file can
    be claimed without being offered only through a non-ranked card (a patch
    card), so the buckets are counted independently rather than nested.
    """
    manifest = read_manifest(ctx.results_dir)
    claimed = claimed_files(ctx, manifest)
    receipted = examined_ranges_by_file(ctx.results_dir)
    empty = {"files": 0, "offered": 0, "claimed": 0, "receipted": 0, "lines": 0, "lines_examined": 0}
    buckets: dict[str, dict] = {}
    totals = dict(empty)
    never: list[dict] = []
    for row in manifest:
        rel = str(row.get("file") or "")
        bucket = buckets.setdefault(
            workqueue.subsystem_bucket(rel, max(1, depth)), dict(empty),
        )
        lines = int(row.get("lines") or 0)
        offered = bool(row.get("offered"))
        is_claimed = rel in claimed
        examined = min(lines, examined_lines(receipted.get(rel, [])))
        for target in (bucket, totals):
            target["files"] += 1
            target["lines"] += lines
            target["lines_examined"] += examined
            target["offered"] += int(offered)
            target["claimed"] += int(is_claimed)
            target["receipted"] += int(examined > 0)
        if not offered and not is_claimed and not examined:
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
                key=lambda item: (
                    item[1]["lines_examined"] / item[1]["lines"] if item[1]["lines"] else 0.0,
                    item[1]["offered"] + item[1]["claimed"],
                    item[0],
                ),
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
        f"- With an examined receipt: {totals['receipted']} files, "
        f"{totals['lines_examined']} lines ({_pct(totals['lines_examined'], totals['lines'])})",
        f"- Never offered, claimed, nor receipted: {report['never_offered']}",
        "",
        "| Directory | Files | Offered | Claimed | Receipted | Lines | Examined |",
        "|---|--:|--:|--:|--:|--:|--:|",
    ]
    for row in report["directories"]:
        lines.append(
            f"| `{row['directory']}` | {row['files']} | {row['offered']} | "
            f"{row['claimed']} | {row['receipted']} | {row['lines']} | "
            f"{_pct(row['lines_examined'], row['lines'])} |"
        )
    if report["untouched"]:
        lines.extend(["", "Largest untouched files:", ""])
        lines.extend(
            f"- `{item['file']}` ({item['lines']} lines)" for item in report["untouched"]
        )
    if not report["totals"]["files"]:
        lines.extend(["", "No manifest yet: run `bin/rank-work` or start an audit."])
    return "\n".join(lines) + "\n"

