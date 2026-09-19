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
  sweep) call attesting the line ranges of a file a session read,
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


def function_ranges(
    results_dir: Path,
    file: str,
    lines: int,
    graph: dict | None = None,
) -> list[tuple[str, int, int]]:
    """(name, start, end) per parsed definition; a definition runs to the next.

    The parser records where a function starts, not where it ends, and
    languages disagree about what ends one. Running each to the line before
    the next definition (the last to end of file) over-counts only comments
    between functions, and never splits a body across two units.
    """
    definitions = callgraph.definitions_for(results_dir, file, graph)
    out: list[tuple[str, int, int]] = []
    for index, (name, start) in enumerate(definitions):
        if start > lines:
            break
        end = definitions[index + 1][1] - 1 if index + 1 < len(definitions) else lines
        out.append((name, start, max(start, min(end, lines))))
    return out


def content_matches_manifest(target_root: Path, rel: str, row: dict) -> bool:
    """Whether the source on disk is the content the manifest row describes.

    The stat triple is the fast path so recording many sweep units does not
    reread a large file after every call. A mismatch is not a verdict: a
    checkout, a build step, or a touch changes times without changing
    content, and a rerank happens only when tracked content changes, so a
    stale stat would otherwise refuse every receipt on the file until the
    next source revision. The hash decides.
    """
    path = Path(target_root) / rel
    try:
        info = path.stat()
        fields = (
            ("bytes", info.st_size),
            ("mtime_ns", info.st_mtime_ns),
            ("ctime_ns", info.st_ctime_ns),
        )
        if all(row.get(key) is not None for key, _ in fields) and all(
            int(row[key]) == current for key, current in fields
        ):
            return True
        return file_identity(path)[1] == str(row.get("sha1") or "")
    except (OSError, TypeError, ValueError):
        return False


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
    expected_sha1: str = "",
) -> dict:
    """Append a verified receipt: the file is in the manifest, every range is
    inside it, and every function named was parsed there. A receipt that
    cannot be checked is refused rather than recorded as coverage.
    `expected_sha1` is the content the reader actually saw; a manifest
    rewritten to newer content in between refuses the receipt."""
    rel = workqueue.normalized_relpath(file)
    row = manifest_row(ctx.results_dir, rel)
    if row is None:
        raise ReceiptError(f"{rel or file!r} is not in the manifest; run bin/rank-work or check the path")
    if expected_sha1 and row.get("sha1") != expected_sha1:
        raise ReceiptError(f"{rel} changed after the reviewed content was loaded")
    if not content_matches_manifest(ctx.target_root, rel, row):
        raise ReceiptError(f"{rel} changed since the coverage manifest was written")
    total = int(row.get("lines") or 0)
    ranges = parse_ranges(lines)
    names = [name.strip() for name in str(functions or "").split(",") if name.strip()]
    if names:
        known: dict[str, list[tuple[int, int]]] = {}
        for name, start, end in function_ranges(ctx.results_dir, rel, total):
            known.setdefault(name, []).append((start, end))
        missing = [name for name in names if name not in known]
        if missing:
            hint = (
                "the call graph parsed no definitions for this file; use --lines"
                if not known else f"parsed functions are: {', '.join(sorted(known))}"
            )
            raise ReceiptError(f"unknown function(s) {', '.join(missing)} in {rel}; {hint}")
        ambiguous = [name for name in names if len(known[name]) > 1]
        if ambiguous:
            raise ReceiptError(
                f"ambiguous function(s) {', '.join(ambiguous)} in {rel}; use --lines"
            )
        ranges = merge_ranges(ranges + [known[name][0] for name in names])
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


def _receipt_ranges_by_file(
    results_dir: Path, *, agent_attested_only: bool = False,
) -> dict[str, list[tuple[int, int]]]:
    """Merged current receipt ranges, optionally limited to agent claims.

    Sweep source reaches the model through the harness-built decision prompt,
    so it is verified examined coverage but has no transcript read event. The
    source filter keeps that coverage while letting the report cross-check only
    the receipts an agent claims for its own source reads. Missing ``source``
    is the legacy form of an agent receipt.
    """
    current = {row.get("file"): row.get("sha1") for row in read_manifest(results_dir)}
    collected: dict[str, list[tuple[int, int]]] = {}
    for receipt in workqueue.read_jsonl(receipts_path(results_dir)):
        if agent_attested_only and str(receipt.get("source") or "agent") != "agent":
            continue
        rel = str(receipt.get("file") or "")
        if not rel or receipt.get("sha1") != current.get(rel):
            continue
        for pair in receipt.get("ranges") or []:
            if isinstance(pair, list) and len(pair) == 2:
                collected.setdefault(rel, []).append((int(pair[0]), int(pair[1])))
    return {rel: merge_ranges(ranges) for rel, ranges in collected.items()}


def examined_ranges_by_file(results_dir: Path) -> dict[str, list[tuple[int, int]]]:
    """Merged receipted ranges per file, counting only receipts on the
    manifest's current content hash."""
    return _receipt_ranges_by_file(results_dir)


def agent_attested_ranges_by_file(results_dir: Path) -> dict[str, list[tuple[int, int]]]:
    """Current ranges that an agent attested reading itself."""
    return _receipt_ranges_by_file(results_dir, agent_attested_only=True)


def examined_lines(ranges: list[tuple[int, int]]) -> int:
    return sum(end - start + 1 for start, end in ranges)


def intersect_ranges(
    left: list[tuple[int, int]], right: list[tuple[int, int]],
) -> list[tuple[int, int]]:
    """Lines present in both merged range lists."""
    out: list[tuple[int, int]] = []
    for a_start, a_end in left:
        for b_start, b_end in right:
            start, end = max(a_start, b_start), min(a_end, b_end)
            if start <= end:
                out.append((start, end))
    return merge_ranges(out)


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


def caller_sets(
    results_dir: Path, target_root: Path, graph: dict | None = None,
) -> dict[str, list[str]]:
    """Second-pass eligibility: files whose every parsed function carries a
    current receipt, mapped to their resolved caller files (most calls
    first). Empty without a call graph."""
    data = graph if graph is not None else callgraph.load(results_dir)
    if data is None or data.get("skipped"):
        return {}
    receipted = examined_ranges_by_file(results_dir)
    out: dict[str, list[str]] = {}
    for row in read_manifest(results_dir):
        rel = str(row.get("file") or "")
        ranges = receipted.get(rel)
        if not ranges or not content_matches_manifest(target_root, rel, row):
            continue
        definitions = function_ranges(results_dir, rel, int(row.get("lines") or 0), data)
        if not definitions or any(
            not any(rs <= start and end <= re for rs, re in ranges)
            for _name, start, end in definitions
        ):
            continue
        callers = callgraph.caller_files(results_dir, rel, data)
        if callers:
            out[rel] = callers
    return out


def call_edge_scope(ctx: workqueue.Context) -> dict:
    """What the bounded second pass has reached.

    One card per eligible caller set, keyed to content, so a set that was
    sampled and concluded leaves no card in the queue. Counting only the
    queue would report a reviewed contract as never carded; the claim ledger
    is what says a set was sampled. Callers beyond each set's seed never get
    their own card, and that count is the sampling boundary.
    """
    graph = callgraph.load(ctx.results_dir)
    empty = {
        "available": False, "eligible_caller_sets": 0, "resolved_callers": 0,
        "sampled_sets": 0, "concluded_sets": 0, "current_sample_cards": 0,
        "callers_without_individual_card": 0,
    }
    if graph is None or graph.get("skipped"):
        return empty
    sets = caller_sets(ctx.results_dir, ctx.target_root, graph)
    manifest_by_file = {str(row.get("file") or ""): row for row in read_manifest(ctx.results_dir)}
    latest = workqueue.latest_claims_by_card(ctx)
    sampled = concluded = 0
    for rel, callers in sets.items():
        card_id, _ = workqueue.edge_card_id(ctx, rel, callers, manifest_by_file)
        claim = latest.get(card_id)
        if claim:
            sampled += 1
            concluded += str(claim.get("status") or "") in workqueue.TERMINAL_CARD_STATUSES
    current_cards = len({
        str(card.get("id") or "")
        for card in workqueue.read_jsonl(workqueue.work_cards_path(ctx))
        if card.get("kind") == "call-edge" and card.get("id")
    })
    return {
        **empty,
        "available": True,
        "eligible_caller_sets": len(sets),
        "resolved_callers": sum(len(callers) for callers in sets.values()),
        "sampled_sets": sampled,
        "concluded_sets": concluded,
        "current_sample_cards": current_cards,
        "callers_without_individual_card": sum(len(callers) - 1 for callers in sets.values()),
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

    Size, mtime, and ctime gate the hash so a rerank on a large tree does not
    re-read every file. The ctime prevents a same-size edit with a restored
    mtime from retaining stale coverage. `offered` is carried forward because
    a file that left the window was still handed to the run.
    """
    path = manifest_path(ctx.results_dir)
    with workqueue.jsonl_lock(path):
        previous = {row.get("file", ""): row for row in read_manifest(ctx.results_dir)}
        rows = _manifest_rows(ctx, source_paths, offered_files, scope, previous)
        rows.sort(key=lambda row: row["file"])
        workqueue._write_jsonl_unlocked(path, rows)
    return rows


def _manifest_rows(
    ctx: workqueue.Context, source_paths: list[tuple[Path, str]],
    offered_files: set[str], scope: str, previous: dict[str, dict],
) -> list[dict]:
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
            and old.get("ctime_ns") == info.st_ctime_ns
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
            "ctime_ns": info.st_ctime_ns,
            "sha1": sha1,
            "subsystem": workqueue.subsystem_for(rel),
            "card_id": workqueue.ranked_card_id(ctx.target_slug, rel),
            "offered": bool(rel in offered_files or (old or {}).get("offered")),
            "scope": scope,
        })
    return rows


def claimed_files(ctx: workqueue.Context, manifest: list[dict]) -> set[str]:
    """Files any session ever claimed a card on, by deterministic card id."""
    claim_rows = workqueue.read_jsonl(
        workqueue.state_dir(ctx.results_dir) / "claims.jsonl",
    )
    claimed_ids = {
        str(row.get("card_id") or "")
        for row in claim_rows
    }
    out = {
        workqueue.normalized_relpath(row.get("file", ""))
        for row in claim_rows
        if workqueue.normalized_relpath(row.get("file", ""))
    }
    claimed_ids.discard("")
    if not claimed_ids:
        return out
    # Cards that carry a file the manifest may not list (patch cards on a
    # generated file, older queues) resolve through the current queue too.
    by_card_file: dict[str, str] = {}
    for card in workqueue.read_jsonl(workqueue.work_cards_path(ctx)):
        rel = workqueue.normalized_relpath(card.get("file", ""))
        if rel and card.get("id"):
            by_card_file[str(card["id"])] = rel
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
    window, `claimed` what a session picked up, `read_requested` what a
    transcript shows a session requesting (`lines_requested`), and
    `receipted` what an agent or the budgeted sweep verifiably examined
    (`lines_examined`). A file can be claimed without being offered only
    through a non-ranked card (a patch card), and a read can be requested
    without either through discovery, so the buckets are counted independently
    rather than nested.

    `lines_attested_unrequested` is the cross-check between the two agent
    ledgers: agent-attested lines no transcript read reached. Sweep receipts
    remain examined coverage, but are excluded because the harness placed
    that source directly in a tool-less decision prompt. The read parser
    misses idioms it does not know, so the number is evidence to inspect, not
    proof of a false receipt.
    """
    import read_ledger  # lazy: it imports this module

    manifest = read_manifest(ctx.results_dir)
    claimed = claimed_files(ctx, manifest)
    receipted = examined_ranges_by_file(ctx.results_dir)
    agent_attested = agent_attested_ranges_by_file(ctx.results_dir)
    requested = read_ledger.requested_ranges_by_file(ctx.results_dir)
    empty = {
        "files": 0, "offered": 0, "claimed": 0, "read_requested": 0, "receipted": 0,
        "lines": 0, "lines_requested": 0, "lines_examined": 0,
        "lines_agent_attested": 0,
        "lines_attested_unrequested": 0,
    }
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
        agent_examined = min(lines, examined_lines(agent_attested.get(rel, [])))
        seen = min(lines, examined_lines(requested.get(rel, [])))
        corroborated = examined_lines(
            intersect_ranges(agent_attested.get(rel, []), requested.get(rel, []))
        )
        for target in (bucket, totals):
            target["files"] += 1
            target["lines"] += lines
            target["lines_requested"] += seen
            target["lines_examined"] += examined
            target["lines_agent_attested"] += agent_examined
            target["lines_attested_unrequested"] += max(0, agent_examined - corroborated)
            target["offered"] += int(offered)
            target["claimed"] += int(is_claimed)
            target["read_requested"] += int(seen > 0)
            target["receipted"] += int(examined > 0)
        if not offered and not is_claimed and not examined:
            never.append({"file": rel, "lines": lines})
    never.sort(key=lambda item: (-item["lines"], item["file"]))
    import sweep  # lazy: it imports this module

    return {
        "scope": "delta" if manifest and all(row.get("scope") == "delta" for row in manifest) else ("tree" if manifest else ""),
        "sweep": sweep.summary_lines(ctx.results_dir),
        "call_edges": call_edge_scope(ctx),
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
    edges = report.get("call_edges") or {}
    lines = [
        "# Review coverage",
        "",
        f"- Scope: `{report.get('scope') or 'tree'}`",
        f"- Files enumerated: {totals['files']} ({totals['lines']} lines)",
        f"- Ever offered in the ranked window: {totals['offered']} ({_pct(totals['offered'], totals['files'])})",
        f"- Ever claimed by a session: {totals['claimed']} ({_pct(totals['claimed'], totals['files'])})",
        f"- Read scope requested per transcripts: {totals['read_requested']} files, "
        f"{totals['lines_requested']} lines ({_pct(totals['lines_requested'], totals['lines'])})",
        f"- With a verified examined receipt: {totals['receipted']} files, "
        f"{totals['lines_examined']} lines ({_pct(totals['lines_examined'], totals['lines'])})",
        f"- Never offered, claimed, nor receipted: {report['never_offered']}",
        *(
            [
                f"- Agent-attested lines no transcript read requested: "
                f"{totals['lines_attested_unrequested']} "
                f"({_pct(totals['lines_attested_unrequested'], totals['lines_agent_attested'])} "
                f"of agent-attested)"
            ]
            if totals["lines_agent_attested"] else []
        ),
        *report.get("sweep", []),
        "",
        "| Directory | Files | Offered | Claimed | Read requested | Receipted | Lines | Requested % | Examined % |",
        "|---|--:|--:|--:|--:|--:|--:|--:|--:|",
    ]
    if edges.get("available") and edges.get("eligible_caller_sets"):
        lines.insert(len(lines) - 3, (
            f"- Cross-file second pass: {edges['eligible_caller_sets']} eligible caller set(s) "
            f"across {edges['resolved_callers']} resolved caller file(s); "
            f"{edges['sampled_sets']} sampled ({edges['concluded_sets']} concluded), "
            f"{edges['current_sample_cards']} card(s) in the current queue; "
            f"{edges['callers_without_individual_card']} caller(s) beyond the seeds have no individual card"
        ))
    for row in report["directories"]:
        lines.append(
            f"| `{row['directory']}` | {row['files']} | {row['offered']} | "
            f"{row['claimed']} | {row['read_requested']} | {row['receipted']} | {row['lines']} | "
            f"{_pct(row['lines_requested'], row['lines'])} | "
            f"{_pct(row['lines_examined'], row['lines'])} |"
        )
    if report["untouched"]:
        lines.extend(["", "Largest files never offered, claimed, or receipted:", ""])
        lines.extend(
            f"- `{item['file']}` ({item['lines']} lines)" for item in report["untouched"]
        )
    if not report["totals"]["files"]:
        lines.extend(["", "No manifest yet: run `bin/rank-work` or start an audit."])
    return "\n".join(lines) + "\n"
