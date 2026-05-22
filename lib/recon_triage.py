#!/usr/bin/env python3
"""recon_triage.py — deterministic glue for the batched recon-validation gate.

bin/audit-recon used to validate every recon hypothesis with its own pair of
independent LLM validators — O(N) cold agent sessions, each re-reading the
same target tree, and no way to deduplicate (each validator saw one claim in
isolation). For a recon pass that emits ~200 hypotheses that is hundreds of
sessions and several hours.

This module owns the deterministic half of the replacement pipeline:

  Stage 1  cluster      — group hypotheses by (file, function, class, line
                          bucket); collapse exact and structural duplicates
                          so one representative stands per real defect.
  Stage 2  parse-batch  — parse the single batched triage pass's JSON verdict
                          out of the model transcript and map it onto reps.
  Stage 3  finalize     — fold the batch verdicts, the per-survivor deep
                          validator results, and duplicate inheritance into
                          one validated hypotheses JSONL.

The LLM calls themselves (Stage 2's batched triage agent, Stage 3's deep
validators) stay in bin/audit-recon — this module is pure data shuffling and
is unit-tested without a backend.

Subcommands:

  cluster --in <hyps.jsonl> --reps <out.jsonl> --clusters <out.json>
          --passthrough <out.jsonl> --validate-mode <all|confirmed>
      Assign every hypothesis a deterministic RECON-<sha16> id, dedup, and
      split into representatives (need triage) and pass-through rows.

  parse-batch --reps <reps.jsonl> --out <verdicts.json>
      Read the batched triage transcript on stdin, extract its JSON verdict,
      and write {fid: {verdict, duplicate_of, rationale}} for every rep.
      Reps the transcript never mentions default to needs-deep-check.

  finalize --reps <reps.jsonl> --passthrough <pass.jsonl>
           --verdicts <verdicts.json> --stage3 <results.tsv> --out <jsonl>
      Resolve duplicate inheritance, merge batch + deep-validator verdicts,
      and emit the final validated hypotheses JSONL with validator_verdict /
      validator_details on every row.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys


# ── shared helpers ────────────────────────────────────────────────────────

def _fid(rec: dict) -> str:
    """Deterministic RECON-<16 hex> id for a hypothesis.

    Keyed on (file, line, function, title-or-notes) so identical hypotheses
    emitted across slices / re-rolls collapse onto the same id — the same
    key bin/audit-recon used for its recon/RECON-* directories.
    """
    file = rec.get("file") or "?"
    line = rec.get("line") or 0
    func = rec.get("function") or ""
    title = rec.get("title") or rec.get("notes") or ""
    digest = hashlib.sha256(f"{file}:{line}:{func}:{title}".encode("utf-8", "replace"))
    return "RECON-" + digest.hexdigest()[:16]


def _cluster_key(rec: dict) -> tuple:
    """Structural dedup key: same defect even when line/title wording drift.

    Two hypotheses in the same function and bug class within ~15 lines of
    each other are treated as one cluster. The line bucket keeps genuinely
    distinct defects in a large function apart.
    """
    file = (rec.get("file") or "").strip()
    func = (rec.get("function") or "").strip()
    klass = (rec.get("class") or "").strip().lower()
    try:
        bucket = int(rec.get("line") or 0) // 15
    except (TypeError, ValueError):
        bucket = 0
    return (file, func, klass, bucket)


def _read_jsonl(path: str) -> list[dict]:
    rows: list[dict] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                if isinstance(obj, dict):
                    rows.append(obj)
    except OSError:
        pass
    return rows


def _extract_triage_json(text: str) -> dict | None:
    """Pull the {"triage": [...]} object out of a model transcript.

    The model is asked for one bare JSON object, but transcripts wrap it in
    prose or fences in practice. Scan for every balanced { } span, parse it,
    and return the first that carries a list-valued "triage" key.
    """
    best: dict | None = None
    for start in range(len(text)):
        if text[start] != "{":
            continue
        depth = 0
        in_str = False
        esc = False
        for end in range(start, len(text)):
            ch = text[end]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    span = text[start:end + 1]
                    try:
                        obj = json.loads(span)
                    except ValueError:
                        break
                    if isinstance(obj, dict) and isinstance(obj.get("triage"), list):
                        # Prefer the largest valid object (the real answer
                        # over a quoted fragment of the instructions).
                        if best is None or len(span) > len(json.dumps(best)):
                            best = obj
                    break
    return best


# ── Stage 1: cluster ──────────────────────────────────────────────────────

def cmd_cluster(args) -> int:
    rows = _read_jsonl(args.in_path)

    passthrough: list[dict] = []
    to_validate: list[dict] = []
    for rec in rows:
        rec["id"] = _fid(rec)
        conf = rec.get("confidence") or "NEEDS-VERIFICATION"
        if conf == "AUDIT-CLEAN":
            passthrough.append(rec)
            continue
        if args.validate_mode == "confirmed" and not str(conf).startswith("CONFIRMED-"):
            # cost-control opt-in: only CONFIRMED-* rows are triaged
            passthrough.append(rec)
            continue
        to_validate.append(rec)

    # Exact dedup by id first (identical hypotheses across slices/re-rolls),
    # then structural clustering. The representative is the member with the
    # most detailed notes — the richest claim for the triage pass to judge.
    by_id: dict[str, dict] = {}
    for rec in to_validate:
        by_id.setdefault(rec["id"], rec)

    clusters: dict[tuple, list[dict]] = {}
    for rec in by_id.values():
        clusters.setdefault(_cluster_key(rec), []).append(rec)

    reps: list[dict] = []
    cluster_map: dict[str, list[str]] = {}
    for members in clusters.values():
        members.sort(key=lambda r: len(r.get("notes") or ""), reverse=True)
        rep = members[0]
        reps.append(rep)
        cluster_map[rep["id"]] = [m["id"] for m in members]

    with open(args.reps, "w", encoding="utf-8") as fh:
        for rec in reps:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    with open(args.passthrough, "w", encoding="utf-8") as fh:
        for rec in passthrough:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
    with open(args.clusters, "w", encoding="utf-8") as fh:
        json.dump({"clusters": cluster_map}, fh, indent=2)

    sys.stdout.write(
        f"{len(to_validate)} {len(reps)} {len(passthrough)}\n"
    )
    return 0


# ── Stage 2: parse-batch ──────────────────────────────────────────────────

_VALID_VERDICTS = {"reject", "needs-deep-check", "likely-real"}


def cmd_parse_batch(args) -> int:
    reps = _read_jsonl(args.reps)
    rep_ids = [r["id"] for r in reps if r.get("id")]

    text = sys.stdin.read()
    parsed = _extract_triage_json(text)

    verdicts: dict[str, dict] = {}
    if parsed:
        for entry in parsed.get("triage", []):
            if not isinstance(entry, dict):
                continue
            fid = entry.get("id")
            if not fid:
                continue
            verdict = str(entry.get("verdict") or "").strip().lower()
            if verdict not in _VALID_VERDICTS:
                verdict = "needs-deep-check"
            dup = entry.get("duplicate_of")
            if not dup or dup in ("null", "None"):
                dup = None
            verdicts[fid] = {
                "verdict": verdict,
                "duplicate_of": dup,
                "rationale": str(entry.get("rationale") or "").strip(),
            }

    # Any rep the batch pass did not return a verdict for (truncated
    # transcript, model skipped it) defaults to needs-deep-check so it still
    # gets a deep validator — never silently dropped.
    defaulted = 0
    for fid in rep_ids:
        if fid not in verdicts:
            verdicts[fid] = {
                "verdict": "needs-deep-check",
                "duplicate_of": None,
                "rationale": "batch triage returned no verdict; defaulted",
            }
            defaulted += 1

    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump({"verdicts": verdicts}, fh, indent=2)

    sys.stdout.write(f"{len(rep_ids)} {defaulted}\n")
    return 0


# ── Stage 3: survivors / finalize ─────────────────────────────────────────

def _resolve_dup(fid: str, verdicts: dict[str, dict]) -> str:
    """Follow duplicate_of links to the canonical rep, with a cycle guard."""
    seen = set()
    cur = fid
    while cur in verdicts:
        if cur in seen:
            break
        seen.add(cur)
        dup = verdicts[cur].get("duplicate_of")
        if not dup or dup == cur or dup not in verdicts:
            break
        cur = dup
    return cur


def cmd_survivors(args) -> int:
    """Print the fid of every rep that needs a Stage-3 deep validator.

    A survivor is a *canonical* rep (not itself a duplicate of another) whose
    batch verdict is needs-deep-check or likely-real. Duplicates inherit
    their canonical rep's deep result, so they are not validated again.

    With --limit, at most N fids are printed, likely-real ahead of
    needs-deep-check so the most promising reps get the deep check first.
    Reps past the limit get no deep result and finalize keeps them as
    Uncertain — still investigated downstream, never dropped. The limit is
    the safety valve that stops a recall-heavy recon from spending the whole
    cell budget in Stage 3.
    """
    try:
        with open(args.verdicts, encoding="utf-8") as fh:
            verdicts = json.load(fh).get("verdicts", {})
    except (OSError, ValueError):
        verdicts = {}

    # likely-real first, then needs-deep-check; fid as a stable tiebreak.
    rank = {"likely-real": 0, "needs-deep-check": 1}
    survivors = [
        (rank[info["verdict"]], fid)
        for fid, info in verdicts.items()
        if info.get("verdict") in rank and _resolve_dup(fid, verdicts) == fid
    ]
    survivors.sort()
    if args.limit and args.limit > 0:
        survivors = survivors[:args.limit]
    for _, fid in survivors:
        sys.stdout.write(fid + "\n")
    return 0


def cmd_finalize(args) -> int:
    reps = _read_jsonl(args.reps)
    passthrough = _read_jsonl(args.passthrough)

    try:
        with open(args.verdicts, encoding="utf-8") as fh:
            verdicts = json.load(fh).get("verdicts", {})
    except (OSError, ValueError):
        verdicts = {}

    # Stage-3 deep-validator results: TSV "fid<TAB>verdict<TAB>details".
    stage3: dict[str, dict] = {}
    try:
        with open(args.stage3, encoding="utf-8") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) >= 2 and parts[0]:
                    stage3[parts[0]] = {
                        "verdict": parts[1],
                        "details": parts[2] if len(parts) > 2 else "",
                    }
    except OSError:
        pass

    promoted = rejected = uncertain = 0
    out_rows: list[dict] = []

    for rec in reps:
        fid = rec.get("id") or ""
        canon = _resolve_dup(fid, verdicts)
        batch = verdicts.get(canon, {})
        batch_verdict = batch.get("verdict", "needs-deep-check")

        if batch_verdict == "reject":
            final = "Reject"
            details = "batch-triage reject: " + (batch.get("rationale") or "")
        elif canon in stage3:
            s3 = stage3[canon]
            final = s3["verdict"] or "Uncertain"
            details = "deep-validator: " + (s3.get("details") or "")
        else:
            # survivor with no deep result (validator skipped or failed):
            # keep it in play for investigation rather than dropping it.
            final = "Uncertain"
            details = "deep verification did not complete"

        if canon != fid:
            details = f"duplicate of {canon}; {details}"

        if final == "Promote":
            promoted += 1
        elif final == "Reject":
            rejected += 1
        else:
            uncertain += 1

        rec = dict(rec)
        rec["validator_verdict"] = final
        rec["validator_details"] = details
        out_rows.append(rec)

    for rec in passthrough:
        out_rows.append(rec)

    with open(args.out, "w", encoding="utf-8") as fh:
        for rec in out_rows:
            fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    sys.stdout.write(f"{promoted} {rejected} {uncertain}\n")
    return 0


# ── argument parsing ──────────────────────────────────────────────────────

def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="recon_triage.py")
    sub = p.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("cluster")
    c.add_argument("--in", dest="in_path", required=True)
    c.add_argument("--reps", required=True)
    c.add_argument("--clusters", required=True)
    c.add_argument("--passthrough", required=True)
    c.add_argument("--validate-mode", dest="validate_mode", default="all",
                   choices=("all", "confirmed"))
    c.set_defaults(func=cmd_cluster)

    b = sub.add_parser("parse-batch")
    b.add_argument("--reps", required=True)
    b.add_argument("--out", required=True)
    b.set_defaults(func=cmd_parse_batch)

    s = sub.add_parser("survivors")
    s.add_argument("--verdicts", required=True)
    s.add_argument("--limit", type=int, default=0,
                   help="cap the number of survivors deep-verified (0 = no cap)")
    s.set_defaults(func=cmd_survivors)

    f = sub.add_parser("finalize")
    f.add_argument("--reps", required=True)
    f.add_argument("--passthrough", required=True)
    f.add_argument("--verdicts", required=True)
    f.add_argument("--stage3", required=True)
    f.add_argument("--out", required=True)
    f.set_defaults(func=cmd_finalize)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
