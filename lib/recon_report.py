#!/usr/bin/env python3
"""recon_report.py — render a human-readable REPORT.md for recon candidates.

Recon (the breadth-first survey) emits one RECON-<sha> directory per
candidate hypothesis, each holding a machine-readable ``finding.json``
plus ``validator-vote-*.json`` files from the independent reviewers.
That is enough for the harness but not for a developer who wants to
eyeball a raw claim and decide whether it deserves a re-check.

This helper turns each RECON-* directory into a ``REPORT.md`` (and, when
``bin/render-md`` is available, a sibling ``REPORT.html``) so recon
output is inspectable the same way ``crashes/`` and ``findings/`` are.
The JSON files are left untouched — REPORT.md is purely additive.

A recon candidate is an UNVERIFIED hypothesis, not a confirmed bug; the
report says so prominently so nobody mistakes it for a finding.

Usage:
  python3 lib/recon_report.py <recon-dir>      # one RECON-* directory
  python3 lib/recon_report.py <recon-root>     # a results/recon/ directory
  python3 lib/recon_report.py <results-dir>    # any dir containing recon/
  python3 lib/recon_report.py <path> --no-html # skip the HTML sibling

Exit status: 0 on success (including "nothing to render"), 1 on a bad
path argument.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# ── source-location helpers ──────────────────────────────────────────────

# Absolute recon file paths point inside the audited tree
# (.../targets/<slug>/lib/escape.c). Show the path relative to that
# checkout root so reports stay readable and machine-independent.
_TARGETS_PREFIX_RE = re.compile(r"^.*/targets/[^/]+/")


def _rel_source(path: str) -> str:
    """Best-effort target-relative form of a recon source path."""
    if not path:
        return "?"
    stripped = _TARGETS_PREFIX_RE.sub("", path)
    return stripped or path


def _location(rec: dict) -> str:
    """`file:line in function` rendered from a finding.json record."""
    f = _rel_source(str(rec.get("file") or "?"))
    line = rec.get("line") or 0
    func = rec.get("function") or "?"
    return f"`{f}:{line}` in `{func}`"


# ── REPORT.md rendering ──────────────────────────────────────────────────


def _md_escape_cell(text: str) -> str:
    """Make a string safe to drop inside a GFM table cell."""
    return str(text).replace("|", "\\|").replace("\n", " ").strip()


def _vote_files(recon_dir: Path) -> list[Path]:
    """validator-vote-*.json sorted by their numeric suffix."""

    def _n(p: Path) -> int:
        m = re.search(r"validator-vote-(\d+)\.json$", p.name)
        return int(m.group(1)) if m else 0

    return sorted(recon_dir.glob("validator-vote-*.json"), key=_n)


def render_report_md(recon_dir: Path) -> str:
    """Build the REPORT.md text for a single RECON-* directory."""
    finding_path = recon_dir / "finding.json"
    try:
        rec = json.loads(finding_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError(f"unreadable finding.json in {recon_dir}: {exc}") from exc

    rec_id = rec.get("id") or recon_dir.name
    title = rec.get("title") or "(no title)"
    verdict = rec.get("validator_verdict") or "(not validated)"

    out: list[str] = []
    out.append(f"# {rec_id} — {title}")
    out.append("")
    out.append(
        "> **Recon hypothesis — an UNVERIFIED candidate from the "
        "breadth-first survey.** This is not a confirmed bug and not a "
        "finding. It is a raw claim recorded so a developer can re-check "
        "it. Trust the testcase evidence and the validator votes below, "
        "not the claim itself."
    )
    out.append("")

    rows = [
        ("Confidence", rec.get("confidence") or "?"),
        ("Class", rec.get("class") or "?"),
        ("Location", _location(rec)),
        ("Slice", rec.get("slice") or "?"),
        ("Validator verdict", verdict),
    ]
    out.append("| Field | Value |")
    out.append("| --- | --- |")
    for label, value in rows:
        out.append(f"| {label} | {_md_escape_cell(value)} |")
    out.append("")

    notes = rec.get("notes")
    if notes:
        out.append("## Hypothesis")
        out.append("")
        out.append(str(notes).strip())
        out.append("")

    # Optional strict-schema fields — only emitted when the recon agent
    # supplied them, so older/lighter rows don't sprout empty sections.
    reach = rec.get("reach_path")
    if isinstance(reach, list) and reach:
        out.append("## Reach path")
        out.append("")
        out.append(" → ".join(str(s) for s in reach))
        out.append("")
    if rec.get("input_shape"):
        out.append("## Input shape")
        out.append("")
        out.append(str(rec["input_shape"]).strip())
        out.append("")
    guards = rec.get("guards_passed")
    if isinstance(guards, list) and guards:
        out.append("## Guards passed")
        out.append("")
        for g in guards:
            out.append(f"- {g}")
        out.append("")
    if rec.get("primitive"):
        out.append("## Primitive")
        out.append("")
        out.append(str(rec["primitive"]).strip())
        out.append("")
    if rec.get("falsification"):
        out.append("## Falsification attempt")
        out.append("")
        out.append(str(rec["falsification"]).strip())
        out.append("")

    # ── Independent validator review ─────────────────────────────────────
    votes = _vote_files(recon_dir)
    out.append("## Independent validator review")
    out.append("")
    if not votes:
        out.append(
            "_No validator votes on disk — this candidate was not run "
            "through the validation gate (recon validation may have been "
            "disabled, or the candidate was audit-clean)._"
        )
        out.append("")
    for vote_path in votes:
        try:
            vote = json.loads(vote_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            out.append(f"### {vote_path.name} — (unreadable)")
            out.append("")
            continue
        n = re.search(r"(\d+)", vote_path.name)
        label = n.group(1) if n else "?"
        out.append(f"### Vote {label} — {vote.get('vote', 'Unknown')}")
        out.append("")
        rationale = vote.get("rationale")
        if rationale:
            out.append(str(rationale).strip())
            out.append("")
        verified = vote.get("verified")
        if isinstance(verified, dict) and verified:
            checks = ", ".join(
                f"{k}={'yes' if v else 'no'}" for k, v in verified.items()
            )
            out.append(f"- **Verified:** {checks}")
        caveats = vote.get("caveats")
        if caveats:
            out.append(f"- **Caveats:** {str(caveats).strip()}")
        out.append("")

    out.append("---")
    out.append("")
    out.append(
        "_Generated by `lib/recon_report.py` from `finding.json` + "
        "`validator-vote-*.json`. Re-run that helper to refresh._"
    )
    out.append("")
    return "\n".join(out)


def _maybe_render_html(md_path: Path) -> None:
    """Best-effort REPORT.html sibling via bin/render-md (mirrors cluster-*)."""
    here = Path(__file__).resolve().parent.parent / "bin" / "render-md"
    if not here.is_file() or not os.access(here, os.X_OK):
        return
    try:
        subprocess.run(
            ["python3", str(here), str(md_path), "--html-sibling"],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (subprocess.SubprocessError, OSError):
        pass


def write_report(recon_dir: Path, html: bool = True) -> Path:
    """Render REPORT.md (and optionally REPORT.html) for one RECON dir."""
    md = render_report_md(recon_dir)
    md_path = recon_dir / "REPORT.md"
    md_path.write_text(md, encoding="utf-8")
    if html:
        _maybe_render_html(md_path)
    return md_path


# ── directory discovery ──────────────────────────────────────────────────


def _is_recon_dir(path: Path) -> bool:
    return path.is_dir() and (path / "finding.json").is_file()


def discover_recon_dirs(arg: Path) -> list[Path]:
    """Resolve a CLI path argument to the list of RECON-* dirs under it.

    Accepts a single RECON-* dir, a recon/ root, or any results dir that
    contains a recon/ subdirectory.
    """
    if _is_recon_dir(arg):
        return [arg]
    roots: list[Path] = []
    if arg.is_dir():
        roots.append(arg)
        recon_sub = arg / "recon"
        if recon_sub.is_dir():
            roots.append(recon_sub)
    found: list[Path] = []
    seen: set[Path] = set()
    for root in roots:
        for child in sorted(root.iterdir()):
            if child.name.startswith("RECON-") and _is_recon_dir(child):
                rp = child.resolve()
                if rp not in seen:
                    seen.add(rp)
                    found.append(child)
    return found


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument(
        "path",
        type=Path,
        help="a RECON-* dir, a recon/ dir, or a results dir containing recon/",
    )
    ap.add_argument(
        "--no-html",
        action="store_true",
        help="skip the REPORT.html sibling (REPORT.md only)",
    )
    args = ap.parse_args(argv)

    if not args.path.exists():
        print(f"recon_report: path not found: {args.path}", file=sys.stderr)
        return 1

    recon_dirs = discover_recon_dirs(args.path)
    if not recon_dirs:
        print(
            f"recon_report: no RECON-* directories under {args.path}",
            file=sys.stderr,
        )
        return 0

    written = 0
    for recon_dir in recon_dirs:
        try:
            write_report(recon_dir, html=not args.no_html)
            written += 1
        except ValueError as exc:
            print(f"recon_report: skipping {recon_dir.name}: {exc}", file=sys.stderr)
    print(f"recon_report: wrote {written} REPORT.md file(s).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
