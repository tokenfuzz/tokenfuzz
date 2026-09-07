"""evidence_pages.py — the pages a reviewer opens after the ledger.

Three page kinds share one visual language with `lib/benchmark_page.py`, so a
reader who clicks from the benchmark result page into a cluster index, and
from there into a report, never changes idiom:

  * the **cluster index** (`FINDING-CLUSTERS.html`, `CRASH-CLUSTERS.html`):
    every distinct problem a run surfaced — when each was first filed, where in
    the tree it sits, which strategy lane reached it, how often the model
    re-found it, and who filed it when several conditions or backends share
    the page;
  * the **rejected index** (`REJECTED-FINDINGS.html`, `REJECTED-CRASHES.html`):
    what did not hold up, grouped by why, so over-claiming reads as a property
    of a condition rather than noise to skip;
  * the **report shell** around a single `report.html` / `REPORT.html`:
    the Markdown body `bin/render-md` produces, framed by an action card (what
    to fix, where, how to reproduce, how sure the harness is) and an evidence
    rail (severity vector, review receipt, bundle files, timeline) read from
    the sidecars beside the report.

Every number on these pages is read from what the clusterers and triage
already wrote to disk — cluster JSON, `severity.json`, `validation.json`,
`REJECTION.md`, the filing clock — never re-derived, so the pages cannot
disagree with the Markdown indexes beside them. The pages are self-contained
(inline CSS and script, no network) and render without script as plain tables.
"""

from __future__ import annotations

import html
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

import bug_classes
import crash_artifacts
import report_identity
import strategies
import validation_receipt

__all__ = [
    "artifact_facts", "report_context", "report_document", "action_card",
    "write_cluster_page", "write_rejected_page", "render_cluster_page",
    "render_rejected_page",
]

# ── vocabulary ────────────────────────────────────────────────────────────

_KIND = {
    "find": {
        "sub": "findings", "rejected_sub": "findings-rejected",
        "index": "FINDING-CLUSTERS", "rejected_index": "REJECTED-FINDINGS",
        "noun": "finding", "report": "finding report",
        "problem": "distinct problem", "problems": "distinct problems", "axis": "Class",
    },
    "crash": {
        "sub": "crashes", "rejected_sub": "crashes-rejected",
        "index": "CRASH-CLUSTERS", "rejected_index": "REJECTED-CRASHES",
        "noun": "crash", "report": "sanitizer report",
        "problem": "distinct crash", "problems": "distinct crashes", "axis": "Primitive",
    },
}
_SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
_SEVERITY_ORDER = ("Critical", "High", "Medium", "Low")
# Backend hues: the same categorical order the benchmark page validated.
_HUES = ("codex", "claude", "gemini", "grok", "oss", "opencode")
_CONDITIONS = ("harness", "model-direct")

# Path components that name a layer rather than a subsystem. When a site path
# starts with one of these, the subsystem is the next component joined to it
# (`modules/core`, `src/lib`), so a tree that nests everything under `src/`
# still spreads across bars. Inclusion criterion: a directory name that
# conventional layouts use for "where the code lives" in any project.
_LAYER_DIRS = frozenset({
    "src", "lib", "libs", "source", "sources", "modules", "module", "include",
    "internal", "pkg", "packages", "crates", "cmd", "app", "apps", "core",
})

# CVSS v4.0 metric names and value words, for the severity rail.
_CVSS_METRICS = {
    "AV": ("Attack vector", {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}),
    "AC": ("Attack complexity", {"L": "low", "H": "high"}),
    "AT": ("Attack requirements", {"N": "none", "P": "present"}),
    "PR": ("Privileges required", {"N": "none", "L": "low", "H": "high"}),
    "UI": ("User interaction", {"N": "none", "P": "passive", "A": "active"}),
    "VC": ("Confidentiality impact", {"H": "high", "L": "low", "N": "none"}),
    "VI": ("Integrity impact", {"H": "high", "L": "low", "N": "none"}),
    "VA": ("Availability impact", {"H": "high", "L": "low", "N": "none"}),
    "SC": ("Subsequent confidentiality", {"H": "high", "L": "low", "N": "none"}),
    "SI": ("Subsequent integrity", {"H": "high", "L": "low", "N": "none"}),
    "SA": ("Subsequent availability", {"H": "high", "L": "low", "N": "none"}),
    "E": ("Exploit maturity (reproduction confidence here)",
          {"X": "not defined", "A": "attacked", "P": "proof of concept", "U": "unreported"}),
}
_CVSS_GROUPS = (
    ("Reach", ("AV", "AC", "AT", "PR", "UI")),
    ("Impact", ("VC", "VI", "VA", "SC", "SI", "SA")),
    ("Confidence", ("E",)),
)

_TITLE_RE = re.compile(r"^#\s*(?:/?[\w/.-]*?[A-Z]+-[\w.-]+\s*[:—–-]\s*)?(.+?)\s*$")
_TLDR_RE = re.compile(r"^-\s*\*\*(Bug|Trigger|Fix)\*\*\s*[—–-]\s*(.+?)\s*$")
_TABLE_FIELD_RE = re.compile(r"^\|\s*([A-Za-z][A-Za-z0-9 /_-]{0,48}?)\s*\|\s*(.*?)\s*\|\s*$")
_BARE_FIELD_RE = re.compile(r"^([A-Za-z][A-Za-z0-9 /_-]{1,48}):\s+(\S.*)$")
_LOCATION_RE = re.compile(
    r"^Location:\s*`?(?P<path>[\w./+\-]+):(?P<func>[^:\s`]+):(?P<line>\d+)`?", re.MULTILINE)
_FRAME_RE = re.compile(r"^(?P<func>.+?)\s+(?P<path>[\w./+\-]+):(?P<line>\d+)$")
_UPSTREAM_RE = re.compile(r"\[View at [0-9a-f]{6,}[^\]]*\]\((https?://[^)\s]+)\)")
_SECTION_RE = re.compile(r"^##\s+(?P<name>[^\n]+)\n(?P<body>.*?)(?=^##\s|\Z)", re.MULTILINE | re.DOTALL)
_ENRICH_RE = re.compile(r"<!--\s*enrich:[\w-]+\s*-->.*?<!--\s*/enrich:[\w-]+\s*-->", re.DOTALL)
_HEADING_RE = re.compile(r'<h([23]) id="([^"]+)">(.*?)<a class="anchor"', re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
_SIBLING_RE = re.compile(r"\b((?:CRASH|FIND)-\d+(?:-\d+)?)\b")
_REJECTION_REASON_RE = re.compile(r"^\s*(?:#\s*)?Reason:\s*(.+?)\s*$", re.I | re.M)
_REASON_FAMILY_RE = re.compile(r"^([a-z][a-z-]{2,})\s*(?:\([^)]*\))?\s*:\s*(.+)$")
_INDEPENDENT_RE = re.compile(r"\s*\(\d+ independent rejects?\)")
_FIX_HEADINGS = ("fix direction", "fix", "patch", "remediation")


# ── small helpers ─────────────────────────────────────────────────────────

def _e(value: object) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _read_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return default


def _read_text(path: Path | None) -> str:
    if path is None:
        return ""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _epoch(stamp: object) -> float | None:
    if isinstance(stamp, (int, float)):
        return float(stamp)
    if not isinstance(stamp, str) or not stamp.strip():
        return None
    try:
        parsed = datetime.fromisoformat(stamp.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _when(epoch: float | None) -> str:
    if epoch is None:
        return ""
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def _rel_hours(epoch: float | None, origin: float | None) -> float | None:
    if epoch is None or origin is None:
        return None
    return max(0.0, (epoch - origin) / 3600.0)


def _tcell(epoch: float | None, hours: float | None) -> str:
    """A filing-time cell: absolute for the no-script reader, relative on screen."""
    if epoch is None:
        return '<td class="num tcell">—</td>'
    rel = "" if hours is None else f' data-rel="{hours:.4f}"'
    return f'<td class="num tcell"{rel}>{_e(_when(epoch))}</td>'


def _fmt_h(hours: float | None) -> str:
    if hours is None:
        return "—"
    if hours < 1:
        return f"+{hours * 60:.0f} min"
    return f"+{hours:.1f} h"


def _href(target: Path | None, page_dir: Path, *, must_exist: bool = True) -> str:
    """A relative link from the page's directory, or "" when the target is gone."""
    if target is None or (must_exist and not target.exists()):
        return ""
    return "/".join(
        _quote(part) for part in
        os.path.relpath(target.absolute(), page_dir.absolute()).split(os.sep)
    )


def _quote(part: str) -> str:
    from urllib.parse import quote
    return quote(part, safe="")


def _report_view(report: Path | None) -> Path | None:
    """The rendered sibling of a report.

    Index maintenance renders every report it indexes in the same pass, so
    the page is the link target from the moment the Markdown exists; linking
    the Markdown instead would leave the first pass pointing at raw text.
    """
    if report is None:
        return None
    return report.with_suffix(".html")


def _token(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-") or "none"


def _sev_rank(level: str) -> int:
    return _SEVERITY_RANK.get(str(level or "").strip().capitalize(), 0)


def _sev_pill(level: str, score: float | None = None) -> str:
    label = str(level or "").strip() or "Pending"
    score_html = f'<span class="score">{score:g}</span>' if score else ""
    return f'<span class="sev sev-{_token(label)}">{_e(label)}{score_html}</span>'


def _who_class(who: str) -> str:
    if who in _CONDITIONS:
        return f"who-{who}"
    return f"who-{who}" if who in _HUES else "who-other"


def _who_chip(who: str) -> str:
    if not who:
        return ""
    return f'<span class="who {_who_class(who)}">{_e(who)}</span>'


def _lane_chip(lane: str) -> str:
    if not lane:
        return ""
    name = strategies.NAMES.get(lane, "")
    title = f' title="{_e(lane)} — {_e(name)}"' if name else ""
    return f'<span class="lane lane-{_e(lane)}"{title}>{_e(lane)}</span>'


def _status_chip(status: str) -> str:
    raw = str(status or "OK").strip()
    head = raw.split(" ", 1)[0].rstrip(":;").lower()
    words = {
        "ok": "pinned" if "override" in raw.lower() else "accepted",
        "pending": "pending", "needs": raw.lower(),
        "not-reportable": "no security credit", "stale": "stale review",
    }
    label = words.get(head, raw.lower())
    return f'<span class="st st-{_token(head)}" title="{_e(raw)}">{_e(label)}</span>'


def _subsystem(path: str) -> str:
    parts = [p for p in str(path or "").split("/") if p]
    if not parts:
        return ""
    if len(parts) == 1:
        return parts[0]
    if parts[0] in _LAYER_DIRS and len(parts) > 2:
        return "/".join(parts[:2])
    return parts[0]


def _outside_fences(text: str) -> list[str]:
    lines = text.splitlines()
    mask = report_identity.code_fence_mask(lines)
    return [line for line, fenced in zip(lines, mask) if not fenced]


# ── reading one report ────────────────────────────────────────────────────

def report_fields(text: str) -> dict[str, str]:
    """`{lowercased label: value}` from the Fields table and the bare labels.

    The table wins where both carry a label — it is the promoted, reviewed
    form — and a bare label only counts when the shared vocabulary knows it,
    so prose lines shaped like `Note: ...` never become fields.
    """
    known = {label.casefold() for label in report_identity.ALL_FIELD_LABELS}
    table: dict[str, str] = {}
    bare: dict[str, str] = {}
    for line in _outside_fences(text):
        match = _TABLE_FIELD_RE.match(line)
        if match:
            key = match.group(1).strip().casefold()
            value = match.group(2).strip()
            if key and key != "field" and not set(value) <= set(":- ") and key not in table:
                table[key] = value
            continue
        match = _BARE_FIELD_RE.match(line)
        if match and match.group(1).strip().casefold() in known:
            bare.setdefault(match.group(1).strip().casefold(), match.group(2).strip())
    merged = dict(bare)
    merged.update({k: v for k, v in table.items()
                   if not report_identity.field_value_is_placeholder(k, v)})
    return merged


_ID_ONLY_RE = re.compile(r"^/?[\w/.-]*?(?:CRASH|FIND)-[\w.-]+$")


def _report_title(text: str, fallback: str) -> str:
    """The report's own heading, or its one-line bug summary when the heading
    is only the artifact id."""
    for line in _outside_fences(text):
        if line.startswith("# "):
            match = _TITLE_RE.match(line)
            title = (match.group(1) if match else line[2:]).strip()
            if title and not _ID_ONLY_RE.match(title):
                return title
            break
    tldr = _tldr(text)
    line = tldr.get("bug") or _first_paragraph(_sections(text).get("summary", ""), 140)
    if line:
        return line if len(line) <= 140 else line[:137].rstrip() + "…"
    return fallback


def _tldr(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in text.splitlines():
        match = _TLDR_RE.match(line.strip())
        if match:
            out.setdefault(match.group(1).lower(), match.group(2).strip())
    return out


def _sections(text: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for match in _SECTION_RE.finditer(text):
        name = match.group("name").strip().lower()
        body = _ENRICH_RE.sub("", match.group("body")).strip()
        out.setdefault(name, body)
    return out


def _first_paragraph(body: str, limit: int = 420) -> str:
    plain = body.split("\n\n", 1)[0]
    plain = " ".join(s.strip() for s in plain.splitlines() if s.strip())
    plain = re.sub(r"\s+", " ", plain)
    if len(plain) > limit:
        plain = plain[:limit - 1].rstrip() + "…"
    return plain


def _site(fields: dict[str, str], text: str) -> dict[str, str]:
    """`{path, function, line}` for the report's primary site."""
    match = _LOCATION_RE.search(text)
    if match:
        return {"path": match.group("path"), "function": match.group("func"),
                "line": match.group("line")}
    path = fields.get("file", "").strip("`")
    line = fields.get("line", "").strip("`")
    function = fields.get("function", "").strip("`")
    if path:
        return {"path": path, "function": function, "line": line}
    frames = fields.get("dedup frames") or fields.get("clusterfuzz key frames") or ""
    for frame in frames.split(" -> "):
        match = _FRAME_RE.match(frame.strip())
        if match:
            return {"path": match.group("path"), "function": match.group("func"),
                    "line": match.group("line")}
    return {"path": "", "function": "", "line": ""}


def _site_text(site: dict[str, str]) -> str:
    parts = [site.get("path", "")]
    if site.get("function"):
        parts.append(site["function"])
    if site.get("line"):
        parts.append(site["line"])
    return ":".join(p for p in parts if p)


def _upstream_link(text: str, site: dict[str, str]) -> str:
    links = _UPSTREAM_RE.findall(text)
    if not links:
        return ""
    path, line = site.get("path", ""), site.get("line", "")
    for link in links:
        if path and path in link and (not line or link.endswith(f"#L{line}")):
            return link
    for link in links:
        if path and path.rsplit("/", 1)[-1] in link:
            return link
    return links[0]


def _severity(directory: Path, text: str) -> dict:
    receipt = _read_json(directory / "severity.json", {}) or {}
    level = str(receipt.get("level") or "").strip()
    if not level:
        # bin/severity writes the report's own line; the receipt can lag it
        import finding_signature
        level, _rank, score = finding_signature.extract_severity(text)
        level = "" if level == "—" else level
        return {"level": level, "score": score or None, "vector": "", "rank": _sev_rank(level),
                "scored_at": None, "primitive": ""}
    score = receipt.get("score")
    return {
        "level": level,
        "score": float(score) if isinstance(score, (int, float)) and score else None,
        "vector": str(receipt.get("vector") or ""),
        "rank": _sev_rank(level),
        "scored_at": _epoch(receipt.get("scored_at")),
        "primitive": str(receipt.get("primitive") or ""),
    }


def _bundle(directory: Path) -> list[dict]:
    """Visible files beside the report, largest first within their role."""
    roles = (
        ("reproduce", lambda n: n == "reproduce.sh"),
        ("patch", lambda n: n == "patch.diff"),
        ("testcase", lambda n: n.startswith(("input", "testcase", "repro", "seed")) or n.endswith(".raw")),
        ("harness", lambda n: n.startswith(("harness", "probe-harness")) and "." in n),
        ("sanitizer", lambda n: crash_artifacts.is_sanitizer_name(n)),
        ("receipt", lambda n: n in ("severity.json", "validation.json", "REJECTION.md")),
        ("report", lambda n: n in report_identity.REPORT_NAMES or n.lower().endswith(".html")),
    )
    out: list[dict] = []
    try:
        children = sorted(directory.iterdir())
    except OSError:
        return out
    for child in children:
        if child.name.startswith(".") or not child.is_file():
            continue
        role = next((r for r, test in roles if test(child.name)), "other")
        try:
            size = child.stat().st_size
        except OSError:
            size = 0
        out.append({"name": child.name, "role": role, "size": size, "path": child})
    return out


def artifact_facts(directory: Path, kind: str, *, stamps: dict[str, float] | None = None) -> dict:
    """Everything a page shows about one artifact directory, read once.

    `kind` is `find` or `crash`. `stamps` is the per-results discovery clock
    (`state/events.jsonl`) keyed by artifact id, which beats the filesystem
    fallback for a finding that was edited after it was filed.
    """
    directory = Path(directory)
    report = report_identity.find_report(directory)
    text = _read_text(report)
    fields = report_fields(text)
    severity = _severity(directory, text)
    validation = _read_json(directory / "validation.json", {}) or {}
    quality = _read_json(directory / ".llm-find-quality.json", {}) or {}
    gate = _read_json(directory / ".trigger-gate.json", {}) or {}
    site = _site(fields, text)
    tldr = _tldr(text)
    sections = _sections(text)
    rejection = _REJECTION_REASON_RE.search(_read_text(directory / "REJECTION.md"))
    filed = (stamps or {}).get(directory.name)
    if filed is None:
        filed = crash_artifacts.filing_time(directory)
    raw_class = fields.get("class") or quality.get("class") or ""
    bug_class = bug_classes.canonical_class(raw_class) if raw_class else ""
    primitive = fields.get("primitive") or severity.get("primitive") or ""
    lanes = [
        lane for lane in re.split(r"[,\s/]+", strategies.normalize(fields.get("strategy", "")))
        if lane
    ]
    state = str(validation.get("state") or "")
    no_credit = validation_receipt.claims_no_security_credit(directory)
    if rejection or state == "rejected":
        status = "rejected"
    elif no_credit:
        status = "not-reportable"
    elif state in validation_receipt.FINAL_STATES:
        status = "accepted"
    elif state == "pending" or not state:
        status = "pending"
    else:
        status = state
    fix = tldr.get("fix", "")
    if not fix:
        for name in _FIX_HEADINGS:
            if sections.get(name):
                fix = _first_paragraph(sections[name])
                break
    bundle = _bundle(directory)
    by_role: dict[str, list[dict]] = {}
    for item in bundle:
        by_role.setdefault(item["role"], []).append(item)
    return {
        "id": directory.name,
        "dir": directory,
        "kind": kind,
        "report": report,
        "view": _report_view(report),
        "title": _report_title(text, directory.name),
        "summary": _first_paragraph(sections.get("summary", "")) or tldr.get("bug", ""),
        "fields": fields,
        "severity": severity,
        "class": bug_class,
        "family": bug_classes.family_of(bug_class) if bug_class else "",
        "primitive": primitive,
        "surface": fields.get("surface", "").split("—", 1)[0].strip(),
        "site": site,
        "site_text": _site_text(site),
        "upstream": _upstream_link(text, site),
        "lanes": lanes,
        "filed_at": filed,
        "validated_at": _epoch(validation.get("validated_at")),
        "validation": {"state": state, "detail": str(validation.get("detail") or "")},
        "status": status,
        "rejection": rejection.group(1).strip() if rejection else "",
        "votes": {
            "accept": int(quality.get("accept_count") or 0),
            "reject": int(quality.get("reject_count") or 0),
            "reason": str(quality.get("reason") or ""),
        },
        "gate": {
            "vote": str(gate.get("vote") or ""),
            "rationale": str(gate.get("rationale") or ""),
            "trigger_path": str(gate.get("trigger_path") or ""),
            "anchors": len(gate.get("anchors") or []) if isinstance(gate.get("anchors"), list) else 0,
        },
        "attestations": len((validation.get("evidence") or {}).get("source_attestations") or []),
        "repro_rate": fields.get("reproduction rate", ""),
        "tldr": tldr,
        "fix": fix,
        "bundle": bundle,
        "by_role": by_role,
        "cluster": fields.get("cluster", ""),
    }


# ── run context: who filed what, and on which clock ───────────────────────

def _event_stamps(results: Path) -> dict[str, float]:
    events = results / "state" / "events.jsonl"
    out: dict[str, float] = {}
    if not events.is_file():
        return out
    try:
        with events.open(errors="replace") as stream:
            for line in stream:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if row.get("type") not in ("finding_created", "crash_created"):
                    continue
                when = _epoch(row.get("mtime") or row.get("first_seen"))
                if when is not None and row.get("id"):
                    out.setdefault(str(row["id"]), when)
    except OSError:
        pass
    return out


def _session_start(results: Path) -> float | None:
    for line in _read_text(results / ".session-env").splitlines():
        if line.startswith("SESSION_STARTED="):
            return _epoch(line.split("=", 1)[1])
    return None


def _cells_clock(run_dir: Path, condition: str) -> tuple[dict[str, float], float | None]:
    """Each condition's earliest cell start, and the longest wall in hours.

    Conditions of one run start on their own clocks, so a merged page places
    every report on its own condition's clock: the comparison is hours into
    each run, not hours since whichever condition happened to start first.
    """
    starts: dict[str, float] = {}
    walls: list[float] = []
    for cell in sorted((run_dir / "cells").glob("*/cell.json")):
        meta = _read_json(cell, {}) or {}
        cond = str(meta.get("condition") or "")
        if condition and cond != condition:
            continue
        start = _epoch(meta.get("started_at"))
        if start is not None and (cond not in starts or start < starts[cond]):
            starts[cond] = start
        try:
            walls.append(float(meta.get("wall_seconds") or 0) / 3600.0)
        except (TypeError, ValueError):
            pass
    return starts, (max(walls) if walls else None)


class _Context:
    """Who filed each artifact and where t=0 is, derived from the layout.

    Recognised layouts, most specific first:
      * `<run>/pool/<condition>/<sub>/` — one benchmark condition;
      * `<run>/pool/<sub>/` — the merged benchmark pool, owners in
        `pool-members.json`;
      * `output/<target>/<backend>/results/<sub>/` — one backend's audit;
      * anything else — no attribution.
    """

    def __init__(self, root: Path, sub: str) -> None:
        root = Path(root)
        self.root = root
        self.owner: dict[str, str] = {}
        self.constant = ""
        self.origins: dict[str, float] = {}
        self.wall_h: float | None = None
        self.stamps: dict[str, float] = {}
        self.target = ""
        parents = root.parents
        if root.parent.name in _CONDITIONS and len(parents) > 2 and parents[1].name == "pool":
            self.constant = root.parent.name
            self.origins, self.wall_h = _cells_clock(parents[2], self.constant)
            self.target = _target_name(parents[2])
        elif root.parent.name == "pool" and len(parents) > 1 and (parents[1] / "pool-members.json").is_file():
            members = _read_json(parents[1] / "pool-members.json", {}) or {}
            self.owner = {str(k): str(v) for k, v in (members.get(sub) or {}).items()}
            self.origins, self.wall_h = _cells_clock(parents[1], "")
            self.target = _target_name(parents[1])
        elif root.parent.name == "results" and len(parents) > 1:
            self.constant = parents[1].name
            start = _session_start(root.parent)
            if start is not None:
                self.origins = {self.constant: start}
            self.stamps = _event_stamps(root.parent)
            self.target = _target_name(parents[2] if len(parents) > 2 else parents[1])
        else:
            self.target = _target_name(root)

    def who(self, artifact_id: str, hint: str = "") -> str:
        return hint or self.owner.get(artifact_id, "") or self.constant

    @property
    def origin(self) -> float | None:
        """The earliest known run start, for a page with one clock."""
        return min(self.origins.values()) if self.origins else None

    def origin_for(self, whos: Iterable[str]) -> float | None:
        """The clock a report is placed on: its own condition's start."""
        mine = [self.origins[w] for w in whos if w in self.origins]
        return min(mine) if mine else self.origin

    def hours(self, epoch: float | None, whos: Iterable[str]) -> float | None:
        return _rel_hours(epoch, self.origin_for(whos))


def _target_name(start: Path) -> str:
    # Path.parents gained slice support in Python 3.10. Materialize only this
    # tiny bounded sequence so index maintenance remains usable on 3.9.
    for base in (start, *tuple(start.parents)[:3]):
        toml = base / "target.toml"
        if toml.is_file():
            match = re.search(r'^\s*target\s*=\s*"([^"]+)"', _read_text(toml), re.M)
            if match:
                return match.group(1)
            return base.name
    return ""


# ── the cluster index ─────────────────────────────────────────────────────

def _problem(cluster: dict, kind: str, ctx: _Context, page_dir: Path) -> dict:
    members: list[dict] = []
    facts_by: dict[str, dict] = {}
    for member in cluster.get("_full") or []:
        directory = Path(member.get("path") or "")
        facts = artifact_facts(directory, kind, stamps=ctx.stamps) if directory.is_dir() else None
        display = member.get("display_id") or member.get("id") or directory.name
        who = ctx.who(member.get("id") or directory.name, member.get("agent", ""))
        level = str(member.get("severity_label") or member.get("severity_level") or "")
        score = facts["severity"]["score"] if facts else None
        if not score:
            try:
                score = float(member.get("severity_score") or 0) or None
            except (TypeError, ValueError):
                score = None
        lane = strategies.normalize(str(member.get("strategy") or ""))
        row = {
            "id": display,
            "href": _href(facts["view"], page_dir, must_exist=False) if facts else "",
            "level": level if level and level != "—" else (facts["severity"]["level"] if facts else ""),
            "score": score,
            "who": who,
            "lanes": [lane] if lane else (facts["lanes"] if facts else []),
            "filed_at": facts["filed_at"] if facts else None,
            "filed_h": ctx.hours(facts["filed_at"], [who]) if facts else None,
            "status": str(member.get("status") or "OK"),
            "title": facts["title"] if facts else display,
            "site": facts["site_text"] if facts else "",
            "path": facts["site"]["path"] if facts else "",
        }
        members.append(row)
        if facts:
            facts_by[display] = facts
    canonical_id = str(cluster.get("canonical") or (members[0]["id"] if members else ""))
    canonical = facts_by.get(canonical_id) or next(iter(facts_by.values()), None)
    level = str(cluster.get("severity_label") or cluster.get("severity_level") or "")
    if level == "—":
        level = ""
    score = None
    if canonical and canonical["severity"]["score"] and canonical["severity"]["rank"] == _sev_rank(level):
        score = canonical["severity"]["score"]
    elif cluster.get("severity_score"):
        try:
            score = float(cluster["severity_score"]) or None
        except (TypeError, ValueError):
            score = None
    if kind == "find":
        axis = str(cluster.get("class") or (canonical["class"] if canonical else "") or "other")
    else:
        axis = str(cluster.get("primitive") or (canonical["primitive"] if canonical else "") or "unknown")
    path = ""
    if kind == "find":
        path = str(cluster.get("file") or "")
    if not path and canonical:
        path = canonical["site"]["path"]
    if not path:
        path = next((m["path"] for m in members if m["path"]), "")
    site = canonical["site_text"] if canonical else next((m["site"] for m in members if m["site"]), "")
    if kind == "find" and cluster.get("file") and cluster.get("line"):
        site = f"{cluster['file']}:{cluster['line']}"
        if canonical and canonical["site"]["function"]:
            site = f"{cluster['file']}:{canonical['site']['function']}:{cluster['line']}"
    lanes = sorted({lane for m in members for lane in m["lanes"]},
                   key=lambda k: (k not in strategies.NAMES, k))
    whos = sorted({m["who"] for m in members if m["who"]})
    times = [m["filed_at"] for m in members if m["filed_at"] is not None]
    first = min(times) if times else None
    canonical_row = next((m for m in members if m["id"] == canonical_id), members[0] if members else None)
    return {
        "id": str(cluster.get("id") or ""),
        "level": level,
        "rank": _sev_rank(level),
        "score": score,
        "axis": axis,
        "family": bug_classes.family_of(axis) if kind == "find" else axis,
        "signature": str(cluster.get("signature") or ""),
        "key_kind": str(cluster.get("key_kind") or ""),
        "merged_via": str(cluster.get("merged_via") or ""),
        "title": canonical["title"] if canonical else (canonical_row["title"] if canonical_row else ""),
        "summary": canonical["summary"] if canonical else "",
        "site": site,
        "subsystem": _subsystem(path),
        "href": canonical_row["href"] if canonical_row else "",
        "canonical": canonical_id,
        "lanes": lanes,
        "who": whos,
        "size": int(cluster.get("size") or len(members) or 1),
        "first_at": first,
        "first_h": ctx.hours(first, whos),
        "status": str(cluster.get("status") or "OK"),
        "members": sorted(members, key=lambda m: (m["filed_at"] is None, m["filed_at"] or 0)),
    }


def _timeline_payload(points: list[dict], ctx: _Context) -> dict:
    """Series for the discovery chart: cumulative count per `who`, on run time."""
    times = [p["t_abs"] for p in points if p["t_abs"] is not None]
    origin = ctx.origin if ctx.origin is not None else (min(times) if times else None)
    out_points = []
    for p in points:
        t = _rel_hours(p["t_abs"], ctx.origin_for(p.get("who") or ()) if ctx.origins else origin)
        out_points.append({**{k: v for k, v in p.items() if k != "t_abs"}, "t": t})
    wall = ctx.wall_h
    placed = [p["t"] for p in out_points if p["t"] is not None]
    x_max = max([wall or 0.0] + placed) if (placed or wall) else 0.0
    return {
        "points": out_points,
        "origin": _when(origin),
        "origin_is_run_start": ctx.origin is not None,
        "per_condition": len(ctx.origins) > 1,
        "wall_h": wall,
        "x_max": x_max,
        "unplaced": sum(1 for p in out_points if p["t"] is None),
    }


def render_cluster_page(kind: str, clusters: list[dict], root: Path, page_dir: Path,
                        *, generated: str | None = None) -> str:
    """The cluster index as a page: problems, their clock, their map."""
    spec = _KIND[kind]
    ctx = _Context(root, spec["sub"])
    problems = [_problem(c, kind, ctx, page_dir) for c in clusters]
    reports = sum(p["size"] for p in problems)
    # the who column and filter only earn their place when they split the page
    whos = sorted({w for p in problems for w in p["who"]})
    whos = whos if len(whos) > 1 else []
    by_level: dict[str, int] = {}
    for p in problems:
        by_level[p["level"] or "Pending"] = by_level.get(p["level"] or "Pending", 0) + 1
    mplus = sum(1 for p in problems if p["rank"] >= 2)
    lanes_used = sorted({lane for p in problems for lane in p["lanes"]},
                        key=lambda k: (k not in strategies.NAMES, k))
    axes = sorted({p["axis"] for p in problems})
    strongest = max(problems, key=lambda p: (p["rank"], p["score"] or 0, p["size"]), default=None)
    points = [{
        "id": p["id"], "t_abs": p["first_at"], "sev": _token(p["level"] or "pending"),
        "title": p["title"], "site": p["site"], "href": p["href"], "who": p["who"],
        "size": p["size"], "axis": p["axis"], "color": f"--{_sev_color(p['level'])}",
    } for p in problems]
    timeline = _timeline_payload(points, ctx)
    rejected_href = _href(_sibling_index(root, spec["rejected_sub"], spec["rejected_index"]), page_dir, must_exist=False)
    target = ctx.target
    scope = ctx.constant or ("both conditions" if ctx.owner else "")
    kick = " · ".join(x for x in ("TokenFuzz", spec["sub"], target, scope) if x)
    n_problems = len(problems)
    headline = (
        f"{n_problems} {spec['problems'] if n_problems != 1 else spec['problem']} "
        f"from {reports} {spec['report']}{'s' if reports != 1 else ''}"
    )
    lede = _cluster_lede(kind, problems, reports, mplus, strongest, whos)
    tiles = [
        (spec["problems"], str(n_problems), "after merging duplicates"),
        ("Medium or higher", str(mplus), "the security-yield subset"),
        ("reports filed", str(reports),
         f"{reports / n_problems:.2f}× rediscovery" if n_problems else "nothing filed yet"),
        (f"{spec['axis'].lower()}es" if spec["axis"].endswith("s") else f"{spec['axis'].lower()}s",
         str(len(axes)), ", ".join(axes[:4]) + ("…" if len(axes) > 4 else "")),
        ("strategy lanes", str(len(lanes_used)), " ".join(lanes_used) or "none recorded"),
    ]
    first_placed = [p for p in timeline["points"] if p["t"] is not None]
    if first_placed:
        first = min(first_placed, key=lambda p: p["t"])
        last = max(first_placed, key=lambda p: p["t"])
        tiles.append(("first problem", _fmt_h(first["t"]),
                      "into the run" if timeline["origin_is_run_start"] else "after the first report"))
        tiles.append(("last problem", _fmt_h(last["t"]),
                      f"of a {timeline['wall_h']:.1f} h budget" if timeline["wall_h"] else "on the same clock"))
    body = [
        _hero(kick, headline, lede, generated, [
            (rejected_href, f"what was rejected") if rejected_href else None,
            ("#guide", "how to read this page"),
        ]),
        _tiles(tiles),
        _severity_strip(by_level),
        '<section class="sec"><h2>When each problem was first filed</h2>'
        '<p class="pd">Each dot is one distinct problem at the moment its first report landed; the line '
        'counts them up over the run' + (', one per side' if len(whos) > 1 else '') + '. '
        'A run that keeps climbing was still finding new ground when the budget ended; one that '
        'flattens early had exhausted what its strategy could reach. Hover a dot for the problem, '
        'click it for the report.</p>'
        f'<div class="chart timeline" id="timeline"></div>{_timeline_legend(whos, timeline)}</section>',
        '<section class="sec two">'
        f'<div><h2>Where in the tree</h2><p class="pd">Problems by the subsystem their primary site '
        f'sits in, stacked by severity. Wide bars are where the model spent its attention; '
        f'a subsystem with one High and nothing else is a lead worth a second pass.</p>{_subsystem_bars(problems)}</div>'
        f'<div><h2>Which lane reached which {spec["axis"].lower()}</h2><p class="pd">The strategy lane '
        f'the filing agent was running, against the {spec["axis"].lower()} it found. A lane that only '
        f'ever finds one class is a lane the model reasons about narrowly.</p>{_heat(problems, lanes_used, axes, spec)}</div>'
        '</section>',
        _problem_table(problems, kind, whos, lanes_used, axes, spec),
        _cluster_guide(kind, spec),
    ]
    payload = {"timeline": timeline, "kind": kind}
    return _document(f"{spec['index']}", "".join(body), payload, page_class="index")


def _sev_color(level: str) -> str:
    key = str(level or "").strip().capitalize()
    return {"Critical": "crit", "High": "high", "Medium": "med", "Low": "low"}.get(key, "none")


def _sibling_index(root: Path, sub: str, basename: str) -> Path | None:
    """The rendered sibling index, once its Markdown exists.

    The index writers emit the Markdown and the page together, so the page is
    the link target whenever the index has been written at all; a tree with
    neither gets no link.
    """
    directory = root.parent / sub
    for suffix in (".html", ".md"):
        if (directory / f"{basename}{suffix}").is_file():
            return directory / f"{basename}.html"
    return None


def _cluster_lede(kind, problems, reports, mplus, strongest, whos) -> str:
    spec = _KIND[kind]
    if not problems:
        return (f"No {spec['report']}s have been filed here yet. The index fills in as triage "
                f"accepts reports; rejected ones are listed separately.")
    parts = []
    if kind == "find":
        parts.append("Each row is one problem: reports that name the same class at the same file "
                     "and line, or the same crash state, are merged and counted once.")
    else:
        parts.append("Each row is one crash: sanitizer reports with the same top frames are merged "
                     "and counted once, however many inputs reached them.")
    parts.append(f"{mplus} of {len(problems)} rate Medium or higher.")
    if strongest is not None and strongest["rank"]:
        where = f" at <span class=\"mono\">{_e(strongest['site'])}</span>" if strongest["site"] else ""
        link = f'<a href="{_e(strongest["href"])}">{_e(strongest["title"])}</a>' if strongest["href"] else _e(strongest["title"])
        parts.append(f"The strongest is {link} ({_e(strongest['level'])}{where}).")
    if len(whos) > 1:
        parts.append(f"Reports come from {_e(', '.join(whos))}; the who column and the filters split them.")
    parts.append("A cluster is a claim about identity, not a verdict: the report behind each row "
                 "carries the evidence, and a maintainer's confirmation is still the last word.")
    return " ".join(parts)


def _hero(kick: str, headline: str, lede: str, generated: str | None, links: list) -> str:
    stamp = generated or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    meta = " · ".join(
        [f"Generated {_e(stamp)}"] + [f'<a href="{_e(h)}">{_e(t)}</a>' for h, t in (l for l in links if l)]
    )
    return (
        f'<header class="hero"><p class="kick">{_e(kick)}</p><h1>{_e(headline)}</h1>'
        f'<p class="lede">{lede}</p><p class="meta">{meta}</p></header>'
    )


def _tiles(tiles: list[tuple[str, str, str]]) -> str:
    return '<div class="tiles">' + "".join(
        f'<div class="tile"><div class="tl">{_e(label)}</div><div class="tv">{_e(value)}</div>'
        f'<div class="tn">{_e(note)}</div></div>' for label, value, note in tiles
    ) + "</div>"


def _severity_strip(by_level: dict[str, int]) -> str:
    total = sum(by_level.values())
    if not total:
        return ""
    order = list(_SEVERITY_ORDER) + sorted(k for k in by_level if k not in _SEVERITY_ORDER)
    segs = "".join(
        f'<span class="seg sev-{_token(level)}" style="flex:{by_level[level]}" '
        f'title="{_e(level)}: {by_level[level]}"></span>'
        for level in order if by_level.get(level)
    )
    keys = "".join(
        f'<span class="k">{_sev_pill(level)} {by_level[level]}</span>'
        for level in order if by_level.get(level)
    )
    return f'<div class="sevbar"><div class="bar">{segs}</div><div class="legend">{keys}</div></div>'


def _timeline_legend(whos: list[str], timeline: dict) -> str:
    keys = [f'<span class="k"><i class="sw {_who_class(w)}"></i>{_e(w)}</span>' for w in whos]
    if len(whos) > 1:
        keys.append('<span class="k"><i class="sw sw-total"></i>all</span>')
    keys += [f'<span class="k"><b class="dot demo sev-{_token(l)}"></b>{l}</span>' for l in _SEVERITY_ORDER]
    notes = []
    if timeline["per_condition"]:
        notes.append("t = 0 is each condition's own run start")
    elif timeline["origin"]:
        notes.append(("t = 0 is the run start, " if timeline["origin_is_run_start"] else
                      "t = 0 is the first report, ") + timeline["origin"])
    if timeline["unplaced"]:
        notes.append(f"{timeline['unplaced']} without a filing clock are listed below but not drawn")
    return ('<div class="legend">' + "".join(keys) + "</div>"
            + (f'<p class="fine dim">{_e("; ".join(notes))}.</p>' if notes else ""))


def _subsystem_bars(problems: list[dict]) -> str:
    groups: dict[str, dict[str, int]] = {}
    for p in problems:
        name = p["subsystem"] or "(no site)"
        bucket = groups.setdefault(name, {})
        level = p["level"] if p["level"] in _SEVERITY_ORDER else "other"
        bucket[level] = bucket.get(level, 0) + 1
    if not groups:
        return '<p class="empty">Nothing to map yet.</p>'
    widest = max(sum(b.values()) for b in groups.values())
    rows = []
    for name, bucket in sorted(groups.items(), key=lambda kv: (-sum(kv[1].values()), kv[0]))[:14]:
        total = sum(bucket.values())
        segs = "".join(
            f'<span class="ff sev-{_token(level)}" style="width:{bucket[level] / widest * 100:.1f}%" '
            f'title="{level}: {bucket[level]}"></span>'
            for level in list(_SEVERITY_ORDER) + ["other"] if bucket.get(level)
        )
        rows.append(f'<div class="fr"><span class="fl mono" title="{_e(name)}">{_e(name)}</span>'
                    f'<span class="fb">{segs}</span><span class="fv">{total}</span></div>')
    more = len(groups) - 14
    if more > 0:
        rows.append(f'<p class="fine dim">and {more} more subsystem{"s" if more != 1 else ""} with fewer problems.</p>')
    return '<div class="funnel">' + "".join(rows) + "</div>"


def _heat(problems: list[dict], lanes: list[str], axes: list[str], spec: dict) -> str:
    if not problems:
        return '<p class="empty">Nothing to map yet.</p>'
    rows = lanes + (["—"] if any(not p["lanes"] for p in problems) else [])
    grid: dict[tuple[str, str], int] = {}
    for p in problems:
        for lane in (p["lanes"] or ["—"]):
            grid[(lane, p["axis"])] = grid.get((lane, p["axis"]), 0) + 1
    peak = max(grid.values()) if grid else 1
    head = "".join(f'<th class="num">{_e(a)}</th>' for a in axes)
    body = []
    for lane in rows:
        cells = []
        for axis in axes:
            n = grid.get((lane, axis), 0)
            alpha = 0.12 + 0.75 * n / peak if n else 0
            cells.append(f'<td class="hm num" style="--a:{alpha:.2f}">{n if n else ""}</td>')
        label = _lane_chip(lane) if lane != "—" else '<span class="dim">no lane</span>'
        name = strategies.NAMES.get(lane, "")
        body.append(f'<tr><td>{label} <span class="fine dim">{_e(name)}</span></td>{"".join(cells)}</tr>')
    return (f'<div class="tablewrap heat"><table><thead><tr><th>lane</th>{head}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def _filter_chips(name: str, values: Iterable[str], render: Callable[[str], str]) -> str:
    values = list(values)
    if len(values) < 2:
        return ""
    chips = "".join(
        f'<button type="button" class="chip on" data-filter="{_e(name)}" data-value="{_e(v)}">'
        f'{render(v)}</button>' for v in values
    )
    return f'<span class="fl">{_e(name)}</span>{chips}<span class="gap"></span>'


def _problem_table(problems, kind, whos, lanes, axes, spec) -> str:
    levels = [l for l in _SEVERITY_ORDER if any(p["level"] == l for p in problems)]
    levels += sorted({p["level"] or "Pending" for p in problems} - set(_SEVERITY_ORDER))
    filters = (
        '<div class="filters">'
        + _filter_chips("severity", levels, lambda v: _sev_pill(v))
        + _filter_chips("who", whos, _who_chip)
        + _filter_chips("lane", lanes, _lane_chip)
        + '<input type="search" class="search" placeholder="filter by title, site, class, id…" '
        'aria-label="filter problems">'
        '<span class="fsp"></span><span class="fine dim" id="shown"></span></div>'
    )
    head = (
        '<thead><tr>'
        '<th data-sort="rank" class="sorted">Severity</th>'
        f'<th data-sort="text">{"Problem" if kind == "find" else "Crash"}</th>'
        f'<th data-sort="axis">{_e(spec["axis"])}</th>'
        '<th data-sort="lanes">Lane</th>'
        + ('<th data-sort="who">Who</th>' if whos else '')
        + '<th data-sort="size" class="num">Reports</th>'
        '<th data-sort="t" class="num">First filed</th>'
        '<th data-sort="status">Status</th></tr></thead>'
    )
    rows = []
    for index, p in enumerate(problems):
        query = " ".join(x for x in (p["title"], p["site"], p["axis"], p["id"], p["canonical"],
                                    " ".join(m["id"] for m in p["members"]),
                                    " ".join(p["who"]), p["status"]) if x).lower()
        title = (f'<a class="ptitle" href="{_e(p["href"])}">{_e(p["title"])}</a>' if p["href"]
                 else f'<span class="ptitle">{_e(p["title"])}</span>')
        site = f'<span class="psite">{_e(p["site"])}</span>' if p["site"] else ""
        who_cell = "".join(_who_chip(w) for w in p["who"]) if whos else ""
        rows.append(
            f'<tr class="prow" data-rank="{p["rank"]}" data-severity="{_e(p["level"] or "Pending")}" '
            f'data-axis="{_e(p["axis"])}" data-lanes="{_e(" ".join(p["lanes"]))}" '
            f'data-lane="{_e(" ".join(p["lanes"]))}" data-who="{_e(" ".join(p["who"]))}" '
            f'data-size="{p["size"]}" data-t="{"" if p["first_at"] is None else p["first_at"]}" '
            f'data-status="{_e(p["status"])}" data-text="{_e(p["title"].lower())}" data-q="{_e(query)}" '
            f'data-id="{_e(p["id"])}">'
            f'<td>{_sev_pill(p["level"], p["score"])}</td>'
            f'<td class="c-prob">{title}{site}</td>'
            f'<td><span class="klass">{_e(p["axis"])}</span></td>'
            f'<td class="c-lanes">{"".join(_lane_chip(l) for l in p["lanes"]) or "<span class=dim>—</span>"}</td>'
            + (f'<td class="c-who">{who_cell}</td>' if whos else '')
            + f'<td class="num"><button type="button" class="more" aria-expanded="false" '
            f'aria-controls="m{index}">{p["size"]} report{"s" if p["size"] != 1 else ""}</button></td>'
            + _tcell(p["first_at"], p["first_h"]) +
            f'<td>{_status_chip(p["status"])}</td></tr>'
            f'<tr class="pmore" id="m{index}" hidden><td colspan="{8 if whos else 7}">{_members(p, kind, whos)}</td></tr>'
        )
    if not rows:
        rows.append('<tr><td colspan="8" class="empty">No reports have been accepted yet.</td></tr>')
    return (
        f'<section class="sec"><h2>The {"problems" if kind == "find" else "crashes"}</h2>'
        '<p class="pd">Sorted by severity, then by how many reports reached the same problem. '
        'Click a heading to sort, a title to open the canonical report, and the report count to '
        'see every member with who filed it and when.</p>'
        f'{filters}<div class="tablewrap"><table class="problems">{head}<tbody>{"".join(rows)}</tbody></table></div></section>'
    )


def _members(p: dict, kind: str, whos: list[str]) -> str:
    rows = []
    for m in p["members"]:
        link = f'<a href="{_e(m["href"])}">{_e(m["id"])}</a>' if m["href"] else _e(m["id"])
        canonical = ' <span class="fine dim">canonical</span>' if m["id"] == p["canonical"] else ""
        rows.append(
            f'<tr><td class="mono">{link}{canonical}</td><td>{_sev_pill(m["level"], m["score"])}</td>'
            + (f'<td>{_who_chip(m["who"])}</td>' if whos else "")
            + f'<td>{"".join(_lane_chip(l) for l in m["lanes"]) or "—"}</td>'
            + _tcell(m["filed_at"], m["filed_h"]) +
            f'<td>{_status_chip(m["status"])}</td></tr>'
        )
    identity = []
    if p["signature"]:
        identity.append(f'<div class="fine"><b>Signature</b> <span class="mono">{_e(p["signature"])}</span></div>')
    how = {"exact-match": "same class, file and line", "crash-state": "same crash state",
           "site": "same file and line"}.get(p["merged_via"], p["merged_via"])
    identity.append(f'<div class="fine"><b>Cluster</b> <span class="mono">{_e(p["id"])}</span>'
                    + (f' · merged on {_e(how)}' if how and p["size"] > 1 else "") + "</div>")
    if p["summary"]:
        identity.append(f'<p class="fine">{_e(p["summary"])}</p>')
    return (
        '<div class="members">' + "".join(identity)
        + f'<table class="mtable"><thead><tr><th>report</th><th>severity</th>'
        + ('<th>who</th>' if whos else '') + '<th>lane</th><th>filed</th><th>status</th></tr></thead>'
        f'<tbody>{"".join(rows)}</tbody></table></div>'
    )


def _cluster_guide(kind: str, spec: dict) -> str:
    if kind == "find":
        what = ("A finding is a written security claim: a class, a site, a data flow, and an impact, "
                "with or without a runnable reproducer. Two findings merge when they name the same bug "
                "class family at the same file and line, or the same crash state.")
    else:
        what = ("A crash is a sanitizer diagnostic reproduced through <code>bin/probe</code>. Two "
                "crashes merge when their normalized top frames match — the same rule ClusterFuzz "
                "uses — so different inputs into one bug count once.")
    return (
        '<details class="guide" id="guide"><summary>How to read this page</summary><div class="gbody">'
        f'<h3>What a row is</h3><p>{what} The canonical report is the strongest evidence in the '
        'cluster; other members are listed under the report count.</p>'
        '<h3>Severity</h3><p>The CVSS v4.0 score <code>bin/severity</code> computed from the '
        'primitive, the surface and how far the audit got toward proving the bug. '
        '<b>Pending</b> means the quality gate has not finished; <b>Needs review</b> means the class '
        'has no trustworthy CVSS mapping without a human; <b>Not a security report</b> is a real '
        'defect retained as engineering evidence that earns no security credit.</p>'
        '<h3>Status</h3><p><b>accepted</b> passed every gate; <b>pinned</b> was kept by a '
        'human marker and bypassed the gate; <b>needs content</b> / <b>needs attention</b> / '
        '<b>needs review</b> want a person; <b>pending</b> is an auto-filed skeleton the agent has not '
        'finished; <b>stale review</b> means the report changed after its review concluded.</p>'
        '<h3>Clock</h3><p>Each report carries the moment it was filed. The chart places every '
        'problem at its first report, on the run\'s own clock when the run start is known and '
        'otherwise from the first report. A problem with no clock is listed but not drawn.</p>'
        '<h3>Lanes</h3><p>' + " ".join(
            f'<b>{_e(k)}</b> {_e(v)}.' for k, v in strategies.NAMES.items() if k in strategies.ACTIVE)
        + '</p></div></details>'
    )


def write_cluster_page(kind: str, clusters: list[dict], root: Path, out_html: Path) -> Path | None:
    """Render the cluster index beside its Markdown and return the path.

    `CLUSTER_HTML=0` is the same opt-out the member-report renderer honours:
    with it set, no page is written, so an index never links reports that
    were never rendered.
    """
    if os.environ.get("CLUSTER_HTML") == "0":
        return None
    out_html = Path(out_html)
    page = render_cluster_page(kind, clusters, Path(root), out_html.parent)
    _atomic_write(out_html, page)
    return out_html


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(text, encoding="utf-8")
    os.replace(tmp, path)


# ── the rejected index ────────────────────────────────────────────────────

def _reason_family(reason: str) -> tuple[str, str]:
    """(family, detail) for a rejection reason.

    Triage prefixes machine reasons with their gate (`trigger-provenance: …`);
    a validator's free-form rationale has no prefix and is the reviewer's own
    sentence, so it files under `reviewer verdict`.
    """
    text = _INDEPENDENT_RE.sub("", str(reason or "")).strip()
    match = _REASON_FAMILY_RE.match(text)
    if match:
        return match.group(1), match.group(2).strip()
    if not text or text == "—":
        return "unrecorded", ""
    return "reviewer verdict", text


def _rejected_row(row: dict, kind: str, ctx: _Context, page_dir: Path) -> dict:
    directory = ctx.root / str(row.get("id") or "")
    facts = artifact_facts(directory, kind, stamps=ctx.stamps) if directory.is_dir() else None
    reason = str(row.get("reason") or (facts["rejection"] if facts else "") or "")
    family, detail = _reason_family(reason)
    return {
        "id": str(row.get("id") or directory.name),
        "title": (facts["title"] if facts else "") or str(row.get("title") or "") or directory.name,
        "site": (facts["site_text"] if facts else "") or str(row.get("site") or ""),
        "href": _href(facts["view"], page_dir, must_exist=False) if facts else "",
        "level": facts["severity"]["level"] if facts else "",
        "score": facts["severity"]["score"] if facts else None,
        "axis": (facts["class"] if kind == "find" else facts["primitive"]) if facts else "",
        "lanes": facts["lanes"] if facts else [],
        "who": ctx.who(directory.name),
        "filed_at": facts["filed_at"] if facts else None,
        "filed_h": ctx.hours(facts["filed_at"], [ctx.who(directory.name)]) if facts else None,
        "reason": reason,
        "family": family,
        "detail": detail,
        "gate": facts["gate"] if facts else {},
    }


def render_rejected_page(kind: str, rows: list[dict], rejected_dir: Path, page_dir: Path,
                         *, ledgers: list[tuple[str, str]] = (), discarded: list[dict] = (),
                         generated: str | None = None) -> str:
    """What did not hold up, grouped by why."""
    spec = _KIND[kind]
    ctx = _Context(rejected_dir, spec["rejected_sub"])
    items = [_rejected_row(r, kind, ctx, page_dir) for r in rows]
    families: dict[str, int] = {}
    for it in items:
        families[it["family"]] = families.get(it["family"], 0) + 1
    whos = sorted({it["who"] for it in items if it["who"]})
    whos = whos if len(whos) > 1 else []
    lanes = sorted({l for it in items for l in it["lanes"]}, key=lambda k: (k not in strategies.NAMES, k))
    points = [{
        "id": it["id"], "t_abs": it["filed_at"], "sev": _token(it["family"]), "title": it["title"],
        "site": it["site"], "href": it["href"], "who": [it["who"]] if it["who"] else [],
        "size": 1, "axis": it["family"], "color": f"--{_family_color(it['family'])}",
    } for it in items]
    timeline = _timeline_payload(points, ctx)
    accepted_href = _href(_sibling_index(rejected_dir, spec["sub"], spec["index"]), page_dir, must_exist=False)
    kick = " · ".join(x for x in ("TokenFuzz", spec["rejected_sub"], ctx.target,
                                  ctx.constant or ("both conditions" if ctx.owner else "")) if x)
    n = len(items)
    headline = f"{n} {spec['report']}{'s' if n != 1 else ''} did not hold up"
    if not n and not ledgers and not discarded:
        headline = f"Nothing was rejected"
    lede = _rejected_lede(kind, items, families, whos)
    tiles = [("rejected reports", str(n), "kept on disk, never counted")]
    for family, count in sorted(families.items(), key=lambda kv: -kv[1])[:4]:
        tiles.append((family, str(count), _family_gloss(family)))
    filters = (
        '<div class="filters">'
        + _filter_chips("why", sorted(families, key=lambda f: -families[f]), _family_chip)
        + _filter_chips("who", whos, _who_chip)
        + _filter_chips("lane", lanes, _lane_chip)
        + '<input type="search" class="search" placeholder="filter by title, site, reason…" aria-label="filter">'
        '<span class="fsp"></span><span class="fine dim" id="shown"></span></div>'
    )
    head = (
        '<thead><tr><th data-sort="text">Claimed</th><th data-sort="axis">'
        f'{_e(spec["axis"])}</th><th data-sort="rank">Claimed severity</th>'
        '<th data-sort="family" class="sorted">Why it was rejected</th>'
        + ('<th data-sort="who">Who</th>' if whos else '') + '<th data-sort="lanes">Lane</th>'
        '<th data-sort="t" class="num">Filed</th></tr></thead>'
    )
    body_rows = []
    for it in sorted(items, key=lambda x: (x["family"], -(x["score"] or 0), x["id"])):
        title = (f'<a class="ptitle" href="{_e(it["href"])}">{_e(it["title"])}</a>' if it["href"]
                 else f'<span class="ptitle">{_e(it["title"])}</span>')
        site = f'<span class="psite">{_e(it["site"])}</span>' if it["site"] else ""
        ident = f'<span class="psite mono">{_e(it["id"])}</span>'
        query = " ".join(x for x in (it["title"], it["site"], it["reason"], it["id"], it["axis"], it["who"]) if x).lower()
        why = _family_chip(it["family"]) + (f' <span class="why">{_e(it["detail"])}</span>' if it["detail"] else "")
        gate = it.get("gate") or {}
        if gate.get("rationale") and gate.get("rationale") != it["detail"]:
            why += f'<details class="fine why-more"><summary>reviewer\'s rationale</summary>{_e(gate["rationale"])}</details>'
        body_rows.append(
            f'<tr class="prow" data-family="{_e(it["family"])}" data-why="{_e(it["family"])}" '
            f'data-who="{_e(it["who"])}" data-lane="{_e(" ".join(it["lanes"]))}" data-lanes="{_e(" ".join(it["lanes"]))}" '
            f'data-rank="{_sev_rank(it["level"])}" data-axis="{_e(it["axis"])}" data-text="{_e(it["title"].lower())}" '
            f'data-t="{"" if it["filed_at"] is None else it["filed_at"]}" data-q="{_e(query)}">'
            f'<td class="c-prob">{title}{site}{ident}</td><td><span class="klass">{_e(it["axis"] or "—")}</span></td>'
            f'<td>{_sev_pill(it["level"], it["score"]) if it["level"] else "<span class=dim>unscored</span>"}</td>'
            f'<td class="c-why">{why}</td>'
            + (f'<td>{_who_chip(it["who"])}</td>' if whos else '')
            + f'<td class="c-lanes">{"".join(_lane_chip(l) for l in it["lanes"]) or "<span class=dim>—</span>"}</td>'
            + _tcell(it["filed_at"], it["filed_h"]) + "</tr>"
        )
    if not body_rows:
        body_rows.append(f'<tr><td colspan="7" class="empty">No {spec["report"]}s were rejected.</td></tr>')
    sections = [
        _hero(kick, headline, lede, generated, [
            (accepted_href, "what was accepted") if accepted_href else None,
            ("#guide", "how to read this page"),
        ]),
        _tiles(tiles),
        _family_bars(families),
    ]
    if items:
        sections.append(
            '<section class="sec"><h2>When the rejected reports were filed</h2>'
            '<p class="pd">Rejections on the same clock as the accepted problems, coloured by why '
            'they fell. Over-claiming that clusters late in a run says something different from '
            'a false start in the first hour.</p>'
            f'<div class="chart timeline" id="timeline"></div>{_family_legend(families, whos, timeline)}</section>'
        )
    sections.append(
        f'<section class="sec"><h2>The rejected {spec["report"]}s</h2>'
        '<p class="pd">Every report triage turned away, with the reason it recorded. The report '
        'itself is kept and linked so the claim can be re-examined; nothing here earns credit.</p>'
        f'{filters}<div class="tablewrap"><table class="problems rejected">{head}<tbody>{"".join(body_rows)}</tbody></table></div></section>'
    )
    if ledgers:
        sections.append('<section class="sec"><h2>Per-cell rejection ledgers</h2><p class="pd">'
                        'Signatures triage rejected before they became a directory: the row is all '
                        'that exists for them.</p>' + "".join(
                            f'<h3 class="mono">{_e(name)}</h3>{_md_table_html(text)}' for name, text in ledgers)
                        + '</section>')
    if discarded:
        sections.append('<section class="sec"><h2>Discarded hypotheses</h2><p class="pd">Leads the '
                        'agents investigated and closed themselves, before triage saw them — the '
                        'ideas that did not pay off, in their own words.</p><div class="tablewrap">'
                        '<table><thead><tr><th>cell</th><th class="num">discarded</th><th>roster</th></tr></thead><tbody>'
                        + "".join(
                            f'<tr><td class="mono">{_e(d["cell"])}</td><td class="num">{d["count"]}</td>'
                            f'<td><a href="{_e(d["href"])}">{_e(d["name"])}</a></td></tr>' for d in discarded)
                        + '</tbody></table></div></section>')
    sections.append(_rejected_guide(spec))
    payload = {"timeline": timeline, "kind": kind}
    return _document(spec["rejected_index"], "".join(sections), payload, page_class="index")


_FAMILY_COLORS = {"trigger-provenance": "S7", "threat-model": "S2", "unsettled-scope": "S5",
                  "reviewer verdict": "S3", "quality": "S4", "substance": "S4",
                  "duplicate": "none", "unrecorded": "none"}


def _family_color(family: str) -> str:
    for key, color in _FAMILY_COLORS.items():
        if family.startswith(key):
            return color
    return "S1"


def _family_chip(family: str) -> str:
    return f'<span class="fam fam-{_family_color(family)}">{_e(family)}</span>'


def _family_gloss(family: str) -> str:
    return {
        "trigger-provenance": "the claimed trigger is not attacker-reachable or the consequence is disproved",
        "threat-model": "a real defect whose trigger sits outside the declared attacker controls",
        "unsettled-scope": "no review could place the trigger inside the threat model once every review had answered",
        "reviewer verdict": "an independent reviewer read the report and rejected the claim",
        "unrecorded": "rejected without a recorded reason",
    }.get(family, "gate that turned the report away")


def _family_bars(families: dict[str, int]) -> str:
    if not families:
        return ""
    total = sum(families.values())
    segs = "".join(
        f'<span class="seg fam-{_family_color(f)}" style="flex:{n}" title="{_e(f)}: {n}"></span>'
        for f, n in sorted(families.items(), key=lambda kv: -kv[1])
    )
    keys = "".join(f'<span class="k">{_family_chip(f)} {n} · {n / total:.0%}</span>'
                   for f, n in sorted(families.items(), key=lambda kv: -kv[1]))
    return f'<div class="sevbar"><div class="bar">{segs}</div><div class="legend">{keys}</div></div>'


def _family_legend(families, whos, timeline) -> str:
    keys = [f'<span class="k"><i class="sw {_who_class(w)}"></i>{_e(w)}</span>' for w in whos]
    if len(whos) > 1:
        keys.append('<span class="k"><i class="sw sw-total"></i>all</span>')
    keys += [f'<span class="k"><b class="dot demo fam-{_family_color(f)}"></b>{_e(f)}</span>' for f in families]
    note = ""
    if timeline["per_condition"]:
        note = "t = 0 is each condition's own run start"
    elif timeline["origin"]:
        note = ("t = 0 is the run start, " if timeline["origin_is_run_start"] else "t = 0 is the first report, ") + timeline["origin"]
    return '<div class="legend">' + "".join(keys) + "</div>" + (f'<p class="fine dim">{_e(note)}.</p>' if note else "")


def _rejected_lede(kind, items, families, whos) -> str:
    spec = _KIND[kind]
    if not items:
        return (f"Every {spec['report']} that triage saw was accepted, or nothing reached triage. "
                f"An empty page is still a claim about the run: read it beside the accepted index.")
    top = max(families.items(), key=lambda kv: kv[1])
    parts = [
        f"Rejections are as much a description of a model as its yield: the same over-claiming a raw "
        f"tally would reward shows up here as a reason.",
        f"The most common was <b>{_e(top[0])}</b> ({top[1]} of {len(items)}): {_e(_family_gloss(top[0]))}.",
    ]
    if len(whos) > 1:
        parts.append(f"Reports come from {_e(', '.join(whos))}; the who column and the filters split them.")
    parts.append("Nothing is deleted — every report is kept and linked so a rejection can itself be reviewed.")
    return " ".join(parts)


def _rejected_guide(spec: dict) -> str:
    return (
        '<details class="guide" id="guide"><summary>How to read this page</summary><div class="gbody">'
        '<h3>Where a rejection comes from</h3><p><b>trigger-provenance</b> is the source-anchored '
        'review that checks whether the claimed trigger is reachable from a public boundary and '
        'whether the claimed consequence survives reading the code; its detail names which of the '
        'two failed. A <b>reviewer verdict</b> is an independent model\'s rationale when it voted '
        'to reject after the quality gate. A quality-gate reason is recorded when nothing else is.</p>'
        '<h3>Claimed severity</h3><p>The score the report carried before rejection, when it was '
        'scored at all. It is shown so an ambitious wrong claim can be told from a modest one; it '
        'earns nothing.</p>'
        '<h3>Ledgers and hypotheses</h3><p>Per-cell ledgers list signatures rejected before they '
        'became a directory. Discarded hypotheses are the agents\' own closed leads, kept because '
        'what a model tried and abandoned is part of how it reasons.</p></div></details>'
    )


def _md_table_html(text: str) -> str:
    """A Markdown ledger's tables and prose as HTML, without the full renderer."""
    out: list[str] = []
    rows: list[list[str]] = []

    def flush() -> None:
        if not rows:
            return
        head, *body = rows
        out.append('<div class="tablewrap"><table><thead><tr>' + "".join(
            f'<th>{_e(c)}</th>' for c in head) + '</tr></thead><tbody>' + "".join(
            '<tr>' + "".join(f'<td>{_inline(c)}</td>' for c in r) + '</tr>' for r in body)
            + '</tbody></table></div>')
        rows.clear()

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if all(set(c) <= set(":- ") for c in cells):
                continue
            rows.append(cells)
            continue
        flush()
        if stripped.startswith("#"):
            out.append(f'<h4>{_e(stripped.lstrip("#").strip())}</h4>')
        elif stripped:
            out.append(f'<p class="fine">{_inline(stripped)}</p>')
    flush()
    return "".join(out)


def _inline(text: str) -> str:
    escaped = _e(text)
    escaped = re.sub(r"`([^`]+)`", r'<code>\1</code>', escaped)
    escaped = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", escaped)
    escaped = re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)",
                     lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>' if not re.match(r"^[a-z]+:", m.group(2), re.I) or m.group(2).lower().startswith(("http:", "https:")) else m.group(1),
                     escaped)
    return escaped


def write_rejected_page(kind: str, rows: list[dict], rejected_dir: Path, *,
                        ledgers: list[tuple[str, str]] = (), discarded: list[dict] = ()) -> Path | None:
    """Render the rejected index beside its Markdown and return the path.

    `INDEX_HTML_AUTO=0` is the opt-out index maintenance honours for report
    rendering; with it set the index stays Markdown-only for the same reason.
    """
    if os.environ.get("INDEX_HTML_AUTO") == "0":
        return None
    rejected_dir = Path(rejected_dir)
    out_html = rejected_dir / f"{_KIND[kind]['rejected_index']}.html"
    page = render_rejected_page(kind, rows, rejected_dir, rejected_dir,
                                ledgers=ledgers, discarded=discarded)
    _atomic_write(out_html, page)
    return out_html


# ── the report shell ──────────────────────────────────────────────────────

def report_context(directory: Path | None) -> dict | None:
    """Facts for the report shell, or None when the file is not an artifact report."""
    if directory is None:
        return None
    directory = Path(directory)
    name = directory.name
    if name.startswith("CRASH-"):
        kind = "crash"
    elif name.startswith("FIND-"):
        kind = "find"
    else:
        return None
    if report_identity.find_report(directory) is None:
        return None
    sub = _KIND[kind]["rejected_sub" if "-rejected" in directory.parent.name else "sub"]
    ctx = _Context(directory.parent, sub)
    facts = artifact_facts(directory, kind, stamps=ctx.stamps)
    facts["who"] = ctx.who(name)
    facts["run_origin"] = ctx.origin_for([facts["who"]])
    facts["target"] = ctx.target
    index_name = _KIND[kind]["rejected_index" if "-rejected" in directory.parent.name else "index"]
    index = None
    if any((directory.parent / f"{index_name}{suffix}").is_file() for suffix in (".html", ".md")):
        index = directory.parent / f"{index_name}.html"
    facts["index_href"] = _href(index, directory, must_exist=False)
    facts["index_label"] = ("all rejected " if "-rejected" in directory.parent.name else "all ") + _KIND[kind]["sub"]
    return facts


def _sibling_links(facts: dict) -> list[tuple[str, str]]:
    out = []
    own = facts["view"].name if facts.get("view") else "report.html"
    for sid in _SIBLING_RE.findall(facts.get("cluster") or ""):
        if sid == facts["id"]:
            continue
        target = facts["dir"].parent / sid
        view = _report_view(report_identity.find_report(target)) if target.is_dir() else None
        href = _href(view, facts["dir"], must_exist=False) if view else f"../{sid}/{own}"
        out.append((sid, href))
    return out


def action_card(facts: dict) -> str:
    """What to do about this report, for a maintainer who has thirty seconds."""
    if not facts:
        return ""
    site = facts["site"]
    by_role = facts["by_role"]
    items: list[str] = []
    # fix
    patch = by_role.get("patch", [])
    if patch:
        href = _href(patch[0]["path"], facts["dir"])
        fix = (f'<a href="{_e(href)}">patch.diff</a> is captured beside this report'
               + (f' — {_e(facts["fix"])}' if facts["fix"] else "") + ".")
    elif facts["fix"]:
        fix = _e(facts["fix"])
    else:
        fix = '<span class="dim">no fix direction recorded; the Root Cause section names the invariant to restore.</span>'
    items.append(f'<div class="act"><div class="al">Fix</div><div class="av">{fix}</div></div>')
    # where
    if facts["site_text"]:
        where = f'<span class="mono">{_e(facts["site_text"])}</span>'
        if facts["upstream"]:
            where += f' <a class="fine" href="{_e(facts["upstream"])}">view upstream ↗</a>'
        if facts.get("surface"):
            where += f' <span class="fine dim">· reached through the {_e(facts["surface"])} surface</span>'
        items.append(f'<div class="act"><div class="al">Where</div><div class="av">{where}</div></div>')
    # reproduce
    repro: list[str] = []
    if by_role.get("reproduce"):
        href = _href(by_role["reproduce"][0]["path"], facts["dir"])
        repro.append(f'run <a href="{_e(href)}"><code>./reproduce.sh</code></a> — it clones the audited '
                     f'revision, builds with the sanitizer and replays the input')
    for role, word in (("testcase", "input"), ("harness", "harness"), ("sanitizer", "sanitizer log")):
        for item in by_role.get(role, [])[:2]:
            href = _href(item["path"], facts["dir"])
            repro.append(f'{word} <a href="{_e(href)}"><code>{_e(item["name"])}</code></a> ({_size(item["size"])})')
    if facts["repro_rate"]:
        repro.append(f'reproduced {_e(facts["repro_rate"])} times when re-run')
    if not repro:
        repro.append('<span class="dim">no runnable reproducer — verify by reading the Data Flow against the source</span>')
    items.append(f'<div class="act"><div class="al">Reproduce</div><div class="av">{"; ".join(repro)}.</div></div>')
    # confidence
    conf: list[str] = []
    v = facts["validation"]
    if facts["status"] == "rejected":
        conf.append(f'<b>rejected</b> — {_e(facts["rejection"] or v["detail"])}')
    elif facts["status"] == "not-reportable":
        conf.append("<b>retained without security credit</b> — a real defect, not a security boundary")
    elif v["state"]:
        conf.append(f'<b>{_e(v["state"])}</b>' + (f' — {_e(v["detail"])}' if v["detail"] else ""))
    else:
        conf.append("<b>not yet reviewed</b>")
    votes = facts["votes"]
    if votes["accept"] or votes["reject"]:
        conf.append(f'{votes["accept"]} accept / {votes["reject"]} reject from independent reviewers')
    if facts["gate"]["vote"]:
        conf.append(f'source-anchored trigger review voted <b>{_e(facts["gate"]["vote"])}</b>'
                    + (f' on {facts["gate"]["anchors"]} verified source anchors' if facts["gate"]["anchors"] else ""))
    items.append(f'<div class="act"><div class="al">Confidence</div><div class="av">{"; ".join(conf)}.</div></div>')
    # affects
    fields = facts["fields"]
    affects = []
    if fields.get("boundary"):
        affects.append(f'<b>boundary</b> {_e(fields["boundary"])}')
    if fields.get("caller controls"):
        affects.append(f'<b>attacker controls</b> {_e(fields["caller controls"])}')
    if fields.get("trusted caller actions"):
        affects.append(f'<b>needs the caller to</b> {_e(fields["trusted caller actions"])}')
    if affects:
        items.append(f'<div class="act"><div class="al">Affects</div><div class="av">{"; ".join(affects)}.</div></div>')
    return '<section class="action"><div class="at">Act on it</div>' + "".join(items) + "</section>"


def _size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.0f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


def _band(facts: dict) -> str:
    crumbs = []
    if facts.get("index_href"):
        crumbs.append(f'<a href="{_e(facts["index_href"])}">← {_e(facts["index_label"])}</a>')
    crumbs.append(f'<span class="mono">{_e(facts["id"])}</span>')
    if facts.get("target"):
        crumbs.append(_e(facts["target"]))
    if facts.get("who"):
        crumbs.append(_who_chip(facts["who"]))
    for lane in facts["lanes"]:
        crumbs.append(_lane_chip(lane))
    crumbs.append(_status_chip({
        "accepted": "OK", "rejected": "rejected", "not-reportable": "NOT-REPORTABLE",
        "pending": "PENDING",
    }.get(facts["status"], facts["status"])))
    if facts["filed_at"]:
        crumbs.append(f'<span class="fine dim">filed {_e(_when(facts["filed_at"]))}</span>')
    banner = ""
    if facts["status"] == "rejected":
        reason = (facts["rejection"] or facts["validation"]["detail"]).rstrip()
        if reason and reason[-1] not in ".!?":
            reason += "."
        banner = (f'<p class="banner reject"><b>Rejected by triage.</b> {_e(reason)} '
                  'The evidence is kept for review and earns no credit.</p>')
    elif facts["status"] == "not-reportable":
        banner = '<p class="banner"><b>Retained without security credit.</b> A real defect worth fixing, but not a security boundary.</p>'
    elif facts["status"] == "pending":
        banner = '<p class="banner"><b>Not yet reviewed.</b> Severity and validation can still change.</p>'
    return f'<div class="band">{" · ".join(crumbs)}</div>{banner}'


def _cvss_rail(facts: dict) -> str:
    sev = facts["severity"]
    if not sev["level"]:
        return ""
    vector = sev["vector"]
    parts = []
    metrics = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p) if vector.startswith("CVSS:4.0/") else {}
    for group, keys in _CVSS_GROUPS:
        chips = []
        for key in keys:
            if key not in metrics:
                continue
            name, words = _CVSS_METRICS[key]
            word = words.get(metrics[key], metrics[key])
            weight = "hi" if metrics[key] in ("H", "N") and key in ("AV", "PR", "UI", "AT", "VC", "VI", "VA") else ""
            if key in ("VC", "VI", "VA", "SC", "SI", "SA"):
                weight = {"H": "hi", "L": "mid", "N": ""}[metrics[key]] if metrics[key] in "HLN" else ""
            chips.append(f'<span class="cv {weight}" title="{_e(name)}: {_e(word)}">{_e(key)}<b>{_e(metrics[key])}</b></span>')
        if chips:
            parts.append(f'<div class="cvg"><span class="cvl">{group}</span>{"".join(chips)}</div>')
    env = [k for k in metrics if k.startswith("M")]
    if env:
        parts.append(f'<p class="fine dim">environmental: {_e(", ".join(f"{k}:{metrics[k]}" for k in env))}</p>')
    score = f'<span class="big">{sev["score"]:g}</span>' if sev["score"] else ""
    return (
        f'<div class="rs"><h4>Severity</h4><div class="cvhead">{_sev_pill(sev["level"])}{score}'
        f'<span class="fine dim">CVSS v4.0</span></div>{"".join(parts)}'
        + (f'<p class="fine dim">scored {_e(_when(sev["scored_at"]))}</p>' if sev["scored_at"] else "")
        + '</div>'
    )


def _review_rail(facts: dict) -> str:
    v = facts["validation"]
    rows = []
    if v["state"]:
        rows.append(f'<div><b>{_e(v["state"])}</b>' + (f' <span class="fine">{_e(v["detail"])}</span>' if v["detail"] else "") + "</div>")
    if facts["votes"]["accept"] or facts["votes"]["reject"]:
        rows.append(f'<div>quality gate: {facts["votes"]["accept"]} accept, {facts["votes"]["reject"]} reject'
                    + (f' <span class="fine dim">{_e(facts["votes"]["reason"])}</span>' if facts["votes"]["reason"] else "") + "</div>")
    g = facts["gate"]
    if g["vote"]:
        rows.append(f'<div>trigger review: <b>{_e(g["vote"])}</b>' + (f' on {g["anchors"]} source anchors' if g["anchors"] else "") + "</div>")
        if g["trigger_path"]:
            rows.append(f'<div class="fine dim">{_e(g["trigger_path"])}</div>')
    if facts["attestations"]:
        rows.append(f'<div class="fine">{facts["attestations"]} source attestation{"s" if facts["attestations"] != 1 else ""} bound to the receipt</div>')
    if not rows:
        return ""
    return '<div class="rs"><h4>Review</h4>' + "".join(rows) + "</div>"


def _bundle_rail(facts: dict) -> str:
    items = [b for b in facts["bundle"] if b["role"] != "report"]
    if not items:
        return ""
    rows = "".join(
        f'<li><a href="{_e(_href(b["path"], facts["dir"]))}"><code>{_e(b["name"])}</code></a>'
        f' <span class="fine dim">{_e(b["role"])} · {_size(b["size"])}</span></li>' for b in items
    )
    return f'<div class="rs"><h4>Bundle</h4><ul class="files">{rows}</ul></div>'


def _timeline_rail(facts: dict) -> str:
    events = []
    if facts["filed_at"]:
        events.append(("filed", facts["filed_at"]))
    if facts["severity"]["scored_at"]:
        events.append(("scored", facts["severity"]["scored_at"]))
    if facts["validated_at"]:
        events.append(("reviewed", facts["validated_at"]))
    if not events:
        return ""
    origin = facts.get("run_origin")
    rows = "".join(
        f'<li><b>{label}</b> {_e(_when(when))}'
        + (f' <span class="fine dim">{_fmt_h(_rel_hours(when, origin))} into the run</span>' if origin and label == "filed" else "")
        + "</li>" for label, when in sorted(events, key=lambda e: e[1])
    )
    return f'<div class="rs"><h4>Timeline</h4><ul class="files">{rows}</ul></div>'


def _outline(body: str) -> str:
    items = []
    for level, slug, text in _HEADING_RE.findall(body):
        label = _TAG_RE.sub("", text).strip()
        if label:
            items.append(f'<li class="l{level}"><a href="#{_e(slug)}">{_e(label)}</a></li>')
    if not items:
        return ""
    return '<div class="rs"><h4>On this page</h4><ul class="outline">' + "".join(items) + "</ul></div>"


def _siblings_rail(facts: dict) -> str:
    links = _sibling_links(facts)
    if not links and not facts.get("cluster"):
        return ""
    cluster = facts["cluster"].split(" ", 1)[0]
    rows = "".join(f'<li><a href="{_e(href)}" class="mono">{_e(sid)}</a></li>' for sid, href in links)
    note = f'<div class="fine">cluster <span class="mono">{_e(cluster)}</span>' + (
        f' · {len(links)} sibling report{"s" if len(links) != 1 else ""} of the same problem' if links else " · singleton") + "</div>"
    return f'<div class="rs"><h4>Same problem</h4>{note}<ul class="files">{rows}</ul></div>'


def report_document(title: str, body: str, facts: dict | None) -> str:
    """The full HTML document for one rendered report."""
    if facts is None:
        return _document(title, f'<article class="doc">{body}</article>', None, page_class="report plain")
    rail = "".join((
        _outline(body), _cvss_rail(facts), _siblings_rail(facts), _review_rail(facts),
        _timeline_rail(facts), _bundle_rail(facts),
    ))
    inner = f'<article class="doc">{_band(facts)}{body}</article><aside class="rail">{rail}</aside>'
    return _document(title, inner, None, page_class="report")


# ── document chrome ───────────────────────────────────────────────────────

def _document(title: str, inner: str, payload: dict | None, *, page_class: str) -> str:
    data = ""
    script = ""
    if payload is not None:
        encoded = json.dumps(payload, separators=(",", ":")).replace("<", "\\u003c")
        data = f'<script type="application/json" id="page-data">{encoded}</script>\n'
        script = "<script>" + _JS + "</script>\n"
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        f"<title>{_e(title)}</title>\n<style>{_CSS}</style>\n</head>\n<body>\n"
        f'<main class="page {page_class}">{inner}</main>\n'
        '<div class="tip" id="tip" role="tooltip"></div>\n'
        f"{data}{script}</body>\n</html>\n"
    )


# The shared palette is the benchmark page's (backend hues validated for both
# surfaces; severity on the reserved status steps), so a reader moving from
# the ledger into a cluster and a report keeps one colour vocabulary.
_CSS = r"""
:root{color-scheme:light;
 --bg:#f9f9f7;--surf:#fcfcfb;--surf2:#f1f1ee;--ink:#0b0b0b;--ink2:#52514e;--muted:#898781;
 --grid:#e1e0d9;--axis:#c3c2b7;--ring:rgba(11,11,11,.10);--link:#1c5cab;
 --codex:#2a78d6;--claude:#eb6834;--gemini:#4a3aa7;--grok:#1baf7a;--oss:#eda100;--opencode:#e87ba4;
 --other:#898781;--harness:#0b0b0b;--direct:#898781;
 --crit:#d03b3b;--high:#ec835a;--med:#fab219;--low:#86b6ef;--none:#c3c2b7;--good:#0ca30c;
 --S1:#2a78d6;--S2:#eb6834;--S3:#1baf7a;--S4:#eda100;--S5:#e87ba4;--S6:#008300;--S7:#4a3aa7;--S8:#e34948;
 --da:#dcfce7;--da-ink:#166534;--dr:#fee2e2;--dr-ink:#991b1b;--dx:#dbeafe;--dx-ink:#1e3a8a;
 --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
 --sans:system-ui,-apple-system,"Segoe UI",sans-serif}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){color-scheme:dark;
 --bg:#0d0d0d;--surf:#1a1a19;--surf2:#232321;--ink:#fff;--ink2:#c3c2b7;--muted:#898781;
 --grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);--link:#86b6ef;
 --codex:#3987e5;--claude:#d95926;--gemini:#9085e9;--grok:#199e70;--oss:#c98500;--opencode:#d55181;
 --harness:#fff;--direct:#898781;--low:#5598e7;--none:#55554f;
 --S1:#3987e5;--S2:#d95926;--S3:#199e70;--S4:#c98500;--S5:#d55181;--S6:#008300;--S7:#9085e9;--S8:#e66767;
 --da:#14361f;--da-ink:#86efac;--dr:#3f1414;--dr-ink:#fca5a5;--dx:#172554;--dx-ink:#93c5fd}}
:root[data-theme="dark"]{color-scheme:dark;
 --bg:#0d0d0d;--surf:#1a1a19;--surf2:#232321;--ink:#fff;--ink2:#c3c2b7;--muted:#898781;
 --grid:#2c2c2a;--axis:#383835;--ring:rgba(255,255,255,.10);--link:#86b6ef;
 --codex:#3987e5;--claude:#d95926;--gemini:#9085e9;--grok:#199e70;--oss:#c98500;--opencode:#d55181;
 --harness:#fff;--direct:#898781;--low:#5598e7;--none:#55554f;
 --S1:#3987e5;--S2:#d95926;--S3:#199e70;--S4:#c98500;--S5:#d55181;--S6:#008300;--S7:#9085e9;--S8:#e66767;
 --da:#14361f;--da-ink:#86efac;--dr:#3f1414;--dr-ink:#fca5a5;--dx:#172554;--dx-ink:#93c5fd}
*{box-sizing:border-box}
html{background:var(--bg);overflow-x:hidden}
body{margin:0;font:15px/1.55 var(--sans);color:var(--ink);background:var(--bg);overflow-x:hidden}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline}
.page{max-width:1400px;margin:0 auto;padding:28px 22px 60px}
.mono{font-family:var(--mono);font-size:.9em}.dim{color:var(--muted)}.fine{font-size:.8em}.num{text-align:right;font-variant-numeric:tabular-nums}
.hero{padding:6px 0 18px}
.kick{font-size:.72em;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:var(--ink2);margin:0 0 8px}
.hero h1{font-size:2.1em;line-height:1.15;margin:0 0 12px;letter-spacing:-.01em}
.lede{font-size:1.08em;color:var(--ink2);max-width:66em;margin:0 0 10px}
.meta{font-size:.86em;color:var(--muted);margin:0}
.banner{background:var(--surf2);border-left:3px solid var(--med);padding:10px 14px;border-radius:8px;margin:14px 0;color:var(--ink2)}
.banner.reject{border-left-color:var(--crit)}
.sec{margin:26px 0 0}.sec>h2,.sec>div>h2{font-size:1.25em;margin:0 0 8px;letter-spacing:-.005em}
.sec.two{display:grid;grid-template-columns:1fr 1fr;gap:26px}
.pd{color:var(--ink2);font-size:.92em;margin:0 0 12px;max-width:74em}
.empty{color:var(--muted);font-style:italic}
.tiles{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:8px;margin:6px 0 14px}
.tile{background:var(--surf2);border-radius:10px;padding:8px 10px;min-width:0}
.tl{font-size:.74em;color:var(--ink2);text-transform:uppercase;letter-spacing:.05em}
.tv{font-size:1.35em;font-weight:700;margin-top:2px;line-height:1.2}.tn{font-size:.74em;color:var(--muted);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sevbar .bar{display:flex;height:14px;border-radius:5px;overflow:hidden;background:var(--surf2);gap:2px}
.sevbar .seg{display:block;height:100%;background:var(--none)}
.legend{display:flex;flex-wrap:wrap;gap:6px 16px;font-size:.82em;color:var(--ink2);margin:6px 0 2px;align-items:center}
.legend .k{display:inline-flex;align-items:center;gap:6px}
.sw{display:inline-block;width:14px;height:0;border-top:2.5px solid var(--other)}
.sw-total{border-top-color:var(--ink);border-top-style:dashed}
.who-harness{--c:var(--harness)}.who-model-direct{--c:var(--direct)}.who-codex{--c:var(--codex)}.who-claude{--c:var(--claude)}
.who-gemini{--c:var(--gemini)}.who-grok{--c:var(--grok)}.who-oss{--c:var(--oss)}.who-opencode{--c:var(--opencode)}.who-other{--c:var(--other)}
.sw.who-harness,.sw.who-model-direct,.sw.who-codex,.sw.who-claude,.sw.who-gemini,.sw.who-grok,.sw.who-oss,.sw.who-opencode,.sw.who-other{border-top-color:var(--c)}
.who{display:inline-block;font-size:.74em;font-weight:700;padding:1px 8px;border-radius:999px;color:#fff;background:var(--c,var(--other));white-space:nowrap;vertical-align:middle;margin-right:3px}
.who.who-harness{color:var(--bg)}
.sev,.dot,.seg,.ff{--s:var(--none)}
.sev-critical,.sev-Critical{--s:var(--crit)}.sev-high,.sev-High{--s:var(--high)}.sev-medium,.sev-Medium{--s:var(--med)}.sev-low,.sev-Low{--s:var(--low)}
.sev{display:inline-block;font-size:.78em;font-weight:700;padding:1px 8px;border-radius:999px;color:#fff;background:var(--s);white-space:nowrap;line-height:1.5;letter-spacing:.02em;text-transform:uppercase}
.sev.sev-medium,.sev.sev-Medium,.sev.sev-low,.sev.sev-Low{color:#0b0b0b}
.sev.sev-none,.sev.sev-None,.sev.sev-pending,.sev.sev-Pending,.sev.sev-unknown,.sev.sev-Unknown,.sev.sev-needs-review,.sev.sev-Needs-review,.sev.sev-not-a-security-report{background:var(--none);color:var(--ink2);text-transform:none;font-weight:600}
.sev .score,.sev .sev-score{font-weight:500;opacity:.9;margin-left:5px}
.seg.sev-critical,.seg.sev-high,.seg.sev-medium,.seg.sev-low,.ff.sev-critical,.ff.sev-high,.ff.sev-medium,.ff.sev-low{background:var(--s)}
.dot{display:inline-block;width:12px;height:12px;border-radius:50%;background:var(--s);border:2px solid var(--surf);box-shadow:0 0 0 1px var(--ring);vertical-align:middle}
.fam-S1{--f:var(--S1)}.fam-S2{--f:var(--S2)}.fam-S3{--f:var(--S3)}.fam-S4{--f:var(--S4)}.fam-S5{--f:var(--S5)}.fam-S7{--f:var(--S7)}.fam-none{--f:var(--none)}
.fam{display:inline-block;font-size:.76em;font-weight:700;padding:1px 8px;border-radius:6px;color:#fff;background:var(--f,var(--other));white-space:nowrap}
.fam-S4{color:#3a2a00}.seg.fam-S1,.seg.fam-S2,.seg.fam-S3,.seg.fam-S4,.seg.fam-S5,.seg.fam-S7,.seg.fam-none,.dot.fam-S1,.dot.fam-S2,.dot.fam-S3,.dot.fam-S4,.dot.fam-S5,.dot.fam-S7,.dot.fam-none{background:var(--f)}
.why{font-size:.92em}.why-more{margin-top:3px;color:var(--ink2)}.why-more summary{cursor:pointer;color:var(--muted)}
.lane{display:inline-block;font-family:var(--mono);font-size:.78em;font-weight:700;padding:0 6px;border-radius:5px;color:#fff;background:var(--other);margin-right:3px;vertical-align:middle}
.lane-S1{background:var(--S1)}.lane-S2{background:var(--S2)}.lane-S3{background:var(--S3)}.lane-S4{background:var(--S4);color:#3a2a00}
.lane-S5{background:var(--S5)}.lane-S6{background:var(--S6)}.lane-S7{background:var(--S7)}.lane-S8{background:var(--S8)}
.st{display:inline-block;font-size:.76em;font-weight:600;padding:1px 8px;border-radius:6px;background:var(--surf2);color:var(--ink2);border:1px solid var(--grid);white-space:nowrap}
.st-ok{color:var(--good);border-color:var(--good)}.st-rejected{color:var(--crit);border-color:var(--crit)}
.st-pending,.st-needs,.st-stale{color:#8a5a00;border-color:var(--med)}.st-not-reportable{color:var(--muted)}
.klass{font-family:var(--mono);font-size:.86em}
.chart{margin-top:6px}.chart svg{display:block;width:100%;height:auto;overflow:visible;font:inherit}
.chart svg .pt{cursor:pointer}.chart svg .pt:hover{stroke:var(--ink);stroke-width:2}
.funnel .fr{display:grid;grid-template-columns:150px 1fr 36px;align-items:center;gap:8px;font-size:.84em;margin:4px 0}
.funnel .fl{color:var(--ink2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.fb{display:flex;height:12px;background:var(--surf2);border-radius:4px;overflow:hidden;gap:1px}
.ff{display:block;height:100%}.fv{text-align:right;font-variant-numeric:tabular-nums}
.tablewrap{overflow-x:auto;background:var(--surf);border:1px solid var(--ring);border-radius:12px}
.index table{border-collapse:collapse;width:100%;font-size:.88em}
.index th,.index td{padding:7px 9px;text-align:left;vertical-align:top;border-bottom:1px solid var(--grid)}
.index th{font-size:.76em;text-transform:uppercase;letter-spacing:.05em;color:var(--ink2);background:var(--surf2);position:sticky;top:0;white-space:nowrap}
.index th[data-sort]{cursor:pointer;user-select:none}.index th[data-sort]:hover{color:var(--ink)}.index th.sorted::after{content:" ▾";color:var(--muted)}.index th.sorted.asc::after{content:" ▴"}
.index tbody tr:hover{background:var(--surf2)}.index tr[hidden]{display:none}
.heat td.hm{background:rgba(42,120,214,var(--a,0))}:root[data-theme="dark"] .heat td.hm{background:rgba(57,135,229,var(--a,0))}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]) .heat td.hm{background:rgba(57,135,229,var(--a,0))}}
.heat th,.heat td{white-space:nowrap}
.filters{display:flex;align-items:center;gap:6px;flex-wrap:wrap;position:sticky;top:0;z-index:5;background:var(--bg);padding:10px 0;border-bottom:1px solid var(--grid);margin:8px 0 10px}
.filters .fl{font-size:.74em;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin:0 2px 0 6px}
.filters .gap{width:8px}.filters .fsp{flex:1}
.chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--grid);background:var(--surf);color:var(--ink);border-radius:999px;padding:3px 9px 3px 6px;font:inherit;font-size:.84em;cursor:pointer}
.chip:not(.on){opacity:.4}.chip .sev,.chip .who,.chip .lane,.chip .fam{margin:0}
.search{font:inherit;font-size:.86em;padding:5px 10px;border:1px solid var(--grid);border-radius:8px;background:var(--surf);color:var(--ink);min-width:220px}
.c-prob{min-width:260px;max-width:520px}.ptitle{display:block;font-weight:600}.psite{display:block;font-family:var(--mono);font-size:.78em;color:var(--muted);overflow-wrap:anywhere}
.c-lanes,.c-who{white-space:nowrap}.c-why{min-width:240px}
.more{font:inherit;font-size:.9em;border:1px solid var(--grid);background:var(--surf);color:var(--link);border-radius:6px;padding:2px 8px;cursor:pointer;white-space:nowrap}
.more[aria-expanded="true"]{background:var(--ink);color:var(--surf);border-color:var(--ink)}
.pmore>td{background:var(--surf2);padding:10px 14px 14px}
.members .fine{margin:2px 0}.mtable{margin-top:8px;font-size:.92em}.mtable th{position:static;background:transparent}
.tcell{white-space:nowrap}
.guide{margin:34px 0 0;scroll-margin-top:64px;background:var(--surf);border:1px solid var(--ring);border-radius:14px;padding:6px 18px}
.guide summary{cursor:pointer;font-weight:700;padding:8px 0}
.gbody{font-size:.93em;color:var(--ink2);max-width:76em}.gbody h3{font-size:.95em;color:var(--ink);margin:14px 0 4px}
.gbody code,.rs code,.act code{font-family:var(--mono);font-size:.9em;background:var(--surf2);padding:0 4px;border-radius:4px}
.tip{position:fixed;z-index:60;display:none;pointer-events:none;max-width:340px;background:var(--ink);color:var(--surf);font-size:.8em;line-height:1.5;padding:8px 10px;border-radius:9px;box-shadow:0 2px 10px rgba(0,0,0,.3)}
.tip b{display:block;font-weight:700}.tip .src{font-family:var(--mono);word-break:break-all;color:var(--low)}.tip .dim{opacity:.75}
@media(max-width:900px){.sec.two{grid-template-columns:1fr}.hero h1{font-size:1.6em}.funnel .fr{grid-template-columns:110px 1fr 36px}}
@media print{.filters,.tip{display:none!important}}

/* ── report shell ─────────────────────────────────────────────────────── */
.report{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:32px;align-items:start}
.report.plain{grid-template-columns:minmax(0,1fr)}
.doc{min-width:0;max-width:960px}
.rail{position:sticky;top:16px;max-height:calc(100vh - 32px);overflow:auto;font-size:.88em}
.rs{background:var(--surf);border:1px solid var(--ring);border-radius:12px;padding:10px 14px;margin-bottom:12px}
.rs h4{font-size:.74em;text-transform:uppercase;letter-spacing:.06em;color:var(--ink2);margin:0 0 6px}
.rs .fine{color:var(--ink2)}.rs>div{margin:3px 0}
.outline,.files{list-style:none;margin:0;padding:0}.outline li{margin:2px 0}.outline .l3{padding-left:12px;font-size:.92em}.files li{margin:3px 0;overflow-wrap:anywhere}
.cvhead{display:flex;align-items:center;gap:10px;margin-bottom:6px}.cvhead .big{font-size:1.5em;font-weight:700}
.cvg{display:flex;flex-wrap:wrap;align-items:center;gap:4px;margin:4px 0}.cvl{font-size:.74em;color:var(--muted);width:66px;text-transform:uppercase;letter-spacing:.05em}
.cv{display:inline-block;font-family:var(--mono);font-size:.78em;padding:1px 6px;border-radius:5px;background:var(--surf2);color:var(--ink2);cursor:help}
.cv b{margin-left:3px;color:var(--ink)}.cv.hi{background:var(--high);color:#0b0b0b}.cv.hi b{color:#0b0b0b}.cv.mid{background:var(--med);color:#0b0b0b}.cv.mid b{color:#0b0b0b}
.band{display:flex;flex-wrap:wrap;align-items:center;gap:4px 8px;font-size:.86em;color:var(--ink2);margin:0 0 10px}
.action{background:var(--surf);border:1px solid var(--ring);border-left:4px solid var(--ink);border-radius:12px;padding:12px 16px;margin:16px 0 22px}
.at{font-size:.74em;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--ink2);margin-bottom:6px}
.act{display:grid;grid-template-columns:96px 1fr;gap:10px;padding:5px 0;border-top:1px solid var(--grid)}
.act:first-of-type{border-top:0}.al{font-weight:700;color:var(--ink)}.av{color:var(--ink2);overflow-wrap:anywhere}.av b{color:var(--ink)}
@media(max-width:1100px){.report{grid-template-columns:minmax(0,1fr)}.rail{position:static;max-height:none}.act{grid-template-columns:80px 1fr}}

/* ── report body (the classes bin/render-md emits) ────────────────────── */
.doc h1{font-size:1.85em;line-height:1.2;margin:0 0 .5em;letter-spacing:-.01em}
.doc h2{font-size:1.3em;margin:1.6em 0 .6em;letter-spacing:-.005em}
.doc h3{font-size:1.05em;margin:1.4em 0 .5em}
.doc h2 .anchor,.doc h3 .anchor{color:var(--muted);margin-left:.35em;opacity:0;font-weight:500}
.doc h2:hover .anchor,.doc h3:hover .anchor{opacity:.55}
.doc p,.doc ul,.doc ol{margin:.65em 0}.doc li{margin:.3em 0}
.doc em,.doc em.note{color:var(--muted);font-style:normal}
.doc a{text-decoration:underline;text-decoration-color:color-mix(in srgb,var(--link) 45%,transparent);text-underline-offset:2px}
.doc a:hover{text-decoration-color:currentColor}.doc a code{color:inherit}
.doc code{background:var(--surf2);padding:2px 6px;border-radius:5px;font-family:var(--mono);font-size:.92em;overflow-wrap: anywhere;}
.doc pre{background:var(--surf);padding:.9em 1.1em;border-radius:10px;overflow:auto;border:1px solid var(--ring);font-size:.9em}
.doc pre code{background:transparent;padding:0}
.doc blockquote{margin:1em 0;padding:.7em 1.1em;border-left:3px solid var(--axis);background:var(--surf2);border-radius:0 8px 8px 0;color:var(--ink2)}
.doc hr{border:0;border-top:1px solid var(--grid);margin:1.2em 0}
.doc table{border-collapse:separate;border-spacing:0;width:100%;min-width: 100%;font-size:.92em;background:var(--surf)}
.table-wrap{margin:1em 0;overflow-x:auto;overflow-y:hidden;border-radius:10px;border:1px solid var(--ring);background:var(--surf)}
.doc thead th{background:var(--surf2);border-bottom:1px solid var(--grid);text-align:left;font-weight:600;font-size:.86em;padding:9px 12px;position: sticky;top:0;z-index:2;white-space: nowrap;}
.doc tbody td{border-top:1px solid var(--grid);padding:8px 12px;vertical-align:top;word-break:break-word}
.doc tbody tr:first-child td{border-top:none}.doc tbody tr:hover td{background:var(--surf2)}
.doc td.right,.doc th.right{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}.doc td.center,.doc th.center{text-align:center}
td code, th code{white-space:nowrap}
td code.wrap, th code.wrap{white-space:normal;word-break:normal;overflow-wrap:anywhere}
.chip-library,.chip-cli,.chip-maint,.chip-unknown{display:inline-block;padding:1px 8px;border-radius:5px;font-size:.85em;font-weight:500;white-space:nowrap;background:var(--surf2);color:var(--ink2)}
.chip-library{background:var(--dx);color:var(--dx-ink)}.chip-maint{background:#fef3c7;color:#854d0e}
.chip-reason{color:var(--muted);margin-left:.35em;font-weight:400}
.fields-table th:first-child{width:220px}.fields-table td:first-child{font-weight:500;color:var(--muted)}
.fields-table td:first-child abbr{text-decoration:underline dotted;text-underline-offset:3px;cursor: help;}
.rejected-table{table-layout:fixed}.rejected-table th:nth-child(1),.rejected-table td:nth-child(1),.rejected-table th:nth-child(2),.rejected-table td:nth-child(2){width:14rem;overflow-wrap:anywhere}
.rejected-table th:nth-child(4),.rejected-table td:nth-child(4){width:6rem;white-space:nowrap}.rejected-table td:nth-child(3){word-break:normal;overflow-wrap:anywhere}
.benchmark-table{min-width:0;font-size:.88em}.benchmark-table thead th,.benchmark-table tbody td{padding:7px 6px;vertical-align:middle}
.benchmark-table thead th{white-space:normal;line-height:1.25}
dl.report-definition{display:grid;grid-template-columns:minmax(160px,240px) 1fr;margin:.8em 0 1em;border:1px solid var(--ring);border-radius:8px;overflow:hidden;background:var(--surf)}
dl.report-definition dt,dl.report-definition dd{margin:0;padding:8px 11px;border-top:1px solid var(--grid)}
dl.report-definition dt:nth-of-type(1),dl.report-definition dd:nth-of-type(1){border-top:none}
dl.report-definition dt{color:var(--muted);font-weight:600;background:var(--surf2);white-space:nowrap}dl.report-definition dd{word-break:break-word}
.triage-card{margin:1em 0 1.2em;padding:1em 1.2em;background:var(--surf);border:1px solid var(--ring);border-left:4px solid var(--s,var(--none));border-radius:12px}
.triage-card.sev-Critical{--s:var(--crit)}.triage-card.sev-High{--s:var(--high)}.triage-card.sev-Medium{--s:var(--med)}.triage-card.sev-Low{--s:var(--low)}
.triage-row{display:flex;flex-wrap:wrap;align-items:center;gap:.55em}
.triage-row+.triage-row,.triage-card .triage-frames,.triage-card .triage-meta,.triage-card .triage-summary{margin-top:.55em}
.triage-frames{display:grid;gap:.2em}.triage-frame{font-family:var(--mono);font-size:.9em}.triage-frame code{background:transparent;padding:0}
.triage-frame .frame-func{font-weight:600}.triage-frame .frame-loc{color:var(--muted)}.frame-index{color:var(--muted)}
.triage-meta{color:var(--muted);font-size:.92em;display:flex;flex-wrap:wrap;gap:.3em 1.2em}.triage-meta strong{color:var(--ink);font-weight:600}
.triage-summary{font-size:.98em;line-height:1.55;border-top:1px solid var(--grid);padding-top:.65em;overflow-wrap:anywhere;word-break:break-word}
.primitive{display:inline-block;padding:1px 8px;border-radius:5px;font-family:var(--mono);font-size:.85em;font-weight:500;background:var(--surf2);color:var(--ink2);white-space:nowrap}
.primitive.cat-bounds{background:var(--dr);color:var(--dr-ink)}.primitive.cat-lifetime{background:#ffedd5;color:#9a3412}
.primitive.cat-uninit{background:#fef3c7;color:#92400e}.primitive.cat-type{background:var(--dx);color:var(--dx-ink)}.primitive.cat-state{background:var(--da);color:var(--da-ink)}
.enrich-card{background:var(--surf);border:1px solid var(--ring);border-radius:12px;padding:1em 1.3em;margin:1em 0 1.4em}
.enrich-card>:first-child{margin-top:0}.enrich-card>:last-child{margin-bottom:0}
.enrich-card pre{background:var(--surf2);border:0;border-radius:8px;margin:.5em 0 .75em}
.enrich-snippets>p{margin:.4em 0}.enrich-snippets>hr{margin:1em -.4em}.enrich-patch pre{margin:0}
code.language-diff > span{display:block;min-height:1.2em}
code.language-diff .da{color:var(--da-ink);background:var(--da)}
code.language-diff .dr{color:var(--dr-ink);background:var(--dr)}
code.language-diff .dh{font-weight:600}code.language-diff .dx{color:var(--dx-ink);background:var(--dx)}
details.collapsible{margin:1.6em 0 .6em}details.collapsible>summary{cursor:pointer;font-size:1.3em;font-weight:600;margin:1.6em 0 .6em;list-style:none}
details.collapsible>summary::-webkit-details-marker{display:none}
details.collapsible>summary::before{content:"▸";color:var(--muted);margin-right:.4em;font-size:.85em;display:inline-block;transition:transform .15s ease}
details.collapsible[open]>summary::before{transform:rotate(90deg)}details.collapsible td{vertical-align:top;line-height:1.55}
@media(max-width:700px){.page{padding:14px 12px 40px}.doc table{font-size:.88em}dl.report-definition{grid-template-columns:1fr}}
"""

_JS = r"""
(function(){
"use strict";
var el=document.getElementById("page-data");if(!el)return;
var D=JSON.parse(el.textContent),NS="http://www.w3.org/2000/svg";
var css=getComputedStyle(document.documentElement);
function v(name){return css.getPropertyValue(name).trim()}
function mk(t,a,k){var e=document.createElementNS(NS,t);for(var x in a)if(a[x]!=null)e.setAttribute(x,a[x]);(k||[]).forEach(function(c){e.appendChild(c)});return e}
function tx(s){return document.createTextNode(String(s))}
var WHO={harness:v("--harness"),"model-direct":v("--direct"),codex:v("--codex"),claude:v("--claude"),gemini:v("--gemini"),grok:v("--grok"),oss:v("--oss"),opencode:v("--opencode")};
function whoHue(w){return WHO[w]||v("--other")}
// ── tooltip ────────────────────────────────────────────────────────────────
var tip=document.getElementById("tip");
function place(e){var pad=14,w=tip.offsetWidth,ht=tip.offsetHeight,x=e.clientX+pad,y=e.clientY+pad;
 if(x+w>innerWidth-8)x=e.clientX-w-pad;if(y+ht>innerHeight-8)y=e.clientY-ht-pad;tip.style.left=Math.max(8,x)+"px";tip.style.top=Math.max(8,y)+"px"}
function show(e,lines){tip.replaceChildren();lines.forEach(function(l){if(!l||!l.text)return;var p=document.createElement(l.b?"b":"span");
 p.textContent=l.text;if(l.src)p.className="src";if(l.dim)p.className="dim";tip.appendChild(p);if(!l.b)tip.appendChild(document.createElement("br"))});
 tip.style.display="block";place(e)}
function hide(){tip.style.display="none"}
function hover(node,fn){node.addEventListener("mouseenter",function(e){show(e,fn())});node.addEventListener("mousemove",place);node.addEventListener("mouseleave",hide)}
function fmtH(t){return t<1?"+"+Math.round(t*60)+" min":"+"+t.toFixed(1)+" h"}
// ── discovery timeline ─────────────────────────────────────────────────────
function timeline(){var host=document.getElementById("timeline"),T=D.timeline;if(!host||!T)return;
 var pts=T.points.filter(function(p){return p.t!=null}).sort(function(a,b){return a.t-b.t});
 if(!pts.length){host.innerHTML='<p class="empty">No report on this page carries a filing clock.</p>';return}
 var W=1000,H=260,L=44,R=16,Tp=14,B=34,xmax=Math.max(T.x_max||0,pts[pts.length-1].t,0.25)*1.04;
 var whos={};pts.forEach(function(p){(p.who&&p.who.length?p.who:["all"]).forEach(function(w){whos[w]=1})});
 var names=Object.keys(whos);var multi=names.length>1;
 var series=[];names.forEach(function(w){var n=0,pth=[];pts.forEach(function(p){if((p.who&&p.who.length?p.who:["all"]).indexOf(w)<0)return;n++;pth.push([p.t,n])});series.push({who:w,pts:pth,n:n})});
 var ymax=Math.max.apply(null,[pts.length].concat(series.map(function(s){return s.n})));ymax=Math.max(1,ymax);
 function X(t){return L+(t/xmax)*(W-L-R)}function Y(n){return H-B-(n/ymax)*(H-Tp-B)}
 var svg=mk("svg",{viewBox:"0 0 "+W+" "+H,role:"img","aria-label":"cumulative distinct problems over the run"});
 var step=[0.1,0.25,0.5,1,2,4,6,12,24,48].find(function(s){return xmax/s<=8})||96;
 for(var t=0;t<=xmax+1e-9;t+=step){var x=X(t);
  svg.appendChild(mk("line",{x1:x,x2:x,y1:Tp,y2:H-B,stroke:v("--grid")}));
  svg.appendChild(mk("text",{x:x,y:H-B+16,"text-anchor":"middle","font-size":11,fill:v("--muted")},[tx((step<1?t.toFixed(2).replace(/\.?0+$/,""):t)+" h")]))}
 var ysteps=Math.min(6,ymax);for(var j=0;j<=ysteps;j++){var n=Math.round(ymax*j/ysteps),y=Y(n);
  svg.appendChild(mk("line",{x1:L,x2:W-R,y1:y,y2:y,stroke:v("--grid")}));
  svg.appendChild(mk("text",{x:L-6,y:y+4,"text-anchor":"end","font-size":11,fill:v("--muted")},[tx(n)]))}
 if(T.wall_h){var wx=X(T.wall_h);svg.appendChild(mk("line",{x1:wx,x2:wx,y1:Tp,y2:H-B,stroke:v("--axis"),"stroke-dasharray":"3 3"}));
  svg.appendChild(mk("text",{x:wx+4,y:H-B-6,"text-anchor":"start","font-size":10,fill:v("--muted")},[tx("budget")]))}
 svg.appendChild(mk("text",{x:W-R,y:H-4,"text-anchor":"end","font-size":11,fill:v("--muted")},[tx(T.per_condition?"hours into each condition's run":T.origin_is_run_start?"hours into the run":"hours after the first report")]));
 series.forEach(function(s){var d="M"+X(0)+","+Y(0);s.pts.forEach(function(q){d+="H"+X(q[0])+"V"+Y(q[1])});d+="H"+X(xmax);
  svg.appendChild(mk("path",{d:d,fill:"none",stroke:multi?whoHue(s.who):v("--ink"),"stroke-width":multi?2:2.2,opacity:multi?.9:1}))});
 if(multi){var d="M"+X(0)+","+Y(0);pts.forEach(function(p,i){d+="H"+X(p.t)+"V"+Y(i+1)});d+="H"+X(xmax);
  svg.appendChild(mk("path",{d:d,fill:"none",stroke:v("--ink"),"stroke-width":1.4,"stroke-dasharray":"5 4",opacity:.7}))}
 pts.forEach(function(p,i){var c=mk("circle",{cx:X(p.t),cy:Y(i+1),r:5.5,fill:v(p.color)||v("--none"),stroke:v("--surf"),"stroke-width":1.5,"class":"pt"});
  hover(c,function(){return[{text:p.title||p.site||p.id,b:true},{text:p.site,src:true},
   {text:fmtH(p.t)+(p.who&&p.who.length?" · "+p.who.join(", "):"")+(p.size>1?" · "+p.size+" reports":"")},
   {text:p.axis,dim:true},p.href?{text:"click to open the report",dim:true}:null]});
  if(p.href)c.addEventListener("click",function(){location.href=p.href});
  svg.appendChild(c)});
 host.replaceChildren(svg)}
timeline();
// ── filters, search, sort, expand ─────────────────────────────────────────
var rows=[].slice.call(document.querySelectorAll("tr.prow")),shown=document.getElementById("shown");
var chips=[].slice.call(document.querySelectorAll(".chip[data-filter]")),search=document.querySelector(".search");
function apply(){var on={};chips.forEach(function(c){var f=c.dataset.filter;on[f]=on[f]||{};if(c.classList.contains("on"))on[f][c.dataset.value]=1});
 var q=(search&&search.value||"").toLowerCase().trim(),n=0;
 rows.forEach(function(r){var ok=true;
  for(var f in on){var vals=(r.dataset[f]||"").split(" ").filter(Boolean);if(!vals.length)vals=[""];
   var hit=vals.some(function(x){return on[f][x]});if(Object.keys(on[f]).length&&!hit&&!(vals[0]===""&&f!=="severity"))ok=false;
   if(f==="severity"&&!on[f][r.dataset.severity])ok=false}
  if(ok&&q&&(r.dataset.q||"").indexOf(q)<0)ok=false;
  r.hidden=!ok;if(!ok){var m=r.nextElementSibling;if(m&&m.classList.contains("pmore")){m.hidden=true;var b=r.querySelector(".more");if(b)b.setAttribute("aria-expanded","false")}}
  if(ok)n++});
 if(shown)shown.textContent=n===rows.length?rows.length+" shown":n+" of "+rows.length+" shown"}
chips.forEach(function(c){c.addEventListener("click",function(){c.classList.toggle("on");apply()})});
if(search)search.addEventListener("input",apply);
apply();
document.querySelectorAll(".more").forEach(function(b){b.addEventListener("click",function(){var m=document.getElementById(b.getAttribute("aria-controls"));if(!m)return;
 var open=m.hidden;m.hidden=!open;b.setAttribute("aria-expanded",open?"true":"false")})});
document.querySelectorAll("th[data-sort]").forEach(function(th){th.addEventListener("click",function(){var key=th.dataset.sort,tbl=th.closest("table"),body=tbl.tBodies[0];
 var asc=th.classList.contains("sorted")&&!th.classList.contains("asc");
 tbl.querySelectorAll("th").forEach(function(o){o.classList.remove("sorted","asc")});th.classList.add("sorted");if(asc)th.classList.add("asc");
 var pairs=[].slice.call(body.querySelectorAll("tr.prow")).map(function(r){var m=r.nextElementSibling;return[r,m&&m.classList.contains("pmore")?m:null]});
 function val(r){var x=r.dataset[key];if(x==null)x="";var n=parseFloat(x);return isNaN(n)||key==="text"||key==="axis"||key==="who"||key==="status"||key==="lanes"||key==="family"?x:n}
 pairs.sort(function(a,b){var x=val(a[0]),y=val(b[0]);if(typeof x==="number"&&typeof y==="number")return asc?x-y:y-x;
  if(x===""&&y!=="")return 1;if(y===""&&x!=="")return -1;return asc?String(x).localeCompare(String(y)):String(y).localeCompare(String(x))});
 pairs.forEach(function(p){body.appendChild(p[0]);if(p[1])body.appendChild(p[1])})})});
// filing times: absolute in HTML for no-script readers, relative to the run on screen
document.querySelectorAll(".tcell[data-rel]").forEach(function(c){var r=parseFloat(c.dataset.rel);
 if(isNaN(r))return;c.setAttribute("title",c.textContent);c.textContent=fmtH(r)});
})();
"""
