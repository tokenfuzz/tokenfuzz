"""Content-bound record of what a report's published severity was scored from.

`severity.json` used to record only that scoring ran. Reports are rewritten
after they are scored — reach-field fills, enrichment, pool copies — so a
timestamp cannot tell a consumer whether the Severity row still matches the
report it sits beside, and a score computed by an older scorer reads exactly
like a current one.

Bind the marker to the scoring inputs instead: the agent-authored report
content and the scorer's decision version. `report_identity.content_sha1`
already excludes the Severity row and rationale the scorer itself maintains,
so writing a score never invalidates its own marker, while a changed trigger,
surface, or caller-control field does.

A stale marker is never a security decision — it only means the score must be
re-derived before anything reads it.
"""

from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

import finding_signature
import report_identity

SCHEMA_VERSION = 5
# Bump whenever scoring semantics change, so scores a previous scorer computed
# are re-derived instead of being read as current. Named for the change that
# introduced the version, the way the trigger gate names its decision version.
SCORER_DECISION_VERSION = "severity-v3-observed-read-impact"

FILENAME = "severity.json"


def _payload(report: Path, severity: dict) -> dict:
    cvss = severity.get("cvss") if isinstance(severity, dict) else None
    vector = str((cvss or {}).get("vector") or "")
    return {
        "schema_version": SCHEMA_VERSION,
        "scorer_version": SCORER_DECISION_VERSION,
        "scored_at": datetime.now(timezone.utc).isoformat(),
        "report_sha1": report_identity.content_sha1(report) or "",
        "level": str(severity.get("level") or ""),
        "score": severity.get("score"),
        "vector": vector,
        # The scorer already chose a normalized primitive; only the receipt
        # was dropping it. Without it every later variety read re-parses
        # mutable report prose, which is the identity class that invalidated
        # the reverted disposition shadow. Recorded, never re-decided: it
        # describes what was scored, and gates nothing.
        "primitive": str(severity.get("primitive") or ""),
        "primitive_key": str(severity.get("primitive_key") or ""),
    }


def write(report_dir: Path, report: Path, severity: dict) -> dict:
    """Record the severity *report* was scored to, bound to its content.

    Callers must write the scored report before calling this: the binding
    hashes the report as it stands on disk.
    """
    payload = _payload(Path(report), severity)
    destination = Path(report_dir) / FILENAME
    temporary = destination.with_name(
        f".{FILENAME}.{os.getpid()}.{time.time_ns()}.tmp",
    )
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8",
    )
    os.replace(temporary, destination)
    return payload


def read_current(report_dir: Path, report: Path) -> dict | None:
    """Return the marker only while it still describes *report*'s score.

    None means "not scored by this scorer against this content" — missing,
    unreadable, written by an older schema or scorer, or bound to report
    content that has since changed.
    """
    path = Path(report_dir) / FILENAME
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != SCHEMA_VERSION
        or payload.get("scorer_version") != SCORER_DECISION_VERSION
    ):
        return None
    current = report_identity.content_sha1(Path(report))
    if not current or payload.get("report_sha1") != current:
        return None
    try:
        text = Path(report).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    level, _rank, score = finding_signature.extract_severity(text)
    if level != payload.get("level"):
        return None
    expected_score = payload.get("score")
    if expected_score is not None:
        if (
            isinstance(expected_score, bool)
            or not isinstance(expected_score, (int, float))
            or abs(score - float(expected_score)) > 1e-9
        ):
            return None
    vector = payload.get("vector")
    if not isinstance(vector, str) or (vector and vector not in text):
        return None
    return payload
