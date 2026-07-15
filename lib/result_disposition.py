#!/usr/bin/env python3
"""Read-only technical/scope disposition for crash and finding artifacts."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import crash_artifacts
import crash_bundle
import report_identity
import target_config
import triage_validate
import verdict


SCHEMA_VERSION = 1
ORIGIN_NAME = ".artifact-origin.json"
_REPORT_FIELDS = {
    "trigger source", "issue id", "recon id", "source finding",
    "source finding id",
}
_TRIGGER_ALIASES = {
    "data": "bytes", "data-driven": "bytes", "input": "bytes",
    "call-order": "call-sequence", "call_order": "call-sequence",
    "call-seq": "call-sequence", "call_sequence": "call-sequence",
    "sequence": "call-sequence",
}


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def _nearest(start: Path, name: str) -> Path | None:
    current = start.resolve()
    if current.is_file():
        current = current.parent
    for directory in (current, *current.parents):
        candidate = directory / name
        if candidate.is_file():
            return candidate
    return None


def _clean_revision(value: object) -> str:
    text = str(value or "").strip()
    return "" if text.lower() in {"", "?", "head", "unknown", "no-vcs", "norev"} else text


def _attacker_controls(parsed: dict) -> list[str]:
    threat = parsed.get("threat_model", {})
    raw = threat.get("attacker_controls", []) if isinstance(threat, dict) else []
    if not isinstance(raw, list):
        raw = []
    controls = {
        target_config._normalize_attacker_control(str(value).strip())
        for value in raw if str(value).strip()
    }
    ordered = [
        value for value in target_config.ATTACKER_CONTROLS_VALID
        if value != "call-order" and value in controls
    ]
    return ordered or ["bytes"]


def target_identity(results_dir: Path) -> dict:
    """Resolve actual run identity separately from mutable target config."""
    results_dir = Path(results_dir)
    session_path = _nearest(results_dir, ".session-env")
    session = {}
    if session_path is not None:
        try:
            session = target_config.read_session_env(session_path.parent)
        except (OSError, ValueError):
            session = {}
    run = _read_json(_nearest(results_dir, "run.json") or Path("/__missing__"))
    toml_path = _nearest(results_dir, "target.toml")
    parsed = {}
    if toml_path is not None:
        try:
            value = target_config.parse_toml(toml_path)
            parsed = value if isinstance(value, dict) else {}
        except Exception:
            parsed = {}

    actual = _clean_revision(session.get("TARGET_REV")) or _clean_revision(run.get("target_sha"))
    configured = _clean_revision(parsed.get("pinned_rev"))
    if actual and configured:
        revision_status = "matched" if actual == configured else "mismatch"
    elif actual:
        revision_status = "actual-only"
    elif configured:
        revision_status = "config-only"
    else:
        revision_status = "unknown"
    return {
        "target": str(session.get("TARGET_SLUG") or run.get("target") or parsed.get("slug") or ""),
        "target_revision": actual,
        "config_revision": configured,
        "revision_status": revision_status,
        "attacker_controls": _attacker_controls(parsed),
    }


def _probe_context(artifact_dir: Path) -> dict:
    for path in (
        artifact_dir / ".probe-context.json",
        artifact_dir / ".audit" / ".probe-context.json",
    ):
        value = _read_json(path)
        if value:
            return value
    return {}


def _artifact_json(artifact_dir: Path, name: str) -> dict:
    for root in (artifact_dir, artifact_dir / ".audit"):
        value = _read_json(root / name)
        if value:
            return value
    return {}


def _build_identity(context: dict) -> dict:
    binary = context.get("binary")
    if not isinstance(binary, dict):
        return {}
    return {
        key: binary[key]
        for key in ("sha1", "size", "mtime_ns") if binary.get(key) not in (None, "")
    }


def _report_and_fields(artifact_dir: Path) -> tuple[Path | None, dict[str, str]]:
    report = report_identity.find_report(artifact_dir)
    if report is None:
        return None, {}
    try:
        text = report.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return report, {}
    return report, report_identity.extract_fields(text, _REPORT_FIELDS)


def _card_source(row: dict) -> tuple[str, str]:
    recon = row.get("recon")
    if isinstance(recon, dict) and recon.get("id"):
        return "recon", str(recon["id"])
    if row.get("issue_id"):
        return "upstream", str(row["issue_id"])
    if row.get("find_id"):
        return "finding", str(row["find_id"])
    return "", ""


def _state_issue_source(results_dir: Path, artifact_name: str) -> tuple[str, str]:
    try:
        card_lines = (results_dir / "work-cards.jsonl").read_text(
            encoding="utf-8", errors="replace",
        ).splitlines()
    except OSError:
        card_lines = []
    cards = []
    for line in card_lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            cards.append(row)
    for card in cards:
        if isinstance(card, dict) and str(card.get("find_id", "")) == artifact_name:
            kind, source = _card_source(card)
            if source:
                return kind, source

    latest: dict[str, dict] = {}
    try:
        lines = (results_dir / "state" / "hypotheses.jsonl").read_text(
            encoding="utf-8", errors="replace",
        ).splitlines()
    except OSError:
        lines = []
    for line in lines:
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict) and row.get("id"):
            latest[str(row["id"])] = row
    for hypothesis_id, row in latest.items():
        status = str(row.get("status", "")).strip()
        if status == artifact_name or status.startswith(artifact_name + " "):
            return "hypothesis", hypothesis_id
    return "", ""


def issue_id(results_dir: Path, artifact_dir: Path, target: dict) -> tuple[str, str]:
    origin = _read_json(artifact_dir / ORIGIN_NAME)
    if origin.get("issue_id"):
        return str(origin["issue_id"]), "pooled-origin"
    context = _probe_context(artifact_dir)
    if context.get("issue_id"):
        return str(context["issue_id"]), "probe-context"
    _report, fields = _report_and_fields(artifact_dir)
    if fields.get("issue id"):
        value = fields["issue id"]
        if value.startswith("tokenfuzz-issue/v1:"):
            return value, "report"
        return crash_bundle.format_issue_id(
            target.get("target", ""), target.get("target_revision", ""),
            "upstream", value,
        ), "report-provenance"
    for name, kind in (
        ("recon id", "recon"),
        ("source finding id", "finding"),
        ("source finding", "finding"),
    ):
        if fields.get(name):
            return crash_bundle.format_issue_id(
                target.get("target", ""), target.get("target_revision", ""),
                kind, fields[name],
            ), "report-provenance"
    source_kind, source_id = _state_issue_source(results_dir, artifact_dir.name)
    if source_id:
        return crash_bundle.format_issue_id(
            target.get("target", ""), target.get("target_revision", ""),
            source_kind, source_id,
        ), "run-state"
    return crash_bundle.format_issue_id(
        target.get("target", ""), target.get("target_revision", ""),
        "artifact", artifact_dir.name,
    ), "artifact-local"


def _trigger_vote_evidence(
    artifact_dir: Path, name: str, controls: list[str],
) -> tuple[str, bool, bool]:
    """Return (vote, controls_bound, content_bound), retaining stale advice."""
    advisory: tuple[str, bool, bool] = ("", False, False)
    for root in (artifact_dir, artifact_dir / ".audit"):
        payload = _read_json(root / name)
        if not payload:
            continue
        report = report_identity.find_report(root) or report_identity.find_report(artifact_dir)
        vote = payload.get("vote")
        if vote not in {"Promote", "Reject", "Uncertain"}:
            continue
        controls_bound = (
            payload.get("decision_version") == triage_validate.TRIGGER_GATE_DECISION_VERSION
            and payload.get("attacker_controls") == sorted(controls)
        )
        content_bound = (
            report is not None
            and payload.get("content_sha1") == report_identity.content_sha1(report)
        )
        evidence = str(vote), controls_bound, content_bound
        if content_bound:
            return evidence
        if not advisory[0]:
            advisory = evidence
    return advisory


def _quality_state(artifact_dir: Path) -> tuple[str, str]:
    if (artifact_dir / ".keep").is_file() or (artifact_dir / ".reviewed").is_file():
        return "confirmed", "human pin"
    payload = _read_json(artifact_dir / ".llm-find-quality.json")
    if payload.get("decision_version") != report_identity.FIND_QUALITY_DECISION_VERSION:
        return "unknown", "no current quality verdict"
    if not report_identity.quality_cache_matches_report(artifact_dir, payload):
        return "unknown", "stale quality verdict"
    if payload.get("accept") is True:
        return "confirmed", "two report-quality accepts"
    if payload.get("accept") is False:
        return "refuted", "two report-quality rejects"
    return "unknown", "quality review incomplete"


def _trigger_components(value: str) -> list[str]:
    out: set[str] = set()
    for item in str(value or "").split(","):
        token = _TRIGGER_ALIASES.get(item.strip().lower(), item.strip().lower())
        if token == "both":
            out.update(("bytes", "call-sequence"))
        elif token:
            out.add(token)
    return sorted(out)


def disposition_for(technical: str, scope: str) -> str:
    if technical == "refuted":
        return "invalid"
    if technical == "confirmed" and scope == "in":
        return "security"
    if technical == "confirmed" and scope == "out":
        return "robustness"
    return "needs-review"


def artifact_origin(
    results_dir: Path,
    artifact_dir: Path,
    kind: str,
    *,
    target_override: dict | None = None,
) -> dict:
    target = target_identity(results_dir)
    if target_override:
        for key in ("target", "target_revision"):
            if target_override.get(key):
                target[key] = target_override[key]
        actual = _clean_revision(target.get("target_revision"))
        configured = _clean_revision(target.get("config_revision"))
        target["revision_status"] = (
            "matched" if actual and configured and actual == configured
            else "mismatch" if actual and configured
            else "actual-only" if actual
            else "config-only" if configured
            else "unknown"
        )
    identifier, source = issue_id(results_dir, artifact_dir, target)
    context = _probe_context(artifact_dir)
    direct = _artifact_json(
        artifact_dir, ".trigger-gate-bypass.json",
    ).get("bypass") is True
    if direct:
        direct = crash_bundle.verified_probe_context(artifact_dir) is not None
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "source_artifact": artifact_dir.name,
        "issue_id": identifier,
        "issue_id_source": source,
        **target,
        "build_identity": _build_identity(context),
        "direct_probe_verified": direct,
    }


def inspect_artifact(results_dir: Path, artifact_dir: Path, kind: str) -> dict:
    root_target = target_identity(results_dir)
    origin = _read_json(artifact_dir / ORIGIN_NAME)
    target = dict(root_target)
    for key in (
        "target", "target_revision", "config_revision", "revision_status",
        "attacker_controls",
    ):
        if origin.get(key) not in (None, "", []):
            target[key] = origin[key]
    controls = list(target.get("attacker_controls") or ["bytes"])
    report, fields = _report_and_fields(artifact_dir)
    required = _trigger_components(fields.get("trigger source", ""))
    missing = sorted(set(required) - set(controls))
    declared_scope = "unknown" if not required else ("out" if missing else "in")

    if kind.startswith("crash"):
        sanitizer = crash_artifacts.find_primary_sanitizer(
            (artifact_dir, artifact_dir / ".audit"),
        )
        technical = (
            "confirmed"
            if sanitizer is not None and verdict.file_has_crash(sanitizer)
            else "unknown"
        )
        technical_reason = (
            "sanitizer diagnostic"
            if technical == "confirmed" else "no sanitizer diagnostic"
        )
    else:
        technical, technical_reason = _quality_state(artifact_dir)

    first, first_controls_bound, first_content_bound = _trigger_vote_evidence(
        artifact_dir, ".trigger-gate.json", controls,
    )
    second, second_controls_bound, second_content_bound = _trigger_vote_evidence(
        artifact_dir, ".trigger-gate-2.json", controls,
    )
    direct = origin.get("direct_probe_verified") is True
    if not direct and _artifact_json(
        artifact_dir, ".trigger-gate-bypass.json",
    ).get("bypass") is True:
        direct = crash_bundle.verified_probe_context(artifact_dir) is not None
    if direct:
        scope, scope_reason = "in", "verified standard-input probe"
    elif (
        first == "Promote"
        and first_controls_bound and first_content_bound
        and required and not missing
    ):
        scope, scope_reason = "in", "bound source review and structured controls agree"
    elif (
        first == second == "Reject"
        and first_controls_bound and second_controls_bound
        and first_content_bound and second_content_bound
    ):
        scope, scope_reason = "out", "two source reviewers disproved attacker reachability"
    else:
        scope, scope_reason = "unknown", "no conclusive source-review quorum"

    identifier, identifier_source = issue_id(results_dir, artifact_dir, target)
    review_reasons = []
    if target.get("revision_status") == "mismatch":
        review_reasons.append("target revision mismatches config revision")
    if not target.get("target_revision"):
        review_reasons.append("actual target revision unavailable")
    if technical == "unknown":
        review_reasons.append("technical validity unresolved")
    if scope == "unknown":
        review_reasons.append("security scope unresolved")
    if first == "Promote" and scope == "unknown":
        review_reasons.append("constructed path lacks matching structured scope evidence")
    if declared_scope != "unknown" and scope != "unknown" and declared_scope != scope:
        review_reasons.append("declared trigger conflicts with source-backed scope")
    if identifier_source == "artifact-local":
        review_reasons.append("no cross-artifact issue provenance")
    disposition = disposition_for(technical, scope)
    if target.get("revision_status") in {"mismatch", "config-only", "unknown"}:
        disposition = "needs-review"
    return {
        "artifact": f"{artifact_dir.parent.name}/{artifact_dir.name}",
        "evidence_kind": "crash" if kind.startswith("crash") else "finding",
        "accepted_tree": kind in {"crashes", "findings"},
        "issue_id": identifier,
        "issue_id_source": identifier_source,
        "technical": technical,
        "technical_reason": technical_reason,
        "scope": scope,
        "scope_reason": scope_reason,
        "disposition": disposition,
        "required_controls": required,
        "attacker_controls": controls,
        "missing_controls": missing,
        "declared_scope": declared_scope,
        "trigger_votes": [
            {
                "vote": vote,
                "attacker_controls_bound": controls_bound,
                "report_content_bound": content_bound,
            }
            for vote, controls_bound, content_bound in (
                (first, first_controls_bound, first_content_bound),
                (second, second_controls_bound, second_content_bound),
            ) if vote
        ],
        "target_revision": target.get("target_revision", ""),
        "config_revision": target.get("config_revision", ""),
        "revision_status": target.get("revision_status", "unknown"),
        "build_identity": (
            origin.get("build_identity")
            or _build_identity(_probe_context(artifact_dir))
        ),
        "review_reasons": review_reasons,
        "report_present": report is not None,
    }


def _summary(records: list[dict]) -> dict:
    return dict(sorted(Counter(record["disposition"] for record in records).items()))


def _issue_records(records: list[dict]) -> list[dict]:
    grouped: dict[str, list[dict]] = {}
    for record in records:
        grouped.setdefault(record["issue_id"], []).append(record)
    out = []
    for identifier, members in sorted(grouped.items()):
        conclusive = {m["disposition"] for m in members if m["disposition"] != "needs-review"}
        issue_disposition = next(iter(conclusive)) if len(conclusive) == 1 else "needs-review"
        out.append({
            "issue_id": identifier,
            "disposition": issue_disposition,
            "artifacts": [member["artifact"] for member in members],
        })
    return out


def inspect_results(results_dir: Path, *, include_rejected: bool = False) -> dict:
    results_dir = Path(results_dir)
    kinds = ["crashes", "findings"]
    if include_rejected:
        kinds += ["crashes-rejected", "findings-rejected"]
    records = []
    for kind in kinds:
        root = results_dir / kind
        if not root.is_dir():
            continue
        for artifact in sorted(root.iterdir()):
            if artifact.is_dir() and not artifact.name.startswith("."):
                records.append(inspect_artifact(results_dir, artifact, kind))
    issues = _issue_records(records)
    return {
        "schema_version": SCHEMA_VERSION,
        "mode": "shadow",
        "results": results_dir.name,
        "target": target_identity(results_dir),
        "artifact_summary": _summary(records),
        "issue_summary": _summary(issues),
        "artifacts": records,
        "issues": issues,
    }


def discover_results_roots(path: Path) -> list[Path]:
    path = Path(path)
    if any((path / name).is_dir() for name in ("crashes", "findings")):
        return [path]
    pool = path / "pool"
    if pool.is_dir():
        conditions = [
            child for child in sorted(pool.iterdir())
            if child.is_dir() and child.name not in {
                "crashes", "findings", "crashes-rejected", "findings-rejected", "logs",
            } and any((child / name).is_dir() for name in ("crashes", "findings"))
        ]
        return conditions or [pool]
    return []
