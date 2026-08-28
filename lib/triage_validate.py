#!/usr/bin/env python3
"""Independent-validator quorum for source-backed findings."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


# Bump whenever the trigger-provenance prompt changes classification semantics.
# Old verdicts then fail open and receive a fresh source-reading review.
TRIGGER_GATE_DECISION_VERSION = "trigger-v11-product-root"
# A resolver reads the cached reviews as evidence and answers their exact open
# question. It has a separate identity so changing that policy never invalidates
# the independent first-pass votes it is meant to adjudicate.
TRIGGER_RESOLUTION_DECISION_VERSION = "trigger-resolution-v3"
# A legacy non-negative vote cannot hide an issue, so triage may reuse it as a
# fail-open keep decision. Legacy Rejects are never reused: they were not bound
# to the target threat model and could otherwise create a false negative.
# v7 is deliberately absent: its batch votes could not answer
# `trigger_controls_fit`, so reusing them as advisory would re-derive the
# `pending` they already produced instead of asking the question.
TRIGGER_GATE_ADVISORY_VERSIONS = {
    "trigger-v2-caller-buffer",
    "trigger-v3-scoped-controls",
    "trigger-v4-source-anchors",
}


def trigger_resolution_review_names(
    first_vote: str | None, second_vote: str | None,
) -> tuple[str, ...]:
    """Return the prior review files needed to resolve an unsettled gate."""
    if first_vote == "Uncertain":
        return (".trigger-gate.json",)
    if first_vote == "Reject" and second_vote in {"Promote", "Uncertain"}:
        return (".trigger-gate.json", ".trigger-gate-2.json")
    return ()


def prior_review_sha256s(paths: Iterable[Path]) -> list[str]:
    """Bind a resolution vote to the exact reviews it adjudicated."""
    values: list[str] = []
    for path in paths:
        try:
            values.append(hashlib.sha256(path.read_bytes()).hexdigest())
        except OSError:
            continue
    return values

ANCHOR_KINDS = {"source", "contract", "build"}
BOUNDARY_SURFACES = {
    "network", "library-api", "file-format", "cli", "dev-tool", "internal",
    "unknown",
}
REPRODUCER_CARRIERS = {
    "network", "library-api", "file-format", "cli", "harness", "runner",
    "unknown",
}
REJECTION_KINDS = {
    "contract-invalid", "unreachable", "nonshipping", "no-added-boundary",
    "consequence-disproved", "unknown",
}
# The reviewer's own threat-model comparison, read from source. The report's
# self-declared `Trigger source` is written by whoever found the bug and is
# wrong in both directions: a driver that calls the target's documented entry
# points reads as caller-driven, while an unreproduced claim reads as
# byte-driven. This fact lets the deterministic comparison be corrected by a
# reviewer that read the code, in either direction.
TRIGGER_CONTROLS_FIT = {"within", "outside", "unclear"}


def source_review_facts(value: object) -> dict[str, str]:
    """Return only the generic boundary facts a source reviewer may assert."""
    if not isinstance(value, dict):
        return {}
    facts: dict[str, str] = {}
    for key, allowed in (
        ("vulnerable_boundary_surface", BOUNDARY_SURFACES),
        ("reproducer_carrier", REPRODUCER_CARRIERS),
        ("rejection_kind", REJECTION_KINDS),
        ("trigger_controls_fit", TRIGGER_CONTROLS_FIT),
    ):
        normalized = str(value.get(key) or "").strip().lower()
        if normalized in allowed:
            facts[key] = normalized
    return facts


def verify_source_anchors(value: object, target_root: Path) -> list[dict]:
    """Return source anchors whose path, line, symbol, and excerpt verify.

    LLM conclusions may be semantic, but their citations are deterministic.
    Each anchor is one exact source line so verification stays language-neutral
    and does not require a target-specific parser.
    """
    if not isinstance(value, list):
        return []
    try:
        root = target_root.resolve(strict=True)
    except OSError:
        return []
    verified: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        relative = str(item.get("path") or "").strip()
        excerpt = str(item.get("excerpt") or "").strip()
        symbol = str(item.get("symbol") or "").strip()
        kind = str(item.get("kind") or "").strip().lower()
        try:
            line = int(item.get("line"))
        except (TypeError, ValueError):
            continue
        if (
            not relative or not excerpt or not symbol or kind not in ANCHOR_KINDS
            or line < 1
        ):
            continue
        path = root / relative
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
            source_lines = resolved.read_text(
                encoding="utf-8", errors="replace",
            ).splitlines()
        except (OSError, ValueError):
            continue
        # Reviewers naturally qualify methods (`Type::method`, `Type.method`,
        # `Type#method`) even when the declaration spells only `method`. The
        # exact path, line, and excerpt remain the citation identity; accept a
        # qualified label only when its source-spelled leaf is present too.
        symbol_candidates = {symbol}
        for separator in ("::", ".", "#"):
            symbol_candidates.update(
                candidate.rsplit(separator, 1)[-1]
                for candidate in tuple(symbol_candidates)
                if separator in candidate
            )
        source_text = "\n".join(source_lines)
        if (
            line > len(source_lines)
            or source_lines[line - 1].strip() != excerpt
            or not any(candidate in source_text for candidate in symbol_candidates)
        ):
            continue
        verified.append({
            "path": resolved.relative_to(root).as_posix(),
            "line": line,
            "symbol": symbol,
            "kind": kind,
            "excerpt": excerpt,
            # The reviewer supplies the citation; deterministic code supplies
            # its digest. Requiring an LLM to calculate a cryptographic hash
            # would turn formatting arithmetic into false pending verdicts.
            "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
        })
    return verified


def trigger_attacker_controls(value: str | None = None) -> list[str]:
    """Canonical attacker_controls bound into trigger-review cache identity.

    Bound into each cached vote so a verdict computed under one threat model is
    not silently reused after attacker_controls changes (e.g. a target that
    later exposes call-sequence).
    """
    raw = value if value is not None else os.environ.get(
        "TARGET_ATTACKER_CONTROLS_CSV", "bytes",
    )
    aliases = {
        "data": "bytes", "data-driven": "bytes", "input": "bytes",
        "call-order": "call-sequence", "call_order": "call-sequence",
        "call-seq": "call-sequence", "call_sequence": "call-sequence",
        "sequence": "call-sequence",
    }
    controls = {
        aliases.get(token.strip().lower(), token.strip().lower())
        for token in str(raw).split(",") if token.strip()
    }
    return sorted(controls or {"bytes"})


@dataclass(frozen=True)
class ValidationResult:
    verdict: str
    promotes: int
    votes: int
    path: Path | None
    detail: str = ""

    @property
    def returncode(self) -> int:
        return {"Promote": 0, "Reject": 1}.get(self.verdict, 2)

    def summary(self) -> str:
        path = str(self.path) if self.path else "-"
        detail = f" ({self.detail})" if self.detail else ""
        return (
            f"verdict={self.verdict} votes={self.promotes}/{self.votes}"
            f"{detail} path={path}"
        )


def _vote_timed_out(path: Path) -> bool:
    try:
        vote = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return False
    return vote.get("timed_out") is True or vote.get("backend_rc") == 124


def _run_vote(
    validator: Path,
    finding: Path,
    target_path: Path,
    output: Path,
    backend: str,
    model: str,
    *,
    tiebreak: bool = False,
) -> int:
    command = [
        str(validator), "--backend", backend, "--finding", str(finding),
        "--target-path", str(target_path), "--output", str(output),
    ]
    if model:
        command[2:2] = ["--model", model]
    if tiebreak:
        command.append("--tiebreak")
    completed = subprocess.run(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
    )
    if completed.returncode == 3 and not _vote_timed_out(output):
        completed = subprocess.run(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
        )
    return completed.returncode


def validate_finding(
    finding: str | os.PathLike[str],
    target_path: str | os.PathLike[str],
    results_dir: str | os.PathLike[str] | None = None,
    *,
    backend: str | None = None,
    model: str | None = None,
    votes: int = 2,
    validator: str | os.PathLike[str] | None = None,
) -> ValidationResult:
    finding_path = Path(finding)
    finding_dir = finding_path.parent
    script_root = Path(__file__).resolve().parent.parent
    validator_path = Path(validator or script_root / "bin" / "validate-finding")
    if not validator_path.is_file() or not os.access(validator_path, os.X_OK):
        return ValidationResult(
            "Uncertain", 0, 0, None, f"validator missing: {validator_path}"
        )
    active_backend = (
        backend
        or os.environ.get("TRIAGE_VALIDATE_BACKEND")
        or os.environ.get("ACTIVE_BACKEND")
        or os.environ.get("BACKEND")
        or "claude"
    )
    active_model = model if model is not None else (
        os.environ.get("TRIAGE_VALIDATE_MODEL") or os.environ.get("MODEL") or ""
    )

    first = _run_vote(
        validator_path, finding_path, Path(target_path),
        finding_dir / "validator-vote-1.json", active_backend, active_model,
    )
    if votes == 1:
        if first == 0:
            return ValidationResult("Promote", 1, 1, finding_dir)
        if first == 1:
            return ValidationResult("Reject", 0, 1, finding_dir)
        detail = f"parse-failure backend={active_backend}" if first == 3 else ""
        return ValidationResult("Uncertain", 0, 1, finding_dir, detail)

    second = _run_vote(
        validator_path, finding_path, Path(target_path),
        finding_dir / "validator-vote-2.json", active_backend, active_model,
    )
    results = (first, second)
    promotes = sum(rc == 0 for rc in results)
    rejects = sum(rc == 1 for rc in results)
    parse_failures = sum(rc == 3 for rc in results)
    if parse_failures >= 2:
        return ValidationResult(
            "Uncertain", 0, 2, finding_dir,
            f"parse-failure backend={active_backend}",
        )
    if promotes >= 2:
        return ValidationResult("Promote", 2, 2, finding_dir)
    if rejects:
        return ValidationResult("Reject", promotes, 2, finding_dir, f"reject={rejects}")

    third = _run_vote(
        validator_path, finding_path, Path(target_path),
        finding_dir / "validator-vote-3.json", active_backend, active_model,
        tiebreak=True,
    )
    if third == 0:
        promotes += 1
        if promotes >= 2:
            return ValidationResult("Promote", promotes, 3, finding_dir, "tiebreak")
        return ValidationResult(
            "Uncertain", promotes, 3, finding_dir,
            "tiebreak agreed but lone Promote",
        )
    if third == 1:
        return ValidationResult("Reject", promotes, 3, finding_dir, "tiebreak Reject")
    detail = (
        f"tiebreak parse-failure backend={active_backend}"
        if third == 3 else "tiebreak Uncertain"
    )
    return ValidationResult("Uncertain", promotes, 3, finding_dir, detail)
