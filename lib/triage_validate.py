#!/usr/bin/env python3
"""Independent-validator quorum for source-backed findings."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


# Bump whenever the trigger-provenance prompt changes classification semantics.
# Old verdicts then fail open and receive a fresh source-reading review.
TRIGGER_GATE_DECISION_VERSION = "trigger-v2-caller-buffer"


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
