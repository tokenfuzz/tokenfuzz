#!/usr/bin/env python3
"""Trigger-provenance review facts and source anchors for findings."""

from __future__ import annotations

import hashlib
import os
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
    *, first_scope_open: bool = False,
) -> tuple[str, ...]:
    """Return the prior review files needed to resolve an unsettled gate.

    A Promote whose reviewer left `trigger_controls_fit` unclear settled
    reachability but not scope, and scope decides publication; it is re-asked
    the way an Uncertain is, or the artifact stays `pending` for good.
    """
    if first_vote == "Uncertain" or (first_vote == "Promote" and first_scope_open):
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
                leaf
                for candidate in tuple(symbol_candidates)
                if separator in candidate
                and (leaf := candidate.rsplit(separator, 1)[-1])
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
