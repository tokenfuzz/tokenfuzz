#!/usr/bin/env python3
"""recon_to_cards.py — Convert recon-hypotheses.jsonl into work-cards.jsonl
entries that the bin/audit strategy rotator can pick up.

Each substantive recon finding (CONFIRMED-* or NEEDS-VERIFICATION)
becomes the cross-product of work-cards over (enabled sanitizers) ×
(agent-suggested strategies). AUDIT-CLEAN entries are skipped. Work-card
fields follow the schema used by build_patch_cards() in lib/workqueue.py.

Fan-out rationale:
  Sanitizer: ASan alone misses several bug classes that are reachable
    via the same input (signed integer overflow caught by UBSan, uninit
    reads caught by MSan, data races by TSan). The list comes from the
    operator's target.toml [sanitizer].enabled — no hardcoded mapping.
  Strategy: strategies are angles of attack, not bug categories. The
    same OOB-read can be triggered via S5 (lifetime/state probing) or
    S7 (adversarial input). We fix the strategy set to (S5, S7) — two
    complementary shapes that cover most real bugs without making the
    agent emit a new schema field. Class-table single-strategy mapping
    is intentionally NOT used as a fallback (brittle to mislabels).

Card IDs are RECON-<sha>-<san>-<strategy>; each combination is one
independent probe attempt.

Class-to-strategy mapping (target-agnostic; chosen so the rotator picks
the strategy whose investigative shape best matches the finding's
expected primitive):

  UAF, double-free, OOB-read, OOB-write  -> S5 (Lifetime-and-state)
  integer-overflow                        -> S2 (Invariant-negation)
  DoS-amplification                       -> S8 (Property-oracle)
  info-leak                               -> S7 (Adversarial-input)
  protocol-state                          -> S3 (Spec-vs-impl)
  logic                                   -> S2 (Invariant-negation)
  other / unmatched                       -> S5 (default to lifetime)

Scoring rationale: recon cards must outrank generic S1 patch cards so the
rotator picks them first. Validator-promoted findings score higher than
unverified ones. The numbers are calibrated against build_patch_cards()
output which typically scores 20-60.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

CLASS_TO_STRATEGY = {
    "UAF": "S5",
    "double-free": "S5",
    "OOB-read": "S5",
    "OOB-write": "S5",
    "use-after-free": "S5",
    "integer-overflow": "S2",
    "DoS-amplification": "S8",
    "info-leak": "S7",
    "protocol-state": "S3",
    "logic": "S2",
}
DEFAULT_STRATEGY = "S5"

# Fixed strategy fan-out. Every recon finding gets one card per strategy
# in this list × one per enabled sanitizer. S5 (lifetime-and-state) and
# S7 (adversarial-input) cover complementary investigative shapes — S5
# chases reachability via API-sequence manipulation, S7 hammers the input
# surface. Two independent probe angles per finding regardless of class
# label accuracy. We deliberately don't ask the recon agent to suggest
# strategies: an extra schema field for marginal benefit, since (S5, S7)
# already cover the bulk of real bug shapes.
RECON_STRATEGIES = ("S5", "S7")

# Scoring — calibrated so a *validated* recon hypothesis outranks every
# generic ranked-source card. A Promote verdict means the recon agent
# named a concrete bug AND an independent validator pass re-verified it
# against the source — that is strictly more signal than a structural
# "this file has size_t / memcpy" feature score. Empirically (see
# benchmark output/benchmark/codex/20260523-070510), the prior
# SCORE_VALIDATOR_PROMOTED=90 left every Promote card sitting below a
# wall of ranked-source cards at 100-337, so they were never claimed in
# the 2-hour budget even though they named every bug the model-direct
# baseline found.
#
# New floor: Promote=1000 (above any structural-feature score we expect
# rank_target to emit), Confirmed-* slightly below, NEEDS-VERIFICATION
# below the typical ranked-source band so it surfaces only after
# explicit work is exhausted, Reject=10 (still in the pool but well
# below every other card class — see SCORE_VALIDATOR_REJECTED below).
SCORE_VALIDATOR_PROMOTED = 1000
SCORE_CONFIRMED_HIGH = 800
SCORE_CONFIRMED_MEDIUM = 600
SCORE_NEEDS_VERIFICATION = 200
# Reject stays a demote (not a drop). The validator is a heuristic
# LLM reviewer, not an oracle — ASan is. Dropping Reject cards
# entirely would discard a small but non-zero recovery path for
# real bugs misclassified by the validator. We push Reject to a
# very low score (below s1-patch's typical 80-140 band post-P3
# decay) so the rotator only drains them after every higher-signal
# card is exhausted — but they remain in the pool. Test
# coverage in test_recon_changes.sh enforces this contract.
SCORE_VALIDATOR_REJECTED = 10


def class_to_strategy(klass: str) -> str:
    if not klass:
        return DEFAULT_STRATEGY
    return CLASS_TO_STRATEGY.get(klass, DEFAULT_STRATEGY)


def score_for(finding: dict) -> int:
    verdict = (finding.get("validator_verdict") or "").lower()
    if verdict == "promote":
        return SCORE_VALIDATOR_PROMOTED
    if verdict == "reject":
        # Demote, don't delete. The card still probes; if the validator
        # was wrong (LLM-noisy Reject on a real bug), the sanitizer will
        # catch it on probe. Ranked below patch cards so high-confidence
        # work drains first.
        return SCORE_VALIDATOR_REJECTED
    # Missing/null confidence defaults to the lowest substantive tier so a
    # malformed row still gets one probe attempt rather than vanishing. See
    # the matching default in finding_to_card().
    conf = finding.get("confidence") or "NEEDS-VERIFICATION"
    if conf == "CONFIRMED-HIGH":
        return SCORE_CONFIRMED_HIGH
    if conf == "CONFIRMED-MEDIUM":
        return SCORE_CONFIRMED_MEDIUM
    if conf == "NEEDS-VERIFICATION":
        return SCORE_NEEDS_VERIFICATION
    return 0


def make_relative(path: str, target_path: str) -> str:
    """Strip the absolute target path prefix so the work-card's `file`
    field is portable. Leave bare relative paths alone."""
    if not path:
        return ""
    if target_path and path.startswith(target_path):
        return path[len(target_path):].lstrip("/")
    return path


def subsystem_for_path(rel_path: str) -> str:
    """Subsystem key for a target-relative path.

    Delegates to ``workqueue.subsystem_for`` (which honours the live
    per-target depth choice from ``state/subsystem-depth``) so that
    recon-derived work cards bucket into the SAME subsystem labels the
    rest of the queue uses. Without this, a flat src/ layout (pcre2,
    libxml2, etc.) collapses every recon card to a placeholder bucket
    ("root") while ranked-source cards bucket into "src/<file>", and
    the subsystem-diversity routing in _claim_next_card_locked starves
    the recon pool.
    """
    if not rel_path:
        return "other"
    # workqueue is imported lazily to avoid a circular import at module
    # load time (workqueue does not import recon_to_cards, but adding
    # an unconditional `from workqueue import ...` here would force any
    # consumer of recon_to_cards to pay the workqueue import cost). The
    # function is cheap; this path is hit O(recon-hypotheses) times.
    try:
        from workqueue import subsystem_for as _ws_subsystem_for
        return _ws_subsystem_for(rel_path)
    except Exception:
        # Defensive fallback: legacy first-segment keying, but unlike
        # the old code we return the bare filename (not "root") for
        # flat-layout targets so cards stay distinguishable.
        parts = [p for p in rel_path.split("/") if p]
        while parts and parts[0] in {"src", "lib"}:
            parts = parts[1:]
        return parts[0] if parts else "other"


def derive_card_id(
    target_slug: str,
    rec_id: str,
    file_path: str,
    line: int,
    sanitizer: str = "",
    strategy: str = "",
) -> str:
    """Stable card ID derived from the recon finding's identity plus the
    fan-out dimensions (sanitizer, strategy). Same (finding, sanitizer,
    strategy) tuple always maps to the same work-card so re-runs don't
    multiply cards in the queue.

    Suffixes are appended when non-empty so fan-out cards have distinct,
    debuggable IDs. Empty sanitizer + empty strategy preserves the legacy
    single-card-per-finding ID for back-compat with existing on-disk
    work-card pools.
    """
    key = f"{target_slug}:recon:{rec_id}:{file_path}:{line}"
    if sanitizer:
        key = f"{key}:{sanitizer}"
    if strategy:
        key = f"{key}:{strategy}"
    base = "WORK-recon-" + hashlib.sha1(key.encode()).hexdigest()[:10]
    suffix = ""
    if sanitizer:
        suffix += f"-{sanitizer}"
    if strategy:
        suffix += f"-{strategy}"
    return f"{base}{suffix}"


# ── FIND materialization ─────────────────────────────────────────────────
#
# Root-cause fix for benchmark undercount: recon already names a concrete
# defect (file:function:line + class + reasoning) for every non-AUDIT-CLEAN
# row. Historically those facts only existed inside the work-card pool, so
# the benchmark's `count_subdirs(findings/, "FIND-")` only saw a FIND when
# an agent later claimed the card AND produced a sanitizer reproducer. Two
# loss modes followed: (a) high-score Promote cards left unclaimed at
# timeout, (b) agents discarding ASan-clean leads as "parser quality only"
# even when recon had already identified a real security defect.
#
# materialize_find() lifts the FIND artifact upstream — recon naming a
# defect IS the FIND. Work cards then become evidence-gathering attempts
# against an existing FIND (the augment-don't-refile contract enforced by
# the agent prompt), not the gate that decides whether the FIND exists.
#
# No-double-count guarantees:
#   1. Deterministic id: FIND-RECON-<sha10(rec_id)>-<slug> — re-runs of
#      recon_to_cards, the per-sanitizer fan-out, and parallel agents all
#      converge on the same dir. report.md is written once (skip if it
#      already exists) so a re-run never clobbers agent augmentations.
#   2. Cards carry find_id pointing at the materialized dir. The agent
#      prompt forbids filing a fresh FIND-NNN for a card with find_id.
#   3. bin/cluster-findings signature dedup (file:func) collapses any
#      independently-filed FIND that happens to match — safety net only.
#
# No-overinflation guarantees:
#   1. AUDIT-CLEAN rows materialize nothing.
#   2. Rows missing any of {file, function, line>0, class, notes} are
#      treated as sparse — work card still emitted (so the agent can
#      investigate) but no FIND dir is created.
#   3. validator_verdict == "reject" routes the FIND directly to
#      findings-rejected/ (still counted in the rejected ledger but not in
#      the headline count).
#   4. The existing LLM-quality gate (triage.sh::llm_find_quality_decision)
#      and the validator-quorum gate (triage_validate_confirm_findings)
#      run over every FIND-* dir regardless of provenance; low-quality
#      auto-materialized FINDs get demoted by the same machinery that
#      handles agent-filed ones.

_SLUG_NONALNUM = re.compile(r"[^a-z0-9]+")


def _slug_from_title(title: str, fallback_id: str) -> str:
    """Short kebab-case slug for the FIND dir name.

    Slug is for human readability in dir listings; uniqueness is carried
    by the sha10 prefix. Empty title falls back to a short id-derived
    label so the resulting dir name is always at least
    FIND-RECON-<sha10>-untitled (never bare).
    """
    text = (title or "").strip().lower()
    text = _SLUG_NONALNUM.sub("-", text).strip("-")
    if not text:
        text = "untitled"
    # Cap at 40 chars so the full dir name stays under typical FS limits
    # with the FIND-RECON-<sha10>- prefix (12 + 10 + 1 = 23) and any
    # downstream suffixes a tool might add.
    if len(text) > 40:
        text = text[:40].rstrip("-")
    return text or "untitled"


def derive_find_id(rec_id: str, title: str) -> str:
    """Stable FIND id derived from the recon id + a slug of the title.

    Same recon row → same FIND id across re-runs, sanitizer fan-out, and
    parallel agents. Title slug is cosmetic; the sha10 carries uniqueness.
    """
    sha = hashlib.sha1(rec_id.encode()).hexdigest()[:10]
    slug = _slug_from_title(title, rec_id)
    return f"FIND-RECON-{sha}-{slug}"


def _has_find_fields(finding: dict, file_path: str, line: int) -> bool:
    """Field-completeness check for FIND materialization.

    A FIND needs enough detail for a reviewer to act on it without
    needing the work card. The gate is intentionally strict: a sparse
    recon row gets a work card (so the agent can investigate) but no
    FIND dir (so the benchmark count isn't inflated by claims a
    reviewer can't actually use).
    """
    if not file_path:
        return False
    if line <= 0:
        return False
    if not (finding.get("function") or "").strip():
        return False
    if not (finding.get("class") or "").strip():
        return False
    if not (finding.get("notes") or "").strip():
        return False
    return True


def _render_find_report(
    finding: dict,
    file_path: str,
    line: int,
    target_slug: str,
) -> str:
    """report.md content for a recon-materialized FIND.

    Shape mirrors what agents file (title, TL;DR, Summary, Location,
    Provenance) so the downstream LLM-quality gate and validator quorum
    judge it on the same rubric. The "Sanitizer evidence" line is the
    hook the augmenting agent overwrites once it runs the linked work
    card.
    """
    title = (finding.get("title") or "").strip() or finding.get("id", "Recon finding")
    klass = (finding.get("class") or "unspecified").strip()
    function = (finding.get("function") or "").strip()
    notes = (finding.get("notes") or "").strip()
    rec_id = finding.get("id", "")
    slice_name = (finding.get("slice") or "").strip()
    verdict = (finding.get("validator_verdict") or "").strip() or "unset"
    vdetails = (finding.get("validator_details") or "").strip()
    # Keep only the dedup anchor `duplicate of RECON-<hash>` (the bit
    # lib/benchmark._link_pool_recon_ids actually reads from the
    # rendered markdown); the rest of vdetails is internal noise —
    # verdict tallies, absolute /Users/.../output paths, deep-validator
    # debug lines — that an upstream maintainer doesn't need and that
    # we'd otherwise have to scrub at pool-render time.
    vdetails_keep = ""
    dup_m = re.search(r"duplicate of (RECON-[0-9a-f]+)", vdetails)
    if dup_m:
        vdetails_keep = f"duplicate of {dup_m.group(1)}"

    tldr_bug = f"`{file_path}:{function}:{line}` — {title}"
    # Section order: Title → TL;DR → Summary → Fields → Reproducer →
    # Sanitizer evidence → Reachability → Severity rationale. Summary
    # precedes Fields so the human-facing description anchors the
    # structured data. Location, Classification, and Provenance sections
    # are gone — their data lives in Fields (File / Function / Line /
    # Class / Severity) and in the canonical `file:func:line` token in
    # the TL;DR (which `finding_signature.extract_location` matches via
    # `_INLINE_FILE_FUNC_LINE_RE`). `_CLASS_PATTERNS` in finding_signature
    # has a Fields-table entry, so Class extraction still works after
    # the `- **Class**` bullet is dropped. `bin/reachability` skips the
    # `- **Severity**:` bullet entirely when the Fields-table Severity
    # row gets updated, so there's no risk of a stub Classification
    # heading being synthesized under us.
    lines = [
        f"# {title}",
        "",
        "<!-- enrich:tldr -->",
        "**Reviewer TL;DR**",
        "",
        f"- **Bug** — {tldr_bug}",
        f"- **Class** — {klass}",
        f"- **Origin** — recon stage ({slice_name or 'no slice'}); "
        f"validator verdict: {verdict}",
        "<!-- /enrich:tldr -->",
        "",
        "## Summary",
        "",
        notes,
        "",
        # Fields table mirrors the crash-report shape so a reviewer
        # sees the structured signal in one block. `Severity` is the
        # row bin/reachability rewrites on scoring; it starts as `TBD`
        # and becomes e.g. `Medium (32)` after the first reachability
        # pass.
        "## Fields",
        "",
        "| Field    | Value           |",
        "| :------- | :-------------- |",
        f"| Class    | {klass}         |",
        f"| Severity | TBD             |",
        f"| File     | `{file_path}`   |",
        f"| Function | `{function}`    |",
        f"| Line     | {line}          |",
        f"| Target   | `{target_slug}` |",
        "",
    ]
    # Optional dedup-anchor — the `duplicate of RECON-<hash>` substring
    # is read by `lib/benchmark._link_pool_recon_ids` to linkify the
    # surviving parent vote in pooled reports. Render as a bare paragraph
    # so render-md's bare-label suppression keeps it out of the HTML view.
    if vdetails_keep:
        lines.append(f"Validator details: {vdetails_keep}")
        lines.append("")
    lines += [
        # Lone audit-only metadata row: `Recon ID` is parsed by
        # `lib/benchmark._link_pool_recon_ids` to linkify the recon
        # vote that promoted the FIND. `Source` and `Slice` were never
        # parsed and are dropped. The line stays on its own bare-label
        # paragraph so render-md's bare-label suppression hides it from
        # the rendered HTML — the audit operator still sees it in the
        # markdown view, but it doesn't clutter the upstream-facing
        # report.html.
        f"Recon ID: {rec_id}",
        "",
        "## Sanitizer evidence",
        "",
        "_not yet attempted — augmented by the agent that claims the linked "
        "work card; ASan-clean does not invalidate this FIND (recon already "
        "named the defect from source). See the linked work card for "
        "reproducer attempts._",
        "",
    ]
    return "\n".join(lines)


def materialize_find(
    finding: dict,
    target_slug: str,
    file_path: str,
    line: int,
    results_dir: Path | None,
) -> str:
    """Create FIND-RECON-* dir for a recon row, return its id (or "").

    Returns the FIND id when a dir was created or already existed; "" when
    materialization was skipped (missing results_dir, AUDIT-CLEAN, or
    sparse fields). The empty-return path is what lets non-find_id work
    cards continue to flow through the queue as before.

    Routing:
      validator_verdict == "reject"  →  skipped (no FIND); the agent's
                                         work card still flows and can
                                         file a FIND from scratch if a
                                         probe proves the validator wrong
      AUDIT-CLEAN                    →  skipped
      sparse fields                  →  skipped
      everything else                →  results_dir/findings/<id>/

    Why Reject is skipped (not routed to findings-rejected/):
      The validator emitted a substantive negative judgment. Materializing
      Reject as a FIND artifact would:
        1. Inflate the findings_rejected metric across the change boundary
           in a way that breaks run-to-run comparability.
        2. Force any augmenting agent to write into findings-rejected/,
           making it harder for a sanitizer-confirmed bug to land in the
           headline findings/ bucket.
        3. Couple the PRE-FILED FIND prompt block to a path the agent
           would have to override to promote the FIND back.
      The work card still emits without find_id, so an agent who *does*
      reproduce the bug files a fresh FIND-NNN-* the normal way. The
      validator's negative signal is preserved by the score floor in
      score_for() (SCORE_VALIDATOR_REJECTED).

    Idempotent: if report.md already exists in the destination, do not
    overwrite — agent augmentations (ASan output, reproducer, severity
    bumps) survive a recon re-run unmolested.
    """
    if results_dir is None:
        return ""
    if not _has_find_fields(finding, file_path, line):
        return ""
    rec_id = finding.get("id", "")
    if not rec_id:
        return ""
    confidence = finding.get("confidence") or "NEEDS-VERIFICATION"
    if confidence == "AUDIT-CLEAN":
        return ""
    verdict = (finding.get("validator_verdict") or "").strip().lower()
    if verdict == "reject":
        return ""
    find_id = derive_find_id(rec_id, finding.get("title", ""))
    find_dir = results_dir / "findings" / find_id
    find_dir.mkdir(parents=True, exist_ok=True)
    report = find_dir / "report.md"
    if not report.exists():
        report.write_text(
            _render_find_report(finding, file_path, line, target_slug),
            encoding="utf-8",
        )
    return find_id


# ── Mechanical augment-don't-refile guard ───────────────────────────────
#
# The agent prompt instructs that any work card with a find_id must
# augment the linked FIND-RECON-* dir rather than file a fresh
# FIND-NNN-*. Prompt compliance is soft — an agent could ignore the
# instruction and create a duplicate. This function is the mechanical
# enforcement: at validate-gate / benchmark time, any agent-filed FIND
# whose (file, function) signature collides with an existing
# FIND-RECON-* gets moved into findings-rejected/ with a sentinel
# annotation. The recon-materialized FIND remains canonical; the
# headline `count_subdirs(findings, FIND-*)` stays bounded by recon-
# unique-defects + agent-unique-defects (no double-count for the same
# defect filed both ways).
#
# Idempotent: re-running after a sweep is a no-op because the moved
# dirs no longer live under findings_dir. False-positive risk is
# bounded by requiring BOTH file and function to match — distinct
# defects in the same function are rare in practice and would be
# caught by cluster-findings' richer signature.


def _read_report_text(find_dir: Path) -> str:
    """Best-effort read of the primary report file in a FIND dir."""
    for name in ("REPORT.md", "report.md", "description.md",
                 "analysis.md", "README.md"):
        path = find_dir / name
        if path.is_file():
            try:
                return path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return ""
    return ""


def _extract_find_signature(
    find_dir: Path,
    target_root: str,
) -> tuple[str, str, str]:
    """(file, function, class) signature for a FIND dir, using the same
    extraction the cluster-findings pipeline uses.

    Class is included so two DISTINCT defects in the same function
    (e.g. a UAF on line 100 and an integer-overflow on line 150) do not
    collapse to the same signature and get incorrectly deduped. This is
    the load-bearing fix against the capability-regression risk where
    the augment-don't-refile sweep would otherwise hide an agent-found
    bug whose class differs from the recon-named one.

    Class is normalized via finding_signature.normalize_class so
    surface variations ("memory-safety:bounds" vs "OOB-read" vs "bounds")
    don't defeat the match. Class "" (extractor found no class label)
    is preserved as "" rather than coerced to "other" — an unknown
    class deduping against another unknown class would be wrong, so we
    leave the dedup gate to require BOTH non-empty for a match.
    """
    text = _read_report_text(find_dir)
    if not text:
        return ("", "", "")
    try:
        from finding_signature import (
            extract_class,
            extract_location,
            normalize_class,
        )
        f, fn = extract_location(text, target_root)
        raw_class = extract_class(text)
        # normalize_class returns "other" for empty input; we want "" to
        # signal "no extractable class" so the dedup gate can reject the
        # match. Only normalize when extract_class found something.
        klass = normalize_class(raw_class) if raw_class else ""
        return (f, fn, klass)
    except Exception:
        return ("", "", "")


def dedupe_recon_findings(
    findings_dir: Path,
    rejected_dir: Path,
    target_root: str = "",
) -> list[tuple[str, str]]:
    """Move agent-filed FIND-* dirs that duplicate a FIND-RECON-* by
    (file, function) into rejected_dir. Returns the list of
    (moved_id, canonical_recon_id) pairs.

    The mechanical complement to the augment-don't-refile prompt
    contract. Safe to call repeatedly: nothing happens once duplicates
    have been moved.
    """
    import shutil
    findings_dir = Path(findings_dir)
    rejected_dir = Path(rejected_dir)
    if not findings_dir.is_dir():
        return []
    # Index 1: signatures held by recon-materialized FINDs.
    # Signature is (file, function, class). All three must be non-empty
    # for the match to fire — see _extract_find_signature for the
    # rationale on why class is included (distinct defects in the same
    # function would otherwise be wrongly collapsed).
    recon_sigs: dict[tuple[str, str, str], str] = {}
    for d in sorted(findings_dir.glob("FIND-RECON-*")):
        if not d.is_dir():
            continue
        sig = _extract_find_signature(d, target_root)
        if sig[0] and sig[1] and sig[2] and sig not in recon_sigs:
            recon_sigs[sig] = d.name
    if not recon_sigs:
        return []
    moved: list[tuple[str, str]] = []
    for d in sorted(findings_dir.glob("FIND-*")):
        if not d.is_dir():
            continue
        if d.name.startswith("FIND-RECON-"):
            continue
        # Operator pin: .keep / .reviewed marks a FIND as human-approved;
        # never auto-move those (mirrors validate_find_gate behavior).
        if (d / ".keep").is_file() or (d / ".reviewed").is_file():
            continue
        sig = _extract_find_signature(d, target_root)
        # All three signature components must be non-empty AND match.
        # Missing class on either side → no dedup (safer to keep a
        # potential duplicate than to wrongly hide a distinct bug).
        if not (sig[0] and sig[1] and sig[2]):
            continue
        canonical = recon_sigs.get(sig)
        if not canonical:
            continue
        rejected_dir.mkdir(parents=True, exist_ok=True)
        target = rejected_dir / d.name
        if target.exists():
            target = rejected_dir / f"{d.name}.dup-{int(time.time())}"
        # Audit-trail sentinel: the moved dir carries a note saying why,
        # so a QA reviewer who opens findings-rejected/ later understands
        # this was a programmatic dedup, not an LLM-quality reject.
        try:
            note = d / ".duplicate-of-recon"
            note.write_text(
                f"duplicates: {canonical}\n"
                f"signature: file={sig[0]} function={sig[1]} "
                f"class={sig[2]}\n"
                f"moved_at: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
                "reason: agent-filed FIND collides with a recon-materialized "
                "FIND for the same (file, function, class); moved here to keep "
                "the headline finding count bounded. Recon-materialized FIND "
                "remains the canonical record.\n",
                encoding="utf-8",
            )
        except OSError:
            pass
        try:
            shutil.move(str(d), str(target))
        except OSError:
            continue
        moved.append((d.name, canonical))
    return moved


def finding_to_cards(
    finding: dict,
    target_slug: str,
    target_path: str,
    sanitizers: list[str],
    results_dir: Path | None = None,
) -> list[dict]:
    """Convert one recon finding into the cross-product of work-cards
    spanning (enabled sanitizers) × (suggested strategies).

    Returns [] for findings that should be dropped (AUDIT-CLEAN, missing
    rec_id, score <= 0). Each card has a distinct ID so the rotator can
    interleave independent probes."""
    # Only AUDIT-CLEAN is an explicit "scanned, nothing here" signal — drop it.
    # A missing / null / empty confidence field is treated as the lowest
    # substantive tier (NEEDS-VERIFICATION) rather than silently dropped,
    # because older recon-hypotheses.jsonl rows sometimes lack the field
    # and we'd lose real findings on a re-run.
    confidence = finding.get("confidence") or "NEEDS-VERIFICATION"
    if confidence == "AUDIT-CLEAN":
        return []
    rec_id = finding.get("id") or ""
    if not (rec_id.startswith("RECON-") or rec_id.startswith("REC-")):
        return []
    file_path = make_relative(finding.get("file") or "", target_path)
    line = int(finding.get("line") or 0)
    klass = finding.get("class") or "other"
    score = score_for(finding)
    if score <= 0:
        return []
    # Strategy fan-out: fixed (S5, S7) pair, no class-table single-strategy
    # mapping. We don't ask the agent to suggest strategies — that's an
    # extra schema field for marginal benefit. Two complementary
    # investigative angles per finding cover most real bug shapes.
    strategies = list(RECON_STRATEGIES)
    title = (finding.get("title") or "").strip()
    notes = (finding.get("notes") or "").strip()
    verdict = finding.get("validator_verdict") or ""
    reason_parts = [
        f"recon hypothesis ({confidence})",
        f"class={klass}",
    ]
    if verdict:
        reason_parts.append(f"validator={verdict}")
    if title:
        reason_parts.append(title)
    if notes:
        reason_parts.append(notes[:140])
    reason = " | ".join(p for p in reason_parts if p)
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    recon_block = {
        "id": rec_id,
        "confidence": confidence,
        "validator_verdict": verdict or None,
        "line": line,
        "class": klass,
        "strategies": strategies,
    }
    # P7: validator-Promoted findings collapse to ONE card per sanitizer
    # with `allowed_strategies` covering the full RECON_STRATEGIES set,
    # instead of fanning out one card per strategy. Rationale:
    #
    #   - Promote is already the strongest pre-probe signal we have, and
    #     the P3 precedence gate steers any agent onto the card regardless
    #     of strategy filter. The per-strategy fan-out was diluting that
    #     signal — 5 Promote findings × 2 strategies = 10 separate cards,
    #     each occupying a queue slot and tripping the subsystem
    #     diversity floor as if they were independent leads.
    #   - With one consolidated card, the diversity floor sees a single
    #     promoted entry per (finding, sanitizer), and `allowed_strategies`
    #     keeps the card claimable from any of S5/S7 when an agent does
    #     have a strategy filter.
    #
    # Non-Promote findings keep the per-strategy fan-out: those are
    # NEEDS-VERIFICATION / CONFIRMED-* leads where two independent probe
    # angles (S5 lifetime, S7 adversarial-input) are worth exploring
    # separately, since neither has the validator's seal.
    # Materialize the FIND-RECON-* dir BEFORE emitting cards so every
    # card we emit can carry the find_id pointer. Returns "" when results_dir
    # is missing (back-compat callers) or the row is too sparse to be a
    # standalone finding — in those cases the cards still go out, just
    # without a find_id, and the legacy "agent decides whether to file"
    # path applies.
    find_id = materialize_find(finding, target_slug, file_path, line, results_dir)
    is_promoted = (verdict or "").strip().lower() == "promote"
    sans = sanitizers or ["asan"]
    cards: list[dict] = []
    if is_promoted:
        primary_strategy = "S7" if "S7" in strategies else strategies[0]
        for san in sans:
            card = {
                "id": derive_card_id(target_slug, rec_id, file_path, line, san, ""),
                "kind": "recon-hypothesis",
                "target_slug": target_slug,
                "subsystem": subsystem_for_path(file_path),
                "file": file_path,
                "function": finding.get("function") or "",
                "mode": san,
                "strategy": primary_strategy,
                "allowed_strategies": list(strategies),
                "score": score,
                "seed": None,
                "patch_cards": [],
                "reason": reason,
                "status": "unclaimed",
                "created_at": created_at,
                "recon": recon_block,
            }
            if find_id:
                card["find_id"] = find_id
            cards.append(card)
        return cards
    for san in sans:
        for strat in strategies:
            card = {
                "id": derive_card_id(target_slug, rec_id, file_path, line, san, strat),
                "kind": "recon-hypothesis",
                "target_slug": target_slug,
                "subsystem": subsystem_for_path(file_path),
                "file": file_path,
                "function": finding.get("function") or "",
                "mode": san,
                "strategy": strat,
                "score": score,
                "seed": None,
                "patch_cards": [],
                "reason": reason,
                "status": "unclaimed",
                "created_at": created_at,
                "recon": recon_block,
            }
            if find_id:
                card["find_id"] = find_id
            cards.append(card)
    return cards


def load_jsonl(path: Path, label: str = "") -> list[dict]:
    """Load a JSONL file, tolerating blank and malformed lines.

    Malformed lines are skipped but counted; the count is logged to stderr
    so a silent recon-cache poisoning incident is visible (previously the
    parse failures were swallowed with no diagnostic at all).
    """
    out: list[dict] = []
    if not path.exists():
        return out
    dropped = 0
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                dropped += 1
                continue
    if dropped:
        tag = f" ({label})" if label else ""
        print(
            f"recon_to_cards: dropped {dropped} unparseable JSONL line(s) from "
            f"{path}{tag}",
            file=sys.stderr,
        )
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Convert recon-hypotheses.jsonl into work-cards.jsonl entries."
    )
    ap.add_argument(
        "--dedupe-only", action="store_true",
        help="Run the augment-don't-refile dedup sweep against an existing "
        "findings/ tree (no recon → cards conversion). Requires --results-dir. "
        "Moves any agent-filed FIND-* whose (file,function) signature collides "
        "with an existing FIND-RECON-* into findings-rejected/. Intended to be "
        "called periodically by validate_find_gate.",
    )
    ap.add_argument("--target-slug", default="")
    ap.add_argument("--target-path", default="",
                    help="Absolute target source root, for relativising the .file field")
    ap.add_argument("--recon-jsonl", default="",
                    help="Path to recon-hypotheses.jsonl (required unless --dedupe-only)")
    ap.add_argument("--work-cards", default="",
                    help="Path to work-cards.jsonl (will be MERGED with: existing "
                    "cards kept, recon-hypothesis cards rewritten)")
    ap.add_argument(
        "--sanitizers", default="",
        help="Comma-separated list of sanitizers to fan out per finding "
        "(e.g. 'asan,ubsan'). Sourced from target.toml [sanitizer].enabled "
        "by the caller. Empty or missing → default to 'asan' only for "
        "back-compat with older callers.",
    )
    ap.add_argument(
        "--results-dir", default="",
        help="Results directory under which to materialize FIND-RECON-* dirs "
        "(non-AUDIT-CLEAN recon rows that pass the field-completeness gate "
        "get a FIND in <results-dir>/findings/; validator-Reject rows go to "
        "<results-dir>/findings-rejected/). When omitted, no FINDs are "
        "materialized and emitted cards have no find_id — preserves the "
        "pre-fix behavior for callers that do not yet pass this arg.",
    )
    ap.add_argument(
        "--quiet", action="store_true",
        help="Suppress per-card stderr output (still prints a one-line summary)",
    )
    args = ap.parse_args(argv)

    results_dir: Path | None = None
    if args.results_dir:
        results_dir = Path(args.results_dir).expanduser().resolve()

    # Dedupe-only mode: skip the recon→cards conversion entirely, just
    # run the augment-don't-refile sweep against an existing tree.
    if args.dedupe_only:
        if results_dir is None:
            print("recon_to_cards: --dedupe-only requires --results-dir",
                  file=sys.stderr)
            return 2
        target_root = ""
        if args.target_path:
            target_root = str(Path(args.target_path).expanduser().resolve())
        moved = dedupe_recon_findings(
            results_dir / "findings",
            results_dir / "findings-rejected",
            target_root=target_root,
        )
        if not args.quiet:
            print(
                f"recon_to_cards: dedupe moved {len(moved)} agent-filed FIND(s) "
                f"that duplicated a recon-materialized FIND",
                file=sys.stderr,
            )
            for moved_id, canonical in moved:
                print(f"  - {moved_id} → findings-rejected/ (canonical: {canonical})",
                      file=sys.stderr)
        return 0

    # Conversion mode: require the conversion-specific args that were
    # previously declared as `required=True`. We validate here so both
    # modes can share the same argparse without conflict.
    missing = [
        name for name in ("target_slug", "target_path", "recon_jsonl", "work_cards")
        if not getattr(args, name, "")
    ]
    if missing:
        print(
            f"recon_to_cards: missing required arg(s) for conversion mode: "
            f"{', '.join('--' + n.replace('_', '-') for n in missing)}",
            file=sys.stderr,
        )
        return 2
    recon_path = Path(args.recon_jsonl).expanduser().resolve()
    cards_path = Path(args.work_cards).expanduser().resolve()
    target_path = str(Path(args.target_path).expanduser().resolve())
    sanitizers = [s.strip() for s in (args.sanitizers or "").split(",") if s.strip()]

    findings = load_jsonl(recon_path, label="recon")
    if not findings:
        if not args.quiet:
            print(f"recon_to_cards: no findings in {recon_path}; nothing to do",
                  file=sys.stderr)
        return 0

    new_cards = []
    seen_ids = set()
    for f in findings:
        for card in finding_to_cards(
            f, args.target_slug, target_path, sanitizers,
            results_dir=results_dir,
        ):
            if card["id"] in seen_ids:
                continue
            seen_ids.add(card["id"])
            new_cards.append(card)

    # Merge with existing cards: keep non-recon cards verbatim; replace
    # any existing recon-hypothesis cards with the new set (so a re-run
    # cleanly updates the recon pool without leaving stale entries).
    existing = load_jsonl(cards_path, label="work-cards")
    kept_existing = [c for c in existing if c.get("kind") != "recon-hypothesis"]

    cards_path.parent.mkdir(parents=True, exist_ok=True)
    with cards_path.open("w", encoding="utf-8") as f:
        for c in kept_existing:
            f.write(json.dumps(c, separators=(",", ":")) + "\n")
        for c in new_cards:
            f.write(json.dumps(c, separators=(",", ":")) + "\n")

    if not args.quiet:
        by_conf: dict[str, int] = {}
        for c in new_cards:
            by_conf[c["recon"]["confidence"]] = by_conf.get(c["recon"]["confidence"], 0) + 1
        breakdown = ", ".join(f"{k}={v}" for k, v in sorted(by_conf.items()))
        # Count distinct FINDs materialized (cards share find_id by
        # design — multi-sanitizer fan-out maps to one FIND per recon row).
        find_ids = {c["find_id"] for c in new_cards if c.get("find_id")}
        find_msg = ""
        if results_dir is not None:
            find_msg = f"; materialized {len(find_ids)} FIND-RECON-* dir(s)"
        print(
            f"recon_to_cards: wrote {len(new_cards)} recon-hypothesis card(s) "
            f"({breakdown or 'empty'}); kept {len(kept_existing)} other card(s)"
            f"{find_msg}",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
