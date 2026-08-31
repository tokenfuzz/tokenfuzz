#!/usr/bin/env python3
"""Crash and finding promotion gates plus artifact index maintenance."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import benchmark
import cluster_common
import crash_artifacts
import crash_bundle
import finding_signature
import llm_decide
import llm_usage
import report_identity
import stack_frames
import triage_validate
import validation_receipt
import workqueue
from prompt_render import render_template

SCRIPT_ROOT = Path(__file__).resolve().parent.parent

_TRIGGER_PRIMARY_NAME = ".trigger-gate.json"
_TRIGGER_SECOND_NAME = ".trigger-gate-2.json"
_TRIGGER_RESOLUTION_NAME = ".trigger-gate-resolution.json"
_TRIGGER_REVIEW_NAMES = (_TRIGGER_PRIMARY_NAME, _TRIGGER_SECOND_NAME)
_TRIGGER_EVIDENCE_NAMES = (*_TRIGGER_REVIEW_NAMES, _TRIGGER_RESOLUTION_NAME)

_DIAGNOSTIC = re.compile(
    r"ERROR: (?:AddressSanitizer|HWAddressSanitizer|UndefinedBehaviorSanitizer)"
    r"|SUMMARY: (?:AddressSanitizer|HWAddressSanitizer|UndefinedBehaviorSanitizer)"
    r"|WARNING: (?:ThreadSanitizer|MemorySanitizer):|SUMMARY: (?:ThreadSanitizer|MemorySanitizer):"
    r"|^WARNING: DATA RACE$|UndefinedBehaviorSanitizer:"
    r"|^[^\s].*:\d+:\d+: runtime error:",
    re.MULTILINE,
)
# Language-runtime crash signals accepted in place of a sanitizer diagnostic on
# findings-only targets ([sanitizer] enabled = []). Once the artifact is complete,
# these signals are demoted to findings instead of promoted as sanitizer crashes.
_RUNTIME_DIAGNOSTIC = re.compile(
    r"panic: runtime error:|fatal error: (?:stack overflow|out of memory|concurrent map)|^goroutine \d+ \["
    r"|^thread '[^']*'(?: \([^)]*\))? panicked at|fatal runtime error:"
    r"|^Exception in thread|java\.lang\.(?:OutOfMemoryError|StackOverflowError|NullPointerException"
    r"|IndexOutOfBoundsException|VerifyError|ClassCastException)"
    r"|^Fatal Python error:|^Traceback \(most recent call last\):"
    r"|^\[BUG\]|\(NoMemoryError\)|SystemStackError|stack level too deep"
    r"|^FATAL ERROR:.*(?:heap out of memory|Allocation failed)|RangeError: Maximum call stack"
    r"|^PHP Fatal error:|^Fatal error:|^Uncaught \w+Error:",
    re.MULTILINE,
)
# The ASan half is answered by the shared vocabulary in lib/stack_frames.py: a
# private copy here went stale against the runtime and cost a reproducing crash
# its verdict.
_OTHER_MEMORY_SAFETY = re.compile(
    r"WARNING: ThreadSanitizer: (?:data race|heap-use-after-free)"
    r"|WARNING: MemorySanitizer: use-of-uninitialized-value"
    r"|(?:ERROR|SUMMARY): HWAddressSanitizer: tag-mismatch"
    r"|^WARNING: DATA RACE$"
    r"|SEGV on unknown address 0x0*[1-9a-fA-F][0-9a-fA-F]{3,}"
    r"|SCARINESS: \d+ \(wild-addr",
    re.MULTILINE,
)
_UBSAN_REPORT = re.compile(
    r"UndefinedBehaviorSanitizer|^[^\s].*:\d+:\d+: runtime error:",
    re.MULTILINE,
)
_UBSAN_SECURITY = re.compile(
    r"through pointer to incorrect function type|out of bounds for type"
    r"|with insufficient space for an object of type"
    r"|variable length array bound evaluates to non-positive value"
    r"|does not point to an object of type",
    re.IGNORECASE,
)
_DEBUG_ASSERT = re.compile(
    r"^Assertion failed:|__assert_rtn|__assert_fail"
    r"|^\s*#\d+ .* in [A-Z][A-Z0-9_]*(?:ASSERT|CHECK)\b",
    re.MULTILINE,
)
_ABORT_SIGNAL = re.compile(r"AddressSanitizer: ABRT|SIGABRT")
_AUTO_REJECT = (
    (re.compile(r"Hint: address points to the zero page|SCARINESS: \d+ \(null-deref\)|SEGV on unknown address 0x0+(?:[^0-9a-fA-F]|$)"), "null-deref"),
    (re.compile(r"AddressSanitizer: stack-overflow(?: |$)"), "stack exhaustion"),
    (re.compile(r"AddressSanitizer: (?:allocation-size-too-big|out-of-memory)|AddressSanitizer failed to allocate|requested allocation size .* exceeds maximum|rss limit (?:exhausted|exceeded)"), "resource exhaustion"),
    (re.compile(r"(?:^|[][\s:>])Hit MOZ_CRASH\(|^Assertion failure:|###!!! ASSERTION:", re.MULTILINE), "intentional assertion crash"),
    (re.compile(r"^thread '[^']*'(?: \([^)]*\))? panicked at |\bRustMozCrash\b", re.MULTILINE), "runtime panic"),
)


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        return default
    return value if value >= 1 else default


def _read(path: Path, limit: int = 1_000_000) -> str:
    try:
        size = path.stat().st_size
        with path.open("rb") as stream:
            if size <= limit:
                data = stream.read()
            else:
                tail = limit // 2
                head = limit - tail
                data = stream.read(head)
                stream.seek(-tail, os.SEEK_END)
                data += stream.read(tail)
        return data.decode("utf-8", errors="replace")
    except OSError:
        return ""


def _decision_timeout(default: int, deadline: float | None) -> int:
    if deadline is None:
        return default
    remaining = int(deadline - time.monotonic())
    return max(0, min(default, remaining))


def _deadline_expired(deadline: float | None) -> bool:
    return deadline is not None and time.monotonic() >= deadline


def _report(directory: Path) -> Path | None:
    """The shared report path, with triage's stricter non-empty requirement.

    An empty file is a report an agent created and has not written yet; gating
    on it would score a placeholder.
    """
    candidate = report_identity.find_report(directory)
    return candidate if candidate is not None and candidate.stat().st_size else None


def _sanitizer_file(directory: Path) -> Path | None:
    exact = directory / "sanitizer.txt"
    if exact.is_file() and exact.stat().st_size:
        return exact
    found = crash_artifacts.find_primary_sanitizer((directory, directory / ".audit"))
    return found if found and found.is_file() else None


def has_valid_diagnostic(text: str, findings_only: bool = False) -> bool:
    """A crash must prove itself with a sanitizer diagnostic. A findings-only
    target has no instrumented build, so a language-runtime diagnostic (Go panic,
    Python traceback, JVM exception, ...) is the strongest proof available and
    stands in for one."""
    if _DIAGNOSTIC.search(text):
        return True
    return findings_only and bool(_RUNTIME_DIAGNOSTIC.search(text))


def _runtime_only_diagnostic(text: str, findings_only: bool) -> bool:
    return (
        findings_only
        and bool(_RUNTIME_DIAGNOSTIC.search(text))
        and not _DIAGNOSTIC.search(text)
    )


def autodiscard_reason(text: str) -> str:
    if (
        stack_frames.memory_safety_class(text)
        or _OTHER_MEMORY_SAFETY.search(text)
        or _ubsan_class(text) == "security"
    ):
        return ""
    if _DEBUG_ASSERT.search(text) and _ABORT_SIGNAL.search(text):
        return "debug assertion abort"
    for pattern, reason in _AUTO_REJECT:
        if pattern.search(text):
            return reason
    if re.search(r"SIGABRT|^abort\(\)|libsystem_kernel.*__pthread_kill", text, re.MULTILINE) and not _DIAGNOSTIC.search(text):
        return "abort without sanitizer diagnostic"
    return ""


def _unique_destination(root: Path, name: str) -> Path:
    destination = root / name
    if not destination.exists():
        return destination
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    serial = 1
    while True:
        candidate = root / f"{name}.{stamp}.{serial}"
        if not candidate.exists():
            return candidate
        serial += 1


def _annotate_rejection(directory: Path, reason: str) -> None:
    (directory / "REJECTION.md").write_text(
        "# Rejected artifact\n\n"
        f"Reason: {reason}\n\n"
        "The original evidence is retained for audit and can be restored after review.\n",
        encoding="utf-8",
    )


def _unreachable_route_summary(text: str, limit: int = 300) -> str:
    """A disproof reduced to one bounded line.

    Truncating the whole text keeps the clause label *and* the start of the
    blocking invariant. Taking the leading sentence instead would keep only
    "Clause (c)." — the label alone tells a later session nothing about which
    route was closed.
    """
    compact = " ".join(str(text).split())
    if len(compact) <= limit:
        return compact
    return compact[: limit - 1].rstrip() + "…"


def _record_unreachable_route(directory: Path, results_dir: Path) -> None:
    """Keep the disproof that killed a trigger route where an agent will read it.

    The gate writes a precise, anchored reason for every trigger rejection and
    then only the artifact moves — nothing carries that reason back to a
    session. Measured over four targets, 55% of trigger rejections landed on a
    file that had already produced one in the same run, and each repeat paid a
    full harness / confirm / bundle / enrich cycle to re-derive the same
    answer. Recording the route is advisory only: it never removes a card and
    never blocks a claim, so a different route to the same defect stays open.
    """
    row: dict | None = None
    for name in _TRIGGER_EVIDENCE_NAMES:
        vote = _finding_cache(directory / name)
        summary = _unreachable_route_summary(vote.get("disproof", ""))
        anchors = vote.get("anchors") or []
        # An unverified anchor set is the reviewer's unchecked claim about
        # where the code is; keying advice on it would put the note on a file
        # nobody confirmed it belongs to.
        if (
            not summary or vote.get("anchors_verified") is False
            or not isinstance(anchors, list)
        ):
            continue
        sites = [
            {
                "file": workqueue.normalized_relpath(str(a.get("path", ""))),
                "symbol": str(a.get("symbol", "")),
                "line": a.get("line", ""),
            }
            for a in anchors if isinstance(a, dict) and a.get("path")
        ]
        sites = [s for s in sites if s["file"]]
        if not sites:
            continue
        # Every verified anchor, not just the first: the schema fixes no
        # primary, and on the measured runs the leading anchor was a
        # different file from the reported one 17 times in 61. Landing the
        # note on each file the disproof actually names is the recoverable
        # error; landing it on none of them is not.
        row = {
            "sites": sites,
            "artifact": directory.name,
            "lane": directory.parent.name,
            "summary": summary,
            "recorded_at": workqueue.now_iso(),
        }
        break
    if row is None:
        return
    try:
        workqueue.append_jsonl(
            results_dir / "state" / "unreachable-routes.jsonl", row,
        )
    except OSError as exc:
        # Advisory context for a later session; never worth failing a
        # rejection that has already been decided.
        print(
            f"WARN: could not record unreachable route for {directory.name}: {exc}",
            file=sys.stderr,
        )


def _retract_unreachable_route(directory: Path, results_dir: Path) -> None:
    """Retire advice tied to one rejection before its path can be reused."""
    path = results_dir / "state" / "unreachable-routes.jsonl"
    if not path.is_file():
        return
    lane = directory.parent.name
    artifact = directory.name

    def remove(rows: list[dict]) -> int:
        before = len(rows)
        rows[:] = [
            row for row in rows
            if not (
                isinstance(row, dict)
                and row.get("lane") == lane
                and row.get("artifact") == artifact
            )
        ]
        return before - len(rows)

    try:
        workqueue.update_jsonl(path, remove)
    except OSError as exc:
        # The move already reopens the artifact and therefore suppresses the
        # note. Warn because a later rejection could reuse this path; never
        # strand an artifact in the rejected lane over advisory context.
        print(
            f"WARN: could not retract unreachable route for {artifact}: {exc}",
            file=sys.stderr,
        )


def _reject(
    directory: Path, rejected_root: Path, reason: str, *, category: str = "",
) -> Path:
    rejected_root.mkdir(parents=True, exist_ok=True)
    _annotate_rejection(directory, reason)
    validation_receipt.write(
        directory,
        kind="crash" if directory.name.startswith("CRASH-") else "finding",
        state="rejected",
        detail=reason,
    )
    destination = _unique_destination(rejected_root, directory.name)
    shutil.move(str(directory), destination)
    if category == workqueue.UNREACHABLE_REJECTION_CATEGORY:
        # Only after the move lands, and keyed to where it landed: the note
        # tells a session not to rebuild a reproducer, so it must never
        # outlive the rejection it describes. A failed move leaves the
        # artifact active and records nothing; a later requeue moves the
        # artifact back out and the note stops rendering with it.
        _record_unreachable_route(destination, rejected_root.parent)
    try:
        workqueue.record_artifact_rejection(
            rejected_root.parent, directory.name, reason, category=category,
        )
    except OSError as exc:
        print(
            f"WARN: could not record structured rejection for {directory.name}: {exc}",
            file=sys.stderr,
        )
    return destination


_TRIGGER_REJECTION_RE = re.compile(
    r"^trigger-provenance(?:\s|\(|:)", re.IGNORECASE,
)


def _rejection_reason(directory: Path) -> str:
    try:
        text = (directory / "REJECTION.md").read_text(
            encoding="utf-8", errors="replace",
        )
    except OSError:
        return ""
    match = re.search(r"^Reason:\s*(.+)$", text, re.MULTILINE)
    return match.group(1).strip() if match else ""


_DISPOSITIVE_REJECTION_KINDS = frozenset({
    "contract-invalid", "unreachable", "nonshipping",
})
# A reachable trigger whose exact claimed consequence source contradicts. Only
# a source-only finding may be removed this way: a sanitizer diagnostic stays
# concrete crash evidence even when its report overstates the impact, and crash
# classification and severity handle that case.
_CONSEQUENCE_REJECTION_KIND = "consequence-disproved"


def _trigger_rejection_is_dispositive(
    report: Path | None, vote_files: tuple[Path, ...],
    *, allow_consequence: bool = False,
) -> bool:
    """Whether reviewed trigger evidence may remove a security artifact.

    A scope mismatch — a contract-obeying public boundary that this target's
    configured attacker controls do not list — is not `unreachable`. The
    reviewer is told to vote Promote there and let severity carry the attack
    precondition, so the surface cannot be used to second-guess the kind: an
    `unreachable` vote is the affirmative disproof it says it is, and a public
    surface is where the reviewer most often has the source to prove one.

    Quorum is on the disproof, not on its label. Every kind admitted here says
    "the claimed defect is not one"; they differ only in why. Requiring the two
    reviewers to spell the same one published findings that both had refuted
    with the same cited source, and clause (g) widens that trap — one reviewer
    may name an unreachable trigger where the other names the refuted
    consequence. `no-added-boundary` is a different claim — a real defect at no
    security boundary — so a vote for it never joins this quorum, and a split
    against it falls through to the softer outcome.
    """
    allowed = _DISPOSITIVE_REJECTION_KINDS | (
        {_CONSEQUENCE_REJECTION_KIND} if allow_consequence else set()
    )
    kinds = [
        triage_validate.source_review_facts(payload).get("rejection_kind", "")
        for payload in _trigger_vote_payloads(report, vote_files, "Reject")
    ]
    return len(kinds) >= 2 and all(kind in allowed for kind in kinds)


def _trigger_vote_payloads(
    report: Path | None, vote_files: tuple[Path, ...], vote: str,
) -> list[dict]:
    """`review_facts` from each current vote file carrying `vote`."""
    if report is None:
        return []
    payloads = []
    for vote_file in vote_files:
        if _cached_trigger_vote(report, vote_file) != vote:
            continue
        try:
            payload = json.loads(vote_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        payloads.append(payload.get("review_facts"))
    return payloads


def _restore_rejected_artifact(
    directory: Path, active_root: Path, *, kind: str, detail: str,
) -> Path:
    """Move one superseded rejection back to its active validation lane."""
    active_root.mkdir(parents=True, exist_ok=True)
    had_route_advice = bool(
        _TRIGGER_REJECTION_RE.match(_rejection_reason(directory))
    )
    destination = _unique_destination(active_root, directory.name)
    shutil.move(str(directory), destination)
    # The rejected path is reusable after this move. Remove its row rather
    # than relying only on directory absence, or rejecting the reopened
    # artifact under the same name would make the obsolete route live again.
    if had_route_advice:
        _retract_unreachable_route(directory, active_root.parent)
    (destination / "REJECTION.md").unlink(missing_ok=True)
    (destination / "validation.json").unlink(missing_ok=True)
    validation_receipt.write(
        destination, kind=kind, state="pending", detail=detail,
    )
    try:
        workqueue.record_artifact_reconsideration(
            active_root.parent, directory.name, detail,
        )
    except OSError as exc:
        print(
            f"WARN: could not restore structured state for {directory.name}: {exc}",
            file=sys.stderr,
        )
    return destination


def _restore_stale_trigger_rejections(
    results_dir: Path, *, kind: str,
) -> int:
    """Requeue trigger Rejects that the current gate cannot affirm.

    Reject votes from an older prompt are intentionally not reusable. Leaving
    their directories in the rejected tree nevertheless made that fail-open
    rule ineffective: regeneration never visited them. Current votes are also
    requeued when their source facts say the vulnerable boundary is public and
    the only objection is configured threat-model reachability.
    """
    if kind == "crash":
        rejected_root = results_dir / "crashes-rejected"
        active_root = results_dir / "crashes"
        prefix = "CRASH-*"
    elif kind == "finding":
        rejected_root = results_dir / "findings-rejected"
        active_root = results_dir / "findings"
        prefix = "FIND-*"
    else:
        raise ValueError(f"unsupported artifact kind: {kind}")
    restored = 0
    for directory in sorted(rejected_root.glob(prefix)):
        if (
            not directory.is_dir()
            or not _TRIGGER_REJECTION_RE.match(_rejection_reason(directory))
        ):
            continue
        report = _report(directory)
        vote_pairs = [
            (
                directory / _TRIGGER_PRIMARY_NAME,
                directory / _TRIGGER_SECOND_NAME,
            ),
            (
                directory / _TRIGGER_PRIMARY_NAME,
                directory / _TRIGGER_RESOLUTION_NAME,
            ),
        ]
        vote_files = next(
            (
                pair for pair in vote_pairs
                if report is not None
                and [_cached_trigger_vote(report, path) for path in pair]
                == ["Reject", "Reject"]
            ),
            vote_pairs[0],
        )
        current_votes = (
            [_cached_trigger_vote(report, path) for path in vote_files]
            if report is not None else []
        )
        facts = (
            _source_review_facts(
                report, vote_files, rejection_quorum=2,
            )
            if report is not None else {}
        )
        if (
            current_votes == ["Reject", "Reject"]
            and _trigger_rejection_is_dispositive(
                report, vote_files, allow_consequence=kind == "finding",
            )
        ):
            if validation_receipt.read_current(directory) is None:
                validation_receipt.write(
                    directory, kind=kind, state="rejected",
                    detail=_rejection_reason(directory),
                    review_facts=facts,
                )
            continue
        _restore_rejected_artifact(
            directory, active_root, kind=kind,
            detail="requeued after trigger-review policy or schema change",
        )
        restored += 1
    if restored:
        print(
            f"INFO: requeued {restored} {kind} trigger rejection(s) "
            "for current source review",
            file=sys.stderr,
        )
    return restored


def restore_stale_trigger_rejections(
    results_dir: str | os.PathLike[str],
) -> int:
    """Reconcile both rejected lanes before a resumed agent sees their advice."""
    results = Path(results_dir)
    return sum(
        _restore_stale_trigger_rejections(results, kind=kind)
        for kind in ("crash", "finding")
    )


def _refresh_or_restore_quality_rejections(
    results_dir: Path, *, quorum: int, accept_quorum: int,
) -> int:
    """Bind current quality Rejects and requeue the stale remainder."""
    rejected_root = results_dir / "findings-rejected"
    restored = 0
    for directory in sorted(rejected_root.glob("FIND-*")):
        if (
            not directory.is_dir()
            or _TRIGGER_REJECTION_RE.match(_rejection_reason(directory))
        ):
            continue
        report = _report(directory)
        cache_path = directory / ".llm-find-quality.json"
        cache = _finding_cache(cache_path)
        current_reject = (
            report is not None
            and _quality_cache_matches(
                cache_path, cache, report, read_report_bounded(report),
            )
            and _quality_terminal(cache, quorum, accept_quorum)
            and cache.get("accept") is False
        )
        if current_reject:
            if validation_receipt.read_current(directory) is None:
                validation_receipt.write(
                    directory, kind="finding", state="rejected",
                    detail=_rejection_reason(directory),
                )
            continue
        _restore_rejected_artifact(
            directory, results_dir / "findings", kind="finding",
            detail="requeued because the finding-quality rejection is stale",
        )
        restored += 1
    if restored:
        print(
            f"INFO: requeued {restored} stale finding-quality rejection(s)",
            file=sys.stderr,
        )
    return restored


def demote_to_finding(directory: Path, results_dir: Path, reason: str) -> Path:
    """Move a runtime-only CRASH artifact into the findings pipeline."""
    report = _report(directory)
    if report is not None:
        try:
            with report.open("a", encoding="utf-8") as stream:
                stream.write(
                    "\n## Triage disposition\n\n"
                    f"Demoted from `crashes/`: {reason}.\n"
                )
        except OSError as exc:
            print(
                f"WARN: could not annotate findings demotion in {report}: {exc}",
                file=sys.stderr,
            )
    _clear_promotion_sidecars(directory)
    finding_id = (
        f"FIND-{directory.name.removeprefix('CRASH-')}"
        if directory.name.startswith("CRASH-")
        else f"FIND-{directory.name}"
    )
    findings_root = results_dir / "findings"
    findings_root.mkdir(parents=True, exist_ok=True)
    destination = _unique_destination(findings_root, finding_id)
    shutil.move(str(directory), destination)
    return destination


_CRASH_DEMOTION_MARKER = re.compile(
    r"Demoted from `crashes/`", re.IGNORECASE,
)
# The two demotion reasons that were never verdicts about the crash: a replay
# that produced no measurement, and one no runnable contract could be resolved
# for. Both blamed the crash for a harness failure, both have been withdrawn,
# and both are reconsidered when a caller asks. Every other reason states what
# a replay that ran actually saw, and stays permanent.
_UNVERIFIABLE_REPLAY_DEMOTION_MARKER = re.compile(
    r"Demoted from `crashes/`: (?:"
    r"configured-target replay produced no measurement of the original fault"
    r"|sanitizer evidence has no executable configured-target replay contract"
    r")",
    re.IGNORECASE,
)


def _last_crash_demotion_was_unverifiable_replay(report_text: str) -> bool:
    dispositions = re.findall(
        r"^Demoted from `crashes/`:[^\n]*$",
        report_text, re.IGNORECASE | re.MULTILINE,
    )
    return bool(
        dispositions
        and _UNVERIFIABLE_REPLAY_DEMOTION_MARKER.search(dispositions[-1])
    )


def route_finding_diagnostics(
    results_dir: str | os.PathLike[str], *,
    reconsider_unverifiable_replay: bool = False,
) -> int:
    """Move complete sanitizer-backed FIND bundles into crash triage.

    Only a dedicated sanitizer artifact is authoritative, and only a bundle
    with a runnable testcase crosses lanes — or, on the reconsidered path
    below, any saved reproducer, because that artifact was already a crash
    before a demotion since withdrawn.  Source-only memory
    findings remain findings and receive a crash-lead marker; they must not be
    lost merely because reproduction is incomplete. Artifacts deliberately
    demoted from crash triage are never promoted back, except when the caller
    explicitly reconsiders the historical demotions a replay that established
    nothing caused.

    The scan is limited to directories containing a sanitizer sidecar, so
    calling it before crash triage does not add another full finding-gate pass.
    """
    results = Path(results_dir)
    findings = results / "findings"
    roots = [findings]
    if reconsider_unverifiable_replay:
        roots.append(results / "findings-rejected")
    if not any(root.is_dir() for root in roots):
        return 0
    routed = 0
    candidates: set[Path] = set()
    for root in roots:
        for pattern in ("FIND-*/sanitizer.txt", "FIND-*/.audit/sanitizer.txt"):
            for path in root.glob(pattern):
                if path.is_file():
                    candidates.add(
                        path.parent.parent
                        if path.parent.name == ".audit" else path.parent
                    )
    for directory in sorted(candidates):
        report = _report(directory)
        sanitizer = _sanitizer_file(directory)
        if report is None or sanitizer is None:
            continue
        report_text = _read(report)
        reconsidered_replay_demotion = False
        if _CRASH_DEMOTION_MARKER.search(report_text):
            reconsidered_replay_demotion = bool(
                reconsider_unverifiable_replay
                and _last_crash_demotion_was_unverifiable_replay(report_text)
            )
            if not reconsidered_replay_demotion:
                continue
        sanitizer_text = _read(sanitizer)
        if not (
            has_valid_diagnostic(sanitizer_text)
            and _has_memory_safety_signal(sanitizer_text)
            and not autodiscard_reason(sanitizer_text)
        ):
            continue
        testcase = crash_artifacts.find_testcase(
            (directory, directory / ".audit"),
            sanitizer_files=(sanitizer,),
        )
        if testcase is None and not (
            reconsidered_replay_demotion
            and crash_artifacts.carries_replay_evidence(directory)
        ):
            _write_atomic_json(
                directory / ".crash-lead.json",
                {
                    "schema_version": 1,
                    "state": "unreproduced",
                    "reason": (
                        "saved memory-safety diagnostic without a runnable "
                        "testcase or harness"
                    ),
                },
            )
            continue
        if directory.parent.name == "findings-rejected":
            directory = _restore_rejected_artifact(
                directory, findings, kind="finding",
                detail="requeued after an unverifiable crash replay was reconsidered",
            )
            report = _report(directory)
            if report is None:
                continue
        (directory / ".crash-lead.json").unlink(missing_ok=True)
        with report.open("a", encoding="utf-8") as stream:
            stream.write(
                "\n## Triage disposition\n\n"
                "Routed from `findings/` to `crashes/`: a dedicated sanitizer "
                "artifact and saved reproducer establish a crash candidate.\n"
            )
        crash_id = (
            f"CRASH-{directory.name.removeprefix('FIND-')}"
            if directory.name.startswith("FIND-")
            else f"CRASH-{directory.name}"
        )
        crashes = results / "crashes"
        crashes.mkdir(parents=True, exist_ok=True)
        shutil.move(str(directory), _unique_destination(crashes, crash_id))
        routed += 1
    return routed


def _field(text: str, name: str) -> str:
    table = re.search(rf"^\|\s*{re.escape(name)}\s*\|\s*([^|\n]+)", text, re.IGNORECASE | re.MULTILINE)
    if table:
        return table.group(1).strip()
    label = re.search(rf"^{re.escape(name)}\s*:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
    return label.group(1).strip() if label else ""


# Labels come from the shared report vocabulary so a field added here is known
# to the promoter and the renderer too.
_REACH_FIELD_LABELS = {
    key: report_identity.FIELD_LABELS[key]
    for key in (
        "surface", "primitive", "class", "caller_contract", "caller_controls",
        "trigger_source", "parameter_control", "trusted_caller_actions",
        "boundary", "advisory",
    )
}
_OPTIONAL_REACH_FIELD_LABELS = {
    key: report_identity.FIELD_LABELS[key]
    for key in (
        # Older reports correctly describe only the vulnerable surface. Carrier
        # is useful when it differs, but absence is not evidence that the
        # surface is unknown and must not invalidate an otherwise complete
        # report.
        "reproducer_carrier",
        # What the disclosed bytes actually are. Optional on purpose: a report
        # that cannot say leaves severity exactly where it is, so classifying is
        # the only way this field moves a score and silence never costs a
        # finding.
        "disclosed_content",
        # Whether a resource-exhaustion report demonstrates total loss or a
        # slower service. Optional the same way; the scorer reads silence as
        # degraded, so a source-only DoS claim earns VA:H only once graded.
        "availability_loss",
    )
}
_ALL_REACH_FIELD_LABELS = {
    **_REACH_FIELD_LABELS,
    **_OPTIONAL_REACH_FIELD_LABELS,
}
# Bump when a prompt/schema defect could have consumed the bounded retry budget
# without asking for a field. Complete reports still short-circuit; only reports
# that remain open receive fresh attempts.
# Bumped with the prompt: 12420dd made fixed pre-input shaping application
# setup (`trigger_source: bytes`, `parameter_control: application-supplied`)
# but left cached answers keyed to the old policy, which severity reads.
# v7 added `availability_loss`; a resource report whose attempts an earlier
# schema exhausted must be asked once for the grade the scorer now reads.
_REACH_FIELD_DECISION_VERSION = "reach-fields-v7-availability-loss"
_REACH_FIELD_ENUMS = {
    "caller_contract": {"obeyed", "violated", "unspecified"},
    "caller_controls": {"bytes", "length", "number", "flags", "call-sequence", "timing", "none"},
    "trigger_source": {"bytes", "both", "call-sequence", "timing", "race", "protocol-state", "env", "fs-state"},
    "parameter_control": {"direct", "indirect", "application-supplied", "trusted", "harness-only"},
    "trusted_caller_actions": {"normal public call", "private mutation", "callback ordering", "harness-only"},
    "advisory": {"yes", "no"},
    "disclosed_content": {
        "cross-principal", "same-context", "attacker-derived", "fixed-or-zero",
    },
    "availability_loss": {"total", "degraded"},
}
_SURFACE_KINDS = {"network", "library-api", "file-format", "cli", "dev-tool", "internal", "unknown"}
_CARRIER_KINDS = {"network", "library-api", "file-format", "cli", "harness", "runner", "unknown"}


def _valid_reach_field(key: str, value: object) -> str:
    """Return a safe scorer field value, or empty when a decision is malformed."""
    if key not in _ALL_REACH_FIELD_LABELS or not isinstance(value, str):
        return ""
    normalized = " ".join(value.split()).strip()
    if not normalized or len(normalized) > 300 or "|" in normalized:
        return ""
    lowered = normalized.lower()
    if key in _REACH_FIELD_ENUMS and lowered not in _REACH_FIELD_ENUMS[key]:
        return ""
    # bin/severity owns the canonical primitive table. Keep this boundary
    # structural so adding a scorer primitive does not require a second list;
    # unsupported keys are ignored by the scorer rather than gaining impact.
    if key == "primitive" and not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", lowered):
        return ""
    if key == "surface":
        kind = lowered.split(None, 1)[0].rstrip(":;,-")
        if kind not in _SURFACE_KINDS:
            return ""
    if key == "reproducer_carrier":
        kind = lowered.split(None, 1)[0].rstrip(":;,-")
        if kind not in _CARRIER_KINDS:
            return ""
    return normalized


def _atomic_write_text(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def _reach_field_present(text: str, label: str) -> bool:
    """Treat generated placeholders as missing while preserving real author values."""
    values = re.findall(
        rf"^\|\s*{re.escape(label)}\s*\|\s*([^|\n]*)|^{re.escape(label)}\s*:\s*(.*)$",
        text, re.IGNORECASE | re.MULTILINE,
    )
    return any(
        not report_identity.field_value_is_placeholder(
            label, table_value or bare_value,
        )
        for table_value, bare_value in values
    )


def _missing_reach_fields(text: str) -> dict[str, str]:
    return {
        key: label for key, label in _REACH_FIELD_LABELS.items()
        if not _reach_field_present(text, label)
    }


# Broad and stable rather than a class list that rots: any report whose own
# class or primitive says it discloses something, or that it exhausts a
# resource, is worth one bounded ask for the grade the scorer reads.
_OPTIONAL_REACH_FIELD_SHAPES = (
    ("disclosed_content",
     re.compile(r"disclos|info[-_ ]?leak|uninit|residu", re.I)),
    ("availability_loss",
     re.compile(r"\bdos\b|amplif|exhaust|memory[-_ ]?leak|regex|resource", re.I)),
)


def _pending_optional_reach_fields(text: str) -> dict[str, str]:
    """The optional classification this report still owes, if it owes one.

    Kept out of `_missing_reach_fields`, which means "publication-required and
    absent": a report is complete without this, and treating it as missing
    would make every disclosure report look unfinished. Without a separate ask
    a complete report short-circuits before the fill prompt ever runs, so the
    field could never be populated on exactly the reports it exists for.
    """
    shape_text = " ".join(
        match.group(1)
        for field in ("Class", "Primitive")
        if (match := re.search(
            rf"^(?:{field}\s*:\s*|\|\s*{field}\s*\|\s*)([^|\n]+)",
            text, re.IGNORECASE | re.MULTILINE,
        ))
    )
    return {
        key: _OPTIONAL_REACH_FIELD_LABELS[key]
        for key, shape in _OPTIONAL_REACH_FIELD_SHAPES
        if shape.search(shape_text)
        and not _reach_field_present(text, _OPTIONAL_REACH_FIELD_LABELS[key])
    }


def _accepted_reach_fields(
    source: object, missing: dict[str, str],
) -> dict[str, str]:
    if not isinstance(source, dict):
        return {}
    return {
        key: value
        for key, raw in source.items()
        if (
            (key in missing or key in _OPTIONAL_REACH_FIELD_LABELS)
            and (value := _valid_reach_field(key, raw))
        )
    }


def _reach_field_cache(path: Path) -> dict:
    """Retain valid field evidence while resetting obsolete retry exhaustion."""
    cache = _finding_cache(path)
    if cache.get("_decision_version") == _REACH_FIELD_DECISION_VERSION:
        return cache
    migrated = {
        key: value
        for key in _ALL_REACH_FIELD_LABELS
        if (value := _valid_reach_field(key, cache.get(key)))
    }
    migrated.update({
        "_decision_version": _REACH_FIELD_DECISION_VERSION,
        "_fill_attempts": 0,
    })
    return migrated


def _materialize_reach_fields(
    report: Path, accepted: dict[str, str],
) -> bool:
    if not accepted:
        return False
    current = report.read_text(encoding="utf-8", errors="replace")
    additions = [
        f"{_ALL_REACH_FIELD_LABELS[key]}: {value}"
        for key, value in accepted.items()
        if not _reach_field_present(current, _ALL_REACH_FIELD_LABELS[key])
    ]
    if not additions:
        return False
    lines = current.rstrip().splitlines()
    insertion = next(
        (
            index for index, line in enumerate(lines)
            if line.strip() == report_identity.SEVERITY_RATIONALE_HEADING
        ),
        len(lines),
    )
    block = [*additions, ""]
    if insertion and lines[insertion - 1].strip():
        block.insert(0, "")
    lines[insertion:insertion] = block
    _atomic_write_text(report, "\n".join(lines).rstrip() + "\n")
    return True


def _materialize_reach_fields_preserving_positive_votes(
    report: Path, accepted: dict[str, str],
) -> bool:
    """Advance fail-open trigger evidence across one harness field annotation."""
    vote_files = (
        report.parent / _TRIGGER_PRIMARY_NAME,
        report.parent / _TRIGGER_SECOND_NAME,
        report.parent / _TRIGGER_RESOLUTION_NAME,
    )
    prior_votes = {
        path: _cached_trigger_vote(report, path)
        for path in vote_files
    }
    if not _materialize_reach_fields(report, accepted):
        return False
    # A positive trigger review cannot hide a bug. Reach fields are generated
    # by the harness from the same report evidence, so preserve only fail-open
    # votes captured immediately before this exact annotation. A Reject is
    # deliberately never carried across semantic content.
    current_sha1 = report_identity.content_sha1(report)

    def _carry(path: Path, extra: dict | None = None) -> None:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(payload, dict):
            return
        payload["content_sha1"] = current_sha1
        payload.update(extra or {})
        _write_atomic_json(path, payload)

    resolution = report.parent / _TRIGGER_RESOLUTION_NAME
    for path, vote in prior_votes.items():
        if vote in {"Promote", "Uncertain"} and path != resolution:
            _carry(path)
    # Strictly after the reviews above: a resolution is bound to their exact
    # bytes, which that loop just rewrote. Carrying only the report identity
    # would leave it bound to the pre-annotation reviews and silently stale,
    # buying a second resolver call for a question already answered.
    if prior_votes.get(resolution) in {"Promote", "Uncertain"}:
        _carry(resolution, {
            "prior_review_sha256s": triage_validate.prior_review_sha256s(
                _trigger_resolution_sources(report, report.parent)
            ),
        })
    return True


def _materialize_crash_class(directory: Path) -> bool:
    """Fill the class that follows deterministically from crash admission."""
    report = _report(directory)
    if report is None or _reach_field_present(_read(report), "Class"):
        return False
    return _materialize_reach_fields_preserving_positive_votes(
        report, {"class": "memory-safety"},
    )


_NO_REACH_DECISION = object()


def fill_reach_fields(
    directory: Path, usage_index: str | os.PathLike[str] | None = None,
    *, decision_override: object = _NO_REACH_DECISION,
) -> bool:
    """Fill missing scorer fields from report evidence without overriding authors.

    The report is the severity scorer's sole input. The decision sidecar only
    records bounded retry state; accepted fallback values are materialized as
    bare report fields so every downstream consumer sees the same facts.
    """
    if os.environ.get("LLM_FIELD_FILL_DISABLE", "0") == "1":
        return False
    report = _report(directory)
    if report is None:
        return False
    try:
        full_text = report.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    text = full_text[:6000]
    missing = _missing_reach_fields(full_text)
    if not missing and not _pending_optional_reach_fields(full_text):
        return False
    sidecar = directory / ".llm_fields.json"
    cache = _reach_field_cache(sidecar)
    changed = _materialize_reach_fields_preserving_positive_votes(
        report, _accepted_reach_fields(cache, missing),
    )
    if changed:
        full_text = report.read_text(encoding="utf-8", errors="replace")
        text = full_text[:6000]
        missing = _missing_reach_fields(full_text)
        if not missing:
            return True
    try:
        attempts = int(cache.get("_fill_attempts", 0))
        max_attempts = _positive_int_env("LLM_FIELD_FILL_MAX_ATTEMPTS", 2)
    except (TypeError, ValueError):
        attempts, max_attempts = 0, 2
    if attempts >= max_attempts:
        return changed
    decision = decision_override
    if decision is _NO_REACH_DECISION:
        prompt = render_template("triage_reachability_fields.md.j2", {"narrative": text})
        timeout = llm_decide.decision_timeout("reachability-fields")
        decision = llm_decide.llm_decide(
            "reachability-fields", "", prompt, timeout, usage_index=usage_index,
        )
    cache["_fill_attempts"] = attempts + 1
    if not isinstance(decision, dict):
        _write_atomic_json(sidecar, cache)
        return changed
    accepted = _accepted_reach_fields(decision, missing)
    cache.update(accepted)
    _write_atomic_json(sidecar, cache)
    if not accepted:
        return changed
    return (
        _materialize_reach_fields_preserving_positive_votes(report, accepted)
        or changed
    )


def _batch_reach_field_decisions(
    directories: list[Path],
    usage_index: str | os.PathLike[str] | None,
    deadline: float | None = None,
    workers: int = 4,
) -> tuple[set[Path], dict[Path, dict], set[Path]]:
    """Apply cached fields, then batch unresolved fields without per-item fan-out."""
    items: list[dict] = []
    attempted: set[Path] = set()
    prefilled: set[Path] = set()
    for directory in directories:
        report = _report(directory)
        if report is None:
            continue
        try:
            report_text = report.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        narrative = report_text[:6000]
        missing = _missing_reach_fields(report_text)
        if not missing and not _pending_optional_reach_fields(report_text):
            continue
        cache = _reach_field_cache(directory / ".llm_fields.json")
        cached = _accepted_reach_fields(cache, missing)
        if cached:
            if _materialize_reach_fields_preserving_positive_votes(
                report, cached,
            ):
                prefilled.add(directory)
            report_text = report.read_text(encoding="utf-8", errors="replace")
            narrative = report_text[:6000]
            missing = _missing_reach_fields(report_text)
            if not missing and not _pending_optional_reach_fields(report_text):
                continue
        try:
            attempts = int(cache.get("_fill_attempts", 0))
            max_attempts = _positive_int_env("LLM_FIELD_FILL_MAX_ATTEMPTS", 2)
        except (TypeError, ValueError):
            attempts, max_attempts = 0, 2
        if attempts >= max_attempts:
            continue
        attempted.add(directory)
        items.append({"id": directory.name, "report": narrative})
    if not items:
        return attempted, {}, prefilled
    timeout = llm_decide.decision_timeout("reachability_fields_batch")
    instructions = render_template(
        "triage_reachability_fields.md.j2", {"narrative": ""},
    ).split("\nReport:", 1)[0]
    by_id = _batch_decisions(
        "reachability_fields_batch", "triage_reachability_fields_batch.md.j2",
        instructions, items, timeout, usage_index, deadline, workers,
        batch_size=4,
    )
    return (
        attempted,
        {
            directory: decision
            for directory in attempted
            if isinstance((decision := by_id.get(directory.name)), dict)
        },
        prefilled,
    )


def reach_fields_open(directory: Path) -> bool:
    """Fields still missing here with retry budget left — no provider call.

    Lets the cached fast paths ask whether an artifact owes convergence before
    entering it. Those paths exist to finish already-reviewed work before
    anything asks a provider, so an artifact whose fields are already settled
    must not be handed to the batch decider merely to be told so.
    """
    report = _report(directory)
    if report is None:
        return False
    try:
        text = report.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    if not _missing_reach_fields(text) and not _pending_optional_reach_fields(text):
        return False
    cache = _reach_field_cache(directory / ".llm_fields.json")
    try:
        attempts = int(cache.get("_fill_attempts", 0))
    except (TypeError, ValueError):
        return True
    return attempts < _positive_int_env("LLM_FIELD_FILL_MAX_ATTEMPTS", 2)


def converge_reach_fields(
    directories: list[Path],
    usage_index: str | os.PathLike[str] | None = None,
    deadline: float | None = None,
    workers: int = 4,
) -> None:
    """Batch reach-field fill until nothing is pending or the budget is spent.

    One batched pass applies what one answer supplies and stops. When an
    answer is omitted or unparsable it still spends an attempt and
    materializes nothing, so a later pass — the pool rebuild runs one —
    rewrites a report that a validation receipt already covers. That
    invalidates the receipt, bin/severity declines to score a report its
    review no longer describes, and the artifact publishes unrated.

    Repeating the pass here spends the same per-artifact attempt ceiling
    before the receipt binds, at the same batch width, so the later pass has
    nothing left to change. Provider calls keep their count and their shape —
    only their timing moves.

    Termination rides on the batch pass itself: it already skips a converged
    report and one that has spent its attempts, so the set it reports as
    attempted shrinks to empty. Looping on that set, rather than on "did the
    report change", is what keeps an answerless pass retrying.
    """
    remaining = [Path(directory) for directory in directories]
    for _ in range(_positive_int_env("LLM_FIELD_FILL_MAX_ATTEMPTS", 2) + 1):
        if _deadline_expired(deadline):
            return
        attempted, decisions, _ = _batch_reach_field_decisions(
            remaining, usage_index, deadline, workers,
        )
        if not attempted:
            return
        for directory in remaining:
            if directory not in attempted:
                continue
            # An omitted id yields None, which spends this artifact's attempt
            # without a second single-report call; the next pass re-batches it.
            fill_reach_fields(
                directory, usage_index,
                decision_override=decisions.get(directory),
            )
        remaining = sorted(attempted)


def fill_reach_fields_tree(root: Path) -> int:
    """Apply reach-field convergence to every pooled crash and finding.

    A report already covered by a current final receipt is left alone. This
    pass runs over pooled copies, after review, so materializing a field here
    rewrites the very text a review concluded on — which invalidates that
    receipt, and is how an adjudicated artifact ends up published unrated.
    Converging upstream is what keeps fields from being left open; this makes
    the pool unable to reopen them regardless of why one still is (an expired
    deadline, an unavailable provider, a spent attempt budget).

    Whatever a cell left open, it left open under a receipt that describes the
    report as it stands, and that is the report the score must reflect.
    """
    if os.environ.get("LLM_FIELD_FILL_DISABLE", "0") == "1":
        return 0
    changed: set[Path] = set()
    usage_index = benchmark._find_index_jsonl(Path(root))
    directories: list[Path] = []
    for kind, prefix in (("findings", "FIND-*"), ("crashes", "CRASH-*")):
        for directory in sorted((Path(root) / kind).glob(prefix)):
            if not directory.is_dir():
                continue
            receipt = validation_receipt.read_current(directory)
            if (
                receipt is not None
                and receipt.get("state") in validation_receipt.FINAL_STATES
            ):
                continue
            directories.append(directory)
    attempted, batched, prefilled = _batch_reach_field_decisions(
        directories, usage_index,
    )
    changed.update(prefilled)
    for directory in directories:
        if directory not in attempted:
            continue
        if fill_reach_fields(
            directory, usage_index,
            decision_override=batched.get(directory),
        ):
            changed.add(directory)
    return len(changed)


def _cluster_source_path(location: str, target_root: Path) -> tuple[Path, int] | None:
    match = re.search(r"^(.*?):(\d+)(?::\d+)?$", location or "")
    if not match:
        return None
    candidate = Path(match.group(1))
    candidate = candidate if candidate.is_absolute() else target_root / candidate
    try:
        resolved = candidate.resolve()
        resolved.relative_to(target_root.resolve())
    except (OSError, ValueError):
        return None
    return (resolved, max(1, int(match.group(2)))) if resolved.is_file() else None


def _cluster_expansion_item(
    crash_dir: Path, target_root: Path,
) -> dict | None:
    """Build bounded source evidence for one cluster-expansion item."""
    sanitizer = _sanitizer_file(crash_dir)
    if sanitizer is None:
        return None
    text = _read(sanitizer)
    frames = stack_frames.iter_asan_frames(text)[:8]
    if not frames:
        return None
    source_parts: list[str] = []
    seen: set[Path] = set()
    for frame in frames:
        resolved = _cluster_source_path(frame.location, Path(target_root))
        if resolved is None:
            continue
        path, line = resolved
        if path in seen:
            continue
        seen.add(path)
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        start = max(0, line - 7)
        end = min(len(lines), line + 6)
        relative = path.relative_to(Path(target_root).resolve())
        source_parts.append(f">>> {relative}:{line}\n" + "\n".join(lines[start:end]))
        if len(source_parts) >= 3:
            break
    return {
        "id": crash_dir.name,
        "frames": "\n".join(frame.raw for frame in frames),
        "source_block": "\n\n".join(source_parts) or "(source unavailable)",
    }


def cluster_expansion_decisions(
    crash_dirs: list[Path], target_root: Path, *,
    attacker_controls: list[str] | None = None,
    deadline: float | None = None,
) -> dict[Path, list[dict] | None]:
    """Return keyed source-grounded sibling leads for new crashes in one call.

    Each missing or malformed id remains ``None`` (retryable); an explicit
    empty row list is a completed decision.  Keying the response lets one
    independent model session cover the post-iteration group without treating
    a partial answer as evidence about crashes it omitted.

    `attacker_controls` scopes the leads. A seed crash is expanded whatever its
    own publication state, because a neighbour's reachability is not the
    seed's; asking for siblings the declared model can reach is what keeps an
    out-of-model seed from breeding a generation of out-of-model variants.
    """
    decisions = {crash: None for crash in crash_dirs}
    items = []
    by_id: dict[str, Path] = {}
    for crash in crash_dirs:
        item = _cluster_expansion_item(crash, target_root)
        if item is None:
            continue
        items.append(item)
        by_id[crash.name] = crash
    if not items:
        return decisions
    controls = ",".join(attacker_controls or [])
    scope_block = (
        f"\nName only siblings an attacker could reach supplying `{controls}`.\n"
        "A seed crash's own trigger does not bind you — a neighbour's\n"
        "reachability is its own, and a sibling beside an out-of-scope crash may\n"
        f"still be reachable — but one needing something outside `{controls}`\n"
        "earns no security credit however it turns out, so it is not worth a\n"
        "session. Drop it and return fewer rows.\n"
    ) if controls else ""
    prompt = render_template(
        "triage_cluster_expand_batch.md.j2",
        {
            "items_block": "\n\n".join(
                f"## {item['id']}\n\nTop frames:\n{item['frames']}\n\n"
                f"Nearby source:\n{item['source_block']}"
                for item in items
            ),
            "scope_block": scope_block,
        },
    )
    configured = llm_decide.decision_timeout("cluster_expand")
    timeout = _decision_timeout(configured, deadline)
    if timeout <= 0:
        return decisions
    decision = llm_decide.llm_decide(
        "cluster_expand", "items", prompt, timeout,
        usage_index=llm_usage.find_usage_index(crash_dirs[0].parents[1]),
    )
    if not isinstance(decision, dict) or not isinstance(decision.get("items"), list):
        return decisions
    seen_ids: set[str] = set()
    for answer in decision["items"]:
        if not isinstance(answer, dict):
            continue
        item_id = str(answer.get("id", ""))
        rows = answer.get("rows")
        if item_id in seen_ids or item_id not in by_id or not isinstance(rows, list):
            continue
        seen_ids.add(item_id)
        decisions[by_id[item_id]] = [
            row for row in rows[:3] if isinstance(row, dict)
        ]
    return decisions


def cluster_expansion_decision(
    crash_dir: Path, target_root: Path, *,
    attacker_controls: list[str] | None = None,
    deadline: float | None = None,
) -> list[dict] | None:
    """Single-crash form used by standalone callers and focused tests."""
    return cluster_expansion_decisions(
        [crash_dir], target_root,
        attacker_controls=attacker_controls, deadline=deadline,
    ).get(crash_dir)


def evaluate_crash_verdict(report_text: str, controls: list[str]) -> tuple[str, str]:
    """Compare the report's self-declared trigger against the threat model.

    `contract-flag` is the report admitting caller misuse and is dispositive.
    `out-of-model` is only the set difference against `attacker_controls`, and
    a source reviewer may correct it in either direction — see
    `_final_publication_state`.
    """
    contract = _field(report_text, "Caller contract").lower()
    parameter = _field(report_text, "Parameter control").lower().replace("_", "-")
    trigger = _field(report_text, "Trigger source").lower()
    if contract == "violated" or parameter == "harness-only":
        return "contract-flag", "report identifies caller-contract misuse"
    if not contract and not trigger:
        return "incomplete", "report has no Caller contract or Trigger source field"
    trigger = trigger or "bytes"
    aliases = {
        "data": "bytes", "data-driven": "bytes", "input": "bytes",
        "call-order": "call-sequence", "call_order": "call-sequence",
        "call-seq": "call-sequence", "call_sequence": "call-sequence",
        "sequence": "call-sequence",
    }
    required: set[str] = set()
    for item in trigger.split(","):
        normalized = aliases.get(item.strip(), item.strip())
        if normalized == "both":
            required.update(("bytes", "call-sequence"))
        elif normalized:
            required.add(normalized)
    accepted = {aliases.get(item.strip(), item.strip()) for item in controls}
    missing = sorted(required - accepted)
    if missing:
        return "out-of-model", f"trigger requires {','.join(missing)} outside attacker_controls={','.join(controls)}"
    return "promote", f"trigger within attacker_controls={','.join(controls)}"


_UNSETTLED_REVIEW_DETAIL = (
    "source review did not settle whether the trigger is in the threat model"
)


def _final_publication_state(
    reach_verdict: str,
    trigger_votes: set[str | None] | frozenset[str | None] = frozenset(),
    review_facts: dict[str, str] | None = None,
    *,
    direct_trigger_proof: bool = False,
) -> str:
    """Resolve a kept artifact to a security report, a retained defect, or neither.

    Rejection remains a separate, two-review decision. `not-reportable` asserts
    a fact somebody established — the report admitting caller misuse, agreeing
    reviewers placing the trigger outside the declared controls, or agreeing
    reviewers finding no added security boundary. A review that ran and did not
    settle the question establishes none of those, so the artifact stays
    `pending`: not security yield, and not a defect anyone showed is out of
    scope. The benchmark then carries it as the unjudged remainder that marks
    its counts a floor, where writing a negative would instead publish an
    adjudication that never happened. An inconclusive first review or split is
    re-asked once with the prior evidence; a resolver that remains uncertain is
    cached, and content-addressing reopens it when the report, prior reviews,
    evidence, or prompt version changes.

    Scope comes from `trigger_controls_fit` — the reviewer's own threat-model
    comparison, read from source and supplied by `_source_review_facts` only
    from anchor-verified reviewers that agree. The report's self-declared
    `Trigger source` is not evidence for it: the finder writes that field and
    gets it wrong in both directions. So a review that ran and did not answer
    the scope question cannot carry an artifact to `reportable`. Only a path
    that needed no review — a machine trigger proof, an operator opt-out, or a
    human pin — falls back to the report's own comparison, because there is no
    reviewer to have answered.
    """
    facts = review_facts or {}
    fit = facts.get("trigger_controls_fit", "")
    if (
        reach_verdict == "contract-flag"
        or facts.get("rejection_kind") == "no-added-boundary"
    ):
        return "not-reportable"
    if direct_trigger_proof:
        # A confirmed probe already answered the scope question by machine.
        # The ambiguous-surface reviewer still runs, to settle boundary and
        # carrier; its opinion about a proved byte path is not evidence
        # against that proof.
        return "reportable"
    if fit == "outside":
        return "not-reportable"
    if any(vote in {"Reject", "Uncertain"} for vote in trigger_votes):
        return "pending"
    if fit == "within":
        return "reportable"
    if any(vote is not None for vote in trigger_votes):
        return "pending"
    return "not-reportable" if reach_verdict == "out-of-model" else "reportable"


def _publication_detail(
    state: str,
    reach_verdict: str,
    reach_detail: str,
    review_facts: dict[str, str] | None,
    attacker_controls: list[str] | None = None,
    *,
    direct_trigger_proof: bool = False,
) -> str:
    """The reason a receipt records, matching the decision it records.

    `reach_detail` compares the report's self-declared `Trigger source`, which
    `_final_publication_state` lets the source review outrank. Recording the
    reach reason under a decision the review made leaves the receipt
    contradicting itself — "trigger within attacker_controls=bytes" stamped on
    a `not-reportable` artifact — and sends whoever reads it afterwards
    looking for the bug in the wrong gate.
    """
    if state == "pending":
        return _UNSETTLED_REVIEW_DETAIL
    facts = review_facts or {}
    controls = ",".join(attacker_controls or [])
    # Match _final_publication_state's precedence. A lower-priority review fact
    # must not explain a decision made by the contract or machine-proof branch.
    if reach_verdict == "contract-flag":
        return reach_detail
    if facts.get("rejection_kind") == "no-added-boundary":
        return "real defect that crosses no security boundary"
    if direct_trigger_proof:
        return (
            "confirmed probe placed the trigger within "
            f"attacker_controls={controls}"
        )
    fit = facts.get("trigger_controls_fit")
    if fit in {"within", "outside"}:
        return (
            f"source review placed the trigger {fit} "
            f"attacker_controls={controls}"
        )
    return reach_detail


def _set_contract_concern(report: Path, reason: str) -> None:
    text = _read(report)
    heading = report_identity.CONTRACT_CONCERN_HEADING
    boundary = "|".join(re.escape(p) for p in report_identity.SECTION_BOUNDARY_PREFIXES)
    text = re.sub(
        rf"\n?{re.escape(heading)}\s*\n.*?(?=\n(?:{boundary})|\Z)", "", text,
        flags=re.DOTALL,
    ).rstrip()
    block = (
        f"{heading}\n\n"
        f"Triage kept this crash and flagged a contract concern: {reason}.\n\n"
        "The diagnostic is real; downstream scoring recomputes the impact "
        "from the report fields and target.toml.\n\n"
    )
    summary = re.search(r"(?m)^(?:Summary:|##\s+Summary\s*$)", text)
    updated = text[:summary.start()] + block + text[summary.start():] if summary else text + "\n\n" + block
    report.write_text(updated.rstrip() + "\n", encoding="utf-8")
    (report.parent / ".contract-flagged").write_text(
        f"# Contract-flagged by triage\n# Reason: {reason}\n", encoding="utf-8"
    )


def _clear_contract_concern(report: Path) -> None:
    (report.parent / ".contract-flagged").unlink(missing_ok=True)
    text = _read(report)
    updated = re.sub(
        r"\n?## Contract concern\s*\n.*?(?=\n(?:## |Summary:)|\Z)", "", text,
        flags=re.DOTALL,
    )
    if updated != text:
        report.write_text(updated.rstrip() + "\n", encoding="utf-8")


def _run_tool(
    name: str, *args: str, env: dict | None = None,
    stdin_data: bytes | None = None,
) -> int:
    return subprocess.run(
        [str(SCRIPT_ROOT / "bin" / name), *map(str, args)],
        env=env, input=stdin_data, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, check=False,
    ).returncode


_REPORT_GATE_DEFAULT_MAX_BYTES = 96 * 1024


def _report_gate_cap() -> int:
    try:
        cap = int(os.environ.get(
            "REPORT_GATE_MAX_BYTES", _REPORT_GATE_DEFAULT_MAX_BYTES,
        ))
    except ValueError:
        return _REPORT_GATE_DEFAULT_MAX_BYTES
    return cap if cap >= 1 else _REPORT_GATE_DEFAULT_MAX_BYTES


def read_report_bounded(path: Path) -> str:
    """Read a report for an LLM gate, bounded by REPORT_GATE_MAX_BYTES.

    Reports at or under the cap (the overwhelming majority) are returned whole,
    so a real finding is never judged on a truncated prefix. On overflow, return
    a head+tail slice joined by a visible elision marker — head-biased because
    the verdict-critical structure sits at the top and middle, tail kept so the
    closing Impact/Reproduction sections stay in view — and warn once on stderr.
    Bytes are never dropped silently."""
    cap = _report_gate_cap()
    try:
        size = path.stat().st_size
        if size <= cap:
            return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if not size:
        return ""
    tail = cap // 4
    head = cap - tail
    dropped = size - head - tail
    try:
        with path.open("rb") as stream:
            head_data = stream.read(head)
            stream.seek(-tail, os.SEEK_END)
            tail_data = stream.read(tail)
    except OSError:
        return ""
    print(
        f"POSSIBLE-FALSE-NEGATIVE: report '{path}' is {size} bytes "
        f"(> REPORT_GATE_MAX_BYTES={cap}); the LLM gate saw head {head}B + tail {tail}B "
        f"and {dropped}B from the middle were elided. Raise REPORT_GATE_MAX_BYTES so the "
        f"gate sees the whole report.",
        file=sys.stderr,
    )
    marker = f"\n\n[... {dropped} bytes elided by REPORT_GATE_MAX_BYTES (oversize report) ...]\n\n"
    return (
        head_data.decode("utf-8", errors="replace")
        + marker
        + tail_data.decode("utf-8", errors="replace")
    )


# Root Cause / Data Flow placeholder lines a bin/probe skeleton carries until an
# agent enriches them; anchored to line start so an instructional mention does
# not keep an otherwise-complete report pending forever.
_SKELETON_MARKER = re.compile(r"^_TODO \(agent\):", re.MULTILINE)
_PENDING_SIDECARS = (".promotion_pending", ".promotion_pending.sig", ".promotion_pending.count")


def _promotion_pending_max() -> int:
    try:
        value = int(os.environ.get("CRASH_PROMOTION_PENDING_MAX", "10"))
    except ValueError:
        return 10
    return value if value >= 0 else 10


def _clear_promotion_sidecars(directory: Path) -> None:
    """Retire the pending sidecars wherever a reader will look for them.

    `cluster_common.promotion_pending_reasons` searches beside the report *and*
    under `.audit/`, where export and pooling move sidecars. Clearing only the
    top level left the `.audit/` copy behind, so a crash that later reproduced
    5/5 with sanitizer output still published as PENDING off a marker no pass
    could reach. Reader and writer now cover the same two places.
    """
    for base in (directory, directory / ".audit"):
        for name in _PENDING_SIDECARS:
            try:
                (base / name).unlink(missing_ok=True)
            except OSError:
                pass


def _bump_promotion_pending(directory: Path, scope: str, missing: list[str]) -> int:
    """Track repeated promotion-pending state across triage passes. Same missing
    signature as last pass → count += 1; a different (or first) signature resets
    to 1. The scope prefix ('missing'/'bundle') keeps unrelated failure sets from
    aggregating."""
    signature = scope + ":" + ",".join(sorted(set(missing)))
    sig_path = directory / ".promotion_pending.sig"
    count_path = directory / ".promotion_pending.count"
    previous_sig = ""
    if sig_path.is_file():
        try:
            lines = sig_path.read_text(encoding="utf-8").splitlines()
            previous_sig = lines[0] if lines else ""
        except OSError:
            pass
    previous_count = 0
    if count_path.is_file():
        try:
            previous_count = int(count_path.read_text(encoding="utf-8").splitlines()[0])
        except (OSError, ValueError, IndexError):
            previous_count = 0
    count = previous_count + 1 if signature == previous_sig else 1
    try:
        sig_path.write_text(signature + "\n", encoding="utf-8")
        count_path.write_text(f"{count}\n", encoding="utf-8")
    except OSError:
        pass
    return count


def _log_ttl_false_negative(
    crash_id: str, count: int, maximum: int, missing_csv: str, report: Path | None
) -> None:
    """A crash aged out of crashes/ after too many incomplete passes is NOT a
    non-security autodiscard — the sanitizer signal may be real and this is more
    likely a bundling/reproduction failure. Warn loudly and annotate in place so
    an operator can spot a lost bug without grepping every rejected dir."""
    print(
        f"POSSIBLE-FALSE-NEGATIVE: crashes/{crash_id} aged out of crashes/ after "
        f"{count}/{maximum} incomplete triage passes; missing artifact(s): {missing_csv}. "
        f"The dir is preserved at crashes-rejected/{crash_id}; the sanitizer signal may be "
        f"real. Raise CRASH_PROMOTION_PENDING_MAX (current={maximum}) to give bundling "
        f"more passes.",
        file=sys.stderr,
    )
    if report is not None and report.is_file():
        try:
            with report.open("a", encoding="utf-8") as stream:
                stream.write(
                    "\n## Possible false negative — incomplete-bundle TTL\n\n"
                    f"This crash dir was moved to `crashes-rejected/` after {count}/{maximum} "
                    f"consecutive triage passes left it incomplete (missing: {missing_csv}). It is "
                    "not a non-security class by signal — the sanitizer diagnostic may be real; "
                    "this is most likely a bundling / reproduction failure.\n"
                )
        except OSError:
            pass


def _write_pending_marker(directory: Path, missing: list[str]) -> None:
    try:
        (directory / ".promotion_pending").write_text(
            "\n".join(missing) + "\n", encoding="utf-8"
        )
    except OSError:
        pass


def _hold_incomplete(
    crash_dir: Path,
    rejected_root: Path,
    report: Path | None,
    scope: str,
    missing: list[str],
    *,
    age_pending: bool = True,
) -> str:
    # Give a held bundle a pending receipt so it reports in the pending lane.
    # Without one it is indistinguishable from an artifact written before
    # receipts existed, i.e. it reads as un-migrated data rather than as a real
    # crash still waiting on evidence.
    validation_receipt.write(
        crash_dir, kind="crash", state="pending",
        detail=f"incomplete {scope}: missing {','.join(missing)}",
    )
    if not age_pending:
        _write_pending_marker(crash_dir, missing)
        return "pending"
    maximum = _promotion_pending_max()
    count = _bump_promotion_pending(crash_dir, scope, missing)
    _write_pending_marker(crash_dir, missing)
    if count < maximum:
        return "pending"
    missing_csv = ",".join(missing)
    _log_ttl_false_negative(crash_dir.name, count, maximum, missing_csv, report)
    _clear_promotion_sidecars(crash_dir)
    prefix = "bundle-incomplete" if scope == "bundle" else "never-reproduced-under-sanitizer"
    _reject(
        crash_dir, rejected_root,
        f"{prefix}: missing {missing_csv} across {count} triage passes",
    )
    return "rejected"


def _nonempty(path: Path) -> bool:
    try:
        return path.is_file() and path.stat().st_size > 0
    except OSError:
        return False


def _bundle_missing_artifacts(directory: Path) -> list[str]:
    missing: list[str] = []
    for name in ("REPORT.md", "reproduce.sh"):
        if not _nonempty(directory / name):
            missing.append(name)

    diagnostic = next(
        (path for path in (directory / "sanitizer.txt",) if path.is_file()), None)
    if diagnostic is None:
        missing.append("sanitizer.txt")
    elif not has_valid_diagnostic(_read(diagnostic)):
        missing.append("sanitizer.txt(valid)")

    inputs = []
    try:
        candidates = list(directory.glob("input.*"))
    except OSError:
        candidates = []
    for path in candidates:
        lower = path.name.lower()
        if any(lower.endswith(suffix) for suffix in (
            ".asan.txt", ".msan.txt", ".tsan.txt", ".ubsan.txt",
        )):
            continue
        if _nonempty(path):
            inputs.append(path)
    if not inputs and crash_artifacts.find_harness_source((directory,)) is None:
        missing.append("input.* or harness.*")
    return missing


def _bundle_needs_refresh(directory: Path) -> bool:
    if _bundle_missing_artifacts(directory):
        return True
    source = directory / ".audit" / "report.md"
    rendered = directory / "REPORT.md"
    try:
        return source.is_file() and source.stat().st_mtime_ns > rendered.stat().st_mtime_ns
    except OSError:
        return False


def _ubsan_class(text: str) -> str:
    if not _UBSAN_REPORT.search(text):
        return ""
    return "security" if _UBSAN_SECURITY.search(text) else "nonsecurity"


def _has_memory_safety_signal(text: str) -> bool:
    return bool(
        stack_frames.memory_safety_class(text)
        or _OTHER_MEMORY_SAFETY.search(text)
        or _ubsan_class(text) == "security"
    )


def _harness_rooted(crash_dir: Path) -> bool:
    # bin/severity owns frame classification; triage only consumes its focused
    # exit-status API so the harness/target boundary cannot drift in two places.
    try:
        return subprocess.run(
            [
                str(SCRIPT_ROOT / "bin" / "severity"), "--report", str(crash_dir),
                "--harness-rooted-check",
            ],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        ).returncode == 0
    except OSError as exc:
        print(f"WARN: harness-rooted check unavailable for {crash_dir}: {exc}", file=sys.stderr)
        return False


_SOURCE_FRAME_RE = re.compile(r"^(?P<path>.+\.\w+):\d+(?::\d+)?$")


def _fault_frame_is_in_target(sanitizer_text: str, target_root: Path) -> bool:
    """Prove the first source-bearing fault frame belongs to the target tree."""
    try:
        root = target_root.resolve(strict=True)
    except OSError:
        return False
    for line in sanitizer_text.splitlines():
        frame = stack_frames.parse_asan_frame(line)
        if frame is None:
            continue
        match = _SOURCE_FRAME_RE.match(frame.location or "")
        if not match:
            continue
        source = Path(match.group("path"))
        if source.is_absolute():
            try:
                return source.resolve(strict=False) == root or root in source.resolve(strict=False).parents
            except OSError:
                return False
        if ".." in source.parts:
            return False
        direct = root / source
        if direct.is_file():
            return True
        if len(source.parts) != 1:
            return False
        try:
            matches = [path for path in root.rglob(source.name) if path.is_file()]
        except OSError:
            return False
        return len(matches) == 1
    return False


def _direct_probe_trigger_bypass(
    crash_dir: Path,
    target_root: Path,
    attacker_controls: list[str],
) -> bool:
    """Prove a confirmed crash came from the target's ordinary byte-input path.

    Every condition is machine-authored and fail-closed. Missing legacy evidence
    simply keeps the existing LLM trigger review; it never rejects a crash.

    The empty-argv requirement makes this rare in practice — it fired on none
    of 268 crash directories across a full benchmark, because a decoder or a
    shell needs flags to read a file at all. Accepting the target's configured
    argv instead was measured and rejected: it would reach seven more
    artifacts while dropping the one independent reachability check on a
    sanitizer-confirmed crash, and a runner's operator-chosen flag can itself
    be the precondition the review exists to disclose.
    """
    bypass = crash_dir / ".trigger-gate-bypass.json"
    bypass.unlink(missing_ok=True)
    controls = {str(value).strip().lower() for value in attacker_controls}
    context = crash_bundle.verified_probe_context(crash_dir)
    if (
        "bytes" not in controls
        or context is None
        or context.get("mode") != "generic"
        or context.get("sanitizer") == "runner"
        or context.get("harness") is not False
        or context.get("args") != []
    ):
        return False
    build_config_id = str(context.get("build_config_id") or "")
    primary_differential = crash_bundle.verified_primary_differential(crash_dir)
    if build_config_id and (
        primary_differential is None
        or primary_differential.get("status") != "reproduced"
    ):
        # An alternate-config invocation is not proof of the ordinary primary
        # byte-input path. Keep the normal trigger reviewers unless the same
        # sanitizer fault was machine-confirmed on the primary build.
        return False
    binary = (context.get("binary") or {}).get("path")
    try:
        binary_path = Path(binary).resolve(strict=True)
        root = target_root.resolve(strict=True)
    except (OSError, TypeError):
        return False
    if binary_path != root and root not in binary_path.parents:
        return False
    if not os.access(binary_path, os.X_OK):
        return False
    sanitizer = _sanitizer_file(crash_dir)
    if sanitizer is None:
        return False
    sanitizer_text = _read(sanitizer)
    rates = re.findall(r"^CRASH_RATE:\s*(\d+)\s*/\s*(\d+)\s*$", sanitizer_text, re.MULTILINE)
    if not rates or rates[-1] != ("5", "5"):
        return False
    if not _fault_frame_is_in_target(sanitizer_text, root):
        return False
    _write_atomic_json(
        bypass,
        {
            "decision_version": "direct-probe-v2",
            "bypass": True,
            "reason": (
                "same sanitizer fault confirmed 5/5 on the primary target byte-input invocation"
                if build_config_id
                else "bin/probe --confirm 5/5 through standard target byte-input invocation"
            ),
            "binary": str(binary_path),
            "primary_differential": primary_differential.get("status") if build_config_id else "not-needed",
        },
    )
    return True


def _cached_trigger_vote(report: Path, vote_file: Path) -> str | None:
    """Return only a verdict produced for this prompt version and report."""
    try:
        payload = json.loads(vote_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None
    content_sha1s = report_identity.content_sha1_candidates(report)
    if payload.get("content_sha1") not in content_sha1s:
        return None
    vote = payload.get("vote")
    if vote not in {"Promote", "Reject", "Uncertain"}:
        return None
    version = payload.get("decision_version")
    if version in {
        triage_validate.TRIGGER_GATE_DECISION_VERSION,
        triage_validate.TRIGGER_RESOLUTION_DECISION_VERSION,
    }:
        if version == triage_validate.TRIGGER_RESOLUTION_DECISION_VERSION:
            if vote_file.name != _TRIGGER_RESOLUTION_NAME:
                return None
            prior_paths = _trigger_resolution_sources(report, vote_file.parent)
            if not prior_paths:
                return None
            prior_sha256s = triage_validate.prior_review_sha256s(prior_paths)
            if payload.get("prior_review_sha256s") != prior_sha256s:
                return None
        # A current verdict is only reusable under the threat model it was
        # produced for; a controls, revision, or config change forces review.
        if payload.get("attacker_controls") != triage_validate.trigger_attacker_controls():
            return None
        evidence = crash_bundle.recorded_evidence_context(report.parent)
        evidence_id = evidence.get("evidence_id") if evidence else None
        if evidence_id != payload.get("evidence_id"):
            return None
        for key, environment_name in (
            ("target_revision", "TARGET_REV"),
            ("target_config_sha256", "TARGET_CONFIG_SHA256"),
        ):
            current_scope = str(
                (evidence or {}).get(key)
                or os.environ.get(environment_name, ""),
            )
            if str(payload.get(key) or "") != current_scope:
                return None
        if vote in {"Promote", "Reject"}:
            anchors = payload.get("anchors")
            if (
                payload.get("anchors_verified") is not True
                or not isinstance(anchors, list)
                or not anchors
            ):
                return None
            target_root_value = os.environ.get("TARGET_ROOT", "")
            target_root = Path(target_root_value)
            if target_root_value and target_root.is_dir():
                verified = triage_validate.verify_source_anchors(
                    anchors, target_root,
                )
                if verified != anchors:
                    return None
        return vote
    # Legacy verdicts predate controls binding: reuse only their non-negative
    # decisions (fail-open keep), never a Reject that could hide a real issue.
    if (
        version in triage_validate.TRIGGER_GATE_ADVISORY_VERSIONS
        and vote in {"Promote", "Uncertain"}
    ):
        # Legacy positive votes remain visible but are provisional until the
        # source-anchor schema is refreshed. Legacy Rejects remain ignored.
        return "Uncertain"
    return None


def _promote_left_scope_open(report: Path, vote_file: Path) -> bool:
    """A Promote whose reviewer placed the trigger neither within nor outside
    the declared controls. Reachability is settled, scope is not, and scope is
    what publishes: without a resolver the artifact stayed `pending` for good."""
    if _cached_trigger_vote(report, vote_file) != "Promote":
        return False
    facts = _source_review_facts(report, (vote_file,))
    return facts.get("trigger_controls_fit") not in {"within", "outside"}


def _trigger_resolution_sources(report: Path, directory: Path) -> tuple[Path, ...]:
    """Return the cached reviews a focused resolver must adjudicate."""
    first = directory / _TRIGGER_PRIMARY_NAME
    first_vote = _cached_trigger_vote(report, first)
    second = directory / _TRIGGER_SECOND_NAME
    names = triage_validate.trigger_resolution_review_names(
        first_vote, _cached_trigger_vote(report, second),
        first_scope_open=_promote_left_scope_open(report, first),
    )
    return tuple(directory / name for name in names)


#: Facts that describe the artifact rather than answer the disputed question.
#: A resolver is pointed at one open question and fills the rest of the schema
#: in passing, so these stay with the reviewers when those agreed.
_DESCRIPTIVE_REVIEW_FACTS = ("vulnerable_boundary_surface", "reproducer_carrier")


def _trigger_publication_evidence(
    report: Path, directory: Path,
) -> tuple[set[str | None], dict[str, str]]:
    """Return the votes and source facts that actually settled publication.

    A resolution owns the verdict and the question it was asked -- scope and
    rejection kind -- because it read the reviews it adjudicated. It does not
    own what those reviews already agreed on: `vulnerable_boundary_surface`
    overrides the Surface that severity scores, and on the split reviews
    measured here the two reviewers agreed on it every time while disagreeing
    only about scope. Letting one resolver's incidental answer replace a
    two-reviewer consensus would move published severity on a field nobody
    disputed, so consensus stands and the resolution fills the rest.
    """
    reviews = tuple(directory / name for name in _TRIGGER_REVIEW_NAMES)
    resolution = directory / _TRIGGER_RESOLUTION_NAME
    resolution_vote = _cached_trigger_vote(report, resolution)
    if resolution_vote is None:
        return (
            {_cached_trigger_vote(report, path) for path in reviews},
            _source_review_facts(report, reviews, rejection_quorum=2),
        )
    facts = _source_review_facts(report, (resolution,), rejection_quorum=2)
    agreed = _source_review_facts(report, reviews, rejection_quorum=2)
    facts.update({
        key: agreed[key]
        for key in _DESCRIPTIVE_REVIEW_FACTS if key in agreed
    })
    return {resolution_vote}, facts


def _source_review_facts(
    report: Path, vote_files: tuple[Path, ...], *, rejection_quorum: int = 1,
) -> dict[str, str]:
    """Return verified boundary facts only when current reviewers agree."""
    observed: dict[str, dict[str, int]] = {
        "vulnerable_boundary_surface": {},
        "reproducer_carrier": {},
        "rejection_kind": {},
        "trigger_controls_fit": {},
    }
    for vote_file in vote_files:
        if _cached_trigger_vote(report, vote_file) not in {"Promote", "Reject"}:
            continue
        try:
            payload = json.loads(vote_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        facts = triage_validate.source_review_facts(payload.get("review_facts"))
        for key, value in facts.items():
            observed[key][value] = observed[key].get(value, 0) + 1
    settled = {
        key: next(iter(counts))
        for key, counts in observed.items()
        if (
            len(counts) == 1
            and (
                key != "rejection_kind"
                or next(iter(counts.values())) >= rejection_quorum
            )
        )
    }
    if "trigger_controls_fit" not in settled:
        scope = _unsettled_scope_fact(report, vote_files)
        if scope:
            settled["trigger_controls_fit"] = scope
    return settled


def _unsettled_scope_fact(report: Path, vote_files: tuple[Path, ...]) -> str:
    """Scope from reviewers that read the source and did not settle the defect.

    The prompt asks an Uncertain reviewer for this one field ("Do not use
    Uncertain to park a case you did establish — say so through the vote and
    `trigger_controls_fit`"), and `stamp_trigger_vote` then drops it with the
    rest of that vote's facts, so it is read back off the vote itself.

    A fallback, never a peer: consulted only when no settled reviewer answered
    the scope question, so it can neither contradict one nor turn agreement into
    a split. Scope is the only field taken this way — `rejection_kind` demotes on
    its own, and an unsettled reviewer must not carry that. It cannot publish
    anything either: `_final_publication_state` routes an Uncertain vote to
    `pending` before it reads `within`, so the one disposition this can add is
    the `outside` one, which withholds credit rather than granting it.

    Withholding credit is still terminal, though — `not-reportable` drops the
    artifact out of the unjudged floor — so "cannot publish" is not the whole
    safety argument. The citations are re-read against the source as it stands,
    the way a settled vote's are, and anything unverifiable here contributes no
    fact at all, leaving the artifact pending.
    """
    observed: set[str] = set()
    for vote_file in vote_files:
        if _cached_trigger_vote(report, vote_file) != "Uncertain":
            continue
        try:
            payload = json.loads(vote_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        # Anchors are what make the reading verifiable, and the recorded bit
        # only says they verified once. `not-reportable` is terminal — it drops
        # the artifact out of the unjudged floor — so the citations are checked
        # against the source as it stands now, exactly as a settled vote's are.
        # A stale anchor contributes nothing and the artifact stays pending.
        anchors = payload.get("anchors")
        if payload.get("anchors_verified") is not True or not anchors:
            continue
        target_root_value = os.environ.get("TARGET_ROOT", "")
        target_root = Path(target_root_value)
        if not target_root_value or not target_root.is_dir():
            continue
        if triage_validate.verify_source_anchors(anchors, target_root) != anchors:
            continue
        fit = triage_validate.source_review_facts(payload).get(
            "trigger_controls_fit"
        )
        if fit:
            observed.add(fit)
    return next(iter(observed)) if len(observed) == 1 else ""


_TRIGGER_BATCH_SIZE = 4


def _trigger_review_seconds() -> int:
    """The wall for one provenance review session, whatever it carries.

    A review that runs out of wall emits no vote at all, so its ids fall
    through to a retry that pays a fresh wall over again; at the bare hosted
    tier that was starving 5 of 16 batches and 3 of 20 singletons. Cost sits in
    per-session setup rather than per-item work — a four-item batch runs about
    1.4x a singleton, not 4x — so the wall does not scale with the batch. The
    measured default is registered as a decision default rather than fixed
    here, so an explicit `LLM_DECISION_TIMEOUT` still overrides it and a slow
    `oss` host still gets the tier's proportional room.
    """
    return llm_decide.decision_timeout("trigger_validator")


def _batch_finding_trigger_votes(
    directories: list[Path], results_dir: Path, deadline: float | None,
    usage_index: str | os.PathLike[str] | None,
    target_root_is_product: bool,
    workers: int = 4,
    vote_name: str = ".trigger-gate.json",
) -> set[Path]:
    """Populate one round of independent keyed trigger votes in batches."""
    resolution = vote_name == _TRIGGER_RESOLUTION_NAME
    backend = os.environ.get("ACTIVE_BACKEND") or os.environ.get("BACKEND") or ""
    target_root = Path(os.environ.get("TARGET_ROOT", ""))
    # Same preconditions `_trigger_vote` checks before spending a session. With
    # reviews disabled nothing is attempted, so claim nothing: the serial gate
    # reaches the same no-verdict outcome without spawning the reviewer an
    # operator switched off.
    if (
        not backend
        or not target_root.is_dir()
        or os.environ.get("LLM_DECIDE_DISABLE") == "1"
    ):
        return set()
    if llm_decide.provider_limit_open():
        return set(directories)
    pending = []
    for directory in directories:
        vote_file = directory / vote_name
        report = _report(directory)
        if report is None:
            continue
        if vote_file.is_file() and vote_file.stat().st_size:
            if _cached_trigger_vote(report, vote_file) is not None:
                continue
            vote_file.unlink(missing_ok=True)
        pending.append((directory, report, vote_file))
    raw_dir = (
        Path(usage_index).parent / ".raw"
        if usage_index else results_dir / "logs" / ".raw"
    )
    raw_dir.mkdir(parents=True, exist_ok=True)
    batches = [
        pending[start:start + _TRIGGER_BATCH_SIZE]
        for start in range(0, len(pending), _TRIGGER_BATCH_SIZE)
    ]
    attempted = {directory for directory, _report_path, _vote_file in pending}

    model = os.environ.get("MODEL", "")

    def run_batch(batch: list[tuple[Path, Path, Path]], tag: str, timeout: int) -> int:
        """Validate one batch.

        The validator preserves the timeout status (124) to distinguish a
        consumed review wall from another
        transient backend failure (2), and our outer hard timeout maps to the
        same wall-exhausted status.
        """
        manifest = raw_dir / f"trigger-batch-{os.getpid()}-{time.time_ns()}-{tag}.json"
        payload = {
            "items": [
                {
                    "id": directory.name,
                    "finding": str(report),
                    "output": str(vote_file),
                    **(
                        {
                            "prior_reviews": [
                                str(path) for path in _trigger_resolution_sources(
                                    report, directory,
                                )
                            ],
                        }
                        if resolution else {}
                    ),
                }
                for directory, report, vote_file in batch
            ]
        }
        _write_atomic_json(manifest, payload)
        command = [
            str(SCRIPT_ROOT / "bin" / "validate-finding"),
            "--batch-manifest", str(manifest), "--target-path", str(target_root),
            "--backend", backend, "--gate", "trigger", "--timeout", str(timeout),
        ]
        if resolution:
            command.append("--resolve-trigger")
        if model:
            command += ["--model", model]
        if usage_index:
            command += ["--usage-index", os.fspath(usage_index)]
        if target_root_is_product:
            command.append("--target-root-is-product")
        try:
            return subprocess.run(
                command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=timeout + 2, check=False,
            ).returncode
        except subprocess.TimeoutExpired:
            return 124
        finally:
            manifest.unlink(missing_ok=True)

    def validate(
        index_and_batch: tuple[int, list[tuple[Path, Path, Path]]],
    ) -> tuple[int, list[tuple[Path, Path, Path]], int | None]:
        index, batch = index_and_batch
        timeout = _decision_timeout(_trigger_review_seconds(), deadline)
        if timeout <= 0 or llm_decide.provider_limit_open():
            return index, batch, None
        return index, batch, run_batch(batch, str(index), timeout)

    if not batches:
        return attempted
    with ThreadPoolExecutor(max_workers=min(max(1, workers), len(batches))) as pool:
        first_results = list(pool.map(validate, enumerate(batches)))

    retries: list[tuple[str, list[tuple[Path, Path, Path]]]] = []
    for index, batch, rc in first_results:
        # Retry exactly once, and only ids still unvoted after a completed
        # response or a consumed review wall. A source-heavy four-item review
        # can exhaust its wall before emitting any keyed output; retrying the
        # same group on every regeneration permanently starves those ids.
        # Only that demonstrated failure earns singleton walls. Completed
        # partial/parse-failed responses keep the old grouped retry, while
        # provider failures (2) are never hot-retried.
        # Finish the whole first wave first so an early incomplete batch cannot
        # consume the shared deadline ahead of untouched ids.
        if rc not in (0, 3, 124):
            continue
        missing = [
            (directory, report, vote_file)
            for directory, report, vote_file in batch
            if _cached_trigger_vote(report, vote_file) is None
        ]
        if rc == 124:
            retries.extend(
                (f"{index}-retry-{offset}", [item])
                for offset, item in enumerate(missing)
            )
        elif missing:
            retries.append((f"{index}-retry", missing))

    def retry(tag_and_batch: tuple[str, list[tuple[Path, Path, Path]]]) -> None:
        tag, batch = tag_and_batch
        timeout = _decision_timeout(_trigger_review_seconds(), deadline)
        if timeout <= 0 or llm_decide.provider_limit_open():
            return
        run_batch(batch, tag, timeout)

    if retries:
        with ThreadPoolExecutor(max_workers=min(max(1, workers), len(retries))) as pool:
            list(pool.map(retry, retries))
    return attempted


def _trigger_vote(
    report: Path, vote_file: Path, backend: str, model: str,
    target_root: Path, deadline: float | None = None,
    usage_index: str | os.PathLike[str] | None = None,
    target_root_is_product: bool = False,
    *, resolve: bool = False,
) -> int:
    """Run the recall-safe trigger-provenance reviewer (`validate-finding --gate
    trigger`) over a report. Returns 1 = disproof-backed Reject, 0 = keep
    (Promote/Uncertain), 2 = no verdict yet (retryable). Only a conclusive cached
    verdict short-circuits a re-run; a cached ParseFailure is not a verdict and
    falls through to retry."""
    if vote_file.is_file() and vote_file.stat().st_size:
        cached = _cached_trigger_vote(report, vote_file)
        if cached == "Reject":
            return 1
        if cached in ("Promote", "Uncertain"):
            return 0
    if os.environ.get("LLM_DECIDE_DISABLE") == "1":
        return 2
    if llm_decide.provider_limit_open():
        return 2
    if not (report.is_file() and report.stat().st_size) or not target_root.is_dir() or not backend:
        return 2
    timeout = _decision_timeout(_trigger_review_seconds(), deadline)
    if timeout <= 0:
        return 2
    command = [
        str(SCRIPT_ROOT / "bin" / "validate-finding"),
        "--finding", str(report), "--target-path", str(target_root),
        "--backend", backend, "--gate", "trigger", "--output", str(vote_file),
        "--timeout", str(timeout),
    ]
    if resolve:
        command.append("--resolve-trigger")
        for prior in _trigger_resolution_sources(report, vote_file.parent):
            command += ["--prior-review", str(prior)]
    if model:
        command += ["--model", model]
    if usage_index:
        command += ["--usage-index", os.fspath(usage_index)]
    if target_root_is_product:
        command.append("--target-root-is-product")
    try:
        rc = subprocess.run(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout + 2, check=False,
        ).returncode
    except subprocess.TimeoutExpired:
        return 2
    if rc not in (0, 1, 2):
        raw = vote_file.with_suffix(".raw.log")
        try:
            llm_decide.record_provider_limit(
                raw.read_text(encoding="utf-8", errors="replace")
            )
        except OSError:
            pass
    # Exit 1 is also Python's default for an uncaught validator exception. Trust
    # only the content-addressed artifact, never the process status, for a
    # finding-removing Reject.
    vote = _cached_trigger_vote(report, vote_file)
    if vote == "Reject":
        return 1
    if vote in {"Promote", "Uncertain"}:
        return 0
    return 2


def _crash_trigger_gate(
    crash_dir: Path, report: Path, target_root: Path,
    deadline: float | None = None,
    usage_index: str | os.PathLike[str] | None = None,
    target_root_is_product: bool = False,
    attacker_controls: list[str] | None = None,
    direct_probe_bypass: bool | None = None,
) -> bool:
    """Recall-safe trigger-provenance gate for a kept crash. A `bytes`-labelled
    trigger passes evaluate_crash_verdict's set-difference even when those bytes
    are internal state only a trusted in-process caller could forge; this
    independent source-reading reviewer applies the same reachability test to
    every trigger kind. A sanitizer-confirmed crash is higher-consequence than a
    finding, so it requires TWO independent disproof-backed Rejects before
    rejection — a single or disagreeing vote keeps the crash. Default on; opt out
    with CRASH_TRIGGER_GATE=0. Returns True to reject."""
    if os.environ.get("CRASH_TRIGGER_GATE", "1") == "0":
        return False
    bypass = (
        _direct_probe_trigger_bypass(
            crash_dir, target_root, attacker_controls or ["bytes"],
        )
        if direct_probe_bypass is None else direct_probe_bypass
    )
    if bypass:
        _review_ambiguous_crash_surface(
            crash_dir, report, target_root, deadline, usage_index,
            target_root_is_product,
        )
        return False
    backend = os.environ.get("ACTIVE_BACKEND") or os.environ.get("BACKEND") or ""
    model = os.environ.get("MODEL", "")
    first = crash_dir / _TRIGGER_PRIMARY_NAME
    if _trigger_vote(
        report, first, backend, model,
        target_root, deadline, usage_index,
        target_root_is_product,
    ) != 1:
        if (
            _cached_trigger_vote(report, first) == "Uncertain"
            or _promote_left_scope_open(report, first)
        ):
            _trigger_vote(
                report, crash_dir / _TRIGGER_RESOLUTION_NAME, backend, model,
                target_root, deadline, usage_index, target_root_is_product,
                resolve=True,
            )
        return False
    second = crash_dir / _TRIGGER_SECOND_NAME
    if _trigger_vote(
        report, second, backend, model,
        target_root, deadline, usage_index,
        target_root_is_product,
    ) != 1:
        if _cached_trigger_vote(report, second) in {"Promote", "Uncertain"}:
            resolution = crash_dir / _TRIGGER_RESOLUTION_NAME
            _trigger_vote(
                report, resolution, backend, model, target_root, deadline,
                usage_index, target_root_is_product, resolve=True,
            )
            if _cached_trigger_vote(report, resolution) == "Reject":
                return _trigger_rejection_is_dispositive(
                    report, (first, resolution),
                )
        return False
    return _trigger_rejection_is_dispositive(
        report, (first, second),
    )


def _review_ambiguous_crash_surface(
    crash_dir: Path, report: Path, target_root: Path,
    deadline: float | None,
    usage_index: str | os.PathLike[str] | None,
    target_root_is_product: bool,
) -> None:
    """Source-review boundary/carrier only when the report leaves them conflated."""
    if os.environ.get("CRASH_TRIGGER_GATE", "1") == "0":
        return
    if not _crash_surface_needs_review(report):
        return
    backend = os.environ.get("ACTIVE_BACKEND") or os.environ.get("BACKEND") or ""
    if not backend or not target_root.is_dir():
        return
    _trigger_vote(
        report, crash_dir / ".trigger-gate.json", backend,
        os.environ.get("MODEL", ""), target_root, deadline, usage_index,
        target_root_is_product,
    )


def _crash_surface_needs_review(report: Path) -> bool:
    surface = _field(_read(report), "Surface").lower()
    kind = surface.split("—", 1)[0].split("-", 1)[0].strip()
    return kind in {"", "cli", "unknown"}


def _is_final_crash_receipt(receipt: dict | None) -> bool:
    """Whether a receipt is this crash's own, current, final publication."""
    return (
        receipt is not None
        and receipt.get("kind") == "crash"
        and receipt.get("state") in validation_receipt.FINAL_STATES
    )


def _crash_review_is_reusable(crash_dir: Path) -> bool:
    """Whether a receipt's trigger review still answers the current policy.

    A receipt binds its own report and gate files, so the one thing it cannot
    notice is `TRIGGER_GATE_DECISION_VERSION` moving under an unchanged vote.
    Asking here is what lets a bumped version reach an already-published crash,
    the way the findings lane's cached-finalization gate already does. Only
    callers that can actually spend a review ask: on an expired deadline the
    answer changes nothing, and discarding a verdict no pass will replace
    would lose an adjudication rather than refresh it.
    """
    if os.environ.get("CRASH_TRIGGER_GATE", "1") == "0":
        return True
    report = _report(crash_dir)
    return report is not None and _cached_trigger_resolution(crash_dir, report)


def triage_one_crash(
    crash_dir: Path,
    results_dir: Path,
    target_root: Path,
    target_slug: str,
    attacker_controls: list[str],
    findings_only: bool = False,
    deadline: float | None = None,
    target_root_is_product: bool = False,
    reach_fields_override: object = _NO_REACH_DECISION,
    confirmed_trigger_bypass: bool = False,
    age_pending: bool = True,
    trigger_batch_attempted: bool = False,
) -> str:
    report = _report(crash_dir)
    if _deadline_expired(deadline):
        current_receipt = validation_receipt.read_current(crash_dir)
        if _is_final_crash_receipt(current_receipt):
            return "promoted"
        validation_receipt.write(
            crash_dir, kind="crash", state="pending",
            detail=(
                "incomplete missing: missing report.md"
                if report is None else "crash triage deadline expired"
            ),
        )
        if report is None and current_receipt is None:
            print(
                f"WARN: {crash_dir}: missing report; held pending",
                file=sys.stderr,
            )
        return "pending"
    usage_index = benchmark._find_index_jsonl(results_dir)
    rejected_root = results_dir / "crashes-rejected"
    sanitizer = _sanitizer_file(crash_dir)
    sanitizer_text = _read(sanitizer) if sanitizer else ""
    runtime_only = _runtime_only_diagnostic(sanitizer_text, findings_only)
    if sanitizer_text and not _deadline_expired(deadline) and _harness_rooted(crash_dir):
        _clear_promotion_sidecars(crash_dir)
        _reject(
            crash_dir, rejected_root,
            "harness-rooted: fault frame in audit harness/driver, no target-library frame",
        )
        return "rejected"
    # Immediate hard reject: non-security autodiscard classes (OOM, stack
    # exhaustion, null-deref, intentional assert, runtime panic). These are
    # dispositive from the sanitizer text and never become real with more passes.
    if sanitizer_text and not runtime_only and (reason := autodiscard_reason(sanitizer_text)):
        _clear_promotion_sidecars(crash_dir)
        _reject(crash_dir, rejected_root, reason)
        return "rejected"
    # Completeness gate. An incomplete bundle — missing report, an unenriched
    # bin/probe skeleton, no valid sanitizer diagnostic, or no testcase/harness —
    # is held promotion-pending for up to CRASH_PROMOTION_PENDING_MAX passes
    # rather than rejected, so a real crash the agent is still bundling is not
    # lost. Only a persistently incomplete dir ages out to crashes-rejected/.
    missing: list[str] = []
    if report is None:
        missing.append("report.md")
    elif _SKELETON_MARKER.search(_read(report)):
        missing.append("report.md(auto-filed skeleton not yet enriched)")
    if sanitizer is None or not has_valid_diagnostic(sanitizer_text, findings_only):
        missing.append("sanitizer.txt(valid)")
    testcase = crash_artifacts.find_testcase(
        (crash_dir, crash_dir / ".audit"), sanitizer_files=(sanitizer,) if sanitizer else ()
    )
    harness = crash_artifacts.find_harness_source((crash_dir, crash_dir / ".audit"))
    if testcase is None and harness is None:
        missing.append("testcase or harness")
    if missing:
        return _hold_incomplete(
            crash_dir, rejected_root, report, "missing", missing,
            age_pending=age_pending,
        )
    if runtime_only:
        demote_to_finding(
            crash_dir,
            results_dir,
            "runtime diagnostic without a sanitizer-class memory-safety signal",
        )
        return "demoted"
    if not _has_memory_safety_signal(sanitizer_text):
        reason = (
            "UBSan non-memory-safety class - real undefined behavior, filed as a finding not a crash"
            if _ubsan_class(sanitizer_text) == "nonsecurity"
            else "sanitizer diagnostic without a recognized memory-safety class"
        )
        demote_to_finding(crash_dir, results_dir, reason)
        return "demoted"
    environment = os.environ.copy()
    environment.update(
        RESULTS_DIR=str(results_dir), TARGET_ROOT=str(target_root), TARGET_SLUG=target_slug
    )
    if _bundle_needs_refresh(crash_dir) and _decision_timeout(1, deadline):
        _run_tool(
            "export-repro", crash_dir.name, "--crash-dir", str(crash_dir),
            "--slug", target_slug, env=environment,
        )
    bundle_missing = _bundle_missing_artifacts(crash_dir)
    if bundle_missing:
        return _hold_incomplete(
            crash_dir, rejected_root, report, "bundle", bundle_missing,
            age_pending=age_pending,
        )
    report = _report(crash_dir)
    if report is None:
        return _hold_incomplete(
            crash_dir, rejected_root, None, "bundle", ["REPORT.md"],
            age_pending=age_pending,
        )
    if not _deadline_expired(deadline):
        fill_reach_fields(
            crash_dir, usage_index, decision_override=reach_fields_override,
        )
        report = _report(crash_dir) or report
    verdict, detail = evaluate_crash_verdict(_read(report), attacker_controls)
    if verdict == "incomplete":
        return _hold_incomplete(
            crash_dir, rejected_root, report, "fields",
            ["Caller contract or Trigger source"], age_pending=age_pending,
        )
    _clear_promotion_sidecars(crash_dir)
    if verdict in {"contract-flag", "out-of-model"}:
        _set_contract_concern(report, detail)
    else:
        _clear_contract_concern(report)
    direct_trigger_proof = (
        confirmed_trigger_bypass
        or _direct_probe_trigger_bypass(
            crash_dir, Path(target_root), attacker_controls,
        )
    )
    if direct_trigger_proof:
        _review_ambiguous_crash_surface(
            crash_dir, report, Path(target_root), deadline, usage_index,
            target_root_is_product,
        )
        reject_trigger = False
    elif trigger_batch_attempted and not _cached_trigger_resolution(
        crash_dir, report,
    ):
        # The keyed batch already spent this artifact's review attempt.  A
        # missing or malformed id is unadjudicated evidence, not permission to
        # launch another serial review in the same pass or to publish on one
        # incomplete vote.
        validation_receipt.write(
            crash_dir, kind="crash", state="pending",
            detail="batched source review is incomplete",
            attacker_controls=attacker_controls,
        )
        return "pending"
    else:
        reject_trigger = _crash_trigger_gate(
            crash_dir, report, Path(target_root), deadline, usage_index,
            target_root_is_product, attacker_controls,
            direct_probe_bypass=direct_trigger_proof,
        )
    if reject_trigger:
        _reject(
            crash_dir, rejected_root,
            "trigger-provenance (2 independent rejects): triggering state not attacker-reachable from a public boundary",
            category=workqueue.UNREACHABLE_REJECTION_CATEGORY,
        )
        return "rejected"
    trigger_votes, review_facts = _trigger_publication_evidence(
        report, crash_dir,
    )
    source_review_required = (
        os.environ.get("CRASH_TRIGGER_GATE", "1") != "0"
        and (
            not direct_trigger_proof
            or _crash_surface_needs_review(report)
        )
    )
    if (
        source_review_required
        and not any(
            vote in {"Promote", "Reject", "Uncertain"}
            for vote in trigger_votes
        )
    ):
        validation_receipt.write(
            crash_dir, kind="crash", state="pending",
            detail="source review is uncertain, stale, or incomplete",
            attacker_controls=attacker_controls,
        )
        return "pending"
    state = _final_publication_state(
        verdict, trigger_votes, review_facts,
        direct_trigger_proof=direct_trigger_proof,
    )
    validation_receipt.write(
        crash_dir, kind="crash", state=state,
        detail=_publication_detail(
            state, verdict, detail, review_facts, attacker_controls,
            direct_trigger_proof=direct_trigger_proof,
        ),
        attacker_controls=attacker_controls, review_facts=review_facts,
    )
    if state == "pending":
        return "pending"
    # A not-reportable decision must synchronously remove a score an earlier
    # receipt published, or an obsolete rating outlives the decision that
    # voided it. Reportable scoring may still yield to the triage deadline.
    if state == "not-reportable" or _decision_timeout(1, deadline):
        state = _score_final_report(
            crash_dir, report, "crash", state,
            attacker_controls=attacker_controls, env=environment,
        )
    return "pending" if state == "pending" else "promoted"


def triage_crash_dirs(
    results_dir: str | os.PathLike[str],
    target_root: str | os.PathLike[str],
    target_slug: str,
    attacker_controls: list[str] | None = None,
    *,
    workers: int = 4,
    findings_only: bool = False,
    deadline: float | None = None,
    target_root_is_product: bool = False,
    confirmed_trigger_bypasses: set[Path] | None = None,
    age_pending: bool = True,
    held: set[Path] | None = None,
) -> dict[str, int]:
    """Triage the crash bundles in one results tree.

    `held` names bundles this pass must not adjudicate. They keep their place
    under `crashes/` and take no verdict, so they carry no final receipt and
    are counted as unadjudicated rather than as confirmed crashes.
    """
    results = Path(results_dir)
    _restore_stale_trigger_rejections(results, kind="crash")
    route_finding_diagnostics(results)
    crashes = results / "crashes"
    crashes.mkdir(parents=True, exist_ok=True)
    controls = attacker_controls or ["bytes"]
    bypasses = set(confirmed_trigger_bypasses or ())
    withheld = held or set()
    for directory in withheld:
        if directory.is_dir():
            # A prior pass may already have finalized this exact artifact.
            # Merely skipping it would leave that receipt current and keep
            # publication credit for a crash this pass could not measure.
            validation_receipt.write(
                directory, kind="crash", state="pending",
                detail="configured-target replay could not be measured",
            )
    directories = [
        path for path in sorted(crashes.glob("CRASH-*"))
        if path.is_dir() and path not in withheld
    ]
    for directory in directories:
        sanitizer = _sanitizer_file(directory)
        sanitizer_text = _read(sanitizer) if sanitizer else ""
        if (
            _has_memory_safety_signal(sanitizer_text)
            and not autodiscard_reason(sanitizer_text)
        ):
            _materialize_crash_class(directory)
    counts = {"promoted": 0, "rejected": 0, "pending": 0, "demoted": 0}
    if not directories:
        return counts
    # A current final receipt needs no repeated triage. Cached trigger reviews
    # whose core boundary verdict is complete also need no provider call, so
    # finish those before optional severity enrichment can consume the shared
    # deadline.
    finalized: list[Path] = []
    cached_ready: list[Path] = []
    for directory in directories:
        if (
            _is_final_crash_receipt(validation_receipt.read_current(directory))
            and _crash_review_is_reusable(directory)
        ):
            finalized.append(directory)
            continue
        report = _report(directory)
        if report is None:
            continue
        reach_verdict, _reach_detail = evaluate_crash_verdict(
            _read(report), controls,
        )
        if reach_verdict == "incomplete":
            continue
        if (
            os.environ.get("CRASH_TRIGGER_GATE", "1") == "0"
            or directory in bypasses
            or _cached_trigger_resolution(directory, report)
        ):
            cached_ready.append(directory)
    counts["promoted"] += len(finalized)
    usage_index = benchmark._find_index_jsonl(results)
    if cached_ready:
        # Converge before this shortcut writes their receipts, for the same
        # reason the main path does below: a receipt must cover a report no
        # later pass needs to rewrite. Filtered first so the settled artifacts
        # this fast path exists for still reach finalization without a
        # provider-shaped call in front of them.
        owed = [d for d in cached_ready if reach_fields_open(d)]
        if owed:
            converge_reach_fields(owed, usage_index, deadline, workers)
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            cached_statuses = list(pool.map(
                lambda directory: triage_one_crash(
                    directory, results, Path(target_root), target_slug, controls,
                    findings_only, deadline, target_root_is_product,
                    _NO_REACH_DECISION, directory in bypasses, age_pending,
                ),
                cached_ready,
            ))
        for status in cached_statuses:
            counts[status] = counts.get(status, 0) + 1
    handled = set(finalized) | set(cached_ready)
    directories = [
        directory for directory in directories if directory not in handled
    ]
    if not directories:
        return counts
    reach_directories = []
    for directory in directories:
        sanitizer = _sanitizer_file(directory)
        sanitizer_text = _read(sanitizer) if sanitizer else ""
        if (
            _report(directory) is not None
            and _has_memory_safety_signal(sanitizer_text)
            and not autodiscard_reason(sanitizer_text)
        ):
            reach_directories.append(directory)
    environment = os.environ.copy()
    environment.update(
        RESULTS_DIR=str(results), TARGET_ROOT=str(target_root),
        TARGET_SLUG=target_slug,
    )
    # Trigger votes bind to report content. Export first so a vote cannot be
    # invalidated immediately when report.md becomes the canonical REPORT.md.
    # Incomplete bundles remain on triage_one_crash's ordinary pending path and
    # do not consume a source-review session.
    for directory in reach_directories:
        report = _report(directory)
        sanitizer = _sanitizer_file(directory)
        sanitizer_text = _read(sanitizer) if sanitizer else ""
        testcase = crash_artifacts.find_testcase(
            (directory, directory / ".audit"),
            sanitizer_files=(sanitizer,) if sanitizer else (),
        )
        harness = crash_artifacts.find_harness_source(
            (directory, directory / ".audit"),
        )
        if (
            report is not None
            and not _SKELETON_MARKER.search(_read(report))
            and has_valid_diagnostic(sanitizer_text, findings_only)
            and (testcase is not None or harness is not None)
            and _bundle_needs_refresh(directory)
            and _decision_timeout(1, deadline)
        ):
            _run_tool(
                "export-repro", directory.name, "--crash-dir", str(directory),
                "--slug", target_slug, env=environment,
            )
    # Export chooses the canonical REPORT.md and moves audit-side caches under
    # .audit/.  Converge only after that boundary so the field decision, trigger
    # review, and final receipt all bind the same report.  Doing this first
    # bought a second field review and then invalidated conservative trigger
    # votes when the canonical report was annotated later.
    converge_reach_fields(reach_directories, usage_index, deadline, workers)
    trigger_candidates: list[Path] = []
    for directory in directories:
        report = _report(directory)
        sanitizer = _sanitizer_file(directory)
        sanitizer_text = _read(sanitizer) if sanitizer else ""
        if (
            report is None
            or _SKELETON_MARKER.search(_read(report))
            or not has_valid_diagnostic(sanitizer_text, findings_only)
            or _runtime_only_diagnostic(sanitizer_text, findings_only)
            or autodiscard_reason(sanitizer_text)
            or not _has_memory_safety_signal(sanitizer_text)
            or _bundle_missing_artifacts(directory)
        ):
            continue
        if directory in bypasses or _direct_probe_trigger_bypass(
            directory, Path(target_root), controls,
        ):
            bypasses.add(directory)
            continue
        trigger_candidates.append(directory)
    if os.environ.get("CRASH_TRIGGER_GATE", "1") == "0":
        # The serial gate and the cached shortcut both honour the opt-out; a
        # batch that ran anyway spent reviews and parked any crash whose keyed
        # vote came back malformed.
        trigger_candidates = []

    trigger_attempted = _batch_finding_trigger_votes(
        trigger_candidates, results, deadline, usage_index,
        target_root_is_product, workers,
    )
    second_round = [
        directory for directory in trigger_candidates
        if (
            (report := _report(directory)) is not None
            and _cached_trigger_vote(
                report, directory / _TRIGGER_PRIMARY_NAME,
            ) == "Reject"
        )
    ]
    if second_round:
        trigger_attempted.update(_batch_finding_trigger_votes(
            second_round, results, deadline, usage_index,
            target_root_is_product, workers,
            vote_name=_TRIGGER_SECOND_NAME,
        ))
    resolution_round = [
        directory for directory in trigger_candidates
        if (
            (report := _report(directory)) is not None
            and _trigger_resolution_sources(report, directory)
        )
    ]
    if resolution_round:
        trigger_attempted.update(_batch_finding_trigger_votes(
            resolution_round, results, deadline, usage_index,
            target_root_is_product, workers,
            vote_name=_TRIGGER_RESOLUTION_NAME,
        ))
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        statuses = pool.map(
            lambda directory: triage_one_crash(
                directory, results, Path(target_root), target_slug, controls,
                findings_only, deadline,
                target_root_is_product,
                _NO_REACH_DECISION,
                confirmed_trigger_bypass=directory in bypasses,
                age_pending=age_pending,
                trigger_batch_attempted=directory in trigger_attempted,
            ),
            directories,
        )
    for status in statuses:
        counts[status] = counts.get(status, 0) + 1
    return counts


def _finding_cache(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


_FIND_QUALITY_VERSION = report_identity.FIND_QUALITY_DECISION_VERSION


def _quality_content_sha1(report_text: str) -> str:
    return report_identity.semantic_text_sha1(report_text)


def _quality_cache_matches(
    cache_path: Path, cache: dict, report: Path, report_text: str,
) -> bool:
    """Accept only a verdict/progress cache for the report it reviewed.

    v13 caches written before semantic hashes were added may carry a raw hash
    or no hash. Raw hashes must match exactly; hashless caches are tolerated
    only while they are at least as new as the report. That preserves completed
    audits without letting a later report edit replay a stale verdict.
    """
    if cache.get("decision_version") != _FIND_QUALITY_VERSION:
        return False
    cached_report_sha1 = cache.get("report_sha1")
    if isinstance(cached_report_sha1, str) and cached_report_sha1:
        # The full semantic identity is authoritative for new caches. The
        # bounded hash remains useful provenance but can shift when generated
        # annotations move a large report's head/tail cut points.
        return cached_report_sha1 in report_identity.content_sha1_candidates(report)
    cached_sha1 = cache.get("content_sha1")
    if isinstance(cached_sha1, str) and cached_sha1:
        # Pre-incremental v13 caches hashed the raw bounded report. Accept that
        # exact legacy key once; every new write advances it to the semantic key.
        return cached_sha1 in {
            _quality_content_sha1(report_text),
            hashlib.sha1(report_text.encode()).hexdigest(),
        }
    try:
        return cache_path.stat().st_mtime_ns >= report.stat().st_mtime_ns
    except OSError:
        return False


def _valid_quality_votes(value: object, limit: int) -> list[dict]:
    if not isinstance(value, list):
        return []
    votes: list[dict] = []
    for item in value[:limit]:
        if not isinstance(item, dict) or not isinstance(item.get("accept"), bool):
            continue
        votes.append({
            "accept": item["accept"],
            "reason": str(item.get("reason") or ""),
            "class": str(item.get("class") or ""),
            "severity": str(item.get("severity") or ""),
        })
    return votes


def _quality_payload(
    report_text: str, votes: list[dict], quorum: int, accept_quorum: int,
    report_sha1: str | None = None,
) -> dict:
    """Build one non-terminal or terminal cache from independent valid votes."""
    vote_limit = max(1, accept_quorum + quorum - 1)
    normalized = _valid_quality_votes(votes, vote_limit)
    accepts = [vote for vote in normalized if vote["accept"] is True]
    rejects = [vote for vote in normalized if vote["accept"] is False]
    payload: dict = {
        "decision_version": _FIND_QUALITY_VERSION,
        "content_sha1": _quality_content_sha1(report_text),
        "votes": normalized,
        "accept_count": len(accepts),
        "reject_count": len(rejects),
    }
    if report_sha1:
        payload["report_sha1"] = report_sha1
    if len(accepts) >= accept_quorum:
        accepted = accepts[-1]
        payload.update({
            "accept": True,
            "reason": accepted["reason"],
            "class": accepted["class"],
            "severity": accepted["severity"],
        })
    elif len(rejects) >= quorum:
        payload.update({
            "accept": False,
            "reason": rejects[-1]["reason"] or "quality gate rejected finding",
            "class": "",
            "severity": "",
        })
    return payload


def _quality_terminal(payload: dict, quorum: int, accept_quorum: int) -> bool:
    try:
        return (
            payload.get("accept") is True
            and int(payload.get("accept_count", 0)) >= accept_quorum
        ) or (
            payload.get("accept") is False
            and int(payload.get("reject_count", 0)) >= quorum
        )
    except (TypeError, ValueError):
        return False


def _quality_vote(
    report_text: str, timeout: int,
    usage_index: str | os.PathLike[str] | None = None,
) -> dict | None:
    prompt = render_template("triage_find_quality.md.j2", {"body": report_text})
    return llm_decide.llm_decide(
        "find_quality", "accept,reason,class,severity", prompt, timeout,
        usage_index=usage_index,
    )


_DECISION_BATCH_SIZE = 16


def _batch_decisions(
    decision: str, template: str, instructions: str,
    items: list[dict], timeout: int,
    usage_index: str | os.PathLike[str] | None,
    deadline: float | None = None,
    workers: int = 1,
    batch_size: int = _DECISION_BATCH_SIZE,
) -> dict[str, dict]:
    """Return only well-keyed batch results; callers retry omitted ids safely."""
    batches = [
        items[start:start + batch_size]
        for start in range(0, len(items), batch_size)
    ]

    def decide(batch: list[dict]) -> dict[str, dict]:
        call_timeout = _decision_timeout(timeout, deadline)
        if call_timeout <= 0:
            return {}
        allowed = {str(item["id"]) for item in batch}
        prompt = render_template(template, {
            "instructions": instructions,
            "items_json": json.dumps(batch, ensure_ascii=False),
        })
        result = llm_decide.llm_decide(
            decision, "items", prompt, call_timeout, usage_index=usage_index,
        )
        if not isinstance(result, dict) or not isinstance(result.get("items"), list):
            return {}
        found: dict[str, dict] = {}
        for item in result["items"]:
            if not isinstance(item, dict):
                continue
            item_id = str(item.get("id") or "")
            if item_id in allowed and item_id not in found:
                found[item_id] = item
        return found

    decisions: dict[str, dict] = {}
    if not batches:
        return decisions
    with ThreadPoolExecutor(max_workers=min(max(1, workers), len(batches))) as pool:
        # map preserves chunk order, so duplicate ids still resolve
        # deterministically even though independent provider calls overlap.
        for found in pool.map(decide, batches):
            for item_id, item in found.items():
                decisions.setdefault(item_id, item)
    return decisions


def _batch_quality_votes(
    directories: list[Path], results_dir: Path, quorum: int, accept_quorum: int,
    timeout: int, deadline: float | None, workers: int,
) -> dict[Path, list[dict]]:
    usage_index = benchmark._find_index_jsonl(results_dir)
    reports: dict[Path, str] = {}
    report_hashes: dict[Path, str | None] = {}
    votes: dict[Path, list[dict]] = {}
    for directory in directories:
        if (directory / ".keep").is_file() or (directory / ".reviewed").is_file():
            continue
        report = _report(directory)
        if report is None:
            continue
        report_text = read_report_bounded(report)
        reports[directory] = report_text
        report_hashes[directory] = report_identity.content_sha1(report)
        cache_path = directory / ".llm-find-quality.json"
        cache = _finding_cache(cache_path)
        current = _quality_cache_matches(
            cache_path, cache, report, report_text,
        )
        if current and _quality_terminal(cache, quorum, accept_quorum):
            reports.pop(directory, None)
            continue
        existing = _valid_quality_votes(
            cache.get("votes") if current else None,
            max(1, accept_quorum + quorum - 1),
        )
        payload = _quality_payload(
            report_text, existing, quorum, accept_quorum,
            report_hashes[directory],
        )
        votes[directory] = list(payload["votes"])
        # Invalidate a stale terminal verdict before any provider call. If the
        # backend is unavailable, metrics must show pending rather than replay
        # a verdict produced for different report content.
        if not current or _quality_terminal(payload, quorum, accept_quorum):
            _write_atomic_json(cache_path, payload)
        if _quality_terminal(payload, quorum, accept_quorum):
            reports.pop(directory, None)
    active = set(reports)
    instructions = render_template("triage_find_quality.md.j2", {"body": ""}).split(
        "Output a single JSON object", 1,
    )[0]
    for _ in range(max(1, accept_quorum + quorum - 1)):
        vote_timeout = _decision_timeout(timeout, deadline)
        if vote_timeout <= 0 or not active:
            break
        ordered = sorted(active)
        items = [{"id": directory.name, "report": reports[directory]} for directory in ordered]
        by_id = _batch_decisions(
            "find_quality_batch", "triage_find_quality_batch.md.j2",
            instructions, items, vote_timeout, usage_index, deadline, workers,
        )
        for directory in ordered:
            vote = by_id.get(directory.name)
            if not isinstance(vote, dict) or not isinstance(vote.get("accept"), bool):
                continue
            votes[directory].append(vote)
            payload = _quality_payload(
                reports[directory], votes[directory], quorum, accept_quorum,
                report_hashes[directory],
            )
            _write_atomic_json(directory / ".llm-find-quality.json", payload)
            votes[directory] = list(payload["votes"])
            if _quality_terminal(payload, quorum, accept_quorum):
                active.discard(directory)
    return votes


def _prepare_accepted_finding(
    finding_dir: Path, report: Path, deadline: float | None,
    usage_index: str | os.PathLike[str] | None = None,
    reach_fields_override: object = _NO_REACH_DECISION,
) -> Path:
    """Stabilize report content before a content-addressed trigger vote."""
    if not _deadline_expired(deadline):
        fill_reach_fields(
            finding_dir, usage_index, decision_override=reach_fields_override,
        )
        report = _report(finding_dir) or report
    # Quality already reached quorum on the authored report. Advance that
    # verdict across the harness-owned reach annotations now, even if
    # trigger review is temporarily unavailable, so a later trigger retry does
    # not repeat the quality calls first.
    cache_path = finding_dir / ".llm-find-quality.json"
    cache = _finding_cache(cache_path)
    if (
        cache.get("decision_version") == _FIND_QUALITY_VERSION
        and cache.get("accept") is True
    ):
        cache["content_sha1"] = _quality_content_sha1(read_report_bounded(report))
        cache["report_sha1"] = report_identity.content_sha1(report)
        _write_atomic_json(cache_path, cache)
    return report


def _trigger_bypass_confirmed(directory: Path) -> bool:
    """Whether a machine probe already proved this artifact's byte path."""
    try:
        bypass = json.loads(
            (directory / ".trigger-gate-bypass.json").read_text(
                encoding="utf-8",
            )
        )
    except (OSError, ValueError):
        return False
    return isinstance(bypass, dict) and bypass.get("bypass") is True


def _finding_trigger_disposition(
    finding_dir: Path, report: Path, deadline: float | None = None,
    usage_index: str | os.PathLike[str] | None = None,
    target_root_is_product: bool = False,
) -> str:
    """Return accepted, rejected, or pending from current trigger evidence."""
    if _trigger_bypass_confirmed(finding_dir):
        return "accepted"
    backend = os.environ.get("ACTIVE_BACKEND") or os.environ.get("BACKEND") or ""
    target_root = Path(os.environ.get("TARGET_ROOT", ""))
    if backend and target_root.is_dir():
        _trigger_vote(
            report, finding_dir / ".trigger-gate.json", backend,
            os.environ.get("MODEL", ""), target_root, deadline, usage_index,
            target_root_is_product,
        )
    vote = _cached_trigger_vote(report, finding_dir / ".trigger-gate.json")
    if vote == "Reject":
        second = finding_dir / ".trigger-gate-2.json"
        if backend and target_root.is_dir():
            _trigger_vote(
                report, second, backend,
                os.environ.get("MODEL", ""), target_root, deadline, usage_index,
                target_root_is_product,
            )
        second_vote = _cached_trigger_vote(report, second)
        if second_vote != "Reject":
            if second_vote not in {"Promote", "Uncertain"}:
                return "pending"
            resolution = finding_dir / _TRIGGER_RESOLUTION_NAME
            if backend and target_root.is_dir():
                _trigger_vote(
                    report, resolution, backend,
                    os.environ.get("MODEL", ""), target_root, deadline,
                    usage_index, target_root_is_product, resolve=True,
                )
            resolution_vote = _cached_trigger_vote(report, resolution)
            if resolution_vote != "Reject":
                return (
                    "accepted"
                    if resolution_vote in {"Promote", "Uncertain"}
                    else "pending"
                )
            rejection_files = (
                finding_dir / _TRIGGER_PRIMARY_NAME,
                resolution,
            )
        else:
            rejection_files = (
                finding_dir / _TRIGGER_PRIMARY_NAME,
                second,
            )
        facts = _source_review_facts(
            report, rejection_files, rejection_quorum=2,
        )
        if facts.get("rejection_kind") == "no-added-boundary":
            return "not-reportable"
        if _trigger_rejection_is_dispositive(
            report, rejection_files,
            allow_consequence=True,
        ):
            # Only when both reviewers named it; a split disproof keeps the
            # generic reachability reason rather than claiming a consequence
            # finding neither of them fully asserted.
            if facts.get("rejection_kind") == _CONSEQUENCE_REJECTION_KIND:
                return "rejected-consequence"
            return "rejected"
        return "accepted"
    if vote == "Promote" and not _promote_left_scope_open(
        report, finding_dir / ".trigger-gate.json",
    ):
        return "accepted"
    if vote in {"Uncertain", "Promote"}:
        resolution = finding_dir / _TRIGGER_RESOLUTION_NAME
        if backend and target_root.is_dir():
            _trigger_vote(
                report, resolution, backend,
                os.environ.get("MODEL", ""), target_root, deadline,
                usage_index, target_root_is_product, resolve=True,
            )
        return (
            "accepted"
            if _cached_trigger_vote(report, resolution)
            in {"Promote", "Reject", "Uncertain"}
            else "pending"
        )
    return "pending"


def _cached_trigger_resolution(directory: Path, report: Path) -> bool:
    """Whether trigger adjudication can finish without a provider call."""
    if _trigger_bypass_confirmed(directory):
        return True
    first = _cached_trigger_vote(report, directory / ".trigger-gate.json")
    resolution = _cached_trigger_vote(
        report, directory / _TRIGGER_RESOLUTION_NAME,
    )
    if first == "Promote":
        return (
            not _promote_left_scope_open(report, directory / ".trigger-gate.json")
            or resolution in {"Promote", "Reject", "Uncertain"}
        )
    if first == "Uncertain":
        return resolution in {"Promote", "Reject", "Uncertain"}
    if first == "Reject":
        second = _cached_trigger_vote(
            report, directory / ".trigger-gate-2.json",
        )
        if second == "Reject":
            return True
        if second in {"Promote", "Uncertain"}:
            return resolution in {"Promote", "Reject", "Uncertain"}
    return False


def _finding_ready_for_cached_finalization(
    finding_dir: Path, quorum: int, accept_quorum: int,
) -> bool:
    """Whether the quality gate can finish this finding without model work."""
    if (
        (finding_dir / ".keep").is_file()
        or (finding_dir / ".reviewed").is_file()
    ):
        return True
    report = _report(finding_dir)
    if report is None:
        return False
    report_text = read_report_bounded(report)
    cache_path = finding_dir / ".llm-find-quality.json"
    cache = _finding_cache(cache_path)
    if (
        not _quality_cache_matches(
            cache_path, cache, report, report_text,
        )
        or not _quality_terminal(cache, quorum, accept_quorum)
    ):
        return False
    if cache.get("accept") is False:
        return True
    reach_verdict, _reach_detail = evaluate_crash_verdict(
        _read(report), triage_validate.trigger_attacker_controls(),
    )
    return (
        cache.get("accept") is True
        and reach_verdict != "incomplete"
        and _cached_trigger_resolution(finding_dir, report)
    )


def _score_validated_report(
    directory: Path, report: Path, *, env: dict | None = None,
) -> int:
    """Score a validated report and carry its verdicts across that rewrite.

    Severity may synthesize a Fields table from the report's existing bare
    labels. That is a representation-only transform, but it changes the full
    report identity. Snapshot only verdicts that are current immediately
    before scoring, then bind those same verdicts and the validation receipt to
    the scored form. Any later authored edit still invalidates them normally.
    """
    quality_path = directory / ".llm-find-quality.json"
    quality = _finding_cache(quality_path)
    quality_current = (
        quality.get("accept") is True
        and _quality_cache_matches(
            quality_path, quality, report, read_report_bounded(report),
        )
    )
    trigger_payloads: dict[Path, dict] = {}
    for name in _TRIGGER_EVIDENCE_NAMES:
        path = directory / name
        if _cached_trigger_vote(report, path) is None:
            continue
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(payload, dict):
            trigger_payloads[path] = payload

    # Call shape matches the historical scorer invocation exactly: an explicit
    # env=None is equivalent for subprocess, but callers assert on this call.
    rc = (
        _run_tool("severity", "--report", str(directory), env=env)
        if env is not None
        else _run_tool("severity", "--report", str(directory))
    )
    if rc != 0:
        return rc
    report = _report(directory) or report
    current_sha1 = report_identity.content_sha1(report)
    if current_sha1 is None:
        return rc
    scored_receipt = validation_receipt.read_current(directory)
    try:
        caches_rebound = False
        if quality_current:
            bounded_sha1 = _quality_content_sha1(read_report_bounded(report))
            if (
                quality.get("content_sha1") != bounded_sha1
                or quality.get("report_sha1") != current_sha1
            ):
                quality["content_sha1"] = bounded_sha1
                quality["report_sha1"] = current_sha1
                _write_atomic_json(quality_path, quality)
                caches_rebound = True
        resolution_payload = trigger_payloads.pop(
            directory / _TRIGGER_RESOLUTION_NAME, None,
        )
        for path, payload in trigger_payloads.items():
            if payload.get("content_sha1") != current_sha1:
                payload["content_sha1"] = current_sha1
                _write_atomic_json(path, payload)
                caches_rebound = True
        if resolution_payload is not None:
            resolution_path = directory / _TRIGGER_RESOLUTION_NAME
            prior_paths = _trigger_resolution_sources(report, directory)
            resolution_payload["content_sha1"] = current_sha1
            resolution_payload["prior_review_sha256s"] = (
                triage_validate.prior_review_sha256s(prior_paths)
            )
            _write_atomic_json(resolution_path, resolution_payload)
            caches_rebound = True
        if caches_rebound and scored_receipt is not None:
            validation_receipt.rewrite_after_equivalent_transform(
                directory, scored_receipt,
            )
    except OSError as exc:
        print(
            f"WARN: could not bind {directory.name} validation to scored report: {exc}",
            file=sys.stderr,
        )
    return rc


def _score_final_report(
    directory: Path, report: Path, kind: str, state: str,
    *, attacker_controls: list[str] | None = None,
    env: dict | None = None,
) -> str:
    """Score a final artifact, or hold it pending when unscoring failed.

    A `not-reportable` decision voids any numeric severity an earlier receipt
    published, and only the scorer removes it. Leaving the final receipt in
    place after a failed removal would freeze a report that carries both a
    numeric CVSS line and the decision that voided it, and the next pass skips
    current final receipts, so nothing would ever retry. Hold the artifact
    retryable instead and say so.
    """
    if _score_validated_report(directory, report, env=env) == 0:
        return state
    if state != "not-reportable":
        return state
    detail = "obsolete numeric severity could not be cleared"
    validation_receipt.write(
        directory, kind=kind, state="pending", detail=detail,
        attacker_controls=attacker_controls,
    )
    print(f"WARN: {directory.name}: {detail}; held pending", file=sys.stderr)
    return "pending"


def _record_accepted_finding_card(finding_dir: Path, results_dir: Path) -> None:
    """Feed an accepted finding back to queue ranking without gating triage."""
    try:
        workqueue.record_accepted_artifact_card(
            results_dir, finding_dir.name, "find",
        )
    except OSError as exc:
        print(
            f"WARN: could not record productive card for {finding_dir.name}: {exc}",
            file=sys.stderr,
        )


def _finalize_accepted_finding(
    finding_dir: Path, results_dir: Path, report: Path,
    deadline: float | None,
    usage_index: str | os.PathLike[str] | None = None,
    target_root_is_product: bool = False,
    reach_fields_override: object = _NO_REACH_DECISION,
    *,
    prepared: bool = False,
) -> str:
    if not prepared:
        report = _prepare_accepted_finding(
            finding_dir, report, deadline, usage_index,
            reach_fields_override,
        )
    disposition = _finding_trigger_disposition(
        finding_dir, report, deadline, usage_index,
        target_root_is_product,
    )
    if disposition == "rejected":
        _reject(
            finding_dir, results_dir / "findings-rejected",
            "trigger-provenance: triggering state not attacker-reachable",
            category=workqueue.UNREACHABLE_REJECTION_CATEGORY,
        )
        return "rejected"
    if disposition == "rejected-consequence":
        _reject(
            finding_dir, results_dir / "findings-rejected",
            "trigger-provenance: exact claimed security consequence is source-disproved",
        )
        return "rejected"
    if disposition == "pending":
        validation_receipt.write(
            finding_dir, kind="finding", state="pending",
            detail="source review is uncertain, stale, or incomplete",
        )
        return "pending"
    controls = triage_validate.trigger_attacker_controls()
    if disposition == "not-reportable":
        resolution = finding_dir / _TRIGGER_RESOLUTION_NAME
        vote_files = (
            (finding_dir / _TRIGGER_PRIMARY_NAME, resolution)
            if _cached_trigger_vote(report, resolution) == "Reject"
            else tuple(finding_dir / name for name in _TRIGGER_REVIEW_NAMES)
        )
        review_facts = _source_review_facts(
            report, vote_files,
            rejection_quorum=2,
        )
        validation_receipt.write(
            finding_dir, kind="finding", state="not-reportable",
            detail="real defect that crosses no security boundary",
            attacker_controls=controls,
            review_facts=review_facts,
        )
        state = _score_final_report(
            finding_dir, report, "finding", "not-reportable",
            attacker_controls=controls,
        )
        if state == "pending":
            return "pending"
        return "accepted"
    reach_verdict, reach_detail = evaluate_crash_verdict(_read(report), controls)
    if reach_verdict == "incomplete":
        validation_receipt.write(
            finding_dir, kind="finding", state="pending",
            detail="required boundary or trigger fields are incomplete",
            attacker_controls=controls,
        )
        return "pending"
    trigger_votes, review_facts = _trigger_publication_evidence(
        report, finding_dir,
    )
    direct_trigger_proof = _trigger_bypass_confirmed(finding_dir)
    state = _final_publication_state(
        reach_verdict, trigger_votes, review_facts,
        direct_trigger_proof=direct_trigger_proof,
    )
    validation_receipt.write(
        finding_dir, kind="finding", state=state,
        detail=_publication_detail(
            state, reach_verdict, reach_detail, review_facts, controls,
            direct_trigger_proof=direct_trigger_proof,
        ),
        attacker_controls=controls,
        review_facts=review_facts,
    )
    if state == "pending":
        return "pending"
    # Numeric severity is published only after source-backed validation. A
    # missing consequence or boundary stays unrated rather than being read as
    # a weak security rating.
    #
    # Score only after source-backed validation. Severity may canonicalize the
    # report while doing so; _score_validated_report carries the current gate
    # caches across that exact harness-owned rewrite. Scoring first would score
    # a report no receipt vouches for.
    state = _score_final_report(
        finding_dir, report, "finding", state, attacker_controls=controls,
    )
    if state == "pending":
        return "pending"
    # A retained defect that crosses no security boundary is not yield: the
    # not-reportable branch above records no card, and neither does this one.
    if state in validation_receipt.SECURITY_STATES:
        _record_accepted_finding_card(finding_dir, results_dir)
    return "accepted"


def validate_one_finding(
    finding_dir: Path,
    results_dir: Path,
    *,
    quorum: int = 2,
    accept_quorum: int = 2,
    timeout: int = 300,
    deadline: float | None = None,
    target_root_is_product: bool = False,
    initial_votes: list[dict] | None = None,
    defer_trigger: bool = False,
    reject_missing_report: bool = False,
) -> str:
    pinned = (
        (finding_dir / ".keep").is_file()
        or (finding_dir / ".reviewed").is_file()
    )
    report = _report(finding_dir)
    if report is None:
        if reject_missing_report:
            (finding_dir / ".needs-content").unlink(missing_ok=True)
            _reject(
                finding_dir,
                results_dir / "findings-rejected",
                "incomplete missing: missing report.md",
            )
            return "rejected"
        (finding_dir / ".needs-content").touch()
        current_receipt = validation_receipt.read_current(finding_dir)
        validation_receipt.write(
            finding_dir, kind="finding", state="pending",
            detail="missing report",
        )
        if current_receipt is None:
            print(
                f"WARN: {finding_dir}: missing report; held pending",
                file=sys.stderr,
            )
        return "pending"
    if _deadline_expired(deadline) and not pinned:
        current_receipt = validation_receipt.read_current(finding_dir)
        if (
            current_receipt is not None
            and current_receipt.get("state") in validation_receipt.FINAL_STATES
        ):
            return "accepted"
        validation_receipt.write(
            finding_dir, kind="finding", state="pending",
            detail="finding validation deadline expired",
        )
        return "pending"
    usage_index = benchmark._find_index_jsonl(results_dir)
    (finding_dir / ".needs-content").unlink(missing_ok=True)
    if pinned:
        controls = triage_validate.trigger_attacker_controls()
        reach_verdict, reach_detail = evaluate_crash_verdict(
            _read(report), controls,
        )
        if reach_verdict == "incomplete":
            validation_receipt.write(
                finding_dir, kind="finding", state="pending",
                detail="human override requires complete boundary fields",
                attacker_controls=controls,
            )
            return "pending"
        state = _final_publication_state(reach_verdict)
        validation_receipt.write(
            finding_dir, kind="finding", state=state,
            detail=f"human override; {reach_detail}",
            attacker_controls=controls,
        )
        state = _score_final_report(
            finding_dir, report, "finding", state, attacker_controls=controls,
        )
        return "pending" if state == "pending" else "accepted"
    report_text = read_report_bounded(report)
    report_sha1 = report_identity.content_sha1(report)
    cache_path = finding_dir / ".llm-find-quality.json"
    cache = _finding_cache(cache_path)
    current = _quality_cache_matches(cache_path, cache, report, report_text)
    if current and _quality_terminal(cache, quorum, accept_quorum):
        if cache.get("accept") is True:
            (finding_dir / ".pending-drop").unlink(missing_ok=True)
            if defer_trigger:
                return "quality-accepted"
            return _finalize_accepted_finding(
                finding_dir, results_dir, report, deadline, usage_index,
                target_root_is_product,
            )
        if cache.get("accept") is False:
            _reject(finding_dir, results_dir / "findings-rejected", str(cache.get("reason") or "quality gate reject"))
            return "rejected"
    vote_limit = max(1, accept_quorum + quorum - 1)
    persisted_votes = _valid_quality_votes(
        cache.get("votes") if current else None, vote_limit,
    )
    queued_votes = (
        _valid_quality_votes(initial_votes, vote_limit)
        if initial_votes is not None else persisted_votes
    )
    # A report edit invalidates both terminal verdicts and partial progress.
    # Persist that pending state before a potentially unavailable provider call
    # so downstream metrics cannot count the stale acceptance.
    payload = _quality_payload(
        report_text, queued_votes, quorum, accept_quorum, report_sha1,
    )
    _write_atomic_json(cache_path, payload)

    while (
        not _quality_terminal(payload, quorum, accept_quorum)
        and len(queued_votes) < vote_limit
    ):
        vote_timeout = _decision_timeout(timeout, deadline)
        if vote_timeout <= 0:
            break
        if initial_votes is not None:
            # A batch was attempted for this pass. Missing keyed results stay
            # pending for the next bounded pass; immediately fanning every
            # omission back out into individual calls recreates the provider
            # storm batching is meant to prevent.
            break
        vote = _quality_vote(report_text, vote_timeout, usage_index)
        if not isinstance(vote, dict) or not isinstance(vote.get("accept"), bool):
            break
        queued_votes.append(vote)
        payload = _quality_payload(
            report_text, queued_votes, quorum, accept_quorum, report_sha1,
        )
        queued_votes = list(payload["votes"])
        _write_atomic_json(cache_path, payload)

    if payload.get("accept") is True and _quality_terminal(payload, quorum, accept_quorum):
        (finding_dir / ".pending-drop").unlink(missing_ok=True)
        if defer_trigger:
            return "quality-accepted"
        return _finalize_accepted_finding(
            finding_dir, results_dir, report, deadline, usage_index,
            target_root_is_product,
        )
    if payload.get("accept") is False and _quality_terminal(payload, quorum, accept_quorum):
        (finding_dir / ".pending-drop").unlink(missing_ok=True)
        _reject(finding_dir, results_dir / "findings-rejected", payload["reason"])
        return "rejected"
    rejects = int(payload.get("reject_count", 0))
    if rejects:
        rejected_reason = next(
            (
                vote["reason"] for vote in reversed(queued_votes)
                if not vote["accept"] and vote["reason"]
            ),
            "finding quality review did not reach quorum",
        )
        (finding_dir / ".pending-drop").write_text(
            f"Reject count: {rejects}/{quorum}\n"
            f"Reason: {rejected_reason}\n",
            encoding="utf-8",
        )
    validation_receipt.write(
        finding_dir, kind="finding", state="pending",
        detail="finding quality review is incomplete",
    )
    return "pending"


def _write_atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def record_finding_discovery(results_dir: str | os.PathLike[str]) -> int:
    """Stamp each finding's first-seen time into ``state/events.jsonl``.

    The in-run accepted counter answers "what do we hold right now", not "when
    was this found": it drops when a finding is demoted and finalization
    re-adjudicates it in either direction, so it cannot carry a discovery
    curve. Each finding instead gets one immutable first-seen row, keyed by the
    cluster signature so the stamp still joins to the pooled result after
    pooling rewrites the directory names.

    Scans the rejected root too — a finding that the gate later cuts was still
    discovered, and rejection moves the directory out of ``findings/``.

    Returns the number of newly recorded findings.
    """
    results = Path(results_dir)
    events = results / "state" / "events.jsonl"
    seen = {
        row.get("id") for row in workqueue.read_jsonl(events)
        if row.get("type") == "finding_created"
    }
    rows = []
    for root in (results / "findings", results / "findings-rejected"):
        if not root.is_dir():
            continue
        for directory in sorted(root.glob("FIND-*")):
            if not directory.is_dir() or directory.name in seen:
                continue
            report = _report(directory)
            signature: list[str] = []
            if report is not None:
                signature = [
                    str(part) for part in finding_signature.finding_signature(
                        report.read_text(encoding="utf-8", errors="replace"),
                    )["key"]
                ]
            rows.append({
                "type": "finding_created",
                "id": directory.name,
                "signature": signature,
                # first_seen is when housekeeping first observed it; mtime is the
                # directory's own clock, which is closer to when the agent filed it.
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "mtime": datetime.fromtimestamp(
                    directory.stat().st_mtime, timezone.utc,
                ).isoformat(),
            })
            seen.add(directory.name)
    if not rows:
        return 0
    # One lock for the batch: a fsync per finding turns a 200-finding iteration
    # into 200 locked writes, and re-reading between them is what lets two
    # writers stamp the same finding twice.
    with workqueue.jsonl_lock(events):
        known = {
            row.get("id") for row in workqueue.read_jsonl(events)
            if row.get("type") == "finding_created"
        }
        fresh = [row for row in rows if row["id"] not in known]
        workqueue._append_jsonl_many_unlocked(events, fresh)
    return len(fresh)


def record_artifact_events(results_dir: str | os.PathLike[str]) -> int:
    """Stamp crash discovery and terminal dispositions into ``state/events.jsonl``.

    The finding_created stream answers "when was it found" for findings; this
    adds the same immutable first-seen row for crashes (``crash_created``) and
    one for the moment a receipt first claimed a terminal state
    (``artifact_admitted`` for reportable, ``artifact_rejected`` for rejected),
    so time-to-first-admitted can be read without replaying the gates. Rows are
    keyed by artifact id and schema version; a later re-review does not move a
    current stamp, while a newer schema may append corrected legacy evidence.

    Crash rows carry the same address-stable top-frame signature used to match
    confirmation runs. Empty means the saved diagnostic had no parseable
    target frame; those rows remain valid timeline events but cannot contribute
    to duplicate-root telemetry.
    """
    results = Path(results_dir)
    events = results / "state" / "events.jsonl"
    existing = workqueue.read_jsonl(events)

    def event_key(row: dict) -> tuple:
        base = (row.get("type"), row.get("id"))
        if row.get("type") == "crash_created":
            try:
                version = int(row.get("event_version") or 1)
            except (TypeError, ValueError):
                version = 1
            return (*base, version)
        return base

    seen = {
        event_key(row) for row in existing
        if row.get("type") in ("crash_created", "artifact_admitted", "artifact_rejected")
    }
    now = datetime.now(timezone.utc).isoformat()
    rows: list[dict] = []

    def stamp(event: str, directory: Path, **extra: object) -> None:
        payload = {"type": event, "id": directory.name, **extra}
        key = event_key(payload)
        if key in seen:
            return
        seen.add(key)
        rows.append({**payload, "first_seen": now})

    for root in (results / "crashes", results / "crashes-rejected"):
        if not root.is_dir():
            continue
        for directory in sorted(root.glob("CRASH-*")):
            if directory.is_dir() and ("crash_created", directory.name, 2) not in seen:
                filed = crash_artifacts.filing_time(directory)
                if filed is None:
                    continue
                sanitizer_file = _sanitizer_file(directory)
                signature = stack_frames.crash_signature(
                    _read(sanitizer_file) if sanitizer_file else "",
                )
                stamp(
                    "crash_created", directory, event_version=2, signature=signature,
                    mtime=datetime.fromtimestamp(filed, timezone.utc).isoformat(),
                )
    lanes = (
        ("findings", "FIND-*", "finding"), ("crashes", "CRASH-*", "crash"),
        ("findings-rejected", "FIND-*", "finding"),
        ("crashes-rejected", "CRASH-*", "crash"),
    )
    for lane, pattern, kind in lanes:
        root = results / lane
        if not root.is_dir():
            continue
        for directory in sorted(root.glob(pattern)):
            if not directory.is_dir():
                continue
            if validation_receipt.claims_state(directory, validation_receipt.SECURITY_STATES):
                stamp("artifact_admitted", directory, kind=kind)
            elif validation_receipt.claims_state(directory, frozenset({"rejected"})):
                stamp("artifact_rejected", directory, kind=kind)
    if not rows:
        return 0
    with workqueue.jsonl_lock(events):
        known = {
            event_key(row) for row in workqueue.read_jsonl(events)
        }
        fresh = [row for row in rows if event_key(row) not in known]
        workqueue._append_jsonl_many_unlocked(events, fresh)
    return len(fresh)


# Enough of a report to reach its fields table. Ranking reads its own head
# rather than read_report_bounded, whose oversize warning names a real
# false-negative risk in a gate and must not also fire for a sort key.
_FIND_RANK_HEAD_BYTES = 8192


def _finding_review_rank(directory: Path) -> tuple[str, int, str]:
    """Sort key for one queued finding: bug class, evidence gaps, then name."""
    report = _report(directory)
    text = ""
    if report is not None:
        try:
            with report.open(encoding="utf-8", errors="replace") as stream:
                text = stream.read(_FIND_RANK_HEAD_BYTES)
        except OSError:
            text = ""
    match = re.search(
        r"^(?:Class\s*:\s*|\|\s*Class\s*\|\s*)([^|\n]+)",
        text, re.IGNORECASE | re.MULTILINE,
    )
    klass = " ".join((match.group(1) if match else "").split()).lower()
    missing = len(_missing_reach_fields(text))
    return klass, missing, directory.name


def _finding_review_order(directories: list[Path]) -> list[Path]:
    """Rotate the review queue over bug classes, best-evidenced first.

    Queue order decides what a partial result represents, and a drain stops
    mid-queue whenever a provider limit or an operator ceiling ends it. Plain
    name order made the remainder a whole class rather than a sample: one cell
    adjudicated 80 of 274 reports and every one came from a single class,
    while every other class it filed went unread. Rotating classes makes any
    prefix span the corpus.

    Within a class, reports carrying the fields a reviewer needs go first, so
    the earliest reviews are the ones that can reach a verdict. That ordering
    only ranks -- an incomplete report is still reviewed in its turn, because
    thin writing is not evidence that the bug is unreal.
    """
    groups: dict[str, list[Path]] = {}
    for klass, missing, name, directory in sorted(
        (*_finding_review_rank(directory), directory)
        for directory in directories
    ):
        groups.setdefault(klass, []).append(directory)
    ordered: list[Path] = []
    lanes = [groups[klass] for klass in sorted(groups)]
    for index in range(max((len(lane) for lane in lanes), default=0)):
        ordered.extend(lane[index] for lane in lanes if index < len(lane))
    return ordered


def validate_find_gate(
    results_dir: str | os.PathLike[str],
    *,
    workers: int = 4,
    quorum: int | None = None,
    accept_quorum: int | None = None,
    deadline: float | None = None,
    target_root_is_product: bool = False,
    reject_missing_reports: bool = False,
    finish_started_group: bool = False,
) -> dict[str, int]:
    results = Path(results_dir)
    findings = results / "findings"
    findings.mkdir(parents=True, exist_ok=True)
    q = quorum or _positive_int_env("FIND_GATE_QUORUM", 2)
    aq = accept_quorum or _positive_int_env("FIND_GATE_ACCEPT_QUORUM", 2)
    _restore_stale_trigger_rejections(results, kind="finding")
    _refresh_or_restore_quality_rejections(
        results, quorum=q, accept_quorum=aq,
    )
    # Stamp discovery before the deadline-gated vote work below: when the wall
    # budget is already spent the votes are skipped, but the finding was still
    # found and must keep its place on the timeline. This is telemetry for a
    # report — it must never be able to fail the validation it rides along with,
    # so a broken state file is loud but not fatal.
    try:
        record_finding_discovery(results)
    except Exception as exc:  # noqa: BLE001 - telemetry is never worth a gate
        print(
            f"WARN: finding discovery stamps unavailable ({exc}); "
            "validation continues, timeline may be incomplete",
            file=sys.stderr,
        )
    directories = [path for path in sorted(findings.glob("FIND-*")) if path.is_dir()]
    timeout = _positive_int_env("LLM_DECISION_TIMEOUT", 300)
    counts = {"accepted": 0, "rejected": 0, "pending": 0}
    # Finish conclusive cached work before asking a provider for anything.
    # Regeneration often has a large legacy backlog alongside already-reviewed
    # artifacts. Letting the backlog consume the shared deadline first made
    # those artifacts look unadjudicated even though no model call was needed.
    cached_directories = [
        directory for directory in directories
        if _finding_ready_for_cached_finalization(directory, q, aq)
    ]
    usage_index = benchmark._find_index_jsonl(results)
    if cached_directories:
        # Converge before this shortcut writes their receipts, for the same
        # reason the disposition groups below do: a receipt must cover a
        # report no later pass needs to rewrite. Filtered first so the settled
        # artifacts this fast path exists for still reach finalization without
        # a provider-shaped call in front of them.
        owed = [d for d in cached_directories if reach_fields_open(d)]
        if owed:
            converge_reach_fields(owed, usage_index, deadline, workers)
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            cached_statuses = list(pool.map(
                lambda directory: validate_one_finding(
                    directory, results, quorum=q, accept_quorum=aq,
                    timeout=timeout, deadline=deadline,
                    target_root_is_product=target_root_is_product,
                    reject_missing_report=reject_missing_reports,
                ),
                cached_directories,
            ))
        for status in cached_statuses:
            counts[status] += 1
    cached_set = set(cached_directories)
    directories = _finding_review_order([
        directory for directory in directories if directory not in cached_set
    ])
    # Quality batches are wide enough to keep every worker occupied. Within
    # each quality group, carry trigger-sized disposition groups through reach
    # fields, both trigger rounds, and finalization before opening the next.
    # Running a stage breadth-first across the whole corpus produced 138 single
    # votes and zero dispositions in one drain; making the entire quality group
    # the finalization unit instead would require four serial trigger waves and
    # recreate the same starvation one level down.
    quality_group_size = max(1, workers) * _DECISION_BATCH_SIZE
    disposition_group_size = max(1, workers) * _TRIGGER_BATCH_SIZE
    for start in range(0, len(directories), quality_group_size):
        group = directories[start:start + quality_group_size]
        if _deadline_expired(deadline):
            counts["pending"] += len(group)
            continue
        # Post-cell measurement may finish a group it admitted before its
        # ceiling. In-run callers leave this off: their deadline is productive
        # benchmark time and must remain a hard stop. This distinction avoids
        # both paid-for vote starvation and hidden extra harness budget.
        group_deadline = None if finish_started_group else deadline
        initial_votes = _batch_quality_votes(
            group, results, q, aq, timeout, group_deadline, workers,
        )
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            statuses = list(pool.map(
                lambda directory: validate_one_finding(
                    directory, results, quorum=q, accept_quorum=aq,
                    timeout=timeout, deadline=group_deadline,
                    target_root_is_product=target_root_is_product,
                    initial_votes=initial_votes.get(directory),
                    defer_trigger=True,
                    reject_missing_report=reject_missing_reports,
                ),
                group,
            ))
        accepted_quality = [
            directory for directory, status in zip(group, statuses)
            if status == "quality-accepted"
        ]
        for status in statuses:
            if status != "quality-accepted":
                counts[status] += 1
        for disposition_start in range(
            0, len(accepted_quality), disposition_group_size,
        ):
            disposition_group = accepted_quality[
                disposition_start:disposition_start + disposition_group_size
            ]
            # The first disposition group belongs to the quality work already
            # admitted. Later groups start only while the original ceiling is
            # open; an admitted group uses group_deadline and therefore finishes
            # post-cell, while the in-run caller retains its hard deadline.
            if disposition_start and _deadline_expired(deadline):
                counts["pending"] += len(accepted_quality) - disposition_start
                break
            # Converge before the trigger vote binds a receipt to the report,
            # so the pool's later pass has nothing left to rewrite.
            converge_reach_fields(
                disposition_group, usage_index, group_deadline, workers,
            )
            for directory in disposition_group:
                report = _report(directory)
                if report is None:
                    continue
                _prepare_accepted_finding(
                    directory, report, group_deadline, usage_index,
                )
            trigger_attempted = _batch_finding_trigger_votes(
                disposition_group, results, group_deadline, usage_index,
                target_root_is_product, workers,
            )
            second_trigger_directories = [
                directory for directory in disposition_group
                if _report(directory) is not None
                and _cached_trigger_vote(
                    _report(directory), directory / ".trigger-gate.json",
                ) == "Reject"
            ]
            second_trigger_attempted = (
                _batch_finding_trigger_votes(
                    second_trigger_directories, results, group_deadline,
                    usage_index, target_root_is_product, workers,
                    vote_name=".trigger-gate-2.json",
                )
                if second_trigger_directories else set()
            )
            resolution_directories = [
                directory for directory in disposition_group
                if (
                    (report := _report(directory)) is not None
                    and _trigger_resolution_sources(report, directory)
                )
            ]
            resolution_attempted = (
                _batch_finding_trigger_votes(
                    resolution_directories, results, group_deadline,
                    usage_index, target_root_is_product, workers,
                    vote_name=_TRIGGER_RESOLUTION_NAME,
                )
                if resolution_directories else set()
            )
            for directory in disposition_group:
                report = _report(directory)
                if (
                    report is None
                    or (
                        directory in trigger_attempted
                        and _cached_trigger_vote(
                            report, directory / ".trigger-gate.json",
                        ) is None
                    )
                    or (
                        directory in second_trigger_attempted
                        and _cached_trigger_vote(
                            report, directory / ".trigger-gate-2.json",
                        ) is None
                    )
                    or (
                        directory in resolution_attempted
                        and _cached_trigger_vote(
                            report, directory / _TRIGGER_RESOLUTION_NAME,
                        ) is None
                    )
                ):
                    # A batch was already attempted. Missing, malformed, or
                    # stale keyed output stays pending for a later bounded pass
                    # instead of immediately spawning a serial per-finding
                    # validator.
                    status = "pending"
                else:
                    status = _finalize_accepted_finding(
                        directory, results, report, group_deadline, usage_index,
                        target_root_is_product, prepared=True,
                    )
                counts[status] += 1
    return counts


def _render_reports(results: Path, workers: int) -> bool:
    reports: list[Path] = []
    for parent in ("crashes", "crashes-rejected", "findings", "findings-rejected"):
        for directory in (results / parent).glob("*-*"):
            if directory.is_dir() and (report := _report(directory)) is not None:
                reports.append(report)
    if not reports:
        return True
    enrich_succeeded = True
    if os.environ.get("ENRICH_REPORT_AUTO", "1") == "1":
        report_paths = b"\0".join(os.fsencode(report) for report in reports) + b"\0"
        enrich_succeeded = _run_tool(
            "enrich-report", "--quiet", "--paths-from-stdin",
            stdin_data=report_paths,
        ) == 0

    batches = [
        reports[start:start + cluster_common.RENDER_MD_BATCH_PATHS]
        for start in range(0, len(reports), cluster_common.RENDER_MD_BATCH_PATHS)
    ]

    def render(batch: list[Path]) -> bool:
        return _run_tool(
            "render-md", *(str(report) for report in batch),
            "--html-sibling", "--title-from", "parent",
        ) == 0

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(batches)))) as pool:
        render_succeeded = all(pool.map(render, batches))
    return render_succeeded and enrich_succeeded


def maintain_indexes(
    results_dir: str | os.PathLike[str],
    target_root: str | os.PathLike[str] | None = None,
    *,
    workers: int = 4,
    refresh_clusters: bool = True,
) -> bool:
    results = Path(results_dir)
    prior_validations = validation_receipt.snapshot_current_tree(results)
    for name in ("crashes", "crashes-rejected", "findings", "findings-rejected"):
        (results / name).mkdir(parents=True, exist_ok=True)
    benchmark.write_rejected_crashes_index(results / "crashes-rejected")
    benchmark.write_rejected_findings_index(results / "findings-rejected")
    environment = os.environ.copy()
    if target_root:
        environment["TARGET_ROOT"] = str(target_root)
    succeeded = True
    if refresh_clusters:
        succeeded = _run_tool("cluster-crashes", str(results), env=environment) == 0
        succeeded = (
            _run_tool("cluster-findings", str(results), env=environment) == 0
            and succeeded
        )
    if os.environ.get("INDEX_HTML_AUTO", "1") == "1":
        succeeded = _render_reports(results, workers) and succeeded
        summaries = [
            results / "crashes" / "CRASH-CLUSTERS.md",
            results / "crashes-rejected" / "REJECTED-CRASHES.md",
            results / "findings" / "FINDING-CLUSTERS.md",
            results / "findings-rejected" / "REJECTED-FINDINGS.md",
        ]
        existing = [str(path) for path in summaries if path.is_file() and path.stat().st_size]
        if existing:
            succeeded = _run_tool("render-md", *existing, "--html-sibling") == 0 and succeeded
    if succeeded:
        # Clustering, enrichment, and Markdown normalization change only the
        # maintainer-facing representation. Rebind after the whole successful
        # transaction so condition copies and severity consumers see the final
        # rendered form.
        validation_receipt.rewrite_tree_after_equivalent_transform(
            prior_validations,
        )
    return succeeded
