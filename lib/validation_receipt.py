"""Content-addressed publication receipts for crash and finding artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path, PurePosixPath

import crash_artifacts
import report_identity
import target_config
import triage_validate

SCHEMA_VERSION = 2
# Security yield is one state, not a family: an artifact either carries the
# evidence a security report needs or it does not. `not-reportable` is a real
# defect that crosses no security boundary — final, visible on disk, never
# counted as yield and never scored.
SECURITY_STATES = frozenset({"reportable"})
FINAL_STATES = SECURITY_STATES | {"not-reportable"}
ALL_STATES = FINAL_STATES | {"pending", "rejected"}
_FIXED_EVIDENCE_NAMES = (
    "sanitizer.txt",
    "repro.cmd",
    "reproduce.sh",
    ".probe-context.json",
    ".build-config.json",
    ".build-config-recipe.sh",
    ".primary-build-differential.json",
    ".primary-build-sanitizer.txt",
    ".keep",
    ".reviewed",
    ".llm-find-quality.json",
    ".trigger-gate.json",
    ".trigger-gate-2.json",
    ".trigger-gate-resolution.json",
    ".trigger-gate-bypass.json",
)
_SOURCE_REVIEW_NAMES = (
    ".trigger-gate.json",
    ".trigger-gate-2.json",
    ".trigger-gate-resolution.json",
)
_SOURCE_REVIEW_ARTIFACTS = frozenset(
    _SOURCE_REVIEW_NAMES
    + tuple(f".audit/{name}" for name in _SOURCE_REVIEW_NAMES)
)
_SOURCE_ATTESTATION_VERSION = "source-anchor-v1"
_SOURCE_REVISION_CONTEXT_PREFIX = "revision:"
_SOURCE_ROOT_CONTEXT_PREFIX = "root-path-sha256:"


# Only large files are memoized. Every publication consumer rebuilds the
# evidence record, so a reproducer is digested several times per pass, and a
# multi-gigabyte testcase is a legitimate artifact. Small files are re-read
# every time on purpose: they include the mutable gate caches, and a memo keyed
# on stat data could serve a stale digest for a same-size rewrite whose mtime
# did not advance at the filesystem's granularity. Publication authority is
# worth more than the microseconds.
_DIGEST_MEMO_MIN_BYTES = 4 * 1024 * 1024
_DIGEST_MEMO_MAX_ENTRIES = 4096
_digest_memo: dict[tuple[str, int, int, int, int, int], str] = {}


def _stat_identity(stat: os.stat_result) -> tuple[int, int, int, int, int]:
    """Fields that change when a file's identity or contents change."""
    return (
        stat.st_dev, stat.st_ino, stat.st_size,
        stat.st_mtime_ns, stat.st_ctime_ns,
    )


def _sha256(path: Path) -> str:
    before = path.stat()
    memoize = before.st_size >= _DIGEST_MEMO_MIN_BYTES
    key = (str(path), *_stat_identity(before))
    if memoize:
        cached = _digest_memo.get(key)
        if cached is not None:
            return cached
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    if _stat_identity(before) != _stat_identity(after):
        raise OSError(f"evidence changed while hashing: {path}")
    value = digest.hexdigest()
    if memoize and len(_digest_memo) < _DIGEST_MEMO_MAX_ENTRIES:
        _digest_memo[key] = value
    return value


def _artifact_paths(directory: Path) -> list[Path]:
    roots = (directory, directory / ".audit")
    paths: set[Path] = set()
    for root in roots:
        for name in _FIXED_EVIDENCE_NAMES:
            path = root / name
            if path.is_file():
                paths.add(path)
    sanitizer = crash_artifacts.find_primary_sanitizer(roots)
    # Publication binds the self-contained bundle, never a mutable scratch
    # path recorded in an old sanitizer header.  find_testcase deliberately
    # follows that header before scanning the bundle so export can recover the
    # exact original input; after export, however, the local copy is the
    # evidence.  Following the external path here also makes relative_to()
    # below fail and silently prevents any receipt from being written.
    testcase = crash_artifacts.find_testcase(roots)
    harness = crash_artifacts.find_harness_source(roots)
    for path in (sanitizer, testcase, harness):
        if path is not None and path.is_file():
            paths.add(path)
    return sorted(paths)


def _probe_facts(directory: Path) -> dict:
    for path in (
        directory / ".probe-context.json",
        directory / ".audit" / ".probe-context.json",
    ):
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(value, dict) and value.get("version") == 4:
            return {
                key: value.get(key)
                for key in (
                    "evidence_id", "target_revision", "target_config_sha256",
                    "mode", "sanitizer", "args", "binary", "build_config_id",
                    "build_recipe_sha256", "prerequisites",
                )
            }
    return {}


def _source_attestations(
    directory: Path, artifacts: dict[str, dict],
) -> list[dict]:
    """Join host-verified source anchors to the review bytes that supplied them.

    The review remains an untrusted model artifact.  Verification re-reads its
    citations from the configured target tree and writes only the normalized
    anchors returned by ``verify_source_anchors``.  The review digest already
    present in ``artifacts`` makes that join independently checkable.
    """
    target_root_value = os.environ.get("TARGET_ROOT", "")
    if not target_root_value:
        return []
    target_root = Path(target_root_value)
    attestations: list[dict] = []
    for root in (directory, directory / ".audit"):
        for name in _SOURCE_REVIEW_NAMES:
            path = root / name
            try:
                relative = path.relative_to(directory).as_posix()
                artifact = artifacts.get(relative)
                payload = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if not isinstance(artifact, dict) or not isinstance(payload, dict):
                continue
            anchors = triage_validate.verify_source_anchors(
                payload.get("anchors"), target_root,
            )
            if not anchors:
                continue
            attestations.append({
                "review_artifact": relative,
                "review_sha256": str(artifact.get("sha256") or ""),
                "verifier": _SOURCE_ATTESTATION_VERSION,
                "anchors": anchors,
            })
    return attestations


def _source_root_context() -> str:
    """Opaque identity for one exact host checkout path."""
    target_root = os.environ.get("TARGET_ROOT", "").strip()
    if not target_root:
        return ""
    try:
        resolved = Path(target_root).resolve(strict=True)
    except OSError:
        return ""
    if not resolved.is_dir():
        return ""
    digest = hashlib.sha256(os.fsencode(str(resolved))).hexdigest()
    return f"{_SOURCE_ROOT_CONTEXT_PREFIX}{digest}"


def _new_source_context(target_revision: str) -> str:
    """Bind fresh source claims to a revision or one exact plain checkout."""
    root_context = _source_root_context()
    if not root_context:
        return ""
    expected = str(target_revision or "")
    declared = os.environ.get("TARGET_REV")
    if declared is not None and declared != expected:
        return ""
    if target_config.is_unpinned_rev(expected):
        return root_context
    target_root = os.environ.get("TARGET_ROOT", "").strip()
    try:
        detected = target_config.detect_rev(target_root)
    except OSError:
        detected = ""
    if detected == expected:
        return f"{_SOURCE_REVISION_CONTEXT_PREFIX}{expected}"
    # Source archives can carry the immutable session revision without VCS
    # metadata. Keep those claims local to this exact checkout rather than
    # treating every archive with the same declaration as interchangeable.
    if declared == expected and target_config.is_unpinned_rev(detected):
        return root_context
    return ""


def _stored_source_context_valid(value: object, target_revision: str) -> bool:
    """Whether a stored source context has a host-authored shape."""
    if not isinstance(value, str):
        return False
    if value.startswith(_SOURCE_REVISION_CONTEXT_PREFIX):
        revision = value.removeprefix(_SOURCE_REVISION_CONTEXT_PREFIX)
        return (
            bool(revision)
            and not target_config.is_unpinned_rev(revision)
            and revision == str(target_revision or "")
        )
    if not value.startswith(_SOURCE_ROOT_CONTEXT_PREFIX):
        return False
    digest = value.removeprefix(_SOURCE_ROOT_CONTEXT_PREFIX)
    return (
        len(digest) == 64
        and all(char in "0123456789abcdef" for char in digest)
    )


def _source_context_matches(value: object, target_revision: str) -> bool:
    """Whether TARGET_ROOT is the checkout a stored source claim describes."""
    if not _stored_source_context_valid(value, target_revision):
        return False
    context = str(value)
    if context.startswith(_SOURCE_ROOT_CONTEXT_PREFIX):
        return _source_root_context() == context
    target_root = os.environ.get("TARGET_ROOT", "").strip()
    if not target_root:
        return False
    revision = context.removeprefix(_SOURCE_REVISION_CONTEXT_PREFIX)
    try:
        return target_config.detect_rev(target_root) == revision
    except OSError:
        return False


def _stored_source_attestation_valid(value: object) -> bool:
    """Whether one stored entry has the verifier's normalized shape."""
    if not isinstance(value, dict):
        return False
    review_sha256 = value.get("review_sha256")
    anchors = value.get("anchors")
    if (
        value.get("review_artifact") not in _SOURCE_REVIEW_ARTIFACTS
        or value.get("verifier") != _SOURCE_ATTESTATION_VERSION
        or not isinstance(review_sha256, str)
        or len(review_sha256) != 64
        or any(char not in "0123456789abcdef" for char in review_sha256)
        or not isinstance(anchors, list)
        or not anchors
    ):
        return False
    for anchor in anchors:
        if not isinstance(anchor, dict):
            return False
        relative = str(anchor.get("path") or "")
        excerpt = str(anchor.get("excerpt") or "")
        line = anchor.get("line")
        normalized_path = PurePosixPath(relative)
        if (
            not relative
            or normalized_path.is_absolute()
            or normalized_path.as_posix() != relative
            or ".." in normalized_path.parts
            or not excerpt
            or not str(anchor.get("symbol") or "")
            or str(anchor.get("kind") or "")
            not in triage_validate.ANCHOR_KINDS
            or isinstance(line, bool)
            or not isinstance(line, int)
            or line < 1
            or anchor.get("excerpt_sha256")
            != hashlib.sha256(excerpt.encode()).hexdigest()
        ):
            return False
    return True


def _attestations_match_artifacts(
    value: object, artifacts: dict[str, dict],
) -> bool:
    """Whether stored attestations still name their digested review bytes."""
    if not isinstance(value, list):
        return False
    for item in value:
        if not _stored_source_attestation_valid(item):
            return False
        artifact = artifacts.get(item["review_artifact"])
        if (
            not isinstance(artifact, dict)
            or item["review_sha256"] != artifact.get("sha256")
        ):
            return False
    return True


def _review_anchor_candidates(path: Path) -> list[dict] | None:
    """Normalize cited anchors without claiming that source still matches."""
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("anchors"), list):
        return None
    anchors: list[dict] = []
    for item in payload["anchors"]:
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
        normalized_path = PurePosixPath(relative)
        if (
            not relative
            or normalized_path.is_absolute()
            or normalized_path.as_posix() != relative
            or ".." in normalized_path.parts
            or not excerpt
            or not symbol
            or kind not in triage_validate.ANCHOR_KINDS
            or line < 1
        ):
            continue
        anchors.append({
            "path": relative,
            "line": line,
            "symbol": symbol,
            "kind": kind,
            "excerpt": excerpt,
            "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
        })
    return anchors


def _anchors_contain(candidates: list[dict], required: list[dict]) -> bool:
    """Whether every previously verified anchor remains in the review."""
    remaining = list(candidates)
    for anchor in required:
        try:
            remaining.remove(anchor)
        except ValueError:
            return False
    return True


def _rebind_source_attestations(
    directory: Path, value: object, artifacts: dict[str, dict],
) -> list[dict] | None:
    """Bind saved anchors across a trusted representation-only rewrite.

    The old review digest may legitimately change when the harness updates
    report hashes or scrubs local paths. The saved, host-verified anchors may
    move to the same fixed review filename beneath ``.audit``; they may not be
    removed or altered. This path never makes a new source claim.
    """
    if not isinstance(value, list):
        return None
    if not value:
        return []
    rebound: list[dict] = []
    for item in value:
        if not _stored_source_attestation_valid(item):
            return None
        previous = str(item["review_artifact"])
        basename = PurePosixPath(previous).name
        candidates = [
            review for review in sorted(_SOURCE_REVIEW_ARTIFACTS)
            if PurePosixPath(review).name == basename
            and isinstance(artifacts.get(review), dict)
            and (
                normalized := _review_anchor_candidates(directory / review)
            ) is not None
            and _anchors_contain(normalized, item["anchors"])
        ]
        if previous in candidates:
            review = previous
        elif len(candidates) == 1:
            review = candidates[0]
        else:
            return None
        candidate = {
            "review_artifact": review,
            "review_sha256": artifacts[review]["sha256"],
            "verifier": item.get("verifier"),
            "anchors": item.get("anchors"),
        }
        if not _attestations_match_artifacts([candidate], artifacts):
            return None
        if candidate not in rebound:
            rebound.append(candidate)
    return rebound


def _source_anchor_claims(value: object) -> list[str] | None:
    """Comparable verified claims, independent of review path and metadata."""
    if not isinstance(value, list):
        return None
    claims: list[str] = []
    for item in value:
        if not _stored_source_attestation_valid(item):
            return None
        claims.append(json.dumps({
            "verifier": item.get("verifier"),
            "anchors": item.get("anchors"),
        }, sort_keys=True, separators=(",", ":")))
    return sorted(claims)


def _stamp_evidence_id(record: dict) -> dict:
    identity = {
        key: value for key, value in record.items() if key != "evidence_id"
    }
    encoded = json.dumps(
        identity, sort_keys=True, separators=(",", ":"),
    ).encode()
    record["evidence_id"] = hashlib.sha256(encoded).hexdigest()
    return record


def evidence_record(
    directory: Path,
    *,
    target_revision: str = "",
    target_config_sha256: str = "",
    attacker_controls: list[str] | None = None,
    review_facts: dict[str, str] | None = None,
    allow_missing_report: bool = False,
    _preserved_source_attestations: object | None = None,
    _preserved_source_context: object | None = None,
) -> dict | None:
    """Build the stable evidence identity used by every publication consumer."""
    directory = Path(directory)
    report = report_identity.find_report(directory)
    if report is None and not allow_missing_report:
        return None
    artifacts: dict[str, dict] = {}
    try:
        for path in _artifact_paths(directory):
            relative = path.relative_to(directory).as_posix()
            artifacts[relative] = {
                "sha256": _sha256(path),
                "size": path.stat().st_size,
            }
    except (OSError, ValueError):
        return None
    probe = _probe_facts(directory)
    resolved_target_revision = (
        target_revision or str(probe.get("target_revision") or "")
    )
    preserving_source = _preserved_source_attestations is not None
    source_context = (
        _preserved_source_context
        if preserving_source
        else (_new_source_context(resolved_target_revision) or None)
    )
    if (
        source_context is not None
        and not _stored_source_context_valid(
            source_context, resolved_target_revision,
        )
    ):
        return None
    source_checkout_matches = (
        _source_context_matches(source_context, resolved_target_revision)
        if source_context is not None else False
    )
    source_attestations = (
        _source_attestations(directory, artifacts)
        if source_checkout_matches else []
    )
    if _preserved_source_attestations is not None:
        rebound = _rebind_source_attestations(
            directory, _preserved_source_attestations, artifacts,
        )
        if rebound is None:
            return None
        if source_context is not None and not rebound:
            return None
        if source_checkout_matches:
            # A matching checkout can strengthen the trusted-transform check:
            # metadata may change, but the set of live verified claims may not.
            if _source_anchor_claims(
                rebound,
            ) != _source_anchor_claims(source_attestations):
                return None
        else:
            source_attestations = rebound
    elif not source_attestations:
        source_context = None
    record = {
        # Pending/rejected artifacts may be incomplete by definition. An empty
        # identity binds the absence itself: adding a report later changes this
        # field and invalidates the receipt for a fresh pass.
        "report_sha1": (
            report_identity.content_sha1(report) if report is not None else ""
        ),
        "artifacts": artifacts,
        "target_revision": resolved_target_revision,
        "target_config_sha256": (
            target_config_sha256
            or str(probe.get("target_config_sha256") or "")
        ),
        "attacker_controls": triage_validate.trigger_attacker_controls(
            ",".join(str(value) for value in attacker_controls)
            if attacker_controls is not None else None
        ),
        "probe": probe,
        "source_attestations": source_attestations,
        "review_facts": triage_validate.source_review_facts(
            review_facts or {},
        ),
    }
    if source_context is not None:
        record["source_context"] = source_context
    return _stamp_evidence_id(record)


def write(
    directory: Path,
    *,
    kind: str,
    state: str,
    detail: str = "",
    target_revision: str | None = None,
    target_config_sha256: str | None = None,
    attacker_controls: list[str] | None = None,
    review_facts: dict[str, str] | None = None,
    _preserved_source_attestations: object | None = None,
    _preserved_source_context: object | None = None,
) -> dict | None:
    if kind not in {"finding", "crash"} or state not in ALL_STATES:
        raise ValueError("invalid validation receipt kind/state")
    record = evidence_record(
        directory,
        target_revision=(
            os.environ.get("TARGET_REV", "")
            if target_revision is None else target_revision
        ),
        target_config_sha256=(
            os.environ.get("TARGET_CONFIG_SHA256", "")
            if target_config_sha256 is None else target_config_sha256
        ),
        attacker_controls=attacker_controls,
        review_facts=review_facts,
        allow_missing_report=state in {"pending", "rejected"},
        _preserved_source_attestations=_preserved_source_attestations,
        _preserved_source_context=_preserved_source_context,
    )
    if record is None:
        return None
    payload = {
        "schema_version": SCHEMA_VERSION,
        "kind": kind,
        "state": state,
        "detail": detail,
        "evidence": record,
        "validated_at": time.time(),
    }
    destination = Path(directory) / "validation.json"
    temporary = destination.with_name(
        f".{destination.name}.{os.getpid()}.{time.time_ns()}.tmp",
    )
    temporary.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, destination)
    return payload


def rewrite_after_equivalent_transform(
    directory: Path, prior_receipt: dict,
) -> dict | None:
    """Rebind a current receipt after a trusted representation-only rewrite.

    Callers must capture *prior_receipt* with :func:`read_current` before they
    rewrite the validated directory.  This is for harness-owned transforms
    such as path scrubbing, bundle canonicalization, and replay-rate
    annotation; it must not carry validation across a semantic report edit or
    a change to the underlying reproducer.
    """
    if (
        not isinstance(prior_receipt, dict)
        or prior_receipt.get("schema_version") != SCHEMA_VERSION
        or prior_receipt.get("kind") not in {"finding", "crash"}
        or prior_receipt.get("state") not in ALL_STATES
        or not isinstance(prior_receipt.get("evidence"), dict)
    ):
        raise ValueError("invalid prior validation receipt")
    saved = prior_receipt["evidence"]
    return write(
        directory,
        kind=str(prior_receipt["kind"]),
        state=str(prior_receipt["state"]),
        detail=str(prior_receipt.get("detail") or ""),
        target_revision=str(saved.get("target_revision") or ""),
        target_config_sha256=str(saved.get("target_config_sha256") or ""),
        attacker_controls=[
            str(value) for value in (saved.get("attacker_controls") or [])
        ],
        review_facts=(
            saved.get("review_facts")
            if isinstance(saved.get("review_facts"), dict) else {}
        ),
        _preserved_source_attestations=(
            saved.get("source_attestations")
            if "source_attestations" in saved else None
        ),
        _preserved_source_context=(
            saved.get("source_context")
            if "source_context" in saved else None
        ),
    )


def snapshot_current_tree(root: Path) -> dict[Path, dict]:
    """Capture current accepted-artifact receipts before a tree-wide rewrite."""
    root = Path(root)
    snapshots: dict[Path, dict] = {}
    for kind, prefix in (("crashes", "CRASH-*"), ("findings", "FIND-*")):
        for directory in sorted((root / kind).glob(prefix)):
            if not directory.is_dir():
                continue
            receipt = read_current(directory)
            if receipt is not None:
                snapshots[directory] = receipt
    return snapshots


def rewrite_tree_after_equivalent_transform(
    snapshots: dict[Path, dict],
) -> None:
    """Rebind receipts captured by :func:`snapshot_current_tree`."""
    for directory, receipt in snapshots.items():
        if directory.is_dir():
            rewrite_after_equivalent_transform(directory, receipt)


def claims_state(directory: Path, states: frozenset[str]) -> bool:
    """Whether the receipt on disk claims one of `states`, ignoring freshness.

    `read_current` returning None conflates "never reviewed" with "reviewed,
    then the report changed underneath". Only the raw state separates those,
    and they need different handling: the first is expected, the second means
    a concluded review lost its subject.
    """
    try:
        payload = json.loads(
            (Path(directory) / "validation.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError):
        return False
    return isinstance(payload, dict) and payload.get("state") in states


def claims_no_security_credit(directory: Path) -> bool:
    """Whether a *current* final receipt says the artifact earns no credit.

    Deliberately stricter than `claims_state`: an edited report or a changed
    bundle invalidates the receipt, and a verdict that no longer describes the
    artifact must not keep labelling it. Such an artifact returns to review
    instead. Matches what `bin/severity` and the benchmark's admission check
    read, so the page, the score, and the count cannot disagree.
    """
    payload = read_current(directory)
    return bool(
        isinstance(payload, dict)
        and payload.get("state") in FINAL_STATES - SECURITY_STATES
    )


def read_current(directory: Path) -> dict | None:
    """Return a receipt only while its report, artifacts, and scope still match.

    Scope fields the environment can contradict — attacker controls, target
    revision, target config — are compared against it directly. Everything else
    is re-derived from disk and compared whole, so an edited report, a changed
    testcase, or a re-run review invalidates the receipt.

    `review_facts` is deliberately not re-derived: it is the review's own
    conclusion, carried so consumers need not re-read the gate files, and its
    authenticity comes from those files being digested in `artifacts`. A review
    that changes its mind changes the gate file, which invalidates the receipt.
    """
    path = Path(directory) / "validation.json"
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != SCHEMA_VERSION
        or payload.get("state") not in ALL_STATES
        or payload.get("kind") not in {"finding", "crash"}
        or not isinstance(payload.get("evidence"), dict)
    ):
        return None
    saved = payload["evidence"]
    explicit_controls = os.environ.get("TARGET_ATTACKER_CONTROLS_CSV")
    if (
        explicit_controls is not None
        and triage_validate.trigger_attacker_controls(explicit_controls)
        != saved.get("attacker_controls")
    ):
        return None
    for environment_name, evidence_name in (
        ("TARGET_REV", "target_revision"),
        ("TARGET_CONFIG_SHA256", "target_config_sha256"),
    ):
        current_scope = os.environ.get(environment_name)
        if (
            current_scope is not None
            and current_scope != str(saved.get(evidence_name) or "")
        ):
            return None
    current = evidence_record(
        Path(directory),
        target_revision=str(saved.get("target_revision") or ""),
        target_config_sha256=str(saved.get("target_config_sha256") or ""),
        attacker_controls=[
            str(value) for value in (saved.get("attacker_controls") or [])
        ],
        review_facts=(
            saved.get("review_facts")
            if isinstance(saved.get("review_facts"), dict) else {}
        ),
        allow_missing_report=payload.get("state") in {"pending", "rejected"},
        _preserved_source_attestations=(
            saved.get("source_attestations")
            if "source_attestations" in saved else None
        ),
        _preserved_source_context=(
            saved.get("source_context")
            if "source_context" in saved else None
        ),
    )
    if current is None:
        return None
    restamp = False
    if "source_attestations" not in saved:
        # Schema-2 receipts written before source attestations remain readable.
        # They gain source freshness only when a later review rewrites them.
        current.pop("source_attestations", None)
        current.pop("source_context", None)
        restamp = True
    else:
        saved_attestations = saved.get("source_attestations")
        if not _attestations_match_artifacts(
            saved_attestations, current.get("artifacts", {}),
        ):
            return None
    report = report_identity.find_report(Path(directory))
    if (
        report is not None
        and saved.get("report_sha1")
        in report_identity.content_sha1_candidates(report)
    ):
        # Generated fenced snippets were accidentally included in the first
        # receipt identity. Accept that bounded legacy hash while migrating;
        # every artifact digest and scope field must still match below.
        current["report_sha1"] = saved.get("report_sha1")
        restamp = True
    if restamp:
        _stamp_evidence_id(current)
    if current != saved:
        return None
    return payload
