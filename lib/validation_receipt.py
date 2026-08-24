"""Content-addressed publication receipts for crash and finding artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import crash_artifacts
import report_identity
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


def evidence_record(
    directory: Path,
    *,
    target_revision: str = "",
    target_config_sha256: str = "",
    attacker_controls: list[str] | None = None,
    review_facts: dict[str, str] | None = None,
    allow_missing_report: bool = False,
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
    record = {
        # Pending/rejected artifacts may be incomplete by definition. An empty
        # identity binds the absence itself: adding a report later changes this
        # field and invalidates the receipt for a fresh pass.
        "report_sha1": (
            report_identity.content_sha1(report) if report is not None else ""
        ),
        "artifacts": artifacts,
        "target_revision": (
            target_revision or str(probe.get("target_revision") or "")
        ),
        "target_config_sha256": (
            target_config_sha256
            or str(probe.get("target_config_sha256") or "")
        ),
        "attacker_controls": triage_validate.trigger_attacker_controls(
            ",".join(str(value) for value in attacker_controls)
            if attacker_controls is not None else None
        ),
        "probe": probe,
        "review_facts": triage_validate.source_review_facts(
            review_facts or {},
        ),
    }
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    record["evidence_id"] = hashlib.sha256(encoded).hexdigest()
    return record


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
    )
    report = report_identity.find_report(Path(directory))
    if (
        current is not None
        and report is not None
        and saved.get("report_sha1")
        in report_identity.content_sha1_candidates(report)
    ):
        # Generated fenced snippets were accidentally included in the first
        # receipt identity. Accept that bounded legacy hash while migrating;
        # every artifact digest and scope field must still match below.
        current["report_sha1"] = saved.get("report_sha1")
        identity_record = {
            key: value for key, value in current.items()
            if key != "evidence_id"
        }
        encoded = json.dumps(
            identity_record, sort_keys=True, separators=(",", ":"),
        ).encode()
        current["evidence_id"] = hashlib.sha256(encoded).hexdigest()
    if current is None or current != saved:
        return None
    return payload
