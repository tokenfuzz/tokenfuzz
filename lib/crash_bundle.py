#!/usr/bin/env python3
"""Materialize confirmed probe diagnostics as crash bundles."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import shutil
import sys
from pathlib import Path
from typing import Sequence


def should_file(verdict: str, sanitizer: str, runs: int) -> bool:
    return verdict == "CRASH" and sanitizer != "runner" and runs >= 2


def _sha1(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _binary_identity(binary: str | os.PathLike[str] | None) -> dict:
    """Cheap build identity for a probe binary; empty when it cannot be proven."""
    if not binary:
        return {}
    try:
        path = Path(binary).resolve(strict=True)
        before = path.stat()
        digest = _sha1(path)
        after = path.stat()
    except OSError:
        return {}
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        return {}
    return {
        "path": str(path),
        "size": after.st_size,
        "mtime_ns": after.st_mtime_ns,
        "sha1": digest,
    }


def _probe_context_path(crash_dir: Path) -> Path | None:
    for path in (
        crash_dir / ".probe-context.json",
        crash_dir / ".audit" / ".probe-context.json",
    ):
        if path.is_file():
            return path
    return None


def verified_probe_context(crash_dir: Path) -> dict | None:
    """Return probe-authored context only while its testcase and build still match."""
    path = _probe_context_path(Path(crash_dir))
    if path is None:
        return None
    try:
        context = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(context, dict) or context.get("version") not in {1, 2}:
        return None
    testcase_name = context.get("testcase")
    if not isinstance(testcase_name, str) or not testcase_name:
        return None
    testcase = next(
        (
            root / testcase_name
            for root in (crash_dir, crash_dir / ".audit")
            if (root / testcase_name).is_file()
        ),
        None,
    )
    if testcase is None:
        return None
    try:
        if _sha1(testcase) != context.get("testcase_sha1"):
            return None
    except OSError:
        return None
    recorded_binary = context.get("binary")
    if not isinstance(recorded_binary, dict) or not recorded_binary:
        return None
    current_binary = _binary_identity(recorded_binary.get("path"))
    if current_binary != recorded_binary:
        return None
    identity = str(context.get("identity") or "")
    if not identity:
        return None
    identity_path = next(
        (
            candidate
            for candidate in (
                crash_dir / ".probe-identity",
                crash_dir / ".audit" / ".probe-identity",
            )
            if candidate.is_file()
        ),
        None,
    )
    try:
        if identity_path is None or identity_path.read_text(encoding="utf-8").strip() != identity:
            return None
    except OSError:
        return None
    return context


def restore_probe_context(sources: Sequence[Path], destination: Path) -> bool:
    """Restore probe provenance after a verified bundle was copied or renamed.

    Model-direct agents may publish the same testcase and sanitizer evidence in
    their benchmark result root without copying hidden probe sidecars.  Recover
    those sidecars only from a still-valid probe bundle and only when both
    evidence files match exactly.  Any missing or ambiguous evidence fails
    closed and leaves normal trigger review in place.
    """
    destination_sanitizer = destination / "sanitizer.txt"
    if not destination_sanitizer.is_file():
        return False
    try:
        sanitizer_sha1 = _sha1(destination_sanitizer)
        contexts = []
        for source in sources:
            context = verified_probe_context(source)
            source_sanitizer = source / "sanitizer.txt"
            if (
                context is not None
                and source_sanitizer.is_file()
                and _sha1(source_sanitizer) == sanitizer_sha1
            ):
                contexts.append(context)
    except OSError:
        return False
    unique = {
        json.dumps(
            {key: value for key, value in context.items() if key != "testcase"},
            sort_keys=True,
        ): context
        for context in contexts
    }
    if len(unique) != 1:
        return False
    context = next(iter(unique.values()))
    try:
        testcase_sha1 = context["testcase_sha1"]
        excluded = {
            "sanitizer.txt", "report.md", "REPORT.md", "reproduce.sh", "reproducer.sh",
        }
        testcases = [
            path for path in destination.iterdir()
            if path.is_file() and not path.name.startswith(".")
            and path.name not in excluded and _sha1(path) == testcase_sha1
        ]
    except (KeyError, OSError):
        return False
    if len(testcases) != 1:
        return False

    restored = dict(context)
    restored["testcase"] = testcases[0].name
    identity = str(restored.get("identity") or "")
    if not identity:
        return False
    identity_tmp = destination / ".probe-identity.tmp"
    context_tmp = destination / ".probe-context.json.tmp"
    try:
        identity_tmp.write_text(identity + "\n", encoding="utf-8")
        context_tmp.write_text(json.dumps(restored, sort_keys=True) + "\n", encoding="utf-8")
        identity_tmp.replace(destination / ".probe-identity")
        context_tmp.replace(destination / ".probe-context.json")
    except OSError:
        identity_tmp.unlink(missing_ok=True)
        context_tmp.unlink(missing_ok=True)
        return False
    if verified_probe_context(destination) is not None:
        return True
    (destination / ".probe-identity").unlink(missing_ok=True)
    (destination / ".probe-context.json").unlink(missing_ok=True)
    return False


def _identity(testcase: Path, sanitizer: str, mode: str, harness: Path | None, args: Sequence[str]) -> str:
    argument_data = f"argc={len(args)}\n" + "".join(f"{len(arg)}:{arg}\n" for arg in args)
    argument_hash = hashlib.sha1(argument_data.encode()).hexdigest()
    return ":".join((_sha1(testcase), sanitizer, mode, _sha1(harness) if harness else "", argument_hash))


def format_issue_id(
    target_slug: str,
    target_revision: str,
    source_kind: str,
    source_id: str,
) -> str:
    if not source_id:
        return ""
    slug = target_slug or "unknown-target"
    revision = target_revision or "unknown-revision"
    return f"tokenfuzz-issue/v1:{slug}:{revision}:{source_kind}:{source_id}"


def derive_issue_id(
    results_dir: str | os.PathLike[str],
    *,
    target_slug: str = "",
    target_revision: str = "",
    hypothesis: str = "",
    card: str = "",
) -> str:
    """Return a revision-scoped issue identity from existing run provenance.

    Recon and imported-issue cards carry identities shared by their pre-filed
    finding and later crash. Ordinary investigations fall back to the
    hypothesis id. No stack or source-location similarity participates, so an
    unknown relation remains split rather than hiding a distinct root cause.
    """
    card_row: dict = {}
    if card:
        try:
            for line in (Path(results_dir) / "work-cards.jsonl").read_text(
                encoding="utf-8", errors="replace",
            ).splitlines():
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict) and str(row.get("id", "")) == card:
                    card_row = row
        except OSError:
            pass

    source_kind = ""
    source_id = ""
    recon = card_row.get("recon")
    if isinstance(recon, dict) and recon.get("id"):
        source_kind, source_id = "recon", str(recon["id"])
    elif card_row.get("issue_id"):
        source_kind, source_id = "upstream", str(card_row["issue_id"])
    elif card_row.get("find_id"):
        source_kind, source_id = "finding", str(card_row["find_id"])
    elif hypothesis:
        source_kind, source_id = "hypothesis", hypothesis
    elif card:
        source_kind, source_id = "card", card
    return format_issue_id(
        target_slug, target_revision, source_kind, source_id,
    )


def _write_probe_context(
    destination: Path,
    *,
    identity: str,
    testcase: Path,
    sanitizer: str,
    mode: str,
    harness: Path | None,
    args: Sequence[str],
    binary: str | os.PathLike[str] | None,
    target_slug: str = "",
    target_revision: str = "",
    hypothesis: str = "",
    card: str = "",
    issue_id: str = "",
) -> None:
    (destination / ".probe-context.json").write_text(
        json.dumps(
            {
                "version": 2,
                "identity": identity,
                "testcase": testcase.name,
                "testcase_sha1": _sha1(testcase),
                "sanitizer": sanitizer,
                "mode": mode,
                "harness": bool(harness),
                "args": list(args),
                "binary": _binary_identity(binary),
                "target_slug": target_slug,
                "target_revision": target_revision,
                "hypothesis_id": hypothesis,
                "card_id": card,
                "issue_id": issue_id,
            },
            sort_keys=True,
        ) + "\n",
        encoding="utf-8",
    )


def materialize(
    results_dir: str | os.PathLike[str],
    agent: str,
    testcase: str | os.PathLike[str],
    sanitizer_output: str | os.PathLike[str],
    sanitizer: str,
    mode: str,
    *,
    harness: str | os.PathLike[str] | None = None,
    args: Sequence[str] = (),
    target: str = "",
    target_slug: str = "",
    target_revision: str = "",
    hypothesis: str = "",
    card: str = "",
    strategy: str = "",
    binary: str | os.PathLike[str] | None = None,
) -> tuple[str, str]:
    testcase_path = Path(testcase)
    sanitizer_path = Path(sanitizer_output)
    harness_path = Path(harness) if harness else None
    if not testcase_path.is_file() or not sanitizer_path.is_file() or (harness_path and not harness_path.is_file()):
        raise FileNotFoundError("bundle input missing")
    crashes = Path(results_dir) / "crashes"
    crashes.mkdir(parents=True, exist_ok=True)
    identity = _identity(testcase_path, sanitizer, mode, harness_path, args)
    issue_id = derive_issue_id(
        results_dir,
        target_slug=target_slug,
        target_revision=target_revision,
        hypothesis=hypothesis,
        card=card,
    )
    index = crashes / f".probe-filed-{agent}.tsv"
    if index.is_file():
        try:
            index_lines = index.read_text(errors="replace").splitlines()
        except OSError as exc:
            print(f"WARN: crash dedup index could not be read; continuing: {exc}", file=sys.stderr)
            index_lines = []
        for line in index_lines:
            key, separator, crash_id = line.partition("\t")
            if separator and key == identity and (crashes / crash_id).is_dir():
                _write_probe_context(
                    crashes / crash_id, identity=identity, testcase=testcase_path,
                    sanitizer=sanitizer, mode=mode, harness=harness_path,
                    args=args, binary=binary, target_slug=target_slug,
                    target_revision=target_revision, hypothesis=hypothesis,
                    card=card, issue_id=issue_id,
                )
                return "DUP", crash_id
    maximum = 0
    pattern = re.compile(rf"^CRASH-([0-9]+)-{re.escape(str(agent))}$")
    for path in crashes.iterdir():
        match = pattern.match(path.name) if path.is_dir() else None
        if match:
            maximum = max(maximum, int(match.group(1)))
            for identity_path in (path / ".probe-identity", path / ".audit" / ".probe-identity"):
                try:
                    if identity_path.read_text(encoding="utf-8").strip() == identity:
                        _write_probe_context(
                            path, identity=identity, testcase=testcase_path,
                            sanitizer=sanitizer, mode=mode, harness=harness_path,
                            args=args, binary=binary, target_slug=target_slug,
                            target_revision=target_revision, hypothesis=hypothesis,
                            card=card, issue_id=issue_id,
                        )
                        return "DUP", path.name
                except OSError:
                    pass
    crash_id = f"CRASH-{maximum + 1:03d}-{agent}"
    destination = crashes / crash_id
    destination.mkdir()
    try:
        (destination / ".probe-identity").write_text(identity + "\n", encoding="utf-8")
        _write_probe_context(
            destination, identity=identity, testcase=testcase_path,
            sanitizer=sanitizer, mode=mode, harness=harness_path, args=args,
            binary=binary, target_slug=target_slug,
            target_revision=target_revision, hypothesis=hypothesis,
            card=card, issue_id=issue_id,
        )
        shutil.copy2(testcase_path, destination / testcase_path.name)
        shutil.copy2(sanitizer_path, destination / "sanitizer.txt")
        if harness_path:
            shutil.copy2(harness_path, destination / harness_path.name)
        if args:
            quoted = " ".join(shlex.quote(arg) for arg in args)
            (destination / "repro.cmd").write_text(
                "# Args after the target binary or harness. {TESTCASE} is replaced by export-repro.\n"
                f"{{TESTCASE}} {quoted}\n"
            )
        diagnostic_pattern = re.compile(
            r"(AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer|LeakSanitizer): [a-zA-Z0-9-]+"
        )
        match = None
        with sanitizer_path.open(errors="replace") as trace:
            for line in trace:
                if match := diagnostic_pattern.search(line):
                    break
        diagnostic = match.group(0) if match else "sanitizer diagnostic"
        harness_line = f"- Harness: `{harness_path.name}`\n" if harness_path else ""
        card_line = f"CARD-ID: {card}\n" if card else ""
        location = f" at {target}" if target else ""
        report = f"""# {crash_id}: {diagnostic} (auto-filed by bin/probe)

> AUTO-FILED skeleton. bin/probe confirmed this sanitizer diagnostic for
> hypothesis `{hypothesis or '?'}`. Triage holds this as promotion-pending until you
> REPLACE the TODO Root Cause / Data Flow sections and fill the
> bare-label fields below. The reproducer and sanitizer trace are already
> on disk here - do not re-file or leave this stub in scratch.

## Summary
{diagnostic} reproduced via hypothesis `{hypothesis or '?'}`{location}.

## Reproduction
- Reproducer: `{testcase_path.name}`
- Sanitizer output: `sanitizer.txt`
{harness_line}
## Root Cause
_TODO (agent): describe the defect and why the sanitizer fires._

## Data Flow
_TODO (agent): step: func (file:line) - desc._

Boundary:
Caller controls:
Trusted caller actions:
Caller contract:
Trigger source:
Strategy: {strategy}
{card_line}"""
        (destination / "report.md").write_text(report)
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    try:
        with index.open("a") as stream:
            stream.write(f"{identity}\t{crash_id}\n")
    except OSError as exc:
        # The bundle is already complete. Losing the dedup hint must not make
        # bin/probe claim that filing failed or delete usable crash evidence.
        print(f"WARN: crash filed as {crash_id}, but dedup index update failed: {exc}", file=sys.stderr)
    return "FILED", crash_id
