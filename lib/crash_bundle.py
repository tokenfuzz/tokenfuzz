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
    if not isinstance(context, dict) or context.get("version") != 1:
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


def _identity(testcase: Path, sanitizer: str, mode: str, harness: Path | None, args: Sequence[str]) -> str:
    argument_data = f"argc={len(args)}\n" + "".join(f"{len(arg)}:{arg}\n" for arg in args)
    argument_hash = hashlib.sha1(argument_data.encode()).hexdigest()
    return ":".join((_sha1(testcase), sanitizer, mode, _sha1(harness) if harness else "", argument_hash))


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
) -> None:
    (destination / ".probe-context.json").write_text(
        json.dumps(
            {
                "version": 1,
                "identity": identity,
                "testcase": testcase.name,
                "testcase_sha1": _sha1(testcase),
                "sanitizer": sanitizer,
                "mode": mode,
                "harness": bool(harness),
                "args": list(args),
                "binary": _binary_identity(binary),
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
                    args=args, binary=binary,
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
                            args=args, binary=binary,
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
            binary=binary,
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
