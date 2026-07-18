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
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

import stack_frames


def should_file(verdict: str, sanitizer: str, runs: int) -> bool:
    return verdict == "CRASH" and sanitizer != "runner" and runs >= 2


def _sha1(path: Path) -> str:
    digest = hashlib.sha1()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def binary_identity(binary: str | os.PathLike[str] | None) -> dict:
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
    if not isinstance(context, dict) or context.get("version") not in (1, 2, 3):
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
    current_binary = binary_identity(recorded_binary.get("path"))
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


_PRIMARY_DIFFERENTIAL_JSON = ".primary-build-differential.json"
_PRIMARY_DIFFERENTIAL_SANITIZER = ".primary-build-sanitizer.txt"
_PRIMARY_DIFFERENTIAL_STATUSES = {
    "reproduced", "not-reproduced", "different-crash", "inconclusive",
}


def _artifact_path(crash_dir: Path, name: str) -> Path | None:
    for root in (Path(crash_dir), Path(crash_dir) / ".audit"):
        path = root / name
        if path.is_file():
            return path
    return None


def build_config_metadata(crash_dir: Path) -> dict | None:
    """Return recorded alternate-build identity from either bundle layout."""
    path = _artifact_path(Path(crash_dir), ".build-config.json")
    if path is None:
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict) or not isinstance(payload.get("id"), str):
        return None
    return payload


def verified_primary_differential(crash_dir: Path) -> dict | None:
    """Return a probe-authored alternate-vs-primary result while evidence matches."""
    crash_dir = Path(crash_dir)
    context = verified_probe_context(crash_dir)
    if context is None or not context.get("build_config_id"):
        return None
    result_path = _artifact_path(crash_dir, _PRIMARY_DIFFERENTIAL_JSON)
    sanitizer_path = _artifact_path(crash_dir, _PRIMARY_DIFFERENTIAL_SANITIZER)
    if result_path is None or sanitizer_path is None:
        return None
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if not isinstance(result, dict) or result.get("version") != 1:
            return None
        if result.get("status") not in _PRIMARY_DIFFERENTIAL_STATUSES:
            return None
        if (
            result.get("context_identity") != context.get("identity")
            or result.get("testcase_sha1") != context.get("testcase_sha1")
            or result.get("build_config_id") != context.get("build_config_id")
            or result.get("primary_sanitizer_sha1") != _sha1(sanitizer_path)
        ):
            return None
        recorded_binary = result.get("primary_binary")
        if not isinstance(recorded_binary, dict) or not recorded_binary:
            return None
        if binary_identity(recorded_binary.get("path")) != recorded_binary:
            return None
    except (OSError, ValueError, TypeError):
        return None
    return result


def _rate(text: str, label: str) -> tuple[int, int] | None:
    matches = re.findall(
        rf"^(?:\[run-sanitizer-multi\]\s+)?{re.escape(label)}:\s*(\d+)\s*/\s*(\d+)\s*$",
        text,
        re.MULTILINE,
    )
    if not matches:
        return None
    numerator, denominator = matches[-1]
    return int(numerator), int(denominator)


def _config_name(crash_dir: Path, config_id: str) -> str:
    payload = build_config_metadata(crash_dir)
    if payload is None or payload.get("id") != config_id:
        return ""
    return str(payload.get("name") or "")


def record_primary_differential(
    crash_dir: Path,
    primary_sanitizer: Path,
    primary_result: dict,
) -> dict | None:
    """Bind one forced-primary probe result to an alternate-config crash bundle."""
    crash_dir = Path(crash_dir)
    context = verified_probe_context(crash_dir)
    sanitizer = Path(primary_sanitizer)
    if context is None or not context.get("build_config_id") or not sanitizer.is_file():
        return None
    try:
        primary_text = sanitizer.read_text(encoding="utf-8", errors="replace")
        alternate_path = crash_dir / "sanitizer.txt"
        if not alternate_path.is_file():
            alternate_path = _artifact_path(crash_dir, "sanitizer.txt") or alternate_path
        alternate_text = alternate_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    primary_binary = primary_result.get("binary")
    if (
        primary_result.get("version") != 1
        or primary_result.get("testcase_sha1") != context.get("testcase_sha1")
        or primary_result.get("build_config") != "primary"
        or not isinstance(primary_binary, dict)
        or not primary_binary
        or binary_identity(primary_binary.get("path")) != primary_binary
    ):
        return None
    primary_crash = _rate(primary_text, "CRASH_RATE")
    primary_execution = _rate(primary_text, "EXECUTION_RATE")
    alternate_signature = stack_frames.crash_signature(alternate_text)
    primary_signature = stack_frames.crash_signature(primary_text)
    if (
        primary_crash == (5, 5)
        and alternate_signature
        and primary_signature == alternate_signature
    ):
        status = "reproduced"
    elif primary_crash == (0, 5) and primary_execution == (5, 5):
        status = "not-reproduced"
    elif primary_crash == (5, 5) and primary_signature:
        status = "different-crash"
    else:
        status = "inconclusive"
    destination = crash_dir / _PRIMARY_DIFFERENTIAL_SANITIZER
    result_path = crash_dir / _PRIMARY_DIFFERENTIAL_JSON
    result = {
        "version": 1,
        "context_identity": context["identity"],
        "testcase_sha1": context["testcase_sha1"],
        "build_config_id": context["build_config_id"],
        "build_config_name": _config_name(crash_dir, context["build_config_id"]),
        "status": status,
        "primary_verdict": str(primary_result.get("verdict") or ""),
        "primary_binary": primary_binary,
        "primary_crash_rate": list(primary_crash) if primary_crash else None,
        "primary_execution_rate": list(primary_execution) if primary_execution else None,
        "alternate_signature": alternate_signature,
        "primary_signature": primary_signature,
    }
    fd, sanitizer_tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.", dir=crash_dir)
    os.close(fd)
    sanitizer_tmp = Path(sanitizer_tmp_name)
    json_tmp = result_path.with_name(f".{result_path.name}.{os.getpid()}.tmp")
    try:
        shutil.copy2(sanitizer, sanitizer_tmp)
        result["primary_sanitizer_sha1"] = _sha1(sanitizer_tmp)
        json_tmp.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
        os.replace(sanitizer_tmp, destination)
        os.replace(json_tmp, result_path)
    except OSError:
        sanitizer_tmp.unlink(missing_ok=True)
        json_tmp.unlink(missing_ok=True)
        return None
    # bin/severity surfaces the configuration and this status as a Fields-table
    # row in report.md (and thus report.html); no report edit is needed here.
    return verified_primary_differential(crash_dir)


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
        _restore_primary_differential(sources, destination)
        return True
    (destination / ".probe-identity").unlink(missing_ok=True)
    (destination / ".probe-context.json").unlink(missing_ok=True)
    return False


def _restore_primary_differential(sources: Sequence[Path], destination: Path) -> None:
    """Best-effort restore of differential sidecars alongside restored context."""
    candidates: dict[str, tuple[Path, Path]] = {}
    for source in sources:
        result = verified_primary_differential(source)
        result_path = _artifact_path(source, _PRIMARY_DIFFERENTIAL_JSON)
        sanitizer_path = _artifact_path(source, _PRIMARY_DIFFERENTIAL_SANITIZER)
        if result is None or result_path is None or sanitizer_path is None:
            continue
        key = json.dumps(result, sort_keys=True)
        candidates[key] = (result_path, sanitizer_path)
    if len(candidates) != 1:
        return
    result_path, sanitizer_path = next(iter(candidates.values()))
    try:
        shutil.copy2(result_path, destination / _PRIMARY_DIFFERENTIAL_JSON)
        shutil.copy2(sanitizer_path, destination / _PRIMARY_DIFFERENTIAL_SANITIZER)
    except OSError:
        (destination / _PRIMARY_DIFFERENTIAL_JSON).unlink(missing_ok=True)
        (destination / _PRIMARY_DIFFERENTIAL_SANITIZER).unlink(missing_ok=True)
        return
    if verified_primary_differential(destination) is None:
        (destination / _PRIMARY_DIFFERENTIAL_JSON).unlink(missing_ok=True)
        (destination / _PRIMARY_DIFFERENTIAL_SANITIZER).unlink(missing_ok=True)


def _identity(
    testcase: Path, sanitizer: str, mode: str, harness: Path | None,
    args: Sequence[str], build_config_id: str = "", build_recipe_digest: str = "",
) -> str:
    argument_data = f"argc={len(args)}\n" + "".join(f"{len(arg)}:{arg}\n" for arg in args)
    argument_hash = hashlib.sha1(argument_data.encode()).hexdigest()
    identity = ":".join((
        _sha1(testcase), sanitizer, mode, _sha1(harness) if harness else "",
        argument_hash,
    ))
    return (
        f"{identity}:cfg={build_config_id}@{build_recipe_digest}"
        if build_config_id else identity
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
    build_config_id: str = "",
    build_recipe_digest: str = "",
) -> None:
    (destination / ".probe-context.json").write_text(
        json.dumps(
            {
                "version": 3 if build_config_id else 1,
                "identity": identity,
                "testcase": testcase.name,
                "testcase_sha1": _sha1(testcase),
                "sanitizer": sanitizer,
                "mode": mode,
                "harness": bool(harness),
                "args": list(args),
                "binary": binary_identity(binary),
                "build_config_id": build_config_id,
                "build_recipe_sha256": build_recipe_digest,
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
    build_config=None,
    build_recipe: str | os.PathLike[str] | None = None,
) -> tuple[str, str]:
    testcase_path = Path(testcase)
    sanitizer_path = Path(sanitizer_output)
    harness_path = Path(harness) if harness else None
    build_config_id = str(getattr(build_config, "config_id", "") or "")
    build_recipe_path = Path(build_recipe) if build_recipe else None
    if not testcase_path.is_file() or not sanitizer_path.is_file() or (harness_path and not harness_path.is_file()):
        raise FileNotFoundError("bundle input missing")
    if build_config_id and (build_recipe_path is None or not build_recipe_path.is_file()):
        raise FileNotFoundError("alternate build recipe missing")
    build_recipe_digest = (
        hashlib.sha256(build_recipe_path.read_bytes()).hexdigest()
        if build_config_id and build_recipe_path is not None else ""
    )
    crashes = Path(results_dir) / "crashes"
    crashes.mkdir(parents=True, exist_ok=True)
    identity = _identity(
        testcase_path, sanitizer, mode, harness_path, args,
        build_config_id, build_recipe_digest,
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
                    args=args, binary=binary, build_config_id=build_config_id,
                    build_recipe_digest=build_recipe_digest,
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
                            args=args, binary=binary, build_config_id=build_config_id,
                            build_recipe_digest=build_recipe_digest,
                        )
                        return "DUP", path.name
                except OSError:
                    pass
    crash_id = f"CRASH-{maximum + 1:03d}-{agent}"
    destination = crashes / crash_id
    destination.mkdir()
    try:
        # copy2 below preserves source mtimes, so none of the copied evidence is
        # an honest filing clock. Record one immutable bundle-creation timestamp
        # before copying; duplicate probes reuse the existing bundle and never
        # rewrite it.
        (destination / ".crash-created-at").write_text(
            datetime.now(timezone.utc).isoformat() + "\n", encoding="utf-8",
        )
        (destination / ".probe-identity").write_text(identity + "\n", encoding="utf-8")
        _write_probe_context(
            destination, identity=identity, testcase=testcase_path,
            sanitizer=sanitizer, mode=mode, harness=harness_path, args=args,
            binary=binary, build_config_id=build_config_id,
            build_recipe_digest=build_recipe_digest,
        )
        shutil.copy2(testcase_path, destination / testcase_path.name)
        shutil.copy2(sanitizer_path, destination / "sanitizer.txt")
        if harness_path:
            shutil.copy2(harness_path, destination / harness_path.name)
        if build_config_id and build_recipe_path is not None:
            recipe_copy = destination / ".build-config-recipe.sh"
            shutil.copy2(build_recipe_path, recipe_copy)
            (destination / ".build-config.json").write_text(
                json.dumps(
                    {
                        "id": build_config_id,
                        "name": str(getattr(build_config, "name", "")),
                        "label": str(getattr(build_config, "label", "")),
                        "features": [
                            str(feature)
                            for feature in getattr(build_config, "features", ())
                            if str(feature).strip()
                        ],
                        "recipe_sha256": build_recipe_digest,
                    },
                    sort_keys=True,
                ) + "\n",
                encoding="utf-8",
            )
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
