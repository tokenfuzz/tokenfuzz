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
import crash_artifacts
import llm_decide
import llm_usage
import stack_frames
from prompt_render import render_template

SCRIPT_ROOT = Path(__file__).resolve().parent.parent

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
_MEMORY_SAFETY = re.compile(
    r"AddressSanitizer: (?:heap-buffer-overflow|(?:heap-)?use-after-free|container-overflow"
    r"|dynamic-stack-buffer-overflow|stack-buffer-overflow|stack-use-after-return"
    r"|stack-use-after-scope|global-buffer-overflow|alloc-dealloc-mismatch"
    r"|intra-object-overflow|double-free|negative-size-param|bad-free|calloc-overflow"
    r"|new-delete-type-mismatch|invalid-pointer-pair|[a-z]+-param-overlap)"
)
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
_REPORT_NAMES = ("REPORT.md", "report.md", "description.md", "analysis.md", "README.md")


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
    for name in _REPORT_NAMES:
        candidate = directory / name
        if candidate.is_file() and candidate.stat().st_size:
            return candidate
    return None


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
        _MEMORY_SAFETY.search(text)
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


def _reject(directory: Path, rejected_root: Path, reason: str) -> Path:
    rejected_root.mkdir(parents=True, exist_ok=True)
    _annotate_rejection(directory, reason)
    destination = _unique_destination(rejected_root, directory.name)
    shutil.move(str(directory), destination)
    return destination


def _demote_to_finding(directory: Path, results_dir: Path, reason: str) -> Path:
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


def _field(text: str, name: str) -> str:
    table = re.search(rf"^\|\s*{re.escape(name)}\s*\|\s*([^|\n]+)", text, re.IGNORECASE | re.MULTILINE)
    if table:
        return table.group(1).strip()
    label = re.search(rf"^{re.escape(name)}\s*:\s*(.+)$", text, re.IGNORECASE | re.MULTILINE)
    return label.group(1).strip() if label else ""


_REACH_FIELD_LABELS = {
    "surface": "Surface",
    "primitive": "Primitive",
    "class": "Class",
    "caller_contract": "Caller contract",
    "caller_controls": "Caller controls",
    "trigger_source": "Trigger source",
    "parameter_control": "Parameter control",
    "trusted_caller_actions": "Trusted caller actions",
    "boundary": "Boundary",
    "advisory": "Advisory",
}
_REACH_FIELD_ENUMS = {
    "caller_contract": {"obeyed", "violated"},
    "caller_controls": {"bytes", "length", "number", "flags", "call-sequence", "timing", "none"},
    "trigger_source": {"bytes", "both", "call-sequence", "timing", "race", "protocol-state", "env", "fs-state"},
    "parameter_control": {"direct", "indirect", "application-supplied", "trusted", "harness-only"},
    "trusted_caller_actions": {"normal public call", "private mutation", "callback ordering", "harness-only"},
    "advisory": {"yes", "no"},
}
_SURFACE_KINDS = {"network", "library-api", "file-format", "cli", "dev-tool", "internal", "unknown"}


def _valid_reach_field(key: str, value: object) -> str:
    """Return a safe scorer field value, or empty when a decision is malformed."""
    if key not in _REACH_FIELD_LABELS or not isinstance(value, str):
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
    placeholders = {"", "-", "—", "tbd", "unspecified", "unknown / not assessed"}
    return any(
        (table_value or bare_value).strip().lower() not in placeholders
        for table_value, bare_value in values
    )


def fill_reach_fields(
    directory: Path, usage_index: str | os.PathLike[str] | None = None,
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
        with report.open("rb") as stream:
            text = stream.read(6000).decode("utf-8", errors="replace")
    except OSError:
        return False
    missing = {
        key: label for key, label in _REACH_FIELD_LABELS.items()
        if not _reach_field_present(text, label)
    }
    if not missing:
        return False
    sidecar = directory / ".llm_fields.json"
    cache = _finding_cache(sidecar)
    try:
        attempts = int(cache.get("_fill_attempts", 0))
        max_attempts = _positive_int_env("LLM_FIELD_FILL_MAX_ATTEMPTS", 2)
    except (TypeError, ValueError):
        attempts, max_attempts = 0, 2
    if attempts >= max_attempts:
        return False
    prompt = render_template("triage_reachability_fields.md.j2", {"narrative": text})
    try:
        timeout = _positive_int_env("LLM_DECISION_TIMEOUT", 45)
    except ValueError:
        timeout = 45
    decision = llm_decide.llm_decide(
        "reachability-fields", "", prompt, timeout, usage_index=usage_index,
    )
    cache["_fill_attempts"] = attempts + 1
    if not isinstance(decision, dict):
        _write_atomic_json(sidecar, cache)
        return False
    accepted = {
        key: value
        for key, raw in decision.items()
        if key in missing and (value := _valid_reach_field(key, raw))
    }
    cache.update(accepted)
    _write_atomic_json(sidecar, cache)
    if not accepted:
        return False
    current = report.read_text(encoding="utf-8", errors="replace")
    additions = [
        f"{_REACH_FIELD_LABELS[key]}: {value}"
        for key, value in accepted.items()
        if not _reach_field_present(current, _REACH_FIELD_LABELS[key])
    ]
    if not additions:
        return False
    _atomic_write_text(report, current.rstrip() + "\n\n" + "\n".join(additions) + "\n")
    return True


def fill_reach_fields_tree(root: Path) -> int:
    """Apply reach-field convergence to every pooled crash and finding."""
    filled = 0
    usage_index = benchmark._find_index_jsonl(Path(root))
    for kind, prefix in (("findings", "FIND-*"), ("crashes", "CRASH-*")):
        for directory in sorted((Path(root) / kind).glob(prefix)):
            if directory.is_dir() and fill_reach_fields(directory, usage_index):
                filled += 1
    return filled


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


def cluster_expansion_decision(
    crash_dir: Path, target_root: Path, *, deadline: float | None = None,
) -> list[dict] | None:
    """Return up to three source-grounded sibling leads for one new crash.

    ``None`` means retryable/unavailable; an empty list is a completed decision
    that found no strong siblings and may be marked final by the caller.
    """
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
    prompt = render_template(
        "triage_cluster_expand.md.j2",
        {
            "id": crash_dir.name,
            "frames": "\n".join(frame.raw for frame in frames),
            "source_block": "\n\n".join(source_parts) or "(source unavailable)",
        },
    )
    try:
        configured = _positive_int_env("LLM_DECISION_TIMEOUT", 45)
    except ValueError:
        configured = 45
    # This decision sees only the bounded frame/source excerpts above. It does
    # not need the old ten-minute floor; use the backend-appropriate decision
    # timeout and let the live productive-wall deadline shorten it further.
    timeout = _decision_timeout(configured, deadline)
    if timeout <= 0:
        return None
    decision = llm_decide.llm_decide(
        "cluster_expand", "rows", prompt, timeout,
        usage_index=llm_usage.find_usage_index(crash_dir.parents[1]),
    )
    if not isinstance(decision, dict) or not isinstance(decision.get("rows"), list):
        return None
    return [row for row in decision["rows"][:3] if isinstance(row, dict)]


def evaluate_crash_verdict(report_text: str, controls: list[str]) -> tuple[str, str]:
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
        return "contract-flag", f"trigger requires {','.join(missing)} outside attacker_controls={','.join(controls)}"
    return "promote", f"trigger within attacker_controls={','.join(controls)}"


def _set_contract_concern(report: Path, reason: str) -> None:
    text = _read(report)
    text = re.sub(
        r"\n?## Contract concern\s*\n.*?(?=\n(?:## |Summary:)|\Z)", "", text,
        flags=re.DOTALL,
    ).rstrip()
    block = (
        "## Contract concern\n\n"
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


def _run_tool(name: str, *args: str, env: dict | None = None) -> int:
    return subprocess.run(
        [str(SCRIPT_ROOT / "bin" / name), *map(str, args)],
        env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    ).returncode


def _report_gate_cap() -> int:
    try:
        cap = int(os.environ.get("REPORT_GATE_MAX_BYTES", "262144"))
    except ValueError:
        return 262144
    return cap if cap >= 1 else 262144


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
    for name in _PENDING_SIDECARS:
        try:
            (directory / name).unlink(missing_ok=True)
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
) -> str:
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
        _MEMORY_SAFETY.search(text)
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


def _finding_trigger_rejected(
    finding_dir: Path, report: Path, deadline: float | None = None,
    usage_index: str | os.PathLike[str] | None = None,
) -> bool:
    backend = os.environ.get("ACTIVE_BACKEND") or os.environ.get("BACKEND") or ""
    target_root = os.environ.get("TARGET_ROOT", "")
    if not backend or not target_root:
        return False
    return _trigger_vote(
        report, finding_dir / ".trigger-gate.json", backend,
        os.environ.get("MODEL", ""), Path(target_root), deadline, usage_index,
    ) == 1


def _trigger_vote(
    report: Path, vote_file: Path, backend: str, model: str,
    target_root: Path, deadline: float | None = None,
    usage_index: str | os.PathLike[str] | None = None,
) -> int:
    """Run the recall-safe trigger-provenance reviewer (`validate-finding --gate
    trigger`) over a report. Returns 1 = disproof-backed Reject, 0 = keep
    (Promote/Uncertain), 2 = no verdict yet (retryable). Only a conclusive cached
    verdict short-circuits a re-run; a cached ParseFailure is not a verdict and
    falls through to retry."""
    if vote_file.is_file() and vote_file.stat().st_size:
        try:
            cached = json.loads(vote_file.read_text(encoding="utf-8")).get("vote")
        except (OSError, ValueError):
            cached = None
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
    timeout = _decision_timeout(300, deadline)
    if timeout <= 0:
        return 2
    command = [
        str(SCRIPT_ROOT / "bin" / "validate-finding"),
        "--finding", str(report), "--target-path", str(target_root),
        "--backend", backend, "--gate", "trigger", "--output", str(vote_file),
        "--timeout", str(timeout),
    ]
    if model:
        command += ["--model", model]
    if usage_index:
        command += ["--usage-index", os.fspath(usage_index)]
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
    if rc == 1:
        return 1
    if rc in (0, 2):
        return 0
    return 2


def _crash_trigger_gate(
    crash_dir: Path, report: Path, target_root: Path,
    deadline: float | None = None,
    usage_index: str | os.PathLike[str] | None = None,
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
    backend = os.environ.get("ACTIVE_BACKEND") or os.environ.get("BACKEND") or ""
    model = os.environ.get("MODEL", "")
    if _trigger_vote(
        report, crash_dir / ".trigger-gate.json", backend, model,
        target_root, deadline, usage_index,
    ) != 1:
        return False
    return _trigger_vote(
        report, crash_dir / ".trigger-gate-2.json", backend, model,
        target_root, deadline, usage_index,
    ) == 1


def triage_one_crash(
    crash_dir: Path,
    results_dir: Path,
    target_root: Path,
    target_slug: str,
    attacker_controls: list[str],
    findings_only: bool = False,
    deadline: float | None = None,
) -> str:
    if _deadline_expired(deadline):
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
    report = _report(crash_dir)
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
        return _hold_incomplete(crash_dir, rejected_root, report, "missing", missing)
    if runtime_only:
        _demote_to_finding(
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
        _demote_to_finding(crash_dir, results_dir, reason)
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
            crash_dir, rejected_root, report, "bundle", bundle_missing
        )
    report = _report(crash_dir)
    if report is None:
        return _hold_incomplete(
            crash_dir, rejected_root, None, "bundle", ["REPORT.md"]
        )
    if not _deadline_expired(deadline):
        fill_reach_fields(crash_dir, usage_index)
        report = _report(crash_dir) or report
    verdict, detail = evaluate_crash_verdict(_read(report), attacker_controls)
    if verdict == "incomplete":
        return _hold_incomplete(
            crash_dir, rejected_root, report, "fields",
            ["Caller contract or Trigger source"],
        )
    _clear_promotion_sidecars(crash_dir)
    if verdict == "contract-flag":
        _set_contract_concern(report, detail)
    else:
        _clear_contract_concern(report)
    if _crash_trigger_gate(
        crash_dir, report, Path(target_root), deadline, usage_index,
    ):
        _reject(
            crash_dir, rejected_root,
            "trigger-provenance (2 independent rejects): triggering state not attacker-reachable from a public boundary",
        )
        return "rejected"
    if _decision_timeout(1, deadline):
        _run_tool("severity", "--report", str(crash_dir), env=environment)
    return "promoted"


def triage_crash_dirs(
    results_dir: str | os.PathLike[str],
    target_root: str | os.PathLike[str],
    target_slug: str,
    attacker_controls: list[str] | None = None,
    *,
    workers: int = 4,
    findings_only: bool = False,
    deadline: float | None = None,
) -> dict[str, int]:
    results = Path(results_dir)
    crashes = results / "crashes"
    crashes.mkdir(parents=True, exist_ok=True)
    controls = attacker_controls or ["bytes"]
    directories = [path for path in sorted(crashes.glob("CRASH-*")) if path.is_dir()]
    counts = {"promoted": 0, "rejected": 0, "pending": 0, "demoted": 0}
    if not directories:
        return counts
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        statuses = pool.map(
            lambda directory: triage_one_crash(
                directory, results, Path(target_root), target_slug, controls,
                findings_only, deadline,
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


def _quality_vote(
    report_text: str, timeout: int,
    usage_index: str | os.PathLike[str] | None = None,
) -> dict | None:
    prompt = render_template("triage_find_quality.md.j2", {"body": report_text})
    return llm_decide.llm_decide(
        "find_quality", "accept,reason,class,severity", prompt, timeout,
        usage_index=usage_index,
    )


def _finalize_accepted_finding(
    finding_dir: Path, results_dir: Path, report: Path,
    deadline: float | None,
    usage_index: str | os.PathLike[str] | None = None,
) -> str:
    if not _deadline_expired(deadline):
        fill_reach_fields(finding_dir, usage_index)
        report = _report(finding_dir) or report
    if _finding_trigger_rejected(
        finding_dir, report, deadline, usage_index,
    ):
        _reject(
            finding_dir, results_dir / "findings-rejected",
            "trigger-provenance: triggering state not attacker-reachable",
        )
        return "rejected"
    _run_tool("severity", "--report", str(finding_dir))
    return "accepted"


def validate_one_finding(
    finding_dir: Path,
    results_dir: Path,
    *,
    quorum: int = 2,
    accept_quorum: int = 2,
    timeout: int = 300,
    deadline: float | None = None,
) -> str:
    if (finding_dir / ".keep").is_file() or (finding_dir / ".reviewed").is_file():
        return "accepted"
    if _deadline_expired(deadline):
        return "pending"
    usage_index = benchmark._find_index_jsonl(results_dir)
    report = _report(finding_dir)
    if report is None:
        (finding_dir / ".needs-content").touch()
        return "pending"
    (finding_dir / ".needs-content").unlink(missing_ok=True)
    cache_path = finding_dir / ".llm-find-quality.json"
    cache = _finding_cache(cache_path)
    if cache.get("decision_version") == "v13-python":
        if cache.get("accept") is True and int(cache.get("accept_count", 0)) >= accept_quorum:
            (finding_dir / ".pending-drop").unlink(missing_ok=True)
            return _finalize_accepted_finding(
                finding_dir, results_dir, report, deadline, usage_index
            )
        if cache.get("accept") is False and int(cache.get("reject_count", 0)) >= quorum:
            _reject(finding_dir, results_dir / "findings-rejected", str(cache.get("reason") or "quality gate reject"))
            return "rejected"
    report_text = read_report_bounded(report)
    accepts = rejects = 0
    accepted_class = accepted_severity = accepted_reason = rejected_reason = ""
    for _ in range(max(1, accept_quorum + quorum - 1)):
        vote_timeout = _decision_timeout(timeout, deadline)
        if vote_timeout <= 0:
            break
        vote = _quality_vote(report_text, vote_timeout, usage_index)
        if not isinstance(vote, dict) or not isinstance(vote.get("accept"), bool):
            break
        if vote["accept"]:
            accepts += 1
            accepted_reason = str(vote.get("reason") or accepted_reason)
            accepted_class = str(vote.get("class") or accepted_class)
            accepted_severity = str(vote.get("severity") or accepted_severity)
            if accepts >= accept_quorum:
                payload = {
                    "decision_version": "v13-python", "accept": True,
                    "accept_count": accepts, "reason": accepted_reason,
                    "class": accepted_class, "severity": accepted_severity,
                    "content_sha1": hashlib.sha1(report_text.encode()).hexdigest(),
                }
                _write_atomic_json(cache_path, payload)
                (finding_dir / ".pending-drop").unlink(missing_ok=True)
                return _finalize_accepted_finding(
                    finding_dir, results_dir, report, deadline, usage_index
                )
        else:
            rejects += 1
            rejected_reason = str(vote.get("reason") or rejected_reason)
            if rejects >= quorum:
                payload = {
                    "decision_version": "v13-python", "accept": False,
                    "reject_count": rejects,
                    "reason": rejected_reason or "quality gate rejected finding",
                    "class": "", "severity": "",
                    "content_sha1": hashlib.sha1(report_text.encode()).hexdigest(),
                }
                _write_atomic_json(cache_path, payload)
                (finding_dir / ".pending-drop").unlink(missing_ok=True)
                _reject(finding_dir, results_dir / "findings-rejected", payload["reason"])
                return "rejected"
    if rejects:
        (finding_dir / ".pending-drop").write_text(
            f"Reject count: {rejects}/{quorum}\n"
            f"Reason: {rejected_reason or 'finding quality review did not reach quorum'}\n",
            encoding="utf-8",
        )
    return "pending"


def _write_atomic_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def validate_find_gate(
    results_dir: str | os.PathLike[str],
    *,
    workers: int = 4,
    quorum: int | None = None,
    accept_quorum: int | None = None,
    deadline: float | None = None,
) -> dict[str, int]:
    results = Path(results_dir)
    findings = results / "findings"
    findings.mkdir(parents=True, exist_ok=True)
    directories = [path for path in sorted(findings.glob("FIND-*")) if path.is_dir()]
    q = quorum or _positive_int_env("FIND_GATE_QUORUM", 2)
    aq = accept_quorum or _positive_int_env("FIND_GATE_ACCEPT_QUORUM", 2)
    timeout = _positive_int_env("LLM_DECISION_TIMEOUT", 300)
    counts = {"accepted": 0, "rejected": 0, "pending": 0}
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        statuses = pool.map(
            lambda directory: validate_one_finding(
                directory, results, quorum=q, accept_quorum=aq,
                timeout=timeout, deadline=deadline,
            ),
            directories,
        )
    for status in statuses:
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
    def render(report: Path) -> bool:
        succeeded = True
        if os.environ.get("ENRICH_REPORT_AUTO", "1") == "1":
            succeeded = _run_tool("enrich-report", "--quiet", str(report)) == 0
        return (
            _run_tool("render-md", str(report), "--html-sibling", "--title", report.parent.name) == 0
            and succeeded
        )
    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return all(pool.map(render, reports))


def maintain_indexes(
    results_dir: str | os.PathLike[str],
    target_root: str | os.PathLike[str] | None = None,
    *,
    workers: int = 4,
) -> bool:
    results = Path(results_dir)
    for name in ("crashes", "crashes-rejected", "findings", "findings-rejected"):
        (results / name).mkdir(parents=True, exist_ok=True)
    benchmark.write_rejected_crashes_index(results / "crashes-rejected")
    benchmark.write_rejected_findings_index(results / "findings-rejected")
    environment = os.environ.copy()
    if target_root:
        environment["TARGET_ROOT"] = str(target_root)
    succeeded = _run_tool("cluster-crashes", str(results), env=environment) == 0
    succeeded = _run_tool("cluster-findings", str(results), env=environment) == 0 and succeeded
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
    return succeeded
