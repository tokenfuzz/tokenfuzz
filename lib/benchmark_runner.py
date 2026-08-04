#!/usr/bin/env python3
"""Long-running benchmark orchestration.

The metric, pool, aggregation, and rendering algorithms live in benchmark.py;
this module owns process lifecycle and isolated benchmark cells.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

import audit_helpers
import benchmark as metrics
import benchmark_graph
import benchmark_model_direct_render
import build_lease
import build_preflight
import crash_artifacts
import crash_bundle
import llm_invoke
import llm_usage
import process_tree
import report_identity
import runner_preflight
import severity_receipt
import stack_frames
import target_config
import target_profile
import triage
import validation_receipt
from timeout import run_timeout

SCRIPT_ROOT = Path(__file__).resolve().parent.parent
SESSION_PAUSE_BACKSTOP = 21600
_RESULT_SIGNATURES: dict[str, str] = {}


def log(message: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] [benchmark] {message}", flush=True)


def format_duration(seconds: int) -> str:
    seconds = max(0, int(seconds or 0))
    return f"{seconds // 60}m{seconds % 60:02d}s ({seconds}s)"


@contextmanager
def _signal_cleanup():
    """Ensure terminating a benchmark also terminates backend descendants."""
    watched = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    previous = {sig: signal.getsignal(sig) for sig in watched}

    def stop(signum, _frame):
        process_tree.kill_descendants(os.getpid(), signal.SIGTERM, 1.0)
        raise SystemExit(128 + signum)

    for sig in watched:
        signal.signal(sig, stop)
    try:
        yield
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)


@contextmanager
def _decision_environment(
    backend: str, model: str, target: Path, target_slug: str,
    decision_log: Path | None = None,
    attacker_controls: str = "bytes",
    *,
    target_revision: str = "",
    target_config_sha256: str = "",
):
    values = {
        "ACTIVE_BACKEND": backend, "BACKEND": backend, "MODEL": model,
        "TARGET_ROOT": str(target), "TARGET_SLUG": target_slug,
        "TARGET_ATTACKER_CONTROLS_CSV": attacker_controls or "bytes",
        "TARGET_REV": target_revision,
        "TARGET_CONFIG_SHA256": target_config_sha256,
    }
    if decision_log is not None:
        values["LLM_DECIDE_LOG"] = str(decision_log)
    previous = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _find_gate_reset(path: Path) -> int | None:
    try:
        values = [int(line) for line in path.read_text().splitlines() if line.isdigit()]
    except OSError:
        return None
    return max(values) if values else 0


def _stamp_finalization_start(results: Path) -> None:
    """Record when the audit stopped and measurement began, once per cell."""
    marker = metrics._find_index_jsonl(results).parent / ".finalization_started"
    try:
        marker.parent.mkdir(parents=True, exist_ok=True)
        if not marker.is_file():
            marker.write_text(
                datetime.now(timezone.utc).isoformat(), encoding="utf-8",
            )
    except OSError:
        pass


def _finalize_deadline(finalize_wall: int) -> float | None:
    """Fresh ceiling for one finalization phase.

    Crash triage and the finding drain each call this so a slow crash pass
    cannot consume the finding gate's budget: a crash-heavy cell once spent
    ~57 of a 60-minute shared deadline on crashes and left every quality-
    accepted finding unadjudicated. Returns None when the phase is unbounded.
    """
    return time.monotonic() + finalize_wall if finalize_wall else None


# Repeat passes over a gate that still holds pending ids. Three is enough for
# the observed failure — a batch that answered for some ids and not others —
# without turning a genuinely stuck reviewer into an unbounded retry loop; the
# strictly-falling remainder below is what actually ends it.
_FIND_GATE_COMPLETION_PASSES = 3


def drain_find_gate(
    results: Path, backend: str, model: str, target: Path, target_slug: str,
    *, deadline: float | None = None, workers: int = 4,
) -> dict[str, int]:
    """Adjudicate a finished cell, pausing only for a confirmed provider cap."""
    import triage

    limit_file = results / ".find-gate-limit"
    try:
        max_pauses = max(0, int(os.environ.get("FIND_GATE_MAX_PAUSES", "12")))
        max_pause_total = max(0, int(os.environ.get("FIND_GATE_PAUSE_MAX_TOTAL", "21600")))
        pause_chunk = max(1, int(os.environ.get("FIND_GATE_PAUSE_CHUNK", "1800")))
    except ValueError:
        max_pauses, max_pause_total, pause_chunk = 12, 21600, 1800
    paused = 0
    counts = {"accepted": 0, "rejected": 0, "pending": 0}
    config = benchmark_target_config(results, target, target_slug)
    revision, config_digest = _evidence_scope(results, target, target_slug)
    with _decision_environment(
        backend, model, target, target_slug,
        attacker_controls=config.attacker_controls_csv(),
        target_revision=revision,
        target_config_sha256=config_digest,
    ):
        previous_limit = os.environ.get("LLM_DECIDE_LIMIT_FILE")
        os.environ["LLM_DECIDE_LIMIT_FILE"] = str(limit_file)

        def drain_once() -> dict[str, int]:
            nonlocal paused
            result = {"accepted": 0, "rejected": 0, "pending": 0}
            for attempt in range(max_pauses + 1):
                # The first pass must still enumerate expired findings so the
                # cell is marked incomplete; validate_find_gate's own deadline
                # check makes that bookkeeping pass spend no provider quota.
                if attempt and deadline is not None and time.monotonic() >= deadline:
                    break
                limit_file.write_text("", encoding="utf-8")
                result = triage.validate_find_gate(
                    results, deadline=deadline, target_root_is_product=True,
                    reject_missing_reports=True, finish_started_group=True,
                    workers=workers,
                )
                reset = _find_gate_reset(limit_file)
                if reset is None:
                    break
                if reset == 0 and limit_file.stat().st_size == 0:
                    break
                if attempt >= max_pauses or paused >= max_pause_total:
                    break
                now = int(time.time())
                wait = reset - now + 30 if reset and reset > now else pause_chunk
                wait = max(1, min(wait, max_pause_total - paused))
                if deadline is not None:
                    wait = min(wait, max(0, int(deadline - time.monotonic())))
                    if wait <= 0:
                        break
                log(f"Find-gate provider limit: pausing {wait}s before retry")
                time.sleep(wait)
                paused += wait
            return result

        try:
            counts = drain_once()
            # A review batch that returns no keyed output leaves its ids
            # pending, and the pass ends with them unadjudicated even on an
            # unlimited wall — so an unbounded budget alone does not finish the
            # gate. Cached receipts make a repeat pass pay only for what is
            # still missing, so retry while the remainder actually falls. A
            # pass that converges, stalls, or runs past the ceiling ends the
            # drain instead of looping on a stuck id.
            for _ in range(_FIND_GATE_COMPLETION_PASSES):
                if not counts.get("pending"):
                    break
                if deadline is not None and time.monotonic() >= deadline:
                    break
                before = counts["pending"]
                counts = drain_once()
                if counts.get("pending", 0) >= before:
                    break
        finally:
            if previous_limit is None:
                os.environ.pop("LLM_DECIDE_LIMIT_FILE", None)
            else:
                os.environ["LLM_DECIDE_LIMIT_FILE"] = previous_limit
            limit_file.unlink(missing_ok=True)
    if paused:
        counts["paused_seconds"] = paused
    return counts


def _benchmark_target_config_path(
    results: Path, target: Path, target_slug: str,
) -> Path | None:
    """The immutable config nearest this result, then the live fallback."""
    resolved_results = results.resolve()
    directories = (resolved_results, *resolved_results.parents)
    for directory in directories:
        if (directory / "run.json").is_file():
            snapshot = directory / "target.toml"
            if snapshot.is_file():
                return snapshot
            break
    if any(directory.name == "output" for directory in directories):
        config_path = metrics._find_output_target_toml(results)
        if config_path is not None:
            return config_path
    canonical = SCRIPT_ROOT / "output" / target_slug / "target.toml"
    if canonical.is_file():
        return canonical
    target_config_path = target / "target.toml"
    return target_config_path if target_config_path.is_file() else None


def benchmark_target_config(
    results: Path, target: Path, target_slug: str,
) -> target_config.Config:
    """Load the benchmark target through the same target.toml channel as audit."""
    config = target_config.Config(
        slug=target_slug,
        target_root=str(target),
        attacker_controls=["bytes"],
        sanitizers_enabled=["asan"],
    )
    # A benchmark run owns an immutable snapshot above its cells (and harness
    # facades copy it into their output tree). Prefer that nearest contract;
    # the live canonical config may change while a long run is still active.
    config_path = _benchmark_target_config_path(results, target, target_slug)
    if config_path is not None:
        target_config.load_toml_into(config, config_path)
    return config


def _evidence_scope(
    results: Path, target: Path, target_slug: str,
) -> tuple[str, str]:
    """Return the audited revision and immutable config digest for receipts."""
    revision = target_config.find_benchmark_target_rev(results, target_slug)
    config_path = _benchmark_target_config_path(results, target, target_slug)
    try:
        config_digest = (
            hashlib.sha256(config_path.read_bytes()).hexdigest()
            if config_path is not None else ""
        )
    except OSError:
        config_digest = ""
    return revision, config_digest


# Why a direct-condition crash lost its promotion. "unmeasured" is distinct
# from "no-contract" because the replay did launch: the missing measurement
# points at the run, not at the crash's evidence.
_REPLAY_DEMOTION_REASONS = {
    "clean": "sanitizer evidence did not reproduce through the configured target invocation",
    "unmeasured": "configured-target replay produced no measurement of the original fault (see .audit/reverify.log)",
    "no-contract": "sanitizer evidence has no executable configured-target replay contract",
}


def triage_cell_crashes(
    results: Path, target: Path, target_slug: str, *, workers: int = 4,
    deadline: float | None = None,
    require_replay: bool = False,
    age_pending: bool = True,
) -> dict[str, int]:
    """Apply the audit crash gate to a finished benchmark cell."""
    nested_crashes = results / "session" / "results" / "crashes"
    if nested_crashes.is_dir():
        sources = [path for path in nested_crashes.iterdir() if path.is_dir()]
        for destination in (results / "crashes").iterdir():
            if not destination.is_dir() or crash_bundle.verified_probe_context(destination) is not None:
                continue
            crash_bundle.restore_probe_context(sources, destination)
    config = benchmark_target_config(results, target, target_slug)
    bypasses: set[Path] = set()
    pre_demoted = 0
    if require_replay:
        candidates = sorted((results / "crashes").glob("CRASH-*"))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(2, len(candidates) or 1)
        ) as executor:
            futures = {
                crash_dir: executor.submit(
                    _verify_model_direct_crash,
                    crash_dir, target, target_slug, config.attacker_controls,
                )
                for crash_dir in candidates
            }
            replay_results: dict[Path, str] = {}
            for crash_dir in candidates:
                try:
                    replay_results[crash_dir] = futures[crash_dir].result()
                except (OSError, subprocess.SubprocessError, ValueError):
                    replay_results[crash_dir] = "no-contract"
        for crash_dir in candidates:
            status = replay_results[crash_dir]
            if status == "bypass":
                bypasses.add(crash_dir)
                continue
            if status == "reproduced":
                continue
            triage.demote_to_finding(
                crash_dir, results, _REPLAY_DEMOTION_REASONS[status]
            )
            pre_demoted += 1
    counts = triage.triage_crash_dirs(
        results, target, target_slug, config.attacker_controls,
        workers=max(1, workers),
        findings_only=config.sanitizers_explicitly_disabled,
        deadline=deadline,
        target_root_is_product=True,
        confirmed_trigger_bypasses=bypasses,
        age_pending=age_pending,
    )
    counts["demoted"] = counts.get("demoted", 0) + pre_demoted
    return counts


def _verify_model_direct_crash(
    crash_dir: Path, target: Path, target_slug: str,
    attacker_controls: list[str],
) -> str:
    """Return bypass/reproduced/clean/unmeasured/no-contract for one crash."""
    controls = {str(value).strip().lower() for value in attacker_controls}
    if triage._direct_probe_trigger_bypass(crash_dir, target, attacker_controls):
        return "bypass"
    resolved = _resolve_reverify_fields(crash_dir, target, target_slug)
    if resolved is None:
        return "no-contract"
    fields, replay_args = resolved
    if not reverify_one_crash(crash_dir, target, target_slug):
        return "unmeasured"
    rate = _measured_crash_rate(crash_dir / "sanitizer.txt")
    if rate is None or rate[0] == 0:
        return "clean"
    standard = False
    try:
        binary = Path(fields.get("BIN", "")).resolve(strict=True)
        root = target.resolve(strict=True)
        standard = (
            fields.get("MODE") in {"generic", "cli"}
            and not replay_args
            and (binary == root or root in binary.parents)
        )
    except (OSError, TypeError):
        pass
    if (
        standard and rate == (5, 5) and "bytes" in controls
        and triage._fault_frame_is_in_target(
            (crash_dir / "sanitizer.txt").read_text(
                encoding="utf-8", errors="replace"
            ), root,
        )
    ):
        return "bypass"
    return "reproduced"


def target_key(raw: str) -> str:
    if raw and all(ch.isalnum() or ch in "._-" for ch in raw):
        return raw
    safe = "-".join(filter(None, __import__("re").split(r"[^a-z0-9._-]+", raw.lower()))).strip("-")
    return f"{safe or 'target'}-{hashlib.sha1(raw.encode()).hexdigest()[:8]}"


def _positive(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def _nonnegative(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a non-negative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="benchmark")
    result.add_argument("--target", default="")
    result.add_argument("--backend", default="codex", choices=("claude", "codex", "gemini", "grok", "oss"))
    result.add_argument("--model", default="")
    result.add_argument("--replicates", type=_positive, default=3)
    result.add_argument(
        "--budget-wall", type=_nonnegative, default=10800,
        help=(
            "active audit wall seconds per cell, including housekeeping; "
            "provider-recovery pauses are excluded (0 = unlimited)"
        ),
    )
    result.add_argument(
        "--finalize-wall", type=_nonnegative, default=0,
        help="wall-clock ceiling per final validation phase; crash triage and the "
             "finding drain each get their own budget (0 = unlimited, the default)",
    )
    result.add_argument(
        "--finalize-workers", type=_positive, default=4,
        help="concurrent reviewers per final validation phase; independent of "
             "--agents, which sizes the audit itself. Also scales the find "
             "gate's admission groups, so raising it coarsens where a finite "
             "--finalize-wall can cut",
    )
    result.add_argument("--agents", type=_positive)
    result.add_argument("--conditions", default="model-direct,harness")
    result.add_argument("--ledger")
    result.add_argument("--bench-root", default="output/benchmark")
    result.add_argument("--run-id", default="")
    result.add_argument("--reset", action="store_true")
    result.add_argument("--hard", action="store_true")
    result.add_argument("--regenerate", action="store_true")
    result.add_argument("--dry-run", action="store_true")
    result.add_argument(
        "--isolate-build", action="store_true",
        help="build into a private tree keyed by build inputs, instead of "
             "sharing the target's canonical build with concurrent runs",
    )
    validation = result.add_mutually_exclusive_group()
    validation.add_argument("--no-validate-findings", dest="validate_findings", action="store_false")
    validation.add_argument("--validate-findings", dest="validate_findings", action="store_true")
    result.set_defaults(validate_findings=os.environ.get("BENCHMARK_VALIDATE_FINDINGS", "1") != "0")
    return result


class Tee:
    def __init__(self, *streams):
        self.streams = streams

    def write(self, value: str) -> int:
        for stream in self.streams:
            stream.write(value)
            stream.flush()
        return len(value)

    def flush(self) -> None:
        for stream in self.streams:
            stream.flush()


class BenchmarkLock:
    def __init__(self, path: Path):
        self.path = path
        self.owned = False

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            try:
                owner = int(self.path.read_text(encoding="utf-8").split()[0])
                os.kill(owner, 0)
            except (OSError, ValueError, IndexError):
                self.path.unlink(missing_ok=True)
                return self.__enter__()
            run_id = self.path.stem.removeprefix(".run-")
            raise RuntimeError(
                f"benchmark run {run_id} for backend={self.path.parent.name} "
                f"is already running (pid {owner})"
            )
        os.write(fd, f"{os.getpid()} {datetime.now(timezone.utc).isoformat()}\n".encode())
        os.close(fd)
        self.owned = True
        return self

    def __exit__(self, *_):
        if self.owned:
            self.path.unlink(missing_ok=True)


def _git_rev(path: Path, short: bool = False) -> str:
    command = ["git", "-c", f"safe.directory={path}", "-C", str(path), "rev-parse"]
    if short:
        command.append("--short")
    command.append("HEAD")
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False)
    return result.stdout.strip() if result.returncode == 0 else "no-vcs"


def _is_shallow_checkout(path: Path) -> bool:
    result = subprocess.run(
        ["git", "-c", f"safe.directory={path}", "-C", str(path), "rev-parse", "--is-shallow-repository"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    return result.returncode == 0 and result.stdout.strip() == "true"


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2)
            stream.write("\n")
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_cell(
    path: Path, condition: str, replicate: int, experiment: str,
    results_dir: Path, wall: int, status: str, requested_agents: int | None,
    paused: int = 0, started_at: str = "", housekeeping: int = 0,
    build_identity: dict | None = None,
) -> None:
    # Source/build drift and unowned evidence leave the headline comparison, so
    # their persistent reason must survive into the cell record.
    quality = metrics.cell_run_quality(path.parent, status)
    drift: dict = {}
    try:
        drift = json.loads((path.parent / "source-drift.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    payload = {
        "condition": condition, "replicate": replicate, "experiment": experiment,
        "results_dir": str(results_dir), "wall_seconds": wall, "status": status,
        "run_quality": quality, "paused_seconds": paused,
        "housekeeping_seconds": housekeeping,
        "wall_effective_seconds": max(0, wall - paused),
        # When the cell began. Reports that place a result on a timeline need an
        # origin; without one they rebase onto their own first artifact and put
        # hour zero wherever that landed. model-direct keeps no audit log, so
        # this is the only origin it has.
        "started_at": started_at,
    }
    if requested_agents is not None:
        payload["requested_agents"] = requested_agents
    if drift:
        payload["source_drift"] = drift
    if build_identity is None:
        try:
            previous = json.loads(path.read_text(encoding="utf-8"))
            build_identity = previous.get("build_identity")
        except (OSError, ValueError):
            build_identity = None
    if build_identity:
        payload["build_identity"] = build_identity
    try:
        config = json.loads((results_dir / "state" / "run-config.json").read_text(encoding="utf-8"))
        actual = config.get("num_agents")
        if isinstance(actual, int) and actual > 0:
            payload["actual_agents"] = actual
            if requested_agents is not None and actual != requested_agents:
                payload["agent_count_mismatch"] = True
    except (OSError, ValueError):
        pass
    _write_json(path, payload)


def _benchmark_config(
    target: Path, target_slug: str, config_path: Path | None = None,
) -> target_config.Config:
    """Load the exact target configuration a benchmark run executes."""
    config = target_config.Config(target_root=str(target))
    if config_path is None:
        config_path = SCRIPT_ROOT / "output" / target_slug / "target.toml"
        if not config_path.is_file():
            config_path = target / "target.toml"
    target_config.load_toml_into(config, config_path)
    return config


def _target_build_identity(
    target: Path, target_slug: str, config: target_config.Config | None = None,
) -> dict:
    """Content identity of the target artifacts a benchmark replay can execute."""
    if config is None:
        try:
            config = _benchmark_config(target, target_slug)
        except (OSError, ValueError):
            return {}
    return build_preflight.build_identity(target, config)


def _replay_artifact_keys(
    crash_dirs: list[Path],
    config: target_config.Config | None,
    recorded: dict,
) -> set[str]:
    """Target-owned files replaying this saved evidence will execute."""
    keys: set[str] = set()
    for crash_dir in crash_dirs:
        sanitizer = crash_artifacts.crash_sanitizer(crash_dir)
        if crash_artifacts.crash_harness_binary(crash_dir) is not None:
            key = f"{sanitizer}-lib"
            artifact = recorded.get("artifacts", {}).get(key)
            recorded_path = (
                artifact.get("path", "") if isinstance(artifact, dict) else ""
            )
            current_path = (
                config.sanitizer_lib(sanitizer) if config is not None else ""
            )
            if any(
                raw and target_config._is_shared_lib(Path(raw).name)
                for raw in (recorded_path, current_path)
            ):
                keys.add(key)
            continue
        runner_selected = (
            config is not None
            and bool(config.runner_bin)
            and not config.sanitizer_bin(sanitizer)
        )
        runner_key = "runner-bin"
        if (sanitizer in {"race", "runner"} or runner_selected) and (
            runner_key in recorded.get("artifacts", {})
            or runner_selected
        ):
            keys.add(runner_key)
            continue
        key = f"{sanitizer}-bin"
        if key in recorded.get("artifacts", {}) or \
                config is not None and config.sanitizer_bin(sanitizer):
            keys.add(key)
        else:
            keys.add("asan-bin")
    return keys


def _source_drift(target: Path, baseline: str) -> dict:
    """Describe persistent tracked-source drift at a cell boundary."""
    if not baseline:
        return {}
    current = target_config.vcs_source_signature(
        target, include_untracked=False,
    )
    if not current or current == baseline:
        return {}
    return {
        "observed_at": datetime.now(timezone.utc).isoformat(),
        "paths": target_config.source_changed_paths(
            target, include_untracked=False,
        ),
    }


def _cell_build_identity(cell: dict) -> dict:
    recorded = cell.get("build_identity")
    return recorded if isinstance(recorded, dict) else {}


def _mark_build_finalization_incomplete(cell: dict, reason: str) -> None:
    """Record that a cell's replay build could not be verified.

    A cell that failed, or one a provider cut short, keeps that status: a later
    regeneration promotes `incomplete` back to `done` once the build matches
    again, which would launder those into the aggregate they are excluded from.
    """
    if cell.get("status") != "failed":
        cell["status"] = "incomplete"
    if cell.get("run_quality") == "clean":
        cell["run_quality"] = "incomplete"
    cell["build_finalization_error"] = reason


def _replay_build_status(
    cell: dict, results: Path, target: Path, target_slug: str,
    config: target_config.Config | None = None,
) -> tuple[bool, str]:
    if config is None:
        try:
            config = _benchmark_config(target, target_slug)
        except (OSError, ValueError):
            config = None
    recorded = _cell_build_identity(cell)
    crash_dirs = sorted((results / "crashes").glob("CRASH-*"))
    keys = _replay_artifact_keys(crash_dirs, config, recorded)
    problems = build_preflight.pinned_build_problems(
        target, recorded, config, keys,
    )
    return not problems, "; ".join(problems)


def dryrun_cell(cell_dir: Path, condition: str, replicate: int, backend: str) -> Path:
    results = cell_dir / "results"
    good = results / "crashes" / "CRASH-001"
    decoy = results / "crashes" / "CRASH-002"
    (results / "logs").mkdir(parents=True, exist_ok=True)
    good.mkdir(parents=True, exist_ok=True)
    decoy.mkdir(parents=True, exist_ok=True)
    if condition == "harness":
        (good / "sanitizer.txt").write_text(
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on 0x602\n"
            "    #0 0x55 in dryrun_sink /src/dry.c:42:5\n"
            "    #1 0x66 in dryrun_caller /src/dry.c:99:1\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow\n",
            encoding="utf-8",
        )
    (decoy / "notes.txt").write_text("this directory has no sanitizer output\n", encoding="utf-8")
    (results / "logs" / "index.jsonl").write_text(
        json.dumps({
            "backend": backend,
            "resolved_effort": llm_invoke.default_effort(backend),
            "tokens": {"input": 1000, "cached_input": 900, "output": replicate * 100},
            "probe": {"asan_invocations": 3},
        }) + "\n",
        encoding="utf-8",
    )
    return results


def mark_target_artifacts(target: Path) -> set[Path]:
    marked: set[Path] = set()
    if not target.is_dir():
        return marked
    for parent_name, glob in (("findings", "FIND-*"), ("crashes", "CRASH-*")):
        for parent in target.rglob(parent_name):
            if ".git" in parent.parts or not parent.is_dir():
                continue
            marked.update(entry.resolve() for entry in parent.glob(glob))
    return marked


@contextmanager
def _target_artifact_guard(target: Path, cell_dir: Path):
    """Exclude a cell that writes unowned evidence into the shared target.

    A target-tree FIND/CRASH carries no run id, so moving it into this cell is
    unsafe whenever peer benchmarks share the checkout. Leave it untouched and
    count only evidence written through the cell's RESULTS_DIR contract.
    """
    marked = mark_target_artifacts(target)
    try:
        yield
    finally:
        leaked = mark_target_artifacts(target) - marked
        if leaked:
            (cell_dir / ".target-artifacts-unowned").touch()
            (cell_dir / ".run-quality").write_text(
                "unowned_artifacts\n", encoding="utf-8",
            )
            resolved_target = target.resolve()
            names = ", ".join(
                str(path.relative_to(resolved_target))
                for path in sorted(leaked)[:5]
            )
            log(
                f"WARN: Cell {cell_dir.name}: target-tree artifacts have no "
                f"benchmark owner ({names}); evidence left in place and this cell "
                "excluded from the comparison"
            )


def cleanup_model_direct_scratch(cell_dir: Path) -> None:
    scratch = cell_dir / "scratch"
    if not scratch.is_dir():
        return
    count = sum(1 for path in scratch.rglob("*") if path.is_file())
    shutil.rmtree(scratch, ignore_errors=True)
    log(f"Cell {cell_dir.name}: reclaimed scratch/ ({count} file(s))")


def _provider_issue(cell_dir: Path) -> str:
    quota_marker = cell_dir / ".quota-exhausted"
    if quota_marker.is_file():
        return "capacity_limited"
    saw_transient = False
    candidates = [cell_dir / "backend.raw.log", cell_dir / "audit.log"]
    candidates.extend((cell_dir / "repo-root" / "output").glob("**/logs/.raw/session_*.log.raw"))
    candidates.extend((cell_dir / "repo-root" / "output").glob("**/logs/.raw/model-preflight-*.raw"))
    candidates.extend((cell_dir / "repo-root" / "output").glob("**/logs/index.log"))
    for path in candidates:
        try:
            with path.open(encoding="utf-8", errors="replace") as stream:
                issue = audit_helpers._provider_issue_from_lines(stream)
        except OSError:
            continue
        if issue == "capacity_limited":
            return issue
        saw_transient |= issue == "transient"
    return "transient" if saw_transient else "none"


def _has_artifacts(results: Path) -> bool:
    return any(path.is_dir() for root in (results / "crashes", results / "findings") if root.is_dir() for path in root.iterdir())


def _record_provider_quality(cell_dir: Path, results: Path, rc: int = 1) -> str:
    """Persist provider quality, letting conclusive capacity evidence outrank rc."""
    if (cell_dir / ".backend-unavailable").is_file():
        (cell_dir / ".run-quality").write_text("provider_limited\n", encoding="utf-8")
        return "capacity_limited"
    issue = _provider_issue(cell_dir)
    if issue == "none":
        return issue
    existing = ""
    try:
        existing = (cell_dir / ".run-quality").read_text(encoding="utf-8").strip()
    except OSError:
        pass
    (cell_dir / ".run-quality").write_text(
        (existing if existing in {"provider_recovered", "normal"} else "provider_recovered") + "\n",
        encoding="utf-8",
    )
    if issue == "capacity_limited" and rc not in (0, 124) and not _has_artifacts(results):
        (cell_dir / ".backend-unavailable").touch()
        (cell_dir / ".run-quality").write_text("provider_limited\n", encoding="utf-8")
    return issue


def _reap_cell_processes(marker: str) -> None:
    """Kill fuzzers a completed cell left behind.

    The cell command runs under a setsid'd timeout wrapper that reaps its own
    session group, but bin/audit gives each agent a nested wrapper in a *new*
    session, so a leak there survives the outer group kill. Every cell process
    inherits this cell's reap marker, so reaping by marker catches those
    regardless of session, parent, or command line, and can never touch a
    concurrent sibling cell or an unrelated process.
    """
    reaped = process_tree.kill_marked(marker)
    if reaped:
        print(
            f"reaped {len(reaped)} leaked cell process(es): "
            + " ".join(str(pid) for pid in reaped),
            file=sys.stderr, flush=True,
        )


def run_model_direct(
    cell_dir: Path,
    target: Path,
    backend: str,
    model: str,
    wall: int,
    config_snapshot: Path | None = None,
) -> int:
    for name in ("crashes", "findings", "logs"):
        (cell_dir / name).mkdir(parents=True, exist_ok=True)
    prompt = benchmark_model_direct_render.render(
        str(target), str(cell_dir), str(SCRIPT_ROOT), wall,
        str(config_snapshot) if config_snapshot is not None else "",
    )
    (cell_dir / "prompt.txt").write_text(prompt, encoding="utf-8")
    raw = cell_dir / "backend.raw.log"
    for marker in (".quota-exhausted", ".backend-unavailable", ".run-quality"):
        (cell_dir / marker).unlink(missing_ok=True)
    previous_logdir = os.environ.get("LOGDIR")
    os.environ["LOGDIR"] = str(cell_dir / "logs")
    # Marker goes into the child's environment only, never this process's, so
    # the reap can never turn on the orchestrator itself.
    reap_marker = process_tree.new_marker()
    with _target_artifact_guard(target, cell_dir):
        try:
            rc = llm_invoke.run_agent_prompt(
                backend, prompt, wall, raw, model=model, max_turns=0,
                add_dirs=f"{cell_dir},{target}", cwd=cell_dir,
                watchdog_marker_dir=cell_dir,
                allow_subagents=False,
                extra_env={process_tree.REAP_MARKER_VAR: reap_marker},
            )
        finally:
            if previous_logdir is None:
                os.environ.pop("LOGDIR", None)
            else:
                os.environ["LOGDIR"] = previous_logdir
            _reap_cell_processes(reap_marker)
    usage = subprocess.run(
        [
            sys.executable, str(SCRIPT_ROOT / "lib" / "llm_usage.py"),
            "extract-usage", backend, str(raw), str(cell_dir / "prompt.txt"),
        ],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    try:
        usage_event = json.loads(usage.stdout or "{}")
    except ValueError:
        usage_event = {}
    usage_event["resolved_effort"] = llm_invoke.default_effort(backend)
    usage_event["usage_complete"] = llm_usage.usage_is_complete(usage_event, rc)
    (cell_dir / "logs" / "index.jsonl").write_text(
        json.dumps(usage_event, separators=(",", ":")) + "\n", encoding="utf-8"
    )
    issue = _record_provider_quality(cell_dir, cell_dir, rc)
    if issue == "capacity_limited" and (cell_dir / ".backend-unavailable").is_file():
        return 0
    if backend == "gemini" and not raw.stat().st_size and not _has_artifacts(cell_dir):
        return 44
    return 0 if rc in (0, 124) else rc


def prepare_facade(
    cell_dir: Path, target_slug: str, config_snapshot: Path | None = None,
) -> Path:
    facade = cell_dir / "repo-root"
    shutil.rmtree(facade, ignore_errors=True)
    facade.mkdir(parents=True)
    for name in ("bin", "lib", ".agents", "docs", "schema", "targets"):
        (facade / name).symlink_to(SCRIPT_ROOT / name, target_is_directory=True)
    config_dir = facade / "output" / target_slug
    config_dir.mkdir(parents=True)
    source_config = (
        config_snapshot
        if config_snapshot is not None
        else SCRIPT_ROOT / "output" / target_slug / "target.toml"
    )
    if source_config.is_file():
        shutil.copy2(source_config, config_dir / "target.toml")
    for name in ("AGENTS.md", "CHANGELOG.md", "LICENSE", "README.md", "SECURITY.md", "requirements.txt", ".gitignore"):
        source = SCRIPT_ROOT / name
        if source.exists():
            (facade / name).symlink_to(source)
    return facade


def run_harness(
    cell_dir: Path, target_slug: str, backend: str, model: str,
    experiment: str, wall: int, agents: int | None, build_identity: dict,
    config_snapshot: Path | None = None,
) -> tuple[int, Path]:
    facade = prepare_facade(cell_dir, target_slug, config_snapshot)
    target = (SCRIPT_ROOT / "targets" / target_slug).resolve()
    result_dir = facade / "output" / f"{target_slug}-{experiment}" / backend / "results"
    command = [
        str(facade / "bin" / "audit"), "--target", target_slug,
        "--backend", backend,
    ]
    if model:
        command += ["--model", model]
    command += ["--experiment", experiment]
    reap_marker = process_tree.new_marker()
    environment = os.environ.copy()
    environment.update({
        "SCRIPT_ROOT": str(facade),
        # Benchmark cells must differ by the tested condition/backend, not by
        # whichever backend happened to synthesize a widened build recipe.
        "_TOKENFUZZ_BENCHMARK_PRIMARY_BUILD": "1",
        build_preflight.BENCHMARK_BUILD_PIN_ENV:
            build_preflight.encode_benchmark_build_pin(build_identity),
        "PROBE_AUTO_ROUTE": "0",
        # Inherited by every cell process; see _reap_cell_processes.
        process_tree.REAP_MARKER_VAR: reap_marker,
    })
    if agents is not None:
        environment["NUM_AGENTS"] = str(agents)
    if wall:
        environment["AUDIT_WALL_BUDGET_SECS"] = str(wall)
    with _target_artifact_guard(target, cell_dir):
        with (cell_dir / "audit.log").open("w", encoding="utf-8") as stream:
            try:
                if wall:
                    rc = run_timeout(
                        command, wall + SESSION_PAUSE_BACKSTOP, cwd=facade,
                        env=environment, stdout=stream, stderr=subprocess.STDOUT,
                    ).returncode
                else:
                    rc = subprocess.run(command, cwd=facade, env=environment, stdout=stream, stderr=subprocess.STDOUT, check=False).returncode
            finally:
                # Reap escaped cell processes even if the launch raised
                # (OSError, timeout-helper failure) — the leak this guards
                # against is exactly what an abnormal exit leaves behind.
                _reap_cell_processes(reap_marker)
        result_dir.mkdir(parents=True, exist_ok=True)
    logs = result_dir.parent / "logs"
    for marker in (".run-quality", ".backend-unavailable"):
        source = logs / marker
        if source.exists():
            shutil.copy2(source, cell_dir / marker)
    # This also catches a provider-limited startup/preflight before the audit
    # runtime had a chance to create its own marker.
    _record_provider_quality(cell_dir, result_dir, rc)
    return (0 if rc == 124 else rc), result_dir


def _run_tool(name: str, *args: str, env: dict | None = None, stdout=None) -> int:
    command = [str(SCRIPT_ROOT / "bin" / name), *map(str, args)]
    return subprocess.run(command, env=env, stdout=stdout or subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode


def _resolve_reverify_fields(
    crash_dir: Path, target_root: Path, target_slug: str,
) -> tuple[dict[str, str], list[str]] | None:
    command = [
        sys.executable, str(SCRIPT_ROOT / "lib" / "benchmark.py"),
        "resolve-reverify", str(crash_dir), str(target_root), target_slug,
    ]
    config_path = _benchmark_target_config_path(
        crash_dir.parent.parent, target_root, target_slug,
    )
    if config_path is not None:
        command.extend(["--target-toml", str(config_path)])
    resolved = subprocess.run(
        command,
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    if resolved.returncode:
        return None
    fields: dict[str, str] = {}
    replay_args: list[str] = []
    for line in resolved.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator:
            continue
        if key == "ARG":
            replay_args.append(value)
        else:
            fields[key] = value
    mode = fields.get("MODE", "none")
    binary = fields.get("BIN", "")
    if mode == "none" or not binary:
        return None
    return fields, replay_args


def _write_reverify_log(crash_dir: Path, measured: str) -> None:
    """Keep an unmeasurable replay's output for diagnosis; never fatal."""
    try:
        audit_dir = crash_dir / ".audit"
        audit_dir.mkdir(parents=True, exist_ok=True)
        (audit_dir / "reverify.log").write_text(
            measured or "replay produced no output\n", encoding="utf-8",
        )
    except OSError:
        pass


def reverify_one_crash(crash_dir: Path, target_root: Path, target_slug: str) -> bool:
    resolved = _resolve_reverify_fields(crash_dir, target_root, target_slug)
    if resolved is None:
        return False
    fields, replay_args = resolved
    mode = fields.get("MODE", "none")
    binary = fields.get("BIN", "")
    testcase = fields.get("TESTCASE", "")
    sanitizer_name = fields.get("SAN", "asan")
    try:
        original = (crash_dir / "sanitizer.txt").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        original = ""
    temporary = crash_dir / "sanitizer.txt.reverify.tmp"
    temporary.unlink(missing_ok=True)
    environment = os.environ.copy()
    upper = "ASAN" if sanitizer_name in {"race", "runner"} else sanitizer_name.upper()
    environment.update({
        "SANITIZER_RUNS": "5", "SAN_OUTPUT_FILE": str(temporary),
        f"{upper}_GENERIC_BIN": binary,
    })
    for key, entry in fields.items():
        if not key.startswith("ENV_") or "=" not in entry:
            continue
        name, value = entry.split("=", 1)
        environment[name] = value
    # The options the crash was found under are part of how it was found —
    # allocator shaping decides whether some faults surface at all — and the
    # runner header recorded them. The runners append the environment after
    # their own defaults, and a sanitizer runtime takes the last duplicate key.
    for option_name in (
        "ASAN_OPTIONS", "UBSAN_OPTIONS", "MSAN_OPTIONS", "TSAN_OPTIONS",
    ):
        environment.pop(option_name, None)
    try:
        recorded_options = crash_artifacts.recorded_sanitizer_options(original)
    except ValueError as exc:
        _write_reverify_log(crash_dir, f"recorded sanitizer options are unusable: {exc}\n")
        return False
    if recorded_options is not None:
        environment[f"{upper}_OPTIONS"] = recorded_options
    arguments = [testcase, *replay_args] if replay_args else [testcase]
    if mode == "harness":
        # The harness carries its own input, and keeps the sanitizer it was
        # built with: under the ASan wrapper a UBSan harness never gets
        # UBSAN_OPTIONS, so halt_on_error is unset and a real crash exits 0.
        # Both skip flags, because bin/run-asan reads only its own.
        arguments = ["/dev/null"]
        environment.update({
            "ASAN_GENERIC_SKIP_TESTCASE": "1", "SANITIZER_GENERIC_SKIP_TESTCASE": "1",
        })
        # An agent-compiled harness carries no rpath, so it dies in the loader
        # before main() and its crash looks unmeasurable. Supply the directory
        # bin/probe would have baked in. Harness mode only: a configured target
        # binary is launched the way the target itself is, and overriding the
        # loader path there could change which library a clean run resolves.
        # Guard the empty string too — Path("") is the working directory.
        library_dir = fields.get("LIBDIR", "")
        if library_dir and Path(library_dir).is_dir():
            for variable in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
                existing = environment.get(variable, "")
                environment[variable] = (
                    f"{library_dir}{os.pathsep}{existing}" if existing else library_dir
                )
    elif replay_args:
        environment.update({"ASAN_GENERIC_SKIP_TESTCASE": "1", "SANITIZER_GENERIC_SKIP_TESTCASE": "1"})
    subprocess.run(
        [str(SCRIPT_ROOT / "bin" / "run-sanitizer-multi"), sanitizer_name, "generic", *arguments],
        env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    try:
        measured = temporary.read_text(encoding="utf-8", errors="replace")
    except OSError:
        measured = ""
    finally:
        temporary.unlink(missing_ok=True)
    rate_match = re.search(r"^CRASH_RATE:\s*([0-9]+)/([0-9]+)", measured, re.MULTILINE)
    crashes = int(rate_match.group(1)) if rate_match else 0
    runs = int(rate_match.group(2)) if rate_match else 0
    success_match = re.search(r"^\[run-sanitizer-multi\]\s+SUCCESS_RATE:\s*([0-9]+/[0-9]+)", measured, re.MULTILINE)
    clean_runs = int(success_match.group(1).split("/", 1)[0]) if success_match else 0
    if not rate_match or (crashes == 0 and clean_runs == 0):
        # Nothing ran to completion: no summary at all, or a rate with neither
        # a crash nor a clean exit behind it (a loader or exec failure). Keep
        # the output so the demotion is diagnosable without re-running the cell.
        _write_reverify_log(crash_dir, measured)
        return False
    if crashes:
        crashes = _runs_reproducing(original, measured)
        if (
            not crashes
            or triage.autodiscard_reason(measured)
            or not triage._has_memory_safety_signal(measured)
        ):
            # The replay crashed, but not with the original's fault. Nothing
            # here confirms the crash, so it demotes like an unmeasured one —
            # and the operator needs the output to see which it was.
            _write_reverify_log(crash_dir, measured)
            return False
    rate = f"{crashes}/{runs}"
    note = (
        f"reproduced in {rate} reverification runs" if crashes
        else f"original one-shot trace did not reproduce in {runs} reverification runs"
    )
    with (crash_dir / "sanitizer.txt").open("a", encoding="utf-8") as output:
        output.write(f"\nCRASH_RATE: {rate}\n[run-sanitizer-multi] REVERIFY: {rate} - {note}\n")
    return True


_REPLAY_RUN_SPLIT_RE = re.compile(r"^=== Run [0-9]+/[0-9]+ ===$", re.MULTILINE)


def _source_location(location: str) -> tuple[str, int | None]:
    """Normalize a source location while retaining its faulting line."""
    parts = location.rsplit(":", 2)
    if len(parts) >= 2 and parts[-1].isdigit():
        if len(parts) == 3 and parts[-2].isdigit():
            return parts[0].replace("\\", "/"), int(parts[-2])
        return ":".join(parts[:-1]).replace("\\", "/"), int(parts[-1])
    return location.replace("\\", "/"), None


def _fault_site(text: str) -> tuple[str, str, int | None] | None:
    """The normalized function, path, and line of the reported fault."""
    frame = stack_frames.first_interesting_frame(text)
    if frame is None:
        return None
    path, line = _source_location(frame.location)
    return frame.state_function, path, line


def _same_source_path(left: str, right: str) -> bool:
    """Compare paths after pooling may have removed one workspace prefix."""
    left = left.rstrip("/")
    right = right.rstrip("/")
    return (
        left == right
        or bool(left and right and left.endswith(f"/{right.lstrip('/')}"))
        or bool(left and right and right.endswith(f"/{left.lstrip('/')}"))
    )


def _same_fault(
    key: tuple[str, str],
    site: tuple[str, str, int | None] | None,
    text: str,
) -> bool:
    """Whether `text` reports the fault `key` and `site` describe.

    Sanitizer family and primitive, plus the faulting site when both sides name
    one: two unrelated heap-buffer-overflows in one binary share a primitive,
    and counting either as the other's reproduction confirms the wrong bug at
    the wrong rate. Where a side has no parseable frame the primitive stands
    alone rather than rejecting a real reproduction.
    """
    if crash_artifacts.sanitizer_fault_key(text) != key:
        return False
    measured_site = _fault_site(text)
    if site is None or measured_site is None:
        return True
    function, path, line = site
    measured_function, measured_path, measured_line = measured_site
    if function != measured_function:
        return False
    if line is None or measured_line is None:
        # A frame with no source line carries a module offset or a bare symbol,
        # which names no bug. Whether a symbolizer was on PATH is a property of
        # the host at replay time, not of the fault, so a replay that could not
        # symbolize must read as the same crash rather than a different one.
        return True
    return line == measured_line and _same_source_path(path, measured_path)


def _runs_reproducing(original: str, measured: str) -> int:
    """How many replay runs carry the original's fault, not merely some crash.

    run-sanitizer-multi concatenates every repetition into one transcript, so a
    rate read off the whole of it counts a run that faulted somewhere else as a
    reproduction, and rejects the whole replay when only the last run diverged.
    Split the transcript back into its runs and count the matching ones.

    Evidence whose own fault cannot be characterised counts nothing: there is
    no claim "this reproduced" to make. Model-direct triage demotes that
    unmeasured evidence to a finding; a pooled rate remains unset.
    """
    key = crash_artifacts.sanitizer_fault_key(original)
    if key is None:
        return 0
    site = _fault_site(original)
    transcript = measured.split("\n=== SUMMARY ===", 1)[0]
    runs = _REPLAY_RUN_SPLIT_RE.split(transcript)[1:] or [measured]
    return sum(1 for run in runs if _same_fault(key, site, run))


def _measured_crash_rate(path: Path) -> tuple[int, int] | None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    rates = re.findall(r"^CRASH_RATE:\s*(\d+)\s*/\s*(\d+)\s*$", text, re.MULTILINE)
    if not rates:
        return None
    crashes, runs = rates[-1]
    return int(crashes), int(runs)


def reverify_pool_crash_rates(
    pool: Path, target_root: Path, target_slug: str, reason: str,
    skip: frozenset[str] | set[str] = frozenset(),
) -> int:
    candidates: list[Path] = []
    for crash_dir in sorted((pool / "crashes").glob("CRASH-*")):
        if crash_dir.name in skip:
            continue
        sanitizer_file = crash_dir / "sanitizer.txt"
        if not sanitizer_file.is_file():
            continue
        text = sanitizer_file.read_text(encoding="utf-8", errors="replace")
        if re.search(r"^CRASH_RATE:\s*[0-9]+/[0-9]+", text, re.MULTILINE):
            continue
        candidates.append(crash_dir)
    prior_validations = {
        crash_dir: validation_receipt.read_current(crash_dir)
        for crash_dir in candidates
    }
    results: dict[Path, bool] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(2, len(candidates) or 1)) as executor:
        futures = {
            crash_dir: executor.submit(
                reverify_one_crash, crash_dir, target_root, target_slug,
            )
            for crash_dir in candidates
        }
        for crash_dir in candidates:
            try:
                results[crash_dir] = futures[crash_dir].result()
            except (OSError, subprocess.SubprocessError, ValueError):
                results[crash_dir] = False
    reverified = 0
    for crash_dir in candidates:
        if results.get(crash_dir):
            reverified += 1
            prior_validation = prior_validations.get(crash_dir)
            if prior_validation is not None:
                validation_receipt.rewrite_after_equivalent_transform(
                    crash_dir, prior_validation,
                )
        else:
            log(f"WARN: reverify could not measure {crash_dir.name} - leaving rate unset ({reason})")
    if reverified:
        log(f"reverified crash repro rates: {reverified} ({reason})")
    return reverified


def _finalize_condition_pools(
    pool: Path, target_root: Path, backend: str, model: str, target_slug: str,
    decision_log: Path,
) -> None:
    """Build condition-local indexes after split_pool has copied its members."""
    reserved = {"crashes", "crashes-rejected", "findings", "findings-rejected"}
    config = benchmark_target_config(pool, target_root, target_slug)
    revision, config_digest = _evidence_scope(pool, target_root, target_slug)
    with _decision_environment(
        backend, model, target_root, target_slug, decision_log,
        config.attacker_controls_csv(),
        target_revision=revision,
        target_config_sha256=config_digest,
    ):
        for condition in sorted(pool.iterdir()):
            if not condition.is_dir() or condition.name in reserved:
                continue
            if not triage.maintain_indexes(condition, target_root):
                log(f"WARN: per-condition index maintenance failed ({condition.name})")


def _run_target_sha(bench_dir: Path) -> str:
    """The revision this run audited, as recorded at its start; "" if unknown."""
    try:
        run = json.loads((bench_dir / "run.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    return str(run.get("target_sha") or "")


def _pool_crash_owners(bench_dir: Path, pool: Path) -> dict[str, list[Path]]:
    """Pooled crashes grouped by the cell they were copied from.

    build_pool records that mapping, so each crash is checked against the build
    its own cell ran, not against every cell in the run. An unmapped crash
    groups under "" and is treated as belonging to no recorded build.
    """
    try:
        members = json.loads((bench_dir / "pool-members.json").read_text(encoding="utf-8"))
        owners = members.get("crash_cells") or {}
    except (OSError, ValueError):
        owners = {}
    grouped: dict[str, list[Path]] = {}
    for crash_dir in sorted((pool / "crashes").glob("CRASH-*")):
        cell = owners.get(crash_dir.name, "") if isinstance(owners, dict) else ""
        grouped.setdefault(str(cell), []).append(crash_dir)
    return grouped


def _pool_replay_blocked(
    bench_dir: Path, pool: Path, target: Path, target_slug: str,
) -> dict[str, str]:
    """Pooled crashes whose executed build cannot be verified, and why.

    Per crash, using its owning cell: one required artifact whose build has
    moved on says nothing about another crash from the same or another cell.
    """
    snapshot = bench_dir / "target.toml"
    try:
        config = _benchmark_config(
            target, target_slug, snapshot if snapshot.is_file() else None,
        )
    except (OSError, ValueError):
        config = None
    blocked: dict[str, str] = {}
    for cell_name, crash_dirs in sorted(_pool_crash_owners(bench_dir, pool).items()):
        cell = {}
        if cell_name:
            try:
                cell = json.loads(
                    (bench_dir / "cells" / cell_name / "cell.json").read_text(encoding="utf-8")
                )
            except (OSError, ValueError):
                cell = {}
        recorded = _cell_build_identity(cell)
        for crash_dir in crash_dirs:
            keys = _replay_artifact_keys([crash_dir], config, recorded)
            problems = build_preflight.pinned_build_problems(
                target, recorded, config, keys,
            )
            if problems:
                blocked[crash_dir.name] = "; ".join(problems)
    return blocked


def _pool_severity_not_current(pool: Path) -> list[str]:
    """Accepted pooled artifacts whose Severity row no scorer run vouches for.

    Clustering reads severity out of the report, so a score bound to different
    report content — or produced by an older scorer — is credited as if it were
    current. The marker makes that visible instead of silent.
    """
    stale: list[str] = []
    for kind, prefix in (("crashes", "CRASH-"), ("findings", "FIND-")):
        for directory in sorted((pool / kind).glob(f"{prefix}*")):
            receipt = validation_receipt.read_current(directory)
            # Only artifacts that carry a published score: an unrated one
            # (pending, native hardening) has no marker by design.
            if (
                receipt is None
                or receipt.get("state")
                not in validation_receipt.SECURITY_STATES
            ):
                continue
            report = report_identity.find_report(directory)
            if report is None:
                continue
            if severity_receipt.read_current(directory, report) is None:
                stale.append(f"{kind}/{directory.name}")
    return stale


def rebuild_pool(bench_dir: Path, target_slug: str, backend: str, model: str, dry_run: bool, reason: str) -> None:
    stage_name = ".pool.staging"
    metrics.build_pool(bench_dir, stage_name)
    metrics.relocate_experiments(bench_dir)
    pool = bench_dir / stage_name
    environment = os.environ.copy()
    environment.update({
        "ACTIVE_BACKEND": backend,
        "BACKEND": backend,
        "MODEL": model,
        "TARGET_SLUG": target_slug,
        "LLM_DECIDE_LOG": str(bench_dir / "llm-decisions.log"),
    })
    target = SCRIPT_ROOT / "targets" / target_slug
    config = benchmark_target_config(pool, target, target_slug)
    revision, config_digest = _evidence_scope(pool, target, target_slug)
    environment["TARGET_ATTACKER_CONTROLS_CSV"] = config.attacker_controls_csv()
    bundled = 0
    if not dry_run:
        with _decision_environment(
            backend, model, target, target_slug, bench_dir / "llm-decisions.log",
            config.attacker_controls_csv(),
            target_revision=revision,
            target_config_sha256=config_digest,
        ):
            triage.fill_reach_fields_tree(pool)
        if (pool / "crashes").is_dir():
            blocked = _pool_replay_blocked(bench_dir, pool, target, target_slug)
            for message in sorted(set(blocked.values())):
                count = sum(1 for value in blocked.values() if value == message)
                log(
                    f"WARN: pooled crash-rate replay skipped for {count} crash(es) — "
                    f"{message}; original evidence was left unchanged"
                )
            reverify_pool_crash_rates(
                pool, target, target_slug, reason, skip=set(blocked),
            )
        bundle_candidates: list[Path] = []
        for crash in sorted((pool / "crashes").glob("CRASH-*")):
            reports = list(crash.glob("[Rr][Ee][Pp][Oo][Rr][Tt].md"))
            canonical = any(
                "## Expected sanitizer output" in (text := report.read_text(encoding="utf-8", errors="replace"))
                and re.search(r"^CRASH_RATE:\s*[0-9]+/[0-9]+", text, re.MULTILINE)
                for report in reports
            )
            if not canonical:
                bundle_candidates.append(crash)
        # Bundling stays on when replay is skipped: a bundle reproduces from
        # source at the recorded revision and carries the crash's own saved
        # evidence, neither of which the current build's identity decides.
        export_env = environment | {"RESULTS_DIR": str(pool), "TARGET_ROOT": str(target)}
        # The run recorded the revision it audited. A pool is rebuilt long
        # after that, against a slug whose live session may belong to another
        # run entirely, so pass it explicitly rather than let export-repro
        # rediscover a revision this pool was never audited at. A run that
        # recorded none says so: the checkout's current commit is not an
        # answer to what this pool was audited at, only a plausible-looking one.
        audited = _run_target_sha(bench_dir) or target_config.NO_REV
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(2, len(bundle_candidates) or 1)
        ) as executor:
            futures = {
                crash: executor.submit(
                    _run_tool, "export-repro", crash.name,
                    "--crash-dir", str(crash), "--slug", target_slug,
                    "--target-root", str(target), "--target-rev", audited,
                    env=export_env,
                )
                for crash in bundle_candidates
            }
            for crash in bundle_candidates:
                try:
                    bundled += futures[crash].result() == 0
                except (OSError, subprocess.SubprocessError):
                    log(f"WARN: reproducer bundle failed for {crash.name} ({reason})")
    if bundled:
        log(f"reproducer bundles created: {bundled} ({reason})")
    # Score the pool on every path, including a dry run. Clustering below reads
    # each report's Severity row, and the pool it reads was just recopied from
    # the cells — so a pool that skipped scoring publishes whatever severity the
    # cells happened to carry, computed by whichever scorer ran back then. The
    # scorer is offline and deterministic, so there is nothing for a dry run to
    # hold back.
    with (bench_dir / "severity.log").open("w", encoding="utf-8") as output:
        _run_tool("severity", "--batch", str(pool), env=environment, stdout=output)
    unscored = _pool_severity_not_current(pool)
    if unscored:
        detail = (
            f"{len(unscored)} pooled artifact(s) carry a severity the current "
            f"scorer did not produce ({reason}): {', '.join(unscored[:5])}"
        )
        log(f"WARN: {detail}; refusing to publish stale severity")
        raise RuntimeError(detail)
    prior_cluster_validations = validation_receipt.snapshot_current_tree(pool)
    clustering_succeeded = True
    for kind, tool, output_name in (
        ("crashes", "cluster-crashes", "clusters-crashes.json"),
        ("findings", "cluster-findings", "clusters-findings.json"),
    ):
        if not (pool / kind).is_dir():
            continue
        with (bench_dir / output_name).open("w", encoding="utf-8") as output:
            if _run_tool(tool, str(pool), "--json", env=environment, stdout=output):
                clustering_succeeded = False
                output.seek(0)
                output.truncate()
                output.write('{"clusters":[]}\n')
        if _run_tool(tool, str(pool), env=environment):
            clustering_succeeded = False
    # Cluster the rejected side the same way, so "unique kept" and "unique cut"
    # count comparably — a raw reject tally against a deduplicated accept tally
    # measures two different things. The tool's root detection already accepts a
    # bare directory of FIND-*/CRASH-* subdirs, so point it straight at the
    # rejected root; --dry-run keeps cluster markers out of the rejection ledger
    # (we want the counts, not a rewrite of the evidence).
    for kind, tool, output_name in (
        ("crashes-rejected", "cluster-crashes", "clusters-crashes-rejected.json"),
        ("findings-rejected", "cluster-findings", "clusters-findings-rejected.json"),
    ):
        if not (pool / kind).is_dir():
            continue
        with (bench_dir / output_name).open("w", encoding="utf-8") as output:
            if _run_tool(
                tool, str(pool / kind), "--json", "--dry-run",
                env=environment, stdout=output,
            ):
                output.seek(0)
                output.truncate()
                output.write('{"clusters":[]}\n')
    if clustering_succeeded:
        validation_receipt.rewrite_tree_after_equivalent_transform(
            prior_cluster_validations,
        )
    metrics.split_pool(bench_dir, stage_name)
    if not triage.maintain_indexes(pool, target):
        log("WARN: combined pool index maintenance failed")
    _finalize_condition_pools(
        pool, target, backend, model, target_slug, bench_dir / "llm-decisions.log"
    )
    rejected_indexes = [
        pool / "findings-rejected" / "REJECTED-FINDINGS.md",
        pool / "crashes-rejected" / "REJECTED-CRASHES.md",
    ]
    rejected_indexes = [path for path in rejected_indexes if path.is_file()]
    if rejected_indexes:
        subprocess.run(
            [str(SCRIPT_ROOT / "bin" / "render-md"), *map(str, rejected_indexes), "--html-sibling"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
    live = bench_dir / "pool"
    old = bench_dir / ".pool.old"
    shutil.rmtree(old, ignore_errors=True)
    if live.exists():
        live.rename(old)
    pool.rename(live)
    shutil.rmtree(old, ignore_errors=True)
    log(f"benchmark-result update ({reason}): pool rebuilt")


def _result_signature(bench_dir: Path) -> str:
    digest = hashlib.sha256()
    for pattern in ("cells/*/cell.json", "cells/*/metrics.json"):
        for path in sorted(bench_dir.glob(pattern)):
            digest.update(str(path.relative_to(bench_dir)).encode())
            try:
                digest.update(path.read_bytes())
            except OSError:
                digest.update(b"<missing>")
    return digest.hexdigest()


@contextmanager
def _root_result_lock(bench_root: Path):
    """Serialize the shared crosstab across concurrently running backends."""
    bench_root.mkdir(parents=True, exist_ok=True)
    with (bench_root / ".benchmark-result.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


@contextmanager
def _ledger_lock(ledger: Path):
    """Serialize one backend ledger's read-modify-write update."""
    ledger.parent.mkdir(parents=True, exist_ok=True)
    with ledger.with_name(f".{ledger.name}.lock").open("a+") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _render_root_result(bench_root: Path) -> Path:
    """Atomically replace the cheap cross-run Markdown and HTML views."""
    crosstab = bench_root / "benchmark-result.md"
    html = crosstab.with_suffix(".html")
    temporary_md = temporary_html = None
    with _root_result_lock(bench_root):
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=bench_root,
                prefix=".benchmark-result.", suffix=".md", delete=False,
            ) as output:
                temporary_md = Path(output.name)
                output.write(metrics.crosstab(bench_root))
            temporary_html = temporary_md.with_suffix(".html")
            render = SCRIPT_ROOT / "bin" / "render-md"
            if render.is_file():
                rendered = subprocess.run(
                    [str(render), str(temporary_md), "--html", str(temporary_html),
                     "--title", "benchmark-result"],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                    check=False,
                )
                if rendered.returncode or not temporary_html.is_file():
                    raise RuntimeError("render-md did not produce benchmark-result HTML")
                # Graph goes straight after the table it visualises. A failure
                # here must not cost us the table: the numbers are the report.
                try:
                    temporary_html.write_text(
                        benchmark_graph.inject(
                            temporary_html.read_text(encoding="utf-8"), bench_root,
                        ),
                        encoding="utf-8",
                    )
                except Exception as exc:  # noqa: BLE001 - dashboard is best-effort
                    log(f"WARN: time-to-discovery graph skipped: {exc}")
            temporary_md.chmod(0o644)
            os.replace(temporary_md, crosstab)
            temporary_md = None
            if temporary_html.is_file():
                temporary_html.chmod(0o644)
                os.replace(temporary_html, html)
                temporary_html = None
        finally:
            if temporary_md is not None:
                temporary_md.unlink(missing_ok=True)
            if temporary_html is not None:
                temporary_html.unlink(missing_ok=True)
    return html if html.is_file() else crosstab


def update_live_result(bench_root: Path, reason: str) -> Path | None:
    """Refresh the provisional crosstab without pooling or finalization."""
    try:
        artifact = _render_root_result(bench_root)
    except Exception as exc:
        # The benchmark evidence is authoritative; a dashboard failure must be
        # visible without aborting the cell sequence that produces it.
        log(f"WARN: benchmark-result live update failed ({reason}): {exc}")
        return None
    log(
        f"benchmark-result live update ({reason}): "
        f"{artifact} ({artifact.resolve().as_uri()})"
    )
    return artifact


def update_result(bench_dir: Path, bench_root: Path, target: str, backend: str, model: str, dry_run: bool, reason: str) -> dict:
    signature = _result_signature(bench_dir)
    signature_key = str(bench_dir.resolve())
    if _RESULT_SIGNATURES.get(signature_key) == signature and (bench_dir / "report.json").is_file():
        log(f"benchmark-result update ({reason}): inputs unchanged, skipped rebuild")
        return json.loads((bench_dir / "report.json").read_text(encoding="utf-8"))
    rebuild_pool(bench_dir, target, backend, model, dry_run, reason)
    report = metrics.aggregate(bench_dir)
    _write_json(bench_dir / "report.json", report)
    artifact = _render_root_result(bench_root)
    (bench_dir / ".result-signature").unlink(missing_ok=True)
    _RESULT_SIGNATURES[signature_key] = signature
    log(f"benchmark-result update ({reason}): {artifact} ({artifact.resolve().as_uri()})")
    return report


def _latest_run(backend_root: Path) -> str:
    candidates = sorted(path.parent.name for path in backend_root.glob("*/cells") if path.is_dir())
    return candidates[-1] if candidates else ""


def _regenerate_all(args: argparse.Namespace, bench_root: Path) -> int:
    runs = []
    for cells in sorted(bench_root.glob("*/*/cells")):
        run_dir = cells.parent
        try:
            data = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        target = str(data.get("target") or "")
        backend = str(data.get("backend") or run_dir.parent.name)
        if target:
            runs.append((target, backend, run_dir.name))
    failures = 0
    for target, backend, run_id in runs:
        log(f"Regenerate-all: target={target} backend={backend} run={run_id}")
        child = replace_namespace(args, target=target, backend=backend, run_id=run_id)
        failures += run_single(child, bench_root) != 0
    if not runs:
        print(f"FATAL: --regenerate: no runs found under {bench_root}", file=sys.stderr)
        return 1
    crosstab = _render_root_result(bench_root).with_suffix(".md")
    log(f"Regenerate-all: rebuilt {crosstab} ({len(runs)} run(s), {failures} failed)")
    return 1 if failures else 0


def replace_namespace(namespace: argparse.Namespace, **changes) -> argparse.Namespace:
    values = vars(namespace).copy()
    values.update(changes)
    return argparse.Namespace(**values)


def _recorded_run(bench_dir: Path) -> dict:
    try:
        return json.loads((bench_dir / "run.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _resolve_build_suffix(args: argparse.Namespace, previous: dict) -> str:
    """The build directory suffix this run uses, composed onto any base.

    A resumed or regenerated run has to land on the tree it originally built —
    recomputing the key would read whatever the checkout has become since — so a
    recorded suffix always wins. A container's own suffix is composed with, not
    replaced, or an isolated run inside one would escape its image's tree.
    """
    recorded = str(previous.get("build_suffix") or "")
    if recorded:
        return recorded
    base = os.environ.get("AUDIT_BUILD_SUFFIX", "")
    if getattr(args, "isolate_build", False) and not args.regenerate:
        target = (SCRIPT_ROOT / "targets" / args.target).resolve()
        return f"{base}+bench-{target_config.build_input_key(target)}"
    return base


@contextmanager
def _build_suffix(value: str):
    """Scope AUDIT_BUILD_SUFFIX to one run.

    --regenerate walks many runs in one process; leaking one run's isolated
    suffix into the next would resolve the next run's builds to a tree that was
    never its own.
    """
    previous = os.environ.get("AUDIT_BUILD_SUFFIX")
    if value:
        os.environ["AUDIT_BUILD_SUFFIX"] = value
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("AUDIT_BUILD_SUFFIX", None)
        else:
            os.environ["AUDIT_BUILD_SUFFIX"] = previous


def _source_pin_conflict(target: Path, target_slug: str, signature: str) -> str:
    """Why this run must not start against this checkout, if it must not.

    A live run has pinned the source state it is auditing. If ours differs, the
    two are not comparable and one of us would have to rebuild under the other.
    A private build directory does not help — both runs read their source from
    this one checkout — so only a separate checkout is actually correct. This is
    deliberately checked against the checkout rather than the build directory,
    so an isolated run is caught too.

    Claiming and checking are the same operation: two runs that check before
    either publishes would both see a clear field and both proceed.
    """
    peers = build_lease.claim_source_pin(target, signature)
    if not peers:
        return ""
    return (
        f"targets/{target_slug} is at a different source state than a live run "
        f"({', '.join(peers)}). Sharing its build would measure a binary this "
        f"source did not produce, and rebuilding would corrupt that run; "
        f"--isolate-build cannot help because both runs read this same "
        f"checkout. Use a separate checkout, or wait for the other run."
    )


def _snapshot_benchmark_config(
    bench_dir: Path,
    target_root: Path,
    target_slug: str,
    *,
    replace: bool,
) -> Path:
    """Materialize the target execution contract owned by one benchmark run."""
    bench_dir.mkdir(parents=True, exist_ok=True)
    snapshot = bench_dir / "target.toml"
    if snapshot.is_file() and not replace:
        return snapshot
    source = SCRIPT_ROOT / "output" / target_slug / "target.toml"
    if not source.is_file():
        source = target_root / "target.toml"
    temporary = snapshot.with_name(f".{snapshot.name}.{os.getpid()}")
    temporary.unlink(missing_ok=True)
    try:
        if source.is_file():
            shutil.copy2(source, temporary)
        else:
            target_config.seed_toml(target_root, temporary)
        os.replace(temporary, snapshot)
    finally:
        temporary.unlink(missing_ok=True)
    return snapshot


def _config_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def preflight_build(
    args: argparse.Namespace, bench_dir: Path, model: str,
    pinned: dict | None = None, config: target_config.Config | None = None,
) -> list[str]:
    """Converge, hold and verify the build this run pins.

    Returns the reasons the run must not start; empty when every required build
    is present, matches its source, and is leased. A benchmark reports numbers
    produced by a specific binary, so unlike an audit it refuses to start on a
    build it could not verify or could not hold — every cell would otherwise be
    measuring something nobody can name afterwards.

    ``pinned`` carries a run's recorded generation, which makes this
    verify-only: see below.
    """
    if args.dry_run:
        return []
    target_root = SCRIPT_ROOT / "targets" / args.target
    try:
        config = config or _benchmark_config(target_root, args.target)
    except (OSError, ValueError) as exc:
        # A target with no generated config declares no sanitizer artifacts, so
        # there is nothing to verify rather than something wrong. Say so and let
        # the build checks below speak for themselves.
        log(f"WARN: sanitizer build preflight could not load target config: {exc}")
        config = target_config.Config(target_root=str(target_root))
    try:
        runner_preflight.validate(config, log)
    except (OSError, RuntimeError, ValueError) as exc:
        # ValueError included: a [runner].bin that escapes the target root is a
        # config the operator has to fix, not a traceback.
        return [str(exc)]
    if args.regenerate or pinned is not None:
        # Nothing is converged here. A regeneration replays existing evidence,
        # and a resumed run already has cells measured on the build it pinned —
        # converging either one could rebuild that generation out from under the
        # evidence that depends on it, before any check could refuse the run.
        unleased = build_preflight.hold_builds(
            target_root, config, log,
        )
    else:
        unleased = build_preflight.refresh(
            SCRIPT_ROOT, target_root, args.target, config, bench_dir,
            args.backend, model, log, include_alternates=False,
        )
    if pinned is not None:
        log("Resuming a pinned run: verifying the recorded build, not rebuilding")
    blocking = [f"{name} could not be leased" for name in unleased]
    if pinned is not None:
        blocking += build_preflight.pinned_build_problems(
            target_root, pinned, config,
        )
    else:
        blocking += build_preflight.build_problems(target_root, config)
    return blocking


def run_single(args: argparse.Namespace, bench_root: Path) -> int:
    args.target = target_profile.effective_slug(SCRIPT_ROOT, args.target)
    backend_root = bench_root / args.backend
    ledger = Path(args.ledger).resolve() if args.ledger else backend_root / "benchmark-results.md"
    if args.reset:
        with _ledger_lock(ledger):
            archive = metrics.reset_ledger(ledger, args.hard)
        log(f"Ledger {'deleted' if args.hard else f'archived to {archive}' if archive else 'already absent'}")
        return 0
    if not args.target:
        print("FATAL: --target is required", file=sys.stderr)
        return 1
    target = SCRIPT_ROOT / "targets" / args.target
    if not args.dry_run and not args.regenerate and not target.is_dir():
        print(f"FATAL: targets/{args.target} does not exist", file=sys.stderr)
        return 1
    if target.is_dir() and _is_shallow_checkout(target):
        log("WARN: target checkout is shallow; S1 history + work-card queue may be incomplete")
    conditions = [item.strip() for item in args.conditions.split(",") if item.strip()]
    unknown = [item for item in conditions if item not in {"model-direct", "harness"}]
    if unknown:
        print(f"FATAL: unknown condition '{unknown[0]}' (expected model-direct|harness)", file=sys.stderr)
        return 1
    run_id = args.run_id or os.environ.get("BENCHMARK_RUNID", "")
    if args.regenerate:
        run_id = run_id or _latest_run(backend_root)
        if not run_id:
            print(f"FATAL: --regenerate: no run found under {backend_root}", file=sys.stderr)
            return 1
    else:
        run_id = run_id or datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    bench_dir = backend_root / run_id
    cells_dir = bench_dir / "cells"
    if args.regenerate and not cells_dir.is_dir():
        print(f"FATAL: --regenerate: no cells/ to re-derive at {bench_dir}", file=sys.stderr)
        return 1
    # Protect only one run directory. Build/source leases coordinate peer runs,
    # and the result/ledger writers have their own locks, so serializing every
    # same-target run would unnecessarily prevent same-backend comparisons.
    lock_name = f".run-{target_key(run_id)}.lock"
    with BenchmarkLock(backend_root / lock_name):
        bench_dir.mkdir(parents=True, exist_ok=True)
        cells_dir.mkdir(parents=True, exist_ok=True)
        previous = _recorded_run(bench_dir)
        console_path = bench_dir / "console.log"
        with console_path.open("a", encoding="utf-8") as console, redirect_stdout(Tee(sys.stdout, console)), redirect_stderr(Tee(sys.stderr, console)), _build_suffix(_resolve_build_suffix(args, previous)):
            return _run_locked(args, bench_root, backend_root, bench_dir, cells_dir, ledger, run_id, conditions, previous)


def _source_pin_mismatch(previous: dict, source: str) -> str:
    """Why a resume cannot continue at this tracked source state."""
    recorded_source = str(previous.get("source_signature") or "")
    if recorded_source and source and recorded_source != source:
        return "the target source differs from the state this run pinned"
    return ""


_BENCH_TOKEN_RE = re.compile(r"\+bench-[0-9a-f]+")


def _bench_token(name: str) -> str:
    found = _BENCH_TOKEN_RE.search(name)
    return found.group(0) if found else ""


def _record_isolated_reference(target_root: Path, suffix: str, bench_dir: Path) -> None:
    """Note, next to the target, that a run depends on an isolated build tree.

    Collection would otherwise infer ownership by scanning one benchmark root,
    and a run under a different --bench-root would look like nobody's — its
    build would be collected while it still needed it for replay.
    """
    token = _bench_token(suffix)
    if not token:
        return
    directory = target_root / ".audit" / "bench-refs" / token
    directory.mkdir(parents=True, exist_ok=True)
    key = hashlib.sha1(str(bench_dir).encode()).hexdigest()[:12]
    (directory / f"{key}.ref").write_text(f"{bench_dir}\n", encoding="utf-8")


def _referenced_tokens(target_root: Path, bench_root: Path, keep: str) -> "set[str] | None":
    """Isolated build tokens some run still depends on, or None if unknowable.

    Two sources, because neither alone is complete: run records under the
    benchmark root in use, and markers beside the target that a run under any
    root leaves behind. A marker whose run directory is gone is itself garbage
    and is pruned.
    """
    referenced = {_bench_token(keep)} if keep else set()
    for run_json in sorted(bench_root.glob("*/*/run.json")):
        try:
            data = json.loads(run_json.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # An unreadable run record is not permission to delete a build it
            # may depend on. Collect nothing rather than guess.
            return None
        referenced.add(_bench_token(str(data.get("build_suffix") or "")))
    refs = target_root / ".audit" / "bench-refs"
    for marker in sorted(refs.glob("*/*.ref")):
        try:
            owner = Path(marker.read_text(encoding="utf-8").strip())
        except OSError:
            return None
        if owner.is_dir():
            referenced.add(marker.parent.name)
        else:
            marker.unlink(missing_ok=True)
    referenced.discard("")
    return referenced


def _collect_isolated_builds(target_root: Path, bench_root: Path, keep: str) -> int:
    """Remove isolated build trees no benchmark run refers to any more.

    An isolated tree has to outlive its run, because --regenerate replays crashes
    against the build they were found on, so a referenced tree stays however old
    it is — including one referenced from a different --bench-root. What is
    collected is a tree nothing on disk points at: an abandoned run directory, or
    inputs whose run never recorded them. Alternate configurations built under an
    isolated suffix share its token and are kept or collected with it.

    Only the +bench- namespace is considered, so the canonical build, a
    container-suffixed tree and build-<san>-repro are never candidates.
    """
    referenced = _referenced_tokens(target_root, bench_root, keep)
    if referenced is None:
        return 0
    removed = 0
    for tree in sorted(target_root.glob("build-*+bench-*")):
        token = _bench_token(tree.name)
        if not tree.is_dir() or not token or token in referenced:
            continue
        if build_lease.consumers_active(target_root, tree.name):
            continue
        with build_lease.exclusive(target_root, tree.name) as leased:
            if not leased:
                continue
            shutil.rmtree(tree, ignore_errors=True)
        removed += 1
    return removed


def _settings_mismatch(previous: dict, args: argparse.Namespace, model: str) -> str:
    """Why a resumed run cannot continue under these settings, if it cannot.

    Cells already on disk were produced under the settings recorded for the run.
    Changing what defines the experiment and then adding cells would put two
    different experiments in one median. Replicates, conditions and the
    finalization budget are deliberately not on this list: raising replicates and
    resuming a subset of conditions are how a run is legitimately continued, and
    the finalize budget governs measurement rather than what the agents did.
    """
    if not previous:
        return ""
    fields = (
        ("model", model),
        ("resolved_effort", llm_invoke.default_effort(args.backend)),
        ("budget_wall", args.budget_wall),
        ("harness_agents", args.agents),
        ("target_sha", target_config.detect_rev(SCRIPT_ROOT / "targets" / args.target)),
    )
    for name, current in fields:
        recorded = previous.get(name)
        if recorded is None or recorded == current:
            continue
        return f"{name} was {recorded!r} for this run and is now {current!r}"
    return ""


def _resume_refusal(reason: str, run_id: str) -> str:
    return (
        f"{reason}. Cells already recorded for run {run_id} were measured on the "
        f"state it pinned, and mixing generations would average two different "
        f"experiments into one result. Start a new run id, or restore the build "
        f"and source this one pinned."
    )


def _run_locked(args, bench_root, backend_root, bench_dir, cells_dir, ledger, run_id, conditions, previous=None) -> int:
    model = args.model or llm_invoke.default_model(args.backend)
    llm_invoke.apply_memory_policy(False)
    if not args.regenerate:
        run_data = {
            "runid": run_id, "target": args.target, "backend": args.backend,
            "model": model, "resolved_effort": llm_invoke.default_effort(args.backend),
            "replicates": args.replicates,
            "budget_wall": args.budget_wall, "harness_agents": args.agents,
            "finalize_wall": getattr(args, "finalize_wall", 0),
            "finalize_workers": getattr(args, "finalize_workers", 4),
            "model_direct_agents": 1, "conditions": conditions,
            "target_sha": target_config.detect_rev(SCRIPT_ROOT / "targets" / args.target),
            "tokenfuzz_sha": _git_rev(SCRIPT_ROOT), "harness_sha": _git_rev(SCRIPT_ROOT, True),
            "finding_confirmation": metrics.FINDING_CONFIRMATION_VERSION,
            "dry_run": args.dry_run,
        }
        # Written once, below, after the pin checks: a refused resume must not
        # overwrite the pin it was refused for, or the next attempt would find
        # nothing to contradict and proceed.
        budget = "unlimited" if not args.budget_wall else f"{format_duration(args.budget_wall)} per cell"
        log(f"Benchmark run {run_id}: target={args.target} backend={args.backend} model={model or '?'} replicates={args.replicates} budget={budget}")
        log(f"Conditions: {','.join(conditions)}")
        if args.dry_run:
            log("Dry run: synthetic cells, no LLM calls")
    else:
        log(f"Regenerating run {run_id}: target={args.target} backend={args.backend} (no cells launched)")
    log(f"Output: {bench_dir}")

    previous = previous or {}
    target_root = (SCRIPT_ROOT / "targets" / args.target).resolve()
    build_suffix = os.environ.get("AUDIT_BUILD_SUFFIX", "")
    run_identity: dict = {}
    run_source = ""
    config_snapshot: Path | None = None
    run_config: target_config.Config | None = None
    # A run that already recorded a generation is being resumed, so from here on
    # it verifies rather than converges.
    recorded_identity = previous.get("build_identity")
    pinned_identity = (
        recorded_identity
        if isinstance(recorded_identity, dict) and recorded_identity
        else None
    )
    if not args.dry_run:
        try:
            config_snapshot = _snapshot_benchmark_config(
                bench_dir, target_root, args.target,
                replace=pinned_identity is None and not args.regenerate,
            )
            recorded_config = str(previous.get("target_config_sha256") or "")
            current_config = _config_digest(config_snapshot)
            if recorded_config and current_config != recorded_config:
                reason = (
                    f"the run target.toml snapshot was modified "
                    f"({config_snapshot})"
                )
                print(
                    f"FATAL: {_resume_refusal(reason, run_id)}",
                    file=sys.stderr,
                )
                return 1
            run_config = _benchmark_config(
                target_root, args.target, config_snapshot,
            )
        except (OSError, ValueError) as exc:
            print(
                f"FATAL: benchmark target configuration is unusable: {exc}",
                file=sys.stderr,
            )
            return 1
    if not args.dry_run and not args.regenerate:
        # Everything that can refuse the run happens before convergence. Once we
        # rebuild, a peer run's evidence is already invalid and a resumed run has
        # already lost the generation its finished cells were measured on.
        settings = _settings_mismatch(previous, args, model)
        if settings:
            print(f"FATAL: {_resume_refusal(settings, run_id)}", file=sys.stderr)
            return 1
        run_source = target_config.vcs_source_signature(
            target_root, include_untracked=False,
        )
        drifted = _source_pin_mismatch(previous, run_source)
        if drifted:
            print(f"FATAL: {_resume_refusal(drifted, run_id)}", file=sys.stderr)
            return 1
        conflict = _source_pin_conflict(target_root, args.target, run_source)
        if conflict:
            print(f"FATAL: {conflict}", file=sys.stderr)
            return 1

    blocking = preflight_build(
        args, bench_dir, model, pinned_identity, run_config,
    )
    if blocking and not args.regenerate:
        if pinned_identity is not None:
            for reason in blocking:
                print(
                    f"FATAL: {_resume_refusal(reason, run_id)}",
                    file=sys.stderr,
                )
        else:
            for reason in blocking:
                print(f"FATAL: {reason}", file=sys.stderr)
            print(
                f"FATAL: fix the paths above and rerun, or build with "
                f"`bin/setup-target {args.target} --build`; no benchmark cell "
                "was launched",
                file=sys.stderr,
            )
        return 1
    for reason in blocking:
        log(f"WARN: regenerating over an unverified build: {reason}")

    # One build generation for the whole run. The preflight above converged it
    # and holds its lease, so it is captured once, here, and every cell, replay
    # and pooled check compares against the build the run actually used.
    # Capturing per cell instead recorded a build that the cell's own startup
    # could still replace — which is what made finalization refuse valid
    # evidence even with nothing else running.
    if not args.regenerate:
        if not args.dry_run:
            # A resume was already verified against its recorded pin above.
            # Keep that pin byte-for-byte; recomputing it would turn a schema
            # upgrade into a fictitious build change.
            run_identity = pinned_identity or _target_build_identity(
                target_root, args.target, run_config,
            )
            run_source = str(previous.get("source_signature") or "") or run_source
            run_data["build_identity"] = run_identity
            run_data["source_signature"] = run_source
            if config_snapshot is not None:
                run_data["target_config_sha256"] = _config_digest(
                    config_snapshot,
                )
            if build_suffix:
                run_data["build_suffix"] = build_suffix
                _record_isolated_reference(target_root, build_suffix, bench_dir)
        _write_json(bench_dir / "run.json", run_data)

    done = failed = 0
    provider_unavailable = False
    require_trigger_confirmation = True
    if not args.regenerate:
        for condition in conditions:
            for replicate in range(1, args.replicates + 1):
                name = f"{condition}-r{replicate}"
                cell_dir = cells_dir / name
                cell_json = cell_dir / "cell.json"
                try:
                    prior = json.loads(cell_json.read_text(encoding="utf-8"))
                except (OSError, ValueError):
                    prior = {}
                if prior.get("status") == "done":
                    # Clean and recovered replicates alike finished on their
                    # full budget; keep them. Retrying a recovered cell would
                    # discard a valid measurement and likely re-hit the same
                    # provider window, so a resume leaves it as-is.
                    log(f"Cell {name}: already done, skipping")
                    done += 1
                    continue
                if prior.get("status"):
                    # A same-run-id resume re-runs any replicate that did not
                    # finish clean — provider-limited (excluded from the totals)
                    # or failed — trading it for a real measurement.
                    log(f"Cell {name}: prior run {prior.get('run_quality') or prior['status']}; retrying")
                if provider_unavailable:
                    cell_dir.mkdir(parents=True, exist_ok=True)
                    (cell_dir / ".backend-unavailable").touch()
                    (cell_dir / ".run-quality").write_text("provider_limited\n", encoding="utf-8")
                    write_cell(cell_json, condition, replicate, f"bench-{run_id}-{condition}-r{replicate}", Path(), 0, "incomplete", args.agents)
                    failed += 1
                    continue
                shutil.rmtree(cell_dir, ignore_errors=True)
                cell_dir.mkdir(parents=True)
                experiment = f"bench-{run_id}-{condition}-r{replicate}"
                log(f"Cell {name} starting: condition={condition} replicate={replicate} agents={1 if condition == 'model-direct' else args.agents or 'default'} model={model or '?'} experiment={experiment}")
                predicted = cell_dir if condition == "model-direct" else cell_dir / "repo-root" / "output" / f"{args.target}-{experiment}" / args.backend / "results"
                drift = build_preflight.pinned_build_problems(
                    target_root, run_identity, run_config,
                )
                if drift:
                    # Nothing inside the harness can reach here: the lease keeps
                    # every cooperating rebuild out for the run's whole life. An
                    # agent that ran a build tool by hand is outside that lease,
                    # and a cell measured on a different binary than its peers
                    # is not comparable, so refuse it rather than average it in.
                    log(
                        f"WARN: Cell {name}: not started — {'; '.join(drift)}; "
                        f"original evidence was left unchanged"
                    )
                    cell_dir.mkdir(parents=True, exist_ok=True)
                    (cell_dir / ".run-quality").write_text(
                        "build_drift\n", encoding="utf-8"
                    )
                    write_cell(
                        cell_json, condition, replicate,
                        f"bench-{run_id}-{condition}-r{replicate}", Path(), 0,
                        "incomplete", args.agents, build_identity=run_identity,
                    )
                    failed += 1
                    continue
                cell_build_identity = run_identity
                write_cell(
                    cell_json, condition, replicate, experiment, predicted, 0,
                    "running", args.agents,
                    build_identity=cell_build_identity,
                )
                # Regen fires again on completion; do it at start too so a
                # just-started long cell (the trailing harness cell) shows in the
                # shared dashboard for its whole run, not only after it finishes.
                update_live_result(bench_root, f"start {name}")
                start = time.monotonic()
                started_at = datetime.now(timezone.utc).isoformat()
                status = "done"
                if args.dry_run:
                    results = dryrun_cell(cell_dir, condition, replicate, args.backend)
                    rc = 0
                elif condition == "model-direct":
                    log(f"Cell {name} live log: {(cell_dir / 'backend.raw.log').resolve()}")
                    results = cell_dir
                    rc = run_model_direct(
                        cell_dir, target_root, args.backend, model,
                        args.budget_wall, config_snapshot,
                    )
                else:
                    log(f"Cell {name} live log: {(cell_dir / 'audit.log').resolve()}")
                    rc, results = run_harness(
                        cell_dir, args.target, args.backend, model, experiment,
                        args.budget_wall, args.agents, cell_build_identity,
                        config_snapshot,
                    )
                # Stop the clock where the finding work stops. Everything below
                # — crash triage, the find-gate drain, metrics — is measurement
                # of what was already found, so charging it to the cell's wall
                # makes a 3h budget report as ~4h and makes conditions that
                # produce more to adjudicate look slower at finding things.
                wall = int(time.monotonic() - start)
                source_drift = (
                    {}
                    if args.dry_run
                    else _source_drift(target_root, run_source)
                )
                if source_drift:
                    # Keep every artifact — the findings are still findings — but
                    # take the cell out of the headline comparison: its agents
                    # read code its peers did not. Never respond by rebuilding,
                    # which would also invalidate the cells that came before.
                    changed = ", ".join(source_drift.get("paths", [])[:5]) or "unknown"
                    log(
                        f"WARN: Cell {name}: target source changed during the "
                        f"cell ({changed}); artifacts kept, cell excluded from "
                        f"the comparison"
                    )
                    _write_json(cell_dir / "source-drift.json", source_drift)
                    (cell_dir / ".run-quality").write_text(
                        "source_drift\n", encoding="utf-8"
                    )
                build_drift = (
                    []
                    if args.dry_run
                    else build_preflight.pinned_build_problems(
                        target_root, cell_build_identity, run_config,
                    )
                )
                if build_drift:
                    log(
                        f"WARN: Cell {name}: target build changed during the "
                        f"cell ({'; '.join(build_drift)}); artifacts kept, cell "
                        "excluded from the comparison"
                    )
                    (cell_dir / ".run-quality").write_text(
                        "build_drift\n", encoding="utf-8"
                    )
                if (cell_dir / ".backend-unavailable").exists():
                    status = "incomplete"
                    provider_unavailable = True
                elif rc:
                    status = "failed"
                elif (cell_dir / ".target-artifacts-unowned").exists():
                    status = "incomplete"
                elif source_drift or build_drift:
                    status = "incomplete"
                paused = 0
                housekeeping = 0
                try:
                    paused = int((results.parent / "logs" / ".paused_secs").read_text().strip())
                except (OSError, ValueError):
                    pass
                try:
                    housekeeping = int(float(
                        (results.parent / "logs" / ".housekeeping_secs").read_text().strip()
                    ))
                except (OSError, ValueError):
                    pass
                finalize_wall = getattr(args, "finalize_wall", 0)
                finalize_workers = getattr(args, "finalize_workers", 4)
                # Post-cell adjudication is measurement, not discovery, but its
                # tokens land in the same index as the audit's. Stamp the
                # boundary so the two can be told apart after the fact; the
                # published totals stay combined.
                _stamp_finalization_start(results)
                replay_build_ok = not build_drift
                if (
                    not args.dry_run
                    and replay_build_ok
                    and results.is_dir()
                    and (results / "crashes").is_dir()
                ):
                    log(f"Cell {name}: completing crash triage before metrics")
                    try:
                        target_root = (SCRIPT_ROOT / "targets" / args.target).resolve()
                        config = benchmark_target_config(results, target_root, args.target)
                        revision, config_digest = _evidence_scope(
                            results, target_root, args.target,
                        )
                        with _decision_environment(
                            args.backend, model, target_root, args.target,
                            attacker_controls=config.attacker_controls_csv(),
                            target_revision=revision,
                            target_config_sha256=config_digest,
                        ):
                            crash_counts = triage_cell_crashes(
                                results, target_root, args.target,
                                workers=finalize_workers,
                                deadline=_finalize_deadline(finalize_wall),
                                require_replay=condition == "model-direct",
                            )
                        log(
                            f"Cell {name} crash triage: promoted={crash_counts.get('promoted', 0)} "
                            f"rejected={crash_counts.get('rejected', 0)} "
                            f"demoted={crash_counts.get('demoted', 0)} "
                            f"pending={crash_counts.get('pending', 0)}"
                        )
                    except Exception as exc:
                        log(f"WARN: crash triage failed for {name}: {exc}")
                        status = "incomplete"
                if not args.dry_run and args.validate_findings and results.is_dir() and (results / "findings").is_dir():
                    # Final triage is measurement, not timed finding work. Run
                    # it synchronously after the audit consumes its productive
                    # budget so a normal wall-budget stop remains a completed
                    # benchmark cell with fully adjudicated metrics.
                    log(f"Cell {name}: draining find-gate before metrics")
                    try:
                        counts = drain_find_gate(
                            results, args.backend, model,
                            (SCRIPT_ROOT / "targets" / args.target).resolve(), args.target,
                            deadline=_finalize_deadline(finalize_wall),
                            workers=finalize_workers,
                        )
                        # A pause inside the drain sits in the untimed
                        # measurement phase, so it is not subtracted from the
                        # cell's wall — only the audit's own pauses are.
                        log(
                            f"Cell {name} validation: accepted={counts.get('accepted', 0)} "
                            f"rejected={counts.get('rejected', 0)} pending={counts.get('pending', 0)} "
                            f"paused={counts.get('paused_seconds', 0)}s"
                        )
                    except Exception as exc:
                        log(f"WARN: find-gate drain failed for {name}: {exc}")
                        status = "incomplete"
                elif not args.dry_run and condition == "model-direct" and not args.validate_findings:
                    log(f"Cell {name} validation: DISABLED (--no-validate-findings)")
                if results.is_dir():
                    summary = metrics.harvest(
                        results, args.backend, model,
                        require_trigger_confirmation=require_trigger_confirmation,
                    )
                    # A drain that stops early leaves findings unjudged, and
                    # every one of them counts as unconfirmed — so the cell
                    # reports a yield it never actually measured. The
                    # regenerate path already says this; a live run is where an
                    # operator can still act on it.
                    unjudged = summary.get("findings_unadjudicated", 0)
                    if args.validate_findings and unjudged:
                        log(
                            f"WARN: {name} has {unjudged} finding(s) still "
                            "un-adjudicated after drain; they count as "
                            "unconfirmed. Re-run `bin/benchmark --regenerate` "
                            "to finish the gate"
                        )
                    _write_json(cell_dir / "metrics.json", summary)
                else:
                    summary = {"exists": False}
                    _write_json(cell_dir / "metrics.json", summary)
                    status = "failed"
                write_cell(
                    cell_json, condition, replicate, experiment, results, wall,
                    status, args.agents, paused=paused, started_at=started_at,
                    housekeeping=housekeeping,
                )
                if condition == "model-direct":
                    cleanup_model_direct_scratch(cell_dir)
                log(f"Cell {name} {metrics.metric_gate_summary(summary)}")
                if status == "done":
                    done += 1
                    log(
                        f"Cell {name} done in {format_duration(wall)}: "
                        f"crashes={summary.get('confirmed_crashes', 0)} "
                        f"findings={summary.get('confirmed_findings', 0)} "
                        f"refusals={summary.get('model_refusals', 0)}"
                    )
                else:
                    failed += 1
                    if status == "incomplete":
                        log(
                            f"Cell {name} incomplete — observed "
                            f"{summary.get('confirmed_crashes', 0)} crashes / "
                            f"{summary.get('confirmed_findings', 0)} findings; "
                            f"excluded from aggregate after {format_duration(wall)}; "
                            f"see {cell_dir}"
                        )
                    else:
                        log(f"Cell {name} {status} after {format_duration(wall)}; see {cell_dir}")
                update_live_result(bench_root, f"after {name}")
                log(f"Cell {name}: metrics saved; pooled finalization deferred")
        log(f"Cells complete: {done} done, {failed} failed")
    else:
        refreshed = 0
        for cell_dir in cells_dir.iterdir():
            try:
                cell = json.loads((cell_dir / "cell.json").read_text(encoding="utf-8"))
                results = Path(cell.get("results_dir", ""))
            except (OSError, ValueError):
                continue
            if (
                (cell_dir / ".target-artifacts-unowned").is_file()
                and cell.get("run_quality")
                not in {"provider_limited", "source_drift", "build_drift"}
            ):
                cell["run_quality"] = "unowned_artifacts"
                _write_json(cell_dir / "cell.json", cell)
            if results.is_dir():
                finalizers_ok = True
                finalize_wall = getattr(args, "finalize_wall", 0)
                finalize_workers = getattr(args, "finalize_workers", 4)
                replay_build_ok = True
                if (results / "crashes").is_dir():
                    replay_build_ok, reason = _replay_build_status(
                        cell,
                        results,
                        target_root, args.target, run_config,
                    )
                    if not replay_build_ok:
                        finalizers_ok = False
                        _mark_build_finalization_incomplete(cell, reason)
                        _write_json(cell_dir / "cell.json", cell)
                        log(
                            f"WARN: Regenerate: crash triage skipped for "
                            f"{cell_dir.name} — {reason}; original evidence "
                            "was left unchanged"
                        )
                    else:
                        cell.pop("build_finalization_error", None)
                if replay_build_ok and (results / "crashes").is_dir():
                    log(f"Regenerate: completing crash triage for {cell_dir.name} ({cell.get('condition', '?')})")
                    try:
                        target_root = (SCRIPT_ROOT / "targets" / args.target).resolve()
                        config = benchmark_target_config(results, target_root, args.target)
                        revision, config_digest = _evidence_scope(
                            results, target_root, args.target,
                        )
                        with _decision_environment(
                            args.backend, model, target_root, args.target,
                            attacker_controls=config.attacker_controls_csv(),
                            target_revision=revision,
                            target_config_sha256=config_digest,
                        ):
                            triage_cell_crashes(
                                results, target_root, args.target,
                                workers=finalize_workers,
                                deadline=_finalize_deadline(finalize_wall),
                                require_replay=cell.get("condition") == "model-direct",
                                age_pending=False,
                            )
                    except Exception as exc:
                        log(f"WARN: crash triage failed for {cell_dir.name}: {exc}")
                        finalizers_ok = False
                if args.validate_findings and (results / "findings").is_dir():
                    log(f"Regenerate: draining find-gate for {cell_dir.name} ({cell.get('condition', '?')})")
                    try:
                        drain_find_gate(
                            results, args.backend, model,
                            (SCRIPT_ROOT / "targets" / args.target).resolve(), args.target,
                            deadline=_finalize_deadline(finalize_wall),
                            workers=finalize_workers,
                        )
                    except Exception as exc:
                        log(f"WARN: find-gate drain failed for {cell_dir.name}: {exc}")
                        finalizers_ok = False
                summary = metrics.harvest(
                    results, args.backend, model,
                    require_trigger_confirmation=require_trigger_confirmation,
                )
                _write_json(cell_dir / "metrics.json", summary)
                remaining = summary.get("findings_unadjudicated", 0)
                if args.validate_findings and remaining:
                    log(f"WARN: {cell_dir.name} has {remaining} finding(s) still un-adjudicated after drain")
                # `incomplete` is reserved for a provider-limited run or a
                # finalizer that actually failed. Older runners also used it
                # for an otherwise successful cell containing one unfinished
                # artifact; recover that stale status after fresh finalizers
                # return normally. Residual artifacts remain visible in
                # metrics without erasing confirmed evidence from the cell.
                if (
                    finalizers_ok
                    and cell.get("status") == "incomplete"
                    # A provider-limited cell never ran its budget; a drifted one
                    # read or executed something its peers did not. Neither
                    # becomes comparable later, so regeneration must not promote
                    # them back into the totals.
                    and cell.get("run_quality")
                    not in metrics.NONCOMPARABLE_RUN_QUALITIES
                    and not (cell_dir / ".target-artifacts-unowned").is_file()
                    and not (cell_dir / ".backend-unavailable").is_file()
                ):
                    cell["status"] = "done"
                    if cell.get("run_quality") == "incomplete":
                        cell["run_quality"] = "clean"
                    _write_json(cell_dir / "cell.json", cell)
                refreshed += 1
        log(f"Regenerate: re-derived metrics from {refreshed} cell(s)")

    report = update_result(bench_dir, bench_root, args.target, args.backend, model, args.dry_run, "pre-ledger")
    section = metrics.render_section(report)
    render = SCRIPT_ROOT / "bin" / "render-md"
    with _ledger_lock(ledger):
        metrics.append_to_ledger(ledger, section)
        if render.is_file() and ledger.is_file():
            subprocess.run(
                [str(render), str(ledger), "--html-sibling"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                check=False,
            )
    print()
    log(f"Run {run_id} summary:")
    for condition in report.get("conditions", []):
        print(
            f"  {condition.get('condition')}: crash median={condition.get('crash_median', 0)} "
            f"finding total={condition.get('confirmed_finding_total', 0)}"
        )
        for observed in condition.get("incomplete_observed", []):
            print(
                f"    {observed.get('cell')}: incomplete — observed "
                f"{observed.get('crashes', 0)} crashes / "
                f"{observed.get('findings', 0)} findings; excluded from aggregate"
            )
    print()
    log(f"Ledger: {ledger}")
    if not args.dry_run:
        collected = _collect_isolated_builds(target_root, bench_root, build_suffix)
        if collected:
            log(f"Collected {collected} isolated build tree(s) no run refers to")
    log("Benchmark complete.")
    return 1 if failed else 0


def _main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    bench_root = Path(args.bench_root)
    if not bench_root.is_absolute():
        bench_root = (SCRIPT_ROOT / bench_root).resolve()
    if args.regenerate and not args.target:
        return _regenerate_all(args, bench_root)
    targets = [item.strip() for item in args.target.split(",") if item.strip()]
    if args.target and not targets:
        print("FATAL: --target must contain at least one non-empty slug", file=sys.stderr)
        return 1
    if len(targets) > 1:
        failures = 0
        for index, target in enumerate(targets, start=1):
            log(f"Multi-target {index}: {target} starting")
            run_id = f"{args.run_id}-{target_key(target)}" if args.run_id else ""
            # Isolate per-target fatals (e.g. an unusable runner at preflight) so
            # one misconfigured target fails only its own cell instead of
            # crashing the grid and losing every later target's results.
            try:
                failed = run_single(replace_namespace(args, target=target, run_id=run_id), bench_root) != 0
            except RuntimeError as exc:
                print(f"FATAL: {target}: {exc}", file=sys.stderr)
                failed = True
            failures += failed
        log(f"Multi-target complete: {len(targets) - failures}/{len(targets)} target(s) succeeded")
        return 1 if failures else 0
    if targets:
        args.target = targets[0]
    try:
        return run_single(args, bench_root)
    except RuntimeError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    with _signal_cleanup():
        return _main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
