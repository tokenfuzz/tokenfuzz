#!/usr/bin/env python3
"""Long-running benchmark orchestration.

The metric, pool, aggregation, and rendering algorithms live in benchmark.py;
this module owns process lifecycle and isolated benchmark cells.
"""

from __future__ import annotations

import argparse
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
import benchmark_model_direct_render
import build_preflight
import llm_invoke
import process_tree
import target_config
import triage
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
):
    values = {
        "ACTIVE_BACKEND": backend, "BACKEND": backend, "MODEL": model,
        "TARGET_ROOT": str(target), "TARGET_SLUG": target_slug,
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


def drain_find_gate(
    results: Path, backend: str, model: str, target: Path, target_slug: str,
    *, deadline: float | None = None,
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
    with _decision_environment(backend, model, target, target_slug):
        previous_limit = os.environ.get("LLM_DECIDE_LIMIT_FILE")
        os.environ["LLM_DECIDE_LIMIT_FILE"] = str(limit_file)
        try:
            for attempt in range(max_pauses + 1):
                if deadline is not None and time.monotonic() >= deadline:
                    break
                limit_file.write_text("", encoding="utf-8")
                counts = triage.validate_find_gate(results, deadline=deadline)
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
                log(f"Find-gate provider limit: pausing {wait}s before retry")
                time.sleep(wait)
                paused += wait
                if deadline is not None:
                    deadline += wait
        finally:
            if previous_limit is None:
                os.environ.pop("LLM_DECIDE_LIMIT_FILE", None)
            else:
                os.environ["LLM_DECIDE_LIMIT_FILE"] = previous_limit
            limit_file.unlink(missing_ok=True)
    if paused:
        counts["paused_seconds"] = paused
    return counts


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
            "productive wall seconds per cell for recon and agents; final "
            "triage runs to completion afterward and provider-recovery pauses "
            "are excluded (0 = unlimited)"
        ),
    )
    result.add_argument("--agents", type=_positive)
    result.add_argument("--conditions", default="model-direct,harness")
    result.add_argument("--skip-recon", action="store_true")
    result.add_argument("--ledger")
    result.add_argument("--bench-root", default="output/benchmark")
    result.add_argument("--run-id", default="")
    result.add_argument("--reset", action="store_true")
    result.add_argument("--hard", action="store_true")
    result.add_argument("--regenerate", action="store_true")
    result.add_argument("--dry-run", action="store_true")
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
            target = self.path.stem.removeprefix(".run-")
            raise RuntimeError(
                f"benchmark for target={target} backend={self.path.parent.name} "
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
    paused: int = 0,
) -> None:
    quality = "clean"
    try:
        candidate = (path.parent / ".run-quality").read_text(encoding="utf-8").strip()
        if candidate in {"clean", "provider_recovered", "provider_limited"}:
            quality = candidate
    except OSError:
        pass
    if status == "incomplete" and quality == "clean":
        quality = "provider_limited"
    payload = {
        "condition": condition, "replicate": replicate, "experiment": experiment,
        "results_dir": str(results_dir), "wall_seconds": wall, "status": status,
        "run_quality": quality, "paused_seconds": paused,
        "wall_effective_seconds": max(0, wall - paused),
    }
    if requested_agents is not None:
        payload["requested_agents"] = requested_agents
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


def dryrun_cell(cell_dir: Path, condition: str, replicate: int) -> Path:
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
        json.dumps({"tokens": {"input": 1000, "cached_input": 900, "output": replicate * 100}, "probe": {"asan_invocations": 3}}) + "\n",
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


def sweep_target_artifacts(target: Path, destination: Path, marked: set[Path] | None) -> int:
    if marked is None or not target.is_dir() or not destination.is_dir():
        return 0
    moved = 0
    for parent_name, glob in (("findings", "FIND-*"), ("crashes", "CRASH-*")):
        output = destination / parent_name
        output.mkdir(parents=True, exist_ok=True)
        for parent in target.rglob(parent_name):
            if ".git" in parent.parts or not parent.is_dir():
                continue
            for entry in list(parent.glob(glob)):
                if entry.resolve() in marked:
                    continue
                target_path = output / entry.name
                if target_path.exists():
                    target_path = output / f"{entry.name}.from-target-{int(time.time())}-{os.getpid()}"
                shutil.move(entry, target_path)
                moved += 1
                log(f"  Sweep: rescued {parent_name}/{entry.name} from source tree -> {target_path}")
    for name in ("findings", "crashes"):
        try:
            (target / name).rmdir()
        except OSError:
            pass
    return moved


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


def run_model_direct(cell_dir: Path, target: Path, backend: str, model: str, wall: int) -> int:
    for name in ("crashes", "findings", "logs"):
        (cell_dir / name).mkdir(parents=True, exist_ok=True)
    prompt = benchmark_model_direct_render.render(str(target), str(cell_dir), str(SCRIPT_ROOT))
    (cell_dir / "prompt.txt").write_text(prompt, encoding="utf-8")
    raw = cell_dir / "backend.raw.log"
    for marker in (".quota-exhausted", ".backend-unavailable", ".run-quality"):
        (cell_dir / marker).unlink(missing_ok=True)
    marked = mark_target_artifacts(target)
    previous_logdir = os.environ.get("LOGDIR")
    os.environ["LOGDIR"] = str(cell_dir / "logs")
    try:
        rc = llm_invoke.run_agent_prompt(
            backend, prompt, wall, raw, model=model, max_turns=0,
            add_dirs=f"{cell_dir},{target}", cwd=cell_dir,
            watchdog_marker_dir=cell_dir,
        )
    finally:
        if previous_logdir is None:
            os.environ.pop("LOGDIR", None)
        else:
            os.environ["LOGDIR"] = previous_logdir
    sweep_target_artifacts(target, cell_dir, marked)
    usage = subprocess.run(
        [
            sys.executable, str(SCRIPT_ROOT / "lib" / "llm_usage.py"),
            "extract-usage", backend, str(raw), str(cell_dir / "prompt.txt"),
        ],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    (cell_dir / "logs" / "index.jsonl").write_text(usage.stdout or "{}\n", encoding="utf-8")
    issue = _record_provider_quality(cell_dir, cell_dir, rc)
    if issue == "capacity_limited" and (cell_dir / ".backend-unavailable").is_file():
        return 0
    if backend == "gemini" and not raw.stat().st_size and not _has_artifacts(cell_dir):
        return 44
    return 0 if rc in (0, 124) else rc


def prepare_facade(cell_dir: Path, target_slug: str) -> Path:
    facade = cell_dir / "repo-root"
    shutil.rmtree(facade, ignore_errors=True)
    facade.mkdir(parents=True)
    for name in ("bin", "lib", ".agents", "docs", "schema", "targets"):
        (facade / name).symlink_to(SCRIPT_ROOT / name, target_is_directory=True)
    config_dir = facade / "output" / target_slug
    config_dir.mkdir(parents=True)
    source_config = SCRIPT_ROOT / "output" / target_slug / "target.toml"
    if source_config.is_file():
        shutil.copy2(source_config, config_dir / "target.toml")
    for name in ("AGENTS.md", "CHANGELOG.md", "LICENSE", "README.md", "SECURITY.md", "requirements.txt", ".gitignore"):
        source = SCRIPT_ROOT / name
        if source.exists():
            (facade / name).symlink_to(source)
    return facade


def run_harness(
    cell_dir: Path, target_slug: str, backend: str, model: str,
    experiment: str, wall: int, agents: int | None, skip_recon: bool,
) -> tuple[int, Path]:
    facade = prepare_facade(cell_dir, target_slug)
    target = (SCRIPT_ROOT / "targets" / target_slug).resolve()
    marked = mark_target_artifacts(target)
    result_dir = facade / "output" / f"{target_slug}-{experiment}" / backend / "results"
    command = [str(facade / "bin" / "audit"), "--target", target_slug, "--backend", backend]
    if skip_recon:
        command.append("--skip-recon")
    if model:
        command += ["--model", model]
    command += ["--experiment", experiment]
    environment = os.environ.copy()
    environment["SCRIPT_ROOT"] = str(facade)
    if agents is not None:
        environment["NUM_AGENTS"] = str(agents)
    if wall:
        environment["AUDIT_WALL_BUDGET_SECS"] = str(wall)
    with (cell_dir / "audit.log").open("w", encoding="utf-8") as stream:
        if wall:
            rc = run_timeout(
                command, wall + SESSION_PAUSE_BACKSTOP, cwd=facade,
                env=environment, stdout=stream, stderr=subprocess.STDOUT,
            ).returncode
        else:
            rc = subprocess.run(command, cwd=facade, env=environment, stdout=stream, stderr=subprocess.STDOUT, check=False).returncode
    result_dir.mkdir(parents=True, exist_ok=True)
    sweep_target_artifacts(target, result_dir, marked)
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


def reverify_one_crash(crash_dir: Path, target_root: Path, target_slug: str) -> bool:
    resolved = subprocess.run(
        [sys.executable, str(SCRIPT_ROOT / "lib" / "benchmark.py"), "resolve-reverify",
         str(crash_dir), str(target_root), target_slug],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
    )
    if resolved.returncode:
        return False
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
    testcase = fields.get("TESTCASE", "")
    sanitizer_name = fields.get("SAN", "asan")
    if mode == "none" or not binary:
        return False
    temporary = crash_dir / "sanitizer.txt.reverify.tmp"
    temporary.unlink(missing_ok=True)
    environment = os.environ.copy()
    upper = "ASAN" if sanitizer_name in {"race", "runner"} else sanitizer_name.upper()
    environment.update({
        "SANITIZER_RUNS": "5", "SAN_OUTPUT_FILE": str(temporary),
        f"{upper}_GENERIC_BIN": binary,
    })
    arguments = [testcase, *replay_args] if replay_args else [testcase]
    if mode == "harness":
        arguments = ["/dev/null"]
        environment.update({"ASAN_GENERIC_BIN": binary, "ASAN_GENERIC_SKIP_TESTCASE": "1"})
        sanitizer_name = "asan"
    elif replay_args:
        environment.update({"ASAN_GENERIC_SKIP_TESTCASE": "1", "SANITIZER_GENERIC_SKIP_TESTCASE": "1"})
    subprocess.run(
        [str(SCRIPT_ROOT / "bin" / "run-sanitizer-multi"), sanitizer_name, "generic", *arguments],
        env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
    )
    try:
        measured = temporary.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    finally:
        temporary.unlink(missing_ok=True)
    rate_match = re.search(r"^CRASH_RATE:\s*([0-9]+/[0-9]+)", measured, re.MULTILINE)
    if not rate_match:
        return False
    rate = rate_match.group(1)
    crashes = int(rate.split("/", 1)[0])
    success_match = re.search(r"^\[run-sanitizer-multi\]\s+SUCCESS_RATE:\s*([0-9]+/[0-9]+)", measured, re.MULTILINE)
    clean_runs = int(success_match.group(1).split("/", 1)[0]) if success_match else 0
    if crashes == 0 and clean_runs == 0:
        return False
    note = f"reproduced in {rate} reverification runs" if crashes else "original one-shot trace did not reproduce in 5 reverification runs"
    with (crash_dir / "sanitizer.txt").open("a", encoding="utf-8") as output:
        output.write(f"\nCRASH_RATE: {rate}\n[run-sanitizer-multi] REVERIFY: {rate} - {note}\n")
    return True


def reverify_pool_crash_rates(pool: Path, target_root: Path, target_slug: str, reason: str) -> int:
    reverified = 0
    for crash_dir in sorted((pool / "crashes").glob("CRASH-*")):
        sanitizer_file = crash_dir / "sanitizer.txt"
        if not sanitizer_file.is_file():
            continue
        text = sanitizer_file.read_text(encoding="utf-8", errors="replace")
        if re.search(r"^CRASH_RATE:\s*[0-9]+/[0-9]+", text, re.MULTILINE):
            continue
        if reverify_one_crash(crash_dir, target_root, target_slug):
            reverified += 1
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
    with _decision_environment(backend, model, target_root, target_slug, decision_log):
        for condition in sorted(pool.iterdir()):
            if not condition.is_dir() or condition.name in reserved:
                continue
            if not triage.maintain_indexes(condition, target_root):
                log(f"WARN: per-condition index maintenance failed ({condition.name})")


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
    bundled = 0
    if not dry_run:
        with _decision_environment(
            backend, model, target, target_slug, bench_dir / "llm-decisions.log"
        ):
            triage.fill_reach_fields_tree(pool)
        if (pool / "crashes").is_dir():
            reverify_pool_crash_rates(pool, target, target_slug, reason)
        with (bench_dir / "severity.log").open("w", encoding="utf-8") as output:
            for finding in sorted((pool / "findings").glob("FIND-*")):
                if finding.is_dir():
                    _run_tool("severity", "--report", str(finding), env=environment, stdout=output)
            if (pool / "crashes").is_dir():
                _run_tool("severity", "--batch", str(pool), env=environment, stdout=output)
        for crash in sorted((pool / "crashes").glob("CRASH-*")):
            reports = list(crash.glob("[Rr][Ee][Pp][Oo][Rr][Tt].md"))
            canonical = any(
                "## Expected sanitizer output" in (text := report.read_text(encoding="utf-8", errors="replace"))
                and re.search(r"^CRASH_RATE:\s*[0-9]+/[0-9]+", text, re.MULTILINE)
                for report in reports
            )
            if not canonical:
                export_env = environment | {"RESULTS_DIR": str(pool), "TARGET_ROOT": str(target)}
                if _run_tool("export-repro", crash.name, "--crash-dir", str(crash), "--slug", target_slug, env=export_env) == 0:
                    bundled += 1
    if bundled:
        log(f"reproducer bundles created: {bundled} ({reason})")
    for kind, tool, output_name in (
        ("crashes", "cluster-crashes", "clusters-crashes.json"),
        ("findings", "cluster-findings", "clusters-findings.json"),
    ):
        if not (pool / kind).is_dir():
            continue
        with (bench_dir / output_name).open("w", encoding="utf-8") as output:
            if _run_tool(tool, str(pool), "--json", env=environment, stdout=output):
                output.seek(0)
                output.truncate()
                output.write('{"clusters":[]}\n')
        _run_tool(tool, str(pool), env=environment)
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


def update_result(bench_dir: Path, bench_root: Path, target: str, backend: str, model: str, dry_run: bool, reason: str) -> dict:
    signature = _result_signature(bench_dir)
    signature_key = str(bench_dir.resolve())
    if _RESULT_SIGNATURES.get(signature_key) == signature and (bench_dir / "report.json").is_file():
        log(f"benchmark-result update ({reason}): inputs unchanged, skipped rebuild")
        return json.loads((bench_dir / "report.json").read_text(encoding="utf-8"))
    rebuild_pool(bench_dir, target, backend, model, dry_run, reason)
    report = metrics.aggregate(bench_dir)
    _write_json(bench_dir / "report.json", report)
    crosstab = bench_root / "benchmark-result.md"
    crosstab.write_text(metrics.crosstab(bench_root), encoding="utf-8")
    render = SCRIPT_ROOT / "bin" / "render-md"
    if render.is_file():
        subprocess.run([str(render), str(crosstab), "--html-sibling"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    artifact = crosstab.with_suffix(".html") if crosstab.with_suffix(".html").is_file() else crosstab
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
    crosstab = bench_root / "benchmark-result.md"
    crosstab.write_text(metrics.crosstab(bench_root), encoding="utf-8")
    log(f"Regenerate-all: rebuilt {crosstab} ({len(runs)} run(s), {failures} failed)")
    return 1 if failures else 0


def replace_namespace(namespace: argparse.Namespace, **changes) -> argparse.Namespace:
    values = vars(namespace).copy()
    values.update(changes)
    return argparse.Namespace(**values)


def preflight_build(args: argparse.Namespace, bench_dir: Path, model: str) -> None:
    if args.dry_run or args.regenerate:
        return
    target_root = SCRIPT_ROOT / "targets" / args.target
    config = target_config.Config(target_root=str(target_root))
    try:
        target_config.load_toml_into(
            config, SCRIPT_ROOT / "output" / args.target / "target.toml"
        )
    except (OSError, ValueError) as exc:
        log(f"WARN: sanitizer build preflight could not load target config: {exc}")
        return
    build_preflight.refresh(
        SCRIPT_ROOT, target_root, args.target, config, bench_dir,
        args.backend, model, log,
    )


def run_single(args: argparse.Namespace, bench_root: Path) -> int:
    backend_root = bench_root / args.backend
    ledger = Path(args.ledger).resolve() if args.ledger else backend_root / "benchmark-results.md"
    if args.reset:
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
    lock_name = f".run-{target_key(args.target)}.lock"
    with BenchmarkLock(backend_root / lock_name):
        bench_dir.mkdir(parents=True, exist_ok=True)
        cells_dir.mkdir(parents=True, exist_ok=True)
        console_path = bench_dir / "console.log"
        with console_path.open("a", encoding="utf-8") as console, redirect_stdout(Tee(sys.stdout, console)), redirect_stderr(Tee(sys.stderr, console)):
            return _run_locked(args, bench_root, backend_root, bench_dir, cells_dir, ledger, run_id, conditions)


def _run_locked(args, bench_root, backend_root, bench_dir, cells_dir, ledger, run_id, conditions) -> int:
    model = args.model or llm_invoke.default_model(args.backend)
    llm_invoke.apply_memory_policy(False)
    if not args.regenerate:
        run_data = {
            "runid": run_id, "target": args.target, "backend": args.backend,
            "model": model, "replicates": args.replicates,
            "budget_wall": args.budget_wall, "harness_agents": args.agents,
            "model_direct_agents": 1, "conditions": conditions,
            "skip_recon": args.skip_recon,
            "target_sha": target_config.detect_rev(SCRIPT_ROOT / "targets" / args.target),
            "tokenfuzz_sha": _git_rev(SCRIPT_ROOT), "harness_sha": _git_rev(SCRIPT_ROOT, True),
            "dry_run": args.dry_run,
        }
        _write_json(bench_dir / "run.json", run_data)
        budget = "unlimited" if not args.budget_wall else f"{format_duration(args.budget_wall)} per cell"
        log(f"Benchmark run {run_id}: target={args.target} backend={args.backend} model={model or '?'} replicates={args.replicates} budget={budget}")
        log(f"Conditions: {','.join(conditions)}")
        if args.dry_run:
            log("Dry run: synthetic cells, no LLM calls")
        if args.skip_recon:
            log("Harness recon: skipped (--skip-recon)")
    else:
        log(f"Regenerating run {run_id}: target={args.target} backend={args.backend} (no cells launched)")
    log(f"Output: {bench_dir}")

    preflight_build(args, bench_dir, model)

    done = failed = 0
    provider_unavailable = False
    if not args.regenerate:
        for condition in conditions:
            for replicate in range(1, args.replicates + 1):
                name = f"{condition}-r{replicate}"
                cell_dir = cells_dir / name
                cell_json = cell_dir / "cell.json"
                try:
                    if json.loads(cell_json.read_text(encoding="utf-8")).get("status") == "done":
                        log(f"Cell {name}: already done, skipping")
                        done += 1
                        continue
                except (OSError, ValueError):
                    pass
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
                write_cell(cell_json, condition, replicate, experiment, predicted, 0, "running", args.agents)
                start = time.monotonic()
                status = "done"
                if args.dry_run:
                    results = dryrun_cell(cell_dir, condition, replicate)
                    rc = 0
                elif condition == "model-direct":
                    log(f"Cell {name} live log: {(cell_dir / 'backend.raw.log').resolve()}")
                    results = cell_dir
                    rc = run_model_direct(cell_dir, (SCRIPT_ROOT / "targets" / args.target).resolve(), args.backend, model, args.budget_wall)
                else:
                    log(f"Cell {name} live log: {(cell_dir / 'audit.log').resolve()}")
                    rc, results = run_harness(cell_dir, args.target, args.backend, model, experiment, args.budget_wall, args.agents, args.skip_recon)
                if (cell_dir / ".backend-unavailable").exists():
                    status = "incomplete"
                    provider_unavailable = True
                elif rc:
                    status = "failed"
                paused = 0
                try:
                    paused = int((results.parent / "logs" / ".paused_secs").read_text().strip())
                except (OSError, ValueError):
                    pass
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
                        )
                        paused += counts.get("paused_seconds", 0)
                        log(
                            f"Cell {name} validation: accepted={counts.get('accepted', 0)} "
                            f"rejected={counts.get('rejected', 0)} pending={counts.get('pending', 0)}"
                        )
                        if counts.get("pending", 0):
                            status = "incomplete"
                    except Exception as exc:
                        log(f"WARN: find-gate drain failed for {name}: {exc}")
                elif not args.dry_run and condition == "model-direct" and not args.validate_findings:
                    log(f"Cell {name} validation: DISABLED (--no-validate-findings)")
                wall = int(time.monotonic() - start)
                if results.is_dir():
                    _write_json(cell_dir / "metrics.json", metrics.harvest(results, args.backend, model))
                else:
                    _write_json(cell_dir / "metrics.json", {"exists": False})
                    status = "failed"
                write_cell(cell_json, condition, replicate, experiment, results, wall, status, args.agents, paused)
                if condition == "model-direct":
                    cleanup_model_direct_scratch(cell_dir)
                summary = metrics.harvest(results, args.backend, model) if results.is_dir() else {}
                log(
                    f"Cell {name} findings: rejected={summary.get('findings_rejected', 0)} "
                    f"confirmed={summary.get('findings', 0)} unique={summary.get('finding_clusters', 0)}; "
                    f"crashes: rejected={summary.get('crashes_rejected', 0)} "
                    f"confirmed={summary.get('confirmed_crashes', 0)} unique={summary.get('crash_clusters', 0)}"
                )
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
                    log(f"Cell {name} {status} after {format_duration(wall)}; see {cell_dir}")
                update_result(bench_dir, bench_root, args.target, args.backend, model, args.dry_run, f"after {name}")
        log(f"Cells complete: {done} done, {failed} failed")
    else:
        refreshed = 0
        for cell_dir in cells_dir.iterdir():
            try:
                cell = json.loads((cell_dir / "cell.json").read_text(encoding="utf-8"))
                results = Path(cell.get("results_dir", ""))
            except (OSError, ValueError):
                continue
            if results.is_dir():
                if args.validate_findings and (results / "findings").is_dir():
                    log(f"Regenerate: draining find-gate for {cell_dir.name} ({cell.get('condition', '?')})")
                    try:
                        drain_find_gate(
                            results, args.backend, model,
                            (SCRIPT_ROOT / "targets" / args.target).resolve(), args.target,
                        )
                    except Exception as exc:
                        log(f"WARN: find-gate drain failed for {cell_dir.name}: {exc}")
                _write_json(cell_dir / "metrics.json", metrics.harvest(results, args.backend, model))
                remaining = metrics.harvest(results, args.backend, model).get("findings_unadjudicated", 0)
                if args.validate_findings and remaining:
                    log(f"WARN: {cell_dir.name} has {remaining} finding(s) still un-adjudicated after drain")
                refreshed += 1
        log(f"Regenerate: re-derived metrics from {refreshed} cell(s)")

    report = update_result(bench_dir, bench_root, args.target, args.backend, model, args.dry_run, "pre-ledger")
    section = metrics.render_section(report)
    metrics.append_to_ledger(ledger, section)
    render = SCRIPT_ROOT / "bin" / "render-md"
    if render.is_file() and ledger.is_file():
        subprocess.run([str(render), str(ledger), "--html-sibling"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
    print()
    log(f"Run {run_id} summary:")
    for condition in report.get("conditions", []):
        print(
            f"  {condition.get('condition')}: crash median={condition.get('crash_median', 0)} "
            f"finding total={condition.get('confirmed_finding_total', 0)}"
        )
    print()
    log(f"Ledger: {ledger}")
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
            failures += run_single(replace_namespace(args, target=target, run_id=run_id), bench_root) != 0
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
