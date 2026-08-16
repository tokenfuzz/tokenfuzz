#!/usr/bin/env python3
"""Parallel structured-state audit orchestration."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import fcntl
import http.server
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import audit_helpers
import build_preflight
import build_config
import build_session_seed
import callgraph
import cluster_common
import housekeeping
import llm_decide
import llm_invoke
import llm_usage
import prompt
import quality
import runner_preflight
import sanitizer_run
import structured_state
import process_tree
import target_config
import target_profile
import triage
import verdict
import vocab_rules
import workqueue
from timeout import run_timeout


STRATEGIES = ("S1", "S2", "S3", "S4", "S5", "S6", "S7", "S8")
STRATEGY_DRY_THRESHOLD = 3
STRATEGY_S1_DRY_THRESHOLD = 8
STRATEGY_FORCE_EXTRA = 5
PROVIDER_PAUSE_MAX_SECONDS = 6 * 60 * 60
TRANSIENT_RETRY_MAX = 6
_OWNED_INSTANCE_LOCKS: set[Path] = set()


def _agent_timeout() -> int:
    """Wall ceiling for one agent session, and for one pool epoch."""
    return max(1, int(os.environ.get("AGENT_TIMEOUT", "7200")))


def log(message: str) -> str:
    line = f"[{time.strftime('%H:%M:%S')}] {message}"
    print(line, flush=True)
    return line


def _append(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as stream:
        fcntl.flock(stream, fcntl.LOCK_EX)
        stream.write(line.rstrip("\n") + "\n")
        stream.flush()
        fcntl.flock(stream, fcntl.LOCK_UN)


def index_log(runtime: "Runtime", message: str) -> None:
    _append(runtime.index, log(message))


def _nonnegative(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be a non-negative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be >= 0")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit",
        description="Run parallel security-audit agents against one configured target.",
    )
    parser.add_argument("max_iterations", nargs="?", type=_nonnegative, default=0)
    parser.add_argument("--target", default="firefox")
    parser.add_argument("--target-path")
    parser.add_argument("--backend", choices=("all", "claude", "codex", "gemini", "grok", "oss"), default=None)
    parser.add_argument("--model", default="")
    parser.add_argument("--experiment", default="")
    parser.add_argument("--strategy", choices=STRATEGIES, default="")
    parser.add_argument("--claude-bin")
    parser.add_argument("--codex-bin")
    parser.add_argument("--gemini-bin")
    parser.add_argument("--grok-bin")
    parser.add_argument("--new-target")
    parser.add_argument("--allow-concurrent", action="store_true")
    parser.add_argument("--enable-memory", action="store_true")
    parser.add_argument(
        "--agent-security", choices=llm_invoke.AGENT_SECURITY_MODES, default=None,
        help="backend execution boundary (default: sandboxed)",
    )
    parser.add_argument(
        "--refill-workers", action=argparse.BooleanOptionalAction, default=True,
        help="relaunch a finished worker slot while an initial session is still running",
    )
    return parser


def _sanitize_experiment(raw: str) -> str:
    value = re.sub(r"[^a-z0-9._-]+", "-", raw.lower()).strip("-")
    if not value:
        raise ValueError("--experiment requires a non-empty name")
    return value


def _backend_command(backend: str) -> list[str]:
    binary = llm_invoke.backend_bin(backend)
    if backend == "claude":
        return [binary, "auth", "status"]
    if backend == "codex":
        return [binary, "login", "status"]
    if backend == "gemini":
        return [binary, "--version"] if llm_invoke.use_gemini_cli() else [binary, "changelog"]
    if backend == "grok":
        return [binary, "models"]
    return [binary, "--version"]


def backend_configured(backend: str) -> bool:
    binary = llm_invoke.backend_bin(backend)
    if not (Path(binary).is_file() or shutil.which(binary)):
        return False
    command = _backend_command(backend)
    try:
        completed = subprocess.run(
            command, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(
            f"WARN: backend preflight failed for {backend} ({command[0]}): {exc}",
            file=sys.stderr,
        )
        return False
    if backend == "grok" and "not authenticated" in completed.stdout.lower():
        return False
    return completed.returncode == 0


def discover_backends() -> list[str]:
    return [backend for backend in ("claude", "codex", "gemini", "grok") if backend_configured(backend)]


def _configure_binaries(args) -> None:
    for backend, value in (
        ("claude", args.claude_bin), ("codex", args.codex_bin),
        ("gemini", args.gemini_bin), ("grok", args.grok_bin),
    ):
        if value:
            os.environ[f"{backend.upper()}_BIN"] = value


def _output_slug(slug: str, experiment: str) -> str:
    return f"{slug}-{_sanitize_experiment(experiment)}" if experiment else slug


def _log_tour(path: Path) -> None:
    readme = path / "README.md"
    if readme.exists():
        return
    readme.write_text(
        "# Log Tour\n\n"
        "- `index.log`: launch, promotion, rejection, and session timeline.\n"
        "- `index.jsonl`: structured session metrics.\n"
        "- `.raw/session_*.log.raw`: complete backend transcripts.\n"
        "- `.raw/session_*.prompt.md`: exact rendered prompts.\n",
        encoding="utf-8",
    )


@dataclass
class Runtime:
    root: Path
    target_root: Path
    target_slug: str
    output_slug: str
    backend: str
    model: str
    config: target_config.Config
    target_rev: str
    repo_type: str
    results: Path
    logs: Path
    raw: Path
    index: Path
    index_jsonl: Path
    num_agents: int
    browser_agents: int
    shell_agents: int
    agent_roles: tuple[str, ...]
    fixed_strategy: str
    decision_timeout: int  # operator's explicit ceiling; 0 when they set none
    refill_workers: bool = True
    agent_security: str = llm_invoke.DEFAULT_AGENT_SECURITY
    cluster_expansion_attempted: set[Path] = field(default_factory=set, repr=False)

    def prompt_context(self, guide: str) -> prompt.PromptContext:
        return prompt.PromptContext(
            results_dir=self.results,
            target_root=self.target_root,
            target_slug=self.target_slug,
            reference_dir=self.root / ".agents" / "references",
            num_agents=self.num_agents,
            is_browser=self.config.is_browser in ("1", "true", "True"),
            browser_agents=self.browser_agents,
            agent_roles=self.agent_roles,
            repo_type=self.repo_type,
            guide_text=guide,
            fixed_strategy=self.fixed_strategy,
            turn_soft_cap=_turn_cap(),
            config=self.config,
        )


def _load_config(
    root: Path, target_root: Path, output_root: Path, target_slug: str
) -> target_config.Config:
    config_path = output_root / "target.toml"
    if not config_path.is_file():
        base_config = root / "output" / target_slug / "target.toml"
        if base_config.is_file() and base_config != config_path:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(base_config, config_path)
        else:
            target_config.seed_toml(target_root, config_path)
    config = target_config.Config(target_root=str(target_root))
    target_config.load_toml_into(config, config_path)
    return config


def _agent_counts(config: target_config.Config, max_iterations: int) -> tuple[int, int, int]:
    page_browser = (
        config.is_browser in ("1", "true", "True")
        and target_config.browser_page_launch_configured(config)
    )
    if max_iterations == 1:
        browser = int(page_browser)
        return 1, browser, 1 - browser
    explicit = os.environ.get("NUM_AGENTS")
    if explicit:
        total = max(1, int(explicit))
        return total, 0, total
    if config.is_browser in ("1", "true", "True"):
        browser = (
            max(0, int(os.environ.get("BROWSER_AGENTS", "1")))
            if page_browser else 0
        )
        shell_default = "2" if page_browser else "3"
        shell = max(0, int(os.environ.get("SHELL_AGENTS", shell_default)))
        return max(1, browser + shell), browser, shell
    total = max(1, int(os.environ.get("SHELL_AGENTS", "3")))
    return total, 0, total


def _agent_roles(total: int) -> tuple[str, ...]:
    raw = os.environ.get("AGENT_ROLES", "").strip()
    if not raw:
        return ()
    roles = tuple(value.strip().lower() for value in raw.split(","))
    if len(roles) != total or any(role not in ("analysis", "reproduce") for role in roles):
        raise ValueError(
            f"AGENT_ROLES must contain exactly {total} comma-separated analysis/reproduce values"
        )
    return roles


def prepare_runtime(
    root: Path, target_root: Path, target_slug: str, output_slug: str,
    backend: str, model_override: str, fixed_strategy: str,
    max_iterations: int, decision_timeout_override: str | None = None,
    refill_workers: bool = True,
    agent_security: str = llm_invoke.DEFAULT_AGENT_SECURITY,
) -> Runtime:
    output_root = root / "output" / output_slug
    config = _load_config(root, target_root, output_root, target_slug)
    results = output_root / backend / "results"
    logs = output_root / backend / "logs"
    raw = logs / ".raw"
    for directory in (
        results, logs, raw, results / "crashes", results / "crashes-rejected",
        results / "findings", results / "findings-rejected", results / "state",
        results / "corpus",
    ):
        directory.mkdir(parents=True, exist_ok=True)
    model = llm_invoke.resolve_model_name(backend, model_override)
    total, browser, shell = _agent_counts(config, max_iterations)
    roles = _agent_roles(total)
    for agent in range(1, total + 1):
        (results / f"scratch-{agent}").mkdir(exist_ok=True)
        if fixed_strategy:
            (results / "state" / f"strategy-{agent}").write_text(fixed_strategy + "\n", encoding="utf-8")
    target_rev = target_config.detect_rev(target_root)
    repo_type = target_config.detect_repo_type(target_root)
    target_config.write_session_env(results, str(results), str(target_root), target_slug, target_rev, str(logs))
    _write_run_config(
        results / "state" / "run-config.json", total, browser, shell,
        backend, model, target_slug, agent_security,
    )
    _log_tour(logs)
    runtime = Runtime(
        root, target_root, target_slug, output_slug, backend, model, config,
        target_rev, repo_type,
        results, logs, raw, logs / "index.log", logs / "index.jsonl",
        total, browser, shell, roles, fixed_strategy,
        _operator_decision_timeout(decision_timeout_override),
        refill_workers, agent_security,
    )
    _activate_runtime(runtime)
    return runtime


def _activate_runtime(runtime: Runtime) -> None:
    os.environ.update(
        RESULTS_DIR=str(runtime.results), TARGET_ROOT=str(runtime.target_root),
        TARGET_SLUG=runtime.target_slug, TARGET_REV=runtime.target_rev,
        TARGET_REPO_TYPE=runtime.repo_type, LOGDIR=str(runtime.logs),
        ACTIVE_BACKEND=runtime.backend, BACKEND=runtime.backend, MODEL=runtime.model,
        IS_BROWSER_TARGET="1" if runtime.config.is_browser in ("1", "true", "True") else "0",
        TARGET_ATTACKER_CONTROLS_CSV=runtime.config.attacker_controls_csv(),
        LLM_DECIDE_LOG=str(runtime.logs / "llm-decisions.log"),
        LLM_DECIDE_COUNTER_FILE=str(runtime.logs / ".llm_decisions_harness"),
    )
    os.environ[llm_invoke.AGENT_SECURITY_ENV] = runtime.agent_security
    try:
        config_digest = target_config.read_session_env(runtime.results).get(
            "TARGET_CONFIG_SHA256", "",
        )
    except (OSError, ValueError):
        config_digest = ""
    if config_digest:
        os.environ["TARGET_CONFIG_SHA256"] = config_digest
    else:
        # A runtime activated before config pinning, or one with no pin, must
        # not inherit another runtime's publication scope.
        os.environ.pop("TARGET_CONFIG_SHA256", None)
    # Export only a real operator choice. Writing a resolved tier default back
    # would read downstream as an explicit setting and suppress the longer
    # per-decision defaults; clearing it when there is no choice keeps a value
    # from an earlier runtime in this process from leaking into this one.
    if runtime.decision_timeout:
        os.environ["LLM_DECISION_TIMEOUT"] = str(runtime.decision_timeout)
    else:
        os.environ.pop("LLM_DECISION_TIMEOUT", None)
    os.environ.update(llm_invoke.memory_env(runtime.backend))


def _operator_decision_timeout(override: str | None) -> int:
    """Validate an explicit decision ceiling; 0 when the operator set none.

    Zero is not a fallback default — it records "no operator choice", which
    leaves lib/llm_decide.py free to apply its per-decision defaults. Resolving
    a tier default here instead would be indistinguishable downstream from an
    operator who asked for exactly the tier ceiling.
    """
    if override in (None, ""):
        return 0
    if not str(override).isdigit() or int(override) <= 0:
        raise ValueError(
            f"LLM_DECISION_TIMEOUT must be a positive integer number of seconds (got {override!r})"
        )
    return int(override)


def validate_model(runtime: Runtime) -> None:
    """Exercise the requested model through the same tool-capable launch path.

    CLI auth/version checks cannot detect an invalid model selection, and an
    OSS model that can chat but cannot read files is unusable for an audit.
    Keep this probe small and bounded; failed transcripts remain on disk for
    diagnosis. Offline/mock runs may disable the probe before launch.
    """
    if os.environ.get("AUDIT_MODEL_PREFLIGHT", "1") == "0":
        return
    try:
        default_timeout = "300" if runtime.backend == "gemini" and llm_invoke.use_gemini_cli() else "60"
        timeout_secs = int(os.environ.get("AUDIT_MODEL_PREFLIGHT_TIMEOUT", default_timeout))
        attempts = int(os.environ.get("AUDIT_MODEL_PREFLIGHT_ATTEMPTS", "3"))
    except ValueError as exc:
        raise ValueError("model preflight timeout and attempts must be integers") from exc
    if timeout_secs <= 0 or attempts <= 0:
        raise ValueError("model preflight timeout and attempts must be positive")

    preflight_dir = runtime.logs / ".preflight"
    preflight_dir.mkdir(parents=True, exist_ok=True)
    raw = runtime.raw / f"model-preflight-{runtime.backend}-{os.getpid()}-{time.time_ns()}.raw"
    prompt_text = (runtime.root / "lib/prompts/model_preflight.md.j2").read_text(encoding="utf-8")
    expected = "MODEL_PREFLIGHT_OK"
    if runtime.backend == "oss":
        token = f"OSS_TOOL_PREFLIGHT_OK_{os.getpid()}_{time.time_ns()}"
        (preflight_dir / "oss-tool-sentinel.txt").write_text(token + "\n", encoding="utf-8")
        prompt_text = (runtime.root / "lib/prompts/oss_tool_preflight.md.j2").read_text(encoding="utf-8")
        expected = token

    last_rc = 1
    agy_log = (
        raw.with_suffix(".agylog")
        if runtime.backend == "gemini" and not llm_invoke.use_gemini_cli()
        else None
    )
    prior_agy_log = os.environ.get("AGY_LOG_FILE")
    if agy_log is not None:
        os.environ["AGY_LOG_FILE"] = str(agy_log)
    try:
        for attempt in range(1, attempts + 1):
            last_rc = llm_invoke.run_agent_prompt(
                runtime.backend, prompt_text, timeout_secs, raw,
                model=runtime.model, max_turns=6 if runtime.backend == "oss" else 1,
                add_dirs=str(preflight_dir if runtime.backend == "oss" else runtime.root),
                cwd=preflight_dir if runtime.backend == "oss" else runtime.root,
                agent_security=runtime.agent_security,
            )
            llm_usage.append_usage_event(
                getattr(runtime, "index_jsonl", runtime.logs / "index.jsonl"),
                backend=runtime.backend, model=runtime.model,
                kind="model-preflight", prompt_text=prompt_text, raw_path=raw,
                usage_complete=last_rc == 0,
            )
            try:
                response = llm_invoke.extract_text(runtime.backend, str(raw)).strip()
            except (OSError, ValueError):
                response = ""
            tool_ok = runtime.backend != "oss" or llm_invoke.raw_has_tool(str(raw), "read")
            unresolved_model = bool(
                agy_log is not None and agy_log.is_file()
                and "Failed to resolve model flag" in agy_log.read_text(encoding="utf-8", errors="replace")
            )
            if unresolved_model:
                last_rc = 45
                break
            response_ok = (
                response == expected
                if runtime.backend in {"gemini", "grok", "oss"}
                else True
            )
            if last_rc == 0 and tool_ok and response_ok:
                raw.unlink(missing_ok=True)
                if agy_log is not None:
                    agy_log.unlink(missing_ok=True)
                index_log(runtime, f"Model preflight passed: backend={runtime.backend} model={runtime.model}")
                return
            if attempt < attempts:
                # Provider startup and authentication failures benefit from a
                # short retry delay, but this is harness policy rather than an
                # operator tuning surface.
                time.sleep(min(15 * (4 ** (attempt - 1)), 60))
    finally:
        if agy_log is not None:
            if prior_agy_log is None:
                os.environ.pop("AGY_LOG_FILE", None)
            else:
                os.environ["AGY_LOG_FILE"] = prior_agy_log
        if runtime.backend == "oss":
            (preflight_dir / "oss-tool-sentinel.txt").unlink(missing_ok=True)

    message = (
        f"model preflight failed for backend={runtime.backend} model={runtime.model} "
        f"after {attempts} attempt(s) (last exit={last_rc}); transcript: {raw}"
    )
    raise RuntimeError(message)


def _write_run_config(
    path, total, browser, shell, backend, model, slug, agent_security,
) -> None:
    payload = {
        "num_agents": total, "browser_agents": browser, "shell_agents": shell,
        "backend": backend, "model": model,
        "resolved_effort": llm_invoke.default_effort(backend), "target_slug": slug,
        "agent_security": agent_security,
        "agent_count_overridden": bool(os.environ.get("NUM_AGENTS")),
    }
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _release_instance_lock(lock: Path) -> None:
    """Remove the lock dir only if this process still owns it, so a stale-lock
    reclamation by a newer instance is never clobbered."""
    try:
        if (lock / "pid").read_text().strip() == str(os.getpid()):
            shutil.rmtree(lock)
    except OSError:
        pass


@contextmanager
def _terminate_on_signal(lock: Path | None):
    """On SIGTERM/SIGINT/SIGHUP, kill the whole agent subprocess tree and release
    the instance lock before dying. Agents are setsid'd into their own sessions
    (lib/timeout.py), so they are not in our process group and would otherwise
    outlive us for up to AGENT_TIMEOUT, burning provider quota; and the default
    SIGTERM disposition skips the lock-release finally. Handlers run only in the
    main thread — a signal arriving during a blocked pool join is delivered once
    the join is interrupted, after which the killed agents let it complete."""
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def handler(signum, _frame):
        try:
            try:
                process_tree.kill_descendants(os.getpid(), signal.SIGTERM, 1.0)
            except (OSError, subprocess.SubprocessError) as exc:
                print(f"WARN: could not terminate every child process: {exc}", file=sys.stderr)
        finally:
            locks = set(_OWNED_INSTANCE_LOCKS)
            if lock is not None:
                locks.add(lock)
            for owned_lock in locks:
                _release_instance_lock(owned_lock)
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    previous = {}
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            previous[sig] = signal.signal(sig, handler)
        except (OSError, ValueError):
            pass
    try:
        yield
    finally:
        for sig, prior in previous.items():
            try:
                signal.signal(sig, prior)
            except (OSError, ValueError):
                pass


@contextmanager
def instance_lock(runtime: Runtime, allow: bool):
    lock = runtime.logs / ".instance.lock.d"
    if allow:
        with _terminate_on_signal(None):
            yield
        return
    try:
        lock.mkdir()
    except FileExistsError:
        pid_path = lock / "pid"
        try:
            owner = int(pid_path.read_text().strip())
        except (OSError, ValueError) as exc:
            try:
                age = time.time() - lock.stat().st_mtime
            except OSError:
                age = 0
            # mkdir and the owner write cannot be one filesystem operation. A
            # second process that observes a fresh ownerless directory must
            # fail closed instead of deleting a lock still being initialized.
            if age < 30:
                raise RuntimeError(
                    f"another bin/audit instance is initializing the lock for {runtime.logs}"
                ) from exc
            shutil.rmtree(lock)
            lock.mkdir()
        else:
            try:
                os.kill(owner, 0)
            except ProcessLookupError:
                shutil.rmtree(lock)
                lock.mkdir()
            except PermissionError as exc:
                raise RuntimeError(
                    f"another bin/audit instance owns {runtime.logs} (holder PID={owner})"
                ) from exc
            else:
                raise RuntimeError(
                    f"another bin/audit instance is writing to {runtime.logs} (holder PID={owner})"
                )
    try:
        (lock / "pid").write_text(str(os.getpid()) + "\n", encoding="utf-8")
    except OSError:
        shutil.rmtree(lock, ignore_errors=True)
        raise
    _OWNED_INSTANCE_LOCKS.add(lock)
    try:
        with _terminate_on_signal(lock):
            yield
    finally:
        _release_instance_lock(lock)
        _OWNED_INSTANCE_LOCKS.discard(lock)


def _queue_context(runtime: Runtime) -> workqueue.Context:
    return workqueue.Context(
        runtime.root, runtime.target_root, runtime.target_slug, runtime.results,
        runtime.repo_type,
    )


def _work_card_signature(
    runtime: Runtime, *, source_signature: str | None = None,
) -> str:
    # rank-work consumes source, coverage, and corpus state—not target.toml.
    # Browser mode and attacker controls are explicit housekeeping fields; S6
    # peer selection is the only remaining config input. Hash those parsed
    # values by content so an asan_bin repair or cosmetic rewrite does not
    # force a whole-repo source scan, which takes minutes on browser trees.
    inputs: list[str] = []
    inputs.extend(str(path) for path in sorted((runtime.results / "coverage").glob("edges-agent-*.journal")))
    inputs.extend(str(path) for path in sorted((runtime.results / "corpus").glob("COVER-*/metadata.md")))
    # The call-neighbourhood graph keys on inputs this signature does not see
    # — the sanitizer route, the built artifact, the parser version. Without
    # this the gate can return before rank-work runs, so installing trailmark
    # or retargeting a binary never rebuilds the graph. Empty when the
    # analysis is unavailable, which is the common case and changes nothing.
    callgraph_signature = callgraph.cache_signature(runtime.target_root, runtime.results)
    config = getattr(runtime, "config", None)
    rank_config = json.dumps(
        {
            "s6_domain": getattr(config, "s6_domain", ""),
            "s6_peers": getattr(config, "s6_peers", []),
        },
        sort_keys=True, separators=(",", ":"),
    )
    if source_signature is None:
        source_signature = target_config.vcs_source_signature(
            runtime.target_root, include_untracked=False,
        )
    return housekeeping.signature(
        "work-cards-refresh", inputs,
        f"{source_signature or runtime.target_rev}\nrank_config={rank_config}"
        f"\ncallgraph={callgraph_signature}",
    )


def _base_rank_work_limit() -> int:
    raw = os.environ.get("RANK_WORK_LIMIT", "120")
    if not raw.isdigit() or int(raw) <= 0:
        raise ValueError(f"RANK_WORK_LIMIT must be a positive integer (got {raw!r})")
    return int(raw)


def _rank_window_path(runtime: Runtime) -> Path:
    return runtime.results / "state" / "rank-work-window.json"


def _rank_window(runtime: Runtime) -> tuple[int, int]:
    try:
        row = json.loads(_rank_window_path(runtime).read_text(encoding="utf-8"))
        limit = int(row.get("limit", 0))
        core_count = int(row.get("core_count", 0))
        if limit > 0 and core_count >= 0:
            return limit, core_count
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        pass
    return _base_rank_work_limit(), 0


def _write_rank_window(runtime: Runtime, limit: int) -> None:
    cards = workqueue.read_jsonl(runtime.results / "work-cards.jsonl")
    core_count = sum(card.get("kind") != "s6-peer-fix" for card in cards)
    path = _rank_window_path(runtime)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps({"limit": limit, "core_count": core_count}, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def refresh_work_cards(
    runtime: Runtime, *, force: bool = False, limit: int | None = None,
) -> bool:
    _activate_runtime(runtime)
    workqueue.init_state(_queue_context(runtime))
    source_signature = target_config.vcs_source_signature(
        runtime.target_root, include_untracked=False,
    )
    signature = _work_card_signature(
        runtime, source_signature=source_signature,
    )
    # A VCS signature includes both the revision and tracked working-tree
    # content. With that complete identity, age alone cannot make ranking
    # stale; plain trees retain housekeeping's periodic safety refresh.
    ttl = 0 if source_signature else None
    if not force and not housekeeping.should_run(
        "work-cards-refresh", signature, ttl=ttl,
    ):
        return False
    rank_limit = limit if limit is not None else _rank_window(runtime)[0]
    if rank_limit <= 0:
        raise ValueError("rank-work limit must be positive")
    refresh_ok = True
    patch_cards = runtime.results / "patch-cards.jsonl"
    if (runtime.root / "bin" / "patch-cards").is_file():
        completed = subprocess.run(
            [str(runtime.root / "bin" / "patch-cards"), "--target-path", str(runtime.target_root),
             "--target-slug", runtime.target_slug, "--results-dir", str(runtime.results),
             "--limit", str(rank_limit), "--output", str(patch_cards), "--quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        if completed.returncode:
            patch_cards.unlink(missing_ok=True)
            refresh_ok = False
            index_log(runtime, f"WARN: patch-cards refresh failed rc={completed.returncode}; stale cards removed")
    peer_cards = runtime.root / "bin" / "peer-fix-cards"
    if os.environ.get("AUDIT_DISABLE_PEER_FIX_CARDS") != "1" and peer_cards.is_file():
        completed = subprocess.run(
            [str(peer_cards), "--target-path", str(runtime.target_root),
             "--target-slug", runtime.target_slug, "--results-dir", str(runtime.results),
             "--output", str(runtime.results / "s6-peer-cards.jsonl")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        if completed.returncode:
            (runtime.results / "s6-peer-cards.jsonl").unlink(missing_ok=True)
            refresh_ok = False
            index_log(runtime, f"WARN: peer-fix-cards refresh failed rc={completed.returncode}; stale cards removed")
    rank = runtime.root / "bin" / "rank-work"
    if rank.is_file():
        completed = subprocess.run(
            [str(rank), "--target-path", str(runtime.target_root), "--target-slug", runtime.target_slug,
             "--results-dir", str(runtime.results), "--patch-cards", str(patch_cards),
             "--limit", str(rank_limit),
             "--output", str(runtime.results / "work-cards.jsonl"), "--quiet"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        if completed.returncode:
            (runtime.results / "work-cards.jsonl").unlink(missing_ok=True)
            refresh_ok = False
            index_log(runtime, f"WARN: rank-work refresh failed rc={completed.returncode}; stale cards removed")
    else:
        refresh_ok = False
        index_log(runtime, "WARN: rank-work is missing; work-card refresh remains dirty")
    if refresh_ok:
        _write_rank_window(runtime, rank_limit)
        # Mark the state that was ranked, not the state now: with ttl=0 no
        # periodic re-rank absorbs an input that changed mid-rank. Reusing the
        # decision signature also keeps the source scan to one per refresh.
        housekeeping.mark_clean("work-cards-refresh", signature)
    return True


def expand_work_cards_if_exhausted(runtime: Runtime) -> bool:
    """Grow a fully-consumed ranked batch until the source itself is exhausted."""
    if hasattr(runtime, "prompt_context") and hasattr(runtime, "num_agents"):
        context = runtime.prompt_context("")
        try:
            for agent in range(1, runtime.num_agents + 1):
                if workqueue.claim_next_card(
                    _queue_context(runtime), str(agent), context.mode(agent),
                    context.role(agent), claim=False, strategy=context.strategy(agent),
                ) is not None:
                    return False
        except (OSError, ValueError):
            return False
    else:
        cards = workqueue.apply_latest_claim_status(
            _queue_context(runtime),
            workqueue.read_jsonl(runtime.results / "work-cards.jsonl"),
        )
        if any(card.get("status", "unclaimed") == "unclaimed" for card in cards):
            return False
    current, core_count = _rank_window(runtime)
    if core_count < current:
        return False
    # Stop naturally when rank-work returns fewer core cards than requested;
    # a fixed maximum would silently truncate unusually large targets.
    next_limit = current + _base_rank_work_limit()
    index_log(
        runtime,
        f"BATCH_EXHAUSTED: no eligible cards in rank window {current}; expanding to {next_limit}",
    )
    refresh_work_cards(runtime, force=True, limit=next_limit)
    return True


def _eligible_strategy_counts(runtime: Runtime) -> dict[str, int]:
    ctx = _queue_context(runtime)
    cards = workqueue.apply_latest_claim_status(
        ctx, workqueue.read_jsonl(runtime.results / "work-cards.jsonl")
    )
    counts = {strategy: 0 for strategy in STRATEGIES}
    for card in cards:
        if card.get("status", "unclaimed") != "unclaimed":
            continue
        strategies = {str(card.get("strategy", "")).upper()}
        allowed = card.get("allowed_strategies") or []
        if isinstance(allowed, list):
            strategies.update(str(value).upper() for value in allowed)
        for strategy in strategies:
            if strategy in counts:
                counts[strategy] += 1
    return counts


def initialize_agent_strategies(runtime: Runtime) -> None:
    if runtime.fixed_strategy:
        return
    counts = _eligible_strategy_counts(runtime)
    # Card supply first — an agent pinned to a starved strategy stalls — then
    # expected yield. The tie-break carries the whole decision whenever the
    # queue gives every strategy a comparable share, and canonical numbering
    # would then hand the opening portfolio to the lowest-numbered methods
    # rather than the most productive ones.
    ranked = sorted(
        (strategy for strategy in STRATEGIES[1:] if counts[strategy]),
        key=lambda strategy: (
            -counts[strategy],
            workqueue.expected_yield_rank(strategy),
            STRATEGIES.index(strategy),
        ),
    ) or ["S1"]
    state = runtime.results / "state"
    state.mkdir(parents=True, exist_ok=True)
    for agent in range(1, runtime.num_agents + 1):
        path = state / f"strategy-{agent}"
        try:
            current = path.read_text(encoding="utf-8").strip().upper()
        except OSError:
            current = ""
        if current not in STRATEGIES:
            path.write_text(ranked[(agent - 1) % len(ranked)] + "\n", encoding="utf-8")


def _strategy_streak_path(runtime: Runtime, agent: int) -> Path:
    return runtime.results / f".agent_strategy_streak_{agent}"


def _read_streak(runtime: Runtime, agent: int) -> int:
    try:
        return max(0, int(_strategy_streak_path(runtime, agent).read_text().strip()))
    except (OSError, ValueError):
        return 0


def _write_streak(runtime: Runtime, agent: int, value: int) -> None:
    _strategy_streak_path(runtime, agent).write_text(str(max(0, value)) + "\n", encoding="utf-8")


@dataclass(frozen=True)
class AgentProgress:
    active: int
    env_blocked: int
    roots: frozenset[str]


def update_strategy_rotation(
    runtime: Runtime, context: prompt.PromptContext,
    after_progress: dict[int, AgentProgress],
    productive_agents: set[int],
) -> None:
    if runtime.fixed_strategy:
        return
    counts = _eligible_strategy_counts(runtime)
    assigned = {context.strategy(agent) for agent in range(1, runtime.num_agents + 1)}
    ctx = _queue_context(runtime)
    for agent in range(1, runtime.num_agents + 1):
        after = after_progress[agent]
        productive = agent in productive_agents
        streak = 0 if productive else _read_streak(runtime, agent)
        if not productive:
            streak += 1
        _write_streak(runtime, agent, streak)
        current = context.strategy(agent)
        threshold = STRATEGY_S1_DRY_THRESHOLD if current == "S1" else STRATEGY_DRY_THRESHOLD
        if streak < threshold or after.active:
            continue
        completion = workqueue.strategy_completion_status(ctx, str(agent), current)
        if not completion["complete"] and streak < threshold + STRATEGY_FORCE_EXTRA:
            continue
        alternatives = [
            strategy for strategy in STRATEGIES
            if strategy != current and counts[strategy]
        ]
        if not alternatives:
            following = STRATEGIES.index(current) + 1 if current in STRATEGIES else 0
            alternatives = [STRATEGIES[following % len(STRATEGIES)]]
        alternatives.sort(
            key=lambda strategy: (
                strategy in assigned, -counts[strategy],
                STRATEGIES.index(strategy),
            )
        )
        selected = alternatives[0]
        (runtime.results / "state" / f"strategy-{agent}").write_text(selected + "\n", encoding="utf-8")
        assigned.discard(current)
        assigned.add(selected)
        _write_streak(runtime, agent, 0)
        index_log(
            runtime,
            f"STRATEGY_ROTATION: agent={agent} {current}->{selected} dry={streak} "
            f"evidence={completion['evidence']}/{completion['threshold']} cards={counts[selected]}",
        )


def update_subsystem_dry_streaks(
    runtime: Runtime,
    productive_agents: set[int],
) -> None:
    """Record one dry/productive outcome for each subsystem touched this pass."""
    ctx = _queue_context(runtime)
    outcomes: dict[str, bool] = {}
    for agent in range(1, runtime.num_agents + 1):
        subsystem, file = workqueue.agent_current_scopes(ctx, str(agent))
        productive = agent in productive_agents
        # Two keys, two questions: the subsystem ages an area for the
        # productive-relaxation decay, the file ages the one ranked source a
        # broad card actually covers. Sharing one key made a sibling's dry
        # pass retire a productive card on a file nobody had touched.
        for scope in (subsystem, workqueue.card_dry_scope({"file": file}) if file else ""):
            if not scope:
                continue
            outcomes[scope] = outcomes.get(scope, False) or productive
    for subsystem, productive in outcomes.items():
        if not workqueue.record_subsystem_iteration(ctx, subsystem, productive):
            index_log(runtime, f"WARN: could not update dry streak for subsystem {subsystem}")


def _session_files(prompt_text: str, scratch: Path) -> str:
    return (
        prompt_text
        + "\n\n## SESSION FILES\n\n"
        + f"Keep every working file — testcases, seeds, fuzzing scripts, corpora, crash "
        f"dumps — under `{scratch}`, and run every testcase through `bin/probe`. Never "
        f"write to `/tmp` or other shared temp: those escape the results tree, survive "
        f"into later cells, and let one run inherit another run's corpus.\n"
    )


@dataclass
class AgentResult:
    agent: int
    role: str
    returncode: int
    raw: Path
    text: Path
    usage: dict
    provider_issue: str
    reset_at: int | None
    # Cut off mid-investigation at the rollover target, so its state carries
    # in-flight work that the slot's next session is meant to continue.
    turn_capped: bool = False


def sanitizer_run_budget(
    context: prompt.PromptContext, agent: int, environment: dict[str, str] | None = None,
) -> int:
    env = os.environ if environment is None else environment
    value = env.get("SANITIZER_RUN_BUDGET_PER_ITERATION")
    if value is None:
        key, default = (
            ("BROWSER_SANITIZER_RUN_BUDGET", "25")
            if context.mode(agent) == "browser"
            else ("SHELL_SANITIZER_RUN_BUDGET", "60")
        )
        value = env.get(key, default)
    if not value.isdigit() or int(value) < 1:
        raise ValueError(f"invalid sanitizer run budget: {value!r}")
    return int(value)


def reset_sanitizer_run_counters(runtime: Runtime) -> None:
    for agent in range(1, runtime.num_agents + 1):
        (runtime.logs / f".sanitizer_runs_{agent}").write_text("0", encoding="utf-8")


def reset_llm_decision_counters(runtime: Runtime) -> None:
    """Give each iteration an independent bounded decision budget."""
    paths = [runtime.logs / ".llm_decisions_harness"]
    paths.extend(
        runtime.logs / f".llm_decisions_{agent}"
        for agent in range(1, runtime.num_agents + 1)
    )
    for path in paths:
        path.write_text("0", encoding="utf-8")


def _turn_cap() -> int:
    """Rollover target for one audit-agent session.

    Native backends count model turns; transcript-polled backends count
    completed tool calls. Cached-input replay grows with session length on
    every provider, so one operator setting controls both safe boundaries.
    Backends without either mechanism receive the target in their prompt.
    0 disables it.
    """
    raw = os.environ.get("TURN_SOFT_CAP", str(prompt.DEFAULT_TURN_SOFT_CAP))
    if not raw.isdigit():
        raise ValueError(f"TURN_SOFT_CAP must be a non-negative integer (got {raw!r})")
    return int(raw)


def _claude_stream_idle_retry_needed(raw_path: Path) -> bool:
    try:
        with raw_path.open(encoding="utf-8", errors="replace") as stream:
            idle = any(
                "Stream idle timeout" in line or "API Error: Stream idle" in line
                for line in stream
            )
        if not idle:
            return False
        with raw_path.open(encoding="utf-8", errors="replace") as stream:
            if audit_helpers._provider_issue_from_lines(stream) != "none":
                return False
        return audit_helpers._count_tools(str(raw_path))["all_tools"] < 2
    except OSError:
        return False


_TOKEN_DISPLAY_BUCKETS = (
    ("in", "input"), ("cache", "cached_input"),
    ("create", "cache_creation"), ("out", "output"),
)


def _token_display(usage: dict, complete: bool) -> str:
    """Render a session's token use as its separate buckets.

    Never one sum. Fresh input, cache writes, cache reads, and output are
    different operations at different prices, and a single figure reads as
    generated content when it is mostly replayed context — which is how a
    context-replay cost was once diagnosed as a prompt-size problem. The same
    shape bin/benchmark prints per cell.
    """
    counts = usage.get("tokens") or {}
    buckets = {label: int(counts.get(key) or 0) for label, key in _TOKEN_DISPLAY_BUCKETS}
    if not any(buckets.values()):
        # Nothing measured and nothing estimated: say so rather than print
        # four zeroes that read as a session which used no tokens.
        return "unknown" if not complete else "0"
    rendered = " ".join(f"{label}:{value}" for label, value in buckets.items())
    estimated = usage.get("estimated") is True or not complete
    return f"{rendered} (estimated)" if estimated else rendered


def run_agent(
    runtime: Runtime, context: prompt.PromptContext, agent: int,
    iteration: int, cold: bool, timeout_limit: int | None = None,
) -> AgentResult:
    role = context.role(agent)
    launch = "cold-start" if cold else "deep_investigation"
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
    stem = f"session_{stamp}_{launch}-{agent}"
    raw_path = runtime.raw / f"{stem}.log.raw"
    text_path = runtime.logs / f"{stem}.log"
    prompt_path = runtime.raw / f"{stem}.prompt.md"
    base = prompt.cold_start_prompt(context, agent) if cold else prompt.deep_investigation_prompt(context, agent)
    turn_cap = context.turn_soft_cap
    rendered = _session_files(base, context.scratch_dir(agent))
    # Neutralize classifier-hot vocabulary in the assembled prompt, then strip the
    # NOVOCAB sentinels, so a safety classifier does not refuse a benign audit
    # prompt (recall loss). Run once, on the final text, after every framing pass.
    rendered = vocab_rules.strip_markers(vocab_rules.neutralize_string(rendered))
    prompt_path.write_text(rendered, encoding="utf-8")
    timeout = _agent_timeout()
    if timeout_limit is not None:
        timeout = min(timeout, max(1, timeout_limit))
    sanitizer_budget = sanitizer_run_budget(context, agent)
    extra_env = {
        "AGENT_NUM": str(agent),
        "SANITIZER_RUN_COUNTER_FILE": str(runtime.logs / f".sanitizer_runs_{agent}"),
        "SANITIZER_RUN_BUDGET": str(sanitizer_budget),
        "TRIED_INPUTS_LOG": str(runtime.results / f"tried-inputs-{agent}.log"),
        "HITS_LOG_PATH": str(runtime.results / f"hits-{agent}.log"),
        "LLM_DECIDE_COUNTER_FILE": str(runtime.logs / f".llm_decisions_{agent}"),
        # Facade-relative, so a benchmark cell gets this audit's wrappers after
        # the launcher's universal process-safety guards.
        "AGENT_WRAPPERS_PATH": str(runtime.root / "lib" / "wrappers"),
        "SCRIPT_ROOT": str(runtime.root),
    }
    # A marker belongs to one launch only. Failing to clear it must stop the
    # launch; otherwise a stale quota result can misclassify a healthy session.
    quota_marker = context.scratch_dir(agent) / ".quota-exhausted"
    quota_marker.unlink(missing_ok=True)
    launch_started = time.monotonic()

    def invoke(limit: int) -> int:
        return llm_invoke.run_agent_prompt(
            runtime.backend, rendered, limit, raw_path, model=runtime.model,
            max_turns=turn_cap,
            add_dirs=f"{runtime.root},{runtime.target_root},{runtime.results}",
            cwd=runtime.root, extra_env=extra_env,
            watchdog_marker_dir=context.scratch_dir(agent),
            turn_cap=turn_cap,
            agent_security=runtime.agent_security,
        )

    rc = invoke(timeout)
    if runtime.backend == "claude" and _claude_stream_idle_retry_needed(raw_path):
        remaining = timeout - int(time.monotonic() - launch_started)
        if remaining > 0:
            archived = raw_path.with_name(raw_path.name + ".idle-attempt-1")
            os.replace(raw_path, archived)
            quota_marker.unlink(missing_ok=True)
            index_log(
                runtime,
                f"STREAM_IDLE_RETRY: agent={agent} role={role} produced fewer than two tool events; retrying once",
            )
            rc = invoke(remaining)
    try:
        build_session_seed.write_session_seed(
            str(raw_path), str(runtime.results / f".session_seed_{agent}.md")
        )
    except (OSError, ValueError) as exc:
        index_log(runtime, f"WARN: agent {agent} session seed refresh failed: {exc}")
    try:
        extracted = llm_invoke.extract_text(runtime.backend, str(raw_path))
    except (OSError, ValueError):
        extracted = ""
    text_path.write_text(extracted, encoding="utf-8")
    usage = llm_usage.extract_usage(str(raw_path), str(prompt_path), backend=runtime.backend)
    try:
        with raw_path.open(encoding="utf-8", errors="replace") as raw_stream:
            issue = audit_helpers._provider_issue_from_lines(raw_stream, quota_marker)
    except OSError:
        issue = "none"
    if (
        issue == "none"
        and runtime.backend == "claude"
        and _claude_stream_idle_retry_needed(raw_path)
    ):
        issue = "transient"
    reset_at = None
    if issue == "capacity_limited":
        try:
            reset_at = audit_helpers._provider_reset_from_text(
                raw_path.read_text(encoding="utf-8", errors="replace")
            )
        except OSError:
            pass
    usage_complete = llm_usage.usage_is_complete(usage, rc)
    turn_capped = llm_invoke.session_turn_capped(raw_path)
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(), "iteration": iteration,
        "agent": agent, "role": role, "backend": runtime.backend, "model": runtime.model,
        "resolved_effort": llm_invoke.default_effort(runtime.backend),
        "usage_complete": usage_complete, "turn_capped": turn_capped,
        "turn_soft_cap": turn_cap,
        "returncode": rc, "provider_issue": issue, "prompt_chars": len(rendered),
        "raw_log": str(raw_path), "text_log": str(text_path), **usage,
    }
    workqueue.append_jsonl(runtime.index_jsonl, event)
    outcome = (
        "turn-capped; continuing from state"
        if turn_capped
        else "deadline-truncated rc=124"
        if rc == 124 and issue == "none"
        else f"finished rc={rc}"
    )
    token_display = _token_display(usage, usage_complete)
    index_log(
        runtime,
        f"Agent {agent} {launch} {outcome} provider={issue} "
        f"tokens={token_display} log={text_path.name}",
    )
    return AgentResult(
        agent, role, rc, raw_path, text_path, usage, issue, reset_at, turn_capped,
    )


def run_agent_guarded(
    runtime: Runtime, context: prompt.PromptContext, agent: int,
    iteration: int, cold: bool, timeout_limit: int | None = None,
) -> AgentResult:
    """Keep one internal worker failure from discarding the other slots' work."""
    try:
        return run_agent(runtime, context, agent, iteration, cold, timeout_limit)
    except Exception as exc:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
        error_path = runtime.raw / f"session_{stamp}_internal-error-{agent}.log.raw"
        try:
            error_path.write_text(traceback.format_exc(), encoding="utf-8")
        except OSError:
            pass
        index_log(
            runtime,
            f"ERROR: agent {agent} internal launch failure: {type(exc).__name__}: {exc}; "
            "other slots and post-iteration triage will continue",
        )
        return AgentResult(
            agent, context.role(agent), 1, error_path, error_path, {}, "internal", None
        )


def _artifact_root_id(directory: Path) -> str:
    cluster = cluster_common.artifact_cluster_id(directory)
    if cluster:
        return cluster
    # Before the first clustering pass, keep unlabelled artifacts distinct.
    # post_iteration stamps the deterministic root id before the next snapshot.
    return directory.name


@dataclass(frozen=True)
class ProgressSnapshot:
    findings: int
    crashes: int
    finding_roots: int
    crash_roots: int
    active: int
    env_blocked: int
    artifact_roots: dict[str, str]


def progress(runtime: Runtime) -> ProgressSnapshot:
    findings, finding_names = benchmark_count_findings(runtime.results / "findings")
    crashes, crash_names = benchmark_count_crashes(runtime.results / "crashes")
    artifact_roots: dict[str, str] = {}
    finding_root_ids: set[str] = set()
    crash_root_ids: set[str] = set()
    for name in finding_names:
        root = _artifact_root_id(runtime.results / "findings" / name)
        artifact_roots[name] = f"finding:{root}"
        finding_root_ids.add(root)
    for name in crash_names:
        root = _artifact_root_id(runtime.results / "crashes" / name)
        artifact_roots[name] = f"crash:{root}"
        crash_root_ids.add(root)
    active = env_blocked = 0
    for agent in range(1, runtime.num_agents + 1):
        counts = structured_state.agent_counts(str(agent), runtime.results) or {}
        active += counts.get("active", 0)
        env_blocked += counts.get("env_blocked", 0)
    return ProgressSnapshot(
        findings, crashes, len(finding_root_ids), len(crash_root_ids),
        active, env_blocked, artifact_roots,
    )


def agent_progress(runtime: Runtime, agent: int, snapshot: ProgressSnapshot) -> AgentProgress:
    counts = structured_state.agent_counts(str(agent), runtime.results) or {}
    roots = {
        snapshot.artifact_roots[status]
        for row in structured_state.agent_rows(str(agent), runtime.results)
        if (status := str(row.get("status", ""))) in snapshot.artifact_roots
    }
    return AgentProgress(
        counts.get("active", 0), counts.get("env_blocked", 0), frozenset(roots)
    )


def newly_introduced_roots(
    before: ProgressSnapshot, after: ProgressSnapshot,
) -> set[str]:
    """Return roots represented only by artifacts accepted this iteration.

    Resolve both old and new artifacts through the *after* snapshot so a first
    clustering pass that replaces directory-name fallbacks with real cluster
    ids cannot manufacture or hide progress.
    """
    old_names = set(before.artifact_roots)
    old_roots_after = {
        root for name, root in after.artifact_roots.items() if name in old_names
    }
    new_roots = {
        root for name, root in after.artifact_roots.items() if name not in old_names
    }
    return new_roots - old_roots_after


def benchmark_count_findings(path: Path):
    import benchmark
    return benchmark.count_admitted_findings(path)


def benchmark_count_crashes(path: Path):
    import benchmark
    return benchmark.count_confirmed_crashes(path)


@contextlib.contextmanager
def _phase_span(spans: list[str], name: str):
    """Record one post_iteration phase's duration.

    Housekeeping has been a single aggregate number, so a barrier that costs a
    fifth of the audit wall could not be attributed to a phase and every
    estimate had to be inferred from decision timestamps. Timing is advisory:
    a span never changes a disposition, and a phase that raises still records
    what it spent before failing.
    """
    started = time.monotonic()
    try:
        yield
    finally:
        spans.append(f"{name}={time.monotonic() - started:.1f}s")


def _log_phase_spans(runtime: Runtime, spans: list[str]) -> None:
    """Publish advisory timing without changing housekeeping's outcome."""
    if not spans:
        return
    try:
        index_log(runtime, "Housekeeping phases: " + " ".join(spans))
    except OSError as exc:
        print(
            f"WARN: housekeeping phase timing could not be recorded: {exc}",
            file=sys.stderr,
        )


def post_iteration(runtime: Runtime, *, deadline: float | None = None) -> None:
    spans: list[str] = []
    try:
        with _phase_span(spans, "crash_triage"):
            crash_counts = triage.triage_crash_dirs(
                runtime.results, runtime.target_root, runtime.target_slug,
                runtime.config.attacker_controls, workers=runtime.num_agents,
                findings_only=runtime.config.sanitizers_explicitly_disabled,
                deadline=deadline,
            )
        with _phase_span(spans, "finding_gate"):
            finding_counts = triage.validate_find_gate(
                runtime.results, workers=runtime.num_agents, deadline=deadline,
            )
        if deadline is not None and time.monotonic() >= deadline:
            index_log(
                runtime,
                "Housekeeping: productive wall budget reached during result triage; "
                "remaining index work deferred",
            )
            return
        with _phase_span(spans, "cluster_expand"):
            cluster_counts = expand_new_crash_clusters(runtime, deadline=deadline)
        if deadline is not None and time.monotonic() >= deadline:
            index_log(
                runtime,
                "Housekeeping: productive wall budget reached during cluster expansion; "
                "remaining index work deferred",
            )
            return
        with _phase_span(spans, "indexes"):
            maintain_local_indexes(runtime)
            maintain_aggregate_indexes(runtime)
        with _phase_span(spans, "orphan_enforce"):
            enforced = enforce_orphan_testcases(runtime, deadline=deadline)
        with _phase_span(spans, "corpus_promote"):
            promoted = promote_corpus(runtime)
        index_log(
            runtime,
            f"Housekeeping: crashes promoted={crash_counts['promoted']} rejected={crash_counts['rejected']} "
            f"pending={crash_counts['pending']} demoted={crash_counts['demoted']} "
            f"findings accepted={finding_counts['accepted']} rejected={finding_counts['rejected']} "
            f"pending={finding_counts['pending']} cluster_added={cluster_counts['added']} "
            f"orphans_enforced={enforced} corpus_promoted={promoted}",
        )
    finally:
        _log_phase_spans(runtime, spans)


def _write_cluster_marker(path: Path) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text("expanded\n", encoding="utf-8")
    os.replace(temporary, path)


def _migrate_cluster_backlog(runtime: Runtime) -> None:
    sentinel = runtime.results / "state" / ".cluster-expand-backlog-done"
    if sentinel.is_file():
        return
    index = runtime.results / "crashes" / "CRASH-CLUSTERS.md"
    try:
        indexed = set(re.findall(r"\bCRASH-[A-Za-z0-9._-]+", index.read_text(encoding="utf-8")))
    except OSError:
        indexed = set()
    for crash in sorted((runtime.results / "crashes").glob("CRASH-*")):
        if crash.is_dir() and crash.name in indexed:
            _write_cluster_marker(crash / ".cluster_expanded")
    _write_cluster_marker(sentinel)


def expand_new_crash_clusters(
    runtime: Runtime, *, deadline: float | None = None,
) -> dict[str, int]:
    """Expand each newly accepted crash once and queue its concrete siblings.

    Every crash on disk is expanded, including one the review placed outside
    the threat model. Expansion proposes source neighbours — peer handlers,
    callers, same-file siblings — and a neighbour's reachability is its own:
    an out-of-model seed can sit beside a byte-reachable sibling, so skipping
    the seed would lose that lead permanently. What the seed's scope changes is
    the constraint on the leads, not whether to look; `attacker_controls` goes
    into the decision so the siblings it names are ones the model can reach.
    """
    _migrate_cluster_backlog(runtime)
    candidates = [
        crash for crash in sorted((runtime.results / "crashes").glob("CRASH-*"))
        if crash.is_dir()
        and not (crash / ".cluster_expanded").is_file()
    ]
    attempted = getattr(runtime, "cluster_expansion_attempted", None)
    if attempted is None:
        attempted = set()
        runtime.cluster_expansion_attempted = attempted
    crashes = [crash for crash in candidates if crash not in attempted]
    counts = {
        "expanded": 0,
        "added": 0,
        "skipped": 0,
        "pending": len(candidates) - len(crashes),
    }
    if not crashes:
        return counts
    # Expansion is optional lead generation. A transiently unavailable
    # decision remains eligible after an audit resume, but retrying the same
    # timed-out prompt after every live iteration can consume the audit wall.
    attempted.update(crashes)
    decisions: dict[Path, list[dict] | None] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, runtime.num_agents)) as pool:
        futures = {
            pool.submit(
                triage.cluster_expansion_decision,
                crash,
                runtime.target_root,
                attacker_controls=runtime.config.attacker_controls,
                deadline=deadline,
            ): crash
            for crash in crashes
        }
        for future in concurrent.futures.as_completed(futures):
            crash = futures[future]
            try:
                decisions[crash] = future.result()
            except Exception as exc:
                decisions[crash] = None
                index_log(runtime, f"WARN: cluster expansion failed for {crash.name}: {exc}")
    context = _queue_context(runtime)
    for crash in crashes:
        rows = decisions.get(crash)
        if rows is None:
            counts["pending"] += 1
            continue
        result = workqueue.add_cluster_hypotheses(
            context, crash.name, rows, num_agents=runtime.num_agents,
        )
        _write_cluster_marker(crash / ".cluster_expanded")
        counts["expanded"] += 1
        counts["added"] += result["added"]
        counts["skipped"] += result["skipped"]
        index_log(
            runtime,
            f"CLUSTER-EXPAND: {crash.name} agent={result['agent']} "
            f"added={result['added']} skipped={result['skipped']}",
        )
    return counts


def maintain_local_indexes(runtime: Runtime) -> bool:
    paths = [
        str(runtime.results / name)
        for name in ("crashes", "crashes-rejected", "findings", "findings-rejected")
    ]
    signature = housekeeping.signature("local-indexes", paths)
    if not housekeeping.should_run("local-indexes", signature, 0):
        return False
    succeeded = triage.maintain_indexes(
        runtime.results, runtime.target_root, workers=runtime.num_agents
    )
    if succeeded:
        housekeeping.mark_clean(
            "local-indexes", housekeeping.signature("local-indexes", paths)
        )
    else:
        index_log(runtime, "WARN: local index maintenance failed; leaving it dirty for retry")
    return succeeded


def maintain_aggregate_indexes(runtime: Runtime) -> bool:
    target_output = runtime.results.parents[1]
    inputs: list[str] = []
    for backend_dir in sorted(target_output.iterdir()):
        results = backend_dir / "results"
        if not results.is_dir():
            continue
        for kind, prefix in (("crashes", "CRASH-"), ("findings", "FIND-")):
            artifact_root = results / kind
            if not artifact_root.is_dir():
                continue
            for artifact in sorted(artifact_root.glob(f"{prefix}*")):
                if artifact.is_dir():
                    inputs.append(str(artifact))
    signature = housekeeping.signature("aggregate-indexes", inputs)
    if not housekeeping.should_run("aggregate-indexes", signature, 0):
        return False
    environment = os.environ.copy() | {"TARGET_ROOT": str(runtime.target_root)}
    succeeded = True
    for command in ("cluster-crashes", "cluster-findings"):
        completed = subprocess.run(
            [str(runtime.root / "bin" / command), str(target_output)],
            env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        succeeded = succeeded and completed.returncode == 0
        if completed.returncode:
            index_log(runtime, f"WARN: aggregate {command} failed rc={completed.returncode}")
    refreshed_inputs = [path for path in inputs if Path(path).exists()]
    if succeeded:
        housekeeping.mark_clean(
            "aggregate-indexes", housekeeping.signature("aggregate-indexes", refreshed_inputs)
        )
    return succeeded


def promote_corpus(runtime: Runtime) -> int:
    helper = runtime.root / "lib" / "quality.py"
    corpus = runtime.results / "corpus"
    promoted = 0
    for agent in range(1, runtime.num_agents + 1):
        hits = runtime.results / f"hits-{agent}.log"
        scratch = runtime.results / f"scratch-{agent}"
        label = f"corpus-agent-{agent}"
        # Every promotable testcase has a HIT journal row. Using that journal
        # avoids recursively statting a potentially large scratch tree each
        # iteration.
        signature = housekeeping.signature(label, [str(hits)])
        if not hits.is_file() or not housekeeping.should_run(label, signature, 0):
            continue
        completed = subprocess.run(
            [sys.executable, str(helper), "promote-corpus", str(hits),
             str(runtime.results / f"scratch-{agent}"), str(corpus), str(agent)],
            text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False,
        )
        if completed.returncode == 0:
            match = re.search(r"\bpromoted=([0-9]+)", completed.stdout)
            promoted += int(match.group(1)) if match else 0
            housekeeping.mark_clean(label, signature)
    if promoted:
        subprocess.run(
            [sys.executable, str(helper), "regenerate-corpus-index", str(corpus)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
    return promoted


def enforce_orphan_testcases(runtime: Runtime, *, deadline: float | None = None) -> int:
    """Run a bounded probe for runnable testcases that agents left unexecuted."""
    try:
        maximum = max(0, int(os.environ.get("ASAN_AUTOENFORCE_MAX", "3")))
        timeout_secs = max(1, int(os.environ.get("ASAN_AUTOENFORCE_TIMEOUT", "30")))
    except ValueError:
        maximum, timeout_secs = 3, 30
        index_log(runtime, "WARN: invalid orphan-enforcement limit; using max=3 timeout=30s")
    enforced = 0
    for agent in range(1, runtime.num_agents + 1):
        (runtime.results / f".enforcement_results_{agent}").write_text("", encoding="utf-8")
    for agent in range(1, runtime.num_agents + 1):
        results_file = runtime.results / f".enforcement_results_{agent}"
        _runs, _testcases, orphans = quality.scan_scratch(
            str(runtime.results / f"scratch-{agent}")
        )
        for testcase in orphans:
            try:
                if Path(testcase).stat().st_size == 0:
                    continue
            except OSError:
                continue
            if enforced >= maximum:
                return enforced
            remaining = None if deadline is None else int(deadline - time.monotonic())
            if remaining is not None and remaining <= 0:
                return enforced
            per_run_timeout = timeout_secs if remaining is None else min(timeout_secs, remaining)
            environment = os.environ.copy() | {
                "AGENT_NUM": str(agent),
                "TRIED_INPUTS_LOG": str(runtime.results / f"tried-inputs-{agent}.log"),
                "HITS_LOG_PATH": str(runtime.results / f"hits-{agent}.log"),
                "SANITIZER_RUNS": "1",
                "SKIP_COVERAGE_GATE": "1",
            }
            completed = run_timeout(
                [str(runtime.root / "bin/probe"), testcase], per_run_timeout,
                cwd=runtime.root, env=environment,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            output = Path(testcase).with_suffix(".asan.txt")
            if output.is_file() and verdict.file_has_crash(output):
                label = "CRASH"
            elif output.is_file() and verdict.file_is_clean(output):
                label = "CLEAN"
            elif completed.returncode == 124:
                label = "TIMEOUT"
            elif output.is_file() and output.stat().st_size:
                label = "EXEC_FAIL"
            else:
                label = "NO_EXEC"
            _append(results_file, f"- {label} `{Path(testcase).name}` — harness probe rc={completed.returncode}")
            index_log(runtime, f"orphan enforcement: agent={agent} testcase={Path(testcase).name} verdict={label}")
            enforced += 1
    return enforced


def _cold(runtime: Runtime) -> bool:
    return not any(structured_state.agent_rows(str(i), runtime.results) for i in range(1, runtime.num_agents + 1))


def _fuzz_leads_empty(results: Path) -> bool:
    try:
        lines = (results / "fuzz-leads.md").read_text(encoding="utf-8").splitlines()
    except OSError:
        return True
    return not any(line.strip() and not line.lstrip().startswith(("#", "_")) for line in lines)


def should_skip_launch(
    runtime: Runtime, context: prompt.PromptContext, agent: int,
    *, primary_always_launches: bool = True,
) -> bool:
    """Skip an idle slot only when every current work source is dry.

    Agent 1 launches unconditionally so an iteration always keeps one discovery
    slot even on a dry queue. That is a guarantee about the *initial* cohort;
    applying it to refills would relaunch agent 1 against a dry queue for the
    rest of the epoch, so the pool asks without the exception.
    """
    if agent == 1 and primary_always_launches:
        return False
    counts = structured_state.agent_counts(str(agent), runtime.results)
    if counts and counts.get("active", 0):
        return False
    if prompt.handoff_rows(context, agent):
        return False
    cards = runtime.results / "work-cards.jsonl"
    if cards.is_file() and cards.stat().st_size:
        try:
            card = workqueue.claim_next_card(
                _queue_context(runtime), str(agent), context.mode(agent),
                context.role(agent), claim=False, strategy=context.strategy(agent),
            )
        except (OSError, ValueError):
            return False
        if card is not None:
            return False
    return _fuzz_leads_empty(runtime.results)


def release_stale_card_claims(runtime: Runtime) -> int:
    try:
        return len(workqueue.release_stale_claims(_queue_context(runtime)))
    except (OSError, ValueError):
        return 0


def assign_build_configs(runtime: Runtime, context: prompt.PromptContext, iteration: int) -> None:
    """Keep a regular-build control while rotating one reproducer slot.

    Assignments are session state consumed automatically by bin/probe. A slot
    with active work stays on its current build so an investigation does not
    change binaries mid-hypothesis.
    """
    state_dir = runtime.results / "state"
    state_dir.mkdir(parents=True, exist_ok=True)
    if os.environ.get("_TOKENFUZZ_BENCHMARK_PRIMARY_BUILD") == "1":
        for agent in range(1, runtime.num_agents + 1):
            (state_dir / f"build-config-{agent}").unlink(missing_ok=True)
        return
    base_suffix = os.environ.get("AUDIT_BUILD_SUFFIX", "")
    ready = [
        item for item in runtime.config.build_configs
        if build_config.recipe_path(runtime.target_root, item).is_file()
        and build_config.is_ready(
            build_config.build_dir(runtime.target_root, item, base_suffix=base_suffix),
            build_config.recipe_path(runtime.target_root, item),
        )
    ]
    reproduce = [
        agent for agent in range(1, runtime.num_agents + 1)
        if context.role(agent) == "reproduce"
    ]
    alternate_agent = (
        reproduce[-1]
        if len(reproduce) >= 2
        else reproduce[0] if reproduce and iteration % 4 == 0 else 0
    )
    for agent in range(1, runtime.num_agents + 1):
        path = state_dir / f"build-config-{agent}"
        counts = structured_state.agent_counts(str(agent), runtime.results)
        current = path.read_text(encoding="utf-8").strip() if path.is_file() else ""
        if counts and counts.get("active"):
            # A single-agent audit cannot provide simultaneous control and
            # alternate coverage. Preserve whichever binary the live
            # hypothesis started on, then rotate only after closure.
            if current and build_config.find(ready, current):
                continue
            path.unlink(missing_ok=True)
            continue
        if agent != alternate_agent or not ready:
            path.unlink(missing_ok=True)
            continue
        index = (iteration - 1) if len(reproduce) >= 2 else (iteration // 4 - 1)
        selected = ready[index % len(ready)]
        temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
        temporary.write_text(selected.config_id + "\n", encoding="utf-8")
        os.replace(temporary, path)
        index_log(
            runtime,
            f"Build configuration assignment: agent={agent} config={selected.name} id={selected.config_id}",
        )


@dataclass
class BackendState:
    runtime: Runtime
    context: prompt.PromptContext
    iteration: int = 0
    dry_streak: int = 0
    paused_seconds: int = 0
    housekeeping_seconds: float = 0.0
    transient_streak: int = 0
    started_at: float = 0.0
    stopped: bool = False


def _max_dry_sessions() -> int:
    requested = max(1, int(os.environ.get("MAX_DRY_SESSIONS", "10")))
    return max(requested, STRATEGY_S1_DRY_THRESHOLD + 1)


def runtime_config_path(runtime: Runtime) -> Path | None:
    """Return this runtime's shared config path when it has a full layout."""
    root = getattr(runtime, "root", None)
    output_slug = getattr(runtime, "output_slug", "")
    if root is None or not output_slug:
        return None
    return Path(root) / "output" / output_slug / "target.toml"


def pin_runtime_config(runtime: Runtime) -> None:
    """Reload and freeze the post-build execution contract for one backend."""
    config_path = runtime_config_path(runtime)
    if config_path is not None and config_path.is_file():
        refreshed = target_config.Config(target_root=str(runtime.target_root))
        target_config.load_toml_into(refreshed, config_path)
        runtime.config = refreshed
        target_config.pin_session_config(runtime.results, config_path)
        _activate_runtime(runtime)


def _canary_paths(runtime: Runtime, name: str) -> tuple[Path, Path]:
    """Canary testcase and its sanitizer output, cleared of any older run."""
    canary_dir = runtime.results / ".preflight"
    canary_dir.mkdir(parents=True, exist_ok=True)
    output = canary_dir / "canary-asan.txt"
    output.unlink(missing_ok=True)
    return canary_dir / name, output


def _run_canary(
    runtime: Runtime, mode: str, canary: Path, output: Path,
    *, browser_override: str = "", runner_args: list[str] | None = None,
) -> None:
    environment = os.environ.copy() | {
        "SANITIZER_RUNS": "1", "SAN_OUTPUT_FILE": str(output),
        "SKIP_COVERAGE_GATE": "1",
    }
    if browser_override:
        environment["ASAN_BROWSER"] = browser_override
    if runner_args is not None:
        environment["ASAN_GENERIC_SKIP_TESTCASE"] = "1"
        environment["SANITIZER_GENERIC_SKIP_TESTCASE"] = "1"
    command = [
        str(runtime.root / "bin" / "run-sanitizer-multi"),
        "asan", mode, str(canary),
    ]
    if runner_args is not None:
        command.extend(runner_args)
    subprocess.run(
        command,
        cwd=runtime.root, env=environment, stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL, check=False,
    )


def _canary_captured(output: Path) -> bool:
    # The browser canary constructs this token from character codes, so a bare
    # match cannot come from --dump-dom echoing the testcase source.
    try:
        with output.open(encoding="utf-8", errors="replace") as stream:
            return any("TESTCASE_EXECUTED" in line for line in stream)
    except OSError:
        return False


def _shell_canary_observed(runtime: Runtime) -> tuple[bool, Path]:
    """Prove the shell route for a script engine with no page route."""
    canary, output = _canary_paths(runtime, "canary.js")
    canary.write_text("print('TESTCASE_EXECUTED');\n", encoding="utf-8")
    configured: list[str] | None = None
    if runtime.config.runner_args:
        configured = [
            sanitizer_run.expand_runner_value(
                value, runtime.config, "asan", testcase=str(canary),
            )
            for value in runtime.config.runner_args
        ]
        if not any(
            "{TESTCASE}" in value for value in runtime.config.runner_args
        ):
            configured.append(str(canary))
    _run_canary(
        runtime, "generic", canary, output, runner_args=configured,
    )
    return _canary_captured(output), output


def _browser_canary_observed(
    runtime: Runtime, *, browser_override: str = "",
) -> tuple[bool, Path]:
    """Run one product-route canary without trusting output from an older run."""
    canary, output = _canary_paths(runtime, "canary.html")
    browser_loaded = threading.Event()

    class CanaryHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            browser_loaded.set()
            self.send_response(204)
            self.end_headers()

        def log_message(self, _format: str, *_args) -> None:
            return

    server = http.server.ThreadingHTTPServer(
        ("127.0.0.1", 0), CanaryHandler
    )
    server_thread = threading.Thread(
        target=server.serve_forever, daemon=True
    )
    server_thread.start()
    marker_url = (
        f"http://127.0.0.1:{server.server_address[1]}/executed"
    )
    canary.write_text(
        f'<!doctype html><body><img hidden src="{marker_url}"><script>'
        "const m=String.fromCharCode("
        "84,69,83,84,67,65,83,69,95,69,88,69,67,85,84,69,68"
        ");console.log(m);document.body.textContent=m;"
        "setTimeout(()=>window.close(),50)"
        "</script>\n",
        encoding="utf-8",
    )
    try:
        _run_canary(
            runtime, "browser-minimal", canary, output,
            browser_override=browser_override,
        )
        loaded = browser_loaded.wait(1)
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=1)
    return loaded or _canary_captured(output), output


def preflight_build(runtime: Runtime) -> None:
    config_path = runtime_config_path(runtime)
    benchmark_pinned = (
        os.environ.get("_TOKENFUZZ_BENCHMARK_PRIMARY_BUILD") == "1"
    )
    if benchmark_pinned:
        # A benchmark converges one build for the whole run and holds its lease.
        # A cell that rebuilt would replace the generation its own earlier cells'
        # evidence was measured against, so a cell verifies and never builds. An
        # unusable pinned build is a failed cell, not a repair job: a cell run
        # against the wrong binary is not a measurement, and continuing would
        # launder it into the comparison.
        problems = build_preflight.pinned_build_problems(
            runtime.target_root, build_preflight.benchmark_build_pin(),
            runtime.config,
        )
        if problems:
            raise RuntimeError(
                "pinned benchmark build is not usable: " + "; ".join(problems)
            )
    else:
        build_preflight.refresh(
            runtime.root, runtime.target_root, runtime.target_slug, runtime.config,
            runtime.logs, runtime.backend, runtime.model,
            lambda message: index_log(runtime, message),
        )
    pin_runtime_config(runtime)
    if runtime.config.is_browser not in ("1", "true", "True"):
        return
    if not target_config.browser_page_launch_configured(runtime.config):
        observed, output = _shell_canary_observed(runtime)
    else:
        # A browser tree ships a script shell beside the product, so a shell
        # canary proves nothing about the page route browser agents drive.
        observed, output = _browser_canary_observed(runtime)
        if not observed and not benchmark_pinned and \
                config_path is not None and config_path.is_file():
            detected = target_config.detect_browser_sanitizer_bin(
                runtime.target_root, "asan"
            )
            configured = runtime.config.sanitizer_bin("asan")
            if detected and detected != configured:
                candidate = runtime.config.resolve_path(detected)
                observed, output = _browser_canary_observed(
                    runtime, browser_override=candidate,
                )
                if observed:
                    original = config_path.read_text(encoding="utf-8")
                    updated = target_config.set_sanitizer_bin(
                        original, "asan", detected
                    )
                    if updated == original:
                        # Only an override made the proved product run, and an
                        # override does not reach the probes agents launch.
                        raise RuntimeError(
                            f"browser product {detected} passed preflight but "
                            f"{config_path} declares no active asan_bin to "
                            "point at it; set asan_bin and rerun"
                        )
                    temporary = config_path.with_name(
                        f".{config_path.name}.{os.getpid()}.tmp"
                    )
                    try:
                        temporary.write_text(updated, encoding="utf-8")
                        os.replace(temporary, config_path)
                    finally:
                        temporary.unlink(missing_ok=True)
                    pin_runtime_config(runtime)
                    index_log(
                        runtime,
                        "Browser preflight repaired the configured sanitizer product",
                    )
    if not observed:
        raise RuntimeError(
            "sanitizer harness canary did not observe target execution; "
            f"see {output}"
        )
    index_log(runtime, "PREFLIGHT OK: sanitizer harness canary observed target execution")


def initialize_backend(
    runtime: Runtime, args, guide: str, *, started_at: float | None = None,
) -> BackendState:
    _activate_runtime(runtime)
    index_log(runtime, f"LLM backend: provider={runtime.backend} model={runtime.model}")
    index_log(runtime, f"Target: slug={runtime.target_slug} path={runtime.target_root}")
    index_log(runtime, f"Output: results={runtime.results} logs={runtime.logs}")
    index_log(runtime, callgraph.status())
    context = runtime.prompt_context(guide)
    prompt.write_static_prompt_file(context)
    state = BackendState(
        runtime, context,
        started_at=time.monotonic() if started_at is None else started_at,
    )
    housekeeping_started = time.monotonic()
    try:
        # A resumed tree may carry trigger verdicts from an older report,
        # revision, threat model, or decision schema. Reconcile them before
        # the first agent receives work-card advice derived from those votes;
        # post-iteration triage is one cohort too late.
        triage.restore_stale_trigger_rejections(runtime.results)
        refresh_work_cards(runtime)
        initialize_agent_strategies(runtime)
    finally:
        state.housekeeping_seconds += max(
            0.0, time.monotonic() - housekeeping_started
        )
        runtime.logs.mkdir(parents=True, exist_ok=True)
        (runtime.logs / ".housekeeping_secs").write_text(
            f"{state.housekeeping_seconds:.6f}\n", encoding="utf-8"
        )
    return state


def _productive_wall_exhausted(state: BackendState) -> bool:
    try:
        budget = max(0, int(os.environ.get("AUDIT_WALL_BUDGET_SECS", "0")))
    except ValueError:
        budget = 0
    if not budget:
        return False
    elapsed = time.monotonic() - state.started_at - state.paused_seconds
    if elapsed < budget:
        return False
    index_log(
        state.runtime,
        f"Reached productive wall budget: {budget}s productive, "
        f"{state.paused_seconds}s provider pause excluded and "
        f"{state.housekeeping_seconds:.1f}s housekeeping included",
    )
    state.stopped = True
    return True


def _productive_wall_remaining(state: BackendState) -> int | None:
    try:
        budget = max(0, int(os.environ.get("AUDIT_WALL_BUDGET_SECS", "0")))
    except ValueError:
        return None
    if not budget:
        return None
    elapsed = time.monotonic() - state.started_at - state.paused_seconds
    return max(0, int(budget - elapsed))


def _productive_wall_deadline(state: BackendState) -> float | None:
    try:
        budget = max(0, int(os.environ.get("AUDIT_WALL_BUDGET_SECS", "0")))
    except ValueError:
        return None
    if not budget:
        return None
    return state.started_at + budget + state.paused_seconds


def _run_post_iteration(state: BackendState) -> None:
    """Run housekeeping within the audit wall and record its cost."""
    started = time.monotonic()
    try:
        post_iteration(state.runtime, deadline=_productive_wall_deadline(state))
    finally:
        state.housekeeping_seconds += max(0.0, time.monotonic() - started)
        (state.runtime.logs / ".housekeeping_secs").write_text(
            f"{state.housekeeping_seconds:.6f}\n", encoding="utf-8"
        )


def _refill_outcome(result: AgentResult) -> str:
    """Classify a finished session by how its slot may be reused.

    - `provider`: the caller's pause/recovery path owns this, not the pool.
    - `continue`: turn-capped, so it stopped at the rollover target with work
      still in flight — a continuation receipt that needs no other work source.
    - `clean`: exited normally; reuse the slot only while work remains.
    - `deadline`: rc=124 is the epoch or wall running out, so there is no time
      to retry into.
    - `failed`: an ambiguous process failure (a kill, a CLI crash). Recorded
      audits show these are usually one-off — an rc=-9 and an rc=1 session were
      each followed by a replacement that then ran a full productive session —
      so the slot gets one retry per cohort, never a loop.
    """
    if result.provider_issue != "none":
        return "provider"
    if result.turn_capped:
        return "continue"
    if result.returncode == 0:
        return "clean"
    if result.returncode == 124:
        return "deadline"
    return "failed"


# Provider states the outer loop recovers from, so the pool must stop feeding
# them. The synthetic "internal" issue is a local harness fault, not provider
# health, and halting every slot on one would discard the others' work.
_PROVIDER_HALT_ISSUES = ("capacity_limited", "transient")


def _session_did_work(result: AgentResult) -> bool:
    """Whether a finished session acted at all, so its slot is worth reusing.

    Work availability is sticky — a fuzz lead stays listed and a PENDING
    hypothesis stays active for the whole pool — so it cannot bound how often a
    slot relaunches. A transcript that parsed but holds no tool call is the one
    positive signal that a session did nothing and that its replacement would
    repeat the same no-op. Falls open when nothing parsed at all: an unreadable
    or unrecognised transcript must not silently disable a backend's refills.
    """
    events = tools = 0
    for event in audit_helpers._iter_json_events(str(result.raw)):
        events += 1
        tools += audit_helpers._event_tool_counts(event)[1]
    return tools > 0 or events == 0


def run_agent_pool(
    state: BackendState, agents: list[int], cold: bool
) -> list[AgentResult]:
    """Reuse a finished agent slot for as long as the initial cohort runs.

    A slot used to get a single replacement and then idle at the iteration
    barrier for however long the slowest peer still had to run, so a fast agent
    lost most of its hours to waiting. Any finished slot is relaunched instead,
    repeatedly, while an initial session is still outstanding and the slot has
    work: it was turn-capped, or its own state still shows a live work source.
    Every session is clamped to one epoch deadline fixed at cohort start, so a
    refill launched just before the last initial ended cannot run a further full
    AGENT_TIMEOUT and push post-iteration triage arbitrarily far out.

    What this deliberately does NOT do is keep refilling until the epoch closes.
    The `initial` sentinel is load-bearing twice over, and both reasons have to
    be retired before it can go:

    - It is the clock for iteration-counted control loops. Refilling to the
      epoch stretches an iteration from about one session to AGENT_TIMEOUT,
      which on a 5h run turns five iterations into roughly two — and strategy
      rotation needs STRATEGY_DRY_THRESHOLD *iterations* of dryness, so it
      would stop firing at all.
    - It bounds stale-signal spin. should_skip_launch reports work from sticky
      sources: a PENDING hypothesis that never resolves, or any line in
      fuzz-leads.md. Capped at one generation those cost a few sessions;
      uncapped they justify clean sessions for the whole epoch.

    So a slot does still idle once the last initial session ends while a peer's
    refill runs. Closing that window needs triage to stop being stop-the-world
    and per-session progress receipts, not a looser sentinel. A one-slot cohort
    likewise chains nothing — its only session is also the last initial one, and
    continuation comes from the next iteration.
    """
    runtime = state.runtime
    context = state.context
    results: list[AgentResult] = []
    epoch_budget = _agent_timeout()
    wall = _productive_wall_remaining(state)
    if wall is not None:
        epoch_budget = min(epoch_budget, wall)
    epoch_deadline = time.monotonic() + epoch_budget

    def epoch_remaining() -> int:
        remaining = int(epoch_deadline - time.monotonic())
        current_wall = _productive_wall_remaining(state)
        return remaining if current_wall is None else min(remaining, current_wall)

    # One retry per slot per cohort after an ambiguous process failure.
    retried: set[int] = set()
    # Provider trouble reported by any slot stops launches in all of them.
    halted = ""
    with concurrent.futures.ThreadPoolExecutor(max_workers=runtime.num_agents) as pool:
        futures: dict[concurrent.futures.Future, tuple[int, bool]] = {}

        def launch(agent: int, initial: bool) -> None:
            future = pool.submit(
                run_agent_guarded, runtime, context, agent, state.iteration,
                cold and initial, epoch_remaining(),
            )
            futures[future] = (agent, initial)

        for agent in agents:
            launch(agent, True)
        while futures:
            done, _ = concurrent.futures.wait(
                futures, return_when=concurrent.futures.FIRST_COMPLETED
            )
            finished = []
            for future in done:
                futures.pop(future)
                result = future.result()
                results.append(result)
                finished.append(result)
                if result.provider_issue in _PROVIDER_HALT_ISSUES and not halted:
                    halted = result.provider_issue
                    index_log(
                        runtime,
                        f"Worker-pool: agent={result.agent} reported {halted}; no further "
                        "launches this iteration, finishing in-flight sessions first",
                    )
            if halted or not getattr(runtime, "refill_workers", True):
                continue
            if not any(initial for _agent, initial in futures.values()):
                continue
            for result in finished:
                outcome = _refill_outcome(result)
                if outcome in ("provider", "deadline"):
                    index_log(
                        runtime,
                        f"Worker-pool refill: agent={result.agent} slot left idle; "
                        f"{outcome} outcome rc={result.returncode}",
                    )
                    continue
                # A turn-capped session carries in-flight work, and a failed one
                # produced no information about whether work remains — treating
                # its crash as "found nothing" would strand the slot. Only a
                # clean session has to justify its replacement.
                if outcome == "clean":
                    if should_skip_launch(
                        runtime, context, result.agent, primary_always_launches=False,
                    ):
                        index_log(
                            runtime,
                            f"Worker-pool refill: agent={result.agent} slot left idle; "
                            "no active hypothesis, handoff, claimable card, or fuzz lead",
                        )
                        continue
                    if not _session_did_work(result):
                        index_log(
                            runtime,
                            f"Worker-pool refill: agent={result.agent} slot left idle; "
                            "its session made no tool call, so a replacement would repeat it",
                        )
                        continue
                elif outcome == "failed" and result.agent in retried:
                    index_log(
                        runtime,
                        f"Worker-pool refill: agent={result.agent} slot left idle; "
                        f"already retried once after an unexpected exit rc={result.returncode}",
                    )
                    continue
                remaining = epoch_remaining()
                if remaining <= 0:
                    index_log(
                        runtime,
                        f"Worker-pool refill: agent={result.agent} slot left idle; "
                        "pool epoch closed, deferring to post-iteration triage",
                    )
                    continue
                if outcome == "failed":
                    # Spend the allowance only on a launch that actually happens.
                    retried.add(result.agent)
                index_log(
                    runtime,
                    f"Worker-pool refill: agent={result.agent} slot free; "
                    f"launching another session with {remaining}s left in the epoch",
                )
                launch(result.agent, False)
    return results


def run_iteration(state: BackendState) -> tuple[str, list[AgentResult]]:
    runtime = state.runtime
    context = state.context
    _activate_runtime(runtime)
    if _productive_wall_exhausted(state):
        return "budget", []
    state.iteration += 1
    fuzz_triage = runtime.root / "bin" / "triage-fuzz-crashes"
    if os.access(fuzz_triage, os.X_OK):
        with runtime.index.open("a", encoding="utf-8") as output:
            completed = subprocess.run(
                [str(fuzz_triage), str(runtime.results), "20"],
                stdout=output, stderr=subprocess.STDOUT, check=False,
            )
        if completed.returncode:
            index_log(runtime, f"WARN: triage-fuzz-crashes failed rc={completed.returncode}")
    reset_sanitizer_run_counters(runtime)
    reset_llm_decision_counters(runtime)
    before = progress(runtime)
    cold = _cold(runtime)
    refreshed = refresh_work_cards(runtime)
    if refreshed:
        initialize_agent_strategies(runtime)
    released = release_stale_card_claims(runtime)
    if released:
        index_log(runtime, f"queue: released {released} stale work-card claim(s)")
    if expand_work_cards_if_exhausted(runtime):
        initialize_agent_strategies(runtime)
    if _productive_wall_exhausted(state):
        return "budget", []
    assign_build_configs(runtime, context, state.iteration)
    index_log(
        runtime,
        f"Iteration {state.iteration} starting: agents={runtime.num_agents} cold={str(cold).lower()} "
        f"totals={before.findings} findings/{before.crashes} crashes",
    )
    agents = [
        agent for agent in range(1, runtime.num_agents + 1)
        if not should_skip_launch(runtime, context, agent)
    ]
    skipped = runtime.num_agents - len(agents)
    if skipped:
        index_log(runtime, f"SKIP_LAUNCH: {skipped} idle secondary agent(s) have no card, active hypothesis, or fuzz lead")
    remaining = _productive_wall_remaining(state)
    results = (
        run_agent_pool(state, agents, cold)
        if remaining is None or remaining > 0
        else []
    )
    # Agents can file valid artifacts before another worker hits a provider
    # limit. Always triage the iteration before deciding whether to pause.
    _run_post_iteration(state)
    after = progress(runtime)
    after_agent_progress = {
        agent: agent_progress(runtime, agent, after)
        for agent in range(1, runtime.num_agents + 1)
    }
    novel_roots = newly_introduced_roots(before, after)
    productive = bool(novel_roots)
    productive_agents = {
        agent for agent, current in after_agent_progress.items()
        if current.roots & novel_roots
    }
    diagnostic = after.env_blocked > before.env_blocked
    capacity_limited = any(result.provider_issue == "capacity_limited" for result in results)
    transient = any(result.provider_issue == "transient" for result in results)
    if capacity_limited or transient:
        if productive:
            state.dry_streak = 0
        issue = "capacity" if capacity_limited else "transient"
        index_log(runtime, f"Iteration {state.iteration} interrupted by {issue} provider failure")
        return issue, results
    if productive:
        state.dry_streak = 0
    else:
        state.dry_streak += 1
    state.transient_streak = 0
    update_subsystem_dry_streaks(
        runtime, productive_agents
    )
    update_strategy_rotation(
        runtime, context, after_agent_progress, productive_agents
    )
    outcome = "productive" if productive else "env-blocked" if diagnostic else "dry"
    index_log(
        runtime,
        f"Iteration {state.iteration} result: {outcome} "
        f"totals={after.findings} findings/{after.crashes} crashes "
        f"unique={after.finding_roots} finding-roots/{after.crash_roots} crash-roots "
        f"active={after.active} "
        f"dry={state.dry_streak}/{_max_dry_sessions()}",
    )
    if state.dry_streak >= _max_dry_sessions() and after.active == 0:
        index_log(runtime, "STALL_STOP: no promoted results or active hypotheses remain")
        state.stopped = True
        return "stalled", results
    return "productive" if productive else "diagnostic" if diagnostic else "dry", results


def _recover_capacity(state: BackendState, results: list[AgentResult]) -> bool:
    state.transient_streak = 0
    remaining = PROVIDER_PAUSE_MAX_SECONDS - state.paused_seconds
    if remaining <= 0:
        return False
    now = int(time.time())
    reset_at = max((result.reset_at or 0 for result in results), default=0)
    wait = max(0, reset_at - now + 30) if reset_at else min(30 * 60, remaining)
    wait = min(wait, remaining)
    if wait:
        index_log(state.runtime, f"Provider capacity limited; pausing {wait}s before retry")
        time.sleep(wait)
        state.paused_seconds += wait
        (state.runtime.logs / ".paused_secs").write_text(
            str(state.paused_seconds) + "\n", encoding="utf-8"
        )
    (state.runtime.logs / ".run-quality").write_text("provider_recovered\n", encoding="utf-8")
    (state.runtime.logs / ".backend-unavailable").unlink(missing_ok=True)
    return True


def _recover_transient(state: BackendState) -> bool:
    state.transient_streak += 1
    if state.transient_streak > TRANSIENT_RETRY_MAX:
        return False
    wait = min(5 * 60, 30 * (2 ** (state.transient_streak - 1)))
    index_log(
        state.runtime,
        f"Transient provider failure; retrying in {wait}s ({state.transient_streak}/{TRANSIENT_RETRY_MAX})",
    )
    time.sleep(wait)
    state.paused_seconds += wait
    (state.runtime.logs / ".paused_secs").write_text(
        str(state.paused_seconds) + "\n", encoding="utf-8"
    )
    (state.runtime.logs / ".run-quality").write_text("provider_recovered\n", encoding="utf-8")
    return True


def run_backend(runtime: Runtime, args, guide: str) -> int:
    with instance_lock(runtime, args.allow_concurrent):
        runner_preflight.validate(
            runtime.config, lambda message: index_log(runtime, message)
        )
        validate_model(runtime)
        preflight_build(runtime)
        state = initialize_backend(runtime, args, guide, started_at=time.monotonic())
        while args.max_iterations == 0 or state.iteration < args.max_iterations:
            status, results = run_iteration(state)
            if status in ("budget", "stalled"):
                break
            if _productive_wall_exhausted(state):
                break
            if status == "capacity":
                can_retry = args.max_iterations == 0 or state.iteration < args.max_iterations
                if not can_retry or not _recover_capacity(state, results):
                    (runtime.logs / ".backend-unavailable").touch()
                    (runtime.logs / ".run-quality").write_text("provider_limited\n", encoding="utf-8")
                    index_log(runtime, "BACKEND_UNAVAILABLE: provider did not recover within the pause budget")
                    return 2
            if status == "transient":
                can_retry = args.max_iterations == 0 or state.iteration < args.max_iterations
                if not can_retry or not _recover_transient(state):
                    (runtime.logs / ".backend-unavailable").touch()
                    (runtime.logs / ".run-quality").write_text("provider_limited\n", encoding="utf-8")
                    index_log(runtime, "BACKEND_UNAVAILABLE: transient provider failures did not clear")
                    return 2
            cooldown = max(0, int(os.environ.get("COOLDOWN", "5")))
            if cooldown and (args.max_iterations == 0 or state.iteration < args.max_iterations):
                time.sleep(cooldown)
        return 0


def run_ensemble(runtimes: list[Runtime], args, guide: str) -> int:
    with ExitStack() as stack:
        for runtime in runtimes:
            stack.enter_context(instance_lock(runtime, args.allow_concurrent))
        runner_preflight.validate(
            runtimes[0].config,
            lambda message: index_log(runtimes[0], message),
        )
        for runtime in runtimes:
            _activate_runtime(runtime)
            validate_model(runtime)
        preflight_build(runtimes[0])
        for runtime in runtimes[1:]:
            pin_runtime_config(runtime)
        started_at = time.monotonic()
        states = [
            initialize_backend(runtime, args, guide, started_at=started_at)
            for runtime in runtimes
        ]
        total_iterations = 0
        failures = 0
        while args.max_iterations == 0 or total_iterations < args.max_iterations:
            available = [state for state in states if not state.stopped]
            if not available:
                break
            for state in available:
                if args.max_iterations and total_iterations >= args.max_iterations:
                    break
                status, results = run_iteration(state)
                total_iterations += status not in ("budget",)
                if status != "budget" and _productive_wall_exhausted(state):
                    continue
                if status == "capacity":
                    has_alternative = any(
                        other is not state and not other.stopped for other in states
                    )
                    if has_alternative:
                        state.stopped = True
                        failures += 1
                        (state.runtime.logs / ".backend-unavailable").touch()
                        (state.runtime.logs / ".run-quality").write_text("provider_limited\n", encoding="utf-8")
                        index_log(state.runtime, "BACKEND_UNAVAILABLE: leaving this backend out of the remaining ensemble cycle")
                    elif not _recover_capacity(state, results):
                        state.stopped = True
                        failures += 1
                        (state.runtime.logs / ".backend-unavailable").touch()
                        (state.runtime.logs / ".run-quality").write_text("provider_limited\n", encoding="utf-8")
                        index_log(state.runtime, "BACKEND_UNAVAILABLE: final ensemble backend exhausted its recovery budget")
                elif status == "transient":
                    state.transient_streak += 1
                    no_retry_left = bool(
                        args.max_iterations and total_iterations >= args.max_iterations
                    )
                    if no_retry_left or state.transient_streak > TRANSIENT_RETRY_MAX:
                        state.stopped = True
                        failures += 1
                        (state.runtime.logs / ".backend-unavailable").touch()
                        index_log(state.runtime, "BACKEND_UNAVAILABLE: transient failure left no healthy retry in this ensemble run")
            cooldown = max(0, int(os.environ.get("COOLDOWN", "5")))
            if cooldown and any(not state.stopped for state in states):
                time.sleep(cooldown)
        return 2 if failures == len(states) else 0


def _new_target(root: Path, slug: str) -> int:
    return subprocess.run(
        [str(root / "bin" / "setup-target"), slug],
        env=os.environ.copy() | {"AUDIT_ROOT": str(root), "SCRIPT_ROOT": str(root)},
        check=False,
    ).returncode


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(os.environ.get("SCRIPT_ROOT") or Path(__file__).resolve().parent.parent).absolute()
    os.environ["SCRIPT_ROOT"] = str(root)
    _configure_binaries(args)
    llm_invoke.apply_memory_policy(args.enable_memory)
    if args.new_target:
        return _new_target(root, args.new_target)
    effective_target = (
        args.target if args.target_path
        else target_profile.effective_slug(root, args.target)
    )
    target_root = Path(
        args.target_path or root / "targets" / effective_target
    ).expanduser().absolute()
    if not target_root.is_dir():
        print(f"FATAL: target path does not exist: {target_root}", file=sys.stderr)
        return 1
    try:
        target_slug = audit_helpers.sanitize_target_slug(str(target_root), str(root / "targets"))
        output_slug = _output_slug(target_slug, args.experiment)
    except ValueError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1
    requested = args.backend or os.environ.get("AUDIT_BACKEND", "all")
    try:
        args.agent_security = llm_invoke.resolve_agent_security(args.agent_security)
    except ValueError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1
    if requested == "all":
        if args.model:
            print("FATAL: --model requires a single backend", file=sys.stderr)
            return 1
        backends = discover_backends()
        if not backends:
            print("FATAL: no installed and configured hosted backend found", file=sys.stderr)
            return 1
    else:
        if requested == "oss" and not args.model:
            print("FATAL: --backend oss requires --model", file=sys.stderr)
            return 1
        if not backend_configured(requested):
            print(f"FATAL: backend '{requested}' is not installed or configured", file=sys.stderr)
            return 1
        backends = [requested]
    # An ensemble drops a backend this profile cannot launch; a backend the
    # operator named by hand is a hard error instead of a silent substitution.
    usable = []
    for backend in backends:
        problem = llm_invoke.agent_security_problem(backend, args.agent_security)
        if not problem:
            usable.append(backend)
            continue
        message = (
            f"backend '{backend}' cannot use agent security "
            f"'{args.agent_security}': {problem}"
        )
        if requested != "all":
            print(f"FATAL: {message}", file=sys.stderr)
            return 1
        print(f"WARN: skipping {message}", file=sys.stderr)
    if not usable:
        print(
            f"FATAL: no backend can run under agent security "
            f"'{args.agent_security}'", file=sys.stderr,
        )
        return 1
    # Limit last: an ensemble cannot rotate more backends than it has
    # iterations, and slicing before the filter could spend the whole limit on
    # backends this profile then drops.
    backends = usable[:args.max_iterations] if args.max_iterations else usable
    try:
        guide = (root / "AGENTS.md").read_text(encoding="utf-8")
    except OSError:
        guide = ""
    try:
        decision_timeout_override = os.environ.get("LLM_DECISION_TIMEOUT")
        runtimes = [
            prepare_runtime(
                root, target_root, target_slug, output_slug, backend,
                args.model, args.strategy, args.max_iterations,
                decision_timeout_override,
                args.refill_workers,
                args.agent_security,
            )
            for backend in backends
        ]
        if requested == "all" and len(runtimes) > 1:
            return int(run_ensemble(runtimes, args, guide) != 0)
        return int(run_backend(runtimes[0], args, guide) != 0)
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
