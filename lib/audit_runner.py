#!/usr/bin/env python3
"""Parallel structured-state audit orchestration."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import fcntl
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Collection
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
import fuzz_triage
import housekeeping
import llm_invoke
import llm_usage
import prompt
import prompt_render
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


_POOL_OVERTIME_POLICIES = ("cohort-era", "any-peer")


def _pool_overtime_policy() -> str:
    """Which in-flight peer lets a drained slot take its one overtime session.

    ``cohort-era`` (default): only an initial session or a refill launched
    beside one. ``any-peer``: any peer, including another slot's overtime. The
    one-session-per-slot cap and the epoch clamp hold under both; the policy
    only decides whether a slot may fill a gap that an overtime peer holds
    open. A value outside the set is a configuration error, not a default.
    """
    value = os.environ.get("POOL_OVERTIME", "").strip() or _POOL_OVERTIME_POLICIES[0]
    if value not in _POOL_OVERTIME_POLICIES:
        raise ValueError(
            "POOL_OVERTIME must be one of "
            f"{', '.join(_POOL_OVERTIME_POLICIES)}, not {value!r}"
        )
    return value


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
    parser.add_argument(
        "--since", metavar="REV", default="",
        help=(
            "delta mode: audit only the files changed in REV..HEAD, their one-hop callers, and S1 cards for exactly those commits. The results tree records the delta; a resumed run must pass the same REV."
        ),
    )
    parser.add_argument("--claude-bin")
    parser.add_argument("--codex-bin")
    parser.add_argument("--gemini-bin")
    parser.add_argument("--grok-bin")
    parser.add_argument("--new-target")
    parser.add_argument("--allow-concurrent", action="store_true")
    parser.add_argument("--enable-memory", action="store_true")
    parser.add_argument(
        "--agent-security", choices=llm_invoke.AGENT_SECURITY_MODES, default=None,
        help=(
            "backend execution boundary. sandboxed runs the backend inside its own OS sandbox; external-bypass drops that for an outer container or VM you administer, and warns once when nothing asserts IS_SANDBOX=1. Defaults to external-bypass for oss, which OpenCode is the only backend to need: its permissions are an approval policy, not an OS sandbox, so it cannot run sandboxed at all. Every other backend defaults to sandboxed."
        ),
    )
    parser.add_argument(
        "--refill-workers", action=argparse.BooleanOptionalAction, default=True,
        help="relaunch a finished worker slot while a peer session is still running",
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
    delta: workqueue.DeltaScope | None = None
    # Why the last delta refresh failed; a stale scoped queue stops the run.
    delta_refresh_failed: str = ""
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
            backend=self.backend,
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


def _read_first_token(path: str) -> str:
    try:
        with open(path, encoding="utf-8") as handle:
            tokens = handle.read().split()
        return tokens[0] if tokens else ""
    except (OSError, ValueError):
        return ""


def _cgroup_cpu_limit() -> float:
    """CPUs granted by a cgroup quota (Docker `--cpus`), or 0.0 when unlimited.

    v2 `cpu.max` reads "quota period" or "max period"; v1 splits them into
    `cpu.cfs_quota_us` (-1 when unlimited) and `cpu.cfs_period_us`.
    """
    try:
        with open("/sys/fs/cgroup/cpu.max", encoding="utf-8") as handle:
            quota, period = handle.read().split()[:2]
        if quota != "max" and int(period) > 0:
            return int(quota) / int(period)
        return 0.0
    except (OSError, ValueError, IndexError):
        pass
    for controller in ("cpu", "cpu,cpuacct"):
        quota = _read_first_token(f"/sys/fs/cgroup/{controller}/cpu.cfs_quota_us")
        period = _read_first_token(f"/sys/fs/cgroup/{controller}/cpu.cfs_period_us")
        try:
            if quota and period and int(quota) > 0 and int(period) > 0:
                return int(quota) / int(period)
        except ValueError:
            continue
    return 0.0


def _cgroup_memory_limit_bytes() -> int:
    """Bytes granted by a cgroup memory limit (Docker `-m`), or 0 when unlimited."""
    for path in (
        "/sys/fs/cgroup/memory.max",
        "/sys/fs/cgroup/memory/memory.limit_in_bytes",
    ):
        raw = _read_first_token(path)
        if not raw or raw == "max":
            continue
        try:
            value = int(raw)
        except ValueError:
            continue
        # v1 reports a huge sentinel when unlimited.
        if 0 < value < (1 << 60):
            return value
    return 0


def _machine_cpus() -> int:
    """CPUs this process may actually use: affinity and cgroup quota, then host."""
    host = os.cpu_count() or 4
    try:
        host = min(host, len(os.sched_getaffinity(0)))  # Linux only
    except (AttributeError, OSError):
        pass
    quota = _cgroup_cpu_limit()
    if quota > 0:
        host = min(host, max(1, int(quota)))
    return max(1, host)


def _machine_memory_gb() -> float:
    """RAM in GiB available to this process, or 0.0 when the platform will not say.

    Inside a container the host figure is a lie; a cgroup limit wins over it.
    """
    physical = 0.0
    try:
        physical = (
            os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        ) / (1024 ** 3)
    except (ValueError, OSError, AttributeError):
        pass
    limit = _cgroup_memory_limit_bytes()
    if limit:
        limited = limit / (1024 ** 3)
        return min(physical, limited) if physical else limited
    return physical


def _auto_shell_agents() -> int:
    """Default shell-worker count sized to the machine, not a fixed 3.

    The old default of three predates continuous scheduling: it was a
    round-robin cohort, so a fourth slot mostly added barrier idle. With slots
    that refill to the wall, more of them is more coverage at the same budget,
    up to what the machine can host. Each slot is one agent CLI plus the
    occasional build or `bin/probe` it spawns, so the ceiling is CPU and RAM,
    not the provider — a shared account limit is enforced by the provider and
    surfaces as a capacity pause, which the loop already handles, so it is not
    second-guessed here.

    ``cpu_count`` bounds it because a build or sanitizer run is CPU-bound;
    ``AGENT_MEMORY_GB`` (default 4) bounds it against RAM so a low-memory host
    does not thrash; ``AGENT_POOL_MAX`` (default 8) is the safety ceiling.
    ``NUM_AGENTS`` or ``SHELL_AGENTS`` still override this entirely.
    """
    cpus = _machine_cpus()
    try:
        per_agent_gb = max(0.5, float(os.environ.get("AGENT_MEMORY_GB", "4")))
    except ValueError:
        per_agent_gb = 4.0
    try:
        ceiling = max(1, int(os.environ.get("AGENT_POOL_MAX", "8")))
    except ValueError:
        ceiling = 8
    memory_gb = _machine_memory_gb()
    by_memory = int(memory_gb // per_agent_gb) if memory_gb else ceiling
    return max(1, min(cpus, by_memory or 1, ceiling))


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
        shell_default = "2" if page_browser else str(_auto_shell_agents())
        shell = max(0, int(os.environ.get("SHELL_AGENTS", shell_default)))
        return max(1, browser + shell), browser, shell
    total = max(1, int(os.environ.get("SHELL_AGENTS", str(_auto_shell_agents()))))
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
    since: str = "",
) -> Runtime:
    output_root = root / "output" / output_slug
    config = _load_config(root, target_root, output_root, target_slug)
    results = output_root / backend / "results"
    logs = output_root / backend / "logs"
    raw = logs / ".raw"
    target_rev = target_config.detect_rev(target_root)
    repo_type = target_config.detect_repo_type(target_root)
    # Resolved and checked before any run state is written, so a delta
    # the tree cannot take leaves no half-started run behind it.
    delta = workqueue.delta_scope(
        workqueue.Context(root, target_root, target_slug, results, repo_type),
        since,
    ) if since else None
    if delta is not None \
            and fixed_strategy.upper() in _UNRANKED_LANE_STRATEGIES:
        # S4 (whole-target fuzz campaign) and S6 (other projects' fixes)
        # draw their cards from a source that is not this range, so their
        # queue cannot be the delta. Refuse rather than file a non-delta
        # queue under the delta's recorded settings.
        raise ValueError(
            f"--since cannot be combined with --strategy {fixed_strategy.upper()}: "
            "its cards do not come from the changed range"
        )
    _refuse_changed_delta(results / "state" / "run-config.json", delta)
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
    fixed_strategy_path = results / "state" / "fixed-strategy"
    if fixed_strategy:
        fixed_strategy_path.write_text(fixed_strategy + "\n", encoding="utf-8")
    else:
        fixed_strategy_path.unlink(missing_ok=True)
    target_config.write_session_env(results, str(results), str(target_root), target_slug, target_rev, str(logs))
    _write_run_config(
        results / "state" / "run-config.json", total, browser, shell,
        backend, model, target_slug, agent_security, delta=delta,
    )
    _log_tour(logs)
    runtime = Runtime(
        root, target_root, target_slug, output_slug, backend, model, config,
        target_rev, repo_type,
        results, logs, raw, logs / "index.log", logs / "index.jsonl",
        total, browser, shell, roles, fixed_strategy,
        _operator_decision_timeout(decision_timeout_override),
        refill_workers, agent_security, delta,
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


def validate_model(runtime: Runtime, audit_guide: str = "") -> None:
    """Exercise the requested model through the same tool-capable launch path.

    CLI auth/version checks cannot detect an invalid model selection, and an
    OSS model that can chat but cannot read files is unusable for an audit.
    Keep this probe bounded; failed transcripts remain on disk for diagnosis.
    The audit guide is part of the request because a tiny unrelated command
    can be served by the requested model even when its policy routes the real
    audit contract elsewhere. Offline/mock runs may disable the probe before
    launch.
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

    raw = runtime.raw / f"model-preflight-{runtime.backend}-{os.getpid()}-{time.time_ns()}.raw"
    # The probe runs the launch contract the audit itself will use: the same
    # granted directories, the same working directory, and a command that has
    # to reach the target tree. Asking only for a reply answers "the provider
    # is up", never "an agent can act here" — and a backend that could not
    # create a single process passed that weaker probe, so a run spent its
    # whole wall issuing nothing and published the silence as a clean zero.
    # A write is what proves it: a grant can also arrive readable and silently
    # unwritable, which no exit code reports. It lands in the target's .audit/
    # — where the build lease the audit needs already lives, and which
    # freshness prunes, so the probe cannot read as target drift.
    stamp = f"{os.getpid()}_{time.time_ns()}"
    token = f"AGENT_PREFLIGHT_OK_{stamp}"
    sentinel = runtime.target_root / ".audit" / f"preflight-{stamp}"
    sentinel.parent.mkdir(parents=True, exist_ok=True)
    # Quoted here rather than in the template: a checkout path may legally
    # contain a quote, and a prompt that renders its own quoting would hand the
    # agent an unrunnable command and read the failure as a blocked sandbox.
    prompt_text = prompt_render.render_template(
        "agent_preflight.md.j2",
        {
            "token": token,
            "command": f"printf %s {shlex.quote(token)} > {shlex.quote(str(sentinel))}",
            "audit_guide": audit_guide,
        },
    )
    # Match the final transform applied to every real agent prompt. Testing a
    # different vocabulary here can certify a route the first session loses.
    prompt_text = vocab_rules.strip_markers(
        vocab_rules.neutralize_string(prompt_text)
    )

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
            # Each attempt has to produce its own evidence: a sentinel left by
            # an attempt that then failed would pass the next one, which need
            # only exit zero without acting.
            sentinel.unlink(missing_ok=True)
            last_rc = llm_invoke.run_agent_prompt(
                runtime.backend, prompt_text, timeout_secs, raw,
                model=runtime.model, max_turns=6,
                add_dirs=f"{runtime.root},{runtime.target_root},{runtime.results}",
                cwd=runtime.root,
                agent_security=runtime.agent_security,
            )
            llm_usage.append_usage_event(
                getattr(runtime, "index_jsonl", runtime.logs / "index.jsonl"),
                backend=runtime.backend, model=runtime.model,
                kind="model-preflight", prompt_text=prompt_text, raw_path=raw,
                usage_complete=last_rc == 0,
            )
            try:
                acted = sentinel.read_text(encoding="utf-8").strip() == token
            except OSError:
                acted = False
            unresolved_model = bool(
                agy_log is not None and agy_log.is_file()
                and "Failed to resolve model flag" in agy_log.read_text(encoding="utf-8", errors="replace")
            )
            if unresolved_model:
                last_rc = 45
                break
            if runtime.backend == "gemini" and llm_invoke.use_gemini_cli() \
                    and llm_invoke.gemini_admin_policy_dropped(raw):
                # Gemini CLI discards every --admin-policy, silently for the
                # run, when a system policies directory holds any policy.
                # That drops the memory and web denies together, so a run
                # would proceed unisolated with nothing in its logs saying so.
                raise RuntimeError(
                    "model preflight refused for backend=gemini: Gemini CLI "
                    "ignored the harness admin policies (a system policies "
                    "directory is defined on this host), so cross-run memory "
                    f"and web access would stay enabled; transcript: {raw}"
                )
            if last_rc == 0 and acted:
                # A CLI that quietly falls back to another model answers a
                # wrong --model with a cheerful success, so no exit code
                # reports it. Retrying cannot change which model is served,
                # so this fails the run outright rather than costing an
                # attempt: every row of a substituted run names a model that
                # served nothing and prices its traffic at the wrong rate.
                served = llm_usage.substituted_model(raw, runtime.model)
                if served:
                    # Recorded the way a refused backend is, not left as an
                    # ordinary failed cell: substitution is deterministic, so a
                    # benchmark that cannot tell the difference re-runs it for
                    # every replicate and every resume. bin/benchmark copies
                    # these markers out of the logs dir.
                    (runtime.logs / ".backend-unavailable").touch()
                    (runtime.logs / ".run-quality").write_text(
                        "provider_limited\n", encoding="utf-8",
                    )
                    raise RuntimeError(
                        f"model preflight refused for backend={runtime.backend}: "
                        f"requested model={runtime.model} but the provider served "
                        f"{served}. Results would name a model that never ran."
                        f"{llm_usage.substitution_note(raw)}"
                        f" Transcript: {raw}"
                    )
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
        sentinel.unlink(missing_ok=True)

    message = (
        f"model preflight failed for backend={runtime.backend} "
        f"model={runtime.model} after {attempts} attempt(s) (last exit="
        f"{last_rc}): no command of its own reached {sentinel.parent}, so the "
        f"audit would spend its wall unable to act; transcript: {raw}"
    )
    raise RuntimeError(message)


def _delta_record(delta: workqueue.DeltaScope | None) -> dict | None:
    if delta is None:
        return None
    return {
        "since": delta.since, "base_rev": delta.base_rev,
        "head_rev": delta.head_rev, "commits": len(delta.commits),
        "changed_files": list(delta.files),
    }


def _refuse_changed_delta(
    path: Path, delta: workqueue.DeltaScope | None,
) -> None:
    """A results tree keeps the delta scope it was started with.

    Cards, claims, and dry conclusions in the tree were derived under that
    scope, so a run under another base — or under none — would mix a
    delta's evidence into a full audit's. Refused the way a benchmark
    cell refuses an unusable pinned build; `--experiment` names a fresh
    tree when both scopes are wanted.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return  # a fresh tree has no recorded scope to contradict
    except OSError as exc:
        raise ValueError(
            f"cannot read {path} to confirm the delta scope: {exc}"
        ) from exc
    try:
        previous = json.loads(text)
    except ValueError as exc:
        # The write is atomic, so a present file parses or is corrupt;
        # a corrupt one cannot prove the scope, so it stops the run.
        raise ValueError(
            f"{path} is unreadable; cannot confirm the delta scope: {exc}"
        ) from exc
    recorded = previous.get("delta") if isinstance(previous, dict) else None
    recorded_scope = (
        str(recorded.get("base_rev") or ""),
        str(recorded.get("head_rev") or ""),
        tuple(str(item) for item in (recorded.get("changed_files") or [])),
    ) if isinstance(recorded, dict) else ("", "", ())
    requested_scope = (
        delta.base_rev, delta.head_rev, tuple(delta.files)
    ) if delta is not None else ("", "", ())
    if recorded_scope == requested_scope:
        return

    def describe(base: str, since: str) -> str:
        return f"--since {since} ({base[:12]})" if base else "no --since"

    recorded_since = (
        str(recorded.get("since") or "") if isinstance(recorded, dict) else ""
    )
    raise ValueError(
        "this results tree's delta scope changed: it was started with "
        f"{describe(recorded_scope[0], recorded_since)} at "
        f"{recorded_scope[1][:12] or '<no head>'} and cannot resume with "
        f"{describe(requested_scope[0], delta.since if delta else '')} at "
        f"{requested_scope[1][:12] or '<no head>'}; restore the recorded "
        "checkout and pass the same --since, or use --experiment <name> for "
        "a separate tree"
    )


def _write_run_config(
    path, total, browser, shell, backend, model, slug, agent_security,
    delta: workqueue.DeltaScope | None = None,
) -> None:
    payload = {
        "num_agents": total, "browser_agents": browser, "shell_agents": shell,
        "backend": backend, "model": model,
        "resolved_effort": llm_invoke.default_effort(backend), "target_slug": slug,
        "agent_security": agent_security,
        "agent_count_overridden": bool(os.environ.get("NUM_AGENTS")),
        "delta": _delta_record(delta),
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
    #
    # The pin and the peer-mining switch decide which generators run at all,
    # so they are part of the queue's identity. Without them a re-run under a
    # different --strategy reads its predecessor's queue as fresh and never
    # rebuilds it — and on a VCS target ttl=0 makes that permanent.
    inputs: list[str] = []
    inputs.extend(str(path) for path in sorted((runtime.results / "coverage").glob("edges-agent-*.journal")))
    inputs.extend(str(path) for path in sorted((runtime.results / "corpus").glob("COVER-*/metadata.md")))
    if source_signature is None:
        source_signature = target_config.vcs_source_signature(
            runtime.target_root, include_untracked=False,
        )
    # The call-neighbourhood graph keys on inputs this signature does not see
    # — the sanitizer route, the built artifact, the parser version. Without
    # this the gate can return before rank-work runs, so installing trailmark
    # or retargeting a binary never rebuilds the graph. Empty when the
    # analysis is unavailable, which is the common case and changes nothing.
    callgraph_signature = callgraph.cache_signature(
        runtime.target_root, runtime.results,
        source_signature=source_signature,
    )
    config = getattr(runtime, "config", None)
    rank_config = json.dumps(
        {
            "s4_campaign_supported": workqueue.campaign_supported(config),
            "s6_domain": getattr(config, "s6_domain", ""),
            "s6_peers": getattr(config, "s6_peers", []),
            "fixed_strategy": str(getattr(runtime, "fixed_strategy", "")).upper(),
            "delta_base": getattr(
                getattr(runtime, "delta", None), "base_rev", "",
            ),
            "peer_mining_disabled":
                os.environ.get("AUDIT_DISABLE_PEER_FIX_CARDS", "") == "1",
        },
        sort_keys=True, separators=(",", ":"),
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
    # The rank limit buys distinct source files; their per-strategy cards are
    # independent completion surfaces but did not consume extra window slots.
    # Count each file once so a small target does not trigger a needless second
    # full ranking pass merely because each file signalled many angles. The
    # campaign and peer cards never came from the window at all.
    core_surfaces = {
        ("file", workqueue.normalized_relpath(card.get("file", "")))
        if card.get("kind") == "ranked-source"
        else ("card", str(card.get("id", "")))
        for card in cards
        if card.get("kind") not in {"s4-campaign", "s6-peer-fix"}
    }
    core_count = len(core_surfaces)
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
    pinned_strategy = str(getattr(runtime, "fixed_strategy", "")).upper()
    pinned_s1 = pinned_strategy == "S1"
    pinned_s4 = pinned_strategy == "S4"
    pinned_s6 = pinned_strategy == "S6"
    delta = getattr(runtime, "delta", None)
    patch_generator = runtime.root / "bin" / "patch-cards"
    if pinned_s4:
        # The campaign card has no generator and is not ranked source, so a
        # pinned S4 queue is that one card and every other source is skipped.
        patch_cards.unlink(missing_ok=True)
        (runtime.results / "s6-peer-cards.jsonl").unlink(missing_ok=True)
        cards = []
        if workqueue.campaign_supported(runtime.config):
            cards.append(workqueue.campaign_card(_queue_context(runtime)))
        workqueue.write_cards(
            runtime.results / "work-cards.jsonl",
            workqueue.apply_latest_claim_status(_queue_context(runtime), cards),
        )
        _write_rank_window(runtime, rank_limit)
        housekeeping.mark_clean("work-cards-refresh", signature)
        return True
    if pinned_strategy and not pinned_s1:
        patch_cards.unlink(missing_ok=True)
    elif patch_generator.is_file():
        command = [
            str(patch_generator), "--target-path", str(runtime.target_root),
            "--target-slug", runtime.target_slug, "--results-dir", str(runtime.results),
            "--limit", str(rank_limit), "--output", str(patch_cards), "--quiet",
        ]
        if delta is not None:
            command += ["--since", delta.base_rev]
        completed = subprocess.run(
            command,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        if completed.returncode:
            patch_cards.unlink(missing_ok=True)
            refresh_ok = False
            runtime.s1_source_degraded = True
            index_log(runtime, f"WARN: patch-cards refresh failed rc={completed.returncode}; stale cards removed")
        else:
            runtime.s1_source_degraded = False
    else:
        # Missing generator: a permanent fault, not a degraded source (see the
        # peer-mining branch below), so a pinned lane is left to stop.
        patch_cards.unlink(missing_ok=True)
        if pinned_s1:
            refresh_ok = False
            index_log(runtime, "WARN: patch-cards is missing; pinned S1 queue cannot be generated")
    peer_cards = runtime.root / "bin" / "peer-fix-cards"
    peer_mining_disabled = os.environ.get("AUDIT_DISABLE_PEER_FIX_CARDS") == "1"
    if (pinned_strategy and not pinned_s6) or peer_mining_disabled \
            or delta is not None:
        # Peer mining is S6's card source alone; another pinned lane can never
        # claim what it produces, and an operator disable must remove prior
        # output before rank-work can merge it back into the queue. A delta
        # run emits nothing outside the delta, and peer cards come from
        # other projects' histories, not this range.
        (runtime.results / "s6-peer-cards.jsonl").unlink(missing_ok=True)
    elif peer_cards.is_file():
        completed = subprocess.run(
            [str(peer_cards), "--target-path", str(runtime.target_root),
             "--target-slug", runtime.target_slug, "--results-dir", str(runtime.results),
             "--output", str(runtime.results / "s6-peer-cards.jsonl")],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False,
        )
        if completed.returncode:
            (runtime.results / "s6-peer-cards.jsonl").unlink(missing_ok=True)
            refresh_ok = False
            runtime.s6_source_degraded = True
            index_log(runtime, f"WARN: peer-fix-cards refresh failed rc={completed.returncode}; stale cards removed")
        else:
            runtime.s6_source_degraded = False
    else:
        # A missing generator is a permanent fault, not a degraded source, so
        # the campaign is left to stop rather than retried for the whole wall.
        (runtime.results / "s6-peer-cards.jsonl").unlink(missing_ok=True)
        if pinned_s6:
            refresh_ok = False
            index_log(runtime, "WARN: peer-fix-cards is missing; pinned S6 queue cannot be generated")
    rank = runtime.root / "bin" / "rank-work"
    if pinned_s1:
        ctx = _queue_context(runtime)
        callgraph.refresh(ctx)
        s1_cards = workqueue.load_patch_cards(
            patch_cards, None if delta is not None else rank_limit, ctx=ctx,
        )
        workqueue.write_cards(
            runtime.results / "work-cards.jsonl",
            workqueue.apply_latest_claim_status(ctx, s1_cards),
        )
    elif pinned_s6:
        s6_cards = [
            card for card in workqueue.read_jsonl(runtime.results / "s6-peer-cards.jsonl")
            if card.get("kind") == "s6-peer-fix"
        ]
        s6_cards = workqueue.annotate_card_buildability(
            _queue_context(runtime), s6_cards,
        )
        workqueue.write_cards(
            runtime.results / "work-cards.jsonl",
            workqueue.apply_latest_claim_status(_queue_context(runtime), s6_cards),
        )
    elif rank.is_file():
        command = [
            str(rank), "--target-path", str(runtime.target_root),
            "--target-slug", runtime.target_slug,
            "--results-dir", str(runtime.results),
            "--patch-cards", str(patch_cards), "--limit", str(rank_limit),
            "--output", str(runtime.results / "work-cards.jsonl"), "--quiet",
        ]
        if pinned_strategy:
            command += ["--strategy", pinned_strategy]
        if delta is not None:
            command += ["--since", delta.base_rev]
        completed = subprocess.run(
            command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            text=True, errors="replace", check=False,
        )
        if completed.returncode:
            refresh_ok = False
            cause = str(getattr(completed, "stderr", "") or "").strip().splitlines()
            why = f"rc={completed.returncode}" + (f": {cause[-1][:200]}" if cause else "")
            if delta is not None:
                # A delta with no queue would launch the unconstrained
                # discovery slot over the whole tree; keep the scoped cards
                # and stop instead of widening.
                runtime.delta_refresh_failed = why
                index_log(runtime, f"WARN: rank-work refresh failed {why}; delta keeps its last queue")
            else:
                (runtime.results / "work-cards.jsonl").unlink(missing_ok=True)
                index_log(runtime, f"WARN: rank-work refresh failed {why}; stale cards removed")
        elif delta is not None:
            runtime.delta_refresh_failed = ""
            _log_delta_queue(runtime, delta)
    elif not pinned_s6:
        refresh_ok = False
        index_log(runtime, "WARN: rank-work is missing; work-card refresh remains dirty")
    if refresh_ok:
        _write_rank_window(runtime, rank_limit)
        # Mark the state that was ranked, not the state now: with ttl=0 no
        # periodic re-rank absorbs an input that changed mid-rank. Reusing the
        # decision signature also keeps the source scan to one per refresh.
        housekeeping.mark_clean("work-cards-refresh", signature)
    return True


def _log_delta_queue(runtime: Runtime, delta: workqueue.DeltaScope) -> None:
    """Say once per refresh what the delta bought, including a missing graph.

    Caller expansion falls open by design, so an operator reading only the
    card count cannot tell a small delta from an absent analysis; the run
    log says which it was.
    """
    cards = workqueue.read_jsonl(runtime.results / "work-cards.jsonl")
    ranked = {
        workqueue.normalized_relpath(card.get("file", ""))
        for card in cards if card.get("kind") == "ranked-source"
    }
    graph = callgraph.load(runtime.results)
    expansion = (
        f"callers={len(ranked - set(delta.files))}"
        if graph is not None and not graph.get("skipped")
        else "no caller expansion (call-neighbourhood graph unavailable)"
    )
    index_log(
        runtime,
        f"DELTA: since={delta.since} base={delta.base_rev[:12]}"
        f" head={delta.head_rev[:12]} commits={len(delta.commits)}"
        f" changed_files={len(delta.files)} {expansion} cards={len(cards)}",
    )


def expand_work_cards_if_exhausted(runtime: Runtime) -> bool:
    """Grow a fully-consumed ranked batch until the source itself is exhausted.

    "Consumed" means no *unworked* card is left, not that nothing is
    claimable: a broad ranked-source card stays claimable after its dry
    conclusion (workqueue.card_closed_for_run), so reading claimability alone
    would report the window busy forever and freeze the queue at
    RANK_WORK_LIMIT files. Cross-file supply is the run's main breadth, so
    this leans toward one extra ranking pass over a silent recall ceiling.
    """
    if str(getattr(runtime, "fixed_strategy", "")).upper() in _UNRANKED_LANE_STRATEGIES:
        return False
    if getattr(runtime, "delta", None) is not None:
        # The window is the delta; there is nothing wider to rank.
        return False
    if hasattr(runtime, "prompt_context") and hasattr(runtime, "num_agents"):
        context = runtime.prompt_context("")
        try:
            ctx = _queue_context(runtime)
            for agent in range(1, runtime.num_agents + 1):
                offer = workqueue.claim_next_card(
                    ctx, str(agent), context.mode(agent),
                    context.role(agent), claim=False, strategy=context.strategy(agent),
                    unworked_only=True,
                )
                if offer is not None:
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
    """Per-strategy count of cards an agent could still be handed.

    Supply is what the claimer would offer, so it reads the same
    card_closed_for_run rule rather than the raw claim status. A card keeps
    its recorded conclusion as that status while staying claimable — a broad
    ranked-source card always, a still-yielding concrete one until its
    distinct hypotheses run out — and counting only literal "unclaimed"
    reported those lanes starved. initialize_agent_strategies then rotated
    every agent onto the ["S1"] fallback while the queue was still offering
    their own strategy's cards. A live lease still hides a card: its owner
    is working it.
    """
    ctx = _queue_context(runtime)
    cards = workqueue.apply_latest_claim_status(
        ctx, workqueue.read_jsonl(runtime.results / "work-cards.jsonl")
    )
    conclusion_counts = workqueue.card_conclusion_counts(ctx)
    distinct_counts = workqueue.card_distinct_hypothesis_counts(ctx)
    counts = {strategy: 0 for strategy in STRATEGIES}
    for card in cards:
        status = str(card.get("status", "unclaimed"))
        if status == "claimed" or workqueue.card_closed_for_run(
            ctx, card, status,
            conclusion_counts=conclusion_counts, distinct_counts=distinct_counts,
        ):
            continue
        strategies = {str(card.get("strategy", "")).upper()}
        allowed = card.get("allowed_strategies") or []
        if isinstance(allowed, list):
            strategies.update(str(value).upper() for value in allowed)
        for strategy in strategies:
            if strategy in counts:
                counts[strategy] += 1
    return counts


#: The one strategy whose queue supply is a fixed-size campaign rather than a
#: list of candidate sites, so card count cannot rank it against the others.
_CAMPAIGN_STRATEGY = "S4"


def _agent_live_strategies(runtime: Runtime) -> dict[str, set[str]]:
    """Strategies each agent is already working, by live claim or open hypothesis.

    A claimed card leaves the unclaimed count, so an agent that just took the
    last card in its lane makes that lane look starved -- and reassigning it
    then rotates the agent off the very work it is doing, mid-investigation.
    What the agent holds is therefore consulted alongside what the queue still
    offers.
    """
    ctx = _queue_context(runtime)
    cards = {
        str(card.get("id", "")): card
        for card in workqueue.read_jsonl(runtime.results / "work-cards.jsonl")
    }
    held: dict[str, set[str]] = {}

    def _record(agent: object, *sources: object) -> None:
        # Current queues keep one card per strategy angle. Older resumed queues
        # may still carry collapsed angles in `allowed_strategies`, so include
        # those when identifying the lane an agent is already working.
        angles: set[str] = set()
        for source in sources:
            if isinstance(source, dict):
                angles.add(str(source.get("strategy", "")))
                allowed = source.get("allowed_strategies")
                if isinstance(allowed, list):
                    angles.update(str(value) for value in allowed)
            elif source:
                angles.add(str(source))
        live = {angle.upper() for angle in angles} & set(STRATEGIES)
        if live:
            held.setdefault(str(agent or ""), set()).update(live)

    ttl = workqueue.work_card_claim_ttl()
    now = datetime.now(timezone.utc)
    for card_id, claim in workqueue.latest_claims_by_card(ctx).items():
        if workqueue.claim_blocks_card(claim, ttl, now):
            _record(claim.get("agent", ""), cards.get(str(card_id)))
    for row in workqueue.read_jsonl(
        runtime.results / "state" / "hypotheses.jsonl"
    ):
        if workqueue.is_active_hypothesis_status(str(row.get("status", ""))):
            # The hypothesis records the angle actually being investigated,
            # which need not be the card's primary one.
            _record(
                row.get("agent", ""),
                cards.get(str(row.get("card_id", ""))),
                row.get("strategy", ""),
            )
    return held


def initialize_agent_strategies(runtime: Runtime) -> None:
    if runtime.fixed_strategy:
        return
    counts = _eligible_strategy_counts(runtime)
    # Card supply first — an agent pinned to a starved strategy stalls — then
    # expected yield. The tie-break carries the whole decision whenever the
    # queue gives every strategy a comparable share, and canonical numbering
    # would then hand the opening portfolio to the lowest-numbered methods
    # rather than the most productive ones.
    #
    # The campaign lane is the exception, because supply there measures breadth
    # and its supply is depth: one card by construction — one corpus, one lock,
    # one campaign per iteration — so a lane holding a whole iteration of work
    # sorted behind every lane holding a list of files, on every target
    # measured, and no bounded run ever reached it. It is never ranked. It is
    # reserved below, or it is absent.
    ranked = sorted(
        (
            strategy for strategy in STRATEGIES[1:]
            if counts[strategy] and strategy != _CAMPAIGN_STRATEGY
        ),
        key=lambda strategy: (
            -counts[strategy],
            workqueue.expected_yield_rank(strategy),
            STRATEGIES.index(strategy),
        ),
    ) or ["S1"]
    # One slot, and a reproduce one. Its own exclusive lock allows a single
    # campaign at a time, so a second agent on it exits having done nothing;
    # and the campaign is execution — build a harness, run a bounded slice,
    # replay what it finds — which is the reproduce contract, not the analysis
    # worker's read-and-hand-off. Taking the highest-numbered reproduce slot
    # leaves the default layout's sole analysis lane intact.
    reproduce = [
        agent for agent in range(1, runtime.num_agents + 1)
        if prompt.agent_role(agent, runtime.num_agents, runtime.agent_roles)
        == "reproduce"
    ]
    reserved_agent = (
        reproduce[-1]
        if counts.get(_CAMPAIGN_STRATEGY) and runtime.num_agents > 1 and reproduce
        else 0
    )
    # Ranked lanes fill the remaining agents in order, so reserving one slot
    # shortens the opening portfolio by one rather than displacing a lane.
    position = {
        agent: index
        for index, agent in enumerate(
            agent for agent in range(1, runtime.num_agents + 1)
            if agent != reserved_agent
        )
    }
    state = runtime.results / "state"
    state.mkdir(parents=True, exist_ok=True)
    live = _agent_live_strategies(runtime)
    for agent in range(1, runtime.num_agents + 1):
        path = state / f"strategy-{agent}"
        try:
            current = path.read_text(encoding="utf-8").strip().upper()
        except OSError:
            current = ""
        # Re-assigned when the lane offers nothing and holds nothing, not only
        # when the file is unreadable: an agent whose strategy has no claimable
        # card and no work of its own cannot act, and nothing else moves it.
        # Post-iteration rotation is the wrong place to catch that -- it never
        # runs on a provider-interrupted iteration, and its evidence is
        # productivity, which a starved agent cannot produce either way. An
        # empty lane needs no streak to be conclusive, but it is only empty if
        # the agent is not already working it: a card this agent claimed has
        # left the unclaimed count, and rotating on that would pull the agent
        # off its own live investigation. A starved campaign lane also clears
        # `reserved_agent` above, so the agent lands on a ranked lane rather
        # than back on the empty one.
        if current not in STRATEGIES or not (
            counts.get(current) or current in live.get(str(agent), ())
        ):
            selected = (
                _CAMPAIGN_STRATEGY if agent == reserved_agent
                else ranked[position[agent] % len(ranked)]
            )
            if selected != current:
                path.write_text(selected + "\n", encoding="utf-8")


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
    agents: Collection[int] | None = None,
) -> None:
    """Advance each agent's dry streak once and rotate a starved lane.

    `agents` restricts the pass to slots that ended a session in this
    generation; a slot mid-session earns neither a dry mark nor a rotation
    for a generation it did not finish.
    """
    if runtime.fixed_strategy:
        return
    counts = _eligible_strategy_counts(runtime)
    assigned = {context.strategy(agent) for agent in range(1, runtime.num_agents + 1)}
    ctx = _queue_context(runtime)
    scored = set(agents) if agents is not None else set(range(1, runtime.num_agents + 1))
    for agent in range(1, runtime.num_agents + 1):
        if agent not in scored:
            continue
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
    agents: Collection[int] | None = None,
) -> None:
    """Record one dry/productive outcome for each subsystem touched this pass."""
    ctx = _queue_context(runtime)
    outcomes: dict[str, bool] = {}
    scored = set(agents) if agents is not None else set(range(1, runtime.num_agents + 1))
    for agent in range(1, runtime.num_agents + 1):
        if agent not in scored:
            continue
        subsystem = workqueue.agent_current_scopes(ctx, str(agent))[0]
        productive = agent in productive_agents
        if subsystem:
            outcomes[subsystem] = outcomes.get(subsystem, False) or productive
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
    # Tallied once when the session ends. `transcript_events == 0` means
    # nothing parsed, which is not the same as a session that did nothing.
    tool_calls: int = 0
    transcript_events: int = 0


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
    """Renew each slot's sanitizer-launch budget.

    Under the same lock `bin/run-sanitizer-multi` takes to add to the tally,
    so a probe in flight beside the reset cannot write its old total back
    over the zero and keep the exhausted budget for another generation.
    """
    for agent in range(1, runtime.num_agents + 1):
        counter = runtime.logs / f".sanitizer_runs_{agent}"
        counter.parent.mkdir(parents=True, exist_ok=True)
        with counter.open("a+", encoding="utf-8") as stream:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                stream.seek(0)
                stream.truncate()
                stream.write("0")
                stream.flush()
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


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


def _scan_transcript(
    raw_path: Path, quota_marker: Path | None = None,
) -> tuple[str, int, int]:
    """(provider issue, tool calls, parsed events) from one transcript pass.

    Two numbers, not one: no tool call means the session did nothing, but no
    parsed event at all means the transcript said nothing about it — and those
    have to stay distinguishable, or an unreadable log would be filed as an
    agent that could not act.
    """
    tools = events = 0

    def tally_event(event: dict) -> None:
        nonlocal tools, events
        events += 1
        tools += audit_helpers._event_tool_counts(event)[1]

    try:
        with raw_path.open(encoding="utf-8", errors="replace") as raw_stream:
            issue = audit_helpers._provider_issue_from_lines(
                raw_stream, quota_marker, tally_event,
            )
    except OSError:
        # The watchdog marker is authoritative and the former two-pass path
        # classified it before opening the transcript. Preserve that verdict
        # if a partial or concurrently replaced log fails while this fused
        # pass is also tallying events.
        issue = (
            "capacity_limited"
            if quota_marker is not None and quota_marker.is_file()
            else "none"
        )
    return issue, tools, events


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
    launched_at = datetime.now(timezone.utc)
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
    served = llm_usage.substituted_model(raw_path, runtime.model)
    if served:
        # The preflight's gate saw the requested model; this session did not.
        # The row names what ran so the ledger prices the right rate card.
        usage["served_model"] = served
        index_log(
            runtime,
            f"WARN: agent {agent} requested model={runtime.model} but the "
            f"provider served {served}; its usage row is priced as {served}."
            f"{llm_usage.substitution_note(raw_path)}",
        )
    issue, tools, events = _scan_transcript(raw_path, quota_marker)
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
    ended_at = datetime.now(timezone.utc)
    probe_stats = workqueue.probe_span_stats(
        runtime.results, str(agent), launched_at, ended_at,
    )
    event = {
        "timestamp": ended_at.isoformat(), "iteration": iteration,
        # Session span: occupancy is occupied seconds over seats × wall, and a
        # seat idle at the barrier is invisible without both ends recorded.
        "started": launched_at.isoformat(), "ended": ended_at.isoformat(),
        "seconds": round((ended_at - launched_at).total_seconds(), 3),
        "agent": agent, "role": role, "backend": runtime.backend, "model": runtime.model,
        "resolved_effort": llm_invoke.default_effort(runtime.backend),
        "usage_complete": usage_complete, "turn_capped": turn_capped,
        "turn_soft_cap": turn_cap,
        "returncode": rc, "provider_issue": issue, "prompt_chars": len(rendered),
        "tool_calls": tools, "transcript_events": events,
        # Where the session's wall went, from state: reasoning before the
        # first probe, seconds inside probes, and probes that paid.
        **probe_stats,
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
    first_probe = probe_stats.get("first_probe_seconds")
    index_log(
        runtime,
        f"Agent {agent} {launch} {outcome} provider={issue} "
        f"tokens={token_display} probes={probe_stats['probes']}"
        f"{'' if first_probe is None else f' first-probe={first_probe:.0f}s'}"
        f" probe-seconds={probe_stats['probe_seconds']:.0f} log={text_path.name}",
    )
    return AgentResult(
        agent, role, rc, raw_path, text_path, usage, issue, reset_at, turn_capped,
        tools, events,
    )


def run_agent_guarded(
    runtime: Runtime, context: prompt.PromptContext, agent: int,
    iteration: int, cold: bool, timeout_limit: int | None = None,
) -> AgentResult:
    """Keep one internal worker failure from discarding the other slots' work."""
    try:
        return run_agent(runtime, context, agent, iteration, cold, timeout_limit)
    except Exception as exc:
        import traceback

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


def filed_artifact_count(runtime: Runtime) -> int:
    """Raw on-disk FIND-/CRASH- subdirs, admitted or not.

    progress() counts only admitted findings and confirmed crashes, so a
    candidate filed but not yet adjudicated is invisible to it. This raw total
    lets the iteration label separate "filed, awaiting adjudication" from a
    genuinely env-blocked or dry iteration — rejected artifacts have already
    been moved to the *-rejected trees and so are not counted.
    """
    import benchmark
    return (
        benchmark.count_subdirs(runtime.results / "findings", "FIND-")
        + benchmark.count_subdirs(runtime.results / "crashes", "CRASH-")
    )


def iteration_outcome_label(
    *, productive: bool, filed: bool, diagnostic: bool,
) -> str:
    """The operator-facing name for an iteration's result.

    A candidate filed this iteration but not yet admitted (the result gate
    deferred past the deadline) is neither dry nor env-blocked, so it gets its
    own name rather than being read as a blocked or empty iteration. Filing and
    env-blocking are independent, though — an iteration can file one candidate
    and close another hypothesis on the environment — so when both happened the
    label carries both rather than letting the filing hide the block an
    operator is looking for.

    This names the log line only. Productivity (admitted findings and confirmed
    crashes), dry_streak, and strategy rotation are decided by the caller and
    are not affected by what this returns.
    """
    if productive:
        return "productive"
    if filed:
        return "filed-unadjudicated+env-blocked" if diagnostic else "filed-unadjudicated"
    return "env-blocked" if diagnostic else "dry"


def agent_progress(runtime: Runtime, agent: int, snapshot: ProgressSnapshot) -> AgentProgress:
    counts = structured_state.agent_counts(str(agent), runtime.results) or {}
    roots_by_status: dict[str, set[str]] = {}
    for artifact, root in snapshot.artifact_roots.items():
        status_id = workqueue._artifact_status_id(artifact)
        roots_by_status.setdefault(status_id, set()).add(root)
    roots: set[str] = set()
    for row in structured_state.agent_rows(str(agent), runtime.results):
        status = str(row.get("status", ""))
        if status in snapshot.artifact_roots:
            roots.add(snapshot.artifact_roots[status])
            continue
        roots.update(roots_by_status.get(workqueue._artifact_status_id(status), ()))
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


def _timed(call, *args, **kwargs):
    """Run a call and report what it spent, for a span it shares with another."""
    started = time.monotonic()
    return call(*args, **kwargs), time.monotonic() - started


@contextlib.contextmanager
def _phase_span(
    spans: list[str], name: str, *, detail: list[str] | None = None,
    records: list[dict] | None = None,
):
    """Record one post_iteration phase's duration.

    Housekeeping has been a single aggregate number, so a barrier that costs a
    fifth of the audit wall could not be attributed to a phase and every
    estimate had to be inferred from decision timestamps. Timing is advisory:
    a span never changes a disposition, and a phase that raises still records
    what it spent before failing.

    `detail` carries the sub-phases of a span whose work overlaps, so the top
    level still sums to the housekeeping wall without losing attribution.
    """
    started = time.monotonic()
    try:
        yield
    finally:
        seconds = time.monotonic() - started
        suffix = f"({' '.join(detail)})" if detail else ""
        spans.append(f"{name}={seconds:.1f}s{suffix}")
        # The structured twin of the log token, read by lib/telemetry.py:
        # the log line is for the operator, the row is for the harvest.
        if records is not None:
            records.append({"phase": name, "seconds": round(seconds, 3)})


def _log_phase_spans(
    runtime: Runtime, spans: list[str], *,
    records: list[dict] | None = None, iteration: int | None = None,
) -> None:
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
    # Every phase here ran while the pool was empty, so it blocked discovery.
    _record_phase_rows(runtime, records, iteration=iteration, blocked=True)


def _record_phase_rows(
    runtime: Runtime, records: list[dict] | None, *,
    iteration: int | None, blocked: bool,
) -> None:
    """Append phase rows to the timeline; advisory, never fatal."""
    if not records:
        return
    rows = [
        {"type": "housekeeping_phase", "iteration": iteration, "blocked": blocked,
         "recorded": datetime.now(timezone.utc).isoformat(), **record}
        for record in records
    ]
    try:
        events = Path(runtime.results) / "state" / "events.jsonl"
        events.parent.mkdir(parents=True, exist_ok=True)
        workqueue.append_jsonl_many(events, rows)
    except (OSError, AttributeError, TypeError) as exc:
        print(
            f"WARN: housekeeping phase rows could not be recorded: {exc}",
            file=sys.stderr,
        )


def _result_gate_pass(
    runtime: Runtime, *, deadline: float | None, detail: list[str] | None = None,
) -> tuple[dict, dict]:
    """Run the find gate and cluster expansion together, returning their counts.

    The two touch disjoint trees — findings/ against crashes/ plus the
    flock-serialized work queue — so overlapping them takes the shorter off
    the wall. It is the body of the result_gates phase, run as a single serial pass.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        expansion = pool.submit(
            _timed, expand_new_crash_clusters, runtime, deadline=deadline,
        )
        try:
            finding_counts, gate_seconds = _timed(
                triage.validate_find_gate, runtime.results,
                workers=runtime.num_agents, deadline=deadline,
                target_root_is_product=True,
            )
        finally:
            # Collected even when the gate raised, so an expansion failure
            # is not discarded behind the gate's.
            cluster_counts, expand_seconds = expansion.result()
    if detail is not None:
        detail.append(f"finding_gate={gate_seconds:.1f}s")
        detail.append(f"cluster_expand={expand_seconds:.1f}s")
    return finding_counts, cluster_counts


def post_iteration(
    runtime: Runtime, *, deadline: float | None = None,
    iteration: int | None = None,
) -> None:
    spans: list[str] = []
    records: list[dict] = []
    try:
        with _phase_span(spans, "crash_triage", records=records):
            crash_counts = triage.triage_crash_dirs(
                runtime.results, runtime.target_root, runtime.target_slug,
                runtime.config.attacker_controls, workers=runtime.num_agents,
                findings_only=runtime.config.sanitizers_explicitly_disabled,
                deadline=deadline, target_root_is_product=True,
            )
        # Both gates are provider-latency bound and touch disjoint trees —
        # findings/ against crashes/ plus the flock-serialized work queue — so
        # running them together takes the shorter of the two off the audit
        # wall. Crash triage keeps its place in front of both: it demotes
        # crashes into findings/ and settles the crash set expansion reads.
        gate_detail: list[str] = []
        with _phase_span(spans, "result_gates", detail=gate_detail, records=records):
            finding_counts, cluster_counts = _result_gate_pass(
                runtime, deadline=deadline, detail=gate_detail,
            )
        # Discovery and disposition stamps for the timeline, stamped before the
        # deadline gate below. The find gate already stamps finding discovery
        # inside the result-gate pass; crash stamps must land here too, or a
        # wall-cut iteration returns having left its crashes off the timeline
        # while its findings stayed on it. Telemetry only: loud but never able
        # to fail the gates it rode in behind.
        with _phase_span(spans, "artifact_events", records=records):
            try:
                triage.record_artifact_events(runtime.results)
            except Exception as exc:  # noqa: BLE001 - telemetry is never worth a gate
                print(
                    f"WARN: artifact event stamps unavailable ({exc}); "
                    "timeline may be incomplete", file=sys.stderr,
                )
        if deadline is not None and time.monotonic() >= deadline:
            index_log(
                runtime,
                "Housekeeping: productive wall budget reached during result triage; "
                "remaining index work deferred",
            )
            return
        with _phase_span(spans, "indexes", records=records):
            maintain_local_indexes(runtime)
            maintain_aggregate_indexes(runtime)
        with _phase_span(spans, "orphan_enforce", records=records):
            enforced = enforce_orphan_testcases(runtime, deadline=deadline)
        with _phase_span(spans, "corpus_promote", records=records):
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
        _log_phase_spans(runtime, spans, records=records, iteration=iteration)


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
    only: Collection[Path] | None = None,
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
    if only is not None:
        chosen = {Path(path) for path in only}
        candidates = [crash for crash in candidates if crash in chosen]
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
    try:
        decisions = triage.cluster_expansion_decisions(
            crashes,
            runtime.target_root,
            attacker_controls=runtime.config.attacker_controls,
            deadline=deadline,
        )
    except Exception as exc:
        decisions = {crash: None for crash in crashes}
        index_log(runtime, f"WARN: cluster expansion failed: {exc}")
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
    corpus = runtime.results / "corpus"
    promoted = 0
    for agent in range(1, runtime.num_agents + 1):
        hits = runtime.results / f"hits-{agent}.log"
        label = f"corpus-agent-{agent}"
        # Every promotable testcase has a HIT journal row. Using that journal
        # avoids recursively statting a potentially large scratch tree each
        # iteration.
        signature = housekeeping.signature(label, [str(hits)])
        if not hits.is_file() or not housekeeping.should_run(label, signature, 0):
            continue
        try:
            tally = quality.promote_corpus(str(hits), str(corpus), str(agent))
        except (Exception, SystemExit) as exc:  # noqa: BLE001 - fail open
            index_log(runtime, f"WARN: corpus promotion failed for agent {agent}: {exc}")
            continue
        promoted += tally["promoted"]
        housekeeping.mark_clean(label, signature)
    if promoted:
        try:
            index_ok = quality.regenerate_corpus_index(str(corpus))
        except (Exception, SystemExit) as exc:  # noqa: BLE001 - fail open
            index_log(runtime, f"WARN: corpus index regeneration failed: {exc}")
        else:
            if not index_ok:
                index_log(runtime, "WARN: corpus index regeneration failed")
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
    # Nothing below can run without budget or wall, and scanning every agent's
    # scratch tree to discover that is the one cost this function pays before
    # its own cap applies.
    if maximum <= 0 or (deadline is not None and time.monotonic() >= deadline):
        return 0
    # One budget shared by every agent, spent round-robin. Draining agent 1's
    # orphans first spent all of it on the lowest-numbered agent: on measured
    # 3-agent runs 17 of 18 enforcements went to agent 1, so the other agents'
    # unexecuted testcases were never probed and their next session never saw
    # the enforcement feedback that names them.
    queues: list[tuple[int, list[str]]] = []
    for agent in range(1, runtime.num_agents + 1):
        _runs, _testcases, orphans = quality.scan_scratch(
            str(runtime.results / f"scratch-{agent}")
        )
        runnable = []
        for testcase in orphans:
            try:
                if Path(testcase).stat().st_size:
                    runnable.append(testcase)
            except OSError:
                continue
        queues.append((agent, runnable))
    for index in range(max((len(runnable) for _agent, runnable in queues), default=0)):
        for agent, runnable in queues:
            if index >= len(runnable):
                continue
            testcase = runnable[index]
            results_file = runtime.results / f".enforcement_results_{agent}"
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
            # Probe's order: a partial SUCCESS_RATE still matches the clean
            # pattern, so the timeout has to be read before it.
            if output.is_file() and verdict.file_has_crash(output):
                label = "CRASH"
            elif completed.returncode == 124:
                label = "TIMEOUT"
            elif output.is_file() and verdict.file_is_clean(output):
                label = "CLEAN"
            elif output.is_file() and verdict.file_execution_attempted(output):
                label = "EXEC_FAIL"
            else:
                label = "NO_EXEC"
            _append(results_file, f"- {label} `{Path(testcase).name}` — harness probe rc={completed.returncode}")
            index_log(runtime, f"orphan enforcement: agent={agent} testcase={Path(testcase).name} verdict={label}")
            enforced += 1
    return enforced


def _cold(runtime: Runtime) -> bool:
    return not any(
        structured_state.agent_rows(str(agent), runtime.results)
        or workqueue.agent_has_card_activity(runtime.results, str(agent))
        for agent in range(1, runtime.num_agents + 1)
    )


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
    return prompt.fuzz_leads_empty(runtime.results)


def delta_queue_exhausted(
    runtime: Runtime, context: prompt.PromptContext,
) -> bool:
    """Whether a delta has no scoped work left for any agent.

    A normal audit keeps agent 1 as an unconditional discovery slot when the
    queue is dry. Delta mode cannot: that session has no card to constrain it
    and would turn an empty ``REV..HEAD`` into a whole-tree audit recorded as a
    delta. Ask every slot through the ordinary work-source predicate without
    the primary exception; unreadable state still falls open there.
    """
    if getattr(runtime, "delta", None) is None:
        return False
    return all(
        should_skip_launch(
            runtime, context, agent, primary_always_launches=False,
        )
        for agent in range(1, runtime.num_agents + 1)
    )


def _s6_peers_configured(runtime: Runtime) -> bool:
    return bool(getattr(getattr(runtime, "config", None), "s6_peers", []))


def _pinned_lane_work_open(runtime: Runtime, card_ids: set[str]) -> bool:
    """Is an active hypothesis still doing this pinned lane's work?

    Matched by one of the lane's own cards or by the pin, never by activity
    alone: work carried in from an earlier pin belongs to that strategy, and
    counting it would keep this campaign running on results it never produced.
    """
    pinned = str(getattr(runtime, "fixed_strategy", "")).upper()
    for row in structured_state.rows(runtime.results):
        if str(row.get("status", "")) not in structured_state.ACTIVE:
            continue
        if str(row.get("card_id", "")) in card_ids:
            return True
        if workqueue.strategy_matches_pin(row.get("strategy", ""), pinned):
            return True
    return False


def _log_foreign_active_work(runtime: Runtime) -> None:
    """Name pre-existing active work that a new pin does not cover.

    `add-hyp` refuses an off-pin hypothesis, so this can only be work carried
    in from an earlier run in the same results directory. It stays runnable
    rather than filtered — hiding it would strand the rows with no owner — but
    a pinned run whose totals include another strategy's yield must say so.
    """
    pinned = str(getattr(runtime, "fixed_strategy", "")).upper()
    if not pinned:
        return
    foreign = sorted({
        str(row.get("strategy", "")).strip().upper() or "unlabelled"
        for row in structured_state.rows(runtime.results)
        if str(row.get("status", "")) in structured_state.ACTIVE
        and not workqueue.strategy_matches_pin(row.get("strategy", ""), pinned)
    })
    if foreign:
        index_log(
            runtime,
            f"WARN: pinned {pinned} run carries active work from "
            f"{', '.join(foreign)}; those results are attributed to their own "
            "strategy, not to the pin",
        )


# The card kind a pinned lane consumes when it has a generator of its own. A
# pin outside this map draws from the ranked window, where "no card" means the
# scorer signalled nothing — not that the strategy has no surface to audit.
_FIXED_LANE_KINDS = {
    "S1": "s1-patch", "S4": "s4-campaign", "S6": "s6-peer-fix",
}

# The subset whose cards do not come from the ranked window at all. S1 is not
# one of them: its patch cards are capped by that window, so growing it is
# what mines the next batch of prior fixes.
_UNRANKED_LANE_STRATEGIES = frozenset({"S4", "S6"})


def _fixed_lane_source_degraded(runtime: Runtime, strategy: str) -> bool:
    """Whether this pin's card source failed rather than answered "nothing"."""
    if strategy == "S1":
        return bool(getattr(runtime, "s1_source_degraded", False))
    if strategy == "S6":
        return bool(getattr(runtime, "s6_source_degraded", False))
    # S4 and a missing peer set are both read fresh from the target config,
    # which answers definitively; `_fixed_lane_unavailable` reports that "no"
    # rather than holding the lane open for a source that cannot recover.
    return False


def _fixed_lane_unavailable(runtime: Runtime) -> str:
    """Why this pin cannot run against this target at all, or "" if it can."""
    pinned = str(getattr(runtime, "fixed_strategy", "")).upper()
    if pinned == "S4" and not workqueue.campaign_supported(runtime.config):
        return (
            "S4 requires a native sanitizer library; use S7 for this "
            "findings-only or CLI-only target"
        )
    if pinned == "S6" and not _s6_peers_configured(runtime):
        return (
            "S6 requires configured peer projects; run bin/suggest-peers "
            "or drop the pin"
        )
    return ""


def fixed_lane_exhausted(runtime: Runtime, iteration: int = 0) -> bool:
    """Whether a pinned, finite card lane has no work left.

    A lane with its own generator (S1 patch cards, S4's campaign, S6 peer
    fixes) can read an empty queue as its source's answer, so it gets one
    discovery iteration and then stops.  A ranked-window lane cannot: no ranked
    card only means the scorer signalled nothing, which is not proof the
    strategy has no surface, so it keeps its normal runway.  Once any lane did
    receive cards, relaunching after every one is closed cannot expose more.
    Productive cards use the queue's normal scope-aware closure rule: one
    finding is a reason to search clustered variants, not an exhaustion proof.

    An open hypothesis still can, so it holds the run open the way STALL_STOP
    requires: an agent can close its card and keep investigating what the card
    started, and stopping there would strand that work unfinished. Only *this
    lane's* open work counts: a results directory reused across pins carries
    active hypotheses from the earlier strategy, and letting those hold the
    current lane open keeps the run alive on work that lane never did.
    """
    pinned = str(getattr(runtime, "fixed_strategy", "")).upper()
    if not pinned:
        return False
    if _fixed_lane_unavailable(runtime):
        return True
    kind = _FIXED_LANE_KINDS.get(pinned)
    ctx = _queue_context(runtime)
    supplied = [
        card for card in workqueue.apply_latest_claim_status(
            ctx, workqueue.read_jsonl(runtime.results / "work-cards.jsonl")
        )
        if (
            card.get("kind") == kind if kind
            else workqueue.card_strategy_matches(card, pinned)
        )
    ]
    if _pinned_lane_work_open(
        runtime, {str(card.get("id", "")) for card in supplied},
    ):
        return False
    if not supplied:
        # An empty ranked window is a ranking gap, not a finished lane.
        if kind is None:
            return False
        # An empty generator result only proves exhaustion when the source
        # could answer. A peer set that is missing, unreachable, or returning
        # nothing is a fault to surface, not a lane that finished with no yield.
        if _fixed_lane_source_degraded(runtime, pinned):
            return False
        return iteration > 1
    conclusion_counts = workqueue.card_conclusion_counts(ctx)
    distinct_counts = workqueue.card_distinct_hypothesis_counts(ctx)
    return all(
        workqueue.card_closed_for_run(
            ctx, card, str(card.get("status", "unclaimed")),
            conclusion_counts=conclusion_counts,
            distinct_counts=distinct_counts,
        )
        for card in supplied
    )


def release_stale_card_claims(
    runtime: Runtime, *, keep_agents: Collection[int] = (),
) -> int:
    try:
        return len(workqueue.release_stale_claims(
            _queue_context(runtime), keep_agents=[str(agent) for agent in keep_agents],
        ))
    except (OSError, ValueError):
        return 0


def assign_build_configs(
    runtime: Runtime, context: prompt.PromptContext, iteration: int,
    *, skip_agents: Collection[int] = (),
) -> None:
    """Keep a regular-build control while rotating one reproducer slot.

    Assignments are session state consumed automatically by bin/probe. A slot
    with active work stays on its current build so an investigation does not
    change binaries mid-hypothesis; `skip_agents` (slots with a session in
    flight) are left untouched for the same reason even before they open one.
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
        if agent in skip_agents:
            continue
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
    # Continuous scheduler only: no slot refills once this many steward
    # generations have opened (0 = unbounded); in-flight sessions finish.
    max_generations: int = 0


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
    # Imported here: http.server costs ~50ms at startup for one preflight probe.
    import http.server

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
        post_iteration(
            state.runtime, deadline=_productive_wall_deadline(state),
            iteration=state.iteration,
        )
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
_PROVIDER_HALT_ISSUES = ("capacity_limited", "transient", "backend_rejected")


def _session_did_work(result: AgentResult) -> bool:
    """Whether a finished session acted at all, so its slot is worth reusing.

    Work availability is sticky — a fuzz lead stays listed and a PENDING
    hypothesis stays active for the whole pool — so it cannot bound how often a
    slot relaunches. A transcript that parsed but holds no tool call is the one
    positive signal that a session did nothing and that its replacement would
    repeat the same no-op. Falls open when nothing parsed at all: an unreadable
    or unrecognised transcript must not silently disable a backend's refills.
    """
    return result.tool_calls > 0 or result.transcript_events == 0


_CRASH_OWNER_RE = re.compile(r"CRASH-\d+-(\d+)$")


def _crash_owner(name: str) -> int | None:
    """The slot that filed a crash bundle, from the name bin/probe gave it."""
    match = _CRASH_OWNER_RE.match(name)
    return int(match.group(1)) if match else None


class SealedGateWorker:
    """Adjudicate artifacts no live session can still write, while agents run.

    The barrier held every result gate until the slowest slot returned:
    measured cells spent 12-14% of the audit wall there with every slot
    idle, and a crash-heavy target up to 700s an iteration. None of that work
    depends on the barrier, only on the artifact being finished, and an
    artifact is finished when the session that wrote it has ended. The one
    earlier attempt to gate in the background had no such seal, raced agents
    mid-write, and was reverted; the seal is the difference.

    Ownership is never read from content. A crash bundle names its slot
    (`CRASH-NNN-<agent>`), and its owner is sent back to it by every later
    resume while it is still a `bin/probe` skeleton or holds a
    `.promotion_pending` marker — so an unfinished bundle is never sealed,
    and is first seen only once complete, by which point the chain that
    completed it holds a tick no earlier. A finding names no slot, so it is
    sealed only once it predates every chain still in flight. A chain is one slot's run of
    sessions sharing in-flight work: a turn-capped session's continuation
    inherits its start, so nothing the cut session filed is sealed before the
    continuation ends. Time is a logical clock: a slot's launch takes a fresh
    tick, and the pool stamps every artifact it can see just before it
    relaunches a slot, so first-seen is an upper bound on filing time and
    sits strictly before the chain launched next. That keeps the test
    conservative on any wall clock.
    Six recorded cells (141 findings) show no session writing into a finding
    another session filed; that observation is what makes a session's end
    the seal.

    Everything a sweep does the barrier repeats over the whole tree, with the
    caches the sweep left, so a repeated verdict costs no provider call and a
    failed sweep is retried there. A sweep never ages a pending crash: the
    promotion-pending ceiling counts barrier passes, not sweeps.
    """

    def __init__(self, state: BackendState) -> None:
        self.state = state
        self.runtime = state.runtime
        self._lock = threading.Lock()
        self._clock = 0
        self._chains: dict[int, int] = {}
        self._first_seen: dict[str, int] = {}
        self._wake = threading.Event()
        self._stop = False
        self._thread: threading.Thread | None = None
        self.sweeps = 0
        self.seconds = 0.0
        self._sweep_started: float | None = None
        results = getattr(self.runtime, "results", None)
        self._results = Path(results) if results else None
        if self._results is None:
            return
        # Whatever exists before the first launch was filed by a session that
        # has already ended, or by the harness itself.
        self.observe()
        self._thread = threading.Thread(
            target=self._run, name="sealed-gate", daemon=True,
        )
        self._thread.start()

    def _artifacts(self) -> list[Path]:
        found: list[Path] = []
        for sub, prefix in (("findings", "FIND-"), ("crashes", "CRASH-")):
            root = self._results / sub
            if root.is_dir():
                found.extend(
                    path for path in sorted(root.glob(prefix + "*"))
                    if path.is_dir()
                )
        return found

    @staticmethod
    def _unfinished(directory: Path) -> bool:
        """A bundle its owner's next session is told to finish first."""
        return directory.name.startswith("CRASH-") and workqueue.crash_bundle_unfinished(directory)

    def _stamp(self, artifacts: list[Path]) -> dict[str, int | None]:
        """Record first-seen for what is complete; None for what is not."""
        seen: dict[str, int | None] = {}
        for directory in artifacts:
            if self._unfinished(directory):
                # First-seen restarts from completion, so a bundle held again
                # after a stamp cannot re-seal on the older tick.
                self._first_seen.pop(directory.name, None)
                seen[directory.name] = None
                continue
            seen[directory.name] = self._first_seen.setdefault(
                directory.name, self._clock,
            )
        return seen

    def observe(self) -> None:
        """Stamp every complete artifact on disk as seen no later than now."""
        if self._results is None:
            return
        with self._lock:
            self._stamp(self._artifacts())

    def launch(self, agent: int, *, continuation: bool) -> None:
        with self._lock:
            if not continuation or agent not in self._chains:
                self._clock += 1
                self._chains[agent] = self._clock

    def retire(self, agent: int) -> None:
        with self._lock:
            self._chains.pop(agent, None)

    def request_sweep(self) -> None:
        if self._thread is not None:
            self._wake.set()

    def close(self) -> None:
        """Finish the sweep in flight, start no other, and return.

        From the moment the pool drained, a sweep still running is the
        barrier by another name: nothing else is working. Its tail past that
        moment is charged to housekeeping and recorded as blocked, so the
        blocked share cannot hide review time behind a sweep that outlived
        the last session.
        """
        if self._thread is None:
            return
        # Stop first: a sweep cannot start after this stamp and escape billing.
        self._stop = True
        drained_at = time.monotonic()
        self._wake.set()
        self._thread.join()
        started = self._sweep_started
        if started is None or started > drained_at:
            return
        tail = time.monotonic() - drained_at
        if tail <= 0:
            return
        self.state.housekeeping_seconds += tail
        try:
            (self.runtime.logs / ".housekeeping_secs").write_text(
                f"{self.state.housekeeping_seconds:.6f}\n", encoding="utf-8",
            )
        except (OSError, AttributeError, TypeError):
            pass
        _record_phase_rows(
            self.runtime, [{"phase": "gate_drain", "seconds": round(tail, 3)}],
            iteration=self.state.iteration, blocked=True,
        )

    def _run(self) -> None:
        while True:
            self._wake.wait()
            self._wake.clear()
            if self._stop:
                return
            self._sweep_started = time.monotonic()
            try:
                self._sweep()
            except Exception as exc:  # noqa: BLE001 - the barrier retries; a silent worker is the R08 failure
                index_log(
                    self.runtime,
                    "ERROR: background result gate failed: "
                    f"{type(exc).__name__}: {exc}; the barrier will retry it",
                )
            finally:
                if not self._stop:
                    self._sweep_started = None

    def sealed(self) -> tuple[list[Path], list[Path], int, int]:
        """Sealed findings and crashes, plus the totals they were drawn from."""
        with self._lock:
            chains = dict(self._chains)
            artifacts = self._artifacts()
            seen_at = self._stamp(artifacts)
            threshold = min(chains.values(), default=self._clock + 1)
        findings: list[Path] = []
        crashes: list[Path] = []
        total_findings = total_crashes = 0
        for directory in artifacts:
            seen = seen_at[directory.name]
            if seen is None:
                total_crashes += 1
                continue
            if directory.name.startswith("FIND-"):
                total_findings += 1
                if seen < threshold:
                    findings.append(directory)
                continue
            total_crashes += 1
            owner = _crash_owner(directory.name)
            start = chains.get(owner) if owner is not None else threshold
            if start is None or seen < start:
                crashes.append(directory)
        return findings, crashes, total_findings, total_crashes

    def _sweep(self) -> None:
        findings, crashes, total_findings, total_crashes = self.sealed()
        if not findings and not crashes:
            return
        deadline = _productive_wall_deadline(self.state)
        if deadline is not None and time.monotonic() >= deadline:
            return
        runtime = self.runtime
        started = time.monotonic()
        # The same phase rows the barrier writes, marked as not blocking the
        # pool: review cost per artifact keeps counting them, the blocked
        # share does not.
        records: list[dict] = []
        crash_counts = {"promoted": 0, "rejected": 0, "pending": 0, "demoted": 0}
        with _phase_span([], "crash_triage", records=records):
            if crashes:
                crash_counts.update(triage.triage_crash_dirs(
                    runtime.results, runtime.target_root, runtime.target_slug,
                    runtime.config.attacker_controls, workers=runtime.num_agents,
                    findings_only=runtime.config.sanitizers_explicitly_disabled,
                    deadline=deadline, target_root_is_product=True,
                    age_pending=False, only=crashes,
                ))
        finding_counts = {"accepted": 0, "rejected": 0, "pending": 0}
        with _phase_span([], "result_gates", records=records), \
                concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            expansion = pool.submit(
                expand_new_crash_clusters, runtime, deadline=deadline,
                only=crashes,
            )
            try:
                if findings:
                    finding_counts.update(triage.validate_find_gate(
                        runtime.results, workers=runtime.num_agents,
                        deadline=deadline, target_root_is_product=True,
                        only=findings,
                    ))
            finally:
                cluster_counts = expansion.result()
        elapsed = time.monotonic() - started
        self.sweeps += 1
        self.seconds += elapsed
        _record_phase_rows(
            runtime, records, iteration=self.state.iteration, blocked=False,
        )
        acted = (
            crash_counts["rejected"] or crash_counts["demoted"]
            or finding_counts["rejected"] or cluster_counts["added"]
        )
        if elapsed >= 1.0 or acted:
            index_log(
                runtime,
                f"Background gates: sealed findings={len(findings)}/{total_findings} "
                f"crashes={len(crashes)}/{total_crashes}: "
                f"crashes promoted={crash_counts['promoted']} rejected={crash_counts['rejected']} "
                f"pending={crash_counts['pending']} demoted={crash_counts['demoted']} "
                f"findings accepted={finding_counts['accepted']} rejected={finding_counts['rejected']} "
                f"pending={finding_counts['pending']} cluster_added={cluster_counts['added']} "
                f"in {elapsed:.1f}s",
            )


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
    The `initial` sentinel is load-bearing twice over:

    - It is the clock for iteration-counted control loops. Refilling to the
      epoch stretches an iteration from about one session to AGENT_TIMEOUT,
      which on a 5h run turns five iterations into roughly two — and strategy
      rotation needs STRATEGY_DRY_THRESHOLD *iterations* of dryness, so it
      would stop firing at all.
    - It bounds stale-signal spin. should_skip_launch reports work from sticky
      sources: a PENDING hypothesis that never resolves, or any line in
      fuzz-leads.md. Capped at a generation those cost a few sessions;
      uncapped they justify clean sessions for the whole epoch.

    Once the cohort has drained the sentinel is spent, and on a target whose
    sessions run long a fast slot lost hours to the barrier — a measured 5h
    audit idled two of three slots for the last 90 minutes of its first
    iteration, one of them holding a live NEEDS_TESTCASE lead. So each slot
    gets one overtime session, and only while a *cohort-era* peer is in flight:
    an initial session, or a refill launched while one was still running. Both
    halves of that are load-bearing. The barrier is already committed to that
    peer, so the overtime rides a wait the iteration was paying anyway; and
    refusing to let one overtime justify the next is what stops a cohort that
    drains early from growing an extra session per slot, one slot at a time.

    What remains is that an overtime session can outlive the peer that
    justified it, so an iteration can still end up one session longer than it
    was. On a backend whose sessions run to the epoch that is exactly zero; on
    one whose cohorts drain early it is real, and it trades iterations — the
    clock for strategy rotation — for agent-seconds. The idle capacity is
    measured; that trade is not. Re-measure it on a fresh cell per backend
    before treating this default as settled.

    A one-slot cohort chains nothing either way: with no peer in flight there
    is no overtime, and continuation comes from the next iteration.

    ``POOL_OVERTIME=any-peer`` relaxes the cohort-era half only: a drained slot
    may take its one overtime session beside an overtime peer too. The cap
    per slot still bounds the iteration at one extra session per slot; what
    it buys back is the idle a measured cell spent with "every peer still
    running is itself overtime" as its most common refill refusal.
    """
    runtime = state.runtime
    context = state.context
    results: list[AgentResult] = []
    policy = _pool_overtime_policy()
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
    # One session per slot after the initial cohort has drained.
    overtime: set[int] = set()
    # Provider trouble reported by any slot stops launches in all of them.
    halted = ""
    # Gates sealed artifacts while the slots run; joined before the barrier so
    # post-iteration triage never overlaps a sweep.
    gate_worker = SealedGateWorker(state)
    launched_now: set[int] = set()
    with ExitStack() as stack:
        stack.callback(gate_worker.close)
        pool = stack.enter_context(
            concurrent.futures.ThreadPoolExecutor(max_workers=runtime.num_agents)
        )
        futures: dict[concurrent.futures.Future, tuple[bool, bool]] = {}

        def launch(
            agent: int, initial: bool, cohort_era: bool = True,
            continuation: bool = False,
        ) -> None:
            gate_worker.launch(agent, continuation=continuation)
            launched_now.add(agent)
            future = pool.submit(
                run_agent_guarded, runtime, context, agent, state.iteration,
                cold and initial, epoch_remaining(),
            )
            futures[future] = (initial, cohort_era)

        for agent in agents:
            launch(agent, True)
        while futures:
            done, _ = concurrent.futures.wait(
                futures, return_when=concurrent.futures.FIRST_COMPLETED
            )
            finished = []
            launched_now.clear()
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
            # Before any relaunch: what the finished sessions filed is on disk
            # now, and must be seen before the next chain takes its tick.
            gate_worker.observe()
            # Nothing in flight means the barrier is here: the iteration ends
            # whatever this slot would do next.
            if futures and not halted and getattr(runtime, "refill_workers", True):
                _refill_finished_slots(
                    state, finished, futures, launch, policy, epoch_remaining,
                    retried, overtime,
                )
            for result in finished:
                if result.agent not in launched_now:
                    gate_worker.retire(result.agent)
            # With nothing left in flight the barrier gate is next; a sweep
            # here would do its work under the wrong accounting.
            if futures:
                gate_worker.request_sweep()
    return results


def _refill_finished_slots(
    state: BackendState, finished: list[AgentResult],
    futures: dict, launch, policy: str, epoch_remaining,
    retried: set[int], overtime: set[int],
) -> None:
    """Decide, for each slot that just finished, whether it launches again."""
    runtime = state.runtime
    context = state.context
    in_flight = list(futures.values())
    cohort_running = any(initial for initial, _era in in_flight)
    # Only a cohort-era peer justifies overtime. Letting one overtime
    # session justify the next is what turns a slot filling an idle gap
    # into an iteration that outlives its cohort by a session per slot.
    cohort_era_running = any(era for _initial, era in in_flight)
    for result in finished:
        if not cohort_running and result.agent in overtime:
            index_log(
                runtime,
                f"Worker-pool refill: agent={result.agent} slot left idle; "
                "its one overtime session is spent",
            )
            continue
        if (
            not cohort_running and not cohort_era_running
            and policy == "cohort-era"
        ):
            index_log(
                runtime,
                f"Worker-pool refill: agent={result.agent} slot left idle; "
                "every peer still running is itself overtime",
            )
            continue
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
        if not cohort_running:
            overtime.add(result.agent)
        index_log(
            runtime,
            f"Worker-pool refill: agent={result.agent} slot free; launching "
            f"{'an overtime' if not cohort_running else 'another'} session "
            f"with {remaining}s left in the epoch",
        )
        # A continuation or a retry resumes state its predecessor left
        # mid-write, so the slot's chain, and its seal, carry over.
        launch(
            result.agent, False, cohort_running,
            continuation=outcome in ("continue", "failed"),
        )


def refresh_fuzz_leads(runtime: Runtime) -> bool:
    """Refresh the bounded fuzz-lead index without starting another Python."""
    returncode = 1
    failure: BaseException | None = None
    with runtime.index.open("a", encoding="utf-8") as output:
        try:
            returncode, message = fuzz_triage.update_fuzz_leads(
                str(runtime.results), fuzz_triage.DEFAULT_MAX_LEADS,
            )
        except (Exception, SystemExit) as exc:
            # The former child process isolated this auxiliary summary from
            # the audit loop. Retain that boundary while leaving interrupts
            # and other process-control exceptions alone.
            failure = exc
            message = (
                f"[{fuzz_triage.TOOL}] failed to refresh fuzz leads: "
                f"{type(exc).__name__}: {exc}"
            )
        if message:
            print(message, file=output)
    if failure is not None:
        index_log(runtime, "WARN: triage-fuzz-crashes failed rc=1")
        return False
    if returncode:
        index_log(runtime, f"WARN: triage-fuzz-crashes failed rc={returncode}")
        return False
    return True


def _steward_interval() -> int:
    """Seconds between steward ticks: the continuous scheduler's generation.

    A generation is what rotation and the dry-streak stop count, and what
    the audit log and the benchmark curves show as an iteration. Five
    minutes gives a lane a few chances before rotation retires it and keeps
    the log legible; both stops are guarded by open hypotheses, so a long
    session spanning ticks is never read as a dry lane.
    """
    try:
        return max(1, int(os.environ.get("STEWARD_INTERVAL_SECS", "300")))
    except ValueError:
        return 300


def _steward_steer(
    state: BackendState, before: "ProgressSnapshot", filed_before: int,
    *, live_agents: Collection[int] = (), ended_agents: Collection[int] = (),
) -> tuple[str, "ProgressSnapshot", int]:
    """Close one generation and open the next while the slots keep running.

    Everything here is safe beside live sessions: card writes are atomic
    under their own lock and claims lock a separate file, so a re-rank
    never tears a claim; a claim held by a slot in flight is never released,
    so no peer is offered a card its owner is still reading; strategy files
    are read at launch, so rotating a running slot only steers its next
    session; a live slot keeps its build assignment; the sealed gate worker
    owns every artifact verdict. What is *not* safe beside a live session
    stays with the final barrier: orphan-testcase enforcement and corpus
    promotion run `bin/probe` against a slot's own scratch, and index
    maintenance (`cluster-findings`, enrichment, rendering) rewrites every
    report, which would silently drop a narrative an agent is still writing.

    A generation is scored only when at least one session ended in it
    (`ended_agents`), and only those slots earn a dry mark. Every threshold
    counted in iterations — lane rotation, the subsystem decay, the
    dry-streak stop — keeps a unit no finer than a session; a tick that only
    saw long sessions still running refreshes the queue and nothing else.
    The per-iteration budgets (sanitizer launches, harness decisions) and the
    fuzz-lead index are likewise renewed once per scored generation, as the
    cohort loop renewed them once per iteration.
    """
    runtime = state.runtime
    ended = set(ended_agents)
    if ended:
        status, _results = _assess_generation(
            state, before, filed_before, [], scored_agents=ended,
        )
        if status == "stalled":
            return status, before, filed_before
    refresh_work_cards(runtime)
    released = release_stale_card_claims(runtime, keep_agents=live_agents)
    if released:
        index_log(runtime, f"queue: released {released} stale work-card claim(s)")
    expand_work_cards_if_exhausted(runtime)
    initialize_agent_strategies(runtime)
    if not ended:
        return "continue", before, filed_before
    state.iteration += 1
    refresh_fuzz_leads(runtime)
    reset_sanitizer_run_counters(runtime)
    reset_llm_decision_counters(runtime)
    assign_build_configs(runtime, state.context, state.iteration, skip_agents=live_agents)
    after = progress(runtime)
    index_log(
        runtime,
        f"Iteration {state.iteration} starting: agents={runtime.num_agents} cold=false "
        f"totals={after.findings} findings/{after.crashes} crashes",
    )
    return "continue", after, filed_artifact_count(runtime)


def run_continuous(state: BackendState) -> tuple[str, list[AgentResult]]:
    """Keep every slot busy to the wall; steer on a timer, never at a barrier.

    The cohort model launched N sessions, refilled a finished slot only while
    a peer of the same cohort still ran, then held everyone at a barrier for
    housekeeping. On every measured cell the slow slot set the pace and the
    fast ones idled 27-40% of the wall. Here a slot that finishes relaunches
    at once if it has work, sealed artifacts are gated in the background as
    they complete, and a steward tick every `STEWARD_INTERVAL_SECS` scores
    the generation, rotates starved lanes and re-ranks the queue — all
    without stopping a single session. The one full barrier is the final
    pass after the last slot drains, which is also where the pool-empty gate
    work is charged to housekeeping.

    A provider halt (capacity, transient, rejected) stops further launches,
    lets in-flight sessions finish, and returns that status so the caller's
    pause-and-retry path runs exactly as it does for the cohort model.
    """
    runtime = state.runtime
    context = state.context
    _activate_runtime(runtime)
    if _productive_wall_exhausted(state):
        return "budget", []
    refresh_fuzz_leads(runtime)
    reset_sanitizer_run_counters(runtime)
    reset_llm_decision_counters(runtime)
    refresh_work_cards(runtime)
    released = release_stale_card_claims(runtime)
    if released:
        index_log(runtime, f"queue: released {released} stale work-card claim(s)")
    expand_work_cards_if_exhausted(runtime)
    initialize_agent_strategies(runtime)
    if state.iteration == 0:
        _log_foreign_active_work(runtime)
    state.iteration += 1
    cold = _cold(runtime)
    assign_build_configs(runtime, context, state.iteration)
    gen_before = progress(runtime)
    gen_filed_before = filed_artifact_count(runtime)
    index_log(
        runtime,
        f"Iteration {state.iteration} starting: agents={runtime.num_agents} cold={str(cold).lower()} "
        f"totals={gen_before.findings} findings/{gen_before.crashes} crashes",
    )
    results: list[AgentResult] = []
    session_ceiling = _agent_timeout()
    interval = _steward_interval()
    gate_worker = SealedGateWorker(state)
    halted = ""
    stalled = False
    retried: set[int] = set()
    launched_now: set[int] = set()
    # Clean relaunches a slot may take between two scored ticks. A sticky
    # work source — a fuzz lead that stays listed, a PENDING hypothesis that
    # never resolves — justifies a relaunch every time it is asked, so without
    # a bound one slot could spin on it for the whole wall; the cohort model
    # bounded that by its epoch, this bounds it by the steward's cadence.
    clean_relaunch_cap = 2
    clean_relaunches: dict[int, int] = {}

    def session_limit() -> int:
        wall = _productive_wall_remaining(state)
        return max(1, session_ceiling if wall is None else min(session_ceiling, wall))

    with ExitStack() as stack:
        stack.callback(gate_worker.close)
        pool = stack.enter_context(
            concurrent.futures.ThreadPoolExecutor(max_workers=runtime.num_agents)
        )
        futures: dict[concurrent.futures.Future, int] = {}

        def launch(agent: int, cold_launch: bool, *, continuation: bool = False) -> None:
            gate_worker.launch(agent, continuation=continuation)
            launched_now.add(agent)
            future = pool.submit(
                run_agent_guarded, runtime, context, agent, state.iteration,
                cold_launch, session_limit(),
            )
            futures[future] = agent

        def ceiling_reached() -> bool:
            return bool(
                state.max_generations and state.iteration >= state.max_generations
            )

        def wants_launch(
            agent: int, result: AgentResult | None, *, initial: bool = False,
        ) -> bool:
            """Whether this slot should run another session right now."""
            if halted or stalled:
                return False
            remaining = _productive_wall_remaining(state)
            if remaining is not None and remaining <= 0:
                return False
            if not initial and ceiling_reached():
                return False
            if result is None:
                return not should_skip_launch(runtime, context, agent)
            outcome = _refill_outcome(result)
            if outcome in ("provider", "deadline"):
                index_log(runtime, f"slot {agent}: idle after {outcome} outcome rc={result.returncode}")
                return False
            if outcome == "failed":
                if agent in retried:
                    index_log(runtime, f"slot {agent}: idle; already retried once after rc={result.returncode}")
                    return False
                retried.add(agent)
                return True
            if outcome == "continue":
                return True
            if should_skip_launch(runtime, context, agent, primary_always_launches=False):
                index_log(runtime, f"slot {agent}: idle; no active hypothesis, handoff, claimable card, or fuzz lead")
                return False
            if not _session_did_work(result):
                index_log(runtime, f"slot {agent}: idle; its session made no tool call, so a replacement would repeat it")
                return False
            if clean_relaunches.get(agent, 0) >= clean_relaunch_cap:
                index_log(
                    runtime,
                    f"slot {agent}: idle until the next steward tick; "
                    f"{clean_relaunch_cap} clean relaunches already taken this generation",
                )
                return False
            clean_relaunches[agent] = clean_relaunches.get(agent, 0) + 1
            return True

        for agent in range(1, runtime.num_agents + 1):
            if wants_launch(agent, None, initial=True):
                launch(agent, cold)
        if not futures:
            index_log(runtime, "SKIP_LAUNCH: no slot has a card, active hypothesis, or fuzz lead")
        last_steward = time.monotonic()
        ended_since_tick: set[int] = set()
        idle_slots: set[int] = set()
        while futures:
            wait_for = max(1.0, min(30.0, interval - (time.monotonic() - last_steward)))
            done, _ = concurrent.futures.wait(
                futures, timeout=wait_for,
                return_when=concurrent.futures.FIRST_COMPLETED,
            )
            finished: list[tuple[int, AgentResult]] = []
            launched_now.clear()
            for future in done:
                agent = futures.pop(future)
                result = future.result()
                results.append(result)
                finished.append((agent, result))
                if result.provider_issue in _PROVIDER_HALT_ISSUES and not halted:
                    halted = result.provider_issue
                    index_log(
                        runtime,
                        f"slot {agent}: reported {halted}; no further launches, "
                        "finishing in-flight sessions first",
                    )
            ended_since_tick.update(agent for agent, _ in finished)
            if finished:
                # Before any relaunch: what just ended is on disk now and must
                # be seen before the next chain takes its tick.
                gate_worker.observe()
            if (
                time.monotonic() - last_steward >= interval
                and not halted and not ceiling_reached()
            ):
                # A slot that just ended turn-capped or failed relaunches as a
                # continuation a few lines down: its claim and its build stay
                # its own. A clean one relaunches fresh and may be re-assigned.
                continuing = {
                    agent for agent, result in finished
                    if _refill_outcome(result) in ("continue", "failed")
                }
                status, gen_before, gen_filed_before = _steward_steer(
                    state, gen_before, gen_filed_before,
                    live_agents=set(futures.values()) | continuing,
                    ended_agents=ended_since_tick,
                )
                last_steward = time.monotonic()
                ended_since_tick = set()
                clean_relaunches.clear()
                if status == "stalled":
                    stalled = True
                else:
                    # A slot that found nothing to do earlier may now: the
                    # steward re-ranked and may have expanded the queue.
                    gate_worker.observe()
                    for agent in sorted(idle_slots):
                        if wants_launch(agent, None):
                            idle_slots.discard(agent)
                            launch(agent, False)
            for agent, result in finished:
                if wants_launch(agent, result):
                    outcome = _refill_outcome(result)
                    launch(
                        agent, False,
                        continuation=outcome in ("continue", "failed"),
                    )
                else:
                    idle_slots.add(agent)
            for agent, _result in finished:
                if agent not in launched_now:
                    gate_worker.retire(agent)
            if futures:
                gate_worker.request_sweep()
    # The only barrier: every slot has drained, so the whole tree is sealed.
    # Full triage, orphan enforcement and corpus promotion run here, charged
    # to housekeeping because nothing else was running.
    _run_post_iteration(state)
    if stalled:
        # The tick that stalled already scored this span; scoring it again
        # would count the same dry generation twice.
        return "stalled", results
    status, results = _assess_generation(state, gen_before, gen_filed_before, results)
    if status in ("rejected", "capacity", "transient"):
        return status, results
    if state.stopped:
        return "stalled", results
    if _productive_wall_exhausted(state):
        return "budget", results
    return status, results


def run_iteration(state: BackendState) -> tuple[str, list[AgentResult]]:
    runtime = state.runtime
    context = state.context
    _activate_runtime(runtime)
    if _productive_wall_exhausted(state):
        return "budget", []
    state.iteration += 1
    refresh_fuzz_leads(runtime)
    reset_sanitizer_run_counters(runtime)
    reset_llm_decision_counters(runtime)
    before = progress(runtime)
    filed_before = filed_artifact_count(runtime)
    cold = _cold(runtime)
    refresh_work_cards(runtime)
    released = release_stale_card_claims(runtime)
    if released:
        index_log(runtime, f"queue: released {released} stale work-card claim(s)")
    expand_work_cards_if_exhausted(runtime)
    # Once, after every step that can change card supply, and unconditionally:
    # a lane starves between iterations without the queue itself changing.
    initialize_agent_strategies(runtime)
    if state.iteration == 1:
        _log_foreign_active_work(runtime)
    if fixed_lane_exhausted(runtime, state.iteration):
        unavailable = _fixed_lane_unavailable(runtime)
        if unavailable:
            index_log(runtime, f"LANE_UNAVAILABLE: {unavailable}")
        else:
            index_log(
                runtime,
                "LANE_EXHAUSTED: no open "
                f"{str(runtime.fixed_strategy).upper()} card or hypothesis remains",
            )
        state.stopped = True
        return "stalled", []
    if getattr(runtime, "delta_refresh_failed", ""):
        index_log(
            runtime,
            "DELTA_STOPPED: the scoped queue could not be refreshed "
            f"({runtime.delta_refresh_failed}); stopping instead of auditing "
            "outside the delta",
        )
        state.stopped = True
        return "stalled", []
    if delta_queue_exhausted(runtime, context):
        index_log(
            runtime,
            "DELTA_EXHAUSTED: no scoped card, active hypothesis, handoff, or "
            "fuzz lead remains; stopping instead of opening a whole-tree "
            "primary discovery slot",
        )
        state.stopped = True
        return "stalled", []
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
    return _assess_generation(state, before, filed_before, results)


def _assess_generation(
    state: BackendState, before: "ProgressSnapshot", filed_before: int,
    results: list[AgentResult], *, scored_agents: Collection[int] | None = None,
) -> tuple[str, list[AgentResult]]:
    """Score one generation's progress and rotate starved lanes.

    Shared by the barrier loop (`run_iteration`) and the continuous scheduler
    (`run_continuous`). A generation is the span between two progress
    snapshots; the continuous scheduler measures it between steward ticks
    while the slots keep running, and passes ``results=[]`` because provider
    health is handled by its own launch-halt path rather than by inspecting a
    drained cohort. ``scored_agents`` names the slots that ended a session in
    the generation; only they earn a dry mark, so a two-hour investigation
    spanning many ticks is not read as many dry sessions.
    """
    runtime = state.runtime
    context = state.context
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
    rejected = any(result.provider_issue == "backend_rejected" for result in results)
    capacity_limited = any(result.provider_issue == "capacity_limited" for result in results)
    transient = any(result.provider_issue == "transient" for result in results)
    if rejected or capacity_limited or transient:
        if productive:
            state.dry_streak = 0
        issue = (
            "rejected" if rejected
            else "capacity" if capacity_limited else "transient"
        )
        index_log(runtime, f"Iteration {state.iteration} interrupted by {issue} provider failure")
        return issue, results
    if productive:
        state.dry_streak = 0
    else:
        state.dry_streak += 1
    state.transient_streak = 0
    update_subsystem_dry_streaks(
        runtime, productive_agents, agents=scored_agents,
    )
    update_strategy_rotation(
        runtime, context, after_agent_progress, productive_agents,
        agents=scored_agents,
    )
    outcome = iteration_outcome_label(
        productive=productive,
        filed=filed_artifact_count(runtime) > filed_before,
        diagnostic=diagnostic,
    )
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
        unavailable = _fixed_lane_unavailable(runtime)
        if unavailable:
            refresh_work_cards(runtime, force=True)
            index_log(runtime, f"LANE_UNAVAILABLE: {unavailable}")
            return 0
        runner_preflight.validate(
            runtime.config, lambda message: index_log(runtime, message)
        )
        validate_model(runtime, guide)
        preflight_build(runtime)
        state = initialize_backend(runtime, args, guide, started_at=time.monotonic())
        # Fixed-lane and delta audits are bounded, card-list-shaped work that
        # wants the cohort barrier and an iteration count; open-ended
        # discovery runs continuously and treats `max_iterations` as a
        # ceiling on steward generations.
        bounded = bool(
            getattr(runtime, "fixed_strategy", "") or getattr(runtime, "delta", None)
            or not getattr(runtime, "refill_workers", True)
        )
        drive = run_iteration if bounded else run_continuous
        state.max_generations = 0 if bounded else args.max_iterations
        while args.max_iterations == 0 or state.iteration < args.max_iterations:
            status, results = drive(state)
            if status in ("budget", "stalled"):
                break
            if _productive_wall_exhausted(state):
                break
            if status == "rejected":
                # No recovery: the provider refused the request itself, so a
                # pause buys nothing and would be subtracted from the wall as
                # if the provider had withheld capacity it was going to return.
                (runtime.logs / ".backend-unavailable").touch()
                (runtime.logs / ".run-quality").write_text("provider_limited\n", encoding="utf-8")
                index_log(runtime, "BACKEND_UNAVAILABLE: provider refused the request; retrying cannot clear it")
                return 2
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
        unavailable = _fixed_lane_unavailable(runtimes[0])
        if unavailable:
            for runtime in runtimes:
                refresh_work_cards(runtime, force=True)
                index_log(runtime, f"LANE_UNAVAILABLE: {unavailable}")
            return 0
        runner_preflight.validate(
            runtimes[0].config,
            lambda message: index_log(runtimes[0], message),
        )
        for runtime in runtimes:
            _activate_runtime(runtime)
            validate_model(runtime, guide)
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
                if status == "rejected":
                    # Terminal for this backend, whatever the ensemble's peers
                    # are doing: nothing it could wait for will change the answer.
                    state.stopped = True
                    failures += 1
                    (state.runtime.logs / ".backend-unavailable").touch()
                    (state.runtime.logs / ".run-quality").write_text("provider_limited\n", encoding="utf-8")
                    index_log(state.runtime, "BACKEND_UNAVAILABLE: provider refused the request; retrying cannot clear it")
                elif status == "capacity":
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
        args.agent_security = llm_invoke.resolve_agent_security(
            args.agent_security, requested,
        )
    except ValueError as exc:
        print(f"FATAL: {exc}", file=sys.stderr)
        return 1
    llm_invoke.warn_agent_security(args.agent_security)
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
                args.since,
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
