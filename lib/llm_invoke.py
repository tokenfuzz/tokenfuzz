#!/usr/bin/env python3
"""Shared backend-flag picker and assistant-text extractor.

Single source of truth for the five LLM backends the harness drives —
claude / codex / oss (OpenCode against local OpenAI-compatible servers) /
gemini / grok. The `gemini` backend keeps
one harness-visible name while supporting two CLI dialects underneath:
Antigravity (`agy`, default) and Google Gemini CLI (`gemini` when
USE_GEMINI_CLI=1). Audit, validation, and decision callers import
this module directly, so backend flags and invocation behavior cannot drift.

CLI subcommands (`python3 lib/llm_invoke.py …`):

  known-backend <backend>
      Exit 0 if backend ∈ {claude, codex, oss, gemini, grok}; else 1.

  default-model <backend>
      Print the project's default model name for <backend>, read from
      config/models.toml. A per-backend env override (CLAUDE_MODEL_DEFAULT /
      CODEX_MODEL_DEFAULT / GEMINI_MODEL_DEFAULT / GROK_MODEL_DEFAULT)
      wins when set. Exit 1 on unknown backend.

  default-effort <backend>
      Print the backend-native reasoning effort from config/models.toml.

  agent-flags <backend> [--model …] [--max-turns N] [--add-dirs CSV]
      [--agent-security sandboxed|external-bypass]
      Print the agent-mode flag list, one flag per line. Used for
      interactive tool-using agent calls.

  decide-flags <backend> [--model …]
      Print the decide-mode flag list (text output, no tools, read-only
      sandbox). One flag per line.

  extract-text <backend> <raw_log_path>
      Stream the assistant's natural-language text from a raw transcript
      to stdout. Per-backend: claude (.message.content[].text, with
      .result as fallback only), codex (item.completed/agent_message),
      oss (OpenCode JSON output), gemini (agy plain stdout, or Gemini CLI
      stream-json assistant text), grok (Grok Build streaming-json text).

  gemini-isolated-home
      Stage (when cross-run memory is off and USE_GEMINI_CLI=1) a throwaway
      Gemini CLI home that excludes the global GEMINI.md, and print its path
      for the caller to export as GEMINI_CLI_HOME. Prints nothing
      when isolation does not apply.
"""

from __future__ import annotations

import argparse
import atexit
import fcntl
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from contextlib import contextmanager
from pathlib import Path


def _load_tomllib():
    """Import tomllib lazily, so only the TOML-reading subcommands depend on it.

    Kept out of module import on purpose: gemini-isolated-home / known-backend /
    agent-flags etc. need no TOML, and a too-old python without tomllib AND
    without the tomli fallback must NOT take the whole module — and with it the
    memory-isolation staging — down.
    """
    try:
        import tomllib  # py3.11+
        return tomllib
    except ModuleNotFoundError:
        import tomli  # py3.9/py3.10 optional fallback
        return tomli


_KNOWN_BACKENDS = ("claude", "codex", "oss", "gemini", "grok")
AGENT_SECURITY_MODES = ("sandboxed", "external-bypass")
DEFAULT_AGENT_SECURITY = "sandboxed"
AGENT_SECURITY_ENV = "TOKENFUZZ_AGENT_SECURITY"

# Per-backend env var that overrides the configured default (CI / throttled
# runs). When unset, the default comes from config/models.toml.
_MODEL_ENV_OVERRIDE = {
    "claude": "CLAUDE_MODEL_DEFAULT",
    "codex": "CODEX_MODEL_DEFAULT",
    "gemini": "GEMINI_MODEL_DEFAULT",
    "grok": "GROK_MODEL_DEFAULT",
}

# config/models.toml (repo root) is the single source of truth for the
# default model names. Resolved from this file so cwd doesn't matter.
_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "models.toml"


_CONFIG_DOC_CACHE: tuple[tuple[int, int, int, int], dict] | None = None


def _config_document() -> dict:
    """Parse config/models.toml, cached by stat signature.

    Resolved once per (unchanged) file: model/flag/effort lookups hit this
    several times per decision and per agent launch, and the file is a fixed
    repo artifact immutable for a run. The signature bundles ino/size/mtime/
    ctime, so a test or operator edit — even an atomic replace or an mtime-
    preserving restore — re-parses; callers otherwise see identical tables.
    """
    global _CONFIG_DOC_CACHE
    try:
        st = _CONFIG_PATH.stat()
        signature = (st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    except OSError:
        signature = (-1, -1, -1, -1)
    if _CONFIG_DOC_CACHE is not None and _CONFIG_DOC_CACHE[0] == signature:
        return _CONFIG_DOC_CACHE[1]
    try:
        toml = _load_tomllib()
        with open(_CONFIG_PATH, "rb") as fh:
            document = toml.load(fh)
    except ModuleNotFoundError:
        from target_config import parse_toml

        document = parse_toml(_CONFIG_PATH)
    _CONFIG_DOC_CACHE = (signature, document)
    return document


def _config_table(name: str) -> dict:
    """Return one table from config/models.toml."""
    return _config_document().get(name, {})


def _config_models() -> dict:
    return _config_table("models")


def known_backend(backend: str) -> bool:
    return backend in _KNOWN_BACKENDS


def use_gemini_cli() -> bool:
    """Return true when the gemini backend should invoke Google Gemini CLI."""
    return os.environ.get("USE_GEMINI_CLI", "").strip() == "1"


def external_sandbox_active() -> bool:
    """Whether the operator launched through an asserted outer sandbox."""
    return os.environ.get("IS_SANDBOX", "").strip() == "1"


def inherited_agent_security(backend: str = "") -> str:
    """Security profile selected by the parent audit or benchmark process.

    With no parent choice, the backend's own default applies. OpenCode has no
    native OS sandbox, so `sandboxed` refuses it outright; defaulting oss to
    that profile means `--backend oss` cannot start anywhere, and the only way
    through is to type the bypass flag by hand — which asserts nothing extra,
    since the flag is not evidence of a boundary either. Default it to the
    profile it can actually run under and let warn_agent_security say what is
    unconfined, rather than gating the default on IS_SANDBOX and turning a
    missing assertion back into a refusal.
    """
    default = "external-bypass" if backend == "oss" else DEFAULT_AGENT_SECURITY
    return (os.environ.get(AGENT_SECURITY_ENV) or default).strip()


def resolve_agent_security(
    agent_security: str | None, backend: str = "",
) -> str:
    """One resolution rule: an explicit choice, else the inherited profile."""
    resolved = (agent_security or inherited_agent_security(backend)).strip()
    if resolved not in AGENT_SECURITY_MODES:
        raise ValueError(f"unknown agent security mode: {resolved}")
    return resolved


def agent_security_problem(backend: str, agent_security: str) -> str:
    """Why this backend cannot launch a tool-using agent under this profile.

    Only capability facts refuse here: a CLI sandbox that provably cannot host
    an audit is not something an operator can waive by insisting. Whether an
    outer boundary actually exists is the operator's to assert, and IS_SANDBOX
    is their assertion, not a measurement — so its absence is advice rather
    than a refusal. See agent_security_warning.

    Read-only decide calls do not consult this: they carry no execution
    boundary to assert.
    """
    if agent_security not in AGENT_SECURITY_MODES:
        return f"unknown agent security mode: {agent_security}"
    if agent_security == "external-bypass":
        return ""
    if backend == "oss":
        return (
            "the OpenCode backend has no native OS sandbox; run it inside an "
            "externally hardened sandbox (oss defaults to external-bypass "
            "when no mode is specified)"
        )
    if backend == "grok":
        # workspace reads the whole host including credential paths (only
        # writes to them are blocked) and allows child network, and the
        # stricter profiles' network block is Linux-only. An agent reading a
        # hostile tree could read a key and curl it out.
        return (
            "Grok's sandbox profiles leave host-wide reads and child network "
            "available on macOS, so they cannot contain an agent reading a "
            "hostile tree; run it inside an externally hardened sandbox and "
            "select --agent-security external-bypass"
        )
    if backend == "gemini":
        # Measured: Antigravity's terminal sandbox runs commands in a scratch
        # directory, refuses workspace writes and reads outside the launch
        # directory, and auto-denies its file-writing tool headless; Google
        # Gemini CLI's container mounts only the launch directory, so
        # --include-directories leaves the target unmounted.
        return (
            "neither Gemini dialect's sandbox can host an audit: Antigravity "
            "denies workspace writes and outside reads, and Google Gemini CLI "
            "mounts only the launch directory; run it inside an externally "
            "hardened sandbox and select --agent-security external-bypass"
        )
    return ""


_UNASSERTED_BYPASS_WARNED = False


def agent_security_warning(agent_security: str) -> str:
    """Advice for a bypass whose outer boundary nothing has asserted."""
    if agent_security != "external-bypass" or external_sandbox_active():
        return ""
    return (
        "--agent-security external-bypass is running without IS_SANDBOX=1. "
        "No CLI sandbox confines the agent and nothing has asserted that a "
        "container or VM does, so agents run target build scripts and "
        "harness-authored testcases with this account's filesystem, "
        "credentials, and network."
    )


def warn_agent_security(agent_security: str) -> str:
    """Emit that advice once per process, and return what it said.

    Once, not per launch: an audit starts hundreds of agents, and a warning
    repeated into every log is one nobody reads. The entry points call this at
    startup so it heads the run, and run_agent_prompt calls it too so a caller
    reaching the library directly cannot end up with no notice at all.
    """
    global _UNASSERTED_BYPASS_WARNED
    warning = agent_security_warning(agent_security)
    if warning and not _UNASSERTED_BYPASS_WARNED:
        _UNASSERTED_BYPASS_WARNED = True
        print(f"WARN: {warning}", file=sys.stderr)
    return warning


def gemini_default_bin() -> str:
    return "gemini" if use_gemini_cli() else "agy"


def apply_memory_policy(enabled: bool | None = None) -> None:
    """Set the process-wide backend memory policy inherited by child CLIs."""
    if enabled is None:
        enabled = os.environ.get("TOKENFUZZ_MEMORY_ENABLED", "0") == "1"
    os.environ["TOKENFUZZ_MEMORY_ENABLED"] = "1" if enabled else "0"
    if enabled:
        os.environ.pop("CLAUDE_CODE_DISABLE_AUTO_MEMORY", None)
    else:
        os.environ["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] = "1"


def backend_bin(backend: str) -> str:
    configured = {
        "claude": ("CLAUDE_BIN", "claude"),
        "codex": ("CODEX_BIN", "codex"),
        "oss": ("OPENCODE_BIN", "opencode"),
        "gemini": ("GEMINI_BIN", gemini_default_bin()),
        "grok": ("GROK_BIN", "grok"),
    }
    if backend not in configured:
        raise ValueError(f"unknown backend: {backend}")
    variable, default = configured[backend]
    return os.environ.get(variable) or default


def memory_enabled() -> bool:
    """Cross-run backend auto-memory is OFF unless TOKENFUZZ_MEMORY_ENABLED=1.

    Default-off (unset / empty / anything but "1") so every flag builder
    injects the per-backend disable controls automatically — no entry point
    can forget to. bin/audit's --enable-memory exports it as 1; bin/benchmark
    always leaves it off. See lib/llm_invoke.py:llm_apply_memory_policy.
    """
    return os.environ.get("TOKENFUZZ_MEMORY_ENABLED", "").strip() == "1"


def gemini_memory_policy_path() -> str:
    """Absolute path to the Gemini CLI admin policy that denies save_memory."""
    return str(_CONFIG_PATH.parent / "gemini-no-memory.policy.toml")


# The exact warning Gemini CLI prints when it drops --admin-policy files.
GEMINI_ADMIN_POLICY_DROPPED = "Ignoring --admin-policy"


def gemini_admin_policy_dropped(raw_log: str | os.PathLike[str]) -> bool:
    """Whether a Gemini CLI transcript shows the admin policies were dropped."""
    try:
        with open(raw_log, encoding="utf-8", errors="replace") as stream:
            return any(GEMINI_ADMIN_POLICY_DROPPED in line for line in stream)
    except OSError:
        return False


def gemini_no_web_policy_path() -> str:
    """Absolute path to the Gemini CLI admin policy that denies web tools."""
    return str(_CONFIG_PATH.parent / "gemini-no-web.policy.toml")


# Marker file that identifies a TokenFuzz-staged GEMINI_CLI_HOME, so a child
# process that inherits the exported GEMINI_CLI_HOME reuses it instead of
# wiping and re-staging it mid-run.
_GEMINI_ISOLATION_MARKER = ".tokenfuzz-memory-isolated"

# Cache the staged isolated home for the lifetime of one process so repeated
# memory_env("gemini") calls reuse the one staged dir.
_gemini_iso_home: "str | None" = None
_gemini_iso_lock = threading.Lock()
_gemini_settings: dict[tuple[str, str, int], str] = {}


def _is_tokenfuzz_gemini_home(path: str) -> bool:
    if not path:
        return False
    return (Path(path) / ".gemini" / _GEMINI_ISOLATION_MARKER).exists()


def _same_path(a: str, b) -> bool:
    """True when two paths resolve to the same location.

    Ignores `//`, trailing slashes, and symlinks so an inherited GEMINI_CLI_HOME
    string compares equal to this run's freshly built Path. The desired path may
    not exist yet — realpath then just normalizes lexically, which is what we
    want for the equality test.
    """
    if not a or not b:
        return False
    try:
        return os.path.realpath(a) == os.path.realpath(os.fspath(b))
    except (OSError, ValueError):
        return False


def _is_clean_gemini_home(path: Path) -> bool:
    try:
        _verify_clean_gemini_home(path)
    except OSError:
        return False
    return True


@contextmanager
def _gemini_home_file_lock(home: Path):
    """Serialize first staging across audit and llm_decide processes."""
    home.parent.mkdir(parents=True, exist_ok=True)
    lock_path = home.with_name(f".{home.name}.lock")
    with lock_path.open("a+") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def _stage_clean_gemini_home(iso_root: Path) -> None:
    """Wipe and recreate an empty staged Gemini CLI home at iso_root.

    Wiping first means a stale throwaway GEMINI.md from a prior (e.g. killed)
    run under the same $LOGDIR cannot be read back on resume.
    """
    if iso_root.exists():
        shutil.rmtree(iso_root)
    if iso_root.exists():
        raise OSError(f"failed to remove stale Gemini CLI home: {iso_root}")
    iso_gemini = iso_root / ".gemini"
    iso_gemini.mkdir(parents=True, exist_ok=True)
    (iso_gemini / _GEMINI_ISOLATION_MARKER).write_text(
        "TokenFuzz staged this empty Gemini CLI home to disable cross-run memory.\n",
        encoding="utf-8",
    )
    _verify_clean_gemini_home(iso_root)


def _verify_clean_gemini_home(iso_root: Path) -> None:
    """Fail unless iso_root is exactly the empty home TokenFuzz expects."""
    iso_gemini = iso_root / ".gemini"
    top_names = sorted(p.name for p in iso_root.iterdir())
    if top_names != [".gemini"] or not iso_gemini.is_dir() or iso_gemini.is_symlink():
        raise OSError(f"Gemini CLI home is not clean: {iso_root}")
    gemini_entries = sorted(p.name for p in iso_gemini.iterdir())
    marker = iso_gemini / _GEMINI_ISOLATION_MARKER
    if gemini_entries != [_GEMINI_ISOLATION_MARKER] or not marker.is_file() or marker.is_symlink():
        raise OSError(f"Gemini CLI .gemini directory is not clean: {iso_gemini}")


def _prepare_gemini_memory_isolation_locked() -> "str | None":
    """Relocate GEMINI_CLI_HOME to a clean, empty per-run home and return it.

    Denying the save_memory tool does NOT isolate Gemini CLI's cross-run
    memory: the global ~/.gemini/GEMINI.md is auto-loaded as context on every
    run regardless of tool policy, and write_file/replace can append to memory
    files without going through save_memory. Settings (context.fileName,
    loadMemoryFromIncludeDirectories, discoveryMaxDirs) do not gate the global
    load either — all verified by running the CLI. The only lever Gemini CLI
    exposes is GEMINI_CLI_HOME, which overrides the dir it derives its global
    .gemini from. We point it at a clean, EMPTY home: no GEMINI.md, no
    project-memory dir, no history — nothing to read and nothing to write back
    into the operator's real home.

    Authentication rides on the GEMINI_API_KEY / GOOGLE_API_KEY env the harness
    already forwards, so the empty home needs no credential files (verified: an
    empty home authenticates and recalls no planted memory). Operators who use
    file-based (OAuth) Gemini CLI auth must export an API key for memory-off
    runs, or use the default agy backend; that surfaces as a loud preflight
    auth error, never as silent memory leakage.

    Location: under $LOGDIR (the run's own output tree) when set, so the home is
    wiped fresh each run, cleaned with the run's artifacts, and never litters
    /tmp. Standalone callers with no $LOGDIR get a throwaway removed at process
    exit. Returns the home path, or None when isolation does not apply (memory
    enabled, not the Gemini CLI dialect) or it cannot be staged.

    Reuse is keyed to THIS run's home ($LOGDIR/.gemini-home): an inherited or
    cached GEMINI_CLI_HOME is reused (not re-wiped) only when it resolves to the
    same path — so parallel agents and the llm_decide subprocess in ONE run
    share the single staged home, while a later run or a sequential benchmark
    cell with a different $LOGDIR stages its own clean home instead of
    inheriting the previous one's (which would leak that run's memory).
    """
    global _gemini_iso_home
    if memory_enabled() or not use_gemini_cli():
        return None
    existing = os.environ.get("GEMINI_CLI_HOME", "").strip()
    logdir = os.environ.get("LOGDIR", "").strip()
    if logdir:
        desired = Path(logdir) / ".gemini-home"
        with _gemini_home_file_lock(desired):
            # Reuse ONLY when the inherited/cached home is this run's home; a
            # mismatch belongs to a different run/cell and must not be reused.
            if existing and _same_path(existing, desired) and _is_tokenfuzz_gemini_home(existing):
                _gemini_iso_home = str(desired)
                return _gemini_iso_home
            if _gemini_iso_home is not None and _same_path(_gemini_iso_home, desired):
                return _gemini_iso_home
            # Another process from this run may have won initial staging.
            if _is_clean_gemini_home(desired):
                _gemini_iso_home = str(desired)
                return _gemini_iso_home
            try:
                _stage_clean_gemini_home(desired)
            except OSError:
                return None
            _gemini_iso_home = str(desired)
            return _gemini_iso_home
    # No $LOGDIR (standalone caller): there is no per-run path to key on, so an
    # inherited marked home or the in-process cache is reused; otherwise a
    # throwaway removed at process exit.
    if existing and _is_tokenfuzz_gemini_home(existing):
        return existing
    if _gemini_iso_home is not None:
        return _gemini_iso_home
    try:
        iso_root = Path(tempfile.mkdtemp(prefix="tokenfuzz-gemini-home-"))
        atexit.register(shutil.rmtree, iso_root, ignore_errors=True)
        _stage_clean_gemini_home(iso_root)
    except OSError:
        return None
    _gemini_iso_home = str(iso_root)
    return _gemini_iso_home


def prepare_gemini_memory_isolation() -> "str | None":
    """Stage or reuse the current run's Gemini CLI home atomically."""
    with _gemini_iso_lock:
        return _prepare_gemini_memory_isolation_locked()


def memory_env(backend: str) -> dict:
    """Environment overrides that disable cross-run memory for <backend>.

    Empty when memory is enabled, or when the backend needs no env-level
    control — codex disables memory through `-c` flags in agent_flags /
    decide_flags, OpenCode does not need a harness memory knob for local OSS
    runs, and headless agy has no auth-preserving home/profile isolation wired
    here. Apply this on top of the child env at every launch
    site (lib/llm_decide.py's subprocess, and lib/llm_invoke.py's agent
    launchers via llm_apply_memory_policy) so even standalone llm_decide tools
    get the same isolation bin/audit gets.

      claude  CLAUDE_CODE_DISABLE_AUTO_MEMORY=1 — claude reads this env var
              directly; there is no launch flag for it.
      gemini  (Google Gemini CLI only) GEMINI_CLI_HOME -> an isolated home that
              excludes the global GEMINI.md (see prepare_gemini_memory_isolation).
    """
    if memory_enabled():
        return {}
    if backend == "claude":
        return {"CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"}
    if backend == "gemini" and use_gemini_cli():
        home = prepare_gemini_memory_isolation()
        if not home:
            raise RuntimeError(
                "Gemini CLI memory isolation could not stage a clean home; "
                "refusing to inherit the operator's global GEMINI.md"
            )
        return {"GEMINI_CLI_HOME": home}
    return {}


def _capture_agy_cli_log_diag(raw_log: str | os.PathLike[str]) -> None:
    """Recover bounded provider diagnostics when Antigravity emits no stdout."""
    raw = Path(raw_log)
    try:
        if raw.stat().st_size:
            return
    except OSError:
        pass
    pinned = os.environ.get("AGY_LOG_FILE", "").strip()
    candidates = [Path(pinned)] if pinned else []
    if not candidates:
        log_dir = Path(os.environ.get(
            "AUDIT_GEMINI_CLI_LOG_DIR",
            str(Path(os.environ.get("GEMINI_DIR", str(Path.home() / ".gemini"))) / "antigravity-cli" / "log"),
        ))
        try:
            candidates = sorted(log_dir.glob("cli-*.log"), key=lambda path: path.stat().st_mtime, reverse=True)
        except OSError:
            candidates = []
    source = next((path for path in candidates if path.is_file()), None)
    if source is None:
        return
    pattern = re.compile(r"RESOURCE_EXHAUSTED|quota|429|503|UNAVAILABLE|executor error|Resets in", re.I)
    matches: deque[str] = deque(maxlen=15)
    try:
        with source.open(encoding="utf-8", errors="replace") as stream:
            for line in stream:
                if pattern.search(line):
                    matches.append(line.rstrip("\n"))
        if matches:
            with raw.open("a", encoding="utf-8") as destination:
                destination.write(f"[agy CLI log tail: {source}]\n")
                destination.write("\n".join(matches) + "\n")
    except OSError:
        return


def prepare_gemini_settings(
    model: str = "", max_session_turns: int = 0,
) -> "str | None":
    """Write Gemini CLI system settings for isolation, effort, and turn cap."""
    if not use_gemini_cli():
        return None
    resolved_model = resolve_model_name("gemini", model).strip()
    effort = default_effort("gemini").strip().upper()
    cap = max(0, int(max_session_turns))
    key = (resolved_model, effort, cap)
    existing = _gemini_settings.get(key)
    if existing:
        return existing
    root = Path(tempfile.mkdtemp(prefix="tokenfuzz-gemini-settings-"))
    atexit.register(shutil.rmtree, root, ignore_errors=True)
    path = root / "settings.json"
    payload = {
        # Gemini CLI has no safe-mode flag. System settings take precedence
        # over user/workspace settings, so disable skills and extensions that
        # can inject a duplicate workflow. An empty boundary-marker list makes
        # the launch cwd the upper bound for GEMINI.md discovery instead of
        # walking to an enclosing checkout.
        "skills": {"enabled": False},
        "admin": {
            "extensions": {"enabled": False},
        },
        "context": {"memoryBoundaryMarkers": []},
    }
    if cap:
        payload["model"] = {"maxSessionTurns": cap}
    if resolved_model and effort:
        payload["modelConfigs"] = {
            "customOverrides": [{
                "match": {"model": resolved_model},
                "modelConfig": {
                    "generateContentConfig": {
                        "thinkingConfig": {"thinkingLevel": effort},
                    },
                },
            }],
        }
    path.write_text(json.dumps(payload, separators=(",", ":")) + "\n", encoding="utf-8")
    _gemini_settings[key] = str(path)
    return str(path)


def invocation_env(
    backend: str, model: str = "", max_session_turns: int = 0,
) -> dict[str, str]:
    """Return environment controls needed for one backend invocation."""
    environment = memory_env(backend)
    if backend == "gemini" and use_gemini_cli():
        settings = prepare_gemini_settings(model, max_session_turns)
        if settings:
            environment["GEMINI_CLI_SYSTEM_SETTINGS_PATH"] = settings
    return environment


# Claude Code's built-in web tools and its delegation tools (current name and
# the legacy one), for --disallowedTools. Named tools are removed from the
# session whatever the permission mode.
_CLAUDE_WEB_TOOLS = ("WebFetch", "WebSearch")
_CLAUDE_DELEGATION_TOOLS = ("Agent", "Task")

# Codex memory-disable controls, added to the flag list when memory is
# disabled. All are `-c` config overrides rather than `--disable memories`:
# an unknown `-c` key is accepted and ignored on any Codex version, whereas
# `--disable <feature>` hard-errors when the feature name is unknown, which
# would break the run on a Codex build without the experimental feature.
#   features.memories=false          turn the memories feature off entirely
#   memories.use_memories=false      don't read ~/.codex/memories into context
#   memories.generate_memories=false don't write new cross-run memories
# Codex stores learned memory under ~/.codex/memories/; without these a prior
# run's notes are injected into every later session (docs:
# https://developers.openai.com/codex/memories).
_CODEX_MEMORY_OFF_FLAGS = [
    "-c", "features.memories=false",
    "-c", "memories.use_memories=false",
    "-c", "memories.generate_memories=false",
]

# Codex has no single Claude-style --safe-mode flag. Disabling the plugins
# feature also removes plugin-contributed skills, hooks, and MCPs — preventing
# a security plugin from wrapping TokenFuzz's own workflow. Use the `-c` form,
# not `--disable plugins`: both mean features.plugins=false, but an unknown `-c`
# key is ignored on any Codex version whereas `--disable` hard-errors on a build
# that lacks the feature (same reasoning as _CODEX_MEMORY_OFF_FLAGS).
_CODEX_PLUGIN_OFF_FLAGS = [
    "-c", "features.plugins=false",
]

# Codex otherwise walks from --cd to the enclosing Git root and loads every
# AGENTS.md on that path. Benchmark cells live below the TokenFuzz checkout, so
# that silently gives a model-direct control the harness's audit contract.
# An empty marker list makes the explicit launch directory the project root;
# an AGENTS.md in that directory still loads, which is exactly what harness
# facade launches require.
_CODEX_PROJECT_ROOT_FLAGS = [
    "-c", "project_root_markers=[]",
]


def ensure_project_root(path: str | os.PathLike[str]) -> None:
    """Make path a self-contained CLI project root without invoking Git."""
    root = Path(path)
    if not root.is_dir():
        raise RuntimeError(f"project root does not exist: {root}")
    git_dir = root / ".git"
    # Never alter an existing marker. In particular, validator cwds symlink the
    # target's .git; completing that directory would mutate the checkout under
    # audit. Both affected CLIs treat even an incomplete marker as a boundary.
    if git_dir.exists() or git_dir.is_symlink():
        return
    for relative in ("objects/info", "objects/pack", "refs/heads"):
        (git_dir / relative).mkdir(parents=True, exist_ok=True)
    (git_dir / "HEAD").write_text(
        "ref: refs/heads/tokenfuzz-launch\n", encoding="utf-8",
    )
    (git_dir / "config").write_text(
        "[core]\n\trepositoryformatversion = 0\n\tbare = false\n",
        encoding="utf-8",
    )


def default_model(backend: str) -> str:
    """Default model for <backend>: per-backend env override, else config/models.toml.

    Raises ValueError on an unknown backend.
    """
    if backend not in _KNOWN_BACKENDS:
        raise ValueError(f"unknown backend: {backend}")
    override_key = _MODEL_ENV_OVERRIDE.get(backend)
    if override_key:
        primary = os.environ.get(override_key)
        if primary:
            return primary
    return _config_models().get(backend, "")


def default_effort(backend: str) -> str:
    """Return the configured backend-native reasoning effort."""
    if backend not in _KNOWN_BACKENDS:
        raise ValueError(f"unknown backend: {backend}")
    key = "agy" if backend == "gemini" and not use_gemini_cli() else backend
    return str(_config_table("effort").get(key, "")).strip()


def _ensure_http_url(value: str) -> str:
    value = value.strip()
    if value and "://" not in value:
        value = "http://" + value
    return value.rstrip("/")


def local_provider_base_url() -> str:
    generic = os.environ.get("AUDIT_LOCAL_BASE_URL")
    if generic:
        url = _ensure_http_url(generic)
        return url if url.endswith("/v1") else url + "/v1"
    return "http://127.0.0.1:8000/v1"


def resolve_model_name(backend: str, model: str = "") -> str:
    return model or default_model(backend)


def _is_opencode_builtin_model(model: str) -> bool:
    # Only OpenCode's own provider prefix bypasses the local adapter. Served
    # vLLM model ids commonly contain a slash (for example org/model), so a
    # generic provider/model test would silently reroute existing local runs.
    return model.startswith("opencode/") and bool(model.removeprefix("opencode/"))


def opencode_model_ref(model: str) -> str:
    resolved = (model or default_model("oss")).strip()
    if _is_opencode_builtin_model(resolved):
        return resolved
    return f"local/{resolved}" if resolved else "local"


def opencode_config(model: str, agent_security: str | None = None) -> dict:
    resolved = (model or default_model("oss")).strip()
    if not resolved:
        raise ValueError("oss model is required")
    config = {"$schema": "https://opencode.ai/config.json"}
    if not _is_opencode_builtin_model(resolved):
        api_key = os.environ.get("AUDIT_LOCAL_API_KEY") or "EMPTY"
        config["provider"] = {
            "local": {
                "npm": "@ai-sdk/openai-compatible",
                "name": "Local OpenAI-compatible",
                "options": {
                    "baseURL": local_provider_base_url(),
                    "apiKey": api_key,
                },
                "models": {
                    resolved: {
                        "name": resolved,
                    },
                },
            },
        }
    # Deliberately resolved without the backend, so the oss agent default does
    # not reach here: an agent launch always passes its already-resolved
    # profile, and the only caller that passes none is the read-only decide
    # path, which should keep these denies rather than inherit a boundary it
    # never asserts.
    if resolve_agent_security(agent_security) == "sandboxed":
        # OpenCode permissions are an approval policy, not an OS sandbox, so
        # agent launches refuse this backend in sandboxed mode. These denies
        # bound what a read-only decide call can still reach.
        config["permission"] = {
            "*": "allow",
            "external_directory": "deny",
            "webfetch": "deny",
            "websearch": "deny",
        }
    else:
        # The only profile an oss agent can run under. Web stays denied here
        # too, matching every other backend's harness launch (claude denies
        # WebFetch/WebSearch, grok --disable-web-search, codex
        # web_search="disabled"): audited source is untrusted, so no agent
        # gets egress.
        config["permission"] = {"webfetch": "deny", "websearch": "deny"}
    return config


def local_model_available(model: str) -> bool:
    resolved = (model or "").strip()
    url = local_provider_base_url().rstrip("/") + "/models"
    try:
        with urllib.request.urlopen(url, timeout=3) as resp:
            data = json.load(resp)
    except (OSError, urllib.error.URLError, json.JSONDecodeError, ValueError):
        return False
    models = data.get("data") if isinstance(data, dict) else data
    if not isinstance(models, list):
        return False
    ids = {
        str(item.get("id", "")).strip()
        for item in models
        if isinstance(item, dict)
    }
    return bool(resolved and resolved in ids)


# agy (Antigravity CLI) gained --model in 1.0.5, but it selects models by the
# display label shown in `agy models` — NOT the API slug — and SILENTLY falls
# back to its persistent /model setting when handed a value it can't resolve
# (exit 0, no stderr; the fallback model even echoes the preflight token). So
# config/models.toml stays the source of truth in API-slug form and we map the
# slug to the exact label here; bin/audit's model preflight parses agy's log
# for the unresolved-flag signature as the hard backstop.
_AGY_SLUG_TO_LABEL = {
    "gemini-3.7-flash": {
        "high": "Gemini 3.7 Flash (High)",
        "medium": "Gemini 3.7 Flash (Medium)",
        "low": "Gemini 3.7 Flash (Low)",
    },
    "gemini-3.6-flash": {
        "high": "Gemini 3.6 Flash (High)",
        "medium": "Gemini 3.6 Flash (Medium)",
        "low": "Gemini 3.6 Flash (Low)",
    },
    "gemini-3.5-flash": {
        "high": "Gemini 3.5 Flash (High)",
        "medium": "Gemini 3.5 Flash (Medium)",
        "low": "Gemini 3.5 Flash (Low)",
    },
    "gemini-3.1-pro-preview": {
        "high": "Gemini 3.1 Pro (High)",
        "low": "Gemini 3.1 Pro (Low)",
    },
}


def agy_model_label(model: str, effort: str = "") -> str:
    """Map a harness model identifier to an ``agy --model`` display label.

    A known slug maps to its label; anything else (an empty string, or a value
    that is already an exact agy label) is returned unchanged. An unmapped,
    non-label value would make agy silently fall back, so bin/audit's preflight
    is responsible for catching that.
    """
    m = (model or "").strip()
    labels = _AGY_SLUG_TO_LABEL.get(m)
    if not labels:
        return m
    selected = (effort or default_effort("gemini")).lower()
    if selected not in labels:
        raise ValueError(f"agy effort {selected!r} is not available for {m}")
    return labels[selected]


def granted_dirs(add_dirs: str) -> list[str]:
    """Each granted directory as the path a sandbox actually enforces.

    Every sandbox here matches its write rules against the resolved path, so
    the symlinked spelling of a grant is the one spelling that cannot work.
    Claude made such a grant readable and silently unwritable, which left the
    target's build lease unopenable. Codex is stricter still: it refuses to
    create *any* process while a symlinked writable root is configured, so a
    session lost every command it ran, `pwd` included.

    A benchmark cell grants exactly that shape — its facade reaches the target
    tree through a symlink — so both failures land on the harness row and on
    no other. Resolving widens nothing: the resolved path is the one the
    kernel was already checking, and it is the only spelling every backend
    agrees on.
    """
    granted: list[str] = []
    for raw in (add_dirs or "").split(","):
        directory = raw.strip()
        if not directory:
            continue
        resolved = os.path.realpath(directory)
        if resolved not in granted:
            granted.append(resolved)
    return granted


def decide_env(backend: str) -> dict[str, str]:
    """Cost-only environment for a one-shot decision. Never changes behaviour.

    Claude Code writes its prompt cache at the one-hour tier by default, billed
    at 2x fresh input against the five-minute tier's 1.25x. A decision is one
    short session — a few read-only tool turns at most, seconds apart — whose
    prompt is never sent again once it ends, and the system-prompt prefix it
    shares with its fan-out siblings is re-read within minutes, so the hour
    buys nothing. This changes only which cache-write tier the request bills at
    — same model, same tools, same output — so it is a cost choice, not a
    configuration that alters what the decision can do. It touches decision
    calls alone, which have no model-direct counterpart, so no benchmark
    condition is advantaged relative to another. Agent sessions are left on the
    CLI default: their prefix is re-read across the iteration barrier, which can
    exceed five minutes. An operator's own cache setting wins.
    """
    if backend == "claude":
        # Presence, not value: an operator who set either has made the choice.
        if (
            "CLAUDE_CODE_PROMPT_CACHE_TTL" in os.environ
            or "FORCE_PROMPT_CACHING_5M" in os.environ
        ):
            return {}
        return {"CLAUDE_CODE_PROMPT_CACHE_TTL": "5m"}
    return {}


def agent_flags(
    backend: str,
    model: str = "",
    max_turns: int = 80,
    add_dirs: str = "",
    allow_subagents: bool = True,
    agent_security: str | None = None,
) -> list[str]:
    """Build the flag array for an interactive tool-using agent call.

    ``sandboxed`` puts each backend's native OS sandbox between the agent and
    the host: the kernel boundary is what holds, so approval prompts are
    turned off rather than relied on. ``external-bypass`` drops that boundary
    for an explicitly asserted outer sandbox.
    """
    resolved_model = resolve_model_name(backend, model)
    effort = default_effort(backend)
    bypass = resolve_agent_security(agent_security, backend) == "external-bypass"

    if backend == "claude":
        flags = [
            "--print",
            "--safe-mode",
            "--verbose",
            "--output-format", "stream-json",
        ]
        # One disallowed list for both security profiles. The web tools are
        # named here and not only in the sandboxed settings below, because
        # external-bypass carries no settings at all and used to leave
        # WebFetch/WebSearch reachable; every other backend's launch denies
        # web, and audited source is untrusted. Delegation is added only for
        # a bounded validator review (see allow_subagents).
        disallowed = list(_CLAUDE_WEB_TOOLS)
        if not allow_subagents:
            disallowed += list(_CLAUDE_DELEGATION_TOOLS)
        flags += ["--disallowedTools", ",".join(disallowed)]
        if bypass:
            flags.append("--dangerously-skip-permissions")
        else:
            # The sandbox is the boundary, so dontAsk only keeps the session
            # from blocking on a prompt; a tool it cannot sandbox is denied.
            # allowLocalBinding keeps loopback probes (client/server harnesses
            # in network targets) working while egress stays blocked.
            #
            # Bash, and only Bash, is allowed. dontAsk denies whatever the
            # rules leave undecided, and a `;`-chained or multi-line command
            # lands there: `bin/peek f:1-5` ran while
            # `bin/peek f:1-5; echo; bin/peek f:7-9` was denied, taking 9% of
            # agent Bash calls with it — the harness's own peek/rg-safe/state/
            # probe invocations — while the unchained command it split on was
            # permitted anyway. Allowing Bash moves that decision to the
            # sandbox, which confines it: a write or delete outside the cwd and
            # the --add-dir grants fails EPERM whatever an agent runs, egress
            # stays blocked, and `deny` still outranks the rule.
            #
            # The built-in file tools are deliberately NOT allowed here. The
            # sandbox arbitrates Bash; Write/Edit answer to the permission
            # system alone, so a bare allow is an allow-all-file-access grant
            # reaching any path on the host — measured, not assumed: with
            # `allow: [Write, Edit]` a session created and overwrote files
            # under $HOME that no --add-dir covered. Nothing here needs them:
            # agents reach files through Bash, where the kernel is the
            # boundary, so the question of which narrower rule would have been
            # safe never arises. Reads are unconfined either way, so nothing
            # secret may live in a session's environment.
            settings = {
                "permissions": {
                    "allow": ["Bash"],
                    "deny": ["WebFetch", "WebSearch"],
                },
                "sandbox": {
                    "enabled": True,
                    "autoAllowBashIfSandboxed": True,
                    "allowUnsandboxedCommands": False,
                    "failIfUnavailable": True,
                    "network": {"allowLocalBinding": True},
                },
            }
            flags += [
                "--permission-mode", "dontAsk",
                "--settings", json.dumps(settings, separators=(",", ":")),
            ]
        # Audit sessions pass TURN_SOFT_CAP here because Claude can end at its
        # own structured turn boundary and retain terminal usage. Other callers
        # use max_turns for their own contract (for example, preflight=1).
        # max_turns <= 0 omits the flag; the model-direct benchmark uses that
        # form so only its wall-clock budget ends the open-ended cell.
        if max_turns > 0:
            flags += ["--max-turns", str(max_turns)]
        if resolved_model:
            flags += ["--model", resolved_model]
        if effort:
            flags += ["--effort", effort]
        for d in granted_dirs(add_dirs):
            flags += ["--add-dir", d]
        return flags

    if backend == "codex":
        # Not --ephemeral: the stream reports usage only in `turn.completed`,
        # which a session stopped at the turn cap or the wall deadline never
        # emits, so the longest sessions in a run priced as free. Dropping it
        # writes a rollout that carries those counters, and llm_usage deletes
        # each one as it reads it. That trade is deliberate: between
        # extraction and deletion, a full transcript of the audit sits in
        # CODEX_HOME, and a killed harness leaves it there. Prompt history
        # stays off, which --ephemeral did not control.
        flags = [
            "--json",
            "-c", 'history.persistence="none"',
            *_CODEX_PLUGIN_OFF_FLAGS,
            *_CODEX_PROJECT_ROOT_FLAGS,
            # Codex's web search is on by default (measured: a default session
            # answered a search with example.com's title and streamed a
            # `web_search` item). Every other backend's agent launch denies
            # web tools, because audited source is untrusted input, so codex
            # does too. The value is an enum — disabled|cached|indexed|live —
            # and a bare boolean is rejected at config load.
            "-c", 'web_search="disabled"',
            "--skip-git-repo-check",
        ]
        if bypass:
            flags += [
                "--sandbox", "danger-full-access",
                "--dangerously-bypass-approvals-and-sandbox",
            ]
        else:
            flags += [
                "--sandbox", "workspace-write",
                "-c", 'approval_policy="never"',
            ]
        if resolved_model:
            flags += ["--model", resolved_model]
        if effort:
            flags += ["-c", f'model_reasoning_effort="{effort}"']
        if not allow_subagents:
            flags += ["-c", "features.multi_agent=false"]
        dirs = granted_dirs(add_dirs)
        if dirs:
            flags += ["--cd", dirs[0]]
            for d in dirs[1:]:
                flags += ["--add-dir", d]
        if not memory_enabled():
            flags += _CODEX_MEMORY_OFF_FLAGS
        return flags

    if backend == "oss":
        # OpenCode has no native OS sandbox. Its current non-interactive switch
        # is --auto; the entry points permit it only under external-bypass.
        flags = ["run", "--pure", "--auto"]
        if resolved_model:
            flags += ["--model", opencode_model_ref(resolved_model)]
        flags += ["--format", "json"]
        return flags

    if backend == "gemini":
        if use_gemini_cli():
            # Google Gemini CLI: --approval-mode=yolo is the closest
            # equivalent to agy's non-interactive tool approval bypass.
            # --skip-trust avoids a workspace-trust prompt in fresh
            # worktrees/containers. Gemini CLI accepts launch-time model
            # selection and --include-directories for extra workspaces.
            flags = [
                "--approval-mode=yolo", "--skip-trust",
                "--output-format", "stream-json",
            ]
            if resolved_model:
                flags += ["--model", resolved_model]
            # Deny the save_memory tool at the admin policy tier as
            # defence-in-depth. This alone is NOT sufficient isolation — the
            # global ~/.gemini/GEMINI.md is auto-loaded regardless of tool
            # policy, and write_file/replace can append to it without touching
            # save_memory. The actual read+write isolation comes from
            # GEMINI_CLI_HOME relocation (memory_env / prepare_gemini_memory_isolation),
            # exported by the entry point's llm_apply_memory_policy and applied
            # to the subprocess env in lib/llm_decide.py. The deny stays as a
            # cheap explicit block on the one tool whose whole job is writing
            # cross-run memory.
            if not memory_enabled():
                flags += ["--admin-policy", gemini_memory_policy_path()]
            # Unconditional: web stays denied whatever the memory setting, as
            # it is for every other backend's harness launch.
            flags += ["--admin-policy", gemini_no_web_policy_path()]
            for d in granted_dirs(add_dirs):
                flags += ["--include-directories", d]
            return flags

        # Antigravity CLI (agy): plain stdout in --print mode. Outside an
        # asserted outer boundary, accept edits while terminal commands run
        # only through its native sandbox and proceed-in-sandbox setting.
        # agy 1.0.5+ takes --model, but only as the `agy models` display
        # label (mapped from the config slug) — and silently falls back on an
        # unrecognized value, so the audit preflight verifies it was honored.
        # AGY_LOG_FILE, when set (by that preflight), pins agy's log to a
        # per-probe path so the unresolved-flag signature can be read back
        # deterministically.
        # --disable-slash-commands is agy's only launch-time control over
        # operator skills; it is the parity with claude --safe-mode, codex
        # features.plugins=false and gemini-cli skills.enabled=false. agy has
        # no memory or home isolation switch at all, and its memory store
        # shares a directory with its OAuth token, so cross-run memory cannot
        # be isolated for this dialect; use gemini-cli for benchmark rows.
        flags = ["--dangerously-skip-permissions", "--disable-slash-commands"]
        label = agy_model_label(resolved_model, effort)
        if label:
            flags += ["--model", label]
        agy_log = os.environ.get("AGY_LOG_FILE", "").strip()
        if agy_log:
            flags += ["--log-file", agy_log]
        for d in granted_dirs(add_dirs):
            flags += ["--add-dir", d]
        return flags

    if backend == "grok":
        flags = [
            "--no-auto-update",
            "--output-format", "streaming-json",
            # No sandbox profile: the sandboxed profile refuses this backend,
            # and --permission-mode is not enforced for anything but bypass.
            "--always-approve",
            "--disable-web-search",
        ]
        if not allow_subagents:
            # Same rule as claude and codex: only a bounded validator review
            # turns delegation off; agents and model-direct keep the default.
            # Grok may report each spawn as a `subagent_start` event (the
            # usage reader counts those where they appear) and its fan-out is
            # disclosed as unobservable either way; its spend is a floor.
            flags.append("--no-subagents")
        flags.append("--experimental-memory" if memory_enabled() else "--no-memory")
        if max_turns > 0:
            flags += ["--max-turns", str(max_turns)]
        if resolved_model:
            flags += ["--model", resolved_model]
        if effort:
            flags += ["--reasoning-effort", effort]
        dirs = granted_dirs(add_dirs)
        if dirs:
            flags += ["--cwd", dirs[0]]
        return flags

    raise ValueError(f"unknown backend: {backend}")


def _apply_agent_shell_environment(
    environment: dict[str, str], configured_wrappers: str = "",
) -> None:
    """Install process guards without leaking audit wrappers into controls.

    Every tool-using launch gets the small process-safety directory. Only
    callers that explicitly supply AGENT_WRAPPERS_PATH get the audit search
    and compiler wrappers; in particular, model-direct and validator launches
    must remain free of that TokenFuzz machinery.
    """
    lib_dir = Path(__file__).resolve().parent
    guards = lib_dir / "agent_shell_guards"
    default_wrappers = lib_dir / "wrappers"
    inherited_wrappers = environment.pop("AGENT_WRAPPERS_PATH", "")
    wrappers = Path(configured_wrappers) if configured_wrappers else None

    guard_text = str(guards)
    environment["AGENT_SHELL_GUARDS_PATH"] = guard_text
    environment["ZDOTDIR"] = str(guards / "_zdotdir")
    if wrappers is not None:
        environment["AGENT_WRAPPERS_PATH"] = str(wrappers)

    # Empty entries mean "current directory" — never carry one into an agent
    # shell that cd's through the target tree. Strip inherited TokenFuzz paths
    # as well: only an explicit caller opt-in may install the audit wrappers.
    excluded = {
        guard_text,
        str(default_wrappers),
        inherited_wrappers,
        str(wrappers) if wrappers is not None else "",
    }
    entries = (environment.get("PATH") or os.defpath).split(os.pathsep)
    prefixes = [guard_text]
    if wrappers is not None:
        prefixes.append(str(wrappers))
    environment["PATH"] = os.pathsep.join([
        *prefixes,
        *(entry for entry in entries if entry and entry not in excluded),
    ])


def run_agent_prompt(
    backend: str,
    prompt: str,
    timeout_secs: int,
    raw_log: str | os.PathLike[str],
    *,
    model: str = "",
    max_turns: int = 80,
    add_dirs: str = "",
    cwd: str | os.PathLike[str] | None = None,
    extra_env: dict[str, str] | None = None,
    watchdog_marker_dir: str | os.PathLike[str] | None = None,
    turn_cap: int | None = None,
    allow_subagents: bool = True,
    agent_security: str | None = None,
) -> int:
    """Launch a tool-using backend and write its combined raw transcript."""
    agent_security = resolve_agent_security(agent_security, backend)
    problem = agent_security_problem(backend, agent_security)
    if problem:
        raise ValueError(problem)
    warn_agent_security(agent_security)
    binary = backend_bin(backend)
    requested_cap = max(0, int(turn_cap)) if turn_cap is not None else None
    native_session_cap = (
        requested_cap
        if requested_cap is not None and backend in ("claude", "grok")
        else max_turns
    )
    flags = agent_flags(
        backend, model, native_session_cap, add_dirs,
        allow_subagents=allow_subagents,
        agent_security=agent_security,
    )
    first_dir = next(iter(granted_dirs(add_dirs)), "")
    working_dir = Path(cwd or first_dir or Path.cwd())
    # Grok and Antigravity have no launch flag that disables parent project
    # discovery. Make the directory each CLI treats as its workspace a hard
    # boundary even when TokenFuzz itself came from a source archive nested in
    # an unrelated checkout. Existing Git/worktree markers are untouched.
    try:
        if backend == "grok":
            ensure_project_root(first_dir or working_dir)
        elif backend == "gemini" and not use_gemini_cli():
            ensure_project_root(working_dir)
    except (OSError, RuntimeError) as exc:
        message = f"project boundary unavailable: {exc}"
        print(f"ERROR: {message}", file=sys.stderr)
        try:
            Path(raw_log).write_text(message + "\n", encoding="utf-8")
        except OSError:
            pass
        return 127
    environment = os.environ.copy()
    environment.update(invocation_env(
        backend,
        model,
        requested_cap
        if requested_cap is not None and backend == "gemini" and use_gemini_cli()
        else 0,
    ))
    if extra_env:
        environment.update({str(key): str(value) for key, value in extra_env.items()})
    configured_wrappers = str((extra_env or {}).get("AGENT_WRAPPERS_PATH", ""))
    _apply_agent_shell_environment(environment, configured_wrappers)
    if backend == "claude":
        command, input_text = [binary, *flags, "-p", prompt], None
    elif backend == "codex":
        command, input_text = [binary, "exec", *flags, "-"], prompt
    elif backend == "oss":
        environment["OPENCODE_CONFIG_CONTENT"] = json.dumps(
            opencode_config(model, agent_security), separators=(",", ":")
        )
        command, input_text = [binary, *flags, prompt], None
    elif backend == "gemini":
        command = [binary, *flags]
        if use_gemini_cli():
            command.extend(("-p", ""))
            input_text = prompt
        else:
            command.extend(("--print-timeout", f"{timeout_secs}s"))
            command.extend(("-p", prompt))
            input_text = None
    elif backend == "grok":
        command, input_text = [binary, *flags, "-p", prompt], None
    else:
        raise ValueError(f"unknown backend: {backend}")
    launch_command = command
    if timeout_secs > 0:
        launch_command = [
            sys.executable, str(Path(__file__).with_name("timeout.py")),
            str(timeout_secs), "TERM", "0", *command,
        ]
    try:
        # Claude, Grok, and current Google Gemini CLI versions have native turn
        # limits. Gemini also keeps its completed-tool watchdog armed as a
        # compatibility fallback for versions that ignore maxSessionTurns.
        # Codex and OpenCode expose completed tool events, so the harness can
        # stop them at the same rollover target. Antigravity (`agy`) has no
        # native cap or stable documented completed-tool event contract. Its
        # hidden stream-json step updates are not a safe termination boundary,
        # so that dialect remains cooperative plus wall-clock bounded.
        transcript_cap = requested_cap or 0
        if backend in ("claude", "grok") or (
            backend == "gemini" and not use_gemini_cli()
        ):
            transcript_cap = 0
        returncode = _run_agent_process(
            launch_command, input_text, raw_log, working_dir, environment,
            turn_cap=transcript_cap,
            checkpoint_on_native_limit=bool(
                requested_cap
                and (
                    backend in ("claude", "grok")
                    or (backend == "gemini" and use_gemini_cli())
                )
            ),
            health_watchdog=(
                backend == "gemini" and timeout_secs > 0
            ),
            watchdog_marker_dir=watchdog_marker_dir,
        )
    except OSError as exc:
        Path(raw_log).write_text(str(exc) + "\n", encoding="utf-8")
        return 127
    if backend == "gemini" and not use_gemini_cli():
        _capture_agy_cli_log_diag(raw_log)
    if backend == "gemini" and use_gemini_cli() and gemini_admin_policy_dropped(raw_log):
        # Gemini CLI discards every --admin-policy, with one warning, when a
        # system policies directory holds any policy. The memory and web
        # denies went with it, so this session ran unisolated. The audit
        # preflight refuses before any session; a benchmark cell has no
        # preflight, so the launch itself reports the failure and the cell
        # counts as failed rather than as a measurement.
        message = (
            "Gemini CLI ignored the harness admin policies (a system policies "
            "directory is defined on this host); the session ran with memory "
            f"and web tools enabled: {raw_log}"
        )
        print(f"ERROR: {message}", file=sys.stderr)
        return 46
    warning = refusal_warning(backend, str(raw_log), prompt)
    if warning:
        print(warning, file=sys.stderr)
        Path(f"{raw_log}.refusals.log").write_text(warning + "\n")
    return returncode


_CRASH_ENRICHMENT_GRACE_COMMANDS = 15
_CRASH_ENRICHMENT_GRACE_SECONDS = 300

# Written to the transcript when the harness ends a session at the turn cap.
# A capped session exits 0, so this is the only signal separating "checkpointed
# for continuation" from "finished on its own".
TURN_CAP_MARKER = "TURN_SOFT_CAP reached"


def _agent_has_unfinished_crash(environment: dict) -> bool:
    """Whether this audit agent owns a crash report that still needs prose."""
    tried = environment.get("TRIED_INPUTS_LOG", "")
    agent = str(environment.get("AGENT_NUM", ""))
    if not tried or not agent:
        return False
    crashes = Path(tried).parent / "crashes"
    for crash_dir in crashes.glob(f"CRASH-*-{agent}"):
        if not crash_dir.is_dir():
            continue
        report = crash_dir / "report.md"
        if not report.is_file() and (crash_dir / "REPORT.md").is_file():
            report = crash_dir / "REPORT.md"
        try:
            if "_TODO (agent):" in report.read_text(
                encoding="utf-8", errors="replace"
            ):
                return True
        except OSError:
            return True
    return False


def _feed_stdin(process, input_text: str):
    """Write the prompt from a thread so a large prompt cannot deadlock.

    stdout goes to a file, so the child never blocks there; without this a
    prompt larger than the pipe buffer stalls against a child that streams
    stdout before draining stdin.
    """
    def _feed() -> None:
        try:
            process.stdin.write(input_text)
        except (OSError, ValueError):
            pass
        finally:
            try:
                process.stdin.close()
            except OSError:
                pass

    feeder = threading.Thread(target=_feed, daemon=True)
    feeder.start()
    return feeder


def _run_agent_process(
    launch_command, input_text, raw_log, cwd, environment, *,
    turn_cap: int = 0,
    checkpoint_on_native_limit: bool = False,
    health_watchdog: bool = False,
    watchdog_marker_dir: str | os.PathLike[str] | None = None,
) -> int:
    """Run one agent CLI, optionally under a turn cap and a health watchdog.

    A transcript cap ends a session after a bounded number of completed tool
    calls. Native-cap backends are normalized here too when explicitly armed
    by the audit caller. A capped session exits 0 and is continued from
    `bin/state resume`, not treated as a failure.

    The health watchdog is Gemini's sustained-quota-stall detector; it needs
    the transcript streamed live, which the polling loop already provides.
    """
    import audit_helpers
    import process_tree

    raw = Path(raw_log)
    if turn_cap <= 0 and not health_watchdog:
        with raw.open("w", encoding="utf-8") as sink:
            completed = subprocess.run(
                launch_command, input=input_text,
                stdin=subprocess.DEVNULL if input_text is None else None,
                stdout=sink, stderr=subprocess.STDOUT, text=True, cwd=cwd, env=environment,
                check=False,
            )
        return _normalize_native_turn_limit(
            raw, completed.returncode, checkpoint_on_native_limit,
        )

    capped = False
    enrichment_limit = None
    enrichment_deadline = None
    offset = total = 0
    feeder = watchdog = None
    with raw.open("w", encoding="utf-8") as sink:
        process = subprocess.Popen(
            launch_command,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=sink,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=cwd,
            env=environment,
        )
        try:
            if health_watchdog:
                import gemini_watchdog

                agent_num = environment.get("AGENT_NUM", "")
                marker = (
                    Path(watchdog_marker_dir)
                    if watchdog_marker_dir is not None else raw.parent
                )
                watchdog = gemini_watchdog.Watchdog(
                    raw, process.pid, marker,
                    f"Agent{agent_num}" if agent_num else "gemini agent",
                    use_cli=use_gemini_cli(),
                )
                watchdog.start()
            if input_text is not None:
                feeder = _feed_stdin(process, input_text)
            while process.poll() is None:
                if turn_cap <= 0:
                    time.sleep(0.5)
                    continue
                # stdout is a regular file, so flushing Python's handle is
                # enough to make every completed JSONL record observable.
                sink.flush()
                count, offset = audit_helpers.tool_call_delta(raw, offset)
                total += count
                if total >= turn_cap:
                    unfinished = _agent_has_unfinished_crash(environment)
                    if enrichment_limit is None and unfinished:
                        # Confirmation can land on the nominal last call.
                        # Give the required report a small, bounded tail; the
                        # structured resume path will preempt new work if this
                        # tail still is not enough.
                        enrichment_limit = total + _CRASH_ENRICHMENT_GRACE_COMMANDS
                        enrichment_deadline = (
                            time.monotonic() + _CRASH_ENRICHMENT_GRACE_SECONDS
                        )
                    if not unfinished or (
                        enrichment_limit is not None
                        and (
                            total >= enrichment_limit
                            or time.monotonic() >= enrichment_deadline
                        )
                    ):
                        try:
                            process_tree.kill_descendants(process.pid, signal.SIGTERM, 1.0)
                        except (OSError, subprocess.SubprocessError):
                            pass
                        # A process that already exited on its own is a natural
                        # finish, not a checkpoint. Only mark the session capped
                        # when this terminate actually applied to a live child.
                        try:
                            process.terminate()
                        except OSError:
                            pass
                        else:
                            capped = True
                        break
                time.sleep(0.5)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        finally:
            if watchdog is not None:
                watchdog.stop()
                watchdog.join(timeout=7)
            if process.poll() is None:
                process.kill()
                process.wait()
            if feeder is not None:
                feeder.join(timeout=1)
    if capped:
        _mark_turn_capped(raw, f"after {total} completed tool calls")
        return 0
    return _normalize_native_turn_limit(
        raw, process.returncode, checkpoint_on_native_limit,
    )


def _native_turn_limit_reached(raw_log: Path) -> bool:
    """Recognize exact structured native-cap events, never model/tool prose."""
    from file_tools import reverse_lines

    for index, line in enumerate(reverse_lines(raw_log)):
        if index >= 32:
            break
        try:
            event = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(event, dict):
            continue
        if (
            event.get("type") == "result"
            and event.get("subtype") == "error_max_turns"
        ):
            return True
        if event.get("type") == "max_turns_reached":
            return True
        error = event.get("error")
        if (
            event.get("type") == "result"
            and event.get("status") == "error"
            and isinstance(error, dict)
            and error.get("type") == "FatalTurnLimitedError"
        ):
            return True
    return False


def _normalize_native_turn_limit(
    raw_log: Path, returncode: int, checkpoint_on_native_limit: bool,
) -> int:
    """Turn a deliberately armed native ceiling into a clean checkpoint."""
    if checkpoint_on_native_limit and _native_turn_limit_reached(raw_log):
        _mark_turn_capped(raw_log, "at the backend CLI's own turn ceiling")
        return 0
    return returncode


def _mark_turn_capped(raw_log: Path, detail: str) -> None:
    with open(raw_log, "a", encoding="utf-8") as stream:
        stream.write(
            f"[audit] {TURN_CAP_MARKER} {detail}; "
            "session checkpointed for a fresh continuation.\n"
        )


def session_turn_capped(raw_log: str | os.PathLike[str]) -> bool:
    """Whether this session ended at the turn cap rather than on its own."""
    try:
        from file_tools import reverse_lines

        for line in reverse_lines(raw_log):
            if line.strip():
                return line.startswith(f"[audit] {TURN_CAP_MARKER} ")
    except OSError:
        return False
    return False


def decide_flags(backend: str, model: str = "") -> list[str]:
    """Build the flag array for a decision call.

    Read-only tools and no turn cap: every backend runs a
    decision bounded by the decision timeout, not a fixed number of turns, so a
    decision that reads source to judge (find_quality, reachability, cluster
    siblings, …) can — with the same read-only reach across backends: codex
    --sandbox read-only, gemini --approval-mode=plan, claude --permission-mode
    plan. Web tools are denied here as on agent launches: a decision reads
    untrusted source, and read-only modes gate the filesystem, not egress.
    Antigravity exposes no web switch. Used by lib/llm_decide.py's backend
    dispatcher (imported, not subprocessed).
    """
    resolved_model = resolve_model_name(backend, model)
    effort = default_effort(backend)

    if backend == "claude":
        # plan is claude's read-only mode: Read/Grep/Glob for source-grounded
        # verdicts, writes and exec blocked. Mode-enforced, so it stays
        # read-only as tools evolve — no allow/deny list to keep complete.
        #
        # Safe mode keeps one-shot harness decisions from loading operator
        # plugins/skills/hooks/statusline context. Unlike full audit-agent
        # sessions, decide calls are never resumed, so session persistence is
        # disabled too.
        # json, not text: the single-result envelope carries this call's own
        # usage — fresh input, both cache buckets, the TTL split, and output —
        # so decision spend is measured instead of estimated from character
        # counts. lib/llm_decide.py unwraps the envelope before parsing.
        flags = [
            "--print",
            "--safe-mode",
            "--no-session-persistence",
            "--output-format", "json",
            "--permission-mode", "plan",
            # Plan mode is read-only for the filesystem, not for the network:
            # a decision reads untrusted source and artifacts, so it gets the
            # same web denial as an agent session.
            "--disallowedTools", ",".join(_CLAUDE_WEB_TOOLS),
        ]
        if resolved_model:
            flags += ["--model", resolved_model]
        if effort:
            flags += ["--effort", effort]
        return flags

    if backend == "codex":
        # Same rollout contract as an agent session above: a decision the
        # timeout stops mid-turn would otherwise report no usage at all.
        flags = [
            "--json", "-c", 'history.persistence="none"',
            *_CODEX_PLUGIN_OFF_FLAGS, *_CODEX_PROJECT_ROOT_FLAGS,
            "-c", 'web_search="disabled"',
            "--skip-git-repo-check", "--sandbox", "read-only",
        ]
        if resolved_model:
            flags += ["--model", resolved_model]
        if effort:
            flags += ["-c", f'model_reasoning_effort="{effort}"']
        if not memory_enabled():
            flags += _CODEX_MEMORY_OFF_FLAGS
        return flags

    if backend == "oss":
        flags = ["run", "--pure"]
        if resolved_model:
            flags += ["--model", opencode_model_ref(resolved_model)]
        flags += ["--format", "json"]
        return flags

    if backend == "gemini":
        if use_gemini_cli():
            # Plan mode is Gemini CLI's read-only approval mode, matching
            # decide calls' single-shot/no-write contract.
            # stream-json retains the terminal stats block, so the decision
            # ledger uses native counts instead of a character estimate.
            flags = [
                "--approval-mode=plan", "--skip-trust",
                "--output-format", "stream-json",
            ]
            if resolved_model:
                flags += ["--model", resolved_model]
            # Deny save_memory even here, so the no-write contract holds
            # regardless of plan-mode tool gating (see agent_flags).
            if not memory_enabled():
                flags += ["--admin-policy", gemini_memory_policy_path()]
            flags += ["--admin-policy", gemini_no_web_policy_path()]
            return flags

        # Antigravity CLI (agy) decide mode: --print emits plain text.
        # --dangerously-skip-permissions keeps decide calls non-interactive.
        # Its --mode plan is not a read-only guarantee (measured: a shell write
        # under plan still lands), and its sandbox cannot read the tree a
        # decision must judge, so neither is used here.
        flags = ["--dangerously-skip-permissions", "--disable-slash-commands"]
        label = agy_model_label(resolved_model, effort)
        if label:
            flags += ["--model", label]
        return flags

    if backend == "grok":
        flags = [
            "--no-auto-update",
            "--no-subagents",
            "--permission-mode", "plan",
            "--output-format", "plain",
            "--disable-web-search",
        ]
        flags.append("--experimental-memory" if memory_enabled() else "--no-memory")
        if resolved_model:
            flags += ["--model", resolved_model]
        if effort:
            flags += ["--reasoning-effort", effort]
        return flags

    raise ValueError(f"unknown backend: {backend}")


# ── Assistant-text extraction ───────────────────────────────────────


def _iter_json_values(lines):
    """Yield JSON objects from transcript lines, tolerating non-JSON lines."""
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if not line.startswith(("{", "[")):
            continue
        try:
            yield json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue


def _iter_json_lines(raw_log_path: str):
    """Yield JSON objects from a raw transcript, tolerating non-JSON lines.

    Some CLIs interleave stream-json lines with stderr banner output, so
    non-JSON lines are skipped.
    """
    try:
        with open(raw_log_path, "r", encoding="utf-8", errors="replace") as f:
            yield from _iter_json_values(f)
    except OSError:
        return


def _collect_text_values(value) -> list[str]:
    pieces: list[str] = []
    if isinstance(value, str):
        pieces.append(value)
    elif isinstance(value, list):
        for item in value:
            pieces.extend(_collect_text_values(item))
    elif isinstance(value, dict):
        for key in ("text", "content", "delta", "result", "response"):
            item = value.get(key)
            if isinstance(item, (str, list, dict)):
                pieces.extend(_collect_text_values(item))
        message = value.get("message")
        if isinstance(message, dict):
            pieces.extend(_collect_text_values(message))
    return pieces


def _opencode_assistant_texts(ev: dict) -> list[str]:
    ev_type = str(ev.get("type", "")).lower()
    role = str(ev.get("role", "")).lower()
    if role and role not in {"assistant", "model"}:
        return []
    if ev_type and any(marker in ev_type for marker in ("tool", "permission", "diagnostic")):
        return []

    pieces: list[str] = []
    for key in ("content", "text", "delta", "result", "response"):
        value = ev.get(key)
        if isinstance(value, (str, list, dict)):
            pieces.extend(_collect_text_values(value))

    message = ev.get("message")
    if isinstance(message, dict):
        msg_role = str(message.get("role", role)).lower()
        if msg_role in {"assistant", "model", ""}:
            pieces.extend(_collect_text_values(message.get("content")))

    part = ev.get("part")
    if isinstance(part, dict):
        pieces.extend(_collect_text_values(part))

    return pieces


def extract_text(backend: str, raw_log_path: str) -> str:
    """Pull the assistant's text from a raw transcript.

    Returns the empty string on:
      - empty / missing-content transcript
      - log file unreadable (caller distinguishes via separate check)

    Raises FileNotFoundError when <raw_log_path> does not exist so callers can
    distinguish a missing transcript from an empty response.
    """
    if not os.path.isfile(raw_log_path):
        raise FileNotFoundError(raw_log_path)

    pieces: list[str] = []

    if backend == "claude":
        # Two text sources in a stream-json transcript: per-turn
        # assistant messages (.message.content[].text) and the trailing
        # result event (.result). The result event echoes the final
        # assistant turn *verbatim* — collecting both double-counts
        # every line the agent emitted (e.g. JSONL rows parsed
        # twice). Prefer the per-turn assistant text, which is complete
        # across multi-turn replies; fall back to .result only when no
        # assistant message text exists (non-streaming output formats
        # emit just a result event).
        msg_pieces: list[str] = []
        result_pieces: list[str] = []
        for ev in _iter_json_lines(raw_log_path):
            if not isinstance(ev, dict):
                continue
            msg = ev.get("message")
            if isinstance(msg, dict):
                content = msg.get("content")
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict):
                            t = item.get("text")
                            if isinstance(t, str):
                                msg_pieces.append(t)
            result = ev.get("result")
            if isinstance(result, str):
                result_pieces.append(result)
        pieces = msg_pieces if msg_pieces else result_pieces
        # Each extracted value is emitted on its own line.
        return "\n".join(pieces) + ("\n" if pieces else "")

    if backend == "codex":
        # item.completed events with .item.type == "agent_message",
        # take .item.text. The CLI emits a JSON string for the model's
        # output; json.loads() on the outer line already decoded it.
        for ev in _iter_json_lines(raw_log_path):
            if not isinstance(ev, dict):
                continue
            if ev.get("type") != "item.completed":
                continue
            item = ev.get("item")
            if isinstance(item, dict) and item.get("type") == "agent_message":
                t = item.get("text")
                if isinstance(t, str):
                    pieces.append(t)
        return "\n".join(pieces) + ("\n" if pieces else "")

    if backend == "oss":
        for ev in _iter_json_lines(raw_log_path):
            if isinstance(ev, dict):
                pieces.extend(_opencode_assistant_texts(ev))
        if pieces:
            return "".join(pieces).rstrip("\n")
        try:
            with open(raw_log_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read().rstrip("\n")
        except OSError:
            return ""

    if backend == "gemini":
        if use_gemini_cli():
            for ev in _iter_json_lines(raw_log_path):
                if not isinstance(ev, dict):
                    continue
                ev_type = ev.get("type")
                role = ev.get("role")
                is_assistant = (
                    role in ("assistant", "model")
                    or ev_type == "assistant"
                    or (ev_type == "message" and role in ("assistant", "model"))
                )
                if is_assistant:
                    content = ev.get("content")
                    if isinstance(content, str):
                        pieces.append(content)
                    elif isinstance(content, list):
                        for item in content:
                            if isinstance(item, str):
                                pieces.append(item)
                            elif isinstance(item, dict):
                                t = item.get("text") or item.get("content")
                                if isinstance(t, str):
                                    pieces.append(t)
                    text = ev.get("text") or ev.get("delta") or ev.get("result") or ev.get("response")
                    if isinstance(text, str):
                        pieces.append(text)
                msg = ev.get("message")
                if is_assistant and isinstance(msg, dict):
                    content = msg.get("content")
                    if isinstance(content, str):
                        pieces.append(content)
                    elif isinstance(content, list):
                        for item in content:
                            if isinstance(item, dict):
                                t = item.get("text") or item.get("content")
                                if isinstance(t, str):
                                    pieces.append(t)
            # Gemini CLI stream-json emits assistant text as deltas. The
            # fragments are not line-oriented; inserting separators corrupts
            # structured replies such as batch JSONL (`{"id":...}` split
            # across several message events). Preserve the model's emitted
            # bytes exactly and rely on embedded "\n" deltas for line breaks.
            return "".join(pieces).rstrip("\n")

        # agy emits plain text in non-interactive output mode. The entire
        # stdout transcript IS the assistant's reply; strip a trailing
        # newline for parity with the JSON-extracted backends.
        try:
            with open(raw_log_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read().rstrip("\n")
        except OSError:
            return ""

    if backend == "grok":
        for ev in _iter_json_lines(raw_log_path):
            if not isinstance(ev, dict) or ev.get("type") != "text":
                continue
            data = ev.get("data")
            if isinstance(data, str):
                pieces.append(data)
        return "".join(pieces).rstrip("\n")

    raise ValueError(f"unknown backend: {backend}")


# ── Transient provider-failure detection ────────────────────────────────
# Single source of truth for "did this run die on a transient backend
# failure (overload / 429 / 5xx / rate-limit / timeout)?" It lives next to
# the transcript parsers so callers never hand-roll the keyword regex. The
# stream-json backends (codex, gemini-CLI) surface the failure as a JSON
# error event OR a trailing stderr line that the text extractor drops, so
# detection reads the RAW transcript and understands both shapes.
_TRANSIENT_KW = re.compile(
    r"(?:\b(?:429|5\d\d)\b|overload|temporar\w* limit|rate[\s_-]?limit"
    r"|usage[\s_-]?limit|too many requests|timed?\s?out|time[\s_-]?out"
    r"|service unavailable|server is temporarily)",
    re.IGNORECASE,
)
_ERROR_LINE = re.compile(r"^\s*(?:api error|error:|fatal|stream error)", re.IGNORECASE)


def _event_is_transient_error(ev) -> bool:
    """True for a JSON transcript event that signals a transient failure."""
    if not isinstance(ev, dict):
        return False
    et = str(ev.get("type", "")).lower()
    sub = str(ev.get("subtype", "")).lower()
    marked = (
        ev.get("is_error") is True
        or "error" in et
        or et in ("overloaded_error", "server_error")
        or "error" in sub
        or isinstance(ev.get("error"), (dict, str))
    )
    if not marked:
        return False
    return bool(_TRANSIENT_KW.search(json.dumps(ev, ensure_ascii=False)))


def transient_tail(raw_log_path: str, tail_lines: int = 4) -> bool:
    """True if the tail of a raw transcript shows a fatal transient provider
    failure that cut the run off (overload / 429 / 5xx / rate-limit / timeout).

    Reads only the last few non-empty lines — the failure is the terminal
    write before the process exits — and detects both a plain stderr error
    line and a JSON error event, so it is correct for every backend
    regardless of how that CLI surfaces the error. Anchoring on an error
    context (an error-prefixed line or an error-typed event) keeps an
    ordinary trailing result/agent_message event from tripping it.
    """
    if not os.path.isfile(raw_log_path):
        return False
    from file_tools import tail_lines as read_tail_lines

    tail = read_tail_lines(Path(raw_log_path), max(1, tail_lines), nonempty=True)
    for line in tail:
        if _ERROR_LINE.search(line) and _TRANSIENT_KW.search(line):
            return True
        stripped = line.lstrip()
        if stripped.startswith("{"):
            try:
                ev = json.loads(stripped)
            except Exception:
                continue
            if _event_is_transient_error(ev):
                return True
    return False


_GEMINI_REFUSAL_FINISH_REASONS = {
    "SAFETY",
    "BLOCKLIST",
    "PROHIBITED_CONTENT",
    "IMAGE_SAFETY",
    "IMAGE_PROHIBITED_CONTENT",
    "SPII",
}
_REFUSAL_SCAN_EDGE_BYTES = 2 * 1024 * 1024
_CLI_NO_WORK_REFUSAL_CONTEXT = ("security", "vulnerab")
_CLI_NO_WORK_REFUSAL_PREFIXES = ("i can't help", "sorry, i cannot fulfill")


def _norm_json_scalar(value) -> str:
    return str(value).strip().upper() if isinstance(value, str) else ""


def _has_refusal_value(value) -> bool:
    if isinstance(value, str):
        return value.strip().lower() not in ("", "null", "none", "false")
    return isinstance(value, (dict, list)) and bool(value)


def _json_has_refusal_signal(value) -> bool:
    if isinstance(value, dict):
        for key, item in value.items():
            k = str(key).lower()
            scalar = _norm_json_scalar(item)
            if k in ("stop_reason", "stopreason") and scalar == "REFUSAL":
                return True
            if k == "type" and scalar == "REFUSAL":
                return True
            if k == "refusal" and _has_refusal_value(item):
                return True
            if k == "finishreason" and scalar in _GEMINI_REFUSAL_FINISH_REASONS:
                return True
            if (
                k == "blockreason"
                and scalar
                and scalar != "BLOCK_REASON_UNSPECIFIED"
            ):
                return True
            if isinstance(item, (dict, list)) and _json_has_refusal_signal(item):
                return True
        return False
    if isinstance(value, list):
        return any(_json_has_refusal_signal(item) for item in value)
    return False


def _normalize_refusal_text(text: str) -> str:
    return " ".join(
        text.lower()
        .replace("\r", " ")
        .replace("’", "'")
        .replace("‘", "'")
        .split()
    )


def _json_event_has_tool_activity(ev: dict) -> bool:
    ev_type = ev.get("type")
    if ev_type in {"tool_use", "tool_result", "function_call", "function_call_output"}:
        return True
    if ev.get("tool_name") or ev.get("tool_call_id"):
        return True
    item = ev.get("item")
    item_type = item.get("type") if isinstance(item, dict) else ""
    return bool(item_type and item_type != "agent_message")


def _cli_assistant_texts(backend: str, ev: dict) -> list[str]:
    pieces: list[str] = []

    if backend == "codex":
        item = ev.get("item")
        if isinstance(item, dict) and item.get("type") == "agent_message":
            text = item.get("text")
            if isinstance(text, str):
                pieces.append(text)
        return pieces

    if backend == "oss":
        return _opencode_assistant_texts(ev)

    if backend == "claude":
        msg = ev.get("message")
        if isinstance(msg, dict):
            content = msg.get("content")
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        text = item.get("text")
                        if isinstance(text, str):
                            pieces.append(text)
        result = ev.get("result")
        if isinstance(result, str):
            pieces.append(result)
        return pieces

    if backend == "gemini":
        ev_type = ev.get("type")
        role = ev.get("role")
        is_assistant = (
            role in ("assistant", "model")
            or ev_type == "assistant"
            or (ev_type == "message" and role in ("assistant", "model"))
        )
        if not is_assistant:
            return pieces

        content = ev.get("content")
        if isinstance(content, str):
            pieces.append(content)
        elif isinstance(content, list):
            for item in content:
                if isinstance(item, str):
                    pieces.append(item)
                elif isinstance(item, dict):
                    text = item.get("text") or item.get("content")
                    if isinstance(text, str):
                        pieces.append(text)
        for key in ("text", "delta", "result", "response"):
            text = ev.get(key)
            if isinstance(text, str):
                pieces.append(text)

    if backend == "grok" and ev.get("type") == "text":
        data = ev.get("data")
        if isinstance(data, str):
            pieces.append(data)

    return pieces


def raw_log_has_cli_no_work_refusal(backend: str, raw_log_path: str) -> bool:
    """Detect short CLI prose refusals that lack structured metadata."""
    try:
        size = os.path.getsize(raw_log_path)
    except OSError:
        return False
    if size > _REFUSAL_SCAN_EDGE_BYTES:
        return False

    assistant_pieces: list[str] = []
    for ev in _iter_json_lines(raw_log_path):
        if not isinstance(ev, dict):
            continue
        if _json_event_has_tool_activity(ev):
            return False
        assistant_pieces.extend(_cli_assistant_texts(backend, ev))

    text = _normalize_refusal_text(" ".join(assistant_pieces))
    return (
        0 < len(text) <= 1200
        and any(text.startswith(prefix) for prefix in _CLI_NO_WORK_REFUSAL_PREFIXES)
        and any(marker in text for marker in _CLI_NO_WORK_REFUSAL_CONTEXT)
    )


def _iter_refusal_scan_json(raw_log_path: str):
    """Yield JSON events from bounded refusal-relevant transcript regions."""
    try:
        size = os.path.getsize(raw_log_path)
    except OSError:
        return

    if size <= _REFUSAL_SCAN_EDGE_BYTES * 2:
        yield from _iter_json_lines(raw_log_path)
        return

    try:
        with open(raw_log_path, "rb") as f:
            head = f.read(_REFUSAL_SCAN_EDGE_BYTES)
            f.seek(size - _REFUSAL_SCAN_EDGE_BYTES)
            tail = f.read(_REFUSAL_SCAN_EDGE_BYTES)
    except OSError:
        return

    yield from _iter_json_values(
        head.decode("utf-8", errors="replace").splitlines()
    )
    tail_lines = tail.decode("utf-8", errors="replace").splitlines()
    if tail_lines:
        tail_lines = tail_lines[1:]
    yield from _iter_json_values(tail_lines)


def raw_log_has_structured_refusal(raw_log_path: str) -> bool:
    # Refusal/block markers are normally either early (Gemini promptFeedback)
    # or in final stream-json events (Claude/OpenAI stop/content metadata).
    # Scan both edges so large audit transcripts do not get fully re-read.
    return any(
        _json_has_refusal_signal(ev)
        for ev in _iter_refusal_scan_json(raw_log_path)
    )


def raw_log_has_model_refusal(backend: str, raw_log_path: str) -> bool:
    return (
        raw_log_has_structured_refusal(raw_log_path)
        or raw_log_has_cli_no_work_refusal(backend, raw_log_path)
    )


def prompt_first_line(prompt: str, limit: int = 180) -> str:
    for line in prompt.replace("\r", "").splitlines():
        first = " ".join(line.split())
        if first:
            return first[:limit]
    return "<empty prompt>"


def refusal_warning(backend: str, raw_log_path: str, prompt: str) -> str:
    # Prefer provider refusal/block fields. Some CLIs can also return a short
    # assistant-message refusal with no structured metadata; catch only those
    # no-tool, response-initial shapes.
    if not raw_log_has_model_refusal(backend, raw_log_path):
        return ""
    return (
        f"WARN: MODEL_REFUSAL backend={backend} refused to answer prompt: "
        f"{prompt_first_line(prompt)}..."
    )


# ── CLI dispatch ───────────────────────────────────────────────────


def _print_flags(flags: list[str]) -> int:
    # One flag per line. Bash reads with `while IFS= read -r line` which
    # handles spaces inside a single flag value correctly. NUL separation would be safer
    # against newline-containing values, but no flag value here contains
    # newlines (paths are sanitised before reaching this layer).
    for f in flags:
        sys.stdout.write(f + "\n")
    return 0


def _cmd_known_backend(args) -> int:
    return 0 if known_backend(args.backend) else 1


def _cmd_default_model(args) -> int:
    try:
        sys.stdout.write(default_model(args.backend) + "\n")
        return 0
    except ValueError:
        return 1


def _cmd_default_effort(args) -> int:
    try:
        sys.stdout.write(default_effort(args.backend) + "\n")
        return 0
    except ValueError:
        return 1


def _cmd_resolve_model(args) -> int:
    try:
        sys.stdout.write(resolve_model_name(args.backend, args.model or "") + "\n")
        return 0
    except ValueError:
        return 1


def _cmd_local_base_url(_args) -> int:
    try:
        sys.stdout.write(local_provider_base_url() + "\n")
        return 0
    except ValueError:
        return 1


def _cmd_opencode_config(args) -> int:
    try:
        json.dump(opencode_config(args.model or ""), sys.stdout, separators=(",", ":"))
        sys.stdout.write("\n")
        return 0
    except ValueError:
        return 1


def _cmd_local_model_available(args) -> int:
    try:
        return 0 if local_model_available(args.model or "") else 1
    except ValueError:
        return 1


def _cmd_agent_flags(args) -> int:
    try:
        return _print_flags(agent_flags(
            args.backend,
            model=args.model or "",
            max_turns=args.max_turns,
            add_dirs=args.add_dirs or "",
            agent_security=args.agent_security,
        ))
    except ValueError:
        return 1


def _cmd_decide_flags(args) -> int:
    try:
        return _print_flags(decide_flags(args.backend, model=args.model or ""))
    except ValueError:
        return 1


def _cmd_extract_text(args) -> int:
    try:
        sys.stdout.write(extract_text(args.backend, args.raw_log))
        return 0
    except FileNotFoundError:
        return 1
    except ValueError:
        return 1


def _cmd_transient_tail(args) -> int:
    return 0 if transient_tail(args.raw_log) else 1


def _cmd_refusal_warning(args) -> int:
    prompt = sys.stdin.read()
    try:
        warning = refusal_warning(args.backend, args.raw_log, prompt)
    except (FileNotFoundError, ValueError):
        return 1
    if not warning:
        return 1
    sys.stdout.write(warning + "\n")
    return 0


def _cmd_gemini_isolated_home(_args) -> int:
    # Stage the isolated Gemini CLI home (when memory is off and USE_GEMINI_CLI=1)
    # and print its path so the caller can export GEMINI_CLI_HOME.
    # Prints nothing when isolation does not apply.
    home = prepare_gemini_memory_isolation()
    if home:
        sys.stdout.write(home + "\n")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="llm_invoke")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("known-backend")
    s.add_argument("backend")
    s.set_defaults(func=_cmd_known_backend)

    s = sub.add_parser("default-model")
    s.add_argument("backend")
    s.set_defaults(func=_cmd_default_model)

    s = sub.add_parser("default-effort")
    s.add_argument("backend")
    s.set_defaults(func=_cmd_default_effort)

    s = sub.add_parser("resolve-model")
    s.add_argument("backend")
    s.add_argument("--model", default="")
    s.set_defaults(func=_cmd_resolve_model)

    s = sub.add_parser("local-base-url")
    s.set_defaults(func=_cmd_local_base_url)

    s = sub.add_parser("opencode-config")
    s.add_argument("--model", default="")
    s.set_defaults(func=_cmd_opencode_config)

    s = sub.add_parser("local-model-available")
    s.add_argument("--model", default="")
    s.set_defaults(func=_cmd_local_model_available)

    s = sub.add_parser("agent-flags")
    s.add_argument("backend")
    s.add_argument("--model", default="")
    s.add_argument("--max-turns", type=int, default=80)
    s.add_argument("--add-dirs", default="")
    s.add_argument("--agent-security", choices=AGENT_SECURITY_MODES, default=None)
    s.set_defaults(func=_cmd_agent_flags)

    s = sub.add_parser("decide-flags")
    s.add_argument("backend")
    s.add_argument("--model", default="")
    s.set_defaults(func=_cmd_decide_flags)

    s = sub.add_parser("extract-text")
    s.add_argument("backend")
    s.add_argument("raw_log")
    s.set_defaults(func=_cmd_extract_text)

    s = sub.add_parser("transient-tail")
    s.add_argument("raw_log")
    s.set_defaults(func=_cmd_transient_tail)

    s = sub.add_parser("refusal-warning")
    s.add_argument("backend")
    s.add_argument("raw_log")
    s.set_defaults(func=_cmd_refusal_warning)

    s = sub.add_parser("gemini-isolated-home")
    s.set_defaults(func=_cmd_gemini_isolated_home)

    return p


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
