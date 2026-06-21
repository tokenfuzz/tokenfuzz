#!/usr/bin/env python3
"""Shared backend-flag picker and assistant-text extractor.

Single source of truth for the four LLM backends the harness drives —
claude / codex / oss (OpenCode against local OpenAI-compatible servers) /
gemini. The `gemini` backend keeps
one harness-visible name while supporting two CLI dialects underneath:
Antigravity (`agy`, default) and Google Gemini CLI (`gemini` when
USE_GEMINI_CLI=1). Previously this logic lived in lib/llm_invoke.sh
(sourced by bin/audit, bin/audit-recon, bin/validate-finding) with the
decide-mode flag subset duplicated into lib/llm_decide.py. That
duplication is now gone: lib/llm_decide.py imports `decide_flags()` from
here, and lib/llm_invoke.sh is a thin bash shim that subprocess-calls
this module so the same flag arrays reach bash callers without drift.

Why bash kept its function-call interface (vs. having callers
subprocess directly): the three binaries above use bash arrays for the
agent-flag list (`"${flags[@]}"`) — that's the natural shape for
forwarding into `exec`. Replacing the array pattern with shell-quoted
strings would be a larger callsite refactor with no readability gain.

CLI subcommands (used by the bash shim — `python3 lib/llm_invoke.py …`):

  known-backend <backend>
      Exit 0 if backend ∈ {claude, codex, oss, gemini}; else 1.

  default-model <backend>
      Print the project's default model name for <backend>, read from
      config/models.toml. A per-backend env override (CLAUDE_MODEL_DEFAULT /
      CODEX_MODEL_DEFAULT / GEMINI_MODEL_DEFAULT)
      wins when set. Exit 1 on unknown backend.

  agent-flags <backend> [--model …] [--max-turns N] [--add-dirs CSV]
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
      stream-json assistant text).

  gemini-isolated-home
      Stage (when cross-run memory is off and USE_GEMINI_CLI=1) a throwaway
      Gemini CLI home that excludes the global GEMINI.md, and print its path
      for the bash entry point to export as GEMINI_CLI_HOME. Prints nothing
      when isolation does not apply.
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import shutil
import sys
import tempfile
import urllib.error
import urllib.request
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


_KNOWN_BACKENDS = ("claude", "codex", "oss", "gemini")

# Per-backend env var that overrides the configured default (CI / throttled
# runs). When unset, the default comes from config/models.toml.
_MODEL_ENV_OVERRIDE = {
    "claude": "CLAUDE_MODEL_DEFAULT",
    "codex": "CODEX_MODEL_DEFAULT",
    "gemini": "GEMINI_MODEL_DEFAULT",
}

# config/models.toml (repo root) is the single source of truth for the
# default model names. Resolved from this file so cwd doesn't matter.
_CONFIG_PATH = Path(__file__).resolve().parent.parent / "config" / "models.toml"


def _config_models() -> dict:
    """Return the [models] table from config/models.toml as {backend: model}."""
    try:
        toml = _load_tomllib()
    except ModuleNotFoundError:
        from target_config import parse_toml

        return parse_toml(_CONFIG_PATH).get("models", {})
    with open(_CONFIG_PATH, "rb") as fh:
        return toml.load(fh).get("models", {})


def known_backend(backend: str) -> bool:
    return backend in _KNOWN_BACKENDS


def use_gemini_cli() -> bool:
    """Return true when the gemini backend should invoke Google Gemini CLI."""
    return os.environ.get("USE_GEMINI_CLI", "").strip() == "1"


def gemini_default_bin() -> str:
    return "gemini" if use_gemini_cli() else "agy"


def memory_enabled() -> bool:
    """Cross-run backend auto-memory is OFF unless TOKENFUZZ_MEMORY_ENABLED=1.

    Default-off (unset / empty / anything but "1") so every flag builder
    injects the per-backend disable controls automatically — no entry point
    can forget to. bin/audit's --enable-memory exports it as 1; bin/benchmark
    always leaves it off. See lib/llm_invoke.sh:llm_apply_memory_policy.
    """
    return os.environ.get("TOKENFUZZ_MEMORY_ENABLED", "").strip() == "1"


def gemini_memory_policy_path() -> str:
    """Absolute path to the Gemini CLI admin policy that denies save_memory."""
    return str(_CONFIG_PATH.parent / "gemini-no-memory.policy.toml")


# Marker file that identifies a TokenFuzz-staged GEMINI_CLI_HOME, so a child
# process that inherits the exported GEMINI_CLI_HOME reuses it instead of
# wiping and re-staging it mid-run.
_GEMINI_ISOLATION_MARKER = ".tokenfuzz-memory-isolated"

# Cache the staged isolated home for the lifetime of one process so repeated
# memory_env("gemini") calls reuse the one staged dir.
_gemini_iso_home: "str | None" = None


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


def prepare_gemini_memory_isolation() -> "str | None":
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
        # Reuse ONLY when the inherited/cached home is this run's home; a
        # mismatch belongs to a different run/cell and must not be reused.
        if existing and _same_path(existing, desired) and _is_tokenfuzz_gemini_home(existing):
            _gemini_iso_home = str(desired)
            return _gemini_iso_home
        if _gemini_iso_home is not None and _same_path(_gemini_iso_home, desired):
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


def memory_env(backend: str) -> dict:
    """Environment overrides that disable cross-run memory for <backend>.

    Empty when memory is enabled, or when the backend needs no env-level
    control — codex disables memory through `-c` flags in agent_flags /
    decide_flags, OpenCode does not need a harness memory knob for local OSS
    runs, and headless agy has no auth-preserving home/profile isolation wired
    here. Apply this on top of the child env at every launch
    site (lib/llm_decide.py's subprocess, and lib/llm_invoke.sh's agent
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
        if home:
            return {"GEMINI_CLI_HOME": home}
    return {}


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


def opencode_model_ref(model: str) -> str:
    resolved = (model or default_model("oss")).strip()
    return f"local/{resolved}" if resolved else "local"


def opencode_config(model: str) -> dict:
    resolved = (model or default_model("oss")).strip()
    if not resolved:
        raise ValueError("oss model is required")
    api_key = os.environ.get("AUDIT_LOCAL_API_KEY") or "EMPTY"
    return {
        "$schema": "https://opencode.ai/config.json",
        "provider": {
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
        },
    }


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
    "gemini-3.1-pro-preview": "Gemini 3.1 Pro (High)",
}


def agy_model_label(model: str) -> str:
    """Map a harness model identifier to an ``agy --model`` display label.

    A known slug maps to its label; anything else (an empty string, or a value
    that is already an exact agy label) is returned unchanged. An unmapped,
    non-label value would make agy silently fall back, so bin/audit's preflight
    is responsible for catching that.
    """
    m = (model or "").strip()
    return _AGY_SLUG_TO_LABEL.get(m, m)


def agent_flags(
    backend: str,
    model: str = "",
    max_turns: int = 80,
    add_dirs: str = "",
) -> list[str]:
    """Build the flag array for an interactive tool-using agent call.

    Codex inside our docker container needs --sandbox danger-full-access
    + --dangerously-bypass-approvals-and-sandbox because the inner bwrap
    can't create a user namespace; the outer container is the sandbox
    boundary (same reasoning as IS_SANDBOX=1 for claude).
    """
    resolved_model = resolve_model_name(backend, model)

    if backend == "claude":
        flags = [
            "--print",
            "--verbose",
            "--output-format", "stream-json",
            "--dangerously-skip-permissions",
        ]
        # max_turns <= 0 means "no cap" — omit the flag so the CLI lets
        # the agent run until the outer wall-clock budget hits. Used by
        # the benchmark's model-direct cell, which is open-ended.
        if max_turns > 0:
            flags += ["--max-turns", str(max_turns)]
        if resolved_model:
            flags += ["--model", resolved_model]
        for d in (add_dirs or "").split(","):
            d = d.strip()
            if d:
                flags += ["--add-dir", d]
        return flags

    if backend == "codex":
        flags = [
            "--json",
            "--ephemeral",
            "--skip-git-repo-check",
            "--sandbox", "danger-full-access",
            "--dangerously-bypass-approvals-and-sandbox",
        ]
        if resolved_model:
            flags += ["--model", resolved_model]
        dirs = [d.strip() for d in (add_dirs or "").split(",") if d.strip()]
        if dirs:
            flags += ["--cd", dirs[0]]
            for d in dirs[1:]:
                flags += ["--add-dir", d]
        if not memory_enabled():
            flags += _CODEX_MEMORY_OFF_FLAGS
        return flags

    if backend == "oss":
        # OpenCode has no per-directory grant flag like codex/gemini --add-dir;
        # --dangerously-skip-permissions auto-approves tool use and filesystem
        # access is scoped by the launch cwd, so add_dirs is intentionally
        # unused here.
        flags = ["run", "--dangerously-skip-permissions"]
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
            flags = ["--approval-mode=yolo", "--skip-trust", "--output-format", "stream-json"]
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
            for d in (add_dirs or "").split(","):
                d = d.strip()
                if d:
                    flags += ["--include-directories", d]
            return flags

        # Antigravity CLI (agy): plain stdout in --print mode.
        # --dangerously-skip-permissions keeps the run non-interactive.
        # agy 1.0.5+ takes --model, but only as the `agy models` display
        # label (mapped from the config slug) — and silently falls back on an
        # unrecognized value, so the audit preflight verifies it was honored.
        # AGY_LOG_FILE, when set (by that preflight), pins agy's log to a
        # per-probe path so the unresolved-flag signature can be read back
        # deterministically.
        flags = ["--dangerously-skip-permissions"]
        label = agy_model_label(resolved_model)
        if label:
            flags += ["--model", label]
        agy_log = os.environ.get("AGY_LOG_FILE", "").strip()
        if agy_log:
            flags += ["--log-file", agy_log]
        for d in (add_dirs or "").split(","):
            d = d.strip()
            if d:
                flags += ["--add-dir", d]
        return flags

    raise ValueError(f"unknown backend: {backend}")


def decide_flags(backend: str, model: str = "") -> list[str]:
    """Build the flag array for a single-shot decision call.

    No tools, text output, read-only sandbox where applicable. Used by
    lib/llm_decide.py's backend dispatcher (imported, not subprocessed).
    """
    resolved_model = resolve_model_name(backend, model)

    if backend == "claude":
        flags = ["--print", "--max-turns", "1", "--output-format", "text"]
        if resolved_model:
            flags += ["--model", resolved_model]
        return flags

    if backend == "codex":
        flags = ["--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only"]
        if resolved_model:
            flags += ["--model", resolved_model]
        if not memory_enabled():
            flags += _CODEX_MEMORY_OFF_FLAGS
        return flags

    if backend == "oss":
        flags = ["run"]
        if resolved_model:
            flags += ["--model", opencode_model_ref(resolved_model)]
        flags += ["--format", "json"]
        return flags

    if backend == "gemini":
        if use_gemini_cli():
            # Plan mode is Gemini CLI's read-only approval mode, matching
            # decide calls' single-shot/no-write contract.
            flags = ["--approval-mode=plan", "--skip-trust"]
            if resolved_model:
                flags += ["--model", resolved_model]
            # Deny save_memory even here, so the no-write contract holds
            # regardless of plan-mode tool gating (see agent_flags).
            if not memory_enabled():
                flags += ["--admin-policy", gemini_memory_policy_path()]
            return flags

        # Antigravity CLI (agy) decide mode: --print emits plain text.
        # --dangerously-skip-permissions keeps decide calls non-interactive.
        # See agent_flags for the --model label-mapping rationale.
        flags = ["--dangerously-skip-permissions"]
        label = agy_model_label(resolved_model)
        if label:
            flags += ["--model", label]
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

    Some CLIs interleave stream-json lines with stderr banner output.
    The bash version uses `jq -R … fromjson?` to drop those; we mirror
    by simply skipping any line that doesn't parse.
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


def _json_has_tool_name(value, tool_name: str) -> bool:
    wanted = tool_name.lower()
    if isinstance(value, dict):
        for key in ("tool", "name", "tool_name"):
            item = value.get(key)
            if isinstance(item, str) and item.lower() == wanted:
                return True
        return any(_json_has_tool_name(item, tool_name) for item in value.values())
    if isinstance(value, list):
        return any(_json_has_tool_name(item, tool_name) for item in value)
    return False


def raw_has_tool(raw_log_path: str, tool_name: str) -> bool:
    if not os.path.isfile(raw_log_path):
        raise FileNotFoundError(raw_log_path)
    return any(
        isinstance(ev, dict) and _json_has_tool_name(ev, tool_name)
        for ev in _iter_json_lines(raw_log_path)
    )


def extract_text(backend: str, raw_log_path: str) -> str:
    """Pull the assistant's text from a raw transcript.

    Returns the empty string on:
      - empty / missing-content transcript
      - log file unreadable (caller distinguishes via separate check)

    Raises FileNotFoundError when <raw_log_path> does not exist — the
    bash shim translates this to rc=1 to match the prior contract.
    """
    if not os.path.isfile(raw_log_path):
        raise FileNotFoundError(raw_log_path)

    pieces: list[str] = []

    if backend == "claude":
        # Two text sources in a stream-json transcript: per-turn
        # assistant messages (.message.content[].text) and the trailing
        # result event (.result). The result event echoes the final
        # assistant turn *verbatim* — collecting both double-counts
        # every line the agent emitted (e.g. recon hypotheses parsed
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
        # `-r` semantics: each value on its own line. The bash version
        # uses `jq -r` which puts each emitted value on a new line.
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
            # structured replies such as recon JSONL (`{"id":...}` split
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
    from collections import deque

    tail: deque = deque(maxlen=max(1, tail_lines))
    try:
        with open(raw_log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.rstrip("\n")
                if line.strip():
                    tail.append(line)
    except OSError:
        return False
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


# ── CLI dispatch (used by the bash shim) ────────────────────────────


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
        ))
    except ValueError:
        return 1


def _cmd_decide_flags(args) -> int:
    try:
        return _print_flags(decide_flags(
            args.backend,
            model=args.model or "",
        ))
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


def _cmd_raw_has_tool(args) -> int:
    try:
        return 0 if raw_has_tool(args.raw_log, args.tool_name) else 1
    except FileNotFoundError:
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
    # and print its path so the bash entry point can export GEMINI_CLI_HOME.
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

    s = sub.add_parser("raw-has-tool")
    s.add_argument("raw_log")
    s.add_argument("tool_name")
    s.set_defaults(func=_cmd_raw_has_tool)

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
