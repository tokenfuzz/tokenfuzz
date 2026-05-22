#!/usr/bin/env python3
"""Shared backend-flag picker and assistant-text extractor.

Single source of truth for the four LLM backends the harness drives —
claude / codex / oss (codex --oss) / gemini. The `gemini` backend keeps
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
      Print the project's default model name for <backend> (honouring
      CLAUDE_MODEL_DEFAULT / CODEX_MODEL_DEFAULT / GEMINI_MODEL_DEFAULT /
      CODEX_OSS_MODEL_DEFAULT). Exit 1 on unknown backend.

  agent-flags <backend> [--model …] [--max-turns N] [--add-dirs CSV]
      Print the agent-mode flag list, one flag per line. Used for
      interactive tool-using agent calls (stream-json, sandbox bypass,
      --add-dir / --cd wiring).

  decide-flags <backend> [--model …]
      Print the decide-mode flag list (text output, no tools, read-only
      sandbox). One flag per line.

  extract-text <backend> <raw_log_path>
      Stream the assistant's natural-language text from a raw transcript
      to stdout. Per-backend: claude (.message.content[].text, with
      .result as fallback only), codex (item.completed/agent_message),
      gemini (agy plain stdout, or Gemini CLI stream-json assistant text).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


_KNOWN_BACKENDS = ("claude", "codex", "oss", "gemini")


def known_backend(backend: str) -> bool:
    return backend in _KNOWN_BACKENDS


def use_gemini_cli() -> bool:
    """Return true when the gemini backend should invoke Google Gemini CLI."""
    return os.environ.get("USE_GEMINI_CLI", "").strip() == "1"


def gemini_default_bin() -> str:
    return "gemini" if use_gemini_cli() else "agy"


def default_model(backend: str) -> str:
    """Echo the project-wide default model for <backend>.

    Env overrides win when set (matches the bash shim's per-invocation
    export). Raises ValueError on unknown backend.
    """
    if backend == "claude":
        return os.environ.get("CLAUDE_MODEL_DEFAULT") or "claude-opus-4-7"
    if backend == "codex":
        return os.environ.get("CODEX_MODEL_DEFAULT") or "gpt-5.5"
    if backend == "gemini":
        return os.environ.get("GEMINI_MODEL_DEFAULT") or "gemini-3.1-pro-preview"
    if backend == "oss":
        return os.environ.get("CODEX_OSS_MODEL_DEFAULT") or ""
    raise ValueError(f"unknown backend: {backend}")


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
    resolved_model = model or default_model(backend)

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

    if backend in ("codex", "oss"):
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
        if backend == "oss":
            flags = ["--oss", "--local-provider", "ollama", *flags]
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
            for d in (add_dirs or "").split(","):
                d = d.strip()
                if d:
                    flags += ["--include-directories", d]
            return flags

        # Antigravity CLI (agy): plain stdout in --print mode.
        # --dangerously-skip-permissions keeps the run non-interactive.
        # Model selection is currently managed by agy's persistent /model
        # setting, not a launch-time flag.
        flags = ["--dangerously-skip-permissions"]
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
    resolved_model = model or default_model(backend)

    if backend == "claude":
        flags = ["--print", "--max-turns", "1", "--output-format", "text"]
        if resolved_model:
            flags += ["--model", resolved_model]
        return flags

    if backend in ("codex", "oss"):
        flags = ["--ephemeral", "--skip-git-repo-check", "--sandbox", "read-only"]
        if resolved_model:
            flags += ["--model", resolved_model]
        if backend == "oss":
            flags = ["--oss", "--local-provider", "ollama", *flags]
        return flags

    if backend == "gemini":
        if use_gemini_cli():
            # Plan mode is Gemini CLI's read-only approval mode, matching
            # decide calls' single-shot/no-write contract.
            flags = ["--approval-mode=plan", "--skip-trust"]
            if resolved_model:
                flags += ["--model", resolved_model]
            return flags

        # Antigravity CLI (agy) decide mode: --print emits plain text.
        # --dangerously-skip-permissions keeps decide calls non-interactive.
        # Model selection is currently managed by agy's persistent /model
        # setting, not a launch-time flag.
        return ["--dangerously-skip-permissions"]

    raise ValueError(f"unknown backend: {backend}")


# ── Assistant-text extraction ───────────────────────────────────────


def _iter_json_lines(raw_log_path: str):
    """Yield JSON objects from a raw transcript, tolerating non-JSON lines.

    Some CLIs interleave stream-json lines with stderr banner output.
    The bash version uses `jq -R … fromjson?` to drop those; we mirror
    by simply skipping any line that doesn't parse.
    """
    try:
        with open(raw_log_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if not line.startswith(("{", "[")):
                    continue
                try:
                    yield json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
    except OSError:
        return


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

    if backend in ("codex", "oss"):
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


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="llm_invoke")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("known-backend")
    s.add_argument("backend")
    s.set_defaults(func=_cmd_known_backend)

    s = sub.add_parser("default-model")
    s.add_argument("backend")
    s.set_defaults(func=_cmd_default_model)

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

    return p


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
