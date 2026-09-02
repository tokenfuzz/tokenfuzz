#!/usr/bin/env python3
"""Regression tests for lib/llm_invoke.py.

The audit and benchmark runners delegate backend launches to this module.
This file exercises focused Python-level behavior for
each subcommand (and the importable API used by lib/llm_decide.py).
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import signal
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "lib" / "llm_invoke.py"

# The default assertions below are for the existing agy dialect. Keep the
# test process insulated from a developer shell that happens to export the
# Gemini CLI switch.
os.environ.pop("USE_GEMINI_CLI", None)
# Cross-run memory defaults to OFF when the switch is unset; clear any
# developer-shell value so the default-off assertions are deterministic.
os.environ.pop("TOKENFUZZ_MEMORY_ENABLED", None)
for key in (
    "CLAUDE_MODEL_DEFAULT",
    "CODEX_MODEL_DEFAULT",
    "GEMINI_MODEL_DEFAULT",
    "GROK_MODEL_DEFAULT",
    "AUDIT_LOCAL_BASE_URL",
    "AUDIT_LOCAL_API_KEY",
):
    os.environ.pop(key, None)

sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "lib"))
import llm_invoke as inv  # noqa: E402
from python_test_helpers import invoke_main  # noqa: E402

PASSED = 0
FAILED = 0


def ok(cond, name, detail=""):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        FAILED += 1
        print(f"  \033[0;31m✗\033[0m {name}")
        if detail:
            print(f"    {detail}")


def assert_eq(expected, actual, name):
    ok(expected == actual, name, f"expected={expected!r} actual={actual!r}")


def run(args, env=None, check=False, process_boundary=False):
    child_env = env if env is not None else os.environ.copy()
    if process_boundary:
        proc = subprocess.run(
            [sys.executable, str(HELPER), *args],
            capture_output=True, text=True, env=child_env,
        )
        if check and proc.returncode != 0:
            raise AssertionError(
                f"helper failed rc={proc.returncode}: {proc.stderr}",
            )
        return proc
    stdout = io.StringIO()
    stderr = io.StringIO()
    with mock.patch.dict(os.environ, child_env, clear=True):
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            returncode = invoke_main(inv.main, args, argv0=str(HELPER))
    proc = subprocess.CompletedProcess(
        [str(HELPER), *args], returncode, stdout.getvalue(), stderr.getvalue(),
    )
    if check and proc.returncode != 0:
        raise AssertionError(f"helper failed rc={proc.returncode}: {proc.stderr}")
    return proc


def flags(proc):
    return [line for line in proc.stdout.splitlines() if line]


# ── known-backend ───────────────────────────────────────────────────
print("known-backend")
for b in ("claude", "codex", "oss", "gemini", "grok"):
    assert_eq(
        0,
        run(["known-backend", b]).returncode,
        f"{b} → rc=0",
    )
assert_eq(
    1,
    run(["known-backend", "openai"], process_boundary=True).returncode,
    "openai → rc=1",
)
assert_eq(1, run(["known-backend", ""]).returncode, "empty → rc=1")


# ── default-model ───────────────────────────────────────────────────
print("\ndefault-model")
proc = run(["default-model", "claude"], check=True)
assert_eq("claude-opus-5", proc.stdout.strip(), "claude default")
proc = run(["default-model", "codex"], check=True)
assert_eq("gpt-5.6-sol", proc.stdout.strip(), "codex default")
proc = run(["default-model", "gemini"], check=True)
assert_eq("gemini-3.7-flash", proc.stdout.strip(), "gemini default")
proc = run(["default-model", "grok"], check=True)
assert_eq("grok-4.6", proc.stdout.strip(), "grok default")
assert_eq(1, run(["default-model", "openai"]).returncode, "unknown → rc=1")

for backend in ("claude", "codex", "gemini", "grok"):
    proc = run(["default-effort", backend], check=True)
    assert_eq("high", proc.stdout.strip(), f"{backend} default effort")

# Env override
env = os.environ.copy()
env["CLAUDE_MODEL_DEFAULT"] = "claude-opus-9-9"
proc = run(["default-model", "claude"], env=env, check=True)
assert_eq("claude-opus-9-9", proc.stdout.strip(), "CLAUDE_MODEL_DEFAULT override honoured")
env = os.environ.copy()
env["GEMINI_MODEL_DEFAULT"] = "gemini-3.1-flash-lite-high"
proc = run(["default-model", "gemini"], env=env, check=True)
assert_eq("gemini-3.1-flash-lite-high", proc.stdout.strip(), "GEMINI_MODEL_DEFAULT override honoured")
env = os.environ.copy()
env["GROK_MODEL_DEFAULT"] = "custom-grok"
proc = run(["default-model", "grok"], env=env, check=True)
assert_eq("custom-grok", proc.stdout.strip(), "GROK_MODEL_DEFAULT override honoured")

env = os.environ.copy()
env["USE_GEMINI_CLI"] = "1"
env.pop("GEMINI_MODEL_DEFAULT", None)
proc = run(["default-model", "gemini"], env=env, check=True)
assert_eq("gemini-3.7-flash", proc.stdout.strip(), "Gemini CLI dialect defaults model to 3.7 flash")


# ── agent-flags ─────────────────────────────────────────────────────
print("\nagent-flags")
proc = run(["agent-flags", "claude"], check=True)
f = flags(proc)
ok("--print" in f, "claude has --print", f)
ok("stream-json" in f, "claude has stream-json")
assert_eq("WebFetch,WebSearch", f[f.index("--disallowedTools") + 1],
          "claude agent removes the web tools outright; delegation stays at the CLI default")
bypass = inv.agent_flags("claude", agent_security="external-bypass")
assert_eq("WebFetch,WebSearch", bypass[bypass.index("--disallowedTools") + 1],
          "claude external-bypass launch denies web too (it carries no settings deny)")
ok("--dangerously-skip-permissions" not in f, "claude sandboxed mode omits skip-permissions")
assert_eq("dontAsk", f[f.index("--permission-mode") + 1], "claude never blocks on a prompt")
claude_settings = json.loads(f[f.index("--settings") + 1])
ok(claude_settings["sandbox"]["enabled"] is True, "claude enables its native sandbox")
ok(claude_settings["sandbox"]["failIfUnavailable"] is True, "claude sandbox fails closed")
ok(claude_settings["sandbox"]["allowUnsandboxedCommands"] is False,
   "claude denies sandbox escape requests")
ok(claude_settings["sandbox"]["network"]["allowLocalBinding"] is True,
   "claude keeps loopback harnesses runnable while egress stays blocked")
ok(claude_settings["permissions"]["deny"] == ["WebFetch", "WebSearch"],
   "claude denies web tools, the one rule a permission mode still enforces")
# Without this, dontAsk denies whatever the rules leave undecided. A
# `;`-chained command lands there, so read-only harness tools were denied
# while the same tool ran unchained. The sandbox keys above are the boundary.
ok(claude_settings["permissions"]["allow"] == ["Bash"],
   "claude allows Bash alone so dontAsk cannot deny what the sandbox permits")
# The sandbox arbitrates Bash; Write/Edit answer to the permission system
# alone, so allowing them bare would grant file access anywhere on the host.
for tool in ("Read", "Write", "Edit", "Glob", "Grep"):
    ok(tool not in claude_settings["permissions"]["allow"],
       f"claude never blanket-allows {tool}: no sandbox confines that tool")
ok("--max-turns" in f, "claude has --max-turns")
ok("80" in f, "claude default max-turns 80")
ok("claude-opus-5" in f, "claude default model wired")
assert_eq("high", f[f.index("--effort") + 1], "claude agent wires configured effort")

proc = run(["agent-flags", "codex"], check=True)
f = proc.stdout
ok("--json" in f, "codex has --json", f)
ok("workspace-write" in f, "codex uses its workspace-write sandbox")
ok("--dangerously-bypass-approvals-and-sandbox" not in f, "codex omits the bypass flag")
ok('approval_policy="never"' in f, "codex runs non-interactively without approval prompts")
ok('model_reasoning_effort="high"' in f, "codex agent wires configured effort")
ok("project_root_markers=[]" in f,
   "codex agent stops project instruction discovery at --cd")
ok('web_search="disabled"' in f,
   "codex agent denies web search like every other backend's agent launch (its default is on)")
ok("features.multi_agent=false" not in f,
   "codex agent keeps the CLI's default delegation; only a bounded validator turns it off")
guide_bytes = (ROOT / "AGENTS.md").stat().st_size
ok(guide_bytes < 32768,
   "AGENTS.md stays under codex's default 32 KiB project-doc cap, so a cold "
   "codex session's auto-loaded guide is never truncated",
   f"{guide_bytes} bytes")

with mock.patch.dict(os.environ, {"USE_GEMINI_CLI": "0"}):
    agy = inv.agent_flags("gemini")
    ok("--disable-slash-commands" in agy,
       "agy agent turns operator skill expansion off (parity with claude --safe-mode, codex plugins off, gemini-cli skills off)")
    ok("--disable-slash-commands" in inv.decide_flags("gemini"),
       "agy decide turns operator skill expansion off too")
with mock.patch.dict(os.environ, {"USE_GEMINI_CLI": "1"}):
    dec = inv.decide_flags("gemini")
    ok(any(dec[i + 1].endswith("gemini-no-web.policy.toml")
           for i, x in enumerate(dec) if x == "--admin-policy"),
       "gemini-cli decide loads the no-web policy like its agent launch")
with mock.patch.dict(os.environ, {"USE_GEMINI_CLI": "1", "TOKENFUZZ_MEMORY_ENABLED": "1"}):
    cli = inv.agent_flags("gemini")
    policies = [cli[i + 1] for i, x in enumerate(cli) if x == "--admin-policy"]
    ok(any(p.endswith("gemini-no-web.policy.toml") for p in policies),
       "gemini-cli agent denies web tools even with memory enabled")
    ok(not any(p.endswith("gemini-no-memory.policy.toml") for p in policies),
       "gemini-cli memory policy stays conditional on the memory setting")
ok(inv.opencode_config("m", "external-bypass").get("permission") == {"webfetch": "deny", "websearch": "deny"},
   "oss agent launch (external-bypass) denies web like every other backend")
ok(inv.opencode_config("m", "sandboxed").get("permission", {}).get("external_directory") == "deny",
   "oss sandboxed decide config keeps its full deny set")
proc = run(["agent-flags", "oss"], check=True)
f = flags(proc)
assert_eq(
    ["run", "--pure", "--auto", "--format", "json"],
    f,
    "oss agent flags do not invent a model when none is supplied",
)

proc = run(["agent-flags", "oss", "--model", "qwen3-8b"], check=True)
f = flags(proc)
assert_eq("local/qwen3-8b", f[f.index("--model") + 1], "oss model uses shared local provider ref for vLLM")
ok("--auto" in f, "oss uses OpenCode's current auto-approval flag")

proc = run(["agent-flags", "oss", "--model", "qwen3:8b"], check=True)
f = flags(proc)
assert_eq("local/qwen3:8b", f[f.index("--model") + 1], "oss model uses shared local provider ref for colon-tagged models")

proc = run(["agent-flags", "oss", "--model", "org/qwen3-8b"], check=True)
f = flags(proc)
assert_eq("local/org/qwen3-8b", f[f.index("--model") + 1], "oss keeps slash-bearing served model ids on the local provider")

proc = run(["agent-flags", "oss", "--model", "opencode/x-preview-f-free"], check=True)
f = flags(proc)
assert_eq("opencode/x-preview-f-free", f[f.index("--model") + 1], "oss passes OpenCode built-in model refs through")

proc = run(["local-base-url"], check=True)
assert_eq("http://127.0.0.1:8000/v1", proc.stdout.strip(), "oss vLLM default base URL includes /v1")

env = os.environ.copy()
env["AUDIT_LOCAL_BASE_URL"] = "127.0.0.1:9999"
proc = run(["local-base-url"], env=env, check=True)
assert_eq("http://127.0.0.1:9999/v1", proc.stdout.strip(), "oss generic local base URL overrides provider defaults")

env = os.environ.copy()
env["AUDIT_LOCAL_BASE_URL"] = "127.0.0.1:11434"
proc = run(["local-base-url"], env=env, check=True)
assert_eq("http://127.0.0.1:11434/v1", proc.stdout.strip(), "oss Ollama-style bare host base URL gains /v1")

env = os.environ.copy()
env["AUDIT_LOCAL_BASE_URL"] = "127.0.0.1:8000"
proc = run(["opencode-config", "--model", "qwen3-8b"], env=env, check=True)
cfg = json.loads(proc.stdout)
assert_eq(
    "http://127.0.0.1:8000/v1",
    cfg["provider"]["local"]["options"]["baseURL"],
    "oss OpenCode config uses normalized vLLM base URL",
)
ok(cfg["permission"]["external_directory"] == "deny",
   "oss sandboxed config denies external directories")
ok(cfg["permission"]["webfetch"] == "deny",
   "oss sandboxed config denies web fetch tools")

proc = run(["opencode-config", "--model", "opencode/x-preview-f-free"], check=True)
cfg = json.loads(proc.stdout)
ok("provider" not in cfg,
   "oss built-in model config does not shadow OpenCode's provider")
ok(cfg["permission"]["external_directory"] == "deny",
   "oss built-in model decisions retain external-directory denies")

proc = run(["agent-flags", "gemini"], check=True)
f = flags(proc)
ok("--dangerously-skip-permissions" in f,
   "agy has one usable mode: its sandbox cannot write a workspace")
ok("--sandbox" not in f, "agy omits a sandbox that denies the audit its own tree")
# agy 1.0.5+ pins the model via its `agy models` display label, mapped from
# the config slug — it resolves labels, not API slugs.
model_idx = f.index("--model")
assert_eq("Gemini 3.7 Flash (High)", f[model_idx + 1], "gemini agy wires the mapped model label")
for legacy in ("--output-format", "--yolo", "--skip-trust"):
    ok(legacy not in f, f"gemini omits legacy gemini-cli flag {legacy}")

env = os.environ.copy()
env["USE_GEMINI_CLI"] = "1"
env.pop("GEMINI_MODEL_DEFAULT", None)
proc = run(["agent-flags", "gemini", "--add-dirs", "/a,/b"], env=env, check=True)
f = flags(proc)
ok("--approval-mode=yolo" in f, "Gemini CLI agent uses yolo approval mode")
ok("--sandbox" not in f,
   "Gemini CLI omits a sandbox that would mount only the launch directory")
ok("--skip-trust" in f, "Gemini CLI agent skips workspace trust prompt")
ok("--output-format" in f and "stream-json" in f, "Gemini CLI agent uses stream-json output")
model_idx = f.index("--model")
assert_eq("gemini-3.7-flash", f[model_idx + 1], "Gemini CLI agent uses launch-time model")
indices = [i for i, x in enumerate(f) if x == "--include-directories"]
assert_eq(2, len(indices), "Gemini CLI emits two --include-directories flags")
ok(f[indices[0] + 1] == "/a", "first Gemini CLI include dir = /a")
ok(f[indices[1] + 1] == "/b", "second Gemini CLI include dir = /b")
ok("--dangerously-skip-permissions" not in f, "Gemini CLI agent omits agy skip-permissions")

proc = run(["agent-flags", "grok", "--max-turns", "23"], check=True)
f = flags(proc)
ok("--sandbox" not in f, "Grok omits a profile that cannot contain a hostile tree")
ok("--permission-mode" not in f, "Grok skips a permission mode its CLI does not enforce")
ok("--disable-web-search" in f,
   "Grok disables web tools in every profile: no outer sandbox withholds them")
ok("streaming-json" in f, "Grok agent uses streaming JSON")
ok("--no-auto-update" in f, "Grok agent disables background updates")
ok("--no-subagents" not in f,
   "Grok harness agent keeps the CLI's default delegation, like claude and codex")
ok("--no-subagents" in inv.agent_flags("grok", allow_subagents=False),
   "a bounded Grok validator review turns delegation off, like claude and codex")
ok("--no-memory" in f, "Grok agent disables cross-run memory by default")
assert_eq("23", f[f.index("--max-turns") + 1], "Grok agent wires max turns")
assert_eq("grok-4.6", f[f.index("--model") + 1], "Grok agent wires default model")
assert_eq("high", f[f.index("--reasoning-effort") + 1], "Grok agent wires configured effort")

external = {
    "claude": "--dangerously-skip-permissions",
    "codex": "--dangerously-bypass-approvals-and-sandbox",
    "gemini": "--dangerously-skip-permissions",
    "grok": "--always-approve",
}
for backend, bypass_flag in external.items():
    proc = run([
        "agent-flags", backend,
        "--agent-security", "external-bypass",
    ], check=True)
    f = flags(proc)
    ok(bypass_flag in f,
       f"{backend} external-bypass preserves its explicit legacy bypass")
    ok("--sandbox" not in f or backend == "codex",
       f"{backend} external-bypass drops the native sandbox it replaces")

env = os.environ.copy()
env["TOKENFUZZ_AGENT_SECURITY"] = "external-bypass"
proc = run(["agent-flags", "claude"], env=env, check=True)
ok("--dangerously-skip-permissions" in flags(proc),
   "an unflagged launch inherits the profile its parent run selected")

assert_eq(1, run(["agent-flags", "openai"]).returncode, "unknown backend → rc=1")


# ── agent-flags add-dirs wiring ─────────────────────────────────────
print("\nadd-dirs wiring")
proc = run(["agent-flags", "claude", "--add-dirs", "/a,/b"], check=True)
f = flags(proc)
# Two --add-dir occurrences with /a then /b.
indices = [i for i, x in enumerate(f) if x == "--add-dir"]
assert_eq(2, len(indices), "claude emits two --add-dir flags")
ok(f[indices[0] + 1] == "/a", "first add-dir = /a")
ok(f[indices[1] + 1] == "/b", "second add-dir = /b")

proc = run(["agent-flags", "codex", "--add-dirs", "/a,/b"], check=True)
f = flags(proc)
# codex uses the first directory as --cd and grants the rest via --add-dir.
ok("--cd" in f, "codex has --cd")
cd_idx = f.index("--cd")
assert_eq("/a", f[cd_idx + 1], "codex --cd uses first add-dir")
indices = [i for i, x in enumerate(f) if x == "--add-dir"]
assert_eq(1, len(indices), "codex emits one --add-dir for the second dir")
ok(f[indices[0] + 1] == "/b", "codex grants second add-dir")

proc = run(["agent-flags", "grok", "--add-dirs", "/a,/b"], check=True)
f = flags(proc)
assert_eq("/a", f[f.index("--cwd") + 1], "grok --cwd uses first add-dir")

proc = run(["agent-flags", "gemini", "--add-dirs", "/a,/b"], check=True)
f = flags(proc)
indices = [i for i, x in enumerate(f) if x == "--add-dir"]
assert_eq(2, len(indices), "gemini emits two --add-dir flags")
ok(f[indices[0] + 1] == "/a", "first gemini add-dir = /a")
ok(f[indices[1] + 1] == "/b", "second gemini add-dir = /b")

# A benchmark cell reaches the target tree by symlink, and every backend sandbox
# matches its write rules against the resolved path: the facade spelling left
# Claude's target readable and unwritable, and Codex refuses to start any
# process while such a root is configured. Granting the resolved spelling alone
# is the one answer both accept. The per-backend matrix is asserted against the
# imported API below; this covers the CLI that renders it.
print("\nagent-flags grants the resolved spelling of a symlinked directory")
# Resolved up front: the platform temp root is itself a symlink on macOS, which
# would make even the non-symlinked control case resolve to something else.
_sandbox_tmp = Path(tempfile.mkdtemp(prefix="granted-dirs-")).resolve()
try:
    _real = _sandbox_tmp / "real"
    _real.mkdir()
    _facade = _sandbox_tmp / "facade"
    _facade.symlink_to(_real)
    proc = run(["agent-flags", "claude", "--add-dirs", str(_facade)], check=True)
    f = flags(proc)
    granted = [f[i + 1] for i, x in enumerate(f) if x == "--add-dir"]
    assert_eq([str(_real)], granted, "only the resolved target tree is granted")
    # An ordinary directory must not be granted twice.
    proc = run(["agent-flags", "claude", "--add-dirs", str(_real)], check=True)
    f = flags(proc)
    assert_eq(1, len([x for x in f if x == "--add-dir"]),
              "a path that is already resolved is granted once")
finally:
    shutil.rmtree(_sandbox_tmp, ignore_errors=True)


# ── decide-flags ────────────────────────────────────────────────────
print("\ndecide-flags")
proc = run(["decide-flags", "claude"], check=True)
f = flags(proc)
ok("--print" in f, "decide claude --print")
ok("--max-turns" not in f, "decide claude has no turn cap (timeout-bounded, like codex/gemini)")
assert_eq("WebFetch,WebSearch", f[f.index("--disallowedTools") + 1],
          "decide claude denies web: plan mode gates the filesystem, not egress")
ok(inv.prompt_cache_env("codex") == {}, "the cache tier is a no-op for codex")
with mock.patch.dict(os.environ, {}, clear=False):
    os.environ.pop("CLAUDE_CODE_PROMPT_CACHE_TTL", None)
    os.environ.pop("FORCE_PROMPT_CACHING_5M", None)
    assert_eq({"CLAUDE_CODE_PROMPT_CACHE_TTL": "5m"}, inv.prompt_cache_env("claude"),
              "claude launches bill the cheaper five-minute cache tier")
    assert_eq("5m", inv.invocation_env("claude").get("CLAUDE_CODE_PROMPT_CACHE_TTL"),
              "every claude invocation — session, validator, decision — carries the tier")
    ok("CLAUDE_CODE_PROMPT_CACHE_TTL" not in inv.invocation_env("codex"),
       "a codex invocation carries no Claude cache setting")
with mock.patch.dict(os.environ, {"CLAUDE_CODE_PROMPT_CACHE_TTL": "1h"}):
    assert_eq({}, inv.prompt_cache_env("claude"), "an operator's own cache TTL is respected")
with mock.patch.dict(os.environ, {"FORCE_PROMPT_CACHING_5M": "1"}):
    assert_eq({}, inv.prompt_cache_env("claude"), "an operator's legacy cache switch is respected")
assert_eq("json", f[f.index("--output-format") + 1],
          "decide claude asks for the usage-bearing envelope")
turns_idx = f.index("--permission-mode")
assert_eq("plan", f[turns_idx + 1], "decide claude uses read-only plan mode")
ok("--dangerously-skip-permissions" not in f, "decide claude omits skip-permissions (read-only, not full access)")
assert_eq("high", f[f.index("--effort") + 1], "decide claude wires configured effort")

proc = run(["decide-flags", "codex"], check=True)
f = proc.stdout
ok("read-only" in f, "decide codex read-only sandbox")
ok("danger-full-access" not in f, "decide codex NOT danger-full-access")
ok('model_reasoning_effort="high"' in f, "decide codex wires configured effort")
ok("project_root_markers=[]" in f,
   "decide codex stops project instruction discovery at cwd")
ok('web_search="disabled"' in f,
   "decide codex denies web search like every other harness launch")

proc = run(["decide-flags", "gemini"], check=True)
f = flags(proc)
ok("--dangerously-skip-permissions" in f, "Antigravity decision stays non-interactive")
ok("--sandbox" not in f and "--mode" not in f,
   "a decision claims no boundary agy would not enforce")
model_idx = f.index("--model")
assert_eq("Gemini 3.7 Flash (High)", f[model_idx + 1], "decide gemini agy wires the mapped model label")
for legacy in ("--output-format", "--approval-mode"):
    ok(legacy not in f, f"decide gemini omits legacy gemini-cli flag {legacy}")

env = os.environ.copy()
env["USE_GEMINI_CLI"] = "1"
env.pop("GEMINI_MODEL_DEFAULT", None)
proc = run(["decide-flags", "gemini"], env=env, check=True)
f = flags(proc)
ok("--approval-mode=plan" in f, "Gemini CLI decide uses plan approval mode")
ok("--skip-trust" in f, "Gemini CLI decide skips workspace trust prompt")
model_idx = f.index("--model")
assert_eq("gemini-3.7-flash", f[model_idx + 1], "Gemini CLI decide wires model")
ok("--dangerously-skip-permissions" not in f, "Gemini CLI decide omits agy skip-permissions")

proc = run(["decide-flags", "grok"], check=True)
f = flags(proc)
assert_eq("plan", f[f.index("--permission-mode") + 1], "Grok decide uses read-only plan mode")
ok("--disable-web-search" in f, "Grok decide denies web search like its agent launch")
ok("plain" in f, "Grok decide uses plain assistant output")
ok("--no-memory" in f, "Grok decide disables cross-run memory")
ok("--always-approve" not in f, "Grok decide does not allow writes")
assert_eq("high", f[f.index("--reasoning-effort") + 1], "decide Grok wires configured effort")


# ── extract-text per backend ────────────────────────────────────────
print("\nextract-text")
with tempfile.TemporaryDirectory() as td:
    p = Path(td)

    # claude — in a real stream-json transcript the trailing result
    # event echoes the final assistant turn verbatim. Extraction must
    # NOT emit it twice (would double-count every emitted row).
    (p / "claude.jsonl").write_text(
        '{"type":"system","subtype":"init"}\n'
        '{"type":"assistant","message":{"content":[{"type":"text","text":"hello from claude"}]}}\n'
        '{"type":"result","result":"hello from claude"}\n'
    )
    proc = run(["extract-text", "claude", str(p / "claude.jsonl")], check=True)
    ok("hello from claude" in proc.stdout, "claude .message.content[].text extracted")
    assert_eq(1, proc.stdout.count("hello from claude"),
              "claude result event does not double-count assistant text")

    # claude — result-only transcript (non-streaming output): with no
    # assistant message text, .result is used as the fallback source.
    (p / "claude-result-only.jsonl").write_text(
        '{"type":"system","subtype":"init"}\n'
        '{"type":"result","result":"final result"}\n'
    )
    proc = run(["extract-text", "claude", str(p / "claude-result-only.jsonl")], check=True)
    ok("final result" in proc.stdout, "claude .result extracted as fallback")

    # codex agent_message
    (p / "codex.jsonl").write_text(
        '{"type":"thread.started","thread_id":"abc"}\n'
        '{"type":"item.completed","item":{"id":"x","type":"agent_message",'
        '"text":"{\\"vote\\":\\"Reject\\",\\"rationale\\":\\"because X\\"}"}}\n'
        '{"type":"turn.completed"}\n'
    )
    proc = run(["extract-text", "codex", str(p / "codex.jsonl")], check=True)
    ok('"vote":"Reject"' in proc.stdout, "codex agent_message decoded")
    ok("because X" in proc.stdout, "codex rationale preserved")

    # oss/OpenCode assistant JSON content
    (p / "oss.jsonl").write_text(
        '{"type":"message","role":"assistant",'
        '"content":"{\\"vote\\":\\"Promote\\",\\"rationale\\":\\"opencode\\"}"}\n'
    )
    proc = run(["extract-text", "oss", str(p / "oss.jsonl")], check=True)
    ok('"vote":"Promote"' in proc.stdout, "oss assistant JSON content extracted")
    ok("opencode" in proc.stdout, "oss rationale preserved")

    # oss/OpenCode real `opencode run --format json` text event
    (p / "oss_text_event.jsonl").write_text(
        '{"type":"text","part":{"type":"text",'
        '"text":"{\\"smoke\\":true,\\"model\\":\\"qwen3.6-35b-a3b\\"}"}}\n'
    )
    proc = run(["extract-text", "oss", str(p / "oss_text_event.jsonl")], check=True)
    ok('"smoke":true' in proc.stdout, "oss text event content extracted")
    ok("qwen3.6-35b-a3b" in proc.stdout, "oss text event model preserved")

    # gemini — Antigravity CLI emits plain text on stdout; the entire
    # transcript IS the assistant reply.
    (p / "gemini.txt").write_text(
        '{"vote":"Promote","rationale":"agy plain print",'
        '"verified":{"reachability":true}}\n'
    )
    proc = run(["extract-text", "gemini", str(p / "gemini.txt")], check=True)
    try:
        parsed = json.loads(proc.stdout)
        ok(parsed.get("vote") == "Promote", "gemini plain JSON preserves vote")
        ok(parsed.get("verified", {}).get("reachability") is True,
           "nested object preserved through extract-text")
    except (json.JSONDecodeError, AttributeError):
        ok(False, "gemini plain stdout is parseable JSON",
           f"got: {proc.stdout!r}")

    env = os.environ.copy()
    env["USE_GEMINI_CLI"] = "1"
    (p / "gemini-cli.jsonl").write_text(
        '{"type":"init","session_id":"s"}\n'
        '{"type":"tool_use","tool_name":"run_shell_command","parameters":{"command":"pwd"}}\n'
        '{"type":"message","role":"assistant","content":"hello from gemini cli"}\n'
    )
    proc = run(["extract-text", "gemini", str(p / "gemini-cli.jsonl")], env=env, check=True)
    assert_eq("hello from gemini cli", proc.stdout, "Gemini CLI stream-json assistant text extracted")

    (p / "grok.jsonl").write_text(
        '{"type":"text","data":"{\\"vote\\":\\"Promote\\","}\n'
        '{"type":"text","data":"\\"rationale\\":\\"grok\\"}"}\n'
        '{"type":"end","stopReason":"EndTurn","sessionId":"session-1"}\n'
    )
    proc = run(["extract-text", "grok", str(p / "grok.jsonl")], check=True)
    assert_eq('{"vote":"Promote","rationale":"grok"}', proc.stdout,
              "Grok streaming JSON text deltas are reassembled")

    (p / "gemini-cli-deltas.jsonl").write_text(
        '{"type":"init","session_id":"s"}\n'
        '{"type":"message","role":"assistant","content":"{\\"id\\"","delta":true}\n'
        '{"type":"message","role":"assistant","content":":\\"REC-one\\",","delta":true}\n'
        '{"type":"message","role":"assistant","content":"\\"confidence\\":\\"NEEDS-VERIFICATION\\"}\\n","delta":true}\n'
        '{"type":"message","role":"assistant","content":"{\\"id\\":\\"REC-two\\",\\"confidence\\":\\"AUDIT-CLEAN\\"}","delta":true}\n'
    )
    proc = run(["extract-text", "gemini", str(p / "gemini-cli-deltas.jsonl")], env=env, check=True)
    lines = proc.stdout.splitlines()
    assert_eq(2, len(lines), "Gemini CLI stream-json deltas preserve JSONL line boundaries")
    assert_eq("REC-one", json.loads(lines[0])["id"], "Gemini CLI split JSON object is reassembled")
    assert_eq("REC-two", json.loads(lines[1])["id"], "Gemini CLI second JSONL row is preserved")

    # Empty log → empty stdout, rc=0
    (p / "empty.log").write_text("")
    proc = run(["extract-text", "claude", str(p / "empty.log")], check=True)
    assert_eq("", proc.stdout, "empty log → empty output")

    # Missing log → rc=1
    assert_eq(
        1, run(["extract-text", "claude", str(p / "nope.log")]).returncode,
        "missing log → rc=1",
    )


# ── Importable API used by lib/llm_decide.py ────────────────────────
print("\nimportable API")

with mock.patch.dict(os.environ, {}, clear=True):
    ok("native OS sandbox" in inv.agent_security_problem("oss", "sandboxed"),
       "OpenCode sandboxed audits fail closed because approvals are not isolation")
    assert_eq("external-bypass", inv.resolve_agent_security(None, "oss"),
              "an unflagged OpenCode launch picks the only profile it can run under")
    ok(inv.decide_flags("oss"),
       "a read-only decision carries no execution boundary and still runs")
    ok("child network" in inv.agent_security_problem("grok", "sandboxed"),
       "Grok is refused: its profiles leave reads and egress open on macOS")
    ok("mounts only the launch directory"
       in inv.agent_security_problem("gemini", "sandboxed"),
       "both Gemini dialects are refused: neither sandbox can host an audit")
    assert_eq(
        inv.agent_flags("gemini"),
        inv.agent_flags("gemini", agent_security="external-bypass"),
        "a backend with one usable mode builds one flag list",
    )
    # IS_SANDBOX is the operator's assertion, not a measurement, so its
    # absence advises rather than refuses; only capability facts refuse.
    assert_eq("", inv.agent_security_problem("codex", "external-bypass"),
              "an unasserted outer boundary does not refuse the launch")
    ok("IS_SANDBOX=1" in inv.agent_security_warning("external-bypass"),
       "an unasserted external bypass warns about what confines the agent")
    assert_eq("", inv.agent_security_warning("sandboxed"),
              "a CLI-sandboxed launch has nothing to warn about")
    inv._UNASSERTED_BYPASS_WARNED = False
    with mock.patch.object(sys, "stderr", new_callable=io.StringIO) as warnings:
        first = inv.warn_agent_security("external-bypass")
        second = inv.warn_agent_security("external-bypass")
    ok(first and second, "the advice is returned to every caller that asks")
    assert_eq(1, warnings.getvalue().count("WARN:"),
              "an audit's hundreds of launches print the advice once")
with mock.patch.dict(os.environ, {"IS_SANDBOX": "1"}, clear=True):
    assert_eq("", inv.agent_security_problem("codex", "external-bypass"),
              "an asserted boundary launches cleanly")
    assert_eq("", inv.agent_security_warning("external-bypass"),
              "an asserted outer boundary needs no advice")
with mock.patch.dict(
    os.environ, {inv.AGENT_SECURITY_ENV: "external-bypass"}, clear=True,
):
    assert_eq("external-bypass", inv.inherited_agent_security(),
              "child agent launches inherit the parent orchestration profile")
with mock.patch.dict(os.environ, {}, clear=True):
    assert_eq("external-bypass", inv.resolve_agent_security(None, "oss"),
              "an unasserted boundary advises rather than blocking the backend")
    assert_eq("sandboxed", inv.resolve_agent_security(None, "codex"),
              "native-sandbox backends retain the sandboxed default")
with mock.patch.dict(os.environ, {"IS_SANDBOX": "1"}, clear=True):
    assert_eq("external-bypass", inv.resolve_agent_security(None, "oss"),
              "OpenCode uses the asserted outer sandbox without a redundant flag")
with mock.patch.dict(
    os.environ, {inv.AGENT_SECURITY_ENV: "sandboxed"}, clear=True,
):
    assert_eq("sandboxed", inv.resolve_agent_security(None, "oss"),
              "an inherited profile overrides the OpenCode default")
import llm_decide as decide_mod  # noqa: E402

with tempfile.TemporaryDirectory() as td:
    isolated = Path(td) / "launch-root"
    isolated.mkdir()
    with mock.patch.dict(os.environ, {"PATH": "/tokenfuzz/no-git-here"}):
        inv.ensure_project_root(isolated)
    ok((isolated / ".git" / "objects" / "info").is_dir(),
       "project boundary creates standard metadata without Git")
    ok((isolated / ".git" / "HEAD").is_file(),
       "project boundary writes standard repository metadata")

with tempfile.TemporaryDirectory() as td:
    partial = Path(td) / "partial-root"
    (partial / ".git").mkdir(parents=True)
    inv.ensure_project_root(partial)
    ok(not (partial / ".git" / "HEAD").exists(),
       "project boundary leaves an existing marker untouched")

# A validator cwd links every target entry, including the checkout's own .git.
# Staging a boundary there must neither fail the launch — bin/validate-finding
# exit 1 is the Reject vote — nor write through the link into the target.
with tempfile.TemporaryDirectory() as td:
    checkout = Path(td) / "target"
    (checkout / ".git" / "refs").mkdir(parents=True)
    linked = Path(td) / ".validator-cwd"
    linked.mkdir()
    (linked / ".git").symlink_to(checkout / ".git", target_is_directory=True)
    inv.ensure_project_root(linked)
    ok(not (checkout / ".git" / "objects").exists(),
       "project boundary never writes through a symlinked marker")
    ok(not (checkout / ".git" / "HEAD").exists(),
       "project boundary leaves the audited checkout's repository intact")

with tempfile.TemporaryDirectory() as td:
    launch_root = Path(td)
    raw = launch_root / "raw.jsonl"

    def capture_rollover(backend, binary, cap, *, gemini_cli=False):
        raw.touch()
        with mock.patch.dict(
            os.environ, {"USE_GEMINI_CLI": "1" if gemini_cli else "0"},
        ), mock.patch.object(
            inv, "backend_bin", return_value=binary,
        ), mock.patch.object(
            inv, "_run_agent_process", return_value=0,
        ) as process, mock.patch.object(
            inv, "agent_security_problem", return_value="",
        ):
            inv.run_agent_prompt(
                backend, "prompt", 0, raw, model="fixture-model", max_turns=999,
                turn_cap=cap, cwd=launch_root,
            )
        return process.call_args.args[0], process.call_args.kwargs

    command, kwargs = capture_rollover("claude", "claude", 17)
    assert_eq(
        "17", command[command.index("--max-turns") + 1],
        "audit rollover uses Claude's native cap, not a looser hidden ceiling",
    )
    ok(
        kwargs["turn_cap"] == 0 and kwargs["checkpoint_on_native_limit"],
        "Claude native cap avoids kill-based transcript polling",
        repr(kwargs),
    )

    dropped = launch_root / "dropped.raw"

    def _write_dropped(*_args, **_kwargs):
        dropped.write_text(
            "Security Warning: Ignoring --admin-policy because system policies "
            "are already defined in /etc/gemini-cli/policies\n",
            encoding="utf-8",
        )
        return 0

    dropped_stderr = io.StringIO()
    with mock.patch.dict(os.environ, {"USE_GEMINI_CLI": "1"}), mock.patch.object(
        inv, "backend_bin", return_value="gemini",
    ), mock.patch.object(
        inv, "_run_agent_process", side_effect=_write_dropped,
    ), mock.patch.object(
        inv, "agent_security_problem", return_value="",
    ), contextlib.redirect_stderr(dropped_stderr):
        rc = inv.run_agent_prompt(
            "gemini", "prompt", 0, dropped, model="fixture-model", cwd=launch_root,
            agent_security="external-bypass",
        )
    assert_eq(46, rc,
              "a gemini-cli launch whose admin policies were dropped fails loudly "
              "(memory and web denies went with them), so a benchmark cell is not a measurement")
    ok("ignored the harness admin policies" in dropped_stderr.getvalue(),
       "the dropped-policy failure names its cause on stderr")

    command, kwargs = capture_rollover("grok", "grok", 17)
    assert_eq(
        "17", command[command.index("--max-turns") + 1],
        "Grok audit rollover uses the same native cap",
    )
    ok(
        kwargs["turn_cap"] == 0 and kwargs["checkpoint_on_native_limit"],
        "Grok native cap avoids kill-based transcript polling",
        repr(kwargs),
    )

    _command, kwargs = capture_rollover("codex", "codex", 17)
    ok(
        kwargs["turn_cap"] == 17 and not kwargs["checkpoint_on_native_limit"],
        "Codex uses the completed-tool watchdog at the same rollover target",
        repr(kwargs),
    )

    for backend, binary, gemini_cli in (
        ("oss", "opencode", False),
        ("gemini", "gemini", True),
    ):
        _command, kwargs = capture_rollover(
            backend, binary, 17, gemini_cli=gemini_cli,
        )
        ok(
            kwargs["turn_cap"] == 17
            and kwargs["checkpoint_on_native_limit"] == (backend == "gemini"),
            (
                "Gemini CLI uses its native ceiling with a completed-tool fallback"
                if backend == "gemini"
                else "OpenCode uses the completed-tool watchdog"
            ),
            repr(kwargs),
        )

    _command, kwargs = capture_rollover("gemini", "agy", 17)
    ok(
        kwargs["turn_cap"] == 0 and not kwargs["checkpoint_on_native_limit"],
        "Antigravity does not treat undocumented step updates as a safe turn counter",
        repr(kwargs),
    )

    command, kwargs = capture_rollover("claude", "claude", 0)
    ok(
        "--max-turns" not in command
        and kwargs["turn_cap"] == 0
        and not kwargs["checkpoint_on_native_limit"],
        "TURN_SOFT_CAP=0 disables both native and transcript limits",
        repr((command, kwargs)),
    )

    with mock.patch.object(
        inv, "backend_bin", return_value="codex",
    ), mock.patch.object(
        inv, "_run_agent_process", return_value=0,
    ) as guarded_process:
        inv.run_agent_prompt(
            "codex", "prompt", 0, raw, cwd=launch_root,
            extra_env={"PATH": "/fixture/bin"},
        )
    guarded_env = guarded_process.call_args.args[4]
    ok("CLAUDE_CODE_PROMPT_CACHE_TTL" not in guarded_env,
       "a codex launch carries no Claude cache-tier setting")
    with mock.patch.dict(os.environ, {}, clear=False), mock.patch.object(
        inv, "backend_bin", return_value="claude",
    ), mock.patch.object(
        inv, "_run_agent_process", return_value=0,
    ) as claude_process, mock.patch.object(
        inv, "agent_security_problem", return_value="",
    ):
        os.environ.pop("CLAUDE_CODE_PROMPT_CACHE_TTL", None)
        os.environ.pop("FORCE_PROMPT_CACHING_5M", None)
        inv.run_agent_prompt("claude", "prompt", 0, raw, cwd=launch_root)
    assert_eq(
        "5m", claude_process.call_args.args[4].get("CLAUDE_CODE_PROMPT_CACHE_TTL"),
        "a claude agent launch bills the five-minute cache tier",
    )
    wrappers = str(ROOT / "lib" / "wrappers")
    guards = str(ROOT / "lib" / "agent_shell_guards")
    ok(
        guarded_env["PATH"].split(os.pathsep)[0] == guards,
        "every tool-using agent launch puts process guards first in PATH",
        guarded_env["PATH"],
    )
    ok(
        wrappers not in guarded_env["PATH"].split(os.pathsep)
        and "AGENT_WRAPPERS_PATH" not in guarded_env,
        "a direct launch does not inherit TokenFuzz audit wrappers",
        repr(guarded_env),
    )
    assert_eq(
        guards, guarded_env["AGENT_SHELL_GUARDS_PATH"],
        "agent launch exports the process guard directory",
    )
    assert_eq(
        str(ROOT / "lib" / "agent_shell_guards" / "_zdotdir"),
        guarded_env["ZDOTDIR"],
        "agent launch exports the guard-only login-shell bootstrap",
    )

    # A benchmark cell points AGENT_WRAPPERS_PATH at its facade so the agent
    # sees its own repo root. The process guards remain first, followed by the
    # explicitly opted-in audit wrappers.
    with mock.patch.object(
        inv, "backend_bin", return_value="codex",
    ), mock.patch.object(
        inv, "_run_agent_process", return_value=0,
    ) as facade_process:
        inv.run_agent_prompt(
            "codex", "prompt", 0, raw, cwd=launch_root,
            extra_env={"PATH": "/fixture/bin",
                       "AGENT_WRAPPERS_PATH": "/facade/lib/wrappers"},
        )
    facade_env = facade_process.call_args.args[4]
    assert_eq(
        guards, facade_env["PATH"].split(os.pathsep)[0],
        "process guards lead an audit agent PATH",
    )
    assert_eq(
        "/facade/lib/wrappers", facade_env["PATH"].split(os.pathsep)[1],
        "an explicitly configured audit wrapper directory follows guards",
    )
    assert_eq(
        "/facade/lib/wrappers", facade_env["AGENT_WRAPPERS_PATH"],
        "audit launch exports only its explicitly configured wrapper directory",
    )
    assert_eq(
        str(ROOT / "lib" / "agent_shell_guards" / "_zdotdir"),
        facade_env["ZDOTDIR"],
        "audit launch uses the shared guard bootstrap",
    )

    inherited_env = {
        "PATH": os.pathsep.join((wrappers, "/fixture/bin")),
        "AGENT_WRAPPERS_PATH": wrappers,
    }
    inv._apply_agent_shell_environment(inherited_env)
    ok(
        wrappers not in inherited_env["PATH"].split(os.pathsep)
        and "AGENT_WRAPPERS_PATH" not in inherited_env,
        "ambient audit wrapper state cannot contaminate model-direct",
        repr(inherited_env),
    )

with tempfile.TemporaryDirectory() as td, \
        mock.patch.dict(os.environ, {
            "SCRIPT_ROOT": td,
            "GEMINI_BIN": "/fake/agy",
        }, clear=False), \
        mock.patch.object(decide_mod, "_which", return_value="/fake/agy"), \
        mock.patch.object(
            decide_mod, "run_timeout",
            return_value=SimpleNamespace(returncode=0, stdout="ok", stderr=""),
        ) as agy_run:
    os.environ.pop("USE_GEMINI_CLI", None)
    assert_eq("ok", decide_mod._invoke_backend("gemini", "DECISION_PROMPT", 5),
              "Antigravity decision invocation succeeds")
    agy_command = agy_run.call_args.args[0]
    assert_eq("DECISION_PROMPT", agy_command[agy_command.index("-p") + 1],
              "Antigravity decision passes a non-empty -p value")
    ok(agy_run.call_args.kwargs["input"] is None,
       "Antigravity decision does not duplicate the prompt on stdin")
    assert_eq(Path(td), agy_run.call_args.kwargs["cwd"],
              "Antigravity decision is rooted at SCRIPT_ROOT")

with mock.patch.dict(os.environ, {"MODEL": "qwen3-8b"}, clear=True), \
        mock.patch.object(decide_mod, "_which", return_value="/fake/opencode"), \
        mock.patch.object(
            decide_mod, "run_timeout",
            return_value=SimpleNamespace(returncode=0, stdout="ok", stderr=""),
        ) as oss_decide_run:
    assert_eq("ok", decide_mod._invoke_backend("oss", "DECISION_PROMPT", 5),
              "an OpenCode decision reads source without asserting a sandbox")
    oss_config = json.loads(
        oss_decide_run.call_args.kwargs["env"]["OPENCODE_CONFIG_CONTENT"]
    )
    assert_eq("deny", oss_config["permission"]["webfetch"],
              "an OpenCode decision still runs under the sandboxed denies")

# A decision timeout must reap the backend's whole process tree. Backend CLIs
# may launch helpers; killing only the direct process leaves those helpers
# consuming CPU after the decision has already failed open.
with tempfile.TemporaryDirectory() as td:
    directory = Path(td)
    child_pid = directory / "child.pid"
    backend = directory / "backend.py"
    backend.write_text(
        "#!/usr/bin/env python3\n"
        "import os, subprocess, sys, time\n"
        "subprocess.Popen([sys.executable, '-c', "
        "\"import os,time;open(os.environ['CHILD_PID'],'w').write(str(os.getpid()));time.sleep(10)\"], "
        "env=os.environ.copy())\n"
        "time.sleep(10)\n",
        encoding="utf-8",
    )
    backend.chmod(0o755)
    timed_out = False
    leaked_pid = 0
    try:
        with mock.patch.dict(os.environ, {
            "CODEX_BIN": str(backend), "CHILD_PID": str(child_pid),
        }, clear=False):
            decide_mod._invoke_backend("codex", "PROMPT", 1)
    except subprocess.TimeoutExpired:
        timed_out = True
    if child_pid.is_file():
        leaked_pid = int(child_pid.read_text())
    deadline = time.monotonic() + 2
    while leaked_pid and time.monotonic() < deadline:
        try:
            os.kill(leaked_pid, 0)
        except ProcessLookupError:
            leaked_pid = 0
            break
        time.sleep(0.05)
    if leaked_pid:
        os.kill(leaked_pid, signal.SIGKILL)
    ok(timed_out, "decision process-tree wrapper preserves TimeoutExpired semantics")
    ok(not leaked_pid, "decision timeout reaps backend descendants")

with tempfile.TemporaryDirectory() as td:
    for backend in ("grok", "gemini"):
        launch_root = Path(td) / backend
        launch_root.mkdir()
        raw = launch_root / "raw.log"
        with mock.patch.object(inv, "backend_bin", return_value=f"/fake/{backend}"), \
                mock.patch.object(
                    inv.subprocess, "run",
                    return_value=SimpleNamespace(returncode=0),
                ), mock.patch.object(
                    inv, "agent_security_problem", return_value="",
                ):
            assert_eq(
                0,
                inv.run_agent_prompt(
                    backend, "PROMPT", 0, raw,
                    add_dirs=str(launch_root), cwd=launch_root,
                ),
                f"{backend} agent launch succeeds",
            )
        ok((launch_root / ".git" / "HEAD").is_file(),
           f"{backend} agent launch stages its project boundary")

# Raise site: an unusable launch boundary becomes a _LaunchPreparationError (not
# the CalledProcessError a backend non-zero exit raises), and the backend never
# runs — so the handler below can tell a local setup failure apart from a storm.
with tempfile.TemporaryDirectory() as td, \
        mock.patch.dict(os.environ, {"SCRIPT_ROOT": td}, clear=False), \
        mock.patch.object(decide_mod, "_which", return_value="/fake/grok"), \
        mock.patch.object(
            decide_mod, "_ensure_project_root",
            side_effect=OSError("read-only root"),
        ), mock.patch.object(decide_mod, "run_timeout") as prep_run:
    prep_raised = False
    try:
        decide_mod._invoke_backend("grok", "PROMPT", 5)
    except decide_mod._LaunchPreparationError:
        prep_raised = True
    ok(prep_raised, "an unusable launch boundary raises _LaunchPreparationError")
    ok(not prep_run.called,
       "the backend never runs after a launch-boundary failure")

# Handler: that local failure returns no verdict without arming the backend breaker.
with mock.patch.dict(os.environ, {"ACTIVE_BACKEND": "grok"}, clear=False), \
        mock.patch.object(
            decide_mod, "_invoke_backend",
            side_effect=decide_mod._LaunchPreparationError("read-only root"),
        ):
    local_result, local_backend_error = decide_mod._run_decision(
        "fixture", "vote", "PROMPT", 5, "",
    )
assert_eq(None, local_result, "local decision launch failure returns no verdict")
ok(local_backend_error is False,
   "local decision launch failure does not arm the backend breaker")

boundary_error = io.StringIO()
with tempfile.TemporaryDirectory() as td, \
        mock.patch.object(
            inv, "ensure_project_root", side_effect=OSError("read-only root"),
        ), mock.patch.object(inv.subprocess, "run") as backend_run, \
        mock.patch.object(inv, "agent_security_problem", return_value=""), \
        mock.patch.object(inv.sys, "stderr", boundary_error):
    raw = Path(td) / "raw.log"
    assert_eq(
        127,
        inv.run_agent_prompt(
            "grok", "PROMPT", 0, raw, add_dirs=td, cwd=td,
        ),
        "a missing project boundary fails the backend launch",
    )
    ok(not backend_run.called,
       "a backend never runs after project-boundary failure")
    ok("project boundary unavailable" in raw.read_text(),
       "project-boundary failure is recorded in the raw log")
    ok("project boundary unavailable" in boundary_error.getvalue(),
       "project-boundary failure is visible on stderr")

claude_single = inv.agent_flags("claude", allow_subagents=False)
ok("--disallowedTools" in claude_single, "single-agent Claude disables native delegation")
assert_eq("WebFetch,WebSearch,Agent,Task", claude_single[claude_single.index("--disallowedTools") + 1],
          "a bounded validator adds both delegation tool names to the standing web deny")
codex_single = inv.agent_flags("codex", allow_subagents=False)
ok("features.multi_agent=false" in codex_single, "single-agent Codex disables native delegation")
ok("features.plugins=false" in codex_single,
   "Codex agent disables plugin-contributed skills and workflows")

ok(inv.known_backend("claude") is True, "known_backend('claude') True")
ok(inv.known_backend("openai") is False, "known_backend('openai') False")
assert_eq("claude-opus-5", inv.default_model("claude"), "default_model claude")
assert_eq("gpt-5.6-sol", inv.default_model("codex"), "default_model codex")
assert_eq("gemini-3.7-flash", inv.default_model("gemini"), "default_model gemini")
assert_eq("grok-4.6", inv.default_model("grok"), "default_model grok")
os.environ["USE_GEMINI_CLI"] = "1"
os.environ.pop("GEMINI_MODEL_DEFAULT", None)
assert_eq("gemini-3.7-flash", inv.default_model("gemini"), "default_model gemini CLI")
os.environ.pop("USE_GEMINI_CLI", None)

decide_claude = inv.decide_flags("claude")
ok("--print" in decide_claude, "decide_flags('claude') has --print")
ok("--safe-mode" in decide_claude, "decide_flags('claude') disables user customizations")
ok("--no-session-persistence" in decide_claude, "decide_flags('claude') disables persistence")
ok("--max-turns" not in decide_claude, "decide_flags('claude') has no turn cap")
ok("plan" in decide_claude, "decide_flags('claude') uses read-only plan mode")
# The single-result envelope is what carries this call's measured usage; text
# output leaves decision spend to be estimated from character counts.
assert_eq("json", decide_claude[decide_claude.index("--output-format") + 1],
          "decide_flags('claude') asks for the usage-bearing envelope")

decide_codex = inv.decide_flags("codex")
ok("--json" in decide_codex,
   "Codex decisions ask for usage-bearing JSONL")
ok("features.plugins=false" in decide_codex,
   "Codex decisions disable plugins")

for builder in (inv.agent_flags, inv.decide_flags):
    ok("--pure" in builder("oss"),
       f"OpenCode {builder.__name__} runs without external plugins")

agent_codex = inv.agent_flags("codex", add_dirs="/x,/y")
ok("--json" in agent_codex and "--sandbox" in agent_codex,
   "agent_flags('codex') has --json and --sandbox")
ok(agent_codex[agent_codex.index("--cd") + 1] == "/x",
   "codex --cd uses first add-dir entry")
ok(agent_codex[agent_codex.index("--add-dir") + 1] == "/y",
   "codex --add-dir grants second add-dir entry")

# A benchmark cell reaches its target tree through a symlinked facade entry, so
# every grant a backend receives must already be resolved. Claude turns a
# symlinked grant readable-but-unwritable; Codex refuses to create any process
# at all while one is configured, which cost a whole harness row every command
# it ran. Neither failure is visible in a settings dict, so assert the paths.
with tempfile.TemporaryDirectory() as _raw_td:
    facade_td = Path(os.path.realpath(_raw_td))
    real_targets = facade_td / "checkout" / "targets"
    (real_targets / "demo").mkdir(parents=True)
    facade_root = facade_td / "cell" / "repo-root"
    facade_root.mkdir(parents=True)
    (facade_root / "targets").symlink_to(real_targets, target_is_directory=True)
    symlinked = facade_root / "targets" / "demo"

    ok(str(symlinked) != os.path.realpath(symlinked),
       "fixture reproduces a benchmark cell's symlinked target grant")
    ok(inv.granted_dirs(f"{symlinked},{os.path.realpath(symlinked)}")
       == [os.path.realpath(symlinked)],
       "granted_dirs collapses both spellings of one directory")

    # Both positions matter: the first entry becomes the workspace root
    # (codex --cd, grok --cwd) and the rest become explicit grants, and codex
    # rejects a symlinked writable root in either position.
    for sandboxable in ("claude", "codex", "gemini", "grok"):
        for position, grants in (
            ("as a grant", f"{facade_root},{symlinked}"),
            ("as the workspace root", str(symlinked)),
        ):
            emitted = [
                flag
                for flag in inv.agent_flags(sandboxable, add_dirs=grants)
                if flag.startswith(str(facade_td))
            ]
            unresolved = [f for f in emitted if f != os.path.realpath(f)]
            ok(emitted and not unresolved,
               f"agent_flags('{sandboxable}') resolves a symlinked dir {position}",
               f"symlinked spelling reached the sandbox: {unresolved}")

# max_turns is consumed by Claude and Grok; Codex and the Antigravity-CLI
# Gemini backend do not take a --max-turns flag.
agent_claude = inv.agent_flags("claude", max_turns=120)
ok("--safe-mode" in agent_claude, "agent_flags('claude') disables user customizations")
ok("--no-session-persistence" not in agent_claude,
   "agent_flags('claude') stays persistable so audit resume can work")
ok(agent_claude[agent_claude.index("--max-turns") + 1] == "120",
   "max_turns kwarg threaded through claude flag list")


# ── cross-run memory policy (TOKENFUZZ_MEMORY_ENABLED) ──────────────
print("\nmemory policy")
# Default (switch unset → memory OFF): codex gets the memory-off config
# overrides on both agent and decide flags; Gemini CLI gets the deny-save_memory
# admin policy; claude carries no memory flag (it is env-driven). OpenCode/oss
# does not need a harness memory knob.
os.environ.pop("TOKENFUZZ_MEMORY_ENABLED", None)
for builder in (inv.agent_flags, inv.decide_flags):
    fl = builder("codex")
    ok("features.memories=false" in fl,
       f"codex.{builder.__name__} disables the memories feature by default", fl)
    ok("memories.use_memories=false" in fl,
       f"codex.{builder.__name__} disables memory reads by default")
    ok("memories.generate_memories=false" in fl,
       f"codex.{builder.__name__} disables memory writes by default")
    ok(not any("memories" in x for x in builder("oss")),
       f"oss.{builder.__name__} carries no Codex memory flags")

os.environ["USE_GEMINI_CLI"] = "1"
gem_agent = inv.agent_flags("gemini")
ok("--admin-policy" in gem_agent,
   "Gemini CLI agent denies save_memory via --admin-policy by default", gem_agent)
pol = gem_agent[gem_agent.index("--admin-policy") + 1]
ok(pol.endswith("config/gemini-no-memory.policy.toml"),
   "admin-policy points at the shipped policy file", pol)
ok(Path(pol).is_file(), "the admin policy file exists on disk", pol)
ok("save_memory" in Path(pol).read_text(), "the policy file names the save_memory tool")
ok("--admin-policy" in inv.decide_flags("gemini"),
   "Gemini CLI decide also denies save_memory by default")
gemini_decide = inv.decide_flags("gemini")
assert_eq(
    "stream-json",
    gemini_decide[gemini_decide.index("--output-format") + 1],
    "Gemini CLI decisions ask for usage-bearing stream JSON",
)
os.environ.pop("USE_GEMINI_CLI", None)

ok(not any("memor" in x.lower() for x in inv.agent_flags("claude")),
   "claude agent flags carry no memory flag (env-driven)")
for builder in (inv.agent_flags, inv.decide_flags):
    ok("--no-memory" in builder("grok"),
       f"grok.{builder.__name__} disables cross-run memory by default")

# --enable-memory (switch=1): every per-backend memory disable disappears.
os.environ["TOKENFUZZ_MEMORY_ENABLED"] = "1"
for builder in (inv.agent_flags, inv.decide_flags):
    fl = builder("codex")
    ok(not any("memories" in x for x in fl),
       f"codex.{builder.__name__} omits memory flags when memory enabled", fl)
    grok_flags = builder("grok")
    ok("--experimental-memory" in grok_flags and "--no-memory" not in grok_flags,
       f"grok.{builder.__name__} enables memory only on explicit opt-in", grok_flags)
os.environ["USE_GEMINI_CLI"] = "1"
ok(not any(x.endswith("gemini-no-memory.policy.toml") for x in inv.agent_flags("gemini")),
   "Gemini CLI agent omits the memory policy when memory enabled")
ok(not any(x.endswith("gemini-no-memory.policy.toml") for x in inv.decide_flags("gemini")),
   "Gemini CLI decide omits the memory policy when memory enabled")
os.environ.pop("USE_GEMINI_CLI", None)
os.environ.pop("TOKENFUZZ_MEMORY_ENABLED", None)


# ── memory_env: env-level disable controls (claude + Gemini CLI home) ──
print("\nmemory_env")
# Reset the per-process isolated-home cache so each case stages fresh.
inv._gemini_iso_home = None
os.environ.pop("TOKENFUZZ_MEMORY_ENABLED", None)
os.environ.pop("USE_GEMINI_CLI", None)
os.environ.pop("GEMINI_CLI_HOME", None)

# Default (memory off): claude gets the disable env var; codex and Grok have
# CLI flags; oss has no harness memory knob; agy-dialect gemini has no auth-preserving
# isolation mechanism wired for Antigravity CLI.
ok(inv.memory_env("claude") == {"CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"},
   "claude memory_env sets CLAUDE_CODE_DISABLE_AUTO_MEMORY by default")
ok(inv.memory_env("codex") == {} and inv.memory_env("oss") == {},
   "codex/oss memory_env is empty")
ok(inv.memory_env("gemini") == {},
   "agy-dialect gemini memory_env is empty (no auth-preserving relocation)")

# Gemini CLI dialect: memory_env relocates GEMINI_CLI_HOME to a CLEAN, EMPTY
# per-run home — a .gemini/ holding only the TokenFuzz marker, no GEMINI.md and
# no other state. There is nothing to read (no cross-run memory) and no
# credential files (auth rides on the GEMINI_API_KEY env the harness forwards).
os.environ["USE_GEMINI_CLI"] = "1"
gem_logdir = tempfile.mkdtemp()
os.environ["LOGDIR"] = gem_logdir
inv._gemini_iso_home = None
gem_env = inv.memory_env("gemini")
ok(list(gem_env) == ["GEMINI_CLI_HOME"],
   "Gemini CLI memory_env relocates GEMINI_CLI_HOME", gem_env)
iso_home = gem_env["GEMINI_CLI_HOME"]
iso_gemini = Path(iso_home) / ".gemini"
ok(iso_home == str(Path(gem_logdir) / ".gemini-home"),
   "isolated home lives under $LOGDIR (run output tree, not /tmp)", iso_home)
ok(iso_gemini.is_dir(), "isolated home has a .gemini directory", iso_home)
ok(not (iso_gemini / "GEMINI.md").exists(),
   "isolated home excludes the global GEMINI.md (no cross-run memory read)")
ok(sorted(os.listdir(iso_gemini)) == [inv._GEMINI_ISOLATION_MARKER],
   "isolated .gemini holds only the marker — empty, no symlinks, no creds",
   sorted(os.listdir(iso_gemini)))
ok(not any((iso_gemini / e).is_symlink() for e in os.listdir(iso_gemini)),
   "isolated home contains no symlinks (no credentials placed on disk)")
ok(inv.memory_env("gemini")["GEMINI_CLI_HOME"] == iso_home,
   "isolated home is cached per process (no leak of a dir per call)")

invoke_env = inv.invocation_env("gemini")
settings_path = Path(invoke_env["GEMINI_CLI_SYSTEM_SETTINGS_PATH"])
settings = json.loads(settings_path.read_text())
ok(settings["skills"]["enabled"] is False,
   "Gemini CLI system settings disable skills")
ok(settings["admin"]["extensions"]["enabled"] is False,
   "Gemini CLI system settings disable extensions")
assert_eq([], settings["context"]["memoryBoundaryMarkers"],
          "Gemini CLI stops GEMINI.md discovery at cwd")
override = settings["modelConfigs"]["customOverrides"][0]
assert_eq("gemini-3.7-flash", override["match"]["model"],
          "Gemini effort override targets the configured model")
assert_eq("HIGH", override["modelConfig"]["generateContentConfig"]
          ["thinkingConfig"]["thinkingLevel"],
          "Gemini CLI wires configured effort as thinkingLevel")
cap_env = inv.invocation_env("gemini", max_session_turns=17)
cap_settings = json.loads(
    Path(cap_env["GEMINI_CLI_SYSTEM_SETTINGS_PATH"]).read_text()
)
assert_eq(17, cap_settings["model"]["maxSessionTurns"],
          "Gemini CLI audit sessions receive a native turn ceiling")

# Re-staging (a fresh run reusing the same $LOGDIR) wipes a stale throwaway
# GEMINI.md so a killed run's memory can't be read back on resume.
(iso_gemini / "GEMINI.md").write_text("STALE\n")
inv._gemini_iso_home = None
restaged = Path(inv.prepare_gemini_memory_isolation())
ok(not (restaged / ".gemini" / "GEMINI.md").exists(),
   "re-staging wipes a stale GEMINI.md from a prior run under the same $LOGDIR")

# If cleanup fails to remove an old staged home, do not return a dirty home with
# stale memory still present. Simulate a pathological rmtree that silently leaves
# the old tree behind; verification must fail closed.
dirty_logdir = tempfile.mkdtemp()
dirty_home = Path(dirty_logdir) / ".gemini-home"
dirty_gemini = dirty_home / ".gemini"
dirty_gemini.mkdir(parents=True)
(dirty_gemini / inv._GEMINI_ISOLATION_MARKER).write_text("old marker\n")
(dirty_gemini / "GEMINI.md").write_text("STALE\n")
os.environ["LOGDIR"] = dirty_logdir
inv._gemini_iso_home = None
real_rmtree = inv.shutil.rmtree
try:
    inv.shutil.rmtree = lambda *args, **kwargs: None
    ok(inv.prepare_gemini_memory_isolation() is None,
       "failed cleanup returns no Gemini home rather than reusing stale memory")
finally:
    inv.shutil.rmtree = real_rmtree
    shutil.rmtree(dirty_logdir, ignore_errors=True)
os.environ["LOGDIR"] = gem_logdir

# An inherited TokenFuzz-staged home matching THIS run's $LOGDIR/.gemini-home is
# reused as-is, so parallel agents / the llm_decide subprocess in one run share
# the single staged home rather than racing to re-wipe it.
os.environ["GEMINI_CLI_HOME"] = iso_home
inv._gemini_iso_home = None
ok(inv.prepare_gemini_memory_isolation() == iso_home,
   "an inherited GEMINI_CLI_HOME matching this run's $LOGDIR is reused without re-wiping")

# But an inherited home from a DIFFERENT run/cell (its $LOGDIR ≠ this one) must
# NOT be reused — that would leak the prior cell's memory. With cell A's home
# (carrying planted memory) still exported, switching $LOGDIR to cell B stages a
# fresh clean home under B, not A's.
(Path(iso_home) / ".gemini" / "GEMINI.md").write_text("STALE A MEMORY\n")
gem_logdir_b = tempfile.mkdtemp()
os.environ["LOGDIR"] = gem_logdir_b           # cell B
os.environ["GEMINI_CLI_HOME"] = iso_home      # still A's, inherited in-shell
inv._gemini_iso_home = None
home_b = inv.prepare_gemini_memory_isolation()
ok(home_b == str(Path(gem_logdir_b) / ".gemini-home") and home_b != iso_home,
   "a different $LOGDIR stages its own home, not the inherited prior-cell one", home_b)
ok(not (Path(home_b) / ".gemini" / "GEMINI.md").exists(),
   "the new cell's home is clean (prior cell's planted memory does not leak in)")
os.environ["LOGDIR"] = gem_logdir
os.environ.pop("GEMINI_CLI_HOME", None)
shutil.rmtree(gem_logdir_b, ignore_errors=True)
shutil.rmtree(gem_logdir, ignore_errors=True)

# No $LOGDIR (standalone caller): falls back to a throwaway dir, still empty.
os.environ.pop("LOGDIR", None)
inv._gemini_iso_home = None
fallback = Path(inv.prepare_gemini_memory_isolation())
ok((fallback / ".gemini").is_dir() and not (fallback / ".gemini" / "GEMINI.md").exists(),
   "no-$LOGDIR fallback stages a clean empty home")
shutil.rmtree(fallback, ignore_errors=True)

# Memory enabled: no env overrides for any backend.
os.environ["TOKENFUZZ_MEMORY_ENABLED"] = "1"
inv._gemini_iso_home = None
ok(inv.memory_env("claude") == {}, "claude memory_env empty when memory enabled")
ok(inv.memory_env("gemini") == {}, "Gemini CLI memory_env empty when memory enabled")
ok(inv.prepare_gemini_memory_isolation() is None,
   "no isolated home staged when memory enabled")
os.environ.pop("USE_GEMINI_CLI", None)
os.environ.pop("TOKENFUZZ_MEMORY_ENABLED", None)
inv._gemini_iso_home = None


# ── config/models.toml ──────────────────────────────────────────────
print("\nconfig/models.toml")
import tempfile  # noqa: E402

cfg_path = ROOT / "config" / "models.toml"
ok(cfg_path.is_file(), "config/models.toml exists")

# default_model reads straight from config/models.toml; the per-backend
# env var still wins when set.
_saved_cfg_path = inv._CONFIG_PATH
with tempfile.TemporaryDirectory() as _td:
    alt = Path(_td) / "models.toml"
    alt.write_text(
        '[models]\nclaude = "claude-from-config"\n'
        '[effort]\nclaude = "low"\ncodex = "xhigh"\n'
        'agy = "low"\ngemini = "medium"\ngrok = "max"\n'
    )
    try:
        inv._CONFIG_PATH = alt
        os.environ.pop("CLAUDE_MODEL_DEFAULT", None)
        assert_eq("claude-from-config", inv.default_model("claude"),
                  "default_model reads value from config/models.toml")
        assert_eq("low", inv.default_effort("claude"),
                  "default_effort reads the backend-specific value")
        assert_eq("xhigh", inv.default_effort("codex"),
                  "Codex effort does not reuse another backend's value")
        os.environ.pop("USE_GEMINI_CLI", None)
        assert_eq("low", inv.default_effort("gemini"),
                  "agy dialect reads its separate effort value")
        os.environ["USE_GEMINI_CLI"] = "1"
        assert_eq("medium", inv.default_effort("gemini"),
                  "Gemini CLI dialect reads its separate effort value")
        os.environ.pop("USE_GEMINI_CLI", None)
        _saved_loader = inv._load_tomllib
        try:
            inv._load_tomllib = lambda: (_ for _ in ()).throw(ModuleNotFoundError("tomli"))
            assert_eq("claude-from-config", inv.default_model("claude"),
                      "default_model falls back without tomllib/tomli")
        finally:
            inv._load_tomllib = _saved_loader
        os.environ["CLAUDE_MODEL_DEFAULT"] = "claude-from-env"
        assert_eq("claude-from-env", inv.default_model("claude"),
                  "env override beats config file")
        os.environ.pop("CLAUDE_MODEL_DEFAULT", None)
    finally:
        inv._CONFIG_PATH = _saved_cfg_path


# ── transient_tail: backend-agnostic provider-failure detection ─────────
# Retry paths use this to recover work killed mid-pass by a transient
# overload/429/5xx/rate-limit/timeout. It must read the RAW transcript and
# understand BOTH a plain stderr error line AND a JSON error event, because
# the stream-json text extractors (codex, gemini-CLI) drop the error. And it
# must NOT fire on healthy output or on "rate limit" merely discussed in
# agent prose — a false positive there costs a needless extra agent run.
def _tt(content: str) -> bool:
    with tempfile.NamedTemporaryFile("w", suffix=".raw", delete=False) as fh:
        fh.write(content)
        path = fh.name
    try:
        return inv.transient_tail(path)
    finally:
        os.unlink(path)


_TT_TRANSIENT = {
    "claude 529 stderr tail":
        '{"type":"assistant","message":{"content":[{"text":"working"}]}}\n'
        'API Error: 529 Overloaded. This is a server-side issue.',
    "codex partial then stderr 529":
        '{"type":"item.completed","item":{"type":"agent_message","text":"{c}"}}\n'
        'API Error: 529 Overloaded.',
    "codex JSON error event":
        '{"type":"item.completed","item":{"type":"agent_message","text":"x"}}\n'
        '{"type":"error","message":"server_error: 529 overloaded, retry"}',
    "agy timeout line":
        'plain agy output\nError: timed out waiting for response',
    "gemini 503 unavailable event":
        '{"role":"model","content":"hi"}\n'
        '{"type":"error","error":{"code":503,"status":"UNAVAILABLE","message":"x"}}',
}
_TT_CLEAN = {
    "healthy claude result (is_error false)":
        '{"type":"assistant","message":{"content":[{"text":"{\\"id\\":\\"REC-a\\"}"}]}}\n'
        '{"type":"result","is_error":false,"result":"done"}',
    'prose "Error:" without a transient keyword':
        '{"id":"REC-a"}\nError: no second bug found in parser.c, finishing up.',
    "recovered mid-run (error pushed out of tail)":
        'API Error: 529 Overloaded.\nRetrying...\n'
        '{"id":"REC-a"}\n{"id":"REC-b"}\n{"id":"REC-c"}\n{"id":"REC-d"}',
    '"rate limit" merely discussed in agent prose':
        '{"type":"item.completed","item":{"type":"agent_message",'
        '"text":"the rate limit logic in net.c looks ok"}}',
}
for _name, _c in _TT_TRANSIENT.items():
    ok(_tt(_c) is True, f"transient_tail fires: {_name}")
for _name, _c in _TT_CLEAN.items():
    ok(_tt(_c) is False, f"transient_tail clean: {_name}")
with tempfile.NamedTemporaryFile("w", suffix=".raw", delete=False) as _fh:
    _fh.write("old event\n" * 500_000)
    _fh.write("API Error: 529 Overloaded.\n\n")
    _large_tail = _fh.name
ok(inv.transient_tail(_large_tail), "transient_tail finds a terminal error without scanning semantics drift")
os.unlink(_large_tail)
# Subcommand exit codes mirror the API (0 = transient, 1 = clean/missing).
with tempfile.NamedTemporaryFile("w", suffix=".raw", delete=False) as _fh:
    _fh.write("API Error: 529 Overloaded.\n")
    _p = _fh.name
ok(run(["transient-tail", _p]).returncode == 0, "transient-tail subcommand: exit 0 on a fatal tail")
os.unlink(_p)
ok(run(["transient-tail", "/no/such/raw.log"]).returncode == 1, "transient-tail subcommand: exit 1 when the log is missing")

# A Claude safeguard can answer by switching models rather than returning an
# error status. The structured event is still a refusal of the requested
# model, and must reach the same warning path as a terminal refusal.
with tempfile.NamedTemporaryFile("w", suffix=".raw", delete=False) as _fh:
    json.dump({
        "type": "system", "subtype": "model_refusal_fallback",
        "trigger": "refusal", "original_model": "claude-fable-5-1",
        "fallback_model": "claude-opus-4-8",
    }, _fh)
    _refusal_fallback = _fh.name
ok(
    inv.raw_log_has_model_refusal("claude", _refusal_fallback),
    "model safeguard fallback reaches the structured refusal detector",
)
os.unlink(_refusal_fallback)


print(f"\n  \033[1m{PASSED}/{PASSED + FAILED} passed\033[0m")
sys.exit(0 if FAILED == 0 else 1)
