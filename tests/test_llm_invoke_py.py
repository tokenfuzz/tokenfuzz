#!/usr/bin/env python3
"""Regression tests for lib/llm_invoke.py.

The bash shim at lib/llm_invoke.sh delegates to this module — the
existing tests/test_llm_invoke.sh exercises the integration end-to-end.
This file complements that with focused Python-level assertions on
each subcommand (and the importable API used by lib/llm_decide.py).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "lib" / "llm_invoke.py"

# The default assertions below are for the existing agy dialect. Keep the
# test process insulated from a developer shell that happens to export the
# Gemini CLI switch.
os.environ.pop("USE_GEMINI_CLI", None)
for key in (
    "CLAUDE_MODEL_DEFAULT",
    "CODEX_MODEL_DEFAULT",
    "GEMINI_MODEL_DEFAULT",
    "CODEX_OSS_MODEL_DEFAULT",
):
    os.environ.pop(key, None)

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


def run(args, env=None, check=False):
    child_env = env if env is not None else os.environ.copy()
    proc = subprocess.run(
        [sys.executable, str(HELPER), *args],
        capture_output=True, text=True,
        env=child_env,
    )
    if check and proc.returncode != 0:
        raise AssertionError(f"helper failed rc={proc.returncode}: {proc.stderr}")
    return proc


def flags(proc):
    return [line for line in proc.stdout.splitlines() if line]


# ── known-backend ───────────────────────────────────────────────────
print("known-backend")
for b in ("claude", "codex", "oss", "gemini"):
    assert_eq(0, run(["known-backend", b]).returncode, f"{b} → rc=0")
assert_eq(1, run(["known-backend", "openai"]).returncode, "openai → rc=1")
assert_eq(1, run(["known-backend", ""]).returncode, "empty → rc=1")


# ── default-model ───────────────────────────────────────────────────
print("\ndefault-model")
proc = run(["default-model", "claude"], check=True)
assert_eq("claude-opus-4-8", proc.stdout.strip(), "claude default")
proc = run(["default-model", "codex"], check=True)
assert_eq("gpt-5.5", proc.stdout.strip(), "codex default")
proc = run(["default-model", "gemini"], check=True)
assert_eq("gemini-3.1-pro-preview", proc.stdout.strip(), "gemini default")
assert_eq(1, run(["default-model", "openai"]).returncode, "unknown → rc=1")

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
env["USE_GEMINI_CLI"] = "1"
env.pop("GEMINI_MODEL_DEFAULT", None)
proc = run(["default-model", "gemini"], env=env, check=True)
assert_eq("gemini-3.1-pro-preview", proc.stdout.strip(), "Gemini CLI dialect defaults model to pro-preview")


# ── agent-flags ─────────────────────────────────────────────────────
print("\nagent-flags")
proc = run(["agent-flags", "claude"], check=True)
f = flags(proc)
ok("--print" in f, "claude has --print", f)
ok("stream-json" in f, "claude has stream-json")
ok("--dangerously-skip-permissions" in f, "claude has skip-permissions")
ok("--max-turns" in f, "claude has --max-turns")
ok("80" in f, "claude default max-turns 80")
ok("claude-opus-4-8" in f, "claude default model wired")

proc = run(["agent-flags", "codex"], check=True)
f = proc.stdout
ok("--json" in f, "codex has --json", f)
ok("danger-full-access" in f, "codex has danger-full-access sandbox")
ok("--dangerously-bypass-approvals-and-sandbox" in f, "codex bypasses approvals")

proc = run(["agent-flags", "oss"], check=True)
f = proc.stdout
ok("--oss" in f, "oss has --oss")
ok("--local-provider" in f and "ollama" in f, "oss has --local-provider ollama")
ok("danger-full-access" in f, "oss inherits codex sandbox")

proc = run(["agent-flags", "gemini"], check=True)
f = proc.stdout
ok("--dangerously-skip-permissions" in f, "gemini has --dangerously-skip-permissions")
for legacy in ("--output-format", "--yolo", "--skip-trust", "--model"):
    ok(legacy not in f, f"gemini omits legacy gemini-cli flag {legacy}")

env = os.environ.copy()
env["USE_GEMINI_CLI"] = "1"
env.pop("GEMINI_MODEL_DEFAULT", None)
proc = run(["agent-flags", "gemini", "--add-dirs", "/a,/b"], env=env, check=True)
f = flags(proc)
ok("--approval-mode=yolo" in f, "Gemini CLI agent uses yolo approval mode")
ok("--skip-trust" in f, "Gemini CLI agent skips workspace trust prompt")
ok("--output-format" in f and "stream-json" in f, "Gemini CLI agent uses stream-json output")
model_idx = f.index("--model")
assert_eq("gemini-3.1-pro-preview", f[model_idx + 1], "Gemini CLI agent uses launch-time model")
indices = [i for i, x in enumerate(f) if x == "--include-directories"]
assert_eq(2, len(indices), "Gemini CLI emits two --include-directories flags")
ok(f[indices[0] + 1] == "/a", "first Gemini CLI include dir = /a")
ok(f[indices[1] + 1] == "/b", "second Gemini CLI include dir = /b")
ok("--dangerously-skip-permissions" not in f, "Gemini CLI agent omits agy skip-permissions")

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

proc = run(["agent-flags", "gemini", "--add-dirs", "/a,/b"], check=True)
f = flags(proc)
indices = [i for i, x in enumerate(f) if x == "--add-dir"]
assert_eq(2, len(indices), "gemini emits two --add-dir flags")
ok(f[indices[0] + 1] == "/a", "first gemini add-dir = /a")
ok(f[indices[1] + 1] == "/b", "second gemini add-dir = /b")


# ── decide-flags ────────────────────────────────────────────────────
print("\ndecide-flags")
proc = run(["decide-flags", "claude"], check=True)
f = flags(proc)
ok("--print" in f, "decide claude --print")
ok("--max-turns" in f, "decide claude pins max-turns")
turns_idx = f.index("--max-turns")
assert_eq("1", f[turns_idx + 1], "decide claude max-turns 1")
ok("text" in f, "decide claude text output")
ok("--dangerously-skip-permissions" not in f, "decide claude omits skip-permissions (no tools)")

proc = run(["decide-flags", "codex"], check=True)
f = proc.stdout
ok("read-only" in f, "decide codex read-only sandbox")
ok("danger-full-access" not in f, "decide codex NOT danger-full-access")

proc = run(["decide-flags", "gemini"], check=True)
f = proc.stdout
ok("--dangerously-skip-permissions" in f, "decide gemini has --dangerously-skip-permissions")
for legacy in ("--output-format", "--approval-mode", "--model"):
    ok(legacy not in f, f"decide gemini omits legacy gemini-cli flag {legacy}")

env = os.environ.copy()
env["USE_GEMINI_CLI"] = "1"
env.pop("GEMINI_MODEL_DEFAULT", None)
proc = run(["decide-flags", "gemini"], env=env, check=True)
f = flags(proc)
ok("--approval-mode=plan" in f, "Gemini CLI decide uses plan approval mode")
ok("--skip-trust" in f, "Gemini CLI decide skips workspace trust prompt")
model_idx = f.index("--model")
assert_eq("gemini-3.1-pro-preview", f[model_idx + 1], "Gemini CLI decide wires model")
ok("--dangerously-skip-permissions" not in f, "Gemini CLI decide omits agy skip-permissions")


# ── extract-text per backend ────────────────────────────────────────
print("\nextract-text")
with tempfile.TemporaryDirectory() as td:
    p = Path(td)

    # claude — in a real stream-json transcript the trailing result
    # event echoes the final assistant turn verbatim. Extraction must
    # NOT emit it twice (would double-count every recon hypothesis).
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
sys.path.insert(0, str(ROOT / "lib"))
import llm_invoke as inv  # noqa: E402

ok(inv.known_backend("claude") is True, "known_backend('claude') True")
ok(inv.known_backend("openai") is False, "known_backend('openai') False")
assert_eq("claude-opus-4-8", inv.default_model("claude"), "default_model claude")
assert_eq("gpt-5.5", inv.default_model("codex"), "default_model codex")
assert_eq("gemini-3.1-pro-preview", inv.default_model("gemini"), "default_model gemini")
os.environ["USE_GEMINI_CLI"] = "1"
os.environ.pop("GEMINI_MODEL_DEFAULT", None)
assert_eq("gemini-3.1-pro-preview", inv.default_model("gemini"), "default_model gemini CLI")
os.environ.pop("USE_GEMINI_CLI", None)

decide_claude = inv.decide_flags("claude")
ok("--print" in decide_claude, "decide_flags('claude') has --print")
ok("--max-turns" in decide_claude, "decide_flags('claude') has --max-turns")

agent_codex = inv.agent_flags("codex", add_dirs="/x,/y")
ok("--json" in agent_codex and "--sandbox" in agent_codex,
   "agent_flags('codex') has --json and --sandbox")
ok(agent_codex[agent_codex.index("--cd") + 1] == "/x",
   "codex --cd uses first add-dir entry")
ok(agent_codex[agent_codex.index("--add-dir") + 1] == "/y",
   "codex --add-dir grants second add-dir entry")

# max_turns kwarg is only consumed by claude (CLI-side: codex and the
# Antigravity-CLI gemini backend don't take a --max-turns flag).
agent_claude = inv.agent_flags("claude", max_turns=120)
ok(agent_claude[agent_claude.index("--max-turns") + 1] == "120",
   "max_turns kwarg threaded through claude flag list")


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
    alt.write_text('[models]\nclaude = "claude-from-config"\n')
    try:
        inv._CONFIG_PATH = alt
        os.environ.pop("CLAUDE_MODEL_DEFAULT", None)
        assert_eq("claude-from-config", inv.default_model("claude"),
                  "default_model reads value from config/models.toml")
        os.environ["CLAUDE_MODEL_DEFAULT"] = "claude-from-env"
        assert_eq("claude-from-env", inv.default_model("claude"),
                  "env override beats config file")
        os.environ.pop("CLAUDE_MODEL_DEFAULT", None)
    finally:
        inv._CONFIG_PATH = _saved_cfg_path


print(f"\n  \033[1m{PASSED}/{PASSED + FAILED} passed\033[0m")
sys.exit(0 if FAILED == 0 else 1)
