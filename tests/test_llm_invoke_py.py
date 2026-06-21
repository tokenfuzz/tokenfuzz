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
import shutil
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
# Cross-run memory defaults to OFF when the switch is unset; clear any
# developer-shell value so the default-off assertions are deterministic.
os.environ.pop("TOKENFUZZ_MEMORY_ENABLED", None)
for key in (
    "CLAUDE_MODEL_DEFAULT",
    "CODEX_MODEL_DEFAULT",
    "GEMINI_MODEL_DEFAULT",
    "AUDIT_LOCAL_BASE_URL",
    "AUDIT_LOCAL_API_KEY",
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
f = flags(proc)
assert_eq(
    ["run", "--dangerously-skip-permissions", "--format", "json"],
    f,
    "oss agent flags do not invent a model when none is supplied",
)

proc = run(["agent-flags", "oss", "--model", "qwen3-8b"], check=True)
f = flags(proc)
assert_eq("local/qwen3-8b", f[f.index("--model") + 1], "oss model uses shared local provider ref for vLLM")
ok("--dangerously-skip-permissions" in f, "oss agent auto-approves OpenCode permissions")

proc = run(["agent-flags", "oss", "--model", "qwen3:8b"], check=True)
f = flags(proc)
assert_eq("local/qwen3:8b", f[f.index("--model") + 1], "oss model uses shared local provider ref for colon-tagged models")

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

proc = run(["agent-flags", "gemini"], check=True)
f = flags(proc)
ok("--dangerously-skip-permissions" in f, "gemini has --dangerously-skip-permissions")
# agy 1.0.5+ pins the model via its `agy models` display label, mapped from
# the config slug — it resolves labels, not API slugs.
model_idx = f.index("--model")
assert_eq("Gemini 3.1 Pro (High)", f[model_idx + 1], "gemini agy wires the mapped model label")
for legacy in ("--output-format", "--yolo", "--skip-trust"):
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
f = flags(proc)
ok("--dangerously-skip-permissions" in f, "decide gemini has --dangerously-skip-permissions")
model_idx = f.index("--model")
assert_eq("Gemini 3.1 Pro (High)", f[model_idx + 1], "decide gemini agy wires the mapped model label")
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

    (p / "oss_tool_spaced.jsonl").write_text(
        '{ "type": "tool_use", "part": { "type": "tool", '
        '"tool": "read", "state": { "status": "completed" } } }\n'
    )
    proc = run(["raw-has-tool", str(p / "oss_tool_spaced.jsonl"), "read"])
    assert_eq(0, proc.returncode, "raw-has-tool detects nested OpenCode read tool with spaced JSON")
    proc = run(["raw-has-tool", str(p / "oss_tool_spaced.jsonl"), "bash"])
    assert_eq(1, proc.returncode, "raw-has-tool rejects absent tool names")

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
os.environ.pop("USE_GEMINI_CLI", None)

ok(not any("memor" in x.lower() for x in inv.agent_flags("claude")),
   "claude agent flags carry no memory flag (env-driven)")

# --enable-memory (switch=1): every per-backend memory disable disappears.
os.environ["TOKENFUZZ_MEMORY_ENABLED"] = "1"
for builder in (inv.agent_flags, inv.decide_flags):
    fl = builder("codex")
    ok(not any("memories" in x for x in fl),
       f"codex.{builder.__name__} omits memory flags when memory enabled", fl)
os.environ["USE_GEMINI_CLI"] = "1"
ok("--admin-policy" not in inv.agent_flags("gemini"),
   "Gemini CLI agent omits admin-policy when memory enabled")
ok("--admin-policy" not in inv.decide_flags("gemini"),
   "Gemini CLI decide omits admin-policy when memory enabled")
os.environ.pop("USE_GEMINI_CLI", None)
os.environ.pop("TOKENFUZZ_MEMORY_ENABLED", None)


# ── memory_env: env-level disable controls (claude + Gemini CLI home) ──
print("\nmemory_env")
# Reset the per-process isolated-home cache so each case stages fresh.
inv._gemini_iso_home = None
os.environ.pop("TOKENFUZZ_MEMORY_ENABLED", None)
os.environ.pop("USE_GEMINI_CLI", None)
os.environ.pop("GEMINI_CLI_HOME", None)

# Default (memory off): claude gets the disable env var; codex has CLI flags;
# oss has no harness memory knob; agy-dialect gemini has no auth-preserving
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
    alt.write_text('[models]\nclaude = "claude-from-config"\n')
    try:
        inv._CONFIG_PATH = alt
        os.environ.pop("CLAUDE_MODEL_DEFAULT", None)
        assert_eq("claude-from-config", inv.default_model("claude"),
                  "default_model reads value from config/models.toml")
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
# Recon's retry uses this to recover slices killed mid-pass by a transient
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
# Subcommand exit codes mirror the API (0 = transient, 1 = clean/missing).
with tempfile.NamedTemporaryFile("w", suffix=".raw", delete=False) as _fh:
    _fh.write("API Error: 529 Overloaded.\n")
    _p = _fh.name
ok(run(["transient-tail", _p]).returncode == 0, "transient-tail subcommand: exit 0 on a fatal tail")
os.unlink(_p)
ok(run(["transient-tail", "/no/such/raw.log"]).returncode == 1, "transient-tail subcommand: exit 1 when the log is missing")


print(f"\n  \033[1m{PASSED}/{PASSED + FAILED} passed\033[0m")
sys.exit(0 if FAILED == 0 else 1)
