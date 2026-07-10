#!/usr/bin/env python3
"""Regression tests for lib/audit_helpers.py.

Each subcommand is exercised through its argparse CLI (the same shape
bin/audit and bin/validate-finding invoke), so the test surface matches
production. Keeps zero coupling to internal helpers — only public CLI
behavior is asserted.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import datetime as dt
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HELPER = ROOT / "lib" / "audit_helpers.py"

PASSED = 0
FAILED = 0


def ok(cond: bool, name: str, detail: str = "") -> None:
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        FAILED += 1
        print(f"  \033[0;31m✗\033[0m {name}")
        if detail:
            print(f"    {detail}")


def assert_eq(expected, actual, name: str) -> None:
    ok(expected == actual, name, f"expected={expected!r} actual={actual!r}")


def run(args, stdin: str = "", check: bool = False):
    proc = subprocess.run(
        [sys.executable, str(HELPER), *args],
        input=stdin,
        capture_output=True,
        text=True,
    )
    if check and proc.returncode != 0:
        raise AssertionError(f"helper failed rc={proc.returncode}: {proc.stderr}")
    return proc


# ── relpath-list ────────────────────────────────────────────────────
print("relpath-list")
with tempfile.TemporaryDirectory() as td:
    td_path = Path(td).resolve()
    (td_path / "a").mkdir()
    (td_path / "a" / "b.txt").write_text("x")
    stdin = "\n".join([str(td_path / "a"), str(td_path / "a" / "b.txt"), str(td_path)]) + "\n"
    proc = run(["relpath-list", str(td_path)], stdin=stdin)
    assert_eq(0, proc.returncode, "relpath-list exit code")
    lines = [ln for ln in proc.stdout.splitlines() if ln]
    assert_eq(["a", "a/b.txt"], sorted(lines), "relpath-list drops '.' and prints relpaths")

proc = run(["relpath-list", str(ROOT)], stdin="\n\n")
assert_eq("", proc.stdout, "relpath-list ignores blank stdin lines")


# ── sanitize-target-slug ───────────────────────────────────────────
print("\nsanitize-target-slug")
with tempfile.TemporaryDirectory() as td:
    targets = Path(td) / "targets"
    nested = targets / "Samples" / "Sample Ruby"
    external = Path(td) / "External Project!"
    nested.mkdir(parents=True)
    external.mkdir()
    proc = run(["sanitize-target-slug", str(nested), str(targets)])
    assert_eq(0, proc.returncode, "sanitize-target-slug nested exit code")
    assert_eq(
        "samples/sample-ruby",
        proc.stdout.strip(),
        "sanitize-target-slug preserves nested target slug",
    )
    proc = run(["sanitize-target-slug", str(external), str(targets)])
    assert_eq(
        "external-project",
        proc.stdout.strip(),
        "sanitize-target-slug external path uses sanitized basename",
    )

proc = run(["sanitize-target-slug", "v1.2_Test", "/path/that/cannot/contain/input"])
assert_eq("v1.2_test", proc.stdout.strip(), "sanitize-target-slug preserves dot and underscore")


# ── run metadata and display formatting ──────────────────────────────────
print("\nwrite-run-config")
with tempfile.TemporaryDirectory() as td:
    config = Path(td) / "run-config.json"
    proc = run([
        "write-run-config", str(config), "3", "bad", "1", "codex",
        "model-name", "sample/target", "1",
    ])
    assert_eq(0, proc.returncode, "write-run-config exit code")
    assert_eq(
        {
            "agent_count_overridden": True,
            "backend": "codex",
            "browser_agents": 0,
            "model": "model-name",
            "num_agents": 3,
            "shell_agents": 1,
            "target_slug": "sample/target",
        },
        json.loads(config.read_text()),
        "write-run-config preserves schema and integer coercion",
    )
    proc = run([
        "write-run-config", str(config), "4", "2", "2", "claude",
        "next-model", "sample/target", "true",
    ])
    assert_eq(False, json.loads(config.read_text())["agent_count_overridden"],
              "write-run-config accepts only integer one as override")

print("\nformat-waste")
telemetry = (
    'tool_bytes=9003 max_output=9000 over8k=1 '
    'native_tools=Read:1,Grep:0,Glob:0 top_cmds=ls:1,probe:1 '
    'largest="probe: bin/probe scratch-1/testcase.html"'
)
proc = run(["format-waste", telemetry])
assert_eq(
    'tool output: bytes=9k max=9k oversized=1 top=ls:1,probe:1 '
    'native=Read:1 largest="probe: bin/probe scratch-1/testcase.html"',
    proc.stdout.strip(),
    "format-waste renders compact nonzero fields",
)
proc = run(["format-waste", ""])
assert_eq("tool output: bytes=0 max=0", proc.stdout.strip(),
          "format-waste renders empty structured telemetry")

print("\ncluster-count")
clusters = json.dumps({"clusters": [
    {"status": "PROMOTED"}, {"status": "pending-review"}, {"status": ""},
]})
proc = run(["cluster-count", "PENDING,REJECTED"], stdin=clusters)
assert_eq(0, proc.returncode, "cluster-count valid JSON exit code")
assert_eq("2", proc.stdout.strip(), "cluster-count excludes status prefixes")
proc = run(["cluster-count", ""], stdin=clusters)
assert_eq("3", proc.stdout.strip(), "cluster-count with no exclusions counts every cluster")
proc = run(["cluster-count", ""], stdin="not json")
assert_eq(1, proc.returncode, "cluster-count malformed JSON exits nonzero")

print("\nmarkdown-finding and json-field")
with tempfile.TemporaryDirectory() as td:
    report = Path(td) / "report.md"
    report.write_text(
        "# Finding\n\n"
        "**File and function:** src/sample.c:parse:42\n"
        "**Bug class:** bounds\n"
        "Caller controls: bytes\n"
        "  and length\n"
        "Strategy: S2\n",
        encoding="utf-8",
    )
    proc = run(["markdown-finding", str(report)])
    candidate = json.loads(proc.stdout)
    assert_eq("markdown-report", candidate["format"],
              "markdown-finding records source format")
    assert_eq("src/sample.c:parse:42", candidate["location"],
              "markdown-finding recognizes bold prose label")
    assert_eq("bytes and length", candidate["caller_controls"],
              "markdown-finding joins continuation line")
    ok("# Finding" in candidate["report_text"],
       "markdown-finding preserves full report text")

proc = run(["json-field", "card_id"], stdin='{"card_id":"CARD-7"}')
assert_eq("CARD-7", proc.stdout.strip(), "json-field reads requested field")
proc = run(["json-field", "card_id"], stdin="invalid")
assert_eq("", proc.stdout.strip(), "json-field fails open on invalid JSON")


# ── waste-telemetry ─────────────────────────────────────────────────
print("\nwaste-telemetry")

proc = run(["waste-telemetry", "/nonexistent/path-that-cannot-exist.log"])
ok(
    "tool_bytes=0" in proc.stdout and "top_cmds=none" in proc.stdout,
    "missing log → zero-row default",
    proc.stdout.strip(),
)

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    codex_path = f.name
    json.dump(
        {
            "type": "item.completed",
            "item": {
                "type": "command_execution",
                "command": "rg --files src/ | head -3",
                "aggregated_output": "a\nb\nc\n",
            },
        },
        f,
    )
    f.write("\n")
try:
    proc = run(["waste-telemetry", codex_path])
    assert_eq(0, proc.returncode, "codex transcript rc=0")
    ok("rg:1" in proc.stdout, "codex command_execution → rg pattern", proc.stdout)
    ok("tool_bytes=6" in proc.stdout, "codex tool_bytes counts aggregated_output")
finally:
    os.unlink(codex_path)

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    claude_path = f.name
    json.dump(
        {
            "type": "assistant",
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "u1",
                        "name": "Read",
                        "input": {"file_path": "/x"},
                    }
                ]
            },
        },
        f,
    )
    f.write("\n")
    json.dump(
        {
            "type": "user",
            "message": {
                "content": [
                    {"type": "tool_result", "tool_use_id": "u1", "content": "hello"}
                ]
            },
        },
        f,
    )
    f.write("\n")
try:
    proc = run(["waste-telemetry", claude_path])
    ok("Read:1" in proc.stdout, "claude tool_use → native_tools Read:1", proc.stdout)
    ok("tool_bytes=5" in proc.stdout, "claude tool_result content size = 5")
finally:
    os.unlink(claude_path)

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    gemini_path = f.name
    json.dump(
        {
            "type": "tool_use",
            "tool_name": "run_shell_command",
            "tool_id": "g1",
            "parameters": {"command": "bin/probe scratch-1/testcase.c"},
        },
        f,
    )
    f.write("\n")
    json.dump(
        {
            "type": "tool_result",
            "tool_id": "g1",
            "status": "success",
            "output": "hello",
        },
        f,
    )
    f.write("\n")
try:
    proc = run(["waste-telemetry", gemini_path])
    ok("probe:1" in proc.stdout, "gemini tool_use → probe command pattern", proc.stdout)
    ok("tool_bytes=5" in proc.stdout, "gemini tool_result output size = 5")
    ok("largest=\"probe: bin/probe scratch-1/testcase.c\"" in proc.stdout, "gemini largest command label")
finally:
    os.unlink(gemini_path)

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    bad_path = f.name
    f.write("not json at all\n")
    f.write(
        '{"type":"item.completed","item":{"type":"command_execution",'
        '"command":"jq .","aggregated_output":"ok"}}\n'
    )
try:
    proc = run(["waste-telemetry", bad_path])
    assert_eq(0, proc.returncode, "garbage lines do not crash")
    ok("jq:1" in proc.stdout, "second valid line still parsed")
finally:
    os.unlink(bad_path)


# ── count-tools ─────────────────────────────────────────────────────
print("\ncount-tools")
with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
    tools_path = f.name
    rows = [
        {"type": "item.completed", "item": {"type": "command_execution", "command": "ls"}},
        {"type": "item.completed", "item": {"type": "file_change", "path": "x"}},
        {
            "message": {
                "content": [
                    {"type": "tool_use", "name": "Bash", "input": {"command": "pwd"}},
                    {"type": "tool_use", "name": "Read", "input": {"path": "foo"}},
                ]
            }
        },
        {"type": "tool_use", "tool_name": "run_shell_command", "tool_id": "g1"},
        {"type": "tool_use", "tool_name": "read_file", "tool_id": "g2"},
    ]
    for row in rows:
        json.dump(row, f)
        f.write("\n")
try:
    proc = run(["count-tools", tools_path, "command_execution"])
    assert_eq("3", proc.stdout.strip(), "single command_execution count")
    proc = run(["count-tools", tools_path, "all_tools"])
    assert_eq("6", proc.stdout.strip(), "single all_tools count")
    proc = run(["count-tools-all", tools_path])
    assert_eq(
        ["command_execution=3", "all_tools=6"],
        proc.stdout.splitlines(),
        "count-tools-all prints both counts",
    )
finally:
    os.unlink(tools_path)

proc = run(["count-tools-all", "/nonexistent/path-that-cannot-exist.log"])
assert_eq(["command_execution=0", "all_tools=0"], proc.stdout.splitlines(), "missing log → zero tool counts")


# ── raw-status ──────────────────────────────────────────────────────
print("\nraw-status")
with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
    raw_status_path = f.name
    rows = [
        {"type": "turn.completed"},
        {"type": "result", "status": "success"},
        {"type": "agent_message", "message": "You've hit your usage limit. Please try again at 9:01 AM."},
    ]
    for row in rows:
        json.dump(row, f, separators=(",", ":"))
        f.write("\n")
try:
    proc = run(["raw-status", raw_status_path])
    assert_eq(
        ["rate_limit=1", "codex_completed=1", "codex_failed=0", "gemini_success=1"],
        proc.stdout.splitlines(),
        "raw-status: completed codex + gemini success + usage-limit wording",
    )
finally:
    os.unlink(raw_status_path)

with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
    raw_failed_path = f.name
    f.write('{"type":"turn.failed","error":"Server returned 429"}\n')
try:
    proc = run(["raw-status", raw_failed_path])
    assert_eq(
        ["rate_limit=1", "codex_completed=0", "codex_failed=1", "gemini_success=0"],
        proc.stdout.splitlines(),
        "raw-status: codex failed turn with 429",
    )
finally:
    os.unlink(raw_failed_path)

with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
    stray_429_path = f.name
    f.write('{"type":"item.completed","item":{"type":"command_execution","aggregated_output":"tool said status:429"}}\n')
try:
    proc = run(["raw-status", stray_429_path])
    assert_eq(
        ["rate_limit=0", "codex_completed=0", "codex_failed=0", "gemini_success=0"],
        proc.stdout.splitlines(),
        "raw-status: non-gemini stray status:429 is not a backend rate limit",
    )
finally:
    os.unlink(stray_429_path)

with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
    gemini_429_path = f.name
    f.write('{"type":"init","model":"gemini-2.5-pro"}\n')
    f.write('Attempt 1 failed with status 429\n')
try:
    proc = run(["raw-status", gemini_429_path])
    assert_eq(
        ["rate_limit=1", "codex_completed=0", "codex_failed=0", "gemini_success=0"],
        proc.stdout.splitlines(),
        "raw-status: gemini dialect marker scopes backend rejection text",
    )
finally:
    os.unlink(gemini_429_path)

# Overload (5xx) reads the same as a rate limit so the backoff path handles it.
with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
    claude_529_path = f.name
    f.write('{"type":"result","is_error":true,"api_error_status":529,"result":"API Error: 529 Overloaded"}\n')
try:
    proc = run(["raw-status", claude_529_path])
    assert_eq(
        ["rate_limit=1", "codex_completed=0", "codex_failed=0", "gemini_success=0"],
        proc.stdout.splitlines(),
        "raw-status: claude 529 overload is a transient rejection",
    )
finally:
    os.unlink(claude_529_path)

with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
    codex_5xx_path = f.name
    f.write('{"type":"turn.failed","error":"Server returned 503"}\n')
try:
    proc = run(["raw-status", codex_5xx_path])
    assert_eq(
        ["rate_limit=1", "codex_completed=0", "codex_failed=1", "gemini_success=0"],
        proc.stdout.splitlines(),
        "raw-status: codex 5xx server error is a transient rejection",
    )
finally:
    os.unlink(codex_5xx_path)

# Event-scoping: a gemini-dialect session whose TOOL OUTPUT contains
# overload-shaped text must NOT be read as a backend rejection (the trigger
# text is audited program output inside a tool_result, not a CLI error).
with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
    gemini_tooloutput_path = f.name
    f.write('{"type":"init","model":"gemini-3.1-pro"}\n')
    f.write('{"type":"user","message":{"content":[{"type":"tool_result","content":"grep hit: code 503 UNAVAILABLE status:500"}]}}\n')
try:
    proc = run(["raw-status", gemini_tooloutput_path])
    assert_eq(
        ["rate_limit=0", "codex_completed=0", "codex_failed=0", "gemini_success=0"],
        proc.stdout.splitlines(),
        "raw-status: gemini tool-output 5xx text is not a backend rejection",
    )
finally:
    os.unlink(gemini_tooloutput_path)

# ...but a real gemini backend error on a glog (non-JSON) line still counts.
with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
    gemini_glog_path = f.name
    f.write('{"type":"init","model":"gemini-3.1-pro"}\n')
    f.write('Attempt 1 failed with status 503. Retrying in 2s.\n')
try:
    proc = run(["raw-status", gemini_glog_path])
    assert_eq(
        ["rate_limit=1", "codex_completed=0", "codex_failed=0", "gemini_success=0"],
        proc.stdout.splitlines(),
        "raw-status: gemini glog 5xx backend error is a transient rejection",
    )
finally:
    os.unlink(gemini_glog_path)

# Non-transient 4xx (auth/config) must NOT be treated as a transient
# rejection — otherwise the harness would silently retry an unrecoverable
# error instead of surfacing it. Only 429 and 5xx are retryable.
for code in (400, 401, 403, 404, 413):
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        cfg_path = f.name
        f.write('{"type":"result","is_error":true,"api_error_status":%d}\n' % code)
    try:
        proc = run(["raw-status", cfg_path])
        assert_eq(
            ["rate_limit=0", "codex_completed=0", "codex_failed=0", "gemini_success=0"],
            proc.stdout.splitlines(),
            f"raw-status: claude {code} (auth/config) is NOT a transient rejection",
        )
    finally:
        os.unlink(cfg_path)

proc = run(["raw-status", "/nonexistent/path-that-cannot-exist.log"])
assert_eq(
    ["rate_limit=0", "codex_completed=0", "codex_failed=0", "gemini_success=0"],
    proc.stdout.splitlines(),
    "raw-status: missing log returns zero flags",
)


# ── provider-issue ─────────────────────────────────────────────────
print("\nprovider-issue")

provider_cases = [
    (
        [{"type": "result", "is_error": True, "api_error_status": 429}],
        "capacity_limited",
        "provider-issue: claude api_error_status 429 is capacity-limited",
    ),
    (
        [{"type": "turn.failed", "error": {"message": "Server returned 503"}}],
        "transient",
        "provider-issue: codex Server returned 503 is transient",
    ),
    (
        [{"type": "error", "error": {"code": 429, "message": "Too Many Requests"}}],
        "capacity_limited",
        "provider-issue: quoted JSON code 429 is capacity-limited",
    ),
    (
        [{"type": "error", "error": {"code": 503, "message": "backend unavailable"}}],
        "transient",
        "provider-issue: quoted JSON code 503 is transient",
    ),
    (
        [
            {"type": "init", "model": "gemini-3.1-pro-preview"},
            "Attempt 1 failed with status 429. RESOURCE_EXHAUSTED You exceeded your current quota.",
        ],
        "capacity_limited",
        "provider-issue: gemini RESOURCE_EXHAUSTED 429 is capacity-limited",
    ),
    (
        [
            "[agy CLI log tail: /tmp/agy-cli-log/cli-20260521_233915.log]",
            "E0521 23:39:17.828 log.go:398 agent executor error: "
            "RESOURCE_EXHAUSTED (code 429): Individual quota reached. Resets in 137h39m19s.",
        ],
        "capacity_limited",
        "provider-issue: copied agy CLI log quota tail is capacity-limited",
    ),
    (
        [
            {"type": "error", "error": {"message": "upstream UNAVAILABLE"}},
        ],
        "transient",
        "provider-issue: opencode-style unavailable error is transient",
    ),
    (
        [
            {"type": "tool_result", "content": "fixture text says status:500 UNAVAILABLE"},
            {"type": "item.completed", "item": {"aggregated_output": "Server returned 429"}},
        ],
        "none",
        "provider-issue: tool output is not a provider failure",
    ),
    (
        # The model reasoning about a target's rate-limit behaviour in its own
        # prose must NOT read as a provider failure (the agent_message FP guard).
        [{"type": "agent_message",
          "message": "The target returns HTTP 429 Too Many Requests once its "
                     "rate limit is exceeded; we should fuzz that path."}],
        "none",
        "provider-issue: assistant prose about 429 is not a provider failure",
    ),
    (
        # Conjunction guard: a generic 'limit' + 'reset' in prose is not the
        # account usage notice.
        [{"type": "agent_message",
          "message": "The parser will hit your configured recursion limit and "
                     "then reset its state."}],
        "none",
        "provider-issue: generic limit+reset prose is not capacity-limited",
    ),
    (
        # The account-limit conjunction must be local to one trusted provider
        # line. Otherwise normal assistant reasoning about target-side usage
        # limits plus unrelated tool output mentioning reset would discard a
        # benchmark cell as provider-limited.
        [
            {"type": "agent_message",
             "message": "We should add a usage limit regression test for the target."},
            {"type": "item.completed",
             "item": {"type": "command_execution", "aggregated_output": "reset complete"}},
        ],
        "none",
        "provider-issue: usage-limit prose plus unrelated reset is not capacity-limited",
    ),
    (
        # The real Codex/Claude account notice: account-limit phrase AND retry
        # wording, in an agent_message → capacity.
        [{"type": "agent_message",
          "message": "You've hit your usage limit. Please try again at 9:01 AM."}],
        "capacity_limited",
        "provider-issue: codex usage-limit notice is capacity-limited",
    ),
    (
        # Plain capacity wording with NO provider-CLI dialect marker must not
        # match (the dialect-gate guard for non-JSON lines).
        ["2026-06-22 some unrelated tool log: exceeded your current quota here"],
        "none",
        "provider-issue: plain capacity text without dialect is not a failure",
    ),
    (
        # Claude's account notice via the session-limit phrasing → capacity.
        [{"type": "agent_message",
          "message": "You've hit your session limit · resets 9:40am"}],
        "capacity_limited",
        "provider-issue: claude session-limit notice is capacity-limited",
    ),
    (
        # Anthropic 529 overload is server-side, not a quota → transient.
        [{"type": "result", "is_error": True, "api_error_status": 529}],
        "transient",
        "provider-issue: claude 529 overload is transient",
    ),
    (
        # Non-429 4xx (auth/config/input) is NOT a provider retry/quota signal.
        # It must fall through so normal failure handling exposes the real cause
        # (bad key, forbidden, not found, payload too large) — never a backoff.
        [
            {"type": "error", "error": {"code": 400, "message": "Bad Request"}},
            {"type": "error", "error": {"code": 401, "message": "Unauthorized"}},
            {"type": "error", "error": {"code": 403, "message": "Forbidden"}},
            {"type": "turn.failed", "error": {"message": "Server returned 404"}},
            {"type": "error", "error": {"code": 413, "message": "Payload Too Large"}},
        ],
        "none",
        "provider-issue: non-429 4xx is not transient or capacity",
    ),
]

for rows, expected, name in provider_cases:
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
        provider_path = f.name
        for row in rows:
            if isinstance(row, str):
                f.write(row)
            else:
                json.dump(row, f, separators=(",", ":"))
            f.write("\n")
    try:
        proc = run(["provider-issue", provider_path])
        assert_eq(expected, proc.stdout.strip(), name)
    finally:
        os.unlink(provider_path)

proc = run(["provider-issue", "/nonexistent/path-that-cannot-exist.log"])
assert_eq("none", proc.stdout.strip(), "provider-issue: missing log returns none")


# ── finish-fields ──────────────────────────────────────────────────
print("\nfinish-fields")
with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
    finish_path = f.name
    rows = [
        {"type": "item.completed", "item": {"type": "command_execution", "command": "ls"}},
        {"type": "tool_use", "tool_name": "run_shell_command", "tool_id": "g1"},
        {"type": "tool_use", "tool_name": "read_file", "tool_id": "g2"},
        {
            "type": "turn.completed",
            "usage": {
                "input_tokens": 7,
                "cached_input_tokens": 2,
                "cache_creation_input_tokens": 3,
                "output_tokens": 5,
            },
            "duration_ms": 456,
        },
        {"type": "result", "status": "success"},
    ]
    for row in rows:
        json.dump(row, f)
        f.write("\n")
try:
    proc = run(["finish-fields", finish_path, "codex"])
    assert_eq(0, proc.returncode, "finish-fields rc=0")
    lines = dict(line.split("=", 1) for line in proc.stdout.splitlines() if "=" in line)
    assert_eq("7", lines.get("input_tokens"), "finish-fields input_tokens")
    assert_eq("12", lines.get("total_tokens"), "finish-fields total_tokens")
    assert_eq("2", lines.get("cached_input_tokens"), "finish-fields cached_input_tokens")
    assert_eq("3", lines.get("cache_creation_input_tokens"), "finish-fields cache_creation_input_tokens")
    assert_eq("5", lines.get("output_tokens"), "finish-fields output_tokens")
    assert_eq("456", lines.get("duration_ms"), "finish-fields duration_ms")
    assert_eq("2", lines.get("command_execution"), "finish-fields command_execution")
    assert_eq("3", lines.get("all_tools"), "finish-fields all_tools")
    assert_eq("1", lines.get("codex_completed"), "finish-fields codex_completed")
    assert_eq("1", lines.get("gemini_success"), "finish-fields gemini_success")
finally:
    os.unlink(finish_path)

proc = run(["finish-fields", "/nonexistent/path-that-cannot-exist.log", "codex"])
ok(
    "command_execution=0" in proc.stdout and "rate_limit=0" in proc.stdout,
    "finish-fields: missing log returns zero/default fields",
    proc.stdout,
)


# ── codex-turn-delta ───────────────────────────────────────────────
print("\ncodex-turn-delta")
with tempfile.NamedTemporaryFile("wb", suffix=".jsonl", delete=False) as f:
    delta_path = f.name
    f.write(b'{"type":"item.completed","item":{"type":"command_execution","command":"one"}}\n')
    f.write(b'{"type":"item.completed","item":{"type":"agent_message","text":"skip"}}\n')
    # Nested JSON-looking output must not inflate the structured count.
    f.write(
        b'{"type":"item.completed","item":{"type":"command_execution",'
        b'"aggregated_output":"{\\"type\\":\\"command_execution\\"}"}}\n'
    )
    partial_offset = f.tell()
    f.write(b'{"type":"item.completed","item":{"type":"command_execution"')
try:
    proc = run(["codex-turn-delta", delta_path, "0"])
    lines = proc.stdout.splitlines()
    assert_eq(0, proc.returncode, "codex-turn-delta exit code")
    assert_eq("count=2", lines[0], "codex-turn-delta counts only completed command executions")
    assert_eq(f"offset={partial_offset}", lines[1], "codex-turn-delta stops before partial line")

    with open(delta_path, "ab") as f:
        f.write(b',"command":"two"}}\n')
    proc = run(["codex-turn-delta", delta_path, str(partial_offset)])
    assert_eq(["count=1", f"offset={os.path.getsize(delta_path)}"], proc.stdout.splitlines(),
              "codex-turn-delta retries and counts completed partial line")

    proc = run(["codex-turn-delta", delta_path, str(os.path.getsize(delta_path) + 100)])
    assert_eq("count=3", proc.stdout.splitlines()[0],
              "codex-turn-delta resets if offset is past truncated file")
finally:
    os.unlink(delta_path)


# ── provider-reset-at ───────────────────────────────────────────────
print("\nprovider-reset-at")

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    p1 = f.name
    future_clock = (dt.datetime.now() + dt.timedelta(minutes=15)).strftime("%I:%M %p").lstrip("0")
    f.write(f"You've hit your usage limit. Please try again at {future_clock}.\n")
try:
    proc = run(["provider-reset-at", p1])
    assert_eq(0, proc.returncode, "absolute time form rc=0")
    out = proc.stdout.strip()
    ok(re.fullmatch(r"\d{9,11}", out) is not None, "prints integer epoch", out)
finally:
    os.unlink(p1)

fixed_now = int(time.mktime(dt.datetime(2026, 6, 14, 23, 18, 0).timetuple()))
with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    p1_stale = f.name
    f.write("You've hit your usage limit. Please try again at 10:55 PM.\n")
try:
    proc = run(["provider-reset-at", p1_stale, "--now-epoch", str(fixed_now)])
    assert_eq(1, proc.returncode, "stale same-day clock reset does not roll to tomorrow")
    assert_eq("", proc.stdout, "stale same-day clock reset → empty stdout")
finally:
    os.unlink(p1_stale)

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    p1_rollover = f.name
    f.write("You've hit your usage limit. Please try again at 12:10 AM.\n")
try:
    proc = run(["provider-reset-at", p1_rollover, "--now-epoch", str(fixed_now)])
    expected = int(time.mktime(dt.datetime(2026, 6, 15, 0, 10, 0).timetuple()))
    assert_eq(0, proc.returncode, "near-midnight next-day clock reset rc=0")
    assert_eq(str(expected), proc.stdout.strip(), "near-midnight next-day clock reset rolls forward")
finally:
    os.unlink(p1_rollover)

# Claude session-limit prose ("resets 9:40am") parses as an absolute clock time.
claude_now = int(time.mktime(dt.datetime(2026, 7, 4, 8, 0, 0).timetuple()))
with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    p_claude = f.name
    f.write('{"type":"agent_message","message":"You\'ve hit your session limit \\u00b7 resets 9:40am"}\n')
try:
    proc = run(["provider-reset-at", p_claude, "--now-epoch", str(claude_now)])
    expected = int(time.mktime(dt.datetime(2026, 7, 4, 9, 40, 0).timetuple()))
    assert_eq(0, proc.returncode, "claude 'resets 9:40am' clock reset rc=0")
    assert_eq(str(expected), proc.stdout.strip(), "claude 'resets 9:40am' → 9:40 same day epoch")
finally:
    os.unlink(p_claude)

with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
    p_rejected_reset = f.name
    f.write(json.dumps({
        "type": "rate_limit_event",
        "rate_limit_info": {"status": "allowed_warning", "resetsAt": 9999999999},
    }, separators=(",", ":")) + "\n")
    f.write(json.dumps({
        "type": "rate_limit_event",
        "rate_limit_info": {"status": "rejected", "resetsAt": 1777850000},
    }, separators=(",", ":")) + "\n")
try:
    proc = run(["provider-reset-at", p_rejected_reset])
    assert_eq(0, proc.returncode, "provider-reset-at rejected rate_limit_event rc=0")
    assert_eq("1777850000", proc.stdout.strip(), "provider-reset-at ignores allowed_warning resetsAt")
finally:
    os.unlink(p_rejected_reset)

# ── iteration-provider-status ───────────────────────────────────────
print("\niteration-provider-status")


def _ips(raw_dir: str, timestamp: str) -> dict:
    proc = run(["iteration-provider-status", raw_dir, timestamp])
    assert proc.returncode == 0, proc.stderr
    out = {}
    for line in proc.stdout.splitlines():
        k, _, v = line.partition("=")
        out[k] = v
    return out


_ips_dir = tempfile.mkdtemp()
try:
    # A refill's -rN log is covered by the session_<ts>_*.log.raw glob.
    Path(_ips_dir, "session_tsref_deep_investigation-1-generic-r1.log.raw").write_text(
        '{"type":"result","api_error_status":429}\n'
        '{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":2000}}\n'
    )
    r = _ips(_ips_dir, "tsref")
    assert_eq("1", r.get("rate_limit"), "iteration-provider-status: refill cap → rate_limit=1")
    assert_eq("capacity_limited", r.get("issue"), "iteration-provider-status: refill cap → capacity_limited")
    assert_eq("2000", r.get("reset_at"), "iteration-provider-status: refill cap reset_at from event")

    # No log for this timestamp → no rejection, empty reset (distinct from unknown).
    r = _ips(_ips_dir, "absent")
    assert_eq("0", r.get("rate_limit"), "iteration-provider-status: no logs → rate_limit=0")
    assert_eq("none", r.get("issue"), "iteration-provider-status: no logs → issue=none")
    assert_eq("", r.get("reset_at"), "iteration-provider-status: no logs → reset_at empty")

    # Transient 5xx with no parseable reset → unknown (distinct from empty).
    Path(_ips_dir, "session_ts2_cold-start-1-generic.log.raw").write_text(
        '{"type":"result","api_error_status":503}\n'
    )
    r = _ips(_ips_dir, "ts2")
    assert_eq("1", r.get("rate_limit"), "iteration-provider-status: 5xx → rate_limit=1")
    assert_eq("transient", r.get("issue"), "iteration-provider-status: 5xx → transient")
    assert_eq("unknown", r.get("reset_at"), "iteration-provider-status: 5xx no reset → unknown")

    # Capacity beats transient across the pool, and reset_at is the max epoch.
    Path(_ips_dir, "session_ts2_deep_investigation-2-shell.log.raw").write_text(
        '{"type":"result","api_error_status":429}\n'
        '{"type":"rate_limit_event","rate_limit_info":{"status":"rejected","resetsAt":5000}}\n'
    )
    r = _ips(_ips_dir, "ts2")
    assert_eq("capacity_limited", r.get("issue"), "iteration-provider-status: capacity beats transient")
    assert_eq("5000", r.get("reset_at"), "iteration-provider-status: reset_at is the pool max")
finally:
    import shutil
    shutil.rmtree(_ips_dir, ignore_errors=True)

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    p2 = f.name
    f.write("rate limited, retry after 15 minutes\n")
try:
    before = int(time.time())
    proc = run(["provider-reset-at", p2])
    after = int(time.time())
    assert_eq(0, proc.returncode, "relative form rc=0")
    parsed = int(proc.stdout.strip())
    ok(
        before + 15 * 60 - 2 <= parsed <= after + 15 * 60 + 2,
        "retry-after 15m yields ~15m from now",
        f"got {parsed}, window [{before + 15 * 60}, {after + 15 * 60}]",
    )
finally:
    os.unlink(p2)

with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
    p3 = f.name
    f.write("a routine log line that mentions nothing about limits\n")
try:
    proc = run(["provider-reset-at", p3])
    assert_eq(1, proc.returncode, "no match → rc=1")
    assert_eq("", proc.stdout, "no match → empty stdout")
finally:
    os.unlink(p3)


# ── claims-activity-since ───────────────────────────────────────────
print("\nclaims-activity-since")
with tempfile.TemporaryDirectory() as td:
    claims = Path(td) / "claims.jsonl"
    rows = [
        {"claimed_at": "2026-05-18T00:00:01Z", "status": "claimed", "card_id": "A-1"},
        {"claimed_at": "2026-05-18T00:00:02Z", "status": "claimed", "card_id": "A-2"},
        {"claimed_at": "2026-05-18T00:00:03Z", "status": "released", "card_id": "A-1"},
        {"claimed_at": "2025-01-01T00:00:00Z", "status": "claimed", "card_id": "OLD"},
    ]
    claims.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    # since well before the rows above → all 4 rows count
    since = 1
    proc = run(["claims-activity-since", str(claims), str(since)])
    assert_eq(0, proc.returncode, "rc=0")
    out = proc.stdout.strip()
    ok("total=4" in out, "total counts every row at/after since", out)
    ok("claimed:3" in out, "histogram counts claimed:3")
    ok("released:1" in out, "histogram counts released:1")
    ok("claimed_ids=[" in out, "claimed_ids list emitted")

    proc = run(["claims-activity-since", str(claims), "99999999999"])
    assert_eq(0, proc.returncode, "future since rc=0")
    assert_eq("", proc.stdout, "future since silent")

    proc = run(["claims-activity-since", str(claims), "not-a-number"])
    assert_eq(0, proc.returncode, "non-numeric since is tolerated silently")
    assert_eq("", proc.stdout, "non-numeric since → empty stdout")


# ── extract-vote-json ───────────────────────────────────────────────
print("\nextract-vote-json")
proc = run(["extract-vote-json"], stdin='noise {"vote":"Promote","conf":0.9} tail')
assert_eq(0, proc.returncode, "Promote rc=0")
assert_eq('{"vote":"Promote","conf":0.9}', proc.stdout.strip(), "extracts trim-free")

proc = run(["extract-vote-json"], stdin='prose\n{"vote": "Reject", "reason": "no repro"}\nmore')
assert_eq(0, proc.returncode, "multi-line Reject rc=0")
ok('"vote": "Reject"' in proc.stdout, "multi-line vote object emitted")

proc = run(["extract-vote-json"], stdin="no vote at all here")
assert_eq(1, proc.returncode, "no vote → rc=1")
assert_eq("", proc.stdout, "no vote → empty stdout")

proc = run(
    ["extract-vote-json"],
    stdin='before {"vote":"Maybe"} mid {"vote":"Uncertain","x":1} after',
)
assert_eq(0, proc.returncode, "invalid-then-valid rc=0")
ok('"vote":"Uncertain"' in proc.stdout, "skips invalid vote, takes valid one")

proc = run(
    ["extract-vote-json"],
    stdin='{"vote":"Promote","note":"contains } and \\" quotes"}',
)
assert_eq(0, proc.returncode, "string-with-brace rc=0")
ok('"vote":"Promote"' in proc.stdout, "balanced parse survives '}' inside strings")

# Invalid escape repair: validators writing prose about escape sequences
# emit bare backslashes ("ESC \ terminates the sequence") that strict JSON
# rejects. The vote must survive with the backslash doubled, and the
# repaired output must itself be valid JSON (downstream jq re-parses it).
proc = run(
    ["extract-vote-json"],
    stdin='{"vote":"Promote","rationale":"a pty run emitted ESC ] 8 then ESC \\ in the label","verified":{"reachability":true}}',
)
assert_eq(0, proc.returncode, "invalid-escape repair rc=0")
repaired = json.loads(proc.stdout)
assert_eq("Promote", repaired.get("vote"), "invalid-escape repair keeps vote")
ok("ESC \\ in the label" in repaired.get("rationale", ""), "repair preserves rationale text")

proc = run(
    ["extract-vote-json"],
    stdin='{"vote":"Reject","rationale":"tab \\t and unicode \\u00e9 stay; bad \\x and \\uZZZZ get doubled"}',
)
assert_eq(0, proc.returncode, "mixed valid/invalid escapes rc=0")
repaired = json.loads(proc.stdout)
assert_eq("Reject", repaired.get("vote"), "mixed-escape repair keeps vote")
ok("tab \t and unicode é" in repaired.get("rationale", ""), "valid escapes decode unchanged")
ok("bad \\x and \\uZZZZ" in repaired.get("rationale", ""), "invalid escapes survive as literal text")

proc = run(["extract-vote-json"], stdin='{"vote":"Promote", broken beyond repair')
assert_eq(1, proc.returncode, "unbalanced garbage still rc=1")


# ── emit-event ──────────────────────────────────────────────────────
print("\nemit-event")
with tempfile.TemporaryDirectory() as td:
    events = Path(td) / "deep" / "state" / "events.jsonl"
    proc = run(
        [
            "emit-event", str(events), "agent-plan",
            "agent=1", "launch=cold-start", "role=writer",
            "--int", "streak=3", "--int", "pending=5",
            "--bool", "productive=true",
        ],
        check=True,
    )
    assert_eq(0, proc.returncode, "emit-event rc=0")
    ok(events.parent.is_dir(), "parent dirs auto-created")
    rows = [json.loads(ln) for ln in events.read_text().splitlines() if ln.strip()]
    assert_eq(1, len(rows), "exactly one row written")
    row = rows[0]
    assert_eq("agent-plan", row["event"], "event field")
    assert_eq("1", row["agent"], "agent string-typed")
    assert_eq("cold-start", row["launch"], "launch string-typed")
    assert_eq(3, row["streak"], "streak coerced to int")
    assert_eq(5, row["pending"], "pending coerced to int")
    assert_eq(True, row["productive"], "productive coerced to bool")
    ok("created_at" in row and row["created_at"].endswith("Z"),
       "created_at present + RFC3339", row.get("created_at"))

    # Second emission appends, doesn't overwrite.
    run(["emit-event", str(events), "subsystem-claim",
         "agent=1", "before=unknown", "after=src/lib"],
        check=True)
    rows = [json.loads(ln) for ln in events.read_text().splitlines() if ln.strip()]
    assert_eq(2, len(rows), "second emission appended")
    assert_eq("subsystem-claim", rows[1]["event"], "second row event")

    # Bad --int value coerces to 0 (matches pre-port jq --argjson default behavior).
    run(["emit-event", str(events), "strategy-status",
         "agent=1", "--int", "streak=not-a-number"],
        check=True)
    rows = [json.loads(ln) for ln in events.read_text().splitlines() if ln.strip()]
    assert_eq(0, rows[2]["streak"], "bad int coerces to 0")

    # Argument shaped like 'key=value=more' keeps the full tail as the value.
    run(["emit-event", str(events), "strategy-rotation",
         "agent=1", "reason=S1 exhausted: drop=here"],
        check=True)
    rows = [json.loads(ln) for ln in events.read_text().splitlines() if ln.strip()]
    assert_eq("S1 exhausted: drop=here", rows[3]["reason"], "value tail preserved")

# Missing parent dir + write failure is silent (best-effort).
with tempfile.TemporaryDirectory() as td:
    # Use a file as the parent so mkdir + write both fail.
    blocker = Path(td) / "not-a-dir"
    blocker.write_text("blocking file")
    target = blocker / "state" / "events.jsonl"
    proc = run(["emit-event", str(target), "agent-plan", "agent=1"])
    assert_eq(0, proc.returncode, "broken target → rc=0 (best-effort)")


# Concurrent appenders must produce one well-formed JSON object per line.
# events.jsonl is shared across parallel agents + orchestrator
# (see docs/development.md logging discipline). This is a property test: each
# subprocess opens, writes one buffered line, and closes — the kernel
# does a single write() per process, which O_APPEND serializes for
# regular files. So the test passes regardless of whether the in-process
# flock around the write is present. The flock + flush-in-locked-region
# matter when a single Python process makes multiple writes on one fd
# or when a write is large enough to be split into multiple os.write()
# syscalls; the test below does not exercise that path. Kept as a
# regression sentinel for "concurrent emit-event produces valid JSONL".
print("\nemit-event concurrent writes")
import threading
with tempfile.TemporaryDirectory() as td:
    events = Path(td) / "state" / "events.jsonl"
    events.parent.mkdir(parents=True, exist_ok=True)
    long_reason = "x" * 8000  # exceeds PIPE_BUF on Linux (4096)
    n_workers = 8
    n_events_per_worker = 25

    def worker(idx: int) -> None:
        for i in range(n_events_per_worker):
            subprocess.run(
                [
                    sys.executable, str(HELPER), "emit-event",
                    str(events), "agent-plan",
                    f"agent={idx}", f"iter={i}",
                    f"reason={long_reason}",
                ],
                check=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    raw_lines = events.read_text().splitlines()
    assert_eq(n_workers * n_events_per_worker, len(raw_lines),
              "every concurrent write produced exactly one line")
    parsed = 0
    for ln in raw_lines:
        if not ln.strip():
            continue
        try:
            row = json.loads(ln)
            ok_row = row.get("event") == "agent-plan" and row.get("reason") == long_reason
            if ok_row:
                parsed += 1
        except json.JSONDecodeError:
            pass
    assert_eq(n_workers * n_events_per_worker, parsed,
              "every line parses as JSON with the long reason intact")


# ── summary ─────────────────────────────────────────────────────────
print(f"\n  \033[1m{PASSED}/{PASSED + FAILED} passed\033[0m")
sys.exit(0 if FAILED == 0 else 1)
