#!/usr/bin/env python3
"""Regression checks for the full 9356915 migration re-review."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import tempfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
import sys
sys.path.insert(0, str(ROOT / "lib"))

import audit_helpers
import benchmark_runner
import build_session_seed
import crash_artifacts
import llm_invoke
import prompt
import triage
import workqueue
from timeout import capture_timeout


passed = failed = 0


def check(value: bool, name: str) -> None:
    global passed, failed
    if value:
        passed += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        failed += 1
        print(f"  \033[0;31m✗\033[0m {name}")


def load_script(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


with tempfile.TemporaryDirectory(prefix="port-rereview-") as temporary:
    root = Path(temporary)

    context = prompt.PromptContext(
        target_root=root, target_slug="demo", results_dir=root,
        reference_dir=root, num_agents=1,
    )
    check(context.mode(1) == "generic", "non-browser prompt workers keep the generic mode contract")

    try:
        audit_helpers.sanitize_target_slug("!!!", str(root / "targets"))
    except ValueError:
        empty_slug_rejected = True
    else:
        empty_slug_rejected = False
    check(empty_slug_rejected, "target slug normalization rejects an empty result")

    raw = root / "raw.jsonl"
    raw.write_text('[]\n42\n{"type":"item.completed","item":{"type":"command_execution","command":"sed -n \'2,4p\' targets/demo/a.c","exit_code":0}}\n')
    reads, _writes, _order, _searches = build_session_seed.parse_raw_log(raw)
    check("targets/demo/a.c" in reads, "session-seed parsing skips valid JSON scalars")

    alias = root / "asan-output.txt"
    alias.write_text("ERROR: AddressSanitizer\n")
    check(crash_artifacts.find_primary_sanitizer([root]) == alias, "legacy sanitizer diagnostic aliases remain discoverable")
    wrapper = root / "testcase.sh"
    wrapper.write_text("#!/bin/sh\nexec \"$BIN\" \"$1\"\n")
    check(
        crash_artifacts.looks_like_shell_wrapper(wrapper)
        and not crash_artifacts.is_testcase_candidate(wrapper),
        "legacy shell wrappers are not mistaken for raw testcases",
    )

    crash = root / "CRASH-1"
    crash.mkdir()
    report = crash / "report.md"
    report.write_text("## Summary\n\nbody\n")
    triage._set_contract_concern(report, "call-sequence outside configured controls")
    check(
        (crash / ".contract-flagged").is_file()
        and "## Contract concern" in report.read_text(),
        "contract concerns retain their report block and machine sidecar",
    )
    triage._clear_contract_concern(report)
    check(
        not (crash / ".contract-flagged").exists()
        and "## Contract concern" not in report.read_text(),
        "stale contract annotations are reconciled away",
    )

    with capture_timeout(
        [sys.executable, "-c", "import sys; sys.stdout.write('x' * 2_000_000)"], 5
    ) as (completed, output):
        check(completed.returncode == 0 and output.stat().st_size == 2_000_000,
              "timeout capture keeps large child output file-backed")

    probe = load_script("probe_rereview", ROOT / "bin" / "probe")
    multi = load_script("sanitizer_multi_rereview", ROOT / "bin" / "run-sanitizer-multi")
    huge = root / "huge.js"
    huge.write_bytes(b"// TARGET: a.c:f:1\n// HYPOTHESIS-ID: H1\n// CATEGORY: state\n")
    with huge.open("ab") as stream:
        stream.truncate(64 * 1024 * 1024)
    check(probe.parse_header(huge)["hypothesis"] == "H1", "probe reads only the bounded testcase header")

    tried = root / "tried inputs.log"
    testcase = root / "input with spaces.bin"
    testcase.write_bytes(b"x")
    with mock.patch.dict(os.environ, {
        "ASAN_RUNS": "2", "ASAN_NO_DIGEST": "1",
        "ASAN_DIGEST_HEAD": "7", "ASAN_DIGEST_TAIL": "9",
        "TRIED_INPUTS_LOG": str(tried), "TARGET": "Mock target frame",
        "CLOSEST_FRAME": "Mock closest frame", "HYPOTHESIS_ID": "H1",
    }, clear=True):
        runner = multi.MultiRun("asan", ["generic", str(testcase)])
        runner.record_tried()
    parsed = workqueue._parse_tried_line(tried.read_text().strip())
    check(
        runner.runs == 2 and runner.no_digest and runner.digest_head == 7
        and runner.digest_tail == 9,
        "legacy ASAN_* controls retain precedence-compatible aliases",
    )
    check(
        parsed.get("testcase") == str(testcase)
        and parsed.get("target") == "Mock target frame"
        and parsed.get("closest") == "Mock closest frame",
        "tried-input records round-trip fields containing spaces",
    )

    prior_home = llm_invoke._gemini_iso_home
    llm_invoke._gemini_iso_home = None
    try:
        with mock.patch.dict(os.environ, {
            "USE_GEMINI_CLI": "1", "TOKENFUZZ_MEMORY_ENABLED": "0",
            "LOGDIR": str(root / "logs"),
        }, clear=False), mock.patch.object(llm_invoke, "_stage_clean_gemini_home", side_effect=OSError("denied")):
            try:
                llm_invoke.memory_env("gemini")
            except RuntimeError:
                isolation_failed_closed = True
            else:
                isolation_failed_closed = False
    finally:
        llm_invoke._gemini_iso_home = prior_home
    check(isolation_failed_closed, "Gemini CLI memory isolation fails closed")

    agy = root / "agy.log"
    agy.write_text("noise\nRESOURCE_EXHAUSTED quota 429\n")
    recovered = root / "agy.raw"
    recovered.write_text("")
    with mock.patch.dict(os.environ, {"AGY_LOG_FILE": str(agy)}, clear=False):
        llm_invoke._capture_agy_cli_log_diag(recovered)
    check("RESOURCE_EXHAUSTED" in recovered.read_text(), "empty Antigravity output recovers bounded provider diagnostics")

    bench = root / "bench"
    (bench / "cells" / "one").mkdir(parents=True)
    (bench / "cells" / "one" / "cell.json").write_text("{}\n")
    (bench / "cells" / "one" / "metrics.json").write_text("{}\n")
    (bench / ".result-signature").write_text(benchmark_runner._result_signature(bench) + "\n")
    (bench / "report.json").write_text("{}\n")
    with mock.patch.object(benchmark_runner, "rebuild_pool") as rebuild, \
         mock.patch.object(benchmark_runner.metrics, "aggregate", return_value={}), \
         mock.patch.object(benchmark_runner.metrics, "crosstab", return_value=""):
        benchmark_runner.update_result(bench, root, "demo", "codex", "fixture", True, "regenerate")
    check(rebuild.called, "fresh benchmark regeneration ignores stale on-disk signatures")

    # run-sanitizer-multi's chunked crash scan must anchor ^ only at real line
    # starts. A MULTILINE ^-token landing mid-line at a 64 KB chunk join must NOT
    # count as a crash (the historical false positive from carrying an arbitrary
    # byte window), while a real crash straddling the boundary still must.
    import re as _re
    abort = _re.compile(r"^==[0-9]+==ABORTING", _re.MULTILINE)
    fp_buf = ["Q"] * 70000
    fp_buf[61000] = "\n"                       # a real line start well before the join
    for i, ch in enumerate("==123==ABORTING"):
        fp_buf[65536 - 4096 + i] = ch          # token mid-line, exactly at the old carry origin
    fp_file = root / "sanitizer-fp.txt"
    fp_file.write_text("".join(fp_buf))
    check(multi._file_matches(fp_file, abort) is False,
          "chunked crash scan does not false-match a ^-token at a mid-line chunk join")
    real_buf = ["R"] * 70000
    real_buf[65530] = "\n"
    for i, ch in enumerate("==9==ABORTING"):
        real_buf[65531 + i] = ch
    real_file = root / "sanitizer-real.txt"
    real_file.write_text("".join(real_buf))
    check(multi._file_matches(real_file, abort) is True,
          "chunked crash scan still detects a real crash straddling a chunk boundary")

print(f"\n{passed}/{passed + failed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
