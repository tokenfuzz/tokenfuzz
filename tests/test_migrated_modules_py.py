#!/usr/bin/env python3
"""Behavior tests for the Python modules that replaced sourced shell libraries."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import audit_runner
import benchmark_runner
import crash_bundle
import edges
import llm_decide
import llm_invoke
import llm_usage
import prompt
import sanitizer
import sanitizer_run
import structured_state
import target_config
import triage
import verdict
import vocab_rules
import timeout
from timeout import run_timeout

passed = failed = 0


def check(condition: bool, name: str, detail: str = "") -> None:
    global passed, failed
    if condition:
        passed += 1
        print(f"  \033[0;32m✓\033[0m {name}")
    else:
        failed += 1
        print(f"  \033[0;31m✗\033[0m {name}")
        if detail:
            print(f"    {detail}")


def equal(expected, actual, name: str) -> None:
    check(expected == actual, name, f"expected={expected!r} actual={actual!r}")


with tempfile.TemporaryDirectory(prefix="migration-modules-") as temporary:
    root = Path(temporary)

    harness_results = root / "harness-layout" / "grok" / "results"
    sibling_index = harness_results.parent / "logs" / "index.jsonl"
    sibling_index.parent.mkdir(parents=True)
    sibling_index.write_text("{}\n", encoding="utf-8")
    # An ancillary in-results log directory must not split final decisions
    # away from the already-populated harness ledger.
    (harness_results / "logs").mkdir(parents=True)
    equal(
        sibling_index, llm_usage.find_usage_index(harness_results),
        "harness usage keeps the sibling ledger when results/logs also exists",
    )
    standalone_results = root / "standalone" / "results"
    standalone_index = standalone_results / "logs" / "index.jsonl"
    standalone_index.parent.mkdir(parents=True)
    standalone_index.write_text("{}\n", encoding="utf-8")
    equal(
        standalone_index, llm_usage.find_usage_index(standalone_results),
        "an existing standalone in-tree ledger remains readable",
    )
    (standalone_results.parent / "logs").mkdir()
    equal(
        standalone_index, llm_usage.find_usage_index(standalone_results),
        "an empty sibling log directory cannot displace an existing in-tree ledger",
    )
    direct_results = root / "model-direct-r1"
    equal(
        direct_results / "logs" / "index.jsonl",
        llm_usage.find_usage_index(direct_results),
        "model-direct usage keeps its in-tree ledger",
    )

    incomplete_cell_dir = root / "incomplete-cell"
    incomplete_cell_dir.mkdir()
    benchmark_runner.write_cell(
        incomplete_cell_dir / "cell.json", "harness", 1, "fixture",
        incomplete_cell_dir / "results", 10, "incomplete", None,
    )
    incomplete_cell = json.loads(
        (incomplete_cell_dir / "cell.json").read_text(encoding="utf-8")
    )
    equal(
        "incomplete", incomplete_cell["run_quality"],
        "artifact-incomplete cell is not mislabeled as provider-limited",
    )
    (incomplete_cell_dir / ".run-quality").write_text(
        "provider_limited\n", encoding="utf-8"
    )
    benchmark_runner.write_cell(
        incomplete_cell_dir / "cell.json", "harness", 1, "fixture",
        incomplete_cell_dir / "results", 10, "incomplete", None,
    )
    limited_cell = json.loads(
        (incomplete_cell_dir / "cell.json").read_text(encoding="utf-8")
    )
    equal(
        "provider_limited", limited_cell["run_quality"],
        "explicit provider-limit evidence retains its specific label",
    )
    cli_cell_dir = root / "cli-incomplete-cell"
    cli_cell_dir.mkdir()
    benchmark_module = __import__("benchmark")
    benchmark_module._cmd_write_cell(SimpleNamespace(
        path=str(cli_cell_dir / "cell.json"), condition="harness",
        replicate="1", experiment="fixture", results_dir=str(cli_cell_dir / "results"),
        wall_seconds="10", status="incomplete", requested_agents="",
        paused_seconds="0",
    ))
    cli_cell = json.loads(
        (cli_cell_dir / "cell.json").read_text(encoding="utf-8")
    )
    equal(
        "incomplete", cli_cell["run_quality"],
        "benchmark metadata CLI uses the same factual incomplete label",
    )
    (cli_cell_dir / ".run-quality").write_text(
        "provider_recovered\n", encoding="utf-8",
    )
    (cli_cell_dir / ".target-artifacts-unowned").touch()
    benchmark_module._cmd_write_cell(SimpleNamespace(
        path=str(cli_cell_dir / "cell.json"), condition="harness",
        replicate="1", experiment="fixture", results_dir=str(cli_cell_dir / "results"),
        wall_seconds="10", status="incomplete", requested_agents="",
        paused_seconds="0",
    ))
    equal(
        "unowned_artifacts",
        json.loads((cli_cell_dir / "cell.json").read_text())["run_quality"],
        "benchmark metadata CLI preserves the unowned-artifact warning",
    )

    # A productive session whose usage was never recorded (the zero-token
    # `primary` row) understates the cell total, so the cell must read
    # `unknown` — not hide behind the `mixed` that measured+estimated
    # decisions produce on every normal cell.
    missing_primary = root / "missing-primary-usage.jsonl"
    missing_primary.write_text(
        '{"backend":"codex","role":"primary","tokens":{"input":0,"output":0}}\n'
        '{"backend":"codex","role":"decision","tokens":{"input":10,"output":2}}\n',
        encoding="utf-8",
    )
    usage = __import__("benchmark").harvest_tokens(missing_primary)
    equal(
        "unknown", usage["token_source"],
        "a missing productive session makes the cell token source unknown",
    )
    # A fully-recorded cell that merely mixes measured + estimated decisions
    # must stay distinguishable from the missing-session case above, or the
    # `unknown` flag is useless.
    measured_estimated = root / "measured-estimated-usage.jsonl"
    measured_estimated.write_text(
        '{"backend":"codex","role":"decision","tokens":{"input":10,"output":2}}\n'
        '{"backend":"codex","role":"decision","estimated":true,'
        '"tokens":{"input":8,"output":1}}\n',
        encoding="utf-8",
    )
    usage_me = __import__("benchmark").harvest_tokens(measured_estimated)
    equal(
        "mixed", usage_me["token_source"],
        "measured+estimated stays 'mixed', distinct from a missing session",
    )
    # A nonzero exit sets usage_complete=false even when the backend reported
    # its full counters and cost first. That spend IS in the total, so the
    # cell is measured — marking it unknown flagged cells missing nothing.
    nonzero_exit = root / "nonzero-exit-usage.jsonl"
    nonzero_exit.write_text(
        '{"backend":"claude","usage_complete":false,'
        '"tokens":{"input":10,"output":2}}\n', encoding="utf-8",
    )
    equal(
        "measured", __import__("benchmark").harvest_tokens(nonzero_exit)["token_source"],
        "a nonzero exit that still reported usage keeps the cell measured",
    )
    check(
        not llm_usage.usage_is_complete(
            {"estimated": False, "tokens": {"input": 0, "output": 0}}, 0,
        ),
        "a successful native session without terminal telemetry is incomplete",
    )

    state = root / "results" / "state"
    state.mkdir(parents=True)
    hypotheses = state / "hypotheses.jsonl"
    hypotheses.write_text(
        '{"agent":"1","status":"PENDING","file":"src/a.c","strategy":"S5"}\n'
        'not-json\n'
        '{"agent":"1","status":"DISCARDED","file":"src/b.c"}\n'
        '{"agent":"2","status":"NEEDS_TESTCASE","file":"lib/x.c"}\n',
        encoding="utf-8",
    )
    counts = structured_state.agent_counts("1", root / "results")
    equal(2, counts["total"], "structured state ignores corrupt JSONL rows")
    equal(1, counts["active"], "structured state counts active statuses")
    with mock.patch.dict(os.environ, {"RESULTS_DIR": str(root / "results")}, clear=False):
        equal("src/a.c", structured_state.agent_subsystem("1"), "structured state preserves generic subsystem paths")
        equal("S5", structured_state.latest_strategy("1"), "structured state reads latest strategy")

    edge_log = root / "edges.log"
    edge_log.write_text("parse_a\nsrc/a.c:10:4\nparse_b\nlib/b.c:2:1\nparse_a\nsrc/a.c:10:9\n", encoding="utf-8")
    extracted = edges.extract(edge_log)
    equal(["parse_a|src/a.c:10", "parse_b|lib/b.c:2"], extracted, "edge extraction de-duplicates and sorts")
    edge_journal = root / "edge-journal"
    edge_journal.write_text("\n".join(extracted) + "\n", encoding="utf-8")
    equal(set(extracted), edges.file_edges(edge_journal), "edge journals load as sets")

    env = {"TARGET_ROOT": str(root / "target"), "AUDIT_BUILD_SUFFIX": "-img42"}
    equal(root / "target" / "build-asan-img42", sanitizer.build_dir("asan", env=env), "sanitizer build suffix is centralized")
    runtime = sanitizer.prepare_runtime_env("asan", {"PATH": "/bin", "ASAN_OPTIONS": "stale"})
    check("ASAN_OPTIONS" in runtime and "MSAN_OPTIONS" not in runtime, "sanitizer runtime keeps only the selected sanitizer options")
    check(sanitizer.validate_fuzzer_name("Parse_target_2"), "sanitizer accepts safe fuzzer names")
    check(not sanitizer.validate_fuzzer_name("../target"), "sanitizer rejects unsafe fuzzer names")
    equal("detect_leaks=0", sanitizer.runtime_options("asan", "detect_leaks=0", {}), "sanitizer options preserve explicit base")
    equal(
        "base:symbolize=1:symbolize=0",
        sanitizer.runtime_options(
            "asan", "base", {"ASAN_OPTIONS": "symbolize=1"}, "symbolize=0"
        ),
        "forced sanitizer options follow and override the ambient environment",
    )
    option_rows = []
    for line in sanitizer.OPTIONS_FILE.read_text(encoding="utf-8").splitlines():
        fields = line.split(None, 2)
        if len(fields) == 3 and not fields[0].startswith("#"):
            option_rows.append(tuple(fields))
    expected_modes = {
        *(('asan', mode) for mode in ('full', 'minimal', 'js', 'xpcshell', 'fuzz', 'fuzz-repro')),
        *(('ubsan', mode) for mode in ('full', 'minimal', 'js', 'fuzz', 'fuzz-repro')),
        *(('msan', mode) for mode in ('full', 'js', 'fuzz', 'fuzz-repro')),
        *(('tsan', mode) for mode in ('full', 'js', 'fuzz', 'fuzz-repro')),
    }
    check(
        expected_modes <= {(name, mode) for name, mode, _ in option_rows},
        "sanitizer option table covers every supported runtime mode",
    )
    for sanitizer_name, mode, expected in option_rows:
        equal(
            expected,
            sanitizer.options_for(sanitizer_name, mode),
            f"sanitizer option table round-trips {sanitizer_name}/{mode}",
        )

    executable = root / "runner.py"
    executable.write_text("#!/usr/bin/env python3\nimport sys\nprint(open(sys.argv[1]).read().strip())\n", encoding="utf-8")
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    testcase = root / "input.txt"
    testcase.write_text("EXECUTED\n", encoding="utf-8")
    runner = sanitizer_run.SanitizerRunner("ubsan", env={"UBSAN_GENERIC_BIN": str(executable), "PATH": os.environ["PATH"]})
    with mock.patch.object(sanitizer, "symbolize_available", return_value=False):
        equal(0, runner.generic("", 5, [str(testcase)]), "sanitizer generic runner executes configured command")
    accepting = sanitizer_run.SanitizerRunner(
        "ubsan",
        config=SimpleNamespace(
            runner_success_codes=[0, 1],
            runner_env=[],
            sanitizer_bin=lambda _name: "",
        ),
        env={"UBSAN_GENERIC_BIN": str(executable), "PATH": os.environ["PATH"]},
    )
    with mock.patch.object(
        accepting, "_run_symbolized", return_value=SimpleNamespace(returncode=1),
    ):
        equal(0, accepting.generic("", 5, [str(testcase)]),
              "shared sanitizer runner accepts a configured normal rejection exit")
    equal(1, sanitizer_run.run_standard("ubsan", []), "sanitizer runner rejects a missing mode")

    crash_log = root / "verdict-crash.log"
    crash_log.write_text("==7==ERROR: AddressSanitizer: heap-buffer-overflow\n", encoding="utf-8")
    check(verdict.file_has_crash(crash_log), "verdict recognizes an ASan crash")
    crash_log.write_text("WARNING: DATA RACE\n", encoding="utf-8")
    check(verdict.file_has_crash(crash_log), "verdict recognizes a Go race diagnostic")
    crash_log.write_text("panic: runtime error: index out of range\n", encoding="utf-8")
    check(verdict.file_has_crash(crash_log), "verdict recognizes a managed-runtime crash")
    clean_log = root / "verdict-clean.log"
    clean_log.write_text("[probe] asan EXECUTION VERIFIED (post-run, rc=0)\n", encoding="utf-8")
    check(verdict.file_is_clean(clean_log), "verdict recognizes verified clean probe output")
    check(not verdict.file_has_crash(clean_log), "clean execution is not classified as a crash")

    raw_report = root / "raw-symbols.txt"
    raw_report.write_text("    #0 0x123  (/tmp/apptool+0x123)\n", encoding="utf-8")
    symbolizer_command = []
    def _fake_symbolizer(command, **kwargs):
        symbolizer_command.extend(command)
        kwargs["stdout"].write(b"    #0 0x123 in app_parse sample.c:42\n")
        return SimpleNamespace(returncode=0)
    with mock.patch.object(sanitizer.sys, "platform", "darwin"), \
         mock.patch.object(sanitizer.shutil, "which", side_effect=lambda name: "/usr/bin/atos" if name == "atos" else None), \
         mock.patch.object(sanitizer.subprocess, "run", side_effect=_fake_symbolizer):
        sanitizer.symbolize_file(raw_report)
    check(
        "--no-llvm-symbolizer" in symbolizer_command,
        "macOS offline symbolization explicitly prefers debug-map-aware atos",
        repr(symbolizer_command),
    )
    check("sample.c:42" in raw_report.read_text(), "offline symbolization replaces raw frames in place")

    # A sandboxed agent shell can be refused a pty, and atos behind a pty is the
    # only path that symbolizes a macOS debug-map build. Losing it silently cost
    # a whole run its file:line frames, so the converter runs the child per
    # address instead of giving up.
    import clusterfuzz_symbolizer  # noqa: E402
    echo_answer = ["/bin/sh", "-c",
                   'printf "got symbolicator for x\\nANSWER %s\\n" "$1"', "sh"]
    with mock.patch.object(clusterfuzz_symbolizer.pty, "fork",
                           side_effect=OSError("out of pty devices")):
        converter = clusterfuzz_symbolizer.UnbufferedLineConverter(echo_answer)
    equal("ANSWER 0x2a", converter.convert("0x2a"),
          "no pty available still converts an address")
    # A frame nothing can resolve must keep its module and offset: that is all
    # the forensics it has left. Rendering an empty answer as "<addr> in "
    # destroyed it, on the pty path as well as the per-address fallback.
    with mock.patch.object(clusterfuzz_symbolizer.pty, "fork",
                           side_effect=OSError("out of pty devices")):
        darwin = clusterfuzz_symbolizer.DarwinSymbolizer(
            "0x1000", "/nonexistent/sample-bin", "arm64")

    def _keeps_provenance(label):
        frame = darwin.symbolize("0x1000", "/nonexistent/sample-bin", "0x20")
        check(
            bool(frame) and "/nonexistent/sample-bin" in frame[0] and "0x20" in frame[0],
            f"an unresolvable frame keeps its module and offset ({label})",
            repr(frame),
        )

    darwin.atos.args = ["/nonexistent/atos"]
    _keeps_provenance("per-address child cannot run")
    # The same harm on the pty path, where a dead child yields an empty line.
    darwin.atos.convert = lambda line: ""
    _keeps_provenance("symbolizer answers nothing")
    # atos echoes the address back for an offset it cannot resolve inside a
    # binary it did open. Accepting that as a symbol produced "<addr> in 0x…",
    # which no longer looks raw, so the loss was reported as success.
    darwin.atos.convert = lambda line: line
    _keeps_provenance("symbolizer echoes the address back")

    # ASan's dladdr fallback names the function but not the file. Those frames
    # went unrecognized, so a report full of them was declared nothing-to-do.
    dladdr = "    #0 0x1036d4f30 in xmlBufGetChildContent+0x4a0 (/t/libxml2.dylib:arm64+0x84f30)\n"
    check(bool(sanitizer.RAW_FRAME.search(dladdr)),
          "a dladdr frame counts as needing symbolization")
    check(bool(clusterfuzz_symbolizer.STACK_TRACE_LINE_REGEX.match(dladdr)),
          "the symbolizer parses a dladdr frame instead of passing it through")
    check(not sanitizer.RAW_FRAME.search("    #0 0x123 in app_parse sample.c:42\n"),
          "an already symbolized frame is not re-symbolized")
    check(not sanitizer.RAW_FRAME.search("    #4 0x180b37dfc in start (in dyld) + 6988\n"),
          "a resolved frame naming its module is not mistaken for a raw one")

    # The loop resolves only module+offset frames and passes the rest through
    # with their original numbers. Numbering the resolved ones from a counter
    # that never saw the others renumbered a stack's last frame to `#0`, so a
    # repaired report carried two `#0` frames and lost its real order.
    loop = clusterfuzz_symbolizer.SymbolizationLoop()
    loop.symbolize_address = lambda addr, binary, offset, arch: [
        "app_start start.c:7"]
    mixed = (
        "    #0 0x10a in app_update_error report.c:190\n"
        "    #1 0x10a in app_raise_error report.c:718\n"
        "    #2 0x2f0 in app_main main.c:100\n"
        "    #3 0x18e0 in app_start+0x1b4c (/usr/lib/dyld:arm64+0x1fdfc)\n"
    )
    equal("    #3 app_start start.c:7",
          loop.process_stacktrace(mixed).splitlines()[3],
          "a resolved frame keeps its own number instead of restarting at #0")

    # One raw instruction can expand into multiple inline names. The following
    # frame must move with that expansion or the repaired report carries two
    # frames with the same number. Already-symbolized and unresolved raw
    # followers both take the accumulated offset; a new #0 starts a new stack.
    loop = clusterfuzz_symbolizer.SymbolizationLoop()
    loop.symbolize_address = lambda addr, binary, offset, arch: [
        "app_inner child.c:7", "app_outer parent.c:19"]
    expanded = (
        "    #3 0x18e0 in app_outer+0x1b4c (/tmp/app:arm64+0x1fdfc)\n"
        "    #4: 0x2f0 in app_main main.c:100\n"
        "    #5 0x3000  (/tmp/missing:arm64+0x20)\n"
        "    #0 0x10a in worker thread.c:12\n"
    )
    with mock.patch.object(
        loop, "symbolize_address",
        side_effect=[
            ["app_inner child.c:7", "app_outer parent.c:19"],
            None,
        ],
    ):
        numbered = loop.process_stacktrace(expanded).splitlines()
    equal("    #3 app_inner child.c:7", numbered[0],
          "an inline expansion begins at the source frame number")
    equal("    #4 app_outer parent.c:19", numbered[1],
          "an inline expansion extends from the source frame number")
    equal("    #5: 0x2f0 in app_main main.c:100", numbered[2],
          "an already-symbolized follower moves past the inline expansion")
    equal("    #6 0x3000  (/tmp/missing:arm64+0x20)", numbered[3],
          "an unresolved raw follower moves past the inline expansion")
    equal("    #0 0x10a in worker thread.c:12", numbered[4],
          "a second stack resets accumulated inline numbering")

    # A demangled C++ name carries spaces and parentheses. Constraining the
    # symbol text recognized only plain C identifiers, which is why a libxml2
    # validation passed while a C++ target stayed unrepaired and unwarned.
    for name in ("operator new(unsigned long)", "foo::bar(std::__1::string const&)"):
        frame = f"    #0 0x1000 in {name}+0x20 (/tmp/a.dylib:arm64+0x30)\n"
        check(bool(sanitizer.RAW_FRAME.search(frame)),
              f"a dladdr frame named `{name[:24]}` counts as needing symbolization")
        check(bool(clusterfuzz_symbolizer.STACK_TRACE_LINE_REGEX.match(frame)),
              f"the symbolizer parses a dladdr frame named `{name[:24]}`")
        equal(("0", "0x1000", "/tmp/a.dylib", "0x30", "arm64"),
              clusterfuzz_symbolizer.SymbolizationLoop()._line_parser(frame),
              "the module, offset and arch survive a name containing spaces")
    check(not sanitizer.RAW_FRAME.search(
              "    #0 0x1000 in foo::bar(std::string const&) a.cc:10\n"),
          "a symbolized C++ frame is not re-symbolized")

    # An alternate build tree carries a '+' in its directory name, and stopping
    # the module at the first '+' left the whole frame unparsed.
    plus_frame = ("    #0 0x1000 in app_parse+0x20 "
                  "(targets/t/build-asan+cfg-widened-0000000000/lib.dylib:arm64+0x30)\n")
    equal(("0", "0x1000", "targets/t/build-asan+cfg-widened-0000000000/lib.dylib", "0x30", "arm64"),
          clusterfuzz_symbolizer.SymbolizationLoop()._line_parser(plus_frame),
          "a module path containing '+' anchors on the trailing offset")

    # Every backend has an answer that means "resolved nothing": atos echoes the
    # address, with or without the module it opened, and llvm-symbolizer and
    # addr2line answer `??`. Rendering any of them as a symbol discarded the
    # module and offset, so the test is the result, not each tool's shape.
    equal("", clusterfuzz_symbolizer.get_stack_frame("/t/lib.dylib", "0x1000", "??", "??:0:0"),
          "an unresolved llvm/addr2line answer yields no frame at all")
    darwin.atos.convert = lambda line: "0x00000001 (in lib.dylib)"
    _keeps_provenance("symbolizer answers an address plus a module")
    darwin.atos.convert = lambda line: "wrap_free (in libclang_rt.asan_osx_dynamic.dylib) + 124"
    frame = darwin.symbolize("0x1000", "/nonexistent/sample-bin", "0x20")
    check(bool(frame) and "wrap_free" in frame[0],
          "a real symbol with no source file is still kept", repr(frame))
    kept = clusterfuzz_symbolizer.SymbolizationLoop().process_stacktrace(
        "    #0 0x1000  (/t/definitely-not-here.dylib:arm64+0x30)\n")
    check("/t/definitely-not-here.dylib" in kept and "0x30" in kept,
          "a frame nothing could resolve survives the pass intact", repr(kept))

    # Teardown ran straight into the symbolizer's own failure: addr2line exits
    # on a binary that is not there, so the buffered flush inside close()
    # raised BrokenPipeError and threw away a stacktrace the loop had already
    # symbolized. Only Linux picks addr2line, so the fixture is the dead pipe
    # itself rather than a platform the developer may not be on.
    dead = subprocess.Popen(
        [sys.executable, "-c", "raise SystemExit(1)"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
    )
    dead.wait()
    # The payload has to stay inside the write buffer, whose default size grew
    # in 3.14: a larger one flushes on write, so the pipe breaks here instead
    # of inside close() and the fixture never arms.
    dead.stdin.write(b"unflushed")
    saved_pipes = clusterfuzz_symbolizer.pipes
    clusterfuzz_symbolizer.pipes = [dead]
    try:
        clusterfuzz_symbolizer.SymbolizationLoop()._close_pipes()
        closed_cleanly = True
    except OSError:
        closed_cleanly = False
    finally:
        clusterfuzz_symbolizer.pipes = saved_pipes
    check(closed_cleanly, "a symbolizer that already exited cannot fail teardown")

    # Silence is what let a whole run ship address-only stacks while reporting
    # itself clean, so a report that keeps raw frames must say so.
    stubborn = root / "stubborn-symbols.txt"
    stubborn.write_text(dladdr, encoding="utf-8")
    def _no_op_symbolizer(command, **kwargs):
        kwargs["stdout"].write(dladdr.encode())
        return SimpleNamespace(returncode=0)
    warning = io.StringIO()
    with contextlib.redirect_stderr(warning), \
         mock.patch.object(sanitizer.sys, "platform", "darwin"), \
         mock.patch.object(sanitizer.shutil, "which", side_effect=lambda name: "/usr/bin/atos" if name == "atos" else None), \
         mock.patch.object(sanitizer.subprocess, "run", side_effect=_no_op_symbolizer):
        symbolized = sanitizer.symbolize_file(stubborn)
    check(symbolized is False, "a report that keeps raw frames reports failure")
    check(dladdr.strip() in stubborn.read_text(),
          "a failed symbolization leaves the original frames intact")
    check("some stack frames may lack source lines" in warning.getvalue(),
          "a partial symbolization warning does not claim every frame is raw")

    completed = run_timeout([sys.executable, "-c", "print('timeout-ok')"], 2, capture_output=True)
    check(completed.returncode == 0 and completed.stdout.strip() == b"timeout-ok", "timeout runner captures successful commands")
    completed = run_timeout([sys.executable, "-c", "import time; time.sleep(2)"], 1, capture_output=True)
    equal(124, completed.returncode, "timeout runner terminates expired commands")

    # A successful agent that backgrounds a fuzzer must not leave it running:
    # the wrapper reaps the whole session group on a normal (TERM-mode) exit.
    import time as _time
    leak_pidfile = root / "leaked-bg.pid"
    leaked = run_timeout(
        ["sh", "-c", f'sleep 30 & echo $! > "{leak_pidfile}"; exit 0'], 10,
        capture_output=True,
    )
    check(leaked.returncode == 0, "wrapped command that backgrounds a child still exits 0")
    for _ in range(40):
        if leak_pidfile.is_file():
            break
        _time.sleep(0.05)
    bg_pid = int(leak_pidfile.read_text().strip())
    bg_dead = False
    for _ in range(40):
        try:
            os.kill(bg_pid, 0)
            _time.sleep(0.1)
        except OSError:
            bg_dead = True
            break
    if not bg_dead:  # never leave the test's own orphan running
        try:
            os.kill(bg_pid, 9)
        except OSError:
            pass
    check(bg_dead, "normal-exit wrapper reaps a leaked background descendant")

    # An RSS cap must not cost a short command a whole sampling interval. The
    # reap poll and the `ps` sample once shared one tick, so every sanitizer
    # run — the harness's hottest path — slept half a second after its command
    # had already exited. Measured against an uncapped run of the same command
    # so the assertion is about the cap's overhead, not about host speed.
    quick = [sys.executable, "-c", "pass"]
    uncapped = _time.perf_counter()
    run_timeout(quick, 10, capture_output=True)
    uncapped = _time.perf_counter() - uncapped
    capped = _time.perf_counter()
    run_timeout(quick, 10, rss_mb=4096, capture_output=True)
    capped = _time.perf_counter() - capped
    check(capped - uncapped < timeout.RSS_SAMPLE_SECONDS / 2,
          "an RSS cap does not bill a short command a sampling interval")

    with mock.patch.dict(os.environ, {"LLM_DECIDE_MOCK_THREAT_MODEL_SUGGEST": '{"attacker_controls":["bytes"],"reasoning":"fixture"}'}, clear=False):
        equal(
            {"attacker_controls": ["bytes"], "reasoning": "fixture"},
            llm_decide.llm_decide("threat-model-suggest", "attacker_controls,reasoning", "suggest", 2),
            "LLM decision mocks use the Python engine",
        )
    equal("reproducer and external party", vocab_rules.neutralize_line("exploit and attacker"), "vocabulary normalization remains available in Python")

    references = root / "references"
    (references / "strategies").mkdir(parents=True)
    (references / "session-rules.digest.md").write_text("DIGEST\n", encoding="utf-8")
    (root / "target").mkdir()
    results = root / "prompt-results"
    (results / "state").mkdir(parents=True)
    context = prompt.PromptContext(
        results, root / "target", "demo", references, 3,
        is_browser=True, browser_agents=1,
    )
    equal("browser", context.mode(1), "prompt assigns the configured browser worker")
    equal("shell", context.mode(2), "prompt assigns remaining browser-target workers shell mode")
    equal("analysis", context.role(3), "prompt assigns final parallel agent analysis role")
    (results / "state" / "strategy-1").write_text("S7\n", encoding="utf-8")
    equal("S7", context.strategy(1), "prompt reads persisted strategy")
    (results / "work-cards.jsonl").write_text(
        json.dumps({
            "id": "WORK-prompt-card", "kind": "ranked-source", "target_slug": "demo",
            "subsystem": "src/parser", "file": "src/parser/input.c", "mode": "browser",
            "strategy": "S7", "score": 80, "reason": "input parser",
            "status": "unclaimed",
        }) + "\n",
        encoding="utf-8",
    )
    assigned = prompt.work_card_directive(context, 1, force=True)
    check(
        "WORK-prompt-card" in assigned and "ASSIGNED WORK CARD" in assigned,
        "prompt claims and renders a real work card through the queue API",
        assigned,
    )
    static = prompt.write_static_prompt_file(context)
    check(static.is_file() and "DIGEST" in static.read_text(encoding="utf-8"), "prompt writes cached static rules atomically")
    context.turn_soft_cap = 17
    prompt.write_static_prompt_file(context)
    check(
        "~17 agent/tool turns" in prompt.common_suffix(context),
        "prompt refreshes a cached turn budget when a results tree is reused",
    )
    context.turn_soft_cap = prompt.DEFAULT_TURN_SOFT_CAP
    prompt.write_static_prompt_file(context)
    cold = prompt.cold_start_prompt(context, 1)
    check("Agent 1" in cold and "ROLE: REPRODUCE" in cold, "cold prompt renders role and agent identity")
    check(
        "BUILD CONFIGURATION" not in cold,
        "browser prompts do not advertise native alternate-build controls",
        cold,
    )
    check(
        "--role reproduce --strategy S7" in cold
        and "reproduce--strategy" not in cold,
        "cold prompt renders a parseable strategy-bearing state resume command",
    )
    static_text = static.read_text(encoding="utf-8")
    check(
        "bin/state resume --agent N" in static_text
        and "bin/state resume --agent `" not in static_text,
        "static prompt suffix keeps its compression resume command agent-neutral",
    )
    generic_target = root / "generic-target"
    (generic_target / "build-asan").mkdir(parents=True)
    generic_config = target_config.Config(
        target_root=str(generic_target), sanitizers_enabled=["ubsan"],
        attacker_controls=["bytes", "call-sequence"], includes=["include"],
        link_libs=["-lsample"], runner_bin="python3",
    )
    generic_context = prompt.PromptContext(
        results, generic_target, "demo", references, 2, config=generic_config,
    )
    generic_cold = prompt.cold_start_prompt(generic_context, 1)
    check(
        "It is not legitimate for the testcase" in generic_cold
        and "free the active callback state itself" in generic_cold
        and "silence in the docs means the contract is in-domain" not in generic_cold,
        "safety rules reject testcase-driven callback self-destruction",
    )
    directive = prompt.sanitizer_build_directive(generic_context)
    check(
        "build-asan" in directive and "ubsan" in directive,
        "generic prompt reports the mandatory ASan build and selected sanitizer",
        directive,
    )
    check(
        "attacker_controls`: `bytes,call-sequence`" in directive
        and "`link_libs`: `-lsample`" in directive,
        "generic prompt injects parsed threat-model and harness config",
        directive,
    )
    cache = results / "scratch-1" / ".harness-cache"
    cache.mkdir(parents=True)
    for index in range(3):
        (cache / f"fixture-{index}.build.log").write_text("missing header\n", encoding="utf-8")
    failure_directive = prompt.harness_build_failures_directive(generic_context)
    check(
        "PERSISTENT HARNESS BUILD FAILURES" in failure_directive
        and "target.toml" in failure_directive,
        "generic prompt surfaces persistent harness build failures",
        failure_directive,
    )
    (results / "work-cards.jsonl").write_text('{"id":"WORK-1"}\n', encoding="utf-8")
    card_payload = {
        "id": "WORK-1", "kind": "ranked-source", "subsystem": "parser",
        "file": "src/parser.c", "strategy": "S7", "score": 90,
        "reason": "structural rank", "fix_hashes": ["abc123"],
    }
    with mock.patch.object(prompt.workqueue, "claim_next_card", return_value=card_payload), \
         mock.patch.object(structured_state, "agent_counts", return_value=None):
        directive = prompt.work_card_directive(context, 1)
    check("src/parser.c" in directive and "abc123" in directive, "prompt renders work-card detail")

    # What claim_next_card actually returns for a carried angle: relabelled to
    # the claiming lane, with the card's own strategy kept as provenance.
    companion_payload = {
        **card_payload, "strategy": "S7", "source_strategy": "S2",
        "allowed_strategies": ["S7"],
    }
    with mock.patch.object(prompt.workqueue, "claim_next_card", return_value=companion_payload), \
         mock.patch.object(structured_state, "agent_counts", return_value=None):
        companion_directive = prompt.work_card_directive(context, 1)
    check(
        "**Strategy:** S7" in companion_directive
        and "**Card primary strategy:** S2" in companion_directive
        and "minimal deterministic public-API harness" in companion_directive
        and "NO_EXEC: <proof>" in companion_directive,
        "initial prompts label and instruct the assigned S7 companion strategy",
        companion_directive,
    )
    compact_after_claim = prompt.deep_investigation_prompt(context, 1)
    check(
        "COMPACT FRESH START" in compact_after_claim
        and not audit_runner._cold(SimpleNamespace(num_agents=1, results=results)),
        "a claimed card makes a no-hypothesis relaunch compact instead of cold",
        compact_after_claim,
    )
    (results / "state" / "strategy-1").write_text("S7\n", encoding="utf-8")

    equal("null-deref", triage.autodiscard_reason("Hint: address points to the zero page"), "triage rejects null dereferences")
    equal("", triage.autodiscard_reason("ERROR: AddressSanitizer: heap-buffer-overflow"), "triage retains memory-safety diagnostics")
    equal(("promote", "trigger within attacker_controls=bytes"), triage.evaluate_crash_verdict("Trigger source: bytes\n", ["bytes"]), "triage promotes in-contract triggers")
    equal(
        ("incomplete", "report has no Caller contract or Trigger source field"),
        triage.evaluate_crash_verdict("## Summary\nCrash details only.\n", ["bytes"]),
        "triage does not promote reports missing contract and trigger fields",
    )
    verdict, reason = triage.evaluate_crash_verdict("Trigger source: env\n", ["bytes"])
    check(verdict == "out-of-model" and "env" in reason, "triage flags out-of-contract triggers without discarding")
    verdict, _ = triage.evaluate_crash_verdict(
        "Caller controls: bytes\nParameter control: harness-only\nTrigger source: input\n",
        ["bytes"],
    )
    # Admitted misuse is the report's own words, so it is dispositive; only the
    # threat-model set difference is a self-report a reviewer may correct.
    equal("contract-flag", verdict, "triage reads Parameter control independently from Caller controls")
    verdict, _ = triage.evaluate_crash_verdict("Trigger source: both\n", ["bytes"])
    equal("out-of-model", verdict, "triage expands both into bytes plus call-sequence")

    rejected_results = root / "triage-results"
    crash = rejected_results / "crashes" / "CRASH-001"
    crash.mkdir(parents=True)
    # A crash with no sanitizer evidence is held promotion-pending, not rejected
    # on the first pass — a real crash still being bundled must not be lost. It
    # ages out to crashes-rejected/ only after CRASH_PROMOTION_PENDING_MAX passes.
    equal(
        "pending",
        triage.triage_one_crash(crash, rejected_results, root / "target", "demo", ["bytes"]),
        "triage holds a crash without sanitizer evidence promotion-pending",
    )
    with mock.patch.dict(os.environ, {"CRASH_PROMOTION_PENDING_MAX": "1"}, clear=False):
        equal(
            "rejected",
            triage.triage_one_crash(crash, rejected_results, root / "target", "demo", ["bytes"]),
            "triage quarantines a crash that never produces sanitizer evidence",
        )
    check((rejected_results / "crashes-rejected" / "CRASH-001" / "REJECTION.md").is_file(), "triage preserves a rejection rationale")

    findings = rejected_results / "findings"
    accepted = findings / "FIND-ACCEPTED"
    accepted.mkdir(parents=True)
    (accepted / "report.md").write_text("# Concrete issue\n\nsrc/a.c:10 bounds issue\n", encoding="utf-8")
    (accepted / ".llm-find-quality.json").write_text(json.dumps({"decision_version": triage.report_identity.FIND_QUALITY_DECISION_VERSION, "accept": True, "accept_count": 2}), encoding="utf-8")
    equal(
        "pending",
        triage.validate_one_finding(accepted, rejected_results),
        "quality-only cached quorum remains pending without source validation",
    )
    batched_pending = findings / "FIND-BATCH-PENDING"
    batched_pending.mkdir()
    (batched_pending / "report.md").write_text("# Concrete issue\n\nsrc/c.c:30 state issue\n", encoding="utf-8")
    with mock.patch.object(triage, "_quality_vote", side_effect=AssertionError("individual fan-out")):
        equal(
            "pending",
            triage.validate_one_finding(
                batched_pending, rejected_results, initial_votes=[],
            ),
            "missing batch votes stay pending without individual quality fan-out",
        )
    with mock.patch.dict(
        os.environ,
        {"ACTIVE_BACKEND": "claude", "TARGET_ROOT": str(root)},
        clear=False,
    ), mock.patch.object(triage.llm_decide, "provider_limit_open", return_value=True):
        equal(
            {accepted},
            triage._batch_finding_trigger_votes(
                [accepted], rejected_results, None, None, False,
            ),
            "provider-limited trigger batches leave quality-accepted findings pending",
        )
    pending = findings / "FIND-PENDING"
    pending.mkdir()
    equal("pending", triage.validate_one_finding(pending, rejected_results), "finding gate leaves missing reports pending")
    check((pending / ".needs-content").is_file(), "finding gate marks reports needing content")
    rejected = findings / "FIND-REJECTED"
    rejected.mkdir()
    (rejected / "report.md").write_text("# Concrete issue\n\nsrc/b.c:20 state issue\n", encoding="utf-8")
    (rejected / ".llm-find-quality.json").write_text(json.dumps({"decision_version": triage.report_identity.FIND_QUALITY_DECISION_VERSION, "accept": False, "reject_count": 2, "reason": "not security relevant"}), encoding="utf-8")
    equal("rejected", triage.validate_one_finding(rejected, rejected_results), "finding gate quarantines cached reject quorums")
    check((rejected_results / "findings-rejected" / "FIND-REJECTED" / "REJECTION.md").is_file(), "finding rejection keeps the validator rationale")

    check(crash_bundle.should_file("CRASH", "asan", 5), "crash bundle files confirmed sanitizer crashes")
    check(not crash_bundle.should_file("CLEAN", "asan", 5), "crash bundle rejects clean probes")
    check(not crash_bundle.should_file("CRASH", "asan", 1), "crash bundle requires confirmation runs")
    bundle_results = root / "bundle-results"
    bundle_case = root / "bundle.dat"
    bundle_case.write_text("input\n", encoding="utf-8")
    bundle_san = root / "bundle.asan.txt"
    bundle_san.write_text("ERROR: AddressSanitizer: heap-buffer-overflow\n", encoding="utf-8")
    outcome, crash_id = crash_bundle.materialize(
        bundle_results, "2", bundle_case, bundle_san, "asan", "generic",
        args=("--decode",), target="src/decode.c:parse:10", hypothesis="H-1", strategy="S7",
    )
    equal("FILED", outcome, "crash bundle materializes a first confirmed diagnostic")
    bundle_dir = bundle_results / "crashes" / crash_id
    check((bundle_dir / "report.md").is_file() and (bundle_dir / "repro.cmd").is_file(), "crash bundle includes report and replay arguments")
    equal(
        ["{TESTCASE}", "--decode"],
        shlex.split((bundle_dir / "repro.cmd").read_text().splitlines()[-1]),
        "crash bundle keeps trailing probe arguments after the testcase",
    )
    template_case = root / "template-bundle.dat"
    template_case.write_text("input\n", encoding="utf-8")
    _, template_id = crash_bundle.materialize(
        bundle_results, "2", template_case, bundle_san, "asan", "generic",
        args=("--input", "{TESTCASE}", "--sink", "/dev/null"),
    )
    equal(
        ["--input", "{TESTCASE}", "--sink", "/dev/null"],
        shlex.split(
            (bundle_results / "crashes" / template_id / "repro.cmd")
            .read_text().splitlines()[-1]
        ),
        "crash bundle preserves a learned runner template's testcase position",
    )
    created_at = (bundle_dir / ".crash-created-at").read_text(encoding="utf-8")
    check(bool(created_at.strip()), "crash bundle records its immutable filing clock")
    original_evidence = crash_bundle.recorded_evidence_context(bundle_dir)
    bundle_san.write_text(
        "ERROR: AddressSanitizer: heap-buffer-overflow\nconfirmation run\n",
        encoding="utf-8",
    )
    duplicate, duplicate_id = crash_bundle.materialize(
        bundle_results, "2", bundle_case, bundle_san, "asan", "generic", args=("--decode",)
    )
    equal(("DUP", crash_id), (duplicate, duplicate_id), "crash bundle identity prevents duplicate filing")
    equal(
        original_evidence,
        crash_bundle.recorded_evidence_context(bundle_dir),
        "duplicate confirmation cannot bind context to unsaved diagnostic output",
    )
    equal(
        created_at,
        (bundle_dir / ".crash-created-at").read_text(encoding="utf-8"),
        "duplicate confirmation does not rewrite the filing clock",
    )

    # A crash directory can hold more than one main()-bearing source; only the
    # receipt says which one probe compiled, so exporters must read it rather
    # than pick by name — and must not fall back to a guess when it says
    # something they dislike.
    built_harness = root / "H-9-driver.c"
    built_harness.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    harness_case = root / "harness-bundle.dat"
    harness_case.write_text("input\n", encoding="utf-8")
    _, harness_id = crash_bundle.materialize(
        bundle_results, "2", harness_case, bundle_san, "asan", "generic",
        harness=built_harness,
    )
    harness_dir = bundle_results / "crashes" / harness_id
    (harness_dir / "harness.c").write_text(
        "int main(void) { return 1; }\n", encoding="utf-8",
    )
    recorded = crash_bundle.receipt_artifacts(harness_dir)
    equal(
        built_harness.name, getattr(recorded[1], "name", None),
        "recorded harness wins over a harness-named sibling in the crash dir",
    )
    equal(
        harness_case.name, getattr(recorded[0], "name", None),
        "the receipt binds the testcase too, not only the harness",
    )
    equal(
        ["{TESTCASE}"], recorded[2],
        "the receipt binds the replay arguments too",
    )

    nocase = root / "no-harness.dat"
    nocase.write_text("input\n", encoding="utf-8")
    _, nohar_id = crash_bundle.materialize(
        bundle_results, "2", nocase, bundle_san, "asan", "generic",
    )
    nohar_dir = bundle_results / "crashes" / nohar_id
    (nohar_dir / "harness.c").write_text(
        "int main(void) { return 1; }\n", encoding="utf-8",
    )
    equal(
        False, crash_bundle.receipt_artifacts(nohar_dir)[1],
        "a receipt recording no harness does not send the caller back to discovery",
    )

    (harness_dir / built_harness.name).write_text(
        "int main(void) { return 2; }\n", encoding="utf-8",
    )
    raised = ""
    try:
        crash_bundle.receipt_artifacts(harness_dir)
    except crash_bundle.ReceiptError as exc:
        raised = str(exc)
    check(
        "does not match the evidence" in raised,
        "an edited harness fails the receipt loudly instead of exporting a guess",
    )
    equal(
        None, crash_bundle.receipt_artifacts(root / "no-such-crash"),
        "a crash with no receipt still leaves discovery in charge",
    )

    original_path_open = Path.open

    def fail_bundle_index(path, *args, **kwargs):
        if path.name == ".probe-filed-3.tsv" and args and "a" in args[0]:
            raise PermissionError("synthetic index failure")
        return original_path_open(path, *args, **kwargs)

    warnings = io.StringIO()
    with mock.patch.object(Path, "open", fail_bundle_index), contextlib.redirect_stderr(warnings):
        filed, unindexed_id = crash_bundle.materialize(
            bundle_results, "3", bundle_case, bundle_san, "asan", "generic"
        )
    equal("FILED", filed, "crash bundle remains filed when only its dedup index is unwritable")
    check(
        (bundle_results / "crashes" / unindexed_id / "report.md").is_file()
        and "dedup index update failed" in warnings.getvalue(),
        "crash bundle preserves evidence and reports the failed index update",
    )
    duplicate, duplicate_id = crash_bundle.materialize(
        bundle_results, "3", bundle_case, bundle_san, "asan", "generic"
    )
    equal(
        ("DUP", unindexed_id), (duplicate, duplicate_id),
        "bundle-local identity preserves dedup when the optional index was not written",
    )

    direct_target = root / "direct-target"
    (direct_target / "src").mkdir(parents=True)
    (direct_target / "src" / "app.c").write_text("int app_parse(void) { return 0; }\n")
    direct_binary = direct_target / "build-asan" / "app"
    direct_binary.parent.mkdir()
    direct_binary.write_bytes(b"sanitizer build\n")
    direct_binary.chmod(0o755)
    direct_case = root / "direct-input.bin"
    direct_case.write_bytes(b"input")
    direct_san = root / "direct.asan.txt"
    direct_san.write_text(
        "ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "    #0 0x1 in app_parse src/app.c:1\n"
        "CRASH_RATE: 5/5\n",
        encoding="utf-8",
    )
    direct_results = root / "direct-results"
    _, direct_id = crash_bundle.materialize(
        direct_results, "1", direct_case, direct_san, "asan", "generic",
        binary=direct_binary,
    )
    direct_crash = direct_results / "crashes" / direct_id
    direct_context = crash_bundle.verified_probe_context(direct_crash)
    check(direct_context is not None, "probe context verifies testcase and sanitizer build identity")
    _ctx_path = direct_crash / ".probe-context.json"
    _ctx_v1 = _ctx_path.read_text()
    _ctx_v2 = json.loads(_ctx_v1); _ctx_v2["version"] = 2
    _ctx_path.write_text(json.dumps(_ctx_v2), encoding="utf-8")
    check(
        crash_bundle.verified_probe_context(direct_crash) is not None,
        "probe context version 2 is accepted (resume compatibility)",
    )
    _ctx_path.write_text(_ctx_v1, encoding="utf-8")  # restore v1 for the flow below
    check(
        triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
        "5/5 standard target byte-input crash bypasses only trigger review",
    )
    check(
        (direct_crash / ".trigger-gate-bypass.json").is_file(),
        "trigger bypass leaves machine-readable provenance",
    )
    published_results = root / "published-results"
    nested_crash = published_results / "session" / "results" / "crashes" / direct_id
    nested_crash.parent.mkdir(parents=True)
    shutil.copytree(direct_crash, nested_crash)
    published_crash = published_results / "crashes" / "CRASH-1"
    published_crash.mkdir(parents=True)
    shutil.copy2(direct_crash / direct_case.name, published_crash / "input.bin")
    shutil.copy2(direct_crash / "sanitizer.txt", published_crash / "sanitizer.txt")
    (published_crash / "report.md").write_text("Trigger source: bytes\n", encoding="utf-8")
    with mock.patch.object(benchmark_runner.triage, "triage_crash_dirs", return_value={"promoted": 1}):
        benchmark_runner.triage_cell_crashes(
            published_results, direct_target, "direct-target", workers=1,
        )
    check(
        crash_bundle.verified_probe_context(published_crash) is not None
        and triage._direct_probe_trigger_bypass(published_crash, direct_target, ["bytes"]),
        "model-direct triage restores exact nested probe provenance after testcase rename",
    )
    unreplayable_results = root / "unreplayable-results"
    unreplayable = unreplayable_results / "crashes" / "CRASH-1"
    unreplayable.mkdir(parents=True)
    (unreplayable / "sanitizer.txt").write_text(
        "ERROR: AddressSanitizer: heap-buffer-overflow\n", encoding="utf-8",
    )
    (unreplayable / "report.md").write_text("# Concrete crash\n", encoding="utf-8")
    (unreplayable / "input.bin").write_bytes(b"input")
    with mock.patch.object(
        benchmark_runner.triage, "triage_crash_dirs",
        return_value={"promoted": 0, "rejected": 0, "demoted": 0, "pending": 0},
    ), mock.patch.object(benchmark_runner, "_resolve_reverify_fields", return_value=None):
        replay_counts = benchmark_runner.triage_cell_crashes(
            unreplayable_results, direct_target, "direct-target", workers=1,
            require_replay=True,
        )
    check(
        replay_counts["promoted"] == 0
        and replay_counts["demoted"] == 0
        and replay_counts["unreplayed"] == 1
        and (unreplayable / "sanitizer.txt").is_file()
        and not (unreplayable_results / "findings").exists(),
        "a resolver that finds no contract leaves a saved reproducer a crash",
    )
    def _replay_outcome(status, name):
        outcome_results = root / name
        shutil.copytree(
            unreplayable, outcome_results / "crashes" / "CRASH-1",
        )
        adjudicated = {}

        def _record(*_args, **kwargs):
            adjudicated.update(kwargs)
            return {"promoted": 0, "rejected": 0, "demoted": 0, "pending": 0}

        with mock.patch.object(
            benchmark_runner.triage, "triage_crash_dirs", side_effect=_record,
        ), mock.patch.object(
            benchmark_runner, "_resolve_reverify_fields",
            return_value=({"MODE": "generic", "BIN": "fixture"}, []),
        ), mock.patch.object(
            benchmark_runner, "reverify_one_crash", return_value=status,
        ):
            counts = benchmark_runner.triage_cell_crashes(
                outcome_results, direct_target, "direct-target", workers=1,
                require_replay=True,
            )
        return outcome_results, counts, adjudicated.get("held") or set()

    # A replay that never ran says nothing about the crash — neither that it is
    # real nor that it is not. Demoting on it emptied a whole condition's crash
    # column; adjudicating on it would credit crashes no replay ever measured.
    unmeasured_results, unmeasured_counts, unmeasured_held = _replay_outcome(
        "unmeasured", "unmeasured-replay-results",
    )
    check(
        unmeasured_counts["demoted"] == 0
        and unmeasured_counts["unreplayed"] == 1
        and (unmeasured_results / "crashes" / "CRASH-1").is_dir()
        and not (unmeasured_results / "findings" / "FIND-1").exists()
        and unmeasured_held == {unmeasured_results / "crashes" / "CRASH-1"},
        "a model-direct crash whose replay could not run is withheld, not demoted",
    )
    failed_replay_results, failed_replay_counts, _ = _replay_outcome(
        "mismatch", "failed-replay-results",
    )
    check(
        failed_replay_counts["promoted"] == 0
        and failed_replay_counts["demoted"] == 1
        and (failed_replay_results / "findings" / "FIND-1").is_dir(),
        "a model-direct crash whose replay returned another fault becomes a finding",
    )
    standard_replay = root / "standard-replay" / "CRASH-1"
    shutil.copytree(failed_replay_results / "findings" / "FIND-1", standard_replay)

    def _record_standard_replay(crash_dir, _target, _slug):
        with (crash_dir / "sanitizer.txt").open("a", encoding="utf-8") as stream:
            stream.write("CRASH_RATE: 5/5\n")
        return "reproduced"

    with mock.patch.object(
        benchmark_runner.triage, "_direct_probe_trigger_bypass", return_value=False,
    ), mock.patch.object(
        benchmark_runner, "_resolve_reverify_fields",
        return_value=({"MODE": "cli", "BIN": str(direct_binary)}, []),
    ), mock.patch.object(
        benchmark_runner, "reverify_one_crash", side_effect=_record_standard_replay,
    ), mock.patch.object(
        benchmark_runner.triage, "_fault_frame_is_in_target", return_value=True,
    ):
        equal(
            "bypass",
            benchmark_runner._verify_model_direct_crash(
                standard_replay, direct_target, "direct-target", ["bytes"],
            ),
            "a configured-target 5/5 replay bypasses redundant trigger review",
        )
    zero_rate = root / "zero-rate-crashes" / "CRASH-1"
    zero_rate.mkdir(parents=True)
    (zero_rate / "sanitizer.txt").write_text(
        "ERROR: AddressSanitizer: heap-buffer-overflow\nCRASH_RATE: 0/5\n",
        encoding="utf-8",
    )
    equal(
        (0, []), __import__("benchmark").count_confirmed_crashes(zero_rate.parent),
        "a measured zero-rate diagnostic cannot inflate benchmark crash counts",
    )
    equal(
        0,
        benchmark_runner._runs_reproducing(
            "SUMMARY: AddressSanitizer: heap-buffer-overflow child.c:9",
            "=== Run 1/1 ===\nSUMMARY: AddressSanitizer: ABRT child.c:8\n",
        ),
        "reverify cannot substitute an assertion abort for the reported memory fault",
    )
    mismatched = published_results / "crashes" / "CRASH-2"
    shutil.copytree(published_crash, mismatched)
    (mismatched / ".probe-context.json").unlink()
    (mismatched / ".probe-identity").unlink()
    (mismatched / "sanitizer.txt").write_text("different evidence\n", encoding="utf-8")
    check(
        not crash_bundle.restore_probe_context([nested_crash], mismatched),
        "model-direct provenance recovery fails closed on changed sanitizer evidence",
    )
    with mock.patch.object(crash_bundle, "verified_probe_context", return_value={
        **direct_context, "harness": True,
    }):
        check(
            not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
            "custom harness evidence cannot bypass trigger review",
        )
    with mock.patch.object(crash_bundle, "verified_probe_context", return_value={
        **direct_context, "args": ["--nonstandard"],
    }):
        check(
            not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
            "non-standard argv cannot bypass trigger review",
        )
    with mock.patch.object(crash_bundle, "verified_probe_context", return_value={
        **direct_context, "build_config_id": "wide-id",
    }), mock.patch.object(crash_bundle, "verified_primary_differential", return_value=None):
        check(
            not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
            "alternate-config crash cannot bypass trigger review without a primary differential",
        )
    with mock.patch.object(crash_bundle, "verified_probe_context", return_value={
        **direct_context, "build_config_id": "wide-id",
    }), mock.patch.object(crash_bundle, "verified_primary_differential", return_value={
        "status": "reproduced",
    }):
        check(
            triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
            "same-fault primary reproduction restores the direct byte-path bypass",
        )
    check(
        not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["call-sequence"]),
        "out-of-model input cannot bypass trigger review",
    )
    filed_sanitizer = direct_crash / "sanitizer.txt"
    filed_sanitizer.write_text(
        "ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "    #0 0x1 in app_parse src/app.c:1\n"
        "CRASH_RATE: 4/5\n",
        encoding="utf-8",
    )
    check(
        not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
        "non-deterministic crash cannot bypass trigger review",
    )
    filed_sanitizer.write_text(
        "ERROR: AddressSanitizer: heap-buffer-overflow\n"
        "    #0 0x1 in wrapper /outside/wrapper.c:1\n"
        "CRASH_RATE: 5/5\n",
        encoding="utf-8",
    )
    check(
        not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
        "fault frame outside the target cannot bypass trigger review",
    )
    filed_sanitizer.write_text(direct_san.read_text(encoding="utf-8"), encoding="utf-8")
    with mock.patch.object(triage, "_direct_probe_trigger_bypass", return_value=True), \
         mock.patch.object(triage, "_trigger_vote") as trigger_vote:
        check(
            triage._crash_trigger_gate(
                direct_crash, direct_crash / "report.md", direct_target,
                attacker_controls=["bytes"],
            ) is False and trigger_vote.call_count == 0,
            "direct proof bypasses only the LLM trigger votes",
        )
    filed_testcase = direct_crash / direct_case.name
    filed_testcase.write_bytes(b"changed input")
    check(
        crash_bundle.verified_probe_context(direct_crash) is None,
        "changed testcase invalidates direct-probe evidence",
    )
    filed_testcase.write_bytes(direct_case.read_bytes())
    direct_binary.write_bytes(b"changed sanitizer build\n")
    check(
        crash_bundle.verified_probe_context(direct_crash) is None
        and not triage._direct_probe_trigger_bypass(direct_crash, direct_target, ["bytes"]),
        "changed sanitizer build invalidates direct-probe bypass",
    )

    artifact_target = root / "artifact-target"
    old = artifact_target / "findings" / "FIND-OLD"
    old.mkdir(parents=True)
    destination = root / "cell"
    destination.mkdir()
    with benchmark_runner._target_artifact_guard(
        artifact_target, destination,
    ):
        new = artifact_target / "findings" / "FIND-NEW"
        new.mkdir()
    check(
        old.is_dir() and new.is_dir()
        and not (destination / ".target-artifacts-unowned").exists()
        and not (destination / ".run-quality").exists(),
        "an empty target artifact shell is not benchmark evidence",
    )
    with benchmark_runner._target_artifact_guard(
        artifact_target, destination,
    ):
        evidence = artifact_target / "findings" / "FIND-EVIDENCE"
        evidence.mkdir()
        (evidence / "report.md").write_text("substantive report\n")
    check(
        evidence.is_dir()
        and (destination / ".target-artifacts-unowned").is_file()
        and (destination / ".run-quality").read_text().strip()
        == "unowned_artifacts",
        "benchmark preserves and marks substantive unowned target evidence",
    )
    propagated = False
    try:
        with benchmark_runner._target_artifact_guard(
            artifact_target, destination,
        ):
            raise RuntimeError("cell launch failed")
    except RuntimeError:
        propagated = True
    check(propagated, "target artifact guard preserves cell launch failures")

    scratch_cell = root / "scratch-cell"
    (scratch_cell / "scratch" / "nested").mkdir(parents=True)
    (scratch_cell / "scratch-1").mkdir()
    benchmark_runner.cleanup_model_direct_scratch(scratch_cell)
    check(not (scratch_cell / "scratch").exists() and (scratch_cell / "scratch-1").is_dir(), "benchmark cleanup is scoped to model-direct scratch")

    lock = root / "locks" / ".run-demo.lock"
    with benchmark_runner.BenchmarkLock(lock):
        check(lock.is_file(), "benchmark lock is materialized while owned")
        try:
            with benchmark_runner.BenchmarkLock(lock):
                pass
            duplicate_refused = False
        except RuntimeError:
            duplicate_refused = True
        check(duplicate_refused, "benchmark refuses a live duplicate target run")
    check(not lock.exists(), "benchmark releases its lock")

    parser = audit_runner.build_parser()
    args = parser.parse_args(["--target", "demo", "--backend", "codex", "--experiment", "Exp A"])
    equal("exp-a", audit_runner._sanitize_experiment(args.experiment), "audit experiment names become safe path components")
    equal("demo-exp-a", audit_runner._output_slug("demo", "exp-a"), "audit experiment output slug is deterministic")
    with mock.patch.object(audit_runner.llm_invoke, "backend_bin", return_value=sys.executable), \
         mock.patch.object(
             audit_runner.subprocess, "run",
             side_effect=audit_runner.subprocess.TimeoutExpired([sys.executable], 30),
         ), contextlib.redirect_stderr(io.StringIO()):
        check(
            not audit_runner.backend_configured("codex"),
            "a hung backend preflight is unavailable instead of aborting audit startup",
        )
    model_runtime = SimpleNamespace(
        root=ROOT, logs=root / "model-preflight-logs",
        raw=root / "model-preflight-logs" / ".raw",
        index=root / "model-preflight-logs" / "index.log",
        target_root=root / "model-preflight-target",
        results=root / "model-preflight-results",
        backend="gemini", model="fixture-model", agent_security="sandboxed",
    )
    model_runtime.raw.mkdir(parents=True)
    model_runtime.target_root.mkdir()
    model_runtime.results.mkdir()

    preflight_grants: list[str] = []

    def _preflight_command(prompt_text):
        """The (token, sentinel) the probe told its agent to write."""
        line = next(
            row for row in prompt_text.splitlines() if row.startswith("printf ")
        )
        parts = shlex.split(line)
        return parts[2], parts[4]

    def _preflight_acts(_backend, prompt_text, *_args, **kwargs):
        """Stand in for an agent that can actually run the command it was given."""
        preflight_grants.append(kwargs.get("add_dirs", ""))
        token, sentinel = _preflight_command(prompt_text)
        Path(sentinel).write_text(token, encoding="utf-8")
        return 0

    with mock.patch.dict(
        os.environ,
        {"AUDIT_MODEL_PREFLIGHT_ATTEMPTS": "1"},
        clear=False,
    ), mock.patch.object(
        audit_runner.llm_invoke, "run_agent_prompt", side_effect=_preflight_acts,
    ):
        audit_runner.validate_model(model_runtime)
    check(
        "Model preflight passed" in model_runtime.index.read_text(encoding="utf-8"),
        "model preflight exercises the requested model through the agent launch path",
    )
    # The probe has to ask its question with the audit's own grants. Asking with
    # a narrower set is how a target tree the agent could not write stayed
    # invisible until the run had spent its wall.
    check(
        str(model_runtime.target_root) in preflight_grants[0]
        and str(model_runtime.results) in preflight_grants[0],
        "the preflight is granted the same directories the audit will use",
    )
    preflight_usage = json.loads(
        (model_runtime.logs / "index.jsonl").read_text(encoding="utf-8")
    )
    check(
        preflight_usage["role"] == "model-preflight"
        and preflight_usage["backend"] == "gemini",
        "model preflight usage is charged to the session ledger",
    )
    model_runtime.backend = "oss"
    with mock.patch.dict(
        os.environ,
        {"AUDIT_MODEL_PREFLIGHT_ATTEMPTS": "1"},
        clear=False,
    ), mock.patch.object(
        audit_runner.llm_invoke, "run_agent_prompt", side_effect=_preflight_acts,
    ):
        audit_runner.validate_model(model_runtime)
    check(
        not list((model_runtime.target_root / ".audit").glob("preflight-*")),
        "every backend answers one preflight, and it leaves no sentinel behind",
    )
    model_runtime.backend = "gemini"
    with mock.patch.dict(
        os.environ,
        {"AUDIT_MODEL_PREFLIGHT_ATTEMPTS": "1"},
        clear=False,
    ), mock.patch.object(
        audit_runner.llm_invoke, "run_agent_prompt", return_value=0,
    ):
        try:
            audit_runner.validate_model(model_runtime)
            rejected_idle_agent = False
        except RuntimeError:
            rejected_idle_agent = True
    check(
        rejected_idle_agent,
        "model preflight rejects a nominal exit whose agent never ran a command",
    )

    # A provider that serves a different model refuses the request as surely as
    # one that errors, and deterministically: without the provider markers a
    # harness-only benchmark records an ordinary failed cell and re-runs it for
    # every replicate and resume.
    def _preflight_acts_as_other_model(_backend, prompt_text, *args, **kwargs):
        token, sentinel = _preflight_command(prompt_text)
        Path(sentinel).write_text(token, encoding="utf-8")
        Path(args[1]).write_text(
            json.dumps({"type": "result", "stats": {"models": {
                "gemini-3.5-flash": {"total_tokens": 4096},
            }}}) + "\n",
            encoding="utf-8",
        )
        return 0

    (model_runtime.logs / ".backend-unavailable").unlink(missing_ok=True)
    (model_runtime.logs / ".run-quality").unlink(missing_ok=True)
    model_runtime.model = "gemini-3.7-flash"
    with mock.patch.dict(
        os.environ, {"AUDIT_MODEL_PREFLIGHT_ATTEMPTS": "1"}, clear=False,
    ), mock.patch.object(
        audit_runner.llm_invoke, "run_agent_prompt",
        side_effect=_preflight_acts_as_other_model,
    ):
        try:
            audit_runner.validate_model(model_runtime)
            refused_substitution = ""
        except RuntimeError as exc:
            refused_substitution = str(exc)
    check(
        "gemini-3.5-flash" in refused_substitution
        and (model_runtime.logs / ".backend-unavailable").is_file()
        and (model_runtime.logs / ".run-quality").read_text().strip()
        == "provider_limited",
        "a substituted model is refused and recorded as a provider rejection",
    )

    # A sentinel has to be produced by the attempt that is judged on it. One
    # left behind by an attempt that then failed would pass the next attempt,
    # which need only exit zero without acting.
    stale_attempts = []

    def _acts_then_fails(_backend, prompt_text, *_args, **_kwargs):
        stale_attempts.append(None)
        if len(stale_attempts) == 1:
            token, sentinel = _preflight_command(prompt_text)
            Path(sentinel).write_text(token, encoding="utf-8")
            return 1
        return 0

    with mock.patch.dict(
        os.environ,
        {"AUDIT_MODEL_PREFLIGHT_ATTEMPTS": "2"},
        clear=False,
    ), mock.patch.object(
        audit_runner.llm_invoke, "run_agent_prompt", side_effect=_acts_then_fails,
    ), mock.patch.object(audit_runner.time, "sleep"):
        try:
            audit_runner.validate_model(model_runtime)
            rejected_stale_sentinel = False
        except RuntimeError:
            rejected_stale_sentinel = True
    check(
        rejected_stale_sentinel,
        "preflight never passes on a sentinel an earlier attempt left behind",
    )

    # The per-session tally is telemetry, not a verdict: it is how a run that
    # could not act is diagnosed afterwards. A tool count cannot tell a blocked
    # agent from one that read its state and concluded, and a session denied
    # every command can still make read calls — so the two numbers have to stay
    # distinguishable and stay evidence for a human.
    tally = root / "tally"
    tally.mkdir()

    def _transcript(name, rows):
        path = tally / name
        path.write_text(
            "\n".join(json.dumps(row) for row in rows), encoding="utf-8",
        )
        return path

    equal(
        (1, 1),
        audit_runner._tally_transcript(_transcript("acted.jsonl", [
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "name": "Bash", "input": {}}]}},
        ])),
        "a session that used a tool is tallied as having acted",
    )
    equal(
        (0, 1),
        audit_runner._tally_transcript(_transcript("silent.jsonl", [
            {"type": "assistant", "message": {"content": [
                {"type": "text", "text": "nothing to do"}]}},
        ])),
        "a parsed session with no tool call is tallied as idle",
    )
    plain = tally / "plain.log"
    plain.write_text("assistant text, not JSON\n", encoding="utf-8")
    equal(
        (0, 0), audit_runner._tally_transcript(plain),
        "a transcript that parsed nothing stays distinct from an idle session",
    )
    config = target_config.Config(is_browser="1", build_system="mach")
    with mock.patch.dict(os.environ, {"BROWSER_AGENTS": "2", "SHELL_AGENTS": "2"}, clear=False):
        equal((4, 2, 2), audit_runner._agent_counts(config, 10), "audit honors configured browser and shell role counts")
    equal((1, 1, 0), audit_runner._agent_counts(config, 1), "browser smoke mode keeps one browser worker")
    with mock.patch.dict(os.environ, {"AGENT_ROLES": "analysis,reproduce,reproduce"}, clear=False):
        equal(
            ("analysis", "reproduce", "reproduce"),
            audit_runner._agent_roles(3),
            "audit honors explicit per-agent roles",
        )
    explicit_context = prompt.PromptContext(
        results, generic_target, "demo", references, 3,
        agent_roles=("analysis", "reproduce", "reproduce"),
    )
    equal("analysis", explicit_context.role(1), "prompt applies explicit role ordering")
    handoff_results = root / "handoff-results"
    (handoff_results / "state").mkdir(parents=True)
    (handoff_results / "state/hypotheses.jsonl").write_text(json.dumps({
        "id": "H-HANDOFF", "agent": "1", "status": "NEEDS_TESTCASE",
        "file": "src/parser.c:app_parse:91", "hypothesis": "nested state reaches stale entry",
        "input_shape": "nested document", "guard_gap": "cleanup ordering",
        "diagnostic": "lifetime", "strategy": "S5", "updated_at": "2026-07-10T00:00:00Z",
    }) + "\n", encoding="utf-8")
    handoff_context = prompt.PromptContext(
        handoff_results, generic_target, "demo", references, 3,
        agent_roles=("analysis", "reproduce", "reproduce"),
    )
    assigned_handoffs = {
        agent: prompt.handoff_rows(handoff_context, agent) for agent in (2, 3)
    }
    assigned_agent = next(agent for agent, rows in assigned_handoffs.items() if rows)
    check(
        sum(bool(rows) for rows in assigned_handoffs.values()) == 1
        and "H-HANDOFF" in prompt.handoff_directive(handoff_context, assigned_agent),
        "analysis NEEDS_TESTCASE is routed to exactly one reproduce worker",
    )
    handoff_runtime = SimpleNamespace(
        root=ROOT, results=handoff_results, target_root=generic_target,
        target_slug="demo", repo_type="none",
    )
    check(
        not audit_runner.should_skip_launch(handoff_runtime, handoff_context, assigned_agent),
        "a pending analysis handoff keeps its reproduce worker launchable",
    )

    strategy_results = root / "strategy-results"
    (strategy_results / "state").mkdir(parents=True)
    strategy_cards = [
        {"id": "WORK-S7-a", "strategy": "S7", "status": "unclaimed"},
        {"id": "WORK-S7-b", "strategy": "S7", "status": "unclaimed"},
        {"id": "WORK-S2", "strategy": "S2", "status": "unclaimed"},
    ]
    (strategy_results / "work-cards.jsonl").write_text(
        "".join(json.dumps(card) + "\n" for card in strategy_cards), encoding="utf-8"
    )
    strategy_runtime = SimpleNamespace(
        root=ROOT, target_root=generic_target, target_slug="demo",
        results=strategy_results, repo_type="none", num_agents=3, fixed_strategy="",
        agent_roles=(),
    )
    audit_runner.initialize_agent_strategies(strategy_runtime)
    equal(
        ["S7", "S2", "S7"],
        [
            (strategy_results / "state" / f"strategy-{agent}").read_text().strip()
            for agent in range(1, 4)
        ],
        "cold-start strategies fan out by available queue load",
    )


    # Card supply is the first key, but a queue that gives every strategy a
    # comparable share leaves the whole decision to the tie-break. Canonical
    # S1..S8 numbering would then open the run on the lowest-numbered
    # methods; expected yield keeps the most productive ones in front.
    equal_results = root / "equal-share-results"
    (equal_results / "state").mkdir(parents=True)
    (equal_results / "work-cards.jsonl").write_text(
        "".join(
            json.dumps({
                "id": f"WORK-{strategy}-{index}",
                "strategy": strategy,
                "status": "unclaimed",
            }) + "\n"
            for strategy in ("S2", "S3", "S5", "S7", "S8")
            for index in range(4)
        ),
        encoding="utf-8",
    )
    audit_runner.initialize_agent_strategies(SimpleNamespace(
        root=ROOT, target_root=generic_target, target_slug="demo",
        results=equal_results, repo_type="none", num_agents=3,
        fixed_strategy="", agent_roles=(),
    ))
    equal(
        ["S7", "S5", "S2"],
        [
            (equal_results / "state" / f"strategy-{agent}").read_text().strip()
            for agent in range(1, 4)
        ],
        "an equal-share queue opens on expected yield, not on strategy number",
    )

    # A campaign lane holds one card by construction — one corpus, one lock,
    # one campaign per iteration — so ranking lanes by card supply buries it
    # behind every lane holding a list of files. Measured on four targets it
    # sorted last of all of them, and no bounded run ever drew it, which left
    # the only strategy that runs a fuzzer permanently unassigned.
    campaign_results = root / "campaign-results"
    (campaign_results / "state").mkdir(parents=True)
    (campaign_results / "work-cards.jsonl").write_text(
        "".join(
            json.dumps({
                "id": f"WORK-{strategy}-{index}",
                "strategy": strategy,
                "status": "unclaimed",
            }) + "\n"
            for strategy in ("S2", "S3", "S5", "S7", "S8")
            for index in range(4)
        )
        + json.dumps({
            "id": "FUZZ-abc123", "kind": "s4-campaign", "strategy": "S4",
            "status": "unclaimed",
        }) + "\n",
        encoding="utf-8",
    )

    campaign_only = json.dumps({
        "id": "FUZZ-narrow", "kind": "s4-campaign", "strategy": "S4",
        "status": "unclaimed",
    }) + "\n"
    narrow_results = root / "campaign-narrow-results"
    (narrow_results / "state").mkdir(parents=True)
    (narrow_results / "work-cards.jsonl").write_text(campaign_only, encoding="utf-8")
    mixed_results = root / "campaign-mixed-results"
    (mixed_results / "state").mkdir(parents=True)
    (mixed_results / "work-cards.jsonl").write_text(
        "".join(
            json.dumps({"id": f"WORK-S7-{i}", "strategy": "S7", "status": "unclaimed"}) + "\n"
            for i in range(3)
        ) + campaign_only,
        encoding="utf-8",
    )

    def campaign_strategies(agents: int, results: Path = campaign_results) -> list[str]:
        for agent in range(1, agents + 1):
            (results / "state" / f"strategy-{agent}").unlink(missing_ok=True)
        audit_runner.initialize_agent_strategies(SimpleNamespace(
            root=ROOT, target_root=generic_target, target_slug="demo",
            results=results, repo_type="none", num_agents=agents,
            fixed_strategy="", agent_roles=(),
        ))
        return [
            (results / "state" / f"strategy-{agent}").read_text().strip()
            for agent in range(1, agents + 1)
        ]

    # The campaign is execution work — build a harness, run a slice, replay what
    # it finds — so it goes to a reproduce worker. Taking the last slot instead
    # handed it the default layout's only analysis agent, whose contract is to
    # read and hand off, so nothing would have run the fuzzer there either.
    equal(
        ["S7", "S4", "S5"], campaign_strategies(3),
        "the campaign takes a reproduce slot, leaving the analysis lane intact",
    )
    # Its own lock allows one campaign at a time, so one slot is the whole ask.
    equal(
        ["S7", "S5", "S4", "S2"], campaign_strategies(4),
        "the campaign takes one slot, not a share that grows with the fleet",
    )
    # A lone agent spent on the campaign would leave the ranked queue untouched.
    equal(["S7"], campaign_strategies(1), "a single agent is not spent on the campaign")
    # A narrow queue used to put the campaign in the ranked positions as well as
    # the reserved one, so two agents opened on it and the one that lost the
    # exclusive lock exited having done nothing.
    equal(
        ["S4", "S1"], campaign_strategies(2, narrow_results),
        "a queue holding only the campaign still spends one agent on it",
    )
    equal(
        ["S7", "S4", "S7"], campaign_strategies(3, mixed_results),
        "a campaign never doubles up by also filling a ranked slot",
    )

    rotation_runtime = SimpleNamespace(
        root=ROOT, target_root=generic_target, target_slug="demo",
        results=strategy_results, repo_type="none", num_agents=1, fixed_strategy="",
        index=root / "strategy-index.log",
    )
    (strategy_results / "state" / "strategy-1").write_text("S2\n", encoding="utf-8")
    (strategy_results / ".agent_strategy_streak_1").write_text("2\n", encoding="utf-8")
    rotation_context = prompt.PromptContext(
        strategy_results, generic_target, "demo", references, 1,
    )
    idle_progress = audit_runner.AgentProgress(0, 0, frozenset())
    with mock.patch.object(
        audit_runner.workqueue, "strategy_completion_status",
        return_value={"complete": True, "evidence": 2, "threshold": 2},
    ):
        audit_runner.update_strategy_rotation(
            rotation_runtime, rotation_context,
            {1: idle_progress}, set(),
        )
    equal(
        "S7", (strategy_results / "state" / "strategy-1").read_text().strip(),
        "dry strategy rotation selects the largest available queue",
    )
    (strategy_results / "state" / "strategy-1").write_text("S2\n", encoding="utf-8")
    (strategy_results / ".agent_strategy_streak_1").write_text("2\n", encoding="utf-8")
    with mock.patch.object(
        audit_runner.workqueue, "strategy_completion_status",
        return_value={"complete": True, "evidence": 2, "threshold": 2},
    ):
        audit_runner.update_strategy_rotation(
            rotation_runtime, rotation_context,
            {1: audit_runner.AgentProgress(0, 1, frozenset())},
            set(),
        )
    equal(
        "S7", (strategy_results / "state" / "strategy-1").read_text().strip(),
        "environment-blocked work advances strategy rotation",
    )

    # A resumed run can carry an assignment no longer in the registry — a
    # retired identifier, or a truncated write. Initialization replaces
    # anything it does not recognise with a strategy the queue can feed.
    (strategy_results / "state" / "strategy-1").write_text("S9\n", encoding="utf-8")
    audit_runner.initialize_agent_strategies(
        SimpleNamespace(
            root=ROOT, target_root=generic_target, target_slug="demo",
            results=strategy_results, repo_type="none", num_agents=1,
            fixed_strategy="", agent_roles=(),
        )
    )
    equal(
        "S7", (strategy_results / "state" / "strategy-1").read_text().strip(),
        "an unrecognised assignment is replaced by a strategy that owns cards",
    )
    # A recognised assignment whose lane still has cards is left alone, so a
    # working agent is never churned between iterations.
    (strategy_results / "state" / "strategy-1").write_text("S7\n", encoding="utf-8")
    audit_runner.initialize_agent_strategies(
        SimpleNamespace(
            root=ROOT, target_root=generic_target, target_slug="demo",
            results=strategy_results, repo_type="none", num_agents=1,
            fixed_strategy="", agent_roles=(),
        )
    )
    equal(
        "S7", (strategy_results / "state" / "strategy-1").read_text().strip(),
        "a recognised assignment with cards survives initialization",
    )
    # An operator's --strategy pin outranks supply: it is honoured even with an
    # empty lane, which is what keeps a deliberate pin from being undone here.
    (strategy_results / "state" / "strategy-1").write_text("S4\n", encoding="utf-8")
    audit_runner.initialize_agent_strategies(
        SimpleNamespace(
            root=ROOT, target_root=generic_target, target_slug="demo",
            results=strategy_results, repo_type="none", num_agents=1,
            fixed_strategy="S4", agent_roles=(),
        )
    )
    equal(
        "S4", (strategy_results / "state" / "strategy-1").read_text().strip(),
        "an operator strategy pin survives an empty lane",
    )
    # Unpinned, an empty lane is reassigned instead: this runs after the rank
    # pass that mints companions, so a lane still empty here has nothing
    # coming, and an agent left on it does no work at all. One benchmark cell
    # held an agent on an empty lane for 88% of the run while 104 cards sat
    # unclaimed in other lanes.
    audit_runner.initialize_agent_strategies(
        SimpleNamespace(
            root=ROOT, target_root=generic_target, target_slug="demo",
            results=strategy_results, repo_type="none", num_agents=1,
            fixed_strategy="", agent_roles=(),
        )
    )
    equal(
        "S7", (strategy_results / "state" / "strategy-1").read_text().strip(),
        "an unpinned agent is rotated off a lane with no claimable cards",
    )
    (strategy_results / "state" / "strategy-1").write_text("S7\n", encoding="utf-8")
    (strategy_results / "work-cards.jsonl").write_text(
        json.dumps({"id": "WORK-only", "strategy": "S3", "status": "unclaimed"}) + "\n",
        encoding="utf-8",
    )
    (strategy_results / "state" / "strategy-1").write_text("S3\n", encoding="utf-8")
    (strategy_results / ".agent_strategy_streak_1").write_text("2\n", encoding="utf-8")
    with mock.patch.object(
        audit_runner.workqueue, "strategy_completion_status",
        return_value={"complete": True, "evidence": 2, "threshold": 2},
    ):
        audit_runner.update_strategy_rotation(
            rotation_runtime, rotation_context, {1: idle_progress}, set(),
        )
    equal(
        "S4", (strategy_results / "state" / "strategy-1").read_text().strip(),
        "rotation with no alternative queue advances in canonical order",
    )
    (strategy_results / "work-cards.jsonl").write_text(
        "".join(json.dumps(card) + "\n" for card in strategy_cards), encoding="utf-8"
    )

    subsystem_runtime = SimpleNamespace(
        root=ROOT, target_root=generic_target, target_slug="demo",
        results=strategy_results, repo_type="none", num_agents=2,
    )
    (strategy_results / "state" / "hypotheses.jsonl").write_text(
        json.dumps({"agent": "1", "status": "FIND-001", "file": "src/parser/a.c", "subsystem": "src/parser"}) + "\n"
        + json.dumps({"agent": "2", "status": "DISCARDED", "file": "src/parser/b.c", "subsystem": "src/parser"}) + "\n",
        encoding="utf-8",
    )
    audit_runner.update_subsystem_dry_streaks(
        subsystem_runtime, {1},
    )
    equal(
        0,
        audit_runner.workqueue.subsystem_dry_streak(
            audit_runner._queue_context(subsystem_runtime), "src/parser"
        ),
        "any productive agent resets a shared subsystem dry streak",
    )
    audit_runner.update_subsystem_dry_streaks(
        subsystem_runtime, set(),
    )
    equal(
        1,
        audit_runner.workqueue.subsystem_dry_streak(
            audit_runner._queue_context(subsystem_runtime), "src/parser"
        ),
        "multiple dry agents advance a shared subsystem only once per iteration",
    )
    audit_runner.update_subsystem_dry_streaks(
        subsystem_runtime, set(),
    )
    equal(
        2,
        audit_runner.workqueue.subsystem_dry_streak(
            audit_runner._queue_context(subsystem_runtime), "src/parser"
        ),
        "environment-blocked work advances subsystem dry streak",
    )

    refresh_results = root / "refresh-results"
    refresh_logs = root / "refresh-logs"
    refresh_results.mkdir()
    refresh_logs.mkdir()
    refresh_runtime = SimpleNamespace(
        root=ROOT, target_root=generic_target, target_slug="demo",
        target_rev="rev1", repo_type="none", results=refresh_results,
        logs=refresh_logs, backend="codex", model="fixture-model",
        config=generic_config, index=refresh_logs / "index.log",
        decision_timeout=0, agent_security="sandboxed",
    )
    with mock.patch.object(
         audit_runner.target_config, "vcs_source_signature",
         return_value="tracked-source",
    ), mock.patch.object(audit_runner.housekeeping, "should_run", return_value=True) as should_refresh, \
         mock.patch.object(audit_runner.housekeeping, "mark_clean") as marked_clean, \
         mock.patch.object(audit_runner.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as launched:
        refreshed = audit_runner.refresh_work_cards(refresh_runtime)
    # Only the refresh passes themselves. Computing the signature may probe
    # for the optional call-neighbourhood interpreter, which is a lookup, not
    # a refresh pass, and must not be pinned here.
    launched_tools = [
        Path(call.args[0][0]).name for call in launched.call_args_list
        if Path(call.args[0][0]).name in ("patch-cards", "peer-fix-cards", "rank-work")
    ]
    check(
        refreshed and launched_tools == ["patch-cards", "peer-fix-cards", "rank-work"],
        "work-card refresh includes patch, peer-fix, and rank passes",
        repr(launched_tools),
    )
    check(
        should_refresh.call_args.kwargs.get("ttl") == 0,
        "versioned work-card refreshes do not rerun on age alone",
    )
    check(
        marked_clean.call_args.args[1] == should_refresh.call_args.args[1],
        "a refresh marks clean the state it ranked, not the state after it",
    )
    refresh_runtime.fixed_strategy = "S4"
    with mock.patch.object(audit_runner.housekeeping, "should_run", return_value=True), \
         mock.patch.object(audit_runner.housekeeping, "mark_clean"), \
         mock.patch.object(audit_runner.workqueue, "campaign_supported", return_value=True), \
         mock.patch.object(audit_runner.subprocess, "run") as s4_launch:
        audit_runner.refresh_work_cards(refresh_runtime, force=True)
    s4_cards = audit_runner.workqueue.read_jsonl(
        refresh_results / "work-cards.jsonl"
    )
    s4_window = json.loads(
        (refresh_results / "state" / "rank-work-window.json").read_text()
    )
    check(
        not s4_launch.called
        and [card.get("kind") for card in s4_cards] == ["s4-campaign"]
        and s4_window.get("core_count") == 0,
        "a pinned S4 refresh creates only its unranked campaign card",
        f"cards={s4_cards!r} window={s4_window!r}",
    )
    with mock.patch.object(audit_runner.housekeeping, "should_run", return_value=True), \
         mock.patch.object(audit_runner.housekeeping, "mark_clean"), \
         mock.patch.object(audit_runner.workqueue, "campaign_supported", return_value=False), \
         mock.patch.object(audit_runner.subprocess, "run") as unsupported_launch:
        audit_runner.refresh_work_cards(refresh_runtime, force=True)
    check(
        not unsupported_launch.called
        and not audit_runner.workqueue.read_jsonl(refresh_results / "work-cards.jsonl"),
        "an unsupported pinned S4 refresh skips every unrelated card source",
    )
    refresh_runtime.fixed_strategy = "S6"
    (refresh_results / "s6-peer-cards.jsonl").write_text(
        json.dumps({"id": "S6-only", "kind": "s6-peer-fix", "strategy": "S6", "file": "", "mode": "auto"}) + "\n",
        encoding="utf-8",
    )
    with mock.patch.object(audit_runner.housekeeping, "should_run", return_value=True), \
         mock.patch.object(audit_runner.housekeeping, "mark_clean"), \
         mock.patch.object(audit_runner.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as pinned_launch:
        audit_runner.refresh_work_cards(refresh_runtime)
    pinned_tools = [Path(call.args[0][0]).name for call in pinned_launch.call_args_list]
    pinned_cards = audit_runner.workqueue.read_jsonl(refresh_results / "work-cards.jsonl")
    check(
        pinned_tools == ["peer-fix-cards"] and [card.get("id") for card in pinned_cards] == ["S6-only"],
        "a pinned S6 refresh skips unrelated patch and source ranking",
        f"tools={pinned_tools!r} cards={pinned_cards!r}",
    )
    refresh_runtime.fixed_strategy = "S1"
    audit_runner.workqueue.write_cards(
        refresh_results / "patch-cards.jsonl",
        [
            {
                "id": f"PATCH-{index:02d}", "kind": "s1-patch",
                "strategy": "S1", "target_slug": "demo",
                "touched_files": [f"src/unit{index:02d}.c"],
                "description": "fix bounds check", "score": 80 - index,
                "fix_hashes": [f"abc{index:03d}"], "status": "unclaimed",
            }
            for index in range(12)
        ],
    )
    with mock.patch.object(audit_runner.housekeeping, "should_run", return_value=True), \
         mock.patch.object(audit_runner.housekeeping, "mark_clean"), \
         mock.patch.object(audit_runner.callgraph, "refresh", return_value="fresh"), \
         mock.patch.object(audit_runner.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as pinned_launch:
        audit_runner.refresh_work_cards(refresh_runtime, limit=4)
    pinned_tools = [Path(call.args[0][0]).name for call in pinned_launch.call_args_list]
    pinned_cards = audit_runner.workqueue.read_jsonl(refresh_results / "work-cards.jsonl")
    check(
        pinned_tools == ["patch-cards"]
        and [card.get("id") for card in pinned_cards]
        == ["PATCH-00", "PATCH-01", "PATCH-02", "PATCH-03"]
        and audit_runner._rank_window(refresh_runtime) == (4, 4),
        "a pinned S1 refresh uses the full expandable window and skips unrelated ranking",
        f"tools={pinned_tools!r} cards={pinned_cards!r}",
    )
    refresh_runtime.fixed_strategy = "S6"
    audit_runner.workqueue.write_cards(
        refresh_results / "work-cards.jsonl",
        [{"id": "S6-only", "kind": "s6-peer-fix", "strategy": "S6", "file": "", "mode": "auto"}],
    )
    audit_runner.workqueue.update_card_status(
        audit_runner._queue_context(refresh_runtime), "S6-only", "blocked",
        agent="1", note="source proof",
    )
    check(
        audit_runner.fixed_lane_exhausted(refresh_runtime),
        "a pinned S6 campaign stops when every supplied card is terminal",
    )
    # Closing the card does not close the investigation it started: stopping
    # here would strand an open hypothesis mid-analysis.
    (refresh_results / "state" / "hypotheses.jsonl").write_text(
        json.dumps({"agent": "1", "id": "HYP-1", "status": "INVESTIGATING",
                    "card_id": "S6-only"}) + "\n",
        encoding="utf-8",
    )
    check(
        not audit_runner.fixed_lane_exhausted(refresh_runtime),
        "an open hypothesis holds a pinned S6 campaign open",
    )
    (refresh_results / "state" / "hypotheses.jsonl").write_text(
        json.dumps({"agent": "1", "id": "HYP-1", "status": "FIND-001",
                    "card_id": "S6-only", "hypothesis": "one angle",
                    "input_shape": "shape", "guard_gap": "gap",
                    "diagnostic": "bounds", "strategy": "S6"}) + "\n",
        encoding="utf-8",
    )
    audit_runner.workqueue.update_card_status(
        audit_runner._queue_context(refresh_runtime), "S6-only", "find",
        agent="1", note="finding filed",
    )
    check(
        not audit_runner.fixed_lane_exhausted(refresh_runtime),
        "a first productive S6 conclusion remains open for clustered variants",
    )
    audit_runner.workqueue.write_cards(refresh_results / "work-cards.jsonl", [])
    refresh_runtime.config = SimpleNamespace(s6_peers=["peerlib"])
    refresh_runtime.s6_source_degraded = False
    check(
        not audit_runner.fixed_lane_exhausted(refresh_runtime, iteration=1)
        and audit_runner.fixed_lane_exhausted(refresh_runtime, iteration=2),
        "a healthy but empty S6 source gets exactly one discovery iteration",
    )
    (refresh_results / "state" / "hypotheses.jsonl").write_text(
        json.dumps({
            "agent": "1", "id": "H-MANUAL-S6", "status": "INVESTIGATING",
            "strategy": "S6", "card_id": "",
        }) + "\n",
        encoding="utf-8",
    )
    check(
        not audit_runner.fixed_lane_exhausted(refresh_runtime, iteration=2),
        "an empty source cannot strand an active cardless S6 hypothesis",
    )
    (refresh_results / "state" / "hypotheses.jsonl").write_text(
        "", encoding="utf-8",
    )
    refresh_runtime.config = generic_config
    # A pinned S1 lane draws only from patch cards, so a target whose history
    # mines nothing must stop rather than skip agents for the whole wall.
    refresh_runtime.fixed_strategy = "S1"
    audit_runner.workqueue.write_cards(refresh_results / "work-cards.jsonl", [])
    refresh_runtime.s1_source_degraded = False
    check(
        not audit_runner.fixed_lane_exhausted(refresh_runtime, iteration=1)
        and audit_runner.fixed_lane_exhausted(refresh_runtime, iteration=2),
        "a healthy but empty S1 patch source gets exactly one discovery iteration",
    )
    refresh_runtime.s1_source_degraded = True
    check(
        not audit_runner.fixed_lane_exhausted(refresh_runtime, iteration=2),
        "a failed patch-cards generation is a fault, not an exhausted S1 lane",
    )
    refresh_runtime.s1_source_degraded = False
    audit_runner.workqueue.write_cards(
        refresh_results / "work-cards.jsonl",
        [{"id": "PATCH-open", "kind": "s1-patch", "strategy": "S1",
          "file": "src/unit.c", "mode": "auto"}],
    )
    check(
        not audit_runner.fixed_lane_exhausted(refresh_runtime, iteration=9),
        "an unclaimed S1 patch card keeps its lane open",
    )
    # S1's patch cards are capped by the ranked window, so a consumed batch
    # must still grow it — unlike the campaigns that never read that window.
    audit_runner.workqueue.write_cards(refresh_results / "work-cards.jsonl", [])
    with mock.patch.object(audit_runner, "_rank_window", return_value=(120, 120)), \
         mock.patch.object(audit_runner, "refresh_work_cards") as s1_expansion:
        audit_runner.expand_work_cards_if_exhausted(refresh_runtime)
    check(
        s1_expansion.called,
        "a pinned S1 lane still grows the window its patch cards are capped by",
    )
    refresh_runtime.fixed_strategy = "S4"
    audit_runner.workqueue.write_cards(
        refresh_results / "work-cards.jsonl",
        [{"id": "S4-only", "kind": "s4-campaign", "strategy": "S4",
          "file": "", "mode": "auto"}],
    )
    audit_runner.workqueue.update_card_status(
        audit_runner._queue_context(refresh_runtime), "S4-only", "blocked",
        agent="1", note="campaign cannot build",
    )
    check(
        audit_runner.fixed_lane_exhausted(refresh_runtime),
        "a blocked pinned S4 campaign stops without empty agent relaunches",
    )
    with mock.patch.object(audit_runner, "_rank_window", return_value=(120, 120)), \
         mock.patch.object(audit_runner, "refresh_work_cards") as no_expansion:
        expanded = audit_runner.expand_work_cards_if_exhausted(refresh_runtime)
    check(
        not expanded and not no_expansion.called,
        "a pinned finite campaign does not expand unrelated ranked-source cards",
    )
    with mock.patch.object(
        audit_runner.workqueue, "campaign_supported", return_value=False,
    ):
        unavailable_stops = audit_runner.fixed_lane_exhausted(
            refresh_runtime, iteration=1,
        )
    check(
        unavailable_stops,
        "a structurally unsupported S4 campaign stops before launching an agent",
    )
    # Card-backed pinned lanes stop once their ranked work is genuinely closed,
    # but an empty one still gets the normal discovery runway: ranking can miss
    # a useful manual strategy angle, which an absent generator answer cannot.
    refresh_runtime.fixed_strategy = "S5"
    audit_runner.workqueue.write_cards(
        refresh_results / "work-cards.jsonl",
        [{"id": "S5-only", "kind": "ranked-source", "strategy": "S5",
          "file": "src/state.c", "mode": "auto", "subsystem": "src"}],
    )
    audit_runner.workqueue.update_card_status(
        audit_runner._queue_context(refresh_runtime), "S5-only", "blocked",
        agent="1", note="source proof: configured build cannot execute this surface",
    )
    check(
        audit_runner.fixed_lane_exhausted(refresh_runtime, iteration=2),
        "a pinned card-backed lane stops after all of its supplied work closes",
    )
    (refresh_results / "state" / "hypotheses.jsonl").write_text(
        json.dumps({"agent": "1", "id": "H-S5", "status": "INVESTIGATING",
                    "strategy": "S5", "card_id": "S5-only"}) + "\n",
        encoding="utf-8",
    )
    check(
        not audit_runner.fixed_lane_exhausted(refresh_runtime, iteration=2),
        "an active hypothesis keeps its pinned card-backed lane open",
    )
    (refresh_results / "state" / "hypotheses.jsonl").write_text("", encoding="utf-8")
    audit_runner.workqueue.write_cards(refresh_results / "work-cards.jsonl", [])
    check(
        not audit_runner.fixed_lane_exhausted(refresh_runtime, iteration=20),
        "an empty ranked-window lane retains manual discovery turns",
    )
    refresh_runtime.fixed_strategy = "S6"
    # A pin decides which generators run, so it is part of the queue identity:
    # without it a re-run under a new --strategy reads the old queue as fresh.
    pin_signatures = {
        pin: audit_runner._work_card_signature(
            SimpleNamespace(
                root=ROOT, target_root=generic_target, target_slug="demo",
                target_rev="rev1", results=refresh_results, repo_type="none",
                config=generic_config, fixed_strategy=pin,
            ),
            source_signature="fixed-source",
        )
        for pin in ("", "S2", "S6")
    }
    check(
        len(set(pin_signatures.values())) == 3,
        "changing the strategy pin invalidates the work-card refresh signature",
        repr(sorted(s[:8] for s in pin_signatures.values())),
    )
    refresh_runtime.fixed_strategy = "S2"
    (refresh_results / "s6-peer-cards.jsonl").write_text("stale\n", encoding="utf-8")
    with mock.patch.object(audit_runner.housekeeping, "should_run", return_value=True), \
         mock.patch.object(audit_runner.housekeeping, "mark_clean"), \
         mock.patch.object(audit_runner.subprocess, "run", return_value=SimpleNamespace(returncode=0)) as other_pin:
        audit_runner.refresh_work_cards(refresh_runtime)
    other_tools = [Path(call.args[0][0]).name for call in other_pin.call_args_list]
    check(
        other_tools == ["patch-cards", "rank-work"]
        and not (refresh_results / "s6-peer-cards.jsonl").exists(),
        "a pinned non-S6 lane skips peer mining and drops stale S6 cards",
        repr(other_tools),
    )
    refresh_runtime.fixed_strategy = ""
    (refresh_results / "s6-peer-cards.jsonl").write_text(
        json.dumps({"id": "S6-stale", "kind": "s6-peer-fix"}) + "\n",
        encoding="utf-8",
    )
    with mock.patch.dict(
        os.environ, {"AUDIT_DISABLE_PEER_FIX_CARDS": "1"}, clear=False,
    ), mock.patch.object(
        audit_runner.housekeeping, "should_run", return_value=True,
    ), mock.patch.object(
        audit_runner.housekeeping, "mark_clean",
    ), mock.patch.object(
        audit_runner.subprocess, "run", return_value=SimpleNamespace(returncode=0),
    ) as disabled_peer_launch:
        audit_runner.refresh_work_cards(refresh_runtime)
    disabled_tools = [
        Path(call.args[0][0]).name
        for call in disabled_peer_launch.call_args_list
    ]
    check(
        disabled_tools == ["patch-cards", "rank-work"]
        and not (refresh_results / "s6-peer-cards.jsonl").exists(),
        "disabling peer mining removes stale S6 cards before source ranking",
        repr(disabled_tools),
    )
    saved_refresh_root = refresh_runtime.root
    refresh_runtime.root = refresh_results / "missing-tools"
    refresh_runtime.fixed_strategy = "S6"
    (refresh_results / "s6-peer-cards.jsonl").write_text(
        json.dumps({"id": "S6-stale", "kind": "s6-peer-fix"}) + "\n",
        encoding="utf-8",
    )
    with mock.patch.object(
        audit_runner.housekeeping, "should_run", return_value=True,
    ), mock.patch.object(
        audit_runner.housekeeping, "mark_clean",
    ) as missing_generator_clean:
        audit_runner.refresh_work_cards(refresh_runtime)
    check(
        not (refresh_results / "s6-peer-cards.jsonl").exists()
        and audit_runner.workqueue.read_jsonl(
            refresh_results / "work-cards.jsonl",
        ) == []
        and not missing_generator_clean.called,
        "a missing pinned-lane generator removes stale cards and leaves refresh dirty",
    )
    refresh_runtime.root = saved_refresh_root
    # Work carried in from an earlier pin belongs to that strategy; counting
    # it would keep this campaign alive on results S6 never produced.
    refresh_runtime.fixed_strategy = "S6"
    audit_runner.workqueue.write_cards(
        refresh_results / "work-cards.jsonl",
        [{"id": "S6-only", "kind": "s6-peer-fix", "strategy": "S6",
          "file": "", "mode": "auto", "subsystem": "root"}],
    )
    audit_runner.workqueue.update_card_status(
        audit_runner._queue_context(refresh_runtime), "S6-only", "blocked",
        agent="1", note="source proof: no analogue in this tree",
    )
    (refresh_results / "state" / "hypotheses.jsonl").write_text(
        json.dumps({"agent": "1", "id": "H-OLD", "status": "INVESTIGATING",
                    "strategy": "S1", "card_id": "WORK-OLD"}) + "\n",
        encoding="utf-8",
    )
    foreign_stops = audit_runner.fixed_lane_exhausted(refresh_runtime, 3)
    (refresh_results / "state" / "hypotheses.jsonl").write_text(
        json.dumps({"agent": "1", "id": "H-OWN", "status": "INVESTIGATING",
                    "strategy": "S6", "card_id": "S6-only"}) + "\n",
        encoding="utf-8",
    )
    check(
        foreign_stops and not audit_runner.fixed_lane_exhausted(refresh_runtime, 3),
        "only the pinned lane's own open work holds its campaign open",
    )
    # An empty queue proves exhaustion only when the source could answer.
    # OSV returns [] for an outage exactly as it does for "no advisories", so
    # a degraded or unconfigured source must not read as a finished campaign.
    audit_runner.workqueue.write_cards(refresh_results / "work-cards.jsonl", [])
    (refresh_results / "state" / "hypotheses.jsonl").write_text("", encoding="utf-8")
    refresh_runtime.config = SimpleNamespace(s6_peers=["peerlib"])
    refresh_runtime.s6_source_degraded = True
    degraded = audit_runner.fixed_lane_exhausted(refresh_runtime, 2)
    refresh_runtime.s6_source_degraded = False
    healthy = audit_runner.fixed_lane_exhausted(refresh_runtime, 2)
    refresh_runtime.config = SimpleNamespace(s6_peers=[])
    unconfigured = audit_runner.fixed_lane_exhausted(refresh_runtime, 2)
    check(
        not degraded and not unconfigured and healthy,
        "only a healthy, configured S6 source can report an exhausted campaign",
        f"degraded={degraded} unconfigured={unconfigured} healthy={healthy}",
    )
    refresh_runtime.config = generic_config
    refresh_runtime.fixed_strategy = ""
    with mock.patch.object(audit_runner.housekeeping, "should_run", return_value=False), \
         mock.patch.object(audit_runner.subprocess, "run") as skipped_refresh:
        unchanged = audit_runner.refresh_work_cards(refresh_runtime)
    check(
        not unchanged and not skipped_refresh.called,
        "unchanged work-card inputs skip the expensive ranking pipeline",
    )
    (refresh_results / "patch-cards.jsonl").write_text("{}\n", encoding="utf-8")
    (refresh_results / "s6-peer-cards.jsonl").write_text("{}\n", encoding="utf-8")
    (refresh_results / "work-cards.jsonl").write_text(
        json.dumps({"id": "OLD", "kind": "ranked-source"}) + "\n",
        encoding="utf-8",
    )
    with mock.patch.object(audit_runner.housekeeping, "should_run", return_value=True), \
         mock.patch.object(audit_runner.housekeeping, "mark_clean") as failed_clean, \
         mock.patch.object(
             audit_runner.subprocess, "run",
             side_effect=[SimpleNamespace(returncode=1)] * 3,
         ):
        audit_runner.refresh_work_cards(refresh_runtime)
    remaining_cards = audit_runner.workqueue.read_jsonl(
        refresh_results / "work-cards.jsonl"
    )
    check(
        not failed_clean.called
        and not (refresh_results / "patch-cards.jsonl").exists()
        and not (refresh_results / "s6-peer-cards.jsonl").exists()
        and remaining_cards == [],
        "failed card generators cannot leave stale cards or mark the refresh clean",
    )
    cycle_order = []
    ensemble_runtimes = [
        SimpleNamespace(backend="claude", config=mock.Mock()),
        SimpleNamespace(backend="codex", config=mock.Mock()),
    ]
    def _initialize_cycle(runtime, _args, _guide, **_kwargs):
        return audit_runner.BackendState(runtime, mock.Mock(), started_at=1.0)
    def _cycle_once(state):
        cycle_order.append(state.runtime.backend)
        state.iteration += 1
        return "dry", []
    with mock.patch.object(audit_runner, "instance_lock", return_value=contextlib.nullcontext()), \
         mock.patch.object(audit_runner, "_activate_runtime"), \
         mock.patch.object(audit_runner.runner_preflight, "validate") as ensemble_runner_preflight, \
         mock.patch.object(audit_runner, "validate_model") as ensemble_model_preflight, \
         mock.patch.object(audit_runner, "preflight_build") as ensemble_preflight, \
         mock.patch.object(audit_runner, "initialize_backend", side_effect=_initialize_cycle), \
         mock.patch.object(audit_runner, "run_iteration", side_effect=_cycle_once), \
         mock.patch.dict(os.environ, {"COOLDOWN": "0"}, clear=False):
        ensemble_rc = audit_runner.run_ensemble(
            ensemble_runtimes, SimpleNamespace(max_iterations=3, allow_concurrent=False), "guide"
        )
    check(
        ensemble_rc == 0 and cycle_order == ["claude", "codex", "claude"]
        and ensemble_runner_preflight.call_count == 1
        and ensemble_model_preflight.call_count == 2
        and ensemble_preflight.call_count == 1,
        "ensemble mode preflights the runner/build once, each model, and cycles backends",
        repr(cycle_order),
    )

    budget_runtime = SimpleNamespace(
        index=root / "budget-index.log", logs=root / "budget-runtime-logs",
    )
    budget_runtime.logs.mkdir()
    budget_state = audit_runner.BackendState(
        budget_runtime, mock.Mock(), started_at=100.0, paused_seconds=20,
    )
    with mock.patch.dict(os.environ, {"AUDIT_WALL_BUDGET_SECS": "50"}, clear=False), \
         mock.patch.object(audit_runner.time, "monotonic", return_value=171.0):
        wall_done = audit_runner._productive_wall_exhausted(budget_state)
    check(
        wall_done and budget_state.stopped,
        "audit wall budget excludes provider-recovery pause and stops cleanly",
    )
    with mock.patch.dict(os.environ, {"AUDIT_WALL_BUDGET_SECS": "50"}, clear=False), \
         mock.patch.object(audit_runner.time, "monotonic", return_value=171.0):
        equal(
            0, audit_runner._productive_wall_remaining(budget_state),
            "expired audit budget exposes zero remaining time instead of a synthetic extra second",
        )
    init_runtime = SimpleNamespace(
        backend="codex", model="fixture-model", target_slug="demo",
        target_root=generic_target, results=root / "init-results",
        logs=root / "init-logs", prompt_context=lambda _guide: mock.Mock(),
    )
    with mock.patch.dict(os.environ, {"AUDIT_WALL_BUDGET_SECS": "50"}, clear=False), \
         mock.patch.object(audit_runner, "_activate_runtime"), \
         mock.patch.object(audit_runner, "index_log"), \
         mock.patch.object(audit_runner.prompt, "write_static_prompt_file"), \
         mock.patch.object(audit_runner, "refresh_work_cards", return_value=False), \
         mock.patch.object(audit_runner, "initialize_agent_strategies"), \
         mock.patch.object(audit_runner.time, "monotonic", return_value=120.0):
        initialized = audit_runner.initialize_backend(
            init_runtime, SimpleNamespace(), "guide", started_at=100.0,
        )
    check(
        initialized.started_at == 100.0,
        "audit productive clock carries the caller's start time",
    )
    recovery_state = audit_runner.BackendState(
        budget_runtime, mock.Mock(), started_at=100.0,
    )
    with mock.patch.object(audit_runner.time, "time", return_value=1000), \
         mock.patch.object(audit_runner.time, "sleep") as paused:
        recovered = audit_runner._recover_capacity(
            recovery_state, [SimpleNamespace(reset_at=1020)]
        )
    check(
        recovered and recovery_state.paused_seconds == 50
        and paused.call_args == mock.call(50)
        and (budget_runtime.logs / ".run-quality").read_text().strip() == "provider_recovered",
        "provider capacity pause uses the reported reset and records excluded wall time",
    )
    budget_prompt = audit_runner._session_files('A "quoted" prompt', root / "scratch-1")
    check(
        'A "quoted" prompt' in budget_prompt and "SESSION FILES" in budget_prompt,
        "audit session file rule preserves quoted prompt text",
    )
    check(
        "Never write to `/tmp`" in budget_prompt and "seeds" in budget_prompt,
        "audit session file rule keeps all working files under scratch, not shared /tmp",
    )

    launch_results = root / "launch-results"
    launch_logs = root / "launch-logs"
    launch_raw = launch_logs / ".raw"
    launch_scratch = launch_results / "scratch-1"
    for directory in (launch_results, launch_logs, launch_raw, launch_scratch):
        directory.mkdir(parents=True, exist_ok=True)
    launch_runtime = SimpleNamespace(
        root=ROOT, target_root=generic_target, target_slug="demo",
        results=launch_results, logs=launch_logs, raw=launch_raw,
        index=launch_logs / "index.log", index_jsonl=launch_logs / "index.jsonl",
        backend="codex", model="fixture-model", agent_security="sandboxed",
    )
    launch_context = mock.Mock()
    launch_context.role.return_value = "reproduce"
    launch_context.scratch_dir.return_value = launch_scratch
    launch_context.turn_soft_cap = 128
    with mock.patch.object(audit_runner.prompt, "cold_start_prompt", return_value="prompt"), \
         mock.patch.object(audit_runner.llm_invoke, "run_agent_prompt", return_value=0) as launch_invoke, \
         mock.patch.object(audit_runner.llm_invoke, "extract_text", return_value="done"), \
         mock.patch.object(audit_runner.llm_usage, "extract_usage", return_value={}), \
         mock.patch.object(audit_runner.build_session_seed, "write_session_seed", return_value=True) as seed_refresh:
        audit_runner.run_agent(launch_runtime, launch_context, 1, 1, True)
    seed_args = seed_refresh.call_args.args
    check(
        len(seed_args) == 2
        and Path(seed_args[0]).parent == launch_raw
        and seed_args[1] == str(launch_results / ".session_seed_1.md"),
        "each completed agent launch refreshes the next prompt's session seed",
        repr(seed_refresh.call_args),
    )
    launch_env = launch_invoke.call_args.kwargs["extra_env"]
    check(
        launch_env["HITS_LOG_PATH"] == str(launch_results / "hits-1.log")
        and launch_env["TRIED_INPUTS_LOG"] == str(launch_results / "tried-inputs-1.log"),
        "agent and probe share the canonical per-agent evidence journals",
        repr(launch_env),
    )
    launch_usage_row = json.loads((launch_logs / "index.jsonl").read_text())
    check(
        (launch_logs / ".index.jsonl.lock").is_file()
        and launch_usage_row["agent"] == 1
        and launch_usage_row["resolved_effort"] == "high"
        and launch_usage_row["turn_soft_cap"] == 128,
        "agent usage writes share the JSONL lock used by concurrent harness writers",
    )
    corpus_testcase = launch_scratch / "coverage.html"
    corpus_testcase.write_text(
        "<!-- HYPOTHESIS-ID: H77 -->\n<!-- TARGET: src/parser.c -->\n"
        "<!-- CATEGORY: bounds -->\n<html></html>\n",
        encoding="utf-8",
    )
    (launch_scratch / "coverage.asan.txt").write_text(
        "[run-sanitizer-multi] SUCCESS_RATE: 1/1\n",
        encoding="utf-8",
    )
    (launch_results / "hits-1.log").write_text(
        f"HIT: 2026-07-10T00:00:00Z testcase={corpus_testcase} "
        "want=app_parse edges=2 new=1 frame=app_parse\n",
        encoding="utf-8",
    )
    launch_runtime.num_agents = 1
    with mock.patch.dict(os.environ, {"RESULTS_DIR": str(launch_results)}, clear=False):
        promoted = audit_runner.promote_corpus(launch_runtime)
    check(
        promoted == 1 and any((launch_results / "corpus").glob("COVER-*/coverage.html")),
        "post-iteration corpus promotion consumes probe's canonical HIT journal",
    )
    orphan = launch_scratch / "orphan.html"
    orphan.write_text("<!-- TARGET: src/parser.c -->\n<!-- HYPOTHESIS-ID: H78 -->\n<html/>\n")
    def _enforce_probe(command, _seconds, **_kwargs):
        Path(command[-1]).with_suffix(".asan.txt").write_text(
            "[run-sanitizer-multi] SUCCESS_RATE: 1/1\n", encoding="utf-8"
        )
        return SimpleNamespace(returncode=0)
    with mock.patch.object(audit_runner, "run_timeout", side_effect=_enforce_probe):
        enforced = audit_runner.enforce_orphan_testcases(launch_runtime)
    check(
        enforced == 1 and "CLEAN `orphan.html`" in
        (launch_results / ".enforcement_results_1").read_text(encoding="utf-8"),
        "post-iteration housekeeping probes runnable orphan testcases once",
    )
    enforcement_context = prompt.PromptContext(
        launch_results, generic_target, "demo", references, 1,
    )
    check(
        "ORPHAN TESTCASE RESULTS" in prompt.enforcement_results_directive(enforcement_context, 1),
        "the next agent prompt receives orphan enforcement results",
    )

    audit_logs = root / "audit-logs"
    audit_logs.mkdir()
    audit_runtime = SimpleNamespace(logs=audit_logs)
    with audit_runner.instance_lock(audit_runtime, False):
        check((audit_logs / ".instance.lock.d" / "pid").is_file(), "audit instance lock records its owner")
        try:
            with audit_runner.instance_lock(audit_runtime, False):
                pass
            refused = False
        except RuntimeError:
            refused = True
        check(refused, "audit instance lock refuses a live duplicate")
    check(not (audit_logs / ".instance.lock.d").exists(), "audit instance lock releases cleanly")
    fresh_lock = audit_logs / ".instance.lock.d"
    fresh_lock.mkdir()
    try:
        with audit_runner.instance_lock(audit_runtime, False):
            pass
        initializing_refused = False
    except RuntimeError:
        initializing_refused = True
    check(
        initializing_refused and fresh_lock.is_dir(),
        "audit lock fails closed while another process is initializing its owner file",
    )
    fresh_lock.rmdir()

    queue_runtime = SimpleNamespace(
        root=ROOT, results=results, target_root=generic_target,
        target_slug="demo", repo_type="none", num_agents=2,
    )
    with mock.patch.object(structured_state, "agent_counts", return_value=None):
        check(
            audit_runner.should_skip_launch(queue_runtime, generic_context, 2),
            "audit skips an idle secondary agent when every work source is dry",
        )
        check(
            not audit_runner.should_skip_launch(queue_runtime, generic_context, 1),
            "audit always preserves one discovery agent",
        )
        check(
            audit_runner.should_skip_launch(
                queue_runtime, generic_context, 1, primary_always_launches=False,
            ),
            "the primary agent's free launch does not extend to slot refills",
        )
        (results / "fuzz-leads.md").write_text("# Leads\nparser.c:91\n", encoding="utf-8")
        check(
            not audit_runner.should_skip_launch(queue_runtime, generic_context, 2),
            "a fuzz lead keeps an otherwise idle secondary agent launchable",
        )
        (results / "fuzz-leads.md").unlink()
        with mock.patch.object(
            audit_runner.workqueue, "claim_next_card", return_value={"id": "WORK"},
        ):
            check(
                not audit_runner.should_skip_launch(queue_runtime, generic_context, 2),
                "an eligible peekable work card keeps the secondary agent launchable",
            )

    with mock.patch.object(
        audit_runner.workqueue, "release_stale_claims", return_value=[{}, {}],
    ):
        equal(2, audit_runner.release_stale_card_claims(queue_runtime), "audit loop wires stale-claim release through structured state")

    pool_runtime = SimpleNamespace(
        num_agents=2, index=root / "pool-index.log", raw=root / "pool-raw",
    )
    pool_runtime.raw.mkdir()
    pool_context = mock.Mock()
    pool_context.role.return_value = "reproduce"
    pool_state = audit_runner.BackendState(
        pool_runtime, pool_context, iteration=1, started_at=1.0,
    )
    def _pool_result(agent, rc=0, issue="none", turn_capped=False, raw=Path()):
        # Tallied from the transcript exactly as a finished session is, so the
        # refill decision is still driven by real transcript content.
        tools, events = audit_runner._tally_transcript(raw)
        return audit_runner.AgentResult(
            agent, "reproduce", rc, raw, Path(), {}, issue, None, turn_capped,
            tools, events,
        )

    def _transcript(name, tool_calls):
        """A minimal Claude-shaped transcript with `tool_calls` tool uses."""
        path = root / f"pool-{name}.log.raw"
        content = [{"type": "assistant", "message": {"content": (
            [{"type": "tool_use", "name": "Bash", "input": {}}] * tool_calls
            or [{"type": "text", "text": "nothing to do"}]
        )}}]
        path.write_text(
            "\n".join(json.dumps(row) for row in content), encoding="utf-8",
        )
        return path

    def _drive_pool(responder, *, skip_launch=False, want_slot1=3):
        """Hold slot 2's initial session open until slot 1 stops being refilled.

        Slot 2 keeps an initial session outstanding, which is the window in
        which refills are issued; it returns once slot 1 has run `want_slot1`
        sessions, or after a short backstop when no refill is coming.
        """
        calls = []
        lock = threading.Lock()
        def _slot1_sessions():
            with lock:
                return sum(1 for agent, _cold, _limit in calls if agent == 1)
        def _agent(_runtime, _context, agent, _iteration, cold, limit):
            with lock:
                calls.append((agent, cold, limit))
            if agent == 2:
                backstop = time.monotonic() + 0.5
                while _slot1_sessions() < want_slot1 and time.monotonic() < backstop:
                    time.sleep(0.005)
            return responder(agent, calls)
        def _skip(_runtime, _context, agent, *, primary_always_launches=True):
            if callable(skip_launch):
                return skip_launch(agent, primary_always_launches)
            return skip_launch
        with mock.patch.object(audit_runner, "run_agent_guarded", side_effect=_agent), \
             mock.patch.object(audit_runner, "should_skip_launch", side_effect=_skip):
            results = audit_runner.run_agent_pool(pool_state, [1, 2], True)
        return calls, results

    # Duration is not a work-availability signal: an instant session with work
    # available must still be replaced. The old minute-long floor vetoed these.
    fast_calls, fast_results = _drive_pool(lambda agent, _calls: _pool_result(agent))
    check(
        sum(1 for a, cold, _l in fast_calls if a == 1 and not cold) >= 2
        and len(fast_results) == len(fast_calls),
        "an instant session with work available is relaunched repeatedly",
        repr(fast_calls),
    )
    check(
        [c for c in fast_calls if c[1]].__len__() == 2,
        "only the first session in each slot is a cold start",
        repr(fast_calls),
    )
    check(
        all(limit is not None and limit > 0 for _a, _c, limit in fast_calls),
        "every session in the epoch is clamped to the remaining epoch deadline",
        repr(fast_calls),
    )
    # No live work source: the slot stays idle instead of spinning.
    idle_calls, _ = _drive_pool(
        lambda agent, _calls: _pool_result(agent), skip_launch=True,
    )
    check(
        sorted((a, c) for a, c, _l in idle_calls) == [(1, True), (2, True)],
        "no slot is relaunched without a live work source",
        repr(idle_calls),
    )
    # Agent 1's unconditional launch is an initial-cohort guarantee. If the pool
    # asked with it, the primary slot would refill against a dry queue all epoch.
    dry_primary_calls, _ = _drive_pool(
        lambda agent, _calls: _pool_result(agent),
        skip_launch=lambda agent, primary_always_launches: not (
            agent == 1 and primary_always_launches
        ),
    )
    check(
        sorted((a, c) for a, c, _l in dry_primary_calls) == [(1, True), (2, True)],
        "the pool asks about work without agent 1's initial-cohort free pass",
        repr(dry_primary_calls),
    )
    # A turn-capped session was stopped mid-investigation, so its slot continues
    # even when no separate work source is visible.
    capped_calls, _ = _drive_pool(
        lambda agent, _calls: _pool_result(agent, turn_capped=True),
        skip_launch=True,
    )
    check(
        sum(1 for a, cold, _l in capped_calls if a == 1 and not cold) >= 1,
        "a turn-capped session continues in its slot without a separate work source",
        repr(capped_calls),
    )
    # An ambiguous process failure is usually one-off -- recorded audits show a
    # replacement after rc=-9 and rc=1 each running a full productive session --
    # so the slot retries exactly once, and never loops.
    for rc, label in ((-9, "killed"), (1, "crashed")):
        retry_calls, _ = _drive_pool(
            lambda agent, _calls, rc=rc: _pool_result(agent, rc=rc if agent == 1 else 0),
        )
        slot1 = [c for c in retry_calls if c[0] == 1]
        check(
            len(slot1) == 2 and slot1[0][1] is True and slot1[1][1] is False,
            f"a {label} session (rc={rc}) retries its slot exactly once",
            repr(retry_calls),
        )
    # A deadline truncation means the epoch or wall ran out: nothing to retry into.
    deadline_calls, _ = _drive_pool(
        lambda agent, _calls: _pool_result(agent, rc=124 if agent == 1 else 0),
    )
    check(
        sorted((a, c) for a, c, _l in deadline_calls) == [(1, True), (2, True)],
        "a deadline-truncated session (rc=124) does not get its slot relaunched",
        repr(deadline_calls),
    )
    # A crashed session says nothing about whether work remains, so its one
    # retry must not be vetoed by a dry queue -- and must not be spent by that
    # veto either, or the slot is stranded for the rest of the cohort.
    dry_retry_calls, _ = _drive_pool(
        lambda agent, calls: _pool_result(
            agent, rc=1 if agent == 1 else 0,
        ),
        skip_launch=True,
    )
    slot1 = [c for c in dry_retry_calls if c[0] == 1]
    check(
        len(slot1) == 2 and slot1[1][1] is False,
        "a crashed session retries once even when every work source reads dry",
        repr(dry_retry_calls),
    )
    # Provider trouble in one slot must stop launches in every *other* slot too,
    # so a limited provider is not fed while the outer recovery path waits for
    # the pool to drain. Needs a third slot: with only the failing slot and the
    # one holding the cohort open, no refill is possible either way.
    pool_runtime.num_agents = 3
    latch_calls = []
    latch_lock = threading.Lock()
    limited = threading.Event()
    def _latch_agent(_runtime, _context, agent, _iteration, cold, _limit):
        with latch_lock:
            latch_calls.append((agent, cold))
        if agent == 1:
            outcome = _pool_result(1, issue="capacity_limited")
            limited.set()
            return outcome
        if agent == 2:
            # Report after the limit is known, so a refill here would be a
            # decision made with the provider already flagged.
            limited.wait(1)
            time.sleep(0.05)
            return _pool_result(2, raw=_transcript("latch2", 3))
        backstop = time.monotonic() + 0.5
        while time.monotonic() < backstop:
            with latch_lock:
                if len(latch_calls) > 3:
                    break
            time.sleep(0.005)
        return _pool_result(3, raw=_transcript("latch3", 3))
    with mock.patch.object(audit_runner, "run_agent_guarded", side_effect=_latch_agent), \
         mock.patch.object(audit_runner, "should_skip_launch", return_value=False):
        audit_runner.run_agent_pool(pool_state, [1, 2, 3], True)
    check(
        sorted(latch_calls) == [(1, True), (2, True), (3, True)],
        "a provider-limited slot halts launches across the whole pool",
        repr(latch_calls),
    )
    pool_runtime.num_agents = 2
    # Work availability is sticky (a fuzz lead stays listed all pool), so a
    # clean session that did nothing must not be replaced by another no-op.
    noop_calls, _ = _drive_pool(
        lambda agent, _calls: _pool_result(agent, raw=_transcript(f"noop{agent}", 0)),
    )
    check(
        sorted((a, c) for a, c, _l in noop_calls) == [(1, True), (2, True)],
        "a clean session with no tool call does not get its slot replaced",
        repr(noop_calls),
    )
    worked_calls, _ = _drive_pool(
        lambda agent, _calls: _pool_result(agent, raw=_transcript(f"work{agent}", 3)),
    )
    check(
        sum(1 for a, cold, _l in worked_calls if a == 1 and not cold) >= 1,
        "a clean session that made tool calls does get its slot replaced",
        repr(worked_calls),
    )
    # The epoch deadline, not the last initial session, bounds the tail.
    with mock.patch.object(audit_runner, "_agent_timeout", return_value=1):
        epoch_calls, _ = _drive_pool(lambda agent, _calls: _pool_result(agent))
    check(
        sorted((a, c) for a, c, _l in epoch_calls) == [(1, True), (2, True)],
        "a closed pool epoch defers the slot to post-iteration triage",
        repr(epoch_calls),
    )
    # Refills stop with the last initial session on purpose: that sentinel is
    # the clock for iteration-counted strategy rotation and the bound on
    # sticky-signal spin. A one-slot cohort therefore chains nothing, and
    # continuation of a turn-capped session comes from the next iteration.
    solo_calls = []
    def _solo_agent(_runtime, _context, agent, _iteration, cold, _limit):
        solo_calls.append((agent, cold))
        return _pool_result(agent, turn_capped=True)
    with mock.patch.object(audit_runner, "run_agent_guarded", side_effect=_solo_agent), \
         mock.patch.object(audit_runner, "should_skip_launch", return_value=False):
        audit_runner.run_agent_pool(pool_state, [1], True)
    check(
        solo_calls == [(1, True)],
        "a one-slot cohort runs one session and defers continuation to triage",
        repr(solo_calls),
    )
    pool_runtime.refill_workers = False
    no_refill_calls = []
    def _no_refill_agent(_runtime, _context, agent, _iteration, cold, _limit):
        no_refill_calls.append((agent, cold))
        return audit_runner.AgentResult(
            agent, "reproduce", 0, Path(), Path(), {}, "none", None
        )
    with mock.patch.object(audit_runner, "run_agent_guarded", side_effect=_no_refill_agent), \
         mock.patch.object(audit_runner, "should_skip_launch", return_value=False):
        audit_runner.run_agent_pool(pool_state, [1, 2], True)
    check(
        sorted(no_refill_calls) == [(1, True), (2, True)],
        "disabled worker refills never expand the configured pool",
        repr(no_refill_calls),
    )
    pool_runtime.refill_workers = True
    refill_block = threading.Event()
    expired_calls = []
    def _expired_pool_agent(_runtime, _context, agent, _iteration, cold, _limit):
        expired_calls.append((agent, cold))
        if agent == 2:
            refill_block.wait(0.2)
        else:
            refill_block.set()
        return audit_runner.AgentResult(
            agent, "reproduce", 0, Path(), Path(), {}, "none", None
        )
    with mock.patch.object(
        audit_runner, "run_agent_guarded", side_effect=_expired_pool_agent,
    ), mock.patch.object(
        audit_runner, "should_skip_launch", return_value=False,
    ), mock.patch.object(
        audit_runner, "_productive_wall_remaining", return_value=0,
    ):
        audit_runner.run_agent_pool(pool_state, [1, 2], True)
    check(
        sorted(expired_calls) == [(1, True), (2, True)],
        "worker-pool refill is suppressed once the productive deadline expires",
        repr(expired_calls),
    )
    with mock.patch.object(audit_runner, "run_agent", side_effect=RuntimeError("fixture failure")):
        guarded = audit_runner.run_agent_guarded(
            pool_runtime, pool_context, 1, 1, False
        )
    check(
        guarded.provider_issue == "internal" and guarded.raw.is_file(),
        "one internal agent failure is logged and isolated from the worker pool",
    )

    benchmark_preflight_args = SimpleNamespace(
        dry_run=False, regenerate=False, target="sample-c",
        backend="codex",
    )
    with mock.patch.object(
        benchmark_runner.target_config, "load_toml_into"
    ), mock.patch.object(
        benchmark_runner.build_preflight, "refresh"
    ) as benchmark_preflight:
        benchmark_runner.preflight_build(
            benchmark_preflight_args, root / "benchmark-preflight", "fixture-model"
        )
    check(
        benchmark_preflight.call_count == 1
        and benchmark_preflight.call_args[0][2] == "sample-c"
        and benchmark_preflight.call_args[0][5:7] == ("codex", "fixture-model")
        and benchmark_preflight.call_args.kwargs.get("include_alternates") is False,
        "benchmark preflights the shared primary sanitizer build without alternate synthesis",
    )
    benchmark_preflight_args.dry_run = True
    with mock.patch.object(
        benchmark_runner.build_preflight, "refresh"
    ) as dry_preflight:
        benchmark_runner.preflight_build(
            benchmark_preflight_args, root / "benchmark-preflight", "fixture-model"
        )
    check(
        dry_preflight.call_count == 0,
        "benchmark dry runs do not materialize sanitizer builds",
    )

    limited_cell = root / "limited-cell"
    limited_cell.mkdir()
    with mock.patch.object(
        benchmark_runner, "_provider_issue", return_value="capacity_limited"
    ):
        benchmark_runner._record_provider_quality(limited_cell, limited_cell)
    check(
        (limited_cell / ".backend-unavailable").is_file()
        and (limited_cell / ".run-quality").read_text().strip() == "provider_limited",
        "quota evidence with no artifacts overrides a nominally successful cell",
    )
    productive_cell = root / "productive-limited-cell"
    (productive_cell / "findings" / "FIND-001").mkdir(parents=True)
    with mock.patch.object(
        benchmark_runner, "_provider_issue", return_value="capacity_limited"
    ):
        benchmark_runner._record_provider_quality(productive_cell, productive_cell)
    check(
        not (productive_cell / ".backend-unavailable").exists()
        and (productive_cell / ".run-quality").read_text().strip() == "provider_recovered",
        "quota evidence preserves a productive partial cell as recovered",
    )

    gate_results = root / "benchmark-gate"
    gate_results.mkdir()
    decision_seen = {}
    def _gate_probe(_results, **_kwargs):
        decision_seen.update(
            backend=os.environ.get("ACTIVE_BACKEND"),
            model=os.environ.get("MODEL"), target=os.environ.get("TARGET_ROOT"),
            controls=os.environ.get("TARGET_ATTACKER_CONTROLS_CSV"),
            product=_kwargs.get("target_root_is_product"),
        )
        return {"accepted": 1, "rejected": 0, "pending": 0}
    with mock.patch.object(
        benchmark_runner, "benchmark_target_config", return_value=generic_config,
    ), mock.patch.object(triage, "validate_find_gate", side_effect=_gate_probe):
        counts = benchmark_runner.drain_find_gate(
            gate_results, "codex", "fixture-model", generic_target, "demo",
        )
    check(
        counts["accepted"] == 1 and decision_seen == {
            "backend": "codex", "model": "fixture-model", "target": str(generic_target),
            "controls": "bytes,call-sequence", "product": True,
        },
        "benchmark finding drain receives target scope and threat-model controls",
        repr(decision_seen),
    )
    gate_passes = [0]
    def _limited_gate(_results, **_kwargs):
        # First pass records an unknown provider reset; the second recovers.
        marker = Path(os.environ["LLM_DECIDE_LIMIT_FILE"])
        gate_passes[0] += 1
        if gate_passes[0] == 1:
            marker.write_text("unknown\n", encoding="utf-8")
        return {"accepted": gate_passes[0], "rejected": 0, "pending": 0}
    with mock.patch.dict(os.environ, {
        "FIND_GATE_MAX_PAUSES": "1", "FIND_GATE_PAUSE_MAX_TOTAL": "1",
        "FIND_GATE_PAUSE_CHUNK": "1",
    }, clear=False), mock.patch.object(triage, "validate_find_gate", side_effect=_limited_gate), \
         mock.patch.object(benchmark_runner.time, "sleep") as sleep_mock:
        resumed = benchmark_runner.drain_find_gate(
            gate_results, "codex", "fixture-model", generic_target, "demo",
        )
    check(
        gate_passes[0] == 2 and resumed["accepted"] == 2 and sleep_mock.call_count == 1,
        "benchmark finding drain resumes after a provider-limit marker",
    )
    with mock.patch.object(
        triage, "validate_find_gate",
        return_value={"accepted": 0, "rejected": 0, "pending": 1},
    ) as expired_gate, \
         mock.patch.object(benchmark_runner.time, "monotonic", return_value=100.0):
        expired_counts = benchmark_runner.drain_find_gate(
            gate_results, "codex", "fixture-model", generic_target, "demo",
            deadline=100.0,
        )
    check(
        expired_counts == {"accepted": 0, "rejected": 0, "pending": 1}
        and expired_gate.call_args.kwargs["deadline"] == 100.0,
        "expired benchmark validation reports pending findings without extending the deadline",
    )

    limit_marker = root / "decision-provider-limit"
    limit_marker.write_text("unknown\n", encoding="utf-8")
    with mock.patch.dict(os.environ, {"LLM_DECIDE_LIMIT_FILE": str(limit_marker)}, clear=False), \
         mock.patch.object(llm_decide, "_resolve_mock_value", return_value=""), \
         mock.patch.object(llm_decide, "_run_decision") as limited_decision:
        limited_result = llm_decide.llm_decide(
            "find_quality", "accept,reason,class,severity", "review this", 1,
        )
    check(
        limited_result is None and not limited_decision.called,
        "a confirmed provider limit stops queued validation decisions",
    )

    decision_payload = '{"accept":true,"reason":"ok","class":"state","severity":"low"}'
    for usage_backend in ("claude", "codex", "gemini", "grok"):
        usage_index = root / f"usage-index-{usage_backend}.jsonl"
        with mock.patch.dict(os.environ, {
            "ACTIVE_BACKEND": usage_backend, "MODEL": "fixture-model",
        }, clear=False), mock.patch.object(
            llm_decide, "_invoke_backend", return_value=decision_payload,
        ):
            usage_result, usage_error = llm_decide._run_decision(
                "find_quality", "accept,reason,class,severity", "p" * 400, 1, "",
                usage_index,
            )
        usage_row = json.loads(usage_index.read_text(encoding="utf-8"))
        check(
            usage_result == {"accept": True, "reason": "ok", "class": "state", "severity": "low"}
            and usage_error is False
            and usage_row["estimated"] is True
            and usage_row["tokens"]["input"] == 100
            and usage_row["tokens"]["output"] > 0
            and usage_row["role"] == "decision:find_quality"
            and usage_row["backend"] == usage_backend
            and usage_row["resolved_effort"] == llm_invoke.default_effort(usage_backend),
            f"{usage_backend} one-shot decisions append labeled estimated usage",
            repr(usage_row),
        )

    # The shape `claude --print --output-format json` actually returns. The
    # envelope is valid JSON, so a parser that reads it as the decision finds
    # none of the required keys and fails without arming the breaker — every
    # decision falling open at once. Unwrapping it is what keeps the answer
    # parseable, and keeping it whole is what makes the usage measured.
    envelope_index = root / "usage-index-envelope.jsonl"
    envelope = json.dumps({
        "type": "result", "subtype": "success", "is_error": False,
        "result": decision_payload,
        "usage": {
            "input_tokens": 2, "cache_creation_input_tokens": 6647,
            "cache_read_input_tokens": 15185, "output_tokens": 9,
            "cache_creation": {
                "ephemeral_1h_input_tokens": 6647,
                "ephemeral_5m_input_tokens": 0,
            },
        },
        "modelUsage": {
            "claude-opus-5[1m]": {
                "inputTokens": 2, "outputTokens": 9,
                "cacheReadInputTokens": 15185,
                "cacheCreationInputTokens": 6647,
                "costUSD": 0.0742975,
            },
        },
        "total_cost_usd": 0.0742975,
    })
    with mock.patch.dict(os.environ, {
        "ACTIVE_BACKEND": "claude", "MODEL": "fixture-model",
    }, clear=False), mock.patch.object(
        llm_decide, "_invoke_backend", return_value=envelope,
    ):
        envelope_result, envelope_error = llm_decide._run_decision(
            "find_quality", "accept,reason,class,severity", "p" * 400, 1, "",
            envelope_index,
        )
    envelope_row = json.loads(envelope_index.read_text(encoding="utf-8"))
    check(
        envelope_result == {"accept": True, "reason": "ok", "class": "state", "severity": "low"}
        and envelope_error is False
        and envelope_row["estimated"] is False
        and envelope_row["usage_complete"] is True
        and envelope_row["tokens"] == {
            "input": 2, "cached_input": 15185, "cache_creation": 6647,
            "cache_creation_1h": 6647, "output": 9,
        },
        "a decision envelope parses to the answer and meters its own usage",
        repr(envelope_row),
    )
    result_shaped_answer = json.dumps({
        "type": "result", "result": "model-selected value",
        "accept": True, "reason": "ok", "class": "state", "severity": "low",
    })
    with mock.patch.dict(os.environ, {
        "ACTIVE_BACKEND": "codex", "MODEL": "fixture-model",
    }, clear=False), mock.patch.object(
        llm_decide, "_invoke_backend", return_value=result_shaped_answer,
    ):
        result_shaped, result_shaped_error = llm_decide._run_decision(
            "find_quality", "accept,reason,class,severity", "p" * 400, 1, "",
        )
    check(
        result_shaped == {
            "type": "result", "result": "model-selected value",
            "accept": True, "reason": "ok", "class": "state", "severity": "low",
        }
        and result_shaped_error is False,
        "another backend's result-shaped answer is not mistaken for a Claude envelope",
        repr(result_shaped),
    )
    check(
        llm_decide._decision_payload(
            '{"accept":true}', "claude",
        ) == '{"accept":true}'
        and llm_decide._decision_payload("prose", "claude") == "prose"
        and llm_decide._decision_payload(
            '{"type":"result","result":"decision value"}', "codex",
        ) == '{"type":"result","result":"decision value"}',
        "a bare decision response is left as it is",
    )

    # opencode streams the answer as events and closes with the step_finish
    # that carries its token counts, so the stream is what the usage recorder
    # needs and the concatenated assistant text is what the parser needs.
    stream_index = root / "usage-index-stream.jsonl"
    stream = "\n".join(json.dumps(event) for event in (
        {"type": "step_start", "part": {"type": "step-start"}},
        {"type": "text", "part": {"type": "text", "text": decision_payload}},
        {"type": "step_finish", "part": {
            "type": "step-finish", "cost": 0,
            "tokens": {
                "total": 11941, "input": 11887, "output": 54,
                "reasoning": 0, "cache": {"write": 0, "read": 0},
            },
        }},
    ))
    with mock.patch.dict(os.environ, {
        "ACTIVE_BACKEND": "oss", "MODEL": "fixture-local-model",
    }, clear=False), mock.patch.object(
        llm_decide, "_invoke_backend", return_value=stream,
    ):
        stream_result, stream_error = llm_decide._run_decision(
            "find_quality", "accept,reason,class,severity", "p" * 400, 1, "",
            stream_index,
        )
    stream_row = json.loads(stream_index.read_text(encoding="utf-8"))
    check(
        stream_result == {"accept": True, "reason": "ok", "class": "state", "severity": "low"}
        and stream_error is False
        and stream_row["estimated"] is False
        and stream_row["tokens"]["input"] == 11887
        and stream_row["tokens"]["output"] == 54,
        "an event stream parses to the answer and meters its own usage",
        repr(stream_row),
    )
    check(
        llm_decide._decision_payload("not a stream", "oss") == "not a stream",
        "a transport that yields no assistant text is left as it is",
    )

    # Codex and native Gemini expose the same measured terminal counts used by
    # full audit sessions. Decisions must retain those transports too; plain
    # output silently turns both into character-count estimates.
    for structured_backend, structured_stream, structured_tokens in (
        (
            "codex",
            "\n".join(json.dumps(event) for event in (
                {"type": "thread.started", "thread_id": "fixture"},
                {"type": "item.completed", "item": {
                    "type": "agent_message", "text": decision_payload,
                }},
                {"type": "turn.completed", "usage": {
                    "input_tokens": 12003, "cached_input_tokens": 11000,
                    "output_tokens": 38,
                }},
            )),
            {"input": 12003, "cached_input": 11000, "output": 38},
        ),
        (
            "gemini",
            "\n".join(json.dumps(event) for event in (
                {"type": "init", "session_id": "fixture"},
                {"type": "message", "role": "assistant",
                 "content": decision_payload},
                {"type": "result", "status": "success", "stats": {
                    "input_tokens": 8011, "cached": 7000,
                    "output_tokens": 29,
                }},
            )),
            {"input": 8011, "cached_input": 7000, "output": 29},
        ),
    ):
        structured_index = (
            root / f"usage-index-structured-{structured_backend}.jsonl"
        )
        env = {
            "ACTIVE_BACKEND": structured_backend, "MODEL": "fixture-model",
        }
        if structured_backend == "gemini":
            env["USE_GEMINI_CLI"] = "1"
        with mock.patch.dict(os.environ, env, clear=False), mock.patch.object(
            llm_decide, "_invoke_backend", return_value=structured_stream,
        ):
            structured_result, structured_error = llm_decide._run_decision(
                "find_quality", "accept,reason,class,severity", "p" * 400, 1,
                "", structured_index,
            )
        structured_row = json.loads(
            structured_index.read_text(encoding="utf-8")
        )
        check(
            structured_result == {
                "accept": True, "reason": "ok", "class": "state",
                "severity": "low",
            }
            and structured_error is False
            and structured_row["estimated"] is False
            and structured_row["usage_complete"] is True
            and all(
                structured_row["tokens"][key] == value
                for key, value in structured_tokens.items()
            ),
            f"{structured_backend} decision transport preserves answer and measured usage",
            repr((structured_result, structured_row)),
        )
    timeout_index = root / "usage-index-timeout.jsonl"
    timeout_error = subprocess.TimeoutExpired(
        ["claude"], 45, output=b'{"type":"assistant"}', stderr=b"partial",
    )
    with mock.patch.dict(os.environ, {
        "ACTIVE_BACKEND": "claude", "MODEL": "fixture-model",
    }, clear=False), mock.patch.object(
        llm_decide, "_invoke_backend", side_effect=timeout_error,
    ):
        timeout_result, timeout_backend_error = llm_decide._run_decision(
            "find_quality", "accept,reason,class,severity", "review", 45, "",
            timeout_index,
        )
    timeout_row = json.loads(timeout_index.read_text(encoding="utf-8"))
    check(
        timeout_result is None and timeout_backend_error is False
        and timeout_row["usage_complete"] is False,
        "timed-out decisions retain partial usage without crashing finalization",
    )

    check(
        benchmark_runner.parser().parse_args([]).finalize_wall == 0
        and benchmark_runner.parser().parse_args([]).finalize_workers == 4,
        "benchmark final validation runs to completion by default",
    )
    layout_root = root / "usage-layouts"
    harness_results = layout_root / "harness" / "results"
    harness_results.mkdir(parents=True)
    (harness_results.parent / "logs").mkdir()
    direct_results = layout_root / "direct"
    (direct_results / "logs").mkdir(parents=True)
    check(
        benchmark_runner.metrics._find_index_jsonl(harness_results)
        == harness_results.parent / "logs" / "index.jsonl"
        and benchmark_runner.metrics._find_index_jsonl(direct_results)
        == direct_results / "logs" / "index.jsonl",
        "usage ledger routing is stable before either layout creates index.jsonl",
    )

    config_root = root / "config-root"
    target_tree = config_root / "targets" / "nested" / "demo"
    target_tree.mkdir(parents=True)
    base_config = config_root / "output" / "nested" / "demo" / "target.toml"
    base_config.parent.mkdir(parents=True)
    base_config.write_text('target = "nested/demo"\n[threat_model]\nattacker_controls = ["timing"]\n', encoding="utf-8")
    experiment_root = config_root / "output" / "nested" / "demo-exp"
    loaded_config = audit_runner._load_config(config_root, target_tree, experiment_root, "nested/demo")
    equal(["timing"], loaded_config.attacker_controls, "audit experiments preserve the curated base target config")
    check((experiment_root / "target.toml").is_file(), "audit experiment config is materialized for reproducibility")

    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        equal(1, benchmark_runner.main(["--target", ", ,", "--dry-run"]), "benchmark rejects an empty target list")
    check("non-empty slug" in stderr.getvalue(), "benchmark empty-target error is actionable")

print(f"\n{passed}/{passed + failed} passed, {failed} failed")
raise SystemExit(1 if failed else 0)
