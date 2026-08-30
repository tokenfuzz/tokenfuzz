#!/usr/bin/env python3
"""Sanitizer policy, runtime options, and symbolization helpers."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Mapping

import build_lease

LIB_DIR = Path(__file__).resolve().parent
OPTIONS_FILE = LIB_DIR / "sanitizer_options.conf"
SYMBOLIZER = LIB_DIR / "clusterfuzz_symbolizer.py"
SANITIZER_ENV = {
    "asan": "ASAN_OPTIONS",
    "ubsan": "UBSAN_OPTIONS",
    "msan": "MSAN_OPTIONS",
    "tsan": "TSAN_OPTIONS",
}
FUZZER_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# A frame with no source location: either bare (symbolize=0) or ASan's dladdr
# fallback, which names the function but not the file — `#0 0xADDR in func+0x4a0
# (/lib/foo.dylib:arm64+0x84f30)`. Recognition anchors on the trailing
# module+offset, which is what makes such a frame repairable, and treats
# whatever sits between it and the address as opaque: a demangled C++ name
# carries spaces and parentheses (`operator new(unsigned long)+0x20`), so any
# pattern that constrains that text only recognizes plain C identifiers. A
# fully symbolized frame has no such trailer.
RAW_FRAME = re.compile(
    r"^ *#[0-9]+ +0x[0-9a-f]+ +(?:in +.*? +)?\([^)]*\+0x[0-9a-f]+\)", re.M)


def build_dir(name: str, target_root: str = "", env: Mapping[str, str] | None = None) -> Path:
    environment = os.environ if env is None else env
    root = target_root or environment.get("TARGET_ROOT", "")
    return Path(root) / f"build-{name}{environment.get('AUDIT_BUILD_SUFFIX', '')}"


def hold_build(name: str, target_root: str = "", env: Mapping[str, str] | None = None) -> None:
    """Keep the tree this runner is about to execute from being replaced.

    A build is rewritten in place, so between resolving a binary and finishing
    with it the tree can otherwise vanish — the runner then reports a load
    failure, or worse a clean run, for a build that was merely mid-rebuild. The
    lease is held until this process exits, which is exactly the span of one
    execution. It binds cooperating rebuilders only: an agent invoking a build
    tool by hand is outside it.
    """
    tree = build_dir(name, target_root, env)
    if not tree.is_dir():
        return
    build_lease.hold_shared(
        tree.parent, tree.name,
        logger=lambda message: print(f"[sanitizer] {message}", file=sys.stderr),
    )


def generic_skips_testcase(name: str, env: Mapping[str, str] | None = None) -> bool:
    """Whether the generic runner was told its target takes no testcase.

    One reader for a decision three processes make: run-sanitizer-multi guards
    on it and the child runner it launches acts on it. bin/run-asan (asan,
    race, runner) reads only its own spelling, the others prefer the shared
    one, and a guard reading them differently from its child could reject a
    placeholder the child ignores — or admit a path the child never opens.
    """
    environment = os.environ if env is None else env
    if name in {"asan", "race", "runner"}:
        return environment.get("ASAN_GENERIC_SKIP_TESTCASE", "0") == "1"
    return environment.get(
        "SANITIZER_GENERIC_SKIP_TESTCASE",
        environment.get("ASAN_GENERIC_SKIP_TESTCASE", "0"),
    ) == "1"


def generic_runner_cwd(
    name: str, env: Mapping[str, str] | None = None,
) -> str | None:
    """The directory bin/probe chose for a configured language runner.

    Probe has already decided whether the configured runner owns this
    execution. The child re-deriving that by comparing paths disagreed with it
    whenever the two resolved the runner differently -- an overridden
    [runner].bin resolves to one program in probe and another here -- and the
    module search directory was dropped with no diagnostic. An empty value is
    probe's explicit "not the configured runner" answer; an absent value means
    a direct invocation supplied no answer and the child must compare paths.
    """
    environment = os.environ if env is None else env
    if name in {"asan", "race", "runner"}:
        key = "ASAN_GENERIC_RUNNER_CWD"
    elif "SANITIZER_GENERIC_RUNNER_CWD" in environment:
        key = "SANITIZER_GENERIC_RUNNER_CWD"
    else:
        key = "ASAN_GENERIC_RUNNER_CWD"
    return environment[key] if key in environment else None


#: Carrier for a loader search path a caller needs the executed binary to have.
#: A caller cannot set DYLD_LIBRARY_PATH itself and have it survive: every
#: bin/ entry point starts `#!/usr/bin/env python3`, and macOS SIP strips
#: DYLD_* at the exec of the protected /usr/bin/env, so the variable is gone
#: before the runner reads it. This name is not DYLD_*, so it crosses every
#: hop, and prepare_runtime_env is the last point before the binary launches.
LIBRARY_PATH_ENV = "SANITIZER_LIBRARY_PATH"


def prepare_runtime_env(selected: str, env: Mapping[str, str] | None = None) -> dict[str, str]:
    result = dict(os.environ if env is None else env)
    selected_name = SANITIZER_ENV.get(selected)
    if selected not in {*SANITIZER_ENV, "none", "runner", "race", ""}:
        raise ValueError(f"unknown sanitizer: {selected}")
    for name in SANITIZER_ENV.values():
        if name != selected_name:
            result.pop(name, None)
    carried = result.get(LIBRARY_PATH_ENV, "")
    if carried:
        for variable in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH"):
            existing = result.get(variable, "")
            result[variable] = (
                f"{carried}{os.pathsep}{existing}" if existing else carried
            )
    return result


def options_for(name: str, mode: str) -> str:
    if not OPTIONS_FILE.is_file():
        raise FileNotFoundError(f"option table missing: {OPTIONS_FILE}")
    full = ""
    for line in OPTIONS_FILE.read_text().splitlines():
        fields = line.split(None, 2)
        if not fields or fields[0].startswith("#") or len(fields) < 3:
            continue
        sanitizer, configured_mode, options = fields
        if sanitizer != name:
            continue
        if configured_mode == mode:
            return options
        if configured_mode == "full":
            full = options
    return full


def runtime_options(
    name: str, base: str, env: Mapping[str, str] | None = None, final: str = ""
) -> str:
    environment = os.environ if env is None else env
    try:
        existing = environment.get(SANITIZER_ENV[name], "")
    except KeyError as exc:
        raise ValueError(f"unknown sanitizer: {name}") from exc
    # ``final`` is for harness invariants that ambient options must not undo.
    # Sanitizer runtimes use the last duplicate key, so it belongs after the
    # operator-provided environment rather than in ``base``.
    return ":".join(part for part in (base, existing, final) if part)


def compose_options(name: str, base: str, config=None) -> str:
    if config is None:
        return base
    parts = [base] if base else []
    suppression = config.sanitizer_suppressions_path(name)
    if suppression:
        if Path(suppression).is_file():
            parts.append(f"suppressions={suppression}")
        else:
            print(f"[sanitizer] WARNING: {name} suppressions file not found: {suppression}", file=sys.stderr)
    extra = config.sanitizer_options.get(name, "")
    if extra:
        parts.append(extra)
    return ":".join(parts)


def generic_rss_limit_mb(env: Mapping[str, str] | None = None) -> int:
    value = (os.environ if env is None else env).get("PROBE_RSS_LIMIT_MB", "5120")
    return int(value) if value.isdigit() and int(value) > 0 else 0


def validate_fuzzer_name(value: str) -> bool:
    return bool(FUZZER_NAME.fullmatch(value))


def default_fuzz_crash_dir(env: Mapping[str, str] | None = None) -> Path:
    environment = os.environ if env is None else env
    return Path(environment.get("RESULTS_DIR", "results")) / "fuzz-crashes" / environment.get("FUZZER", "")


def llvm_tool(name: str) -> str:
    prefix = os.environ.get("LLVM_PREFIX")
    if prefix and os.access(Path(prefix) / "bin" / name, os.X_OK):
        return str(Path(prefix) / "bin" / name)
    candidates = [Path("/opt/homebrew/opt/llvm"), Path("/usr/local/opt/llvm")]
    candidates.extend(sorted(Path("/usr/lib").glob("llvm-*")))
    candidates.append(Path("/usr/local"))
    for candidate in candidates:
        tool = candidate / "bin" / name
        if os.access(tool, os.X_OK):
            return str(tool)
    return shutil.which(name) or name


def symbolize_available() -> bool:
    if not SYMBOLIZER.is_file():
        return False
    tool = llvm_tool("llvm-symbolizer")
    return (Path(tool).is_file() and os.access(tool, os.X_OK)) or bool(shutil.which("atos") or shutil.which("addr2line"))


def symbolize_file(path: str | os.PathLike[str], *, full_path: bool = False) -> bool:
    """Rewrite a sanitizer report in place with source locations.

    ``full_path`` asks the platform symbolizer for full source paths; coverage
    journals need them, crash reports keep the basenames their signatures use.

    Returns whether the report is free of unsymbolized frames afterwards. A
    failure is never fatal — the raw report is still evidence — but it must not
    be silent: this returned quietly when the symbolizer could not start, and a
    whole benchmark run shipped address-only stacks while reporting itself
    clean. Anything that leaves a raw frame behind says so on stderr.
    """
    report = Path(path)
    if not report.is_file() or not report.stat().st_size or not SYMBOLIZER.is_file():
        return False
    raw = report.read_text(errors="replace")
    if not RAW_FRAME.search(raw):
        return True
    args = [sys.executable, str(SYMBOLIZER)]
    if sys.platform == "darwin" and shutil.which("atos"):
        args.append("--no-llvm-symbolizer")
    else:
        args.extend(("--llvm-symbolizer", llvm_tool("llvm-symbolizer")))
    if full_path:
        args.append("--full-path")
    with tempfile.NamedTemporaryFile() as rendered, report.open("rb") as source:
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).with_name("timeout.py")), "60", "TERM", "0", *args],
            stdin=source,
            stdout=rendered,
            stderr=subprocess.PIPE,
            check=False,
        )
        rendered.flush()
        if completed.returncode != 0 or not Path(rendered.name).stat().st_size:
            _warn_unsymbolized(report, completed)
            return False
        # Replaced, never truncated in place: this rewrites saved evidence now,
        # not just a runner's scratch output, and a write interrupted halfway
        # would leave the only copy of a diagnostic damaged.
        staged = report.with_name(f"{report.name}.symbolized")
        staged.write_bytes(Path(rendered.name).read_bytes())
        os.replace(staged, report)
    if RAW_FRAME.search(report.read_text(errors="replace")):
        # The symbolizer ran and answered, and frames still carry no source
        # location: a stripped build, a moved binary, or a debug-info mismatch.
        _warn_unsymbolized(report, None)
        return False
    return True


def _warn_unsymbolized(report: Path, completed) -> None:
    """Say that a report kept raw frames, and why, on the runner's stderr."""
    detail = "symbolizer left raw frames"
    if completed is not None:
        tail = (completed.stderr or b"").decode(errors="replace").strip().splitlines()
        reason = tail[-1] if tail else f"rc={completed.returncode}"
        detail = f"symbolizer failed: {reason}"
        if completed.returncode == 124:
            detail = "symbolizer timed out after 60s"
    print(
        f"[sanitizer] WARN: {report.name} keeps unsymbolized frames "
        f"({detail}); some stack frames may lack source lines",
        file=sys.stderr,
    )


def warn_if_disabled(name: str, config=None) -> None:
    if config is None or not config.sanitizers_enabled:
        return
    if not config.sanitizer_is_enabled(name):
        print(
            f"[sanitizer] NOTE: '{name}' is not in [sanitizer].enabled in target.toml "
            f"- running anyway. Add '{name}' to enable it for the audit harness.",
            file=sys.stderr,
        )
