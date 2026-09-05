"""Shared helpers for invoking importable Python command entry points."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parent.parent


def invoke_main(
    main: Callable[[list[str]], int],
    arguments: Sequence[str],
    *,
    argv0: str | None = None,
) -> int:
    """Invoke a command ``main`` with the wrapper's argv/exit semantics."""
    argv = list(arguments)
    previous_argv = sys.argv
    sys.argv = [argv0 or previous_argv[0], *argv]
    try:
        try:
            code = main(argv)
        except SystemExit as error:
            code = error.code
        if code is None:
            return 0
        if isinstance(code, int):
            if not -sys.maxsize - 1 <= code <= sys.maxsize:
                return 255
            return code & 0xFF
        print(code, file=sys.stderr)
        return 1
    finally:
        sys.argv = previous_argv


def run_main_captured(
    main: Callable[[list[str]], int],
    arguments: Sequence[str],
    *,
    command: Sequence[str] | None = None,
    argv0: str | None = None,
) -> subprocess.CompletedProcess[str]:
    """Call ``main`` while capturing Python and inherited child output.

    Redirecting ``sys.stdout`` alone misses subprocesses that inherit file
    descriptors 1 and 2. The test harness exercises several thin Python
    entry points whose real work still launches contained children, so capture
    the descriptors and preserve the same observable output as a CLI call.
    """
    argv = list(arguments)
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        sys.stdout.flush()
        sys.stderr.flush()
        saved_stdout = os.dup(1)
        saved_stderr = os.dup(2)
        try:
            os.dup2(stdout.fileno(), 1)
            os.dup2(stderr.fileno(), 2)
            returncode = invoke_main(
                main, argv,
                argv0=argv0 or (str(command[0]) if command else None),
            )
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            os.dup2(saved_stdout, 1)
            os.dup2(saved_stderr, 2)
            os.close(saved_stdout)
            os.close(saved_stderr)
        stdout.seek(0)
        stderr.seek(0)
        return subprocess.CompletedProcess(
            list(command or argv),
            int(returncode or 0),
            stdout.read().decode(encoding="utf-8", errors="replace"),
            stderr.read().decode(encoding="utf-8", errors="replace"),
        )


def isolated_script_root(base: Path) -> Path:
    """Build a harness root under ``base`` whose ``output/`` holds no targets.

    Target-overlay resolution reads ``<root>/output/<name>/target.toml``: an
    operator who has set up an ordinary target under an overlay's name keeps
    that identity, so ``chromium`` stops meaning ``chromium/src`` on their
    machine. A test that asserts the alias against the checkout's own
    ``output/`` therefore samples that operator state. This root shares the
    checkout's ``bin`` and ``lib`` (so overlays and imports resolve) but owns
    empty ``output`` and ``targets`` trees, which is the host state the alias
    behaviour is defined against.
    """
    root = Path(base) / "harness-root"
    root.mkdir()
    for shared in ("bin", "lib"):
        (root / shared).symlink_to(REPO_ROOT / shared, target_is_directory=True)
    (root / "output").mkdir()
    (root / "targets").mkdir()
    return root
