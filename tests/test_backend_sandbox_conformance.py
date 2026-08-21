#!/usr/bin/env python3
"""Live check that a sandboxed backend can still run ordinary agent commands.

Every other test here asserts the *configuration* a backend launches with.
That is what let a real regression through: the launch flags stayed correct
while the permission layer silently denied 9% of agent Bash calls, and no
assertion about a settings dict could notice, because the flags were never
the thing that was wrong. Only running a backend and looking at what reached
the filesystem separates "configured to allow" from "allows".

The shapes below are the ones audit sessions actually issue — a `;` chain, a
pipe into a redirect, mixed quoting, a multi-line script. The `;` chain is
the specific shape that broke: `bin/peek f:1-5` ran while
`bin/peek f:1-5; echo; bin/peek f:7-9` was denied.

The second case covers the *launch* rather than the command: a grant that
reaches its tree through a symlink, which is what every benchmark cell hands
its agents. That one cost a five-hour harness row every command it ran, and a
plain workspace cannot expose it — the symlink has to be in the fixture.

Opt-in, because each backend costs a real provider call:

    TOKENFUZZ_LIVE_BACKENDS=claude python3 tests/test_backend_sandbox_conformance.py
    TOKENFUZZ_LIVE_BACKENDS=all bash tests/run-tests.sh

Unset, the suite skips — an ordinary `bash tests/run-tests.sh` stays offline
and free. This asserts only that work is *not blocked*; it deliberately makes
no claim about the sandbox boundary, since an operator's own granted
directories differ per machine and would make a containment assertion fail
for a reason that is not a defect. `test_llm_invoke_py` pins those keys.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import llm_invoke  # noqa: E402

# Backends whose native sandbox the harness accepts for agent launches, asked
# of the harness rather than listed here: the rest refuse `sandboxed` outright,
# so there is no configuration under which this test could run them, and a
# backend that gains or loses a usable sandbox joins or leaves on its own.
SANDBOXABLE = tuple(
    backend
    for backend in ("claude", "codex", "gemini", "grok", "oss")
    if not llm_invoke.agent_security_problem(backend, "sandboxed")
)

# One shell shape per row, each writing a marker only a command that actually
# ran can produce. Filesystem side effects keep the assertion backend-neutral:
# every CLI reports denials in its own transcript dialect, but none of them
# can fake a file.
SHAPES = (
    ("chain.txt", "printf one > chain.txt; printf two >> chain.txt", "onetwo"),
    ("pipe.txt", "printf hello | tr a-z A-Z > pipe.txt", "HELLO"),
    ("quote.txt", "printf '%s' \"mixed 'quoting' ok\" > quote.txt", "mixed 'quoting' ok"),
    ("multi.txt", "for n in a b c; do\n  printf '%s' \"$n\" >> multi.txt\ndone", "abc"),
)

PROMPT = """You are a non-interactive conformance probe. Run each of these
shell commands with your Bash tool, exactly as written, one tool call each,
in the current working directory. Do not rewrite, split, combine, or simplify
them — the exact shell syntax is what is under test. Do not use file-editing
tools; these must go through Bash. Report the exit code of each, then stop.

{commands}
"""

# The shape a benchmark cell launches: the workspace root is an ordinary
# directory whose `targets` entry is a symlink to the real tree, and the grant
# handed to the backend points *through* that symlink. Claude turned such a
# grant readable-but-unwritable; Codex refused to create any process at all
# while one was configured, so a five-hour harness row ran zero commands. A
# write that lands in the real tree is the only proof both are fixed.
FACADE_MARKER = "wrote.txt"
FACADE_PROMPT = """You are a non-interactive conformance probe. Run this exact
shell command with your Bash tool, in the current working directory, then
report its exit code and stop. Do not use file-editing tools; it must go
through Bash.

printf conformance > targets/demo/{marker}
"""


# A launch that failed for one of these reasons says nothing about
# permissions, so it skips. Anything else — an unparsable setting, a sandbox
# that would not start, a flag the CLI rejects — is a launch regression this
# suite exists to catch, and it fails. Matched against the transcript, which
# every backend writes before it can reach a provider.
PROVIDER_OUTAGE = (
    "not logged in",
    "please run /login",
    "authentication",
    "unauthorized",
    "401",
    "invalid_api_key",
    "credit balance",
    "quota",
    "rate limit",
    "model requires a newer version",
    "is not supported when using",
    "model metadata for",
    "overloaded",
    "503",
    "529",
)


def requested_backends() -> list[str]:
    raw = os.environ.get("TOKENFUZZ_LIVE_BACKENDS", "").strip()
    if not raw:
        return []
    if raw == "all":
        return list(SANDBOXABLE)
    names = [name.strip() for name in raw.split(",") if name.strip()]
    unknown = sorted(set(names) - set(SANDBOXABLE))
    if unknown:
        raise SystemExit(
            f"TOKENFUZZ_LIVE_BACKENDS: {', '.join(unknown)} cannot launch a "
            f"sandboxed agent; choose from {', '.join(SANDBOXABLE)}"
        )
    return names


class BackendSandboxConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self._workspaces: list[Path] = []
        self._keep = False

    def tearDown(self) -> None:
        # A workspace is the only record of why a live run disagreed, so keep
        # it whenever the answer was not a clean pass.
        if self._keep:
            for workspace in self._workspaces:
                print(f"kept for diagnosis: {workspace}")
            return
        for workspace in self._workspaces:
            shutil.rmtree(workspace, ignore_errors=True)

    def _workspace(self, backend: str, label: str) -> Path:
        """A scratch root with no symlink of its own.

        Resolved, because the platform temp root is itself a symlink on macOS:
        leaving it unresolved would put a symlink component in every path here
        and make the facade case prove nothing about the one link it builds.
        """
        workspace = Path(
            tempfile.mkdtemp(prefix=f"conformance-{label}-{backend}-")
        ).resolve()
        self._workspaces.append(workspace)
        return workspace

    def _run(
        self, backend: str, workspace: Path, launch_dir: Path,
        add_dirs: str, prompt: str, max_turns: int,
    ) -> Path | None:
        """The workspace a finished session left, or None on a provider outage.

        A session the provider refused answers nothing about permissions, so it
        skips. A session that failed for any other reason is a launch
        regression — an unparsable setting or a sandbox that would not start —
        and must fail, or this suite would report green for the very breakage
        it exists to catch. The originally-guarded failure exits 0 and leaves
        the markers unwritten, so that one stays a failure either way.
        """
        transcript = workspace / "transcript.log"
        rc = llm_invoke.run_agent_prompt(
            backend,
            prompt,
            600,
            transcript,
            max_turns=max_turns,
            add_dirs=add_dirs,
            cwd=launch_dir,
            allow_subagents=False,
            agent_security="sandboxed",
        )
        if not rc:
            return workspace
        self._keep = True
        try:
            text = transcript.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        lowered = text.lower()
        if any(marker in lowered for marker in PROVIDER_OUTAGE):
            return None
        self.fail(
            f"{backend} session failed to launch (rc={rc}) for a reason that "
            f"is not a provider outage — the launch configuration is the "
            f"suspect; transcript at {transcript}"
        )

    def _each_backend(self, run_case) -> None:
        """Run `run_case(backend)` for every requested backend.

        One backend being unavailable must not decide the verdict for the
        others: a skip raised mid-loop would end the run and hide a backend
        that had already answered. `run_case` returns False when the provider
        refused the session, and asserts whatever its own case proves.
        """
        backends = requested_backends()
        if not backends:
            self.skipTest("set TOKENFUZZ_LIVE_BACKENDS=claude,codex (or all)")
        unavailable: list[str] = []
        verified = 0
        for backend in backends:
            with self.subTest(backend=backend):
                if not shutil.which(llm_invoke.backend_bin(backend)):
                    unavailable.append(f"{backend}: CLI not on PATH")
                    continue
                try:
                    answered = run_case(backend)
                except AssertionError:
                    self._keep = True
                    raise
                if not answered:
                    unavailable.append(f"{backend}: provider refused the session")
                    continue
                verified += 1
        if not verified:
            self.skipTest(
                "no requested backend produced a session: "
                + "; ".join(unavailable)
            )

    def test_ordinary_command_shapes_are_not_blocked(self) -> None:
        def case(backend: str) -> bool:
            workspace = self._workspace(backend, "shapes")
            commands = "\n\n".join(shell for _, shell, _ in SHAPES)
            finished = self._run(
                backend, workspace, workspace, str(workspace),
                PROMPT.format(commands=commands), len(SHAPES) * 3,
            )
            if finished is None:
                return False
            for name, shell, expected in SHAPES:
                marker = workspace / name
                self.assertTrue(
                    marker.is_file(),
                    f"{backend} never ran `{shell}` — a sandboxed "
                    f"backend must not block an ordinary agent command",
                )
                self.assertEqual(
                    expected, marker.read_text(encoding="utf-8").strip(),
                    f"{backend} ran `{shell}` but its effect differs",
                )
            return True

        self._each_backend(case)

    def test_symlinked_grant_is_writable(self) -> None:
        """A grant reaching its tree through a symlink must still work.

        This is a benchmark cell in miniature. It is a separate case from the
        command shapes above because it fails for a different reason and at a
        different layer: the shapes ask whether a *command* is permitted, this
        asks whether the session can run commands at all, and a backend that
        rejects the writable root answers no to every command equally.
        """
        def case(backend: str) -> bool:
            workspace = self._workspace(backend, "facade")
            targets = workspace / "checkout" / "targets"
            (targets / "demo").mkdir(parents=True)
            facade = workspace / "repo-root"
            facade.mkdir()
            (facade / "targets").symlink_to(targets, target_is_directory=True)
            grant = facade / "targets" / "demo"
            self.assertNotEqual(
                str(grant), os.path.realpath(grant),
                "fixture must reach its grant through a symlink",
            )
            finished = self._run(
                backend, workspace, facade, f"{facade},{grant}",
                FACADE_PROMPT.format(marker=FACADE_MARKER), 6,
            )
            if finished is None:
                return False
            landed = targets / "demo" / FACADE_MARKER
            self.assertTrue(
                landed.is_file(),
                f"{backend} wrote nothing through a symlinked grant — every "
                f"benchmark cell hands its agents exactly this shape",
            )
            self.assertEqual(
                "conformance", landed.read_text(encoding="utf-8").strip(),
                f"{backend} wrote through its symlinked grant but the "
                f"content differs",
            )
            return True

        self._each_backend(case)


if __name__ == "__main__":
    unittest.main(verbosity=2)
