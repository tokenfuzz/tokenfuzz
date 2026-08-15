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

    def _run(self, backend: str) -> Path | None:
        """The workspace a finished session left, or None on a provider outage.

        A session the provider refused answers nothing about permissions, so it
        skips. A session that failed for any other reason is a launch
        regression — an unparsable setting or a sandbox that would not start —
        and must fail, or this suite would report green for the very breakage
        it exists to catch. The originally-guarded failure exits 0 and leaves
        the markers unwritten, so that one stays a failure either way.
        """
        workspace = Path(tempfile.mkdtemp(prefix=f"conformance-{backend}-"))
        self._workspaces.append(workspace)
        transcript = workspace / "transcript.log"
        commands = "\n\n".join(shell for _, shell, _ in SHAPES)
        rc = llm_invoke.run_agent_prompt(
            backend,
            PROMPT.format(commands=commands),
            600,
            transcript,
            max_turns=len(SHAPES) * 3,
            add_dirs=str(workspace),
            cwd=workspace,
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

    def test_ordinary_command_shapes_are_not_blocked(self) -> None:
        backends = requested_backends()
        if not backends:
            self.skipTest("set TOKENFUZZ_LIVE_BACKENDS=claude,codex (or all)")
        # One backend being unavailable must not decide the verdict for the
        # others: a skip raised mid-loop would end the run and hide a backend
        # that had already answered.
        unavailable: list[str] = []
        verified = 0
        for backend in backends:
            with self.subTest(backend=backend):
                if not shutil.which(llm_invoke.backend_bin(backend)):
                    unavailable.append(f"{backend}: CLI not on PATH")
                    continue
                workspace = self._run(backend)
                if workspace is None:
                    unavailable.append(f"{backend}: provider refused the session")
                    continue
                verified += 1
                try:
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
                except AssertionError:
                    self._keep = True
                    raise
        if not verified:
            self.skipTest(
                "no requested backend produced a session: "
                + "; ".join(unavailable)
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
