#!/usr/bin/env python3
"""Commands that refuse unsafe cleanup from tool-using agent shells."""

from __future__ import annotations

import sys


def refuse_process_name_kill(tool: str) -> int:
    """Reject a name-based killer without persisting its arguments."""
    print(
        f"[process-kill-guard] refusing {tool}: name-based process killing can "
        "terminate concurrent audit cells",
        file=sys.stderr,
    )
    print(
        "[process-kill-guard] save and signal the exact PID of a process you "
        "started, or let bin/probe and the harness cleanup own its process tree",
        file=sys.stderr,
    )
    return 2
