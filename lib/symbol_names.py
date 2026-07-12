"""Best-effort native symbol presentation helpers."""

from __future__ import annotations

import shutil
import subprocess


def demangle_text(text: str) -> str:
    """Demangle C++ and Rust-v0 symbols when the platform tool supports it."""
    if not text or shutil.which("c++filt") is None:
        return text
    try:
        result = subprocess.run(
            ["c++filt"], input=text, capture_output=True, text=True, timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return text
    return result.stdout if result.returncode == 0 else text
