"""Best-effort native symbol presentation helpers."""

from __future__ import annotations

import shutil
import subprocess

import sanitizer


def demangle_text(text: str) -> str:
    """Demangle C++ and Rust-v0 symbols when the platform tool supports it."""
    # GNU c++filt only partially handles Rust-v0 symbols.  Prefer LLVM's
    # demangler, which supports that scheme, while retaining GNU as the C++
    # fallback on installations without LLVM.
    tool = shutil.which(sanitizer.llvm_tool("llvm-cxxfilt")) or shutil.which("c++filt")
    if not text or tool is None:
        return text
    try:
        result = subprocess.run(
            [tool], input=text, capture_output=True, text=True, timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return text
    return result.stdout if result.returncode == 0 else text
