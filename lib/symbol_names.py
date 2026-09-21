"""Best-effort native symbol presentation helpers."""

from __future__ import annotations

import os

import native_symbols
import sanitizer


def demangle_text(text: str) -> str:
    """Demangle C++ and Rust symbols with the pinned LLVM when it has one.

    GNU c++filt only partially handles Rust-v0 symbols. Prefer the LLVM
    demangler the sanitizer toolchain resolves, and let `native_symbols`
    fall back to whatever PATH offers on installations without LLVM.
    """
    tool = sanitizer.llvm_tool("llvm-cxxfilt")
    return native_symbols.demangle_text(
        text, tool if os.access(tool, os.X_OK) else None,
    )
