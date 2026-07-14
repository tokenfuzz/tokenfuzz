#!/usr/bin/env python3
"""reportkit_cli — command-line front end for the reportnative C extension.

Reads one *job file* and performs a single native reportkit operation with it.
The reportnative extension packs a grid of report cells in C, so this target
audits native memory safety: a job crashes the extension under AddressSanitizer
through build-asan/reportnative_harness (the same C core, without an instrumented
interpreter).

Job-file format — a header line ``op: native``, then a body whose first line is
``<rows> <width>``::

    op: native
    64 32
"""
from __future__ import annotations

import sys

import reportnative


def _split_job(text: str) -> tuple[str, str]:
    header, _, body = text.partition("\n")
    prefix, _, name = header.partition(":")
    if prefix.strip() != "op":
        raise ValueError("job file must begin with 'op: <name>'")
    return name.strip(), body


def _run_native(body: str) -> str:
    dims_line, _, _ = body.partition("\n")
    dims = dims_line.split()
    rows = int(dims[0]) if dims else 0
    width = int(dims[1]) if len(dims) > 1 else 0
    return str(reportnative.pack_cells(rows, width, 0x41))


_OPERATIONS = {
    "native": _run_native,
}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {argv[0]} job-file", file=sys.stderr)
        return 2

    with open(argv[1], "r", encoding="utf-8") as handle:
        op, body = _split_job(handle.read())

    handler = _OPERATIONS.get(op)
    if handler is None:
        print(f"unknown operation: {op!r}", file=sys.stderr)
        return 1

    result = handler(body)
    print(f"{op}: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
