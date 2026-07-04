#!/usr/bin/env python3
"""reportkit_cli — command-line front end for the reportkit toolkit.

Reads one *job file* and performs a single reportkit operation with it. This is
the entry point an audit harness (or a CI step) drives: it turns a file on disk
into exactly one library call so a report task can be scripted.

Job-file format — a header line naming the operation, then an operation-specific
body::

    op: render
    {"price": 3, "quantity": 4}
    Total is {{ price * quantity }}.

The first line is always ``op: <name>``. The remaining lines are the body, whose
shape depends on the operation:

    render    first body line is a JSON object (the context); the rest is the
              template whose ``{{ ... }}`` placeholders are filled from it.
    state     the body is base64-encoded state bytes to restore.
    export    the body is the name of an export hook to run.
    asset     first body line is the project root; the second is the asset name.
    save      first two body lines are the output root and name; the rest is the
              content to write.
    config    the body is a literal configuration value to parse.
    command   the body is a single data argument echoed by a fixed tool.

Every operation prints a one-line summary of its result.
"""
from __future__ import annotations

import base64
import json
import sys

import reportkit


def _split_job(text: str) -> tuple[str, str]:
    """Split a job file into its ``op`` name and its raw body."""
    header, _, body = text.partition("\n")
    prefix, _, name = header.partition(":")
    if prefix.strip() != "op":
        raise ValueError("job file must begin with 'op: <name>'")
    return name.strip(), body


def _run_render(body: str) -> str:
    context_line, _, template = body.partition("\n")
    context = json.loads(context_line) if context_line.strip() else {}
    return reportkit.render_template(template, context)


def _run_state(body: str) -> str:
    blob = base64.b64decode(body.strip())
    return repr(reportkit.load_state(blob))


def _run_save(body: str) -> str:
    root_line, _, rest = body.partition("\n")
    name_line, _, data = rest.partition("\n")
    written = reportkit.save_render(name_line.strip(), root_line.strip(), data.encode("utf-8"))
    return str(written)


def _run_export(body: str) -> str:
    return reportkit.run_export(body.strip())


def _run_asset(body: str) -> str:
    root_line, _, name = body.partition("\n")
    return repr(reportkit.read_asset(name.strip(), root_line.strip()))


def _run_config(body: str) -> str:
    return repr(reportkit.parse_config(body.strip()))


def _run_command(body: str) -> str:
    return reportkit.run_command(body.strip())


_OPERATIONS = {
    "render": _run_render,
    "state": _run_state,
    "export": _run_export,
    "asset": _run_asset,
    "save": _run_save,
    "config": _run_config,
    "command": _run_command,
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
