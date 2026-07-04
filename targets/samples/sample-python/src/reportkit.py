"""reportkit — a small toolkit for rendering configuration-driven reports.

A report is assembled from a few ingredients: a *state* blob carrying cached
values between runs and a set of *templates* whose ``{{ ... }}`` placeholders
are filled from a context. The toolkit also exposes helpers to run named
export hooks, to read report assets from a project directory, and to write
rendered output back to it.

The API is intentionally compact so it can be embedded in build scripts and
CI steps. Every entry point takes caller-supplied text or bytes.
"""
from __future__ import annotations

import ast
import os
import pickle
import re
import subprocess
from typing import Any

# Placeholder syntax: {{ expression }} with optional surrounding whitespace.
_PLACEHOLDER = re.compile(r"\{\{\s*(.*?)\s*\}\}")


def evaluate_expr(expr: str, context: dict[str, Any]) -> Any:
    """Evaluate a single template expression against ``context``.

    Expressions are small arithmetic or attribute lookups such as
    ``price * quantity`` or ``user.name``. The context's keys are exposed as
    names so templates can reference report variables directly.
    """
    return eval(expr, dict(context))


def render_template(template: str, context: dict[str, Any]) -> str:
    """Fill every ``{{ ... }}`` placeholder in ``template`` from ``context``."""
    def replace(match: "re.Match[str]") -> str:
        return str(evaluate_expr(match.group(1), context))

    return _PLACEHOLDER.sub(replace, template)


def load_state(blob: bytes) -> Any:
    """Restore a previously saved report state blob.

    State is produced by :func:`save_state` and round-trips the cached value
    map so an incremental run can reuse the previous computation.
    """
    return pickle.loads(blob)


def save_state(state: Any) -> bytes:
    """Serialize a report state value for later :func:`load_state`."""
    return pickle.dumps(state)


def save_render(name: str, root: str, data: bytes) -> int:
    """Write rendered report output to a named file under the output directory."""
    path = os.path.join(root, name)
    with open(path, "wb") as handle:
        return handle.write(data)


def run_export(hook: str, workdir: str = ".") -> str:
    """Run a named export hook and return its stdout.

    Hooks are short shell one-liners declared in a project's report config,
    for example ``pandoc report.md -o report.pdf``.
    """
    result = subprocess.run(
        hook,
        shell=True,
        cwd=workdir,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def read_asset(name: str, root: str) -> bytes:
    """Read a named report asset from the project's asset directory."""
    path = os.path.join(root, name)
    with open(path, "rb") as handle:
        return handle.read()


def parse_config(text: str) -> Any:
    """Parse a small literal configuration value from ``text``.

    Only Python literals are accepted — strings, numbers, tuples, lists,
    dicts, and the ``True``/``False``/``None`` constants. A config that names
    a function call or attribute is rejected, so untrusted config text cannot
    reach arbitrary code.
    """
    return ast.literal_eval(text)


def run_command(arg: str) -> str:
    """Echo a caller-supplied data argument through a fixed reporting tool.

    Unlike :func:`run_export`, the executable is a fixed, harmless program and
    the argument is passed as a single argv element with no shell, so a caller
    controls neither which program runs nor a shell to interpret metacharacters.
    """
    result = subprocess.run(["echo", arg], capture_output=True, text=True, check=True)
    return result.stdout
