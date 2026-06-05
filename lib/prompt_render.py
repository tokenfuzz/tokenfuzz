#!/usr/bin/env python3
"""Render lib/prompts/*.md.j2 templates with {{ var }} substitution.

A deliberate Jinja2-subset renderer — supports `{{ var }}` placeholders
only. The harness has no other Jinja2 dependency, and adding one (with
its install / vendoring / version-pinning story) for this single use
case would create more friction than it removes.

The {{ var }} syntax is universally recognised by OSS readers as
Jinja2-flavoured templating, which is why the .md.j2 extension is used.
Anything more complex (conditionals, loops) is computed in lib/prompt.sh
and passed in as a pre-rendered string — keeping the templates readable
as plain markdown.

CLI:
    python3 lib/prompt_render.py <template.md.j2> \\
        --var key=value [--var key=value ...]

Each --var argument is one `name=multi line value` pair. argv survives
embedded newlines fine, so bash callers pass values directly:

    python3 lib/prompt_render.py cold_start.md.j2 \\
        --var agent_num="$agent_num" \\
        --var role="$role" \\
        --var guide_section="$guide_section"

Missing placeholders render as empty (matches bash heredoc semantics
where an unset `${var}` expands to empty). Unknown variables in the
context are ignored.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

_PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")
# Jinja-style comment blocks: stripped before rendering so authors can leave
# editor notes / sentinels in .md.j2 sources without inflating the prompt
# token cost or confusing the model. Multiline-friendly.
_COMMENT_RE = re.compile(r"\{#.*?#\}", re.DOTALL)


def render(template_text: str, context: dict[str, str]) -> str:
    """Substitute every `{{ name }}` in template_text with context[name].

    `{# … #}` blocks are stripped first (Jinja comment syntax) so the
    sentinel banners that some templates carry never reach the LLM.

    Unknown names render as the empty string. Whitespace inside the
    `{{ … }}` braces is tolerated (`{{ x }}`, `{{x}}`, `{{   x   }}`
    all match the same key). The replacement is non-recursive — a
    placeholder that itself appears in a substituted value is left
    alone, matching the prior bash heredoc semantics.
    """
    template_text = _COMMENT_RE.sub("", template_text)

    def replace(m: re.Match) -> str:
        key = m.group(1)
        value = context.get(key, "")
        return value if isinstance(value, str) else str(value)
    return _PLACEHOLDER_RE.sub(replace, template_text)


def render_template(template: str | Path, context: dict[str, str]) -> str:
    """Render a template path or lib/prompts template name with context."""
    template_path = Path(template)
    if not template_path.is_absolute():
        template_path = Path(__file__).resolve().parent / "prompts" / template_path
    template_text = template_path.read_text(encoding="utf-8")
    return render(template_text, context)


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="prompt_render")
    p.add_argument("template", help="Path to the .md.j2 template file.")
    p.add_argument(
        "--var", dest="vars", action="append", default=[],
        help="key=value pair to bind in the template context. Repeatable.",
    )
    return p


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    context: dict[str, str] = {}
    for kv in args.vars:
        if "=" not in kv:
            continue
        key, _, value = kv.partition("=")
        if key:
            context[key] = value

    try:
        rendered = render_template(args.template, context)
    except OSError as exc:
        print(f"prompt_render: cannot read {args.template}: {exc}", file=sys.stderr)
        return 2

    # Byte-transparent output, matching the bash heredocs this replaced.
    # Python decodes the OS's byte-oriented argv with errors="surrogateescape",
    # so a --var value carrying an undecodable byte (e.g. a stray 0xC2 from a
    # latin-1 / mojibake target string) arrives as a lone surrogate like
    # \udcc2. Re-encode with the same handler and write the raw bytes so that
    # byte round-trips back to its original form, instead of crashing strict
    # UTF-8 stdout with "surrogates not allowed".
    data = rendered.encode("utf-8", "surrogateescape")
    sys.stdout.buffer.write(data)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
