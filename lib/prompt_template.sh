#!/usr/bin/env bash
# lib/prompt_template.sh — shared renderer for lib/prompts/*.md.j2.

_prompt_template_root() {
  if [ -n "${SCRIPT_ROOT:-}" ]; then
    printf '%s\n' "$SCRIPT_ROOT"
  else
    cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
  fi
}

render_prompt_template() {
  local template="$1" root
  shift || true
  root="$(_prompt_template_root)"
  python3 "$root/lib/prompt_render.py" "$root/lib/prompts/$template" "$@"
}
