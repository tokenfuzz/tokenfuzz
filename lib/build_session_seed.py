#!/usr/bin/env python3
"""Generate a compact session seed from an agent's raw log.

The seed lists what files + line ranges the agent has already Read, what
source searches it already ran, and what testcases it has Written. Injected
into the next session's prompt so the agent doesn't re-derive context after
compaction or across iterations.

Usage:
    build_session_seed.py <raw-log-path> <output-seed-path>

Validated waste:
    33.7% of all Read bytes across 51 sessions are range-overlapping re-reads
    of the same file in the same session.

Edge cases handled:
- Range merging: overlapping (offset, limit) pairs collapse to a single span.
- Empty/binary tool_results don't pollute the seed (we record what was
  requested, not what was returned).
- Malformed JSON lines are skipped silently (logs may be truncated).

Output is capped at MAX_SEED_BYTES; least-recently-Read files are dropped first.
"""
import json
import os
import re
import sys
from collections import defaultdict

MAX_SEED_BYTES = 2048
DEFAULT_READ_LIMIT = 2000  # Claude Code's Read default
MAX_SEARCH_COMMANDS = 8
EXCLUDE_PATTERNS = (
    '.session_seed',
    '.read_log',
    '.static-prompt-rules',
)


def is_excludable(path: str) -> bool:
    return any(p in path for p in EXCLUDE_PATTERNS)


def merge_ranges(ranges):
    """Collapse overlapping (start, end) tuples into disjoint spans."""
    if not ranges:
        return []
    ranges = sorted(ranges)
    merged = [list(ranges[0])]
    for s, e in ranges[1:]:
        if s <= merged[-1][1] + 1:
            merged[-1][1] = max(merged[-1][1], e)
        else:
            merged.append([s, e])
    return [(s, e) for s, e in merged]


def fmt_ranges(ranges):
    """Render merged ranges compactly: '1-200, 350-500'."""
    return ', '.join(f'{s}-{e}' for s, e in ranges)


def detect_format(path):
    """Sniff the first non-empty JSON events to classify the log.

    Returns 'codex' if any of the first few lines match Codex's structured
    schema (`thread.started` / `turn.started` / `item.completed`);
    'gemini' if they match the Antigravity/Gemini CLI event schema
    (`init` / top-level `tool_use` / top-level `tool_result`);
    'claude' otherwise. Falls back to 'claude' for empty / unparseable
    files — Claude's parser handles those silently.
    """
    codex_markers = {'thread.started', 'turn.started', 'item.completed', 'item.started'}
    gemini_markers = {'init', 'tool_use', 'tool_result'}
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f):
                if i >= 32:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if not isinstance(ev, dict):
                    continue
                ev_type = ev.get('type')
                if ev_type in codex_markers:
                    return 'codex'
                if ev_type in gemini_markers:
                    return 'gemini'
    except OSError:
        pass
    return 'claude'


def parse_raw_log(path):
    """Detect log format and dispatch to the matching parser. Returns:
        reads:   {file_path: [(start_line, end_line), ...]}
        writes:  [file_path, ...]   (testcases written)
        read_order: [file_path, ...]
        searches: [command, ...]     (successful source-tree searches)
    """
    fmt = detect_format(path)
    if fmt == 'codex':
        return _parse_codex_log(path)
    if fmt == 'gemini':
        return _parse_gemini_log(path)
    return _parse_claude_log(path)


def _parse_claude_log(path):
    """Walk Claude's stream-json JSONL, pair tool_use → tool_result."""
    pending = {}
    reads = defaultdict(list)
    writes = []
    read_order = []
    searches = []

    try:
        f = open(path, 'r', encoding='utf-8', errors='replace')
    except OSError:
        return reads, writes, read_order, searches

    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(ev, dict):
                continue
            t = ev.get('type')
            if t == 'assistant':
                msg = ev.get('message', {})
                for c in msg.get('content', []) or []:
                    if not isinstance(c, dict):
                        continue
                    if c.get('type') != 'tool_use':
                        continue
                    name = c.get('name')
                    tid = c.get('id')
                    inp = c.get('input', {}) or {}
                    if name == 'Read':
                        pending[tid] = ('Read', inp)
                    elif name == 'Bash':
                        cmd = inp.get('command', '')
                        if isinstance(cmd, str) and cmd:
                            pending[tid] = ('Shell', {'command': cmd})
                    elif name == 'Write':
                        fp = inp.get('file_path', '')
                        if fp and not is_excludable(fp):
                            writes.append(fp)
            elif t == 'user':
                msg = ev.get('message', {})
                cont = msg.get('content', [])
                if not isinstance(cont, list):
                    continue
                for c in cont:
                    if not isinstance(c, dict) or c.get('type') != 'tool_result':
                        continue
                    tid = c.get('tool_use_id')
                    pend = pending.pop(tid, None)
                    if not pend:
                        continue
                    kind, inp = pend
                    if c.get('is_error'):
                        continue
                    if kind == 'Shell':
                        cmd = inp.get('command', '')
                        _record_shell_command_reads(cmd, reads, read_order)
                        _record_shell_command_writes(cmd, writes)
                        _record_shell_command_searches(cmd, searches)
                        continue
                    if kind != 'Read':
                        continue
                    fp = inp.get('file_path', '')
                    if not fp or is_excludable(fp):
                        continue
                    try:
                        offset = int(inp.get('offset', 0) or 0)
                    except (TypeError, ValueError):
                        offset = 0
                    try:
                        limit = int(inp.get('limit', 0) or 0)
                    except (TypeError, ValueError):
                        limit = 0
                    start = max(1, offset if offset > 0 else 1)
                    end = start + (limit if limit > 0 else DEFAULT_READ_LIMIT) - 1
                    reads[fp].append((start, end))
                    if fp not in read_order:
                        read_order.append(fp)

    return reads, writes, read_order, searches


# Shell command-extraction patterns. We only honor commands that give us
# a clear file argument and ideally a line range. Anything else (rg, jq
# pipelines, awk, multi-arg patterns) is skipped — false negatives are
# fine; false positives that lie about what was read are not.
_CODEX_SED_RE = re.compile(
    r"sed\s+-n\s+['\"]?\s*(\d+)\s*,\s*(\d+)\s*p['\"]?\s+['\"]?([^\s;&|<>'\"`]+)['\"]?"
)
_CODEX_HEAD_RE = re.compile(
    r"\bhead\s+(?:-n\s*)?(\d+)\s+['\"]?([^\s;&|<>'\"`]+)['\"]?"
)
_CODEX_CAT_RE = re.compile(
    r"\bcat\s+([^\s|;&<>'\"`]+)"
)
_CODEX_PEEK_RANGE_RE = re.compile(
    r"(?:^|[\s;&|\"'])(?:\./)?bin/peek\s+"
    r"(?:(?:--no-cap|--)\s+)*"
    r"([^\s;&|<>'\"`]+):(\d+)(?:-(\d+))?"
)
_SHELL_CAT_HEREDOC_WRITE_RE = re.compile(
    r"\bcat\s+(?:"
    r"<<\s*['\"]?[A-Za-z0-9_.-]+['\"]?\s*>\s*([^\s;&|<>'\"`]+)"
    r"|>\s*([^\s;&|<>'\"`]+)\s+<<"
    r")"
)
_SHELL_SOURCE_SEARCH_RE = re.compile(
    r"^(?:\./)?(?:bin/)?(?:rg-safe|rg|grep|peek)\b"
)
_SHELL_ZSH_LC_RE = re.compile(r"^/bin/zsh\s+-lc\s+(.+)$")
PEEK_DEFAULT_RANGE = 200


def _strip_quotes(s):
    """Strip any combination of leading/trailing shell quote chars.
    Codex commands are wrapped in `/bin/zsh -lc \"...\"`, so paths inside
    can carry one or two stray quote chars after regex extraction."""
    return s.strip('"\'`')


def _normalize_shell_command_for_seed(cmd):
    """Compact shell wrappers/noisy output filters for prompt display."""
    cmd = (cmd or '').strip()
    m = _SHELL_ZSH_LC_RE.match(cmd)
    if m:
        inner = m.group(1).strip()
        if len(inner) >= 2 and inner[0] == inner[-1] and inner[0] in ("'", '"'):
            cmd = inner[1:-1]
        else:
            cmd = inner
    cmd = re.sub(r'\s+', ' ', cmd).strip()
    cmd = re.sub(r'\s+2>&1\s*\|\s*(?:head|tail)(?:\s+-n)?\s+\d+\s*$', '', cmd)
    return cmd


def _record_read(reads, read_order, fp, start, end):
    if not fp or is_excludable(fp):
        return
    # Cap end to avoid pathological values from malformed sed ranges
    if end < start:
        return
    reads[fp].append((start, end))
    if fp not in read_order:
        read_order.append(fp)


def _parse_codex_log(path):
    """Walk Codex's structured-JSON log. Reads come from command_execution
    items (sed/head/cat patterns); writes come from file_change items
    which carry structured `changes[].path`."""
    reads = defaultdict(list)
    writes = []
    read_order = []
    searches = []

    try:
        f = open(path, 'r', encoding='utf-8', errors='replace')
    except OSError:
        return reads, writes, read_order, searches

    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(ev, dict):
                continue
            if ev.get('type') != 'item.completed':
                continue
            item = ev.get('item', {}) or {}
            it_type = item.get('type')

            if it_type == 'command_execution':
                cmd = item.get('command', '') or ''
                if not isinstance(cmd, str):
                    continue
                exit_code = item.get('exit_code')
                if exit_code not in (0, None):
                    continue
                _record_shell_command_reads(cmd, reads, read_order)
                _record_shell_command_searches(cmd, searches)

            elif it_type == 'file_change':
                changes = item.get('changes', []) or []
                if not isinstance(changes, list):
                    continue
                for ch in changes:
                    if not isinstance(ch, dict):
                        continue
                    fp = ch.get('path', '')
                    if fp and not is_excludable(fp):
                        writes.append(fp)

    return reads, writes, read_order, searches


def _record_shell_command_reads(cmd, reads, read_order):
    """Extract conservative read ranges from a shell command string."""
    # sed -n 'A,Bp' file → exact range
    for m in _CODEX_SED_RE.finditer(cmd):
        start = int(m.group(1))
        end = int(m.group(2))
        fp = _strip_quotes(m.group(3))
        _record_read(reads, read_order, fp, max(1, start), end)
    # head -n N file → 1..N
    for m in _CODEX_HEAD_RE.finditer(cmd):
        n = int(m.group(1))
        fp = _strip_quotes(m.group(2))
        _record_read(reads, read_order, fp, 1, n)
    # cat file → assume default span
    for m in _CODEX_CAT_RE.finditer(cmd):
        fp = _strip_quotes(m.group(1))
        # Skip non-file args (heredoc markers, env vars, flags)
        if not (
            fp.startswith('/')
            or fp.startswith('./')
            or fp.startswith('../')
            or ('/' in fp and not fp.startswith('-'))
        ):
            continue
        _record_read(reads, read_order, fp, 1, DEFAULT_READ_LIMIT)
    # bin/peek FILE:START[-END] → exact range. Do not infer grep
    # mode reads; only the single-operand range form is safe.
    for m in _CODEX_PEEK_RANGE_RE.finditer(cmd):
        fp = _strip_quotes(m.group(1))
        start = int(m.group(2))
        end = int(m.group(3)) if m.group(3) else start + PEEK_DEFAULT_RANGE - 1
        _record_read(reads, read_order, fp, max(1, start), end)


def _record_shell_command_writes(cmd, writes):
    """Extract conservative write paths from shell heredoc commands."""
    for m in _SHELL_CAT_HEREDOC_WRITE_RE.finditer(cmd):
        fp = _strip_quotes(m.group(1) or m.group(2) or '')
        if fp and not is_excludable(fp):
            writes.append(fp)


def _record_shell_command_searches(cmd, searches):
    """Record exact successful source-search commands, not inferred reads.

    Only source-tree searches are listed. Audit-output searches can become
    stale as the agent writes new files, so recording them would risk
    discouraging a useful later check.
    """
    if not cmd or '\n' in cmd:
        return
    compact = _normalize_shell_command_for_seed(cmd)
    if not compact or not _SHELL_SOURCE_SEARCH_RE.search(compact):
        return
    if ';' in compact or '&&' in compact:
        return
    if 'targets/' not in compact:
        return
    # Range-only peek reads are already represented in the read-range section.
    if _CODEX_PEEK_RANGE_RE.search(compact) and not any(
        token in compact for token in (' -A', ' -B', ' -C', ' --after-context', ' --before-context', ' --context')
    ):
        return
    if len(compact) > 220:
        compact = compact[:217] + '...'
    if compact not in searches:
        searches.append(compact)


def _parse_gemini_log(path):
    """Walk Antigravity/Gemini JSONL and record successful shell reads."""
    pending = {}
    reads = defaultdict(list)
    writes = []
    read_order = []
    searches = []

    try:
        f = open(path, 'r', encoding='utf-8', errors='replace')
    except OSError:
        return reads, writes, read_order, searches

    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if not isinstance(ev, dict):
                continue

            ev_type = ev.get('type')
            if ev_type == 'tool_use':
                if ev.get('tool_name') != 'run_shell_command':
                    continue
                tool_id = ev.get('tool_id')
                params = ev.get('parameters', {}) or {}
                cmd = params.get('command', '')
                if tool_id and isinstance(cmd, str):
                    pending[tool_id] = cmd
            elif ev_type == 'tool_result':
                tool_id = ev.get('tool_id')
                cmd = pending.pop(tool_id, None)
                if not cmd or ev.get('status') != 'success':
                    continue
                _record_shell_command_reads(cmd, reads, read_order)
                _record_shell_command_writes(cmd, writes)
                _record_shell_command_searches(cmd, searches)

    return reads, writes, read_order, searches


def shorten_path(fp, target_root_marker='/targets/'):
    """Strip a known workspace prefix so the seed reads cleanly.
    Order matters: TARGET_ROOT (codex symlink-resolved path) wins over
    the `/targets/` marker (Claude's symlinked layout) which wins over
    the workspace-relative markers."""
    # 1. TARGET_ROOT prefix — codex resolves symlinks, so paths look like
    #    `<TARGET_ROOT>/firefox/dom/x.cpp` with no `/targets/` segment.
    target_root = os.environ.get('TARGET_ROOT', '').rstrip('/')
    if target_root and fp.startswith(target_root + '/'):
        return fp[len(target_root) + 1:]
    # 2. Claude's `/targets/<target>/` layout
    idx = fp.find(target_root_marker)
    if idx >= 0:
        rest = fp[idx + len(target_root_marker):]
        parts = rest.split('/', 1)
        return parts[1] if len(parts) == 2 else rest
    # 3. Output scratch dirs
    if '/output/' in fp and '/scratch-' in fp:
        m = re.search(r'(scratch-\d+/[^/]+)$', fp)
        if m:
            return m.group(1)
    # 4. Workspace-relative segments
    for marker in ('/.agents/', '/lib/', '/bin/', '/tests/'):
        idx = fp.find(marker)
        if idx >= 0:
            return fp[idx + 1:]  # drop leading slash
    return fp


def render_seed(reads, writes, read_order, searches=None):
    """Render reads/writes/searches into the seed text (≤MAX_SEED_BYTES)."""
    searches = searches or []

    rendered_reads = []
    for fp in read_order:
        merged = merge_ranges(reads.get(fp, []))
        if not merged:
            continue
        rendered_reads.append(f'  {shorten_path(fp)}: {fmt_ranges(merged)}')

    rendered_searches = [f'  {s}' for s in searches[-MAX_SEARCH_COMMANDS:]]

    def build_body(read_lines, search_lines):
        lines = []
        lines.append('# Already Read this session — do NOT re-Read these ranges')
        lines.append('# (use offset/limit to read DIFFERENT ranges of the same file)')
        if read_lines:
            lines.extend(read_lines)
        else:
            lines.append('  (none)')

        if search_lines:
            lines.append('')
            lines.append('# Source searches already run — do NOT repeat exact commands')
            lines.append('# Change the pattern or scope if you need new information')
            lines.extend(search_lines)

        if writes:
            lines.append('')
            lines.append('# Testcases written this session — already on disk')
            seen = set()
            for fp in writes:
                short = shorten_path(fp)
                if short in seen:
                    continue
                seen.add(short)
                lines.append(f'  {short}')
        return '\n'.join(lines) + '\n'

    body = build_body(rendered_reads, rendered_searches)

    # Truncate from the oldest read end first. If searches are still too
    # large, drop oldest searches next. Writes stay intact — they're small
    # and high-signal.
    while len(body.encode('utf-8')) > MAX_SEED_BYTES and rendered_reads:
        rendered_reads.pop(0)
        body = build_body(rendered_reads or ['  (older entries dropped)'], rendered_searches)
    while len(body.encode('utf-8')) > MAX_SEED_BYTES and rendered_searches:
        rendered_searches.pop(0)
        body = build_body(rendered_reads or ['  (older entries dropped)'], rendered_searches)

    return body


def write_session_seed(raw_path, out_path):
    """Refresh a seed from one completed launch. Return True when replaced."""
    if not os.path.exists(raw_path):
        return False
    reads, writes, read_order, searches = parse_raw_log(raw_path)
    if not reads and not writes and not searches:
        # Do not erase a useful prior seed after an empty backend session.
        return False
    body = render_seed(reads, writes, read_order, searches)
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    temporary = f'{out_path}.{os.getpid()}.tmp'
    try:
        with open(temporary, 'w', encoding='utf-8') as f:
            f.write(body)
        os.replace(temporary, out_path)
    finally:
        try:
            os.unlink(temporary)
        except OSError:
            pass
    return True


def main(argv):
    if len(argv) != 3:
        print(f'Usage: {argv[0]} <raw-log-path> <output-seed-path>', file=sys.stderr)
        return 2
    raw_path, out_path = argv[1], argv[2]
    write_session_seed(raw_path, out_path)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
