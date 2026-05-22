#!/usr/bin/env python3
"""Generate a compact session seed from an agent's raw log.

The seed lists what files + line ranges the agent has already Read, and what
testcases it has Written. Injected into the next session's prompt so the agent
doesn't re-derive context after compaction or across iterations.

Usage:
    build_session_seed.py <raw-log-path> <output-seed-path>

Validated waste:
    33.7% of all Read bytes across 51 sessions are range-overlapping re-reads
    of the same file in the same session.

Edge cases handled:
- Range merging: overlapping (offset, limit) pairs collapse to a single span.
- AUDIT_STATE files are excluded from the "do not re-read" list — agents
  legitimately re-read state after compaction.
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
EXCLUDE_PATTERNS = (
    'AUDIT_STATE',
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

    Returns 'codex' if any of the first 8 events match Codex's structured
    schema (`thread.started` / `turn.started` / `item.completed`);
    'claude' otherwise. Falls back to 'claude' for empty / unparseable
    files — Claude's parser handles those silently.
    """
    codex_markers = {'thread.started', 'turn.started', 'item.completed', 'item.started'}
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for i, line in enumerate(f):
                if i >= 8:
                    break
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if ev.get('type') in codex_markers:
                    return 'codex'
    except OSError:
        pass
    return 'claude'


def parse_raw_log(path):
    """Detect log format and dispatch to the matching parser. Returns:
        reads:   {file_path: [(start_line, end_line), ...]}
        writes:  [file_path, ...]   (testcases written)
        read_order: [file_path, ...]
    """
    if detect_format(path) == 'codex':
        return _parse_codex_log(path)
    return _parse_claude_log(path)


def _parse_claude_log(path):
    """Walk Claude's stream-json JSONL, pair tool_use → tool_result."""
    pending = {}
    reads = defaultdict(list)
    writes = []
    read_order = []

    try:
        f = open(path, 'r', encoding='utf-8', errors='replace')
    except OSError:
        return reads, writes, read_order

    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except (json.JSONDecodeError, ValueError):
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
                    if kind != 'Read':
                        continue
                    fp = inp.get('file_path', '')
                    if not fp or is_excludable(fp):
                        continue
                    # is_error / "File does not exist" → skip; agent will retry
                    if c.get('is_error'):
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

    return reads, writes, read_order


# Codex command-extraction patterns. We only honor commands that give us
# a clear file argument and ideally a line range. Anything else (rg, jq
# pipelines, awk, multi-arg patterns) is skipped — false negatives are
# fine; false positives that lie about what was read are not.
_CODEX_SED_RE = re.compile(
    r"sed\s+-n\s+['\"]?\s*(\d+)\s*,\s*(\d+)\s*p['\"]?\s+(\S+)"
)
_CODEX_HEAD_RE = re.compile(
    r"\bhead\s+(?:-n\s*)?(\d+)\s+(\S+)"
)
_CODEX_CAT_RE = re.compile(
    r"\bcat\s+([^\s|;&<>'\"`]+)"
)


def _strip_quotes(s):
    """Strip any combination of leading/trailing shell quote chars.
    Codex commands are wrapped in `/bin/zsh -lc \"...\"`, so paths inside
    can carry one or two stray quote chars after regex extraction."""
    return s.strip('"\'`')


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

    try:
        f = open(path, 'r', encoding='utf-8', errors='replace')
    except OSError:
        return reads, writes, read_order

    with f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except (json.JSONDecodeError, ValueError):
                continue
            if ev.get('type') != 'item.completed':
                continue
            item = ev.get('item', {}) or {}
            it_type = item.get('type')

            if it_type == 'command_execution':
                cmd = item.get('command', '') or ''
                if not isinstance(cmd, str):
                    continue
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
                    if not (fp.startswith('/') or fp.startswith('./') or fp.startswith('../')):
                        continue
                    _record_read(reads, read_order, fp, 1, DEFAULT_READ_LIMIT)

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

    return reads, writes, read_order


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


def render_seed(reads, writes, read_order):
    """Render reads/writes into the seed text (≤MAX_SEED_BYTES)."""
    lines = []
    lines.append('# Already Read this session — do NOT re-Read these ranges')
    lines.append('# (use offset/limit to read DIFFERENT ranges of the same file)')

    # Iterate in read order so the most recently introduced file isn't dropped
    # by truncation alone — we still drop oldest first.
    rendered_reads = []
    for fp in read_order:
        merged = merge_ranges(reads.get(fp, []))
        if not merged:
            continue
        rendered_reads.append(f'  {shorten_path(fp)}: {fmt_ranges(merged)}')

    if rendered_reads:
        lines.extend(rendered_reads)
    else:
        lines.append('  (none)')

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

    body = '\n'.join(lines) + '\n'

    # Truncate from the OLDEST Read end if over budget. Writes stay intact —
    # they're small and high-signal.
    while len(body.encode('utf-8')) > MAX_SEED_BYTES and rendered_reads:
        rendered_reads.pop(0)
        # rebuild
        rebuilt = ['# Already Read this session — do NOT re-Read these ranges',
                   '# (use offset/limit to read DIFFERENT ranges of the same file)']
        rebuilt.extend(rendered_reads or ['  (older entries dropped)'])
        if writes:
            rebuilt.append('')
            rebuilt.append('# Testcases written this session — already on disk')
            seen = set()
            for fp in writes:
                short = shorten_path(fp)
                if short in seen:
                    continue
                seen.add(short)
                rebuilt.append(f'  {short}')
        body = '\n'.join(rebuilt) + '\n'

    return body


def main(argv):
    if len(argv) != 3:
        print(f'Usage: {argv[0]} <raw-log-path> <output-seed-path>', file=sys.stderr)
        return 2
    raw_path, out_path = argv[1], argv[2]
    if not os.path.exists(raw_path):
        # No prior log — nothing to seed. Don't create an empty file.
        return 0
    reads, writes, read_order = parse_raw_log(raw_path)
    if not reads and not writes:
        # Empty/short session — skip writing to avoid stomping a useful prior seed.
        return 0
    body = render_seed(reads, writes, read_order)
    out_dir = os.path.dirname(out_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(body)
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
