#!/usr/bin/env python3
"""Trim bloated agent state files. Called by bin/audit after each iteration.

Trims three types of content:
1. Hypothesis table: keeps active rows + last MAX_TERMINAL_ROWS terminal rows
2. Completed Investigations: caps at MAX_CI_LINES lines
3. Dead Ends: caps at MAX_DE_LINES lines
4. Working Context: caps at MAX_WC_LINES lines (preserves most recent)
"""
import re
import sys

MAX_ACTIVE_ROWS = 8
MAX_TERMINAL_ROWS = 15
MAX_RESEARCH_LINES = 8
MAX_FINDING_LINES = 12
MAX_CI_LINES = 20
MAX_DE_LINES = 5
MAX_AREAS_LINES = 10
MAX_STRATEGY_LINES = 10
MAX_CRASH_ATTEMPT_LINES = 16
MAX_WC_LINES = 30
MAX_TRACE_LINES = 12
ACTIVE_STATUSES = {'PENDING', 'INVESTIGATING', 'NEEDS_TESTCASE'}


def trim_hypothesis_table(content):
    """Keep active hypothesis rows and last MAX_TERMINAL_ROWS terminal rows."""
    lines = content.split('\n')
    new_lines = []
    table_header = []
    active_rows = []
    terminal_rows = []
    in_table = False

    for line in lines:
        m = re.match(r'^\| (H\d+) \|', line)
        if m:
            in_table = True
            fields = [f.strip() for f in line.split('|')]
            status = fields[8] if len(fields) > 8 else ''
            if any(s in status for s in ACTIVE_STATUSES):
                active_rows.append(line)
            else:
                terminal_rows.append(line)
        elif in_table and line.startswith('|'):
            table_header.append(line)
        else:
            if in_table:
                in_table = False
                new_lines.extend(table_header)
                active_kept = active_rows[-MAX_ACTIVE_ROWS:] if len(active_rows) > MAX_ACTIVE_ROWS else active_rows
                if len(active_rows) > MAX_ACTIVE_ROWS:
                    new_lines.append(f'<!-- {len(active_rows) - MAX_ACTIVE_ROWS} older active rows trimmed; regenerate from archive if needed -->')
                new_lines.extend(active_kept)
                kept = terminal_rows[-MAX_TERMINAL_ROWS:] if len(terminal_rows) > MAX_TERMINAL_ROWS else terminal_rows
                new_lines.extend(kept)
                table_header, active_rows, terminal_rows = [], [], []
            new_lines.append(line)

    if in_table:
        new_lines.extend(table_header)
        active_kept = active_rows[-MAX_ACTIVE_ROWS:] if len(active_rows) > MAX_ACTIVE_ROWS else active_rows
        if len(active_rows) > MAX_ACTIVE_ROWS:
            new_lines.append(f'<!-- {len(active_rows) - MAX_ACTIVE_ROWS} older active rows trimmed; regenerate from archive if needed -->')
        new_lines.extend(active_kept)
        kept = terminal_rows[-MAX_TERMINAL_ROWS:] if len(terminal_rows) > MAX_TERMINAL_ROWS else terminal_rows
        new_lines.extend(kept)

    return '\n'.join(new_lines)


def trim_section(content, section_name, max_lines, keep='first'):
    """Trim a markdown section to max_lines. keep='first' or 'last'."""
    pattern = r'(## ' + re.escape(section_name) + r'[^\n]*\n)(.*?)(?=\n## [A-Z]|\Z)'
    match = re.search(pattern, content, re.DOTALL)
    if not match:
        return content

    header = match.group(1)
    body_lines = [l for l in match.group(2).strip().split('\n') if l.strip()]
    if len(body_lines) <= max_lines:
        return content

    if keep == 'last':
        trimmed = '\n'.join(body_lines[-max_lines:])
    else:
        trimmed = '\n'.join(body_lines[:max_lines]) + '\n(older entries trimmed)'

    return content[:match.start()] + header + trimmed + '\n' + content[match.end():]


def trim_state_file(path):
    with open(path, 'r') as f:
        content = f.read()

    content = trim_hypothesis_table(content)
    content = trim_section(content, 'Research Directions', MAX_RESEARCH_LINES, keep='last')
    content = trim_section(content, 'Verified Findings', MAX_FINDING_LINES, keep='last')
    content = trim_section(content, 'Completed Investigations', MAX_CI_LINES)
    content = trim_section(content, 'Dead Ends', MAX_DE_LINES)
    content = trim_section(content, 'Areas Not Yet Examined', MAX_AREAS_LINES, keep='last')
    content = trim_section(content, 'Areas Examined Without Findings', MAX_AREAS_LINES, keep='last')
    content = trim_section(content, 'Strategies Applied Per Area', MAX_STRATEGY_LINES, keep='last')
    content = trim_section(content, 'Crash Reproduction Attempts', MAX_CRASH_ATTEMPT_LINES, keep='last')
    content = trim_section(content, 'Strategy Effectiveness', MAX_STRATEGY_LINES, keep='last')
    content = trim_section(content, 'Working Context', MAX_WC_LINES, keep='last')
    content = trim_section(content, 'Cross-File Traces', MAX_TRACE_LINES, keep='last')

    with open(path, 'w') as f:
        f.write(content)


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <state-file>", file=sys.stderr)
        sys.exit(1)
    trim_state_file(sys.argv[1])
