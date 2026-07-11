#!/usr/bin/env python3
"""Testcase and sanitizer-evidence filesystem classification.

This module owns the filesystem scanning and classification used by audit
commands:
which files look like testcases, which sanitizer-output files contain a
verifiable ASan run, how many of the testcases are "orphans" (no .asan.txt).

`scan-scratch` classifies every directory entry in one `os.scandir` pass,
instead of launching a subprocess for each predicate.

Subcommands (run as `python3 lib/quality.py <name> ...`):

  testcase-mode <file>
      Emit the recognised testcase mode ("browser", "js", "generic"), or
      exit 1 if the file is not a testcase (per the sidecar blacklist).

  has-verified-asan <file>
      Exit 0 if the testcase has a sibling *.asan.txt with a verifiable
      ASan run; exit 1 otherwise. Used for single-file orphan checks.

  list-testcases <dir>
      Print null-separated paths of testcases under <dir> (non-recursive).
      Emit paths for callers that need to inspect scratch inputs.

  count-asan-runs <dir>
      Print the integer count of verifiable .asan.txt files in <dir>.

  count-testcases <dir>
      Print the integer count of testcases in <dir>.

  count-orphans <dir>
      Print the integer count of testcases without a verified .asan.txt
      sibling.

  scan-scratch <dir>
      Print a single line `sanitizer_runs=N testcases=M orphans=K` plus an
      optional second line listing orphan paths (used by enforcement).
      The directory is scanned once.

  promote-corpus <hits_log> <scratch_dir> <corpus_root> <agent_num>
      Walk a hits.log, copy promotable testcases (plus their .asan.txt)
      into the corpus under COVER-NNN-<agent_num>/, and emit one tally
      line `promoted=N skipped_no_asan=N skipped_crashing=N
      skipped_no_header=N skipped_no_new_edges=N` to stdout.

  regenerate-corpus-index <corpus_root>
      Rebuild the corpus INDEX.md table from each COVER-*/metadata.md.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import os
import re
import shutil
import sys

import languages

# Sidecar blacklist: filenames that are never testcases. Lowercased stem
# matches except where explicitly noted.
_BLACK_EXACT_LOWER = {
    ".ds_store", ".gitignore", ".gitkeep", ".keep",
    ".harness-cache", ".enforced", ".config-hash", ".config_hash",
    ".promotion_pending", ".autodiscard",
    ".severity_failed", ".severity_pending", ".severity_ok",
}
_BLACK_EXACT_PRESERVE_CASE = {
    "REPORT.md", "REPORT.html", "description.md",
    "reproduce.sh",
    "severity.json", "promotion.log",
}

# Suffix-based blacklist (lowercase): log files, sanitizer outputs, docs, build artifacts,
# JSON sidecars. Pattern: a tuple is checked as suffix or as a glob with
# the wildcard expressed as a prefix-match.
_BLACK_GLOB_LOWER = (
    ".asan.txt", ".ubsan.txt", ".asan.log",
    ".log", ".raw", ".diff",
    ".coverage", ".coverage.json", ".coverage.txt",
    ".notes", ".notes.md", ".summary", ".summary.md",
    ".md", ".markdown", ".rst", ".txt.md",
    ".o", ".obj", ".a", ".lib", ".so", ".dylib", ".dll", ".pdb", ".dsym",
    ".pyc", ".pyo", ".class", ".swp", ".swo", ".bak",
    ".config-hash", ".cache.json", ".lock", ".tmp", ".partial",
    ".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx", ".inl", ".ipp",
    ".py", ".rb", ".go", ".rs", ".java", ".kt", ".swift", ".ts", ".tsx", ".jsx",
    ".sh", ".bash", ".zsh", ".fish", ".ps1", ".bat", ".cmd", ".mk",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".cmake",
)

_HARNESS_PATTERN = re.compile(r"^(harness.*\.(c|cc|cpp)|.*\.harness\.(c|cc|cpp))$", re.IGNORECASE)
_ASAN_PREFIX_PATTERNS = (
    "asan_output", "asan-output", "asan_output", "asan.log.",
)

_ASAN_VERIFIED_RE = re.compile(
    r"(ASAN_RUN_HEADER:|SANITIZER_RUN_HEADER:|CRASH_RATE:|EXECUTION_RATE:|SUCCESS_RATE: [1-9][0-9]*/|"
    r"\[run-asan\] CRASH DETECTED|"
    r"\[run-asan\] (?:browser|js|js-diff|xpcshell|generic)? ?EXECUTION VERIFIED|"
    r"ERROR: AddressSanitizer)"
)
# Clean-success evidence for corpus promotion. Mirrors lib/verdict.py:
# SUCCESS_RATE means rc=0 execution. A bare run-sanitizer-multi EXECUTION_RATE
# only proves the target was reached, so it does not count as clean.
_CLEAN_EVIDENCE_RE = re.compile(
    r"(\[run-sanitizer-multi\] SUCCESS_RATE: [1-9][0-9]*/[0-9]+|"
    r"\[run-(?:asan|ubsan|msan|tsan)\] (?:browser|js|xpcshell|generic) EXECUTION VERIFIED \(post-run|"
    r"\[run-ubsan\] EXECUTION VERIFIED:|"
    r"ERROR: AddressSanitizer)"
)
_COVERAGE_MISSED_RE = re.compile(r"COVERAGE_GATE: MISSED")
_HIT_LINE_RE = re.compile(r"^HIT:")
_HID_RE = re.compile(r"HYPOTHESIS-ID:\s*(H[0-9]+)")
_TARGET_RE = re.compile(r"^[^A-Za-z]*TARGET:\s*(.+?)(?:\s*(?:-->|\*/)\s*)?$")
_CATEGORY_RE = re.compile(r"^[^A-Za-z]*(?:CATEGORY|INTENT):\s*(.+?)(?:\s*(?:-->|\*/)\s*)?$")
_C_FAMILY_HARNESS_EXTS = frozenset((".c", ".cc", ".cpp", ".cxx"))
_RUNNABLE_SOURCE_EXTS = languages.all_harness_exts() - _C_FAMILY_HARNESS_EXTS


def _is_testcase_blacklisted(stem: str, lower: str) -> bool:
    if lower in _BLACK_EXACT_LOWER:
        return True
    if stem.startswith("."):
        return True
    if stem.startswith("audit_state-") or stem == "audit_state.md":
        return True
    if stem in _BLACK_EXACT_PRESERVE_CASE:
        return True
    if stem.startswith("README"):
        return True
    if _HARNESS_PATTERN.match(lower):
        return True
    # Match asan_output*.txt / asan-output*.log / asan.log.* prefixes.
    for prefix in _ASAN_PREFIX_PATTERNS:
        if lower.startswith(prefix):
            return True
    for suffix in _BLACK_GLOB_LOWER:
        if lower.endswith(suffix):
            return True
    if lower == "makefile" or lower == "cmakelists.txt":
        return True
    # .so.* shared libraries.
    if ".so." in lower:
        return True
    # Tilde backup files.
    if stem.endswith("~"):
        return True
    return False


_TXT_TESTCASE_PREFIXES = (
    "input.", "input_", "input-",
    "testcase", "test-case",
    "tc.", "tc_", "tc-",
    "repro.", "repro_", "repro-",
    "reproducer",
)


def testcase_mode_for_file(path: str) -> str | None:
    """Classify a file as a testcase mode, or return None if not a testcase.

    Matches the policy in lib/quality.py: invert the prior allowlist. Anything
    not on the sidecar blacklist (sanitizer output, docs, source, build
    artifacts) is assumed to be a testcase. Plain *.txt requires an explicit
    testcase-shaped stem.
    """
    stem = os.path.basename(path)
    lower = stem.lower()
    suffix = os.path.splitext(lower)[1]
    if suffix in _RUNNABLE_SOURCE_EXTS:
        header = _read_header(path)
        if _HID_RE.search(header) and any(_TARGET_RE.match(line) for line in header.splitlines()):
            return "js" if suffix in (".js", ".mjs", ".cjs", ".ts", ".tsx") else "generic"
    if _is_testcase_blacklisted(stem, lower):
        return None

    if lower.endswith((".html", ".xhtml", ".svg")):
        return "browser"
    if lower.endswith((".js", ".mjs")):
        return "js"

    if lower.endswith(".txt"):
        for prefix in _TXT_TESTCASE_PREFIXES:
            if lower.startswith(prefix):
                return "generic"
        return None

    try:
        st = os.stat(path)
    except OSError:
        return None
    if not os.path.isfile(path):
        return None
    if st.st_size <= 0:
        return None
    if st.st_mode & 0o111:
        # Executable testcases include compiled reproducers and script inputs.
        # The sidecar blacklist has already removed known harness artifacts.
        return "generic"

    return "generic"


def _file_has_verified_asan(path: str) -> bool:
    """Return True if `path` is a .asan.txt-shaped file with a verifiable run.

    Accepts ASAN_RUN_HEADER, CRASH_RATE, EXECUTION_RATE, run-asan
    CRASH/VERIFIED markers, or an AddressSanitizer error line. A
    COVERAGE_GATE: MISSED marker disqualifies the run.
    """
    verified = False
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                if _COVERAGE_MISSED_RE.search(line):
                    return False
                verified |= bool(_ASAN_VERIFIED_RE.search(line))
    except OSError:
        return False
    return verified


def count_verified_sanitizer_runs(directory: str) -> int:
    if not os.path.isdir(directory):
        return 0
    n = 0
    try:
        entries = os.scandir(directory)
    except OSError:
        return 0
    with entries as it:
        for entry in it:
            if not entry.is_file(follow_symlinks=False):
                continue
            name = entry.name
            lower = name.lower()
            if lower.endswith(".asan.txt") or lower.startswith(("asan_output", "asan-output")):
                if _file_has_verified_asan(entry.path):
                    n += 1
    return n


def _testcase_has_verified_asan_output(path: str) -> bool:
    base, _, _ = path.rpartition(".")
    candidates = []
    if base:
        candidates.append(base + ".asan.txt")
    candidates.append(path + ".asan.txt")
    for c in candidates:
        if os.path.isfile(c) and _file_has_verified_asan(c):
            return True
    return False


def list_testcases(directory: str) -> list[str]:
    if not os.path.isdir(directory):
        return []
    out: list[str] = []
    try:
        entries = list(os.scandir(directory))
    except OSError:
        return []
    for entry in entries:
        if not entry.is_file(follow_symlinks=False):
            continue
        if testcase_mode_for_file(entry.path) is not None:
            out.append(entry.path)
    return out


def count_orphan_testcases(directory: str) -> int:
    n = 0
    for tc in list_testcases(directory):
        if not _testcase_has_verified_asan_output(tc):
            n += 1
    return n


def scan_scratch(directory: str) -> tuple[int, list[str], list[str]]:
    """Return (verified ASan runs, testcases, orphan testcases) in one pass.

    The standalone count helpers above intentionally stay small and obvious,
    because they are useful CLI/API entry points. The quality feedback path
    needs all three values at once, so this scanner classifies entries once
    and reads each sanitizer sidecar at most once.
    """
    if not os.path.isdir(directory):
        return 0, [], []

    testcases: list[str] = []
    verified_asan: set[str] = set()

    try:
        entries = list(os.scandir(directory))
    except OSError:
        return 0, [], []

    for entry in entries:
        if not entry.is_file(follow_symlinks=False):
            continue

        if testcase_mode_for_file(entry.path) is not None:
            testcases.append(entry.path)

        lower = entry.name.lower()
        if lower.endswith(".asan.txt") or lower.startswith(("asan_output", "asan-output")):
            if _file_has_verified_asan(entry.path):
                verified_asan.add(entry.path)

    orphans: list[str] = []
    for tc in testcases:
        base, _, _ = tc.rpartition(".")
        candidates = []
        if base:
            candidates.append(base + ".asan.txt")
        candidates.append(tc + ".asan.txt")
        if not any(c in verified_asan for c in candidates):
            orphans.append(tc)

    return len(verified_asan), testcases, orphans


# ── CLI dispatch ────────────────────────────────────────────────────


def _cmd_testcase_mode(args) -> int:
    mode = testcase_mode_for_file(args.path)
    if mode is None:
        return 1
    print(mode)
    return 0


def _cmd_has_verified_asan(args) -> int:
    return 0 if _testcase_has_verified_asan_output(args.path) else 1


def _cmd_list_testcases(args) -> int:
    for path in list_testcases(args.dir):
        sys.stdout.write(path + "\0")
    return 0


def _cmd_count_sanitizer_runs(args) -> int:
    print(count_verified_sanitizer_runs(args.dir))
    return 0


def _cmd_count_testcases(args) -> int:
    print(len(list_testcases(args.dir)))
    return 0


def _cmd_count_orphans(args) -> int:
    print(count_orphan_testcases(args.dir))
    return 0


def _cmd_scan_scratch(args) -> int:
    sanitizer_runs, testcases, orphans = scan_scratch(args.dir)
    print(f"sanitizer_runs={sanitizer_runs} testcases={len(testcases)} orphans={len(orphans)}")
    if args.list_orphans and orphans:
        for tc in orphans:
            sys.stdout.write(tc + "\0")
    return 0


def _read_header(path: str, max_lines: int = 12) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return "".join(f.readline() for _ in range(max_lines))
    except OSError:
        return ""


def _extract_header_field(header: str, regex: re.Pattern) -> str:
    for line in header.splitlines():
        m = regex.match(line)
        if m:
            return m.group(1).strip()
    return ""


def _parse_hit_line(line: str) -> dict[str, str]:
    """Parse `HIT: <ts> testcase=... want=... frame=... edges=... new=...`."""
    out: dict[str, str] = {}
    parts = line.split()
    if parts and len(parts) >= 2:
        out["ts"] = parts[1]
    for part in parts[2:]:
        if "=" in part:
            k, _, v = part.partition("=")
            out[k] = v
    # frame= can contain spaces; recover the tail if present.
    m = re.search(r"\sframe=(.+)$", line)
    if m:
        out["frame"] = m.group(1).rstrip()
    return out


def _file_sha256(path: str) -> str:
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _cmd_promote_corpus(args) -> int:
    hits_log = args.hits_log
    scratch_dir = args.scratch_dir
    corpus_root = args.corpus_root
    agent_num = args.agent_num
    require_new_edges = os.environ.get("CORPUS_REQUIRE_NEW_EDGES", "1") != "0"

    if not os.path.isfile(hits_log):
        print("promoted=0 skipped_no_asan=0 skipped_crashing=0 skipped_no_header=0 skipped_no_new_edges=0")
        return 0

    os.makedirs(corpus_root, exist_ok=True)

    promoted = 0
    skipped_no_asan = 0
    skipped_crashing = 0
    skipped_no_header = 0
    skipped_no_new_edges = 0

    # Agents routinely reuse names such as testcase.js. Deduplicate the bytes,
    # not the basename, so a new coverage input is never discarded by name.
    existing_digests: set[str] = set()
    try:
        for cover in os.scandir(corpus_root):
            if cover.is_dir() and cover.name.startswith("COVER-"):
                for entry in os.scandir(cover.path):
                    if entry.is_file() and testcase_mode_for_file(entry.path) is not None:
                        if digest := _file_sha256(entry.path):
                            existing_digests.add(digest)
    except OSError:
        pass

    try:
        f = open(hits_log, "r", encoding="utf-8", errors="replace")
    except OSError:
        print("promoted=0 skipped_no_asan=0 skipped_crashing=0 skipped_no_header=0 skipped_no_new_edges=0")
        return 0

    with f:
        for raw in f:
            line = raw.rstrip("\n")
            if not _HIT_LINE_RE.match(line):
                continue
            fields = _parse_hit_line(line)
            tc = fields.get("testcase")
            if not tc or not os.path.isfile(tc):
                continue
            stem = os.path.basename(tc)
            base, _, _ = tc.rpartition(".")
            asan_out = (base + ".asan.txt") if base else (tc + ".asan.txt")

            if not os.path.isfile(asan_out) or os.path.getsize(asan_out) == 0:
                skipped_no_asan += 1
                continue

            clean = crashing = False
            try:
                with open(asan_out, "r", encoding="utf-8", errors="replace") as af:
                    for diagnostic_line in af:
                        clean |= bool(_CLEAN_EVIDENCE_RE.search(diagnostic_line))
                        crashing |= bool(re.search(
                            r"ERROR: AddressSanitizer|CRASH_RATE: [1-9]",
                            diagnostic_line,
                        ))
            except OSError:
                skipped_no_asan += 1
                continue

            if not clean:
                skipped_no_asan += 1
                continue

            if crashing:
                skipped_crashing += 1
                continue

            header = _read_header(tc)
            hid_m = _HID_RE.search(header)
            if not hid_m:
                skipped_no_header += 1
                continue
            hid = hid_m.group(1)
            target = _extract_header_field(header, _TARGET_RE)
            category = _extract_header_field(header, _CATEGORY_RE)

            digest = _file_sha256(tc)
            if not digest or digest in existing_digests:
                continue

            new_edges_raw = fields.get("new", "")
            if require_new_edges and new_edges_raw.isdigit() and int(new_edges_raw) == 0:
                skipped_no_new_edges += 1
                continue

            # Pick the next COVER-NNN-{agent_num} slot. Two concurrent
            # promote-corpus calls for the same agent_num would otherwise
            # both see seq=N, both call os.makedirs, and the loser would
            # silently `continue` — dropping a real promotion on the
            # floor. Retry-with-incremented-seq closes the window: when
            # a sibling beat us to COVER-N, we rescan and try N+1.
            cover_dir = None
            for _ in range(64):  # bounded retries; corpus rarely > a few hundred
                seq = sum(
                    1 for entry in os.scandir(corpus_root)
                    if entry.is_dir() and entry.name.startswith("COVER-")
                ) + 1
                candidate = os.path.join(corpus_root, f"COVER-{seq:03d}-{agent_num}")
                try:
                    os.makedirs(candidate)
                except FileExistsError:
                    continue
                except OSError:
                    cover_dir = None
                    break
                cover_dir = candidate
                break
            if cover_dir is None:
                continue

            try:
                shutil.copy2(tc, os.path.join(cover_dir, stem))
            except OSError:
                try:
                    os.rmdir(cover_dir)
                except OSError:
                    pass
                continue

            try:
                shutil.copy2(asan_out, os.path.join(cover_dir, os.path.basename(asan_out)))
            except OSError:
                pass

            want = fields.get("want", "unknown")
            frame = fields.get("frame", "unknown")
            ts = fields.get("ts", "unknown")
            edges = fields.get("edges", "unknown")

            metadata = (
                f"# COVER-{seq:03d}-{agent_num}\n\n"
                f"- **Testcase:** `{stem}`\n"
                f"- **Agent:** {agent_num}\n"
                f"- **Hypothesis:** {hid}\n"
                f"- **Target:** {target or '(unspecified)'}\n"
                f"- **Category:** {category or '(unspecified)'}\n"
                f"- **Coverage want-regex:** `{want}`\n"
                f"- **Reached frame:** `{frame}`\n"
                f"- **Edges hit:** {edges}\n"
                f"- **New edges contributed:** {new_edges_raw or 'unknown'}\n"
                f"- **HIT timestamp:** {ts}\n"
                f"- **Crash:** no (corpus-only — reached target without sanitizer diagnostic)\n"
            )
            try:
                with open(os.path.join(cover_dir, "metadata.md"), "w", encoding="utf-8") as mf:
                    mf.write(metadata)
            except OSError:
                pass

            existing_digests.add(digest)
            promoted += 1

    print(
        f"promoted={promoted} skipped_no_asan={skipped_no_asan} "
        f"skipped_crashing={skipped_crashing} skipped_no_header={skipped_no_header} "
        f"skipped_no_new_edges={skipped_no_new_edges}"
    )
    return 0


_META_FIELD_RES = {
    "agent": re.compile(r"^- \*\*Agent:\*\* (.*)$"),
    "hid":   re.compile(r"^- \*\*Hypothesis:\*\* (.*)$"),
    "tgt":   re.compile(r"^- \*\*Target:\*\* (.*)$"),
    "tc":    re.compile(r"^- \*\*Testcase:\*\* `(.*)`$"),
}


def _cmd_regenerate_corpus_index(args) -> int:
    corpus_root = args.corpus_root
    idx_path = os.path.join(corpus_root, "INDEX.md")
    lines = [
        "# Corpus INDEX",
        "",
        "| ID | Agent | Hypothesis | Target | Testcase |",
        "|----|-------|-----------|--------|----------|",
    ]
    try:
        cover_dirs = sorted(
            entry.path for entry in os.scandir(corpus_root)
            if entry.is_dir() and entry.name.startswith("COVER-")
        )
    except OSError:
        cover_dirs = []
    for cd in cover_dirs:
        meta_path = os.path.join(cd, "metadata.md")
        if not os.path.isfile(meta_path):
            continue
        try:
            with open(meta_path, "r", encoding="utf-8", errors="replace") as f:
                meta_text = f.read()
        except OSError:
            continue
        fields = {}
        for line in meta_text.splitlines():
            for key, pat in _META_FIELD_RES.items():
                if key in fields:
                    continue
                m = pat.match(line)
                if m:
                    fields[key] = m.group(1)
        cover_id = os.path.basename(cd)
        lines.append(
            f"| {cover_id} | {fields.get('agent', '-')} | {fields.get('hid', '-')} | "
            f"{fields.get('tgt', '-')} | {fields.get('tc', '-')} |"
        )
    lines.append("")
    lines.append(f"_Last regenerated: {_dt.datetime.now(_dt.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}_")
    try:
        with open(idx_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except OSError:
        return 1
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="quality")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("testcase-mode")
    s.add_argument("path")
    s.set_defaults(func=_cmd_testcase_mode)

    s = sub.add_parser("has-verified-asan")
    s.add_argument("path")
    s.set_defaults(func=_cmd_has_verified_asan)

    s = sub.add_parser("list-testcases")
    s.add_argument("dir")
    s.set_defaults(func=_cmd_list_testcases)

    s = sub.add_parser("count-asan-runs")
    s.add_argument("dir")
    s.set_defaults(func=_cmd_count_sanitizer_runs)

    s = sub.add_parser("count-testcases")
    s.add_argument("dir")
    s.set_defaults(func=_cmd_count_testcases)

    s = sub.add_parser("count-orphans")
    s.add_argument("dir")
    s.set_defaults(func=_cmd_count_orphans)

    s = sub.add_parser("scan-scratch")
    s.add_argument("dir")
    s.add_argument("--list-orphans", action="store_true",
                   help="After the stats line, emit null-separated orphan paths.")
    s.set_defaults(func=_cmd_scan_scratch)

    s = sub.add_parser("promote-corpus")
    s.add_argument("hits_log")
    s.add_argument("scratch_dir")
    s.add_argument("corpus_root")
    s.add_argument("agent_num")
    s.set_defaults(func=_cmd_promote_corpus)

    s = sub.add_parser("regenerate-corpus-index")
    s.add_argument("corpus_root")
    s.set_defaults(func=_cmd_regenerate_corpus_index)

    return p


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
