#!/usr/bin/env python3
"""Crash clustering, signatures, canonicalization, and rendering regressions."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "cluster-crashes"


class ClusterCrashesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cluster-crashes-")
        self.root = Path(self.temporary.name)
        self.results = self.root / "results"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_cluster(
        self, path: Path | None = None, *arguments: str,
        environment: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(COMMAND), str(path or self.results), *arguments],
            env=environment, capture_output=True, text=True, check=False,
        )

    @staticmethod
    def cluster_id(report: Path) -> str:
        match = re.search(r"^Cluster: (CL-[0-9a-f]+)", report.read_text(), re.MULTILINE)
        return match.group(1) if match else ""

    def make_crash(
        self, crash_id: str, primitive: str, top: str, root_cause: str,
        caller: str = "caller", tail: str = "tail", *, parent: Path | None = None,
        severity: tuple[str, str] | None = None,
    ) -> Path:
        crashes = parent or (self.results / "crashes")
        crash = crashes / crash_id
        crash.mkdir(parents=True)
        (crash / "sanitizer.txt").write_text(
            f"==12345==ERROR: AddressSanitizer: {primitive} on address 0x60200000abcd\n"
            "READ of size 4 at 0x60200000abcd\n"
            "    #0 0x100000000 in strlen+0x40 (libclang_rt.asan.dylib+0x3ec80)\n"
            f"    #1 0x100000008 in {top} src/foo.c:42\n"
            f"    #2 0x100000010 in {caller} src/bar.c:99\n"
            f"    #3 0x100000018 in {tail} src/baz.c:123\n"
            "    #4 0x100000020 in main harness.c:5\n",
            encoding="utf-8",
        )
        report = (
            f"# {crash_id}\n\n| Field | Value |\n| --- | --- |\n"
            "| Surface | library-api |\n| Cluster | (set by bin/cluster-crashes) |\n\n"
            "Boundary: serialized sample bytes\nTrigger source: bytes\n\n"
            f"## Root Cause\n{root_cause}\n"
        )
        if severity:
            level, score = severity
            report += f"\n## Classification\n- **Severity**: {level} (CVSS-BTE 4.0: {score} {level}; primitive=x)\n"
        (crash / "REPORT.md").write_text(report, encoding="utf-8")
        return crash

    def make_simple_crash(
        self, parent: Path, crash_id: str, sanitizer: str, report: str,
    ) -> Path:
        crash = parent / "crashes" / crash_id
        crash.mkdir(parents=True)
        (crash / "sanitizer.txt").write_text(sanitizer.rstrip() + "\n", encoding="utf-8")
        (crash / "REPORT.md").write_text(report.rstrip() + "\n", encoding="utf-8")
        return crash

    def make_cli_fallback(self, crash_id: str, line: int, object_name: str, object_line: int) -> Path:
        sanitizer = f"""==12345==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x1
WRITE of size 1 at 0x1 thread T0
    #0 0x100000000 in main+0x1aac (xmlcatalog:arm64+0x100002f94)
    #1 0x100000008 in start+0x1b4c (dyld:arm64e+0x1fda0)
  This frame has 4 object(s):
    [32, 533) 'buf' (line 78)
    [608, 708) '{object_name}' (line {object_line}) <== Memory access at offset 708 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow (xmlcatalog:arm64+0x100002f94) in main+0x1aac
"""
        report = f"""# {crash_id}
Surface: cli
Boundary: xmlcatalog --shell stdin
Trigger source: bytes
Target: xmlcatalog.c:usershell:{line}
## Classification
- **Severity**: Low (CVSS-BTE 4.0: 3.3 Low; primitive=x)
## Root Cause
The parser writes past `{object_name}`.
"""
        return self.make_simple_crash(self.results, crash_id, sanitizer, report)

    def populate_core(self) -> dict[str, Path]:
        crashes = {
            "A1": self.make_crash(
                "CRASH-A1-1", "heap-buffer-overflow", "resolve_helper",
                "Decoded `code_start` is not bounded inside `blocksize`.",
                "shared_dispatch", "shared_tail", severity=("High", "8.7"),
            ),
            "A2": self.make_crash(
                "CRASH-A2-1", "heap-buffer-overflow", "scan_helper",
                "`decode_blob` allows `code_start` outside the allocation.",
                "shared_dispatch", "shared_tail", severity=("Medium", "6.5"),
            ),
            "B1": self.make_crash(
                "CRASH-B1-1", "heap-buffer-overflow", "nametable_scan",
                "The name table extends past the decoded allocation.",
                "name_table_dispatch", "name_table_tail", severity=("Medium", "6.5"),
            ),
            "C1": self.make_crash(
                "CRASH-C1-1", "stack-buffer-overflow", "process_command_line",
                "An input token exceeds the local name array.",
                "command_dispatch", "command_tail", severity=("Low", "3.3"),
            ),
            "D1": self.make_crash(
                "CRASH-D1-1", "heap-buffer-overflow", "parse_config",
                "Parser state reaches a bounds diagnostic.",
                "config_dispatch", "config_tail", severity=("Low", "1.1"),
            ),
            "E1": self.make_crash(
                "CRASH-E1-1", "heap-buffer-overflow", "shared_leaf",
                "Parser state reaches a diagnostic through path E.", "abc", "def",
                severity=("Low", "1.0"),
            ),
            "F1": self.make_crash(
                "CRASH-F1-1", "heap-buffer-overflow", "shared_leaf",
                "Parser state reaches a diagnostic through path F.",
                "z" * 30, "y" * 30, severity=("Low", "1.0"),
            ),
            "G1": self.make_cli_fallback("CRASH-G1-1", 138, "command", 116),
            "H1": self.make_cli_fallback("CRASH-H1-1", 155, "arg", 117),
        }
        crashes["I1"] = self.make_simple_crash(
            self.results, "CRASH-I1-1",
            "parser.c:77:5: runtime error: index 4 out of bounds for type 'int[4]'\n"
            "    #0 0x1 in parse_token parser.c:77\n"
            "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior parser.c:77:5",
            "# CRASH-I1-1\nSurface: library-api\nTarget: parser.c:parse_token:77\nTrigger source: bytes",
        )
        return crashes

    def test_core_clustering_signatures_severity_and_idempotency(self) -> None:
        crashes = self.populate_core()
        process = self.run_cluster()
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        index = self.results / "crashes" / "CRASH-CLUSTERS.md"
        html = index.with_suffix(".html")
        self.assertTrue(index.is_file())
        self.assertTrue(html.is_file())
        self.assertTrue((crashes["A1"] / "REPORT.html").is_file())
        self.assertIn('href="CRASH-A1-1/REPORT.html"', html.read_text())

        ids = {key: self.cluster_id(crash / "REPORT.md") for key, crash in crashes.items()}
        self.assertEqual(ids["A1"], ids["A2"])
        self.assertNotEqual(ids["A1"], ids["B1"])
        self.assertNotEqual(ids["A1"], ids["C1"])
        self.assertNotEqual(ids["E1"], ids["F1"])
        self.assertNotEqual(ids["G1"], ids["H1"])

        text = index.read_text(encoding="utf-8")
        for pattern in (
            r"\[CRASH-A1-1\]\(CRASH-A1-1/REPORT\.md\).*CRASH-A2-1",
            r"\[CRASH-B1-1\]", r"\[CRASH-C1-1\]", r"\[CRASH-D1-1\]",
            r"\[CRASH-E1-1\]", r"\[CRASH-F1-1\]", r"\[CRASH-I1-1\]",
            r"ubsan-out-of-bounds", r"parse_config", r"abc",
            r"shared_leaf src/foo\.c:42 -> abc src/bar\.c:99 -> def src/baz\.c:123",
            r"fallback:xmlcatalog\.c:usershell:138 stack-object command line 116",
            r"\| High \(CVSS 8\.7\) ", r"\| Medium \(CVSS 6\.5\) ",
            r"\| Low \(CVSS 3\.3\) ", r"\| Canonical ",
        ):
            self.assertRegex(text, pattern)
        self.assertNotIn("strlen", text)
        report = (crashes["E1"] / "REPORT.md").read_text()
        signature = "shared_leaf src/foo.c:42 -> abc src/bar.c:99 -> def src/baz.c:123"
        self.assertIn(f"Dedup frames: {signature}", report)
        self.assertIn(f"| Dedup frames | {signature} |", report)
        high = text.index("| High (CVSS 8.7)")
        medium = text.index("| Medium (CVSS 6.5)", high + 1)
        low = text.index("| Low (CVSS 3.3)", medium + 1)
        self.assertLess(high, medium)
        self.assertLess(medium, low)
        high_row = next(line for line in text.splitlines() if "| High (CVSS 8.7)" in line)
        self.assertRegex(
            high_row,
            r"\| \[CRASH-A1-1\]\(CRASH-A1-1/REPORT\.md\) \| "
            r"\*\*\[CRASH-A1-1\]\(CRASH-A1-1/REPORT\.md\)\*\*, \[CRASH-A2-1\]",
        )

        index_before = index.read_bytes()
        report_before = (crashes["A1"] / "REPORT.md").read_bytes()
        self.assertEqual(self.run_cluster().returncode, 0)
        self.assertEqual(index.read_bytes(), index_before)
        self.assertEqual((crashes["A1"] / "REPORT.md").read_bytes(), report_before)
        index.unlink()
        mtime = (crashes["A1"] / "REPORT.md").stat().st_mtime_ns
        self.assertEqual(self.run_cluster(None, "--dry-run").returncode, 0)
        self.assertFalse(index.exists())
        self.assertEqual((crashes["A1"] / "REPORT.md").stat().st_mtime_ns, mtime)

    def test_highest_severity_member_is_canonical(self) -> None:
        parent = self.root / "severity" / "crashes"
        low = self.make_crash(
            "CRASH-AAA-1", "heap-buffer-overflow", "unique_low", "Low path.",
            "shared_mid", "shared_tail", parent=parent, severity=("Low", "1.2"),
        )
        high = self.make_crash(
            "CRASH-ZZZ-1", "heap-buffer-overflow", "unique_high", "High path.",
            "shared_mid", "shared_tail", parent=parent, severity=("High", "8.7"),
        )
        process = self.run_cluster(parent.parent)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(self.cluster_id(low / "REPORT.md"), self.cluster_id(high / "REPORT.md"))
        row = next(
            line for line in (parent / "CRASH-CLUSTERS.md").read_text().splitlines()
            if "High (CVSS 8.7)" in line
        )
        self.assertRegex(row, r"\| \[CRASH-ZZZ-1\].*\| \*\*\[CRASH-ZZZ-1\]")

    def test_aggregate_nested_and_container_detection(self) -> None:
        aggregate = self.root / "output" / "demo"
        aggregate.mkdir(parents=True)
        (aggregate / "target.toml").write_text('target = "demo"\n')
        sanitizer_a = """==1==ERROR: AddressSanitizer: heap-buffer-overflow
#0 0x1 in shared_bug src/shared.c:10
#1 0x2 in entry_a src/a.c:20
"""
        sanitizer_b = sanitizer_a.replace("==1==", "==2==").replace("entry_a src/a.c", "entry_b src/b.c")
        self.make_simple_crash(
            aggregate / "claude" / "results", "CRASH-AGG-1", sanitizer_a,
            "# Aggregate A\nSurface: library-api",
        )
        self.make_simple_crash(
            aggregate / "codex" / "results", "CRASH-AGG-2", sanitizer_b,
            "# Aggregate B\nSurface: library-api",
        )
        self.assertEqual(self.run_cluster(aggregate).returncode, 0)
        text = (aggregate / "CRASH-CLUSTERS.md").read_text()
        self.assertIn("claude/CRASH-AGG-1", text)
        self.assertIn("codex/CRASH-AGG-2", text)

        nested = self.root / "output" / "samples" / "demo"
        nested.mkdir(parents=True)
        (nested / "target.toml").write_text('target = "demo"\n')
        self.make_simple_crash(
            nested / "codex" / "results", "CRASH-NEST-1",
            "==3==ERROR: AddressSanitizer: heap-buffer-overflow\n#0 0x1 in nested_bug src/nested.c:10",
            "# Nested aggregate crash\nSurface: library-api",
        )
        self.assertEqual(self.run_cluster(nested).returncode, 0)
        self.assertIn("codex/CRASH-NEST-1", (nested / "CRASH-CLUSTERS.md").read_text())
        process = self.run_cluster(self.root / "output" / "samples", "--json")
        self.assertEqual(process.returncode, 0, process.stderr)
        payload = json.loads(process.stdout)
        self.assertIn("crashes_root", payload)
        self.assertNotIn("target_root", payload)

    def test_ubsan_and_copy_overlap_primitives(self) -> None:
        parent = self.root / "primitives"
        shift = self.make_simple_crash(
            parent, "CRASH-UBSAN-SHIFT",
            "src/encoder.c:42:9: runtime error: shift exponent 33 is too large\n"
            "#0 0x1 in encode_value src/encoder.c:42\n"
            "SUMMARY: UndefinedBehaviorSanitizer: shift-base src/encoder.c:42:9 in encode_value",
            "# Shift\nSurface: library-api\nTarget: src/encoder.c:encode_value:42",
        )
        overflow = self.make_simple_crash(
            parent, "CRASH-UBSAN-OVERFLOW",
            "src/parser.c:120:14: runtime error: signed integer overflow\n"
            "#0 0x2 in add_token src/parser.c:120\n"
            "SUMMARY: UndefinedBehaviorSanitizer: signed-integer-overflow src/parser.c:120 in add_token",
            "# Overflow\nSurface: library-api\nTarget: src/parser.c:add_token:120",
        )
        fallback = self.make_simple_crash(
            parent, "CRASH-UBSAN-FALLBACK",
            "src/lookup.c:9:5: runtime error: index 4 out of bounds for type 'int[4]'\n"
            "#0 0x3 in idx_lookup src/lookup.c:9\n"
            "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior src/lookup.c:9:5",
            "# Bounds\nSurface: library-api\nTarget: src/lookup.c:idx_lookup:9",
        )
        overlap = self.make_simple_crash(
            parent, "CRASH-OVERLAP-1",
            "==1==ERROR: AddressSanitizer: strcpy-param-overlap: memory ranges overlap\n"
            "#0 0x1 in app_copy app.c:42\n#1 0x2 in app_parse app.c:88\n"
            "SUMMARY: AddressSanitizer: strcpy-param-overlap app.c:42 in app_copy",
            "# Copy overlap\nSurface: library-api\nTarget: app.c:app_copy:42",
        )
        self.assertEqual(self.run_cluster(parent).returncode, 0)
        text = (parent / "crashes" / "CRASH-CLUSTERS.md").read_text()
        for primitive in (
            "ubsan-shift-base", "ubsan-signed-integer-overflow",
            "ubsan-out-of-bounds", "strcpy-param-overlap",
        ):
            self.assertIn(primitive, text)
        self.assertNotEqual(self.cluster_id(shift / "REPORT.md"), self.cluster_id(overflow / "REPORT.md"))
        self.assertTrue(self.cluster_id(fallback / "REPORT.md"))
        self.assertTrue(self.cluster_id(overlap / "REPORT.md"))

    def make_lcs_pair(self, parent: Path, prefix: str = "LCS") -> tuple[Path, Path]:
        first = self.make_simple_crash(
            parent, f"CRASH-{prefix}-A",
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow\nREAD of size 4\n"
            "#0 0x1 in unique_top_a src/a.c:42\n#1 0x2 in shared_mid src/shared.c:99\n"
            "#2 0x3 in shared_tail src/shared.c:123",
            "# A\nSurface: library-api",
        )
        second = self.make_simple_crash(
            parent, f"CRASH-{prefix}-B",
            "==2==ERROR: AddressSanitizer: heap-buffer-overflow\nREAD of size 4\n"
            "#0 0x4 in unique_top_b src/b.c:88\n#1 0x5 in shared_mid src/shared.c:99\n"
            "#2 0x6 in shared_tail src/shared.c:123",
            "# B\nSurface: library-api",
        )
        return first, second

    def test_lcs_threshold_fuzzy_default_and_table_severity(self) -> None:
        lcs = self.root / "lcs"
        first, second = self.make_lcs_pair(lcs)
        self.assertEqual(self.run_cluster(lcs).returncode, 0)
        self.assertEqual(self.cluster_id(first / "REPORT.md"), self.cluster_id(second / "REPORT.md"))
        for crash in (first, second):
            report = crash / "REPORT.md"
            report.write_text(
                "\n".join(line for line in report.read_text().splitlines() if not line.startswith("Cluster: ")) + "\n"
            )
        (lcs / "crashes" / "CRASH-CLUSTERS.md").unlink()
        env = os.environ | {"CLUSTER_LCS_THRESHOLD": "3"}
        self.assertEqual(self.run_cluster(lcs, environment=env).returncode, 0)
        self.assertNotEqual(self.cluster_id(first / "REPORT.md"), self.cluster_id(second / "REPORT.md"))

        fuzzy = self.root / "fuzzy"
        fuzz_a = self.make_simple_crash(
            fuzzy, "CRASH-FUZZ-A",
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow\nREAD of size 4\n"
            "#0 0x1 in parse_token_a src/a.c:10\n#1 0x2 in scan_input_a src/a.c:20\n#2 0x3 in driver_a src/a.c:30",
            "# A\nSurface: library-api",
        )
        fuzz_b = self.make_simple_crash(
            fuzzy, "CRASH-FUZZ-B",
            "==2==ERROR: AddressSanitizer: heap-buffer-overflow\nREAD of size 4\n"
            "#0 0x4 in parse_token_b src/b.c:11\n#1 0x5 in scan_input_b src/b.c:21\n#2 0x6 in driver_b src/b.c:31",
            "# B\nSurface: library-api",
        )
        self.assertEqual(self.run_cluster(fuzzy).returncode, 0)
        self.assertNotEqual(self.cluster_id(fuzz_a / "REPORT.md"), self.cluster_id(fuzz_b / "REPORT.md"))

        table = self.root / "table"
        self.make_simple_crash(
            table, "CRASH-TBLONLY",
            "==1==ERROR: AddressSanitizer: heap-use-after-free\nREAD of size 4\n"
            "#0 0x1 in tbl_only_fn src/t.c:10\n#1 0x2 in tbl_caller src/t.c:20",
            "# CRASH-TBLONLY\n\n| Field | Value |\n| --- | --- |\n"
            "| Severity | Low (CVSS-BTE 4.0: 3.3) |\n| Surface | maint-tool |\n\nTrigger source: bytes",
        )
        self.assertEqual(self.run_cluster(table).returncode, 0)
        row = next(
            line for line in (table / "crashes" / "CRASH-CLUSTERS.md").read_text().splitlines()
            if "CRASH-TBLONLY" in line
        )
        self.assertRegex(row, r"^\|\s*Low \(CVSS 3\.3\) ")


if __name__ == "__main__":
    unittest.main(verbosity=2)
