#!/usr/bin/env python3
"""Finding clustering, canonicalization, and aggregate regressions."""

from __future__ import annotations

import hashlib
import importlib.machinery
import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
COMMAND = ROOT / "bin" / "cluster-findings"


class ClusterFindingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="cluster-findings-")
        self.root = Path(self.temporary.name)
        self.results = self.root / "results"

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def quality(report: Path, finding_class: str, severity: str = "low") -> None:
        content = report.read_bytes()
        (report.parent / ".llm-find-quality.json").write_text(
            json.dumps({
                "decision": "find_quality", "decision_version": "v10",
                "content_sha1": hashlib.sha1(content).hexdigest(), "accept": True,
                "reason": "test", "class": finding_class, "severity": severity,
                "cached_at": "2026-05-12T00:00:00Z",
            }) + "\n",
            encoding="utf-8",
        )

    def make_find(
        self, finding_id: str, body: str, finding_class: str,
        *, severity: str = "low", root: Path | None = None,
    ) -> Path:
        parent = root or (self.results / "findings")
        report = parent / finding_id / "report.md"
        report.parent.mkdir(parents=True)
        report.write_text(body.rstrip() + "\n", encoding="utf-8")
        self.quality(report, finding_class, severity)
        return report

    def run_cluster(self, path: Path | None = None, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, str(COMMAND), str(path or self.results), *arguments],
            capture_output=True, text=True, check=False,
        )

    @staticmethod
    def cluster_id(report: Path) -> str:
        match = re.search(r"^Cluster: (FCL-[0-9a-f]+)", report.read_text(), re.MULTILINE)
        return match.group(1) if match else ""

    def populate_core_fixtures(self) -> dict[str, Path]:
        fixtures = {
            "A1": ("# Auth boundary one\nLocation: `server/handlers/admin.go:HandleListUsers:42`\nClass: auth:bypass", "auth:bypass"),
            "A2": ("# Auth boundary alternate angle\nLocation: `server/handlers/admin.go:HandleListUsers:42`\nClass: auth:bypass", "auth:bypass"),
            "B1": ("# Allocation size wraps\nLocation: `src/calc.c:compute:88`\nClass: integer-overflow", "integer-overflow"),
            "B2": ("# Allocation consequence\nLocation: `src/calc.c:compute:88`\nClass: memory-safety", "memory-safety"),
            "C1": ("# Bounds site one\nLocation: `a/x.c:f1:1`\nClass: memory-safety:bounds", "memory-safety:bounds"),
            "C2": ("# Bounds site two\nLocation: `b/y.c:f2:2`\nClass: memory-safety:bounds", "memory-safety:bounds"),
            "C3": ("# Bounds site three\nLocation: `c/z.c:f3:3`\nClass: memory-safety:bounds", "memory-safety:bounds"),
            "D1": ("# Default policy permits inline content\n\nThe default policy weakens the boundary.", "config:permissive-default"),
            "E1": ("Cluster: FCL-stale (singleton)\nDedup key: [title] stale\n# Metadata should not lead the report\n\nParser state is retained.", "state:parser-reset"),
            "G1": ("# Shared helper site one\nLocation: `src/shared/util.c:helper:10`\nClass: memory-safety:bounds", "memory-safety:bounds"),
            "G2": ("# Shared helper site two\nLocation: `src/shared/util.c:helper:20`\nClass: memory-safety:bounds", "memory-safety:bounds"),
            "H1": (
                "# Heap bounds diagnostic\nLocation: `src/render.c:render_draw:77`\n"
                "Class: memory-safety\n```\nSUMMARY: AddressSanitizer: heap-buffer-overflow\n"
                "    #0 0x1 in render_draw src/render.c:77\n    #1 0x2 in main_loop src/main.c:10\n```",
                "memory-safety",
            ),
        }
        return {
            key: self.make_find(f"FIND-{key}", body, finding_class)
            for key, (body, finding_class) in fixtures.items()
        }

    def test_site_clustering_rendering_markers_and_idempotency(self) -> None:
        reports = self.populate_core_fixtures()
        process = self.run_cluster()
        self.assertEqual(process.returncode, 0, process.stdout + process.stderr)
        index = self.results / "findings" / "FINDING-CLUSTERS.md"
        html = index.with_suffix(".html")
        self.assertTrue(index.is_file())
        self.assertTrue(html.is_file())
        self.assertTrue(reports["A1"].with_suffix(".html").is_file())
        self.assertIn('href="FIND-A1/report.html"', html.read_text(encoding="utf-8"))

        ids = {key: self.cluster_id(report) for key, report in reports.items()}
        self.assertEqual(ids["A1"], ids["A2"])
        self.assertEqual(ids["B1"], ids["B2"])
        self.assertNotEqual(ids["G1"], ids["G2"])
        self.assertEqual(len({ids["C1"], ids["C2"], ids["C3"]}), 3)
        self.assertNotEqual(ids["A1"], ids["B1"])
        self.assertTrue(ids["D1"])

        e1_lines = reports["E1"].read_text(encoding="utf-8").splitlines()
        self.assertEqual(e1_lines[0], "# Metadata should not lead the report")
        self.assertGreater(next(i for i, line in enumerate(e1_lines) if line.startswith("Cluster: FCL-")), 0)
        self.assertGreater(next(i for i, line in enumerate(e1_lines) if line.startswith("Dedup key:")), 0)

        a_reports = [reports["A1"], reports["A2"]]
        canonical = next(report for report in a_reports if not (report.parent / ".dup-of").exists())
        duplicate = next(report for report in a_reports if report != canonical)
        self.assertIn(canonical.parent.name, (duplicate.parent / ".dup-of").read_text())
        cluster_text = index.read_text(encoding="utf-8")
        for pattern in (
            r"memory-safety, src/calc\.c, 88",
            r"\(auth, server/handlers/admin\.go, 42\)",
            r"render\.c, 77.* or .*render_draw",
            r"FIND-A1", r"FIND-B1",
        ):
            self.assertRegex(cluster_text, pattern)

        index_before = index.read_bytes()
        report_before = reports["A1"].read_bytes()
        self.assertEqual(self.run_cluster().returncode, 0)
        self.assertEqual(index.read_bytes(), index_before)
        self.assertEqual(reports["A1"].read_bytes(), report_before)

        index.unlink()
        mtime = reports["A1"].stat().st_mtime_ns
        self.assertEqual(self.run_cluster(None, "--dry-run").returncode, 0)
        self.assertFalse(index.exists())
        self.assertEqual(reports["A1"].stat().st_mtime_ns, mtime)

        self.assertEqual(self.run_cluster().returncode, 0)
        self.quality(reports["A2"], "auth:bypass", "high")
        self.assertEqual(self.run_cluster().returncode, 0)
        self.assertTrue((reports["A1"].parent / ".dup-of").is_file())
        self.assertFalse((reports["A2"].parent / ".dup-of").exists())

    def test_aggregate_nested_and_container_root_detection(self) -> None:
        aggregate = self.root / "output" / "demo"
        (aggregate / "target.toml").parent.mkdir(parents=True)
        (aggregate / "target.toml").write_text('target = "demo"\n')
        first = self.make_find(
            "FIND-AGG-1", "# Aggregate A\nLocation: `src/auth/session.go:ValidateSession:40`\nClass: auth:bypass",
            "auth:bypass", root=aggregate / "claude" / "results" / "findings",
        )
        second = self.make_find(
            "FIND-AGG-2", "# Aggregate B\nLocation: `src/auth/session.go:ValidateSession:40`\nClass: auth:bypass",
            "auth:bypass", severity="high", root=aggregate / "codex" / "results" / "findings",
        )
        self.assertEqual(self.run_cluster(aggregate).returncode, 0)
        index = (aggregate / "FINDING-CLUSTERS.md").read_text(encoding="utf-8")
        self.assertIn("claude/FIND-AGG-1", index)
        self.assertIn("codex/FIND-AGG-2", index)
        self.assertIn("duplicate of codex/FIND-AGG-2", first.read_text())
        self.assertIn("Canonical: codex/FIND-AGG-2", (first.parent / ".dup-of").read_text())
        self.assertFalse((second.parent / ".dup-of").exists())

        nested = self.root / "output" / "samples" / "demo"
        nested.mkdir(parents=True)
        (nested / "target.toml").write_text('target = "demo"\n')
        self.make_find(
            "FIND-NEST-1", "# Nested finding\nLocation: `src/nested/session.go:Validate:40`\nClass: auth:bypass",
            "auth:bypass", root=nested / "codex" / "results" / "findings",
        )
        self.assertEqual(self.run_cluster(nested).returncode, 0)
        self.assertIn("codex/FIND-NEST-1", (nested / "FINDING-CLUSTERS.md").read_text())

        process = self.run_cluster(self.root / "output" / "samples", "--json")
        self.assertEqual(process.returncode, 0, process.stderr)
        payload = json.loads(process.stdout)
        self.assertIn("findings_root", payload)
        self.assertNotIn("target_root", payload)

        loader = importlib.machinery.SourceFileLoader("cluster_findings_test", str(COMMAND))
        spec = importlib.util.spec_from_loader(loader.name, loader)
        module = importlib.util.module_from_spec(spec)
        loader.exec_module(module)
        cases = {
            "/x/output/results/demo/codex/results/findings/FIND-1/report.md": "targets/results/demo",
            "/x/output/samples/sample-c/codex/results/findings/FIND-1/report.md": "targets/samples/sample-c",
            "/x/output/cjson/claude/results/findings/FIND-1/report.md": "targets/cjson",
        }
        for path, expected in cases.items():
            self.assertEqual(module._derive_target_root(Path(path)), expected)

    def test_evidence_gating_and_needs_review_rendering(self) -> None:
        unproven = self.make_find(
            "FIND-EVU",
            "# Unproven escalation\nLocation: `src/util.c:resolve_entry:242`\nClass: memory-safety\n"
            "Severity: Medium\nCVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U/CR:M/IR:M/AR:M",
            "memory-safety",
        )
        proven = self.make_find(
            "FIND-EVP",
            "# Proven manifestation\nLocation: `src/util.c:resolve_entry:242`\nClass: memory-safety\n"
            "Severity: Low\nCVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N/E:P/CR:M/IR:M/AR:M",
            "memory-safety",
        )
        self.make_find(
            "FIND-NEEDS-REVIEW",
            "# Accepted finding needing classification\n## Location\n"
            "`src/format.c:parse_record:88`\n## Classification\n"
            "- **Class**: boundary:new-class\n"
            "- **Severity**: Needs review (unclassified — no CVSS vector; primitive=unclassified)",
            "boundary:new-class",
        )
        process = self.run_cluster()
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(self.cluster_id(unproven), self.cluster_id(proven))
        self.assertTrue((unproven.parent / ".dup-of").is_file())
        self.assertFalse((proven.parent / ".dup-of").exists())
        markdown = (self.results / "findings" / "FINDING-CLUSTERS.md").read_text()
        html = (self.results / "findings" / "FINDING-CLUSTERS.html").read_text()
        self.assertIn("Needs review", markdown)
        self.assertIn("NEEDS REVIEW", markdown)
        self.assertIn("sev-Needs-review", html)


if __name__ == "__main__":
    unittest.main(verbosity=2)
