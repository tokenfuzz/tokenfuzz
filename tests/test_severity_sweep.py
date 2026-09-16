#!/usr/bin/env python3
"""bin/severity-sweep reads the cluster index the cluster tools write."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lib"))

loader = importlib.machinery.SourceFileLoader("severity_sweep_mod", str(ROOT / "bin" / "severity-sweep"))
spec = importlib.util.spec_from_loader("severity_sweep_mod", loader)
sweep = importlib.util.module_from_spec(spec)
loader.exec_module(sweep)


class SeveritySweepTests(unittest.TestCase):
    def test_the_cluster_index_decides_which_members_are_scored(self) -> None:
        """Only the canonical member of each cluster is scored; without the
        index every member would be, each flagged canonical, and a
        deduplicated count would be inflated by every duplicate."""
        with tempfile.TemporaryDirectory() as tmp:
            pool = Path(tmp)
            findings = pool / "findings"
            for fid in ("FIND-0001", "FIND-0002"):
                (findings / fid).mkdir(parents=True)
                (findings / fid / "report.md").write_text(f"# {fid}\n", encoding="utf-8")
            (findings / "finding-clusters.md").write_text(
                "| Severity | Cluster | Size | Class | Strategy | Signature | Canonical | Members | Status |\n"
                "|:--|:--|--:|:--|:--|:--|:--|:--|:--|\n"
                "| High | `FCL-1` | 2 | app_parse | S1 | `app_parse app.c:7` "
                "| [FIND-0001](FIND-0001/report.md) "
                "| **[FIND-0001](FIND-0001/report.md)**, [FIND-0002](FIND-0002/report.md) | OK |\n",
                encoding="utf-8")
            out = io.StringIO()
            with mock.patch.object(sweep, "_score", return_value={}), redirect_stdout(out):
                count = sweep._emit(pool, "pool")
        rows = {line.split(",")[2]: line.split(",")[3] for line in out.getvalue().splitlines()}
        self.assertEqual(count, 1)
        self.assertEqual(rows, {"FIND-0001": "1"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
