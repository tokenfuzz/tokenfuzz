#!/usr/bin/env python3
"""The two single-class sample targets actually produce the bug they claim.

A fixture that no longer reproduces is worse than no fixture: recall for its
bug class silently reads zero and the answer key still says the bug is there.
Checking that a configured path exists proves nothing about that, so this
builds each target with its own recipe and runs it.

MemorySanitizer has no Darwin runtime. That is not a reason to skip: on a host
without one the recipe must *refuse*, because a silently uninstrumented binary
would read as a clean run of the very bug the target plants. So both hosts
assert something real — the refusal here, the diagnostic where MSan exists.
"""

from __future__ import annotations

import ast
import base64
import json
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import benchmark  # noqa: E402
import bug_classes  # noqa: E402
import sanitizer  # noqa: E402


def _field(tag: int, value: bytes) -> bytes:
    """One type-length-value field, as both sample formats frame them."""
    return bytes([tag]) + struct.pack(">H", len(value)) + value


def _clang() -> str:
    found = sanitizer.llvm_tool("clang")
    return found if (shutil.which(found) or Path(found).is_file()) else ""


class SampleBugClassTests(unittest.TestCase):
    def setUp(self) -> None:
        self.clang = _clang()
        if not self.clang:
            self.skipTest("no clang to build the sample fixtures")
        self._tmp = tempfile.TemporaryDirectory(prefix="sample-bug-class-")
        self.build = Path(self._tmp.name)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _recipe(self, slug: str, name: str) -> Path:
        recipe = ROOT / "targets" / "samples" / slug / ".audit" / name
        self.assertTrue(recipe.is_file(), f"{slug} has no {name}")
        return recipe

    def _manifest(self, slug: str) -> dict:
        return json.loads(
            (ROOT / "output" / "samples" / slug / ".ground-truth.json").read_text()
        )

    def test_the_double_free_target_reproduces_its_planted_bug(self) -> None:
        slug = "sample-c-doublefree"
        source = ROOT / "targets" / "samples" / slug
        built = subprocess.run(
            ["bash", str(self._recipe(slug, "build.sh")), str(source), str(self.build)],
            capture_output=True, text=True, check=False, timeout=300)
        if built.returncode:
            self.skipTest(f"cannot build {slug}: {built.stderr[-300:]}")
        binary = self.build / "chtio"
        self.assertTrue(binary.is_file())

        # OPEN a one-byte transfer, then PUSH more than fits: the failure path
        # frees the buffer without clearing the owner, and the exit cleanup
        # frees it again.
        testcase = self.build / "case-doublefree"
        testcase.write_bytes(
            b"CHT1" + _field(0x01, struct.pack(">H", 1)) + _field(0x02, b"AAAA")
        )
        run = subprocess.run(
            [str(binary), str(testcase)],
            capture_output=True, text=True, check=False, timeout=120)
        report = run.stdout + run.stderr
        self.assertIn("AddressSanitizer", report)
        self.assertIn("double-free", report)
        # The frame the answer key pins is the one the sanitizer names.
        planted = self._manifest(slug)["planted_bugs"][0]
        self.assertEqual(planted["primitive"], "double-free")
        self.assertIn(planted["signature_symbol"], report)

    def test_a_clean_input_is_clean(self) -> None:
        """The trap the answer key says is safe must not fire."""
        slug = "sample-c-doublefree"
        source = ROOT / "targets" / "samples" / slug
        built = subprocess.run(
            ["bash", str(self._recipe(slug, "build.sh")), str(source), str(self.build)],
            capture_output=True, text=True, check=False, timeout=300)
        if built.returncode:
            self.skipTest(f"cannot build {slug}: {built.stderr[-300:]}")
        testcase = self.build / "case-note"
        testcase.write_bytes(b"CHT1" + _field(0x05, b"xy"))
        run = subprocess.run(
            [str(self.build / "chtio"), str(testcase)],
            capture_output=True, text=True, check=False, timeout=120)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertNotIn("AddressSanitizer", run.stdout + run.stderr)

    def test_the_uninit_target_reproduces_or_refuses_to_build(self) -> None:
        slug = "sample-c-uninit"
        source = ROOT / "targets" / "samples" / slug
        built = subprocess.run(
            ["bash", str(self._recipe(slug, "build-msan.sh")),
             str(source), str(self.build)],
            capture_output=True, text=True, check=False, timeout=300)
        binary = self.build / "gauge"

        if built.returncode:
            # No MSan runtime for this host. The contract is that the recipe
            # says so and produces nothing — never an uninstrumented binary
            # that would read as a clean run of the planted bug.
            self.assertFalse(binary.exists(), "a refused build left a binary behind")
            self.assertIn("MemorySanitizer", built.stderr)
            return

        self.assertTrue(binary.is_file())
        # A SAMPLE body of 2..4 bytes leaves the scale field unwritten, and
        # the handler branches on it.
        testcase = self.build / "case-uninit"
        testcase.write_bytes(b"GAU1" + _field(0x01, b"\x00\x05"))
        run = subprocess.run(
            [str(binary), str(testcase)],
            capture_output=True, text=True, check=False, timeout=120)
        report = run.stdout + run.stderr
        self.assertIn("MemorySanitizer", report)
        self.assertIn("use-of-uninitialized-value", report)
        planted = self._manifest(slug)["planted_bugs"][0]
        self.assertIn(planted["signature_symbol"], report)

    def test_sample_answer_keys_cover_every_supported_class(self) -> None:
        """Every CVD and harness-native class has a concrete sample site."""
        manifests = sorted((ROOT / "output" / "samples").glob("sample-*/.ground-truth.json"))
        self.assertEqual(len(manifests), 17)
        covered: set[str] = set()

        for path in manifests:
            manifest = json.loads(path.read_text())
            self.assertEqual(benchmark.manifest_errors(manifest), [], path)
            target = ROOT / "targets" / manifest["target"]
            source_text = "\n".join(
                candidate.read_text(errors="ignore")
                for candidate in target.rglob("*")
                if candidate.is_file()
                and not any(part.startswith("build-") or part == "target"
                            for part in candidate.parts)
            )
            for bug in manifest["planted_bugs"]:
                self.assertIn("classes", bug, f"{path}: {bug['id']}")
                classes = bug["classes"]
                self.assertIsInstance(classes, list, f"{path}: {bug['id']}")
                self.assertTrue(classes, f"{path}: {bug['id']}")
                for name in classes:
                    self.assertIn(name, bug_classes.BUG_CLASSES, f"{path}: {bug['id']}")
                covered.update(classes)

                # Class coverage must point at real source. Runtime
                # symbols may be decorated (C++ namespaces or Go closures), so
                # the stable function component is the source receipt.
                symbol = bug["signature_symbol"].split("::")[-1].split(".")[0]
                self.assertIn(symbol, source_text, f"{path}: {bug['id']}")

        expected = set(bug_classes.DASHBOARD_CLASSES) | set(bug_classes.HARNESS_CLASSES)
        self.assertEqual(covered, expected)

    def test_python_ground_truth_inputs_name_reachable_operations(self) -> None:
        """Embedded example jobs cannot drift away from the sample CLI."""
        target = ROOT / "targets" / "samples" / "sample-python"
        tree = ast.parse((target / "reportkit_cli.py").read_text())
        operations: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(
                isinstance(item, ast.Name) and item.id == "_OPERATIONS" for item in node.targets
            ) and isinstance(node.value, ast.Dict):
                operations.update(
                    key.value for key in node.value.keys
                    if isinstance(key, ast.Constant) and isinstance(key.value, str)
                )
        manifest = self._manifest("sample-python")
        for entry in manifest["planted_bugs"] + manifest["false_positive_traps"]:
            text = entry.get("input_text")
            if not text:
                continue
            header = text.partition("\n")[0]
            self.assertTrue(header.startswith("op: "), entry["id"])
            self.assertIn(header.removeprefix("op: ").strip(), operations, entry["id"])

    def test_documented_sample_counts_match_the_answer_keys(self) -> None:
        page = (ROOT / "docs" / "getting-started" / "sample-targets.md").read_text()
        rows = {
            target: (int(bugs), int(traps))
            for target, bugs, traps in re.findall(
                r"^\| `(samples/sample-[^`]+)` \|.*?\| (\d+) \| (\d+) \|$",
                page,
                re.MULTILINE,
            )
        }
        manifests = sorted((ROOT / "output" / "samples").glob("sample-*/.ground-truth.json"))
        for path in manifests:
            manifest = json.loads(path.read_text())
            self.assertEqual(
                rows.get(manifest["target"]),
                (len(manifest["planted_bugs"]), len(manifest["false_positive_traps"])),
                manifest["target"],
            )

    def test_python_boundary_examples_execute_through_the_runner(self) -> None:
        target = ROOT / "targets" / "samples" / "sample-python"
        cases = {
            "sql-owner-injection": "query: public,private",
            "token-prefix-authentication": "login: True",
            "cross-owner-document-read": "document: alice:payroll draft",
            "unescaped-html-comment": "comment: <article><script>alert(1)</script></article>",
            "negative-refund-logic": "refund: True",
            "diagnostic-secret-disclosure": "diagnostic: sample-signing-key",
            "hardcoded-debug-password": "debug: True",
        }
        entries = {entry["id"]: entry for entry in self._manifest("sample-python")["planted_bugs"]}
        for bug_id, expected in cases.items():
            with self.subTest(bug_id=bug_id):
                job = self.build / f"{bug_id}.job"
                job.write_text(entries[bug_id]["input_text"])
                run = subprocess.run(
                    [sys.executable, str(target / "reportkit_cli.py"), str(job)],
                    env={"PYTHONPATH": str(target / "src")},
                    capture_output=True, text=True, check=False, timeout=10,
                )
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stdout.strip(), expected)

    def test_javascript_prototype_pollution_reaches_its_consumer(self) -> None:
        node = shutil.which("node")
        if not node:
            self.skipTest("node is not installed")
        target = ROOT / "targets" / "samples" / "sample-javascript"
        manifest = self._manifest("sample-javascript")
        entry = next(
            bug for bug in manifest["planted_bugs"]
            if bug["id"] == "prototype-policy-bypass"
        )
        job = self.build / "prototype-policy-bypass.job"
        job.write_text(entry["input_text"])
        run = subprocess.run(
            [node, str(target / "reportkit_cli.js"), str(job)],
            capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(run.stdout.strip(), "state: allowed=true")

    def test_cpp_memory_examples_emit_the_declared_diagnostics(self) -> None:
        slug = "sample-cpp"
        source = ROOT / "targets" / "samples" / slug
        built = subprocess.run(
            ["bash", str(self._recipe(slug, "build.sh")), str(source), str(self.build)],
            capture_output=True, text=True, check=False, timeout=300)
        if built.returncode:
            self.skipTest(f"cannot build {slug}: {built.stderr[-300:]}")

        wanted = {
            "global-option-overflow": "global-buffer-overflow",
            "range-integer-underflow": "heap-buffer-overflow",
            "compact-record-type-confusion": "stack-buffer-overflow",
            "adjusted-pointer-invalid-free": "double-free",
        }
        entries = {entry["id"]: entry for entry in self._manifest(slug)["planted_bugs"]}
        for bug_id, diagnostic in wanted.items():
            with self.subTest(bug_id=bug_id):
                testcase = self.build / bug_id
                testcase.write_bytes(base64.b64decode(entries[bug_id]["input_base64"]))
                run = subprocess.run(
                    [str(self.build / "rbundle"), str(testcase)],
                    capture_output=True, text=True, check=False, timeout=120)
                report = run.stdout + run.stderr
                self.assertIn("AddressSanitizer", report)
                self.assertIn(diagnostic, report)
                symbol = entries[bug_id]["signature_symbol"].split("::")[-1]
                self.assertIn(symbol, report)


if __name__ == "__main__":
    unittest.main(verbosity=2)
