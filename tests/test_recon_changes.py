#!/usr/bin/env python3
"""Recon patch ranking, slicing, dependency, and scope regressions."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import recon_slicer
import workqueue


def load_script(name: str, path: Path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    loader.exec_module(module)
    return module


severity = load_script("recon_test_severity", ROOT / "bin" / "severity")
audit_recon = load_script("recon_test_command", ROOT / "bin" / "audit-recon")


class ReconChangesTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="recon-changes-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_patch_filter_boost_coverage_and_recon_primitives(self) -> None:
        self.assertTrue(workqueue.is_non_audit_patch_description(
            "release-1.34.0 (#896)", ["include/sample_version.h"]
        ))
        self.assertFalse(workqueue.is_non_audit_patch_description(
            "release 1.2: fix CVE-2025-12345 heap overflow", ["src/sample.c"]
        ))
        self.assertTrue(workqueue.is_version_only_file_set(["include/sample_version.h"]))
        self.assertFalse(workqueue.is_version_only_file_set(
            ["include/sample_version.h", "src/sample.c"]
        ))
        self.assertEqual(workqueue.patch_audit_boost("release-1.34.0"), 0)
        phrases = (
            "fix CVE-2025-12345 heap overflow", "Fix UAF in worker pool",
            "Patch SQL injection in admin search", "Resolve XSS in profile rendering",
            "Patch SSRF in webhook handler", "Fix path traversal via Zip-Slip",
            "Address GHSA-abcd-1234-efgh in TLS handshake", "CWE-22: arbitrary file disclosure",
            "Insecure deserialization in loader", "Authorization bypass for admin endpoint",
            "Hard-coded API key in default config", "ReDoS in email validator",
            "Race condition between cancel and free", "Fix uninitialized memory read in parser",
            "CRLF injection in logger", "Open redirect via crafted Location header",
            "Patch typosquat in package install path", "Fix remote code execution in handler",
            "Prevent stack exhaustion from nested input", "Mitigate DoS amplification in resolver",
        )
        for phrase in phrases:
            with self.subTest(phrase=phrase):
                self.assertGreaterEqual(workqueue.patch_audit_boost(phrase), 20)

        primitives = {
            "DNS cache poisoning enables protocol downgrade": "protocol_state",
            "DNS name decompression memory amplification of 100x": "dos_amplification",
            "DNS0x20 security feature defeated by cache normalization bug": "logic_regression",
        }
        for text, expected in primitives.items():
            self.assertEqual(severity.detect_primitive(text)[0], expected)
        for key, minimum in (
            ("protocol_state", 5), ("dos_amplification", 4),
            ("logic_regression", 2), ("info_leak", 5),
        ):
            metrics, _ = severity._cvss4_metrics(key, "library", {}, False)
            self.assertIsNotNone(metrics)
            self.assertGreaterEqual(int(severity.cvss4.score(metrics)), minimum)

        coverage = {
            "uaf_write": "use-after-free write", "uaf_read": "use-after-free read",
            "double_free": "double free", "wild_write": "wild pointer write",
            "wild_read": "wild pointer read", "type_confusion": "type confusion",
            "heap_write": "heap buffer overflow", "heap_read_big": "heap buffer over-read",
            "heap_read_small": "out-of-bounds read", "stack_write": "stack buffer overflow",
            "stack_read": "stack buffer over-read", "global_write": "global buffer overflow",
            "global_read": "global buffer over-read", "data_race": "data race",
            "info_leak": "uninitialized memory read", "null_deref": "null pointer dereference",
            "stack_exhaustion": "stack exhaustion via deep recursion",
            "integer_overflow": "integer overflow", "regex_dos": "ReDoS catastrophic backtracking",
            "dos_amplification": "DoS amplification", "command_injection": "remote code execution",
            "deserialization": "insecure deserialization", "ssti": "server-side template injection",
            "sqli": "SQL injection", "authn_bypass": "authentication bypass",
            "authz_bypass": "authorization bypass", "idor": "insecure direct object reference",
            "path_traversal": "path traversal", "xxe": "XML external entity",
            "secrets_exposure": "hard-coded credential leak", "ssrf": "server-side request forgery",
            "prototype_pollution": "prototype pollution", "xss": "cross-site scripting",
            "open_redirect": "open redirect", "csrf": "cross-site request forgery",
            "crypto_weakness": "weak cryptography", "injection": "CRLF injection",
        }
        exemptions = {"memory_leak", "oom", "bus", "protocol_state", "logic_regression"}
        self.assertFalse(set(coverage) & exemptions)
        self.assertEqual(set(severity.CVSS4_CLASS), set(coverage) | exemptions)
        for key, phrase in coverage.items():
            with self.subTest(cvss_class=key):
                self.assertGreater(workqueue.patch_audit_boost(phrase), 0)

    def source_tree(self, name: str, directories: dict[str, int], root_files: int = 0) -> Path:
        target = self.root / name / "src" / "lib"
        for directory, count in directories.items():
            path = target / directory
            path.mkdir(parents=True)
            for index in range(count):
                (path / f"file_{index}.c").write_text("int sample;\n")
        target.mkdir(parents=True, exist_ok=True)
        for index in range(root_files):
            (target / f"root_{index}.c").write_text("int sample;\n")
        return target.parents[1]

    @staticmethod
    def members(slices: list[tuple[str, list[Path]]]) -> dict[Path, str]:
        return {path: label for label, files in slices for path in files}

    def test_partition_completeness_seed_reroll_loc_balance_and_flat_tree(self) -> None:
        target = self.source_tree(
            "partition", {"dsa": 10, "record": 10, "event": 10, "util": 10}, 8
        )
        source = target / "src" / "lib"
        files = recon_slicer.collect_source_files(source)
        seed0 = recon_slicer.partition(source, files, 4, 0)
        seed0_again = recon_slicer.partition(source, files, 4, 0)
        seed1 = recon_slicer.partition(source, files, 4, 1)
        self.assertEqual(len(seed0), 4)
        self.assertEqual(len(self.members(seed0)), 48)
        self.assertEqual(self.members(seed0), self.members(seed0_again))
        self.assertEqual(set(self.members(seed0)), set(self.members(seed1)))
        self.assertNotEqual(self.members(seed0), self.members(seed1))

        heavy = self.root / "heavy" / "src" / "lib"
        parse = heavy / "parse"
        network = heavy / "net"
        parse.mkdir(parents=True)
        network.mkdir()
        (parse / "big.c").write_text("line\n" * 500)
        for index in range(3):
            (parse / f"stub_{index}.c").write_text("line\n")
        for index in range(4):
            (network / f"net_{index}.c").write_text("line\n")
        files = recon_slicer.collect_source_files(heavy)
        slices = recon_slicer.partition(heavy, files, 2, 0)
        self.assertEqual(len(slices), 2)
        self.assertEqual(len(self.members(slices)), 8)
        big_label = self.members(slices)[parse / "big.c"]
        self.assertNotEqual(big_label, self.members(slices)[parse / "stub_0.c"])

        flat = self.root / "flat"
        flat.mkdir()
        for name in ("parser", "valid", "tree", "schema", "encoding", "uri", "xpath", "regexp"):
            (flat / f"{name}.c").write_text("line\n" * 60)
        flat_files = recon_slicer.collect_source_files(flat)
        flat_slices = recon_slicer.partition(flat, flat_files, 4, 0)
        self.assertEqual(len(flat_slices), 4)
        self.assertEqual(len(self.members(flat_slices)), 8)
        source = (ROOT / "lib" / "recon_slicer.py").read_text()
        self.assertNotRegex(source, r"(?m)^(NAME_PREFIX_GROUPS|def (?:detect_project_prefix|label_for_root_file))")

    @staticmethod
    def component(units: list[tuple[str, list[Path]]], name: str) -> set[str]:
        for _, files in units:
            names = {path.name for path in files}
            if name in names:
                return names
        return set()

    def paired_units(self, files: dict[str, str]):
        directory = Path(tempfile.mkdtemp(prefix="recon-deps-", dir=self.root))
        for name, body in files.items():
            (directory / name).write_text(body)
        paths = sorted(path for path in directory.iterdir() if path.is_file())
        return recon_slicer.build_dependency_units(directory, paths)

    def test_dependency_units_across_languages_and_mixed_language_guards(self) -> None:
        units = self.paired_units({
            "sample_parse.h": "int sample_decode(int);\n",
            "sample_parse.c": '#include "sample_parse.h"\nint run(int x){ return sample_decode(x); }\n',
            "sample_codec.c": "int sample_decode(int x){ return x + 1; }\n",
            "sample_misc.c": "int unrelated(void){ return 0; }\n",
        })
        component = self.component(units, "sample_parse.c")
        self.assertTrue({"sample_parse.c", "sample_parse.h", "sample_codec.c"} <= component)
        self.assertNotIn("sample_misc.c", component)
        self.assertEqual(self.paired_units({
            "one.c": "int duplicate(void){return 1;}\n",
            "two.c": "int duplicate(void){return 2;}\n",
            "call.c": "void go(void){duplicate();}\n",
        }), [])
        php = self.paired_units({
            "entry.php": "<?php require_once 'helper.php'; run();\n",
            "helper.php": "<?php function run(){ return 1; }\n",
        })
        self.assertTrue({"entry.php", "helper.php"} <= self.component(php, "entry.php"))
        extension = self.paired_units({
            "driver.py": "import fastthing\nfastthing.go()\n",
            "fastthing.c": '#include <Python.h>\nPyMODINIT_FUNC PyInit_fastthing(void){ return NULL; }\n',
        })
        self.assertTrue({"driver.py", "fastthing.c"} <= self.component(extension, "driver.py"))

        language_cases = {
            ".rs": ("pub fn decode(x: i32) -> i32 { x + 1 }\n", "fn run() { let _ = decode(1); }\n"),
            ".go": ("func Decode(x int) int { return x + 1 }\n", "func Run() { Decode(1) }\n"),
            ".java": ("public int decode(int x) { return x + 1; }\n", "void run() { decode(1); }\n"),
            ".swift": ("func decode(_ x: Int) -> Int { return x + 1 }\n", "func run() { _ = decode(1) }\n"),
            ".kt": ("fun decode(x: Int): Int { return x + 1 }\n", "fun run() { decode(1) }\n"),
            ".pl": ("sub decode { return $_[0] + 1; }\n", "sub run { decode(1); }\n"),
            ".rb": ("def decode(x)\n x + 1\nend\n", "def run\n decode(1)\nend\n"),
            ".ts": ("export function decode(x: number) { return x + 1 }\n", "function run() { decode(1) }\n"),
        }
        for extension, (definition, caller) in language_cases.items():
            with self.subTest(extension=extension):
                units = self.paired_units({f"def{extension}": definition, f"use{extension}": caller})
                self.assertTrue(
                    {f"def{extension}", f"use{extension}"} <= self.component(units, f"def{extension}")
                )

        self.assertEqual(self.paired_units({
            "driver.py": "def go():\n    decode(1)\n",
            "codec.c": "int decode(int x){ return x + 1; }\n",
        }), [])
        js_ts = self.paired_units({
            "lib.js": "function decode(x){ return x + 1 }\n",
            "app.ts": "function run(){ decode(1) }\n",
        })
        self.assertTrue({"lib.js", "app.ts"} <= self.component(js_ts, "lib.js"))
        c_cpp = self.paired_units({
            "impl.c": "int decode(int x){ return x + 1; }\n",
            "use.cc": "void run(){ decode(1); }\n",
        })
        self.assertTrue({"impl.c", "use.cc"} <= self.component(c_cpp, "impl.c"))
        duplicate_cross_runtime = self.paired_units({
            "codec.c": "int decode(int x){ return x + 1; }\n",
            "use.c": "void run(void){ decode(1); }\n",
            "helper.py": "def decode(x):\n    return x\n",
        })
        self.assertTrue(
            {"codec.c", "use.c"} <= self.component(duplicate_cross_runtime, "codec.c")
        )
        for definition in (
            "export const decode = (x) => { return x + 1 }\n",
            "export const decode = (x: number): number => x + 1\n",
        ):
            extension = ".ts" if ": number" in definition else ".js"
            units = self.paired_units({
                f"lib{extension}": definition,
                f"app{extension}": "function run(){ return decode(1) }\n",
            })
            self.assertTrue(
                {f"lib{extension}", f"app{extension}"} <= self.component(units, f"lib{extension}")
            )

    def test_external_symlink_and_end_to_end_dependency_partition(self) -> None:
        base = self.root / "symlink"
        outside = self.root / "outside"
        base.mkdir()
        outside.mkdir()
        (outside / "external.c").write_text("int decode(int x){ return x + 1; }\n")
        (base / "real.c").write_text("void run(void){ decode(1); }\n")
        (base / "link.c").symlink_to(outside / "external.c")
        units = recon_slicer.build_dependency_units(base, [base / "real.c", base / "link.c"])
        self.assertIn("real.c", {path.name for _, files in units for path in files})

        flat = self.root / "connected"
        flat.mkdir()
        (flat / "sample_parse.h").write_text("int sample_decode(int);\n")
        (flat / "sample_parse.c").write_text(
            '#include "sample_parse.h"\nint run(int x){ return sample_decode(x); }\n'
        )
        (flat / "sample_codec.c").write_text("int sample_decode(int x){ return x + 1; }\n")
        for name in ("alpha", "beta", "gamma"):
            (flat / f"sample_{name}.c").write_text("line\n" * 40)
        files = recon_slicer.collect_source_files(flat)
        slices = recon_slicer.partition(flat, files, 3, 0)
        membership = self.members(slices)
        connected = {membership[flat / name] for name in (
            "sample_parse.h", "sample_parse.c", "sample_codec.c"
        )}
        self.assertEqual(len(connected), 1)
        self.assertEqual(len(membership), 6)

    def test_path_and_changed_since_scopes(self) -> None:
        target = self.root / "scoped"
        parse = target / "src" / "lib" / "parse"
        network = target / "src" / "lib" / "net"
        parse.mkdir(parents=True)
        network.mkdir()
        for index in range(3):
            (parse / f"parse_{index}.c").write_text("a\nb\n")
        for index in range(2):
            (network / f"net_{index}.c").write_text("a\nb\n")
        output = self.root / "path-output"
        rc = recon_slicer.main([
            "--target-path", str(target), "--path", "parse", "--slices", "2",
            "--out-dir", str(output),
        ])
        self.assertEqual(rc, 0)
        content = "".join(path.read_text() for path in output.glob("slice-*.txt"))
        self.assertIn("/parse/", content)
        self.assertNotIn("/net/", content)

        repository = self.root / "git-target"
        parse = repository / "src" / "lib" / "parse"
        network = repository / "src" / "lib" / "net"
        parse.mkdir(parents=True)
        network.mkdir()
        (parse / "parse.c").write_text("a\nb\n")
        (network / "net.c").write_text("a\nb\n")
        subprocess.run(["git", "-C", str(repository), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(repository), "config", "user.email", "test@example.invalid"], check=True)
        subprocess.run(["git", "-C", str(repository), "config", "user.name", "test"], check=True)
        subprocess.run(["git", "-C", str(repository), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-qm", "base"], check=True)
        (parse / "parse.c").write_text("a\nb\nc\n")
        subprocess.run(["git", "-C", str(repository), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repository), "commit", "-qm", "change"], check=True)
        changed = self.root / "changed-output"
        rc = recon_slicer.main([
            "--target-path", str(repository), "--changed-since", "HEAD~1",
            "--slices", "4", "--out-dir", str(changed),
        ])
        self.assertEqual(rc, 0)
        content = "".join(path.read_text() for path in changed.glob("slice-*.txt"))
        self.assertIn("/parse/parse.c", content)
        self.assertNotIn("/net/net.c", content)
        self.assertEqual(recon_slicer.main([
            "--target-path", str(repository), "--changed-since", "HEAD",
            "--slices", "4", "--out-dir", str(changed),
        ]), 7)

    def test_audit_recon_argument_validation_and_removed_focus_mode(self) -> None:
        parser = audit_recon.build_parser()
        base = ["--target", "sample", "--target-path", str(self.root), "--backend", "codex"]
        args = parser.parse_args(base)
        self.assertEqual(args.recon_lookback, 365)
        self.assertEqual(args.concurrency, 4)
        self.assertFalse(args.no_reroll)
        self.assertTrue(parser.parse_args(base + ["--no-reroll"]).no_reroll)
        for arguments in (
            ["--scope", "bogus"], ["--concurrency", "abc"], ["--recon-lookback", "xyz"],
        ):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit):
                parser.parse_args(base + arguments)
        with self.assertRaises(SystemExit):
            audit_recon.main(base + ["--scope", "path"])
        self.assertFalse((ROOT / "lib" / "recon_focus_areas.txt").exists())
        source = (ROOT / "bin" / "audit-recon").read_text()
        for removed in ("focus-prompt", "recon_focus", "FOCUS_LIST"):
            self.assertNotIn(removed, source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
