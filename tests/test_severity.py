#!/usr/bin/env python3
"""Behavioral coverage for the offline CVSS v4 severity scorer."""

from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))


def load_severity():
    loader = importlib.machinery.SourceFileLoader(
        "tokenfuzz_severity", str(ROOT / "bin" / "severity")
    )
    spec = importlib.util.spec_from_loader(loader.name, loader)
    if spec is None:
        raise RuntimeError("cannot create bin/severity module spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    loader.exec_module(module)
    return module


severity = load_severity()


class SeverityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="severity-")
        self.root = Path(self.temporary.name)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def make_report(
        self,
        primitive: str,
        *,
        report_id: str = "CRASH-TEST",
        surface: str = "library-api",
        contract: str = "obeyed",
        controls: str = "bytes",
        reproduction: str = "5/5",
        trigger: str = "",
        extra_fields: tuple[tuple[str, str], ...] = (),
        extra: str = "",
        finding: bool = False,
        target_controls: tuple[str, ...] | None = None,
    ) -> Path:
        if target_controls is None:
            parent = self.root / ("findings" if finding else "crashes")
        else:
            target = self.root / "output" / report_id.lower() / "target.toml"
            target.parent.mkdir(parents=True, exist_ok=True)
            values = ", ".join(json.dumps(item) for item in target_controls)
            target.write_text(f"[threat_model]\nattacker_controls = [{values}]\n")
            parent = target.parent / "backend" / "results" / ("findings" if finding else "crashes")
        report_dir = parent / report_id
        report_dir.mkdir(parents=True, exist_ok=True)
        rows = [
            ("Surface", surface),
            ("Caller contract", contract),
            ("Caller controls", controls),
            ("Reproduction rate", reproduction),
            ("Cluster", "CL-test (singleton)"),
        ]
        if trigger:
            rows.append(("Trigger source", trigger))
        rows.extend(extra_fields)
        table = "\n".join(f"| {key} | {value} |" for key, value in rows)
        (report_dir / "report.md").write_text(
            f"# {report_id}: regression fixture\n\n"
            "## Fields\n\n| Field | Value |\n|:--|:--|\n"
            f"{table}\n\n## Root Cause\n\n{primitive}\n{extra}\n\n"
            "## Classification\n\n- **Severity**: TBD\n",
            encoding="utf-8",
        )
        return report_dir

    def score(self, report_dir: Path) -> dict:
        text = (report_dir / "report.md").read_text(encoding="utf-8")
        sanitizer = report_dir / "sanitizer.txt"
        if sanitizer.is_file():
            text += "\n" + sanitizer.read_text(encoding="utf-8", errors="replace")
        return severity.compute_severity(
            severity._strip_auto_sections(text),
            cluster_size=severity._detect_cluster_size(text),
            report_dir=report_dir,
        )

    def assert_metrics(self, result: dict, **expected: str) -> None:
        metrics = result.get("metrics", {})
        for key, value in expected.items():
            self.assertEqual(metrics.get(key, ""), value, f"{key} in {result.get('cvss')}")

    def test_cluster_size_parses_bare_and_table_forms(self) -> None:
        # bin/cluster-findings writes bare-label Cluster: lines (finding reports);
        # bin/cluster-crashes writes the |Cluster| table (crash REPORTs). Both must
        # report the true size, else cluster/reproduction metrics are wrong.
        self.assertEqual(
            severity._detect_cluster_size("Cluster: FCL-abc (4 reports: a, b, c, d)\n"), 4)
        self.assertEqual(
            severity._detect_cluster_size("| Cluster | CL-abc (7 reports: ...) |\n"), 7)
        self.assertEqual(
            severity._detect_cluster_size("Cluster: FCL-abc (singleton)\n"), 1)
        self.assertEqual(severity._detect_cluster_size("no cluster field here\n"), 1)

    def test_primitive_detection_matrix(self) -> None:
        cases = {
            "heap-use-after-free\nWRITE of size 8": "uaf_write",
            "heap-use-after-free\nREAD of size 4": "uaf_read",
            "SCARINESS: 20 (wild-addr-write)": "wild_write",
            "heap-buffer-overflow\nWRITE of size 8": "heap_write",
            "heap-buffer-overflow\nREAD of size 64": "heap_read_big",
            "heap-buffer-overflow\nREAD of size 1": "heap_read_small",
            "stack-overflow on address 0xfeed": "stack_exhaustion",
            "LeakSanitizer: detected memory leaks": "memory_leak",
            "AddressSanitizer: SEGV on unknown address 0x000000000020": "null_deref",
            "AddressSanitizer: SEGV on unknown address 0x12345678\ncaused by a READ memory access": "wild_read",
            "AddressSanitizer: SEGV on unknown address 0x12345678\ncaused by a WRITE memory access": "wild_write",
            "WARNING: ThreadSanitizer: data race": "data_race",
            "x.c:12:5: runtime error: signed integer overflow": "integer_overflow",
            "attempting free on address which was not malloc()-ed": "double_free",
            "Bad-cast detected": "type_confusion",
            "x.cc:10:5: runtime error: member access within address which does not point to an object; invalid vptr": "type_confusion",
            "WARNING: MemorySanitizer: use-of-uninitialized-value": "info_leak",
            "open redirect in login return URL": "open_redirect",
            "server-side request forgery in URL fetch": "ssrf",
            "SQL injection in query builder": "sqli",
            "command injection in shell argument": "command_injection",
            "stored XSS in profile bio": "xss",
            "type confusion is possible in the state transition": "heap_read_small",
        }
        for text, expected in cases.items():
            with self.subTest(expected=expected, text=text):
                self.assertEqual(severity.detect_primitive(text)[0], expected)

    def test_authoritative_overlap_and_signal_precedence(self) -> None:
        cases = (
            ("==7==ERROR: AddressSanitizer: strcpy-param-overlap\nstack of thread T0", "stack_write"),
            ("SUMMARY: AddressSanitizer: memcpy-param-overlap", "heap_write"),
            ("SUMMARY: AddressSanitizer: strcmp-param-overlap", "unknown"),
            ("No AddressSanitizer: strcpy-param-overlap was observed", "unknown"),
            ("ERROR: AddressSanitizer: BUS on unknown address; WRITE of size 8; SCARINESS: 20 (wild-addr-write)", "bus"),
            ("SEGV on unknown address 0x20\nREAD of size 8", "null_deref"),
            ("MemorySanitizer build unavailable\nSEGV", "null_deref"),
            ("input contains ../../tmp\nSEGV", "null_deref"),
            ("heap-buffer-overflow\nWRITE of size 8\npossible SQL injection", "heap_write"),
        )
        for text, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(severity.detect_primitive(text)[0], expected)

    def test_narrative_negation_does_not_invent_findings(self) -> None:
        negatives = (
            "No SQL injection or XSS is possible.",
            "SQL injection is not possible.",
            "Class: no SSRF",
            "The validation prevents type confusion and guards against XXE.",
            "There is no evidence of open redirect.",
        )
        for text in negatives:
            with self.subTest(text=text):
                self.assertEqual(severity.detect_primitive(text)[0], "unknown")
        self.assertEqual(
            severity.detect_primitive("input is not sanitized, leading to SQL injection")[0],
            "sqli",
        )

    def test_structured_primitive_precedence(self) -> None:
        structured = self.make_report(
            "No SQL injection is possible. Narrative mentions open redirect.",
            extra_fields=(("Primitive", "sqli"),),
        )
        self.assertEqual(self.score(structured)["primitive_key"], "sqli")
        sanitizer = self.make_report(
            "heap-use-after-free\nWRITE of size 8\nopen redirect",
            report_id="CRASH-AUTH",
            extra_fields=(("Primitive", "open_redirect"),),
        )
        self.assertEqual(self.score(sanitizer)["primitive_key"], "uaf_write")

    def test_surface_contract_and_control_metrics(self) -> None:
        cases = (
            ({"report_id": "CRASH-NET", "surface": "network — TLS handler"}, "network", {"AV": "N", "UI": "N"}),
            ({"report_id": "CRASH-LIB"}, "library", {"AV": "N", "UI": "N"}),
            ({"report_id": "CRASH-CLI", "surface": "cli — shipped tool"}, "cli_production", {"AV": "L"}),
            ({"report_id": "CRASH-VIOLATED", "contract": "violated"}, "library", {"AT": "N", "MAT": "P"}),
            ({"report_id": "CRASH-NUMBER", "controls": "number"}, "library", {"MAT": "P"}),
            ({"report_id": "CRASH-PARAM", "extra_fields": (("Parameter control", "application-supplied"),)}, "library", {"MAT": "P"}),
            ({"report_id": "CRASH-TRUSTED", "extra_fields": (("Trusted caller actions", "private struct mutation"),)}, "library", {"MAT": "P"}),
        )
        for kwargs, surface, metrics in cases:
            with self.subTest(report_id=kwargs["report_id"]):
                result = self.score(self.make_report("heap-buffer-overflow\nWRITE of size 8", **kwargs))
                self.assertEqual(result["surface_label"], surface)
                self.assert_metrics(result, **metrics)

    def test_local_call_sequence_is_floored_but_bytes_are_not(self) -> None:
        local = self.score(self.make_report(
            "attempting free on address which was not malloc()-ed",
            report_id="CRASH-LOCAL",
            controls="call-sequence",
            trigger="call-sequence",
        ))
        self.assert_metrics(local, AV="L", AT="P", MVC="N", MVI="N")
        self.assertEqual(local["level"], "Low")

        byte_reachable = self.score(self.make_report(
            "attempting free on address which was not malloc()-ed",
            report_id="CRASH-BYTES",
            controls="input bytes",
            extra="\n## Contract concern\n\nStale narrative annotation.",
        ))
        self.assert_metrics(byte_reachable, AV="N", MVC="")
        self.assertEqual(byte_reachable["level"], "High")

        content = self.score(self.make_report(
            "attempting free on address which was not malloc()-ed",
            report_id="CRASH-CONTENT",
            controls="JSON string and public call sequence",
        ))
        self.assert_metrics(content, AV="N")

    def test_every_local_caller_path_floors_impacts_and_bytes_veto_it(self) -> None:
        local_cases = (
            (
                "CRASH-FLOOR-PARAM",
                "heap-use-after-free\nWRITE of size 8",
                "application configuration parameter",
                "",
                (("Parameter control", "application-supplied"),),
                {"AV": "L", "AT": "P", "MVC": "N", "MVI": "N"},
                "Low",
            ),
            (
                "CRASH-FLOOR-TRUSTED",
                "heap-use-after-free\nWRITE of size 8",
                "private internal state",
                "",
                (("Trusted caller actions", "private struct mutation"),),
                {"AV": "L", "AT": "P", "MVC": "N", "MVI": "N"},
                "Low",
            ),
            (
                "CRASH-FLOOR-SSRF",
                "server-side request forgery via unvalidated callback URL",
                "public call sequence",
                "call-sequence",
                (),
                {"AV": "L", "MSC": "N"},
                "None",
            ),
            (
                "CRASH-FLOOR-XSS",
                "stored XSS in profile bio rendered without escape",
                "public call sequence",
                "call-sequence",
                (),
                {"AV": "L", "MSC": "N", "MSI": "N"},
                "None",
            ),
        )
        for report_id, primitive, controls, trigger, fields, metrics, level in local_cases:
            with self.subTest(report_id=report_id):
                result = self.score(self.make_report(
                    primitive,
                    report_id=report_id,
                    contract="unspecified",
                    controls=controls,
                    trigger=trigger,
                    extra_fields=fields,
                ))
                self.assert_metrics(result, **metrics)
                self.assertEqual(result["level"], level)

        byte_cases = (
            (
                "CRASH-PARAM-BYTES", "heap-use-after-free\nWRITE of size 8",
                (("Parameter control", "application-supplied"),), "MVC", "High",
            ),
            (
                "CRASH-TRUSTED-BYTES", "heap-use-after-free\nWRITE of size 8",
                (("Trusted caller actions", "private struct mutation"),), "MVC", "High",
            ),
            (
                "CRASH-SSRF-BYTES", "server-side request forgery via callback URL",
                (), "MSC", "Medium",
            ),
            (
                "CRASH-XSS-BYTES", "stored XSS in profile bio",
                (), "MSC", "Medium",
            ),
        )
        for report_id, primitive, fields, floor_metric, level in byte_cases:
            with self.subTest(report_id=report_id):
                result = self.score(self.make_report(
                    primitive,
                    report_id=report_id,
                    controls="input bytes",
                    trigger="bytes",
                    extra_fields=fields,
                ))
                self.assert_metrics(result, AV="N", **{floor_metric: ""})
                self.assertEqual(result["level"], level)

    def test_trigger_policy_distinguishes_local_and_remote_capable_preconditions(self) -> None:
        cases = (
            (
                "CRASH-PROSE-SEQUENCE", "library-api", "the sequence of public API calls",
                "", (), {"AV": "L", "AT": "P"},
            ),
            (
                "CRASH-STRUCTURED-SEQUENCE", "library-api", "which handle is passed",
                "call-sequence", (), {"AV": "L", "AT": "P"},
            ),
            (
                "CRASH-API-LENGTH", "library-api", "length",
                "api", (), {"AV": "N", "MAT": "P"},
            ),
            (
                "CRASH-ENV", "library-api", "environment variable state",
                "env", (), {"AV": "N", "MAT": "P"},
            ),
            (
                "CRASH-ENV-TRUSTED", "library-api", "process environment state",
                "env", (("Parameter control", "trusted"),), {"AV": "N"},
            ),
            (
                "CRASH-RACE-TRUSTED", "library-api", "thread scheduling window",
                "race", (("Trusted caller actions", "private struct mutation"),), {"AV": "N"},
            ),
            (
                "CRASH-TRUSTED-LOCAL", "library-api", "which internal handle is passed",
                "", (("Parameter control", "application-supplied"),), {"AV": "L", "AT": "P"},
            ),
            (
                "CRASH-CLI-SEQUENCE", "cli — shipped tool", "call-sequence",
                "", (), {"AV": "L", "AT": "P"},
            ),
        )
        for report_id, surface, controls, trigger, fields, metrics in cases:
            with self.subTest(report_id=report_id):
                result = self.score(self.make_report(
                    "heap-use-after-free\nWRITE of size 8",
                    report_id=report_id,
                    surface=surface,
                    contract="unspecified",
                    controls=controls,
                    trigger=trigger,
                    extra_fields=fields,
                ))
                self.assert_metrics(result, **metrics)

        oom = self.score(self.make_report(
            "ERROR: AddressSanitizer: out-of-memory: allocator is out of memory",
            report_id="CRASH-OOM-AT",
        ))
        self.assertEqual(oom["primitive_key"], "oom")
        self.assert_metrics(oom, AT="P")

    def test_active_threat_model_controls_localization(self) -> None:
        allowed = self.score(self.make_report(
            "attempting free on address which was not malloc()-ed",
            report_id="CRASH-ALLOWED",
            controls="both",
            trigger="both",
            target_controls=("bytes", "call-sequence"),
            extra="\n## Contract concern\n\nStale attacker_controls=[bytes].",
        ))
        self.assert_metrics(allowed, AV="N", MVC="")
        self.assertEqual(allowed["level"], "High")

        allowed_sequence = self.score(self.make_report(
            "attempting free on address which was not malloc()-ed",
            report_id="CRASH-ALLOWED-SEQUENCE",
            controls="ordered public API calls",
            trigger="call-sequence",
            target_controls=("bytes", "call-sequence"),
        ))
        self.assert_metrics(allowed_sequence, AV="N", MVC="")
        self.assertEqual(allowed_sequence["level"], "High")

        constrained_sequence = self.score(self.make_report(
            "attempting free on address which was not malloc()-ed",
            report_id="CRASH-ALLOWED-SEQUENCE-CONSTRAINED",
            controls="ordered public API calls",
            trigger="call-sequence",
            target_controls=("bytes", "call-sequence"),
            extra_fields=(("Parameter control", "harness-only"),),
        ))
        self.assert_metrics(constrained_sequence, AV="L", AT="P")

        for report_id, trigger in (("CRASH-OUTSIDE", "both"), ("CRASH-ALIAS", "sequence")):
            with self.subTest(trigger=trigger):
                outside = self.score(self.make_report(
                    "attempting free on address which was not malloc()-ed",
                    report_id=report_id,
                    controls=trigger,
                    trigger=trigger,
                    target_controls=("bytes",),
                ))
                self.assert_metrics(outside, AV="L", AT="P")
                self.assertEqual(outside["level"], "Low")

    def test_structured_trigger_beats_incidental_prose(self) -> None:
        result = self.score(self.make_report(
            "heap-use-after-free\nWRITE of size 8",
            report_id="CRASH-TRIGGER",
            controls="subject bytes, callback data pointer",
            trigger="call-sequence",
        ))
        self.assert_metrics(result, AV="L", AT="P")

        callback = self.score(self.make_report(
            "heap-use-after-free\nWRITE of size 8",
            report_id="CRASH-CALLBACK",
            controls="both",
            trigger="both",
            target_controls=("bytes", "call-sequence"),
            extra="\n## Contract concern\n\nA callback frees the active parser context.",
        ))
        self.assert_metrics(callback, AV="N", MAT="")
        self.assertEqual(callback["level"], "High")

    def test_exploit_maturity_uses_evidence_not_prose(self) -> None:
        cases = (
            ("?", False, "", "U"),
            ("?", True, "", "P"),
            ("0/5", True, "", "U"),
            ("?", False, "A reproducer and proof-of-concept could be constructed.", "U"),
            ("5/5", False, "Vendor confirms this is actively exploited.", "A"),
            ("5/5", False, "There is no evidence this was exploited in the wild.", "P"),
        )
        for index, (rate, artifact, extra, expected) in enumerate(cases):
            report = self.make_report(
                "heap-buffer-overflow\nWRITE of size 8",
                report_id=f"CRASH-E-{index}",
                reproduction=rate,
                extra=extra,
            )
            if artifact:
                (report / "input.bin").write_bytes(b"payload")
            result = self.score(report)
            self.assert_metrics(result, E=expected)

        clean = self.make_report(
            "heap-buffer-overflow\nWRITE of size 8",
            report_id="CRASH-E-CLEAN",
            reproduction="?",
            extra="BUDGET: 21/60 sanitizer invocations\nCRASH_RATE: 0/1\n[probe] verdict=CLEAN",
        )
        (clean / "input.bin").write_bytes(b"payload")
        self.assert_metrics(self.score(clean), E="U")

    def test_canonical_scores_and_non_shipping_surfaces(self) -> None:
        network = self.score(self.make_report(
            "heap-use-after-free\nWRITE of size 8",
            report_id="CRASH-SCORE-NET",
            surface="network — TLS handler",
        ))
        self.assertEqual((network["score"], network["level"]), (8.9, "High"))
        self.assertEqual(
            network["cvss"]["vector"],
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:P",
        )
        small_read = self.score(self.make_report(
            "heap-buffer-overflow\nREAD of size 1", report_id="CRASH-SCORE-READ"
        ))
        self.assertEqual((small_read["score"], small_read["level"]), (5.5, "Medium"))
        unknown = self.score(self.make_report("process exited abnormally", report_id="CRASH-UNKNOWN"))
        self.assertEqual((unknown["score"], unknown["level"]), (None, "Unknown"))

        dev = self.score(self.make_report(
            "stack-buffer-overflow\nWRITE of size 1",
            report_id="CRASH-DEV",
            surface="maint-tool — maintenance/test program",
        ))
        self.assertEqual((dev["surface_label"], dev["level"]), ("dev_tool", "Low"))
        self.assert_metrics(dev, MVA="L")
        internal = self.score(self.make_report(
            "heap-use-after-free\nWRITE of size 8",
            report_id="CRASH-INTERNAL",
            surface="internal — audit harness",
        ))
        self.assertEqual((internal["surface_label"], internal["level"]), ("internal", "None"))
        library = self.score(self.make_report(
            "heap-buffer-overflow\nREAD of size 1",
            report_id="CRASH-LIB-HARNESS",
            surface="library-api — C harness calls a public entry point",
        ))
        self.assertEqual(library["surface_label"], "library")

    def test_harness_root_detection_requires_no_target_frame(self) -> None:
        harness_only = """==1==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x1 in LLVMFuzzerTestOneInput(unsigned char const*, unsigned long) fuzz_harness.cc:42
    #1 0x2 in fuzzer::Fuzzer::ExecuteCallback /llvm/compiler-rt/FuzzerLoop.cpp:10
"""
        self.assertTrue(severity._crash_is_harness_rooted(harness_only))
        target_context = harness_only + "    #2 0x3 in app_free child.c:91\n"
        self.assertFalse(severity._crash_is_harness_rooted(target_context))
        cli_main = """==1==ERROR: AddressSanitizer: heap-buffer-overflow
    #0 0x1 in main src/tool.c:20
"""
        self.assertFalse(severity._crash_is_harness_rooted(cli_main))
        target_named_free = harness_only + "    #2 0x3 in free_node src/tree.c:91\n"
        self.assertFalse(severity._crash_is_harness_rooted(target_named_free))

    def test_unenriched_and_validated_findings_fail_closed(self) -> None:
        skeleton = self.make_report(
            "heap-use-after-free\nWRITE of size 8\n_TODO (agent): describe the defect.",
            report_id="CRASH-SKELETON",
        )
        self.assertEqual((self.score(skeleton)["level"], self.score(skeleton)["score"]), ("Unknown", None))

        accepted = self.make_report(
            "Concrete attacker-controlled repeated work.",
            report_id="FIND-ACCEPTED",
            finding=True,
            surface="library-api",
        )
        (accepted / ".llm-find-quality.json").write_text(json.dumps({
            "decision_version": "v13-python", "accept": True, "accept_count": 2,
            "class": "dos:algorithmic", "severity": "critical",
        }))
        accepted_result = self.score(accepted)
        self.assertEqual(accepted_result["primitive_key"], "dos_amplification")
        self.assertNotEqual(accepted_result["level"], "Critical")

        review = self.make_report(
            "Concrete but unmapped boundary crossing.",
            report_id="FIND-REVIEW",
            finding=True,
        )
        (review / ".llm-find-quality.json").write_text(json.dumps({
            "decision_version": "v13-python", "accept": True, "accept_count": 2,
            "class": "boundary:new-unmapped-kind",
        }))
        self.assertEqual((self.score(review)["level"], self.score(review)["score"]), ("Needs review", None))
        (review / ".llm-find-quality.json").write_text("[]\n")
        self.assertEqual(self.score(review)["level"], "Needs review")

    def test_report_cli_is_idempotent_and_batch_writes_json(self) -> None:
        report = self.make_report(
            "heap-use-after-free\nWRITE of size 8",
            report_id="CRASH-CLI-REPORT",
            surface="network — TLS handler",
        )
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(severity.main(["--report", str(report)]), 0)
            first = (report / "report.md").read_text()
            self.assertEqual(severity.main(["--report", str(report)]), 0)
        second = (report / "report.md").read_text()
        self.assertEqual(first, second)
        self.assertEqual(second.count("## Severity rationale"), 1)
        self.assertIn("CVSS:4.0/AV:N/AC:L", second)
        self.assertIn("Verification facts", second)
        self.assertIn("not part of severity", second)
        self.assertTrue((report / "severity.json").is_file())

        finding = self.make_report(
            "path traversal in archive extraction",
            report_id="FIND-BATCH",
            finding=True,
            extra_fields=(("Primitive", "path_traversal"),),
        )
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(severity.main(["--batch", str(self.root)]), 0)
        self.assertTrue((finding / "severity.json").is_file())


if __name__ == "__main__":
    unittest.main()
