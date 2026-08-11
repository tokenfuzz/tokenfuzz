#!/usr/bin/env python3
"""Behavioral coverage for the offline CVSS v4 severity scorer."""

from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import io
import itertools
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import severity_receipt  # noqa: E402


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
        return severity.compute_severity(
            severity._strip_auto_sections(text),
            cluster_size=severity._detect_cluster_size(text),
            report_dir=report_dir,
            sanitizer_text=(
                sanitizer.read_text(encoding="utf-8", errors="replace")
                if sanitizer.is_file() else None
            ),
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

    def test_field_specific_placeholder_does_not_shadow_inferred_value(self) -> None:
        fields = severity.extract_report_fields(
            "| Field | Value |\n"
            "|:--|:--|\n"
            "| Boundary | unspecified |\n"
            "| Caller contract | unspecified |\n\n"
            "Boundary: caller-supplied document\n"
            "Caller contract: obeyed\n"
        )
        self.assertEqual(fields["boundary"], "caller-supplied document")
        self.assertEqual(fields["caller_contract"], "unspecified")

    def test_claimed_race_without_detector_scores_as_logic_race(self) -> None:
        # A report-only classifier cannot tell a TSan-detected memory race from
        # a race argued out of source, and picking `data_race` buys the
        # code-execution row (VC/VI/VA H/H/H) — how an unsynchronized-shared-
        # state finding with no runtime evidence at all reaches High.
        #
        # The fixture is the population this path actually sees: a race the
        # quality gate already accepted as security-relevant, defeating a named
        # security decision. VI:H is the floor for "a security control stopped
        # holding", not an impact invented from the word "race" — a report that
        # establishes some other consequence names it, and is scored through it
        # (see test_a_race_that_names_its_consequence_scores_through_it).
        claimed = self.make_report(
            "A concurrent resolution skips the shared lookup table, so the "
            "configured redirect is not applied and the untrusted identifier "
            "is used verbatim.",
            report_id="FIND-RACE", finding=True, reproduction="",
            extra_fields=(("Primitive", "data_race"),),
        )
        scored = self.score(claimed)
        self.assertEqual(scored["primitive_key"], "race_condition")
        self.assert_metrics(scored, VC="N", VI="H", VA="N", AT="P")
        self.assertEqual(scored["level"], "Medium")

        # A race detector actually reported it: the memory-corruption reading
        # is evidenced, so the row and the band are unchanged. Dropping this row
        # would leave every TSan/Go-race crash unscored — rank 0, below any Low
        # prose finding — which no test that checks only ground-truth
        # attribution can see.
        detected = self.make_report(
            "concurrent access", report_id="CRASH-RACE",
            extra_fields=(("Primitive", "data_race"),),
        )
        (detected / "sanitizer.txt").write_text(
            "WARNING: ThreadSanitizer: data race\n"
            "    #0 worker sample.c:31\n",
            encoding="utf-8",
        )
        confirmed = self.score(detected)
        self.assertEqual(confirmed["primitive_key"], "data_race")
        self.assert_metrics(confirmed, VC="H", VI="H", VA="H")
        self.assertIsNotNone(confirmed["score"])

        # Prose that merely names a consequence the report speculates about is
        # not evidence for it: a catalog-race narrative mentioning SSRF must not
        # be scored through the ssrf row on the strength of the phrase.
        speculative = self.make_report(
            "The shared-state collision could enable server-side request forgery.",
            report_id="FIND-RACE-PROSE", finding=True, reproduction="",
            extra_fields=(("Primitive", "data_race"),),
        )
        self.assertEqual(self.score(speculative)["primitive_key"], "race_condition")

    def test_a_race_that_names_its_consequence_scores_through_it(self) -> None:
        # The redirect catches only the case where no consequence was named.
        # A race whose report classifies what actually goes wrong keeps that
        # class and its impact — so `race_condition` can never become a ceiling
        # that flattens availability, disclosure, or corruption races into
        # integrity-only.
        for primitive, expected in (
            ("dos_amplification", ("N", "N", "H")),
            ("info_leak", ("H", "N", "L")),
            ("authz_bypass", ("H", "L", "N")),
            ("heap_write", ("H", "H", "H")),
        ):
            with self.subTest(primitive=primitive):
                report = self.make_report(
                    "concurrent access to shared state under load",
                    report_id=f"FIND-{primitive}", finding=True, reproduction="",
                    extra_fields=(("Primitive", primitive),),
                )
                scored = self.score(report)
                self.assertEqual(scored["primitive_key"], primitive)
                self.assert_metrics(
                    scored, VC=expected[0], VI=expected[1], VA=expected[2],
                )

    def test_unsupported_race_claim_is_demoted_by_a_clean_sanitizer_run(self) -> None:
        # The claimed-impact valve covers `race_condition` too: a race the
        # report asserts but an on-disk run contradicts loses its impact rather
        # than keeping a Medium band on the strength of the label alone.
        report = self.make_report(
            "concurrent counter update", report_id="FIND-RACE-CLEAN",
            finding=True, reproduction="",
            extra_fields=(("Primitive", "data_race"),),
        )
        (report / "sanitizer.txt").write_text(
            "[probe] verdict=CLEAN\nNO CRASHES in 5 runs\n", encoding="utf-8",
        )
        scored = self.score(report)
        self.assertEqual((scored["level"], scored["score"]), ("Needs review", None))

    def test_sanitizer_class_without_a_row_still_outranks_a_claimed_field(self) -> None:
        # `undefined_behavior` is deliberately absent from CVSS4_CLASS. Gating
        # runtime authority on membership in that table would let a report's own
        # `Primitive:` field overrule what the sanitizer observed — an
        # unscoreable UB crash reappearing as a self-declared High.
        report = self.make_report(
            "ERROR: AddressSanitizer: new-delete-type-mismatch on 0x602000000010\n"
            "SUMMARY: AddressSanitizer: new-delete-type-mismatch",
            report_id="CRASH-UB", extra_fields=(("Primitive", "heap_write"),),
        )
        scored = self.score(report)
        self.assertEqual(scored["primitive_key"], "undefined_behavior")
        self.assertEqual((scored["level"], scored["score"]), ("Unknown", None))

    def test_saved_reproducer_is_recognised_by_prefix_not_extension(self) -> None:
        # A standalone reproducer harness writes `input_1.html` / `repro.cmd`;
        # an exact `input.*` match graded that bundle as carrying no reproducer
        # and dropped it to E:U — unproven, next to a saved, replayable input.
        bundle = self.make_report(
            "heap-buffer-overflow\nWRITE of size 8", report_id="FIND-REPRO",
            finding=True, reproduction="",
        )
        self.assert_metrics(self.score(bundle), E="U")
        (bundle / "repro.cmd").write_text("./harness input_1.html\n", encoding="utf-8")
        self.assert_metrics(self.score(bundle), E="U")
        (bundle / "input_1.html").write_text("<a>", encoding="utf-8")
        self.assert_metrics(self.score(bundle), E="P")

        metadata = self.make_report(
            "heap-buffer-overflow\nWRITE of size 8",
            report_id="FIND-REPRO-METADATA", finding=True, reproduction="",
        )
        (metadata / "reproduction-notes.md").write_text(
            "No runnable testcase saved.\n", encoding="utf-8")
        (metadata / "input-analysis.md").write_text(
            "Potential input shape.\n", encoding="utf-8")
        (metadata / "report.html").write_text(
            "<html>Generated report</html>\n", encoding="utf-8")
        (metadata / "input-files").mkdir()
        self.assert_metrics(self.score(metadata), E="U")

    def test_primitive_detection_matrix(self) -> None:
        cases = {
            "heap-use-after-free\nWRITE of size 8": "uaf_write",
            "heap-use-after-free\nREAD of size 4": "uaf_read",
            "ERROR: AddressSanitizer: use-after-poison\nWRITE of size 8": "uaf_write",
            "ERROR: AddressSanitizer: bad-free": "bad_free",
            "ERROR: AddressSanitizer: new-delete-type-mismatch": "undefined_behavior",
            "ERROR: AddressSanitizer: free-size-mismatch": "undefined_behavior",
            "ERROR: AddressSanitizer: calloc-overflow": "undefined_behavior",
            "ERROR: AddressSanitizer: reallocarray-overflow": "undefined_behavior",
            "ERROR: AddressSanitizer: pvalloc-overflow": "undefined_behavior",
            "ERROR: AddressSanitizer: invalid-pointer-pair": "undefined_behavior",
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
            "attempting free on address which was not malloc()-ed": "bad_free",
            "Bad-cast detected": "type_confusion",
            "x.cc:10:5: runtime error: member access within address which does not point to an object; invalid vptr": "type_confusion",
            "x.c:1:2: runtime error: call to function through pointer to incorrect function type": "type_confusion",
            "x.c:1:2: runtime error: member access within address which does not point to an object of type X": "type_confusion",
            "x.c:1:2: runtime error: member access within address with insufficient space for an object of type X": "heap_read_small",
            "x.c:1:2: runtime error: store to address with insufficient space for an object of type X": "heap_write",
            "x.c:1:2: runtime error: variable length array bound evaluates to non-positive value 0": "undefined_behavior",
            "WARNING: MemorySanitizer: use-of-uninitialized-value": "info_leak",
            "open redirect in login return URL": "open_redirect",
            "server-side request forgery in URL fetch": "ssrf",
            "SQL injection in query builder": "sqli",
            "command injection in shell argument": "command_injection",
            "remote code execution in expression evaluator": "code_execution",
            "arbitrary file read through a decoded path": "arbitrary_file_read",
            "arbitrary file write through a decoded path": "arbitrary_file_write",
            "sandbox escape through the worker boundary": "sandbox_escape",
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
            ("ERROR: HWAddressSanitizer: tag-mismatch", "unknown"),
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

    def test_saved_diagnostic_outranks_report_narrative(self) -> None:
        diagnostic = (
            "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
            "READ of size 1 at 0x1 thread T0\n"
            "SCARINESS: 12 (1-byte-read-heap-buffer-overflow)\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow\n"
        )
        for narrative in (
            "An upstream change called this a use-after-free.",
            "The iterator discusses a 17-byte span and a sibling double-free.",
        ):
            with self.subTest(narrative=narrative):
                self.assertEqual(
                    severity.detect_primitive(narrative, diagnostic)[0],
                    "heap_read_small",
                )
        later_run = diagnostic + (
            "==2==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x2\n"
            "READ of size 4096 at 0x2 thread T0\n"
        )
        self.assertEqual(
            severity.detect_primitive("use-after-free", later_run)[0],
            "heap_read_small",
        )

    def test_wild_address_tag_requires_matching_runtime_direction(self) -> None:
        common = "==1==ERROR: AddressSanitizer: BUS on unknown address\n"
        self.assertEqual(
            severity.detect_primitive(
                "",
                common
                + "The signal is caused by a WRITE memory access.\n"
                + "SCARINESS: 30 (wild-addr-write)\n",
            )[0],
            "wild_write",
        )
        self.assertEqual(
            severity.detect_primitive(
                "",
                common
                + "The signal is caused by a READ memory access.\n"
                + "SCARINESS: 30 (wild-addr-write)\n",
            )[0],
            "bus",
        )

    def test_saved_diagnostic_preserves_allocator_and_overlap_classes(self) -> None:
        for token in ("calloc-overflow", "reallocarray-overflow", "pvalloc-overflow"):
            with self.subTest(token=token):
                self.assertEqual(
                    severity.detect_primitive(
                        "", f"ERROR: AddressSanitizer: {token}\n"
                    )[0],
                    "undefined_behavior",
                )
        self.assertEqual(
            severity.detect_primitive(
                "",
                "ERROR: AddressSanitizer: strcpy-param-overlap\n"
                "Address 0x1 is located in stack of thread T0\n",
            )[0],
            "stack_write",
        )

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
        structured_read = self.make_report(
            "The analysis also discusses a sibling write overflow.",
            report_id="FIND-READ",
            extra_fields=(("Primitive", "heap_read_small"),),
        )
        self.assertEqual(
            self.score(structured_read)["primitive_key"], "heap_read_small",
        )
        sanitizer = self.make_report(
            "ERROR: AddressSanitizer: heap-use-after-free\n"
            "WRITE of size 8\nopen redirect",
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

    def test_primary_build_prerequisite_is_environmental_not_base_severity(self) -> None:
        report = self.make_report(
            "heap-buffer-overflow\nWRITE of size 8",
            report_id="CRASH-CONFIG",
        )
        evidence = {
            "status": "not-reproduced",
            "build_config_name": "widened",
            "build_config_id": "wide-id",
        }
        with mock.patch.object(
            severity.crash_bundle, "verified_primary_differential", return_value=evidence
        ):
            result = self.score(report)
        self.assert_metrics(result, MAT="P")
        self.assertNotIn("MAT:P", result["cvss"]["base_vector"])
        self.assertIn("primary-build differential: not-reproduced", result["repro_facts"][-1])
        self.assertTrue(any("environmental prerequisite" in note for note in result["derivation"]))

    def test_alternate_config_is_surfaced_as_a_fields_table_row(self) -> None:
        report = self.make_report(
            "heap-buffer-overflow\nWRITE of size 8", report_id="CRASH-CFGROW",
        )
        (report / ".build-config.json").write_text(
            json.dumps({
                "id": "widened-abc123",
                "name": "widened",
                "label": "widened in-tree features",
                "features": ["JIT", "16/32-bit APIs"],
                "recipe_sha256": "deadbeef",
            }),
            encoding="utf-8",
        )
        evidence = {
            "status": "not-reproduced",
            "build_config_name": "widened",
            "build_config_id": "widened-abc123",
        }
        with mock.patch.object(
            severity.crash_bundle, "verified_primary_differential", return_value=evidence
        ):
            result = self.score(report)
            severity.update_report(report / "report.md", result)
        text = (report / "report.md").read_text(encoding="utf-8")
        row = next(line for line in text.splitlines() if line.startswith("| Build config |"))
        for token in ("widened", "widened-abc123", "JIT", "16/32-bit APIs",
                      "does not reproduce on the primary build"):
            self.assertIn(token, row)

        # export-repro migrates hidden audit provenance before triage invokes
        # severity; the report row must survive that real bundle layout.
        audit = report / ".audit"
        audit.mkdir()
        (report / ".build-config.json").replace(audit / ".build-config.json")
        evidence["status"] = "reproduced"
        with mock.patch.object(
            severity.crash_bundle, "verified_primary_differential", return_value=evidence
        ):
            result = self.score(report)
            severity.update_report(report / "report.md", result)
        rows = [
            line for line in (report / "report.md").read_text().splitlines()
            if line.startswith("| Build config |")
        ]
        self.assertEqual(len(rows), 1)
        self.assertIn("also reproduces on the primary build", rows[0])
        self.assertNotIn("does not reproduce on the primary build", rows[0])

    def test_primary_build_crash_has_no_build_config_row(self) -> None:
        report = self.make_report(
            "heap-buffer-overflow\nWRITE of size 8", report_id="CRASH-PRIMARY",
        )
        with mock.patch.object(
            severity.crash_bundle, "verified_primary_differential", return_value=None
        ):
            result = self.score(report)
            severity.update_report(report / "report.md", result)
        self.assertEqual(result["build_config_field"], "")
        self.assertNotIn("| Build config |", (report / "report.md").read_text())

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

        mixed = self.score(self.make_report(
            "attempting free on address which was not malloc()-ed",
            report_id="CRASH-OUTSIDE", controls="both", trigger="both",
            target_controls=("bytes",),
        ))
        self.assert_metrics(mixed, AV="N", MAT="P", MVC="")
        self.assertEqual(mixed["level"], "High")

        sequence = self.score(self.make_report(
            "attempting free on address which was not malloc()-ed",
            report_id="CRASH-ALIAS", controls="sequence", trigger="sequence",
            target_controls=("bytes",),
        ))
        self.assert_metrics(sequence, AV="L", AT="P")
        self.assertEqual(sequence["level"], "Low")

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
        self.assert_metrics(small_read, VC="N", VI="N", VA="L")
        self.assertNotIn("MVC", small_read.get("metrics", {}))
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
            "decision_version": severity.report_identity.FIND_QUALITY_DECISION_VERSION, "accept": True, "accept_count": 2,
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
            "decision_version": severity.report_identity.FIND_QUALITY_DECISION_VERSION, "accept": True, "accept_count": 2,
            "class": "boundary:new-unmapped-kind",
        }))
        self.assertEqual((self.score(review)["level"], self.score(review)["score"]), ("Needs review", None))
        (review / ".llm-find-quality.json").write_text("[]\n")
        self.assertEqual(self.score(review)["level"], "Needs review")

    def test_validated_class_aliases_preserve_consequence(self) -> None:
        aliases = {
            "boundary:path-traversal": "path_traversal",
            "boundary:path-traversal-read": "arbitrary_file_read",
            "filesystem:path-traversal-write": "arbitrary_file_write",
            "file-write:path-traversal": "arbitrary_file_write",
            "boundary:sandbox-escape": "sandbox_escape",
            "injection:command": "code_execution",
            "memory-safety:allocator-mismatch": "allocator_mismatch",
            "memory-safety:alignment": "bus",
        }
        for label, expected in aliases.items():
            with self.subTest(label=label):
                self.assertEqual(
                    severity._primitive_from_validated_class(label), expected,
                )

        # These labels do not establish one stable impact shape. Keeping the
        # accepted finding unscored avoids manufacturing either high or low
        # impact from a descriptive class alone.
        for ambiguous in (
            "auth:token-confusion", "config:permissive-default", "race:toctou",
        ):
            with self.subTest(ambiguous=ambiguous):
                self.assertEqual(
                    severity._primitive_from_validated_class(ambiguous), "",
                )

        for report_id, finding_class, expected in (
            (
                "FIND-ALLOCATOR",
                "memory-safety:allocator-mismatch",
                "allocator_mismatch",
            ),
            ("FIND-ALIGNMENT", "memory-safety:alignment", "bus"),
        ):
            with self.subTest(finding_class=finding_class):
                report = self.make_report(
                    "Concrete source-reviewed memory-safety consequence.",
                    report_id=report_id, finding=True,
                    extra_fields=(("Primitive", "undefined_behavior"),),
                )
                (report / ".llm-find-quality.json").write_text(json.dumps({
                    "decision_version": severity.report_identity.FIND_QUALITY_DECISION_VERSION,
                    "accept": True,
                    "accept_count": 2,
                    "class": finding_class,
                }))
                scored = self.score(report)
                self.assertEqual(scored["primitive_key"], expected)
                self.assertIsNotNone(scored["score"])
                if expected == "allocator_mismatch":
                    self.assert_metrics(scored, VC="N", VI="N", VA="H")

    def test_disclosed_content_reaches_the_scorer_from_the_report(self) -> None:
        """report -> extract_report_fields -> scorer, not a hand-built dict.

        The unit test for the modifier passed while the field never left the
        parser: `disclosed content` was absent from _FIELD_KEYS, so the scorer
        saw an empty value on every real report and the modifier was dead.
        """
        self.assertIn(
            "disclosed_content",
            severity.extract_report_fields(
                "| Field | Value |\n| Disclosed content | same-context |\n",
            ),
        )
        scored = {}
        for reproduction in ("", "5/5"):
            for value in ("cross-principal", "same-context", "fixed-or-zero"):
                report_dir = self.make_report(
                    "uninitialized read disclosed to the caller",
                    report_id=f"FIND-disc-{reproduction or 'unproven'}-{value}",
                    finding=True,
                    reproduction=reproduction,
                    extra_fields=[("Primitive", "info_leak"),
                                  ("Disclosed content", value)],
                )
                scored[(reproduction, value)] = self.score(report_dir)

        # Source-only findings are E:U. The modifier moves caller-local or
        # fixed contents from Medium to Low despite info_leak's VA:L row.
        for value in ("same-context", "fixed-or-zero"):
            self.assertEqual(
                (scored[("", value)]["level"], scored[("", value)]["score"]),
                ("Low", 2.7),
            )
        self.assertEqual(
            (scored[("", "cross-principal")]["level"],
             scored[("", "cross-principal")]["score"]),
            ("Medium", 6.7),
        )

        # A reproducing disclosure is E:P. VA:L keeps the modified score in
        # Medium, while a cross-principal disclosure remains High.
        for value in ("same-context", "fixed-or-zero"):
            self.assertEqual(
                (scored[("5/5", value)]["level"],
                 scored[("5/5", value)]["score"]),
                ("Medium", 5.5),
            )
        self.assertEqual(
            (scored[("5/5", "cross-principal")]["level"],
             scored[("5/5", "cross-principal")]["score"]),
            ("High", 7.8),
        )

        # Base impact stays VC:H; only the Environmental metric moves.
        self.assertEqual(scored[("", "cross-principal")]["metrics"]["VC"], "H")
        self.assertNotIn("MVC", scored[("", "cross-principal")]["cvss"]["vector"])
        self.assertIn("MVC:L", scored[("", "same-context")]["cvss"]["vector"])
        self.assertIn("MVC:N", scored[("", "fixed-or-zero")]["cvss"]["vector"])

        # The scorer surfaces the input it used into the canonical Fields
        # table even when triage materialized it as a bare label.
        surfaced = self.make_report(
            "uninitialized read disclosed to the caller",
            report_id="FIND-disc-surfaced",
            finding=True,
            reproduction="",
            extra_fields=(("Primitive", "info_leak"),),
            extra="\nDisclosed content: same-context\n",
        )
        severity.update_report(surfaced / "report.md", self.score(surfaced))
        self.assertRegex(
            (surfaced / "report.md").read_text(encoding="utf-8"),
            r"(?m)^\|\s*Disclosed content\s*\|\s*same-context\s*\|$",
        )

        # Silence must cost nothing: an unclassified report scores as before.
        unset = self.score(self.make_report(
            "uninitialized read disclosed to the caller",
            report_id="FIND-disc-unset",
            extra_fields=[("Primitive", "info_leak")],
        ))
        self.assertEqual(
            unset["cvss"]["score"],
            scored[("5/5", "cross-principal")]["cvss"]["score"],
        )

    def test_accepted_finding_primitive_tracks_the_quality_version(self) -> None:
        """A quality-version bump must not silently disable the fallback.

        The scorer hardcoded the version string, so bumping it for an unrelated
        prompt change would make every new receipt unreadable exactly when
        field-filling is missing or provider-limited.
        """
        self.assertNotIn("v13-python", Path(severity.__file__).read_text())

    def test_disclosed_content_modifier_units(self) -> None:
        """Each enum value maps to the modifier it claims, DoS untouched."""
        # Every info-disclosure class maps to info_leak (VC:H), so a few bytes
        # of the caller's own prior frame scored exactly like a leaked key: one
        # corpus produced 149 accepted findings and 0 Low. What actually leaked
        # is an Environmental fact; the Base row stays right for the worst case.
        unclassified, _ = severity._cvss4_metrics("info_leak", "library", {}, False)
        self.assertEqual(unclassified["VC"], "H")
        self.assertNotIn("MVC", unclassified)  # silence must not move a score
        for value, expected in (
            ("fixed-or-zero", "N"), ("attacker-derived", "N"),
            ("same-context", "L"),
        ):
            scoped, _ = severity._cvss4_metrics(
                "info_leak", "library", {"disclosed_content": value}, False,
            )
            self.assertEqual(scoped["VC"], "H", value)
            self.assertEqual(scoped["MVC"], expected, value)
        cross, _ = severity._cvss4_metrics(
            "info_leak", "library", {"disclosed_content": "cross-principal"}, False,
        )
        self.assertNotIn("MVC", cross)
        # A DoS-only class has nothing to disclose; the field cannot touch it.
        dos, _ = severity._cvss4_metrics(
            "null_deref", "library", {"disclosed_content": "fixed-or-zero"}, False,
        )
        self.assertNotIn("MVC", dos)

        file_write, _ = severity._cvss4_metrics(
            "arbitrary_file_write", "library", {}, False,
        )
        self.assertEqual(
            (file_write["VC"], file_write["VI"], file_write["VA"]),
            ("N", "H", "L"),
        )
        sandbox, _ = severity._cvss4_metrics(
            "sandbox_escape", "library", {}, False,
        )
        self.assertEqual(
            (sandbox["VC"], sandbox["VI"], sandbox["VA"],
             sandbox["SC"], sandbox["SI"], sandbox["SA"]),
            ("H", "H", "H", "H", "H", "H"),
        )

    def test_new_classes_have_consequence_calibrated_cvss(self) -> None:
        expected = {
            "code_execution": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                9.3, "Critical",
            ),
            "arbitrary_file_read": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
                8.7, "High",
            ),
            "arbitrary_file_write": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N",
                8.8, "High",
            ),
            "sandbox_escape": (
                "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                10.0, "Critical",
            ),
        }
        for primitive, (vector, score, band) in expected.items():
            with self.subTest(primitive=primitive):
                metrics, _ = severity._cvss4_metrics(
                    primitive, "library", {}, False,
                )
                self.assertIsNotNone(metrics)
                self.assertEqual(severity.cvss4.vector(metrics), vector)
                self.assertEqual(severity.cvss4.score(metrics), score)
                self.assertEqual(severity.cvss4.rating(score), band)

        # A sanitizer can prove that an operation was undefined without
        # proving confidentiality, integrity, or availability impact in the
        # unsanitized product. Preserve the class, but do not invent CVSS.
        metrics, notes = severity._cvss4_metrics(
            "undefined_behavior", "library", {}, False,
        )
        self.assertIsNone(metrics)
        self.assertIn("unclassified", notes[0])

    def test_report_cli_is_idempotent_and_batch_writes_json(self) -> None:
        report = self.make_report(
            "heap-use-after-free\nWRITE of size 8",
            report_id="CRASH-CLI-REPORT",
            surface="network — TLS handler",
        )
        severity.validation_receipt.write(
            report, kind="crash", state="reportable",
            attacker_controls=["bytes"],
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
        severity.validation_receipt.write(
            finding, kind="finding", state="reportable",
            attacker_controls=["bytes"],
        )
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(severity.main(["--batch", str(self.root)]), 0)
        self.assertTrue((finding / "severity.json").is_file())

    def test_scored_marker_binds_the_report_it_scored(self) -> None:
        """A report edited after scoring no longer has a current marker.

        Severity comes from the report's reach fields, and later passes rewrite
        reports. Without a content binding a stale score reads as current and
        is published as if the scorer had just produced it.
        """
        finding = self.make_report(
            "heap-buffer-overflow\nREAD of size 8",
            report_id="FIND-SCORE-FRESHNESS",
            finding=True,
            trigger="bytes",
        )
        severity.validation_receipt.write(
            finding, kind="finding", state="reportable",
            attacker_controls=["bytes"],
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(severity.main(["--report", str(finding)]), 0)
        report = finding / "report.md"
        self.assertIsNotNone(
            severity_receipt.read_current(finding, report),
        )
        marker = json.loads((finding / "severity.json").read_text())
        self.assertEqual(
            marker["scorer_version"], severity_receipt.SCORER_DECISION_VERSION,
        )
        self.assertIn("CVSS:4.0/", marker["vector"])
        self.assertEqual(marker["level"], marker["level"].capitalize())

        # The content hash alone cannot detect a scorer-semantics change. A
        # receipt from the preceding scorer must be stale even when its report
        # and rendered severity still agree byte-for-byte.
        marker["scorer_version"] = "severity-v1-caller-only-set-difference"
        (finding / "severity.json").write_text(
            json.dumps(marker), encoding="utf-8",
        )
        self.assertIsNone(severity_receipt.read_current(finding, report))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(severity.main(["--report", str(finding)]), 0)
        self.assertIsNotNone(severity_receipt.read_current(finding, report))

        # Re-scoring is idempotent: rewriting the Severity row and rationale
        # must not invalidate the marker the same run just wrote.
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(severity.main(["--report", str(finding)]), 0)
        self.assertIsNotNone(severity_receipt.read_current(finding, report))

        # Generated severity text is excluded from report_sha1 so scoring is
        # idempotent, but the receipt must still describe what readers see.
        replacement = "Low" if marker["level"] != "Low" else "Critical"
        report.write_text(
            report.read_text(encoding="utf-8").replace(
                f"- **Severity**: {marker['level']}",
                f"- **Severity**: {replacement}",
                1,
            ),
            encoding="utf-8",
        )
        self.assertIsNone(severity_receipt.read_current(finding, report))
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(severity.main(["--report", str(finding)]), 0)
        self.assertIsNotNone(severity_receipt.read_current(finding, report))

        # A changed scoring input does invalidate it.
        report.write_text(
            report.read_text(encoding="utf-8").replace(
                "| Trigger source | bytes |",
                "| Trigger source | call-sequence |",
            ),
            encoding="utf-8",
        )
        self.assertIsNone(severity_receipt.read_current(finding, report))

        # So does a scorer whose semantics have moved on. Re-validate first:
        # the edit invalidated the publication receipt too, and an unvalidated
        # report is cleared rather than scored.
        severity.validation_receipt.write(
            finding, kind="finding", state="reportable",
            attacker_controls=["bytes"],
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(severity.main(["--report", str(finding)]), 0)
        self.assertIsNotNone(severity_receipt.read_current(finding, report))
        stale = json.loads((finding / "severity.json").read_text())
        stale["scorer_version"] = "severity-v0-superseded"
        (finding / "severity.json").write_text(json.dumps(stale))
        self.assertIsNone(severity_receipt.read_current(finding, report))

    def test_pooled_harness_check_uses_the_report_target(self) -> None:
        """A pool report must not borrow another target's live session."""
        checkout = self.root / "checkout"
        mine = checkout / "targets" / "mine"
        other = checkout / "targets" / "other"
        mine.mkdir(parents=True)
        other.mkdir(parents=True)

        pool = checkout / "output" / "benchmark" / "run" / "pool"
        crash = pool / "crashes" / "CRASH-POOLED"
        crash.mkdir(parents=True)
        (pool / "target.toml").write_text(
            'target = "mine"\n', encoding="utf-8",
        )

        # This is the unrelated session find_session_dir used to discover by
        # scanning the checkout's output tree from a sessionless pool.
        foreign = checkout / "output" / "other" / "codex" / "results"
        foreign.mkdir(parents=True)
        (checkout / "output" / "other" / "target.toml").write_text(
            'target = "other"\n', encoding="utf-8",
        )
        (foreign / ".session-env").write_text(
            f"TARGET_ROOT={other}\n", encoding="utf-8",
        )

        report = crash / "report.md"
        report.write_text("# pooled crash\n", encoding="utf-8")
        (crash / "sanitizer.txt").write_text(
            "ERROR: AddressSanitizer: heap-use-after-free\n"
            "    #0 driver harness.c:13\n"
            f"    #1 target_free {mine / 'src.c'}:27\n",
            encoding="utf-8",
        )

        self.assertEqual(severity.tc.find_session_dir(crash), foreign.resolve())
        self.assertEqual(
            Path(severity._target_root_for_report(crash)),
            mine.resolve(),
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            rc = severity.main([
                "--report", str(crash), "--harness-rooted-check",
            ])
        self.assertEqual(rc, 1)
        self.assertEqual(output.getvalue().strip(), "0")

        # A live result remains bound to the exact checkout in its own session,
        # even when a same-slug source tree exists under the harness checkout.
        live_root = self.root / "external-mine"
        live_root.mkdir()
        live = (
            checkout / "output" / "mine" / "codex" / "results"
            / "crashes" / "CRASH-LIVE"
        )
        live.mkdir(parents=True)
        (live.parents[1] / ".session-env").write_text(
            f"TARGET_ROOT={live_root}\n", encoding="utf-8",
        )
        self.assertEqual(
            Path(severity._target_root_for_report(live)),
            live_root.resolve(),
        )

    def test_report_cli_does_not_score_pending_evidence(self) -> None:
        finding = self.make_report(
            "possible path traversal",
            report_id="FIND-PENDING-SCORE",
            finding=True,
            extra_fields=(("Primitive", "path_traversal"),),
        )
        severity.validation_receipt.write(
            finding, kind="finding", state="pending",
            attacker_controls=["bytes"],
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                severity.main(["--report", str(finding), "--json"]), 0,
            )
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["severity"]["level"], "Unknown")
        self.assertFalse((finding / "severity.json").exists())

    def test_clearing_an_unrated_report_twice_changes_nothing(self) -> None:
        """An unrated artifact is re-examined on every triage pass.

        `_strip_auto_sections` drops the bullet the clear writes, so a blind
        rewrite re-inserts it one line lower each pass and the report grows
        without end — while the content-addressed receipt is rebound to each
        new form.
        """
        for report_id, body in (
            ("FIND-CLEAR-BULLET",
             "# Issue\n\n## Classification\n\n"
             "- **Severity**: High (CVSS-BT 4.0: 8.9)\n"),
            ("FIND-CLEAR-BARE", "# Issue\n\nBoundary: network\n"),
        ):
            with self.subTest(report_id=report_id):
                report_dir = self.root / "findings" / report_id
                report_dir.mkdir(parents=True)
                report = report_dir / "report.md"
                report.write_text(body, encoding="utf-8")
                severity.clear_report_severity(
                    report, report_dir, "Not a security report",
                )
                once = report.read_text(encoding="utf-8")
                severity.clear_report_severity(
                    report, report_dir, "Not a security report",
                )
                self.assertEqual(report.read_text(encoding="utf-8"), once)
                self.assertIn("Not a security report", once)

    def test_claimed_leak_cannot_restore_read_confidentiality(self) -> None:
        """An invalid read proves a fault, not that its value escapes.

        `disclosed_content` is authored in the report, so it may only lower.
        Letting it raise would hand every fluent read claim back the impact
        the class rows were changed to stop assuming.
        """
        report_dir = self.make_report(
            "heap-buffer-overflow\nREAD of size 64",
            report_id="CRASH-LEAK",
            extra_fields=(("Disclosed content", "cross-principal"),),
        )
        claimed = self.score(report_dir)
        self.assert_metrics(claimed, VC="N", VI="N", VA="L")
        self.assertNotIn("MVC", claimed.get("metrics", {}))
        self.assertEqual(claimed["level"], "Medium")

    def test_not_reportable_defect_receives_no_numeric_rating(self) -> None:
        finding = self.make_report(
            "heap-buffer-overflow\nWRITE of size 8",
            report_id="FIND-NOT-REPORTABLE",
            finding=True,
        )
        severity.validation_receipt.write(
            finding, kind="finding", state="reportable",
            attacker_controls=["bytes"],
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(severity.main(["--report", str(finding)]), 0)
        self.assertTrue((finding / "severity.json").is_file())
        severity.validation_receipt.write(
            finding, kind="finding", state="not-reportable",
            attacker_controls=["bytes"],
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                severity.main(["--report", str(finding), "--json"]), 0,
            )
        payload = json.loads(output.getvalue())["severity"]
        # Never "Low": that band is a security report with a small impact, and
        # a reader cannot tell the two apart once they share a word.
        self.assertEqual(payload["level"], "Not a security report")
        self.assertIsNone(payload["score"])
        self.assertFalse((finding / "severity.json").exists())
        report = (finding / "report.md").read_text(encoding="utf-8")
        self.assertIn("Not a security report", report)
        self.assertNotIn("## Severity rationale", report)
        self.assertIsNotNone(
            severity.validation_receipt.read_current(finding),
        )

    def test_verified_boundary_fact_overrides_reproducer_carrier(self) -> None:
        crash = self.make_report(
            "heap-buffer-overflow\nWRITE of size 8",
            report_id="CRASH-CARRIER-BOUNDARY",
            surface="cli — shipped command-line reproducer",
        )
        severity.validation_receipt.write(
            crash, kind="crash", state="reportable",
            attacker_controls=["bytes"],
            review_facts={
                "vulnerable_boundary_surface": "file-format",
                "reproducer_carrier": "cli",
            },
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                severity.main(["--report", str(crash), "--json"]), 0,
            )
        scored = json.loads(output.getvalue())["severity"]
        self.assertEqual(scored["fields_used"]["surface"], "file-format")
        self.assertEqual(scored["surface_label"], "file")
        self.assert_metrics(scored, AV="N", UI="N")

    def test_unverified_boundary_prose_cannot_override_surface(self) -> None:
        crash = self.make_report(
            "heap-buffer-overflow\nWRITE of size 8",
            report_id="CRASH-UNVERIFIED-BOUNDARY",
            surface="cli — shipped command-line reproducer",
            extra=(
                "The narrative claims Surface: file-format, but no source "
                "review established that boundary."
            ),
        )
        severity.validation_receipt.write(
            crash, kind="crash", state="reportable",
            attacker_controls=["bytes"],
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(
                severity.main(["--report", str(crash), "--json"]), 0,
            )
        scored = json.loads(output.getvalue())["severity"]
        self.assertEqual(scored["surface_label"], "cli_production")
        self.assert_metrics(scored, AV="L", UI="P")

    def test_unknown_runtime_class_does_not_claim_narrative_authority(self) -> None:
        report = self.make_report(
            "The narrative mentions a heap-buffer-overflow.",
            report_id="FIND-UNKNOWN-DIAGNOSTIC",
            finding=True,
            extra_fields=(("Primitive", "path_traversal"),),
        )
        result = severity.compute_severity(
            (report / "report.md").read_text(encoding="utf-8"),
            report_dir=report,
            sanitizer_text="ERROR: HWAddressSanitizer: tag-mismatch\n",
        )
        self.assertEqual(result["primitive_key"], "path_traversal")

    # ── exploit maturity ───────────────────────────────────────────────

    def test_filed_finding_without_evidence_is_unproven_not_worst_case(self) -> None:
        """CVSS scores an undefined E as Attacked. A recon lead with no
        reproducer must not tie a bug with mature in-the-wild exploitation."""
        report = (self.root / "findings" / "FIND-RECON")
        report.mkdir(parents=True)
        (report / "report.md").write_text(
            "# unbounded allocation from a header field\n\n"
            "| Field | Value |\n|:--|:--|\n| Class | dos |\n"
            "| Primitive | dos_amplification |\n"
            "| File | `libavformat/demux.c` |\n\n"
            "## Sanitizer evidence\n\nnot yet attempted\n",
            encoding="utf-8",
        )
        result = self.score(report)
        self.assert_metrics(result, E="U")

        # A bare crash dir handed straight to bin/severity is still unknown
        # input — the scorer must not invent a threat metric for it.
        crash = self.root / "workspace" / "CRASH-RAW"
        crash.mkdir(parents=True)
        (crash / "report.md").write_text(
            "# raw crash\n\nheap-buffer-overflow in demux\n", encoding="utf-8",
        )
        self.assertNotIn("E", self.score(crash).get("metrics", {}))

    # ── declared trigger components ────────────────────────────────────

    def test_taxonomy_caller_controls_preserves_attacker_byte_path(self) -> None:
        """`Trigger source: bytes` + `Caller controls: call-sequence` states
        what a crash states as `Trigger source: both`. Attacker-controlled
        bytes keep the public surface vector; the local ordering is MAT:P."""
        report = self.make_report(
            "options are dropped on a reused context, leaving XXE enabled",
            report_id="FIND-TOKENCTL", finding=True, trigger="bytes",
            controls="call-sequence", target_controls=("bytes",),
            extra_fields=(("Primitive", "xxe"),),
        )
        result = self.score(report)
        self.assert_metrics(result, AV="N", MAT="P", MVC="")

    def test_placeholder_cell_does_not_shadow_an_inferred_bare_label(self) -> None:
        """Triage writes inferred reach fields as bare labels below a table
        whose row is still a generated placeholder. The placeholder must not
        win first-place extraction, or the inferred value never scores and
        never reaches the table."""
        report_dir = self.make_report(
            "parser reads past the record while decoding attacker bytes",
            report_id="CRASH-PLACEHOLDER", trigger="bytes",
            extra_fields=(("Boundary", "?"), ("Parameter control", "—")),
            extra="\nBoundary: caller-supplied document\n"
                  "Parameter control: direct\n",
        )
        report = report_dir / "report.md"
        fields = severity.extract_report_fields(
            report.read_text(encoding="utf-8"), report_dir,
        )
        self.assertEqual(fields["boundary"], "caller-supplied document")
        self.assertEqual(fields["parameter_control"], "direct")
        severity.update_report(report, self.score(report_dir))
        synchronized = report.read_text(encoding="utf-8")
        self.assertRegex(
            synchronized,
            r"(?m)^\|\s*Boundary\s*\|\s*caller-supplied document\s*\|",
        )
        self.assertRegex(
            synchronized, r"(?m)^\|\s*Parameter control\s*\|\s*direct\s*\|",
        )

    def test_an_ordinary_table_is_not_mistaken_for_the_fields_table(self) -> None:
        # The Fields table is identified by its `| Field | Value |` header,
        # not by row labels: every label distinctive enough to name the table
        # (Strategy, Class, File) is also a plausible first column of an
        # ordinary comparison table. Matching one appended reach rows into
        # that table and left the report with no real Fields grid.
        # A report whose only table is that comparison — no `## Fields` grid
        # ahead of it to find first.
        report_dir = self.make_report(
            "parser reads past the record while decoding attacker bytes",
            report_id="FIND-CMPTABLE", finding=True, trigger="bytes",
            extra_fields=(("Primitive", "heap_read_small"),),
        )
        report = report_dir / "report.md"
        report.write_text(
            "# FIND-CMPTABLE: strategy comparison\n\n"
            "Primitive: heap_read_small\nSurface: library-api\n"
            "Trigger source: bytes\n\n## Root Cause\n\n"
            "parser reads past the record while decoding attacker bytes\n\n"
            "| Strategy | Result |\n|:---------|:-------|\n"
            "| S1 | missed |\n| S3 | found |\n",
            encoding="utf-8",
        )
        self.assertEqual(
            severity._find_fields_table_end(
                report.read_text(encoding="utf-8").splitlines()),
            -1,
        )
        severity.update_report(report, self.score(report_dir))
        text = report.read_text(encoding="utf-8")
        # The comparison table keeps exactly its own rows: separator, S1, S3.
        block = list(itertools.takewhile(
            lambda line: line.startswith("|"),
            text.split("| Strategy | Result |\n")[1].splitlines(),
        ))
        self.assertEqual(len(block), 3, block)
        # The score went into a real Fields grid instead.
        self.assertRegex(text, r"(?m)^\|\s*Field\s*\|\s*Value\s*\|")
        self.assertRegex(text, r"(?m)^\|\s*Severity\s*\|\s*\w+\s*\(CVSS")
        self.assertRegex(text, r"(?m)^\|\s*Primitive\s*\|\s*heap_read_small\s*\|")

    def test_writer_and_renderer_agree_on_the_fields_table(self) -> None:
        # The scorer appends rows to the Fields table and render-md draws the
        # grid; both must mean the same table. Holding two lookalike regexes
        # is how they came to disagree over `| : | : |` — a separator the
        # scorer accepted and the renderer rejected, so the scorer wrote rows
        # into a table that then rendered as no grid at all.
        malformed = "| Field | Value |\n| : | : |\n| Boundary | bytes |\n"
        self.assertEqual(severity._find_fields_table_end(malformed.splitlines()), -1)
        # Every GFM separator the renderer accepts, the scorer accepts too —
        # and both read it from one predicate, so they cannot drift apart.
        for separator in ("|:-|:-|", "| --- | --- |", "| :--- | ---: |",
                          "|:-:|:-:|", "| ---------- | ----- |"):
            document = f"| Field | Value |\n{separator}\n| Boundary | bytes |\n"
            self.assertEqual(
                severity._find_fields_table_end(document.splitlines()), 2, separator,
            )
            self.assertTrue(
                severity.report_identity.is_fields_table_header(
                    *document.splitlines()[:2]),
                separator,
            )

    def test_prose_caller_controls_stays_prose(self) -> None:
        report = self.make_report(
            "parser reads past the record while decoding attacker bytes",
            report_id="FIND-PROSECTL", finding=True, trigger="bytes",
            controls="the document bytes, and the call sequence the app uses",
            target_controls=("bytes",),
            extra_fields=(("Primitive", "xxe"),),
        )
        result = self.score(report)
        self.assert_metrics(result, AV="N")


if __name__ == "__main__":
    unittest.main()
