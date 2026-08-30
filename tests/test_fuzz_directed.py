#!/usr/bin/env python3
"""tests/test_fuzz_directed.py — S4 boundary-directed fuzzing.

Four invariants, in the order they decide whether a campaign was worth
running:

1. *Only the right APIs get a harness.* The gate admits a published symbol
   whose declaration carries a parameter shape the declared threat model can
   supply and that nothing already drives, and rejects everything else with
   the reason it failed.
2. *No fake targets.* A harness that fabricates state, reaches past the public
   headers, or hand-declares a symbol is refused before it is ever built.
3. *The shared build is untouched.* A harness cannot be built from inside the
   checkout, because that would stale the build for every other backend.
4. *The budget comes back.* A campaign stops when its harnesses stop paying,
   and never starts a slice it cannot finish inside the budget it was given.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))
import fuzz_campaign  # noqa: E402
import fuzz_harness  # noqa: E402
import target_config  # noqa: E402


def config_for(root: Path, controls: "list[str]") -> target_config.Config:
    config = target_config.Config()
    config.target_root = str(root)
    config.results_dir = str(root.parent / "results")
    config.attacker_controls = list(controls)
    config.sanitizers_enabled = ["asan"]
    return config


class AdmissionGateTests(unittest.TestCase):
    """A fuzz target is only worth building where an attacker can reach it."""

    EXPORTED = {"vl_parse", "vl_load_file", "vl_helper", "vl_close"}
    DECLS = {
        "vl_parse": "int vl_parse(struct vl_ctx *c, const unsigned char *data, size_t len);",
        "vl_load_file": "int vl_load_file(const char *path);",
        "vl_helper": "int vl_helper(int x);",
        "vl_close": "void vl_close(struct vl_ctx *c);",
    }

    def test_bytes_reach_a_buffer_but_not_a_path_or_an_integer(self) -> None:
        admitted = {
            symbol for symbol in self.EXPORTED
            if fuzz_harness.gate(
                symbol, self.DECLS[symbol], self.EXPORTED, ["bytes"]).admitted
        }
        self.assertEqual(admitted, {"vl_parse"})

    def test_declaring_fs_state_admits_the_path_taker(self) -> None:
        verdict = fuzz_harness.gate(
            "vl_load_file", self.DECLS["vl_load_file"], self.EXPORTED,
            ["bytes", "fs-state"])
        self.assertTrue(verdict.admitted)
        self.assertEqual(verdict.controls, ["fs-state"])

    def test_call_sequence_admits_a_handle_taker_bytes_cannot_reach(self) -> None:
        self.assertFalse(fuzz_harness.gate(
            "vl_close", self.DECLS["vl_close"], self.EXPORTED, ["bytes"]).admitted)
        self.assertTrue(fuzz_harness.gate(
            "vl_close", self.DECLS["vl_close"], self.EXPORTED,
            ["call-sequence"]).admitted)

    def test_an_unexported_symbol_is_refused_however_good_its_signature(self) -> None:
        verdict = fuzz_harness.gate(
            "vl_parse", self.DECLS["vl_parse"], set(), ["bytes"])
        self.assertFalse(verdict.admitted)
        self.assertIn("not exported", verdict.blockers[0])

    def test_a_covered_symbol_routes_to_improvement_not_a_second_harness(self) -> None:
        verdict = fuzz_harness.gate(
            "vl_parse", self.DECLS["vl_parse"], self.EXPORTED, ["bytes"],
            covered_by="fuzz/parse_fuzzer.c")
        self.assertFalse(verdict.admitted)
        self.assertIn("improve that harness", verdict.blockers[0])

    def test_every_failing_fact_is_reported_not_just_the_first(self) -> None:
        verdict = fuzz_harness.gate("vl_helper", self.DECLS["vl_helper"], set(),
                                    ["bytes"], covered_by="fuzz/a.c")
        self.assertEqual(len(verdict.blockers), 3)

    def test_a_path_parameter_is_not_mistaken_for_a_buffer(self) -> None:
        # The pointer/integer adjacency rule is the whole difference between
        # these two, and reading the second as a buffer would admit every
        # file-writing API on a bytes-only threat model.
        buffer_taker = "xmlDoc *xmlReadMemory(const char *buf, int size, const char *URL);"
        path_taker = "int htmlSaveFileFormat(const char *filename, xmlDoc *cur, int format);"
        self.assertIn(fuzz_harness.SHAPE_BUFFER, fuzz_harness.input_shapes(buffer_taker))
        self.assertNotIn(fuzz_harness.SHAPE_BUFFER, fuzz_harness.input_shapes(path_taker))

    def test_an_unrelated_adjacent_string_and_int_are_not_a_buffer(self) -> None:
        self.assertNotIn(
            fuzz_harness.SHAPE_BUFFER,
            fuzz_harness.input_shapes(
                "xmlDoc *xmlReadDoc(const char *encoding, int options);"))

    def test_an_opaque_handle_and_integer_are_not_a_buffer(self) -> None:
        for declaration in (
            "void *api_context(api_context *ctx, int nBytes);",
            "int api_step(api_backup *p, int nPage);",
            "const char *api_name(api_stmt *stmt, int N);",
            "int api_scan(api_byte_context *ctx, int nBytes);",
            "int api_decode(charset_context *ctx, int len);",
            "int api_wide(wchar_t *text, int length);",
        ):
            self.assertNotIn(fuzz_harness.SHAPE_BUFFER,
                             fuzz_harness.input_shapes(declaration), declaration)

    def test_a_void_buffer_with_single_letter_length_is_a_buffer(self) -> None:
        declaration = "int api_read(api_blob *blob, void *Z, int N, int offset);"
        self.assertIn(fuzz_harness.SHAPE_BUFFER,
                      fuzz_harness.input_shapes(declaration))

    def test_a_typedef_byte_buffer_stays_admitted(self) -> None:
        """Every library spells its byte buffer differently."""
        for declaration in (
            "int api_parse(const xmlChar *ptr, int len);",
            "int api_pack(Bytef *dest, uLong destLen);",
            "int api_read(const guchar *p, gsize n_bytes);",
            "int api_scan(const unsigned char *b, size_t nbytes);",
            "int api_take(const char *b, int cbSize);",
        ):
            self.assertIn(fuzz_harness.SHAPE_BUFFER,
                          fuzz_harness.input_shapes(declaration), declaration)

    def test_a_structurally_named_custom_byte_typedef_stays_admitted(self) -> None:
        for declaration in (
            "int api_parse(const my_byte_t *ptr, int len);",
            "int api_unpack(packet_octet *src, size_t length);",
            "int api_read(const PRODUCT_BYTE_T *src, size_t length);",
            "int api_decode(CustomOctetT *src, size_t length);",
        ):
            self.assertIn(fuzz_harness.SHAPE_BUFFER,
                          fuzz_harness.input_shapes(declaration), declaration)

    def test_a_handle_beside_an_unrelated_integer_is_not_a_buffer(self) -> None:
        for declaration in (
            "int api_x(api_stmt *stmt, int nLen);",
            "int api_y(api_stmt *stmt, int span);",
            "int api_z(api_stmt *stmt, int iOffset);",
        ):
            self.assertNotIn(fuzz_harness.SHAPE_BUFFER,
                             fuzz_harness.input_shapes(declaration), declaration)


    def test_an_element_count_is_not_a_byte_length(self) -> None:
        # A pointer to a wider element measured by an adjacent integer counts
        # elements, not bytes: a harness handed the mutator's length would be
        # claiming an array it never allocated, so every crash it reached
        # would be its own miscount.
        # The whole shape set, because a counted array that merely stops
        # being a buffer would fall through to the handle rule and be admitted
        # under a call-sequence threat model instead.
        for counted in ("int vl_set_levels(const double *levels, int count);",
                        "int vl_set_flags(const unsigned *flags, int count);"):
            self.assertEqual(fuzz_harness.input_shapes(counted), set(), counted)
        # Every spelling of a byte stays a buffer, including the one that
        # shares a keyword with the rejected types.
        for measured in ("int vl_write(const unsigned char *data, int count);",
                         "int vl_put(const char *data, size_t len);"):
            self.assertIn(fuzz_harness.SHAPE_BUFFER,
                          fuzz_harness.input_shapes(measured), measured)

    def test_an_array_of_pointers_is_not_a_single_buffer(self) -> None:
        # The qualifier between the stars is what hid this shape: fuzzing it
        # means fabricating pointers out of mutator bytes.
        declaration = "int vl_set_names(const char *const *names, int count);"
        self.assertEqual(fuzz_harness.input_shapes(declaration), set())

    def test_a_mutable_byte_buffer_with_a_named_typedef_length_is_input(self) -> None:
        declaration = (
            "int api_deserialize(ctx *db, unsigned char *data, "
            "api_int64 size, api_int64 capacity, unsigned flags);"
        )
        self.assertIn(fuzz_harness.SHAPE_BUFFER,
                      fuzz_harness.input_shapes(declaration))


class DeclarationReadingTests(unittest.TestCase):
    """Every one of these was found by running the gate on a real target.

    A header that does not parse is not a quiet degradation: the symbol gets
    no declaration, so it is dropped before the gate ever sees it and the
    target reports a surface it does not have.
    """

    def index(self, header: str) -> "dict[str, str]":
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "api.h").write_text(header, encoding="utf-8")
            return fuzz_harness.declaration_index(root, [str(root)])

    def test_a_macro_wrapped_return_type_still_yields_the_symbol(self) -> None:
        # `CJSON_PUBLIC(cJSON *) cJSON_Parse(...)` is how a C library spells a
        # public entry point. Anchoring on the first `name(` finds the macro,
        # not the function; cjson exposed 1 of 78 symbols until this parsed.
        index = self.index(
            "CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value);\n"
            "CJSON_PUBLIC(void) cJSON_Delete(cJSON *item);\n")
        self.assertEqual(sorted(index), ["cJSON_Delete", "cJSON_Parse"])
        self.assertEqual(
            index["cJSON_Parse"],
            "CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value);")

    def test_a_doc_comment_stays_out_of_the_declaration(self) -> None:
        # The shape classifier reads this text. With comments left in, a
        # paragraph of prose above a declaration became part of it.
        index = self.index(
            "/* Supply a block of JSON, and this returns a cJSON object\n"
            "   you can interrogate. Free it with cJSON_Delete(item). */\n"
            "CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value);\n")
        self.assertEqual(
            index["cJSON_Parse"],
            "CJSON_PUBLIC(cJSON *) cJSON_Parse(const char *value);")

    def test_a_definition_in_a_header_is_not_a_declaration(self) -> None:
        index = self.index(
            "static inline int api_helper(int x) { return x + 1; }\n"
            "extern int api_parse(const char *b, size_t n);\n")
        self.assertEqual(sorted(index), ["api_parse"])

    def test_a_function_like_macro_is_not_a_declaration(self) -> None:
        index = self.index(
            "#define API_CHECK(cond) do { if (!(cond)) return -1; } while (0)\n"
            "int api_parse(const char *b, size_t n);\n")
        self.assertEqual(sorted(index), ["api_parse"])

    def test_a_public_header_template_is_indexed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "api.h.in").write_text(
                "int api_parse(const char *data, size_t size);\n",
                encoding="utf-8",
            )
            index = fuzz_harness.declaration_index(root, [str(root)])
        self.assertIn("api_parse", index)


class LocalCallerExampleTests(unittest.TestCase):
    """Harness construction starts from bounded, target-local usage."""

    def test_exact_symbol_examples_are_bounded_and_source_anchored(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for directory in ("tests", "examples", "samples"):
                (root / directory).mkdir()
            (root / "tests" / "first.c").write_text(
                "void check(const unsigned char *data, unsigned long size) {\n"
                "  sample_parse(data, size);\n}\n",
                encoding="utf-8",
            )
            (root / "examples" / "second.cc").write_text(
                "void check_more(const char *data) { sample_parse(data, 1); }\n",
                encoding="utf-8",
            )
            (root / "samples" / "third.c").write_text(
                "void another(const char *data) { sample_parse(data, 1); }\n",
                encoding="utf-8",
            )
            (root / "tests" / "noise.c").write_text(
                "/* sample_parse(data, size); */\n"
                "void check_other(void) { sample_parser(); }\n",
                encoding="utf-8",
            )

            found = fuzz_harness.local_caller_examples(
                root, "sample_parse", limit=2)

        self.assertEqual(len(found), 2)
        self.assertEqual(
            [(entry.path, entry.line) for entry in found],
            [("examples/second.cc", 1), ("samples/third.c", 1)],
        )

    def test_an_existing_fuzz_harness_outranks_a_test_fixture(self) -> None:
        """Walk order is alphabetical noise; the fuzz dir teaches the most."""
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            for directory in ("fuzz", "tests"):
                (root / directory).mkdir()
            # Sorts after "fuzz/..." only because of the rank, not the name.
            (root / "tests" / "aaa_first.c").write_text(
                "void t(const char *d) { sample_parse(d, 1); }\n",
                encoding="utf-8")
            (root / "fuzz" / "zzz_last.c").write_text(
                "void f(const char *d) { sample_parse(d, 1); }\n",
                encoding="utf-8")

            found = fuzz_harness.local_caller_examples(
                root, "sample_parse", limit=1)

        self.assertEqual([entry.path for entry in found], ["fuzz/zzz_last.c"])

    def test_missing_examples_fail_open(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            root.mkdir(exist_ok=True)
            self.assertEqual(
                fuzz_harness.local_caller_examples(root, "sample_parse"), [])

    def test_a_parent_directory_named_tests_does_not_expand_the_scope(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "tests" / "project"
            (root / "src").mkdir(parents=True)
            (root / "src" / "internal.c").write_text(
                "void internal(const char *data) { sample_parse(data, 1); }\n",
                encoding="utf-8",
            )
            self.assertEqual(
                fuzz_harness.local_caller_examples(root, "sample_parse"), [])


class HarnessInputAgreementTests(unittest.TestCase):
    """Whether the configured library and includes describe the same thing.

    `setup-target` proves the CLI route by launching the program, but historically
    proved the library route with `is_file()` — which a helper archive beside the
    product passes just as well. Symbol/header overlap makes that ambiguity
    visible without treating the heuristic as authority to replace the config.
    """

    def config(self, library: str, includes: "list[str]") -> "tuple[object, Path]":
        root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, root, True)
        (root / "build-asan").mkdir(parents=True)
        (root / "api").mkdir()
        (root / "api" / "pub.h").write_text(
            "int app_parse(const char *data, unsigned long len);\n", encoding="utf-8",
        )
        configuration = target_config.Config(
            slug="demo", target_root=str(root),
            asan_lib=library, includes=includes,
            sanitizers_enabled=["asan"],
        )
        return configuration, root

    def test_a_library_no_configured_header_describes_is_reported(self) -> None:
        configuration, root = self.config("build-asan/libhelper.a", ["api"])
        (root / "build-asan" / "libhelper.a").write_bytes(b"!<arch>\n")
        with mock.patch.object(
            fuzz_harness.native_symbols, "defined_symbols",
            return_value={"helper_internal_thing"},
        ):
            self.assertEqual(
                fuzz_harness.declared_exports(configuration, "asan"), (1, 0),
            )

    def test_a_matching_pair_reports_the_overlap(self) -> None:
        configuration, root = self.config("build-asan/libdemo.a", ["api"])
        (root / "build-asan" / "libdemo.a").write_bytes(b"!<arch>\n")
        with mock.patch.object(
            fuzz_harness.native_symbols, "defined_symbols",
            return_value={"app_parse", "app_private"},
        ):
            self.assertEqual(
                fuzz_harness.declared_exports(configuration, "asan"), (2, 1),
            )

    def test_includes_that_resolve_to_no_header_are_reported(self) -> None:
        # The shipped shape: `includes` names the build directory, which exists
        # and holds no header.
        configuration, root = self.config("build-asan/libdemo.a", ["build-asan"])
        (root / "build-asan" / "libdemo.a").write_bytes(b"!<arch>\n")
        with mock.patch.object(
            fuzz_harness.native_symbols, "defined_symbols",
            return_value={"app_parse"},
        ):
            self.assertEqual(
                fuzz_harness.declared_exports(configuration, "asan"), (1, 0),
            )

    def test_a_missing_configured_include_never_falls_back_to_the_whole_tree(self) -> None:
        configuration, root = self.config(
            "build-asan/libdemo.a", ["missing/include"],
        )
        (root / "build-asan" / "libdemo.a").write_bytes(b"!<arch>\n")
        with mock.patch.object(
            fuzz_harness.native_symbols, "defined_symbols",
            return_value={"app_parse"},
        ):
            self.assertEqual(
                fuzz_harness.declared_exports(configuration, "asan"), (1, 0),
            )

    def test_a_width_suffixed_export_matches_its_public_declaration(self) -> None:
        configuration, root = self.config("build-asan/libdemo.a", ["api"])
        (root / "build-asan" / "libdemo.a").write_bytes(b"!<arch>\n")
        with mock.patch.object(
            fuzz_harness.native_symbols, "defined_symbols",
            return_value={"app_parse_8"},
        ):
            self.assertEqual(
                fuzz_harness.declared_exports(configuration, "asan"), (1, 1),
            )

    def test_a_cpp_export_matches_its_source_level_declaration(self) -> None:
        configuration, root = self.config("build-asan/libdemo.a", ["api"])
        (root / "build-asan" / "libdemo.a").write_bytes(b"!<arch>\n")
        with (
            mock.patch.object(
                fuzz_harness.native_symbols, "defined_symbols",
                return_value={"_Z9app_parsePKcm"},
            ),
            mock.patch.object(
                fuzz_harness.symbol_names, "demangle_text",
                return_value="app_parse(char const*, unsigned long)\n",
            ),
        ):
            self.assertEqual(
                fuzz_harness.declared_exports(configuration, "asan"), (1, 1),
            )


class SymbolFamilyTests(unittest.TestCase):
    """A macro-mangled API is still the API."""

    EXPORTED = {"pcre2_compile_8", "pcre2_match_8", "pcre2_code_free_8",
                "other_plain"}

    def test_a_width_suffixed_export_resolves_to_its_bare_spelling(self) -> None:
        aliases = fuzz_harness.suffix_aliases(self.EXPORTED)
        self.assertEqual(aliases["pcre2_compile"], "pcre2_compile_8")
        self.assertNotIn("other_plain", aliases)

    def test_a_harness_calling_the_bare_name_counts_as_driving_the_export(self) -> None:
        # pcre2's own fuzz harness read as driving 0 of 113 symbols, so every
        # already-fuzzed entry point was offered as a fresh candidate.
        driven = fuzz_harness._driven(
            {"pcre2_compile", "pcre2_match", "malloc"}, self.EXPORTED)
        self.assertEqual(driven, {"pcre2_compile_8", "pcre2_match_8"})

    def test_a_library_publishing_both_spellings_keeps_them_distinct(self) -> None:
        aliases = fuzz_harness.suffix_aliases({"api_read", "api_read_8"})
        self.assertEqual(aliases, {})

    def test_a_reserved_identifier_is_not_a_published_api(self) -> None:
        # A static archive has no export list, so `nm` reports every
        # cross-unit helper as global. C reserves the leading underscore for
        # the implementation, which is the library saying so itself.
        verdict = fuzz_harness.gate(
            "_pcre2_strcpy_c8_8", "extern PCRE2_SIZE _pcre2_strcpy_c8(PCRE2_UCHAR *, const char *);",
            {"_pcre2_strcpy_c8_8"}, ["bytes"])
        self.assertFalse(verdict.admitted)
        self.assertIn("reserved identifier", verdict.blockers[0])


class RankingTests(unittest.TestCase):
    """On a large library the reading order is what an agent acts on."""

    def test_a_named_parser_outranks_an_equally_shaped_array_builder(self) -> None:
        # `cJSON_CreateDoubleArray(const double *, int)` is a buffer by shape
        # and an array builder in fact; `cJSON_ParseWithLength` is the parser.
        exported = {"cJSON_ParseWithLength", "cJSON_CreateDoubleArray"}
        config = config_for(Path("/t"), ["bytes"])
        ranked = fuzz_harness.candidates(config, exported, [], {
            "cJSON_ParseWithLength":
                "CJSON_PUBLIC(cJSON *) cJSON_ParseWithLength(const char *value, size_t buffer_length);",
            "cJSON_CreateDoubleArray":
                "CJSON_PUBLIC(cJSON *) cJSON_CreateDoubleArray(const double *numbers, int count);",
        })
        self.assertEqual([c.symbol for c in ranked][0], "cJSON_ParseWithLength")

    def test_the_verb_is_read_from_the_identifier_not_the_file(self) -> None:
        # workqueue's pattern anchors on `\b`, and `_` is a word character, so
        # it cannot see the verb inside `cJSON_ParseWithLength`. The
        # vocabulary is shared; the matching has to be identifier-aware.
        for symbol in ("cJSON_ParseWithLength", "xmlReadMemory",
                       "xml_read_memory", "pcre2_compile_8"):
            with self.subTest(symbol=symbol):
                self.assertTrue(fuzz_harness.consumes_input(symbol))
        for symbol in ("cJSON_CreateDoubleArray", "xmlNewDoc", "api_free"):
            with self.subTest(symbol=symbol):
                self.assertFalse(fuzz_harness.consumes_input(symbol))


class ContractFaithfulnessTests(unittest.TestCase):
    """A harness that reaches the target as no caller could is refused."""

    def build(self, body: str) -> "list[tuple[str, str]]":
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "fuzz_x.c"
            source.write_text(body, encoding="utf-8")
            return fuzz_harness.contract_violations(source)

    def test_forging_a_state_object_from_fuzzer_bytes_is_refused(self) -> None:
        found = self.build(
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            "  struct vl_ctx *c = (struct vl_ctx *)data;\n"
            "  return vl_parse(c, data, size);\n}\n")
        self.assertEqual([name for name, _ in found], ["forged-state"])

    def test_reaching_past_the_public_headers_is_refused(self) -> None:
        found = self.build('#include "../src/internal.h"\nint main(void){return 0;}\n')
        self.assertEqual([name for name, _ in found], ["private-header"])

    def test_hand_declaring_a_target_function_is_refused(self) -> None:
        for declaration in ('extern int vl_secret(const char *s);',
                            'extern "C" int vl_secret(const char *s);'):
            with self.subTest(declaration=declaration):
                self.assertEqual(
                    [name for name, _ in self.build(declaration + "\n")],
                    ["hand-declared-symbol"])

    def test_a_cpp_harness_may_declare_the_fuzzer_entry_points(self) -> None:
        # OSS-Fuzz C++ harnesses spell the entry point exactly this way.
        # Rejecting it would refuse every correct C++ harness.
        for declaration in (
            'extern "C" int LLVMFuzzerTestOneInput(const uint8_t *d, size_t n);',
            'extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv);',
        ):
            with self.subTest(declaration=declaration):
                self.assertEqual(self.build(declaration + "\n"), [])

    def test_an_extern_variable_is_not_a_hand_declared_function(self) -> None:
        self.assertEqual(self.build("extern int vl_global_flag;\n"), [])

    def test_a_faithful_harness_passes(self) -> None:
        self.assertEqual(self.build(
            '#include "vulnlib.h"\n'
            "int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {\n"
            "  struct vl_ctx *c = vl_open(0);\n"
            "  if (!c) return 0;\n"
            "  vl_parse(c, data, size);\n"
            "  vl_close(c);\n"
            "  return 0;\n}\n"), [])

    def test_the_generated_template_is_itself_faithful(self) -> None:
        # The template's own comments describe the shapes the rules reject.
        # If it tripped its own gate, every generated harness would be
        # unbuildable until an agent deleted the guidance explaining why.
        source = ROOT / "bin" / "fuzz"
        namespace: dict = {}
        text = source.read_text(encoding="utf-8")
        start = text.index("TEMPLATE = ")
        end = text.index("\ndef cmd_template")
        exec(compile(text[start:end], "fuzz-template", "exec"), namespace)
        rendered = namespace["TEMPLATE"].format(
            target="a.c:f", hypothesis="H-1", symbol="f",
            declaration="int f(const unsigned char *d, size_t n);",
            controls="bytes", shapes="buffer+length",
            source_usage="tests/sample_usage.c:7")
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "fuzz_f.c"
            path.write_text(rendered, encoding="utf-8")
            self.assertEqual(fuzz_harness.contract_violations(path), [])
        # Both entry points must survive, or an artifact cannot be replayed.
        self.assertIn("LLVMFuzzerTestOneInput", rendered)
        self.assertIn("#ifndef FUZZ_CAMPAIGN_BUILD", rendered)
        for field in (
            "BOUNDARY", "CONTROLS", "DECLARATION", "SOURCE-USAGE",
            "CONSTRUCTOR", "ARG-RELATIONS", "RESOURCE-FLOW", "TEARDOWN",
            "UNRESOLVED",
        ):
            self.assertIn(f"S4-RECEIPT {field}:", rendered)


class HarnessReceiptTests(unittest.TestCase):
    """A receipt preserves source facts without becoming an evidence gate."""

    def test_receipt_fields_and_unresolved_items_are_parsed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            source = Path(raw) / "fuzz_sample.c"
            source.write_text(
                "// S4-RECEIPT BOUNDARY: sample_parse\n"
                "// S4-RECEIPT CONTROLS: bytes\n"
                "// S4-RECEIPT DECLARATION: int sample_parse(const char *, size_t);\n"
                "// S4-RECEIPT SOURCE-USAGE: tests/sample_usage.c:7\n"
                "// S4-RECEIPT CONSTRUCTOR: sample_open — include/sample.h:12\n"
                "// S4-RECEIPT ARG-RELATIONS: length is payload bytes\n"
                "// S4-RECEIPT RESOURCE-FLOW: handle remains caller-owned\n"
                "// S4-RECEIPT TEARDOWN: sample_close — include/sample.h:19\n"
                "// S4-RECEIPT UNRESOLVED: callback-order, optional-state\n",
                encoding="utf-8",
            )
            receipt = fuzz_harness.harness_receipt(source)

        self.assertEqual(receipt.boundary, "sample_parse")
        self.assertEqual(receipt.source_usage, "tests/sample_usage.c:7")
        self.assertEqual(receipt.unresolved, ["callback-order", "optional-state"])
        self.assertEqual(receipt.warnings, [])

    def test_duplicates_warn_and_legacy_sources_remain_compatible(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            duplicate = root / "duplicate.c"
            duplicate.write_text(
                "// S4-RECEIPT BOUNDARY: sample_parse\n"
                "// S4-RECEIPT BOUNDARY: sample_other\n",
                encoding="utf-8",
            )
            legacy = root / "legacy.c"
            legacy.write_text("int LLVMFuzzerTestOneInput(void) { return 0; }\n")
            parsed = fuzz_harness.harness_receipt(duplicate)
            old = fuzz_harness.harness_receipt(legacy)

        self.assertEqual(parsed.boundary, "sample_parse")
        self.assertTrue(any("duplicate BOUNDARY" in item for item in parsed.warnings))
        # Nothing answered the source questions, so every one is unresolved
        # whether or not the author remembered to list it.
        self.assertEqual(parsed.unresolved, [
            "source-usage", "constructor", "argument-relations",
            "resource-flow", "teardown",
        ])
        # A source with no receipt records none, so "has a receipt" is
        # readable straight off the manifest field rather than off a dict of
        # blanks that any consumer would read as grounded.
        self.assertEqual(old.as_dict(), {})
        self.assertEqual(old.boundary, "")
        self.assertEqual(old.unresolved, [])
        self.assertEqual(old.warnings, [])


class BuildIsolationTests(unittest.TestCase):
    """Nothing S4 does may make the shared build look stale to a peer."""

    def test_a_harness_inside_the_checkout_is_refused_with_the_reason(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "src"
            root.mkdir()
            source = root / "fuzz_x.c"
            source.write_text("int main(void){return 0;}\n", encoding="utf-8")
            with self.assertRaises(fuzz_harness.InTreeSource) as caught:
                fuzz_harness.reject_in_tree_source(source, root)
            message = str(caught.exception)
            self.assertIn("source signature", message)
            self.assertIn("RESULTS_DIR", message)

    def test_a_harness_under_results_is_accepted(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "src"
            root.mkdir()
            source = Path(raw) / "results" / "fuzz" / "src" / "fuzz_x.c"
            source.parent.mkdir(parents=True)
            source.write_text("int main(void){return 0;}\n", encoding="utf-8")
            fuzz_harness.reject_in_tree_source(source, root)  # must not raise

    def test_the_sibling_coverage_tree_is_pruned_from_build_freshness(self) -> None:
        # This is the property the whole design rests on: a coverage build
        # sits beside the shared one and cannot change the source signature
        # that decides whether the shared build is fresh.
        name = f"build-asan{fuzz_harness.COVERAGE_TREE_SUFFIX}"
        self.assertTrue(target_config._freshness_pruned(name))
        self.assertTrue(target_config._path_is_pruned(f"{name}/lib/libx.a"))

    def test_the_sibling_tree_takes_its_own_build_lease(self) -> None:
        # Same directory, two names, two locks — so building the coverage tree
        # never blocks a runner holding the plain one.
        import build_lease
        plain = build_lease.lease_path("/t", "build-asan")
        sibling = build_lease.lease_path(
            "/t", f"build-asan{fuzz_harness.COVERAGE_TREE_SUFFIX}")
        self.assertNotEqual(plain, sibling)

    def test_the_campaign_build_defines_out_the_replay_entry_point(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            config = config_for(Path(raw), ["bytes"])
            config.link_libs = ["support.c", "-lm"]
            command = fuzz_harness.build_command(
                Path(raw) / "fuzz_x.c", Path(raw) / "out", "asan", config, "", [])
        self.assertIn("-DFUZZ_CAMPAIGN_BUILD=1", command)
        self.assertIn("-fsanitize=fuzzer,address", command)
        self.assertIn(str(Path(raw) / "support.c"), command)
        self.assertIn("-lm", command)


class SliceReadingTests(unittest.TestCase):
    LOG = (
        "INFO: Seed: 1\n"
        "#2\tINITED cov: 3 ft: 3 corp: 1/1b exec/s: 0 rss: 29Mb\n"
        "#4096\tNEW    cov: 9 ft: 12 corp: 3/4b lim: 4 exec/s: 4096 rss: 30Mb\n"
        "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
        "artifact_prefix='/x/'; Test unit written to /x/crash-abc\n"
        "Done 4096 runs in 3 second(s)\n"
    )

    def test_a_slice_log_of_arbitrary_bytes_does_not_kill_the_campaign(self) -> None:
        # A fuzzer echoes fragments of the inputs it mutates, so any slice can
        # contain non-UTF-8 sequences. Strict decoding turned the first such
        # byte into a dead campaign on a real target.
        with tempfile.TemporaryDirectory() as raw:
            log = Path(raw) / "slice.log"
            log.write_bytes(
                b"#2\tINITED cov: 3 ft: 3 corp: 1/1b exec/s: 0 rss: 29Mb\n"
                b"Running: \xf9\xfe\xff binary junk\n"
                b"Done 5 runs in 1 second(s)\n")
            parsed = fuzz_campaign.parse_log(fuzz_campaign.read_log(log))
        self.assertEqual(parsed["executions"], 5)
        self.assertTrue(parsed["inited"])

    def test_an_oversized_slice_log_is_bounded_but_keeps_its_ends(self) -> None:
        # A target that logs per parse emitted tens of megabytes in one slice.
        # The head says why a harness failed to start and the tail carries
        # every measurement, so both survive and the middle does not.
        with tempfile.TemporaryDirectory() as raw:
            log = Path(raw) / "slice.log"
            log.write_bytes(
                b"INFO: Seed: 1\n"
                + b"noise\n" * 400_000
                + b"#9\tDONE cov: 7 ft: 9 corp: 2/2b exec/s: 5 rss: 30Mb\n"
                  b"Done 9 runs in 1 second(s)\n")
            original = log.stat().st_size
            parsed = fuzz_campaign.parse_log(fuzz_campaign.read_log(log))
            self.assertLess(log.stat().st_size, original)
        self.assertEqual(parsed["executions"], 9)
        self.assertEqual(parsed["edges"], 7)

    def test_an_artifact_is_found_where_libfuzzer_actually_prints_it(self) -> None:
        # libFuzzer prints the path after artifact_prefix on the same line, so
        # a line-anchored pattern finds nothing and every crash is lost.
        parsed = fuzz_campaign.parse_log(self.LOG)
        self.assertEqual(parsed["artifacts"], ["/x/crash-abc"])
        self.assertEqual(parsed["edges"], 9)
        self.assertEqual(parsed["executions"], 4096)
        self.assertTrue(parsed["inited"])


class HealthAndRecoveryTests(unittest.TestCase):
    """A harness that stops paying gets out of the way of one that pays."""

    @staticmethod
    def state(**kwargs) -> fuzz_campaign.HarnessState:
        return fuzz_campaign.HarnessState(name="h", binary="/b", **kwargs)

    @staticmethod
    def result(**kwargs) -> fuzz_campaign.SliceResult:
        base = dict(harness="h", seconds=60.0, returncode=0)
        base.update(kwargs)
        return fuzz_campaign.SliceResult(**base)

    def test_a_binary_that_never_ran_is_dead_not_merely_dry(self) -> None:
        verdict, detail = fuzz_campaign.classify(
            self.result(returncode=1, executions=0), self.state(), 0)
        self.assertEqual(verdict, fuzz_campaign.VERDICT_DEAD)
        self.assertIn("INITED", detail)

    def test_a_crash_before_inited_blames_the_harness_not_the_target(self) -> None:
        # This one has almost no executions too, so it must be checked before
        # the dead-binary rule or every broken harness lands under the vaguer
        # verdict and nobody fixes it.
        verdict, detail = fuzz_campaign.classify(
            self.result(returncode=1, executions=1, artifacts=["/x/crash-a"]),
            self.state(), 0)
        self.assertEqual(verdict, fuzz_campaign.VERDICT_STARTUP_CRASH)
        self.assertIn("harness", detail)

    def test_noise_is_counted_across_slices_not_within_one(self) -> None:
        # libFuzzer exits at its first OOM/timeout/leak, so a slice can only
        # ever produce one. Requiring three within a slice made the verdict
        # unreachable, and pure noise was reported as a filed crash.
        noisy = self.result(executions=9999, inited=True, oom=True,
                            artifacts=["a"])
        first, _ = fuzz_campaign.classify(noisy, self.state(), 0)
        self.assertEqual(first, fuzz_campaign.VERDICT_PRODUCTIVE)
        second, detail = fuzz_campaign.classify(
            noisy, self.state(noise_streak=1), 0)
        self.assertEqual(second, fuzz_campaign.VERDICT_NOISE_FLOOD)
        self.assertIn("out-of-memory", detail)

    def test_three_slices_with_no_new_coverage_is_saturation(self) -> None:
        verdict, _ = fuzz_campaign.classify(
            self.result(executions=9999, inited=True, edges=100),
            self.state(dry_streak=2, edges=100), 0)
        self.assertEqual(verdict, fuzz_campaign.VERDICT_SATURATED)

    def test_repeat_crashes_without_new_coverage_block_the_harness(self) -> None:
        # Each input for one bug gets its own sha1, so filename dedup would
        # call the same wall a new discovery forever. Coverage decides.
        first, _ = fuzz_campaign.classify(
            self.result(executions=500, inited=True, artifacts=["/x/crash-a"]),
            self.state(repeat_streak=0), 0)
        self.assertEqual(first, fuzz_campaign.VERDICT_PRODUCTIVE)
        blocked, detail = fuzz_campaign.classify(
            self.result(executions=500, inited=True, artifacts=["/x/crash-b"]),
            self.state(repeat_streak=1), 0)
        self.assertEqual(blocked, fuzz_campaign.VERDICT_BLOCKED_ON_CRASH)
        self.assertIn("already filed", detail)

    def test_a_saturated_harness_returns_when_its_corpus_grows(self) -> None:
        state = self.state(
            quarantine=fuzz_campaign.VERDICT_SATURATED, corpus_at_quarantine=4)
        self.assertEqual(fuzz_campaign.revive([state], lambda _: 4), [])
        self.assertEqual(fuzz_campaign.revive([state], lambda _: 5), ["h"])
        self.assertEqual(state.quarantine, "")

    def test_a_dead_harness_never_returns_on_its_own(self) -> None:
        state = self.state(quarantine=fuzz_campaign.VERDICT_DEAD,
                           corpus_at_quarantine=0)
        self.assertEqual(fuzz_campaign.revive([state], lambda _: 99), [])


class CorpusTests(unittest.TestCase):
    """The corpus is what makes short slices as good as one long run."""

    def campaign(self, root: Path) -> fuzz_campaign.Campaign:
        results = root / "results"
        results.mkdir(parents=True, exist_ok=True)
        config = config_for(root / "src", ["bytes"])
        config.results_dir = str(results)
        return fuzz_campaign.Campaign(config, log=lambda _: None)

    def test_a_failed_merge_leaves_the_corpus_it_was_minimising(self) -> None:
        # Minimisation replaces a corpus wholesale. If a merge that produced
        # nothing were trusted, one bad slice would delete every input the
        # campaign had accumulated — the one failure here that destroys data
        # rather than wasting time.
        with tempfile.TemporaryDirectory() as raw:
            campaign = self.campaign(Path(raw))
            state = campaign.add("h", "/nonexistent-binary")
            corpus = fuzz_harness.corpus_dir(campaign.results, "h")
            corpus.mkdir(parents=True)
            for index in range(3):
                (corpus / f"seed{index}").write_bytes(bytes([index]))
            campaign._minimise(state)
            self.assertEqual(campaign.corpus_size("h"), 3)
            self.assertFalse(corpus.with_name(corpus.name + ".merged").exists())
            self.assertEqual(state.since_merge, 0)

    def test_an_empty_corpus_is_seeded_from_the_target_test_data(self) -> None:
        # Measured on libxml2: the same harness reached ~1900 edges in its
        # first slice from the target's own test files and 318 from nothing.
        # On a five-minute budget that difference is most of the budget.
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            data = root / "src" / "test" / "HTML"
            data.mkdir(parents=True)
            (data / "a.html").write_bytes(b"<html><body>a</body></html>")
            (data / "b.html").write_bytes(b"<p>b")
            (data / "helper.c").write_bytes(b"int main(void){return 0;}")
            campaign = self.campaign(root)
            state = campaign.add("h", "/nonexistent-binary")
            self.assertEqual(campaign.seed(state), 2)
            self.assertEqual(campaign.corpus_size("h"), 2)

    def test_a_corpus_the_fuzzer_built_is_never_reseeded(self) -> None:
        # Re-seeding would undo the minimisation that keeps slices fast, and
        # overwrite a corpus worth more than anything copied in.
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            data = root / "src" / "corpus"
            data.mkdir(parents=True)
            (data / "seed").write_bytes(b"xyz")
            campaign = self.campaign(root)
            state = campaign.add("h", "/nonexistent-binary")
            corpus = fuzz_harness.corpus_dir(campaign.results, "h")
            corpus.mkdir(parents=True)
            (corpus / "learned").write_bytes(b"already here")
            self.assertEqual(campaign.seed(state), 0)
            self.assertEqual(campaign.corpus_size("h"), 1)

    def test_seed_selection_skips_source_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            data = root / "tests"
            data.mkdir(parents=True)
            (data / "good.xml").write_bytes(b"<a/>")
            (data / "code.py").write_bytes(b"print(1)")
            (data / "huge.bin").write_bytes(
                b"x" * (fuzz_harness.MAX_SEED_BYTES + 1))
            (data / "empty.dat").write_bytes(b"")
            names = {p.name for p in fuzz_harness.seed_candidates(root)}
        self.assertEqual(names, {"good.xml"})

    def test_a_corpus_below_two_entries_is_not_worth_merging(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            campaign = self.campaign(Path(raw))
            state = campaign.add("h", "/nonexistent-binary")
            fuzz_harness.corpus_dir(campaign.results, "h").mkdir(parents=True)
            campaign._minimise(state)
            self.assertEqual(campaign.corpus_size("h"), 0)


class ManifestTests(unittest.TestCase):
    """A binary's identity comes from a manifest, never from its filename."""

    def manifest(self, results: Path, name: str, san: str,
                 hypothesis: str = "") -> Path:
        binaries = fuzz_harness.binary_dir(results)
        binaries.mkdir(parents=True, exist_ok=True)
        binary = binaries / f"{name}.{san}.deadbeef"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        path = fuzz_harness.manifest_path(binary)
        path.write_text(json.dumps({
            "schema": 1, "harness": name, "sanitizer": san,
            "binary": str(binary), "source": f"/src/{name}.c",
            "hypothesis_id": hypothesis,
        }), encoding="utf-8")
        return binary

    def test_a_campaign_never_selects_another_sanitizers_binary(self) -> None:
        # Selecting the newest binary whose filename prefix matched ran the
        # UBSan build under an ASan campaign, because it sorted later.
        with tempfile.TemporaryDirectory() as raw:
            results = Path(raw)
            self.manifest(results, "fuzz_api", "asan")
            self.manifest(results, "fuzz_api", "ubsan")
            asan = fuzz_harness.built_harnesses(results, "asan")
            ubsan = fuzz_harness.built_harnesses(results, "ubsan")
        self.assertEqual(set(asan), {"fuzz_api"})
        self.assertTrue(asan["fuzz_api"]["binary"].endswith("asan.deadbeef"))
        self.assertTrue(ubsan["fuzz_api"]["binary"].endswith("ubsan.deadbeef"))

    def test_a_harness_name_containing_a_dot_survives(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            results = Path(raw)
            self.manifest(results, "fuzz_v1.2_api", "asan")
            built = fuzz_harness.built_harnesses(results, "asan")
        self.assertEqual(set(built), {"fuzz_v1.2_api"})

    def test_the_manifest_carries_the_hypothesis_for_replay(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            results = Path(raw)
            self.manifest(results, "fuzz_api", "asan", hypothesis="H-9")
            built = fuzz_harness.built_harnesses(results, "asan")
        self.assertEqual(built["fuzz_api"]["hypothesis_id"], "H-9")

    def test_schema_two_binds_the_harness_receipt_and_schema_one_fails_open(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            binary = root / "fuzz_sample"
            binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            binary.chmod(0o755)
            source = root / "fuzz_sample.c"
            source.write_text(
                "// S4-RECEIPT BOUNDARY: sample_parse\n"
                "// S4-RECEIPT CONTROLS: bytes\n"
                "// S4-RECEIPT DECLARATION: int sample_parse(const char *, size_t);\n"
                "// S4-RECEIPT SOURCE-USAGE: tests/sample_usage.c:7\n"
                "// S4-RECEIPT CONSTRUCTOR: UNRESOLVED\n"
                "// S4-RECEIPT ARG-RELATIONS: length is payload bytes\n"
                "// S4-RECEIPT RESOURCE-FLOW: UNRESOLVED\n"
                "// S4-RECEIPT TEARDOWN: UNRESOLVED\n"
                "// S4-RECEIPT UNRESOLVED: constructor, resource-flow, teardown\n",
                encoding="utf-8",
            )
            choice = fuzz_harness.LibraryChoice(
                path="/build/libsample.a", tree="build-asan+fuzz",
                instrumented=True,
            )
            fuzz_harness.write_manifest(
                binary, source, "asan", choice, "digest", sanitized=True)
            record = json.loads(fuzz_harness.manifest_path(binary).read_text())

            plain = root / "fuzz_plain"
            plain.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            plain.chmod(0o755)
            plain_source = root / "fuzz_plain.c"
            plain_source.write_text(
                "int LLVMFuzzerTestOneInput(void) { return 0; }\n",
                encoding="utf-8")
            fuzz_harness.write_manifest(
                plain, plain_source, "asan", choice, "digest", sanitized=True)
            ungrounded = json.loads(
                fuzz_harness.manifest_path(plain).read_text())

            results = root / "results"
            self.manifest(results, "fuzz_legacy", "asan")
            legacy = fuzz_harness.built_harnesses(results, "asan")["fuzz_legacy"]

        self.assertEqual(record["schema"], 2)
        self.assertEqual(record["receipt"]["boundary"], "sample_parse")
        self.assertEqual(
            record["receipt"]["unresolved"],
            ["constructor", "resource-flow", "teardown"],
        )
        self.assertEqual(ungrounded["receipt"], {})
        self.assertEqual(legacy["receipt"], {})
        self.assertEqual(legacy["receipt_warnings"], [])


class FirstSliceReceiptTests(unittest.TestCase):
    """The first useful feedback survives resume and is never overwritten."""

    def test_first_slice_is_persisted_and_later_slices_do_not_replace_it(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            results = Path(raw) / "results"
            results.mkdir()
            config = config_for(Path(raw) / "source", ["bytes"])
            config.results_dir = str(results)
            campaign = fuzz_campaign.Campaign(config, log=lambda _: None)
            state = campaign.add("fuzz_sample", "/tmp/fuzz_sample")
            first = fuzz_campaign.SliceResult(
                harness=state.name, seconds=2.0, returncode=0,
                executions=200, edges=12, features=18, inited=True,
                log="fuzz/logs/fuzz_sample/slice-0001.log",
            )
            campaign._record(
                state, first, fuzz_campaign.VERDICT_PRODUCTIVE,
                "12 new edges", 12, [], 18,
            )
            second = fuzz_campaign.SliceResult(
                harness=state.name, seconds=3.0, returncode=0,
                executions=500, edges=40, features=80, inited=True,
                log="fuzz/logs/fuzz_sample/slice-0002.log",
            )
            campaign._record(
                state, second, fuzz_campaign.VERDICT_PRODUCTIVE,
                "28 new edges", 28, [], 62,
            )
            fuzz_campaign.save_states(results, campaign.states)
            resumed = fuzz_campaign.load_states(results)[state.name]

        self.assertEqual(resumed.first_slice["executions"], 200)
        self.assertEqual(resumed.first_slice["new_edges"], 12)
        self.assertEqual(resumed.first_slice["new_features"], 18)
        self.assertEqual(resumed.first_slice["verdict"], "productive")

    def test_status_joins_build_and_receipt_without_changing_campaign_state(self) -> None:
        state = fuzz_campaign.HarnessState(
            name="fuzz_sample", binary="/tmp/fuzz_sample",
            slices=3, quarantine=fuzz_campaign.VERDICT_SATURATED,
        )
        original = state.as_dict()
        rows = fuzz_campaign.status_rows({state.name: state}, {
            state.name: {
                "binary": state.binary, "guided": True, "sanitized": True,
                "source_sha1": "abc", "receipt": {
                    "schema": 1, "boundary": "sample_parse",
                    "unresolved": ["resource-flow"],
                },
                "receipt_warnings": [],
            },
        })

        self.assertEqual(state.as_dict(), original)
        self.assertTrue(rows[state.name]["build"]["guided"])
        self.assertEqual(rows[state.name]["receipt"]["boundary"], "sample_parse")
        self.assertIn("resolve", rows[state.name]["next"])

    def test_parameter_types_and_compatible_api_hints(self) -> None:
        self.assertEqual(
            fuzz_harness.parameter_types(
                "int f(sample_ctx * const ctx, const char *s, size_t n, char **out, "
                "void (*cb)(int), unsigned int flags, struct sample_opt *o, uint8_t buf[16])"),
            {"sample_ctx *", "char *", "size_t", "char **", "unsigned int",
             "struct sample_opt *", "uint8_t *"},
        )
        candidates = [
            fuzz_harness.Candidate("sample_add", "int sample_add(sample_ctx *ctx, sample_ctx *item)", [], [], True, []),
            fuzz_harness.Candidate("sample_print", "char *sample_print(const sample_ctx *ctx, int depth)", [], [], True, []),
            fuzz_harness.Candidate("sample_parse", "sample_ctx *sample_parse(const char *text)", [], [], True, []),
            fuzz_harness.Candidate("sample_free_all", "void sample_free_all(sample_ctx *ctx)", [], [], False, ["private"]),
            fuzz_harness.Candidate("sample_version", "const char *sample_version(void)", [], [], True, []),
            fuzz_harness.Candidate("sample_scan", "int sample_scan(const char *text, size_t n)", [], [], True, []),
        ]
        hints = fuzz_harness.compatible_api_hints(
            "char *sample_print(const sample_ctx *ctx, int depth)", candidates,
            exclude="sample_print")
        # Shares the handle type as a parameter; a producer that merely
        # returns it, the rejected candidate, the boundary itself, and a
        # bare-`char *` API never appear.
        self.assertEqual([h["symbol"] for h in hints], ["sample_add"])
        self.assertEqual(hints[0]["shared_types"], ["sample_ctx *"])
        # A boundary with only generic types falls back to sharing them.
        generic = fuzz_harness.compatible_api_hints(
            "sample_ctx *sample_parse(const char *text)", candidates,
            exclude="sample_parse", limit=1)
        self.assertEqual([h["symbol"] for h in generic], ["sample_scan"])

    def test_status_shows_compatible_apis_only_when_a_derivative_is_due(self) -> None:
        state = fuzz_campaign.HarnessState(
            name="fuzz_sample", binary="/tmp/fuzz_sample",
            slices=3, quarantine=fuzz_campaign.VERDICT_SATURATED,
        )
        resolved = {
            "binary": state.binary, "guided": True, "sanitized": True,
            "receipt": {"boundary": "sample_parse", "unresolved": []},
            "receipt_warnings": [],
        }
        hints = {state.name: [{"symbol": "sample_add", "declaration": "int sample_add(sample_ctx *, sample_ctx *)", "shared_types": ["sample_ctx *"]}]}
        self.assertTrue(fuzz_campaign.derivative_ready(state, resolved))
        rows = fuzz_campaign.status_rows({state.name: state}, {state.name: resolved}, hints)
        self.assertEqual(rows[state.name]["compatible_apis"][0]["symbol"], "sample_add")
        self.assertIn("contract-preserving derivative", rows[state.name]["next"])
        # Not ready: unresolved receipt, blind build, or still dry.
        unresolved = dict(resolved, receipt={"boundary": "sample_parse", "unresolved": ["teardown"]})
        self.assertFalse(fuzz_campaign.derivative_ready(state, unresolved))
        self.assertFalse(fuzz_campaign.derivative_ready(state, dict(resolved, guided=False)))
        dry = fuzz_campaign.HarnessState(name="fuzz_sample", binary=state.binary, slices=1)
        self.assertFalse(fuzz_campaign.derivative_ready(dry, resolved))
        self.assertNotIn("compatible_apis", fuzz_campaign.status_rows({dry.name: dry}, {dry.name: resolved}, hints)[dry.name])

    def test_a_rebuilt_binary_does_not_inherit_a_stale_saturation_decision(self) -> None:
        state = fuzz_campaign.HarnessState(
            name="fuzz_sample", binary="/tmp/fuzz_sample-old",
            slices=3, quarantine=fuzz_campaign.VERDICT_SATURATED,
        )
        rows = fuzz_campaign.status_rows({state.name: state}, {
            state.name: {
                "binary": "/tmp/fuzz_sample-new", "source": "/tmp/fuzz_sample.c",
                "guided": True, "sanitized": True,
                "receipt": {"schema": 1, "boundary": "sample_parse", "unresolved": []},
            },
        })

        self.assertEqual(rows[state.name]["binary"], "/tmp/fuzz_sample-new")
        self.assertEqual(rows[state.name]["slices"], 0)
        self.assertFalse(rows[state.name]["quarantine"])
        self.assertEqual(rows[state.name]["coverage"], "0 edges, 0 features")
        self.assertIn("first-slice", rows[state.name]["next"])

    def test_changed_source_is_told_to_rebuild_before_campaign_advice(self) -> None:
        state = fuzz_campaign.HarnessState(
            name="fuzz_sample", binary="/tmp/fuzz_sample",
            slices=3, quarantine=fuzz_campaign.VERDICT_SATURATED,
        )
        rows = fuzz_campaign.status_rows({state.name: state}, {
            state.name: {
                "binary": state.binary, "current": False,
                "guided": True, "sanitized": True,
                "receipt": {"schema": 1, "boundary": "sample_parse", "unresolved": []},
            },
        })

        self.assertIn("rebuild", rows[state.name]["next"])
        self.assertNotIn("derivative", rows[state.name]["next"])

    def test_a_harness_with_no_receipt_keeps_the_generic_saturation_advice(self) -> None:
        state = fuzz_campaign.HarnessState(
            name="fuzz_sample", binary="/tmp/fuzz_sample",
            slices=3, quarantine=fuzz_campaign.VERDICT_SATURATED,
        )
        rows = fuzz_campaign.status_rows({state.name: state}, {
            state.name: {"binary": state.binary, "guided": True, "receipt": {}},
        })


        self.assertEqual(
            rows[state.name]["next"], fuzz_campaign.recommendation(state))
        self.assertNotIn("derivative", rows[state.name]["next"])


class ArtifactLifecycleTests(unittest.TestCase):
    """An artifact is evidence until something adjudicates it.

    The green suite hid this: nothing exercised the path where probe fails or
    the budget runs out, and both silently discarded real crashes.
    """

    def test_only_a_terminal_probe_verdict_marks_an_artifact_seen(self) -> None:
        # A build failure, a timeout, or a killed replay must leave the
        # artifact pending — one transient failure used to suppress a real
        # crash for every later campaign.
        self.assertTrue(fuzz_campaign._terminal_verdict(
            "[probe] verdict=CRASH\n", 1))
        self.assertTrue(fuzz_campaign._terminal_verdict(
            "[probe] verdict=CLEAN\n", 0))
        self.assertFalse(fuzz_campaign._terminal_verdict(
            "harness build failed\n", 2))
        self.assertFalse(fuzz_campaign._terminal_verdict("", 124))

    def test_unadjudicated_artifacts_are_found_again_next_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            results = Path(raw) / "results"
            results.mkdir()
            config = config_for(Path(raw) / "src", ["bytes"])
            config.results_dir = str(results)
            campaign = fuzz_campaign.Campaign(config, log=lambda _: None)
            state = campaign.add("h", "/nonexistent")
            artifacts = fuzz_harness.artifact_dir(results, "h")
            artifacts.mkdir(parents=True)
            (artifacts / "crash-aaa").write_bytes(b"a")
            (artifacts / "crash-bbb").write_bytes(b"b")
            self.assertEqual(len(campaign.pending_artifacts(state)), 2)
            state.seen_artifacts = ["crash-aaa"]
            pending = campaign.pending_artifacts(state)
        self.assertEqual([Path(p).name for p in pending], ["crash-bbb"])


class BuildSelectionTests(unittest.TestCase):
    """The campaign must fuzz the source that replay will rebuild."""

    def build(self, results: Path, source: Path, san: str, digest: str,
              mtime: float) -> None:
        binaries = fuzz_harness.binary_dir(results)
        binaries.mkdir(parents=True, exist_ok=True)
        binary = binaries / f"{source.stem}.{san}.{digest}"
        binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        binary.chmod(0o755)
        os.utime(binary, (mtime, mtime))
        fuzz_harness.manifest_path(binary).write_text(json.dumps({
            "schema": 1, "harness": source.stem, "sanitizer": san,
            "binary": str(binary), "source": str(source), "digest": digest,
            "source_sha1": hashlib.sha1(source.read_bytes()).hexdigest()
            if digest == "current" else "stale",
        }), encoding="utf-8")

    def test_a_reverted_source_selects_its_own_build_not_the_newest(self) -> None:
        # Build A, edit to B, revert to A. A's cached binary is never
        # retouched, so B stays newest — and the campaign would fuzz B while
        # replay copied A into scratch, making every artifact unreproducible.
        with tempfile.TemporaryDirectory() as raw:
            results = Path(raw) / "results"
            source = Path(raw) / "fuzz_api.c"
            source.write_bytes(b"int LLVMFuzzerTestOneInput(void){return 0;}")
            self.build(results, source, "asan", "current", mtime=1000)
            self.build(results, source, "asan", "abandoned", mtime=9000)
            chosen = fuzz_harness.built_harnesses(results, "asan")["fuzz_api"]
        self.assertTrue(chosen["binary"].endswith("current"))


class ChosenSanitizerTests(unittest.TestCase):
    """S4 needs a native build; saying otherwise fails later and worse."""

    def test_a_findings_only_target_is_refused_not_defaulted_to_asan(self) -> None:
        import workqueue
        managed = target_config.Config()
        managed.sanitizers_enabled = []
        self.assertFalse(workqueue.campaign_supported(managed))

    def test_a_cli_only_target_has_nothing_to_link(self) -> None:
        import workqueue
        cli = target_config.Config()
        cli.sanitizers_enabled = ["asan"]
        cli.asan_bin = "build-asan/tool"
        self.assertFalse(workqueue.campaign_supported(cli))

    def test_a_native_target_with_a_library_is_supported(self) -> None:
        import workqueue
        native = target_config.Config()
        native.sanitizers_enabled = ["asan"]
        native.asan_lib = "build-asan/libx.dylib"
        self.assertTrue(workqueue.campaign_supported(native))


class ConcurrencyTests(unittest.TestCase):
    """One campaign per results tree, or two agents share one corpus."""

    def test_a_second_campaign_does_not_start_while_one_holds_the_lock(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            with fuzz_campaign.exclusive(raw) as first:
                self.assertTrue(first)
                with fuzz_campaign.exclusive(raw) as second:
                    self.assertFalse(second)
            # Released on exit, so the next iteration is not blocked.
            with fuzz_campaign.exclusive(raw) as third:
                self.assertTrue(third)


class CoverageFeedbackTests(unittest.TestCase):
    """Edges alone say nothing; the instrumented total is what makes them
    actionable, and the advice has to change with it."""

    def test_the_instrumented_total_is_read_from_the_startup_line(self) -> None:
        parsed = fuzz_campaign.parse_log(
            "INFO: Loaded 2 modules   (84213 inline 8-bit counters): "
            "12 [0x1, 0x2), 84201 [0x3, 0x4), \n"
            "#2\tINITED cov: 5 ft: 5 corp: 1/1b exec/s: 0 rss: 29Mb\n")
        self.assertEqual(parsed["counters"], 84213)

    def test_progress_counts_features_not_only_edges(self) -> None:
        """Value profiling reports through `ft`, not `cov`.

        A dry harness is switched to value profiling and then judged; judging
        on edges alone called it saturated while it was still learning, which
        quarantined the harness the feedback loop had just helped.
        """
        state = fuzz_campaign.HarnessState(
            name="h", binary="/b", dry_streak=2, edges=100, features=500)
        result = fuzz_campaign.SliceResult(
            harness="h", seconds=60.0, returncode=0, executions=9999,
            inited=True, edges=100, features=900)
        new_edges, new_features = fuzz_campaign.progress(result, state)
        self.assertEqual((new_edges, new_features), (0, 400))
        verdict, _ = fuzz_campaign.classify(
            result, state, new_edges, new_features=new_features)
        self.assertEqual(verdict, fuzz_campaign.VERDICT_PRODUCTIVE)

    def test_coverage_is_reported_but_no_fraction_is_claimed(self) -> None:
        """The instrumented total spans every loaded module, including the
        harness's own — it is not the code reachable from this entry point,
        so it cannot say whether a harness is narrow or nearly done."""
        state = fuzz_campaign.HarnessState(
            name="h", binary="/b", edges=307, counters=1225, features=900)
        note = fuzz_campaign.coverage_note(state)
        self.assertIn("307 edges", note)
        self.assertIn("900 features", note)
        self.assertNotIn("%", note)
        self.assertFalse(hasattr(fuzz_campaign, "coverage_fraction"))

    def test_a_climbing_harness_is_told_more_wall_still_pays(self) -> None:
        climbing = fuzz_campaign.HarnessState(
            name="h", binary="/b", edges=900, counters=84000, value=4.2)
        self.assertIn("more wall still pays",
                      fuzz_campaign.recommendation(climbing))


class DictionaryTests(unittest.TestCase):
    """A project's own token list is the cheapest coverage a mutator can buy.

    Every target in this tree ships one; a campaign that ignores them makes
    the mutator rediscover `<!DOCTYPE` a byte at a time.
    """

    def tree(self, root: Path, names: "list[str]") -> None:
        directory = root / "fuzz"
        directory.mkdir(parents=True, exist_ok=True)
        for name in names:
            (directory / name).write_text('"<a"\n', encoding="utf-8")

    def test_the_format_name_is_matched_inside_the_api_name(self) -> None:
        # A harness is named for the API it drives and a dictionary for the
        # format, so the format name is buried inside the API name. Token
        # equality finds nothing; `html` has to match `htmlReadMemory`.
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.tree(root, ["html.dict", "xml.dict", "regexp.dict"])
            for harness, expected in (
                ("fuzz_htmlReadMemory", "html.dict"),
                ("fuzz_xmlCreateMemoryParserCtxt", "xml.dict"),
                ("fuzz_xmlRegexpCompile", "regexp.dict"),
            ):
                with self.subTest(harness=harness):
                    chosen = fuzz_harness.dictionary_for(root, harness)
                    self.assertEqual(Path(chosen).name, expected)

    def test_a_single_dictionary_is_used_even_without_a_name_match(self) -> None:
        # One format is the common case; leaving the only dictionary on the
        # floor because the filename differs is pure loss.
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.tree(root, ["json.dict"])
            chosen = fuzz_harness.dictionary_for(root, "fuzz_cJSON_ParseWithLength")
            self.assertEqual(Path(chosen).name, "json.dict")

    def test_no_dictionary_is_not_an_error(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            self.assertEqual(fuzz_harness.dictionary_for(Path(raw), "fuzz_api"), "")

    def test_ambiguous_dictionaries_with_no_match_pick_none(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            self.tree(root, ["png.dict", "jpeg.dict"])
            self.assertEqual(fuzz_harness.dictionary_for(root, "fuzz_api"), "")


class SchedulingTests(unittest.TestCase):
    """Diversity first, then whichever harness is actually producing."""

    def test_every_harness_runs_before_any_runs_twice(self) -> None:
        rich = fuzz_campaign.HarnessState(name="a", binary="/a", slices=3, value=99.0)
        unrun = fuzz_campaign.HarnessState(name="b", binary="/b")
        self.assertEqual(fuzz_campaign.select_next([rich, unrun], 3).name, "b")

    def test_a_productive_harness_wins_once_exploration_is_paid(self) -> None:
        good = fuzz_campaign.HarnessState(name="a", binary="/a", slices=20, value=50.0)
        bad = fuzz_campaign.HarnessState(name="b", binary="/b", slices=20, value=0.01)
        self.assertEqual(fuzz_campaign.select_next([good, bad], 40).name, "a")

    def test_quarantined_harnesses_are_never_selected(self) -> None:
        dead = fuzz_campaign.HarnessState(
            name="a", binary="/a", quarantine=fuzz_campaign.VERDICT_DEAD)
        self.assertIsNone(fuzz_campaign.select_next([dead], 1))

    def test_selection_is_stable_across_a_resume(self) -> None:
        # Two harnesses with identical history must not be ordered by whatever
        # the filesystem listed first, or a resumed campaign diverges.
        pair = [fuzz_campaign.HarnessState(name=n, binary="/x", slices=2, value=1.0)
                for n in ("b", "a")]
        self.assertEqual(fuzz_campaign.select_next(pair, 4).name, "a")


class BudgetTests(unittest.TestCase):
    """S4 shares an iteration with seven other strategies."""

    def test_the_default_budget_is_a_slice_of_an_iteration(self) -> None:
        self.assertLessEqual(fuzz_campaign.DEFAULT_BUDGET_SECONDS, 10 * 60)

    def test_a_campaign_stops_when_every_harness_is_quarantined(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            results = Path(raw) / "results"
            results.mkdir()
            config = config_for(Path(raw) / "src", ["bytes"])
            config.results_dir = str(results)
            campaign = fuzz_campaign.Campaign(config, log=lambda _: None)
            campaign.add("h", "/nonexistent")
            campaign.states["h"].quarantine = fuzz_campaign.VERDICT_DEAD
            summary = campaign.run(budget_seconds=3600)
        self.assertEqual(summary["slices"], 0)
        self.assertIn("quarantined", summary["stopped"])
        # The unspent time is reported, because that is what the next
        # strategy gets and an operator has to be able to see it.
        self.assertGreater(summary["seconds_returned"], 3000)

    def test_a_slice_that_cannot_finish_in_the_budget_never_starts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            results = Path(raw) / "results"
            results.mkdir()
            config = config_for(Path(raw) / "src", ["bytes"])
            config.results_dir = str(results)
            campaign = fuzz_campaign.Campaign(
                config, slice_seconds=600, log=lambda _: None)
            campaign.add("h", "/nonexistent")
            # Budget below one slice: run() floors the deadline at a single
            # slice, so exactly one runs and no second one overruns.
            summary = campaign.run(budget_seconds=1)
        self.assertLessEqual(summary["slices"], 1)


class CallerOwnedObjectTests(unittest.TestCase):
    """The harness's own redzones are what report a caller-owned overrun.

    A unit test on the link flags cannot catch this: a harness linked without
    its sanitizer still builds, still runs, still fuzzes, and only stops
    reporting a target that writes past a buffer *the harness* owns. That
    regression shipped once and read as a working campaign, so the property is
    pinned to a real compile rather than to the flag list.
    """

    HEADER = ("#ifndef VS_H\n#define VS_H\n#include <stddef.h>\n"
              "void vs_fill(char *out, size_t n);\n#endif\n")
    LIBRARY = ("#include \"vs.h\"\n"
               "void vs_fill(char *out, size_t n) {\n"
               "  for (size_t i = 0; i <= n; i++) out[i] = 'A';  /* one past */\n"
               "}\n")
    HARNESS = ("#include <stdint.h>\n#include <stddef.h>\n#include \"vs.h\"\n"
               "int LLVMFuzzerTestOneInput(const uint8_t *d, size_t s) {\n"
               "  (void)d; (void)s;\n"
               "  char owned[16];\n"
               "  vs_fill(owned, sizeof owned);\n"
               "  return 0;\n}\n")

    def test_a_target_overrunning_a_caller_owned_buffer_is_reported(self) -> None:
        compiler = shutil.which(fuzz_harness.fuzzing_compiler())
        if not compiler:
            self.skipTest("no clang shipping libFuzzer on this machine")
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target, results = root / "target", root / "results"
            (results / "fuzz" / "src").mkdir(parents=True)
            target.mkdir()
            (target / "vs.h").write_text(self.HEADER, encoding="utf-8")
            (target / "vs.c").write_text(self.LIBRARY, encoding="utf-8")
            source = results / "fuzz" / "src" / "fuzz_vs_fill.c"
            source.write_text(self.HARNESS, encoding="utf-8")
            suffix = ".dylib" if sys.platform == "darwin" else ".so"
            library = target / f"libvs{suffix}"
            # The same compiler the harness will use, so the link keeps its
            # sanitizer and this measures the policy, not a toolchain gap.
            built = subprocess.run(
                [compiler, "-fsanitize=address", "-g", "-O0", "-shared",
                 "-fPIC", "-I", str(target)]
                + (["-install_name", str(library)] if suffix == ".dylib" else [])
                + ["-o", str(library), str(target / "vs.c")],
                capture_output=True, text=True)
            if built.returncode:
                self.skipTest("cannot build an instrumented library: "
                              + built.stderr[-200:])
            config = config_for(target, ["bytes"])
            config.results_dir = str(results)
            config.includes = [str(target)]
            config.asan_lib = library.name
            result = fuzz_harness.build(source, config, "asan")
            self.assertTrue(result.binary, result.error)
            manifest = json.loads(
                fuzz_harness.manifest_path(result.binary).read_text())
            self.assertTrue(manifest["sanitized"], result.remedy)
            probe = root / "input"
            probe.write_bytes(b"x")
            ran = subprocess.run([result.binary, str(probe)],
                                 capture_output=True, text=True)
            self.assertIn("stack-buffer-overflow", ran.stdout + ran.stderr)


class RuntimeLinkageTests(unittest.TestCase):
    """The harness keeps its own instrumentation unless it cannot start."""

    def command_for(self, sanitize: bool) -> "list[str]":
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "fuzz_api.c"
            source.write_bytes(b"int LLVMFuzzerTestOneInput(void){return 0;}")
            return fuzz_harness.build_command(
                source, root / "out", "asan", config_for(root, ["bytes"]),
                str(root / "libtarget.dylib"), [], sanitize)

    def test_the_harness_is_sanitized_by_default(self) -> None:
        # Redzones around the harness's own stack and globals are what report
        # a target overrunning a buffer its caller owns.
        self.assertIn("-fsanitize=fuzzer,address", self.command_for(True))

    def test_the_fallback_drops_the_sanitizer_and_nothing_else(self) -> None:
        command = self.command_for(False)
        self.assertIn("-fsanitize=fuzzer", command)
        self.assertNotIn("-fsanitize=fuzzer,address", command)

    def test_only_a_duplicate_runtime_earns_the_fallback(self) -> None:
        self.assertTrue(fuzz_harness.duplicate_runtime(
            "==1==ERROR: Interceptors are not working. This may be because "
            "AddressSanitizer is loaded too late"))
        self.assertTrue(fuzz_harness.duplicate_runtime(
            "==1==ERROR: ASan runtime does not come first in initial library "
            "list"))
        self.assertFalse(fuzz_harness.duplicate_runtime(
            "dyld: Library not loaded: @rpath/libtarget.dylib"))


class DeadSliceDiagnosisTests(unittest.TestCase):
    """A slice that never ran must report what it saw, not a guess."""

    def verdict(self, log_text: str) -> str:
        parsed = fuzz_campaign.parse_log(log_text)
        result = fuzz_campaign.SliceResult(
            harness="h", seconds=0.1, returncode=127, **parsed)
        return fuzz_campaign.classify(
            result, fuzz_campaign.HarnessState(name="h", binary="/gone"), 0)[1]

    def test_the_opening_line_is_the_diagnosis(self) -> None:
        # A binary rebuilt out from under the campaign, or a library that will
        # not load, says so before libFuzzer prints anything.
        detail = self.verdict("exec: [Errno 2] No such file or directory\n")
        self.assertIn("No such file or directory", detail)

    def test_a_libfuzzer_banner_is_not_mistaken_for_an_error(self) -> None:
        detail = self.verdict("INFO: Seed: 1\nINFO: Running with entropic\n")
        self.assertIn("check the build log", detail)


class ToolchainMismatchTests(unittest.TestCase):
    """A version-locked runtime must name its repair, not a missing symbol."""

    LINK_ERROR = (
        "Undefined symbols for architecture arm64:\n"
        '  "___asan_version_mismatch_check_apple_clang_2100", referenced from:\n'
        "      _asan.module_ctor in libtarget.a(target.o)\n"
    )

    def test_a_version_locked_runtime_names_the_toolchain_to_rebuild_with(self) -> None:
        repair = fuzz_harness.toolchain_mismatch(self.LINK_ERROR)
        self.assertIn(fuzz_harness.fuzzing_compiler(), repair)
        self.assertIn(fuzz_harness.COVERAGE_TREE_SUFFIX, repair)

    def test_the_recipe_covers_c_and_cxx(self) -> None:
        # A C++ target ignores CC and CFLAGS and would come back unchanged.
        recipe = fuzz_harness.rebuild_recipe()
        for variable in ("CC=", "CXX=", "CFLAGS/CXXFLAGS"):
            self.assertIn(variable, recipe)

    def test_the_recipe_emits_trace_pc_guard_for_native_coverage(self) -> None:
        # The one sibling serves both consumers: libFuzzer's counters and the
        # __sancov_guards section bin/hits --mode generic needs for .sancov.
        # Without this flag native CLI coverage silently reports unavailable.
        recipe = fuzz_harness.rebuild_recipe()
        self.assertIn("fuzzer-no-link", recipe)
        self.assertIn("-fsanitize-coverage=trace-pc-guard", recipe)

    def test_an_ordinary_compile_error_is_left_alone(self) -> None:
        self.assertEqual(fuzz_harness.toolchain_mismatch(
            "fuzz_api.c:12:3: error: use of undeclared identifier 'foo'"), "")


class StartupProbeTests(unittest.TestCase):
    """A harness that cannot start is a build error, not a wasted slice."""

    def probe(self, script: str) -> str:
        with tempfile.TemporaryDirectory() as raw:
            binary = Path(raw) / "harness"
            binary.write_text(script, encoding="utf-8")
            binary.chmod(0o755)
            return fuzz_harness.startup_failure(binary, "", "asan")

    def test_a_binary_that_cannot_start_reports_what_it_printed(self) -> None:
        failure = self.probe(
            "#!/bin/sh\necho 'Interceptors are not working' >&2\nexit 134\n")
        self.assertIn("Interceptors are not working", failure)

    def test_a_failure_after_the_banner_is_still_a_failure(self) -> None:
        # `-help=1` executes no input, so nothing the target does can make the
        # status non-zero: a binary that prints and then dies is broken, and
        # accepting it would hand the campaign a slice to waste.
        failure = self.probe(
            "#!/bin/sh\necho 'INFO: Seed: 1'\necho 'boom' >&2\nexit 134\n")
        self.assertIn("boom", failure)

    def test_a_binary_that_prints_its_flags_and_exits_has_started(self) -> None:
        self.assertEqual(self.probe("#!/bin/sh\necho 'Usage:'\n"), "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
