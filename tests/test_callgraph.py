#!/usr/bin/env python3
"""Behaviour of the call-neighbourhood artifact and its prompt block.

The reader must fall open on every degraded input — that is the property that
lets an audit run with the analysis disabled, half-built, or stale — and it
must suppress the block rather than show a partial map as a whole one.
"""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import callgraph  # noqa: E402
import native_symbols  # noqa: E402
import target_config  # noqa: E402


def _sidecar():
    """Import bin/callgraph, which has no .py suffix, as a module."""
    loader = importlib.machinery.SourceFileLoader("callgraph_sidecar", str(ROOT / "bin" / "callgraph"))
    module = importlib.util.module_from_spec(importlib.util.spec_from_loader(loader.name, loader))
    loader.exec_module(module)
    return module


ARTIFACT = {
    "version": callgraph.SCHEMA_VERSION,
    "signature": "sig-1",
    "root": "/tmp/target",
    "languages": ["c"],
    "entry": {"basis": "cli-main", "artifact": "app", "roots": ["driver:main"], "root_count": 1},
    "coverage": {"artifact": "libapp.so", "symbols": 100, "covered": 95, "ratio": 0.95},
    "files": {
        "src/parse.c": {
            "functions": 12,
            "reachable": 7,
            "callers": [["src/main.c", 4], ["src/io.c", 2]],
            "callees": [["src/buf.c", 9]],
            "paths": [
                {"function": "app_parse", "path": ["main", "run", "app_parse"]},
                {"function": "app_reset", "path": []},
                {"function": "app_open", "path": ["app_open"]},
            ],
        },
        "src/lonely.c": {
            "functions": 3, "reachable": 0, "callers": [], "callees": [], "paths": [],
        },
    },
}


class BlockRenderingTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.results = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, artifact: dict) -> None:
        path = callgraph.artifact_path(self.results)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact), encoding="utf-8")

    def render(self, file: str) -> str:
        return "\n".join(callgraph.block_for(self.results, file))

    def test_renders_callers_callees_and_paths(self) -> None:
        self.write(ARTIFACT)
        block = self.render("src/parse.c")
        self.assertIn("`src/main.c`(4 fn)", block)
        self.assertIn("`src/buf.c`(9 fn)", block)
        self.assertIn("main -> run -> app_parse", block)
        self.assertIn("95% of the built target's symbols", block)
        self.assertIn("`driver:main` in `app`", block)

    def test_missing_path_is_stated_not_implied(self) -> None:
        self.write(ARTIFACT)
        block = self.render("src/parse.c")
        self.assertIn("no direct-call path found", block)
        # The recall-safety contract: nothing downstream may read a missing
        # path as unreachability, so the block has to say so itself.
        self.assertIn("not evidence of unreachability", block)

    def test_root_function_is_labelled_not_shown_as_a_stub_path(self) -> None:
        self.write(ARTIFACT)
        self.assertIn("`app_open`: is itself on the entry boundary", self.render("src/parse.c"))

    def test_a_file_with_nothing_to_report_renders_nothing(self) -> None:
        # No caller, no callee, no route: the block would be an entry-boundary
        # claim, two "no direct parsed edge" lines and a caveat. That is what
        # every card got on targets whose cross-file resolution is weak.
        self.write(ARTIFACT)
        self.assertEqual(self.render("src/lonely.c"), "")

    def test_one_neighbour_is_enough_to_report(self) -> None:
        artifact = json.loads(json.dumps(ARTIFACT))
        artifact["files"]["src/lonely.c"]["callees"] = [["src/buf.c", 2]]
        self.write(artifact)
        block = self.render("src/lonely.c")
        self.assertIn("`src/buf.c`(2 fn)", block)
        self.assertIn("no direct parsed edge observed", block)

    def test_a_boundary_that_routed_nowhere_is_not_announced(self) -> None:
        # Naming a boundary that reached nothing states a conclusion the
        # analysis did not reach.
        artifact = json.loads(json.dumps(ARTIFACT))
        artifact["files"]["src/parse.c"]["paths"] = [
            {"function": "app_reset", "path": []},
        ]
        self.write(artifact)
        block = self.render("src/parse.c")
        self.assertIn("`src/main.c`(4 fn)", block)
        self.assertNotIn("Observed entry roots", block)
        self.assertNotIn("Shortest path", block)

    def test_a_routed_boundary_is_announced(self) -> None:
        self.write(ARTIFACT)
        block = self.render("src/parse.c")
        self.assertIn("Observed entry roots", block)
        self.assertIn("main -> run -> app_parse", block)

    def test_low_coverage_withholds_the_boundary_not_the_neighbours(self) -> None:
        # Coverage measures how much of the built target the parser matched.
        # That bears on "main reaches here"; it says nothing about whether one
        # parsed file calls another, so it must not silence the neighbours.
        artifact = json.loads(json.dumps(ARTIFACT))
        artifact["coverage"]["ratio"] = callgraph.MIN_COVERAGE - 0.01
        self.write(artifact)
        block = self.render("src/parse.c")
        self.assertIn("`src/main.c`(4 fn)", block)
        self.assertNotIn("Observed entry roots", block)
        self.assertNotIn("Shortest path", block)

    def test_unmeasured_coverage_renders_with_a_caveat(self) -> None:
        artifact = json.loads(json.dumps(ARTIFACT))
        artifact["coverage"]["ratio"] = None
        self.write(artifact)
        self.assertIn("unmeasured", self.render("src/parse.c"))

    def test_absent_artifact_renders_nothing(self) -> None:
        self.assertEqual(self.render("src/parse.c"), "")

    def test_unknown_file_renders_nothing(self) -> None:
        self.write(ARTIFACT)
        self.assertEqual(self.render("src/never-parsed.c"), "")

    def test_corrupt_artifact_renders_nothing(self) -> None:
        path = callgraph.artifact_path(self.results)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not json", encoding="utf-8")
        self.assertEqual(self.render("src/parse.c"), "")

    def test_future_version_renders_nothing(self) -> None:
        artifact = json.loads(json.dumps(ARTIFACT))
        artifact["version"] = callgraph.SCHEMA_VERSION + 1
        self.write(artifact)
        self.assertEqual(self.render("src/parse.c"), "")

    def test_path_is_normalised_like_a_work_card_file(self) -> None:
        self.write(ARTIFACT)
        self.assertNotEqual(self.render("./src/parse.c"), "")


class ExplainTests(unittest.TestCase):
    """`no block` has to come with a reason; every branch above is silent."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.results = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def write(self, artifact: dict) -> None:
        path = callgraph.artifact_path(self.results)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact), encoding="utf-8")

    def test_a_rendered_block_explains_nothing(self) -> None:
        self.write(ARTIFACT)
        self.assertEqual(callgraph.explain(self.results, "src/parse.c"), "")

    def test_an_unparsed_file_says_so(self) -> None:
        self.write(ARTIFACT)
        self.assertIn("not in the parsed graph", callgraph.explain(self.results, "src/other.c"))

    def test_a_recorded_skip_is_repeated_verbatim(self) -> None:
        self.write({"version": callgraph.SCHEMA_VERSION, "signature": "s", "skipped": "too big", "files": {}})
        self.assertEqual(callgraph.explain(self.results, "src/parse.c"), "too big")

    def test_a_missing_artifact_points_at_the_likely_cause(self) -> None:
        original = callgraph.interpreter
        callgraph.interpreter = lambda: ""
        self.addCleanup(setattr, callgraph, "interpreter", original)
        self.assertIn("pip install trailmark", callgraph.explain(self.results, "src/parse.c"))

        callgraph.interpreter = lambda: "/usr/bin/python3"
        self.assertIn("bin/rank-work", callgraph.explain(self.results, "src/parse.c"))


class RefreshTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "target").mkdir()
        (self.root / "results").mkdir()
        import workqueue
        self.ctx = workqueue.Context(
            ROOT, self.root / "target", "unit", self.root / "results", "none",
        )
        self.addCleanup(setattr, callgraph, "_RESOLVED", None)

    def _pin_interpreter(self, value: str) -> None:
        """Bypass discovery: these tests are about refresh, not selection."""
        original = callgraph.interpreter
        callgraph.interpreter = lambda: value
        self.addCleanup(setattr, callgraph, "interpreter", original)

    def test_no_interpreter_is_a_clean_opt_out(self) -> None:
        self._pin_interpreter("")
        self.assertEqual(callgraph.refresh(self.ctx), "no trailmark interpreter")

    def test_a_stale_artifact_is_dropped_even_when_no_rebuild_is_possible(self) -> None:
        # block_for is handed a results directory, not a target, so it cannot
        # re-check freshness. If refresh left the file, a map of source that
        # has since moved would keep being quoted into prompts.
        self._pin_interpreter("")
        self._pin_signature("sig-new")
        self._write_artifact("sig-old")
        self.assertEqual(callgraph.refresh(self.ctx), "no trailmark interpreter")
        self.assertIsNone(callgraph.load(self.ctx.results_dir))

    def test_a_fresh_artifact_survives_the_analysis_being_switched_off(self) -> None:
        self._pin_interpreter("")
        self._pin_signature("sig-a")
        self._write_artifact("sig-a")
        self.assertEqual(callgraph.refresh(self.ctx), "fresh")
        self.assertIsNotNone(callgraph.load(self.ctx.results_dir))

    def test_unusable_interpreter_never_raises(self) -> None:
        self._pin_interpreter(str(self.root / "no-such-python"))
        (self.root / "target" / "a.c").write_text("int f(void){return 0;}\n", encoding="utf-8")
        self.assertTrue(callgraph.refresh(self.ctx).startswith("unavailable"))
        self.assertEqual(callgraph.block_for(self.ctx.results_dir, "a.c"), [])

    def _pin_signature(self, value: str) -> None:
        original = callgraph.cache_signature
        callgraph.cache_signature = lambda root, results, artifacts=None: value
        self.addCleanup(setattr, callgraph, "_source_signature", original)

    def _write_artifact(self, signature: str) -> None:
        artifact = json.loads(json.dumps(ARTIFACT))
        artifact["signature"] = signature
        path = callgraph.artifact_path(self.root / "results")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(artifact), encoding="utf-8")

    def test_matching_signature_is_not_rebuilt(self) -> None:
        self._pin_interpreter(str(self.root / "no-such-python"))
        self._pin_signature("sig-a")
        self._write_artifact("sig-a")
        self.assertEqual(callgraph.refresh(self.ctx), "fresh")

    def test_changed_signature_rebuilds(self) -> None:
        self._pin_interpreter(str(self.root / "no-such-python"))
        self._pin_signature("sig-b")
        self._write_artifact("sig-a")
        (self.ctx.target_root / "a.c").write_text("int f(void){return 0;}\n", encoding="utf-8")
        self.assertTrue(callgraph.refresh(self.ctx).startswith("unavailable"))

    def test_a_target_with_no_vcs_signature_is_never_treated_as_fresh(self) -> None:
        # Caching against "" would pin one map for the life of the target and
        # keep serving it after the source moved.
        self._pin_interpreter(str(self.root / "no-such-python"))
        self._pin_signature("")
        self._write_artifact("")
        (self.ctx.target_root / "a.c").write_text("int f(void){return 0;}\n", encoding="utf-8")
        self.assertTrue(callgraph.refresh(self.ctx).startswith("unavailable"))

    def test_empty_tree_is_skipped_before_spawning(self) -> None:
        self._pin_interpreter(str(self.root / "no-such-python"))
        self.assertEqual(callgraph.refresh(self.ctx), "skipped: no auditable source")

    def test_a_recorded_refusal_still_renders_no_block(self) -> None:
        path = callgraph.artifact_path(self.ctx.results_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({"version": callgraph.SCHEMA_VERSION, "signature": "s", "skipped": "too big", "files": {}}),
            encoding="utf-8",
        )
        self.assertEqual(callgraph.block_for(self.ctx.results_dir, "src/parse.c"), [])

    def test_a_failure_is_cached_so_it_is_not_repeated_every_iteration(self) -> None:
        # A tree the parser cannot handle fails the same way every time, and
        # re-deriving that costs the audit wall. Safe to cache because the
        # fingerprint covers the interpreter and tool versions, so repairing
        # the environment invalidates the record on its own.
        self._pin_interpreter(str(self.root / "no-such-python"))
        self._pin_signature("sig-x")
        (self.ctx.target_root / "a.c").write_text("int f(void){return 0;}\n", encoding="utf-8")
        first = callgraph.refresh(self.ctx)
        self.assertTrue(first.startswith("unavailable"))
        self.assertEqual(callgraph.refresh(self.ctx), first)
        self.assertEqual(callgraph.block_for(self.ctx.results_dir, "a.c"), [])


class InterpreterDiscoveryTests(unittest.TestCase):
    """The analysis should find a usable interpreter without being told."""

    def setUp(self) -> None:
        callgraph._RESOLVED = None
        self.addCleanup(setattr, callgraph, "_RESOLVED", None)

    def _pin_candidates(self, values: list[str]) -> None:
        original = callgraph.candidate_interpreters
        callgraph.candidate_interpreters = lambda: values
        self.addCleanup(setattr, callgraph, "candidate_interpreters", original)

    def test_discovery_looks_at_this_process_then_path(self) -> None:
        candidates = callgraph.candidate_interpreters()
        # Running the harness from the environment holding trailmark is one of
        # the two documented routes; installing into a `python3` already on
        # PATH is the other.
        self.assertEqual(candidates[0], sys.executable)
        self.assertIn("python3", candidates)
        # A platform `python3` older than trailmark's floor is the reason the
        # versioned names are there at all.
        self.assertTrue(any(c.startswith("python3.1") for c in candidates))

    def test_discovery_takes_no_configuration(self) -> None:
        # Every candidate is derived, never read from the environment.
        os.environ["CALLGRAPH_PYTHON"] = "/opt/custom/python"
        self.addCleanup(os.environ.pop, "CALLGRAPH_PYTHON", None)
        self.assertNotIn("/opt/custom/python", callgraph.candidate_interpreters())

    def test_no_working_candidate_resolves_to_nothing(self) -> None:
        self._pin_candidates(["/nonexistent/python"])
        self.assertEqual(callgraph.interpreter(), "")

    def test_a_nonexistent_candidate_is_skipped_without_spawning(self) -> None:
        self._pin_candidates(["/nonexistent/python", "python3-also-absent"])
        self.assertEqual(callgraph.interpreter(), "")

    def test_resolution_is_memoised(self) -> None:
        self._pin_candidates(["/nonexistent/python"])
        self.assertEqual(callgraph.interpreter(), "")
        calls: list[int] = []
        callgraph.candidate_interpreters = lambda: calls.append(1) or []
        self.assertEqual(callgraph.interpreter(), "")
        self.assertEqual(calls, [])

    def test_the_probe_answers_for_the_interpreter_running_it(self) -> None:
        # Discovery and the real build must agree, so they ask the same code.
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "callgraph"), "--probe"],
            capture_output=True, text=True, check=False,
        )
        combined = proc.stdout + proc.stderr
        if proc.returncode == 0:
            self.assertIn("ready", combined)
        else:
            self.assertIn("unavailable", combined)

    def test_a_build_without_root_or_out_is_refused(self) -> None:
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "callgraph")],
            capture_output=True, text=True, check=False,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("--root", proc.stderr)


class RankWorkOutputTests(unittest.TestCase):
    """The analysis must not grow bin/rank-work's bounded summary."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "target" / "src").mkdir(parents=True)
        (self.root / "target" / "src" / "parser.c").write_text(
            "int parse(const char *s) { return s ? 1 : 0; }\n", encoding="utf-8",
        )
        (self.root / "results").mkdir()

    def _run(self) -> str:
        import subprocess
        proc = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "rank-work"),
             "--results-dir", str(self.root / "results"),
             "--target-path", str(self.root / "target"),
             "--target-slug", "unit",
             "--limit", "20", "--llm-top-n", "0", "--summary-limit", "1"],
            capture_output=True, text=True, check=False,
            env={**os.environ, "LLM_DECIDE_DISABLE": "1"},
        )
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        return proc.stdout

    def test_the_summary_stays_within_its_line_budget(self) -> None:
        # Whether or not trailmark resolves on this host, the compact summary
        # is the same height: the status rides on the existing first line.
        # An unconditional extra line broke tests/test_workqueue.py once.
        self.assertLessEqual(len(self._run().splitlines()), 5)

    def test_the_status_rides_on_the_first_line(self) -> None:
        self.assertTrue(self._run().splitlines()[0].startswith("rank-work: wrote "))

    def test_an_unchanged_rebuild_says_nothing(self) -> None:
        # "fresh" is the steady state across a long run; naming it every
        # iteration is noise the operator has to read past.
        self._run()
        self.assertNotIn("(call neighbourhood: fresh)", self._run())
        self.assertLessEqual(len(self._run().splitlines()), 5)


class UntrustedTargetTests(unittest.TestCase):
    """The audited tree must not be able to author the evidence we render."""

    def test_the_mirror_carries_only_auditable_files(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "target" / ".trailmark").mkdir(parents=True)
        (root / "target" / "src.c").write_text("int main(void){return 0;}\n", encoding="utf-8")
        (root / "target" / ".trailmark" / "links.toml").write_text(
            '[[link]]\nsource = "a"\ntarget = "b"\n', encoding="utf-8",
        )
        mirror = root / "mirror"
        mirror.mkdir()
        callgraph._link_sources(root / "target", ["src.c"], mirror)
        present = {p.name for p in mirror.rglob("*")}
        self.assertIn("src.c", present)
        # trailmark reads .trailmark/links.toml from the root it is given, and
        # a link entry may declare a call edge at confidence "certain". The
        # mirror is the only thing standing between that file and a rendered
        # entry path.
        self.assertNotIn(".trailmark", present)
        self.assertNotIn("links.toml", present)
        self.assertTrue((mirror / "src.c").is_symlink())
        self.assertEqual((mirror / "src.c").read_text(), "int main(void){return 0;}\n")


class RealTrailmarkTests(unittest.TestCase):
    """End to end against the real parser, when one is installed.

    The mock tests prove the mirror omits `.trailmark/`; only this proves the
    fabricated route it would have carried is actually gone.
    """

    def setUp(self) -> None:
        if not callgraph.interpreter():
            self.skipTest("no interpreter can run the analysis")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "target" / ".trailmark").mkdir(parents=True)
        (self.root / "results").mkdir()
        (self.root / "target" / "app.c").write_text(
            "static void helper(void) { }\n"
            "int main(void) { helper(); return 0; }\n"
            "void sink(const char *p) { (void)p; }\n",
            encoding="utf-8",
        )
        (self.root / "target" / ".trailmark" / "links.toml").write_text(
            '[[link]]\nsource = "app:main"\ntarget = "app:sink"\n'
            'kind = "calls"\nconfidence = "certain"\n',
            encoding="utf-8",
        )
        import workqueue
        self.ctx = workqueue.Context(
            ROOT, self.root / "target", "unit", self.root / "results", "none",
        )

    def test_a_target_authored_edge_never_becomes_a_route(self) -> None:
        self.assertEqual(callgraph.refresh(self.ctx), "built")
        data = callgraph.load(self.ctx.results_dir)
        routes = {row["function"]: row["path"] for row in data["files"]["app.c"]["paths"]}
        # main() calls helper() and nothing else. The links.toml entry claims
        # main -> sink at confidence "certain"; honouring it would put a
        # fabricated route in front of an agent.
        self.assertEqual(routes.get("sink"), [])
        self.assertEqual(routes.get("helper"), ["main", "helper"])


class StatusLineTests(unittest.TestCase):
    """The run log has to say whether this contributed, either way."""

    def setUp(self) -> None:
        self.addCleanup(setattr, callgraph, "_RESOLVED", None)
        self.addCleanup(setattr, callgraph, "_TOOLCHAIN", "")

    def test_an_absent_analysis_warns_and_says_how_to_enable_it(self) -> None:
        callgraph._RESOLVED, callgraph._TOOLCHAIN = "", ""
        line = callgraph.status()
        self.assertTrue(line.startswith("WARN:"), line)
        self.assertIn("pip install trailmark", line)

    def test_an_available_analysis_records_interpreter_and_versions(self) -> None:
        callgraph._RESOLVED = "/usr/bin/python3.12"
        callgraph._TOOLCHAIN = "trailmark=0.5.0 tree-sitter=0.25.2"
        line = callgraph.status()
        self.assertFalse(line.startswith("WARN:"), line)
        self.assertIn("/usr/bin/python3.12", line)
        self.assertIn("trailmark=0.5.0", line)

    def test_the_run_start_banner_emits_it(self) -> None:
        import audit_runner
        self.assertIn("status", audit_runner.initialize_backend.__code__.co_names)


class FingerprintTests(unittest.TestCase):
    """Every input to the graph has to reach the signature that gates a rebuild."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "target").mkdir()
        (self.root / "results").mkdir()
        import workqueue
        self.ctx = workqueue.Context(
            ROOT, self.root / "target", "unit", self.root / "results", "none",
        )
        self.artifact = self.root / "target" / "app"
        self.artifact.write_bytes(b"one")
        callgraph._RESOLVED, callgraph._TOOLCHAIN = "/usr/bin/python3", "trailmark=0.5.0"
        self.addCleanup(setattr, callgraph, "_RESOLVED", None)
        self.addCleanup(setattr, callgraph, "_TOOLCHAIN", "")
        original = target_config.vcs_source_signature
        target_config.vcs_source_signature = lambda root, **kw: "src-1"
        self.addCleanup(setattr, target_config, "vcs_source_signature", original)

    def sign(self) -> str:
        return callgraph.cache_signature(
            self.ctx.target_root, self.ctx.results_dir,
            (str(self.artifact), str(self.artifact)))

    def test_rebuilding_the_artifact_in_place_changes_the_signature(self) -> None:
        before = self.sign()
        self.artifact.write_bytes(b"two")
        self.assertNotEqual(before, self.sign())

    def test_retargeting_to_another_artifact_changes_the_signature(self) -> None:
        before = self.sign()
        other = self.root / "target" / "other"
        other.write_bytes(b"one")
        self.assertNotEqual(
            before, callgraph.cache_signature(
                self.ctx.target_root, self.ctx.results_dir, (str(other), str(other))),
        )

    def test_a_toolchain_upgrade_changes_the_signature(self) -> None:
        before = self.sign()
        callgraph._TOOLCHAIN = "trailmark=0.6.0"
        self.assertNotEqual(before, self.sign())

    def test_no_analysis_means_no_key(self) -> None:
        # The outer gate folds this in; with nothing installed it must not
        # churn work cards on its own.
        callgraph._RESOLVED = ""
        self.assertEqual(self.sign(), "")

    def test_the_outer_work_card_gate_sees_it(self) -> None:
        # refresh_work_cards can return before rank-work ever runs, so the
        # inner fingerprint alone never fires.
        import audit_runner
        self.assertIn("callgraph", audit_runner._work_card_signature.__code__.co_names)


class SanitizerRouteTests(unittest.TestCase):
    """A target with no ASan build still has a boundary."""

    def _config(self, body: str) -> tuple[str, str]:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "results").mkdir()
        (root / "build-ubsan").mkdir()
        binary = root / "build-ubsan" / "app"
        binary.write_bytes(b"x")
        binary.chmod(0o755)
        (root / "target.toml").write_text(body, encoding="utf-8")
        import workqueue
        ctx = workqueue.Context(ROOT, root, "unit", root / "results", "none")
        original = target_config.find_target_toml
        target_config.find_target_toml = lambda start: root / "target.toml"
        self.addCleanup(setattr, target_config, "find_target_toml", original)
        return callgraph._built_artifacts(root, root / "results")

    def test_a_ubsan_only_target_selects_its_own_route(self) -> None:
        api, entry = self._config(
            # Only asan_bin is top-level; the other routes live in [sanitizer].
            'target = "unit"\n'
            "[sanitizer]\nenabled = [\"ubsan\"]\n"
            'ubsan_bin = "build-ubsan/app"\n'
        )
        self.assertTrue(entry.endswith("build-ubsan/app"), entry)
        self.assertEqual(api, entry)

    def test_a_findings_only_target_has_no_artifacts(self) -> None:
        api, entry = self._config('target = "unit"\n[sanitizer]\nenabled = []\n')
        self.assertEqual((api, entry), ("", ""))


class SymbolTableTests(unittest.TestCase):
    """The sanitizer artifact is the oracle; misreading it corrupts coverage."""

    def setUp(self) -> None:
        self.sidecar = _sidecar()

    def test_macho_underscore_is_stripped_once_for_the_whole_artifact(self) -> None:
        names = native_symbols.normalise({"_app_parse", "_app_open", "_asan.module_ctor"})
        self.assertEqual(names, {"app_parse", "app_open"})

    def test_elf_names_are_left_alone(self) -> None:
        names = native_symbols.normalise({"app_parse", "app_open", "_pcre2_internal"})
        self.assertEqual(names, {"app_parse", "app_open", "_pcre2_internal"})

    def test_missing_artifact_yields_no_symbols(self) -> None:
        self.assertEqual(self.sidecar.defined_symbols(Path("/nonexistent/libapp.so")), set())

    def test_the_sidecar_reads_the_shared_symbol_module(self) -> None:
        """One reader for one question, shared with lib/fuzz_harness."""
        self.assertIs(self.sidecar.defined_symbols, native_symbols.defined_symbols)

    def test_the_shared_symbol_module_stays_stdlib_only(self) -> None:
        """bin/callgraph runs under trailmark's interpreter, which is
        guaranteed to have trailmark and nothing else. A third-party import
        here would break the sidecar on an interpreter the harness never
        chose."""
        source = (ROOT / "lib" / "native_symbols.py").read_text(encoding="utf-8")
        imported = {
            name.split(".")[0]
            for name in re.findall(r"^(?:import|from)\s+([\w.]+)", source, re.M)
        }
        # Named rather than checked against sys.stdlib_module_names, which is
        # 3.10+: the harness still supports the 3.9 a stock macOS ships, and a
        # test that cannot run there does not guard anything there.
        allowed = {"__future__", "subprocess", "pathlib", "os", "sys", "re"}
        self.assertTrue(imported <= allowed,
                        f"non-stdlib or unvetted imports: {imported - allowed}")


class EntryBoundaryTests(unittest.TestCase):
    """Which `main` belongs to the configured binary."""

    class FakeStore:
        def __init__(self, entrypoints, reachable):
            self._entrypoints = entrypoints
            self._reachable = reachable

        def all_entrypoints(self):
            return [(node, None) for node in self._entrypoints]

        def reachable_from(self, node):
            return self._reachable.get(node, [])

    def setUp(self) -> None:
        self.sidecar = _sidecar()

    def test_closure_picks_the_main_that_reaches_the_binary(self) -> None:
        name_of = {"app:main": "main", "driver:main": "main", "core:work": "work"}
        store = self.FakeStore(
            ["app:main", "driver:main"],
            {"app:main": ["core:work"], "driver:main": []},
        )
        roots, basis = self.sidecar._entry_roots(store, name_of, {"work"}, {"work"})
        self.assertEqual((roots, basis), (["app:main"], "cli-main"))

    def test_a_tie_falls_through_to_the_exported_surface(self) -> None:
        # Every driver exports only `main`, so nothing discriminates. Guessing
        # a winner would anchor every path on an arbitrary test binary.
        name_of = {"a:main": "main", "b:main": "main", "lib:api": "api"}
        store = self.FakeStore(["a:main", "b:main"], {})
        roots, basis = self.sidecar._entry_roots(
            store, name_of, {"main"}, {"api", "main"},
        )
        self.assertEqual((roots, basis), (["lib:api"], "exported-api"))

    def test_exported_roots_never_include_a_driver_main(self) -> None:
        name_of = {"a:main": "main", "lib:api": "api"}
        store = self.FakeStore([], {})
        roots, _ = self.sidecar._entry_roots(store, name_of, set(), {"api", "main"})
        self.assertEqual(roots, ["lib:api"])


class ShortestPathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sidecar = _sidecar()

    def test_one_traversal_answers_every_function(self) -> None:
        callees = {"main": {"a", "b"}, "a": {"deep"}, "b": {"deep"}}
        paths = self.sidecar._shortest_paths(["main"], callees)
        self.assertEqual(paths["main"], ["main"])
        self.assertEqual(len(paths["deep"]), 3)
        self.assertNotIn("unrelated", paths)

    def test_cycles_terminate(self) -> None:
        callees = {"main": {"a"}, "a": {"b"}, "b": {"a", "c"}}
        paths = self.sidecar._shortest_paths(["main"], callees)
        self.assertEqual(paths["c"], ["main", "a", "b", "c"])


if __name__ == "__main__":
    unittest.main()
