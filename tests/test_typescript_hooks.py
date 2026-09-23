#!/usr/bin/env python3
"""The Node runner's TypeScript hooks: preload wiring, resolution, transpile."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "lib"))

import sanitizer_run

NODE = shutil.which("node")

# Enough of the typescript API for the hooks: tsconfig lookup, `paths`
# resolution and a transpile that echoes the options it was given. Fixture
# sources are already CommonJS, so echoing them is a faithful "transpile".
FAKE_TYPESCRIPT = textwrap.dedent("""\
    const fs = require("fs"), path = require("path");
    exports.ModuleKind = { CommonJS: 1, ESNext: 99 };
    exports.ScriptTarget = { Latest: 99 };
    exports.SyntaxKind = { AwaitExpression: 1 };
    exports.createSourceFile = () => ({});
    exports.forEachChild = () => undefined;
    exports.isFunctionLike = () => false;
    exports.isClassLike = () => false;
    exports.isForOfStatement = () => false;
    exports.sys = { fileExists: fs.existsSync, readFile: (f) => fs.readFileSync(f, "utf8") };
    exports.findConfigFile = (dir, exists) => {
      for (let d = dir; ; d = path.dirname(d)) {
        if (exists(path.join(d, "tsconfig.json"))) return path.join(d, "tsconfig.json");
        if (path.dirname(d) === d) return undefined;
      }
    };
    exports.readConfigFile = (file, read) => ({ config: JSON.parse(read(file)) });
    exports.parseJsonConfigFileContent = (json, _host, dir) =>
      ({ options: { ...json.compilerOptions, configDir: dir } });
    exports.resolveModuleName = (spec, _parent, options) => {
      const alias = /^@fixture\\/(.*)$/.exec(spec);
      return alias ? { resolvedModule: { resolvedFileName:
        path.join(options.configDir, "lib", alias[1] + ".ts") } } : {};
    };
    exports.transpileModule = (source, { compilerOptions: o }) => ({ outputText:
      `exports.options = ${JSON.stringify({ module: o.module,
        experimentalDecorators: o.experimentalDecorators,
        emitDecoratorMetadata: o.emitDecoratorMetadata })};\\n` + source });
""")


def node_supports_hooks() -> bool:
    if not NODE:
        return False
    probe = subprocess.run(
        [NODE, "-p", "typeof require('node:module').registerHooks === 'function'"
         " && Boolean(process.features.typescript)"],
        capture_output=True, text=True, check=False,
    )
    return probe.stdout.strip() == "true"


def node_hooks_imported_cjs_requires() -> bool:
    """Whether Node runs module hooks for require() in CJS an ES module imported.

    Before nodejs/node#62920 (24.18 and 26.2), a CommonJS module imported with
    hook-supplied source got a re-invented require() that skips the hooks.
    """
    if not NODE:
        return False
    probe = subprocess.run(
        [NODE, "-p", "process.versions.node"], capture_output=True, text=True, check=False,
    )
    version = tuple(int(part) for part in probe.stdout.strip().split(".")[:2])
    return version >= (26, 2) or (24, 18) <= version < (25, 0)


class NodeOptionsTests(unittest.TestCase):
    def test_node_runner_preloads_the_hooks_after_the_targets_options(self) -> None:
        options = sanitizer_run.node_options(
            "/usr/local/bin/node", {"NODE_OPTIONS": "--max-old-space-size=512"},
        )
        self.assertEqual(
            options["NODE_OPTIONS"],
            f"--max-old-space-size=512 --require "
            f"{json.dumps(str(sanitizer_run.TYPESCRIPT_HOOKS))}",
        )
        self.assertTrue(sanitizer_run.TYPESCRIPT_HOOKS.is_file())
        self.assertEqual(sanitizer_run.node_options("/opt/build-asan/app", {}), {})
        # NODE_OPTIONS does not decode JSON's \u escapes.
        with mock.patch.object(sanitizer_run, "TYPESCRIPT_HOOKS", Path("/tmp/dé j/h.cjs")):
            self.assertIn('"/tmp/dé j/h.cjs"', sanitizer_run.node_options("node", {})["NODE_OPTIONS"])


@unittest.skipUnless(node_supports_hooks(), "needs Node with registerHooks and type stripping")
class TypeScriptHooksTests(unittest.TestCase):
    def run_node(self, project: Path, entry: str) -> subprocess.CompletedProcess:
        environment = {"PATH": str(Path(NODE).parent)}
        environment.update(sanitizer_run.node_options(NODE, environment))
        return subprocess.run(
            [NODE, str(project / entry)], cwd=project, env=environment,
            capture_output=True, text=True, timeout=60, check=False,
        )

    def write(self, root: Path, files: dict[str, str]) -> None:
        for name, text in files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def check_paths_project(self, entry: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            self.write(project, {
                "node_modules/typescript/package.json": '{"main": "index.js"}',
                "node_modules/typescript/index.js": FAKE_TYPESCRIPT,
                "tsconfig.json": json.dumps({"compilerOptions": {
                    "experimentalDecorators": True, "emitDecoratorMetadata": True,
                }}),
                "src/entry.ts": 'exports.value = require("@fixture/value").value;\n',
                "lib/value.ts": 'exports.value = "from-paths";\n',
                "main.cjs": 'console.log(JSON.stringify(require("./src/entry.js")));\n',
                "main.mjs": 'import entry from "./src/entry.js";\n'
                            "console.log(JSON.stringify(entry));\n",
            })
            result = self.run_node(project, entry)
            self.assertEqual(result.returncode, 0, result.stderr)
            loaded = json.loads(result.stdout)
            # `.js` named the `.ts` source; the alias resolved through tsconfig.
            self.assertEqual(loaded["value"], "from-paths")
            self.assertEqual(loaded["options"], {
                "module": 1, "experimentalDecorators": True,
                "emitDecoratorMetadata": False,
            })

    def test_the_targets_typescript_resolves_paths_and_transpiles_to_commonjs(self) -> None:
        self.check_paths_project("main.cjs")

    @unittest.skipUnless(node_hooks_imported_cjs_requires(),
                         "needs Node 24.18+ or 26.2+ (nodejs/node#62920)")
    def test_an_es_module_testcase_reaches_the_same_resolution(self) -> None:
        self.check_paths_project("main.mjs")

    def test_without_typescript_node_strips_types_after_extension_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory)
            self.write(project, {
                "package.json": '{"type": "module"}',
                "util.ts": "export const count: number = 3;\n",
                "main.mjs": 'import { count } from "./util";\nconsole.log(count);\n',
                "missing.mjs": 'import "./absent";\n',
            })
            result = self.run_node(project, "main.mjs")
            self.assertEqual((result.returncode, result.stdout.strip()), (0, "3"), result.stderr)
            # A specifier nothing can satisfy keeps Node's own diagnostic.
            missing = self.run_node(project, "missing.mjs")
            self.assertNotEqual(missing.returncode, 0)
            self.assertIn("ERR_MODULE_NOT_FOUND", missing.stderr)
            self.assertIn("imported from", missing.stderr)


if __name__ == "__main__":
    unittest.main()
