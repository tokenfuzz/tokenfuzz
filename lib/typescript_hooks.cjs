"use strict";
// Preloaded (NODE_OPTIONS=--require) into every Node runner execution by
// lib/sanitizer_run.py so a testcase can import a TypeScript target's source.
//
// Node's own type stripping handles erasable syntax only: it rejects
// decorators, parameter properties and enums, and it cannot resolve the
// extensionless, `.js`-for-`.ts` or tsconfig `paths` specifiers that real
// TypeScript projects are written with. Both jobs are handed to the target's
// own `typescript` package under the target's own tsconfig, which is exactly
// how the project compiles. A target without `typescript` keeps Node's
// behaviour plus the plain-extension fallback, and a JavaScript module is
// never touched: resolution only retries after Node itself failed.

const fs = require("node:fs");
const path = require("node:path");
const nodeModule = require("node:module");
const { fileURLToPath, pathToFileURL } = require("node:url");

const TYPESCRIPT_SOURCE = /\.(?:ts|tsx|mts|cts)$/;
const RESOLUTION_FAILURES = new Set([
  "ERR_MODULE_NOT_FOUND", "ERR_UNSUPPORTED_DIR_IMPORT", "MODULE_NOT_FOUND",
  "ERR_PACKAGE_PATH_NOT_EXPORTED",
]);
const compilers = new Map();
const projects = new Map();

function compilerFor(file) {
  const directory = path.dirname(file);
  if (!compilers.has(directory)) {
    // This require runs through these hooks, and a failed lookup from a .ts
    // file asks for its compiler again: settle the entry first or that
    // recursion runs until the stack overflows.
    compilers.set(directory, null);
    try {
      compilers.set(directory, nodeModule.createRequire(file)("typescript"));
    } catch (error) {
      // No typescript package: Node's own stripping is the route.
      if (!error || error.code !== "MODULE_NOT_FOUND") {
        // A broken compiler fails every file, not only the first.
        compilers.delete(directory);
        throw error;
      }
    }
  }
  return compilers.get(directory);
}

function optionsFor(ts, file) {
  const config = ts.findConfigFile(path.dirname(file), ts.sys.fileExists);
  if (!projects.has(config)) {
    let options = {};
    if (config) {
      const read = ts.readConfigFile(config, ts.sys.readFile);
      // No directory listing: only the options (with `extends`) are needed,
      // and expanding a monorepo's include globs would cost every run.
      const host = { ...ts.sys, readDirectory: () => [] };
      options = ts.parseJsonConfigFileContent(
        read.config || {}, host, path.dirname(config),
      ).options;
    }
    projects.set(config, options);
  }
  return projects.get(config);
}

function packageType(file) {
  for (let directory = path.dirname(file); ; directory = path.dirname(directory)) {
    try {
      return JSON.parse(fs.readFileSync(path.join(directory, "package.json"), "utf8")).type || "";
    } catch {
      // No readable manifest here; keep walking as Node does.
    }
    if (path.dirname(directory) === directory) return "";
  }
}

function hasTopLevelAwait(ts, file, source) {
  const visit = (node) => {
    if (ts.isFunctionLike(node) || ts.isClassLike(node)) return false;
    if (node.kind === ts.SyntaxKind.AwaitExpression) return true;
    if (ts.isForOfStatement(node) && node.awaitModifier) return true;
    return ts.forEachChild(node, visit) || false;
  };
  const tree = ts.createSourceFile(file, source, ts.ScriptTarget.Latest, false);
  return Boolean(ts.forEachChild(tree, visit));
}

// A transpile sees one file, so it cannot tell a re-exported interface from a
// value, and ESM linking rejects the missing export that leaves. A project
// declaring isolatedModules or verbatimModuleSyntax marks type exports, so its
// files take the module format Node itself would give them. Any other
// project's files are CommonJS, which reads such an export as undefined,
// unless the file can only be a module.
function formatFor(ts, file, source, options) {
  if (file.endsWith(".mts")) return "module";
  if (file.endsWith(".cts") || /^\s*(?:export\s*=|import\s+[\w$]+\s*=\s*require\s*\()/m.test(source)) {
    return "commonjs";
  }
  if (/\bimport\.meta\b/.test(source) || hasTopLevelAwait(ts, file, source)) return "module";
  if (packageType(file) === "commonjs") return "commonjs";
  if (options.isolatedModules || options.verbatimModuleSyntax) {
    return /^\s*(?:import|export)\b/m.test(source) ? "module" : "commonjs";
  }
  return "commonjs";
}

function isPathSpecifier(specifier) {
  return /^(?:\.{1,2}\/|\/|file:)/.test(specifier);
}

function extensionCandidates(specifier) {
  const swapped = specifier.replace(/\.([cm]?)js(x?)$/, (_all, kind, jsx) => `.${kind}ts${jsx}`);
  if (swapped !== specifier) return [swapped];
  return [".ts", ".tsx", "/index.ts", "/index.tsx"].map((suffix) => specifier + suffix);
}

function resolve(specifier, context, nextResolve) {
  try {
    return nextResolve(specifier, context);
  } catch (error) {
    const parent = context.parentURL;
    if (!RESOLUTION_FAILURES.has(error && error.code) || !parent || !parent.startsWith("file:")) {
      throw error;
    }
    const parentFile = fileURLToPath(parent);
    const ts = TYPESCRIPT_SOURCE.test(parentFile) ? compilerFor(parentFile) : null;
    if (ts) {
      const found = ts.resolveModuleName(
        specifier, parentFile, optionsFor(ts, parentFile), ts.sys,
      ).resolvedModule;
      if (found && !found.resolvedFileName.endsWith(".d.ts")) {
        return { url: pathToFileURL(found.resolvedFileName).href, shortCircuit: true };
      }
    }
    if (isPathSpecifier(specifier)) {
      for (const candidate of extensionCandidates(specifier)) {
        try {
          return nextResolve(candidate, context);
        } catch (retry) {
          // Try the next spelling; the original error is the one to report.
          if (!RESOLUTION_FAILURES.has(retry && retry.code)) throw retry;
        }
      }
    }
    throw error;
  }
}

function load(url, context, nextLoad) {
  if (!url.startsWith("file:")) return nextLoad(url, context);
  const file = fileURLToPath(url);
  if (!TYPESCRIPT_SOURCE.test(file)) return nextLoad(url, context);
  const ts = compilerFor(file);
  if (!ts) return nextLoad(url, context);
  const source = fs.readFileSync(file, "utf8");
  const options = optionsFor(ts, file);
  const format = formatFor(ts, file, source, options);
  const output = ts.transpileModule(source, {
    fileName: file,
    compilerOptions: {
      ...options,
      module: format === "module" ? ts.ModuleKind.ESNext : ts.ModuleKind.CommonJS,
      declaration: false,
      noEmit: false,
      // A per-file transpile emits a parameter type that a later class in the
      // same file declares, and the module then fails before any code runs.
      emitDecoratorMetadata: false,
      // Output-layout options would relocate the source map's file names.
      rootDir: undefined,
      outDir: undefined,
      sourceRoot: undefined,
      mapRoot: undefined,
      sourceMap: false,
      inlineSourceMap: true,
      inlineSources: false,
    },
  }).outputText;
  // Stack frames then name the .ts line an agent reads and a report cites.
  process.setSourceMapsEnabled(true);
  return { format, source: output, shortCircuit: true };
}

if (typeof nodeModule.registerHooks === "function") {
  nodeModule.registerHooks({ resolve, load });
}
