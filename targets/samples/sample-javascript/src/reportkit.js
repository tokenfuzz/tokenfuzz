'use strict';

/**
 * reportkit — a small toolkit for rendering configuration-driven reports.
 *
 * A report is assembled from a few ingredients: a *state* object merged across
 * runs, a set of *templates* whose `{{ ... }}` placeholders are filled from a
 * context, named export hooks, report assets read from a project directory,
 * and report *includes* loaded from that directory. The API is intentionally
 * compact so it can be embedded in build scripts and CI steps. Every entry
 * point takes caller-supplied text or objects.
 */

const cp = require('child_process');
const fs = require('fs');
const path = require('path');

// Placeholder syntax: {{ expression }} with optional surrounding whitespace.
const PLACEHOLDER = /\{\{\s*(.*?)\s*\}\}/g;

/**
 * Evaluate a single template expression against `context`.
 *
 * Expressions are small arithmetic or lookups such as `price * quantity`. The
 * context keys are exposed as parameter names so templates can reference report
 * values directly.
 */
function evaluateExpr(expr, context) {
  const names = Object.keys(context);
  const values = names.map((name) => context[name]);
  const fn = new Function(...names, `return (${expr});`);
  return fn(...values);
}

/** Fill every {{ ... }} placeholder in `template` from `context`. */
function renderTemplate(template, context) {
  return template.replace(PLACEHOLDER, (_match, expr) => String(evaluateExpr(expr, context)));
}

/**
 * Merge a saved state patch into a base state, recursing into nested objects
 * so incremental runs can layer cached values on top of previous ones.
 */
function mergeState(base, patch) {
  for (const key of Object.keys(patch)) {
    if (patch[key] && typeof patch[key] === 'object') {
      if (!base[key]) {
        base[key] = {};
      }
      mergeState(base[key], patch[key]);
    } else {
      base[key] = patch[key];
    }
  }
  return base;
}

/** Run a named export hook and return its stdout. */
function runExport(hook) {
  return cp.execSync(hook).toString();
}

/** Read a named report asset from the project's asset directory. */
function readAsset(name, root) {
  return fs.readFileSync(path.join(root, name), 'utf8');
}

/** Load a named report include from the project's include directory. */
function loadInclude(name, root) {
  return require(path.resolve(root, name));
}

/**
 * Parse a small configuration document from `text`.
 *
 * The document is JSON, so `__proto__` keys become ordinary own properties on
 * the returned object rather than touching any prototype. Untrusted config text
 * cannot pollute a prototype here.
 */
function parseConfig(text) {
  return JSON.parse(text);
}

/**
 * Echo a caller-supplied data argument through a fixed reporting tool.
 *
 * Unlike `runExport`, the executable is fixed and the argument is passed as a
 * single argv element with no shell, so a caller controls neither which program
 * runs nor a shell to interpret metacharacters.
 */
function runCommand(arg) {
  return cp.execFileSync('echo', [arg]).toString();
}

module.exports = {
  evaluateExpr,
  renderTemplate,
  mergeState,
  runExport,
  readAsset,
  loadInclude,
  parseConfig,
  runCommand,
};
