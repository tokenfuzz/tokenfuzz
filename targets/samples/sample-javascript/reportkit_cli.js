'use strict';

/**
 * reportkit_cli — command-line front end for the reportkit toolkit.
 *
 * Reads one *job file* and performs a single reportkit operation with it. This
 * is the entry point an audit harness (or a CI step) drives: it turns a file on
 * disk into exactly one library call so a report task can be scripted.
 *
 * Job-file format — a header line naming the operation, then an
 * operation-specific body:
 *
 *     op: render
 *     {"price": 3, "quantity": 4}
 *     Total is {{ price * quantity }}.
 *
 * The first line is always "op: <name>". The remaining lines are the body:
 *
 *     render    first body line is a JSON object (the context); the rest is the
 *               template whose {{ ... }} placeholders are filled from it.
 *     state     the body is a JSON state patch to merge into a fresh state.
 *     export    the body is the name of an export hook to run.
 *     asset     first body line is the project root; the second is the name.
 *     include   first body line is the include root; the second is the name.
 *     config    the body is a JSON configuration document to parse.
 *     command   the body is a single data argument echoed by a fixed tool.
 */

const fs = require('fs');
const reportkit = require('./src/reportkit');

function splitJob(text) {
  const nl = text.indexOf('\n');
  const header = nl === -1 ? text : text.slice(0, nl);
  const body = nl === -1 ? '' : text.slice(nl + 1);
  const [prefix, name = ''] = header.split(/:(.*)/s);
  if (prefix.trim() !== 'op') {
    throw new Error('job file must begin with "op: <name>"');
  }
  return { op: name.trim(), body };
}

function firstRest(body) {
  const nl = body.indexOf('\n');
  return nl === -1 ? [body, ''] : [body.slice(0, nl), body.slice(nl + 1)];
}

const OPERATIONS = {
  render(body) {
    const [contextLine, template] = firstRest(body);
    const context = contextLine.trim() ? JSON.parse(contextLine) : {};
    return reportkit.renderTemplate(template, context);
  },
  state(body) {
    reportkit.mergeState({}, JSON.parse(body));
    return `polluted=${JSON.stringify({}.polluted)}`;
  },
  export(body) {
    return reportkit.runExport(body.trim());
  },
  asset(body) {
    const [root, name] = firstRest(body);
    return reportkit.readAsset(name.trim(), root.trim());
  },
  include(body) {
    const [root, name] = firstRest(body);
    return String(reportkit.loadInclude(name.trim(), root.trim()));
  },
  config(body) {
    return JSON.stringify(reportkit.parseConfig(body.trim()));
  },
  command(body) {
    return reportkit.runCommand(body.trim());
  },
};

function main(argv) {
  if (argv.length !== 1) {
    process.stderr.write(`usage: reportkit_cli.js job-file\n`);
    return 2;
  }

  const { op, body } = splitJob(fs.readFileSync(argv[0], 'utf8'));
  const handler = OPERATIONS[op];
  if (!handler) {
    process.stderr.write(`unknown operation: ${op}\n`);
    return 1;
  }

  process.stdout.write(`${op}: ${handler(body)}\n`);
  return 0;
}

process.exit(main(process.argv.slice(2)));
