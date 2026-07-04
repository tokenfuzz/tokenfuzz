<?php

declare(strict_types=1);

/**
 * reportkit_cli — command-line front end for the ReportKit toolkit.
 *
 * Reads one *job file* and performs a single ReportKit operation with it. This
 * is the entry point an audit harness (or a CI step) drives: it turns a file on
 * disk into exactly one library call so a report task can be scripted.
 *
 * Job-file format — a header line naming the operation, then an
 * operation-specific body:
 *
 *     op: render
 *     {"price": 3, "quantity": 4}
 *     Total is {{ $price * $quantity }}.
 *
 * The first line is always "op: <name>". The remaining lines are the body:
 *
 *     render    first body line is a JSON object (the context); the rest is the
 *               template whose {{ ... }} placeholders are filled from it.
 *     state     the body is a serialized state string to restore.
 *     verify    first body line is a report id; the second is its export token.
 *     export    the body is the name of an export hook to run.
 *     asset     first body line is the project root; the second is the name.
 *     config    the body is a JSON configuration document to parse.
 *     command   the body is a single data argument echoed by a fixed tool.
 */

require __DIR__ . '/src/ReportKit.php';

/** @return array{0:string,1:string} */
function split_job(string $text): array
{
    $parts = explode("\n", $text, 2);
    $header = $parts[0];
    $body = $parts[1] ?? '';
    $head = explode(':', $header, 2);
    if (trim($head[0]) !== 'op') {
        throw new RuntimeException('job file must begin with "op: <name>"');
    }
    return [trim($head[1] ?? ''), $body];
}

function run_render(string $body): string
{
    [$contextLine, $template] = array_pad(explode("\n", $body, 2), 2, '');
    $context = trim($contextLine) === '' ? [] : json_decode($contextLine, true, 512, JSON_THROW_ON_ERROR);
    return ReportKit::renderTemplate($template, $context);
}

function run_state(string $body): string
{
    return var_export(ReportKit::loadState(trim($body)), true);
}

function run_verify(string $body): string
{
    [$reportId, $token] = array_pad(explode("\n", $body, 2), 2, '');
    return ReportKit::tokenAuthorised(trim($reportId), trim($token)) ? 'authorised' : 'denied';
}

function run_export(string $body): string
{
    return ReportKit::runExport(trim($body));
}

function run_asset(string $body): string
{
    [$root, $name] = array_pad(explode("\n", $body, 2), 2, '');
    return ReportKit::readAsset(trim($name), trim($root));
}

function run_config(string $body): string
{
    return var_export(ReportKit::parseConfig(trim($body)), true);
}

function run_command(string $body): string
{
    return ReportKit::runCommand(trim($body));
}

$operations = [
    'render' => 'run_render',
    'state' => 'run_state',
    'verify' => 'run_verify',
    'export' => 'run_export',
    'asset' => 'run_asset',
    'config' => 'run_config',
    'command' => 'run_command',
];

function main(array $argv): int
{
    global $operations;
    if (count($argv) !== 2) {
        fwrite(STDERR, "usage: {$argv[0]} job-file\n");
        return 2;
    }

    [$op, $body] = split_job((string) file_get_contents($argv[1]));
    if (!isset($operations[$op])) {
        fwrite(STDERR, "unknown operation: {$op}\n");
        return 1;
    }

    echo $op, ': ', $operations[$op]($body), "\n";
    return 0;
}

exit(main($argv));
