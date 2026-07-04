<?php

declare(strict_types=1);

/**
 * ReportKit — a small toolkit for rendering configuration-driven reports.
 *
 * A report is assembled from a few ingredients: an *outline* of sections, a
 * *state* blob carrying cached values between runs, a set of *templates* whose
 * `{{ ... }}` placeholders are filled from a context, and a signed *token* that
 * authorises privileged export hooks. The toolkit also runs named export hooks
 * and reads report assets from a project directory.
 *
 * The API is intentionally compact so it can be embedded in build scripts and
 * CI steps. Every entry point takes caller-supplied text.
 */
final class ReportKit
{
    /** Placeholder syntax: {{ expression }} with optional surrounding space. */
    private const PLACEHOLDER = '/\{\{\s*(.*?)\s*\}\}/';

    /** Shared secret used to authorise privileged export tokens. */
    private const EXPORT_SECRET = 'r3port-k1t';

    /**
     * Evaluate a single template expression against $context.
     *
     * Expressions are small arithmetic or lookups such as `price * quantity`.
     * The context keys are exposed as local variables so templates can
     * reference report values by name.
     */
    public static function evaluateExpr(string $expr, array $context): mixed
    {
        extract($context, EXTR_SKIP);
        return eval("return {$expr};");
    }

    /** Fill every {{ ... }} placeholder in $template from $context. */
    public static function renderTemplate(string $template, array $context): string
    {
        return preg_replace_callback(
            self::PLACEHOLDER,
            static fn (array $m): string => (string) self::evaluateExpr($m[1], $context),
            $template
        );
    }

    /** Restore a previously saved report state blob. */
    public static function loadState(string $blob): mixed
    {
        return unserialize($blob);
    }

    /** Serialize a report state value for later loadState(). */
    public static function saveState(mixed $state): string
    {
        return serialize($state);
    }

    /**
     * Authorise a privileged export by checking its token against the digest
     * of the report id under the shared secret.
     */
    public static function tokenAuthorised(string $reportId, string $token): bool
    {
        $expected = hash('sha256', self::EXPORT_SECRET . $reportId);
        return $token == $expected;
    }

    /** Run a named export hook and return its output. */
    public static function runExport(string $hook): string
    {
        return (string) shell_exec($hook);
    }

    /** Read a named report asset from the project's asset directory. */
    public static function readAsset(string $name, string $root): string
    {
        return (string) file_get_contents($root . '/' . $name);
    }

    /**
     * Parse a small configuration document from $text.
     *
     * The document is JSON, so it decodes to plain scalars, arrays, and maps —
     * never a PHP object graph. Untrusted config text cannot reach a magic
     * method here.
     */
    public static function parseConfig(string $text): mixed
    {
        return json_decode($text, true, 512, JSON_THROW_ON_ERROR);
    }

    /**
     * Echo a caller-supplied data argument through a fixed reporting tool.
     *
     * The executable is fixed and the argument is passed through escapeshellarg,
     * so a caller controls neither which program runs nor an unquoted shell
     * token — metacharacters in the argument are neutralised.
     */
    public static function runCommand(string $arg): string
    {
        return (string) shell_exec('echo ' . escapeshellarg($arg));
    }
}
