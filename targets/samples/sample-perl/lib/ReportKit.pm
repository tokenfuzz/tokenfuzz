package ReportKit;

# ReportKit — a small toolkit for rendering configuration-driven reports.
#
# A report is assembled from a few ingredients: a *state* blob carrying cached
# values between runs, a set of *templates* whose {{ ... }} placeholders are
# filled from a context, named export hooks, and report assets read from (and
# rendered output written to) a project directory.
#
# The API is intentionally compact so it can be embedded in build scripts and
# CI steps. Every entry point takes caller-supplied text or bytes.

use strict;
use warnings;
use Storable qw(thaw);
use Exporter qw(import);

our @EXPORT_OK = qw(
    render_template load_state run_export read_asset save_render
    parse_config run_command
);

# Placeholder syntax: {{ expression }} with optional surrounding whitespace.
my $PLACEHOLDER = qr/\{\{\s*(.*?)\s*\}\}/;

# Evaluate a single template expression against %$context.
#
# Expressions are small arithmetic or lookups such as "$price * $quantity".
# The context keys are exposed as scalars so templates can reference report
# values by name.
sub _evaluate_expr {
    my ($expr, $context) = @_;
    my $bindings = join('', map { "my \$$_ = \$context->{$_}; " } keys %$context);
    return eval "$bindings $expr";
}

# Fill every {{ ... }} placeholder in $template from $context.
sub render_template {
    my ($template, $context) = @_;
    $template =~ s/$PLACEHOLDER/_evaluate_expr($1, $context)/ge;
    return $template;
}

# Restore a previously saved report state blob produced by Storable::freeze.
sub load_state {
    my ($blob) = @_;
    return thaw($blob);
}

# Run a named export hook and return its stdout. Hooks are short shell
# one-liners declared in a project's report config.
sub run_export {
    my ($hook) = @_;
    return `$hook`;
}

# Read a named report asset from the project's asset directory.
sub read_asset {
    my ($name, $root) = @_;
    open(my $fh, "$root/$name") or die "cannot open asset: $!";
    local $/;
    my $data = <$fh>;
    close($fh);
    return $data;
}

# Write rendered report output to a named file under the output directory.
sub save_render {
    my ($name, $root, $data) = @_;
    open(my $fh, ">$root/$name") or die "cannot open output: $!";
    print {$fh} $data;
    close($fh);
    return length($data);
}

# Parse a small literal configuration value from $text.
#
# The value is decoded as JSON, so it yields only scalars, arrays, and hashes —
# never blessed objects or code. Untrusted config text cannot reach arbitrary
# code here.
sub parse_config {
    my ($text) = @_;
    require JSON::PP;
    return JSON::PP::decode_json($text);
}

# Echo a caller-supplied data argument through a fixed reporting tool.
#
# Unlike run_export, the executable is a fixed, harmless program and the
# argument is spawned as a separate list element with no shell, so a caller
# controls neither which program runs nor a shell to interpret metacharacters.
sub run_command {
    my ($arg) = @_;
    system('echo', $arg);
    return $? >> 8;
}

1;
