#!/usr/bin/env perl

# reportkit_cli — command-line front end for the ReportKit toolkit.
#
# Reads one *job file* and performs a single ReportKit operation with it. This
# is the entry point an audit harness (or a CI step) drives: it turns a file on
# disk into exactly one library call so a report task can be scripted.
#
# Job-file format — a header line naming the operation, then an
# operation-specific body:
#
#     op: render
#     {"price": 3, "quantity": 4}
#     Total is {{ $price * $quantity }}.
#
# The first line is always "op: <name>". The remaining lines are the body:
#
#     render    first body line is a JSON object (the context); the rest is the
#               template whose {{ ... }} placeholders are filled from it.
#     state     the body is a Storable-frozen state blob to restore.
#     export    the body is the name of an export hook to run.
#     asset     first body line is the project root; the second is the name.
#     save      first two body lines are the output root and name; the rest is
#               the content to write.
#     config    the body is a JSON configuration document to parse.
#     command   the body is one argv token per line for a fixed-argv tool run.

use strict;
use warnings;
use FindBin;
use lib "$FindBin::Bin/lib";
use JSON::PP;
use ReportKit qw(
    render_template load_state run_export read_asset save_render
    parse_config run_command
);

sub split_job {
    my ($text) = @_;
    my ($header, $body) = split(/\n/, $text, 2);
    $body = '' unless defined $body;
    my ($prefix, $name) = split(/:/, $header // '', 2);
    die "job file must begin with \"op: <name>\"\n"
        unless defined $prefix && _trim($prefix) eq 'op';
    return (_trim($name // ''), $body);
}

sub _trim { my $s = shift; $s =~ s/^\s+|\s+$//g; return $s; }

sub run_render_op {
    my ($body) = @_;
    my ($context_line, $template) = split(/\n/, $body, 2);
    $template = '' unless defined $template;
    my $context = (defined $context_line && _trim($context_line) ne '')
        ? decode_json($context_line) : {};
    return render_template($template, $context);
}

sub run_state_op   { return _dump(load_state($_[0])); }
sub run_export_op  { return run_export(_trim($_[0])); }

sub run_asset_op {
    my ($body) = @_;
    my ($root, $name) = split(/\n/, $body, 2);
    return read_asset(_trim($name // ''), _trim($root // ''));
}

sub run_save_op {
    my ($body) = @_;
    my ($root, $name, $data) = split(/\n/, $body, 3);
    return save_render(_trim($name // ''), _trim($root // ''), $data // '');
}

sub run_config_op  { return _dump(parse_config(_trim($_[0]))); }

sub run_command_op {
    my ($body) = @_;
    return run_command(_trim($body));
}

sub _dump { my $v = shift; return ref($v) ? ref($v) : (defined $v ? $v : 'undef'); }

my %OPERATIONS = (
    render  => \&run_render_op,
    state   => \&run_state_op,
    export  => \&run_export_op,
    asset   => \&run_asset_op,
    save    => \&run_save_op,
    config  => \&run_config_op,
    command => \&run_command_op,
);

sub main {
    my (@argv) = @_;
    if (@argv != 1) {
        print STDERR "usage: reportkit_cli.pl job-file\n";
        return 2;
    }

    open(my $fh, '<', $argv[0]) or do {
        print STDERR "could not read input\n";
        return 2;
    };
    local $/;
    my $text = <$fh>;
    close($fh);

    my ($op, $body) = split_job($text);
    my $handler = $OPERATIONS{$op};
    unless ($handler) {
        print STDERR "unknown operation: $op\n";
        return 1;
    }

    print "$op: ", $handler->($body), "\n";
    return 0;
}

exit(main(@ARGV));
