#!/usr/bin/env bash
# Portable timeout helpers for audit scripts.
#
# This module intentionally does not depend on GNU coreutils `timeout`.
# macOS does not ship that utility by default, so callers should source this
# file and use audit_timeout_run / audit_timeout_kill instead.

audit_timeout_run() {
  local secs="$1"; shift
  audit_timeout__perl "$secs" TERM "$@"
}

audit_timeout_kill() {
  local secs="$1"; shift
  audit_timeout__perl "$secs" KILL "$@"
}

audit_timeout__perl() {
  local secs="$1" mode="$2"; shift 2
  perl -e '
    use strict;
    use warnings;
    use POSIX qw(setsid);

    my $secs = shift @ARGV;
    my $mode = shift @ARGV;
    my @cmd = @ARGV;
    die "missing timeout seconds\n" unless defined $secs && $secs =~ /^\d+$/ && $secs > 0;
    die "missing command\n" unless @cmd;

    my $pid = fork();
    die "fork: $!" unless defined $pid;

    if ($pid == 0) {
      # setsid (not setpgrp) so the child has no controlling terminal.
      # setpgrp alone moves the child to a background pgrp while leaving
      # the inherited tty attached — any tty touch from a background pgrp
      # triggers SIGTTIN/SIGTTOU, which silently STOPS the process and
      # leaves waitpid blocked until the wall-clock alarm fires. That is
      # exactly how `claude auth status` froze a 7200s harness cell.
      # A fresh session has no controlling tty, so the stop class cannot
      # fire, and pgid == pid keeps the existing group-kill logic intact.
      setsid();
      exec @cmd or die "exec: $!";
    }

    my $descendants = sub {
      my ($root) = @_;
      my %children;
      if (open(my $ps, "-|", "ps", "-axo", "pid=,ppid=")) {
        while (my $line = <$ps>) {
          my ($pid, $ppid) = $line =~ /^\s*(\d+)\s+(\d+)\s*$/;
          next unless defined $pid && defined $ppid;
          push @{ $children{$ppid} }, $pid;
        }
        close($ps);
      }
      my @out;
      my @stack = ($root);
      while (@stack) {
        my $cur = pop @stack;
        for my $child (@{ $children{$cur} || [] }) {
          push @out, $child;
          push @stack, $child;
        }
      }
      return @out;
    };

    my $kill_group = sub {
      my ($signal) = @_;
      my @targets = ($pid, $descendants->($pid));
      for my $target (@targets) {
        kill $signal, -$target;
        kill $signal,  $target;
      }
    };

    $SIG{ALRM} = sub {
      if ($mode eq "KILL") {
        $kill_group->("KILL");
      } else {
        $kill_group->("TERM");
        sleep 1;
        $kill_group->("KILL");
      }
      waitpid($pid, 0);
      exit 124;
    };

    alarm int($secs);
    waitpid($pid, 0);
    my $status = $?;
    alarm 0;

    # KILL-mode callers (the fuzz runners) want orphaned descendants
    # reaped: a libFuzzer-driven browser leaves content processes that
    # outlive the parent and would otherwise leak. The child put itself
    # in its own process group (setpgrp above), so this group-directed
    # signal hits exactly this run and never a sibling agent running the
    # same fuzzer. Harmless no-op when the group is already empty.
    if ($mode eq "KILL") {
      kill "KILL", -$pid;
    }

    if ($status & 127) {
      exit 128 + ($status & 127);
    }
    exit($status >> 8);
  ' "$secs" "$mode" "$@"
}
