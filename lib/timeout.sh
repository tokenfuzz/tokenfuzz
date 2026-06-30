#!/usr/bin/env bash
# Portable timeout helpers for audit scripts.
#
# This module intentionally does not depend on GNU coreutils `timeout`.
# macOS does not ship that utility by default, so callers should source this
# file and use audit_timeout_run / audit_timeout_kill instead.

audit_timeout_run() {
  local secs="$1"; shift
  audit_timeout__perl "$secs" TERM 0 "$@"
}

audit_timeout_kill() {
  local secs="$1"; shift
  audit_timeout__perl "$secs" KILL 0 "$@"
}

# audit_timeout_run_rss <secs> <rss_mb> <cmd...>
#   Like audit_timeout_run, but also SIGKILLs the command's process tree if its
#   summed resident memory crosses <rss_mb> MB — a host-protection cap for
#   generic probe runs where one huge-allocation testcase can swap-wedge the
#   box. <rss_mb> of 0/empty means "no cap" and is byte-identical to
#   audit_timeout_run. The watchdog lives in the same poll loop as the timeout
#   so an over-RSS kill reuses the exact group-kill path, and it is allocator-
#   agnostic — unlike ASan's hard_rss_limit_mb, which is inert on macOS.
audit_timeout_run_rss() {
  local secs="$1" rss_mb="$2"; shift 2
  audit_timeout__perl "$secs" TERM "${rss_mb:-0}" "$@"
}

audit_timeout__perl() {
  local secs="$1" mode="$2" rss_mb="$3"; shift 3
  perl -e '
    use strict;
    use warnings;
    use POSIX qw(setsid :sys_wait_h);

    my $secs = shift @ARGV;
    my $mode = shift @ARGV;
    my $rss_mb = shift @ARGV;
    my @cmd = @ARGV;
    die "missing timeout seconds\n" unless defined $secs && $secs =~ /^\d+$/ && $secs > 0;
    $rss_mb = 0 unless defined $rss_mb && $rss_mb =~ /^\d+$/;
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

    # Summed RSS (KB) of the child and every descendant. One ps call, parsed
    # the same way as $descendants above (pid/ppid) plus the rss column. ps
    # reports rss in KB on macOS and Linux. Only used on the RSS-watch path.
    my $tree_rss_kb = sub {
      my ($root) = @_;
      my (%children, %rss);
      if (open(my $ps, "-|", "ps", "-axo", "pid=,ppid=,rss=")) {
        while (my $line = <$ps>) {
          my ($p, $pp, $r) = $line =~ /^\s*(\d+)\s+(\d+)\s+(\d+)\s*$/;
          next unless defined $p;
          push @{ $children{$pp} }, $p;
          $rss{$p} = $r;
        }
        close($ps);
      }
      my $total = $rss{$root} // 0;
      my %seen;
      my @stack = ($root);
      while (@stack) {
        my $cur = pop @stack;
        for my $c (@{ $children{$cur} || [] }) {
          next if $seen{$c}++;
          $total += $rss{$c} // 0;
          push @stack, $c;
        }
      }
      return $total;
    };

    my %exit_for_signal = (HUP => 129, INT => 130, TERM => 143);
    for my $sig (keys %exit_for_signal) {
      $SIG{$sig} = sub {
        $kill_group->("TERM");
        sleep 1;
        $kill_group->("KILL");
        waitpid($pid, 0);
        exit $exit_for_signal{$sig};
      };
    }

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

    my $status;
    if ($rss_mb > 0) {
      # RSS-watch path: poll instead of a single blocking wait so we can
      # check the process-tree resident memory between waitpid sweeps. The wall-clock
      # timeout is enforced here too (not via SIGALRM) so both ceilings share
      # one loop and one kill path. A fast allocator can overshoot the cap by
      # up to one tick before the kill lands; the tick is short and the cap is
      # set well under host RAM, so the host is protected either way.
      my $limit_kb = $rss_mb * 1024;
      my $deadline = time() + int($secs);
      while (1) {
        my $w = waitpid($pid, WNOHANG);
        if ($w == $pid) { $status = $?; last; }
        if ($w == -1)   { $status = 0;  last; }   # already reaped
        if (time() >= $deadline) {
          if ($mode eq "KILL") { $kill_group->("KILL"); }
          else { $kill_group->("TERM"); sleep 1; $kill_group->("KILL"); }
          waitpid($pid, 0);
          exit 124;
        }
        my $rss_kb = $tree_rss_kb->($pid);
        if ($rss_kb > $limit_kb) {
          my $used_mb = int($rss_kb / 1024);
          # Marker is matched by triage (is_autodiscard_crash_output) and
          # bin/severity detect_primitive — the OOM / host-protection class,
          # so the kill is recorded, never promoted to a memory-safety bug.
          print STDERR "tokenfuzz: probe rss limit exceeded (${used_mb}Mb > ${rss_mb}Mb) -- host-protection kill\n";
          $kill_group->("KILL");
          waitpid($pid, 0);
          exit 137;
        }
        select(undef, undef, undef, 0.5);
      }
    } else {
      alarm int($secs);
      waitpid($pid, 0);
      $status = $?;
      alarm 0;
    }

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
  ' "$secs" "$mode" "$rss_mb" "$@"
}
