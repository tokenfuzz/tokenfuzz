#!/usr/bin/env python3
"""agy / gemini-cli health watchdog.

Polls a running gemini agent for the three known failure modes — sustained 429
quota exhaustion, a post-Drip hang, and a post-generation idle heartbeat loop —
and terminates the process tree when any is confirmed, so a stalled gemini agent
does not burn its whole wall-clock budget producing nothing. Every trigger is
fail-safe: a missing klog, missing /proc and lsof, a parse error, or future
log-format drift all read as "no trigger", so the caller falls through to the
outer wall-clock budget — never a worse outcome than running with no watchdog.

USE_GEMINI_CLI selects Google Gemini CLI (clean stream-json exit); both agy-klog
arms (drip + idle) are then skipped and only the quota arm — which gemini-cli
also hits — stays armed.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

import process_tree
from file_tools import reverse_lines, tail_lines

_QUOTA_429 = re.compile(r"Attempt \d+ failed with status 429")
_PROGRESS = re.compile(r'"role":"assistant"|"type":"result"')
_DRIP = re.compile(r"text_drip\.go:\d+\] Drip stopped")
_STREAM = re.compile(r"streamGenerateContent|:generateContent[^A-Za-z]")
_HEARTBEAT = re.compile(r"fetchAvailableModels|loadCodeAssist")
_CLI_LOG = re.compile(r".*/antigravity-cli/log/cli-.*\.log$")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    proc_stat = Path(f"/proc/{pid}/stat")
    if proc_stat.is_file():
        try:
            state = proc_stat.read_text(encoding="utf-8", errors="replace").rpartition(")")[2].split()[0]
            return state != "Z"
        except (OSError, IndexError):
            pass
    try:
        state = subprocess.check_output(
            ["ps", "-p", str(pid), "-o", "stat="],
            text=True, stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.SubprocessError):
        return True
    if state.startswith("Z"):
        return False
    return True


def quota_dominates(raw_log: Path | str) -> bool:
    """True when the recent tail of the agent transcript is dominated by 429
    retry lines with zero assistant/result progress between them."""
    window = _int_env("GEMINI_QUOTA_WINDOW_LINES", 400)
    minimum = _int_env("GEMINI_QUOTA_MIN_429", 10)
    if window <= 0:
        return False
    lines = tail_lines(Path(raw_log), window)
    n_429 = sum(1 for line in lines if _QUOTA_429.search(line))
    n_progress = sum(1 for line in lines if _PROGRESS.search(line))
    return n_429 >= minimum and n_progress == 0


def cli_log_for_pid(pid: int) -> str:
    """Path to the agy klog (cli-*.log) the process has open, via Linux
    /proc/<pid>/fd first then lsof; empty if unavailable or not open yet."""
    try:
        pids = [pid, *process_tree.descendants(pid)]
    except (OSError, subprocess.SubprocessError):
        pids = [pid]
    for candidate_pid in pids:
        fd_dir = Path(f"/proc/{candidate_pid}/fd")
        if not fd_dir.is_dir():
            continue
        try:
            entries = list(fd_dir.iterdir())
        except OSError:
            continue
        for fd in entries:
            try:
                target = os.readlink(fd)
            except OSError:
                continue
            if _CLI_LOG.match(target):
                return target
    if not shutil.which("lsof"):
        return ""
    for candidate_pid in pids:
        try:
            out = subprocess.check_output(
                ["lsof", "-p", str(candidate_pid)], text=True,
                stderr=subprocess.DEVNULL,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        for line in out.splitlines():
            fields = line.split()
            if fields and _CLI_LOG.match(fields[-1]):
                return fields[-1]
    return ""


def drip_stopped(cli_log: str) -> bool:
    """True once agy logs 'Drip stopped' — its --print stream is fully buffered
    and it should exit within ~1s; rarely it hangs in a polling loop instead."""
    # The watchdog polls from process start, so the event is new when it first
    # appears. A generous bounded tail avoids rescanning a long-lived klog.
    return any(_DRIP.search(line) for line in tail_lines(Path(cli_log), 16_384))


def _klog_time(line: str, now: datetime) -> datetime | None:
    """Parse an agy klog line's leading `IMMDD HH:MM:SS.us` stamp. The year is
    absent from the log, so assume the current year and roll back one year when
    the result would sit in the future (New-Year wraparound)."""
    parts = line.split()
    if len(parts) < 2 or len(parts[0]) < 5 or len(parts[1]) < 8:
        return None
    stamp = parts[0][1:5] + " " + parts[1][:8]
    try:
        parsed = datetime.strptime(stamp, "%m%d %H:%M:%S").replace(year=now.year)
    except ValueError:
        return None
    if parsed - now > timedelta(days=1):
        parsed = parsed.replace(year=now.year - 1)
    return parsed


def in_idle_heartbeat_loop(cli_log: str, window_secs: int) -> bool:
    """True if the klog shows the post-generation idle loop: no stream calls in
    the recent window but at least one keepalive."""
    now = datetime.now()
    cutoff = now - timedelta(seconds=window_secs)
    stream = heartbeat = 0
    for line in reverse_lines(Path(cli_log)):
        stamp = _klog_time(line, now)
        if stamp is None or stamp > now:
            continue
        if stamp < cutoff:
            break
        if _STREAM.search(line):
            stream += 1
        elif _HEARTBEAT.search(line):
            heartbeat += 1
    return stream == 0 and heartbeat >= 1


class Watchdog(threading.Thread):
    """Background poll loop that terminates the agent process tree on a confirmed
    quota/drip/idle stall. Start after launching the agent, stop() after it
    exits. Runs as a daemon so it never keeps the process alive."""

    def __init__(
        self, raw_log: Path | str, pid: int, marker_dir: Path | str | None,
        label: str, *, use_cli: bool, logger=None,
    ) -> None:
        super().__init__(daemon=True)
        self.raw_log = Path(raw_log)
        self.pid = pid
        self.marker_dir = Path(marker_dir) if marker_dir else None
        self.label = label
        self.use_cli = use_cli
        self.logger = logger or (lambda message: print(f"[gemini-watchdog] {message}", file=sys.stderr))
        self._stop_event = threading.Event()
        self.killed = False

    def stop(self) -> None:
        self._stop_event.set()

    def _terminate(self) -> None:
        self.killed = True
        try:
            descendants = process_tree.descendants(self.pid)
        except (OSError, subprocess.SubprocessError):
            descendants = []
        pids = [*reversed(descendants), self.pid]
        for pid in pids:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            except PermissionError:
                pass
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and any(_alive(pid) for pid in pids):
            time.sleep(0.1)
        for pid in pids:
            if not _alive(pid):
                continue
            try:
                os.kill(pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                pass

    def run(self) -> None:
        interval = _int_env("GEMINI_WATCHDOG_POLL_SECS", 10)
        drip_grace = _int_env("AGY_DRIP_GRACE_SECS", 60)
        idle_confirm = _int_env("AGY_IDLE_CONFIRM_POLLS", 2)
        idle_window = _int_env("AGY_IDLE_WINDOW_SECS", 600)
        check_drip = drip_grace > 0 and not self.use_cli
        check_idle = idle_confirm > 0 and not self.use_cli
        cli_log = ""
        idle_strikes = 0
        while not self._stop_event.wait(interval):
            if not _alive(self.pid):
                return
            if quota_dominates(self.raw_log):
                self.logger(f"{self.label} — gemini quota exhausted (sustained 429s, no assistant progress); aborting")
                if self.marker_dir and self.marker_dir.is_dir():
                    try:
                        (self.marker_dir / ".quota-exhausted").touch()
                    except OSError:
                        pass
                self._terminate()
                return
            if (check_drip or check_idle) and not cli_log:
                cli_log = cli_log_for_pid(self.pid)
            if check_drip and cli_log and drip_stopped(cli_log):
                elapsed = 0
                while elapsed < drip_grace:
                    if self._stop_event.wait(2):
                        return
                    elapsed += 2
                    if not _alive(self.pid):
                        return
                self.logger(f"{self.label} — agy hung {drip_grace}s after 'Drip stopped'; aborting (cli-log: {cli_log})")
                self._terminate()
                return
            if check_idle and cli_log:
                if in_idle_heartbeat_loop(cli_log, idle_window):
                    idle_strikes += 1
                    if idle_strikes >= idle_confirm:
                        self.logger(f"{self.label} — agy idle-heartbeat loop (confirmed {idle_strikes}x); aborting (cli-log: {cli_log})")
                        self._terminate()
                        return
                else:
                    idle_strikes = 0
