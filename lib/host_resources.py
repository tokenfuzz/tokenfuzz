#!/usr/bin/env python3
"""Host resource limits shared by parallel harness work."""

from __future__ import annotations

import os
from pathlib import Path


def usable_cpu_count() -> int:
    """CPUs this process may actually run on, including container quotas."""
    count = 0
    getter = getattr(os, "process_cpu_count", None)  # 3.13+
    if getter is not None:
        count = getter() or 0
    if not count and hasattr(os, "sched_getaffinity"):
        try:
            count = len(os.sched_getaffinity(0))
        except OSError:
            count = 0
    count = count or os.cpu_count() or 1
    for quota_path, period_path in (
        ("/sys/fs/cgroup/cpu.max", None),
        ("/sys/fs/cgroup/cpu/cpu.cfs_quota_us",
         "/sys/fs/cgroup/cpu/cpu.cfs_period_us"),
    ):
        try:
            raw = Path(quota_path).read_text().split()
            quota = raw[0]
            period = raw[1] if period_path is None else Path(period_path).read_text().strip()
            if quota in ("max", "-1"):
                continue
            allowed = max(1, int(quota) // int(period))
            count = min(count, allowed)
        except (OSError, ValueError, IndexError, ZeroDivisionError):
            continue
    return max(1, count)
