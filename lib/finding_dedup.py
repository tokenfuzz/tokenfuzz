"""Deterministic clustering for FIND-* findings.

A finding is a written report, often with no sanitizer stack, so it cannot use
the crash dedup path (ClusterFuzz stack bucketing, bin/cluster-crashes).
Findings cluster on two signals, each computed from the report alone and
compared by exact equality — no LLM call, no pairwise scan, no similarity
threshold:

  * identical (class, file, line) — the same normalized issue class at the
    same source line. The line is the discriminator that keeps a location
    edge safe where (file, func) alone would fuse distinct bugs sharing one
    large function. Class is normalized first (lib/finding_signature), so a
    finding labelled by its mechanism (integer-overflow → memory-safety) and
    one labelled by its consequence (memory-safety) share the class and merge.

  * identical crash state — the same normalized top stack frames — when the
    report embeds a sanitizer stack (reused from lib/stack_frames.py, never
    reinvented).

A finding with no line (and no crash state) never merges on the site edge; it
stays its own cluster. That is the safe direction: wrongly splitting just
shows a reviewer two clusters to mentally join, while wrongly merging hides
one real bug behind another.

Union-find over those two edges gives the clusters. Everything here is
deterministic, order-independent, recomputable from stored evidence, and
uncapped: no LLM call, no O(N^2) comparison, no tuning. Crash deduplication is
unrelated and stays in bin/cluster-crashes; this module only touches FIND-*
findings.
"""

from __future__ import annotations

import dataclasses
from typing import Optional

try:  # ClusterFuzz-normalized stack state — reused, never reinvented.
    import stack_frames as _sf
except Exception:  # pragma: no cover - stack_frames should always import
    _sf = None


# ── Crash state ────────────────────────────────────────────────────


def crash_state(report_text: str, want: int = 3) -> tuple[str, ...]:
    """ClusterFuzz-normalized top-N crash frames, or () when there's no stack.

    Delegates to lib/stack_frames so findings and crashes share one frame
    normalization (anonymous-namespace / arg-list / abi stripping, and skipping
    'allocated by' / 'previously allocated by' stacks)."""
    if _sf is None:
        return ()
    try:
        return tuple(_sf.crash_signature(report_text or "", want=want))
    except Exception:
        return ()


# ── Fingerprint ────────────────────────────────────────────────────


@dataclasses.dataclass
class Fingerprint:
    id: str
    cls: str                # normalized issue class, "other" when absent
    file: str               # normalized source file, "" when none extracted
    line: str               # source line as a string, "" when none extracted
    state: tuple[str, ...]  # normalized crash frames, () when stackless


def build_fingerprint(record: dict, report_text: str = "") -> Fingerprint:
    """Assemble a Fingerprint from a cluster-findings signature record.

    `record` carries the fields cluster-findings already computes (id, class,
    file, line); `report_text` supplies the crash state when the report embeds
    a sanitizer stack."""
    return Fingerprint(
        id=record.get("id", ""),
        cls=record.get("class", "") or "other",
        file=record.get("file", "") or "",
        line=str(record.get("line", "") or ""),
        state=crash_state(report_text),
    )


# ── Union-find ─────────────────────────────────────────────────────


class _UnionFind:
    def __init__(self, ids: list[str]):
        self.parent = {i: i for i in ids}

    def find(self, x: str) -> str:
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:  # path compression
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            # Deterministic: smaller id is the root, so component membership is
            # independent of union order.
            lo, hi = sorted((ra, rb))
            self.parent[hi] = lo

    def components(self) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        for i in self.parent:
            out.setdefault(self.find(i), []).append(i)
        return out


# ── Clustering ─────────────────────────────────────────────────────


# Merge provenance — both values are deterministic; there is no probabilistic
# tier. `exact-match` auto-merged on a shared (class, file, line) site or crash
# state; `singleton` had nothing merge into it.
MERGED_SINGLETON = "singleton"
MERGED_STRUCTURAL = "exact-match"


def cluster(
    records: list[dict],
    report_texts: Optional[dict[str, str]] = None,
) -> list[dict]:
    """Cluster findings into components by deterministic auto-merge.

    Returns a list of ``{"members": [ids...], "merged_via": <str>}`` dicts,
    sorted by first member id; members are sorted within each component.
    ``merged_via`` is ``exact-match`` (auto-merged on a shared (class, file,
    line) site or crash state) or ``singleton`` (unmerged).

    records         cluster-findings signature dicts (id, class, file, line).
    report_texts    {id: report_text} for crash-state extraction.

    Union every finding that shares a (class, file, line) site, and every
    finding that shares a crash state. A shared value can never fuse two
    distinct bugs, so each edge bucket-unions with no per-pair guard.
    Order-independent and idempotent: identical inputs always yield identical
    components.
    """
    report_texts = report_texts or {}
    fps = [build_fingerprint(r, report_texts.get(r.get("id", ""), "")) for r in records]
    uf = _UnionFind([f.id for f in fps])

    # Two merge edges, each bucketed by exact value:
    #   site  — (class, file, line), only when both file and line are present
    #   state — the normalized crash frames, only when the report has a stack
    # Bucket-union the whole bucket: a shared value is the same defect, so no
    # per-pair guard is needed.
    site_buckets: dict[object, list[str]] = {}
    state_buckets: dict[object, list[str]] = {}
    for f in fps:
        if f.file and f.line:
            site_buckets.setdefault((f.cls, f.file, f.line), []).append(f.id)
        if f.state:
            state_buckets.setdefault(f.state, []).append(f.id)
    for buckets in (site_buckets, state_buckets):
        for members in buckets.values():
            for other in members[1:]:
                uf.union(members[0], other)

    out: list[dict] = []
    for members in uf.components().values():
        members = sorted(members)
        via = MERGED_SINGLETON if len(members) == 1 else MERGED_STRUCTURAL
        out.append({"members": members, "merged_via": via})
    out.sort(key=lambda c: c["members"][0])
    return out
