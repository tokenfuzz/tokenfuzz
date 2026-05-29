"""Deterministic clustering for FIND-* findings.

A finding is a written report, often with no sanitizer stack, so it cannot use
the crash dedup path (ClusterFuzz stack bucketing, bin/cluster-crashes).
Findings cluster on the two high-precision signals that cannot fuse two
distinct bugs, within one issue class:

  * identical normalized crash state (the same stack), when the report embeds
    one — reused from lib/stack_frames.py, never reinvented; or
  * identical valid dedup_key — the triage model's canonical root-cause slug
    (finding_signature.is_valid_dedup_key), emitted once per finding by the
    find-quality gate, so two reports of the same root cause reached from
    different sites collapse to one cluster.

Union-find over those edges gives the clusters. Everything here is
deterministic, order-independent, recomputable from stored evidence, and
uncapped: no LLM call, no O(N^2) pairwise comparison, no similarity tuning.

Bias-to-separate: only the two signals above merge. Two findings that merely
look related — same file, similar wording — stay in separate clusters unless
they share a key or a stack. Wrongly splitting just shows a reviewer two
clusters to mentally join; wrongly merging hides one real bug behind another.
Crash deduplication is unrelated and stays in bin/cluster-crashes; this module
only touches FIND-* findings.
"""

from __future__ import annotations

import dataclasses
from typing import Optional

import finding_signature as _fs

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
    cls: str                # normalized class — a hard gate; cross-class never merges
    state: tuple[str, ...]  # normalized crash frames, () when stackless
    dedup_key: str


def build_fingerprint(record: dict, report_text: str = "") -> Fingerprint:
    """Assemble a Fingerprint from a cluster-findings signature record.

    `record` carries the fields cluster-findings already computes (id, class,
    dedup_key); `report_text` supplies the crash state when the report embeds a
    sanitizer stack."""
    return Fingerprint(
        id=record.get("id", ""),
        cls=record.get("class", "") or "other",
        state=crash_state(report_text),
        dedup_key=record.get("dedup_key", "") or "",
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
# tier. `exact-match` auto-merged on an identical dedup_key or crash state;
# `singleton` had nothing merge into it.
MERGED_SINGLETON = "singleton"
MERGED_STRUCTURAL = "exact-match"


def cluster(
    records: list[dict],
    report_texts: Optional[dict[str, str]] = None,
) -> list[dict]:
    """Cluster findings into components by deterministic auto-merge.

    Returns a list of ``{"members": [ids...], "merged_via": <str>}`` dicts,
    sorted by first member id; members are sorted within each component.
    ``merged_via`` is ``exact-match`` (auto-merged on an identical valid
    dedup_key or an identical crash state) or ``singleton`` (unmerged).

    records         cluster-findings signature dicts (id, class, dedup_key).
    report_texts    {id: report_text} for crash-state extraction.

    Within each class, union every finding sharing an identical valid dedup_key
    or an identical crash state. Cross-class findings never merge.
    Order-independent and idempotent: identical inputs always yield identical
    components.
    """
    report_texts = report_texts or {}
    fps = [build_fingerprint(r, report_texts.get(r.get("id", ""), "")) for r in records]
    uf = _UnionFind([f.id for f in fps])

    # Cross-class findings never merge, so cluster each class independently.
    by_class: dict[str, list[Fingerprint]] = {}
    for f in fps:
        by_class.setdefault(f.cls, []).append(f)

    for group in by_class.values():
        # Union every finding sharing an identical valid dedup_key or an
        # identical crash state — signals that cannot fuse two distinct bugs.
        for index_key in ("dedup_key", "state"):
            buckets: dict[object, list[str]] = {}
            for f in group:
                if index_key == "dedup_key":
                    val = f.dedup_key if (f.dedup_key and _fs.is_valid_dedup_key(f.dedup_key)) else None
                else:
                    val = f.state or None
                if val is not None:
                    buckets.setdefault(val, []).append(f.id)
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
