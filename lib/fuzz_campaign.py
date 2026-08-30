#!/usr/bin/env python3
"""Spend a short fuzzing budget across many targets without wasting it on
one that is not paying.

An audit iteration has minutes, not machine-days, and it usually has several
harnesses of unknown quality. Running them in turn wastes the budget on the
worst one; running only the best starves everything else and never discovers
that the best has stopped finding anything. So the budget is cut into short
*slices* and allocated the way ClusterFuzz weights its fuzzers and FuzzBench
measures its trials: by what each one actually produced per second, with an
exploration term that guarantees every harness is tried before any is
repeated.

Short slices only work because state persists. Each harness keeps its own
corpus under RESULTS_DIR, so slice N+1 resumes where slice N stopped rather
than restarting from nothing; periodic minimisation keeps that corpus from
growing until re-reading it costs more than the slice itself.

Recovery is the other half. A harness can be broken in ways that look like
work — crashing on startup, flooding OOMs, leaking its own allocations,
or simply having exhausted what it can reach. Every slice is classified, and
a harness that is not producing is quarantined *with the reason* and the
budget moves on. Quarantine is not deletion: a saturated harness comes back
when its corpus grows.

Nothing here decides whether a crash is real. Every artifact is replayed
through ``bin/probe``, which is the harness's single entry point for
harness-authored testcases — so coverage gating, five-run confirmation,
deduplication, the crash gate, and triage all apply to a fuzz finding exactly
as they do to a hand-written one.
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path

import fuzz_harness
import sanitizer as sanitizer_lib
import workqueue
from timeout import run_timeout

# ── Budget shape ────────────────────────────────────────────────────
#
# Defaults, not knobs: the operator sets budget and slice length on the
# command line. These are the values that apply when they do not.

# Long enough for libFuzzer to load a corpus, reach steady state, and show a
# coverage delta; short enough that a dead harness costs one of them.
DEFAULT_SLICE_SECONDS = 60
# One campaign is a *turn*, not a shift. S4 shares an audit iteration with six
# other strategies, and a fuzzer will happily consume every second it is
# given without ever saying it is finished — so the default is a small slice
# of an iteration and the loop below refuses to start a slice it cannot
# finish inside it. A campaign that wants more time gets it by being run
# again next iteration, against a corpus that survived, which is worth more
# than one long run anyway.
DEFAULT_BUDGET_SECONDS = 5 * 60
# libFuzzer's own per-input limits. A single input that needs more than this
# is a timeout or an OOM report, which the crash gate auto-rejects anyway, so
# spending real budget on one is pure loss.
UNIT_TIMEOUT_SECONDS = 25
RSS_LIMIT_MB = 2560
MALLOC_LIMIT_MB = 2048

# ── Health thresholds ───────────────────────────────────────────────
#
# Each is the point at which continuing costs more than switching. They are
# constants rather than environment variables because an operator who wants a
# different allocation changes the budget, not the definition of "broken".

# Consecutive slices with no new edge before a harness is considered mined
# out. Two is noise on a large corpus; three is a trend.
SATURATION_SLICES = 3
# Consecutive slices ending on a crash already filed before the harness is
# treated as blocked by it. One repeat is the fuzzer being unlucky with its
# seed; two in a row means the bug sits across the only path it has.
REPEAT_SLICES = 2
# Consecutive slices ending in a non-diagnostic outcome (OOM, timeout, leak)
# before the harness is treated as generating its own noise. Counted across
# slices, not within one: libFuzzer exits at its first such artifact, so a
# within-slice threshold above one can never be reached.
NOISE_SLICES = 2
# Executions below which a slice did not fuzz at all. libFuzzer reaches
# thousands per second on any working target; single digits means the binary
# is failing to run rather than running slowly.
DEAD_EXEC_FLOOR = 2
# Productive slices between corpus minimisations. Merging costs one pass over
# the corpus, so doing it every slice would eat the budget it saves.
MERGE_EVERY_SLICES = 8
# Exploration weight in the selection score. 1.4 is the standard UCB1
# constant; it is what makes a harness that has been quiet for many slices
# get another look instead of being crowded out permanently.
EXPLORE_WEIGHT = 1.4
# Wall a campaign keeps in hand for work that follows a slice. Replay confirms
# an artifact five times through the full probe path; a merge walks the whole
# corpus. Both used to run after the last deadline check, which is how a
# five-minute campaign became eight.
REPLAY_RESERVE_SECONDS = 45
# Shorter than this a slice only measures process startup and corpus loading,
# so the remaining wall is better returned than spent.
MIN_SLICE_SECONDS = 10
MERGE_RESERVE_SECONDS = 60

VERDICT_PRODUCTIVE = "productive"
VERDICT_DRY = "dry"
VERDICT_DEAD = "dead"
VERDICT_STARTUP_CRASH = "startup-crash"
VERDICT_NOISE_FLOOD = "noise-flood"
VERDICT_SATURATED = "saturated"
VERDICT_BLOCKED_ON_CRASH = "blocked-on-crash"

# Verdicts that take a harness out of rotation. `saturated` and
# `blocked-on-crash` are revocable — see `revive` — the rest describe a
# harness that has to be fixed by hand before it is worth another second.
QUARANTINE_VERDICTS = frozenset({
    VERDICT_DEAD, VERDICT_STARTUP_CRASH, VERDICT_NOISE_FLOOD,
    VERDICT_SATURATED, VERDICT_BLOCKED_ON_CRASH,
})
REVIVABLE_VERDICTS = frozenset({VERDICT_SATURATED, VERDICT_BLOCKED_ON_CRASH})


# ── Reading a slice ─────────────────────────────────────────────────

_STAT_LINE = re.compile(r"^#(\d+)\s+\S+", re.M)
_COV = re.compile(r"\bcov: (\d+)")
_FEATURES = re.compile(r"\bft: (\d+)")
_EXEC_RATE = re.compile(r"\bexec/s: (\d+)")
_INITED = re.compile(r"^#\d+\s+INITED", re.M)
# libFuzzer prints this after the artifact_prefix it used, on the same line:
# `artifact_prefix='./'; Test unit written to ./crash-<sha1>`. Anchoring the
# phrase to the start of a line finds nothing.
_ARTIFACT = re.compile(r"Test unit written to (\S+)")
_DONE_RUNS = re.compile(r"^Done (\d+) runs in", re.M)
# libFuzzer's own non-diagnostic outcomes. Each is auto-rejected downstream,
# so a harness producing mostly these is producing nothing.
_OOM = re.compile(r"ERROR: libFuzzer: out-of-memory")
_TIMEOUT = re.compile(r"ERROR: libFuzzer: timeout")
_LEAK = re.compile(r"ERROR: LeakSanitizer: detected memory leaks")
# libFuzzer reports the size of the instrumented universe at startup:
# `INFO: Loaded 2 modules (84213 inline 8-bit counters): 12 [0x..], 84201 [0x..]`
# That denominator is what turns "1961 edges" — a number meaning nothing on its
# own — into "1961 of 84213", which is the difference between a harness worth
# widening and one that is genuinely mined out.
_COUNTERS = re.compile(r"Loaded \d+ modules\s+\((\d+) inline 8-bit counters\)")


@dataclass
class SliceResult:
    harness: str
    seconds: float
    returncode: int
    executions: int = 0
    edges: int = 0
    features: int = 0
    exec_rate: int = 0
    inited: bool = False
    artifacts: "list[str]" = field(default_factory=list)
    oom: bool = False
    timeout: bool = False
    leak: bool = False
    counters: int = 0
    log: str = ""
    # What the process printed before libFuzzer got going. Empty for a healthy
    # slice; for a broken one it is the whole diagnosis.
    opening: str = ""


# How much of a slice log to read back and keep. Everything `parse_log` needs
# — the last statistics line, the artifact path, the final run count — is at
# the end, and a target that logs per parse can put a hundred megabytes in
# front of it. The head is kept too because that is where a harness that
# failed to start says why.
LOG_HEAD_BYTES = 64 * 1024
LOG_TAIL_BYTES = 512 * 1024
_ELISION = b"\n[fuzz] ... slice log elided %d bytes ...\n"


def read_log(path: Path) -> str:
    """A slice log's head and tail, decoded leniently.

    Lenient because the bytes are not ours: a fuzzer echoes fragments of the
    inputs it mutates, so any slice can contain arbitrary non-UTF-8 sequences.
    Decoding strictly turned the first such byte into a crashed campaign.
    Oversized logs are truncated on disk as well — a run that keeps every
    slice at full size fills the results tree with output nobody reads.
    """
    try:
        size = path.stat().st_size
        with path.open("rb") as stream:
            if size <= LOG_HEAD_BYTES + LOG_TAIL_BYTES:
                data = stream.read()
            else:
                head = stream.read(LOG_HEAD_BYTES)
                stream.seek(-LOG_TAIL_BYTES, os.SEEK_END)
                data = head + (_ELISION % (size - LOG_HEAD_BYTES - LOG_TAIL_BYTES))
                data += stream.read()
                path.write_bytes(data)
    except OSError:
        return ""
    return data.decode("utf-8", errors="replace")


# libFuzzer's own first lines. Anything printed before one of these came from
# the loader, the sanitizer runtime, or the exec that never happened — which
# is what a harness that produced no executions needs reported.
_LIBFUZZER_BANNER = ("INFO: Running with", "INFO: Seed:", "Dictionary:")


def _opening_line(text: str) -> str:
    """The first line the process printed that libFuzzer did not."""
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith(_LIBFUZZER_BANNER):
            return ""
        return line[:200]
    return ""


def parse_log(text: str) -> dict:
    """Measurements from one libFuzzer run's output.

    Reads the *last* statistics line rather than the maximum: libFuzzer's
    counters are monotonic within a run, and taking the last one keeps the
    reading correct if a future version ever reports a decrease after a
    corpus reload.
    """
    stats = _STAT_LINE.findall(text)
    done = _DONE_RUNS.findall(text)
    lines = [line for line in text.splitlines() if line.startswith("#")]
    tail = lines[-1] if lines else ""
    covs = _COV.findall(text)
    features = _FEATURES.findall(text)
    rates = _EXEC_RATE.findall(text)

    def last(values: "list[str]") -> int:
        return int(values[-1]) if values else 0

    executions = int(done[-1]) if done else (int(stats[-1]) if stats else 0)
    return {
        "executions": executions,
        "edges": last(_COV.findall(tail)) or last(covs),
        "features": last(_FEATURES.findall(tail)) or last(features),
        "exec_rate": last(rates),
        "inited": bool(_INITED.search(text)),
        "artifacts": [line.strip() for line in _ARTIFACT.findall(text)],
        "counters": last(_COUNTERS.findall(text)),
        "oom": bool(_OOM.search(text)),
        "timeout": bool(_TIMEOUT.search(text)),
        "leak": bool(_LEAK.search(text)),
        "opening": _opening_line(text),
    }


# ── Per-harness state ───────────────────────────────────────────────

@dataclass
class HarnessState:
    name: str
    binary: str
    source: str = ""
    # Stamped from the harness header at build time; every replayed artifact
    # is filed against it so campaign crashes join the strategy's evidence.
    hypothesis_id: str = ""
    slices: int = 0
    seconds: float = 0.0
    executions: int = 0
    edges: int = 0
    artifacts: int = 0
    dry_streak: int = 0
    since_merge: int = 0
    corpus_at_quarantine: int = 0
    quarantine: str = ""
    quarantine_detail: str = ""
    # Artifacts already handed to bin/probe, by libFuzzer's own sha1-of-input
    # filename. This suppresses re-running probe on a byte-identical input
    # only; whether a *different* input for the same bug is progress is
    # decided by coverage, in `classify`.
    seen_artifacts: "list[str]" = field(default_factory=list)
    # Consecutive slices that ended in a crash without reaching new code.
    repeat_streak: int = 0
    # Consecutive slices that ended in a non-diagnostic outcome.
    noise_streak: int = 0
    # Size of the instrumented universe, from libFuzzer's own startup line.
    # Zero means it never reported one — a blind build, or a dead slice.
    counters: int = 0
    # libFuzzer's `ft`: edge counters *plus* value profiles, indirect-call
    # pairs, and the other signals it mutates toward. Tracked because `cov`
    # alone cannot see value-profile progress, and value profiling is exactly
    # what a dry harness gets switched to.
    features: int = 0
    # The project's own token list for this harness's format, if it ships one.
    dictionary: str = ""
    # New edges per second on the most recent slices, exponentially weighted.
    # One number, because that is what selection needs and a full history
    # would have to be re-derived on every resume.
    value: float = 0.0
    # The first slice is the fastest falsifier of a generated harness: it says
    # whether the binary really executed, whether guidance moved, and which
    # repair class applies. Keep that exact receipt across later productive
    # slices instead of replacing it with high-water totals.
    first_slice: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return asdict(self)


# What probe prints when it has adjudicated an input either way. Anything
# else — a build failure, a timeout, a killed replay — means no verdict was
# reached and the artifact must stay pending rather than be marked seen.
_PROBE_VERDICT = re.compile(r"^\[probe\] verdict=(\w+)", re.M)


def _terminal_verdict(output: str, returncode: int) -> bool:
    """Whether bin/probe actually decided something about this input."""
    return bool(_PROBE_VERDICT.search(output)) and returncode in (0, 1)


def _ewma(previous: float, sample: float, weight: float = 0.5) -> float:
    return sample if previous == 0.0 else previous * (1 - weight) + sample * weight


# ── Coverage feedback ───────────────────────────────────────────────
#
# What compounds across campaigns: the corpus persists, the coverage
# high-water mark persists, and each harness's recent yield feeds selection.
# So a campaign resumes where the last stopped, and a harness that is still
# reaching new code keeps its share of every future budget.
#
# What is deliberately *not* claimed: a coverage percentage. libFuzzer's
# instrumented-counter total spans every loaded module, including the
# harness's own translation unit — it is not the code reachable from this
# entry point, so dividing by it cannot say whether a harness is narrow or
# nearly done. Fuzz Introspector answers that by comparing static
# reachability against dynamic coverage, which is a different analysis than
# anything available here. The numbers are reported; the inference is not.

def coverage_note(state: HarnessState) -> str:
    """What this harness has reached, in the terms libFuzzer reports.

    Both signals, because they answer different questions: `edges` is code
    reached, `features` folds in the value profiles and indirect-call pairs
    the mutator actually steers on. The instrumented total is shown as
    context, never as a denominator — see the note above.
    """
    total = f" of {state.counters} instrumented" if state.counters else ""
    return f"{state.edges} edges{total}, {state.features} features"


def recommendation(state: HarnessState) -> str:
    """What to do with this harness next, in one sentence.

    The point of the loop: an agent reading `bin/fuzz status` after any
    campaign gets the same answer the campaign would give itself.
    """
    if state.quarantine == VERDICT_DEAD:
        return "fix the build — it never executed"
    if state.quarantine == VERDICT_STARTUP_CRASH:
        return "fix the harness — it crashes before fuzzing starts"
    if state.quarantine == VERDICT_NOISE_FLOOD:
        return "bound its allocations and free what it allocates"
    if state.quarantine == VERDICT_BLOCKED_ON_CRASH:
        return "nothing — the crash it keeps hitting is filed; move on"
    if state.quarantine == VERDICT_SATURATED:
        return ("widen or re-seed it — drive more of the API, split the input "
                "into a call sequence, or add seeds it cannot reach from the "
                "corpus it has")
    if state.value > 0:
        return "keep — still finding new code, so more wall still pays"
    return "keep — one more campaign decides whether it is saturated"


def status_rows(states: "dict[str, HarnessState]",
                built: "dict[str, dict]") -> "dict[str, dict]":
    """Join campaign state with current build/grounding receipts.

    Returning data keeps ``bin/fuzz status`` a thin printer and makes the
    resume view testable without spawning another Python process. The join is
    read-only: receipts may explain what to try next, but they do not change a
    quarantine, schedule, or evidence decision.
    """
    rows: "dict[str, dict]" = {}
    for name in sorted(set(states) | set(built)):
        state = states.get(name)
        record = built.get(name, {})
        record_binary = str(record.get("binary", ""))
        if state is None or (record_binary and state.binary != record_binary):
            state = HarnessState(
                name=name, binary=record_binary,
                source=str(record.get("source", "")),
                hypothesis_id=str(record.get("hypothesis_id", "")),
            )
        row = state.as_dict()
        build = {
            key: record.get(key)
            for key in (
                "binary", "compiler", "source", "source_sha1", "library",
                "tree", "guided", "sanitized", "current",
            )
            if key in record
        }
        receipt = record.get("receipt")
        if not isinstance(receipt, dict):
            receipt = {}
        warnings = record.get("receipt_warnings")
        if not isinstance(warnings, list):
            warnings = []
        next_step = recommendation(state)
        if record and record.get("current") is False:
            next_step = (
                "rebuild — the harness source changed since this binary was built"
            )
        elif state.slices == 0 and record:
            next_step = "run one bounded campaign to obtain first-slice feedback"
        elif (state.quarantine == VERDICT_SATURATED
              and bool(record.get("guided")) and receipt):
            # No receipt at all — a legacy or hand-written harness — is not a
            # grounded one, so it keeps the generic widen/re-seed advice
            # rather than being told to preserve a contract nothing recorded.
            unresolved = receipt.get("unresolved")
            unresolved = unresolved if isinstance(unresolved, list) else []
            if unresolved:
                next_step = (
                    "resolve the source-grounded receipt before varying this "
                    "guided harness: " + ", ".join(str(item) for item in unresolved[:5])
                )
            else:
                next_step = (
                    "make at most one contract-preserving derivative: vary one "
                    "caller-controlled argument or add one source-grounded "
                    "public call, then rebuild — the next S4 iteration's single "
                    "campaign runs it"
                )
        row.update({
            "build": build,
            "receipt": receipt,
            "receipt_warnings": warnings,
            "coverage": coverage_note(state),
            "next": next_step,
        })
        rows[name] = row
    return rows


def fresh_artifacts(result: SliceResult, state: HarnessState) -> "list[str]":
    """Artifacts from this slice that no earlier slice already produced."""
    seen = set(state.seen_artifacts)
    return [path for path in result.artifacts if Path(path).name not in seen]


def progress(result: SliceResult, state: HarnessState) -> "tuple[int, int]":
    """New edges and new features this slice reached.

    Both count. `cov` is edge coverage; `ft` folds in value profiles and
    indirect-call pairs, and it is the only place value-profile progress
    shows up — so judging a value-profiled slice on edges alone reports a
    harness that is still learning as mined out.
    """
    return (max(0, result.edges - state.edges),
            max(0, result.features - state.features))


def classify(result: SliceResult, state: HarnessState,
             new_edges: int, fresh: "list[str] | None" = None,
             new_features: int = 0) -> "tuple[str, str]":
    """One slice's verdict and the sentence explaining it.

    Order matters, and the startup crash is checked first: it also has almost
    no executions and no ``INITED``, so testing for a dead binary ahead of it
    would file every broken harness under the vaguer of the two verdicts.
    """
    if result.artifacts and not result.inited:
        return VERDICT_STARTUP_CRASH, (
            "crashed before libFuzzer finished executing its initial corpus. "
            "That is either a harness whose own setup faults, or a corpus "
            "input that already reproduces — the replay says which, so read "
            "its verdict before editing anything"
        )
    if result.executions <= DEAD_EXEC_FLOOR and not result.inited:
        # The opening line is the cause when there is one: a binary that was
        # rebuilt out from under the campaign, a library that will not load, a
        # sanitizer runtime refusing to start. Reporting the generic sentence
        # over it sends the reader to the build log for an answer that was
        # already printed.
        return VERDICT_DEAD, (
            f"ran {result.executions} executions and never reached INITED "
            f"(rc={result.returncode}); the binary is not fuzzing"
            + (f" — it printed: {result.opening}" if result.opening else
               " — check the build log and that the linked library loads")
        )
    kinds = [name for name, hit in
             (("out-of-memory", result.oom), ("timeout", result.timeout),
              ("leak", result.leak)) if hit]
    if kinds and state.noise_streak + 1 >= NOISE_SLICES:
        return VERDICT_NOISE_FLOOD, (
            f"ended in {'/'.join(kinds)} for {state.noise_streak + 1} slices "
            f"running; these are auto-rejected downstream, so the slices "
            f"bought nothing — bound the allocation in the harness, or free "
            f"what it allocates"
        )
    fresh = result.artifacts if fresh is None else fresh
    if new_edges > 0 or new_features > 0:
        return VERDICT_PRODUCTIVE, (
            f"{new_edges} new edges, {new_features} new features, "
            f"{len(fresh)} new artifacts"
        )
    if result.artifacts:
        # Coverage, not the artifact's name, decides whether a repeat crash is
        # progress. One bug is reached by countless different inputs, each
        # saved under its own sha1, so comparing filenames would call the same
        # wall a new discovery every slice. No new edges *and* a crash means
        # the fuzzer keeps ending in the same place.
        if state.repeat_streak + 1 >= REPEAT_SLICES:
            return VERDICT_BLOCKED_ON_CRASH, (
                f"crashed with no new coverage for {state.repeat_streak + 1} "
                f"slices running. libFuzzer stops at its first crash, so this "
                f"harness cannot explore past a bug that is already filed — "
                f"there is nothing more here until that one is fixed"
            )
        return VERDICT_PRODUCTIVE, (
            f"{len(fresh)} new artifacts, no new coverage — the crash is "
            f"filed; one more slice decides whether it blocks the harness"
        )
    if state.dry_streak + 1 >= SATURATION_SLICES:
        return VERDICT_SATURATED, (
            f"no new edges and no new features across {state.dry_streak + 1} "
            f"slices at {coverage_note(state)}; widen or re-seed it"
        )
    return VERDICT_DRY, f"no new coverage ({state.dry_streak + 1} in a row)"


def select_next(states: "list[HarnessState]", total_slices: int) -> "HarnessState | None":
    """Which harness gets the next slice.

    UCB1 over new-edges-per-second. An unrun harness scores infinite, so every
    harness is tried once before any is tried twice — that is the diversity
    floor, and it is what stops a lucky first harness from consuming the whole
    budget. After that the exploration term grows with how long a harness has
    been passed over, so a quiet one is revisited rather than written off.
    """
    live = [state for state in states if not state.quarantine]
    if not live:
        return None
    unrun = [state for state in live if state.slices == 0]
    if unrun:
        return min(unrun, key=lambda state: state.name)
    ceiling = max((state.value for state in live), default=0.0) or 1.0
    horizon = math.log(max(total_slices, 1) + 1)

    def score(state: HarnessState) -> float:
        return (state.value / ceiling
                + EXPLORE_WEIGHT * math.sqrt(horizon / state.slices))

    # Name breaks ties so a resumed campaign makes the same choice a fresh one
    # would; two harnesses with identical history are otherwise ordered by
    # whatever the filesystem listed first.
    return min(live, key=lambda state: (-score(state), state.name))


def revive(states: "list[HarnessState]", corpus_size) -> "list[str]":
    """Return saturated harnesses to rotation once their corpus has grown.

    A saturated harness is not broken — it ran out of reach with the corpus it
    had — and a blocked one is waiting on a bug it already reported. Another
    agent's campaign, a merge, a seeding pass, or a landed fix can change
    either, and the cheapest way to notice is to compare the corpus against
    its size when the harness was set aside. The other quarantine reasons need
    a human edit to the harness and are never revived automatically.
    """
    revived = []
    for state in states:
        if state.quarantine not in REVIVABLE_VERDICTS:
            continue
        if corpus_size(state.name) > state.corpus_at_quarantine:
            state.quarantine = ""
            state.quarantine_detail = ""
            state.dry_streak = 0
            state.repeat_streak = 0
            revived.append(state.name)
    return revived


# ── The campaign ────────────────────────────────────────────────────

@contextlib.contextmanager
def exclusive(results_dir: "str | os.PathLike", logger=None):
    """Hold the one campaign slot for this results tree.

    Two agents assigned S4 would otherwise run the same global campaign at the
    same time: one `state.json`, one corpus per harness, and a merge that
    replaces a corpus directory wholesale. libFuzzer tolerates concurrent
    writers into a corpus — every file is named for its own hash — but nothing
    else here does.

    Advisory and kernel-held, like the build lease: released when the holder
    dies, so a killed campaign cannot wedge the next one. A caller that cannot
    take it does not queue behind it — the point of S4 is to spend one
    campaign's wall per iteration, and waiting would spend two.
    """
    lock = fuzz_harness.fuzz_root(results_dir) / ".campaign.lock"
    lock.parent.mkdir(parents=True, exist_ok=True)
    try:
        handle = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        yield True  # unwritable results tree: fall open rather than refuse
        return
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(handle)
        if logger:
            logger("[fuzz] another agent is already running the campaign for "
                   "this target; leaving the wall to it")
        yield False
        return
    try:
        yield True
    finally:
        fcntl.flock(handle, fcntl.LOCK_UN)
        os.close(handle)


def state_path(results_dir: "str | os.PathLike") -> Path:
    return fuzz_harness.fuzz_root(results_dir) / "state.json"


def journal_path(results_dir: "str | os.PathLike") -> Path:
    return fuzz_harness.fuzz_root(results_dir) / "campaign.jsonl"


def load_states(results_dir: "str | os.PathLike") -> "dict[str, HarnessState]":
    try:
        raw = json.loads(state_path(results_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    fields = {f for f in HarnessState.__dataclass_fields__}
    out: "dict[str, HarnessState]" = {}
    for name, row in (raw.get("harnesses") or {}).items():
        if isinstance(row, dict):
            out[name] = HarnessState(**{k: v for k, v in row.items() if k in fields})
    return out


def save_states(results_dir: "str | os.PathLike",
                states: "dict[str, HarnessState]") -> None:
    path = state_path(results_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"harnesses": {name: s.as_dict() for name, s in states.items()}}
    staged = path.with_suffix(".json.tmp")
    staged.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    os.replace(staged, path)


class Campaign:
    """One process's fuzzing budget, spent across the harnesses it was given."""

    def __init__(self, config, agent: int = 1, *,
                 slice_seconds: int = DEFAULT_SLICE_SECONDS,
                 sanitizer: str = "asan",
                 log=lambda message: print(message, file=sys.stderr)):
        self.config = config
        self.agent = agent
        self.slice_seconds = max(5, int(slice_seconds))
        self.sanitizer = sanitizer
        self.log = log
        self.results = Path(config.results_dir)
        self.states = load_states(self.results)
        self.total_slices = sum(s.slices for s in self.states.values())
        # Set by run(); replay and merge check it so the whole campaign — not
        # just its slices — stays inside the wall it was given.
        self.deadline = float("inf")
        self.reserve = REPLAY_RESERVE_SECONDS
        # A target library whose install name is relative is not found by an
        # rpath, and a harness that cannot load its library reports as a dead
        # binary rather than as a configuration problem. Carrying the
        # directory through sanitizer.LIBRARY_PATH_ENV is the existing answer:
        # the name survives every hop, and prepare_runtime_env expands it into
        # the loader's own variable at the last point before exec.
        library = fuzz_harness.coverage_library(config, sanitizer).path
        self.library_dir = str(Path(library).parent) if library else ""

    # ── corpus ──────────────────────────────────────────────────────

    def remaining(self) -> float:
        """Seconds left of the campaign's whole wall, not just its slices."""
        return self.deadline - time.monotonic()

    def seed(self, state: HarnessState) -> int:
        """Fill an empty corpus from the target's own test data.

        Only when it is empty: a corpus the fuzzer has been building is worth
        more than anything copied in, and re-seeding one would undo the
        minimisation that keeps slices fast. Copying, never linking, because
        libFuzzer rewrites and prunes what it is given.

        An operator can point ``FUZZ_SEED_CORPUS_DIR`` at a locally staged
        OSS-Fuzz/ClusterFuzz corpus; its inputs seed the empty corpus alongside
        the target's own test data. Local only — nothing is fetched.
        """
        corpus = fuzz_harness.corpus_dir(self.results, state.name)
        if self.corpus_size(state.name):
            return 0
        corpus.mkdir(parents=True, exist_ok=True)
        sources = list(fuzz_harness.seed_candidates(self.config.target_root))
        operator_dir = os.environ.get(fuzz_harness.SEED_CORPUS_DIR_ENV, "")
        if operator_dir:
            sources += fuzz_harness.operator_seed_candidates(operator_dir)
        copied = 0
        for source in sources:
            # Content-addressed, so two test files with the same name from
            # different directories both survive.
            digest = hashlib.sha1(source.read_bytes()).hexdigest()[:16]
            destination = corpus / digest
            if destination.exists():
                continue
            try:
                destination.write_bytes(source.read_bytes())
            except OSError:
                continue
            copied += 1
        if copied:
            self.log(f"[fuzz] {state.name}: seeded {copied} inputs from the "
                     f"target's test data into an empty corpus")
        return copied

    def corpus_size(self, name: str) -> int:
        directory = fuzz_harness.corpus_dir(self.results, name)
        try:
            return sum(1 for path in directory.iterdir() if path.is_file())
        except OSError:
            return 0

    def _minimise(self, state: HarnessState) -> None:
        """Replace a harness's corpus with the smallest set of equal coverage.

        Short slices pay the corpus-loading cost every time, so an unpruned
        corpus makes each later slice slower than the last. This is
        ClusterFuzz's corpus pruning, run on a slice counter rather than a
        daily cron.
        """
        corpus = fuzz_harness.corpus_dir(self.results, state.name)
        if self.corpus_size(state.name) < 2:
            return
        if self.remaining() < MERGE_RESERVE_SECONDS + self.reserve:
            return  # minimisation is an optimisation; the wall is a promise
        staged = corpus.with_name(corpus.name + ".merged")
        shutil.rmtree(staged, ignore_errors=True)
        staged.mkdir(parents=True, exist_ok=True)
        completed = self._execute(
            state, ["-merge=1", str(staged), str(corpus)],
            seconds=max(30, self.slice_seconds), corpus_cwd=staged,
        )
        merged = sum(1 for path in staged.iterdir() if path.is_file())
        if completed.returncode == 0 and merged:
            before = self.corpus_size(state.name)
            shutil.rmtree(corpus, ignore_errors=True)
            staged.rename(corpus)
            self.log(f"[fuzz] {state.name}: corpus {before} -> {merged} after merge")
        else:
            # A failed merge must not destroy the corpus it was minimising.
            shutil.rmtree(staged, ignore_errors=True)
        state.since_merge = 0

    # ── running ─────────────────────────────────────────────────────

    def _execute(self, state: HarnessState, args: "list[str]", *,
                 seconds: int, corpus_cwd: Path,
                 log: "Path | None" = None) -> subprocess.CompletedProcess:
        """Run the fuzzer, streaming its output to a file rather than memory.

        A fuzzer's output is arbitrary bytes and arbitrary length: it echoes
        parts of the inputs it is mutating, and a target that logs per parse
        can emit tens of megabytes in one slice. Capturing that into a decoded
        string is two failures waiting — a UnicodeDecodeError that kills the
        whole campaign on the first non-UTF-8 byte, and a slice's worth of
        output held in memory. Writing to disk and reading a bounded tail back
        avoids both, and the log is evidence the agent wants anyway.
        """
        corpus_cwd.mkdir(parents=True, exist_ok=True)
        environment = dict(os.environ, FUZZER=state.name)
        if self.library_dir:
            environment[sanitizer_lib.LIBRARY_PATH_ENV] = self.library_dir
        # cwd is under RESULTS_DIR and -artifact_prefix is absolute, so nothing
        # this process writes can land in the target checkout — which is the
        # whole reason a peer backend's build stays fresh while we fuzz.
        sink = log.open("wb") if log is not None else subprocess.DEVNULL
        try:
            return run_timeout(
                [state.binary, *args], seconds + 30, kill=True,
                rss_mb=0, cwd=str(corpus_cwd),
                stdout=sink, stderr=subprocess.STDOUT,
                env=sanitizer_lib.prepare_runtime_env(self.sanitizer, environment),
            )
        finally:
            if log is not None:
                sink.close()

    def run_slice(self, state: HarnessState, window: int = 0) -> SliceResult:
        corpus = fuzz_harness.corpus_dir(self.results, state.name)
        artifacts = fuzz_harness.artifact_dir(self.results, state.name)
        artifacts.mkdir(parents=True, exist_ok=True)
        corpus.mkdir(parents=True, exist_ok=True)
        window = window or self.slice_seconds
        args = [
            f"-max_total_time={window}",
            f"-timeout={UNIT_TIMEOUT_SECONDS}",
            f"-rss_limit_mb={RSS_LIMIT_MB}",
            f"-malloc_limit_mb={MALLOC_LIMIT_MB}",
            f"-artifact_prefix={artifacts}{os.sep}",
            "-print_final_stats=1",
        ]
        # The format's own tokens, when the project ships them. Without a
        # dictionary the mutator rediscovers `<!DOCTYPE` a byte at a time.
        if state.dictionary:
            args.append(f"-dict={state.dictionary}")
        # ClusterFuzz rotates value profile onto a third of its runs; a
        # five-slice campaign has no room for a coin flip, so it is aimed
        # instead. A harness that has gone dry is the case value profile
        # exists for: it makes memcmp-style comparisons visible to the
        # mutator, which is exactly the `magic-gate` wall a dry harness is
        # usually stuck behind.
        if state.dry_streak:
            args.append("-use_value_profile=1")
        args.append(str(corpus))
        logs = fuzz_harness.log_dir(self.results, state.name)
        logs.mkdir(parents=True, exist_ok=True)
        log = logs / f"slice-{state.slices + 1:04d}.log"
        started = time.monotonic()
        completed = self._execute(
            state, args, seconds=window, corpus_cwd=corpus, log=log)
        elapsed = time.monotonic() - started
        parsed = parse_log(read_log(log))
        return SliceResult(
            harness=state.name, seconds=elapsed,
            returncode=completed.returncode, log=str(log), **parsed,
        )

    # ── crash routing ───────────────────────────────────────────────

    def route_artifacts(self, state: HarnessState,
                        artifacts: "list[str]") -> "list[str]":
        """Replay every artifact through bin/probe and report what it filed.

        The campaign deliberately files nothing itself. bin/probe is the single
        entry point for harness-authored testcases: it picks the runner,
        records structured run state, confirms across five runs, and hands a
        stable crash to the existing gate. A fuzz artifact that skipped that
        would be an unconfirmed, undeduplicated, ungated claim.
        """
        if not state.source:
            self.log(
                f"[fuzz] {state.name}: {len(artifacts)} artifacts left "
                f"unreplayed — no harness source recorded, so bin/probe has "
                f"nothing to rebuild them against"
            )
            return []
        scratch = self.results / f"scratch-{self.agent}"
        scratch.mkdir(parents=True, exist_ok=True)
        source = Path(state.source)
        replica = scratch / source.name
        if not replica.is_file() or replica.read_bytes() != source.read_bytes():
            replica.write_bytes(source.read_bytes())
        filed: "list[str]" = []
        replayed: "list[str]" = []
        for raw in artifacts:
            artifact = Path(raw)
            if not artifact.is_file():
                continue
            if self.remaining() < self.reserve:
                self.log(
                    f"[fuzz] {state.name}: out of budget with artifacts left "
                    f"unreplayed; they stay in artifacts/ and are replayed by "
                    f"the next campaign")
                break
            landed = scratch / f"fz-{state.name}-{artifact.name}"
            if not landed.is_file():
                landed.write_bytes(artifact.read_bytes())
            probe = Path(__file__).resolve().parent.parent / "bin" / "probe"
            # probe rebuilds the same source with its own compiler. Left to
            # its default that can be a different clang from the one that
            # built the fuzzer — and two sanitizer runtimes in one process
            # abort with "interceptors are not working" before the testcase
            # ever runs, which reads as an unreproducible crash.
            compiler = fuzz_harness.compiler_for(source)
            command = [sys.executable, str(probe), "--confirm",
                       "--harness", replica.name]
            # Without the hypothesis the run records against nothing, so the
            # campaign's crashes never join the strategy's evidence.
            if state.hypothesis_id:
                command += ["--hypothesis-id", state.hypothesis_id]
            command.append(str(landed))
            # Bounded by the campaign's own wall, through the same process
            # tree wrapper everything else uses. A plain subprocess.run has no
            # deadline, and probe's five confirmation runs plus a harness
            # build can outlast the whole budget on their own.
            completed = run_timeout(
                command, max(self.reserve, int(self.remaining())),
                kill=True, capture_output=True, text=True,
                env={**os.environ,
                     # The replay has to use the sanitizer the campaign fuzzed
                     # under, or a UBSan finding is re-run under ASan and
                     # recorded as unreproducible.
                     "PROBE_SANITIZER": self.sanitizer,
                     # The compiler that built the campaign binary, not an
                     # ambient one: two sanitizer runtimes in one process
                     # abort before the testcase runs, which reads as an
                     # unreproducible crash.
                     "CC": compiler,
                     "CXX": compiler + "++" if not compiler.endswith("++") else compiler},
            )
            output = (completed.stdout or "") + (completed.stderr or "")
            for line in output.splitlines():
                if "CRASH FILED" in line:
                    filed.append(line.strip())
            # Seen only on a verdict probe actually reached. A build failure,
            # a timeout, or a killed replay leaves the artifact pending, and
            # `pending_artifacts` picks it up at the start of the next
            # campaign — otherwise one transient failure suppressed a real
            # crash permanently.
            if _terminal_verdict(output, completed.returncode):
                replayed.append(artifact.name)
            else:
                self.log(f"[fuzz] {state.name}: {landed.name} reached no "
                         f"verdict (rc={completed.returncode}); left pending "
                         f"for the next campaign")
                break
            self.log(f"[fuzz] {state.name}: replayed {landed.name} "
                     f"(probe rc={completed.returncode})")
        state.seen_artifacts = sorted(set(state.seen_artifacts) | set(replayed))
        return filed

    def pending_artifacts(self, state: HarnessState) -> "list[str]":
        """Artifacts on disk that no campaign has adjudicated yet.

        Replayed before any new fuzzing: an artifact already found is worth
        more than another slice, and the previous campaign may have run out of
        wall midway through its replays.
        """
        directory = fuzz_harness.artifact_dir(self.results, state.name)
        seen = set(state.seen_artifacts)
        try:
            return sorted(str(path) for path in directory.iterdir()
                          if path.is_file() and path.name not in seen)
        except OSError:
            return []

    # ── the loop ────────────────────────────────────────────────────

    def add(self, name: str, binary: str, source: str = "",
            hypothesis_id: str = "") -> HarnessState:
        state = self.states.get(name)
        if state is None:
            state = HarnessState(name=name, binary=binary, source=source,
                                 hypothesis_id=hypothesis_id)
            self.states[name] = state
        else:
            if state.binary != binary:
                # A rebuilt harness is a different experiment, so *all* of it
                # is stale — not just the coverage. Keeping slices, value,
                # counters, streaks, or seen artifacts would schedule the new
                # binary on the old one's yield and suppress inputs it has
                # never run. The corpus is the one thing that carries over,
                # and it lives on disk rather than here.
                carried = HarnessState(
                    name=state.name, binary=binary, source=source or state.source,
                    hypothesis_id=hypothesis_id or state.hypothesis_id,
                    dictionary=state.dictionary,
                )
                self.states[name] = carried
                return carried
            state.source = source or state.source
            state.hypothesis_id = hypothesis_id or state.hypothesis_id
        return state

    def run(self, budget_seconds: int = DEFAULT_BUDGET_SECONDS) -> dict:
        """Spend the budget, hand the rest of the iteration back, and report.

        The budget is the *whole* campaign — slices, artifact replays, and
        corpus merges alike. Counting only slices was how a five-minute
        campaign became eight: replay confirms each artifact five times, and
        a merge walks the corpus, and both ran after the last deadline check.
        """
        budget = max(1, int(budget_seconds))
        # A budget shorter than a slice shrinks the slice rather than
        # overrunning it. Rounding up to a full slice is the one way a bounded
        # campaign can exceed the wall it was given.
        self.slice_seconds = min(self.slice_seconds, budget)
        # Proportional, not fixed: a flat 45s holdback is prudent against a
        # five-minute budget and eats half of a short one. A quarter of the
        # wall is enough for probe's five confirmation runs on any target
        # whose slices are this short.
        self.reserve = min(REPLAY_RESERVE_SECONDS, max(10, budget // 4))
        self.deadline = time.monotonic() + budget
        deadline = self.deadline
        states = list(self.states.values())
        summary_filed: "list[str]" = []
        for state in states:
            pending = self.pending_artifacts(state)
            if pending:
                self.log(f"[fuzz] {state.name}: {len(pending)} artifact(s) "
                         f"pending from an earlier campaign; replaying first")
                summary_filed.extend(self.route_artifacts(state, pending))
            self.seed(state)
            if not state.dictionary:
                state.dictionary = fuzz_harness.dictionary_for(
                    self.config.target_root, state.name)
                if state.dictionary:
                    self.log(f"[fuzz] {state.name}: using "
                             f"{Path(state.dictionary).name}")
        for name in revive(states, self.corpus_size):
            self.log(f"[fuzz] {name}: corpus grew since quarantine; back in rotation")
        summary = {
            "slices": 0, "artifacts": 0, "filed": summary_filed,
            "quarantined": {}, "harnesses": {}, "stopped": "",
        }
        while True:
            # Checked before selecting, not after running: starting a slice
            # with less than a slice left overruns the budget by most of one,
            # and this budget is time the other strategies are waiting for.
            # A crash found in the final slice is worthless with no wall left
            # to adjudicate it, so the replay window is always held back — but
            # held back by *shrinking* the last slice rather than skipping it,
            # or a 70-second budget would buy one 25-second slice and idle.
            window = min(self.slice_seconds,
                         int(self.remaining()) - self.reserve)
            if window < MIN_SLICE_SECONDS:
                summary["stopped"] = "budget spent"
                break
            state = select_next(states, self.total_slices)
            if state is None:
                summary["stopped"] = (
                    "every harness is quarantined — nothing left to run, so "
                    "the rest of the budget goes back to the other strategies"
                )
                break
            result = self.run_slice(state, window)
            new_edges, new_features = progress(result, state)
            fresh = fresh_artifacts(result, state)
            verdict, detail = classify(
                result, state, new_edges, fresh, new_features)
            self._record(state, result, verdict, detail,
                         new_edges, fresh, new_features)
            summary["slices"] += 1
            if fresh:
                summary["artifacts"] += len(fresh)
                summary["filed"].extend(self.route_artifacts(state, fresh))
            if verdict in QUARANTINE_VERDICTS:
                state.quarantine = verdict
                state.quarantine_detail = detail
                summary["quarantined"][state.name] = f"{verdict}: {detail}"
                self.log(f"[fuzz] {state.name}: QUARANTINED ({verdict}) — {detail}")
            elif state.since_merge >= MERGE_EVERY_SLICES:
                self._minimise(state)
            save_states(self.results, self.states)
        summary["harnesses"] = {
            name: state.as_dict() for name, state in self.states.items()
        }
        summary["seconds_returned"] = round(max(0.0, deadline - time.monotonic()), 1)
        save_states(self.results, self.states)
        self.log(f"[fuzz] campaign over ({summary['stopped']}); "
                 f"{summary['seconds_returned']}s of the budget unspent")
        return summary

    def _record(self, state: HarnessState, result: SliceResult,
                verdict: str, detail: str, new_edges: int,
                fresh: "list[str]", new_features: int = 0) -> None:
        if not state.first_slice:
            state.first_slice = {
                "seconds": round(result.seconds, 2),
                "verdict": verdict,
                "detail": detail,
                "executions": result.executions,
                "exec_rate": int(result.executions / result.seconds)
                if result.seconds else 0,
                "edges": result.edges,
                "new_edges": new_edges,
                "features": result.features,
                "new_features": new_features,
                "artifacts": len(result.artifacts),
                "new_artifacts": len(fresh),
                "log": result.log,
            }
        state.slices += 1
        self.total_slices += 1
        state.seconds += result.seconds
        state.executions += result.executions
        state.edges = max(state.edges, result.edges)
        state.counters = max(state.counters, result.counters)
        state.features = max(state.features, result.features)
        state.artifacts += len(fresh)
        state.since_merge += 1
        # Dry means neither signal moved. Counting only edges made a
        # value-profiled slice look dry while it was still learning.
        state.dry_streak = 0 if (new_edges or new_features) else state.dry_streak + 1
        state.repeat_streak = (
            state.repeat_streak + 1
            if result.artifacts and not (new_edges or new_features) else 0)
        state.noise_streak = (
            state.noise_streak + 1
            if (result.oom or result.timeout or result.leak) else 0)
        state.value = _ewma(
            state.value,
            (new_edges + new_features) / result.seconds if result.seconds else 0.0)
        if verdict in REVIVABLE_VERDICTS:
            state.corpus_at_quarantine = self.corpus_size(state.name)
        # A crash cuts a slice short, so libFuzzer's own exec/s is missing or
        # stale on exactly the slices that mattered; the measured rate is
        # always available and is what the scheduler's value derives from.
        rate = int(result.executions / result.seconds) if result.seconds else 0
        workqueue.append_jsonl(journal_path(self.results), {
            "ts": workqueue.now_iso(), "agent": self.agent,
            "harness": state.name, "slice": state.slices,
            "seconds": round(result.seconds, 2), "verdict": verdict,
            "detail": detail, "executions": result.executions,
            "exec_rate": rate, "libfuzzer_exec_rate": result.exec_rate,
            "edges": result.edges,
            "new_edges": new_edges, "features": result.features,
            "new_features": new_features,
            "artifacts": len(result.artifacts), "new_artifacts": len(fresh),
            "log": result.log, "corpus": self.corpus_size(state.name),
        })
        self.log(
            f"[fuzz] {state.name} slice {state.slices}: {verdict} — "
            f"{result.executions} execs at {rate}/s, "
            f"{result.edges} edges (+{new_edges}), "
            f"{result.features} features (+{new_features}), {detail}"
        )
