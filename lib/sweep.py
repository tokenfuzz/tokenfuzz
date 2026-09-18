#!/usr/bin/env python3
"""The budgeted sweep: one cheap, tool-less pass per unreceipted unit.

The ranked queue buys depth on the files the scorer likes, and a session
pays for every file it opens again on every later turn. The sweep buys
breadth instead: it hands one unit of source (a parsed function, or a fixed
line window where the call graph has nothing) to a one-shot decision with
no tools, and requires a receipt plus zero or more leads in return. Each
unit is paid for once, on whatever model `[sweep] model` names.

It never probes, claims a card, or files a finding. Its outputs are
receipts (`source: sweep`) and pending hypotheses owned by agent `sweep`,
which the reproduce lane picks up through the ordinary handoff. It spends
against `[sweep] token_budget`, an operator-visible number, and records
where it stopped in `state/sweep.json` so the coverage report can say how
far the budget reached instead of implying the tree was covered.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import signal
from dataclasses import dataclass, field
from pathlib import Path

import callgraph
import coverage_ledger
import llm_decide
import llm_usage
import prompt_render
import strategies
import workqueue


DECISION = "sweep_unit"
REQUIRED_KEYS = "examined,verdicts,leads"
STATE_NAME = "sweep.json"
AGENT = "sweep"
#: Consecutive units with no usable reply before the sweep stops: a backend
#: that is refusing or throttling is not worth the rest of the budget.
MAX_CONSECUTIVE_FAILURES = 3
_LEAD_STRATEGIES = frozenset(strategies.ACTIVE) - {"S1", "S4", "S6"}


@dataclass
class Unit:
    file: str
    start: int
    end: int
    functions: list[str] = field(default_factory=list)
    reason: str = ""
    total_lines: int = 0
    sha1: str = ""
    manifest_entry: dict = field(default_factory=dict, repr=False)

    @property
    def key(self) -> str:
        return f"{self.file}:{self.start}-{self.end}"


class SweepStateError(ValueError):
    """Persisted spend state is unreadable or owned by another process, so
    another call would be unsafe."""


@contextlib.contextmanager
def _owner_lock(results_dir: Path):
    """One sweep per results tree, refused rather than queued.

    The audit's background sweep can run for hours; a manual `bin/sweep`
    that silently waited behind it would look hung, and two spenders
    interleaving on one state file would double-count or lose spend.
    """
    path = state_path(results_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    lock_path = path.with_name(f".{path.name}.lock")
    with lock_path.open("a+", encoding="utf-8") as lock:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            raise SweepStateError(
                f"another sweep holds {lock_path}; wait for it or stop it"
            ) from exc
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def state_path(results_dir: Path) -> Path:
    return workqueue.state_dir(Path(results_dir)) / STATE_NAME


def read_state(results_dir: Path) -> dict:
    try:
        data = json.loads(state_path(results_dir).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as exc:
        raise SweepStateError(f"cannot read {state_path(results_dir)}: {exc}") from exc
    if not isinstance(data, dict):
        raise SweepStateError(f"{state_path(results_dir)} is not a JSON object")
    return data


def _write_state(results_dir: Path, data: dict) -> None:
    path = state_path(results_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(data, sort_keys=True, indent=1) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def _windows(start: int, end: int, size: int) -> list[tuple[int, int]]:
    out = []
    cursor = start
    while cursor <= end:
        out.append((cursor, min(end, cursor + size - 1)))
        cursor += size
    return out


def plan_units(
    ctx: workqueue.Context,
    unit_lines: int = 120,
    graph: dict | None = None,
) -> list[Unit]:
    """Unreceipted units, gap first: files the window never offered come
    before files it did, and the least-read file before the better-read one.
    A parsed function is one unit unless it is long enough to split."""
    manifest = coverage_ledger.read_manifest(ctx.results_dir)
    receipted = coverage_ledger.examined_ranges_by_file(ctx.results_dir)
    if graph is None:
        graph = callgraph.load(ctx.results_dir) or {}
    fraction = {
        str(row.get("file") or ""): min(
            1.0,
            coverage_ledger.examined_lines(receipted.get(str(row.get("file") or ""), []))
            / int(row.get("lines") or 1),
        )
        for row in manifest if int(row.get("lines") or 0) > 0
    }
    size = max(20, int(unit_lines))
    ordered = sorted(
        manifest,
        key=lambda row: (
            bool(row.get("offered")),
            fraction.get(str(row.get("file") or ""), 0.0),
            str(row.get("file") or ""),
        ),
    )
    units: list[Unit] = []
    for row in ordered:
        rel = str(row.get("file") or "")
        total = int(row.get("lines") or 0)
        done = receipted.get(rel, [])
        if (
            not rel or total <= 0
            or coverage_ledger.examined_lines(done) >= total
        ):
            continue
        reason = "never offered" if not row.get("offered") else f"{fraction.get(rel, 0.0) * 100:.0f}% receipted"
        definitions = coverage_ledger.function_ranges(
            ctx.results_dir, rel, total, graph,
        )
        candidates: list[tuple[int, int, list[str]]] = []
        if definitions:
            first_start = definitions[0][1]
            if first_start > 1:
                candidates.extend((s, e, []) for s, e in _windows(1, first_start - 1, size))
            for name, start, end in definitions:
                if end - start + 1 > size:
                    candidates.extend((s, e, [name]) for s, e in _windows(start, end, size))
                else:
                    candidates.append((start, end, [name]))
        else:
            candidates.extend((s, e, []) for s, e in _windows(1, total, size))
        for start, end, names in candidates:
            if any(rs <= start and end <= re for rs, re in done):
                continue
            units.append(Unit(
                rel, start, end, names, reason, total,
                str(row.get("sha1") or ""), dict(row),
            ))
    return units


def _numbered_source(
    ctx: workqueue.Context, unit: Unit,
    expected_sha1: str,
    source_cache: dict[str, tuple[str, list[str]]] | None = None,
) -> str:
    path = ctx.target_root / unit.file
    cache = source_cache if source_cache is not None else {}
    if unit.file not in cache:
        with path.open("rb") as stream:
            body = stream.read()
        cache[unit.file] = (
            hashlib.sha1(body).hexdigest(),
            body.decode("utf-8", "replace").splitlines(),
        )
    sha1, lines = cache[unit.file]
    if not expected_sha1 or sha1 != expected_sha1:
        raise OSError(f"{unit.file} changed after the sweep plan")
    width = len(str(unit.end))
    return "\n".join(
        f"{number:>{width}}  {lines[number - 1] if number - 1 < len(lines) else ''}"
        for number in range(unit.start, unit.end + 1)
    )


def build_prompt(
    ctx: workqueue.Context, unit: Unit, attacker_controls: str,
    source_cache: dict[str, tuple[str, list[str]]] | None = None,
    neighbourhood_cache: dict[str, list[str]] | None = None,
    graph: dict | None = None,
) -> str:
    row = (
        {"lines": unit.total_lines, "sha1": unit.sha1}
        if unit.total_lines and unit.sha1
        else (coverage_ledger.manifest_row(ctx.results_dir, unit.file) or {})
    )
    blocks = neighbourhood_cache if neighbourhood_cache is not None else {}
    if unit.file not in blocks:
        blocks[unit.file] = callgraph.block_for(
            ctx.results_dir, unit.file, ctx.target_root, graph,
        )
    block = blocks[unit.file]
    return prompt_render.render_template("sweep_unit.md.j2", {
        "attacker_controls": attacker_controls or "bytes",
        "file": unit.file,
        "start": str(unit.start),
        "end": str(unit.end),
        "total_lines": str(row.get("lines") or unit.end),
        "functions": ", ".join(unit.functions) or "(none parsed; treat the window as one unit)",
        "neighbourhood": "\n".join(block).strip(),
        "source": _numbered_source(ctx, unit, str(row.get("sha1") or ""), source_cache),
    })


class ReplyError(ValueError):
    """A reply the sweep cannot turn into a verified receipt."""


class _Stopped(Exception):
    """SIGTERM from the audit's shutdown; the loop ends and state is written."""


def _covered(unit: Unit, receipted: dict[str, list[tuple[int, int]]]) -> bool:
    return any(s <= unit.start and unit.end <= e for s, e in receipted.get(unit.file, []))


def _name(value: object) -> str:
    """A function name as the parser wrote it: no call parentheses, no space."""
    text = str(value or "").strip()
    return text[:-2].strip() if text.endswith("()") else text


def parse_reply(unit: Unit, reply: object) -> tuple[list[tuple[int, int]], list[dict], list[dict]]:
    """(examined ranges, verdicts, leads) from a decision reply, each checked
    against the unit: ranges must sit inside it, and a lead must name a
    parsed function (or fall inside the window) with a known diagnostic."""
    if not isinstance(reply, dict):
        raise ReplyError("reply is not an object")
    ranges: list[tuple[int, int]] = []
    for pair in reply.get("examined") or []:
        if not (isinstance(pair, list) and len(pair) == 2):
            raise ReplyError(f"examined entry {pair!r} is not [start, end]")
        try:
            start, end = int(pair[0]), int(pair[1])
        except (TypeError, ValueError) as exc:
            raise ReplyError(f"examined entry {pair!r} is not numeric") from exc
        if start < unit.start or end > unit.end or end < start:
            raise ReplyError(f"examined range {start}-{end} is outside unit {unit.key}")
        ranges.append((start, end))
    ranges = coverage_ledger.merge_ranges(ranges)
    if not ranges:
        raise ReplyError("reply has no examined ranges")
    if ranges != [(unit.start, unit.end)]:
        raise ReplyError(f"examined ranges do not cover the whole unit {unit.key}")
    verdicts = [v for v in (reply.get("verdicts") or []) if isinstance(v, dict)]
    window = f"lines {unit.start}-{unit.end}"
    expected_verdicts = unit.functions or [window]
    for verdict in verdicts:
        verdict["function"] = _name(verdict.get("function")) or (window if not unit.functions else "")
    actual_verdicts = [str(v.get("function") or "") for v in verdicts]
    allowed_verdicts = {"clean", "suspicious", "needs-context"}
    if sorted(actual_verdicts) != sorted(expected_verdicts) or any(
        str(v.get("verdict") or "").strip().lower() not in allowed_verdicts
        for v in verdicts
    ):
        raise ReplyError(f"verdicts do not cover {', '.join(expected_verdicts)} exactly once")
    verdict_by_function = {
        str(verdict.get("function") or ""): str(verdict.get("verdict") or "").strip().lower()
        for verdict in verdicts
    }
    leads: list[dict] = []
    seen_leads: set[tuple[str, int, str]] = set()
    for raw in reply.get("leads") or []:
        if not isinstance(raw, dict):
            continue
        function = raw.get("function")
        try:
            line = int(raw.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        diagnostic = str(raw.get("diagnostic") or "").strip().lower()
        # The label only routes the lead to a lane; an absent or unknown one
        # is not a reason to lose a concrete claim.
        strategy = str(raw.get("strategy") or "").strip().upper()
        if strategy not in _LEAD_STRATEGIES:
            strategy = "S3"
        function = _name(function) or (window if not unit.functions else "")
        if function not in expected_verdicts:
            continue
        if verdict_by_function.get(function) == "clean":
            continue
        if not (unit.start <= line <= unit.end):
            continue
        if diagnostic not in workqueue.HYPOTHESIS_DIAGNOSTIC_CATEGORIES:
            continue
        if not any(start <= line <= end for start, end in ranges):
            continue
        text = {key: str(raw.get(key) or "").strip() for key in ("hypothesis", "input_shape", "guard_gap")}
        if not all(text.values()):
            continue
        identity = (function, line, diagnostic)
        if identity in seen_leads:
            continue
        seen_leads.add(identity)
        leads.append({
            "function": function, "line": line,
            "diagnostic": diagnostic, "strategy": strategy, **text,
        })
    return ranges, verdicts, leads


def _record_lead(ctx: workqueue.Context, unit: Unit, lead: dict) -> dict:
    # No card id on purpose: add_hypothesis would claim the card for
    # `sweep` and hold it against real agents for the lease TTL. The lead
    # reaches them through the reproduce handoff, keyed on this row.
    return workqueue.add_hypothesis(ctx, argparse.Namespace(
        id="", agent=AGENT, card_id="",
        hypothesis=lead["hypothesis"],
        file=f"{unit.file}:{lead['function']}:{lead['line']}",
        input_shape=lead["input_shape"], guard_gap=lead["guard_gap"],
        diagnostic=lead["diagnostic"], strategy=lead["strategy"],
        status="NEEDS_TESTCASE",
    ))


def run(
    ctx: workqueue.Context,
    *,
    token_budget: int,
    attacker_controls: str = "bytes",
    unit_lines: int = 120,
    max_units: int = 0,
    model: str = "",
    log=None,
) -> dict:
    """Sweep unreceipted units until the budget, the unit cap, or the tree
    runs out. Spend is the estimated prompt plus reply tokens of every call
    made, including failed ones, accumulated in state/sweep.json across
    invocations so a resumed run does not restart the budget. One process
    owns that read-modify-write state at a time."""
    with _owner_lock(ctx.results_dir):
        return _run_locked(
            ctx, token_budget=token_budget, attacker_controls=attacker_controls,
            unit_lines=unit_lines, max_units=max_units, model=model, log=log,
        )


def _run_locked(
    ctx: workqueue.Context,
    *,
    token_budget: int,
    attacker_controls: str,
    unit_lines: int,
    max_units: int,
    model: str,
    log,
) -> dict:
    say = log or (lambda message: None)
    state = read_state(ctx.results_dir)
    spent = int(state.get("spent_tokens") or 0)
    counts = {key: int(state.get(key) or 0) for key in ("units", "receipts", "leads", "failures")}
    graph = callgraph.load(ctx.results_dir) or {}
    units = plan_units(ctx, unit_lines, graph)
    stop = "exhausted" if not units else "interrupted"
    consecutive = 0
    attempted = 0
    source_cache: dict[str, tuple[str, list[str]]] = {}
    neighbourhood_cache: dict[str, list[str]] = {}
    cached_file = ""
    open_units = {unit.key for unit in units}
    receipt_signature: tuple[int, int, int] | None = None

    def refresh_open_units(force: bool = False) -> None:
        nonlocal receipt_signature
        try:
            info = coverage_ledger.receipts_path(ctx.results_dir).stat()
            signature = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
        except OSError:
            signature = (0, 0, 0)
        if not force and signature == receipt_signature:
            return
        receipted = coverage_ledger.examined_ranges_by_file(ctx.results_dir)
        open_units.intersection_update(
            unit.key for unit in units if not _covered(unit, receipted)
        )
        receipt_signature = signature

    refresh_open_units(force=True)

    def persist(reason: str) -> dict:
        # After every unit, not only at the end: the audit ends the sweep
        # with SIGTERM whenever the slots finish first, and spend that was
        # never written would be spent again on the next resume.
        current = {
            "spent_tokens": spent, "token_budget": token_budget, "stop": reason,
            "units_remaining": len(open_units),
            "updated_at": workqueue.now_iso(), **counts,
        }
        _write_state(ctx.results_dir, current)
        return current

    def _on_term(signum, frame):
        raise _Stopped()

    previous_model = os.environ.get("MODEL")
    previous_handler = signal.getsignal(signal.SIGTERM)
    if model:
        os.environ["MODEL"] = model
    signal.signal(signal.SIGTERM, _on_term)
    usage_index = llm_usage.find_usage_index(ctx.results_dir)
    try:
        for unit in units:
            if token_budget and spent >= token_budget:
                stop = "budget"
                break
            if max_units and attempted >= max_units:
                stop = "unit-cap"
                break
            # A session may have receipted this unit since the plan was made.
            # Stat the ledger on each turn and reparse it only after a write.
            refresh_open_units()
            if unit.key not in open_units:
                continue
            if cached_file != unit.file:
                source_cache.clear()
                neighbourhood_cache.clear()
                cached_file = unit.file
            try:
                text = build_prompt(
                    ctx, unit, attacker_controls,
                    source_cache=source_cache,
                    neighbourhood_cache=neighbourhood_cache,
                    graph=graph,
                )
            except OSError as exc:
                # The file changed or vanished under the plan; skip it, do
                # not spend on it, and let the next plan see the tree.
                say(f"sweep: cannot read {unit.key}: {exc}")
                continue
            refresh_open_units()
            if unit.key not in open_units:
                continue
            prompt_tokens = llm_usage.estimate_tokens(text)
            if token_budget and spent + prompt_tokens > token_budget:
                stop = "budget"
                break
            # Charge and persist the known cost before dispatch. SIGTERM can
            # arrive while the provider call is in flight; charging only on
            # return would let a resume buy the same call again.
            spent += prompt_tokens
            counts["units"] += 1
            attempted += 1
            persist("interrupted")
            reply = llm_decide.llm_decide(
                DECISION, REQUIRED_KEYS, text,
                timeout=llm_decide.decision_timeout(DECISION), usage_index=usage_index,
            )
            failure = ""
            ranges: list[tuple[int, int]] = []
            leads: list[dict] = []
            if reply is None:
                failure = "no usable reply"
            else:
                spent += llm_usage.estimate_tokens(json.dumps(reply))
                try:
                    ranges, verdicts, leads = parse_reply(unit, reply)
                    if ranges:
                        summary = ", ".join(
                            f"{v.get('function', '?')}={v.get('verdict', '?')}" for v in verdicts[:6]
                        )
                        refresh_open_units()
                        if unit.key in open_units:
                            coverage_ledger.record_receipt(
                                ctx, AGENT, unit.file,
                                lines=",".join(f"{s}-{e}" for s, e in ranges),
                                source="sweep", note=summary[:240],
                                expected_sha1=source_cache[unit.file][0],
                                manifest_entry=unit.manifest_entry or None,
                            )
                            counts["receipts"] += 1
                            open_units.discard(unit.key)
                            try:
                                info = coverage_ledger.receipts_path(ctx.results_dir).stat()
                                receipt_signature = (info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                            except OSError:
                                receipt_signature = None
                except (ReplyError, coverage_ledger.ReceiptError) as exc:
                    # A receipt the manifest cannot verify (the file was
                    # re-ranked or changed between plan and reply) is not
                    # coverage; the unit stays open for the next plan.
                    failure = f"rejected: {exc}"
            if failure:
                counts["failures"] += 1
                consecutive += 1
                say(f"sweep: {unit.key} {failure}")
                persist("interrupted")
                if consecutive >= MAX_CONSECUTIVE_FAILURES:
                    stop = "backend"
                    break
                continue
            consecutive = 0
            for lead in leads:
                _record_lead(ctx, unit, lead)
                counts["leads"] += 1
            persist("interrupted")
            say(
                f"sweep: {unit.key} examined={len(ranges)} leads={len(leads)} "
                f"spent={spent}{'/' + str(token_budget) if token_budget else ''}"
            )
        else:
            refresh_open_units(force=True)
            stop = "exhausted" if not open_units else "incomplete"
    except _Stopped:
        stop = "interrupted"
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
        if model:
            if previous_model is None:
                os.environ.pop("MODEL", None)
            else:
                os.environ["MODEL"] = previous_model
        # Persist even when an unexpected ledger or handoff error escapes.
        # The process may fail, but its completed calls must never disappear
        # from the spend ledger and become buyable again on resume.
        refresh_open_units(force=True)
        final_state = persist(stop)
    return final_state


def summary_lines(results_dir: Path) -> list[str]:
    """Coverage-report lines for the sweep's last recorded state."""
    try:
        state = read_state(results_dir)
    except SweepStateError as exc:
        return [f"- Sweep: state unavailable ({exc})"]
    if not state:
        return []
    budget = state.get("token_budget") or 0
    return [
        f"- Sweep: {state.get('receipts', 0)} receipted unit(s), {state.get('leads', 0)} lead(s), "
        f"{state.get('units_remaining', 0)} unit(s) left; spent ~{state.get('spent_tokens', 0)}"
        f"{f'/{budget}' if budget else ''} tokens, stopped: {state.get('stop', '?')}",
    ]


def main(argv: list[str]) -> int:
    import target_config

    parser = argparse.ArgumentParser(
        description="Sweep unreceipted source units with one-shot, tool-less decisions",
    )
    workqueue.add_common_args(parser)
    parser.add_argument("--token-budget", type=int, default=None,
                        help="estimated prompt/reply budget across the run (default: [sweep] token_budget)")
    parser.add_argument("--max-units", type=int, default=0, help="stop after this many units (0 = no cap)")
    parser.add_argument("--unit-lines", type=int, default=None,
                        help="maximum source lines in one decision (default: [sweep] unit_lines)")
    parser.add_argument("--model", default=None, help="model for the decisions (default: [sweep] model, else the backend default)")
    parser.add_argument("--dry-run", action="store_true", help="list the planned units and exit")
    args = parser.parse_args(argv)
    ctx = workqueue.context_from_args(args)
    config = target_config.Config(target_root=str(ctx.target_root))
    toml = target_config.find_target_toml(ctx.results_dir)
    if toml is not None:
        target_config.load_toml_into(config, toml)
    budget = config.sweep_token_budget if args.token_budget is None else args.token_budget
    unit_lines = config.sweep_unit_lines if args.unit_lines is None else args.unit_lines
    model = config.sweep_model if args.model is None else args.model
    if args.dry_run:
        for unit in plan_units(ctx, unit_lines):
            print(f"{unit.key} {','.join(unit.functions) or '-'} ({unit.reason})")
        return 0
    if budget <= 0:
        print("[sweep] no token budget: set [sweep] token_budget in target.toml or pass --token-budget", file=os.sys.stderr)
        return 2
    state = run(
        ctx, token_budget=budget, attacker_controls=config.attacker_controls_csv(),
        unit_lines=unit_lines, max_units=args.max_units, model=model, log=print,
    )
    print(json.dumps(state, sort_keys=True))
    return 0
