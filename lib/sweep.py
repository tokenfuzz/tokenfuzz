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
#: A parsed function longer than this many windows is split; one prompt
#: holding thousands of lines is exactly the read the sweep exists to avoid.
MAX_UNIT_WINDOWS = 4
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

    @property
    def key(self) -> str:
        return f"{self.file}:{self.start}-{self.end}"


def state_path(results_dir: Path) -> Path:
    return workqueue.state_dir(Path(results_dir)) / STATE_NAME


def read_state(results_dir: Path) -> dict:
    try:
        data = json.loads(state_path(results_dir).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


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


def plan_units(ctx: workqueue.Context, unit_lines: int = 120) -> list[Unit]:
    """Unreceipted units, gap first: files the window never offered come
    before files it did, and the least-read file before the better-read one.
    A parsed function is one unit unless it is long enough to split."""
    manifest = coverage_ledger.read_manifest(ctx.results_dir)
    receipted = coverage_ledger.examined_ranges_by_file(ctx.results_dir)
    fraction = coverage_ledger.examined_fraction_by_file(ctx.results_dir)
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
        if not rel or total <= 0 or fraction.get(rel, 0.0) >= 0.999:
            continue
        done = receipted.get(rel, [])
        reason = "never offered" if not row.get("offered") else f"{fraction.get(rel, 0.0) * 100:.0f}% receipted"
        definitions = coverage_ledger.function_ranges(ctx.results_dir, rel, total)
        candidates: list[tuple[int, int, list[str]]] = []
        if definitions:
            first_start = definitions[0][1]
            if first_start > 1:
                candidates.extend((s, e, []) for s, e in _windows(1, first_start - 1, size))
            for name, start, end in definitions:
                if end - start + 1 > size * MAX_UNIT_WINDOWS:
                    candidates.extend((s, e, [name]) for s, e in _windows(start, end, size))
                else:
                    candidates.append((start, end, [name]))
        else:
            candidates.extend((s, e, []) for s, e in _windows(1, total, size))
        for start, end, names in candidates:
            if any(rs <= start and end <= re for rs, re in done):
                continue
            units.append(Unit(rel, start, end, names, reason))
    return units


def _numbered_source(ctx: workqueue.Context, unit: Unit) -> str:
    path = ctx.target_root / unit.file
    with path.open("rb") as stream:
        lines = stream.read().decode("utf-8", "replace").splitlines()
    width = len(str(unit.end))
    return "\n".join(
        f"{number:>{width}}  {lines[number - 1][:200] if number - 1 < len(lines) else ''}"
        for number in range(unit.start, unit.end + 1)
    )


def build_prompt(ctx: workqueue.Context, unit: Unit, attacker_controls: str) -> str:
    row = coverage_ledger.manifest_row(ctx.results_dir, unit.file) or {}
    block = callgraph.block_for(ctx.results_dir, unit.file, ctx.target_root)
    return prompt_render.render_template("sweep_unit.md.j2", {
        "attacker_controls": attacker_controls or "bytes",
        "file": unit.file,
        "start": str(unit.start),
        "end": str(unit.end),
        "total_lines": str(row.get("lines") or unit.end),
        "functions": ", ".join(unit.functions) or "(none parsed; treat the window as one unit)",
        "neighbourhood": "\n".join(block).strip(),
        "source": _numbered_source(ctx, unit),
    })


class ReplyError(ValueError):
    """A reply the sweep cannot turn into a verified receipt."""


class _Stopped(Exception):
    """SIGTERM from the audit's shutdown; the loop ends and state is written."""


def _covered(unit: Unit, receipted: dict[str, list[tuple[int, int]]]) -> bool:
    return any(s <= unit.start and unit.end <= e for s, e in receipted.get(unit.file, []))


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
    verdicts = [v for v in (reply.get("verdicts") or []) if isinstance(v, dict)]
    leads: list[dict] = []
    for raw in reply.get("leads") or []:
        if not isinstance(raw, dict):
            continue
        function = str(raw.get("function") or "").strip()
        try:
            line = int(raw.get("line") or 0)
        except (TypeError, ValueError):
            line = 0
        diagnostic = str(raw.get("diagnostic") or "").strip().lower()
        strategy = str(raw.get("strategy") or "S3").strip().upper()
        if unit.functions and function not in unit.functions:
            continue
        if not (unit.start <= line <= unit.end):
            continue
        if diagnostic not in workqueue.HYPOTHESIS_DIAGNOSTIC_CATEGORIES:
            continue
        if strategy not in _LEAD_STRATEGIES:
            strategy = "S3"
        text = {key: str(raw.get(key) or "").strip() for key in ("hypothesis", "input_shape", "guard_gap")}
        if not all(text.values()):
            continue
        leads.append({
            "function": function or f"lines {unit.start}-{unit.end}", "line": line,
            "diagnostic": diagnostic, "strategy": strategy, **text,
        })
    return coverage_ledger.merge_ranges(ranges), verdicts, leads


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
    invocations so a resumed run does not restart the budget."""
    say = log or (lambda message: None)
    state = read_state(ctx.results_dir)
    spent = int(state.get("spent_tokens") or 0)
    counts = {key: int(state.get(key) or 0) for key in ("units", "receipts", "leads", "failures")}
    units = plan_units(ctx, unit_lines)
    stop = "exhausted" if not units else "interrupted"
    consecutive = 0
    done = 0

    def persist(reason: str) -> dict:
        # After every unit, not only at the end: the audit ends the sweep
        # with SIGTERM whenever the slots finish first, and spend that was
        # never written would be spent again on the next resume.
        current = {
            "spent_tokens": spent, "token_budget": token_budget, "stop": reason,
            "units_remaining": max(0, len(units) - done),
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
            if max_units and done >= max_units:
                stop = "unit-cap"
                break
            # A session may have receipted this unit since the plan was made.
            if _covered(unit, coverage_ledger.examined_ranges_by_file(ctx.results_dir)):
                done += 1
                continue
            try:
                text = build_prompt(ctx, unit, attacker_controls)
            except OSError as exc:
                # The file changed or vanished under the plan; skip it, do
                # not spend on it, and let the next plan see the tree.
                say(f"sweep: cannot read {unit.key}: {exc}")
                done += 1
                continue
            reply = llm_decide.llm_decide(
                DECISION, REQUIRED_KEYS, text,
                timeout=llm_decide.decision_timeout(DECISION), usage_index=usage_index,
            )
            spent += llm_usage.estimate_tokens(text)
            counts["units"] += 1
            done += 1
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
                        coverage_ledger.record_receipt(
                            ctx, AGENT, unit.file,
                            lines=",".join(f"{s}-{e}" for s, e in ranges),
                            source="sweep", note=summary[:240],
                        )
                        counts["receipts"] += 1
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
            stop = "exhausted"
    except _Stopped:
        stop = "interrupted"
    finally:
        signal.signal(signal.SIGTERM, previous_handler)
        if model:
            if previous_model is None:
                os.environ.pop("MODEL", None)
            else:
                os.environ["MODEL"] = previous_model
    return persist(stop)


def summary_lines(results_dir: Path) -> list[str]:
    """Coverage-report lines for the sweep's last recorded state."""
    state = read_state(results_dir)
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
                        help="estimated tokens the sweep may spend in total (default: [sweep] token_budget)")
    parser.add_argument("--max-units", type=int, default=0, help="stop after this many units (0 = no cap)")
    parser.add_argument("--unit-lines", type=int, default=None,
                        help="window size where no function boundaries are parsed (default: [sweep] unit_lines)")
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
