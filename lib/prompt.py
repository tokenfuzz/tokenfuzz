#!/usr/bin/env python3
"""Prompt assembly for audit agent sessions."""

from __future__ import annotations

import os
import hashlib
from dataclasses import dataclass
from pathlib import Path

import callgraph
import structured_state
import target_config
import workqueue
import build_config
from prompt_render import render_template

SCRIPT_ROOT = Path(__file__).resolve().parent.parent

_STRATEGIES = {
    "S1": ("S1-prior-fix-review.md", "Prior-fix regression: inspect the named fixes, derive the repaired invariant, and test neighboring paths for unfixed variants."),
    "S2": ("S2-assert-negation.md", "Invariant negation: identify checks and preconditions, then reach a violated assumption through the public boundary."),
    "S3": ("S3-spec-vs-impl.md", "Rule-vs-implementation: trace a security, published-spec, or fast/slow-path rule to the exact code that must enforce it. For a boundary-ranked card, start with access control, identity/origin, credential/assertion, outbound-request, query/template, path, injection, deserialization, or external-entity decisions."),
    "S4": ("S4-directed-fuzzing.md", "Boundary-directed fuzzing: run `bin/fuzz candidates` to find published APIs that untrusted input reaches and no harness drives, improve or write one faithful harness, then spend one bounded campaign on it. The only strategy that runs a fuzzer."),
    "S5": ("S5-reentrancy.md", "Lifetime/state: target-driven re-entrancy, rollback, races, and harmful but valid call sequences; do not free active callback state in the testcase."),
    "S6": ("S6-cross-project.md", "Cross-project variant mining: resolve exact peer fixes, distill their repaired invariants, then search the closest target analogue and bounded siblings before opening a hypothesis."),
    "S7": ("S7-adversarial-input.md", "Adversarial input engineering: mutate real seeds around lengths, nesting, and checksums, by hand. Fuzz harnesses and campaigns belong to S4."),
    "S8": ("S8-property-based.md", "Property oracle: test security-relevant inverse, injectivity, idempotence, canonicalization, and numeric invariants."),
    "REF": ("REF-pattern-search.md", "Pattern library: use broad target-agnostic searches to support the assigned strategy, then form concrete hypotheses."),
}


def session_rules_digest(reference_dir: Path) -> str:
    digest = reference_dir / "session-rules.digest.md"
    try:
        return digest.read_text(encoding="utf-8")
    except OSError:
        return f"(session-rules digest missing - read {reference_dir / 'session-rules.md'} once if needed)"


def strategy_brief(strategy: str, reference_dir: Path) -> str:
    strategy = strategy.upper()
    if strategy not in _STRATEGIES:
        return ""
    filename, summary = _STRATEGIES[strategy]
    return (
        f"Strategy brief ({strategy}): {summary}\n"
        f"Full playbook: `{reference_dir / 'strategies' / filename}`. Open it before committing to hypotheses."
    )


# Rollover target for one analysis session. Native-cap backends count agent
# turns; structured streaming backends use completed tool calls as the nearest
# safe proxy. Owned here so the runner and the contract the agent reads use the
# same number. lib/audit_runner.py resolves $TURN_SOFT_CAP against it.
DEFAULT_TURN_SOFT_CAP = 128


def agent_role(
    agent: int, num_agents: int, agent_roles: "tuple[str, ...]" = (),
) -> str:
    """Which role an agent runs under: the operator's list, or the default.

    Module-level so a caller that must reason about roles — which agent runs
    execution-heavy work — can ask without building a whole PromptContext, and
    cannot drift from the answer the prompt itself gives that agent.
    """
    if 1 <= agent <= len(agent_roles):
        return agent_roles[agent - 1]
    return "analysis" if num_agents > 1 and agent == num_agents else "reproduce"


@dataclass
class PromptContext:
    results_dir: Path
    target_root: Path
    target_slug: str
    reference_dir: Path
    num_agents: int
    is_browser: bool = False
    browser_agents: int = 0
    agent_roles: tuple[str, ...] = ()
    repo_type: str = ""
    guide_text: str = ""
    guide_path: str = "AGENTS.md"
    fixed_strategy: str = ""
    tool_call_soft_target: int = 80
    tool_call_deep_soft_target: int = 150
    turn_soft_cap: int = DEFAULT_TURN_SOFT_CAP
    config: target_config.Config | None = None

    def soft_target(self, deep: bool) -> int:
        """Self-pacing hint, never above the cap that actually ends the session."""
        target = self.tool_call_deep_soft_target if deep else self.tool_call_soft_target
        return min(target, self.turn_soft_cap) if self.turn_soft_cap > 0 else target

    def scratch_dir(self, agent: int) -> Path:
        return self.results_dir / f"scratch-{agent}"

    def mode(self, agent: int) -> str:
        if not self.is_browser:
            return "generic"
        return "browser" if agent <= self.browser_agents else "shell"

    def role(self, agent: int) -> str:
        return agent_role(agent, self.num_agents, self.agent_roles)

    def strategy(self, agent: int) -> str:
        path = self.results_dir / "state" / f"strategy-{agent}"
        try:
            value = path.read_text(encoding="utf-8").strip().upper()
        except OSError:
            value = ""
        return value if value in _STRATEGIES else self.fixed_strategy.upper() or "S1"


def safety_framing(context: PromptContext) -> str:
    if not str(context.results_dir):
        raise ValueError("RESULTS_DIR is required for prompt paths")
    return render_template("safety_framing.md.j2", {"results_dir": str(context.results_dir)})


def guide_section(context: PromptContext, cold: bool) -> str:
    if not context.guide_text:
        return ""
    if cold:
        return f"\n## AGENT GUIDE\n\n{context.guide_text}\n"
    return (
        f"\n## AGENT GUIDE\n\nFollow `{context.guide_path}`. Do not re-read it unless "
        "the structured resume or this prompt conflicts with the remembered workflow.\n"
    )


def find_first_directive(context: PromptContext) -> str:
    return render_template(
        "find_first_directive.md.j2",
        {
            "results_dir": str(context.results_dir),
            # Rendered into this directive rather than the session suffix:
            # cold-start, compact-fresh and deep-investigation all embed it,
            # so the narrative contract lands exactly once per prompt —
            # including the compact variant, which has no common suffix.
            "report_prose": render_template("report_prose.md.j2", {}),
        },
    )


def turn_budget_section(context: PromptContext) -> str:
    template = (
        "turn_budget.md.j2"
        if context.turn_soft_cap > 0
        else "turn_budget_disabled.md.j2"
    )
    return render_template(
        template, {"turn_soft_cap": str(context.turn_soft_cap)},
    )


def _render_common_suffix(context: PromptContext) -> str:
    return render_template(
        "common_suffix.md.j2",
        {
            "blocklist_text": "<none>",
            "results_dir": str(context.results_dir),
            "fuzz_leads_path": str(context.results_dir / "fuzz-leads.md"),
            "reference_dir": str(context.reference_dir),
            "tool_call_soft_target": str(context.soft_target(False)),
            "tool_call_deep_soft_target": str(context.soft_target(True)),
            "turn_budget_section": turn_budget_section(context),
            "session_rules_digest": session_rules_digest(context.reference_dir),
        },
    )


def common_suffix(context: PromptContext) -> str:
    cache = context.results_dir / ".static-prompt-rules.md"
    if cache.is_file() and cache.stat().st_size:
        return cache.read_text(encoding="utf-8")
    return _render_common_suffix(context)


def compact_suffix(context: PromptContext, agent: int) -> str:
    """Small self-contained contract for a fresh session with no active work.

    The full common suffix is about 22 KB once its session-rules digest is
    embedded. Replaying that on every turn would erase much of the saving from
    choosing the compact launch variant, so this keeps only the exact commands
    and safety rules that prevent predictable discovery/help round-trips.
    """
    return render_template(
        "compact_suffix.md.j2",
        {
            "scratch_dir": str(context.scratch_dir(agent)),
            "tool_call_soft_target": str(context.soft_target(False)),
            "tool_call_deep_soft_target": str(context.soft_target(True)),
            "turn_budget_section": turn_budget_section(context),
        },
    )


def write_static_prompt_file(context: PromptContext) -> Path:
    destination = context.results_dir / ".static-prompt-rules.md"
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    # Refresh once at backend initialization. Reusing a results tree with a
    # different TURN_SOFT_CAP must not preserve the previous run's budget or
    # cap-bounded pacing targets in this otherwise-static cache.
    text = _render_common_suffix(context)
    if text.strip():
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, destination)
    return destination


def _state_strategy_arg(context: PromptContext, agent: int) -> str:
    strategy = context.strategy(agent)
    # The prompt templates append this fragment directly after --role. Keep
    # the separator here so an empty optional fragment and a populated one are
    # both syntactically valid.
    return f" --strategy {strategy}" if strategy else ""


# Enough to show the shape of what was already disproved without crowding the
# card. The complete evidence remains in the rejected artifact.
_RULED_OUT_ROUTES_SHOWN = 3


def _ruled_out_routes(context: PromptContext, file: str) -> list[str]:
    """Trigger routes a source-review gate already disproved on this file.

    Without this the gate's reasoning dies with the artifact, and sessions
    re-derive it: over four measured targets, 55% of trigger rejections landed
    on a file that had already produced one in the same run, each after a full
    harness / confirm / bundle / enrich cycle. This is context, never a filter
    — the file keeps its card and a different route stays open, so a real
    defect reachable another way is not lost.
    """
    rel = workqueue.normalized_relpath(file)
    if not rel:
        return []
    rows = workqueue.read_jsonl(
        context.results_dir / "state" / "unreachable-routes.jsonl"
    )
    seen: set[str] = set()
    shown: list[str] = []
    # Newest first. A session repeats the route it just watched fail, so the
    # oldest three entries are the least useful three to keep showing — and
    # once a file had three, nothing later could ever appear.
    for row in reversed(rows):
        artifact = str(row.get("artifact", ""))
        lane = str(row.get("lane", ""))
        # The rejected artifact is the record of its own rejection. When the
        # gate requeues one because its verdict went stale, the directory
        # leaves that lane and this note stops with it — no tombstone, no
        # second copy of the gate's validity rules to drift out of step.
        if not artifact or not lane:
            continue
        if not (context.results_dir / lane / artifact).is_dir():
            continue
        site = next(
            (
                s for s in (row.get("sites") or [])
                if isinstance(s, dict)
                and workqueue.normalized_relpath(str(s.get("file", ""))) == rel
            ),
            None,
        )
        if site is None:
            continue
        summary = str(row.get("summary", "")).strip()
        if not summary or summary in seen:
            continue
        seen.add(summary)
        symbol = str(site.get("symbol", "")).strip()
        where = f"`{symbol}` — " if symbol else ""
        shown.append(f"  - {where}{summary}")
        if len(shown) >= _RULED_OUT_ROUTES_SHOWN:
            break
    if not shown:
        return []
    return [
        "- **Trigger routes already disproved on this file** (independent "
        "source review, most recent first):",
        *shown,
        "  Check the stated invariant before rebuilding a reproducer for one "
        "of these. They rule out a *route*, not the file: reach the same code "
        "through a different attacker-controlled path and it counts, and a "
        "disproof you can show to be wrong is worth arguing.",
    ]


def work_card_directive(context: PromptContext, agent: int, *, force: bool = False) -> str:
    cards = context.results_dir / "work-cards.jsonl"
    if not cards.is_file() or not cards.stat().st_size:
        return ""
    counts = structured_state.agent_counts(str(agent), context.results_dir)
    if not force and counts and counts["active"]:
        return ""
    try:
        queue_context = workqueue.Context(
            SCRIPT_ROOT, context.target_root, context.target_slug,
            context.results_dir,
            context.repo_type or target_config.detect_repo_type(context.target_root),
        )
        card = workqueue.claim_next_card(
            queue_context, str(agent), context.mode(agent), context.role(agent),
            claim=True, strategy=context.strategy(agent),
        )
    except (OSError, ValueError):
        return ""
    if card is None:
        return ""
    assigned_strategy = (
        str(card.get("strategy", "")).strip().upper()
        or context.strategy(agent).strip().upper()
    )
    primary_strategy = (
        str(card.get("source_strategy", "")).strip().upper() or assigned_strategy
    )
    lines = [
        "\n## ASSIGNED WORK CARD", "",
        f"- **ID:** {card.get('id', '')}",
        f"- **Kind:** {card.get('kind', '')}",
        f"- **Subsystem:** `{card.get('subsystem', '')}`",
        f"- **File:** `{card.get('file', '')}`",
        f"- **Strategy:** {assigned_strategy}",
        f"- **Score:** {card.get('score', '')}",
        f"- **Why ranked:** {card.get('reason', 'structural/code-feature score')}",
    ]
    if assigned_strategy != primary_strategy:
        lines.append(f"- **Card primary strategy:** {primary_strategy}")
    if card.get("seed"):
        lines.append(f"- **Seed:** `{card['seed']}`")
    if card.get("buildability") == "not-built":
        lines.append(
            "- **Execution availability:** no matching object in the current "
            "sanitizer builds; source review remains valid, but do not invent "
            "CLEAN probe evidence if the public surface cannot execute"
        )
    fixes = card.get("fix_hashes") or []
    lines.append(f"- **Fix commits:** {', '.join(fixes) if fixes else 'none listed'}")
    lines += workqueue.peer_fix_markdown(card)
    lines += _ruled_out_routes(context, card.get("file", ""))
    lines += callgraph.block_for(context.results_dir, card.get("file", ""))
    lines.extend([
        "",
        "Use this card first unless structured state already has a higher-priority active row.",
    ])
    lines.append(f"Next action: {workqueue.card_next_action(card, assigned_strategy)}")
    lines.append(
        f"Include `--card-id {card.get('id', '')}` in structured state and `CARD-ID: {card.get('id', '')}` in testcase headers."
    )
    return "\n".join(lines)


def _agent_state_instructions(context: PromptContext, agent: int) -> str:
    return (
        f"Use `bin/state resume --agent {agent}` as structured source of truth. "
        f"Write testcases under `{context.scratch_dir(agent)}` and update state after each closure."
    )


def _targets(context: PromptContext, mode: str) -> str:
    if context.is_browser:
        return (
            f"Audit `{context.target_root}` in {mode} mode. Use `bin/probe <testcase>`; "
            "it selects the configured browser or JS runner."
        )
    return (
        f"Audit source under `{context.target_root}` through its configured public file, bytes, or API boundary. "
        "Use `bin/find-seed` before parser/decoder inputs and `bin/probe` for every testcase."
    )


def _compact(values: list[str], limit: int = 8) -> str:
    cleaned = [value.replace("\n", " ")[:120] for value in values]
    shown = cleaned[:limit]
    if len(cleaned) > limit:
        shown.append(f"... (+{len(cleaned) - limit} more)")
    return ", ".join(shown)


def sanitizer_build_directive(context: PromptContext) -> str:
    """Describe parsed target config and sanitizer availability to generic agents.

    The orchestrator already paid to parse target.toml. Repeating the relevant
    facts here prevents agents from spending a turn rediscovering them or
    rebuilding an existing instrumented tree.
    """
    if context.is_browser or context.config is None:
        return ""
    config = context.config
    enabled = config.sanitizers_enabled
    if config.sanitizers_explicitly_disabled:
        build_section = (
            "## SANITIZER BUILDS - DISABLED\n\n"
            "`[sanitizer] enabled = []`; use the configured runner and file "
            "runtime-diagnostic issues under `findings/`."
        )
    else:
        enabled = enabled or ["asan"]
        build_names = ["asan", *(name for name in enabled if name != "asan")]
        available: list[str] = []
        missing: list[str] = []
        for name in build_names:
            configured = config.sanitizer_bin(name)
            build_dir = context.target_root / f"build-{name}{os.environ.get('AUDIT_BUILD_SUFFIX', '')}"
            if configured and Path(configured).exists():
                available.append(f"- {name}: `{configured}` (configured binary)")
            elif build_dir.is_dir():
                available.append(f"- {name}: `{build_dir}` (build tree)")
            elif name in {"asan", "ubsan", "msan", "tsan"}:
                config_key = "asan_bin" if name == "asan" else f"[sanitizer].{name}_bin"
                missing.append(
                    f"- {name}: build with `bin/setup-target {context.target_slug} --build` "
                    f"or set `{config_key}`"
                )
        state = "PARTIAL" if available and missing else "ALREADY AVAILABLE" if available else "NOT FOUND"
        parts = [
            f"## SANITIZER BUILDS - {state}", "",
            f"Enabled sanitizers: `{','.join(enabled)}`",
        ]
        if available:
            parts += ["", "Detected:", *available]
        if missing:
            parts += ["", "Missing:", *missing]
        if available:
            parts += ["", "Do not rebuild detected artifacts. Use `bin/probe`; mark a genuinely missing required build ENV-BLOCKED."]
        build_section = "\n".join(parts)

    facts = [
        "## TARGET CONFIG (already parsed from target.toml - do not re-read it)", "",
        f"- `[threat_model] attacker_controls`: `{config.attacker_controls_csv()}`",
        f"- `[sanitizer] enabled`: `{config.sanitizers_enabled_csv()}`",
    ]
    for label, values in (
        ("includes", config.includes), ("defines", config.defines),
        ("link_libs", config.link_libs), ("[runner].args", config.runner_args),
        ("[runner].env", config.runner_env),
    ):
        if values:
            facts.append(f"- `{label}`: `{_compact(values)}`")
    if config.asan_lib:
        facts.append(f"- `asan_lib`: `{config.asan_lib}`")
    if config.runner_bin:
        facts.append(f"- `[runner].bin`: `{config.runner_bin}`")
    facts += ["", "Open target.toml only when changing this configuration."]
    ready: list[str] = []
    configured_builds = (
        []
        if os.environ.get("_TOKENFUZZ_BENCHMARK_PRIMARY_BUILD") == "1"
        else config.build_configs
    )
    for item in configured_builds:
        recipe = build_config.recipe_path(context.target_root, item)
        tree = build_config.build_dir(
            context.target_root, item,
            base_suffix=os.environ.get("AUDIT_BUILD_SUFFIX", ""),
        )
        if (
            recipe.is_file()
            and build_config.is_ready(tree, recipe)
        ):
            feature_text = f"; surfaces: {_compact(list(item.features))}" if item.features else ""
            ready.append(f"- `{item.name}` ({item.config_id}){feature_text}")
    if ready:
        facts += [
            "", "Built alternate ASan configurations:", *ready,
            "Use the assigned configuration below; `PROBE_BUILD_CONFIG=<name>` is available for a deliberate comparison.",
        ]
    return build_section + "\n\n" + "\n".join(facts)


def build_config_assignment_directive(context: PromptContext, agent: int) -> str:
    if context.is_browser or context.config is None:
        return ""
    path = context.results_dir / "state" / f"build-config-{agent}"
    try:
        selector = path.read_text(encoding="utf-8").strip()
    except OSError:
        selector = ""
    if not selector:
        return (
            "## BUILD CONFIGURATION - PRIMARY\n\n"
            "This agent is the regular-configuration control. `bin/probe` uses the canonical build; "
            "do not set `PROBE_BUILD_CONFIG` unless making one explicit differential comparison."
        )
    item = build_config.find(context.config.build_configs if context.config else [], selector)
    if item is None:
        return ""
    features = f" Expected added surfaces: `{_compact(list(item.features))}`." if item.features else ""
    return (
        f"## BUILD CONFIGURATION - {item.name.upper()}\n\n"
        f"This agent is assigned alternate ASan configuration `{item.name}` ({item.config_id}). "
        "`bin/probe` selects it automatically from session state; keep using ordinary `bin/probe` commands."
        f"{features} Compare a surprising result against `PROBE_BUILD_CONFIG=primary bin/probe ...`."
    )


def agent_build_directive(context: PromptContext, agent: int) -> str:
    parts = [sanitizer_build_directive(context), build_config_assignment_directive(context, agent)]
    return "\n\n".join(part for part in parts if part)


def harness_build_failures_directive(context: PromptContext) -> str:
    if context.is_browser:
        return ""
    logs = [
        path for path in context.results_dir.glob("scratch-*/.harness-cache/*.build.log")
        if path.is_file() and path.stat().st_size
    ]
    if len(logs) < 3:
        return ""
    recent = sorted(logs, key=lambda path: path.stat().st_mtime_ns, reverse=True)[:3]
    paths = "\n".join(f"- `{path}`" for path in recent)
    return (
        "## PERSISTENT HARNESS BUILD FAILURES - FIX THE LOOP\n\n"
        f"{len(logs)} cached build failures exist. Read the latest bounded log tail before retrying:\n"
        f"{paths}\n\n"
        "Fix the scratch harness when its source is wrong. The session target "
        "configuration is pinned; never edit target.toml during the audit. "
        "For wrong parsed build flags or a genuine toolchain conflict, mark "
        "the hypothesis ENV-BLOCKED with the exact diagnostic for operator repair."
    )


def _continuation(context: PromptContext, agent: int) -> str:
    seed = context.results_dir / f".session_seed_{agent}.md"
    try:
        seed_text = seed.read_text(encoding="utf-8").strip()
    except OSError:
        seed_text = ""
    if not seed_text:
        return ""
    return (
        "## PRIOR SESSION SEED\n\nAvoid re-reading the same ranges or repeating exact searches.\n\n"
        f"```\n{seed_text}\n```"
    )


def _role_guidance(context: PromptContext, agent: int) -> str:
    if context.role(agent) == "analysis":
        return (
            "**ROLE: ANALYSIS** - trace control/data flow and name concrete hypotheses. "
            "Before NEEDS_TESTCASE, write a minimal probe and confirm the target path executes."
        )
    return (
        f"**ROLE: REPRODUCE** - start from `bin/find-seed`, write under `{context.scratch_dir(agent)}`, "
        "and run `bin/probe` in the same turn."
    )


def first_probe_checkpoint(context: PromptContext, agent: int) -> str:
    if context.role(agent) != "reproduce":
        return ""
    if context.strategy(agent) == "S6":
        return (
            "**S6 SOURCE GATE:** Resolve the exact peer fix and verify the target analogue "
            "before creating a hypothesis. If the target is already safe or has no analogue, "
            "block the card with source proof; do not manufacture a testcase. Once a real "
            "missing guard is named, write and run its trigger-aimed `bin/probe` in the same turn."
        )
    return (
        "**FIRST-PROBE CHECKPOINT:** Create or adopt one card-linked hypothesis, then "
        "run a trigger-aimed `bin/probe` before turn 20. Put its required TARGET / "
        "HYPOTHESIS-ID / CATEGORY headers in the testcase so the run reaches structured "
        "state; for raw byte inputs, preserve the bytes and pass `--hypothesis-id H-...` "
        "instead. NO_EXEC does not satisfy this checkpoint. Use the best existing seed plus "
        "the smallest useful mutation instead of postponing execution for exhaustive review."
    )


def enforcement_results_directive(context: PromptContext, agent: int) -> str:
    path = context.results_dir / f".enforcement_results_{agent}"
    try:
        body = path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    if not body:
        return ""
    if any(line.startswith("- CRASH ") for line in body.splitlines()):
        heading = "## ORPHAN TESTCASE RESULTS — CONFIRM CRASHES FIRST"
        action = "The harness found a diagnostic while probing an unexecuted testcase. Inspect it and run `bin/probe --confirm` before starting new work."
    else:
        heading = "## ORPHAN TESTCASE RESULTS"
        action = "The harness probed testcases left unexecuted in the prior session. Fix every NO_EXEC/TIMEOUT before writing another testcase."
    return f"{heading}\n\n{action}\n\n{body}"


def handoff_rows(context: PromptContext, agent: int) -> list[dict]:
    """Assign analysis NEEDS_TESTCASE rows stably across reproduce workers."""
    if context.role(agent) != "reproduce":
        return []
    reproduce_agents = [
        number for number in range(1, context.num_agents + 1)
        if context.role(number) == "reproduce"
    ]
    analysis_agents = {
        str(number) for number in range(1, context.num_agents + 1)
        if context.role(number) == "analysis"
    }
    if not reproduce_agents or not analysis_agents:
        return []
    assigned: list[dict] = []
    for row in structured_state.rows(context.results_dir):
        if row.get("status") != "NEEDS_TESTCASE" or str(row.get("agent", "")) not in analysis_agents:
            continue
        key = str(row.get("id") or row.get("hypothesis") or "")
        slot = int(hashlib.sha1(key.encode()).hexdigest()[:8], 16) % len(reproduce_agents)
        if reproduce_agents[slot] == agent:
            assigned.append(row)
    assigned.sort(key=lambda row: str(row.get("updated_at") or row.get("created_at") or ""))
    return assigned[:5]


def handoff_directive(context: PromptContext, agent: int) -> str:
    rows = handoff_rows(context, agent)
    if not rows:
        return ""
    lines = [
        "## HANDOFF FROM ANALYSIS",
        "",
        "Continue one of these source-validated hypotheses before claiming new work. Use its existing H ID in the testcase; do not create a duplicate hypothesis.",
        "",
        "| ID | File | Hypothesis | Input shape | Guard gap | Diagnostic | Strategy |",
        "|---|---|---|---|---|---|---|",
    ]
    for row in rows:
        values = [
            row.get("id", ""), row.get("file", ""), row.get("hypothesis", ""),
            row.get("input_shape", ""), row.get("guard_gap", ""),
            row.get("diagnostic", ""), row.get("strategy", ""),
        ]
        lines.append("| " + " | ".join(str(value).replace("|", "\\|").replace("\n", " ")[:180] for value in values) + " |")
    return "\n".join(lines)


def cold_start_prompt(context: PromptContext, agent: int) -> str:
    mode = context.mode(agent)
    strategy = context.strategy(agent)
    strategy_block = f"## ASSIGNED STRATEGY - {strategy}\n\n{strategy_brief(strategy, context.reference_dir)}"
    # The pin says which strategy, never how to work it — step 4 below owns
    # the procedure, so restating it here only paraphrases the same rule.
    fixed = (
        f"Every hypothesis on this run must be Strategy {context.fixed_strategy}."
        if context.fixed_strategy else ""
    )
    if strategy == "S6":
        workflow = (
            "Distill the peer fix's repaired invariant and verify a target analogue. "
            "Only when the same input reaches the same operation without the peer's "
            "guard, record one concrete hypothesis with `bin/state add-hyp`, take the "
            "best `bin/find-seed` candidate, and run `bin/probe`; otherwise block the "
            "stale or already-safe card with source proof."
        )
    else:
        workflow = (
            "Record one concrete hypothesis with `bin/state add-hyp`, take the best "
            "`bin/find-seed` candidate, and run `bin/probe`. Then fill the "
            "same-subsystem queue to 3-5 hypotheses; add concise "
            "data-flow/guard/variant context with `bin/state add-note`."
        )
    return render_template(
        "cold_start.md.j2",
        {
            "agent_num": str(agent), "role": context.role(agent), "mode": mode,
            "safety_framing": safety_framing(context),
            "guide_section": guide_section(context, True),
            "state_strategy_arg": _state_strategy_arg(context, agent),
            "suggested_sub_line": "", "audit_fixed_strategy_hint": fixed,
            "cold_start_workflow": workflow,
            "reference_dir": str(context.reference_dir), "strategy_a_block": strategy_block,
            "role_guidance": _role_guidance(context, agent),
            "first_probe_checkpoint": first_probe_checkpoint(context, agent),
            "work_card_directive": work_card_directive(context, agent),
            "targets": _targets(context, mode),
            "asan_build_directive": agent_build_directive(context, agent),
            "harness_build_failures_directive": harness_build_failures_directive(context),
            "find_first_directive": find_first_directive(context),
            "mode_lock_line": f"**NO OVERLAP.** Mode lock: {mode}." if context.is_browser else "**NO OVERLAP.** Pick a different subsystem from every other agent.",
            "agent_state_instructions": _agent_state_instructions(context, agent),
            "common_suffix": common_suffix(context),
        },
    )


def compact_fresh_prompt(context: PromptContext, agent: int) -> str:
    return render_template(
        "compact_fresh.md.j2",
        {
            "agent_num": str(agent), "role": context.role(agent), "mode": context.mode(agent),
            "safety_framing": safety_framing(context),
            "find_first_directive": find_first_directive(context),
            "guide_section": guide_section(context, False),
            "state_strategy_arg": _state_strategy_arg(context, agent),
            "scratch_dir": str(context.scratch_dir(agent)),
            "audit_fixed_strategy_compact_clause": "",
            "strategy_assignment_line": strategy_brief(context.strategy(agent), context.reference_dir),
            "work_card_directive": work_card_directive(context, agent),
            "asan_build_directive": agent_build_directive(context, agent),
            "harness_build_failures_directive": harness_build_failures_directive(context),
            "agent_state_instructions": _agent_state_instructions(context, agent),
            "first_probe_checkpoint": first_probe_checkpoint(context, agent),
            "compact_suffix": compact_suffix(context, agent),
        },
    )


def deep_investigation_prompt(context: PromptContext, agent: int) -> str:
    counts = structured_state.agent_counts(str(agent), context.results_dir)
    if not counts:
        if workqueue.agent_has_card_activity(context.results_dir, str(agent)):
            return compact_fresh_prompt(context, agent)
        return cold_start_prompt(context, agent)
    if not counts["active"]:
        return compact_fresh_prompt(context, agent)
    mode = context.mode(agent)
    strategy = context.strategy(agent)
    seed = _continuation(context, agent)
    target_block = _targets(context, mode)
    if not context.is_browser:
        target_block += "\n\n" + agent_build_directive(context, agent)
        failures = harness_build_failures_directive(context)
        if failures:
            target_block += "\n\n" + failures
    card_min_runs, card_min_hypotheses = workqueue.card_discard_requirements()
    return render_template(
        "deep_investigation.md.j2",
        {
            "agent_num": str(agent), "agent_id": chr(64 + agent) if 1 <= agent <= 26 else str(agent),
            "role": context.role(agent), "mode": mode,
            "safety_framing": safety_framing(context),
            "guide_section": guide_section(context, False),
            "state_strategy_arg": _state_strategy_arg(context, agent),
            "asan_loop_cmd": f"bin/probe {context.scratch_dir(agent)}/testcase",
            "mode_lock_or_targets_block": target_block,
            "directive_block": "", "enforcement_block": enforcement_results_directive(context, agent),
            "session_continuation_section": seed,
            "audit_fixed_strategy_clause": "", "wrong_mode_subsystem_line": "",
            "role_block": _role_guidance(context, agent), "handoff_directive": handoff_directive(context, agent),
            "first_probe_checkpoint": first_probe_checkpoint(context, agent),
            "work_card_directive": work_card_directive(context, agent),
            "strategy_assignment_line": strategy_brief(strategy, context.reference_dir),
            "strategy_roi_directive": "", "find_first_directive": find_first_directive(context),
            "card_discard_min_runs": str(card_min_runs),
            "card_discard_min_hypotheses": str(card_min_hypotheses),
            "agent_state_instructions": _agent_state_instructions(context, agent),
            "common_suffix": common_suffix(context),
        },
    )
