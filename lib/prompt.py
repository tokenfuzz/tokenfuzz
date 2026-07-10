#!/usr/bin/env python3
"""Prompt assembly for audit agent sessions."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import structured_state
import target_config
import workqueue
from prompt_render import render_template

SCRIPT_ROOT = Path(__file__).resolve().parent.parent

_STRATEGIES = {
    "S1": ("S1-prior-fix-review.md", "Prior-fix regression: inspect the named fixes, derive the repaired invariant, and test neighboring paths for unfixed variants."),
    "S2": ("S2-assert-negation.md", "Invariant negation: identify checks and preconditions, then reach a violated assumption through the public boundary."),
    "S3": ("S3-spec-vs-impl.md", "Spec-vs-implementation: compare documented rules with parser fast paths, normalization, and edge cases."),
    "S4": ("S4-differential.md", "Advanced differential: compare execution modes, tiers, builds, or feature flags using stable divergence as the oracle."),
    "S5": ("S5-reentrancy.md", "Lifetime/state: target re-entrancy, rollback, races, and harmful but valid call sequences."),
    "S6": ("S6-cross-project.md", "Cross-project variant mining: map peer security fixes onto analogous local surfaces and confirm local reachability."),
    "S7": ("S7-fuzz-improvement.md", "Adversarial input engineering: mutate real seeds around lengths, nesting, dictionaries, and checksums."),
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
    config: target_config.Config | None = None

    def scratch_dir(self, agent: int) -> Path:
        return self.results_dir / f"scratch-{agent}"

    def mode(self, agent: int) -> str:
        if not self.is_browser:
            return "shell"
        return "browser" if agent <= self.browser_agents else "shell"

    def role(self, agent: int) -> str:
        if 1 <= agent <= len(self.agent_roles):
            return self.agent_roles[agent - 1]
        return "analysis" if self.num_agents > 1 and agent == self.num_agents else "reproduce"

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
        "find_first_directive.md.j2", {"results_dir": str(context.results_dir)}
    )


def common_suffix(context: PromptContext) -> str:
    cache = context.results_dir / ".static-prompt-rules.md"
    if cache.is_file() and cache.stat().st_size:
        return cache.read_text(encoding="utf-8")
    return render_template(
        "common_suffix.md.j2",
        {
            "blocklist_text": "<none>",
            "results_dir": str(context.results_dir),
            "fuzz_leads_path": str(context.results_dir / "fuzz-leads.md"),
            "reference_dir": str(context.reference_dir),
            "tool_call_soft_target": str(context.tool_call_soft_target),
            "tool_call_deep_soft_target": str(context.tool_call_deep_soft_target),
            "session_rules_digest": session_rules_digest(context.reference_dir),
        },
    )


def write_static_prompt_file(context: PromptContext) -> Path:
    destination = context.results_dir / ".static-prompt-rules.md"
    temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
    text = common_suffix(context)
    if text.strip():
        temporary.write_text(text, encoding="utf-8")
        os.replace(temporary, destination)
    return destination


def _state_strategy_arg(context: PromptContext, agent: int) -> list[str]:
    strategy = context.strategy(agent)
    return ["--strategy", strategy] if strategy else []


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
    lines = [
        "\n## ASSIGNED WORK CARD", "",
        f"- **ID:** {card.get('id', '')}",
        f"- **Kind:** {card.get('kind', '')}",
        f"- **Subsystem:** `{card.get('subsystem', '')}`",
        f"- **File:** `{card.get('file', '')}`",
        f"- **Strategy:** {card.get('strategy', '')}",
        f"- **Score:** {card.get('score', '')}",
        f"- **Why ranked:** {card.get('reason', 'structural/code-feature score')}",
    ]
    if card.get("seed"):
        lines.append(f"- **Seed:** `{card['seed']}`")
    fixes = card.get("fix_hashes") or []
    lines.append(f"- **Fix commits:** {', '.join(fixes) if fixes else 'none listed'}")
    recon = card.get("recon") or {}
    if recon:
        lines += [
            "", "## RECON HYPOTHESIS DETAIL", "",
            f"- **Recon ID:** {recon.get('id', 'unknown')}",
            f"- **Line:** {recon.get('line', 'unknown')}",
            f"- **Class:** {recon.get('class', 'unspecified')}",
            f"- **Validator verdict:** {recon.get('validator_verdict', 'unspecified')}",
        ]
    if card.get("find_id"):
        lines += [
            "", "### PRE-FILED FIND (augment, do not re-file)", "",
            f"Augment `{context.results_dir / 'findings' / card['find_id'] / 'report.md'}` with reproducer evidence; do not create a duplicate FIND.",
        ]
    lines += [
        "",
        "Use this card first unless structured state already has a higher-priority active row.",
        f"Include `--card-id {card.get('id', '')}` in structured state and `CARD-ID: {card.get('id', '')}` in testcase headers.",
    ]
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
    return build_section + "\n\n" + "\n".join(facts)


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
    config_path = context.results_dir.parents[1] / "target.toml"
    return (
        "## PERSISTENT HARNESS BUILD FAILURES - FIX THE LOOP\n\n"
        f"{len(logs)} cached build failures exist. Read the latest bounded log tail before retrying:\n"
        f"{paths}\n\n"
        "Fix the scratch harness when its source is wrong. If the parsed build flags are wrong, update "
        f"`{config_path}` (`includes`, `defines`, or `link_libs`) and rerun `bin/probe`. "
        "For a genuine toolchain conflict, mark the hypothesis ENV-BLOCKED with the exact diagnostic."
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
        "and run `bin/probe` in the same turn. Try at least three variants before discarding."
    )


def cold_start_prompt(context: PromptContext, agent: int) -> str:
    mode = context.mode(agent)
    strategy = context.strategy(agent)
    strategy_block = ""
    if strategy != "S1":
        strategy_block = f"## ASSIGNED STRATEGY - {strategy}\n\n{strategy_brief(strategy, context.reference_dir)}"
    fixed = (
        f"Pinned strategy: create a Strategy {context.fixed_strategy} hypothesis and run one probe."
        if context.fixed_strategy else ""
    )
    return render_template(
        "cold_start.md.j2",
        {
            "agent_num": str(agent), "role": context.role(agent), "mode": mode,
            "safety_framing": safety_framing(context),
            "guide_section": guide_section(context, True),
            "state_strategy_arg": " ".join(_state_strategy_arg(context, agent)),
            "suggested_sub_line": "", "audit_fixed_strategy_hint": fixed,
            "reference_dir": str(context.reference_dir), "strategy_a_block": strategy_block,
            "role_guidance": _role_guidance(context, agent),
            "work_card_directive": work_card_directive(context, agent),
            "targets": _targets(context, mode),
            "asan_build_directive": sanitizer_build_directive(context),
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
            "state_strategy_arg": " ".join(_state_strategy_arg(context, agent)),
            "scratch_dir": str(context.scratch_dir(agent)),
            "audit_fixed_strategy_compact_clause": "",
            "strategy_assignment_line": strategy_brief(context.strategy(agent), context.reference_dir),
            "work_card_directive": work_card_directive(context, agent),
            "asan_build_directive": sanitizer_build_directive(context),
            "harness_build_failures_directive": harness_build_failures_directive(context),
            "agent_state_instructions": _agent_state_instructions(context, agent),
            "session_continuation_section": _continuation(context, agent),
        },
    )


def deep_investigation_prompt(context: PromptContext, agent: int) -> str:
    counts = structured_state.agent_counts(str(agent), context.results_dir)
    if not counts:
        return cold_start_prompt(context, agent)
    if not counts["active"]:
        return compact_fresh_prompt(context, agent)
    mode = context.mode(agent)
    strategy = context.strategy(agent)
    seed = _continuation(context, agent)
    target_block = _targets(context, mode)
    if not context.is_browser:
        target_block += "\n\n" + sanitizer_build_directive(context)
        failures = harness_build_failures_directive(context)
        if failures:
            target_block += "\n\n" + failures
    return render_template(
        "deep_investigation.md.j2",
        {
            "agent_num": str(agent), "agent_id": chr(64 + agent) if 1 <= agent <= 26 else str(agent),
            "role": context.role(agent), "mode": mode,
            "safety_framing": safety_framing(context),
            "guide_section": guide_section(context, False),
            "state_strategy_arg": " ".join(_state_strategy_arg(context, agent)),
            "asan_loop_cmd": f"bin/probe {context.scratch_dir(agent)}/testcase",
            "mode_lock_or_targets_block": target_block,
            "directive_block": "", "enforcement_block": "",
            "session_seed_section": seed, "session_continuation_section": seed,
            "audit_fixed_strategy_clause": "", "wrong_mode_subsystem_line": "",
            "role_block": _role_guidance(context, agent), "handoff_directive": "",
            "work_card_directive": work_card_directive(context, agent),
            "strategy_assignment_line": strategy_brief(strategy, context.reference_dir),
            "strategy_roi_directive": "", "find_first_directive": find_first_directive(context),
            "agent_state_instructions": _agent_state_instructions(context, agent),
            "common_suffix": common_suffix(context),
        },
    )
