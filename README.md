<p align="center">
  <img src="docs/assets/logo-lockup.svg" alt="TokenFuzz" width="400">
</p>

TokenFuzz is an open platform for LLM-based vulnerability research: a
coordinated fleet of agents that audits a codebase, finds security issues, and
hands each one back with the evidence and reasoning a developer needs to
triage it. Point it at any source tree you are authorized to test —
C/C++, Rust, Go, Python, Java, and more, including browsers — and it runs
as a pipeline:

- **Finds bugs from scratch.** A cold-start survey sweeps the source in
  parallel — no crashing input or bug list handed in — and turns what it
  sees into a prioritized queue of leads. On a large codebase it scopes
  to recently-changed code so the pass stays bounded.
- **Investigates with real method.** A fleet of agents works that queue
  through eight named strategies — mining recent fixes, breaking
  invariants, spec-vs-code, differential testing, lifetime and state,
  peer-fix mining, adversarial input, and property oracles — across
  Claude, Codex, Gemini, or a local open-source model behind one contract.
- **Tells real risk from noise.** Every finding is labelled by who can
  reach it — attacker-controlled input versus internal misuse — so triage
  moves on signal instead of drowning in null-derefs, OOMs, and harmless
  assert-only aborts.
- **Keeps long runs affordable.** Prompt caching, capped reads, per-agent
  run budgets, and turn limits make cost a first-class control, so an
  unattended overnight audit doesn't quietly turn into a large bill.
- **Coordinates instead of colliding.** Shared state and automatic
  clustering keep parallel agents building on each other, and an
  independent reviewer with no shared context checks the work before
  anything is accepted.
- **Hands off fix-ready evidence.** Every accepted crash exports as a
  bundle — sanitizer trace, reproducer input, one-command reproduce
  script, fix direction, and optional patch — that rebuilds against a
  clean upstream checkout.

The platform does the discovery, the analysis, the triage, and the
handoff; the final security judgment stays with you.

## Documentation

Read the [detailed documentation](https://tokenfuzz.github.io/tokenfuzz/) to
learn how to use TokenFuzz.
