# Getting Started

The shortest useful path is: install the host tools, prove one backend on a
sample target, add the real target, then run one bounded iteration.

## Try the pipeline first

1. Install the [prerequisites](prerequisites.md).
2. Pick one of the [sample targets](sample-targets.md).
3. Run a single-worker smoke test:

   ```bash
   bin/audit --target samples/sample-python --backend <backend> 1
   ```

This route needs no target setup, so it is the quickest way to tell a host or
backend problem from a real project's build problem.

## Add a real target

1. [Add the target](add-a-target.md) and establish its sanitizer build or
   language runner.
2. Review the generated `output/<target>/target.toml`.
3. Follow [First audit](first-audit.md) to run and inspect one iteration.

An empty `findings/` or `crashes/` directory is normal after one iteration.
Success means the target, backend, structured state, and result paths worked
together. The [Guides](../guides/index.md) cover longer-running operation, and
the [Concepts](../concepts/index.md) explain the design behind it.
