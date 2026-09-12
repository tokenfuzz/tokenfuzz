# Getting Started

Start with a sample target to check your installation. Then add the project
you want to review and check its configuration before a longer run.

Run examples from the repository root. Replace placeholders such as
`<target>` and `<backend>` with your own values before running a command.

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
