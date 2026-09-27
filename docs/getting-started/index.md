# Getting started

Check your installation against a sample target first. Then add the project
you want to review and read its generated configuration before you commit to
a longer run.

Run every example from the repository root, and replace placeholders such as
`<target>` and `<backend>` with your own values.

## Try the pipeline first

1. Install the [prerequisites](prerequisites.md).
2. Run a one-worker smoke test against the Python
   [sample target](sample-targets.md):

   ```bash
   bin/audit --target samples/sample-python --backend <backend> 1
   ```

The Python sample is already configured and needs no build, so this is the
quickest way to separate a host or backend problem from a problem with your
own project's build. The other samples cover more languages and bug classes.

## Add a real target

1. [Add the target](add-a-target.md) and establish its sanitizer build or
   language runner.
2. Review the generated `output/<target>/target.toml`
   ([Target configuration](../guides/configure-target.md)).
3. Follow [First audit](first-audit.md) to run one iteration and inspect what
   it produced.

An empty `findings/` or `crashes/` directory is normal after one iteration.
The smoke test succeeds when the target, backend, structured state, and
result paths work together. The [Guides](../guides/index.md) cover longer
runs, and [Concepts](../concepts/index.md) explains the design behind them.
