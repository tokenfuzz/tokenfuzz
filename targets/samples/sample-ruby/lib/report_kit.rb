# frozen_string_literal: true

# ReportKit — a small toolkit for rendering configuration-driven reports.
#
# A report is assembled from a few ingredients: a *state* blob carrying cached
# values between runs and a set of *templates* whose `{{ ... }}` placeholders
# are filled from a binding. The toolkit also runs named export hooks, reads
# report assets from a project directory, and writes rendered output back to it.
#
# The API is intentionally compact so it can be embedded in build scripts and
# CI steps. Every entry point takes caller-supplied text or bytes.
module ReportKit
  # Placeholder syntax: {{ expression }} with optional surrounding whitespace.
  PLACEHOLDER = /\{\{\s*(.*?)\s*\}\}/.freeze

  module_function

  # Evaluate a single template expression against +context+.
  #
  # Expressions are small arithmetic or lookups such as +price * quantity+.
  # The context hash is exposed as local variables so templates can reference
  # report values by name.
  def evaluate_expr(expr, context)
    bindings = context.map { |key, value| "#{key} = #{value.inspect}; " }.join
    eval("#{bindings}#{expr}")
  end

  # Fill every {{ ... }} placeholder in +template+ from +context+.
  def render_template(template, context)
    template.gsub(PLACEHOLDER) { evaluate_expr(Regexp.last_match(1), context).to_s }
  end

  # Restore a previously saved report state blob produced by +save_state+.
  #
  # State is persisted with Ruby's native object-serialization format so a
  # cached value can be any object graph an earlier run produced, not just a
  # scalar or plain hash.
  def load_state(blob)
    Marshal.load(blob)
  end

  # Serialize a report state value for later +load_state+.
  def save_state(state)
    Marshal.dump(state)
  end

  # Write rendered report output to a named file under the output directory.
  def save_render(name, root, data)
    File.binwrite(File.join(root, name), data)
  end

  # Run a named export hook and return its stdout. Hooks are short shell
  # one-liners declared in a project's report config, e.g.
  # "pandoc report.md -o report.pdf".
  def run_export(hook)
    `#{hook}`
  end

  # Read a named report asset from the project's asset directory.
  def read_asset(name, root)
    File.binread(File.join(root, name))
  end

  # Parse a small literal configuration from +text+.
  #
  # Only scalars, arrays, and hashes are accepted; the permitted-class list is
  # empty, so a serialized object or symbol is rejected rather than
  # instantiated. Untrusted config text cannot reach arbitrary code here.
  def parse_config(text)
    YAML.safe_load(text)
  end

  # Echo a caller-supplied data argument through a fixed reporting tool.
  #
  # Unlike +run_export+, the executable is a fixed, harmless program and the
  # argument is spawned as a single argv element with no shell, so a caller
  # controls neither which program runs nor a shell to interpret metacharacters.
  def run_command(arg)
    IO.popen(['echo', arg], &:read)
  end
end
