#!/usr/bin/env ruby
# frozen_string_literal: true

# reportkit_cli — command-line front end for the ReportKit toolkit.
#
# Reads one *job file* and performs a single ReportKit operation with it. This
# is the entry point an audit harness (or a CI step) drives: it turns a file on
# disk into exactly one library call so a report task can be scripted.
#
# Job-file format — a header line naming the operation, then an
# operation-specific body:
#
#     op: render
#     {"price": 3, "quantity": 4}
#     Total is {{ price * quantity }}.
#
# The first line is always "op: <name>". The remaining lines are the body:
#
#     render    first body line is a JSON object (the context); the rest is the
#               template whose {{ ... }} placeholders are filled from it.
#     state     the body is base64-encoded state bytes to restore.
#     export    the body is the name of an export hook to run.
#     asset     first body line is the project root; the second is the name.
#     save      first two body lines are the output root and name; the rest is
#               the content to write.
#     config    the body is a literal configuration document to parse.
#     command   the body is one argv token per line for a fixed-argv tool run.
require 'base64'
require 'json'
require 'yaml'
require_relative 'lib/report_kit'

def split_job(text)
  header, body = text.split("\n", 2)
  prefix, name = (header || '').split(':', 2)
  raise 'job file must begin with "op: <name>"' unless prefix&.strip == 'op'

  [name.strip, body || '']
end

def run_render(body)
  context_line, template = body.split("\n", 2)
  context = context_line.to_s.strip.empty? ? {} : JSON.parse(context_line)
  ReportKit.render_template(template.to_s, context)
end

def run_state(body)
  ReportKit.load_state(Base64.decode64(body)).inspect
end

def run_save(body)
  root_line, rest = body.split("\n", 2)
  name_line, data = rest.to_s.split("\n", 2)
  ReportKit.save_render(name_line.to_s.strip, root_line.to_s.strip, data.to_s).to_s
end

def run_export(body)
  ReportKit.run_export(body.strip)
end

def run_asset(body)
  root_line, name = body.split("\n", 2)
  ReportKit.read_asset(name.to_s.strip, root_line.to_s.strip).inspect
end

def run_config(body)
  ReportKit.parse_config(body).inspect
end

def run_command(body)
  ReportKit.run_command(body.strip)
end

OPERATIONS = {
  'render' => method(:run_render),
  'state' => method(:run_state),
  'export' => method(:run_export),
  'asset' => method(:run_asset),
  'save' => method(:run_save),
  'config' => method(:run_config),
  'command' => method(:run_command)
}.freeze

def main(argv)
  if argv.length != 1
    warn "usage: #{$PROGRAM_NAME} job-file"
    return 2
  end

  op, body = split_job(File.read(argv[0]))
  handler = OPERATIONS[op]
  unless handler
    warn "unknown operation: #{op.inspect}"
    return 1
  end

  puts "#{op}: #{handler.call(body)}"
  0
end

exit(main(ARGV)) if $PROGRAM_NAME == __FILE__
