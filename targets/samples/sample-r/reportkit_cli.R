#!/usr/bin/env Rscript

# reportkit_cli — command-line front end for the report_kit toolkit.
#
# Reads one *job file* and performs a single report_kit operation with it. This
# is the entry point an audit harness (or a CI step) drives: it turns a file on
# disk into exactly one library call so a report task can be scripted.
#
# Job-file format — a header line naming the operation, then an
# operation-specific body:
#
#     op: render
#     price=3;quantity=4
#     Total is {{ price * quantity }}.
#
# The first line is always "op: <name>". The remaining lines are the body:
#
#     render    first body line is a ";"-separated list of key=number context
#               bindings; the rest is the template whose {{ ... }} placeholders
#               are filled from it.
#     export    the body is the name of an export hook to run.
#     asset     first body line is the project root; the second is the name.
#     save      first body line is the output root; the second is the name; the
#               rest is the rendered content to write.
#     include   first body line is the include root; the second is the name.
#     config    the body is a "key: value" configuration document to parse.
#     command   the body is a single data argument echoed by a fixed tool.

script_path <- sub("--file=", "", grep("--file=", commandArgs(FALSE), value = TRUE))
source(file.path(dirname(script_path), "R", "report_kit.R"))

split_job <- function(text) {
  nl <- regexpr("\n", text, fixed = TRUE)
  header <- if (nl > 0) substr(text, 1, nl - 1) else text
  body <- if (nl > 0) substr(text, nl + 1, nchar(text)) else ""
  head <- strsplit(header, ":", fixed = TRUE)[[1]]
  if (trimws(head[1]) != "op") {
    stop("job file must begin with \"op: <name>\"")
  }
  list(op = trimws(paste(head[-1], collapse = ":")), body = body)
}

parse_context <- function(line) {
  context <- list()
  if (is.na(line) || !nzchar(trimws(line))) {
    return(context)
  }
  for (pair in strsplit(line, ";", fixed = TRUE)[[1]]) {
    kv <- strsplit(pair, "=", fixed = TRUE)[[1]]
    if (length(kv) == 2) {
      context[[trimws(kv[1])]] <- as.numeric(trimws(kv[2]))
    }
  }
  context
}

first_line <- function(body) strsplit(body, "\n", fixed = TRUE)[[1]][1]
rest_lines <- function(body) {
  parts <- strsplit(body, "\n", fixed = TRUE)[[1]]
  paste(parts[-1], collapse = "\n")
}

op_render <- function(body) {
  render_template(rest_lines(body), parse_context(first_line(body)))
}

op_save <- function(body) {
  root <- trimws(first_line(body))
  after_root <- rest_lines(body)
  name <- trimws(first_line(after_root))
  data <- rest_lines(after_root)
  as.character(save_render(name, root, data))
}

op_export <- function(body) {
  as.character(run_export(trimws(body)))
}

op_asset <- function(body) {
  read_asset(trimws(first_line(rest_lines(body))), trimws(first_line(body)))
}

op_include <- function(body) {
  as.character(load_include(trimws(first_line(rest_lines(body))), trimws(first_line(body))))
}

op_config <- function(body) {
  format(parse_config(body))
}

op_command <- function(body) {
  paste(run_command(trimws(body)), collapse = "\n")
}

OPERATIONS <- list(
  render = op_render,
  export = op_export,
  asset = op_asset,
  save = op_save,
  include = op_include,
  config = op_config,
  command = op_command
)

main <- function(argv) {
  if (length(argv) != 1) {
    write("usage: reportkit_cli.R job-file", stderr())
    return(2)
  }

  text <- readChar(argv[1], file.info(argv[1])$size, useBytes = TRUE)
  job <- split_job(text)
  handler <- OPERATIONS[[job$op]]
  if (is.null(handler)) {
    write(paste("unknown operation:", job$op), stderr())
    return(1)
  }

  cat(job$op, ": ", paste(handler(job$body), collapse = ""), "\n", sep = "")
  0
}

quit(status = main(commandArgs(trailingOnly = TRUE)))
