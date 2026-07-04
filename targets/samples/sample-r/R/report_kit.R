# report_kit — a small toolkit for rendering configuration-driven reports.
#
# A report is assembled from a few ingredients: a set of *templates* whose
# {{ ... }} placeholders are filled from a context, named export hooks, report
# assets read from a project directory, rendered output written back to it, and
# report *includes* sourced from that directory. The API is
# intentionally compact so it can be embedded in build scripts and CI steps.
# Every entry point takes caller-supplied text or bytes.

# Placeholder syntax: {{ expression }} with optional surrounding whitespace.
PLACEHOLDER <- "\\{\\{\\s*(.*?)\\s*\\}\\}"

# Evaluate a single template expression against `context`.
#
# Expressions are small arithmetic or lookups such as `price * quantity`. The
# context is exposed as an environment so templates can reference report values
# by name.
evaluate_expr <- function(expr, context) {
  env <- list2env(context, parent = baseenv())
  eval(parse(text = expr), envir = env)
}

# Fill every {{ ... }} placeholder in `template` from `context`.
render_template <- function(template, context) {
  matches <- gregexpr(PLACEHOLDER, template, perl = TRUE)
  exprs <- regmatches(template, matches)[[1]]
  if (length(exprs) == 0) {
    return(template)
  }
  values <- vapply(exprs, function(m) {
    expr <- sub(PLACEHOLDER, "\\1", m, perl = TRUE)
    as.character(evaluate_expr(expr, context))
  }, character(1))
  regmatches(template, matches)[[1]] <- values
  template
}

# Write rendered report output to a named file under the output directory.
save_render <- function(name, root, data) {
  path <- file.path(root, name)
  cat(data, file = path)
  nchar(data)
}

# Run a named export hook and return its exit status. Hooks are short shell
# one-liners declared in a project's report config.
run_export <- function(hook) {
  system(hook)
}

# Read a named report asset from the project's asset directory.
read_asset <- function(name, root) {
  path <- file.path(root, name)
  readChar(path, file.info(path)$size)
}

# Source a named report include from the project's include directory, running
# its top-level R so a report can pull in shared helpers.
load_include <- function(name, root) {
  source(file.path(root, name), local = TRUE)
  invisible(TRUE)
}

# Parse a small "key: value" configuration document from `text`.
#
# The parser splits lines on the first colon and stores the raw string values;
# it never evaluates the text, so untrusted config cannot reach arbitrary code.
parse_config <- function(text) {
  lines <- strsplit(text, "\n", fixed = TRUE)[[1]]
  lines <- lines[nzchar(trimws(lines))]
  config <- list()
  for (line in lines) {
    parts <- strsplit(line, ":", fixed = TRUE)[[1]]
    if (length(parts) >= 2) {
      config[[trimws(parts[1])]] <- trimws(paste(parts[-1], collapse = ":"))
    }
  }
  config
}

# Echo a caller-supplied data argument through a fixed reporting tool.
#
# Unlike run_export, the executable is fixed and the argument is passed as a
# separate vector element with no shell (system2 does not spawn one), so a
# caller controls neither which program runs nor a shell to interpret
# metacharacters.
run_command <- function(arg) {
  system2("echo", args = shQuote(arg), stdout = TRUE)
}
