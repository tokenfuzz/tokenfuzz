//! reportkit_cli — command-line front end for the reportkit toolkit.
//!
//! Reads one *job file* and performs a single reportkit operation with it. This
//! is the entry point an audit harness (or a CI step) drives: it turns a file on
//! disk into exactly one library call so a report task can be scripted.
//!
//! Job-file format — a header line naming the operation, then an
//! operation-specific body:
//!
//! ```text
//! op: window
//! 64 32
//! short data
//! ```
//!
//! The first line is always `op: <name>`. The remaining lines are the body:
//!
//! * `table`   — the body's first line is `<rows> <width>`; packs that grid.
//! * `window`  — first body line is `<off> <len>`; the rest is the data buffer.
//! * `export`  — the body is the name of an export hook to run.
//! * `asset`   — first body line is the project root; the second is the name.
//! * `save`    — first two body lines are the output root and name; the rest is
//!               the content to write.
//! * `config`  — the body is a `key=value` configuration document to parse.
//! * `command` — the body is a single data argument echoed by a fixed tool.

mod reportkit;

use std::process::exit;

/// Split raw job text into the operation name (from the `op:` header) and body.
fn split_job(text: &str) -> (String, String) {
    let (header, body) = text.split_once('\n').unwrap_or((text, ""));
    let (prefix, name) = header.split_once(':').unwrap_or(("", ""));
    if prefix.trim() != "op" {
        panic!("job file must begin with \"op: <name>\"");
    }
    (name.trim().to_string(), body.to_string())
}

/// Split a body into its first line and the remaining lines.
fn first_rest(body: &str) -> (&str, &str) {
    body.split_once('\n').unwrap_or((body, ""))
}

/// Parse one operation's body and dispatch it to the matching reportkit call.
fn run(op: &str, body: &str) -> Option<String> {
    match op {
        "table" => {
            let nums: Vec<u32> = first_rest(body)
                .0
                .split_whitespace()
                .map(|n| n.parse().unwrap_or(0))
                .collect();
            Some(format!("bytes={}", reportkit::pack_table(nums[0], nums[1], 0x41).len()))
        }
        "window" => {
            let (header, data) = first_rest(body);
            let nums: Vec<usize> = header
                .split_whitespace()
                .map(|n| n.parse().unwrap_or(0))
                .collect();
            Some(reportkit::sum_window(data.as_bytes(), nums[0], nums[1]).to_string())
        }
        "export" => Some(reportkit::run_export(body.trim())),
        "asset" => {
            let (root, rest) = first_rest(body);
            let (name, _) = first_rest(rest);
            Some(String::from_utf8_lossy(&reportkit::read_asset(name.trim(), root.trim())).into_owned())
        }
        "save" => {
            let (root, rest) = first_rest(body);
            let (name, data) = first_rest(rest);
            Some(reportkit::save_render(name.trim(), root.trim(), data.as_bytes()).to_string())
        }
        "config" => Some(format!("{:?}", reportkit::parse_config(body))),
        "command" => Some(reportkit::run_command(body.trim())),
        _ => None,
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("usage: sample-rust job-file");
        exit(2);
    }

    let text = std::fs::read_to_string(&args[1]).unwrap_or_else(|_| {
        eprintln!("could not read input");
        exit(2);
    });

    let (op, body) = split_job(&text);
    match run(&op, &body) {
        Some(result) => println!("{op}: {result}"),
        None => {
            eprintln!("unknown operation: {op}");
            exit(1);
        }
    }
}
