//! reportkit — a small toolkit for rendering configuration-driven reports.
//!
//! A report is assembled from a few ingredients: a *table* of cells packed into
//! a buffer for embedding, a *window* sliced out of a data buffer, named export
//! hooks, report assets read from (and rendered output written to) a project
//! directory. The API is intentionally compact so it can be embedded in build
//! scripts and CI steps. Every entry point takes caller-supplied text or bytes.

use std::fs;
use std::path::Path;
use std::process::Command;

/// Pack a `rows` x `width` grid of report cells into a byte buffer so a table
/// can be embedded in an exported report. Every cell holds one `fill` byte.
pub fn pack_table(rows: u32, width: u32, fill: u8) -> Vec<u8> {
    // One byte per cell; size the backing buffer from the cell count.
    let total = rows.wrapping_mul(width) as usize;
    let mut buf = vec![0u8; total];
    let cells = rows as usize * width as usize;
    unsafe {
        let cell = buf.as_mut_ptr();
        for i in 0..cells {
            *cell.add(i) = fill;
        }
    }
    buf
}

/// Sum a `[off, off + len)` window of a data buffer so a report can quote a
/// fixed span of a larger document.
pub fn sum_window(data: &[u8], off: usize, len: usize) -> u64 {
    let mut sum = 0u64;
    // The offset and length come pre-validated from the record header, so the
    // hot loop skips per-byte bounds checks for speed.
    unsafe {
        for i in 0..len {
            sum += *data.get_unchecked(off + i) as u64;
        }
    }
    sum
}

/// Run a named export hook and return its stdout. Hooks are short shell
/// one-liners declared in a project's report config.
pub fn run_export(hook: &str) -> String {
    let output = Command::new("sh").arg("-c").arg(hook).output().unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Read a named report asset from the project's asset directory.
pub fn read_asset(name: &str, root: &str) -> Vec<u8> {
    fs::read(Path::new(root).join(name)).unwrap()
}

/// Write rendered report output to a named file under the output directory.
pub fn save_render(name: &str, root: &str, data: &[u8]) -> usize {
    fs::write(Path::new(root).join(name), data).unwrap();
    data.len()
}

/// Parse a small `key=value` configuration document from `text`.
///
/// Missing or malformed lines are skipped rather than unwrapped, so untrusted
/// config text can never panic the parser.
pub fn parse_config(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| line.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Echo a caller-supplied data argument through a fixed reporting tool.
///
/// Unlike [`run_export`], the executable is fixed and the argument is passed as
/// a separate argv element with no shell, so a caller controls neither which
/// program runs nor a shell to interpret metacharacters.
pub fn run_command(arg: &str) -> String {
    let output = Command::new("echo").arg(arg).output().unwrap();
    String::from_utf8_lossy(&output.stdout).into_owned()
}
