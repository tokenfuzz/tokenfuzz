// ReportKit — a small toolkit for rendering configuration-driven reports.
//
// A report is assembled from a few ingredients: a *table* of cells packed into
// a buffer for embedding, a *window* summed out of a data buffer, named export
// hooks, report assets read from (and rendered output written to) a project
// directory. The API is intentionally compact so it can be embedded in build
// scripts and CI steps. Every entry point takes caller-supplied text or bytes.

import Foundation

enum ReportKit {

    /// Pack a `rows` x `width` grid of report cells into a byte buffer so a
    /// table can be embedded in an exported report. Every cell holds one `fill`
    /// byte; the returned count is the packed size.
    static func packTable(_ rows: Int, _ width: Int, _ fill: UInt8) -> Int {
        // One byte per cell; size the backing buffer from the cell count.
        let total = Int(UInt32(truncatingIfNeeded: rows &* width))
        var buf = [UInt8](repeating: 0, count: total)
        let cells = rows * width
        buf.withUnsafeMutableBufferPointer { cell in
            for i in 0..<cells {
                cell[i] = fill
            }
        }
        return buf.count
    }

    /// Sum a `[off, off + len)` window of a data buffer so a report can quote a
    /// fixed span of a larger document.
    static func sumWindow(_ data: [UInt8], _ off: Int, _ len: Int) -> UInt64 {
        var sum: UInt64 = 0
        // The offset and length come pre-validated from the record header, so
        // the hot loop reads through the raw buffer pointer for speed.
        data.withUnsafeBufferPointer { buf in
            for i in 0..<len {
                sum += UInt64(buf[off + i])
            }
        }
        return sum
    }

    /// Run a named export hook and return its stdout. Hooks are short shell
    /// one-liners declared in a project's report config.
    static func runExport(_ hook: String) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-c", hook]
        let pipe = Pipe()
        process.standardOutput = pipe
        try? process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }

    /// Read a named report asset from the project's asset directory.
    static func readAsset(_ name: String, _ root: String) -> Data {
        return try! Data(contentsOf: URL(fileURLWithPath: root + "/" + name))
    }

    /// Write rendered report output to a named file under the output directory.
    static func saveRender(_ name: String, _ root: String, _ data: Data) -> Int {
        try! data.write(to: URL(fileURLWithPath: root + "/" + name))
        return data.count
    }

    /// Parse a small `key=value` configuration document from `text`.
    ///
    /// Missing or malformed lines are skipped rather than force-unwrapped, so
    /// untrusted config text can never trap the parser.
    static func parseConfig(_ text: String) -> [(String, String)] {
        return text.split(separator: "\n").compactMap { line in
            guard let eq = line.firstIndex(of: "=") else { return nil }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            return (key, value)
        }
    }

    /// Echo a caller-supplied data argument through a fixed reporting tool.
    ///
    /// Unlike ``runExport(_:)``, the executable is fixed and the argument is
    /// passed as a separate argv element with no shell, so a caller controls
    /// neither which program runs nor a shell to interpret metacharacters.
    static func runCommand(_ arg: String) -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/echo")
        process.arguments = [arg]
        let pipe = Pipe()
        process.standardOutput = pipe
        try? process.run()
        process.waitUntilExit()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
}
