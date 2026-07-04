// reportkit_cli — command-line front end for the ReportKit toolkit.
//
// Reads one *job file* and performs a single ReportKit operation with it. This
// is the entry point an audit harness (or a CI step) drives: it turns a file on
// disk into exactly one library call so a report task can be scripted.
//
// Job-file format — a header line "op: <name>", then an operation-specific body:
//
//     op: window
//     64 32
//     short data
//
// The remaining lines are the body:
//   table    the body's first line is "<rows> <width>"; packs that grid.
//   window   first body line is "<off> <len>"; the rest is the data buffer.
//   export   the body is the name of an export hook to run.
//   asset    first body line is the project root; the second is the name.
//   save     first two body lines are the output root and name; the rest is the
//            content to write.
//   config   the body is a key=value configuration document to parse.
//   command  the body is a single data argument echoed by a fixed tool.

import Foundation

// Split raw job text into the operation name (from the "op:" header) and body.
func splitJob(_ text: String) -> (op: String, body: String) {
    let parts = text.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
    let header = String(parts.first ?? "")
    let body = parts.count > 1 ? String(parts[1]) : ""
    let head = header.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
    guard head.first?.trimmingCharacters(in: .whitespaces) == "op" else {
        fatalError("job file must begin with \"op: <name>\"")
    }
    let op = head.count > 1 ? head[1].trimmingCharacters(in: .whitespaces) : ""
    return (op, body)
}

// Split a body into its first line and the remaining lines.
func firstRest(_ body: String) -> (String, String) {
    let parts = body.split(separator: "\n", maxSplits: 1, omittingEmptySubsequences: false)
    return (String(parts.first ?? ""), parts.count > 1 ? String(parts[1]) : "")
}

// Parse one operation's body and dispatch it to the matching ReportKit call.
func run(_ op: String, _ body: String) -> String? {
    switch op {
    case "table":
        let nums = firstRest(body).0.split(separator: " ").compactMap { Int($0) }
        return "bytes=\(ReportKit.packTable(nums[0], nums[1], 0x41))"
    case "window":
        let (header, data) = firstRest(body)
        let nums = header.split(separator: " ").compactMap { Int($0) }
        return String(ReportKit.sumWindow(Array(data.utf8), nums[0], nums[1]))
    case "export":
        return ReportKit.runExport(body.trimmingCharacters(in: .whitespacesAndNewlines))
    case "asset":
        let (root, rest) = firstRest(body)
        let (name, _) = firstRest(rest)
        return String(decoding: ReportKit.readAsset(name.trimmingCharacters(in: .whitespaces),
                                                    root.trimmingCharacters(in: .whitespaces)), as: UTF8.self)
    case "save":
        let (root, rest) = firstRest(body)
        let (name, data) = firstRest(rest)
        return String(ReportKit.saveRender(name.trimmingCharacters(in: .whitespaces),
                                           root.trimmingCharacters(in: .whitespaces),
                                           Data(data.utf8)))
    case "config":
        return "\(ReportKit.parseConfig(body))"
    case "command":
        return ReportKit.runCommand(body.trimmingCharacters(in: .whitespacesAndNewlines))
    default:
        return nil
    }
}

let arguments = CommandLine.arguments
if arguments.count != 2 {
    FileHandle.standardError.write("usage: sample-swift job-file\n".data(using: .utf8)!)
    exit(2)
}

guard let text = try? String(contentsOfFile: arguments[1], encoding: .utf8) else {
    FileHandle.standardError.write("could not read input\n".data(using: .utf8)!)
    exit(2)
}

let (op, body) = splitJob(text)
if let result = run(op, body) {
    print("\(op): \(result)")
} else {
    FileHandle.standardError.write("unknown operation: \(op)\n".data(using: .utf8)!)
    exit(1)
}
