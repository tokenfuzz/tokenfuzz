/*
 * reportkit — a small toolkit for rendering configuration-driven reports, plus
 * a command-line front end (a Kotlin script run with `kotlinc -script`).
 *
 * A report is assembled from a few ingredients: a *state* blob carrying cached
 * values between runs, an *XML manifest* describing sections, named export
 * hooks, report assets read from a project directory, and report *plugins*
 * loaded by class name. The script turns one job file into exactly one library
 * call so a report task can be scripted.
 *
 * Job-file format — a header line "op: <name>", then an operation-specific body:
 *
 *     op: asset
 *     /tmp
 *     ../etc/passwd
 */

import java.io.ByteArrayInputStream
import java.io.File
import java.io.ObjectInputStream
import java.util.Base64
import java.util.Properties
import javax.xml.parsers.DocumentBuilderFactory

/** Restore a previously saved report state blob produced by Java serialization. */
fun loadState(blob: ByteArray): Any? =
    ObjectInputStream(ByteArrayInputStream(blob)).use { it.readObject() }

/** Parse an XML report manifest and return its concatenated text. */
fun parseManifest(xml: String): String {
    val factory = DocumentBuilderFactory.newInstance()
    val doc = factory.newDocumentBuilder().parse(ByteArrayInputStream(xml.toByteArray()))
    return doc.documentElement.textContent
}

/** Read a named report asset from the project's asset directory. */
fun readAsset(name: String, root: String): ByteArray = File(root, name).readBytes()

/** Run a named export hook and return its stdout. */
fun runExport(hook: String): String {
    val process = ProcessBuilder("sh", "-c", hook).redirectErrorStream(true).start()
    return process.inputStream.readBytes().toString(Charsets.UTF_8)
}

/** Load a named report plugin by class name and instantiate it. */
fun loadPlugin(className: String): Any =
    Class.forName(className).getDeclaredConstructor().newInstance()

/**
 * Parse a small "key=value" configuration document from [text].
 *
 * Backed by [Properties], which only ever produces string keys and values — it
 * never deserializes an object or resolves an external entity, so untrusted
 * config text stays inert data.
 */
fun parseConfig(text: String): Properties {
    val config = Properties()
    config.load(text.reader())
    return config
}

/**
 * Echo a caller-supplied data argument through a fixed reporting tool.
 *
 * Unlike [runExport], the executable is fixed and the argument is passed as a
 * separate argv element with no shell, so a caller controls neither which
 * program runs nor a shell to interpret metacharacters.
 */
fun runCommand(arg: String): String {
    val process = ProcessBuilder("echo", arg).redirectErrorStream(true).start()
    return process.inputStream.readBytes().toString(Charsets.UTF_8)
}

// ── Command-line front end ──────────────────────────────────────────────

/** Split a job body into its first line and the remaining text. */
fun firstRest(body: String): Pair<String, String> {
    val nl = body.indexOf('\n')
    return if (nl == -1) Pair(body, "") else Pair(body.substring(0, nl), body.substring(nl + 1))
}

/** Route one operation name and its body to the matching library call. */
fun dispatch(op: String, body: String): String? = when (op) {
    "state" -> loadState(Base64.getMimeDecoder().decode(body.trim())).toString()
    "manifest" -> parseManifest(body).trim()
    "asset" -> {
        val (root, rest) = firstRest(body)
        String(readAsset(firstRest(rest).first.trim(), root.trim()))
    }
    "export" -> runExport(body.trim())
    "plugin" -> loadPlugin(body.trim())::class.java.name
    "config" -> parseConfig(body).toString()
    "command" -> runCommand(body.trim())
    else -> null
}

if (args.size != 1) {
    System.err.println("usage: kotlinc -script reportkit.kts job-file")
    kotlin.system.exitProcess(2)
}

val text = File(args[0]).readText()
val (header, body) = firstRest(text)
val colon = header.indexOf(':')
if (colon == -1 || header.substring(0, colon).trim() != "op") {
    throw IllegalArgumentException("job file must begin with \"op: <name>\"")
}
val op = header.substring(colon + 1).trim()

val result = dispatch(op, body)
if (result == null) {
    System.err.println("unknown operation: $op")
    kotlin.system.exitProcess(1)
}
println("$op: $result")
