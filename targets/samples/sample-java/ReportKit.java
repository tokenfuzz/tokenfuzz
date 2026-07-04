import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Properties;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;

/**
 * ReportKit — a small toolkit for rendering configuration-driven reports, plus
 * a command-line front end (see {@link #main}).
 *
 * A report is assembled from a few ingredients: a *state* blob carrying cached
 * values between runs, an *XML manifest* describing sections, named export
 * hooks, report assets read from a project directory, and report *plugins*
 * loaded by class name. The toolkit is a single source file so it can be run
 * directly with {@code java ReportKit.java <job-file>} (JEP 330).
 *
 * The job file names an operation and carries its body; {@link #main} turns one
 * file into exactly one library call so a report task can be scripted.
 *
 * <p>Job-file format — a header line "op: &lt;name&gt;", then an
 * operation-specific body:
 *
 * <pre>
 * op: asset
 * /tmp
 * ../etc/passwd
 * </pre>
 */
public class ReportKit {

    /** Restore a previously saved report state blob produced by Java serialization. */
    static Object loadState(byte[] blob) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(blob))) {
            return in.readObject();
        }
    }

    /** Parse an XML report manifest and return its concatenated text. */
    static String parseManifest(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        Document doc = factory.newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes()));
        return doc.getDocumentElement().getTextContent();
    }

    /** Read a named report asset from the project's asset directory. */
    static byte[] readAsset(String name, String root) throws Exception {
        return Files.readAllBytes(Path.of(root, name));
    }

    /** Run a named export hook and return its stdout. */
    static String runExport(String hook) throws Exception {
        Process process = Runtime.getRuntime().exec(new String[] {"sh", "-c", hook});
        return new String(process.getInputStream().readAllBytes());
    }

    /** Load a named report plugin by class name and instantiate it. */
    static Object loadPlugin(String className) throws Exception {
        return Class.forName(className).getDeclaredConstructor().newInstance();
    }

    /**
     * Parse a small "key=value" configuration document from {@code text}.
     *
     * Backed by {@link Properties}, which only ever produces string keys and
     * values — it never deserializes an object or resolves an external entity,
     * so untrusted config text stays inert data.
     */
    static Properties parseConfig(String text) throws Exception {
        Properties config = new Properties();
        config.load(new java.io.StringReader(text));
        return config;
    }

    /**
     * Echo a caller-supplied data argument through a fixed reporting tool.
     *
     * The executable is fixed and the argument is passed as a single argv
     * element via {@link ProcessBuilder} with no shell, so a caller controls
     * neither which program runs nor a shell to interpret metacharacters.
     */
    static String runCommand(String arg) throws Exception {
        Process process = new ProcessBuilder(List.of("echo", arg)).start();
        return new String(process.getInputStream().readAllBytes());
    }

    // ── Command-line front end ──────────────────────────────────────────

    /** Split a job body into its first line and the remaining text. */
    private static String[] firstRest(String body) {
        int nl = body.indexOf('\n');
        return nl == -1 ? new String[] {body, ""}
                        : new String[] {body.substring(0, nl), body.substring(nl + 1)};
    }

    /** Route one operation name and its body to the matching library call. */
    private static String dispatch(String op, String body) throws Exception {
        switch (op) {
            case "state":
                return String.valueOf(loadState(Base64.getMimeDecoder().decode(body.trim())));
            case "manifest":
                return parseManifest(body).trim();
            case "asset": {
                String[] parts = firstRest(body);
                return new String(readAsset(firstRest(parts[1])[0].trim(), parts[0].trim()));
            }
            case "export":
                return runExport(body.trim());
            case "plugin":
                return loadPlugin(body.trim()).getClass().getName();
            case "config":
                return parseConfig(body).toString();
            case "command":
                return runCommand(body.trim());
            default:
                return null;
        }
    }

    /** Read a job file, parse its "op:" header, and print the operation's result. */
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("usage: java ReportKit.java job-file");
            System.exit(2);
        }

        String text = Files.readString(Path.of(args[0]));
        int nl = text.indexOf('\n');
        String header = nl == -1 ? text : text.substring(0, nl);
        String body = nl == -1 ? "" : text.substring(nl + 1);
        int colon = header.indexOf(':');
        if (colon == -1 || !header.substring(0, colon).trim().equals("op")) {
            throw new IllegalArgumentException("job file must begin with \"op: <name>\"");
        }
        String op = header.substring(colon + 1).trim();

        String result = dispatch(op, body);
        if (result == null) {
            System.err.println("unknown operation: " + op);
            System.exit(1);
        }
        System.out.println(op + ": " + result);
    }
}
