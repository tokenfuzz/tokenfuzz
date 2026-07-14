// reportkit — a small toolkit for rendering configuration-driven reports, plus
// a command-line front end.
//
// A report is assembled from a few ingredients: a *template* expanded against
// the current report context, a *bundle* (a zip archive) unpacked into a
// working directory, named export hooks, report assets read from (and rendered
// output written to) a project directory. The CLI turns one job file into
// exactly one library call so a report task can be scripted.
//
// Job-file format — a header line "op: <name>", then an operation-specific body:
//
//	op: asset
//	/tmp
//	../etc/passwd
package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"text/template"
)

// renderContext carries the values a report template is expanded against. The
// public fields are meant to appear in rendered output; SigningKey is an
// internal credential used to sign exported bundles and must never be emitted.
type renderContext struct {
	Title      string
	Author     string
	SigningKey string
}

// loadContext builds the render context for the current report, reading the
// bundle-signing key from the environment with a development default.
func loadContext() renderContext {
	key := os.Getenv("REPORTKIT_SIGNING_KEY")
	if key == "" {
		key = "dev-signing-key-do-not-ship"
	}
	return renderContext{Title: "Report", Author: "reportkit", SigningKey: key}
}

// renderTemplate expands a report template against the report context and
// returns the rendered text so a caller can produce a formatted report body.
func renderTemplate(tmplText string, ctx renderContext) string {
	t, err := template.New("report").Parse(tmplText)
	if err != nil {
		return ""
	}
	var buf strings.Builder
	t.Execute(&buf, ctx)
	return buf.String()
}

// extractBundle unpacks a report bundle (a zip archive) into the destination
// directory and returns the number of files written.
func extractBundle(archivePath, dest string) int {
	r, err := zip.OpenReader(archivePath)
	if err != nil {
		panic(err)
	}
	defer r.Close()

	written := 0
	for _, f := range r.File {
		if f.FileInfo().IsDir() {
			continue
		}
		target := filepath.Join(dest, f.Name)
		os.MkdirAll(filepath.Dir(target), 0o755)
		out, err := os.Create(target)
		if err != nil {
			panic(err)
		}
		rc, err := f.Open()
		if err != nil {
			panic(err)
		}
		io.Copy(out, rc)
		rc.Close()
		out.Close()
		written++
	}
	return written
}

// runExport runs a named export hook and returns its stdout. Hooks are short
// shell one-liners declared in a project's report config.
func runExport(hook string) string {
	out, _ := exec.Command("sh", "-c", hook).Output()
	return string(out)
}

// readAsset reads a named report asset from the project's asset directory.
func readAsset(name, root string) []byte {
	data, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		panic(err)
	}
	return data
}

// saveRender writes rendered report output to a named file under the output
// directory.
func saveRender(name, root string, data []byte) int {
	if err := os.WriteFile(filepath.Join(root, name), data, 0o644); err != nil {
		panic(err)
	}
	return len(data)
}

// parseConfig parses a small "key=value" configuration document from text.
//
// It is backed by encoding/json, which yields only strings, numbers, bools,
// slices, and maps — never a pointer to dereference or a program to run — so
// untrusted config text stays inert data.
func parseConfig(text string) map[string]any {
	config := map[string]any{}
	json.Unmarshal([]byte(text), &config)
	return config
}

// runCommand echoes a caller-supplied data argument through a fixed reporting
// tool.
//
// Unlike runExport, the executable is fixed and the argument is passed as a
// separate argv element with no shell, so a caller controls neither which
// program runs nor a shell to interpret metacharacters.
func runCommand(arg string) string {
	out, _ := exec.Command("echo", arg).Output()
	return string(out)
}

// mergeTallies totals the entry counts of report shards concurrently, so a
// large multi-shard report can be summed in parallel. Each worker adds into the
// shared running total; the accumulator is not synchronised, so overlapping
// shards race on it — a data race the race detector reports, and a total that is
// silently short without it.
func mergeTallies(shards [][]string) int {
	total := 0
	var wg sync.WaitGroup
	for _, shard := range shards {
		wg.Add(1)
		go func(entries []string) {
			defer wg.Done()
			for range entries {
				total++
			}
		}(shard)
	}
	wg.Wait()
	return total
}

// ── Command-line front end ──────────────────────────────────────────────

// firstRest splits a job body into its first line and the remaining text.
func firstRest(body string) (string, string) {
	if i := strings.IndexByte(body, '\n'); i >= 0 {
		return body[:i], body[i+1:]
	}
	return body, ""
}

// dispatch routes one operation name and its body to the matching library call.
func dispatch(op, body string) (string, bool) {
	switch op {
	case "render":
		return renderTemplate(body, loadContext()), true
	case "extract":
		dest, rest := firstRest(body)
		archive, _ := firstRest(rest)
		n := extractBundle(strings.TrimSpace(archive), strings.TrimSpace(dest))
		return "extracted=" + strconv.Itoa(n), true
	case "export":
		return runExport(strings.TrimSpace(body)), true
	case "asset":
		root, rest := firstRest(body)
		name, _ := firstRest(rest)
		return string(readAsset(strings.TrimSpace(name), strings.TrimSpace(root))), true
	case "save":
		root, rest := firstRest(body)
		name, data := firstRest(rest)
		return strconv.Itoa(saveRender(strings.TrimSpace(name), strings.TrimSpace(root), []byte(data))), true
	case "config":
		return fmt.Sprintf("%v", parseConfig(body)), true
	case "command":
		return runCommand(strings.TrimSpace(body)), true
	case "merge":
		shards := [][]string{}
		for _, line := range strings.Split(body, "\n") {
			if strings.TrimSpace(line) != "" {
				shards = append(shards, strings.Fields(line))
			}
		}
		return "merged=" + strconv.Itoa(mergeTallies(shards)), true
	default:
		return "", false
	}
}

// main reads a job file, parses its "op:" header, and prints the result.
func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: sample-go job-file")
		os.Exit(2)
	}

	text, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "could not read input")
		os.Exit(2)
	}

	header, body := firstRest(string(text))
	prefix, name, found := strings.Cut(header, ":")
	if !found || strings.TrimSpace(prefix) != "op" {
		fmt.Fprintln(os.Stderr, "job file must begin with \"op: <name>\"")
		os.Exit(2)
	}
	op := strings.TrimSpace(name)

	result, ok := dispatch(op, body)
	if !ok {
		fmt.Fprintln(os.Stderr, "unknown operation: "+op)
		os.Exit(1)
	}
	fmt.Println(op + ": " + result)
}
