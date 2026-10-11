// Package cli is sudowarden's command line.
package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/sriharifortitude/sudowarden/internal/rules"
	"github.com/sriharifortitude/sudowarden/internal/sudoers"
)

// Version is the release.
var Version = "0.1.0"

const usage = `sudowarden: find the sudoers rules that give more than they seem to.

usage: sudowarden [flags] FILE

FILE is a sudoers file (its @include and @includedir lines are followed) or - for standard
input (includes are not followed there).

flags:
  --root DIR        prefix for absolute include paths, to audit a copy of another machine's /etc
  --fail-on LEVEL   exit 1 at or above: critical, high (default), medium, low, info, none
  --json            machine-readable findings
  --version

exit status: 0 nothing at or above --fail-on, 1 at least one finding is, 2 usage error or unreadable file
`

// Run executes the command and returns the exit status.
func Run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sudowarden", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	root := fs.String("root", "", "")
	failOn := fs.String("fail-on", "high", "")
	asJSON := fs.Bool("json", false, "")
	showVersion := fs.Bool("version", false, "")
	help := fs.Bool("help", false, "")

	var paths []string
	rest := args
	for len(rest) > 0 {
		if err := fs.Parse(rest); err != nil {
			fmt.Fprintf(stderr, "sudowarden: %v\n\n%s", err, usage)
			return 2
		}
		rest = fs.Args()
		if len(rest) > 0 {
			paths = append(paths, rest[0])
			rest = rest[1:]
		}
	}
	switch {
	case *help:
		fmt.Fprint(stdout, usage)
		return 0
	case *showVersion:
		fmt.Fprintf(stdout, "sudowarden %s\n", Version)
		return 0
	case len(paths) != 1:
		fmt.Fprint(stderr, usage)
		return 2
	case *failOn != "none" && rules.Rank(*failOn) == len(rules.Severities):
		fmt.Fprintf(stderr, "sudowarden: --fail-on must be critical, high, medium, low, info or none, not %q\n", *failOn)
		return 2
	}

	var f *sudoers.File
	if paths[0] == "-" {
		data, err := io.ReadAll(io.LimitReader(stdin, 1<<20+1))
		if err != nil || len(data) > 1<<20 {
			fmt.Fprintln(stderr, "sudowarden: standard input is unreadable or over 1 MiB")
			return 2
		}
		f = sudoers.Parse("(stdin)", data)
	} else {
		var err error
		f, err = sudoers.Load(paths[0], sudoers.Options{Root: *root})
		if err != nil {
			fmt.Fprintf(stderr, "sudowarden: %v\n", err)
			return 2
		}
	}
	findings := rules.Check(f, sudoers.Expand(f))

	if *asJSON {
		if findings == nil {
			findings = []rules.Finding{}
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		enc.SetEscapeHTML(false)
		if err := enc.Encode(map[string]any{"files": f.Files, "findings": findings}); err != nil {
			return 2
		}
	} else {
		fmt.Fprint(stdout, Render(f, findings))
	}
	for _, x := range findings {
		if *failOn != "none" && rules.Rank(x.Severity) <= rules.Rank(*failOn) {
			return 1
		}
	}
	return 0
}

// Render formats findings as text.
func Render(f *sudoers.File, findings []rules.Finding) string {
	var b strings.Builder
	for _, x := range findings {
		who := ""
		if x.Who != "" {
			who = " [" + x.Who + "]"
		}
		fmt.Fprintf(&b, "%s:%d  %s %-8s %s%s\n", x.File, x.Line, x.ID, x.Severity, x.Message, who)
	}
	counts := map[string]int{}
	for _, x := range findings {
		counts[x.Severity]++
	}
	var parts []string
	for _, s := range rules.Severities {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	summary := "no findings"
	if len(parts) > 0 {
		summary = strings.Join(parts, ", ")
	}
	fmt.Fprintf(&b, "%d file(s) read, %d rule(s); %s\n", len(f.Files), len(f.Rules), summary)
	return b.String()
}
