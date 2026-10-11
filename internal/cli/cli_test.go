package cli

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func run(t *testing.T, stdin string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := Run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

const td = "../../testdata/"

func TestTheDebianLayout(t *testing.T) {
	code, out, _ := run(t, "", "--root", td+"debian", td+"debian/etc/sudoers")
	if code != 1 || !strings.Contains(out, "2 file(s) read") || strings.Contains(out, "dpkg-dist") {
		t.Fatalf("%d\n%s", code, out)
	}
}

func TestFailOn(t *testing.T) {
	text := "%sudo ALL=(ALL:ALL) ALL\nalice ALL = /usr/bin/cat /var/log/*\n"
	for level, want := range map[string]int{"high": 0, "medium": 1, "info": 1, "none": 0} {
		if code, _, _ := run(t, text, "-", "--fail-on", level); code != want {
			t.Errorf("--fail-on %s: %d", level, code)
		}
	}
}

func TestJSON(t *testing.T) {
	_, out, _ := run(t, "alice ALL = NOPASSWD: ALL\n", "--json", "-")
	var res struct {
		Files    []string `json:"files"`
		Findings []struct {
			ID, Severity, File, Who, Message string
			Line                             int
		} `json:"findings"`
	}
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Who != "alice" || res.Findings[0].Line != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no file":     {},
		"two files":   {"a", "b"},
		"bad fail-on": {"--fail-on", "severe", "-"},
		"unknown":     {"--nope", "-"},
		"missing":     {filepath.Join(t.TempDir(), "nope")},
	} {
		if code, _, errOut := run(t, "", args...); code != 2 || errOut == "" {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _, _ := run(t, strings.Repeat("#\n", 1<<19+1), "-"); code != 2 {
		t.Error("oversized stdin")
	}
}

func TestVersionAndHelp(t *testing.T) {
	if code, out, _ := run(t, "", "--version"); code != 0 || !strings.HasPrefix(out, "sudowarden ") {
		t.Fatal(out)
	}
	if code, out, _ := run(t, "", "--help"); code != 0 || !strings.Contains(out, "usage:") {
		t.Fatal(out)
	}
}
