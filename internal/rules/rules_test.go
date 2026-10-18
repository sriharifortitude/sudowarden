package rules

import (
	"strings"
	"testing"

	"github.com/sriharifortitude/sudowarden/internal/sudoers"
)

func run(t *testing.T, text string) []Finding {
	t.Helper()
	f := sudoers.Parse("t", []byte(text))
	return Check(f, sudoers.Expand(f))
}

func has(fs []Finding, id, sev, fragment string) bool {
	for _, f := range fs {
		if f.ID == id && f.Severity == sev && strings.Contains(f.Message, fragment) {
			return true
		}
	}
	return false
}

func list(fs []Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID+"/"+f.Severity+": "+f.Message)
	}
	return strings.Join(out, "\n")
}

func TestRootsOwnLineIsNotAFinding(t *testing.T) {
	if fs := run(t, "root ALL=(ALL:ALL) ALL\n"); len(fs) != 0 {
		t.Fatal(list(fs))
	}
}

func TestFullAdministrators(t *testing.T) {
	if fs := run(t, "%sudo ALL=(ALL:ALL) ALL\n"); !has(fs, "SUDO001", "info", "any command as ALL, with a password") || len(fs) != 1 {
		t.Fatal(list(fs))
	}
	if fs := run(t, "ci ALL=(ALL) NOPASSWD: ALL\n"); !has(fs, "SUDO001", "high", "without a password") {
		t.Fatal(list(fs))
	}
	if fs := run(t, "ci ALL=(www-data) NOPASSWD: ALL\n"); len(fs) != 0 {
		t.Fatal("ALL as a non-root user is not root:", list(fs))
	}
}

func TestShellEscapes(t *testing.T) {
	cases := []struct{ line, sev, fragment string }{
		{"alice ALL = /usr/bin/vim /etc/hosts", "high", ":!sh"},
		{"alice ALL = /usr/bin/less /var/log/syslog", "high", "!sh"},
		{"alice ALL = /usr/bin/python3.12 /opt/x.py", "high", "any code"},
		{"alice ALL = /bin/bash", "high", "shell"},
		{"alice ALL = /usr/bin/find", "high", "-exec"},
		{"alice ALL = /usr/bin/tar *", "high", "checkpoint-action"},
		{"alice ALL = (www-data) /usr/bin/vim", "medium", ":!sh"},
		{"alice ALL = NOEXEC: /usr/bin/less /var/log/syslog", "low", "NOEXEC"},
		{"alice ALL = /usr/bin/systemctl status nginx", "high", "status, show"},
		{"alice ALL = /usr/bin/journalctl -u nginx", "high", "--no-pager"},
		{"alice ALL = /usr/bin/git -C /srv pull", "high", "hooks"},
		{"alice ALL = (:adm) /usr/bin/vim", "high", ":!sh"},
		{"alice ALL = () /usr/bin/vim", "high", ":!sh"},
		{"alice ALL = /usr/bin/systemctl restart *", "high", "status, show"},
		{"alice ALL = /usr/bin/man --no-pager ls", "high", "less"},
	}
	for _, c := range cases {
		if fs := run(t, c.line+"\n"); !has(fs, "SUDO002", c.sev, c.fragment) {
			t.Errorf("%s: want SUDO002/%s with %q, got\n%s", c.line, c.sev, c.fragment, list(fs))
		}
	}
}

func TestSafeGrants(t *testing.T) {
	for _, line := range []string{
		"alice ALL = /usr/bin/systemctl restart nginx",
		"alice ALL = /usr/bin/systemctl --no-pager status nginx",
		"alice ALL = /usr/bin/journalctl --no-pager -u nginx",
		"alice ALL = /usr/bin/tar -czf /backup/etc.tgz /etc",
		"alice ALL = /usr/sbin/service nginx reload",
		"alice ALL = /usr/bin/apt-get update",
		"alice ALL = sudoedit /etc/hosts",
		"alice ALL = /usr/local/bin/deploy.sh",
		"alice ALL = /usr/bin/python3x",
		"alice ALL = /usr/local/bin/cp2",
		"alice ALL = /usr/local/bin/less7 /x",
	} {
		if fs := run(t, line+"\n"); len(fs) != 0 {
			t.Errorf("%s:\n%s", line, list(fs))
		}
	}
}

func TestWildcardsAndWritablePaths(t *testing.T) {
	if fs := run(t, "alice ALL = /usr/bin/cat /var/log/*\n"); !has(fs, "SUDO003", "medium", "../../etc/shadow") {
		t.Fatal(list(fs))
	}
	if fs := run(t, "alice ALL = /opt/tools/*\n"); !has(fs, "SUDO003", "high", "path") {
		t.Fatal(list(fs))
	}
	for _, p := range []string{"/home/alice/bin/x", "/tmp/x", "/var/tmp/x", "/dev/shm/x"} {
		if fs := run(t, "alice ALL = "+p+"\n"); !has(fs, "SUDO004", "high", p) {
			t.Errorf("%s:\n%s", p, list(fs))
		}
	}
}

func TestDenyLists(t *testing.T) {
	fs := run(t, "Cmnd_Alias SHELLS = /bin/sh, /bin/bash\nhelp ALL = ALL, !SHELLS, !/usr/bin/su\n")
	n := 0
	for _, f := range fs {
		if f.ID == "SUDO005" {
			n++
		}
	}
	if n != 3 || has(fs, "SUDO001", "info", "") {
		t.Fatal(list(fs))
	}
	// A negation without ALL is not a deny list.
	if fs := run(t, "alice ALL = /usr/bin/id, !/usr/bin/su\n"); len(fs) != 0 {
		t.Fatal(list(fs))
	}
}

func TestSetenv(t *testing.T) {
	if fs := run(t, "alice ALL = SETENV: /usr/local/bin/report\n"); !has(fs, "SUDO011", "high", "LD_PRELOAD") {
		t.Fatal(list(fs))
	}
}

func TestDefaultsChecks(t *testing.T) {
	cases := []struct{ line, id, sev string }{
		{"Defaults !env_reset", "SUDO010", "high"},
		{`Defaults env_keep += "LD_PRELOAD"`, "SUDO010", "high"},
		{`Defaults:deploy env_keep += "PYTHONPATH TZ"`, "SUDO010", "high"},
		{"Defaults env_keep = LD_LIBRARY_PATH", "SUDO010", "high"},
		{`Defaults env_keep += "LD_BIND_NOW"`, "SUDO010", "high"},
		{`Defaults env_keep += "PYTHONPATH*"`, "SUDO010", "high"},
		{"Defaults setenv", "SUDO011", "high"},
		{"Defaults:ci !authenticate", "SUDO012", "high"},
		{"Defaults visiblepw", "SUDO012", "medium"},
		{"Defaults exempt_group=staff", "SUDO012", "medium"},
		{"Defaults timestamp_timeout=-1", "SUDO013", "low"},
		{"Defaults timestamp_timeout=120", "SUDO013", "low"},
		{"Defaults !use_pty", "SUDO013", "low"},
		{"Defaults !log_output", "SUDO013", "low"},
	}
	for _, c := range cases {
		if fs := run(t, c.line+"\n"); !has(fs, c.id, c.sev, "") || len(fs) != 1 {
			t.Errorf("%s: want only %s/%s, got\n%s", c.line, c.id, c.sev, list(fs))
		}
	}
	for _, line := range []string{"Defaults env_reset", `Defaults env_keep += "LANG TZ"`, `Defaults env_keep -= "LD_PRELOAD"`,
		"Defaults timestamp_timeout=15", "Defaults use_pty", "Defaults !lecture"} {
		if fs := run(t, line+"\n"); len(fs) != 0 {
			t.Errorf("%s:\n%s", line, list(fs))
		}
	}
}

func TestSyntaxErrorsAreHigh(t *testing.T) {
	if fs := run(t, "alice ALL = bin/id\n"); !has(fs, "SUDO030", "high", "visudo -c fails") {
		t.Fatal(list(fs))
	}
	if fs := run(t, "User_Alias UNUSED = bob\n"); !has(fs, "SUDO031", "info", "never used") {
		t.Fatal(list(fs))
	}
	// visudo 1.9.15 accepts a reference to an undefined alias, with a warning.
	if fs := run(t, "alice ALL = MISSING\n"); !has(fs, "SUDO031", "medium", "matches nothing") || has(fs, "SUDO030", "high", "") {
		t.Fatal(list(fs))
	}
}

func TestFindingsNameTheAliasPath(t *testing.T) {
	fs := run(t, "Cmnd_Alias EDIT = /usr/bin/vim\nCmnd_Alias OPS = EDIT\nalice ALL = OPS\n")
	if !has(fs, "SUDO002", "high", "through Cmnd_Alias OPS > EDIT") || fs[0].Who != "alice" || fs[0].Line != 3 {
		t.Fatal(list(fs))
	}
}
