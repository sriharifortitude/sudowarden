package sudoers

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func fatal(f *File) []string {
	var out []string
	for _, p := range f.Problems {
		if p.Fatal {
			out = append(out, p.Message)
		}
	}
	return out
}

func one(t *testing.T, text string) Rule {
	t.Helper()
	f := Parse("t", []byte(text))
	if len(f.Problems) != 0 || len(f.Rules) != 1 {
		t.Fatalf("%q: %+v %+v", text, f.Problems, f.Rules)
	}
	return f.Rules[0]
}

func TestASimpleRule(t *testing.T) {
	r := one(t, "alice ALL=(root) NOPASSWD: /usr/bin/apt update\n")
	c := r.Commands[0]
	if !reflect.DeepEqual(r.Users, []string{"alice"}) || !reflect.DeepEqual(r.Hosts, []string{"ALL"}) ||
		!reflect.DeepEqual(c.RunasUsers, []string{"root"}) || !c.Tags["NOPASSWD"] || c.Text != "/usr/bin/apt update" {
		t.Fatalf("%+v", r)
	}
	if args, ok := c.Args(); !ok || args != "update" {
		t.Fatalf("%q %v", args, ok)
	}
}

func TestUserListsWithSpacesAfterCommas(t *testing.T) {
	r := one(t, "alice, bob, %ops  web1, web2 = /usr/bin/id\n")
	if !reflect.DeepEqual(r.Users, []string{"alice", "bob", "%ops"}) || !reflect.DeepEqual(r.Hosts, []string{"web1", "web2"}) {
		t.Fatalf("%+v", r)
	}
}

func TestRunasAndTagsCarryOverWithinAList(t *testing.T) {
	r := one(t, "alice ALL = (www-data) NOPASSWD: /bin/a, /bin/b, (root) PASSWD: /bin/c, /bin/d\n")
	want := []struct {
		runas    string
		nopasswd bool
	}{{"www-data", true}, {"www-data", true}, {"root", false}, {"root", false}}
	for i, w := range want {
		c := r.Commands[i]
		if strings.Join(c.RunasUsers, ",") != w.runas || c.Tags["NOPASSWD"] != w.nopasswd {
			t.Errorf("command %d: %+v", i, c)
		}
	}
}

func TestRunasListsWithCommasAndGroups(t *testing.T) {
	r := one(t, "alice ALL = (root, www-data : adm, wheel) /usr/bin/id\n")
	c := r.Commands[0]
	if !reflect.DeepEqual(c.RunasUsers, []string{"root", "www-data"}) || !reflect.DeepEqual(c.RunasGroups, []string{"adm", "wheel"}) || len(r.Commands) != 1 {
		t.Fatalf("%+v", r.Commands)
	}
}

func TestAHashInsideAQuotedValueIsNotAComment(t *testing.T) {
	f := Parse("t", []byte(`Defaults passprompt="Password # for %u: "`+"\n"))
	if len(f.Problems) != 0 || len(f.Defaults) != 1 || f.Defaults[0].Value != "Password # for %u: " {
		t.Fatalf("%+v %+v", f.Problems, f.Defaults)
	}
}

func TestHostSegmentsResetState(t *testing.T) {
	r := one(t, "alice web = NOPASSWD: /bin/a : db = /bin/b\n")
	if len(r.Commands) != 2 || !r.Commands[0].Tags["NOPASSWD"] || r.Commands[1].Tags["NOPASSWD"] {
		t.Fatalf("%+v", r.Commands)
	}
	if !reflect.DeepEqual(r.Hosts, []string{"web", "db"}) {
		t.Fatalf("%+v", r.Hosts)
	}
}

func TestTagsWithoutASpaceDigestsAndOptions(t *testing.T) {
	r := one(t, "alice ALL = NOPASSWD:NOEXEC:/usr/bin/vi, CWD=/srv TIMEOUT=5m sha256:abcdef== /usr/bin/id\n")
	if !r.Commands[0].Tags["NOPASSWD"] || !r.Commands[0].Tags["NOEXEC"] || r.Commands[0].Text != "/usr/bin/vi" {
		t.Fatalf("%+v", r.Commands[0])
	}
	c := r.Commands[1]
	if c.Digest != "sha256:abcdef==" || c.Options["CWD"] != "/srv" || c.Options["TIMEOUT"] != "5m" || c.Text != "/usr/bin/id" {
		t.Fatalf("%+v", c)
	}
}

func TestEscapedCharactersStayInTheCommand(t *testing.T) {
	r := one(t, `alice ALL = /bin/echo a\,b\:c\=d, /bin/true`+"\n")
	if len(r.Commands) != 2 || r.Commands[0].Text != `/bin/echo a\,b\:c\=d` {
		t.Fatalf("%+v", r.Commands)
	}
}

func TestContinuationLines(t *testing.T) {
	r := one(t, "alice ALL = /bin/a, \\\n    /bin/b\n")
	if len(r.Commands) != 2 || r.Line != 1 {
		t.Fatalf("%+v", r)
	}
}

func TestCommentsUidsAndIncludes(t *testing.T) {
	f := Parse("t", []byte("# a comment\n#1000 ALL = /bin/id # trailing\nalice ALL=(#0) /bin/id\n"))
	if len(f.Rules) != 2 || f.Rules[0].Users[0] != "#1000" || f.Rules[1].Commands[0].RunasUsers[0] != "#0" {
		t.Fatalf("%+v %+v", f.Rules, f.Problems)
	}
	if f.Rules[0].Commands[0].Text != "/bin/id" {
		t.Fatalf("trailing comment kept: %q", f.Rules[0].Commands[0].Text)
	}
}

func TestDefaults(t *testing.T) {
	f := Parse("t", []byte(`Defaults env_reset, !lecture, timestamp_timeout=5, env_keep += "LANG LC_*, TZ"
Defaults:alice !authenticate
Defaults>root !set_logname
Defaults!/usr/bin/su log_output
`))
	if len(f.Problems) != 0 || len(f.Defaults) != 7 {
		t.Fatalf("%+v %+v", f.Problems, f.Defaults)
	}
	d := f.Defaults
	if d[1].Name != "lecture" || !d[1].Negated || d[2].Op != "=" || d[2].Value != "5" {
		t.Fatalf("%+v", d)
	}
	if d[3].Name != "env_keep" || d[3].Op != "+=" || d[3].Value != "LANG LC_*, TZ" {
		t.Fatalf("a quoted value with a comma: %+v", d[3])
	}
	if d[4].Binding != ":alice" || d[5].Binding != ">root" || d[6].Binding != "!/usr/bin/su" {
		t.Fatalf("%+v", d)
	}
}

func TestAliases(t *testing.T) {
	f := Parse("t", []byte("Cmnd_Alias A = /bin/a, /bin/b : B = /bin/c\nUser_Alias OPS = alice, bob\nCmd_Alias C = /bin/d\n"))
	if len(f.Problems) != 0 || len(f.Aliases) != 4 || f.Aliases[1].Name != "B" || f.Aliases[3].Kind != "Cmnd" {
		t.Fatalf("%+v %+v", f.Problems, f.Aliases)
	}
}

func TestSyntaxErrorsAreFatal(t *testing.T) {
	for _, text := range []string{
		"alice ALL\n",                  // no =
		"alice = /bin/id\n",            // no host list
		"alice ALL = bin/id\n",         // not a full path
		"alice ALL = (root /bin/id\n",  // unclosed Runas
		"alice ALL = NOPASSWD:\n",      // no command
		"Cmnd_Alias lower = /bin/id\n", // alias name not upper case
		"Defaults\n",                   // nothing set
		"Defaults bad-name\n",          // invalid setting name
	} {
		if f := Parse("t", []byte(text)); len(fatal(f)) == 0 {
			t.Errorf("%q should not parse: %+v", text, f.Rules)
		}
	}
}

func TestBuiltinCommandWords(t *testing.T) {
	r := one(t, "alice ALL = sudoedit /etc/hosts, list, ALL, WEB\n")
	if len(r.Commands) != 4 {
		t.Fatalf("%+v", r.Commands)
	}
}

// --- includes --------------------------------------------------------------------------------

func write(t *testing.T, dir, rel, text string) string {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIncludedirSkipsDotsAndTildes(t *testing.T) {
	root := t.TempDir()
	main := write(t, root, "etc/sudoers", "@includedir /etc/sudoers.d\n")
	write(t, root, "etc/sudoers.d/b", "bob ALL = /bin/b\n")
	write(t, root, "etc/sudoers.d/a", "alice ALL = /bin/a\n")
	write(t, root, "etc/sudoers.d/c.rpmsave", "carol ALL = ALL\n")
	write(t, root, "etc/sudoers.d/d~", "dave ALL = ALL\n")
	f, err := Load(main, Options{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Rules) != 2 || f.Rules[0].Users[0] != "alice" || f.Rules[1].Users[0] != "bob" {
		t.Fatalf("%+v", f.Rules)
	}
}

func TestOldStyleAndRelativeIncludes(t *testing.T) {
	dir := t.TempDir()
	main := write(t, dir, "sudoers", "#include extra/one\n#includedir extra/more\n")
	write(t, dir, "extra/one", "alice ALL = /bin/a\n")
	write(t, dir, "extra/more/two", "bob ALL = /bin/b\n")
	f, err := Load(main, Options{})
	if err != nil || len(f.Rules) != 2 {
		t.Fatalf("%v %+v %+v", err, f.Rules, f.Problems)
	}
}

func TestIncludeProblems(t *testing.T) {
	dir := t.TempDir()
	main := write(t, dir, "sudoers", "@include missing\n@includedir nodir\n@include self\n@include /etc/sudoers.%h\n")
	write(t, dir, "self", "@include self\n")
	f, err := Load(main, Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	var got []bool
	for _, p := range f.Problems {
		got = append(got, p.Fatal)
	}
	// A missing @include is an error for sudo; a missing @includedir is skipped; a cycle is an error.
	if !reflect.DeepEqual(got, []bool{true, false, true, false}) {
		t.Fatalf("%+v", f.Problems)
	}
	if !strings.Contains(f.Problems[2].Message, "already being read") {
		t.Fatalf("a cycle must be named as one, not left to the depth limit: %s", f.Problems[2].Message)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "nope"), Options{}); err == nil {
		t.Error("missing")
	}
	if _, err := Load(dir, Options{}); err == nil {
		t.Error("directory")
	}
	if _, err := Load(write(t, dir, "big", strings.Repeat("#", 1<<20+1)), Options{}); err == nil {
		t.Error("oversized")
	}
}

// --- aliases ---------------------------------------------------------------------------------

func TestCommandAliasesExpandWithTheReferencesState(t *testing.T) {
	f := Parse("t", []byte("Cmnd_Alias SHELLS = /bin/sh, /bin/bash\nCmnd_Alias ADMIN = SHELLS, /usr/bin/id\nalice ALL = (root) NOPASSWD: ADMIN, !SHELLS\n"))
	e := Expand(f)
	if len(e.Problems) != 0 || len(e.Grants) != 5 {
		t.Fatalf("%+v %+v", e.Problems, e.Grants)
	}
	g := e.Grants[0]
	if g.Command.Text != "/bin/sh" || !g.Command.Tags["NOPASSWD"] || g.Command.RunasUsers[0] != "root" || strings.Join(g.Via, ">") != "ADMIN>SHELLS" {
		t.Fatalf("%+v", g)
	}
	if !e.Grants[3].Command.Negated || !e.Grants[4].Command.Negated {
		t.Fatal("a negated alias must negate its members")
	}
}

func TestAliasProblems(t *testing.T) {
	f := Parse("t", []byte("Cmnd_Alias A = B\nCmnd_Alias B = A\nCmnd_Alias A = /bin/x\nUser_Alias UNUSED = bob\nalice ALL = A, MISSING\nOPS ALL = /bin/id\n"))
	e := Expand(f)
	var msgs []string
	for _, p := range e.Problems {
		msgs = append(msgs, p.Message)
	}
	joined := strings.Join(msgs, "\n")
	for _, want := range []string{"defined again", "refers to itself", "MISSING is used but not defined", "User_Alias OPS is used but not defined", "UNUSED is defined but never used"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in\n%s", want, joined)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{"alice ALL=(root) NOPASSWD: /bin/a, /bin/b : db = /bin/c\n", "Defaults env_keep+=\"A,B\"\n",
		"Cmnd_Alias A = B\nCmnd_Alias B = A\nx ALL = A\n", "a b = (\n", "\\\n\\", "#include\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		Expand(Parse("f", []byte(s)))
	})
}
