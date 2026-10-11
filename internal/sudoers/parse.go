// Package sudoers parses sudoers files into the parts a security review needs: Defaults,
// aliases, and user specifications with every command's Runas list, tags and options.
package sudoers

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	maxFileBytes = 1 << 20
	maxFiles     = 256
	maxDepth     = 128 // sudo's own include depth limit
)

// Problem is a line sudo would not accept, or an include that could not be read.
type Problem struct {
	File    string
	Line    int
	Message string
	// Fatal problems make visudo -c fail; sudo then refuses to run for everyone.
	Fatal bool
}

// Default is one setting from a Defaults line.
type Default struct {
	// Binding is "", ":users", "@hosts", "!commands" or ">runas".
	Binding string
	Name    string
	// Op is "" for a flag, "=", "+=" or "-=".
	Op      string
	Value   string
	Negated bool
	File    string
	Line    int
}

// Alias is a User_Alias, Runas_Alias, Host_Alias or Cmnd_Alias definition.
type Alias struct {
	Kind    string // User, Runas, Host, Cmnd
	Name    string
	Members []string
	File    string
	Line    int
}

// Command is one command a rule allows (or, negated, excludes), with the state in force for it.
type Command struct {
	// Text is the command as written: a path with arguments, ALL, sudoedit ..., or an alias name.
	Text    string
	Negated bool
	// Digest is set when the command carries a digest (sha256:...).
	Digest string
	// RunasUsers and RunasGroups are nil when the rule gives none: the target is root only.
	RunasUsers  []string
	RunasGroups []string
	Tags        map[string]bool
	Options     map[string]string
}

// Path is the command's first word.
func (c Command) Path() string {
	f := strings.Fields(c.Text)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

// Args is everything after the path; Restricted is false when no arguments were written, which
// in sudoers means any arguments are allowed.
func (c Command) Args() (args string, restricted bool) {
	f := strings.SplitN(strings.TrimSpace(c.Text), " ", 2)
	if len(f) < 2 {
		return "", false
	}
	return strings.TrimSpace(f[1]), true
}

// Rule is one user specification line.
type Rule struct {
	Users    []string
	Hosts    []string
	Commands []Command
	File     string
	Line     int
	Text     string
}

// File is everything parsed from a sudoers file and its includes.
type File struct {
	Defaults []Default
	Aliases  []Alias
	Rules    []Rule
	Problems []Problem
	Files    []string
}

// Options say how to find included files.
type Options struct {
	// Root is prefixed to absolute include paths, to audit a copy of another machine's /etc.
	Root string
}

type parser struct {
	opt   Options
	out   *File
	stack []string
}

// Load parses path and everything it includes.
func Load(path string, opt Options) (*File, error) {
	data, err := readCapped(path)
	if err != nil {
		return nil, err
	}
	p := &parser{opt: opt, out: &File{}}
	abs, _ := filepath.Abs(path)
	p.stack = []string{abs}
	p.file(path, data, 0)
	return p.out, nil
}

// Parse reads sudoers text that includes nothing else.
func Parse(name string, data []byte) *File {
	p := &parser{out: &File{}}
	p.file(name, data, 0)
	return p.out
}

func readCapped(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory", path)
	}
	if info.Size() > maxFileBytes {
		return nil, fmt.Errorf("%s is %d bytes; a sudoers file over 1 MiB is not read", path, info.Size())
	}
	return os.ReadFile(path)
}

func (p *parser) problem(file string, line int, fatal bool, format string, args ...any) {
	p.out.Problems = append(p.out.Problems, Problem{File: file, Line: line, Message: fmt.Sprintf(format, args...), Fatal: fatal})
}

// logicalLines joins backslash-continued lines and returns each with its first line number.
func logicalLines(data []byte) ([]string, []int) {
	raw := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	var lines []string
	var nums []int
	for i := 0; i < len(raw); i++ {
		start := i
		cur := raw[i]
		for strings.HasSuffix(cur, `\`) && !strings.HasSuffix(cur, `\\`) && i+1 < len(raw) {
			i++
			cur = cur[:len(cur)-1] + " " + raw[i]
		}
		lines = append(lines, cur)
		nums = append(nums, start+1)
	}
	return lines, nums
}

// stripComment removes a # comment. A # followed by digits where a name may stand is a uid
// (#1000), and #include / #includedir are directives, so neither starts a comment.
func stripComment(s string) string {
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\':
			i++
		case c == '"':
			inQuote = !inQuote
		case c == '#' && !inQuote:
			if i+1 < len(s) && s[i+1] >= '0' && s[i+1] <= '9' && (i == 0 || strings.ContainsRune(" \t,(:=!", rune(s[i-1]))) {
				continue
			}
			return s[:i]
		}
	}
	return s
}

func (p *parser) file(name string, data []byte, depth int) {
	name = filepath.ToSlash(name)
	p.out.Files = append(p.out.Files, name)
	lines, nums := logicalLines(data)
	for i, raw := range lines {
		line := nums[i]
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if dir, arg, ok := includeDirective(trimmed); ok {
			p.include(name, line, dir, arg, depth)
			continue
		}
		text := strings.TrimSpace(stripComment(trimmed))
		if text == "" {
			continue
		}
		switch word := firstWord(text); {
		case word == "Defaults" || strings.HasPrefix(word, "Defaults:") || strings.HasPrefix(word, "Defaults@") ||
			strings.HasPrefix(word, "Defaults!") || strings.HasPrefix(word, "Defaults>"):
			p.defaults(name, line, text)
		case word == "User_Alias" || word == "Runas_Alias" || word == "Host_Alias" || word == "Cmnd_Alias" || word == "Cmd_Alias":
			p.aliases(name, line, word, strings.TrimSpace(text[len(word):]))
		default:
			p.rule(name, line, text)
		}
	}
}

func firstWord(s string) string {
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

func includeDirective(s string) (dir, arg string, ok bool) {
	for _, d := range []string{"@includedir", "#includedir", "@include", "#include"} {
		if strings.HasPrefix(s, d) && len(s) > len(d) && (s[len(d)] == ' ' || s[len(d)] == '\t') {
			arg = strings.TrimSpace(s[len(d):])
			if len(arg) >= 2 && arg[0] == '"' && arg[len(arg)-1] == '"' {
				arg = arg[1 : len(arg)-1]
			}
			return strings.TrimLeft(d, "@#"), arg, true
		}
	}
	return "", "", false
}

func (p *parser) include(from string, line int, dir, arg string, depth int) {
	if depth+1 > maxDepth {
		p.problem(from, line, true, "includes nested more than %d deep", maxDepth)
		return
	}
	if strings.Contains(arg, "%h") {
		p.problem(from, line, false, "%s %s uses %%h (the host name), which this tool does not expand", dir, arg)
		return
	}
	path := filepath.FromSlash(arg)
	if strings.HasPrefix(arg, "/") {
		path = filepath.Join(p.opt.Root, path)
	} else {
		// Since sudo 1.9.1 a relative path is relative to the file that includes it.
		path = filepath.Join(filepath.Dir(from), path)
	}
	var targets []string
	if dir == "includedir" {
		entries, err := os.ReadDir(path)
		if err != nil {
			p.problem(from, line, false, "@includedir %s cannot be read (%v); sudo skips a missing directory", arg, unwrap(err))
			return
		}
		for _, e := range entries {
			n := e.Name()
			// sudo skips names that end in ~ or contain a dot, so editor backups and *.rpmsave are ignored.
			if e.Type().IsRegular() && !strings.HasSuffix(n, "~") && !strings.Contains(n, ".") {
				targets = append(targets, filepath.Join(path, n))
			}
		}
		sort.Strings(targets)
	} else {
		targets = []string{path}
	}
	for _, t := range targets {
		abs, _ := filepath.Abs(t)
		for _, s := range p.stack {
			if s == abs {
				p.problem(from, line, true, "%s %s includes a file that is already being read", dir, arg)
				return
			}
		}
		if len(p.out.Files) >= maxFiles {
			p.problem(from, line, true, "more than %d files included", maxFiles)
			return
		}
		data, err := readCapped(t)
		if err != nil {
			p.problem(from, line, dir == "include", "%s %s: %v", dir, arg, unwrap(err))
			continue
		}
		p.stack = append(p.stack, abs)
		p.file(t, data, depth+1)
		p.stack = p.stack[:len(p.stack)-1]
	}
}

func unwrap(err error) error {
	if pe, ok := err.(*os.PathError); ok {
		return pe.Err
	}
	return err
}

// splitTop splits s on sep where sep is not escaped, quoted or inside parentheses.
func splitTop(s string, sep byte) []string {
	var out []string
	depth, inQuote, start := 0, false, 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++
		case c == '"':
			inQuote = !inQuote
		case inQuote:
		case c == '(':
			depth++
		case c == ')':
			if depth > 0 {
				depth--
			}
		case c == sep && depth == 0:
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func trimAll(xs []string) []string {
	var out []string
	for _, x := range xs {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func (p *parser) defaults(file string, line int, text string) {
	word := firstWord(text)
	binding := strings.TrimPrefix(word, "Defaults")
	rest := strings.TrimSpace(text[len(word):])
	if rest == "" {
		p.problem(file, line, true, "Defaults with no settings")
		return
	}
	for _, item := range trimAll(splitTop(rest, ',')) {
		d := Default{Binding: binding, File: file, Line: line}
		for _, op := range []string{"+=", "-=", "="} {
			if i := strings.Index(item, op); i > 0 {
				d.Name, d.Op, d.Value = strings.TrimSpace(item[:i]), op, strings.TrimSpace(item[i+len(op):])
				d.Value = strings.Trim(d.Value, `"`)
				break
			}
		}
		if d.Op == "" {
			d.Name = item
		}
		for strings.HasPrefix(d.Name, "!") {
			d.Negated = !d.Negated
			d.Name = strings.TrimSpace(d.Name[1:])
		}
		if !validName(d.Name, false) {
			p.problem(file, line, true, "Defaults setting %q is not a valid name", d.Name)
			continue
		}
		p.out.Defaults = append(p.out.Defaults, d)
	}
}

func validName(s string, upper bool) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		ok := c == '_' || (c >= 'a' && c <= 'z' && !upper) || (c >= 'A' && c <= 'Z') || (i > 0 && c >= '0' && c <= '9')
		if !ok {
			return false
		}
	}
	return true
}

func (p *parser) aliases(file string, line int, word, rest string) {
	kind := strings.TrimSuffix(word, "_Alias")
	if kind == "Cmd" {
		kind = "Cmnd"
	}
	// Several definitions can share a line: NAME1 = a, b : NAME2 = c
	for _, def := range trimAll(splitTop(rest, ':')) {
		name, members, ok := strings.Cut(def, "=")
		name = strings.TrimSpace(name)
		if !ok || !validName(name, true) || name == "ALL" {
			p.problem(file, line, true, "%s definition %q: an alias name is upper case letters, digits and _, followed by =", word, def)
			continue
		}
		p.out.Aliases = append(p.out.Aliases, Alias{Kind: kind, Name: name, Members: trimAll(splitTop(members, ',')), File: file, Line: line})
	}
}

var knownTags = map[string]bool{
	"NOPASSWD": true, "PASSWD": true, "NOEXEC": true, "EXEC": true, "SETENV": true, "NOSETENV": true,
	"LOG_INPUT": true, "NOLOG_INPUT": true, "LOG_OUTPUT": true, "NOLOG_OUTPUT": true, "MAIL": true, "NOMAIL": true,
	"FOLLOW": true, "NOFOLLOW": true, "INTERCEPT": true, "NOINTERCEPT": true,
}

var knownOptions = map[string]bool{"CWD": true, "CHROOT": true, "ROLE": true, "TYPE": true, "TIMEOUT": true,
	"NOTBEFORE": true, "NOTAFTER": true, "APPARMOR_PROFILE": true, "PRIVS": true, "LIMITPRIVS": true}

// rule parses "users hosts = cmnds [: hosts = cmnds ...]".
func (p *parser) rule(file string, line int, text string) {
	eq := indexTop(text, '=')
	if eq < 0 {
		p.problem(file, line, true, "not a Defaults line, an alias or a rule (no =): %q", clip(text))
		return
	}
	left := strings.Join(strings.Fields(strings.ReplaceAll(text[:eq], ", ", ",")), " ")
	parts := strings.SplitN(left, " ", 2)
	if len(parts) != 2 {
		p.problem(file, line, true, "a rule needs a user list and a host list before =: %q", clip(text))
		return
	}
	r := Rule{Users: trimAll(splitTop(parts[0], ',')), File: file, Line: line, Text: text}
	hosts, rest := parts[1], text[eq+1:]
	state := cmdState{tags: map[string]bool{}}
	for {
		r.Hosts = append(r.Hosts, trimAll(splitTop(hosts, ','))...)
		cmnds, next, more := splitSegment(rest)
		for _, item := range trimAll(splitTop(cmnds, ',')) {
			c, err := state.parse(item)
			if err != nil {
				p.problem(file, line, true, "%v in %q", err, clip(item))
				continue
			}
			r.Commands = append(r.Commands, c)
		}
		if !more {
			break
		}
		// A new host segment starts afresh: Runas and tags do not carry across ':'.
		state = cmdState{tags: map[string]bool{}}
		eq := indexTop(next, '=')
		if eq < 0 {
			p.problem(file, line, true, "a ':' must be followed by a host list and =")
			break
		}
		hosts, rest = next[:eq], next[eq+1:]
	}
	if len(r.Commands) == 0 {
		p.problem(file, line, true, "a rule with no commands")
		return
	}
	p.out.Rules = append(p.out.Rules, r)
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

func indexTop(s string, sep byte) int {
	depth, inQuote := 0, false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++
		case c == '"':
			inQuote = !inQuote
		case inQuote:
		case c == '(':
			depth++
		case c == ')':
			if depth > 0 {
				depth--
			}
		case c == sep && depth == 0:
			return i
		}
	}
	return -1
}

// splitSegment finds a ':' that starts a new "hosts = commands" segment. Colons that end a tag
// (NOPASSWD:), belong to a digest (sha256:) or a Runas group, or are escaped, do not.
func splitSegment(s string) (head, tail string, more bool) {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++
		case c == '(':
			depth++
		case c == ')':
			if depth > 0 {
				depth--
			}
		case c == ':' && depth == 0:
			word := lastWord(s[:i])
			if knownTags[word] || strings.HasPrefix(strings.ToLower(word), "sha") {
				continue
			}
			rest := s[i+1:]
			if eq := indexTop(rest, '='); eq > 0 && looksLikeHosts(rest[:eq]) {
				return s[:i], rest, true
			}
		}
	}
	return s, "", false
}

func lastWord(s string) string {
	s = strings.TrimRight(s, " \t")
	if i := strings.LastIndexAny(s, " \t,"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func looksLikeHosts(s string) bool {
	for _, h := range trimAll(splitTop(s, ',')) {
		if strings.ContainsAny(h, " /") {
			return false
		}
	}
	return true
}

type cmdState struct {
	runasUsers, runasGroups []string
	runasSet                bool
	tags                    map[string]bool
	options                 map[string]string
}

// parse reads "[(runas)] [OPTION=x ...] [TAG: ...] [!]command", updating the state that later
// commands in the same list inherit.
func (st *cmdState) parse(item string) (Command, error) {
	s := strings.TrimSpace(item)
	if strings.HasPrefix(s, "(") {
		end := strings.IndexByte(s, ')')
		if end < 0 {
			return Command{}, fmt.Errorf("unclosed Runas list")
		}
		users, groups, _ := strings.Cut(s[1:end], ":")
		st.runasUsers, st.runasGroups, st.runasSet = trimAll(splitTop(users, ',')), trimAll(splitTop(groups, ',')), true
		if st.runasUsers == nil {
			st.runasUsers = []string{}
		}
		s = strings.TrimSpace(s[end+1:])
	}
	st.options = map[string]string{}
	for {
		word := firstWord(s)
		name, value, isOpt := strings.Cut(word, "=")
		if isOpt && knownOptions[name] {
			st.options[name] = strings.Trim(value, `"`)
			s = strings.TrimSpace(s[len(word):])
			continue
		}
		if strings.HasSuffix(word, ":") && knownTags[strings.TrimSuffix(word, ":")] {
			tag := strings.TrimSuffix(word, ":")
			st.setTag(tag)
			s = strings.TrimSpace(s[len(word):])
			continue
		}
		// Tags may also be written without a space before the command: NOPASSWD:/bin/ls
		if i := strings.IndexByte(word, ':'); i > 0 && knownTags[word[:i]] && !strings.HasPrefix(strings.ToLower(word), "sha") {
			st.setTag(word[:i])
			s = strings.TrimSpace(s[i+1:])
			continue
		}
		break
	}
	c := Command{Tags: map[string]bool{}, Options: st.options}
	for k, v := range st.tags {
		c.Tags[k] = v
	}
	if st.runasSet {
		c.RunasUsers, c.RunasGroups = st.runasUsers, st.runasGroups
	}
	for strings.HasPrefix(s, "!") {
		c.Negated = !c.Negated
		s = strings.TrimSpace(s[1:])
	}
	if word := firstWord(s); strings.Contains(word, ":") && strings.HasPrefix(strings.ToLower(word), "sha") {
		c.Digest = word
		s = strings.TrimSpace(s[len(word):])
	}
	if s == "" {
		return Command{}, fmt.Errorf("a command is missing")
	}
	c.Text = s
	path := c.Path()
	switch {
	case path == "ALL", path == "sudoedit", path == "list", validName(path, true):
	case !strings.HasPrefix(path, "/"):
		return Command{}, fmt.Errorf("command %q is not a full path; sudoers requires one", path)
	}
	return c, nil
}

func (st *cmdState) setTag(tag string) {
	opposite := map[string]string{"NOPASSWD": "PASSWD", "PASSWD": "NOPASSWD", "NOEXEC": "EXEC", "EXEC": "NOEXEC",
		"SETENV": "NOSETENV", "NOSETENV": "SETENV"}
	if o, ok := opposite[tag]; ok {
		delete(st.tags, o)
	}
	st.tags[tag] = true
}
