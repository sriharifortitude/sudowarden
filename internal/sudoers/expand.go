package sudoers

import "strings"

// Grant is one command a rule allows or excludes, after Cmnd_Alias expansion.
type Grant struct {
	Rule    *Rule
	Command Command
	// Via names the Cmnd_Alias chain the command came through, outermost first.
	Via []string
}

// Expanded is the result of resolving aliases.
type Expanded struct {
	Grants   []Grant
	Problems []Problem
	// Used records which aliases are referenced, by "Kind Name".
	Used map[string]bool
}

// Expand resolves Cmnd_Alias references in every rule and checks that every alias used is
// defined and that none refers to itself.
func Expand(f *File) *Expanded {
	e := &Expanded{Used: map[string]bool{}}
	defs := map[string]*Alias{}
	for i := range f.Aliases {
		a := &f.Aliases[i]
		key := a.Kind + " " + a.Name
		if prev, dup := defs[key]; dup {
			e.Problems = append(e.Problems, Problem{File: a.File, Line: a.Line, Fatal: true,
				Message: a.Kind + "_Alias " + a.Name + " is defined again; it was defined at " + prev.File + ":" + itoa(prev.Line)})
			continue
		}
		defs[key] = a
	}
	for i := range f.Rules {
		r := &f.Rules[i]
		for _, u := range r.Users {
			e.reference(defs, "User", strings.TrimPrefix(u, "!"), r.File, r.Line, nil)
		}
		for _, h := range r.Hosts {
			e.reference(defs, "Host", strings.TrimPrefix(h, "!"), r.File, r.Line, nil)
		}
		for _, c := range r.Commands {
			for _, ru := range append(append([]string{}, c.RunasUsers...), c.RunasGroups...) {
				e.reference(defs, "Runas", strings.TrimPrefix(ru, "!"), r.File, r.Line, nil)
			}
			e.command(defs, r, c, nil, map[string]bool{})
		}
	}
	for _, a := range f.Aliases {
		if !e.Used[a.Kind+" "+a.Name] {
			e.Problems = append(e.Problems, Problem{File: a.File, Line: a.Line, Message: a.Kind + "_Alias " + a.Name + " is defined but never used"})
		}
	}
	return e
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func isAliasName(s string) bool { return s != "ALL" && validName(s, true) }

// reference marks an alias name as used and its members as used in turn.
func (e *Expanded) reference(defs map[string]*Alias, kind, name, file string, line int, seen map[string]bool) {
	if !isAliasName(name) {
		return
	}
	key := kind + " " + name
	a, ok := defs[key]
	if !ok {
		// visudo 1.9.15 prints "referenced but not defined" and still accepts the file.
		e.Problems = append(e.Problems, Problem{File: file, Line: line, Warn: true,
			Message: kind + "_Alias " + name + " is used but not defined, so the reference matches nothing"})
		return
	}
	if seen == nil {
		seen = map[string]bool{}
	}
	if seen[key] {
		// visudo 1.9.15 prints "cycle in ..._Alias" and still accepts the file.
		e.Problems = append(e.Problems, Problem{File: a.File, Line: a.Line, Warn: true, Message: kind + "_Alias " + name + " refers to itself"})
		return
	}
	seen[key] = true
	e.Used[key] = true
	for _, m := range a.Members {
		e.reference(defs, kind, strings.TrimPrefix(strings.TrimSpace(m), "!"), a.File, a.Line, seen)
	}
	delete(seen, key)
}

// command adds a grant, expanding a Cmnd_Alias into its members. A member inherits the
// referencing command's Runas and tags; a "!" on the reference negates every member.
func (e *Expanded) command(defs map[string]*Alias, r *Rule, c Command, via []string, seen map[string]bool) {
	name := c.Path()
	if !isAliasName(name) || strings.ContainsRune(c.Text, ' ') {
		e.Grants = append(e.Grants, Grant{Rule: r, Command: c, Via: via})
		return
	}
	key := "Cmnd " + name
	a, ok := defs[key]
	if !ok {
		e.Problems = append(e.Problems, Problem{File: r.File, Line: r.Line, Warn: true,
			Message: "Cmnd_Alias " + name + " is used but not defined, so the reference matches nothing"})
		return
	}
	if seen[key] {
		e.Problems = append(e.Problems, Problem{File: a.File, Line: a.Line, Warn: true, Message: "Cmnd_Alias " + name + " refers to itself"})
		return
	}
	seen[key] = true
	e.Used[key] = true
	for _, m := range a.Members {
		st := cmdState{tags: map[string]bool{}}
		mc, err := st.parse(m)
		if err != nil {
			e.Problems = append(e.Problems, Problem{File: a.File, Line: a.Line, Fatal: true, Message: err.Error() + " in Cmnd_Alias " + name})
			continue
		}
		mc.Negated = mc.Negated != c.Negated
		mc.RunasUsers, mc.RunasGroups, mc.Tags, mc.Options = c.RunasUsers, c.RunasGroups, c.Tags, c.Options
		e.command(defs, r, mc, append(append([]string{}, via...), name), seen)
	}
	delete(seen, key)
}
