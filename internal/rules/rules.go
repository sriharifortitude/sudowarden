// Package rules judges what a sudoers file lets each user do.
package rules

import (
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/sriharifortitude/sudowarden/internal/sudoers"
)

// Severities, most serious first.
var Severities = []string{"critical", "high", "medium", "low", "info"}

// Rank orders severities: critical is 0.
func Rank(s string) int {
	for i, v := range Severities {
		if v == s {
			return i
		}
	}
	return len(Severities)
}

// Finding is one problem at one line.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	// Who is the rule's user list, when the finding is about a rule.
	Who     string `json:"who,omitempty"`
	Message string `json:"message"`
}

// escape is how a program can be turned into a shell.
type escape struct {
	class string
	how   string
}

// Classes of programs, by how they give a shell. Sources: GTFOBins (gtfobins.github.io), each
// program's documentation.
const (
	classShell  = "shell"       // is a shell, or starts one directly
	classInterp = "interpreter" // runs code given to it
	classEscape = "escape"      // an editor, pager or client with a "run a command" feature
	classArgs   = "args"        // runs a command or writes a file when given the right arguments
)

var escapes = map[string]escape{}

func init() {
	add := func(class, how string, names ...string) {
		for _, n := range names {
			escapes[n] = escape{class, how}
		}
	}
	add(classShell, "it is a shell", "sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "ash", "busybox", "su", "sudo", "login", "runuser", "doas")
	add(classInterp, "it runs any code it is given", "python", "python2", "python3", "perl", "ruby", "irb", "lua", "php", "node", "nodejs",
		"tclsh", "wish", "gdb", "awk", "gawk", "mawk", "nawk", "expect", "pwsh", "jrunscript", "rlwrap", "julia", "R", "Rscript")
	add(classEscape, "it can start a shell from inside (for example !sh, or :!sh, or through its pager)", "vi", "vim", "view", "vimdiff", "rvim",
		"nvim", "emacs", "nano", "pico", "ed", "less", "more", "most", "pg", "man", "journalctl", "systemctl", "git", "mysql", "mariadb",
		"psql", "sqlite3", "ftp", "telnet", "top", "htop", "mail", "mutt", "nmap", "ssh", "lftp", "smbclient")
	add(classArgs, "its arguments can run a command or overwrite a file such as /etc/sudoers", "find", "xargs", "env", "nice", "nohup",
		"timeout", "strace", "ltrace", "taskset", "ionice", "stdbuf", "time", "chroot", "unshare", "nsenter", "setarch", "flock", "script",
		"make", "docker", "podman", "apt", "apt-get", "aptitude", "dpkg", "rpm", "yum", "dnf", "zypper", "pip", "pip3", "npm", "gem",
		"tar", "zip", "unzip", "rsync", "scp", "tcpdump", "socat", "nc", "ncat", "netcat", "service", "systemd-run", "at", "crontab",
		"mount", "cp", "mv", "tee", "dd", "install", "ln", "chmod", "chown", "chgrp", "truncate", "sed", "wget", "curl", "openssl",
		"cpio", "watch", "run-parts", "start-stop-daemon", "kubectl", "ansible-playbook", "terraform")
}

// specific says, for common programs, exactly how the shell is reached.
var specific = map[string]string{
	"vi": "':!sh' at its prompt runs a shell", "vim": "':!sh' at its prompt runs a shell", "view": "':!sh' at its prompt runs a shell",
	"nvim": "':!sh' at its prompt runs a shell", "nano": "^R^X runs a command", "emacs": "M-x shell runs a shell",
	"ed": "'!sh' runs a shell", "less": "'!sh' at its prompt runs a shell", "more": "'!sh' at its prompt runs a shell",
	"man":        "it shows pages in less, where '!sh' runs a shell",
	"journalctl": "it shows output in less, where '!sh' runs a shell (unless --no-pager)",
	"systemctl":  "status, show and list commands open less, where '!sh' runs a shell (unless --no-pager)",
	"git":        "it runs hooks, core.pager and other commands named in the repository's configuration, and pages output through less",
	"mysql":      "'\\! sh' runs a shell", "psql": "'\\! sh' runs a shell", "sqlite3": "'.shell sh' runs a shell",
	"find": "-exec runs any command", "xargs": "it runs any command", "env": "'env sh' runs a shell",
	"tar": "--checkpoint-action=exec runs any command", "zip": "-TT runs any command", "rsync": "-e runs any command",
	"scp": "-S runs any command", "tcpdump": "-z runs any command", "apt-get": "-o APT::Update::Pre-Invoke runs any command",
	"apt": "-o APT::Update::Pre-Invoke runs any command", "pip": "installing a local package runs its setup code",
	"pip3": "installing a local package runs its setup code", "npm": "lifecycle scripts run any command",
	"docker": "'docker run -v /:/host' gives the whole file system", "podman": "'podman run -v /:/host' gives the whole file system",
	"cp": "it can overwrite /etc/sudoers or /etc/shadow", "mv": "it can replace /etc/sudoers or /etc/shadow",
	"tee": "it can overwrite /etc/sudoers", "dd": "it can overwrite any file", "sed": "-i rewrites any file, and 'e' runs commands",
	"chmod": "it can make /etc/shadow readable or a root-owned program writable", "chown": "it can take ownership of any file",
	"crontab": "-e runs an editor, and -u root installs root jobs", "service": "'service ../../bin/sh' runs a shell",
	"curl": "-o overwrites any file", "wget": "-O overwrites any file", "make": "-f with a user's Makefile runs any command",
}

func escapeFor(p string) (escape, bool) {
	base := path.Base(p)
	if e, ok := escapes[base]; ok {
		if how, ok := specific[base]; ok {
			e.how = how
		}
		return e, true
	}
	// python3.12, perl5.36, php8.2, ruby3.1
	trimmed := strings.TrimRight(base, "0123456789.")
	if e, ok := escapes[trimmed]; ok && trimmed != base && (e.class == classInterp || e.class == classShell) {
		return e, true
	}
	return escape{}, false
}

// dangerousEnv are variables that change what a program loads or runs.
var dangerousEnv = map[string]bool{
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "LD_AUDIT": true, "PYTHONPATH": true, "PYTHONSTARTUP": true,
	"PYTHONHOME": true, "PERL5LIB": true, "PERL5OPT": true, "PERLLIB": true, "RUBYLIB": true, "RUBYOPT": true,
	"NODE_OPTIONS": true, "NODE_PATH": true, "BASH_ENV": true, "ENV": true, "PS4": true, "SHELLOPTS": true,
	"GCONV_PATH": true, "JAVA_TOOL_OPTIONS": true, "_JAVA_OPTIONS": true, "PATH": true, "IFS": true, "LUA_PATH": true,
	"GIT_EXEC_PATH": true, "EDITOR": true, "VISUAL": true, "PAGER": true, "SUDO_EDITOR": true,
}

var writableDirs = []string{"/home/", "/tmp/", "/var/tmp/", "/dev/shm/", "/Users/", "/run/user/", "/var/www/"}

// targetsRoot reports whether a command can run as root: no Runas list means root only; ALL,
// root, #0 or a negation-free alias may include root.
func targetsRoot(c sudoers.Command) (bool, string) {
	if c.RunasUsers == nil && c.RunasGroups == nil {
		return true, "root"
	}
	if len(c.RunasUsers) == 0 {
		// "()" and "(:group)" keep root as the user.
		return true, "root"
	}
	for _, u := range c.RunasUsers {
		if u == "ALL" || u == "root" || u == "#0" {
			return true, u
		}
		if u != "" && u[0] >= 'A' && u[0] <= 'Z' && !strings.ContainsAny(u, "!") {
			return true, u + " (an alias that may include root)"
		}
	}
	return false, strings.Join(c.RunasUsers, ",")
}

func onlyRoot(users []string) bool {
	for _, u := range users {
		if u != "root" && u != "#0" {
			return false
		}
	}
	return len(users) > 0
}

// Check runs every rule.
func Check(f *sudoers.File, e *sudoers.Expanded) []Finding {
	var out []Finding
	for _, p := range append(append([]sudoers.Problem{}, f.Problems...), e.Problems...) {
		sev, id := "info", "SUDO031"
		if p.Warn {
			sev = "medium"
			p.Message += "; visudo accepts the file but warns"
		}
		if p.Fatal {
			sev, id = "high", "SUDO030"
			p.Message += "; visudo -c fails, and sudo refuses to run for anyone while the file is broken"
		}
		out = append(out, Finding{ID: id, Severity: sev, File: p.File, Line: p.Line, Message: p.Message})
	}
	out = append(out, checkGrants(e)...)
	out = append(out, checkDefaults(f)...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].ID < out[j].ID
	})
	return dedupe(out)
}

func dedupe(fs []Finding) []Finding {
	seen := map[string]bool{}
	var out []Finding
	for _, f := range fs {
		k := f.File + "\x00" + strconv.Itoa(f.Line) + "\x00" + f.ID + "\x00" + f.Message
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}

func checkGrants(e *sudoers.Expanded) []Finding {
	var out []Finding
	// Rules that allow ALL but subtract commands: the subtraction is the finding.
	allWithDeny := map[*sudoers.Rule]bool{}
	hasAll := map[*sudoers.Rule]bool{}
	for _, g := range e.Grants {
		if g.Command.Path() == "ALL" && !g.Command.Negated {
			hasAll[g.Rule] = true
		}
	}
	for _, g := range e.Grants {
		if g.Command.Negated && hasAll[g.Rule] {
			allWithDeny[g.Rule] = true
		}
	}

	for _, g := range e.Grants {
		r, c := g.Rule, g.Command
		if onlyRoot(r.Users) {
			continue
		}
		who := strings.Join(r.Users, ",")
		find := func(id, sev, format string, args ...any) {
			msg := fmt.Sprintf(format, args...)
			if len(g.Via) > 0 {
				msg += " (through Cmnd_Alias " + strings.Join(g.Via, " > ") + ")"
			}
			out = append(out, Finding{ID: id, Severity: sev, File: r.File, Line: r.Line, Who: who, Message: msg})
		}
		asRoot, target := targetsRoot(c)
		p := c.Path()
		nopasswd := c.Tags["NOPASSWD"]

		if c.Negated {
			if allWithDeny[r] {
				find("SUDO005", "high", "ALL minus %s: a deny list does not hold, because the user can copy the program, rename it, or reach it through any other command", c.Text)
			}
			continue
		}
		if p == "ALL" {
			if allWithDeny[r] {
				continue // reported as SUDO005
			}
			if nopasswd && asRoot {
				find("SUDO001", "high", "%s may run any command as %s without a password: anyone with this account's session is root", who, target)
			} else if asRoot {
				find("SUDO001", "info", "%s may run any command as %s, with a password: a full administrator", who, target)
			}
			continue
		}
		if strings.ContainsAny(p, "*?[") {
			find("SUDO003", "high", "the command path %s is a wildcard: any program whose path matches can be run", p)
		}
		for _, dir := range writableDirs {
			if strings.HasPrefix(p, dir) {
				find("SUDO004", "high", "%s is under %s, where a user may be able to replace it", p, dir)
				break
			}
		}
		args, restricted := c.Args()
		wildArgs := restricted && strings.ContainsAny(args, "*?[")
		if wildArgs {
			find("SUDO003", "medium", "the arguments %q contain a wildcard, which also matches extra arguments and paths such as ../../etc/shadow", args)
		}
		if c.Tags["SETENV"] && p != "ALL" {
			find("SUDO011", "high", "SETENV on %s lets the user pass LD_PRELOAD and other variables that make it run their code", p)
		}
		if p == "sudoedit" {
			continue
		}
		esc, ok := escapeFor(p)
		if !ok {
			continue
		}
		severity := "high"
		if !asRoot {
			severity = "medium"
		}
		switch esc.class {
		case classArgs:
			if restricted && !wildArgs {
				continue // fixed arguments: the dangerous options cannot be added
			}
			how := "any arguments are allowed"
			if wildArgs {
				how = "its arguments contain a wildcard"
			}
			find("SUDO002", severity, "%s as %s: %s, and %s", p, target, esc.how, how)
		case classEscape:
			if pagerSafe(path.Base(p), args, restricted, wildArgs) {
				continue
			}
			if c.Tags["NOEXEC"] {
				find("SUDO002", "low", "%s as %s: %s; NOEXEC blocks this only for dynamically linked programs", p, target, esc.how)
				continue
			}
			find("SUDO002", severity, "%s as %s: %s", p, target, esc.how)
		default:
			find("SUDO002", severity, "%s as %s: %s, so this grant is a root shell", p, target, esc.how)
		}
	}
	return out
}

// systemctl pages only some subcommands; these do not open a pager.
var systemctlQuiet = map[string]bool{
	"start": true, "stop": true, "restart": true, "reload": true, "try-restart": true, "reload-or-restart": true,
	"try-reload-or-restart": true, "enable": true, "disable": true, "reenable": true, "daemon-reload": true,
	"is-active": true, "is-enabled": true, "is-failed": true, "kill": true, "reset-failed": true, "mask": true, "unmask": true,
}

// pagerSafe reports grants of programs that escape only through a pager, written with fixed
// arguments that keep the pager closed.
func pagerSafe(base, args string, restricted, wild bool) bool {
	if !restricted || wild {
		return false
	}
	fields := strings.Fields(args)
	for _, f := range fields {
		if f == "--no-pager" {
			return base == "systemctl" || base == "journalctl" || base == "git"
		}
	}
	if base == "systemctl" {
		for _, f := range fields {
			if !strings.HasPrefix(f, "-") {
				return systemctlQuiet[f]
			}
		}
	}
	return false
}

func checkDefaults(f *sudoers.File) []Finding {
	var out []Finding
	for _, d := range f.Defaults {
		find := func(id, sev, format string, args ...any) {
			scope := ""
			if d.Binding != "" {
				scope = " (for Defaults" + d.Binding + ")"
			}
			out = append(out, Finding{ID: id, Severity: sev, File: d.File, Line: d.Line, Message: fmt.Sprintf(format, args...) + scope})
		}
		switch {
		case d.Name == "env_reset" && d.Negated:
			find("SUDO010", "high", "!env_reset passes the user's whole environment, LD_PRELOAD included, to the command")
		case (d.Name == "env_keep" || d.Name == "env_check") && d.Op != "-=" && !d.Negated:
			for _, v := range strings.Fields(strings.ReplaceAll(d.Value, ",", " ")) {
				if dangerousEnv[strings.TrimSuffix(v, "*")] || strings.HasPrefix(v, "LD_") {
					find("SUDO010", "high", "%s keeps %s, which can make the command load or run the user's code", d.Name, v)
				}
			}
		case d.Name == "setenv" && !d.Negated:
			find("SUDO011", "high", "setenv lets users set any variable, LD_PRELOAD included, for every command")
		case d.Name == "authenticate" && d.Negated:
			find("SUDO012", "high", "!authenticate turns off the password for every rule it applies to")
		case d.Name == "visiblepw" && !d.Negated:
			find("SUDO012", "medium", "visiblepw lets sudo read the password where it is echoed, for example over a non-tty pipe")
		case d.Name == "exempt_group" && !d.Negated:
			find("SUDO012", "medium", "exempt_group %s: its members are not asked for a password", d.Value)
		case d.Name == "timestamp_timeout" && !d.Negated:
			if v, err := strconv.ParseFloat(d.Value, 64); err == nil && (v < 0 || v > 60) {
				find("SUDO013", "low", "timestamp_timeout %s: a password is remembered %s", d.Value,
					map[bool]string{true: "until reboot", false: "for over an hour"}[v < 0])
			}
		case d.Name == "use_pty" && d.Negated:
			find("SUDO013", "low", "!use_pty lets a command run with root's privileges keep the user's terminal, which allows input injection (TIOCSTI)")
		case (d.Name == "log_input" || d.Name == "log_output" || d.Name == "syslog" || d.Name == "logfile") && d.Negated:
			find("SUDO013", "low", "!%s turns off a record of what was run", d.Name)
		}
	}
	return out
}
