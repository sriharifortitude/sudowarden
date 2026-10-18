# sudowarden

[![CI](https://github.com/sriharifortitude/sudowarden/actions/workflows/ci.yml/badge.svg)](https://github.com/sriharifortitude/sudowarden/actions/workflows/ci.yml)

Finds the sudoers rules that give more than they seem to: a "read the logs" grant that is a
root shell, a wildcard that reaches `/etc/shadow`, a deny list that does not hold, an
environment variable that runs the user's code, and the syntax error that would lock every
administrator out. Go, standard library only, MIT.

## What it is for

Narrow sudo grants are written by careful people, which is why their mistakes survive review.
`less` has a `!` command. `journalctl` and `systemctl status` open `less`. `rsync -e` runs
a command. `/var/log/nginx/*` matches `/var/log/nginx/../../../etc/shadow`. `ALL,
!/bin/bash` stops nobody who can type `cp /bin/bash /tmp/x`. Here is a layout like a Debian
server's, with an operations team's file in /etc/sudoers.d:

<!-- demo:start -->
```
$ sudowarden --root testdata/debian testdata/debian/etc/sudoers
testdata/debian/etc/sudoers:13  SUDO001 info     %sudo may run any command as ALL, with a password: a full administrator [%sudo]
testdata/debian/etc/sudoers.d/ops:5  SUDO002 high     /usr/bin/less as root: '!sh' at its prompt runs a shell (through Cmnd_Alias LOGS) [deploy]
testdata/debian/etc/sudoers.d/ops:5  SUDO002 high     /usr/bin/journalctl as root: it shows output in less, where '!sh' runs a shell (unless --no-pager) (through Cmnd_Alias LOGS) [deploy]
testdata/debian/etc/sudoers.d/ops:5  SUDO003 medium   the arguments "/var/log/nginx/*" contain a wildcard, which also matches extra arguments and paths such as ../../etc/shadow (through Cmnd_Alias LOGS) [deploy]
testdata/debian/etc/sudoers.d/ops:6  SUDO002 medium   /usr/bin/git as www-data: it runs hooks, core.pager and other commands named in the repository's configuration, and pages output through less [deploy]
testdata/debian/etc/sudoers.d/ops:7  SUDO002 high     /usr/bin/rsync as root: -e runs any command, and any arguments are allowed [backup]
testdata/debian/etc/sudoers.d/ops:8  SUDO004 high     /home/monitor/bin/check_disk is under /home/, where a user may be able to replace it [monitor]
testdata/debian/etc/sudoers.d/ops:9  SUDO005 high     ALL minus /usr/bin/su: a deny list does not hold, because the user can copy the program, rename it, or reach it through any other command [helpdesk]
testdata/debian/etc/sudoers.d/ops:9  SUDO005 high     ALL minus /bin/bash: a deny list does not hold, because the user can copy the program, rename it, or reach it through any other command [helpdesk]
testdata/debian/etc/sudoers.d/ops:10  SUDO010 high     env_keep keeps PYTHONPATH, which can make the command load or run the user's code (for Defaults:deploy)
2 file(s) read, 7 rule(s); 7 high, 2 medium, 1 info
```
<!-- demo:end -->

`systemctl restart nginx` and `systemctl reload nginx` (line 2 of that file, used through
`WEB`) are not reported: they open no pager, so they cannot become a shell. The root and
`%sudo` lines are administrators by design and are noted as such. `README.dpkg-dist` in
sudoers.d is skipped, as sudo skips any name containing a dot.

## Usage

```bash
go install github.com/sriharifortitude/sudowarden/cmd/sudowarden@v0.1.0

sudo sudowarden /etc/sudoers                             # follows @include and @includedir
sudowarden --root /mnt/image /mnt/image/etc/sudoers      # a copy of another machine's /etc
sudowarden generated.sudoers --fail-on medium            # in CI, before deployment
```

Exit codes: 0 nothing at or above `--fail-on` (default high), 1 at least one finding is,
2 a usage error or an unreadable file. `--json` gives the files read and the findings, each
with the rule's user list.

## Checks

| ID | Severity | What it finds |
|---|---|---|
| SUDO001 | high / info | `NOPASSWD: ALL` as root (high); `ALL` with a password (info: an administrator) |
| SUDO002 | high / medium / low | a program that gives a shell: a shell or interpreter; an editor, pager or client with a command escape (`vi`, `less`, `man`, `journalctl`, `systemctl status`, `git`, `mysql`, ...); a program whose arguments run commands or overwrite files (`find`, `tar`, `rsync`, `cp`, `tee`, `apt-get`, `docker`, ...) when its arguments are open or wildcarded. High as root, medium as another user, low when NOEXEC blocks an escape |
| SUDO003 | high / medium | a wildcard in the command path, or in its arguments |
| SUDO004 | high | a command under /home, /tmp, /var/tmp, /dev/shm or another place a user may write |
| SUDO005 | high | `ALL` minus a deny list |
| SUDO010 | high | `!env_reset`, or `env_keep` of LD_PRELOAD, LD_*, PYTHONPATH, PERL5LIB, BASH_ENV and similar |
| SUDO011 | high | SETENV on a command, or `Defaults setenv` |
| SUDO012 | high / medium | `!authenticate`; `visiblepw`; `exempt_group` |
| SUDO013 | low | `timestamp_timeout` negative or over an hour; `!use_pty`; logging turned off |
| SUDO030 | high | a line sudo cannot parse: sudo refuses to run for anyone until it is fixed |
| SUDO031 | info / medium | an unused alias, a missing `@includedir`, an include using `%h`; an alias used but never defined, or one that refers to itself (medium: visudo accepts the file with a warning) |

Every finding names the file, line and user list, and the Cmnd_Alias chain the command came
through. [ADR 1](docs/adr/0001-judge-what-a-grant-allows.md) explains how programs are judged
and where the line between a safe and an unsafe grant is drawn.

## How it reads sudoers

Continuation lines, `#` as a comment or a uid (`#1000`) or an old-style `#include`, quoted
Defaults values, escaped `\,` `\:` `\=` in commands, several aliases on one line, several
`hosts = commands` segments on one rule, Runas lists and tags that carry over to the next
command in a list (and reset at each segment), tags written without a space, options (CWD,
CHROOT, TIMEOUT, ...) and digests. `@include` paths are relative to the including file, as
since sudo 1.9.1; `@includedir` reads files in sorted order and skips names containing a dot
or ending in `~`. A negated Cmnd_Alias negates every member.

## Tested

```bash
go test ./...                       # 35 tests and a fuzz target
./scripts/differential.sh           # against the real visudo; needs sudo
```

**Against visudo.** `scripts/differential.sh` runs `visudo -c` on the Debian layout and on
the files in `testdata/syntax/`: one with every form the parser handles, one that visudo only
warns about, and the rest each broken in one way. visudo must reject a file exactly when
sudowarden reports SUDO030. There is no sudo on the Windows machine this was built on, so it
runs in CI, against visudo 1.9.15, and all twelve fixtures now agree with it. Getting there
took two corrections. First, an alias that is used but never defined does not make visudo
fail: it prints "referenced but not defined" and accepts the file. Second, after that run I
added two fixtures for the remaining alias claims, and the next run showed visudo treats an
alias cycle the same way: it warns and accepts. A duplicate alias, on the other hand, is
rejected, as predicted. Both the undefined alias and the cycle are now medium findings, not
fatal ones. The first run also found a bug in the script itself: under `set -o pipefail`,
sudowarden's exit status decided the prediction instead of its findings, so every file was
predicted to pass.

**Mutation testing.** I broke the code in 52 places on purpose. On the first
run, 9 mutants survived and 2 did not compile.
The survivors were gaps in the tests, not in the code. A `#` inside a quoted Defaults value
was never tested, nor were commas inside a Runas list or Runas groups. Neither were
`systemctl` with wildcard arguments, `man --no-pager` (which still pages), or an `LD_*`
variable outside the named list. Two more passed for a weaker reason. A Runas list of ALL
reached root only through a fallback meant for aliases, which gives a vaguer message. And
the rule that version suffixes (`python3.12`) count only for interpreters had no test with a
program like `cp2`. The include-cycle test passed through the nesting limit instead of the
cycle check, which happens to give the same verdict. Each now has a test, and every mutant
is caught.

**Not tested:** against visudo (above); real sudoers files from production systems (the
Debian fixture is laid out like Debian 12's file from memory, with an invented sudoers.d
file); sudo's LDAP and SSSD sources, which are not files; `%h` in include paths.

## Limits

- **No group membership.** sudo applies the last rule that matches a user. Without knowing
  who is in which group, this tool cannot say which of several matching rules wins.
- **A list of programs.** A program missing from the list is not judged. A vendor tool that
  runs plugins or scripts from a writable place will not be reported.
- **No file permissions.** It does not check that sudoers files are owned by root and mode
  0440, or that the commands they name are not writable; it sees the text only.
- **Hosts are not evaluated.** Every rule is judged as if it applied on this host.

## Licence

MIT.
