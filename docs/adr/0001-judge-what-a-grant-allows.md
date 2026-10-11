# 1. Judge what a grant allows, not what it names

Status: accepted

## Context

A sudoers rule reads like a narrow permission: "deploy may run less on the nginx logs".
What it actually allows depends on the program. `less` has a `!` command that runs a shell,
as root. `/var/log/nginx/*` matches `/var/log/nginx/../../../etc/shadow`, and extra
arguments too. `ALL, !/bin/bash` can be beaten by copying bash. A checker that only looks for
`NOPASSWD: ALL` misses all three, and they are the ones people write while believing they are
being careful.

## Decision

Every command a rule allows is expanded through its Cmnd_Alias chain, keeping the Runas list,
tags and options in force for it, and is judged on four questions:

1. **Can the program run a shell or other code?** Programs are sorted into four groups:
   shells, interpreters, programs with a built-in way to run a command (editors, pagers,
   database clients), and programs whose arguments can run a command or overwrite a file.
   The list draws on GTFOBins. For the last group, fixed arguments (`/usr/bin/tar -czf
   /backup/etc.tgz /etc`) are safe, because the dangerous option cannot be added. For pagers,
   fixed arguments that keep the pager closed (`systemctl restart nginx`, `journalctl
   --no-pager`) are safe. This matters most for `systemctl restart`, the commonest sudoers
   line there is.
2. **Do wildcards let in more than intended?** A wildcard in the path matches other
   programs; a wildcard in the arguments matches `..` and extra arguments.
3. **Can the user replace the program?** Paths under /home, /tmp, /var/tmp, /dev/shm and
   similar.
4. **Can the user change how it runs?** SETENV, `!env_reset`, and `env_keep` of LD_PRELOAD,
   PYTHONPATH and the like.

The target user matters: a shell as www-data is a medium finding, a shell as root is high.
Runas lists that may include root (ALL, an alias) are treated as root.

## Consequences

- `root ALL=(ALL:ALL) ALL` and `%sudo ALL=(ALL:ALL) ALL` are reported as what they are (an
  administrator, info) rather than as findings to fix.
- The program list is a list. A program missing from it is not judged, and a vendor's own
  tool that runs scripts from a writable directory is invisible to this check.
- The tool does not know who is in which group, so it cannot say which rule wins for a user
  matched by several. sudo applies the last matching rule.
