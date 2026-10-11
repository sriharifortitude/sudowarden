# 2. A syntax error is an outage

Status: accepted

## Context

If any file sudo reads has a syntax error, sudo refuses to run, for everyone. On a server
without a root password this locks the administrators out. visudo checks the file it edits,
but files dropped into /etc/sudoers.d by configuration management are often never checked.

## Decision

The parser reports every line sudo could not parse as SUDO030, at high severity, with the
reason. That covers a command that is not a full path, a rule without `=`, an unclosed Runas
list, a missing command, a lower-case alias name, an alias used but never defined or defined
twice, an alias that refers to itself, a missing `@include` and an include cycle. Things sudo
tolerates (an unused alias, a missing `@includedir`) are info.

The parser is written from sudoers(5), and the list above is my reading of what sudo
rejects. `scripts/differential.sh` checks it against the real visudo: on every fixture,
visudo -c must fail exactly when sudowarden reports SUDO030. There is no visudo on the
machine this was written on, so the first run of that check is in CI.

## Consequences

- A CI job can run sudowarden on generated sudoers files before they are deployed, and
  catch the file that would lock everyone out.
- Where my reading of the grammar is wrong, the differential check is what will show it, and
  the README says so until it has run.
