#!/usr/bin/env bash
# Prints the README's example: the command, then what it prints. Run from anywhere.
set -u
cd "$(dirname "$0")/.."
bin=${SUDOWARDEN:-./bin/sudowarden}
echo "\$ sudowarden --root testdata/debian testdata/debian/etc/sudoers"
"$bin" --root testdata/debian testdata/debian/etc/sudoers | tr -d '\r'
