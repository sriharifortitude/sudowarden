#!/usr/bin/env bash
# Checks sudowarden's syntax verdict against the real visudo: for every fixture, visudo -c must
# reject the file exactly when sudowarden reports SUDO030 (a line sudo cannot parse). Needs
# sudo's visudo and sudo itself; CI has both.
set -euo pipefail
cd "$(dirname "$0")/.."
BIN=${SUDOWARDEN:-./bin/sudowarden}
VISUDO=${VISUDO:-$(command -v visudo || echo /usr/sbin/visudo)}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
sudo "$VISUDO" -V | head -1

# visudo resolves the Debian fixture's absolute @includedir against the real /etc; point it at the copy.
sed "s|^@includedir /etc/sudoers.d|@includedir $PWD/testdata/debian/etc/sudoers.d|" testdata/debian/etc/sudoers > "$tmp/debian"

status=0
check() { # display name, file
  local name=$1 file=$2 predicted actual
  predicted=accept
  # sudowarden exits 1 when it has findings; under pipefail that must not decide the prediction.
  "$BIN" --json "$file" > "$tmp/findings.json" || true
  if python3 -c 'import json,sys; sys.exit(0 if any(f["id"] == "SUDO030" for f in json.load(open(sys.argv[1]))["findings"]) else 1)' "$tmp/findings.json"; then
    predicted=reject
  fi
  if sudo "$VISUDO" -c -f "$file" > "$tmp/out.txt" 2>&1; then actual=accept; else actual=reject; fi
  printf '%-40s sudowarden: %-6s  visudo: %-6s  %s\n' "$name" "$predicted" "$actual" "$(grep -v 'parsed OK' "$tmp/out.txt" | head -1)"
  [ "$predicted" = "$actual" ] || status=1
}

check debian/etc/sudoers "$tmp/debian"
for f in testdata/syntax/*.sudoers; do
  check "$f" "$f"
done
exit $status
