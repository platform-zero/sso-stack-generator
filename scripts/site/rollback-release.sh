#!/usr/bin/env bash
set -euo pipefail

# Rollback is intentionally an activation-only operation: it never rebuilds,
# pulls source, or consults a module repository.
ROOT="${WEBSERVICES_RELEASE_ROOT:-$HOME/webservices}"
current="$ROOT/current"
[ -L "$current" ] || { echo 'no active release to roll back' >&2; exit 1; }
active="$(basename "$(readlink "$current")")"
previous_file="$ROOT/releases/$active/previous-release"
[ -f "$previous_file" ] || { echo 'active release has no recorded predecessor' >&2; exit 1; }
previous="$(cat "$previous_file")"
case "$previous" in ''|/*|*'..'*) echo 'invalid recorded predecessor' >&2; exit 1;; esac
[ -f "$ROOT/releases/$previous/resolved-modules.json" ] && [ -f "$ROOT/releases/$previous/verified-release" ] || { echo 'preceding release is not verified' >&2; exit 1; }
ln -s "releases/$previous" "$ROOT/.current.next"; mv -Tf "$ROOT/.current.next" "$current"
echo "rolled back to $previous" >&2
