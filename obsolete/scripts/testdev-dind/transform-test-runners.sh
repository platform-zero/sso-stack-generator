#!/usr/bin/env bash
set -euo pipefail

[ "$#" -eq 1 ] || {
  echo "usage: transform-test-runners.sh <test-runners.yml>" >&2
  exit 2
}

file="$1"
tmp="$(mktemp)"
sed \
  -e '/^[[:space:]]*container_name:[[:space:]]*test-runner[[:space:]]*$/d' \
  -e 's|^\([[:space:]]*context:[[:space:]]*\)\.\([[:space:]]*\)$|\1./build\2|' \
  "$file" > "$tmp"
mv "$tmp" "$file"
