#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

if [ "${1:-}" = "users" ]; then
  exec "$SCRIPT_DIR/lib/stackctl-users.sh" "${@:2}"
fi

printf 'Usage: stackctl users <command> [args...]\n' >&2
exit 2
