#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

case "${1:-}" in
  users) exec "$SCRIPT_DIR/lib/stackctl-users.sh" "${@:2}" ;;
  doctor|plan) exec python3 -B "$SCRIPT_DIR/lib/stackctl-host.py" "$@" ;;
  status) exec python3 -B "$SCRIPT_DIR/lib/stackctl-lifecycle.py" "$@" ;;
esac

printf 'Usage: stackctl {doctor | plan --bundle PATH | status --state-root PATH | users <command> [args...]}\n' >&2
exit 2
