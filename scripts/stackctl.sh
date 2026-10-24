#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

case "${1:-}" in
  users) exec "$SCRIPT_DIR/lib/stackctl-users.sh" "${@:2}" ;;
  doctor|plan) exec python3 -B "$SCRIPT_DIR/lib/stackctl-host.py" "$@" ;;
  install|status) exec python3 -B "$SCRIPT_DIR/lib/stackctl-lifecycle.py" "$@" ;;
  start|stop|verify) exec python3 -B "$SCRIPT_DIR/lib/stackctl-operations.py" "$@" ;;
  backup|restore) exec python3 -B "$SCRIPT_DIR/lib/stackctl-recovery.py" "$@" ;;
esac

printf 'Usage: stackctl {doctor | plan --bundle PATH | install --bundle PATH [--activate] | status --state-root PATH | verify --state-root PATH | start|stop --state-root PATH <exact expected source hashes> | backup|restore --state-root PATH [--plan | <exact expected source hashes> <archive/key arguments>] | users <command> [args...]}\nUse stackctl <command> --help for the exact source-bound operation arguments.\n' >&2
exit 2
