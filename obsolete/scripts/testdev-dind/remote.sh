#!/usr/bin/env bash
set -euo pipefail

REMOTE_HOST="${TESTDEV_REMOTE_HOST:-}"
REMOTE_DIR="${TESTDEV_REMOTE_DIR:-/tmp/sso-testdev-e2e}"

usage() {
  cat <<'EOF'
Usage:
  scripts/testdev/remote.sh up
  scripts/testdev/remote.sh verify [args...]
  scripts/testdev/remote.sh down
  scripts/testdev/remote.sh status

Environment:
  TESTDEV_REMOTE_HOST  SSH target. Required.
  TESTDEV_REMOTE_DIR   Remote testdev bundle dir. Default: /tmp/sso-testdev-e2e
EOF
}

[ "$#" -gt 0 ] || {
  usage >&2
  exit 2
}

[ -n "$REMOTE_HOST" ] || {
  printf 'TESTDEV_REMOTE_HOST is required for remote testdev commands\n' >&2
  exit 2
}

command_name="$1"
shift

remote_run() {
  local script_name="$1"
  shift
  local remote_command
  printf -v remote_command "cd %q && ./%q" "$REMOTE_DIR" "$script_name"
  local arg
  for arg in "$@"; do
    printf -v remote_command "%s %q" "$remote_command" "$arg"
  done
  ssh "$REMOTE_HOST" "$remote_command"
}

case "$command_name" in
  up)
    remote_run testdev-up.sh
    ;;
  verify)
    remote_run testdev-verify.sh "$@"
    ;;
  down)
    remote_run testdev-down.sh
    ;;
  status)
    ssh "$REMOTE_HOST" "test -d $(printf '%q' "$REMOTE_DIR") && echo 'bundle: $(printf '%q' "$REMOTE_DIR")' || echo 'bundle: missing $(printf '%q' "$REMOTE_DIR")'; docker ps --format '{{.Names}}\t{{.Status}}' | grep -E 'webservices_testdev|dind' || true"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    echo "unknown testdev remote command: $command_name" >&2
    usage >&2
    exit 2
    ;;
esac
