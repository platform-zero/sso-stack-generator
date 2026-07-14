#!/usr/bin/env bash
set -euo pipefail

UNIT_NAME="${1:-}"
if [ -z "$UNIT_NAME" ]; then
  echo "usage: systemd-diagnostics.sh <unit-name>" >&2
  exit 1
fi

if [ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/systemd-user.sh" ]; then
  # shellcheck source=scripts/lib/systemd-user.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/systemd-user.sh"
fi
if [ -f "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/common.sh" ]; then
  # shellcheck source=scripts/lib/common.sh
  source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"
fi

printf '[webservices-diagnostics] unit=%s\n' "$UNIT_NAME"
printf '[webservices-diagnostics] target status begin\n'
user_systemd_show_status webservices.target || true
printf '[webservices-diagnostics] target status end\n'
printf '[webservices-diagnostics] unit status begin\n'
user_systemd_show_status "$UNIT_NAME" || true
printf '[webservices-diagnostics] unit status end\n'
printf '[webservices-diagnostics] recent logs begin\n'
user_systemd_show_recent_logs "$UNIT_NAME" 200 || true
printf '[webservices-diagnostics] recent logs end\n'
printf '[webservices-diagnostics] container snapshot begin\n'
container_runtime ps -a --format '{{.Names}}\t{{.Status}}\t{{.Image}}' 2>&1 | sort || true
printf '[webservices-diagnostics] container snapshot end\n'
