#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${WEBSERVICES_CONTRACT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"

assert_absent() {
  local label="$1"
  shift
  if grep -RIn "$@" "$ROOT_DIR/docker-compose.yml" "$ROOT_DIR/stack.compose" "$ROOT_DIR/stack.config" "$ROOT_DIR/stack.systemd" "$ROOT_DIR/global.settings" "$ROOT_DIR/systemd-user" >/tmp/webservices-host-lifecycle-static.grep 2>/dev/null; then
    printf '[host-lifecycle-static-test] unexpected %s\n' "$label" >&2
    cat /tmp/webservices-host-lifecycle-static.grep >&2
    rm -f /tmp/webservices-host-lifecycle-static.grep
    exit 1
  fi
  rm -f /tmp/webservices-host-lifecycle-static.grep
}

assert_file() {
  local file="$1"
  [ -f "$ROOT_DIR/$file" ] || {
    printf '[host-lifecycle-static-test] missing %s\n' "$file" >&2
    exit 1
  }
}

assert_contains() {
  local file="$1" pattern="$2" label="$3"
  if ! grep -Eq "$pattern" "$ROOT_DIR/$file"; then
    printf '[host-lifecycle-static-test] missing %s in %s\n' "$label" "$file" >&2
    exit 1
  fi
}

assert_absent "watchtower container/update automation" \
  -e 'watchtower' \
  -e 'containrrr/watchtower' \
  -e 'centurylinklabs.watchtower'
assert_absent "containerized autoheal implementation" \
  -e 'willfarrell/autoheal' \
  -e 'AUTOHEAL_CONTAINER_LABEL' \
  -e 'DOCKER_SOCK:'
assert_absent "lifecycle Docker socket proxy" \
  -e 'docker-socket-lifecycle-proxy' \
  -e 'docker-host-lifecycle'

assert_file "systemd-user/webservices-host-autoheal.service"
assert_file "systemd-user/webservices-host-autoheal.timer"
assert_file "systemd-user/webservices-update-deploy.service"
assert_file "systemd-user/webservices-update-deploy.timer"
assert_contains "systemd-user/webservices-host-autoheal.timer" '^OnUnitActiveSec=1min$' "one-minute autoheal cadence"
assert_contains "systemd-user/webservices-update-deploy.timer" '^OnCalendar=04:00$' "daily update schedule"
assert_contains "systemd-user/webservices-update-deploy.timer" '^RandomizedDelaySec=30min$' "randomized update delay"
assert_contains "systemd-user/webservices-update-deploy.timer" '^Persistent=true$' "persistent update timer"

printf '[host-lifecycle-static-test] ok\n' >&2
