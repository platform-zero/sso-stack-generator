#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ROOT_DIR="${WEBSERVICES_OVERLAY_ROOT:-$SOURCE_ROOT}"
if [ "$ROOT_DIR" = "$SOURCE_ROOT" ] && [ ! -f "$ROOT_DIR/systemd-user/webservices-host-autoheal.service" ] && [ -f "$SOURCE_ROOT/dist/build/systemd-user/webservices-host-autoheal.service" ]; then
  ROOT_DIR="$SOURCE_ROOT/dist/build"
elif [ "$ROOT_DIR" = "$SOURCE_ROOT" ] && [ ! -d "$ROOT_DIR/quadlet" ] && [ -d "$SOURCE_ROOT/dist/build/quadlet" ]; then
  ROOT_DIR="$SOURCE_ROOT/dist/build"
fi

assert_absent() {
  local label="$1"
  shift
  if grep -RIn "$@" "$ROOT_DIR/runtime-model.yml" "$ROOT_DIR/runtime.overlays" "$ROOT_DIR/stack.config" "$ROOT_DIR/stack.systemd" "$ROOT_DIR/global.settings" "$ROOT_DIR/systemd-user" >/tmp/webservices-host-lifecycle-static.grep 2>/dev/null; then
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
  -e 'CONTAINER_SOCK:'
assert_absent "lifecycle socket proxy" \
  -e 'socket-lifecycle-proxy' \
  -e 'host-lifecycle'

if [ -d "$ROOT_DIR/quadlet" ]; then
  assert_absent "Podman bundle host lifecycle compatibility" \
    -e 'webservices-host-autoheal' \
    -e 'webservices-update-deploy' \
    -e 'socket-lifecycle-proxy'
else
  assert_file "systemd-user/webservices-host-autoheal.service"
  assert_file "systemd-user/webservices-host-autoheal.timer"
  assert_file "systemd-user/webservices-update-deploy.service"
  assert_file "systemd-user/webservices-update-deploy.timer"
  assert_contains "systemd-user/webservices-host-autoheal.timer" '^OnUnitActiveSec=1min$' "one-minute autoheal cadence"
  assert_contains "systemd-user/webservices-update-deploy.timer" '^OnCalendar=04:00$' "daily update schedule"
  assert_contains "systemd-user/webservices-update-deploy.timer" '^RandomizedDelaySec=30min$' "randomized update delay"
  assert_contains "systemd-user/webservices-update-deploy.timer" '^Persistent=true$' "persistent update timer"
fi

printf '[host-lifecycle-static-test] ok\n' >&2
