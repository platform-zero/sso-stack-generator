#!/usr/bin/env bash
set -Eeuo pipefail

LEGACY_USER="webservices"
EXPECTED_UID="999"
CONFIRM=""

usage() {
  printf 'Usage: %s --confirm DELETE_LEGACY_WEBSERVICES [--expected-uid UID]\n' "${0##*/}" >&2
}
while [ "$#" -gt 0 ]; do
  case "$1" in
    --confirm) CONFIRM="$2"; shift 2 ;;
    --expected-uid) EXPECTED_UID="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { printf 'legacy retirement requires root\n' >&2; exit 1; }
[ "$CONFIRM" = DELETE_LEGACY_WEBSERVICES ] || { printf 'explicit deletion confirmation is required\n' >&2; exit 1; }
record="$(getent passwd "$LEGACY_USER" || true)"
[ -n "$record" ] || { printf 'legacy account is already absent\n'; exit 0; }
uid="$(printf '%s\n' "$record" | cut -d: -f3)"
home="$(printf '%s\n' "$record" | cut -d: -f6)"
[ "$uid" = "$EXPECTED_UID" ] || { printf 'refusing unexpected UID %s for %s\n' "$uid" "$LEGACY_USER" >&2; exit 1; }
[ "$home" = /home/webservices ] || { printf 'refusing unexpected home %s\n' "$home" >&2; exit 1; }

status="$(runuser -u stack_lab -- p0-hostctl status)"
printf '%s\n' "$status" | jq -e '
  .ok == true and .result.rootful == "active" and
  all(.result.domains[]; .state == "active")
' >/dev/null || { printf 'modular Platform Zero is not fully healthy\n' >&2; exit 1; }

runtime="/run/user/$uid"
if [ -S "$runtime/bus" ]; then
  runuser -u "$LEGACY_USER" -- env HOME="$home" XDG_RUNTIME_DIR="$runtime" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" systemctl --user stop webservices.target || true
  runuser -u "$LEGACY_USER" -- env HOME="$home" XDG_RUNTIME_DIR="$runtime" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime/bus" systemctl --user disable webservices.target || true
fi
loginctl disable-linger "$LEGACY_USER" || true
loginctl terminate-user "$LEGACY_USER" || true
for _ in {1..30}; do
  pgrep -u "$uid" >/dev/null || break
  sleep 1
done
if pgrep -u "$uid" >/dev/null; then
  printf 'legacy UID still owns processes\n' >&2
  ps -u "$uid" -o pid,cmd >&2
  exit 1
fi
if ss -H -lntupe 2>/dev/null | grep -Eq "uid:$uid([^0-9]|$)"; then
  printf 'legacy UID still owns listening sockets\n' >&2
  exit 1
fi

userdel -r "$LEGACY_USER"
getent group "$LEGACY_USER" >/dev/null && groupdel "$LEGACY_USER" || true
rm -rf -- /var/lib/webservices-rootless
sed -i "/^${LEGACY_USER}:/d" /etc/subuid /etc/subgid
rm -rf -- "$runtime"
getent passwd "$LEGACY_USER" >/dev/null && { printf 'legacy account deletion failed\n' >&2; exit 1; }
printf 'legacy webservices account and private rootless state removed\n'
