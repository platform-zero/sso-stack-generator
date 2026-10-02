#!/usr/bin/env bash
set -Eeuo pipefail

BUNDLE=""
STACK_LAB_ROOT="${P0_STACK_LAB_ROOT:-/mnt/lab_debian/stack_lab}"
SOPS_AGE_KEY_FILE=""
SOPS_BINARY=""

usage() { printf 'Usage: %s --bundle DIR [--sops-age-key-file FILE] [--sops-binary FILE]\n' "${0##*/}" >&2; }
while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2 ;;
    --sops-age-key-file) SOPS_AGE_KEY_FILE="$2"; shift 2 ;;
    --sops-binary) SOPS_BINARY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { printf 'control-plane installation requires root\n' >&2; exit 1; }
[ -f "$BUNDLE/podman-domains.json" ] || { printf 'missing podman-domains.json\n' >&2; exit 1; }
for command in install jq systemctl udevadm; do command -v "$command" >/dev/null; done
id stack_lab >/dev/null 2>&1 || { printf 'stack_lab account does not exist\n' >&2; exit 1; }
[ -z "$SOPS_AGE_KEY_FILE" ] || [ -f "$SOPS_AGE_KEY_FILE" ] || { printf 'SOPS age key file does not exist\n' >&2; exit 1; }
[ -z "$SOPS_BINARY" ] || [ -x "$SOPS_BINARY" ] || { printf 'SOPS binary is not executable\n' >&2; exit 1; }

install -d -m 0755 /usr/local/libexec /etc/platform-zero /etc/systemd/user
install -d -m 0750 -o root -g stack_lab /run/platform-zero
install -d -m 0700 -o root -g root /var/lib/platform-zero/incoming /mnt/stack/platform-zero-snapshots
install -m 0755 "$BUNDLE/ops/p0-host-broker.py" /usr/local/libexec/p0-host-broker
install -m 0755 "$BUNDLE/ops/p0-hostctl.py" /usr/local/bin/p0-hostctl
install -m 0755 "$BUNDLE/ops/start-worklane-containers.py" /usr/local/libexec/p0-start-worklanes
install -m 0755 "$BUNDLE/ops/reap-idle-worklanes.py" /usr/local/libexec/p0-reap-idle-worklanes
install -m 0644 "$BUNDLE/ops/platform-zero-worklanes.service" /etc/systemd/user/platform-zero-worklanes.service
install -m 0644 "$BUNDLE/ops/platform-zero-worklane-idle-reaper.service" /etc/systemd/user/platform-zero-worklane-idle-reaper.service
install -m 0644 "$BUNDLE/ops/platform-zero-worklane-idle-reaper.timer" /etc/systemd/user/platform-zero-worklane-idle-reaper.timer
install -m 0644 "$BUNDLE/ops/platform-zero-host-broker.service" /etc/systemd/system/
install -m 0644 "$BUNDLE/ops/platform-zero-host-broker.socket" /etc/systemd/system/
install -m 0644 "$BUNDLE/podman-domains.json" /etc/platform-zero/podman-domains.json
kvm_user="$(jq -r '.domains[] | select(any(.hostCapabilities[]?; . == "kvm")) | .user' "$BUNDLE/podman-domains.json" | head -n 1)"
if [ -n "$kvm_user" ]; then
  id "$kvm_user" >/dev/null 2>&1 || { printf 'missing KVM domain account: %s\n' "$kvm_user" >&2; exit 1; }
  printf 'KERNEL=="kvm", OWNER="%s", GROUP="kvm", MODE="0660"\n' "$kvm_user" \
    >/etc/udev/rules.d/70-platform-zero-kvm.rules
  udevadm control --reload-rules
  if [ -e /dev/kvm ]; then
    chown "$kvm_user:kvm" /dev/kvm
    chmod 0660 /dev/kvm
  fi
fi
if [ -n "$SOPS_AGE_KEY_FILE" ]; then
  install -d -m 0700 /root/.config/sops/age
  install -m 0600 "$SOPS_AGE_KEY_FILE" /root/.config/sops/age/keys.txt
fi
if [ -n "$SOPS_BINARY" ]; then
  install -m 0755 "$SOPS_BINARY" /usr/local/bin/sops
fi
command -v sops >/dev/null || { printf 'sops must be installed in the root service PATH\n' >&2; exit 1; }

# Service accounts keep their own shells, homes, Podman stores, and sockets.
# Operational access is brokered through the stack lane's peer-credentialed
# Unix socket; no per-domain dispatcher keys are created during cutover.

install_workspace_lifecycle() {
  local manifest="$1" owner home uid config wants timer_wants
  [ -f "$manifest" ] || return 0
  owner="$(jq -r '.owner' "$manifest")"
  id "$owner" >/dev/null 2>&1 || { printf 'missing workspace owner account: %s\n' "$owner" >&2; exit 1; }
  home="$(getent passwd "$owner" | cut -d: -f6)"
  config="$home/.config/platform-zero"
  install -d -m 0700 -o "$owner" -g "$owner" "$home/.config" "$config"
  install -m 0600 -o "$owner" -g "$owner" "$manifest" "$config/workspaces.json"
  wants="$home/.config/systemd/user/default.target.wants"
  timer_wants="$home/.config/systemd/user/timers.target.wants"
  install -d -m 0700 -o "$owner" -g "$owner" "$home/.config/systemd" "$home/.config/systemd/user" "$wants" "$timer_wants"
  if [ -e "$wants/platform-zero-worklanes.service" ] || [ -L "$wants/platform-zero-worklanes.service" ]; then
    [ "$(readlink "$wants/platform-zero-worklanes.service")" = /etc/systemd/user/platform-zero-worklanes.service ] || {
      printf 'refusing to replace locally changed %s\n' "$wants/platform-zero-worklanes.service" >&2
      exit 1
    }
    rm -f "$wants/platform-zero-worklanes.service"
  fi
  ln -sfn /etc/systemd/user/platform-zero-worklane-idle-reaper.timer "$timer_wants/platform-zero-worklane-idle-reaper.timer"
  chown -h "$owner:$owner" "$timer_wants/platform-zero-worklane-idle-reaper.timer"
  loginctl enable-linger "$owner"
  uid="$(id -u "$owner")"
  runuser -u "$owner" -- env HOME="$home" XDG_RUNTIME_DIR="/run/user/$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
    systemctl --user daemon-reload
  runuser -u "$owner" -- env HOME="$home" XDG_RUNTIME_DIR="/run/user/$uid" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/$uid/bus" \
    systemctl --user enable --now platform-zero-worklane-idle-reaper.timer
}

install_workspace_lifecycle "$BUNDLE/maintenance-workspaces.json"
install_workspace_lifecycle "$BUNDLE/software-workspaces.json"

systemctl daemon-reload
systemctl enable --now platform-zero-host-broker.socket
printf '[platform-zero] restricted control plane installed; Gerald sudo remains unchanged\n'
