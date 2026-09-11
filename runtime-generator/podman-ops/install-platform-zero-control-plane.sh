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
for command in install jq ssh-keygen systemctl; do command -v "$command" >/dev/null; done
id stack_lab >/dev/null 2>&1 || { printf 'stack_lab account does not exist\n' >&2; exit 1; }
[ -z "$SOPS_AGE_KEY_FILE" ] || [ -f "$SOPS_AGE_KEY_FILE" ] || { printf 'SOPS age key file does not exist\n' >&2; exit 1; }
[ -z "$SOPS_BINARY" ] || [ -x "$SOPS_BINARY" ] || { printf 'SOPS binary is not executable\n' >&2; exit 1; }

install -d -m 0755 /usr/local/libexec /etc/platform-zero /etc/systemd/user
install -d -m 0750 -o root -g stack_lab /run/platform-zero
install -d -m 0700 -o root -g root /var/lib/platform-zero/incoming /mnt/stack/platform-zero-snapshots
install -m 0755 "$BUNDLE/ops/p0-host-broker.py" /usr/local/libexec/p0-host-broker
install -m 0755 "$BUNDLE/ops/p0-hostctl.py" /usr/local/bin/p0-hostctl
install -m 0755 "$BUNDLE/ops/p0-domain-dispatch" /usr/local/libexec/p0-domain-dispatch
install -m 0755 "$BUNDLE/ops/start-worklane-containers.py" /usr/local/libexec/p0-start-worklanes
install -m 0755 "$BUNDLE/ops/reap-idle-worklanes.py" /usr/local/libexec/p0-reap-idle-worklanes
install -m 0644 "$BUNDLE/ops/platform-zero-worklanes.service" /etc/systemd/user/platform-zero-worklanes.service
install -m 0644 "$BUNDLE/ops/platform-zero-worklane-idle-reaper.service" /etc/systemd/user/platform-zero-worklane-idle-reaper.service
install -m 0644 "$BUNDLE/ops/platform-zero-worklane-idle-reaper.timer" /etc/systemd/user/platform-zero-worklane-idle-reaper.timer
install -m 0644 "$BUNDLE/ops/platform-zero-host-broker.service" /etc/systemd/system/
install -m 0644 "$BUNDLE/ops/platform-zero-host-broker.socket" /etc/systemd/system/
install -m 0644 "$BUNDLE/podman-domains.json" /etc/platform-zero/podman-domains.json
if [ -n "$SOPS_AGE_KEY_FILE" ]; then
  install -d -m 0700 /root/.config/sops/age
  install -m 0600 "$SOPS_AGE_KEY_FILE" /root/.config/sops/age/keys.txt
fi
if [ -n "$SOPS_BINARY" ]; then
  install -m 0755 "$SOPS_BINARY" /usr/local/bin/sops
fi
command -v sops >/dev/null || { printf 'sops must be installed in the root service PATH\n' >&2; exit 1; }

while IFS="$(printf '\t')" read -r domain user; do
  id "$user" >/dev/null 2>&1 || { printf 'missing domain account: %s\n' "$user" >&2; exit 1; }
  key_dir="$STACK_LAB_ROOT/stack_work/$domain/.p0"
  private_key="$key_dir/dispatcher_ed25519"
  install -d -m 0700 -o stack_lab -g stack_lab "$key_dir"
  if [ ! -f "$private_key" ]; then
    runuser -u stack_lab -- ssh-keygen -q -t ed25519 -N '' -C "p0-$domain" -f "$private_key"
  fi
  chmod 0600 "$private_key"
  chown stack_lab:stack_lab "$private_key" "$private_key.pub"
  home="$(getent passwd "$user" | cut -d: -f6)"
  install -d -m 0700 -o "$user" -g "$user" "$home/.ssh"
  authorized="$home/.ssh/authorized_keys"
  touch "$authorized"
  sed -i "/ p0-${domain}$/d" "$authorized"
  printf 'restrict,command="/usr/local/libexec/p0-domain-dispatch %s" %s p0-%s\n' \
    "$domain" "$(cut -d' ' -f1,2 "$private_key.pub")" "$domain" >>"$authorized"
  chown "$user:$user" "$authorized"
  chmod 0600 "$authorized"
done < <(jq -r '.domains[] | [.name, .user] | @tsv' "$BUNDLE/podman-domains.json")

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
