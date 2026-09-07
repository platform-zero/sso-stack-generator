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

install -d -m 0755 /usr/local/libexec /etc/platform-zero
install -d -m 0750 -o root -g stack_lab /run/platform-zero
install -m 0755 "$BUNDLE/ops/p0-host-broker.py" /usr/local/libexec/p0-host-broker
install -m 0755 "$BUNDLE/ops/p0-hostctl.py" /usr/local/bin/p0-hostctl
install -m 0755 "$BUNDLE/ops/p0-domain-dispatch" /usr/local/libexec/p0-domain-dispatch
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

systemctl daemon-reload
systemctl enable --now platform-zero-host-broker.socket
printf '[platform-zero] restricted control plane installed; Gerald sudo remains unchanged\n'
