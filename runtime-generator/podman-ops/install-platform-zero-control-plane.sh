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
for command in install jq ssh-keygen systemctl useradd usermod getent; do command -v "$command" >/dev/null; done
[[ "$STACK_LAB_ROOT" == /* && "$STACK_LAB_ROOT" != / && ! -L "$STACK_LAB_ROOT" ]] || {
  printf 'unsafe maintenance account home\n' >&2; exit 1;
}
# Inspect site-specific KVM and SOPS gates before creating any host account.
# A refusal must not leave a half-adopted maintenance identity behind.
[ -z "$SOPS_AGE_KEY_FILE" ] || [ -f "$SOPS_AGE_KEY_FILE" ] || { printf 'SOPS age key file does not exist\n' >&2; exit 1; }
[ -z "$SOPS_BINARY" ] || [ -x "$SOPS_BINARY" ] || { printf 'SOPS binary is not executable\n' >&2; exit 1; }
kvm_user="$(jq -r '.domains[] | select(any(.hostCapabilities[]?; . == "kvm")) | .user' "$BUNDLE/podman-domains.json" | head -n 1)"
if [ -n "$kvm_user" ]; then
  [ ! -e /etc/udev/rules.d/70-platform-zero-kvm.rules ] &&
    [ ! -L /etc/udev/rules.d/70-platform-zero-kvm.rules ] || {
      printf 'existing KVM ownership rule requires separate review; install refused\n' >&2; exit 1;
    }
  id "$kvm_user" >/dev/null 2>&1 || { printf 'missing KVM domain account: %s\n' "$kvm_user" >&2; exit 1; }
  kvm_mode="$(stat -c %a /dev/kvm 2>/dev/null)" || { printf 'KVM device unavailable\n' >&2; exit 1; }
  [ -c /dev/kvm ] && [ "$(stat -c %G /dev/kvm)" = kvm ] &&
    [ $(( 8#$kvm_mode & 060 )) -eq $(( 060 )) ] && [ $(( 8#$kvm_mode & 007 )) -eq 0 ] || {
      printf 'existing KVM group/device permissions must be preserved; install refused\n' >&2; exit 1;
    }
fi

if ! id stack_lab >/dev/null 2>&1; then
  [ ! -e "$STACK_LAB_ROOT" ] || { printf 'unowned maintenance account home cannot be adopted\n' >&2; exit 1; }
  useradd --user-group --create-home --home-dir "$STACK_LAB_ROOT" --shell /usr/sbin/nologin stack_lab
fi
account_home="$(getent passwd stack_lab | cut -d: -f6)"
[ "$account_home" = "$STACK_LAB_ROOT" ] && [ "$(id -u stack_lab)" != 0 ] &&
  [ "$(getent passwd stack_lab | cut -d: -f7)" = /usr/sbin/nologin ] || {
    printf 'maintenance account identity mismatch\n' >&2; exit 1;
  }
for range_file in /etc/subuid /etc/subgid; do
  awk -F: '$1 == "stack_lab" && $2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/ && $3 > 0 { n++ } END { exit (n == 1 ? 0 : 1) }' "$range_file" || {
    printf 'maintenance account requires one valid subordinate range\n' >&2; exit 1;
  }
done

# First adoption must not overwrite pre-existing authored units, executables,
# keys or recovery directories. An upgrade needs a separate exact-CAS review.
refuse_unmanaged_target() {
  local source="$1" target="$2"
  if [ -e "$target" ] || [ -L "$target" ]; then
    [ -f "$target" ] && [ ! -L "$target" ] &&
      [ "$(stat -c %u "$target")" = 0 ] &&
      [ $(( 8#$(stat -c %a "$target") & 022 )) -eq 0 ] &&
      cmp -s "$source" "$target" || {
        printf 'existing control target differs; exact-CAS upgrade required\n' >&2; exit 1;
      }
  fi
}
while read -r member target; do
  refuse_unmanaged_target "$BUNDLE/$member" "$target"
done <<'TARGETS'
ops/p0-host-broker.py /usr/local/libexec/p0-host-broker
ops/p0-host-install-inputs.py /usr/local/libexec/p0-host-install-inputs.py
ops/p0-host-operations.py /usr/local/libexec/p0-host-operations.py
ops/verify-agent-vm-bundle.py /usr/local/libexec/p0-verify-agent-vm-bundle
ops/p0-hostctl.py /usr/local/bin/p0-hostctl
ops/p0-host-approve.py /usr/local/sbin/p0-host-approve
ops/p0-domain-dispatch /usr/local/libexec/p0-domain-dispatch
ops/install-domain-dispatch-key.py /usr/local/libexec/p0-install-domain-dispatch-key
ops/start-worklane-containers.py /usr/local/libexec/p0-start-worklanes
ops/reap-idle-worklanes.py /usr/local/libexec/p0-reap-idle-worklanes
ops/platform-zero-worklanes.service /etc/systemd/user/platform-zero-worklanes.service
ops/platform-zero-worklane-idle-reaper.service /etc/systemd/user/platform-zero-worklane-idle-reaper.service
ops/platform-zero-worklane-idle-reaper.timer /etc/systemd/user/platform-zero-worklane-idle-reaper.timer
ops/platform-zero-host-broker.service /etc/systemd/system/platform-zero-host-broker.service
ops/platform-zero-host-broker.socket /etc/systemd/system/platform-zero-host-broker.socket
podman-domains.json /etc/platform-zero/podman-domains.json
TARGETS
for managed in /var/lib/platform-zero/incoming /mnt/stack/platform-zero-snapshots; do
  if [ -e "$managed" ] || [ -L "$managed" ]; then
    [ -d "$managed" ] && [ ! -L "$managed" ] &&
      [ "$(stat -c %u:%g:%a "$managed")" = 0:0:700 ] || {
        printf 'existing recovery directory requires separate review\n' >&2; exit 1;
      }
  fi
done
if [ -e /run/platform-zero ] || [ -L /run/platform-zero ]; then
  [ -d /run/platform-zero ] && [ ! -L /run/platform-zero ] &&
    [ "$(stat -c %u:%g:%a /run/platform-zero)" = "0:$(getent group stack_lab | cut -d: -f3):750" ] || {
      printf 'existing broker socket directory requires separate review\n' >&2; exit 1;
    }
fi
[ -z "$SOPS_AGE_KEY_FILE" ] || refuse_unmanaged_target "$SOPS_AGE_KEY_FILE" /root/.config/sops/age/keys.txt
[ -z "$SOPS_BINARY" ] || refuse_unmanaged_target "$SOPS_BINARY" /usr/local/bin/sops

install -d -m 0755 /usr/local/libexec /etc/platform-zero /etc/systemd/user
install -d -m 0750 -o root -g stack_lab /run/platform-zero
install -d -m 0700 -o root -g root /var/lib/platform-zero/incoming /mnt/stack/platform-zero-snapshots
install -m 0755 "$BUNDLE/ops/p0-host-broker.py" /usr/local/libexec/p0-host-broker
install -m 0750 "$BUNDLE/ops/p0-host-install-inputs.py" /usr/local/libexec/p0-host-install-inputs.py
install -m 0750 "$BUNDLE/ops/p0-host-operations.py" /usr/local/libexec/p0-host-operations.py
install -m 0755 "$BUNDLE/ops/verify-agent-vm-bundle.py" /usr/local/libexec/p0-verify-agent-vm-bundle
install -m 0755 "$BUNDLE/ops/p0-hostctl.py" /usr/local/bin/p0-hostctl
install -m 0750 "$BUNDLE/ops/p0-host-approve.py" /usr/local/sbin/p0-host-approve
install -m 0755 "$BUNDLE/ops/p0-domain-dispatch" /usr/local/libexec/p0-domain-dispatch
install -m 0755 "$BUNDLE/ops/install-domain-dispatch-key.py" /usr/local/libexec/p0-install-domain-dispatch-key
install -m 0755 "$BUNDLE/ops/start-worklane-containers.py" /usr/local/libexec/p0-start-worklanes
install -m 0755 "$BUNDLE/ops/reap-idle-worklanes.py" /usr/local/libexec/p0-reap-idle-worklanes
install -m 0644 "$BUNDLE/ops/platform-zero-worklanes.service" /etc/systemd/user/platform-zero-worklanes.service
install -m 0644 "$BUNDLE/ops/platform-zero-worklane-idle-reaper.service" /etc/systemd/user/platform-zero-worklane-idle-reaper.service
install -m 0644 "$BUNDLE/ops/platform-zero-worklane-idle-reaper.timer" /etc/systemd/user/platform-zero-worklane-idle-reaper.timer
install -m 0644 "$BUNDLE/ops/platform-zero-host-broker.service" /etc/systemd/system/
install -m 0644 "$BUNDLE/ops/platform-zero-host-broker.socket" /etc/systemd/system/
install -m 0644 "$BUNDLE/podman-domains.json" /etc/platform-zero/podman-domains.json
if [ -n "$kvm_user" ]; then
  # Add only the selected workload user to the pre-existing KVM group. Never
  # reown /dev/kvm, change its mode, or replace an unrelated udev policy.
  id -nG "$kvm_user" | tr ' ' '\n' | grep -Fxq kvm || usermod -aG kvm "$kvm_user"
fi
if [ -n "$SOPS_AGE_KEY_FILE" ]; then
  install -d -m 0700 /root/.config/sops/age
  install -m 0600 "$SOPS_AGE_KEY_FILE" /root/.config/sops/age/keys.txt
fi
if [ -n "$SOPS_BINARY" ]; then
  install -m 0755 "$SOPS_BINARY" /usr/local/bin/sops
fi
command -v sops >/dev/null || { printf 'sops must be installed in the root service PATH\n' >&2; exit 1; }

while IFS="$(printf '\t')" read -r domain user maintenance_lane; do
  id "$user" >/dev/null 2>&1 || { printf 'missing domain account: %s\n' "$user" >&2; exit 1; }
  key_dir="$STACK_LAB_ROOT/stack_work/$maintenance_lane/.p0/$domain"
  private_key="$key_dir/dispatcher_ed25519"
  install -d -m 0700 -o stack_lab -g stack_lab \
    "$STACK_LAB_ROOT/stack_work/$maintenance_lane" \
    "$STACK_LAB_ROOT/stack_work/$maintenance_lane/.p0"
  install -d -m 0700 -o stack_lab -g stack_lab "$key_dir"
  if [ ! -f "$private_key" ]; then
    runuser -u stack_lab -- ssh-keygen -q -t ed25519 -N '' -C "p0-$domain" -f "$private_key"
  fi
  chmod 0600 "$private_key"
  chown stack_lab:stack_lab "$private_key" "$private_key.pub"
  python3 /usr/local/libexec/p0-install-domain-dispatch-key \
    --user "$user" --domain "$domain" --public-key-file "$private_key.pub"
done < <(jq -r '.domains[] | [.name, .user, (.maintenanceLane // .name)] | @tsv' "$BUNDLE/podman-domains.json")

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
  # Linger is asynchronous on a first-created account. Wait for the actual
  # logind-owned user manager and bus; never fabricate /run/user/UID.
  manager_ready=false
  for attempt in {1..60}; do
    if systemctl is-active --quiet "user@$uid.service" && [ -S "/run/user/$uid/bus" ]; then
      manager_ready=true
      break
    fi
    sleep 1
  done
  [ "$manager_ready" = true ] || { printf 'maintenance user manager did not become ready\n' >&2; exit 1; }
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
