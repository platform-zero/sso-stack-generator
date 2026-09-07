#!/usr/bin/env bash
set -Eeuo pipefail

MODE=check
DOMAINS_FILE=""
AUTHORIZED_KEYS=""
MIGRATE_EXISTING=false

usage() {
  printf 'Usage: %s --domains FILE [--authorized-keys FILE] [--migrate-existing] [--check|--apply]\n' "${0##*/}" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --domains) DOMAINS_FILE="$2"; shift 2 ;;
    --authorized-keys) AUTHORIZED_KEYS="$2"; shift 2 ;;
    --migrate-existing) MIGRATE_EXISTING=true; shift ;;
    --check) MODE=check; shift ;;
    --apply) MODE=apply; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

[ -f "$DOMAINS_FILE" ] || { printf 'missing domain manifest: %s\n' "$DOMAINS_FILE" >&2; exit 1; }
jq -e '.schemaVersion == 1 and (.domains | length > 0)' "$DOMAINS_FILE" >/dev/null
[ -z "$AUTHORIZED_KEYS" ] || [ -f "$AUTHORIZED_KEYS" ] || { printf 'missing authorized keys file: %s\n' "$AUTHORIZED_KEYS" >&2; exit 1; }

mount_source="$(findmnt -nro SOURCE --target /mnt/lab_debian 2>/dev/null || true)"
mount_target="$(findmnt -nro TARGET --target /mnt/lab_debian 2>/dev/null || true)"
if [ "$mount_target" != "/mnt/lab_debian" ] || [ -z "$mount_source" ] || [ "$mount_source" = "/" ]; then
  printf '/mnt/lab_debian is not a distinct mounted filesystem; refusing account provisioning\n' >&2
  exit 1
fi

printf '[domain-accounts] mode=%s lab_source=%s\n' "$MODE" "$mount_source"
for maintenance_user in software_lab stack_lab; do
  if id "$maintenance_user" >/dev/null 2>&1; then
    printf '[domain-accounts] current user=%s uid=%s\n' "$maintenance_user" "$(id -u "$maintenance_user")"
  else
    printf '[domain-accounts] create user=%s home=/home/%s\n' "$maintenance_user" "$maintenance_user"
  fi
done
jq -r '.domains[] | [.name,.user,.stateRoot,.graphRoot,.volumeRoot,(.uid // ""),(.subuidStart // "")] | @tsv' "$DOMAINS_FILE" |
  while IFS="$(printf '\t')" read -r domain user state_root graph_root volume_root expected_uid expected_subuid; do
    if id "$user" >/dev/null 2>&1; then
      printf '[domain-accounts] current domain=%s user=%s uid=%s\n' "$domain" "$user" "$(id -u "$user")"
    else
      printf '[domain-accounts] create domain=%s user=%s\n' "$domain" "$user"
    fi
    [ -z "$expected_uid" ] || printf '[domain-accounts] identity domain=%s uid=%s subuid_start=%s\n' "$domain" "$expected_uid" "$expected_subuid"
    printf '[domain-accounts] storage domain=%s state=%s graph=%s volumes=%s\n' "$domain" "$state_root" "$graph_root" "$volume_root"
  done

[ "$MODE" = apply ] || exit 0
[ "$(id -u)" -eq 0 ] || { printf '%s\n' '--apply requires root' >&2; exit 1; }

ensure_subids() {
  local user="$1" expected_start="${2:-}" start current_subuid current_subgid
  if [ -n "$expected_start" ]; then
    current_subuid="$(awk -F: -v user="$user" '$1 == user { print $2; exit }' /etc/subuid)"
    current_subgid="$(awk -F: -v user="$user" '$1 == user { print $2; exit }' /etc/subgid)"
    [ -z "$current_subuid" ] || [ "$current_subuid" = "$expected_start" ] || { printf 'subuid drift for %s: expected %s, found %s\n' "$user" "$expected_start" "$current_subuid" >&2; exit 1; }
    [ -z "$current_subgid" ] || [ "$current_subgid" = "$expected_start" ] || { printf 'subgid drift for %s: expected %s, found %s\n' "$user" "$expected_start" "$current_subgid" >&2; exit 1; }
    grep -q "^${user}:" /etc/subuid || usermod --add-subuids "${expected_start}-$((expected_start + 65535))" "$user"
    grep -q "^${user}:" /etc/subgid || usermod --add-subgids "${expected_start}-$((expected_start + 65535))" "$user"
    return 0
  fi
  if grep -q "^${user}:" /etc/subuid && grep -q "^${user}:" /etc/subgid; then
    return 0
  fi
  start="$(python3 - /etc/subuid /etc/subgid <<'PY'
import pathlib
import sys
highest = 1_999_999
for name in sys.argv[1:]:
    path = pathlib.Path(name)
    if not path.exists():
        continue
    for raw in path.read_text().splitlines():
        parts = raw.split(":")
        if len(parts) == 3:
            try:
                highest = max(highest, int(parts[1]) + int(parts[2]) - 1)
            except ValueError:
                pass
block = 65_536
print(((highest + block) // block) * block)
PY
)"
  grep -q "^${user}:" /etc/subuid || usermod --add-subuids "${start}-$((start + 65535))" "$user"
  grep -q "^${user}:" /etc/subgid || usermod --add-subgids "${start}-$((start + 65535))" "$user"
}

install_maintenance_user() {
  local user="$1" data_root="/mnt/lab_debian/$1" podman_root="/mnt/lab_debian/.podman/$1"
  id "$user" >/dev/null 2>&1 || useradd --create-home --home-dir "/home/$user" --shell /bin/bash "$user"
  passwd -l "$user" >/dev/null
  ensure_subids "$user"
  install -d -m 0700 -o "$user" -g "$user" "$data_root" "$podman_root" "/home/$user/.ssh" "/home/$user/.config/containers"
  chown "$user:$user" "/home/$user/.config"
  if [ -n "$AUTHORIZED_KEYS" ]; then
    install -m 0600 -o "$user" -g "$user" "$AUTHORIZED_KEYS" "/home/$user/.ssh/authorized_keys"
  fi
  if [ "$user" = software_lab ]; then
    [ -e "/home/$user/workspaces" ] || ln -s "$data_root" "/home/$user/workspaces"
  else
    install -d -m 0700 -o "$user" -g "$user" "$data_root/stack_work"
    [ -e "/home/$user/stack_work" ] || ln -s "$data_root/stack_work" "/home/$user/stack_work"
  fi
  printf '[storage]\ndriver = "overlay"\ngraphroot = "%s"\n' "$podman_root" > "/home/$user/.config/containers/storage.conf"
  chown "$user:$user" "/home/$user/.config/containers/storage.conf"
  chmod 0600 "/home/$user/.config/containers/storage.conf"
  loginctl enable-linger "$user"
}

install_maintenance_user software_lab
install_maintenance_user stack_lab

jq -r '.domains[] | [.name,.user,.stateRoot,.graphRoot,.volumeRoot,(.uid // ""),(.subuidStart // "")] | @tsv' "$DOMAINS_FILE" |
  while IFS="$(printf '\t')" read -r domain user state_root graph_root volume_root expected_uid expected_subuid; do
    existed=false
    id "$user" >/dev/null 2>&1 && existed=true
    if [ "$existed" = true ]; then
      [ -z "$expected_uid" ] || [ "$(id -u "$user")" = "$expected_uid" ] || { printf 'uid drift for %s: expected %s, found %s\n' "$user" "$expected_uid" "$(id -u "$user")" >&2; exit 1; }
    elif [ -n "$expected_uid" ]; then
      useradd --system --uid "$expected_uid" --create-home --home-dir "/home/$user" --shell /bin/bash "$user"
    else
      useradd --system --create-home --home-dir "/home/$user" --shell /bin/bash "$user"
    fi
    passwd -l "$user" >/dev/null
    ensure_subids "$user" "$expected_subuid"
    [ ! -d "/home/$user/.config" ] || chown "$user:$user" "/home/$user/.config"
    # Shared storage parents are traversal-only; each domain directory is
    # readable/traversable solely by its owning service account.
    install -d -m 0711 -o root -g root /mnt/stack/podman
    for domain_parent in "$(dirname "$graph_root")" "$(dirname "$state_root")"; do
      case "$domain_parent" in
        /mnt/stack/podman/*)
          install -d -m 0710 -o root -g "$user" "$domain_parent"
          ;;
      esac
    done
    if [ "$existed" = true ] && [ "$MIGRATE_EXISTING" != true ]; then
      printf '[domain-accounts] preserving existing Podman storage for %s; use --migrate-existing during its data cutover\n' "$user"
      loginctl enable-linger "$user"
      continue
    fi
    install -d -m 0700 -o "$user" -g "$user" "$state_root" "$graph_root" "$volume_root" "/home/$user/.config/containers"
    if command -v setfacl >/dev/null 2>&1; then
      setfacl -b -k "$graph_root" "$volume_root"
    fi
    chown "$user:$user" "/home/$user/.config"
    printf '[storage]\ndriver = "overlay"\ngraphroot = "%s"\n' "$graph_root" > "/home/$user/.config/containers/storage.conf"
    printf '[network]\ndefault_rootless_network_cmd = "pasta"\npasta_options = ["--map-host-loopback", "169.254.1.2"]\n' > "/home/$user/.config/containers/containers.conf"
    chown "$user:$user" "/home/$user/.config/containers/storage.conf"
    chown "$user:$user" "/home/$user/.config/containers/containers.conf"
    chmod 0600 "/home/$user/.config/containers/storage.conf" "/home/$user/.config/containers/containers.conf"
    loginctl enable-linger "$user"
  done

printf '[domain-accounts] applied\n'
