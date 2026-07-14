#!/usr/bin/env bash
set -Eeuo pipefail

BUNDLE=""
ENV_DIR=""
ACTIVATE=false
STATE_ROOT="${WEBSERVICES_STATE_ROOT:-/var/lib/webservices}"
ROOTLESS_STATE_ROOT="${WEBSERVICES_ROOTLESS_STATE_ROOT:-/var/lib/webservices-rootless}"
ROOTLESS_USER="${WEBSERVICES_ROOTLESS_USER:-webservices}"
QUADLET_DIR="${WEBSERVICES_QUADLET_DIR:-/etc/containers/systemd}"

usage() {
  printf 'Usage: %s --bundle DIR [--env-dir DIR] [--activate]\n' "${0##*/}" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle) BUNDLE="$2"; shift 2 ;;
    --env-dir) ENV_DIR="$2"; shift 2 ;;
    --activate) ACTIVATE=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

[ -d "$BUNDLE/quadlet" ] || { printf 'invalid Podman bundle: %s\n' "$BUNDLE" >&2; exit 1; }
ROOTFUL_QUADLET_SOURCE="$BUNDLE/quadlet/rootful"
ROOTLESS_QUADLET_SOURCE="$BUNDLE/quadlet/rootless"
[ -d "$ROOTFUL_QUADLET_SOURCE" ] || ROOTFUL_QUADLET_SOURCE="$BUNDLE/quadlet"
[ -d "$ROOTLESS_QUADLET_SOURCE" ] || ROOTLESS_QUADLET_SOURCE=""
jq -e '.backend == "podman"' "$BUNDLE/bundle.json" >/dev/null
command -v podman >/dev/null
command -v systemd-analyze >/dev/null

cleanup_paths=()
cleanup() {
  local path
  for path in "${cleanup_paths[@]}"; do
    rm -rf "$path"
  done
}
trap cleanup EXIT

contains_unresolved_env() {
  local env_file="$1"
  if command -v rg >/dev/null 2>&1; then
    rg -n '\$\{' "$env_file"
  else
    grep -n '\${' "$env_file"
  fi
}

root_has_sops_key_material() {
  [ -n "${SOPS_AGE_KEY:-}" ] && return 0
  [ -n "${SOPS_AGE_KEY_FILE:-}" ] && [ -f "$SOPS_AGE_KEY_FILE" ] && return 0
  [ -n "${SOPS_AGE_KEY_CMD:-}" ] && return 0
  [ -n "${SOPS_AGE_SSH_PRIVATE_KEY_FILE:-}" ] && [ -f "$SOPS_AGE_SSH_PRIVATE_KEY_FILE" ] && return 0
  [ -n "${SOPS_AGE_SSH_PRIVATE_KEY_CMD:-}" ] && return 0
  [ -f /root/.config/sops/age/keys.txt ] && return 0
  return 1
}

apply_loopback_rewrites() {
  local caddy_file="$BUNDLE/runtime/configs/caddy/Caddyfile"
  local endpoints_file="$BUNDLE/podman-loopback-endpoints.json"
  [ -f "$caddy_file" ] && [ -f "$endpoints_file" ] || return 0
  python3 - "$caddy_file" "$endpoints_file" <<'PY'
import json
import re
import sys
from pathlib import Path

caddy_file = Path(sys.argv[1])
endpoints = json.load(open(sys.argv[2])).get("endpoints", [])
content = caddy_file.read_text()
for endpoint in endpoints:
    service = re.escape(endpoint["service"])
    container_port = re.escape(str(endpoint["containerPort"]))
    host_port = str(endpoint["hostPort"])
    content = re.sub(rf"\b{service}:{container_port}\b", f"127.0.0.1:{host_port}", content)
caddy_file.write_text(content)
PY
}

if [ -z "$ENV_DIR" ]; then
  if [ "$ACTIVATE" = true ] && [ "$(id -u)" -eq 0 ] && ! root_has_sops_key_material; then
    printf 'root activation without --env-dir requires SOPS key material; render as the deploy user and pass --env-dir\n' >&2
    exit 1
  fi
  command -v python3 >/dev/null
  rendered_env_dir="$(mktemp -d)"
  cleanup_paths+=("$rendered_env_dir")
  if [ ! -f "$BUNDLE/runtime/stack.env" ]; then
    [ -x "$BUNDLE/scripts/deploy/render-runtime.sh" ] || {
      printf 'bundle cannot render runtime environment: missing scripts/deploy/render-runtime.sh\n' >&2
      exit 1
    }
    RENDER_ALL_ENV=1 "$BUNDLE/scripts/deploy/render-runtime.sh" \
      --bundle-root "$BUNDLE" \
      --deploy-root "$BUNDLE" \
      --runtime-root "$BUNDLE/runtime" \
      --skip-compose-validate >/dev/null
  fi
  [ -f "$BUNDLE/runtime/stack.env" ] || {
    printf 'bundle runtime environment was not rendered: %s\n' "$BUNDLE/runtime/stack.env" >&2
    exit 1
  }
  python3 - "$BUNDLE/runtime/stack.env" "$BUNDLE/runtime-env" "$rendered_env_dir" <<'PY'
import os
import re
import sys
from pathlib import Path

stack_env = Path(sys.argv[1])
template_root = Path(sys.argv[2])
output_root = Path(sys.argv[3])
values = {}

for raw in stack_env.read_text().splitlines():
    if not raw or raw.startswith("#") or "=" not in raw:
        continue
    key, value = raw.split("=", 1)
    values[key] = value.replace("$$", "$")

pattern = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?:(:-|:\?)([^}]*))?\}")

def render(value: str, source: Path) -> str:
    def replace(match: re.Match[str]) -> str:
        key, op, fallback = match.group(1), match.group(2), match.group(3) or ""
        current = values.get(key, "")
        if op == ":-":
            return current or fallback
        if op == ":?":
            if not current:
                raise SystemExit(f"missing required environment value {key} while rendering {source}")
            return current
        return current

    previous = None
    current = value
    for _ in range(8):
        if current == previous:
            return current
        previous = current
        current = pattern.sub(replace, current)
    return current

output_root.mkdir(parents=True, exist_ok=True)
for template in sorted(template_root.glob("*.env.template")):
    lines = []
    for raw in template.read_text().splitlines():
        if not raw or raw.startswith("#"):
            continue
        if "=" not in raw:
            raise SystemExit(f"invalid env template line in {template}: {raw}")
        key, value = raw.split("=", 1)
        lines.append(f"{key}={render(value, template)}")
    (output_root / template.name.removesuffix(".template")).write_text("\n".join(lines) + "\n")
PY
  ENV_DIR="$rendered_env_dir"
fi
apply_loopback_rewrites

[ -d "$ENV_DIR" ] || { printf 'runtime environment directory not found: %s\n' "$ENV_DIR" >&2; exit 1; }

if find "$BUNDLE/runtime/configs" -type f -name '*.template' -print -quit 2>/dev/null | grep -q .; then
  printf 'bundle runtime configs still contain template files; render the bundle before activation\n' >&2
  exit 1
fi

while IFS= read -r template; do
  service="${template##*/}"
  service="${service%.env.template}"
  env_file="$ENV_DIR/$service.env"
  [ -f "$env_file" ] || { printf 'missing rendered environment: %s\n' "$env_file" >&2; exit 1; }
  if contains_unresolved_env "$env_file"; then
    printf 'unresolved environment expression in %s\n' "$env_file" >&2
    exit 1
  fi
done < <(find "$BUNDLE/runtime-env" -type f -name '*.env.template' -print 2>/dev/null | sort)

verify_root="$(mktemp -d)"
cleanup_paths+=("$verify_root")
verify_quadlet_dir() {
  local label="$1"
  local source="$2"
  local destination="$verify_root/$label"
  local units=()
  [ -n "$source" ] || return 0
  mkdir -p "$destination/normal" "$destination/early" "$destination/late"
  QUADLET_UNIT_DIRS="$source" /usr/libexec/podman/quadlet \
    "$destination/normal" "$destination/early" "$destination/late"
  while IFS= read -r unit; do
    units+=("$unit")
  done < <(find "$destination" "$source" -maxdepth 2 \( -name '*.service' -o -name '*.target' \) -print | sort)
  [ "${#units[@]}" -gt 0 ] || { printf 'no generated Quadlet units found for %s\n' "$label" >&2; exit 1; }
  systemd-analyze verify "${units[@]}"
}

verify_quadlet_dir rootful "$ROOTFUL_QUADLET_SOURCE"
verify_quadlet_dir rootless "$ROOTLESS_QUADLET_SOURCE"
printf '[podman-install] preflight passed\n'

[ "$ACTIVATE" = true ] || {
  printf '[podman-install] validation only; rerun with --activate as root to install\n'
  exit 0
}
[ "$(id -u)" -eq 0 ] || { printf -- '--activate requires root\n' >&2; exit 1; }

release_id="$(date -u +%Y%m%dT%H%M%SZ)-$(jq -r '.irSha256[0:12]' "$BUNDLE/bundle.json")"
release="$STATE_ROOT/releases/$release_id"
rootless_release="$ROOTLESS_STATE_ROOT/releases/$release_id"
previous="$(readlink -f "$STATE_ROOT/current" 2>/dev/null || true)"
previous_rootless="$(readlink -f "$ROOTLESS_STATE_ROOT/current" 2>/dev/null || true)"

if ! id "$ROOTLESS_USER" >/dev/null 2>&1; then
  useradd --system --create-home --home-dir "/home/$ROOTLESS_USER" --shell /usr/sbin/nologin "$ROOTLESS_USER"
fi
rootless_uid="$(id -u "$ROOTLESS_USER")"
rootless_gid="$(id -g "$ROOTLESS_USER")"
rootless_home="$(getent passwd "$ROOTLESS_USER" | cut -d: -f6)"
grep -q "^${ROOTLESS_USER}:" /etc/subuid || usermod --add-subuids 1000000-1065535 "$ROOTLESS_USER"
grep -q "^${ROOTLESS_USER}:" /etc/subgid || usermod --add-subgids 1000000-1065535 "$ROOTLESS_USER"
loginctl enable-linger "$ROOTLESS_USER"
systemctl start "user@${rootless_uid}.service"

rootless_runtime="/run/user/${rootless_uid}/webservices"
rootless_quadlet_dir="$rootless_home/.config/containers/systemd"
rootless_systemd_dir="$rootless_home/.config/systemd/user"
mkdir -p "$release" "$rootless_release" "$STATE_ROOT/releases" "$ROOTLESS_STATE_ROOT/releases" "$STATE_ROOT/test-results" "$QUADLET_DIR" /run/webservices "$rootless_runtime" "$rootless_quadlet_dir" "$rootless_systemd_dir" /var/log/webservices/caddy
cp -a "$BUNDLE/." "$release/"
cp -a "$BUNDLE/." "$rootless_release/"
install -d -m 0755 "$release/repos"
install -d -m 0755 "$rootless_release/repos"
chown -R "$ROOTLESS_USER:$ROOTLESS_USER" "$ROOTLESS_STATE_ROOT" "$rootless_home/.config" "$rootless_runtime"
find "$rootless_release/runtime/configs" -type d -exec chmod 0755 {} + 2>/dev/null || true
find "$rootless_release/runtime/configs" -type f -exec chmod a+r {} + 2>/dev/null || true
chmod 0700 /run/webservices
for env_file in "$ENV_DIR"/*.env; do
  destination="/run/webservices/${env_file##*/}"
  if [ "$(readlink -f "$env_file")" = "$(readlink -f "$destination" 2>/dev/null || printf '%s' "$destination")" ]; then
    chmod 0600 "$destination"
  else
    install -m 0600 "$env_file" "$destination"
  fi
  rootless_destination="$rootless_runtime/${env_file##*/}"
  install -m 0600 -o "$ROOTLESS_USER" -g "$ROOTLESS_USER" "$env_file" "$rootless_destination"
done

jq -r '.volumes | to_entries[] | [.key, (.value.hostPath // "")] | @tsv' "$BUNDLE/stack.ir.json" | while IFS="$(printf '\t')" read -r name path; do
  case "$path" in
    "")
      ;;
    /*)
      mode=0750
      [ "$name" = "caddy_ca" ] && mode=0755
      install -d -m "$mode" "$path"
      ;;
  esac
done

copy_tree_once() {
  local source="$1"
  local destination="$2"
  local copied=false
  [ -n "$source" ] && [ -n "$destination" ] || return 0
  [ "$source" != "$destination" ] || return 0
  install -d -m 0750 "$destination"
  chown "$ROOTLESS_USER:$ROOTLESS_USER" /mnt/stack/rootless /mnt/stack/rootless/volumes /mnt/stack/rootless/pg-ssd /mnt/stack/rootless/vector-dbs 2>/dev/null || true
  find /mnt/stack/rootless -maxdepth 2 -type d -exec chmod o+rx {} + 2>/dev/null || true
  if [ -d "$source" ] && ! find "$destination" -mindepth 1 -print -quit | grep -q .; then
    if command -v rsync >/dev/null 2>&1; then
      rsync -aHAX --numeric-ids "$source"/ "$destination"/
    else
      cp -a "$source"/. "$destination"/
    fi
    copied=true
  fi
  if [ "$copied" = true ]; then
    chown -R "$ROOTLESS_USER:$ROOTLESS_USER" "$destination"
  fi
}

grant_shared_access() {
  local path="$1"
  [ -n "$path" ] && [ -d "$path" ] || return 0
  if command -v setfacl >/dev/null 2>&1; then
    setfacl -Rm "u:${ROOTLESS_USER}:rwX" "$path"
    setfacl -Rdm "u:${ROOTLESS_USER}:rwX" "$path"
  fi
}

command -v python3 >/dev/null
python3 - "$BUNDLE/stack.ir.json" <<'PY' | while IFS="$(printf '\t')" read -r strategy source destination; do
import json
import sys

ir = json.load(open(sys.argv[1]))
volumes = ir.get("volumes", {})
rootless_services = [svc for svc in ir.get("services", {}).values() if svc.get("placement", "rootful") == "rootless"]
seen = set()

def rootless_host_path(name, host_path):
    if host_path.startswith("/mnt/stack/volumes/"):
        return "/mnt/stack/rootless/volumes/" + host_path.removeprefix("/mnt/stack/volumes/")
    if host_path.startswith("/mnt/stack/pg-ssd/"):
        return "/mnt/stack/rootless/pg-ssd/" + host_path.removeprefix("/mnt/stack/pg-ssd/")
    if host_path.startswith("/mnt/stack/vector-dbs/"):
        return "/mnt/stack/rootless/vector-dbs/" + host_path.removeprefix("/mnt/stack/vector-dbs/")
    return "/mnt/stack/rootless/volumes/" + name

def source_name(volume):
    if isinstance(volume, str):
        return volume.split(":", 1)[0]
    return volume.get("source", "")

for service in rootless_services:
    for mount in service.get("volumes", []):
        name = source_name(mount)
        volume = volumes.get(name)
        if not volume or "hostPath" not in volume:
            continue
        host_path = volume["hostPath"]
        strategy = volume.get("rootlessStrategy", "copy")
        destination = host_path if strategy == "shared" else rootless_host_path(name, host_path)
        row = (strategy, host_path, destination)
        if row not in seen:
            seen.add(row)
            print("\t".join(row))
PY
  case "$strategy" in
    shared) grant_shared_access "$source" ;;
    copy|"") copy_tree_once "$source" "$destination" ;;
    forbidden) printf 'rootless volume is forbidden: %s\n' "$source" >&2; exit 1 ;;
    *) printf 'unknown rootless volume strategy %s for %s\n' "$strategy" "$source" >&2; exit 1 ;;
  esac
done

ln -sfn "$release" "$STATE_ROOT/.current-new"
mv -Tf "$STATE_ROOT/.current-new" "$STATE_ROOT/current"
ln -sfn "$rootless_release" "$ROOTLESS_STATE_ROOT/.current-new"
mv -Tf "$ROOTLESS_STATE_ROOT/.current-new" "$ROOTLESS_STATE_ROOT/current"
find "$QUADLET_DIR" -maxdepth 1 -type f -name 'webservices-*' -delete
find /etc/systemd/system -maxdepth 1 -type f -name 'webservices-*.target' -delete
find /etc/systemd/system -maxdepth 1 -type f -name 'webservices.target' -delete
find "$release/quadlet/rootful" -maxdepth 1 -type f ! -name '*.target' -exec install -m 0644 {} "$QUADLET_DIR/" \;
install -m 0644 "$release/quadlet/rootful"/*.target /etc/systemd/system/
find "$rootless_quadlet_dir" -maxdepth 1 -type f -name 'webservices-*' -delete
find "$rootless_systemd_dir" -maxdepth 1 -type f -name 'webservices-*.target' -delete
find "$rootless_systemd_dir" -maxdepth 1 -type f -name 'webservices.target' -delete
find "$rootless_release/quadlet/rootless" -maxdepth 1 -type f ! -name '*.target' -exec install -m 0644 -o "$ROOTLESS_USER" -g "$ROOTLESS_USER" {} "$rootless_quadlet_dir/" \;
install -m 0644 -o "$ROOTLESS_USER" -g "$ROOTLESS_USER" "$rootless_release/quadlet/rootless"/*.target "$rootless_systemd_dir/"
install -m 0755 "$release/ops/webservices-auto-update" /usr/local/sbin/webservices-auto-update
install -m 0644 "$release/ops/webservices-auto-update.service" "$release/ops/webservices-auto-update.timer" /etc/systemd/system/

rollback() {
  status=$?
  printf '[podman-install] activation failed; restoring previous release\n' >&2
  if [ -n "$previous_rootless" ] && [ -d "$previous_rootless" ]; then
    ln -sfn "$previous_rootless" "$ROOTLESS_STATE_ROOT/.current-old"
    mv -Tf "$ROOTLESS_STATE_ROOT/.current-old" "$ROOTLESS_STATE_ROOT/current"
  fi
  if [ -n "$previous" ] && [ -d "$previous/quadlet" ]; then
    ln -sfn "$previous" "$STATE_ROOT/.current-old"
    mv -Tf "$STATE_ROOT/.current-old" "$STATE_ROOT/current"
    find "$QUADLET_DIR" -maxdepth 1 -type f -name 'webservices-*' -delete
    find /etc/systemd/system -maxdepth 1 -type f -name 'webservices-*.target' -delete
    find /etc/systemd/system -maxdepth 1 -type f -name 'webservices.target' -delete
    previous_rootful="$previous/quadlet/rootful"
    [ -d "$previous_rootful" ] || previous_rootful="$previous/quadlet"
    find "$previous_rootful" -maxdepth 1 -type f ! -name '*.target' -exec install -m 0644 {} "$QUADLET_DIR/" \;
    install -m 0644 "$previous_rootful"/*.target /etc/systemd/system/
    systemctl daemon-reload
    systemctl restart webservices.target || true
  fi
  exit "$status"
}
trap rollback ERR

user_systemctl() {
  /usr/sbin/runuser -u "$ROOTLESS_USER" -- env HOME="$rootless_home" XDG_RUNTIME_DIR="/run/user/${rootless_uid}" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${rootless_uid}/bus" systemctl --user "$@"
}

systemctl stop webservices.target || true
systemctl daemon-reload
user_systemctl daemon-reload
user_systemctl enable --now podman.socket
systemctl enable --now webservices-auto-update.timer
user_systemctl restart webservices.target
user_systemctl --quiet is-active webservices.target
systemctl restart webservices.target
systemctl --quiet is-active webservices.target
trap - ERR
printf '[podman-install] active rootful release: %s\n' "$release"
printf '[podman-install] active rootless release: %s\n' "$rootless_release"
