#!/usr/bin/env bash
set -Eeuo pipefail

BUNDLE=""
ENV_DIR=""
ACTIVATE=false
ACTIVATION_ROLLBACK="${WEBSERVICES_ACTIVATION_ROLLBACK:-1}"
STATE_ROOT="${WEBSERVICES_STATE_ROOT:-/var/lib/webservices}"
ROOTLESS_STATE_ROOT="${WEBSERVICES_ROOTLESS_STATE_ROOT:-/var/lib/webservices-rootless}"
ROOTLESS_USER="${WEBSERVICES_ROOTLESS_USER:-webservices}"
QUADLET_DIR="${WEBSERVICES_QUADLET_DIR:-/etc/containers/systemd}"
declare -a ROOTLESS_DOMAIN_NAMES=()
declare -a ROOTLESS_DOMAIN_USERS=()
declare -a ROOTLESS_DOMAIN_STATE_ROOTS=()
declare -a ROOTLESS_DOMAIN_GRAPH_ROOTS=()
declare -a ROOTLESS_DOMAIN_VOLUME_ROOTS=()
declare -a ROOTLESS_DOMAIN_UIDS=()
declare -a ROOTLESS_DOMAIN_SUBUID_STARTS=()

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
[ -d "$ROOTFUL_QUADLET_SOURCE" ] || ROOTFUL_QUADLET_SOURCE="$BUNDLE/quadlet"
jq -e '.backend == "podman"' "$BUNDLE/bundle.json" >/dev/null
DOMAINS_FILE="$BUNDLE/podman-domains.json"
[ -f "$DOMAINS_FILE" ] || { printf 'Podman bundle is missing podman-domains.json\n' >&2; exit 1; }
jq -e '.schemaVersion == 1 and (.domains | type == "array" and length > 0)' "$DOMAINS_FILE" >/dev/null
mapfile -t ROOTLESS_DOMAIN_NAMES < <(jq -r '.domains[].name' "$DOMAINS_FILE")
mapfile -t ROOTLESS_DOMAIN_USERS < <(jq -r '.domains[].user' "$DOMAINS_FILE")
mapfile -t ROOTLESS_DOMAIN_STATE_ROOTS < <(jq -r '.domains[].stateRoot' "$DOMAINS_FILE")
mapfile -t ROOTLESS_DOMAIN_GRAPH_ROOTS < <(jq -r '.domains[].graphRoot' "$DOMAINS_FILE")
mapfile -t ROOTLESS_DOMAIN_VOLUME_ROOTS < <(jq -r '.domains[].volumeRoot' "$DOMAINS_FILE")
mapfile -t ROOTLESS_DOMAIN_UIDS < <(jq -r '.domains[] | .uid // ""' "$DOMAINS_FILE")
mapfile -t ROOTLESS_DOMAIN_SUBUID_STARTS < <(jq -r '.domains[] | .subuidStart // ""' "$DOMAINS_FILE")
command -v podman >/dev/null
command -v systemd-analyze >/dev/null

domain_index_by_name() {
  local wanted="$1" i
  for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
    if [ "${ROOTLESS_DOMAIN_NAMES[$i]}" = "$wanted" ]; then
      printf '%s\n' "$i"
      return 0
    fi
  done
  return 1
}

next_subid_start() {
  python3 - /etc/subuid /etc/subgid <<'PY'
import pathlib
import sys

highest = 1_999_999
for name in sys.argv[1:]:
    path = pathlib.Path(name)
    if not path.exists():
        continue
    for raw in path.read_text().splitlines():
        parts = raw.split(":")
        if len(parts) != 3:
            continue
        try:
            highest = max(highest, int(parts[1]) + int(parts[2]) - 1)
        except ValueError:
            pass
block = 65_536
print(((highest + block) // block) * block)
PY
}

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
  local config_root="$BUNDLE/runtime/configs"
  local endpoints_file="$BUNDLE/podman-loopback-endpoints.json"
  [ -d "$config_root" ] && [ -f "$endpoints_file" ] || return 0
  python3 - "$config_root" "$endpoints_file" "$BUNDLE/stack.ir.json" <<'PY'
import json
import re
import sys
from pathlib import Path

config_root = Path(sys.argv[1])
endpoints = json.load(open(sys.argv[2])).get("endpoints", [])
ir = json.load(open(sys.argv[3]))
owners = {}
for service in ir.get("services", {}).values():
    domain = service.get("rootlessDomain", "rootful") if service.get("placement") == "rootless" else "rootful"
    for mount in service.get("volumes", []):
        source = mount.split(":", 1)[0] if isinstance(mount, str) else mount.get("source", "")
        if source.startswith("./configs/"):
            relative = source.removeprefix("./configs/")
            owners.setdefault(relative, set()).add(domain)

for path in config_root.rglob("*"):
    if not path.is_file() or path.suffix == ".template":
        continue
    try:
        content = path.read_text()
    except (UnicodeDecodeError, OSError):
        continue
    original = content
    relative = path.relative_to(config_root)
    domains = set()
    for mount, mount_domains in owners.items():
        mounted_path = config_root / mount
        if relative.as_posix() == mount or (mounted_path.is_dir() and mounted_path in path.parents):
            domains.update(mount_domains)
    for endpoint in endpoints:
        consumers = set(endpoint.get("consumers", []))
        if not domains.intersection(consumers):
            continue
        service = re.escape(endpoint["service"])
        container_port = re.escape(str(endpoint["containerPort"]))
        host_port = str(endpoint["hostPort"])
        replacement_host = "127.0.0.1" if domains == {"rootful"} else "host.containers.internal"
        content = re.sub(
            rf"((?:host|hostname|db_host|postgres_host)\s*[:=]\s*[\"']?{service}[\"']?.{{0,160}}?(?:port|db_port|postgres_port)\s*[:=]\s*[\"']?){container_port}(?![0-9])",
            rf"\g<1>{host_port}",
            content,
            flags=re.IGNORECASE | re.DOTALL,
        )
        content = re.sub(rf"(?<![A-Za-z0-9_-]){service}:{container_port}(?![0-9])", f"{replacement_host}:{host_port}", content)
        if replacement_host != "127.0.0.1":
            content = re.sub(rf"(?<![A-Za-z0-9_-]){service}(?![A-Za-z0-9_-])", replacement_host, content)
    if content != original:
        path.write_text(content)
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
      --skip-runtime-model-validate >/dev/null
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
            return current.replace("$$", "$")
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

if jq -e '.volumes | any(.rootlessStrategy? == "shared")' "$BUNDLE/stack.ir.json" >/dev/null; then
  command -v setfacl >/dev/null || {
    printf 'shared rootless volumes require the host ACL utility (setfacl)\n' >&2
    exit 1
  }
fi

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
for domain in "${ROOTLESS_DOMAIN_NAMES[@]}"; do
  source="$BUNDLE/quadlet/rootless-$domain"
  [ -d "$source" ] || { printf 'missing rootless Quadlet domain: %s\n' "$source" >&2; exit 1; }
  verify_quadlet_dir "rootless-$domain" "$source"
done
printf '[podman-install] preflight passed\n'

[ "$ACTIVATE" = true ] || {
  printf '[podman-install] validation only; rerun with --activate as root to install\n'
  exit 0
}
[ "$(id -u)" -eq 0 ] || { printf -- '--activate requires root\n' >&2; exit 1; }

release_id="$(date -u +%Y%m%dT%H%M%SZ)-$(jq -r '.irSha256[0:12]' "$BUNDLE/bundle.json")"
release="$STATE_ROOT/releases/$release_id"
previous="$(readlink -f "$STATE_ROOT/current" 2>/dev/null || true)"

declare -a ROOTLESS_RELEASES=()
declare -a ROOTLESS_PREVIOUS=()
declare -a ROOTLESS_UIDS=()
declare -a ROOTLESS_HOMES=()
declare -a ROOTLESS_RUNTIMES=()
declare -a ROOTLESS_ENV_STORES=()
declare -a ROOTLESS_QUADLET_DIRS=()
declare -a ROOTLESS_SYSTEMD_DIRS=()

ensure_rootless_domain() {
  local index="$1" user state_root graph_root volume_root expected_uid expected_subuid uid home runtime env_store quadlet_dir systemd_dir subid_start current_subuid current_subgid
  user="${ROOTLESS_DOMAIN_USERS[$index]}"
  state_root="${ROOTLESS_DOMAIN_STATE_ROOTS[$index]}"
  graph_root="${ROOTLESS_DOMAIN_GRAPH_ROOTS[$index]}"
  volume_root="${ROOTLESS_DOMAIN_VOLUME_ROOTS[$index]}"
  expected_uid="${ROOTLESS_DOMAIN_UIDS[$index]}"
  expected_subuid="${ROOTLESS_DOMAIN_SUBUID_STARTS[$index]}"
  if ! id "$user" >/dev/null 2>&1; then
    if [ -n "$expected_uid" ]; then
      useradd --system --uid "$expected_uid" --create-home --home-dir "/home/$user" --shell /usr/sbin/nologin "$user"
    else
      useradd --system --create-home --home-dir "/home/$user" --shell /usr/sbin/nologin "$user"
    fi
  fi
  uid="$(id -u "$user")"
  [ -z "$expected_uid" ] || [ "$uid" = "$expected_uid" ] || { printf 'uid drift for %s: expected %s, found %s\n' "$user" "$expected_uid" "$uid" >&2; exit 1; }
  home="$(getent passwd "$user" | cut -d: -f6)"
  if ! grep -q "^${user}:" /etc/subuid || ! grep -q "^${user}:" /etc/subgid; then
    subid_start="${expected_subuid:-$(next_subid_start)}"
    grep -q "^${user}:" /etc/subuid || usermod --add-subuids "${subid_start}-$((subid_start + 65535))" "$user"
    grep -q "^${user}:" /etc/subgid || usermod --add-subgids "${subid_start}-$((subid_start + 65535))" "$user"
  fi
  if [ -n "$expected_subuid" ]; then
    current_subuid="$(awk -F: -v user="$user" '$1 == user { print $2; exit }' /etc/subuid)"
    current_subgid="$(awk -F: -v user="$user" '$1 == user { print $2; exit }' /etc/subgid)"
    [ "$current_subuid" = "$expected_subuid" ] && [ "$current_subgid" = "$expected_subuid" ] || { printf 'subordinate-id drift for %s\n' "$user" >&2; exit 1; }
  fi
  loginctl enable-linger "$user"
  systemctl start "user@${uid}.service"
  runtime="/run/user/${uid}/webservices"
  env_store="$state_root/runtime-env"
  quadlet_dir="$home/.config/containers/systemd"
  systemd_dir="$home/.config/systemd/user"
  ROOTLESS_RELEASES[$index]="$state_root/releases/$release_id"
  ROOTLESS_PREVIOUS[$index]="$(readlink -f "$state_root/current" 2>/dev/null || true)"
  ROOTLESS_UIDS[$index]="$uid"
  ROOTLESS_HOMES[$index]="$home"
  ROOTLESS_RUNTIMES[$index]="$runtime"
  ROOTLESS_ENV_STORES[$index]="$env_store"
  ROOTLESS_QUADLET_DIRS[$index]="$quadlet_dir"
  ROOTLESS_SYSTEMD_DIRS[$index]="$systemd_dir"
  install -d -m 0711 -o root -g root /mnt/stack/podman
  case "$(dirname "$graph_root")" in
    /mnt/stack/podman/*) install -d -m 0710 -o root -g "$user" "$(dirname "$graph_root")" ;;
  esac
  mkdir -p "${ROOTLESS_RELEASES[$index]}" "$state_root/releases" "$graph_root" "$volume_root" "$runtime" "$env_store" "$quadlet_dir" "$systemd_dir" "$home/.config/containers"
  if command -v setfacl >/dev/null 2>&1; then
    setfacl -b -k "$graph_root" "$volume_root"
  fi
  chown "$user:$user" "$state_root" "$state_root/releases" "${ROOTLESS_RELEASES[$index]}" "$graph_root" "$volume_root" "$runtime" "$env_store"
  chown -R "$user:$user" "$home/.config"
  chmod 0700 "$env_store"
  printf '[storage]\ndriver = "overlay"\ngraphroot = "%s"\n' "$graph_root" > "$home/.config/containers/storage.conf"
  printf '[network]\ndefault_rootless_network_cmd = "pasta"\npasta_options = ["--map-host-loopback", "169.254.1.2"]\n' > "$home/.config/containers/containers.conf"
  chown "$user:$user" "$home/.config/containers/storage.conf"
  chown "$user:$user" "$home/.config/containers/containers.conf"
  chmod 0600 "$home/.config/containers/storage.conf" "$home/.config/containers/containers.conf"
}

user_systemctl() {
  local index="$1" user home uid
  shift
  user="${ROOTLESS_DOMAIN_USERS[$index]}"
  home="${ROOTLESS_HOMES[$index]}"
  uid="${ROOTLESS_UIDS[$index]}"
  /usr/sbin/runuser -u "$user" -- env HOME="$home" XDG_RUNTIME_DIR="/run/user/${uid}" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${uid}/bus" systemctl --user "$@"
}

cancel_webservices_start_jobs() {
  local mode="$1" index="$2" job unit type state
  local -a jobs=()
  if [ "$mode" = "rootless" ]; then
    while read -r job unit type state; do
      [[ "$unit" = webservices-* ]] && [ "$type" != "stop" ] && jobs+=("$job")
    done < <(user_systemctl "$index" list-jobs --no-legend --no-pager 2>/dev/null || true)
    [ "${#jobs[@]}" -eq 0 ] || user_systemctl "$index" cancel "${jobs[@]}" >/dev/null 2>&1 || true
  else
    while read -r job unit type state; do
      [[ "$unit" = webservices-* ]] && [ "$type" != "stop" ] && jobs+=("$job")
    done < <(systemctl list-jobs --no-legend --no-pager 2>/dev/null || true)
    [ "${#jobs[@]}" -eq 0 ] || systemctl cancel "${jobs[@]}" >/dev/null 2>&1 || true
  fi
}

mkdir -p "$release" "$STATE_ROOT/releases" "$STATE_ROOT/test-results" "$STATE_ROOT/runtime-env" "$QUADLET_DIR" /run/webservices /var/log/webservices/caddy
chmod 0700 "$STATE_ROOT/runtime-env"
for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
  ensure_rootless_domain "$i"
done

# The persistent rootful store is also the natural input for an update. Snapshot
# it before stale-file cleanup so an in-place update cannot erase its own source.
if [ "$(readlink -f "$ENV_DIR")" = "$(readlink -f "$STATE_ROOT/runtime-env")" ]; then
  env_input_snapshot="$(mktemp -d)"
  cleanup_paths+=("$env_input_snapshot")
  chmod 0700 "$env_input_snapshot"
  cp -a "$ENV_DIR/." "$env_input_snapshot/"
  ENV_DIR="$env_input_snapshot"
fi

# A service moved between rootless domains can otherwise keep its old host port
# and volume mounts while the replacement domain starts.
cancel_webservices_start_jobs rootful 0
for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
  cancel_webservices_start_jobs rootless "$i"
done
systemctl stop webservices.target || true
for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
  user_systemctl "$i" stop webservices.target || true
  user_systemctl "$i" reset-failed 'webservices-*' || true
done
systemctl reset-failed 'webservices-*' || true
cp -a "$BUNDLE/." "$release/"
install -d -m 0755 "$release/repos"
for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
  user="${ROOTLESS_DOMAIN_USERS[$i]}"
  domain="${ROOTLESS_DOMAIN_NAMES[$i]}"
  rootless_release="${ROOTLESS_RELEASES[$i]}"
  cp -a "$BUNDLE/." "$rootless_release/"
  install -d -m 0755 "$rootless_release/repos"
  python3 - "$rootless_release" "$domain" <<'PY'
import json
import shutil
import sys
from pathlib import Path

release = Path(sys.argv[1])
domain = sys.argv[2]
ir_path = release / "stack.ir.json"
ir = json.loads(ir_path.read_text())
owned = {
    name: service
    for name, service in ir.get("services", {}).items()
    if service.get("placement") == "rootless" and service.get("rootlessDomain") == domain
}

allowed_config_roots = set()
for service in owned.values():
    for mount in service.get("volumes", []):
        source = mount.split(":", 1)[0] if isinstance(mount, str) else mount.get("source", "")
        if source.startswith("./configs/"):
            relative = source.removeprefix("./configs/")
            if relative:
                allowed_config_roots.add(relative.split("/", 1)[0])

config_root = release / "runtime" / "configs"
if config_root.is_dir():
    for child in config_root.iterdir():
        if child.name not in allowed_config_roots:
            shutil.rmtree(child) if child.is_dir() else child.unlink()

env_templates = release / "runtime-env"
if env_templates.is_dir():
    for template in env_templates.glob("*.env.template"):
        if template.name.removesuffix(".env.template") not in owned:
            template.unlink()

quadlet_root = release / "quadlet"
if quadlet_root.is_dir():
    for child in quadlet_root.iterdir():
        if child.name != f"rootless-{domain}":
            shutil.rmtree(child) if child.is_dir() else child.unlink()

runtime_env = release / "runtime" / "stack.env"
if runtime_env.exists():
    runtime_env.unlink()
for candidate in release.glob("site/**/*sops*"):
    if candidate.is_file():
        candidate.unlink()

ir["services"] = owned
ir["networks"] = {
    name: value for name, value in ir.get("networks", {}).items()
    if any(name in service.get("networks", {}) for service in owned.values())
}
ir_path.write_text(json.dumps(ir, indent=2) + "\n")
PY
  chown -R "$user:$user" "$rootless_release"
  # The release parent is account-private; mounted configs must remain readable
  # (and scripts executable) by non-root users inside the rootless namespace.
  find "$rootless_release/runtime/configs" -type d -exec chmod 0755 {} + 2>/dev/null || true
  find "$rootless_release/runtime/configs" -type f -exec chmod 0644 {} + 2>/dev/null || true
  while IFS= read -r config_script; do
    [ "$(head -c 2 "$config_script")" != '#!' ] || chmod 0755 "$config_script"
  done < <(find "$rootless_release/runtime/configs" -type f 2>/dev/null)
done

# The integration-test authority is intentionally the only rootless domain
# that receives the aggregate rendered environment.  Its runner exercises
# authenticated flows across every declared dependency, while ordinary
# service domains continue to receive only their own per-service env files.
test_runner_domain="$(jq -r '.services["test-runner"].rootlessDomain // empty' "$BUNDLE/stack.ir.json")"
if [ -n "$test_runner_domain" ]; then
  i="$(domain_index_by_name "$test_runner_domain")" || { printf 'test-runner names unknown domain: %s\n' "$test_runner_domain" >&2; exit 1; }
  user="${ROOTLESS_DOMAIN_USERS[$i]}"
  install -m 0600 -o "$user" -g "$user" "$BUNDLE/runtime/stack.env" "${ROOTLESS_RELEASES[$i]}/runtime/stack.env"
fi
chmod 0700 /run/webservices
find "$STATE_ROOT/runtime-env" -maxdepth 1 -type f -name '*.env' -delete
for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
  find "${ROOTLESS_ENV_STORES[$i]}" -maxdepth 1 -type f -name '*.env' -delete
done
for env_file in "$ENV_DIR"/*.env; do
  [ -e "$env_file" ] || continue
  destination="/run/webservices/${env_file##*/}"
  if [ "$(readlink -f "$env_file")" = "$(readlink -f "$destination" 2>/dev/null || printf '%s' "$destination")" ]; then
    chmod 0600 "$destination"
  else
    install -m 0600 "$env_file" "$destination"
  fi
  install -m 0600 "$env_file" "$STATE_ROOT/runtime-env/${env_file##*/}"
  service="${env_file##*/}"
  service="${service%.env}"
  domain="$(jq -r --arg service "$service" '.services[$service] | select(.placement == "rootless") | .rootlessDomain // empty' "$BUNDLE/stack.ir.json")"
  if [ -n "$domain" ]; then
    i="$(domain_index_by_name "$domain")" || { printf 'environment names unknown domain: %s\n' "$domain" >&2; exit 1; }
    user="${ROOTLESS_DOMAIN_USERS[$i]}"
    rootless_destination="${ROOTLESS_RUNTIMES[$i]}/${env_file##*/}"
    install -m 0600 -o "$user" -g "$user" "$env_file" "$rootless_destination"
    install -m 0600 -o "$user" -g "$user" "$env_file" "${ROOTLESS_ENV_STORES[$i]}/${env_file##*/}"
  fi
done

forgejo_runner_ssh_dir="$(sed -n 's/^FORGEJO_RUNNER_SSH_DIR=//p' "$ENV_DIR/forgejo-runner.env" 2>/dev/null | tail -n 1)"
if [ -n "$forgejo_runner_ssh_dir" ]; then
  forgejo_index="$(domain_index_by_name forgejo-runner)"
  forgejo_user="${ROOTLESS_DOMAIN_USERS[$forgejo_index]}"
  install -d -m 0700 -o "$forgejo_user" -g "$forgejo_user" "$forgejo_runner_ssh_dir"
  chown -R "$forgejo_user:$forgejo_user" "$forgejo_runner_ssh_dir"
fi

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
  local destination_user="$3"
  local copied=false
  [ -n "$source" ] && [ -n "$destination" ] || return 0
  [ "$source" != "$destination" ] || return 0
  install -d -m 0750 "$destination"
  if [ -d "$source" ] && ! find "$destination" -mindepth 1 -print -quit | grep -q .; then
    if command -v rsync >/dev/null 2>&1; then
      rsync -aHAX --numeric-ids "$source"/ "$destination"/
    else
      cp -a "$source"/. "$destination"/
    fi
    copied=true
  fi
  [ "$copied" = false ] || chown "$destination_user:$destination_user" "$destination"
}

translate_rootless_volume_owner() {
  local destination="$1" user="$2" subid_start="$3" desired_uid
  [ -d "$destination" ] || return 0
  desired_uid="$(id -u "$user")"
  [ -n "$subid_start" ] || { printf 'missing subordinate-id range for %s\n' "$user" >&2; return 1; }
  python3 - "$destination" "$desired_uid" "$(id -g "$user")" "$subid_start" <<'PY'
import os
import sys
from pathlib import Path

root = Path(sys.argv[1])
target_uid, target_gid, target_subid = map(int, sys.argv[2:])
legacy_uid = 999
legacy_gid = 999
legacy_subid = 1_000_000
subid_size = 65_536

def translated(value, legacy_root, target_root):
    if value in (0, legacy_root):
        return target_root
    if 0 < value < 65_536:
        return target_subid + value - 1
    if legacy_subid <= value < legacy_subid + subid_size:
        return target_subid + value - legacy_subid
    return value

paths = [root]
for directory, names, files in os.walk(root):
    base = Path(directory)
    paths.extend(base / name for name in names)
    paths.extend(base / name for name in files)
for path in paths:
    stat = path.lstat()
    uid = translated(stat.st_uid, legacy_uid, target_uid)
    gid = translated(stat.st_gid, legacy_gid, target_gid)
    if (uid, gid) != (stat.st_uid, stat.st_gid):
        os.lchown(path, uid, gid)
PY
}

grant_shared_access() {
  local path="$1"
  local user="$2"
  [ -n "$path" ] && [ -d "$path" ] || return 0
  setfacl -Rm "u:${user}:rwX" "$path"
  setfacl -Rdm "u:${user}:rwX" "$path"
}

command -v python3 >/dev/null
python3 - "$BUNDLE/stack.ir.json" "$DOMAINS_FILE" <<'PY' | while IFS="$(printf '\t')" read -r domain strategy source destination; do
import json
import sys

ir = json.load(open(sys.argv[1]))
domain_config = {item["name"]: item for item in json.load(open(sys.argv[2]))["domains"]}
volumes = ir.get("volumes", {})
rootless_services = [svc for svc in ir.get("services", {}).values() if svc.get("placement", "rootful") == "rootless"]
seen = set()

def rootless_host_path(domain, name):
    return domain_config[domain]["volumeRoot"].rstrip("/") + "/" + name

def source_name(volume):
    if isinstance(volume, str):
        return volume.split(":", 1)[0]
    return volume.get("source", "")

for service in rootless_services:
    domain = service.get("rootlessDomain", "webservices")
    for mount in service.get("volumes", []):
        name = source_name(mount)
        volume = volumes.get(name)
        if not volume or "hostPath" not in volume:
            continue
        host_path = volume["hostPath"]
        strategy = volume.get("rootlessStrategy", "copy")
        destination = host_path if strategy == "shared" else rootless_host_path(domain, name)
        row = (domain, strategy, host_path, destination)
        if row not in seen:
            seen.add(row)
            print("\t".join(row))
PY
  domain_index=""
  for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
    if [ "${ROOTLESS_DOMAIN_NAMES[$i]}" = "$domain" ]; then
      domain_index="$i"
      break
    fi
  done
  [ -n "$domain_index" ] || { printf 'unknown rootless volume domain: %s\n' "$domain" >&2; exit 1; }
  domain_user="${ROOTLESS_DOMAIN_USERS[$domain_index]}"
  case "$strategy" in
    shared) grant_shared_access "$source" "$domain_user" ;;
    copy|"") copy_tree_once "$source" "$destination" "$domain_user" ;;
    forbidden) printf 'rootless volume is forbidden: %s\n' "$source" >&2; exit 1 ;;
    *) printf 'unknown rootless volume strategy %s for %s\n' "$strategy" "$source" >&2; exit 1 ;;
  esac
  if [ "$strategy" != "shared" ]; then
    translate_rootless_volume_owner "$destination" "$domain_user" "${ROOTLESS_DOMAIN_SUBUID_STARTS[$domain_index]}"
    # The domain parent remains 0700.  Allow mapped container users to traverse
    # each individual volume root without exposing it to sibling domains.
    chmod u+rwx,go+x "$destination"
  fi
done

install_runtime_env_unit() {
  local unit_file="$1" dropin_dir="$2" source_dir="$3" runtime_dir="$4" owner="${5:-root}" group="${6:-root}"
  install -d -m 0755 -o "$owner" -g "$group" "${unit_file%/*}" "$dropin_dir"
  printf '%s\n' \
    '[Unit]' \
    'Description=Restore rendered webservices environment files' \
    '' \
    '[Service]' \
    'Type=oneshot' \
    "ExecStart=/bin/sh -ec '/usr/bin/install -d -m 0700 $runtime_dir; /usr/bin/find $source_dir -maxdepth 1 -type f -name \"*.env\" -exec /usr/bin/install -m 0600 {} $runtime_dir/ \\;'" \
    'RemainAfterExit=yes' \
    >"$unit_file"
  printf '%s\n' \
    '[Unit]' \
    'Requires=webservices-runtime-env.service' \
    'After=webservices-runtime-env.service' \
    >"$dropin_dir/10-runtime-env.conf"
  chown "$owner:$group" "$unit_file" "$dropin_dir/10-runtime-env.conf"
  chmod 0644 "$unit_file" "$dropin_dir/10-runtime-env.conf"
}

ln -sfn "$release" "$STATE_ROOT/.current-new"
mv -Tf "$STATE_ROOT/.current-new" "$STATE_ROOT/current"
for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
  state_root="${ROOTLESS_DOMAIN_STATE_ROOTS[$i]}"
  rootless_release="${ROOTLESS_RELEASES[$i]}"
  ln -sfn "$rootless_release" "$state_root/.current-new"
  mv -Tf "$state_root/.current-new" "$state_root/current"
done
find "$QUADLET_DIR" -maxdepth 1 -type f -name 'webservices-*' -delete
find /etc/systemd/system -maxdepth 1 -type f -name 'webservices-*.target' -delete
find /etc/systemd/system -maxdepth 1 -type f -name 'webservices.target' -delete
find "$release/quadlet/rootful" -maxdepth 1 -type f ! -name '*.target' -exec install -m 0644 {} "$QUADLET_DIR/" \;
install -m 0644 "$release/quadlet/rootful"/*.target /etc/systemd/system/
install_runtime_env_unit \
  /etc/systemd/system/webservices-runtime-env.service \
  /etc/systemd/system/webservices.target.d \
  "$STATE_ROOT/runtime-env" \
  /run/webservices
for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
  domain="${ROOTLESS_DOMAIN_NAMES[$i]}"
  user="${ROOTLESS_DOMAIN_USERS[$i]}"
  rootless_release="${ROOTLESS_RELEASES[$i]}"
  rootless_quadlet_dir="${ROOTLESS_QUADLET_DIRS[$i]}"
  rootless_systemd_dir="${ROOTLESS_SYSTEMD_DIRS[$i]}"
  find "$rootless_quadlet_dir" -maxdepth 1 -type f -name 'webservices-*' -delete
  find "$rootless_systemd_dir" -maxdepth 1 -type f -name 'webservices-*.target' -delete
  find "$rootless_systemd_dir" -maxdepth 1 -type f -name 'webservices.target' -delete
  find "$rootless_release/quadlet/rootless-$domain" -maxdepth 1 -type f ! -name '*.target' -exec install -m 0644 -o "$user" -g "$user" {} "$rootless_quadlet_dir/" \;
  install -m 0644 -o "$user" -g "$user" "$rootless_release/quadlet/rootless-$domain"/*.target "$rootless_systemd_dir/"
  install_runtime_env_unit \
    "$rootless_systemd_dir/webservices-runtime-env.service" \
    "$rootless_systemd_dir/webservices.target.d" \
    "${ROOTLESS_ENV_STORES[$i]}" \
    "${ROOTLESS_RUNTIMES[$i]}" \
    "$user" \
    "$user"
done
install -m 0755 "$release/ops/webservices-auto-update" /usr/local/sbin/webservices-auto-update
install -m 0644 "$release/ops/webservices-auto-update.service" "$release/ops/webservices-auto-update.timer" /etc/systemd/system/

rollback() {
  status=$?
  printf '[podman-install] activation failed; restoring previous release\n' >&2
  cancel_webservices_start_jobs rootful 0
  systemctl stop webservices.target || true
  for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
    cancel_webservices_start_jobs rootless "$i"
    user_systemctl "$i" stop webservices.target || true
  done
  for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
    previous_rootless="${ROOTLESS_PREVIOUS[$i]}"
    state_root="${ROOTLESS_DOMAIN_STATE_ROOTS[$i]}"
    if [ -n "$previous_rootless" ] && [ -d "$previous_rootless" ]; then
      domain="${ROOTLESS_DOMAIN_NAMES[$i]}"
      user="${ROOTLESS_DOMAIN_USERS[$i]}"
      rootless_quadlet_dir="${ROOTLESS_QUADLET_DIRS[$i]}"
      rootless_systemd_dir="${ROOTLESS_SYSTEMD_DIRS[$i]}"
      ln -sfn "$previous_rootless" "$state_root/.current-old"
      mv -Tf "$state_root/.current-old" "$state_root/current"
      find "$rootless_quadlet_dir" -maxdepth 1 -type f -name 'webservices-*' -delete
      find "$rootless_systemd_dir" -maxdepth 1 -type f -name 'webservices-*.target' -delete
      find "$rootless_systemd_dir" -maxdepth 1 -type f -name 'webservices.target' -delete
      previous_rootless_quadlet="$previous_rootless/quadlet/rootless-$domain"
      find "$previous_rootless_quadlet" -maxdepth 1 -type f ! -name '*.target' -exec install -m 0644 -o "$user" -g "$user" {} "$rootless_quadlet_dir/" \;
      install -m 0644 -o "$user" -g "$user" "$previous_rootless_quadlet"/*.target "$rootless_systemd_dir/"
      user_systemctl "$i" daemon-reload || true
      user_systemctl "$i" reset-failed || true
      user_systemctl "$i" restart webservices.target || true
    fi
  done
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
if [ "$ACTIVATION_ROLLBACK" = "1" ]; then
  trap rollback ERR
else
  trap - ERR
  printf '[podman-install] automatic rollback disabled; activation failures will remain in place for fix-forward repair\n' >&2
fi

wait_for_target_services() {
  local mode="$1" index="$2" target_dir="$3" deadline unit state unit_type result job pending pending_unit
  local -a units=()
  while IFS= read -r unit; do
    [ -n "$unit" ] && units+=("$unit")
  done < <(awk '/^Wants=/ {sub(/^Wants=/, ""); for (i = 1; i <= NF; i++) print $i}' "$target_dir"/webservices-*.target 2>/dev/null | sort -u)
  deadline=$((SECONDS + ${WEBSERVICES_ACTIVATION_TIMEOUT_SECONDS:-1800}))
  while true; do
    pending=0
    pending_unit=""
    for unit in "${units[@]}"; do
      if [ "$mode" = "rootless" ]; then
        state="$(user_systemctl "$index" is-active "$unit" 2>/dev/null || true)"
        unit_type="$(user_systemctl "$index" show -p Type --value "$unit" 2>/dev/null || true)"
        result="$(user_systemctl "$index" show -p Result --value "$unit" 2>/dev/null || true)"
        job="$(user_systemctl "$index" show -p Job --value "$unit" 2>/dev/null || true)"
      else
        state="$(systemctl is-active "$unit" 2>/dev/null || true)"
        unit_type="$(systemctl show -p Type --value "$unit" 2>/dev/null || true)"
        result="$(systemctl show -p Result --value "$unit" 2>/dev/null || true)"
        job="$(systemctl show -p Job --value "$unit" 2>/dev/null || true)"
      fi
      [ "$state" = "active" ] && continue
      [ "$unit_type" = "oneshot" ] && [ "$state" = "inactive" ] && [ "$result" = "success" ] && continue
      if [ "$state" = "failed" ] && [ -z "$job" ]; then
        printf '[podman-install] service readiness failed: unit=%s state=%s type=%s result=%s\n' "$unit" "$state" "$unit_type" "$result" >&2
        if [ "$mode" = "rootless" ]; then
          user_systemctl "$index" status "$unit" --no-pager -l >&2 || true
        else
          systemctl status "$unit" --no-pager -l >&2 || true
        fi
        return 1
      fi
      pending=$((pending + 1))
      [ -n "$pending_unit" ] || pending_unit="$unit"
    done
    [ "$pending" -eq 0 ] && return 0
    if [ "$SECONDS" -ge "$deadline" ]; then
      printf '[podman-install] service readiness timed out: pending=%s first=%s\n' "$pending" "$pending_unit" >&2
      if [ "$mode" = "rootless" ]; then
        user_systemctl "$index" status "$pending_unit" --no-pager -l >&2 || true
      else
        systemctl status "$pending_unit" --no-pager -l >&2 || true
      fi
      return 1
    fi
    sleep 2
  done
}

restart_rootful_network_units() {
  local units=()
  while IFS= read -r unit; do
    [ -n "$unit" ] && units+=("$unit")
  done < <(systemctl list-unit-files 'webservices-*-network.service' --no-legend --no-pager | awk '{print $1}')
  [ "${#units[@]}" -eq 0 ] || systemctl restart "${units[@]}"
}

restart_rootless_network_units() {
  local index="$1" units=()
  while IFS= read -r unit; do
    [ -n "$unit" ] && units+=("$unit")
  done < <(user_systemctl "$index" list-unit-files 'webservices-*-network.service' --no-legend --no-pager | awk '{print $1}')
  [ "${#units[@]}" -eq 0 ] || user_systemctl "$index" restart "${units[@]}"
}

wait_for_cross_domain_producers() {
  local endpoints="$BUNDLE/podman-loopback-endpoints.json"
  local service domain index unit state deadline
  [ -f "$endpoints" ] || return 0
  while IFS=$'\t' read -r service domain; do
    [ -n "$service" ] && [ -n "$domain" ] || continue
    unit="webservices-${service}.service"
    index="$(domain_index_by_name "$domain")"
    deadline=$((SECONDS + ${WEBSERVICES_ACTIVATION_TIMEOUT_SECONDS:-1800}))
    while true; do
      state="$(user_systemctl "$index" is-active "$unit" 2>/dev/null || true)"
      [ "$state" = "active" ] && break
      if [ "$state" = "failed" ]; then
        printf '[podman-install] cross-domain producer failed: domain=%s unit=%s\n' "$domain" "$unit" >&2
        user_systemctl "$index" status "$unit" --no-pager -l >&2 || true
        return 1
      fi
      if [ "$SECONDS" -ge "$deadline" ]; then
        printf '[podman-install] cross-domain producer timed out: domain=%s unit=%s state=%s\n' "$domain" "$unit" "$state" >&2
        return 1
      fi
      sleep 2
    done
  done < <(jq -r --slurpfile ir "$BUNDLE/stack.ir.json" '
    .endpoints[]
    | select(any(.consumers[]; . != "rootful"))
    | [.service, ($ir[0].services[.service].rootlessDomain // "")]
    | @tsv
  ' "$endpoints" | sort -u)
}

retry_failed_rootless_services() {
  local attempt i unit retried quiet_passes=0
  for attempt in $(seq 1 12); do
    retried=0
    for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
      while IFS= read -r unit; do
        [ -n "$unit" ] || continue
        printf '[podman-install] retrying service after cross-domain producers became ready: attempt=%s domain=%s unit=%s\n' "$attempt" "${ROOTLESS_DOMAIN_NAMES[$i]}" "$unit" >&2
        user_systemctl "$i" reset-failed "$unit"
        user_systemctl "$i" --no-block restart "$unit"
        retried=1
      done < <(user_systemctl "$i" --failed --no-legend --plain 'webservices-*' 2>/dev/null | awk '{print $1}')
    done
    if [ "$retried" -eq 1 ]; then
      quiet_passes=0
    else
      quiet_passes=$((quiet_passes + 1))
      # A target can become active before its long-running bootstrap reaches a
      # cross-domain database or cache.  Require a quiet window so failures
      # that surface shortly after producer activation are retried here rather
      # than escaping into the final readiness check.
      [ "$quiet_passes" -lt 6 ] || return 0
    fi
    sleep 5
  done
}

grant_test_runner_managed_socket_access() {
  local launch_domain managed_domain launch_index managed_index launch_user
  launch_domain="$(jq -r '.services["test-runner"].rootlessDomain // empty' "$BUNDLE/stack.ir.json")"
  managed_domain="$(jq -r '.services["test-runner-managed"].rootlessDomain // empty' "$BUNDLE/stack.ir.json")"
  [ -n "$launch_domain" ] && [ -n "$managed_domain" ] || return 0
  launch_index="$(domain_index_by_name "$launch_domain")"
  managed_index="$(domain_index_by_name "$managed_domain")"
  [ "$launch_index" != "$managed_index" ] || return 0
  launch_user="${ROOTLESS_DOMAIN_USERS[$launch_index]}"
  local managed_user="${ROOTLESS_DOMAIN_USERS[$managed_index]}"
  local managed_uid="${ROOTLESS_UIDS[$managed_index]}"
  local runtime_dir="/run/user/${managed_uid}"
  local podman_dir="$runtime_dir/podman"
  local socket="$podman_dir/podman.sock"

  id -nG "$launch_user" | tr ' ' '\n' | grep -Fxq "$managed_user" || usermod --append --groups "$managed_user" "$launch_user"
  [ -d "$runtime_dir" ] && chgrp "$managed_user" "$runtime_dir" && chmod g+x "$runtime_dir"
  [ -d "$podman_dir" ] && chgrp "$managed_user" "$podman_dir" && chmod g+x "$podman_dir"
  # The test-runner container sees this cross-user socket as nobody:nogroup
  # under rootless user namespaces, so group mode is insufficient inside the
  # container. This socket belongs to the isolated test-runners domain only.
  [ -S "$socket" ] && chgrp "$managed_user" "$socket" && chmod go+rw "$socket"
}

systemctl daemon-reload
restart_rootful_network_units
if systemctl list-unit-files webservices-caddy.service --no-legend --no-pager | grep -q '^webservices-caddy\.service'; then
  systemctl restart webservices-caddy.service || true
fi
for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
  user_systemctl "$i" daemon-reload
  user_systemctl "$i" reset-failed 'webservices-*' || true
  user_systemctl "$i" enable podman.socket
  user_systemctl "$i" restart podman.socket
  user_systemctl "$i" enable webservices.target
  restart_rootless_network_units "$i"
done
grant_test_runner_managed_socket_access
systemctl enable --now webservices-auto-update.timer
for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
  user_systemctl "$i" --no-block restart webservices.target
done
wait_for_cross_domain_producers
retry_failed_rootless_services
for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
  wait_for_target_services rootless "$i" "${ROOTLESS_SYSTEMD_DIRS[$i]}"
  user_systemctl "$i" --quiet is-active webservices.target
done
systemctl reset-failed 'webservices-*' || true
systemctl enable webservices.target
systemctl restart webservices.target
wait_for_target_services rootful 0 /etc/systemd/system
systemctl --quiet is-active webservices.target
trap - ERR
printf '[podman-install] active rootful release: %s\n' "$release"
for i in "${!ROOTLESS_DOMAIN_NAMES[@]}"; do
  printf '[podman-install] active rootless %s release: %s\n' "${ROOTLESS_DOMAIN_NAMES[$i]}" "${ROOTLESS_RELEASES[$i]}"
done
