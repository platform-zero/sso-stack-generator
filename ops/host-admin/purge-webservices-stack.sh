#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
STACK_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
STORAGE_PURGE_SCRIPT="$SCRIPT_DIR/purge-site-storage-dirs.sh"
SCRIPT_NAME="$(basename "$0")"
EXPECTED_HOSTNAME="${EXPECTED_HOSTNAME:-}"
STACK_USER="${STACK_USER:-$USER}"
STACK_PROJECT_NAME="${STACK_PROJECT_NAME:-webservices}"
STACK_DEPLOY_DIR="${STACK_DEPLOY_DIR:-}"
CONTAINER_CLI="${CONTAINER_CLI:-podman}"
CONFIRMED=0
PRINT_ONLY=0
PRUNE_CONTAINER_CACHE=0
PURGE_STORAGE=0
ALL_CONTAINERS=0
PURGE_LABWARE_RUNTIME=1
LABWARE_CONTAINER_HOST="${LABWARE_CONTAINER_HOST:-unix:///run/labware/podman.sock}"

log() {
  printf '[%s] %s\n' "$SCRIPT_NAME" "$*" >&2
}

die() {
  printf '[%s] ERROR: %s\n' "$SCRIPT_NAME" "$*" >&2
  exit 1
}

usage() {
  cat <<EOF_USAGE
Usage:
  EXPECTED_HOSTNAME=<host> ./ops/host-admin/purge-webservices-stack.sh [options] --yes-delete-webservices-stack

Stops and removes the webservices stack from the systemd --user runtime path.

Options:
  --print-only                  Print stack, container, labware, storage, and deploy targets without deleting.
  --purge-storage               Also delete the hardcoded site storage directories.
  --prune-container-cache       Also run container system/builder prune for a fully cold rebuild.
  --all-containers              Remove all managed containers and volumes on the host, not just the webservices project.
  --skip-labware-runtime        Do not purge disposable workspace/test resources from the isolated labware container runtime.
  --labware-container-host <host>  Container host for labware runtime cleanup. Default: $LABWARE_CONTAINER_HOST
  --stack-user <user>           User that owns the systemd --user units and deploy dir. Default: $STACK_USER
  --stack-deploy-dir <path>     Deploy directory to delete after stopping the stack. Default: $STACK_DEPLOY_DIR
  --stack-project-name <name>   Container project name. Default: $STACK_PROJECT_NAME
  -h, --help                    Show this help text.

Examples:
  EXPECTED_HOSTNAME=<host> ./ops/host-admin/purge-webservices-stack.sh --yes-delete-webservices-stack
  EXPECTED_HOSTNAME=<host> ./ops/host-admin/purge-webservices-stack.sh --all-containers --yes-delete-webservices-stack
  EXPECTED_HOSTNAME=<host> ./ops/host-admin/purge-webservices-stack.sh --purge-storage --prune-container-cache --yes-delete-webservices-stack
EOF_USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --print-only)
      PRINT_ONLY=1
      ;;
    --purge-storage)
      PURGE_STORAGE=1
      ;;
    --prune-container-cache)
      PRUNE_CONTAINER_CACHE=1
      ;;
    --all-containers)
      ALL_CONTAINERS=1
      ;;
    --skip-labware-runtime)
      PURGE_LABWARE_RUNTIME=0
      ;;
    --labware-container-host)
      LABWARE_CONTAINER_HOST="$2"
      shift
      ;;
    --stack-user)
      STACK_USER="$2"
      shift
      ;;
    --stack-deploy-dir)
      STACK_DEPLOY_DIR="$2"
      shift
      ;;
    --stack-project-name)
      STACK_PROJECT_NAME="$2"
      shift
      ;;
    --yes-delete-webservices-stack)
      CONFIRMED=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
  shift
done

current_hostname="$(hostname -s 2>/dev/null || hostname 2>/dev/null || printf 'unknown')"
[ "$current_hostname" = "$EXPECTED_HOSTNAME" ] || die "refusing to run on host '$current_hostname' (expected '$EXPECTED_HOSTNAME')"

command -v "$CONTAINER_CLI" >/dev/null 2>&1 || die "missing required command: $CONTAINER_CLI"
command -v getent >/dev/null 2>&1 || die "missing required command: getent"
command -v jq >/dev/null 2>&1 || die "missing required command: jq"

stack_user_home="$(getent passwd "$STACK_USER" | cut -d: -f6)"
[ -n "$stack_user_home" ] || die "unable to resolve home directory for user $STACK_USER"
STACK_DEPLOY_DIR="${STACK_DEPLOY_DIR:-$stack_user_home/webservices}"

default_auxiliary_targets() {
  local graph_file="$STACK_DEPLOY_DIR/build/stack.systemd/graph.json"
  if [ -f "$graph_file" ]; then
    jq -r '
      (.defaultTarget.wantsTargets // []) as $wanted
      | (.auxiliaryTargets // [] | .[]?.name | . as $target | select($target != null and ($wanted | index($target)) != null))
    ' "$graph_file"
  fi
}

print_container_targets() {
  printf 'Stack purge target:\n'
  printf '  host: %s\n' "$current_hostname"
  printf '  user: %s\n' "$STACK_USER"
  printf '  deploy dir: %s\n' "$STACK_DEPLOY_DIR"
  printf '  runtime dir: /run/user/%s/webservices-runtime\n' "$(id -u "$STACK_USER")"
  printf '  test results dir: %s/webservices-test-results\n' "$stack_user_home"
  printf '  project: %s\n' "$STACK_PROJECT_NAME"
  printf '  container cli: %s\n' "$CONTAINER_CLI"
  printf '  all containers: %s\n' "$ALL_CONTAINERS"
  printf '  purge storage: %s\n' "$PURGE_STORAGE"
  printf '  purge labware runtime: %s\n' "$PURGE_LABWARE_RUNTIME"
  printf '  labware container host: %s\n' "$LABWARE_CONTAINER_HOST"

  printf '\nContainers:\n'
  list_target_container_names | sed 's/^/  /'

  printf '\nNetworks:\n'
  list_target_network_names | sed 's/^/  /'

  printf '\nVolumes:\n'
  list_target_volume_names | sed 's/^/  /'

  if [ "$PURGE_LABWARE_RUNTIME" = "1" ]; then
    printf '\nLabware container resources:\n'
    if container_host_available "$LABWARE_CONTAINER_HOST"; then
      container_for_host "$LABWARE_CONTAINER_HOST" ps -a --filter "label=webservices.workspace.id" --format '  workspace container {{.Names}}'
      container_for_host "$LABWARE_CONTAINER_HOST" ps -a --filter "label=webservices.test.tenant.id" --format '  test container {{.Names}}'
      container_for_host "$LABWARE_CONTAINER_HOST" volume ls --filter "label=webservices.workspace.id" --format '  workspace volume {{.Name}}'
      container_for_host "$LABWARE_CONTAINER_HOST" volume ls --filter "label=webservices.test.tenant.id" --format '  test volume {{.Name}}'
    else
      printf '  unavailable at %s\n' "$LABWARE_CONTAINER_HOST"
    fi
  fi

  if [ "$PURGE_STORAGE" = "1" ]; then
    printf '\n'
    "$STORAGE_PURGE_SCRIPT" --print-only
  fi
}

systemd_user_env=("XDG_RUNTIME_DIR=/run/user/$(id -u "$STACK_USER")" "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/$(id -u "$STACK_USER")/bus")
run_user_systemctl() {
  sudo -u "$STACK_USER" env "${systemd_user_env[@]}" systemctl --user "$@"
}

container_for_host() {
  local container_host="$1"
  shift
  if [ -n "$container_host" ]; then
    CONTAINER_HOST="$container_host" "$CONTAINER_CLI" --remote "$@"
  else
    "$CONTAINER_CLI" "$@"
  fi
}

container_host_available() {
  local container_host="$1"
  container_for_host "$container_host" info >/dev/null 2>&1
}

dedupe_lines() {
  awk 'NF && !seen[$0]++'
}

list_target_container_ids() {
  if [ "$ALL_CONTAINERS" = "1" ]; then
    "$CONTAINER_CLI" ps -aq
    return 0
  fi

  {
    "$CONTAINER_CLI" ps -aq --filter "label=org.platform-zero.runtime.project=$STACK_PROJECT_NAME"
    "$CONTAINER_CLI" ps -a --format '{{.ID}} {{.Names}}' |
      awk -v prefix="${STACK_PROJECT_NAME}_" 'index($2, prefix) == 1 { print $1 }'
  } | dedupe_lines
}

list_target_container_names() {
  if [ "$ALL_CONTAINERS" = "1" ]; then
    "$CONTAINER_CLI" ps -a --format '{{.Names}}'
    return 0
  fi

  {
    "$CONTAINER_CLI" ps -a --filter "label=org.platform-zero.runtime.project=$STACK_PROJECT_NAME" --format '{{.Names}}'
    "$CONTAINER_CLI" ps -a --format '{{.Names}}' |
      awk -v prefix="${STACK_PROJECT_NAME}_" 'index($0, prefix) == 1 { print }'
  } | dedupe_lines
}

list_target_network_ids() {
  if [ "$ALL_CONTAINERS" = "1" ]; then
    "$CONTAINER_CLI" network ls -q --filter "type=custom"
    return 0
  fi

  {
    "$CONTAINER_CLI" network ls -q --filter "label=org.platform-zero.runtime.project=$STACK_PROJECT_NAME"
    "$CONTAINER_CLI" network ls --format '{{.ID}} {{.Name}}' |
      awk -v prefix="${STACK_PROJECT_NAME}_" 'index($2, prefix) == 1 { print $1 }'
  } | dedupe_lines
}

list_target_network_names() {
  if [ "$ALL_CONTAINERS" = "1" ]; then
    "$CONTAINER_CLI" network ls --filter "type=custom" --format '{{.Name}}'
    return 0
  fi

  {
    "$CONTAINER_CLI" network ls --filter "label=org.platform-zero.runtime.project=$STACK_PROJECT_NAME" --format '{{.Name}}'
    "$CONTAINER_CLI" network ls --format '{{.Name}}' |
      awk -v prefix="${STACK_PROJECT_NAME}_" 'index($0, prefix) == 1 { print }'
  } | dedupe_lines
}

list_target_volume_names() {
  if [ "$ALL_CONTAINERS" = "1" ]; then
    "$CONTAINER_CLI" volume ls -q
    return 0
  fi

  {
    "$CONTAINER_CLI" volume ls -q --filter "label=org.platform-zero.runtime.project=$STACK_PROJECT_NAME"
    "$CONTAINER_CLI" volume ls -q |
      awk -v prefix="${STACK_PROJECT_NAME}_" 'index($0, prefix) == 1 { print }'
  } | dedupe_lines
}

remove_containers_by_filter() {
  local container_host="$1"
  local description="$2"
  shift 2
  local containers=()
  mapfile -t containers < <(container_for_host "$container_host" ps -aq "$@")
  if [ "${#containers[@]}" -gt 0 ]; then
    log "removing $description containers: ${#containers[@]}"
    container_for_host "$container_host" rm -f "${containers[@]}" >/dev/null
  else
    log "no $description containers found"
  fi
}

remove_volumes_by_filter() {
  local container_host="$1"
  local description="$2"
  shift 2
  local volumes=()
  mapfile -t volumes < <(container_for_host "$container_host" volume ls -q "$@")
  if [ "${#volumes[@]}" -gt 0 ]; then
    log "removing $description volumes: ${#volumes[@]}"
    container_for_host "$container_host" volume rm "${volumes[@]}" >/dev/null
  else
    log "no $description volumes found"
  fi
}

purge_labware_runtime() {
  if [ "$PURGE_LABWARE_RUNTIME" != "1" ]; then
    log "skipping isolated labware runtime purge"
    return 0
  fi

  if ! container_host_available "$LABWARE_CONTAINER_HOST"; then
    log "labware container host unavailable at $LABWARE_CONTAINER_HOST; skipping disposable workspace cleanup"
    return 0
  fi

  log "purging disposable workspace/test resources from labware container host $LABWARE_CONTAINER_HOST"
  remove_containers_by_filter "$LABWARE_CONTAINER_HOST" "labware workspace" --filter "label=webservices.workspace.id"
  remove_containers_by_filter "$LABWARE_CONTAINER_HOST" "labware test" --filter "label=webservices.test.tenant.id"
  remove_volumes_by_filter "$LABWARE_CONTAINER_HOST" "labware workspace" --filter "label=webservices.workspace.id"
  remove_volumes_by_filter "$LABWARE_CONTAINER_HOST" "labware test" --filter "label=webservices.test.tenant.id"

  if [ "$PRUNE_CONTAINER_CACHE" = "1" ]; then
    log "pruning labware container images, build cache, and unused volumes"
    container_for_host "$LABWARE_CONTAINER_HOST" system prune -a --volumes -f >/dev/null
    container_for_host "$LABWARE_CONTAINER_HOST" builder prune -a -f >/dev/null
  fi
}

if [ "$PRINT_ONLY" = "1" ]; then
  print_container_targets
  exit 0
fi

[ "$CONFIRMED" = "1" ] || die "missing required --yes-delete-webservices-stack"
[ -n "$EXPECTED_HOSTNAME" ] || die "EXPECTED_HOSTNAME must be set for destructive execution"

command -v sudo >/dev/null 2>&1 || die "missing required command: sudo"
command -v systemctl >/dev/null 2>&1 || die "missing required command: systemctl"

# Disposable Workspaces run on the isolated labware container runtime through
# the stack's tunnel. Purge those labeled resources before stopping the tunnel services.
purge_labware_runtime

log "stopping systemd --user webservices target for $STACK_USER if present"
if [ -S "/run/user/$(id -u "$STACK_USER")/bus" ]; then
  mapfile -t auxiliary_targets < <(default_auxiliary_targets)
  if [ "${#auxiliary_targets[@]}" -gt 0 ]; then
    run_user_systemctl stop "${auxiliary_targets[@]}" >/dev/null 2>&1 || true
  fi
  run_user_systemctl stop webservices.target >/dev/null 2>&1 || true
  run_user_systemctl disable webservices.target >/dev/null 2>&1 || true
  run_user_systemctl reset-failed >/dev/null 2>&1 || true
else
  log "user bus for $STACK_USER is not available; skipping systemd --user stop"
fi

user_unit_dir="$(sudo -u "$STACK_USER" env HOME="$stack_user_home" sh -lc 'printf %s "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"')"
if [ -d "$user_unit_dir" ]; then
  log "removing webservices user units from $user_unit_dir"
  find "$user_unit_dir" -maxdepth 1 \( -type f -o -type l \) \( -name 'webservices*.service' -o -name 'webservices*.target' \) -delete
  find "$user_unit_dir" -maxdepth 2 -type l -path "$user_unit_dir/*.wants/webservices*.service" -delete
  find "$user_unit_dir" -maxdepth 2 -type l -path "$user_unit_dir/*.wants/webservices*.target" -delete
fi
if [ -S "/run/user/$(id -u "$STACK_USER")/bus" ]; then
  run_user_systemctl daemon-reload >/dev/null 2>&1 || true
fi

runtime_dir="/run/user/$(id -u "$STACK_USER")/webservices-runtime"
if [ -e "$runtime_dir" ] || [ -L "$runtime_dir" ]; then
  log "removing runtime directory $runtime_dir"
  sudo rm -rf "$runtime_dir"
fi

test_results_dir="$stack_user_home/webservices-test-results"
if [ -e "$test_results_dir" ] || [ -L "$test_results_dir" ]; then
  log "removing test results directory $test_results_dir"
  sudo rm -rf "$test_results_dir"
fi

if [ "$ALL_CONTAINERS" = "1" ]; then
  log "removing all containers on the host via $CONTAINER_CLI"
  mapfile -t project_containers < <(list_target_container_ids)
else
  log "removing containers for project $STACK_PROJECT_NAME by runtime label or ${STACK_PROJECT_NAME}_ name prefix"
  mapfile -t project_containers < <(list_target_container_ids)
fi

if [ "${#project_containers[@]}" -gt 0 ]; then
  "$CONTAINER_CLI" rm -f "${project_containers[@]}" >/dev/null
else
  if [ "$ALL_CONTAINERS" = "1" ]; then
    log "no containers found on the host"
  else
    log "no runtime-labeled containers found for project $STACK_PROJECT_NAME"
  fi
fi

if [ "$ALL_CONTAINERS" = "1" ]; then
  log "removing all custom container networks on the host"
  mapfile -t project_networks < <(list_target_network_ids)
else
  log "removing networks for project $STACK_PROJECT_NAME by runtime label or ${STACK_PROJECT_NAME}_ name prefix"
  mapfile -t project_networks < <(list_target_network_ids)
fi

if [ "${#project_networks[@]}" -gt 0 ]; then
  "$CONTAINER_CLI" network rm "${project_networks[@]}" >/dev/null 2>&1 || true
else
  if [ "$ALL_CONTAINERS" = "1" ]; then
    log "no custom container networks found on the host"
  else
    log "no runtime-labeled networks found for project $STACK_PROJECT_NAME"
  fi
fi

if [ "$ALL_CONTAINERS" = "1" ]; then
  log "removing all volumes on the host via $CONTAINER_CLI"
  mapfile -t project_volumes < <(list_target_volume_names)
else
  log "removing volumes for project $STACK_PROJECT_NAME by runtime label or ${STACK_PROJECT_NAME}_ name prefix"
  mapfile -t project_volumes < <(list_target_volume_names)
fi

if [ "${#project_volumes[@]}" -gt 0 ]; then
  "$CONTAINER_CLI" volume rm "${project_volumes[@]}" >/dev/null
else
  if [ "$ALL_CONTAINERS" = "1" ]; then
    log "no volumes found on the host"
  else
    log "no runtime-labeled volumes found for project $STACK_PROJECT_NAME"
  fi
fi

if [ "$PURGE_STORAGE" = "1" ]; then
  log "purging hardcoded site storage directories"
  EXPECTED_HOSTNAME="$EXPECTED_HOSTNAME" "$STORAGE_PURGE_SCRIPT" --yes-delete-site-storage
fi

if [ -e "$STACK_DEPLOY_DIR" ] || [ -L "$STACK_DEPLOY_DIR" ]; then
  log "removing deploy directory $STACK_DEPLOY_DIR"
  sudo rm -rf "$STACK_DEPLOY_DIR"
else
  log "deploy directory already absent: $STACK_DEPLOY_DIR"
fi

if [ "$PRUNE_CONTAINER_CACHE" = "1" ]; then
  log "pruning container images, build cache, and unused volumes with $CONTAINER_CLI"
  "$CONTAINER_CLI" system prune -a --volumes -f >/dev/null
  "$CONTAINER_CLI" builder prune -a -f >/dev/null
fi

log "stack purge complete"
