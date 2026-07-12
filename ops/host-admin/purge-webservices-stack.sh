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
CONFIRMED=0
PRINT_ONLY=0
PRUNE_DOCKER_CACHE=0
PURGE_STORAGE=0
ALL_DOCKER=0
PURGE_LABWARE_RUNTIME=1
LABWARE_DOCKER_HOST="${LABWARE_DOCKER_HOST:-unix:///run/docker-labware/docker.sock}"

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

Stops and removes the webservices stack regardless of whether it was started via the
old Compose orchestration path or the new systemd --user path.

Options:
  --print-only                  Print stack, Docker, labware, storage, and deploy targets without deleting.
  --purge-storage               Also delete the hardcoded site storage directories.
  --prune-docker-cache          Also run docker system/builder prune for a fully cold rebuild.
  --all-docker                  Remove all Docker containers and volumes on the host, not just the webservices project.
  --skip-labware-runtime        Do not purge disposable workspace/test resources from the isolated Docker runtime.
  --labware-docker-host <host>  Docker host for labware runtime cleanup. Default: $LABWARE_DOCKER_HOST
  --stack-user <user>           User that owns the systemd --user units and deploy dir. Default: $STACK_USER
  --stack-deploy-dir <path>     Deploy directory to delete after stopping the stack. Default: $STACK_DEPLOY_DIR
  --stack-project-name <name>   Docker Compose project name. Default: $STACK_PROJECT_NAME
  -h, --help                    Show this help text.

Examples:
  EXPECTED_HOSTNAME=<host> ./ops/host-admin/purge-webservices-stack.sh --yes-delete-webservices-stack
  EXPECTED_HOSTNAME=<host> ./ops/host-admin/purge-webservices-stack.sh --all-docker --yes-delete-webservices-stack
  EXPECTED_HOSTNAME=<host> ./ops/host-admin/purge-webservices-stack.sh --purge-storage --prune-docker-cache --yes-delete-webservices-stack
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
    --prune-docker-cache)
      PRUNE_DOCKER_CACHE=1
      ;;
    --all-docker)
      ALL_DOCKER=1
      ;;
    --skip-labware-runtime)
      PURGE_LABWARE_RUNTIME=0
      ;;
    --labware-docker-host)
      LABWARE_DOCKER_HOST="$2"
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

command -v docker >/dev/null 2>&1 || die "missing required command: docker"
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

print_docker_targets() {
  printf 'Stack purge target:\n'
  printf '  host: %s\n' "$current_hostname"
  printf '  user: %s\n' "$STACK_USER"
  printf '  deploy dir: %s\n' "$STACK_DEPLOY_DIR"
  printf '  runtime dir: /run/user/%s/webservices-runtime\n' "$(id -u "$STACK_USER")"
  printf '  test results dir: %s/webservices-test-results\n' "$stack_user_home"
  printf '  project: %s\n' "$STACK_PROJECT_NAME"
  printf '  all docker: %s\n' "$ALL_DOCKER"
  printf '  purge storage: %s\n' "$PURGE_STORAGE"
  printf '  purge labware runtime: %s\n' "$PURGE_LABWARE_RUNTIME"
  printf '  labware docker host: %s\n' "$LABWARE_DOCKER_HOST"

  printf '\nDocker containers:\n'
  list_target_container_names | sed 's/^/  /'

  printf '\nDocker networks:\n'
  list_target_network_names | sed 's/^/  /'

  printf '\nDocker volumes:\n'
  list_target_volume_names | sed 's/^/  /'

  if [ "$PURGE_LABWARE_RUNTIME" = "1" ]; then
    printf '\nLabware Docker resources:\n'
    if docker_host_available "$LABWARE_DOCKER_HOST"; then
      docker_for_host "$LABWARE_DOCKER_HOST" ps -a --filter "label=webservices.workspace.id" --format '  workspace container {{.Names}}'
      docker_for_host "$LABWARE_DOCKER_HOST" ps -a --filter "label=webservices.test.tenant.id" --format '  test container {{.Names}}'
      docker_for_host "$LABWARE_DOCKER_HOST" volume ls --filter "label=webservices.workspace.id" --format '  workspace volume {{.Name}}'
      docker_for_host "$LABWARE_DOCKER_HOST" volume ls --filter "label=webservices.test.tenant.id" --format '  test volume {{.Name}}'
    else
      printf '  unavailable at %s\n' "$LABWARE_DOCKER_HOST"
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

docker_for_host() {
  local docker_host="$1"
  shift
  if [ -n "$docker_host" ]; then
    DOCKER_HOST="$docker_host" docker "$@"
  else
    docker "$@"
  fi
}

docker_host_available() {
  local docker_host="$1"
  docker_for_host "$docker_host" info >/dev/null 2>&1
}

dedupe_lines() {
  awk 'NF && !seen[$0]++'
}

list_target_container_ids() {
  if [ "$ALL_DOCKER" = "1" ]; then
    docker ps -aq
    return 0
  fi

  {
    docker ps -aq --filter "label=com.docker.compose.project=$STACK_PROJECT_NAME"
    docker ps -a --format '{{.ID}} {{.Names}}' |
      awk -v prefix="${STACK_PROJECT_NAME}_" 'index($2, prefix) == 1 { print $1 }'
  } | dedupe_lines
}

list_target_container_names() {
  if [ "$ALL_DOCKER" = "1" ]; then
    docker ps -a --format '{{.Names}}'
    return 0
  fi

  {
    docker ps -a --filter "label=com.docker.compose.project=$STACK_PROJECT_NAME" --format '{{.Names}}'
    docker ps -a --format '{{.Names}}' |
      awk -v prefix="${STACK_PROJECT_NAME}_" 'index($0, prefix) == 1 { print }'
  } | dedupe_lines
}

list_target_network_ids() {
  if [ "$ALL_DOCKER" = "1" ]; then
    docker network ls -q --filter "type=custom"
    return 0
  fi

  {
    docker network ls -q --filter "label=com.docker.compose.project=$STACK_PROJECT_NAME"
    docker network ls --format '{{.ID}} {{.Name}}' |
      awk -v prefix="${STACK_PROJECT_NAME}_" 'index($2, prefix) == 1 { print $1 }'
  } | dedupe_lines
}

list_target_network_names() {
  if [ "$ALL_DOCKER" = "1" ]; then
    docker network ls --filter "type=custom" --format '{{.Name}}'
    return 0
  fi

  {
    docker network ls --filter "label=com.docker.compose.project=$STACK_PROJECT_NAME" --format '{{.Name}}'
    docker network ls --format '{{.Name}}' |
      awk -v prefix="${STACK_PROJECT_NAME}_" 'index($0, prefix) == 1 { print }'
  } | dedupe_lines
}

list_target_volume_names() {
  if [ "$ALL_DOCKER" = "1" ]; then
    docker volume ls -q
    return 0
  fi

  {
    docker volume ls -q --filter "label=com.docker.compose.project=$STACK_PROJECT_NAME"
    docker volume ls -q |
      awk -v prefix="${STACK_PROJECT_NAME}_" 'index($0, prefix) == 1 { print }'
  } | dedupe_lines
}

remove_containers_by_filter() {
  local docker_host="$1"
  local description="$2"
  shift 2
  local containers=()
  mapfile -t containers < <(docker_for_host "$docker_host" ps -aq "$@")
  if [ "${#containers[@]}" -gt 0 ]; then
    log "removing $description containers: ${#containers[@]}"
    docker_for_host "$docker_host" rm -f "${containers[@]}" >/dev/null
  else
    log "no $description containers found"
  fi
}

remove_volumes_by_filter() {
  local docker_host="$1"
  local description="$2"
  shift 2
  local volumes=()
  mapfile -t volumes < <(docker_for_host "$docker_host" volume ls -q "$@")
  if [ "${#volumes[@]}" -gt 0 ]; then
    log "removing $description volumes: ${#volumes[@]}"
    docker_for_host "$docker_host" volume rm "${volumes[@]}" >/dev/null
  else
    log "no $description volumes found"
  fi
}

purge_labware_runtime() {
  if [ "$PURGE_LABWARE_RUNTIME" != "1" ]; then
    log "skipping isolated labware runtime purge"
    return 0
  fi

  if ! docker_host_available "$LABWARE_DOCKER_HOST"; then
    log "labware Docker host unavailable at $LABWARE_DOCKER_HOST; skipping disposable workspace cleanup"
    return 0
  fi

  log "purging disposable workspace/test resources from labware Docker host $LABWARE_DOCKER_HOST"
  remove_containers_by_filter "$LABWARE_DOCKER_HOST" "labware workspace" --filter "label=webservices.workspace.id"
  remove_containers_by_filter "$LABWARE_DOCKER_HOST" "labware test" --filter "label=webservices.test.tenant.id"
  remove_volumes_by_filter "$LABWARE_DOCKER_HOST" "labware workspace" --filter "label=webservices.workspace.id"
  remove_volumes_by_filter "$LABWARE_DOCKER_HOST" "labware test" --filter "label=webservices.test.tenant.id"

  if [ "$PRUNE_DOCKER_CACHE" = "1" ]; then
    log "pruning labware Docker images, build cache, and unused volumes"
    docker_for_host "$LABWARE_DOCKER_HOST" system prune -a --volumes -f >/dev/null
    docker_for_host "$LABWARE_DOCKER_HOST" builder prune -a -f >/dev/null
  fi
}

if [ "$PRINT_ONLY" = "1" ]; then
  print_docker_targets
  exit 0
fi

[ "$CONFIRMED" = "1" ] || die "missing required --yes-delete-webservices-stack"
[ -n "$EXPECTED_HOSTNAME" ] || die "EXPECTED_HOSTNAME must be set for destructive execution"

command -v sudo >/dev/null 2>&1 || die "missing required command: sudo"
command -v systemctl >/dev/null 2>&1 || die "missing required command: systemctl"

# Disposable Workspaces run on the isolated Docker runtime through the stack's
# tunnel. Purge those labeled resources before stopping the tunnel services.
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

if [ "$ALL_DOCKER" = "1" ]; then
  log "removing all Docker containers on the host"
  mapfile -t project_containers < <(list_target_container_ids)
else
  log "removing Docker containers for project $STACK_PROJECT_NAME by compose label or ${STACK_PROJECT_NAME}_ name prefix"
  mapfile -t project_containers < <(list_target_container_ids)
fi

if [ "${#project_containers[@]}" -gt 0 ]; then
  docker rm -f "${project_containers[@]}" >/dev/null
else
  if [ "$ALL_DOCKER" = "1" ]; then
    log "no Docker containers found on the host"
  else
    log "no compose-labeled containers found for project $STACK_PROJECT_NAME"
  fi
fi

if [ "$ALL_DOCKER" = "1" ]; then
  log "removing all custom Docker networks on the host"
  mapfile -t project_networks < <(list_target_network_ids)
else
  log "removing Docker networks for project $STACK_PROJECT_NAME by compose label or ${STACK_PROJECT_NAME}_ name prefix"
  mapfile -t project_networks < <(list_target_network_ids)
fi

if [ "${#project_networks[@]}" -gt 0 ]; then
  docker network rm "${project_networks[@]}" >/dev/null 2>&1 || true
else
  if [ "$ALL_DOCKER" = "1" ]; then
    log "no custom Docker networks found on the host"
  else
    log "no compose-labeled networks found for project $STACK_PROJECT_NAME"
  fi
fi

if [ "$ALL_DOCKER" = "1" ]; then
  log "removing all Docker volumes on the host"
  mapfile -t project_volumes < <(list_target_volume_names)
else
  log "removing Docker volumes for project $STACK_PROJECT_NAME by compose label or ${STACK_PROJECT_NAME}_ name prefix"
  mapfile -t project_volumes < <(list_target_volume_names)
fi

if [ "${#project_volumes[@]}" -gt 0 ]; then
  docker volume rm "${project_volumes[@]}" >/dev/null
else
  if [ "$ALL_DOCKER" = "1" ]; then
    log "no Docker volumes found on the host"
  else
    log "no compose-labeled volumes found for project $STACK_PROJECT_NAME"
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

if [ "$PRUNE_DOCKER_CACHE" = "1" ]; then
  log "pruning Docker images, build cache, and unused volumes"
  docker system prune -a --volumes -f >/dev/null
  docker builder prune -a -f >/dev/null
fi

log "stack purge complete"
