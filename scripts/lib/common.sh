#!/usr/bin/env bash

COMMON_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
STACK_ROOT="$(cd "$COMMON_LIB_DIR/../.." && pwd -P)"
if [ -f "$STACK_ROOT/gradlew" ] && [ -f "$STACK_ROOT/settings.gradle.kts" ]; then
  SOURCE_ROOT="$STACK_ROOT"
elif [ -f "$STACK_ROOT/../gradlew" ] && [ -f "$STACK_ROOT/../settings.gradle.kts" ]; then
  SOURCE_ROOT="$(cd "$STACK_ROOT/.." && pwd -P)"
else
  SOURCE_ROOT="$STACK_ROOT"
fi
STACK_RUNTIME_DIR_NAME="runtime"
STACK_RUNTIME_ENV_BASENAME="stack.env"
STACK_RUNTIME_CONFIGS_DIR_NAME="$STACK_RUNTIME_DIR_NAME/configs"

log() {
  printf '[webservices-build] %s\n' "$*" >&2
}

die() {
  printf '[webservices-build] ERROR: %s\n' "$*" >&2
  exit 1
}

require_cmd() {
  local command_name="$1"
  command -v "$command_name" >/dev/null 2>&1 || die "missing required command: $command_name"
}

container_cli() {
  local cli="${STACK_CONTAINER_CLI:-}"
  if [ -n "$cli" ]; then
    [ "$cli" = "podman" ] || die "unsupported container CLI: $cli (Podman is required)"
    command -v "$cli" >/dev/null 2>&1 || die "requested container CLI is unavailable: $cli"
    printf '%s\n' "$cli"
    return 0
  fi
  if command -v podman >/dev/null 2>&1; then
    printf 'podman\n'
    return 0
  fi
  die "missing required container CLI: podman"
}

container_runtime() {
  local cli
  cli="$(container_cli)"
  if [ "$cli" = "podman" ] && [ -n "${CONTAINER_HOST:-}" ]; then
    podman --remote --url "$CONTAINER_HOST" "$@"
    return 0
  fi
  "$cli" "$@"
}

container_contract() {
  container_cli >/dev/null
  if [ -n "${RUNTIME_PROJECT_NAME:-}" ]; then
    podman compose --project-name "$RUNTIME_PROJECT_NAME" "$@"
    return 0
  fi
  podman compose "$@"
}

iso_timestamp_utc() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

normalize_host_path() {
  local value="$1"
  while [[ "$value" == *///* ]]; do
    value="${value//\/\//\/}"
  done
  if [ "$value" != "/" ]; then
    value="${value%/}"
  fi
  printf '%s\n' "$value"
}

copy_tree() {
  local src="$1"
  local dest="$2"
  [ -d "$src" ] || return 0
  mkdir -p "$dest"
  cp -a "$src/." "$dest/"
}

runtime_dir_path() {
  local root_dir="$1"
  printf '%s/%s\n' "$root_dir" "$STACK_RUNTIME_DIR_NAME"
}

runtime_env_file_path() {
  local root_dir="$1"
  printf '%s/%s/%s\n' "$root_dir" "$STACK_RUNTIME_DIR_NAME" "$STACK_RUNTIME_ENV_BASENAME"
}

runtime_configs_dir_path() {
  local root_dir="$1"
  printf '%s/%s\n' "$root_dir" "$STACK_RUNTIME_CONFIGS_DIR_NAME"
}
