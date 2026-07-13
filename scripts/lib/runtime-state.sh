#!/usr/bin/env bash

# shellcheck source=scripts/lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

RUNTIME_CLEANUP_IMAGE="${RUNTIME_CLEANUP_IMAGE:-alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc}"

ensure_runtime_links() {
  local deploy_root="$1"
  local persistent_runtime_target="${XDG_STATE_HOME:-$HOME/.local/state}/webservices/runtime"
  local runtime_target="${WEBSERVICES_RUNTIME_TARGET:-$persistent_runtime_target}"
  local runtime_link="$deploy_root/runtime"
  local stale_runtime=""

  if ! mkdir -p "$runtime_target" 2>/dev/null || ! chmod 700 "$runtime_target" 2>/dev/null || [ ! -w "$runtime_target" ]; then
    die "runtime target is not writable: $runtime_target"
  fi

  if [ -L "$runtime_link" ] || [ -e "$runtime_link" ]; then
    if ! rm -rf "$runtime_link"; then
      stale_runtime="${deploy_root}/runtime.stale.$(date +%Y%m%d_%H%M%S)"
      mv "$runtime_link" "$stale_runtime" || die "unable to replace stale runtime path $runtime_link"
      printf '[webservices-runtime] preserved previous runtime path at %s\n' "$stale_runtime" >&2
      if command -v docker >/dev/null 2>&1; then
        docker run --rm \
          -v "$deploy_root:/cleanup-root" \
          "$RUNTIME_CLEANUP_IMAGE" \
          sh -ceu 'rm -rf "/cleanup-root/$1"' -- "$(basename "$stale_runtime")" \
          || printf '[webservices-runtime] warning: unable to delete quarantined runtime path %s via Docker\n' "$stale_runtime" >&2
      fi
    fi
  fi
  ln -s "$runtime_target" "$runtime_link"

  printf '%s\n' "$runtime_target"
}

prepare_runtime_dir() {
  local runtime_root="$1"
  if ! rm -rf "$runtime_root/configs" "$runtime_root/stack.env" "$runtime_root/build-info.json"; then
    if ! command -v docker >/dev/null 2>&1; then
      die "unable to clean runtime directory and docker is unavailable: $runtime_root"
    fi
    docker run --rm \
      -v "$runtime_root:/runtime-root" \
      "$RUNTIME_CLEANUP_IMAGE" \
      sh -ceu 'rm -rf /runtime-root/configs /runtime-root/stack.env /runtime-root/build-info.json' \
      || die "unable to clean runtime directory: $runtime_root"
  fi
  mkdir -p "$runtime_root/configs"
  chmod 700 "$runtime_root" "$runtime_root/configs"
}

run_compose_from_bundle() {
  local bundle_root="$1"
  local runtime_env_file="$2"
  local deploy_root
  shift 2
  deploy_root="$(cd "$bundle_root/.." && pwd -P)"
  (
    cd "$deploy_root"
    COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-webservices}" docker compose \
      --project-directory "$deploy_root" \
      --env-file "$runtime_env_file" \
      -f "$bundle_root/docker-compose.yml" \
      "$@"
  )
}
