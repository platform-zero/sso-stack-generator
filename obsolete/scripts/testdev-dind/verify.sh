#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/testdev/common.sh
source "$SCRIPT_DIR/common.sh"

testdev_require_docker
testdev_require_local_docker_context
testdev_require_virtualized_host
testdev_ensure_dind

if [ ! -f "$(testdev_deploy_root)/runtime/stack.env" ]; then
  echo "runtime/stack.env is missing; run ./testdev-up.sh first" >&2
  exit 1
fi

testdev_copy_bundle_to_volume

testdev_run_cli sh -lc '
  cd /workspace-home/deploy/bundle
  services="$(docker compose --env-file runtime/stack.env --project-directory . -f build/runtime-contract.yml config --services)"
  refresh_services=
  for service in caddy; do
    if printf "%s\n" "$services" | grep -qx "$service"; then
      refresh_services="$refresh_services $service"
    fi
  done
  if [ -n "$refresh_services" ]; then
    docker compose --env-file runtime/stack.env --project-directory . -f build/runtime-contract.yml up -d --force-recreate --no-deps $refresh_services
    for service in $refresh_services; do
      container="${COMPOSE_PROJECT_NAME}-${service}-1"
      for attempt in $(seq 1 60); do
        state="$(docker inspect "$container" --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}" 2>/dev/null || true)"
        if [ "$state" = "healthy" ] || [ "$state" = "running" ]; then
          break
        fi
        sleep 2
      done
      state="$(docker inspect "$container" --format "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}" 2>/dev/null || true)"
      if [ "$state" != "healthy" ] && [ "$state" != "running" ]; then
        running="$(docker inspect "$container" --format "{{.State.Running}}" 2>/dev/null || true)"
        if [ "$state" = "starting" ] && [ "$running" = "true" ]; then
          continue
        fi
        echo "testdev refreshed service $service did not become ready; state=$state" >&2
        exit 1
      fi
    done
  fi
'

if [ "$#" -eq 0 ]; then
  set -- kt stack-contract
fi

testdev_run_cli sh -lc '
  apk add --no-cache bash coreutils findutils >/dev/null
  cd /workspace-home/deploy/bundle
  export DIST_DIR=/workspace-home/deploy/bundle/build
  export COMPOSE_PROJECT_DIR=/workspace-home/deploy/bundle
  export RUNTIME_ENV_FILE_PATH=/workspace-home/deploy/bundle/runtime/stack.env
  export TEST_RESULTS_HOST_DIR=/workspace-home/deploy/bundle/test-results
  export TEST_RUNNER_REQUIRE_SYSTEMD_RUNTIME=0
  export TESTDEV_SKIP_GPU_INGESTION=1
  export CADDY_CONTAINER="${COMPOSE_PROJECT_NAME}-caddy-1"
  export TEST_RUNNER_HOST_XDG_RUNTIME_DIR_OVERRIDE=/workspace-home/deploy/bundle/testdev-runtime
  export FORGEJO_RUNNER_SSH_DIR=/workspace-home/testdev/forgejo-runner-ssh
  mkdir -p "$TEST_RUNNER_HOST_XDG_RUNTIME_DIR_OVERRIDE"
  mkdir -p "$FORGEJO_RUNNER_SSH_DIR"
  ./run-tests.sh "$@"
' testdev-verify "$@"
