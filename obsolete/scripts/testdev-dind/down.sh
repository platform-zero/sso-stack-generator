#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/testdev/common.sh
source "$SCRIPT_DIR/common.sh"

testdev_require_docker
testdev_require_local_docker_context
testdev_require_virtualized_host

if docker inspect "$(testdev_dind_name)" >/dev/null 2>&1; then
  testdev_run_cli sh -lc '
    if [ -f /workspace-home/deploy/bundle/build/runtime-contract.yml ]; then
      cd /workspace-home/deploy/bundle
      docker compose \
        --env-file runtime/stack.env \
        --project-directory . \
        -f build/runtime-contract.yml \
        down --remove-orphans
    fi
  ' || true
fi

if [ "${TESTDEV_KEEP_DIND:-0}" != "1" ]; then
  docker rm -f "$(testdev_dind_name)" >/dev/null 2>&1 || true
  docker network rm "$(testdev_network_name)" >/dev/null 2>&1 || true
  docker volume rm "$(testdev_volume_name)" >/dev/null 2>&1 || true
fi
