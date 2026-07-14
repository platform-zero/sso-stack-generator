#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/testdev/common.sh
source "$SCRIPT_DIR/common.sh"

deploy_root="$(testdev_deploy_root)"
bundle_root="$(testdev_root)"
project_name="$(testdev_project_name)"

testdev_require_docker
testdev_require_local_docker_context
testdev_require_virtualized_host

echo "[testdev] rendering runtime material"
SKIP_COMPOSE_VALIDATE=1 COMPOSE_PROJECT_NAME="$project_name" \
  "$bundle_root/scripts/deploy/render-runtime.sh" \
    --bundle-root "$bundle_root" \
    --deploy-root "$deploy_root" \
    --site-manifest "$bundle_root/site/manifest.json"

testdev_ensure_dind
testdev_seed_host_images
testdev_copy_bundle_to_volume
testdev_pull_workspace_base_images

echo "[testdev] starting compose project $project_name inside $(testdev_dind_name)"
testdev_run_cli sh -lc '
  cd /workspace-home/deploy/bundle
  mkdir -p /workspace-home/testdev/forgejo-runner-ssh
  export FORGEJO_RUNNER_SSH_DIR=/workspace-home/testdev/forgejo-runner-ssh
  build_args=
  if [ "${TESTDEV_BUILD_IMAGES:-0}" = "1" ]; then
    build_args=--build
  fi
  docker compose \
    --env-file runtime/stack.env \
    --project-directory . \
    -f build/runtime-contract.yml \
    up -d $build_args
'

echo "[testdev] stack started"
