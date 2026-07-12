#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
deploy_script="$ROOT_DIR/scripts/deploy.sh"

assert_contains() {
  local pattern="$1"
  if ! grep -Fq "$pattern" "$deploy_script"; then
    printf '[test-deploy-preflight] missing deploy preflight pattern: %s\n' "$pattern" >&2
    exit 1
  fi
}

assert_contains 'validate_deploy_root'
assert_contains 'WEBSERVICES_ALLOW_NONSTANDARD_DEPLOY_ROOT'
assert_contains 'COMPOSE_PARALLEL_LIMIT:=2'
assert_contains 'check_gpu_preflight'
assert_contains 'nvidia-container-toolkit'
assert_contains 'DEPLOY_GPU_SMOKE_TEST'
assert_contains 'if type == "object" then (.source // "") else "" end'
assert_contains '(type == "object")'

printf '[test-deploy-preflight] ok\n'
