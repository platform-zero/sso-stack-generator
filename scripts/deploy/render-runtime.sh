#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "[render-runtime] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
LIB_DIR="$(cd "$SCRIPT_DIR/../lib" && pwd -P)"
# shellcheck source=scripts/lib/common.sh
source "$LIB_DIR/common.sh"
# shellcheck source=scripts/lib/site-manifest.sh
source "$LIB_DIR/site-manifest.sh"
# shellcheck source=scripts/lib/render-values.sh
source "$LIB_DIR/render-values.sh"
# shellcheck source=scripts/lib/templates.sh
source "$LIB_DIR/templates.sh"
# shellcheck source=scripts/lib/compose.sh
source "$LIB_DIR/compose.sh"
# shellcheck source=scripts/lib/runtime-state.sh
source "$LIB_DIR/runtime-state.sh"
# shellcheck source=scripts/lib/components.sh
source "$LIB_DIR/components.sh"

BUNDLE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
DEPLOY_ROOT="$(cd "$BUNDLE_ROOT/.." && pwd -P)"
SITE_MANIFEST_PATH=""
RUNTIME_ROOT="$DEPLOY_ROOT/runtime"
RUNTIME_ROOT_EXPLICIT=0
SKIP_COMPOSE_VALIDATE=0

prepare_host_runtime_dirs() {
  local forgejo_runner_ssh_dir
  forgejo_runner_ssh_dir="$(render_get FORGEJO_RUNNER_SSH_DIR)"
  if [ -n "$forgejo_runner_ssh_dir" ]; then
    mkdir -p "$forgejo_runner_ssh_dir"
    chmod 700 "$forgejo_runner_ssh_dir"
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle-root)
      BUNDLE_ROOT="$2"
      shift
      ;;
    --deploy-root)
      DEPLOY_ROOT="$2"
      shift
      ;;
    --site-manifest)
      SITE_MANIFEST_PATH="$2"
      shift
      ;;
    --runtime-root)
      RUNTIME_ROOT="$2"
      RUNTIME_ROOT_EXPLICIT=1
      shift
      ;;
    --skip-compose-validate)
      SKIP_COMPOSE_VALIDATE=1
      ;;
    -h|--help)
      cat <<'EOF_USAGE'
Usage:
  ./scripts/deploy/render-runtime.sh [--bundle-root <path>] [--deploy-root <path>]
EOF_USAGE
      exit 0
      ;;
    *)
      die "unknown argument for render-runtime.sh: $1"
      ;;
  esac
  shift
done

if [ "$RUNTIME_ROOT_EXPLICIT" = "0" ]; then
  RUNTIME_ROOT="$DEPLOY_ROOT/runtime"
fi

require_cmd jq
require_cmd envsubst
require_cmd sops

if [ -z "$SITE_MANIFEST_PATH" ]; then
  SITE_MANIFEST_PATH="$BUNDLE_ROOT/site/manifest.json"
fi
site_manifest_path="$(resolve_site_manifest_file "$SITE_MANIFEST_PATH")"
site_name="$(site_manifest_site_name "$site_manifest_path")"
site_config_file="$(resolve_site_manifest_stack_config_path "$site_manifest_path")"
secret_store_file="$(resolve_site_manifest_secret_store_path "$site_manifest_path")"
component_catalog_file="$BUNDLE_ROOT/stack.config/components.json"
component_lock_file="$BUNDLE_ROOT/site/components.lock.json"
runtime_root="$(cd "$(dirname "$RUNTIME_ROOT")" && pwd -P)/$(basename "$RUNTIME_ROOT")"
runtime_configs_dir="$(runtime_configs_dir_path "$DEPLOY_ROOT")"
runtime_env_file="$(runtime_env_file_path "$DEPLOY_ROOT")"
export STACK_RUNTIME_DIR="$runtime_root"

render_set SITE_NAME "$site_name"
component_selection_load_runtime "$site_manifest_path" "$component_catalog_file" "$component_lock_file"
load_secret_store "$secret_store_file"
load_site_values "$site_config_file"
build_derived_render_values
prepare_host_runtime_dirs
prepare_runtime_dir "$runtime_root"
render_config_tree "$BUNDLE_ROOT/stack.config" "$runtime_configs_dir"
component_selection_filter_contracts_file "$runtime_configs_dir/service-contracts.json"
mapfile -t runtime_env_keys < <(collect_runtime_env_keys "$runtime_configs_dir" "$BUNDLE_ROOT/global.settings" "$BUNDLE_ROOT/docker-compose.yml")
mapfile -t runtime_env_keys < <(
  printf '%s\n' \
    "${runtime_env_keys[@]}" \
    STACK_RUNTIME_DIR \
    MODEL_CONTEXT_PROXY_AUTH_SECRET \
    PLAYWRIGHT_IGNORE_HTTPS_ERRORS \
    GPU_ARBITER_API_TOKEN \
    INFERENCE_CONTROLLER_API_TOKEN \
    SYNAPSE_REGISTRATION_SECRET \
    TEST_RUNNER_OAUTH_SECRET \
    | sort -u
)
write_env_file "$runtime_env_file" "${runtime_env_keys[@]}"
write_build_info "$BUNDLE_ROOT/build-info.json" "$runtime_root/build-info.json"

if [ "$SKIP_COMPOSE_VALIDATE" = "0" ]; then
  require_cmd docker
  COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-webservices}" run_compose_from_bundle \
    "$BUNDLE_ROOT" \
    "$runtime_env_file" \
    config --quiet >/dev/null
fi

printf '%s\n' "$runtime_root"
