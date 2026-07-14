#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
LIB_DIR="$(cd "$SCRIPT_DIR/../lib" && pwd -P)"
# shellcheck source=scripts/lib/common.sh
source "$LIB_DIR/common.sh"
# shellcheck source=scripts/lib/runtime-model.sh
source "$LIB_DIR/runtime-model.sh"

BUNDLE_ROOT=""
OUTPUT_DIR=""
DEPLOY_ROOT_TEMPLATE="${DEPLOY_ROOT_TEMPLATE:-%h/webservices}"
UNIT_ROOT_TEMPLATE=""
RUNTIME_ENV_FILE_TEMPLATE=""
PROJECT_NAME="${PROJECT_NAME:-webservices}"

usage() {
  cat <<'EOF_USAGE'
Usage:
  ./scripts/deploy/render-systemd-user.sh --bundle-root <path> [--output-dir <path>]
EOF_USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle-root)
      BUNDLE_ROOT="$2"
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift
      ;;
    --deploy-root-template)
      DEPLOY_ROOT_TEMPLATE="$2"
      shift
      ;;
    --unit-root-template)
      UNIT_ROOT_TEMPLATE="$2"
      shift
      ;;
    --runtime-env-file-template)
      RUNTIME_ENV_FILE_TEMPLATE="$2"
      shift
      ;;
    --project-name)
      PROJECT_NAME="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument for render-systemd-user.sh: $1"
      ;;
  esac
  shift
done

[ -n "$BUNDLE_ROOT" ] || die "--bundle-root is required"
[ -f "$BUNDLE_ROOT/runtime-model.yml" ] || die "missing runtime model in $BUNDLE_ROOT"

LOCAL_BUNDLE_ROOT="$(cd "$BUNDLE_ROOT" && pwd -P)"
LOCAL_DEPLOY_ROOT="$(cd "$LOCAL_BUNDLE_ROOT/.." && pwd -P)"
OUTPUT_DIR="${OUTPUT_DIR:-$LOCAL_BUNDLE_ROOT/systemd-user}"
UNIT_ROOT_TEMPLATE="${UNIT_ROOT_TEMPLATE:-$DEPLOY_ROOT_TEMPLATE/build/systemd-user}"
RUNTIME_ENV_FILE_TEMPLATE="${RUNTIME_ENV_FILE_TEMPLATE:-$DEPLOY_ROOT_TEMPLATE/runtime/stack.env}"
GRAPH_PATH="$LOCAL_BUNDLE_ROOT/stack.systemd/graph.json"
[ -f "$GRAPH_PATH" ] || die "missing systemd graph source: $GRAPH_PATH"

mkdir -p "$OUTPUT_DIR"
rm -f "$OUTPUT_DIR"/*.service "$OUTPUT_DIR"/*.target "$OUTPUT_DIR"/*.timer
printf '[webservices-build] rendering systemd user units from %s into %s\n' "$GRAPH_PATH" "$OUTPUT_DIR" >&2

require_cmd jq
require_cmd python3
SYSTEMD_NOTIFY_BIN="$(command -v systemd-notify)"
[ -n "$SYSTEMD_NOTIFY_BIN" ] || die "systemd-notify is required to render user units"

runtime_config_json="$(mktemp)"
base_networks_contract="$(mktemp)"
base_networks_json="$(mktemp)"
runtime_model_command="$(runtime_model_config_command)"
cleanup() {
  rm -f "$runtime_config_json" "$base_networks_contract" "$base_networks_json"
}
trap cleanup EXIT

(
  cd "$LOCAL_DEPLOY_ROOT"
  RUNTIME_PROJECT_NAME="$PROJECT_NAME" $runtime_model_command \
    --project-directory "$LOCAL_DEPLOY_ROOT" \
    -f "$LOCAL_BUNDLE_ROOT/runtime-model.yml" \
    config --format json --no-interpolate
) > "$runtime_config_json"

{
  printf 'services:\n'
  printf '  network-probe:\n'
  printf '    image: alpine:3.20\n'
  printf '    command: ["true"]\n\n'
  cat "$LOCAL_BUNDLE_ROOT/global.settings/networks.yml"
} > "$base_networks_contract"

(
  cd "$LOCAL_DEPLOY_ROOT"
  RUNTIME_PROJECT_NAME="$PROJECT_NAME" $runtime_model_command \
    --project-directory "$LOCAL_DEPLOY_ROOT" \
    -f "$base_networks_contract" \
    config --format json --no-interpolate
) > "$base_networks_json"

python3 "$SCRIPT_DIR/render-systemd-user.py" \
  --local-bundle-root "$LOCAL_BUNDLE_ROOT" \
  --local-deploy-root "$LOCAL_DEPLOY_ROOT" \
  --deploy-root-template "$DEPLOY_ROOT_TEMPLATE" \
  --unit-root-template "$UNIT_ROOT_TEMPLATE" \
  --runtime-env-file-template "$RUNTIME_ENV_FILE_TEMPLATE" \
  --runtime-config-json "$runtime_config_json" \
  --graph-path "$GRAPH_PATH" \
  --output-dir "$OUTPUT_DIR" \
  --runtime-project-name "$PROJECT_NAME" \
  --systemd-notify-bin "$SYSTEMD_NOTIFY_BIN" \
  --runtime-helper "$DEPLOY_ROOT_TEMPLATE/build/scripts/lib/systemd-runtime-unit.sh" \
  --infra-helper "$DEPLOY_ROOT_TEMPLATE/build/scripts/lib/systemd-container-infra.sh" \
  --diagnostics-helper "$DEPLOY_ROOT_TEMPLATE/build/scripts/lib/systemd-diagnostics.sh" \
  --host-autoheal-helper "$DEPLOY_ROOT_TEMPLATE/build/scripts/host/host-autoheal.sh" \
  --update-deploy-helper "$DEPLOY_ROOT_TEMPLATE/build/scripts/host/update-deploy.sh" \
  --base-networks-json "$base_networks_json"
