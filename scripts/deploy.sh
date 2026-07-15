#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
BUNDLE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
DEPLOY_ROOT="$(cd "$BUNDLE_ROOT/.." && pwd -P)"
# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=scripts/lib/site-manifest.sh
source "$SCRIPT_DIR/lib/site-manifest.sh"
# shellcheck source=scripts/lib/runtime-state.sh
source "$SCRIPT_DIR/lib/runtime-state.sh"
# shellcheck source=scripts/lib/env-file.sh
source "$SCRIPT_DIR/lib/env-file.sh"
# shellcheck source=scripts/lib/deploy-state.sh
source "$SCRIPT_DIR/lib/deploy-state.sh"
# shellcheck source=scripts/lib/deploy-scope.sh
source "$SCRIPT_DIR/lib/deploy-scope.sh"
# shellcheck source=scripts/lib/systemd-user.sh
source "$SCRIPT_DIR/lib/systemd-user.sh"
# shellcheck source=scripts/lib/components.sh
source "$SCRIPT_DIR/lib/components.sh"

PROJECT_NAME="${PROJECT_NAME:-webservices}"
: "${RUNTIME_PARALLEL_LIMIT:=2}"
export RUNTIME_PARALLEL_LIMIT
EXPECTED_DEPLOY_ROOT="${WEBSERVICES_DEPLOY_ROOT:-$HOME/webservices}"
ALLOW_NONSTANDARD_DEPLOY_ROOT="${WEBSERVICES_ALLOW_NONSTANDARD_DEPLOY_ROOT:-0}"
PREFLIGHT_ONLY=0
PARTIAL_DEPLOY=0
AUTO_PARTIAL_DEPLOY=0
NOOP_DEPLOY=0
PLAN_ONLY=0
SCOPED_COMPONENT_DEPENDENCIES=0
CURRENT_PHASE="initializing"
SYSTEMD_RECONCILE_TIMEOUT_SECONDS="${SYSTEMD_RECONCILE_TIMEOUT_SECONDS:-1800}"
SYSTEMD_PROGRESS_INTERVAL_SECONDS="${SYSTEMD_PROGRESS_INTERVAL_SECONDS:-5}"
SYSTEMD_PROGRESS_MAX_ITEMS="${SYSTEMD_PROGRESS_MAX_ITEMS:-8}"
SYSTEMD_PROGRESS_HEARTBEAT_SECONDS="${SYSTEMD_PROGRESS_HEARTBEAT_SECONDS:-30}"
declare -A BUILT_IMAGE_IDS_BEFORE=()
declare -a SCOPED_COMPONENTS=()
declare -a SCOPED_SERVICES=()
declare -a SCOPED_UNITS=()
declare -a RUNTIME_CONFIG_CHANGED_PATHS=()
RUNTIME_CONFIG_CHANGE_STATUS="unknown"

usage() {
  cat <<'EOF_USAGE'
Usage:
  ./scripts/deploy.sh [--preflight-only] [--plan-only]
  ./scripts/deploy.sh [--component <name> ...] [--service <runtime-service> ...] [--unit <systemd-unit-or-domain> ...] [--include-component-dependencies]

Deploys the in-place bundle under ~/webservices by rendering runtime material into
~/webservices/runtime, installing pre-rendered systemd user units from ./build,
and asking systemd --user to reconcile webservices.target.

Scoped deploys render and install the same bundle, but only reload/start the
selected lifecycle units and the dependency units required by systemd. Use them
for small app/config updates where reconciling the whole webservices.target is
unnecessary.

Component scopes select only the component's own Runtime model files by default. Add
--include-component-dependencies when you intentionally want dependency
components in the scoped action.

Scoped deploys are guarded by the last full deploy signature. If component
selection, the systemd graph, or container network/volume metadata changed, the
deploy aborts and asks for a full deploy so global control-plane changes are
reconciled together.

Unscoped deploys automatically narrow to changed service owners when the last
deploy wrote bundle/runtime manifests and global control-plane inputs are
unchanged. Set DEPLOY_AUTO_SCOPE=0 to force the legacy full-target deploy path.
EOF_USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --preflight-only)
      PREFLIGHT_ONLY=1
      ;;
    --plan-only|--dry-run)
      PLAN_ONLY=1
      ;;
    --include-component-dependencies)
      SCOPED_COMPONENT_DEPENDENCIES=1
      ;;
    --component)
      [ "$#" -ge 2 ] || die "--component requires a value"
      PARTIAL_DEPLOY=1
      SCOPED_COMPONENTS+=("$2")
      shift
      ;;
    --service)
      [ "$#" -ge 2 ] || die "--service requires a value"
      PARTIAL_DEPLOY=1
      SCOPED_SERVICES+=("$2")
      shift
      ;;
    --unit)
      [ "$#" -ge 2 ] || die "--unit requires a value"
      PARTIAL_DEPLOY=1
      SCOPED_UNITS+=("$2")
      shift
      ;;
    *)
      die "unknown argument for deploy.sh: $1"
      ;;
  esac
  shift
done

if [ "${WEBSERVICES_ALLOW_LEGACY_PRODUCTION_DEPLOY:-0}" != "1" ]; then
  die "legacy production deploy is disabled; generate a Podman bundle and run ops/install-podman-bundle.sh"
fi

site_manifest_path="$BUNDLE_ROOT/site/manifest.json"
[ -f "$site_manifest_path" ] || die "missing bundled site manifest: $site_manifest_path"
[ -f "$BUNDLE_ROOT/runtime-model.yml" ] || die "missing bundle runtime model: $BUNDLE_ROOT/runtime-model.yml"
[ -d "$BUNDLE_ROOT/systemd-user" ] || die "missing pre-rendered systemd user units in $BUNDLE_ROOT/systemd-user (run build.sh first)"

deploy_log() {
  printf '[webservices-deploy] %s\n' "$*" >&2
}

set_phase() {
  CURRENT_PHASE="$1"
  deploy_log "phase: $CURRENT_PHASE"
}

dump_deploy_diagnostics() {
  local failed_units unit_name stack_targets=()
  deploy_log "diagnostics begin (phase=$CURRENT_PHASE)"
  mapfile -t stack_targets < <(user_systemd_default_stack_targets "$BUNDLE_ROOT/stack.systemd/graph.json")
  deploy_log "systemd stack target status"
  user_systemd_show_status "${stack_targets[@]}" >&2

  deploy_log "systemd dependency tree"
  user_systemd_list_dependencies webservices.target >&2

  deploy_log "webservices unit inventory"
  user_systemd_list_matching_units >&2

  mapfile -t failed_units < <(user_systemd_failed_units)
  if [ "${#failed_units[@]}" -gt 0 ]; then
    deploy_log "failed user units: ${failed_units[*]}"
    for unit_name in "${failed_units[@]}"; do
      deploy_log "status for failed unit $unit_name"
      user_systemd_show_status "$unit_name" >&2
      deploy_log "recent journal for failed unit $unit_name"
      user_systemd_show_recent_logs "$unit_name" 160 >&2
    done
  else
    deploy_log "no failed user units reported"
  fi

  if [ -f "$DEPLOY_ROOT/runtime/stack.env" ]; then
    deploy_log "container snapshot"
    container_runtime ps -a --format '{{.Names}}\t{{.Status}}\t{{.Image}}' 2>&1 | sort || true
    if [ -x "$BUNDLE_ROOT/scripts/mount-diagnostics.sh" ]; then
      deploy_log "mount diagnostics summary"
      "$BUNDLE_ROOT/scripts/mount-diagnostics.sh" \
        --bundle-root "$BUNDLE_ROOT" \
        --runtime-env-file "$DEPLOY_ROOT/runtime/stack.env" 2>/dev/null \
        | jq -c '{summary, findings}' 2>/dev/null || true
    fi
  fi

  deploy_log "diagnostics end"
}

on_deploy_error() {
  local exit_code=$?
  deploy_log "ERROR: deploy failed during phase '$CURRENT_PHASE' with exit code $exit_code"
  dump_deploy_diagnostics
  exit "$exit_code"
}

trap 'on_deploy_error' ERR

canonicalize_existing_or_parent() {
  local path="$1"
  local parent basename
  if [ -e "$path" ]; then
    cd "$path" && pwd -P
    return
  fi
  parent="$(dirname "$path")"
  basename="$(basename "$path")"
  mkdir -p "$parent"
  printf '%s/%s\n' "$(cd "$parent" && pwd -P)" "$basename"
}

validate_deploy_root() {
  local expected_root
  expected_root="$(canonicalize_existing_or_parent "$EXPECTED_DEPLOY_ROOT")"
  if [ "$DEPLOY_ROOT" = "$expected_root" ]; then
    return 0
  fi
  if [ "$ALLOW_NONSTANDARD_DEPLOY_ROOT" = "1" ]; then
    deploy_log "nonstandard deploy root allowed: actual=$DEPLOY_ROOT expected=$expected_root"
    return 0
  fi

  cat >&2 <<EOF_DEPLOY_ROOT
[webservices-deploy] This bundle is running from:
  $DEPLOY_ROOT

[webservices-deploy] The generated systemd units are rendered for:
  $expected_root

[webservices-deploy] Stage the bundle before deploying:
  ./install.sh --target "$expected_root"
  cd "$expected_root" && ./deploy.sh

[webservices-deploy] Set WEBSERVICES_ALLOW_NONSTANDARD_DEPLOY_ROOT=1 only when the systemd templates were intentionally rendered for another root.
EOF_DEPLOY_ROOT
  die "deploy root does not match rendered systemd unit root"
}

component_selected() {
  local component="$1"
  jq -e --arg component "$component" '(.components // []) | index($component) != null' \
    "$BUNDLE_ROOT/site/components.lock.json" >/dev/null 2>&1
}

print_nvidia_toolkit_help() {
  cat >&2 <<'EOF_NVIDIA_HELP'
[webservices-deploy] GPU inference requires the NVIDIA Container Toolkit. Install and configure it with:
  curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
    | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg

  curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
    | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
    | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list >/dev/null

  sudo apt-get update
  sudo apt-get install -y nvidia-container-toolkit
  sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml
EOF_NVIDIA_HELP
}

container_runtime_has_nvidia_runtime() {
  container_runtime info --format '{{json .Runtimes}}' 2>/dev/null | jq -e 'has("nvidia")' >/dev/null 2>&1
}

check_gpu_preflight() {
  if [ "${DEPLOY_SKIP_GPU_PREFLIGHT:-0}" = "1" ]; then
    deploy_log "GPU preflight skipped by DEPLOY_SKIP_GPU_PREFLIGHT=1"
    return 0
  fi
  component_selected inference || return 0

  command -v nvidia-smi >/dev/null 2>&1 || {
    print_nvidia_toolkit_help
    die "selected inference component requires nvidia-smi on the deployment host"
  }
  nvidia-smi >/dev/null 2>&1 || {
    print_nvidia_toolkit_help
    die "nvidia-smi failed on the deployment host"
  }
  container_runtime_has_nvidia_runtime || {
    print_nvidia_toolkit_help
    die "container runtime is missing the nvidia runtime required by --gpus services"
  }

  if [ "${DEPLOY_GPU_SMOKE_TEST:-0}" = "1" ]; then
    container_runtime run --rm --gpus all nvidia/cuda:12.4.1-base-ubuntu22.04 nvidia-smi >/dev/null
  fi
}

preflight() {
  require_cmd jq
  require_cmd python3
  require_cmd sops
  require_cmd systemctl
  container_contract version >/dev/null 2>&1 || die "runtime model support is unavailable for $(container_cli)"
  validate_deploy_root
  resolve_site_manifest_file "$site_manifest_path" >/dev/null
  check_gpu_preflight
  ensure_runtime_links "$DEPLOY_ROOT" >/dev/null
  ensure_user_systemd_env
  deploy_log "preflight ok (bundle=$BUNDLE_ROOT siteManifestPath=$site_manifest_path runtimeParallelLimit=$RUNTIME_PARALLEL_LIMIT)"
}

model_prep_services() {
  RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
    "$BUNDLE_ROOT" \
    "$DEPLOY_ROOT/runtime/stack.env" \
    config --format json | jq -r '
      .services
      | to_entries[]
      | select(
          (.value.labels // []) as $labels
          | if ($labels | type) == "object" then
              ($labels["webservices.model-prep"] // "false") == "true"
            elif ($labels | type) == "array" then
              any($labels[]; . == "webservices.model-prep=true")
            else
              false
            end
        )
      | .key
    ' | sort
}

built_image_services() {
  RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
    "$BUNDLE_ROOT" \
    "$DEPLOY_ROOT/runtime/stack.env" \
    config --format json | jq -r '
      .services
      | to_entries[]
      | select((.value.build // null) != null or ((.value.image // "") | test(":local-build$")))
      | select((.value.image // "") != "")
      | [.key, .value.image]
      | @tsv
    ' | sort
}

image_id_for_ref() {
  local image_ref="$1"
  container_runtime image inspect --format '{{.Id}}' "$image_ref" 2>/dev/null || true
}

container_image_id_for_service() {
  local service_name="$1"
  local container_id
  container_id="$(RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
    "$BUNDLE_ROOT" \
    "$DEPLOY_ROOT/runtime/stack.env" \
    ps -q "$service_name" 2>/dev/null | head -n 1)"
  [ -n "$container_id" ] || return 0
  container_runtime inspect --format '{{.Image}}' "$container_id" 2>/dev/null || true
}

unit_for_runtime_service() {
  local service_name="$1"
  local graph_file="$BUNDLE_ROOT/stack.systemd/graph.json"
  local unit_prefix domain_name

  unit_prefix="$(jq -r '.unitPrefix // "webservices"' "$graph_file")"
  domain_name="$(jq -r --arg service "$service_name" '
    first(
      .lifecycleDomains[]?
      | select(((.services // []) | index($service)) != null)
      | .name
    ) // $service
  ' "$graph_file")"
  printf '%s-%s.service\n' "$unit_prefix" "$domain_name"
}

runtime_service_exists() {
  local service_name="$1"
  RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
    "$BUNDLE_ROOT" \
    "$DEPLOY_ROOT/runtime/stack.env" \
    config --format json | jq -e --arg service "$service_name" '.services[$service] != null' >/dev/null
}

component_runtime_model_files() {
  local component="$1"
  local catalog="$BUNDLE_ROOT/stack.config/components.json"

  if [ "$SCOPED_COMPONENT_DEPENDENCIES" = "1" ]; then
    jq -r --arg requested "$component" '
      .components as $components
      |
      def walk_component($name):
        if $components[$name] == null then
          error("unknown component: " + $name)
        else
          [$name] + (($components[$name].dependencies // []) | map(walk_component(.)) | add // [])
        end;

      (walk_component($requested) | unique) as $selected
      | $components
      | keys_unsorted[] as $component
      | select($selected | index($component) != null)
      | $components[$component].runtimeFiles[]?
    ' "$catalog"
  else
    jq -r --arg requested "$component" '
    .components as $components
    | if $components[$requested] == null then
        error("unknown component: " + $requested)
      else
        $components[$requested].runtimeFiles[]?
      end
    ' "$catalog"
  fi
}

services_from_runtime_model_file() {
  local overlay_file="$1"
  local overlay_path="$BUNDLE_ROOT/runtime.overlays/$overlay_file"

  [ -f "$overlay_path" ] || die "component references missing runtime model file: $overlay_file"
  container_contract -f "$overlay_path" config --format json --no-interpolate | jq -r '.services | keys[]'
}

append_unique() {
  local value="$1"
  shift
  local -n target_array="$1"
  local existing

  [ -n "$value" ] || return 0
  for existing in "${target_array[@]}"; do
    [ "$existing" != "$value" ] || return 0
  done
  target_array+=("$value")
}

read_lines_into_array() {
  local output="$1"
  shift
  local -n target_array="$1"

  target_array=()
  [ -n "$output" ] || return 0
  mapfile -t target_array <<< "$output"
}

runtime_model_config_snapshot() {
  local output_file="$1"
  RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
    "$BUNDLE_ROOT" \
    "$DEPLOY_ROOT/runtime/stack.env" \
    config --format json > "$output_file"
}

path_requires_full_deploy() {
  local path="$1"

  case "$path" in
    .containerignore|global.settings/*|site/manifest.json|stack.systemd/*|systemd-user/*.timer|systemd-user/infra/*)
      return 0
      ;;
  esac
  return 1
}

path_is_deploy_state_only() {
  local path="$1"

  case "$path" in
    runtime-model.yml|site/components.lock.json|scripts/*|systemd-user/*.target|systemd-user/runtime-shards/*.stopping|runtime.overlays/test-runners.yml|stack.config/test-runner/*|stack.containers/test-runner/*|stack.kotlin/test-runner/*)
      return 0
      ;;
  esac
  return 1
}

services_for_build_owner() {
  local owner="$1"
  local runtime_config_json="$2"

  jq -r --arg owner "$owner" '
    .services
    | to_entries[]
    | select(
        .key == $owner
        or (((.value.build // {}).dockerfile // "") | test("(^|/)stack\\.containers/" + ($owner | gsub("([][.^$*+?{}()|\\\\])"; "\\\\&")) + "(/|$)"))
        or (((.value.build // {}).context // "") | test("(^|/)" + ($owner | gsub("([][.^$*+?{}()|\\\\])"; "\\\\&")) + "(/|$)"))
      )
    | .key
  ' "$runtime_config_json"
}

services_for_runtime_config_path() {
  local config_path="$1"
  local runtime_config_json="$2"

  config_path="${config_path#./}"
  jq -r --arg config "$config_path" '
    def rel_config_source:
      (if type == "object" then (.source // "") else "" end)
      | sub("^.*runtime/configs/?"; "")
      | sub("^\\./"; "");

    .services
    | to_entries[]
    | select(
        any((.value.volumes // [])[]?;
          (type == "object")
          and (.type == "bind")
          and (((.source // "") | test("(^|/)runtime/configs($|/)")))
          and (
            (rel_config_source == "")
            or ($config == rel_config_source)
            or ($config | startswith(rel_config_source + "/"))
            or (rel_config_source | startswith($config + "/"))
          )
        )
      )
    | .key
  ' "$runtime_config_json"
}

services_for_changed_bundle_path() {
  local path="$1"
  local runtime_config_json="$2"
  local owner overlay_file config_path output

  case "$path" in
    runtime.overlays/*)
      overlay_file="${path#runtime.overlays/}"
      overlay_file="${overlay_file%%/*}"
      services_from_runtime_model_file "$overlay_file"
      return 0
      ;;
    stack.containers/*|stack.kotlin/*|stack.js/*)
      owner="${path#*/}"
      owner="${owner%%/*}"
      services_for_build_owner "$owner" "$runtime_config_json"
      return 0
      ;;
    stack.config/*)
      config_path="${path#stack.config/}"
      output="$(services_for_runtime_config_path "$config_path" "$runtime_config_json")"
      if [ -n "$output" ]; then
        printf '%s\n' "$output"
        return 0
      fi
      owner="${config_path%%/*}"
      if runtime_service_exists "$owner"; then
        printf '%s\n' "$owner"
      fi
      return 0
      ;;
  esac

  return 1
}

activate_auto_partial_deploy_if_safe() {
  local changed_output path service_output service_name unit_name
  local runtime_config_json changed_paths=()
  local mapped_services=() mapped_units=() unmapped_paths=() full_paths=() state_only_paths=()

  [ "$PARTIAL_DEPLOY" = "0" ] || return 0
  [ "${DEPLOY_AUTO_SCOPE:-1}" = "1" ] || {
    deploy_log "auto-scope disabled by DEPLOY_AUTO_SCOPE=0"
    return 0
  }

  if ! deploy_state_global_signature_matches "$BUNDLE_ROOT" "$DEPLOY_ROOT"; then
    deploy_log "auto-scope unavailable: global deployment signature changed or is missing; using full deploy"
    return 0
  fi

  if ! changed_output="$(deploy_state_changed_file_paths "$BUNDLE_ROOT" "$DEPLOY_ROOT")"; then
    deploy_log "auto-scope unavailable: previous bundle file manifest is missing; using full deploy"
    return 0
  fi
  read_lines_into_array "$changed_output" changed_paths
  if [ "${#changed_paths[@]}" -eq 0 ]; then
    if [ "$RUNTIME_CONFIG_CHANGE_STATUS" = "known" ] && [ "${#RUNTIME_CONFIG_CHANGED_PATHS[@]}" -eq 0 ]; then
      NOOP_DEPLOY=1
      deploy_log "auto-scope found no tracked bundle or runtime-config changes; deploy is a no-op"
      return 0
    fi
    if [ "$RUNTIME_CONFIG_CHANGE_STATUS" = "known" ] && [ "${#RUNTIME_CONFIG_CHANGED_PATHS[@]}" -gt 0 ]; then
      runtime_config_json="$(mktemp "${TMPDIR:-/tmp}/webservices-auto-scope-runtime.XXXXXX.json")"
      runtime_model_config_snapshot "$runtime_config_json"
      for path in "${RUNTIME_CONFIG_CHANGED_PATHS[@]}"; do
        service_output="$(services_for_runtime_config_path "$path" "$runtime_config_json")"
        while IFS= read -r service_name; do
          append_unique "$service_name" mapped_services
        done <<< "$service_output"
      done
      rm -f "$runtime_config_json"
      if [ "${#mapped_services[@]}" -gt 0 ]; then
        PARTIAL_DEPLOY=1
        AUTO_PARTIAL_DEPLOY=1
        SCOPED_SERVICES=("${mapped_services[@]}")
        deploy_log "auto-scope selected runtime-config-only services: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${SCOPED_SERVICES[@]}")"
        return 0
      fi
    fi
    deploy_log "auto-scope using full deploy because runtime-config changes have no clear service owner"
    return 0
  fi

  runtime_config_json="$(mktemp "${TMPDIR:-/tmp}/webservices-auto-scope-runtime.XXXXXX.json")"
  runtime_model_config_snapshot "$runtime_config_json"

  for path in "${changed_paths[@]}"; do
    [ -n "$path" ] || continue
    if path_requires_full_deploy "$path"; then
      full_paths+=("$path")
      continue
    fi
    if path_is_deploy_state_only "$path"; then
      state_only_paths+=("$path")
      continue
    fi
    case "$path" in
	    systemd-user/*.service)
	        unit_name="${path#systemd-user/}"
	        append_unique "$unit_name" mapped_units
	        continue
	        ;;
	      systemd-user/runtime-shards/*.runtime.json)
	        service_name="${path#systemd-user/runtime-shards/}"
	        service_name="${service_name%.runtime.json}"
	        if runtime_service_exists "$service_name"; then
	          append_unique "$service_name" mapped_services
	        else
	          unit_name="$(deploy_scope_normalize_unit "$service_name" "$PROJECT_NAME")"
	          append_unique "$unit_name" mapped_units
	        fi
	        continue
	        ;;
	    esac
    if service_output="$(services_for_changed_bundle_path "$path" "$runtime_config_json")" && [ -n "$service_output" ]; then
      while IFS= read -r service_name; do
        append_unique "$service_name" mapped_services
      done <<< "$service_output"
    else
      unmapped_paths+=("$path")
    fi
  done
  rm -f "$runtime_config_json"

  if [ "${#full_paths[@]}" -gt 0 ]; then
    deploy_log "auto-scope using full deploy because global paths changed: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${full_paths[@]}")"
    return 0
  fi
  if [ "${#unmapped_paths[@]}" -gt 0 ]; then
    deploy_log "auto-scope using full deploy because paths have no clear service owner: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${unmapped_paths[@]}")"
    return 0
  fi
  if [ "${#mapped_services[@]}" -eq 0 ] && [ "${#mapped_units[@]}" -eq 0 ]; then
    if [ "$RUNTIME_CONFIG_CHANGE_STATUS" = "known" ] && [ "${#RUNTIME_CONFIG_CHANGED_PATHS[@]}" -eq 0 ] && [ "${#state_only_paths[@]}" -gt 0 ]; then
      NOOP_DEPLOY=1
      deploy_log "auto-scope found only deploy-state/script changes; deploy is a no-op"
      return 0
    fi
    deploy_log "auto-scope using full deploy because no changed services or units were resolved"
    return 0
  fi

  PARTIAL_DEPLOY=1
  AUTO_PARTIAL_DEPLOY=1
  SCOPED_SERVICES=("${mapped_services[@]}")
  SCOPED_UNITS=("${mapped_units[@]}")
  if [ "${#SCOPED_SERVICES[@]}" -gt 0 ]; then
    deploy_log "auto-scope selected changed services: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${SCOPED_SERVICES[@]}")"
  else
    deploy_log "auto-scope selected changed services: none"
  fi
  if [ "${#SCOPED_UNITS[@]}" -gt 0 ]; then
    deploy_log "auto-scope selected changed units: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${SCOPED_UNITS[@]}")"
  fi
}

resolve_scoped_services() {
  local services=()
  local component overlay_file service_name contract_output service_output requested_unit unit_service_output
  local overlay_files=() runtime_services=()
  local scoped_runtime_config_json="" unit_services=()
  local graph_file="$BUNDLE_ROOT/stack.systemd/graph.json"
  local unit_prefix

  unit_prefix="$(jq -r '.unitPrefix // "webservices"' "$graph_file")"

  for service_name in "${SCOPED_SERVICES[@]}"; do
    append_unique "$service_name" services
  done

  for component in "${SCOPED_COMPONENTS[@]}"; do
    if ! contract_output="$(component_runtime_model_files "$component")"; then
      die "failed to resolve runtime model files for selected component: $component"
    fi
    read_lines_into_array "$contract_output" overlay_files
    for overlay_file in "${overlay_files[@]}"; do
      [ -n "$overlay_file" ] || continue
      if ! service_output="$(services_from_runtime_model_file "$overlay_file")"; then
        die "failed to resolve services from component runtime model file: $overlay_file"
      fi
      read_lines_into_array "$service_output" runtime_services
      for service_name in "${runtime_services[@]}"; do
        append_unique "$service_name" services
      done
    done
  done

  if [ "${#SCOPED_UNITS[@]}" -gt 0 ]; then
    scoped_runtime_config_json="$(mktemp "${TMPDIR:-/tmp}/webservices-scoped-runtime.XXXXXX.json")"
    RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
      "$BUNDLE_ROOT" \
      "$DEPLOY_ROOT/runtime/stack.env" \
      config --format json > "$scoped_runtime_config_json"
    for requested_unit in "${SCOPED_UNITS[@]}"; do
      if ! unit_service_output="$(deploy_scope_services_for_unit "$requested_unit" "$unit_prefix" "$graph_file" "$scoped_runtime_config_json")"; then
        rm -f "$scoped_runtime_config_json"
        die "failed to resolve runtime services for selected unit: $requested_unit"
      fi
      read_lines_into_array "$unit_service_output" unit_services
      for service_name in "${unit_services[@]}"; do
        append_unique "$service_name" services
      done
    done
    rm -f "$scoped_runtime_config_json"
  fi

  for service_name in "${services[@]}"; do
    if ! runtime_service_exists "$service_name"; then
      die "selected runtime service is not present in this bundle: $service_name"
    fi
    printf '%s\n' "$service_name"
  done
}

normalize_scoped_unit() {
  local unit="$1"
  local prefix

  prefix="$(jq -r '.unitPrefix // "webservices"' "$BUNDLE_ROOT/stack.systemd/graph.json")"
  deploy_scope_normalize_unit "$unit" "$prefix"
}

resolve_scoped_units() {
  local units=()
  local service_name unit_name requested_unit service_output
  local services=()

  if ! service_output="$(resolve_scoped_services)"; then
    die "failed to resolve scoped services"
  fi
  read_lines_into_array "$service_output" services
  for service_name in "${services[@]}"; do
    [ -n "$service_name" ] || continue
    unit_name="$(unit_for_runtime_service "$service_name")"
    append_unique "$unit_name" units
  done

  for requested_unit in "${SCOPED_UNITS[@]}"; do
    unit_name="$(normalize_scoped_unit "$requested_unit")"
    append_unique "$unit_name" units
  done

  [ "${#units[@]}" -gt 0 ] || die "scoped deploy requested, but no service or unit scope resolved"

  for unit_name in "${units[@]}"; do
    [ -f "$BUNDLE_ROOT/systemd-user/$unit_name" ] || die "selected systemd unit is not present in this bundle: $unit_name"
    printf '%s\n' "$unit_name"
  done
}

build_scoped_service_images() {
  local services=() service_output

  if ! service_output="$(resolve_scoped_services)"; then
    die "failed to resolve scoped services for build"
  fi
  read_lines_into_array "$service_output" services
  if [ "${#services[@]}" -eq 0 ]; then
    deploy_log "no runtime services selected for scoped build"
    return 0
  fi

  deploy_log "building selected runtime services: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${services[@]}")"
  RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
    "$BUNDLE_ROOT" \
    "$DEPLOY_ROOT/runtime/stack.env" \
    build "${services[@]}"
}

scoped_health_units() {
  local unit_name health_unit unit_output
  local units=()
  if ! unit_output="$(resolve_scoped_units)"; then
    die "failed to resolve scoped units"
  fi
  read_lines_into_array "$unit_output" units
  for unit_name in "${units[@]}"; do
    [[ "$unit_name" == *.service ]] || continue
    health_unit="${unit_name%.service}-healthy.service"
    [ -f "$BUNDLE_ROOT/systemd-user/$health_unit" ] || continue
    printf '%s\n' "$health_unit"
  done
}

emit_deploy_plan() {
  local services=() units=() health_units=()
  local service_output unit_output health_output

  if [ "$NOOP_DEPLOY" = "1" ]; then
    deploy_log "deploy plan: mode=no-op"
    deploy_log "plan action: no tracked bundle or runtime-config changes; no build, unit reload, restart, or target reconcile required"
  elif [ "$PARTIAL_DEPLOY" = "1" ]; then
    if ! service_output="$(resolve_scoped_services)"; then
      die "failed to resolve scoped services for deploy plan"
    fi
    if ! unit_output="$(resolve_scoped_units)"; then
      die "failed to resolve scoped units for deploy plan"
    fi
    if ! health_output="$(scoped_health_units)"; then
      die "failed to resolve scoped healthy gates for deploy plan"
    fi
    read_lines_into_array "$service_output" services
    read_lines_into_array "$unit_output" units
    read_lines_into_array "$health_output" health_units
    deploy_log "deploy plan: mode=scoped"
    if [ "$SCOPED_COMPONENT_DEPENDENCIES" = "1" ]; then
      deploy_log "plan component dependency expansion: included"
    else
      deploy_log "plan component dependency expansion: direct-only"
    fi
    if [ "${#services[@]}" -gt 0 ]; then
      deploy_log "plan runtime services: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${services[@]}")"
    else
      deploy_log "plan runtime services: none selected directly"
    fi
    deploy_log "plan lifecycle units: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${units[@]}")"
    if [ "${#health_units[@]}" -gt 0 ]; then
      deploy_log "plan healthy gates: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${health_units[@]}")"
    else
      deploy_log "plan healthy gates: none"
    fi
    deploy_log "plan global maintenance: skipped after deploy signature guard"
    deploy_log "plan systemd action: reload active units with ExecReload, restart active units without it, start inactive selected units"
  else
    deploy_log "deploy plan: mode=full target=webservices.target"
    deploy_log "plan global maintenance: model prep, image build, excluded-service cleanup, container infra refresh, deploy jobs, target reconcile, post-reconcile auth bootstrap"
  fi
}

reconcile_scoped_units() {
  local units=() health_units=() reload_units=() restart_units=() start_units=()
  local unit_name action_units=() unit_output health_output

  if ! unit_output="$(resolve_scoped_units)"; then
    die "failed to resolve scoped units for reconcile"
  fi
  if ! health_output="$(scoped_health_units)"; then
    die "failed to resolve scoped healthy gates for reconcile"
  fi
  read_lines_into_array "$unit_output" units
  read_lines_into_array "$health_output" health_units

  deploy_log "scoped deploy selected units: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${units[@]}")"

  for unit_name in "${units[@]}"; do
    if [[ "$unit_name" == *.target ]]; then
      start_units+=("$unit_name")
    elif user_systemctl is-active --quiet "$unit_name"; then
      if grep -q '^ExecReload=' "$BUNDLE_ROOT/systemd-user/$unit_name"; then
        reload_units+=("$unit_name")
      else
        restart_units+=("$unit_name")
      fi
    else
      start_units+=("$unit_name")
    fi
  done

  if [ "${#reload_units[@]}" -gt 0 ]; then
    deploy_log "reloading selected active units: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${reload_units[@]}")"
    user_systemctl reload "${reload_units[@]}"
  fi

  if [ "${#restart_units[@]}" -gt 0 ]; then
    deploy_log "restarting selected active units without ExecReload: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${restart_units[@]}")"
    user_systemctl reset-failed "${restart_units[@]}" || true
    user_systemctl restart "${restart_units[@]}"
  fi

  if [ "${#start_units[@]}" -gt 0 ]; then
    deploy_log "starting selected inactive units: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${start_units[@]}")"
    user_systemctl reset-failed "${start_units[@]}" || true
    user_systemctl start "${start_units[@]}"
  fi

  action_units=("${reload_units[@]}" "${restart_units[@]}" "${start_units[@]}")
  if [ "${#action_units[@]}" -gt 0 ]; then
    user_systemctl reset-failed
  fi

  if [ "${#health_units[@]}" -gt 0 ]; then
    deploy_log "waiting on selected healthy gates: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${health_units[@]}")"
    user_systemctl start "${health_units[@]}"
  fi
}

snapshot_built_image_ids_before() {
  local service_name image_ref image_id
  BUILT_IMAGE_IDS_BEFORE=()
  while IFS=$'\t' read -r service_name image_ref; do
    [ -n "$service_name" ] || continue
    image_id="$(image_id_for_ref "$image_ref")"
    BUILT_IMAGE_IDS_BEFORE["$service_name"]="$image_id"
  done < <(built_image_services)
}

run_model_prep_jobs() {
  local service
  mapfile -t prep_services < <(model_prep_services)
  if [ "${#prep_services[@]}" -eq 0 ]; then
    return 0
  fi

  for service in "${prep_services[@]}"; do
    deploy_log "preparing model assets with $service"
    RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
      "$BUNDLE_ROOT" \
      "$DEPLOY_ROOT/runtime/stack.env" \
      run --rm --build --no-deps "$service"
  done
}

excluded_services() {
  jq -r '.excludedServices // [] | .[]' "$BUNDLE_ROOT/stack.systemd/graph.json"
}

cleanup_excluded_service_containers() {
  local service
  mapfile -t excluded < <(excluded_services)
  if [ "${#excluded[@]}" -eq 0 ]; then
    return 0
  fi

  for service in "${excluded[@]}"; do
    deploy_log "stopping excluded service container state for $service"
    RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
      "$BUNDLE_ROOT" \
      "$DEPLOY_ROOT/runtime/stack.env" \
      stop "$service" >/dev/null 2>&1 || true
    RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
      "$BUNDLE_ROOT" \
      "$DEPLOY_ROOT/runtime/stack.env" \
      rm -f -s "$service" >/dev/null 2>&1 || true
    container_runtime rm -f "$service" "${PROJECT_NAME}-${service}-1" >/dev/null 2>&1 || true
  done
}

cleanup_retired_service_containers() {
  local service unit_name
  local configured_services="${DEPLOY_RETIRED_SERVICES:-qdrant progression nats airflow-init airflow-webserver airflow-scheduler ingestion-runner embedding-gpu autoheal watchtower autobattler autobattler-db-bootstrap tas-dashboard}"

  for service in $configured_services; do
    if runtime_service_exists "$service"; then
      continue
    fi
    unit_name="webservices-${service}.service"
    deploy_log "stopping retired service state for $service"
    user_systemctl stop "$unit_name" >/dev/null 2>&1 || true
    user_systemctl disable "$unit_name" >/dev/null 2>&1 || true
    container_runtime rm -f "$service" "${PROJECT_NAME}-${service}-1" >/dev/null 2>&1 || true
  done
}

ensure_bootstrap_scaffolds() {
  local repos_root="$DEPLOY_ROOT/repos"
  mkdir -p "$repos_root/source"
  deploy_log "ensured bootstrap scaffold: $repos_root"
}

ensure_generated_report_link() {
  local reports_source="$BUNDLE_ROOT/reports"
  local reports_link="$DEPLOY_ROOT/reports"

  [ -d "$reports_source" ] || die "missing generated reports directory: $reports_source"
  if [ -L "$reports_link" ] || [ -e "$reports_link" ]; then
    rm -rf "$reports_link"
  fi
  ln -s "$reports_source" "$reports_link"
  deploy_log "ensured generated reports mount: $reports_link -> $reports_source"
}

runtime_env_value() {
  local key="$1"
  env_file_get_value "$DEPLOY_ROOT/runtime/stack.env" "$key"
}

migrate_legacy_seafile_split_volume() {
  local volumes_config="$BUNDLE_ROOT/systemd-user/infra/volumes.json"
  local volume_name desired_device actual_driver actual_opts seafile_media_root

  [ -f "$volumes_config" ] || return 0

  volume_name="$(jq -r '.[] | select(.key == "seafile_files") | .name // empty' "$volumes_config")"
  desired_device="$(jq -r '.[] | select(.key == "seafile_files") | .driver_opts.device // empty' "$volumes_config")"
  [ -n "$volume_name" ] || return 0
  [ "$desired_device" = '${SEAFILE_MEDIA_ROOT}' ] || return 0
  container_runtime volume inspect "$volume_name" >/dev/null 2>&1 || return 0

  actual_driver="$(container_runtime volume inspect "$volume_name" -f '{{.Driver}}')"
  actual_opts="$(container_runtime volume inspect "$volume_name" | jq -cS '.[0].Options // {}')"
  [ "$actual_driver" = "local" ] || return 0
  [ "$actual_opts" = "{}" ] || return 0

  seafile_media_root="$(runtime_env_value SEAFILE_MEDIA_ROOT)"
  [ -n "$seafile_media_root" ] || die "SEAFILE_MEDIA_ROOT is empty; refusing Seafile volume migration"
  [ "$seafile_media_root" != "/" ] || die "SEAFILE_MEDIA_ROOT resolved to /; refusing Seafile volume migration"

  deploy_log "migrating legacy Seafile split volume $volume_name into $seafile_media_root"
  user_systemctl stop webservices-seafile.service >/dev/null 2>&1 || true
  RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
    "$BUNDLE_ROOT" \
    "$DEPLOY_ROOT/runtime/stack.env" \
    stop seafile >/dev/null 2>&1 || true
  RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
    "$BUNDLE_ROOT" \
    "$DEPLOY_ROOT/runtime/stack.env" \
    rm -f -s seafile >/dev/null 2>&1 || true

  mkdir -p "$seafile_media_root"
  container_runtime run --rm \
    -v "$volume_name:/legacy-shared:ro" \
    -v "$seafile_media_root:/target-shared" \
    "$RUNTIME_CLEANUP_IMAGE" \
    sh -ceu '
      cp -a /legacy-shared/. /target-shared/
      mkdir -p /target-shared/seafile/seafile-data/storage
      for name in blocks commits fs httptemp tmp; do
        source="/target-shared/$name"
        dest="/target-shared/seafile/seafile-data/storage/$name"
        [ -e "$source" ] || continue
        mkdir -p "$dest"
        for entry in "$source"/* "$source"/.[!.]* "$source"/..?*; do
          [ -e "$entry" ] || continue
          base="$(basename "$entry")"
          if [ -e "$dest/$base" ]; then
            echo "refusing to overwrite existing Seafile storage entry: $dest/$base" >&2
            exit 1
          fi
          mv "$entry" "$dest/"
        done
        rmdir "$source" 2>/dev/null || true
      done
    '

  container_runtime volume rm "$volume_name" >/dev/null
  deploy_log "legacy Seafile split volume migrated; $volume_name will be recreated as a bind volume"
}

# shellcheck source=scripts/lib/deploy-reconcile.sh
source "$SCRIPT_DIR/lib/deploy-reconcile.sh"

preflight
if [ "$PREFLIGHT_ONLY" = "1" ]; then
  set_phase "preflight-only"
  exit 0
fi

set_phase "render-runtime"
ensure_runtime_links "$DEPLOY_ROOT" >/dev/null
"$SCRIPT_DIR/deploy/render-runtime.sh" --bundle-root "$BUNDLE_ROOT" --deploy-root "$DEPLOY_ROOT" --site-manifest "$site_manifest_path"
validate_runtime_secrets
write_storage_report
if runtime_config_changes="$(deploy_state_changed_runtime_config_paths "$DEPLOY_ROOT")"; then
  RUNTIME_CONFIG_CHANGE_STATUS="known"
  read_lines_into_array "$runtime_config_changes" RUNTIME_CONFIG_CHANGED_PATHS
else
  RUNTIME_CONFIG_CHANGE_STATUS="unknown"
  RUNTIME_CONFIG_CHANGED_PATHS=()
fi

set_phase "deploy-plan"
activate_auto_partial_deploy_if_safe
if [ "$PARTIAL_DEPLOY" = "1" ]; then
  if ! deploy_state_check_global_signature "$BUNDLE_ROOT" "$DEPLOY_ROOT"; then
    if deploy_state_missing_global_signature "$DEPLOY_ROOT" && deploy_state_bootstrap_missing_global_signature "$BUNDLE_ROOT" "$DEPLOY_ROOT" "webservices.target"; then
      deploy_log "recovered missing deploy-state signature for scoped deploy"
      deploy_state_check_global_signature "$BUNDLE_ROOT" "$DEPLOY_ROOT" || die "scoped deploy refused by deploy-state guard after recovery"
    else
      die "scoped deploy refused by deploy-state guard"
    fi
  fi
fi
emit_deploy_plan
if [ "$PLAN_ONLY" = "1" ]; then
  deploy_log "plan-only complete; no build, systemd, or container changes applied"
  exit 0
fi
if [ "$NOOP_DEPLOY" = "1" ]; then
  set_phase "final-readiness"
  wait_for_final_readiness
  validate_qdrant_schema
  write_module_deployment_report

  set_phase "complete"
  deploy_state_write_global_signature "$BUNDLE_ROOT" "$DEPLOY_ROOT"
  deploy_state_write_file_manifest "$BUNDLE_ROOT" "$DEPLOY_ROOT"
  deploy_state_write_runtime_config_manifest "$DEPLOY_ROOT"
  deploy_log "deploy complete; no changes applied"
  exit 0
fi

set_phase "model-prep"
if [ "$PARTIAL_DEPLOY" = "1" ]; then
  deploy_log "skipping global model prep for scoped deploy"
else
  run_model_prep_jobs
fi

set_phase "runtime-build-snapshot"
if [ "$PARTIAL_DEPLOY" = "1" ]; then
  deploy_log "skipping global built-image snapshot for scoped deploy"
else
  snapshot_built_image_ids_before
fi

set_phase "runtime-build"
if [ "$PARTIAL_DEPLOY" = "1" ]; then
  build_scoped_service_images
else
  deploy_log "building service images"
  RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
    "$BUNDLE_ROOT" \
    "$DEPLOY_ROOT/runtime/stack.env" \
    build
fi

set_phase "cleanup-excluded-services"
if [ "$PARTIAL_DEPLOY" = "1" ]; then
  deploy_log "skipping excluded-service cleanup for scoped deploy after deploy signature guard"
else
  cleanup_excluded_service_containers
  cleanup_retired_service_containers
  recreate_env_sensitive_containers
  cleanup_optional_orphan_containers
fi

set_phase "bootstrap-scaffolds"
ensure_bootstrap_scaffolds
ensure_generated_report_link

set_phase "install-systemd-units"
deploy_log "installing pre-rendered systemd user units"
"$SCRIPT_DIR/deploy/install-systemd-user-units.sh" \
  --unit-dir "$BUNDLE_ROOT/systemd-user"

set_phase "systemd-daemon-reload"
deploy_log "reloading user systemd manager"
user_systemctl daemon-reload
user_systemctl reset-failed
user_systemctl enable webservices.target >/dev/null

deploy_log "enabled target: webservices.target"
for timer_unit in webservices-host-autoheal.timer webservices-update-deploy.timer; do
  if [ -f "$BUNDLE_ROOT/systemd-user/$timer_unit" ]; then
    user_systemctl enable --now "$timer_unit" >/dev/null
    deploy_log "enabled timer: $timer_unit"
  fi
done

set_phase "seafile-volume-migration"
if [ "$PARTIAL_DEPLOY" = "1" ]; then
  deploy_log "skipping legacy Seafile volume migration for scoped deploy after deploy signature guard"
else
  migrate_legacy_seafile_split_volume
fi

set_phase "systemd-refresh-infra"
if [ "$PARTIAL_DEPLOY" = "1" ]; then
  deploy_log "skipping container infra refresh for scoped deploy after deploy signature guard"
else
  refresh_infra_units
fi

set_phase "systemd-restart-deploy-job-units"
if [ "$PARTIAL_DEPLOY" = "1" ]; then
  deploy_log "skipping global deploy job restarts for scoped deploy"
else
  restart_deploy_job_units
fi

set_phase "systemd-reload-changed-built-images"
if [ "$PARTIAL_DEPLOY" = "1" ]; then
  deploy_log "skipping global built-image reload detection for scoped deploy"
else
  reload_changed_built_image_units
fi

set_phase "systemd-reload-deploy-sensitive-units"
if [ "$PARTIAL_DEPLOY" = "1" ]; then
  deploy_log "skipping global deploy-sensitive reloads for scoped deploy"
else
  reload_deploy_sensitive_units
fi

set_phase "systemd-reload-runtime-config-units"
if [ "$PARTIAL_DEPLOY" = "1" ]; then
  deploy_log "skipping global runtime-config reloads for scoped deploy"
else
  reload_runtime_config_units
fi

set_phase "systemd-reconcile-target"
if [ "$PARTIAL_DEPLOY" = "1" ]; then
  reconcile_scoped_units
else
  reconcile_target
fi

set_phase "post-reconcile-bootstrap"
if [ "$PARTIAL_DEPLOY" = "1" ]; then
  deploy_log "skipping global post-reconcile bootstrap restarts for scoped deploy"
else
  restart_post_reconcile_units
fi
reload_deploy_reconcile_units

set_phase "final-readiness"
wait_for_final_readiness
validate_qdrant_schema
write_module_deployment_report

set_phase "complete"
deploy_state_write_global_signature "$BUNDLE_ROOT" "$DEPLOY_ROOT"
if [ "$PARTIAL_DEPLOY" = "0" ] || [ "$AUTO_PARTIAL_DEPLOY" = "1" ]; then
  deploy_state_write_file_manifest "$BUNDLE_ROOT" "$DEPLOY_ROOT"
  deploy_state_write_runtime_config_manifest "$DEPLOY_ROOT"
fi
deploy_log "deploy complete"
deploy_log "next step: cd $DEPLOY_ROOT && ./verify.sh"
