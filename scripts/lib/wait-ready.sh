#!/usr/bin/env bash
set -euo pipefail

LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/lib/common.sh
source "$LIB_DIR/common.sh"
# shellcheck source=scripts/lib/runtime-state.sh
source "$LIB_DIR/runtime-state.sh"

BUNDLE_DIR=""
RUNTIME_ENV_FILE=""
TIMEOUT_SECONDS="900"
INTERVAL_SECONDS="5"
PROJECT_NAME="${PROJECT_NAME:-webservices}"

usage() {
  cat <<'EOF_USAGE'
Usage:
  ./wait-ready.sh --bundle-dir <path> --runtime-env-file <path> [options]
EOF_USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --bundle-dir)
      BUNDLE_DIR="$2"
      shift
      ;;
    --runtime-env-file)
      RUNTIME_ENV_FILE="$2"
      shift
      ;;
    --timeout-seconds)
      TIMEOUT_SECONDS="$2"
      shift
      ;;
    --interval-seconds)
      INTERVAL_SECONDS="$2"
      shift
      ;;
    --project-name)
      PROJECT_NAME="$2"
      shift
      ;;
    *)
      die "unknown argument for wait-ready.sh: $1"
      ;;
  esac
  shift
done

[ -n "$BUNDLE_DIR" ] || die "--bundle-dir is required"
[ -n "$RUNTIME_ENV_FILE" ] || die "--runtime-env-file is required"
[ -f "$BUNDLE_DIR/runtime-model.yml" ] || die "missing runtime model in $BUNDLE_DIR"
[ -f "$RUNTIME_ENV_FILE" ] || die "missing runtime env file: $RUNTIME_ENV_FILE"
[ -f "$BUNDLE_DIR/stack.systemd/graph.json" ] || die "missing systemd graph in $BUNDLE_DIR/stack.systemd/graph.json"
require_cmd jq
require_cmd systemctl

runtime_model_config_json() {
  RUNTIME_PROJECT_NAME="$PROJECT_NAME" run_contract_from_bundle \
    "$BUNDLE_DIR" \
    "$RUNTIME_ENV_FILE" \
    config --format json
}

service_container_name() {
  local runtime_config="$1"
  local service_name="$2"
  printf '%s\n' "$runtime_config" | jq -r --arg service "$service_name" '.services[$service].container_name // ""'
}

container_state() {
  local container_name="$1"
  container_runtime inspect -f '{{.State.Status}}' "$container_name" 2>/dev/null || true
}

container_health() {
  local container_name="$1"
  container_runtime inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container_name" 2>/dev/null || true
}

container_exit_code() {
  local container_name="$1"
  container_runtime inspect -f '{{.State.ExitCode}}' "$container_name" 2>/dev/null || true
}

systemd_unit_name_for_service() {
  local service_name="$1"
  printf '%s-%s.service\n' "$PROJECT_NAME" "$service_name"
}

systemd_unit_property() {
  local unit_name="$1"
  local property_name="$2"
  systemctl --user show "$unit_name" --property "$property_name" --value 2>/dev/null || true
}

systemd_unit_active_state() {
  local unit_name="$1"
  systemd_unit_property "$unit_name" "ActiveState"
}

systemd_unit_sub_state() {
  local unit_name="$1"
  systemd_unit_property "$unit_name" "SubState"
}

systemd_unit_result() {
  local unit_name="$1"
  systemd_unit_property "$unit_name" "Result"
}

systemd_unit_type() {
  local unit_name="$1"
  systemd_unit_property "$unit_name" "Type"
}

systemd_unit_is_oneshot() {
  local unit_name="$1"
  [ "$(systemd_unit_type "$unit_name")" = "oneshot" ]
}

optional_capability_services() {
  return 0
}

service_is_optional_without_isolated_runtime_identity() {
  return 1
}

systemd_unit_successful_oneshot() {
  local unit_name="$1"
  local active_state sub_state result
  systemd_unit_is_oneshot "$unit_name" || return 1
  active_state="$(systemd_unit_active_state "$unit_name")"
  sub_state="$(systemd_unit_sub_state "$unit_name")"
  result="$(systemd_unit_result "$unit_name")"
  [ "$active_state" = "active" ] && [ "$sub_state" = "exited" ] && [ "${result:-success}" = "success" ]
}

systemd_unit_skipped_exec_condition() {
  local unit_name="$1"
  [ "$(systemd_unit_result "$unit_name")" = "exec-condition" ]
}

service_state() {
  local runtime_config="$1"
  local service_name="$2"
  local container_name unit_name
  if service_is_optional_without_isolated_runtime_identity "$service_name"; then
    printf 'skipped\n'
    return 0
  fi
  container_name="$(service_container_name "$runtime_config" "$service_name")"
  unit_name="$(systemd_unit_name_for_service "$service_name")"
  [ -n "$container_name" ] || {
    if systemd_unit_successful_oneshot "$unit_name"; then
      printf 'exited\n'
    else
      printf 'missing\n'
    fi
    return 0
  }
  local state
  state="$(container_state "$container_name")"
  if [ -z "$state" ] && systemd_unit_skipped_exec_condition "$unit_name"; then
    printf 'skipped\n'
    return 0
  fi
  if [ -z "$state" ] && systemd_unit_successful_oneshot "$unit_name"; then
    printf 'exited\n'
    return 0
  fi
  printf '%s\n' "${state:-missing}"
}

service_health() {
  local runtime_config="$1"
  local service_name="$2"
  local container_name
  container_name="$(service_container_name "$runtime_config" "$service_name")"
  [ -n "$container_name" ] || { printf '\n'; return 0; }
  container_health "$container_name"
}

service_exit_code() {
  local runtime_config="$1"
  local service_name="$2"
  local container_name unit_name result
  if service_is_optional_without_isolated_runtime_identity "$service_name"; then
    printf '0\n'
    return 0
  fi
  container_name="$(service_container_name "$runtime_config" "$service_name")"
  unit_name="$(systemd_unit_name_for_service "$service_name")"
  [ -n "$container_name" ] || {
    if systemd_unit_skipped_exec_condition "$unit_name"; then
      printf '0\n'
      return 0
    fi
    if systemd_unit_successful_oneshot "$unit_name"; then
      printf '0\n'
    else
      result="$(systemd_unit_result "$unit_name")"
      [ -n "$result" ] && [ "$result" != "success" ] && printf '1\n' || printf '\n'
    fi
    return 0
  }
  if ! container_runtime inspect "$container_name" >/dev/null 2>&1; then
    if systemd_unit_skipped_exec_condition "$unit_name"; then
      printf '0\n'
      return 0
    fi
    if systemd_unit_successful_oneshot "$unit_name"; then
      printf '0\n'
    else
      result="$(systemd_unit_result "$unit_name")"
      [ -n "$result" ] && [ "$result" != "success" ] && printf '1\n' || printf '\n'
    fi
    return 0
  fi
  container_exit_code "$container_name"
}

service_successful_terminal_state() {
  local state="$1"
  local exit_code="$2"
  { [ "$state" = "exited" ] || [ "$state" = "skipped" ]; } && [ "$exit_code" = "0" ]
}

service_is_completion_dependency_job() {
  local runtime_config="$1"
  local service_name="$2"
  printf '%s\n' "$runtime_config" | jq -r --arg service "$service_name" '
    any(
      .services[]
      | (.depends_on // {})
      | to_entries[]?;
      .key == $service and (.value.condition // "service_started") == "service_completed_successfully"
    )
  '
}

service_is_on_demand_domain_member() {
  local graph_json="$1"
  local service_name="$2"
  printf '%s\n' "$graph_json" | jq -r --arg service "$service_name" '
    . as $graph
    | any(
        ($graph.lifecycleDomains // [])[];
        (.name as $domain_name
          | (($graph.onDemandDomains // []) | index($domain_name) != null)
            and ((.services // []) | index($service) != null))
      )
  '
}

service_is_top_level_readiness_target() {
  local runtime_config="$1"
  local graph_json="$2"
  local service_name="$3"
  local completion_job on_demand_domain_member
  completion_job="$(service_is_completion_dependency_job "$runtime_config" "$service_name")"
  if [ "$completion_job" = "true" ]; then
    printf 'false\n'
    return 0
  fi

  if printf '%s\n' "$graph_json" | jq -e --arg service "$service_name" '(.excludedServices // []) | index($service) != null' >/dev/null; then
    printf 'false\n'
    return 0
  fi

  if printf '%s\n' "$graph_json" | jq -e --arg service "$service_name" '(.onDemandServices // []) | index($service) != null' >/dev/null; then
    printf 'false\n'
    return 0
  fi

  on_demand_domain_member="$(service_is_on_demand_domain_member "$graph_json" "$service_name")"
  if [ "$on_demand_domain_member" = "true" ]; then
    printf 'false\n'
    return 0
  fi

  printf '%s\n' "$runtime_config" | jq -r --arg service "$service_name" '
    if (.services[$service].restart // "") == "no" then
      "false"
    else
      "true"
    end
  '
}

created_service_blockers() {
  local runtime_config="$1"
  local graph_json="$2"
  local service_name="$3"
  local blockers=()
  local state health exit_code restart_policy has_healthcheck dep_name dep_condition dep_state dep_health dep_exit unit_name systemd_oneshot_success
  unit_name="$(systemd_unit_name_for_service "$service_name")"
  systemd_oneshot_success="false"
  if systemd_unit_successful_oneshot "$unit_name"; then
    systemd_oneshot_success="true"
  fi

  state="$(service_state "$runtime_config" "$service_name")"
  health="$(service_health "$runtime_config" "$service_name")"
  exit_code="$(service_exit_code "$runtime_config" "$service_name")"
  restart_policy="$(printf '%s\n' "$runtime_config" | jq -r --arg service "$service_name" '.services[$service].restart // ""')"
  has_healthcheck="$(printf '%s\n' "$runtime_config" | jq -r --arg service "$service_name" 'if .services[$service].healthcheck == null then "false" else "true" end')"

  while IFS=$'\t' read -r dep_name dep_condition; do
    [ -n "$dep_name" ] || continue
    if printf '%s\n' "$graph_json" | jq -e --arg service "$dep_name" '(.excludedServices // []) | index($service) != null' >/dev/null; then
      continue
    fi
    dep_state="$(service_state "$runtime_config" "$dep_name")"
    dep_health="$(service_health "$runtime_config" "$dep_name")"
    dep_exit="$(service_exit_code "$runtime_config" "$dep_name")"
    case "$dep_condition" in
      service_healthy)
        if [ "$dep_state" = "skipped" ] && [ "$dep_exit" = "0" ]; then
          :
        elif [ "$dep_state" != "running" ] || [ "$dep_health" != "healthy" ]; then
          blockers+=("$dep_name:$dep_state${dep_health:+/$dep_health}")
        fi
        ;;
      service_completed_successfully)
        if ! service_successful_terminal_state "$dep_state" "$dep_exit"; then
          blockers+=("$dep_name:$dep_state${dep_exit:+/$dep_exit}")
        fi
        ;;
      *)
        if [ "$dep_state" != "running" ] && ! service_successful_terminal_state "$dep_state" "$dep_exit"; then
          blockers+=("$dep_name:$dep_state${dep_exit:+/$dep_exit}")
        fi
        ;;
    esac
  done < <(printf '%s\n' "$runtime_config" | jq -r --arg service "$service_name" '.services[$service].depends_on // {} | to_entries[]? | "\(.key)\t\(.value.condition // "service_started")"')

  case "$state" in
    running)
      if [ "$has_healthcheck" = "true" ] && [ -n "$health" ] && [ "$health" != "healthy" ]; then
        blockers+=("$service_name:$state/$health")
      fi
      ;;
    exited)
      if ! { [ "$restart_policy" = "no" ] && [ "$exit_code" = "0" ]; } && [ "$systemd_oneshot_success" != "true" ]; then
        blockers+=("$service_name:exited/${exit_code:-unknown}")
      fi
      ;;
    created|missing)
      if [ "${#blockers[@]}" -eq 0 ]; then
        blockers+=("$service_name:$state")
      fi
      ;;
    skipped)
      ;;
    *)
      blockers+=("$service_name:$state")
      ;;
  esac

  printf '%s\n' "${blockers[@]}"
}

start_time="$(date +%s)"
runtime_config="$(runtime_model_config_json)"
graph_json="$(cat "$BUNDLE_DIR/stack.systemd/graph.json")"
while true; do
  mapfile -t services < <(printf '%s\n' "$runtime_config" | jq -r '.services | keys[]')
  blockers=()
  for service_name in "${services[@]}"; do
    if [ "$(service_is_top_level_readiness_target "$runtime_config" "$graph_json" "$service_name")" != "true" ]; then
      continue
    fi
    while IFS= read -r blocker; do
      [ -n "$blocker" ] && blockers+=("$blocker")
    done < <(created_service_blockers "$runtime_config" "$graph_json" "$service_name")
  done

  if [ "${#blockers[@]}" -gt 0 ]; then
    mapfile -t blockers < <(printf '%s\n' "${blockers[@]}" | awk 'NF && !seen[$0]++')
  fi

  if [ "${#blockers[@]}" -eq 0 ]; then
    printf '[webservices-ready] all services ready\n' >&2
    exit 0
  fi

  now="$(date +%s)"
  elapsed="$((now - start_time))"
  if [ "$elapsed" -ge "$TIMEOUT_SECONDS" ]; then
    printf '[webservices-ready] ERROR: timed out after %ss awaiting %s\n' "$TIMEOUT_SECONDS" "$(printf '%s ' "${blockers[@]}")" >&2
    exit 1
  fi

  printf '[webservices-ready] awaiting %s\n' "$(printf '%s ' "${blockers[@]}")" >&2
  sleep "$INTERVAL_SECONDS"
done
