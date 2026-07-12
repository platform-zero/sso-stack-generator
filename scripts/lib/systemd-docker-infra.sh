#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=scripts/lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

usage() {
  cat <<'EOF_USAGE'
Usage:
  systemd-docker-infra.sh ensure-networks --config-file <path> [--env-file <path>]
  systemd-docker-infra.sh ensure-volumes --config-file <path> [--env-file <path>]
EOF_USAGE
}

[ "$#" -gt 0 ] || { usage >&2; exit 1; }
command_name="$1"
shift
CONFIG_FILE=""
ENV_FILE=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --config-file)
      CONFIG_FILE="$2"
      shift
      ;;
    --env-file)
      ENV_FILE="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument for systemd-docker-infra.sh: $1"
      ;;
  esac
  shift
done

[ -n "$CONFIG_FILE" ] || die "--config-file is required"
[ -f "$CONFIG_FILE" ] || die "missing config file: $CONFIG_FILE"
[ -z "$ENV_FILE" ] || [ -f "$ENV_FILE" ] || die "missing env file: $ENV_FILE"
require_cmd docker
require_cmd jq
require_cmd envsubst

declare -A ENV_FILE_VALUES=()
ENV_FILE_KEYS=()

validate_env_file_key() {
  local key="$1"
  [[ "$key" =~ ^[A-Z_][A-Z0-9_]*$ ]] || return 1
}

load_env_file_data() {
  local env_file="$1"
  local line key value
  local line_number=0

  while IFS= read -r line || [ -n "$line" ]; do
    line_number=$((line_number + 1))
    line="${line%$'\r'}"
    case "$line" in
      ''|'#'*)
        continue
        ;;
    esac

    if [[ "$line" != *=* ]]; then
      die "invalid env file entry at $env_file:$line_number: expected KEY=value"
    fi

    key="${line%%=*}"
    value="${line#*=}"
    if ! validate_env_file_key "$key"; then
      die "invalid env file key at $env_file:$line_number: $key"
    fi

    if [[ -z ${ENV_FILE_VALUES[$key]+x} ]]; then
      ENV_FILE_KEYS+=( "$key" )
    fi
    ENV_FILE_VALUES["$key"]="$value"
  done < "$env_file"
}

if [ -n "$ENV_FILE" ]; then
  load_env_file_data "$ENV_FILE"
fi

expand_env_value() {
  local value="${1:-}"
  # Expand environment variable references without evaluating shell code.
  (
    local key
    for key in "${ENV_FILE_KEYS[@]}"; do
      export "$key=${ENV_FILE_VALUES[$key]}"
    done
    printf '%s' "$value" | envsubst
  )
}

ensure_networks() {
  local network_name driver internal enable_ipv6 attachable actual_driver actual_internal actual_enable_ipv6 actual_attachable
  local desired_labels_json actual_labels_json attached_container_count
  jq -c '.[]' "$CONFIG_FILE" | while IFS= read -r row; do
    network_name="$(printf '%s\n' "$row" | jq -r '.name')"
    driver="$(printf '%s\n' "$row" | jq -r '.driver // "bridge"')"
    internal="$(printf '%s\n' "$row" | jq -r '.internal // false')"
    enable_ipv6="$(printf '%s\n' "$row" | jq -r '.enable_ipv6 // false')"
    attachable="$(printf '%s\n' "$row" | jq -r '.attachable // false')"
    desired_labels_json="$(printf '%s\n' "$row" | jq -cS '
      (.labels // [])
      | reduce .[] as $label ({};
          ($label | capture("^(?<key>[^=]+)=(?<value>.*)$")) as $parsed
          | . + {($parsed.key): $parsed.value}
        )
    ')"

    if docker network inspect "$network_name" >/dev/null 2>&1; then
      actual_driver="$(docker network inspect "$network_name" -f '{{.Driver}}')"
      actual_internal="$(docker network inspect "$network_name" -f '{{.Internal}}')"
      actual_enable_ipv6="$(docker network inspect "$network_name" -f '{{.EnableIPv6}}')"
      actual_attachable="$(docker network inspect "$network_name" -f '{{.Attachable}}')"
      actual_labels_json="$(docker network inspect "$network_name" | jq -cS '.[0].Labels // {}')"
      if [ "$actual_driver" != "$driver" ] || [ "$actual_internal" != "$internal" ] || [ "$actual_enable_ipv6" != "$enable_ipv6" ] || [ "$actual_attachable" != "$attachable" ]; then
        printf '[webservices-infra] ERROR: network drift for %s (driver=%s/%s internal=%s/%s ipv6=%s/%s attachable=%s/%s)\n' \
          "$network_name" "$actual_driver" "$driver" "$actual_internal" "$internal" "$actual_enable_ipv6" "$enable_ipv6" "$actual_attachable" "$attachable" >&2
        exit 1
      fi
      if [ "$actual_labels_json" != "$desired_labels_json" ]; then
        attached_container_count="$(docker network inspect "$network_name" | jq -r '.[0].Containers | length')"
        if [ "$attached_container_count" != "0" ]; then
          printf '[webservices-infra] ERROR: network label drift for %s but it still has %s attached containers (actual=%s desired=%s)\n' \
            "$network_name" "$attached_container_count" "$actual_labels_json" "$desired_labels_json" >&2
          exit 1
        fi
        printf '[webservices-infra] recreating network with corrected labels: %s (actual=%s desired=%s)\n' \
          "$network_name" "$actual_labels_json" "$desired_labels_json" >&2
        docker network rm "$network_name" >/dev/null
      else
        printf '[webservices-infra] network matches desired state: %s\n' "$network_name" >&2
        continue
      fi
    fi

    cmd=(docker network create --driver "$driver")
    [ "$internal" = "true" ] && cmd+=(--internal)
    [ "$enable_ipv6" = "true" ] && cmd+=(--ipv6)
    [ "$attachable" = "true" ] && cmd+=(--attachable)
    while IFS= read -r label; do
      [ -n "$label" ] && cmd+=(--label "$label")
    done < <(printf '%s\n' "$row" | jq -r '.labels // [] | .[]')
    cmd+=("$network_name")
    printf '[webservices-infra] creating network: %s\n' "$network_name" >&2
    "${cmd[@]}"
  done
}

ensure_volumes() {
  local volume_name driver desired_opts_json actual_opts_json actual_driver
  local desired_opts_rows_json desired_opts_json_raw opt_key opt_value opt_resolved bind_device
  jq -c '.[]' "$CONFIG_FILE" | while IFS= read -r row; do
    volume_name="$(printf '%s\n' "$row" | jq -r '.name')"
    driver="$(printf '%s\n' "$row" | jq -r '.driver // "local"')"
    desired_opts_rows_json="$(printf '%s\n' "$row" | jq -c '.driver_opts // {} | to_entries')"
    desired_opts_json_raw="$(
      printf '%s\n' "$desired_opts_rows_json" | jq -r '.[] | "\(.key)\t\(.value)"' | while IFS=$'\t' read -r opt_key opt_value; do
        opt_resolved="$(expand_env_value "$opt_value")"
        printf '%s\t%s\n' "$opt_key" "$opt_resolved"
      done | jq -Rn '
        reduce inputs as $line ({};
          ($line | split("\t")) as $parts
          | . + { ($parts[0]): ($parts[1] // "") }
        )
      '
    )"
    desired_opts_json="$(printf '%s\n' "$desired_opts_json_raw" | jq -cS '.')"

    if docker volume inspect "$volume_name" >/dev/null 2>&1; then
      actual_driver="$(docker volume inspect "$volume_name" -f '{{.Driver}}')"
      actual_opts_json="$(docker volume inspect "$volume_name" | jq -cS '.[0].Options // {}')"
      if [ "$actual_driver" != "$driver" ] || [ "$actual_opts_json" != "$desired_opts_json" ]; then
        printf '[webservices-infra] ERROR: volume drift for %s (driver=%s/%s opts=%s/%s)\n' \
          "$volume_name" "$actual_driver" "$driver" "$actual_opts_json" "$desired_opts_json" >&2
        exit 1
      fi
      printf '[webservices-infra] volume matches desired state: %s\n' "$volume_name" >&2
      continue
    fi

    bind_device="$(printf '%s\n' "$desired_opts_json_raw" | jq -r 'select(.type == "bind" and .o == "bind" and (.device // "") != "") | .device // empty')"
    if [ -n "$bind_device" ]; then
      printf '[webservices-infra] ensuring bind volume device directory: %s\n' "$bind_device" >&2
      mkdir -p "$bind_device"
    fi

    cmd=(docker volume create --driver "$driver")
    while IFS= read -r label; do
      [ -n "$label" ] && cmd+=(--label "$label")
    done < <(printf '%s\n' "$row" | jq -r '.labels // [] | .[]')

    while IFS=$'\t' read -r opt_key opt_value; do
      [ -n "$opt_key" ] || continue
      opt_resolved="$(expand_env_value "$opt_value")"
      cmd+=(--opt "$opt_key=$opt_resolved")
    done < <(printf '%s\n' "$desired_opts_rows_json" | jq -r '.[] | "\(.key)\t\(.value)"')

    cmd+=("$volume_name")
    printf '[webservices-infra] creating volume: %s\n' "$volume_name" >&2
    "${cmd[@]}"
  done
}

case "$command_name" in
  ensure-networks)
    ensure_networks
    ;;
  ensure-volumes)
    ensure_volumes
    ;;
  *)
    die "unknown command for systemd-docker-infra.sh: $command_name"
    ;;
esac
