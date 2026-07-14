#!/usr/bin/env bash

# shellcheck source=scripts/lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
# shellcheck source=scripts/lib/components.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/components.sh"
# shellcheck source=scripts/lib/templates.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/templates.sh"

extract_top_level_section() {
  local file="$1"
  local section="$2"
  awk -v section="$section" '
    $0 == section { in_section = 1; next }
    in_section {
      if ($0 ~ /^[^ \t]/ && $0 !~ /^[[:space:]]*$/) {
        exit
      }
      print
    }
  ' "$file"
}

extract_extension_blocks() {
  local file="$1"
  awk '
    function flush() {
      if (length(block) > 0) {
        printf "%s\n", block
        block = ""
      }
    }
    /^[^ \t]/ {
      if ($0 ~ /^x-[^:]+:/) {
        flush()
        in_extension = 1
        block = $0 ORS
        next
      }
      if (in_extension) {
        flush()
        in_extension = 0
      }
    }
    in_extension {
      block = block $0 ORS
    }
    END {
      flush()
    }
  ' "$file"
}

runtime_model_service_files() {
  local stage_dir="$1"
  local manifest_path="${2:-}"
  local catalog selected_file
  local -A selected_files=()
  local file

  if [ -n "$manifest_path" ]; then
    catalog="$(component_catalog_path "$stage_dir")"
    [ -f "$catalog" ] || die "missing component catalog: $catalog"
    while IFS= read -r selected_file; do
      selected_files["$selected_file"]=1
    done < <(component_selection_runtime_files "$manifest_path" "$catalog")
  fi

  for file in "$stage_dir"/runtime.overlays/*.yml; do
    [ -f "$file" ] || continue
    [ "$(basename "$file")" = "test-runners.yml" ] && continue
    if [ -n "$manifest_path" ] && [ -z "${selected_files[$(basename "$file")]+x}" ]; then
      continue
    fi
    printf '%s\n' "$file"
  done | sort
}

build_runtime_model() {
  local stage_dir="$1"
  local output_file="$2"
  local manifest_path="${3:-}"
  local global_settings="$stage_dir/global.settings"
  local component_catalog="$stage_dir/stack.config/components.json"
  local component_lock="$stage_dir/site/components.lock.json"
  local service_file
  local filtered_file
  local temp_dir
  local -a service_files=()

  temp_dir="$(mktemp -d)"
  if [ -n "$manifest_path" ]; then
    component_selection_load_runtime "$manifest_path" "$component_catalog" "$component_lock"
  fi
  while IFS= read -r service_file; do
    if [ -n "$manifest_path" ] && grep -qE '^[[:space:]]*#[[:space:]]*webservices-component-(start|end)' "$service_file"; then
      filtered_file="$temp_dir/$(basename "$service_file").filtered"
      filter_component_blocks "$service_file" "$filtered_file"
      service_files+=( "$filtered_file" )
    else
      service_files+=( "$service_file" )
    fi
  done < <(runtime_model_service_files "$stage_dir" "$manifest_path")

  {
    printf '# Auto-generated runtime-model.yml\n'
    printf '# Generated: %s\n\n' "$(iso_timestamp_utc)"

    for service_file in "${service_files[@]}"; do
      extract_extension_blocks "$service_file"
    done

    printf 'services:\n'
    if [ -f "$global_settings/volume-init.yml" ]; then
      extract_top_level_section "$global_settings/volume-init.yml" 'services:'
    fi
    for service_file in "${service_files[@]}"; do
      extract_top_level_section "$service_file" 'services:'
    done

    printf '\nvolumes:\n'
    if [ -f "$global_settings/volume-init.yml" ]; then
      extract_top_level_section "$global_settings/volume-init.yml" 'volumes:'
    fi
    if [ -f "$global_settings/volumes.yml" ]; then
      extract_top_level_section "$global_settings/volumes.yml" 'volumes:'
    fi
    for service_file in "${service_files[@]}"; do
      extract_top_level_section "$service_file" 'volumes:'
    done

    printf '\nnetworks:\n'
    if [ -f "$global_settings/networks.yml" ]; then
      extract_top_level_section "$global_settings/networks.yml" 'networks:'
    fi
  } > "$output_file"
  rm -rf "$temp_dir"
}

rewrite_runtime_model_paths() {
  local output_file="$1"
  local temp_file
  temp_file="$(mktemp)"
  sed -e 's|context: \.$|context: ./build|g' \
      -e 's|context: \./stack\.containers/|context: ./build/stack.containers/|g' \
      -e 's|^\([[:space:]]*-[[:space:]]*\)\./stack\.containers/|\1./build/stack.containers/|g' \
      -e 's|\./configs/|./runtime/configs/|g' \
      "$output_file" > "$temp_file"
  mv "$temp_file" "$output_file"
}

runtime_model_config_command() {
  if container_contract version >/dev/null 2>&1; then
    printf 'container_contract\n'
    return 0
  fi
  die "missing required runtime model command for $(container_cli)"
}

validate_runtime_model() {
  local stage_dir="$1"
  local output_file="$2"
  local deploy_root
  [ -d "$stage_dir" ] || die "missing stage directory for runtime model validation: $stage_dir"
  [ -f "$output_file" ] || die "missing generated runtime model file: $output_file"
  deploy_root="$(cd "$stage_dir/.." && pwd -P)"

  (
    cd "$deploy_root"
    RUNTIME_PROJECT_NAME="${RUNTIME_PROJECT_NAME:-webservices}" \
      container_contract --project-directory "$deploy_root" -f "$output_file" config --quiet --no-interpolate >/dev/null
  )
}
