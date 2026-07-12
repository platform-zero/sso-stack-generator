#!/usr/bin/env bash

# shellcheck source=scripts/lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

if [ -z "${WEBSERVICES_COMPONENTS_INITIALIZED:-}" ]; then
  declare -gA WEBSERVICES_SELECTED_COMPONENTS=()
  declare -g WEBSERVICES_COMPONENTS_INITIALIZED=1
fi

component_catalog_path() {
  local root="$1"
  printf '%s/stack.config/components.json\n' "$root"
}

component_catalog_validate() {
  local catalog="$1"
  require_cmd jq
  jq -e '
    type == "object" and
    (.schemaVersion == 1) and
    (.defaultComponents | type == "array") and
    (.components | type == "object")
  ' "$catalog" >/dev/null || die "invalid component catalog: $catalog"
}

component_catalog_merge_external() {
  local catalog="$1"
  local external_dir
  local temp_catalog
  local -a external_catalogs=()

  external_dir="$(dirname "$catalog")/components.external"
  [ -d "$external_dir" ] || return 0

  while IFS= read -r external_catalog; do
    external_catalogs+=( "$external_catalog" )
  done < <(find "$external_dir" -maxdepth 1 -type f -name '*.json' | sort)
  [ "${#external_catalogs[@]}" -gt 0 ] || return 0

  if [ ! -f "$catalog" ]; then
    mkdir -p "$(dirname "$catalog")"
    printf '%s\n' '{"schemaVersion":1,"defaultComponents":[],"components":{}}' > "$catalog"
  fi

  component_catalog_validate "$catalog"
  for external_catalog in "${external_catalogs[@]}"; do
    component_catalog_validate "$external_catalog"
  done

  temp_catalog="$(mktemp)"
  jq -s '
    reduce .[] as $catalog (
      {schemaVersion: 1, defaultComponents: [], components: {}};
      .schemaVersion = 1
      | .defaultComponents = ((.defaultComponents + ($catalog.defaultComponents // [])) | unique)
      | .components = (.components + ($catalog.components // {}))
    )
  ' "$catalog" "${external_catalogs[@]}" > "$temp_catalog"
  mv "$temp_catalog" "$catalog"
}

service_contracts_merge_external() {
  local contracts="$1"
  local external_dir
  local temp_contracts
  local -a external_contracts=()

  external_dir="$(dirname "$contracts")/service-contracts.external"
  [ -d "$external_dir" ] || return 0

  while IFS= read -r external_contract; do
    external_contracts+=( "$external_contract" )
  done < <(find "$external_dir" -maxdepth 1 -type f -name '*.json' | sort)
  [ "${#external_contracts[@]}" -gt 0 ] || return 0

  if [ ! -f "$contracts" ]; then
    mkdir -p "$(dirname "$contracts")"
    printf '%s\n' '{"contractVersion":1,"components":{}}' > "$contracts"
  fi

  require_cmd jq
  jq -e '.contractVersion == 1 and (.components | type == "object")' "$contracts" >/dev/null || die "invalid service contracts: $contracts"
  for external_contract in "${external_contracts[@]}"; do
    jq -e '.contractVersion == 1 and (.components | type == "object")' "$external_contract" >/dev/null || die "invalid service contract fragment: $external_contract"
  done

  temp_contracts="$(mktemp)"
  jq -s '
    reduce .[] as $contracts (
      {contractVersion: 1, components: {}};
      .contractVersion = 1
      | .components = (.components + ($contracts.components // {}))
    )
  ' "$contracts" "${external_contracts[@]}" > "$temp_contracts"
  mv "$temp_contracts" "$contracts"
}

component_manifest_requested() {
  local manifest_path="$1"
  local catalog="$2"

  if jq -e 'has("components")' "$manifest_path" >/dev/null; then
    jq -r '
      if (.components | type) != "array" then
        error("manifest components must be an array")
      else
        .components[]
      end
    ' "$manifest_path"
  else
    jq -r '.defaultComponents[]' "$catalog"
  fi
}

component_selection_resolve() {
  local manifest_path="$1"
  local catalog="$2"
  local -A selected=()
  local -a queue=()
  local component dependency changed

  component_catalog_validate "$catalog"

  while IFS= read -r component; do
    [ -n "$component" ] || continue
    if ! jq -e --arg component "$component" '.components[$component] != null' "$catalog" >/dev/null; then
      die "site manifest selects unknown component '$component'"
    fi
    if [ -z "${selected[$component]+x}" ]; then
      selected["$component"]=1
      queue+=( "$component" )
    fi
  done < <(component_manifest_requested "$manifest_path" "$catalog")

  [ "${#queue[@]}" -gt 0 ] || die "component selection is empty"

  changed=1
  while [ "$changed" = "1" ]; do
    changed=0
    for component in "${!selected[@]}"; do
      while IFS= read -r dependency; do
        [ -n "$dependency" ] || continue
        if ! jq -e --arg component "$dependency" '.components[$component] != null' "$catalog" >/dev/null; then
          die "component '$component' depends on unknown component '$dependency'"
        fi
        if [ -z "${selected[$dependency]+x}" ]; then
          selected["$dependency"]=1
          changed=1
        fi
      done < <(jq -r --arg component "$component" '.components[$component].dependencies[]?' "$catalog")
    done
  done

  while IFS= read -r component; do
    if [ -n "${selected[$component]+x}" ]; then
      printf '%s\n' "$component"
    fi
  done < <(jq -r '.components | keys_unsorted[]' "$catalog")
}

component_selection_compose_files() {
  local manifest_path="$1"
  local catalog="$2"
  local -A files=()
  local component file

  while IFS= read -r component; do
    while IFS= read -r file; do
      [ -n "$file" ] || continue
      files["$file"]=1
    done < <(jq -r --arg component "$component" '.components[$component].composeFiles[]?' "$catalog")
  done < <(component_selection_resolve "$manifest_path" "$catalog")

  while IFS= read -r component; do
    while IFS= read -r file; do
      if [ -n "${files[$file]+x}" ]; then
        printf '%s\n' "$file"
        unset "files[$file]"
      fi
    done < <(jq -r --arg component "$component" '.components[$component].composeFiles[]?' "$catalog")
  done < <(jq -r '.components | keys_unsorted[]' "$catalog")
}

component_selection_write_metadata() {
  local manifest_path="$1"
  local catalog="$2"
  local output_file="$3"
  local temp_components contracts_file

  temp_components="$(mktemp)"
  component_selection_resolve "$manifest_path" "$catalog" > "$temp_components"
  contracts_file="$(dirname "$catalog")/service-contracts.json"
  if [ -f "$contracts_file" ]; then
    jq -n \
      --arg generatedAt "$(iso_timestamp_utc)" \
      --slurpfile components <(jq -R . "$temp_components" | jq -s .) \
      --slurpfile contracts "$contracts_file" \
      '{
        generatedAt: $generatedAt,
        components: $components[0],
        serviceContracts: {
          contractVersion: $contracts[0].contractVersion,
          components: (
            $components[0]
            | map({key: ., value: $contracts[0].components[.]})
            | from_entries
          )
        }
      }' > "$output_file"
  else
    jq -n \
      --arg generatedAt "$(iso_timestamp_utc)" \
      --slurpfile components <(jq -R . "$temp_components" | jq -s .) \
      '{generatedAt: $generatedAt, components: $components[0]}' > "$output_file"
  fi
  rm -f "$temp_components"
}

component_selection_filter_contracts_file() {
  local contracts_file="$1"
  local temp_file

  [ -f "$contracts_file" ] || return 0
  require_cmd jq
  temp_file="$(mktemp)"
  jq \
    --argjson selected "$(component_selection_env_value | tr ' ' '\n' | awk 'NF { print }' | jq -R . | jq -s .)" \
    '
      .components = (
        .components
        | with_entries(select(.key as $key | $selected | index($key)))
      )
    ' "$contracts_file" > "$temp_file"
  chmod --reference="$contracts_file" "$temp_file"
  mv "$temp_file" "$contracts_file"
}

component_selection_clear_runtime() {
  WEBSERVICES_SELECTED_COMPONENTS=()
}

component_selection_mark_runtime() {
  local component="$1"
  [ -n "$component" ] || return 0
  WEBSERVICES_SELECTED_COMPONENTS["$component"]=1
}

component_selection_load_runtime() {
  local manifest_path="$1"
  local catalog="$2"
  local lock_file="${3:-}"
  local component

  component_selection_clear_runtime
  if [ -n "$lock_file" ] && [ -f "$lock_file" ]; then
    while IFS= read -r component; do
      component_selection_mark_runtime "$component"
    done < <(jq -r '.components[]?' "$lock_file")
  else
    while IFS= read -r component; do
      component_selection_mark_runtime "$component"
    done < <(component_selection_resolve "$manifest_path" "$catalog")
  fi
}

component_is_selected() {
  local component="$1"
  [ -n "${WEBSERVICES_SELECTED_COMPONENTS[$component]+x}" ]
}

component_selection_env_value() {
  local component
  printf ' '
  for component in "${!WEBSERVICES_SELECTED_COMPONENTS[@]}"; do
    printf '%s ' "$component"
  done
}
