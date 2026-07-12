#!/usr/bin/env bash

# shellcheck source=scripts/lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

deploy_state_dir() {
  local deploy_root="$1"
  printf '%s\n' "$deploy_root/runtime/deploy-state"
}

deploy_state_json_sha256() {
  local path="$1"
  local filter="${2:-.}"
  if [ -f "$path" ]; then
    jq -cS "$filter" "$path" | sha256sum | awk '{print $1}'
  else
    printf 'missing\n'
  fi
}

deploy_state_global_signature() {
  local bundle_root="$1"
  local components_lock="$bundle_root/site/components.lock.json"
  local graph_file="$bundle_root/stack.systemd/graph.json"
  local networks_file="$bundle_root/systemd-user/infra/networks.json"
  local volumes_file="$bundle_root/systemd-user/infra/volumes.json"

  jq -n \
    --arg components "$(deploy_state_json_sha256 "$components_lock" '.components')" \
    --arg systemdGraph "$(deploy_state_json_sha256 "$graph_file" '.')" \
    --arg infraNetworks "$(deploy_state_json_sha256 "$networks_file" '.')" \
    --arg infraVolumes "$(deploy_state_json_sha256 "$volumes_file" '.')" \
    '{
      version: 2,
      inputs: {
        components: $components,
        systemdGraph: $systemdGraph,
        infraNetworks: $infraNetworks,
        infraVolumes: $infraVolumes
      }
    }'
}

deploy_state_file_manifest_path() {
  local deploy_root="$1"
  printf '%s/bundle-files.sha256\n' "$(deploy_state_dir "$deploy_root")"
}

deploy_state_runtime_config_manifest_path() {
  local deploy_root="$1"
  printf '%s/runtime-config-files.sha256\n' "$(deploy_state_dir "$deploy_root")"
}

deploy_state_path_ignored() {
  local path="$1"

  case "$path" in
    stack.containers/test-runner/playwright-tests/node_modules/*|\
    stack.containers/test-runner/playwright-tests/test-results/*|\
    stack.containers/test-runner/playwright-tests/playwright-report/*|\
    stack.containers/test-runner/playwright-tests/.auth/*)
      return 0
      ;;
  esac

  return 1
}

deploy_state_manifest_for_root() {
  local root="$1"
  shift
  local paths=("$@")
  local path

  (
    cd "$root"
    for path in "${paths[@]}"; do
      [ -e "$path" ] || continue
      if [ -d "$path" ]; then
        find "$path" -type f -print
      elif [ -f "$path" ]; then
        printf '%s\n' "$path"
      fi
    done | LC_ALL=C sort | while IFS= read -r path; do
      deploy_state_path_ignored "$path" && continue
      sha256sum "$path"
    done
  )
}

deploy_state_file_manifest() {
  local bundle_root="$1"
  deploy_state_manifest_for_root "$bundle_root" \
    .dockerignore \
    docker-compose.yml \
    global.settings \
    scripts \
    site \
    stack.compose \
    stack.config \
    stack.containers \
    stack.js \
    stack.kotlin \
    stack.systemd \
    systemd-user
}

deploy_state_runtime_config_manifest() {
  local deploy_root="$1"
  local config_root="$deploy_root/runtime/configs"

  if [ ! -d "$config_root" ]; then
    return 0
  fi
  deploy_state_manifest_for_root "$config_root" .
}

deploy_state_changed_paths_between_manifests() {
  local previous_manifest="$1"
  local current_manifest="$2"

  awk '
    FNR == NR {
      previous[$2] = $1
      seen[$2] = 1
      next
    }
    {
      current[$2] = $1
      seen[$2] = 1
    }
    END {
      for (path in seen) {
        if ((path in previous) && (path in current) && previous[path] == current[path]) {
          continue
        }
        print path
      }
    }
  ' "$previous_manifest" "$current_manifest" | LC_ALL=C sort
}

deploy_state_changed_file_paths() {
  local bundle_root="$1"
  local deploy_root="$2"
  local previous_manifest current_manifest

  previous_manifest="$(deploy_state_file_manifest_path "$deploy_root")"
  if [ ! -f "$previous_manifest" ]; then
    return 2
  fi

  current_manifest="$(mktemp "${TMPDIR:-/tmp}/webservices-bundle-files.XXXXXX")"
  deploy_state_file_manifest "$bundle_root" > "$current_manifest"
  deploy_state_changed_paths_between_manifests "$previous_manifest" "$current_manifest"
  rm -f "$current_manifest"
}

deploy_state_changed_runtime_config_paths() {
  local deploy_root="$1"
  local previous_manifest current_manifest

  previous_manifest="$(deploy_state_runtime_config_manifest_path "$deploy_root")"
  if [ ! -f "$previous_manifest" ]; then
    return 2
  fi

  current_manifest="$(mktemp "${TMPDIR:-/tmp}/webservices-runtime-config-files.XXXXXX")"
  deploy_state_runtime_config_manifest "$deploy_root" > "$current_manifest"
  deploy_state_changed_paths_between_manifests "$previous_manifest" "$current_manifest" | sed 's#^\./##'
  rm -f "$current_manifest"
}

deploy_state_write_file_manifest() {
  local bundle_root="$1"
  local deploy_root="$2"
  local state_dir manifest_file temp_file

  state_dir="$(deploy_state_dir "$deploy_root")"
  manifest_file="$(deploy_state_file_manifest_path "$deploy_root")"
  mkdir -p -m 700 "$state_dir"
  chmod go-w "$state_dir"
  temp_file="$(mktemp "$state_dir/.bundle-files.tmp.XXXXXX")"
  deploy_state_file_manifest "$bundle_root" > "$temp_file"
  chmod 0600 "$temp_file"
  mv -f "$temp_file" "$manifest_file"
}

deploy_state_write_runtime_config_manifest() {
  local deploy_root="$1"
  local state_dir manifest_file temp_file

  state_dir="$(deploy_state_dir "$deploy_root")"
  manifest_file="$(deploy_state_runtime_config_manifest_path "$deploy_root")"
  mkdir -p -m 700 "$state_dir"
  chmod go-w "$state_dir"
  temp_file="$(mktemp "$state_dir/.runtime-config-files.tmp.XXXXXX")"
  deploy_state_runtime_config_manifest "$deploy_root" > "$temp_file"
  chmod 0600 "$temp_file"
  mv -f "$temp_file" "$manifest_file"
}

deploy_state_write_global_signature() {
  local bundle_root="$1"
  local deploy_root="$2"
  local state_dir signature_file temp_file

  state_dir="$(deploy_state_dir "$deploy_root")"
  signature_file="$state_dir/global-signature.json"
  mkdir -p -m 700 "$state_dir"
  chmod go-w "$state_dir"
  temp_file="$(mktemp "$state_dir/.global-signature.tmp.XXXXXX")"
  deploy_state_global_signature "$bundle_root" > "$temp_file"
  chmod 0600 "$temp_file"
  mv -f "$temp_file" "$signature_file"
}

deploy_state_global_signature_matches() {
  local bundle_root="$1"
  local deploy_root="$2"
  local state_dir signature_file current_file

  state_dir="$(deploy_state_dir "$deploy_root")"
  signature_file="$state_dir/global-signature.json"
  [ -f "$signature_file" ] || return 2

  current_file="$(mktemp "${TMPDIR:-/tmp}/webservices-global-signature.XXXXXX")"
  deploy_state_global_signature "$bundle_root" > "$current_file"
  if cmp -s "$signature_file" "$current_file"; then
    rm -f "$current_file"
    return 0
  fi
  rm -f "$current_file"
  return 1
}

deploy_state_check_global_signature() {
  local bundle_root="$1"
  local deploy_root="$2"
  local state_dir signature_file current_file diff_output

  state_dir="$(deploy_state_dir "$deploy_root")"
  signature_file="$state_dir/global-signature.json"
  if [ ! -f "$signature_file" ]; then
    printf '[webservices-build] ERROR: scoped deploy has no previous global deploy signature at %s; run a full deploy first\n' "$signature_file" >&2
    return 1
  fi

  current_file="$(mktemp "${TMPDIR:-/tmp}/webservices-global-signature.XXXXXX")"
  deploy_state_global_signature "$bundle_root" > "$current_file"
  if cmp -s "$signature_file" "$current_file"; then
    rm -f "$current_file"
    return 0
  fi

  diff_output="$(diff -u "$signature_file" "$current_file" || true)"
  rm -f "$current_file"
  printf '%s\n' "$diff_output" >&2
  printf '[webservices-build] ERROR: global deployment inputs changed; run a full deploy so component selection, systemd graph, and Docker infra reconcile together\n' >&2
  return 1
}

deploy_state_missing_global_signature() {
  local deploy_root="$1"
  local signature_file

  signature_file="$(deploy_state_dir "$deploy_root")/global-signature.json"
  [ ! -f "$signature_file" ]
}

deploy_state_bootstrap_missing_global_signature() {
  local bundle_root="$1"
  local deploy_root="$2"
  local active_target="${3:-webservices.target}"
  local systemctl_bin="${SYSTEMCTL_USER_BIN:-systemctl}"

  if ! deploy_state_missing_global_signature "$deploy_root"; then
    return 0
  fi

  if ! "$systemctl_bin" --user is-active --quiet "$active_target"; then
    printf '[webservices-build] ERROR: scoped deploy has no previous global deploy signature and %s is not active; run a full deploy first\n' "$active_target" >&2
    return 1
  fi

  printf '[webservices-build] warning: bootstrapping missing deploy-state signature from active %s\n' "$active_target" >&2
  deploy_state_write_global_signature "$bundle_root" "$deploy_root"
}
