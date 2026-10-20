#!/usr/bin/env bash

# shellcheck source=scripts/lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

site_manifest_validate() {
  local manifest_path="$1"
  require_cmd jq

  jq -e '
    type == "object" and
    (.site | type == "string" and length > 0) and
    (.stackConfig | type == "string" and length > 0) and
    (.secretStore | type == "string" and length > 0) and
    (
      (.components == null) or
      ((.components | type) == "array" and all(.components[]; type == "string" and length > 0))
    ) and
    (. as $manifest | all(["excludedModules", "excludedComponents"][]; . as $key | $manifest |
      (has($key) | not) or
      (.[$key] | type == "array" and
        all(.[]; type == "string" and test("^[a-z0-9][a-z0-9-]*$")) and
        (length == (unique | length)))
    ))
  ' "$manifest_path" >/dev/null || die "invalid site manifest: $manifest_path (expected non-empty string keys: site, stackConfig, secretStore; optional components must be a string array)"
}

resolve_site_manifest_file() {
  local manifest_path="$1"
  [ -n "$manifest_path" ] || die "missing required --manifest <path-to-manifest.json>"
  [ -f "$manifest_path" ] || die "site manifest not found: $manifest_path"

  manifest_path="$(cd "$(dirname "$manifest_path")" && pwd -P)/$(basename "$manifest_path")"
  site_manifest_validate "$manifest_path"
  printf '%s\n' "$manifest_path"
}

site_manifest_dir() {
  local manifest_path="$1"
  printf '%s\n' "$(cd "$(dirname "$manifest_path")" && pwd -P)"
}

site_manifest_read_required() {
  local manifest_path="$1"
  local key="$2"
  local value

  value="$(jq -r --arg key "$key" '.[$key] // empty' "$manifest_path")"
  [ -n "$value" ] || die "site manifest is missing $key: $manifest_path"
  printf '%s\n' "$value"
}

site_manifest_site_name() {
  site_manifest_read_required "$1" site
}

resolve_site_manifest_member_path() {
  local manifest_path="$1"
  local key="$2"
  local rel_path manifest_dir candidate canonical_target

  rel_path="$(site_manifest_read_required "$manifest_path" "$key")"
  case "$rel_path" in
    /*)
      die "site manifest entry '$key' must be relative to the manifest directory: $manifest_path"
      ;;
  esac

  manifest_dir="$(site_manifest_dir "$manifest_path")"
  candidate="$manifest_dir/$rel_path"
  [ -f "$candidate" ] || die "site manifest entry '$key' points to a missing file: $candidate"
  canonical_target="$(realpath -e "$candidate")" || die "site manifest entry '$key' points to an unreadable file: $candidate"

  case "$canonical_target" in
    "$manifest_dir"/*) ;;
    *) die "site manifest entry '$key' escapes the manifest directory: $manifest_path" ;;
  esac

  printf '%s\n' "$canonical_target"
}

resolve_site_manifest_stack_config_path() {
  resolve_site_manifest_member_path "$1" stackConfig
}

resolve_site_manifest_secret_store_path() {
  resolve_site_manifest_member_path "$1" secretStore
}

yaml_get_scalar() {
  local file="$1"
  local path="$2"

  awk -v want="$path" '
    function trim(s) {
      gsub(/^[[:space:]]+|[[:space:]]+$/, "", s)
      return s
    }
    function dequote(s) {
      s = trim(s)
      if ((s ~ /^".*"$/) || (s ~ /^\047.*\047$/)) {
        s = substr(s, 2, length(s) - 2)
      }
      return s
    }
    /^[[:space:]]*#/ || /^[[:space:]]*$/ { next }
    {
      match($0, /[^ ]/)
      indent = RSTART ? RSTART - 1 : 0
      level = int(indent / 2)
      text = substr($0, indent + 1)
      colon = index(text, ":")
      if (colon == 0) {
        next
      }
      key = trim(substr(text, 1, colon - 1))
      value = trim(substr(text, colon + 1))
      for (i = level + 1; i < 16; ++i) {
        delete stack[i]
      }
      stack[level] = key
      current = stack[0]
      for (i = 1; i <= level; ++i) {
        current = current "." stack[i]
      }
      if (value != "" && current == want) {
        print dequote(value)
        exit
      }
    }
  ' "$file"
}

stage_site_manifest_bundle() {
  local manifest_path="$1"
  local dest_dir="$2"
  local stack_config_path secret_store_path stack_config_rel secret_store_rel

  mkdir -p "$dest_dir"
  cp "$manifest_path" "$dest_dir/manifest.json"

  stack_config_path="$(resolve_site_manifest_stack_config_path "$manifest_path")"
  secret_store_path="$(resolve_site_manifest_secret_store_path "$manifest_path")"
  stack_config_rel="$(site_manifest_read_required "$manifest_path" stackConfig)"
  secret_store_rel="$(site_manifest_read_required "$manifest_path" secretStore)"

  mkdir -p "$dest_dir/$(dirname "$stack_config_rel")"
  mkdir -p "$dest_dir/$(dirname "$secret_store_rel")"
  cp "$stack_config_path" "$dest_dir/$stack_config_rel"
  cp "$secret_store_path" "$dest_dir/$secret_store_rel"
}
