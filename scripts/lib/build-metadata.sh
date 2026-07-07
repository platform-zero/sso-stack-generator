#!/usr/bin/env bash

iso_timestamp_utc_build_metadata() {
  date -u +"%Y-%m-%dT%H:%M:%SZ"
}

json_escape_build_metadata() {
  local value="${1:-}"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//$'\n'/\\n}"
  value="${value//$'\r'/\\r}"
  value="${value//$'\t'/\\t}"
  printf '%s' "$value"
}

build_metadata_git_sha() {
  local repo_dir="$1"
  git -C "$repo_dir" rev-parse HEAD 2>/dev/null || printf '%s' "${BUILD_SOURCE_VERSION:-unknown}"
}

build_metadata_git_short_sha() {
  local repo_dir="$1"
  git -C "$repo_dir" rev-parse --short=12 HEAD 2>/dev/null || printf '%s' "${BUILD_SOURCE_VERSION_SHORT:-unknown}"
}

build_metadata_version() {
  local repo_dir="$1"
  build_metadata_git_short_sha "$repo_dir"
}

build_metadata_git_branch() {
  local repo_dir="$1"
  git -C "$repo_dir" rev-parse --abbrev-ref HEAD 2>/dev/null || printf '%s' "${BUILD_SOURCE_BRANCH:-unknown}"
}

build_metadata_has_git_checkout() {
  local repo_dir="$1"
  git -C "$repo_dir" rev-parse HEAD >/dev/null 2>&1
}

build_metadata_git_dirty() {
  local repo_dir="$1"
  if ! build_metadata_has_git_checkout "$repo_dir"; then
    printf '%s' "${BUILD_SOURCE_DIRTY:-false}"
    return 0
  fi

  if [ -n "$(git -C "$repo_dir" status --porcelain --untracked-files=normal 2>/dev/null)" ]; then
    printf 'true'
  else
    printf 'false'
  fi
}

require_clean_git_tree() {
  local repo_dir="$1"
  local dirty_state

  if [ "${WEBSERVICES_ALLOW_DIRTY_BUILD:-}" = "1" ]; then
    return 0
  fi

  if ! build_metadata_has_git_checkout "$repo_dir"; then
    printf '[webservices-build] git metadata unavailable for %s; treating source as exported tree\n' "$repo_dir" >&2
    return 0
  fi

  dirty_state="$(build_metadata_git_dirty "$repo_dir")"
  case "$dirty_state" in
    false)
      return 0
      ;;
    true)
      printf '[webservices-build] ERROR: refusing to build from a dirty git tree in %s\n' "$repo_dir" >&2
      printf '[webservices-build] Commit or stash changes first.\n' >&2
      return 1
      ;;
    *)
      printf '[webservices-build] ERROR: could not determine git tree cleanliness for %s\n' "$repo_dir" >&2
      return 1
      ;;
  esac
}

write_source_build_metadata_json() {
  local repo_dir="$1"
  local output_path="$2"
  local built_at="${3:-$(iso_timestamp_utc_build_metadata)}"
  local built_by="${4:-${USER:-unknown}}"
  local build_system="${5:-bazel+shell+sops}"
  local version git_sha git_short_sha git_branch git_dirty

  version="$(build_metadata_version "$repo_dir")"
  git_sha="$(build_metadata_git_sha "$repo_dir")"
  git_short_sha="$(build_metadata_git_short_sha "$repo_dir")"
  git_branch="$(build_metadata_git_branch "$repo_dir")"
  git_dirty="$(build_metadata_git_dirty "$repo_dir")"

  cat > "$output_path" <<EOF_JSON
{
  "version": "$(json_escape_build_metadata "$version")",
  "gitSha": "$(json_escape_build_metadata "$git_sha")",
  "gitShortSha": "$(json_escape_build_metadata "$git_short_sha")",
  "gitBranch": "$(json_escape_build_metadata "$git_branch")",
  "gitDirty": $git_dirty,
  "sourceBuiltAt": "$(json_escape_build_metadata "$built_at")",
  "builtBy": "$(json_escape_build_metadata "$built_by")",
  "buildSystem": "$(json_escape_build_metadata "$build_system")"
}
EOF_JSON
}
