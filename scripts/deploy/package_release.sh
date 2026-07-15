#!/usr/bin/env bash
set -euo pipefail

output_path="$1"
shift

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

die() {
  printf 'package_release.sh: %s\n' "$*" >&2
  exit 1
}

package_root="$(pwd -P)"

validate_relative_dest_path() {
  local src="$1"
  local component
  local -a path_parts

  case "$src" in
    /*) die "release input path must be relative: $src" ;;
  esac

  IFS='/' read -r -a path_parts <<<"$src"
  for component in "${path_parts[@]}"; do
    case "$component" in
      ""|".")
        continue
        ;;
      "..")
        die "release input path must not traverse parent directories: $src"
        ;;
    esac
  done
}

path_is_within() {
  local path="$1"
  local root="$2"
  [ "$path" = "$root" ] || [[ "$path" == "$root"/* ]]
}

validate_symlink_target() {
  local link_path="$1"
  local target_path first_hop first_hop_path candidate candidate_root source_root hop

  target_path="$(realpath -e "$link_path")" || die "broken symlink in release input: $link_path"

  if path_is_within "$target_path" "$package_root"; then
    return 0
  fi

  first_hop="$(readlink "$link_path")" || die "cannot read symlink in release input: $link_path"
  if [[ "$first_hop" == /* ]]; then
    first_hop_path="$first_hop"
  else
    first_hop_path="$(realpath -m "$(dirname "$link_path")/$first_hop")"
  fi

  candidate="$first_hop_path"
  for _ in $(seq 1 20); do
    candidate_root="$(workspace_root_for_path "$candidate" || true)"
    if [ -n "$candidate_root" ]; then
      if path_is_within "$target_path" "$candidate_root"; then
        return 0
      fi
      source_root="$(workspace_source_root "$candidate_root" || true)"
      if [ -n "$source_root" ] && path_is_within "$target_path" "$source_root"; then
        return 0
      fi
    fi

    [ -L "$candidate" ] || break
    hop="$(readlink "$candidate")" || break
    if [[ "$hop" == /* ]]; then
      candidate="$hop"
    else
      candidate="$(realpath -m "$(dirname "$candidate")/$hop")"
    fi
  done

  die "unsafe symlink in release input: $link_path -> $target_path"
}

workspace_root_for_path() {
  local path="$1"
  local current

  current="$(dirname "$path")"
  while [ "$current" != "/" ] && [ -n "$current" ]; do
    if [ -f "$current/MODULE.bazel" ] && [ -f "$current/BUILD.bazel" ]; then
      printf '%s\n' "$(realpath -e "$current")"
      return 0
    fi
    current="$(dirname "$current")"
  done
  return 1
}

workspace_source_root() {
  local workspace_root="$1"
  local marker_path

  marker_path="$(realpath -e "$workspace_root/MODULE.bazel" 2>/dev/null)" || return 1
  printf '%s\n' "$(dirname "$marker_path")"
}

validate_release_input() {
  local src="$1"

  if [ -L "$src" ]; then
    validate_symlink_target "$src"
    return 0
  fi

  [ -d "$src" ] || return 0
  while IFS= read -r -d '' link_path; do
    validate_symlink_target "$link_path"
  done < <(find "$src" -type l -print0)
}

for src in "$@"; do
  validate_relative_dest_path "$src"
  [ -e "$src" ] || continue
  validate_release_input "$src"
  dest="$tmp_dir/$src"
  mkdir -p "$(dirname "$dest")"
  cp -aL "$src" "$dest"
done

tar --sort=name --mtime='UTC 1970-01-01' --owner=0 --group=0 --numeric-owner -C "$tmp_dir" -cf "$output_path" .
