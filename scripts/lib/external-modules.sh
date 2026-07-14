#!/usr/bin/env bash

# shellcheck source=scripts/lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
# shellcheck source=scripts/lib/site-manifest.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/site-manifest.sh"

EXTERNAL_MODULES_CACHE_DIR="${EXTERNAL_MODULES_CACHE_DIR:-$SOURCE_ROOT/out/external-git}"
EXTERNAL_MODULES_ROOT="${EXTERNAL_MODULES_ROOT:-$SOURCE_ROOT/out/external-modules}"
EXTERNAL_MODULES_MATERIALIZED_DIR="${EXTERNAL_MODULES_MATERIALIZED_DIR:-$EXTERNAL_MODULES_ROOT/materialized}"
EXTERNAL_MODULES_METADATA_FILE="${EXTERNAL_MODULES_METADATA_FILE:-$EXTERNAL_MODULES_ROOT/metadata.json}"
EXTERNAL_MODULES_RESOLVED_MANIFEST_FILE=""

external_modules_manifest_pin_file() {
  local site_manifest_path="$1"
  printf '%s/.webservices-generator.json\n' "$(site_manifest_dir "$site_manifest_path")"
}

external_modules_enabled() {
  local site_manifest_path="$1"
  local pin_file
  pin_file="$(external_modules_manifest_pin_file "$site_manifest_path")"
  [ -f "$pin_file" ] && jq -e '(.moduleManifestRemote // "") | length > 0' "$pin_file" >/dev/null
}

external_modules_safe_cache_name() {
  local label="$1"
  printf '%s' "$label" | sed -E 's/[^A-Za-z0-9._-]+/-/g; s/^-+//; s/-+$//' | cut -c1-80
}

external_modules_clone_at_commit() {
  local label="$1"
  local remote="$2"
  local ref="$3"
  local commit="$4"
  local cache_name repo_dir

  [ -n "$remote" ] && [ "$remote" != "null" ] || die "external module '$label' is missing git remote"
  [ -n "$commit" ] && [ "$commit" != "null" ] || die "external module '$label' is missing commit pin"

  require_cmd git
  mkdir -p "$EXTERNAL_MODULES_CACHE_DIR"
  cache_name="$(external_modules_safe_cache_name "$label")"
  [ -n "$cache_name" ] || cache_name="module"
  repo_dir="$EXTERNAL_MODULES_CACHE_DIR/$cache_name"

  if [ ! -d "$repo_dir/.git" ]; then
    git clone --no-checkout "$remote" "$repo_dir" >&2
  else
    current_remote="$(git -C "$repo_dir" remote get-url origin 2>/dev/null || true)"
    if [ "$current_remote" != "$remote" ]; then
      rm -rf "$repo_dir"
      git clone --no-checkout "$remote" "$repo_dir" >&2
    fi
  fi

  if [ -n "$ref" ] && [ "$ref" != "null" ]; then
    git -C "$repo_dir" fetch --tags origin "$ref" >&2 || git -C "$repo_dir" fetch --tags origin >&2
  else
    git -C "$repo_dir" fetch --tags origin >&2
  fi

  git -C "$repo_dir" cat-file -e "$commit^{commit}" 2>/dev/null || die "external module '$label' commit not found after fetch: $commit"
  git -C "$repo_dir" checkout --detach --force "$commit" >/dev/null
  git -C "$repo_dir" clean -fdx >/dev/null
  printf '%s\n' "$repo_dir"
}

external_modules_validate_relative_path() {
  local rel_path="$1"
  local part
  local -a parts
  [ "$rel_path" = "." ] && return 0
  case "$rel_path" in
    ""|/*) die "external module path must be relative: $rel_path" ;;
  esac
  IFS='/' read -r -a parts <<<"$rel_path"
  for part in "${parts[@]}"; do
    case "$part" in
      ""|"."|"..") die "external module path contains unsafe component: $rel_path" ;;
    esac
  done
}

external_modules_validate_tree() {
  local root="$1"
  local link_path target_path
  while IFS= read -r -d '' link_path; do
    target_path="$(realpath -e "$link_path")" || die "broken symlink in external module: $link_path"
    case "$target_path" in
      "$root"/*) ;;
      *) die "external module symlink escapes module root: $link_path -> $target_path" ;;
    esac
  done < <(find "$root" -type l -print0)
}

external_modules_path_allowed() {
  local rel_path="$1"
  case "$rel_path" in
    README.md|stack.module.json|stack.runtime.yaml|tests/*|.github/*)
      return 0
      ;;
    global.settings/*|runtime.contract/*|stack.config/*|stack.containers/*|stack.kotlin/*|stack.js/*|stack.systemd/*|scripts/lib/*|scripts/modules/*|docs/modules/*)
      return 0
      ;;
  esac
  return 1
}

external_modules_sanitize_systemd_graph() {
  local graph_file="$1"
  local temp_graph
  [ -f "$graph_file" ] || return 0
  temp_graph="$(mktemp)"
  jq '
    def retired_services:
      [
        ("dock" + "er-socket-lifecycle-proxy"),
        ("dock" + "er-socket-controller-proxy"),
        ("dock" + "er-socket-proxy"),
        ("dock" + "er-health-exporter"),
        "watchtower",
        "autoheal",
        "cadvisor",
        "dozzle"
      ];
    def strip_target:
      if type == "object" then
        .services = (((.services // []) - retired_services) | unique)
      else
        .
      end;
    .defaultTarget |= strip_target
    | .auxiliaryTargets = ((.auxiliaryTargets // []) | map(strip_target))
  ' "$graph_file" > "$temp_graph"
  mv "$temp_graph" "$graph_file"
}

external_modules_sanitize_materialized_tree() {
  local graph_file="$EXTERNAL_MODULES_MATERIALIZED_DIR/stack.systemd/graph.json"
  external_modules_sanitize_systemd_graph "$graph_file"
}

external_modules_materialize_one() {
  local manifest_file="$1"
  local index="$2"
  local metadata_file="$3"
  local name remote ref commit module_path repo_dir source_dir rel_path dest_path allowed_override provides requires

  name="$(jq -r --argjson i "$index" '.modules[$i].name // empty' "$manifest_file")"
  remote="$(jq -r --argjson i "$index" '.modules[$i].git // empty' "$manifest_file")"
  ref="$(jq -r --argjson i "$index" '.modules[$i].ref // empty' "$manifest_file")"
  commit="$(jq -r --argjson i "$index" '.modules[$i].commit // empty' "$manifest_file")"
  module_path="$(jq -r --argjson i "$index" '.modules[$i].path // "."' "$manifest_file")"
  provides="$(jq -c --argjson i "$index" '.modules[$i].provides // []' "$manifest_file")"
  requires="$(jq -c --argjson i "$index" '.modules[$i].requires // []' "$manifest_file")"
  [ -n "$name" ] || die "external module at index $index is missing name"
  external_modules_validate_relative_path "$module_path"

  repo_dir="$(external_modules_clone_at_commit "module-$name" "$remote" "$ref" "$commit")"
  source_dir="$(realpath -e "$repo_dir/$module_path")" || die "external module '$name' path not found: $module_path"
  case "$source_dir" in
    "$repo_dir"|"$repo_dir"/*) ;;
    *) die "external module '$name' path escapes repo: $module_path" ;;
  esac
  external_modules_validate_tree "$source_dir"

  while IFS= read -r -d '' file_path; do
    rel_path="${file_path#$source_dir/}"
    external_modules_path_allowed "$rel_path" || die "external module '$name' has unsupported path: $rel_path"
    case "$rel_path" in
      stack.config/components.json|stack.config/components.overlay.json)
        dest_path="$EXTERNAL_MODULES_MATERIALIZED_DIR/stack.config/components.external/$name.json"
        ;;
      stack.config/service-contracts.json)
        dest_path="$EXTERNAL_MODULES_MATERIALIZED_DIR/stack.config/service-contracts.external/$name.json"
        ;;
      stack.runtime.yaml)
        dest_path="$EXTERNAL_MODULES_MATERIALIZED_DIR/stack.runtime.external/$name.yaml"
        ;;
      README.md|stack.module.json|tests/*|.github/*)
        continue
        ;;
      *)
        dest_path="$EXTERNAL_MODULES_MATERIALIZED_DIR/$rel_path"
        ;;
    esac
    if [ -e "$dest_path" ]; then
      die "external module '$name' collides with another module output: $rel_path"
    fi
    if [ "$rel_path" != "stack.config/components.json" ] && [ "$rel_path" != "stack.config/components.overlay.json" ] && [ "$rel_path" != "stack.config/service-contracts.json" ] && [ "$rel_path" != "stack.runtime.yaml" ] && [ -e "$SOURCE_ROOT/$rel_path" ]; then
      allowed_override="$(jq -r --argjson i "$index" --arg path "$rel_path" '(.modules[$i].overrides // []) | index($path) // empty' "$manifest_file")"
      [ -n "$allowed_override" ] || die "external module '$name' would override base file without declaring it: $rel_path"
    fi
    mkdir -p "$(dirname "$dest_path")"
    cp -a "$file_path" "$dest_path"
    case "$rel_path" in
      stack.systemd/graph.json)
        external_modules_sanitize_systemd_graph "$dest_path"
        ;;
    esac
  done < <(find "$source_dir" -path '*/.git' -prune -o -type f -print0)

  jq -n \
    --arg name "$name" \
    --arg git "$remote" \
    --arg ref "$ref" \
    --arg commit "$commit" \
    --arg path "$module_path" \
    --argjson provides "$provides" \
    --argjson requires "$requires" \
    '{name: $name, git: $git, ref: $ref, commit: $commit, path: $path, provides: $provides, requires: $requires}' >> "$metadata_file"
}

external_modules_resolved_indices() {
  local manifest_file="$1"
  python3 - "$manifest_file" <<'PY'
import json
import sys

manifest_path = sys.argv[1]
with open(manifest_path, encoding="utf-8") as handle:
    manifest = json.load(handle)

modules = manifest.get("modules") or []
roots = manifest.get("roots") or manifest.get("selectedModules") or []
if not isinstance(modules, list):
    raise SystemExit("modules must be an array")
if not isinstance(roots, list):
    raise SystemExit("roots must be an array when present")

providers = {}
for index, module in enumerate(modules):
    name = module.get("name")
    if not name:
        raise SystemExit(f"external module at index {index} is missing name")
    provided = [name] + list(module.get("provides") or [])
    for capability in provided:
        if not isinstance(capability, str) or not capability:
            raise SystemExit(f"external module '{name}' has invalid provider: {capability!r}")
        previous = providers.get(capability)
        if previous is not None:
            previous_name = modules[previous].get("name")
            raise SystemExit(f"external module provider conflict for '{capability}': {previous_name}, {name}")
        providers[capability] = index

def module_deps(index):
    name = modules[index].get("name")
    requires = modules[index].get("requires") or []
    if not isinstance(requires, list):
        raise SystemExit(f"external module '{name}' requires must be an array")
    deps = []
    for capability in requires:
        if not isinstance(capability, str) or not capability:
            raise SystemExit(f"external module '{name}' has invalid requirement: {capability!r}")
        target = providers.get(capability)
        if target is None:
            raise SystemExit(f"external module '{name}' requires missing provider: {capability}")
        deps.append(target)
    return deps

selected = []
state = {}

def visit(index, stack):
    mark = state.get(index)
    if mark == "done":
        return
    if mark == "visiting":
        cycle = " -> ".join(modules[i].get("name", str(i)) for i in stack + [index])
        raise SystemExit(f"external module dependency cycle: {cycle}")
    state[index] = "visiting"
    for dep in module_deps(index):
        visit(dep, stack + [index])
    state[index] = "done"
    selected.append(index)

if roots:
    for root in roots:
        if not isinstance(root, str) or not root:
            raise SystemExit(f"external module root must be a non-empty string: {root!r}")
        index = providers.get(root)
        if index is None:
            raise SystemExit(f"external module root has no provider: {root}")
        visit(index, [])
else:
    for index in range(len(modules)):
        visit(index, [])

for index in selected:
    print(index)
PY
}

external_modules_resolve() {
  local site_manifest_path="$1"
  local pin_file manifest_remote manifest_ref manifest_commit manifest_path manifest_repo manifest_file
  local module_count metadata_lines resolved_indices index schema_version

  rm -rf "$EXTERNAL_MODULES_ROOT"
  mkdir -p "$EXTERNAL_MODULES_MATERIALIZED_DIR"

  if ! external_modules_enabled "$site_manifest_path"; then
    jq -n '{enabled: false, manifest: null, modules: []}' > "$EXTERNAL_MODULES_METADATA_FILE"
    return 0
  fi

  pin_file="$(external_modules_manifest_pin_file "$site_manifest_path")"
  manifest_remote="$(jq -r '.moduleManifestRemote // empty' "$pin_file")"
  manifest_ref="$(jq -r '.moduleManifestRef // empty' "$pin_file")"
  manifest_commit="$(jq -r '.moduleManifestCommit // empty' "$pin_file")"
  manifest_path="$(jq -r '.moduleManifestPath // "modules.json"' "$pin_file")"
  external_modules_validate_relative_path "$manifest_path"

  manifest_repo="$(external_modules_clone_at_commit "module-manifest" "$manifest_remote" "$manifest_ref" "$manifest_commit")"
  manifest_file="$(realpath -e "$manifest_repo/$manifest_path")" || die "module manifest path not found: $manifest_path"
  EXTERNAL_MODULES_RESOLVED_MANIFEST_FILE="$manifest_file"
  case "$manifest_file" in
    "$manifest_repo"/*) ;;
    *) die "module manifest path escapes manifest repo: $manifest_path" ;;
  esac

  jq -e 'type == "object" and (.modules | type == "array")' "$manifest_file" >/dev/null || die "invalid external module manifest: expected object with modules array"
  schema_version="$(jq -r '.schemaVersion // 1' "$manifest_file")"
  if [ "$schema_version" = "2" ]; then
    "$SOURCE_ROOT/scripts/modules/resolve-module-lock.py" \
      --manifest-file "$manifest_file" \
      --cache-dir "$EXTERNAL_MODULES_CACHE_DIR" \
      --materialized-dir "$EXTERNAL_MODULES_MATERIALIZED_DIR" \
      --metadata-file "$EXTERNAL_MODULES_METADATA_FILE" \
      --source-root "$SOURCE_ROOT" \
      --manifest-remote "$manifest_remote" \
      --manifest-ref "$manifest_ref" \
      --manifest-commit "$manifest_commit" \
      --manifest-path "$manifest_path"
    external_modules_sanitize_materialized_tree
    return 0
  fi
  [ "$schema_version" = "1" ] || die "unsupported external module manifest schemaVersion: $schema_version"

  module_count="$(jq '.modules | length' "$manifest_file")"
  metadata_lines="$(mktemp)"
  if [ "$module_count" -gt 0 ]; then
    resolved_indices="$(external_modules_resolved_indices "$manifest_file")"
    for index in $resolved_indices; do
      external_modules_materialize_one "$manifest_file" "$index" "$metadata_lines"
    done
  fi

  jq -n \
    --arg remote "$manifest_remote" \
    --arg ref "$manifest_ref" \
    --arg commit "$manifest_commit" \
    --arg path "$manifest_path" \
    --slurpfile modules "$metadata_lines" \
    '{
      enabled: true,
      manifest: {git: $remote, ref: $ref, commit: $commit, path: $path},
      modules: $modules
    }' > "$EXTERNAL_MODULES_METADATA_FILE"
  rm -f "$metadata_lines"
  external_modules_sanitize_materialized_tree
}

external_modules_overlay_into() {
  local dest_root="$1"
  [ -d "$EXTERNAL_MODULES_MATERIALIZED_DIR" ] || return 0
  external_modules_sanitize_materialized_tree
  copy_tree "$EXTERNAL_MODULES_MATERIALIZED_DIR" "$dest_root"
}

external_modules_metadata_path() {
  printf '%s\n' "$EXTERNAL_MODULES_METADATA_FILE"
}
