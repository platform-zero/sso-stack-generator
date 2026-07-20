#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=scripts/lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"
# shellcheck source=scripts/lib/site-manifest.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/site-manifest.sh"
# shellcheck source=scripts/lib/external-modules.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/external-modules.sh"

readonly ALLOWLIST_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/modules/service-ownership-allowlist.txt"
SITE_MANIFEST_PATH="${1:-}"

if [ -z "$SITE_MANIFEST_PATH" ]; then
  die "usage: $0 <site-manifest.json>"
fi

SITE_MANIFEST_PATH="$(resolve_site_manifest_file "$SITE_MANIFEST_PATH")"

if ! external_modules_enabled "$SITE_MANIFEST_PATH"; then
  log "service ownership check skipped: no external modules configured"
  exit 0
fi

if [ ! -f "$EXTERNAL_MODULES_RESOLVED_MANIFEST_FILE" ]; then
  external_modules_resolve "$SITE_MANIFEST_PATH"
fi

if [ ! -d "$EXTERNAL_MODULES_MATERIALIZED_DIR" ]; then
  log "service ownership check skipped: no external module materialization found"
  exit 0
fi

declare -A OWNED
while IFS= read -r file_path; do
  [ -n "$file_path" ] || continue
  OWNED["$file_path"]=1
done < <(
  (cd "$EXTERNAL_MODULES_MATERIALIZED_DIR" && rg --files 2>/dev/null | sed '/^$/d')
)

declare -A ALLOWED
if [ -f "$ALLOWLIST_FILE" ]; then
  while IFS= read -r line; do
    line="${line#"${line%%[![:space:]]*}"}"
    line="${line%"${line##*[![:space:]]}"}"
    case "$line" in
      ''|\#*) continue ;;
    esac
    ALLOWED["$line"]=1
  done < "$ALLOWLIST_FILE"
fi

is_allowed() {
  local path="$1"
  local pattern
  for pattern in "${!ALLOWED[@]}"; do
    if [[ "$path" == "$pattern" || "$path" == "${pattern%/}"/* ]]; then
      return 0
    fi
  done
  return 1
}

service_roots=(
  global.settings
  runtime.overlays
  stack.config
  stack.containers
  stack.kotlin
  stack.js
  stack.systemd
  scripts/lib
  scripts/modules
)

declare -a violations=()

for root in "${service_roots[@]}"; do
  [ -d "$SOURCE_ROOT/$root" ] || continue
  while IFS= read -r candidate; do
    [ -n "$candidate" ] || continue
    rel_path="${candidate#"$SOURCE_ROOT/"}"
    if is_allowed "$rel_path"; then
      continue
    fi
    if [ "${OWNED[$rel_path]+x}" ]; then
      continue
    fi
    violations+=("$rel_path")
  done < <(find "$SOURCE_ROOT/$root" -type f -print | sed "s#^$SOURCE_ROOT/##" | sort)
done

if [ "${#violations[@]}" -gt 0 ]; then
  log "service ownership check failed: ${#violations[@]} files are unowned by modules"
  for path in "${violations[@]}"; do
    printf '  - %s\n' "$path"
  done | sort
  exit 1
fi

log "service ownership check passed"
