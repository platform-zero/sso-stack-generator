#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "[module-composition] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
MODULES_WORKSPACE="${1:-${WEBSERVICES_MODULES_WORKSPACE:-$ROOT_DIR/../modules}}"

[ -d "$MODULES_WORKSPACE" ] || {
  printf '[module-composition] module workspace not found: %s\n' "$MODULES_WORKSPACE" >&2
  exit 1
}
MODULES_WORKSPACE="$(cd "$MODULES_WORKSPACE" && pwd -P)"
command -v jq >/dev/null
command -v rsync >/dev/null
command -v java >/dev/null
command -v npm >/dev/null
command -v python3 >/dev/null

tmp_root="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_root"
}
trap cleanup EXIT

normalized_modules="$tmp_root/modules"
composition="$tmp_root/composition"
mkdir -p "$normalized_modules" "$composition"

mapfile -t manifests < <(find "$MODULES_WORKSPACE" -mindepth 2 -maxdepth 3 -name stack.module.json -type f -print | sort)
[ "${#manifests[@]}" -gt 0 ] || {
  printf '[module-composition] no stack.module.json files found under %s\n' "$MODULES_WORKSPACE" >&2
  exit 1
}

declare -A module_roots=()
for manifest in "${manifests[@]}"; do
  module_root="$(dirname "$manifest")"
  module_id="$(jq -r '.id // empty' "$manifest")"
  [ -n "$module_id" ] || {
    printf '[module-composition] module id missing: %s\n' "$manifest" >&2
    exit 1
  }
  [ -z "${module_roots[$module_id]:-}" ] || {
    printf '[module-composition] duplicate module id %s: %s and %s\n' "$module_id" "${module_roots[$module_id]}" "$module_root" >&2
    exit 1
  }
  module_roots[$module_id]="$module_root"
  ln -s "$module_root" "$normalized_modules/$module_id"
done

printf '[module-composition] validating %s modules individually\n' "${#module_roots[@]}"
mapfile -t module_ids < <(printf '%s\n' "${!module_roots[@]}" | sort)
for module_id in "${module_ids[@]}"; do
  "$ROOT_DIR/scripts/test-module.sh" --all "${module_roots[$module_id]}"
done

printf '[module-composition] checking unique runtime volume ownership\n'
python3 - "${manifests[@]}" <<'PY'
import json
import sys
from pathlib import Path

owners: dict[str, list[str]] = {}
for manifest_path in map(Path, sys.argv[1:]):
    metadata = json.loads(manifest_path.read_text(encoding="utf-8"))
    runtime_path = manifest_path.parent / "stack.runtime.yaml"
    if not runtime_path.is_file():
        continue
    in_volumes = False
    for line in runtime_path.read_text(encoding="utf-8").splitlines():
        if line == "volumes:":
            in_volumes = True
            continue
        if in_volumes and line and not line.startswith((" ", "\t", "#")):
            in_volumes = False
        if not in_volumes or not line.startswith("  ") or line.startswith("    "):
            continue
        stripped = line.strip()
        if stripped.endswith(":") and not stripped.startswith("#"):
            owners.setdefault(stripped[:-1], []).append(metadata["id"])

duplicates = {name: ids for name, ids in owners.items() if len(ids) > 1}
if duplicates:
    for name, ids in sorted(duplicates.items()):
        print(f"duplicate runtime volume ownership: {name}: {', '.join(ids)}", file=sys.stderr)
    raise SystemExit(1)
PY

rsync -a \
  --exclude '.git/' \
  --exclude '.gradle/' \
  --exclude 'build/' \
  --exclude 'dist/' \
  --exclude 'modules-workspace/' \
  --exclude 'node_modules/' \
  --exclude 'out/' \
  "$ROOT_DIR/" "$composition/"
rm -rf \
  "$composition/stack.kotlin/test-runner" \
  "$composition/stack.containers/test-runner/playwright-tests"

copy_overlay() {
  local module_root="$1" overlay="$2" source_path destination_path
  [ "$overlay" != "stack.runtime.yaml" ] || return 0
  source_path="$module_root/$overlay"
  destination_path="$composition/$overlay"
  if [ -d "$source_path" ]; then
    mkdir -p "$destination_path"
    rsync -a --exclude '.git/' --exclude 'build/' --exclude 'node_modules/' "$source_path/" "$destination_path/"
  else
    mkdir -p "$(dirname "$destination_path")"
    cp -a "$source_path" "$destination_path"
  fi
}

for module_id in "${module_ids[@]}"; do
  module_root="${module_roots[$module_id]}"
  while IFS= read -r overlay; do
    copy_overlay "$module_root" "$overlay"
  done < <(jq -r '.overlays[]' "$module_root/stack.module.json")
done

export WEBSERVICES_MODULES_ROOT="$normalized_modules"
export WEBSERVICES_GENERATOR_ROOT="$ROOT_DIR"
export CADDY_HOSTS_FILE="$composition/stack.containers/test-runner/fixtures/caddy-hosts.txt"

printf '[module-composition] compiling and running the complete Kotlin source suite\n'
"$composition/gradlew" -p "$composition" test --no-daemon

playwright_dir="$composition/stack.containers/test-runner/playwright-tests"
[ -f "$playwright_dir/package-lock.json" ] || {
  printf '[module-composition] composed Playwright package-lock.json is missing\n' >&2
  exit 1
}
printf '[module-composition] installing and validating the complete TypeScript source suite\n'
npm --prefix "$playwright_dir" ci --ignore-scripts
npm --prefix "$playwright_dir" run build
npm --prefix "$playwright_dir" run test:unit -- --runInBand
(
  cd "$playwright_dir"
  PW_SKIP_GLOBAL_SETUP=1 npx playwright test --list
)

printf '[module-composition] validating generated runtime from the composed module set\n'
MODULES_DIR="$normalized_modules" "$ROOT_DIR/scripts/test-runtime-generator.sh"

printf '[module-composition] ok: %s independently validated modules\n' "${#module_roots[@]}"
