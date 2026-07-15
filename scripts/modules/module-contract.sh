#!/usr/bin/env bash
set -euo pipefail

mode="${1:-}"
repo_root="${2:-}"

usage() {
  cat >&2 <<'EOF'
Usage: scripts/modules/module-contract.sh validate|contract /path/to/module
EOF
}

case "$mode" in
  validate|contract) ;;
  *)
    usage
    exit 2
    ;;
esac

[ -n "$repo_root" ] || { usage; exit 2; }
[ -d "$repo_root" ] || { printf '[module-contract] missing module root: %s\n' "$repo_root" >&2; exit 1; }
repo_root="$(cd "$repo_root" && pwd -P)"
metadata="$repo_root/stack.module.json"
[ -f "$metadata" ] || { printf '[module-contract] missing stack.module.json: %s\n' "$repo_root" >&2; exit 1; }

python3 - "$mode" "$metadata" "$repo_root" <<'PY'
import json
import pathlib
import sys

mode = sys.argv[1]
metadata_path = pathlib.Path(sys.argv[2])
repo_root = pathlib.Path(sys.argv[3])
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))

required = ["overlays"]
if mode == "contract":
    required += ["runtimeDependencies", "contracts", "testAssets"]
for key in required:
    if key not in metadata:
        raise SystemExit(f"missing metadata key: {key}")

if mode == "contract" and "module-contract" not in metadata.get("contracts", []):
    raise SystemExit("missing module-contract declaration")

for key in ("overlays", "testAssets"):
    values = metadata.get(key, [])
    for value in values:
        path = pathlib.Path(value)
        if path.is_absolute() or "." in path.parts or ".." in path.parts:
            raise SystemExit(f"{key} path is unsafe: {value}")
        if not (repo_root / path).exists():
            raise SystemExit(f"missing {key} path: {value}")
        if key == "testAssets" and not value.startswith("tests/fixtures/") and value != "tests/fixtures":
            raise SystemExit(f"testAssets must be source-only paths under tests/fixtures: {value}")

overlays = metadata.get("overlays", [])
for asset in metadata.get("testAssets", []):
    if any(asset == overlay or asset.startswith(overlay.rstrip("/") + "/") for overlay in overlays):
        raise SystemExit(f"testAssets must not overlap deployable overlays: {asset}")

if mode != "contract":
    raise SystemExit(0)

dependencies = metadata.get("dependencies", [])
runtime_dependencies = metadata.get("runtimeDependencies", [])
module_id = metadata.get("id", "")
is_content_pack = (
    not (repo_root / "stack.runtime.yaml").exists()
    and not any(path.startswith(("stack.containers/", "stack.kotlin/", "stack.js/")) for path in metadata.get("overlays", []))
)
if is_content_pack and runtime_dependencies != dependencies:
    raise SystemExit("content-pack runtime dependencies must match dependencies")
if module_id in runtime_dependencies:
    raise SystemExit("module may not depend on itself at runtime")

if (repo_root / "stack.kotlin").exists():
    has_build = any(repo_root.joinpath("stack.kotlin").rglob("build.gradle.kts"))
    if not has_build and not any(path.startswith("stack.kotlin/") for path in metadata.get("overlays", [])):
        raise SystemExit("[module-contract] stack.kotlin exists without build.gradle.kts and is not declared as overlay-only")

if (repo_root / "stack.containers").exists():
    has_containerfile = any(repo_root.joinpath("stack.containers").rglob("Containerfile"))
    if not has_containerfile and not any(path.startswith("stack.containers/") for path in metadata.get("overlays", [])):
        raise SystemExit("[module-contract] stack.containers exists without Containerfile and is not declared as overlay-only")
PY

if [ "$mode" = "contract" ]; then
  while IFS= read -r -d '' script; do
    bash -n "$script"
    if command -v shellcheck >/dev/null 2>&1; then
      shellcheck "$script"
    fi
  done < <(find "$repo_root" \
    -path '*/.git' -prune -o \
    -path '*/node_modules' -prune -o \
    -type f -name '*.sh' -print0)

  if [ -d "$repo_root/stack.js" ]; then
    while IFS= read -r package_json; do
      package_dir="${package_json%/package.json}"
      test -f "$package_dir/package-lock.json" || {
        printf '[module-contract] JS package lacks package-lock.json: %s\n' "$package_dir" >&2
        exit 1
      }
    done < <(find "$repo_root/stack.js" -path '*/node_modules' -prune -o -name package.json -type f -print)
  fi
fi

printf '[module-contract] ok\n' >&2
