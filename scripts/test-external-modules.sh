#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "[external-modules-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT_DIR/scripts/lib/common.sh"
# shellcheck source=scripts/lib/components.sh
source "$ROOT_DIR/scripts/lib/components.sh"
# shellcheck source=scripts/lib/external-modules.sh
source "$ROOT_DIR/scripts/lib/external-modules.sh"

git_commit_all() {
  local repo_dir="$1"
  local message="$2"
  git -C "$repo_dir" add .
  git -C "$repo_dir" \
    -c user.name="External Module Test" \
    -c user.email="external-module-test@example.invalid" \
    commit -m "$message" >/dev/null
  git -C "$repo_dir" rev-parse HEAD
}

assert_file() {
  local file="$1"
  [ -f "$file" ] || {
    printf '[external-modules-test] expected file: %s\n' "$file" >&2
    exit 1
  }
}

tmp_root="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_root"
}
trap cleanup EXIT

EXTERNAL_MODULES_CACHE_DIR="$tmp_root/external-git"
EXTERNAL_MODULES_ROOT="$tmp_root/external-modules"
EXTERNAL_MODULES_MATERIALIZED_DIR="$EXTERNAL_MODULES_ROOT/materialized"
EXTERNAL_MODULES_METADATA_FILE="$EXTERNAL_MODULES_ROOT/metadata.json"

module_repo="$tmp_root/demo-module"
manifest_repo="$tmp_root/module-manifest"
site_root="$tmp_root/site"
bundle_root="$tmp_root/bundle"
mkdir -p "$module_repo" "$manifest_repo" "$site_root" "$bundle_root/stack.config"
git -C "$module_repo" init -b main >/dev/null
git -C "$manifest_repo" init -b main >/dev/null

mkdir -p "$module_repo/stack.compose" "$module_repo/stack.config" "$module_repo/tests"
cat > "$module_repo/README.md" <<'EOF_README'
# Demo module
EOF_README
cat > "$module_repo/stack.module.json" <<'EOF_STACK_MODULE'
{
  "schemaVersion": 1,
  "id": "demo-module",
  "repo": "demo-module-stack-module",
  "lifecycle": "active",
  "overlays": ["stack.compose/demo.yml", "stack.config/components.json"]
}
EOF_STACK_MODULE
cat > "$module_repo/tests/validate.sh" <<'EOF_VALIDATE'
#!/usr/bin/env bash
true
EOF_VALIDATE
cat > "$module_repo/stack.compose/demo.yml" <<'EOF_COMPOSE'
services:
  demo-module:
    image: caddy:2.11.3
EOF_COMPOSE
cat > "$module_repo/stack.config/components.json" <<'EOF_COMPONENTS'
{
  "schemaVersion": 1,
  "defaultComponents": [],
  "components": {
    "demo-module": {
      "name": "Demo module",
      "description": "External module test service.",
      "dependencies": ["core"],
      "composeFiles": ["demo.yml"]
    }
  }
}
EOF_COMPONENTS
module_commit="$(git_commit_all "$module_repo" "Add demo module")"

cat > "$manifest_repo/modules.json" <<EOF_MODULES
{
  "modules": [
    {
      "name": "demo-module",
      "git": "$module_repo",
      "ref": "main",
      "commit": "$module_commit"
    }
  ]
}
EOF_MODULES
manifest_commit="$(git_commit_all "$manifest_repo" "Add module manifest")"

cat > "$site_root/manifest.json" <<'EOF_SITE'
{
  "site": "external-module-test",
  "stackConfig": "stack.config.yaml",
  "secretStore": "webservices.sops.json",
  "components": ["demo-module"]
}
EOF_SITE
cat > "$site_root/stack.config.yaml" <<'EOF_CONFIG'
runtime:
  domain: "example.test"
EOF_CONFIG
cat > "$site_root/webservices.sops.json" <<'EOF_SECRETS'
{}
EOF_SECRETS
cat > "$site_root/.webservices-generator.json" <<EOF_PIN
{
  "generatorRemote": "local",
  "generatorRef": "dev",
  "generatorCommit": "local",
  "moduleManifestRemote": "$manifest_repo",
  "moduleManifestRef": "main",
  "moduleManifestCommit": "$manifest_commit"
}
EOF_PIN

external_modules_resolve "$site_root/manifest.json"
assert_file "$EXTERNAL_MODULES_MATERIALIZED_DIR/stack.compose/demo.yml"
assert_file "$EXTERNAL_MODULES_MATERIALIZED_DIR/stack.config/components.external/demo-module.json"
[ ! -e "$EXTERNAL_MODULES_MATERIALIZED_DIR/stack.module.json" ] || die "stack.module.json should not be materialized"
[ ! -e "$EXTERNAL_MODULES_MATERIALIZED_DIR/README.md" ] || die "README.md should not be materialized"
jq -e '.enabled == true and (.modules | length) == 1 and .modules[0].name == "demo-module"' \
  "$EXTERNAL_MODULES_METADATA_FILE" >/dev/null

external_modules_overlay_into "$bundle_root"
component_catalog_merge_external "$bundle_root/stack.config/components.json"
jq -e '.components["demo-module"].composeFiles == ["demo.yml"]' "$bundle_root/stack.config/components.json" >/dev/null

bad_repo="$tmp_root/bad-module"
mkdir -p "$bad_repo/scripts"
git -C "$bad_repo" init -b main >/dev/null
cat > "$bad_repo/scripts/not-allowed.sh" <<'EOF_BAD'
#!/usr/bin/env bash
true
EOF_BAD
bad_commit="$(git_commit_all "$bad_repo" "Add unsupported path")"
cat > "$manifest_repo/modules.json" <<EOF_BAD_MODULES
{
  "modules": [
    {
      "name": "bad-module",
      "git": "$bad_repo",
      "ref": "main",
      "commit": "$bad_commit"
    }
  ]
}
EOF_BAD_MODULES
bad_manifest_commit="$(git_commit_all "$manifest_repo" "Add bad module manifest")"
jq --arg commit "$bad_manifest_commit" '.moduleManifestCommit = $commit' "$site_root/.webservices-generator.json" > "$site_root/pin.tmp"
mv "$site_root/pin.tmp" "$site_root/.webservices-generator.json"
trap - ERR
set +e
( external_modules_resolve "$site_root/manifest.json" ) >/dev/null 2>&1
bad_status=$?
set -e
trap 'status=$?; printf "[external-modules-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR
if [ "$bad_status" -eq 0 ]; then
  printf '[external-modules-test] unsupported module path was accepted\n' >&2
  exit 1
fi

foundation_repo="$tmp_root/foundation-stack-module"
app_repo="$tmp_root/app-stack-module"
cycle_repo="$tmp_root/cycle-stack-module"
mkdir -p "$foundation_repo/stack.config" "$app_repo/stack.compose" "$cycle_repo/stack.compose"
git -C "$foundation_repo" init -b main >/dev/null
git -C "$app_repo" init -b main >/dev/null
git -C "$cycle_repo" init -b main >/dev/null
cat > "$foundation_repo/stack.config/components.json" <<'EOF_V2_FOUNDATION_COMPONENTS'
{
  "schemaVersion": 1,
  "defaultComponents": [],
  "components": {}
}
EOF_V2_FOUNDATION_COMPONENTS
cat > "$foundation_repo/stack.module.json" <<'EOF_V2_FOUNDATION'
{
  "schemaVersion": 1,
  "id": "foundation-test",
  "repo": "foundation-test-stack-module",
  "lifecycle": "active",
  "dependencies": [],
  "overlays": ["stack.config/components.json"]
}
EOF_V2_FOUNDATION
cat > "$app_repo/stack.compose/app-test.yml" <<'EOF_V2_APP_COMPOSE'
services:
  app-test:
    image: caddy:2.11.3
EOF_V2_APP_COMPOSE
mkdir -p "$app_repo/stack.config/app-test"
cat > "$app_repo/stack.config/app-test/stale.yml" <<'EOF_V2_APP_STALE'
stale: true
EOF_V2_APP_STALE
cat > "$app_repo/stack.module.json" <<'EOF_V2_APP'
{
  "schemaVersion": 1,
  "id": "app-test",
  "repo": "app-test-stack-module",
  "lifecycle": "active",
  "dependencies": ["foundation-test"],
  "overlays": ["stack.compose/app-test.yml"]
}
EOF_V2_APP
cat > "$cycle_repo/stack.compose/cycle-test.yml" <<'EOF_V2_CYCLE_COMPOSE'
services:
  cycle-test:
    image: caddy:2.11.3
EOF_V2_CYCLE_COMPOSE
cat > "$cycle_repo/stack.module.json" <<'EOF_V2_CYCLE'
{
  "schemaVersion": 1,
  "id": "cycle-test",
  "repo": "cycle-test-stack-module",
  "lifecycle": "active",
  "dependencies": ["cycle-test"],
  "overlays": ["stack.compose/cycle-test.yml"]
}
EOF_V2_CYCLE
foundation_commit="$(git_commit_all "$foundation_repo" "Add foundation v2 module")"
app_commit="$(git_commit_all "$app_repo" "Add app v2 module")"
cycle_commit="$(git_commit_all "$cycle_repo" "Add cycle v2 module")"

cat > "$manifest_repo/modules.json" <<EOF_V2_MODULES
{
  "schemaVersion": 2,
  "roots": ["app-test"],
  "modules": [
    {
      "id": "foundation-test",
      "repo": "foundation-test-stack-module",
      "git": "$foundation_repo",
      "ref": "main",
      "commit": "$foundation_commit",
      "overrides": ["stack.config/components.json"]
    },
    {
      "id": "app-test",
      "repo": "app-test-stack-module",
      "git": "$app_repo",
      "ref": "main",
      "commit": "$app_commit",
      "overrides": ["stack.compose/app-test.yml"]
    }
  ]
}
EOF_V2_MODULES
v2_manifest_commit="$(git_commit_all "$manifest_repo" "Add v2 module lock")"
jq --arg commit "$v2_manifest_commit" '.moduleManifestCommit = $commit' "$site_root/.webservices-generator.json" > "$site_root/pin.tmp"
mv "$site_root/pin.tmp" "$site_root/.webservices-generator.json"
external_modules_resolve "$site_root/manifest.json"
trap - ERR
set +e
( "$ROOT_DIR/scripts/verify-module-lock-overrides.sh" "$site_root/manifest.json" ) >/dev/null 2>&1
undeclared_surface_status=$?
set -e
trap 'status=$?; printf "[external-modules-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR
if [ "$undeclared_surface_status" -eq 0 ]; then
  printf '[external-modules-test] undeclared v2 deploy-surface file was accepted\n' >&2
  exit 1
fi
assert_file "$EXTERNAL_MODULES_MATERIALIZED_DIR/stack.config/components.external/foundation-test.json"
assert_file "$EXTERNAL_MODULES_MATERIALIZED_DIR/stack.compose/app-test.yml"
jq -e '.schemaVersion == 2 and (.modules | map(.id)) == ["foundation-test", "app-test"]' \
  "$EXTERNAL_MODULES_METADATA_FILE" >/dev/null

git -C "$app_repo" rm stack.config/app-test/stale.yml >/dev/null
app_clean_commit="$(git_commit_all "$app_repo" "Remove undeclared app v2 module surface")"

cat > "$manifest_repo/modules.json" <<EOF_V2_MODULES_CLEAN
{
  "schemaVersion": 2,
  "roots": ["app-test"],
  "modules": [
    {
      "id": "foundation-test",
      "repo": "foundation-test-stack-module",
      "git": "$foundation_repo",
      "ref": "main",
      "commit": "$foundation_commit",
      "overrides": ["stack.config/components.json"]
    },
    {
      "id": "app-test",
      "repo": "app-test-stack-module",
      "git": "$app_repo",
      "ref": "main",
      "commit": "$app_clean_commit",
      "overrides": ["stack.compose/app-test.yml"]
    }
  ]
}
EOF_V2_MODULES_CLEAN
v2_clean_manifest_commit="$(git_commit_all "$manifest_repo" "Add clean v2 module lock")"
jq --arg commit "$v2_clean_manifest_commit" '.moduleManifestCommit = $commit' "$site_root/.webservices-generator.json" > "$site_root/pin.tmp"
mv "$site_root/pin.tmp" "$site_root/.webservices-generator.json"
external_modules_resolve "$site_root/manifest.json"
"$ROOT_DIR/scripts/verify-module-lock-overrides.sh" "$site_root/manifest.json"

cat > "$manifest_repo/modules.json" <<EOF_V2_STALE_OVERRIDES
{
  "schemaVersion": 2,
  "roots": ["app-test"],
  "modules": [
    {
      "id": "foundation-test",
      "repo": "foundation-test-stack-module",
      "git": "$foundation_repo",
      "ref": "main",
      "commit": "$foundation_commit",
      "overrides": ["stack.config/components.json"]
    },
    {
      "id": "app-test",
      "repo": "app-test-stack-module",
      "git": "$app_repo",
      "ref": "main",
      "commit": "$app_clean_commit",
      "overrides": ["stack.compose/missing.yml"]
    }
  ]
}
EOF_V2_STALE_OVERRIDES
stale_override_commit="$(git_commit_all "$manifest_repo" "Add stale v2 override lock")"
jq --arg commit "$stale_override_commit" '.moduleManifestCommit = $commit' "$site_root/.webservices-generator.json" > "$site_root/pin.tmp"
mv "$site_root/pin.tmp" "$site_root/.webservices-generator.json"
external_modules_resolve "$site_root/manifest.json"
trap - ERR
set +e
( "$ROOT_DIR/scripts/verify-module-lock-overrides.sh" "$site_root/manifest.json" ) >/dev/null 2>&1
stale_override_status=$?
set -e
trap 'status=$?; printf "[external-modules-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR
if [ "$stale_override_status" -eq 0 ]; then
  printf '[external-modules-test] stale v2 override was accepted\n' >&2
  exit 1
fi

cat > "$manifest_repo/modules.json" <<EOF_V2_BAD_NAME
{
  "schemaVersion": 2,
  "modules": [
    {
      "id": "app-test",
      "repo": "wrong-repo",
      "git": "$app_repo",
      "ref": "main",
      "commit": "$app_commit"
    }
  ]
}
EOF_V2_BAD_NAME
bad_name_commit="$(git_commit_all "$manifest_repo" "Add bad v2 name lock")"
trap - ERR
set +e
( "$ROOT_DIR/scripts/modules/resolve-module-lock.py" \
  --manifest-file "$manifest_repo/modules.json" \
  --cache-dir "$tmp_root/v2-negative-cache" \
  --materialized-dir "$tmp_root/v2-negative-materialized" \
  --metadata-file "$tmp_root/v2-negative-metadata.json" \
  --source-root "$ROOT_DIR" \
  --manifest-remote "$manifest_repo" \
  --manifest-ref main \
  --manifest-commit "$bad_name_commit" \
  --manifest-path modules.json ) >/dev/null 2>&1
bad_name_status=$?
set -e
trap 'status=$?; printf "[external-modules-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR
if [ "$bad_name_status" -eq 0 ]; then
  printf '[external-modules-test] v2 repo mismatch was accepted\n' >&2
  exit 1
fi

cat > "$manifest_repo/modules.json" <<EOF_V2_CYCLE
{
  "schemaVersion": 2,
  "modules": [
    {
      "id": "cycle-test",
      "repo": "cycle-test-stack-module",
      "git": "$cycle_repo",
      "ref": "main",
      "commit": "$cycle_commit"
    }
  ]
}
EOF_V2_CYCLE
cycle_manifest_commit="$(git_commit_all "$manifest_repo" "Add v2 cycle lock")"
trap - ERR
set +e
( "$ROOT_DIR/scripts/modules/resolve-module-lock.py" \
  --manifest-file "$manifest_repo/modules.json" \
  --cache-dir "$tmp_root/v2-cycle-cache" \
  --materialized-dir "$tmp_root/v2-cycle-materialized" \
  --metadata-file "$tmp_root/v2-cycle-metadata.json" \
  --source-root "$ROOT_DIR" \
  --manifest-remote "$manifest_repo" \
  --manifest-ref main \
  --manifest-commit "$cycle_manifest_commit" \
  --manifest-path modules.json ) >/dev/null 2>&1
cycle_status=$?
set -e
trap 'status=$?; printf "[external-modules-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR
if [ "$cycle_status" -eq 0 ]; then
  printf '[external-modules-test] v2 dependency cycle was accepted\n' >&2
  exit 1
fi

printf '[external-modules-test] ok\n' >&2
