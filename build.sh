#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/scripts/lib/common.sh"
# shellcheck source=scripts/lib/site-manifest.sh
source "$SCRIPT_DIR/scripts/lib/site-manifest.sh"
# shellcheck source=scripts/lib/runtime-contract.sh
source "$SCRIPT_DIR/scripts/lib/runtime-contract.sh"
# shellcheck source=scripts/lib/components.sh
source "$SCRIPT_DIR/scripts/lib/components.sh"
# shellcheck source=scripts/lib/external-modules.sh
source "$SCRIPT_DIR/scripts/lib/external-modules.sh"

SITE_MANIFEST_PATH=""
BUILD_PROFILE="production"
DIST_DIR="$SCRIPT_DIR/dist"
OUT_DIR="$SCRIPT_DIR/out"

usage() {
  cat <<'EOF_USAGE'
Usage:
  ./build.sh --manifest <path-to-manifest.json>

Builds the local deployable bundle in ./dist without decrypting secrets.
EOF_USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --manifest)
      [ "$#" -ge 2 ] || die "--manifest requires a value"
      SITE_MANIFEST_PATH="$2"
      shift
      ;;
    --profile)
      die "--profile has been retired; build.sh now produces the Podman production bundle only"
      ;;
    *)
      die "unknown argument for build.sh: $1"
      ;;
  esac
  shift
done

[ -n "$SITE_MANIFEST_PATH" ] || die "missing required --manifest <path-to-manifest.json>"
case "$BUILD_PROFILE" in
  production) ;;
  *) die "unsupported build profile: $BUILD_PROFILE" ;;
esac
site_manifest_path="$(resolve_site_manifest_file "$SITE_MANIFEST_PATH")"
if [ -z "${WEBSERVICES_CONTRACT_ROOT:-}" ] && [ ! -f "$SCRIPT_DIR/stack.config/components.json" ]; then
  manifest_bundle_root="$(cd "$(dirname "$site_manifest_path")/.." && pwd -P)"
  if [ -f "$manifest_bundle_root/stack.config/components.json" ]; then
    export WEBSERVICES_CONTRACT_ROOT="$manifest_bundle_root"
    log "using $WEBSERVICES_CONTRACT_ROOT for materialized contract checks"
  fi
fi

external_modules_resolve "$site_manifest_path"
"$SCRIPT_DIR/scripts/verify-module-lock-overrides.sh" "$site_manifest_path"
"$SCRIPT_DIR/scripts/verify-service-ownership.sh" "$site_manifest_path"
artifact_path="$("$SCRIPT_DIR/scripts/build-artifact.sh")"
mkdir -p "$OUT_DIR"
printf '%s\n' "$artifact_path" > "$OUT_DIR/latest-artifact-path.txt"

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR/build"

tar -xf "$artifact_path" -C "$DIST_DIR/build"
external_modules_overlay_into "$DIST_DIR/build"
if [ -d "$DIST_DIR/build/stack.runtime.external" ]; then
  runtime_contract_args=(
    --runtime-dir "$DIST_DIR/build/stack.runtime.external"
    --output-dir "$DIST_DIR/build/runtime.contract"
  )
  if [ -f "$DIST_DIR/build/global.settings/volumes.yml" ]; then
    runtime_contract_args+=(
      --global-volumes "$DIST_DIR/build/global.settings/volumes.yml"
    )
  fi
  "$SCRIPT_DIR/generate.sh" render-runtime-contract \
    "${runtime_contract_args[@]}"
fi
if [ ! -f "$DIST_DIR/build/global.settings/volumes.yml" ] && [ -f "$DIST_DIR/build/runtime.contract/stack-foundation.yml" ]; then
  mkdir -p "$DIST_DIR/build/global.settings"
  {
    printf 'volumes:\n'
    extract_top_level_section "$DIST_DIR/build/runtime.contract/stack-foundation.yml" 'volumes:'
  } > "$DIST_DIR/build/global.settings/volumes.yml"
fi
cp "$OUT_DIR/latest-build.json" "$DIST_DIR/build/build-info.json"
external_modules_metadata="$(external_modules_metadata_path)"
if [ -f "$external_modules_metadata" ]; then
  build_info_temp="$(mktemp)"
  jq --slurpfile externalModules "$external_modules_metadata" \
    '. + {externalModules: $externalModules[0]}' \
    "$DIST_DIR/build/build-info.json" > "$build_info_temp"
  mv "$build_info_temp" "$DIST_DIR/build/build-info.json"
fi
cp "$artifact_path" "$DIST_DIR/build/artifact.tar"
sha256sum "$DIST_DIR/build/artifact.tar" | awk '{print $1}' > "$DIST_DIR/build/artifact.sha256"

stage_site_manifest_bundle "$site_manifest_path" "$DIST_DIR/build/site"
component_catalog="$DIST_DIR/build/stack.config/components.json"
component_catalog_merge_external "$component_catalog"
component_selection_write_metadata "$site_manifest_path" "$component_catalog" "$DIST_DIR/build/site/components.lock.json"
"$SCRIPT_DIR/scripts/generate-contract-reports.sh" \
  --catalog "$component_catalog" \
  --contracts "$DIST_DIR/build/stack.config/service-contracts.json" \
  --profiles "$DIST_DIR/build/stack.config/portal-profiles.json" \
  --theme "$DIST_DIR/build/stack.config/theme-contract.json" \
  --demo-content "$DIST_DIR/build/stack.config/demo-content-contract.json" \
  --pos-exploration "$DIST_DIR/build/stack.config/pos-exploration.json" \
  --lock "$DIST_DIR/build/site/components.lock.json" \
  --output-dir "$DIST_DIR/build/reports"
log "selected components: $(jq -r '.components | join(", ")' "$DIST_DIR/build/site/components.lock.json")"
build_runtime_contract "$DIST_DIR/build" "$DIST_DIR/build/runtime-contract.yml" "$site_manifest_path"
rewrite_runtime_contract_paths "$DIST_DIR/build/runtime-contract.yml"
rewrite_runtime_contract_paths "$DIST_DIR/build/runtime.contract/test-runners.yml"
log "validating generated runtime-contract.yml"
validate_runtime_contract "$DIST_DIR/build" "$DIST_DIR/build/runtime-contract.yml"
if [ ! -f "$DIST_DIR/build/stack.systemd/graph.json" ]; then
  mkdir -p "$DIST_DIR/build/stack.systemd"
  cat > "$DIST_DIR/build/stack.systemd/graph.json" <<'EOF_SYSTEMD_GRAPH'
{
  "unitPrefix": "webservices",
  "defaultTarget": {
    "name": "webservices.target",
    "description": "Web Services",
    "includeUnitsFromNonOnDemandDomains": true
  },
  "auxiliaryTargets": [],
  "lifecycleDomains": [],
  "excludedServices": [],
  "onDemandServices": [],
  "onDemandDomains": []
}
EOF_SYSTEMD_GRAPH
fi
log "rendering systemd user units"
"$SCRIPT_DIR/scripts/deploy/render-systemd-user.sh" \
  --bundle-root "$DIST_DIR/build" \
  --output-dir "$DIST_DIR/build/systemd-user"

cat > "$DIST_DIR/build/.dockerignore" <<'EOF_DOCKERIGNORE'
artifact.tar
artifact.sha256
build-info.json
runtime
systemd-user
EOF_DOCKERIGNORE

cat > "$DIST_DIR/deploy.sh" <<'EOF_DEPLOY'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "$SCRIPT_DIR/build/scripts/deploy.sh" "$@"
EOF_DEPLOY

cat > "$DIST_DIR/verify.sh" <<'EOF_VERIFY'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "$SCRIPT_DIR/build/scripts/verify.sh" "$@"
EOF_VERIFY

cat > "$DIST_DIR/run-tests.sh" <<'EOF_RUN_TESTS'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
export DIST_DIR="$SCRIPT_DIR/build"
exec "$SCRIPT_DIR/build/stack.containers/test-runner/run-tests.sh" "$@"
EOF_RUN_TESTS

cat > "$DIST_DIR/stackctl" <<'EOF_STACKCTL'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "$SCRIPT_DIR/build/scripts/stackctl.sh" "$@"
EOF_STACKCTL

cat > "$DIST_DIR/install.sh" <<'EOF_INSTALL'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "$SCRIPT_DIR/build/scripts/install-bundle.sh" "$@"
EOF_INSTALL

chmod +x "$DIST_DIR/deploy.sh" "$DIST_DIR/verify.sh" "$DIST_DIR/run-tests.sh" "$DIST_DIR/stackctl" "$DIST_DIR/install.sh"

# The bundled artifact uses normalized mtimes for reproducibility. Refresh them in dist/
# so rsync -a notices changed files even when size stays the same.
find "$DIST_DIR" -exec touch {} +

log "dist ready at $DIST_DIR"
