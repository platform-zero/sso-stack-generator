#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/scripts/lib/common.sh"
# shellcheck source=scripts/lib/site-manifest.sh
source "$SCRIPT_DIR/scripts/lib/site-manifest.sh"
# shellcheck source=scripts/lib/compose.sh
source "$SCRIPT_DIR/scripts/lib/compose.sh"
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
  ./build.sh --manifest <path-to-manifest.json> [--profile production|testdev]

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
      [ "$#" -ge 2 ] || die "--profile requires a value"
      BUILD_PROFILE="$2"
      shift
      ;;
    *)
      die "unknown argument for build.sh: $1"
      ;;
  esac
  shift
done

[ -n "$SITE_MANIFEST_PATH" ] || die "missing required --manifest <path-to-manifest.json>"
case "$BUILD_PROFILE" in
  production|testdev) ;;
  *) die "unsupported build profile: $BUILD_PROFILE" ;;
esac
site_manifest_path="$(resolve_site_manifest_file "$SITE_MANIFEST_PATH")"

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
build_merged_compose "$DIST_DIR/build" "$DIST_DIR/build/docker-compose.yml" "$site_manifest_path"
rewrite_compose_runtime_paths "$DIST_DIR/build/docker-compose.yml"
rewrite_compose_runtime_paths "$DIST_DIR/build/stack.compose/test-runners.yml"
if [ "$BUILD_PROFILE" = "testdev" ]; then
  log "applying testdev compose profile"
  "$SCRIPT_DIR/scripts/testdev/transform-compose.py" \
    --compose-file "$DIST_DIR/build/docker-compose.yml" \
    --output-file "$DIST_DIR/build/docker-compose.yml"
  "$SCRIPT_DIR/scripts/testdev/transform-test-runners.sh" \
    "$DIST_DIR/build/stack.compose/test-runners.yml"
fi
log "validating generated docker-compose.yml"
validate_generated_compose "$DIST_DIR/build" "$DIST_DIR/build/docker-compose.yml"
if [ "$BUILD_PROFILE" = "production" ]; then
  log "rendering systemd user units"
  "$SCRIPT_DIR/scripts/deploy/render-systemd-user.sh" \
    --bundle-root "$DIST_DIR/build" \
    --output-dir "$DIST_DIR/build/systemd-user"
else
  printf '%s\n' "$BUILD_PROFILE" > "$DIST_DIR/build/build-profile.txt"
fi

cat > "$DIST_DIR/build/.dockerignore" <<'EOF_DOCKERIGNORE'
artifact.tar
artifact.sha256
build-info.json
runtime
systemd-user
EOF_DOCKERIGNORE

if [ "$BUILD_PROFILE" = "testdev" ]; then
  cat > "$DIST_DIR/deploy.sh" <<'EOF_DEPLOY'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
echo "This is a testdev bundle. Use $SCRIPT_DIR/testdev-up.sh instead of deploy.sh." >&2
exit 2
EOF_DEPLOY

  cat > "$DIST_DIR/verify.sh" <<'EOF_VERIFY'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "$SCRIPT_DIR/testdev-verify.sh" "$@"
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
else
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
fi

chmod +x "$DIST_DIR/deploy.sh" "$DIST_DIR/verify.sh" "$DIST_DIR/run-tests.sh" "$DIST_DIR/stackctl" "$DIST_DIR/install.sh"

if [ "$BUILD_PROFILE" = "testdev" ]; then
  cat > "$DIST_DIR/testdev-up.sh" <<'EOF_TESTDEV_UP'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "$SCRIPT_DIR/build/scripts/testdev/up.sh" "$@"
EOF_TESTDEV_UP

  cat > "$DIST_DIR/testdev-down.sh" <<'EOF_TESTDEV_DOWN'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "$SCRIPT_DIR/build/scripts/testdev/down.sh" "$@"
EOF_TESTDEV_DOWN

  cat > "$DIST_DIR/testdev-verify.sh" <<'EOF_TESTDEV_VERIFY'
#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
exec "$SCRIPT_DIR/build/scripts/testdev/verify.sh" "$@"
EOF_TESTDEV_VERIFY

  chmod +x "$DIST_DIR/testdev-up.sh" "$DIST_DIR/testdev-down.sh" "$DIST_DIR/testdev-verify.sh"
fi

# The bundled artifact uses normalized mtimes for reproducibility. Refresh them in dist/
# so rsync -a notices changed files even when size stays the same.
find "$DIST_DIR" -exec touch {} +

log "dist ready at $DIST_DIR"
