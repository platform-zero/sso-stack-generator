#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
LIB_DIR="$SCRIPT_DIR/lib"
# shellcheck source=scripts/lib/common.sh
source "$LIB_DIR/common.sh"
# shellcheck source=scripts/lib/build-metadata.sh
source "$LIB_DIR/build-metadata.sh"
# shellcheck source=scripts/lib/components.sh
source "$LIB_DIR/components.sh"
# shellcheck source=scripts/lib/external-modules.sh
source "$LIB_DIR/external-modules.sh"

TARGET="//:web_services_release"

usage() {
  cat <<'EOF_USAGE'
Usage:
  ./scripts/build-artifact.sh

Runs local build/test steps and prints the built Bazel release artifact path.
EOF_USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument for build-artifact.sh: $1"
      ;;
  esac
  shift
done

require_cmd bazel
require_cmd git
require_cmd npm
require_cmd tar

cd "$SOURCE_ROOT"
require_clean_git_tree "$SOURCE_ROOT"

contract_test_seed="${WEBSERVICES_CONTRACT_ROOT:-$SOURCE_ROOT}"
external_modules_ready=0
if [ -d "$EXTERNAL_MODULES_MATERIALIZED_DIR" ] && find "$EXTERNAL_MODULES_MATERIALIZED_DIR" -type f -print -quit | grep -q .; then
  external_modules_ready=1
fi
if [ "$contract_test_seed" = "$SOURCE_ROOT" ] && [ "$external_modules_ready" = "0" ] && [ ! -f "$contract_test_seed/stack.config/components.json" ] && [ -f "$SOURCE_ROOT/dist/build/stack.config/components.json" ]; then
  log "using materialized dist/build tree for contract tests"
  contract_test_seed="$SOURCE_ROOT/dist/build"
fi

contract_test_root="$contract_test_seed"
contract_test_tmp=""
needs_contract_test_tmp=0
if [ "$contract_test_seed" != "$SOURCE_ROOT" ]; then
  needs_contract_test_tmp=1
fi
if [ "$external_modules_ready" = "1" ]; then
  needs_contract_test_tmp=1
fi

if [ "$needs_contract_test_tmp" = "1" ]; then
  contract_test_tmp="$(mktemp -d)"
  cleanup_contract_test_root() {
    [ -z "$contract_test_tmp" ] || rm -rf "$contract_test_tmp"
  }
  trap cleanup_contract_test_root EXIT

  for root in global.settings stack.compose stack.config stack.containers stack.kotlin stack.js stack.systemd; do
    if [ -e "$contract_test_seed/$root" ]; then
      cp -a "$contract_test_seed/$root" "$contract_test_tmp/$root"
    elif [ -e "$SOURCE_ROOT/$root" ]; then
      cp -a "$SOURCE_ROOT/$root" "$contract_test_tmp/$root"
    fi
  done

  for root in scripts docs; do
    if [ -e "$SOURCE_ROOT/$root" ]; then
      cp -a "$SOURCE_ROOT/$root" "$contract_test_tmp/$root"
    fi
  done

  for file in .bazelrc BUILD.bazel MODULE.bazel build.gradle.kts settings.gradle.kts gradlew gradlew.bat; do
    if [ -e "$SOURCE_ROOT/$file" ]; then
      cp -a "$SOURCE_ROOT/$file" "$contract_test_tmp/$file"
    fi
  done
  if [ -d "$SOURCE_ROOT/gradle" ]; then
    cp -a "$SOURCE_ROOT/gradle" "$contract_test_tmp/gradle"
  fi
  if [ "$external_modules_ready" = "1" ]; then
    external_modules_overlay_into "$contract_test_tmp"
    component_catalog_merge_external "$contract_test_tmp/stack.config/components.json"
    service_contracts_merge_external "$contract_test_tmp/stack.config/service-contracts.json"
  fi
  contract_test_root="$contract_test_tmp"
fi

local_test_dir="$contract_test_root/stack.containers/test-runner/playwright-tests"
if [ -f "$local_test_dir/package.json" ]; then
  if [ ! -d "$local_test_dir/node_modules" ] || [ ! -f "$local_test_dir/node_modules/jest-cli/package.json" ] || [ ! -f "$local_test_dir/node_modules/typescript/package.json" ] || [ ! -f "$local_test_dir/node_modules/@playwright/test/package.json" ]; then
    log "installing TypeScript test dependencies"
    (cd "$local_test_dir" && npm ci) >&2
  fi
  log "running TypeScript compile check"
  (cd "$local_test_dir" && npm run build) >&2
  log "running TypeScript unit tests"
  (cd "$local_test_dir" && npm run test:unit) >&2
fi

log "running component selection checks"
component_catalog_backup="$(mktemp)"
cp "$contract_test_root/stack.config/components.json" "$component_catalog_backup"
WEBSERVICES_CONTRACT_ROOT="$contract_test_root" "$SCRIPT_DIR/test-component-selection.sh" >&2
mv "$component_catalog_backup" "$contract_test_root/stack.config/components.json"
component_catalog_merge_external "$contract_test_root/stack.config/components.json"
service_contracts_merge_external "$contract_test_root/stack.config/service-contracts.json"

log "running external module checks"
"$SCRIPT_DIR/test-external-modules.sh" >&2

log "running service contract checks"
WEBSERVICES_CONTRACT_ROOT="$contract_test_root" "$SCRIPT_DIR/test-service-contracts.sh" >&2

log "running contract report checks"
WEBSERVICES_CONTRACT_ROOT="$contract_test_root" "$SCRIPT_DIR/test-contract-reports.sh" >&2

if [ "$external_modules_ready" = "1" ] && find "$EXTERNAL_MODULES_MATERIALIZED_DIR" -mindepth 2 -maxdepth 2 -name stack.module.json -print -quit | grep -q .; then
  log "running materialized module contract checks"
  "$SCRIPT_DIR/test-module-group.sh" --contract "$EXTERNAL_MODULES_MATERIALIZED_DIR" >&2
fi

log "running mount diagnostics checks"
"$SCRIPT_DIR/test-mount-diagnostics.sh" >&2

log "running deploy-state guard checks"
"$SCRIPT_DIR/test-deploy-state.sh" >&2

log "running scoped deploy planner checks"
"$SCRIPT_DIR/test-deploy-scope.sh" >&2

log "running env-file security checks"
"$SCRIPT_DIR/test-env-file-security.sh" >&2

log "running deploy preflight checks"
"$SCRIPT_DIR/test-deploy-preflight.sh" >&2

log "running bundle installer checks"
"$SCRIPT_DIR/test-install-bundle.sh" >&2

log "running docs link checks"
"$SCRIPT_DIR/test-docs.sh" >&2

log "running Gradle tests and shadow jars"
mapfile -t shadow_projects < <(
  find "$contract_test_root/stack.kotlin" -mindepth 2 -maxdepth 2 -name build.gradle.kts -print 2>/dev/null \
    | while IFS= read -r build_file; do
        if grep -Eq 'tasks\.shadowJar' "$build_file"; then
          dirname "$build_file"
        fi
      done \
    | sed "s#^$contract_test_root/stack.kotlin/##" \
    | sort
)
gradle_args=(test)
for project_name in "${shadow_projects[@]}"; do
  gradle_args+=(":$project_name:shadowJar")
done
gradle_args+=(--no-daemon --max-workers=2)
if [ -f "$contract_test_root/stack.kotlin/test-runner/build.gradle.kts" ]; then
  gradle_args+=(-x :test-runner:test)
fi
(cd "$contract_test_root" && ./gradlew "${gradle_args[@]}") >&2

log "packaging immutable release artifact with Bazel"
(cd "$contract_test_root" && bazel build "$TARGET") >&2

artifact_path="$(cd "$contract_test_root" && bazel info bazel-bin)/web_services_release.tar"
[ -f "$artifact_path" ] || die "failed to resolve Bazel artifact path for $TARGET"

artifact_listing="$(mktemp)"
tar -tf "$artifact_path" > "$artifact_listing"
grep -Fxq "./scripts/deploy.sh" "$artifact_listing" || die "release artifact missing generic deploy entrypoint: ./scripts/deploy.sh"
grep -Fxq "./scripts/verify.sh" "$artifact_listing" || die "release artifact missing generic verify entrypoint: ./scripts/verify.sh"
grep -Fxq "./scripts/install-bundle.sh" "$artifact_listing" || die "release artifact missing bundle installer entrypoint: ./scripts/install-bundle.sh"
if [ -d "$contract_test_root/stack.js" ] && find "$contract_test_root/stack.js" -type f -print -quit | grep -q .; then
  grep -qE '^\./stack\.js/.+' "$artifact_listing" || die "release artifact missing materialized stack.js sources"
fi
rm -f "$artifact_listing"

mkdir -p "$SOURCE_ROOT/out"
write_source_build_metadata_json "$SOURCE_ROOT" "$SOURCE_ROOT/out/latest-build.json"
printf '%s\n' "$artifact_path"
