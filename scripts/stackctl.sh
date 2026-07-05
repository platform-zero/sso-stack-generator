#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

if [ -d "$SCRIPT_DIR/../stack.config/progression" ]; then
  BUNDLE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
  DEPLOY_ROOT="$BUNDLE_ROOT"
else
  BUNDLE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
  DEPLOY_ROOT="$(cd "$BUNDLE_ROOT/.." && pwd -P)"
fi

if [ "${1:-}" = "users" ]; then
  exec "$SCRIPT_DIR/lib/stackctl-users.sh" "${@:2}"
fi

JAR_PATH="$BUNDLE_ROOT/stack.kotlin/progression/build/libs/progression-1.0.0-all.jar"
if [ ! -f "$JAR_PATH" ]; then
  printf 'stackctl: missing progression jar: %s\n' "$JAR_PATH" >&2
  printf 'Run ./gradlew :progression:shadowJar or build the deploy bundle first.\n' >&2
  exit 2
fi

export PROGRESSION_BUNDLE_ROOT="${PROGRESSION_BUNDLE_ROOT:-$BUNDLE_ROOT}"
export PROGRESSION_DEPLOY_ROOT="${PROGRESSION_DEPLOY_ROOT:-$DEPLOY_ROOT}"
export PROGRESSION_RUNTIME_DIR="${PROGRESSION_RUNTIME_DIR:-$DEPLOY_ROOT/runtime/progression}"
if [ -f "$DEPLOY_ROOT/runtime/build-info.json" ]; then
  export PROGRESSION_RUNTIME_BUILD_INFO="${PROGRESSION_RUNTIME_BUILD_INFO:-$DEPLOY_ROOT/runtime/build-info.json}"
fi

exec java -jar "$JAR_PATH" "$@"
