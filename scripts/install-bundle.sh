#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DEFAULT_BUNDLE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
DEFAULT_DIST_ROOT="$(cd "$DEFAULT_BUNDLE_ROOT/.." && pwd -P)"

DIST_ROOT="$DEFAULT_DIST_ROOT"
TARGET_ROOT="${WEBSERVICES_DEPLOY_ROOT:-$HOME/webservices}"
RUN_DEPLOY=0

usage() {
  cat <<'EOF_USAGE'
Usage:
  ./install.sh [--target <deploy-root>] [--deploy]

Stages this generated bundle into the canonical deployment root. The default
target is $HOME/webservices, matching the pre-rendered systemd user units.
EOF_USAGE
}

die() {
  printf '[webservices-install] ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[webservices-install] %s\n' "$*" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --dist-root)
      [ "$#" -ge 2 ] || die "--dist-root requires a value"
      DIST_ROOT="$2"
      shift
      ;;
    --target)
      [ "$#" -ge 2 ] || die "--target requires a value"
      TARGET_ROOT="$2"
      shift
      ;;
    --deploy)
      RUN_DEPLOY=1
      ;;
    *)
      die "unknown argument for install-bundle.sh: $1"
      ;;
  esac
  shift
done

DIST_ROOT="$(cd "$DIST_ROOT" && pwd -P)"
BUNDLE_ROOT="$DIST_ROOT/build"
[ -d "$BUNDLE_ROOT" ] || die "missing bundle payload: $BUNDLE_ROOT"
[ -f "$BUNDLE_ROOT/scripts/deploy.sh" ] || die "missing bundled deploy script: $BUNDLE_ROOT/scripts/deploy.sh"

case "$TARGET_ROOT" in
  ""|"/") die "refusing unsafe deploy target: ${TARGET_ROOT:-<empty>}" ;;
esac
mkdir -p "$TARGET_ROOT"
TARGET_ROOT="$(cd "$TARGET_ROOT" && pwd -P)"

if [ "$TARGET_ROOT" = "$DIST_ROOT" ]; then
  die "target root must differ from the source dist root"
fi

tmp_build="$TARGET_ROOT/.build.next.$$"
rm -rf "$tmp_build"
mkdir -p "$tmp_build"
cp -a "$BUNDLE_ROOT/." "$tmp_build/"
rm -rf "$TARGET_ROOT/build.previous"
if [ -d "$TARGET_ROOT/build" ]; then
  mv "$TARGET_ROOT/build" "$TARGET_ROOT/build.previous"
fi
mv "$tmp_build" "$TARGET_ROOT/build"
rm -rf "$TARGET_ROOT/build.previous"

for wrapper in deploy.sh verify.sh run-tests.sh stackctl install.sh; do
  if [ -f "$DIST_ROOT/$wrapper" ]; then
    cp "$DIST_ROOT/$wrapper" "$TARGET_ROOT/$wrapper"
    chmod +x "$TARGET_ROOT/$wrapper"
  fi
done

mkdir -p "$TARGET_ROOT/runtime" "$TARGET_ROOT/repos/source"
log "staged bundle into $TARGET_ROOT"

if [ "$RUN_DEPLOY" = "1" ]; then
  cd "$TARGET_ROOT"
  exec "$TARGET_ROOT/deploy.sh"
fi

log "next: cd $TARGET_ROOT && ./deploy.sh"
