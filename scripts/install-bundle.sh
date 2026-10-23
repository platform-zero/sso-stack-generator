#!/usr/bin/env bash
# Stage a generated bundle only; native activation belongs to the bundled deploy path.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DEFAULT_BUNDLE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
DIST_ROOT="$(cd "$DEFAULT_BUNDLE_ROOT/.." && pwd -P)"
TARGET_ROOT="${WEBSERVICES_DEPLOY_ROOT:-$HOME/webservices}"
RUN_DEPLOY=0
WRAPPERS=(deploy.sh verify.sh run-tests.sh stackctl install.sh)
MARKER='.webservices-bundle-root'
PENDING='.webservices-install-pending'
STAGE=''
OLD_BUILD_MOVED=0
NEW_BUILD_MOVED=0
OLD_PREVIOUS_MOVED=0
TRANSACTION=0
COMMITTED=0

usage() {
  printf '%s\n' 'Usage: ./install.sh [--target DEPLOY_ROOT] [--deploy]' \
    'Stages a generated bundle into an empty or previously marked deployment root.' \
    'Unknown destination contents are refused, never removed. The previous build is retained.'
}
die() { printf '[webservices-install] ERROR: %s\n' "$*" >&2; exit 1; }
log() { printf '[webservices-install] %s\n' "$*" >&2; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --dist-root|--target)
      [ "$#" -ge 2 ] && [ -n "$2" ] || die "$1 requires a value"
      if [ "$1" = --dist-root ]; then DIST_ROOT="$2"; else TARGET_ROOT="$2"; fi
      shift 2 ;;
    --deploy) RUN_DEPLOY=1; shift ;;
    *) die "unknown argument: $1" ;;
  esac
done

[ -d "$DIST_ROOT" ] || die 'missing source distribution'
DIST_ROOT="$(cd "$DIST_ROOT" && pwd -P)"
[ -n "$TARGET_ROOT" ] && [ "$TARGET_ROOT" != / ] || die 'unsafe deploy target'
[ ! -L "$TARGET_ROOT" ] || die 'linked deploy target refused'
TARGET_ROOT="$(realpath -m -- "$TARGET_ROOT")"
case "$TARGET_ROOT/" in "$DIST_ROOT/"*) die 'target overlaps source distribution' ;; esac
case "$DIST_ROOT/" in "$TARGET_ROOT/"*) die 'source distribution is inside target' ;; esac
BUNDLE_ROOT="$DIST_ROOT/build"
[ -d "$BUNDLE_ROOT" ] && [ ! -L "$BUNDLE_ROOT" ] || die 'missing plain bundle payload directory'
[ -f "$BUNDLE_ROOT/scripts/deploy.sh" ] || die 'missing bundled deploy script'
[ -d "$BUNDLE_ROOT/reports" ] || die 'missing bundled reports directory'
[ -z "$(find "$BUNDLE_ROOT" -mindepth 1 ! -type d ! -type f -print -quit)" ] || die 'linked or special bundle payload refused'
for wrapper in "${WRAPPERS[@]}"; do
  [ -f "$DIST_ROOT/$wrapper" ] && [ ! -L "$DIST_ROOT/$wrapper" ] || die "missing plain wrapper: $wrapper"
done

mkdir -p -- "$TARGET_ROOT"
[ "$(stat -c %u -- "$TARGET_ROOT")" = "$(id -u)" ] || die 'deployment root must belong to the installing user'
[ ! -L "$TARGET_ROOT/.webservices-install.lock" ] || die 'linked installation lock refused'
# The root is owned by this user. Never follow a pre-existing non-regular lock.
if [ -e "$TARGET_ROOT/.webservices-install.lock" ]; then
  [ -f "$TARGET_ROOT/.webservices-install.lock" ] &&
    [ "$(stat -c %h -- "$TARGET_ROOT/.webservices-install.lock")" = 1 ] &&
    [ "$(stat -c %u -- "$TARGET_ROOT/.webservices-install.lock")" = "$(id -u)" ] || die 'invalid installation lock'
fi
exec 9>"$TARGET_ROOT/.webservices-install.lock"
chmod 0600 "$TARGET_ROOT/.webservices-install.lock"
flock -n 9 || die 'another bundle staging operation holds the lock'
[ ! -e "$TARGET_ROOT/$PENDING" ] && [ ! -L "$TARGET_ROOT/$PENDING" ] || die 'interrupted staging requires explicit inspection; previous data retained'

shopt -s nullglob dotglob
for entry in "$TARGET_ROOT"/*; do
  name="${entry##*/}"
  case "$name" in
    .webservices-install.lock) continue ;;
    build|build.previous|runtime|quarantine)
      [ -d "$entry" ] && [ ! -L "$entry" ] || die "invalid managed directory: $name" ;;
    reports)
      [ -L "$entry" ] && [ "$(readlink -- "$entry")" = "$TARGET_ROOT/build/reports" ] || die 'unmanaged reports path' ;;
    deploy.sh|verify.sh|run-tests.sh|stackctl|install.sh|.webservices-bundle-root)
      [ -f "$entry" ] && [ ! -L "$entry" ] || die "invalid managed file: $name" ;;
    *) die "unmanaged destination entry preserved: $name" ;;
  esac
  [ -f "$TARGET_ROOT/$MARKER" ] && [ ! -L "$TARGET_ROOT/$MARKER" ] || die 'nonempty unmarked destination requires operator review'
done
shopt -u nullglob dotglob
if [ -e "$TARGET_ROOT/$MARKER" ]; then
  [ "$(<"$TARGET_ROOT/$MARKER")" = 'webservices-bundle-root-v1' ] || die 'unknown installation marker'
fi

rollback_staging() {
  local status="$1" wrapper failed=0
  trap - ERR TERM INT
  set +e
  if [ "$TRANSACTION" = 1 ] && [ "$COMMITTED" = 0 ]; then
    if [ "$NEW_BUILD_MOVED" = 1 ]; then mv -- "$TARGET_ROOT/build" "$STAGE/failed-build" || failed=1; fi
    if [ "$OLD_BUILD_MOVED" = 1 ]; then mv -- "$TARGET_ROOT/build.previous" "$TARGET_ROOT/build" || failed=1; fi
    if [ "$OLD_PREVIOUS_MOVED" = 1 ]; then mv -- "$STAGE/old-previous" "$TARGET_ROOT/build.previous" || failed=1; fi
    for wrapper in "${WRAPPERS[@]}" reports "$MARKER"; do
      if [ -e "$STAGE/replaced/$wrapper" ]; then
        if [ -e "$TARGET_ROOT/$wrapper" ] || [ -L "$TARGET_ROOT/$wrapper" ]; then rm -- "$TARGET_ROOT/$wrapper" || failed=1; fi
        if [ -e "$STAGE/previous/$wrapper" ] || [ -L "$STAGE/previous/$wrapper" ]; then
          mv -- "$STAGE/previous/$wrapper" "$TARGET_ROOT/$wrapper" || failed=1
        fi
      fi
    done
    if [ "$failed" = 0 ]; then rm -- "$TARGET_ROOT/$PENDING" || failed=1; fi
  fi
  if [ "$failed" = 0 ] && [ -n "$STAGE" ]; then rm -rf -- "$STAGE"; else log 'staging recovery incomplete; pending record retained; no deploy attempted'; fi
  exit "$status"
}
trap 'rollback_staging $?' ERR
trap 'rollback_staging 143' TERM
trap 'rollback_staging 130' INT
STAGE="$(mktemp -d "$TARGET_ROOT/.install.next.XXXXXXXX")"
mkdir "$STAGE/new" "$STAGE/previous" "$STAGE/replaced"
cp -a -- "$BUNDLE_ROOT" "$STAGE/new/build"
for wrapper in "${WRAPPERS[@]}"; do
  cp -- "$DIST_ROOT/$wrapper" "$STAGE/new/$wrapper"
  chmod +x "$STAGE/new/$wrapper"
done
ln -s -- "$TARGET_ROOT/build/reports" "$STAGE/new/reports"
printf '%s\n' webservices-bundle-root-v1 > "$STAGE/new/$MARKER"
# Prepare immutable rollback inputs before changing any selected artifact.
for wrapper in "${WRAPPERS[@]}" reports "$MARKER"; do
  if [ -e "$TARGET_ROOT/$wrapper" ] || [ -L "$TARGET_ROOT/$wrapper" ]; then
    cp -a -- "$TARGET_ROOT/$wrapper" "$STAGE/previous/$wrapper"
  fi
done
printf '%s\n' "${STAGE##*/}" > "$TARGET_ROOT/$PENDING"
TRANSACTION=1
if [ -d "$TARGET_ROOT/build.previous" ]; then
  mv -- "$TARGET_ROOT/build.previous" "$STAGE/old-previous"
  OLD_PREVIOUS_MOVED=1
fi
if [ -d "$TARGET_ROOT/build" ]; then
  mv -- "$TARGET_ROOT/build" "$TARGET_ROOT/build.previous"
  OLD_BUILD_MOVED=1
fi
mv -- "$STAGE/new/build" "$TARGET_ROOT/build"
NEW_BUILD_MOVED=1
for wrapper in "${WRAPPERS[@]}" reports "$MARKER"; do
  : > "$STAGE/replaced/$wrapper"
  mv -T -- "$STAGE/new/$wrapper" "$TARGET_ROOT/$wrapper"
done
mkdir -p -- "$TARGET_ROOT/runtime"
COMMITTED=1
rm -- "$TARGET_ROOT/$PENDING"
rm -rf -- "$STAGE"
STAGE=''
trap - ERR TERM INT
log "staged bundle into $TARGET_ROOT; previous build retained"
if [ "$RUN_DEPLOY" = 1 ]; then
  cd "$TARGET_ROOT"
  exec "$TARGET_ROOT/deploy.sh"
fi
log "next: cd $TARGET_ROOT && ./deploy.sh"
