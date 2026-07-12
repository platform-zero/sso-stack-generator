#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
LIB_DIR="$(cd "$SCRIPT_DIR/../lib" && pwd -P)"
# shellcheck source=scripts/lib/common.sh
source "$LIB_DIR/common.sh"
# shellcheck source=scripts/lib/systemd-user.sh
source "$LIB_DIR/systemd-user.sh"

UNIT_DIR=""

usage() {
  cat <<'EOF_USAGE'
Usage:
  ./scripts/deploy/install-systemd-user-units.sh --unit-dir <path>
EOF_USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --unit-dir)
      UNIT_DIR="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument for install-systemd-user-units.sh: $1"
      ;;
  esac
  shift
done

[ -n "$UNIT_DIR" ] || die "--unit-dir is required"
[ -d "$UNIT_DIR" ] || die "missing unit directory: $UNIT_DIR"
[ ! -L "$UNIT_DIR" ] || die "unit directory must not be a symlink: $UNIT_DIR"

ensure_user_systemd_env
USER_UNIT_DIR="$(user_systemd_unit_dir)"
mkdir -p -m 700 "$USER_UNIT_DIR"
chmod go-w "$USER_UNIT_DIR"
printf '[webservices-deploy] installing rendered user units from %s into %s\n' "$UNIT_DIR" "$USER_UNIT_DIR" >&2

mapfile -t rendered_units < <(find "$UNIT_DIR" -maxdepth 1 -type f \( -name 'webservices*.service' -o -name 'webservices*.target' -o -name 'webservices*.timer' \) -printf '%f\n' | sort)
[ "${#rendered_units[@]}" -gt 0 ] || die "no rendered user units found in $UNIT_DIR"
printf '[webservices-deploy] rendered user units (%s): %s\n' "${#rendered_units[@]}" "${rendered_units[*]}" >&2

for existing_unit in "$USER_UNIT_DIR"/webservices*.service "$USER_UNIT_DIR"/webservices*.target "$USER_UNIT_DIR"/webservices*.timer; do
  [ -e "$existing_unit" ] || [ -L "$existing_unit" ] || continue
  existing_name="$(basename "$existing_unit")"
  keep_unit=0
  for rendered_name in "${rendered_units[@]}"; do
    if [ "$rendered_name" = "$existing_name" ]; then
      keep_unit=1
      break
    fi
  done
  if [ "$keep_unit" -eq 0 ]; then
    printf '[webservices-deploy] removing stale user unit %s\n' "$existing_unit" >&2
    user_systemctl stop "$existing_name" >/dev/null 2>&1 || true
    user_systemctl disable "$existing_name" >/dev/null 2>&1 || true
    rm -f "$existing_unit"
  fi
done

for rendered_name in "${rendered_units[@]}"; do
  rendered_path="$UNIT_DIR/$rendered_name"
  [ -f "$rendered_path" ] || die "rendered unit is not a regular file: $rendered_path"
  [ ! -L "$rendered_path" ] || die "rendered unit must not be a symlink: $rendered_path"
  printf '[webservices-deploy] installing %s from %s\n' "$USER_UNIT_DIR/$rendered_name" "$rendered_path" >&2
  tmp_unit="$(mktemp "$USER_UNIT_DIR/.${rendered_name}.tmp.XXXXXX")"
  install -m 0644 "$rendered_path" "$tmp_unit"
  mv -f "$tmp_unit" "$USER_UNIT_DIR/$rendered_name"
done
