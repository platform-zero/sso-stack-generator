#!/usr/bin/env bash
set -euo pipefail

# Site-specific storage purge helper.
# This script intentionally does not parse the manifest or site config at runtime.

SCRIPT_NAME="$(basename "$0")"
EXPECTED_HOSTNAME="${EXPECTED_HOSTNAME:-}"
CONFIRMED=0
PRINT_ONLY=0

TARGET_DIRS=(
  "/mnt/stack/pg-ssd/postgres-ssd"
  "/mnt/stack/volumes/postgres_data"
  "/mnt/stack/volumes/mariadb_data"
  "/mnt/stack/vector-dbs/qdrant"
  "/mnt/stack/vector-dbs/opensearch"
  "/mnt/media/seafile-media"
)

die() {
  printf '[%s] ERROR: %s\n' "$SCRIPT_NAME" "$*" >&2
  exit 1
}

log() {
  printf '[%s] %s\n' "$SCRIPT_NAME" "$*" >&2
}

usage() {
  cat <<'EOF_USAGE'
Usage:
  EXPECTED_HOSTNAME=<host> ./ops/host-admin/purge-site-storage-dirs.sh [--print-only] --yes-delete-site-storage

Deletes the hardcoded site storage directories used by this stack.
This script does not read the manifest or site config at runtime.

Options:
  --print-only                  Print the target directories and exit.
  --yes-delete-site-storage     Required for destructive execution.
  -h, --help                    Show this help text.
EOF_USAGE
}

validate_target_dir() {
  local target_dir="$1"
  case "$target_dir" in
    /mnt/stack/pg-ssd/postgres-ssd|\
    /mnt/stack/volumes/postgres_data|\
    /mnt/stack/volumes/mariadb_data|\
    /mnt/stack/vector-dbs/qdrant|\
    /mnt/stack/vector-dbs/opensearch|\
    /mnt/media/seafile-media)
      ;;
    *)
      die "refusing unexpected purge target: $target_dir"
      ;;
  esac
}

print_targets() {
  printf 'Hardcoded purge targets:\n'
  local target_dir
  for target_dir in "${TARGET_DIRS[@]}"; do
    printf '  %s\n' "$target_dir"
  done
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --print-only)
      PRINT_ONLY=1
      ;;
    --yes-delete-site-storage)
      CONFIRMED=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
  shift
done

print_targets

if [ "$PRINT_ONLY" = "1" ]; then
  exit 0
fi

[ "$CONFIRMED" = "1" ] || die "missing required --yes-delete-site-storage"
[ -n "$EXPECTED_HOSTNAME" ] || die "EXPECTED_HOSTNAME must be set for destructive execution"

current_hostname="$(hostname -s 2>/dev/null || hostname 2>/dev/null || printf 'unknown')"
[ "$current_hostname" = "$EXPECTED_HOSTNAME" ] || die "refusing to run on host '$current_hostname' (expected '$EXPECTED_HOSTNAME')"

command -v sudo >/dev/null 2>&1 || die "missing required command: sudo"

log "deleting hardcoded site storage directories"

for target_dir in "${TARGET_DIRS[@]}"; do
  validate_target_dir "$target_dir"
  if [ -e "$target_dir" ] || [ -L "$target_dir" ]; then
    log "removing $target_dir"
    sudo rm -rf --one-file-system -- "$target_dir"
  else
    log "skipping missing path: $target_dir"
  fi
done

log "purge complete"
