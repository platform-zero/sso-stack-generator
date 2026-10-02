#!/usr/bin/env bash
set -euo pipefail

services=(autobattler autobattler-db-bootstrap tas-dashboard)
images=(webservices/autobattler:local-build webservices/tas-dashboard:local-build)
units=(webservices-autobattler.service webservices-autobattler-db-bootstrap.service webservices-tas-dashboard.service)

usage() {
  cat <<'EOF'
Usage: ops/host-admin/quarantine-retired-custom-apps.sh [--emit-purge-commands]

Reports leftover runtime state for retired custom apps. By default this is
read-only and is intended for post-deploy quarantine review.

--emit-purge-commands prints destructive commands for later manual review; it
does not execute them.
EOF
}

emit_purge_commands=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --emit-purge-commands)
      emit_purge_commands=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '[retired-custom-apps] unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

log() {
  printf '[retired-custom-apps] %s\n' "$*" >&2
}

log "systemd user unit state"
for unit in "${units[@]}"; do
  systemctl --user --no-pager --full status "$unit" 2>/dev/null || true
done

log "container state"
for service in "${services[@]}"; do
  podman ps -a --filter "name=^/${service}$" --format '{{.Names}}\t{{.Status}}\t{{.Image}}' || true
  podman ps -a --filter "name=^/webservices-${service}-1$" --format '{{.Names}}\t{{.Status}}\t{{.Image}}' || true
done

log "image state"
for image in "${images[@]}"; do
  podman image inspect "$image" --format '{{.RepoTags}} {{.ID}} {{.Size}}' 2>/dev/null || true
done

log "database quarantine check"
podman exec postgres psql -U "${POSTGRES_ADMIN_USER:-webservices}" -d postgres -c "\\l autobattler" 2>/dev/null || true
podman exec postgres psql -U "${POSTGRES_ADMIN_USER:-webservices}" -d postgres -c "\\du autobattler" 2>/dev/null || true

if [ "$emit_purge_commands" = "1" ]; then
  cat <<'EOF'

# Review carefully before running. These commands remove retired custom-app
# runtime state and are not needed for normal deploy quarantine.
systemctl --user disable --now webservices-autobattler.service webservices-autobattler-db-bootstrap.service webservices-tas-dashboard.service
podman rm -f autobattler webservices-autobattler-1 autobattler-db-bootstrap webservices-autobattler-db-bootstrap-1 tas-dashboard webservices-tas-dashboard-1
podman image rm webservices/autobattler:local-build webservices/tas-dashboard:local-build
podman exec postgres psql -U "${POSTGRES_ADMIN_USER:-webservices}" -d postgres -c "DROP DATABASE IF EXISTS autobattler;"
podman exec postgres psql -U "${POSTGRES_ADMIN_USER:-webservices}" -d postgres -c "DROP ROLE IF EXISTS autobattler;"
EOF
fi
