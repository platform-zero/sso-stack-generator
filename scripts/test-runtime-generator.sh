#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SITE="${SITE_MANIFEST:-$ROOT_DIR/../site-config/sites/latium/manifest.json}"
MODULES_DIR="${MODULES_DIR:-$ROOT_DIR/../modules}"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

generate() {
  "$ROOT_DIR/generate.sh" \
    --site "$SITE" \
    --modules-dir "$MODULES_DIR" \
    --backend "$1" \
    --output "$2"
}

generate docker "$WORK_DIR/docker"
generate podman "$WORK_DIR/podman-a"
generate podman "$WORK_DIR/podman-b"

jq '(.services[] | del(.placement))' "$WORK_DIR/docker/stack.ir.json" > "$WORK_DIR/docker-backend-neutral.ir.json"
jq '(.services[] | del(.placement))' "$WORK_DIR/podman-a/stack.ir.json" > "$WORK_DIR/podman-backend-neutral.ir.json"
cmp "$WORK_DIR/docker-backend-neutral.ir.json" "$WORK_DIR/podman-backend-neutral.ir.json"
diff -ru "$WORK_DIR/podman-a" "$WORK_DIR/podman-b"

jq -e '
  (.schemaVersion == 2) and
  (.modules | type == "array" and length > 0) and
  (has("components") | not) and
  (all(.modules[]; type == "string" or (type == "object" and (.id | type == "string"))))
' "$SITE" >/dev/null

jq -r '.services | keys[]' "$WORK_DIR/docker/stack.ir.json" | sort > "$WORK_DIR/ir-services"
docker compose -f "$WORK_DIR/docker/docker-compose.yml" config --no-interpolate --services | sort > "$WORK_DIR/docker-services"
cmp "$WORK_DIR/ir-services" "$WORK_DIR/docker-services"
docker compose -f "$WORK_DIR/docker/docker-compose.yml" config --no-interpolate --quiet

if rg -n 'docker\.sock|docker-socket|docker-controller|docker-health-exporter|cadvisor|watchtower|autoheal|dozzle' \
  "$WORK_DIR/podman-a/quadlet/rootful" "$WORK_DIR/podman-a/quadlet/rootless"; then
  printf '[runtime-test] Podman bundle contains a retired Docker control-plane reference\n' >&2
  exit 1
fi

if rg -n '^Volume=\$\{' "$WORK_DIR/podman-a/quadlet/rootful" "$WORK_DIR/podman-a/quadlet/rootless"; then
  printf '[runtime-test] Quadlet volume source contains an unresolved host expression\n' >&2
  exit 1
fi

jq -e '
  .services as $services |
  all(["alloy", "caddy", "crowdsec", "kopia", "mailserver", "node-exporter", "volume-init"][]; $services[.].placement == "rootful") and
  all($services | to_entries[]; . as $entry | if (["alloy", "caddy", "crowdsec", "kopia", "mailserver", "node-exporter", "volume-init"] | index($entry.key)) then true else $entry.value.placement == "rootless" end)
' "$WORK_DIR/podman-a/stack.ir.json" >/dev/null

if jq -e '.services[] | select(.lifecycle != "daemon" and .updatePolicy == "registry")' \
  "$WORK_DIR/podman-a/stack.ir.json" >/dev/null; then
  printf '[runtime-test] non-daemon service has registry auto-update enabled\n' >&2
  exit 1
fi

if jq -e '
  .services as $services |
  $services[] | .dependencies // {} | to_entries[] |
  select(.value == "completed" and $services[.key].lifecycle != "oneshot")
' "$WORK_DIR/podman-a/stack.ir.json" >/dev/null; then
  printf '[runtime-test] completed dependency target is not a one-shot service\n' >&2
  exit 1
fi

generated_units="$WORK_DIR/generated-units"
mkdir -p "$generated_units/rootful" "$generated_units/rootful-early" "$generated_units/rootful-late"
QUADLET_UNIT_DIRS="$WORK_DIR/podman-a/quadlet/rootful" /usr/libexec/podman/quadlet \
  "$generated_units/rootful" "$generated_units/rootful-early" "$generated_units/rootful-late"
systemd-analyze verify "$generated_units/rootful"/*.service "$WORK_DIR/podman-a/quadlet/rootful"/*.target
mkdir -p "$generated_units/rootless" "$generated_units/rootless-early" "$generated_units/rootless-late"
QUADLET_UNIT_DIRS="$WORK_DIR/podman-a/quadlet/rootless" /usr/libexec/podman/quadlet \
  "$generated_units/rootless" "$generated_units/rootless-early" "$generated_units/rootless-late"
systemd-analyze verify "$generated_units/rootless"/*.service "$WORK_DIR/podman-a/quadlet/rootless"/*.target

"$WORK_DIR/podman-a/ops/install-podman-bundle.sh" --bundle "$WORK_DIR/podman-a"

test -f "$WORK_DIR/podman-a/runtime/configs/vaultwarden/index.html"
test -f "$WORK_DIR/podman-a/runtime/configs/vaultwarden/seed.sh"
if find "$WORK_DIR/podman-a/runtime/configs" -type f -name '*.template' -print -quit | grep -q .; then
  printf '[runtime-test] self-contained Podman runtime still contains template files\n' >&2
  exit 1
fi
if rg -n '\{\{[A-Z_][A-Z0-9_]*\}\}' "$WORK_DIR/podman-a/runtime/configs" "$WORK_DIR/podman-a/runtime/stack.env"; then
  printf '[runtime-test] self-contained Podman runtime contains unresolved templates\n' >&2
  exit 1
fi
if rg -n '\$\{[A-Z_][A-Z0-9_]*:\?' "$WORK_DIR/podman-a/runtime/stack.env"; then
  printf '[runtime-test] self-contained Podman env contains unresolved required expressions\n' >&2
  exit 1
fi

printf '[runtime-test] dual-backend validation passed (%s services)\n' "$(wc -l < "$WORK_DIR/ir-services")"
