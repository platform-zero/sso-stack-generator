#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
MODULES_DIR="${MODULES_DIR:-$ROOT_DIR/../modules}"
# shellcheck source=scripts/lib/common.sh
source "$ROOT_DIR/scripts/lib/common.sh"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
SOURCE_SITE="${SITE_MANIFEST:-$ROOT_DIR/../site-config/sites/latium/manifest.json}"
SITE="$WORK_DIR/manifest.json"
SOURCE_SITE_DIR="$(cd "$(dirname "$SOURCE_SITE")" && pwd -P)"
cp -a "$SOURCE_SITE_DIR/global.settings" "$WORK_DIR/global.settings"
cp "$SOURCE_SITE" "$SITE"
if [ -d "$MODULES_DIR/workload-spawner" ]; then
  site_with_workload_spawner="$(mktemp)"
  jq '
    .components = ((.components + ["workload-spawner"]) | unique)
    | .modules = ((.modules + ["workload-spawner"]) | unique)
  ' "$SITE" > "$site_with_workload_spawner"
  mv "$site_with_workload_spawner" "$SITE"
fi

generate() {
  "$ROOT_DIR/generate.sh" \
    --site "$SITE" \
    --modules-dir "$MODULES_DIR" \
    --backend "$1" \
    --output "$2"
}

generate podman "$WORK_DIR/podman-a"
generate podman "$WORK_DIR/podman-b"

diff -ru "$WORK_DIR/podman-a" "$WORK_DIR/podman-b"

jq -e '
  (.schemaVersion == 2) and
  (.modules | type == "array" and length > 0) and
  (.components | index("full")) and
  ((.modules | index("workload-spawner") | not) or (.components | index("workload-spawner"))) and
  (all(.modules[]; type == "string" or (type == "object" and (.id | type == "string"))))
' "$SITE" >/dev/null

jq -e '(.components | index("search")) and (.components | index("opensearch")) and (.components | index("grafana"))' \
  "$WORK_DIR/podman-a/site/components.lock.json" >/dev/null

if ! rg -Fq 'search.{$DOMAIN}' "$WORK_DIR/podman-a/runtime/configs/caddy/Caddyfile"; then
  printf '[runtime-test] rendered runtime Caddyfile is missing the OpenSearch search route\n' >&2
  exit 1
fi

jq -r '.services | keys[]' "$WORK_DIR/podman-a/stack.ir.json" | sort > "$WORK_DIR/ir-services"
awk '
  /^services:[[:space:]]*$/ { in_services = 1; next }
  in_services && /^[^[:space:]]/ { in_services = 0 }
  in_services && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ {
    name = $1
    sub(/:$/, "", name)
    print name
  }
' "$WORK_DIR/podman-a/runtime-model.yml" | sort > "$WORK_DIR/runtime-model-services"
cmp "$WORK_DIR/ir-services" "$WORK_DIR/runtime-model-services"

if rg -n 'container-socket|container-controller|container-health-exporter|cadvisor|watchtower|autoheal|dozzle' \
  "$WORK_DIR/podman-a/quadlet/rootful" "$WORK_DIR"/podman-a/quadlet/rootless-*; then
  printf '[runtime-test] Podman bundle contains a retired control-plane reference\n' >&2
  exit 1
fi

if rg -n '^Volume=\$\{' "$WORK_DIR/podman-a/quadlet/rootful" "$WORK_DIR"/podman-a/quadlet/rootless-*; then
  printf '[runtime-test] Quadlet volume source contains an unresolved host expression\n' >&2
  exit 1
fi

jq -e '
  .services as $services |
  all(["alloy", "caddy", "crowdsec", "kopia", "mailserver", "node-exporter", "volume-init"][]; $services[.].placement == "rootful") and
  all($services | to_entries[]; . as $entry | if (["alloy", "caddy", "crowdsec", "kopia", "mailserver", "node-exporter", "volume-init"] | index($entry.key)) then true else $entry.value.placement == "rootless" end) and
  ($services["test-runner"].rootlessDomain == "webservices") and
  ($services["test-runner-managed"].rootlessDomain == "test-runners") and
  (($services | has("forgejo-runner") | not) or $services["forgejo-runner"].rootlessDomain == "forgejo-runner") and
  ($services["jupyterhub"].rootlessDomain == "jupyterhub") and
  ($services["jupyter-notebook-build"].rootlessDomain == "jupyterhub") and
  (($services | has("workload-spawner-postgres") | not) or $services["workload-spawner-postgres"].rootlessDomain == "workload-spawner") and
  (($services | has("workload-spawner-api") | not) or $services["workload-spawner-api"].rootlessDomain == "workload-spawner") and
  (($services | has("workload-spawner-router") | not) or $services["workload-spawner-router"].rootlessDomain == "workload-spawner") and
  ($services["caddy"].networks | keys == ["caddy"])
' "$WORK_DIR/podman-a/stack.ir.json" >/dev/null

for domain in webservices test-runners forgejo-runner jupyterhub workload-spawner; do
  test -d "$WORK_DIR/podman-a/quadlet/rootless-$domain"
done

if rg -n '/run/user/999/podman/podman.sock' \
  "$WORK_DIR/podman-a/stack.ir.json" \
  "$WORK_DIR/podman-a/runtime-model.yml" \
  "$WORK_DIR/podman-a/quadlet"; then
  printf '[runtime-test] Podman bundle still references the old shared rootless socket\n' >&2
  exit 1
fi

if rg -n 'remote_ip private_ranges' "$WORK_DIR/podman-a/runtime/configs/caddy/Caddyfile"; then
  printf '[runtime-test] Caddy trusted-proxy matcher still trusts private_ranges\n' >&2
  exit 1
fi

if [ "$(stat -c '%a' "$SOURCE_SITE_DIR/global.settings/webservices.sops.json")" != "600" ]; then
  printf '[runtime-test] Latium SOPS secret file must be mode 0600\n' >&2
  exit 1
fi

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
for domain in webservices test-runners forgejo-runner jupyterhub workload-spawner; do
  mkdir -p "$generated_units/rootless-$domain" "$generated_units/rootless-$domain-early" "$generated_units/rootless-$domain-late"
  QUADLET_UNIT_DIRS="$WORK_DIR/podman-a/quadlet/rootless-$domain" /usr/libexec/podman/quadlet \
    "$generated_units/rootless-$domain" "$generated_units/rootless-$domain-early" "$generated_units/rootless-$domain-late"
  units=("$WORK_DIR/podman-a/quadlet/rootless-$domain"/*.target)
  if compgen -G "$generated_units/rootless-$domain/*.service" >/dev/null; then
    units+=("$generated_units/rootless-$domain"/*.service)
  fi
  systemd-analyze verify "${units[@]}"
done

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
