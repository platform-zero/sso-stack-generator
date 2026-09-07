#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
MODULES_DIR="${MODULES_DIR:-$ROOT_DIR/../modules}"
# shellcheck source=scripts/lib/common.sh
source "$ROOT_DIR/scripts/lib/common.sh"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT
[ -d "$MODULES_DIR" ] || {
  printf '[runtime-test] module workspace not found: %s\n' "$MODULES_DIR" >&2
  exit 1
}

default_site="$ROOT_DIR/../site-config/sites/latium/manifest.json"
synthetic_site=false
if [ -n "${SITE_MANIFEST:-}" ]; then
  SOURCE_SITE="$SITE_MANIFEST"
elif [ -f "$default_site" ]; then
  SOURCE_SITE="$default_site"
else
  synthetic_site=true
  fixture_site="$WORK_DIR/site-source"
  mkdir -p "$fixture_site/global.settings"
  mapfile -t fixture_modules < <(
    find -L "$MODULES_DIR" -mindepth 2 -maxdepth 3 -name stack.module.json -type f -print \
      | sort \
      | xargs -r -n1 jq -r '.id'
  )
  [ "${#fixture_modules[@]}" -gt 0 ] || {
    printf '[runtime-test] no module manifests found under %s\n' "$MODULES_DIR" >&2
    exit 1
  }
  printf '%s\n' "${fixture_modules[@]}" \
    | jq -R . \
    | jq -s '{
        schemaVersion: 2,
        site: "ci-runtime",
        stackConfig: "./global.settings/stack.config.yaml",
        secretStore: "./global.settings/webservices.sops.json",
        components: ["full", "searxng", "workload-spawner"],
        modules: .
      }' > "$fixture_site/manifest.json"
  cat > "$fixture_site/global.settings/stack.config.yaml" <<'EOF_STACK_CONFIG'
storage:
  media_writer_uid: 1000
  media_writer_gid: 1000
  volume_root: "/mnt/stack/volumes"
  vector_dbs: "/mnt/stack/vector-dbs"
  pg_ssd_root: "/mnt/stack/pg-ssd"
  custom:
    qbittorrent_data: "/mnt/media/qbittorrent"
    seafile_media: "/mnt/media/seafile-media"
    jellyfin_media: "/mnt/media/jellyfin-media"
runtime:
  domain: "example.test"
  admin_email: "admin@example.test"
  admin_user: "admin"
  trusted_proxy_source_ranges: "127.0.0.1/32 ::1/128"
theme:
  name: "ci"
  brand_name: "ci"
  mode: "dark"
vaultwarden:
  org_name: "ci"
  org_identifier: "example.test"
  org_id: "00000000-0000-0000-0000-000000000000"
EOF_STACK_CONFIG
  mapfile -t fixture_secret_keys < <(
    {
      rg --follow -o --no-filename '\{\{[A-Z_][A-Z0-9_]*\}\}' "$MODULES_DIR" \
        | tr -d '{}'
      rg --follow -o --no-filename '\$\{[A-Z_][A-Z0-9_]*[^}]*\}' "$MODULES_DIR" \
        | sed -E 's/^\$\{([A-Z_][A-Z0-9_]*).*/\1/'
    } | sort -u
  )
  printf '%s\n' "${fixture_secret_keys[@]}" \
    | jq -Rn '[inputs | select(length > 0) | {key: ., value: "test"}] | from_entries' \
      > "$fixture_site/global.settings/webservices.sops.json"
  chmod 0600 "$fixture_site/global.settings/webservices.sops.json"
  SOURCE_SITE="$fixture_site/manifest.json"
fi

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
  (
    cd "$WORK_DIR"
    "$ROOT_DIR/generate.sh" \
      --site "$SITE" \
      --modules-dir "$MODULES_DIR" \
      --backend "$1" \
      --output "$2"
  )
}

generate podman "$WORK_DIR/podman-a"
generate podman "$WORK_DIR/podman-b"

diff -ru "$WORK_DIR/podman-a" "$WORK_DIR/podman-b"
WEBSERVICES_OVERLAY_ROOT="$WORK_DIR/podman-a" "$ROOT_DIR/scripts/test-host-lifecycle-static.sh"

jq -e '
  (.schemaVersion == 1) and
  (.domains | length == 14) and
  (([.domains[].name] | unique | length) == 14) and
  (([.domains[].user] | unique | length) == 14) and
  all(.domains[]; (.stateRoot | startswith("/mnt/stack/")) and (.graphRoot | startswith("/mnt/stack/")) and (.volumeRoot | startswith("/mnt/stack/")))
' "$WORK_DIR/podman-a/podman-domains.json" >/dev/null

jq -e --slurpfile domains "$WORK_DIR/podman-a/podman-domains.json" '
  .services as $services |
  all($services | to_entries[] | select(.value.placement == "rootless");
    . as $entry |
    ($domains[0].domains[] | select(.name == $entry.value.rootlessDomain) | .user) == $entry.value.rootlessUser)
' "$WORK_DIR/podman-a/stack.ir.json" >/dev/null

jq -e '(.schemaVersion == 1) and (.workspaces | length == 16) and ([.workspaces[].name] | unique | length == 16)' \
  "$WORK_DIR/podman-a/maintenance-workspaces.json" >/dev/null

jq -e '
  (.schemaVersion == 1) and (.owner == "software_lab") and
  (.root == "/mnt/lab_debian/software_lab") and
  (.workspaces | length == 9) and
  ([.workspaces[].name] | sort == ["auto_scad", "backup", "chatex", "crypto_trading", "hitl", "my_brand", "obelisks", "poe_intelligence", "worklane"]) and
  all(.workspaces[];
    .role == "software" and .profile == "software-gpu" and .startAtBoot == true and
    .devices == ["nvidia.com/gpu=all"] and (.projectPath | startswith("/mnt/lab_debian/software_lab/")))
' "$WORK_DIR/podman-a/software-workspaces.json" >/dev/null

test -x "$WORK_DIR/podman-a/ops/start-worklane-containers.py"
test -f "$WORK_DIR/podman-a/ops/platform-zero-worklanes.service"

python3 "$WORK_DIR/podman-a/ops/materialize-workspaces.py" \
  --manifest "$WORK_DIR/podman-a/maintenance-workspaces.json" \
  --root "$WORK_DIR/workspace-plan" > "$WORK_DIR/workspace-plan.json"
jq -e '(.apply == false) and (.blockers == []) and (.actions | length > 0)' "$WORK_DIR/workspace-plan.json" >/dev/null

python3 "$WORK_DIR/podman-a/ops/materialize-workspaces.py" \
  --manifest "$WORK_DIR/podman-a/software-workspaces.json" \
  --root "$WORK_DIR/software-workspace-plan" > "$WORK_DIR/software-workspace-plan.json"
jq -e '(.apply == false) and (.blockers == []) and (.actions == [])' "$WORK_DIR/software-workspace-plan.json" >/dev/null

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

if jq -e '.services | has("valkey")' "$WORK_DIR/podman-a/stack.ir.json" >/dev/null; then
  if ! rg -Fq '$$VALKEY_PASSWORD' "$WORK_DIR/podman-a/runtime-model.yml"; then
    printf '[runtime-test] Compose output lost the escaped container-side Valkey variable\n' >&2
    exit 1
  fi
  if ! rg -Fq '$$VALKEY_PASSWORD' "$WORK_DIR/podman-a/quadlet/rootless-data/webservices-valkey.container"; then
    printf '[runtime-test] Quadlet output does not preserve the container-side Valkey variable\n' >&2
    exit 1
  fi
fi

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
  ($services["test-runner"].rootlessDomain == "test-runners") and
  ($services["test-runner-managed"].rootlessDomain == "test-runners") and
  (($services | has("forgejo-runner") | not) or $services["forgejo-runner"].rootlessDomain == "forgejo-runner") and
  ($services["jupyterhub"].rootlessDomain == "jupyterhub") and
  ($services["jupyter-notebook-build"].rootlessDomain == "jupyterhub") and
  (($services | has("workload-spawner-postgres") | not) or $services["workload-spawner-postgres"].rootlessDomain == "workload-spawner") and
  (($services | has("workload-spawner-api") | not) or $services["workload-spawner-api"].rootlessDomain == "workload-spawner") and
  (($services | has("workload-spawner-router") | not) or $services["workload-spawner-router"].rootlessDomain == "workload-spawner") and
  ($services["caddy"].networks | keys == ["caddy"])
' "$WORK_DIR/podman-a/stack.ir.json" >/dev/null

while IFS= read -r domain; do
  test -d "$WORK_DIR/podman-a/quadlet/rootless-$domain"
done < <(jq -r '.domains[].name' "$WORK_DIR/podman-a/podman-domains.json")

if ! rg -Fxq 'StopTimeout=60' "$WORK_DIR/podman-a/quadlet/rootless-data/webservices-mariadb.container"; then
  printf '[runtime-test] MariaDB Quadlet is missing its graceful container stop timeout\n' >&2
  exit 1
fi

if ! rg -Fxq 'Network=host' "$WORK_DIR/podman-a/quadlet/rootful/webservices-alloy.container" ||
   rg -q '^Network=webservices-' "$WORK_DIR/podman-a/quadlet/rootful/webservices-alloy.container"; then
  printf '[runtime-test] Alloy must use the host network to reach the loopback-only rootless Loki bridge\n' >&2
  exit 1
fi

if ! rg -Fxq 'PublishPort=127.0.0.1:13100:3100' "$WORK_DIR/podman-a/quadlet/rootless-observability/webservices-loki.container" ||
   ! rg -Fq 'url = "http://127.0.0.1:13100/loki/api/v1/push"' "$WORK_DIR/podman-a/runtime/configs/alloy/alloy.hcl"; then
  printf '[runtime-test] Alloy/Loki cross-domain loopback bridge is incomplete\n' >&2
  exit 1
fi

if yq -e '.podman.cross_domain_endpoints | length > 0' "$SOURCE_SITE_DIR/global.settings/stack.config.yaml" >/dev/null 2>&1; then
  jq -e '
    any(.endpoints[]; .service == "postgres" and .containerPort == "5432" and .hostPort == 25001 and (.consumers | index("identity"))) and
    any(.endpoints[]; .service == "postgres-ssd" and .hostPort == 25002 and (.consumers | index("observability")))
  ' "$WORK_DIR/podman-a/podman-loopback-endpoints.json" >/dev/null
  rg -Fxq 'PublishPort=127.0.0.1:25001:5432' "$WORK_DIR/podman-a/quadlet/rootless-data/webservices-postgres.container"
  rg -Fxq 'PublishPort=127.0.0.1:25002:5432' "$WORK_DIR/podman-a/quadlet/rootless-data/webservices-postgres-ssd.container"
  rg -Fxq 'KC_DB=postgres' "$WORK_DIR/podman-a/runtime-env/keycloak.env.template"
  rg -Fq 'jdbc:postgresql://host.containers.internal:25001/keycloak' "$WORK_DIR/podman-a/runtime-env/keycloak.env.template"
  rg -Fxq 'POSTGRES_PORT=25002' "$WORK_DIR/podman-a/runtime-env/jupyterhub.env.template"
  test -f "$WORK_DIR/podman-a/quadlet/rootless-identity/webservices-p0-egress.network"
  rg -Fq 'Network=webservices-p0-egress.network' "$WORK_DIR/podman-a/quadlet/rootless-identity/webservices-keycloak-bootstrap.container"
  rg -Fq 'http://host.containers.internal:25007' "$WORK_DIR/podman-a/runtime/configs/matrix-authentication-service/config.yaml"
  rg -q -e 'host:[[:space:]]+host\.containers\.internal' "$WORK_DIR/podman-a/runtime/configs/synapse/homeserver.yaml"
  rg -q -e 'port:[[:space:]]+25001' "$WORK_DIR/podman-a/runtime/configs/synapse/homeserver.yaml"
  rg -Fxq 'DB_HOST=host.containers.internal' "$WORK_DIR/podman-a/runtime/configs/mastodon/mastodon.env"
  rg -Fq 'host.containers.internal:25002' "$WORK_DIR/podman-a/runtime/configs/grafana/provisioning/datasources/timescaledb.yml"
  rg -Fq 'psql -h host.containers.internal' "$WORK_DIR/podman-a/stack.ir.json"
  rg -Fq 'chown postgres:postgres' "$WORK_DIR/podman-a/runtime/configs/postgres/ssd-entrypoint.sh"
  test -s "$WORK_DIR/podman-a/ops/platform-zero.nft"
  rg -Fq 'meta skuid 993 tcp dport' "$WORK_DIR/podman-a/ops/platform-zero.nft"
  rg -Fq 'ip daddr 127.0.0.0/8 tcp dport' "$WORK_DIR/podman-a/ops/platform-zero.nft"
fi

if ! jq -e '.panels[] | .targets[]? | select(.expr == "{source=\"journald\"}")' \
  "$WORK_DIR/podman-a/runtime/configs/grafana/provisioning/dashboards/logs.json" >/dev/null; then
  printf '[runtime-test] Grafana Logs dashboard does not query Alloy journal labels\n' >&2
  exit 1
fi

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
while IFS= read -r domain; do
  mkdir -p "$generated_units/rootless-$domain" "$generated_units/rootless-$domain-early" "$generated_units/rootless-$domain-late"
  QUADLET_UNIT_DIRS="$WORK_DIR/podman-a/quadlet/rootless-$domain" /usr/libexec/podman/quadlet \
    "$generated_units/rootless-$domain" "$generated_units/rootless-$domain-early" "$generated_units/rootless-$domain-late"
  units=("$WORK_DIR/podman-a/quadlet/rootless-$domain"/*.target)
  if compgen -G "$generated_units/rootless-$domain/*.service" >/dev/null; then
    units+=("$generated_units/rootless-$domain"/*.service)
  fi
  systemd-analyze verify "${units[@]}"
done < <(jq -r '.domains[].name' "$WORK_DIR/podman-a/podman-domains.json")

if [ "$synthetic_site" = true ]; then
  fake_bin="$WORK_DIR/fake-bin"
  mkdir -p "$fake_bin"
  cat > "$fake_bin/sops" <<'EOF_FAKE_SOPS'
#!/usr/bin/env bash
set -euo pipefail
[ "$#" -eq 2 ] && [ "$1" = "--decrypt" ] && [ -f "$2" ]
cat "$2"
EOF_FAKE_SOPS
  chmod +x "$fake_bin/sops"
  PATH="$fake_bin:$PATH" "$WORK_DIR/podman-a/ops/install-podman-bundle.sh" --bundle "$WORK_DIR/podman-a"
else
  "$WORK_DIR/podman-a/ops/install-podman-bundle.sh" --bundle "$WORK_DIR/podman-a"
fi

if rg -Fq 'chown -R "$domain_user:$domain_user" "$destination"' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-test] installer would overwrite persistent container-UID ownership on every deployment\n' >&2
  exit 1
fi
if ! rg -Fq 'cp -a "$ENV_DIR/." "$env_input_snapshot/"' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-test] installer does not protect an in-place persistent environment source\n' >&2
  exit 1
fi
if ! rg -Fq 'owners.setdefault(relative, set()).add(domain)' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-test] installer does not reapply generated cross-domain config rewrites after environment rendering\n' >&2
  exit 1
fi
if ! rg -Fq 'pasta_options = ["--map-host-loopback", "169.254.1.2"]' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-test] installer does not enable UID-filterable host-loopback mapping for rootless networks\n' >&2
  exit 1
fi
if ! rg -Fq 'wait_for_cross_domain_producers' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh" ||
   ! rg -Fq 'retry_failed_rootless_services' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-test] installer does not sequence cross-domain producers before retrying consumers\n' >&2
  exit 1
fi

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
