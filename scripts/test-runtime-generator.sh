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

bash "$ROOT_DIR/scripts/test-runtime-input-duplicates.sh"
bash "$ROOT_DIR/scripts/test-caddy-private-ingress-render.sh"
python3 -B "$ROOT_DIR/scripts/test-caddy-venue-guest-binding.py"
python3 -B "$ROOT_DIR/scripts/test-livekit-private-ice-binding.py"
python3 -B "$ROOT_DIR/scripts/test-existing-host-venue.py"
python3 -B "$ROOT_DIR/scripts/test-venue-owned-stage.py"
python3 -B "$ROOT_DIR/scripts/test-venue-user-managers.py"
python3 -B "$ROOT_DIR/scripts/test-venue-unit-stage.py"
python3 -B "$ROOT_DIR/scripts/test-venue-graph-clear.py"
python3 -B "$ROOT_DIR/scripts/test-venue-release-inert.py"
python3 -B "$ROOT_DIR/scripts/test-venue-image-authority.py"
python3 -B "$ROOT_DIR/scripts/test-venue-domain-build-inputs.py"
python3 -B "$ROOT_DIR/scripts/test-venue-registry-images.py"
python3 -B "$ROOT_DIR/scripts/test-venue-build-base-images.py"
python3 -B "$ROOT_DIR/scripts/test-venue-shortname-cache-retire.py"
python3 -B "$ROOT_DIR/scripts/test-venue-local-build-images.py"
python3 -B "$ROOT_DIR/scripts/test-venue-offline-build-network.py"
python3 -B "$ROOT_DIR/scripts/test-venue-installer-composite-adoption.py"
python3 -B "$ROOT_DIR/scripts/test-venue-start-quarantine.py"
python3 -B "$ROOT_DIR/scripts/test-venue-guarded-start.py"
python3 -B "$ROOT_DIR/scripts/test-venue-private-ingress.py"
python3 -B "$ROOT_DIR/scripts/test-venue-root-health.py"
python3 -B "$ROOT_DIR/scripts/test-venue-port-screen.py"
python3 -B "$ROOT_DIR/scripts/test-owned-guest-network.py"
python3 -B "$ROOT_DIR/scripts/test-venue-guest-fence-hook.py"
python3 -B "$ROOT_DIR/scripts/test-venue-build-tmp-retire.py"
python3 -B "$ROOT_DIR/scripts/test-venue-runtime-env-inert.py"
python3 -B "$ROOT_DIR/scripts/test-venue-composite-inert.py"
python3 -B "$ROOT_DIR/scripts/test-venue-cross-domain-acl.py"
python3 -B "$ROOT_DIR/scripts/test-venue-runner-token-file-acl.py"
python3 -B "$ROOT_DIR/scripts/test-venue-runtime-render-dir.py"
python3 -B "$ROOT_DIR/scripts/test-venue-caddy-live.py"
python3 -B "$ROOT_DIR/scripts/test-venue-control-source.py"
python3 -B "$ROOT_DIR/scripts/test-venue-huly-volumes.py"
python3 -B "$ROOT_DIR/scripts/test-venue-volume-authority.py"
python3 -B "$ROOT_DIR/scripts/test-venue-bind-dirs.py"
python3 -B "$ROOT_DIR/scripts/test-venue-log-binds.py"
python3 -B "$ROOT_DIR/scripts/test-venue-fixture-binds.py"
python3 -B "$ROOT_DIR/scripts/test-rendered-loopback-configs.py"
python3 -B "$ROOT_DIR/scripts/test-venue-populated-reset.py"
python3 -B "$ROOT_DIR/scripts/test-venue-authority-retirement.py"
python3 -B "$ROOT_DIR/scripts/test-venue-boot-lost-paths.py"
python3 -B "$ROOT_DIR/scripts/test-venue-host-unit-retirement.py"
python3 -B "$ROOT_DIR/scripts/test-venue-recovery-inventory.py"
python3 -B "$ROOT_DIR/scripts/test-existing-host-guest-network.py"
python3 -B "$ROOT_DIR/scripts/test-existing-host-ingress.py"
python3 -B "$ROOT_DIR/scripts/test-existing-host-listener-intent.py"
python3 -B "$ROOT_DIR/scripts/test-pinned-images.py"
python3 -B "$ROOT_DIR/scripts/test-registry-preparation.py"

# Cached dist JARs must be seeded before compilation, never replace selected-source output.
python3 - "$ROOT_DIR/runtime-generator/stack-generator.main.kts" <<'PY'
import sys
from pathlib import Path
source = Path(sys.argv[1]).read_text()
seed = source.index('        materializeGeneratedBuildArtifacts(modules, staging)')
compile_selected = source.index('        buildLocalArtifacts(staging)')
assert seed < compile_selected, 'cached artifacts overwrite freshly compiled selected source'
print('[runtime-test] selected-source compilation wins over cached dist artifacts')
PY

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
if jq -e 'has("agentVmSpec")' "$SITE" >/dev/null; then
  vm_source="$(jq -r '.agentVmSpec' "$SITE")"
  [ "$vm_source" = agent-vm.json ] || { printf '[runtime-test] unexpected VM spec path\n' >&2; exit 1; }
  cp "$SOURCE_SITE_DIR/$vm_source" "$WORK_DIR/$vm_source"
fi
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

(umask 077; generate podman "$WORK_DIR/podman-a")
generate podman "$WORK_DIR/podman-b"

diff -ru "$WORK_DIR/podman-a" "$WORK_DIR/podman-b"
python3 "$ROOT_DIR/scripts/test-agent-vm-bundle.py"
python3 "$WORK_DIR/podman-a/ops/verify-agent-vm-bundle.py" --bundle "$WORK_DIR/podman-a" >/dev/null
if jq -e '.site == "latium"' "$SITE" >/dev/null; then
  cp "$WORK_DIR/agent-vm.json" "$WORK_DIR/agent-vm.original"
  original_bundle_hash="$(sha256sum "$WORK_DIR/podman-a/site/agent-vm.json" | cut -d' ' -f1)"
  python3 - "$WORK_DIR/agent-vm.json" <<'PY_DUPLICATE_VM'
from pathlib import Path
import sys
p=Path(sys.argv[1]);s=p.read_text();p.write_text(s.replace('"controlCommit":', '"controlCommit":"' + '0'*40 + '", "controlCommit":'))
PY_DUPLICATE_VM
  if generate podman "$WORK_DIR/podman-a" > "$WORK_DIR/invalid-vm-generate.log" 2>&1; then
    printf '[runtime-test] duplicate VM authority unexpectedly replaced the bundle\n' >&2; exit 1
  fi
  cmp "$WORK_DIR/agent-vm.original" "$WORK_DIR/podman-a/site/agent-vm.json"
  [ "$(sha256sum "$WORK_DIR/podman-a/site/agent-vm.json" | cut -d' ' -f1)" = "$original_bundle_hash" ]
  python3 - "$WORK_DIR/agent-vm.original" "$WORK_DIR/agent-vm.json" <<'PY_BOOLEAN_VM'
import json,sys
from pathlib import Path
source=Path(sys.argv[1]);target=Path(sys.argv[2]);vm=json.loads(source.read_text());vm['schemaVersion']=True;target.write_text(json.dumps(vm))
PY_BOOLEAN_VM
  if generate podman "$WORK_DIR/podman-a" > "$WORK_DIR/boolean-vm-generate.log" 2>&1; then
    printf '[runtime-test] boolean VM schema unexpectedly replaced the bundle\n' >&2; exit 1
  fi
  cmp "$WORK_DIR/agent-vm.original" "$WORK_DIR/podman-a/site/agent-vm.json"
  mv "$WORK_DIR/agent-vm.original" "$WORK_DIR/agent-vm.json"
  printf '[runtime-test] duplicate and boolean VM authority refused before atomic bundle replacement\n'
fi
if jq -e 'has("agentVmSpec")' "$SITE" >/dev/null; then
  jq -e --arg digest "$(sha256sum "$WORK_DIR/agent-vm.json" | cut -d' ' -f1)" \
    '.schemaVersion == 1 and .path == "agent-vm.json" and .sha256 == $digest' \
    "$WORK_DIR/podman-a/site/agent-vm.provenance.json" >/dev/null
fi
python3 - "$WORK_DIR/podman-a" <<'PY_PUBLIC_MODES'
import json, stat, sys
from pathlib import Path
b = Path(sys.argv[1])
store = b / 'site' / json.loads((b / 'site/manifest.json').read_text())['secretStore']
assert stat.S_IMODE(store.stat().st_mode) == 0o600
assert not (b / 'runtime/stack.env').exists(), 'build emitted a decrypted runtime environment'
for path in b.rglob('*'):
    assert path.name != '__pycache__' and path.suffix not in ('.pyc', '.pyo'), (
        path, 'transient interpreter cache entered immutable bundle')
    mode = stat.S_IMODE(path.stat().st_mode)
    if path.is_dir():
        assert mode == 0o755, (path, 'public directory inherits private umask')
    elif path != store:
        assert mode & 0o444 == 0o444 and mode & 0o022 == 0, (path, 'public asset unreadable/unsafe')
print('[runtime-test] private umask preserves readable public build inputs and encrypted-store privacy')
PY_PUBLIC_MODES
jq -e --arg commit "$(git -C "$ROOT_DIR" rev-parse HEAD)" '
  .schemaVersion == 1 and .generatorCommit == $commit and
  (.manifestSha256 | test("^[0-9a-f]{64}$")) and
  (.stackConfigSha256 | test("^[0-9a-f]{64}$")) and
  (.modules | length > 0) and
  (all(.modules[]; (.id | type == "string") and (.commit | test("^[0-9a-f]{40}$"))))
' "$WORK_DIR/podman-a/source-provenance.json" >/dev/null
jq -e --arg hash "$(sha256sum "$WORK_DIR/podman-a/source-provenance.json" | cut -d' ' -f1)" \
  '.sourceProvenanceSha256 == $hash' "$WORK_DIR/podman-a/bundle.json" >/dev/null
WEBSERVICES_OVERLAY_ROOT="$WORK_DIR/podman-a" "$ROOT_DIR/scripts/test-host-lifecycle-static.sh"

jq -e '
  (.schemaVersion == 1) and
  (.domains | length == 7) and
  (([.domains[].name] | unique | length) == 7) and
  (([.domains[].user] | unique | length) == 7) and
  all(.domains[]; (.stateRoot | startswith("/mnt/stack/")) and (.graphRoot | startswith("/mnt/stack/")) and (.volumeRoot | startswith("/mnt/stack/")))
' "$WORK_DIR/podman-a/podman-domains.json" >/dev/null

jq -e 'all(.endpoints[]; .consumers | index("test-runners"))' \
  "$WORK_DIR/podman-a/podman-loopback-endpoints.json" >/dev/null

jq -e --slurpfile domains "$WORK_DIR/podman-a/podman-domains.json" '
  .services as $services |
  all($services | to_entries[] | select(.value.placement == "rootless");
    . as $entry |
    ($domains[0].domains[] | select(.name == $entry.value.rootlessDomain) | .user) == $entry.value.rootlessUser)
' "$WORK_DIR/podman-a/stack.ir.json" >/dev/null

jq -e '(.schemaVersion == 1) and (.workspaces | length == 6) and ([.workspaces[].name] | unique | length == 6) and all(.workspaces[]; .startAtBoot == false)' \
  "$WORK_DIR/podman-a/maintenance-workspaces.json" >/dev/null

if [ -f "$WORK_DIR/podman-a/software-workspaces.json" ]; then
jq -e '
  (.schemaVersion == 1) and (.owner == "software_lab") and
  (.root == "/mnt/lab_debian/software_lab") and
  (.workspaces | length == 10) and
  ([.workspaces[].name] | sort == ["arbitrage_exploration", "auto_scad", "backup", "chatex", "crypto_trading", "hitl", "my_brand", "obelisks", "poe_intelligence", "worklane"]) and
  all(.workspaces[];
    .role == "software" and .profile == "software-gpu" and .startAtBoot == false and
    .devices == ["nvidia.com/gpu=all"] and (.projectPath | startswith("/mnt/lab_debian/software_lab/")))
' "$WORK_DIR/podman-a/software-workspaces.json" >/dev/null
else
  config_file="$(python3 - "$SITE" <<'PY_NO_SOFTWARE'
import json, sys
from pathlib import Path
manifest = Path(sys.argv[1])
print(manifest.parent / json.loads(manifest.read_text())['stackConfig'])
PY_NO_SOFTWARE
)"
  if grep -Eq '^[[:space:]]*software_workspaces:' "$config_file"; then
    printf '[runtime-test] selected software workspace manifest is missing\n' >&2
    exit 1
  fi
  printf '[runtime-test] unselected software/GPU estate remains absent\n'
fi

test -x "$WORK_DIR/podman-a/ops/start-worklane-containers.py"
test -f "$WORK_DIR/podman-a/ops/platform-zero-worklanes.service"
test -x "$WORK_DIR/podman-a/ops/reap-idle-worklanes.py"
test -f "$WORK_DIR/podman-a/ops/platform-zero-worklane-idle-reaper.service"
test -f "$WORK_DIR/podman-a/ops/platform-zero-worklane-idle-reaper.timer"
grep -Fq 'SocketMode=0666' "$WORK_DIR/podman-a/ops/platform-zero-host-broker.socket"
grep -Fq "fs.inotify.max_user_instances = 1024" "$WORK_DIR/podman-a/ops/provision-domain-accounts.sh"
grep -Fq "/etc/sysctl.d/90-platform-zero-worklanes.conf" "$WORK_DIR/podman-a/ops/provision-domain-accounts.sh"
grep -Fq 'usermod --shell /bin/bash "$user"' "$WORK_DIR/podman-a/ops/provision-domain-accounts.sh"

grep -Eq '^PodmanArgs=.*--memory=2G.*--cpus=2\.0' "$WORK_DIR/podman-a/quadlet/rootless-platform/webservices-keycloak.container"
grep -Eq '^PodmanArgs=.*--memory=3G.*--cpus=2\.0' "$WORK_DIR/podman-a/quadlet/rootless-platform/webservices-opensearch.container"
grep -Eq '^PodmanArgs=.*--memory=2G.*--cpus=1\.0' "$WORK_DIR/podman-a/quadlet/rootless-apps/webservices-huly-redpanda.container"
grep -Eq '^PodmanArgs=.*--memory=2G.*--cpus=1\.5' "$WORK_DIR/podman-a/quadlet/rootless-apps/webservices-huly-elastic.container"
if jq -e '.services | has("android-test-runner-api36")' "$WORK_DIR/podman-a/stack.ir.json" >/dev/null; then
  grep -Fxq 'AddDevice=/dev/kvm:/dev/kvm' "$WORK_DIR/podman-a/quadlet/rootless-test-runners/webservices-android-test-runner-api36.container"
  grep -Fxq 'GroupAdd=keep-groups' "$WORK_DIR/podman-a/quadlet/rootless-test-runners/webservices-android-test-runner-api36.container"
  grep -Fxq 'PidsLimit=4096' "$WORK_DIR/podman-a/quadlet/rootless-test-runners/webservices-android-test-runner-api36.container"
fi

python3 - "$WORK_DIR/podman-a/ops/materialize-workspaces.py" <<'PY'
import importlib.util
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("materialize_workspaces", path)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
assert module.LEGACY_PROFILES.endswith("\n")
assert not module.LEGACY_PROFILES.endswith("\n\n")
control = {
    "name": "control",
    "role": "control",
    "repositories": [],
}
guidance = module.agents_text(control)
assert "You are operating inside the `control` Worklane" in guidance
assert "stack_lab@192.168.0.11" in guidance
assert "7 rootless `webservices-*` Linux-user authorities" in guidance
assert "p0-hostctl status" in guidance
assert "stage, preflight, snapshot, activate, then verify" in guidance
assert "RTX 3060" in guidance
assert "Gerald passwordless sudo is intentionally retained" in guidance
previous = next(text for text in module.legacy_agents_texts(control) if "## Maintenance workflow" not in text)
assert previous != guidance
assert "stack_lab@192.168.0.11" not in previous
assert guidance in module.managed_agents_texts(control)
assert previous in module.managed_agents_texts(control)
assert guidance + "user edit\n" not in module.managed_agents_texts(control)
assert guidance not in module.legacy_agents_texts({"name": "host", "role": "host", "repositories": []})
domain = {
    "name": "platform",
    "role": "domain",
    "authorities": [{"name": "platform", "serviceAccount": "webservices-platform"}],
    "repositories": [],
}
assert "./.p0/<authority>ctl" in module.agents_text(domain)
dispatcher = module.domainctl_text(domain["authorities"][0])
assert "BatchMode=yes" in dispatcher
assert "dispatcher_ed25519" in dispatcher
assert "webservices-platform@${P0_HOST:-192.168.0.11}" in dispatcher
assert len(module.HOST_ACCESS_MOUNTS) == 3
assert "/run/platform-zero" in module.PROFILES
PY

python3 "$WORK_DIR/podman-a/ops/materialize-workspaces.py" \
  --manifest "$WORK_DIR/podman-a/maintenance-workspaces.json" \
  --root "$WORK_DIR/workspace-plan" > "$WORK_DIR/workspace-plan.json"
jq -e '(.apply == false) and (.blockers == []) and (.actions | length > 0)' "$WORK_DIR/workspace-plan.json" >/dev/null

if [ -f "$WORK_DIR/podman-a/software-workspaces.json" ]; then
  python3 "$WORK_DIR/podman-a/ops/materialize-workspaces.py" \
    --manifest "$WORK_DIR/podman-a/software-workspaces.json" \
    --root "$WORK_DIR/software-workspace-plan" > "$WORK_DIR/software-workspace-plan.json"
  jq -e '(.apply == false) and (.blockers == []) and (.actions == [])' "$WORK_DIR/software-workspace-plan.json" >/dev/null
fi

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
  if ! rg -Fq '$${VALKEY_PASSWORD}' "$WORK_DIR/podman-a/runtime-model.yml"; then
    printf '[runtime-test] Compose output lost the escaped container-side Valkey variable\n' >&2
    exit 1
  fi
  if ! rg -Fq '$${VALKEY_PASSWORD}' "$WORK_DIR/podman-a/quadlet/rootless-platform/webservices-valkey.container"; then
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
  (($services | has("kopia-snapshotter") | not) or $services["kopia-snapshotter"].placement == "rootful") and
  ($services["test-runner"].rootlessDomain == "test-runners") and
  ($services["test-runner-managed"].rootlessDomain == "test-runners") and
  (($services | has("forgejo-runner") | not) or $services["forgejo-runner"].rootlessDomain == "ci-runner") and
  ($services["jupyterhub"].rootlessDomain == "workloads") and
  ($services["jupyter-notebook-build"].rootlessDomain == "workloads") and
  (($services | has("workload-spawner-postgres") | not) or $services["workload-spawner-postgres"].rootlessDomain == "workloads") and
  (($services | has("workload-spawner-api") | not) or $services["workload-spawner-api"].rootlessDomain == "workloads") and
  (($services | has("workload-spawner-router") | not) or $services["workload-spawner-router"].rootlessDomain == "workloads") and
  ($services["caddy"].networks | keys == ["caddy"])
' "$WORK_DIR/podman-a/stack.ir.json" >/dev/null

while IFS= read -r domain; do
  test -d "$WORK_DIR/podman-a/quadlet/rootless-$domain"
done < <(jq -r '.domains[].name' "$WORK_DIR/podman-a/podman-domains.json")

if ! rg -Fxq 'StopTimeout=60' "$WORK_DIR/podman-a/quadlet/rootless-platform/webservices-mariadb.container"; then
  printf '[runtime-test] MariaDB Quadlet is missing its graceful container stop timeout\n' >&2
  exit 1
fi

if ! rg -Fxq 'Network=host' "$WORK_DIR/podman-a/quadlet/rootful/webservices-alloy.container" ||
   rg -q '^Network=webservices-' "$WORK_DIR/podman-a/quadlet/rootful/webservices-alloy.container"; then
  printf '[runtime-test] Alloy must use the host network to reach the loopback-only rootless Loki bridge\n' >&2
  exit 1
fi

if ! rg -Fxq 'PublishPort=127.0.0.1:13100:3100' "$WORK_DIR/podman-a/quadlet/rootless-platform/webservices-loki.container" ||
   ! rg -Fq 'url = "http://127.0.0.1:13100/loki/api/v1/push"' "$WORK_DIR/podman-a/runtime/configs/alloy/alloy.hcl"; then
  printf '[runtime-test] Alloy/Loki cross-domain loopback bridge is incomplete\n' >&2
  exit 1
fi

if yq -e '.podman.cross_domain_endpoints | length > 0' "$SOURCE_SITE_DIR/global.settings/stack.config.yaml" >/dev/null 2>&1; then
  jq -e '
    any(.endpoints[]; .service == "postgres" and .containerPort == "5432" and .hostPort == 25001 and (.consumers | index("apps"))) and
    any(.endpoints[]; .service == "postgres-ssd" and .hostPort == 25002 and (.consumers | index("workloads")))
  ' "$WORK_DIR/podman-a/podman-loopback-endpoints.json" >/dev/null
  rg -Fxq 'PublishPort=127.0.0.1:25001:5432' "$WORK_DIR/podman-a/quadlet/rootless-platform/webservices-postgres.container"
  rg -Fxq 'PublishPort=127.0.0.1:25002:5432' "$WORK_DIR/podman-a/quadlet/rootless-platform/webservices-postgres-ssd.container"
  rg -Fxq 'KC_DB=postgres' "$WORK_DIR/podman-a/runtime-env/keycloak.env.template"
  rg -Fq 'jdbc:postgresql://postgres:5432/keycloak' "$WORK_DIR/podman-a/runtime-env/keycloak.env.template"
  rg -Fxq 'POSTGRES_PORT=25002' "$WORK_DIR/podman-a/runtime-env/jupyterhub.env.template"
  test -f "$WORK_DIR/podman-a/quadlet/rootless-platform/webservices-p0-egress.network"
  rg -Fq 'http://host.containers.internal:25007' "$WORK_DIR/podman-a/runtime/configs/matrix-authentication-service/config.yaml"
  rg -q -e 'host:[[:space:]]+host\.containers\.internal' "$WORK_DIR/podman-a/runtime/configs/synapse/homeserver.yaml"
  rg -q -e 'port:[[:space:]]+25001' "$WORK_DIR/podman-a/runtime/configs/synapse/homeserver.yaml"
  jq -e '.services["mastodon-web"].environment.DB_HOST == "host.containers.internal"' "$WORK_DIR/podman-a/stack.ir.json" >/dev/null
  jq -e '.services["mastodon-web"].command | tostring | contains("host.containers.internal.") | not' "$WORK_DIR/podman-a/stack.ir.json" >/dev/null
  rg -Fq 'postgres-ssd:5432' "$WORK_DIR/podman-a/runtime/configs/grafana/provisioning/datasources/timescaledb.yml"
  rg -Fq 'chown postgres:postgres' "$WORK_DIR/podman-a/runtime/configs/postgres/ssd-entrypoint.sh"
  test -s "$WORK_DIR/podman-a/ops/platform-zero.nft"
  rg -Fq 'meta skuid 988 tcp dport' "$WORK_DIR/podman-a/ops/platform-zero.nft"
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

if jq -e '.venue.unitPrefix' "$WORK_DIR/podman-a/podman-domains.json" >/dev/null; then
  python3 -B "$ROOT_DIR/scripts/test-venue-network-aliases.py" --bundle "$WORK_DIR/podman-a"
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
python3 -B "$ROOT_DIR/scripts/test-podman-health.py" "$WORK_DIR/podman-a" "$generated_units"
python3 -B "$ROOT_DIR/scripts/test-podman-health-inputs.py"
python3 -B "$ROOT_DIR/scripts/test-selection-exclusions.py"

image_input_args=()
if [ -n "${IMAGE_INPUTS:-}" ]; then
  image_input_args=(--image-inputs "$IMAGE_INPUTS")
fi
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
  PATH="$fake_bin:$PATH" "$WORK_DIR/podman-a/ops/install-podman-bundle.sh" --bundle "$WORK_DIR/podman-a" "${image_input_args[@]}"
else
  "$WORK_DIR/podman-a/ops/install-podman-bundle.sh" --bundle "$WORK_DIR/podman-a" "${image_input_args[@]}"
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
if ! rg -Fq 'if [ "$state" = "failed" ] && [ -z "$job" ]; then' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-generator-test] producer readiness must not fail while a restart job is queued\n' >&2
  exit 1
fi
if ! rg -Fq 'quiet_passes=$((quiet_passes + 1))' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-test] installer does not observe a post-producer quiet window for late consumer failures\n' >&2
  exit 1
fi
if ! rg -Fq 'user_systemctl "$i" list-units --failed' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-test] first-install retry loop must query failed user units with an explicit systemctl verb\n' >&2
  exit 1
fi
if ! rg -Fq '[ "$SECONDS" -lt $((stable_since + 15)) ] || return 0' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-test] installer must not accept a restarting daemon during a transient active window\n' >&2
  exit 1
fi
if ! rg -Fq '"${ROOTLESS_RELEASES[$i]}/runtime/stack.env"' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-test] installer does not provide the isolated test-runner authority with its cross-stack test environment\n' >&2
  exit 1
fi

if ! rg -Fq -- 'WorkingDirectory=/' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-generator-test] runtime environment restore must not inherit an inaccessible working directory\n' >&2
  exit 1
fi
if ! rg -Fq -- 'for env_file in $source_dir/*.env' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-generator-test] runtime environment restore must use a systemd-safe copy loop\n' >&2
  exit 1
fi
if [ "$(rg -Fc 'except FileNotFoundError:' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh")" -lt 2 ]; then
  printf '[runtime-generator-test] mutable volume ownership translation must tolerate disappearing paths\n' >&2
  exit 1
fi
if ! rg -Fq '"$STACK_LAB_ROOT/stack_work/$maintenance_lane/.p0"' "$WORK_DIR/podman-a/ops/install-platform-zero-control-plane.sh"; then
  printf '[runtime-generator-test] control-plane install must assign role-lane parents to stack_lab\n' >&2
  exit 1
fi
if ! rg -Fq 'id -nG "$kvm_user"' "$WORK_DIR/podman-a/ops/install-platform-zero-control-plane.sh" ||
   ! rg -Fq 'usermod -aG kvm "$kvm_user"' "$WORK_DIR/podman-a/ops/install-platform-zero-control-plane.sh" ||
   rg -Fq 'KERNEL=="kvm", OWNER=' "$WORK_DIR/podman-a/ops/install-platform-zero-control-plane.sh"; then
  printf '[runtime-generator-test] only scoped existing KVM group access may be added; device ownership must remain unchanged\n' >&2
  exit 1
fi
if ! rg -Fq 'chmod 0700 "$graph_root"' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-generator-test] rootless graph roots must strip inherited setgid mode\n' >&2
  exit 1
fi
if ! rg -Fq '\( -name diff -o -name merged \) -exec chmod 0755 {} +' "$WORK_DIR/podman-a/ops/install-podman-bundle.sh"; then
  printf '[runtime-generator-test] existing overlay roots must be traversable by non-root container users\n' >&2
  exit 1
fi

python3 - "$WORK_DIR/podman-a" "$MODULES_DIR" <<'PY_IMAGE_PINS'
import json, sys
from pathlib import Path
bundle = Path(sys.argv[1])
ir = json.loads((bundle / 'stack.ir.json').read_text())
caddy_source = Path(sys.argv[2]) / 'caddy' / 'stack.runtime.yaml'
if 'caddy' in ir['services'] and caddy_source.is_file() and 'rootlessStrategy: "shared"' in caddy_source.read_text():
    anchor = ir['volumes']['caddy_ca']
    assert anchor['rootlessStrategy'] == 'shared', 'declared public CA policy lost during materialization'
    consumers = 0
    for unit in (bundle / 'quadlet').glob('rootless-*/*.container'):
        for line in unit.read_text().splitlines():
            if '/caddy_ca:' in line:
                assert line.startswith('Volume=' + anchor['hostPath'] + ':'), (unit, 'domain-local CA shadow')
                assert ':ro' in line and ':U' not in line, (unit, 'shared public anchor is writable/remapped')
                consumers += 1
    assert consumers > 0, 'no readonly public anchor consumers verified'
    print('[runtime-test] declared shared public CA retained in readonly authority mounts')
for name, service in ir['services'].items():
    image = service.get('image', '')
    if '@sha256:' not in image or service.get('build'):
        continue
    domain = 'rootless-' + service['rootlessDomain'] if service['placement'] == 'rootless' else 'rootful'
    unit = (bundle / 'quadlet' / domain / ('webservices-' + name + '.container')).read_text()
    selected = next(line[6:] for line in unit.splitlines() if line.startswith('Image='))
    assert selected.endswith('@' + image.split('@', 1)[1]), (name, 'locked image digest was discarded')
    assert 'AutoUpdate=registry' not in unit, (name, 'immutable image enables registry advancement')
print('[runtime-test] immutable image digests retained without registry advancement')
PY_IMAGE_PINS

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

python3 -B "$ROOT_DIR/scripts/test-frozen-build-images.py" \
  --site "$SITE" --modules-dir "$MODULES_DIR" \
  --baseline-bundle "$WORK_DIR/podman-a" --work-dir "$WORK_DIR/frozen-image-tests"

printf '[runtime-test] dual-backend validation passed (%s services)\n' "$(wc -l < "$WORK_DIR/ir-services")"
