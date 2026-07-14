#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "[component-selection-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
CONTRACT_ROOT="${WEBSERVICES_CONTRACT_ROOT:-$ROOT_DIR}"
if [ "$CONTRACT_ROOT" = "$ROOT_DIR" ] && [ ! -f "$CONTRACT_ROOT/stack.config/components.json" ] && [ -f "$ROOT_DIR/dist/build/build/stack.config/components.json" ]; then
  CONTRACT_ROOT="$ROOT_DIR/dist/build/build"
elif [ "$CONTRACT_ROOT" = "$ROOT_DIR" ] && [ ! -f "$CONTRACT_ROOT/stack.config/components.json" ] && [ -f "$ROOT_DIR/dist/build/stack.config/components.json" ]; then
  CONTRACT_ROOT="$ROOT_DIR/dist/build"
fi
# shellcheck source=scripts/lib/common.sh
source "$ROOT_DIR/scripts/lib/common.sh"
# shellcheck source=scripts/lib/components.sh
source "$ROOT_DIR/scripts/lib/components.sh"
# shellcheck source=scripts/lib/runtime-contract.sh
source "$ROOT_DIR/scripts/lib/runtime-contract.sh"

assert_not_contains() {
  local file="$1"
  local pattern="$2"
  local label="$3"
  if grep -Eq "$pattern" "$file"; then
    printf '[component-selection-test] unexpected %s in %s\n' "$label" "$file" >&2
    grep -En "$pattern" "$file" >&2 || true
    exit 1
  fi
}

assert_contains() {
  local file="$1"
  local pattern="$2"
  local label="$3"
  if ! grep -Eq "$pattern" "$file"; then
    printf '[component-selection-test] missing %s in %s\n' "$label" "$file" >&2
    exit 1
  fi
}

assert_not_private_mode() {
  local file="$1"
  local label="$2"
  local mode
  mode="$(stat -c '%a' "$file")"
  if [ "$mode" = "600" ]; then
    printf '[component-selection-test] %s should preserve readable source mode, got %s: %s\n' "$label" "$mode" "$file" >&2
    exit 1
  fi
}

validate_caddy_file() {
  local caddy_file="$1"
  local caddy_log
  local container_cli
  caddy_log="$(mktemp)"
  if command -v podman >/dev/null 2>&1; then
    container_cli=podman
  else
    printf '[component-selection-test] missing required container CLI: podman\n' >&2
    exit 1
  fi
  if ! "$container_cli" run --rm \
    -v "$caddy_file:/etc/caddy/Caddyfile:ro" \
    -e DOMAIN=example.test \
    -e ONBOARDING_TRUSTED_PROXY_SECRET=test \
    -e KOPIA_PROXY_AUTHORIZATION=test \
    -e BOOKSTACK_INTERNAL_API_TOKEN=test \
    -e OPENSEARCH_BASIC_AUTH=test \
    -e HOMEASSISTANT_TRUSTED_PROXY_SECRET=test \
    -e VAULTWARDEN_ORG_ID=00000000-0000-0000-0000-000000000000 \
    docker.io/library/caddy:2.11.3 \
    caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >"$caddy_log" 2>&1; then
    cat "$caddy_log" >&2
    rm -f "$caddy_log"
    exit 1
  fi
  rm -f "$caddy_log"
}

tmp_root="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_root"
}
trap cleanup EXIT

fake_bin="$tmp_root/bin"
bundle_root="$tmp_root/bundle/build"
site_root="$bundle_root/site"
runtime_root="$tmp_root/runtime"
test_runner_runtime_dir="$tmp_root/test-runner-runtime"
test_results_dir="$tmp_root/test-results"
forgejo_runner_ssh_dir="$tmp_root/forgejo-runner-ssh"
host_paths_dir="$tmp_root/host-paths"
mkdir -p \
  "$fake_bin" \
  "$bundle_root" \
  "$site_root" \
  "$runtime_root" \
  "$test_runner_runtime_dir" \
  "$test_results_dir" \
  "$forgejo_runner_ssh_dir" \
  "$host_paths_dir"
export FORGEJO_RUNNER_SSH_DIR="$forgejo_runner_ssh_dir"
export TEST_RESULTS_HOST_DIR="$test_results_dir"
export TEST_RUNNER_HOST_XDG_RUNTIME_DIR="$test_runner_runtime_dir"
export TEST_RUNNER_RUNTIME_HOST_DIR="$test_runner_runtime_dir"
export DOMAIN=example.test
export DONETICK_JWT_SECRET=component-test-secret
export DONETICK_OAUTH_SECRET=component-test-secret
export ERPNEXT_OAUTH_SECRET=component-test-secret
export JELLYFIN_OIDC_SECRET=component-test-secret
export KEYCLOAK_ADMIN_PASSWORD=component-test-secret
export KOPIA_PROXY_AUTHORIZATION=component-test-secret
export ONBOARDING_TRUSTED_PROXY_SECRET=component-test-secret
export OPENSEARCH_ADMIN_PASSWORD='ComponentTestPassword123!'
export OPENSEARCH_BASIC_AUTH=test
export VALKEY_ADMIN_PASSWORD=component-test-secret
export BOOKSTACK_INTERNAL_API_TOKEN=component-test-secret
export BOOKSTACK_API_TOKEN_ID=component-test-token-id
export BOOKSTACK_API_TOKEN_SECRET=component-test-secret
export HOMEASSISTANT_TRUSTED_PROXY_SECRET=component-test-secret
export KOPIA_PASSWORD=component-test-secret
export MAIL_DOMAIN=example.test
export MASTODON_ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY=component-test-secret
export MASTODON_ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT=component-test-secret
export MASTODON_ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY=component-test-secret
export MASTODON_OTP_SECRET=component-test-secret
export MASTODON_SECRET_KEY_BASE=component-test-secret
export MASTODON_VAPID_PRIVATE_KEY=component-test-secret
export MASTODON_VAPID_PUBLIC_KEY=component-test-secret
export MEDIA_WRITER_GID="$(id -g)"
export MEDIA_WRITER_UID="$(id -u)"
export NTFY_PASSWORD=component-test-secret
export NTFY_USERNAME=component-test
export PG_SSD_ROOT="$host_paths_dir/pg-ssd"
export POSTGRES_PIPELINE_USER=pipeline
export POSTGRES_AIRFLOW_USER=airflow
export SEAFILE_MEDIA_ROOT="$host_paths_dir/seafile"
export SEAFILE_JWT_KEY=component-test-secret
export STACK_ADMIN_EMAIL=admin@example.test
export VAULTWARDEN_ORG_ID=00000000-0000-0000-0000-000000000000
export VAULTWARDEN_ORG_IDENTIFIER=component-test
export VAULTWARDEN_SMTP_PASSWORD=component-test-secret
export VECTOR_DB_ROOT="$host_paths_dir/vector"

cat > "$fake_bin/sops" <<'EOF_SOPS'
#!/usr/bin/env bash
set -euo pipefail
last=""
for arg in "$@"; do
  last="$arg"
done
cat "$last"
EOF_SOPS
chmod +x "$fake_bin/sops"

copy_tree "$CONTRACT_ROOT/global.settings" "$bundle_root/global.settings"
copy_tree "$CONTRACT_ROOT/runtime.contract" "$bundle_root/runtime.contract"
copy_tree "$CONTRACT_ROOT/stack.config" "$bundle_root/stack.config"
copy_tree "$CONTRACT_ROOT/stack.systemd" "$bundle_root/stack.systemd"
copy_tree "$ROOT_DIR/scripts" "$bundle_root/scripts"
mkdir -p "$bundle_root/runtime.contract"

cat > "$bundle_root/runtime.contract/component-marker-test.yml" <<'EOF_COMPOSE_MARKER'
volumes:
  component_marker_always:
  # webservices-component-start bookstack
  component_marker_bookstack:
  # webservices-component-end bookstack
EOF_COMPOSE_MARKER
catalog_temp="$(mktemp)"
jq '.components.core.composeFiles += ["component-marker-test.yml"]' \
  "$bundle_root/stack.config/components.json" > "$catalog_temp"
mv "$catalog_temp" "$bundle_root/stack.config/components.json"

cat > "$site_root/manifest.json" <<'EOF_MANIFEST'
{
  "site": "component-test",
  "stackConfig": "stack.config.yaml",
  "secretStore": "webservices.sops.json",
  "components": ["core"]
}
EOF_MANIFEST

cat > "$site_root/stack.config.yaml" <<'EOF_CONFIG'
runtime:
  domain: "example.test"
  admin_email: "admin@example.test"
  admin_user: "admin"
  caddy_tls_mode: "local"

vaultwarden:
  org_id: "00000000-0000-0000-0000-000000000000"
EOF_CONFIG

cat > "$site_root/webservices.sops.json" <<'EOF_SECRETS'
{
  "STACK_ADMIN_PASSWORD": "component-test-password"
}
EOF_SECRETS

cat > "$bundle_root/build-info.json" <<'EOF_BUILD_INFO'
{
  "version": "component-test",
  "gitSha": "component-test",
  "gitShortSha": "component-test",
  "gitBranch": "component-test",
  "gitDirty": false,
  "sourceBuiltAt": "component-test",
  "builtBy": "component-test",
  "buildSystem": "component-test"
}
EOF_BUILD_INFO

component_selection_write_metadata \
  "$site_root/manifest.json" \
  "$bundle_root/stack.config/components.json" \
  "$site_root/components.lock.json"

build_runtime_contract "$bundle_root" "$bundle_root/runtime-contract.yml" "$site_root/manifest.json"
assert_contains "$bundle_root/runtime-contract.yml" 'component_marker_always:' "always-on compose marker test volume"
assert_not_contains "$bundle_root/runtime-contract.yml" 'component_marker_bookstack:' "disabled compose marker test volume"

PATH="$fake_bin:$PATH" "$ROOT_DIR/scripts/deploy/render-runtime.sh" \
  --bundle-root "$bundle_root" \
  --deploy-root "$tmp_root/bundle" \
  --site-manifest "$site_root/manifest.json" \
  --runtime-root "$runtime_root" \
  --skip-compose-validate

caddy_file="$tmp_root/bundle/runtime/configs/caddy/Caddyfile"
keycloak_configure="$tmp_root/bundle/runtime/configs/keycloak/configure-runtime.sh"
runtime_contracts="$tmp_root/bundle/runtime/configs/service-contracts.json"

assert_contains "$caddy_file" 'reverse_proxy keycloak:8080' "core Keycloak route"
assert_contains "$caddy_file" 'reverse_proxy onboarding:8080' "core onboarding route"
assert_contains "$caddy_file" 'webservices core stack' "core apex fallback"
if [ -f "$runtime_contracts" ]; then
  jq -e '.components.core and (.components | has("bookstack") | not)' "$runtime_contracts" >/dev/null
  assert_not_private_mode "$runtime_contracts" "filtered runtime service contracts"
fi

assert_not_contains "$caddy_file" 'reverse_proxy (vaultwarden|grafana|portal:8080|bookstack|matrix-authentication-service|mastodon|jupyterhub|homeassistant|search-service|kopia|progression)' "disabled app Caddy upstream"
assert_not_contains "$keycloak_configure" 'ensure_confidential_client "(bookstack|vaultwarden|matrix|planka|forgejo|mastodon|sogo|jellyfin|donetick|erpnext)' "disabled app Keycloak client"
validate_caddy_file "$caddy_file"

cat > "$site_root/manifest.json" <<'EOF_FULL_MANIFEST'
{
  "site": "component-test",
  "stackConfig": "stack.config.yaml",
  "secretStore": "webservices.sops.json",
  "components": ["full"]
}
EOF_FULL_MANIFEST

component_selection_write_metadata \
  "$site_root/manifest.json" \
  "$bundle_root/stack.config/components.json" \
  "$site_root/components.lock.json"

build_runtime_contract "$bundle_root" "$bundle_root/runtime-contract.full.yml" "$site_root/manifest.json"
assert_contains "$bundle_root/runtime-contract.full.yml" 'component_marker_bookstack:' "enabled runtime contract marker test volume"
cp "$bundle_root/runtime-contract.full.yml" "$bundle_root/runtime-contract.yml"

if [ -f "$bundle_root/stack.systemd/graph.json" ]; then
  "$ROOT_DIR/scripts/deploy/render-systemd-user.sh" \
    --bundle-root "$bundle_root" \
    --output-dir "$bundle_root/systemd-user" \
    --deploy-root-template "%h/webservices" \
    --unit-root-template "%h/webservices/build/systemd-user" \
    --runtime-env-file-template "%h/webservices/runtime/stack.env" >/dev/null

  assert_contains "$bundle_root/systemd-user/webservices.target" 'PropagatesStopTo=webservices-core.target' "core target stop propagation"
  assert_contains "$bundle_root/systemd-user/webservices.target" 'PropagatesStopTo=webservices-apps.target' "apps target stop propagation"
fi

PATH="$fake_bin:$PATH" "$ROOT_DIR/scripts/deploy/render-runtime.sh" \
  --bundle-root "$bundle_root" \
  --deploy-root "$tmp_root/bundle" \
  --site-manifest "$site_root/manifest.json" \
  --runtime-root "$runtime_root" \
  --skip-compose-validate

assert_contains "$caddy_file" 'reverse_proxy vaultwarden:80' "full Vaultwarden route"
assert_contains "$caddy_file" 'reverse_proxy portal:3000' "full Portal route"
assert_contains "$caddy_file" 'redir https://portal' "full Homepage compatibility redirect"
assert_contains "$keycloak_configure" 'ensure_confidential_client "vaultwarden"' "full Vaultwarden Keycloak client"
if [ -f "$runtime_contracts" ]; then
  jq -e '.components.vaultwarden and (.components | has("progression") | not) and (.components | has("huly") | not)' "$runtime_contracts" >/dev/null
  assert_not_private_mode "$runtime_contracts" "filtered runtime service contracts"
fi
assert_not_contains "$caddy_file" 'webservices-component-(start|end)' "component marker"
validate_caddy_file "$caddy_file"

printf '[component-selection-test] ok\n' >&2
