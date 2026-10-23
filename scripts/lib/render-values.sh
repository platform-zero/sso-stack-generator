#!/usr/bin/env bash

# shellcheck source=scripts/lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"
# shellcheck source=scripts/lib/site-manifest.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/site-manifest.sh"

if [ -z "${RENDER_VALUES_INITIALIZED:-}" ]; then
  declare -gA RENDER_VALUES=()
  declare -g RENDER_VALUES_INITIALIZED=1
fi

render_context() {
  printf '%s\n' "${RENDER_CONTEXT:-deploy}"
}

build_caddy_global_options() {
  local context="$1"
  local tls_mode="$2"
  local storage_line=$'\tstorage file_system /certs'
  local venue_https venue_http
  venue_https="$(render_get CADDY_VENUE_HTTPS_PORT)"
  venue_http="$(render_get CADDY_VENUE_HTTP_PORT)"
  if [ -n "$venue_https" ] || [ -n "$venue_http" ]; then
    [ "$tls_mode" = local ] && [[ $venue_https =~ ^[1-9][0-9]{3,4}$ ]] &&
      [[ $venue_http =~ ^[1-9][0-9]{3,4}$ ]] &&
      [ "$venue_https" -ge 1024 ] && [ "$venue_http" -ge 1024 ] &&
      [ "$venue_https" -le 65535 ] && [ "$venue_http" -le 65535 ] &&
      [ "$venue_https" != "$venue_http" ] || die 'unsafe isolated Caddy listener ports or TLS mode'
    printf '\tadmin off\n\tdefault_bind 127.0.0.1\n\thttp_port %s\n\thttps_port %s\n\tauto_https disable_redirects\n\tservers {\n\t\tprotocols h1 h2\n\t}\n' "$venue_http" "$venue_https"
  fi

  case "$tls_mode" in
    local)
      printf '%s\n%s\n' "$storage_line" $'\tlocal_certs'
      ;;
    acme)
      printf '%s\n%s\n%s\n' \
        "$storage_line" \
        $'\temail {$STACK_ADMIN_EMAIL:admin@example.com}' \
        $'\tacme_ca https://acme-v02.api.letsencrypt.org/directory'
      ;;
    *)
      die "unsupported Caddy TLS mode '$tls_mode' for render context '$context'"
      ;;
  esac
}

default_shadow_accounts_host_dir() {
  if [ -n "${XDG_STATE_HOME:-}" ]; then
    printf '%s\n' "$XDG_STATE_HOME/stack/shadow-accounts"
  else
    printf '%s\n' "$HOME/.local/state/stack/shadow-accounts"
  fi
}

default_forgejo_runner_ssh_dir() {
  if [ -n "${XDG_STATE_HOME:-}" ]; then
    printf '%s\n' "$XDG_STATE_HOME/stack/forgejo-runner-ssh"
  else
    printf '%s\n' "$HOME/.local/state/stack/forgejo-runner-ssh"
  fi
}

render_set() {
  local key="$1"
  local value="${2-}"
  render_validate_key "$key"
  RENDER_VALUES["$key"]="$value"
}

render_validate_key() {
  local key="$1"
  [[ "$key" =~ ^[A-Z_][A-Z0-9_]*$ ]] || die "invalid render key: $key"
}

render_get() {
  printf '%s' "${RENDER_VALUES[$1]-}"
}

render_has() {
  [[ -n ${RENDER_VALUES[$1]+x} ]]
}

load_secret_store() {
  local secret_store="$1"
  local decrypted_secret_store
  [[ $- != *x* ]] || die 'secret loading refuses shell tracing'
  [ -f "$secret_store" ] || die "secret store not found: $secret_store"
  require_cmd sops
  require_cmd jq

  decrypted_secret_store="$(mktemp)"
  trap 'rm -f "$decrypted_secret_store"' RETURN
  sops --decrypt "$secret_store" > "$decrypted_secret_store"
  while IFS= read -r -d '' key && IFS= read -r -d '' value; do
    case "$key" in
      CADDY_VENUE_HTTPS_PORT|CADDY_VENUE_HTTP_PORT)
        die 'sealed inputs cannot replace site-owned Caddy listener authority' ;;
    esac
    render_set "$key" "$value"
  done < <(jq -j 'to_entries[] | .key, "\u0000", ((.value // "") | tostring), "\u0000"' "$decrypted_secret_store")
}

render_envsubst() {
  [[ $- != *x* ]] || die 'secret projection refuses shell tracing'
  if [ -n "${RENDER_VALUES[STACK_DERIVATION_KEY]-}" ]; then
    validate_stack_derivation_key || return 1
  fi
  local envsubst_keys="$1"
  local root_reference='\$\{?STACK_DERIVATION_KEY([^A-Z0-9_]|$)'
  [[ ! "$envsubst_keys" =~ $root_reference ]] || die 'derivation key cannot be used in service templates'
  shift
  local keys=("$@")
  (
    local key
    unset STACK_DERIVATION_KEY
    for key in "${keys[@]}"; do
      [ "$key" != STACK_DERIVATION_KEY ] || die 'derivation key cannot be used in service templates'
      render_has "$key" || die "missing template value: $key"
      export "$key=${RENDER_VALUES[$key]}"
    done
    envsubst "$envsubst_keys"
  )
}

load_site_values() {
  local site_config_file="$1"
  local domain admin_email admin_user vaultwarden_org_id

  domain="$(yaml_get_scalar "$site_config_file" 'runtime.domain')"
  admin_email="$(yaml_get_scalar "$site_config_file" 'runtime.admin_email')"
  admin_user="$(yaml_get_scalar "$site_config_file" 'runtime.admin_user')"
  vaultwarden_org_id="$(yaml_get_scalar "$site_config_file" 'vaultwarden.org_id')"

  [ -n "$domain" ] || die "site config is missing runtime.domain in $site_config_file"
  [ -n "$admin_email" ] || die "site config is missing runtime.admin_email in $site_config_file"
  [ -n "$admin_user" ] || die "site config is missing runtime.admin_user in $site_config_file"
  [ -n "$vaultwarden_org_id" ] || die "site config is missing vaultwarden.org_id in $site_config_file"

  render_set DOMAIN "$domain"
  render_set MAIL_DOMAIN "$domain"
  render_set STACK_ADMIN_EMAIL "$admin_email"
  render_set STACK_ADMIN_USER "$admin_user"
  render_set VAULTWARDEN_ORG_NAME "$(yaml_get_scalar "$site_config_file" 'vaultwarden.org_name')"
  render_set VAULTWARDEN_ORG_IDENTIFIER "$(yaml_get_scalar "$site_config_file" 'vaultwarden.org_identifier')"
  render_set VAULTWARDEN_ORG_ID "$vaultwarden_org_id"

  [ -n "$(render_get VAULTWARDEN_ORG_NAME)" ] || render_set VAULTWARDEN_ORG_NAME "Stack"
  [ -n "$(render_get VAULTWARDEN_ORG_IDENTIFIER)" ] || render_set VAULTWARDEN_ORG_IDENTIFIER "$domain"

  render_set VECTOR_DB_ROOT "$(normalize_host_path "$(yaml_get_scalar "$site_config_file" 'storage.vector_dbs')")"
  render_set PG_SSD_ROOT "$(normalize_host_path "$(yaml_get_scalar "$site_config_file" 'storage.pg_ssd_root')")"
  render_set STACK_VOLUME_ROOT "$(normalize_host_path "$(yaml_get_scalar "$site_config_file" 'storage.volume_root')")"
  render_set QBITTORRENT_DATA_ROOT "$(normalize_host_path "$(yaml_get_scalar "$site_config_file" 'storage.custom.qbittorrent_data')")"
  render_set SEAFILE_MEDIA_ROOT "$(normalize_host_path "$(yaml_get_scalar "$site_config_file" 'storage.custom.seafile_media')")"
  render_set JELLYFIN_MEDIA_ROOT "$(normalize_host_path "$(yaml_get_scalar "$site_config_file" 'storage.custom.jellyfin_media')")"
  render_set MEDIA_WRITER_UID "$(yaml_get_scalar "$site_config_file" 'storage.media_writer_uid')"
  render_set MEDIA_WRITER_GID "$(yaml_get_scalar "$site_config_file" 'storage.media_writer_gid')"

  [ -n "$(render_get PG_SSD_ROOT)" ] || render_set PG_SSD_ROOT "/mnt/stack/pg-ssd"
  [ -n "$(render_get STACK_VOLUME_ROOT)" ] || render_set STACK_VOLUME_ROOT "/mnt/stack/volumes"
  [ -n "$(render_get QBITTORRENT_DATA_ROOT)" ] || render_set QBITTORRENT_DATA_ROOT "/mnt/media/qbittorrent"
  [ -n "$(render_get SEAFILE_MEDIA_ROOT)" ] || render_set SEAFILE_MEDIA_ROOT "/mnt/media/seafile-media"
  [ -n "$(render_get JELLYFIN_MEDIA_ROOT)" ] || render_set JELLYFIN_MEDIA_ROOT "/mnt/media/jellyfin-media"
  [ -n "$(render_get MEDIA_WRITER_UID)" ] || render_set MEDIA_WRITER_UID "1000"
  [ -n "$(render_get MEDIA_WRITER_GID)" ] || render_set MEDIA_WRITER_GID "1000"

  local forgejo_runner_ssh_dir
  forgejo_runner_ssh_dir="$(yaml_get_scalar "$site_config_file" 'runtime.forgejo_runner_ssh_dir')"
  if [ -n "$forgejo_runner_ssh_dir" ]; then
    render_set FORGEJO_RUNNER_SSH_DIR "$(normalize_host_path "$forgejo_runner_ssh_dir")"
  fi

  render_set CADDY_IP "$(yaml_get_scalar "$site_config_file" 'runtime.caddy_ip')"
  [ -n "$(render_get CADDY_IP)" ] || render_set CADDY_IP "127.0.0.1"

  render_set CADDY_TLS_MODE "$(yaml_get_scalar "$site_config_file" 'runtime.caddy_tls_mode')"
  [ -n "$(render_get CADDY_TLS_MODE)" ] || render_set CADDY_TLS_MODE "local"
  local venue_prefix venue_https venue_http
  render_set CADDY_VENUE_HTTPS_PORT ''
  render_set CADDY_VENUE_HTTP_PORT ''
  venue_prefix="$(yaml_get_scalar "$site_config_file" 'podman.unit_prefix')"
  venue_https="$(yaml_get_scalar "$site_config_file" 'podman.port_map."443"')"
  venue_http="$(yaml_get_scalar "$site_config_file" 'podman.port_map."80"')"
  if [ "$venue_prefix" = webservices ]; then
    [ -z "$venue_https" ] && [ -z "$venue_http" ] || die 'ordinary native Caddy profile cannot redirect listeners'
  elif [ -n "$venue_prefix" ] || [ -n "$venue_https" ] || [ -n "$venue_http" ]; then
    [[ $venue_prefix =~ ^p0test-[a-z0-9-]{1,24}$ ]] || die 'unreviewed isolated Caddy site namespace'
    render_set CADDY_VENUE_HTTPS_PORT "$venue_https"
    render_set CADDY_VENUE_HTTP_PORT "$venue_http"
  fi
  local log_unit_prefix="${venue_prefix:-webservices}"
  render_set STACK_LOG_UNIT_REGEX "(${log_unit_prefix}[-.][^;]*;.*|[^;]*;${log_unit_prefix}[-.].*)"

  render_set TRUSTED_PROXY_SOURCE_RANGES "$(yaml_get_scalar "$site_config_file" 'runtime.trusted_proxy_source_ranges')"
  render_set LIVEKIT_NODE_IP "$(yaml_get_scalar "$site_config_file" 'runtime.livekit_node_ip')"

  local matrix_authentication_service_active
  matrix_authentication_service_active="$(yaml_get_scalar "$site_config_file" 'matrix_authentication_service.active')"
  if [ -n "$matrix_authentication_service_active" ]; then
    case "$matrix_authentication_service_active" in
      true|false)
        render_set MATRIX_AUTHENTICATION_SERVICE_ACTIVE "$matrix_authentication_service_active"
        ;;
      *)
        die "site config matrix_authentication_service.active must be true or false"
        ;;
    esac
  fi
}

compute_ssha() {
  local password="$1"
  printf '%s' "$password" | python3 -c "
import base64, hashlib, os, sys
password = sys.stdin.buffer.read()
salt = os.urandom(4)
digest = hashlib.sha1(password + salt).digest() + salt
print('{SSHA}' + base64.b64encode(digest).decode())
"
}

# STACK_DERIVATION_KEY is a separately generated 256-bit key, encoded as
# 64 hex characters in the encrypted root-only input. Never use a service,
# OAuth client, or owner password as the key. See docs/secret-derivation.md.
validate_stack_derivation_key() {
  [[ $- != *x* ]] || die 'secret derivation refuses shell tracing'
  local root_key="${RENDER_VALUES[STACK_DERIVATION_KEY]-}"
  local key value
  [[ "$root_key" =~ ^[A-Fa-f0-9]{64}$ ]] ||
    die 'missing or invalid independent STACK_DERIVATION_KEY (expected 64 hex characters)'
  # Catch direct key reuse even with all-explicit credentials; independence of
  # the provisioning source itself remains an installer/operator requirement.
  for key in "${!RENDER_VALUES[@]}"; do
    [ "$key" != STACK_DERIVATION_KEY ] || continue
    value="${RENDER_VALUES[$key]}"
    if [ "$value" = "$root_key" ] || {
        [[ "$value" =~ ^[A-Fa-f0-9]{64}$ ]] && [ "${value,,}" = "${root_key,,}" ]; }; then
      die 'STACK_DERIVATION_KEY must not be reused as a service value'
    fi
  done
}

derive_stack_secret() {
  validate_stack_derivation_key || return 1
  local label="$1"
  local length="${2:-48}"
  local domain="${RENDER_VALUES[DOMAIN]-}"
  [ -n "$domain" ] && [ -n "$label" ] || die 'secret derivation requires domain and label'
  [[ "$length" =~ ^([1-9]|[1-5][0-9]|6[0-4])$ ]] || die 'invalid derived secret length (expected 1..64)'

  # Key material travels only over stdin, never argv or the environment.
  # NUL framing prevents label/domain boundary ambiguity. The version is part
  # of the HMAC message; changing it is a credential rotation, not a refactor.
  printf '%s\0%s\0%s\0%s' "${RENDER_VALUES[STACK_DERIVATION_KEY]}" "$domain" "$label" "$length" |
    python3 -c 'import hashlib, hmac, sys
key, domain, label, length = sys.stdin.buffer.read().split(b"\0")
message = b"webservices/secret-derivation/v1\0" + domain + b"\0" + label
print(hmac.new(bytes.fromhex(key.decode("ascii")), message, hashlib.sha256).hexdigest()[:int(length)])'
}

derive_if_missing() {
  local key="$1"
  local label="$2"
  local length="${3:-48}"
  local derived
  if ! render_has "$key" || [ -z "$(render_get "$key")" ]; then
    derived="$(derive_stack_secret "$label" "$length")" || return 1
    render_set "$key" "$derived"
  fi
}

derive_laravel_app_key_if_missing() {
  local key="$1"
  local label="$2"
  local current="${RENDER_VALUES[$key]-}"
  local derived encoded
  if [ -n "$current" ]; then
    printf '%s' "$current" | grep -Eq '^base64:[A-Za-z0-9+/]{43}=?$' ||
      die 'invalid explicit Laravel app key; refusing credential replacement'
    return 0
  fi
  derived="$(derive_stack_secret "$label" 64)" || return 1
  encoded="$(printf '%s' "$derived" | python3 -c 'import base64, sys; print(base64.b64encode(bytes.fromhex(sys.stdin.read())).decode().rstrip("="))')" || return 1
  render_set "$key" "base64:$encoded"
}

derive_policy_secret() {
  local label="$1"
  local length="${2:-32}"
  local derived
  [[ "$length" =~ ^(1[6-9]|[2-5][0-9]|6[0-4])$ ]] || die 'invalid policy secret length (expected 16..64)'
  derived="$(derive_stack_secret "$label" "$((length - 4))")" || return 1
  printf 'Aa1!%s' "$derived"
}

derive_fernet_key_if_missing() {
  local derived encoded
  if ! render_has AIRFLOW_FERNET_KEY || [ -z "$(render_get AIRFLOW_FERNET_KEY)" ]; then
    derived="$(derive_stack_secret airflow-fernet 64)" || return 1
    encoded="$(printf '%s' "$derived" | python3 -c 'import base64, sys; print(base64.urlsafe_b64encode(bytes.fromhex(sys.stdin.read())).decode())')" || return 1
    render_set AIRFLOW_FERNET_KEY "$encoded"
  fi
}

opensearch_password_is_valid() {
  local value="$1"
  [[ "$value" =~ [A-Z] ]] && [[ "$value" =~ [a-z] ]] && [[ "$value" =~ [0-9] ]] && [[ "$value" =~ [^A-Za-z0-9] ]] && [ "${#value}" -ge 8 ]
}

build_derived_render_values() {
  [[ $- != *x* ]] || die 'secret derivation refuses shell tracing'
  if [ -n "${RENDER_VALUES[STACK_DERIVATION_KEY]-}" ]; then
    validate_stack_derivation_key || return 1
  fi
  render_set GENERATION_TIMESTAMP "$(iso_timestamp_utc)"
  render_set BASE_URL "https://$(render_get DOMAIN)"
  render_set CADDY_GLOBAL_OPTIONS "$(build_caddy_global_options "$(render_context)" "$(render_get CADDY_TLS_MODE)")"
  if ! render_has SHADOW_ACCOUNTS_HOST_DIR || [ -z "$(render_get SHADOW_ACCOUNTS_HOST_DIR)" ]; then
    render_set SHADOW_ACCOUNTS_HOST_DIR "$(default_shadow_accounts_host_dir)"
  fi
  if [ -n "$(render_get CADDY_VENUE_HTTPS_PORT)" ] || {
      [ -n "${BUNDLE_ROOT:-}" ] && [ -f "$BUNDLE_ROOT/podman-domains.json" ] &&
      [ "$(jq -r '.deploymentMode // ""' "$BUNDLE_ROOT/podman-domains.json")" = standalone ]; }; then
    [ -n "${BUNDLE_ROOT:-}" ] || die "selected CI SSH directory requires bound bundle authority"
    local venue_ci_state venue_ci_path explicit_ci_path
    venue_ci_state="$(jq -er '[.domains[] | select(.name == "ci-runner")] | if length == 1 then .[0].stateRoot else error("CI domain") end' "$BUNDLE_ROOT/podman-domains.json")"
    venue_ci_path="$venue_ci_state/forgejo-runner-ssh"
    explicit_ci_path="$(yaml_get_scalar "$site_config_file" 'runtime.forgejo_runner_ssh_dir')"
    [ -z "$explicit_ci_path" ] || [ "$(normalize_host_path "$explicit_ci_path")" = "$venue_ci_path" ] ||
      die "selected CI SSH directory conflicts with explicit site authority"
    # This is a generated HOST PATH, not a credential. The unchanged older
    # sealed tuple may contain a legacy host path: never materialize/chmod it.
    render_set FORGEJO_RUNNER_SSH_DIR "$venue_ci_path"
  elif ! render_has FORGEJO_RUNNER_SSH_DIR || [ -z "$(render_get FORGEJO_RUNNER_SSH_DIR)" ]; then
    render_set FORGEJO_RUNNER_SSH_DIR "$(default_forgejo_runner_ssh_dir)"
  fi
  render_set SYSTEMD_USER_UID "$(id -u)"
  render_set SYSTEMD_USER_GID "$(id -g)"
  render_set SYSTEMD_USER_RUNTIME_DIR "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
  render_set STACK_RUNTIME_DIR "${STACK_RUNTIME_DIR:-${WEBSERVICES_RUNTIME_TARGET:-${XDG_STATE_HOME:-$HOME/.local/state}/webservices/runtime}}"
  if ! render_has PLAYWRIGHT_IGNORE_HTTPS_ERRORS || [ -z "$(render_get PLAYWRIGHT_IGNORE_HTTPS_ERRORS)" ]; then
    render_set PLAYWRIGHT_IGNORE_HTTPS_ERRORS "false"
  fi
  derive_if_missing MODEL_CONTEXT_PROXY_AUTH_SECRET model-context-proxy-auth 64 || return 1
  if ! render_has ADMIN_SSHA_PASSWORD || [ -z "$(render_get ADMIN_SSHA_PASSWORD)" ]; then
    [ -n "$(render_get STACK_ADMIN_PASSWORD)" ] ||
      die 'STACK_ADMIN_PASSWORD or explicit ADMIN_SSHA_PASSWORD is required; refusing an empty owner password'
    local admin_ssha
    admin_ssha="$(compute_ssha "$(render_get STACK_ADMIN_PASSWORD)")" || return 1
    render_set ADMIN_SSHA_PASSWORD "$admin_ssha"
  fi
  if ! render_has POSTGRES_ADMIN_USER || [ -z "$(render_get POSTGRES_ADMIN_USER)" ]; then
    render_set POSTGRES_ADMIN_USER "webservices"
  fi
  derive_if_missing KEYCLOAK_ADMIN_PASSWORD keycloak-admin 48 || return 1
  derive_if_missing POSTGRES_ADMIN_PASSWORD postgres-admin 48 || return 1
  derive_if_missing POSTGRES_GRAFANA_PASSWORD postgres-grafana 48 || return 1
  derive_if_missing POSTGRES_PLANKA_PASSWORD postgres-planka 48 || return 1
  derive_if_missing POSTGRES_SYNAPSE_PASSWORD postgres-synapse 48 || return 1
  derive_if_missing POSTGRES_VAULTWARDEN_PASSWORD postgres-vaultwarden 48 || return 1
  derive_if_missing POSTGRES_HOMEASSISTANT_PASSWORD postgres-homeassistant 48 || return 1
  derive_if_missing POSTGRES_AGENT_PASSWORD postgres-agent 48 || return 1
  derive_if_missing POSTGRES_TXGATEWAY_PASSWORD postgres-txgateway 48 || return 1
  derive_if_missing POSTGRES_FORGEJO_PASSWORD postgres-forgejo 48 || return 1
  derive_if_missing POSTGRES_OPENWEBUI_PASSWORD postgres-openwebui 48 || return 1
  derive_if_missing POSTGRES_MASTODON_PASSWORD postgres-mastodon 48 || return 1
  derive_if_missing POSTGRES_PIPELINE_PASSWORD postgres-pipeline 48 || return 1
  derive_if_missing POSTGRES_AIRFLOW_PASSWORD postgres-airflow 48 || return 1
  derive_if_missing POSTGRES_TEST_RUNNER_PASSWORD postgres-test-runner 48 || return 1
  derive_if_missing POSTGRES_LEGAL_RESEARCH_PASSWORD postgres-legal-research 48 || return 1
  derive_if_missing LEGAL_RESEARCH_INGESTION_TOKEN legal-research-ingestion-token 48 || return 1
  derive_if_missing MARIADB_ADMIN_PASSWORD mariadb-admin 48 || return 1
  derive_if_missing MARIADB_BOOKSTACK_PASSWORD mariadb-bookstack 48 || return 1
  derive_if_missing MARIADB_SEAFILE_PASSWORD mariadb-seafile 48 || return 1
  derive_if_missing MARIADB_AGENT_PASSWORD mariadb-agent 48 || return 1
  derive_if_missing VALKEY_ADMIN_PASSWORD valkey-admin 48 || return 1
  derive_if_missing VALKEY_SEAFILE_PASSWORD valkey-seafile 48 || return 1
  derive_if_missing VALKEY_MASTODON_PASSWORD valkey-mastodon 48 || return 1
  derive_if_missing OAUTH2_PROXY_CLIENT_SECRET oauth2-proxy-client 48 || return 1
  derive_if_missing OAUTH2_PROXY_COOKIE_SECRET oauth2-proxy-cookie 32 || return 1
  derive_laravel_app_key_if_missing BOOKSTACK_APP_KEY bookstack-app-key || return 1
  derive_if_missing BOOKSTACK_OAUTH_SECRET bookstack-oauth 48 || return 1
  derive_if_missing HULY_OPENID_CLIENT_SECRET huly-openid 48 || return 1
  derive_if_missing FORGEJO_OAUTH_SECRET forgejo-oauth 48 || return 1
  derive_if_missing MASTODON_OAUTH_SECRET mastodon-oauth 48 || return 1
  derive_if_missing MASTODON_SECRET_KEY_BASE mastodon-secret-key-base 64 || return 1
  derive_if_missing MASTODON_OTP_SECRET mastodon-otp-secret 64 || return 1
  derive_if_missing MASTODON_ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY mastodon-active-record-deterministic 64 || return 1
  derive_if_missing MASTODON_ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT mastodon-active-record-salt 64 || return 1
  derive_if_missing MASTODON_ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY mastodon-active-record-primary 64 || return 1
  derive_if_missing MATRIX_OAUTH_SECRET matrix-oauth 48 || return 1
  derive_if_missing PLANKA_OAUTH_SECRET planka-oauth 48 || return 1
  derive_if_missing TEST_RUNNER_OAUTH_SECRET test-runner-oauth 48 || return 1
  derive_if_missing VAULTWARDEN_OAUTH_SECRET vaultwarden-oauth 48 || return 1
  derive_if_missing QDRANT_ADMIN_API_KEY qdrant-admin-api 48 || return 1
  derive_if_missing NATS_PASSWORD nats 48 || return 1
  if ! render_has OPENSEARCH_ADMIN_PASSWORD || [ -z "$(render_get OPENSEARCH_ADMIN_PASSWORD)" ]; then
    local opensearch_password
    opensearch_password="$(derive_policy_secret opensearch-admin 32)" || return 1
    render_set OPENSEARCH_ADMIN_PASSWORD "$opensearch_password"
  elif ! opensearch_password_is_valid "$(render_get OPENSEARCH_ADMIN_PASSWORD)"; then
    die 'invalid explicit OpenSearch password; refusing credential replacement'
  fi
  derive_if_missing LIVEKIT_API_KEY livekit-api-key 24 || return 1
  derive_if_missing LIVEKIT_API_SECRET livekit-api-secret 48 || return 1
  derive_if_missing ONLYOFFICE_JWT_SECRET onlyoffice-jwt 48 || return 1
  derive_if_missing SEAFILE_EMAIL_PASSWORD seafile-email 48 || return 1
  derive_if_missing SEAFILE_SECRET_KEY seafile-secret 48 || return 1
  derive_if_missing KOPIA_PASSWORD kopia-password 64 || return 1
  derive_if_missing NTFY_SSO_PASSWORD ntfy-sso 48 || return 1
  render_set NTFY_SSO_AUTHORIZATION "Basic $(printf 'ntfy-sso:%s' "$(render_get NTFY_SSO_PASSWORD)" | base64 | tr -d '\n')"
  derive_if_missing NTFY_NATIVE_CLIENT_SECRET ntfy-native-client 48 || return 1
  derive_if_missing NTFY_NATIVE_GATEWAY_SECRET ntfy-native-gateway 48 || return 1
  render_set NTFY_PUBLISHER_AUTHORIZATION "Basic $(printf '%s:%s' "$(render_get NTFY_USERNAME)" "$(render_get NTFY_PASSWORD)" | base64 | tr -d '\n')"
  if ! render_has KOPIA_SERVER_USERNAME || [ -z "$(render_get KOPIA_SERVER_USERNAME)" ]; then
    render_set KOPIA_SERVER_USERNAME "kopia"
  fi
  if ! render_has KOPIA_PROXY_AUTHORIZATION || [ -z "$(render_get KOPIA_PROXY_AUTHORIZATION)" ]; then
    render_set KOPIA_PROXY_AUTHORIZATION "Basic $(printf '%s:%s' "$(render_get KOPIA_SERVER_USERNAME)" "$(render_get KOPIA_PASSWORD)" | base64 | tr -d '\n')"
  fi
  derive_if_missing SYNAPSE_FORM_SECRET synapse-form 48 || return 1
  derive_if_missing SYNAPSE_MACAROON_SECRET synapse-macaroon 48 || return 1
  derive_if_missing SYNAPSE_REGISTRATION_SECRET synapse-registration 48 || return 1
  derive_if_missing SOGO_DB_PASSWORD sogo-db 48 || return 1
  derive_if_missing SOGO_OAUTH_SECRET sogo-oauth 48 || return 1
  derive_if_missing JELLYFIN_OIDC_SECRET jellyfin-oidc 48 || return 1
  derive_if_missing DONETICK_JWT_SECRET donetick-jwt 48 || return 1
  derive_if_missing DONETICK_OAUTH_SECRET donetick-oauth 48 || return 1
  if ! render_has NATS_USER || [ -z "$(render_get NATS_USER)" ]; then
    render_set NATS_USER "webservices"
  fi
  if ! render_has AIRFLOW_ADMIN_USERNAME || [ -z "$(render_get AIRFLOW_ADMIN_USERNAME)" ]; then
    render_set AIRFLOW_ADMIN_USERNAME "admin"
  fi
  derive_if_missing AIRFLOW_ADMIN_PASSWORD airflow-admin 48 || return 1
  derive_fernet_key_if_missing || return 1
  derive_if_missing AIRFLOW_WEBSERVER_SECRET_KEY airflow-webserver 64 || return 1
  derive_if_missing MONITORING_API_KEY monitoring-api 64 || return 1
  derive_if_missing MASTODON_API_TOKEN mastodon-api-token 64 || return 1
  render_set OPENSEARCH_BASIC_AUTH "$(printf 'admin:%s' "$(render_get OPENSEARCH_ADMIN_PASSWORD)" | base64 | tr -d '\n')"
  derive_if_missing ONBOARDING_TRUSTED_PROXY_SECRET onboarding-trusted-proxy 64 || return 1
  derive_if_missing BOOKSTACK_INTERNAL_API_TOKEN bookstack-internal-api 64 || return 1
  derive_if_missing HOMEASSISTANT_TRUSTED_PROXY_SECRET homeassistant-trusted-proxy 64 || return 1
  derive_if_missing INFERENCE_CONTROLLER_API_TOKEN inference-controller-api 64 || return 1
  derive_if_missing GPU_ARBITER_API_TOKEN gpu-arbiter-api 64 || return 1
  derive_if_missing ERPNEXT_OAUTH_SECRET erpnext-oauth 48 || return 1
  derive_if_missing POSTGRES_MATRIX_AUTHENTICATION_SERVICE_PASSWORD matrix-authentication-service-db 48 || return 1
  if ! render_has MATRIX_AUTHENTICATION_SERVICE_ACTIVE || [ -z "$(render_get MATRIX_AUTHENTICATION_SERVICE_ACTIVE)" ]; then
    render_set MATRIX_AUTHENTICATION_SERVICE_ACTIVE "false"
  fi
  if ! render_has MATRIX_AUTHENTICATION_SERVICE_UPSTREAM_PROVIDER_ID || [ -z "$(render_get MATRIX_AUTHENTICATION_SERVICE_UPSTREAM_PROVIDER_ID)" ]; then
    render_set MATRIX_AUTHENTICATION_SERVICE_UPSTREAM_PROVIDER_ID "01JY9K7VKQ23V93TP9FB9VYQVM"
  fi
  derive_if_missing MATRIX_AUTHENTICATION_SERVICE_SHARED_SECRET matrix-authentication-service-shared 64 || return 1
  derive_if_missing MATRIX_AUTHENTICATION_SERVICE_ENCRYPTION_SECRET matrix-authentication-service-encryption 64 || return 1
  derive_if_missing MATRIX_AUTHENTICATION_SERVICE_OAUTH_SECRET matrix-authentication-service-oauth 48 || return 1
  if [ "$(render_get MATRIX_AUTHENTICATION_SERVICE_ACTIVE)" = "true" ]; then
    render_set SYNAPSE_LEGACY_SSO_CONFIG ""
    local domain
    domain="$(render_get DOMAIN)"
    render_set MATRIX_CADDY_AUTH_ROUTES "$(cat <<EOF
	@matrix_client_well_known path /.well-known/matrix/client
	handle @matrix_client_well_known {
		header Content-Type application/json
		header Access-Control-Allow-Origin "*"
		header Access-Control-Allow-Methods "GET, OPTIONS"
		header Access-Control-Allow-Headers "X-Requested-With, Content-Type, Authorization"
		respond "{\"m.homeserver\":{\"base_url\":\"https://matrix.${domain}/\"},\"org.matrix.msc2965.authentication\":{\"issuer\":\"https://matrix-auth.${domain}/\",\"account\":\"https://matrix-auth.${domain}/account\"},\"io.element.e2ee\":{\"default\":true},\"org.matrix.msc4143.rtc_foci\":[{\"type\":\"livekit\",\"livekit_service_url\":\"https://matrix-rtc.${domain}/livekit/jwt\"}]}" 200
	}

	@matrix_mas_auth_metadata path /_matrix/client/v1/auth_metadata /_matrix/client/unstable/org.matrix.msc2965/auth_metadata
	handle @matrix_mas_auth_metadata {
		rewrite * /.well-known/openid-configuration
		reverse_proxy matrix-authentication-service:8080
	}

	@matrix_mas_compat path /_matrix/client/v3/login /_matrix/client/v3/login/* /_matrix/client/v3/logout /_matrix/client/v3/refresh /_matrix/client/r0/login /_matrix/client/r0/login/* /_matrix/client/r0/logout /_matrix/client/r0/refresh
	handle @matrix_mas_compat {
		reverse_proxy matrix-authentication-service:8080
	}
EOF
)"
  else
    local domain matrix_oauth_secret
    domain="$(render_get DOMAIN)"
    matrix_oauth_secret="$(render_get MATRIX_OAUTH_SECRET)"
    render_set MATRIX_CADDY_AUTH_ROUTES "$(cat <<EOF
	@matrix_client_well_known path /.well-known/matrix/client
	handle @matrix_client_well_known {
		header Content-Type application/json
		header Access-Control-Allow-Origin "*"
		header Access-Control-Allow-Methods "GET, OPTIONS"
		header Access-Control-Allow-Headers "X-Requested-With, Content-Type, Authorization"
		respond "{\"m.homeserver\":{\"base_url\":\"https://matrix.${domain}/\"},\"io.element.e2ee\":{\"default\":true},\"org.matrix.msc4143.rtc_foci\":[{\"type\":\"livekit\",\"livekit_service_url\":\"https://matrix-rtc.${domain}/livekit/jwt\"}]}" 200
	}
EOF
)"
    render_set SYNAPSE_LEGACY_SSO_CONFIG "$(cat <<EOF
oidc_providers:
  - idp_id: keycloak
    idp_name: "Keycloak SSO"
    idp_brand: "keycloak"
    discover: false
    skip_verification: true
    issuer: "https://keycloak.${domain}/realms/webservices"
    client_id: "matrix"
    client_secret: "${matrix_oauth_secret}"
    client_auth_method: "client_secret_post"
    scopes:
      - "openid"
      - "profile"
      - "email"
    authorization_endpoint: "https://keycloak.${domain}/realms/webservices/protocol/openid-connect/auth"
    token_endpoint: "http://keycloak:8080/realms/webservices/protocol/openid-connect/token"
    userinfo_endpoint: "http://keycloak:8080/realms/webservices/protocol/openid-connect/userinfo"
    user_profile_method: "userinfo_endpoint"
    jwks_uri: "http://keycloak:8080/realms/webservices/protocol/openid-connect/certs"
    user_mapping_provider:
      config:
        localpart_template: '{{ user.preferred_username|default(user.sub, true)|lower }}'
        display_name_template: '{{ user.name }}'
        email_template: '{{ user.email }}'
    allow_existing_users: true
    backchannel_logout_enabled: false

sso:
  client_whitelist:
    - "https://element.${domain}"
    - "https://element.${domain}/"
  update_profile_information: true
EOF
)"
  fi
}

write_env_file() {
  [[ $- != *x* ]] || die 'secret projection refuses shell tracing'
  if [ -n "${RENDER_VALUES[STACK_DERIVATION_KEY]-}" ]; then
    validate_stack_derivation_key || return 1
  fi
  local output_path="$1"
  shift
  local keys=("$@")
  if [ "${#keys[@]}" -eq 0 ]; then
    mapfile -t keys < <(printf '%s\n' "${!RENDER_VALUES[@]}" | sort)
  fi

  {
    printf '# Stack Environment Variables\n'
    printf '# Generated: %s\n' "$(iso_timestamp_utc)"
    printf '# DO NOT COMMIT THIS FILE\n'
    printf '# Generated from site manifest SOPS runtime store\n\n'

    local key value
    for key in "${keys[@]}"; do
      render_validate_key "$key"
      # Even the all-values/debug path must never project the root key.
      [ "$key" != STACK_DERIVATION_KEY ] || continue
      render_has "$key" || continue
      value="${RENDER_VALUES[$key]}"
      if [[ "$value" == *$'\n'* ]]; then
        printf '# %s: (multiline value rendered into runtime/configs/)\n' "$key"
        continue
      fi
      value="${value//\$/\$\$}"
      printf '%s=%s\n' "$key" "$value"
    done
  } > "$output_path"
  chmod 600 "$output_path"
}

collect_runtime_env_keys() {
  local runtime_configs_root="$1"
  shift
  local search_root
  {
    for search_root in "$@"; do
      if [ -d "$search_root" ]; then
        find "$search_root" -type f -print0 | xargs -0 -r grep -hoE '\$\{[A-Z_][A-Z0-9_]*([^}]*)\}' || true
      elif [ -f "$search_root" ]; then
        grep -hoE '\$\{[A-Z_][A-Z0-9_]*([^}]*)\}' "$search_root" || true
      fi
    done
    if [ -d "$runtime_configs_root" ]; then
      find "$runtime_configs_root" -type f -print0 | xargs -0 -r grep -hoE '\$\{[A-Z_][A-Z0-9_]*([^}]*)\}' || true
    fi
  } | sed -E 's/^\$\{([A-Z_][A-Z0-9_]*).*$/\1/' | sort -u
}

write_build_info() {
  local build_info_source="$1"
  local output_path="$2"
  local source_json site_name domain tls_mode rendered_at rendered_by

  source_json="$(cat "$build_info_source")"
  site_name="$(render_get SITE_NAME)"
  domain="$(render_get DOMAIN)"
  tls_mode="$(render_get CADDY_TLS_MODE)"
  rendered_at="$(iso_timestamp_utc)"
  rendered_by="${USER:-unknown}"

  jq \
    --arg renderedAt "$rendered_at" \
    --arg renderedBy "$rendered_by" \
    --arg siteName "$site_name" \
    --arg domain "$domain" \
    --arg publicUrl "https://$domain" \
    --arg tlsMode "$tls_mode" \
    '. + {
      renderedAt: $renderedAt,
      renderedBy: $renderedBy,
      siteName: $siteName,
      domain: $domain,
      publicUrl: $publicUrl,
      tlsMode: $tlsMode
    }' < "$build_info_source" > "$output_path"
}
