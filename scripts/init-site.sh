#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT_DIR/scripts/lib/common.sh"
# shellcheck source=scripts/lib/components.sh
source "$ROOT_DIR/scripts/lib/components.sh"

CREATE_GITHUB=0
TARGET_DIR=""
GENERATOR_REMOTE=""
COMPONENTS=""
SOPS_AGE_RECIPIENT=""

usage() {
  cat <<'EOF_USAGE'
Usage:
  ./scripts/init-site.sh [--github] [--generator-remote <url>] [--components <ids>] [--sops-age-recipient <recipient>] <site-repo-dir>

Creates a Git-backed site repo containing manifest.json, stack.config.yaml,
encrypted webservices.sops.json, a generator pin, and stack-update.sh.
EOF_USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --github)
      CREATE_GITHUB=1
      ;;
    --generator-remote)
      [ "$#" -ge 2 ] || die "--generator-remote requires a value"
      GENERATOR_REMOTE="$2"
      shift
      ;;
    --components)
      [ "$#" -ge 2 ] || die "--components requires a value"
      COMPONENTS="$2"
      shift
      ;;
    --sops-age-recipient)
      [ "$#" -ge 2 ] || die "--sops-age-recipient requires a value"
      SOPS_AGE_RECIPIENT="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      [ -z "$TARGET_DIR" ] || die "unexpected argument: $1"
      TARGET_DIR="$1"
      ;;
  esac
  shift
done

require_cmd git
require_cmd jq
require_cmd openssl
require_cmd sops

if [ -z "$TARGET_DIR" ]; then
  printf 'Site repo directory: ' >&2
  read -r TARGET_DIR
fi
[ -n "$TARGET_DIR" ] || die "missing site repo directory"

prompt_default() {
  local label="$1"
  local default="$2"
  local value
  printf '%s [%s]: ' "$label" "$default" >&2
  read -r value
  printf '%s\n' "${value:-$default}"
}

random_secret() {
  openssl rand -base64 "${1:-36}" | tr -d '\n'
}

json_pair() {
  local key="$1"
  local value="$2"
  local prefix="$3"
  printf '%s  "%s": "%s"' "$prefix" "$key" "$value"
}

write_secret_json() {
  local output="$1"
  local stack_admin_password="$2"
  local key prefix
  local keys=(
    STACK_ADMIN_PASSWORD
    KEYCLOAK_ADMIN_PASSWORD
    OAUTH2_PROXY_CLIENT_SECRET
    OAUTH2_PROXY_COOKIE_SECRET
    POSTGRES_ADMIN_PASSWORD
    POSTGRES_KEYCLOAK_PASSWORD
    POSTGRES_GRAFANA_PASSWORD
    POSTGRES_PLANKA_PASSWORD
    POSTGRES_SYNAPSE_PASSWORD
    POSTGRES_MATRIX_AUTHENTICATION_SERVICE_PASSWORD
    POSTGRES_VAULTWARDEN_PASSWORD
    POSTGRES_HOMEASSISTANT_PASSWORD
    POSTGRES_AGENT_PASSWORD
    POSTGRES_TXGATEWAY_PASSWORD
    POSTGRES_FORGEJO_PASSWORD
    POSTGRES_OPENWEBUI_PASSWORD
    POSTGRES_MASTODON_PASSWORD
    POSTGRES_PIPELINE_PASSWORD
    POSTGRES_AIRFLOW_PASSWORD
    POSTGRES_TEST_RUNNER_PASSWORD
    MARIADB_ADMIN_PASSWORD
    MARIADB_BOOKSTACK_PASSWORD
    MARIADB_SEAFILE_PASSWORD
    MARIADB_AGENT_PASSWORD
    VALKEY_ADMIN_PASSWORD
    VALKEY_SEAFILE_PASSWORD
    VALKEY_MASTODON_PASSWORD
    QDRANT_ADMIN_API_KEY
    NATS_PASSWORD
    OPENSEARCH_ADMIN_PASSWORD
    AIRFLOW_ADMIN_PASSWORD
    AIRFLOW_FERNET_KEY
    AIRFLOW_WEBSERVER_SECRET_KEY
    BOOKSTACK_OAUTH_SECRET
    BOOKSTACK_API_TOKEN_ID
    BOOKSTACK_API_TOKEN_SECRET
    SOGO_OAUTH_SECRET
    JELLYFIN_OIDC_SECRET
    DONETICK_JWT_SECRET
    DONETICK_OAUTH_SECRET
    ERPNEXT_OAUTH_SECRET
    FORGEJO_OAUTH_SECRET
    MASTODON_OAUTH_SECRET
    MATRIX_OAUTH_SECRET
    PLANKA_OAUTH_SECRET
    VAULTWARDEN_OAUTH_SECRET
    TEST_RUNNER_OAUTH_SECRET
    LIVEKIT_API_KEY
    LIVEKIT_API_SECRET
    ONLYOFFICE_JWT_SECRET
    SEAFILE_EMAIL_PASSWORD
    SEAFILE_SECRET_KEY
    SYNAPSE_FORM_SECRET
    SYNAPSE_MACAROON_SECRET
    SYNAPSE_REGISTRATION_SECRET
    KOPIA_PASSWORD
    KOPIA_PROXY_AUTHORIZATION
    NTFY_USERNAME
    NTFY_PASSWORD
    FORGEJO_RUNNER_TOKEN
    MASTODON_SECRET_KEY_BASE
    MASTODON_OTP_SECRET
    MASTODON_VAPID_PRIVATE_KEY
    MASTODON_VAPID_PUBLIC_KEY
    MASTODON_ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY
    MASTODON_ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT
    MASTODON_ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY
    MASTODON_SMTP_PASSWORD
    CHATGPT_CONNECTOR_KEYCLOAK_ADMIN_CLIENT_SECRET
  )

  {
    printf '{\n'
    prefix=""
    json_pair "POSTGRES_ADMIN_USER" "webservices" "$prefix"
    prefix=$',\n'
    json_pair "KEYCLOAK_ADMIN_USER" "admin" "$prefix"
    json_pair "STACK_ADMIN_PASSWORD" "$stack_admin_password" $',\n'
    for key in "${keys[@]}"; do
      [ "$key" = "STACK_ADMIN_PASSWORD" ] && continue
      json_pair "$key" "$(random_secret 36)" $',\n'
    done
    printf '\n}\n'
  } > "$output"
}

catalog="$ROOT_DIR/stack.config/components.json"
component_catalog_validate "$catalog"

site_name_default="$(basename "$TARGET_DIR")"
site_name="$(prompt_default "Site name" "$site_name_default")"
domain="$(prompt_default "Primary domain" "example.test")"
admin_user="$(prompt_default "Admin username" "admin")"
admin_email="$(prompt_default "Admin email" "admin@$domain")"
tls_mode="$(prompt_default "Caddy TLS mode (local/acme)" "local")"

if [ -z "$COMPONENTS" ]; then
  printf 'Available components: %s\n' "$(jq -r '.components | keys_unsorted | join(", ")' "$catalog")" >&2
  COMPONENTS="$(prompt_default "Components" "core")"
fi

if [ -z "$SOPS_AGE_RECIPIENT" ] && [ -z "${SOPS_AGE_RECIPIENTS:-}" ] && [ -z "${SOPS_PGP_FP:-}" ]; then
  SOPS_AGE_RECIPIENT="$(prompt_default "SOPS age recipient (blank to use existing SOPS config)" "")"
fi

case "$tls_mode" in
  local|acme) ;;
  *) die "unsupported TLS mode: $tls_mode" ;;
esac

target_dir="$(mkdir -p "$TARGET_DIR" && cd "$TARGET_DIR" && pwd -P)"
if [ -n "$(find "$target_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]; then
  die "target directory is not empty: $target_dir"
fi

if [ -n "$SOPS_AGE_RECIPIENT" ]; then
  cat > "$target_dir/.sops.yaml" <<EOF_SOPS_CONFIG
creation_rules:
  - path_regex: webservices\\.sops\\.json$
    age: "$SOPS_AGE_RECIPIENT"
EOF_SOPS_CONFIG
fi

if [ -z "$GENERATOR_REMOTE" ]; then
  GENERATOR_REMOTE="$(git -C "$ROOT_DIR" config --get remote.origin.url || true)"
fi
[ -n "$GENERATOR_REMOTE" ] || GENERATOR_REMOTE="$ROOT_DIR"
generator_ref="$(git -C "$ROOT_DIR" symbolic-ref --quiet --short HEAD || printf 'HEAD')"
generator_commit="$(git -C "$ROOT_DIR" rev-parse HEAD)"
generator_upstream_remote="$(git -C "$ROOT_DIR" config --get remote.upstream.url || true)"
generator_upstream_ref="$(git -C "$ROOT_DIR" config --get webservices.upstreamRef || printf 'main')"

component_json="$(printf '%s\n' "$COMPONENTS" | tr ',' '\n' | awk '{$1=$1; print}' | jq -R 'select(length > 0)' | jq -s '.')"

cat > "$target_dir/manifest.json" <<EOF_MANIFEST
{
  "site": "$site_name",
  "stackConfig": "stack.config.yaml",
  "secretStore": "webservices.sops.json",
  "components": $component_json
}
EOF_MANIFEST

component_selection_resolve "$target_dir/manifest.json" "$catalog" >/dev/null

vaultwarden_org_id="$(uuidgen 2>/dev/null || openssl rand -hex 16)"
cat > "$target_dir/stack.config.yaml" <<EOF_CONFIG
runtime:
  domain: "$domain"
  admin_email: "$admin_email"
  admin_user: "$admin_user"
  caddy_tls_mode: "$tls_mode"

storage:
  volume_root: "/mnt/stack/volumes"
  vector_dbs: "/mnt/stack/vector-dbs"
  pg_ssd_root: "/mnt/stack/pg-ssd"
  media_writer_uid: "1000"
  media_writer_gid: "1000"
  custom:
    qbittorrent_data: "/mnt/media/qbittorrent"
    seafile_media: "/mnt/media/seafile-media"
    jellyfin_media: "/mnt/media/jellyfin-media"

vaultwarden:
  org_name: "$site_name"
  org_identifier: "$domain"
  org_id: "$vaultwarden_org_id"
EOF_CONFIG

plain_secrets="$(mktemp)"
trap 'rm -f "$plain_secrets"' EXIT
write_secret_json "$plain_secrets" "$(random_secret 36)"
if [ -n "$SOPS_AGE_RECIPIENT" ]; then
  SOPS_AGE_RECIPIENTS="$SOPS_AGE_RECIPIENT" sops \
    --encrypt \
    --input-type json \
    --output-type json \
    "$plain_secrets" > "$target_dir/webservices.sops.json"
else
  sops \
    --encrypt \
    --input-type json \
    --output-type json \
    "$plain_secrets" > "$target_dir/webservices.sops.json"
fi

cat > "$target_dir/.webservices-generator.json" <<EOF_GENERATOR
{
  "generatorRemote": "$GENERATOR_REMOTE",
  "generatorRef": "$generator_ref",
  "generatorCommit": "$generator_commit",
  "generatorUpstreamRemote": "$generator_upstream_remote",
  "generatorUpstreamRef": "$generator_upstream_ref"
}
EOF_GENERATOR

cat > "$target_dir/.gitignore" <<'EOF_GITIGNORE'
.stack-generator/
dist/
out/
runtime/
*.plain.json
*.decrypted.json
.env
EOF_GITIGNORE

cat > "$target_dir/README.md" <<EOF_README
# $site_name Webservices Site

This repo contains site-specific deployment inputs for the webservices stack:

- \`manifest.json\` selects components and points at config/secrets.
- \`stack.config.yaml\` contains non-secret site settings.
- \`webservices.sops.json\` contains encrypted runtime secrets.
- \`.webservices-generator.json\` pins the generator commit used for reproducible builds.
- \`.sops.yaml\` records encryption policy when an age recipient was provided.

Build from a generator checkout:

\`\`\`bash
./build.sh --manifest "$target_dir/manifest.json"
\`\`\`

Check for generator updates:

\`\`\`bash
./stack-update.sh
\`\`\`
EOF_README

cat > "$target_dir/stack-update.sh" <<'EOF_UPDATE'
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SITE_ROOT="$SCRIPT_ROOT"
CACHE_DIR="$SCRIPT_ROOT/.stack-generator"

die() {
  printf '[stack-update] ERROR: %s\n' "$*" >&2
  exit 1
}

log() {
  printf '[stack-update] %s\n' "$*" >&2
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --site-root)
      [ "$#" -ge 2 ] || die "--site-root requires a value"
      SITE_ROOT="$(cd "$2" && pwd -P)"
      shift
      ;;
    -h|--help)
      cat <<'EOF_USAGE'
Usage:
  ./stack-update.sh [--site-root <path>]
EOF_USAGE
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
  shift
done

PIN_FILE="$SITE_ROOT/.webservices-generator.json"

command -v git >/dev/null 2>&1 || die "missing required command: git"
command -v jq >/dev/null 2>&1 || die "missing required command: jq"
[ -f "$PIN_FILE" ] || die "missing generator pin: $PIN_FILE"

remote="$(jq -r '.generatorRemote' "$PIN_FILE")"
ref="$(jq -r '.generatorRef // "main"' "$PIN_FILE")"
current="$(jq -r '.generatorCommit' "$PIN_FILE")"
upstream_remote="$(jq -r '.generatorUpstreamRemote // empty' "$PIN_FILE")"
upstream_ref="$(jq -r '.generatorUpstreamRef // "main"' "$PIN_FILE")"
[ -n "$remote" ] && [ "$remote" != "null" ] || die "generatorRemote is empty"
[ -n "$current" ] && [ "$current" != "null" ] || die "generatorCommit is empty"

if [ ! -d "$CACHE_DIR/.git" ]; then
  log "cloning generator into $CACHE_DIR"
  git clone "$remote" "$CACHE_DIR"
fi

git -C "$CACHE_DIR" fetch origin "$ref"
latest="$(git -C "$CACHE_DIR" rev-parse "origin/$ref^{commit}")"
if [ -n "$upstream_remote" ] && [ "$upstream_remote" != "null" ]; then
  if git -C "$CACHE_DIR" remote get-url upstream >/dev/null 2>&1; then
    git -C "$CACHE_DIR" remote set-url upstream "$upstream_remote"
  else
    git -C "$CACHE_DIR" remote add upstream "$upstream_remote"
  fi
  git -C "$CACHE_DIR" fetch upstream "$upstream_ref" || true
  upstream_latest="$(git -C "$CACHE_DIR" rev-parse "upstream/$upstream_ref^{commit}" 2>/dev/null || true)"
  if [ -n "$upstream_latest" ]; then
    log "upstream parent: $upstream_remote $upstream_ref @ $upstream_latest"
  fi
fi

if [ "$latest" = "$current" ]; then
  log "already current on generator at $current"
  exit 0
fi

log "generator update available:"
log "  current: $current"
log "  latest:  $latest"
git -C "$CACHE_DIR" log --oneline --decorate --max-count=30 "$current..$latest" || true

git -C "$CACHE_DIR" checkout --detach "$latest" >/dev/null

if [ -x "$CACHE_DIR/scripts/site/migrate-site.sh" ]; then
  "$CACHE_DIR/scripts/site/migrate-site.sh" --site-root "$SITE_ROOT" --from "$current" --to "$latest"
fi

if [ "${STACK_UPDATE_SKIP_BUILD:-0}" != "1" ]; then
  log "validating with pinned generator candidate"
  "$CACHE_DIR/build.sh" --manifest "$SITE_ROOT/manifest.json"
fi

git -C "$SCRIPT_ROOT" diff -- "$SITE_ROOT" ':!.stack-generator' || true
printf 'Commit this generator update to the site repo? [y/N] ' >&2
read -r answer
case "$answer" in
  y|Y|yes|YES)
    tmp_pin="$(mktemp)"
    jq --arg latest "$latest" '.generatorCommit = $latest' "$PIN_FILE" > "$tmp_pin"
    mv "$tmp_pin" "$PIN_FILE"
    git -C "$SCRIPT_ROOT" add "$SITE_ROOT"
    git -C "$SCRIPT_ROOT" commit -m "Update webservices generator pin to ${latest:0:12}"
    log "updated generator pin to $latest"
    ;;
  *)
    log "left site repo unchanged"
    ;;
esac
EOF_UPDATE
chmod +x "$target_dir/stack-update.sh"

git -C "$target_dir" init
git -C "$target_dir" add .
git -C "$target_dir" commit -m "Initialize webservices site"

if [ "$CREATE_GITHUB" = "1" ]; then
  require_cmd gh
  repo_name="$(basename "$target_dir")"
  gh repo create "$repo_name" --private --source "$target_dir" --remote origin --push
fi

log "site repo ready: $target_dir"
