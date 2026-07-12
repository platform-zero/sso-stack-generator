#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPTS_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
BUNDLE_ROOT="$(cd "$SCRIPTS_DIR/.." && pwd -P)"
DEPLOY_ROOT="$(cd "$BUNDLE_ROOT/.." && pwd -P)"

# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/common.sh"
# shellcheck source=scripts/lib/env-file.sh
source "$SCRIPT_DIR/env-file.sh"

REALM="webservices"
KEYCLOAK_CONTAINER="${KEYCLOAK_CONTAINER:-keycloak}"
RUNTIME_ENV_FILE="${STACKCTL_RUNTIME_ENV_FILE:-$DEPLOY_ROOT/runtime/stack.env}"
MARKER_WAIT_ATTEMPTS="${STACKCTL_USERS_MARKER_WAIT_ATTEMPTS:-8}"
MARKER_WAIT_DELAY_SECONDS="${STACKCTL_USERS_MARKER_WAIT_DELAY_SECONDS:-1}"

usage() {
  cat <<'EOF_USAGE'
Usage:
  stackctl users create --username <u> --password <p> [--email <e>] [--first-name <f>] [--last-name <l>] [--active] [--password-only] [--reset-existing] [--json]
  stackctl users show --username <u> [--json]

Commands:
  create    Create or reset a Keycloak user in the webservices realm.
  show      Show the current Keycloak state for a user.

Modes:
  default         Enabled user, temporary password, required actions UPDATE_PASSWORD and CONFIGURE_TOTP.
  --password-only Enabled user, temporary password, required action UPDATE_PASSWORD only.
  --active        Enabled user, non-temporary password, no required actions.
EOF_USAGE
}

usage_create() {
  cat <<'EOF_USAGE'
Usage:
  stackctl users create --username <u> --password <p> [--email <e>] [--first-name <f>] [--last-name <l>] [--active] [--password-only] [--reset-existing] [--json]
EOF_USAGE
}

usage_show() {
  cat <<'EOF_USAGE'
Usage:
  stackctl users show --username <u> [--json]
EOF_USAGE
}

runtime_env_required() {
  local key="$1"
  local value
  value="$(env_file_get_value "$RUNTIME_ENV_FILE" "$key")"
  [ -n "$value" ] || die "missing $key in $RUNTIME_ENV_FILE"
  printf '%s\n' "$value"
}

runtime_env_optional() {
  local key="$1"
  env_file_get_value "$RUNTIME_ENV_FILE" "$key"
}

load_runtime_config() {
  [ -f "$RUNTIME_ENV_FILE" ] || die "missing runtime env file: $RUNTIME_ENV_FILE"
  require_cmd docker
  require_cmd jq

  DOMAIN="$(runtime_env_required DOMAIN)"
  KEYCLOAK_ADMIN_PASSWORD="$(runtime_env_required KEYCLOAK_ADMIN_PASSWORD)"
  KEYCLOAK_ADMIN_USER="$(runtime_env_optional KEYCLOAK_ADMIN_USER)"
  KEYCLOAK_SERVER="$(runtime_env_optional KEYCLOAK_SERVER)"

  KEYCLOAK_ADMIN_USER="${KEYCLOAK_ADMIN_USER:-admin}"
  KEYCLOAK_SERVER="${KEYCLOAK_SERVER:-http://keycloak:8080}"
}

kcadm() {
  docker exec "$KEYCLOAK_CONTAINER" /opt/keycloak/bin/kcadm.sh "$@"
}

keycloak_auth() {
  kcadm config credentials \
    --server "$KEYCLOAK_SERVER" \
    --realm master \
    --user "$KEYCLOAK_ADMIN_USER" \
    --password "$KEYCLOAK_ADMIN_PASSWORD" >/dev/null
}

lookup_user_json() {
  local username="$1"
  kcadm get users -r "$REALM" -q username="$username" \
    | jq -c --arg username "$username" 'map(select(.username == $username)) | .[0] // empty'
}

require_user_json() {
  local username="$1"
  local user_json
  user_json="$(lookup_user_json "$username")"
  [ -n "$user_json" ] || die "user not found: $username"
  printf '%s\n' "$user_json"
}

fetch_user_json() {
  local user_id="$1"
  kcadm get "users/$user_id" -r "$REALM" | jq -c '.'
}

fetch_user_groups_json() {
  local user_id="$1"
  kcadm get "users/$user_id/groups" -r "$REALM" | jq -c '[.[].name] | sort'
}

set_user_password() {
  local username="$1"
  local password="$2"
  local temporary="$3"
  local -a args=(set-password -r "$REALM" --username "$username" --new-password "$password")
  if [ "$temporary" = "1" ]; then
    args+=(-t)
  fi
  kcadm "${args[@]}" >/dev/null
}

write_create_payload() {
  local path="$1"
  local username="$2"
  local email="$3"
  local first_name="$4"
  local last_name="$5"

  jq -n \
    --arg username "$username" \
    --arg email "$email" \
    --arg first_name "$first_name" \
    --arg last_name "$last_name" \
    '{
      username: $username,
      enabled: true,
      email: $email
    }
    + (if $first_name != "" then {firstName: $first_name} else {} end)
    + (if $last_name != "" then {lastName: $last_name} else {} end)' > "$path"
}

write_update_payload() {
  local path="$1"
  local current_json="$2"
  local required_actions_json="$3"
  local email="$4"
  local first_name="$5"
  local last_name="$6"

  jq \
    --argjson required_actions "$required_actions_json" \
    --arg email "$email" \
    --arg first_name "$first_name" \
    --arg last_name "$last_name" \
    '
      .enabled = true
      | .requiredActions = $required_actions
      | if $email != "" then .email = $email else . end
      | if $first_name != "" then .firstName = $first_name else . end
      | if $last_name != "" then .lastName = $last_name else . end
    ' <<<"$current_json" > "$path"
}

build_user_state_json() {
  local user_id="$1"
  local user_json groups_json
  user_json="$(fetch_user_json "$user_id")"
  groups_json="$(fetch_user_groups_json "$user_id")"

  jq -n \
    --argjson user "$user_json" \
    --argjson groups "$groups_json" \
    '{
      id: $user.id,
      username: $user.username,
      email: ($user.email // ""),
      enabled: ($user.enabled // false),
      requiredActions: ($user.requiredActions // []),
      groups: $groups,
      onboardingRequired: (($groups | index("onboarding_required")) != null or ($groups | index("onboarding-required")) != null)
    }'
}

wait_for_final_state() {
  local user_id="$1"
  local expect_marker="$2"
  local attempt=1
  local final_state=""
  local onboarding_required=""

  while [ "$attempt" -le "$MARKER_WAIT_ATTEMPTS" ]; do
    final_state="$(build_user_state_json "$user_id")"
    onboarding_required="$(jq -r '.onboardingRequired' <<<"$final_state")"
    if [ "$onboarding_required" = "$expect_marker" ]; then
      printf '%s\n' "$final_state"
      return 0
    fi
    if [ "$attempt" -lt "$MARKER_WAIT_ATTEMPTS" ]; then
      sleep "$MARKER_WAIT_DELAY_SECONDS"
    fi
    attempt=$((attempt + 1))
  done

  printf '%s\n' "$final_state"
}

print_human_state() {
  local state_json="$1"
  local required_actions groups onboarding_marker
  required_actions="$(jq -r 'if (.requiredActions | length) == 0 then "(none)" else (.requiredActions | join(", ")) end' <<<"$state_json")"
  groups="$(jq -r 'if (.groups | length) == 0 then "(none)" else (.groups | join(", ")) end' <<<"$state_json")"
  onboarding_marker="$(jq -r 'if .onboardingRequired then "present" else "absent" end' <<<"$state_json")"

  printf 'id: %s\n' "$(jq -r '.id' <<<"$state_json")"
  printf 'username: %s\n' "$(jq -r '.username' <<<"$state_json")"
  printf 'email: %s\n' "$(jq -r '.email' <<<"$state_json")"
  printf 'enabled: %s\n' "$(jq -r '.enabled' <<<"$state_json")"
  printf 'required actions: %s\n' "$required_actions"
  printf 'groups: %s\n' "$groups"
  printf 'onboarding marker: %s\n' "$onboarding_marker"
}

create_user() {
  local username=""
  local password=""
  local email=""
  local email_provided=0
  local first_name=""
  local last_name=""
  local reset_existing=0
  local json_output=0
  local mode="default"
  local temporary_password=1
  local required_actions_json='["UPDATE_PASSWORD","CONFIGURE_TOTP"]'
  local create_payload=""
  local update_payload=""

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --username)
        [ "$#" -ge 2 ] || die "--username requires a value"
        username="$2"
        shift
        ;;
      --password)
        [ "$#" -ge 2 ] || die "--password requires a value"
        password="$2"
        shift
        ;;
      --email)
        [ "$#" -ge 2 ] || die "--email requires a value"
        email="$2"
        email_provided=1
        shift
        ;;
      --first-name)
        [ "$#" -ge 2 ] || die "--first-name requires a value"
        first_name="$2"
        shift
        ;;
      --last-name)
        [ "$#" -ge 2 ] || die "--last-name requires a value"
        last_name="$2"
        shift
        ;;
      --reset-existing)
        reset_existing=1
        ;;
      --password-only)
        [ "$mode" = "default" ] || die "--active cannot be combined with --password-only"
        mode="password-only"
        required_actions_json='["UPDATE_PASSWORD"]'
        ;;
      --active)
        [ "$mode" = "default" ] || die "--active cannot be combined with --password-only"
        mode="active"
        temporary_password=0
        required_actions_json='[]'
        ;;
      --json)
        json_output=1
        ;;
      -h|--help)
        usage_create
        exit 0
        ;;
      *)
        die "unknown argument for stackctl users create: $1"
        ;;
    esac
    shift
  done

  [ -n "$username" ] || die "missing required flag: --username"
  [ -n "$password" ] || die "missing required flag: --password"

  local existing_json user_id current_json final_state expect_marker action_word
  existing_json="$(lookup_user_json "$username")"
  if [ -n "$existing_json" ]; then
    if [ "$reset_existing" != "1" ]; then
      die "user already exists: $username (use --reset-existing to update it)"
    fi
    user_id="$(jq -r '.id' <<<"$existing_json")"
    action_word="updated"
  else
    create_payload="$(mktemp)"
    if [ "$email_provided" != "1" ]; then
      email="${username}@${DOMAIN}"
    fi
    write_create_payload "$create_payload" "$username" "$email" "$first_name" "$last_name"
    kcadm create users -r "$REALM" -f "$create_payload" >/dev/null
    existing_json="$(require_user_json "$username")"
    user_id="$(jq -r '.id' <<<"$existing_json")"
    action_word="created"
  fi

  set_user_password "$username" "$password" "$temporary_password"

  current_json="$(fetch_user_json "$user_id")"
  update_payload="$(mktemp)"
  if [ "$reset_existing" = "1" ]; then
    if [ "$email_provided" = "1" ]; then
      write_update_payload "$update_payload" "$current_json" "$required_actions_json" "$email" "$first_name" "$last_name"
    else
      write_update_payload "$update_payload" "$current_json" "$required_actions_json" "" "$first_name" "$last_name"
    fi
  else
    write_update_payload "$update_payload" "$current_json" "$required_actions_json" "$email" "$first_name" "$last_name"
  fi
  kcadm update "users/$user_id" -r "$REALM" -f "$update_payload" >/dev/null

  if [ "$mode" = "active" ]; then
    expect_marker="false"
  else
    expect_marker="true"
  fi
  final_state="$(wait_for_final_state "$user_id" "$expect_marker")"

  if [ "$json_output" = "1" ]; then
    rm -f "$create_payload" "$update_payload"
    printf '%s\n' "$final_state"
    return 0
  fi

  printf '%s user %s\n' "$action_word" "$username"
  print_human_state "$final_state"
  rm -f "$create_payload" "$update_payload"
}

show_user() {
  local username=""
  local json_output=0

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --username)
        [ "$#" -ge 2 ] || die "--username requires a value"
        username="$2"
        shift
        ;;
      --json)
        json_output=1
        ;;
      -h|--help)
        usage_show
        exit 0
        ;;
      *)
        die "unknown argument for stackctl users show: $1"
        ;;
    esac
    shift
  done

  [ -n "$username" ] || die "missing required flag: --username"

  local user_json user_id state_json
  user_json="$(require_user_json "$username")"
  user_id="$(jq -r '.id' <<<"$user_json")"
  state_json="$(build_user_state_json "$user_id")"

  if [ "$json_output" = "1" ]; then
    printf '%s\n' "$state_json"
    return 0
  fi

  print_human_state "$state_json"
}

main() {
  local subcommand="${1:-}"
  local arg
  case "$subcommand" in
    ""|-h|--help)
      usage
      exit 0
      ;;
  esac

  shift || true
  case "$subcommand" in
    create)
      for arg in "$@"; do
        if [ "$arg" = "-h" ] || [ "$arg" = "--help" ]; then
          usage_create
          exit 0
        fi
      done
      ;;
    show)
      for arg in "$@"; do
        if [ "$arg" = "-h" ] || [ "$arg" = "--help" ]; then
          usage_show
          exit 0
        fi
      done
      ;;
  esac

  load_runtime_config
  keycloak_auth

  case "$subcommand" in
    create)
      create_user "$@"
      ;;
    show)
      show_user "$@"
      ;;
    *)
      die "unknown stackctl users command: $subcommand"
      ;;
  esac
}

main "$@"
