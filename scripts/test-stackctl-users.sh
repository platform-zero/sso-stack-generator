#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "[test-stackctl-users] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

fake_bin="$tmp_dir/bin"
runtime_dir="$tmp_dir/runtime"
state_file="$tmp_dir/state.json"
stdout_file="$tmp_dir/stdout"
stderr_file="$tmp_dir/stderr"
mkdir -p "$fake_bin" "$runtime_dir"

cat > "$runtime_dir/stack.env" <<'EOF_ENV'
DOMAIN=example.test
KEYCLOAK_ADMIN_PASSWORD=test-admin-password
EOF_ENV

cat > "$fake_bin/podman" <<'EOF_PODMAN'
#!/usr/bin/env bash
set -euo pipefail

STATE_FILE="${STACKCTL_USERS_TEST_STATE:?}"

parse_file_arg() {
  local flag="$1"
  shift
  while [ "$#" -gt 0 ]; do
    if [ "$1" = "$flag" ]; then
      printf '%s\n' "$2"
      return 0
    fi
    shift
  done
  return 1
}

parse_username_arg() {
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --username)
        printf '%s\n' "$2"
        return 0
        ;;
      -q)
        case "$2" in
          username=*)
            printf '%s\n' "${2#username=}"
            return 0
            ;;
        esac
        shift
        ;;
    esac
    shift
  done
  return 1
}

if [ "$1" != "exec" ]; then
  printf 'unsupported podman command: %s\n' "$*" >&2
  exit 1
fi
shift

container="$1"
shift
[ "$container" = "keycloak" ] || {
  printf 'unexpected container: %s\n' "$container" >&2
  exit 1
}

[ "$1" = "/opt/keycloak/bin/kcadm.sh" ] || {
  printf 'unexpected command: %s\n' "$1" >&2
  exit 1
}
shift

subcommand="$1"
shift

case "$subcommand" in
  config)
    [ "$1" = "credentials" ] || exit 1
    exit 0
    ;;
  get)
    resource="$1"
    shift
    case "$resource" in
      users)
        username="$(parse_username_arg "$@")"
        jq -c --arg username "$username" '[.users[] | select(.username == $username)]' "$STATE_FILE"
        ;;
      users/*/groups)
        user_id="${resource#users/}"
        user_id="${user_id%/groups}"
        jq -c --arg user_id "$user_id" '
          (.users[] | select(.id == $user_id) | .requiredActions // []) as $actions
          | if ($actions | length) > 0 then [{"name":"onboarding_required"}] else [] end
        ' "$STATE_FILE"
        ;;
      users/*)
        user_id="${resource#users/}"
        jq -c --arg user_id "$user_id" '.users[] | select(.id == $user_id)' "$STATE_FILE"
        ;;
      *)
        printf 'unsupported get resource: %s\n' "$resource" >&2
        exit 1
        ;;
    esac
    ;;
  create)
    resource="$1"
    shift
    [ "$resource" = "users" ] || exit 1
    payload_file="$(parse_file_arg -f "$@")"
    jq --slurpfile payload "$payload_file" '
      .nextId as $next
      | .users += [(($payload[0]) + {id: ("user-" + ($next | tostring)), requiredActions: (($payload[0].requiredActions) // [])})]
      | .nextId = ($next + 1)
    ' "$STATE_FILE" > "$STATE_FILE.tmp"
    mv "$STATE_FILE.tmp" "$STATE_FILE"
    ;;
  update)
    resource="$1"
    shift
    user_id="${resource#users/}"
    payload_file="$(parse_file_arg -f "$@")"
    jq --arg user_id "$user_id" --slurpfile payload "$payload_file" '
      .users |= map(if .id == $user_id then $payload[0] else . end)
    ' "$STATE_FILE" > "$STATE_FILE.tmp"
    mv "$STATE_FILE.tmp" "$STATE_FILE"
    ;;
  set-password)
    username="$(parse_username_arg "$@")"
    temporary=false
    for arg in "$@"; do
      if [ "$arg" = "-t" ]; then
        temporary=true
      fi
    done
    jq --arg username "$username" --argjson temporary "$temporary" '
      .users |= map(if .username == $username then . + {passwordTemporary: $temporary} else . end)
    ' "$STATE_FILE" > "$STATE_FILE.tmp"
    mv "$STATE_FILE.tmp" "$STATE_FILE"
    ;;
  *)
    printf 'unsupported kcadm subcommand: %s\n' "$subcommand" >&2
    exit 1
    ;;
esac
EOF_PODMAN
chmod +x "$fake_bin/podman"

assert_contains() {
  local file="$1"
  local pattern="$2"
  local label="$3"
  if ! grep -Eq -- "$pattern" "$file"; then
    printf '[test-stackctl-users] missing %s in %s\n' "$label" "$file" >&2
    exit 1
  fi
}

reset_state() {
  cat > "$state_file" <<'EOF_STATE'
{"nextId":1,"users":[]}
EOF_STATE
}

run_stackctl() {
  PATH="$fake_bin:$PATH" \
    STACK_CONTAINER_CLI=podman \
    STACKCTL_RUNTIME_ENV_FILE="$runtime_dir/stack.env" \
    STACKCTL_USERS_TEST_STATE="$state_file" \
    STACKCTL_USERS_MARKER_WAIT_ATTEMPTS=1 \
    STACKCTL_USERS_MARKER_WAIT_DELAY_SECONDS=0 \
    "$ROOT_DIR/scripts/stackctl.sh" "$@"
}

expect_failure() {
  if run_stackctl "$@" >"$stdout_file" 2>"$stderr_file"; then
    printf '[test-stackctl-users] expected failure for: %s\n' "$*" >&2
    exit 1
  fi
}

reset_state
PATH="$fake_bin:$PATH" STACK_CONTAINER_CLI=podman "$ROOT_DIR/scripts/stackctl.sh" users create --help >"$stdout_file"
assert_contains "$stdout_file" 'stackctl users create --username <u> --password <p>' "create help output"

reset_state
expect_failure users create --password secret
assert_contains "$stderr_file" 'missing required flag: --username' "missing username error"

reset_state
expect_failure users create --username testuser
assert_contains "$stderr_file" 'missing required flag: --password' "missing password error"

reset_state
expect_failure users create --username testuser --password secret --active --password-only
assert_contains "$stderr_file" '--active cannot be combined with --password-only' "invalid mode error"

reset_state
run_stackctl users create --username testuser --password secret --json >"$stdout_file"
jq -e '.email == "testuser@example.test"' "$stdout_file" >/dev/null
jq -e '.requiredActions == ["UPDATE_PASSWORD","CONFIGURE_TOTP"]' "$stdout_file" >/dev/null
jq -e '.onboardingRequired == true' "$stdout_file" >/dev/null

reset_state
run_stackctl users create --username passwordonly --password secret --password-only --json >"$stdout_file"
jq -e '.requiredActions == ["UPDATE_PASSWORD"]' "$stdout_file" >/dev/null
jq -e '.onboardingRequired == true' "$stdout_file" >/dev/null

reset_state
run_stackctl users create --username activeuser --password secret --active --json >"$stdout_file"
jq -e '.requiredActions == []' "$stdout_file" >/dev/null
jq -e '.onboardingRequired == false' "$stdout_file" >/dev/null

reset_state
run_stackctl users create --username existing --password secret --email existing@example.test --json >"$stdout_file"
expect_failure users create --username existing --password secret
assert_contains "$stderr_file" 'user already exists: existing' "existing user error"

run_stackctl users create --username existing --password secret --password-only --reset-existing --first-name Gerald --json >"$stdout_file"
jq -e '.requiredActions == ["UPDATE_PASSWORD"]' "$stdout_file" >/dev/null
jq -e '.email == "existing@example.test"' "$stdout_file" >/dev/null
jq -e '.users[] | select(.username == "existing") | .firstName == "Gerald"' "$state_file" >/dev/null

run_stackctl users show --username existing --json >"$stdout_file"
jq -e 'has("id") and has("username") and has("email") and has("enabled") and has("requiredActions") and has("groups") and has("onboardingRequired")' "$stdout_file" >/dev/null

printf '[test-stackctl-users] ok\n'
