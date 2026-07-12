#!/usr/bin/env bash

# shellcheck source=scripts/lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

user_systemd_runtime_dir() {
  printf '%s\n' "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
}

ensure_user_systemd_env() {
  local runtime_dir bus_path
  runtime_dir="$(user_systemd_runtime_dir)"
  bus_path="$runtime_dir/bus"

  [ -d "$runtime_dir" ] || die "user systemd runtime directory is unavailable: $runtime_dir"
  [ -S "$bus_path" ] || die "user systemd bus is unavailable at $bus_path (enable lingering and ensure the user manager is running)"

  export XDG_RUNTIME_DIR="$runtime_dir"
  export DBUS_SESSION_BUS_ADDRESS="${DBUS_SESSION_BUS_ADDRESS:-unix:path=$bus_path}"
}

user_systemctl() {
  ensure_user_systemd_env
  systemctl --user "$@"
}

user_journalctl() {
  ensure_user_systemd_env
  journalctl --user "$@"
}

user_systemd_unit_dir() {
  printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
}

user_systemd_failed_units() {
  ensure_user_systemd_env
  systemctl --user --failed --plain --no-legend --no-pager 2>/dev/null | awk '/^webservices[-.]/ {print $1}'
}

user_systemd_list_matching_units() {
  ensure_user_systemd_env
  systemctl --user list-units --all --plain --no-legend --no-pager 2>/dev/null | awk '/^webservices[-.]/ {print $1 "\t" $2 "\t" $3 "\t" $4}'
}

user_systemd_show_status() {
  ensure_user_systemd_env
  systemctl --user --no-pager --full status "$@" 2>&1 || true
}

user_systemd_list_dependencies() {
  ensure_user_systemd_env
  systemctl --user list-dependencies "$@" --no-pager 2>&1 || true
}

user_systemd_show_recent_logs() {
  ensure_user_systemd_env
  local unit_name="$1"
  local lines="${2:-120}"
  journalctl --user -u "$unit_name" -n "$lines" --no-pager 2>&1 || true
}

user_systemd_list_jobs() {
  ensure_user_systemd_env
  systemctl --user list-jobs --all --no-pager 2>&1 || true
}

user_systemd_list_matching_jobs_raw() {
  ensure_user_systemd_env
  systemctl --user list-jobs --all --no-legend --no-pager 2>/dev/null | awk '/webservices[-.]/ {print $2 "\t" $3 "\t" $4}'
}

user_systemd_list_matching_jobs() {
  ensure_user_systemd_env
  systemctl --user list-jobs --all --no-pager 2>/dev/null | awk 'NR == 1 || /^[-[:space:]]*$/ || /^([0-9]+[[:space:]]+webservices[-.])/ {print}'
}

default_auxiliary_targets_from_graph() {
  local graph_file="$1"
  jq -r '
    (.defaultTarget.wantsTargets // []) as $wanted
    | [(.auxiliaryTargets // [] | .[]?.name | . as $target | select($target != null and ($wanted | index($target)) != null))]
    | .[]
  ' "$graph_file"
}

default_stack_targets_from_graph() {
  local graph_file="$1"
  jq -r '.defaultTarget.name // "webservices.target"' "$graph_file"
  default_auxiliary_targets_from_graph "$graph_file"
}

user_systemd_default_stack_targets() {
  local graph_file="$1"
  default_stack_targets_from_graph "$graph_file"
}
