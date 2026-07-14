#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
BUNDLE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
default_deploy_root() {
  if [ -f "$BUNDLE_ROOT/runtime/stack.env" ]; then
    printf '%s\n' "$BUNDLE_ROOT"
  else
    cd "$BUNDLE_ROOT/.." && pwd -P
  fi
}
DEPLOY_ROOT="${DEPLOY_ROOT:-$(default_deploy_root)}"
# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=scripts/lib/systemd-user.sh
source "$SCRIPT_DIR/lib/systemd-user.sh"

PROJECT_NAME="${PROJECT_NAME:-webservices}"
COMMAND_NAME="${COMMAND_NAME:-kt}"
SUITE_NAME="${SUITE_NAME:-stack-contract}"
READY_ONLY=0
RUN_DIRECT=0
CURRENT_PHASE="initializing"
ORIGINAL_ARGS=("$@")

usage() {
  cat <<'EOF_USAGE'
Usage:
  ./scripts/verify.sh [--ready-only]

Runs readiness for the in-place bundle and then the blocking test-runner suite.
EOF_USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --ready-only)
      READY_ONLY=1
      ;;
    --run-direct)
      RUN_DIRECT=1
      ;;
    --command)
      COMMAND_NAME="$2"
      shift
      ;;
    --suite)
      SUITE_NAME="$2"
      shift
      ;;
    *)
      die "unknown argument for verify.sh: $1"
      ;;
  esac
  shift
done

[ -f "$DEPLOY_ROOT/runtime/stack.env" ] || die "missing runtime/stack.env in $DEPLOY_ROOT/runtime"
require_cmd jq

is_podman_bundle() {
  [ -f "$BUNDLE_ROOT/bundle.json" ] && jq -e '.backend == "podman"' "$BUNDLE_ROOT/bundle.json" >/dev/null 2>&1
}

if ! is_podman_bundle; then
  [ -f "$BUNDLE_ROOT/runtime-contract.yml" ] || die "missing runtime contract in $BUNDLE_ROOT"
  [ -f "$BUNDLE_ROOT/stack.systemd/graph.json" ] || die "missing stack.systemd/graph.json in $BUNDLE_ROOT"
fi

verify_log() {
  printf '[webservices-verify] %s\n' "$*" >&2
}

set_phase() {
  CURRENT_PHASE="$1"
  verify_log "phase: $CURRENT_PHASE"
}

dump_verify_diagnostics() {
  local failed_user_units unit_name stack_targets=()
  verify_log "diagnostics begin (phase=$CURRENT_PHASE)"
  mapfile -t stack_targets < <(user_systemd_default_stack_targets "$BUNDLE_ROOT/stack.systemd/graph.json")
  verify_log "stack target status"
  user_systemd_show_status "${stack_targets[@]}" >&2

  verify_log "dependency tree"
  user_systemd_list_dependencies webservices.target >&2

  verify_log "unit inventory"
  user_systemd_list_matching_units >&2

  mapfile -t failed_user_units < <(user_systemd_failed_units)
  if [ "${#failed_user_units[@]}" -gt 0 ]; then
    verify_log "failed user units: ${failed_user_units[*]}"
    for unit_name in "${failed_user_units[@]}"; do
      verify_log "status for failed unit $unit_name"
      user_systemd_show_status "$unit_name" >&2
      verify_log "recent journal for failed unit $unit_name"
      user_systemd_show_recent_logs "$unit_name" 160 >&2
    done
  else
    verify_log "no failed user units reported"
  fi

  verify_log "container snapshot"
  container_runtime ps -a --format '{{.Names}}\t{{.Status}}\t{{.Image}}' 2>&1 | sort || true
  if [ -x "$BUNDLE_ROOT/scripts/mount-diagnostics.sh" ]; then
    verify_log "mount diagnostics summary"
    "$BUNDLE_ROOT/scripts/mount-diagnostics.sh" \
      --bundle-root "$BUNDLE_ROOT" \
      --runtime-env-file "$DEPLOY_ROOT/runtime/stack.env" 2>/dev/null \
      | jq -c '{summary, findings}' 2>/dev/null || true
  fi
  verify_log "diagnostics end"
}

on_verify_error() {
  local exit_code=$?
  verify_log "ERROR: verify failed during phase '$CURRENT_PHASE' with exit code $exit_code"
  dump_verify_diagnostics
  exit "$exit_code"
}

trap 'on_verify_error' ERR

verify_podman_release_ready() {
  local rootless_user="${WEBSERVICES_ROOTLESS_USER:-webservices}"
  local rootless_uid rootless_home failed_rootful failed_rootless

  rootless_uid="$(id -u "$rootless_user")"
  rootless_home="$(getent passwd "$rootless_user" | cut -d: -f6)"

  set_phase "podman-readiness"
  systemctl is-active --quiet webservices.target
  failed_rootful="$(systemctl list-units --failed --no-legend 'webservices*' || true)"
  if [ -n "$failed_rootful" ]; then
    printf '%s\n' "$failed_rootful" >&2
    die "one or more rootful webservices units are failed"
  fi

  /usr/sbin/runuser -u "$rootless_user" -- \
    env HOME="$rootless_home" XDG_RUNTIME_DIR="/run/user/${rootless_uid}" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${rootless_uid}/bus" \
    systemctl --user is-active --quiet webservices.target
  failed_rootless="$(/usr/sbin/runuser -u "$rootless_user" -- \
    env HOME="$rootless_home" XDG_RUNTIME_DIR="/run/user/${rootless_uid}" DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${rootless_uid}/bus" \
    systemctl --user list-units --failed --no-legend 'webservices*' || true)"
  if [ -n "$failed_rootless" ]; then
    printf '%s\n' "$failed_rootless" >&2
    die "one or more rootless webservices units are failed"
  fi

  if [ "$READY_ONLY" != "1" ]; then
    die "installed Podman release verification supports --ready-only; run test suites from the source checkout"
  fi
  set_phase "ready-only-complete"
  verify_log "Podman release readiness passed"
  exit 0
}

default_test_results_host_dir() {
  local deploy_parent deploy_name
  deploy_parent="$(dirname "$DEPLOY_ROOT")"
  deploy_name="$(basename "$DEPLOY_ROOT")"
  printf '%s/%s-test-results\n' "$deploy_parent" "$deploy_name"
}

if [ "$RUN_DIRECT" != "1" ]; then
  if is_podman_bundle; then
    verify_podman_release_ready
  fi
  require_cmd systemd-run
  ensure_user_systemd_env
  transient_unit="webservices-verify-$(date +%Y%m%d_%H%M%S)"
  verify_log "dispatching verification via transient user unit $transient_unit"
  exec systemd-run \
    --user \
    --wait \
    --collect \
    --pipe \
    --unit "$transient_unit" \
    --property "WorkingDirectory=$DEPLOY_ROOT" \
    "$BUNDLE_ROOT/scripts/verify.sh" \
    --run-direct \
    "${ORIGINAL_ARGS[@]}"
fi

verify_ignored_units() {
  jq -r '
    .unitPrefix as $prefix
    | (((.onDemandDomains // []) + (.onDemandServices // [])) | unique)
    | map("\($prefix)-" + . + ".service", "\($prefix)-" + . + "-healthy.service")
    | .[]
  ' "$BUNDLE_ROOT/stack.systemd/graph.json"
}

filtered_failed_user_units() {
  local ignored_units=()
  local failed_units=()
  local unit_name ignore ignored_name
  mapfile -t ignored_units < <(verify_ignored_units)
  mapfile -t failed_units < <(user_systemd_failed_units)
  for unit_name in "${failed_units[@]}"; do
    ignore=0
    for ignored_name in "${ignored_units[@]}"; do
      if [ "$unit_name" = "$ignored_name" ]; then
        ignore=1
        break
      fi
    done
    if [ "$ignore" -eq 0 ]; then
      printf '%s\n' "$unit_name"
    fi
  done
}

inactive_default_stack_targets() {
  local stack_targets=()
  local unit_name
  mapfile -t stack_targets < <(user_systemd_default_stack_targets "$BUNDLE_ROOT/stack.systemd/graph.json")
  for unit_name in "${stack_targets[@]}"; do
    if ! user_systemctl is-active --quiet "$unit_name"; then
      printf '%s\n' "$unit_name"
    fi
  done
}

set_phase "pre-readiness"
verify_log "running readiness gate"
mapfile -t inactive_stack_targets < <(inactive_default_stack_targets)
if [ "${#inactive_stack_targets[@]}" -gt 0 ]; then
  user_systemctl --no-pager --full status "${inactive_stack_targets[@]}" || true
  die "default stack targets are not active under systemd --user: ${inactive_stack_targets[*]}"
fi

mapfile -t failed_user_units < <(filtered_failed_user_units)
if [ "${#failed_user_units[@]}" -gt 0 ]; then
  verify_log "failing user units: ${failed_user_units[*]}"
  user_systemctl --no-pager --full status "${failed_user_units[@]}" || true
  die "one or more webservices user units are failed"
fi

set_phase "readiness"
"$SCRIPT_DIR/lib/wait-ready.sh" \
  --bundle-dir "$BUNDLE_ROOT" \
  --runtime-env-file "$DEPLOY_ROOT/runtime/stack.env" \
  --project-name "$PROJECT_NAME"

if [ "$READY_ONLY" = "1" ]; then
  set_phase "ready-only-complete"
  verify_log "readiness passed"
  exit 0
fi

run_args=("$COMMAND_NAME")
if [ "$COMMAND_NAME" = "kt" ]; then
  run_args+=("$SUITE_NAME")
fi

set_phase "test-runner"
verify_log "running verification command: ${run_args[*]}"
if DIST_DIR="$BUNDLE_ROOT" TEST_RESULTS_HOST_DIR="${TEST_RESULTS_HOST_DIR:-$(default_test_results_host_dir)}" \
  "$BUNDLE_ROOT/stack.containers/test-runner/run-tests.sh" "${run_args[@]}"; then
  set_phase "complete"
  verify_log "verification passed"
else
  die "verification failed"
fi
