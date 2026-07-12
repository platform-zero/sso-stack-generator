#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=scripts/lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

usage() {
  cat <<'EOF_USAGE'
Usage:
  systemd-compose-unit.sh service-start --compose-file <path> --env-file <path> --project-directory <path> --project-name <name> --unit-name <name> [--notify-bin <path>]
  systemd-compose-unit.sh service-stop --compose-file <path> --env-file <path> --project-directory <path> --project-name <name> --unit-name <name>
  systemd-compose-unit.sh service-reload --compose-file <path> --env-file <path> --project-directory <path> --project-name <name> --unit-name <name>
  systemd-compose-unit.sh service-wait-healthy --compose-file <path> --env-file <path> --project-directory <path> --project-name <name> --unit-name <name>
  systemd-compose-unit.sh job-run --compose-file <path> --env-file <path> --project-directory <path> --service-name <name> --project-name <name>
EOF_USAGE
}

[ "$#" -gt 0 ] || { usage >&2; exit 1; }
command_name="$1"
shift

COMPOSE_FILE=""
ENV_FILE=""
PROJECT_DIRECTORY=""
SERVICE_NAME=""
PROJECT_NAME=""
UNIT_NAME=""
NOTIFY_BIN=""
START_TIMEOUT_SECONDS="${START_TIMEOUT_SECONDS:-900}"
HEALTH_TIMEOUT_SECONDS="${HEALTH_TIMEOUT_SECONDS:-900}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-2}"
PREHEALTH_TRANSIENT_GRACE_SECONDS="${PREHEALTH_TRANSIENT_GRACE_SECONDS:-120}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --compose-file)
      COMPOSE_FILE="$2"
      shift
      ;;
    --env-file)
      ENV_FILE="$2"
      shift
      ;;
    --project-directory)
      PROJECT_DIRECTORY="$2"
      shift
      ;;
    --service-name)
      SERVICE_NAME="$2"
      shift
      ;;
    --project-name)
      PROJECT_NAME="$2"
      shift
      ;;
    --unit-name)
      UNIT_NAME="$2"
      shift
      ;;
    --notify-bin)
      NOTIFY_BIN="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument for systemd-compose-unit.sh: $1"
      ;;
  esac
  shift
done

[ -n "$COMPOSE_FILE" ] || die "--compose-file is required"
[ -f "$COMPOSE_FILE" ] || die "missing compose file: $COMPOSE_FILE"
[ -n "$ENV_FILE" ] || die "--env-file is required"
[ -f "$ENV_FILE" ] || die "missing env file: $ENV_FILE"
[ -n "$PROJECT_DIRECTORY" ] || die "--project-directory is required"
[ -d "$PROJECT_DIRECTORY" ] || die "missing project directory: $PROJECT_DIRECTORY"
[ -n "$PROJECT_NAME" ] || die "--project-name is required"
require_cmd docker
require_cmd jq

compose() {
  COMPOSE_IGNORE_ORPHANS="${COMPOSE_IGNORE_ORPHANS:-true}" \
  docker compose \
    --project-name "$PROJECT_NAME" \
    --project-directory "$PROJECT_DIRECTORY" \
    --env-file "$ENV_FILE" \
    -f "$COMPOSE_FILE" \
    "$@"
}

compose_config_json() {
  compose config --format json
}

docker_stop_container() {
  local service_name="$1"
  local container_name="$2"
  local timeout_seconds
  case "$service_name" in
    caddy|mariadb|memcached|postgres|postgres-ssd|prometheus|valkey)
      timeout_seconds=120
      ;;
    mailserver)
      timeout_seconds=15
      ;;
    *)
      timeout_seconds=10
      ;;
  esac
  if docker inspect "$container_name" >/dev/null 2>&1; then
    docker stop --time "$timeout_seconds" "$container_name" >/dev/null 2>&1 || docker kill "$container_name" >/dev/null 2>&1 || true
  fi
}

docker_rm_container() {
  local container_name="$1"
  docker rm -f "$container_name" >/dev/null 2>&1 || true
}

services_from_config() {
  local config_json="$1"
  printf '%s\n' "$config_json" | jq -r '.services | keys[]'
}

container_name_for_service() {
  local config_json="$1"
  local service_name="$2"
  local container_name
  container_name="$(printf '%s\n' "$config_json" | jq -r --arg service "$service_name" '.services[$service].container_name // ""')"
  if [ -n "$container_name" ]; then
    printf '%s\n' "$container_name"
    return 0
  fi
  printf '%s-%s-1\n' "$PROJECT_NAME" "$service_name"
}

service_has_healthcheck() {
  local config_json="$1"
  local service_name="$2"
  printf '%s\n' "$config_json" | jq -r --arg service "$service_name" 'if .services[$service].healthcheck == null then "false" else "true" end'
}

service_has_any_healthcheck() {
  local config_json="$1"
  local service_name
  while IFS= read -r service_name; do
    [ -n "$service_name" ] || continue
    if [ "$(service_has_healthcheck "$config_json" "$service_name")" = "true" ]; then
      printf 'true\n'
      return 0
    fi
  done < <(services_from_config "$config_json")
  printf 'false\n'
}

container_state() {
  local container_name="$1"
  docker inspect -f '{{.State.Status}}' "$container_name" 2>/dev/null || true
}

container_health() {
  local container_name="$1"
  docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$container_name" 2>/dev/null || true
}

log_container_failure_details() {
  local container_name="$1"
  if ! docker inspect "$container_name" >/dev/null 2>&1; then
    printf '[webservices-unit] %s container=%s missing during failure inspection\n' "$UNIT_NAME" "$container_name" >&2
    return
  fi
  docker inspect -f \
    '[webservices-unit] '"$UNIT_NAME"' container={{.Name}} status={{.State.Status}} exit_code={{.State.ExitCode}} oom_killed={{.State.OOMKilled}} restarting={{.State.Restarting}} error={{json .State.Error}} restart_count={{.RestartCount}}' \
    "$container_name" >&2 || true
  docker logs --tail 160 "$container_name" >&2 || true
}

stop_marker_path() {
  printf '%s.stopping\n' "$COMPOSE_FILE"
}

reload_marker_path() {
  printf '%s.reloading\n' "$COMPOSE_FILE"
}

clear_markers() {
  rm -f "$(stop_marker_path)" "$(reload_marker_path)"
}

wait_until_running() {
  local config_json="$1"
  local service_name container_name state
  while IFS= read -r service_name; do
    [ -n "$service_name" ] || continue
    container_name="$(container_name_for_service "$config_json" "$service_name")"
    state="$(container_state "$container_name")"
    case "$state" in
      running)
        ;;
      exited|dead)
        log_container_failure_details "$container_name"
        return 1
        ;;
      *)
        return 2
        ;;
    esac
  done < <(services_from_config "$config_json")
  return 0
}

wait_until_healthy() {
  local config_json="$1"
  local service_name container_name state health has_healthcheck
  while IFS= read -r service_name; do
    [ -n "$service_name" ] || continue
    has_healthcheck="$(service_has_healthcheck "$config_json" "$service_name")"
    if [ "$has_healthcheck" != "true" ]; then
      continue
    fi
    container_name="$(container_name_for_service "$config_json" "$service_name")"
    state="$(container_state "$container_name")"
    health="$(container_health "$container_name")"
    if [ "$state" != "running" ] || [ "$health" != "healthy" ]; then
      return 1
    fi
  done < <(services_from_config "$config_json")
  return 0
}

domain_health_failed() {
  local config_json="$1"
  local service_name container_name health has_healthcheck
  while IFS= read -r service_name; do
    [ -n "$service_name" ] || continue
    has_healthcheck="$(service_has_healthcheck "$config_json" "$service_name")"
    if [ "$has_healthcheck" != "true" ]; then
      continue
    fi
    container_name="$(container_name_for_service "$config_json" "$service_name")"
    health="$(container_health "$container_name")"
    if [ "$health" != "healthy" ]; then
      return 0
    fi
  done < <(services_from_config "$config_json")
  return 1
}

log_service_snapshot() {
  local config_json="$1"
  local service_name container_name state health has_healthcheck
  while IFS= read -r service_name; do
    [ -n "$service_name" ] || continue
    container_name="$(container_name_for_service "$config_json" "$service_name")"
    state="$(container_state "$container_name")"
    has_healthcheck="$(service_has_healthcheck "$config_json" "$service_name")"
    health=""
    if [ "$has_healthcheck" = "true" ]; then
      health="$(container_health "$container_name")"
    fi
    printf '[webservices-unit] %s service=%s container=%s state=%s%s\n' "$UNIT_NAME" "$service_name" "$container_name" "${state:-missing}" "${health:+/$health}" >&2
  done < <(services_from_config "$config_json")
}

service_start() {
  local config_json start_time now elapsed running_rc stop_marker reload_marker health_seen_healthy has_any_healthcheck prehealthy_grace_seconds
  [ -n "$UNIT_NAME" ] || die "--unit-name is required for service-start"
  stop_marker="$(stop_marker_path)"
  reload_marker="$(reload_marker_path)"
  clear_markers

  printf '[webservices-unit] compose up/build domain %s via %s\n' "$UNIT_NAME" "$COMPOSE_FILE" >&2
  compose up -d --build --force-recreate
  config_json="$(compose_config_json)"
  health_seen_healthy=0
  has_any_healthcheck="$(service_has_any_healthcheck "$config_json")"
  prehealthy_grace_seconds="$PREHEALTH_TRANSIENT_GRACE_SECONDS"
  if [ "$HEALTH_TIMEOUT_SECONDS" -lt "$prehealthy_grace_seconds" ]; then
    prehealthy_grace_seconds="$HEALTH_TIMEOUT_SECONDS"
  fi

  start_time="$(date +%s)"
  while true; do
    if wait_until_running "$config_json"; then
      if [ -n "$NOTIFY_BIN" ]; then
        "$NOTIFY_BIN" --ready --status="$UNIT_NAME running"
      fi
      printf '[webservices-unit] %s running\n' "$UNIT_NAME" >&2
      break
    fi
    running_rc=$?
    if [ "$running_rc" -eq 1 ]; then
      exit 1
    fi

    now="$(date +%s)"
    elapsed="$((now - start_time))"
    if [ "$elapsed" -ge "$START_TIMEOUT_SECONDS" ]; then
      printf '[webservices-unit] ERROR: %s failed to reach running state after %ss\n' "$UNIT_NAME" "$START_TIMEOUT_SECONDS" >&2
      log_service_snapshot "$config_json"
      exit 1
    fi
    log_service_snapshot "$config_json"
    sleep "$POLL_INTERVAL_SECONDS"
  done

  while true; do
    if wait_until_running "$config_json"; then
      if wait_until_healthy "$config_json"; then
        health_seen_healthy=1
      elif [ "$health_seen_healthy" -eq 1 ] && domain_health_failed "$config_json"; then
        if [ -f "$reload_marker" ]; then
          sleep 1
          continue
        fi
        printf '[webservices-unit] ERROR: %s became unhealthy\n' "$UNIT_NAME" >&2
        log_service_snapshot "$config_json"
        exit 1
      fi
      sleep 5
      continue
    fi
    running_rc=$?
    if [ -f "$stop_marker" ]; then
      clear_markers
      printf '[webservices-unit] %s stopped cleanly\n' "$UNIT_NAME" >&2
      exit 0
    fi
    if [ -f "$reload_marker" ]; then
      sleep 1
      continue
    fi
    now="$(date +%s)"
    elapsed="$((now - start_time))"
    if [ "$running_rc" -eq 2 ] && [ "$elapsed" -lt "$prehealthy_grace_seconds" ]; then
      printf '[webservices-unit] %s tolerating transient startup state after %ss\n' "$UNIT_NAME" "$elapsed" >&2
      log_service_snapshot "$config_json"
      sleep "$POLL_INTERVAL_SECONDS"
      continue
    fi
    if [ "$has_any_healthcheck" = "true" ] && [ "$health_seen_healthy" -eq 0 ]; then
      if [ "$elapsed" -lt "$prehealthy_grace_seconds" ]; then
        printf '[webservices-unit] %s waiting for first healthy state; tolerating transient startup state after %ss\n' "$UNIT_NAME" "$elapsed" >&2
        log_service_snapshot "$config_json"
        sleep "$POLL_INTERVAL_SECONDS"
        continue
      fi
      printf '[webservices-unit] ERROR: %s failed to stay running until first healthy state after %ss\n' "$UNIT_NAME" "$prehealthy_grace_seconds" >&2
      log_service_snapshot "$config_json"
      exit 1
    fi
    if [ "$running_rc" -eq 1 ]; then
      exit 1
    fi
    printf '[webservices-unit] ERROR: %s left running state unexpectedly\n' "$UNIT_NAME" >&2
    log_service_snapshot "$config_json"
    exit 1
  done
}

service_wait_healthy() {
  local config_json start_time now elapsed
  [ -n "$UNIT_NAME" ] || die "--unit-name is required for service-wait-healthy"
  config_json="$(compose_config_json)"
  if [ "$(service_has_any_healthcheck "$config_json")" != "true" ]; then
    printf '[webservices-unit] %s has no healthchecks; healthy gate passes immediately\n' "$UNIT_NAME" >&2
    exit 0
  fi

  start_time="$(date +%s)"
  while true; do
    if wait_until_healthy "$config_json"; then
      printf '[webservices-unit] %s healthy\n' "$UNIT_NAME" >&2
      exit 0
    fi
    now="$(date +%s)"
    elapsed="$((now - start_time))"
    if [ "$elapsed" -ge "$HEALTH_TIMEOUT_SECONDS" ]; then
      printf '[webservices-unit] ERROR: %s failed healthy gate after %ss\n' "$UNIT_NAME" "$HEALTH_TIMEOUT_SECONDS" >&2
      log_service_snapshot "$config_json"
      exit 1
    fi
    log_service_snapshot "$config_json"
    sleep "$POLL_INTERVAL_SECONDS"
  done
}

service_stop() {
  local stop_marker config_json service_name container_name
  stop_marker="$(stop_marker_path)"
  touch "$stop_marker"
  printf '[webservices-unit] compose stop domain %s via %s\n' "$UNIT_NAME" "$COMPOSE_FILE" >&2
  config_json="$(compose_config_json)"
  while IFS= read -r service_name; do
    [ -n "$service_name" ] || continue
    container_name="$(container_name_for_service "$config_json" "$service_name")"
    [ -n "$container_name" ] || continue
    docker_stop_container "$service_name" "$container_name"
  done < <(services_from_config "$config_json")
  while IFS= read -r service_name; do
    [ -n "$service_name" ] || continue
    container_name="$(container_name_for_service "$config_json" "$service_name")"
    [ -n "$container_name" ] || continue
    docker_rm_container "$container_name"
  done < <(services_from_config "$config_json")
}

service_reload() {
  local reload_marker config_json start_time now elapsed running_rc
  [ -n "$UNIT_NAME" ] || die "--unit-name is required for service-reload"
  reload_marker="$(reload_marker_path)"
  touch "$reload_marker"
  trap 'rm -f "$reload_marker"' EXIT
  printf '[webservices-unit] compose rebuild/recreate domain %s via %s\n' "$UNIT_NAME" "$COMPOSE_FILE" >&2
  compose up -d --build --force-recreate
  config_json="$(compose_config_json)"
  start_time="$(date +%s)"
  while true; do
    if wait_until_running "$config_json"; then
      if wait_until_healthy "$config_json"; then
        break
      fi
    else
      running_rc=$?
      if [ "$running_rc" -eq 1 ]; then
        exit 1
      fi
    fi
    now="$(date +%s)"
    elapsed="$((now - start_time))"
    if [ "$elapsed" -ge "$HEALTH_TIMEOUT_SECONDS" ]; then
      printf '[webservices-unit] ERROR: %s reload failed to restore readiness after %ss\n' "$UNIT_NAME" "$HEALTH_TIMEOUT_SECONDS" >&2
      log_service_snapshot "$config_json"
      exit 1
    fi
    sleep "$POLL_INTERVAL_SECONDS"
  done
  rm -f "$reload_marker"
  trap - EXIT
}

job_run() {
  local rc
  [ -n "$SERVICE_NAME" ] || die "--service-name is required for job-run"
  printf '[webservices-unit] compose build/run oneshot %s via %s\n' "$SERVICE_NAME" "$COMPOSE_FILE" >&2
  compose rm -f -s "$SERVICE_NAME" >/dev/null 2>&1 || true
  set +e
  compose up --build --force-recreate --abort-on-container-exit --exit-code-from "$SERVICE_NAME" "$SERVICE_NAME"
  rc=$?
  set -e
  exit "$rc"
}

case "$command_name" in
  service-start)
    service_start
    ;;
  service-stop)
    service_stop
    ;;
  service-reload)
    service_reload
    ;;
  service-wait-healthy)
    service_wait_healthy
    ;;
  job-run)
    job_run
    ;;
  *)
    die "unknown command for systemd-compose-unit.sh: $command_name"
    ;;
esac
