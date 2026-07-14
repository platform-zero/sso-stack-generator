#!/usr/bin/env bash
# Deployment reconciliation and post-deploy verification helpers.

join_array_limited() {
  local max_items="$1"
  shift
  local items=("$@")
  local total="${#items[@]}"
  local limit="$max_items"
  local output=()

  if [ "$limit" -le 0 ]; then
    limit="$total"
  fi
  if [ "$limit" -gt "$total" ]; then
    limit="$total"
  fi

  local index
  for ((index = 0; index < limit; index++)); do
    output+=("${items[$index]}")
  done
  if [ "$total" -gt "$limit" ]; then
    output+=("...+$((total - limit)) more")
  fi

  local joined=""
  local item
  for item in "${output[@]}"; do
    if [ -n "$joined" ]; then
      joined="$joined "
    fi
    joined="${joined}${item}"
  done
  printf '%s\n' "$joined"
}

matching_systemd_jobs() {
  user_systemd_list_matching_jobs_raw | awk '{print $1 ":" $2 "/" $3}'
}

interesting_systemd_units() {
  user_systemd_list_matching_units | awk '
    $3 == "activating" || $3 == "deactivating" || $3 == "failed" || $4 == "failed" {
      print $1 ":" $3 "/" $4
    }
  '
}

unique_unit_names_limited() {
  local limit="$1"
  shift

  local entries=("$@")
  local names=()
  local seen=" "
  local entry unit_name

  for entry in "${entries[@]}"; do
    [ -n "$entry" ] || continue
    unit_name="${entry%%:*}"
    [ -n "$unit_name" ] || continue
    if [[ "$seen" == *" $unit_name "* ]]; then
      continue
    fi
    names+=("$unit_name")
    seen="$seen$unit_name "
    if [ "${#names[@]}" -ge "$limit" ]; then
      break
    fi
  done

  if [ "${#names[@]}" -eq 0 ]; then
    printf 'none\n'
    return
  fi
  printf '%s\n' "$(join_array_limited "$limit" "${names[@]}")"
}

compact_unit_label() {
  local unit_name="$1"
  unit_name="${unit_name#webservices-}"
  unit_name="${unit_name%.service}"
  unit_name="${unit_name%.target}"
  printf '%s\n' "$unit_name"
}

compact_blockers_from_jobs() {
  local limit="$1"
  shift
  local jobs=("$@")
  local non_targets=()
  local targets=()
  local seen=" "
  local job unit_name

  for job in "${jobs[@]}"; do
    [ -n "$job" ] || continue
    unit_name="${job%%:*}"
    [ -n "$unit_name" ] || continue
    if [[ "$seen" == *" $unit_name "* ]]; then
      continue
    fi
    seen="$seen$unit_name "
    if [[ "$unit_name" == *.target ]]; then
      targets+=("$unit_name")
    else
      non_targets+=("$unit_name")
    fi
  done

  local preferred=()
  if [ "${#non_targets[@]}" -gt 0 ]; then
    preferred=("${non_targets[@]}")
  else
    preferred=("${targets[@]}")
  fi

  if [ "${#preferred[@]}" -eq 0 ]; then
    printf 'none\n'
    return
  fi

  local formatted=()
  local total="${#preferred[@]}"
  local max="$limit"
  local i
  if [ "$max" -le 0 ] || [ "$max" -gt "$total" ]; then
    max="$total"
  fi
  for ((i = 0; i < max; i++)); do
    formatted+=("$(compact_unit_label "${preferred[$i]}")")
  done

  local out
  out="$(IFS=,; printf '%s' "${formatted[*]}")"
  if [ "$total" -gt "$max" ]; then
    out="$out,+$((total - max))"
  fi
  if [ "${#non_targets[@]}" -gt 0 ] && [ "${#targets[@]}" -gt 0 ]; then
    out="$out (+${#targets[@]} targets)"
  fi
  printf '%s\n' "$out"
}

summarize_jobs_brief() {
  local jobs=("$@")
  local total waiting running other
  total="${#jobs[@]}"
  waiting=0
  running=0
  other=0

  local job state
  for job in "${jobs[@]}"; do
    state="${job##*/}"
    case "$state" in
      waiting) waiting=$((waiting + 1)) ;;
      running) running=$((running + 1)) ;;
      *) other=$((other + 1)) ;;
    esac
  done

  printf 'jobs=%s (w:%s r:%s o:%s)' "$total" "$waiting" "$running" "$other"
}

summarize_units_brief() {
  local units=("$@")
  local total activating deactivating failed other
  total="${#units[@]}"
  activating=0
  deactivating=0
  failed=0
  other=0

  local unit activity substate
  for unit in "${units[@]}"; do
    activity="${unit#*:}"
    activity="${activity%%/*}"
    substate="${unit##*/}"
    case "$activity/$substate" in
      activating/*) activating=$((activating + 1)) ;;
      deactivating/*) deactivating=$((deactivating + 1)) ;;
      */failed) failed=$((failed + 1)) ;;
      *) other=$((other + 1)) ;;
    esac
  done

  printf 'units=%s (up:%s down:%s fail:%s other:%s)' "$total" "$activating" "$deactivating" "$failed" "$other"
}

wait_for_target_reconcile() {
  local start_time now elapsed target_state progress_line last_progress_line last_log_time
  local jobs=()
  local interesting_units=()
  local failed_units=()
  start_time="$(date +%s)"
  last_log_time="$start_time"
  last_progress_line=""

  while true; do
    mapfile -t jobs < <(matching_systemd_jobs)
    mapfile -t interesting_units < <(interesting_systemd_units)
    mapfile -t failed_units < <(user_systemd_failed_units)
    target_state="$(user_systemctl is-active webservices.target 2>/dev/null || true)"

    if [ "${#failed_units[@]}" -gt 0 ]; then
      local failed_unit has_restart_job filtered_failed=()
      for failed_unit in "${failed_units[@]}"; do
        has_restart_job=0
        for job in "${jobs[@]}"; do
          if [ "${job%%:*}" = "$failed_unit" ]; then
            has_restart_job=1
            break
          fi
        done
        [ "$has_restart_job" = "1" ] || filtered_failed+=("$failed_unit")
      done
      if [ "${#filtered_failed[@]}" -gt 0 ]; then
        deploy_log "systemd reconcile failed units: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${filtered_failed[@]}")"
        return 1
      fi
    fi

    if [ "${#jobs[@]}" -eq 0 ]; then
      if [ "$target_state" = "active" ]; then
        deploy_log "systemd reconcile complete (target=$target_state)"
        return 0
      fi
      deploy_log "systemd reconcile finished without outstanding jobs, but target state is '$target_state'"
      return 1
    fi

    now="$(date +%s)"
    elapsed="$((now - start_time))"

    progress_line="$(printf '[reconcile t+%ss] target=%s %s' "$elapsed" "$target_state" "$(summarize_jobs_brief "${jobs[@]}")")"
    if [ "${#interesting_units[@]}" -gt 0 ]; then
      progress_line="$progress_line $(summarize_units_brief "${interesting_units[@]}")"
    fi
    progress_line="$progress_line blockers=$(compact_blockers_from_jobs "$SYSTEMD_PROGRESS_MAX_ITEMS" "${jobs[@]}")"

    if [ "$progress_line" != "$last_progress_line" ] || [ "$((now - last_log_time))" -ge "$SYSTEMD_PROGRESS_HEARTBEAT_SECONDS" ]; then
      deploy_log "$progress_line"
      last_progress_line="$progress_line"
      last_log_time="$now"
    fi

    if [ "$elapsed" -ge "$SYSTEMD_RECONCILE_TIMEOUT_SECONDS" ]; then
      deploy_log "timed out waiting for systemd reconcile after ${elapsed}s"
      return 1
    fi

    sleep "$SYSTEMD_PROGRESS_INTERVAL_SECONDS"
  done
}

reconcile_target() {
  local graph_file aux_targets=() excluded_aux_targets=() main_action aux_action
  graph_file="$BUNDLE_ROOT/stack.systemd/graph.json"
  mapfile -t aux_targets < <(default_auxiliary_targets_from_graph "$graph_file")
  mapfile -t excluded_aux_targets < <(
    jq -r '
      (.defaultTarget.wantsTargets // []) as $wanted
      | [(.auxiliaryTargets // [] | .[]?.name | . as $target | select($target != null and (($wanted | index($target)) == null)))]
      | .[]
    ' "$graph_file"
  )

  if user_systemctl is-active --quiet webservices.target; then
    main_action="reconciling"
  else
    main_action="starting"
  fi
  aux_action="start"

  if [ "${#aux_targets[@]}" -gt 0 ]; then
    deploy_log "$main_action webservices.target and default auxiliary targets under systemd --user: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${aux_targets[@]}")"
    user_systemctl "$aux_action" --no-block "${aux_targets[@]}"
  else
    deploy_log "$main_action webservices.target under systemd --user (no auxiliary targets declared)"
  fi

  if [ "${#excluded_aux_targets[@]}" -gt 0 ]; then
    deploy_log "stopping non-default auxiliary targets under systemd --user: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${excluded_aux_targets[@]}")"
    user_systemctl stop --no-block "${excluded_aux_targets[@]}" || true
    user_systemctl reset-failed
  fi

  user_systemctl "${aux_action}" --no-block webservices.target
  wait_for_target_reconcile
}

reload_deploy_reconcile_units() {
  local unit
  local configured_units="${DEPLOY_RECONCILE_RELOAD_UNITS:-webservices-caddy.service}"

  if [ "$PARTIAL_DEPLOY" = "1" ]; then
    deploy_log "skipping post-reconcile reloads for scoped deploy"
    return 0
  fi

  for unit in $configured_units; do
    [ -f "$BUNDLE_ROOT/systemd-user/$unit" ] || continue
    if ! user_systemctl is-active --quiet "$unit"; then
      continue
    fi
    deploy_log "reloading deploy reconciliation unit under systemd --user: $unit"
    user_systemctl reload "$unit"
  done
}

restart_post_reconcile_units() {
  local unit
  local units=(
    webservices-keycloak-configure.service
    webservices-keycloak-auth-gateway.service
  )

  for unit in "${units[@]}"; do
    [ -f "$BUNDLE_ROOT/systemd-user/$unit" ] || continue
    deploy_log "restarting post-reconcile unit under systemd --user: $unit"
    user_systemctl reset-failed "$unit" || true
    user_systemctl restart "$unit"
  done
}

reload_deploy_sensitive_units() {
  local unit_name units=()
  local configured_units="${DEPLOY_RELOAD_UNITS:-webservices-caddy.service webservices-onboarding.service webservices-synapse.service webservices-forgejo.service webservices-homeassistant.service webservices-sogo.service webservices-jellyfin.service webservices-donetick.service webservices-erpnext-backend.service webservices-erpnext-websocket.service webservices-erpnext-queue-short.service webservices-erpnext-queue-long.service webservices-erpnext-scheduler.service webservices-erpnext.service}"

  if [ "${DEPLOY_SKIP_SENSITIVE_RELOADS:-1}" = "1" ]; then
    deploy_log "skipping deploy-sensitive reloads; target reconcile will handle final state"
    return 0
  fi

  for unit_name in $configured_units; do
    [ -f "$BUNDLE_ROOT/systemd-user/$unit_name" ] || continue
    if ! grep -q '^ExecReload=' "$BUNDLE_ROOT/systemd-user/$unit_name"; then
      continue
    fi
    if user_systemctl is-active --quiet "$unit_name"; then
      units+=("$unit_name")
    fi
  done

  if [ "${#units[@]}" -eq 0 ]; then
    deploy_log "no active deploy-sensitive lifecycle units need reload"
    return 0
  fi

  deploy_log "reloading active deploy-sensitive lifecycle units under systemd --user: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${units[@]}")"
  for unit_name in "${units[@]}"; do
    if ! user_systemctl reload "$unit_name"; then
      deploy_log "warning: deploy-sensitive reload failed for $unit_name; target reconcile will handle final state"
    fi
  done
}

reload_runtime_config_units() {
  local service_name unit_name seen=" "
  local services=() reload_units=() restart_units=()
  local runtime_config_json changed_path service_output

  runtime_config_json="$(mktemp "${TMPDIR:-/tmp}/webservices-runtime-config.XXXXXX.json")"
  runtime_contract_config_snapshot "$runtime_config_json"

  if [ "$RUNTIME_CONFIG_CHANGE_STATUS" = "known" ]; then
    if [ "${#RUNTIME_CONFIG_CHANGED_PATHS[@]}" -eq 0 ]; then
      deploy_log "no changed runtime-config files detected"
      rm -f "$runtime_config_json"
      return 0
    fi
    for changed_path in "${RUNTIME_CONFIG_CHANGED_PATHS[@]}"; do
      [ -n "$changed_path" ] || continue
      service_output="$(services_for_runtime_config_path "$changed_path" "$runtime_config_json")"
      while IFS= read -r service_name; do
        append_unique "$service_name" services
      done <<< "$service_output"
    done
    deploy_log "changed runtime-config files: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${RUNTIME_CONFIG_CHANGED_PATHS[@]}")"
  else
    deploy_log "previous runtime-config manifest is missing; checking all runtime-config mounts"
    mapfile -t services < <(
      jq -r '
          .services
          | to_entries[]
          | select(
              any((.value.volumes // [])[]?;
                (type == "object")
                and (.type == "bind")
                and (((.source // "") | test("(^|/)runtime/configs/")))
              )
            )
          | .key
        ' "$runtime_config_json" | sort
    )
  fi
  rm -f "$runtime_config_json"

  for service_name in "${services[@]}"; do
    [ -n "$service_name" ] || continue
    unit_name="$(unit_for_runtime_service "$service_name")"
    [ -f "$BUNDLE_ROOT/systemd-user/$unit_name" ] || continue
    if ! user_systemctl is-active --quiet "$unit_name"; then
      continue
    fi
    if [[ "$seen" == *" $unit_name "* ]]; then
      continue
    fi
    seen="$seen$unit_name "
    if grep -q '^ExecReload=' "$BUNDLE_ROOT/systemd-user/$unit_name"; then
      reload_units+=("$unit_name")
    else
      restart_units+=("$unit_name")
    fi
  done

  if [ "${#reload_units[@]}" -eq 0 ] && [ "${#restart_units[@]}" -eq 0 ]; then
    deploy_log "no active runtime-config lifecycle units need refresh"
    return 0
  fi

  if [ "${#reload_units[@]}" -gt 0 ]; then
    deploy_log "reloading active lifecycle units with runtime config mounts: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${reload_units[@]}")"
    for unit_name in "${reload_units[@]}"; do
      deploy_log "reloading runtime-config lifecycle unit under systemd --user: $unit_name"
      user_systemctl reload "$unit_name"
    done
  fi
  if [ "${#restart_units[@]}" -gt 0 ]; then
    deploy_log "restarting active lifecycle units with runtime config mounts: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${restart_units[@]}")"
    user_systemctl reset-failed "${restart_units[@]}" || true
    for unit_name in "${restart_units[@]}"; do
      deploy_log "restarting runtime-config lifecycle unit under systemd --user: $unit_name"
      user_systemctl restart "$unit_name"
    done
  fi
}

recreate_env_sensitive_containers() {
  local container_name
  local configured_containers="${DEPLOY_RECREATE_ENV_CONTAINERS:-opensearch nats airflow-init airflow-webserver airflow-scheduler ingestion-runner embedding-gpu keycloak bookstack bookstack-procedural-docs onlyoffice mailserver seafile}"

  for container_name in $configured_containers; do
    if container_runtime container inspect "$container_name" >/dev/null 2>&1; then
      deploy_log "removing env-sensitive container for recreate: $container_name"
      container_runtime rm -f "$container_name" >/dev/null
    fi
  done
}

reload_changed_built_image_units() {
  local service_name image_ref before_id after_id container_image_id unit_name
  local units=()
  local seen=" "

  while IFS=$'\t' read -r service_name image_ref; do
    [ -n "$service_name" ] || continue
    before_id="${BUILT_IMAGE_IDS_BEFORE[$service_name]:-}"
    after_id="$(image_id_for_ref "$image_ref")"
    container_image_id="$(container_image_id_for_service "$service_name")"
    if [ -n "$before_id" ] && [ "$before_id" = "$after_id" ] && { [ -z "$container_image_id" ] || [ "$container_image_id" = "$after_id" ]; }; then
      continue
    fi

    unit_name="$(unit_for_runtime_service "$service_name")"
    [ -f "$BUNDLE_ROOT/systemd-user/$unit_name" ] || continue
    if ! grep -q '^ExecReload=' "$BUNDLE_ROOT/systemd-user/$unit_name"; then
      continue
    fi
    if ! user_systemctl is-active --quiet "$unit_name"; then
      continue
    fi
    if [[ "$seen" == *" $unit_name "* ]]; then
      continue
    fi
    seen="$seen$unit_name "
    units+=("$unit_name")
  done < <(built_image_services)

  if [ "${#units[@]}" -eq 0 ]; then
    deploy_log "no active built-image lifecycle units changed"
    return 0
  fi

  deploy_log "reloading active lifecycle units with changed built images under systemd --user: $(join_array_limited "$SYSTEMD_PROGRESS_MAX_ITEMS" "${units[@]}")"
  user_systemctl reload "${units[@]}"
}

restart_deploy_job_units() {
  local unit_name
  local configured_units="${DEPLOY_RESTART_JOB_UNITS:-webservices-volume-init.service webservices-postgres-ssd-bootstrap.service webservices-erpnext-configurator.service webservices-erpnext-bootstrap.service}"

  for unit_name in $configured_units; do
    [ -f "$BUNDLE_ROOT/systemd-user/$unit_name" ] || continue
    deploy_log "restarting deploy job unit under systemd --user: $unit_name"
    user_systemctl reset-failed "$unit_name" || true
    user_systemctl restart "$unit_name"
  done
}

refresh_infra_units() {
  deploy_log "refreshing container networks and volumes from rendered infra config"
  "$SCRIPT_DIR/lib/systemd-container-infra.sh" ensure-networks \
    --config-file "$BUNDLE_ROOT/systemd-user/infra/networks.json" \
    --env-file "$DEPLOY_ROOT/runtime/stack.env"
  "$SCRIPT_DIR/lib/systemd-container-infra.sh" ensure-volumes \
    --config-file "$BUNDLE_ROOT/systemd-user/infra/volumes.json" \
    --env-file "$DEPLOY_ROOT/runtime/stack.env"
}

run_deploy_audit() {
  if [ ! -x "$SCRIPT_DIR/deploy/deploy-audit.py" ]; then
    deploy_log "deploy audit helper unavailable in this bundle; skipping deploy audit command: $*"
    return 0
  fi
  "$SCRIPT_DIR/deploy/deploy-audit.py" "$@"
}

validate_runtime_secrets() {
  run_deploy_audit validate-secrets \
    --bundle-root "$BUNDLE_ROOT" \
    --env-file "$DEPLOY_ROOT/runtime/stack.env" \
    --project-name "$PROJECT_NAME"
}

write_storage_report() {
  run_deploy_audit storage-report \
    --bundle-root "$BUNDLE_ROOT" \
    --env-file "$DEPLOY_ROOT/runtime/stack.env" \
    --project-name "$PROJECT_NAME" \
    --output "$BUNDLE_ROOT/reports/storage-audit.json"
}

cleanup_optional_orphan_containers() {
  run_deploy_audit cleanup-optional-orphans \
    --bundle-root "$BUNDLE_ROOT" \
    --env-file "$DEPLOY_ROOT/runtime/stack.env" \
    --project-name "$PROJECT_NAME"
}

write_module_deployment_report() {
  run_deploy_audit module-report \
    --bundle-root "$BUNDLE_ROOT" \
    --env-file "$DEPLOY_ROOT/runtime/stack.env" \
    --project-name "$PROJECT_NAME" \
    --output "$BUNDLE_ROOT/reports/module-deployment.json" \
    --strict
}

validate_qdrant_schema() {
  run_deploy_audit qdrant-schema \
    --bundle-root "$BUNDLE_ROOT" \
    --env-file "$DEPLOY_ROOT/runtime/stack.env" \
    --project-name "$PROJECT_NAME"
}

wait_for_final_readiness() {
  "$SCRIPT_DIR/lib/wait-ready.sh" \
    --bundle-dir "$BUNDLE_ROOT" \
    --runtime-env-file "$DEPLOY_ROOT/runtime/stack.env" \
    --project-name "$PROJECT_NAME" \
    --timeout-seconds "${DEPLOY_FINAL_READINESS_TIMEOUT_SECONDS:-900}" \
    --interval-seconds "${DEPLOY_FINAL_READINESS_INTERVAL_SECONDS:-5}"
}
