#!/usr/bin/env bash

# shellcheck source=scripts/lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/common.sh"

deploy_scope_validate_unit_reference() {
  local unit_name="$1"
  [[ "$unit_name" =~ ^[A-Za-z0-9][A-Za-z0-9_.@:-]*\.(service|target)$ ]]
}

deploy_scope_normalize_unit() {
  local requested_unit="$1"
  local unit_prefix="$2"
  local normalized

  case "$requested_unit" in
    *.service|*.target)
      normalized="$requested_unit"
      ;;
    "$unit_prefix"-*)
      normalized="$requested_unit.service"
      ;;
    *)
      normalized="$unit_prefix-$requested_unit.service"
      ;;
  esac

  if ! deploy_scope_validate_unit_reference "$normalized"; then
    die "invalid scoped systemd unit reference: $requested_unit"
  fi
  printf '%s\n' "$normalized"
}

deploy_scope_unit_domain() {
  local unit_name="$1"
  local unit_prefix="$2"
  local domain_name

  deploy_scope_validate_unit_reference "$unit_name" || die "invalid scoped systemd unit reference: $unit_name"
  [[ "$unit_name" == *.service ]] || return 0
  [[ "$unit_name" == "$unit_prefix"-* ]] || return 0

  domain_name="${unit_name#"$unit_prefix"-}"
  domain_name="${domain_name%.service}"
  [ -n "$domain_name" ] || return 0
  printf '%s\n' "$domain_name"
}

deploy_scope_services_for_unit() {
  local requested_unit="$1"
  local unit_prefix="$2"
  local graph_file="$3"
  local runtime_config_json="$4"
  local unit_name domain_name services

  [ -f "$graph_file" ] || die "missing systemd graph: $graph_file"
  [ -f "$runtime_config_json" ] || die "missing runtime model config JSON: $runtime_config_json"

  unit_name="$(deploy_scope_normalize_unit "$requested_unit" "$unit_prefix")"
  if [[ "$unit_name" == *.target ]]; then
    jq -r --arg target "$unit_name" '
      . as $graph
      | ($runtime[0]) as $runtimeConfig
      | ($graph.lifecycleDomains // []) as $lifecycleDomains
      | ($graph.onDemandServices // []) as $onDemandServices
      | ($graph.onDemandDomains // []) as $onDemandDomains
      | ($graph.excludedServices // []) as $excludedServices
      | (([$graph.defaultTarget] + ($graph.auxiliaryTargets // [])) | map(select(. != null))) as $targets
      | ($lifecycleDomains | map(.services[]?) | unique) as $assignedLifecycleServices
      | ($runtimeConfig.services | keys) as $runtimeServices
      | def target_by_name($name):
          ([$targets[]? | select(.name == $name)] | first // null);
        def lifecycle_domain_for_service($service):
          ([$lifecycleDomains[]? | select(((.services // []) | index($service)) != null)] | first // null);
        def lifecycle_domain_services($domain):
          ([$lifecycleDomains[]? | select(.name == $domain) | .services] | first // []);
        def service_domain_services($service):
          (lifecycle_domain_for_service($service) | if . == null then [$service] else (.services // []) end);
        def implicit_domain_services:
          ($runtimeServices - $excludedServices - $assignedLifecycleServices);
        def is_lifecycle_domain_on_demand($domain):
          (($onDemandDomains | index($domain.name)) != null)
          or (((($domain.services // []) - $onDemandServices) | length) == 0);
        def default_direct_services:
          (
            ($lifecycleDomains | map(select(is_lifecycle_domain_on_demand(.) | not) | .services) | add // [])
            + implicit_domain_services
          );
        def target_services($targetName; $seen):
          if ($seen | index($targetName)) != null then
            []
          else
            (target_by_name($targetName)) as $targetObject
            | if $targetObject == null then
                error("unknown target unit: " + $targetName)
              else
                (
                  (($targetObject.services // []) | map(service_domain_services(.)) | add // [])
                  + (($targetObject.domains // []) | map(lifecycle_domain_services(.)) | add // [])
                  + (if (($targetObject.includeUnitsFromNonOnDemandDomains // false) == true) then default_direct_services else [] end)
                  + (($targetObject.wantsTargets // []) | map(target_services(.; $seen + [$targetName])) | add // [])
                )
              end
          end;
        target_services($target; [])
        | map(select(($runtimeConfig.services[.] // null) != null))
        | unique[]
    ' --slurpfile runtime "$runtime_config_json" "$graph_file" || return $?
    return 0
  fi

  domain_name="$(deploy_scope_unit_domain "$unit_name" "$unit_prefix")"
  [ -n "$domain_name" ] || return 0

  services="$(jq -r --arg domain "$domain_name" '
    .lifecycleDomains[]?
    | select(.name == $domain)
    | .services[]?
  ' "$graph_file")"
  if [ -n "$services" ]; then
    printf '%s\n' "$services"
    return 0
  fi

  if jq -e --arg service "$domain_name" '.services[$service] != null' "$runtime_config_json" >/dev/null; then
    printf '%s\n' "$domain_name"
  fi
}
