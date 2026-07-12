#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "[service-contract-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

ROOT_DIR="${WEBSERVICES_CONTRACT_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"
catalog="$ROOT_DIR/stack.config/components.json"
contracts="$ROOT_DIR/stack.config/service-contracts.json"
keycloak_realm="$ROOT_DIR/stack.config/keycloak/realm/webservices-realm.json.template"
keycloak_runtime="$ROOT_DIR/stack.config/keycloak/configure-runtime.sh"
profiles="$ROOT_DIR/stack.config/portal-profiles.json"
theme="$ROOT_DIR/stack.config/theme-contract.json"
demo_content="$ROOT_DIR/stack.config/demo-content-contract.json"
pos_exploration="$ROOT_DIR/stack.config/pos-exploration.json"
caddy_hosts="$ROOT_DIR/stack.containers/test-runner/fixtures/caddy-hosts.txt"

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || {
    printf '[service-contract-test] missing required command: %s\n' "$1" >&2
    exit 1
  }
}

require_cmd jq

jq -e '.schemaVersion == 1 and (.components | type == "object")' "$catalog" >/dev/null
jq -e '.contractVersion == 1 and (.components | type == "object")' "$contracts" >/dev/null
jq -e '.schemaVersion == 1 and (.profiles | length >= 6) and .defaultProfile == "employee"' "$profiles" >/dev/null
jq -e '.schemaVersion == 1 and .mode == "dark" and .evidencePolicy.rejectMixedModeScreenshots == true' "$theme" >/dev/null
jq -e '.schemaVersion == 1 and (.personas | length >= 6) and (.requiredEvidence.onlyoffice | index("presentation_edit"))' "$demo_content" >/dev/null
jq -e '.schemaVersion == 1 and .status == "exploration-only" and .excludedFromBuild == true' "$pos_exploration" >/dev/null

catalog_keys="$(mktemp)"
contract_keys="$(mktemp)"
contract_groups="$(mktemp)"
keycloak_groups="$(mktemp)"
trap 'rm -f "$catalog_keys" "$contract_keys" "$contract_groups" "$keycloak_groups"' EXIT

jq -r '.components | keys[]' "$catalog" > "$catalog_keys"
jq -r '.components | keys[]' "$contracts" > "$contract_keys"
if ! diff -u "$catalog_keys" "$contract_keys" >&2; then
  printf '[service-contract-test] component catalog and service contracts must contain the same component keys\n' >&2
  exit 1
fi

jq -e '
  .components
  | all(.[] ;
      (.name | type == "string" and length > 0) and
      (.description | type == "string" and length > 0) and
      (.moduleType | type == "string" and length > 0) and
      (.primaryHost | type == "string" and length > 0) and
      (.routes | type == "array") and
      (.auth.mode | type == "string" and length > 0) and
      (.rbac.groups | type == "array") and
      (.state.mode | type == "string" and length > 0) and
      (.backup.policy | type == "string" and length > 0) and
      (.backup.targets | type == "array") and
      (.restore.drills | type == "array" and length > 0) and
      (.observability.health | type == "boolean") and
      (.observability.logs | type == "boolean") and
      (.evidence.expectations | type == "array" and length > 0) and
      (.screenshots | type == "array") and
      (.portal.visible | type == "boolean") and
      (.portal.description | type == "string") and
      (.slo | type == "object") and
      (.access.offboarding | type == "string" and length > 0) and
      (.artifacts.json | type == "array" and length > 0)
    )
' "$contracts" >/dev/null || {
  printf '[service-contract-test] every contract must declare route/auth/rbac/state/backup/restore/observability/evidence/screenshot/portal/slo/access/artifact metadata\n' >&2
  exit 1
}

jq -e '
  .components
  | all(.[]; all(.routes[]; .rbacEnforcement as $mode |
      ($mode | type == "string") and
      ([
        "edge_group_allow",
        "native_group_mapping",
        "non_browser_token",
        "internal_token",
        "signed_integration",
        "redirect",
        "internal_cli"
      ] | index($mode))
    ))
' "$contracts" >/dev/null || {
  printf '[service-contract-test] every route must declare a supported rbacEnforcement mode\n' >&2
  exit 1
}

jq -e '
  .components
  | all(.[]; all(.routes[]; if .auth == "forward_auth" and .host != "onboarding" then .rbacEnforcement == "edge_group_allow" else true end))
' "$contracts" >/dev/null || {
  printf '[service-contract-test] forward_auth routes must use edge_group_allow unless explicitly exempted\n' >&2
  exit 1
}

jq -e '
  .components
  | to_entries
  | all(.[]; .value as $component |
      if any($component.routes[]?; .ui == true) or $component.portal.visible == true then
        ($component.portal.audience | type == "string") and
        (["client", "employee", "either"] | index($component.portal.audience))
      else
        true
      end
    )
' "$contracts" >/dev/null || {
  printf '[service-contract-test] every web UI or portal-visible service must declare portal.audience as client, employee, or either\n' >&2
  exit 1
}

jq -e '
  .components
  | to_entries
  | all(.[]; .value as $component | all($component.routes[]?; . as $route | if $route.ui == true then
      ($route.audience | type == "string") and
      (["client", "employee", "either"] | index($route.audience))
    else
      true
    end))
' "$contracts" >/dev/null || {
  printf '[service-contract-test] every web UI route must declare route audience as client, employee, or either\n' >&2
  exit 1
}

jq -e '
  .components
  | to_entries
  | all(.[]; .value as $component | ($component.portal.audience // "") != "both" and all($component.routes[]?; . as $route | ($route.audience // "") != "both"))
' "$contracts" >/dev/null || {
  printf '[service-contract-test] portal.audience must not use both; employees inherit access through Keycloak groups\n' >&2
  exit 1
}

jq -e '
  .components.donetick.portal.audience == "client" and
  .components.planka.portal.audience == "client" and
  .components.bookstack.portal.audience == "client" and
  (.components.observability.routes[] | select(.host == "grafana").audience) == "either" and
  (.components.observability.routes[] | select(.host == "alerts").audience) == "employee" and
  .components.erpnext.portal.audience == "employee" and
  .components.huly.portal.audience == "employee"
' "$contracts" >/dev/null || {
  printf '[service-contract-test] service audience defaults must preserve the Portal/Huly/client split\n' >&2
  exit 1
}

jq -r '.components[].rbac.groups[]?' "$contracts" | sort -u > "$contract_groups"
{
  jq -r '.groups[].name' "$keycloak_realm"
  sed -n 's/^[[:space:]]*ensure_group "\([^"]*\)".*/\1/p' "$keycloak_runtime"
} | sort -u > "$keycloak_groups"
if ! comm -23 "$contract_groups" "$keycloak_groups" | sed 's/^/[service-contract-test] missing Keycloak group: /' >&2 | grep -q '^'; then
  :
else
  exit 1
fi

jq -e '
  .components
  | all(.[] | select(.portal.visible == true and .moduleType != "bundle"); (.screenshots | length) > 0)
' "$contracts" >/dev/null || {
  printf '[service-contract-test] visible portal modules must declare screenshot evidence targets\n' >&2
  exit 1
}

jq -e '.components.portal.composeFiles == ["portal.yml"]' "$catalog" >/dev/null
jq -e '.components.homepage.composeFiles == [] and (.components.homepage.dependencies | index("portal"))' "$catalog" >/dev/null
jq -e '.components.apps.dependencies | index("portal") and (index("homepage") | not)' "$catalog" >/dev/null
jq -e '.components.onlyoffice.dependencies | index("seafile")' "$catalog" >/dev/null
jq -e '.components.onlyoffice.capabilities | index("seafile-editor-backend")' "$contracts" >/dev/null
grep -Fq 'ONLYOFFICE_DISABLE_PLUGIN_UPDATES: ${ONLYOFFICE_DISABLE_PLUGIN_UPDATES:-true}' "$ROOT_DIR/stack.compose/onlyoffice.yml"
grep -Fq 'documentserver-pluginsmanager.sh.orig' "$ROOT_DIR/stack.compose/onlyoffice.yml"
jq -e '.components.observability.dependencies | index("crowdsec")' "$catalog" >/dev/null
jq -e '.components.crowdsec.composeFiles == ["crowdsec.yml"]' "$catalog" >/dev/null
jq -e '.components.crowdsec.evidence.expectations | index("crowdsec.simulated_decision")' "$contracts" >/dev/null
grep -Fq './configs/homepage:/app/config' "$ROOT_DIR/stack.compose/portal.yml"

grep -Fq './configs/crowdsec/acquis.yaml:/etc/crowdsec/acquis.yaml:ro' "$ROOT_DIR/stack.compose/crowdsec.yml"
grep -Fq './configs/crowdsec/simulate-alert.sh:/usr/local/bin/webservices-crowdsec-simulate-alert:ro' "$ROOT_DIR/stack.compose/crowdsec.yml"
grep -Fq 'cscli decisions add' "$ROOT_DIR/stack.config/crowdsec/simulate-alert.sh"
grep -Fq 'webservices-simulated-alert' "$ROOT_DIR/stack.config/crowdsec/simulate-alert.sh"
if grep -Fq 'request>uri delete' "$ROOT_DIR/stack.config/caddy/Caddyfile"; then
  printf '[service-contract-test] Caddy access logs must retain request URI for CrowdSec HTTP scenario detection\n' >&2
  exit 1
fi
if grep -Eq 'request>(remote_ip|client_ip)[[:space:]]+ip_mask' "$ROOT_DIR/stack.config/caddy/Caddyfile"; then
  printf '[service-contract-test] Caddy access logs must retain exact source IPs for actionable CrowdSec decisions\n' >&2
  exit 1
fi

if ! grep -REn 'ghcr\.io/gethomepage/homepage|portal:3000' "$ROOT_DIR/stack.compose/portal.yml" "$ROOT_DIR/stack.config/caddy/Caddyfile" >/dev/null; then
  printf '[service-contract-test] portal must run gethomepage and proxy to Homepage port 3000\n' >&2
  exit 1
fi

if ! grep -Fxq 'portal' "$caddy_hosts"; then
  printf '[service-contract-test] Caddy host inventory must include portal\n' >&2
  exit 1
fi

jq -r '.components[].routes[]?.host' "$contracts" | sort -u | while IFS= read -r host; do
  [ -n "$host" ] || continue
  if [ "$host" = "apex" ]; then
    continue
  fi
  if ! grep -Fxq "$host" "$caddy_hosts"; then
    printf '[service-contract-test] route host %s missing from Caddy host inventory\n' "$host" >&2
    exit 1
  fi
done

printf '[service-contract-test] ok\n' >&2
