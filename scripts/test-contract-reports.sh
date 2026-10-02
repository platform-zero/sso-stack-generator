#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "[contract-reports-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
ROOT_DIR="${WEBSERVICES_OVERLAY_ROOT:-$SOURCE_ROOT}"
OVERLAY_ROOT=""
tmp_dir=""
cleanup() {
  [ -z "$OVERLAY_ROOT" ] || rm -rf "$OVERLAY_ROOT"
  [ -z "$tmp_dir" ] || rm -rf "$tmp_dir"
}
trap cleanup EXIT
if [ "$ROOT_DIR" = "$SOURCE_ROOT" ] && [ ! -f "$ROOT_DIR/stack.config/components.json" ] && [ -f "$SOURCE_ROOT/dist/build/build/stack.config/components.json" ]; then
  ROOT_DIR="$SOURCE_ROOT/dist/build/build"
elif [ "$ROOT_DIR" = "$SOURCE_ROOT" ] && [ ! -f "$ROOT_DIR/stack.config/components.json" ] && [ -f "$SOURCE_ROOT/dist/build/stack.config/components.json" ]; then
  ROOT_DIR="$SOURCE_ROOT/dist/build"
fi
if [ -d "$ROOT_DIR/stack.config/components.external" ] || [ -d "$ROOT_DIR/stack.config/service-contracts.external" ]; then
  OVERLAY_ROOT="$(mktemp -d)"
  cp -a "$ROOT_DIR/." "$OVERLAY_ROOT/"
  ROOT_DIR="$OVERLAY_ROOT"
  # shellcheck source=scripts/lib/components.sh
  source "$SOURCE_ROOT/scripts/lib/components.sh"
  component_catalog_merge_external "$ROOT_DIR/stack.config/components.json"
  service_contracts_merge_external "$ROOT_DIR/stack.config/service-contracts.json"
fi
tmp_dir="$(mktemp -d)"

lock_file="$tmp_dir/components.lock.json"
reports_dir="$tmp_dir/reports"

cat > "$lock_file" <<'EOF_JSON'
{
  "generatedAt": "test",
  "components": ["core", "portal", "seafile", "onlyoffice", "crowdsec"]
}
EOF_JSON

"$SOURCE_ROOT/scripts/generate-contract-reports.sh" \
  --catalog "$ROOT_DIR/stack.config/components.json" \
  --contracts "$ROOT_DIR/stack.config/service-contracts.json" \
  --profiles "$ROOT_DIR/stack.config/portal-profiles.json" \
  --theme "$ROOT_DIR/stack.config/theme-contract.json" \
  --demo-content "$ROOT_DIR/stack.config/demo-content-contract.json" \
  --pos-exploration "$ROOT_DIR/stack.config/pos-exploration.json" \
  --lock "$lock_file" \
  --output-dir "$reports_dir"

for report in contracts module-selection evidence-coverage backup-topology access-offboarding slo security profile-widgets theme demo-content secret-inventory footprint availability drift-plan pos-exploration; do
  jq empty "$reports_dir/$report.json"
done

jq -e '.components.portal.name == "Homepage Dashboard"' "$reports_dir/contracts.json" >/dev/null
jq -e '.modules[] | select(.component == "portal" and .portal.visible == true)' "$reports_dir/module-selection.json" >/dev/null
jq -e '.components[] | select(.component == "onlyoffice" and (.evidence.expectations | index("seafile.docx.edit")))' "$reports_dir/evidence-coverage.json" >/dev/null
jq -e '.components[] | select(.component == "seafile" and .backup.policy == "kopia")' "$reports_dir/backup-topology.json" >/dev/null
jq -e '.components[] | select(.component == "portal" and .access.offboarding == "keycloak_group_removal")' "$reports_dir/access-offboarding.json" >/dev/null
jq -e '.components[] | select(.component == "core" and .slo.availability == "99.0%")' "$reports_dir/slo.json" >/dev/null
jq -e '.components[] | select(.component == "crowdsec" and (.evidence | index("crowdsec.simulated_decision")))' "$reports_dir/security.json" >/dev/null
jq -e '.profiles[] | select(.id == "employee" and .defaultView == "work-home")' "$reports_dir/profile-widgets.json" >/dev/null
jq -e '.theme.evidencePolicy.playwrightColorScheme == "dark"' "$reports_dir/theme.json" >/dev/null
jq -e '.requiredEvidence.onlyoffice | index("spreadsheet_edit")' "$reports_dir/demo-content.json" >/dev/null
jq -e '.secrets[] | select(.component == "seafile" and .rotation == "site-owned SOPS update and redeploy")' "$reports_dir/secret-inventory.json" >/dev/null
jq -e '.externalRequirements | index("backup_storage")' "$reports_dir/footprint.json" >/dev/null
jq -e '.availabilityModel == "single-host" and (.excluded | index("live failover"))' "$reports_dir/availability.json" >/dev/null
jq -e '.checks | index("Caddy routes match generated Caddyfile")' "$reports_dir/drift-plan.json" >/dev/null
jq -e '.pos.status == "exploration-only" and .pos.excludedFromBuild == true' "$reports_dir/pos-exploration.json" >/dev/null

printf '[contract-reports-test] ok\n' >&2
