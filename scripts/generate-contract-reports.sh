#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
CATALOG="$ROOT_DIR/stack.config/components.json"
CONTRACTS="$ROOT_DIR/stack.config/service-contracts.json"
PROFILES="$ROOT_DIR/stack.config/portal-profiles.json"
THEME="$ROOT_DIR/stack.config/theme-contract.json"
DEMO_CONTENT="$ROOT_DIR/stack.config/demo-content-contract.json"
POS_EXPLORATION="$ROOT_DIR/stack.config/pos-exploration.json"
LOCK_FILE=""
OUTPUT_DIR=""

usage() {
  cat <<'EOF_USAGE'
Usage:
  ./scripts/generate-contract-reports.sh --lock <components.lock.json> --output-dir <dir> [--catalog <components.json>] [--contracts <service-contracts.json>]

Generates JSON-first reports for selected components: contracts, module
selection, evidence coverage, backup topology, access/offboarding, SLOs, and
security posture.
EOF_USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --catalog)
      CATALOG="$2"
      shift
      ;;
    --contracts)
      CONTRACTS="$2"
      shift
      ;;
    --profiles)
      PROFILES="$2"
      shift
      ;;
    --theme)
      THEME="$2"
      shift
      ;;
    --demo-content)
      DEMO_CONTENT="$2"
      shift
      ;;
    --pos-exploration)
      POS_EXPLORATION="$2"
      shift
      ;;
    --lock)
      LOCK_FILE="$2"
      shift
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '[contract-reports] ERROR: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

[ -f "$CATALOG" ] || { printf '[contract-reports] ERROR: missing catalog: %s\n' "$CATALOG" >&2; exit 1; }
[ -f "$CONTRACTS" ] || { printf '[contract-reports] ERROR: missing contracts: %s\n' "$CONTRACTS" >&2; exit 1; }
[ -f "$PROFILES" ] || { printf '[contract-reports] ERROR: missing profiles: %s\n' "$PROFILES" >&2; exit 1; }
[ -f "$THEME" ] || { printf '[contract-reports] ERROR: missing theme contract: %s\n' "$THEME" >&2; exit 1; }
[ -f "$DEMO_CONTENT" ] || { printf '[contract-reports] ERROR: missing demo content contract: %s\n' "$DEMO_CONTENT" >&2; exit 1; }
[ -f "$POS_EXPLORATION" ] || { printf '[contract-reports] ERROR: missing POS exploration contract: %s\n' "$POS_EXPLORATION" >&2; exit 1; }
[ -f "$LOCK_FILE" ] || { printf '[contract-reports] ERROR: missing lock file: %s\n' "$LOCK_FILE" >&2; exit 1; }
[ -n "$OUTPUT_DIR" ] || { printf '[contract-reports] ERROR: missing --output-dir\n' >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { printf '[contract-reports] ERROR: missing required command: jq\n' >&2; exit 1; }

mkdir -p "$OUTPUT_DIR"
generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

selected_filter='
  def selected_contracts:
    ($lock[0].components // []) as $selected
    | $selected
    | map({component: ., contract: $contracts[0].components[.]})
    | map(select(.contract != null));
'

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile catalog "$CATALOG" \
  --slurpfile contracts "$CONTRACTS" \
  --slurpfile lock "$LOCK_FILE" \
  "$selected_filter
  {
    generatedAt: \$generatedAt,
    contractVersion: \$contracts[0].contractVersion,
    components: (selected_contracts | map({key: .component, value: .contract}) | from_entries)
  }" > "$OUTPUT_DIR/contracts.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile catalog "$CATALOG" \
  --slurpfile contracts "$CONTRACTS" \
  --slurpfile lock "$LOCK_FILE" \
  "$selected_filter
  {
    generatedAt: \$generatedAt,
    selectedComponents: \$lock[0].components,
    defaultComponents: \$catalog[0].defaultComponents,
    modules: (
      selected_contracts
      | map({
          component,
          name: .contract.name,
          moduleType: .contract.moduleType,
          primaryHost: .contract.primaryHost,
          portal: .contract.portal
        })
    )
  }" > "$OUTPUT_DIR/module-selection.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile contracts "$CONTRACTS" \
  --slurpfile lock "$LOCK_FILE" \
  "$selected_filter
  {
    generatedAt: \$generatedAt,
    components: (
      selected_contracts
      | map({
          component,
          evidence: .contract.evidence,
          screenshots: .contract.screenshots,
          artifactJson: .contract.artifacts.json
        })
    )
  }" > "$OUTPUT_DIR/evidence-coverage.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile contracts "$CONTRACTS" \
  --slurpfile lock "$LOCK_FILE" \
  "$selected_filter
  {
    generatedAt: \$generatedAt,
    components: (
      selected_contracts
      | map({
          component,
          state: .contract.state,
          backup: .contract.backup,
          restore: .contract.restore
        })
    )
  }" > "$OUTPUT_DIR/backup-topology.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile contracts "$CONTRACTS" \
  --slurpfile lock "$LOCK_FILE" \
  "$selected_filter
  {
    generatedAt: \$generatedAt,
    components: (
      selected_contracts
      | map({
          component,
          auth: .contract.auth,
          rbac: .contract.rbac,
          access: .contract.access
        })
    )
  }" > "$OUTPUT_DIR/access-offboarding.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile contracts "$CONTRACTS" \
  --slurpfile lock "$LOCK_FILE" \
  "$selected_filter
  {
    generatedAt: \$generatedAt,
    components: (
      selected_contracts
      | map({
          component,
          slo: .contract.slo,
          observability: .contract.observability
        })
    )
  }" > "$OUTPUT_DIR/slo.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile contracts "$CONTRACTS" \
  --slurpfile lock "$LOCK_FILE" \
  "$selected_filter
  {
    generatedAt: \$generatedAt,
    components: (
      selected_contracts
      | map(select(.contract.moduleType != \"bundle\"))
      | map({
          component,
          routes: .contract.routes,
          auth: .contract.auth,
          rbac: .contract.rbac,
          securityOwner: .contract.access.owner,
          evidence: (.contract.evidence.expectations | map(select(startswith(\"crowdsec\") or startswith(\"auth\") or contains(\"denied\") or contains(\"boundary\"))))
        })
    )
  }" > "$OUTPUT_DIR/security.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile profiles "$PROFILES" \
  --slurpfile contracts "$CONTRACTS" \
  --slurpfile lock "$LOCK_FILE" \
  "$selected_filter
  {
    generatedAt: \$generatedAt,
    defaultProfile: \$profiles[0].defaultProfile,
    profiles: (
      \$profiles[0].profiles
      | map(. + {
          selectedServices: ((.services // []) | map(. as \$service | select((\$lock[0].components // []) | index(\$service)))),
          selectedModuleCount: ((.services // []) | map(. as \$service | select((\$lock[0].components // []) | index(\$service))) | length)
        })
    )
  }" > "$OUTPUT_DIR/profile-widgets.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile theme "$THEME" \
  '{generatedAt: $generatedAt, theme: $theme[0]}' > "$OUTPUT_DIR/theme.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile demo "$DEMO_CONTENT" \
  --slurpfile lock "$LOCK_FILE" \
  '{
    generatedAt: $generatedAt,
    canonicalScenario: $demo[0].canonicalScenario,
    personas: $demo[0].personas,
    requiredEvidence: $demo[0].requiredEvidence,
    selectedEvidence: (
      $demo[0].requiredEvidence
      | to_entries
      | map(. as $entry | select(($lock[0].components // []) | index($entry.key)))
    )
  }' > "$OUTPUT_DIR/demo-content.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile contracts "$CONTRACTS" \
  --slurpfile lock "$LOCK_FILE" \
  "$selected_filter
  {
    generatedAt: \$generatedAt,
    secrets: (
      selected_contracts
      | map(select(.contract.moduleType != \"bundle\"))
      | map({
          component,
          owner: .contract.access.owner,
          authMode: .contract.auth.mode,
          consumers: [.component],
          renderedTo: [\"runtime/configs\", \"runtime/env\"],
          offboarding: .contract.access.offboarding,
          rotation: \"site-owned SOPS update and redeploy\",
          blastRadius: (if .contract.state.mode == \"stateful\" then \"service state and credentials\" else \"service credentials only\" end)
        })
    )
  }" > "$OUTPUT_DIR/secret-inventory.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile contracts "$CONTRACTS" \
  --slurpfile lock "$LOCK_FILE" \
  "$selected_filter
  {
    generatedAt: \$generatedAt,
    deploymentProfile: (
      if (selected_contracts | map(.contract.state.mode == \"stateful\") | any) then \"small_team\" else \"tiny\" end
    ),
    costDrivers: (
      selected_contracts
      | map(select((.contract.backup.targets // []) | length > 0))
      | map({component, backupTargets: .contract.backup.targets, state: .contract.state})
    ),
    externalRequirements: [\"domain_dns\", \"backup_storage\", \"smtp_relay_or_mail_reputation_plan\"]
  }" > "$OUTPUT_DIR/footprint.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile contracts "$CONTRACTS" \
  --slurpfile lock "$LOCK_FILE" \
  "$selected_filter
  {
    generatedAt: \$generatedAt,
    availabilityModel: \"single-host\",
    included: [\"reproducible generated bundle\", \"SOPS-backed host secret render\", \"Kopia-backed restore doctrine\", \"post-deploy verification\"],
    excluded: [\"live failover\", \"multi-host clustering\", \"automatic database failover\", \"zero-downtime stateful migrations\", \"24/7 response unless separately contracted\"],
    selectedRoutes: (selected_contracts | map(.contract.routes[]?.host) | unique)
  }" > "$OUTPUT_DIR/availability.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile contracts "$CONTRACTS" \
  --slurpfile lock "$LOCK_FILE" \
  "$selected_filter
  {
    generatedAt: \$generatedAt,
    status: \"desired-state-only\",
    checks: [
      \"component lock matches deployed bundle\",
      \"systemd graph matches generated graph\",
      \"running containers match generated runtime model\",
      \"running images match selected image refs\",
      \"Caddy routes match generated Caddyfile\",
      \"Keycloak clients/groups match generated desired state\",
      \"runtime files match generated inventory\"
    ],
    selectedComponents: \$lock[0].components
  }" > "$OUTPUT_DIR/drift-plan.json"

jq -n \
  --arg generatedAt "$generated_at" \
  --slurpfile pos "$POS_EXPLORATION" \
  '{generatedAt: $generatedAt, pos: $pos[0]}' > "$OUTPUT_DIR/pos-exploration.json"

printf '[contract-reports] wrote reports to %s\n' "$OUTPUT_DIR" >&2
