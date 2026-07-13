#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/lib/deploy-scope.sh
source "$ROOT_DIR/scripts/lib/deploy-scope.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

graph_file="$tmp_dir/graph.json"
compose_config_json="$tmp_dir/compose.json"

cat > "$graph_file" <<'EOF_JSON'
{
  "unitPrefix": "webservices",
  "defaultTarget": {
    "name": "webservices.target",
    "wantsTargets": ["webservices-apps.target"]
  },
  "auxiliaryTargets": [
    {
      "name": "webservices-apps.target",
      "domains": ["mastodon-runtime"],
      "services": ["sample-app"]
    }
  ],
  "lifecycleDomains": [
    {
      "name": "mastodon-runtime",
      "services": ["mastodon-web", "mastodon-streaming", "mastodon-sidekiq"]
    }
  ]
}
EOF_JSON

cat > "$compose_config_json" <<'EOF_JSON'
{
  "services": {
    "sample-app": {},
    "homepage": {},
    "mastodon-web": {},
    "mastodon-streaming": {},
    "mastodon-sidekiq": {}
  }
}
EOF_JSON

assert_eq() {
  local actual="$1"
  local expected="$2"
  local label="$3"
  if [ "$actual" != "$expected" ]; then
    printf '[deploy-scope-test] %s mismatch\nexpected:\n%s\nactual:\n%s\n' "$label" "$expected" "$actual" >&2
    exit 1
  fi
}

assert_rejects_unit() {
  local requested="$1"
  if ( deploy_scope_normalize_unit "$requested" webservices ) >/dev/null 2>"$tmp_dir/reject.log"; then
    printf '[deploy-scope-test] accepted invalid unit reference: %s\n' "$requested" >&2
    exit 1
  fi
}

assert_rejects_target_scope() {
  local requested="$1"
  if deploy_scope_services_for_unit "$requested" webservices "$graph_file" "$compose_config_json" >/dev/null 2>"$tmp_dir/reject-target.log"; then
    printf '[deploy-scope-test] resolved unknown target scope: %s\n' "$requested" >&2
    exit 1
  fi
}

assert_eq \
  "$(deploy_scope_normalize_unit sample-app webservices)" \
  "webservices-sample-app.service" \
  "short unit normalization"

assert_eq \
  "$(deploy_scope_normalize_unit webservices-sample-app webservices)" \
  "webservices-sample-app.service" \
  "prefixed unit normalization"

assert_eq \
  "$(deploy_scope_services_for_unit sample-app webservices "$graph_file" "$compose_config_json")" \
  "sample-app" \
  "single-service unit service derivation"

assert_eq \
  "$(deploy_scope_services_for_unit webservices-mastodon-runtime.service webservices "$graph_file" "$compose_config_json")" \
  $'mastodon-web\nmastodon-streaming\nmastodon-sidekiq' \
  "lifecycle-domain service derivation"

assert_eq \
  "$(deploy_scope_services_for_unit webservices-apps.target webservices "$graph_file" "$compose_config_json")" \
  $'mastodon-sidekiq\nmastodon-streaming\nmastodon-web\nsample-app' \
  "auxiliary target service derivation"

assert_eq \
  "$(deploy_scope_services_for_unit webservices.target webservices "$graph_file" "$compose_config_json")" \
  $'mastodon-sidekiq\nmastodon-streaming\nmastodon-web\nsample-app' \
  "nested target service derivation"

assert_rejects_unit "../evil.service"
assert_rejects_unit "webservices-evil/escape.service"
assert_rejects_unit $'webservices-evil\n.service'
assert_rejects_unit "webservices-evil;systemctl.service"
assert_rejects_target_scope "webservices-missing.target"

printf '[deploy-scope-test] ok\n' >&2
