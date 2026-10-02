#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
deploy_script="$ROOT_DIR/scripts/deploy.sh"
deploy_audit="$ROOT_DIR/scripts/deploy/deploy-audit.py"

assert_contains() {
  local pattern="$1"
  if ! grep -Fq "$pattern" "$deploy_script"; then
    printf '[test-deploy-preflight] missing deploy preflight pattern: %s\n' "$pattern" >&2
    exit 1
  fi
}

assert_contains 'validate_deploy_root'
assert_contains 'WEBSERVICES_ALLOW_NONSTANDARD_DEPLOY_ROOT'
assert_contains 'RUNTIME_PARALLEL_LIMIT:=2'
assert_contains 'check_gpu_preflight'
assert_contains 'nvidia-container-toolkit'
assert_contains 'DEPLOY_GPU_SMOKE_TEST'
assert_contains 'if type == "object" then (.source // "") else "" end'
assert_contains '(type == "object")'

grep -Fq '"/var/log/webservices/caddy"' "$deploy_audit" || {
  printf '[test-deploy-preflight] missing CrowdSec Caddy log bind allowlist\n' >&2
  exit 1
}

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

cat > "$tmp_dir/webservices.sops.json" <<'EOF_SOPS_JSON'
{"KOPIA_PROXY_AUTHORIZATION": "", "sops": {"version": "3.13.1"}}
EOF_SOPS_JSON

if "$deploy_audit" validate-secrets \
  --bundle-root "$tmp_dir" \
  --env-file "$tmp_dir/webservices.sops.json" \
  >"$tmp_dir/audit.out" 2>"$tmp_dir/audit.err"; then
  printf '[test-deploy-preflight] validate-secrets accepted JSON/SOPS input\n' >&2
  exit 1
fi
grep -Fq 'requires the rendered runtime env file' "$tmp_dir/audit.err"

python3 >"$tmp_dir/stack.env" <<'PY'
import base64

required = {
    "BOOKSTACK_APP_KEY": "base64:" + base64.b64encode(bytes(range(32))).decode("ascii").rstrip("="),
    "KOPIA_PASSWORD": "test-secret",
    "KOPIA_PROXY_AUTHORIZATION": "Basic dGVzdDp0ZXN0",
    "MASTODON_SECRET_KEY_BASE": "test-secret",
    "MASTODON_OTP_SECRET": "test-secret",
    "MASTODON_ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY": "test-secret",
    "MASTODON_ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT": "test-secret",
    "MASTODON_ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY": "test-secret",
    "MASTODON_VAPID_PRIVATE_KEY": base64.urlsafe_b64encode(bytes(range(32))).decode("ascii").rstrip("="),
    "MASTODON_VAPID_PUBLIC_KEY": base64.urlsafe_b64encode(b"\x04" + bytes(range(64))).decode("ascii").rstrip("="),
    "OAUTH2_PROXY_CLIENT_SECRET": "test-secret",
    "OAUTH2_PROXY_COOKIE_SECRET": "test-secret",
    "TEST_RUNNER_OAUTH_SECRET": "test-secret",
    "MODEL_CONTEXT_PROXY_AUTH_SECRET": "test-secret",
    "INFERENCE_CONTROLLER_API_TOKEN": "test-secret",
    "GPU_ARBITER_API_TOKEN": "test-secret",
}
for key, value in required.items():
    print(f"{key}={value}")
PY

"$deploy_audit" validate-secrets \
  --bundle-root "$tmp_dir" \
  --env-file "$tmp_dir/stack.env" \
  >"$tmp_dir/valid-audit.out" 2>"$tmp_dir/valid-audit.err"

sed 's/^MASTODON_VAPID_PUBLIC_KEY=.*/MASTODON_VAPID_PUBLIC_KEY=bad-key/' \
  "$tmp_dir/stack.env" >"$tmp_dir/bad-vapid.env"
if "$deploy_audit" validate-secrets \
  --bundle-root "$tmp_dir" \
  --env-file "$tmp_dir/bad-vapid.env" \
  >"$tmp_dir/bad-vapid.out" 2>"$tmp_dir/bad-vapid.err"; then
  printf '[test-deploy-preflight] invalid VAPID public key was accepted\n' >&2
  exit 1
fi
grep -Fq 'MASTODON_VAPID_PUBLIC_KEY must be a 65-byte base64url uncompressed P-256 public key' "$tmp_dir/bad-vapid.err"

python3 - "$deploy_audit" <<'PY'
import importlib.util
import pathlib
import sys

module_path = pathlib.Path(sys.argv[1])
spec = importlib.util.spec_from_file_location("deploy_audit", module_path)
deploy_audit = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(deploy_audit)

deploy_root = pathlib.Path("/srv/webservices")
assert deploy_audit.classify_bind("/srv/webservices/runtime", deploy_root, {}) == "runtime-config"
assert deploy_audit.classify_bind("/srv/webservices/runtime/caddy", deploy_root, {}) == "runtime-config"
assert deploy_audit.classify_bind("/srv/webservices/runtime-evil", deploy_root, {}) == "other-bind"
assert deploy_audit.classify_bind("/srv/webservices/build-output", deploy_root, {}) == "other-bind"
assert deploy_audit.classify_bind("/srv/webservices/reports/latest", deploy_root, {}) == "deploy-root-data"
PY

printf '[test-deploy-preflight] ok\n'
