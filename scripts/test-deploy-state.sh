#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
# shellcheck source=scripts/lib/deploy-state.sh
source "$ROOT_DIR/scripts/lib/deploy-state.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

bundle_root="$tmp_dir/bundle"
deploy_root="$tmp_dir/deploy"
fake_bin="$tmp_dir/bin"
mkdir -p \
  "$fake_bin" \
  "$bundle_root/site" \
  "$bundle_root/stack.config/caddy" \
  "$bundle_root/stack.compose" \
  "$bundle_root/stack.containers/test-runner/playwright-tests/node_modules/pkg" \
  "$bundle_root/stack.containers/test-runner/playwright-tests/test-results/run" \
  "$bundle_root/stack.containers/test-runner/playwright-tests/playwright-report" \
  "$bundle_root/stack.containers/test-runner/playwright-tests/.auth" \
  "$bundle_root/stack.systemd" \
  "$bundle_root/systemd-user/infra" \
  "$deploy_root/runtime/configs/caddy" \
  "$deploy_root/runtime"

cat > "$bundle_root/site/components.lock.json" <<'EOF_JSON'
{"generatedAt":"test","components":["core"]}
EOF_JSON

cat > "$bundle_root/stack.systemd/graph.json" <<'EOF_JSON'
{"unitPrefix":"webservices","defaultTarget":{"name":"webservices.target"}}
EOF_JSON

cat > "$bundle_root/systemd-user/infra/networks.json" <<'EOF_JSON'
[]
EOF_JSON

cat > "$bundle_root/systemd-user/infra/volumes.json" <<'EOF_JSON'
[]
EOF_JSON
cat > "$bundle_root/docker-compose.yml" <<'EOF_YAML'
services: {}
EOF_YAML
cat > "$bundle_root/stack.compose/caddy.yml" <<'EOF_YAML'
services:
  caddy:
    image: caddy:latest
EOF_YAML
cat > "$bundle_root/stack.config/caddy/Caddyfile" <<'EOF_CADDY'
example.test {
  respond "ok"
}
EOF_CADDY
cat > "$bundle_root/stack.containers/test-runner/playwright-tests/node_modules/pkg/index.js" <<'EOF_NODE'
module.exports = "ok";
EOF_NODE
cat > "$bundle_root/stack.containers/test-runner/playwright-tests/test-results/run/output.txt" <<'EOF_TEST'
before
EOF_TEST
cat > "$bundle_root/stack.containers/test-runner/playwright-tests/playwright-report/index.html" <<'EOF_REPORT'
<html>before</html>
EOF_REPORT
cat > "$bundle_root/stack.containers/test-runner/playwright-tests/.auth/state.json" <<'EOF_AUTH'
{"state":"before"}
EOF_AUTH
cat > "$deploy_root/runtime/configs/caddy/Caddyfile" <<'EOF_CADDY'
example.test {
  respond "ok"
}
EOF_CADDY

deploy_state_write_global_signature "$bundle_root" "$deploy_root"
deploy_state_check_global_signature "$bundle_root" "$deploy_root"
deploy_state_write_file_manifest "$bundle_root" "$deploy_root"
deploy_state_write_runtime_config_manifest "$deploy_root"

signature_file="$deploy_root/runtime/deploy-state/global-signature.json"
if grep -q 'core' "$signature_file"; then
  printf '[deploy-state-test] signature leaked component contents\n' >&2
  exit 1
fi

if [ -n "$(deploy_state_changed_file_paths "$bundle_root" "$deploy_root")" ]; then
  printf '[deploy-state-test] unchanged bundle manifest reported changed paths\n' >&2
  exit 1
fi

cat > "$bundle_root/stack.containers/test-runner/playwright-tests/node_modules/pkg/index.js" <<'EOF_NODE'
module.exports = "changed";
EOF_NODE
cat > "$bundle_root/stack.containers/test-runner/playwright-tests/test-results/run/output.txt" <<'EOF_TEST'
after
EOF_TEST
cat > "$bundle_root/stack.containers/test-runner/playwright-tests/playwright-report/index.html" <<'EOF_REPORT'
<html>after</html>
EOF_REPORT
cat > "$bundle_root/stack.containers/test-runner/playwright-tests/.auth/state.json" <<'EOF_AUTH'
{"state":"after"}
EOF_AUTH

if [ -n "$(deploy_state_changed_file_paths "$bundle_root" "$deploy_root")" ]; then
  printf '[deploy-state-test] ignored playwright artifacts affected bundle change detection\n' >&2
  deploy_state_changed_file_paths "$bundle_root" "$deploy_root" >&2 || true
  exit 1
fi

cat > "$bundle_root/stack.config/caddy/Caddyfile" <<'EOF_CADDY'
example.test {
  respond "changed"
}
EOF_CADDY

if [ "$(deploy_state_changed_file_paths "$bundle_root" "$deploy_root")" != "stack.config/caddy/Caddyfile" ]; then
  printf '[deploy-state-test] changed bundle manifest did not report the changed config path\n' >&2
  deploy_state_changed_file_paths "$bundle_root" "$deploy_root" >&2 || true
  exit 1
fi

cat > "$bundle_root/docker-compose.yml" <<'EOF_YAML'
services:
  caddy:
    image: caddy:latest
EOF_YAML
cat > "$bundle_root/site/components.lock.json" <<'EOF_JSON'
{"generatedAt":"changed timestamp","components":["core"]}
EOF_JSON

expected_changed_paths=$'docker-compose.yml\nsite/components.lock.json\nstack.config/caddy/Caddyfile'
if [ "$(deploy_state_changed_file_paths "$bundle_root" "$deploy_root")" != "$expected_changed_paths" ]; then
  printf '[deploy-state-test] aggregate and owned-path changes were not reported together\n' >&2
  deploy_state_changed_file_paths "$bundle_root" "$deploy_root" >&2 || true
  exit 1
fi

cat > "$deploy_root/runtime/configs/caddy/Caddyfile" <<'EOF_CADDY'
example.test {
  respond "changed"
}
EOF_CADDY

if [ "$(deploy_state_changed_runtime_config_paths "$deploy_root")" != "caddy/Caddyfile" ]; then
  printf '[deploy-state-test] changed runtime config manifest did not report the changed config path\n' >&2
  deploy_state_changed_runtime_config_paths "$deploy_root" >&2 || true
  exit 1
fi

deploy_state_check_global_signature "$bundle_root" "$deploy_root"

cat > "$bundle_root/stack.systemd/graph.json" <<'EOF_JSON'
{"unitPrefix":"webservices","defaultTarget":{"name":"webservices.target"},"auxiliaryTargets":[{"name":"webservices-apps.target"}]}
EOF_JSON

if deploy_state_check_global_signature "$bundle_root" "$deploy_root" >/dev/null 2>"$tmp_dir/error.log"; then
  printf '[deploy-state-test] changed graph did not block scoped deploy\n' >&2
  exit 1
fi

if ! grep -q 'run a full deploy' "$tmp_dir/error.log"; then
  printf '[deploy-state-test] missing full-deploy guidance on mismatch\n' >&2
  cat "$tmp_dir/error.log" >&2
  exit 1
fi

rm -f "$signature_file"
cat > "$fake_bin/systemctl" <<'EOF_SYSTEMCTL'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" = "--user" ] && [ "$2" = "is-active" ] && [ "$3" = "--quiet" ] && [ "$4" = "webservices.target" ]; then
  exit 0
fi
exit 1
EOF_SYSTEMCTL
chmod +x "$fake_bin/systemctl"
PATH="$fake_bin:$PATH" deploy_state_bootstrap_missing_global_signature "$bundle_root" "$deploy_root" "webservices.target"
deploy_state_check_global_signature "$bundle_root" "$deploy_root"

rm -f "$signature_file"
cat > "$fake_bin/systemctl" <<'EOF_SYSTEMCTL'
#!/usr/bin/env bash
exit 1
EOF_SYSTEMCTL
chmod +x "$fake_bin/systemctl"
if PATH="$fake_bin:$PATH" deploy_state_bootstrap_missing_global_signature "$bundle_root" "$deploy_root" "webservices.target" >/dev/null 2>"$tmp_dir/inactive.log"; then
  printf '[deploy-state-test] inactive target allowed missing signature bootstrap\n' >&2
  exit 1
fi

if ! grep -q 'not active' "$tmp_dir/inactive.log"; then
  printf '[deploy-state-test] missing inactive target guidance\n' >&2
  cat "$tmp_dir/inactive.log" >&2
  exit 1
fi

printf '[deploy-state-test] ok\n' >&2
