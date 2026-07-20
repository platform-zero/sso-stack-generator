#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mkdir -p "$tmp_dir/clean/stack.containers/app" "$tmp_dir/root/stack.containers/app"
cat > "$tmp_dir/clean/stack.containers/app/Containerfile" <<'EOF'
FROM alpine:3.22
USER 1000:1000
EOF
cat > "$tmp_dir/root/stack.containers/app/Containerfile" <<'EOF'
FROM alpine:3.22
RUN true
EOF

python3 "$SCRIPT_DIR/modules/security-policy.py" "$tmp_dir/clean"

cat > "$tmp_dir/clean/stack.runtime.yaml" <<'EOF'
services:
  example:
    image: example.invalid/service:immutable
    user: "0:0"
EOF
if python3 "$SCRIPT_DIR/modules/security-policy.py" "$tmp_dir/clean" >/dev/null 2>&1; then
  printf '[security-policy-test] explicit root runtime user unexpectedly passed\n' >&2
  exit 1
fi
cat > "$tmp_dir/clean/security-exceptions.json" <<'EOF'
{
  "schemaVersion": 1,
  "exceptions": [
    {
      "rule": "container-root-default",
      "path": "stack.runtime.yaml",
      "reason": "The runtime must perform a privileged bootstrap operation.",
      "mitigations": ["The service is isolated to a dedicated runtime account."]
    }
  ]
}
EOF
python3 "$SCRIPT_DIR/modules/security-policy.py" "$tmp_dir/clean"

if python3 "$SCRIPT_DIR/modules/security-policy.py" "$tmp_dir/root" >/dev/null 2>&1; then
  printf '[security-policy-test] undeclared root default unexpectedly passed\n' >&2
  exit 1
fi

cat > "$tmp_dir/root/security-exceptions.json" <<'EOF'
{
  "schemaVersion": 1,
  "exceptions": [
    {
      "rule": "container-root-default",
      "path": "stack.containers/app/Containerfile",
      "reason": "Initialization requires changing owned volume paths.",
      "mitigations": ["The service drops privileges before accepting traffic."]
    }
  ]
}
EOF
python3 "$SCRIPT_DIR/modules/security-policy.py" "$tmp_dir/root"

perl -0pi -e 's/container-root-default/host-network/' "$tmp_dir/root/security-exceptions.json"
if python3 "$SCRIPT_DIR/modules/security-policy.py" "$tmp_dir/root" >/dev/null 2>&1; then
  printf '[security-policy-test] stale exception unexpectedly passed\n' >&2
  exit 1
fi

printf '[security-policy-test] ok\n'
