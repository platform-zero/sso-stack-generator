#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "[module-runners-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"

tmp_root="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_root"
}
trap cleanup EXIT

workspace="$tmp_root/workspace"
module_dir="$workspace/demo-stack-module"
mkdir -p "$module_dir/stack.compose" "$module_dir/tests"

schema_file="$ROOT_DIR/modules/stack.module.schema.json"
jq -e '
  .additionalProperties == false
  and (.required | index("smoke") != null)
  and (.properties.runtimeDependencies.items["$ref"] == "#/$defs/moduleId")
  and (.properties.contracts.items["$ref"] == "#/$defs/moduleId")
  and (.properties.ciProfiles.items["$ref"] == "#/$defs/moduleId")
  and (.properties.smoke.enum == ["required", "external-only", "unsupported"])
  and (.properties.smokeUnsupportedReason.minLength == 10)
  and (.properties.overlays.minItems == 1)
  and (.properties.overlays.items["$ref"] == "#/$defs/safeOverlayPath")
  and (.properties.testAssets.items["$ref"] == "#/$defs/safeOverlayPath")
' "$schema_file" >/dev/null

cat > "$module_dir/stack.compose/demo.yml" <<'EOF_COMPOSE'
services:
  demo:
    image: caddy:2.11.3
EOF_COMPOSE
cat > "$module_dir/stack.module.json" <<'EOF_MODULE'
{
  "schemaVersion": 1,
  "id": "demo",
  "repo": "demo-stack-module",
  "runtimeId": "demo",
  "lifecycle": "active",
  "dependencies": [],
  "runtimeDependencies": [],
  "contracts": ["demo-contract"],
  "smoke": "required",
  "overlays": ["stack.compose/demo.yml"]
}
EOF_MODULE
cat > "$module_dir/tests/validate.sh" <<'EOF_VALIDATE'
#!/usr/bin/env bash
set -euo pipefail
test -f stack.compose/demo.yml
EOF_VALIDATE
chmod +x "$module_dir/tests/validate.sh"
cat > "$module_dir/tests/contract.sh" <<'EOF_CONTRACT'
#!/usr/bin/env bash
set -euo pipefail
grep -Fq 'caddy:2.11.3' stack.compose/demo.yml
EOF_CONTRACT
chmod +x "$module_dir/tests/contract.sh"
cat > "$module_dir/tests/smoke.sh" <<'EOF_SMOKE'
#!/usr/bin/env bash
set -euo pipefail
test -f stack.compose/demo.yml
EOF_SMOKE
chmod +x "$module_dir/tests/smoke.sh"

"$ROOT_DIR/scripts/test-module.sh" --all "$module_dir" >/dev/null
"$ROOT_DIR/scripts/test-module-group.sh" --all "$workspace" >/dev/null

external_dir="$workspace/external-stack-module"
mkdir -p "$external_dir/stack.compose" "$external_dir/tests"
cp "$module_dir/stack.compose/demo.yml" "$external_dir/stack.compose/external.yml"
cat > "$external_dir/stack.module.json" <<'EOF_EXTERNAL_MODULE'
{
  "schemaVersion": 1,
  "id": "external",
  "repo": "external-stack-module",
  "runtimeId": "external",
  "lifecycle": "active",
  "dependencies": [],
  "runtimeDependencies": ["demo"],
  "contracts": [],
  "smoke": "external-only",
  "smokeUnsupportedReason": "requires deployed DNS and generated secrets",
  "overlays": ["stack.compose/external.yml"]
}
EOF_EXTERNAL_MODULE
"$ROOT_DIR/scripts/test-module.sh" --smoke "$external_dir" >/dev/null

bad_dir="$workspace/bad-stack-module"
mkdir -p "$bad_dir/stack.compose"
cat > "$bad_dir/stack.compose/bad.yml" <<'EOF_BAD_COMPOSE'
services: {}
EOF_BAD_COMPOSE
cat > "$bad_dir/stack.module.json" <<'EOF_BAD_MODULE'
{
  "schemaVersion": 1,
  "id": "bad",
  "repo": "bad-stack-module",
  "lifecycle": "active",
  "dependencies": [],
  "runtimeDependencies": [],
  "contracts": [],
  "smoke": "unsupported",
  "smokeUnsupportedReason": "invalid overlay fixture is expected to fail before smoke",
  "overlays": ["../stack.compose/bad.yml"]
}
EOF_BAD_MODULE

trap - ERR
set +e
"$ROOT_DIR/scripts/test-module.sh" "$bad_dir" >"$tmp_root/bad.log" 2>&1
bad_status=$?
set -e
trap 'status=$?; printf "[module-runners-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR
if [ "$bad_status" -eq 0 ]; then
  printf '[module-runners-test] invalid overlay path was accepted\n' >&2
  exit 1
fi
grep -Eq 'not safe|not an allowed overlay' "$tmp_root/bad.log"

missing_smoke_dir="$workspace/missing-smoke-stack-module"
mkdir -p "$missing_smoke_dir/stack.compose"
cp "$module_dir/stack.compose/demo.yml" "$missing_smoke_dir/stack.compose/missing-smoke.yml"
cat > "$missing_smoke_dir/stack.module.json" <<'EOF_MISSING_SMOKE'
{
  "schemaVersion": 1,
  "id": "missing-smoke",
  "repo": "missing-smoke-stack-module",
  "runtimeId": "missing-smoke",
  "lifecycle": "active",
  "dependencies": [],
  "runtimeDependencies": [],
  "contracts": [],
  "smoke": "required",
  "overlays": ["stack.compose/missing-smoke.yml"]
}
EOF_MISSING_SMOKE

trap - ERR
set +e
"$ROOT_DIR/scripts/test-module.sh" "$missing_smoke_dir" >"$tmp_root/missing-smoke.log" 2>&1
missing_smoke_status=$?
set -e
trap 'status=$?; printf "[module-runners-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR
if [ "$missing_smoke_status" -eq 0 ]; then
  printf '[module-runners-test] missing required smoke script was accepted\n' >&2
  exit 1
fi
grep -Fq 'smoke is required but tests/smoke.sh is missing' "$tmp_root/missing-smoke.log"

bad_dep_dir="$workspace/bad-dep-stack-module"
mkdir -p "$bad_dep_dir/stack.compose"
cp "$module_dir/stack.compose/demo.yml" "$bad_dep_dir/stack.compose/bad-dep.yml"
cat > "$bad_dep_dir/stack.module.json" <<'EOF_BAD_DEP'
{
  "schemaVersion": 1,
  "id": "bad-dep",
  "repo": "bad-dep-stack-module",
  "runtimeId": "bad-dep",
  "lifecycle": "active",
  "dependencies": [],
  "runtimeDependencies": ["Bad_Dep"],
  "contracts": [],
  "smoke": "external-only",
  "smokeUnsupportedReason": "requires deployed DNS and generated secrets",
  "overlays": ["stack.compose/bad-dep.yml"]
}
EOF_BAD_DEP

trap - ERR
set +e
"$ROOT_DIR/scripts/test-module.sh" "$bad_dep_dir" >"$tmp_root/bad-dep.log" 2>&1
bad_dep_status=$?
set -e
trap 'status=$?; printf "[module-runners-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR
if [ "$bad_dep_status" -eq 0 ]; then
  printf '[module-runners-test] bad runtime dependency id was accepted\n' >&2
  exit 1
fi
grep -Fq 'invalid runtimeDependencies id' "$tmp_root/bad-dep.log"

printf '[module-runners-test] ok\n' >&2
