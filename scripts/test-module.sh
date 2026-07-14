#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "[module-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd -P)"
run_smoke=false
run_contract=false
module_dir=""

usage() {
  cat >&2 <<'EOF'
Usage: scripts/test-module.sh [--contract] [--smoke] [--all] /path/to/module

Validates stack.module.json and runs tests/validate.sh when present.
With --contract, also runs tests/contract.sh for declared contracts.
With --smoke, also runs tests/smoke.sh when smoke is required.
With --all, runs validation, declared contracts, and smoke handling.
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --smoke)
      run_smoke=true
      shift
      ;;
    --contract)
      run_contract=true
      shift
      ;;
    --all)
      run_contract=true
      run_smoke=true
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -*)
      printf '[module-test] unknown option: %s\n' "$1" >&2
      usage
      exit 2
      ;;
    *)
      if [ -n "$module_dir" ]; then
        printf '[module-test] only one module path may be specified\n' >&2
        usage
        exit 2
      fi
      module_dir="$1"
      shift
      ;;
  esac
done

[ -n "$module_dir" ] || { usage; exit 2; }
[ -d "$module_dir" ] || { printf '[module-test] module directory not found: %s\n' "$module_dir" >&2; exit 1; }
module_dir="$(cd "$module_dir" && pwd -P)"
metadata_file="$module_dir/stack.module.json"
[ -f "$metadata_file" ] || { printf '[module-test] missing stack.module.json: %s\n' "$module_dir" >&2; exit 1; }

python3 - "$metadata_file" "$module_dir" "$ROOT_DIR/modules/catalog.json" <<'PY'
import json
import re
import sys
from pathlib import Path

metadata_path = Path(sys.argv[1])
module_dir = Path(sys.argv[2])
catalog_path = Path(sys.argv[3])
metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
catalog_modules = {}
if catalog_path.exists():
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    catalog_modules = {
        repo_entry.get("moduleId"): repo_entry.get("name")
        for repo_entry in catalog.get("repositories", [])
        if repo_entry.get("kind") == "stack-module"
    }

allowed_keys = {
    "schemaVersion",
    "id",
    "repo",
    "runtimeId",
    "lifecycle",
    "dependencies",
    "runtimeDependencies",
    "contracts",
    "smoke",
    "smokeUnsupportedReason",
    "ciProfiles",
    "overlays",
    "sourceRepo",
    "testAssets",
}
extra = sorted(set(metadata) - allowed_keys)
if extra:
    raise SystemExit(f"unexpected stack.module.json keys: {', '.join(extra)}")

if metadata.get("schemaVersion") != 1:
    raise SystemExit("schemaVersion must be 1")

module_id = metadata.get("id")
if not isinstance(module_id, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", module_id):
    raise SystemExit("id must be a lowercase module id")

repo = metadata.get("repo")
if not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9._-]+", repo):
    raise SystemExit("repo must be a repository name")

expected_repos = {module_id, f"{module_id}-stack-module", f"{module_id}-module"}
catalog_repo = catalog_modules.get(module_id)
if repo not in expected_repos and repo != catalog_repo:
    expected = " or ".join(sorted(expected_repos))
    raise SystemExit(f"repo must match module id: expected {expected}, got {repo}")

lifecycle = metadata.get("lifecycle")
if lifecycle not in {"active", "experimental", "retired"}:
    raise SystemExit("lifecycle must be active, experimental, or retired")

for key in ("dependencies", "runtimeDependencies", "contracts", "overlays", "testAssets", "ciProfiles"):
    value = metadata.get(key, [] if key != "overlays" else None)
    if not isinstance(value, list):
        raise SystemExit(f"{key} must be an array")
    if len(value) != len(set(value)):
        raise SystemExit(f"{key} contains duplicates")

for key in ("dependencies", "runtimeDependencies"):
    for dep in metadata.get(key, []):
        if not isinstance(dep, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", dep):
            raise SystemExit(f"invalid {key} id: {dep!r}")
        if dep == module_id:
            raise SystemExit(f"module may not list itself in {key}")

for contract in metadata.get("contracts", []):
    if not isinstance(contract, str) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", contract):
        raise SystemExit(f"invalid contract id: {contract!r}")

smoke = metadata.get("smoke")
if smoke not in {"required", "external-only", "unsupported"}:
    raise SystemExit("smoke must be required, external-only, or unsupported")
reason = metadata.get("smokeUnsupportedReason")
if smoke == "required":
    if reason:
        raise SystemExit("smokeUnsupportedReason must not be set when smoke is required")
else:
    if not isinstance(reason, str) or len(reason.strip()) < 10:
        raise SystemExit("smokeUnsupportedReason is required when smoke is external-only or unsupported")

allowed_prefixes = (
    "global.settings/",
    "stack.config/",
    "stack.containers/",
    "stack.kotlin/",
    "stack.js/",
    "stack.systemd/",
    "scripts/lib/",
    "scripts/modules/",
    "docs/modules/",
    "tests/fixtures/",
)
allowed_roots = {prefix.rstrip("/") for prefix in allowed_prefixes} | {"stack.runtime.yaml"}

def validate_relative_path(path_value: str, key: str) -> None:
    if not isinstance(path_value, str) or not path_value:
        raise SystemExit(f"{key} entries must be non-empty strings")
    path = Path(path_value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts:
        raise SystemExit(f"{key} path is not safe: {path_value}")
    if path_value not in allowed_roots and not path_value.startswith(allowed_prefixes):
        raise SystemExit(f"{key} path is not an allowed overlay/test path: {path_value}")
    if not (module_dir / path).exists():
        raise SystemExit(f"{key} path does not exist: {path_value}")

overlays = metadata.get("overlays")
if not overlays:
    raise SystemExit("overlays must contain at least one owned path")
for overlay in overlays:
    validate_relative_path(overlay, "overlays")
for asset in metadata.get("testAssets", []):
    validate_relative_path(asset, "testAssets")

for script_name in ("validate.sh", "contract.sh", "smoke.sh"):
    script_path = module_dir / "tests" / script_name
    if script_path.exists() and not script_path.is_file():
        raise SystemExit(f"tests/{script_name} must be a file")
    if script_path.exists() and not (script_path.stat().st_mode & 0o111):
        raise SystemExit(f"tests/{script_name} must be executable")

if metadata.get("contracts") and not (module_dir / "tests" / "contract.sh").exists():
    raise SystemExit("contracts are declared but tests/contract.sh is missing")
if (module_dir / "tests" / "contract.sh").exists() and not metadata.get("contracts"):
    raise SystemExit("tests/contract.sh exists but contracts metadata is empty")
if smoke == "required" and not (module_dir / "tests" / "smoke.sh").exists():
    raise SystemExit("smoke is required but tests/smoke.sh is missing")

has_kotlin = (module_dir / "stack.kotlin").exists()
has_js = (module_dir / "stack.js").exists()
has_containers = (module_dir / "stack.containers").exists()
if (has_kotlin or has_js or has_containers) and not (metadata.get("contracts") or metadata.get("ciProfiles")):
    raise SystemExit("modules with stack.kotlin, stack.js, or stack.containers must declare contracts or ciProfiles")

if catalog_path.exists():
    if catalog_repo and catalog_repo != repo:
        raise SystemExit(f"catalog maps module {module_id} to {catalog_repo}, metadata says {repo}")
PY

if [ -x "$module_dir/tests/validate.sh" ]; then
  printf '[module-test] running validate.sh: %s\n' "$module_dir"
  (cd "$module_dir" && tests/validate.sh)
else
  printf '[module-test] no tests/validate.sh: %s\n' "$module_dir"
fi

if [ "$run_smoke" = true ]; then
  smoke_status="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["smoke"])' "$metadata_file")"
  smoke_reason="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8")).get("smokeUnsupportedReason", ""))' "$metadata_file")"
  if [ "$smoke_status" = "required" ]; then
    [ -x "$module_dir/tests/smoke.sh" ] || {
      printf '[module-test] %s: smoke is required but tests/smoke.sh is missing or not executable; add the smoke script or mark smoke external-only/unsupported with a concrete reason\n' "$module_dir" >&2
      exit 1
    }
    printf '[module-test] running smoke.sh: %s\n' "$module_dir"
    (cd "$module_dir" && tests/smoke.sh)
  else
    [ -n "$smoke_reason" ] || {
      printf '[module-test] %s: smoke is %s but smokeUnsupportedReason is missing\n' "$module_dir" "$smoke_status" >&2
      exit 1
    }
    printf '[module-test] skipping smoke for %s (%s): %s\n' "$module_dir" "$smoke_status" "$smoke_reason"
  fi
fi

if [ "$run_contract" = true ]; then
  contract_count="$(python3 -c 'import json,sys; print(len(json.load(open(sys.argv[1], encoding="utf-8")).get("contracts", [])))' "$metadata_file")"
  if [ "$contract_count" -gt 0 ]; then
    [ -x "$module_dir/tests/contract.sh" ] || {
      printf '[module-test] %s: contracts are declared but tests/contract.sh is missing or not executable\n' "$module_dir" >&2
      exit 1
    }
    printf '[module-test] running contract.sh: %s\n' "$module_dir"
    (cd "$module_dir" && tests/contract.sh)
  else
    printf '[module-test] no module contracts declared: %s\n' "$module_dir"
  fi
fi

printf '[module-test] ok: %s\n' "$module_dir"
