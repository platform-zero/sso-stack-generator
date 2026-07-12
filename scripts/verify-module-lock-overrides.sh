#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=scripts/lib/common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/common.sh"
# shellcheck source=scripts/lib/site-manifest.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/site-manifest.sh"
# shellcheck source=scripts/lib/external-modules.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib/external-modules.sh"

SITE_MANIFEST_PATH="${1:-}"

if [ -z "$SITE_MANIFEST_PATH" ]; then
  die "usage: $0 <site-manifest.json>"
fi

SITE_MANIFEST_PATH="$(resolve_site_manifest_file "$SITE_MANIFEST_PATH")"

if ! external_modules_enabled "$SITE_MANIFEST_PATH"; then
  log "module lock override check skipped: no external modules configured"
  exit 0
fi

if [ ! -f "$EXTERNAL_MODULES_RESOLVED_MANIFEST_FILE" ]; then
  external_modules_resolve "$SITE_MANIFEST_PATH"
fi

schema_version="$(jq -r '.schemaVersion // 1' "$EXTERNAL_MODULES_RESOLVED_MANIFEST_FILE")"
if [ "$schema_version" != "2" ]; then
  log "module lock override check skipped: schemaVersion $schema_version"
  exit 0
fi

python3 - "$EXTERNAL_MODULES_RESOLVED_MANIFEST_FILE" "$EXTERNAL_MODULES_CACHE_DIR" <<'PY'
import json
import subprocess
import sys
from pathlib import Path


def safe_cache_name(label: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "-" for ch in label).strip("-")
    return (safe or "module")[:80]


def git_lines(repo: Path, *args: str) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise SystemExit(f"module lock override check failed to inspect {repo}: {detail}")
    return [line for line in result.stdout.splitlines() if line]


manifest_path = Path(sys.argv[1])
cache_dir = Path(sys.argv[2])
lock = json.loads(manifest_path.read_text(encoding="utf-8"))
violations: list[str] = []
deploy_roots = (
    "global.settings/",
    "stack.compose/",
    "stack.config/",
    "stack.containers/",
    "stack.kotlin/",
    "stack.js/",
    "stack.systemd/",
    "scripts/lib/",
    "scripts/modules/",
)

for entry in lock.get("modules", []):
    module_id = entry.get("id", "")
    commit = entry.get("commit", "")
    repo_dir = cache_dir / safe_cache_name(f"module-{module_id}")
    if not repo_dir.is_dir():
        violations.append(f"{module_id}: cached module clone is missing: {repo_dir}")
        continue

    actual_commit = git_lines(repo_dir, "rev-parse", "HEAD")[0]
    if commit and actual_commit != commit:
        violations.append(f"{module_id}: cached clone is at {actual_commit}, expected {commit}")
        continue

    metadata_path = repo_dir / entry.get("path", ".") / "stack.module.json"
    if not metadata_path.is_file():
        violations.append(f"{module_id}: missing stack.module.json")
        continue
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    overlays = [str(path).rstrip("/") for path in metadata.get("overlays", [])]
    overrides = sorted({str(path).rstrip("/") for path in entry.get("overrides", [])})
    tracked = git_lines(repo_dir, "ls-files")
    tracked_set = set(tracked)

    for path in tracked:
        if not path.startswith(deploy_roots):
            continue
        covered = any(path == overlay or path.startswith(overlay + "/") for overlay in overlays)
        if not covered:
            violations.append(f"{module_id}: tracked deploy-surface file is outside declared overlays: {path}")

    for override in overrides:
        exists = override in tracked_set or any(path.startswith(override + "/") for path in tracked)
        under_overlay = any(override == overlay or override.startswith(overlay + "/") for overlay in overlays)
        if not exists:
            violations.append(f"{module_id}: stale override path: {override}")
        elif not under_overlay:
            violations.append(f"{module_id}: override path is outside declared overlays: {override}")

    for overlay in overlays:
        if overlay in overrides:
            continue
        overlay_files = [path for path in tracked if path == overlay or path.startswith(overlay + "/")]
        for path in overlay_files:
            covered = path in overrides or any(path.startswith(override + "/") for override in overrides)
            if not covered:
                violations.append(f"{module_id}: missing override path for overlay file: {path}")

if violations:
    print("module lock override check failed:", file=sys.stderr)
    for violation in violations:
        print(f"  - {violation}", file=sys.stderr)
    raise SystemExit(1)
PY

log "module lock override check passed"
