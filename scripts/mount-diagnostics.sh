#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
BUNDLE_ROOT="$(cd "$SCRIPT_DIR/.." && pwd -P)"
DEPLOY_ROOT="$(cd "$BUNDLE_ROOT/.." && pwd -P)"
# shellcheck source=scripts/lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
RUNTIME_MODEL_FILE="$BUNDLE_ROOT/runtime-model.yml"
RUNTIME_CONFIG_JSON=""
RUNTIME_ENV_FILE="$DEPLOY_ROOT/runtime/stack.env"
OUTPUT_FILE=""

usage() {
  cat <<'EOF_USAGE'
Usage:
  ./scripts/mount-diagnostics.sh [--bundle-root <path>] [--runtime-model-file <path>] [--runtime-config-json <path>] [--runtime-env-file <path>] [--output <path>]

Writes a JSON report describing container volume/bind mount sources, targets,
realpaths, devices, duplicate targets, and overlapping source/target paths.
The report is diagnostic only; it does not mutate host paths or container state.
EOF_USAGE
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --bundle-root)
      BUNDLE_ROOT="$2"
      DEPLOY_ROOT="$(cd "$BUNDLE_ROOT/.." && pwd -P)"
      RUNTIME_MODEL_FILE="$BUNDLE_ROOT/runtime-model.yml"
      RUNTIME_ENV_FILE="$DEPLOY_ROOT/runtime/stack.env"
      shift
      ;;
    --runtime-model-file)
      RUNTIME_MODEL_FILE="$2"
      shift
      ;;
    --runtime-config-json)
      RUNTIME_CONFIG_JSON="$2"
      shift
      ;;
    --runtime-env-file)
      RUNTIME_ENV_FILE="$2"
      shift
      ;;
    --output)
      OUTPUT_FILE="$2"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf '[mount-diagnostics] ERROR: unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

require_cmd python3

temp_json=""
cleanup() {
  if [ -n "$temp_json" ]; then
    rm -f "$temp_json"
  fi
  return 0
}
trap cleanup EXIT

if [ -z "$RUNTIME_CONFIG_JSON" ]; then
  require_cmd jq
  [ -f "$RUNTIME_MODEL_FILE" ] || {
    printf '[mount-diagnostics] ERROR: missing runtime model file: %s\n' "$RUNTIME_MODEL_FILE" >&2
    exit 1
  }
  temp_json="$(mktemp)"
  if [ -f "$RUNTIME_ENV_FILE" ]; then
    container_contract \
      --project-directory "$DEPLOY_ROOT" \
      --env-file "$RUNTIME_ENV_FILE" \
      -f "$RUNTIME_MODEL_FILE" \
      config --format json --no-interpolate > "$temp_json"
  else
    container_contract \
      --project-directory "$DEPLOY_ROOT" \
      -f "$RUNTIME_MODEL_FILE" \
      config --format json --no-interpolate > "$temp_json"
  fi
  RUNTIME_CONFIG_JSON="$temp_json"
fi

[ -f "$RUNTIME_CONFIG_JSON" ] || {
  printf '[mount-diagnostics] ERROR: missing runtime config JSON: %s\n' "$RUNTIME_CONFIG_JSON" >&2
  exit 1
}

python3 - "$RUNTIME_CONFIG_JSON" "$DEPLOY_ROOT" "$OUTPUT_FILE" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


runtime_config_json = Path(sys.argv[1])
deploy_root = Path(sys.argv[2]).resolve()
output_file = sys.argv[3]
runtime_config = json.loads(runtime_config_json.read_text(encoding="utf-8"))
declared_volumes = set((runtime_config.get("volumes") or {}).keys())


def parse_string_mount(value):
    parts = value.split(":")
    if len(parts) < 2:
        return None
    source, target = parts[0], parts[1]
    mode = parts[2:] or []
    return {
        "type": "bind" if source.startswith("/") or source.startswith(".") else "volume",
        "source": source,
        "target": target,
        "read_only": "ro" in mode,
    }


def normalize_mount(service, raw):
    if isinstance(raw, str):
        parsed = parse_string_mount(raw)
        if parsed is None:
            return None
        raw = parsed
    if not isinstance(raw, dict):
        return None
    source = raw.get("source") or raw.get("src")
    target = raw.get("target") or raw.get("dst") or raw.get("destination")
    if not target:
        return None
    mount_type = raw.get("type") or ("volume" if source in declared_volumes else "bind")
    read_only = bool(raw.get("read_only") or raw.get("readOnly"))
    if not read_only and isinstance(raw.get("bind"), dict):
        read_only = bool(raw["bind"].get("read_only"))
    return {
        "service": service,
        "type": mount_type,
        "source": str(source or ""),
        "target": str(target),
        "readOnly": read_only,
    }


def host_path(source):
    if not source:
        return None
    if source in declared_volumes:
        return None
    if source.startswith("/"):
        return Path(source)
    if source.startswith("."):
        return (deploy_root / source).resolve()
    if "/" in source:
        return (deploy_root / source).resolve()
    return None


def annotate_mount(mount):
    path = host_path(mount["source"])
    if path is None:
        mount["sourceKind"] = "named-volume" if mount["source"] in declared_volumes else "opaque"
        return mount
    mount["sourceKind"] = "bind"
    mount["hostPath"] = str(path)
    mount["realSource"] = os.path.realpath(path)
    mount["exists"] = os.path.exists(path)
    try:
        stat = os.stat(path)
        mount["device"] = stat.st_dev
        mount["inode"] = stat.st_ino
    except FileNotFoundError:
        mount["missingReason"] = "source path does not exist"
    except PermissionError:
        mount["missingReason"] = "permission denied while statting source path"
    return mount


def is_prefix_path(parent, child):
    if not parent or not child or parent == child:
        return False
    parent = parent.rstrip("/") + "/"
    child = child.rstrip("/") + "/"
    return child.startswith(parent)


def finding(kind, severity, mounts, reason):
    return {
        "kind": kind,
        "severity": severity,
        "services": sorted({m["service"] for m in mounts}),
        "targets": sorted({m["target"] for m in mounts}),
        "sources": sorted({m.get("realSource") or m.get("hostPath") or m["source"] for m in mounts if m.get("source")}),
        "reason": reason,
    }


mounts = []
for service, config in sorted((runtime_config.get("services") or {}).items()):
    for raw in config.get("volumes") or []:
        mount = normalize_mount(service, raw)
        if mount is not None:
            mounts.append(annotate_mount(mount))

findings = []
by_service_target = {}
for mount in mounts:
    key = (mount["service"], mount["target"])
    by_service_target.setdefault(key, []).append(mount)
for duplicates in by_service_target.values():
    if len(duplicates) > 1:
        findings.append(finding("duplicate_target", "warning", duplicates, "multiple mounts target the same path in one service"))

for mount in mounts:
    if mount.get("sourceKind") == "bind" and mount.get("exists") is False:
        findings.append(finding("missing_source", "info", [mount], "bind source path does not currently exist"))

binds = [m for m in mounts if m.get("sourceKind") == "bind"]
for index, left in enumerate(binds):
    for right in binds[index + 1:]:
        left_source = left.get("realSource") or left.get("hostPath")
        right_source = right.get("realSource") or right.get("hostPath")
        if left_source and right_source and (
            is_prefix_path(left_source, right_source) or is_prefix_path(right_source, left_source)
        ):
            findings.append(finding("overlapping_source", "info", [left, right], "one bind source is nested under another bind source"))
        if left["service"] == right["service"] and (
            is_prefix_path(left["target"], right["target"]) or is_prefix_path(right["target"], left["target"])
        ):
            findings.append(finding("overlapping_target", "warning", [left, right], "one target path is nested under another target path in the same service"))

report = {
    "generatedAt": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "deployRoot": str(deploy_root),
    "summary": {
        "services": len(runtime_config.get("services") or {}),
        "mounts": len(mounts),
        "bindMounts": sum(1 for m in mounts if m.get("sourceKind") == "bind"),
        "namedVolumes": sum(1 for m in mounts if m.get("sourceKind") == "named-volume"),
        "findings": len(findings),
        "warnings": sum(1 for f in findings if f["severity"] == "warning"),
    },
    "mounts": mounts,
    "findings": findings,
}

payload = json.dumps(report, indent=2, sort_keys=True) + "\n"
if output_file:
    Path(output_file).parent.mkdir(parents=True, exist_ok=True)
    Path(output_file).write_text(payload, encoding="utf-8")
else:
    sys.stdout.write(payload)
PY
