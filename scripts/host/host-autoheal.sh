#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
# shellcheck source=scripts/lib/common.sh
source "$ROOT/scripts/lib/common.sh"
# shellcheck source=scripts/lib/systemd-user.sh
source "$ROOT/scripts/lib/systemd-user.sh"

DEPLOY_ROOT="${WEBSERVICES_DEPLOY_ROOT:-$HOME/webservices}"
UNIT_PREFIX="${WEBSERVICES_UNIT_PREFIX:-webservices}"
PROJECT_NAME="${PROJECT_NAME:-webservices}"
STATE_ROOT="${WEBSERVICES_AUTOHEAL_STATE_ROOT:-${XDG_STATE_HOME:-$HOME/.local/state}/webservices/host-autoheal}"
STATE_FILE="$STATE_ROOT/state.json"
NTFY_TOPIC="${WEBSERVICES_AUTOHEAL_NTFY_TOPIC:-webservices-autoheal}"

mkdir -p "$STATE_ROOT"
require_cmd jq
require_cmd python3

empty_state() {
  printf '{"unhealthy":{}}\n'
}

load_state() {
  if [ -f "$STATE_FILE" ]; then
    cat "$STATE_FILE"
  else
    empty_state
  fi
}

write_state() {
  local tmp
  tmp="$(mktemp "$STATE_ROOT/.state.XXXXXX")"
  cat > "$tmp"
  mv -f "$tmp" "$STATE_FILE"
}

notify_restart() {
  local service_name="$1" unit_name="$2" status="$3"
  if command -v curl >/dev/null 2>&1; then
    curl -fsS \
      -H "Title: webservices autoheal" \
      -H "Tags: warning" \
      -d "Restarted $unit_name for $service_name after repeated unhealthy state: $status" \
      "http://localhost:80/$NTFY_TOPIC" >/dev/null 2>&1 || true
  fi
}

runtime_shard_dir="$DEPLOY_ROOT/build/systemd-user/runtime-shards"
[ -d "$runtime_shard_dir" ] || die "missing rendered runtime shard directory: $runtime_shard_dir"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/webservices-host-autoheal.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
containers_json="$tmp_dir/containers.json"
current_json="$tmp_dir/current.json"
restarts_file="$tmp_dir/restarts.tsv"

python3 - "$runtime_shard_dir" "$UNIT_PREFIX" > "$tmp_dir/labelled.json" <<'PY'
import json
import sys
from pathlib import Path

runtime_shard_dir = Path(sys.argv[1])
prefix = sys.argv[2]
labelled = {}

def labels_to_dict(value):
    if isinstance(value, dict):
        return {str(k): str(v) for k, v in value.items()}
    if isinstance(value, list):
        result = {}
        for item in value:
            key, sep, val = str(item).partition("=")
            if sep:
                result[key] = val
        return result
    return {}

for path in sorted(runtime_shard_dir.glob("*.runtime.json")):
    domain = path.name[:-len(".runtime.json")]
    data = json.loads(path.read_text())
    for service, config in (data.get("services") or {}).items():
        labels = labels_to_dict(config.get("labels"))
        if labels.get("autoheal") == "true":
            labelled[service] = {
                "unit": f"{prefix}-{domain}.service",
                "domain": domain,
            }

print(json.dumps(labelled, sort_keys=True))
PY

python3 - "$tmp_dir/labelled.json" "$current_json" "$PROJECT_NAME" "$(container_cli)" <<'PY'
import json
import subprocess
import sys
from pathlib import Path

labelled_path = Path(sys.argv[1])
current_path = Path(sys.argv[2])
project_name = sys.argv[3]
container_cli = sys.argv[4]
labelled = json.loads(labelled_path.read_text())
current = []

def inspect_container(name: str):
    result = subprocess.run(
        [container_cli, "inspect", name, "--format", "{{.State.Status}}\t{{if .State.Health}}{{.State.Health.Status}}{{end}}\t{{.State.Error}}"],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    if result.returncode != 0:
        return None
    state, health, error = (result.stdout.rstrip("\n") + "\t\t").split("\t", 2)
    combined_status = ", ".join(part for part in (health, error) if part)
    return {"state": state or "", "status": combined_status}

for service, metadata in sorted(labelled.items()):
    candidates = [f"{project_name}-{service}-1", service]
    inspected = None
    container_name = ""
    for candidate in candidates:
        inspected = inspect_container(candidate)
        if inspected is not None:
            container_name = candidate
            break
    if inspected is None:
        continue
    current.append({
        "service": service,
        "container": container_name,
        "unit": metadata["unit"],
        "state": inspected["state"],
        "status": inspected["status"],
    })

current_path.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n")
PY

python3 - "$STATE_FILE" "$current_json" > "$tmp_dir/next.json" 3> "$restarts_file" <<'PY'
import json
import re
import sys
from pathlib import Path

state_path = Path(sys.argv[1])
current_path = Path(sys.argv[2])
restart_out = open(3, "w", encoding="utf-8", closefd=False)

try:
    state = json.loads(state_path.read_text()) if state_path.exists() else {"unhealthy": {}}
except json.JSONDecodeError:
    state = {"unhealthy": {}}

unhealthy = state.setdefault("unhealthy", {})
current = json.loads(current_path.read_text())
seen = set()
unit_re = re.compile(r"^webservices-[A-Za-z0-9_.-]+\.service$")

for item in current:
    service = item["service"]
    seen.add(service)
    state_value = (item.get("state") or "").lower()
    status = item.get("status") or ""
    is_unhealthy = state_value in {"exited", "dead"} or "(unhealthy)" in status.lower()
    if not is_unhealthy:
        unhealthy.pop(service, None)
        continue
    record = unhealthy.get(service, {})
    count = int(record.get("count", 0)) + 1
    unhealthy[service] = {
        "count": count,
        "unit": item["unit"],
        "container": item["container"],
        "status": status,
    }
    if count >= 2:
        unit = item["unit"]
        if not unit_re.fullmatch(unit):
            continue
        print(f"{service}\t{unit}\t{status}", file=restart_out)
        unhealthy.pop(service, None)

for service in list(unhealthy):
    if service not in seen:
        unhealthy.pop(service, None)

print(json.dumps(state, indent=2, sort_keys=True))
PY

cat "$tmp_dir/next.json" | write_state

if [ -s "$restarts_file" ]; then
  ensure_user_systemd_env
  while IFS=$'\t' read -r service_name unit_name status_text; do
    [ -n "$service_name" ] || continue
    printf '[webservices-autoheal] restarting %s for unhealthy service %s: %s\n' "$unit_name" "$service_name" "$status_text" >&2
    user_systemctl restart "$unit_name"
    notify_restart "$service_name" "$unit_name" "$status_text"
  done < "$restarts_file"
fi
