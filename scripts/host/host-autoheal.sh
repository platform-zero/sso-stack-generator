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
require_cmd docker
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

compose_shard_dir="$DEPLOY_ROOT/build/systemd-user/compose"
[ -d "$compose_shard_dir" ] || die "missing rendered compose shard directory: $compose_shard_dir"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/webservices-host-autoheal.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT
containers_json="$tmp_dir/containers.json"
current_json="$tmp_dir/current.json"
restarts_file="$tmp_dir/restarts.tsv"

python3 - "$compose_shard_dir" "$UNIT_PREFIX" > "$tmp_dir/labelled.json" <<'PY'
import json
import sys
from pathlib import Path

compose_dir = Path(sys.argv[1])
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

for path in sorted(compose_dir.glob("*.compose.json")):
    domain = path.name[:-len(".compose.json")]
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

docker ps -a \
  --filter "label=com.docker.compose.project=$PROJECT_NAME" \
  --format '{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Labels}}' \
  | jq -R -s '
      split("\n")
      | map(select(length > 0) | split("\t") | {
          Names: .[0],
          State: .[1],
          Status: .[2],
          Labels: (.[3] // "")
        })
    ' > "$containers_json"

jq -n \
  --slurpfile labelled "$tmp_dir/labelled.json" \
  --slurpfile containers "$containers_json" '
    ($labelled[0] // {}) as $labelled
    | ($containers[0] // [])
    | map(
        . as $container
        | ($container.Labels // "" | split(",") | map(select(length > 0) | split("=") | {(.[0]): (.[1:] | join("="))}) | add // {}) as $labels
        | ($labels["com.docker.compose.service"] // "") as $service
        | select($labelled[$service] != null)
        | {
            service: $service,
            container: ($container.Names // ""),
            unit: $labelled[$service].unit,
            state: ($container.State // ""),
            status: ($container.Status // "")
          }
      )
  ' > "$current_json"

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
