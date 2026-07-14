#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "[mount-diagnostics-test] failed at line %s: %s (exit %s)\n" "$LINENO" "$BASH_COMMAND" "$status" >&2' ERR

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT

mkdir -p "$tmp_dir/deploy/build" "$tmp_dir/deploy/data/shared/subdir" "$tmp_dir/deploy/reports"

runtime_config_json="$tmp_dir/compose.json"
report_json="$tmp_dir/report.json"

cat > "$runtime_config_json" <<EOF_JSON
{
  "services": {
    "alpha": {
      "volumes": [
        {"type": "bind", "source": "./data/shared", "target": "/srv/data"},
        {"type": "bind", "source": "./data/shared/subdir", "target": "/srv/data/subdir"},
        {"type": "bind", "source": "./missing", "target": "/srv/missing"},
        {"type": "volume", "source": "alpha_data", "target": "/var/lib/alpha"},
        {"type": "bind", "source": "./reports", "target": "/srv/data"}
      ]
    },
    "beta": {
      "volumes": [
        {"type": "bind", "source": "$tmp_dir/deploy/data/shared/subdir", "target": "/mnt/subdir"}
      ]
    }
  },
  "volumes": {
    "alpha_data": {}
  }
}
EOF_JSON

"$ROOT_DIR/scripts/mount-diagnostics.sh" \
  --runtime-config-json "$runtime_config_json" \
  --bundle-root "$tmp_dir/deploy/build" \
  --output "$report_json"

jq -e '.summary.mounts == 6' "$report_json" >/dev/null
jq -e '.summary.bindMounts == 5' "$report_json" >/dev/null
jq -e '.summary.namedVolumes == 1' "$report_json" >/dev/null
jq -e '.findings[] | select(.kind == "duplicate_target" and (.services | index("alpha")))' "$report_json" >/dev/null
jq -e '.findings[] | select(.kind == "overlapping_source" and (.services | index("alpha")))' "$report_json" >/dev/null
jq -e '.findings[] | select(.kind == "overlapping_target" and (.services | index("alpha")))' "$report_json" >/dev/null
jq -e '.findings[] | select(.kind == "missing_source" and (.targets | index("/srv/missing")))' "$report_json" >/dev/null
jq -e '.mounts[] | select(.sourceKind == "bind" and .realSource and (.device | type == "number") and (.inode | type == "number"))' "$report_json" >/dev/null

printf '[mount-diagnostics-test] ok\n' >&2
